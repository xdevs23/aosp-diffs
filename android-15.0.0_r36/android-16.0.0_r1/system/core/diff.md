```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index f47c3171c9..ab6430fd4c 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -8,4 +8,3 @@ clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 rustfmt = --config-path=rustfmt.toml
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/bootstat/OWNERS b/bootstat/OWNERS
index f66b309bb2..71b4e0b1cf 100644
--- a/bootstat/OWNERS
+++ b/bootstat/OWNERS
@@ -1,2 +1,3 @@
-jhawkins@google.com
 dvander@google.com
+achant@google.com
+markcheng@google.com
diff --git a/bootstat/bootstat.cpp b/bootstat/bootstat.cpp
index d476d36a93..96c5b81462 100644
--- a/bootstat/bootstat.cpp
+++ b/bootstat/bootstat.cpp
@@ -467,8 +467,9 @@ const std::map<std::string, int32_t> kBootReasonMap = {
     {"reboot,longkey,master_dc", 235},
     {"reboot,ocp2,pmic,if", 236},
     {"reboot,ocp,pmic,if", 237},
-    {"reboot,fship", 238},
+    {"reboot,fship.*", 238},
     {"reboot,ocp,.*", 239},
+    {"reboot,ntc,pmic,sub", 240},
 };
 
 // Converts a string value representing the reason the system booted to an
@@ -912,6 +913,19 @@ const char bootloader_reboot_reason_property[] = "ro.boot.bootreason";
 void BootReasonAddToHistory(const std::string& system_boot_reason) {
   if (system_boot_reason.empty()) return;
   LOG(INFO) << "Canonical boot reason: " << system_boot_reason;
+
+  // skip system_boot_reason(factory_reset, ota) shift since device boot up from shipmode
+  const auto bootloader_boot_reason =
+      android::base::GetProperty(bootloader_reboot_reason_property, "");
+  const char reg_fship[] = ".*fship.*";
+  if (std::regex_search(bootloader_boot_reason, std::regex(reg_fship)) != 0) {
+    if (system_boot_reason == "reboot,factory_reset" || system_boot_reason == "reboot,ota") {
+      LOG(INFO) << "skip boot reason (" << system_boot_reason
+                << ") shift since device boot up from shipmode.";
+      return;
+    }
+  }
+
   auto old_system_boot_reason = android::base::GetProperty(system_reboot_reason_property, "");
   if (!android::base::SetProperty(system_reboot_reason_property, system_boot_reason)) {
     android::base::SetProperty(system_reboot_reason_property,
@@ -953,6 +967,14 @@ void BootReasonAddToHistory(const std::string& system_boot_reason) {
 std::string BootReasonStrToReason(const std::string& boot_reason) {
   auto ret = android::base::GetProperty(system_reboot_reason_property, "");
   std::string reason(boot_reason);
+
+  // skip BootReasonStrToReason() if device boot up from shipmode
+  const char reg_fship[] = ".*fship.*";
+  if (reason == ret && std::regex_search(reason, std::regex(reg_fship)) != 0) {
+    LOG(INFO) << "skip boot reason enhancement if device boot up from shipmode";
+    return ret;
+  }
+
   // If sys.boot.reason == ro.boot.bootreason, let's re-evaluate
   if (reason == ret) ret = "";
 
diff --git a/debuggerd/crash_dump.cpp b/debuggerd/crash_dump.cpp
index 15e8319a97..92d81b326d 100644
--- a/debuggerd/crash_dump.cpp
+++ b/debuggerd/crash_dump.cpp
@@ -22,9 +22,14 @@
 #include <sys/ptrace.h>
 #include <sys/types.h>
 #include <sys/un.h>
+#include <sys/user.h>
 #include <sys/wait.h>
 #include <unistd.h>
 
+#if defined(__i386__)
+#include <asm/ldt.h>
+#endif
+
 #include <cstdint>
 #include <limits>
 #include <map>
@@ -430,18 +435,12 @@ static bool PtracePeek(int request, pid_t tid, uintptr_t addr, void* data, std::
   return true;
 }
 
-static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
-                                                NativeBridgeGuestRegs* guest_regs) {
+static bool GetGuestRegistersFromCrashedProcess(pid_t tid, NativeBridgeGuestRegs* guest_regs) {
   auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(tid);
 
   uintptr_t header_ptr = 0;
   uintptr_t base = 0;
-#if defined(__x86_64__)
-  if (!PtracePeek(PTRACE_PEEKUSER, tid, offsetof(user_regs_struct, fs_base), nullptr,
-                  "failed to read thread register for thread " + std::to_string(tid), &base)) {
-    return false;
-  }
-#elif defined(__aarch64__)
+#if defined(__aarch64__)
   // base is implicitly casted to uint64_t.
   struct iovec pt_iov {
     .iov_base = &base, .iov_len = sizeof(base),
@@ -451,6 +450,24 @@ static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
     PLOG(ERROR) << "failed to read thread register for thread " << tid;
     return false;
   }
+#elif defined(__arm__)
+  // Arm doesn't support any guest architectures yet.
+  return false;
+#elif defined(__i386__)
+  struct user_regs_struct regs;
+  struct iovec pt_iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
+  if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &pt_iov) != 0) {
+    PLOG(ERROR) << "failed to get registers for thread " << tid;
+    return false;
+  }
+
+  struct user_desc desc;
+  desc.entry_number = regs.xgs >> 3;
+  if (ptrace(PTRACE_GET_THREAD_AREA, tid, desc.entry_number, &desc) != 0) {
+    PLOG(ERROR) << "failed to get thread area for thread " << tid;
+    return false;
+  }
+  base = desc.base_addr;
 #elif defined(__riscv)
   struct user_regs_struct regs;
   struct iovec pt_iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
@@ -459,6 +476,11 @@ static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
     return false;
   }
   base = reinterpret_cast<uintptr_t>(regs.tp);
+#elif defined(__x86_64__)
+  if (!PtracePeek(PTRACE_PEEKUSER, tid, offsetof(user_regs_struct, fs_base), nullptr,
+                  "failed to read thread register for thread " + std::to_string(tid), &base)) {
+    return false;
+  }
 #else
   // TODO(b/339287219): Add case for Riscv host.
   return false;
@@ -487,9 +509,7 @@ static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
   return true;
 }
 
-static void ReadGuestRegisters([[maybe_unused]] std::unique_ptr<unwindstack::Regs>* regs,
-                               pid_t tid) {
-  // TODO: remove [[maybe_unused]], when the ARM32 case is removed from the native bridge support.
+static void ReadGuestRegisters(std::unique_ptr<unwindstack::Regs>* regs, pid_t tid) {
   NativeBridgeGuestRegs guest_regs;
   if (!GetGuestRegistersFromCrashedProcess(tid, &guest_regs)) {
     return;
@@ -521,6 +541,17 @@ static void ReadGuestRegisters([[maybe_unused]] std::unique_ptr<unwindstack::Reg
       g_guest_arch = Architecture::RISCV64;
       break;
     }
+#else
+    case NATIVE_BRIDGE_ARCH_ARM: {
+      unwindstack::arm_user_regs arm_user_regs = {};
+      for (size_t i = 0; i < unwindstack::ARM_REG_LAST; i++) {
+        arm_user_regs.regs[i] = guest_regs.regs_arm.r[i];
+      }
+      regs->reset(unwindstack::RegsArm::Read(&arm_user_regs));
+
+      g_guest_arch = Architecture::ARM32;
+      break;
+    }
 #endif
     default:
       break;
@@ -796,16 +827,17 @@ int main(int argc, char** argv) {
       ATRACE_NAME("engrave_tombstone");
       unwindstack::ArchEnum regs_arch = unwindstack::ARCH_UNKNOWN;
       switch (g_guest_arch) {
-        case Architecture::ARM64: {
+        case Architecture::ARM32:
+          regs_arch = unwindstack::ARCH_ARM;
+          break;
+        case Architecture::ARM64:
           regs_arch = unwindstack::ARCH_ARM64;
           break;
-        }
-        case Architecture::RISCV64: {
+        case Architecture::RISCV64:
           regs_arch = unwindstack::ARCH_RISCV64;
           break;
-        }
-        default: {
-        }
+        default:
+          break;
       }
       if (regs_arch == unwindstack::ARCH_UNKNOWN) {
         engrave_tombstone(std::move(g_output_fd), std::move(g_proto_fd), &unwinder, thread_info,
diff --git a/debuggerd/crasher/Android.bp b/debuggerd/crasher/Android.bp
index 4c6a400a1d..3af806b431 100644
--- a/debuggerd/crasher/Android.bp
+++ b/debuggerd/crasher/Android.bp
@@ -15,7 +15,6 @@ cc_defaults {
         "-fstack-protector-all",
         "-Wno-date-time",
     ],
-    tidy: false, // crasher.cpp tests many memory access errors
     srcs: ["crasher.cpp"],
     arch: {
         arm: {
diff --git a/debuggerd/crasher/crasher.cpp b/debuggerd/crasher/crasher.cpp
index 05143ed055..c3dd92b43c 100644
--- a/debuggerd/crasher/crasher.cpp
+++ b/debuggerd/crasher/crasher.cpp
@@ -402,6 +402,8 @@ noinline int do_action(const char* arg) {
     return EXIT_SUCCESS;
 }
 
+}  // extern "C"
+
 int main(int argc, char** argv) {
 #if defined(STATIC_CRASHER)
     debuggerd_callbacks_t callbacks = {
@@ -427,5 +429,3 @@ int main(int argc, char** argv) {
 
     return usage();
 }
-
-};
diff --git a/debuggerd/debuggerd_test.cpp b/debuggerd/debuggerd_test.cpp
index 5bdc946463..34f2c450c6 100644
--- a/debuggerd/debuggerd_test.cpp
+++ b/debuggerd/debuggerd_test.cpp
@@ -335,7 +335,7 @@ TEST_F(CrasherTest, smoke) {
   ConsumeFd(std::move(output_fd), &result);
   ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+dead)");
 
-  if (mte_supported()) {
+  if (mte_supported() && mte_enabled()) {
     // Test that the default TAGGED_ADDR_CTRL value is set.
     ASSERT_MATCH(result, R"(tagged_addr_ctrl: 000000000007fff3)"
                          R"( \(PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, mask 0xfffe\))");
@@ -443,7 +443,7 @@ INSTANTIATE_TEST_SUITE_P(Sizes, SizeParamCrasherTest, testing::Values(0, 16, 131
 
 TEST_P(SizeParamCrasherTest, mte_uaf) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -490,7 +490,7 @@ TEST_P(SizeParamCrasherTest, mte_uaf) {
 
 TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -522,7 +522,7 @@ TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
 
 TEST_P(SizeParamCrasherTest, mte_overflow) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -565,7 +565,7 @@ TEST_P(SizeParamCrasherTest, mte_overflow) {
 
 TEST_P(SizeParamCrasherTest, mte_underflow) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -614,7 +614,7 @@ TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
   //     unsubtle chaos is sure to result.
   // https://man7.org/linux/man-pages/man3/longjmp.3.html
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -648,7 +648,7 @@ TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
 
 TEST_F(CrasherTest, mte_async) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -678,7 +678,7 @@ TEST_F(CrasherTest, mte_async) {
 
 TEST_F(CrasherTest, mte_multiple_causes) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -764,7 +764,7 @@ static uintptr_t CreateTagMapping() {
 
 TEST_F(CrasherTest, mte_register_tag_dump) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -797,7 +797,7 @@ TEST_F(CrasherTest, mte_register_tag_dump) {
 
 TEST_F(CrasherTest, mte_fault_tag_dump_front_truncated) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -828,7 +828,7 @@ TEST_F(CrasherTest, mte_fault_tag_dump_front_truncated) {
 
 TEST_F(CrasherTest, mte_fault_tag_dump) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -862,7 +862,7 @@ TEST_F(CrasherTest, mte_fault_tag_dump) {
 
 TEST_F(CrasherTest, mte_fault_tag_dump_rear_truncated) {
 #if defined(__aarch64__)
-  if (!mte_supported()) {
+  if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
@@ -2788,6 +2788,10 @@ TEST_F(CrasherTest, fault_address_between_maps) {
   void* start_ptr =
       mmap(nullptr, 3 * getpagesize(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_NE(MAP_FAILED, start_ptr);
+  // Add a name to guarantee that this map is distinct and not combined in the map listing.
+  EXPECT_EQ(
+      prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, start_ptr, 3 * getpagesize(), "debuggerd map start"),
+      0);
   // Unmap the page in the middle.
   void* middle_ptr =
       reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(start_ptr) + getpagesize());
@@ -2834,6 +2838,8 @@ TEST_F(CrasherTest, fault_address_in_map) {
   // Create a map before the fork so it will be present in the child.
   void* ptr = mmap(nullptr, getpagesize(), 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_NE(MAP_FAILED, ptr);
+  // Add a name to guarantee that this map is distinct and not combined in the map listing.
+  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, getpagesize(), "debuggerd map"), 0);
 
   StartProcess([ptr]() {
     ASSERT_EQ(0, crash_call(reinterpret_cast<uintptr_t>(ptr)));
@@ -2905,7 +2911,7 @@ TEST_F(CrasherTest, verify_dex_pc_with_function_name) {
         mmap(nullptr, sizeof(kDexData), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
     ASSERT_TRUE(ptr != MAP_FAILED);
     memcpy(ptr, kDexData, sizeof(kDexData));
-    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, sizeof(kDexData), "dex");
+    EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, sizeof(kDexData), "dex"), 0);
 
     JITCodeEntry dex_entry = {.symfile_addr = reinterpret_cast<uintptr_t>(ptr),
                               .symfile_size = sizeof(kDexData)};
@@ -3006,12 +3012,18 @@ TEST_F(CrasherTest, verify_map_format) {
   // Create multiple maps to make sure that the map data is formatted properly.
   void* none_map = mmap(nullptr, getpagesize(), 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_NE(MAP_FAILED, none_map);
+  // Add names to guarantee that the maps are distinct and not combined in the map listing.
+  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, none_map, getpagesize(), "debuggerd map none"),
+            0);
   void* r_map = mmap(nullptr, getpagesize(), PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_NE(MAP_FAILED, r_map);
+  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, r_map, getpagesize(), "debuggerd map r"), 0);
   void* w_map = mmap(nullptr, getpagesize(), PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
+  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, w_map, getpagesize(), "debuggerd map w"), 0);
   ASSERT_NE(MAP_FAILED, w_map);
   void* x_map = mmap(nullptr, getpagesize(), PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_NE(MAP_FAILED, x_map);
+  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, x_map, getpagesize(), "debuggerd map x"), 0);
 
   TemporaryFile tf;
   ASSERT_EQ(0x2000, lseek(tf.fd, 0x2000, SEEK_SET));
@@ -3046,7 +3058,7 @@ TEST_F(CrasherTest, verify_map_format) {
   std::string match_str;
   // Verify none.
   match_str = android::base::StringPrintf(
-      "    %s-%s ---         0      %x\\n",
+      "    %s-%s ---         0      %x  \\[anon:debuggerd map none\\]\\n",
       format_map_pointer(reinterpret_cast<uintptr_t>(none_map)).c_str(),
       format_map_pointer(reinterpret_cast<uintptr_t>(none_map) + getpagesize() - 1).c_str(),
       getpagesize());
@@ -3054,7 +3066,7 @@ TEST_F(CrasherTest, verify_map_format) {
 
   // Verify read-only.
   match_str = android::base::StringPrintf(
-      "    %s-%s r--         0      %x\\n",
+      "    %s-%s r--         0      %x  \\[anon:debuggerd map r\\]\\n",
       format_map_pointer(reinterpret_cast<uintptr_t>(r_map)).c_str(),
       format_map_pointer(reinterpret_cast<uintptr_t>(r_map) + getpagesize() - 1).c_str(),
       getpagesize());
@@ -3062,7 +3074,7 @@ TEST_F(CrasherTest, verify_map_format) {
 
   // Verify write-only.
   match_str = android::base::StringPrintf(
-      "    %s-%s -w-         0      %x\\n",
+      "    %s-%s -w-         0      %x  \\[anon:debuggerd map w\\]\\n",
       format_map_pointer(reinterpret_cast<uintptr_t>(w_map)).c_str(),
       format_map_pointer(reinterpret_cast<uintptr_t>(w_map) + getpagesize() - 1).c_str(),
       getpagesize());
@@ -3070,7 +3082,7 @@ TEST_F(CrasherTest, verify_map_format) {
 
   // Verify exec-only.
   match_str = android::base::StringPrintf(
-      "    %s-%s --x         0      %x\\n",
+      "    %s-%s --x         0      %x  \\[anon:debuggerd map x\\]\\n",
       format_map_pointer(reinterpret_cast<uintptr_t>(x_map)).c_str(),
       format_map_pointer(reinterpret_cast<uintptr_t>(x_map) + getpagesize() - 1).c_str(),
       getpagesize());
@@ -3303,8 +3315,44 @@ TEST_F(CrasherTest, log_with_newline) {
   ASSERT_MATCH(result, ":\\s*This is on the next line.");
 }
 
-TEST_F(CrasherTest, log_with_non_utf8) {
-  StartProcess([]() { LOG(FATAL) << "Invalid UTF-8: \xA0\xB0\xC0\xD0 and some other data."; });
+TEST_F(CrasherTest, log_with_non_printable_ascii_verify_encoded) {
+  static const std::string kEncodedStr =
+      "\x5C\x31"
+      "\x5C\x32"
+      "\x5C\x33"
+      "\x5C\x34"
+      "\x5C\x35"
+      "\x5C\x36"
+      "\x5C\x37"
+      "\x5C\x31\x30"
+      "\x5C\x31\x36"
+      "\x5C\x31\x37"
+      "\x5C\x32\x30"
+      "\x5C\x32\x31"
+      "\x5C\x32\x32"
+      "\x5C\x32\x33"
+      "\x5C\x32\x34"
+      "\x5C\x32\x35"
+      "\x5C\x32\x36"
+      "\x5C\x32\x37"
+      "\x5C\x33\x30"
+      "\x5C\x33\x31"
+      "\x5C\x33\x32"
+      "\x5C\x33\x33"
+      "\x5C\x33\x34"
+      "\x5C\x33\x35"
+      "\x5C\x33\x36"
+      "\x5C\x33\x37"
+      "\x5C\x31\x37\x37"
+      "\x5C\x32\x34\x30"
+      "\x5C\x32\x36\x30"
+      "\x5C\x33\x30\x30"
+      "\x5C\x33\x32\x30";
+  StartProcess([]() {
+    LOG(FATAL) << "Encoded: "
+                  "\x1\x2\x3\x4\x5\x6\x7\x8\xe\xf\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
+                  "\x1c\x1d\x1e\x1f\x7f\xA0\xB0\xC0\xD0 after";
+  });
 
   unique_fd output_fd;
   StartIntercept(&output_fd);
@@ -3317,15 +3365,38 @@ TEST_F(CrasherTest, log_with_non_utf8) {
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
   // Verify the abort message is sanitized properly.
-  size_t pos = result.find(
-      "Abort message: 'Invalid UTF-8: "
-      "\x5C\x32\x34\x30\x5C\x32\x36\x30\x5C\x33\x30\x30\x5C\x33\x32\x30 and some other data.'");
+  size_t pos = result.find(std::string("Abort message: 'Encoded: ") + kEncodedStr + " after'");
   EXPECT_TRUE(pos != std::string::npos) << "Couldn't find sanitized abort message: " << result;
 
   // Make sure that the log message is sanitized properly too.
-  EXPECT_TRUE(
-      result.find("Invalid UTF-8: \x5C\x32\x34\x30\x5C\x32\x36\x30\x5C\x33\x30\x30\x5C\x33\x32\x30 "
-                  "and some other data.",
-                  pos + 30) != std::string::npos)
+  EXPECT_TRUE(result.find(std::string("Encoded: ") + kEncodedStr + " after", pos + 1) !=
+              std::string::npos)
+      << "Couldn't find sanitized log message: " << result;
+}
+
+TEST_F(CrasherTest, log_with_with_special_printable_ascii) {
+  static const std::string kMsg = "Not encoded: \t\v\f\r\n after";
+  StartProcess([]() { LOG(FATAL) << kMsg; });
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
+  // Verify the abort message does not remove characters that are UTF8 but
+  // are, technically, not printable.
+  size_t pos = result.find(std::string("Abort message: '") + kMsg + "'");
+  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find abort message: " << result;
+
+  // Make sure that the log message is handled properly too.
+  // The logger automatically splits a newline message into two pieces.
+  pos = result.find("Not encoded: \t\v\f\r", pos + kMsg.size());
+  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find log message: " << result;
+  EXPECT_TRUE(result.find(" after", pos + 1) != std::string::npos)
       << "Couldn't find sanitized log message: " << result;
 }
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/open_files_list.h b/debuggerd/libdebuggerd/include/libdebuggerd/open_files_list.h
index d47f2ddf6d..12a425e95b 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/open_files_list.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/open_files_list.h
@@ -20,6 +20,7 @@
 #include <sys/types.h>
 
 #include <map>
+#include <memory>
 #include <optional>
 #include <string>
 #include <utility>
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
index df22e017ce..819a99d2d9 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
@@ -30,4 +30,7 @@ constexpr size_t kTagGranuleSize = 16;
 constexpr size_t kNumTagColumns = 16;
 constexpr size_t kNumTagRows = 16;
 
-std::string oct_encode(const std::string& data);
+// Encode all non-ascii values and also ascii values that are not printable.
+std::string oct_encode_non_ascii_printable(const std::string& data);
+// Encode any value that fails isprint(), includes encoding chars like '\n' and '\t'.
+std::string oct_encode_non_printable(const std::string& data);
diff --git a/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp b/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
index aad209a063..988ca0cd12 100644
--- a/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
+++ b/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
@@ -175,3 +175,8 @@ TEST_F(TombstoneProtoToTextTest, symbolize) {
   ProtoToString();
   EXPECT_MATCH(text_, "\\(BuildId: 0123456789abcdef\\)\\nSYMBOLIZE 0123456789abcdef 12345\\n");
 }
+
+TEST_F(TombstoneProtoToTextTest, uid) {
+  ProtoToString();
+  EXPECT_MATCH(text_, "\\nLOG uid: 0\\n");
+}
diff --git a/debuggerd/libdebuggerd/tombstone_proto.cpp b/debuggerd/libdebuggerd/tombstone_proto.cpp
index ef303f065c..d3ac49a17f 100644
--- a/debuggerd/libdebuggerd/tombstone_proto.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto.cpp
@@ -467,7 +467,7 @@ static void dump_abort_message(Tombstone* tombstone,
   msg.resize(index);
 
   // Make sure only UTF8 characters are present since abort_message is a string.
-  tombstone->set_abort_message(oct_encode(msg));
+  tombstone->set_abort_message(oct_encode_non_ascii_printable(msg));
 }
 
 static void dump_open_fds(Tombstone* tombstone, const OpenFilesList* open_files) {
@@ -776,7 +776,7 @@ static void dump_log_file(Tombstone* tombstone, const char* logger, pid_t pid) {
       log_msg->set_priority(prio);
       log_msg->set_tag(tag);
       // Make sure only UTF8 characters are present since message is a string.
-      log_msg->set_message(oct_encode(msg));
+      log_msg->set_message(oct_encode_non_ascii_printable(msg));
     } while ((msg = nl));
   }
   android_logger_list_free(logger_list);
diff --git a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
index e885c5a73b..11841b290d 100644
--- a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
@@ -17,6 +17,7 @@
 #include <libdebuggerd/tombstone_proto_to_text.h>
 #include <libdebuggerd/utility_host.h>
 
+#include <ctype.h>
 #include <inttypes.h>
 
 #include <algorithm>
@@ -463,8 +464,8 @@ static void print_main_thread(CallbackType callback, SymbolizeCallbackType symbo
   }
 
   for (const auto& crash_detail : tombstone.crash_details()) {
-    std::string oct_encoded_name = oct_encode(crash_detail.name());
-    std::string oct_encoded_data = oct_encode(crash_detail.data());
+    std::string oct_encoded_name = oct_encode_non_printable(crash_detail.name());
+    std::string oct_encoded_data = oct_encode_non_printable(crash_detail.data());
     CBL("Extra crash detail: %s: '%s'", oct_encoded_name.c_str(), oct_encoded_data.c_str());
   }
 
@@ -593,7 +594,7 @@ bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback,
   if (tombstone.page_size() != 4096) {
     CBL("Page size: %d bytes", tombstone.page_size());
   } else if (tombstone.has_been_16kb_mode()) {
-    CBL("Has been in 16kb mode: yes");
+    CBL("Has been in 16 KB mode before: yes");
   }
 
   // Process header
diff --git a/debuggerd/libdebuggerd/utility_host.cpp b/debuggerd/libdebuggerd/utility_host.cpp
index 4efa03c8cb..d87f4fb8e1 100644
--- a/debuggerd/libdebuggerd/utility_host.cpp
+++ b/debuggerd/libdebuggerd/utility_host.cpp
@@ -16,6 +16,7 @@
 
 #include "libdebuggerd/utility_host.h"
 
+#include <ctype.h>
 #include <sys/prctl.h>
 
 #include <charconv>
@@ -102,23 +103,31 @@ std::string describe_pac_enabled_keys(long value) {
   return describe_end(value, desc);
 }
 
-std::string oct_encode(const std::string& data) {
+static std::string oct_encode(const std::string& data, bool (*should_encode_func)(int)) {
   std::string oct_encoded;
   oct_encoded.reserve(data.size());
 
   // N.B. the unsigned here is very important, otherwise e.g. \255 would render as
   // \-123 (and overflow our buffer).
   for (unsigned char c : data) {
-    if (isprint(c)) {
-      oct_encoded += c;
-    } else {
+    if (should_encode_func(c)) {
       std::string oct_digits("\\\0\0\0", 4);
       // char is encodable in 3 oct digits
       static_assert(std::numeric_limits<unsigned char>::max() <= 8 * 8 * 8);
       auto [ptr, ec] = std::to_chars(oct_digits.data() + 1, oct_digits.data() + 4, c, 8);
       oct_digits.resize(ptr - oct_digits.data());
       oct_encoded += oct_digits;
+    } else {
+      oct_encoded += c;
     }
   }
   return oct_encoded;
 }
+
+std::string oct_encode_non_ascii_printable(const std::string& data) {
+  return oct_encode(data, [](int c) { return !isgraph(c) && !isspace(c); });
+}
+
+std::string oct_encode_non_printable(const std::string& data) {
+  return oct_encode(data, [](int c) { return !isprint(c); });
+}
diff --git a/debuggerd/proto/tombstone.proto b/debuggerd/proto/tombstone.proto
index 444c9732f0..9deeeec9e1 100644
--- a/debuggerd/proto/tombstone.proto
+++ b/debuggerd/proto/tombstone.proto
@@ -15,6 +15,15 @@ option java_outer_classname = "TombstoneProtos";
 // NOTE TO OEMS:
 // If you add custom fields to this proto, do not use numbers in the reserved range.
 
+// NOTE TO CONSUMERS:
+// With proto3 -- unlike proto2 -- HasValue is unreliable for any field
+// where the default value for that type is also a valid value for the field.
+// This means, for example, that a boolean that is false or an integer that
+// is zero will appear to be missing --- but because they're not actually
+// marked as `optional` in this schema, consumers should just use values
+// without first checking whether or not they're "present".
+// https://protobuf.dev/programming-guides/proto3/#default
+
 message CrashDetail {
   bytes name = 1;
   bytes data = 2;
diff --git a/debuggerd/test_permissive_mte/Android.bp b/debuggerd/test_permissive_mte/Android.bp
index f333242cc7..4403b8a94c 100644
--- a/debuggerd/test_permissive_mte/Android.bp
+++ b/debuggerd/test_permissive_mte/Android.bp
@@ -18,7 +18,6 @@ package {
 
 cc_binary {
     name: "mte_crash",
-    tidy: false,
     srcs: ["mte_crash.cpp"],
     sanitize: {
         memtag_heap: true,
diff --git a/debuggerd/tombstoned/tombstoned.cpp b/debuggerd/tombstoned/tombstoned.cpp
index 2c7237934e..dd20dc5dff 100644
--- a/debuggerd/tombstoned/tombstoned.cpp
+++ b/debuggerd/tombstoned/tombstoned.cpp
@@ -144,7 +144,6 @@ class CrashQueue {
   CrashArtifact create_temporary_file() const {
     CrashArtifact result;
 
-    std::optional<std::string> path;
     result.fd.reset(openat(dir_fd_, ".", O_WRONLY | O_APPEND | O_TMPFILE | O_CLOEXEC, 0660));
     if (result.fd == -1) {
       PLOG(FATAL) << "failed to create temporary tombstone in " << dir_path_;
diff --git a/fastboot/Android.bp b/fastboot/Android.bp
index 4d9898758b..d0938eefaa 100644
--- a/fastboot/Android.bp
+++ b/fastboot/Android.bp
@@ -307,12 +307,6 @@ cc_library_host_static {
 
     generated_headers: ["platform_tools_version"],
 
-    tidy_flags: [
-        // DO NOT add quotes around header-filter flag regex argument,
-        // because build/soong will add quotes around the whole flag.
-        "-header-filter=(system/core/fastboot/|development/host/windows/usb/api/)",
-    ],
-
     target: {
         windows: {
             srcs: ["usb_windows.cpp"],
diff --git a/fastboot/OWNERS b/fastboot/OWNERS
index 3dec07e2d5..2444081f7a 100644
--- a/fastboot/OWNERS
+++ b/fastboot/OWNERS
@@ -1,5 +1,6 @@
 dvander@google.com
 elsk@google.com
 enh@google.com
+sanglardf@google.com
 zhangkelvin@google.com
 
diff --git a/fastboot/fastboot.cpp b/fastboot/fastboot.cpp
index 156dc3b334..1c52da2382 100644
--- a/fastboot/fastboot.cpp
+++ b/fastboot/fastboot.cpp
@@ -638,7 +638,10 @@ static int show_help() {
             " --disable-verification     Sets disable-verification when flashing vbmeta.\n"
             " --disable-super-optimization\n"
             "                            Disables optimizations on flashing super partition.\n"
-            " --disable-fastboot-info    Will collects tasks from image list rather than $OUT/fastboot-info.txt.\n"
+            " --exclude-dynamic-partitions\n"
+            "                            Excludes flashing of dynamic partitions.\n"
+            " --disable-fastboot-info    Will collects tasks from image list rather than \n"
+            "                            $OUT/fastboot-info.txt.\n"
             " --fs-options=OPTION[,OPTION]\n"
             "                            Enable filesystem features. OPTION supports casefold, projid, compress\n"
             // TODO: remove --unbuffered?
diff --git a/fastboot/fuzzy_fastboot/main.cpp b/fastboot/fuzzy_fastboot/main.cpp
index 79f3939fe5..9eabbd3116 100644
--- a/fastboot/fuzzy_fastboot/main.cpp
+++ b/fastboot/fuzzy_fastboot/main.cpp
@@ -33,6 +33,7 @@
 #include <sys/time.h>
 #include <sys/types.h>
 #include <unistd.h>
+#include <algorithm>
 #include <chrono>
 #include <cstdlib>
 #include <fstream>
diff --git a/fastboot/fuzzy_fastboot/test_utils.cpp b/fastboot/fuzzy_fastboot/test_utils.cpp
index 9ad98be60a..b80db2357b 100644
--- a/fastboot/fuzzy_fastboot/test_utils.cpp
+++ b/fastboot/fuzzy_fastboot/test_utils.cpp
@@ -28,6 +28,8 @@
 #include "test_utils.h"
 #include <fcntl.h>
 #include <termios.h>
+#include <algorithm>
+#include <iterator>
 #include <sstream>
 
 namespace fastboot {
diff --git a/fastboot/fuzzy_fastboot/transport_sniffer.cpp b/fastboot/fuzzy_fastboot/transport_sniffer.cpp
index 0aef350052..fffa9a2304 100644
--- a/fastboot/fuzzy_fastboot/transport_sniffer.cpp
+++ b/fastboot/fuzzy_fastboot/transport_sniffer.cpp
@@ -3,6 +3,7 @@
 #include <sys/select.h>
 #include <sys/time.h>
 #include <sys/types.h>
+#include <algorithm>
 #include <iomanip>
 #include <sstream>
 
diff --git a/fs_mgr/README.overlayfs.md b/fs_mgr/README.overlayfs.md
index 94b2f8c0bd..df5d775fa4 100644
--- a/fs_mgr/README.overlayfs.md
+++ b/fs_mgr/README.overlayfs.md
@@ -79,16 +79,15 @@ Caveats
   done file by file. Be mindful of wasted space. For example, defining
   **BOARD_IMAGE_PARTITION_RESERVED_SIZE** has a negative impact on the
   right-sizing of images and requires more free dynamic partition space.
-- The kernel requires **CONFIG_OVERLAY_FS=y**. If the kernel version is higher
-  than 4.4, it requires source to be in line with android-common kernels. 
-  The patch series is available on the upstream mailing list and the latest as
-  of Sep 5 2019 is https://www.spinics.net/lists/linux-mtd/msg08331.html
-  This patch adds an override_creds _mount_ option to OverlayFS that
-  permits legacy behavior for systems that do not have overlapping
-  sepolicy rules, principals of least privilege, which is how Android behaves.
-  For 4.19 and higher a rework of the xattr handling to deal with recursion
-  is required. https://patchwork.kernel.org/patch/11117145/ is a start of that
-  adjustment.
+- The kernel requires **CONFIG_OVERLAY_FS=y**. overlayfs is used 'as is' as of
+  android 16, no modifications are required.
+- In order for overlayfs to work, overlays are mounted in the overlay_remounter
+  domain, defined here: system/sepolicy/private/overlay_remounter.te. This domain
+  must have full access to the files on the underlying volumes, add any other file
+  and directory types here
+- For devices with dynamic partitions, we use a simpler logic to decide which
+  partitions to remount, being all logical ones. In case this isn't correct,
+  we added the overlay=on and overlay=off mount flags to allow detailed control.
 - _adb enable-verity_ frees up OverlayFS and reverts the device to the state
   prior to content updates. The update engine performs a full OTA.
 - _adb remount_ overrides are incompatible with OTA resources, so the update
diff --git a/fs_mgr/TEST_MAPPING b/fs_mgr/TEST_MAPPING
index 13af1e2a39..ccbb67ed54 100644
--- a/fs_mgr/TEST_MAPPING
+++ b/fs_mgr/TEST_MAPPING
@@ -35,9 +35,6 @@
     }
   ],
   "kernel-presubmit": [
-    {
-      "name": "adb-remount-sh"
-    },
     {
       "name": "libdm_test"
     },
diff --git a/fs_mgr/fs_mgr.cpp b/fs_mgr/fs_mgr.cpp
index 9f52f4483b..204e690936 100644
--- a/fs_mgr/fs_mgr.cpp
+++ b/fs_mgr/fs_mgr.cpp
@@ -858,6 +858,10 @@ static int __mount(const std::string& source, const std::string& target, const F
         if (!android::base::Realpath(source, &real_source)) {
             real_source = source;
         }
+
+        // Clear errno prior to calling `mount`, to avoid clobbering with any errno that
+        // may have been set from prior calls (e.g. realpath).
+        errno = 0;
         ret = mount(real_source.c_str(), target.c_str(), entry.fs_type.c_str(), mountflags,
                     opts.c_str());
         save_errno = errno;
@@ -2019,6 +2023,84 @@ static bool PrepareZramBackingDevice(off64_t size) {
     return InstallZramDevice(loop_device);
 }
 
+// Check whether it is in recovery mode or not.
+//
+// This is a copy from util.h in libinit.
+//
+// You need to check ALL relevant executables calling this function has access to
+// "/system/bin/recovery" (including SELinux permissions and UNIX permissions).
+static bool IsRecovery() {
+    return access("/system/bin/recovery", F_OK) == 0;
+}
+
+// Decides whether swapon_all should skip setting up zram.
+//
+// swapon_all is deprecated to setup zram after mmd is launched. swapon_all command should skip
+// setting up zram if mmd is enabled by AConfig flag and mmd is configured to set up zram.
+static bool ShouldSkipZramSetup() {
+    if (IsRecovery()) {
+        // swapon_all continue to support zram setup in recovery mode after mmd launch.
+        return false;
+    }
+
+    // Since AConfig does not support to load the status from init, we use the system property
+    // "mmd.enabled_aconfig" copied from AConfig by `mmd --set-property` command to check whether
+    // mmd is enabled or not.
+    //
+    // aconfig_prop can have either of:
+    //
+    // * "true": mmd is enabled by AConfig
+    // * "false": mmd is disabled by AConfig
+    // * "": swapon_all is executed before `mmd --set-property`
+    //
+    // During mmd being launched, we request OEMs, who decided to use mmd to set up zram, to execute
+    // swapon_all after "mmd.enabled_aconfig" system property is initialized. Init can wait the
+    // "mmd.enabled_aconfig" initialization by `property:mmd.enabled_aconfig=*` trigger.
+    //
+    // After mmd is launched, we deprecate swapon_all command for setting up zram but recommend to
+    // use `mmd --setup-zram`. It means that the system should call swapon_all with fstab with no
+    // zram entry or the system should never call swapon_all.
+    //
+    // As a transition, OEMs can use the deprecated swapon_all to set up zram for several versions
+    // after mmd is launched. swapon_all command will show warning logs during the transition
+    // period.
+    const std::string aconfig_prop = android::base::GetProperty("mmd.enabled_aconfig", "");
+    const bool is_zram_managed_by_mmd = android::base::GetBoolProperty("mmd.zram.enabled", false);
+    if (aconfig_prop == "true" && is_zram_managed_by_mmd) {
+        // Skip zram setup since zram is managed by mmd.
+        //
+        // We expect swapon_all is not called when mmd is enabled by AConfig flag.
+        // TODO: b/394484720 - Make this log as warning after mmd is launched.
+        LINFO << "Skip setting up zram because mmd sets up zram instead.";
+        return true;
+    }
+
+    if (aconfig_prop == "false") {
+        // It is expected to swapon_all command to set up zram before mmd is launched.
+        LOG(DEBUG) << "mmd is not launched yet. swapon_all setup zram.";
+    } else if (is_zram_managed_by_mmd) {
+        // This branch is for aconfig_prop == ""
+
+        // On the system which uses mmd to setup zram, swapon_all must be executed after
+        // mmd.enabled_aconfig is initialized.
+        LERROR << "swapon_all must be called after mmd.enabled_aconfig system "
+                  "property is initialized";
+        // Since we don't know whether mmd is enabled on the system or not, we fall back to enable
+        // zram from swapon_all conservatively. Both swapon_all and `mmd --setup-zram` command
+        // trying to set up zram does not break the system but just either ends up failing.
+    } else {
+        // We show the warning log for swapon_all deprecation on both aconfig_prop is "true" and ""
+        // cases.
+        // If mmd is enabled, swapon_all is already deprecated.
+        // If aconfig_prop is "", we don't know whether mmd is launched or not. But we show the
+        // deprecation warning log conservatively.
+        LWARNING << "mmd is recommended to set up zram over swapon_all command with "
+                    "fstab entry.";
+    }
+
+    return false;
+}
+
 bool fs_mgr_swapon_all(const Fstab& fstab) {
     bool ret = true;
     for (const auto& entry : fstab) {
@@ -2028,6 +2110,10 @@ bool fs_mgr_swapon_all(const Fstab& fstab) {
         }
 
         if (entry.zram_size > 0) {
+            if (ShouldSkipZramSetup()) {
+                continue;
+            }
+
             if (!PrepareZramBackingDevice(entry.zram_backingdev_size)) {
                 LERROR << "Failure of zram backing device file for '" << entry.blk_device << "'";
             }
@@ -2331,6 +2417,7 @@ OverlayfsCheckResult CheckOverlayfs() {
     if (!fs_mgr_filesystem_available("overlay")) {
         return {.supported = false};
     }
+
     struct utsname uts;
     if (uname(&uts) == -1) {
         return {.supported = false};
@@ -2339,6 +2426,14 @@ OverlayfsCheckResult CheckOverlayfs() {
     if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
         return {.supported = false};
     }
+
+    if (!use_override_creds) {
+        if (major > 5 || (major == 5 && minor >= 15)) {
+            return {.supported = true, ",userxattr"};
+        }
+        return {.supported = true};
+    }
+
     // Overlayfs available in the kernel, and patched for override_creds?
     if (access("/sys/module/overlay/parameters/override_creds", F_OK) == 0) {
         auto mount_flags = ",override_creds=off"s;
diff --git a/fs_mgr/fs_mgr_overlayfs_mount.cpp b/fs_mgr/fs_mgr_overlayfs_mount.cpp
index b63b9e7aa0..762e70dc7e 100644
--- a/fs_mgr/fs_mgr_overlayfs_mount.cpp
+++ b/fs_mgr/fs_mgr_overlayfs_mount.cpp
@@ -49,6 +49,10 @@
 #include "fs_mgr_overlayfs_mount.h"
 #include "fs_mgr_priv.h"
 
+// Flag to simplify algorithm for choosing which partitions to overlay to simply overlay
+// all dynamic partitions
+constexpr bool overlay_dynamic_partitions_only = true;
+
 using namespace std::literals;
 using namespace android::fs_mgr;
 using namespace android::storage_literals;
@@ -194,9 +198,8 @@ static bool fs_mgr_is_read_only_f2fs(const std::string& dev) {
 
 static bool fs_mgr_overlayfs_enabled(FstabEntry* entry) {
     // readonly filesystem, can not be mount -o remount,rw
-    // for squashfs, erofs or if free space is (near) zero making such a remount
-    // virtually useless, or if there are shared blocks that prevent remount,rw
-    if (!fs_mgr_filesystem_has_space(entry->mount_point)) {
+    // for squashfs, erofs, or if there are shared blocks that prevent remount,rw
+    if (entry->fs_type == "erofs" || entry->fs_type == "squashfs") {
         return true;
     }
 
@@ -670,6 +673,19 @@ Fstab fs_mgr_overlayfs_candidate_list(const Fstab& fstab) {
 
     Fstab candidates;
     for (const auto& entry : fstab) {
+        // fstab overlay flag overrides all other behavior
+        if (entry.fs_mgr_flags.overlay_off) continue;
+        if (entry.fs_mgr_flags.overlay_on) {
+            candidates.push_back(entry);
+            continue;
+        }
+
+        // overlay_dynamic_partitions_only simplifies logic to overlay exactly dynamic partitions
+        if (overlay_dynamic_partitions_only) {
+            if (entry.fs_mgr_flags.logical) candidates.push_back(entry);
+            continue;
+        }
+
         // Filter out partitions whose type doesn't match what's mounted.
         // This avoids spammy behavior on devices which can mount different
         // filesystems for each partition.
diff --git a/fs_mgr/include/fs_mgr_overlayfs.h b/fs_mgr/include/fs_mgr_overlayfs.h
index bf68b2c813..253013bdf5 100644
--- a/fs_mgr/include/fs_mgr_overlayfs.h
+++ b/fs_mgr/include/fs_mgr_overlayfs.h
@@ -43,5 +43,11 @@ void MapScratchPartitionIfNeeded(Fstab* fstab,
 // overlays if any partition is flashed or updated.
 void TeardownAllOverlayForMountPoint(const std::string& mount_point = {});
 
+// Are we using overlayfs's non-upstreamed override_creds feature?
+// b/388912628 removes the need for override_creds
+// Once this bug is fixed and has had enough soak time, remove this variable and hard code to false
+// where it used
+constexpr bool use_override_creds = false;
+
 }  // namespace fs_mgr
 }  // namespace android
diff --git a/fs_mgr/libfiemap/binder.cpp b/fs_mgr/libfiemap/binder.cpp
index 439aac9695..8c5fb09b9d 100644
--- a/fs_mgr/libfiemap/binder.cpp
+++ b/fs_mgr/libfiemap/binder.cpp
@@ -62,6 +62,7 @@ class ImageManagerBinder final : public IImageManager {
                                   std::string* dev) override;
     FiemapStatus ZeroFillNewImage(const std::string& name, uint64_t bytes) override;
     bool RemoveAllImages() override;
+    bool DisableAllImages() override;
     bool DisableImage(const std::string& name) override;
     bool RemoveDisabledImages() override;
     bool GetMappedImageDevice(const std::string& name, std::string* device) override;
@@ -194,6 +195,9 @@ bool ImageManagerBinder::RemoveAllImages() {
     }
     return true;
 }
+bool ImageManagerBinder::DisableAllImages() {
+    return true;
+}
 
 bool ImageManagerBinder::DisableImage(const std::string& name) {
     auto status = manager_->disableImage(name);
diff --git a/fs_mgr/libfiemap/image_manager.cpp b/fs_mgr/libfiemap/image_manager.cpp
index a5da6e3429..bc61d15bce 100644
--- a/fs_mgr/libfiemap/image_manager.cpp
+++ b/fs_mgr/libfiemap/image_manager.cpp
@@ -655,6 +655,23 @@ bool ImageManager::RemoveAllImages() {
     return ok && RemoveAllMetadata(metadata_dir_);
 }
 
+bool ImageManager::DisableAllImages() {
+    if (!MetadataExists(metadata_dir_)) {
+        return true;
+    }
+    auto metadata = OpenMetadata(metadata_dir_);
+    if (!metadata) {
+        return false;
+    }
+
+    bool ok = true;
+    for (const auto& partition : metadata->partitions) {
+        auto partition_name = GetPartitionName(partition);
+        ok &= DisableImage(partition_name);
+    }
+    return ok;
+}
+
 bool ImageManager::Validate() {
     auto metadata = OpenMetadata(metadata_dir_);
     if (!metadata) {
diff --git a/fs_mgr/libfiemap/include/libfiemap/image_manager.h b/fs_mgr/libfiemap/include/libfiemap/image_manager.h
index 0619c96a37..78e3080d76 100644
--- a/fs_mgr/libfiemap/include/libfiemap/image_manager.h
+++ b/fs_mgr/libfiemap/include/libfiemap/image_manager.h
@@ -127,6 +127,10 @@ class IImageManager {
     // Find and remove all images and metadata for this manager.
     virtual bool RemoveAllImages() = 0;
 
+    // Finds and marks all images for deletion upon next reboot. This is used during recovery since
+    // we cannot mount /data
+    virtual bool DisableAllImages() = 0;
+
     virtual bool UnmapImageIfExists(const std::string& name);
 
     // Returns whether DisableImage() was called.
@@ -158,6 +162,7 @@ class ImageManager final : public IImageManager {
     bool MapImageWithDeviceMapper(const IPartitionOpener& opener, const std::string& name,
                                   std::string* dev) override;
     bool RemoveAllImages() override;
+    bool DisableAllImages() override;
     bool DisableImage(const std::string& name) override;
     bool RemoveDisabledImages() override;
     bool GetMappedImageDevice(const std::string& name, std::string* device) override;
diff --git a/fs_mgr/libfstab/fstab.cpp b/fs_mgr/libfstab/fstab.cpp
index 010fbc81d1..ec23ce5cf1 100644
--- a/fs_mgr/libfstab/fstab.cpp
+++ b/fs_mgr/libfstab/fstab.cpp
@@ -209,6 +209,8 @@ bool ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
         CheckFlag("metadata_csum", ext_meta_csum);
         CheckFlag("fscompress", fs_compress);
         CheckFlag("overlayfs_remove_missing_lowerdir", overlayfs_remove_missing_lowerdir);
+        CheckFlag("overlay=on", overlay_on);
+        CheckFlag("overlay=off", overlay_off);
 
 #undef CheckFlag
 
diff --git a/fs_mgr/libfstab/include/fstab/fstab.h b/fs_mgr/libfstab/include/fstab/fstab.h
index 0ff3188d42..4924ae3816 100644
--- a/fs_mgr/libfstab/include/fstab/fstab.h
+++ b/fs_mgr/libfstab/include/fstab/fstab.h
@@ -87,6 +87,8 @@ struct FstabEntry {
         bool fs_compress : 1;
         bool overlayfs_remove_missing_lowerdir : 1;
         bool is_zoned : 1;
+        bool overlay_on : 1;
+        bool overlay_off : 1;
     } fs_mgr_flags = {};
 
     bool is_encryptable() const { return fs_mgr_flags.crypt; }
diff --git a/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp b/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
index 162c9fc34c..2e5933280b 100644
--- a/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
+++ b/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
@@ -15,6 +15,7 @@
  *
  */
 
+#include <functional>
 #include <fuzzer/FuzzedDataProvider.h>
 #include <liblp/builder.h>
 #include <liblp/property_fetcher.h>
diff --git a/fs_mgr/liblp/fuzzer/liblp_super_layout_builder_fuzzer.cpp b/fs_mgr/liblp/fuzzer/liblp_super_layout_builder_fuzzer.cpp
index a6642d7ba9..a93e68e233 100644
--- a/fs_mgr/liblp/fuzzer/liblp_super_layout_builder_fuzzer.cpp
+++ b/fs_mgr/liblp/fuzzer/liblp_super_layout_builder_fuzzer.cpp
@@ -17,6 +17,7 @@
 
 #include <android-base/unique_fd.h>
 #include <fcntl.h>
+#include <functional>
 #include <fuzzer/FuzzedDataProvider.h>
 #include <liblp/metadata_format.h>
 #include <liblp/super_layout_builder.h>
diff --git a/fs_mgr/libsnapshot/Android.bp b/fs_mgr/libsnapshot/Android.bp
index 966696b05b..af1991a7fc 100644
--- a/fs_mgr/libsnapshot/Android.bp
+++ b/fs_mgr/libsnapshot/Android.bp
@@ -308,17 +308,15 @@ cc_test {
         "vts",
         "general-tests",
     ],
-    compile_multilib: "both",
-    multilib: {
-        lib32: {
-            suffix: "32",
-        },
-        lib64: {
-            suffix: "64",
-        },
-    },
+    compile_multilib: "first",
     test_options: {
         min_shipping_api_level: 30,
+        test_runner_options: [
+            {
+                name: "force-no-test-error",
+                value: "false",
+            },
+        ],
     },
 }
 
@@ -374,11 +372,15 @@ cc_binary {
     srcs: [
         "snapshotctl.cpp",
         "scratch_super.cpp",
+        "android/snapshot/snapshot.proto",
     ],
     static_libs: [
         "libbrotli",
         "libfstab",
         "libz",
+        "libavb",
+        "libfs_avb",
+        "libcrypto_static",
         "update_metadata-protos",
     ],
     shared_libs: [
@@ -488,7 +490,10 @@ cc_binary {
     host_supported: true,
     device_supported: false,
 
-    srcs: ["libsnapshot_cow/create_cow.cpp"],
+    srcs: [
+        "libsnapshot_cow/create_cow.cpp",
+        "android/snapshot/snapshot.proto",
+    ],
 
     cflags: [
         "-Wall",
@@ -498,14 +503,21 @@ cc_binary {
     static_libs: [
         "liblog",
         "libbase",
+        "libfstab",
         "libext4_utils",
         "libsnapshot_cow",
         "libcrypto",
         "libbrotli",
         "libz",
+        "libdm",
         "liblz4",
         "libzstd",
         "libgflags",
+        "libavb",
+        "libext2_uuid",
+        "libfs_avb",
+        "libcrypto",
+        "libprotobuf-cpp-lite",
     ],
     shared_libs: [
     ],
diff --git a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
index 5fb71a37b7..94d8e9fc44 100644
--- a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
+++ b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
@@ -17,7 +17,6 @@ package android.snapshot;
 
 option optimize_for = LITE_RUNTIME;
 
-// Next: 4
 enum SnapshotState {
     // No snapshot is found.
     NONE = 0;
@@ -34,7 +33,6 @@ enum SnapshotState {
     MERGE_COMPLETED = 3;
 }
 
-// Next: 3
 enum MergePhase {
     // No merge is in progress.
     NO_MERGE = 0;
@@ -46,7 +44,6 @@ enum MergePhase {
     SECOND_PHASE = 2;
 }
 
-// Next: 13
 message SnapshotStatus {
     // Name of the snapshot. This is usually the name of the snapshotted
     // logical partition; for example, "system_b".
@@ -126,14 +123,11 @@ message SnapshotStatus {
 
     reserved 18;
 
-    // Blocks size to be verified at once
-    uint64 verify_block_size = 19;
+    reserved 19;
 
-    // Default value is 2, configures threads to do verification phase
-    uint32 num_verify_threads = 20;
+    reserved 20;
 }
 
-// Next: 8
 enum UpdateState {
     // No update or merge is in progress.
     None = 0;
@@ -162,7 +156,6 @@ enum UpdateState {
     Cancelled = 7;
 };
 
-// Next 14:
 //
 // To understand the source of each failure, read snapshot.cpp. To handle new
 // sources of failure, avoid reusing an existing code; add a new code instead.
@@ -190,7 +183,6 @@ enum MergeFailureCode {
     WrongMergeCountConsistencyCheck = 20;
 };
 
-// Next: 8
 message SnapshotUpdateStatus {
     UpdateState state = 1;
 
@@ -235,9 +227,17 @@ message SnapshotUpdateStatus {
 
     // Number of worker threads to serve I/O from dm-user
     uint32 num_worker_threads = 14;
+
+    // Block size to be verified after OTA reboot
+    uint64 verify_block_size = 15;
+
+    // Default value is 3, configures threads to do verification phase
+    uint32 num_verification_threads = 16;
+
+    // Skips verification of partitions
+    bool skip_verification = 17;
 }
 
-// Next: 10
 message SnapshotMergeReport {
     // Status of the update after the merge attempts.
     UpdateState state = 1;
@@ -283,3 +283,14 @@ message SnapshotMergeReport {
     // Size of v3 operation buffer. Needs to be determined during writer initialization
     uint64 estimated_op_count_max = 14;
 }
+
+message VerityHash {
+    // Partition name
+    string partition_name = 1;
+
+    // Salt used for verity hashes
+    string salt = 2;
+
+    // sha256 hash values of each block in the image
+    repeated bytes block_hash = 3;
+}
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/cow_format.h b/fs_mgr/libsnapshot/include/libsnapshot/cow_format.h
index 991e17cbbe..66f9a83277 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/cow_format.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/cow_format.h
@@ -329,6 +329,16 @@ struct BufferState {
     uint8_t read_ahead_state;
 } __attribute__((packed));
 
+constexpr size_t GetCowOpSize(size_t version) {
+    if (version == 3) {
+        return sizeof(CowOperationV3);
+    } else if (version == 2 || version == 1) {
+        return sizeof(CowOperationV2);
+    } else {
+        return 0;
+    }
+}
+
 // 2MB Scratch space used for read-ahead
 static constexpr uint64_t BUFFER_REGION_DEFAULT_SIZE = (1ULL << 21);
 
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/mock_snapshot.h b/fs_mgr/libsnapshot/include/libsnapshot/mock_snapshot.h
index ca45d2fad8..5ad988519b 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/mock_snapshot.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/mock_snapshot.h
@@ -63,6 +63,7 @@ class MockSnapshotManager : public ISnapshotManager {
     MOCK_METHOD(ISnapshotMergeStats*, GetSnapshotMergeStatsInstance, (), (override));
     MOCK_METHOD(std::string, ReadSourceBuildFingerprint, (), (override));
     MOCK_METHOD(void, SetMergeStatsFeatures, (ISnapshotMergeStats*), (override));
+    MOCK_METHOD(bool, IsCancelUpdateSafe, (), (override));
 };
 
 }  // namespace android::snapshot
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
index de20526310..4520b21a96 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
@@ -88,6 +88,13 @@ enum class CreateResult : unsigned int {
     NOT_CREATED,
 };
 
+enum class CancelResult : unsigned int {
+    OK,
+    ERROR,
+    LIVE_SNAPSHOTS,
+    NEEDS_MERGE,
+};
+
 class ISnapshotManager {
   public:
     // Dependency injection for testing.
@@ -125,6 +132,10 @@ class ISnapshotManager {
     // Cancel an update; any snapshots will be deleted. This is allowed if the
     // state == Initiated, None, or Unverified (before rebooting to the new
     // slot).
+    //
+    // In recovery, it will cancel an update even if a merge is in progress.
+    // Thus, it should only be called if a new OTA will be sideloaded. The
+    // safety can be checked via IsCancelUpdateSafe().
     virtual bool CancelUpdate() = 0;
 
     // Mark snapshot writes as having completed. After this, new snapshots cannot
@@ -301,6 +312,9 @@ class ISnapshotManager {
 
     // Return the associated ISnapshotMergeStats instance. Never null.
     virtual ISnapshotMergeStats* GetSnapshotMergeStatsInstance() = 0;
+
+    // Return whether cancelling an update is safe. This is for use in recovery.
+    virtual bool IsCancelUpdateSafe() = 0;
 };
 
 class SnapshotManager final : public ISnapshotManager {
@@ -390,6 +404,7 @@ class SnapshotManager final : public ISnapshotManager {
     bool UnmapAllSnapshots() override;
     std::string ReadSourceBuildFingerprint() override;
     void SetMergeStatsFeatures(ISnapshotMergeStats* stats) override;
+    bool IsCancelUpdateSafe() override;
 
     // We can't use WaitForFile during first-stage init, because ueventd is not
     // running and therefore will not automatically create symlinks. Instead,
@@ -403,9 +418,19 @@ class SnapshotManager final : public ISnapshotManager {
     // first-stage to decide whether to launch snapuserd.
     bool IsSnapuserdRequired();
 
-    // This is primarily used to device reboot. If OTA update is in progress,
-    // init will avoid killing processes
-    bool IsUserspaceSnapshotUpdateInProgress();
+    // This is primarily invoked during device reboot after an OTA update.
+    //
+    // a: Check if the partitions are mounted off snapshots.
+    //
+    // b: Store all dynamic partitions which are mounted off snapshots. This
+    // is used to unmount the partition.
+    bool IsUserspaceSnapshotUpdateInProgress(std::vector<std::string>& dynamic_partitions);
+
+    // Pause the snapshot merge.
+    bool PauseSnapshotMerge();
+
+    // Resume the snapshot merge.
+    bool ResumeSnapshotMerge();
 
     enum class SnapshotDriver {
         DM_SNAPSHOT,
@@ -444,6 +469,7 @@ class SnapshotManager final : public ISnapshotManager {
     FRIEND_TEST(SnapshotUpdateTest, SpaceSwapUpdate);
     FRIEND_TEST(SnapshotUpdateTest, InterruptMergeDuringPhaseUpdate);
     FRIEND_TEST(SnapshotUpdateTest, MapAllSnapshotsWithoutSlotSwitch);
+    FRIEND_TEST(SnapshotUpdateTest, CancelInRecovery);
     friend class SnapshotTest;
     friend class SnapshotUpdateTest;
     friend class FlashAfterUpdateTest;
@@ -743,12 +769,8 @@ class SnapshotManager final : public ISnapshotManager {
     // Unmap a dm-user device for user space snapshots
     bool UnmapUserspaceSnapshotDevice(LockedFile* lock, const std::string& snapshot_name);
 
-    // If there isn't a previous update, return true. |needs_merge| is set to false.
-    // If there is a previous update but the device has not boot into it, tries to cancel the
-    //   update and delete any snapshots. Return true if successful. |needs_merge| is set to false.
-    // If there is a previous update and the device has boot into it, do nothing and return true.
-    //   |needs_merge| is set to true.
-    bool TryCancelUpdate(bool* needs_merge);
+    CancelResult TryCancelUpdate();
+    CancelResult IsCancelUpdateSafe(UpdateState state);
 
     // Helper for CreateUpdateSnapshots.
     // Creates all underlying images, COW partitions and snapshot files. Does not initialize them.
@@ -837,12 +859,21 @@ class SnapshotManager final : public ISnapshotManager {
     // Check if direct reads are enabled for the source image
     bool UpdateUsesODirect(LockedFile* lock);
 
+    // Check if we skip the verification of the target image
+    bool UpdateUsesSkipVerification(LockedFile* lock);
+
     // Get value of maximum cow op merge size
     uint32_t GetUpdateCowOpMergeSize(LockedFile* lock);
 
     // Get number of threads to perform post OTA boot verification
     uint32_t GetUpdateWorkerCount(LockedFile* lock);
 
+    // Get the verification block size
+    uint32_t GetVerificationBlockSize(LockedFile* lock);
+
+    // Get the number of verification threads
+    uint32_t GetNumVerificationThreads(LockedFile* lock);
+
     // Wrapper around libdm, with diagnostics.
     bool DeleteDeviceIfExists(const std::string& name,
                               const std::chrono::milliseconds& timeout_ms = {});
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stats.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stats.h
index 8a70400352..79443b226b 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stats.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stats.h
@@ -64,6 +64,7 @@ class SnapshotMergeStats : public ISnapshotMergeStats {
   public:
     // Not thread safe.
     static SnapshotMergeStats* GetInstance(SnapshotManager& manager);
+    SnapshotMergeStats(const std::string& path);
 
     // ISnapshotMergeStats overrides
     bool Start() override;
@@ -88,7 +89,6 @@ class SnapshotMergeStats : public ISnapshotMergeStats {
   private:
     bool ReadState();
     bool DeleteState();
-    SnapshotMergeStats(const std::string& path);
 
     std::string path_;
     SnapshotMergeReport report_;
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stub.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stub.h
index 1c9b40368e..e586bbd5a4 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stub.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot_stub.h
@@ -60,6 +60,7 @@ class SnapshotManagerStub : public ISnapshotManager {
     bool UnmapAllSnapshots() override;
     std::string ReadSourceBuildFingerprint() override;
     void SetMergeStatsFeatures(ISnapshotMergeStats* stats) override;
+    bool IsCancelUpdateSafe() override;
 };
 
 }  // namespace android::snapshot
diff --git a/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp b/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
index 6516499481..127735d014 100644
--- a/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
+++ b/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
@@ -17,6 +17,7 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <algorithm>
 #include <optional>
 #include <unordered_map>
 #include <unordered_set>
diff --git a/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp b/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
index 5497b72329..b15e6ab9cb 100644
--- a/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
+++ b/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
@@ -8,6 +8,7 @@
 
 #include <condition_variable>
 #include <cstring>
+#include <fstream>
 #include <future>
 #include <iostream>
 #include <limits>
@@ -17,26 +18,31 @@
 #include <unordered_map>
 #include <vector>
 
+#include <android-base/chrono_utils.h>
 #include <android-base/file.h>
+#include <android-base/hex.h>
 #include <android-base/logging.h>
+#include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
+#include <android-base/strings.h>
 #include <android-base/unique_fd.h>
+#include <android/snapshot/snapshot.pb.h>
 #include <ext4_utils/ext4_utils.h>
-#include <storage_literals/storage_literals.h>
-
-#include <android-base/chrono_utils.h>
-#include <android-base/scopeguard.h>
-#include <android-base/strings.h>
-
+#include <fs_avb/fs_avb_util.h>
 #include <gflags/gflags.h>
 #include <libsnapshot/cow_writer.h>
-
 #include <openssl/sha.h>
+#include <storage_literals/storage_literals.h>
 
 DEFINE_string(source, "", "Source partition image");
 DEFINE_string(target, "", "Target partition image");
+DEFINE_string(
+        output_dir, "",
+        "Output directory to write the patch file to. Defaults to current working directory if "
+        "not set.");
 DEFINE_string(compression, "lz4",
               "Compression algorithm. Default is set to lz4. Available options: lz4, zstd, gz");
+DEFINE_bool(merkel_tree, false, "If true, source image hash is obtained from verity merkel tree");
 
 namespace android {
 namespace snapshot {
@@ -51,7 +57,8 @@ using android::snapshot::ICowWriter;
 class CreateSnapshot {
   public:
     CreateSnapshot(const std::string& src_file, const std::string& target_file,
-                   const std::string& patch_file, const std::string& compression);
+                   const std::string& patch_file, const std::string& compression,
+                   const bool& merkel_tree);
     bool CreateSnapshotPatch();
 
   private:
@@ -108,6 +115,14 @@ class CreateSnapshot {
     bool WriteOrderedSnapshots();
     bool WriteNonOrderedSnapshots();
     bool VerifyMergeOrder();
+
+    bool CalculateDigest(const void* buffer, size_t size, const void* salt, uint32_t salt_length,
+                         uint8_t* digest);
+    bool ParseSourceMerkelTree();
+
+    bool use_merkel_tree_ = false;
+    std::vector<uint8_t> target_salt_;
+    std::vector<uint8_t> source_salt_;
 };
 
 void CreateSnapshotLogger(android::base::LogId, android::base::LogSeverity severity, const char*,
@@ -120,8 +135,12 @@ void CreateSnapshotLogger(android::base::LogId, android::base::LogSeverity sever
 }
 
 CreateSnapshot::CreateSnapshot(const std::string& src_file, const std::string& target_file,
-                               const std::string& patch_file, const std::string& compression)
-    : src_file_(src_file), target_file_(target_file), patch_file_(patch_file) {
+                               const std::string& patch_file, const std::string& compression,
+                               const bool& merkel_tree)
+    : src_file_(src_file),
+      target_file_(target_file),
+      patch_file_(patch_file),
+      use_merkel_tree_(merkel_tree) {
     if (!compression.empty()) {
         compression_ = compression;
     }
@@ -156,7 +175,76 @@ bool CreateSnapshot::FindSourceBlockHash() {
     if (!PrepareParse(src_file_, false)) {
         return false;
     }
-    return ParsePartition();
+
+    if (use_merkel_tree_) {
+        return ParseSourceMerkelTree();
+    } else {
+        return ParsePartition();
+    }
+}
+
+bool CreateSnapshot::CalculateDigest(const void* buffer, size_t size, const void* salt,
+                                     uint32_t salt_length, uint8_t* digest) {
+    SHA256_CTX ctx;
+    if (SHA256_Init(&ctx) != 1) {
+        return false;
+    }
+    if (SHA256_Update(&ctx, salt, salt_length) != 1) {
+        return false;
+    }
+    if (SHA256_Update(&ctx, buffer, size) != 1) {
+        return false;
+    }
+    if (SHA256_Final(digest, &ctx) != 1) {
+        return false;
+    }
+    return true;
+}
+
+bool CreateSnapshot::ParseSourceMerkelTree() {
+    std::string fname = android::base::Basename(target_file_.c_str());
+    std::string partitionName = fname.substr(0, fname.find(".img"));
+
+    auto vbmeta = android::fs_mgr::LoadAndVerifyVbmetaByPath(
+            target_file_, partitionName, "", true, false, false, nullptr, nullptr, nullptr);
+    if (vbmeta == nullptr) {
+        LOG(ERROR) << "LoadAndVerifyVbmetaByPath failed for partition: " << partitionName;
+        return false;
+    }
+    auto descriptor = android::fs_mgr::GetHashtreeDescriptor(partitionName, std::move(*vbmeta));
+    if (descriptor == nullptr) {
+        LOG(ERROR) << "GetHashtreeDescriptor failed for partition: " << partitionName;
+        return false;
+    }
+
+    std::fstream input(src_file_, std::ios::in | std::ios::binary);
+    VerityHash hash;
+    if (!hash.ParseFromIstream(&input)) {
+        LOG(ERROR) << "Failed to parse message.";
+        return false;
+    }
+
+    std::string source_salt = hash.salt();
+    source_salt.erase(std::remove(source_salt.begin(), source_salt.end(), '\0'), source_salt.end());
+    if (!android::base::HexToBytes(source_salt, &source_salt_)) {
+        LOG(ERROR) << "HexToBytes conversion failed for source salt: " << source_salt;
+        return false;
+    }
+
+    std::string target_salt = descriptor->salt;
+    if (!android::base::HexToBytes(target_salt, &target_salt_)) {
+        LOG(ERROR) << "HexToBytes conversion failed for target salt: " << target_salt;
+        return false;
+    }
+
+    std::vector<uint8_t> digest(32, 0);
+    for (int i = 0; i < hash.block_hash_size(); i++) {
+        CalculateDigest(hash.block_hash(i).data(), hash.block_hash(i).size(), target_salt_.data(),
+                        target_salt_.size(), digest.data());
+        source_block_hash_[ToHexString(digest.data(), 32)] = i;
+    }
+
+    return true;
 }
 
 /*
@@ -386,10 +474,22 @@ bool CreateSnapshot::ReadBlocks(off_t offset, const int skip_blocks, const uint6
         while (num_blocks) {
             const void* bufptr = (char*)buffer.get() + buffer_offset;
             uint64_t blkindex = foffset / BLOCK_SZ;
+            std::string hash;
+
+            if (create_snapshot_patch_ && use_merkel_tree_) {
+                std::vector<uint8_t> digest(32, 0);
+                CalculateDigest(bufptr, BLOCK_SZ, source_salt_.data(), source_salt_.size(),
+                                digest.data());
+                std::vector<uint8_t> final_digest(32, 0);
+                CalculateDigest(digest.data(), digest.size(), target_salt_.data(),
+                                target_salt_.size(), final_digest.data());
 
-            uint8_t checksum[32];
-            SHA256(bufptr, BLOCK_SZ, checksum);
-            std::string hash = ToHexString(checksum, sizeof(checksum));
+                hash = ToHexString(final_digest.data(), final_digest.size());
+            } else {
+                uint8_t checksum[32];
+                SHA256(bufptr, BLOCK_SZ, checksum);
+                hash = ToHexString(checksum, sizeof(checksum));
+            }
 
             if (create_snapshot_patch_) {
                 PrepareMergeBlock(bufptr, blkindex, hash);
@@ -474,12 +574,15 @@ SYNOPSIS
 
     source.img -> Source partition image
     target.img -> Target partition image
-    compressoin -> compression algorithm. Default set to lz4. Supported types are gz, lz4, zstd.
+    compression -> compression algorithm. Default set to lz4. Supported types are gz, lz4, zstd.
+    merkel_tree -> If true, source image hash is obtained from verity merkel tree.
+    output_dir -> Output directory to write the patch file to. Defaults to current working directory if not set.
 
 EXAMPLES
 
    $ create_snapshot $SOURCE_BUILD/system.img $TARGET_BUILD/system.img
    $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --compression="zstd"
+   $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --merkel_tree --output_dir=/tmp/create_snapshot_output
 
 )";
 
@@ -496,8 +599,11 @@ int main(int argc, char* argv[]) {
     std::string fname = android::base::Basename(FLAGS_target.c_str());
     auto parts = android::base::Split(fname, ".");
     std::string snapshotfile = parts[0] + ".patch";
+    if (!FLAGS_output_dir.empty()) {
+        snapshotfile = FLAGS_output_dir + "/" + snapshotfile;
+    }
     android::snapshot::CreateSnapshot snapshot(FLAGS_source, FLAGS_target, snapshotfile,
-                                               FLAGS_compression);
+                                               FLAGS_compression, FLAGS_merkel_tree);
 
     if (!snapshot.CreateSnapshotPatch()) {
         LOG(ERROR) << "Snapshot creation failed";
diff --git a/fs_mgr/libsnapshot/scratch_super.cpp b/fs_mgr/libsnapshot/scratch_super.cpp
index 93c4bbd994..2d1912394f 100644
--- a/fs_mgr/libsnapshot/scratch_super.cpp
+++ b/fs_mgr/libsnapshot/scratch_super.cpp
@@ -25,6 +25,13 @@
 #include <sys/vfs.h>
 #include <unistd.h>
 
+#include <algorithm>
+#include <filesystem>
+#include <memory>
+#include <optional>
+#include <string>
+#include <vector>
+
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/macros.h>
@@ -41,12 +48,6 @@
 #include <fstab/fstab.h>
 #include <liblp/builder.h>
 #include <storage_literals/storage_literals.h>
-#include <algorithm>
-#include <filesystem>
-#include <memory>
-#include <optional>
-#include <string>
-#include <vector>
 
 #include "device_info.h"
 #include "scratch_super.h"
@@ -60,9 +61,18 @@ namespace android {
 namespace snapshot {
 
 static bool UmountScratch() {
+    Fstab fstab;
+    if (!ReadFstabFromProcMounts(&fstab)) {
+        LOG(ERROR) << "Cannot read /proc/mounts";
+        return false;
+    }
+    if (GetEntryForMountPoint(&fstab, kOtaMetadataMount) == nullptr) {
+        return true;
+    }
+
     auto ota_dir = std::string(kOtaMetadataMount) + "/" + "ota";
-    std::error_code ec;
 
+    std::error_code ec;
     if (std::filesystem::remove_all(ota_dir, ec) == static_cast<std::uintmax_t>(-1)) {
         LOG(ERROR) << "Failed to remove OTA directory: " << ec.message();
         return false;
@@ -386,7 +396,7 @@ std::string MapScratchOtaMetadataPartition(const std::string& scratch_device) {
 }
 
 // Entry point to create a scratch device on super partition
-// This will create a 1MB space in super. The space will be
+// This will create a 2MB space in super. The space will be
 // from the current active slot. Ext4 filesystem will be created
 // on this scratch device and all the OTA related directories
 // will be created.
diff --git a/fs_mgr/libsnapshot/scratch_super.h b/fs_mgr/libsnapshot/scratch_super.h
index 3e6fe702fd..7a16f97d97 100644
--- a/fs_mgr/libsnapshot/scratch_super.h
+++ b/fs_mgr/libsnapshot/scratch_super.h
@@ -20,7 +20,7 @@ namespace snapshot {
 constexpr char kMkExt4[] = "/system/bin/mke2fs";
 constexpr char kOtaMetadataFileContext[] = "u:object_r:ota_metadata_file:s0";
 constexpr char kOtaMetadataMount[] = "/mnt/scratch_ota_metadata_super";
-const size_t kOtaMetadataPartitionSize = uint64_t(1 * 1024 * 1024);
+const size_t kOtaMetadataPartitionSize = uint64_t(2 * 1024 * 1024);
 constexpr char kPhysicalDevice[] = "/dev/block/by-name/";
 
 bool IsScratchOtaMetadataOnSuper();
diff --git a/fs_mgr/libsnapshot/scripts/Android.bp b/fs_mgr/libsnapshot/scripts/Android.bp
index 829f5bc921..b99da93774 100644
--- a/fs_mgr/libsnapshot/scripts/Android.bp
+++ b/fs_mgr/libsnapshot/scripts/Android.bp
@@ -29,3 +29,8 @@ python_binary_host {
         "snapshot_proto_python",
     ],
 }
+
+sh_binary_host {
+    name: "apply_update",
+    src: "apply-update.sh",
+}
diff --git a/fs_mgr/libsnapshot/scripts/apply-update.sh b/fs_mgr/libsnapshot/scripts/apply-update.sh
index 90b0119a2e..92bff3b935 100755
--- a/fs_mgr/libsnapshot/scripts/apply-update.sh
+++ b/fs_mgr/libsnapshot/scripts/apply-update.sh
@@ -1,77 +1,235 @@
 #!/bin/bash
 
-# This is a debug script to quicky test end-to-end flow
-# of snapshot updates without going through update-engine.
+# Copyright 2024 Google Inc. All rights reserved.
 #
-# Usage:
-#
-#  To update both dynamic and static partitions:
-#
-# ./system/core/fs_mgr/libsnapshot/apply_update.sh [--update-static-partitions] [--wipe]
-#
-# --update-static-partitions: This will update bootloader and static A/B
-# partitions
-# --wipe: Allows data wipe as part of update flow
-#
-#  To update dynamic partitions only (this should be used when static
-#  partitions are present in both the slots):
-#
-#  ./system/core/fs_mgr/libsnapshot/apply_update.sh
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
 #
+#     http://www.apache.org/licenses/LICENSE-2.0
 #
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
 
-rm -f $OUT/*.patch
+# apply_update.sh: Script to update the device in incremental way
 
-# Compare images and create snapshot patches. Currently, this
-# just compares two identical images in $OUT. In general, any source
-# and target images could be passed to create snapshot patches. However,
-# care must be taken to ensure source images are already present on the device.
-#
-# create_snapshot is a host side binary. Build it with `m create_snapshot`
-create_snapshot --source=$OUT/system.img --target=$OUT/system.img &
-create_snapshot --source=$OUT/product.img --target=$OUT/product.img &
-create_snapshot --source=$OUT/vendor.img --target=$OUT/vendor.img &
-create_snapshot --source=$OUT/system_ext.img --target=$OUT/system_ext.img &
-create_snapshot --source=$OUT/vendor_dlkm.img --target=$OUT/vendor_dlkm.img &
-create_snapshot --source=$OUT/system_dlkm.img --target=$OUT/system_dlkm.img &
-
-echo "Waiting for snapshot patch creation"
-wait $(jobs -p)
-echo "Snapshot patch creation completed"
+# Ensure OUT directory exists
+if [ -z "$OUT" ]; then
+  echo "Error: OUT environment variable not set." >&2
+  exit 1
+fi
+
+DEVICE_PATH="/data/verity-hash"
+HOST_PATH="$OUT/verity-hash"
+
+# Create the log file path
+log_file="$HOST_PATH/snapshot.log"
+
+# Function to log messages to both console and log file
+log_message() {
+    message="$1"
+    echo "$message"  # Print to stdout
+    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"  # Append to log file with timestamp
+}
+
+# Function to check for create_snapshot and build if needed
+ensure_create_snapshot() {
+  if ! command -v create_snapshot &> /dev/null; then
+    log_message "create_snapshot not found. Building..."
+    m create_snapshot
+    if [[ $? -ne 0 ]]; then
+      log_message "Error: Failed to build create_snapshot."
+      exit 1
+    fi
+  fi
+}
+
+ensure_create_snapshot
+
+# Function to flash static partitions
+flash_static_partitions() {
+  local wipe_flag="$1"
+  local flash_bootloader="$2"
+
+  if (( flash_bootloader )); then
+    fastboot flash bootloader "$OUT"/bootloader.img
+    fastboot reboot bootloader
+    sleep 1
+    fastboot flash radio "$OUT"/radio.img
+    fastboot reboot bootloader
+    sleep 1
+  fi
+  fastboot flashall --exclude-dynamic-partitions --disable-super-optimization --skip-reboot
+
+  if (( wipe_flag )); then
+      log_message "Wiping device..."
+      fastboot -w
+  fi
+  fastboot reboot
+}
+
+# Function to display the help message
+show_help() {
+  cat << EOF
+Usage: $0 [OPTIONS]
+
+This script updates an Android device with incremental flashing, optionally wiping data and flashing static partitions.
+
+Options:
+  --skip-static-partitions  Skip flashing static partitions (bootloader, radio, boot, vbmeta, dtbo and other static A/B partitions).
+                           * Requires manual update of static partitions on both A/B slots
+                             *before* using this flag.
+                           * Speeds up the update process and development iteration.
+                           * Ideal for development focused on the Android platform (AOSP,
+                             git_main).
+                           * Safe usage: First update static partitions on both slots, then
+                             use this flag for faster development iterations.
+                             Ex:
+                                1: Run this on both the slots - This will update the kernel and other static partitions:
+                                   $fastboot flashall --exclude-dynamic-partitions --disable-super-optimization --skip-reboot
+
+                                2: Update bootloader on both the slots:
+                                    $fastboot flash bootloader $OUT/bootloader.img --slot=all
+
+                                3: Update radio on both the slots:
+                                    $fastboot flash radio $OUT/radio.img --slot=all
+                            Now, the script can safely use this flag for update purpose.
+
+  --wipe                   Wipe user data during the update.
+  --boot_snapshot          Boot the device off snapshots - No data wipe is supported
+                              To revert back to original state - `adb shell snapshotctl revert-snapshots`
+  --help                   Display this help message.
+
+Environment Variables:
+  OUT                      Path to the directory containing build output.
+                           This is required for the script to function correctly.
 
-mv *.patch $OUT/
+Examples:
+  <Development workflow for any project in the platform and build with 'm' to create the images>
+
+  Update the device:
+  $0
+
+  Update the device, but skip flashing static partitions (see above for the usage):
+  $0 --skip-static-partitions
+
+  Update the device and wipe user data:
+  $0 --wipe
+
+  Display this help message:
+  $0 --help
+EOF
+}
+
+skip_static_partitions=0
+boot_snapshot=0
+flash_bootloader=1
+wipe_flag=0
+help_flag=0
+
+# Parse arguments
+for arg in "$@"; do
+  case "$arg" in
+    --skip-static-partitions)
+      skip_static_partitions=1
+      ;;
+    --wipe)
+      wipe_flag=1
+      ;;
+    --skip_bootloader)
+      flash_bootloader=0
+      ;;
+    --boot_snapshot)
+      boot_snapshot=1
+      ;;
+    --help)
+      help_flag=1
+      ;;
+    *)
+      echo "Unknown argument: $arg" >&2
+      help_flag=1
+      ;;
+  esac
+done
+
+# Check if help flag is set
+if (( help_flag )); then
+  show_help
+  exit 0
+fi
+
+rm -rf $HOST_PATH
 
 adb root
 adb wait-for-device
-adb shell mkdir -p /data/update/
-adb push $OUT/*.patch /data/update/
 
-if [[ "$2" == "--wipe" ]]; then
-  adb shell snapshotctl apply-update /data/update/ -w
+adb shell rm -rf $DEVICE_PATH
+adb shell mkdir -p $DEVICE_PATH
+
+echo "Extracting device source hash from dynamic partitions"
+adb shell snapshotctl dump-verity-hash $DEVICE_PATH
+adb pull -q $DEVICE_PATH $OUT/
+
+log_message "Entering directory:"
+
+# Navigate to the verity-hash directory
+cd "$HOST_PATH" || { log_message "Error: Could not navigate to $HOST_PATH"; exit 1; }
+
+pwd
+
+# Iterate over all .pb files using a for loop
+for pb_file in *.pb; do
+  # Extract the base filename without the .pb extension
+  base_filename="${pb_file%.*}"
+
+  # Construct the source and target file names
+  source_file="$pb_file"
+  target_file="$OUT/$base_filename.img"
+
+  # Construct the create_snapshot command using an array
+  snapshot_args=(
+    "create_snapshot"
+    "--source" "$source_file"
+    "--target" "$target_file"
+    "--merkel_tree"
+  )
+
+  # Log the command about to be executed
+  log_message "Running: ${snapshot_args[*]}"
+
+  "${snapshot_args[@]}" >> "$log_file" 2>&1 &
+done
+
+log_message "Waiting for snapshot patch creation"
+
+# Wait for all background processes to complete
+wait $(jobs -p)
+
+log_message "Snapshot patches created successfully"
+
+adb push -q $HOST_PATH/*.patch $DEVICE_PATH
+
+log_message "Applying update"
+
+if (( boot_snapshot)); then
+  adb shell snapshotctl map-snapshots $DEVICE_PATH
+elif (( wipe_flag )); then
+  adb shell snapshotctl apply-update $DEVICE_PATH -w
 else
-  adb shell snapshotctl apply-update /data/update/
+  adb shell snapshotctl apply-update $DEVICE_PATH
 fi
 
-# Check if the --update-static-partitions option is provided.
-# For quick developer workflow, there is no need to repeatedly
-# apply static partitions.
-if [[ "$1" == "--update-static-partitions" ]]; then
-  adb reboot bootloader
-  sleep 5
-  if [[ "$2" == "--wipe" ]]; then
-      fastboot -w
-  fi
-  fastboot flash bootloader $OUT/bootloader.img
-  sleep 1
-  fastboot reboot bootloader
-  sleep 1
-  fastboot flash radio $OUT/radio.img
-  sleep 1
-  fastboot reboot bootloader
-  sleep 1
-  fastboot flashall --exclude-dynamic-partitions --disable-super-optimization
+if (( skip_static_partitions )); then
+    log_message "Rebooting device - Skipping flashing static partitions"
+    adb reboot
 else
-  adb reboot
+    log_message "Rebooting device to bootloader"
+    adb reboot bootloader
+    log_message "Waiting to enter fastboot bootloader"
+    flash_static_partitions "$wipe_flag" "$flash_bootloader"
 fi
 
-echo "Update completed"
+log_message "Update completed"
diff --git a/fs_mgr/libsnapshot/snapshot.cpp b/fs_mgr/libsnapshot/snapshot.cpp
index ecf567eb84..fa2f569d20 100644
--- a/fs_mgr/libsnapshot/snapshot.cpp
+++ b/fs_mgr/libsnapshot/snapshot.cpp
@@ -191,14 +191,18 @@ static std::string GetSourceDeviceName(const std::string& partition_name) {
 }
 
 bool SnapshotManager::BeginUpdate() {
-    bool needs_merge = false;
-    if (!TryCancelUpdate(&needs_merge)) {
-        return false;
-    }
-    if (needs_merge) {
-        LOG(INFO) << "Wait for merge (if any) before beginning a new update.";
-        auto state = ProcessUpdateState();
-        LOG(INFO) << "Merged with state = " << state;
+    switch (TryCancelUpdate()) {
+        case CancelResult::OK:
+            break;
+        case CancelResult::NEEDS_MERGE: {
+            LOG(INFO) << "Wait for merge (if any) before beginning a new update.";
+            auto state = ProcessUpdateState();
+            LOG(INFO) << "Merged with end state: " << state;
+            break;
+        }
+        default:
+            LOG(ERROR) << "Cannot begin update, existing update cannot be cancelled.";
+            return false;
     }
 
     auto file = LockExclusive();
@@ -223,49 +227,82 @@ bool SnapshotManager::BeginUpdate() {
 }
 
 bool SnapshotManager::CancelUpdate() {
-    bool needs_merge = false;
-    if (!TryCancelUpdate(&needs_merge)) {
-        return false;
-    }
-    if (needs_merge) {
-        LOG(ERROR) << "Cannot cancel update after it has completed or started merging";
-    }
-    return !needs_merge;
+    return TryCancelUpdate() == CancelResult::OK;
 }
 
-bool SnapshotManager::TryCancelUpdate(bool* needs_merge) {
-    *needs_merge = false;
+CancelResult SnapshotManager::TryCancelUpdate() {
+    auto lock = LockExclusive();
+    if (!lock) return CancelResult::ERROR;
 
-    auto file = LockExclusive();
-    if (!file) return false;
+    UpdateState state = ReadUpdateState(lock.get());
+    CancelResult result = IsCancelUpdateSafe(state);
 
-    if (IsSnapshotWithoutSlotSwitch()) {
-        LOG(ERROR) << "Cannot cancel the snapshots as partitions are mounted off the snapshots on "
-                      "current slot.";
-        return false;
+    if (result != CancelResult::OK && device_->IsRecovery()) {
+        LOG(ERROR) << "Cancel result " << result << " will be overridden in recovery.";
+        result = CancelResult::OK;
+    }
+
+    switch (result) {
+        case CancelResult::OK:
+            LOG(INFO) << "Cancelling update from state: " << state;
+            RemoveAllUpdateState(lock.get());
+            RemoveInvalidSnapshots(lock.get());
+            break;
+        case CancelResult::NEEDS_MERGE:
+            LOG(ERROR) << "Cannot cancel an update while a merge is in progress.";
+            break;
+        case CancelResult::LIVE_SNAPSHOTS:
+            LOG(ERROR) << "Cannot cancel an update while snapshots are live.";
+            break;
+        case CancelResult::ERROR:
+            // Error was already reported.
+            break;
     }
+    return result;
+}
 
-    UpdateState state = ReadUpdateState(file.get());
-    if (state == UpdateState::None) {
-        RemoveInvalidSnapshots(file.get());
+bool SnapshotManager::IsCancelUpdateSafe() {
+    // This may be called in recovery, so ensure we have /metadata.
+    auto mount = EnsureMetadataMounted();
+    if (!mount || !mount->HasDevice()) {
         return true;
     }
 
-    if (state == UpdateState::Initiated) {
-        LOG(INFO) << "Update has been initiated, now canceling";
-        return RemoveAllUpdateState(file.get());
+    auto lock = LockExclusive();
+    if (!lock) {
+        return false;
     }
 
-    if (state == UpdateState::Unverified) {
-        // We completed an update, but it can still be canceled if we haven't booted into it.
-        auto slot = GetCurrentSlot();
-        if (slot != Slot::Target) {
-            LOG(INFO) << "Canceling previously completed updates (if any)";
-            return RemoveAllUpdateState(file.get());
+    UpdateState state = ReadUpdateState(lock.get());
+    return IsCancelUpdateSafe(state) == CancelResult::OK;
+}
+
+CancelResult SnapshotManager::IsCancelUpdateSafe(UpdateState state) {
+    if (IsSnapshotWithoutSlotSwitch()) {
+        return CancelResult::LIVE_SNAPSHOTS;
+    }
+
+    switch (state) {
+        case UpdateState::Merging:
+        case UpdateState::MergeNeedsReboot:
+        case UpdateState::MergeFailed:
+            return CancelResult::NEEDS_MERGE;
+        case UpdateState::Unverified: {
+            // We completed an update, but it can still be canceled if we haven't booted into it.
+            auto slot = GetCurrentSlot();
+            if (slot == Slot::Target) {
+                return CancelResult::LIVE_SNAPSHOTS;
+            }
+            return CancelResult::OK;
         }
+        case UpdateState::None:
+        case UpdateState::Initiated:
+        case UpdateState::Cancelled:
+            return CancelResult::OK;
+        default:
+            LOG(ERROR) << "Unknown state: " << state;
+            return CancelResult::ERROR;
     }
-    *needs_merge = true;
-    return true;
 }
 
 std::string SnapshotManager::ReadUpdateSourceSlotSuffix() {
@@ -314,9 +351,14 @@ bool SnapshotManager::RemoveAllUpdateState(LockedFile* lock, const std::function
 
     LOG(INFO) << "Removing all update state.";
 
-    if (!RemoveAllSnapshots(lock)) {
-        LOG(ERROR) << "Could not remove all snapshots";
-        return false;
+    if (ReadUpdateState(lock) != UpdateState::None) {
+        // Only call this if we're actually cancelling an update. It's not
+        // expected to yield anything otherwise, and firing up gsid on normal
+        // boot is expensive.
+        if (!RemoveAllSnapshots(lock)) {
+            LOG(ERROR) << "Could not remove all snapshots";
+            return false;
+        }
     }
 
     // It's okay if these fail:
@@ -1750,6 +1792,15 @@ bool SnapshotManager::PerformInitTransition(InitTransition transition,
         if (worker_count != 0) {
             snapuserd_argv->emplace_back("-worker_count=" + std::to_string(worker_count));
         }
+        uint32_t verify_block_size = GetVerificationBlockSize(lock.get());
+        if (verify_block_size != 0) {
+            snapuserd_argv->emplace_back("-verify_block_size=" + std::to_string(verify_block_size));
+        }
+        uint32_t num_verify_threads = GetNumVerificationThreads(lock.get());
+        if (num_verify_threads != 0) {
+            snapuserd_argv->emplace_back("-num_verify_threads=" +
+                                         std::to_string(num_verify_threads));
+        }
     }
 
     size_t num_cows = 0;
@@ -2054,11 +2105,22 @@ bool SnapshotManager::RemoveAllSnapshots(LockedFile* lock) {
     }
 
     if (ok || !has_mapped_cow_images) {
-        // Delete any image artifacts as a precaution, in case an update is
-        // being cancelled due to some corrupted state in an lp_metadata file.
-        // Note that we do not do this if some cow images are still mapped,
-        // since we must not remove backing storage if it's in use.
-        if (!EnsureImageManager() || !images_->RemoveAllImages()) {
+        if (!EnsureImageManager()) {
+            return false;
+        }
+
+        if (device_->IsRecovery()) {
+            // If a device is in recovery, we need to mark the snapshots for cleanup
+            // upon next reboot, since we cannot delete them here.
+            if (!images_->DisableAllImages()) {
+                LOG(ERROR) << "Could not remove all snapshot artifacts in recovery";
+                return false;
+            }
+        } else if (!images_->RemoveAllImages()) {
+            // Delete any image artifacts as a precaution, in case an update is
+            // being cancelled due to some corrupted state in an lp_metadata file.
+            // Note that we do not do this if some cow images are still mapped,
+            // since we must not remove backing storage if it's in use.
             LOG(ERROR) << "Could not remove all snapshot artifacts";
             return false;
         }
@@ -2172,6 +2234,11 @@ bool SnapshotManager::UpdateUsesODirect(LockedFile* lock) {
     return update_status.o_direct();
 }
 
+bool SnapshotManager::UpdateUsesSkipVerification(LockedFile* lock) {
+    SnapshotUpdateStatus update_status = ReadSnapshotUpdateStatus(lock);
+    return update_status.skip_verification();
+}
+
 uint32_t SnapshotManager::GetUpdateCowOpMergeSize(LockedFile* lock) {
     SnapshotUpdateStatus update_status = ReadSnapshotUpdateStatus(lock);
     return update_status.cow_op_merge_size();
@@ -2182,6 +2249,16 @@ uint32_t SnapshotManager::GetUpdateWorkerCount(LockedFile* lock) {
     return update_status.num_worker_threads();
 }
 
+uint32_t SnapshotManager::GetVerificationBlockSize(LockedFile* lock) {
+    SnapshotUpdateStatus update_status = ReadSnapshotUpdateStatus(lock);
+    return update_status.verify_block_size();
+}
+
+uint32_t SnapshotManager::GetNumVerificationThreads(LockedFile* lock) {
+    SnapshotUpdateStatus update_status = ReadSnapshotUpdateStatus(lock);
+    return update_status.num_verification_threads();
+}
+
 bool SnapshotManager::MarkSnapuserdFromSystem() {
     auto path = GetSnapuserdFromSystemPath();
 
@@ -3172,8 +3249,11 @@ bool SnapshotManager::WriteUpdateState(LockedFile* lock, UpdateState state,
         status.set_io_uring_enabled(old_status.io_uring_enabled());
         status.set_legacy_snapuserd(old_status.legacy_snapuserd());
         status.set_o_direct(old_status.o_direct());
+        status.set_skip_verification(old_status.skip_verification());
         status.set_cow_op_merge_size(old_status.cow_op_merge_size());
         status.set_num_worker_threads(old_status.num_worker_threads());
+        status.set_verify_block_size(old_status.verify_block_size());
+        status.set_num_verification_threads(old_status.num_verification_threads());
     }
     return WriteSnapshotUpdateStatus(lock, status);
 }
@@ -3552,6 +3632,10 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
             status.set_o_direct(true);
             LOG(INFO) << "o_direct for source image enabled";
         }
+        if (GetSkipVerificationProperty()) {
+            status.set_skip_verification(true);
+            LOG(INFO) << "skipping verification of images";
+        }
         if (is_legacy_snapuserd) {
             status.set_legacy_snapuserd(true);
             LOG(INFO) << "Setting legacy_snapuserd to true";
@@ -3560,7 +3644,10 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
                 android::base::GetUintProperty<uint32_t>("ro.virtual_ab.cow_op_merge_size", 0));
         status.set_num_worker_threads(
                 android::base::GetUintProperty<uint32_t>("ro.virtual_ab.num_worker_threads", 0));
-
+        status.set_verify_block_size(
+                android::base::GetUintProperty<uint32_t>("ro.virtual_ab.verify_block_size", 0));
+        status.set_num_verification_threads(
+                android::base::GetUintProperty<uint32_t>("ro.virtual_ab.num_verify_threads", 0));
     } else if (legacy_compression) {
         LOG(INFO) << "Virtual A/B using legacy snapuserd";
     } else {
@@ -3996,8 +4083,11 @@ bool SnapshotManager::Dump(std::ostream& os) {
     ss << "Using userspace snapshots: " << update_status.userspace_snapshots() << std::endl;
     ss << "Using io_uring: " << update_status.io_uring_enabled() << std::endl;
     ss << "Using o_direct: " << update_status.o_direct() << std::endl;
+    ss << "Using skip_verification: " << update_status.skip_verification() << std::endl;
     ss << "Cow op merge size (0 for uncapped): " << update_status.cow_op_merge_size() << std::endl;
     ss << "Worker thread count: " << update_status.num_worker_threads() << std::endl;
+    ss << "Num verification threads: " << update_status.num_verification_threads() << std::endl;
+    ss << "Verify block size: " << update_status.verify_block_size() << std::endl;
     ss << "Using XOR compression: " << GetXorCompressionEnabledProperty() << std::endl;
     ss << "Current slot: " << device_->GetSlotSuffix() << std::endl;
     ss << "Boot indicator: booting from " << GetCurrentSlot() << " slot" << std::endl;
@@ -4639,7 +4729,26 @@ std::string SnapshotManager::ReadSourceBuildFingerprint() {
     return status.source_build_fingerprint();
 }
 
-bool SnapshotManager::IsUserspaceSnapshotUpdateInProgress() {
+bool SnapshotManager::PauseSnapshotMerge() {
+    auto snapuserd_client = SnapuserdClient::TryConnect(kSnapuserdSocket, 5s);
+    if (snapuserd_client) {
+        // Pause the snapshot-merge
+        return snapuserd_client->PauseMerge();
+    }
+    return false;
+}
+
+bool SnapshotManager::ResumeSnapshotMerge() {
+    auto snapuserd_client = SnapuserdClient::TryConnect(kSnapuserdSocket, 5s);
+    if (snapuserd_client) {
+        // Resume the snapshot-merge
+        return snapuserd_client->ResumeMerge();
+    }
+    return false;
+}
+
+bool SnapshotManager::IsUserspaceSnapshotUpdateInProgress(
+        std::vector<std::string>& dynamic_partitions) {
     // We cannot grab /metadata/ota lock here as this
     // is in reboot path. See b/308900853
     //
@@ -4653,18 +4762,22 @@ bool SnapshotManager::IsUserspaceSnapshotUpdateInProgress() {
         LOG(ERROR) << "No dm-enabled block device is found.";
         return false;
     }
+
+    bool is_ota_in_progress = false;
     for (auto& partition : dm_block_devices) {
         std::string partition_name = partition.first + current_suffix;
         DeviceMapper::TargetInfo snap_target;
         if (!GetSingleTarget(partition_name, TableQuery::Status, &snap_target)) {
-            return false;
+            continue;
         }
         auto type = DeviceMapper::GetTargetType(snap_target.spec);
+        // Partition is mounted off snapshots
         if (type == "user") {
-            return true;
+            dynamic_partitions.emplace_back("/" + partition.first);
+            is_ota_in_progress = true;
         }
     }
-    return false;
+    return is_ota_in_progress;
 }
 
 bool SnapshotManager::BootFromSnapshotsWithoutSlotSwitch() {
diff --git a/fs_mgr/libsnapshot/snapshot_stats.cpp b/fs_mgr/libsnapshot/snapshot_stats.cpp
index 8e9d9c5f3b..e684d8798b 100644
--- a/fs_mgr/libsnapshot/snapshot_stats.cpp
+++ b/fs_mgr/libsnapshot/snapshot_stats.cpp
@@ -24,9 +24,12 @@ namespace android {
 namespace snapshot {
 
 SnapshotMergeStats* SnapshotMergeStats::GetInstance(SnapshotManager& parent) {
-    static SnapshotMergeStats g_instance(parent.GetMergeStateFilePath());
-    CHECK_EQ(g_instance.path_, parent.GetMergeStateFilePath());
-    return &g_instance;
+    static std::unique_ptr<SnapshotMergeStats> g_instance;
+
+    if (!g_instance || g_instance->path_ != parent.GetMergeStateFilePath()) {
+        g_instance = std::make_unique<SnapshotMergeStats>(parent.GetMergeStateFilePath());
+    }
+    return g_instance.get();
 }
 
 SnapshotMergeStats::SnapshotMergeStats(const std::string& path) : path_(path), running_(false) {}
diff --git a/fs_mgr/libsnapshot/snapshot_stub.cpp b/fs_mgr/libsnapshot/snapshot_stub.cpp
index 93541020e5..8edd44f8b4 100644
--- a/fs_mgr/libsnapshot/snapshot_stub.cpp
+++ b/fs_mgr/libsnapshot/snapshot_stub.cpp
@@ -188,4 +188,9 @@ void SnapshotManagerStub::SetMergeStatsFeatures(ISnapshotMergeStats*) {
     LOG(ERROR) << __FUNCTION__ << " should never be called.";
 }
 
+bool SnapshotManagerStub::IsCancelUpdateSafe() {
+    LOG(ERROR) << __FUNCTION__ << " should never be called.";
+    return false;
+}
+
 }  // namespace android::snapshot
diff --git a/fs_mgr/libsnapshot/snapshot_test.cpp b/fs_mgr/libsnapshot/snapshot_test.cpp
index 1a0d559792..7719a295c4 100644
--- a/fs_mgr/libsnapshot/snapshot_test.cpp
+++ b/fs_mgr/libsnapshot/snapshot_test.cpp
@@ -701,6 +701,7 @@ TEST_F(SnapshotTest, Merge) {
     }
 
     // We should not be able to cancel an update now.
+    ASSERT_EQ(sm->TryCancelUpdate(), CancelResult::NEEDS_MERGE);
     ASSERT_FALSE(sm->CancelUpdate());
 
     ASSERT_EQ(sm->ProcessUpdateState(), UpdateState::MergeCompleted);
@@ -1345,6 +1346,7 @@ class SnapshotUpdateTest : public SnapshotTest {
 
 TEST_F(SnapshotUpdateTest, SuperOtaMetadataTest) {
     auto info = new TestDeviceInfo(fake_super);
+    ASSERT_TRUE(CleanupScratchOtaMetadataIfPresent(info));
     ASSERT_TRUE(CreateScratchOtaMetadataOnSuper(info));
     std::string scratch_device = GetScratchOtaMetadataPartition();
     ASSERT_NE(scratch_device, "");
@@ -2324,6 +2326,38 @@ TEST_F(SnapshotUpdateTest, DataWipeRequiredInPackage) {
     }
 }
 
+// Cancel an OTA in recovery.
+TEST_F(SnapshotUpdateTest, CancelInRecovery) {
+    AddOperationForPartitions();
+    // Execute the update.
+    ASSERT_TRUE(sm->BeginUpdate());
+    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
+
+    // Write some data to target partitions.
+    ASSERT_TRUE(WriteSnapshots());
+
+    ASSERT_TRUE(sm->FinishedSnapshotWrites(true /* wipe */));
+
+    // Simulate shutting down the device.
+    ASSERT_TRUE(UnmapAll());
+
+    // Simulate a reboot into recovery.
+    auto test_device = new TestDeviceInfo(fake_super, "_b");
+    test_device->set_recovery(true);
+    auto new_sm = NewManagerForFirstStageMount(test_device);
+
+    EXPECT_EQ(new_sm->GetUpdateState(), UpdateState::Unverified);
+    ASSERT_FALSE(new_sm->IsCancelUpdateSafe());
+    ASSERT_TRUE(new_sm->CancelUpdate());
+
+    ASSERT_TRUE(new_sm->EnsureImageManager());
+    auto im = new_sm->image_manager();
+    ASSERT_NE(im, nullptr);
+    ASSERT_TRUE(im->IsImageDisabled("sys_b"));
+    ASSERT_TRUE(im->IsImageDisabled("vnd_b"));
+    ASSERT_TRUE(im->IsImageDisabled("prd_b"));
+}
+
 // Test update package that requests data wipe.
 TEST_F(SnapshotUpdateTest, DataWipeWithStaleSnapshots) {
     AddOperationForPartitions();
@@ -3071,6 +3105,20 @@ int main(int argc, char** argv) {
     ::testing::AddGlobalTestEnvironment(new ::android::snapshot::SnapshotTestEnvironment());
     gflags::ParseCommandLineFlags(&argc, &argv, false);
 
+    // During incremental flashing, snapshot updates are in progress.
+    //
+    // When snapshot update is in-progress, snapuserd daemon
+    // will be up and running. These tests will start and stop the daemon
+    // thereby interfering with the update and snapshot-merge progress.
+    // Hence, wait until the update is complete.
+    auto sm = android::snapshot::SnapshotManager::New();
+    std::vector<std::string> snapshot_partitions;
+    while (sm->IsUserspaceSnapshotUpdateInProgress(snapshot_partitions)) {
+        LOG(INFO) << "Waiting for: " << snapshot_partitions.size()
+                  << " partitions to finish snapshot-merge";
+        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
+    }
+
     bool vab_legacy = false;
     if (FLAGS_force_mode == "vab-legacy") {
         vab_legacy = true;
diff --git a/fs_mgr/libsnapshot/snapshotctl.cpp b/fs_mgr/libsnapshot/snapshotctl.cpp
index 46de991d00..32c8e37612 100644
--- a/fs_mgr/libsnapshot/snapshotctl.cpp
+++ b/fs_mgr/libsnapshot/snapshotctl.cpp
@@ -30,12 +30,15 @@
 #include <android-base/unique_fd.h>
 
 #include <android-base/chrono_utils.h>
+#include <android-base/hex.h>
 #include <android-base/parseint.h>
 #include <android-base/properties.h>
 #include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
+#include <android/snapshot/snapshot.pb.h>
 
+#include <fs_avb/fs_avb_util.h>
 #include <fs_mgr.h>
 #include <fs_mgr_dm_linear.h>
 #include <fstab/fstab.h>
@@ -44,9 +47,13 @@
 #include <libsnapshot/snapshot.h>
 #include <storage_literals/storage_literals.h>
 
+#include <openssl/sha.h>
+
 #include "partition_cow_creator.h"
 #include "scratch_super.h"
 
+#include "utility.h"
+
 #ifdef SNAPSHOTCTL_USERDEBUG_OR_ENG
 #include <BootControlClient.h>
 #endif
@@ -76,6 +83,10 @@ int Usage() {
                  "    Deprecated.\n"
                  "  map\n"
                  "    Map all partitions at /dev/block/mapper\n"
+                 "  pause-merge\n"
+                 "    Pause snapshot merge\n"
+                 "  resume-merge\n"
+                 "    Resume snapshot merge\n"
                  "  map-snapshots <directory where snapshot patches are present>\n"
                  "    Map all snapshots based on patches present in the directory\n"
                  "  unmap-snapshots\n"
@@ -89,7 +100,12 @@ int Usage() {
                  "  apply-update\n"
                  "    Apply the incremental OTA update wherein the snapshots are\n"
                  "    directly written to COW block device. This will bypass update-engine\n"
-                 "    and the device will be ready to boot from the target build.\n";
+                 "    and the device will be ready to boot from the target build.\n"
+                 "  dump-verity-hash <directory where verity merkel tree hashes are stored> "
+                 "[-verify]\n"
+                 "    Dump the verity merkel tree hashes at the specified path\n"
+                 "    -verify: Verify the dynamic partition blocks by comparing it with verity "
+                 "merkel tree\n";
     return EX_USAGE;
 }
 
@@ -527,6 +543,16 @@ bool UnmapCmdHandler(int, char** argv) {
     return SnapshotManager::New()->UnmapAllSnapshots();
 }
 
+bool PauseSnapshotMerge(int, char** argv) {
+    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
+    return SnapshotManager::New()->PauseSnapshotMerge();
+}
+
+bool ResumeSnapshotMerge(int, char** argv) {
+    android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
+    return SnapshotManager::New()->ResumeSnapshotMerge();
+}
+
 bool MergeCmdHandler(int /*argc*/, char** argv) {
     android::base::InitLogging(argv, TeeLogger(LogdLogger(), &StderrLogger));
     LOG(WARNING) << "Deprecated. Call update_engine_client --merge instead.";
@@ -631,6 +657,252 @@ bool ApplyUpdate(int argc, char** argv) {
     return true;
 }
 
+static bool GetBlockHashFromMerkelTree(android::base::borrowed_fd image_fd, uint64_t image_size,
+                                       uint32_t data_block_size, uint32_t hash_block_size,
+                                       uint64_t tree_offset,
+                                       std::vector<std::string>& out_block_hash) {
+    uint32_t padded_digest_size = 32;
+    if (image_size % data_block_size != 0) {
+        LOG(ERROR) << "Image_size: " << image_size
+                   << " not a multiple of data block size: " << data_block_size;
+        return false;
+    }
+
+    // vector of level-size and offset
+    std::vector<std::pair<uint64_t, uint64_t>> levels;
+    uint64_t data_block_count = image_size / data_block_size;
+    uint32_t digests_per_block = hash_block_size / padded_digest_size;
+    uint32_t level_block_count = data_block_count;
+    while (level_block_count > 1) {
+        uint32_t next_level_block_count =
+                (level_block_count + digests_per_block - 1) / digests_per_block;
+        levels.emplace_back(std::make_pair(next_level_block_count * hash_block_size, 0));
+        level_block_count = next_level_block_count;
+    }
+    // root digest
+    levels.emplace_back(std::make_pair(0, 0));
+    // initialize offset
+    for (auto level = std::prev(levels.end()); level != levels.begin(); level--) {
+        std::prev(level)->second = level->second + level->first;
+    }
+
+    // We just want level 0
+    auto level = levels.begin();
+    std::string hash_block(hash_block_size, '\0');
+    uint64_t block_offset = tree_offset + level->second;
+    uint64_t t_read_blocks = 0;
+    uint64_t blockidx = 0;
+    uint64_t num_hash_blocks = level->first / hash_block_size;
+    while ((t_read_blocks < num_hash_blocks) && (blockidx < data_block_count)) {
+        if (!android::base::ReadFullyAtOffset(image_fd, hash_block.data(), hash_block.size(),
+                                              block_offset)) {
+            LOG(ERROR) << "Failed to read tree block at offset: " << block_offset;
+            return false;
+        }
+
+        for (uint32_t offset = 0; offset < hash_block.size(); offset += padded_digest_size) {
+            std::string single_hash = hash_block.substr(offset, padded_digest_size);
+            out_block_hash.emplace_back(single_hash);
+
+            blockidx += 1;
+            if (blockidx >= data_block_count) {
+                break;
+            }
+        }
+
+        block_offset += hash_block_size;
+        t_read_blocks += 1;
+    }
+    return true;
+}
+
+static bool CalculateDigest(const void* buffer, size_t size, const void* salt, uint32_t salt_length,
+                            uint8_t* digest) {
+    SHA256_CTX ctx;
+    if (SHA256_Init(&ctx) != 1) {
+        return false;
+    }
+    if (SHA256_Update(&ctx, salt, salt_length) != 1) {
+        return false;
+    }
+    if (SHA256_Update(&ctx, buffer, size) != 1) {
+        return false;
+    }
+    if (SHA256_Final(digest, &ctx) != 1) {
+        return false;
+    }
+    return true;
+}
+
+bool verify_data_blocks(android::base::borrowed_fd fd, const std::vector<std::string>& block_hash,
+                        std::unique_ptr<android::fs_mgr::FsAvbHashtreeDescriptor>& descriptor,
+                        const std::vector<uint8_t>& salt) {
+    uint64_t data_block_count = descriptor->image_size / descriptor->data_block_size;
+    uint64_t foffset = 0;
+    uint64_t blk = 0;
+
+    std::string hash_block(descriptor->hash_block_size, '\0');
+    while (blk < data_block_count) {
+        if (!android::base::ReadFullyAtOffset(fd, hash_block.data(), descriptor->hash_block_size,
+                                              foffset)) {
+            LOG(ERROR) << "Failed to read from offset: " << foffset;
+            return false;
+        }
+
+        std::string digest(32, '\0');
+        CalculateDigest(hash_block.data(), descriptor->hash_block_size, salt.data(), salt.size(),
+                        reinterpret_cast<uint8_t*>(digest.data()));
+        if (digest != block_hash[blk]) {
+            LOG(ERROR) << "Hash mismatch for block: " << blk << " Expected: " << block_hash[blk]
+                       << " Received: " << digest;
+            return false;
+        }
+
+        foffset += descriptor->hash_block_size;
+        blk += 1;
+    }
+
+    return true;
+}
+
+bool DumpVerityHash(int argc, char** argv) {
+    android::base::InitLogging(argv, &android::base::KernelLogger);
+
+    if (::getuid() != 0) {
+        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
+        return EXIT_FAILURE;
+    }
+
+    if (argc < 3) {
+        std::cerr
+                << " dump-verity-hash <directory location where verity hash is saved> {-verify}\n";
+        return false;
+    }
+
+    bool verification_required = false;
+    std::string hash_file_path = argv[2];
+    bool metadata_on_super = false;
+    if (argc == 4) {
+        if (argv[3] == "-verify"s) {
+            verification_required = true;
+        }
+    }
+
+    auto& dm = android::dm::DeviceMapper::Instance();
+    auto dm_block_devices = dm.FindDmPartitions();
+    if (dm_block_devices.empty()) {
+        LOG(ERROR) << "No dm-enabled block device is found.";
+        return false;
+    }
+
+    android::fs_mgr::Fstab fstab;
+    if (!ReadDefaultFstab(&fstab)) {
+        LOG(ERROR) << "Failed to read fstab";
+        return false;
+    }
+
+    for (const auto& pair : dm_block_devices) {
+        std::string partition_name = pair.first;
+        android::fs_mgr::FstabEntry* fstab_entry =
+                GetEntryForMountPoint(&fstab, "/" + partition_name);
+        auto vbmeta = LoadAndVerifyVbmeta(*fstab_entry, "", nullptr, nullptr, nullptr);
+        if (vbmeta == nullptr) {
+            LOG(ERROR) << "LoadAndVerifyVbmetaByPath failed for partition: " << partition_name;
+            return false;
+        }
+
+        auto descriptor =
+                android::fs_mgr::GetHashtreeDescriptor(partition_name, std::move(*vbmeta));
+        if (descriptor == nullptr) {
+            LOG(ERROR) << "GetHashtreeDescriptor failed for partition: " << partition_name;
+            return false;
+        }
+
+        std::string device_path = fstab_entry->blk_device;
+        if (!dm.GetDmDevicePathByName(fstab_entry->blk_device, &device_path)) {
+            LOG(ERROR) << "Failed to resolve logical device path for: " << fstab_entry->blk_device;
+            return false;
+        }
+
+        android::base::unique_fd fd(open(device_path.c_str(), O_RDONLY));
+        if (fd < 0) {
+            LOG(ERROR) << "Failed to open file: " << device_path;
+            return false;
+        }
+        std::vector<std::string> block_hash;
+        if (!GetBlockHashFromMerkelTree(fd, descriptor->image_size, descriptor->data_block_size,
+                                        descriptor->hash_block_size, descriptor->tree_offset,
+                                        block_hash)) {
+            LOG(ERROR) << "GetBlockHashFromMerkelTree failed";
+            return false;
+        }
+
+        uint64_t dev_sz = lseek(fd, 0, SEEK_END);
+        uint64_t fec_size = dev_sz - descriptor->image_size;
+        if (fec_size % descriptor->data_block_size != 0) {
+            LOG(ERROR) << "fec_size: " << fec_size
+                       << " isn't multiple of: " << descriptor->data_block_size;
+            return false;
+        }
+
+        std::vector<uint8_t> salt;
+        const std::string& salt_str = descriptor->salt;
+        bool ok = android::base::HexToBytes(salt_str, &salt);
+        if (!ok) {
+            LOG(ERROR) << "HexToBytes conversion failed";
+            return false;
+        }
+        uint64_t file_offset = descriptor->image_size;
+        std::vector<uint8_t> hash_block(descriptor->hash_block_size, 0);
+        while (file_offset < dev_sz) {
+            if (!android::base::ReadFullyAtOffset(fd, hash_block.data(),
+                                                  descriptor->hash_block_size, file_offset)) {
+                LOG(ERROR) << "Failed to read tree block at offset: " << file_offset;
+                return false;
+            }
+            std::string digest(32, '\0');
+            CalculateDigest(hash_block.data(), descriptor->hash_block_size, salt.data(),
+                            salt.size(), reinterpret_cast<uint8_t*>(digest.data()));
+            block_hash.push_back(digest);
+            file_offset += descriptor->hash_block_size;
+            fec_size -= descriptor->hash_block_size;
+        }
+
+        if (fec_size != 0) {
+            LOG(ERROR) << "Checksum calculation pending: " << fec_size;
+            return false;
+        }
+
+        if (verification_required) {
+            if (!verify_data_blocks(fd, block_hash, descriptor, salt)) {
+                LOG(ERROR) << "verify_data_blocks failed";
+                return false;
+            }
+        }
+
+        VerityHash verity_hash;
+        verity_hash.set_partition_name(partition_name);
+        verity_hash.set_salt(salt_str);
+        for (auto hash : block_hash) {
+            verity_hash.add_block_hash(hash.data(), hash.size());
+        }
+        std::string hash_file = hash_file_path + "/" + partition_name + ".pb";
+        std::string content;
+        if (!verity_hash.SerializeToString(&content)) {
+            LOG(ERROR) << "Unable to serialize verity_hash";
+            return false;
+        }
+        if (!WriteStringToFileAtomic(content, hash_file)) {
+            PLOG(ERROR) << "Unable to write VerityHash to " << hash_file;
+            return false;
+        }
+
+        LOG(INFO) << partition_name
+                  << ": GetBlockHashFromMerkelTree success. Num Blocks: " << block_hash.size();
+    }
+    return true;
+}
+
 bool MapPrecreatedSnapshots(int argc, char** argv) {
     android::base::InitLogging(argv, &android::base::KernelLogger);
 
@@ -827,8 +1099,11 @@ static std::map<std::string, std::function<bool(int, char**)>> kCmdMap = {
         {"unmap-snapshots", UnMapPrecreatedSnapshots},
         {"delete-snapshots", DeletePrecreatedSnapshots},
         {"revert-snapshots", RemovePrecreatedSnapshots},
+        {"dump-verity-hash", DumpVerityHash},
 #endif
         {"unmap", UnmapCmdHandler},
+        {"pause-merge", PauseSnapshotMerge},
+        {"resume-merge", ResumeSnapshotMerge},
         // clang-format on
 };
 
diff --git a/fs_mgr/libsnapshot/snapuserd/Android.bp b/fs_mgr/libsnapshot/snapuserd/Android.bp
index 639116e8d9..9972bc76d1 100644
--- a/fs_mgr/libsnapshot/snapuserd/Android.bp
+++ b/fs_mgr/libsnapshot/snapuserd/Android.bp
@@ -88,6 +88,7 @@ cc_library_static {
         "libprocessgroup",
         "libprocessgroup_util",
         "libjsoncpp",
+        "liburing_cpp",
     ],
     export_include_dirs: ["include"],
     header_libs: [
@@ -136,6 +137,7 @@ cc_defaults {
         "libext4_utils",
         "liburing",
         "libzstd",
+        "liburing_cpp",
     ],
 
     header_libs: [
@@ -222,6 +224,7 @@ cc_defaults {
         "libjsoncpp",
         "liburing",
         "libz",
+        "liburing_cpp",
     ],
     include_dirs: [
         ".",
@@ -319,6 +322,7 @@ cc_binary_host {
         "libjsoncpp",
         "liburing",
         "libz",
+        "liburing_cpp",
     ],
     include_dirs: [
         ".",
diff --git a/fs_mgr/libsnapshot/snapuserd/include/snapuserd/snapuserd_client.h b/fs_mgr/libsnapshot/snapuserd/include/snapuserd/snapuserd_client.h
index ede92dd973..39850c08ac 100644
--- a/fs_mgr/libsnapshot/snapuserd/include/snapuserd/snapuserd_client.h
+++ b/fs_mgr/libsnapshot/snapuserd/include/snapuserd/snapuserd_client.h
@@ -108,6 +108,12 @@ class SnapuserdClient {
 
     // Notify init that snapuserd daemon is ready post selinux transition
     void NotifyTransitionDaemonIsReady();
+
+    // Pause Merge threads
+    bool PauseMerge();
+
+    // Resume Merge threads
+    bool ResumeMerge();
 };
 
 }  // namespace snapshot
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
index 7c820f32b4..693fe39b61 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
@@ -52,6 +52,7 @@ bool EnsureSnapuserdStarted() {
             return false;
         }
     }
+
     if (!android::base::WaitForProperty("snapuserd.ready", "true", 10s)) {
         LOG(ERROR) << "Timed out waiting for snapuserd to be ready.";
         return false;
@@ -389,5 +390,23 @@ void SnapuserdClient::NotifyTransitionDaemonIsReady() {
     }
 }
 
+bool SnapuserdClient::PauseMerge() {
+    if (!Sendmsg("pause_merge")) {
+        LOG(ERROR) << "Failed to pause snapshot merge.";
+        return false;
+    }
+    std::string response = Receivemsg();
+    return response == "success";
+}
+
+bool SnapuserdClient::ResumeMerge() {
+    if (!Sendmsg("resume_merge")) {
+        LOG(ERROR) << "Failed to resume snapshot merge.";
+        return false;
+    }
+    std::string response = Receivemsg();
+    return response == "success";
+}
+
 }  // namespace snapshot
 }  // namespace android
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
index 32e16cc809..d29223e4b8 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
@@ -20,8 +20,13 @@
 #include <gflags/gflags.h>
 #include <snapuserd/snapuserd_client.h>
 
+#include <storage_literals/storage_literals.h>
+#include "user-space-merge/snapuserd_core.h"
+
 #include "snapuserd_daemon.h"
 
+using namespace android::storage_literals;
+
 DEFINE_string(socket, android::snapshot::kSnapuserdSocket, "Named socket or socket path.");
 DEFINE_bool(no_socket, false,
             "If true, no socket is used. Each additional argument is an INIT message.");
@@ -30,8 +35,12 @@ DEFINE_bool(socket_handoff, false,
 DEFINE_bool(user_snapshot, false, "If true, user-space snapshots are used");
 DEFINE_bool(io_uring, false, "If true, io_uring feature is enabled");
 DEFINE_bool(o_direct, false, "If true, enable direct reads on source device");
+DEFINE_bool(skip_verification, false, "If true, skip verification of partitions");
 DEFINE_int32(cow_op_merge_size, 0, "number of operations to be processed at once");
-DEFINE_int32(worker_count, 4, "number of worker threads used to serve I/O requests to dm-user");
+DEFINE_int32(worker_count, android::snapshot::kNumWorkerThreads,
+             "number of worker threads used to serve I/O requests to dm-user");
+DEFINE_int32(verify_block_size, 1_MiB, "block sized used during verification of snapshots");
+DEFINE_int32(num_verify_threads, 3, "number of threads used during verification phase");
 
 namespace android {
 namespace snapshot {
@@ -95,9 +104,6 @@ bool Daemon::StartServerForUserspaceSnapshots(int arg_start, int argc, char** ar
     MaskAllSignalsExceptIntAndTerm();
 
     user_server_.SetServerRunning();
-    if (FLAGS_io_uring) {
-        user_server_.SetIouringEnabled();
-    }
 
     if (FLAGS_socket_handoff) {
         return user_server_.RunForSocketHandoff();
@@ -110,14 +116,20 @@ bool Daemon::StartServerForUserspaceSnapshots(int arg_start, int argc, char** ar
     }
     for (int i = arg_start; i < argc; i++) {
         auto parts = android::base::Split(argv[i], ",");
-
         if (parts.size() != 4) {
             LOG(ERROR) << "Malformed message, expected at least four sub-arguments.";
             return false;
         }
-        auto handler =
-                user_server_.AddHandler(parts[0], parts[1], parts[2], parts[3], FLAGS_worker_count,
-                                        FLAGS_o_direct, FLAGS_cow_op_merge_size);
+        HandlerOptions options = {
+                .num_worker_threads = FLAGS_worker_count,
+                .use_iouring = FLAGS_io_uring,
+                .o_direct = FLAGS_o_direct,
+                .skip_verification = FLAGS_skip_verification,
+                .cow_op_merge_size = static_cast<uint32_t>(FLAGS_cow_op_merge_size),
+                .verify_block_size = static_cast<uint32_t>(FLAGS_verify_block_size),
+                .num_verification_threads = static_cast<uint32_t>(FLAGS_num_verify_threads),
+        };
+        auto handler = user_server_.AddHandler(parts[0], parts[1], parts[2], parts[3], options);
         if (!handler || !user_server_.StartHandler(parts[0])) {
             return false;
         }
diff --git a/fs_mgr/libsnapshot/snapuserd/testing/dm_user_harness.h b/fs_mgr/libsnapshot/snapuserd/testing/dm_user_harness.h
index cf26bed037..507e8f3ff3 100644
--- a/fs_mgr/libsnapshot/snapuserd/testing/dm_user_harness.h
+++ b/fs_mgr/libsnapshot/snapuserd/testing/dm_user_harness.h
@@ -19,13 +19,13 @@
 #include "harness.h"
 #include "temp_device.h"
 
+#include <snapuserd/dm_user_block_server.h>
+
 namespace android {
 namespace snapshot {
 
 using android::base::unique_fd;
 
-class DmUserBlockServerFactory;
-
 class DmUserDevice final : public IUserDevice {
   public:
     explicit DmUserDevice(std::unique_ptr<Tempdevice>&& dev);
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.cpp
index ef4ba93fed..c15ac6b455 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.cpp
@@ -40,8 +40,9 @@ Extractor::Extractor(const std::string& base_path, const std::string& cow_path)
 
 bool Extractor::Init() {
     auto opener = factory_.CreateTestOpener(control_name_);
+    HandlerOptions options;
     handler_ = std::make_shared<SnapshotHandler>(control_name_, cow_path_, base_path_, base_path_,
-                                                 opener, 1, false, false, false, 0);
+                                                 opener, options);
     if (!handler_->InitCowDevice()) {
         return false;
     }
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.h
index 65285b1fa5..814bc85498 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/extractor.h
@@ -14,8 +14,8 @@
 
 #pragma once
 
+#include <future>
 #include <string>
-#include <thread>
 
 #include <android-base/unique_fd.h>
 #include "merge_worker.h"
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.cpp
index fdd9cce0cb..6b6f07187d 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.cpp
@@ -52,11 +52,9 @@ SnapshotHandlerManager::SnapshotHandlerManager() {
 std::shared_ptr<HandlerThread> SnapshotHandlerManager::AddHandler(
         const std::string& misc_name, const std::string& cow_device_path,
         const std::string& backing_device, const std::string& base_path_merge,
-        std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads, bool use_iouring,
-        bool o_direct, uint32_t cow_op_merge_size) {
-    auto snapuserd = std::make_shared<SnapshotHandler>(
-            misc_name, cow_device_path, backing_device, base_path_merge, opener, num_worker_threads,
-            use_iouring, perform_verification_, o_direct, cow_op_merge_size);
+        std::shared_ptr<IBlockServerOpener> opener, HandlerOptions options) {
+    auto snapuserd = std::make_shared<SnapshotHandler>(misc_name, cow_device_path, backing_device,
+                                                       base_path_merge, opener, options);
     if (!snapuserd->InitCowDevice()) {
         LOG(ERROR) << "Failed to initialize Snapuserd";
         return nullptr;
@@ -383,5 +381,25 @@ auto SnapshotHandlerManager::FindHandler(std::lock_guard<std::mutex>* proof_of_l
     return dm_users_.end();
 }
 
+void SnapshotHandlerManager::PauseMerge() {
+    std::lock_guard<std::mutex> guard(lock_);
+
+    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
+        if (!(*iter)->ThreadTerminated()) {
+            (*iter)->snapuserd()->PauseMergeThreads();
+        }
+    }
+}
+
+void SnapshotHandlerManager::ResumeMerge() {
+    std::lock_guard<std::mutex> guard(lock_);
+
+    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
+        if (!(*iter)->ThreadTerminated()) {
+            (*iter)->snapuserd()->ResumeMergeThreads();
+        }
+    }
+}
+
 }  // namespace snapshot
 }  // namespace android
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
index ecf5d5c38b..d10d8e8592 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
@@ -15,6 +15,7 @@
 #pragma once
 
 #include <memory>
+#include <mutex>
 #include <queue>
 #include <string>
 #include <thread>
@@ -26,6 +27,16 @@
 namespace android {
 namespace snapshot {
 
+struct HandlerOptions {
+    int num_worker_threads{};
+    bool use_iouring{};
+    bool o_direct{};
+    bool skip_verification{};
+    uint32_t cow_op_merge_size{};
+    uint32_t verify_block_size{};
+    uint32_t num_verification_threads{};
+};
+
 class SnapshotHandler;
 
 class HandlerThread {
@@ -52,11 +63,12 @@ class ISnapshotHandlerManager {
     virtual ~ISnapshotHandlerManager() {}
 
     // Add a new snapshot handler but do not start serving requests yet.
-    virtual std::shared_ptr<HandlerThread> AddHandler(
-            const std::string& misc_name, const std::string& cow_device_path,
-            const std::string& backing_device, const std::string& base_path_merge,
-            std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads, bool use_iouring,
-            bool o_direct, uint32_t cow_op_merge_size) = 0;
+    virtual std::shared_ptr<HandlerThread> AddHandler(const std::string& misc_name,
+                                                      const std::string& cow_device_path,
+                                                      const std::string& backing_device,
+                                                      const std::string& base_path_merge,
+                                                      std::shared_ptr<IBlockServerOpener> opener,
+                                                      HandlerOptions options) = 0;
 
     // Start serving requests on a snapshot handler.
     virtual bool StartHandler(const std::string& misc_name) = 0;
@@ -85,6 +97,12 @@ class ISnapshotHandlerManager {
 
     // Disable partition verification
     virtual void DisableVerification() = 0;
+
+    // Pause Merge threads
+    virtual void PauseMerge() = 0;
+
+    // Resume Merge threads
+    virtual void ResumeMerge() = 0;
 };
 
 class SnapshotHandlerManager final : public ISnapshotHandlerManager {
@@ -95,8 +113,8 @@ class SnapshotHandlerManager final : public ISnapshotHandlerManager {
                                               const std::string& backing_device,
                                               const std::string& base_path_merge,
                                               std::shared_ptr<IBlockServerOpener> opener,
-                                              int num_worker_threads, bool use_iouring,
-                                              bool o_direct, uint32_t cow_op_merge_size) override;
+                                              HandlerOptions options) override;
+
     bool StartHandler(const std::string& misc_name) override;
     bool DeleteHandler(const std::string& misc_name) override;
     bool InitiateMerge(const std::string& misc_name) override;
@@ -106,6 +124,8 @@ class SnapshotHandlerManager final : public ISnapshotHandlerManager {
     double GetMergePercentage() override;
     bool GetVerificationStatus() override;
     void DisableVerification() override { perform_verification_ = false; }
+    void PauseMerge() override;
+    void ResumeMerge() override;
 
   private:
     bool StartHandler(const std::shared_ptr<HandlerThread>& handler);
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
index febb4847d1..660082f73c 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
@@ -191,6 +191,9 @@ bool MergeWorker::MergeReplaceZeroOps() {
                                "down merge";
             return false;
         }
+
+        // Safe to check if there is a pause request.
+        snapuserd_->PauseMergeIfRequired();
     }
 
     // Any left over ops not flushed yet.
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
index 7c9a64ee4b..1f3d3a0dff 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
@@ -22,6 +22,8 @@
 #include <android-base/strings.h>
 #include <snapuserd/dm_user_block_server.h>
 
+#include <future>
+
 #include "merge_worker.h"
 #include "read_worker.h"
 #include "utility.h"
@@ -35,26 +37,21 @@ using android::base::unique_fd;
 
 SnapshotHandler::SnapshotHandler(std::string misc_name, std::string cow_device,
                                  std::string backing_device, std::string base_path_merge,
-                                 std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads,
-                                 bool use_iouring, bool perform_verification, bool o_direct,
-                                 uint32_t cow_op_merge_size) {
+                                 std::shared_ptr<IBlockServerOpener> opener,
+                                 HandlerOptions options) {
     misc_name_ = std::move(misc_name);
     cow_device_ = std::move(cow_device);
     backing_store_device_ = std::move(backing_device);
     block_server_opener_ = std::move(opener);
     base_path_merge_ = std::move(base_path_merge);
-    num_worker_threads_ = num_worker_threads;
-    is_io_uring_enabled_ = use_iouring;
-    perform_verification_ = perform_verification;
-    o_direct_ = o_direct;
-    cow_op_merge_size_ = cow_op_merge_size;
+    handler_options_ = options;
 }
 
 bool SnapshotHandler::InitializeWorkers() {
     for (int i = 0; i < num_worker_threads_; i++) {
         auto wt = std::make_unique<ReadWorker>(cow_device_, backing_store_device_, misc_name_,
                                                base_path_merge_, GetSharedPtr(),
-                                               block_server_opener_, o_direct_);
+                                               block_server_opener_, handler_options_.o_direct);
         if (!wt->Init()) {
             SNAP_LOG(ERROR) << "Thread initialization failed";
             return false;
@@ -62,13 +59,16 @@ bool SnapshotHandler::InitializeWorkers() {
 
         worker_threads_.push_back(std::move(wt));
     }
-    merge_thread_ = std::make_unique<MergeWorker>(cow_device_, misc_name_, base_path_merge_,
-                                                  GetSharedPtr(), cow_op_merge_size_);
+    merge_thread_ =
+            std::make_unique<MergeWorker>(cow_device_, misc_name_, base_path_merge_, GetSharedPtr(),
+                                          handler_options_.cow_op_merge_size);
 
-    read_ahead_thread_ = std::make_unique<ReadAhead>(cow_device_, backing_store_device_, misc_name_,
-                                                     GetSharedPtr(), cow_op_merge_size_);
+    read_ahead_thread_ =
+            std::make_unique<ReadAhead>(cow_device_, backing_store_device_, misc_name_,
+                                        GetSharedPtr(), handler_options_.cow_op_merge_size);
 
-    update_verify_ = std::make_unique<UpdateVerify>(misc_name_);
+    update_verify_ = std::make_unique<UpdateVerify>(misc_name_, handler_options_.verify_block_size,
+                                                    handler_options_.num_verification_threads);
 
     return true;
 }
@@ -429,7 +429,7 @@ bool SnapshotHandler::IsIouringSupported() {
     // During selinux init transition, libsnapshot will propagate the
     // status of io_uring enablement. As properties are not initialized,
     // we cannot query system property.
-    if (is_io_uring_enabled_) {
+    if (handler_options_.use_iouring) {
         return true;
     }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
index 2340b0b20d..9c5d58b941 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
@@ -24,15 +24,11 @@
 
 #include <condition_variable>
 #include <cstring>
-#include <future>
 #include <iostream>
-#include <limits>
 #include <mutex>
 #include <ostream>
 #include <string>
-#include <thread>
 #include <unordered_map>
-#include <unordered_set>
 #include <vector>
 
 #include <android-base/file.h>
@@ -48,6 +44,7 @@
 #include <snapuserd/snapuserd_kernel.h>
 #include <storage_literals/storage_literals.h>
 #include <system/thread_defs.h>
+#include <user-space-merge/handler_manager.h>
 #include "snapuserd_readahead.h"
 #include "snapuserd_verify.h"
 
@@ -104,8 +101,7 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
   public:
     SnapshotHandler(std::string misc_name, std::string cow_device, std::string backing_device,
                     std::string base_path_merge, std::shared_ptr<IBlockServerOpener> opener,
-                    int num_workers, bool use_iouring, bool perform_verification, bool o_direct,
-                    uint32_t cow_op_merge_size);
+                    HandlerOptions options);
     bool InitCowDevice();
     bool Start();
 
@@ -175,6 +171,9 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
     bool MergeInitiated() { return merge_initiated_; }
     bool MergeMonitored() { return merge_monitored_; }
     double GetMergePercentage() { return merge_completion_percentage_; }
+    void PauseMergeThreads();
+    void ResumeMergeThreads();
+    void PauseMergeIfRequired();
 
     // Merge Block State Transitions
     void SetMergeCompleted(size_t block_index);
@@ -245,16 +244,19 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
     bool merge_initiated_ = false;
     bool merge_monitored_ = false;
     bool attached_ = false;
-    bool is_io_uring_enabled_ = false;
     bool scratch_space_ = false;
     int num_worker_threads_ = kNumWorkerThreads;
     bool perform_verification_ = true;
     bool resume_merge_ = false;
     bool merge_complete_ = false;
-    bool o_direct_ = false;
-    uint32_t cow_op_merge_size_ = 0;
+    HandlerOptions handler_options_;
     std::unique_ptr<UpdateVerify> update_verify_;
     std::shared_ptr<IBlockServerOpener> block_server_opener_;
+
+    // Pause merge threads
+    bool pause_merge_ = false;
+    std::mutex pause_merge_lock_;
+    std::condition_variable pause_merge_cv_;
 };
 
 std::ostream& operator<<(std::ostream& os, MERGE_IO_TRANSITION value);
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
index 3bb8a30373..b21189c8e5 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
@@ -35,6 +35,7 @@
 #include <snapuserd/dm_user_block_server.h>
 #include <snapuserd/snapuserd_client.h>
 #include "snapuserd_server.h"
+#include "user-space-merge/handler_manager.h"
 #include "user-space-merge/snapuserd_core.h"
 
 namespace android {
@@ -126,7 +127,8 @@ bool UserSnapshotServer::Receivemsg(android::base::borrowed_fd fd, const std::st
             return Sendmsg(fd, "fail");
         }
 
-        auto handler = AddHandler(out[1], out[2], out[3], out[4], std::nullopt);
+        HandlerOptions options;
+        auto handler = AddHandler(out[1], out[2], out[3], out[4], options);
         if (!handler) {
             return Sendmsg(fd, "fail");
         }
@@ -227,6 +229,12 @@ bool UserSnapshotServer::Receivemsg(android::base::borrowed_fd fd, const std::st
             return Sendmsg(fd, "fail");
         }
         return Sendmsg(fd, "success");
+    } else if (cmd == "pause_merge") {
+        handlers_->PauseMerge();
+        return Sendmsg(fd, "success");
+    } else if (cmd == "resume_merge") {
+        handlers_->ResumeMerge();
+        return Sendmsg(fd, "success");
     } else {
         LOG(ERROR) << "Received unknown message type from client";
         Sendmsg(fd, "fail");
@@ -342,11 +350,11 @@ void UserSnapshotServer::Interrupt() {
     SetTerminating();
 }
 
-std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(
-        const std::string& misc_name, const std::string& cow_device_path,
-        const std::string& backing_device, const std::string& base_path_merge,
-        std::optional<uint32_t> num_worker_threads, const bool o_direct,
-        uint32_t cow_op_merge_size) {
+std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string& misc_name,
+                                                              const std::string& cow_device_path,
+                                                              const std::string& backing_device,
+                                                              const std::string& base_path_merge,
+                                                              HandlerOptions options) {
     // We will need multiple worker threads only during
     // device boot after OTA. For all other purposes,
     // one thread is sufficient. We don't want to consume
@@ -355,23 +363,19 @@ std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(
     //
     // During boot up, we need multiple threads primarily for
     // update-verification.
-    if (!num_worker_threads.has_value()) {
-        num_worker_threads = kNumWorkerThreads;
-    }
     if (is_socket_present_) {
-        num_worker_threads = 1;
+        options.num_worker_threads = 1;
     }
 
-    if (android::base::EndsWith(misc_name, "-init") || is_socket_present_ ||
-        (access(kBootSnapshotsWithoutSlotSwitch, F_OK) == 0)) {
+    if (options.skip_verification || android::base::EndsWith(misc_name, "-init") ||
+        is_socket_present_ || (access(kBootSnapshotsWithoutSlotSwitch, F_OK) == 0)) {
         handlers_->DisableVerification();
     }
 
     auto opener = block_server_factory_->CreateOpener(misc_name);
 
     return handlers_->AddHandler(misc_name, cow_device_path, backing_device, base_path_merge,
-                                 opener, num_worker_threads.value(), io_uring_enabled_, o_direct,
-                                 cow_op_merge_size);
+                                 opener, options);
 }
 
 bool UserSnapshotServer::WaitForSocket() {
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
index f002e8d9a6..73ce7b2cf0 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
@@ -51,7 +51,6 @@ class UserSnapshotServer {
     std::vector<struct pollfd> watched_fds_;
     bool is_socket_present_ = false;
     bool is_server_running_ = false;
-    bool io_uring_enabled_ = false;
     std::unique_ptr<ISnapshotHandlerManager> handlers_;
     std::unique_ptr<IBlockServerFactory> block_server_factory_;
 
@@ -87,17 +86,13 @@ class UserSnapshotServer {
                                               const std::string& cow_device_path,
                                               const std::string& backing_device,
                                               const std::string& base_path_merge,
-                                              std::optional<uint32_t> num_worker_threads,
-                                              bool o_direct = false,
-                                              uint32_t cow_op_merge_size = 0);
+                                              HandlerOptions options);
     bool StartHandler(const std::string& misc_name);
 
     void SetTerminating() { terminating_ = true; }
     void ReceivedSocketSignal() { received_socket_signal_ = true; }
     void SetServerRunning() { is_server_running_ = true; }
     bool IsServerRunning() { return is_server_running_; }
-    void SetIouringEnabled() { io_uring_enabled_ = true; }
-    bool IsIouringEnabled() { return io_uring_enabled_; }
 };
 
 }  // namespace snapshot
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
index 469fd091a4..f3795a1c33 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
@@ -24,9 +24,8 @@
 #include <unistd.h>
 
 #include <chrono>
-#include <iostream>
+#include <future>
 #include <memory>
-#include <string_view>
 
 #include <android-base/file.h>
 #include <android-base/properties.h>
@@ -44,7 +43,6 @@
 #include "snapuserd_core.h"
 #include "testing/dm_user_harness.h"
 #include "testing/host_harness.h"
-#include "testing/temp_device.h"
 #include "utility.h"
 
 namespace android {
@@ -68,6 +66,8 @@ struct TestParam {
     int block_size;
     int num_threads;
     uint32_t cow_op_merge_size;
+    uint32_t verification_block_size;
+    uint32_t num_verification_threads;
 };
 
 class SnapuserdTestBase : public ::testing::TestWithParam<TestParam> {
@@ -731,9 +731,17 @@ void SnapuserdTest::InitCowDevice() {
     auto opener = factory->CreateOpener(system_device_ctrl_name_);
     handlers_->DisableVerification();
     const TestParam params = GetParam();
-    auto handler = handlers_->AddHandler(
-            system_device_ctrl_name_, cow_system_->path, base_dev_->GetPath(), base_dev_->GetPath(),
-            opener, 1, params.io_uring, params.o_direct, params.cow_op_merge_size);
+    HandlerOptions options = {
+            .num_worker_threads = params.num_threads,
+            .use_iouring = params.io_uring,
+            .o_direct = params.o_direct,
+            .cow_op_merge_size = params.cow_op_merge_size,
+            .verify_block_size = params.verification_block_size,
+            .num_verification_threads = params.num_verification_threads,
+    };
+    auto handler =
+            handlers_->AddHandler(system_device_ctrl_name_, cow_system_->path, base_dev_->GetPath(),
+                                  base_dev_->GetPath(), opener, options);
     ASSERT_NE(handler, nullptr);
     ASSERT_NE(handler->snapuserd(), nullptr);
 #ifdef __ANDROID__
@@ -934,6 +942,26 @@ TEST_P(SnapuserdTest, Snapshot_MERGE_IO_TEST_1) {
     read_future.wait();
 }
 
+TEST_P(SnapuserdTest, Snapshot_MERGE_PAUSE_RESUME) {
+    if (!harness_->HasUserDevice()) {
+        GTEST_SKIP() << "Skipping snapshot read; not supported";
+    }
+    ASSERT_NO_FATAL_FAILURE(SetupDefault());
+    // Start the merge
+    ASSERT_TRUE(StartMerge());
+    std::this_thread::sleep_for(300ms);
+    // Pause merge
+    handlers_->PauseMerge();
+    // Issue I/O after pausing the merge and validate
+    auto read_future =
+            std::async(std::launch::async, &SnapuserdTest::ReadSnapshotDeviceAndValidate, this);
+    // Resume the merge
+    handlers_->ResumeMerge();
+    CheckMergeCompletion();
+    ValidateMerge();
+    read_future.wait();
+}
+
 TEST_P(SnapuserdTest, Snapshot_Merge_Resume) {
     ASSERT_NO_FATAL_FAILURE(SetupDefault());
     ASSERT_NO_FATAL_FAILURE(MergeInterrupt());
@@ -1253,9 +1281,17 @@ void HandlerTest::InitializeDevice() {
     ASSERT_NE(opener_, nullptr);
 
     const TestParam params = GetParam();
-    handler_ = std::make_shared<SnapshotHandler>(
-            system_device_ctrl_name_, cow_system_->path, base_dev_->GetPath(), base_dev_->GetPath(),
-            opener_, 1, false, false, params.o_direct, params.cow_op_merge_size);
+    HandlerOptions options = {
+            .num_worker_threads = params.num_threads,
+            .use_iouring = params.io_uring,
+            .o_direct = params.o_direct,
+            .cow_op_merge_size = params.cow_op_merge_size,
+            .verify_block_size = params.verification_block_size,
+            .num_verification_threads = params.num_verification_threads,
+    };
+    handler_ = std::make_shared<SnapshotHandler>(system_device_ctrl_name_, cow_system_->path,
+                                                 base_dev_->GetPath(), base_dev_->GetPath(),
+                                                 opener_, options);
     ASSERT_TRUE(handler_->InitCowDevice());
     ASSERT_TRUE(handler_->InitializeWorkers());
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
index 714c64124f..90705f7794 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
@@ -257,6 +257,19 @@ bool SnapshotHandler::ReadAheadIOCompleted(bool sync) {
     return true;
 }
 
+void SnapshotHandler::PauseMergeIfRequired() {
+    {
+        std::unique_lock<std::mutex> lock(pause_merge_lock_);
+        while (pause_merge_) {
+            SNAP_LOG(INFO) << "Merge thread paused";
+            pause_merge_cv_.wait(lock);
+            if (!pause_merge_) {
+                SNAP_LOG(INFO) << "Merge thread resumed";
+            }
+        }
+    }
+}
+
 // Invoked by RA thread - Waits for merge thread to finish merging
 // RA Block N - RA thread would be ready will with Block N+1 but
 // will wait to merge thread to finish Block N. Once Block N
@@ -281,8 +294,13 @@ bool SnapshotHandler::WaitForMergeReady() {
             }
             return false;
         }
-        return true;
     }
+
+    // This is a safe place to check if the RA thread should be
+    // paused. Since the scratch space isn't flushed yet, it is safe
+    // to wait here until resume is invoked.
+    PauseMergeIfRequired();
+    return true;
 }
 
 // Invoked by Merge thread - Notify RA thread about Merge completion
@@ -297,6 +315,11 @@ void SnapshotHandler::NotifyRAForMergeReady() {
     }
 
     cv.notify_all();
+
+    // This is a safe place to check if the merge thread should be
+    // paused. The data from the scratch space is merged to disk and is safe
+    // to wait.
+    PauseMergeIfRequired();
 }
 
 // The following transitions are mostly in the failure paths
@@ -393,6 +416,20 @@ void SnapshotHandler::MarkMergeComplete() {
     merge_complete_ = true;
 }
 
+void SnapshotHandler::PauseMergeThreads() {
+    {
+        std::lock_guard<std::mutex> lock(pause_merge_lock_);
+        pause_merge_ = true;
+    }
+}
+
+void SnapshotHandler::ResumeMergeThreads() {
+    {
+        std::lock_guard<std::mutex> lock(pause_merge_lock_);
+        pause_merge_ = false;
+    }
+}
+
 std::string SnapshotHandler::GetMergeStatus() {
     bool merge_not_initiated = false;
     bool merge_monitored = false;
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.cpp
index 957c6a8a78..2dfcc36cd4 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.cpp
@@ -20,8 +20,10 @@
 #include <android-base/scopeguard.h>
 #include <android-base/strings.h>
 
-#include "android-base/properties.h"
+#include <future>
+
 #include "snapuserd_core.h"
+#include "utility.h"
 
 namespace android {
 namespace snapshot {
@@ -30,8 +32,12 @@ using namespace android;
 using namespace android::dm;
 using android::base::unique_fd;
 
-UpdateVerify::UpdateVerify(const std::string& misc_name)
-    : misc_name_(misc_name), state_(UpdateVerifyState::VERIFY_UNKNOWN) {}
+UpdateVerify::UpdateVerify(const std::string& misc_name, uint32_t verify_block_size,
+                           uint32_t num_verification_threads)
+    : misc_name_(misc_name),
+      state_(UpdateVerifyState::VERIFY_UNKNOWN),
+      verify_block_size_(verify_block_size),
+      num_verification_threads_(num_verification_threads) {}
 
 bool UpdateVerify::CheckPartitionVerification() {
     auto now = std::chrono::system_clock::now();
@@ -104,43 +110,107 @@ bool UpdateVerify::VerifyBlocks(const std::string& partition_name,
         return false;
     }
 
-    loff_t file_offset = offset;
-    auto verify_block_size = android::base::GetUintProperty<uint>("ro.virtual_ab.verify_block_size",
-                                                                  kBlockSizeVerify);
-    const uint64_t read_sz = verify_block_size;
+    int queue_depth = std::max(queue_depth_, 1);
+    int verify_block_size = verify_block_size_;
+
+    // Smaller partitions don't need a bigger queue-depth.
+    // This is required for low-memory devices.
+    if (dev_sz < threshold_size_) {
+        queue_depth = std::max(queue_depth / 2, 1);
+        verify_block_size >>= 2;
+    }
+
+    if (!IsBlockAligned(verify_block_size)) {
+        verify_block_size = EXT4_ALIGN(verify_block_size, BLOCK_SZ);
+    }
 
-    void* addr;
-    ssize_t page_size = getpagesize();
-    if (posix_memalign(&addr, page_size, read_sz) < 0) {
-        SNAP_PLOG(ERROR) << "posix_memalign failed "
-                         << " page_size: " << page_size << " read_sz: " << read_sz;
+    std::unique_ptr<io_uring_cpp::IoUringInterface> ring =
+            io_uring_cpp::IoUringInterface::CreateLinuxIoUring(queue_depth, 0);
+    if (ring.get() == nullptr) {
+        PLOG(ERROR) << "Verify: io_uring_queue_init failed for queue_depth: " << queue_depth;
         return false;
     }
 
-    std::unique_ptr<void, decltype(&::free)> buffer(addr, ::free);
+    std::unique_ptr<struct iovec[]> vecs = std::make_unique<struct iovec[]>(queue_depth);
+    std::vector<std::unique_ptr<void, decltype(&::free)>> buffers;
+    for (int i = 0; i < queue_depth; i++) {
+        void* addr;
+        ssize_t page_size = getpagesize();
+        if (posix_memalign(&addr, page_size, verify_block_size) < 0) {
+            LOG(ERROR) << "posix_memalign failed";
+            return false;
+        }
 
-    uint64_t bytes_read = 0;
+        buffers.emplace_back(addr, ::free);
+        vecs[i].iov_base = addr;
+        vecs[i].iov_len = verify_block_size;
+    }
 
-    while (true) {
-        size_t to_read = std::min((dev_sz - file_offset), read_sz);
+    auto ret = ring->RegisterBuffers(vecs.get(), queue_depth);
+    if (!ret.IsOk()) {
+        SNAP_LOG(ERROR) << "io_uring_register_buffers failed: " << ret.ErrCode();
+        return false;
+    }
 
-        if (!android::base::ReadFullyAtOffset(fd.get(), buffer.get(), to_read, file_offset)) {
-            SNAP_PLOG(ERROR) << "Failed to read block from block device: " << dm_block_device
-                             << " partition-name: " << partition_name
-                             << " at offset: " << file_offset << " read-size: " << to_read
-                             << " block-size: " << dev_sz;
-            return false;
+    loff_t file_offset = offset;
+    const uint64_t read_sz = verify_block_size;
+    uint64_t total_read = 0;
+    int num_submitted = 0;
+
+    SNAP_LOG(DEBUG) << "VerifyBlocks: queue_depth: " << queue_depth
+                    << " verify_block_size: " << verify_block_size << " dev_sz: " << dev_sz
+                    << " file_offset: " << file_offset << " skip_blocks: " << skip_blocks;
+
+    while (file_offset < dev_sz) {
+        for (size_t i = 0; i < queue_depth; i++) {
+            uint64_t to_read = std::min((dev_sz - file_offset), read_sz);
+            if (to_read <= 0) break;
+
+            const auto sqe =
+                    ring->PrepReadFixed(fd.get(), vecs[i].iov_base, to_read, file_offset, i);
+            if (!sqe.IsOk()) {
+                SNAP_PLOG(ERROR) << "PrepReadFixed failed";
+                return false;
+            }
+            file_offset += (skip_blocks * to_read);
+            total_read += to_read;
+            num_submitted += 1;
+            if (file_offset >= dev_sz) {
+                break;
+            }
         }
 
-        bytes_read += to_read;
-        file_offset += (skip_blocks * verify_block_size);
-        if (file_offset >= dev_sz) {
+        if (num_submitted == 0) {
             break;
         }
+
+        const auto io_submit = ring->SubmitAndWait(num_submitted);
+        if (!io_submit.IsOk()) {
+            SNAP_LOG(ERROR) << "SubmitAndWait failed: " << io_submit.ErrMsg()
+                            << " for: " << num_submitted << " entries.";
+            return false;
+        }
+
+        SNAP_LOG(DEBUG) << "io_uring_submit: " << total_read << "num_submitted: " << num_submitted
+                        << "ret: " << ret;
+
+        const auto cqes = ring->PopCQE(num_submitted);
+        if (cqes.IsErr()) {
+            SNAP_LOG(ERROR) << "PopCqe failed for: " << num_submitted
+                            << " error: " << cqes.GetError().ErrMsg();
+            return false;
+        }
+        for (const auto& cqe : cqes.GetResult()) {
+            if (cqe.res < 0) {
+                SNAP_LOG(ERROR) << "I/O failed: cqe->res: " << cqe.res;
+                return false;
+            }
+            num_submitted -= 1;
+        }
     }
 
-    SNAP_LOG(DEBUG) << "Verification success with bytes-read: " << bytes_read
-                    << " dev_sz: " << dev_sz << " partition_name: " << partition_name;
+    SNAP_LOG(DEBUG) << "Verification success with io_uring: " << " dev_sz: " << dev_sz
+                    << " partition_name: " << partition_name << " total_read: " << total_read;
 
     return true;
 }
@@ -175,35 +245,29 @@ bool UpdateVerify::VerifyPartition(const std::string& partition_name,
         return false;
     }
 
-    /*
-     * Not all partitions are of same size. Some partitions are as small as
-     * 100Mb. We can just finish them in a single thread. For bigger partitions
-     * such as product, 4 threads are sufficient enough.
-     *
-     * TODO: With io_uring SQ_POLL support, we can completely cut this
-     * down to just single thread for all partitions and potentially verify all
-     * the partitions with zero syscalls. Additionally, since block layer
-     * supports polling, IO_POLL could be used which will further cut down
-     * latency.
-     */
+    if (!KernelSupportsIoUring()) {
+        SNAP_LOG(INFO) << "Kernel does not support io_uring. Skipping verification.\n";
+        // This will fallback to update_verifier to do the verification.
+        return false;
+    }
+
     int num_threads = kMinThreadsToVerify;
-    auto verify_threshold_size = android::base::GetUintProperty<uint>(
-            "ro.virtual_ab.verify_threshold_size", kThresholdSize);
-    if (dev_sz > verify_threshold_size) {
+    if (dev_sz > threshold_size_) {
         num_threads = kMaxThreadsToVerify;
+        if (num_verification_threads_ != 0) {
+            num_threads = num_verification_threads_;
+        }
     }
 
     std::vector<std::future<bool>> threads;
     off_t start_offset = 0;
     const int skip_blocks = num_threads;
 
-    auto verify_block_size =
-            android::base::GetUintProperty("ro.virtual_ab.verify_block_size", kBlockSizeVerify);
     while (num_threads) {
         threads.emplace_back(std::async(std::launch::async, &UpdateVerify::VerifyBlocks, this,
                                         partition_name, dm_block_device, start_offset, skip_blocks,
                                         dev_sz));
-        start_offset += verify_block_size;
+        start_offset += verify_block_size_;
         num_threads -= 1;
         if (start_offset >= dev_sz) {
             break;
@@ -218,9 +282,9 @@ bool UpdateVerify::VerifyPartition(const std::string& partition_name,
     if (ret) {
         succeeded = true;
         UpdatePartitionVerificationState(UpdateVerifyState::VERIFY_SUCCESS);
-        SNAP_LOG(INFO) << "Partition: " << partition_name << " Block-device: " << dm_block_device
-                       << " Size: " << dev_sz
-                       << " verification success. Duration : " << timer.duration().count() << " ms";
+        SNAP_LOG(INFO) << "Partition verification success: " << partition_name
+                       << " Block-device: " << dm_block_device << " Size: " << dev_sz
+                       << " Duration : " << timer.duration().count() << " ms";
         return true;
     }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
index b300a70009..f995c7f960 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
@@ -15,6 +15,7 @@
 
 #pragma once
 
+#include <liburing.h>
 #include <stdint.h>
 #include <sys/types.h>
 
@@ -22,6 +23,7 @@
 #include <mutex>
 #include <string>
 
+#include <liburing_cpp/IoUring.h>
 #include <snapuserd/snapuserd_kernel.h>
 #include <storage_literals/storage_literals.h>
 
@@ -32,7 +34,8 @@ using namespace android::storage_literals;
 
 class UpdateVerify {
   public:
-    UpdateVerify(const std::string& misc_name);
+    UpdateVerify(const std::string& misc_name, uint32_t verify_block_size,
+                 uint32_t num_verification_threads);
     void VerifyUpdatePartition();
     bool CheckPartitionVerification();
 
@@ -48,27 +51,24 @@ class UpdateVerify {
     std::mutex m_lock_;
     std::condition_variable m_cv_;
 
+    int kMinThreadsToVerify = 1;
+    int kMaxThreadsToVerify = 3;
+
     /*
-     * Scanning of partitions is an expensive operation both in terms of memory
-     * and CPU usage. The goal here is to scan the partitions fast enough without
-     * significant increase in the boot time.
-     *
-     * Partitions such as system, product which may be huge and may need multiple
-     * threads to speed up the verification process. Using multiple threads for
-     * all partitions may increase CPU usage significantly. Hence, limit that to
-     * 1 thread per partition.
+     * To optimize partition scanning speed without significantly impacting boot time,
+     * we employ O_DIRECT, bypassing the page-cache. However, O_DIRECT's memory
+     * allocation from CMA can be problematic on devices with restricted CMA space.
+     * To address this, io_uring_register_buffers() pre-registers I/O buffers,
+     * preventing CMA usage. See b/401952955 for more details.
      *
      * These numbers were derived by monitoring the memory and CPU pressure
      * (/proc/pressure/{cpu,memory}; and monitoring the Inactive(file) and
      * Active(file) pages from /proc/meminfo.
-     *
-     * Additionally, for low memory devices, it is advisable to use O_DIRECT
-     * functionality for source block device.
      */
-    int kMinThreadsToVerify = 1;
-    int kMaxThreadsToVerify = 3;
-    uint64_t kThresholdSize = 750_MiB;
-    uint64_t kBlockSizeVerify = 2_MiB;
+    uint64_t verify_block_size_ = 1_MiB;
+    uint64_t threshold_size_ = 2_GiB;
+    uint32_t num_verification_threads_;
+    int queue_depth_ = 4;
 
     bool IsBlockAligned(uint64_t read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
     void UpdatePartitionVerificationState(UpdateVerifyState state);
diff --git a/fs_mgr/libsnapshot/utility.cpp b/fs_mgr/libsnapshot/utility.cpp
index 7eaaca95bc..04ee069598 100644
--- a/fs_mgr/libsnapshot/utility.cpp
+++ b/fs_mgr/libsnapshot/utility.cpp
@@ -199,12 +199,28 @@ bool WriteStringToFileAtomic(const std::string& content, const std::string& path
 }
 
 std::ostream& operator<<(std::ostream& os, const Now&) {
-    struct tm now{};
+    struct tm now {};
     time_t t = time(nullptr);
     localtime_r(&t, &now);
     return os << std::put_time(&now, "%Y%m%d-%H%M%S");
 }
 
+std::ostream& operator<<(std::ostream& os, CancelResult result) {
+    switch (result) {
+        case CancelResult::OK:
+            return os << "ok";
+        case CancelResult::ERROR:
+            return os << "error";
+        case CancelResult::LIVE_SNAPSHOTS:
+            return os << "live_snapshots";
+        case CancelResult::NEEDS_MERGE:
+            return os << "needs_merge";
+        default:
+            LOG(ERROR) << "Unknown cancel result: " << static_cast<uint32_t>(result);
+            return os;
+    }
+}
+
 void AppendExtent(RepeatedPtrField<chromeos_update_engine::Extent>* extents, uint64_t start_block,
                   uint64_t num_blocks) {
     if (extents->size() > 0) {
@@ -277,6 +293,11 @@ bool GetODirectEnabledProperty() {
     return fetcher->GetBoolProperty("ro.virtual_ab.o_direct.enabled", false);
 }
 
+bool GetSkipVerificationProperty() {
+    auto fetcher = IPropertyFetcher::GetInstance();
+    return fetcher->GetBoolProperty("ro.virtual_ab.skip_verification", false);
+}
+
 std::string GetOtherPartitionName(const std::string& name) {
     auto suffix = android::fs_mgr::GetPartitionSlotSuffix(name);
     CHECK(suffix == "_a" || suffix == "_b");
diff --git a/fs_mgr/libsnapshot/utility.h b/fs_mgr/libsnapshot/utility.h
index 7dae942b35..eaf51c1cbd 100644
--- a/fs_mgr/libsnapshot/utility.h
+++ b/fs_mgr/libsnapshot/utility.h
@@ -123,6 +123,8 @@ bool FsyncDirectory(const char* dirname);
 struct Now {};
 std::ostream& operator<<(std::ostream& os, const Now&);
 
+std::ostream& operator<<(std::ostream& os, CancelResult);
+
 // Append to |extents|. Merged into the last element if possible.
 void AppendExtent(google::protobuf::RepeatedPtrField<chromeos_update_engine::Extent>* extents,
                   uint64_t start_block, uint64_t num_blocks);
@@ -134,6 +136,7 @@ bool GetUserspaceSnapshotsEnabledProperty();
 bool GetIouringEnabledProperty();
 bool GetXorCompressionEnabledProperty();
 bool GetODirectEnabledProperty();
+bool GetSkipVerificationProperty();
 
 bool CanUseUserspaceSnapshots();
 bool IsDmSnapshotTestingEnabled();
diff --git a/fs_mgr/tests/adb-remount-test.sh b/fs_mgr/tests/adb-remount-test.sh
index 526c761d36..df9635e426 100755
--- a/fs_mgr/tests/adb-remount-test.sh
+++ b/fs_mgr/tests/adb-remount-test.sh
@@ -1320,7 +1320,10 @@ if ${overlayfs_needed}; then
   for d in ${D}; do
     if adb_sh tune2fs -l "${d}" </dev/null 2>&1 | grep -q "Filesystem features:.*shared_blocks" ||
         adb_sh df -k "${d}" | grep -q " 100% "; then
-      die "remount overlayfs missed a spot (rw)"
+      # See b/397158623
+      # The new overlayfs mounter is a bit more limited due to sepolicy. Since we know of no use
+      # cases for these mounts, disabling for now
+      LOG OK "remount overlayfs missed a spot (rw)"
     fi
   done
 else
@@ -1360,6 +1363,14 @@ cat "${system_build_prop_original}" - <<EOF >"${system_build_prop_modified}"
 # Properties added by adb remount test
 test.adb.remount.system.build.prop=true
 EOF
+
+# Move /system/build.prop to make sure we can move and then replace files
+# Note that as of kernel 6.1 mv creates the char_file that whites out the lower
+# file with different selabels than rm does
+# See b/394290609
+adb shell mv /system/build.prop /system/build.prop.backup >/dev/null ||
+  die "adb shell rm /system/build.prop"
+
 adb push "${system_build_prop_modified}" /system/build.prop >/dev/null ||
   die "adb push /system/build.prop"
 adb pull /system/build.prop "${system_build_prop_fromdevice}" >/dev/null ||
diff --git a/gatekeeperd/OWNERS b/gatekeeperd/OWNERS
index 04cd19e257..7d822e663e 100644
--- a/gatekeeperd/OWNERS
+++ b/gatekeeperd/OWNERS
@@ -1,5 +1,4 @@
 # Bug component: 1124862
 drysdale@google.com
 oarbildo@google.com
-subrahmanyaman@google.com
 swillden@google.com
diff --git a/healthd/BatteryMonitor.cpp b/healthd/BatteryMonitor.cpp
index b8bb58682a..64c85e2d72 100644
--- a/healthd/BatteryMonitor.cpp
+++ b/healthd/BatteryMonitor.cpp
@@ -131,6 +131,7 @@ static void initHealthInfo(HealthInfo* health_info) {
                     (int64_t)HealthInfo::BATTERY_CHARGE_TIME_TO_FULL_NOW_SECONDS_UNSUPPORTED,
             .batteryStatus = BatteryStatus::UNKNOWN,
             .batteryHealth = BatteryHealth::UNKNOWN,
+            .batteryHealthData = std::nullopt,
     };
 }
 
@@ -341,9 +342,10 @@ static bool getBooleanField(const String8& path) {
     return value;
 }
 
-static int getIntField(const String8& path) {
+template <typename T = int>
+static T getIntField(const String8& path) {
     std::string buf;
-    int value = 0;
+    T value = 0;
 
     if (readFromFile(path, &buf) > 0)
         android::base::ParseInt(buf, &value);
@@ -360,6 +362,14 @@ static bool isScopedPowerSupply(const char* name) {
     return (readFromFile(path, &scope) > 0 && scope == kScopeDevice);
 }
 
+static BatteryHealthData *ensureBatteryHealthData(HealthInfo *info) {
+    if (!info->batteryHealthData.has_value()) {
+        return &info->batteryHealthData.emplace();
+    }
+
+    return &info->batteryHealthData.value();
+}
+
 void BatteryMonitor::updateValues(void) {
     initHealthInfo(mHealthInfo.get());
 
@@ -402,16 +412,16 @@ void BatteryMonitor::updateValues(void) {
         mBatteryHealthStatus = getIntField(mHealthdConfig->batteryHealthStatusPath);
 
     if (!mHealthdConfig->batteryStateOfHealthPath.empty())
-        mHealthInfo->batteryHealthData->batteryStateOfHealth =
+        ensureBatteryHealthData(mHealthInfo.get())->batteryStateOfHealth =
                 getIntField(mHealthdConfig->batteryStateOfHealthPath);
 
     if (!mHealthdConfig->batteryManufacturingDatePath.empty())
-        mHealthInfo->batteryHealthData->batteryManufacturingDateSeconds =
-                getIntField(mHealthdConfig->batteryManufacturingDatePath);
+        ensureBatteryHealthData(mHealthInfo.get())->batteryManufacturingDateSeconds =
+                getIntField<int64_t>(mHealthdConfig->batteryManufacturingDatePath);
 
     if (!mHealthdConfig->batteryFirstUsageDatePath.empty())
-        mHealthInfo->batteryHealthData->batteryFirstUsageSeconds =
-                getIntField(mHealthdConfig->batteryFirstUsageDatePath);
+        ensureBatteryHealthData(mHealthInfo.get())->batteryFirstUsageSeconds =
+                getIntField<int64_t>(mHealthdConfig->batteryFirstUsageDatePath);
 
     mHealthInfo->batteryTemperatureTenthsCelsius =
             mBatteryFixedTemperature ? mBatteryFixedTemperature
@@ -706,49 +716,54 @@ void BatteryMonitor::dumpState(int fd) {
     char vs[128];
     const HealthInfo& props = *mHealthInfo;
 
+    snprintf(vs, sizeof(vs), "Cached HealthInfo:\n");
+    write(fd, vs, strlen(vs));
     snprintf(vs, sizeof(vs),
-             "ac: %d usb: %d wireless: %d dock: %d current_max: %d voltage_max: %d\n",
+             "  ac: %d usb: %d wireless: %d dock: %d current_max: %d voltage_max: %d\n",
              props.chargerAcOnline, props.chargerUsbOnline, props.chargerWirelessOnline,
              props.chargerDockOnline, props.maxChargingCurrentMicroamps,
              props.maxChargingVoltageMicrovolts);
     write(fd, vs, strlen(vs));
-    snprintf(vs, sizeof(vs), "status: %d health: %d present: %d\n",
+    snprintf(vs, sizeof(vs), "  status: %d health: %d present: %d\n",
              props.batteryStatus, props.batteryHealth, props.batteryPresent);
     write(fd, vs, strlen(vs));
-    snprintf(vs, sizeof(vs), "level: %d voltage: %d temp: %d\n", props.batteryLevel,
+    snprintf(vs, sizeof(vs), "  level: %d voltage: %d temp: %d\n", props.batteryLevel,
              props.batteryVoltageMillivolts, props.batteryTemperatureTenthsCelsius);
     write(fd, vs, strlen(vs));
 
     if (!mHealthdConfig->batteryCurrentNowPath.empty()) {
-        v = getIntField(mHealthdConfig->batteryCurrentNowPath);
-        snprintf(vs, sizeof(vs), "current now: %d\n", v);
+        snprintf(vs, sizeof(vs), "  current now: %d\n", props.batteryCurrentMicroamps);
         write(fd, vs, strlen(vs));
     }
 
-    if (!mHealthdConfig->batteryCurrentAvgPath.empty()) {
-        v = getIntField(mHealthdConfig->batteryCurrentAvgPath);
-        snprintf(vs, sizeof(vs), "current avg: %d\n", v);
+    if (!mHealthdConfig->batteryCycleCountPath.empty()) {
+        snprintf(vs, sizeof(vs), "  cycle count: %d\n", props.batteryCycleCount);
         write(fd, vs, strlen(vs));
     }
 
-    if (!mHealthdConfig->batteryChargeCounterPath.empty()) {
-        v = getIntField(mHealthdConfig->batteryChargeCounterPath);
-        snprintf(vs, sizeof(vs), "charge counter: %d\n", v);
+    if (!mHealthdConfig->batteryFullChargePath.empty()) {
+        snprintf(vs, sizeof(vs), "  Full charge: %d\n", props.batteryFullChargeUah);
         write(fd, vs, strlen(vs));
     }
 
+    snprintf(vs, sizeof(vs), "Real-time Values:\n");
+    write(fd, vs, strlen(vs));
+
     if (!mHealthdConfig->batteryCurrentNowPath.empty()) {
-        snprintf(vs, sizeof(vs), "current now: %d\n", props.batteryCurrentMicroamps);
+        v = getIntField(mHealthdConfig->batteryCurrentNowPath);
+        snprintf(vs, sizeof(vs), "  current now: %d\n", v);
         write(fd, vs, strlen(vs));
     }
 
-    if (!mHealthdConfig->batteryCycleCountPath.empty()) {
-        snprintf(vs, sizeof(vs), "cycle count: %d\n", props.batteryCycleCount);
+    if (!mHealthdConfig->batteryCurrentAvgPath.empty()) {
+        v = getIntField(mHealthdConfig->batteryCurrentAvgPath);
+        snprintf(vs, sizeof(vs), "  current avg: %d\n", v);
         write(fd, vs, strlen(vs));
     }
 
-    if (!mHealthdConfig->batteryFullChargePath.empty()) {
-        snprintf(vs, sizeof(vs), "Full charge: %d\n", props.batteryFullChargeUah);
+    if (!mHealthdConfig->batteryChargeCounterPath.empty()) {
+        v = getIntField(mHealthdConfig->batteryChargeCounterPath);
+        snprintf(vs, sizeof(vs), "  charge counter: %d\n", v);
         write(fd, vs, strlen(vs));
     }
 }
diff --git a/healthd/OWNERS b/healthd/OWNERS
index e64c33d1ac..c436ba2afd 100644
--- a/healthd/OWNERS
+++ b/healthd/OWNERS
@@ -1 +1 @@
-elsk@google.com
+include platform/hardware/interfaces:/health/OWNERS
diff --git a/init/Android.bp b/init/Android.bp
index ed19b4b865..ed8123e380 100644
--- a/init/Android.bp
+++ b/init/Android.bp
@@ -80,6 +80,7 @@ init_device_sources = [
     "sigchld_handler.cpp",
     "snapuserd_transition.cpp",
     "switch_root.cpp",
+    "tradeinmode.cpp",
     "uevent_listener.cpp",
     "ueventd.cpp",
     "ueventd_parser.cpp",
@@ -136,6 +137,8 @@ libinit_cc_defaults {
                 "-DWORLD_WRITABLE_KMSG=1",
                 "-UDUMP_ON_UMOUNT_FAILURE",
                 "-DDUMP_ON_UMOUNT_FAILURE=1",
+                "-UALLOW_REMOUNT_OVERLAYS",
+                "-DALLOW_REMOUNT_OVERLAYS=1",
             ],
         },
         eng: {
@@ -263,7 +266,10 @@ phony {
     name: "init",
     required: [
         "init_second_stage",
-    ],
+    ] + select(product_variable("debuggable"), {
+        true: ["overlay_remounter"],
+        false: [],
+    }),
 }
 
 cc_defaults {
@@ -594,6 +600,7 @@ cc_defaults {
     ],
     static_libs: [
         "libbase",
+        "libfstab",
         "libselinux",
         "libpropertyinfoserializer",
         "libpropertyinfoparser",
diff --git a/init/README.md b/init/README.md
index 560c5280fe..6a66f14396 100644
--- a/init/README.md
+++ b/init/README.md
@@ -369,6 +369,17 @@ runs the service.
 `setenv <name> <value>`
 > Set the environment variable _name_ to _value_ in the launched process.
 
+`shared_kallsyms`
+> If set, init will behave as if the service specified "file /proc/kallsyms r",
+  except the service will receive a duplicate of a single fd that init saved
+  during early second\_stage. This fd retains address visibility even after the
+  systemwide kptr\_restrict sysctl is set to its steady state on Android. The
+  ability to read from this fd is still constrained by selinux permissions,
+  which need to be granted separately and are gated by a neverallow.
+  Because of performance gotchas of concurrent use of this shared fd, all uses
+  need to coordinate via provisional flock(LOCK\_EX) locks on separately opened
+  /proc/kallsyms fds (since locking requires distinct open file descriptions).
+
 `shutdown <shutdown_behavior>`
 > Set shutdown behavior of the service process. When this is not specified,
   the service is killed during shutdown process by using SIGTERM and SIGKILL.
@@ -443,38 +454,66 @@ runs the service.
 
 Triggers
 --------
-Triggers are strings which can be used to match certain kinds of
-events and used to cause an action to occur.
+Triggers of an action specifies one or more conditions when satisfied
+execute the commands in the action. A trigger encodes a single atomic
+condition, and multiple triggers can be combined using the `&&`
+operator to form a bigger AND condition.
 
-Triggers are subdivided into event triggers and property triggers.
+There are two types of triggers: event triggers and action triggers.
+An action can have multiple property triggers but may have only one
+event trigger.
 
-Event triggers are strings triggered by the 'trigger' command or by
-the QueueEventTrigger() function within the init executable.  These
-take the form of a simple string such as 'boot' or 'late-init'.
+An event trigger takes the simple form of `<event>` where `<event>` is
+the name of a boot stage like `early-init` or `boot`. This trigger
+is satisfied when init reaches the stage via the `trigger` command or
+by the `QueueEventTrigger()` function in the init executable.
 
-Property triggers are strings triggered when a named property changes
-value to a given new value or when a named property changes value to
-any new value.  These take the form of 'property:<name>=<value>' and
-'property:<name>=\*' respectively.  Property triggers are additionally
-evaluated and triggered accordingly during the initial boot phase of
-init.
+A property trigger takes the form of `property:<name>=<value>`. This
+trigger is satisfied when the property of name `<name>` is found to
+have the value of `<value>` when the check is made. The `<value>` part
+can be `\*` to match with any value.
 
-An Action can have multiple property triggers but may only have one
-event trigger.
+The check for property trigger is made in the following cases:
 
-For example:
-`on boot && property:a=b` defines an action that is only executed when
-the 'boot' event trigger happens and the property a equals b at the moment. This
-will NOT be executed when the property a transitions to value b after the `boot`
-event was triggered.
+* All property triggers get checked at least once when the `boot`
+  event is finished (i.e. when the last command under `on boot ...` is
+finished).
+
+* After the one-time check, `property:a=b` is checked when property `a`
+  is newly created, or when the property is set to a new value.
+
+* Property triggers are also checked when other triggers in the same
+  action are checked. For example, `property:a=b && property:c=d` is
+checked not only when property `a` gets a new value, but also when
+property `c` gets a new value (and of course when the one-time check
+is made).
+
+* Before the one-time check, `property:a=b` without an event trigger
+  is NOT checked, even if property `a` gets a new value. Care must be
+taken since this is a non-intuitive behavior, which unfortunately
+can't be changed due to compatibility concerns.
+
+Some examples:
+
+`on property:a=b` is executed in two cases:
+
+1. during the one-time check if property `a` is `b` at the moment.
+2. if property `a` is set to or changed to `b` after the one-time
+   check, but not before then.
 
-`on property:a=b && property:c=d` defines an action that is executed
-at three times:
+`on property:a=b && property:c=d` is executed in three cases:
 
-   1. During initial boot if property a=b and property c=d.
-   2. Any time that property a transitions to value b, while property c already equals d.
-   3. Any time that property c transitions to value d, while property a already equals b.
+1. during the one-time check if property `a` is `b` and property `c`
+   is `d` at the moment.
+2. (after the one-time check) property `a` becomes `b` while property
+   `c` already equals to `d`.
+3. (after the one-time check) property `c` becomes `d` while property
+   `a` already equals to `b`.
 
+`on property:a=b && post-fs` is executed in one case only:
+
+1. `post-fs` is triggered while property `a` already equals to `b`.
+   This is NOT executed when property `a` becomes `b` AFTER `post-fs`.
 
 Trigger Sequence
 ----------------
@@ -746,6 +785,16 @@ provides the `aidl_lazy_test_1` interface.
   fstab.${ro.hardware} or fstab.${ro.hardware.platform} will be scanned for
   under /odm/etc, /vendor/etc, or / at runtime, in that order.
 
+> swapon_all is deprecated and will do nothing if `mmd_enabled` AConfig flag
+  in `system_performance` namespace and `mmd.zram.enabled` sysprop are enabled.
+  OEMs, who decided to use mmd to manage zram, must remove zram entry from fstab
+  or remove swapon_all call from their init script.
+
+> swapon_all continues to support setting up non-zram swap devices.
+
+> swapon_all on recovery mode continues to support setting up zram because mmd
+  does not support the recovery mode.
+
 `swapoff <path>`
 > Stops swapping to the file or block device specified by path.
 
@@ -922,26 +971,13 @@ Init records some boot timing information in system properties.
 
 Bootcharting
 ------------
-This version of init contains code to perform "bootcharting": generating log
-files that can be later processed by the tools provided by <http://www.bootchart.org/>.
+Bootchart provides CPU and I/O load breakdown of all processes for the whole system.
+Refer to the instructions at
+ <https://source.android.com/docs/core/perf/boot-times#bootchart>.
 
 On the emulator, use the -bootchart _timeout_ option to boot with bootcharting
 activated for _timeout_ seconds.
 
-On a device:
-
-    adb shell 'touch /data/bootchart/enabled'
-
-Don't forget to delete this file when you're done collecting data!
-
-The log files are written to /data/bootchart/. A script is provided to
-retrieve them and create a bootchart.tgz file that can be used with the
-bootchart command-line utility:
-
-    sudo apt-get install pybootchartgui
-    # grab-bootchart.sh uses $ANDROID_SERIAL.
-    $ANDROID_BUILD_TOP/system/core/init/grab-bootchart.sh
-
 One thing to watch for is that the bootchart will show init as if it started
 running at 0s. You'll have to look at dmesg to work out when the kernel
 actually started init.
diff --git a/init/capabilities.h b/init/capabilities.h
index fc80c9864f..b71d2cb688 100644
--- a/init/capabilities.h
+++ b/init/capabilities.h
@@ -18,6 +18,7 @@
 #include <sys/capability.h>
 
 #include <bitset>
+#include <memory>
 #include <string>
 #include <type_traits>
 
diff --git a/init/compare-bootcharts.py b/init/compare-bootcharts.py
index 009b63999a..b299b7d1b6 100755
--- a/init/compare-bootcharts.py
+++ b/init/compare-bootcharts.py
@@ -47,7 +47,7 @@ jiffy_to_wallclock = {
 def analyze_process_maps(process_map1, process_map2, jiffy_record):
     # List interesting processes here
     processes_of_interest = [
-        '/init',
+        '/system/bin/init',
         '/system/bin/surfaceflinger',
         '/system/bin/bootanimation',
         'zygote64',
diff --git a/init/devices.cpp b/init/devices.cpp
index aeaa431339..cead726167 100644
--- a/init/devices.cpp
+++ b/init/devices.cpp
@@ -599,7 +599,22 @@ void DeviceHandler::HandleDevice(const std::string& action, const std::string& d
                 PLOG(ERROR) << "Failed to create directory " << Dirname(link);
             }
 
-            if (symlink(target.c_str(), link.c_str())) {
+            // Create symlink and make sure it's correctly labeled
+            std::string secontext;
+            // Passing 0 for mode should work.
+            if (SelabelLookupFileContext(link, 0, &secontext) && !secontext.empty()) {
+                setfscreatecon(secontext.c_str());
+            }
+
+            int rc = symlink(target.c_str(), link.c_str());
+
+            if (!secontext.empty()) {
+                int save_errno = errno;
+                setfscreatecon(nullptr);
+                errno = save_errno;
+            }
+
+            if (rc < 0) {
                 if (errno != EEXIST) {
                     PLOG(ERROR) << "Failed to symlink " << devpath << " to " << link;
                 } else if (std::string link_path;
diff --git a/init/first_stage_mount.cpp b/init/first_stage_mount.cpp
index aa6b551662..6b413f6d65 100644
--- a/init/first_stage_mount.cpp
+++ b/init/first_stage_mount.cpp
@@ -32,12 +32,9 @@
 #include <android-base/chrono_utils.h>
 #include <android-base/file.h>
 #include <android-base/logging.h>
-#include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android/avf_cc_flags.h>
-#include <bootloader_message/bootloader_message.h>
-#include <cutils/android_reboot.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
 #include <fs_mgr_dm_linear.h>
@@ -49,7 +46,6 @@
 
 #include "block_dev_initializer.h"
 #include "devices.h"
-#include "reboot_utils.h"
 #include "result.h"
 #include "snapuserd_transition.h"
 #include "switch_root.h"
@@ -115,8 +111,6 @@ class FirstStageMountVBootV2 : public FirstStageMount {
     bool GetDmVerityDevices(std::set<std::string>* devices);
     bool SetUpDmVerity(FstabEntry* fstab_entry);
 
-    void RequestTradeInModeWipeIfNeeded();
-
     bool InitAvbHandle();
 
     bool need_dm_verity_;
@@ -269,8 +263,6 @@ bool FirstStageMountVBootV2::DoCreateDevices() {
 }
 
 bool FirstStageMountVBootV2::DoFirstStageMount() {
-    RequestTradeInModeWipeIfNeeded();
-
     if (!IsDmLinearEnabled() && fstab_.empty()) {
         // Nothing to mount.
         LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
@@ -890,55 +882,6 @@ bool FirstStageMountVBootV2::InitAvbHandle() {
     return true;
 }
 
-void FirstStageMountVBootV2::RequestTradeInModeWipeIfNeeded() {
-    static constexpr const char* kWipeIndicator = "/metadata/tradeinmode/wipe";
-    static constexpr size_t kWipeAttempts = 3;
-
-    if (access(kWipeIndicator, R_OK) == -1) {
-        return;
-    }
-
-    // Write a counter to the wipe indicator, to try and prevent boot loops if
-    // recovery fails to wipe data.
-    uint32_t counter = 0;
-    std::string contents;
-    if (ReadFileToString(kWipeIndicator, &contents)) {
-        android::base::ParseUint(contents, &counter);
-        contents = std::to_string(++counter);
-        if (android::base::WriteStringToFile(contents, kWipeIndicator)) {
-            sync();
-        } else {
-            PLOG(ERROR) << "Failed to update " << kWipeIndicator;
-        }
-    } else {
-        PLOG(ERROR) << "Failed to read " << kWipeIndicator;
-    }
-
-    std::string err;
-    auto misc_device = get_misc_blk_device(&err);
-    if (misc_device.empty()) {
-        LOG(FATAL) << "Could not find misc device: " << err;
-    }
-
-    auto misc_name = android::base::Basename(misc_device);
-    if (!block_dev_init_.InitDevices({misc_name})) {
-        LOG(FATAL) << "Could not find misc device: " << misc_device;
-    }
-
-    // If we've failed to wipe three times, don't include the wipe command. This
-    // will force us to boot into the recovery menu instead where a manual wipe
-    // can be attempted.
-    std::vector<std::string> options;
-    if (counter <= kWipeAttempts) {
-        options.emplace_back("--wipe_data");
-        options.emplace_back("--reason=tradeinmode");
-    }
-    if (!write_bootloader_message(options, &err)) {
-        LOG(FATAL) << "Could not issue wipe: " << err;
-    }
-    RebootSystem(ANDROID_RB_RESTART2, "recovery", "reboot,tradeinmode,wipe");
-}
-
 void SetInitAvbVersionInRecovery() {
     if (!IsRecoveryMode()) {
         LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
diff --git a/init/init.cpp b/init/init.cpp
index 5b0b0ddee1..f6b2941365 100644
--- a/init/init.cpp
+++ b/init/init.cpp
@@ -88,6 +88,7 @@
 #include "snapuserd_transition.h"
 #include "subcontext.h"
 #include "system/core/init/property_service.pb.h"
+#include "tradeinmode.h"
 #include "util.h"
 
 #ifndef RECOVERY
@@ -100,6 +101,8 @@ using namespace std::string_literals;
 using android::base::boot_clock;
 using android::base::ConsumePrefix;
 using android::base::GetProperty;
+using android::base::GetIntProperty;
+using android::base::GetBoolProperty;
 using android::base::ReadFileToString;
 using android::base::SetProperty;
 using android::base::StringPrintf;
@@ -108,6 +111,8 @@ using android::base::Trim;
 using android::base::unique_fd;
 using android::fs_mgr::AvbHandle;
 using android::snapshot::SnapshotManager;
+using android::base::WaitForProperty;
+using android::base::WriteStringToFile;
 
 namespace android {
 namespace init {
@@ -919,6 +924,39 @@ static Result<void> ConnectEarlyStageSnapuserdAction(const BuiltinArguments& arg
     return {};
 }
 
+static Result<void> CheckTradeInModeStatus([[maybe_unused]] const BuiltinArguments& args) {
+    RequestTradeInModeWipeIfNeeded();
+    return {};
+}
+
+static void SecondStageBootMonitor(int timeout_sec) {
+    auto cur_time = boot_clock::now().time_since_epoch();
+    int cur_sec = std::chrono::duration_cast<std::chrono::seconds>(cur_time).count();
+    int extra_sec = timeout_sec <= cur_sec? 0 : timeout_sec - cur_sec;
+    auto boot_timeout = std::chrono::seconds(extra_sec);
+
+    LOG(INFO) << "Started BootMonitorThread, expiring in "
+              << timeout_sec
+              << " seconds from boot-up";
+
+    if (!WaitForProperty("sys.boot_completed", "1", boot_timeout)) {
+        LOG(ERROR) << "BootMonitorThread: boot didn't complete in "
+                   << timeout_sec
+                   << " seconds. Trigger a panic!";
+
+        // add a short delay for logs to be flushed out.
+        std::this_thread::sleep_for(200ms);
+
+        // trigger a kernel panic
+        WriteStringToFile("c", PROC_SYSRQ);
+    }
+}
+
+static void StartSecondStageBootMonitor(int timeout_sec) {
+    std::thread monitor_thread(&SecondStageBootMonitor, timeout_sec);
+    monitor_thread.detach();
+}
+
 int SecondStageMain(int argc, char** argv) {
     if (REBOOT_BOOTLOADER_ON_PANIC) {
         InstallRebootSignalHandlers();
@@ -1010,6 +1048,14 @@ int SecondStageMain(int argc, char** argv) {
     InstallInitNotifier(&epoll);
     StartPropertyService(&property_fd);
 
+    // If boot_timeout property has been set in a debug build, start the boot monitor
+    if (GetBoolProperty("ro.debuggable", false)) {
+        int timeout = GetIntProperty("ro.boot.boot_timeout", 0);
+        if (timeout > 0) {
+            StartSecondStageBootMonitor(timeout);
+        }
+    }
+
     // Make the time that init stages started available for bootstat to log.
     RecordStageBoottimes(start_time);
 
@@ -1055,6 +1101,14 @@ int SecondStageMain(int argc, char** argv) {
         }
     }
 
+    // This needs to happen before SetKptrRestrictAction, as we are trying to
+    // open /proc/kallsyms while still being allowed to see the full addresses
+    // (since init holds CAP_SYSLOG, and Linux boots with kptr_restrict=0). The
+    // address visibility through the saved fd (more specifically, the backing
+    // open file description) will then be remembered by the kernel for the rest
+    // of its lifetime, even after we raise the kptr_restrict.
+    Service::OpenAndSaveStaticKallsymsFd();
+
     am.QueueBuiltinAction(SetupCgroupsAction, "SetupCgroups");
     am.QueueBuiltinAction(SetKptrRestrictAction, "SetKptrRestrict");
     am.QueueBuiltinAction(TestPerfEventSelinuxAction, "TestPerfEventSelinux");
@@ -1063,6 +1117,7 @@ int SecondStageMain(int argc, char** argv) {
 
     // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
     am.QueueBuiltinAction(wait_for_coldboot_done_action, "wait_for_coldboot_done");
+    am.QueueBuiltinAction(CheckTradeInModeStatus, "CheckTradeInModeStatus");
     // ... so that we can start queuing up actions that require stuff from /dev.
     am.QueueBuiltinAction(SetMmapRndBitsAction, "SetMmapRndBits");
     Keychords keychords;
diff --git a/init/libprefetch/prefetch/prefetch.rc b/init/libprefetch/prefetch/prefetch.rc
index fb3fb3b6a3..56fb827449 100644
--- a/init/libprefetch/prefetch/prefetch.rc
+++ b/init/libprefetch/prefetch/prefetch.rc
@@ -1,28 +1,36 @@
-on init && property:ro.prefetch_boot.enabled=true
-    start prefetch
-
-service prefetch /system/bin/prefetch start
-    class main
-    user root
-    group root system
-    disabled
-    oneshot
-
-on property:ro.prefetch_boot.record=true
-    start prefetch_record
+# Reads data from disk in advance and populates page cache
+# to speed up subsequent disk access.
+#
+# Record:
+#   start by `start prefetch_record` at appropriate timing.
+#   stop by setting `prefetch_boot.record_stop` to 1.
+#   set --duration to only capture for a certain duration instead.
+#
+# Replay:
+#   start by `start prefetch_replay` at appropriate timing.
+#   it will depend on several files generated from record.
+#
+#   replay is I/O intensive. make sure you pick appropriate
+#   timing to run each, so that you can maximize the page cache
+#   hit for subsequent disk access.
+#
+# Example:
+#   on early-init && property:ro.prefetch_boot.enabled=true
+#     start prefetch_replay
+#
+#   on init && property:ro.prefetch_boot.enabled=true
+#     start prefetch_record
+#
+#   on property:sys.boot_completed=1 && property:ro.prefetch_boot.enabled=true
+#     setprop prefetch_boot.record_stop 1
 
 service prefetch_record /system/bin/prefetch record --duration ${ro.prefetch_boot.duration_s:-0}
-    class main
     user root
     group root system
     disabled
     oneshot
 
-on property:ro.prefetch_boot.replay=true
-    start prefetch_replay
-
-service prefetch_replay /system/bin/prefetch replay --io-depth ${ro.prefetch_boot.io_depth:-2} --max-fds ${ro.prefetch_boot.max_fds:-128}
-    class main
+service prefetch_replay /system/bin/prefetch replay --io-depth ${ro.prefetch_boot.io_depth:-2} --max-fds ${ro.prefetch_boot.max_fds:-1024}
     user root
     group root system
     disabled
diff --git a/init/libprefetch/prefetch/src/arch/android.rs b/init/libprefetch/prefetch/src/arch/android.rs
index 3404e42b14..7d446ba5df 100644
--- a/init/libprefetch/prefetch/src/arch/android.rs
+++ b/init/libprefetch/prefetch/src/arch/android.rs
@@ -1,19 +1,22 @@
 use crate::Error;
 use crate::RecordArgs;
-use crate::StartArgs;
-use log::info;
 use log::warn;
 use std::fs::File;
 use std::fs::OpenOptions;
 use std::io::Write;
+use std::path::Path;
 use std::time::Duration;
 
 use rustutils::system_properties::error::PropertyWatcherError;
 use rustutils::system_properties::PropertyWatcher;
 
-const PREFETCH_RECORD_PROPERTY: &str = "prefetch_boot.record";
-const PREFETCH_REPLAY_PROPERTY: &str = "prefetch_boot.replay";
-const PREFETCH_RECORD_PROPERTY_STOP: &str = "ro.prefetch_boot.record_stop";
+const PREFETCH_RECORD_PROPERTY_STOP: &str = "prefetch_boot.record_stop";
+
+fn is_prefetch_enabled() -> Result<bool, Error> {
+    rustutils::system_properties::read_bool("ro.prefetch_boot.enabled", false).map_err(|e| {
+        Error::Custom { error: format!("Failed to read ro.prefetch_boot.enabled: {}", e) }
+    })
+}
 
 fn wait_for_property_true(
     property_name: &str,
@@ -31,68 +34,49 @@ pub fn wait_for_record_stop() {
     });
 }
 
-fn start_prefetch_service(property_name: &str) -> Result<(), Error> {
-    match rustutils::system_properties::write(property_name, "true") {
-        Ok(_) => {}
-        Err(_) => {
-            return Err(Error::Custom { error: "Failed to start prefetch service".to_string() });
-        }
+/// Checks if we can perform replay phase.
+/// Ensure that the pack file exists and is up-to-date, returns false otherwise.
+pub fn can_perform_replay(pack_path: &Path, fingerprint_path: &Path) -> Result<bool, Error> {
+    if !is_prefetch_enabled()? {
+        return Ok(false);
     }
-    Ok(())
-}
 
-/// Start prefetch service
-///
-/// 1: Check the presence of the file 'prefetch_ready'. If it doesn't
-/// exist then the device is booting for the first time after wipe.
-/// Thus, we would just create the file and exit as we do not want
-/// to initiate the record after data wipe primiarly because boot
-/// after data wipe is long and the I/O pattern during first boot may not actually match
-/// with subsequent boot.
-///
-/// 2: If the file 'prefetch_ready' is present:
-///
-///   a: Compare the build-finger-print of the device with the one record format
-///   is associated with by reading the file 'build_finger_print'. If they match,
-///   start the prefetch_replay.
-///
-///   b: If they don't match, then the device was updated through OTA. Hence, start
-///   a fresh record and delete the build-finger-print file. This should also cover
-///   the case of device rollback.
-///
-///   c: If the build-finger-print file doesn't exist, then just restart the record
-///   from scratch.
-pub fn start_prefetch(args: &StartArgs) -> Result<(), Error> {
-    if !args.path.exists() {
-        match File::create(args.path.clone()) {
-            Ok(_) => {}
-            Err(_) => {
-                return Err(Error::Custom { error: "File Creation failed".to_string() });
-            }
-        }
-        return Ok(());
+    if !pack_path.exists() || !fingerprint_path.exists() {
+        return Ok(false);
     }
 
-    if args.build_fingerprint_path.exists() {
-        let device_build_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
-            .map_err(|e| Error::Custom {
+    let saved_fingerprint = std::fs::read_to_string(fingerprint_path)?;
+
+    let current_device_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
+        .map_err(|e| Error::Custom {
             error: format!("Failed to read ro.build.fingerprint: {}", e),
         })?;
-        let pack_build_fingerprint = std::fs::read_to_string(&args.build_fingerprint_path)?;
-        if pack_build_fingerprint.trim() == device_build_fingerprint.as_deref().unwrap_or_default()
-        {
-            info!("Start replay");
-            start_prefetch_service(PREFETCH_REPLAY_PROPERTY)?;
-        } else {
-            info!("Start record");
-            std::fs::remove_file(&args.build_fingerprint_path)?;
-            start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
-        }
-    } else {
-        info!("Start record");
-        start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
+
+    Ok(current_device_fingerprint.is_some_and(|fp| fp == saved_fingerprint.trim()))
+}
+
+/// Checks if we can perform record phase.
+/// Ensure that following conditions hold:
+///   - File specified in ready_path exists. otherwise, create a new file and return false.
+///   - can_perform_replay is false.
+pub fn ensure_record_is_ready(
+    ready_path: &Path,
+    pack_path: &Path,
+    fingerprint_path: &Path,
+) -> Result<bool, Error> {
+    if !is_prefetch_enabled()? {
+        return Ok(false);
     }
-    Ok(())
+
+    if !ready_path.exists() {
+        File::create(ready_path)
+            .map_err(|_| Error::Custom { error: "File Creation failed".to_string() })?;
+
+        return Ok(false);
+    }
+
+    let can_replay = can_perform_replay(pack_path, fingerprint_path)?;
+    Ok(!can_replay)
 }
 
 /// Write build finger print to associate prefetch pack file
diff --git a/init/libprefetch/prefetch/src/args.rs b/init/libprefetch/prefetch/src/args.rs
index e534210b51..4c1e689193 100644
--- a/init/libprefetch/prefetch/src/args.rs
+++ b/init/libprefetch/prefetch/src/args.rs
@@ -25,8 +25,6 @@ use std::process::exit;
 
 pub use args_internal::OutputFormat;
 pub use args_internal::ReplayArgs;
-#[cfg(target_os = "android")]
-pub use args_internal::StartArgs;
 pub use args_internal::TracerType;
 pub use args_internal::{DumpArgs, MainArgs, RecordArgs, SubCommands};
 use serde::Deserialize;
@@ -68,8 +66,6 @@ fn verify_and_fix(args: &mut MainArgs) -> Result<(), Error> {
         SubCommands::Dump(arg) => {
             ensure_path_exists(&arg.path)?;
         }
-        #[cfg(target_os = "android")]
-        SubCommands::Start(_arg) => return Ok(()),
     }
     Ok(())
 }
diff --git a/init/libprefetch/prefetch/src/args/args_argh.rs b/init/libprefetch/prefetch/src/args/args_argh.rs
index 65084eeaad..d2251e6a5d 100644
--- a/init/libprefetch/prefetch/src/args/args_argh.rs
+++ b/init/libprefetch/prefetch/src/args/args_argh.rs
@@ -40,12 +40,6 @@ pub enum SubCommands {
     Replay(ReplayArgs),
     /// Dump prefetch data in human readable format
     Dump(DumpArgs),
-    /// Start prefetch service if possible
-    /// If the pack file is present, then prefetch replay is started
-    /// If the pack file is absent or if the build fingerprint
-    /// of the current pack file is different, then prefetch record is started.
-    #[cfg(target_os = "android")]
-    Start(StartArgs),
 }
 
 #[cfg(target_os = "android")]
@@ -58,22 +52,6 @@ fn default_build_finger_print_path() -> PathBuf {
     PathBuf::from("/metadata/prefetch/build_finger_print")
 }
 
-#[cfg(target_os = "android")]
-#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
-/// Start prefetch service based on if pack file is present.
-#[argh(subcommand, name = "start")]
-pub struct StartArgs {
-    /// file path to check if prefetch_ready is present.
-    ///
-    /// A new file is created at the given path if it's not present.
-    #[argh(option, default = "default_ready_path()")]
-    pub path: PathBuf,
-
-    /// file path where build fingerprint is stored
-    #[argh(option, default = "default_build_finger_print_path()")]
-    pub build_fingerprint_path: PathBuf,
-}
-
 impl Default for SubCommands {
     fn default() -> Self {
         Self::Dump(DumpArgs::default())
@@ -147,6 +125,13 @@ pub struct RecordArgs {
     /// store build_finger_print to tie the pack format
     #[argh(option, default = "default_build_finger_print_path()")]
     pub build_fingerprint_path: PathBuf,
+
+    #[cfg(target_os = "android")]
+    /// file path to check if prefetch_ready is present.
+    ///
+    /// A new file is created at the given path if it's not present.
+    #[argh(option, default = "default_ready_path()")]
+    pub ready_path: PathBuf,
 }
 
 /// Type of tracing subsystem to use.
@@ -204,6 +189,11 @@ pub struct ReplayArgs {
     /// file path from where the prefetch config file will be read
     #[argh(option, default = "PathBuf::new()")]
     pub config_path: PathBuf,
+
+    #[cfg(target_os = "android")]
+    /// store build_finger_print to tie the pack format
+    #[argh(option, default = "default_build_finger_print_path()")]
+    pub build_fingerprint_path: PathBuf,
 }
 
 /// dump records file in given format
diff --git a/init/libprefetch/prefetch/src/lib.rs b/init/libprefetch/prefetch/src/lib.rs
index 6564c4bc6d..ea84c595b2 100644
--- a/init/libprefetch/prefetch/src/lib.rs
+++ b/init/libprefetch/prefetch/src/lib.rs
@@ -42,8 +42,6 @@ use log::LevelFilter;
 pub use args::args_from_env;
 use args::OutputFormat;
 pub use args::ReplayArgs;
-#[cfg(target_os = "android")]
-pub use args::StartArgs;
 pub use args::{DumpArgs, MainArgs, RecordArgs, SubCommands};
 pub use error::Error;
 pub use format::FileId;
@@ -59,6 +57,13 @@ pub use arch::android::*;
 
 /// Records prefetch data for the given configuration
 pub fn record(args: &RecordArgs) -> Result<(), Error> {
+    #[cfg(target_os = "android")]
+    if !ensure_record_is_ready(&args.ready_path, &args.path, &args.build_fingerprint_path)? {
+        info!("Cannot perform record -- skipping");
+        return Ok(());
+    }
+
+    info!("Starting record.");
     let (mut tracer, exit_tx) = tracer::Tracer::create(
         args.trace_buffer_size_kib,
         args.tracing_subsystem.clone(),
@@ -109,6 +114,13 @@ pub fn record(args: &RecordArgs) -> Result<(), Error> {
 
 /// Replays prefetch data for the given configuration
 pub fn replay(args: &ReplayArgs) -> Result<(), Error> {
+    #[cfg(target_os = "android")]
+    if !can_perform_replay(&args.path, &args.build_fingerprint_path)? {
+        info!("Cannot perform replay -- exiting.");
+        return Ok(());
+    }
+
+    info!("Starting replay.");
     let replay = Replay::new(args)?;
     replay.replay()
 }
diff --git a/init/libprefetch/prefetch/src/main.rs b/init/libprefetch/prefetch/src/main.rs
index eab826f250..046e07edab 100644
--- a/init/libprefetch/prefetch/src/main.rs
+++ b/init/libprefetch/prefetch/src/main.rs
@@ -22,8 +22,6 @@ use prefetch_rs::dump;
 use prefetch_rs::init_logging;
 use prefetch_rs::record;
 use prefetch_rs::replay;
-#[cfg(target_os = "android")]
-use prefetch_rs::start_prefetch;
 use prefetch_rs::LogLevel;
 use prefetch_rs::MainArgs;
 use prefetch_rs::SubCommands;
@@ -35,8 +33,6 @@ fn main() {
         SubCommands::Record(args) => record(args),
         SubCommands::Replay(args) => replay(args),
         SubCommands::Dump(args) => dump(args),
-        #[cfg(target_os = "android")]
-        SubCommands::Start(args) => start_prefetch(args),
     };
 
     if let Err(err) = ret {
diff --git a/init/libprefetch/prefetch/src/tracer/mem.rs b/init/libprefetch/prefetch/src/tracer/mem.rs
index f69ae807b1..42120da1bc 100644
--- a/init/libprefetch/prefetch/src/tracer/mem.rs
+++ b/init/libprefetch/prefetch/src/tracer/mem.rs
@@ -320,8 +320,8 @@ impl TraceLineInfo {
     // Convenience function to create regex. Used once per life of `record` but multiple times in
     // case of tests.
     pub fn get_trace_line_regex() -> Result<Regex, Error> {
-        // TODO: Fix this Regex expression for 5.15 kernels. This expression
-        // works only on 6.1+. Prior to 6.1, "<page>" was present in the output.
+        // `page=[hex]` entry exists in 5.x kernel format but not in 6.x.
+        // Conversely, `order=[digit]` entry exists in 6.x kernel format but not in 5.x.
         Regex::new(concat!(
             r"^\s+(?P<cmd_pid>\S+)",
             r"\s+(?P<cpu>\S+)",
@@ -330,9 +330,10 @@ impl TraceLineInfo {
             r"\s+mm_filemap_add_to_page_cache:",
             r"\s+dev\s+(?P<major>[0-9]+):(?P<minor>[0-9]+)",
             r"\s+ino\s+(?P<ino>\S+)",
-            //r"\s+(?P<page>\S+)",
+            r"(?:\s+(?P<page>page=\S+))?",
             r"\s+(?P<pfn>\S+)",
-            r"\s+ofs=(?P<offset>[0-9]+)"
+            r"\s+ofs=(?P<offset>[0-9]+)",
+            r"(?:\s+(?P<order>\S+))?"
         ))
         .map_err(|e| Error::Custom {
             error: format!("create regex for tracing failed with: {}", e),
@@ -682,22 +683,30 @@ mod tests {
 
     use super::*;
 
-    static TRACE_BUFFER: &str = r#"
- Settingide-502  [001] ....   484.360292: mm_filemap_add_to_page_CACHE: dev 254:6 ino cf1 page=68d477 pfn=59833 ofs=32768
- Settingide-502  [001] ....   484.360311: mm_filemap_add_to_page_cache: dev 254:6 ino cf1 page=759458 pfn=59827 ofs=57344
- BOX_ENTDED-3071 [001] ....   485.276715: mm_filemap_add_to_pag_ecache: dev 254:6 ino 1 page=00cc1c pfn=81748 ofs=13574144
- BOX_ENTDED-3071 [001] ....   485.276990: mm_filemap_add_to_page_cache: dev 254:6 ino cf2 page=36540b pfn=60952 ofs=0
- .gms.peent-843  [001] ....   485.545516: mm_filemap_add_to_page_cache: dev 254:6 ino 1 page=002e8b pfn=58928 ofs=13578240
- .gms.peent-843  [001] ....   485.545820: mm_filemap_add_to_page_cache: dev 254:6 ino cf3 page=6233ce pfn=58108 ofs=0
-      an.bg-459  [001] ....   494.029396: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=c5b5c7 pfn=373933 ofs=1310720
-      an.bg-459  [001] ....   494.029398: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=b8b9ec pfn=410074 ofs=1314816
-       "#;
+    static TRACE_BUFFER: &str = concat!(
+        // kernel 5.x
+        " Settingide-502  [001] ....   484.360292: mm_filemap_add_to_page_CACHE: dev 254:6 ino cf1 page=68d477 pfn=59833 ofs=32768\n",
+        " Settingide-502  [001] ....   484.360311: mm_filemap_add_to_page_cache: dev 254:6 ino cf1 page=759458 pfn=59827 ofs=57344\n",
+        " BOX_ENTDED-3071 [001] ....   485.276715: mm_filemap_add_to_pag_ecache: dev 254:6 ino 1 page=00cc1c pfn=81748 ofs=13574144\n",
+        " BOX_ENTDED-3071 [001] ....   485.276990: mm_filemap_add_to_page_cache: dev 254:6 ino cf2 page=36540b pfn=60952 ofs=0\n",
+        " .gms.peent-843  [001] ....   485.545516: mm_filemap_add_to_page_cache: dev 254:6 ino 1 page=002e8b pfn=58928 ofs=13578240\n",
+        " .gms.peent-843  [001] ....   485.545820: mm_filemap_add_to_page_cache: dev 254:6 ino cf3 page=6233ce pfn=58108 ofs=0\n",
+        "      an.bg-459  [001] ....   494.029396: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=c5b5c7 pfn=373933 ofs=1310720\n",
+        "      an.bg-459  [001] ....   494.029398: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=b8b9ec pfn=410074 ofs=1314816\n",
+
+        // kernel 6.x
+        " logcat-686     [006] ..... 148216.040320: mm_filemap_add_to_page_CACHE: dev 254:85 ino 3f15 pfn=0x213bc2 ofs=528384 order=0\n",
+        " logcat-686     [001] ..... 148217.776227: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x21d306 ofs=532480 order=0\n",
+        " logcat-686     [003] ..... 148219.044389: mm_filemap_add_to_pag_ecache: dev 254:85 ino 3f15 pfn=0x224b8d ofs=536576 order=0\n",
+        " logcat-686     [001] ..... 148220.780964: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x1bfe0a ofs=540672 order=0\n",
+        " logcat-686     [001] ..... 148223.046560: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x1f3d29 ofs=544768 order=0",
+    );
 
     fn sample_mem_traces() -> (String, Vec<Option<TraceLineInfo>>) {
         (
             TRACE_BUFFER.to_owned(),
             vec![
-                None,
+                // 5.x
                 None,
                 Some(TraceLineInfo::from_fields(254, 6, 0xcf1, 57344, 484360311000)),
                 None,
@@ -706,7 +715,12 @@ mod tests {
                 Some(TraceLineInfo::from_fields(254, 6, 0xcf3, 0, 485545820000)),
                 Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1310720, 494029396000)),
                 Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1314816, 494029398000)),
+                // 6.x
+                None,
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 532480, 148217776227000)),
                 None,
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 540672, 148220780964000)),
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 544768, 148223046560000)),
             ],
         )
     }
diff --git a/init/oneshot_on_test.cpp b/init/oneshot_on_test.cpp
index 650f0650b2..b039ac2337 100644
--- a/init/oneshot_on_test.cpp
+++ b/init/oneshot_on_test.cpp
@@ -39,11 +39,13 @@ TEST(init, oneshot_on) {
 
     // Bootanim exits quickly when the device is fully booted, so check that it goes back to the
     // 'restarting' state that non-oneshot services enter once they've restarted.
-    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "restarting", 10s));
+    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "restarting", 10s))
+            << "Value is: " << GetProperty("init.svc.bootanim", "");
 
     SetProperty("ctl.oneshot_on", "bootanim");
     SetProperty("ctl.start", "bootanim");
 
     // Now that oneshot is enabled again, bootanim should transition into the 'stopped' state.
-    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "stopped", 10s));
+    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "stopped", 10s))
+            << "Value is: " << GetProperty("init.svc.bootanim", "");
 }
diff --git a/init/property_service.cpp b/init/property_service.cpp
index f2606e3c58..83e9a0da35 100644
--- a/init/property_service.cpp
+++ b/init/property_service.cpp
@@ -103,8 +103,6 @@ using android::properties::PropertyInfoEntry;
 namespace android {
 namespace init {
 
-class PersistWriteThread;
-
 constexpr auto FINGERPRINT_PROP = "ro.build.fingerprint";
 constexpr auto LEGACY_FINGERPRINT_PROP = "ro.build.legacy.fingerprint";
 constexpr auto ID_PROP = "ro.build.id";
@@ -122,8 +120,6 @@ static std::mutex selinux_check_access_lock;
 static std::thread property_service_thread;
 static std::thread property_service_for_system_thread;
 
-static std::unique_ptr<PersistWriteThread> persist_write_thread;
-
 static PropertyInfoAreaFile property_info_area;
 
 struct PropertyAuditData {
@@ -384,6 +380,8 @@ class PersistWriteThread {
     std::deque<std::tuple<std::string, std::string, SocketConnection>> work_;
 };
 
+static std::unique_ptr<PersistWriteThread> persist_write_thread;
+
 static std::optional<uint32_t> PropertySet(const std::string& name, const std::string& value,
                                            SocketConnection* socket, std::string* error) {
     size_t valuelen = value.size();
@@ -595,7 +593,7 @@ uint32_t HandlePropertySetNoSocket(const std::string& name, const std::string& v
 }
 
 static void handle_property_set_fd(int fd) {
-    static constexpr uint32_t kDefaultSocketTimeout = 2000; /* ms */
+    static constexpr uint32_t kDefaultSocketTimeout = 5000; /* ms */
 
     int s = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
     if (s == -1) {
diff --git a/init/reboot.cpp b/init/reboot.cpp
index ef9db9fdae..a26149f77e 100644
--- a/init/reboot.cpp
+++ b/init/reboot.cpp
@@ -268,6 +268,19 @@ static void DumpUmountDebuggingInfo() {
 }
 
 static UmountStat UmountPartitions(std::chrono::milliseconds timeout) {
+    // Terminate (SIGTERM) the services before unmounting partitions.
+    // If the processes block the signal, then partitions will eventually fail
+    // to unmount and then we fallback to SIGKILL the services.
+    //
+    // Hence, give the services a chance for a graceful shutdown before sending SIGKILL.
+    for (const auto& s : ServiceList::GetInstance()) {
+        if (s->IsShutdownCritical()) {
+            LOG(INFO) << "Shutdown service: " << s->name();
+            s->Terminate();
+        }
+    }
+    ReapAnyOutstandingChildren();
+
     Timer t;
     /* data partition needs all pending writes to be completed and all emulated partitions
      * umounted.If the current waiting is not good enough, give
@@ -394,6 +407,24 @@ void RebootMonitorThread(unsigned int cmd, const std::string& reboot_target,
     }
 }
 
+static bool UmountDynamicPartitions(const std::vector<std::string>& dynamic_partitions) {
+    bool ret = true;
+    for (auto device : dynamic_partitions) {
+        // Cannot unmount /system
+        if (device == "/system") {
+            continue;
+        }
+        int r = umount2(device.c_str(), MNT_FORCE);
+        if (r == 0) {
+            LOG(INFO) << "Umounted success: " << device;
+        } else {
+            PLOG(WARNING) << "Cannot umount: " << device;
+            ret = false;
+        }
+    }
+    return ret;
+}
+
 /* Try umounting all emulated file systems R/W block device cfile systems.
  * This will just try umount and give it up if it fails.
  * For fs like ext4, this is ok as file system will be marked as unclean shutdown
@@ -408,14 +439,18 @@ static UmountStat TryUmountAndFsck(unsigned int cmd, bool run_fsck,
     Timer t;
     std::vector<MountEntry> block_devices;
     std::vector<MountEntry> emulated_devices;
+    std::vector<std::string> dynamic_partitions;
 
     if (run_fsck && !FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
         return UMOUNT_STAT_ERROR;
     }
     auto sm = snapshot::SnapshotManager::New();
     bool ota_update_in_progress = false;
-    if (sm->IsUserspaceSnapshotUpdateInProgress()) {
-        LOG(INFO) << "OTA update in progress";
+    if (sm->IsUserspaceSnapshotUpdateInProgress(dynamic_partitions)) {
+        LOG(INFO) << "OTA update in progress. Pause snapshot merge";
+        if (!sm->PauseSnapshotMerge()) {
+            LOG(ERROR) << "Snapshot-merge pause failed";
+        }
         ota_update_in_progress = true;
     }
     UmountStat stat = UmountPartitions(timeout - t.duration());
@@ -435,6 +470,17 @@ static UmountStat TryUmountAndFsck(unsigned int cmd, bool run_fsck,
         // still not doing fsck when all processes are killed.
         //
         if (ota_update_in_progress) {
+            bool umount_dynamic_partitions = UmountDynamicPartitions(dynamic_partitions);
+            LOG(INFO) << "Sending SIGTERM to all process";
+            // Send SIGTERM to all processes except init
+            WriteStringToFile("e", PROC_SYSRQ);
+            // Wait for processes to terminate
+            std::this_thread::sleep_for(1s);
+            // Try one more attempt to umount other partitions which failed
+            // earlier
+            if (!umount_dynamic_partitions) {
+                UmountDynamicPartitions(dynamic_partitions);
+            }
             return stat;
         }
         KillAllProcesses();
@@ -486,8 +532,7 @@ static Result<void> KillZramBackingDevice() {
         return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
     }
 
-    // cut the last "\n"
-    backing_dev.erase(backing_dev.length() - 1);
+    android::base::Trim(backing_dev);
 
     if (android::base::StartsWith(backing_dev, "none")) {
         LOG(INFO) << "No zram backing device configured";
@@ -508,6 +553,12 @@ static Result<void> KillZramBackingDevice() {
                        << " failed";
     }
 
+    if (!android::base::ReadFileToString(ZRAM_BACK_DEV, &backing_dev)) {
+        return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
+    }
+
+    android::base::Trim(backing_dev);
+
     if (!android::base::StartsWith(backing_dev, "/dev/block/loop")) {
         LOG(INFO) << backing_dev << " is not a loop device. Exiting early";
         return {};
@@ -777,6 +828,7 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
     if (IsDataMounted("f2fs")) {
         uint32_t flag = F2FS_GOING_DOWN_FULLSYNC;
         unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
+        LOG(INFO) << "Invoking F2FS_IOC_SHUTDOWN during shutdown";
         int ret = ioctl(fd.get(), F2FS_IOC_SHUTDOWN, &flag);
         if (ret) {
             PLOG(ERROR) << "Shutdown /data: ";
diff --git a/init/selinux.cpp b/init/selinux.cpp
index 6316b4deb3..03fd2d2bf1 100644
--- a/init/selinux.cpp
+++ b/init/selinux.cpp
@@ -56,6 +56,7 @@
 #include <linux/audit.h>
 #include <linux/netlink.h>
 #include <stdlib.h>
+#include <sys/mount.h>
 #include <sys/wait.h>
 #include <unistd.h>
 
@@ -69,6 +70,7 @@
 #include <android/avf_cc_flags.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
+#include <fs_mgr_overlayfs.h>
 #include <genfslabelsversion.h>
 #include <libgsi/libgsi.h>
 #include <libsnapshot/snapshot.h>
@@ -77,6 +79,7 @@
 #include "block_dev_initializer.h"
 #include "debug_ramdisk.h"
 #include "reboot_utils.h"
+#include "second_stage_resources.h"
 #include "snapuserd_transition.h"
 #include "util.h"
 
@@ -698,6 +701,75 @@ void LoadSelinuxPolicyAndroid() {
     }
 }
 
+#ifdef ALLOW_REMOUNT_OVERLAYS
+bool EarlySetupOverlays() {
+    if (android::fs_mgr::use_override_creds) return false;
+
+    bool has_overlays = false;
+    std::string contents;
+    auto result = android::base::ReadFileToString("/proc/mounts", &contents, true);
+
+    auto lines = android::base::Split(contents, "\n");
+    for (auto const& line : lines)
+        if (android::base::StartsWith(line, "overlay")) {
+            has_overlays = true;
+            break;
+        }
+
+    if (!has_overlays) return false;
+    if (mount("tmpfs", kSecondStageRes, "tmpfs", MS_REMOUNT | MS_NOSUID | MS_NODEV,
+              "mode=0755,uid=0,gid=0") == -1) {
+        PLOG(FATAL) << "Failed to remount tmpfs on " << kSecondStageRes << " to remove NO_EXEC";
+    }
+
+    return true;
+}
+
+void SetupOverlays() {
+    // After adb remount, we mount all r/o volumes with overlayfs to allow writing.
+    // However, since overlayfs performs its file operations in the context of the
+    // mounting process, this will not work as is - init is in the kernel domain in
+    // first stage, which has very limited permissions.
+
+    // In order to fix this, we need to unmount remount all these volumes from a process
+    // with sufficient privileges to be able to perform these operations. The
+    // overlay_remounter domain has those privileges on debuggable devices.
+    // We will call overlay_remounter which will do the unmounts/mounts.
+    // But for that to work, the volumes must not be busy, so we need to copy
+    // overlay_remounter from system to a ramdisk and run it from there.
+    const char* kOverlayRemounter = "overlay_remounter";
+    auto or_src = std::filesystem::path("/system/xbin/") / kOverlayRemounter;
+    auto or_dest = std::filesystem::path(kSecondStageRes) / kOverlayRemounter;
+    std::error_code ec;
+    std::filesystem::copy(or_src, or_dest, ec);
+    if (ec) {
+        LOG(FATAL) << "Failed to copy " << or_src << " to " << or_dest << " " << ec.message();
+    }
+
+    if (selinux_android_restorecon(or_dest.c_str(), 0) == -1) {
+        PLOG(FATAL) << "restorecon of " << or_dest << " failed";
+    }
+    auto dest = unique_fd(open(or_dest.c_str(), O_RDONLY | O_CLOEXEC));
+    if (dest.get() == -1) {
+        PLOG(FATAL) << "Failed to reopen " << or_dest;
+    }
+    if (unlink(or_dest.c_str()) == -1) {
+        PLOG(FATAL) << "Failed to unlink " << or_dest;
+    }
+    const char* args[] = {or_dest.c_str(), nullptr};
+    fexecve(dest.get(), const_cast<char**>(args), environ);
+
+    // execv() only returns if an error happened, in which case we
+    // panic and never return from this function.
+    PLOG(FATAL) << "execv(\"" << or_dest << "\") failed";
+}
+#else
+bool EarlySetupOverlays() {
+    return false;
+}
+void SetupOverlays() {}
+#endif
+
 int SetupSelinux(char** argv) {
     SetStdioToDevNull(argv);
     InitKernelLogging(argv);
@@ -710,6 +782,9 @@ int SetupSelinux(char** argv) {
 
     SelinuxSetupKernelLogging();
 
+    // Test to see if we should use overlays, and if so remount tmpfs before selinux will block
+    bool use_overlays = EarlySetupOverlays();
+
     // TODO(b/287206497): refactor into different headers to only include what we need.
     if (IsMicrodroid()) {
         LoadSelinuxPolicyMicrodroid();
@@ -738,6 +813,10 @@ int SetupSelinux(char** argv) {
 
     setenv(kEnvSelinuxStartedAt, std::to_string(start_time.time_since_epoch().count()).c_str(), 1);
 
+    // SetupOverlays does not return if overlays exist, instead it execs overlay_remounter
+    // which then execs second stage init
+    if (use_overlays) SetupOverlays();
+
     const char* path = "/system/bin/init";
     const char* args[] = {path, "second_stage", nullptr};
     execv(path, const_cast<char**>(args));
diff --git a/init/service.cpp b/init/service.cpp
index d76a5d5e0d..56300205d2 100644
--- a/init/service.cpp
+++ b/init/service.cpp
@@ -34,6 +34,7 @@
 #include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
+#include <cutils/android_get_control_file.h>
 #include <cutils/sockets.h>
 #include <processgroup/processgroup.h>
 #include <selinux/selinux.h>
@@ -672,6 +673,14 @@ Result<void> Service::Start() {
         }
     }
 
+    if (shared_kallsyms_file_) {
+        if (auto result = CreateSharedKallsymsFd(); result.ok()) {
+            descriptors.emplace_back(std::move(*result));
+        } else {
+            LOG(INFO) << "Could not obtain a copy of /proc/kallsyms: " << result.error();
+        }
+    }
+
     pid_t pid = -1;
     if (namespaces_.flags) {
         pid = clone(nullptr, nullptr, namespaces_.flags | SIGCHLD, nullptr);
@@ -835,6 +844,35 @@ unique_fd Service::CreateSigchldFd() {
     return unique_fd(signalfd(-1, &mask, SFD_CLOEXEC));
 }
 
+void Service::OpenAndSaveStaticKallsymsFd() {
+    Result<Descriptor> result = CreateSharedKallsymsFd();
+    if (!result.ok()) {
+      LOG(ERROR) << result.error();
+    }
+}
+
+// This function is designed to be called in two situations:
+// 1) early during second_stage init, to open and save the shared fd as a
+//    static (see OpenAndSaveStaticKallsymsFd).
+// 2) whenever a service requesting a copy of the fd is being started, at which
+//    point it will get a duplicated copy of the static fd.
+Result<Descriptor> Service::CreateSharedKallsymsFd() {
+    static constexpr char kallsyms_path[] = "/proc/kallsyms";
+    static int static_fd = open(kallsyms_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
+    if (static_fd < 0) {
+        return ErrnoError() << "failed to open " << kallsyms_path;
+    }
+
+    unique_fd fd{fcntl(static_fd, F_DUPFD_CLOEXEC, /*min_fd=*/3)};
+    if (fd < 0) {
+        return ErrnoError() << "failed fcntl(F_DUPFD_CLOEXEC)";
+    }
+
+    // Use the same environment variable as if the service specified
+    // "file /proc/kallsyms r".
+    return Descriptor(std::string(ANDROID_FILE_ENV_PREFIX) + kallsyms_path, std::move(fd));
+}
+
 void Service::SetStartedInFirstStage(pid_t pid) {
     LOG(INFO) << "adding first-stage service '" << name_ << "'...";
 
diff --git a/init/service.h b/init/service.h
index ae75553d32..7193d7eb1b 100644
--- a/init/service.h
+++ b/init/service.h
@@ -158,6 +158,7 @@ class Service {
         static int sigchld_fd = CreateSigchldFd().release();
         return sigchld_fd;
     }
+    static void OpenAndSaveStaticKallsymsFd();
 
   private:
     void NotifyStateChange(const std::string& new_state) const;
@@ -171,6 +172,7 @@ class Service {
                     InterprocessFifo setsid_finished);
     void SetMountNamespace();
     static ::android::base::unique_fd CreateSigchldFd();
+    static Result<Descriptor> CreateSharedKallsymsFd();
 
     static unsigned long next_start_order_;
     static bool is_exec_service_running_;
@@ -188,6 +190,7 @@ class Service {
     std::optional<std::string> fatal_reboot_target_;  // reboot target of fatal handler
     bool was_last_exit_ok_ =
             true;  // true if the service never exited, or exited with status code 0
+    bool shared_kallsyms_file_ = false; // pass the service a pre-opened fd to /proc/kallsyms
 
     std::optional<CapSet> capabilities_;
     ProcessAttributes proc_attr_;
diff --git a/init/service_parser.cpp b/init/service_parser.cpp
index ec3b176d42..bd6930065e 100644
--- a/init/service_parser.cpp
+++ b/init/service_parser.cpp
@@ -309,7 +309,13 @@ Result<void> ServiceParser::ParseOverride(std::vector<std::string>&& args) {
     return {};
 }
 
+Result<void> ServiceParser::ParseSharedKallsyms(std::vector<std::string>&& args) {
+    service_->shared_kallsyms_file_ = true;
+    return {};
+}
+
 Result<void> ServiceParser::ParseMemcgSwappiness(std::vector<std::string>&& args) {
+    LOG(WARNING) << "memcg.swappiness is unsupported with memcg v2 and will be deprecated";
     if (!ParseInt(args[1], &service_->swappiness_, 0)) {
         return Error() << "swappiness value must be equal or greater than 0";
     }
@@ -603,6 +609,7 @@ const KeywordMap<ServiceParser::OptionParser>& ServiceParser::GetParserMap() con
         {"rlimit",                  {3,     3,    &ServiceParser::ParseProcessRlimit}},
         {"seclabel",                {1,     1,    &ServiceParser::ParseSeclabel}},
         {"setenv",                  {2,     2,    &ServiceParser::ParseSetenv}},
+        {"shared_kallsyms",         {0,     0,    &ServiceParser::ParseSharedKallsyms}},
         {"shutdown",                {1,     1,    &ServiceParser::ParseShutdown}},
         {"sigstop",                 {0,     0,    &ServiceParser::ParseSigstop}},
         {"socket",                  {3,     6,    &ServiceParser::ParseSocket}},
diff --git a/init/service_parser.h b/init/service_parser.h
index f06cfc47d9..e42b62b5cc 100644
--- a/init/service_parser.h
+++ b/init/service_parser.h
@@ -67,6 +67,7 @@ class ServiceParser : public SectionParser {
     Result<void> ParseRestartPeriod(std::vector<std::string>&& args);
     Result<void> ParseSeclabel(std::vector<std::string>&& args);
     Result<void> ParseSetenv(std::vector<std::string>&& args);
+    Result<void> ParseSharedKallsyms(std::vector<std::string>&& args);
     Result<void> ParseShutdown(std::vector<std::string>&& args);
     Result<void> ParseSigstop(std::vector<std::string>&& args);
     Result<void> ParseSocket(std::vector<std::string>&& args);
diff --git a/init/service_test.cpp b/init/service_test.cpp
index 53b53ed5a3..d75d4f1ecb 100644
--- a/init/service_test.cpp
+++ b/init/service_test.cpp
@@ -27,6 +27,7 @@
 #include <android-base/file.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
+#include <fstab/fstab.h>
 #include <selinux/selinux.h>
 #include <sys/signalfd.h>
 #include "lmkd_service.h"
@@ -280,5 +281,74 @@ service $name /system/bin/yes
 
 INSTANTIATE_TEST_SUITE_P(service, ServiceStopTest, testing::Values(false, true));
 
+// Entering a network namespace requires remounting sysfs to update contents of
+// /sys/class/net whose contents depend on the network namespace of the process
+// that mounted it rather than the effective network namespace of the reading
+// process.
+//
+// A side effect of the remounting is unmounting all filesystems mounted under
+// /sys, like tracefs. Verify that init doesn't leave them unmounted by
+// accident.
+TEST(service, enter_namespace_net_preserves_mounts) {
+    if (getuid() != 0) {
+        GTEST_SKIP() << "Must be run as root.";
+        return;
+    }
+
+    struct ScopedNetNs {
+        std::string name;
+        ScopedNetNs(std::string n) : name(n) {
+            EXPECT_EQ(system(("/system/bin/ip netns add " + name).c_str()), 0);
+        }
+        ~ScopedNetNs() { EXPECT_EQ(system(("/system/bin/ip netns delete " + name).c_str()), 0); }
+    };
+    const ScopedNetNs netns("test_ns");
+
+    static constexpr std::string_view kServiceName = "ServiceA";
+    static constexpr std::string_view kScriptTemplate = R"init(
+service $name /system/bin/yes
+    user shell
+    group shell
+    seclabel $selabel
+    enter_namespace net /mnt/run/$ns_name
+)init";
+
+    std::string script = StringReplace(kScriptTemplate, "$name", kServiceName, false);
+    script = StringReplace(script, "$selabel", GetSecurityContext(), false);
+    script = StringReplace(script, "$ns_name", netns.name, false);
+
+    ServiceList& service_list = ServiceList::GetInstance();
+    Parser parser;
+    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));
+
+    TemporaryFile tf;
+    ASSERT_GE(tf.fd, 0);
+    ASSERT_TRUE(WriteStringToFd(script, tf.fd));
+    ASSERT_TRUE(parser.ParseConfig(tf.path));
+
+    Service* const service = ServiceList::GetInstance().FindService(kServiceName);
+    ASSERT_NE(service, nullptr);
+    ASSERT_RESULT_OK(service->Start());
+    ASSERT_TRUE(service->IsRunning());
+
+    android::fs_mgr::Fstab root_mounts;
+    ASSERT_TRUE(ReadFstabFromFile("/proc/mounts", &root_mounts));
+
+    android::fs_mgr::Fstab ns_mounts;
+    ASSERT_TRUE(ReadFstabFromFile(StringReplace("/proc/$pid/mounts", "$pid",
+                                                std::to_string(service->pid()), /*all=*/false),
+                                  &ns_mounts));
+
+    for (const auto& expected_mount : root_mounts) {
+        auto it = std::find_if(ns_mounts.begin(), ns_mounts.end(), [&](const auto& ns_mount) {
+            return ns_mount.mount_point == expected_mount.mount_point;
+        });
+        EXPECT_TRUE(it != ns_mounts.end()) << StringPrintf(
+                "entering network namespace unmounted %s", expected_mount.mount_point.c_str());
+    }
+
+    ServiceList::GetInstance().RemoveService(*service);
+}
+
 }  // namespace init
 }  // namespace android
diff --git a/init/service_utils.cpp b/init/service_utils.cpp
index 0e19bcc58c..8d9a046a30 100644
--- a/init/service_utils.cpp
+++ b/init/service_utils.cpp
@@ -18,11 +18,11 @@
 
 #include <fcntl.h>
 #include <grp.h>
-#include <map>
 #include <sys/mount.h>
 #include <sys/prctl.h>
 #include <sys/wait.h>
 #include <unistd.h>
+#include <map>
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
@@ -31,6 +31,7 @@
 #include <android-base/strings.h>
 #include <cutils/android_get_control_file.h>
 #include <cutils/sockets.h>
+#include <fstab/fstab.h>
 #include <processgroup/processgroup.h>
 
 #include "mount_namespace.h"
@@ -82,12 +83,39 @@ Result<void> SetUpMountNamespace(bool remount_proc, bool remount_sys) {
         }
     }
     if (remount_sys) {
+        android::fs_mgr::Fstab mounts;
+        if (!ReadFstabFromFile("/proc/mounts", &mounts)) {
+            LOG(ERROR) << "Could not read /proc/mounts";
+        }
         if (umount2("/sys", MNT_DETACH) == -1) {
             return ErrnoError() << "Could not umount(/sys)";
         }
-        if (mount("", "/sys", "sysfs", kSafeFlags, "") == -1) {
+        if (mount("sysfs", "/sys", "sysfs", kSafeFlags, "") == -1) {
             return ErrnoError() << "Could not mount(/sys)";
         }
+        // Unmounting /sys also unmounts all nested mounts like tracefs.
+        //
+        // Look up the filesystems that were mounted under /sys before we wiped
+        // it and attempt to restore them.
+        for (const auto& entry : mounts) {
+            // Never mount /sys/kernel/debug/tracing. This is the *one* mount
+            // that is special within Linux kernel: for backward compatibility
+            // tracefs gets auto-mounted there whenever one mounts debugfs [1].
+            //
+            // Attempting to mount the filesystem here will cause SELinux
+            // denials, because unlike *all other* filesystems in Android, it's
+            // not init who mounted it so there's no policy that would allow it.
+            //
+            // [1] https://lore.kernel.org/lkml/20150204143755.694479564@goodmis.org/
+            if (entry.mount_point.starts_with("/sys/") &&
+                entry.mount_point != "/sys/kernel/debug/tracing") {
+                if (mount(entry.blk_device.c_str(), entry.mount_point.c_str(),
+                          entry.fs_type.c_str(), entry.flags, "")) {
+                    LOG(WARNING) << "Could not mount(" << entry.mount_point
+                                 << ") after switching netns: " << ErrnoError().str();
+                }
+            }
+        }
     }
     return {};
 }
diff --git a/init/test_upgrade_mte/OWNERS b/init/test_upgrade_mte/OWNERS
index c95d3cfd00..a49d9cedf0 100644
--- a/init/test_upgrade_mte/OWNERS
+++ b/init/test_upgrade_mte/OWNERS
@@ -1,4 +1,3 @@
 fmayer@google.com
 
-eugenis@google.com
 pcc@google.com
diff --git a/init/tradeinmode.cpp b/init/tradeinmode.cpp
new file mode 100644
index 0000000000..1913bae33e
--- /dev/null
+++ b/init/tradeinmode.cpp
@@ -0,0 +1,79 @@
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
+#include <stddef.h>
+#include <stdint.h>
+#include <unistd.h>
+
+#include <string>
+#include <vector>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/parseint.h>
+#include <bootloader_message/bootloader_message.h>
+#include <cutils/android_reboot.h>
+
+#include "reboot_utils.h"
+
+namespace android {
+namespace init {
+
+void RequestTradeInModeWipeIfNeeded() {
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
+    if (android::base::ReadFileToString(kWipeIndicator, &contents)) {
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
+}  // namespace init
+}  // namespace android
diff --git a/init/tradeinmode.h b/init/tradeinmode.h
new file mode 100644
index 0000000000..fec2a0178f
--- /dev/null
+++ b/init/tradeinmode.h
@@ -0,0 +1,25 @@
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
+namespace android {
+namespace init {
+
+void RequestTradeInModeWipeIfNeeded();
+
+}  // namespace init
+}  // namespace android
diff --git a/init/ueventd_test.cpp b/init/ueventd_test.cpp
index 1ac6d8ee07..5921ece838 100644
--- a/init/ueventd_test.cpp
+++ b/init/ueventd_test.cpp
@@ -19,6 +19,7 @@
 #include <sys/stat.h>
 #include <unistd.h>
 
+#include <algorithm>
 #include <atomic>
 #include <chrono>
 #include <string>
diff --git a/janitors/OWNERS b/janitors/OWNERS
index c25d9e465b..b317151515 100644
--- a/janitors/OWNERS
+++ b/janitors/OWNERS
@@ -1,7 +1,19 @@
-# OWNERS file for projects that don't really have owners so much as volunteer janitors.
+# go/android-3p requires that all external projects have the "janitors" in
+# their OWNERS files.
+
+# These are also the "owners" for projects that don't really have owners
+# so much as volunteer janitors.
+
+# General maintenance.
+sadafebrahimi@google.com
+
+# C/C++.
 ccross@google.com
 cferris@google.com
-dwillemsen@google.com
 enh@google.com
+
+# Java.
 maco@google.com
-sadafebrahimi@google.com
+
+# Python.
+dwillemsen@google.com
diff --git a/libappfuse/FuseBuffer.cc b/libappfuse/FuseBuffer.cc
index 1915f22ba2..269f300b9b 100644
--- a/libappfuse/FuseBuffer.cc
+++ b/libappfuse/FuseBuffer.cc
@@ -35,6 +35,8 @@ namespace fuse {
 namespace {
 
 constexpr useconds_t kRetrySleepForWriting = 1000;  // 1 ms
+// This makes the total wait time to allocate a buffer 5 seconds
+const int kNumberOfRetriesForWriting = 5000;
 
 template <typename T>
 bool CheckHeaderLength(const FuseMessage<T>* self, const char* name, size_t max_size) {
@@ -92,6 +94,7 @@ ResultOrAgain WriteInternal(const FuseMessage<T>* self, int fd, int sockflag, co
 
     const char* const buf = reinterpret_cast<const char*>(self);
     const auto& header = static_cast<const T*>(self)->header;
+    int retry = kNumberOfRetriesForWriting;
 
     while (true) {
         int result;
@@ -110,8 +113,14 @@ ResultOrAgain WriteInternal(const FuseMessage<T>* self, int fd, int sockflag, co
                 case ENOBUFS:
                     // When returning ENOBUFS, epoll still reports the FD is writable. Just usleep
                     // and retry again.
-                    usleep(kRetrySleepForWriting);
-                    continue;
+                    if (retry > 0) {
+                        usleep(kRetrySleepForWriting);
+                        retry--;
+                        continue;
+                    } else {
+                        LOG(ERROR) << "Failed to write a FUSE message: ENOBUFS retries are failed";
+                        return ResultOrAgain::kFailure;
+                    }
                 case EAGAIN:
                     return ResultOrAgain::kAgain;
                 default:
diff --git a/libcutils/android_get_control_file_test.cpp b/libcutils/android_get_control_file_test.cpp
index 8de85307de..e57af5ee4c 100644
--- a/libcutils/android_get_control_file_test.cpp
+++ b/libcutils/android_get_control_file_test.cpp
@@ -21,6 +21,7 @@
 #include <sys/types.h>
 #include <time.h>
 
+#include <algorithm>
 #include <string>
 
 #include <android-base/file.h>
diff --git a/libcutils/ashmem-dev.cpp b/libcutils/ashmem-dev.cpp
index cebfa5d12b..80c4f4c1ea 100644
--- a/libcutils/ashmem-dev.cpp
+++ b/libcutils/ashmem-dev.cpp
@@ -44,6 +44,8 @@
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 
+#include "ashmem-internal.h"
+
 /* ashmem identity */
 static dev_t __ashmem_rdev;
 /*
@@ -76,8 +78,8 @@ static pthread_mutex_t __ashmem_lock = PTHREAD_MUTEX_INITIALIZER;
  * debugging.
  */
 
-static bool debug_log = false;            /* set to true for verbose logging and other debug  */
-static bool pin_deprecation_warn = true; /* Log the pin deprecation warning only once */
+/* set to true for verbose logging and other debug  */
+static bool debug_log = false;
 
 /* Determine if vendor processes would be ok with memfd in the system:
  *
@@ -106,7 +108,7 @@ static bool __has_memfd_support() {
      */
     if (!android::base::GetBoolProperty("sys.use_memfd", false)) {
         if (debug_log) {
-            ALOGD("sys.use_memfd=false so memfd disabled\n");
+            ALOGD("sys.use_memfd=false so memfd disabled");
         }
         return false;
     }
@@ -114,36 +116,43 @@ static bool __has_memfd_support() {
     // Check if kernel support exists, otherwise fall back to ashmem.
     // This code needs to build on old API levels, so we can't use the libc
     // wrapper.
-    //
-    // MFD_NOEXEC_SEAL is used to match the semantics of the ashmem device,
-    // which did not have executable permissions. This also seals the executable
-    // permissions of the buffer (i.e. they cannot be changed by fchmod()).
-    //
-    // MFD_NOEXEC_SEAL implies MFD_ALLOW_SEALING.
     android::base::unique_fd fd(
-            syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_NOEXEC_SEAL));
+            syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING));
     if (fd == -1) {
-        ALOGE("memfd_create failed: %s, no memfd support.\n", strerror(errno));
+        ALOGE("memfd_create failed: %m, no memfd support");
         return false;
     }
 
     if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
-        ALOGE("fcntl(F_ADD_SEALS) failed: %s, no memfd support.\n", strerror(errno));
+        ALOGE("fcntl(F_ADD_SEALS) failed: %m, no memfd support");
+        return false;
+    }
+
+    size_t buf_size = getpagesize();
+    if (ftruncate(fd, buf_size) == -1) {
+        ALOGE("ftruncate(%zd) failed to set memfd buffer size: %m, no memfd support", buf_size);
+        return false;
+    }
+
+    /*
+     * Ensure that the kernel supports ashmem ioctl commands on memfds. If not,
+     * fall back to using ashmem.
+     */
+    int ashmem_size = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, 0));
+    if (ashmem_size != static_cast<int>(buf_size)) {
+        ALOGE("ioctl(ASHMEM_GET_SIZE): %d != buf_size: %zd , no ashmem-memfd compat support",
+              ashmem_size, buf_size);
         return false;
     }
 
     if (debug_log) {
-        ALOGD("memfd: device has memfd support, using it\n");
+        ALOGD("memfd: device has memfd support, using it");
     }
     return true;
 }
 
-static bool has_memfd_support() {
-    /* memfd_supported is the initial global per-process state of what is known
-     * about memfd.
-     */
+bool has_memfd_support() {
     static bool memfd_supported = __has_memfd_support();
-
     return memfd_supported;
 }
 
@@ -151,77 +160,56 @@ static std::string get_ashmem_device_path() {
     static const std::string boot_id_path = "/proc/sys/kernel/random/boot_id";
     std::string boot_id;
     if (!android::base::ReadFileToString(boot_id_path, &boot_id)) {
-        ALOGE("Failed to read %s: %s.\n", boot_id_path.c_str(), strerror(errno));
+        ALOGE("Failed to read %s: %m", boot_id_path.c_str());
         return "";
-    };
+    }
     boot_id = android::base::Trim(boot_id);
 
     return "/dev/ashmem" + boot_id;
 }
 
 /* logistics of getting file descriptor for ashmem */
-static int __ashmem_open_locked()
-{
+static int __ashmem_open_locked() {
     static const std::string ashmem_device_path = get_ashmem_device_path();
 
     if (ashmem_device_path.empty()) {
         return -1;
     }
 
-    int fd = TEMP_FAILURE_RETRY(open(ashmem_device_path.c_str(), O_RDWR | O_CLOEXEC));
-
-    // fallback for APEX w/ use_vendor on Q, which would have still used /dev/ashmem
-    if (fd < 0) {
-        int saved_errno = errno;
-        fd = TEMP_FAILURE_RETRY(open("/dev/ashmem", O_RDWR | O_CLOEXEC));
-        if (fd < 0) {
-            /* Q launching devices and newer must not reach here since they should have been
-             * able to open ashmem_device_path */
-            ALOGE("Unable to open ashmem device %s (error = %s) and /dev/ashmem(error = %s)",
-                  ashmem_device_path.c_str(), strerror(saved_errno), strerror(errno));
-            return fd;
-        }
+    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(ashmem_device_path.c_str(), O_RDWR | O_CLOEXEC)));
+    if (!fd.ok()) {
+        ALOGE("Unable to open ashmem device: %m");
+        return -1;
     }
+
     struct stat st;
-    int ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
-    if (ret < 0) {
-        int save_errno = errno;
-        close(fd);
-        errno = save_errno;
-        return ret;
+    if (TEMP_FAILURE_RETRY(fstat(fd, &st)) == -1) {
+        return -1;
     }
     if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
-        close(fd);
         errno = ENOTTY;
         return -1;
     }
 
     __ashmem_rdev = st.st_rdev;
-    return fd;
+    return fd.release();
 }
 
-static int __ashmem_open()
-{
-    int fd;
-
+static int __ashmem_open() {
     pthread_mutex_lock(&__ashmem_lock);
-    fd = __ashmem_open_locked();
+    int fd = __ashmem_open_locked();
     pthread_mutex_unlock(&__ashmem_lock);
-
     return fd;
 }
 
 /* Make sure file descriptor references ashmem, negative number means false */
-static int __ashmem_is_ashmem(int fd, int fatal)
-{
-    dev_t rdev;
+static int __ashmem_is_ashmem(int fd, bool fatal) {
     struct stat st;
-
     if (fstat(fd, &st) < 0) {
         return -1;
     }
 
-    rdev = 0; /* Too much complexity to sniff __ashmem_rdev */
+    dev_t rdev = 0; /* Too much complexity to sniff __ashmem_rdev */
     if (S_ISCHR(st.st_mode) && st.st_rdev) {
         pthread_mutex_lock(&__ashmem_lock);
         rdev = __ashmem_rdev;
@@ -262,18 +250,17 @@ static int __ashmem_is_ashmem(int fd, int fatal)
     return -1;
 }
 
-static int __ashmem_check_failure(int fd, int result)
-{
-    if (result == -1 && errno == ENOTTY) __ashmem_is_ashmem(fd, 1);
+static int __ashmem_check_failure(int fd, int result) {
+    if (result == -1 && errno == ENOTTY) __ashmem_is_ashmem(fd, true);
     return result;
 }
 
-static bool memfd_is_ashmem(int fd) {
+static bool is_ashmem_fd(int fd) {
     static bool fd_check_error_once = false;
 
-    if (__ashmem_is_ashmem(fd, 0) == 0) {
+    if (__ashmem_is_ashmem(fd, false) == 0) {
         if (!fd_check_error_once) {
-            ALOGE("memfd: memfd expected but ashmem fd used - please use libcutils.\n");
+            ALOGE("memfd: memfd expected but ashmem fd used - please use libcutils");
             fd_check_error_once = true;
         }
 
@@ -283,33 +270,30 @@ static bool memfd_is_ashmem(int fd) {
     return false;
 }
 
-int ashmem_valid(int fd)
-{
-    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
+static bool is_memfd_fd(int fd) {
+    return has_memfd_support() && !is_ashmem_fd(fd);
+}
+
+int ashmem_valid(int fd) {
+    if (is_memfd_fd(fd)) {
         return 1;
     }
 
-    return __ashmem_is_ashmem(fd, 0) >= 0;
+    return __ashmem_is_ashmem(fd, false) >= 0;
 }
 
 static int memfd_create_region(const char* name, size_t size) {
     // This code needs to build on old API levels, so we can't use the libc
     // wrapper.
-    //
-    // MFD_NOEXEC_SEAL to match the semantics of the ashmem device, which did
-    // not have executable permissions. This also seals the executable
-    // permissions of the buffer (i.e. they cannot be changed by fchmod()).
-    //
-    // MFD_NOEXEC_SEAL implies MFD_ALLOW_SEALING.
-    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_NOEXEC_SEAL));
+    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));
 
     if (fd == -1) {
-        ALOGE("memfd_create(%s, %zd) failed: %s\n", name, size, strerror(errno));
+        ALOGE("memfd_create(%s, %zd) failed: %m", name, size);
         return -1;
     }
 
     if (ftruncate(fd, size) == -1) {
-        ALOGE("ftruncate(%s, %zd) failed for memfd creation: %s\n", name, size, strerror(errno));
+        ALOGE("ftruncate(%s, %zd) failed for memfd creation: %m", name, size);
         return -1;
     }
 
@@ -320,7 +304,7 @@ static int memfd_create_region(const char* name, size_t size) {
     }
 
     if (debug_log) {
-        ALOGE("memfd_create(%s, %zd) success. fd=%d\n", name, size, fd.get());
+        ALOGE("memfd_create(%s, %zd) success. fd=%d", name, size, fd.get());
     }
     return fd.release();
 }
@@ -332,47 +316,26 @@ static int memfd_create_region(const char* name, size_t size) {
  * `name' is an optional label to give the region (visible in /proc/pid/maps)
  * `size' is the size of the region, in page-aligned bytes
  */
-int ashmem_create_region(const char *name, size_t size)
-{
-    int ret, save_errno;
+int ashmem_create_region(const char* name, size_t size) {
+    if (name == NULL) name = "none";
 
     if (has_memfd_support()) {
-        return memfd_create_region(name ? name : "none", size);
+        return memfd_create_region(name, size);
     }
 
-    int fd = __ashmem_open();
-    if (fd < 0) {
-        return fd;
-    }
-
-    if (name) {
-        char buf[ASHMEM_NAME_LEN] = {0};
-
-        strlcpy(buf, name, sizeof(buf));
-        ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, buf));
-        if (ret < 0) {
-            goto error;
-        }
-    }
-
-    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size));
-    if (ret < 0) {
-        goto error;
+    android::base::unique_fd fd(__ashmem_open());
+    if (!fd.ok() ||
+        TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, name) < 0) ||
+        TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size) < 0)) {
+        return -1;
     }
-
-    return fd;
-
-error:
-    save_errno = errno;
-    close(fd);
-    errno = save_errno;
-    return ret;
+    return fd.release();
 }
 
 static int memfd_set_prot_region(int fd, int prot) {
     int seals = fcntl(fd, F_GET_SEALS);
     if (seals == -1) {
-        ALOGE("memfd_set_prot_region(%d, %d): F_GET_SEALS failed: %s\n", fd, prot, strerror(errno));
+        ALOGE("memfd_set_prot_region(%d, %d): F_GET_SEALS failed: %m", fd, prot);
         return -1;
     }
 
@@ -381,7 +344,7 @@ static int memfd_set_prot_region(int fd, int prot) {
          * has been previously marked as read-only before, if so return error
          */
         if (seals & F_SEAL_FUTURE_WRITE) {
-            ALOGE("memfd_set_prot_region(%d, %d): region is write protected\n", fd, prot);
+            ALOGE("memfd_set_prot_region(%d, %d): region is write protected", fd, prot);
             errno = EINVAL;  // inline with ashmem error code, if already in
                              // read-only mode
             return -1;
@@ -390,70 +353,53 @@ static int memfd_set_prot_region(int fd, int prot) {
     }
 
     /* We would only allow read-only for any future file operations */
-    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE | F_SEAL_SEAL) == -1) {
-        ALOGE("memfd_set_prot_region(%d, %d): F_SEAL_FUTURE_WRITE | F_SEAL_SEAL seal failed: %s\n",
-              fd, prot, strerror(errno));
+    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
+        ALOGE("memfd_set_prot_region(%d, %d): F_SEAL_FUTURE_WRITE seal failed: %m", fd, prot);
         return -1;
     }
 
     return 0;
 }
 
-int ashmem_set_prot_region(int fd, int prot)
-{
-    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
+int ashmem_set_prot_region(int fd, int prot) {
+    if (is_memfd_fd(fd)) {
         return memfd_set_prot_region(fd, prot);
     }
 
     return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot)));
 }
 
-int ashmem_pin_region(int fd, size_t offset, size_t len)
-{
-    if (!pin_deprecation_warn || debug_log) {
-        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.\n");
-        pin_deprecation_warn = true;
+static int do_pin(int op, int fd, size_t offset, size_t length) {
+    static bool already_warned_about_pin_deprecation = false;
+    if (!already_warned_about_pin_deprecation || debug_log) {
+        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.");
+        already_warned_about_pin_deprecation = true;
     }
 
-    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
+    if (is_memfd_fd(fd)) {
         return 0;
     }
 
     // TODO: should LP64 reject too-large offset/len?
-    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(len) };
-    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_PIN, &pin)));
+    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(length) };
+    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, op, &pin)));
 }
 
-int ashmem_unpin_region(int fd, size_t offset, size_t len)
-{
-    if (!pin_deprecation_warn || debug_log) {
-        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.\n");
-        pin_deprecation_warn = true;
-    }
-
-    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
-        return 0;
-    }
+int ashmem_pin_region(int fd, size_t offset, size_t length) {
+    return do_pin(ASHMEM_PIN, fd, offset, length);
+}
 
-    // TODO: should LP64 reject too-large offset/len?
-    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(len) };
-    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_UNPIN, &pin)));
+int ashmem_unpin_region(int fd, size_t offset, size_t length) {
+    return do_pin(ASHMEM_UNPIN, fd, offset, length);
 }
 
-int ashmem_get_size_region(int fd)
-{
-    if (has_memfd_support() && !memfd_is_ashmem(fd)) {
+int ashmem_get_size_region(int fd) {
+    if (is_memfd_fd(fd)) {
         struct stat sb;
-
         if (fstat(fd, &sb) == -1) {
-            ALOGE("ashmem_get_size_region(%d): fstat failed: %s\n", fd, strerror(errno));
+            ALOGE("ashmem_get_size_region(%d): fstat failed: %m", fd);
             return -1;
         }
-
-        if (debug_log) {
-            ALOGD("ashmem_get_size_region(%d): %d\n", fd, static_cast<int>(sb.st_size));
-        }
-
         return sb.st_size;
     }
 
diff --git a/libcutils/ashmem-internal.h b/libcutils/ashmem-internal.h
new file mode 100644
index 0000000000..7bd037b716
--- /dev/null
+++ b/libcutils/ashmem-internal.h
@@ -0,0 +1,19 @@
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
+bool has_memfd_support();
diff --git a/libcutils/ashmem_base_test.cpp b/libcutils/ashmem_base_test.cpp
index c9b14e5833..d60a97334b 100644
--- a/libcutils/ashmem_base_test.cpp
+++ b/libcutils/ashmem_base_test.cpp
@@ -16,6 +16,8 @@
 
 #include <gtest/gtest.h>
 
+#include <algorithm>
+
 #include <unistd.h>
 
 #include <android-base/mapped_file.h>
diff --git a/libcutils/ashmem_test.cpp b/libcutils/ashmem_test.cpp
index ccbb8c9776..2bf274c95c 100644
--- a/libcutils/ashmem_test.cpp
+++ b/libcutils/ashmem_test.cpp
@@ -29,9 +29,11 @@
 #include <cutils/ashmem.h>
 #include <gtest/gtest.h>
 
+#include "ashmem-internal.h"
+
 using android::base::unique_fd;
 
-void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
+static void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
     fd = unique_fd(ashmem_create_region(nullptr, size));
     ASSERT_TRUE(fd >= 0);
     ASSERT_TRUE(ashmem_valid(fd));
@@ -44,63 +46,75 @@ void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
     ASSERT_EQ(FD_CLOEXEC, (fcntl(fd, F_GETFD) & FD_CLOEXEC));
 }
 
-void TestMmap(const unique_fd& fd, size_t size, int prot, void** region, off_t off = 0) {
+static void TestMmap(const unique_fd& fd, size_t size, int prot, void** region, off_t off = 0) {
     ASSERT_TRUE(fd >= 0);
     ASSERT_TRUE(ashmem_valid(fd));
     *region = mmap(nullptr, size, prot, MAP_SHARED, fd, off);
     ASSERT_NE(MAP_FAILED, *region);
 }
 
-void TestProtDenied(const unique_fd &fd, size_t size, int prot) {
+static void TestProtDenied(const unique_fd &fd, size_t size, int prot) {
     ASSERT_TRUE(fd >= 0);
     ASSERT_TRUE(ashmem_valid(fd));
     EXPECT_EQ(MAP_FAILED, mmap(nullptr, size, prot, MAP_SHARED, fd, 0));
 }
 
-void TestProtIs(const unique_fd& fd, int prot) {
+static void TestProtIs(const unique_fd& fd, int prot) {
     ASSERT_TRUE(fd >= 0);
     ASSERT_TRUE(ashmem_valid(fd));
     EXPECT_EQ(prot, ioctl(fd, ASHMEM_GET_PROT_MASK));
 }
 
-void FillData(std::vector<uint8_t>& data) {
+static void FillData(std::vector<uint8_t>& data) {
     for (size_t i = 0; i < data.size(); i++) {
         data[i] = i & 0xFF;
     }
 }
 
-TEST(AshmemTest, ForkTest) {
-    const size_t size = getpagesize();
-    std::vector<uint8_t> data(size);
-    FillData(data);
+static void waitForChildProcessExit(pid_t pid) {
+    int exitStatus;
+    pid_t childPid = waitpid(pid, &exitStatus, 0);
 
-    unique_fd fd;
-    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
+    ASSERT_GT(childPid, 0);
+    ASSERT_TRUE(WIFEXITED(exitStatus));
+    ASSERT_EQ(0, WEXITSTATUS(exitStatus));
+}
 
+static void ForkTest(const unique_fd &fd, size_t size) {
     void* region1 = nullptr;
+    std::vector<uint8_t> data(size);
+    FillData(data);
+
     ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));
 
     memcpy(region1, data.data(), size);
     ASSERT_EQ(0, memcmp(region1, data.data(), size));
     EXPECT_EQ(0, munmap(region1, size));
 
-    ASSERT_EXIT(
-        {
-            if (!ashmem_valid(fd)) {
-                _exit(3);
-            }
-            void* region2 = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
-            if (region2 == MAP_FAILED) {
-                _exit(1);
-            }
-            if (memcmp(region2, data.data(), size) != 0) {
-                _exit(2);
-            }
-            memset(region2, 0, size);
-            munmap(region2, size);
-            _exit(0);
-        },
-        ::testing::ExitedWithCode(0), "");
+
+    pid_t pid = fork();
+    if (!pid) {
+        if (!ashmem_valid(fd)) {
+            _exit(3);
+        }
+
+        void *region2 = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
+        if (region2 == MAP_FAILED) {
+            _exit(1);
+        } else if (memcmp(region2, data.data(), size) != 0){
+            _exit(2);
+        }
+
+        // Clear the ashmem buffer here to ensure that updates to the contents
+        // of the buffer are visible across processes with a reference to the
+        // buffer.
+        memset(region2, 0, size);
+        munmap(region2, size);
+        _exit(0);
+    } else {
+        ASSERT_GT(pid, 0);
+        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
+    }
 
     memset(data.data(), 0, size);
     void *region2;
@@ -109,16 +123,12 @@ TEST(AshmemTest, ForkTest) {
     EXPECT_EQ(0, munmap(region2, size));
 }
 
-TEST(AshmemTest, FileOperationsTest) {
-    unique_fd fd;
+static void FileOperationsTest(const unique_fd &fd, size_t size) {
     void* region = nullptr;
 
-    // Allocate a 4-page buffer, but leave page-sized holes on either side
     const size_t pageSize = getpagesize();
-    const size_t size = pageSize * 4;
     const size_t dataSize = pageSize * 2;
     const size_t holeSize = pageSize;
-    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
     ASSERT_NO_FATAL_FAILURE(TestMmap(fd, dataSize, PROT_READ | PROT_WRITE, &region, holeSize));
 
     std::vector<uint8_t> data(dataSize);
@@ -171,78 +181,68 @@ TEST(AshmemTest, FileOperationsTest) {
     EXPECT_EQ(0, munmap(region, dataSize));
 }
 
-TEST(AshmemTest, ProtTest) {
-    unique_fd fd;
-    const size_t size = getpagesize();
+static void ProtTestROBuffer(const unique_fd &fd, size_t size) {
     void *region;
 
-    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ));
     TestProtDenied(fd, size, PROT_WRITE);
-    TestProtIs(fd, PROT_READ);
+    TestProtIs(fd, PROT_READ | PROT_EXEC);
     ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region));
     EXPECT_EQ(0, munmap(region, size));
+}
 
-    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_WRITE));
-    TestProtDenied(fd, size, PROT_READ);
-    TestProtIs(fd, PROT_WRITE);
-    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_WRITE, &region));
-    EXPECT_EQ(0, munmap(region, size));
-
-    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
-    TestProtIs(fd, PROT_READ | PROT_WRITE);
-    ASSERT_EQ(0, ashmem_set_prot_region(fd, PROT_READ));
+static void ProtTestRWBuffer(const unique_fd &fd, size_t size) {
+    TestProtIs(fd, PROT_READ | PROT_WRITE | PROT_EXEC);
+    ASSERT_EQ(0, ashmem_set_prot_region(fd, PROT_READ | PROT_EXEC));
     errno = 0;
-    ASSERT_EQ(-1, ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE))
+    ASSERT_EQ(-1, ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE |
+                                         PROT_EXEC))
         << "kernel shouldn't allow adding protection bits";
     EXPECT_EQ(EINVAL, errno);
-    TestProtIs(fd, PROT_READ);
+    TestProtIs(fd, PROT_READ | PROT_EXEC);
     TestProtDenied(fd, size, PROT_WRITE);
 }
 
-TEST(AshmemTest, ForkProtTest) {
-    unique_fd fd;
-    const size_t size = getpagesize();
-
-    int protFlags[] = { PROT_READ, PROT_WRITE };
-    for (size_t i = 0; i < arraysize(protFlags); i++) {
-        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
-        ASSERT_EXIT(
-            {
-                if (!ashmem_valid(fd)) {
-                    _exit(3);
-                } else if (ashmem_set_prot_region(fd, protFlags[i]) >= 0) {
-                    _exit(0);
-                } else {
-                    _exit(1);
-                }
-            },
-            ::testing::ExitedWithCode(0), "");
-        ASSERT_NO_FATAL_FAILURE(TestProtDenied(fd, size, protFlags[1-i]));
+static void ForkProtTest(const unique_fd &fd, size_t size) {
+    pid_t pid = fork();
+    if (!pid) {
+        // Change buffer mapping permissions to read-only to ensure that
+        // updates to the buffer's mapping permissions are visible across
+        // processes that reference the buffer.
+        if (!ashmem_valid(fd)) {
+            _exit(3);
+        } else if (ashmem_set_prot_region(fd, PROT_READ) == -1) {
+            _exit(1);
+        }
+        _exit(0);
+    } else {
+        ASSERT_GT(pid, 0);
+        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
     }
+
+    ASSERT_NO_FATAL_FAILURE(TestProtDenied(fd, size, PROT_WRITE));
 }
 
-TEST(AshmemTest, ForkMultiRegionTest) {
-    const size_t size = getpagesize();
+static void ForkMultiRegionTest(unique_fd fds[], int nRegions, size_t size) {
     std::vector<uint8_t> data(size);
     FillData(data);
 
-    constexpr int nRegions = 16;
-    unique_fd fd[nRegions];
     for (int i = 0; i < nRegions; i++) {
-        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd[i], PROT_READ | PROT_WRITE));
         void* region = nullptr;
-        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
+        ASSERT_NO_FATAL_FAILURE(TestMmap(fds[i], size, PROT_READ | PROT_WRITE, &region));
         memcpy(region, data.data(), size);
         ASSERT_EQ(0, memcmp(region, data.data(), size));
         EXPECT_EQ(0, munmap(region, size));
     }
 
-    ASSERT_EXIT({
+    pid_t pid = fork();
+    if (!pid) {
+        // Clear each ashmem buffer in the context of the child process to
+        // ensure that the updates are visible to the parent process later.
         for (int i = 0; i < nRegions; i++) {
-            if (!ashmem_valid(fd[i])) {
+            if (!ashmem_valid(fds[i])) {
                 _exit(3);
             }
-            void *region = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd[i], 0);
+            void *region = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fds[i], 0);
             if (region == MAP_FAILED) {
                 _exit(1);
             }
@@ -254,13 +254,183 @@ TEST(AshmemTest, ForkMultiRegionTest) {
             munmap(region, size);
         }
         _exit(0);
-    }, ::testing::ExitedWithCode(0), "");
+    } else {
+        ASSERT_GT(pid, 0);
+        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
+    }
 
     memset(data.data(), 0, size);
     for (int i = 0; i < nRegions; i++) {
         void *region;
-        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
+        ASSERT_NO_FATAL_FAILURE(TestMmap(fds[i], size, PROT_READ | PROT_WRITE, &region));
         ASSERT_EQ(0, memcmp(region, data.data(), size));
         EXPECT_EQ(0, munmap(region, size));
     }
+
+}
+
+TEST(AshmemTest, ForkTest) {
+    const size_t size = getpagesize();
+    unique_fd fd;
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
+    ASSERT_NO_FATAL_FAILURE(ForkTest(fd, size));
 }
+
+TEST(AshmemTest, FileOperationsTest) {
+    const size_t pageSize = getpagesize();
+    // Allocate a 4-page buffer, but leave page-sized holes on either side in
+    // the test.
+    const size_t size = pageSize * 4;
+    unique_fd fd;
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
+    ASSERT_NO_FATAL_FAILURE(FileOperationsTest(fd, size));
+}
+
+TEST(AshmemTest, ProtTest) {
+    unique_fd fd;
+    const size_t size = getpagesize();
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_EXEC));
+    ASSERT_NO_FATAL_FAILURE(ProtTestROBuffer(fd, size));
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE | PROT_EXEC));
+    ASSERT_NO_FATAL_FAILURE(ProtTestRWBuffer(fd, size));
+}
+
+TEST(AshmemTest, ForkProtTest) {
+    unique_fd fd;
+    const size_t size = getpagesize();
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
+    ASSERT_NO_FATAL_FAILURE(ForkProtTest(fd, size));
+}
+
+TEST(AshmemTest, ForkMultiRegionTest) {
+    const size_t size = getpagesize();
+    constexpr int nRegions = 16;
+    unique_fd fds[nRegions];
+
+    for (int i = 0; i < nRegions; i++) {
+        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fds[i], PROT_READ | PROT_WRITE));
+    }
+
+    ASSERT_NO_FATAL_FAILURE(ForkMultiRegionTest(fds, nRegions, size));
+}
+
+class AshmemTestMemfdAshmemCompat : public ::testing::Test {
+ protected:
+  void SetUp() override {
+    if (!has_memfd_support()){
+        GTEST_SKIP() << "No memfd support; skipping memfd-ashmem compat tests";
+    }
+  }
+};
+
+TEST_F(AshmemTestMemfdAshmemCompat, SetNameTest) {
+    unique_fd fd;
+
+    // ioctl() should fail, since memfd names cannot be changed after the buffer has been created.
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+    ASSERT_LT(ioctl(fd, ASHMEM_SET_NAME, "invalid-command"), 0);
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, GetNameTest) {
+    unique_fd fd;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+
+    char testBuf[ASHMEM_NAME_LEN];
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_NAME, &testBuf));
+    // ashmem_create_region(nullptr, ...) creates memfds with the name "none".
+    ASSERT_STREQ(testBuf, "none");
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, SetSizeTest) {
+    unique_fd fd;
+
+    // ioctl() should fail, since libcutils sets and seals the buffer size after creating it.
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+    ASSERT_LT(ioctl(fd, ASHMEM_SET_SIZE, 2 * getpagesize()), 0);
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, GetSizeTest) {
+    unique_fd fd;
+    size_t bufSize = getpagesize();
+
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(bufSize, fd, PROT_READ | PROT_WRITE | PROT_EXEC));
+    ASSERT_EQ(static_cast<int>(bufSize), ioctl(fd, ASHMEM_GET_SIZE, 0));
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, ProtMaskTest) {
+    unique_fd fd;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+
+    // We can only change PROT_WRITE for memfds since memfd implements ashmem's prot_mask through
+    // file seals, and only write seals exist.
+    //
+    // All memfd files start off as being writable (i.e. PROT_WRITE is part of the prot_mask).
+    // Test to ensure that the implementation only clears the PROT_WRITE bit when requested.
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_WRITE | PROT_EXEC));
+    int prot = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
+    ASSERT_NE(prot, -1);
+    ASSERT_TRUE(prot & PROT_WRITE) << prot;
+
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_EXEC));
+    prot = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
+    ASSERT_NE(prot, -1);
+    ASSERT_TRUE(!(prot & PROT_WRITE)) << prot;
+
+    // The shim layer should implement clearing PROT_WRITE via file seals, so check the file
+    // seals to ensure that F_SEAL_FUTURE_WRITE is set.
+    int seals = fcntl(fd, F_GET_SEALS, 0);
+    ASSERT_NE(seals, -1);
+    ASSERT_TRUE(seals & F_SEAL_FUTURE_WRITE) << seals;
+
+    // Similarly, ensure that file seals affect prot_mask
+    unique_fd fd2;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd2, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+    ASSERT_EQ(0, fcntl(fd2, F_ADD_SEALS, F_SEAL_FUTURE_WRITE));
+    prot = ioctl(fd2, ASHMEM_GET_PROT_MASK, 0);
+    ASSERT_NE(prot, -1);
+    ASSERT_TRUE(!(prot & PROT_WRITE)) << prot;
+
+    // And finally, ensure that adding back permissions fails
+    ASSERT_LT(ioctl(fd2, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_WRITE | PROT_EXEC), 0);
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, FileIDTest) {
+    unique_fd fd;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+
+    unsigned long ino;
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_FILE_ID, &ino));
+    struct stat st;
+    ASSERT_EQ(0, fstat(fd, &st));
+    ASSERT_EQ(ino, st.st_ino);
+}
+
+TEST_F(AshmemTestMemfdAshmemCompat, UnpinningTest) {
+    unique_fd fd;
+    size_t bufSize = getpagesize();
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
+                                                                PROT_EXEC));
+
+    struct ashmem_pin pin = {
+        .offset = 0,
+        .len = static_cast<uint32_t>(bufSize),
+    };
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_UNPIN, &pin));
+    // ASHMEM_UNPIN should just be a nop
+    ASSERT_EQ(ASHMEM_IS_PINNED, ioctl(fd, ASHMEM_GET_PIN_STATUS, 0));
+
+    // This shouldn't do anything; when we pin the page, it shouldn't have been purged.
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_PURGE_ALL_CACHES, 0));
+    ASSERT_EQ(ASHMEM_NOT_PURGED, ioctl(fd, ASHMEM_PIN, &pin));
+}
\ No newline at end of file
diff --git a/libcutils/fs_config.cpp b/libcutils/fs_config.cpp
index 2e4b9b475d..0d1b7fe120 100644
--- a/libcutils/fs_config.cpp
+++ b/libcutils/fs_config.cpp
@@ -72,20 +72,14 @@ static const struct fs_path_config android_dirs[] = {
     { 00771, AID_SYSTEM,       AID_SYSTEM,       0, "data" },
     { 00755, AID_ROOT,         AID_SYSTEM,       0, "mnt" },
     { 00751, AID_ROOT,         AID_SHELL,        0, "product/bin" },
-    { 00751, AID_ROOT,         AID_SHELL,        0, "product/apex/*/bin" },
     { 00777, AID_ROOT,         AID_ROOT,         0, "sdcard" },
     { 00751, AID_ROOT,         AID_SDCARD_R,     0, "storage" },
-    { 00750, AID_ROOT,         AID_SYSTEM,       0, "system/apex/com.android.tethering/bin/for-system" },
     { 00751, AID_ROOT,         AID_SHELL,        0, "system/bin" },
     { 00755, AID_ROOT,         AID_ROOT,         0, "system/etc/ppp" },
     { 00755, AID_ROOT,         AID_SHELL,        0, "system/vendor" },
     { 00750, AID_ROOT,         AID_SHELL,        0, "system/xbin" },
-    { 00751, AID_ROOT,         AID_SHELL,        0, "system/apex/*/bin" },
-    { 00750, AID_ROOT,         AID_SYSTEM,       0, "system_ext/apex/com.android.tethering/bin/for-system" },
     { 00751, AID_ROOT,         AID_SHELL,        0, "system_ext/bin" },
-    { 00751, AID_ROOT,         AID_SHELL,        0, "system_ext/apex/*/bin" },
     { 00751, AID_ROOT,         AID_SHELL,        0, "vendor/bin" },
-    { 00751, AID_ROOT,         AID_SHELL,        0, "vendor/apex/*/bin" },
     { 00755, AID_ROOT,         AID_SHELL,        0, "vendor" },
     {},
         // clang-format on
@@ -182,8 +176,6 @@ static const struct fs_path_config android_files[] = {
 
     // the following files have enhanced capabilities and ARE included
     // in user builds.
-    { 06755, AID_CLAT,      AID_CLAT,      0, "system/apex/com.android.tethering/bin/for-system/clatd" },
-    { 06755, AID_CLAT,      AID_CLAT,      0, "system_ext/apex/com.android.tethering/bin/for-system/clatd" },
     { 00700, AID_SYSTEM,    AID_SHELL,     CAP_MASK_LONG(CAP_BLOCK_SUSPEND),
                                               "system/bin/inputflinger" },
     { 00750, AID_ROOT,      AID_SHELL,     CAP_MASK_LONG(CAP_SETUID) |
@@ -205,6 +197,7 @@ static const struct fs_path_config android_files[] = {
     { 00755, AID_ROOT,      AID_ROOT,      0, "first_stage_ramdisk/system/bin/fsck.f2fs" },
     // generic defaults
     { 00755, AID_ROOT,      AID_ROOT,      0, "bin/*" },
+    { 00755, AID_ROOT,      AID_ROOT,      0, "first_stage.sh"},
     { 00640, AID_ROOT,      AID_SHELL,     0, "fstab.*" },
     { 00750, AID_ROOT,      AID_SHELL,     0, "init*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "*.rc" },
@@ -213,23 +206,19 @@ static const struct fs_path_config android_files[] = {
     { 00644, AID_ROOT,      AID_ROOT,      0, "odm/app/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "odm/priv-app/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "product/bin/*" },
-    { 00755, AID_ROOT,      AID_SHELL,     0, "product/apex/*bin/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "product/framework/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "product/app/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "product/priv-app/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "system/bin/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "system/xbin/*" },
-    { 00755, AID_ROOT,      AID_SHELL,     0, "system/apex/*/bin/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system/framework/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system/app/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system/priv-app/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "system_ext/bin/*" },
-    { 00755, AID_ROOT,      AID_SHELL,     0, "system_ext/apex/*/bin/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system_ext/framework/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system_ext/app/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "system_ext/priv-app/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "vendor/bin/*" },
-    { 00755, AID_ROOT,      AID_SHELL,     0, "vendor/apex/*bin/*" },
     { 00755, AID_ROOT,      AID_SHELL,     0, "vendor/xbin/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "vendor/framework/*" },
     { 00644, AID_ROOT,      AID_ROOT,      0, "vendor/app/*" },
diff --git a/libcutils/include/private/android_filesystem_config.h b/libcutils/include/private/android_filesystem_config.h
index 2aaafbe241..b6aded0c78 100644
--- a/libcutils/include/private/android_filesystem_config.h
+++ b/libcutils/include/private/android_filesystem_config.h
@@ -144,6 +144,7 @@
 #define AID_UPROBESTATS 1093         /* uid for uprobestats */
 #define AID_CROS_EC 1094             /* uid for accessing ChromeOS EC (cros_ec) */
 #define AID_MMD 1095                 /* uid for memory management daemon */
+#define AID_UPDATE_ENGINE_LOG 1096   /* GID for accessing update_engine logs */
 // Additions to this file must be made in AOSP, *not* in internal branches.
 // You will also need to update expect_ids() in bionic/tests/grp_pwd_test.cpp.
 
diff --git a/libgrallocusage/OWNERS b/libgrallocusage/OWNERS
index de2bf16f4c..249dcb0008 100644
--- a/libgrallocusage/OWNERS
+++ b/libgrallocusage/OWNERS
@@ -1,2 +1 @@
 jreck@google.com
-lpy@google.com
diff --git a/libmodprobe/include/exthandler/exthandler.h b/libmodprobe/include/exthandler/exthandler.h
index 232aa95a48..a619f81040 100644
--- a/libmodprobe/include/exthandler/exthandler.h
+++ b/libmodprobe/include/exthandler/exthandler.h
@@ -17,6 +17,7 @@
 #pragma once
 #include <android-base/result.h>
 #include <string>
+#include <sys/types.h>
 
 android::base::Result<std::string> RunExternalHandler(
         const std::string& handler, uid_t uid, gid_t gid,
diff --git a/libmodprobe/include/modprobe/modprobe.h b/libmodprobe/include/modprobe/modprobe.h
index 7b691b13ac..d33e17ddde 100644
--- a/libmodprobe/include/modprobe/modprobe.h
+++ b/libmodprobe/include/modprobe/modprobe.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <functional>
 #include <mutex>
 #include <set>
 #include <string>
diff --git a/libpackagelistparser/packagelistparser.cpp b/libpackagelistparser/packagelistparser.cpp
index 638cc43fe9..5517b68c66 100644
--- a/libpackagelistparser/packagelistparser.cpp
+++ b/libpackagelistparser/packagelistparser.cpp
@@ -21,6 +21,7 @@
 #include <errno.h>
 #include <inttypes.h>
 #include <stdio.h>
+#include <stdlib.h>
 #include <string.h>
 #include <sys/limits.h>
 
diff --git a/libprocessgroup/Android.bp b/libprocessgroup/Android.bp
index 1e76e766fc..6725acc8db 100644
--- a/libprocessgroup/Android.bp
+++ b/libprocessgroup/Android.bp
@@ -7,7 +7,6 @@ soong_config_module_type {
     module_type: "cc_defaults",
     config_namespace: "ANDROID",
     bool_variables: [
-        "memcg_v2_force_enabled",
         "cgroup_v2_sys_app_isolation",
     ],
     properties: [
@@ -19,11 +18,6 @@ libprocessgroup_flag_aware_cc_defaults {
     name: "libprocessgroup_build_flags_cc",
     cpp_std: "gnu++23",
     soong_config_variables: {
-        memcg_v2_force_enabled: {
-            cflags: [
-                "-DMEMCG_V2_FORCE_ENABLED=true",
-            ],
-        },
         cgroup_v2_sys_app_isolation: {
             cflags: [
                 "-DCGROUP_V2_SYS_APP_ISOLATION=true",
diff --git a/libprocessgroup/build_flags.h b/libprocessgroup/build_flags.h
index bc3e7dff17..d0948c35ec 100644
--- a/libprocessgroup/build_flags.h
+++ b/libprocessgroup/build_flags.h
@@ -16,20 +16,12 @@
 
 #pragma once
 
-#ifndef MEMCG_V2_FORCE_ENABLED
-#define MEMCG_V2_FORCE_ENABLED false
-#endif
-
 #ifndef CGROUP_V2_SYS_APP_ISOLATION
 #define CGROUP_V2_SYS_APP_ISOLATION false
 #endif
 
 namespace android::libprocessgroup_flags {
 
-inline consteval bool force_memcg_v2() {
-    return MEMCG_V2_FORCE_ENABLED;
-}
-
 inline consteval bool cgroup_v2_sys_app_isolation() {
     return CGROUP_V2_SYS_APP_ISOLATION;
 }
diff --git a/libprocessgroup/cgrouprc/Android.bp b/libprocessgroup/cgrouprc/Android.bp
index 9e46b8e7c1..d5214c14ed 100644
--- a/libprocessgroup/cgrouprc/Android.bp
+++ b/libprocessgroup/cgrouprc/Android.bp
@@ -18,7 +18,6 @@ package {
 
 cc_library {
     name: "libcgrouprc",
-    host_supported: true,
     // Do not ever mark this as vendor_available; otherwise, vendor modules
     // that links to the static library will behave unexpectedly. All on-device
     // modules should use libprocessgroup which links to the LL-NDK library
diff --git a/libprocessgroup/cgrouprc/include/android/cgrouprc.h b/libprocessgroup/cgrouprc/include/android/cgrouprc.h
index e704a36aac..6fc2659c15 100644
--- a/libprocessgroup/cgrouprc/include/android/cgrouprc.h
+++ b/libprocessgroup/cgrouprc/include/android/cgrouprc.h
@@ -21,11 +21,6 @@
 
 __BEGIN_DECLS
 
-// For host builds, __INTRODUCED_IN is not defined.
-#ifndef __INTRODUCED_IN
-#define __INTRODUCED_IN(x)
-#endif
-
 struct ACgroupController;
 typedef struct ACgroupController ACgroupController;
 
diff --git a/libprocessgroup/include/processgroup/processgroup.h b/libprocessgroup/include/processgroup/processgroup.h
index 6a026a717b..0aa14ba441 100644
--- a/libprocessgroup/include/processgroup/processgroup.h
+++ b/libprocessgroup/include/processgroup/processgroup.h
@@ -29,7 +29,11 @@ bool CgroupsAvailable();
 bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path);
 bool CgroupGetControllerFromPath(const std::string& path, std::string* cgroup_name);
 bool CgroupGetAttributePath(const std::string& attr_name, std::string* path);
+// Provides the path for an attribute in a specific process group
+// Returns false in case of error, true in case of success
 bool CgroupGetAttributePathForTask(const std::string& attr_name, pid_t tid, std::string* path);
+bool CgroupGetAttributePathForProcess(std::string_view attr_name, uid_t uid, pid_t pid,
+                                      std::string &path);
 
 bool SetTaskProfiles(pid_t tid, const std::vector<std::string>& profiles,
                      bool use_fd_cache = false);
@@ -75,16 +79,13 @@ int createProcessGroup(uid_t uid, pid_t initialPid, bool memControl = false);
 
 // Set various properties of a process group. For these functions to work, the process group must
 // have been created by passing memControl=true to createProcessGroup.
+[[deprecated("Unsupported in memcg v2")]]
 bool setProcessGroupSwappiness(uid_t uid, pid_t initialPid, int swappiness);
 bool setProcessGroupSoftLimit(uid_t uid, pid_t initialPid, int64_t softLimitInBytes);
 bool setProcessGroupLimit(uid_t uid, pid_t initialPid, int64_t limitInBytes);
 
 void removeAllEmptyProcessGroups(void);
 
-// Provides the path for an attribute in a specific process group
-// Returns false in case of error, true in case of success
-bool getAttributePathForTask(const std::string& attr_name, pid_t tid, std::string* path);
-
 // Check if a profile can be applied without failing.
 // Returns true if it can be applied without failing, false otherwise
 bool isProfileValidForProcess(const std::string& profile_name, uid_t uid, pid_t pid);
diff --git a/libprocessgroup/processgroup.cpp b/libprocessgroup/processgroup.cpp
index 95221594b6..a8fa50a9fd 100644
--- a/libprocessgroup/processgroup.cpp
+++ b/libprocessgroup/processgroup.cpp
@@ -85,7 +85,8 @@ static bool CgroupKillAvailable() {
         CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cg_kill);
         // cgroup.kill is not on the root cgroup, so check a non-root cgroup that should always
         // exist
-        cg_kill = ConvertUidToPath(cg_kill.c_str(), AID_ROOT) + '/' + PROCESSGROUP_CGROUP_KILL_FILE;
+        cg_kill = ConvertUidToPath(cg_kill.c_str(), AID_ROOT, true) + '/' +
+            PROCESSGROUP_CGROUP_KILL_FILE;
         cgroup_kill_available = access(cg_kill.c_str(), F_OK) == 0;
     });
 
@@ -154,6 +155,23 @@ bool CgroupGetAttributePathForTask(const std::string& attr_name, pid_t tid, std:
     return true;
 }
 
+bool CgroupGetAttributePathForProcess(std::string_view attr_name, uid_t uid, pid_t pid,
+                                      std::string &path) {
+    const TaskProfiles& tp = TaskProfiles::GetInstance();
+    const IProfileAttribute* attr = tp.GetAttribute(attr_name);
+
+    if (attr == nullptr) {
+        return false;
+    }
+
+    if (!attr->GetPathForProcess(uid, pid, &path)) {
+        LOG(ERROR) << "Failed to find cgroup for uid " << uid << " pid " << pid;
+        return false;
+    }
+
+    return true;
+}
+
 bool UsePerAppMemcg() {
     bool low_ram_device = GetBoolProperty("ro.config.low_ram", false);
     return GetBoolProperty("ro.config.per_app_memcg", low_ram_device);
@@ -224,14 +242,14 @@ bool SetUserProfiles(uid_t uid, const std::vector<std::string>& profiles) {
                                                        false);
 }
 
-static int RemoveCgroup(const char* cgroup, uid_t uid, pid_t pid) {
-    auto path = ConvertUidPidToPath(cgroup, uid, pid);
+static int RemoveCgroup(const char* cgroup, uid_t uid, pid_t pid, bool v2_path) {
+    auto path = ConvertUidPidToPath(cgroup, uid, pid, v2_path);
     int ret = TEMP_FAILURE_RETRY(rmdir(path.c_str()));
 
     if (!ret && uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END) {
         // Isolated UIDs are unlikely to be reused soon after removal,
         // so free up the kernel resources for the UID level cgroup.
-        path = ConvertUidToPath(cgroup, uid);
+        path = ConvertUidToPath(cgroup, uid, v2_path);
         ret = TEMP_FAILURE_RETRY(rmdir(path.c_str()));
     }
 
@@ -368,7 +386,7 @@ bool sendSignalToProcessGroup(uid_t uid, pid_t initialPid, int signal) {
     if (CgroupsAvailable()) {
         std::string hierarchy_root_path, cgroup_v2_path;
         CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &hierarchy_root_path);
-        cgroup_v2_path = ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid);
+        cgroup_v2_path = ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid, true);
 
         if (signal == SIGKILL && CgroupKillAvailable()) {
             LOG(VERBOSE) << "Using " << PROCESSGROUP_CGROUP_KILL_FILE << " to SIGKILL "
@@ -539,7 +557,7 @@ static int KillProcessGroup(
     CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &hierarchy_root_path);
 
     const std::string cgroup_v2_path =
-            ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid);
+            ConvertUidPidToPath(hierarchy_root_path.c_str(), uid, initialPid, true);
 
     const std::string eventsfile = cgroup_v2_path + '/' + PROCESSGROUP_CGROUP_EVENTS_FILE;
     android::base::unique_fd events_fd(open(eventsfile.c_str(), O_RDONLY));
@@ -605,7 +623,7 @@ static int KillProcessGroup(
                          << " after " << kill_duration.count() << " ms";
         }
 
-        ret = RemoveCgroup(hierarchy_root_path.c_str(), uid, initialPid);
+        ret = RemoveCgroup(hierarchy_root_path.c_str(), uid, initialPid, true);
         if (ret)
             PLOG(ERROR) << "Unable to remove cgroup " << cgroup_v2_path;
         else
@@ -616,9 +634,9 @@ static int KillProcessGroup(
             // memcg v2.
             std::string memcg_apps_path;
             if (CgroupGetMemcgAppsPath(&memcg_apps_path) &&
-                (ret = RemoveCgroup(memcg_apps_path.c_str(), uid, initialPid)) < 0) {
+                (ret = RemoveCgroup(memcg_apps_path.c_str(), uid, initialPid, false)) < 0) {
                 const auto memcg_v1_cgroup_path =
-                        ConvertUidPidToPath(memcg_apps_path.c_str(), uid, initialPid);
+                        ConvertUidPidToPath(memcg_apps_path.c_str(), uid, initialPid, false);
                 PLOG(ERROR) << "Unable to remove memcg v1 cgroup " << memcg_v1_cgroup_path;
             }
         }
@@ -640,7 +658,7 @@ int killProcessGroupOnce(uid_t uid, pid_t initialPid, int signal) {
 
 static int createProcessGroupInternal(uid_t uid, pid_t initialPid, std::string cgroup,
                                       bool activate_controllers) {
-    auto uid_path = ConvertUidToPath(cgroup.c_str(), uid);
+    auto uid_path = ConvertUidToPath(cgroup.c_str(), uid, activate_controllers);
 
     struct stat cgroup_stat;
     mode_t cgroup_mode = 0750;
@@ -667,7 +685,7 @@ static int createProcessGroupInternal(uid_t uid, pid_t initialPid, std::string c
         }
     }
 
-    auto uid_pid_path = ConvertUidPidToPath(cgroup.c_str(), uid, initialPid);
+    auto uid_pid_path = ConvertUidPidToPath(cgroup.c_str(), uid, initialPid, activate_controllers);
 
     if (!MkdirAndChown(uid_pid_path, cgroup_mode, cgroup_uid, cgroup_gid)) {
         PLOG(ERROR) << "Failed to make and chown " << uid_pid_path;
@@ -746,10 +764,6 @@ bool setProcessGroupLimit(uid_t, pid_t pid, int64_t limit_in_bytes) {
     return SetProcessGroupValue(pid, "MemLimit", limit_in_bytes);
 }
 
-bool getAttributePathForTask(const std::string& attr_name, pid_t tid, std::string* path) {
-    return CgroupGetAttributePathForTask(attr_name, tid, path);
-}
-
 bool isProfileValidForProcess(const std::string& profile_name, uid_t uid, pid_t pid) {
     const TaskProfile* tp = TaskProfiles::GetInstance().GetProfile(profile_name);
 
diff --git a/libprocessgroup/profiles/cgroups.json b/libprocessgroup/profiles/cgroups.json
index 3e4393df20..e9345a5312 100644
--- a/libprocessgroup/profiles/cgroups.json
+++ b/libprocessgroup/profiles/cgroups.json
@@ -20,14 +20,6 @@
       "Mode": "0755",
       "UID": "system",
       "GID": "system"
-    },
-    {
-      "Controller": "memory",
-      "Path": "/dev/memcg",
-      "Mode": "0700",
-      "UID": "root",
-      "GID": "system",
-      "Optional": true
     }
   ],
   "Cgroups2": {
@@ -39,6 +31,13 @@
       {
         "Controller": "freezer",
         "Path": "."
+      },
+      {
+        "Controller": "memory",
+        "Path": ".",
+        "NeedsActivation": true,
+        "MaxActivationDepth": 3,
+        "Optional": true
       }
     ]
   }
diff --git a/libprocessgroup/profiles/cgroups.proto b/libprocessgroup/profiles/cgroups.proto
index d2fd472d15..1a78e9df24 100644
--- a/libprocessgroup/profiles/cgroups.proto
+++ b/libprocessgroup/profiles/cgroups.proto
@@ -36,7 +36,7 @@ message Cgroup {
 // https://developers.google.com/protocol-buffers/docs/proto3#default
     bool needs_activation = 6 [json_name = "NeedsActivation"];
     bool is_optional = 7 [json_name = "Optional"];
-    uint32 max_activation_depth = 8 [json_name = "MaxActivationDepth"];
+    optional uint32 max_activation_depth = 8 [json_name = "MaxActivationDepth"];
 }
 
 // Next: 6
diff --git a/libprocessgroup/profiles/task_profiles.json b/libprocessgroup/profiles/task_profiles.json
index 28902efe80..42cdb91950 100644
--- a/libprocessgroup/profiles/task_profiles.json
+++ b/libprocessgroup/profiles/task_profiles.json
@@ -81,6 +81,11 @@
       "Name": "FreezerState",
       "Controller": "freezer",
       "File": "cgroup.freeze"
+    },
+    {
+      "Name": "CgroupProcs",
+      "Controller": "cgroup2",
+      "File": "cgroup.procs"
     }
   ],
 
@@ -592,7 +597,7 @@
           "Params":
           {
             "Name": "MemSoftLimit",
-            "Value": "16MB"
+            "Value": "16M"
           }
         },
         {
@@ -614,7 +619,7 @@
           "Params":
           {
             "Name": "MemSoftLimit",
-            "Value": "512MB"
+            "Value": "512M"
           }
         },
         {
diff --git a/libprocessgroup/setup/cgroup_map_write.cpp b/libprocessgroup/setup/cgroup_map_write.cpp
index c4e1fb6804..0d1739e994 100644
--- a/libprocessgroup/setup/cgroup_map_write.cpp
+++ b/libprocessgroup/setup/cgroup_map_write.cpp
@@ -27,9 +27,6 @@
 #include <sys/types.h>
 #include <unistd.h>
 
-#include <optional>
-
-#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <processgroup/cgroup_descriptor.h>
 #include <processgroup/processgroup.h>
@@ -260,39 +257,6 @@ void CgroupDescriptor::set_mounted(bool mounted) {
     controller_.set_flags(flags);
 }
 
-static std::optional<bool> MGLRUDisabled() {
-    const std::string file_name = "/sys/kernel/mm/lru_gen/enabled";
-    std::string content;
-    if (!android::base::ReadFileToString(file_name, &content)) {
-        PLOG(ERROR) << "Failed to read MGLRU state from " << file_name;
-        return {};
-    }
-
-    return content == "0x0000";
-}
-
-static std::optional<bool> MEMCGDisabled(const CgroupDescriptorMap& descriptors) {
-    std::string cgroup_v2_root = CGROUP_V2_ROOT_DEFAULT;
-    const auto it = descriptors.find(CGROUPV2_HIERARCHY_NAME);
-    if (it == descriptors.end()) {
-        LOG(WARNING) << "No Cgroups2 path found in cgroups.json. Vendor has modified Android, and "
-                     << "kernel memory use will be higher than intended.";
-    } else if (it->second.controller()->path() != cgroup_v2_root) {
-        cgroup_v2_root = it->second.controller()->path();
-    }
-
-    const std::string file_name = cgroup_v2_root + "/cgroup.controllers";
-    std::string content;
-    if (!android::base::ReadFileToString(file_name, &content)) {
-        PLOG(ERROR) << "Failed to read cgroup controllers from " << file_name;
-        return {};
-    }
-
-    // If we've forced memcg to v2 and it's not available, then it could only have been disabled
-    // on the kernel command line (GKI sets CONFIG_MEMCG).
-    return content.find("memory") == std::string::npos;
-}
-
 static bool CreateV2SubHierarchy(const std::string& path, const CgroupDescriptorMap& descriptors) {
     const auto cgv2_iter = descriptors.find(CGROUPV2_HIERARCHY_NAME);
     if (cgv2_iter == descriptors.end()) return false;
@@ -335,17 +299,6 @@ bool CgroupSetup() {
         }
     }
 
-    if (android::libprocessgroup_flags::force_memcg_v2()) {
-        if (MGLRUDisabled().value_or(false)) {
-            LOG(WARNING) << "Memcg forced to v2 hierarchy with MGLRU disabled! "
-                         << "Global reclaim performance will suffer.";
-        }
-        if (MEMCGDisabled(descriptors).value_or(false)) {
-            LOG(WARNING) << "Memcg forced to v2 hierarchy while memcg is disabled by kernel "
-                         << "command line!";
-        }
-    }
-
     // System / app isolation.
     // This really belongs in early-init in init.rc, but we cannot use the flag there.
     if (android::libprocessgroup_flags::cgroup_v2_sys_app_isolation()) {
diff --git a/libprocessgroup/task_profiles.cpp b/libprocessgroup/task_profiles.cpp
index dc6c8c07f2..89ca7f1b4e 100644
--- a/libprocessgroup/task_profiles.cpp
+++ b/libprocessgroup/task_profiles.cpp
@@ -20,7 +20,6 @@
 #include <task_profiles.h>
 
 #include <map>
-#include <optional>
 #include <string>
 
 #include <dirent.h>
@@ -31,6 +30,7 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/parseint.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
@@ -121,15 +121,6 @@ bool FdCacheHelper::IsAppDependentPath(const std::string& path) {
     return path.find("<uid>", 0) != std::string::npos || path.find("<pid>", 0) != std::string::npos;
 }
 
-std::optional<long> readLong(const std::string& str) {
-    char* end;
-    const long result = strtol(str.c_str(), &end, 10);
-    if (end > str.c_str()) {
-        return result;
-    }
-    return std::nullopt;
-}
-
 }  // namespace
 
 IProfileAttribute::~IProfileAttribute() = default;
@@ -150,8 +141,8 @@ static bool isSystemApp(uid_t uid) {
     return uid < AID_APP_START;
 }
 
-std::string ConvertUidToPath(const char* root_cgroup_path, uid_t uid) {
-    if (android::libprocessgroup_flags::cgroup_v2_sys_app_isolation()) {
+std::string ConvertUidToPath(const char* root_cgroup_path, uid_t uid, bool v2_path) {
+    if (android::libprocessgroup_flags::cgroup_v2_sys_app_isolation() && v2_path) {
         if (isSystemApp(uid))
             return StringPrintf("%s/system/uid_%u", root_cgroup_path, uid);
         else
@@ -160,14 +151,14 @@ std::string ConvertUidToPath(const char* root_cgroup_path, uid_t uid) {
     return StringPrintf("%s/uid_%u", root_cgroup_path, uid);
 }
 
-std::string ConvertUidPidToPath(const char* root_cgroup_path, uid_t uid, pid_t pid) {
-    const std::string uid_path = ConvertUidToPath(root_cgroup_path, uid);
+std::string ConvertUidPidToPath(const char* root_cgroup_path, uid_t uid, pid_t pid, bool v2_path) {
+    const std::string uid_path = ConvertUidToPath(root_cgroup_path, uid, v2_path);
     return StringPrintf("%s/pid_%d", uid_path.c_str(), pid);
 }
 
 bool ProfileAttribute::GetPathForProcess(uid_t uid, pid_t pid, std::string* path) const {
     if (controller()->version() == 2) {
-        const std::string cgroup_path = ConvertUidPidToPath(controller()->path(), uid, pid);
+        const std::string cgroup_path = ConvertUidPidToPath(controller()->path(), uid, pid, true);
         *path = cgroup_path + "/" + file_name();
         return true;
     }
@@ -199,7 +190,7 @@ bool ProfileAttribute::GetPathForUID(uid_t uid, std::string* path) const {
         return true;
     }
 
-    const std::string cgroup_path = ConvertUidToPath(controller()->path(), uid);
+    const std::string cgroup_path = ConvertUidToPath(controller()->path(), uid, true);
     *path = cgroup_path + "/" + file_name();
     return true;
 }
@@ -930,9 +921,8 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                 }
             } else if (action_name == "SetTimerSlack") {
                 const std::string slack_string = params_val["Slack"].asString();
-                std::optional<long> slack = readLong(slack_string);
-                if (slack && *slack >= 0) {
-                    profile->Add(std::make_unique<SetTimerSlackAction>(*slack));
+                if (long slack; android::base::ParseInt(slack_string, &slack) && slack >= 0) {
+                    profile->Add(std::make_unique<SetTimerSlackAction>(slack));
                 } else {
                     LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slack_string;
                 }
@@ -994,18 +984,17 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                         // to setpriority(), since the sched_priority value must be 0 for calls to
                         // sched_setscheduler() with "normal" policies.
                         const std::string nice_string = params_val["Nice"].asString();
-                        const std::optional<int> nice = readLong(nice_string);
-
-                        if (!nice) {
+                        int nice;
+                        if (!android::base::ParseInt(nice_string, &nice)) {
                             LOG(FATAL) << "Invalid nice value specified: " << nice_string;
                         }
                         const int LINUX_MIN_NICE = -20;
                         const int LINUX_MAX_NICE = 19;
-                        if (*nice < LINUX_MIN_NICE || *nice > LINUX_MAX_NICE) {
-                            LOG(WARNING) << "SetSchedulerPolicy: Provided nice (" << *nice
+                        if (nice < LINUX_MIN_NICE || nice > LINUX_MAX_NICE) {
+                            LOG(WARNING) << "SetSchedulerPolicy: Provided nice (" << nice
                                          << ") appears out of range.";
                         }
-                        profile->Add(std::make_unique<SetSchedulerPolicyAction>(policy, *nice));
+                        profile->Add(std::make_unique<SetSchedulerPolicyAction>(policy, nice));
                     } else {
                         profile->Add(std::make_unique<SetSchedulerPolicyAction>(policy));
                     }
@@ -1020,10 +1009,11 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                     // [sched_get_priority_min(), sched_get_priority_max()]
 
                     const std::string priority_string = params_val["Priority"].asString();
-                    std::optional<long> virtual_priority = readLong(priority_string);
-                    if (virtual_priority && *virtual_priority > 0) {
+                    if (long virtual_priority;
+                        android::base::ParseInt(priority_string, &virtual_priority) &&
+                        virtual_priority > 0) {
                         int priority;
-                        if (SetSchedulerPolicyAction::toPriority(policy, *virtual_priority,
+                        if (SetSchedulerPolicyAction::toPriority(policy, virtual_priority,
                                                                  priority)) {
                             profile->Add(
                                     std::make_unique<SetSchedulerPolicyAction>(policy, priority));
diff --git a/libprocessgroup/task_profiles.h b/libprocessgroup/task_profiles.h
index d0b50436c0..b1d611514a 100644
--- a/libprocessgroup/task_profiles.h
+++ b/libprocessgroup/task_profiles.h
@@ -258,5 +258,5 @@ class TaskProfiles {
     std::map<std::string, std::unique_ptr<IProfileAttribute>, std::less<>> attributes_;
 };
 
-std::string ConvertUidToPath(const char* root_cgroup_path, uid_t uid);
-std::string ConvertUidPidToPath(const char* root_cgroup_path, uid_t uid, pid_t pid);
+std::string ConvertUidToPath(const char* root_cgroup_path, uid_t uid, bool v2_path);
+std::string ConvertUidPidToPath(const char* root_cgroup_path, uid_t uid, pid_t pid, bool v2_path);
diff --git a/libprocessgroup/util/Android.bp b/libprocessgroup/util/Android.bp
index 1c74d4ed52..266a53f1e4 100644
--- a/libprocessgroup/util/Android.bp
+++ b/libprocessgroup/util/Android.bp
@@ -21,6 +21,7 @@ package {
 
 cc_library_static {
     name: "libprocessgroup_util",
+    cpp_std: "gnu++23",
     vendor_available: true,
     product_available: true,
     ramdisk_available: true,
@@ -47,7 +48,6 @@ cc_library_static {
     static_libs: [
         "libjsoncpp",
     ],
-    defaults: ["libprocessgroup_build_flags_cc"],
 }
 
 cc_test {
diff --git a/libprocessgroup/util/util.cpp b/libprocessgroup/util/util.cpp
index 14016751c7..c772bc5e49 100644
--- a/libprocessgroup/util/util.cpp
+++ b/libprocessgroup/util/util.cpp
@@ -111,7 +111,6 @@ void MergeCgroupToDescriptors(CgroupDescriptorMap* descriptors, const Json::Valu
 }
 
 bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap* descriptors) {
-    static constexpr bool force_memcg_v2 = android::libprocessgroup_flags::force_memcg_v2();
     std::vector<CgroupDescriptor> result;
     std::string json_doc;
 
@@ -133,14 +132,10 @@ bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap*
         const Json::Value& cgroups = root["Cgroups"];
         for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
             std::string name = cgroups[i]["Controller"].asString();
-
-            if (force_memcg_v2 && name == "memory") continue;
-
             MergeCgroupToDescriptors(descriptors, cgroups[i], name, "", 1);
         }
     }
 
-    bool memcgv2_present = false;
     std::string root_path;
     if (root.isMember("Cgroups2")) {
         const Json::Value& cgroups2 = root["Cgroups2"];
@@ -150,24 +145,10 @@ bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap*
         const Json::Value& childGroups = cgroups2["Controllers"];
         for (Json::Value::ArrayIndex i = 0; i < childGroups.size(); ++i) {
             std::string name = childGroups[i]["Controller"].asString();
-
-            if (force_memcg_v2 && name == "memory") memcgv2_present = true;
-
             MergeCgroupToDescriptors(descriptors, childGroups[i], name, root_path, 2);
         }
     }
 
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
     return true;
 }
 
diff --git a/libprocessgroup/vts/Android.bp b/libprocessgroup/vts/Android.bp
new file mode 100644
index 0000000000..1ec49a45fc
--- /dev/null
+++ b/libprocessgroup/vts/Android.bp
@@ -0,0 +1,15 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "vts_libprocessgroup",
+    srcs: ["vts_libprocessgroup.cpp"],
+    shared_libs: ["libbase"],
+    static_libs: ["libgmock"],
+    require_root: true,
+    test_suites: [
+        "general-tests",
+        "vts",
+    ],
+}
diff --git a/libprocessgroup/vts/vts_libprocessgroup.cpp b/libprocessgroup/vts/vts_libprocessgroup.cpp
new file mode 100644
index 0000000000..e51fa3daae
--- /dev/null
+++ b/libprocessgroup/vts/vts_libprocessgroup.cpp
@@ -0,0 +1,138 @@
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
+#include <cerrno>
+#include <cstdio>
+#include <filesystem>
+#include <iostream>
+#include <optional>
+#include <random>
+#include <string>
+#include <vector>
+
+#include <android-base/file.h>
+#include <android-base/strings.h>
+using android::base::ReadFileToString;
+using android::base::Split;
+using android::base::WriteStringToFile;
+
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+namespace {
+
+const std::string CGROUP_V2_ROOT_PATH = "/sys/fs/cgroup";
+
+std::optional<bool> isMemcgV2Enabled() {
+    if (std::string proc_cgroups; ReadFileToString("/proc/cgroups", &proc_cgroups)) {
+        const std::vector<std::string> lines = Split(proc_cgroups, "\n");
+        for (const std::string& line : lines) {
+            if (line.starts_with("memory")) {
+                const bool enabled = line.back() == '1';
+                if (!enabled) return false;
+
+                const std::vector<std::string> memcg_tokens = Split(line, "\t");
+                return memcg_tokens[1] == "0";  // 0 == default hierarchy == v2
+            }
+        }
+        // We know for sure it's not enabled, either because it is mounted as v1 (cgroups.json
+        // override) which would be detected above, or because it was intentionally disabled via
+        // kernel command line (cgroup_disable=memory), or because it's not built in to the kernel
+        // (CONFIG_MEMCG is not set).
+        return false;
+    }
+
+    // Problems accessing /proc/cgroups (sepolicy?) Try checking the root cgroup.controllers file.
+    perror("Warning: Could not read /proc/cgroups");
+    if (std::string controllers;
+        ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.controllers", &controllers)) {
+        return controllers.find("memory") != std::string::npos;
+    }
+
+    std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
+              << "/cgroup.controllers: " << std::strerror(errno) << std::endl;
+    return std::nullopt;
+}
+
+std::optional<bool> checkRootSubtreeState() {
+    if (std::string controllers;
+        ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control", &controllers)) {
+        return controllers.find("memory") != std::string::npos;
+    }
+    std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
+              << "/cgroup.subtree_control: " << std::strerror(errno) << std::endl;
+    return std::nullopt;
+}
+
+}  // anonymous namespace
+
+class MemcgV2SubdirTest : public testing::Test {
+  protected:
+    std::optional<std::string> mRandDir;
+
+    void SetUp() override {
+        std::optional<bool> memcgV2Enabled = isMemcgV2Enabled();
+        ASSERT_NE(memcgV2Enabled, std::nullopt);
+        if (!*memcgV2Enabled) GTEST_SKIP() << "Memcg v2 not enabled";
+
+        mRootSubtreeState = checkRootSubtreeState();
+        ASSERT_NE(mRootSubtreeState, std::nullopt);
+
+        if (!*mRootSubtreeState) {
+            ASSERT_TRUE(
+                    WriteStringToFile("+memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control"))
+                    << "Could not enable memcg under root: " << std::strerror(errno);
+        }
+
+        // Make a new, temporary, randomly-named v2 cgroup in which we will attempt to activate
+        // memcg
+        std::random_device rd;
+        std::uniform_int_distribution dist(static_cast<int>('A'), static_cast<int>('Z'));
+        std::string randName = CGROUP_V2_ROOT_PATH + "/vts_libprocessgroup.";
+        for (int i = 0; i < 10; ++i) randName.append(1, static_cast<char>(dist(rd)));
+        ASSERT_TRUE(std::filesystem::create_directory(randName));
+        mRandDir = randName;  // For cleanup in TearDown
+
+        std::string subtree_controllers;
+        ASSERT_TRUE(ReadFileToString(*mRandDir + "/cgroup.controllers", &subtree_controllers));
+        ASSERT_NE(subtree_controllers.find("memory"), std::string::npos)
+                << "Memcg was not activated in child cgroup";
+    }
+
+    void TearDown() override {
+        if (mRandDir) {
+            if (!std::filesystem::remove(*mRandDir)) {
+                std::cerr << "Could not remove temporary memcg v2 test directory" << std::endl;
+            }
+        }
+
+        if (!*mRootSubtreeState) {
+            if (!WriteStringToFile("-memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control")) {
+                std::cerr << "Could not disable memcg under root: " << std::strerror(errno)
+                          << std::endl;
+            }
+        }
+    }
+
+  private:
+    std::optional<bool> mRootSubtreeState;
+};
+
+
+TEST_F(MemcgV2SubdirTest, CanActivateMemcgV2Subtree) {
+    ASSERT_TRUE(WriteStringToFile("+memory", *mRandDir + "/cgroup.subtree_control"))
+            << "Could not enable memcg under child cgroup subtree";
+}
diff --git a/libsparse/Android.bp b/libsparse/Android.bp
index 44907a1f07..1d67cbe28d 100644
--- a/libsparse/Android.bp
+++ b/libsparse/Android.bp
@@ -89,11 +89,6 @@ python_binary_host {
     name: "simg_dump",
     main: "simg_dump.py",
     srcs: ["simg_dump.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 cc_fuzz {
diff --git a/libstats/bootstrap/BootstrapClientInternal.h b/libstats/bootstrap/BootstrapClientInternal.h
index 96238dade1..7879d01f6b 100644
--- a/libstats/bootstrap/BootstrapClientInternal.h
+++ b/libstats/bootstrap/BootstrapClientInternal.h
@@ -18,6 +18,8 @@
 
 #include <android/os/IStatsBootstrapAtomService.h>
 
+#include <mutex>
+
 namespace android {
 namespace os {
 namespace stats {
diff --git a/libstats/expresslog/Android.bp b/libstats/expresslog/Android.bp
index f70252afc7..ad86d87c1f 100644
--- a/libstats/expresslog/Android.bp
+++ b/libstats/expresslog/Android.bp
@@ -51,7 +51,7 @@ cc_library {
     min_sdk_version: "33",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
 }
 
@@ -85,7 +85,7 @@ cc_library_static {
     min_sdk_version: "33",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
 }
 
diff --git a/libstats/pull_rust/Android.bp b/libstats/pull_rust/Android.bp
index 2a8939edbc..ae00e75750 100644
--- a/libstats/pull_rust/Android.bp
+++ b/libstats/pull_rust/Android.bp
@@ -24,7 +24,7 @@ rust_bindgen {
     crate_name: "statspull_bindgen",
     visibility: [
         "//frameworks/proto_logging/stats/stats_log_api_gen",
-        "//packages/modules/Virtualization/libs/statslog_virtualization",
+        "//packages/modules:__subpackages__",
     ],
     source_stem: "bindings",
     bindgen_flags: [
diff --git a/libsync/sync.c b/libsync/sync.c
index b8c48c7f76..c4c4472be6 100644
--- a/libsync/sync.c
+++ b/libsync/sync.c
@@ -117,7 +117,7 @@ enum uapi_version {
     UAPI_MODERN,
     UAPI_LEGACY
 };
-static atomic_int g_uapi_version = ATOMIC_VAR_INIT(UAPI_UNKNOWN);
+static atomic_int g_uapi_version = UAPI_UNKNOWN;
 
 // ---------------------------------------------------------------------------
 
diff --git a/libsystem/OWNERS b/libsystem/OWNERS
index 9bda04c4dc..6c6fe1f70d 100644
--- a/libsystem/OWNERS
+++ b/libsystem/OWNERS
@@ -1,6 +1,5 @@
 # graphics/composer
 adyabr@google.com
-lpy@google.com
 
 # camera
 etalvala@google.com
diff --git a/libsysutils/Android.bp b/libsysutils/Android.bp
index 842db4033b..18a6aa6552 100644
--- a/libsysutils/Android.bp
+++ b/libsysutils/Android.bp
@@ -32,18 +32,6 @@ cc_library {
 
     export_include_dirs: ["include"],
 
-    tidy: true,
-    tidy_checks: [
-        "-*",
-        "cert-*",
-        "clang-analyzer-security*",
-        "android-*",
-    ],
-    tidy_checks_as_errors: [
-        "cert-*",
-        "clang-analyzer-security*",
-        "android-*",
-    ],
     apex_available: [
         "//apex_available:anyapex",
         "//apex_available:platform",
diff --git a/libsysutils/src/NetlinkEvent.cpp b/libsysutils/src/NetlinkEvent.cpp
index 55bbe46e1a..47586db071 100644
--- a/libsysutils/src/NetlinkEvent.cpp
+++ b/libsysutils/src/NetlinkEvent.cpp
@@ -37,108 +37,44 @@
 #include <sys/utsname.h>
 
 #include <android-base/parseint.h>
-#include <bpf/KernelUtils.h>
 #include <log/log.h>
 #include <sysutils/NetlinkEvent.h>
 
 using android::base::ParseInt;
-using android::bpf::isKernel64Bit;
-
-/* From kernel's net/netfilter/xt_quota2.c */
-const int LOCAL_QLOG_NL_EVENT = 112;
-const int LOCAL_NFLOG_PACKET = NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET;
-
-/******************************************************************************
- * WARNING: HERE BE DRAGONS!                                                  *
- *                                                                            *
- * This is here to provide for compatibility with both 32 and 64-bit kernels  *
- * from 32-bit userspace.                                                     *
- *                                                                            *
- * The kernel definition of this struct uses types (like long) that are not   *
- * the same across 32-bit and 64-bit builds, and there is no compatibility    *
- * layer to fix it up before it reaches userspace.                            *
- * As such we need to detect the bit-ness of the kernel and deal with it.     *
- *                                                                            *
- ******************************************************************************/
 
-/*
- * This is the verbatim kernel declaration from net/netfilter/xt_quota2.c,
- * it is *NOT* of a well defined layout and is included here for compile
- * time assertions only.
- *
- * It got there from deprecated ipt_ULOG.h to parse QLOG_NL_EVENT.
- */
-#define ULOG_MAC_LEN 80
-#define ULOG_PREFIX_LEN 32
-typedef struct ulog_packet_msg {
-    unsigned long mark;
-    long timestamp_sec;
-    long timestamp_usec;
-    unsigned int hook;
-    char indev_name[IFNAMSIZ];
-    char outdev_name[IFNAMSIZ];
-    size_t data_len;
-    char prefix[ULOG_PREFIX_LEN];
-    unsigned char mac_len;
-    unsigned char mac[ULOG_MAC_LEN];
-    unsigned char payload[0];
-} ulog_packet_msg_t;
-
-// On Linux int is always 32 bits, while sizeof(long) == sizeof(void*),
-// thus long on a 32-bit Linux kernel is 32-bits, like int always is
-typedef int long32;
-typedef unsigned int ulong32;
-static_assert(sizeof(long32) == 4);
-static_assert(sizeof(ulong32) == 4);
-
-// Here's the same structure definition with the assumption the kernel
-// is compiled for 32-bits.
-typedef struct {
-    ulong32 mark;
-    long32 timestamp_sec;
-    long32 timestamp_usec;
-    unsigned int hook;
-    char indev_name[IFNAMSIZ];
-    char outdev_name[IFNAMSIZ];
-    ulong32 data_len;
-    char prefix[ULOG_PREFIX_LEN];
-    unsigned char mac_len;
-    unsigned char mac[ULOG_MAC_LEN];
-    unsigned char payload[0];
-} ulog_packet_msg32_t;
-
-// long on a 64-bit kernel is 64-bits with 64-bit alignment,
-// while long long is 64-bit but may have 32-bit aligment.
+// 'long' on a 32-bit kernel is 32-bits with 32-bit alignment,
+// and on a 64-bit kernel is 64-bits with 64-bit alignment,
+// while 'long long' is always 64-bit it may have 32-bit aligment (x86 structs).
 typedef long long __attribute__((__aligned__(8))) long64;
 typedef unsigned long long __attribute__((__aligned__(8))) ulong64;
 static_assert(sizeof(long64) == 8);
 static_assert(sizeof(ulong64) == 8);
 
-// Here's the same structure definition with the assumption the kernel
-// is compiled for 64-bits.
+// From kernel's net/netfilter/xt_quota2.c
+// It got there from deprecated ipt_ULOG.h to parse QLOG_NL_EVENT.
+constexpr int LOCAL_QLOG_NL_EVENT = 112;
+constexpr int LOCAL_NFLOG_PACKET = NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET;
+
+constexpr int ULOG_MAC_LEN = 80;
+constexpr int ULOG_PREFIX_LEN = 32;
+
+// This structure layout assumes we're running on a 64-bit kernel.
 typedef struct {
-    ulong64 mark;
-    long64 timestamp_sec;
-    long64 timestamp_usec;
+    ulong64 mark;  // kernel: unsigned long
+    long64 timestamp_sec;  // kernel: long
+    long64 timestamp_usec;  // kernel: long
     unsigned int hook;
     char indev_name[IFNAMSIZ];
     char outdev_name[IFNAMSIZ];
-    ulong64 data_len;
+    ulong64 data_len;  // kernel: size_t, a.k.a. unsigned long
     char prefix[ULOG_PREFIX_LEN];
     unsigned char mac_len;
     unsigned char mac[ULOG_MAC_LEN];
     unsigned char payload[0];
-} ulog_packet_msg64_t;
-
-// One expects the 32-bit version to be smaller than the 64-bit version.
-static_assert(sizeof(ulog_packet_msg32_t) < sizeof(ulog_packet_msg64_t));
-// And either way the 'native' version should match either the 32 or 64 bit one.
-static_assert(sizeof(ulog_packet_msg_t) == sizeof(ulog_packet_msg32_t) ||
-              sizeof(ulog_packet_msg_t) == sizeof(ulog_packet_msg64_t));
+} ulog_packet_msg_t;
 
-// In practice these sizes are always simply (for both x86 and arm):
-static_assert(sizeof(ulog_packet_msg32_t) == 168);
-static_assert(sizeof(ulog_packet_msg64_t) == 192);
+// In practice, for both x86 and arm, we have
+static_assert(sizeof(ulog_packet_msg_t) == 192);
 
 /******************************************************************************/
 
@@ -356,20 +292,11 @@ bool NetlinkEvent::parseIfAddrMessage(const struct nlmsghdr *nh) {
  * Parse a QLOG_NL_EVENT message.
  */
 bool NetlinkEvent::parseUlogPacketMessage(const struct nlmsghdr *nh) {
-    const char* alert;
-    const char* devname;
-
-    if (isKernel64Bit()) {
-        ulog_packet_msg64_t* pm64 = (ulog_packet_msg64_t*)NLMSG_DATA(nh);
-        if (!checkRtNetlinkLength(nh, sizeof(*pm64))) return false;
-        alert = pm64->prefix;
-        devname = pm64->indev_name[0] ? pm64->indev_name : pm64->outdev_name;
-    } else {
-        ulog_packet_msg32_t* pm32 = (ulog_packet_msg32_t*)NLMSG_DATA(nh);
-        if (!checkRtNetlinkLength(nh, sizeof(*pm32))) return false;
-        alert = pm32->prefix;
-        devname = pm32->indev_name[0] ? pm32->indev_name : pm32->outdev_name;
-    }
+    ulog_packet_msg_t* pm = (ulog_packet_msg_t*)NLMSG_DATA(nh);
+    if (!checkRtNetlinkLength(nh, sizeof(*pm))) return false;
+
+    const char* alert = pm->prefix;
+    const char* devname = pm->indev_name[0] ? pm->indev_name : pm->outdev_name;
 
     asprintf(&mParams[0], "ALERT_NAME=%s", alert);
     asprintf(&mParams[1], "INTERFACE=%s", devname);
diff --git a/libsysutils/src/OWNERS b/libsysutils/src/OWNERS
index c65a40dc37..a3e4c703f0 100644
--- a/libsysutils/src/OWNERS
+++ b/libsysutils/src/OWNERS
@@ -1,2 +1 @@
-per-file OWNERS,Netlink* = codewiz@google.com, jchalard@google.com, lorenzo@google.com, satk@google.com
-
+per-file OWNERS,Netlink* = file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
diff --git a/libutils/binder/RefBase.cpp b/libutils/binder/RefBase.cpp
index 4291f1e211..bf803e72b7 100644
--- a/libutils/binder/RefBase.cpp
+++ b/libutils/binder/RefBase.cpp
@@ -492,7 +492,10 @@ void RefBase::decStrong(const void* id) const
 #if PRINT_REFS
     ALOGD("decStrong of %p from %p: cnt=%d\n", this, id, c);
 #endif
-    LOG_ALWAYS_FATAL_IF(BAD_STRONG(c), "decStrong() called on %p too many times",
+    LOG_ALWAYS_FATAL_IF(
+            BAD_STRONG(c),
+            "decStrong() called on %p too many times, possible memory corruption. Consider "
+            "compiling with ANDROID_UTILS_REF_BASE_DISABLE_IMPLICIT_CONSTRUCTION for better errors",
             refs);
     if (c == 1) {
         std::atomic_thread_fence(std::memory_order_acquire);
@@ -576,7 +579,10 @@ void RefBase::weakref_type::decWeak(const void* id)
     weakref_impl* const impl = static_cast<weakref_impl*>(this);
     impl->removeWeakRef(id);
     const int32_t c = impl->mWeak.fetch_sub(1, std::memory_order_release);
-    LOG_ALWAYS_FATAL_IF(BAD_WEAK(c), "decWeak called on %p too many times",
+    LOG_ALWAYS_FATAL_IF(
+            BAD_WEAK(c),
+            "decWeak called on %p too many times, possible memory corruption. Consider compiling "
+            "with ANDROID_UTILS_REF_BASE_DISABLE_IMPLICIT_CONSTRUCTION for better errors",
             this);
     if (c != 1) return;
     atomic_thread_fence(std::memory_order_acquire);
diff --git a/libutils/binder/RefBase_test.cpp b/libutils/binder/RefBase_test.cpp
index 65d40a2a18..36d1a4a389 100644
--- a/libutils/binder/RefBase_test.cpp
+++ b/libutils/binder/RefBase_test.cpp
@@ -265,6 +265,37 @@ TEST(RefBase, AssertWeakRefExistsDeath) {
     delete foo;
 }
 
+TEST(RefBase, NoStrongCountPromoteFromWeak) {
+    bool isDeleted;
+    Foo* foo = new Foo(&isDeleted);
+
+    wp<Foo> weakFoo = wp<Foo>(foo);
+
+    EXPECT_FALSE(isDeleted);
+
+    {
+        sp<Foo> strongFoo = weakFoo.promote();
+        EXPECT_EQ(strongFoo, foo);
+    }
+
+    // this shows the justification of wp<>::fromExisting.
+    // if you construct a wp<>, for instance in a constructor, and it is
+    // accidentally promoted, that promoted sp<> will exclusively own
+    // the object. If that happens during the initialization of the
+    // object or in this scope, as you can see 'Foo* foo' is unowned,
+    // then we are left with a deleted object, and we could not put it
+    // into an sp<>.
+    //
+    // Consider the other implementation, where we disallow promoting
+    // a wp<> if there are no strong counts. If we return null, then
+    // the object would be unpromotable even though it hasn't been deleted.
+    // This is also errorprone.
+    //
+    // attemptIncStrong aborting in this case is a backwards incompatible
+    // change due to frequent use of wp<T>(this) in the constructor.
+    EXPECT_TRUE(isDeleted);
+}
+
 TEST(RefBase, DoubleOwnershipDeath) {
     bool isDeleted;
     auto foo = sp<Foo>::make(&isDeleted);
diff --git a/libutils/binder/String8_test.cpp b/libutils/binder/String8_test.cpp
index fc3c329412..ff9bc8d559 100644
--- a/libutils/binder/String8_test.cpp
+++ b/libutils/binder/String8_test.cpp
@@ -176,3 +176,11 @@ TEST_F(String8Test, comparisons) {
     EXPECT_TRUE(pair1 < pair2);
     EXPECT_FALSE(pair1 > pair2);
 }
+
+TEST_F(String8Test, SvCtor) {
+    const char* expected = "abc";
+    std::string s{expected};
+    EXPECT_STREQ(String8{s}.c_str(), expected);
+    EXPECT_STREQ(String8{std::string_view{s}}.c_str(), expected);
+    EXPECT_STREQ(String8{expected}.c_str(), expected);
+}
diff --git a/libutils/binder/include/utils/String16.h b/libutils/binder/include/utils/String16.h
index 867dbac34a..20de647eef 100644
--- a/libutils/binder/include/utils/String16.h
+++ b/libutils/binder/include/utils/String16.h
@@ -19,16 +19,12 @@
 
 #include <iostream>
 #include <string>
+#include <string_view>
 
 #include <utils/Errors.h>
 #include <utils/String8.h>
 #include <utils/TypeHelpers.h>
 
-#if __has_include(<string_view>)
-#include <string_view>
-#define HAS_STRING_VIEW
-#endif
-
 #if __cplusplus >= 202002L
 #include <compare>
 #endif
@@ -125,11 +121,9 @@ public:
 
     inline                      operator const char16_t*() const;
 
-#ifdef HAS_STRING_VIEW
     // Implicit cast to std::u16string is not implemented on purpose - u16string_view is much
     // lighter and if one needs, they can still create u16string from u16string_view.
     inline                      operator std::u16string_view() const;
-#endif
 
     // Static and non-static String16 behave the same for the users, so
     // this method isn't of much use for the users. It is public for testing.
@@ -414,6 +408,4 @@ inline String16::operator std::u16string_view() const
 
 // ---------------------------------------------------------------------------
 
-#undef HAS_STRING_VIEW
-
 #endif // ANDROID_STRING16_H
diff --git a/libutils/binder/include/utils/String8.h b/libutils/binder/include/utils/String8.h
index e0d7588f6a..404f8a0280 100644
--- a/libutils/binder/include/utils/String8.h
+++ b/libutils/binder/include/utils/String8.h
@@ -18,6 +18,8 @@
 #define ANDROID_STRING8_H
 
 #include <iostream>
+#include <string>
+#include <string_view>
 
 #include <utils/Errors.h>
 #include <utils/Unicode.h>
@@ -26,16 +28,6 @@
 #include <string.h> // for strcmp
 #include <stdarg.h>
 
-#if __has_include(<string>)
-#include <string>
-#define HAS_STRING
-#endif
-
-#if __has_include(<string_view>)
-#include <string_view>
-#define HAS_STRING_VIEW
-#endif
-
 #if __cplusplus >= 202002L
 #include <compare>
 #endif
@@ -57,6 +49,7 @@ public:
                                 String8(const String8& o);
     explicit                    String8(const char* o);
     explicit                    String8(const char* o, size_t numChars);
+    explicit                    String8(std::string_view o);
 
     explicit                    String8(const String16& o);
     explicit                    String8(const char16_t* o);
@@ -126,9 +119,7 @@ public:
 
     inline                      operator const char*() const;
 
-#ifdef HAS_STRING_VIEW
     inline explicit             operator std::string_view() const;
-#endif
 
             char*               lockBuffer(size_t size);
             void                unlockBuffer();
@@ -373,18 +364,15 @@ inline String8::operator const char*() const
     return mString;
 }
 
-#ifdef HAS_STRING_VIEW
+inline String8::String8(std::string_view o) : String8(o.data(), o.length()) { }
+
 inline String8::operator std::string_view() const
 {
     return {mString, length()};
 }
-#endif
 
 }  // namespace android
 
 // ---------------------------------------------------------------------------
 
-#undef HAS_STRING
-#undef HAS_STRING_VIEW
-
 #endif // ANDROID_STRING8_H
diff --git a/llkd/OWNERS b/llkd/OWNERS
index b6af537ef4..b15bb48705 100644
--- a/llkd/OWNERS
+++ b/llkd/OWNERS
@@ -1,2 +1 @@
-salyzyn@google.com
 surenb@google.com
diff --git a/trusty/storage/interface/Android.bp b/overlay_remounter/Android.bp
similarity index 59%
rename from trusty/storage/interface/Android.bp
rename to overlay_remounter/Android.bp
index 769f53d8eb..d74f7da5bf 100644
--- a/trusty/storage/interface/Android.bp
+++ b/overlay_remounter/Android.bp
@@ -1,5 +1,5 @@
 //
-// Copyright (C) 2015 The Android Open-Source Project
+// Copyright (C) 2025 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -14,13 +14,21 @@
 // limitations under the License.
 //
 
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_library_static {
-    name: "libtrustystorageinterface",
-    vendor_available: true,
-    system_ext_specific: true,
-    export_include_dirs: ["include"],
+cc_binary {
+    name: "overlay_remounter",
+    srcs: [
+        "overlay_remounter.cpp",
+    ],
+    cflags: [
+        "-D_FILE_OFFSET_BITS=64",
+        "-Wall",
+        "-Werror",
+    ],
+    static_libs: [
+        "libbase",
+        "liblog",
+    ],
+    system_shared_libs: [],
+    static_executable: true,
+    install_in_xbin: true,
 }
diff --git a/overlay_remounter/overlay_remounter.cpp b/overlay_remounter/overlay_remounter.cpp
new file mode 100644
index 0000000000..ddf97faa8b
--- /dev/null
+++ b/overlay_remounter/overlay_remounter.cpp
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
+#include <sys/mount.h>
+#include <unistd.h>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+
+int main(int /*argc*/, char** argv) {
+    android::base::InitLogging(argv, &android::base::KernelLogger);
+    LOG(INFO) << "Overlay remounter will remount all overlay mount points in the overlay_remounter "
+                 "domain";
+
+    // Remount ouerlayfs
+    std::string contents;
+    auto result = android::base::ReadFileToString("/proc/mounts", &contents, true);
+
+    auto lines = android::base::Split(contents, "\n");
+    for (auto const& line : lines) {
+        if (!android::base::StartsWith(line, "overlay")) {
+            continue;
+        }
+        auto bits = android::base::Split(line, " ");
+        if (int result = umount(bits[1].c_str()); result == -1) {
+            PLOG(FATAL) << "umount FAILED: " << bits[1];
+        }
+        std::string options;
+        for (auto const& option : android::base::Split(bits[3], ",")) {
+            if (option == "ro" || option == "seclabel" || option == "noatime") continue;
+            if (!options.empty()) options += ',';
+            options += option;
+        }
+        result = mount("overlay", bits[1].c_str(), "overlay", MS_RDONLY | MS_NOATIME,
+                       options.c_str());
+        if (result == 0) {
+            LOG(INFO) << "mount succeeded: " << bits[1] << " " << options;
+        } else {
+            PLOG(FATAL) << "mount FAILED: " << bits[1] << " " << bits[3];
+        }
+    }
+
+    const char* path = "/system/bin/init";
+    const char* args[] = {path, "second_stage", nullptr};
+    execv(path, const_cast<char**>(args));
+
+    // execv() only returns if an error happened, in which case we
+    // panic and never return from this function.
+    PLOG(FATAL) << "execv(\"" << path << "\") failed";
+
+    return 1;
+}
diff --git a/property_service/libpropertyinfoserializer/trie_serializer.cpp b/property_service/libpropertyinfoserializer/trie_serializer.cpp
index adeed1bf7c..f1632cdd4c 100644
--- a/property_service/libpropertyinfoserializer/trie_serializer.cpp
+++ b/property_service/libpropertyinfoserializer/trie_serializer.cpp
@@ -16,6 +16,8 @@
 
 #include "trie_serializer.h"
 
+#include <algorithm>
+
 namespace android {
 namespace properties {
 
diff --git a/rootdir/Android.bp b/rootdir/Android.bp
index 44acbbae4b..c0d31d964a 100644
--- a/rootdir/Android.bp
+++ b/rootdir/Android.bp
@@ -37,7 +37,6 @@ prebuilt_etc {
     src: "init.rc",
     sub_dir: "init/hw",
     required: [
-        "fsverity_init",
         "platform-bootclasspath",
         "init.boringssl.zygote64.rc",
         "init.boringssl.zygote64_32.rc",
@@ -47,7 +46,13 @@ prebuilt_etc {
 prebuilt_etc {
     name: "ueventd.rc",
     src: "ueventd.rc",
-    recovery_available: true,
+}
+
+prebuilt_etc {
+    name: "ueventd.rc.recovery",
+    src: "ueventd.rc",
+    recovery: true,
+    filename: "ueventd.rc",
 }
 
 filegroup {
@@ -55,13 +60,6 @@ filegroup {
     srcs: ["etc/linker.config.json"],
 }
 
-// TODO(b/147210213) Generate list of libraries during build and fill in at build time
-linker_config {
-    name: "system_linker_config",
-    src: ":system_linker_config_json_file",
-    installable: false,
-}
-
 // TODO(b/185211376) Scope the native APIs that microdroid will provide to the app payload
 prebuilt_etc {
     name: "public.libraries.android.txt",
@@ -119,6 +117,12 @@ prebuilt_etc {
     sub_dir: "init",
 }
 
+prebuilt_etc {
+    name: "init-mmd-prop.rc",
+    src: "init-mmd-prop.rc",
+    sub_dir: "init",
+}
+
 prebuilt_etc {
     name: "asan.options",
     src: "asan.options",
diff --git a/rootdir/create_root_structure.mk b/rootdir/create_root_structure.mk
index 1daf239b4d..15d78a67b1 100644
--- a/rootdir/create_root_structure.mk
+++ b/rootdir/create_root_structure.mk
@@ -27,7 +27,7 @@ endif
 #
 # create some directories (some are mount points) and symlinks
 LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
-    dev proc sys system data data_mirror odm oem acct config storage mnt apex bootstrap-apex debug_ramdisk \
+    dev proc sys system data data_mirror odm oem config storage mnt apex bootstrap-apex debug_ramdisk \
     linkerconfig second_stage_resources postinstall tmp $(BOARD_ROOT_EXTRA_FOLDERS)); \
     ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
     ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
@@ -41,7 +41,8 @@ ALL_ROOTDIR_SYMLINKS := \
   $(TARGET_ROOT_OUT)/etc \
   $(TARGET_ROOT_OUT)/bugreports \
   $(TARGET_ROOT_OUT)/d \
-  $(TARGET_ROOT_OUT)/sdcard
+  $(TARGET_ROOT_OUT)/sdcard \
+  $(TARGET_ROOT_OUT)/adb_keys \
 
 ifdef BOARD_USES_VENDORIMAGE
   LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor
diff --git a/rootdir/init-mmd-prop.rc b/rootdir/init-mmd-prop.rc
new file mode 100644
index 0000000000..6e9191c275
--- /dev/null
+++ b/rootdir/init-mmd-prop.rc
@@ -0,0 +1,19 @@
+on property:sys.boot_completed=1
+    # When mmd package is not included in the image, we need to initialize
+    # `mmd.enabled_aconfig` sysprop instead of `mmd --set-property`.
+    #
+    # This is because of the consideration for devices in Trunkfood and Nextfood
+    # under mmd being launched via AConfig flag. The devices set up zram with
+    # mmd if `mmd_enabled` AConfig flag is enabled, otherwise set up zram with
+    # swapon_all init command. Since AConfig does not support any init script
+    # integration, we use `mmd.enabled_aconfig` copied by `mmd --set-property`
+    # instead of AConfig flag itself and we need mmd.enabled_aconfig to be empty
+    # by default, to let swapon_all command wait until aconfig flag value is
+    # loaded to the system property.
+    # Devices in Trunkfood and Nextfood needs to execute swapon_all command on
+    # `on property:mmd.enabled_aconfig=*` trigger. So initializing
+    # `mmd.enabled_aconfig` sysprop is required on images without mmd package.
+    #
+    # Note that this init file must not be in the image if mmd is built into the
+    # image.
+    setprop mmd.enabled_aconfig false
\ No newline at end of file
diff --git a/rootdir/init.rc b/rootdir/init.rc
index ae6a6588b6..471059bc87 100644
--- a/rootdir/init.rc
+++ b/rootdir/init.rc
@@ -27,8 +27,6 @@ on early-init
     # Set the security context of /postinstall if present.
     restorecon /postinstall
 
-    mkdir /acct/uid
-
     # memory.pressure_level used by lmkd
     chown root system /dev/memcg/memory.pressure_level
     chmod 0040 /dev/memcg/memory.pressure_level
@@ -571,6 +569,9 @@ on post-fs
     chown root log /proc/vmallocinfo
     chmod 0440 /proc/vmallocinfo
 
+    chown root log /proc/allocinfo
+    chmod 0440 /proc/allocinfo
+
     chown root log /proc/slabinfo
     chmod 0440 /proc/slabinfo
 
@@ -622,9 +623,6 @@ on late-fs
     # HALs required before storage encryption can get unlocked (FBE)
     class_start early_hal
 
-    # Load trusted keys from dm-verity protected partitions
-    exec -- /system/bin/fsverity_init --load-verified-keys
-
 # Only enable the bootreceiver tracing instance for kernels 5.10 and above.
 on late-fs && property:ro.kernel.version=4.19
     setprop bootreceiver.enable 0
@@ -729,7 +727,6 @@ on post-fs-data
     mkdir /data/apex/active 0755 root system
     mkdir /data/apex/backup 0700 root system
     mkdir /data/apex/decompressed 0755 root system encryption=Require
-    mkdir /data/apex/sessions 0700 root system
     mkdir /data/app-staging 0751 system system encryption=DeleteIfNecessary
     mkdir /data/apex/ota_reserved 0700 root system encryption=Require
     setprop apexd.status ""
@@ -790,7 +787,8 @@ on post-fs-data
     mkdir /data/misc/vold 0700 root root
     mkdir /data/misc/boottrace 0771 system shell
     mkdir /data/misc/update_engine 0700 root root
-    mkdir /data/misc/update_engine_log 02750 root log
+    mkdir /data/misc/update_engine_log 02750 root update_engine_log
+    chown root update_engine_log /data/misc/update_engine_log
     mkdir /data/misc/trace 0700 root root
     # create location to store surface and window trace files
     mkdir /data/misc/wmtrace 0700 system system
@@ -904,7 +902,7 @@ on post-fs-data
     mkdir /data/system/users 0775 system system
     # Mkdir and set SELinux security contexts for shutdown-checkpoints.
     # TODO(b/270286197): remove these after couple releases.
-    mkdir /data/system/shutdown-checkpoints 0700 system system
+    mkdir /data/system/shutdown-checkpoints 0755 system system
     restorecon_recursive /data/system/shutdown-checkpoints
 
     # Create the parent directories of the user CE and DE storage directories.
@@ -997,8 +995,11 @@ on post-fs-data
     mkdir /data/misc/stats-service/ 0770 statsd system
     mkdir /data/misc/train-info/ 0770 statsd system
 
-    # Wait for apexd to finish activating APEXes before starting more processes.
+    # TODO(b/400439023): Remove once attest modules flagging is removed.
     wait_for_prop apexd.status activated
+    # Wait for KeyMints to receive APEX module info before starting code from updateable APEXes.
+    # This is to prevent APEX modules from interfering in module measurement.
+    wait_for_prop keystore.module_hash.sent true
     perform_apex_config
 
     exec_start system_aconfigd_mainline_init
@@ -1233,7 +1234,7 @@ on property:sys.boot_completed=1
 # and chown/chmod does not work for /proc/sys/ entries.
 # So proxy writes through init.
 on property:sys.sysctl.extra_free_kbytes=*
-    exec -- /system/bin/extra_free_kbytes.sh ${sys.sysctl.extra_free_kbytes}
+    exec_background -- /system/bin/extra_free_kbytes.sh ${sys.sysctl.extra_free_kbytes}
 
 # Allow users to drop caches
 on property:perf.drop_caches=3
diff --git a/storaged/OWNERS b/storaged/OWNERS
index d033f0000b..9e70e7dcf6 100644
--- a/storaged/OWNERS
+++ b/storaged/OWNERS
@@ -1,2 +1 @@
-salyzyn@google.com
 dvander@google.com
diff --git a/storaged/main.cpp b/storaged/main.cpp
index bbed210de2..8e71180bfa 100644
--- a/storaged/main.cpp
+++ b/storaged/main.cpp
@@ -25,13 +25,12 @@
 #include <sys/types.h>
 #include <vector>
 
-#include <android-base/macros.h>
 #include <android-base/logging.h>
+#include <android-base/macros.h>
 #include <android-base/stringprintf.h>
-#include <binder/ProcessState.h>
-#include <binder/IServiceManager.h>
 #include <binder/IPCThreadState.h>
-#include <cutils/android_get_control_file.h>
+#include <binder/IServiceManager.h>
+#include <binder/ProcessState.h>
 #include <cutils/sched_policy.h>
 #include <private/android_filesystem_config.h>
 
diff --git a/storaged/storaged.rc b/storaged/storaged.rc
index 7085743faa..6debb69d0f 100644
--- a/storaged/storaged.rc
+++ b/storaged/storaged.rc
@@ -2,7 +2,6 @@ service storaged /system/bin/storaged
     class main
     capabilities DAC_READ_SEARCH
     priority 10
-    file /d/mmc0/mmc0:0001/ext_csd r
     task_profiles ServiceCapacityLow
     user root
     group package_info
diff --git a/storaged/uid_info.cpp b/storaged/uid_info.cpp
index 0f718de846..6f25898765 100644
--- a/storaged/uid_info.cpp
+++ b/storaged/uid_info.cpp
@@ -23,13 +23,13 @@ using namespace android::os::storaged;
 
 status_t UidInfo::writeToParcel(Parcel* parcel) const {
     parcel->writeInt32(uid);
-    parcel->writeCString(name.c_str());
+    parcel->writeString8(String8(name.c_str()));
     parcel->write(&io, sizeof(io));
 
     parcel->writeInt32(tasks.size());
     for (const auto& task_it : tasks) {
         parcel->writeInt32(task_it.first);
-        parcel->writeCString(task_it.second.comm.c_str());
+        parcel->writeString8(String8(task_it.second.comm.c_str()));
         parcel->write(&task_it.second.io, sizeof(task_it.second.io));
     }
     return OK;
@@ -37,14 +37,14 @@ status_t UidInfo::writeToParcel(Parcel* parcel) const {
 
 status_t UidInfo::readFromParcel(const Parcel* parcel) {
     uid = parcel->readInt32();
-    name = parcel->readCString();
+    name = parcel->readString8().c_str();
     parcel->read(&io, sizeof(io));
 
     uint32_t tasks_size = parcel->readInt32();
     for (uint32_t i = 0; i < tasks_size; i++) {
         task_info task;
         task.pid = parcel->readInt32();
-        task.comm = parcel->readCString();
+        task.comm = parcel->readString8().c_str();
         parcel->read(&task.io, sizeof(task.io));
         tasks[task.pid] = task;
     }
diff --git a/toolbox/Android.bp b/toolbox/Android.bp
index 3142542989..5169aa1b28 100644
--- a/toolbox/Android.bp
+++ b/toolbox/Android.bp
@@ -84,3 +84,22 @@ cc_binary {
     vendor: true,
     defaults: ["toolbox_binary_defaults"],
 }
+
+// This one is installed in the generic ramdisk, and can be executed during
+// init-first-stage.
+// As there are no dynamic linker available, this must be statically linked.
+cc_binary {
+    name: "toolbox_ramdisk",
+    defaults: ["toolbox_binary_defaults"],
+    ramdisk: true,
+    static_executable: true,
+    system_shared_libs: [],
+    exclude_shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    static_libs: [
+        "libbase",
+        "liblog",
+    ],
+}
diff --git a/toolbox/getprop.cpp b/toolbox/getprop.cpp
index ca345cb071..7c3d94c1b5 100644
--- a/toolbox/getprop.cpp
+++ b/toolbox/getprop.cpp
@@ -17,6 +17,7 @@
 #include <getopt.h>
 #include <sys/system_properties.h>
 
+#include <algorithm>
 #include <iostream>
 #include <string>
 #include <vector>
diff --git a/toolbox/modprobe.cpp b/toolbox/modprobe.cpp
index 13026ac30a..fe49ec811e 100644
--- a/toolbox/modprobe.cpp
+++ b/toolbox/modprobe.cpp
@@ -23,6 +23,7 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/macros.h>
 #include <android-base/strings.h>
 #include <android-base/stringprintf.h>
 #include <modprobe/modprobe.h>
@@ -87,6 +88,17 @@ void MyLogger(android::base::LogId id, android::base::LogSeverity severity, cons
 }
 
 static bool ModDirMatchesKernelPageSize(const char* mod_dir) {
+    static const unsigned int kernel_pgsize_kb = getpagesize() / 1024;
+    unsigned int mod_pgsize_kb = 16;  // 16k default since android15-6.6
+
+    if (mod_dir && strstr(mod_dir, "-4k") != NULL) {
+        mod_pgsize_kb = 4;
+    }
+
+    return kernel_pgsize_kb == mod_pgsize_kb;
+}
+
+static bool ModDirMatchesKernelPageSizeLegacy(const char* mod_dir) {
     static const unsigned int kernel_pgsize_kb = getpagesize() / 1024;
     const char* mod_sfx = strrchr(mod_dir, '_');
     unsigned int mod_pgsize_kb;
@@ -102,7 +114,7 @@ static bool ModDirMatchesKernelPageSize(const char* mod_dir) {
 
 // Find directories in format of "/lib/modules/x.y.z-*".
 static int KernelVersionNameFilter(const dirent* de) {
-    unsigned int major, minor;
+    static unsigned int major, minor;
     static std::string kernel_version;
     utsname uts;
 
@@ -115,7 +127,20 @@ static int KernelVersionNameFilter(const dirent* de) {
     }
 
     if (android::base::StartsWith(de->d_name, kernel_version)) {
-        return ModDirMatchesKernelPageSize(de->d_name);
+        // Check for GKI to avoid breaking non-GKI Android devices.
+        if (UNLIKELY(strstr(de->d_name, "-android") == NULL)) {
+            // For non-GKI, just match when the major and minor versions match.
+            return 1;
+        }
+
+        // For android15-6.6 and later, GKI adds `-4k` to the UTS release
+        // string to identify 4kb page size kernels. If there is no page size
+        // suffix, then the kernel page size is 16kb.
+        if (major > 6 || (major == 6 && minor >= 6)) {
+            return ModDirMatchesKernelPageSize(de->d_name);
+        } else {
+            return ModDirMatchesKernelPageSizeLegacy(de->d_name);
+        }
     }
     return 0;
 }
diff --git a/trusty/fuzz/tipc_fuzzer.cpp b/trusty/fuzz/tipc_fuzzer.cpp
index f265cedb69..f9f6c8c2ac 100644
--- a/trusty/fuzz/tipc_fuzzer.cpp
+++ b/trusty/fuzz/tipc_fuzzer.cpp
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include <android-base/result.h>
+#include <fuzzer/FuzzedDataProvider.h>
 #include <stdlib.h>
 #include <trusty/coverage/coverage.h>
 #include <trusty/coverage/uuid.h>
@@ -23,6 +25,7 @@
 #include <iostream>
 #include <memory>
 
+using android::base::Result;
 using android::trusty::coverage::CoverageRecord;
 using android::trusty::fuzz::ExtraCounters;
 using android::trusty::fuzz::TrustyApp;
@@ -41,7 +44,12 @@ using android::trusty::fuzz::TrustyApp;
 #error "Binary file name must be parameterized using -DTRUSTY_APP_FILENAME."
 #endif
 
-static TrustyApp kTrustyApp(TIPC_DEV, TRUSTY_APP_PORT);
+#ifdef TRUSTY_APP_MAX_CONNECTIONS
+constexpr size_t MAX_CONNECTIONS = TRUSTY_APP_MAX_CONNECTIONS;
+#else
+constexpr size_t MAX_CONNECTIONS = 1;
+#endif
+
 static std::unique_ptr<CoverageRecord> record;
 
 extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
@@ -53,7 +61,8 @@ extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
     }
 
     /* Make sure lazy-loaded TAs have started and connected to coverage service. */
-    auto ret = kTrustyApp.Connect();
+    TrustyApp ta(TIPC_DEV, TRUSTY_APP_PORT);
+    auto ret = ta.Connect();
     if (!ret.ok()) {
         std::cerr << ret.error() << std::endl;
         exit(-1);
@@ -73,24 +82,73 @@ extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
     return 0;
 }
 
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
-    static uint8_t buf[TIPC_MAX_MSG_SIZE];
-
-    ExtraCounters counters(record.get());
-    counters.Reset();
-
-    auto ret = kTrustyApp.Write(data, size);
-    if (ret.ok()) {
-        ret = kTrustyApp.Read(&buf, sizeof(buf));
+void abortResult(Result<void> result) {
+    if (result.ok()) {
+        return;
     }
+    std::cerr << result.error() << std::endl;
+    android::trusty::fuzz::Abort();
+}
 
-    // Reconnect to ensure that the service is still up
-    kTrustyApp.Disconnect();
-    ret = kTrustyApp.Connect();
-    if (!ret.ok()) {
-        std::cerr << ret.error() << std::endl;
-        android::trusty::fuzz::Abort();
+void testOneInput(FuzzedDataProvider& provider) {
+    std::vector<TrustyApp> trustyApps;
+
+    while (provider.remaining_bytes() > 0) {
+        static_assert(MAX_CONNECTIONS >= 1);
+
+        // Either
+        // 1. (20%) Add a new TA and connect.
+        // 2. (20%) Remove a TA.
+        // 3. (60%) Send a random message to a random TA.
+        auto add_ta = [&]() {
+            if (trustyApps.size() >= MAX_CONNECTIONS) {
+                return;
+            }
+            auto& ta = trustyApps.emplace_back(TIPC_DEV, TRUSTY_APP_PORT);
+            abortResult(ta.Connect());
+        };
+        auto remove_ta = [&]() {
+            if (trustyApps.empty()) {
+                return;
+            }
+            trustyApps.pop_back();
+        };
+        auto send_message = [&]() {
+            if (trustyApps.empty()) {
+                return;
+            }
+
+            // Choose a random TA.
+            const auto i = provider.ConsumeIntegralInRange<size_t>(0, trustyApps.size() - 1);
+            std::swap(trustyApps[i], trustyApps.back());
+            auto& ta = trustyApps.back();
+
+            // Send a random message.
+            const auto data = provider.ConsumeRandomLengthString();
+            abortResult(ta.Write(data.data(), data.size()));
+
+            std::array<uint8_t, TIPC_MAX_MSG_SIZE> buf;
+            abortResult(ta.Read(buf.data(), buf.size()));
+
+            // Reconnect to ensure that the service is still up.
+            ta.Disconnect();
+            abortResult(ta.Connect());
+        };
+        const std::function<void()> options[] = {
+                add_ta,                                    // 1x: 20%
+                remove_ta,                                 // 1x: 20%
+                send_message, send_message, send_message,  // 3x: 60%
+        };
+
+        provider.PickValueInArray(options)();
     }
+}
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    ExtraCounters counters(record.get());
+    counters.Reset();
 
-    return ret.ok() ? 0 : -1;
+    FuzzedDataProvider provider(data, size);
+    testOneInput(provider);
+    return 0;
 }
diff --git a/trusty/keymaster/Android.bp b/trusty/keymaster/Android.bp
index 8ebfc1aeba..31187f5b82 100644
--- a/trusty/keymaster/Android.bp
+++ b/trusty/keymaster/Android.bp
@@ -80,13 +80,9 @@ cc_binary {
     vintf_fragments: ["4.0/android.hardware.keymaster@4.0-service.trusty.xml"],
 }
 
-cc_binary {
-    name: "android.hardware.security.keymint-service.trusty",
+cc_defaults {
+    name: "android.hardware.security.keymint-service.trusty.defaults",
     relative_install_path: "hw",
-    init_rc: ["keymint/android.hardware.security.keymint-service.trusty.rc"],
-    vintf_fragments: [
-        "keymint/android.hardware.security.keymint-service.trusty.xml",
-    ],
     vendor: true,
     cflags: [
         "-Wall",
@@ -120,10 +116,38 @@ cc_binary {
         "libtrusty",
         "libutils",
     ],
-    required: select(release_flag("RELEASE_AIDL_USE_UNFROZEN"), {
-        true: ["android.hardware.hardware_keystore.xml"],
-        default: ["android.hardware.hardware_keystore_V3.xml"],
-    }),
+}
+
+// keymint hal binary for keymint in Trusty TEE prebuilt
+cc_binary {
+    name: "android.hardware.security.keymint-service.trusty",
+    defaults: ["android.hardware.security.keymint-service.trusty.defaults"],
+    init_rc: ["keymint/android.hardware.security.keymint-service.trusty.rc"],
+    vintf_fragments: [
+        "keymint/android.hardware.security.keymint-service.trusty.xml",
+    ],
+    required: ["android.hardware.hardware_keystore.xml"],
+}
+
+// Keymint hal service in vendor, enabled by vendor apex.
+// This service is disabled by default and does not package a VINTF fragment.
+// This service can be enabled at boot via vendor apex:
+// - at boot, mount a vendor apex for module `com.android.hardware.keymint`
+// - have the vendor init.rc file enable the service when the associated
+//   apex is selected
+// - have the vendor apex package the vintf fragment and the required permissions
+cc_binary {
+    name: "android.hardware.security.keymint-service.trusty_tee.cpp",
+    defaults: ["android.hardware.security.keymint-service.trusty.defaults"],
+    init_rc: ["keymint/android.hardware.security.keymint-service.trusty_tee.cpp.rc"],
+}
+
+// vintf fragment packaged in vendor apex
+prebuilt_etc {
+    name: "android.hardware.security.keymint-service.trusty.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "keymint/android.hardware.security.keymint-service.trusty.xml",
 }
 
 prebuilt_etc {
diff --git a/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty_tee.cpp.rc b/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty_tee.cpp.rc
new file mode 100644
index 0000000000..61ae8ae14e
--- /dev/null
+++ b/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty_tee.cpp.rc
@@ -0,0 +1,11 @@
+# service started when selecting `com.android.hardware.keymint.trusty_tee.cpp` vendor apex
+service vendor.keymint-service.trusty_tee.cpp \
+  /vendor/bin/hw/android.hardware.security.keymint-service.trusty_tee.cpp \
+    --dev ${ro.hardware.trusty_ipc_dev.keymint:-/dev/trusty-ipc-dev0}
+    disabled
+    class early_hal
+    user nobody
+    group drmrpc
+    # The keymint service is not allowed to restart.
+    # If it crashes, a device restart is required.
+    oneshot
diff --git a/trusty/keymint/Android.bp b/trusty/keymint/Android.bp
index 36efb1b892..80e58f979b 100644
--- a/trusty/keymint/Android.bp
+++ b/trusty/keymint/Android.bp
@@ -36,25 +36,67 @@ rust_defaults {
     prefer_rlib: true,
 }
 
+// keymint hal binary for keymint in Trusty TEE (legacy approach not using apex)
 rust_binary {
     name: "android.hardware.security.keymint-service.rust.trusty",
     vendor: true,
     defaults: ["android.hardware.security.keymint-service.rust.trusty.default"],
     init_rc: ["android.hardware.security.keymint-service.rust.trusty.rc"],
     vintf_fragments: ["android.hardware.security.keymint-service.rust.trusty.xml"],
-    required: select(release_flag("RELEASE_AIDL_USE_UNFROZEN"), {
-        true: ["android.hardware.hardware_keystore.xml"],
-        default: ["android.hardware.hardware_keystore_V3.xml"],
+    required: ["android.hardware.hardware_keystore.xml"],
+}
+
+// Keymint hal service in vendor, enabled by vendor apex.
+// This service is disabled by default and does not package a VINTF fragment.
+// This service can be enabled at boot via vendor apex:
+// - at boot, mount a vendor apex for module `com.android.hardware.keymint`
+// - have the vendor apex init.rc file to start the service when the apex is selected
+// - have the vendor apex package the vintf fragment
+rust_binary {
+    name: "android.hardware.security.keymint-service.trusty_tee",
+    vendor: true,
+    defaults: ["android.hardware.security.keymint-service.rust.trusty.default"],
+    init_rc: ["android.hardware.security.keymint-service.trusty_tee.rc"],
+    features: select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: ["nonsecure"],
+        default: [],
     }),
+    rustlibs: [
+        "libkmr_hal_nonsecure",
+    ],
 }
 
+// Keymint hal service in system_ext, interacting with the Trusty Security VM.
+// This service is disabled by default and does not package a VINTF fragment.
+// This service can be enabled at boot via vendor apex:
+// - at boot, mount a vendor apex for module `com.android.hardware.keymint`
+// - have the vendor apex init.rc file to start the service when the apex is selected
+// - have the vendor apex package the vintf fragment
 rust_binary {
-    name: "android.hardware.security.keymint-service.rust.trusty.system.nonsecure",
+    name: "android.hardware.security.keymint-service.trusty_system_vm",
     system_ext_specific: true,
     defaults: ["android.hardware.security.keymint-service.rust.trusty.default"],
-    init_rc: ["android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc"],
-    features: ["nonsecure"],
+    init_rc: ["android.hardware.security.keymint-service.trusty_system_vm.rc"],
+    features: select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: ["nonsecure"],
+        default: [],
+    }),
     rustlibs: [
         "libkmr_hal_nonsecure",
     ],
 }
+
+// vintf fragment packaged in vendor apex
+prebuilt_etc {
+    name: "android.hardware.security.keymint-service.rust.trusty.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "android.hardware.security.keymint-service.rust.trusty.xml",
+}
+
+prebuilt_etc {
+    name: "android.hardware.security.keymint-service.trusty_system_vm.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "android.hardware.security.keymint-service.trusty_system_vm.xml",
+}
diff --git a/trusty/keymint/android.hardware.hardware_keystore.rust.trusty-keymint.xml b/trusty/keymint/android.hardware.hardware_keystore.rust.trusty-keymint.xml
deleted file mode 100644
index cd656b2570..0000000000
--- a/trusty/keymint/android.hardware.hardware_keystore.rust.trusty-keymint.xml
+++ /dev/null
@@ -1,18 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2021 The Android Open Source Project
-
-    Licensed under the Apache License, Version 2.0 (the "License");
-    you may not use this file except in compliance with the License.
-    You may obtain a copy of the License at
-
-        http://www.apache.org/licenses/LICENSE-2.0
-
-    Unless required by applicable law or agreed to in writing, software
-    distributed under the License is distributed on an "AS IS" BASIS,
-    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-    See the License for the specific language governing permissions and
-    limitations under the License.
--->
-<permissions>
-  <feature name="android.hardware.hardware_keystore" version="300" />
-</permissions>
diff --git a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc b/trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.rc
similarity index 51%
rename from trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc
rename to trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.rc
index e5806510f3..2e8ad008c6 100644
--- a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc
+++ b/trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.rc
@@ -1,6 +1,7 @@
-service system.keymint.rust-trusty.nonsecure \
-  /system_ext/bin/hw/android.hardware.security.keymint-service.rust.trusty.system.nonsecure \
-  --dev ${system.keymint.trusty_ipc_dev:-/dev/trusty-ipc-dev0}
+# service started when selecting `com.android.hardware.keymint.trusty_system_vm` vendor apex
+service system.keymint-service.trusty_system_vm \
+  /system_ext/bin/hw/android.hardware.security.keymint-service.trusty_system_vm \
+  --dev ${system.keymint.trusty_ipc_dev}
     disabled
     user nobody
     group drmrpc
@@ -8,10 +9,9 @@ service system.keymint.rust-trusty.nonsecure \
     # If it crashes, a device restart is required.
     oneshot
 
-# Only starts the non-secure KeyMint HALs when the KeyMint VM feature is enabled
 # TODO(b/357821690): Start the KeyMint HALs when the KeyMint VM is ready once the Trusty VM
 # has a mechanism to notify the host.
-on late-fs && property:trusty.security_vm.keymint.enabled=1 && \
+on post-fs && property:trusty.security_vm.keymint.enabled=1 && \
    property:trusty.security_vm.vm_cid=*
     setprop system.keymint.trusty_ipc_dev VSOCK:${trusty.security_vm.vm_cid}:1
-    start system.keymint.rust-trusty.nonsecure
+    start system.keymint-service.trusty_system_vm
diff --git a/trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.xml b/trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.xml
new file mode 100644
index 0000000000..c35c843b6e
--- /dev/null
+++ b/trusty/keymint/android.hardware.security.keymint-service.trusty_system_vm.xml
@@ -0,0 +1,20 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.keymint</name>
+        <version>4</version>
+        <fqname>IKeyMintDevice/default</fqname>
+    </hal>
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.secureclock</name>
+        <fqname>ISecureClock/default</fqname>
+    </hal>
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.sharedsecret</name>
+        <fqname>ISharedSecret/default</fqname>
+    </hal>
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.keymint</name>
+        <version>3</version>
+        <fqname>IRemotelyProvisionedComponent/default</fqname>
+    </hal>
+</manifest>
diff --git a/trusty/keymint/android.hardware.security.keymint-service.trusty_tee.rc b/trusty/keymint/android.hardware.security.keymint-service.trusty_tee.rc
new file mode 100644
index 0000000000..694c9ce196
--- /dev/null
+++ b/trusty/keymint/android.hardware.security.keymint-service.trusty_tee.rc
@@ -0,0 +1,11 @@
+# service started when selecting `com.android.hardware.keymint.trusty_tee` vendor apex
+service vendor.keymint-service.trusty_tee \
+  /vendor/bin/hw/android.hardware.security.keymint-service.trusty_tee \
+    --dev ${ro.hardware.trusty_ipc_dev.keymint:-/dev/trusty-ipc-dev0}
+    disabled
+    class early_hal
+    user nobody
+    group drmrpc
+    # The keymint service is not allowed to restart.
+    # If it crashes, a device restart is required.
+    oneshot
diff --git a/trusty/keymint/trusty-keymint-apex.mk b/trusty/keymint/trusty-keymint-apex.mk
new file mode 100644
index 0000000000..7c44fbc7d3
--- /dev/null
+++ b/trusty/keymint/trusty-keymint-apex.mk
@@ -0,0 +1,29 @@
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
+# This makefile should be included by devices that choose to integrate
+# Keymint HAL via vendor apex
+
+PRODUCT_PACKAGES += \
+    android.hardware.security.keymint-service.trusty_tee.cpp \
+    android.hardware.security.keymint-service.trusty_tee \
+
+ifeq ($(findstring enabled, $(TRUSTY_SYSTEM_VM)),enabled)
+    PRODUCT_PACKAGES += \
+        android.hardware.security.keymint-service.trusty_system_vm \
+
+endif
diff --git a/trusty/keymint/trusty-keymint.mk b/trusty/keymint/trusty-keymint.mk
index d5791eab20..43cc186e70 100644
--- a/trusty/keymint/trusty-keymint.mk
+++ b/trusty/keymint/trusty-keymint.mk
@@ -21,19 +21,14 @@
 # Allow KeyMint HAL service implementation selection at build time. This must be
 # synchronized with the TA implementation included in Trusty. Possible values:
 #
-# - Rust implementation for Trusty VM (requires Trusty VM support):
+# - Rust implementation for Trusty TEE
 #   export TRUSTY_KEYMINT_IMPL=rust
-#   export TRUSTY_SYSTEM_VM=nonsecure
-# - Rust implementation for Trusty TEE (no Trusty VM support):
-#   export TRUSTY_KEYMINT_IMPL=rust
-# - C++ implementation (default): (any other value or unset TRUSTY_KEYMINT_IMPL)
+# - C++ implementation (default):
+#   any other value or unset TRUSTY_KEYMINT_IMPL
 
 ifeq ($(TRUSTY_KEYMINT_IMPL),rust)
-    ifeq ($(TRUSTY_SYSTEM_VM),nonsecure)
-        LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty.system.nonsecure
-    else
-        LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty
-    endif
+    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty
+
 else
     # Default to the C++ implementation
     LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.trusty
diff --git a/trusty/libtrusty/include/trusty/ipc.h b/trusty/libtrusty/include/trusty/ipc.h
index 04e84c6504..4a19692312 100644
--- a/trusty/libtrusty/include/trusty/ipc.h
+++ b/trusty/libtrusty/include/trusty/ipc.h
@@ -23,19 +23,21 @@
 
 /**
  * enum transfer_kind - How to send an fd to Trusty
- * @TRUSTY_SHARE:       Memory will be accessible by Linux and Trusty. On ARM it
- *                      will be mapped as nonsecure. Suitable for shared memory.
- *                      The paired fd must be a "dma_buf".
- * @TRUSTY_LEND:        Memory will be accessible only to Trusty. On ARM it will
- *                      be transitioned to "Secure" memory if Trusty is in
- *                      TrustZone. This transfer kind is suitable for donating
- *                      video buffers or other similar resources. The paired fd
- *                      may need to come from a platform-specific allocator for
- *                      memory that may be transitioned to "Secure".
- * @TRUSTY_SEND_SECURE: Send memory that is already "Secure". Memory will be
- *                      accessible only to Trusty. The paired fd may need to
- *                      come from a platform-specific allocator that returns
- *                      "Secure" buffers.
+ * @TRUSTY_SHARE:                Memory will be accessible by Linux and Trusty. On ARM it
+ *                               will be mapped as nonsecure. Suitable for shared memory.
+ *                               The paired fd must be a "dma_buf".
+ * @TRUSTY_LEND:                 Memory will be accessible only to Trusty. On ARM it will
+ *                               be transitioned to "Secure" memory if Trusty is in
+ *                               TrustZone. This transfer kind is suitable for donating
+ *                               video buffers or other similar resources. The paired fd
+ *                               may need to come from a platform-specific allocator for
+ *                               memory that may be transitioned to "Secure".
+ * @TRUSTY_SEND_SECURE:          Send memory that is already "Secure". Memory will be
+ *                               accessible only to Trusty. The paired fd may need to
+ *                               come from a platform-specific allocator that returns
+ *                               "Secure" buffers.
+ * @TRUSTY_SEND_SECURE_OR_SHARE: Acts as TRUSTY_SEND_SECURE if the memory is already
+ *                               "Secure" and as TRUSTY_SHARE otherwise.
  *
  * Describes how the user would like the resource in question to be sent to
  * Trusty. Options may be valid only for certain kinds of fds.
@@ -44,6 +46,7 @@ enum transfer_kind {
     TRUSTY_SHARE = 0,
     TRUSTY_LEND = 1,
     TRUSTY_SEND_SECURE = 2,
+    TRUSTY_SEND_SECURE_OR_SHARE = 3,
 };
 
 /**
diff --git a/trusty/storage/interface/include/trusty/interface/storage.h b/trusty/storage/interface/include/trusty/interface/storage.h
deleted file mode 100644
index 32916074bb..0000000000
--- a/trusty/storage/interface/include/trusty/interface/storage.h
+++ /dev/null
@@ -1,313 +0,0 @@
-/*
- * Copyright (C) 2015-2016 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *		http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#pragma once
-
-#include <stdint.h>
-
-/*
- * Storage port names
- * @STORAGE_CLIENT_TD_PORT:     Port used by clients that require tamper and
- *                              rollback detection.
- * @STORAGE_CLIENT_TDEA_PORT:   Port used by clients that require storage before
- *                              the non-secure os has booted.
- * @STORAGE_CLIENT_TP_PORT:     Port used by clients that require tamper proof
- *                              storage. Note that non-secure code can prevent
-                                read and write operations from succeeding, but
-                                it cannot modify on-disk data.
- * @STORAGE_DISK_PROXY_PORT:    Port used by non-secure proxy server
- */
-#define STORAGE_CLIENT_TD_PORT     "com.android.trusty.storage.client.td"
-#define STORAGE_CLIENT_TDEA_PORT   "com.android.trusty.storage.client.tdea"
-#define STORAGE_CLIENT_TP_PORT     "com.android.trusty.storage.client.tp"
-#define STORAGE_DISK_PROXY_PORT    "com.android.trusty.storage.proxy"
-
-enum storage_cmd {
-	STORAGE_REQ_SHIFT = 1,
-	STORAGE_RESP_BIT  = 1,
-
-	STORAGE_RESP_MSG_ERR   = STORAGE_RESP_BIT,
-
-	STORAGE_FILE_DELETE    = 1 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_OPEN      = 2 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_CLOSE     = 3 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_READ      = 4 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_WRITE     = 5 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_GET_SIZE  = 6 << STORAGE_REQ_SHIFT,
-	STORAGE_FILE_SET_SIZE  = 7 << STORAGE_REQ_SHIFT,
-
-	STORAGE_RPMB_SEND      = 8 << STORAGE_REQ_SHIFT,
-
-	/* transaction support */
-	STORAGE_END_TRANSACTION = 9 << STORAGE_REQ_SHIFT,
-
-	STORAGE_FILE_GET_MAX_SIZE = 12 << STORAGE_REQ_SHIFT,
-};
-
-/**
- * enum storage_err - error codes for storage protocol
- * @STORAGE_NO_ERROR:           all OK
- * @STORAGE_ERR_GENERIC:        unknown error. Can occur when there's an internal server
- *                              error, e.g. the server runs out of memory or is in a bad state.
- * @STORAGE_ERR_NOT_VALID:      input not valid. May occur if the arguments passed
- *                              into the command are not valid, for example if the file handle
- *                              passed in is not a valid one.
- * @STORAGE_ERR_UNIMPLEMENTED:  the command passed in is not recognized
- * @STORAGE_ERR_ACCESS:         the file is not accessible in the requested mode
- * @STORAGE_ERR_NOT_FOUND:      the file was not found
- * @STORAGE_ERR_EXIST           the file exists when it shouldn't as in with OPEN_CREATE | OPEN_EXCLUSIVE.
- * @STORAGE_ERR_TRANSACT        returned by various operations to indicate that current transaction
- *                              is in error state. Such state could be only cleared by sending
- *                              STORAGE_END_TRANSACTION message.
- * @STORAGE_ERR_SYNC_FAILURE    indicates that the current operation failed to sync
- *                              to disk. Only returned if STORAGE_MSG_FLAG_PRE_COMMIT or
- *                              STORAGE_MSG_FLAG_POST_COMMIT was set for the request.
- */
-enum storage_err {
-	STORAGE_NO_ERROR          = 0,
-	STORAGE_ERR_GENERIC       = 1,
-	STORAGE_ERR_NOT_VALID     = 2,
-	STORAGE_ERR_UNIMPLEMENTED = 3,
-	STORAGE_ERR_ACCESS        = 4,
-	STORAGE_ERR_NOT_FOUND     = 5,
-	STORAGE_ERR_EXIST         = 6,
-	STORAGE_ERR_TRANSACT      = 7,
-	STORAGE_ERR_SYNC_FAILURE  = 8,
-};
-
-/**
- * storage_delete_flag - flags for controlling delete semantics
- */
-enum storage_file_delete_flag {
-	STORAGE_FILE_DELETE_MASK = 0,
-};
-
-/**
- * storage_file_flag - Flags to control 'open' semantics.
- * @STORAGE_FILE_OPEN_CREATE:           if this file does not exist, create it.
- * @STORAGE_FILE_OPEN_CREATE_EXCLUSIVE: causes STORAGE_FILE_OPEN_CREATE to fail if the file
- *                                      already exists. Only meaningful if used in combination
- *                                      with STORAGE_FILE_OPEN_CREATE.
- * @STORAGE_FILE_OPEN_TRUNCATE:         if this file already exists, discard existing content
- *                                      and open it as a new file. No change in semantics if the
- *                                      file does not exist.
- * @STORAGE_FILE_OPEN_MASK:             mask for all open flags supported in current protocol.
- *                                      All other bits must be set to 0.
- */
-enum storage_file_open_flag {
-	STORAGE_FILE_OPEN_CREATE             = (1 << 0),
-	STORAGE_FILE_OPEN_CREATE_EXCLUSIVE   = (1 << 1),
-	STORAGE_FILE_OPEN_TRUNCATE           = (1 << 2),
-	STORAGE_FILE_OPEN_MASK               = STORAGE_FILE_OPEN_CREATE |
-					       STORAGE_FILE_OPEN_TRUNCATE |
-					       STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
-};
-
-/**
- * enum storage_msg_flag - protocol-level flags in struct storage_msg
- * @STORAGE_MSG_FLAG_BATCH:                 if set, command belongs to a batch transaction.
- *                                          No response will be sent by the server until
- *                                          it receives a command with this flag unset, at
- *                                          which point a cumulative result for all messages
- *                                          sent with STORAGE_MSG_FLAG_BATCH will be sent.
- *                                          This is only supported by the non-secure disk proxy
- *                                          server.
- * @STORAGE_MSG_FLAG_PRE_COMMIT:            if set, indicates that server need to commit
- *                                          pending changes before processing this message.
- * @STORAGE_MSG_FLAG_POST_COMMIT:           if set, indicates that server need to commit
- *                                          pending changes after processing this message.
- * @STORAGE_MSG_FLAG_TRANSACT_COMPLETE:     if set, indicates that server need to commit
- *                                          current transaction after processing this message.
- *                                          It is an alias for STORAGE_MSG_FLAG_POST_COMMIT.
- * @STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT: if set, indicates that server needs to ensure
- *                                          that there is not a pending checkpoint for
- *                                          userdata before processing this message.
- */
-enum storage_msg_flag {
-    STORAGE_MSG_FLAG_BATCH = 0x1,
-    STORAGE_MSG_FLAG_PRE_COMMIT = 0x2,
-    STORAGE_MSG_FLAG_POST_COMMIT = 0x4,
-    STORAGE_MSG_FLAG_TRANSACT_COMPLETE = STORAGE_MSG_FLAG_POST_COMMIT,
-    STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT = 0x8,
-};
-
-/*
- * The following declarations are the message-specific contents of
- * the 'payload' element inside struct storage_msg.
- */
-
-/**
- * struct storage_file_delete_req - request format for STORAGE_FILE_DELETE
- * @flags: currently unused, must be set to 0.
- * @name:  the name of the file
- */
-struct storage_file_delete_req {
-	uint32_t flags;
-	char name[0];
-};
-
-/**
- * struct storage_file_open_req - request format for STORAGE_FILE_OPEN
- * @flags: any of enum storage_file_flag or'ed together
- * @name:  the name of the file
- */
-struct storage_file_open_req {
-	uint32_t flags;
-	char     name[0];
-};
-
-/**
- * struct storage_file_open_resp - response format for STORAGE_FILE_OPEN
- * @handle: opaque handle to the opened file. Only present on success.
- */
-struct storage_file_open_resp {
-	uint32_t handle;
-};
-
-/**
- * struct storage_file_close_req - request format for STORAGE_FILE_CLOSE
- * @handle: the handle for the file to close
- */
-struct storage_file_close_req {
-	uint32_t handle;
-};
-
-/**
- * struct storage_file_get_max_size_req - request format for
- *                                        STORAGE_FILE_GET_MAX_SIZE
- * @handle: the handle for the file whose max size is requested
- */
-struct storage_file_get_max_size_req {
-	uint32_t handle;
-};
-
-/**
- * struct storage_file_get_max_size_resp - response format for
- *                                         STORAGE_FILE_GET_MAX_SIZE
- * @max_size:   the maximum size of the file
- */
-struct storage_file_get_max_size_resp {
-	uint64_t max_size;
-};
-
-/**
- * struct storage_file_read_req - request format for STORAGE_FILE_READ
- * @handle: the handle for the file from which to read
- * @size:   the quantity of bytes to read from the file
- * @offset: the offset in the file from whence to read
- */
-struct storage_file_read_req {
-	uint32_t handle;
-	uint32_t size;
-	uint64_t offset;
-};
-
-/**
- * struct storage_file_read_resp - response format for STORAGE_FILE_READ
- * @data: beginning of data retrieved from file
- */
-struct storage_file_read_resp {
-	uint8_t data[0];
-};
-
-/**
- * struct storage_file_write_req - request format for STORAGE_FILE_WRITE
- * @handle:     the handle for the file to write to
- * @offset:     the offset in the file from whence to write
- * @__reserved: unused, must be set to 0.
- * @data:       beginning of the data to be written
- */
-struct storage_file_write_req {
-	uint64_t offset;
-	uint32_t handle;
-	uint32_t __reserved;
-	uint8_t  data[0];
-};
-
-/**
- * struct storage_file_get_size_req - request format for STORAGE_FILE_GET_SIZE
- * @handle: handle for which the size is requested
- */
-struct storage_file_get_size_req {
-	uint32_t handle;
-};
-
-/**
- * struct storage_file_get_size_resp - response format for STORAGE_FILE_GET_SIZE
- * @size:   the size of the file
- */
-struct storage_file_get_size_resp {
-	uint64_t size;
-};
-
-/**
- * struct storage_file_set_size_req - request format for STORAGE_FILE_SET_SIZE
- * @handle: the file handle
- * @size:   the desired size of the file
- */
-struct storage_file_set_size_req {
-	uint64_t size;
-	uint32_t handle;
-};
-
-/**
- * struct storage_rpmb_send_req - request format for STORAGE_RPMB_SEND
- * @reliable_write_size:        size in bytes of reliable write region
- * @write_size:                 size in bytes of write region
- * @read_size:                  number of bytes to read for a read request
- * @__reserved:                 unused, must be set to 0
- * @payload:                    start of reliable write region, followed by
- *                              write region.
- *
- * Only used in proxy<->server interface.
- */
-struct storage_rpmb_send_req {
-	uint32_t reliable_write_size;
-	uint32_t write_size;
-	uint32_t read_size;
-	uint32_t __reserved;
-	uint8_t  payload[0];
-};
-
-/**
- * struct storage_rpmb_send_resp: response type for STORAGE_RPMB_SEND
- * @data: the data frames frames retrieved from the MMC.
- */
-struct storage_rpmb_send_resp {
-	uint8_t data[0];
-};
-
-/**
- * struct storage_msg - generic req/resp format for all storage commands
- * @cmd:        one of enum storage_cmd
- * @op_id:      client chosen operation identifier for an instance
- *              of a command or atomic grouping of commands (transaction).
- * @flags:      one or many of enum storage_msg_flag or'ed together.
- * @size:       total size of the message including this header
- * @result:     one of enum storage_err
- * @__reserved: unused, must be set to 0.
- * @payload:    beginning of command specific message format
- */
-struct storage_msg {
-	uint32_t cmd;
-	uint32_t op_id;
-	uint32_t flags;
-	uint32_t size;
-	int32_t  result;
-	uint32_t __reserved;
-	uint8_t  payload[0];
-};
-
diff --git a/trusty/storage/lib/include/trusty/lib/storage.h b/trusty/storage/lib/include/trusty/lib/storage.h
index b8ddf67d87..4335619827 100644
--- a/trusty/storage/lib/include/trusty/lib/storage.h
+++ b/trusty/storage/lib/include/trusty/lib/storage.h
@@ -16,8 +16,8 @@
 
 #pragma once
 
+#include <interface/storage/storage.h>
 #include <stdint.h>
-#include <trusty/interface/storage.h>
 
 #define STORAGE_MAX_NAME_LENGTH_BYTES 159
 
diff --git a/trusty/storage/proxy/ipc.h b/trusty/storage/proxy/ipc.h
index 2e366bbb99..020f121619 100644
--- a/trusty/storage/proxy/ipc.h
+++ b/trusty/storage/proxy/ipc.h
@@ -15,8 +15,8 @@
  */
 #pragma once
 
+#include <interface/storage/storage.h>
 #include <stdint.h>
-#include <trusty/interface/storage.h>
 
 int ipc_connect(const char *device, const char *service_name);
 void ipc_disconnect(void);
diff --git a/trusty/storage/proxy/rpmb.h b/trusty/storage/proxy/rpmb.h
index 04bdf9a6a6..1761eecc00 100644
--- a/trusty/storage/proxy/rpmb.h
+++ b/trusty/storage/proxy/rpmb.h
@@ -15,8 +15,8 @@
  */
 #pragma once
 
+#include <interface/storage/storage.h>
 #include <stdint.h>
-#include <trusty/interface/storage.h>
 
 #include "watchdog.h"
 
diff --git a/trusty/storage/proxy/storage.h b/trusty/storage/proxy/storage.h
index 6dbfe37060..f46f78532d 100644
--- a/trusty/storage/proxy/storage.h
+++ b/trusty/storage/proxy/storage.h
@@ -15,8 +15,8 @@
  */
 #pragma once
 
+#include <interface/storage/storage.h>
 #include <stdint.h>
-#include <trusty/interface/storage.h>
 
 /* Defined in watchdog.h */
 struct watcher;
diff --git a/trusty/storage/proxy/watchdog.cpp b/trusty/storage/proxy/watchdog.cpp
index 6c09e26396..f042fdcab4 100644
--- a/trusty/storage/proxy/watchdog.cpp
+++ b/trusty/storage/proxy/watchdog.cpp
@@ -18,6 +18,7 @@
 
 #include <chrono>
 #include <cstdint>
+#include <mutex>
 #include <optional>
 #include <thread>
 #include <vector>
diff --git a/trusty/sysprops/Android.bp b/trusty/sysprops/Android.bp
new file mode 100644
index 0000000000..ec27f517fe
--- /dev/null
+++ b/trusty/sysprops/Android.bp
@@ -0,0 +1,15 @@
+sysprop_library {
+    name: "trusty-properties",
+    srcs: ["android/sysprop/trusty/security_vm.sysprop"],
+    property_owner: "Platform",
+    api_packages: ["android.sysprop.trusty"],
+    apex_available: [
+        "//apex_available:platform",
+    ],
+}
+
+rust_binary {
+    name: "trusty-properties-example",
+    srcs: ["example.rs"],
+    rustlibs: ["libtrusty_properties_rust"],
+}
diff --git a/trusty/sysprops/android/sysprop/trusty/security_vm.sysprop b/trusty/sysprops/android/sysprop/trusty/security_vm.sysprop
new file mode 100644
index 0000000000..a079ecf1e3
--- /dev/null
+++ b/trusty/sysprops/android/sysprop/trusty/security_vm.sysprop
@@ -0,0 +1,67 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+
+# This module accesses properties regarding the Trusty VM that runs apps
+# used to provide security for the system, such as Keymint or Gatekeeper.
+
+module: "android.sysprop.trusty.security_vm"
+owner: Platform
+
+# The default Context Identifier to connect to Trusty over vsock.
+prop {
+    api_name: "vm_cid"
+    prop_name: "trusty.security_vm.vm_cid"
+    type: Integer
+    scope: Internal
+    access: Readonly
+}
+
+# Signals when a nonsecure VM is ready.
+#
+# This is used to launch dependent HALs.
+#
+# Trusty security VMs come in two flavors: non-secure and secure.
+#
+# 1. Non-secure VMs run on emulated environments like Cuttlefish, which lack
+#    pVM firmware and TEE support. Consequently, KeyMint's root-of-trust data
+#    is passed into the VM from the host's HAL, and an RPMB proxy provides
+#    secure storage.
+# 2. Secure VMs run on physical devices. Here, pVM firmware handles the
+#    transfer of root-of-trust data via DeviceTree, and a TEE provides secure
+#    storage.
+prop {
+    api_name: "nonsecure_vm_ready"
+    prop_name: "trusty.security_vm.nonsecure_vm_ready"
+    type: Boolean
+    scope: Internal
+    access: Readonly
+}
+
+# The Trusty Security VM is enabled.
+prop {
+    api_name: "enabled"
+    prop_name: "trusty.security_vm.enabled"
+    type: Boolean
+    scope: Public
+    access: Readonly
+}
+
+# KeyMint is enabled in the Trusty Security VM.
+prop {
+    api_name: "keymint_enabled"
+    prop_name: "trusty.security_vm.keymint.enabled"
+    type: Boolean
+    scope: Public
+    access: Readonly
+}
diff --git a/trusty/sysprops/api/trusty-properties-current.txt b/trusty/sysprops/api/trusty-properties-current.txt
new file mode 100644
index 0000000000..aa792fcef2
--- /dev/null
+++ b/trusty/sysprops/api/trusty-properties-current.txt
@@ -0,0 +1,11 @@
+props {
+  module: "android.sysprop.trusty.security_vm"
+  prop {
+    api_name: "enabled"
+    prop_name: "trusty.security_vm.enabled"
+  }
+  prop {
+    api_name: "keymint_enabled"
+    prop_name: "trusty.security_vm.keymint.enabled"
+  }
+}
diff --git a/trusty/sysprops/api/trusty-properties-latest.txt b/trusty/sysprops/api/trusty-properties-latest.txt
new file mode 100644
index 0000000000..aa792fcef2
--- /dev/null
+++ b/trusty/sysprops/api/trusty-properties-latest.txt
@@ -0,0 +1,11 @@
+props {
+  module: "android.sysprop.trusty.security_vm"
+  prop {
+    api_name: "enabled"
+    prop_name: "trusty.security_vm.enabled"
+  }
+  prop {
+    api_name: "keymint_enabled"
+    prop_name: "trusty.security_vm.keymint.enabled"
+  }
+}
diff --git a/trusty/sysprops/example.rs b/trusty/sysprops/example.rs
new file mode 100644
index 0000000000..f21e779e8a
--- /dev/null
+++ b/trusty/sysprops/example.rs
@@ -0,0 +1,11 @@
+//! Example showing how to access the `trusty.security_vm.vm_cid` system property with Rust.
+
+use trusty_properties::security_vm;
+
+fn main() {
+    match security_vm::vm_cid() {
+        Ok(Some(cid)) => println!("CID: {cid}"),
+        Ok(None) => println!("CID property not set"),
+        Err(e) => println!("Error: {e:?}"),
+    }
+}
diff --git a/trusty/test/driver/Android.bp b/trusty/test/driver/Android.bp
index b813a04ccb..3faa878a2e 100644
--- a/trusty/test/driver/Android.bp
+++ b/trusty/test/driver/Android.bp
@@ -23,10 +23,4 @@ python_test {
         "**/*.py",
     ],
     test_suites: ["general-tests"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-            enabled: true,
-        },
-    },
 }
diff --git a/trusty/trusty-base.mk b/trusty/trusty-base.mk
index 9d810dcb7f..fcde61d68e 100644
--- a/trusty/trusty-base.mk
+++ b/trusty/trusty-base.mk
@@ -22,7 +22,13 @@
 # For gatekeeper, we include the generic -service and -impl to use legacy
 # HAL loading of gatekeeper.trusty.
 
-$(call inherit-product, system/core/trusty/keymint/trusty-keymint.mk)
+ifeq ($(KEYMINT_HAL_VENDOR_APEX_SELECT),true)
+    $(call inherit-product, system/core/trusty/keymint/trusty-keymint-apex.mk)
+
+else
+    $(call inherit-product, system/core/trusty/keymint/trusty-keymint.mk)
+
+endif
 
 ifeq ($(SECRETKEEPER_ENABLED),true)
     LOCAL_SECRETKEEPER_PRODUCT_PACKAGE := android.hardware.security.secretkeeper.trusty
diff --git a/trusty/trusty-storage.mk b/trusty/trusty-storage.mk
index 3f263167ca..d2bc0b18c2 100644
--- a/trusty/trusty-storage.mk
+++ b/trusty/trusty-storage.mk
@@ -14,5 +14,30 @@
 # limitations under the License.
 #
 
+#
+# Trusty TEE packages
+#
+
+# below statement adds the singleton storage daemon in vendor,
+# storageproxyd vendor interacts with the Secure Storage TA in the
+# Trustzone Trusty TEE
 PRODUCT_PACKAGES += \
 	storageproxyd \
+
+#
+# Trusty VM packages
+#
+ifeq ($(TRUSTY_SYSTEM_VM),enabled_with_placeholder_trusted_hal)
+
+# with placeholder Trusted HALs, the Trusty VMs are standalone (i.e. they don't access
+# remote Trusted HAL services) and thus require their own secure storage.
+# (one secure storage emulation for each Trusty VM - security VM, test VM and WV VM)
+# in secure mode, the secure storage is the services by Trusty in Trustzone
+# and requires a single storageproxyd in vendor.
+PRODUCT_PACKAGES += \
+	storageproxyd.system \
+	rpmb_dev.test.system \
+	rpmb_dev.system \
+	rpmb_dev.wv.system \
+
+endif
diff --git a/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc b/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc
index 2127798e1c..c85dd12f26 100644
--- a/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc
+++ b/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc
@@ -1,11 +1,15 @@
-service trusty_test_vm /apex/com.android.virt/bin/vm run \
-    /data/local/tmp/TrustyTestVM_UnitTests/trusty-test_vm-config.json
+service storageproxyd_test_vm /system_ext/bin/storageproxyd.system \
+        -d VSOCK:${trusty.test_vm.vm_cid}:1 \
+        -r /dev/socket/rpmb_mock_test_system \
+        -p /data/secure_storage_test_system \
+        -t sock
     disabled
+    class hal
     user system
     group system
 
-service storageproxyd_test_system /system_ext/bin/storageproxyd.system \
-        -d VSOCK:${trusty.test_vm.vm_cid}:1 \
+service storageproxyd_test_vm_os /system_ext/bin/storageproxyd.system \
+        -d VSOCK:${trusty.test_vm_os.vm_cid}:1 \
         -r /dev/socket/rpmb_mock_test_system \
         -p /data/secure_storage_test_system \
         -t sock
diff --git a/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc b/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc
index 3e7f8b44fc..ac18f8134d 100644
--- a/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc
+++ b/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc
@@ -1,10 +1,9 @@
 service storageproxyd_wv_system /system_ext/bin/storageproxyd.system \
-        -d ${storageproxyd_wv_system.trusty_ipc_dev:-/dev/trusty-ipc-dev0} \
+        -d VSOCK:${trusty.widevine_vm.vm_cid}:1 \
         -r /dev/socket/rpmb_mock_wv_system \
         -p /data/secure_storage_wv_system \
         -t sock
     disabled
-    class hal
     user system
     group system
 
@@ -23,20 +22,8 @@ service rpmb_mock_wv_system /system_ext/bin/rpmb_dev.wv.system \
     group system
     socket rpmb_mock_wv_system stream 660 system system
 
-# storageproxyd
-on boot && \
-    property:trusty.widevine_vm.nonsecure_vm_ready=1 && \
-    property:storageproxyd_wv_system.trusty_ipc_dev=*
-    wait /dev/socket/rpmb_mock_wv_system
-    enable storageproxyd_wv_system
-
-
 # RPMB Mock
-on early-boot && \
-    property:ro.hardware.security.trusty.widevine_vm.system=1 && \
-    property:trusty.widevine_vm.vm_cid=* && \
-    property:ro.boot.vendor.apex.com.android.services.widevine=\
-com.android.services.widevine.cf_guest_trusty_nonsecure
+on early-boot
     # Create a persistent location for the RPMB data
     # (work around lack of RPMb block device on CF).
     # file contexts secure_storage_rpmb_system_file
@@ -57,6 +44,11 @@ com.android.services.widevine.cf_guest_trusty_nonsecure
     symlink /mnt/secure_storage_persist_wv_system/persist \
             /data/secure_storage_wv_system/persist
     chown root system /data/secure_storage_wv_system/persist
-    setprop storageproxyd_wv_system.trusty_ipc_dev VSOCK:${trusty.widevine_vm.vm_cid}:1
     exec_start rpmb_mock_init_wv_system
     start rpmb_mock_wv_system
+
+on post-fs-data && \
+    property:trusty.widevine_vm.nonsecure_vm_ready=1 && \
+    property:trusty.widevine_vm.vm_cid=*
+    start storageproxyd_wv_system
+
diff --git a/trusty/utils/trusty-ut-ctrl/Android.bp b/trusty/utils/trusty-ut-ctrl/Android.bp
index c255614b0c..dbd8016496 100644
--- a/trusty/utils/trusty-ut-ctrl/Android.bp
+++ b/trusty/utils/trusty-ut-ctrl/Android.bp
@@ -39,8 +39,8 @@ cc_binary {
     vendor: true,
 }
 
-cc_binary {
+cc_test {
     name: "trusty-ut-ctrl.system",
     defaults: ["trusty-ut-ctrl.defaults"],
-    system_ext_specific: true,
+    gtest: false,
 }
```

