```diff
diff --git a/aconfigd/Android.bp b/aconfigd/Android.bp
index 501e615..34536f7 100644
--- a/aconfigd/Android.bp
+++ b/aconfigd/Android.bp
@@ -1,28 +1,31 @@
 cc_binary {
-  name: "aconfigd",
-  srcs: [
-    "aconfigd.cpp",
-    "aconfigd.proto",
-    "aconfigd_main.cpp",
-    "aconfigd_util.cpp",
-    "storage_files.cpp",
-    "storage_files_manager.cpp"
-  ],
-  static_libs: [
-    "libaconfig_new_storage_flags",
-    "libaconfig_storage_file_cc",
-    "libaconfig_storage_read_api_cc",
-    "libaconfig_storage_write_api_cc",
-  ],
-  shared_libs: [
-    "libcutils",
-    "libprotobuf-cpp-lite",
-    "libbase",
-    "liblog",
-    "libcrypto",
-  ],
-  init_rc: ["aconfigd.rc"],
-  ldflags: ["-Wl,--allow-multiple-definition"],
+    name: "aconfigd",
+    defaults: [
+        "aconfig_lib_cc_shared_link.defaults",
+    ],
+    srcs: [
+        "aconfigd.cpp",
+        "aconfigd.proto",
+        "aconfigd_main.cpp",
+        "aconfigd_util.cpp",
+        "storage_files.cpp",
+        "storage_files_manager.cpp",
+    ],
+    static_libs: [
+        "libaconfig_storage_file_cc",
+        "libaconfig_new_storage_flags",
+        "libaconfig_storage_read_api_cc",
+        "libaconfig_storage_write_api_cc",
+    ],
+    shared_libs: [
+        "libcutils",
+        "libprotobuf-cpp-lite",
+        "libbase",
+        "liblog",
+        "libcrypto",
+        "server_configurable_flags",
+    ],
+    init_rc: ["aconfigd.rc"],
 }
 
 aconfig_declarations {
@@ -62,8 +65,44 @@ java_library {
     ],
 }
 
+rust_protobuf {
+    name: "libaconfigd_rust_proto",
+    crate_name: "aconfigd_rust_proto",
+    source_stem: "aconfigd_rust_proto_source",
+    protos: [
+        "aconfigd.proto",
+    ],
+    host_supported: true,
+}
+
+rust_defaults {
+    name: "aconfigd_protos.defaults",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libaconfigd_rust_proto",
+        "libanyhow",
+        "libprotobuf",
+    ],
+    proc_macros: [
+        "libpaste",
+    ],
+}
+
+rust_library {
+    name: "libaconfigd_protos",
+    crate_name: "aconfigd_protos",
+    defaults: ["aconfigd_protos.defaults"],
+    host_supported: true,
+}
+
 cc_test {
     name: "aconfigd_test",
+    defaults: [
+        "aconfig_lib_cc_shared_link.defaults",
+    ],
     team: "trendy_team_android_core_experiments",
     srcs: [
         "aconfigd_test.cpp",
@@ -74,8 +113,10 @@ cc_test {
         "aconfigd.proto",
     ],
     static_libs: [
+        "libflagtest",
         "libgmock",
         "libaconfig_storage_file_cc",
+        "libaconfig_new_storage_flags",
         "libaconfig_storage_read_api_cc",
         "libaconfig_storage_write_api_cc",
     ],
@@ -84,6 +125,8 @@ cc_test {
         "libbase",
         "liblog",
         "libcrypto",
+        "server_configurable_flags",
+        "libaconfig_flags_cc",
     ],
     data: [
         "tests/package.map",
@@ -97,7 +140,6 @@ cc_test {
         "device-tests",
         "general-tests",
     ],
-    ldflags: ["-Wl,--allow-multiple-definition"],
 }
 
 cc_test {
diff --git a/aconfigd/Cargo.toml b/aconfigd/Cargo.toml
new file mode 100644
index 0000000..6aa352e
--- /dev/null
+++ b/aconfigd/Cargo.toml
@@ -0,0 +1,18 @@
+[package]
+name = "aconfigd_protos"
+version = "0.1.0"
+edition = "2021"
+build = "build.rs"
+
+[features]
+default = ["cargo"]
+cargo = []
+
+[dependencies]
+anyhow = "1.0.69"
+paste = "1.0.11"
+protobuf = "3.2.0"
+
+[build-dependencies]
+protobuf-codegen = "3.2.0"
+
diff --git a/aconfigd/aconfigd.cpp b/aconfigd/aconfigd.cpp
index cc36a59..fbecd9a 100644
--- a/aconfigd/aconfigd.cpp
+++ b/aconfigd/aconfigd.cpp
@@ -35,10 +35,9 @@ namespace aconfigd {
 Result<void> Aconfigd::HandleFlagOverride(
     const StorageRequestMessage::FlagOverrideMessage& msg,
     StorageReturnMessage& return_msg) {
-  auto result = storage_files_manager_->UpdateFlagValue(msg.package_name(),
-                                                      msg.flag_name(),
-                                                      msg.flag_value(),
-                                                      msg.is_local());
+  auto result = storage_files_manager_->UpdateFlagValue(
+      msg.package_name(), msg.flag_name(), msg.flag_value(),
+      msg.override_type());
   RETURN_IF_ERROR(result, "Failed to set flag override");
   return_msg.mutable_flag_override_message();
   return {};
@@ -176,50 +175,16 @@ Result<std::vector<FlagOverride>> Aconfigd::ReadOTAFlagOverridesToApply() {
       for (const auto& entry : ota_flags_pb->overrides()) {
         ota_flags.push_back(entry);
       }
-    }
-  }
-  return ota_flags;
-}
-
-/// Write remaining OTA flag overrides back to pb file
-Result<void> Aconfigd::WriteRemainingOTAOverrides(
-    const std::vector<FlagOverride>& ota_flags) {
-  auto ota_flags_pb_file = root_dir_ + "/flags/ota.pb";
-
-  if (!ota_flags.empty()) {
-    auto ota_flags_pb = StorageRequestMessage::OTAFlagStagingMessage();
-    auto build_id = GetProperty("ro.build.fingerprint", "");
-    ota_flags_pb.set_build_id(build_id);
-    for (auto const& entry : ota_flags) {
-      auto* flag = ota_flags_pb.add_overrides();
-      flag->set_package_name(entry.package_name());
-      flag->set_flag_name(entry.flag_name());
-      flag->set_flag_value(entry.flag_value());
-    }
-    auto result = WritePbToFile<StorageRequestMessage::OTAFlagStagingMessage>(
-        ota_flags_pb, ota_flags_pb_file);
-    RETURN_IF_ERROR(result, "Failed to write remaining staged OTA flags");
-  } else {
-    if (FileExists(ota_flags_pb_file)) {
+      // delete staged ota flags file if it matches current build id, so that
+      // it will not be reapplied in the future boots
       unlink(ota_flags_pb_file.c_str());
     }
   }
-
-  return {};
+  return ota_flags;
 }
 
 /// Initialize in memory aconfig storage records
 Result<void> Aconfigd::InitializeInMemoryStorageRecords() {
-  // remove old records pb
-  if (FileExists("/metadata/aconfig/persistent_storage_file_records.pb")) {
-    unlink("/metadata/aconfig/persistent_storage_file_records.pb");
-  }
-
-  // remove old records pb
-  if (FileExists("/metadata/aconfig/persist_storage_file_records.pb")) {
-    unlink("/metadata/aconfig/persist_storage_file_records.pb");
-  }
-
   auto records_pb = ReadPbFromFile<PersistStorageRecords>(persist_storage_records_);
   RETURN_IF_ERROR(records_pb, "Unable to read persistent storage records");
   for (const auto& entry : records_pb->records()) {
@@ -240,13 +205,12 @@ Result<void> Aconfigd::InitializePlatformStorage() {
   RETURN_IF_ERROR(ota_flags, "Failed to get remaining staged OTA flags");
   bool apply_ota_flag = !(ota_flags->empty());
 
-  auto value_files = std::vector<std::pair<std::string, std::string>>{
+  auto partitions = std::vector<std::pair<std::string, std::string>>{
     {"system", "/system/etc/aconfig"},
-    {"system_ext", "/system_ext/etc/aconfig"},
     {"vendor", "/vendor/etc/aconfig"},
     {"product", "/product/etc/aconfig"}};
 
-  for (auto const& [container, storage_dir] : value_files) {
+  for (auto const& [container, storage_dir] : partitions) {
     auto package_file = std::string(storage_dir) + "/package.map";
     auto flag_file = std::string(storage_dir) + "/flag.map";
     auto value_file = std::string(storage_dir) + "/flag.val";
@@ -275,9 +239,32 @@ Result<void> Aconfigd::InitializePlatformStorage() {
                     + container);
   }
 
-  if (apply_ota_flag) {
-    auto result = WriteRemainingOTAOverrides(*ota_flags);
-    RETURN_IF_ERROR(result, "Failed to write remaining staged OTA flags");
+  // TODO remove this logic once new storage launch complete
+  // if flag enable_only_new_storage is true, writes a marker file
+  {
+    auto flags = storage_files_manager_->ListFlagsInPackage("com.android.aconfig.flags");
+    RETURN_IF_ERROR(flags, "Failed to list flags");
+    bool enable_only_new_storage = false;
+    for (const auto& flag : *flags) {
+      if (flag.flag_name == "enable_only_new_storage") {
+        enable_only_new_storage = (flag.boot_flag_value == "true");
+        break;
+      }
+    }
+    auto marker_file = std::string("/metadata/aconfig/boot/enable_only_new_storage");
+    if (enable_only_new_storage) {
+      if (!FileExists(marker_file)) {
+        int fd = open(marker_file.c_str(), O_CREAT, 0644);
+        if (fd == -1) {
+          return ErrnoError() << "failed to create marker file";
+        }
+        close(fd);
+      }
+    } else {
+      if (FileExists(marker_file)) {
+        unlink(marker_file.c_str());
+      }
+    }
   }
 
   return {};
@@ -288,10 +275,6 @@ Result<void> Aconfigd::InitializeMainlineStorage() {
   auto init_result = InitializeInMemoryStorageRecords();
   RETURN_IF_ERROR(init_result, "Failed to init from persist stoage records");
 
-  auto ota_flags = ReadOTAFlagOverridesToApply();
-  RETURN_IF_ERROR(ota_flags, "Failed to get remaining staged OTA flags");
-  bool apply_ota_flag = !(ota_flags->empty());
-
   auto apex_dir = std::unique_ptr<DIR, int (*)(DIR*)>(opendir("/apex"), closedir);
   if (!apex_dir) {
     return {};
@@ -320,12 +303,6 @@ Result<void> Aconfigd::InitializeMainlineStorage() {
     RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                     + container);
 
-    if (apply_ota_flag) {
-      ota_flags = storage_files_manager_->ApplyOTAFlagsForContainer(
-          container, *ota_flags);
-      RETURN_IF_ERROR(ota_flags, "Failed to apply staged OTA flags");
-    }
-
     auto write_result = storage_files_manager_->WritePersistStorageRecordsToFile(
         persist_storage_records_);
     RETURN_IF_ERROR(write_result, "Failed to write to persist storage records");
@@ -335,11 +312,6 @@ Result<void> Aconfigd::InitializeMainlineStorage() {
                     + container);
   }
 
-  if (apply_ota_flag) {
-    auto result = WriteRemainingOTAOverrides(*ota_flags);
-    RETURN_IF_ERROR(result, "Failed to write remaining staged OTA flags");
-  }
-
   return {};
 }
 
@@ -359,8 +331,8 @@ Result<void> Aconfigd::HandleSocketRequest(const StorageRequestMessage& message,
     }
     case StorageRequestMessage::kFlagOverrideMessage: {
       auto msg = message.flag_override_message();
-      LOG(INFO) << "received a" << (msg.is_local() ? " local " : " server ")
-                << "flag override request for " << msg.package_name() << "/"
+      LOG(INFO) << "received a '" << OverrideTypeToStr(msg.override_type())
+                << "' flag override request for " << msg.package_name() << "/"
                 << msg.flag_name() << " to " << msg.flag_value();
       result = HandleFlagOverride(msg, return_message);
       break;
diff --git a/aconfigd/aconfigd.h b/aconfigd/aconfigd.h
index 5b9fa57..5f69454 100644
--- a/aconfigd/aconfigd.h
+++ b/aconfigd/aconfigd.h
@@ -115,10 +115,6 @@ namespace android {
     /// Read OTA flag overrides to be applied for current build
     base::Result<std::vector<FlagOverride>> ReadOTAFlagOverridesToApply();
 
-    /// Write remaining OTA flag overrides back to pb file
-    base::Result<void> WriteRemainingOTAOverrides(
-        const std::vector<FlagOverride>& ota_flags);
-
     private:
 
     /// root storage dir
diff --git a/aconfigd/aconfigd.proto b/aconfigd/aconfigd.proto
index 74c2f95..aa6a6f7 100644
--- a/aconfigd/aconfigd.proto
+++ b/aconfigd/aconfigd.proto
@@ -51,12 +51,18 @@ message StorageRequestMessage {
     optional string flag_value = 4;
   }
 
+  enum FlagOverrideType {
+    LOCAL_IMMEDIATE = 1;
+    LOCAL_ON_REBOOT = 2;
+    SERVER_ON_REBOOT = 3;
+  }
+
   // request persistent flag value override
   message FlagOverrideMessage {
     optional string package_name = 1;
     optional string flag_name = 2;
     optional string flag_value = 3;
-    optional bool is_local = 4;
+    optional FlagOverrideType override_type = 4;
   }
 
   // request to stage ota flags
@@ -130,6 +136,7 @@ message StorageReturnMessage {
     optional bool has_server_override = 7;
     optional bool is_readwrite = 8;
     optional bool has_local_override = 9;
+    optional string container = 10;
   }
 
   message RemoveLocalOverrideReturnMessage {}
diff --git a/aconfigd/aconfigd_test.cpp b/aconfigd/aconfigd_test.cpp
index 9152891..43220ef 100644
--- a/aconfigd/aconfigd_test.cpp
+++ b/aconfigd/aconfigd_test.cpp
@@ -14,14 +14,19 @@
  * limitations under the License.
  */
 
-#include <sys/stat.h>
-#include <gtest/gtest.h>
+#include "aconfigd.h"
+
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <flag_macros.h>
+#include <gtest/gtest.h>
+#include <sys/stat.h>
 
-#include <aconfigd.pb.h>
 #include "aconfigd_util.h"
-#include "aconfigd.h"
+#include "com_android_aconfig_new_storage.h"
+
+#define ACONFIGD_NS com::android::aconfig_new_storage
 
 namespace android {
 namespace aconfigd {
@@ -108,13 +113,24 @@ class AconfigdTest : public ::testing::Test {
   StorageRequestMessage flag_override_message(const std::string& package,
                                               const std::string& flag,
                                               const std::string& value,
-                                              bool is_local) {
+                                              bool is_local,
+                                              bool is_immediate) {
     auto message = StorageRequestMessage();
     auto* msg = message.mutable_flag_override_message();
+
+    StorageRequestMessage::FlagOverrideType override_type;
+    if (is_local && is_immediate) {
+      override_type = StorageRequestMessage::LOCAL_IMMEDIATE;
+    } else if (is_local && !is_immediate) {
+      override_type = StorageRequestMessage::LOCAL_ON_REBOOT;
+    } else {
+      override_type = StorageRequestMessage::SERVER_ON_REBOOT;
+    }
+
     msg->set_package_name(package);
     msg->set_flag_name(flag);
     msg->set_flag_value(value);
-    msg->set_is_local(is_local);
+    msg->set_override_type(override_type);
     return message;
   }
 
@@ -307,13 +323,12 @@ TEST_F(AconfigdTest, init_platform_storage_fresh) {
   auto init_result = a_mock.aconfigd.InitializePlatformStorage();
   ASSERT_TRUE(init_result.ok()) << init_result.error();
 
-  auto platform_aconfig_dirs = std::vector<std::pair<std::string, std::string>>{
+  auto partitions = std::vector<std::pair<std::string, std::string>>{
     {"system", "/system/etc/aconfig"},
-    {"system_ext", "/system_ext/etc/aconfig"},
     {"vendor", "/vendor/etc/aconfig"},
     {"product", "/product/etc/aconfig"}};
 
-  for (auto const& [container, storage_dir] : platform_aconfig_dirs) {
+  for (auto const& [container, storage_dir] : partitions) {
     auto package_map = std::string(storage_dir) + "/package.map";
     auto flag_map = std::string(storage_dir) + "/flag.map";
     auto flag_val = std::string(storage_dir) + "/flag.val";
@@ -353,13 +368,12 @@ TEST_F(AconfigdTest, init_platform_storage_reboot) {
   // the boot file must be refreshed
   ASSERT_TRUE(*new_timestamp != *old_timestamp);
 
-  auto platform_aconfig_dirs = std::vector<std::pair<std::string, std::string>>{
+  auto partitions = std::vector<std::pair<std::string, std::string>>{
     {"system", "/system/etc/aconfig"},
-    {"system_ext", "/system_ext/etc/aconfig"},
     {"vendor", "/vendor/etc/aconfig"},
     {"product", "/product/etc/aconfig"}};
 
-  for (auto const& [container, storage_dir] : platform_aconfig_dirs) {
+  for (auto const& [container, storage_dir] : partitions) {
     auto package_map = std::string(storage_dir) + "/package.map";
     auto flag_map = std::string(storage_dir) + "/flag.map";
     auto flag_val = std::string(storage_dir) + "/flag.val";
@@ -516,8 +530,8 @@ TEST_F(AconfigdTest, server_override) {
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -528,8 +542,8 @@ TEST_F(AconfigdTest, server_override) {
       return_msg, "com.android.aconfig.storage.test_1", "enabled_rw", "false", "",
       "true", "true", true, true, false);
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "true", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "true", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -550,8 +564,8 @@ TEST_F(AconfigdTest, server_override_survive_update) {
   verify_new_storage_return_message(return_msg, true);
 
   // create a server override
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -582,6 +596,29 @@ TEST_F(AconfigdTest, server_override_survive_update) {
       "true", "true", true, true, false);
 }
 
+TEST_F_WITH_FLAGS(AconfigdTest, local_override_immediate,
+                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(
+                      ACONFIGD_NS, support_immediate_local_overrides))) {
+  auto a_mock = AconfigdMock();
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+
+  auto request_msg = new_storage_message(c_mock);
+  auto return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_new_storage_return_message(return_msg, true);
+
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", true, true);
+  return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_flag_override_return_message(return_msg);
+
+  request_msg =
+      flag_query_message("com.android.aconfig.storage.test_1", "enabled_rw");
+  return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_flag_query_return_message(
+      return_msg, "com.android.aconfig.storage.test_1", "enabled_rw", "",
+      "false", "false", "true", true, false, true);
+}
+
 TEST_F(AconfigdTest, local_override) {
   auto a_mock = AconfigdMock();
   auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
@@ -590,8 +627,8 @@ TEST_F(AconfigdTest, local_override) {
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -602,8 +639,8 @@ TEST_F(AconfigdTest, local_override) {
       return_msg, "com.android.aconfig.storage.test_1", "enabled_rw", "", "false",
       "true", "true", true, false, true);
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "true", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "true", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -624,8 +661,8 @@ TEST_F(AconfigdTest, local_override_survive_update) {
   verify_new_storage_return_message(return_msg, true);
 
   // create a local override
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -665,14 +702,14 @@ TEST_F(AconfigdTest, single_local_override_remove) {
   verify_new_storage_return_message(return_msg, true);
 
   // local override enabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
   // local override disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_2", "disabled_rw", "true", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_2",
+                                      "disabled_rw", "true", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -707,13 +744,13 @@ TEST_F(AconfigdTest, readonly_flag_override) {
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_ro", "false", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_ro", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_error_message(return_msg, "Cannot update read only flag");
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_ro", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_ro", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_error_message(return_msg, "Cannot update read only flag");
 }
@@ -726,12 +763,13 @@ TEST_F(AconfigdTest, nonexist_flag_override) {
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  request_msg = flag_override_message("unknown", "enabled_rw", "false", false);
+  request_msg =
+      flag_override_message("unknown", "enabled_rw", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_error_message(return_msg, "Failed to find owning container");
 
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "unknown", "false", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "unknown", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_error_message(return_msg, "Flag does not exist");
 }
@@ -762,14 +800,14 @@ TEST_F(AconfigdTest, storage_reset) {
   verify_new_storage_return_message(return_msg, true);
 
   // server override enabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
   // local override disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_2", "disabled_rw", "true", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_2",
+                                      "disabled_rw", "true", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -804,14 +842,14 @@ TEST_F(AconfigdTest, list_package) {
   verify_new_storage_return_message(return_msg, true);
 
   // server override disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "disabled_rw", "true", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "disabled_rw", "true", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
   // local override enabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "enabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "enabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -841,14 +879,14 @@ TEST_F(AconfigdTest, list_container) {
   verify_new_storage_return_message(return_msg, true);
 
   // server override test1.disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "disabled_rw", "true", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "disabled_rw", "true", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
   // local override test2.disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_2", "disabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_2",
+                                      "disabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -893,14 +931,14 @@ TEST_F(AconfigdTest, list_all) {
   verify_new_storage_return_message(return_msg, true);
 
   // server override test1.disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_1", "disabled_rw", "true", false);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_1",
+                                      "disabled_rw", "true", false, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
   // local override test2.disabled_rw
-  request_msg = flag_override_message(
-      "com.android.aconfig.storage.test_2", "disabled_rw", "false", true);
+  request_msg = flag_override_message("com.android.aconfig.storage.test_2",
+                                      "disabled_rw", "false", true, false);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_flag_override_return_message(return_msg);
 
@@ -987,5 +1025,79 @@ TEST_F(AconfigdTest, ota_flag_staging) {
   ASSERT_EQ(flag.flag_value(), "false");
 }
 
+TEST_F(AconfigdTest, ota_flag_unstaging) {
+  // cerate mock aconfigd and initialize platform storage
+  auto a_mock = AconfigdMock();
+  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
+  ASSERT_TRUE(init_result.ok()) << init_result.error();
+
+  auto flags_to_stage =
+      std::vector<std::tuple<std::string, std::string, std::string>>();
+
+  // for fake OTA flag overrides, flip all RW flag value
+  auto request_msg = list_container_storage_message("system");
+  auto return_msg = a_mock.SendRequestToSocket(request_msg);
+  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
+  auto flags_msg = return_msg->list_storage_message();
+
+  for (auto const& flag : flags_msg.flags()) {
+    if (flag.is_readwrite()) {
+      flags_to_stage.push_back({
+          flag.package_name(),
+          flag.flag_name(),
+          flag.server_flag_value() == "true" ? "false" : "true"
+        });
+    }
+  }
+
+  // fake an OTA staging request, using current build id
+  auto build_id = base::GetProperty("ro.build.fingerprint", "");
+  request_msg = ota_flag_staging_message(build_id, flags_to_stage);
+  return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_ota_staging_return_message(return_msg);
+  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
+
+  init_result = a_mock.aconfigd.InitializePlatformStorage();
+  ASSERT_TRUE(init_result.ok()) << init_result.error();
+  ASSERT_FALSE(FileExists(a_mock.flags_dir + "/ota.pb"));
+
+  // list container
+  request_msg = list_container_storage_message("system");
+  return_msg = a_mock.SendRequestToSocket(request_msg);
+  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
+  flags_msg = return_msg->list_storage_message();
+
+  size_t i = 0;
+  for (auto const& flag : flags_msg.flags()) {
+    if (flag.is_readwrite()) {
+      ASSERT_EQ(flag.package_name(), std::get<0>(flags_to_stage[i]));
+      ASSERT_EQ(flag.flag_name(), std::get<1>(flags_to_stage[i]));
+      ASSERT_EQ(flag.server_flag_value(), std::get<2>(flags_to_stage[i]));
+      ++i;
+    }
+  }
+}
+
+TEST_F(AconfigdTest, ota_flag_unstaging_negative) {
+  // cerate mock aconfigd and initialize platform storage
+  auto a_mock = AconfigdMock();
+  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
+  ASSERT_TRUE(init_result.ok()) << init_result.error();
+
+  // fake an OTA staging request, using fake build id
+  auto request_msg = ota_flag_staging_message(
+      "some_fake_build_id",
+      {{"abc", "def", "true"}});
+  auto return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_ota_staging_return_message(return_msg);
+  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
+
+  init_result = a_mock.aconfigd.InitializePlatformStorage();
+  ASSERT_TRUE(init_result.ok()) << init_result.error();
+
+  // the ota overrides file should still exist
+  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
+}
+
 } // namespace aconfigd
 } // namespace android
diff --git a/aconfigd/aconfigd_util.cpp b/aconfigd/aconfigd_util.cpp
index 6a9419b..8b3507e 100644
--- a/aconfigd/aconfigd_util.cpp
+++ b/aconfigd/aconfigd_util.cpp
@@ -26,6 +26,7 @@
 #include <android-base/logging.h>
 #include <android-base/unique_fd.h>
 
+#include <aconfigd.pb.h>
 #include "aconfigd_util.h"
 
 using namespace android::base;
@@ -143,5 +144,24 @@ Result<std::string> GetFilesDigest(const std::vector<std::string>& files) {
   return ss.str();
 }
 
+/// convert override type enum to string
+std::string OverrideTypeToStr(
+    const StorageRequestMessage::FlagOverrideType& override_type) {
+  switch (override_type) {
+    case StorageRequestMessage::LOCAL_IMMEDIATE: {
+      return "local immediate";
+    }
+    case StorageRequestMessage::LOCAL_ON_REBOOT: {
+      return "local on reboot";
+    }
+    case StorageRequestMessage::SERVER_ON_REBOOT: {
+      return "server on reboot";
+    }
+    default: {
+      return "unknown";
+    }
+  }
+}
+
 } // namespace aconfig
 } // namespace android
diff --git a/aconfigd/aconfigd_util.h b/aconfigd/aconfigd_util.h
index 85a96d3..ff38a99 100644
--- a/aconfigd/aconfigd_util.h
+++ b/aconfigd/aconfigd_util.h
@@ -86,5 +86,8 @@ namespace android {
     return {};
   }
 
+  /// convert override type enum to string
+  std::string OverrideTypeToStr(const StorageRequestMessage::FlagOverrideType&);
+
   }// namespace aconfig
 } // namespace android
diff --git a/aconfigd/build.rs b/aconfigd/build.rs
new file mode 100644
index 0000000..a79f7af
--- /dev/null
+++ b/aconfigd/build.rs
@@ -0,0 +1,17 @@
+use protobuf_codegen::Codegen;
+
+fn main() {
+    let proto_files = vec!["aconfigd.proto"];
+
+    // tell cargo to only re-run the build script if any of the proto files has changed
+    for path in &proto_files {
+        println!("cargo:rerun-if-changed={}", path);
+    }
+
+    Codegen::new()
+        .pure()
+        .include(".")
+        .inputs(proto_files)
+        .cargo_out_dir("aconfigd_proto")
+        .run_from_script();
+}
diff --git a/aconfigd/new_aconfig_storage.aconfig b/aconfigd/new_aconfig_storage.aconfig
index 1d3e2bf..db92ac0 100644
--- a/aconfigd/new_aconfig_storage.aconfig
+++ b/aconfigd/new_aconfig_storage.aconfig
@@ -8,3 +8,10 @@ flag {
   bug: "312444587"
   is_fixed_read_only: true
 }
+
+flag {
+    name: "support_immediate_local_overrides"
+    namespace: "core_experiments_team_internal"
+    description: "Support immediate local overrides."
+    bug: "360205436"
+}
\ No newline at end of file
diff --git a/aconfigd/src/lib.rs b/aconfigd/src/lib.rs
new file mode 100644
index 0000000..c0ad36f
--- /dev/null
+++ b/aconfigd/src/lib.rs
@@ -0,0 +1,70 @@
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
+//! Crate containing protos used in aconfigd
+// When building with the Android tool-chain
+//
+//   - an external crate `aconfig_protos` will be generated
+//   - the feature "cargo" will be disabled
+//
+// When building with cargo
+//
+//   - a local sub-module will be generated in OUT_DIR and included in this file
+//   - the feature "cargo" will be enabled
+//
+// This module hides these differences from the rest of aconfig.
+
+// ---- When building with the Android tool-chain ----
+#[cfg(not(feature = "cargo"))]
+mod auto_generated {
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
+    pub use aconfigd_rust_proto::aconfigd::StorageRequestMessage as ProtoStorageRequestMessage;
+    pub use aconfigd_rust_proto::aconfigd::StorageRequestMessages as ProtoStorageRequestMessages;
+    pub use aconfigd_rust_proto::aconfigd::StorageReturnMessage as ProtoStorageReturnMessage;
+    pub use aconfigd_rust_proto::aconfigd::StorageReturnMessages as ProtoStorageReturnMessages;
+}
+
+// ---- When building with cargo ----
+#[cfg(feature = "cargo")]
+mod auto_generated {
+    // include! statements should be avoided (because they import file contents verbatim), but
+    // because this is only used during local development, and only if using cargo instead of the
+    // Android tool-chain, we allow it
+    include!(concat!(env!("OUT_DIR"), "/aconfigd_proto/mod.rs"));
+    pub use aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
+    pub use aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
+    pub use aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
+    pub use aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
+    pub use aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
+    pub use aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
+    pub use aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
+    pub use aconfigd::StorageRequestMessage as ProtoStorageRequestMessage;
+    pub use aconfigd::StorageRequestMessages as ProtoStorageRequestMessages;
+    pub use aconfigd::StorageReturnMessage as ProtoStorageReturnMessage;
+    pub use aconfigd::StorageReturnMessages as ProtoStorageReturnMessages;
+}
+
+pub use auto_generated::*;
diff --git a/aconfigd/srcs/AconfigdFlagInfo.java b/aconfigd/srcs/AconfigdFlagInfo.java
index 359d986..6f88593 100644
--- a/aconfigd/srcs/AconfigdFlagInfo.java
+++ b/aconfigd/srcs/AconfigdFlagInfo.java
@@ -27,6 +27,7 @@ public class AconfigdFlagInfo {
     private String mLocalFlagValue;
     private String mBootFlagValue;
     private String mDefaultFlagValue;
+    private String mNamespace;
     private boolean mHasServerOverride;
     private boolean mHasLocalOverride;
     private boolean mIsReadWrite;
@@ -44,6 +45,7 @@ public class AconfigdFlagInfo {
         if (mBootFlagValue == null) {
             updateBootFlagValue();
         }
+        mNamespace = builder.mNamespace;
     }
 
     public String getFullFlagName() {
@@ -75,6 +77,10 @@ public class AconfigdFlagInfo {
         return mDefaultFlagValue;
     }
 
+    public String getNamespace() {
+        return mNamespace;
+    }
+
     public boolean getHasServerOverride() {
         return mHasServerOverride;
     }
@@ -227,6 +233,7 @@ public class AconfigdFlagInfo {
         private String mLocalFlagValue;
         private String mBootFlagValue;
         private String mDefaultFlagValue;
+        private String mNamespace;
         private boolean mHasServerOverride;
         private boolean mHasLocalOverride;
         private boolean mIsReadWrite;
@@ -261,6 +268,11 @@ public class AconfigdFlagInfo {
             return this;
         }
 
+        public Builder setNamespace(String namespace) {
+            mNamespace = namespace;
+            return this;
+        }
+
         public Builder setHasServerOverride(boolean hasServerOverride) {
             mHasServerOverride = hasServerOverride;
             return this;
diff --git a/aconfigd/srcs/AconfigdJavaUtils.java b/aconfigd/srcs/AconfigdJavaUtils.java
index 4cba0f3..607f780 100644
--- a/aconfigd/srcs/AconfigdJavaUtils.java
+++ b/aconfigd/srcs/AconfigdJavaUtils.java
@@ -71,7 +71,9 @@ public class AconfigdJavaUtils {
         proto.write(StorageRequestMessage.FlagOverrideMessage.PACKAGE_NAME, packageName);
         proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_NAME, flagName);
         proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_VALUE, flagValue);
-        proto.write(StorageRequestMessage.FlagOverrideMessage.IS_LOCAL, isLocal);
+        proto.write(StorageRequestMessage.FlagOverrideMessage.OVERRIDE_TYPE, isLocal
+                ? StorageRequestMessage.LOCAL_ON_REBOOT
+                : StorageRequestMessage.SERVER_ON_REBOOT);
         proto.end(msgToken);
         proto.end(msgsToken);
     }
diff --git a/aconfigd/storage_files.cpp b/aconfigd/storage_files.cpp
index 1f08d3c..b5a230a 100644
--- a/aconfigd/storage_files.cpp
+++ b/aconfigd/storage_files.cpp
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include "storage_files.h"
+
 #include <android-base/logging.h>
 #include <unistd.h>
 
@@ -21,7 +23,7 @@
 
 #include "aconfigd.h"
 #include "aconfigd_util.h"
-#include "storage_files.h"
+#include "com_android_aconfig_new_storage.h"
 
 using namespace aconfig_storage;
 
@@ -621,9 +623,29 @@ namespace android {
     return {};
   }
 
+  /// Write override immediately to boot copy.
+  base::Result<void> StorageFiles::WriteLocalOverrideToBootCopy(
+      const PackageFlagContext& context, const std::string& flag_value) {
+    if (chmod(storage_record_.boot_flag_val.c_str(), 0644) == -1) {
+      return base::ErrnoError() << "chmod() failed to set to 0644";
+    }
+
+    auto flag_value_file =
+        map_mutable_storage_file(storage_record_.boot_flag_val);
+    auto update_result = set_boolean_flag_value(
+        **flag_value_file, context.flag_index, flag_value == "true");
+    RETURN_IF_ERROR(update_result, "Failed to update flag value");
+
+    if (chmod(storage_record_.boot_flag_val.c_str(), 0444) == -1) {
+      return base::ErrnoError() << "chmod() failed to set to 0444";
+    }
+
+    return {};
+  }
+
   /// local flag override, update local flag override pb filee
-  base::Result<void> StorageFiles::SetLocalFlagValue(const PackageFlagContext& context,
-                                                     const std::string& flag_value) {
+  base::Result<void> StorageFiles::SetLocalFlagValue(
+      const PackageFlagContext& context, const std::string& flag_value) {
     if (!context.flag_exists) {
       return base::Error() << "Flag does not exist";
     }
diff --git a/aconfigd/storage_files.h b/aconfigd/storage_files.h
index 0f9094d..6de608c 100644
--- a/aconfigd/storage_files.h
+++ b/aconfigd/storage_files.h
@@ -129,6 +129,10 @@ namespace android {
       base::Result<void> SetServerFlagValue(const PackageFlagContext& context,
                                             const std::string& flag_value);
 
+      /// write local override to boot flag file immediately
+      base::Result<void> WriteLocalOverrideToBootCopy(
+          const PackageFlagContext& context, const std::string& flag_value);
+
       /// local flag override, update local flag override pb filee
       base::Result<void> SetLocalFlagValue(const PackageFlagContext& context,
                                            const std::string& flag_value);
diff --git a/aconfigd/storage_files_manager.cpp b/aconfigd/storage_files_manager.cpp
index 075946f..84eb355 100644
--- a/aconfigd/storage_files_manager.cpp
+++ b/aconfigd/storage_files_manager.cpp
@@ -15,9 +15,11 @@
  * limitations under the License.
  */
 
+#include "storage_files_manager.h"
+
 #include "aconfigd.h"
 #include "aconfigd_util.h"
-#include "storage_files_manager.h"
+#include "com_android_aconfig_new_storage.h"
 
 using namespace aconfig_storage;
 
@@ -263,11 +265,9 @@ namespace android {
 
   /// apply flag override
   base::Result<void> StorageFilesManager::UpdateFlagValue(
-      const std::string& package_name,
-      const std::string& flag_name,
+      const std::string& package_name, const std::string& flag_name,
       const std::string& flag_value,
-      bool is_local_override) {
-
+      const StorageRequestMessage::FlagOverrideType override_type) {
     auto container = GetContainer(package_name);
     RETURN_IF_ERROR(container, "Failed to find owning container");
 
@@ -277,12 +277,36 @@ namespace android {
     auto context = (**storage_files).GetPackageFlagContext(package_name, flag_name);
     RETURN_IF_ERROR(context, "Failed to find package flag context");
 
-    if (is_local_override) {
-      auto update = (**storage_files).SetLocalFlagValue(*context, flag_value);
-      RETURN_IF_ERROR(update, "Failed to set local flag override");
-    } else {
-      auto update =(**storage_files).SetServerFlagValue(*context, flag_value);
-      RETURN_IF_ERROR(update, "Failed to set server flag value");
+    switch (override_type) {
+      case StorageRequestMessage::LOCAL_ON_REBOOT: {
+        auto update = (**storage_files).SetLocalFlagValue(*context, flag_value);
+        RETURN_IF_ERROR(update, "Failed to set local flag override");
+        break;
+      }
+      case StorageRequestMessage::SERVER_ON_REBOOT: {
+        auto update =
+            (**storage_files).SetServerFlagValue(*context, flag_value);
+        RETURN_IF_ERROR(update, "Failed to set server flag value");
+        break;
+      }
+      case StorageRequestMessage::LOCAL_IMMEDIATE: {
+        if (!com::android::aconfig_new_storage::
+                support_immediate_local_overrides()) {
+          return base::Error() << "local immediate override not supported";
+        }
+
+        auto updateOverride =
+            (**storage_files).SetLocalFlagValue(*context, flag_value);
+        RETURN_IF_ERROR(updateOverride, "Failed to set local flag override");
+        auto updateBootFile =
+            (**storage_files)
+                .WriteLocalOverrideToBootCopy(*context, flag_value);
+        RETURN_IF_ERROR(updateBootFile,
+                        "Failed to write local override to boot file");
+        break;
+      }
+      default:
+        return base::Error() << "unknown flag override type";
     }
 
     return {};
diff --git a/aconfigd/storage_files_manager.h b/aconfigd/storage_files_manager.h
index d42bb0c..f90c91c 100644
--- a/aconfigd/storage_files_manager.h
+++ b/aconfigd/storage_files_manager.h
@@ -105,10 +105,11 @@ namespace android {
           const std::string& file_name);
 
       /// apply flag override
-      base::Result<void> UpdateFlagValue(const std::string& package_name,
-                                         const std::string& flag_name,
-                                         const std::string& flag_value,
-                                         bool is_local_override = false);
+      base::Result<void> UpdateFlagValue(
+          const std::string& package_name, const std::string& flag_name,
+          const std::string& flag_value,
+          const StorageRequestMessage::FlagOverrideType overrideType =
+              StorageRequestMessage::SERVER_ON_REBOOT);
 
       /// apply ota flags and return remaining ota flags
       base::Result<std::vector<FlagOverride>> ApplyOTAFlagsForContainer(
diff --git a/aconfigd/tests/flag.map b/aconfigd/tests/flag.map
index e868f53..cf4685c 100644
Binary files a/aconfigd/tests/flag.map and b/aconfigd/tests/flag.map differ
diff --git a/aconfigd/tests/flag.val b/aconfigd/tests/flag.val
index ed203d4..37d4750 100644
Binary files a/aconfigd/tests/flag.val and b/aconfigd/tests/flag.val differ
diff --git a/aconfigd/tests/package.map b/aconfigd/tests/package.map
index 6c46a03..358010c 100644
Binary files a/aconfigd/tests/package.map and b/aconfigd/tests/package.map differ
diff --git a/aconfigd/tests/updated_flag.map b/aconfigd/tests/updated_flag.map
index c280e8d..e4c608c 100644
Binary files a/aconfigd/tests/updated_flag.map and b/aconfigd/tests/updated_flag.map differ
diff --git a/aconfigd/tests/updated_flag.val b/aconfigd/tests/updated_flag.val
index 5f5dcd1..041f435 100644
Binary files a/aconfigd/tests/updated_flag.val and b/aconfigd/tests/updated_flag.val differ
diff --git a/aconfigd/tests/updated_package.map b/aconfigd/tests/updated_package.map
index 64059f1..782d837 100644
Binary files a/aconfigd/tests/updated_package.map and b/aconfigd/tests/updated_package.map differ
diff --git a/libflags/Android.bp b/libflags/Android.bp
index 9908fd8..1cdb7f2 100644
--- a/libflags/Android.bp
+++ b/libflags/Android.bp
@@ -24,6 +24,11 @@ cc_library {
     ],
     min_sdk_version: "29",
     afdo: true,
+    target: {
+        windows: {
+            enabled: true,
+        },
+    },
 }
 
 // Tests
```

