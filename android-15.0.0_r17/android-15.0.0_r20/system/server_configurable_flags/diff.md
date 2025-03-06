```diff
diff --git a/aconfigd/Android.bp b/aconfigd/Android.bp
index 34536f7..c48ba78 100644
--- a/aconfigd/Android.bp
+++ b/aconfigd/Android.bp
@@ -1,21 +1,99 @@
-cc_binary {
-    name: "aconfigd",
-    defaults: [
-        "aconfig_lib_cc_shared_link.defaults",
+rust_binary {
+    name: "aconfigd-system",
+    defaults: ["aconfigd_system.defaults"],
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libaconfig_new_storage_flags_rust",
+        "libaconfigd_system",
+        "libaconfigd_rust",
+        "libandroid_logger",
+        "librustutils",
+        "liblibc",
+    ],
+    native_coverage: false,
+    init_rc: ["aconfigd.rc"],
+}
+
+rust_library {
+    name: "libaconfigd_system",
+    crate_name: "aconfigd_system",
+    defaults: ["aconfigd_system.defaults"],
+    srcs: ["lib.rs"],
+    rustlibs: [
+        "libcxx",
+        "libbase",
+        "libaconfigd_protos_rust",
     ],
+    static_libs: [
+        "libcxx_aconfigd",
+        "libaconfigd_protos_cc",
+        "libaconfig_storage_file_cc",
+        "libaconfig_new_storage_flags",
+        "libaconfig_storage_read_api_cc",
+        "libaconfig_storage_write_api_cc",
+    ],
+    shared_libs: [
+        "libbase",
+        "libaconfigd",
+        "libprotobuf-cpp-lite",
+    ],
+}
+
+cc_library_static {
+    name: "libcxx_aconfigd",
+    srcs: ["libcxx_aconfigd.cpp"],
+    generated_headers: [
+        "cxx-bridge-header",
+        "libcxx_aconfigd_bridge_header",
+    ],
+    static_libs: [
+        "libaconfigd_protos_cc",
+        "libaconfig_storage_file_cc",
+        "libaconfig_new_storage_flags",
+        "libaconfig_storage_read_api_cc",
+        "libaconfig_storage_write_api_cc",
+    ],
+    shared_libs: [
+        "libaconfigd",
+        "libbase",
+        "libprotobuf-cpp-lite",
+    ],
+    generated_sources: ["libcxx_aconfigd_bridge_code"],
+}
+
+genrule {
+    name: "libcxx_aconfigd_bridge_code",
+    tools: ["cxxbridge"],
+    cmd: "$(location cxxbridge) $(in) > $(out)",
+    srcs: ["lib.rs"],
+    out: ["libcxx_aconfigd_cxx_generated.cc"],
+}
+
+genrule {
+    name: "libcxx_aconfigd_bridge_header",
+    tools: ["cxxbridge"],
+    cmd: "$(location cxxbridge) $(in) --header > $(out)",
+    srcs: ["lib.rs"],
+    out: ["lib.rs.h"],
+}
+
+cc_library {
+    name: "libaconfigd",
     srcs: [
         "aconfigd.cpp",
-        "aconfigd.proto",
-        "aconfigd_main.cpp",
         "aconfigd_util.cpp",
         "storage_files.cpp",
         "storage_files_manager.cpp",
     ],
     static_libs: [
+        "libaconfig_flags_cc",
+        "libaconfigd_protos_cc",
         "libaconfig_storage_file_cc",
         "libaconfig_new_storage_flags",
         "libaconfig_storage_read_api_cc",
         "libaconfig_storage_write_api_cc",
+        // TODO(370864013): Remove this once the CTS annotation issue is fixed.
+        "cts_flags_tests_cc",
     ],
     shared_libs: [
         "libcutils",
@@ -25,7 +103,7 @@ cc_binary {
         "libcrypto",
         "server_configurable_flags",
     ],
-    init_rc: ["aconfigd.rc"],
+    export_include_dirs: ["include"],
 }
 
 aconfig_declarations {
@@ -40,62 +118,20 @@ cc_aconfig_library {
     aconfig_declarations: "aconfig_new_storage_flags",
 }
 
-java_aconfig_library {
-    name: "aconfig_new_storage_flags_lib",
+rust_aconfig_library {
+    name: "libaconfig_new_storage_flags_rust",
+    crate_name: "aconfig_new_storage_flags",
     aconfig_declarations: "aconfig_new_storage_flags",
-}
-
-filegroup {
-    name: "aconfigd_protos",
-    srcs: ["aconfigd.proto"],
-}
-
-java_library {
-    name: "aconfigd_java_proto_lib",
-    host_supported: true,
-    srcs: ["aconfigd.proto"],
-    proto: {
-        type: "stream",
-    },
-    sdk_version: "current",
-    min_sdk_version: "UpsideDownCake",
     apex_available: [
         "//apex_available:anyapex",
         "//apex_available:platform",
     ],
+    min_sdk_version: "34",
 }
 
-rust_protobuf {
-    name: "libaconfigd_rust_proto",
-    crate_name: "aconfigd_rust_proto",
-    source_stem: "aconfigd_rust_proto_source",
-    protos: [
-        "aconfigd.proto",
-    ],
-    host_supported: true,
-}
-
-rust_defaults {
-    name: "aconfigd_protos.defaults",
-    edition: "2021",
-    clippy_lints: "android",
-    lints: "android",
-    srcs: ["src/lib.rs"],
-    rustlibs: [
-        "libaconfigd_rust_proto",
-        "libanyhow",
-        "libprotobuf",
-    ],
-    proc_macros: [
-        "libpaste",
-    ],
-}
-
-rust_library {
-    name: "libaconfigd_protos",
-    crate_name: "aconfigd_protos",
-    defaults: ["aconfigd_protos.defaults"],
-    host_supported: true,
+java_aconfig_library {
+    name: "aconfig_new_storage_flags_lib",
+    aconfig_declarations: "aconfig_new_storage_flags",
 }
 
 cc_test {
@@ -107,34 +143,33 @@ cc_test {
     srcs: [
         "aconfigd_test.cpp",
         "aconfigd_util.cpp",
-        "aconfigd.cpp",
-        "storage_files_manager.cpp",
-        "storage_files.cpp",
-        "aconfigd.proto",
     ],
     static_libs: [
         "libflagtest",
         "libgmock",
+        "libaconfigd_protos_cc",
         "libaconfig_storage_file_cc",
         "libaconfig_new_storage_flags",
         "libaconfig_storage_read_api_cc",
         "libaconfig_storage_write_api_cc",
+        "libaconfigd",
     ],
     shared_libs: [
-        "libprotobuf-cpp-lite",
         "libbase",
         "liblog",
         "libcrypto",
+        "libprotobuf-cpp-lite",
         "server_configurable_flags",
-        "libaconfig_flags_cc",
     ],
     data: [
-        "tests/package.map",
-        "tests/flag.map",
-        "tests/flag.val",
-        "tests/updated_package.map",
-        "tests/updated_flag.map",
-        "tests/updated_flag.val",
+        "tests/data/v1/package.map",
+        "tests/data/v1/flag.map",
+        "tests/data/v1/flag.val",
+        "tests/data/v1/flag.info",
+        "tests/data/v2/package.map",
+        "tests/data/v2/flag.map",
+        "tests/data/v2/flag.val",
+        "tests/data/v2/flag.info",
     ],
     test_suites: [
         "device-tests",
@@ -142,15 +177,48 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "aconfigd_proton_collider_test",
+    defaults: [
+        "aconfig_lib_cc_shared_link.defaults",
+    ],
+    team: "trendy_team_android_core_experiments",
+    srcs: [
+        "aconfigd_proton_collider_test.cpp",
+    ],
+    static_libs: [
+        "libflagtest",
+        "libgmock",
+        "libaconfigd_protos_cc",
+        "libaconfig_storage_file_cc",
+        "libaconfig_new_storage_flags",
+        "libaconfig_storage_read_api_cc",
+        "libaconfig_storage_write_api_cc",
+        "libaconfigd",
+    ],
+    shared_libs: [
+        "libprotobuf-cpp-lite",
+        "libbase",
+        "liblog",
+        "libcrypto",
+        "server_configurable_flags",
+    ],
+    test_suites: [
+        "device-tests",
+        "general-tests",
+    ],
+    test_config: "AndroidTest.aconfigd_proton_collider_test.xml",
+}
+
 cc_test {
     name: "aconfigd_socket_test",
     team: "trendy_team_android_core_experiments",
     srcs: [
         "aconfigd_socket_test.cpp",
-        "aconfigd.proto",
     ],
     static_libs: [
         "libgmock",
+        "libaconfigd_protos_cc",
         "libaconfig_new_storage_flags",
     ],
     shared_libs: [
@@ -160,14 +228,15 @@ cc_test {
         "liblog",
     ],
     data: [
-        "tests/package.map",
-        "tests/flag.map",
-        "tests/flag.val",
+        "tests/data/v1/package.map",
+        "tests/data/v1/flag.map",
+        "tests/data/v1/flag.val",
     ],
     test_suites: [
         "device-tests",
         "general-tests",
     ],
+    test_config: "AndroidTest.aconfigd_socket_test.xml",
 }
 
 java_library {
@@ -184,3 +253,21 @@ java_library {
         "//apex_available:platform",
     ],
 }
+
+rust_defaults {
+    name: "aconfigd_system.defaults",
+    edition: "2021",
+    lints: "none",
+    rustlibs: [
+        "libaconfig_storage_file",
+        "libaconfig_storage_read_api",
+        "libaconfig_storage_write_api",
+        "libaconfigd_protos_rust",
+        "libanyhow",
+        "libclap",
+        "libmemmap2",
+        "liblog_rust",
+        "libprotobuf",
+        "libthiserror",
+    ],
+}
diff --git a/aconfigd/AndroidTest.aconfigd_proton_collider_test.xml b/aconfigd/AndroidTest.aconfigd_proton_collider_test.xml
new file mode 100644
index 0000000..05f6cc7
--- /dev/null
+++ b/aconfigd/AndroidTest.aconfigd_proton_collider_test.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
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
+<configuration description="Runs aconfigd_proton_collider_test tests">
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer" />
+
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push" value="aconfigd_proton_collider_test->/data/local/tmp/aconfigd_proton_collider_test" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.GTest" >
+        <option name="native-test-device-path" value="/data/local/tmp" />
+        <option name="module-name" value="aconfigd_proton_collider_test" />
+    </test>
+</configuration>
diff --git a/aconfigd/AndroidTest.aconfigd_socket_test.xml b/aconfigd/AndroidTest.aconfigd_socket_test.xml
new file mode 100644
index 0000000..e91c46b
--- /dev/null
+++ b/aconfigd/AndroidTest.aconfigd_socket_test.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
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
+<configuration description="Runs aconfigd_socket_test tests">
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer" />
+
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push" value="aconfigd_socket_test->/data/local/tmp/aconfigd_socket_test" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.GTest" >
+        <option name="native-test-device-path" value="/data/local/tmp" />
+        <option name="module-name" value="aconfigd_socket_test" />
+    </test>
+</configuration>
diff --git a/aconfigd/Cargo.toml b/aconfigd/Cargo.toml
deleted file mode 100644
index 6aa352e..0000000
--- a/aconfigd/Cargo.toml
+++ /dev/null
@@ -1,18 +0,0 @@
-[package]
-name = "aconfigd_protos"
-version = "0.1.0"
-edition = "2021"
-build = "build.rs"
-
-[features]
-default = ["cargo"]
-cargo = []
-
-[dependencies]
-anyhow = "1.0.69"
-paste = "1.0.11"
-protobuf = "3.2.0"
-
-[build-dependencies]
-protobuf-codegen = "3.2.0"
-
diff --git a/aconfigd/TEST_MAPPING b/aconfigd/TEST_MAPPING
index 9a7a53d..4ea951a 100644
--- a/aconfigd/TEST_MAPPING
+++ b/aconfigd/TEST_MAPPING
@@ -4,6 +4,10 @@
       // aconfigd unit tests
       "name": "aconfigd_test"
     },
+    {
+      // aconfigd proton collider unit tests
+      "name": "aconfigd_proton_collider_test"
+    },
     {
       // aconfigd java utils test
       "name": "aconfigd_java_utils_test"
diff --git a/aconfigd/aconfigd.cpp b/aconfigd/aconfigd.cpp
index fbecd9a..2773c93 100644
--- a/aconfigd/aconfigd.cpp
+++ b/aconfigd/aconfigd.cpp
@@ -48,8 +48,62 @@ Result<void> Aconfigd::HandleOTAStaging(
     const StorageRequestMessage::OTAFlagStagingMessage& msg,
     StorageReturnMessage& return_msg) {
   auto ota_flags_pb_file = root_dir_ + "/flags/ota.pb";
+  auto stored_pb_result =
+      ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
+          ota_flags_pb_file);
+
+  if (!stored_pb_result.ok() ||
+      (msg.build_id() != (*stored_pb_result).build_id())) {
+    LOG(INFO) << "discarding staged flags from " +
+                     (*stored_pb_result).build_id() +
+                     "; staging new flags for " + msg.build_id();
+    auto result = WritePbToFile<StorageRequestMessage::OTAFlagStagingMessage>(
+        msg, ota_flags_pb_file);
+    RETURN_IF_ERROR(result, "Failed to stage OTA flags");
+    return_msg.mutable_ota_staging_message();
+    return {};
+  }
+
+  std::set<std::string> qualified_names;
+
+  std::map<std::string, android::aconfigd::FlagOverride> new_name_to_override;
+  for (const auto& flag_override : msg.overrides()) {
+    auto qualified_name =
+        flag_override.package_name() + "." + flag_override.flag_name();
+    new_name_to_override[qualified_name] = flag_override;
+
+    qualified_names.insert(qualified_name);
+  }
+
+  std::map<std::string, android::aconfigd::FlagOverride> prev_name_to_override;
+  for (const auto& flag_override : (*stored_pb_result).overrides()) {
+    auto qualified_name =
+        flag_override.package_name() + "." + flag_override.flag_name();
+    prev_name_to_override[qualified_name] = flag_override;
+
+    qualified_names.insert(qualified_name);
+  }
+
+  std::vector<android::aconfigd::FlagOverride> overrides;
+  for (const auto& qualified_name : qualified_names) {
+    if (new_name_to_override.contains(qualified_name)) {
+      overrides.push_back(new_name_to_override[qualified_name]);
+    } else {
+      overrides.push_back(prev_name_to_override[qualified_name]);
+    }
+  }
+
+  StorageRequestMessage::OTAFlagStagingMessage message_to_persist;
+  message_to_persist.set_build_id(msg.build_id());
+  for (const auto& flag_override : overrides) {
+    auto override_ = message_to_persist.add_overrides();
+    override_->set_flag_name(flag_override.flag_name());
+    override_->set_package_name(flag_override.package_name());
+    override_->set_flag_value(flag_override.flag_value());
+  }
+
   auto result = WritePbToFile<StorageRequestMessage::OTAFlagStagingMessage>(
-      msg, ota_flags_pb_file);
+      message_to_persist, ota_flags_pb_file);
   RETURN_IF_ERROR(result, "Failed to stage OTA flags");
   return_msg.mutable_ota_staging_message();
   return {};
@@ -60,7 +114,8 @@ Result<void> Aconfigd::HandleNewStorage(
     const StorageRequestMessage::NewStorageMessage& msg,
     StorageReturnMessage& return_msg) {
   auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
-      msg.container(), msg.package_map(), msg.flag_map(), msg.flag_value());
+      msg.container(), msg.package_map(), msg.flag_map(), msg.flag_value(),
+      msg.flag_info());
   RETURN_IF_ERROR(updated, "Failed to add or update container");
 
   auto write_result = storage_files_manager_->WritePersistStorageRecordsToFile(
@@ -100,10 +155,11 @@ Result<void> Aconfigd::HandleLocalOverrideRemoval(
     StorageReturnMessage& return_msg) {
   auto result = Result<void>();
   if (msg.remove_all()) {
-    result = storage_files_manager_->RemoveAllLocalOverrides();
+    result = storage_files_manager_->RemoveAllLocalOverrides(
+        msg.remove_override_type());
   } else {
     result = storage_files_manager_->RemoveFlagLocalOverride(
-        msg.package_name(), msg.flag_name());
+        msg.package_name(), msg.flag_name(), msg.remove_override_type());
   }
   RETURN_IF_ERROR(result, "");
   return_msg.mutable_remove_local_override_message();
@@ -158,6 +214,7 @@ Result<void> Aconfigd::HandleListStorage(
     flag_msg->set_is_readwrite(flag.is_readwrite);
     flag_msg->set_has_server_override(flag.has_server_override);
     flag_msg->set_has_local_override(flag.has_local_override);
+    flag_msg->set_has_boot_local_override(flag.has_boot_local_override);
   }
   return {};
 }
@@ -214,13 +271,14 @@ Result<void> Aconfigd::InitializePlatformStorage() {
     auto package_file = std::string(storage_dir) + "/package.map";
     auto flag_file = std::string(storage_dir) + "/flag.map";
     auto value_file = std::string(storage_dir) + "/flag.val";
+    auto info_file = std::string(storage_dir) + "/flag.info";
 
     if (!FileNonZeroSize(value_file)) {
       continue;
     }
 
     auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
-        container, package_file, flag_file, value_file);
+        container, package_file, flag_file, value_file, info_file);
     RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                     + container);
 
@@ -239,34 +297,6 @@ Result<void> Aconfigd::InitializePlatformStorage() {
                     + container);
   }
 
-  // TODO remove this logic once new storage launch complete
-  // if flag enable_only_new_storage is true, writes a marker file
-  {
-    auto flags = storage_files_manager_->ListFlagsInPackage("com.android.aconfig.flags");
-    RETURN_IF_ERROR(flags, "Failed to list flags");
-    bool enable_only_new_storage = false;
-    for (const auto& flag : *flags) {
-      if (flag.flag_name == "enable_only_new_storage") {
-        enable_only_new_storage = (flag.boot_flag_value == "true");
-        break;
-      }
-    }
-    auto marker_file = std::string("/metadata/aconfig/boot/enable_only_new_storage");
-    if (enable_only_new_storage) {
-      if (!FileExists(marker_file)) {
-        int fd = open(marker_file.c_str(), O_CREAT, 0644);
-        if (fd == -1) {
-          return ErrnoError() << "failed to create marker file";
-        }
-        close(fd);
-      }
-    } else {
-      if (FileExists(marker_file)) {
-        unlink(marker_file.c_str());
-      }
-    }
-  }
-
   return {};
 }
 
@@ -293,13 +323,14 @@ Result<void> Aconfigd::InitializeMainlineStorage() {
     auto package_file = std::string(storage_dir) + "/package.map";
     auto flag_file = std::string(storage_dir) + "/flag.map";
     auto value_file = std::string(storage_dir) + "/flag.val";
+    auto info_file = std::string(storage_dir) + "/flag.info";
 
     if (!FileExists(value_file) || !FileNonZeroSize(value_file)) {
       continue;
     }
 
     auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
-        container, package_file, flag_file, value_file);
+        container, package_file, flag_file, value_file, info_file);
     RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                     + container);
 
@@ -331,7 +362,7 @@ Result<void> Aconfigd::HandleSocketRequest(const StorageRequestMessage& message,
     }
     case StorageRequestMessage::kFlagOverrideMessage: {
       auto msg = message.flag_override_message();
-      LOG(INFO) << "received a '" << OverrideTypeToStr(msg.override_type())
+      LOG(DEBUG) << "received a '" << OverrideTypeToStr(msg.override_type())
                 << "' flag override request for " << msg.package_name() << "/"
                 << msg.flag_name() << " to " << msg.flag_value();
       result = HandleFlagOverride(msg, return_message);
diff --git a/aconfigd/aconfigd.proto b/aconfigd/aconfigd.proto
index aa6a6f7..eaf10a0 100644
--- a/aconfigd/aconfigd.proto
+++ b/aconfigd/aconfigd.proto
@@ -25,6 +25,7 @@ message PersistStorageRecord {
   optional string flag_map = 4;
   optional string flag_val = 5;
   optional string digest = 6;
+  optional string flag_info = 7;
 }
 
 message PersistStorageRecords {
@@ -49,6 +50,7 @@ message StorageRequestMessage {
     optional string package_map = 2;
     optional string flag_map = 3;
     optional string flag_value = 4;
+    optional string flag_info = 5;
   }
 
   enum FlagOverrideType {
@@ -71,11 +73,17 @@ message StorageRequestMessage {
     repeated FlagOverride overrides = 2;
   }
 
+  enum RemoveOverrideType {
+    REMOVE_LOCAL_IMMEDIATE = 1;
+    REMOVE_LOCAL_ON_REBOOT = 2;
+  }
+
   // request to remove local flag override
   message RemoveLocalOverrideMessage {
     optional bool remove_all = 1;
     optional string package_name = 2;
     optional string flag_name = 3;
+    optional RemoveFlagOverrideType remove_override_type = 4;
   }
 
   // query persistent flag value and info
@@ -136,7 +144,8 @@ message StorageReturnMessage {
     optional bool has_server_override = 7;
     optional bool is_readwrite = 8;
     optional bool has_local_override = 9;
-    optional string container = 10;
+    optional bool has_boot_local_override = 10;
+    optional string container = 11;
   }
 
   message RemoveLocalOverrideReturnMessage {}
diff --git a/aconfigd/aconfigd.rc b/aconfigd/aconfigd.rc
index 9ea4ec2..b364662 100644
--- a/aconfigd/aconfigd.rc
+++ b/aconfigd/aconfigd.rc
@@ -1,30 +1,31 @@
-service aconfigd-platform-init /system/bin/aconfigd --platform_init
+service system_aconfigd_mainline_init /system/bin/aconfigd-system mainline-init
     class core
     user system
     group system
     oneshot
     disabled # does not start with the core class
     file /dev/kmsg w
-    #turn it on when b/312444587 completes
-    #reboot_on_failure reboot
 
-service aconfigd-mainline-init /system/bin/aconfigd --mainline_init
+service system_aconfigd_platform_init /system/bin/aconfigd-system platform-init
     class core
     user system
     group system
     oneshot
     disabled # does not start with the core class
     file /dev/kmsg w
-    #turn it on when b/312444587 completes
-    #reboot_on_failure reboot
 
-service aconfigd /system/bin/aconfigd
+service system_aconfigd_socket_service /system/bin/aconfigd-system start-socket
     class core
     user system
     group system
     oneshot
     disabled # does not start with the core class
     file /dev/kmsg w
-    #turn it on when b/312444587 completes
-    #reboot_on_failure reboot
-    socket aconfigd stream 666 system system
+    socket aconfigd_system stream 666 system system
+
+on post-fs
+    mkdir /metadata/aconfig 0775 root system
+    mkdir /metadata/aconfig/flags 0770 root system
+    mkdir /metadata/aconfig/maps 0775 root system
+    mkdir /metadata/aconfig/boot 0775 root system
+    exec_start system_aconfigd_platform_init
diff --git a/aconfigd/aconfigd_main.cpp b/aconfigd/aconfigd_main.cpp
deleted file mode 100644
index 3446947..0000000
--- a/aconfigd/aconfigd_main.cpp
+++ /dev/null
@@ -1,216 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include <android-base/logging.h>
-#include <android-base/unique_fd.h>
-#include <cutils/sockets.h>
-#include <sys/un.h>
-
-#include "com_android_aconfig_new_storage.h"
-#include "aconfigd.h"
-#include "aconfigd_util.h"
-
-using namespace android::aconfigd;
-using namespace android::base;
-
-static int aconfigd_platform_init() {
-  auto aconfigd = Aconfigd(kAconfigdRootDir,
-                           kPersistentStorageRecordsFileName);
-
-  auto init_result = aconfigd.InitializePlatformStorage();
-  if (!init_result.ok()) {
-    LOG(ERROR) << "failed to initialize platform storage records: " << init_result.error();
-    return 1;
-  }
-
-  return 0;
-}
-
-static int aconfigd_mainline_init() {
-  auto aconfigd = Aconfigd(kAconfigdRootDir,
-                           kPersistentStorageRecordsFileName);
-
-  auto init_result = aconfigd.InitializeMainlineStorage();
-  if (!init_result.ok()) {
-    LOG(ERROR) << "failed to initialize mainline storage records: " << init_result.error();
-    return 1;
-  }
-
-  return 0;
-}
-
-/// receive storage requests from socket
-static Result<StorageRequestMessages> receiveMessage(int client_fd) {
-  unsigned char size_buffer[4] = {};
-  int size_bytes_received = 0;
-  while (size_bytes_received < 4) {
-    auto chunk_bytes =
-        TEMP_FAILURE_RETRY(recv(client_fd, size_buffer + size_bytes_received,
-                                4 - size_bytes_received, 0));
-    if (chunk_bytes <= 0) {
-      return ErrnoError() << "received error polling for message size";
-    }
-    size_bytes_received += chunk_bytes;
-  }
-
-  uint32_t payload_size = uint32_t(
-      size_buffer[0]<<24 | size_buffer[1]<<16 | size_buffer[2]<<8 | size_buffer[3]);
-
-  char payload_buffer[payload_size];
-  int payload_bytes_received = 0;
-  while (payload_bytes_received < payload_size) {
-    auto chunk_bytes = TEMP_FAILURE_RETRY(
-        recv(client_fd, payload_buffer + payload_bytes_received,
-             payload_size - payload_bytes_received, 0));
-    if (chunk_bytes <= 0) {
-      return ErrnoError() << "received error polling for message payload";
-    }
-    payload_bytes_received += chunk_bytes;
-  }
-
-  auto msg = std::string(payload_buffer, payload_bytes_received);
-
-  auto requests = StorageRequestMessages{};
-  if (!requests.ParseFromString(msg)) {
-      return Error() << "Could not parse message from aconfig storage init socket";
-  }
-  return requests;
-}
-
-/// send return acknowledgement
-static Result<void> sendMessage(int client_fd, const StorageReturnMessages& msg) {
-  auto content = std::string();
-  if (!msg.SerializeToString(&content)) {
-    return Error() << "failed to serialize return messages to string";
-  }
-
-  unsigned char bytes[4];
-  uint32_t msg_size = content.size();
-  bytes[0] = (msg_size >> 24) & 0xFF;
-  bytes[1] = (msg_size >> 16) & 0xFF;
-  bytes[2] = (msg_size >> 8) & 0xFF;
-  bytes[3] = (msg_size >> 0) & 0xFF;
-
-  int payload_bytes_sent = 0;
-  while (payload_bytes_sent < 4) {
-    auto chunk_bytes = TEMP_FAILURE_RETRY(
-        send(client_fd, bytes + payload_bytes_sent,
-             4 - payload_bytes_sent, 0));
-    if (chunk_bytes <= 0) {
-      return ErrnoError() << "send() failed for return msg size";
-    }
-    payload_bytes_sent += chunk_bytes;
-  }
-
-  payload_bytes_sent = 0;
-  const char* payload_buffer = content.c_str();
-  while (payload_bytes_sent < content.size()) {
-    auto chunk_bytes = TEMP_FAILURE_RETRY(
-        send(client_fd, payload_buffer + payload_bytes_sent,
-             content.size() - payload_bytes_sent, 0));
-    if (chunk_bytes < 0) {
-      return ErrnoError() << "send() failed for return msg";
-    }
-    payload_bytes_sent += chunk_bytes;
-  }
-
-  return {};
-}
-
-static int aconfigd_start() {
-  auto aconfigd = Aconfigd(kAconfigdRootDir,
-                           kPersistentStorageRecordsFileName);
-
-  auto init_result = aconfigd.InitializeInMemoryStorageRecords();
-  if (!init_result.ok()) {
-    LOG(ERROR) << "Failed to initialize persistent storage records in memory: "
-               << init_result.error();
-    return 1;
-  }
-
-  auto aconfigd_fd = android::base::unique_fd(android_get_control_socket(kAconfigdSocket));
-  if (aconfigd_fd == -1) {
-    PLOG(ERROR) << "failed to get aconfigd socket";
-    return 1;
-  }
-
-  if (listen(aconfigd_fd, 8) < 0) {
-    PLOG(ERROR) << "failed to listen to socket";
-    return 1;
-  };
-
-  auto addr = sockaddr_un();
-  addr.sun_family = AF_UNIX;
-  auto path = std::string("/dev/socket/") + kAconfigdSocket;
-  strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
-  socklen_t addr_len = sizeof(addr);
-
-  while(true) {
-    LOG(INFO) << "start accepting client requests";
-    auto client_fd = android::base::unique_fd(accept4(
-        aconfigd_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len, SOCK_CLOEXEC));
-    if (client_fd == -1) {
-      PLOG(ERROR) << "failed to establish connection";
-      continue;
-    }
-    LOG(INFO) << "received client requests";
-
-    auto requests = receiveMessage(client_fd.get());
-    if (!requests.ok()) {
-      LOG(ERROR) << requests.error();
-      continue;
-    }
-
-    auto return_messages = StorageReturnMessages();
-    for (auto& request : requests->msgs()) {
-      auto* return_msg = return_messages.add_msgs();
-      auto result = aconfigd.HandleSocketRequest(request, *return_msg);
-      if (!result.ok()) {
-        auto* errmsg = return_msg->mutable_error_message();
-        *errmsg = result.error().message();
-        LOG(ERROR) << "Failed to handle socket request: " << *errmsg;
-      } else {
-        LOG(INFO) << "Successfully handled socket request";
-      }
-    }
-
-    auto result = sendMessage(client_fd.get(), return_messages);
-    if (!result.ok()) {
-      LOG(ERROR) << result.error();
-    }
-  }
-
-  return 1;
-}
-
-int main(int argc, char** argv) {
-  if (!com::android::aconfig_new_storage::enable_aconfig_storage_daemon()) {
-    return 0;
-  }
-
-  android::base::InitLogging(argv, &android::base::KernelLogger);
-
-  if (argc == 1) {
-    return aconfigd_start();
-  } else if (argc == 2 && strcmp(argv[1], "--platform_init") == 0) {
-    return aconfigd_platform_init();
-  } else if (argc == 2 && strcmp(argv[1], "--mainline_init") == 0) {
-    return aconfigd_mainline_init();
-  } else {
-    LOG(ERROR) << "invalid aconfigd command";
-    return 1;
-  }
-}
diff --git a/aconfigd/aconfigd_proton_collider_test.cpp b/aconfigd/aconfigd_proton_collider_test.cpp
new file mode 100644
index 0000000..62bd488
--- /dev/null
+++ b/aconfigd/aconfigd_proton_collider_test.cpp
@@ -0,0 +1,170 @@
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
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <flag_macros.h>
+#include <gtest/gtest.h>
+
+#include "aconfigd_test_mock.h"
+#include "aconfigd_util.h"
+
+namespace android {
+namespace aconfigd {
+
+class AconfigdProtonColliderTest : public ::testing::Test {
+ protected:
+
+  StorageRequestMessage list_container_storage_message(const std::string& container) {
+    auto message = StorageRequestMessage();
+    auto* msg = message.mutable_list_storage_message();
+    msg->set_container(container);
+    return message;
+  }
+
+  StorageRequestMessage ota_flag_staging_message(
+      const std::string& build_id,
+      const std::vector<std::tuple<std::string, std::string, std::string>> flags) {
+    auto message = StorageRequestMessage();
+    auto* msg = message.mutable_ota_staging_message();
+    msg->set_build_id(build_id);
+    for (auto const& [package_name, flag_name, flag_value] : flags) {
+      auto* flag = msg->add_overrides();
+      flag->set_package_name(package_name);
+      flag->set_flag_name(flag_name);
+      flag->set_flag_value(flag_value);
+    }
+    return message;
+  }
+
+  void verify_ota_staging_return_message(base::Result<StorageReturnMessage> msg_result) {
+    ASSERT_TRUE(msg_result.ok()) << msg_result.error();
+    auto msg = *msg_result;
+    ASSERT_TRUE(msg.has_ota_staging_message()) << msg.error_message();
+  }
+
+  void verify_error_message(base::Result<StorageReturnMessage> msg_result,
+                            const std::string& errmsg) {
+    ASSERT_FALSE(msg_result.ok());
+    ASSERT_TRUE(msg_result.error().message().find(errmsg) != std::string::npos)
+        << msg_result.error().message();
+  }
+}; // class AconfigdProtonColliderTest
+
+
+TEST_F(AconfigdProtonColliderTest, ota_flag_staging) {
+  auto a_mock = AconfigdMock();
+  auto request_msg = ota_flag_staging_message(
+      "mock_build_id",
+      {{"package_1", "flag_1", "true"},
+       {"package_2", "flag_1", "false"}});
+  auto return_msg = a_mock.SendRequestToSocket(request_msg);
+  verify_ota_staging_return_message(return_msg);
+  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
+  auto pb = ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
+      a_mock.flags_dir + "/ota.pb");
+  ASSERT_TRUE(pb.ok());
+  ASSERT_EQ(pb->build_id(), "mock_build_id");
+  auto flags = pb->overrides();
+  ASSERT_EQ(flags.size(), 2);
+  auto flag = pb->overrides(0);
+  ASSERT_EQ(flag.package_name(), "package_1");
+  ASSERT_EQ(flag.flag_name(), "flag_1");
+  ASSERT_EQ(flag.flag_value(), "true");
+  flag = pb->overrides(1);
+  ASSERT_EQ(flag.package_name(), "package_2");
+  ASSERT_EQ(flag.flag_name(), "flag_1");
+  ASSERT_EQ(flag.flag_value(), "false");
+}
+
+TEST_F(AconfigdProtonColliderTest, ota_flag_unstaging) {
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
+TEST_F(AconfigdProtonColliderTest, ota_flag_unstaging_negative) {
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
+} // namespace aconfigd
+} // namespace android
diff --git a/aconfigd/aconfigd_socket_test.cpp b/aconfigd/aconfigd_socket_test.cpp
index 7b262d1..9a5d068 100644
--- a/aconfigd/aconfigd_socket_test.cpp
+++ b/aconfigd/aconfigd_socket_test.cpp
@@ -128,9 +128,9 @@ class AconfigdSocketTest : public ::testing::Test {
     auto* msg = message->mutable_new_storage_message();
     auto test_dir = base::GetExecutableDirectory();
     msg->set_container("mockup");
-    msg->set_package_map(test_dir + "/tests/package.map");
-    msg->set_flag_map(test_dir + "/tests/flag.map");
-    msg->set_flag_value(test_dir + "/tests/flag.val");
+    msg->set_package_map(test_dir + "/tests/data/v1/package.map");
+    msg->set_flag_map(test_dir + "/tests/data/v1/flag.map");
+    msg->set_flag_value(test_dir + "/tests/data/v1/flag.val");
   }
 
   void add_flag_query_message(StorageRequestMessages& messages,
diff --git a/aconfigd/aconfigd_test.cpp b/aconfigd/aconfigd_test.cpp
index 43220ef..7ac2db9 100644
--- a/aconfigd/aconfigd_test.cpp
+++ b/aconfigd/aconfigd_test.cpp
@@ -23,6 +23,7 @@
 #include <gtest/gtest.h>
 #include <sys/stat.h>
 
+#include "aconfigd_test_mock.h"
 #include "aconfigd_util.h"
 #include "com_android_aconfig_new_storage.h"
 
@@ -31,83 +32,27 @@
 namespace android {
 namespace aconfigd {
 
-struct AconfigdMock {
-  TemporaryDir root_dir;
-  const std::string flags_dir;
-  const std::string maps_dir;
-  const std::string boot_dir;
-  const std::string persist_pb;
-  Aconfigd aconfigd;
-
-  AconfigdMock()
-      : root_dir()
-      , flags_dir(std::string(root_dir.path) + "/flags")
-      , maps_dir(std::string(root_dir.path) + "/maps")
-      , boot_dir(std::string(root_dir.path) + "/boot")
-      , persist_pb(std::string(root_dir.path) + "/persist.pb")
-      , aconfigd(root_dir.path, persist_pb) {
-    mkdir(flags_dir.c_str(), 0770);
-    mkdir(maps_dir.c_str(), 0770);
-    mkdir(boot_dir.c_str(), 0775);
-  }
-
-  base::Result<StorageReturnMessage> SendRequestToSocket(
-      const StorageRequestMessage& request) {
-    auto return_msg = StorageReturnMessage();
-    auto result = aconfigd.HandleSocketRequest(request, return_msg);
-    if (!result.ok()) {
-      return base::Error() << result.error();
-    } else {
-      return return_msg;
-    }
-  }
-};
-
-struct ContainerMock {
-  TemporaryDir root_dir;
-  const std::string container;
-  const std::string package_map;
-  const std::string flag_map;
-  const std::string flag_val;
-
-  ContainerMock(const std::string& container_name,
-                const std::string& package_map_file,
-                const std::string& flag_map_file,
-                const std::string& flag_val_file)
-      : root_dir()
-      , container(container_name)
-      , package_map(std::string(root_dir.path) + "/etc/aconfig/package.map")
-      , flag_map(std::string(root_dir.path) + "/etc/aconfig/flag.map")
-      , flag_val(std::string(root_dir.path) + "/etc/aconfig/flag.val") {
-    auto etc_dir = std::string(root_dir.path) + "/etc";
-    auto aconfig_dir = etc_dir + "/aconfig";
-    mkdir(etc_dir.c_str(), 0777);
-    mkdir(aconfig_dir.c_str(), 0777);
-    CopyFile(package_map_file, package_map, 0444);
-    CopyFile(flag_map_file, flag_map, 0444);
-    CopyFile(flag_val_file, flag_val, 0444);
-  }
-};
-
 class AconfigdTest : public ::testing::Test {
  protected:
 
   StorageRequestMessage new_storage_message(const std::string& container,
                                             const std::string& package_map_file,
                                             const std::string& flag_map_file,
-                                            const std::string& flag_value_file) {
+                                            const std::string& flag_value_file,
+                                            const std::string& flag_info_file) {
     auto message = StorageRequestMessage();
     auto* msg = message.mutable_new_storage_message();
     msg->set_container(container);
     msg->set_package_map(package_map_file);
     msg->set_flag_map(flag_map_file);
     msg->set_flag_value(flag_value_file);
+    msg->set_flag_info(flag_info_file);
     return message;
   }
 
   StorageRequestMessage new_storage_message(const ContainerMock& mock) {
-    return new_storage_message(
-        mock.container, mock.package_map, mock.flag_map, mock.flag_val);
+    return new_storage_message(mock.container, mock.package_map, mock.flag_map,
+                               mock.flag_val, mock.flag_info);
   }
 
   StorageRequestMessage flag_override_message(const std::string& package,
@@ -182,21 +127,6 @@ class AconfigdTest : public ::testing::Test {
     return message;
   }
 
-  StorageRequestMessage ota_flag_staging_message(
-      const std::string& build_id,
-      const std::vector<std::tuple<std::string, std::string, std::string>> flags) {
-    auto message = StorageRequestMessage();
-    auto* msg = message.mutable_ota_staging_message();
-    msg->set_build_id(build_id);
-    for (auto const& [package_name, flag_name, flag_value] : flags) {
-      auto* flag = msg->add_overrides();
-      flag->set_package_name(package_name);
-      flag->set_flag_name(flag_name);
-      flag->set_flag_value(flag_value);
-    }
-    return message;
-  }
-
   void verify_new_storage_return_message(base::Result<StorageReturnMessage> msg_result,
                                          bool ensure_updated = false) {
     ASSERT_TRUE(msg_result.ok()) << msg_result.error();
@@ -208,7 +138,8 @@ class AconfigdTest : public ::testing::Test {
     }
   }
 
-  void verify_flag_override_return_message(base::Result<StorageReturnMessage> msg_result) {
+  void verify_flag_override_return_message(
+      base::Result<StorageReturnMessage> msg_result) {
     ASSERT_TRUE(msg_result.ok()) << msg_result.error();
     auto msg = *msg_result;
     ASSERT_TRUE(msg.has_flag_override_message()) << msg.error_message();
@@ -268,12 +199,6 @@ class AconfigdTest : public ::testing::Test {
     ASSERT_TRUE(msg.has_reset_storage_message()) << msg.error_message();
   }
 
-  void verify_ota_staging_return_message(base::Result<StorageReturnMessage> msg_result) {
-    ASSERT_TRUE(msg_result.ok()) << msg_result.error();
-    auto msg = *msg_result;
-    ASSERT_TRUE(msg.has_ota_staging_message()) << msg.error_message();
-  }
-
   void verify_error_message(base::Result<StorageReturnMessage> msg_result,
                             const std::string& errmsg) {
     ASSERT_FALSE(msg_result.ok());
@@ -283,7 +208,8 @@ class AconfigdTest : public ::testing::Test {
 
   void verify_equal_file_content(const std::string& file_one,
                                  const std::string& file_two) {
-
+    ASSERT_TRUE(FileExists(file_one)) << file_one << " does not exist";
+    ASSERT_TRUE(FileExists(file_two)) << file_one << " does not exist";
     auto content_one = std::string();
     auto content_two = std::string();
     ASSERT_TRUE(base::ReadFileToString(file_one, &content_one)) << strerror(errno);
@@ -295,28 +221,34 @@ class AconfigdTest : public ::testing::Test {
   // setup test suites
   static void SetUpTestSuite() {
     auto test_dir = base::GetExecutableDirectory();
-    package_map_ = test_dir + "/tests/package.map";
-    flag_map_ = test_dir + "/tests/flag.map";
-    flag_val_ = test_dir + "/tests/flag.val";
-    updated_package_map_ = test_dir + "/tests/updated_package.map";
-    updated_flag_map_ = test_dir + "/tests/updated_flag.map";
-    updated_flag_val_ = test_dir + "/tests/updated_flag.val";
+    package_map_ = test_dir + "/tests/data/v1/package.map";
+    flag_map_ = test_dir + "/tests/data/v1/flag.map";
+    flag_val_ = test_dir + "/tests/data/v1/flag.val";
+    flag_info_ = test_dir + "/tests/data/v1/flag.info";
+    updated_package_map_ = test_dir + "/tests/data/v2/package.map";
+    updated_flag_map_ = test_dir + "/tests/data/v2/flag.map";
+    updated_flag_val_ = test_dir + "/tests/data/v2/flag.val";
+    updated_flag_info_ = test_dir + "/tests/data/v2/flag.info";
   }
 
   static std::string package_map_;
   static std::string flag_map_;
   static std::string flag_val_;
+  static std::string flag_info_;
   static std::string updated_package_map_;
   static std::string updated_flag_map_;
   static std::string updated_flag_val_;
+  static std::string updated_flag_info_;
 }; // class AconfigdTest
 
 std::string AconfigdTest::package_map_;
 std::string AconfigdTest::flag_map_;
 std::string AconfigdTest::flag_val_;
+std::string AconfigdTest::flag_info_;
 std::string AconfigdTest::updated_package_map_;
 std::string AconfigdTest::updated_flag_map_;
 std::string AconfigdTest::updated_flag_val_;
+std::string AconfigdTest::updated_flag_info_;
 
 TEST_F(AconfigdTest, init_platform_storage_fresh) {
   auto a_mock = AconfigdMock();
@@ -332,23 +264,17 @@ TEST_F(AconfigdTest, init_platform_storage_fresh) {
     auto package_map = std::string(storage_dir) + "/package.map";
     auto flag_map = std::string(storage_dir) + "/flag.map";
     auto flag_val = std::string(storage_dir) + "/flag.val";
+    auto flag_info = std::string(storage_dir) + "/flag.info";
     if (!FileNonZeroSize(flag_val)) {
       continue;
     }
 
-    ASSERT_TRUE(FileExists(a_mock.maps_dir + "/" + container + ".package.map"));
-    ASSERT_TRUE(FileExists(a_mock.maps_dir + "/" + container + ".flag.map"));
-    ASSERT_TRUE(FileExists(a_mock.flags_dir + "/" + container + ".val"));
-    ASSERT_TRUE(FileExists(a_mock.flags_dir + "/" + container + ".info"));
-    ASSERT_TRUE(FileExists(a_mock.boot_dir + "/" + container + ".val"));
-    ASSERT_TRUE(FileExists(a_mock.boot_dir + "/" + container + ".info"));
-
     verify_equal_file_content(a_mock.maps_dir + "/" + container + ".package.map", package_map);
     verify_equal_file_content(a_mock.maps_dir + "/" + container + ".flag.map", flag_map);
     verify_equal_file_content(a_mock.flags_dir + "/" + container + ".val", flag_val);
     verify_equal_file_content(a_mock.boot_dir + "/" + container + ".val", flag_val);
-    verify_equal_file_content(a_mock.flags_dir + "/" + container + ".info",
-                              a_mock.boot_dir + "/" + container + ".info");
+    verify_equal_file_content(a_mock.flags_dir + "/" + container + ".info", flag_info);
+    verify_equal_file_content(a_mock.boot_dir + "/" + container + ".info", flag_info);
   }
 }
 
@@ -356,17 +282,9 @@ TEST_F(AconfigdTest, init_platform_storage_reboot) {
   auto a_mock = AconfigdMock();
   auto init_result = a_mock.aconfigd.InitializePlatformStorage();
   ASSERT_TRUE(init_result.ok()) << init_result.error();
-  auto old_timestamp = GetFileTimeStamp(a_mock.boot_dir + "/system.val");
-  ASSERT_TRUE(old_timestamp.ok()) << old_timestamp.error();
 
-  std::this_thread::sleep_for(std::chrono::milliseconds{10});
   init_result = a_mock.aconfigd.InitializePlatformStorage();
   ASSERT_TRUE(init_result.ok()) << init_result.error();
-  auto new_timestamp = GetFileTimeStamp(a_mock.boot_dir + "/system.val");
-  ASSERT_TRUE(new_timestamp.ok()) << new_timestamp.error();
-
-  // the boot file must be refreshed
-  ASSERT_TRUE(*new_timestamp != *old_timestamp);
 
   auto partitions = std::vector<std::pair<std::string, std::string>>{
     {"system", "/system/etc/aconfig"},
@@ -377,23 +295,17 @@ TEST_F(AconfigdTest, init_platform_storage_reboot) {
     auto package_map = std::string(storage_dir) + "/package.map";
     auto flag_map = std::string(storage_dir) + "/flag.map";
     auto flag_val = std::string(storage_dir) + "/flag.val";
+    auto flag_info = std::string(storage_dir) + "/flag.info";
     if (!FileNonZeroSize(flag_val)) {
       continue;
     }
 
-    ASSERT_TRUE(FileExists(a_mock.maps_dir + "/" + container + ".package.map"));
-    ASSERT_TRUE(FileExists(a_mock.maps_dir + "/" + container + ".flag.map"));
-    ASSERT_TRUE(FileExists(a_mock.flags_dir + "/" + container + ".val"));
-    ASSERT_TRUE(FileExists(a_mock.flags_dir + "/" + container + ".info"));
-    ASSERT_TRUE(FileExists(a_mock.boot_dir + "/" + container + ".val"));
-    ASSERT_TRUE(FileExists(a_mock.boot_dir + "/" + container + ".info"));
-
     verify_equal_file_content(a_mock.maps_dir + "/" + container + ".package.map", package_map);
     verify_equal_file_content(a_mock.maps_dir + "/" + container + ".flag.map", flag_map);
     verify_equal_file_content(a_mock.flags_dir + "/" + container + ".val", flag_val);
     verify_equal_file_content(a_mock.boot_dir + "/" + container + ".val", flag_val);
-    verify_equal_file_content(a_mock.flags_dir + "/" + container + ".info",
-                              a_mock.boot_dir + "/" + container + ".info");
+    verify_equal_file_content(a_mock.flags_dir + "/" + container + ".info", flag_info);
+    verify_equal_file_content(a_mock.boot_dir + "/" + container + ".info", flag_info);
   }
 }
 
@@ -406,21 +318,21 @@ TEST_F(AconfigdTest, init_mainline_storage_fresh) {
 TEST_F(AconfigdTest, add_new_storage) {
   // create mocks
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   // mock a socket request
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  auto digest = GetFilesDigest({c_mock.package_map, c_mock.flag_map, c_mock.flag_val});
+  auto digest = GetFilesDigest(
+      {c_mock.package_map, c_mock.flag_map, c_mock.flag_val, c_mock.flag_info});
   ASSERT_TRUE(digest.ok());
 
   // verify the record exists in persist records pb
   auto persist_records_pb = PersistStorageRecords();
   auto content = std::string();
-  ASSERT_TRUE(base::ReadFileToString(a_mock.persist_pb, &content))
-      << strerror(errno);
+  ASSERT_TRUE(base::ReadFileToString(a_mock.persist_pb, &content)) << strerror(errno);
   ASSERT_TRUE(persist_records_pb.ParseFromString(content)) << strerror(errno);
   bool found = false;
   for (auto& entry : persist_records_pb.records()) {
@@ -430,6 +342,7 @@ TEST_F(AconfigdTest, add_new_storage) {
       ASSERT_EQ(entry.package_map(), c_mock.package_map);
       ASSERT_EQ(entry.flag_map(), c_mock.flag_map);
       ASSERT_EQ(entry.flag_val(), c_mock.flag_val);
+      ASSERT_EQ(entry.flag_info(), c_mock.flag_info);
       ASSERT_EQ(entry.digest(), *digest);
       break;
     }
@@ -437,48 +350,35 @@ TEST_F(AconfigdTest, add_new_storage) {
   ASSERT_TRUE(found);
 
   // verify persist and boot files
-  ASSERT_TRUE(FileExists(a_mock.maps_dir + "/mockup.package.map"));
-  ASSERT_TRUE(FileExists(a_mock.maps_dir + "/mockup.flag.map"));
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/mockup.val"));
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/mockup.info"));
-  ASSERT_TRUE(FileExists(a_mock.boot_dir + "/mockup.val"));
-  ASSERT_TRUE(FileExists(a_mock.boot_dir + "/mockup.info"));
-
   verify_equal_file_content(a_mock.maps_dir + "/mockup.package.map", package_map_);
   verify_equal_file_content(a_mock.maps_dir + "/mockup.flag.map", flag_map_);
   verify_equal_file_content(a_mock.flags_dir + "/mockup.val", flag_val_);
   verify_equal_file_content(a_mock.boot_dir + "/mockup.val", flag_val_);
-  verify_equal_file_content(a_mock.flags_dir + "/mockup.info",
-                            a_mock.boot_dir + "/mockup.info");
+  verify_equal_file_content(a_mock.flags_dir + "/mockup.info", flag_info_);
+  verify_equal_file_content(a_mock.boot_dir + "/mockup.info", flag_info_);
 }
 
 TEST_F(AconfigdTest, container_update_in_ota) {
   // create mocks
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   // mock a socket request
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  // cache current boot flag info content
-  ASSERT_TRUE(FileExists(a_mock.boot_dir + "/mockup.info"));
-  auto boot_flag_info_content = std::string();
-  ASSERT_TRUE(base::ReadFileToString(a_mock.boot_dir + "/mockup.info",
-                                     &boot_flag_info_content));
-
   // mock an ota container update
-  ASSERT_TRUE(CopyFile(updated_package_map_, c_mock.package_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_map_, c_mock.flag_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_val_, c_mock.flag_val, 0444).ok());
+  c_mock.UpdateFiles(
+      updated_package_map_, updated_flag_map_, updated_flag_val_, updated_flag_info_);
 
   // force update
   request_msg = new_storage_message(c_mock);
   return_msg = a_mock.SendRequestToSocket(request_msg);
   verify_new_storage_return_message(return_msg, true);
 
-  auto digest = GetFilesDigest({c_mock.package_map, c_mock.flag_map, c_mock.flag_val});
+  auto digest = GetFilesDigest(
+      {c_mock.package_map, c_mock.flag_map, c_mock.flag_val, c_mock.flag_info});
   ASSERT_TRUE(digest.ok());
 
   // verify the record exists in persist records pb
@@ -495,6 +395,7 @@ TEST_F(AconfigdTest, container_update_in_ota) {
       ASSERT_EQ(entry.package_map(), c_mock.package_map);
       ASSERT_EQ(entry.flag_map(), c_mock.flag_map);
       ASSERT_EQ(entry.flag_val(), c_mock.flag_val);
+      ASSERT_EQ(entry.flag_info(), c_mock.flag_info);
       ASSERT_EQ(entry.digest(), *digest);
       break;
     }
@@ -502,29 +403,19 @@ TEST_F(AconfigdTest, container_update_in_ota) {
   ASSERT_TRUE(found);
 
   // verify persist and boot files
-  ASSERT_TRUE(FileExists(a_mock.maps_dir + "/mockup.package.map"));
-  ASSERT_TRUE(FileExists(a_mock.maps_dir + "/mockup.flag.map"));
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/mockup.val"));
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/mockup.info"));
-  ASSERT_TRUE(FileExists(a_mock.boot_dir + "/mockup.val"));
-  ASSERT_TRUE(FileExists(a_mock.boot_dir + "/mockup.info"));
-
-  verify_equal_file_content(a_mock.maps_dir + "/mockup.package.map",
-                            updated_package_map_);
+  verify_equal_file_content(a_mock.maps_dir + "/mockup.package.map", updated_package_map_);
   verify_equal_file_content(a_mock.maps_dir + "/mockup.flag.map", updated_flag_map_);
   verify_equal_file_content(a_mock.flags_dir + "/mockup.val", updated_flag_val_);
+  verify_equal_file_content(a_mock.flags_dir + "/mockup.info", updated_flag_info_);
 
   // the boot copy should never be updated
   verify_equal_file_content(a_mock.boot_dir + "/mockup.val", flag_val_);
-  auto new_boot_flag_info_content = std::string();
-  ASSERT_TRUE(base::ReadFileToString(a_mock.boot_dir + "/mockup.info",
-                                     &new_boot_flag_info_content));
-  ASSERT_EQ(boot_flag_info_content, new_boot_flag_info_content);
+  verify_equal_file_content(a_mock.boot_dir + "/mockup.info", flag_info_);
 }
 
 TEST_F(AconfigdTest, server_override) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -557,7 +448,7 @@ TEST_F(AconfigdTest, server_override) {
 
 TEST_F(AconfigdTest, server_override_survive_update) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -577,10 +468,8 @@ TEST_F(AconfigdTest, server_override_survive_update) {
       "true", "true", true, true, false);
 
   // mock an ota container update
-  std::this_thread::sleep_for(std::chrono::milliseconds{10});
-  ASSERT_TRUE(CopyFile(updated_package_map_, c_mock.package_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_map_, c_mock.flag_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_val_, c_mock.flag_val, 0444).ok());
+  c_mock.UpdateFiles(
+      updated_package_map_, updated_flag_map_, updated_flag_val_, updated_flag_info_);
 
   // force update
   request_msg = new_storage_message(c_mock);
@@ -600,7 +489,7 @@ TEST_F_WITH_FLAGS(AconfigdTest, local_override_immediate,
                   REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(
                       ACONFIGD_NS, support_immediate_local_overrides))) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -621,7 +510,7 @@ TEST_F_WITH_FLAGS(AconfigdTest, local_override_immediate,
 
 TEST_F(AconfigdTest, local_override) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -654,7 +543,7 @@ TEST_F(AconfigdTest, local_override) {
 
 TEST_F(AconfigdTest, local_override_survive_update) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -674,10 +563,8 @@ TEST_F(AconfigdTest, local_override_survive_update) {
       "true", "true", true, false, true);
 
   // mock an ota container update
-  std::this_thread::sleep_for(std::chrono::milliseconds{10});
-  ASSERT_TRUE(CopyFile(updated_package_map_, c_mock.package_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_map_, c_mock.flag_map, 0444).ok());
-  ASSERT_TRUE(CopyFile(updated_flag_val_, c_mock.flag_val, 0444).ok());
+  c_mock.UpdateFiles(
+      updated_package_map_, updated_flag_map_, updated_flag_val_, updated_flag_info_);
 
   // force update
   request_msg = new_storage_message(c_mock);
@@ -695,7 +582,7 @@ TEST_F(AconfigdTest, local_override_survive_update) {
 
 TEST_F(AconfigdTest, single_local_override_remove) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -738,7 +625,7 @@ TEST_F(AconfigdTest, single_local_override_remove) {
 
 TEST_F(AconfigdTest, readonly_flag_override) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -757,7 +644,7 @@ TEST_F(AconfigdTest, readonly_flag_override) {
 
 TEST_F(AconfigdTest, nonexist_flag_override) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -776,7 +663,7 @@ TEST_F(AconfigdTest, nonexist_flag_override) {
 
 TEST_F(AconfigdTest, nonexist_flag_query) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -793,7 +680,7 @@ TEST_F(AconfigdTest, nonexist_flag_query) {
 
 TEST_F(AconfigdTest, storage_reset) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -835,7 +722,7 @@ TEST_F(AconfigdTest, storage_reset) {
 
 TEST_F(AconfigdTest, list_package) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -872,7 +759,7 @@ TEST_F(AconfigdTest, list_package) {
 
 TEST_F(AconfigdTest, list_container) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -924,7 +811,7 @@ TEST_F(AconfigdTest, list_container) {
 
 TEST_F(AconfigdTest, list_all) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -976,7 +863,7 @@ TEST_F(AconfigdTest, list_all) {
 
 TEST_F(AconfigdTest, list_nonexist_package) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -989,7 +876,7 @@ TEST_F(AconfigdTest, list_nonexist_package) {
 
 TEST_F(AconfigdTest, list_nonexist_container) {
   auto a_mock = AconfigdMock();
-  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_);
+  auto c_mock = ContainerMock("mockup", package_map_, flag_map_, flag_val_, flag_info_);
 
   auto request_msg = new_storage_message(c_mock);
   auto return_msg = a_mock.SendRequestToSocket(request_msg);
@@ -1000,104 +887,5 @@ TEST_F(AconfigdTest, list_nonexist_container) {
   verify_error_message(return_msg, "Missing storage files object");
 }
 
-TEST_F(AconfigdTest, ota_flag_staging) {
-  auto a_mock = AconfigdMock();
-  auto request_msg = ota_flag_staging_message(
-      "mock_build_id",
-      {{"package_1", "flag_1", "true"},
-       {"package_2", "flag_1", "false"}});
-  auto return_msg = a_mock.SendRequestToSocket(request_msg);
-  verify_ota_staging_return_message(return_msg);
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
-  auto pb = ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
-      a_mock.flags_dir + "/ota.pb");
-  ASSERT_TRUE(pb.ok());
-  ASSERT_EQ(pb->build_id(), "mock_build_id");
-  auto flags = pb->overrides();
-  ASSERT_EQ(flags.size(), 2);
-  auto flag = pb->overrides(0);
-  ASSERT_EQ(flag.package_name(), "package_1");
-  ASSERT_EQ(flag.flag_name(), "flag_1");
-  ASSERT_EQ(flag.flag_value(), "true");
-  flag = pb->overrides(1);
-  ASSERT_EQ(flag.package_name(), "package_2");
-  ASSERT_EQ(flag.flag_name(), "flag_1");
-  ASSERT_EQ(flag.flag_value(), "false");
-}
-
-TEST_F(AconfigdTest, ota_flag_unstaging) {
-  // cerate mock aconfigd and initialize platform storage
-  auto a_mock = AconfigdMock();
-  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
-  ASSERT_TRUE(init_result.ok()) << init_result.error();
-
-  auto flags_to_stage =
-      std::vector<std::tuple<std::string, std::string, std::string>>();
-
-  // for fake OTA flag overrides, flip all RW flag value
-  auto request_msg = list_container_storage_message("system");
-  auto return_msg = a_mock.SendRequestToSocket(request_msg);
-  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
-  auto flags_msg = return_msg->list_storage_message();
-
-  for (auto const& flag : flags_msg.flags()) {
-    if (flag.is_readwrite()) {
-      flags_to_stage.push_back({
-          flag.package_name(),
-          flag.flag_name(),
-          flag.server_flag_value() == "true" ? "false" : "true"
-        });
-    }
-  }
-
-  // fake an OTA staging request, using current build id
-  auto build_id = base::GetProperty("ro.build.fingerprint", "");
-  request_msg = ota_flag_staging_message(build_id, flags_to_stage);
-  return_msg = a_mock.SendRequestToSocket(request_msg);
-  verify_ota_staging_return_message(return_msg);
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
-
-  init_result = a_mock.aconfigd.InitializePlatformStorage();
-  ASSERT_TRUE(init_result.ok()) << init_result.error();
-  ASSERT_FALSE(FileExists(a_mock.flags_dir + "/ota.pb"));
-
-  // list container
-  request_msg = list_container_storage_message("system");
-  return_msg = a_mock.SendRequestToSocket(request_msg);
-  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
-  flags_msg = return_msg->list_storage_message();
-
-  size_t i = 0;
-  for (auto const& flag : flags_msg.flags()) {
-    if (flag.is_readwrite()) {
-      ASSERT_EQ(flag.package_name(), std::get<0>(flags_to_stage[i]));
-      ASSERT_EQ(flag.flag_name(), std::get<1>(flags_to_stage[i]));
-      ASSERT_EQ(flag.server_flag_value(), std::get<2>(flags_to_stage[i]));
-      ++i;
-    }
-  }
-}
-
-TEST_F(AconfigdTest, ota_flag_unstaging_negative) {
-  // cerate mock aconfigd and initialize platform storage
-  auto a_mock = AconfigdMock();
-  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
-  ASSERT_TRUE(init_result.ok()) << init_result.error();
-
-  // fake an OTA staging request, using fake build id
-  auto request_msg = ota_flag_staging_message(
-      "some_fake_build_id",
-      {{"abc", "def", "true"}});
-  auto return_msg = a_mock.SendRequestToSocket(request_msg);
-  verify_ota_staging_return_message(return_msg);
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
-
-  init_result = a_mock.aconfigd.InitializePlatformStorage();
-  ASSERT_TRUE(init_result.ok()) << init_result.error();
-
-  // the ota overrides file should still exist
-  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
-}
-
 } // namespace aconfigd
 } // namespace android
diff --git a/aconfigd/aconfigd_test_mock.h b/aconfigd/aconfigd_test_mock.h
new file mode 100644
index 0000000..e2795a6
--- /dev/null
+++ b/aconfigd/aconfigd_test_mock.h
@@ -0,0 +1,101 @@
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
+#include <android-base/file.h>
+
+#include "aconfigd.h"
+#include "aconfigd_util.h"
+
+namespace android {
+namespace aconfigd {
+
+struct AconfigdMock {
+  TemporaryDir root_dir;
+  const std::string flags_dir;
+  const std::string maps_dir;
+  const std::string boot_dir;
+  const std::string persist_pb;
+  Aconfigd aconfigd;
+
+  AconfigdMock()
+      : root_dir()
+      , flags_dir(std::string(root_dir.path) + "/flags")
+      , maps_dir(std::string(root_dir.path) + "/maps")
+      , boot_dir(std::string(root_dir.path) + "/boot")
+      , persist_pb(std::string(root_dir.path) + "/persist.pb")
+      , aconfigd(root_dir.path, persist_pb) {
+    mkdir(flags_dir.c_str(), 0770);
+    mkdir(maps_dir.c_str(), 0770);
+    mkdir(boot_dir.c_str(), 0775);
+  }
+
+  base::Result<StorageReturnMessage> SendRequestToSocket(
+      const StorageRequestMessage& request) {
+    auto return_msg = StorageReturnMessage();
+    auto result = aconfigd.HandleSocketRequest(request, return_msg);
+    if (!result.ok()) {
+      return base::Error() << result.error();
+    } else {
+      return return_msg;
+    }
+  }
+};
+
+struct ContainerMock {
+  TemporaryDir root_dir;
+  const std::string container;
+  const std::string package_map;
+  const std::string flag_map;
+  const std::string flag_val;
+  const std::string flag_info;
+
+  ContainerMock(const std::string& container_name,
+                const std::string& package_map_file,
+                const std::string& flag_map_file,
+                const std::string& flag_val_file,
+                const std::string& flag_info_file)
+      : root_dir()
+      , container(container_name)
+      , package_map(std::string(root_dir.path) + "/etc/aconfig/package.map")
+      , flag_map(std::string(root_dir.path) + "/etc/aconfig/flag.map")
+      , flag_val(std::string(root_dir.path) + "/etc/aconfig/flag.val")
+      , flag_info(std::string(root_dir.path) + "/etc/aconfig/flag.info") {
+    auto etc_dir = std::string(root_dir.path) + "/etc";
+    auto aconfig_dir = etc_dir + "/aconfig";
+    mkdir(etc_dir.c_str(), 0777);
+    mkdir(aconfig_dir.c_str(), 0777);
+    CopyFile(package_map_file, package_map, 0444);
+    CopyFile(flag_map_file, flag_map, 0444);
+    CopyFile(flag_val_file, flag_val, 0444);
+    CopyFile(flag_info_file, flag_info, 0444);
+  }
+
+  void UpdateFiles(const std::string& package_map_file,
+                   const std::string& flag_map_file,
+                   const std::string& flag_val_file,
+                   const std::string& flag_info_file) {
+    CopyFile(package_map_file, package_map, 0444);
+    CopyFile(flag_map_file, flag_map, 0444);
+    CopyFile(flag_val_file, flag_val, 0444);
+    CopyFile(flag_info_file, flag_info, 0444);
+  }
+};
+
+} // namespace aconfigd
+} // namespace android
diff --git a/aconfigd/aconfigd_util.h b/aconfigd/aconfigd_util.h
index ff38a99..7d23f33 100644
--- a/aconfigd/aconfigd_util.h
+++ b/aconfigd/aconfigd_util.h
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#pragma once
+
 #include <string>
 #include <sys/stat.h>
 
diff --git a/aconfigd/build.rs b/aconfigd/build.rs
deleted file mode 100644
index a79f7af..0000000
--- a/aconfigd/build.rs
+++ /dev/null
@@ -1,17 +0,0 @@
-use protobuf_codegen::Codegen;
-
-fn main() {
-    let proto_files = vec!["aconfigd.proto"];
-
-    // tell cargo to only re-run the build script if any of the proto files has changed
-    for path in &proto_files {
-        println!("cargo:rerun-if-changed={}", path);
-    }
-
-    Codegen::new()
-        .pure()
-        .include(".")
-        .inputs(proto_files)
-        .cargo_out_dir("aconfigd_proto")
-        .run_from_script();
-}
diff --git a/aconfigd/aconfigd.h b/aconfigd/include/aconfigd.h
similarity index 100%
rename from aconfigd/aconfigd.h
rename to aconfigd/include/aconfigd.h
diff --git a/aconfigd/lib.rs b/aconfigd/lib.rs
new file mode 100644
index 0000000..2fac912
--- /dev/null
+++ b/aconfigd/lib.rs
@@ -0,0 +1,122 @@
+//! Library for interacting with aconfigd.
+use crate::ffi::{CppAconfigd, CppResultStatus, CppStringResult, CppVoidResult};
+use cxx::{let_cxx_string, CxxString, UniquePtr};
+use std::error::Error;
+use std::fmt;
+
+/// Wrapper for interacting with aconfigd.
+pub struct Aconfigd {
+    cpp_aconfigd: UniquePtr<CppAconfigd>,
+}
+
+impl Aconfigd {
+    /// Create a new Aconfigd.
+    pub fn new(root_dir: &str, persist_storage_records: &str) -> Self {
+        let_cxx_string!(root_dir_ = root_dir);
+        let_cxx_string!(persist_storage_records_ = persist_storage_records);
+        Self { cpp_aconfigd: ffi::new_cpp_aconfigd(&root_dir_, &persist_storage_records_) }
+    }
+
+    /// Create persistent storage files for platform partition.
+    pub fn initialize_platform_storage(&self) -> Result<(), CppAconfigdError> {
+        self.cpp_aconfigd.initialize_platform_storage().into()
+    }
+
+    /// Create persistent storage files for mainline modules.
+    pub fn initialize_mainline_storage(&self) -> Result<(), CppAconfigdError> {
+        self.cpp_aconfigd.initialize_mainline_storage().into()
+    }
+
+    /// Read storage records into memory.
+    pub fn initialize_in_memory_storage_records(&self) -> Result<(), CppAconfigdError> {
+        self.cpp_aconfigd.initialize_in_memory_storage_records().into()
+    }
+
+    /// Process a `StorageRequestMessages`, and return the bytes of a `StorageReturnMessages`.
+    ///
+    /// `messages_bytes` should contain the serialized bytes of a `StorageRequestMessages`.
+    pub fn handle_socket_request(
+        &self,
+        messages_bytes: &[u8],
+    ) -> Result<Vec<u8>, CppAconfigdError> {
+        let_cxx_string!(messages_string_ = messages_bytes);
+        let res: Result<UniquePtr<CxxString>, CppAconfigdError> =
+            self.cpp_aconfigd.handle_socket_request(&messages_string_).into();
+        res.map(|s| s.as_bytes().to_vec())
+    }
+}
+
+/// Represents an error in the C++ aconfigd.
+///
+/// The C++ aconfigd uses the C++ Result type. Result errors are mapped
+/// to this type.
+#[derive(Debug)]
+pub struct CppAconfigdError {
+    msg: String,
+}
+
+impl CppAconfigdError {
+    pub fn new(msg: &str) -> Self {
+        Self { msg: msg.to_string() }
+    }
+}
+
+impl fmt::Display for CppAconfigdError {
+    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        write!(f, "CppAconfigd error: {}", self.msg)
+    }
+}
+
+impl Error for CppAconfigdError {}
+
+#[cxx::bridge(namespace = "aconfigdwrapper")]
+mod ffi {
+    enum CppResultStatus {
+        Ok,
+        Err,
+    }
+
+    struct CppVoidResult {
+        error_message: String,
+        status: CppResultStatus,
+    }
+
+    struct CppStringResult {
+        data: UniquePtr<CxxString>,
+        error_message: String,
+        status: CppResultStatus,
+    }
+
+    unsafe extern "C++" {
+        include!("libcxx_aconfigd.hpp");
+
+        type CppAconfigd;
+
+        fn new_cpp_aconfigd(str1: &CxxString, str2: &CxxString) -> UniquePtr<CppAconfigd>;
+        fn initialize_platform_storage(&self) -> CppVoidResult;
+        fn initialize_mainline_storage(&self) -> CppVoidResult;
+
+        fn initialize_in_memory_storage_records(&self) -> CppVoidResult;
+        fn handle_socket_request(&self, message_string: &CxxString) -> CppStringResult;
+    }
+}
+
+impl Into<Result<(), CppAconfigdError>> for CppVoidResult {
+    fn into(self) -> Result<(), CppAconfigdError> {
+        match self.status {
+            CppResultStatus::Ok => Ok(()),
+            CppResultStatus::Err => Err(CppAconfigdError::new(&self.error_message)),
+            _ => Err(CppAconfigdError::new("unknown status")),
+        }
+    }
+}
+
+impl Into<Result<UniquePtr<CxxString>, CppAconfigdError>> for CppStringResult {
+    fn into(self) -> Result<UniquePtr<CxxString>, CppAconfigdError> {
+        match self.status {
+            CppResultStatus::Ok => Ok(self.data),
+            CppResultStatus::Err => Err(CppAconfigdError::new(&self.error_message)),
+            _ => Err(CppAconfigdError::new("unknown status")),
+        }
+    }
+}
diff --git a/aconfigd/libcxx_aconfigd.cpp b/aconfigd/libcxx_aconfigd.cpp
new file mode 100644
index 0000000..d5e1d46
--- /dev/null
+++ b/aconfigd/libcxx_aconfigd.cpp
@@ -0,0 +1,97 @@
+#include "libcxx_aconfigd.hpp"
+
+#include <stdexcept>
+
+#include "com_android_aconfig_new_storage.h"
+#include "include/aconfigd.h"
+#include "lib.rs.h"
+#include "rust/cxx.h"
+
+namespace aconfigdwrapper {
+
+class CppAconfigd::impl {
+  friend CppAconfigd;
+
+ public:
+  impl(const std::string& root_dir, const std::string& storage_records)
+      : m_aconfigd(std::make_unique<android::aconfigd::Aconfigd>(
+            root_dir, storage_records))
+
+  {}
+
+ private:
+  std::unique_ptr<android::aconfigd::Aconfigd> m_aconfigd;
+};
+
+CppAconfigd::CppAconfigd(const std::string& str1, const std::string& str2)
+    : impl(new class CppAconfigd::impl(str1, str2)) {}
+
+CppVoidResult CppAconfigd::initialize_platform_storage() const {
+  auto init_result = impl->m_aconfigd->InitializePlatformStorage();
+
+  CppVoidResult result;
+  if (!init_result.ok()) {
+    result.error_message = init_result.error().message();
+    result.status = CppResultStatus::Err;
+  } else {
+    result.status = CppResultStatus::Ok;
+  }
+  return result;
+}
+
+CppVoidResult CppAconfigd::initialize_mainline_storage() const {
+  auto init_result = impl->m_aconfigd->InitializeMainlineStorage();
+
+  CppVoidResult result;
+  if (!init_result.ok()) {
+    result.error_message = init_result.error().message();
+    result.status = CppResultStatus::Err;
+  } else {
+    result.status = CppResultStatus::Ok;
+  }
+  return result;
+}
+
+CppVoidResult CppAconfigd::initialize_in_memory_storage_records() const {
+  auto init_result = impl->m_aconfigd->InitializeInMemoryStorageRecords();
+
+  CppVoidResult result;
+  if (!init_result.ok()) {
+    result.error_message = init_result.error().message();
+    result.status = CppResultStatus::Err;
+  } else {
+    result.status = CppResultStatus::Ok;
+  }
+  return result;
+}
+
+CppStringResult CppAconfigd::handle_socket_request(
+    const std::string& messages_string) const {
+  auto request_messages = android::aconfigd::StorageRequestMessages{};
+  request_messages.ParseFromString(messages_string);
+
+  auto return_messages = android::aconfigd::StorageReturnMessages();
+  for (auto& request : request_messages.msgs()) {
+    auto* return_msg = return_messages.add_msgs();
+    auto result = impl->m_aconfigd->HandleSocketRequest(request, *return_msg);
+    if (!result.ok()) {
+      auto* errmsg = return_msg->mutable_error_message();
+      *errmsg = result.error().message();
+    }
+  }
+
+  auto content = std::string();
+  return_messages.SerializeToString(&content);
+
+  CppStringResult result;
+  result.data = std::make_unique<std::string>(content);
+  result.status = CppResultStatus::Ok;
+  return result;
+}
+
+std::unique_ptr<CppAconfigd> new_cpp_aconfigd(const std::string& str1,
+                                              const std::string& str2) {
+  return std::make_unique<CppAconfigd>(str1, str2);
+}
+
+}  // namespace aconfigdwrapper
diff --git a/aconfigd/libcxx_aconfigd.hpp b/aconfigd/libcxx_aconfigd.hpp
new file mode 100644
index 0000000..7a5d2a9
--- /dev/null
+++ b/aconfigd/libcxx_aconfigd.hpp
@@ -0,0 +1,29 @@
+#pragma once
+
+#include "include/aconfigd.h"
+#include "rust/cxx.h"
+
+namespace aconfigdwrapper {
+
+struct CppVoidResult;
+struct CppStringResult;
+enum class CppResultStatus : uint8_t;
+
+class CppAconfigd {
+ public:
+  CppAconfigd(const std::string& aconfigd_root_dir,
+              const std::string& storage_records);
+  CppVoidResult initialize_platform_storage() const;
+  CppVoidResult initialize_mainline_storage() const;
+  CppVoidResult initialize_in_memory_storage_records() const;
+  CppStringResult handle_socket_request(
+      const std::string& messages_string) const;
+
+ private:
+  class impl;
+  std::shared_ptr<impl> impl;
+};
+
+std::unique_ptr<CppAconfigd> new_cpp_aconfigd(const std::string& str1,
+                                              const std::string& str2);
+}  // namespace aconfigdwrapper
diff --git a/aconfigd/new_aconfig_storage.aconfig b/aconfigd/new_aconfig_storage.aconfig
index db92ac0..7351be2 100644
--- a/aconfigd/new_aconfig_storage.aconfig
+++ b/aconfigd/new_aconfig_storage.aconfig
@@ -14,4 +14,30 @@ flag {
     namespace: "core_experiments_team_internal"
     description: "Support immediate local overrides."
     bug: "360205436"
-}
\ No newline at end of file
+}
+
+flag {
+    name: "support_clear_local_overrides_immediately"
+    namespace: "core_experiments_team_internal"
+    description: "Support ability to clear local overrides immediately."
+    bug: "360205436"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+    }
+}
+
+flag {
+    name: "enable_full_rust_system_aconfigd"
+    namespace: "core_experiments_team_internal"
+    description: "enable full rust implementation aconfigd"
+    is_fixed_read_only: true
+    bug: "312444587"
+}
+
+flag {
+  name: "enable_aconfigd_from_mainline"
+  namespace: "core_experiments_team_internal"
+  bug: "369808805"
+  description: "When enabled, launch aconfigd from config infra module."
+  is_fixed_read_only: true
+}
diff --git a/aconfigd/src/aconfigd_commands.rs b/aconfigd/src/aconfigd_commands.rs
new file mode 100644
index 0000000..3455fc0
--- /dev/null
+++ b/aconfigd/src/aconfigd_commands.rs
@@ -0,0 +1,142 @@
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
+use aconfigd_protos::ProtoStorageReturnMessage;
+use aconfigd_rust::aconfigd::Aconfigd;
+use aconfigd_system::Aconfigd as CXXAconfigd;
+use anyhow::{anyhow, bail, Result};
+use log::{debug, error, info};
+use std::io::{Read, Write};
+use std::os::fd::AsRawFd;
+use std::os::unix::net::UnixListener;
+use std::path::Path;
+
+const ACONFIGD_SOCKET: &str = "aconfigd_system";
+const ACONFIGD_ROOT_DIR: &str = "/metadata/aconfig";
+const STORAGE_RECORDS: &str = "/metadata/aconfig/storage_records.pb";
+const PLATFORM_STORAGE_RECORDS: &str = "/metadata/aconfig/platform_storage_records.pb";
+const ACONFIGD_SOCKET_BACKLOG: i32 = 8;
+
+/// start aconfigd socket service
+pub fn start_socket() -> Result<()> {
+    let fd = rustutils::sockets::android_get_control_socket(ACONFIGD_SOCKET)?;
+
+    // SAFETY: Safe because this doesn't modify any memory and we check the return value.
+    let ret = unsafe { libc::listen(fd.as_raw_fd(), ACONFIGD_SOCKET_BACKLOG) };
+    if ret < 0 {
+        bail!(std::io::Error::last_os_error());
+    }
+
+    let listener = UnixListener::from(fd);
+
+    let storage_records = if aconfig_new_storage_flags::enable_aconfigd_from_mainline() {
+        PLATFORM_STORAGE_RECORDS
+    } else {
+        STORAGE_RECORDS
+    };
+
+    if aconfig_new_storage_flags::enable_full_rust_system_aconfigd() {
+        let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(storage_records));
+        aconfigd.initialize_from_storage_record()?;
+
+        debug!("start waiting for a new client connection through socket.");
+        for stream in listener.incoming() {
+            match stream {
+                Ok(mut stream) => {
+                    if let Err(errmsg) = aconfigd.handle_socket_request_from_stream(&mut stream) {
+                        error!("failed to handle socket request: {:?}", errmsg);
+                    }
+                }
+                Err(errmsg) => {
+                    error!("failed to listen for an incoming message: {:?}", errmsg);
+                }
+            }
+        }
+    } else {
+        let aconfigd = CXXAconfigd::new(ACONFIGD_ROOT_DIR, storage_records);
+        aconfigd
+            .initialize_in_memory_storage_records()
+            .map_err(|e| anyhow!("failed to init memory storage records: {e}"))?;
+
+        debug!("start waiting for a new client connection through socket.");
+        for stream in listener.incoming() {
+            match stream {
+                Ok(mut stream) => {
+                    let mut length_buffer = [0u8; 4];
+                    stream.read_exact(&mut length_buffer)?;
+                    let message_length = u32::from_be_bytes(length_buffer);
+
+                    let mut message_buffer = vec![0u8; message_length as usize];
+                    stream.read_exact(&mut message_buffer)?;
+
+                    match aconfigd.handle_socket_request(&message_buffer) {
+                        Ok(response_buffer) => {
+                            let mut response_length_buffer: [u8; 4] = [0; 4];
+                            let response_size = &response_buffer.len();
+                            response_length_buffer[0] = (response_size >> 24) as u8;
+                            response_length_buffer[1] = (response_size >> 16) as u8;
+                            response_length_buffer[2] = (response_size >> 8) as u8;
+                            response_length_buffer[3] = *response_size as u8;
+                            stream.write_all(&response_length_buffer)?;
+                            stream.write_all(&response_buffer)?;
+                        }
+                        Err(e) => {
+                            error!("failed to process socket request: {e}");
+                        }
+                    };
+                }
+                Err(errmsg) => {
+                    error!("failed to listen for an incoming message: {:?}", errmsg);
+                }
+            }
+        }
+    }
+
+    Ok(())
+}
+
+/// initialize mainline module storage files
+pub fn mainline_init() -> Result<()> {
+    if aconfig_new_storage_flags::enable_full_rust_system_aconfigd() {
+        let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(STORAGE_RECORDS));
+        aconfigd.initialize_from_storage_record()?;
+        Ok(aconfigd.initialize_mainline_storage()?)
+    } else {
+        CXXAconfigd::new(ACONFIGD_ROOT_DIR, STORAGE_RECORDS)
+            .initialize_mainline_storage()
+            .map_err(|e| anyhow!("failed to init mainline storage: {e}"))
+    }
+}
+
+/// initialize platform storage files
+pub fn platform_init() -> Result<()> {
+    let storage_records = if aconfig_new_storage_flags::enable_aconfigd_from_mainline() {
+        PLATFORM_STORAGE_RECORDS
+    } else {
+        STORAGE_RECORDS
+    };
+
+    if aconfig_new_storage_flags::enable_full_rust_system_aconfigd() {
+        let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(storage_records));
+        aconfigd.remove_boot_files()?;
+        aconfigd.initialize_from_storage_record()?;
+        Ok(aconfigd.initialize_platform_storage()?)
+    } else {
+        CXXAconfigd::new(ACONFIGD_ROOT_DIR, storage_records)
+            .initialize_platform_storage()
+            .map_err(|e| anyhow!("failed to init platform storage: {e}"))
+    }
+}
diff --git a/aconfigd/src/lib.rs b/aconfigd/src/lib.rs
deleted file mode 100644
index c0ad36f..0000000
--- a/aconfigd/src/lib.rs
+++ /dev/null
@@ -1,70 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-//! Crate containing protos used in aconfigd
-// When building with the Android tool-chain
-//
-//   - an external crate `aconfig_protos` will be generated
-//   - the feature "cargo" will be disabled
-//
-// When building with cargo
-//
-//   - a local sub-module will be generated in OUT_DIR and included in this file
-//   - the feature "cargo" will be enabled
-//
-// This module hides these differences from the rest of aconfig.
-
-// ---- When building with the Android tool-chain ----
-#[cfg(not(feature = "cargo"))]
-mod auto_generated {
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
-    pub use aconfigd_rust_proto::aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
-    pub use aconfigd_rust_proto::aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
-    pub use aconfigd_rust_proto::aconfigd::StorageRequestMessage as ProtoStorageRequestMessage;
-    pub use aconfigd_rust_proto::aconfigd::StorageRequestMessages as ProtoStorageRequestMessages;
-    pub use aconfigd_rust_proto::aconfigd::StorageReturnMessage as ProtoStorageReturnMessage;
-    pub use aconfigd_rust_proto::aconfigd::StorageReturnMessages as ProtoStorageReturnMessages;
-}
-
-// ---- When building with cargo ----
-#[cfg(feature = "cargo")]
-mod auto_generated {
-    // include! statements should be avoided (because they import file contents verbatim), but
-    // because this is only used during local development, and only if using cargo instead of the
-    // Android tool-chain, we allow it
-    include!(concat!(env!("OUT_DIR"), "/aconfigd_proto/mod.rs"));
-    pub use aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
-    pub use aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
-    pub use aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
-    pub use aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
-    pub use aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
-    pub use aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
-    pub use aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
-    pub use aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
-    pub use aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
-    pub use aconfigd::StorageRequestMessage as ProtoStorageRequestMessage;
-    pub use aconfigd::StorageRequestMessages as ProtoStorageRequestMessages;
-    pub use aconfigd::StorageReturnMessage as ProtoStorageReturnMessage;
-    pub use aconfigd::StorageReturnMessages as ProtoStorageReturnMessages;
-}
-
-pub use auto_generated::*;
diff --git a/aconfigd/src/main.rs b/aconfigd/src/main.rs
new file mode 100644
index 0000000..7867f41
--- /dev/null
+++ b/aconfigd/src/main.rs
@@ -0,0 +1,86 @@
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
+//! `aconfigd-mainline` is a daemon binary that responsible for:
+//! (1) initialize mainline storage files
+//! (2) initialize and maintain a persistent socket based service
+
+use clap::Parser;
+use log::{error, info};
+use std::panic;
+
+mod aconfigd_commands;
+
+#[derive(Parser, Debug)]
+struct Cli {
+    #[clap(subcommand)]
+    command: Command,
+}
+
+#[derive(Parser, Debug)]
+enum Command {
+    /// start aconfigd socket.
+    StartSocket,
+
+    /// initialize platform storage files.
+    PlatformInit,
+
+    /// initialize mainline module storage files.
+    MainlineInit,
+}
+
+fn main() {
+    if !aconfig_new_storage_flags::enable_aconfig_storage_daemon() {
+        info!("aconfigd_system is disabled, exiting");
+        std::process::exit(0);
+    }
+
+    // SAFETY: nobody has taken ownership of the inherited FDs yet.
+    // This needs to be called before logger initialization as logger setup will create a
+    // file descriptor.
+    unsafe {
+        if let Err(errmsg) = rustutils::inherited_fd::init_once() {
+            error!("failed to run init_once for inherited fds: {:?}.", errmsg);
+            std::process::exit(1);
+        }
+    };
+
+    // setup android logger, direct to logcat
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("aconfigd_system")
+            .with_max_level(log::LevelFilter::Trace),
+    );
+    info!("starting aconfigd_system commands.");
+
+    let cli = Cli::parse();
+    let command_return = match cli.command {
+        Command::StartSocket => aconfigd_commands::start_socket(),
+        Command::PlatformInit => aconfigd_commands::platform_init(),
+        Command::MainlineInit => {
+            if aconfig_new_storage_flags::enable_aconfigd_from_mainline() {
+                info!("aconfigd_mainline is enabled, skipping mainline init");
+                std::process::exit(1);
+            }
+            aconfigd_commands::mainline_init()
+        }
+    };
+
+    if let Err(errmsg) = command_return {
+        error!("failed to run aconfigd command: {:?}.", errmsg);
+        std::process::exit(1);
+    }
+}
diff --git a/aconfigd/srcs/AconfigdClientSocketImpl.java b/aconfigd/srcs/AconfigdClientSocketImpl.java
index dc6eb75..a2e94e8 100644
--- a/aconfigd/srcs/AconfigdClientSocketImpl.java
+++ b/aconfigd/srcs/AconfigdClientSocketImpl.java
@@ -39,7 +39,9 @@ public class AconfigdClientSocketImpl implements AconfigdClientSocket {
     }
 
     AconfigdClientSocketImpl() {
-        this(new LocalSocketAddress("aconfigd", LocalSocketAddress.Namespace.RESERVED));
+        this(new LocalSocketAddress(
+                     "aconfigd_system",
+                     LocalSocketAddress.Namespace.RESERVED));
     }
 
     /**
diff --git a/aconfigd/srcs/AconfigdJavaUtils.java b/aconfigd/srcs/AconfigdJavaUtils.java
index 607f780..a7f267e 100644
--- a/aconfigd/srcs/AconfigdJavaUtils.java
+++ b/aconfigd/srcs/AconfigdJavaUtils.java
@@ -65,19 +65,37 @@ public class AconfigdJavaUtils {
             String packageName,
             String flagName,
             String flagValue,
-            boolean isLocal) {
+            long overrideType) {
         long msgsToken = proto.start(StorageRequestMessages.MSGS);
         long msgToken = proto.start(StorageRequestMessage.FLAG_OVERRIDE_MESSAGE);
         proto.write(StorageRequestMessage.FlagOverrideMessage.PACKAGE_NAME, packageName);
         proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_NAME, flagName);
         proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_VALUE, flagValue);
-        proto.write(StorageRequestMessage.FlagOverrideMessage.OVERRIDE_TYPE, isLocal
-                ? StorageRequestMessage.LOCAL_ON_REBOOT
-                : StorageRequestMessage.SERVER_ON_REBOOT);
+        proto.write(StorageRequestMessage.FlagOverrideMessage.OVERRIDE_TYPE, overrideType);
         proto.end(msgToken);
         proto.end(msgsToken);
     }
 
+    /**
+     * Send a request to aconfig storage to remove a flag local override.
+     *
+     * @param proto
+     * @param packageName the package of the flag
+     * @param flagName the name of the flag
+     *
+     * @hide
+     */
+    public static void writeFlagOverrideRemovalRequest(
+        ProtoOutputStream proto, String packageName, String flagName) {
+      long msgsToken = proto.start(StorageRequestMessages.MSGS);
+      long msgToken = proto.start(StorageRequestMessage.REMOVE_LOCAL_OVERRIDE_MESSAGE);
+      proto.write(StorageRequestMessage.RemoveLocalOverrideMessage.PACKAGE_NAME, packageName);
+      proto.write(StorageRequestMessage.RemoveLocalOverrideMessage.FLAG_NAME, flagName);
+      proto.write(StorageRequestMessage.RemoveLocalOverrideMessage.REMOVE_ALL, false);
+      proto.end(msgToken);
+      proto.end(msgsToken);
+    }
+
     /**
      * deserialize a flag input proto stream and log
      *
@@ -146,7 +164,12 @@ public class AconfigdJavaUtils {
                 }
                 String packageName = fullFlagName.substring(0, idx);
                 String flagName = fullFlagName.substring(idx + 1);
-                writeFlagOverrideRequest(requests, packageName, flagName, stagedValue, isLocal);
+                long overrideType =
+                        isLocal
+                                ? StorageRequestMessage.LOCAL_ON_REBOOT
+                                : StorageRequestMessage.SERVER_ON_REBOOT;
+                writeFlagOverrideRequest(requests, packageName, flagName, stagedValue,
+                    overrideType);
                 ++num_requests;
             }
         }
@@ -203,7 +226,7 @@ public class AconfigdJavaUtils {
                                     res.end(tokens.pop());
                                     break;
                                 default:
-                                    Slog.w(
+                                    Slog.i(
                                             TAG,
                                             "Could not read undefined field: "
                                                     + res.getFieldNumber());
@@ -215,7 +238,7 @@ public class AconfigdJavaUtils {
                         Slog.w(TAG, "list request failed: " + errmsg);
                         break;
                     default:
-                        Slog.w(TAG, "Could not read undefined field: " + res.getFieldNumber());
+                        Slog.i(TAG, "Could not read undefined field: " + res.getFieldNumber());
                 }
             }
         } catch (IOException e) {
@@ -282,7 +305,7 @@ public class AconfigdJavaUtils {
                                     StorageReturnMessage.FlagQueryReturnMessage.IS_READWRITE));
                     break;
                 default:
-                    Slog.w(
+                    Slog.i(
                             TAG,
                             "Could not read undefined field: " + protoInputStream.getFieldNumber());
             }
diff --git a/aconfigd/storage_files.cpp b/aconfigd/storage_files.cpp
index b5a230a..360fd2c 100644
--- a/aconfigd/storage_files.cpp
+++ b/aconfigd/storage_files.cpp
@@ -35,6 +35,7 @@ namespace android {
                              const std::string& package_map,
                              const std::string& flag_map,
                              const std::string& flag_val,
+                             const std::string& flag_info,
                              const std::string& root_dir,
                              base::Result<void>& status)
       : container_(container)
@@ -52,7 +53,7 @@ namespace android {
       return;
     }
 
-    auto digest = GetFilesDigest({package_map, flag_map, flag_val});
+    auto digest = GetFilesDigest({package_map, flag_map, flag_val, flag_info});
     if (!digest.ok()) {
       status = base::Error() << "failed to get files digest: " << digest.error();
       return;
@@ -63,6 +64,7 @@ namespace android {
     storage_record_.package_map = package_map;
     storage_record_.flag_map = flag_map;
     storage_record_.flag_val = flag_val;
+    storage_record_.flag_info = flag_info;
     storage_record_.persist_package_map =
         root_dir + "/maps/" + container + ".package.map";
     storage_record_.persist_flag_map =
@@ -103,12 +105,11 @@ namespace android {
       return;
     }
 
-    // create flag info file
-    auto create_result = create_flag_info(
-        package_map, flag_map, storage_record_.persist_flag_info);
-    if (!create_result.ok()) {
-      status = base::Error() << "failed to create flag info file for " << container
-                             << create_result.error();
+    // copy flag info file
+    copy_result = CopyFile(flag_info, storage_record_.persist_flag_info, 0644);
+    if (!copy_result.ok()) {
+      status = base::Error() << "CopyFile failed for " << flag_info << ": "
+                             << copy_result.error();
       return;
     }
   }
@@ -130,6 +131,12 @@ namespace android {
     storage_record_.package_map = pb.package_map();
     storage_record_.flag_map = pb.flag_map();
     storage_record_.flag_val = pb.flag_val();
+    if (pb.has_flag_info()) {
+      storage_record_.flag_info = pb.flag_info();
+    } else {
+      auto val_file = storage_record_.flag_val;
+      storage_record_.flag_info = val_file.substr(0, val_file.size()-3) + "info";
+    }
     storage_record_.persist_package_map =
         root_dir + "/maps/" + pb.container() + ".package.map";
     storage_record_.persist_flag_map =
@@ -623,21 +630,37 @@ namespace android {
     return {};
   }
 
-  /// Write override immediately to boot copy.
-  base::Result<void> StorageFiles::WriteLocalOverrideToBootCopy(
-      const PackageFlagContext& context, const std::string& flag_value) {
+  /// Set value and has_local_override for boot copy immediately.
+  base::Result<void> StorageFiles::UpdateBootValueAndInfoImmediately(
+      const PackageFlagContext& context, const std::string& flag_value,
+      bool has_local_override) {
     if (chmod(storage_record_.boot_flag_val.c_str(), 0644) == -1) {
-      return base::ErrnoError() << "chmod() failed to set to 0644";
+      return base::ErrnoError() << "chmod() failed to set boot val to 0644";
     }
 
     auto flag_value_file =
         map_mutable_storage_file(storage_record_.boot_flag_val);
     auto update_result = set_boolean_flag_value(
         **flag_value_file, context.flag_index, flag_value == "true");
-    RETURN_IF_ERROR(update_result, "Failed to update flag value");
+    RETURN_IF_ERROR(update_result, "Failed to update boot flag value");
 
     if (chmod(storage_record_.boot_flag_val.c_str(), 0444) == -1) {
-      return base::ErrnoError() << "chmod() failed to set to 0444";
+      return base::ErrnoError() << "chmod() failed to set boot val to 0444";
+    }
+
+    if (chmod(storage_record_.boot_flag_info.c_str(), 0644) == -1) {
+      return base::ErrnoError() << "chmod() failed to set boot info to 0644";
+    }
+
+    auto flag_info_file =
+        map_mutable_storage_file(storage_record_.boot_flag_info);
+    auto update_info_result =
+        set_flag_has_local_override(**flag_info_file, context.value_type,
+                                    context.flag_index, has_local_override);
+    RETURN_IF_ERROR(update_info_result, "Failed to update boot flag info");
+
+    if (chmod(storage_record_.boot_flag_info.c_str(), 0444) == -1) {
+      return base::ErrnoError() << "chmod() failed to set boot info to 0444";
     }
 
     return {};
@@ -739,8 +762,7 @@ namespace android {
 
   /// remove a single flag local override, return if removed
   base::Result<bool> StorageFiles::RemoveLocalFlagValue(
-      const PackageFlagContext& context) {
-
+      const PackageFlagContext& context, bool immediate) {
     auto pb_file = storage_record_.local_overrides;
     auto pb = ReadPbFromFile<LocalFlagOverrides>(pb_file);
     if (!pb.ok()) {
@@ -759,6 +781,7 @@ namespace android {
       kept_override->set_flag_value(entry.flag_value());
     }
 
+    bool return_result;
     if (remaining_overrides.overrides_size() != pb->overrides_size()) {
       auto result = WritePbToFile<LocalFlagOverrides>(remaining_overrides, pb_file);
       if (!result.ok()) {
@@ -768,14 +791,32 @@ namespace android {
       auto update = SetHasLocalOverride(context, false);
       RETURN_IF_ERROR(update, "Failed to unset flag has local override");
 
-      return true;
+      return_result = true;
     } else {
-      return false;
+      return_result = false;
+    }
+
+    if (immediate) {
+      auto attribute = GetFlagAttribute(context);
+      RETURN_IF_ERROR(
+          attribute,
+          "Failed to get flag attribute for removing override immediately");
+
+      auto value = ((*attribute) & FlagInfoBit::HasServerOverride)
+                       ? GetServerFlagValue(context)
+                       : GetDefaultFlagValue(context);
+      RETURN_IF_ERROR(value, "Failed to get server or default value");
+
+      auto update = UpdateBootValueAndInfoImmediately(context, *value, false);
+      RETURN_IF_ERROR(update,
+                      "Failed to remove local override boot flag value");
     }
+
+    return return_result;
   }
 
   /// remove all local overrides
-  base::Result<void> StorageFiles::RemoveAllLocalFlagValue() {
+  base::Result<void> StorageFiles::RemoveAllLocalFlagValue(bool immediate) {
     auto pb_file = storage_record_.local_overrides;
     auto overrides_pb = ReadPbFromFile<LocalFlagOverrides>(pb_file);
     RETURN_IF_ERROR(overrides_pb, "Failed to read local overrides");
@@ -787,6 +828,23 @@ namespace android {
 
       auto update = SetHasLocalOverride(*context, false);
       RETURN_IF_ERROR(update, "Failed to unset flag has local override");
+
+      if (immediate) {
+        auto attribute = GetFlagAttribute(*context);
+        RETURN_IF_ERROR(
+            attribute,
+            "Failed to get flag attribute for removing override immediately");
+
+        auto value = ((*attribute) & FlagInfoBit::HasServerOverride)
+                         ? GetServerFlagValue(*context)
+                         : GetDefaultFlagValue(*context);
+        RETURN_IF_ERROR(value, "Failed to get server or default value");
+
+        auto boot_update =
+            UpdateBootValueAndInfoImmediately(*context, *value, false);
+        RETURN_IF_ERROR(boot_update,
+                        "Failed to remove local override boot flag value");
+      }
     }
 
     if (overrides_pb->overrides_size()) {
@@ -965,19 +1023,20 @@ namespace android {
     }
 
     // fill boot value
-    listed_flags = list_flags(storage_record_.package_map,
-                              storage_record_.flag_map,
-                              storage_record_.boot_flag_val);
-    RETURN_IF_ERROR(
-        listed_flags, "Failed to list boot flags for " + storage_record_.container);
+    auto listed_flags_boot = list_flags_with_info(
+        storage_record_.package_map, storage_record_.flag_map,
+        storage_record_.boot_flag_val, storage_record_.boot_flag_info);
+    RETURN_IF_ERROR(listed_flags_boot, "Failed to list boot flags for " +
+                                           storage_record_.container);
 
-    for (auto const& flag : *listed_flags) {
+    for (auto const& flag : *listed_flags_boot) {
       auto full_flag_name = flag.package_name + "/" + flag.flag_name;
       if (!idxs.count(full_flag_name)) {
         continue;
       }
       auto idx = idxs[full_flag_name];
       snapshots[idx].boot_flag_value = std::move(flag.flag_value);
+      snapshots[idx].has_boot_local_override = flag.has_local_override;
     }
 
     // fill server value and attribute
diff --git a/aconfigd/storage_files.h b/aconfigd/storage_files.h
index 6de608c..f7cd41d 100644
--- a/aconfigd/storage_files.h
+++ b/aconfigd/storage_files.h
@@ -34,6 +34,7 @@ namespace android {
       std::string package_map;          // package.map on container
       std::string flag_map;             // flag.map on container
       std::string flag_val;             // flag.val on container
+      std::string flag_info;            // flag.info on container
       std::string persist_package_map;  // persist package.map (backup copy for OTA)
       std::string persist_flag_map;     // persist flag.map (backup copy for OTA)
       std::string persist_flag_val;     // persist flag.val
@@ -53,6 +54,7 @@ namespace android {
                    const std::string& package_map,
                    const std::string& flag_map,
                    const std::string& flag_val,
+                   const std::string& flag_info,
                    const std::string& root_dir,
                    base::Result<void>& status);
 
@@ -129,9 +131,10 @@ namespace android {
       base::Result<void> SetServerFlagValue(const PackageFlagContext& context,
                                             const std::string& flag_value);
 
-      /// write local override to boot flag file immediately
-      base::Result<void> WriteLocalOverrideToBootCopy(
-          const PackageFlagContext& context, const std::string& flag_value);
+      /// Set boot value and local_override info immediately
+      base::Result<void> UpdateBootValueAndInfoImmediately(
+          const PackageFlagContext& context, const std::string& flag_value,
+          bool has_local_override);
 
       /// local flag override, update local flag override pb filee
       base::Result<void> SetLocalFlagValue(const PackageFlagContext& context,
@@ -146,10 +149,11 @@ namespace android {
                                              bool has_local_override);
 
       /// remove a single flag local override, return if removed
-      base::Result<bool> RemoveLocalFlagValue(const PackageFlagContext& context);
+      base::Result<bool> RemoveLocalFlagValue(const PackageFlagContext& context,
+                                              bool immediate);
 
       /// remove all local overrides
-      base::Result<void> RemoveAllLocalFlagValue();
+      base::Result<void> RemoveAllLocalFlagValue(bool immediate);
 
       /// strcut for server flag value entries
       struct ServerOverride {
@@ -178,6 +182,7 @@ namespace android {
         bool is_readwrite;
         bool has_server_override;
         bool has_local_override;
+        bool has_boot_local_override;
       };
 
       /// list a flag
diff --git a/aconfigd/storage_files_manager.cpp b/aconfigd/storage_files_manager.cpp
index 84eb355..68185d5 100644
--- a/aconfigd/storage_files_manager.cpp
+++ b/aconfigd/storage_files_manager.cpp
@@ -17,6 +17,8 @@
 
 #include "storage_files_manager.h"
 
+#include <android-base/logging.h>
+
 #include "aconfigd.h"
 #include "aconfigd_util.h"
 #include "com_android_aconfig_new_storage.h"
@@ -40,14 +42,15 @@ namespace android {
       const std::string& container,
       const std::string& package_map,
       const std::string& flag_map,
-      const std::string& flag_val) {
+      const std::string& flag_val,
+      const std::string& flag_info) {
     if (all_storage_files_.count(container)) {
       return base::Error() << "Storage file object for " << container << " already exists";
     }
 
     auto result = base::Result<void>({});
     auto storage_files = std::make_unique<StorageFiles>(
-          container, package_map, flag_map, flag_val, root_dir_, result);
+          container, package_map, flag_map, flag_val, flag_info, root_dir_, result);
 
     if (!result.ok()) {
       return base::Error() << "Failed to create storage file object for " << container
@@ -76,7 +79,8 @@ namespace android {
       const std::string& container,
       const std::string& package_map,
       const std::string& flag_map,
-      const std::string& flag_val) {
+      const std::string& flag_val,
+      const std::string& flag_info) {
     if (!all_storage_files_.count(container)) {
       return base::Error() << "Failed to update storage files object for " << container
                      << ", it does not exist";
@@ -95,7 +99,8 @@ namespace android {
     // clean up existing storage files object and recreate
     (**storage_files).RemoveAllPersistFiles();
     all_storage_files_.erase(container);
-    storage_files = AddNewStorageFiles(container, package_map, flag_map, flag_val);
+    storage_files = AddNewStorageFiles(
+        container, package_map, flag_map, flag_val, flag_info);
     RETURN_IF_ERROR(storage_files, "Failed to add a new storage object for " + container);
 
     // reapply local overrides
@@ -145,11 +150,12 @@ namespace android {
       const std::string& container,
       const std::string& package_map,
       const std::string& flag_map,
-      const std::string& flag_val) {
+      const std::string& flag_val,
+      const std::string& flag_info) {
     bool new_container = !HasContainer(container);
     bool update_existing_container = false;
     if (!new_container) {
-      auto digest = GetFilesDigest({package_map, flag_map, flag_val});
+      auto digest = GetFilesDigest({package_map, flag_map, flag_val, flag_info});
       RETURN_IF_ERROR(digest, "Failed to get digest for " + container);
       auto storage_files = GetStorageFiles(container);
       RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
@@ -165,11 +171,11 @@ namespace android {
 
     if (new_container) {
       auto storage_files = AddNewStorageFiles(
-          container, package_map, flag_map, flag_val);
+          container, package_map, flag_map, flag_val, flag_info);
       RETURN_IF_ERROR(storage_files, "Failed to add a new storage object for " + container);
     } else {
       auto storage_files = UpdateStorageFiles(
-          container, package_map, flag_map, flag_val);
+          container, package_map, flag_map, flag_val, flag_info);
       RETURN_IF_ERROR(storage_files, "Failed to update storage object for " + container);
     }
 
@@ -201,7 +207,7 @@ namespace android {
 
       if (available) {
         auto storage_files = AddNewStorageFiles(
-            container, record.package_map, record.flag_map, record.flag_val);
+            container, record.package_map, record.flag_map, record.flag_val, record.flag_info);
         RETURN_IF_ERROR(storage_files, "Failed to add a new storage object for " + container);
       }
     }
@@ -258,6 +264,7 @@ namespace android {
       record_pb->set_package_map(record.package_map);
       record_pb->set_flag_map(record.flag_map);
       record_pb->set_flag_val(record.flag_val);
+      record_pb->set_flag_info(record.flag_info);
       record_pb->set_digest(record.digest);
     }
     return WritePbToFile<PersistStorageRecords>(records_pb, file_name);
@@ -290,17 +297,12 @@ namespace android {
         break;
       }
       case StorageRequestMessage::LOCAL_IMMEDIATE: {
-        if (!com::android::aconfig_new_storage::
-                support_immediate_local_overrides()) {
-          return base::Error() << "local immediate override not supported";
-        }
-
         auto updateOverride =
             (**storage_files).SetLocalFlagValue(*context, flag_value);
         RETURN_IF_ERROR(updateOverride, "Failed to set local flag override");
         auto updateBootFile =
             (**storage_files)
-                .WriteLocalOverrideToBootCopy(*context, flag_value);
+                .UpdateBootValueAndInfoImmediately(*context, flag_value, true);
         RETURN_IF_ERROR(updateBootFile,
                         "Failed to write local override to boot file");
         break;
@@ -327,8 +329,10 @@ namespace android {
         auto result = UpdateFlagValue(entry.package_name(),
                                       entry.flag_name(),
                                       entry.flag_value());
-        RETURN_IF_ERROR(result, "Failed to apply staged OTA flag " + entry.package_name()
-                        + "/" + entry.flag_name());
+        if (!result.ok()) {
+          LOG(ERROR) << "Failed to apply staged OTA flag " << entry.package_name()
+                     << "/" << entry.flag_name() << ": " << result.error();
+        }
       } else {
         remaining_ota_flags.push_back(entry);
       }
@@ -338,9 +342,12 @@ namespace android {
   }
 
   /// remove all local overrides
-  base::Result<void> StorageFilesManager::RemoveAllLocalOverrides() {
+  base::Result<void> StorageFilesManager::RemoveAllLocalOverrides(
+      const StorageRequestMessage::RemoveOverrideType remove_override_type) {
     for (const auto& [container, storage_files] : all_storage_files_) {
-      auto update = storage_files->RemoveAllLocalFlagValue();
+      bool immediate =
+          remove_override_type == StorageRequestMessage::REMOVE_LOCAL_IMMEDIATE;
+      auto update = storage_files->RemoveAllLocalFlagValue(immediate);
       RETURN_IF_ERROR(update, "Failed to remove local overrides for " + container);
     }
     return {};
@@ -348,8 +355,8 @@ namespace android {
 
   /// remove a local override
   base::Result<void> StorageFilesManager::RemoveFlagLocalOverride(
-      const std::string& package,
-      const std::string& flag) {
+      const std::string& package, const std::string& flag,
+      const StorageRequestMessage::RemoveOverrideType remove_override_type) {
     auto container = GetContainer(package);
     RETURN_IF_ERROR(container, "Failed to find owning container");
 
@@ -359,7 +366,9 @@ namespace android {
     auto context = (**storage_files).GetPackageFlagContext(package, flag);
     RETURN_IF_ERROR(context, "Failed to find package flag context");
 
-    auto removed = (**storage_files).RemoveLocalFlagValue(*context);
+    bool immediate =
+        remove_override_type == StorageRequestMessage::REMOVE_LOCAL_IMMEDIATE;
+    auto removed = (**storage_files).RemoveLocalFlagValue(*context, immediate);
     RETURN_IF_ERROR(removed, "Failed to remove local override");
 
     return {};
diff --git a/aconfigd/storage_files_manager.h b/aconfigd/storage_files_manager.h
index f90c91c..0483128 100644
--- a/aconfigd/storage_files_manager.h
+++ b/aconfigd/storage_files_manager.h
@@ -68,7 +68,8 @@ namespace android {
       base::Result<StorageFiles*> AddNewStorageFiles(const std::string& container,
                                                      const std::string& package_map,
                                                      const std::string& flag_map,
-                                                     const std::string& flag_val);
+                                                     const std::string& flag_val,
+                                                     const std::string& flag_info);
 
       /// restore storage files object from a storage record pb entry
       base::Result<void> RestoreStorageFiles(const PersistStorageRecord& pb);
@@ -77,13 +78,15 @@ namespace android {
       base::Result<void> UpdateStorageFiles(const std::string& container,
                                             const std::string& package_map,
                                             const std::string& flag_map,
-                                            const std::string& flag_val);
+                                            const std::string& flag_val,
+                                            const std::string& flag_info);
 
       /// add or update storage file set for a container
       base::Result<bool> AddOrUpdateStorageFiles(const std::string& container,
                                                  const std::string& package_map,
                                                  const std::string& flag_map,
-                                                 const std::string& flag_val);
+                                                 const std::string& flag_val,
+                                                 const std::string& flag_info);
 
       /// create boot copy
       base::Result<void> CreateStorageBootCopy(const std::string& container);
@@ -117,11 +120,13 @@ namespace android {
           const std::vector<FlagOverride>& ota_flags);
 
       /// remove all local overrides
-      base::Result<void> RemoveAllLocalOverrides();
+      base::Result<void> RemoveAllLocalOverrides(
+          const StorageRequestMessage::RemoveOverrideType removeOverrideType);
 
       /// remove a local override
-      base::Result<void> RemoveFlagLocalOverride(const std::string& package,
-                                                 const std::string& flag);
+      base::Result<void> RemoveFlagLocalOverride(
+          const std::string& package, const std::string& flag,
+          const StorageRequestMessage::RemoveOverrideType removeOverrideType);
 
       /// list a flag
       base::Result<StorageFiles::FlagSnapshot> ListFlag(const std::string& package,
diff --git a/aconfigd/tests/data/v1/flag.info b/aconfigd/tests/data/v1/flag.info
new file mode 100644
index 0000000..6223edf
Binary files /dev/null and b/aconfigd/tests/data/v1/flag.info differ
diff --git a/aconfigd/tests/flag.map b/aconfigd/tests/data/v1/flag.map
similarity index 80%
rename from aconfigd/tests/flag.map
rename to aconfigd/tests/data/v1/flag.map
index cf4685c..e868f53 100644
Binary files a/aconfigd/tests/flag.map and b/aconfigd/tests/data/v1/flag.map differ
diff --git a/aconfigd/tests/data/v1/flag.val b/aconfigd/tests/data/v1/flag.val
new file mode 100644
index 0000000..ed203d4
Binary files /dev/null and b/aconfigd/tests/data/v1/flag.val differ
diff --git a/aconfigd/tests/data/v1/package.map b/aconfigd/tests/data/v1/package.map
new file mode 100644
index 0000000..6c46a03
Binary files /dev/null and b/aconfigd/tests/data/v1/package.map differ
diff --git a/aconfigd/tests/data/v2/flag.info b/aconfigd/tests/data/v2/flag.info
new file mode 100644
index 0000000..06e464f
Binary files /dev/null and b/aconfigd/tests/data/v2/flag.info differ
diff --git a/aconfigd/tests/updated_flag.map b/aconfigd/tests/data/v2/flag.map
similarity index 81%
rename from aconfigd/tests/updated_flag.map
rename to aconfigd/tests/data/v2/flag.map
index e4c608c..38aebde 100644
Binary files a/aconfigd/tests/updated_flag.map and b/aconfigd/tests/data/v2/flag.map differ
diff --git a/aconfigd/tests/data/v2/flag.val b/aconfigd/tests/data/v2/flag.val
new file mode 100644
index 0000000..6e9f652
Binary files /dev/null and b/aconfigd/tests/data/v2/flag.val differ
diff --git a/aconfigd/tests/data/v2/package.map b/aconfigd/tests/data/v2/package.map
new file mode 100644
index 0000000..dc0be2b
Binary files /dev/null and b/aconfigd/tests/data/v2/package.map differ
diff --git a/aconfigd/tests/flag.val b/aconfigd/tests/flag.val
deleted file mode 100644
index 37d4750..0000000
Binary files a/aconfigd/tests/flag.val and /dev/null differ
diff --git a/aconfigd/tests/package.map b/aconfigd/tests/package.map
deleted file mode 100644
index 358010c..0000000
Binary files a/aconfigd/tests/package.map and /dev/null differ
diff --git a/aconfigd/tests/updated_flag.val b/aconfigd/tests/updated_flag.val
deleted file mode 100644
index 041f435..0000000
Binary files a/aconfigd/tests/updated_flag.val and /dev/null differ
diff --git a/aconfigd/tests/updated_package.map b/aconfigd/tests/updated_package.map
deleted file mode 100644
index 782d837..0000000
Binary files a/aconfigd/tests/updated_package.map and /dev/null differ
```

