```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 5f4e5dc..9600834 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,7 +1,10 @@
 {
   "postsubmit": [
-     {
-       "name": "ConfigInfrastructureServiceUnitTests"
-     }
+    {
+      "name": "ConfigInfrastructureServiceUnitTests"
+    },
+    {
+      "name": "AconfigPackageTests"
+    }
   ]
-}
+}
\ No newline at end of file
diff --git a/aconfigd/Android.bp b/aconfigd/Android.bp
new file mode 100644
index 0000000..e92f7ac
--- /dev/null
+++ b/aconfigd/Android.bp
@@ -0,0 +1,81 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+rust_defaults {
+    name: "aconfigd_rust.defaults",
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
+        "libopenssl",
+        "liblog_rust",
+        "libprotobuf",
+        "libthiserror",
+        "librustutils",
+    ],
+    apex_available: [
+        "com.android.configinfrastructure",
+        "//apex_available:platform",
+    ],
+    min_sdk_version: "34",
+}
+
+rust_library {
+    name: "libaconfigd_rust",
+    crate_name: "aconfigd_rust",
+    defaults: ["aconfigd_rust.defaults"],
+    srcs: ["src/lib.rs"],
+}
+
+rust_binary {
+    name: "aconfigd-mainline",
+    defaults: ["aconfigd_rust.defaults"],
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libaconfigd_rust",
+        "libandroid_logger",
+        "liblibc",
+        "libaconfig_new_storage_flags_rust",
+    ],
+}
+
+rust_test {
+    name: "libaconfigd_rust.test",
+    team: "trendy_team_android_core_experiments",
+    test_suites: [
+        "general-tests",
+    ],
+    defaults: ["aconfigd_rust.defaults"],
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libtempfile",
+    ],
+    data: [
+        "./tests/data/package.map",
+        "./tests/data/flag.map",
+        "./tests/data/flag.val",
+        "./tests/data/flag.info",
+        "./tests/data/container_with_more_flags.package.map",
+        "./tests/data/container_with_more_flags.flag.map",
+        "./tests/data/container_with_more_flags.flag.val",
+        "./tests/data/container_with_more_flags.flag.info",
+    ],
+    require_root: true
+}
diff --git a/aconfigd/Cargo.toml b/aconfigd/Cargo.toml
new file mode 100644
index 0000000..0a5a8b7
--- /dev/null
+++ b/aconfigd/Cargo.toml
@@ -0,0 +1,31 @@
+[package]
+name = "aconfigd_mainline"
+version = "0.1.0"
+edition = "2021"
+
+[features]
+default = ["cargo"]
+cargo = []
+
+[dependencies]
+anyhow = "1.0.69"
+protobuf = "3.2.0"
+thiserror = "1.0.56"
+clap = { version = "4.1.8", features = ["derive"] }
+memmap2 = "0.8.0"
+tempfile = "3.13.0"
+log = "0.4"
+android_logger = "0.13"
+libc = "0.2"
+aconfig_storage_file = {path = "../../../../build/tools/aconfig/aconfig_storage_file"}
+aconfig_storage_read_api = {path = "../../../../build/tools/aconfig/aconfig_storage_read_api"}
+aconfig_storage_write_api = {path = "../../../../build/tools/aconfig/aconfig_storage_write_api"}
+aconfigd_protos = {path = "./proto"}
+openssl = "0.10.68"
+
+[[bin]]
+name = "aconfigd-mainline"
+path = "src/main.rs"
+
+[build-dependencies]
+protobuf-codegen = "3.2.0"
diff --git a/aconfigd/TEST_MAPPING b/aconfigd/TEST_MAPPING
new file mode 100644
index 0000000..ac41c46
--- /dev/null
+++ b/aconfigd/TEST_MAPPING
@@ -0,0 +1,8 @@
+{
+  "postsubmit": [
+    {
+      // rust aconfigd unit tests
+      "name": "libaconfigd_rust.test"
+    }
+  ]
+}
diff --git a/aconfigd/proto/Android.bp b/aconfigd/proto/Android.bp
new file mode 100644
index 0000000..61c3b20
--- /dev/null
+++ b/aconfigd/proto/Android.bp
@@ -0,0 +1,108 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+filegroup {
+    name: "aconfigd_protos",
+    srcs: ["aconfigd.proto"],
+}
+
+rust_protobuf {
+    name: "libaconfigd_rust_proto",
+    crate_name: "aconfigd_rust_proto",
+    source_stem: "aconfigd_rust_proto_source",
+    protos: [
+        "aconfigd.proto",
+    ],
+    host_supported: true,
+    min_sdk_version: "34",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
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
+    min_sdk_version: "34",
+}
+
+rust_library {
+    name: "libaconfigd_protos_rust",
+    crate_name: "aconfigd_protos",
+    defaults: ["aconfigd_protos.defaults"],
+    host_supported: true,
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
+
+cc_library_static {
+    name: "libaconfigd_protos_cc",
+    proto: {
+        export_proto_headers: true,
+        type: "lite",
+    },
+    srcs: ["aconfigd.proto"],
+    min_sdk_version: "34",
+    visibility: [
+        "//system/server_configurable_flags/aconfigd",
+    ],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
+
+java_library {
+    name: "aconfigd_java_proto_lib",
+    host_supported: true,
+    srcs: ["aconfigd.proto"],
+    proto: {
+        type: "stream",
+    },
+    sdk_version: "current",
+    min_sdk_version: "UpsideDownCake",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
+
+java_library {
+    name: "aconfigd_java_proto_lite_lib",
+    host_supported: true,
+    srcs: ["aconfigd.proto"],
+    proto: {
+        type: "lite",
+    },
+    sdk_version: "core_current",
+    min_sdk_version: "UpsideDownCake",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
diff --git a/aconfigd/proto/Cargo.toml b/aconfigd/proto/Cargo.toml
new file mode 100644
index 0000000..e04b7c9
--- /dev/null
+++ b/aconfigd/proto/Cargo.toml
@@ -0,0 +1,17 @@
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
diff --git a/aconfigd/proto/aconfigd.proto b/aconfigd/proto/aconfigd.proto
new file mode 100644
index 0000000..2a7c9fc
--- /dev/null
+++ b/aconfigd/proto/aconfigd.proto
@@ -0,0 +1,173 @@
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
+syntax = "proto2";
+package android.aconfigd;
+option optimize_for = LITE_RUNTIME;
+
+message PersistStorageRecord {
+  optional uint32 version = 1;
+  optional string container = 2;
+  optional string package_map = 3;
+  optional string flag_map = 4;
+  optional string flag_val = 5;
+  optional string digest = 6;
+  optional string flag_info = 7;
+}
+
+message PersistStorageRecords {
+  repeated PersistStorageRecord records = 1;
+}
+
+message FlagOverride {
+  optional string package_name = 1;
+  optional string flag_name = 2;
+  optional string flag_value = 3;
+}
+
+message LocalFlagOverrides {
+  repeated FlagOverride overrides = 1;
+}
+
+// incoming request to aconfigd
+message StorageRequestMessage {
+  // new storage notification
+  message NewStorageMessage {
+    optional string container = 1;
+    optional string package_map = 2;
+    optional string flag_map = 3;
+    optional string flag_value = 4;
+    optional string flag_info = 5;
+  }
+
+  enum FlagOverrideType {
+    LOCAL_IMMEDIATE = 1;
+    LOCAL_ON_REBOOT = 2;
+    SERVER_ON_REBOOT = 3;
+  }
+
+  // request persistent flag value override
+  message FlagOverrideMessage {
+    optional string package_name = 1;
+    optional string flag_name = 2;
+    optional string flag_value = 3;
+    optional FlagOverrideType override_type = 4;
+  }
+
+  // request to stage ota flags
+  message OTAFlagStagingMessage {
+    optional string build_id = 1;
+    repeated FlagOverride overrides = 2;
+  }
+
+  enum RemoveOverrideType {
+    REMOVE_LOCAL_IMMEDIATE = 1;
+    REMOVE_LOCAL_ON_REBOOT = 2;
+  }
+
+  // request to remove local flag override
+  message RemoveLocalOverrideMessage {
+    optional bool remove_all = 1;
+    optional string package_name = 2;
+    optional string flag_name = 3;
+    optional RemoveOverrideType remove_override_type = 4;
+  }
+
+  // query persistent flag value and info
+  message FlagQueryMessage {
+    optional string package_name = 1;
+    optional string flag_name = 2;
+  }
+
+  // reset all storage
+  message ResetStorageMessage {
+    oneof msg {
+      bool all = 1;
+      string container = 2;
+    }
+  }
+
+  // list storage
+  message ListStorageMessage {
+    oneof msg {
+      bool all = 1;
+      string container = 2;
+      string package_name = 3;
+    }
+  }
+
+  oneof msg {
+    NewStorageMessage new_storage_message = 1;
+    FlagOverrideMessage flag_override_message = 2;
+    OTAFlagStagingMessage ota_staging_message = 3;
+    FlagQueryMessage flag_query_message = 4;
+    RemoveLocalOverrideMessage remove_local_override_message = 5;
+    ResetStorageMessage reset_storage_message = 6;
+    ListStorageMessage list_storage_message = 7;
+  };
+}
+
+message StorageRequestMessages {
+  repeated StorageRequestMessage msgs = 1;
+}
+
+// aconfigd return to client
+message StorageReturnMessage {
+  message NewStorageReturnMessage {
+    optional bool storage_updated = 1;
+  }
+
+  message FlagOverrideReturnMessage {}
+
+  message OTAFlagStagingReturnMessage {}
+
+  message FlagQueryReturnMessage {
+    optional string package_name = 1;
+    optional string flag_name = 2;
+    optional string server_flag_value = 3;
+    optional string local_flag_value = 4;
+    optional string boot_flag_value = 5;
+    optional string default_flag_value = 6;
+    optional bool has_server_override = 7;
+    optional bool is_readwrite = 8;
+    optional bool has_local_override = 9;
+    optional bool has_boot_local_override = 10;
+    optional string container = 11;
+  }
+
+  message RemoveLocalOverrideReturnMessage {}
+
+  message ResetStorageReturnMessage {}
+
+  message ListStorageReturnMessage {
+    repeated FlagQueryReturnMessage flags = 1;
+  }
+
+  oneof msg {
+    NewStorageReturnMessage new_storage_message = 1;
+    FlagOverrideReturnMessage flag_override_message = 2;
+    OTAFlagStagingReturnMessage ota_staging_message = 3;
+    FlagQueryReturnMessage flag_query_message = 4;
+    RemoveLocalOverrideReturnMessage remove_local_override_message = 5;
+    ResetStorageReturnMessage reset_storage_message = 6;
+    ListStorageReturnMessage list_storage_message = 7;
+    string error_message = 8;
+  };
+}
+
+message StorageReturnMessages {
+  repeated StorageReturnMessage msgs = 1;
+}
diff --git a/aconfigd/proto/build.rs b/aconfigd/proto/build.rs
new file mode 100644
index 0000000..a79f7af
--- /dev/null
+++ b/aconfigd/proto/build.rs
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
diff --git a/aconfigd/proto/src/lib.rs b/aconfigd/proto/src/lib.rs
new file mode 100644
index 0000000..b4a6155
--- /dev/null
+++ b/aconfigd/proto/src/lib.rs
@@ -0,0 +1,84 @@
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
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::FlagOverride as ProtoFlagOverride;
+    pub use aconfigd_rust_proto::aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
+    pub use aconfigd_rust_proto::aconfigd::PersistStorageRecord as ProtoPersistStorageRecord;
+    pub use aconfigd_rust_proto::aconfigd::PersistStorageRecords as ProtoPersistStorageRecords;
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
+    pub use aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
+    pub use aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
+    pub use aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
+    pub use aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
+    pub use aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
+    pub use aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
+    pub use aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
+    pub use aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
+    pub use aconfigd::FlagOverride as ProtoFlagOverride;
+    pub use aconfigd::LocalFlagOverrides as ProtoLocalFlagOverrides;
+    pub use aconfigd::PersistStorageRecord as ProtoPersistStorageRecord;
+    pub use aconfigd::PersistStorageRecords as ProtoPersistStorageRecords;
+    pub use aconfigd::StorageRequestMessage as ProtoStorageRequestMessage;
+    pub use aconfigd::StorageRequestMessages as ProtoStorageRequestMessages;
+    pub use aconfigd::StorageReturnMessage as ProtoStorageReturnMessage;
+    pub use aconfigd::StorageReturnMessages as ProtoStorageReturnMessages;
+}
+
+pub use auto_generated::*;
diff --git a/aconfigd/rustfmt.toml b/aconfigd/rustfmt.toml
new file mode 120000
index 0000000..99fc71e
--- /dev/null
+++ b/aconfigd/rustfmt.toml
@@ -0,0 +1 @@
+../../../../build/soong/scripts/rustfmt.toml
\ No newline at end of file
diff --git a/aconfigd/src/aconfigd.rs b/aconfigd/src/aconfigd.rs
new file mode 100644
index 0000000..45105fd
--- /dev/null
+++ b/aconfigd/src/aconfigd.rs
@@ -0,0 +1,1107 @@
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
+use crate::storage_files_manager::StorageFilesManager;
+use crate::utils::{read_pb_from_file, remove_file, write_pb_to_file};
+use crate::AconfigdError;
+use aconfigd_protos::{
+    ProtoFlagOverrideMessage, ProtoFlagQueryMessage, ProtoFlagQueryReturnMessage,
+    ProtoListStorageMessage, ProtoListStorageMessageMsg, ProtoNewStorageMessage,
+    ProtoOTAFlagStagingMessage, ProtoPersistStorageRecords, ProtoRemoveLocalOverrideMessage,
+    ProtoStorageRequestMessage, ProtoStorageRequestMessageMsg, ProtoStorageRequestMessages,
+    ProtoStorageReturnMessage, ProtoStorageReturnMessages,
+};
+use log::{debug, error, warn};
+use std::io::{Read, Write};
+use std::os::unix::net::UnixStream;
+use std::path::{Path, PathBuf};
+
+// Aconfigd that is capable of doing both one shot storage file init and socket service
+#[derive(Debug)]
+pub struct Aconfigd {
+    pub root_dir: PathBuf,
+    pub persist_storage_records: PathBuf,
+    pub(crate) storage_manager: StorageFilesManager,
+}
+
+impl Aconfigd {
+    /// Constructor
+    pub fn new(root_dir: &Path, records: &Path) -> Self {
+        Self {
+            root_dir: root_dir.to_path_buf(),
+            persist_storage_records: records.to_path_buf(),
+            storage_manager: StorageFilesManager::new(root_dir),
+        }
+    }
+
+    /// Remove old boot storage record
+    pub fn remove_boot_files(&mut self) -> Result<(), AconfigdError> {
+        let boot_dir = self.root_dir.join("boot");
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&self.persist_storage_records)?;
+        for entry in pb.records.iter() {
+            let boot_value_file = boot_dir.join(entry.container().to_owned() + ".val");
+            let boot_info_file = boot_dir.join(entry.container().to_owned() + ".info");
+            if boot_value_file.exists() {
+                remove_file(&boot_value_file)?;
+            }
+            if boot_info_file.exists() {
+                remove_file(&boot_info_file)?;
+            }
+        }
+        Ok(())
+    }
+
+    /// Initialize aconfigd from persist storage records
+    pub fn initialize_from_storage_record(&mut self) -> Result<(), AconfigdError> {
+        let boot_dir = self.root_dir.join("boot");
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&self.persist_storage_records)?;
+        for entry in pb.records.iter() {
+            self.storage_manager.add_storage_files_from_pb(entry);
+        }
+        Ok(())
+    }
+
+    /// Initialize platform storage files, create or update existing persist storage files and
+    /// create new boot storage files for each platform partitions
+    pub fn initialize_platform_storage(&mut self) -> Result<(), AconfigdError> {
+        for container in ["system", "product", "vendor"] {
+            let aconfig_dir = PathBuf::from("/".to_string() + container + "/etc/aconfig");
+            let default_package_map = aconfig_dir.join("package.map");
+            let default_flag_map = aconfig_dir.join("flag.map");
+            let default_flag_val = aconfig_dir.join("flag.val");
+            let default_flag_info = aconfig_dir.join("flag.info");
+
+            if !default_package_map.exists()
+                || !default_flag_map.exists()
+                || !default_flag_val.exists()
+                || !default_flag_info.exists()
+            {
+                debug!("skip {} initialization due to missing storage files", container);
+                continue;
+            }
+
+            if std::fs::metadata(&default_flag_val)
+                .map_err(|errmsg| AconfigdError::FailToGetFileMetadata {
+                    file: default_flag_val.display().to_string(),
+                    errmsg,
+                })?
+                .len()
+                == 0
+            {
+                debug!("skip {} initialization due to zero sized storage files", container);
+                continue;
+            }
+
+            self.storage_manager.add_or_update_container_storage_files(
+                container,
+                &default_package_map,
+                &default_flag_map,
+                &default_flag_val,
+                &default_flag_info,
+            )?;
+
+            self.storage_manager
+                .write_persist_storage_records_to_file(&self.persist_storage_records)?;
+        }
+
+        self.storage_manager.apply_staged_ota_flags()?;
+
+        for container in ["system", "product", "vendor"] {
+            self.storage_manager.apply_all_staged_overrides(container)?;
+        }
+
+        Ok(())
+    }
+
+    /// Initialize mainline storage files, create or update existing persist storage files and
+    /// create new boot storage files for each mainline container
+    pub fn initialize_mainline_storage(&mut self) -> Result<(), AconfigdError> {
+        // get all the apex dirs to visit
+        let mut dirs_to_visit = Vec::new();
+        let apex_dir = PathBuf::from("/apex");
+        for entry in std::fs::read_dir(&apex_dir)
+            .map_err(|errmsg| AconfigdError::FailToReadApexDir { errmsg })?
+        {
+            match entry {
+                Ok(entry) => {
+                    let path = entry.path();
+                    if !path.is_dir() {
+                        continue;
+                    }
+                    if let Some(base_name) = path.file_name() {
+                        if let Some(dir_name) = base_name.to_str() {
+                            if dir_name.starts_with('.') {
+                                continue;
+                            }
+                            if dir_name.find('@').is_some() {
+                                continue;
+                            }
+                            if dir_name == "sharedlibs" {
+                                continue;
+                            }
+                            dirs_to_visit.push(dir_name.to_string());
+                        }
+                    }
+                }
+                Err(errmsg) => {
+                    warn!("failed to visit entry: {}", errmsg);
+                }
+            }
+        }
+
+        // initialize each container
+        for container in dirs_to_visit.iter() {
+            let etc_dir = apex_dir.join(container).join("etc");
+            let default_package_map = etc_dir.join("package.map");
+            let default_flag_map = etc_dir.join("flag.map");
+            let default_flag_val = etc_dir.join("flag.val");
+            let default_flag_info = etc_dir.join("flag.info");
+
+            if !default_package_map.exists()
+                || !default_flag_val.exists()
+                || !default_flag_val.exists()
+                || !default_flag_map.exists()
+            {
+                continue;
+            }
+
+            if std::fs::metadata(&default_flag_val)
+                .map_err(|errmsg| AconfigdError::FailToGetFileMetadata {
+                    file: default_flag_val.display().to_string(),
+                    errmsg,
+                })?
+                .len()
+                == 0
+            {
+                continue;
+            }
+
+            self.storage_manager.add_or_update_container_storage_files(
+                container,
+                &default_package_map,
+                &default_flag_map,
+                &default_flag_val,
+                &default_flag_info,
+            )?;
+
+            self.storage_manager
+                .write_persist_storage_records_to_file(&self.persist_storage_records)?;
+
+            self.storage_manager.apply_all_staged_overrides(container)?;
+        }
+
+        Ok(())
+    }
+
+    /// Handle a flag override request
+    fn handle_flag_override(
+        &mut self,
+        request_pb: &ProtoFlagOverrideMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        self.storage_manager.override_flag_value(
+            request_pb.package_name(),
+            request_pb.flag_name(),
+            request_pb.flag_value(),
+            request_pb.override_type(),
+        )?;
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        return_pb.mut_flag_override_message();
+        Ok(return_pb)
+    }
+
+    /// Handle ota flag staging request
+    fn handle_ota_staging(
+        &mut self,
+        request_pb: &ProtoOTAFlagStagingMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        let ota_flags_pb_file = self.root_dir.join("flags").join("ota.pb");
+        write_pb_to_file::<ProtoOTAFlagStagingMessage>(request_pb, &ota_flags_pb_file)?;
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        return_pb.mut_ota_staging_message();
+        Ok(return_pb)
+    }
+
+    /// Handle new container storage request
+    fn handle_new_storage(
+        &mut self,
+        request_pb: &ProtoNewStorageMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        self.storage_manager.add_or_update_container_storage_files(
+            request_pb.container(),
+            Path::new(request_pb.package_map()),
+            Path::new(request_pb.flag_map()),
+            Path::new(request_pb.flag_value()),
+            Path::new(request_pb.flag_info()),
+        )?;
+
+        self.storage_manager
+            .write_persist_storage_records_to_file(&self.persist_storage_records)?;
+        self.storage_manager.apply_all_staged_overrides(request_pb.container())?;
+
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        return_pb.mut_new_storage_message();
+        Ok(return_pb)
+    }
+
+    /// Handle flag query request
+    fn handle_flag_query(
+        &mut self,
+        request_pb: &ProtoFlagQueryMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        match self
+            .storage_manager
+            .get_flag_snapshot(request_pb.package_name(), request_pb.flag_name())?
+        {
+            Some(snapshot) => {
+                let result = return_pb.mut_flag_query_message();
+                result.set_container(snapshot.container);
+                result.set_package_name(snapshot.package);
+                result.set_flag_name(snapshot.flag);
+                result.set_server_flag_value(snapshot.server_value);
+                result.set_local_flag_value(snapshot.local_value);
+                result.set_boot_flag_value(snapshot.boot_value);
+                result.set_default_flag_value(snapshot.default_value);
+                result.set_is_readwrite(snapshot.is_readwrite);
+                result.set_has_server_override(snapshot.has_server_override);
+                result.set_has_local_override(snapshot.has_local_override);
+                Ok(return_pb)
+            }
+            None => Err(AconfigdError::FlagDoesNotExist {
+                flag: request_pb.package_name().to_string() + "." + request_pb.flag_name(),
+            }),
+        }
+    }
+
+    /// Handle local override removal request
+    fn handle_local_override_removal(
+        &mut self,
+        request_pb: &ProtoRemoveLocalOverrideMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        if request_pb.remove_all() {
+            self.storage_manager.remove_all_local_overrides()?;
+        } else {
+            self.storage_manager
+                .remove_local_override(request_pb.package_name(), request_pb.flag_name())?;
+        }
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        return_pb.mut_remove_local_override_message();
+        Ok(return_pb)
+    }
+
+    /// Handle storage reset request
+    fn handle_storage_reset(&mut self) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        self.storage_manager.reset_all_storage()?;
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        return_pb.mut_reset_storage_message();
+        Ok(return_pb)
+    }
+
+    /// Handle list storage request
+    fn handle_list_storage(
+        &mut self,
+        request_pb: &ProtoListStorageMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        let flags = match &request_pb.msg {
+            Some(ProtoListStorageMessageMsg::All(_)) => self.storage_manager.list_all_flags(),
+            Some(ProtoListStorageMessageMsg::Container(container)) => {
+                self.storage_manager.list_flags_in_container(container)
+            }
+            Some(ProtoListStorageMessageMsg::PackageName(package)) => {
+                self.storage_manager.list_flags_in_package(package)
+            }
+            _ => Err(AconfigdError::InvalidSocketRequest {
+                errmsg: "Invalid list storage type".to_string(),
+            }),
+        }?;
+        let mut return_pb = ProtoStorageReturnMessage::new();
+        let result = return_pb.mut_list_storage_message();
+        result.flags = flags
+            .into_iter()
+            .map(|f| {
+                let mut snapshot = ProtoFlagQueryReturnMessage::new();
+                snapshot.set_container(f.container);
+                snapshot.set_package_name(f.package);
+                snapshot.set_flag_name(f.flag);
+                snapshot.set_server_flag_value(f.server_value);
+                snapshot.set_local_flag_value(f.local_value);
+                snapshot.set_boot_flag_value(f.boot_value);
+                snapshot.set_default_flag_value(f.default_value);
+                snapshot.set_is_readwrite(f.is_readwrite);
+                snapshot.set_has_server_override(f.has_server_override);
+                snapshot.set_has_local_override(f.has_local_override);
+                snapshot
+            })
+            .collect();
+        Ok(return_pb)
+    }
+
+    /// Handle socket request
+    fn handle_socket_request(
+        &mut self,
+        request_pb: &ProtoStorageRequestMessage,
+    ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
+        match request_pb.msg {
+            Some(ProtoStorageRequestMessageMsg::NewStorageMessage(_)) => {
+                self.handle_new_storage(request_pb.new_storage_message())
+            }
+            Some(ProtoStorageRequestMessageMsg::FlagOverrideMessage(_)) => {
+                self.handle_flag_override(request_pb.flag_override_message())
+            }
+            Some(ProtoStorageRequestMessageMsg::OtaStagingMessage(_)) => {
+                self.handle_ota_staging(request_pb.ota_staging_message())
+            }
+            Some(ProtoStorageRequestMessageMsg::FlagQueryMessage(_)) => {
+                self.handle_flag_query(request_pb.flag_query_message())
+            }
+            Some(ProtoStorageRequestMessageMsg::RemoveLocalOverrideMessage(_)) => {
+                self.handle_local_override_removal(request_pb.remove_local_override_message())
+            }
+            Some(ProtoStorageRequestMessageMsg::ResetStorageMessage(_)) => {
+                self.handle_storage_reset()
+            }
+            Some(ProtoStorageRequestMessageMsg::ListStorageMessage(_)) => {
+                self.handle_list_storage(request_pb.list_storage_message())
+            }
+            _ => Err(AconfigdError::InvalidSocketRequest { errmsg: String::new() }),
+        }
+    }
+
+    /// Handle socket request from a unix stream
+    pub fn handle_socket_request_from_stream(
+        &mut self,
+        stream: &mut UnixStream,
+    ) -> Result<(), AconfigdError> {
+        let mut length_buffer = [0u8; 4];
+        stream
+            .read_exact(&mut length_buffer)
+            .map_err(|errmsg| AconfigdError::FailToReadFromSocket { errmsg })?;
+        let mut message_length = u32::from_be_bytes(length_buffer);
+
+        let mut request_buffer = vec![0u8; message_length as usize];
+        stream
+            .read_exact(&mut request_buffer)
+            .map_err(|errmsg| AconfigdError::FailToReadFromSocket { errmsg })?;
+
+        let requests: &ProtoStorageRequestMessages =
+            &protobuf::Message::parse_from_bytes(&request_buffer[..]).map_err(|errmsg| {
+                AconfigdError::FailToParsePbFromBytes { file: "socket request".to_string(), errmsg }
+            })?;
+
+        let mut return_msgs = ProtoStorageReturnMessages::new();
+        for request in requests.msgs.iter() {
+            let return_pb = match self.handle_socket_request(request) {
+                Ok(return_msg) => return_msg,
+                Err(errmsg) => {
+                    error!("failed to handle socket request: {}", errmsg);
+                    let mut return_msg = ProtoStorageReturnMessage::new();
+                    return_msg.set_error_message(format!(
+                        "failed to handle socket request: {:?}",
+                        errmsg
+                    ));
+                    return_msg
+                }
+            };
+            return_msgs.msgs.push(return_pb);
+        }
+
+        let bytes = protobuf::Message::write_to_bytes(&return_msgs).map_err(|errmsg| {
+            AconfigdError::FailToSerializePb { file: "socket".to_string(), errmsg }
+        })?;
+
+        message_length = bytes.len() as u32;
+        length_buffer = message_length.to_be_bytes();
+        stream
+            .write_all(&length_buffer)
+            .map_err(|errmsg| AconfigdError::FailToWriteToSocket { errmsg })?;
+        stream.write_all(&bytes).map_err(|errmsg| AconfigdError::FailToWriteToSocket { errmsg })?;
+
+        Ok(())
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::test_utils::{has_same_content, ContainerMock, StorageRootDirMock};
+    use crate::utils::{get_files_digest, read_pb_from_file};
+    use aconfigd_protos::{
+        ProtoFlagOverride, ProtoFlagOverrideType, ProtoLocalFlagOverrides,
+        ProtoPersistStorageRecord,
+    };
+    use std::net::Shutdown;
+    use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
+    use tempfile::tempfile;
+
+    fn create_mock_aconfigd(root_dir: &StorageRootDirMock) -> Aconfigd {
+        Aconfigd::new(root_dir.tmp_dir.path(), &root_dir.flags_dir.join("storage_records.pb"))
+    }
+
+    fn add_mockup_container_storage(container: &ContainerMock, aconfigd: &mut Aconfigd) {
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_new_storage_message();
+        actual_request.set_container("mockup".to_string());
+        actual_request.set_package_map(container.package_map.display().to_string());
+        actual_request.set_flag_map(container.flag_map.display().to_string());
+        actual_request.set_flag_value(container.flag_val.display().to_string());
+        actual_request.set_flag_info(container.flag_info.display().to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+    }
+
+    #[test]
+    fn test_new_storage_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+
+        let persist_package_map = root_dir.maps_dir.join("mockup.package.map");
+        assert!(persist_package_map.exists());
+        assert!(has_same_content(&container.package_map, &persist_package_map));
+        let persist_flag_map = root_dir.maps_dir.join("mockup.flag.map");
+        assert!(persist_flag_map.exists());
+        assert!(has_same_content(&container.flag_map, &persist_flag_map));
+        let persist_flag_val = root_dir.flags_dir.join("mockup.val");
+        assert!(persist_flag_val.exists());
+        assert!(has_same_content(&container.flag_val, &persist_flag_val));
+        let persist_flag_info = root_dir.flags_dir.join("mockup.info");
+        assert!(persist_flag_info.exists());
+        assert!(has_same_content(&container.flag_info, &persist_flag_info));
+        let boot_flag_val = root_dir.boot_dir.join("mockup.val");
+        assert!(boot_flag_val.exists());
+        assert!(has_same_content(&container.flag_val, &boot_flag_val));
+        let boot_flag_info = root_dir.boot_dir.join("mockup.info");
+        assert!(boot_flag_info.exists());
+        assert!(has_same_content(&container.flag_info, &boot_flag_info));
+
+        let digest = get_files_digest(
+            &[
+                container.package_map.as_path(),
+                container.flag_map.as_path(),
+                container.flag_val.as_path(),
+                container.flag_info.as_path(),
+            ][..],
+        )
+        .unwrap();
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&aconfigd.persist_storage_records)
+            .unwrap();
+        assert_eq!(pb.records.len(), 1);
+        let mut entry = ProtoPersistStorageRecord::new();
+        entry.set_version(1);
+        entry.set_container("mockup".to_string());
+        entry.set_package_map(container.package_map.display().to_string());
+        entry.set_flag_map(container.flag_map.display().to_string());
+        entry.set_flag_val(container.flag_val.display().to_string());
+        entry.set_flag_info(container.flag_info.display().to_string());
+        entry.set_digest(digest);
+        assert_eq!(pb.records[0], entry);
+    }
+
+    fn get_flag_snapshot(
+        aconfigd: &mut Aconfigd,
+        package: &str,
+        flag: &str,
+    ) -> ProtoFlagQueryReturnMessage {
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_query_message();
+        actual_request.set_package_name(package.to_string());
+        actual_request.set_flag_name(flag.to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+        return_msg.unwrap().flag_query_message().clone()
+    }
+
+    #[test]
+    fn test_server_on_boot_flag_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::SERVER_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "false");
+        assert_eq!(flag.boot_flag_value(), "true");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_server_override(), true);
+        assert_eq!(flag.has_local_override(), false);
+    }
+
+    #[test]
+    fn test_local_on_boot_flag_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "");
+        assert_eq!(flag.boot_flag_value(), "true");
+        assert_eq!(flag.local_flag_value(), "false");
+        assert_eq!(flag.has_server_override(), false);
+        assert_eq!(flag.has_local_override(), true);
+    }
+
+    #[test]
+    fn test_local_immediate_flag_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_IMMEDIATE);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "");
+        assert_eq!(flag.boot_flag_value(), "false");
+        assert_eq!(flag.local_flag_value(), "false");
+        assert_eq!(flag.has_server_override(), false);
+        assert_eq!(flag.has_local_override(), true);
+    }
+
+    #[test]
+    fn test_negative_flag_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("not_exist".to_string());
+        actual_request.set_flag_name("not_exist".to_string());
+        actual_request.set_flag_value("false".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_err());
+        if let Err(errmsg) = return_msg {
+            assert_eq!("cannot find container for package not_exist", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_ota_flag_staging_request() {
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_ota_staging_message();
+        actual_request.set_build_id("xyz.123".to_string());
+        let mut flag1 = ProtoFlagOverride::new();
+        flag1.set_package_name("package_foo".to_string());
+        flag1.set_flag_name("flag_foo".to_string());
+        flag1.set_flag_value("false".to_string());
+        actual_request.overrides.push(flag1.clone());
+        let mut flag2 = ProtoFlagOverride::new();
+        flag2.set_package_name("package_bar".to_string());
+        flag2.set_flag_name("flag_bar".to_string());
+        flag2.set_flag_value("true".to_string());
+        actual_request.overrides.push(flag2.clone());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let ota_pb_file = root_dir.flags_dir.join("ota.pb");
+        assert!(ota_pb_file.exists());
+        let ota_flags = read_pb_from_file::<ProtoOTAFlagStagingMessage>(&ota_pb_file).unwrap();
+        assert_eq!(ota_flags.build_id(), "xyz.123");
+        assert_eq!(ota_flags.overrides.len(), 2);
+        assert_eq!(ota_flags.overrides[0], flag1);
+        assert_eq!(ota_flags.overrides[1], flag2);
+    }
+
+    #[test]
+    fn test_flag_querry_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.container(), "mockup");
+        assert_eq!(flag.package_name(), "com.android.aconfig.storage.test_1");
+        assert_eq!(flag.flag_name(), "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "");
+        assert_eq!(flag.boot_flag_value(), "true");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.default_flag_value(), "true");
+        assert_eq!(flag.is_readwrite(), true);
+        assert_eq!(flag.has_server_override(), false);
+        assert_eq!(flag.has_local_override(), false);
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let mut actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::SERVER_ON_REBOOT);
+        let mut return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        flag = get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.container(), "mockup");
+        assert_eq!(flag.package_name(), "com.android.aconfig.storage.test_1");
+        assert_eq!(flag.flag_name(), "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "false");
+        assert_eq!(flag.boot_flag_value(), "true");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.default_flag_value(), "true");
+        assert_eq!(flag.is_readwrite(), true);
+        assert_eq!(flag.has_server_override(), true);
+        assert_eq!(flag.has_local_override(), false);
+
+        request = ProtoStorageRequestMessage::new();
+        actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_IMMEDIATE);
+        return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        flag = get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.container(), "mockup");
+        assert_eq!(flag.package_name(), "com.android.aconfig.storage.test_1");
+        assert_eq!(flag.flag_name(), "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "false");
+        assert_eq!(flag.boot_flag_value(), "false");
+        assert_eq!(flag.local_flag_value(), "false");
+        assert_eq!(flag.default_flag_value(), "true");
+        assert_eq!(flag.is_readwrite(), true);
+        assert_eq!(flag.has_server_override(), true);
+        assert_eq!(flag.has_local_override(), true);
+    }
+
+    #[test]
+    fn test_negative_flag_querry_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_query_message();
+        actual_request.set_package_name("not_exist".to_string());
+        actual_request.set_flag_name("not_exist".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_err());
+        if let Err(errmsg) = return_msg {
+            assert_eq!("flag not_exist.not_exist does not exist", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_remove_single_local_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("disabled_rw".to_string());
+        actual_request.set_flag_value("true".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_remove_local_override_message();
+        actual_request.set_remove_all(false);
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_local_override(), false);
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "disabled_rw");
+        assert_eq!(flag.local_flag_value(), "true");
+        assert_eq!(flag.has_local_override(), true);
+    }
+
+    #[test]
+    fn test_remove_all_local_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("disabled_rw".to_string());
+        actual_request.set_flag_value("true".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_remove_local_override_message();
+        actual_request.set_remove_all(true);
+        actual_request.set_package_name("abc".to_string());
+        actual_request.set_flag_name("def".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_local_override(), false);
+
+        let flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "disabled_rw");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_local_override(), false);
+
+        let local_pb_file = root_dir.flags_dir.join("mockup_local_overrides.pb");
+        let pb = read_pb_from_file::<ProtoLocalFlagOverrides>(&local_pb_file).unwrap();
+        assert_eq!(pb.overrides.len(), 0);
+    }
+
+    #[test]
+    fn test_negative_remove_local_override_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_remove_local_override_message();
+        actual_request.set_remove_all(false);
+        actual_request.set_package_name("abc".to_string());
+        actual_request.set_flag_name("def".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_err());
+        if let Err(errmsg) = return_msg {
+            assert_eq!("cannot find container for package abc", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_reset_storage_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("enabled_rw".to_string());
+        actual_request.set_flag_value("false".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::SERVER_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_override_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        actual_request.set_flag_name("disabled_rw".to_string());
+        actual_request.set_flag_value("true".to_string());
+        actual_request.set_override_type(ProtoFlagOverrideType::LOCAL_ON_REBOOT);
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let _actual_request = request.mut_reset_storage_message();
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let mut flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "enabled_rw");
+        assert_eq!(flag.server_flag_value(), "");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_server_override(), false);
+        assert_eq!(flag.has_local_override(), false);
+
+        flag =
+            get_flag_snapshot(&mut aconfigd, "com.android.aconfig.storage.test_1", "disabled_rw");
+        assert_eq!(flag.server_flag_value(), "");
+        assert_eq!(flag.local_flag_value(), "");
+        assert_eq!(flag.has_server_override(), false);
+        assert_eq!(flag.has_local_override(), false);
+    }
+
+    #[test]
+    fn test_list_package_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_list_storage_message();
+        actual_request.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flags = return_msg.unwrap().list_storage_message().clone();
+        assert_eq!(flags.flags.len(), 3);
+
+        let mut flag = ProtoFlagQueryReturnMessage::new();
+        flag.set_container("mockup".to_string());
+        flag.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        flag.set_flag_name("disabled_rw".to_string());
+        flag.set_server_flag_value("".to_string());
+        flag.set_local_flag_value("".to_string());
+        flag.set_boot_flag_value("false".to_string());
+        flag.set_default_flag_value("false".to_string());
+        flag.set_is_readwrite(true);
+        flag.set_has_server_override(false);
+        flag.set_has_local_override(false);
+        assert_eq!(flags.flags[0], flag);
+
+        flag.set_flag_name("enabled_ro".to_string());
+        flag.set_boot_flag_value("true".to_string());
+        flag.set_default_flag_value("true".to_string());
+        flag.set_is_readwrite(false);
+        assert_eq!(flags.flags[1], flag);
+
+        flag.set_flag_name("enabled_rw".to_string());
+        flag.set_is_readwrite(true);
+        assert_eq!(flags.flags[2], flag);
+    }
+
+    #[test]
+    fn test_negative_list_package_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_list_storage_message();
+        actual_request.set_package_name("not_exist".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_err());
+        if let Err(errmsg) = return_msg {
+            assert_eq!("cannot find container for package not_exist", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_list_container_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_list_storage_message();
+        actual_request.set_container("mockup".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_ok());
+
+        let flags = return_msg.unwrap().list_storage_message().clone();
+        assert_eq!(flags.flags.len(), 8);
+    }
+
+    #[test]
+    fn test_negative_list_container_request() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_list_storage_message();
+        actual_request.set_container("not_exist".to_string());
+        let return_msg = aconfigd.handle_socket_request(&request);
+        assert!(return_msg.is_err());
+        if let Err(errmsg) = return_msg {
+            assert_eq!("fail to get storage files for not_exist", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_aconfigd_unix_stream() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        add_mockup_container_storage(&container, &mut aconfigd);
+        aconfigd.storage_manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut request = ProtoStorageRequestMessage::new();
+        let actual_request = request.mut_flag_query_message();
+        actual_request.set_package_name("abc".to_string());
+        actual_request.set_flag_name("def".to_string());
+        let bytes = protobuf::Message::write_to_bytes(&request).unwrap();
+
+        let (mut stream1, mut stream2) = UnixStream::pair().unwrap();
+        let length_bytes = (bytes.len() as u32).to_be_bytes();
+        stream1.write_all(&length_bytes).unwrap();
+        stream1.write_all(&bytes).unwrap();
+        stream1.shutdown(Shutdown::Write).unwrap();
+        let result = aconfigd.handle_socket_request_from_stream(&mut stream2);
+        assert!(result.is_ok());
+    }
+
+    #[test]
+    fn test_negative_aconfigd_unix_stream() {
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+
+        let (mut stream1, mut stream2) = UnixStream::pair().unwrap();
+        let length_bytes = 11_u32.to_be_bytes();
+        stream1.write_all(&length_bytes).unwrap();
+        stream1.write_all(b"hello world").unwrap();
+        stream1.shutdown(Shutdown::Write).unwrap();
+        let result = aconfigd.handle_socket_request_from_stream(&mut stream2);
+        assert!(result.is_err());
+        if let Err(errmsg) = result {
+            assert_eq!("fail to parse to protobuf from bytes for socket request: Error(WireError(UnexpectedWireType(EndGroup)))", format!("{}", errmsg));
+        }
+    }
+
+    #[test]
+    fn test_initialize_platform_storage_fresh_install() {
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        aconfigd.initialize_platform_storage().unwrap();
+        assert!(aconfigd.persist_storage_records.exists());
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&aconfigd.persist_storage_records)
+            .unwrap();
+        assert_eq!(pb.records.len(), 3);
+
+        for container in ["system", "product", "vendor"] {
+            let aconfig_dir = PathBuf::from("/".to_string() + container + "/etc/aconfig");
+            let default_package_map = aconfig_dir.join("package.map");
+            let default_flag_map = aconfig_dir.join("flag.map");
+            let default_flag_val = aconfig_dir.join("flag.val");
+            let default_flag_info = aconfig_dir.join("flag.info");
+
+            let persist_package_map =
+                root_dir.maps_dir.join(container.to_string() + ".package.map");
+            let persist_flag_map = root_dir.maps_dir.join(container.to_string() + ".flag.map");
+            let persist_flag_val = root_dir.flags_dir.join(container.to_string() + ".val");
+            let persist_flag_info = root_dir.flags_dir.join(container.to_string() + ".info");
+            let boot_flag_val = root_dir.boot_dir.join(container.to_string() + ".val");
+            let boot_flag_info = root_dir.boot_dir.join(container.to_string() + ".info");
+            let local_overrides =
+                root_dir.flags_dir.join(container.to_string() + "_local_overrides.pb");
+
+            assert!(has_same_content(&persist_package_map, &default_package_map));
+            assert!(has_same_content(&persist_flag_map, &default_flag_map));
+            assert!(has_same_content(&persist_flag_val, &default_flag_val));
+            assert!(has_same_content(&persist_flag_info, &default_flag_info));
+            assert!(has_same_content(&boot_flag_val, &default_flag_val));
+            assert!(has_same_content(&boot_flag_info, &default_flag_info));
+            assert!(local_overrides.exists());
+
+            let mut entry = ProtoPersistStorageRecord::new();
+            entry.set_version(1);
+            entry.set_container(container.to_string());
+            entry.set_package_map(default_package_map.display().to_string());
+            entry.set_flag_map(default_flag_map.display().to_string());
+            entry.set_flag_val(default_flag_val.display().to_string());
+            entry.set_flag_info(default_flag_info.display().to_string());
+            let digest = get_files_digest(
+                &[
+                    default_package_map.as_path(),
+                    default_flag_map.as_path(),
+                    default_flag_val.as_path(),
+                    default_flag_info.as_path(),
+                ][..],
+            )
+            .unwrap();
+            entry.set_digest(digest);
+            assert!(pb.records.iter().any(|x| *x == entry));
+        }
+    }
+
+    #[test]
+    fn test_initialize_mainline_storage() {
+        let root_dir = StorageRootDirMock::new();
+        let mut aconfigd = create_mock_aconfigd(&root_dir);
+        aconfigd.initialize_mainline_storage().unwrap();
+        let entries: Vec<_> = std::fs::read_dir(&root_dir.flags_dir).into_iter().collect();
+        assert!(entries.len() > 0);
+    }
+}
diff --git a/aconfigd/src/aconfigd_commands.rs b/aconfigd/src/aconfigd_commands.rs
new file mode 100644
index 0000000..9633a44
--- /dev/null
+++ b/aconfigd/src/aconfigd_commands.rs
@@ -0,0 +1,73 @@
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
+use aconfigd_rust::aconfigd::Aconfigd;
+use anyhow::{bail, Result};
+use log::{debug, error};
+use std::os::fd::AsRawFd;
+use std::os::unix::net::UnixListener;
+use std::path::Path;
+
+const ACONFIGD_SOCKET: &str = "aconfigd_mainline";
+const ACONFIGD_ROOT_DIR: &str = "/metadata/aconfig";
+const STORAGE_RECORDS: &str = "/metadata/aconfig/mainline_storage_records.pb";
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
+    let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(STORAGE_RECORDS));
+    aconfigd.initialize_from_storage_record()?;
+
+    debug!("start waiting for a new client connection through socket.");
+    for stream in listener.incoming() {
+        match stream {
+            Ok(mut stream) => {
+                if let Err(errmsg) = aconfigd.handle_socket_request_from_stream(&mut stream) {
+                    error!("failed to handle socket request: {:?}", errmsg);
+                }
+            }
+            Err(errmsg) => {
+                error!("failed to listen for an incoming message: {:?}", errmsg);
+            }
+        }
+    }
+
+    Ok(())
+}
+
+/// initialize mainline module storage files
+pub fn init() -> Result<()> {
+    let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(STORAGE_RECORDS));
+    aconfigd.remove_boot_files()?;
+    aconfigd.initialize_from_storage_record()?;
+    aconfigd.initialize_mainline_storage()?;
+    Ok(())
+}
+
+/// initialize bootstrapped mainline module storage files
+pub fn bootstrap_init() -> Result<()> {
+    Ok(())
+}
diff --git a/aconfigd/src/lib.rs b/aconfigd/src/lib.rs
new file mode 100644
index 0000000..2bab37f
--- /dev/null
+++ b/aconfigd/src/lib.rs
@@ -0,0 +1,148 @@
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
+//! `aconfig_mainline` is a crate that defines library functions that are needed by
+//! aconfig daemon for mainline (aconfigd-mainline binary).
+
+pub mod aconfigd;
+pub mod storage_files;
+pub mod storage_files_manager;
+pub mod utils;
+
+#[cfg(test)]
+mod test_utils;
+
+/// aconfigd-mainline error
+#[non_exhaustive]
+#[derive(thiserror::Error, Debug)]
+pub enum AconfigdError {
+    #[error("failed to update file permission of {} to {}: {:?}", .file, .mode, .errmsg)]
+    FailToUpdateFilePerm { file: String, mode: u32, errmsg: std::io::Error },
+
+    #[error("failed to copy file from {} to {}: {:?}", .src, .dst, .errmsg)]
+    FailToCopyFile { src: String, dst: String, errmsg: std::io::Error },
+
+    #[error("fail to remove file {}: {:?}", .file, .errmsg)]
+    FailToRemoveFile { file: String, errmsg: std::io::Error },
+
+    #[error("fail to open file {}: {:?}", .file, .errmsg)]
+    FailToOpenFile { file: String, errmsg: std::io::Error },
+
+    #[error("fail to read file {}: {:?}", .file, .errmsg)]
+    FailToReadFile { file: String, errmsg: std::io::Error },
+
+    #[error("fail to write file {}: {:?}", .file, .errmsg)]
+    FailToWriteFile { file: String, errmsg: std::io::Error },
+
+    #[error("fail to parse to protobuf from bytes for {}: {:?}", .file, .errmsg)]
+    FailToParsePbFromBytes { file: String, errmsg: protobuf::Error },
+
+    #[error("fail to serialize protobuf to bytes for file {}: {:?}", .file, .errmsg)]
+    FailToSerializePb { file: String, errmsg: protobuf::Error },
+
+    #[error("fail to get hasher for digest: {:?}", .errmsg)]
+    FailToGetHasherForDigest { errmsg: openssl::error::ErrorStack },
+
+    #[error("failed to hash file {}: {:?}", .file, .errmsg)]
+    FailToHashFile { file: String, errmsg: openssl::error::ErrorStack },
+
+    #[error("failed to get files digest: {:?}", .errmsg)]
+    FailToGetDigest { errmsg: openssl::error::ErrorStack },
+
+    #[error("fail to get storage file version of {}: {:?}", .file, .errmsg)]
+    FailToGetFileVersion { file: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to map storage file {}: {:?}", .file, .errmsg)]
+    FailToMapFile { file: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("mapped storage file {} is none", .file)]
+    MappedFileIsNone { file: String },
+
+    #[error("invalid flag value type for {}: {:?}", .flag, .errmsg)]
+    InvalidFlagValueType { flag: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("flag {} does not exist", .flag)]
+    FlagDoesNotExist { flag: String },
+
+    #[error("fail to get package context for {}: {:?}", .package, .errmsg)]
+    FailToGetPackageContext { package: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to get flag context for {}: {:?}", .flag, .errmsg)]
+    FailToGetFlagContext { flag: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to get flag attribute for {}: {:?}", .flag, .errmsg)]
+    FailToGetFlagAttribute { flag: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to get flag value for {}: {:?}", .flag, .errmsg)]
+    FailToGetFlagValue { flag: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("flag {} has no local override", .flag)]
+    FlagHasNoLocalOverride { flag: String },
+
+    #[error("invalid flag value {} for flag {}", .value, .flag)]
+    InvalidFlagValue { flag: String, value: String },
+
+    #[error("failed to set flag value for flag {}: {:?}", .flag, .errmsg)]
+    FailToSetFlagValue { flag: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("failed to set flag has server override for flag {}: {:?}", .flag, .errmsg)]
+    FailToSetFlagHasServerOverride {
+        flag: String,
+        errmsg: aconfig_storage_file::AconfigStorageError,
+    },
+
+    #[error("failed to set flag has local override for flag {}: {:?}", .flag, .errmsg)]
+    FailToSetFlagHasLocalOverride {
+        flag: String,
+        errmsg: aconfig_storage_file::AconfigStorageError,
+    },
+
+    #[error("flag {} is readonly", .flag)]
+    FlagIsReadOnly { flag: String },
+
+    #[error("fail to list flags for cotnainer {}: {:?}", .container, .errmsg)]
+    FailToListFlags { container: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to list flags with info for container {}: {:?}", .container, .errmsg)]
+    FailToListFlagsWithInfo { container: String, errmsg: aconfig_storage_file::AconfigStorageError },
+
+    #[error("fail to get storage files for {}", .container)]
+    FailToGetStorageFiles { container: String },
+
+    #[error("unexpected internal error")]
+    InternalError(#[source] anyhow::Error),
+
+    #[error("fail to get metadata of file {}: {:?}", .file, .errmsg)]
+    FailToGetFileMetadata { file: String, errmsg: std::io::Error },
+
+    #[error("fail to read /apex dir: {:?}", .errmsg)]
+    FailToReadApexDir { errmsg: std::io::Error },
+
+    #[error("cannot find container for package {}", .package)]
+    FailToFindContainer { package: String },
+
+    #[error("invalid socket request: {}", .errmsg)]
+    InvalidSocketRequest { errmsg: String },
+
+    #[error("fail to read from socket unix stream: {:?}", .errmsg)]
+    FailToReadFromSocket { errmsg: std::io::Error },
+
+    #[error("fail to write to socket unix stream: {:?}", .errmsg)]
+    FailToWriteToSocket { errmsg: std::io::Error },
+
+    #[error("fail to read device build fingerpirnt: {:?}", .errmsg)]
+    FailToReadBuildFingerPrint { errmsg: rustutils::system_properties::PropertyWatcherError },
+}
diff --git a/aconfigd/src/main.rs b/aconfigd/src/main.rs
new file mode 100644
index 0000000..7d6b06b
--- /dev/null
+++ b/aconfigd/src/main.rs
@@ -0,0 +1,81 @@
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
+    /// initialize mainline module storage files.
+    Init,
+
+    /// initialize bootstrap mainline module storage files.
+    BootstrapInit,
+}
+
+fn main() {
+    if !aconfig_new_storage_flags::enable_aconfig_storage_daemon()
+        || !aconfig_new_storage_flags::enable_aconfigd_from_mainline()
+    {
+        info!("aconfigd_mainline is disabled, exiting");
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
+            .with_tag("aconfigd_mainline")
+            .with_max_level(log::LevelFilter::Trace),
+    );
+    info!("starting aconfigd_mainline commands.");
+
+    let cli = Cli::parse();
+    let command_return = match cli.command {
+        Command::StartSocket => aconfigd_commands::start_socket(),
+        Command::Init => aconfigd_commands::init(),
+        Command::BootstrapInit => aconfigd_commands::bootstrap_init(),
+    };
+
+    if let Err(errmsg) = command_return {
+        error!("failed to run aconfigd command: {:?}.", errmsg);
+        std::process::exit(1);
+    }
+}
diff --git a/aconfigd/src/storage_files.rs b/aconfigd/src/storage_files.rs
new file mode 100644
index 0000000..844ad44
--- /dev/null
+++ b/aconfigd/src/storage_files.rs
@@ -0,0 +1,1687 @@
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
+use crate::utils::{copy_file, get_files_digest, read_pb_from_file, remove_file, write_pb_to_file};
+use crate::AconfigdError;
+use aconfig_storage_file::{
+    list_flags, list_flags_with_info, FlagInfoBit, FlagValueSummary, FlagValueType,
+};
+use aconfig_storage_read_api::{
+    get_boolean_flag_value, get_flag_read_context, get_package_read_context,
+    get_storage_file_version, map_file,
+};
+use aconfig_storage_write_api::{
+    map_mutable_storage_file, set_boolean_flag_value, set_flag_has_local_override,
+    set_flag_has_server_override,
+};
+use aconfigd_protos::{ProtoFlagOverride, ProtoLocalFlagOverrides, ProtoPersistStorageRecord};
+use anyhow::anyhow;
+use memmap2::{Mmap, MmapMut};
+use std::collections::HashMap;
+use std::path::{Path, PathBuf};
+
+// In memory data structure for storage file locations for each container
+#[derive(PartialEq, Debug, Clone)]
+pub(crate) struct StorageRecord {
+    pub version: u32,
+    pub container: String,            // container name
+    pub default_package_map: PathBuf, // default package map file
+    pub default_flag_map: PathBuf,    // default flag map file
+    pub default_flag_val: PathBuf,    // default flag val file
+    pub default_flag_info: PathBuf,   // default flag info file
+    pub persist_package_map: PathBuf, // persist package.map file
+    pub persist_flag_map: PathBuf,    // persist flag.map file
+    pub persist_flag_val: PathBuf,    // persist flag.val file
+    pub persist_flag_info: PathBuf,   // persist flag.info file
+    pub local_overrides: PathBuf,     // local overrides pb file
+    pub boot_flag_val: PathBuf,       // boot flag.val file
+    pub boot_flag_info: PathBuf,      // boot flag.info file
+    pub digest: String,               // hash for all default storage files
+}
+
+// Storage files for a particular container
+#[derive(Debug)]
+pub(crate) struct StorageFiles {
+    pub storage_record: StorageRecord,
+    pub package_map: Option<Mmap>,
+    pub flag_map: Option<Mmap>,
+    pub flag_val: Option<Mmap>,                  // default flag value file
+    pub boot_flag_val: Option<Mmap>,             // boot flag value file
+    pub boot_flag_info: Option<Mmap>,            // boot flag info file
+    pub persist_flag_val: Option<MmapMut>,       // persist flag value file
+    pub persist_flag_info: Option<MmapMut>,      // persist flag info file
+    pub mutable_boot_flag_val: Option<MmapMut>,  // mutable boot flag value file
+    pub mutable_boot_flag_info: Option<MmapMut>, // mutable boot flag info file
+}
+
+// Compare two options of mmap/mmapmut
+fn same_mmap_contents<T: std::ops::Deref<Target = [u8]>>(
+    opt_a: &Option<T>,
+    opt_b: &Option<T>,
+) -> bool {
+    match (opt_a, opt_b) {
+        (Some(map_a), Some(map_b)) => map_a[..] == map_b[..],
+        (None, None) => true,
+        _ => false,
+    }
+}
+
+impl PartialEq for StorageFiles {
+    fn eq(&self, other: &Self) -> bool {
+        self.storage_record == other.storage_record
+            && same_mmap_contents(&self.package_map, &other.package_map)
+            && same_mmap_contents(&self.flag_map, &other.flag_map)
+            && same_mmap_contents(&self.flag_val, &other.flag_val)
+            && same_mmap_contents(&self.boot_flag_val, &other.boot_flag_val)
+            && same_mmap_contents(&self.boot_flag_info, &other.boot_flag_info)
+            && same_mmap_contents(&self.persist_flag_val, &other.persist_flag_val)
+            && same_mmap_contents(&self.persist_flag_info, &other.persist_flag_info)
+            && same_mmap_contents(&self.mutable_boot_flag_val, &other.mutable_boot_flag_val)
+            && same_mmap_contents(&self.mutable_boot_flag_info, &other.mutable_boot_flag_info)
+    }
+}
+
+// Package and flag query context
+#[derive(PartialEq, Debug)]
+pub(crate) struct PackageFlagContext {
+    pub package: String,
+    pub flag: String,
+    pub package_exists: bool,
+    pub flag_exists: bool,
+    pub value_type: FlagValueType,
+    pub flag_index: u32,
+}
+
+// Flag snapshot in storage
+#[derive(PartialEq, Debug)]
+pub(crate) struct FlagSnapshot {
+    pub container: String,
+    pub package: String,
+    pub flag: String,
+    pub server_value: String,
+    pub local_value: String,
+    pub boot_value: String,
+    pub default_value: String,
+    pub is_readwrite: bool,
+    pub has_server_override: bool,
+    pub has_local_override: bool,
+}
+
+impl StorageFiles {
+    /// Constructor from a container
+    pub(crate) fn from_container(
+        container: &str,
+        package_map: &Path,
+        flag_map: &Path,
+        flag_val: &Path,
+        flag_info: &Path,
+        root_dir: &Path,
+    ) -> Result<Self, AconfigdError> {
+        let version =
+            get_storage_file_version(&flag_val.display().to_string()).map_err(|errmsg| {
+                AconfigdError::FailToGetFileVersion { file: flag_val.display().to_string(), errmsg }
+            })?;
+
+        let record = StorageRecord {
+            version,
+            container: container.to_string(),
+            default_package_map: package_map.to_path_buf(),
+            default_flag_map: flag_map.to_path_buf(),
+            default_flag_val: flag_val.to_path_buf(),
+            default_flag_info: flag_info.to_path_buf(),
+            persist_package_map: root_dir.join("maps").join(container.to_string() + ".package.map"),
+            persist_flag_map: root_dir.join("maps").join(container.to_string() + ".flag.map"),
+            persist_flag_val: root_dir.join("flags").join(container.to_string() + ".val"),
+            persist_flag_info: root_dir.join("flags").join(container.to_string() + ".info"),
+            local_overrides: root_dir
+                .join("flags")
+                .join(container.to_string() + "_local_overrides.pb"),
+            boot_flag_val: root_dir.join("boot").join(container.to_string() + ".val"),
+            boot_flag_info: root_dir.join("boot").join(container.to_string() + ".info"),
+            digest: get_files_digest(&[package_map, flag_map, flag_val, flag_info][..])?,
+        };
+
+        copy_file(package_map, &record.persist_package_map, 0o444)?;
+        copy_file(flag_map, &record.persist_flag_map, 0o444)?;
+        copy_file(flag_val, &record.persist_flag_val, 0o644)?;
+        copy_file(flag_info, &record.persist_flag_info, 0o644)?;
+        copy_file(flag_val, &record.boot_flag_val, 0o644)?;
+        copy_file(flag_info, &record.boot_flag_info, 0o644)?;
+
+        let pb = ProtoLocalFlagOverrides::new();
+        write_pb_to_file::<ProtoLocalFlagOverrides>(&pb, &record.local_overrides)?;
+
+        let files = Self {
+            storage_record: record,
+            package_map: None,
+            flag_map: None,
+            flag_val: None,
+            boot_flag_val: None,
+            boot_flag_info: None,
+            persist_flag_val: None,
+            persist_flag_info: None,
+            mutable_boot_flag_val: None,
+            mutable_boot_flag_info: None,
+        };
+
+        Ok(files)
+    }
+
+    pub(crate) fn has_boot_copy(&self) -> bool {
+        self.storage_record.boot_flag_val.exists() && self.storage_record.boot_flag_info.exists()
+    }
+
+    /// Constructor from a pb record
+    pub(crate) fn from_pb(
+        pb: &ProtoPersistStorageRecord,
+        root_dir: &Path,
+    ) -> Result<Self, AconfigdError> {
+        let record = StorageRecord {
+            version: pb.version(),
+            container: pb.container().to_string(),
+            default_package_map: PathBuf::from(pb.package_map()),
+            default_flag_map: PathBuf::from(pb.flag_map()),
+            default_flag_val: PathBuf::from(pb.flag_val()),
+            default_flag_info: PathBuf::from(pb.flag_info()),
+            persist_package_map: root_dir
+                .join("maps")
+                .join(pb.container().to_string() + ".package.map"),
+            persist_flag_map: root_dir.join("maps").join(pb.container().to_string() + ".flag.map"),
+            persist_flag_val: root_dir.join("flags").join(pb.container().to_string() + ".val"),
+            persist_flag_info: root_dir.join("flags").join(pb.container().to_string() + ".info"),
+            local_overrides: root_dir
+                .join("flags")
+                .join(pb.container().to_string() + "_local_overrides.pb"),
+            boot_flag_val: root_dir.join("boot").join(pb.container().to_string() + ".val"),
+            boot_flag_info: root_dir.join("boot").join(pb.container().to_string() + ".info"),
+            digest: pb.digest().to_string(),
+        };
+
+        copy_file(&record.persist_flag_val, &record.boot_flag_val, 0o644)?;
+        copy_file(&record.persist_flag_info, &record.boot_flag_info, 0o644)?;
+
+        Ok(Self {
+            storage_record: record,
+            package_map: None,
+            flag_map: None,
+            flag_val: None,
+            boot_flag_val: None,
+            boot_flag_info: None,
+            persist_flag_val: None,
+            persist_flag_info: None,
+            mutable_boot_flag_val: None,
+            mutable_boot_flag_info: None,
+        })
+    }
+
+    /// Get immutable file mapping of a file.
+    ///
+    /// # Safety
+    ///
+    /// The memory mapped file may have undefined behavior if there are writes to the underlying
+    /// file after being mapped. Ensure no writes can happen to the underlying file that is memory
+    /// mapped while this mapping stays alive to guarantee safety.
+    unsafe fn get_immutable_file_mapping(file_path: &Path) -> Result<Mmap, AconfigdError> {
+        // SAFETY: As per the safety comment, there are no other writes to the underlying file.
+        unsafe {
+            map_file(&file_path.display().to_string()).map_err(|errmsg| {
+                AconfigdError::FailToMapFile { file: file_path.display().to_string(), errmsg }
+            })
+        }
+    }
+
+    /// Get package map memory mapping.
+    fn get_package_map(&mut self) -> Result<&Mmap, AconfigdError> {
+        if self.package_map.is_none() {
+            // SAFETY: Here it is safe as package map files are always read only.
+            self.package_map = unsafe {
+                Some(Self::get_immutable_file_mapping(&self.storage_record.persist_package_map)?)
+            };
+        }
+        Ok(self.package_map.as_ref().unwrap())
+    }
+
+    /// Get flag map memory mapping.
+    fn get_flag_map(&mut self) -> Result<&Mmap, AconfigdError> {
+        if self.flag_map.is_none() {
+            // SAFETY: Here it is safe as flag map files are always read only.
+            self.flag_map = unsafe {
+                Some(Self::get_immutable_file_mapping(&self.storage_record.persist_flag_map)?)
+            };
+        }
+        Ok(self.flag_map.as_ref().unwrap())
+    }
+
+    /// Get default flag value memory mapping.
+    fn get_flag_val(&mut self) -> Result<&Mmap, AconfigdError> {
+        if self.flag_val.is_none() {
+            // SAFETY: Here it is safe as default flag value files are always read only.
+            self.flag_val = unsafe {
+                Some(Self::get_immutable_file_mapping(&self.storage_record.default_flag_val)?)
+            };
+        }
+        Ok(self.flag_val.as_ref().unwrap())
+    }
+
+    /// Get boot flag value memory mapping.
+    ///
+    /// # Safety
+    ///
+    /// The memory mapped file may have undefined behavior if there are writes to the underlying
+    /// file after being mapped. Ensure no writes can happen to the underlying file that is memory
+    /// mapped while this mapping stays alive to guarantee safety.
+    unsafe fn get_boot_flag_val(&mut self) -> Result<&Mmap, AconfigdError> {
+        if self.boot_flag_val.is_none() {
+            // SAFETY: As per the safety comment, there are no other writes to the underlying file.
+            self.boot_flag_val = unsafe {
+                Some(Self::get_immutable_file_mapping(&self.storage_record.boot_flag_val)?)
+            };
+        }
+        Ok(self.boot_flag_val.as_ref().unwrap())
+    }
+
+    /// Get boot flag info memory mapping.
+    ///
+    /// # Safety
+    ///
+    /// The memory mapped file may have undefined behavior if there are writes to the underlying
+    /// file after being mapped. Ensure no writes can happen to the underlying file that is memory
+    /// mapped while this mapping stays alive to guarantee safety.
+    unsafe fn get_boot_flag_info(&mut self) -> Result<&Mmap, AconfigdError> {
+        if self.boot_flag_info.is_none() {
+            // SAFETY: As per the safety comment, there are no other writes to the underlying file.
+            self.boot_flag_info = unsafe {
+                Some(Self::get_immutable_file_mapping(&self.storage_record.boot_flag_info)?)
+            };
+        }
+        Ok(self.boot_flag_info.as_ref().unwrap())
+    }
+
+    /// Get mutable file mapping of a file.
+    ///
+    /// # Safety
+    ///
+    /// The memory mapped file may have undefined behavior if there are writes to this
+    /// file not thru this memory mapped file or there are concurrent writes to this
+    /// memory mapped file. Ensure all writes to the underlying file are thru this memory
+    /// mapped file and there are no concurrent writes.
+    pub(crate) unsafe fn get_mutable_file_mapping(
+        file_path: &Path,
+    ) -> Result<MmapMut, AconfigdError> {
+        // SAFETY: As per the safety comment, there are no other writes to the underlying file.
+        unsafe {
+            map_mutable_storage_file(&file_path.display().to_string()).map_err(|errmsg| {
+                AconfigdError::FailToMapFile { file: file_path.display().to_string(), errmsg }
+            })
+        }
+    }
+
+    /// Get persist flag value memory mapping.
+    fn get_persist_flag_val(&mut self) -> Result<&mut MmapMut, AconfigdError> {
+        if self.persist_flag_val.is_none() {
+            // SAFETY: safety is ensured that all writes to the persist file is thru this
+            // memory mapping, and there are no concurrent writes
+            self.persist_flag_val = unsafe {
+                Some(Self::get_mutable_file_mapping(&self.storage_record.persist_flag_val)?)
+            };
+        }
+        Ok(self.persist_flag_val.as_mut().unwrap())
+    }
+
+    /// Get persist flag info memory mapping.
+    fn get_persist_flag_info(&mut self) -> Result<&mut MmapMut, AconfigdError> {
+        if self.persist_flag_info.is_none() {
+            // SAFETY: safety is ensured that all writes to the persist file is thru this
+            // memory mapping, and there are no concurrent writes
+            self.persist_flag_info = unsafe {
+                Some(Self::get_mutable_file_mapping(&self.storage_record.persist_flag_info)?)
+            };
+        }
+        Ok(self.persist_flag_info.as_mut().unwrap())
+    }
+
+    /// Get mutable boot flag value memory mapping.
+    fn get_mutable_boot_flag_val(&mut self) -> Result<&mut MmapMut, AconfigdError> {
+        if self.mutable_boot_flag_val.is_none() {
+            // SAFETY: safety is ensured that all writes to the persist file is thru this
+            // memory mapping, and there are no concurrent writes
+            self.mutable_boot_flag_val = unsafe {
+                Some(Self::get_mutable_file_mapping(&self.storage_record.boot_flag_val)?)
+            };
+        }
+        Ok(self.mutable_boot_flag_val.as_mut().unwrap())
+    }
+
+    /// Get mutable boot flag info memory mapping.
+    fn get_mutable_boot_flag_info(&mut self) -> Result<&mut MmapMut, AconfigdError> {
+        if self.mutable_boot_flag_info.is_none() {
+            // SAFETY: safety is ensured that all writes to the persist file is thru this
+            // memory mapping, and there are no concurrent writes
+            self.mutable_boot_flag_info = unsafe {
+                Some(Self::get_mutable_file_mapping(&self.storage_record.boot_flag_info)?)
+            };
+        }
+        Ok(self.mutable_boot_flag_info.as_mut().unwrap())
+    }
+
+    /// Get package and flag query context
+    pub(crate) fn get_package_flag_context(
+        &mut self,
+        package: &str,
+        flag: &str,
+    ) -> Result<PackageFlagContext, AconfigdError> {
+        let mut context = PackageFlagContext {
+            package: package.to_string(),
+            flag: flag.to_string(),
+            package_exists: false,
+            flag_exists: false,
+            value_type: FlagValueType::Boolean,
+            flag_index: 0,
+        };
+
+        if package.is_empty() {
+            return Ok(context);
+        }
+
+        let package_context =
+            get_package_read_context(self.get_package_map()?, package).map_err(|errmsg| {
+                AconfigdError::FailToGetPackageContext { package: package.to_string(), errmsg }
+            })?;
+
+        if let Some(pkg) = package_context {
+            context.package_exists = true;
+            if flag.is_empty() {
+                return Ok(context);
+            }
+
+            let flag_context = get_flag_read_context(self.get_flag_map()?, pkg.package_id, flag)
+                .map_err(|errmsg| AconfigdError::FailToGetFlagContext {
+                    flag: package.to_string() + "." + flag,
+                    errmsg,
+                })?;
+
+            if let Some(flg) = flag_context {
+                context.flag_exists = true;
+                context.value_type = FlagValueType::try_from(flg.flag_type).map_err(|errmsg| {
+                    AconfigdError::InvalidFlagValueType {
+                        flag: package.to_string() + "." + flag,
+                        errmsg,
+                    }
+                })?;
+                context.flag_index = pkg.boolean_start_index + flg.flag_index as u32;
+            }
+        }
+
+        Ok(context)
+    }
+
+    /// Check if has an aconfig package
+    pub(crate) fn has_package(&mut self, package: &str) -> Result<bool, AconfigdError> {
+        let context = self.get_package_flag_context(package, "")?;
+        Ok(context.package_exists)
+    }
+
+    /// Get flag attribute bitfield
+    pub(crate) fn get_flag_attribute(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<u8, AconfigdError> {
+        if !context.flag_exists {
+            return Err(AconfigdError::FlagDoesNotExist {
+                flag: context.package.to_string() + "." + &context.flag,
+            });
+        }
+
+        let flag_info_file = self.get_persist_flag_info()?;
+        Ok(aconfig_storage_read_api::get_flag_attribute(
+            flag_info_file,
+            context.value_type,
+            context.flag_index,
+        )
+        .map_err(|errmsg| AconfigdError::FailToGetFlagAttribute {
+            flag: context.package.to_string() + "." + &context.flag,
+            errmsg,
+        })?)
+    }
+
+    /// Get flag value from a mapped file
+    fn get_flag_value_from_file(
+        file: &[u8],
+        context: &PackageFlagContext,
+    ) -> Result<String, AconfigdError> {
+        if !context.flag_exists {
+            return Err(AconfigdError::FlagDoesNotExist {
+                flag: context.package.to_string() + "." + &context.flag,
+            });
+        }
+
+        match context.value_type {
+            FlagValueType::Boolean => {
+                let value = get_boolean_flag_value(file, context.flag_index).map_err(|errmsg| {
+                    AconfigdError::FailToGetFlagValue {
+                        flag: context.package.to_string() + "." + &context.flag,
+                        errmsg,
+                    }
+                })?;
+                if value {
+                    Ok(String::from("true"))
+                } else {
+                    Ok(String::from("false"))
+                }
+            }
+        }
+    }
+
+    /// Get server flag value
+    pub(crate) fn get_server_flag_value(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<String, AconfigdError> {
+        let attribute = self.get_flag_attribute(context)?;
+        if (attribute & FlagInfoBit::HasServerOverride as u8) == 0 {
+            return Ok(String::new());
+        }
+
+        let flag_val_file = self.get_persist_flag_val()?;
+        Self::get_flag_value_from_file(flag_val_file, context)
+    }
+
+    /// Get boot flag value
+    pub(crate) fn get_boot_flag_value(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<String, AconfigdError> {
+        // SAFETY: safety is ensured as we are only read from the memory mapping
+        let flag_val_file = unsafe { self.get_boot_flag_val()? };
+        Self::get_flag_value_from_file(flag_val_file, context)
+    }
+
+    /// Get default flag value
+    pub(crate) fn get_default_flag_value(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<String, AconfigdError> {
+        let flag_val_file = self.get_flag_val()?;
+        Self::get_flag_value_from_file(flag_val_file, context)
+    }
+
+    /// Get local flag value
+    pub(crate) fn get_local_flag_value(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<String, AconfigdError> {
+        let attribute = self.get_flag_attribute(context)?;
+        if (attribute & FlagInfoBit::HasLocalOverride as u8) == 0 {
+            return Ok(String::new());
+        }
+
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+
+        for entry in pb.overrides {
+            if entry.package_name() == context.package && entry.flag_name() == context.flag {
+                return Ok(String::from(entry.flag_value()));
+            }
+        }
+
+        Err(AconfigdError::FlagHasNoLocalOverride {
+            flag: context.package.to_string() + "." + &context.flag,
+        })
+    }
+
+    /// Set flag value to file
+    pub(crate) fn set_flag_value_to_file(
+        file: &mut MmapMut,
+        context: &PackageFlagContext,
+        value: &str,
+    ) -> Result<(), AconfigdError> {
+        match context.value_type {
+            FlagValueType::Boolean => {
+                if value != "true" && value != "false" {
+                    return Err(AconfigdError::InvalidFlagValue {
+                        flag: context.package.to_string() + "." + &context.flag,
+                        value: value.to_string(),
+                    });
+                }
+                set_boolean_flag_value(file, context.flag_index, value == "true").map_err(
+                    |errmsg| AconfigdError::FailToSetFlagValue {
+                        flag: context.package.to_string() + "." + &context.flag,
+                        errmsg,
+                    },
+                )?;
+            }
+        }
+
+        Ok(())
+    }
+
+    /// Set flag has server override to file
+    fn set_flag_has_server_override_to_file(
+        file: &mut MmapMut,
+        context: &PackageFlagContext,
+        value: bool,
+    ) -> Result<(), AconfigdError> {
+        set_flag_has_server_override(file, context.value_type, context.flag_index, value).map_err(
+            |errmsg| AconfigdError::FailToSetFlagHasServerOverride {
+                flag: context.package.to_string() + "." + &context.flag,
+                errmsg,
+            },
+        )?;
+
+        Ok(())
+    }
+
+    /// Set flag has local override to file
+    pub(crate) fn set_flag_has_local_override_to_file(
+        file: &mut MmapMut,
+        context: &PackageFlagContext,
+        value: bool,
+    ) -> Result<(), AconfigdError> {
+        set_flag_has_local_override(file, context.value_type, context.flag_index, value).map_err(
+            |errmsg| AconfigdError::FailToSetFlagHasLocalOverride {
+                flag: context.package.to_string() + "." + &context.flag,
+                errmsg,
+            },
+        )?;
+
+        Ok(())
+    }
+
+    /// Server override a flag
+    pub(crate) fn stage_server_override(
+        &mut self,
+        context: &PackageFlagContext,
+        value: &str,
+    ) -> Result<(), AconfigdError> {
+        let attribute = self.get_flag_attribute(context)?;
+        if (attribute & FlagInfoBit::IsReadWrite as u8) == 0 {
+            return Err(AconfigdError::FlagIsReadOnly {
+                flag: context.package.to_string() + "." + &context.flag,
+            });
+        }
+
+        let flag_val_file = self.get_persist_flag_val()?;
+        Self::set_flag_value_to_file(flag_val_file, context, value)?;
+
+        let flag_info_file = self.get_persist_flag_info()?;
+        Self::set_flag_has_server_override_to_file(flag_info_file, context, true)?;
+
+        Ok(())
+    }
+
+    /// Stage local override of a flag
+    pub(crate) fn stage_local_override(
+        &mut self,
+        context: &PackageFlagContext,
+        value: &str,
+    ) -> Result<(), AconfigdError> {
+        let attribute = self.get_flag_attribute(context)?;
+        if (attribute & FlagInfoBit::IsReadWrite as u8) == 0 {
+            return Err(AconfigdError::FlagIsReadOnly {
+                flag: context.package.to_string() + "." + &context.flag,
+            });
+        }
+
+        let mut exist = false;
+        let mut pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+        for entry in &mut pb.overrides {
+            if entry.package_name() == context.package && entry.flag_name() == context.flag {
+                entry.set_flag_value(String::from(value));
+                exist = true;
+                break;
+            }
+        }
+        if !exist {
+            let mut new_entry = ProtoFlagOverride::new();
+            new_entry.set_package_name(context.package.clone());
+            new_entry.set_flag_name(context.flag.clone());
+            new_entry.set_flag_value(String::from(value));
+            pb.overrides.push(new_entry);
+        }
+
+        write_pb_to_file::<ProtoLocalFlagOverrides>(&pb, &self.storage_record.local_overrides)?;
+
+        let flag_info_file = self.get_persist_flag_info()?;
+        Self::set_flag_has_local_override_to_file(flag_info_file, context, true)?;
+
+        Ok(())
+    }
+
+    /// Stage and apply local override of a flag
+    pub(crate) fn stage_and_apply_local_override(
+        &mut self,
+        context: &PackageFlagContext,
+        value: &str,
+    ) -> Result<(), AconfigdError> {
+        self.stage_local_override(&context, value)?;
+        let mut mut_boot_flag_val = self.get_mutable_boot_flag_val()?;
+        Self::set_flag_value_to_file(&mut mut_boot_flag_val, &context, value)?;
+        let mut mut_boot_flag_info = self.get_mutable_boot_flag_info()?;
+        Self::set_flag_has_local_override_to_file(&mut mut_boot_flag_info, &context, true)?;
+        Ok(())
+    }
+
+    /// Apply all staged local overrides
+    fn apply_staged_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+
+        for entry in pb.overrides {
+            let context = self.get_package_flag_context(entry.package_name(), entry.flag_name())?;
+            let mut flag_val_file = self.get_mutable_boot_flag_val()?;
+            Self::set_flag_value_to_file(&mut flag_val_file, &context, entry.flag_value())?;
+        }
+
+        Ok(())
+    }
+
+    /// Apply both server and local overrides
+    pub(crate) fn apply_all_staged_overrides(&mut self) -> Result<(), AconfigdError> {
+        copy_file(
+            &self.storage_record.persist_flag_val,
+            &self.storage_record.boot_flag_val,
+            0o644,
+        )?;
+        copy_file(
+            &self.storage_record.persist_flag_info,
+            &self.storage_record.boot_flag_info,
+            0o644,
+        )?;
+        self.apply_staged_local_overrides()?;
+        Ok(())
+    }
+
+    /// Get all current server overrides
+    pub(crate) fn get_all_server_overrides(
+        &mut self,
+    ) -> Result<Vec<FlagValueSummary>, AconfigdError> {
+        let listed_flags = list_flags_with_info(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.persist_flag_val.display().to_string(),
+            &self.storage_record.persist_flag_info.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlagsWithInfo {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?;
+
+        Ok(listed_flags
+            .into_iter()
+            .filter(|f| f.has_server_override)
+            .map(|f| FlagValueSummary {
+                package_name: f.package_name,
+                flag_name: f.flag_name,
+                flag_value: f.flag_value,
+                value_type: f.value_type,
+            })
+            .collect())
+    }
+
+    /// Get all local overrides
+    pub(crate) fn get_all_local_overrides(
+        &mut self,
+    ) -> Result<Vec<ProtoFlagOverride>, AconfigdError> {
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+        Ok(pb.overrides)
+    }
+
+    /// Remove a local flag override
+    pub(crate) fn remove_local_override(
+        &mut self,
+        context: &PackageFlagContext,
+    ) -> Result<(), AconfigdError> {
+        let attribute = self.get_flag_attribute(context)?;
+        if (attribute & FlagInfoBit::HasLocalOverride as u8) == 0 {
+            return Err(AconfigdError::FlagHasNoLocalOverride {
+                flag: context.package.to_string() + "." + &context.flag,
+            });
+        }
+
+        let mut pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+        pb.overrides = pb
+            .overrides
+            .into_iter()
+            .filter(|f| f.package_name() != context.package || f.flag_name() != context.flag)
+            .collect();
+        write_pb_to_file::<ProtoLocalFlagOverrides>(&pb, &self.storage_record.local_overrides)?;
+
+        let flag_info_file = self.get_persist_flag_info()?;
+        Self::set_flag_has_local_override_to_file(flag_info_file, context, false)?;
+
+        Ok(())
+    }
+
+    /// Remove all local flag overrides
+    pub(crate) fn remove_all_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+
+        for entry in pb.overrides {
+            let context = self.get_package_flag_context(entry.package_name(), entry.flag_name())?;
+            let attribute = self.get_flag_attribute(&context)?;
+            if (attribute & FlagInfoBit::HasLocalOverride as u8) == 0 {
+                return Err(AconfigdError::FlagHasNoLocalOverride {
+                    flag: context.package.to_string() + "." + &context.flag,
+                });
+            }
+
+            let flag_info_file = self.get_persist_flag_info()?;
+            Self::set_flag_has_local_override_to_file(flag_info_file, &context, false)?;
+        }
+
+        write_pb_to_file::<ProtoLocalFlagOverrides>(
+            &ProtoLocalFlagOverrides::new(),
+            &self.storage_record.local_overrides,
+        )?;
+
+        Ok(())
+    }
+
+    /// Clean up, it cannot be implemented as the drop trait as it needs to return a Result
+    pub(crate) fn remove_persist_files(&mut self) -> Result<(), AconfigdError> {
+        remove_file(&self.storage_record.persist_package_map)?;
+        remove_file(&self.storage_record.persist_flag_map)?;
+        remove_file(&self.storage_record.persist_flag_val)?;
+        remove_file(&self.storage_record.persist_flag_info)?;
+        remove_file(&self.storage_record.local_overrides)
+    }
+
+    /// get flag snapshot
+    pub(crate) fn get_flag_snapshot(
+        &mut self,
+        package: &str,
+        flag: &str,
+    ) -> Result<Option<FlagSnapshot>, AconfigdError> {
+        let context = self.get_package_flag_context(package, flag)?;
+        if !context.flag_exists {
+            return Ok(None);
+        }
+
+        let attribute = self.get_flag_attribute(&context)?;
+        let server_value = self.get_server_flag_value(&context)?;
+        let local_value = self.get_local_flag_value(&context)?;
+        let boot_value = self.get_boot_flag_value(&context)?;
+        let default_value = self.get_default_flag_value(&context)?;
+
+        Ok(Some(FlagSnapshot {
+            container: self.storage_record.container.clone(),
+            package: package.to_string(),
+            flag: flag.to_string(),
+            server_value,
+            local_value,
+            boot_value,
+            default_value,
+            is_readwrite: attribute & FlagInfoBit::IsReadWrite as u8 != 0,
+            has_server_override: attribute & FlagInfoBit::HasServerOverride as u8 != 0,
+            has_local_override: attribute & FlagInfoBit::HasLocalOverride as u8 != 0,
+        }))
+    }
+
+    /// list flags in a package
+    pub(crate) fn list_flags_in_package(
+        &mut self,
+        package: &str,
+    ) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        if !self.has_package(package)? {
+            return Ok(Vec::new());
+        }
+
+        let mut snapshots: Vec<_> = list_flags_with_info(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.persist_flag_val.display().to_string(),
+            &self.storage_record.persist_flag_info.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlagsWithInfo {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .filter(|f| f.package_name == package)
+        .map(|f| FlagSnapshot {
+            container: self.storage_record.container.clone(),
+            package: f.package_name.clone(),
+            flag: f.flag_name.clone(),
+            server_value: if f.has_server_override { f.flag_value.clone() } else { String::new() },
+            local_value: String::new(),
+            boot_value: String::new(),
+            default_value: String::new(),
+            is_readwrite: f.is_readwrite,
+            has_server_override: f.has_server_override,
+            has_local_override: f.has_local_override,
+        })
+        .collect();
+
+        let mut flag_index = HashMap::new();
+        for (i, f) in snapshots.iter().enumerate() {
+            flag_index.insert(f.package.clone() + "/" + &f.flag, i);
+        }
+
+        let mut flags: Vec<_> = list_flags(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.boot_flag_val.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlags {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .filter(|f| f.package_name == package)
+        .collect();
+
+        for f in flags.iter() {
+            let full_flag_name = f.package_name.clone() + "/" + &f.flag_name;
+            let index =
+                flag_index.get(&full_flag_name).ok_or(AconfigdError::InternalError(anyhow!(
+                    "Flag {}.{} appears in boot files but not in persist fliles",
+                    &f.package_name,
+                    &f.flag_name,
+                )))?;
+            snapshots[*index].boot_value = f.flag_value.clone();
+        }
+
+        flags = list_flags(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.default_flag_val.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlags {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .filter(|f| f.package_name == package)
+        .collect();
+
+        for f in flags.iter() {
+            let full_flag_name = f.package_name.clone() + "/" + &f.flag_name;
+            let index =
+                flag_index.get(&full_flag_name).ok_or(AconfigdError::InternalError(anyhow!(
+                    "Flag {}.{} appears in default files but not in persist fliles",
+                    &f.package_name,
+                    &f.flag_name,
+                )))?;
+            snapshots[*index].default_value = f.flag_value.clone();
+        }
+
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+
+        for entry in pb.overrides {
+            let full_flag_name = entry.package_name().to_string() + "/" + entry.flag_name();
+            if let Some(index) = flag_index.get(&full_flag_name) {
+                snapshots[*index].local_value = entry.flag_value().to_string();
+            }
+        }
+
+        Ok(snapshots)
+    }
+
+    /// list all flags in a container
+    pub(crate) fn list_all_flags(&mut self) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        let mut snapshots: Vec<_> = list_flags_with_info(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.persist_flag_val.display().to_string(),
+            &self.storage_record.persist_flag_info.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlagsWithInfo {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .map(|f| FlagSnapshot {
+            container: self.storage_record.container.clone(),
+            package: f.package_name.clone(),
+            flag: f.flag_name.clone(),
+            server_value: if f.has_server_override { f.flag_value.clone() } else { String::new() },
+            local_value: String::new(),
+            boot_value: String::new(),
+            default_value: String::new(),
+            is_readwrite: f.is_readwrite,
+            has_server_override: f.has_server_override,
+            has_local_override: f.has_local_override,
+        })
+        .collect();
+
+        let mut flag_index = HashMap::new();
+        for (i, f) in snapshots.iter().enumerate() {
+            flag_index.insert(f.package.clone() + "/" + &f.flag, i);
+        }
+
+        let mut flags: Vec<_> = list_flags(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.boot_flag_val.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlags {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .collect();
+
+        for f in flags.iter() {
+            let full_flag_name = f.package_name.clone() + "/" + &f.flag_name;
+            let index =
+                flag_index.get(&full_flag_name).ok_or(AconfigdError::InternalError(anyhow!(
+                    "Flag {}.{} appears in boot files but not in persist fliles",
+                    &f.package_name,
+                    &f.flag_name,
+                )))?;
+            snapshots[*index].boot_value = f.flag_value.clone();
+        }
+
+        flags = list_flags(
+            &self.storage_record.persist_package_map.display().to_string(),
+            &self.storage_record.persist_flag_map.display().to_string(),
+            &self.storage_record.default_flag_val.display().to_string(),
+        )
+        .map_err(|errmsg| AconfigdError::FailToListFlags {
+            container: self.storage_record.container.clone(),
+            errmsg,
+        })?
+        .into_iter()
+        .collect();
+
+        for f in flags.iter() {
+            let full_flag_name = f.package_name.clone() + "/" + &f.flag_name;
+            let index =
+                flag_index.get(&full_flag_name).ok_or(AconfigdError::InternalError(anyhow!(
+                    "Flag {}.{} appears in default files but not in persist fliles",
+                    &f.package_name,
+                    &f.flag_name,
+                )))?;
+            snapshots[*index].default_value = f.flag_value.clone();
+        }
+
+        let pb =
+            read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
+
+        for entry in pb.overrides {
+            let full_flag_name = entry.package_name().to_string() + "/" + entry.flag_name();
+            if let Some(index) = flag_index.get(&full_flag_name) {
+                snapshots[*index].local_value = entry.flag_value().to_string();
+            }
+        }
+
+        Ok(snapshots)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::test_utils::{has_same_content, ContainerMock, StorageRootDirMock};
+    use aconfig_storage_file::StoredFlagType;
+
+    fn create_mock_storage_files(
+        container: &ContainerMock,
+        root_dir: &StorageRootDirMock,
+    ) -> StorageFiles {
+        StorageFiles::from_container(
+            &container.name,
+            &container.package_map,
+            &container.flag_map,
+            &container.flag_val,
+            &container.flag_info,
+            &root_dir.tmp_dir.path(),
+        )
+        .unwrap()
+    }
+
+    #[test]
+    fn test_create_storage_file_from_container() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let expected_record = StorageRecord {
+            version: 1,
+            container: String::from("mockup"),
+            default_package_map: container.package_map.clone(),
+            default_flag_map: container.flag_map.clone(),
+            default_flag_val: container.flag_val.clone(),
+            default_flag_info: container.flag_info.clone(),
+            persist_package_map: root_dir.maps_dir.join("mockup.package.map"),
+            persist_flag_map: root_dir.maps_dir.join("mockup.flag.map"),
+            persist_flag_val: root_dir.flags_dir.join("mockup.val"),
+            persist_flag_info: root_dir.flags_dir.join("mockup.info"),
+            local_overrides: root_dir.flags_dir.join("mockup_local_overrides.pb"),
+            boot_flag_val: root_dir.boot_dir.join("mockup.val"),
+            boot_flag_info: root_dir.boot_dir.join("mockup.info"),
+            digest: get_files_digest(
+                &[
+                    container.package_map.as_path(),
+                    container.flag_map.as_path(),
+                    container.flag_val.as_path(),
+                    container.flag_info.as_path(),
+                ][..],
+            )
+            .unwrap(),
+        };
+
+        let expected_storage_files = StorageFiles {
+            storage_record: expected_record,
+            package_map: None,
+            flag_map: None,
+            flag_val: None,
+            boot_flag_val: None,
+            boot_flag_info: None,
+            persist_flag_val: None,
+            persist_flag_info: None,
+            mutable_boot_flag_val: None,
+            mutable_boot_flag_info: None,
+        };
+
+        assert_eq!(storage_files, expected_storage_files);
+
+        assert!(has_same_content(
+            &container.package_map,
+            &storage_files.storage_record.persist_package_map
+        ));
+        assert!(has_same_content(
+            &container.flag_map,
+            &storage_files.storage_record.persist_flag_map
+        ));
+        assert!(has_same_content(
+            &container.flag_val,
+            &storage_files.storage_record.persist_flag_val
+        ));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.persist_flag_info
+        ));
+        assert!(has_same_content(&container.flag_val, &storage_files.storage_record.boot_flag_val));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.boot_flag_info
+        ));
+        assert!(storage_files.storage_record.local_overrides.exists());
+    }
+
+    #[test]
+    fn test_create_storage_file_from_pb() {
+        let root_dir = StorageRootDirMock::new();
+        let container = ContainerMock::new();
+
+        let persist_package_map = root_dir.maps_dir.join("mockup.package.map");
+        let persist_flag_map = root_dir.maps_dir.join("mockup.flag.map");
+        let persist_flag_val = root_dir.flags_dir.join("mockup.val");
+        let persist_flag_info = root_dir.flags_dir.join("mockup.info");
+        copy_file(&container.package_map, &persist_package_map, 0o444).unwrap();
+        copy_file(&container.flag_map, &persist_flag_map, 0o444).unwrap();
+        copy_file(&container.flag_val, &persist_flag_val, 0o644).unwrap();
+        copy_file(&container.flag_info, &persist_flag_info, 0o644).unwrap();
+
+        let mut pb = ProtoPersistStorageRecord::new();
+        pb.set_version(123);
+        pb.set_container("mockup".to_string());
+        pb.set_package_map(container.package_map.display().to_string());
+        pb.set_flag_map(container.flag_map.display().to_string());
+        pb.set_flag_val(container.flag_val.display().to_string());
+        pb.set_flag_info(container.flag_info.display().to_string());
+        pb.set_digest(String::from("abc"));
+
+        let storage_files = StorageFiles::from_pb(&pb, &root_dir.tmp_dir.path()).unwrap();
+
+        let expected_record = StorageRecord {
+            version: 123,
+            container: String::from("mockup"),
+            default_package_map: container.package_map.clone(),
+            default_flag_map: container.flag_map.clone(),
+            default_flag_val: container.flag_val.clone(),
+            default_flag_info: container.flag_info.clone(),
+            persist_package_map: root_dir.maps_dir.join("mockup.package.map"),
+            persist_flag_map: root_dir.maps_dir.join("mockup.flag.map"),
+            persist_flag_val: root_dir.flags_dir.join("mockup.val"),
+            persist_flag_info: root_dir.flags_dir.join("mockup.info"),
+            local_overrides: root_dir.flags_dir.join("mockup_local_overrides.pb"),
+            boot_flag_val: root_dir.boot_dir.join("mockup.val"),
+            boot_flag_info: root_dir.boot_dir.join("mockup.info"),
+            digest: String::from("abc"),
+        };
+
+        let expected_storage_files = StorageFiles {
+            storage_record: expected_record,
+            package_map: None,
+            flag_map: None,
+            flag_val: None,
+            boot_flag_val: None,
+            boot_flag_info: None,
+            persist_flag_val: None,
+            persist_flag_info: None,
+            mutable_boot_flag_val: None,
+            mutable_boot_flag_info: None,
+        };
+
+        assert!(has_same_content(
+            &storage_files.storage_record.persist_flag_val,
+            &storage_files.storage_record.boot_flag_val
+        ));
+        assert!(has_same_content(
+            &storage_files.storage_record.persist_flag_info,
+            &storage_files.storage_record.boot_flag_info
+        ));
+
+        assert_eq!(storage_files, expected_storage_files);
+    }
+
+    #[test]
+    fn test_get_package_flag_context() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let mut context = PackageFlagContext {
+            package: String::from("not_exist"),
+            flag: String::new(),
+            package_exists: false,
+            flag_exists: false,
+            value_type: FlagValueType::Boolean,
+            flag_index: 0,
+        };
+        let mut actual_context = storage_files.get_package_flag_context("not_exist", "").unwrap();
+        assert_eq!(context, actual_context);
+
+        context.package = String::from("com.android.aconfig.storage.test_1");
+        context.package_exists = true;
+        actual_context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "")
+            .unwrap();
+        assert_eq!(context, actual_context);
+
+        context.flag = String::from("not_exist");
+        actual_context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "not_exist")
+            .unwrap();
+        assert_eq!(context, actual_context);
+
+        context.flag = String::from("enabled_rw");
+        context.flag_exists = true;
+        context.flag_index = 2;
+        actual_context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        assert_eq!(context, actual_context);
+
+        context.package = String::from("com.android.aconfig.storage.test_2");
+        context.flag = String::from("disabled_rw");
+        context.flag_index = 3;
+        actual_context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        assert_eq!(context, actual_context);
+    }
+
+    #[test]
+    fn test_has_package() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        assert!(!storage_files.has_package("not_exist").unwrap());
+        assert!(storage_files.has_package("com.android.aconfig.storage.test_1").unwrap());
+    }
+
+    #[test]
+    fn test_get_flag_attribute() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let mut context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "not_exist")
+            .unwrap();
+        assert!(storage_files.get_flag_attribute(&context).is_err());
+
+        context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::IsReadWrite as u8) != 0);
+        assert!(attribute & (FlagInfoBit::HasServerOverride as u8) == 0);
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) == 0);
+    }
+
+    #[test]
+    fn test_get_server_flag_value() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+
+        assert_eq!(&storage_files.get_server_flag_value(&context).unwrap(), "");
+        storage_files.stage_server_override(&context, "false").unwrap();
+        assert_eq!(&storage_files.get_server_flag_value(&context).unwrap(), "false");
+        storage_files.stage_server_override(&context, "true").unwrap();
+        assert_eq!(&storage_files.get_server_flag_value(&context).unwrap(), "true");
+    }
+
+    #[test]
+    fn test_get_boot_flag_value() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let mut context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        assert_eq!(storage_files.get_boot_flag_value(&context).unwrap(), "true");
+        context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        assert_eq!(storage_files.get_boot_flag_value(&context).unwrap(), "false");
+    }
+
+    #[test]
+    fn test_get_default_flag_value() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let mut context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        assert_eq!(storage_files.get_default_flag_value(&context).unwrap(), "true");
+        context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        assert_eq!(storage_files.get_default_flag_value(&context).unwrap(), "false");
+    }
+
+    #[test]
+    fn test_get_local_flag_value() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "");
+        storage_files.stage_local_override(&context, "false").unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "false");
+        storage_files.stage_local_override(&context, "true").unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "true");
+    }
+
+    #[test]
+    fn test_stage_server_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context, "false").unwrap();
+        assert_eq!(&storage_files.get_server_flag_value(&context).unwrap(), "false");
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::HasServerOverride as u8) != 0);
+    }
+
+    #[test]
+    fn test_stage_local_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_local_override(&context, "false").unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "false");
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) != 0);
+    }
+
+    #[test]
+    fn test_stage_and_apply_local_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_and_apply_local_override(&context, "false").unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "false");
+        assert_eq!(&storage_files.get_boot_flag_value(&context).unwrap(), "false");
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) != 0);
+    }
+
+    #[test]
+    fn test_apply_all_staged_overrides() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let context_one = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_one, "false").unwrap();
+
+        let context_two = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_two, "false").unwrap();
+        storage_files.stage_local_override(&context_two, "true").unwrap();
+
+        storage_files.apply_all_staged_overrides().unwrap();
+
+        assert!(storage_files.storage_record.boot_flag_val.exists());
+        assert!(storage_files.storage_record.boot_flag_info.exists());
+
+        assert_eq!(storage_files.get_boot_flag_value(&context_one).unwrap(), "false");
+        assert_eq!(storage_files.get_boot_flag_value(&context_two).unwrap(), "true");
+    }
+
+    #[test]
+    fn test_get_all_server_overrides() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let mut context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context, "false").unwrap();
+        context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context, "true").unwrap();
+        let server_overrides = storage_files.get_all_server_overrides().unwrap();
+        assert_eq!(server_overrides.len(), 2);
+        assert_eq!(
+            server_overrides[0],
+            FlagValueSummary {
+                package_name: "com.android.aconfig.storage.test_1".to_string(),
+                flag_name: "enabled_rw".to_string(),
+                flag_value: "false".to_string(),
+                value_type: StoredFlagType::ReadWriteBoolean,
+            }
+        );
+        assert_eq!(
+            server_overrides[1],
+            FlagValueSummary {
+                package_name: "com.android.aconfig.storage.test_2".to_string(),
+                flag_name: "disabled_rw".to_string(),
+                flag_value: "true".to_string(),
+                value_type: StoredFlagType::ReadWriteBoolean,
+            }
+        );
+    }
+
+    #[test]
+    fn test_get_all_local_overrides() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let context_one = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_local_override(&context_one, "false").unwrap();
+
+        let context_two = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        storage_files.stage_local_override(&context_two, "false").unwrap();
+
+        let local_overrides = storage_files.get_all_local_overrides().unwrap();
+        assert_eq!(local_overrides.len(), 2);
+
+        let mut override_proto = ProtoFlagOverride::new();
+        override_proto.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        override_proto.set_flag_name("enabled_rw".to_string());
+        override_proto.set_flag_value("false".to_string());
+        assert_eq!(local_overrides[0], override_proto);
+
+        override_proto.set_package_name("com.android.aconfig.storage.test_2".to_string());
+        override_proto.set_flag_name("disabled_rw".to_string());
+        assert_eq!(local_overrides[1], override_proto);
+    }
+
+    #[test]
+    fn test_remove_local_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+
+        assert!(storage_files.remove_local_override(&context).is_err());
+        storage_files.stage_local_override(&context, "false").unwrap();
+        storage_files.remove_local_override(&context).unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "");
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) == 0);
+    }
+
+    #[test]
+    fn test_remove_all_local_overrides() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let context_one = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_local_override(&context_one, "false").unwrap();
+
+        let context_two = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        storage_files.stage_local_override(&context_two, "false").unwrap();
+
+        let mut pb = read_pb_from_file::<ProtoLocalFlagOverrides>(
+            &storage_files.storage_record.local_overrides,
+        )
+        .unwrap();
+        assert_eq!(pb.overrides.len(), 2);
+
+        storage_files.remove_all_local_overrides().unwrap();
+
+        assert_eq!(&storage_files.get_local_flag_value(&context_one).unwrap(), "");
+        let mut attribute = storage_files.get_flag_attribute(&context_one).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) == 0);
+
+        assert_eq!(&storage_files.get_local_flag_value(&context_two).unwrap(), "");
+        attribute = storage_files.get_flag_attribute(&context_one).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) == 0);
+
+        pb = read_pb_from_file::<ProtoLocalFlagOverrides>(
+            &storage_files.storage_record.local_overrides,
+        )
+        .unwrap();
+        assert_eq!(pb.overrides.len(), 0);
+    }
+
+    #[test]
+    fn test_remove_persist_files() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+        write_pb_to_file::<ProtoLocalFlagOverrides>(
+            &ProtoLocalFlagOverrides::new(),
+            &storage_files.storage_record.local_overrides,
+        )
+        .unwrap();
+        assert!(storage_files.storage_record.persist_package_map.exists());
+        assert!(storage_files.storage_record.persist_flag_map.exists());
+        assert!(storage_files.storage_record.persist_flag_val.exists());
+        assert!(storage_files.storage_record.persist_flag_info.exists());
+        assert!(storage_files.storage_record.local_overrides.exists());
+
+        storage_files.remove_persist_files().unwrap();
+        assert!(!storage_files.storage_record.persist_package_map.exists());
+        assert!(!storage_files.storage_record.persist_flag_map.exists());
+        assert!(!storage_files.storage_record.persist_flag_val.exists());
+        assert!(!storage_files.storage_record.persist_flag_info.exists());
+        assert!(!storage_files.storage_record.local_overrides.exists());
+    }
+
+    #[test]
+    fn test_get_flag_snapshot() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let mut flag = storage_files
+            .get_flag_snapshot("com.android.aconfig.storage.test_1", "not_exist")
+            .unwrap();
+        assert_eq!(flag, None);
+
+        let context = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "disabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context, "false").unwrap();
+        storage_files.stage_local_override(&context, "true").unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+
+        flag = storage_files
+            .get_flag_snapshot("com.android.aconfig.storage.test_1", "disabled_rw")
+            .unwrap();
+
+        let expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_list_flags_in_package() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let context_one = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_one, "false").unwrap();
+        let context_two = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "disabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_two, "false").unwrap();
+        storage_files.stage_local_override(&context_two, "true").unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+
+        let flags =
+            storage_files.list_flags_in_package("com.android.aconfig.storage.test_1").unwrap();
+
+        let mut flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+        assert_eq!(flags[0], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_ro"),
+            server_value: String::new(),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("true"),
+            is_readwrite: false,
+            has_server_override: false,
+            has_local_override: false,
+        };
+        assert_eq!(flags[1], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+        assert_eq!(flags[2], flag);
+    }
+
+    #[test]
+    fn test_list_all_flags() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut storage_files = create_mock_storage_files(&container, &root_dir);
+
+        let context_one = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_one, "false").unwrap();
+        let context_two = storage_files
+            .get_package_flag_context("com.android.aconfig.storage.test_2", "disabled_rw")
+            .unwrap();
+        storage_files.stage_server_override(&context_two, "false").unwrap();
+        storage_files.stage_local_override(&context_two, "true").unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+
+        let flags = storage_files.list_all_flags().unwrap();
+        assert_eq!(flags.len(), 8);
+
+        let mut flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+        assert_eq!(flags[2], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_2"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+        assert_eq!(flags[3], flag);
+    }
+}
diff --git a/aconfigd/src/storage_files_manager.rs b/aconfigd/src/storage_files_manager.rs
new file mode 100644
index 0000000..d5aff16
--- /dev/null
+++ b/aconfigd/src/storage_files_manager.rs
@@ -0,0 +1,1192 @@
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
+use crate::storage_files::{FlagSnapshot, StorageFiles};
+use crate::utils::{get_files_digest, read_pb_from_file, remove_file, write_pb_to_file};
+use crate::AconfigdError;
+use aconfigd_protos::{
+    ProtoFlagOverride, ProtoFlagOverrideType, ProtoLocalFlagOverrides, ProtoOTAFlagStagingMessage,
+    ProtoPersistStorageRecord, ProtoPersistStorageRecords,
+};
+use log::debug;
+use std::collections::HashMap;
+use std::path::{Path, PathBuf};
+
+// Storage files manager to manage all the storage files across containers
+#[derive(Debug)]
+pub(crate) struct StorageFilesManager {
+    pub root_dir: PathBuf,
+    pub all_storage_files: HashMap<String, StorageFiles>,
+    pub package_to_container: HashMap<String, String>,
+}
+
+impl StorageFilesManager {
+    /// Constructor
+    pub(crate) fn new(root_dir: &Path) -> Self {
+        Self {
+            root_dir: root_dir.to_path_buf(),
+            all_storage_files: HashMap::new(),
+            package_to_container: HashMap::new(),
+        }
+    }
+
+    /// Get storage files for a container
+    fn get_storage_files(&mut self, container: &str) -> Option<&mut StorageFiles> {
+        self.all_storage_files.get_mut(container)
+    }
+
+    /// Add storage files based on a storage record pb entry
+    pub(crate) fn add_storage_files_from_pb(
+        &mut self,
+        pb: &ProtoPersistStorageRecord,
+    ) -> Result<(), AconfigdError> {
+        if self.all_storage_files.contains_key(pb.container()) {
+            debug!(
+                "Ignored request to add storage files from pb for {}, already exists",
+                pb.container()
+            );
+            return Ok(());
+        }
+        self.all_storage_files
+            .insert(String::from(pb.container()), StorageFiles::from_pb(pb, &self.root_dir)?);
+
+        Ok(())
+    }
+
+    /// Add a new container's storage files
+    fn add_storage_files_from_container(
+        &mut self,
+        container: &str,
+        default_package_map: &Path,
+        default_flag_map: &Path,
+        default_flag_val: &Path,
+        default_flag_info: &Path,
+    ) -> Result<&mut StorageFiles, AconfigdError> {
+        if self.all_storage_files.contains_key(container) {
+            debug!(
+                "Ignored request to add storage files from container {}, already exists",
+                container
+            );
+        }
+
+        self.all_storage_files.insert(
+            String::from(container),
+            StorageFiles::from_container(
+                container,
+                default_package_map,
+                default_flag_map,
+                default_flag_val,
+                default_flag_info,
+                &self.root_dir,
+            )?,
+        );
+
+        self.all_storage_files
+            .get_mut(container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })
+    }
+
+    /// Update a container's storage files in the case of container update
+    fn update_container_storage_files(
+        &mut self,
+        container: &str,
+        default_package_map: &Path,
+        default_flag_map: &Path,
+        default_flag_val: &Path,
+        default_flag_info: &Path,
+    ) -> Result<(), AconfigdError> {
+        let mut storage_files = self
+            .get_storage_files(container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+        // backup overrides
+        let server_overrides = storage_files.get_all_server_overrides()?;
+        let local_overrides = storage_files.get_all_local_overrides()?;
+
+        // recreate storage files object
+        storage_files.remove_persist_files()?;
+        self.all_storage_files.remove(container);
+        storage_files = self.add_storage_files_from_container(
+            container,
+            default_package_map,
+            default_flag_map,
+            default_flag_val,
+            default_flag_info,
+        )?;
+
+        // restage server overrides
+        for f in server_overrides.iter() {
+            let context = storage_files.get_package_flag_context(&f.package_name, &f.flag_name)?;
+            if context.flag_exists {
+                storage_files.stage_server_override(&context, &f.flag_value)?;
+            }
+        }
+
+        // restage local overrides
+        let mut new_pb = ProtoLocalFlagOverrides::new();
+        for f in local_overrides.into_iter() {
+            let context =
+                storage_files.get_package_flag_context(f.package_name(), f.flag_name())?;
+            if context.flag_exists {
+                storage_files.stage_local_override(&context, f.flag_value())?;
+                new_pb.overrides.push(f);
+            }
+        }
+        write_pb_to_file::<ProtoLocalFlagOverrides>(
+            &new_pb,
+            &storage_files.storage_record.local_overrides,
+        )?;
+
+        Ok(())
+    }
+
+    /// add or update a container's storage files in the case of container update
+    pub(crate) fn add_or_update_container_storage_files(
+        &mut self,
+        container: &str,
+        default_package_map: &Path,
+        default_flag_map: &Path,
+        default_flag_val: &Path,
+        default_flag_info: &Path,
+    ) -> Result<(), AconfigdError> {
+        match self.get_storage_files(container) {
+            Some(storage_files) => {
+                let digest = get_files_digest(
+                    &[default_package_map, default_flag_map, default_flag_val, default_flag_info][..],
+                )?;
+                if storage_files.storage_record.digest != digest {
+                    self.update_container_storage_files(
+                        container,
+                        default_package_map,
+                        default_flag_map,
+                        default_flag_val,
+                        default_flag_info,
+                    )?;
+                }
+            }
+            None => {
+                self.add_storage_files_from_container(
+                    container,
+                    default_package_map,
+                    default_flag_map,
+                    default_flag_val,
+                    default_flag_info,
+                )?;
+            }
+        }
+
+        Ok(())
+    }
+
+    /// Apply all staged server and local overrides
+    pub(crate) fn apply_all_staged_overrides(
+        &mut self,
+        container: &str,
+    ) -> Result<(), AconfigdError> {
+        let storage_files = self
+            .get_storage_files(container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+        storage_files.apply_all_staged_overrides()?;
+        Ok(())
+    }
+
+    /// Reset all storage files
+    pub(crate) fn reset_all_storage(&mut self) -> Result<(), AconfigdError> {
+        let all_containers = self.all_storage_files.keys().cloned().collect::<Vec<String>>();
+        for container in all_containers {
+            let storage_files = self
+                .get_storage_files(&container)
+                .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+            let record = storage_files.storage_record.clone();
+            storage_files.remove_persist_files()?;
+            self.all_storage_files.remove(&container);
+
+            self.add_storage_files_from_container(
+                &container,
+                &record.default_package_map,
+                &record.default_flag_map,
+                &record.default_flag_val,
+                &record.default_flag_info,
+            )?;
+        }
+        Ok(())
+    }
+
+    /// Get container
+    fn get_container(&mut self, package: &str) -> Result<Option<String>, AconfigdError> {
+        match self.package_to_container.get(package) {
+            Some(container) => Ok(Some(container.clone())),
+            None => {
+                for (container, storage_files) in &mut self.all_storage_files {
+                    if storage_files.has_package(package)? {
+                        self.package_to_container.insert(String::from(package), container.clone());
+                        return Ok(Some(container.clone()));
+                    }
+                }
+                Ok(None)
+            }
+        }
+    }
+
+    /// Apply flag override
+    pub(crate) fn override_flag_value(
+        &mut self,
+        package: &str,
+        flag: &str,
+        value: &str,
+        override_type: ProtoFlagOverrideType,
+    ) -> Result<(), AconfigdError> {
+        let container = self
+            .get_container(package)?
+            .ok_or(AconfigdError::FailToFindContainer { package: package.to_string() })?;
+
+        let storage_files = self
+            .get_storage_files(&container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+        let context = storage_files.get_package_flag_context(package, flag)?;
+        match override_type {
+            ProtoFlagOverrideType::SERVER_ON_REBOOT => {
+                storage_files.stage_server_override(&context, value)?;
+            }
+            ProtoFlagOverrideType::LOCAL_ON_REBOOT => {
+                storage_files.stage_local_override(&context, value)?;
+            }
+            ProtoFlagOverrideType::LOCAL_IMMEDIATE => {
+                storage_files.stage_and_apply_local_override(&context, value)?;
+            }
+        }
+
+        Ok(())
+    }
+
+    /// Read staged ota flags
+    fn get_ota_flags(&mut self) -> Result<Option<Vec<ProtoFlagOverride>>, AconfigdError> {
+        let ota_pb_file = self.root_dir.join("flags/ota.pb");
+        if !ota_pb_file.exists() {
+            return Ok(None);
+        }
+
+        let ota_flags_pb = read_pb_from_file::<ProtoOTAFlagStagingMessage>(&ota_pb_file)?;
+        if let Some(target_build_id) = ota_flags_pb.build_id {
+            let device_build_id = rustutils::system_properties::read("ro.build.fingerprint")
+                .map_err(|errmsg| AconfigdError::FailToReadBuildFingerPrint { errmsg })?;
+            if device_build_id == Some(target_build_id) {
+                remove_file(&ota_pb_file)?;
+                Ok(Some(ota_flags_pb.overrides))
+            } else {
+                Ok(None)
+            }
+        } else {
+            remove_file(&ota_pb_file)?;
+            return Ok(None);
+        }
+    }
+
+    /// Apply staged ota flags
+    pub(crate) fn apply_staged_ota_flags(&mut self) -> Result<(), AconfigdError> {
+        if let Some(flags) = self.get_ota_flags()? {
+            for flag in flags.iter() {
+                if let Err(errmsg) = self.override_flag_value(
+                    flag.package_name(),
+                    flag.flag_name(),
+                    flag.flag_value(),
+                    ProtoFlagOverrideType::SERVER_ON_REBOOT,
+                ) {
+                    debug!(
+                        "failed to apply ota flag override for {}.{}: {:?}",
+                        flag.package_name(),
+                        flag.flag_name(),
+                        errmsg
+                    );
+                }
+            }
+        }
+        Ok(())
+    }
+
+    /// Write persist storage records to file
+    pub(crate) fn write_persist_storage_records_to_file(
+        &self,
+        file: &Path,
+    ) -> Result<(), AconfigdError> {
+        let mut pb = ProtoPersistStorageRecords::new();
+        pb.records = self
+            .all_storage_files
+            .values()
+            .map(|storage_files| {
+                let record = &storage_files.storage_record;
+                let mut entry = ProtoPersistStorageRecord::new();
+                entry.set_version(record.version);
+                entry.set_container(record.container.clone());
+                entry.set_package_map(record.default_package_map.display().to_string());
+                entry.set_flag_map(record.default_flag_map.display().to_string());
+                entry.set_flag_val(record.default_flag_val.display().to_string());
+                entry.set_flag_info(record.default_flag_info.display().to_string());
+                entry.set_digest(record.digest.clone());
+                entry
+            })
+            .collect();
+        write_pb_to_file(&pb, file)
+    }
+
+    /// Remove a single local override
+    pub(crate) fn remove_local_override(
+        &mut self,
+        package: &str,
+        flag: &str,
+    ) -> Result<(), AconfigdError> {
+        let container = self
+            .get_container(package)?
+            .ok_or(AconfigdError::FailToFindContainer { package: package.to_string() })?;
+
+        let storage_files = self
+            .get_storage_files(&container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+        let context = storage_files.get_package_flag_context(package, flag)?;
+        storage_files.remove_local_override(&context)
+    }
+
+    /// Remove all local overrides
+    pub(crate) fn remove_all_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        for storage_files in self.all_storage_files.values_mut() {
+            storage_files.remove_all_local_overrides()?;
+        }
+        Ok(())
+    }
+
+    /// Get flag snapshot
+    pub(crate) fn get_flag_snapshot(
+        &mut self,
+        package: &str,
+        flag: &str,
+    ) -> Result<Option<FlagSnapshot>, AconfigdError> {
+        match self.get_container(package)? {
+            Some(container) => {
+                let storage_files = self.get_storage_files(&container).ok_or(
+                    AconfigdError::FailToGetStorageFiles { container: container.to_string() },
+                )?;
+
+                storage_files.get_flag_snapshot(package, flag)
+            }
+            None => Ok(None),
+        }
+    }
+
+    /// List all flags in a package
+    pub(crate) fn list_flags_in_package(
+        &mut self,
+        package: &str,
+    ) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        let container = self
+            .get_container(package)?
+            .ok_or(AconfigdError::FailToFindContainer { package: package.to_string() })?;
+
+        let storage_files = self
+            .get_storage_files(&container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+        storage_files.list_flags_in_package(package)
+    }
+
+    /// List flags in a container
+    pub(crate) fn list_flags_in_container(
+        &mut self,
+        container: &str,
+    ) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        let storage_files = self
+            .get_storage_files(&container)
+            .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
+
+        storage_files.list_all_flags()
+    }
+
+    /// List all the flags
+    pub(crate) fn list_all_flags(&mut self) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        let mut flags = Vec::new();
+        for storage_files in self.all_storage_files.values_mut() {
+            if !storage_files.has_boot_copy() {
+                continue;
+            }
+            flags.extend(storage_files.list_all_flags()?);
+        }
+        Ok(flags)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::storage_files::StorageRecord;
+    use crate::test_utils::{has_same_content, ContainerMock, StorageRootDirMock};
+    use crate::utils::{copy_file, get_files_digest, read_pb_from_file};
+    use aconfig_storage_file::{FlagValueSummary, StoredFlagType};
+    use aconfigd_protos::ProtoFlagOverride;
+
+    #[test]
+    fn test_add_storage_files_from_pb() {
+        let root_dir = StorageRootDirMock::new();
+        let container = ContainerMock::new();
+
+        let persist_package_map = root_dir.maps_dir.join("mockup.package.map");
+        let persist_flag_map = root_dir.maps_dir.join("mockup.flag.map");
+        let persist_flag_val = root_dir.flags_dir.join("mockup.val");
+        let persist_flag_info = root_dir.flags_dir.join("mockup.info");
+        copy_file(&container.package_map, &persist_package_map, 0o444).unwrap();
+        copy_file(&container.flag_map, &persist_flag_map, 0o444).unwrap();
+        copy_file(&container.flag_val, &persist_flag_val, 0o644).unwrap();
+        copy_file(&container.flag_info, &persist_flag_info, 0o644).unwrap();
+
+        let mut pb = ProtoPersistStorageRecord::new();
+        pb.set_version(123);
+        pb.set_container("mockup".to_string());
+        pb.set_package_map(container.package_map.display().to_string());
+        pb.set_flag_map(container.flag_map.display().to_string());
+        pb.set_flag_val(container.flag_val.display().to_string());
+        pb.set_flag_info(container.flag_info.display().to_string());
+        pb.set_digest(String::from("abc"));
+
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        manager.add_storage_files_from_pb(&pb);
+        assert_eq!(manager.all_storage_files.len(), 1);
+        assert_eq!(
+            manager.all_storage_files.get("mockup").unwrap(),
+            &StorageFiles::from_pb(&pb, &root_dir.tmp_dir.path()).unwrap(),
+        );
+    }
+
+    fn init_storage(container: &ContainerMock, manager: &mut StorageFilesManager) {
+        manager
+            .add_or_update_container_storage_files(
+                &container.name,
+                &container.package_map,
+                &container.flag_map,
+                &container.flag_val,
+                &container.flag_info,
+            )
+            .unwrap();
+    }
+
+    #[test]
+    fn test_add_storage_files_from_container() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+
+        let storage_files = manager.get_storage_files(&container.name).unwrap();
+
+        let expected_record = StorageRecord {
+            version: 1,
+            container: String::from("mockup"),
+            default_package_map: container.package_map.clone(),
+            default_flag_map: container.flag_map.clone(),
+            default_flag_val: container.flag_val.clone(),
+            default_flag_info: container.flag_info.clone(),
+            persist_package_map: root_dir.maps_dir.join("mockup.package.map"),
+            persist_flag_map: root_dir.maps_dir.join("mockup.flag.map"),
+            persist_flag_val: root_dir.flags_dir.join("mockup.val"),
+            persist_flag_info: root_dir.flags_dir.join("mockup.info"),
+            local_overrides: root_dir.flags_dir.join("mockup_local_overrides.pb"),
+            boot_flag_val: root_dir.boot_dir.join("mockup.val"),
+            boot_flag_info: root_dir.boot_dir.join("mockup.info"),
+            digest: get_files_digest(
+                &[
+                    container.package_map.as_path(),
+                    container.flag_map.as_path(),
+                    container.flag_val.as_path(),
+                    container.flag_info.as_path(),
+                ][..],
+            )
+            .unwrap(),
+        };
+
+        let expected_storage_files = StorageFiles {
+            storage_record: expected_record,
+            package_map: None,
+            flag_map: None,
+            flag_val: None,
+            boot_flag_val: None,
+            boot_flag_info: None,
+            persist_flag_val: None,
+            persist_flag_info: None,
+            mutable_boot_flag_val: None,
+            mutable_boot_flag_info: None,
+        };
+
+        assert_eq!(storage_files, &expected_storage_files);
+
+        assert!(has_same_content(
+            &container.package_map,
+            &storage_files.storage_record.persist_package_map
+        ));
+        assert!(has_same_content(
+            &container.flag_map,
+            &storage_files.storage_record.persist_flag_map
+        ));
+        assert!(has_same_content(
+            &container.flag_val,
+            &storage_files.storage_record.persist_flag_val
+        ));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.persist_flag_info
+        ));
+        assert!(has_same_content(&container.flag_val, &storage_files.storage_record.boot_flag_val));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.boot_flag_info
+        ));
+    }
+
+    #[test]
+    fn test_simple_update_container_storage_files() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+
+        // copy files over to mimic a container update
+        std::fs::copy("./tests/data/container_with_more_flags.package.map", &container.package_map)
+            .unwrap();
+        std::fs::copy("./tests/data/container_with_more_flags.flag.map", &container.flag_map)
+            .unwrap();
+        std::fs::copy("./tests/data/container_with_more_flags.flag.val", &container.flag_val)
+            .unwrap();
+        std::fs::copy("./tests/data/container_with_more_flags.flag.info", &container.flag_info)
+            .unwrap();
+
+        // update container
+        manager
+            .add_or_update_container_storage_files(
+                &container.name,
+                &container.package_map,
+                &container.flag_map,
+                &container.flag_val,
+                &container.flag_info,
+            )
+            .unwrap();
+
+        let storage_files = manager.get_storage_files(&container.name).unwrap();
+
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.package.map"),
+            &storage_files.storage_record.persist_package_map
+        ));
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.flag.map"),
+            &storage_files.storage_record.persist_flag_map
+        ));
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.flag.val"),
+            &storage_files.storage_record.persist_flag_val
+        ));
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.flag.info"),
+            &storage_files.storage_record.persist_flag_info
+        ));
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.flag.val"),
+            &storage_files.storage_record.boot_flag_val
+        ));
+        assert!(has_same_content(
+            &Path::new("./tests/data/container_with_more_flags.flag.info"),
+            &storage_files.storage_record.boot_flag_info
+        ));
+        assert!(storage_files.storage_record.local_overrides.exists());
+    }
+
+    fn add_example_overrides(manager: &mut StorageFilesManager) {
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "enabled_rw",
+                "false",
+                ProtoFlagOverrideType::SERVER_ON_REBOOT,
+            )
+            .unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "disabled_rw",
+                "false",
+                ProtoFlagOverrideType::SERVER_ON_REBOOT,
+            )
+            .unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "disabled_rw",
+                "true",
+                ProtoFlagOverrideType::LOCAL_ON_REBOOT,
+            )
+            .unwrap();
+    }
+
+    #[test]
+    fn test_overrides_after_update_container_storage_files() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+
+        // copy files over to mimic a container update
+        std::fs::copy("./tests/data/package.map", &container.package_map).unwrap();
+        std::fs::copy("./tests/data/flag.map", &container.flag_map).unwrap();
+        std::fs::copy("./tests/data/flag.val", &container.flag_val).unwrap();
+        std::fs::copy("./tests/data/flag.info", &container.flag_info).unwrap();
+
+        // update container
+        manager
+            .add_or_update_container_storage_files(
+                &container.name,
+                &container.package_map,
+                &container.flag_map,
+                &container.flag_val,
+                &container.flag_info,
+            )
+            .unwrap();
+
+        // verify that server override is persisted
+        let storage_files = manager.get_storage_files(&container.name).unwrap();
+        let server_overrides = storage_files.get_all_server_overrides().unwrap();
+        assert_eq!(server_overrides.len(), 2);
+        assert_eq!(
+            server_overrides[0],
+            FlagValueSummary {
+                package_name: "com.android.aconfig.storage.test_1".to_string(),
+                flag_name: "disabled_rw".to_string(),
+                flag_value: "false".to_string(),
+                value_type: StoredFlagType::ReadWriteBoolean,
+            }
+        );
+        assert_eq!(
+            server_overrides[1],
+            FlagValueSummary {
+                package_name: "com.android.aconfig.storage.test_1".to_string(),
+                flag_name: "enabled_rw".to_string(),
+                flag_value: "false".to_string(),
+                value_type: StoredFlagType::ReadWriteBoolean,
+            }
+        );
+
+        // verify that local override is persisted
+        let local_overrides = storage_files.get_all_local_overrides().unwrap();
+        assert_eq!(local_overrides.len(), 1);
+        let mut pb = ProtoFlagOverride::new();
+        pb.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        pb.set_flag_name("disabled_rw".to_string());
+        pb.set_flag_value("true".to_string());
+        assert_eq!(local_overrides[0], pb);
+    }
+
+    #[test]
+    fn test_apply_all_staged_overrides() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let mut flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "enabled_rw").unwrap();
+
+        let mut expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+
+        flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
+
+        expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_reset_all_storage() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        manager.reset_all_storage().unwrap();
+        let storage_files = manager.get_storage_files(&container.name).unwrap();
+        assert!(has_same_content(
+            &container.flag_val,
+            &storage_files.storage_record.persist_flag_val
+        ));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.persist_flag_info
+        ));
+        assert!(has_same_content(&container.flag_val, &storage_files.storage_record.boot_flag_val));
+        assert!(has_same_content(
+            &container.flag_info,
+            &storage_files.storage_record.boot_flag_info
+        ));
+    }
+
+    fn test_override_flag_server_on_reboot() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "enabled_rw",
+                "false",
+                ProtoFlagOverrideType::SERVER_ON_REBOOT,
+            )
+            .unwrap();
+
+        let flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "enabled_rw").unwrap();
+
+        let expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_override_flag_local_on_reboot() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "enabled_rw",
+                "false",
+                ProtoFlagOverrideType::LOCAL_ON_REBOOT,
+            )
+            .unwrap();
+
+        let flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "enabled_rw").unwrap();
+
+        let expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::new(),
+            local_value: String::from("false"),
+            boot_value: String::from("true"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: false,
+            has_local_override: true,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_override_flag_local_immediate() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "enabled_rw",
+                "false",
+                ProtoFlagOverrideType::LOCAL_IMMEDIATE,
+            )
+            .unwrap();
+
+        let flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "enabled_rw").unwrap();
+
+        let expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::new(),
+            local_value: String::from("false"),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: false,
+            has_local_override: true,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_get_ota_flags() {
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+
+        let mut ota_flags = ProtoOTAFlagStagingMessage::new();
+        ota_flags.set_build_id("xyz.123".to_string());
+        write_pb_to_file::<ProtoOTAFlagStagingMessage>(
+            &ota_flags,
+            &root_dir.flags_dir.join("ota.pb"),
+        )
+        .unwrap();
+        let staged_ota_flags = manager.get_ota_flags().unwrap();
+        assert!(staged_ota_flags.is_none());
+        assert!(root_dir.flags_dir.join("ota.pb").exists());
+
+        let device_build_id =
+            rustutils::system_properties::read("ro.build.fingerprint").unwrap().unwrap();
+        ota_flags.set_build_id(device_build_id);
+        let mut flag1 = ProtoFlagOverride::new();
+        flag1.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        flag1.set_flag_name("enabled_rw".to_string());
+        flag1.set_flag_value("false".to_string());
+        ota_flags.overrides.push(flag1.clone());
+        let mut flag2 = ProtoFlagOverride::new();
+        flag2.set_package_name("com.android.aconfig.storage.test_2".to_string());
+        flag2.set_flag_name("disabled_rw".to_string());
+        flag2.set_flag_value("true".to_string());
+        ota_flags.overrides.push(flag2.clone());
+        write_pb_to_file::<ProtoOTAFlagStagingMessage>(
+            &ota_flags,
+            &root_dir.flags_dir.join("ota.pb"),
+        )
+        .unwrap();
+        let staged_ota_flags = manager.get_ota_flags().unwrap().unwrap();
+        assert_eq!(staged_ota_flags.len(), 2);
+        assert_eq!(staged_ota_flags[0], flag1);
+        assert_eq!(staged_ota_flags[1], flag2);
+        assert!(!root_dir.flags_dir.join("ota.pb").exists());
+    }
+
+    #[test]
+    fn test_apply_staged_ota_flags() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+
+        let mut ota_flags = ProtoOTAFlagStagingMessage::new();
+        let device_build_id =
+            rustutils::system_properties::read("ro.build.fingerprint").unwrap().unwrap();
+        ota_flags.set_build_id(device_build_id);
+        let mut flag1 = ProtoFlagOverride::new();
+        flag1.set_package_name("com.android.aconfig.storage.test_1".to_string());
+        flag1.set_flag_name("enabled_rw".to_string());
+        flag1.set_flag_value("false".to_string());
+        ota_flags.overrides.push(flag1.clone());
+        let mut flag2 = ProtoFlagOverride::new();
+        flag2.set_package_name("com.android.aconfig.storage.test_2".to_string());
+        flag2.set_flag_name("disabled_rw".to_string());
+        flag2.set_flag_value("true".to_string());
+        ota_flags.overrides.push(flag2.clone());
+        let mut flag3 = ProtoFlagOverride::new();
+        flag3.set_package_name("not_exist".to_string());
+        flag3.set_flag_name("not_exist".to_string());
+        flag3.set_flag_value("true".to_string());
+        ota_flags.overrides.push(flag3.clone());
+        write_pb_to_file::<ProtoOTAFlagStagingMessage>(
+            &ota_flags,
+            &root_dir.flags_dir.join("ota.pb"),
+        )
+        .unwrap();
+
+        manager.apply_staged_ota_flags().unwrap();
+        let storage_files = manager.get_storage_files(&container.name).unwrap();
+        let server_overrides = storage_files.get_all_server_overrides().unwrap();
+        assert_eq!(server_overrides.len(), 2);
+        assert_eq!(
+            server_overrides[0].package_name,
+            "com.android.aconfig.storage.test_1".to_string()
+        );
+        assert_eq!(server_overrides[0].flag_name, "enabled_rw".to_string());
+        assert_eq!(server_overrides[0].flag_value, "false".to_string());
+        assert_eq!(
+            server_overrides[1].package_name,
+            "com.android.aconfig.storage.test_2".to_string()
+        );
+        assert_eq!(server_overrides[1].flag_name, "disabled_rw".to_string());
+        assert_eq!(server_overrides[1].flag_value, "true".to_string());
+    }
+
+    #[test]
+    fn test_write_persist_storage_records_to_file() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+
+        let pb_file = root_dir.tmp_dir.path().join("records.pb");
+        manager.write_persist_storage_records_to_file(&pb_file).unwrap();
+
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&pb_file).unwrap();
+        assert_eq!(pb.records.len(), 1);
+
+        let mut entry = ProtoPersistStorageRecord::new();
+        entry.set_version(1);
+        entry.set_container("mockup".to_string());
+        entry.set_package_map(container.package_map.display().to_string());
+        entry.set_flag_map(container.flag_map.display().to_string());
+        entry.set_flag_val(container.flag_val.display().to_string());
+        entry.set_flag_info(container.flag_info.display().to_string());
+        let digest = get_files_digest(
+            &[
+                container.package_map.as_path(),
+                container.flag_map.as_path(),
+                container.flag_val.as_path(),
+                container.flag_info.as_path(),
+            ][..],
+        )
+        .unwrap();
+        entry.set_digest(digest);
+        assert_eq!(pb.records[0], entry);
+    }
+
+    #[test]
+    fn test_remove_local_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        manager.remove_local_override("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
+
+        let flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
+
+        let expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_remove_all_local_override() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_1",
+                "disabled_rw",
+                "true",
+                ProtoFlagOverrideType::LOCAL_ON_REBOOT,
+            )
+            .unwrap();
+
+        manager
+            .override_flag_value(
+                "com.android.aconfig.storage.test_2",
+                "disabled_rw",
+                "true",
+                ProtoFlagOverrideType::LOCAL_ON_REBOOT,
+            )
+            .unwrap();
+        manager.apply_all_staged_overrides("mockup").unwrap();
+        manager.remove_all_local_overrides().unwrap();
+
+        let mut flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
+
+        let mut expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from(""),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: false,
+            has_local_override: false,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+
+        flag =
+            manager.get_flag_snapshot("com.android.aconfig.storage.test_2", "disabled_rw").unwrap();
+
+        expected_flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_2"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from(""),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: false,
+            has_local_override: false,
+        };
+
+        assert_eq!(flag, Some(expected_flag));
+    }
+
+    #[test]
+    fn test_list_flags_in_package() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let flags = manager.list_flags_in_package("com.android.aconfig.storage.test_1").unwrap();
+
+        let mut flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+        assert_eq!(flags[0], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_ro"),
+            server_value: String::new(),
+            local_value: String::new(),
+            boot_value: String::from("true"),
+            default_value: String::from("true"),
+            is_readwrite: false,
+            has_server_override: false,
+            has_local_override: false,
+        };
+        assert_eq!(flags[1], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+        assert_eq!(flags[2], flag);
+    }
+
+    #[test]
+    fn test_list_flags_in_container() {
+        let container = ContainerMock::new();
+        let root_dir = StorageRootDirMock::new();
+        let mut manager = StorageFilesManager::new(&root_dir.tmp_dir.path());
+        init_storage(&container, &mut manager);
+        add_example_overrides(&mut manager);
+        manager.apply_all_staged_overrides("mockup").unwrap();
+
+        let flags = manager.list_flags_in_container("mockup").unwrap();
+        assert_eq!(flags.len(), 8);
+
+        let mut flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("enabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::new(),
+            boot_value: String::from("false"),
+            default_value: String::from("true"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: false,
+        };
+        assert_eq!(flags[2], flag);
+
+        flag = FlagSnapshot {
+            container: String::from("mockup"),
+            package: String::from("com.android.aconfig.storage.test_1"),
+            flag: String::from("disabled_rw"),
+            server_value: String::from("false"),
+            local_value: String::from("true"),
+            boot_value: String::from("true"),
+            default_value: String::from("false"),
+            is_readwrite: true,
+            has_server_override: true,
+            has_local_override: true,
+        };
+        assert_eq!(flags[0], flag);
+    }
+}
diff --git a/aconfigd/src/test_utils.rs b/aconfigd/src/test_utils.rs
new file mode 100644
index 0000000..713723e
--- /dev/null
+++ b/aconfigd/src/test_utils.rs
@@ -0,0 +1,97 @@
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
+use std::io::Read;
+use std::path::{Path, PathBuf};
+use tempfile::{tempdir, TempDir};
+
+/// Container mockup
+pub(crate) struct ContainerMock {
+    pub tmp_dir: TempDir,
+    pub name: String,
+    pub package_map: PathBuf,
+    pub flag_map: PathBuf,
+    pub flag_val: PathBuf,
+    pub flag_info: PathBuf,
+}
+
+/// Implementation for container mockup
+impl ContainerMock {
+    pub(crate) fn new() -> Self {
+        let tmp_dir = tempdir().unwrap();
+        let package_map = tmp_dir.path().join("package.map");
+        let flag_map = tmp_dir.path().join("flag.map");
+        let flag_val = tmp_dir.path().join("flag.val");
+        let flag_info = tmp_dir.path().join("flag.info");
+        std::fs::copy("./tests/data/package.map", &package_map).unwrap();
+        std::fs::copy("./tests/data/flag.map", &flag_map).unwrap();
+        std::fs::copy("./tests/data/flag.val", &flag_val).unwrap();
+        std::fs::copy("./tests/data/flag.info", &flag_info).unwrap();
+        Self { tmp_dir, name: String::from("mockup"), package_map, flag_map, flag_val, flag_info }
+    }
+}
+
+/// Implement drop trait for ContainerMock
+impl Drop for ContainerMock {
+    fn drop(&mut self) {
+        std::fs::remove_dir_all(&self.tmp_dir).unwrap();
+    }
+}
+
+/// Storage root dir mockup
+pub(crate) struct StorageRootDirMock {
+    pub tmp_dir: TempDir,
+    pub flags_dir: PathBuf,
+    pub maps_dir: PathBuf,
+    pub boot_dir: PathBuf,
+}
+
+/// Implementation for storage root dir mockup
+impl StorageRootDirMock {
+    pub(crate) fn new() -> Self {
+        let tmp_dir = tempdir().unwrap();
+        let flags_dir = tmp_dir.path().join("flags");
+        let maps_dir = tmp_dir.path().join("maps");
+        let boot_dir = tmp_dir.path().join("boot");
+        std::fs::create_dir(&flags_dir).unwrap();
+        std::fs::create_dir(&maps_dir).unwrap();
+        std::fs::create_dir(&boot_dir).unwrap();
+        Self { tmp_dir, flags_dir, maps_dir, boot_dir }
+    }
+}
+
+/// Implement drop trait for StorageRootDirMock
+impl Drop for StorageRootDirMock {
+    fn drop(&mut self) {
+        std::fs::remove_dir_all(&self.tmp_dir).unwrap();
+    }
+}
+
+/// Check if has the same content
+pub(crate) fn has_same_content(file_one: &Path, file_two: &Path) -> bool {
+    assert!(file_one.exists());
+    assert!(file_two.exists());
+
+    let mut f1 = std::fs::File::open(file_one).unwrap();
+    let mut b1 = Vec::new();
+    f1.read_to_end(&mut b1).unwrap();
+
+    let mut f2 = std::fs::File::open(file_two).unwrap();
+    let mut b2 = Vec::new();
+    f2.read_to_end(&mut b2).unwrap();
+
+    b1 == b2
+}
diff --git a/aconfigd/src/utils.rs b/aconfigd/src/utils.rs
new file mode 100644
index 0000000..91d06f6
--- /dev/null
+++ b/aconfigd/src/utils.rs
@@ -0,0 +1,191 @@
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
+use crate::AconfigdError;
+use openssl::hash::{Hasher, MessageDigest};
+use std::fs::File;
+use std::io::Read;
+use std::os::unix::fs::PermissionsExt;
+use std::path::Path;
+
+/// Set file permission
+pub(crate) fn set_file_permission(file: &Path, mode: u32) -> Result<(), AconfigdError> {
+    let perms = std::fs::Permissions::from_mode(mode);
+    std::fs::set_permissions(file, perms).map_err(|errmsg| {
+        AconfigdError::FailToUpdateFilePerm { file: file.display().to_string(), mode, errmsg }
+    })?;
+    Ok(())
+}
+
+/// Copy file
+pub(crate) fn copy_file(src: &Path, dst: &Path, mode: u32) -> Result<(), AconfigdError> {
+    std::fs::copy(src, dst).map_err(|errmsg| AconfigdError::FailToCopyFile {
+        src: src.display().to_string(),
+        dst: dst.display().to_string(),
+        errmsg,
+    })?;
+    set_file_permission(dst, mode)
+}
+
+/// Remove file
+pub(crate) fn remove_file(src: &Path) -> Result<(), AconfigdError> {
+    std::fs::remove_file(src).map_err(|errmsg| AconfigdError::FailToRemoveFile {
+        file: src.display().to_string(),
+        errmsg,
+    })
+}
+
+/// Read pb from file
+pub(crate) fn read_pb_from_file<T: protobuf::Message>(file: &Path) -> Result<T, AconfigdError> {
+    if !Path::new(file).exists() {
+        return Ok(T::new());
+    }
+
+    let data = std::fs::read(file).map_err(|errmsg| AconfigdError::FailToReadFile {
+        file: file.display().to_string(),
+        errmsg,
+    })?;
+    protobuf::Message::parse_from_bytes(data.as_ref()).map_err(|errmsg| {
+        AconfigdError::FailToParsePbFromBytes { file: file.display().to_string(), errmsg }
+    })
+}
+
+/// Write pb to file
+pub(crate) fn write_pb_to_file<T: protobuf::Message>(
+    pb: &T,
+    file: &Path,
+) -> Result<(), AconfigdError> {
+    let bytes = protobuf::Message::write_to_bytes(pb).map_err(|errmsg| {
+        AconfigdError::FailToSerializePb { file: file.display().to_string(), errmsg }
+    })?;
+    std::fs::write(file, bytes).map_err(|errmsg| AconfigdError::FailToWriteFile {
+        file: file.display().to_string(),
+        errmsg,
+    })?;
+    Ok(())
+}
+
+/// The digest is returned as a hexadecimal string.
+pub(crate) fn get_files_digest(paths: &[&Path]) -> Result<String, AconfigdError> {
+    let mut hasher = Hasher::new(MessageDigest::sha256())
+        .map_err(|errmsg| AconfigdError::FailToGetHasherForDigest { errmsg })?;
+    let mut buffer = [0; 1024];
+    for path in paths {
+        let mut f = File::open(path).map_err(|errmsg| AconfigdError::FailToOpenFile {
+            file: path.display().to_string(),
+            errmsg,
+        })?;
+        loop {
+            let n = f.read(&mut buffer[..]).map_err(|errmsg| AconfigdError::FailToReadFile {
+                file: path.display().to_string(),
+                errmsg,
+            })?;
+            if n == 0 {
+                break;
+            }
+            hasher.update(&buffer).map_err(|errmsg| AconfigdError::FailToHashFile {
+                file: path.display().to_string(),
+                errmsg,
+            })?;
+        }
+    }
+    let digest: &[u8] =
+        &hasher.finish().map_err(|errmsg| AconfigdError::FailToGetDigest { errmsg })?;
+    let mut xdigest = String::new();
+    for x in digest {
+        xdigest.push_str(format!("{:02x}", x).as_str());
+    }
+    Ok(xdigest)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use aconfigd_protos::ProtoLocalFlagOverrides;
+    use std::io::Write;
+    use tempfile::tempdir;
+
+    fn get_file_perm_mode(file: &Path) -> u32 {
+        let f = std::fs::File::open(&file).unwrap();
+        let metadata = f.metadata().unwrap();
+        metadata.permissions().mode() & 0o777
+    }
+
+    #[test]
+    fn test_copy_file() {
+        let tmp_dir = tempdir().unwrap();
+
+        let package_map = tmp_dir.path().join("package.map");
+        copy_file(&Path::new("./tests/data/package.map"), &package_map, 0o444).unwrap();
+        assert_eq!(get_file_perm_mode(&package_map), 0o444);
+
+        let flag_map = tmp_dir.path().join("flag.map");
+        copy_file(&Path::new("./tests/data/flag.map"), &flag_map, 0o644).unwrap();
+        assert_eq!(get_file_perm_mode(&flag_map), 0o644);
+    }
+
+    #[test]
+    fn test_remove_file() {
+        let tmp_dir = tempdir().unwrap();
+        let package_map = tmp_dir.path().join("package.map");
+        copy_file(&Path::new("./tests/data/package.map"), &package_map, 0o444).unwrap();
+        assert!(remove_file(&package_map).is_ok());
+        assert!(!package_map.exists());
+    }
+
+    #[test]
+    fn test_set_file_permission() {
+        let tmp_dir = tempdir().unwrap();
+        let package_map = tmp_dir.path().join("package.map");
+        copy_file(&Path::new("./tests/data/package.map"), &package_map, 0o644).unwrap();
+        set_file_permission(&package_map, 0o444).unwrap();
+        assert_eq!(get_file_perm_mode(&package_map), 0o444);
+    }
+
+    #[test]
+    fn test_write_pb_to_file() {
+        let tmp_dir = tempdir().unwrap();
+        let test_pb = tmp_dir.path().join("test.pb");
+        let pb = ProtoLocalFlagOverrides::new();
+        write_pb_to_file(&pb, &test_pb).unwrap();
+        assert!(test_pb.exists());
+    }
+
+    #[test]
+    fn test_read_pb_from_file() {
+        let tmp_dir = tempdir().unwrap();
+        let test_pb = tmp_dir.path().join("test.pb");
+        let pb = ProtoLocalFlagOverrides::new();
+        write_pb_to_file(&pb, &test_pb).unwrap();
+        let new_pb: ProtoLocalFlagOverrides = read_pb_from_file(&test_pb).unwrap();
+        assert_eq!(new_pb.overrides.len(), 0);
+    }
+
+    #[test]
+    fn test_get_files_digest() {
+        let path1 = Path::new("/tmp/hi.txt");
+        let path2 = Path::new("/tmp/bye.txt");
+        let mut file1 = File::create(path1).unwrap();
+        let mut file2 = File::create(path2).unwrap();
+        file1.write_all(b"Hello, world!").expect("Writing to file");
+        file2.write_all(b"Goodbye, world!").expect("Writing to file");
+        let digest = get_files_digest(&[path1, path2]);
+        assert_eq!(
+            digest.expect("Calculating digest"),
+            "8352c31d9ff5f446b838139b7f4eb5fed821a1f80d6648ffa6ed7391ecf431f4"
+        );
+    }
+}
diff --git a/aconfigd/tests/data/container_with_more_flags.flag.info b/aconfigd/tests/data/container_with_more_flags.flag.info
new file mode 100644
index 0000000..06e464f
Binary files /dev/null and b/aconfigd/tests/data/container_with_more_flags.flag.info differ
diff --git a/aconfigd/tests/data/container_with_more_flags.flag.map b/aconfigd/tests/data/container_with_more_flags.flag.map
new file mode 100644
index 0000000..38aebde
Binary files /dev/null and b/aconfigd/tests/data/container_with_more_flags.flag.map differ
diff --git a/aconfigd/tests/data/container_with_more_flags.flag.val b/aconfigd/tests/data/container_with_more_flags.flag.val
new file mode 100644
index 0000000..6e9f652
Binary files /dev/null and b/aconfigd/tests/data/container_with_more_flags.flag.val differ
diff --git a/aconfigd/tests/data/container_with_more_flags.package.map b/aconfigd/tests/data/container_with_more_flags.package.map
new file mode 100644
index 0000000..dc0be2b
Binary files /dev/null and b/aconfigd/tests/data/container_with_more_flags.package.map differ
diff --git a/aconfigd/tests/data/flag.info b/aconfigd/tests/data/flag.info
new file mode 100644
index 0000000..6223edf
Binary files /dev/null and b/aconfigd/tests/data/flag.info differ
diff --git a/aconfigd/tests/data/flag.map b/aconfigd/tests/data/flag.map
new file mode 100644
index 0000000..e868f53
Binary files /dev/null and b/aconfigd/tests/data/flag.map differ
diff --git a/aconfigd/tests/data/flag.val b/aconfigd/tests/data/flag.val
new file mode 100644
index 0000000..ed203d4
Binary files /dev/null and b/aconfigd/tests/data/flag.val differ
diff --git a/aconfigd/tests/data/package.map b/aconfigd/tests/data/package.map
new file mode 100644
index 0000000..6c46a03
Binary files /dev/null and b/aconfigd/tests/data/package.map differ
diff --git a/apex/Android.bp b/apex/Android.bp
index c2277a5..edaf6dd 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -40,9 +40,15 @@ bootclasspath_fragment {
         // classes into an API surface, e.g. public, system, etc.. Doing so will
         // result in a build failure due to inconsistent flags.
         package_prefixes: [
+            "android.internal.configinfra",
+            "android.provider.configinfra.internal.protobuf",
             "android.provider.aidl",
             "android.provider.flags",
+            "android.provider.internal.aconfig.storage",
             "android.provider.internal.modules.utils.build",
+
+            "android.os.flagging",
+            "android.provider.x.android.provider.flags",
         ],
     },
     // The bootclasspath_fragments that provide APIs on which this depends.
@@ -80,6 +86,12 @@ android_app_certificate {
     certificate: "com.android.configinfrastructure",
 }
 
+prebuilt_etc {
+    name: "com.android.configinfrastrcture.init.rc",
+    src: "configinfrastructure.rc",
+    installable: false,
+}
+
 apex {
     name: "com.android.configinfrastructure",
     bootclasspath_fragments: ["com.android.configinfrastructure-bootclasspath-fragment"],
@@ -89,7 +101,11 @@ apex {
     ],
     manifest: "manifest.json",
     file_contexts: ":com.android.configinfrastructure-file_contexts",
+    binaries: [
+        "aconfigd-mainline",
+    ],
     prebuilts: [
+        "com.android.configinfrastrcture.init.rc",
         "current_sdkinfo",
     ],
     min_sdk_version: "34",
diff --git a/apex/configinfrastructure.rc b/apex/configinfrastructure.rc
new file mode 100644
index 0000000..e4e4bb7
--- /dev/null
+++ b/apex/configinfrastructure.rc
@@ -0,0 +1,42 @@
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
+
+service mainline_aconfigd_bootstrap_init /apex/com.android.configinfrastructure/bin/aconfigd-mainline bootstrap-init
+    class core
+    user system
+    group system
+    oneshot
+    disabled # does not start with the core class
+    file /dev/kmsg w
+    #turn it on when b/312444587 completes
+    #reboot_on_failure reboot
+
+service mainline_aconfigd_init /apex/com.android.configinfrastructure/bin/aconfigd-mainline init
+    class core
+    user system
+    group system
+    oneshot
+    disabled # does not start with the core class
+    file /dev/kmsg w
+    #turn it on when b/312444587 completes
+    #reboot_on_failure reboot
+
+service mainline_aconfigd_socket_service /apex/com.android.configinfrastructure/bin/aconfigd-mainline start-socket
+    class core
+    user system
+    group system
+    oneshot
+    disabled # does not start with the core class
+    file /dev/kmsg w
+    socket aconfigd_mainline stream 666 system system
diff --git a/framework/Android.bp b/framework/Android.bp
index 4b52710..18e10bd 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -24,9 +24,12 @@ java_sdk_library {
     ],
     defaults: ["framework-module-defaults"],
     permitted_packages: [
+        "android.internal.configinfra",
         "android.provider",
         "android.provider.flags",
+        "android.provider.x",
         "android.provider.aidl",
+        "android.os.flagging",
     ],
     apex_available: [
         "com.android.configinfrastructure",
@@ -35,12 +38,17 @@ java_sdk_library {
     sdk_version: "module_current",
     impl_library_visibility: [
         "//packages/modules/ConfigInfrastructure:__subpackages__",
+        "//frameworks/base/ravenwood",
     ],
     libs: [
-        "configinfra_framework_flags_java_lib",
+        "unsupportedappusage",
+        "aconfig_storage_stub",
     ],
     static_libs: [
+        "aconfigd_java_proto_lite_lib",
+        "configinfra_framework_flags_java_lib",
         "modules-utils-build",
+        "aconfig_storage_file_java",
     ],
     aconfig_declarations: [
         "configinfra_framework_flags",
@@ -51,6 +59,14 @@ java_sdk_library {
     },
 }
 
+filegroup {
+    name: "framework-configinfrastructure-ravenwood-policies",
+    srcs: [
+        "framework-configinfrastructure-ravenwood-policies.txt",
+    ],
+    visibility: ["//frameworks/base/ravenwood"],
+}
+
 aconfig_declarations {
     name: "configinfra_framework_flags",
     package: "android.provider.flags",
diff --git a/framework/api/current.txt b/framework/api/current.txt
index d802177..80ab746 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -1 +1,22 @@
 // Signature format: 2.0
+package android.os.flagging {
+
+  @FlaggedApi("android.provider.flags.new_storage_public_api") public class AconfigPackage {
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public boolean getBooleanFlagValue(@NonNull String, boolean);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") @NonNull public static android.os.flagging.AconfigPackage load(@NonNull String);
+  }
+
+  @FlaggedApi("android.provider.flags.new_storage_public_api") public class AconfigStorageReadException extends java.lang.RuntimeException {
+    ctor @FlaggedApi("android.provider.flags.new_storage_public_api") public AconfigStorageReadException(int, @NonNull String);
+    ctor @FlaggedApi("android.provider.flags.new_storage_public_api") public AconfigStorageReadException(int, @NonNull String, @NonNull Throwable);
+    ctor @FlaggedApi("android.provider.flags.new_storage_public_api") public AconfigStorageReadException(int, @NonNull Throwable);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public int getErrorCode();
+    field @FlaggedApi("android.provider.flags.new_storage_public_api") public static final int ERROR_CANNOT_READ_STORAGE_FILE = 4; // 0x4
+    field @FlaggedApi("android.provider.flags.new_storage_public_api") public static final int ERROR_CONTAINER_NOT_FOUND = 3; // 0x3
+    field @FlaggedApi("android.provider.flags.new_storage_public_api") public static final int ERROR_GENERIC = 0; // 0x0
+    field @FlaggedApi("android.provider.flags.new_storage_public_api") public static final int ERROR_PACKAGE_NOT_FOUND = 2; // 0x2
+    field @FlaggedApi("android.provider.flags.new_storage_public_api") public static final int ERROR_STORAGE_SYSTEM_NOT_FOUND = 1; // 0x1
+  }
+
+}
+
diff --git a/framework/api/module-lib-current.txt b/framework/api/module-lib-current.txt
index ad11041..f62dcc7 100644
--- a/framework/api/module-lib-current.txt
+++ b/framework/api/module-lib-current.txt
@@ -1,4 +1,12 @@
 // Signature format: 2.0
+package android.os.flagging {
+
+  @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class ConfigInfrastructureFrameworkInitializer {
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public static void registerServiceWrappers();
+  }
+
+}
+
 package android.provider {
 
   public final class DeviceConfig {
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index cbe9399..1d775ef 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -1,4 +1,22 @@
 // Signature format: 2.0
+package android.os.flagging {
+
+  @FlaggedApi("android.provider.flags.stage_flags_for_build") public class AconfigWriteException extends android.util.AndroidRuntimeException {
+    ctor @FlaggedApi("android.provider.flags.stage_flags_for_build") public AconfigWriteException(@NonNull String);
+    ctor @FlaggedApi("android.provider.flags.stage_flags_for_build") public AconfigWriteException(@NonNull String, @NonNull Throwable);
+  }
+
+  @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class FlagManager {
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void clearBooleanLocalOverridesImmediately(@Nullable java.util.Set<java.lang.String>);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void clearBooleanLocalOverridesOnReboot(@Nullable java.util.Set<java.lang.String>);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanLocalOverridesImmediately(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanLocalOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanOverridesOnSystemBuildFingerprint(@NonNull String, @NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+  }
+
+}
+
 package android.provider {
 
   public final class DeviceConfig {
@@ -7,8 +25,9 @@ package android.provider {
     method @RequiresPermission(android.Manifest.permission.WRITE_DEVICE_CONFIG) public static void clearLocalOverride(@NonNull String, @NonNull String);
     method @RequiresPermission(android.Manifest.permission.MONITOR_DEVICE_CONFIG_ACCESS) public static void clearMonitorCallback(@NonNull android.content.ContentResolver);
     method @RequiresPermission(anyOf={android.Manifest.permission.WRITE_DEVICE_CONFIG, android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG}) public static boolean deleteProperty(@NonNull String, @NonNull String);
-    method @FlaggedApi("android.provider.flags.dump_improvements") @RequiresPermission(android.Manifest.permission.DUMP) public static void dump(@NonNull android.os.ParcelFileDescriptor, @NonNull java.io.PrintWriter, @NonNull String, @Nullable String[]);
+    method @FlaggedApi("android.provider.flags.dump_improvements") public static void dump(@NonNull java.io.PrintWriter, @NonNull String, @Nullable String[]);
     method @NonNull public static java.util.Set<java.lang.String> getAdbWritableFlags();
+    method @FlaggedApi("android.provider.flags.device_config_writable_namespaces_api") @NonNull public static java.util.Set<java.lang.String> getAdbWritableNamespaces();
     method @NonNull public static java.util.Set<android.provider.DeviceConfig.Properties> getAllProperties();
     method public static boolean getBoolean(@NonNull String, @NonNull String, boolean);
     method @RequiresPermission(android.Manifest.permission.READ_DEVICE_CONFIG) public static float getFloat(@NonNull String, @NonNull String, float);
@@ -27,6 +46,7 @@ package android.provider {
     method @RequiresPermission(anyOf={android.Manifest.permission.WRITE_DEVICE_CONFIG, android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG}) public static boolean setProperties(@NonNull android.provider.DeviceConfig.Properties) throws android.provider.DeviceConfig.BadConfigException;
     method @RequiresPermission(anyOf={android.Manifest.permission.WRITE_DEVICE_CONFIG, android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG}) public static boolean setProperty(@NonNull String, @NonNull String, @Nullable String, boolean);
     method @RequiresPermission(anyOf={android.Manifest.permission.WRITE_DEVICE_CONFIG, android.Manifest.permission.READ_WRITE_SYNC_DISABLED_MODE_CONFIG}) public static void setSyncDisabledMode(int);
+    field @FlaggedApi("android.provider.flags.dump_improvements") public static final String DUMP_ARG_NAMESPACE = "--namespace";
     field public static final String NAMESPACE_ACCESSIBILITY = "accessibility";
     field public static final String NAMESPACE_ACTIVITY_MANAGER = "activity_manager";
     field public static final String NAMESPACE_ACTIVITY_MANAGER_NATIVE_BOOT = "activity_manager_native_boot";
@@ -143,7 +163,9 @@ package android.provider {
   }
 
   @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class StageOtaFlags {
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public static void stageBooleanAconfigFlagsForBuild(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>, @NonNull String);
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public static int stageBooleanAconfigFlagsForBuild(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>, @NonNull String);
+    field public static final int STATUS_STAGE_SUCCESS = 0; // 0x0
+    field public static final int STATUS_STORAGE_NOT_ENABLED = -1; // 0xffffffff
   }
 
   public final class UpdatableDeviceConfigServiceReadiness {
diff --git a/framework/flags.aconfig b/framework/flags.aconfig
index 0d5346f..9f314a8 100644
--- a/framework/flags.aconfig
+++ b/framework/flags.aconfig
@@ -17,3 +17,20 @@ flag {
     bug: "364399200"
   is_exported: true
 }
+
+flag {
+  name: "new_storage_public_api"
+  namespace: "core_experiments_team_internal"
+  description: "API flag for accessing new storage"
+  bug: "367765164"
+  is_fixed_read_only: true
+  is_exported: true
+}
+
+flag {
+  name: "device_config_writable_namespaces_api"
+  namespace: "psap_ai"
+  description: "API flag for accessing DeviceConfig writable namespaces"
+  bug: "364083026"
+  is_exported: true
+}
diff --git a/framework/framework-configinfrastructure-ravenwood-policies.txt b/framework/framework-configinfrastructure-ravenwood-policies.txt
new file mode 100644
index 0000000..3dfb73f
--- /dev/null
+++ b/framework/framework-configinfrastructure-ravenwood-policies.txt
@@ -0,0 +1,4 @@
+# Policy file for ravenwood
+
+# These classes are included from external libraries statically
+class android.provider.internal.modules.utils.build.SdkLevel keepclass
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
index c0fbba5..2108e8f 100644
--- a/framework/jarjar-rules.txt
+++ b/framework/jarjar-rules.txt
@@ -1 +1,8 @@
 rule com.android.modules.utils.** android.provider.internal.modules.utils.@1
+rule android.aconfig.storage.** android.provider.internal.aconfig.storage.@1
+rule com.google.protobuf.** android.provider.configinfra.internal.protobuf.@1
+rule android.aconfigd.** android.internal.configinfra.aconfigd.@1
+
+rule android.provider.flags.*FeatureFlags* android.provider.x.@0
+rule android.provider.flags.FeatureFlags* android.provider.x.@0
+rule android.provider.flags.Flags android.provider.x.@0
diff --git a/framework/java/android/os/flagging/AconfigPackage.java b/framework/java/android/os/flagging/AconfigPackage.java
new file mode 100644
index 0000000..acb6d9b
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigPackage.java
@@ -0,0 +1,179 @@
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
+package android.os.flagging;
+
+import static android.provider.flags.Flags.FLAG_NEW_STORAGE_PUBLIC_API;
+
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.os.StrictMode;
+
+import java.io.Closeable;
+import java.io.File;
+import java.nio.MappedByteBuffer;
+import java.nio.channels.FileChannel;
+import java.nio.file.Paths;
+import java.nio.file.StandardOpenOption;
+
+/**
+ * An {@code aconfig} package containing the enabled state of its flags.
+ *
+ * <p><strong>Note: this is intended only to be used by generated code. To determine if a given flag
+ * is enabled in app code, the generated android flags should be used.</strong>
+ *
+ * <p>This class is used to read the flag from Aconfig Package.Each instance of this class will
+ * cache information related to one package. To read flags from a different package, a new instance
+ * of this class should be {@link #load loaded}.
+ */
+@FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+public class AconfigPackage {
+
+    private static final String MAP_PATH = "/metadata/aconfig/maps/";
+    private static final String BOOT_PATH = "/metadata/aconfig/boot/";
+    private static final String SYSTEM_MAP = "/metadata/aconfig/maps/system.package.map";
+    private static final String PMAP_FILE_EXT = ".package.map";
+
+    private FlagTable mFlagTable;
+    private FlagValueList mFlagValueList;
+
+    private int mPackageBooleanStartOffset = -1;
+    private int mPackageId = -1;
+
+    private AconfigPackage() {}
+
+    /**
+     * Loads an Aconfig Package from Aconfig Storage.
+     *
+     * <p>This method attempts to load the specified Aconfig package.
+     *
+     * @param packageName The name of the Aconfig package to load.
+     * @return An instance of {@link AconfigPackage}, which may be empty if the package is not found
+     *     in the container.
+     * @throws AconfigStorageReadException if there is an error reading from Aconfig Storage, such
+     *     as if the storage system is not found, the package is not found, or there is an error
+     *     reading the storage file. The specific error code can be obtained using {@link
+     *     AconfigStorageReadException#getErrorCode()}.
+     */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static @NonNull AconfigPackage load(@NonNull String packageName) {
+        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
+        try {
+            AconfigPackage aconfigPackage = new AconfigPackage();
+            PackageTable pTable = null;
+            PackageTable.Node pNode = null;
+
+            try {
+                pTable = PackageTable.fromBytes(mapStorageFile(SYSTEM_MAP));
+                pNode = pTable.get(packageName);
+            } catch (Exception e) {
+                // Ignore exceptions when loading the system map file.
+            }
+
+            if (pNode == null) {
+                File mapDir = new File(MAP_PATH);
+                String[] mapFiles = mapDir.list();
+                if (mapFiles == null) {
+                    throw new AconfigStorageReadException(
+                            AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
+                            "package " + packageName + " cannot be found on the device");
+                }
+
+                for (String file : mapFiles) {
+                    if (!file.endsWith(PMAP_FILE_EXT)) {
+                        continue;
+                    }
+                    pTable = PackageTable.fromBytes(mapStorageFile(MAP_PATH + file));
+                    pNode = pTable.get(packageName);
+                    if (pNode != null) {
+                        break;
+                    }
+                }
+            }
+
+            if (pNode == null) {
+                throw new AconfigStorageReadException(
+                        AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
+                        "package " + packageName + " cannot be found on the device");
+            }
+
+            String container = pTable.getHeader().getContainer();
+            aconfigPackage.mFlagTable =
+                    FlagTable.fromBytes(mapStorageFile(MAP_PATH + container + ".flag.map"));
+            aconfigPackage.mFlagValueList =
+                    FlagValueList.fromBytes(mapStorageFile(BOOT_PATH + container + ".val"));
+            aconfigPackage.mPackageBooleanStartOffset = pNode.getBooleanStartIndex();
+            aconfigPackage.mPackageId = pNode.getPackageId();
+            return aconfigPackage;
+        } catch (AconfigStorageReadException e) {
+            throw e;
+        } catch (Exception e) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_GENERIC, "Fail to create AconfigPackage", e);
+        } finally {
+            StrictMode.setThreadPolicy(oldPolicy);
+        }
+    }
+
+    /**
+     * Retrieves the value of a boolean flag.
+     *
+     * <p>This method retrieves the value of the specified flag. If the flag exists within the
+     * loaded Aconfig Package, its value is returned. Otherwise, the provided `defaultValue` is
+     * returned.
+     *
+     * @param flagName The name of the flag (excluding any package name prefix).
+     * @param defaultValue The value to return if the flag is not found.
+     * @return The boolean value of the flag, or `defaultValue` if the flag is not found.
+     */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public boolean getBooleanFlagValue(@NonNull String flagName, boolean defaultValue) {
+        FlagTable.Node fNode = mFlagTable.get(mPackageId, flagName);
+        if (fNode == null) {
+            return defaultValue;
+        }
+        return mFlagValueList.getBoolean(fNode.getFlagIndex() + mPackageBooleanStartOffset);
+    }
+
+    // Map a storage file given file path
+    private static MappedByteBuffer mapStorageFile(String file) {
+        FileChannel channel = null;
+        try {
+            channel = FileChannel.open(Paths.get(file), StandardOpenOption.READ);
+            return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
+        } catch (Exception e) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE,
+                    "Fail to mmap storage",
+                    e);
+        } finally {
+            quietlyDispose(channel);
+        }
+    }
+
+    private static void quietlyDispose(Closeable closable) {
+        try {
+            if (closable != null) {
+                closable.close();
+            }
+        } catch (Exception e) {
+            // no need to care, at least as of now
+        }
+    }
+}
diff --git a/framework/java/android/os/flagging/AconfigPackageInternal.java b/framework/java/android/os/flagging/AconfigPackageInternal.java
new file mode 100644
index 0000000..5d16ccc
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigPackageInternal.java
@@ -0,0 +1,135 @@
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
+package android.os.flagging;
+
+import android.aconfig.storage.AconfigStorageException;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.annotation.NonNull;
+import android.compat.annotation.UnsupportedAppUsage;
+import android.os.StrictMode;
+
+/**
+ * An {@code aconfig} package containing the enabled state of its flags.
+ *
+ * <p><strong>Note: this is intended only to be used by generated code. To determine if a given flag
+ * is enabled in app code, the generated android flags should be used.</strong>
+ *
+ * <p>This class is not part of the public API and should be used by Acnofig Flag internally </b> It
+ * is intended for internal use only and will be changed or removed without notice.
+ *
+ * <p>This class is used to read the flag from Aconfig Package.Each instance of this class will
+ * cache information related to one package. To read flags from a different package, a new instance
+ * of this class should be {@link #load loaded}.
+ *
+ * @hide
+ */
+public class AconfigPackageInternal {
+
+    private final FlagValueList mFlagValueList;
+    private final int mPackageBooleanStartOffset;
+
+    private AconfigPackageInternal(
+            @NonNull FlagValueList flagValueList, int packageBooleanStartOffset) {
+        this.mFlagValueList = flagValueList;
+        this.mPackageBooleanStartOffset = packageBooleanStartOffset;
+    }
+
+    /**
+     * Loads an Aconfig package from the specified container and verifies its fingerprint.
+     *
+     * <p>This method is intended for internal use only and may be changed or removed without
+     * notice.
+     *
+     * @param container The name of the container.
+     * @param packageName The name of the Aconfig package.
+     * @param packageFingerprint The expected fingerprint of the package.
+     * @return An instance of {@link AconfigPackageInternal} representing the loaded package.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public static @NonNull AconfigPackageInternal load(
+            @NonNull String container, @NonNull String packageName, long packageFingerprint) {
+        return load(
+                container,
+                packageName,
+                packageFingerprint,
+                StorageFileProvider.getDefaultProvider());
+    }
+
+    /** @hide */
+    public static @NonNull AconfigPackageInternal load(
+            @NonNull String container,
+            @NonNull String packageName,
+            long packageFingerprint,
+            @NonNull StorageFileProvider fileProvider) {
+        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
+        PackageTable.Node pNode = null;
+        FlagValueList vList = null;
+        try {
+            pNode = fileProvider.getPackageTable(container).get(packageName);
+            vList = fileProvider.getFlagValueList(container);
+        } catch (AconfigStorageException e) {
+            throw new AconfigStorageReadException(e.getErrorCode(), e.toString());
+        } finally {
+            StrictMode.setThreadPolicy(oldPolicy);
+        }
+
+        if (pNode == null || vList == null) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
+                    String.format(
+                            "package "
+                                    + packageName
+                                    + " in container "
+                                    + container
+                                    + " cannot be found on the device"));
+        }
+
+        if (pNode.hasPackageFingerprint() && packageFingerprint != pNode.getPackageFingerprint()) {
+            throw new AconfigStorageReadException(
+                    5, // AconfigStorageReadException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    String.format(
+                            "package "
+                                    + packageName
+                                    + " in container "
+                                    + container
+                                    + " cannot be found on the device"));
+        }
+
+        return new AconfigPackageInternal(vList, pNode.getBooleanStartIndex());
+    }
+
+    /**
+     * Retrieves the value of a boolean flag using its index.
+     *
+     * <p>This method is intended for internal use only and may be changed or removed without
+     * notice.
+     *
+     * <p>This method retrieves the value of a flag within the loaded Aconfig package using its
+     * index. The index is generated at build time and may vary between builds.
+     *
+     * @param index The index of the flag within the package.
+     * @return The boolean value of the flag.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public boolean getBooleanFlagValue(int index) {
+        return mFlagValueList.getBoolean(index + mPackageBooleanStartOffset);
+    }
+}
diff --git a/framework/java/android/os/flagging/AconfigStorageReadException.java b/framework/java/android/os/flagging/AconfigStorageReadException.java
new file mode 100644
index 0000000..999a6f9
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigStorageReadException.java
@@ -0,0 +1,183 @@
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
+package android.os.flagging;
+
+import static android.provider.flags.Flags.FLAG_NEW_STORAGE_PUBLIC_API;
+
+import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.compat.annotation.UnsupportedAppUsage;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+/**
+ * Exception thrown when an error occurs while reading from Aconfig Storage.
+ *
+ * <p>This exception indicates a problem accessing or retrieving configuration data from Aconfig
+ * Storage. This could be due to various reasons, such as:
+ *
+ * <ul>
+ *   <li>The Aconfig Storage system is not found on the device.
+ *   <li>The requested configuration package is not found.
+ *   <li>The specified container is not found.
+ *   <li>There was an error reading the Aconfig Storage file.
+ *   <li>The fingerprint of the Aconfig Storage file does not match the expected fingerprint.
+ * </ul>
+ */
+@FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+public class AconfigStorageReadException extends RuntimeException {
+
+    /** Generic error code indicating an unspecified Aconfig Storage error. */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static final int ERROR_GENERIC = 0;
+
+    /** Error code indicating that the Aconfig Storage system is not found on the device. */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static final int ERROR_STORAGE_SYSTEM_NOT_FOUND = 1;
+
+    /** Error code indicating that the requested configuration package is not found. */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static final int ERROR_PACKAGE_NOT_FOUND = 2;
+
+    /** Error code indicating that the specified container is not found. */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static final int ERROR_CONTAINER_NOT_FOUND = 3;
+
+    /** Error code indicating that there was an error reading the Aconfig Storage file. */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public static final int ERROR_CANNOT_READ_STORAGE_FILE = 4;
+
+    /**
+     * Error code indicating that the fingerprint of the Aconfig Storage file does not match the
+     * expected fingerprint.
+     *
+     * <p><b>This constant is not part of the public API and should be used by Acnofig Flag
+     * internally </b> It is intended for internal use only and may be changed or removed without
+     * notice.
+     *
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public static final int ERROR_FILE_FINGERPRINT_MISMATCH = 5;
+
+    /** @hide */
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef(
+            prefix = {"ERROR_"},
+            value = {
+                ERROR_GENERIC,
+                ERROR_STORAGE_SYSTEM_NOT_FOUND,
+                ERROR_PACKAGE_NOT_FOUND,
+                ERROR_CONTAINER_NOT_FOUND,
+                ERROR_CANNOT_READ_STORAGE_FILE,
+                ERROR_FILE_FINGERPRINT_MISMATCH
+            })
+    public @interface ErrorCode {}
+
+    @ErrorCode private final int mErrorCode;
+
+    /**
+     * Constructs a new {@code AconfigStorageReadException} with the specified error code and detail
+     * message.
+     *
+     * @param errorCode The error code for this exception.
+     * @param msg The detail message for this exception.
+     */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public AconfigStorageReadException(@ErrorCode int errorCode, @NonNull String msg) {
+        super(msg);
+        mErrorCode = errorCode;
+    }
+
+    /**
+     * Constructs a new {@code AconfigStorageReadException} with the specified error code, detail
+     * message, and cause.
+     *
+     * @param errorCode The error code for this exception.
+     * @param msg The detail message for this exception.
+     * @param cause The cause of this exception.
+     */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public AconfigStorageReadException(
+            @ErrorCode int errorCode, @NonNull String msg, @NonNull Throwable cause) {
+        super(msg, cause);
+        mErrorCode = errorCode;
+    }
+
+    /**
+     * Constructs a new {@code AconfigStorageReadException} with the specified error code and cause.
+     *
+     * @param errorCode The error code for this exception.
+     * @param cause The cause of this exception.
+     */
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public AconfigStorageReadException(@ErrorCode int errorCode, @NonNull Throwable cause) {
+        super(cause);
+        mErrorCode = errorCode;
+    }
+
+    /**
+     * Returns the error code associated with this exception.
+     *
+     * @return The error code.
+     */
+    @ErrorCode
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public int getErrorCode() {
+        return mErrorCode;
+    }
+
+    /**
+     * Returns the error message for this exception, including the error code and the original
+     * message.
+     *
+     * @return The error message.
+     */
+    @Override
+    @NonNull
+    @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+    public String getMessage() {
+        return errorString() + ": " + super.getMessage();
+    }
+
+    /**
+     * Returns a string representation of the error code.
+     *
+     * @return The error code string.
+     */
+    @NonNull
+    private String errorString() {
+        switch (mErrorCode) {
+            case ERROR_GENERIC:
+                return "ERROR_GENERIC";
+            case ERROR_STORAGE_SYSTEM_NOT_FOUND:
+                return "ERROR_STORAGE_SYSTEM_NOT_FOUND";
+            case ERROR_PACKAGE_NOT_FOUND:
+                return "ERROR_PACKAGE_NOT_FOUND";
+            case ERROR_CONTAINER_NOT_FOUND:
+                return "ERROR_CONTAINER_NOT_FOUND";
+            case ERROR_CANNOT_READ_STORAGE_FILE:
+                return "ERROR_CANNOT_READ_STORAGE_FILE";
+            case ERROR_FILE_FINGERPRINT_MISMATCH:
+                return "ERROR_FILE_FINGERPRINT_MISMATCH";
+            default:
+                return "<Unknown error code " + mErrorCode + ">";
+        }
+    }
+}
diff --git a/framework/java/android/os/flagging/AconfigWriteException.java b/framework/java/android/os/flagging/AconfigWriteException.java
new file mode 100644
index 0000000..57aabc9
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigWriteException.java
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
+package android.os.flagging;
+
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.SystemApi;
+import android.provider.flags.Flags;
+import android.util.AndroidRuntimeException;
+
+/**
+ * Exception raised when there is an error writing to aconfig flag storage.
+ *
+ * @hide
+ */
+@SystemApi
+@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+public class AconfigWriteException extends AndroidRuntimeException {
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public AconfigWriteException(@NonNull String message) {
+        super(message);
+    }
+
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public AconfigWriteException(@NonNull String message, @NonNull Throwable cause) {
+        super(message, cause);
+    }
+}
diff --git a/framework/java/android/os/flagging/AconfigdSocketWriter.java b/framework/java/android/os/flagging/AconfigdSocketWriter.java
new file mode 100644
index 0000000..eac4b70
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigdSocketWriter.java
@@ -0,0 +1,96 @@
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
+package android.os.flagging;
+
+import android.aconfigd.Aconfigd.StorageRequestMessages;
+import android.aconfigd.Aconfigd.StorageReturnMessages;
+import android.annotation.NonNull;
+import android.net.LocalSocket;
+import android.net.LocalSocketAddress;
+
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.OutputStream;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+import java.util.Arrays;
+
+/**
+ * Writes messages to aconfigd, and parses responses.
+ *
+ * @hide
+ */
+final class AconfigdSocketWriter {
+    private static final String SOCKET_ADDRESS = "aconfigd_system";
+
+    private final LocalSocket mSocket;
+
+    /**
+     * Create a new aconfigd socket connection.
+     *
+     * @hide
+     */
+    public AconfigdSocketWriter() throws IOException {
+        mSocket = new LocalSocket();
+        LocalSocketAddress address =
+                new LocalSocketAddress(SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
+        if (!mSocket.isConnected()) {
+            mSocket.connect(address);
+        }
+    }
+
+    /**
+     * Serialize {@code messages}, send to aconfigd, then receive and parse response.
+     *
+     * @param messages messages to send to aconfigd
+     * @return a {@code StorageReturnMessages} received from the socket
+     * @throws IOException if there is an IOException communicating with the socket
+     * @hide
+     */
+    public StorageReturnMessages sendMessages(@NonNull StorageRequestMessages messages)
+            throws IOException {
+        OutputStream outputStream = mSocket.getOutputStream();
+        byte[] requestMessageBytes = messages.toByteArray();
+        outputStream.write(ByteBuffer.allocate(4).putInt(requestMessageBytes.length).array());
+        outputStream.write(requestMessageBytes);
+        outputStream.flush();
+
+        InputStream inputStream = mSocket.getInputStream();
+        byte[] lengthBytes = new byte[4];
+        int bytesRead = inputStream.read(lengthBytes);
+        if (bytesRead != 4) {
+            throw new IOException(
+                    "Failed to read message length. Expected 4 bytes, read "
+                            + bytesRead
+                            + " bytes, with content: "
+                            + Arrays.toString(lengthBytes));
+        }
+        int messageLength = ByteBuffer.wrap(lengthBytes).order(ByteOrder.BIG_ENDIAN).getInt();
+        byte[] responseMessageBytes = new byte[messageLength];
+        bytesRead = inputStream.read(responseMessageBytes);
+        if (bytesRead != messageLength) {
+            throw new IOException(
+                    "Failed to read complete message. Expected "
+                            + messageLength
+                            + " bytes, read "
+                            + bytesRead
+                            + " bytes");
+        }
+
+        return StorageReturnMessages.parseFrom(responseMessageBytes);
+    }
+}
diff --git a/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java b/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java
new file mode 100644
index 0000000..3d7e655
--- /dev/null
+++ b/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java
@@ -0,0 +1,50 @@
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
+package android.os.flagging;
+
+import android.annotation.FlaggedApi;
+import android.annotation.SystemApi;
+import android.app.SystemServiceRegistry;
+import android.provider.flags.Flags;
+
+/**
+ * Initializes framework services.
+ *
+ * @hide
+ */
+@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+public final class ConfigInfrastructureFrameworkInitializer {
+    /** Prevent instantiation. */
+    private ConfigInfrastructureFrameworkInitializer() {}
+
+    /**
+     * Called by {@link SystemServiceRegistry}'s static initializer and registers
+     * {@link FlagManager} to {@link Context}, so that {@link Context#getSystemService} can return
+     * it.
+     *
+     * <p>If this is called from other places, it throws a {@link IllegalStateException).
+     *
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public static void registerServiceWrappers() {
+        SystemServiceRegistry.registerContextAwareService(
+                FlagManager.FLAG_SERVICE_NAME,
+                FlagManager.class,
+                (context) -> new FlagManager(context));
+    }
+}
diff --git a/framework/java/android/os/flagging/FlagManager.java b/framework/java/android/os/flagging/FlagManager.java
new file mode 100644
index 0000000..1566e15
--- /dev/null
+++ b/framework/java/android/os/flagging/FlagManager.java
@@ -0,0 +1,312 @@
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
+package android.os.flagging;
+
+import android.aconfigd.Aconfigd.FlagOverride;
+import android.aconfigd.Aconfigd.StorageRequestMessage;
+import android.aconfigd.Aconfigd.StorageRequestMessage.FlagOverrideType;
+import android.aconfigd.Aconfigd.StorageRequestMessage.RemoveOverrideType;
+import android.aconfigd.Aconfigd.StorageRequestMessages;
+import android.aconfigd.Aconfigd.StorageReturnMessage;
+import android.aconfigd.Aconfigd.StorageReturnMessages;
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SystemApi;
+import android.annotation.SystemService;
+import android.content.Context;
+import android.provider.flags.Flags;
+
+import java.io.IOException;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * Provides write access to aconfigd-backed flag storage.
+ *
+ * @hide
+ */
+@SystemApi
+@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+@SystemService(FlagManager.FLAG_SERVICE_NAME)
+public final class FlagManager {
+    /**
+     * Create a new FlagManager.
+     *
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public FlagManager(@NonNull Context unusedContext) {}
+
+    /**
+     * Use with {@link #getSystemService(String)} to retrieve a {@link
+     * android.os.flagging.FlagManager} for pushing flag values to aconfig.
+     *
+     * @see Context#getSystemService(String)
+     *
+     * @hide
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public static final String FLAG_SERVICE_NAME = "flag";
+
+    /**
+     * Stage flag values, to apply when the device boots into system build {@code buildFingerprint}.
+     *
+     * <p>The mapping persists across reboots, until the device finally boots into the system {@code
+     * buildFingerprint}, when the mapping is cleared.
+     *
+     * <p>Only one {@code buildFingerprint} and map of flags can be stored at a time. Subsequent
+     * calls will overwrite the existing mapping.
+     *
+     * <p>If overrides are staged for the next reboot, from {@link
+     * WriteAconfig#setOverridesOnReboot}, and overrides are also staged for a {@code
+     * buildFingerprint}, and the device boots into {@code buildFingerprint}, the {@code
+     * buildFingerprint}-associated overrides will take precedence over the reboot-associated
+     * overrides.
+     *
+     * @param buildFingerprint a system build fingerprint identifier.
+     * @param flags map from flag qualified name to new value.
+     * @throws AconfigWriteException if the write fails.
+     * @see android.os.Build.FINGERPRINT
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void setBooleanOverridesOnSystemBuildFingerprint(
+            @NonNull String buildFingerprint, @NonNull Map<String, Boolean> flags) {
+        StorageRequestMessages requestMessages =
+                buildOtaFlagStagingMessages(Flag.buildFlags(flags), buildFingerprint);
+        sendMessages(requestMessages);
+    }
+
+    /**
+     * Stage flag values, to apply when the device reboots.
+     *
+     * <p>These flags will be cleared on the next reboot, regardless of whether they take effect.
+     * See {@link setBooleanOverridesOnSystemBuildFingerprint} for a thorough description of how the
+     * set of flags to take effect is determined on the next boot.
+     *
+     * @param flags map from flag qualified name to new value.
+     * @throws AconfigWriteException if the write fails.
+     *
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void setBooleanOverridesOnReboot(@NonNull Map<String, Boolean> flags) {
+        StorageRequestMessages requestMessages =
+                buildFlagOverrideMessages(
+                        Flag.buildFlags(flags), FlagOverrideType.SERVER_ON_REBOOT);
+        sendMessages(requestMessages);
+    }
+
+    /**
+     * Set local overrides, to apply on device reboot.
+     *
+     * <p>Local overrides take precedence over normal overrides. They must be cleared for normal
+     * overrides to take effect again.
+     *
+     * @param flags map from flag qualified name to new value.
+     * @see clearBooleanLocalOverridesOnReboot
+     * @see clearBooleanLocalOverridesImmediately
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void setBooleanLocalOverridesOnReboot(@NonNull Map<String, Boolean> flags) {
+        StorageRequestMessages requestMessages =
+                buildFlagOverrideMessages(Flag.buildFlags(flags), FlagOverrideType.LOCAL_ON_REBOOT);
+        sendMessages(requestMessages);
+    }
+
+    /**
+     * Set local overrides, to apply immediately.
+     *
+     * <p>Local overrides take precedence over normal overrides. They must be cleared for normal
+     * overrides to take effect again.
+     *
+     * <p>Note that processes cache flag values, so a process restart or reboot is still required to
+     * get the latest flag value.
+     *
+     * @param flags map from flag qualified name to new value.
+     * @see clearBooleanLocalOverridesOnReboot
+     * @see clearBooleanLocalOverridesImmediately
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void setBooleanLocalOverridesImmediately(@NonNull Map<String, Boolean> flags) {
+        StorageRequestMessages requestMessages =
+                buildFlagOverrideMessages(Flag.buildFlags(flags), FlagOverrideType.LOCAL_IMMEDIATE);
+        sendMessages(requestMessages);
+    }
+
+    /**
+     * Clear local overrides, to take effect on reboot.
+     *
+     * <p>If {@code flags} is {@code null}, clear all local overrides.
+     *
+     * @param flags map from flag qualified name to new value.
+     * @see setBooleanLocalOverridesOnReboot
+     * @see setBooleanLocalOverridesImmediately
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void clearBooleanLocalOverridesOnReboot(@Nullable Set<String> flags) {
+        StorageRequestMessages requestMessages =
+                buildClearFlagOverridesMessages(
+                        Flag.buildFlagsWithoutValues(flags),
+                        RemoveOverrideType.REMOVE_LOCAL_ON_REBOOT);
+        sendMessages(requestMessages);
+    }
+
+    /**
+     * Clear local overrides, to take effect immediately.
+     *
+     * <p>Note that processes cache flag values, so a process restart or reboot is still required to
+     * get the latest flag value.
+     *
+     * <p>If {@code flags} is {@code null}, clear all local overrides.
+     *
+     * @param flags map from flag qualified name to new value.
+     * @see setBooleanLocalOverridesOnReboot
+     * @see setBooleanLocalOverridesImmediately
+     */
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    public void clearBooleanLocalOverridesImmediately(@Nullable Set<String> flags) {
+        StorageRequestMessages requestMessages =
+                buildClearFlagOverridesMessages(
+                        Flag.buildFlagsWithoutValues(flags),
+                        RemoveOverrideType.REMOVE_LOCAL_IMMEDIATE);
+        sendMessages(requestMessages);
+    }
+
+    private void sendMessages(StorageRequestMessages messages) {
+        try {
+            StorageReturnMessages returnMessages =
+                    (new AconfigdSocketWriter()).sendMessages(messages);
+
+            String errorMessage = "";
+            for (StorageReturnMessage message : returnMessages.getMsgsList()) {
+                if (message.hasErrorMessage()) {
+                    errorMessage += message.getErrorMessage() + "\n";
+                }
+            }
+
+            if (!errorMessage.isEmpty()) {
+                throw new AconfigWriteException("error(s) writing aconfig flags: " + errorMessage);
+            }
+        } catch (IOException e) {
+            throw new AconfigWriteException("IO error writing aconfig flags", e);
+        }
+    }
+
+    private static class Flag {
+        public final String packageName;
+        public final String flagName;
+        public final String value;
+
+        public Flag(@NonNull String qualifiedName, @Nullable Boolean value) {
+            packageName = qualifiedName.substring(0, qualifiedName.lastIndexOf("."));
+            flagName = qualifiedName.substring(qualifiedName.lastIndexOf(".") + 1);
+            this.value = Boolean.toString(value);
+        }
+
+        public static Set<Flag> buildFlags(@NonNull Map<String, Boolean> flags) {
+            HashSet<Flag> flagSet = new HashSet();
+            for (Map.Entry<String, Boolean> flagAndValue : flags.entrySet()) {
+                flagSet.add(new Flag(flagAndValue.getKey(), flagAndValue.getValue()));
+            }
+            return flagSet;
+        }
+
+        public static Set<Flag> buildFlagsWithoutValues(@NonNull Set<String> flags) {
+            HashSet<Flag> flagSet = new HashSet();
+            for (String flag : flags) {
+                flagSet.add(new Flag(flag, null));
+            }
+            return flagSet;
+        }
+    }
+
+    private static StorageRequestMessages buildFlagOverrideMessages(
+            @NonNull Set<Flag> flagSet, FlagOverrideType overrideType) {
+        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
+        for (Flag flag : flagSet) {
+            StorageRequestMessage.FlagOverrideMessage message =
+                    StorageRequestMessage.FlagOverrideMessage.newBuilder()
+                            .setPackageName(flag.packageName)
+                            .setFlagName(flag.flagName)
+                            .setFlagValue(flag.value)
+                            .setOverrideType(overrideType)
+                            .build();
+            StorageRequestMessage requestMessage =
+                    StorageRequestMessage.newBuilder().setFlagOverrideMessage(message).build();
+            requestMessagesBuilder.addMsgs(requestMessage);
+        }
+        return requestMessagesBuilder.build();
+    }
+
+    private static StorageRequestMessages buildOtaFlagStagingMessages(
+            @NonNull Set<Flag> flagSet, @NonNull String buildFingerprint) {
+        StorageRequestMessage.OTAFlagStagingMessage.Builder otaMessageBuilder =
+                StorageRequestMessage.OTAFlagStagingMessage.newBuilder()
+                        .setBuildId(buildFingerprint);
+        for (Flag flag : flagSet) {
+            FlagOverride override =
+                    FlagOverride.newBuilder()
+                            .setPackageName(flag.packageName)
+                            .setFlagName(flag.flagName)
+                            .setFlagValue(flag.value)
+                            .build();
+            otaMessageBuilder.addOverrides(override);
+        }
+        StorageRequestMessage.OTAFlagStagingMessage otaMessage = otaMessageBuilder.build();
+        StorageRequestMessage requestMessage =
+                StorageRequestMessage.newBuilder().setOtaStagingMessage(otaMessage).build();
+        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
+        requestMessagesBuilder.addMsgs(requestMessage);
+        return requestMessagesBuilder.build();
+    }
+
+    private static StorageRequestMessages buildClearFlagOverridesMessages(
+            @Nullable Set<Flag> flagSet, RemoveOverrideType removeOverrideType) {
+        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
+
+        if (flagSet == null) {
+            StorageRequestMessage.RemoveLocalOverrideMessage message =
+                    StorageRequestMessage.RemoveLocalOverrideMessage.newBuilder()
+                            .setRemoveAll(true)
+                            .setRemoveOverrideType(removeOverrideType)
+                            .build();
+            StorageRequestMessage requestMessage =
+                    StorageRequestMessage.newBuilder()
+                            .setRemoveLocalOverrideMessage(message)
+                            .build();
+            requestMessagesBuilder.addMsgs(requestMessage);
+            return requestMessagesBuilder.build();
+        }
+
+        for (Flag flag : flagSet) {
+            StorageRequestMessage.RemoveLocalOverrideMessage message =
+                    StorageRequestMessage.RemoveLocalOverrideMessage.newBuilder()
+                            .setPackageName(flag.packageName)
+                            .setFlagName(flag.flagName)
+                            .setRemoveOverrideType(removeOverrideType)
+                            .setRemoveAll(false)
+                            .build();
+            StorageRequestMessage requestMessage =
+                    StorageRequestMessage.newBuilder()
+                            .setRemoveLocalOverrideMessage(message)
+                            .build();
+            requestMessagesBuilder.addMsgs(requestMessage);
+        }
+        return requestMessagesBuilder.build();
+    }
+}
diff --git a/framework/java/android/provider/DeviceConfig.java b/framework/java/android/provider/DeviceConfig.java
index 7b97151..5133ed7 100644
--- a/framework/java/android/provider/DeviceConfig.java
+++ b/framework/java/android/provider/DeviceConfig.java
@@ -34,11 +34,22 @@ import android.annotation.SystemApi;
 import android.content.ContentResolver;
 import android.database.ContentObserver;
 import android.net.Uri;
+import android.os.Binder;
+import android.os.IBinder;
+import android.os.ParcelFileDescriptor;
+import android.provider.DeviceConfigServiceManager;
+import android.provider.DeviceConfigInitializer;
+import android.provider.aidl.IDeviceConfigManager;
 import android.provider.flags.Flags;
+import android.ravenwood.annotation.RavenwoodKeepWholeClass;
+import android.ravenwood.annotation.RavenwoodRedirect;
+import android.ravenwood.annotation.RavenwoodRedirectionClass;
+import android.ravenwood.annotation.RavenwoodThrow;
 import android.util.ArrayMap;
 import android.util.ArraySet;
 import android.util.Log;
 import android.util.Pair;
+import android.util.Slog;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.modules.utils.build.SdkLevel;
@@ -63,15 +74,6 @@ import java.util.TreeMap;
 import java.util.TreeSet;
 import java.util.concurrent.Executor;
 
-import android.util.Log;
-
-import android.provider.aidl.IDeviceConfigManager;
-import android.provider.DeviceConfigServiceManager;
-import android.provider.DeviceConfigInitializer;
-import android.os.Binder;
-import android.os.IBinder;
-import android.os.ParcelFileDescriptor;
-
 /**
  * Device level configuration parameters which can be tuned by a separate configuration service.
  * Namespaces that end in "_native" such as {@link #NAMESPACE_NETD_NATIVE} are intended to be used
@@ -80,6 +82,8 @@ import android.os.ParcelFileDescriptor;
  * @hide
  */
 @SystemApi
+@RavenwoodKeepWholeClass
+@RavenwoodRedirectionClass("DeviceConfig_host")
 public final class DeviceConfig {
 
     /**
@@ -1033,6 +1037,20 @@ public final class DeviceConfig {
     @SystemApi
     public static final int SYNC_DISABLED_MODE_UNTIL_REBOOT = 2;
 
+
+    // NOTE: this API is only used by the framework code, but using MODULE_LIBRARIES causes a
+    // build-time error on CtsDeviceConfigTestCases, so it's using PRIVILEGED_APPS.
+    /**
+     * Optional argument to {@link #dump(ParcelFileDescriptor, PrintWriter, String, String[])} to
+     * indicate that the next argument is a namespace. How {@code dump()} will handle that
+     * argument is documented there.
+     *
+     * @hide
+     */
+    @SystemApi(client = SystemApi.Client.PRIVILEGED_APPS)
+    @FlaggedApi(Flags.FLAG_DUMP_IMPROVEMENTS)
+    public static final String DUMP_ARG_NAMESPACE = "--namespace";
+
     private static final Object sLock = new Object();
     @GuardedBy("sLock")
     private static ArrayMap<OnPropertiesChangedListener, Pair<String, Executor>> sListeners =
@@ -1040,8 +1058,14 @@ public final class DeviceConfig {
     @GuardedBy("sLock")
     private static Map<String, Pair<ContentObserver, Integer>> sNamespaces = new HashMap<>();
     private static final String TAG = "DeviceConfig";
+    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
+
+    private static final DeviceConfigDataStore sDataStore = newDataStore();
 
-    private static final DeviceConfigDataStore sDataStore = new SettingsConfigDataStore();
+    @RavenwoodRedirect
+    private static DeviceConfigDataStore newDataStore() {
+        return new SettingsConfigDataStore();
+    }
 
     private static final String DEVICE_CONFIG_OVERRIDES_NAMESPACE =
             "device_config_overrides";
@@ -1242,7 +1266,7 @@ public final class DeviceConfig {
         try {
             return Integer.parseInt(value);
         } catch (NumberFormatException e) {
-            Log.e(TAG, "Parsing integer failed for " + namespace + ":" + name);
+            Slog.e(TAG, "Parsing integer failed for " + namespace + ":" + name);
             return defaultValue;
         }
     }
@@ -1267,7 +1291,7 @@ public final class DeviceConfig {
         try {
             return Long.parseLong(value);
         } catch (NumberFormatException e) {
-            Log.e(TAG, "Parsing long failed for " + namespace + ":" + name);
+            Slog.e(TAG, "Parsing long failed for " + namespace + ":" + name);
             return defaultValue;
         }
     }
@@ -1293,7 +1317,7 @@ public final class DeviceConfig {
         try {
             return Float.parseFloat(value);
         } catch (NumberFormatException e) {
-            Log.e(TAG, "Parsing float failed for " + namespace + ":" + name);
+            Slog.e(TAG, "Parsing float failed for " + namespace + ":" + name);
             return defaultValue;
         }
     }
@@ -1463,6 +1487,7 @@ public final class DeviceConfig {
      * @see #setProperty(String, String, String, boolean)
      */
     @SystemApi
+    @RavenwoodThrow
     @RequiresPermission(anyOf = {WRITE_DEVICE_CONFIG, WRITE_ALLOWLISTED_DEVICE_CONFIG})
     public static void resetToDefaults(int resetMode, @Nullable String namespace) {
         sDataStore.resetToDefaults(resetMode, namespace);
@@ -1535,13 +1560,21 @@ public final class DeviceConfig {
         }
     }
 
+    // TODO(b/364399200): should provide a getOnPropertiesChangedListeners() methods instead and let
+    // caller implement dump() instead
+
     // NOTE: this API is only used by the framework code, but using MODULE_LIBRARIES causes a
     // build-time error on CtsDeviceConfigTestCases, so it's using PRIVILEGED_APPS.
     /**
-     * Dumps internal state into the given {@code fd} or {@code pw}.
+     * Dumps internal state into the given {@code fd} or {@code printWriter}.
+     *
+     * <p><b>Note:</b> Currently the only supported argument is
+     * {@link DeviceConfig#DUMP_ARG_NAMESPACE}, which will filter the output using a substring of
+     * the next argument. But other arguments might be
+     * dynamically added in the future, without documentation - this method is meant only for
+     * debugging purposes, and should not be used as a formal API.
      *
-     * @param fd file descriptor that will output the dump state. Typically used for binary dumps.
-     * @param pw print writer that will output the dump state. Typically used for formatted text.
+     * @param printWriter print writer that will output the dump state.
      * @param prefix prefix added to each line
      * @param args (optional) arguments passed by {@code dumpsys}.
      *
@@ -1549,19 +1582,44 @@ public final class DeviceConfig {
      */
     @SystemApi(client = SystemApi.Client.PRIVILEGED_APPS)
     @FlaggedApi(Flags.FLAG_DUMP_IMPROVEMENTS)
-    @RequiresPermission(DUMP)
-    public static void dump(@NonNull ParcelFileDescriptor fd, @NonNull PrintWriter pw,
-            @NonNull String dumpPrefix, @Nullable String[] args) {
+    public static void dump(@NonNull PrintWriter printWriter, @NonNull String dumpPrefix,
+            @Nullable String[] args) {
+        if (DEBUG) {
+            Slog.d(TAG, "dump(): args=" + Arrays.toString(args));
+        }
+        Objects.requireNonNull(printWriter, "printWriter cannot be null");
+
         Comparator<OnPropertiesChangedListener> comparator = (o1, o2) -> o1.toString()
                 .compareTo(o2.toString());
         TreeMap<String, Set<OnPropertiesChangedListener>> listenersByNamespace  =
                 new TreeMap<>();
         ArraySet<OnPropertiesChangedListener> uniqueListeners = new ArraySet<>();
+        String filter = null;
+        if (args.length > 0) {
+            switch (args[0]) {
+                case DUMP_ARG_NAMESPACE:
+                    if (args.length < 2) {
+                        throw new IllegalArgumentException(
+                                "argument " + DUMP_ARG_NAMESPACE + " requires an extra argument");
+                    }
+                    filter = args[1];
+                    if (DEBUG) {
+                        Slog.d(TAG, "dump(): setting filter as " + filter);
+                    }
+                    break;
+                default:
+                    Slog.w(TAG, "dump(): ignoring invalid arguments: " + Arrays.toString(args));
+                    break;
+            }
+        }
         int listenersSize;
         synchronized (sLock) {
             listenersSize = sListeners.size();
             for (int i = 0; i < listenersSize; i++) {
                 var namespace = sListeners.valueAt(i).first;
+                if (filter != null && !namespace.contains(filter)) {
+                    continue;
+                }
                 var listener = sListeners.keyAt(i);
                 var listeners = listenersByNamespace.get(namespace);
                 if (listeners == null) {
@@ -1573,14 +1631,14 @@ public final class DeviceConfig {
                 uniqueListeners.add(listener);
             }
         }
-        pw.printf("%s%d listeners for %d namespaces:\n", dumpPrefix, uniqueListeners.size(),
+        printWriter.printf("%s%d listeners for %d namespaces:\n", dumpPrefix, uniqueListeners.size(),
                 listenersByNamespace.size());
         for (var entry : listenersByNamespace.entrySet()) {
             var namespace = entry.getKey();
             var listeners = entry.getValue();
-            pw.printf("%s%s: %d listeners\n", dumpPrefix, namespace, listeners.size());
+            printWriter.printf("%s%s: %d listeners\n", dumpPrefix, namespace, listeners.size());
             for (var listener : listeners) {
-                pw.printf("%s%s%s\n", dumpPrefix, dumpPrefix, listener);
+                printWriter.printf("%s%s%s\n", dumpPrefix, dumpPrefix, listener);
             }
         }
     }
@@ -1614,6 +1672,7 @@ public final class DeviceConfig {
      * @hide
      */
     @SystemApi
+    @RavenwoodThrow
     @RequiresPermission(Manifest.permission.MONITOR_DEVICE_CONFIG_ACCESS)
     public static void setMonitorCallback(
             @NonNull ContentResolver resolver,
@@ -1629,6 +1688,7 @@ public final class DeviceConfig {
      * @hide
      */
     @SystemApi
+    @RavenwoodThrow
     @RequiresPermission(Manifest.permission.MONITOR_DEVICE_CONFIG_ACCESS)
     public static void clearMonitorCallback(@NonNull ContentResolver resolver) {
         sDataStore.clearMonitorCallback(resolver);
@@ -1702,7 +1762,7 @@ public final class DeviceConfig {
                 properties = getProperties(namespace, keys);
             } catch (SecurityException e) {
                 // Silently failing to not crash binder or listener threads.
-                Log.e(TAG, "OnPropertyChangedListener update failed: permission violation.");
+                Slog.e(TAG, "OnPropertyChangedListener update failed: permission violation.");
                 return;
             }
 
@@ -1744,6 +1804,16 @@ public final class DeviceConfig {
         return WritableFlags.ALLOWLIST;
     }
 
+    /**
+     * Returns the list of namespaces in which all flags can be written with adb as non-root.
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(Flags.FLAG_DEVICE_CONFIG_WRITABLE_NAMESPACES_API)
+    public static @NonNull Set<String> getAdbWritableNamespaces() {
+        return WritableNamespaces.ALLOWLIST;
+    }
+
     /**
      * Interface for monitoring changes to properties. Implementations will receive callbacks when
      * properties change, including a {@link Properties} object which contains a single namespace
@@ -1881,7 +1951,7 @@ public final class DeviceConfig {
             try {
                 return Integer.parseInt(value);
             } catch (NumberFormatException e) {
-                Log.e(TAG, "Parsing int failed for " + name);
+                Slog.e(TAG, "Parsing int failed for " + name);
                 return defaultValue;
             }
         }
@@ -1903,7 +1973,7 @@ public final class DeviceConfig {
             try {
                 return Long.parseLong(value);
             } catch (NumberFormatException e) {
-                Log.e(TAG, "Parsing long failed for " + name);
+                Slog.e(TAG, "Parsing long failed for " + name);
                 return defaultValue;
             }
         }
@@ -1925,7 +1995,7 @@ public final class DeviceConfig {
             try {
                 return Float.parseFloat(value);
             } catch (NumberFormatException e) {
-                Log.e(TAG, "Parsing float failed for " + name);
+                Slog.e(TAG, "Parsing float failed for " + name);
                 return defaultValue;
             }
         }
diff --git a/framework/java/android/provider/OWNERS b/framework/java/android/provider/OWNERS
index 20d7511..66438db 100644
--- a/framework/java/android/provider/OWNERS
+++ b/framework/java/android/provider/OWNERS
@@ -1 +1,2 @@
-per-file WritableFlags.java = cbrubaker@google.com,tedbauer@google.com
+per-file WritableFlags.java = mpgroover@google.com,tedbauer@google.com
+per-file WritableNamespaces.java = mpgroover@google.com,tedbauer@google.com
diff --git a/framework/java/android/provider/StageOtaFlags.java b/framework/java/android/provider/StageOtaFlags.java
index 6d56ee6..74d697b 100644
--- a/framework/java/android/provider/StageOtaFlags.java
+++ b/framework/java/android/provider/StageOtaFlags.java
@@ -13,49 +13,161 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 package android.provider;
 
+import android.aconfigd.Aconfigd.FlagOverride;
+import android.aconfigd.Aconfigd.StorageRequestMessage;
+import android.aconfigd.Aconfigd.StorageRequestMessages;
+import android.aconfigd.Aconfigd.StorageReturnMessages;
+import android.annotation.IntDef;
 import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.SystemApi;
+import android.net.LocalSocket;
+import android.net.LocalSocketAddress;
 import android.provider.flags.Flags;
+import android.util.AndroidRuntimeException;
 import android.util.Log;
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.OutputStream;
+import java.io.File;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
 import java.util.Map;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Retention;
 
 /** @hide */
 @SystemApi
 @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
 public final class StageOtaFlags {
   private static String LOG_TAG = "StageOtaFlags";
+  private static final String SOCKET_ADDRESS = "aconfigd_system";
+  private static final String STORAGE_MARKER_FILE_PATH
+        = "/metadata/aconfig/boot/enable_only_new_storage";
+
+  /** Aconfig storage is disabled and unavailable for writes. @hide */
+  @SystemApi public static final int STATUS_STORAGE_NOT_ENABLED = -1;
+  /** Stage request was successful. @hide */
+  @SystemApi public static final int STATUS_STAGE_SUCCESS = 0;
+
+  /** @hide */
+  @IntDef(prefix = { "STATUS_" }, value = {
+    STATUS_STORAGE_NOT_ENABLED,
+    STATUS_STAGE_SUCCESS,
+  })
+  @Retention(RetentionPolicy.SOURCE)
+  public @interface StageStatus {}
 
   private StageOtaFlags() {}
 
   /**
    * Stage aconfig flags to be applied when booting into {@code buildId}.
    *
-   * <p>Only a single {@code buildId} and its corresponding flags are stored at
-   * once. Every invocation of this method will overwrite whatever mapping was
-   * previously stored.
+   * <p>Only a single {@code buildId} and its corresponding flags are stored at once. Every
+   * invocation of this method will overwrite whatever mapping was previously stored.
    *
-   * It is an implementation error to call this if the storage is not
-   * initialized and ready to receive writes. Callers must ensure that it is
-   * available before invoking.
+   * <p>It is an implementation error to call this if the storage is not initialized and ready to
+   * receive writes. Callers must ensure that it is available before invoking.
    *
-   * TODO(b/361783454): create an isStorageAvailable API and mention it in this
-   * docstring.
+   * <p>TODO(b/361783454): create an isStorageAvailable API and mention it in this docstring.
    *
    * @param flags a map from {@code <packagename>.<flagname>} to flag values
    * @param buildId when the device boots into buildId, it will apply {@code flags}
-   * @throws IllegalStateException if the storage is not ready to receive writes
-   *
+   * @throws AndroidRuntimeException if communication with aconfigd fails
    * @hide
    */
   @SystemApi
   @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
-  public static void stageBooleanAconfigFlagsForBuild(
+  @StageStatus
+  public static int stageBooleanAconfigFlagsForBuild(
       @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
     int flagCount = flags.size();
     Log.d(LOG_TAG, "stageFlagsForBuild invoked for " + flagCount + " flags");
+
+    try {
+      LocalSocket socket = new LocalSocket();
+      LocalSocketAddress address =
+          new LocalSocketAddress(SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
+      if (!socket.isConnected()) {
+        socket.connect(address);
+      }
+      InputStream inputStream = socket.getInputStream();
+      OutputStream outputStream = socket.getOutputStream();
+
+      StorageRequestMessages requestMessages = buildRequestMessages(flags, buildId);
+
+      writeToSocket(outputStream, requestMessages);
+      readFromSocket(inputStream);
+    } catch (IOException e) {
+      throw new AndroidRuntimeException(e);
+    }
+
+    return STATUS_STAGE_SUCCESS;
+  }
+
+  private static void writeToSocket(
+      OutputStream outputStream, StorageRequestMessages requestMessages) throws IOException {
+    byte[] messageBytes = requestMessages.toByteArray();
+    outputStream.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
+    outputStream.write(messageBytes);
+    outputStream.flush();
+  }
+
+  private static StorageReturnMessages readFromSocket(InputStream inputStream) throws IOException {
+    byte[] lengthBytes = new byte[4];
+    int bytesRead = inputStream.read(lengthBytes);
+    if (bytesRead != 4) {
+      throw new IOException("Failed to read message length");
+    }
+
+    int messageLength = ByteBuffer.wrap(lengthBytes).order(ByteOrder.BIG_ENDIAN).getInt();
+
+    byte[] messageBytes = new byte[messageLength];
+    bytesRead = inputStream.read(messageBytes);
+    if (bytesRead != messageLength) {
+      throw new IOException("Failed to read complete message");
+    }
+
+    return StorageReturnMessages.parseFrom(messageBytes);
+  }
+
+  private static StorageRequestMessages buildRequestMessages(
+      @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
+    StorageRequestMessage.OTAFlagStagingMessage.Builder otaMessageBuilder =
+        StorageRequestMessage.OTAFlagStagingMessage.newBuilder().setBuildId(buildId);
+    for (Map.Entry<String, Boolean> flagAndValue : flags.entrySet()) {
+      String qualifiedFlagName = flagAndValue.getKey();
+
+      // aconfig flags follow a package_name [dot] flag_name convention and will always have
+      // a [dot] character in the flag name.
+      //
+      // If a [dot] character wasn't found it's likely because this was a legacy flag. We make no
+      // assumptions here and still attempt to stage these flags with aconfigd and let it decide
+      // whether to use the flag / discard it.
+      String packageName = "";
+      String flagName = qualifiedFlagName;
+      int idx = qualifiedFlagName.lastIndexOf(".");
+      if (idx != -1) {
+        packageName = qualifiedFlagName.substring(0, qualifiedFlagName.lastIndexOf("."));
+        flagName = qualifiedFlagName.substring(qualifiedFlagName.lastIndexOf(".") + 1);
+      }
+
+      String value = flagAndValue.getValue() ? "true" : "false";
+      FlagOverride override =
+          FlagOverride.newBuilder()
+              .setPackageName(packageName)
+              .setFlagName(flagName)
+              .setFlagValue(value)
+              .build();
+      otaMessageBuilder.addOverrides(override);
+    }
+    StorageRequestMessage.OTAFlagStagingMessage otaMessage = otaMessageBuilder.build();
+    StorageRequestMessage requestMessage =
+        StorageRequestMessage.newBuilder().setOtaStagingMessage(otaMessage).build();
+    StorageRequestMessages requestMessages =
+        StorageRequestMessages.newBuilder().addMsgs(requestMessage).build();
+    return requestMessages;
   }
 }
diff --git a/framework/java/android/provider/WritableFlags.java b/framework/java/android/provider/WritableFlags.java
index 47f5acf..e6c1f77 100644
--- a/framework/java/android/provider/WritableFlags.java
+++ b/framework/java/android/provider/WritableFlags.java
@@ -1,5 +1,7 @@
 package android.provider;
 
+import android.ravenwood.annotation.RavenwoodKeepWholeClass;
+
 import java.util.Arrays;
 import java.util.HashSet;
 import java.util.Set;
@@ -13,15 +15,19 @@ import java.util.List;
  * description of the flag's functionality, and a justification for why it needs to be
  * allowlisted.
  */
+@RavenwoodKeepWholeClass
 final class WritableFlags {
     public static final Set<String> ALLOWLIST =
             new HashSet<String>(Arrays.asList(
+                "a.a.a/b.b",
+                "a.a.a/b.b.b",
                 "accessibility/enable_font_scaling_qs_tile",
                 "accessibility/enable_magnifier_thumbnail",
                 "activity_manager/am_block_activity_starts_after_home",
                 "activity_manager/android_app_data_isolation_min_sdk",
                 "activity_manager/background_activity_starts_package_names_whitelist",
                 "activity_manager/bg_abusive_notification_minimal_interval",
+                "activity_manager/bg_auto_restricted_bucket_on_bg_restricted",
                 "activity_manager/bg_current_drain_auto_restrict_abusive_apps_enabled",
                 "activity_manager/bg_current_drain_threshold_to_bg_restricted",
                 "activity_manager/bg_prompt_abusive_apps_to_bg_restricted",
@@ -31,14 +37,32 @@ final class WritableFlags {
                 "activity_manager/compact_proc_state_throttle",
                 "activity_manager/compact_statsd_sample_rate",
                 "activity_manager/containing",
-                "activity_manager/containing",
+                "activity_manager/data_sync_fgs_timeout_duration",
                 "activity_manager/default_background_activity_starts_enabled",
                 "activity_manager/default_background_fgs_starts_restriction_enabled",
                 "activity_manager/enable_app_start_info",
                 "activity_manager/enforce_exported_flag_requirement",
+                "activity_manager/fgs_crash_extra_wait_duration",
+                "activity_manager/fgs_type_perm_enforcement_flag_camera",
+                "activity_manager/fgs_type_perm_enforcement_flag_connected_device",
+                "activity_manager/fgs_type_perm_enforcement_flag_data_sync",
+                "activity_manager/fgs_type_perm_enforcement_flag_health",
+                "activity_manager/fgs_type_perm_enforcement_flag_location",
+                "activity_manager/fgs_type_perm_enforcement_flag_media_playback",
+                "activity_manager/fgs_type_perm_enforcement_flag_media_projection",
+                "activity_manager/fgs_type_perm_enforcement_flag_microphone",
+                "activity_manager/fgs_type_perm_enforcement_flag_phone_call",
+                "activity_manager/fgs_type_perm_enforcement_flag_remote_messaging",
+                "activity_manager/fgs_type_perm_enforcement_flag_special_use",
+                "activity_manager/fgs_type_perm_enforcement_flag_system_exempted",
+                "activity_manager/fg_to_bg_fgs_grace_duration",
                 "activity_manager/low_swap_threshold_percent",
                 "activity_manager/lru_weight",
                 "activity_manager/max_cached_processes",
+                "activity_manager/max_phantom_processes",
+                "activity_manager/max_service_connections_per_process",
+                "activity_manager/media_processing_fgs_timeout_duration",
+                "activity_manager_native_boot/freeze_debounce_timeout",
                 "activity_manager_native_boot/freeze_debounce_timeout_ms",
                 "activity_manager_native_boot/freeze_exempt_inst_pkg",
                 "activity_manager_native_boot/modern_queue_enabled",
@@ -49,113 +73,39 @@ final class WritableFlags {
                 "activity_manager/proactive_kills_enabled",
                 "activity_manager/push_messaging_over_quota_behavior",
                 "activity_manager/rss_weight",
+                "activity_manager/service_start_foreground_timeout_ms",
+                "activity_manager/short_fgs_anr_extra_wait_duration",
+                "activity_manager/short_fgs_proc_state_extra_wait_duration",
+                "activity_manager/short_fgs_timeout_duration",
+                "activity_manager/top_to_fgs_grace_duration",
                 "activity_manager/use_compaction",
                 "activity_manager/use_oom_re_ranking",
                 "activity_manager/uses_weight",
                 "adaptive_charging/adaptive_charging_enabled",
                 "adaptive_charging/adaptive_charging_notification",
-                "adservices/adid_kill_switch",
-                "adservices/adservice_enabled",
-                "adservices/adservice_system_service_enabled",
-                "adservices/appsetid_kill_switch",
-                "adservices/back_compact_test_param",
-                "adservices/disable_sdk_sandbox",
-                "adservices/enable_test_param",
-                "adservices/enable_topic_contributors_check",
-                "adservices/enrollment_blocklist_ids",
-                "adservices/fledge_ad_selection_bidding_timeout_per_ca_ms",
-                "adservices/fledge_ad_selection_concurrent_bidding_count",
-                "adservices/fledge_ad_selection_enforce_foreground_status_ad_selection_override",
-                "adservices/fledge_ad_selection_enforce_foreground_status_custom_audience",
-                "adservices/fledge_ad_selection_enforce_foreground_status_report_impression",
-                "adservices/fledge_ad_selection_enforce_foreground_status_run_ad_selection",
-                "adservices/fledge_ad_selection_overall_timeout_ms",
-                "adservices/fledge_ad_selection_scoring_timeout_ms",
-                "adservices/fledge_background_fetch_eligible_update_base_interval_s",
-                "adservices/fledge_background_fetch_enabled",
-                "adservices/fledge_background_fetch_job_flex_ms",
-                "adservices/fledge_background_fetch_job_max_runtime_ms",
-                "adservices/fledge_background_fetch_job_period_ms",
-                "adservices/fledge_background_fetch_max_num_updated",
-                "adservices/fledge_background_fetch_max_response_size_b",
-                "adservices/fledge_background_fetch_network_connect_timeout_ms",
-                "adservices/fledge_background_fetch_network_read_timeout_ms",
-                "adservices/fledge_background_fetch_thread_pool_size",
-                "adservices/fledge_custom_audience_active_time_window_ms",
-                "adservices/fledge_custom_audience_default_expire_in_ms",
-                "adservices/fledge_custom_audience_max_activate_in_ms",
-                "adservices/fledge_custom_audience_max_ads_size_b",
-                "adservices/fledge_custom_audience_max_bidding_logic_uri_size_b",
-                "adservices/fledge_custom_audience_max_count",
-                "adservices/fledge_custom_audience_max_daily_update_uri_size_b",
-                "adservices/fledge_custom_audience_max_expire_in_ms",
-                "adservices/fledge_custom_audience_max_name_size_b",
-                "adservices/fledge_custom_audience_max_num_ads",
-                "adservices/fledge_custom_audience_max_owner_count",
-                "adservices/fledge_custom_audience_max_trusted_bidding_data_size_b",
-                "adservices/fledge_custom_audience_max_user_bidding_signals_size_b",
-                "adservices/fledge_custom_audience_per_app_max_count",
-                "adservices/fledge_custom_audience_service_kill_switch",
-                "adservices/fledge_js_isolate_enforce_max_heap_size",
-                "adservices/fledge_js_isolate_max_heap_size_bytes",
-                "adservices/fledge_report_impression_overall_timeout_ms",
-                "adservices/fledge_select_ads_kill_switch",
-                "adservices/foreground_validation_status_level",
-                "adservices/ga_ux_enabled",
-                "adservices/global_kill_switch",
-                "adservices/mdd_android_sharing_sample_interval",
-                "adservices/mdd_api_logging_sample_interval",
-                "adservices/mdd_background_task_kill_switch",
-                "adservices/mdd_cellular_charging_gcm_task_period_seconds",
-                "adservices/mdd_charging_gcm_task_period_seconds",
-                "adservices/mdd_default_sample_interval",
-                "adservices/mdd_download_events_sample_interval",
-                "adservices/mdd_group_stats_logging_sample_interval",
-                "adservices/mdd_logger_kill_switch",
-                "adservices/mdd_maintenance_gcm_task_period_seconds",
-                "adservices/mdd_measurement_manifest_file_url",
-                "adservices/mdd_mobstore_file_service_stats_sample_interval",
-                "adservices/mdd_network_stats_logging_sample_interval",
-                "adservices/mdd_storage_stats_logging_sample_interval",
-                "adservices/mdd_topics_classifier_manifest_file_url",
-                "adservices/mdd_ui_ota_strings_manifest_file_url",
-                "adservices/mdd_wifi_charging_gcm_task_period_seconds",
-                "adservices/measurement_api_delete_registrations_kill_switch",
-                "adservices/measurement_api_register_source_kill_switch",
-                "adservices/measurement_api_register_trigger_kill_switch",
-                "adservices/measurement_api_register_web_source_kill_switch",
-                "adservices/measurement_api_register_web_trigger_kill_switch",
-                "adservices/measurement_api_status_kill_switch",
-                "adservices/measurement_job_aggregate_fallback_reporting_kill_switch",
-                "adservices/measurement_job_aggregate_reporting_kill_switch",
-                "adservices/measurement_job_attribution_kill_switch",
-                "adservices/measurement_job_delete_expired_kill_switch",
-                "adservices/measurement_job_event_fallback_reporting_kill_switch",
-                "adservices/measurement_job_event_reporting_kill_switch",
-                "adservices/measurement_kill_switch",
-                "adservices/measurement_receiver_delete_packages_kill_switch",
-                "adservices/measurement_receiver_install_attribution_kill_switch",
-                "adservices/ppapi_app_allow_list",
-                "adservices/ppapi_app_signature_allow_list",
-                "adservices/sdksandbox_customized_sdk_context_enabled",
-                "adservices/topics_epoch_job_flex_ms",
-                "adservices/topics_epoch_job_period_ms",
-                "adservices/topics_kill_switch",
-                "adservices/topics_number_of_lookback_epochs",
-                "adservices/topics_number_of_random_topics",
-                "adservices/topics_number_of_top_topics",
-                "adservices/topics_percentage_for_random_topics",
-                "adservices/ui_dialogs_feature_enabled",
-                "adservices/ui_ota_strings_download_deadline",
-                "adservices/ui_ota_strings_feature_enabled",
+                "alarm_manager/allow_while_idle_compat_quota",
+                "alarm_manager/allow_while_idle_compat_window",
+                "alarm_manager/allow_while_idle_quota",
+                "alarm_manager/allow_while_idle_window",
+                "alarm_manager/app_standby_restricted_window",
+                "alarm_manager/app_standby_window",
                 "alarm_manager/lazy_batching",
+                "alarm_manager/max_alarm_managers_per_uid",
+                "alarm_manager/min_futurity",
+                "alarm_manager/min_interval",
+                "alarm_manager/min_window",
+                "alarm_manager/priority_alarm_manager_delay",
                 "alarm_manager/temporary_quota_bump",
+                "ambient_context/service_enabled",
+                "android/system_gesture_exclusion_limit_dp",
                 "app_cloning/cloned_apps_enabled",
                 "app_cloning/enable_app_cloning_building_blocks",
+                "app_compat/hidden_api_access_statslog_sampling_rate",
                 "app_compat/hidden_api_log_sampling_rate",
                 "app_compat/hidden_api_statslog_sampling_rate",
                 "app_compat_overrides/cn_wps_moffice_eng_flag",
                 "app_compat_overrides/com_amanotes_beathopper_flag",
+                "app_compat_overrides/com.android.cts.appcompat.preinstalloverride",
                 "app_compat_overrides/com_balaji_alt_flag",
                 "app_compat_overrides/com_camerasideas_instashot_flag",
                 "app_compat_overrides/com_facebook_lite_flag",
@@ -190,16 +140,31 @@ final class WritableFlags {
                 "app_compat_overrides/net_zedge_android_flag",
                 "app_compat_overrides/org_telegram_messenger_flag",
                 "app_compat_overrides/org_zwanoo_android_speedtest_flag",
+                "app_compat_overrides/owned_change_ids",
                 "app_compat_overrides/owned_change_ids_flag",
+                "app_compat_overrides/remove_overrides",
                 "app_compat_overrides/remove_overrides_flag",
                 "app_compat_overrides/sg_bigo_live_flag",
                 "app_compat_overrides/tw_mobileapp_qrcode_banner_flag",
                 "app_compat_overrides/us_zoom_videomeetings_flag",
+                "appfunctions/execute_app_function_cancellation_timeout_millis",
+                "appfunctions/execute_app_function_timeout_millis",
                 "app_hibernation/app_hibernation_enabled",
                 "app_hibernation/app_hibernation_targets_pre_s_apps",
                 "app_hibernation/auto_revoke_check_frequency_millis",
+                "appsearch/app_function_call_timeout_millis",
+                "appsearch/contacts_indexer_enabled",
+                "app_standby/broadcast_response_fg_threshold_state",
+                "app_standby/broadcast_response_window_timeout_ms",
+                "app_standby/broadcast_sessions_duration_ms",
+                "app_standby/broadcast_sessions_with_response_duration_ms",
+                "app_standby/brodacast_response_exempted_permissions",
+                "app_standby/brodacast_response_exempted_roles",
+                "app_standby/note_response_event_for_all_broadcast_sessions",
+                "app_standby/notification_seen_duration",
                 "app_standby/notification_seen_duration_millis",
                 "app_standby/notification_seen_promoted_bucket",
+                "app_standby/retain_notification_seen_impact_for_pre_t_apps",
                 "app_standby/trigger_quota_bump_on_notification_seen",
                 "attention_manager_service/enable_flip_to_screen_off",
                 "attention_manager_service/keep_screen_on_enabled",
@@ -208,17 +173,26 @@ final class WritableFlags {
                 "attention_manager_service/post_dim_check_duration_millis",
                 "attention_manager_service/pre_dim_check_duration_millis",
                 "attention_manager_service/service_enabled",
-                "autofill/autofill_credential_manager_ignore_views",
                 "autofill/autofill_credential_manager_enabled",
+                "autofill/autofill_credential_manager_ignore_views",
                 "autofill/autofill_credential_manager_suppress_fill_dialog",
                 "autofill/autofill_credential_manager_suppress_save_dialog",
                 "autofill/autofill_dialog_enabled",
                 "autofill/autofill_dialog_hints",
+                "autofill/enable_relative_location_for_relayout",
+                "autofill/enable_relayout",
+                "autofill/fill_dialog_min_wait_after_animation_end_ms",
+                "autofill/fill_dialog_timeout_ms",
                 "autofill/compat_mode_allowed_packages",
+                "autofill/fill_fields_from_current_session_only",
+                "autofill/ignore_view_state_reset_to_empty",
+                "autofill/improve_fill_dialog",
                 "autofill/include_all_autofill_type_not_none_views_in_assist_structure",
                 "autofill/include_all_views_in_assist_structure",
+                "autofill/include_invisible_view_group_in_assist_structure",
                 "autofill/landscape_body_height_max_percent",
                 "autofill/legacy_augmented_autofill_mode",
+                "autofill/max_input_length_for_autofill",
                 "autofill/multiline_filter_enabled",
                 "autofill/non_autofillable_ime_action_ids",
                 "autofill/package_and_activity_allowlist_for_triggering_fill_request",
@@ -233,14 +207,27 @@ final class WritableFlags {
                 "autofill/trigger_fill_request_on_filtered_important_views",
                 "autofill/trigger_fill_request_on_unimportant_view",
                 "auto_pin_confirmation/enable_auto_pin_confirmation",
+                "b.b.b/c.c",
+                "backstage_power/min_consumed_power_threshold",
                 "backup_and_restore/backup_transport_callback_timeout_millis",
                 "backup_and_restore/backup_transport_callback_timeout_millis_new",
                 "backup_and_restore/backup_transport_future_timeout_millis",
                 "backup_and_restore/backup_transport_future_timeout_millis_new",
                 "backup_and_restore/full_backup_utils_route_buffer_size_bytes",
                 "backup_and_restore/full_backup_write_to_transport_buffer_size_bytes",
+                "battery_saver/enable_night_mode",
                 "battery_saver/location_mode",
+                "biometrics/biometric_strengths",
                 "biometrics/enable_biometric_property_verification",
+                "blobstore/delete_on_last_lease_delay_ms",
+                "blobstore/lease_acquisition_wait_time_ms",
+                "blobstore/max_active_sessions",
+                "blobstore/max_committed_blobs",
+                "blobstore/max_leased_blobs",
+                "blobstore/max_permitted_pks",
+                "blobstore/session_expiry_timeout_ms",
+                "blobstore/total_bytes_per_app_limit_floor",
+                "blobstore/total_bytes_per_app_limit_fraction",
                 "bluetooth/acl",
                 "bluetooth/apm_enhancement_enabled",
                 "bluetooth/bt_audio_policy_ag",
@@ -257,6 +244,7 @@ final class WritableFlags {
                 "bluetooth/logging_debug_enabled_for_all",
                 "bluetooth/report_delay",
                 "bluetooth/scanning",
+                "bluetooth/scan_quota_count",
                 "camera_native/sample_bool_flag",
                 "camera_native/sample_int_flag",
                 "car/bugreport_upload_destination",
@@ -273,43 +261,27 @@ final class WritableFlags {
                 "configuration/minimum_dpi",
                 "configuration/namespace_to_package_mapping",
                 "configuration/test_flag",
-                "configuration/test_flag",
-                "configuration/test_flag",
                 "configuration/test_flag_three",
                 "configuration/test_flag_two",
                 "configuration/version_test_flag",
-                "connectivity/actively_prefer_bad_wifi_value",
-                "connectivity/announce_interval",
-                "connectivity/automatic_enabled",
-                "connectivity/consecutive_dns_count",
-                "connectivity/first_announce_delay",
-                "connectivity/first_probe_delay",
-                "connectivity/garp_na_roaming_version",
-                "connectivity/gratuitous_na_version",
-                "connectivity/init_reboot_enabled",
-                "connectivity/init_reboot_version",
-                "connectivity/ip_conflict_detect_version",
-                "connectivity/parse_netlink_events_version",
-                "connectivity/probe_max",
-                "connectivity/probe_min",
-                "connectivity/rapid_commit_enabled",
-                "connectivity/rapid_commit_version",
-                "connectivity/reachability_mcast_resolicit_version",
-                "connectivity/restart_configuration_delay",
-                "connectivity/server_decline_version",
-                "connectivity/slow_retransmission_version",
                 "connectivity_thermal_power_manager/cellular_thermal_adaptive_thermal_status_adaptive_action_list",
                 "connectivity_thermal_power_manager/cellular_thermal_thermal_status_action_list_param",
                 "connectivity_thermal_power_manager/cellular_thermal_thermal_status_per_shutdown_action_param",
                 "constrain_display_apis/always_constrain_display_apis",
-                "constrain_display_apis/never_constrain_display_apis_all_packages",
                 "constrain_display_apis/never_constrain_display_apis",
+                "constrain_display_apis/never_constrain_display_apis_all_packages",
                 "content_capture/idle_flush_frequency",
                 "content_capture/legacy_enable_contentcapture",
                 "content_capture/logging_level",
                 "content_capture/service_explicitly_enabled",
                 "credential_manager/enable_credential_description_api",
                 "credential_manager/enable_credential_manager",
+                "DeviceConfigBootstrapValues/processed_values",
+                "device_config_overrides/namespace3:key3",
+                "device_config_overrides/namespace3:key4",
+                "device_config_overrides/namespace4:key3",
+                "device_config_overrides/namespace4:key4",
+                "device_idle/notification_allowlist_duration_ms",
                 "device_personalization_services/accel_sensor_collection_enabled",
                 "device_personalization_services/accel_sensor_enabled",
                 "device_personalization_services/accel_sensor_max_extension_millis",
@@ -364,7 +336,6 @@ final class WritableFlags {
                 "device_personalization_services/ambient_music_use_latest_track_offset",
                 "device_personalization_services/annotation_confidence_cutoff",
                 "device_personalization_services/app_blocklist",
-                "device_personalization_services/app_blocklist",
                 "device_personalization_services/app_prediction_active_model",
                 "device_personalization_services/app_prediction_active_predictor",
                 "device_personalization_services/app_prediction_enable_taskbar_deduping",
@@ -394,7 +365,6 @@ final class WritableFlags {
                 "device_personalization_services/can_use_gms_core_to_save_boarding_pass",
                 "device_personalization_services/can_use_gpay_to_save_boarding_pass",
                 "device_personalization_services/capture_interval_millis",
-                "device_personalization_services/capture_interval_millis",
                 "device_personalization_services/characterset_lang_detection_enabled",
                 "device_personalization_services/chat_translate_languages",
                 "device_personalization_services/chronicle_enabled",
@@ -478,12 +448,6 @@ final class WritableFlags {
                 "device_personalization_services/emergency_disable_feature_safecomm",
                 "device_personalization_services/emergency_disable_feature_smart_dictation",
                 "device_personalization_services/enable",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable",
                 "device_personalization_services/enable_action_boost_generator",
                 "device_personalization_services/enable_adaptive_audio",
                 "device_personalization_services/enable_adaptive_media_volume",
@@ -505,7 +469,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_appsearch_universal_fetcher_clock_corpus_app_srp_preview",
                 "device_personalization_services/enable_app_widget_cache",
                 "device_personalization_services/enable_assistant_geller_data_index",
-                "device_personalization_services/enable_assistant_geller_data_index",
                 "device_personalization_services/enable_assistant_memory_generator",
                 "device_personalization_services/enable_assist_parser",
                 "device_personalization_services/enable_audio_device_event_usage",
@@ -523,7 +486,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_biasing_for_screen_context",
                 "device_personalization_services/enable_blobstore_bitmap_fetch_in_launcher",
                 "device_personalization_services/enable_brella_in_astrea",
-                "device_personalization_services/enable_brella_in_astrea",
                 "device_personalization_services/enable_call_log_signals",
                 "device_personalization_services/enable_chat_app_biasing",
                 "device_personalization_services/enable_chronicle_eventbuffer",
@@ -531,7 +493,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_cinematic_effect",
                 "device_personalization_services/enable_cinematic_mdd",
                 "device_personalization_services/enable_clearcut_log",
-                "device_personalization_services/enable_clearcut_log",
                 "device_personalization_services/enable_clearcut_logging",
                 "device_personalization_services/enable_clipboard_entity_type_logging",
                 "device_personalization_services/enable_cloud_search",
@@ -548,11 +509,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_covid_card_inflate_buffer",
                 "device_personalization_services/enable_cross_device_timers",
                 "device_personalization_services/enabled",
-                "device_personalization_services/enabled",
-                "device_personalization_services/enabled",
-                "device_personalization_services/enabled",
-                "device_personalization_services/enabled",
-                "device_personalization_services/enabled",
                 "device_personalization_services/enable_dark_launch_outlook_events",
                 "device_personalization_services/enable_data_capture",
                 "device_personalization_services/enable_data_fetch",
@@ -581,14 +537,12 @@ final class WritableFlags {
                 "device_personalization_services/enable_example_consumption_recording",
                 "device_personalization_services/enable_example_store",
                 "device_personalization_services/enable_fa",
-                "device_personalization_services/enable_fa",
                 "device_personalization_services/enable_face_detection_from_camera",
                 "device_personalization_services/enable_face_detection_when_phone_in_portrait",
                 "device_personalization_services/enable_face_only_mode",
                 "device_personalization_services/enable_fa_synthetic",
                 "device_personalization_services/enable_fedex",
                 "device_personalization_services/enable_fed_sql",
-                "device_personalization_services/enable_fed_sql",
                 "device_personalization_services/enable_feedback_ranking",
                 "device_personalization_services/enable_flight_landing_smartspace_aiai",
                 "device_personalization_services/enable_foldable_hotseat",
@@ -605,7 +559,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_hotel_smartspace_aiai",
                 "device_personalization_services/enable_hybrid_hotseat_client",
                 "device_personalization_services/enable_image_selection",
-                "device_personalization_services/enable_image_selection",
                 "device_personalization_services/enable_image_selection_adjustments",
                 "device_personalization_services/enable_indirect_insights",
                 "device_personalization_services/enable_input_context_snapshot_capture",
@@ -683,7 +636,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_priority_suggestion_client",
                 "device_personalization_services/enable_proactive_hints",
                 "device_personalization_services/enable_profile_signals",
-                "device_personalization_services/enable_prominent_entities",
                 "device_personalization_services/enable_proximity",
                 "device_personalization_services/enable_punctuations",
                 "device_personalization_services/enable_query_intent_bloom_filter",
@@ -750,7 +702,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_travel_features_type_merge",
                 "device_personalization_services/enable_typing_interactions",
                 "device_personalization_services/enable_uncaught_exception_counter",
-                "device_personalization_services/enable_uncaught_exception_counter",
                 "device_personalization_services/enable_upgrade_importance",
                 "device_personalization_services/enable_uptime_logger",
                 "device_personalization_services/enable_usage_fa",
@@ -780,7 +731,6 @@ final class WritableFlags {
                 "device_personalization_services/fail_new_connections",
                 "device_personalization_services/fa_min_training_interval_ms",
                 "device_personalization_services/fa_population_name",
-                "device_personalization_services/fa_population_name",
                 "device_personalization_services/fast_recognition_ui_cleanup_enabled",
                 "device_personalization_services/favorites_enabled",
                 "device_personalization_services/feature_users_count_enabled",
@@ -878,12 +828,10 @@ final class WritableFlags {
                 "device_personalization_services/min_tc_entity_topicality",
                 "device_personalization_services/min_trained_events_to_log",
                 "device_personalization_services/min_training_interval_millis",
-                "device_personalization_services/min_training_interval_millis",
                 "device_personalization_services/min_travel_distance_meters",
                 "device_personalization_services/min_update_interval_seconds",
                 "device_personalization_services/model_url",
                 "device_personalization_services/model_version",
-                "device_personalization_services/model_version",
                 "device_personalization_services/module_enable",
                 "device_personalization_services/music_break_mode_update_policy",
                 "device_personalization_services/music_model_generate_negative_events",
@@ -901,7 +849,6 @@ final class WritableFlags {
                 "device_personalization_services/now_playing_allowed",
                 "device_personalization_services/nudges_amplification",
                 "device_personalization_services/num_frames",
-                "device_personalization_services/num_frames",
                 "device_personalization_services/num_simple_draws_per_job",
                 "device_personalization_services/oak_url",
                 "device_personalization_services/ocr_model_download_enabled",
@@ -918,8 +865,6 @@ final class WritableFlags {
                 "device_personalization_services/paired_device_low_battery_level",
                 "device_personalization_services/param",
                 "device_personalization_services/parameter",
-                "device_personalization_services/parameter",
-                "device_personalization_services/parameter",
                 "device_personalization_services/parameters",
                 "device_personalization_services/participation_window_days",
                 "device_personalization_services/pause_camera_after_screen_on_period_millis",
@@ -938,9 +883,6 @@ final class WritableFlags {
                 "device_personalization_services/probe_slice_id",
                 "device_personalization_services/process_seen_messages_in_message_expiring_apps",
                 "device_personalization_services/profile_app_suggestions_enable",
-                "device_personalization_services/prominent_entities_config_superpacks_url",
-                "device_personalization_services/prominent_entities_config_version",
-                "device_personalization_services/prominent_entities_enabled_packages_list",
                 "device_personalization_services/promote_sys_pointer_in_psb",
                 "device_personalization_services/proximity_configs",
                 "device_personalization_services/proximity_sensor_enabled",
@@ -1016,10 +958,8 @@ final class WritableFlags {
                 "device_personalization_services/should_enable_for_common_packages",
                 "device_personalization_services/show_cross_device_timer_label",
                 "device_personalization_services/show_debug_notification",
-                "device_personalization_services/show_debug_notification",
                 "device_personalization_services/show_enabled_apps_list_in_settings",
                 "device_personalization_services/show_promo_notification",
-                "device_personalization_services/show_promo_notification",
                 "device_personalization_services/show_user_settings",
                 "device_personalization_services/silent_feedback_crash_rate_percent",
                 "device_personalization_services/sim_event_screen_session_id",
@@ -1065,7 +1005,6 @@ final class WritableFlags {
                 "device_personalization_services/split_text_by_newline",
                 "device_personalization_services/storage_stats_log_sample_interval",
                 "device_personalization_services/superpacks_manifest_url",
-                "device_personalization_services/superpacks_manifest_url",
                 "device_personalization_services/superpacks_manifest_ver",
                 "device_personalization_services/s_upper_threshold",
                 "device_personalization_services/supported_app_packages",
@@ -1127,7 +1066,6 @@ final class WritableFlags {
                 "device_personalization_services/use_mdd_download_system",
                 "device_personalization_services/use_people_db_entities",
                 "device_personalization_services/user_setting_default_value",
-                "device_personalization_services/user_setting_default_value",
                 "device_personalization_services/use_silence_detector_state_bug_fix",
                 "device_personalization_services/use_translate_kit_streaming_api",
                 "device_personalization_services/use_vocab_annotator",
@@ -1142,6 +1080,7 @@ final class WritableFlags {
                 "device_personalization_services/wifi_predictor_weight",
                 "device_personalization_services/write_to_pfd",
                 "device_personalization_services/youtube_export_enabled",
+                "device_policy_manager/add-isfinanced-device",
                 "device_policy_manager/deprecate_usermanagerinternal_devicepolicy",
                 "device_policy_manager/enable_coexistence",
                 "device_policy_manager/enable_device_policy_engine",
@@ -1154,26 +1093,20 @@ final class WritableFlags {
                 "display_manager/fixed_refresh_rate_zones",
                 "display_manager/high_refresh_rate_blacklist",
                 "display_manager/peak_refresh_rate_default",
-                "exo/app_scaling_allowed_components",
-                "exo/app_streaming_allowed_components",
-                "exo/app_streaming_blocked_components",
-                "exo/app_streaming_task_navigation_allowed_components",
-                "exo/app_streaming_task_navigation_blocked_components",
-                "exo/enter_to_send_app_packages",
-                "exo/include_default_browser_in_allowed_task_navigation_components",
-                "exo/is_exo_dogfood",
-                "exo/is_exo_eng",
-                "exo/log_exo_metrics",
-                "exo/need_scale_screen",
-                "exo/show_exo_settings",
-                "exo/tile_is_available",
-                "exo/use_encrypted_transport",
-                "exo/wirecutter_start_automatically",
+                "flipendo/default_savings_mode_launch",
                 "flipendo/essential_apps",
+                "flipendo/flipendo_enabled_launch",
+                "flipendo/grayscale_enabled_launch",
+                "flipendo/is_ask_feature_enabled_launch",
+                "flipendo/lever_hotspot_enabled_launch",
+                "flipendo/lever_work_profile_enabled_launch",
+                "flipendo/resuspend_delay_minutes",
+                "flipendo/work_profile_tab_enabled",
                 "game_driver/crosshatch_blacklists",
                 "game_overlay/bubbleshooter.orig",
                 "game_overlay/com.activision.callofduty.shooter",
                 "game_overlay/com.aim.racing",
+                "game_overlay/com.android.server.cts.device.statsdatom",
                 "game_overlay/com.aniplex.fategrandorder",
                 "game_overlay/com.aniplex.twst.jp",
                 "game_overlay/com.ansangha.drdriving",
@@ -1287,6 +1220,9 @@ final class WritableFlags {
                 "health_connect/entry_points_enable",
                 "health_connect/exercise_routes_enable",
                 "health_connect/session_types_enable",
+                "health_fitness/enable_complete_state_change_jobs",
+                "health_fitness/enable_pause_state_change_jobs",
+                "health_fitness/enable_rate_limiter",
                 "health_fitness/exercise_routes_enable",
                 "health_fitness/session_types_enable",
                 "input_native_boot/deep_press_enabled",
@@ -1301,13 +1237,26 @@ final class WritableFlags {
                 "interaction_jank_monitor/trace_threshold_frame_time_millis",
                 "interaction_jank_monitor/trace_threshold_missed_frames",
                 "ipsec/config_auto_natt_keepalives_cellular_timeout_override_seconds",
+                "jobscheduler/aq_schedule_count",
+                "jobscheduler/aq_schedule_return_failure",
+                "jobscheduler/aq_schedule_throw_exception",
+                "jobscheduler/aq_schedule_window_ms",
+                "jobscheduler/conn_transport_batch_threshold",
+                "jobscheduler/enable_api_quotas",
+                "jobscheduler/fc_applied_constraints",
+                "jobscheduler/min_ready_cpu_only_jobs_count",
+                "jobscheduler/min_ready_non_active_jobs_count",
+                "jobscheduler/qc_allowed_time_per_period_rare_ms",
+                "jobscheduler/qc_max_session_count_restricted",
+                "jobscheduler/qc_timing_session_coalescing_duration_ms",
+                "jobscheduler/runtime_min_ej_guarantee_ms",
                 "kiwi/enable_remapping_by_inputsdk_version",
                 "kiwi/input_remapping_blocklist",
                 "latency_tracker/action_request_ime_shown_enable",
+                "latency_tracker/action_show_selection_toolbar_enable",
                 "latency_tracker/action_show_voice_interaction_enable",
                 "latency_tracker/action_show_voice_interaction_sample_interval",
                 "latency_tracker/action_show_voice_interaction_trace_threshold",
-                "latency_tracker/action_show_selection_toolbar_enable",
                 "latency_tracker/action_user_switch_enable",
                 "latency_tracker/enabled",
                 "latency_tracker/sampling_interval",
@@ -1324,10 +1273,6 @@ final class WritableFlags {
                 "latency_tracker/trigger_action_toggle_recents",
                 "latency_tracker/trigger_action_turn_on_screen",
                 "launcher/enabled",
-                "launcher/enabled",
-                "launcher/enabled",
-                "launcher/enabled",
-                "launcher/enabled",
                 "launcher/enable_ime_latency_logger",
                 "launcher/enable_impression_logging",
                 "launcher/enable_keyboard_transition_sync",
@@ -1337,7 +1282,6 @@ final class WritableFlags {
                 "launcher/inject_web_top",
                 "launcher_lily/enable_camera_block",
                 "launcher_lily/enable_feature",
-                "launcher_lily/enable_feature",
                 "launcher_lily/enable_files_block",
                 "launcher_lily/enable_rani_block",
                 "launcher/match_state_charlen",
@@ -1350,12 +1294,12 @@ final class WritableFlags {
                 "launcher/show_search_educard_qsb",
                 "launcher/use_app_search_for_web",
                 "launcher/use_fallback_app_search",
-                "low_power_standby/enable_policy",
-                "low_power_standby/enable_standby_ports",
                 "lmkd_native/thrashing_limit_critical",
                 "location/adas_settings_allowlist",
                 "location/enable_location_provider_manager_msl",
                 "location/ignore_settings_allowlist",
+                "low_power_standby/enable_policy",
+                "low_power_standby/enable_standby_ports",
                 "media_better_together/scanning_package_minimum_importance",
                 "media/media_metrics_mode",
                 "media/player_metrics_app_allowlist",
@@ -1366,39 +1310,22 @@ final class WritableFlags {
                 "media/player_metrics_per_app_user_media_activity_blocklist",
                 "media/player_metrics_per_app_use_time_allowlist",
                 "media/player_metrics_per_app_use_time_blocklist",
+                "mediaprovider/allowed_cloud_providers",
+                "mediaprovider/cloud_media_feature_enabled",
+                "mediaprovider/picker_pick_images_preload_selected",
                 "memory_safety_native_boot/bootloader_override",
                 "mglru_native/lru_gen_config",
-                "namespace/key",
                 "namespace1/key1",
                 "namespace1/key2",
                 "namespace1/key3",
+                "namespace1/key_non_existing",
                 "namespace2/key1",
                 "namespace2/key2",
                 "namespace2/key3",
-                "nearby/enable_presence_broadcast_legacy",
-                "nearby/fast_pair_aosp_enabled",
-                "nearby/nano_app_min_version",
-                "nearby/support_test_app",
-                "netd_native/cache_size",
-                "netd_native/dnsevent_subsampling",
-                "netd_native/doh_early_data",
-                "netd_native/doh_session_resumption",
-                "netd_native/dot_connect_timeout",
-                "netd_native/dot_maxtries",
-                "netd_native/dot_query_timeout",
-                "netd_native/dot_revalidation_threshold",
-                "netd_native/dot_xport_unusable_threshold",
-                "netd_native/enable_async_dot",
-                "netd_native/enable_doh",
-                "netd_native/enable_keep_listening_udp",
-                "netd_native/enable_parallel_lookup",
-                "netd_native/enable_server_selection",
-                "netd_native/latency_factor",
-                "netd_native/latency_offset_ms",
-                "netd_native/limiter",
-                "netd_native/parallel_lookup_sleep_time_millis",
-                "netd_native/retransmit_interval",
-                "netd_native/retransmit_retries",
+                "namespace3/key3",
+                "namespace3/key4",
+                "namespace4/key4",
+                "namespace/key",
                 "nnapi_native/current_feature_level",
                 "nnapi_native/telemetry_enable",
                 "notification_assistant/generate_actions",
@@ -1436,29 +1363,43 @@ final class WritableFlags {
                 "odad/scan_least_scanned",
                 "odad/sw_scn",
                 "odad/westworld_logging",
+                "ondeviceintelligence/service_enabled",
                 "oslo/mcc_whitelist",
                 "oslo/media_app_whitelist",
                 "ota/enable_server_based_ror",
+                "ota/server_based_ror_enabled",
                 "ota/wait_for_internet_ror",
-                "package_manager_service/MinInstallableTargetSdk__install_block_enabled",
-                "package_manager_service/MinInstallableTargetSdk__install_block_strict_mode_enabled",
-                "package_manager_service/MinInstallableTargetSdk__min_installable_target_sdk",
+                "package_manager_service/deferred_no_kill_post_delete_delay_ms_extended",
                 "package_manager_service/dormant_app_threshold_days",
                 "package_manager_service/downgrade_unused_apps_enabled",
                 "package_manager_service/inactive_app_threshold_days",
                 "package_manager_service/incfs_default_timeouts",
                 "package_manager_service/install_block_enabled",
                 "package_manager_service/install_block_strict_mode_enabled",
+                "package_manager_service/is_preapproval_available",
+                "package_manager_service/is_update_ownership_enforcement_available",
                 "package_manager_service/known_digesters_list",
                 "package_manager_service/low_storage_threshold_multiplier_for_downgrade",
                 "package_manager_service/min_installable_target_sdk",
+                "package_manager_service/MinInstallableTargetSdk__install_block_enabled",
+                "package_manager_service/MinInstallableTargetSdk__install_block_strict_mode_enabled",
+                "package_manager_service/MinInstallableTargetSdk__min_installable_target_sdk",
                 "package_manager_service/strict_mode_target_sdk",
+                "package_manager_service/verification_request_timeout_millis",
+                "package_manager_service/verifier_connection_timeout_millis",
                 "permissions/auto_revoke_check_frequency_millis",
+                "permissions/auto_revoke_unused_threshold_millis2",
+                "permissions/one_time_permissions_killed_delay_millis",
+                "permissions/one_time_permissions_timeout_millis",
                 "permissions/permission_changes_store_exact_time",
                 "privacy/bg_location_check_is_enabled",
                 "privacy/camera_mic_icons_enabled",
                 "privacy/camera_toggle_enabled",
                 "privacy/data_sharing_update_period_millis",
+                "privacy/discrete_history_cutoff_millis",
+                "privacy/discrete_history_op_flags",
+                "privacy/discrete_history_ops_cslist",
+                "privacy/discrete_history_quantization_millis",
                 "privacy/location_access_check_delay_millis",
                 "privacy/location_access_check_periodic_interval_millis",
                 "privacy/location_indicators_enabled",
@@ -1467,48 +1408,93 @@ final class WritableFlags {
                 "privacy/max_safety_labels_persisted_per_app",
                 "privacy/mic_toggle_enabled",
                 "privacy/notification_listener_check_enabled",
-                "privacy/param",
-                "privacy/param",
-                "privacy/param",
+                "privacy/notification_listener_check_interval_millis",
                 "privacy/param",
                 "privacy/permission_rationale_enabled",
                 "privacy/permissions_hub_subattribution_enabled",
+                "privacy/photo_picker_prompt_enabled",
                 "privacy/placeholder_safety_label_updates_enabled",
                 "privacy/privacy_attribution_tag_full_log_enabled",
                 "privacy/privacy_dashboard_7_day_toggle",
                 "privacy/privacy_hub_enabled",
                 "privacy/privacy_placeholder_safety_label_data_enabled",
+                "privacy/safety_center_actions_to_override_with_default_intent",
+                "privacy/safety_center_additional_allow_package_certs",
+                "privacy/safety_center_allow_statsd_logging",
                 "privacy/safety_center_background_refresh_denied_sources",
                 "privacy/safety_center_background_refresh_is_enabled",
                 "privacy/safety_center_background_requires_charging",
+                "privacy/safety_center_hide_resolved_ui_transition_delay_millis",
                 "privacy/safety_center_is_enabled",
                 "privacy/safety_center_issue_category_allowlists",
+                "privacy/safety_center_notification_resurface_interval",
                 "privacy/safety_center_notifications_allowed_sources",
                 "privacy/safety_center_notifications_enabled",
                 "privacy/safety_center_notifications_immediate_behavior_issues",
                 "privacy/safety_center_notifications_min_delay",
                 "privacy/safety_center_override_refresh_on_page_open_sources",
                 "privacy/safety_center_periodic_background_interval_millis",
+                "privacy/safety_center_qs_tile_component_setting_flags",
                 "privacy/safety_center_refresh_fgs_allowlist_duration_millis",
                 "privacy/safety_center_refresh_sources_timeouts_millis",
+                "privacy/safety_center_replace_lock_screen_icon_action",
                 "privacy/safety_center_resolve_action_timeout_millis",
                 "privacy/safety_center_resurface_issue_delays_millis",
                 "privacy/safety_center_resurface_issue_max_counts",
                 "privacy/safety_center_show_subpages",
+                "privacy/safety_center_temp_hidden_issue_resurface_delay_millis",
                 "privacy/safety_center_untracked_sources",
-                "privacy/safety_protection_enabled",
                 "privacy/safety_label_change_notifications_enabled",
                 "privacy/safety_label_changes_job_interval_millis",
+                "privacy/safety_protection_enabled",
+                "privacy/sc_accessibility_job_interval_millis",
                 "privacy/sc_accessibility_listener_enabled",
                 "profcollect_native_boot/enable",
+                "profiling/cost_heap_profile",
+                "profiling/cost_java_heap_dump",
+                "profiling/cost_stack_sampling",
+                "profiling/cost_system_trace",
+                "profiling/heap_profile_duration_ms_default",
+                "profiling/heap_profile_duration_ms_max",
+                "profiling/heap_profile_duration_ms_min",
+                "profiling/java_heap_dump_data_source_stop_timeout_ms_default",
+                "profiling/java_heap_dump_duration_ms_default",
+                "profiling/killswitch_heap_profile",
+                "profiling/killswitch_java_heap_dump",
+                "profiling/killswitch_stack_sampling",
+                "profiling/killswitch_system_trace",
+                "profiling/max_cost_process_1_hour",
+                "profiling/max_cost_process_24_hour",
+                "profiling/max_cost_process_7_day",
+                "profiling/max_cost_system_1_hour",
+                "profiling/max_cost_system_24_hour",
+                "profiling/max_cost_system_7_day",
+                "profiling/max_result_redelivery_count",
+                "profiling/persist_queue_to_disk_frequency_ms",
+                "profiling/persist_to_disk_frequency_ms",
+                "profiling/stack_sampling_duration_ms_default",
+                "profiling/stack_sampling_duration_ms_max",
+                "profiling/stack_sampling_duration_ms_min",
+                "profiling/system_trace_duration_ms_default",
+                "profiling/system_trace_duration_ms_max",
+                "profiling/system_trace_duration_ms_min",
+                "profiling_testing/rate_limiter.disabled",
+                "reboot_readiness/active_polling_interval_ms",
+                "reboot_readiness/alarm_clock_threshold_ms",
+                "reboot_readiness/disable_app_activity_check",
+                "reboot_readiness/disable_interactivity_check",
+                "reboot_readiness/disable_subsystems_check",
+                "reboot_readiness/interactivity_threshold_ms",
+                "reboot_readiness/logging_blocking_entity_threshold_ms",
                 "remote_key_provisioning_native/enable_rkpd",
+                "repair_mode/userdata_size_gb",
+                "rollback_boot/rollback_lifetime_in_millis",
                 "rollback/containing",
                 "rollback/enable_rollback_timeout",
                 "rollback/watchdog_explicit_health_check_enabled",
                 "rollback/watchdog_request_timeout_millis",
                 "rollback/watchdog_trigger_failure_count",
                 "rollback/watchdog_trigger_failure_duration_millis",
-                "rollback_boot/rollback_lifetime_in_millis",
                 "rotation_resolver/service_enabled",
                 "runtime_native_boot/blacklisted_packages",
                 "runtime_native_boot/disable_lock_profiling",
@@ -1538,18 +1524,12 @@ final class WritableFlags {
                 "runtime_native/usap_pool_size_min",
                 "runtime_native/use_app_image_startup_cache",
                 "settings_stats/boolean_whitelist",
-                "settings_stats/boolean_whitelist",
-                "settings_stats/boolean_whitelist",
-                "settings_stats/float_whitelist",
                 "settings_stats/float_whitelist",
-                "settings_stats/float_whitelist",
-                "settings_stats/integer_whitelist",
-                "settings_stats/integer_whitelist",
+                "settings_stats/GlobalFeature__integer_whitelist",
                 "settings_stats/integer_whitelist",
                 "settings_stats/string_whitelist",
-                "settings_stats/string_whitelist",
-                "settings_stats/string_whitelist",
                 "statsd_java/include_certificate_hash",
+                "statsd_java/use_file_descriptor",
                 "statsd_native/app_upgrade_bucket_split",
                 "statsd_native_boot/aggregate_atoms",
                 "statsd_native_boot/enable_restricted_metrics",
@@ -1560,6 +1540,8 @@ final class WritableFlags {
                 "storage_native_boot/allowed_cloud_providers",
                 "storage_native_boot/anr_delay_millis",
                 "storage_native_boot/anr_delay_notify_external_storage_service",
+                "storage_native_boot/cache_reserve_percent_high",
+                "storage_native_boot/cache_reserve_percent_low",
                 "storage_native_boot/charging_required",
                 "storage_native_boot/cloud_media_enforce_provider_allowlist",
                 "storage_native_boot/cloud_media_feature_enabled",
@@ -1582,12 +1564,12 @@ final class WritableFlags {
                 "storage_native_boot/transcode_compat_stale",
                 "storage_native_boot/transcode_default",
                 "storage_native_boot/transcode_enabled",
+                "storage/pickerdb.default_sync_delay_ms",
                 "surface_flinger_native_boot/adpf_cpu_hint",
                 "surface_flinger_native_boot/demo_flag",
                 "surface_flinger_native_boot/max_frame_buffer_acquired_buffers",
                 "surface_flinger_native_boot/use_skia_tracing",
                 "system_scheduler/dummy_flag",
-                "system_scheduler/dummy_flag",
                 "system_scheduler/enable_fast_metrics_collection",
                 "system_scheduler/location_mode",
                 "system_time/enhanced_metrics_collection_enabled",
@@ -1605,6 +1587,7 @@ final class WritableFlags {
                 "system_time/time_detector_origin_priorities_override",
                 "system_time/time_zone_detector_auto_detection_enabled_default",
                 "system_time/time_zone_detector_telephony_fallback_supported",
+                "systemui/android.app.visit_person_uri",
                 "systemui/apply_sharing_app_limits_in_sysui",
                 "systemui/back_gesture_ml_name",
                 "systemui/back_gesture_ml_threshold",
@@ -1613,8 +1596,6 @@ final class WritableFlags {
                 "systemui/duration_per_px_fast",
                 "systemui/duration_per_px_regular",
                 "systemui/enabled",
-                "systemui/enabled",
-                "systemui/enabled",
                 "systemui/enable_notification_memory_monitoring",
                 "systemui/enable_screenshot_corner_flow",
                 "systemui/enable_screenshot_notification_smart_actions",
@@ -1622,6 +1603,8 @@ final class WritableFlags {
                 "systemui/exp_flag_release",
                 "systemui/fade_in_duration",
                 "systemui/generate_actions",
+                "systemui/generated_preview_api_max_calls_per_interval",
+                "systemui/generated_preview_api_reset_interval_ms",
                 "systemui/generate_replies",
                 "systemui/is_nearby_share_first_target_in_ranked_app",
                 "systemui/learn_count",
@@ -1634,6 +1617,10 @@ final class WritableFlags {
                 "systemui/max_total_duration",
                 "systemui/min_num_sys_gen_replies",
                 "systemui/min_total_duration",
+                "systemui/nas_generate_actions",
+                "systemui/nas_generate_replies",
+                "systemui/nas_max_messages_to_extract",
+                "systemui/nas_max_suggestions",
                 "systemui/predict_using_people_service_share",
                 "systemui/replies_require_targeting_p",
                 "systemui/scanner_activity_name",
@@ -1665,36 +1652,33 @@ final class WritableFlags {
                 "telephony/anomaly_setup_data_call_failure",
                 "telephony/auto_data_switch_availability_stability_time_threshold",
                 "telephony/auto_data_switch_validation_max_retry",
+                "telephony/enable_logcat_collection_for_emergency_call_diagnostics",
                 "telephony/enable_new_data_stack",
                 "telephony/enable_slicing_upsell",
                 "telephony/enable_subscription_manager_service",
+                "telephony/enable_telecom_dump_collection_for_emergency_call_diagnostics",
+                "telephony/enable_telephony_dump_collection_for_emergency_call_diagnostics",
                 "telephony/enable_work_profile_telephony",
                 "telephony/erase_modem_config",
                 "telephony/is_telephony_anomaly_report_enabled",
                 "telephony/ramping_ringer_duration",
                 "telephony/ramping_ringer_enabled",
                 "telephony/ramping_ringer_vibration_duration",
-                "testspace/flagname",
+                "test_od_namespace/key1",
                 "testspace/another",
-                "tethering/enable_java_bpf_map",
+                "testspace/flagname",
                 "textclassifier/ar_manifest",
                 "textclassifier/da_manifest",
                 "textclassifier/de_ch_manifest",
                 "textclassifier/de_li_manifest",
                 "textclassifier/de_manifest",
-                "textclassifier/de_manifest",
                 "textclassifier/en_manifest",
-                "textclassifier/en_manifest",
-                "textclassifier/es_manifest",
                 "textclassifier/es_manifest",
                 "textclassifier/fr_manifest",
-                "textclassifier/fr_manifest",
                 "textclassifier/generate_links_max_text_length",
                 "textclassifier/it_manifest",
-                "textclassifier/it_manifest",
-                "textclassifier/ja_manifest",
                 "textclassifier/ja_manifest",
-                "textclassifier/ko_manifest",
+                "textclassifier/key",
                 "textclassifier/ko_manifest",
                 "textclassifier/local_textclassifier_enabled",
                 "textclassifier/manifest_download_max_attempts",
@@ -1713,15 +1697,13 @@ final class WritableFlags {
                 "textclassifier/ru_manifest",
                 "textclassifier/sv_manifest",
                 "textclassifier/system_textclassifier_api_timeout_in_second",
+                "textclassifier/system_textclassifier_enabled",
                 "textclassifier/textclassifier_service_package_override",
                 "textclassifier/th_manifest",
                 "textclassifier/tr_manifest",
                 "textclassifier/universal_manifest",
-                "textclassifier/universal_manifest",
-                "textclassifier/universal_manifest",
                 "textclassifier/zh_hant_manifest",
                 "textclassifier/zh_manifest",
-                "textclassifier/zh_manifest",
                 "tv_hdr_output_control/enable_hdr_output_control",
                 "uwb/device_error_bugreport_enabled",
                 "vendor_system_native/background_cpuset",
@@ -1730,10 +1712,11 @@ final class WritableFlags {
                 "vendor_system_native/foreground_cpuset",
                 "vendor_system_native/restricted_cpuset",
                 "virtualization_framework_native/isolated_compilation_enabled",
+                "voice_interaction/restart_period_in_seconds",
                 "vpn/enable_pixel_ppn_feature",
                 "wallpaper_content/enabled",
-                "wearable_sensing/service_enabled_platforms",
                 "wearable_sensing/service_enabled",
+                "wearable_sensing/service_enabled_platforms",
                 "wear/ambient_auto_resume_timeout_max_reset_count",
                 "wear/bedtime_hard_mode_feature_enabled",
                 "wear/enable_backup_service_in_wear_framework",
@@ -1787,6 +1770,7 @@ final class WritableFlags {
                 "wifi/software_pno_enabled",
                 "wifi/stationary_scan_rssi_valid_time_ms",
                 "wifi/wfd_failure_bugreport_enabled",
+                "window_manager/ActivitySecurity__asm_restrictions_enabled",
                 "window_manager/asm_exempted_packages",
                 "window_manager/asm_restrictions_enabled",
                 "window_manager/asm_toasts_enabled",
@@ -1807,6 +1791,7 @@ final class WritableFlags {
                 "window_manager/rotation_resolver_timeout_millis",
                 "window_manager/screen_record_enterprise_policies",
                 "window_manager/single_use_token",
-                "window_manager/splash_screen_exception_list"
+                "window_manager/splash_screen_exception_list",
+                "wrong/nas_generate_replies"
             ));
 }
diff --git a/framework/java/android/provider/WritableNamespaces.java b/framework/java/android/provider/WritableNamespaces.java
new file mode 100644
index 0000000..e3ea00b
--- /dev/null
+++ b/framework/java/android/provider/WritableNamespaces.java
@@ -0,0 +1,51 @@
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
+package android.provider;
+
+import android.ravenwood.annotation.RavenwoodKeepWholeClass;
+import android.util.ArraySet;
+
+import java.util.Arrays;
+import java.util.Set;
+
+/**
+ * Contains the list of namespaces in which any flag can be written by adb without root
+ * permissions.
+ * <p>
+ * A security review is required for any namespace that's added to this list. To add to
+ * the list, create a change and tag the OWNER. In the commit message, include a
+ * description of the flag's functionality, and a justification for why it needs to be
+ * allowlisted.
+ * @hide
+ */
+@RavenwoodKeepWholeClass
+final class WritableNamespaces {
+    public static final Set<String> ALLOWLIST =
+            new ArraySet<String>(Arrays.asList(
+                    "adservices",
+                    "captive_portal_login",
+                    "connectivity",
+                    "exo",
+                    "nearby",
+                    "netd_native",
+                    "network_security",
+                    "on_device_personalization",
+                    "tethering",
+                    "tethering_u_or_later_native",
+                    "thread_network"
+            ));
+}
diff --git a/framework/tests/Android.bp b/framework/tests/Android.bp
new file mode 100644
index 0000000..77bbfdd
--- /dev/null
+++ b/framework/tests/Android.bp
@@ -0,0 +1,36 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "AconfigPackageTests",
+    srcs: ["src/**/*.java"],
+    static_libs: [
+        "aconfig_device_paths_java",
+        "androidx.test.rules",
+        "aconfig_storage_file_java",
+        "junit",
+    ],
+    libs: [
+        "framework-configinfrastructure.impl"
+    ],
+    sdk_version: "module_current",
+    test_suites: [
+        "general-tests",
+    ],
+    team: "trendy_team_android_core_experiments",
+}
diff --git a/framework/tests/AndroidManifest.xml b/framework/tests/AndroidManifest.xml
new file mode 100644
index 0000000..33d226f
--- /dev/null
+++ b/framework/tests/AndroidManifest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.os.flagging.test">
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="android.os.flagging.test" />
+
+</manifest>
diff --git a/framework/tests/src/AconfigPackageInternalTests.java b/framework/tests/src/AconfigPackageInternalTests.java
new file mode 100644
index 0000000..e6a8db8
--- /dev/null
+++ b/framework/tests/src/AconfigPackageInternalTests.java
@@ -0,0 +1,120 @@
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
+package android.os.flagging.test;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.aconfig.DeviceProtos;
+import android.aconfig.nano.Aconfig;
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.os.flagging.AconfigPackageInternal;
+import android.os.flagging.AconfigStorageReadException;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.IOException;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+
+@RunWith(JUnit4.class)
+public class AconfigPackageInternalTests {
+    @Test
+    public void testAconfigPackageInternal_load() throws IOException {
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        Map<String, AconfigPackageInternal> readerMap = new HashMap<>();
+        StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
+
+        for (parsed_flag flag : flags) {
+            if (flag.permission == Aconfig.READ_ONLY && flag.state == Aconfig.DISABLED) {
+                continue;
+            }
+            String container = flag.container;
+            String packageName = flag.package_;
+            String flagName = flag.name;
+
+            PackageTable pTable = fp.getPackageTable(container);
+            PackageTable.Node pNode = pTable.get(packageName);
+            FlagTable fTable = fp.getFlagTable(container);
+            FlagTable.Node fNode = fTable.get(pNode.getPackageId(), flagName);
+            FlagValueList fList = fp.getFlagValueList(container);
+
+            int index = pNode.getBooleanStartIndex() + fNode.getFlagIndex();
+            boolean rVal = fList.getBoolean(index);
+
+            long fingerprint = pNode.getPackageFingerprint();
+
+            AconfigPackageInternal reader = readerMap.get(packageName);
+            if (reader == null) {
+                reader = AconfigPackageInternal.load(container, packageName, fingerprint);
+                readerMap.put(packageName, reader);
+            }
+            boolean jVal = reader.getBooleanFlagValue(fNode.getFlagIndex());
+
+            assertEquals(rVal, jVal);
+        }
+    }
+
+    @Test
+    public void testAconfigPackage_load_withError() throws IOException {
+        // container not found fake_container
+        AconfigStorageReadException e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () -> AconfigPackageInternal.load("fake_container", "fake_package", 0));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+
+        // package not found
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () -> AconfigPackageInternal.load("system", "fake_container", 0));
+        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+
+        // fingerprint doesn't match
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
+
+        parsed_flag flag = flags.get(0);
+
+        String container = flag.container;
+        String packageName = flag.package_;
+        boolean value = flag.state == Aconfig.ENABLED;
+
+        PackageTable pTable = fp.getPackageTable(container);
+        PackageTable.Node pNode = pTable.get(packageName);
+        if (pNode.hasPackageFingerprint()) {
+            long fingerprint = pNode.getPackageFingerprint();
+            e =
+                    assertThrows(
+                            AconfigStorageReadException.class,
+                            () ->
+                                    AconfigPackageInternal.load(
+                                            container, packageName, fingerprint + 1));
+            assertEquals(
+                    // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    5, e.getErrorCode());
+        }
+    }
+}
diff --git a/framework/tests/src/AconfigPackageTests.java b/framework/tests/src/AconfigPackageTests.java
new file mode 100644
index 0000000..99243d2
--- /dev/null
+++ b/framework/tests/src/AconfigPackageTests.java
@@ -0,0 +1,84 @@
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
+package android.os.flagging.test;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.aconfig.DeviceProtos;
+import android.aconfig.nano.Aconfig;
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.os.flagging.AconfigPackage;
+import android.os.flagging.AconfigStorageReadException;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.IOException;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+
+@RunWith(JUnit4.class)
+public class AconfigPackageTests {
+    @Test
+    public void testExternalAconfigPackageInstance() throws IOException {
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        Map<String, AconfigPackage> readerMap = new HashMap<>();
+        StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
+
+        for (parsed_flag flag : flags) {
+            if (flag.permission == Aconfig.READ_ONLY && flag.state == Aconfig.DISABLED) {
+                continue;
+            }
+            String container = flag.container;
+            String packageName = flag.package_;
+            String flagName = flag.name;
+
+            PackageTable pTable = fp.getPackageTable(container);
+            PackageTable.Node pNode = pTable.get(packageName);
+            FlagTable fTable = fp.getFlagTable(container);
+            FlagTable.Node fNode = fTable.get(pNode.getPackageId(), flagName);
+            FlagValueList fList = fp.getFlagValueList(container);
+            boolean rVal = fList.getBoolean(pNode.getBooleanStartIndex() + fNode.getFlagIndex());
+
+            AconfigPackage reader = readerMap.get(packageName);
+            if (reader == null) {
+                reader = AconfigPackage.load(packageName);
+                readerMap.put(packageName, reader);
+            }
+            boolean jVal = reader.getBooleanFlagValue(flagName, false);
+
+            assertEquals(rVal, jVal);
+        }
+    }
+
+    @Test
+    public void testAconfigPackage_load_withError() {
+        // load fake package
+        AconfigStorageReadException e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () -> AconfigPackage.load("fake_package"));
+        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+    }
+}
diff --git a/service/ServiceResources/Android.bp b/service/ServiceResources/Android.bp
index cd2dcc8..0a9080c 100644
--- a/service/ServiceResources/Android.bp
+++ b/service/ServiceResources/Android.bp
@@ -33,4 +33,5 @@ android_app {
     apex_available: [
         "com.android.configinfrastructure",
     ],
+    updatable: true,
 }
diff --git a/service/javatests/src/com/android/server/deviceconfig/DeviceConfigBootstrapValuesTest.java b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigBootstrapValuesTest.java
index 9d77e8c..b804ad0 100644
--- a/service/javatests/src/com/android/server/deviceconfig/DeviceConfigBootstrapValuesTest.java
+++ b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigBootstrapValuesTest.java
@@ -40,6 +40,9 @@ public class DeviceConfigBootstrapValuesTest {
     private static final String WRITE_DEVICE_CONFIG_PERMISSION =
             "android.permission.WRITE_DEVICE_CONFIG";
 
+    private static final String WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION =
+            "android.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG";
+
     private static final String READ_DEVICE_CONFIG_PERMISSION =
             "android.permission.READ_DEVICE_CONFIG";
 
@@ -49,7 +52,8 @@ public class DeviceConfigBootstrapValuesTest {
     public void assertParsesFiles() throws IOException {
         assumeTrue(SdkLevel.isAtLeastV());
         InstrumentationRegistry.getInstrumentation().getUiAutomation().adoptShellPermissionIdentity(
-                WRITE_DEVICE_CONFIG_PERMISSION, READ_DEVICE_CONFIG_PERMISSION);
+                WRITE_DEVICE_CONFIG_PERMISSION, WRITE_ALLOWLISTED_DEVICE_CONFIG_PERMISSION,
+                READ_DEVICE_CONFIG_PERMISSION);
 
         DeviceConfigBootstrapValues values = new DeviceConfigBootstrapValues(PATH_1);
         values.applyValuesIfNeeded();
diff --git a/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java
index a32e131..1956c79 100644
--- a/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java
+++ b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java
@@ -15,6 +15,9 @@
  */
 package com.android.server.deviceconfig;
 
+import static org.junit.Assert.assertThrows;
+
+import android.os.ParcelFileDescriptor;
 import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.DeviceFlagsValueProvider;
@@ -41,11 +44,21 @@ public final class DeviceConfigTest {
     private static final String NAMESPACE_B = "B Space has no name";
 
     private static final String DUMP_PREFIX = "..";
+    private static final String[] DUMP_NO_ARGS = null;
 
     @Rule public final Expect expect = Expect.create();
     @Rule public final CheckFlagsRule checkFlagsRule =
             DeviceFlagsValueProvider.createCheckFlagsRule();
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_DUMP_IMPROVEMENTS)
+    public void testDump_nullPrintWriter() throws Exception {
+        try (ParcelFileDescriptor fd = ParcelFileDescriptor.createPipe()[0]) {
+            assertThrows(NullPointerException.class, () ->
+                    DeviceConfig.dump(/* printWriter= */ null, DUMP_PREFIX, DUMP_NO_ARGS));
+        }
+    }
+
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_DUMP_IMPROVEMENTS)
     public void testDump_empty() throws Exception {
@@ -90,7 +103,7 @@ public final class DeviceConfigTest {
         try (StringWriter sw = new StringWriter()) {
             PrintWriter pw = new PrintWriter(sw);
 
-            DeviceConfig.dump(/* fd= */ null, pw, DUMP_PREFIX, args);
+            DeviceConfig.dump(pw, DUMP_PREFIX, args);
 
             pw.flush();
             String dump = sw.toString();
```

