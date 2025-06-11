```diff
diff --git a/OWNERS b/OWNERS
index d0007bd..17b3ab2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,5 @@
 # Bug component: 326016
 dzshen@google.com
+marybethfair@google.com
 opg@google.com
-tedbauer@google.com
 zhidou@google.com
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 9600834..73fd8d8 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -5,6 +5,9 @@
     },
     {
       "name": "AconfigPackageTests"
+    },
+    {
+      "name": "AconfigPublicApiCtsTests"
     }
   ]
 }
\ No newline at end of file
diff --git a/aconfigd/Android.bp b/aconfigd/Android.bp
index e92f7ac..4ec8eee 100644
--- a/aconfigd/Android.bp
+++ b/aconfigd/Android.bp
@@ -17,12 +17,14 @@ rust_defaults {
     edition: "2021",
     lints: "none",
     rustlibs: [
+        "libaconfig_new_storage_flags_rust",
         "libaconfig_storage_file",
         "libaconfig_storage_read_api",
         "libaconfig_storage_write_api",
         "libaconfigd_protos_rust",
         "libanyhow",
         "libclap",
+        "libconfiginfra_framework_flags_rust",
         "libmemmap2",
         "libopenssl",
         "liblog_rust",
@@ -54,6 +56,10 @@ rust_binary {
         "liblibc",
         "libaconfig_new_storage_flags_rust",
     ],
+    cfgs: select(release_flag("RELEASE_ENABLE_MAINLINE_ACONFIGD_SOCKET"), {
+        true: ["enable_mainline_aconfigd_socket"],
+        default: [],
+    }),
 }
 
 rust_test {
@@ -61,6 +67,7 @@ rust_test {
     team: "trendy_team_android_core_experiments",
     test_suites: [
         "general-tests",
+        "mts-configinfrastructure",
     ],
     defaults: ["aconfigd_rust.defaults"],
     srcs: ["src/lib.rs"],
@@ -79,3 +86,14 @@ rust_test {
     ],
     require_root: true
 }
+
+rust_aconfig_library {
+    name: "libconfiginfra_framework_flags_rust",
+    crate_name: "configinfra_framework_flags_rust",
+    aconfig_declarations: "configinfra_framework_flags",
+    apex_available: [
+        "com.android.configinfrastructure",
+        "//apex_available:platform",
+    ],
+    min_sdk_version: "34",
+}
diff --git a/aconfigd/proto/Android.bp b/aconfigd/proto/Android.bp
index 61c3b20..2761652 100644
--- a/aconfigd/proto/Android.bp
+++ b/aconfigd/proto/Android.bp
@@ -84,12 +84,26 @@ java_library {
     proto: {
         type: "stream",
     },
-    sdk_version: "current",
+    sdk_version: "core_current",
+    min_sdk_version: "UpsideDownCake",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
+
+java_library {
+    name: "aconfigd_java_proto_lib_repackaged",
+    sdk_version: "core_current",
+    static_libs: [
+        "aconfigd_java_proto_lib",
+    ],
     min_sdk_version: "UpsideDownCake",
     apex_available: [
         "//apex_available:anyapex",
         "//apex_available:platform",
     ],
+    jarjar_rules: "repackage-aconfigd-proto-stream.txt",
 }
 
 java_library {
diff --git a/aconfigd/proto/aconfigd.proto b/aconfigd/proto/aconfigd.proto
index 2a7c9fc..26f84e1 100644
--- a/aconfigd/proto/aconfigd.proto
+++ b/aconfigd/proto/aconfigd.proto
@@ -170,4 +170,4 @@ message StorageReturnMessage {
 
 message StorageReturnMessages {
   repeated StorageReturnMessage msgs = 1;
-}
+}
\ No newline at end of file
diff --git a/aconfigd/proto/repackage-aconfigd-proto-stream.txt b/aconfigd/proto/repackage-aconfigd-proto-stream.txt
new file mode 100644
index 0000000..76ee79f
--- /dev/null
+++ b/aconfigd/proto/repackage-aconfigd-proto-stream.txt
@@ -0,0 +1,2 @@
+rule android.aconfigd.Aconfigd android.internal.configinfra.aconfigd.x.Aconfigd
+rule android.aconfigd.Aconfigd$* android.internal.configinfra.aconfigd.x.Aconfigd$@1
diff --git a/aconfigd/proto/src/lib.rs b/aconfigd/proto/src/lib.rs
index b4a6155..db278b6 100644
--- a/aconfigd/proto/src/lib.rs
+++ b/aconfigd/proto/src/lib.rs
@@ -32,13 +32,14 @@
 mod auto_generated {
     pub use aconfigd_rust_proto::aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
     pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
-    pub use aconfigd_rust_proto::aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
     pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
     pub use aconfigd_rust_proto::aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
     pub use aconfigd_rust_proto::aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
+    pub use aconfigd_rust_proto::aconfigd::storage_request_message::RemoveOverrideType as ProtoRemoveOverrideType;
     pub use aconfigd_rust_proto::aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
     pub use aconfigd_rust_proto::aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
     pub use aconfigd_rust_proto::aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
@@ -55,19 +56,20 @@ mod auto_generated {
 // ---- When building with cargo ----
 #[cfg(feature = "cargo")]
 mod auto_generated {
-    // include! statements should be avoided (because they import file contents verbatim), but
-    // because this is only used during local development, and only if using cargo instead of the
-    // Android tool-chain, we allow it
+    // include! statements should be avoided (because they import file contents
+    // verbatim), but because this is only used during local development, and
+    // only if using cargo instead of the Android tool-chain, we allow it
     include!(concat!(env!("OUT_DIR"), "/aconfigd_proto/mod.rs"));
     pub use aconfigd::storage_request_message::list_storage_message::Msg as ProtoListStorageMessageMsg;
     pub use aconfigd::storage_request_message::FlagOverrideMessage as ProtoFlagOverrideMessage;
-    pub use aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
-    pub use aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
-    pub use aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
-    pub use aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
     pub use aconfigd::storage_request_message::FlagOverrideType as ProtoFlagOverrideType;
+    pub use aconfigd::storage_request_message::FlagQueryMessage as ProtoFlagQueryMessage;
     pub use aconfigd::storage_request_message::ListStorageMessage as ProtoListStorageMessage;
     pub use aconfigd::storage_request_message::Msg as ProtoStorageRequestMessageMsg;
+    pub use aconfigd::storage_request_message::NewStorageMessage as ProtoNewStorageMessage;
+    pub use aconfigd::storage_request_message::OTAFlagStagingMessage as ProtoOTAFlagStagingMessage;
+    pub use aconfigd::storage_request_message::RemoveLocalOverrideMessage as ProtoRemoveLocalOverrideMessage;
+    pub use aconfigd::storage_request_message::RemoveOverrideType as ProtoRemoveOverrideType;
     pub use aconfigd::storage_return_message::FlagQueryReturnMessage as ProtoFlagQueryReturnMessage;
     pub use aconfigd::storage_return_message::ListStorageReturnMessage as ProtoListStorageReturnMessage;
     pub use aconfigd::storage_return_message::Msg as ProtoStorageReturnMessageMsg;
diff --git a/aconfigd/src/aconfigd.rs b/aconfigd/src/aconfigd.rs
index 45105fd..a6177b3 100644
--- a/aconfigd/src/aconfigd.rs
+++ b/aconfigd/src/aconfigd.rs
@@ -29,7 +29,8 @@ use std::io::{Read, Write};
 use std::os::unix::net::UnixStream;
 use std::path::{Path, PathBuf};
 
-// Aconfigd that is capable of doing both one shot storage file init and socket service
+// Aconfigd that is capable of doing both one shot storage file init and socket
+// service
 #[derive(Debug)]
 pub struct Aconfigd {
     pub root_dir: PathBuf,
@@ -52,6 +53,7 @@ impl Aconfigd {
         let boot_dir = self.root_dir.join("boot");
         let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&self.persist_storage_records)?;
         for entry in pb.records.iter() {
+            debug!("remove boot storage files for container {}", entry.container());
             let boot_value_file = boot_dir.join(entry.container().to_owned() + ".val");
             let boot_info_file = boot_dir.join(entry.container().to_owned() + ".info");
             if boot_value_file.exists() {
@@ -64,6 +66,39 @@ impl Aconfigd {
         Ok(())
     }
 
+    /// Remove non platform boot storage file copies
+    pub fn remove_non_platform_boot_files(&mut self) -> Result<(), AconfigdError> {
+        let boot_dir = self.root_dir.join("boot");
+        for entry in std::fs::read_dir(&boot_dir)
+            .map_err(|errmsg| AconfigdError::FailToReadBootDir { errmsg })?
+        {
+            match entry {
+                Ok(entry) => {
+                    let path = entry.path();
+                    if !path.is_file() {
+                        continue;
+                    }
+                    if let Some(base_name) = path.file_name() {
+                        if let Some(file_name) = base_name.to_str() {
+                            if file_name.starts_with("system")
+                                || file_name.starts_with("system_ext")
+                                || file_name.starts_with("product")
+                                || file_name.starts_with("vendor")
+                            {
+                                continue;
+                            }
+                            remove_file(&path);
+                        }
+                    }
+                }
+                Err(errmsg) => {
+                    warn!("failed to visit entry: {}", errmsg);
+                }
+            }
+        }
+        Ok(())
+    }
+
     /// Initialize aconfigd from persist storage records
     pub fn initialize_from_storage_record(&mut self) -> Result<(), AconfigdError> {
         let boot_dir = self.root_dir.join("boot");
@@ -74,10 +109,13 @@ impl Aconfigd {
         Ok(())
     }
 
-    /// Initialize platform storage files, create or update existing persist storage files and
-    /// create new boot storage files for each platform partitions
+    /// Initialize platform storage files, create or update existing persist
+    /// storage files and create new boot storage files for each platform
+    /// partitions
     pub fn initialize_platform_storage(&mut self) -> Result<(), AconfigdError> {
-        for container in ["system", "product", "vendor"] {
+        for container in ["system", "system_ext", "product", "vendor"] {
+            debug!("start initialize {} flags", container);
+
             let aconfig_dir = PathBuf::from("/".to_string() + container + "/etc/aconfig");
             let default_package_map = aconfig_dir.join("package.map");
             let default_flag_map = aconfig_dir.join("flag.map");
@@ -119,15 +157,16 @@ impl Aconfigd {
 
         self.storage_manager.apply_staged_ota_flags()?;
 
-        for container in ["system", "product", "vendor"] {
+        for container in ["system", "system_ext", "product", "vendor"] {
             self.storage_manager.apply_all_staged_overrides(container)?;
         }
 
         Ok(())
     }
 
-    /// Initialize mainline storage files, create or update existing persist storage files and
-    /// create new boot storage files for each mainline container
+    /// Initialize mainline storage files, create or update existing persist
+    /// storage files and create new boot storage files for each mainline
+    /// container
     pub fn initialize_mainline_storage(&mut self) -> Result<(), AconfigdError> {
         // get all the apex dirs to visit
         let mut dirs_to_visit = Vec::new();
@@ -164,6 +203,7 @@ impl Aconfigd {
 
         // initialize each container
         for container in dirs_to_visit.iter() {
+            debug!("start initialize {} flags", container);
             let etc_dir = apex_dir.join(container).join("etc");
             let default_package_map = etc_dir.join("package.map");
             let default_flag_map = etc_dir.join("flag.map");
@@ -228,7 +268,41 @@ impl Aconfigd {
         request_pb: &ProtoOTAFlagStagingMessage,
     ) -> Result<ProtoStorageReturnMessage, AconfigdError> {
         let ota_flags_pb_file = self.root_dir.join("flags").join("ota.pb");
-        write_pb_to_file::<ProtoOTAFlagStagingMessage>(request_pb, &ota_flags_pb_file)?;
+
+        let mut existing_ota_flags =
+            read_pb_from_file::<ProtoOTAFlagStagingMessage>(&ota_flags_pb_file)
+                .unwrap_or_else(|_| ProtoOTAFlagStagingMessage::new());
+
+        if request_pb.has_build_id()
+            && existing_ota_flags.has_build_id()
+            && request_pb.build_id() == existing_ota_flags.build_id()
+        {
+            let mut merged_flags = existing_ota_flags.overrides.to_vec();
+            merged_flags.extend(request_pb.overrides.clone());
+
+            let mut seen_flags = std::collections::HashSet::new();
+            let mut new_flags = Vec::new();
+
+            for flag in merged_flags {
+                let flag = flag.clone();
+                let package_name = flag.package_name().to_string();
+                let flag_name = flag.flag_name().to_string();
+                let key = (package_name, flag_name);
+                if seen_flags.insert(key) {
+                    new_flags.push(flag);
+                }
+            }
+            merged_flags = new_flags;
+            existing_ota_flags.overrides = merged_flags.into();
+
+            write_pb_to_file::<ProtoOTAFlagStagingMessage>(
+                &existing_ota_flags,
+                &ota_flags_pb_file,
+            )?;
+        } else {
+            write_pb_to_file::<ProtoOTAFlagStagingMessage>(request_pb, &ota_flags_pb_file)?;
+        }
+
         let mut return_pb = ProtoStorageReturnMessage::new();
         return_pb.mut_ota_staging_message();
         Ok(return_pb)
@@ -294,8 +368,11 @@ impl Aconfigd {
         if request_pb.remove_all() {
             self.storage_manager.remove_all_local_overrides()?;
         } else {
-            self.storage_manager
-                .remove_local_override(request_pb.package_name(), request_pb.flag_name())?;
+            self.storage_manager.remove_local_override(
+                request_pb.package_name(),
+                request_pb.flag_name(),
+                request_pb.remove_override_type(),
+            )?;
         }
         let mut return_pb = ProtoStorageReturnMessage::new();
         return_pb.mut_remove_local_override_message();
@@ -343,6 +420,7 @@ impl Aconfigd {
                 snapshot.set_is_readwrite(f.is_readwrite);
                 snapshot.set_has_server_override(f.has_server_override);
                 snapshot.set_has_local_override(f.has_local_override);
+                snapshot.set_has_boot_local_override(f.has_boot_local_override);
                 snapshot
             })
             .collect();
@@ -1050,7 +1128,7 @@ mod tests {
             .unwrap();
         assert_eq!(pb.records.len(), 3);
 
-        for container in ["system", "product", "vendor"] {
+        for container in ["system", "system_ext", "product", "vendor"] {
             let aconfig_dir = PathBuf::from("/".to_string() + container + "/etc/aconfig");
             let default_package_map = aconfig_dir.join("package.map");
             let default_flag_map = aconfig_dir.join("flag.map");
diff --git a/aconfigd/src/aconfigd_commands.rs b/aconfigd/src/aconfigd_commands.rs
index 9633a44..3b8f92d 100644
--- a/aconfigd/src/aconfigd_commands.rs
+++ b/aconfigd/src/aconfigd_commands.rs
@@ -62,6 +62,19 @@ pub fn start_socket() -> Result<()> {
 pub fn init() -> Result<()> {
     let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(STORAGE_RECORDS));
     aconfigd.remove_boot_files()?;
+
+    // One time clean up to remove the boot value and info file for mainline modules
+    // that are not in the pb records file. For those mainline modules already in the
+    // records pb file, the above code should remove their boot copy already. Here
+    // we add additional enforcement to ensure that we clear up all mainline boot
+    // copies, regardless if a mainline module is in records or not.
+    // NOTE: this is a one time operation to be removed once the flag is finalized.
+    // as we will add the second change that block boot copy from inactive container
+    // to be generated in the first place.
+    if aconfig_new_storage_flags::bluetooth_flag_value_bug_fix() {
+        aconfigd.remove_non_platform_boot_files()?
+    }
+
     aconfigd.initialize_from_storage_record()?;
     aconfigd.initialize_mainline_storage()?;
     Ok(())
diff --git a/aconfigd/src/lib.rs b/aconfigd/src/lib.rs
index 2bab37f..865ca71 100644
--- a/aconfigd/src/lib.rs
+++ b/aconfigd/src/lib.rs
@@ -131,6 +131,9 @@ pub enum AconfigdError {
     #[error("fail to read /apex dir: {:?}", .errmsg)]
     FailToReadApexDir { errmsg: std::io::Error },
 
+    #[error("fail to read /boot dir: {:?}", .errmsg)]
+    FailToReadBootDir { errmsg: std::io::Error },
+
     #[error("cannot find container for package {}", .package)]
     FailToFindContainer { package: String },
 
diff --git a/aconfigd/src/main.rs b/aconfigd/src/main.rs
index 7d6b06b..783add2 100644
--- a/aconfigd/src/main.rs
+++ b/aconfigd/src/main.rs
@@ -69,7 +69,13 @@ fn main() {
 
     let cli = Cli::parse();
     let command_return = match cli.command {
-        Command::StartSocket => aconfigd_commands::start_socket(),
+        Command::StartSocket => {
+            if cfg!(enable_mainline_aconfigd_socket) {
+                aconfigd_commands::start_socket()
+            } else {
+                Ok(())
+            }
+        }
         Command::Init => aconfigd_commands::init(),
         Command::BootstrapInit => aconfigd_commands::bootstrap_init(),
     };
diff --git a/aconfigd/src/storage_files.rs b/aconfigd/src/storage_files.rs
index 844ad44..81b001e 100644
--- a/aconfigd/src/storage_files.rs
+++ b/aconfigd/src/storage_files.rs
@@ -14,7 +14,10 @@
  * limitations under the License.
  */
 
-use crate::utils::{copy_file, get_files_digest, read_pb_from_file, remove_file, write_pb_to_file};
+use crate::utils::{
+    copy_file, copy_file_without_fsync, get_files_digest, read_pb_from_file, remove_file,
+    write_pb_to_file,
+};
 use crate::AconfigdError;
 use aconfig_storage_file::{
     list_flags, list_flags_with_info, FlagInfoBit, FlagValueSummary, FlagValueType,
@@ -29,6 +32,7 @@ use aconfig_storage_write_api::{
 };
 use aconfigd_protos::{ProtoFlagOverride, ProtoLocalFlagOverrides, ProtoPersistStorageRecord};
 use anyhow::anyhow;
+use log::debug;
 use memmap2::{Mmap, MmapMut};
 use std::collections::HashMap;
 use std::path::{Path, PathBuf};
@@ -118,6 +122,7 @@ pub(crate) struct FlagSnapshot {
     pub is_readwrite: bool,
     pub has_server_override: bool,
     pub has_local_override: bool,
+    pub has_boot_local_override: bool,
 }
 
 impl StorageFiles {
@@ -130,6 +135,7 @@ impl StorageFiles {
         flag_info: &Path,
         root_dir: &Path,
     ) -> Result<Self, AconfigdError> {
+        debug!("create storage files object from container {}", container);
         let version =
             get_storage_file_version(&flag_val.display().to_string()).map_err(|errmsg| {
                 AconfigdError::FailToGetFileVersion { file: flag_val.display().to_string(), errmsg }
@@ -154,6 +160,7 @@ impl StorageFiles {
             digest: get_files_digest(&[package_map, flag_map, flag_val, flag_info][..])?,
         };
 
+        debug!("copy {} storage files to persist and boot directories", container);
         copy_file(package_map, &record.persist_package_map, 0o444)?;
         copy_file(flag_map, &record.persist_flag_map, 0o444)?;
         copy_file(flag_val, &record.persist_flag_val, 0o644)?;
@@ -180,15 +187,12 @@ impl StorageFiles {
         Ok(files)
     }
 
-    pub(crate) fn has_boot_copy(&self) -> bool {
-        self.storage_record.boot_flag_val.exists() && self.storage_record.boot_flag_info.exists()
-    }
-
     /// Constructor from a pb record
     pub(crate) fn from_pb(
         pb: &ProtoPersistStorageRecord,
         root_dir: &Path,
     ) -> Result<Self, AconfigdError> {
+        debug!("create {} storage files object from pb entry", pb.container());
         let record = StorageRecord {
             version: pb.version(),
             container: pb.container().to_string(),
@@ -210,9 +214,6 @@ impl StorageFiles {
             digest: pb.digest().to_string(),
         };
 
-        copy_file(&record.persist_flag_val, &record.boot_flag_val, 0o644)?;
-        copy_file(&record.persist_flag_info, &record.boot_flag_info, 0o644)?;
-
         Ok(Self {
             storage_record: record,
             package_map: None,
@@ -423,6 +424,11 @@ impl StorageFiles {
                 })?;
                 context.flag_index = pkg.boolean_start_index + flg.flag_index as u32;
             }
+        } else {
+            debug!(
+                "failed to find package {} in container {}",
+                package, self.storage_record.container
+            );
         }
 
         Ok(context)
@@ -606,6 +612,11 @@ impl StorageFiles {
         context: &PackageFlagContext,
         value: &str,
     ) -> Result<(), AconfigdError> {
+        debug!(
+            "staging server override for flag {} with value {}",
+            context.package.to_string() + "." + &context.flag,
+            value
+        );
         let attribute = self.get_flag_attribute(context)?;
         if (attribute & FlagInfoBit::IsReadWrite as u8) == 0 {
             return Err(AconfigdError::FlagIsReadOnly {
@@ -628,6 +639,11 @@ impl StorageFiles {
         context: &PackageFlagContext,
         value: &str,
     ) -> Result<(), AconfigdError> {
+        debug!(
+            "staging local override for flag {} with value {}",
+            context.package.to_string() + "." + &context.flag,
+            value
+        );
         let attribute = self.get_flag_attribute(context)?;
         if (attribute & FlagInfoBit::IsReadWrite as u8) == 0 {
             return Err(AconfigdError::FlagIsReadOnly {
@@ -668,6 +684,12 @@ impl StorageFiles {
         value: &str,
     ) -> Result<(), AconfigdError> {
         self.stage_local_override(&context, value)?;
+
+        debug!(
+            "apply local override for flag {} with value {}",
+            context.package.to_string() + "." + &context.flag,
+            value
+        );
         let mut mut_boot_flag_val = self.get_mutable_boot_flag_val()?;
         Self::set_flag_value_to_file(&mut mut_boot_flag_val, &context, value)?;
         let mut mut_boot_flag_info = self.get_mutable_boot_flag_info()?;
@@ -677,6 +699,7 @@ impl StorageFiles {
 
     /// Apply all staged local overrides
     fn apply_staged_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        debug!("apply staged local overrides for container {}", &self.storage_record.container);
         let pb =
             read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
 
@@ -691,12 +714,13 @@ impl StorageFiles {
 
     /// Apply both server and local overrides
     pub(crate) fn apply_all_staged_overrides(&mut self) -> Result<(), AconfigdError> {
-        copy_file(
+        debug!("apply staged server overrides for container {}", &self.storage_record.container);
+        copy_file_without_fsync(
             &self.storage_record.persist_flag_val,
             &self.storage_record.boot_flag_val,
             0o644,
         )?;
-        copy_file(
+        copy_file_without_fsync(
             &self.storage_record.persist_flag_info,
             &self.storage_record.boot_flag_info,
             0o644,
@@ -709,6 +733,7 @@ impl StorageFiles {
     pub(crate) fn get_all_server_overrides(
         &mut self,
     ) -> Result<Vec<FlagValueSummary>, AconfigdError> {
+        debug!("get all staged server overrides for container {}", &self.storage_record.container);
         let listed_flags = list_flags_with_info(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
@@ -736,6 +761,7 @@ impl StorageFiles {
     pub(crate) fn get_all_local_overrides(
         &mut self,
     ) -> Result<Vec<ProtoFlagOverride>, AconfigdError> {
+        debug!("get all staged local overrides for container {}", &self.storage_record.container);
         let pb =
             read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
         Ok(pb.overrides)
@@ -745,7 +771,12 @@ impl StorageFiles {
     pub(crate) fn remove_local_override(
         &mut self,
         context: &PackageFlagContext,
+        immediate: bool,
     ) -> Result<(), AconfigdError> {
+        debug!(
+            "remove local override for flag {}",
+            context.package.to_string() + "." + &context.flag
+        );
         let attribute = self.get_flag_attribute(context)?;
         if (attribute & FlagInfoBit::HasLocalOverride as u8) == 0 {
             return Err(AconfigdError::FlagHasNoLocalOverride {
@@ -765,11 +796,26 @@ impl StorageFiles {
         let flag_info_file = self.get_persist_flag_info()?;
         Self::set_flag_has_local_override_to_file(flag_info_file, context, false)?;
 
+        if configinfra_framework_flags_rust::enable_immediate_clear_override_bugfix() && immediate {
+            let value = if (attribute & FlagInfoBit::HasServerOverride as u8) == 1 {
+                self.get_server_flag_value(&context)?
+            } else {
+                self.get_default_flag_value(&context)?
+            };
+
+            let mut mut_boot_flag_val = self.get_mutable_boot_flag_val()?;
+            Self::set_flag_value_to_file(&mut mut_boot_flag_val, &context, &value)?;
+
+            let mut mut_boot_flag_info = self.get_mutable_boot_flag_info()?;
+            Self::set_flag_has_local_override_to_file(&mut mut_boot_flag_info, &context, false)?;
+        }
+
         Ok(())
     }
 
     /// Remove all local flag overrides
     pub(crate) fn remove_all_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        debug!("remove all local overrides for container {}", &self.storage_record.container);
         let pb =
             read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
 
@@ -796,6 +842,10 @@ impl StorageFiles {
 
     /// Clean up, it cannot be implemented as the drop trait as it needs to return a Result
     pub(crate) fn remove_persist_files(&mut self) -> Result<(), AconfigdError> {
+        debug!(
+            "remove all persistent storage files for container {}",
+            &self.storage_record.container
+        );
         remove_file(&self.storage_record.persist_package_map)?;
         remove_file(&self.storage_record.persist_flag_map)?;
         remove_file(&self.storage_record.persist_flag_val)?;
@@ -831,6 +881,7 @@ impl StorageFiles {
             is_readwrite: attribute & FlagInfoBit::IsReadWrite as u8 != 0,
             has_server_override: attribute & FlagInfoBit::HasServerOverride as u8 != 0,
             has_local_override: attribute & FlagInfoBit::HasLocalOverride as u8 != 0,
+            has_boot_local_override: false, // This is unsupported for get_flag_snapshot.
         }))
     }
 
@@ -839,6 +890,7 @@ impl StorageFiles {
         &mut self,
         package: &str,
     ) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        debug!("list all flags in package {}", &package);
         if !self.has_package(package)? {
             return Ok(Vec::new());
         }
@@ -866,6 +918,7 @@ impl StorageFiles {
             is_readwrite: f.is_readwrite,
             has_server_override: f.has_server_override,
             has_local_override: f.has_local_override,
+            has_boot_local_override: false, // Placeholder; this is mutated and set below.
         })
         .collect();
 
@@ -874,10 +927,11 @@ impl StorageFiles {
             flag_index.insert(f.package.clone() + "/" + &f.flag, i);
         }
 
-        let mut flags: Vec<_> = list_flags(
+        let mut flags: Vec<_> = list_flags_with_info(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
             &self.storage_record.boot_flag_val.display().to_string(),
+            &self.storage_record.boot_flag_info.display().to_string(),
         )
         .map_err(|errmsg| AconfigdError::FailToListFlags {
             container: self.storage_record.container.clone(),
@@ -896,9 +950,10 @@ impl StorageFiles {
                     &f.flag_name,
                 )))?;
             snapshots[*index].boot_value = f.flag_value.clone();
+            snapshots[*index].has_boot_local_override = f.has_local_override;
         }
 
-        flags = list_flags(
+        let flags: Vec<_> = list_flags(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
             &self.storage_record.default_flag_val.display().to_string(),
@@ -937,6 +992,7 @@ impl StorageFiles {
 
     /// list all flags in a container
     pub(crate) fn list_all_flags(&mut self) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        debug!("list all flags in container {}", &self.storage_record.container);
         let mut snapshots: Vec<_> = list_flags_with_info(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
@@ -959,6 +1015,7 @@ impl StorageFiles {
             is_readwrite: f.is_readwrite,
             has_server_override: f.has_server_override,
             has_local_override: f.has_local_override,
+            has_boot_local_override: false, // Placeholder value; this is mutated and set below.
         })
         .collect();
 
@@ -967,10 +1024,11 @@ impl StorageFiles {
             flag_index.insert(f.package.clone() + "/" + &f.flag, i);
         }
 
-        let mut flags: Vec<_> = list_flags(
+        let mut flags: Vec<_> = list_flags_with_info(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
             &self.storage_record.boot_flag_val.display().to_string(),
+            &self.storage_record.boot_flag_info.display().to_string(),
         )
         .map_err(|errmsg| AconfigdError::FailToListFlags {
             container: self.storage_record.container.clone(),
@@ -988,9 +1046,10 @@ impl StorageFiles {
                     &f.flag_name,
                 )))?;
             snapshots[*index].boot_value = f.flag_value.clone();
+            snapshots[*index].has_boot_local_override = f.has_local_override;
         }
 
-        flags = list_flags(
+        let flags: Vec<_> = list_flags(
             &self.storage_record.persist_package_map.display().to_string(),
             &self.storage_record.persist_flag_map.display().to_string(),
             &self.storage_record.default_flag_val.display().to_string(),
@@ -1173,15 +1232,6 @@ mod tests {
             mutable_boot_flag_info: None,
         };
 
-        assert!(has_same_content(
-            &storage_files.storage_record.persist_flag_val,
-            &storage_files.storage_record.boot_flag_val
-        ));
-        assert!(has_same_content(
-            &storage_files.storage_record.persist_flag_info,
-            &storage_files.storage_record.boot_flag_info
-        ));
-
         assert_eq!(storage_files, expected_storage_files);
     }
 
@@ -1464,9 +1514,9 @@ mod tests {
             .get_package_flag_context("com.android.aconfig.storage.test_1", "enabled_rw")
             .unwrap();
 
-        assert!(storage_files.remove_local_override(&context).is_err());
+        assert!(storage_files.remove_local_override(&context, false).is_err());
         storage_files.stage_local_override(&context, "false").unwrap();
-        storage_files.remove_local_override(&context).unwrap();
+        storage_files.remove_local_override(&context, false).unwrap();
         assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "");
         let attribute = storage_files.get_flag_attribute(&context).unwrap();
         assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) == 0);
@@ -1568,6 +1618,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -1604,6 +1655,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[0], flag);
 
@@ -1618,6 +1670,7 @@ mod tests {
             is_readwrite: false,
             has_server_override: false,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[1], flag);
 
@@ -1632,6 +1685,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[2], flag);
     }
@@ -1667,6 +1721,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[2], flag);
 
@@ -1681,6 +1736,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[3], flag);
     }
diff --git a/aconfigd/src/storage_files_manager.rs b/aconfigd/src/storage_files_manager.rs
index d5aff16..8fc890d 100644
--- a/aconfigd/src/storage_files_manager.rs
+++ b/aconfigd/src/storage_files_manager.rs
@@ -19,7 +19,7 @@ use crate::utils::{get_files_digest, read_pb_from_file, remove_file, write_pb_to
 use crate::AconfigdError;
 use aconfigd_protos::{
     ProtoFlagOverride, ProtoFlagOverrideType, ProtoLocalFlagOverrides, ProtoOTAFlagStagingMessage,
-    ProtoPersistStorageRecord, ProtoPersistStorageRecords,
+    ProtoPersistStorageRecord, ProtoPersistStorageRecords, ProtoRemoveOverrideType,
 };
 use log::debug;
 use std::collections::HashMap;
@@ -60,8 +60,26 @@ impl StorageFilesManager {
             );
             return Ok(());
         }
-        self.all_storage_files
-            .insert(String::from(pb.container()), StorageFiles::from_pb(pb, &self.root_dir)?);
+
+        if aconfig_new_storage_flags::bluetooth_flag_value_bug_fix() {
+            // Only create storage file object if the container is active. This is to
+            // ensure that for inactive containers, the storage files object will not
+            // be created and thus their boot copy will not be produced. And thus we
+            // can prevent them from being used.
+            if PathBuf::from(pb.package_map()).exists()
+                && PathBuf::from(pb.flag_map()).exists()
+                && PathBuf::from(pb.flag_val()).exists()
+                && PathBuf::from(pb.flag_info()).exists()
+            {
+                self.all_storage_files.insert(
+                    String::from(pb.container()),
+                    StorageFiles::from_pb(pb, &self.root_dir)?,
+                );
+            }
+        } else {
+            self.all_storage_files
+                .insert(String::from(pb.container()), StorageFiles::from_pb(pb, &self.root_dir)?);
+        }
 
         Ok(())
     }
@@ -108,6 +126,7 @@ impl StorageFilesManager {
         default_flag_val: &Path,
         default_flag_info: &Path,
     ) -> Result<(), AconfigdError> {
+        debug!("update {} storage files", container);
         let mut storage_files = self
             .get_storage_files(container)
             .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
@@ -128,6 +147,7 @@ impl StorageFilesManager {
         )?;
 
         // restage server overrides
+        debug!("restaging existing server overrides");
         for f in server_overrides.iter() {
             let context = storage_files.get_package_flag_context(&f.package_name, &f.flag_name)?;
             if context.flag_exists {
@@ -136,6 +156,7 @@ impl StorageFilesManager {
         }
 
         // restage local overrides
+        debug!("restaging existing local overrides");
         let mut new_pb = ProtoLocalFlagOverrides::new();
         for f in local_overrides.into_iter() {
             let context =
@@ -153,7 +174,8 @@ impl StorageFilesManager {
         Ok(())
     }
 
-    /// add or update a container's storage files in the case of container update
+    /// add or update a container's storage files in the case of container
+    /// update
     pub(crate) fn add_or_update_container_storage_files(
         &mut self,
         container: &str,
@@ -175,6 +197,8 @@ impl StorageFilesManager {
                         default_flag_val,
                         default_flag_info,
                     )?;
+                } else {
+                    debug!("no need to update {}, computed digest matches with record", container);
                 }
             }
             None => {
@@ -205,6 +229,7 @@ impl StorageFilesManager {
 
     /// Reset all storage files
     pub(crate) fn reset_all_storage(&mut self) -> Result<(), AconfigdError> {
+        debug!("reset storage files of all containers");
         let all_containers = self.all_storage_files.keys().cloned().collect::<Vec<String>>();
         for container in all_containers {
             let storage_files = self
@@ -278,6 +303,7 @@ impl StorageFilesManager {
     fn get_ota_flags(&mut self) -> Result<Option<Vec<ProtoFlagOverride>>, AconfigdError> {
         let ota_pb_file = self.root_dir.join("flags/ota.pb");
         if !ota_pb_file.exists() {
+            debug!("no OTA flags staged, skip");
             return Ok(None);
         }
 
@@ -285,13 +311,19 @@ impl StorageFilesManager {
         if let Some(target_build_id) = ota_flags_pb.build_id {
             let device_build_id = rustutils::system_properties::read("ro.build.fingerprint")
                 .map_err(|errmsg| AconfigdError::FailToReadBuildFingerPrint { errmsg })?;
-            if device_build_id == Some(target_build_id) {
+            if device_build_id == Some(target_build_id.clone()) {
                 remove_file(&ota_pb_file)?;
                 Ok(Some(ota_flags_pb.overrides))
             } else {
+                debug!(
+                    "fingerprint mismatch between OTA flag staging {}, and device {}",
+                    target_build_id,
+                    device_build_id.unwrap_or(String::from("None")),
+                );
                 Ok(None)
             }
         } else {
+            debug!("ill formatted OTA staged flags, build fingerprint not set");
             remove_file(&ota_pb_file)?;
             return Ok(None);
         }
@@ -300,6 +332,7 @@ impl StorageFilesManager {
     /// Apply staged ota flags
     pub(crate) fn apply_staged_ota_flags(&mut self) -> Result<(), AconfigdError> {
         if let Some(flags) = self.get_ota_flags()? {
+            debug!("apply staged OTA flags");
             for flag in flags.iter() {
                 if let Err(errmsg) = self.override_flag_value(
                     flag.package_name(),
@@ -324,6 +357,7 @@ impl StorageFilesManager {
         &self,
         file: &Path,
     ) -> Result<(), AconfigdError> {
+        debug!("writing updated storage records {}", file.display().to_string());
         let mut pb = ProtoPersistStorageRecords::new();
         pb.records = self
             .all_storage_files
@@ -349,6 +383,7 @@ impl StorageFilesManager {
         &mut self,
         package: &str,
         flag: &str,
+        remove_override_type: ProtoRemoveOverrideType,
     ) -> Result<(), AconfigdError> {
         let container = self
             .get_container(package)?
@@ -359,11 +394,13 @@ impl StorageFilesManager {
             .ok_or(AconfigdError::FailToGetStorageFiles { container: container.to_string() })?;
 
         let context = storage_files.get_package_flag_context(package, flag)?;
-        storage_files.remove_local_override(&context)
+        let immediate = remove_override_type == ProtoRemoveOverrideType::REMOVE_LOCAL_IMMEDIATE;
+        storage_files.remove_local_override(&context, immediate)
     }
 
     /// Remove all local overrides
     pub(crate) fn remove_all_local_overrides(&mut self) -> Result<(), AconfigdError> {
+        debug!("remove all local overrides for all containers");
         for storage_files in self.all_storage_files.values_mut() {
             storage_files.remove_all_local_overrides()?;
         }
@@ -418,12 +455,20 @@ impl StorageFilesManager {
 
     /// List all the flags
     pub(crate) fn list_all_flags(&mut self) -> Result<Vec<FlagSnapshot>, AconfigdError> {
+        debug!("list all flags across containers");
         let mut flags = Vec::new();
         for storage_files in self.all_storage_files.values_mut() {
-            if !storage_files.has_boot_copy() {
-                continue;
+            match storage_files.list_all_flags() {
+                Ok(f) => {
+                    flags.extend(f);
+                }
+                Err(errmsg) => {
+                    debug!(
+                        "failed to list all flags for {}: {:?}",
+                        storage_files.storage_record.container, errmsg
+                    );
+                }
             }
-            flags.extend(storage_files.list_all_flags()?);
         }
         Ok(flags)
     }
@@ -468,6 +513,15 @@ mod tests {
             manager.all_storage_files.get("mockup").unwrap(),
             &StorageFiles::from_pb(&pb, &root_dir.tmp_dir.path()).unwrap(),
         );
+
+        // Ensure we can run this again, to exercise the case where the storage
+        // files already exist, for example if the storage proto is deleted.
+        manager.add_storage_files_from_pb(&pb);
+        assert_eq!(manager.all_storage_files.len(), 1);
+        assert_eq!(
+            manager.all_storage_files.get("mockup").unwrap(),
+            &StorageFiles::from_pb(&pb, &root_dir.tmp_dir.path()).unwrap(),
+        );
     }
 
     fn init_storage(container: &ContainerMock, manager: &mut StorageFilesManager) {
@@ -721,6 +775,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -739,6 +794,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -800,6 +856,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -836,6 +893,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: false,
             has_local_override: true,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -872,6 +930,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: false,
             has_local_override: true,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -1010,7 +1069,13 @@ mod tests {
         add_example_overrides(&mut manager);
         manager.apply_all_staged_overrides("mockup").unwrap();
 
-        manager.remove_local_override("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
+        manager
+            .remove_local_override(
+                "com.android.aconfig.storage.test_1",
+                "disabled_rw",
+                ProtoRemoveOverrideType::REMOVE_LOCAL_ON_REBOOT,
+            )
+            .unwrap();
 
         let flag =
             manager.get_flag_snapshot("com.android.aconfig.storage.test_1", "disabled_rw").unwrap();
@@ -1026,6 +1091,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -1072,6 +1138,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: false,
             has_local_override: false,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -1090,6 +1157,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: false,
             has_local_override: false,
+            has_boot_local_override: false,
         };
 
         assert_eq!(flag, Some(expected_flag));
@@ -1117,6 +1185,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[0], flag);
 
@@ -1131,6 +1200,7 @@ mod tests {
             is_readwrite: false,
             has_server_override: false,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[1], flag);
 
@@ -1145,6 +1215,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[2], flag);
     }
@@ -1172,6 +1243,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: false,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[2], flag);
 
@@ -1186,6 +1258,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
+            has_boot_local_override: false,
         };
         assert_eq!(flags[0], flag);
     }
diff --git a/aconfigd/src/utils.rs b/aconfigd/src/utils.rs
index 91d06f6..7370ee6 100644
--- a/aconfigd/src/utils.rs
+++ b/aconfigd/src/utils.rs
@@ -32,20 +32,82 @@ pub(crate) fn set_file_permission(file: &Path, mode: u32) -> Result<(), Aconfigd
 
 /// Copy file
 pub(crate) fn copy_file(src: &Path, dst: &Path, mode: u32) -> Result<(), AconfigdError> {
-    std::fs::copy(src, dst).map_err(|errmsg| AconfigdError::FailToCopyFile {
+    if dst.exists() {
+        set_file_permission(dst, 0o644)?;
+    }
+
+    let mut src_file = File::open(src).map_err(|errmsg| AconfigdError::FailToCopyFile {
+        src: src.display().to_string(),
+        dst: dst.display().to_string(),
+        errmsg,
+    })?;
+
+    let mut dst_file = File::create(dst).map_err(|errmsg| AconfigdError::FailToCopyFile {
+        src: src.display().to_string(),
+        dst: dst.display().to_string(),
+        errmsg,
+    })?;
+
+    std::io::copy(&mut src_file, &mut dst_file).map_err(|errmsg| {
+        AconfigdError::FailToCopyFile {
+            src: src.display().to_string(),
+            dst: dst.display().to_string(),
+            errmsg,
+        }
+    })?;
+
+    // force kernel to flush file data in kernel buffer to filesystem
+    dst_file.sync_all().map_err(|errmsg| AconfigdError::FailToCopyFile {
         src: src.display().to_string(),
         dst: dst.display().to_string(),
         errmsg,
     })?;
+
+    set_file_permission(dst, mode)
+}
+
+/// Copy file without fsync
+pub(crate) fn copy_file_without_fsync(
+    src: &Path,
+    dst: &Path,
+    mode: u32,
+) -> Result<(), AconfigdError> {
+    if dst.exists() {
+        set_file_permission(dst, 0o644)?;
+    }
+
+    let mut src_file = File::open(src).map_err(|errmsg| AconfigdError::FailToCopyFile {
+        src: src.display().to_string(),
+        dst: dst.display().to_string(),
+        errmsg,
+    })?;
+
+    let mut dst_file = File::create(dst).map_err(|errmsg| AconfigdError::FailToCopyFile {
+        src: src.display().to_string(),
+        dst: dst.display().to_string(),
+        errmsg,
+    })?;
+
+    std::io::copy(&mut src_file, &mut dst_file).map_err(|errmsg| {
+        AconfigdError::FailToCopyFile {
+            src: src.display().to_string(),
+            dst: dst.display().to_string(),
+            errmsg,
+        }
+    })?;
+
     set_file_permission(dst, mode)
 }
 
 /// Remove file
 pub(crate) fn remove_file(src: &Path) -> Result<(), AconfigdError> {
-    std::fs::remove_file(src).map_err(|errmsg| AconfigdError::FailToRemoveFile {
-        file: src.display().to_string(),
-        errmsg,
-    })
+    if let Ok(true) = src.try_exists() {
+        std::fs::remove_file(src).map_err(|errmsg| AconfigdError::FailToRemoveFile {
+            file: src.display().to_string(),
+            errmsg,
+        })?;
+    }
+    Ok(())
 }
 
 /// Read pb from file
diff --git a/aflags/Android.bp b/aflags/Android.bp
new file mode 100644
index 0000000..ff74350
--- /dev/null
+++ b/aflags/Android.bp
@@ -0,0 +1,40 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "aflags_updatable.defaults",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libaconfig_device_paths",
+        "libaconfig_flags",
+        "libaconfig_protos",
+        "libaconfigd_protos_rust",
+        "libaconfig_storage_read_api",
+        "libaconfig_storage_file",
+        "libanyhow",
+        "libclap",
+        "libnix",
+        "libprotobuf",
+        "libregex",
+    ],
+}
+
+rust_binary {
+    name: "aflags_updatable",
+    host_supported: true,
+    defaults: ["aflags.defaults"],
+    apex_available: [
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
+}
+
+rust_test_host {
+    name: "aflags_updatable.test",
+    defaults: ["aflags_updatable.defaults"],
+    test_suites: ["general-tests"],
+}
diff --git a/aflags/Cargo.toml b/aflags/Cargo.toml
new file mode 100644
index 0000000..794eb54
--- /dev/null
+++ b/aflags/Cargo.toml
@@ -0,0 +1,18 @@
+[package]
+name = "aflags"
+version = "0.1.0"
+edition = "2021"
+
+[dependencies]
+anyhow = "1.0.69"
+paste = "1.0.11"
+protobuf = "3.2.0"
+regex = "1.10.3"
+aconfig_protos = { path = "../../../../build/make/tools/aconfig/aconfig_protos" }
+aconfigd_protos = { version = "0.1.0", path = "../aconfigd/proto"}
+nix = { version = "0.28.0", features = ["user"] }
+aconfig_storage_file = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_storage_file" }
+aconfig_storage_read_api = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_storage_read_api" }
+clap = {version = "4.5.2" }
+aconfig_device_paths = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_device_paths" }
+aconfig_flags = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_flags" }
diff --git a/aflags/rustfmt.toml b/aflags/rustfmt.toml
new file mode 100644
index 0000000..cefaa42
--- /dev/null
+++ b/aflags/rustfmt.toml
@@ -0,0 +1,5 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
diff --git a/aflags/src/aconfig_storage_source.rs b/aflags/src/aconfig_storage_source.rs
new file mode 100644
index 0000000..d9370de
--- /dev/null
+++ b/aflags/src/aconfig_storage_source.rs
@@ -0,0 +1,282 @@
+use crate::load_protos;
+use crate::{Flag, FlagSource};
+use crate::{FlagPermission, FlagValue, ValuePickedFrom};
+use aconfigd_protos::{
+    ProtoFlagOverrideMessage, ProtoFlagOverrideType, ProtoFlagQueryReturnMessage,
+    ProtoListStorageMessage, ProtoListStorageMessageMsg, ProtoRemoveLocalOverrideMessage,
+    ProtoRemoveOverrideType, ProtoStorageRequestMessage, ProtoStorageRequestMessageMsg,
+    ProtoStorageRequestMessages, ProtoStorageReturnMessage, ProtoStorageReturnMessageMsg,
+    ProtoStorageReturnMessages,
+};
+use anyhow::anyhow;
+use anyhow::Result;
+use protobuf::Message;
+use protobuf::SpecialFields;
+use std::collections::HashMap;
+use std::io::{Read, Write};
+use std::net::Shutdown;
+use std::os::unix::net::UnixStream;
+
+pub struct AconfigStorageSource {}
+
+static ACONFIGD_SYSTEM_SOCKET_NAME: &str = "/dev/socket/aconfigd_system";
+static ACONFIGD_MAINLINE_SOCKET_NAME: &str = "/dev/socket/aconfigd_mainline";
+
+enum AconfigdSocket {
+    System,
+    Mainline,
+}
+
+impl AconfigdSocket {
+    pub fn name(&self) -> &str {
+        match self {
+            AconfigdSocket::System => ACONFIGD_SYSTEM_SOCKET_NAME,
+            AconfigdSocket::Mainline => ACONFIGD_MAINLINE_SOCKET_NAME,
+        }
+    }
+}
+
+fn convert(msg: ProtoFlagQueryReturnMessage, containers: &HashMap<String, String>) -> Result<Flag> {
+    let value = FlagValue::try_from(
+        msg.boot_flag_value
+            .clone()
+            .ok_or(anyhow!("no boot flag value for {:?}", msg.flag_name))?
+            .as_str(),
+    )?;
+
+    let value_picked_from = if msg.has_boot_local_override.unwrap_or(false) {
+        ValuePickedFrom::Local
+    } else if msg.boot_flag_value == msg.default_flag_value {
+        ValuePickedFrom::Default
+    } else {
+        ValuePickedFrom::Server
+    };
+
+    let staged_value = if msg.has_local_override.unwrap_or(false) {
+        // If a local override is staged, display it.
+        if msg.boot_flag_value == msg.local_flag_value {
+            None
+        } else {
+            Some(FlagValue::try_from(
+                msg.local_flag_value.ok_or(anyhow!("no local flag value"))?.as_str(),
+            )?)
+        }
+    } else {
+        // Otherwise, display if we're flipping to the default, or a server value.
+        let boot_value = msg.boot_flag_value.unwrap_or("".to_string());
+        let server_value = msg.server_flag_value.unwrap_or("".to_string());
+        let default_value = msg.default_flag_value.unwrap_or("".to_string());
+
+        if boot_value != server_value && server_value != *"" {
+            Some(FlagValue::try_from(server_value.as_str())?)
+        } else if msg.has_boot_local_override.unwrap_or(false) && boot_value != default_value {
+            Some(FlagValue::try_from(default_value.as_str())?)
+        } else {
+            None
+        }
+    };
+
+    let permission = match msg.is_readwrite {
+        Some(is_readwrite) => {
+            if is_readwrite {
+                FlagPermission::ReadWrite
+            } else {
+                FlagPermission::ReadOnly
+            }
+        }
+        None => return Err(anyhow!("missing permission")),
+    };
+
+    let name = msg.flag_name.ok_or(anyhow!("missing flag name"))?;
+    let package = msg.package_name.ok_or(anyhow!("missing package name"))?;
+    let qualified_name = format!("{package}.{name}");
+    Ok(Flag {
+        name,
+        package,
+        value,
+        permission,
+        value_picked_from,
+        staged_value,
+        container: containers
+            .get(&qualified_name)
+            .cloned()
+            .unwrap_or_else(|| "<no container>".to_string())
+            .to_string(),
+        // TODO: remove once DeviceConfig is not in the CLI.
+        namespace: "-".to_string(),
+    })
+}
+
+fn write_socket_messages(
+    socket: AconfigdSocket,
+    messages: ProtoStorageRequestMessages,
+) -> Result<ProtoStorageReturnMessages> {
+    let mut socket = UnixStream::connect(socket.name())?;
+
+    let message_buffer = messages.write_to_bytes()?;
+    let mut message_length_buffer: [u8; 4] = [0; 4];
+    let message_size = &message_buffer.len();
+    message_length_buffer[0] = (message_size >> 24) as u8;
+    message_length_buffer[1] = (message_size >> 16) as u8;
+    message_length_buffer[2] = (message_size >> 8) as u8;
+    message_length_buffer[3] = *message_size as u8;
+    socket.write_all(&message_length_buffer)?;
+    socket.write_all(&message_buffer)?;
+    socket.shutdown(Shutdown::Write)?;
+
+    let mut response_length_buffer: [u8; 4] = [0; 4];
+    socket.read_exact(&mut response_length_buffer)?;
+    let response_length = u32::from_be_bytes(response_length_buffer) as usize;
+    let mut response_buffer = vec![0; response_length];
+    socket.read_exact(&mut response_buffer)?;
+
+    let response: ProtoStorageReturnMessages =
+        protobuf::Message::parse_from_bytes(&response_buffer)?;
+
+    Ok(response)
+}
+
+fn send_list_flags_command(socket: AconfigdSocket) -> Result<Vec<ProtoFlagQueryReturnMessage>> {
+    let messages = ProtoStorageRequestMessages {
+        msgs: vec![ProtoStorageRequestMessage {
+            msg: Some(ProtoStorageRequestMessageMsg::ListStorageMessage(ProtoListStorageMessage {
+                msg: Some(ProtoListStorageMessageMsg::All(true)),
+                special_fields: SpecialFields::new(),
+            })),
+            special_fields: SpecialFields::new(),
+        }],
+        special_fields: SpecialFields::new(),
+    };
+
+    let response = write_socket_messages(socket, messages)?;
+    match response.msgs.as_slice() {
+        [ProtoStorageReturnMessage {
+            msg: Some(ProtoStorageReturnMessageMsg::ListStorageMessage(list_storage_message)),
+            ..
+        }] => Ok(list_storage_message.flags.clone()),
+        _ => Err(anyhow!("unexpected response from aconfigd")),
+    }
+}
+
+fn send_override_command(
+    socket: AconfigdSocket,
+    package_name: &str,
+    flag_name: &str,
+    value: &str,
+    immediate: bool,
+) -> Result<()> {
+    let override_type = if immediate {
+        ProtoFlagOverrideType::LOCAL_IMMEDIATE
+    } else {
+        ProtoFlagOverrideType::LOCAL_ON_REBOOT
+    };
+
+    let messages = ProtoStorageRequestMessages {
+        msgs: vec![ProtoStorageRequestMessage {
+            msg: Some(ProtoStorageRequestMessageMsg::FlagOverrideMessage(
+                ProtoFlagOverrideMessage {
+                    package_name: Some(package_name.to_string()),
+                    flag_name: Some(flag_name.to_string()),
+                    flag_value: Some(value.to_string()),
+                    override_type: Some(override_type.into()),
+                    special_fields: SpecialFields::new(),
+                },
+            )),
+            special_fields: SpecialFields::new(),
+        }],
+        special_fields: SpecialFields::new(),
+    };
+
+    write_socket_messages(socket, messages)?;
+    Ok(())
+}
+
+impl FlagSource for AconfigStorageSource {
+    fn list_flags() -> Result<Vec<Flag>> {
+        let flag_defaults = load_protos::load()?;
+        let system_messages = send_list_flags_command(AconfigdSocket::System);
+        let mainline_messages = send_list_flags_command(AconfigdSocket::Mainline);
+
+        let mut all_messages = vec![];
+        if let Ok(system_messages) = system_messages {
+            all_messages.extend_from_slice(&system_messages);
+        }
+        if let Ok(mainline_messages) = mainline_messages {
+            all_messages.extend_from_slice(&mainline_messages);
+        }
+
+        let container_map: HashMap<String, String> = flag_defaults
+            .clone()
+            .into_iter()
+            .map(|default| (default.qualified_name(), default.container))
+            .collect();
+        let socket_flags: Vec<Result<Flag>> = all_messages
+            .into_iter()
+            .map(|query_message| convert(query_message.clone(), &container_map))
+            .collect();
+        let socket_flags: Result<Vec<Flag>> = socket_flags.into_iter().collect();
+
+        // Load the defaults from the on-device protos.
+        // If the sockets are unavailable, just display the proto defaults.
+        let mut flags = flag_defaults.clone();
+        let name_to_socket_flag: HashMap<String, Flag> =
+            socket_flags?.into_iter().map(|p| (p.qualified_name(), p)).collect();
+        flags.iter_mut().for_each(|flag| {
+            if let Some(socket_flag) = name_to_socket_flag.get(&flag.qualified_name()) {
+                *flag = socket_flag.clone();
+            }
+        });
+
+        Ok(flags)
+    }
+
+    fn override_flag(
+        _namespace: &str,
+        qualified_name: &str,
+        value: &str,
+        immediate: bool,
+    ) -> Result<()> {
+        let (package, flag_name) = if let Some(last_dot_index) = qualified_name.rfind('.') {
+            (&qualified_name[..last_dot_index], &qualified_name[last_dot_index + 1..])
+        } else {
+            return Err(anyhow!(format!("invalid flag name: {qualified_name}")));
+        };
+
+        let _ = send_override_command(AconfigdSocket::System, package, flag_name, value, immediate);
+        let _ =
+            send_override_command(AconfigdSocket::Mainline, package, flag_name, value, immediate);
+        Ok(())
+    }
+
+    fn unset_flag(_namespace: &str, qualified_name: &str, immediate: bool) -> Result<()> {
+        let last_period_index = qualified_name.rfind('.').ok_or(anyhow!("No period found"))?;
+        let (package, flag_name) = qualified_name.split_at(last_period_index);
+
+        let removal_type = if immediate {
+            ProtoRemoveOverrideType::REMOVE_LOCAL_IMMEDIATE
+        } else {
+            ProtoRemoveOverrideType::REMOVE_LOCAL_ON_REBOOT
+        };
+
+        let socket_message = ProtoStorageRequestMessages {
+            msgs: vec![ProtoStorageRequestMessage {
+                msg: Some(ProtoStorageRequestMessageMsg::RemoveLocalOverrideMessage(
+                    ProtoRemoveLocalOverrideMessage {
+                        package_name: Some(package.to_string()),
+                        flag_name: Some(flag_name[1..].to_string()),
+                        remove_all: Some(false),
+                        remove_override_type: Some(removal_type.into()),
+                        special_fields: SpecialFields::new(),
+                    },
+                )),
+                special_fields: SpecialFields::new(),
+            }],
+            special_fields: SpecialFields::new(),
+        };
+
+        let _ = write_socket_messages(AconfigdSocket::Mainline, socket_message.clone());
+        let _ = write_socket_messages(AconfigdSocket::System, socket_message);
+
+        Ok(())
+    }
+}
diff --git a/aflags/src/load_protos.rs b/aflags/src/load_protos.rs
new file mode 100644
index 0000000..c5ac8ff
--- /dev/null
+++ b/aflags/src/load_protos.rs
@@ -0,0 +1,72 @@
+use crate::{Flag, FlagPermission, FlagValue, ValuePickedFrom};
+use aconfig_protos::ProtoFlagPermission as ProtoPermission;
+use aconfig_protos::ProtoFlagState as ProtoState;
+use aconfig_protos::ProtoParsedFlag;
+use aconfig_protos::ProtoParsedFlags;
+use anyhow::Result;
+use std::fs;
+use std::path::Path;
+
+// TODO(b/329875578): use container field directly instead of inferring.
+fn infer_container(path: &Path) -> String {
+    let path_str = path.to_string_lossy();
+    path_str
+        .strip_prefix("/apex/")
+        .or_else(|| path_str.strip_prefix('/'))
+        .unwrap_or(&path_str)
+        .strip_suffix("/etc/aconfig_flags.pb")
+        .unwrap_or(&path_str)
+        .to_string()
+}
+
+fn convert_parsed_flag(path: &Path, flag: &ProtoParsedFlag) -> Flag {
+    let namespace = flag.namespace().to_string();
+    let package = flag.package().to_string();
+    let name = flag.name().to_string();
+
+    let value = match flag.state() {
+        ProtoState::ENABLED => FlagValue::Enabled,
+        ProtoState::DISABLED => FlagValue::Disabled,
+    };
+
+    let permission = match flag.permission() {
+        ProtoPermission::READ_ONLY => FlagPermission::ReadOnly,
+        ProtoPermission::READ_WRITE => FlagPermission::ReadWrite,
+    };
+
+    Flag {
+        namespace,
+        package,
+        name,
+        container: infer_container(path),
+        value,
+        staged_value: None,
+        permission,
+        value_picked_from: ValuePickedFrom::Default,
+    }
+}
+
+pub(crate) fn load() -> Result<Vec<Flag>> {
+    let mut result = Vec::new();
+
+    let paths = aconfig_device_paths::parsed_flags_proto_paths()?;
+    for path in paths {
+        let Ok(bytes) = fs::read(&path) else {
+            eprintln!("warning: failed to read {:?}", path);
+            continue;
+        };
+        let parsed_flags: ProtoParsedFlags = protobuf::Message::parse_from_bytes(&bytes)?;
+        for flag in parsed_flags.parsed_flag {
+            // TODO(b/334954748): enforce one-container-per-flag invariant.
+            result.push(convert_parsed_flag(&path, &flag));
+        }
+    }
+    Ok(result)
+}
+
+pub(crate) fn list_containers() -> Result<Vec<String>> {
+    Ok(aconfig_device_paths::parsed_flags_proto_paths()?
+        .into_iter()
+        .map(|p| infer_container(&p))
+        .collect())
+}
diff --git a/aflags/src/main.rs b/aflags/src/main.rs
new file mode 100644
index 0000000..e18c0eb
--- /dev/null
+++ b/aflags/src/main.rs
@@ -0,0 +1,435 @@
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
+//! `aflags` is a device binary to read and write aconfig flags.
+
+use anyhow::{anyhow, ensure, Result};
+use clap::Parser;
+
+mod aconfig_storage_source;
+use aconfig_storage_source::AconfigStorageSource;
+
+mod load_protos;
+
+#[derive(Clone, PartialEq, Debug)]
+enum FlagPermission {
+    ReadOnly,
+    ReadWrite,
+}
+
+impl std::fmt::Display for FlagPermission {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "{}",
+            match &self {
+                Self::ReadOnly => "read-only",
+                Self::ReadWrite => "read-write",
+            }
+        )
+    }
+}
+
+#[derive(Clone, Debug)]
+enum ValuePickedFrom {
+    Default,
+    Server,
+    Local,
+}
+
+impl std::fmt::Display for ValuePickedFrom {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "{}",
+            match &self {
+                Self::Default => "default",
+                Self::Server => "server",
+                Self::Local => "local",
+            }
+        )
+    }
+}
+
+#[derive(Clone, Copy, PartialEq, Eq, Debug)]
+enum FlagValue {
+    Enabled,
+    Disabled,
+}
+
+impl TryFrom<&str> for FlagValue {
+    type Error = anyhow::Error;
+
+    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
+        match value {
+            "true" | "enabled" => Ok(Self::Enabled),
+            "false" | "disabled" => Ok(Self::Disabled),
+            _ => Err(anyhow!("cannot convert string '{}' to FlagValue", value)),
+        }
+    }
+}
+
+impl std::fmt::Display for FlagValue {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "{}",
+            match &self {
+                Self::Enabled => "enabled",
+                Self::Disabled => "disabled",
+            }
+        )
+    }
+}
+
+#[derive(Clone, Debug)]
+struct Flag {
+    namespace: String,
+    name: String,
+    package: String,
+    container: String,
+    value: FlagValue,
+    staged_value: Option<FlagValue>,
+    permission: FlagPermission,
+    value_picked_from: ValuePickedFrom,
+}
+
+impl Flag {
+    fn qualified_name(&self) -> String {
+        format!("{}.{}", self.package, self.name)
+    }
+
+    fn display_staged_value(&self) -> String {
+        match (&self.permission, self.staged_value) {
+            (FlagPermission::ReadOnly, _) => "-".to_string(),
+            (FlagPermission::ReadWrite, None) => "-".to_string(),
+            (FlagPermission::ReadWrite, Some(v)) => format!("(->{})", v),
+        }
+    }
+}
+
+trait FlagSource {
+    fn list_flags() -> Result<Vec<Flag>>;
+    fn override_flag(
+        namespace: &str,
+        qualified_name: &str,
+        value: &str,
+        immediate: bool,
+    ) -> Result<()>;
+    fn unset_flag(namespace: &str, qualified_name: &str, immediate: bool) -> Result<()>;
+}
+
+enum FlagSourceType {
+    AconfigStorage,
+}
+
+const ABOUT_TEXT: &str = "Tool for reading and writing flags.
+
+Rows in the table from the `list` command follow this format:
+
+  package flag_name value provenance permission container
+
+  * `package`: package set for this flag in its .aconfig definition.
+  * `flag_name`: flag name, also set in definition.
+  * `value`: the value read from the flag.
+  * `staged_value`: the value on next boot:
+    + `-`: same as current value
+    + `(->enabled) flipped to enabled on boot.
+    + `(->disabled) flipped to disabled on boot.
+  * `provenance`: one of:
+    + `default`: the flag value comes from its build-time default.
+    + `server`: the flag value comes from a server override.
+    + `local`: the flag value comes from local override.
+  * `permission`: read-write or read-only.
+  * `container`: the container for the flag, configured in its definition.
+";
+
+#[derive(Parser, Debug)]
+#[clap(long_about=ABOUT_TEXT, bin_name="aflags")]
+struct Cli {
+    #[clap(subcommand)]
+    command: Command,
+}
+
+#[derive(Parser, Debug)]
+enum Command {
+    /// List all aconfig flags on this device.
+    List {
+        /// Optionally filter by container name.
+        #[clap(short = 'c', long = "container")]
+        container: Option<String>,
+    },
+
+    /// Locally enable an aconfig flag on this device.
+    ///
+    /// Prevents server overrides until the value is unset.
+    ///
+    /// By default, requires a reboot to take effect.
+    Enable {
+        /// <package>.<flag_name>
+        qualified_name: String,
+
+        /// Apply the change immediately.
+        #[clap(short = 'i', long = "immediate")]
+        immediate: bool,
+    },
+
+    /// Locally disable an aconfig flag on this device.
+    ///
+    /// Prevents server overrides until the value is unset.
+    ///
+    /// By default, requires a reboot to take effect.
+    Disable {
+        /// <package>.<flag_name>
+        qualified_name: String,
+
+        /// Apply the change immediately.
+        #[clap(short = 'i', long = "immediate")]
+        immediate: bool,
+    },
+
+    /// Clear any local override value and re-allow server overrides.
+    ///
+    /// By default, requires a reboot to take effect.
+    Unset {
+        /// <package>.<flag_name>
+        qualified_name: String,
+
+        /// Apply the change immediately.
+        #[clap(short = 'i', long = "immediate")]
+        immediate: bool,
+    },
+}
+
+struct PaddingInfo {
+    longest_flag_col: usize,
+    longest_val_col: usize,
+    longest_staged_val_col: usize,
+    longest_value_picked_from_col: usize,
+    longest_permission_col: usize,
+}
+
+struct Filter {
+    container: Option<String>,
+}
+
+impl Filter {
+    fn apply(&self, flags: &[Flag]) -> Vec<Flag> {
+        flags
+            .iter()
+            .filter(|flag| match &self.container {
+                Some(c) => flag.container == *c,
+                None => true,
+            })
+            .cloned()
+            .collect()
+    }
+}
+
+fn format_flag_row(flag: &Flag, info: &PaddingInfo) -> String {
+    let full_name = flag.qualified_name();
+    let p0 = info.longest_flag_col + 1;
+
+    let val = flag.value.to_string();
+    let p1 = info.longest_val_col + 1;
+
+    let staged_val = flag.display_staged_value();
+    let p2 = info.longest_staged_val_col + 1;
+
+    let value_picked_from = flag.value_picked_from.to_string();
+    let p3 = info.longest_value_picked_from_col + 1;
+
+    let perm = flag.permission.to_string();
+    let p4 = info.longest_permission_col + 1;
+
+    let container = &flag.container;
+
+    format!(
+        "{full_name:p0$}{val:p1$}{staged_val:p2$}{value_picked_from:p3$}{perm:p4$}{container}\n"
+    )
+}
+
+fn set_flag(qualified_name: &str, value: &str, immediate: bool) -> Result<()> {
+    let flags_binding = AconfigStorageSource::list_flags()?;
+    let flag = flags_binding.iter().find(|f| f.qualified_name() == qualified_name).ok_or(
+        anyhow!("no aconfig flag '{qualified_name}'. Does the flag have an .aconfig definition?"),
+    )?;
+
+    ensure!(flag.permission == FlagPermission::ReadWrite,
+            format!("could not write flag '{qualified_name}', it is read-only for the current release configuration."));
+
+    AconfigStorageSource::override_flag(&flag.namespace, qualified_name, value, immediate)?;
+
+    Ok(())
+}
+
+fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String> {
+    let flags_unfiltered = match source_type {
+        FlagSourceType::AconfigStorage => AconfigStorageSource::list_flags()?,
+    };
+
+    if let Some(ref c) = container {
+        ensure!(
+            load_protos::list_containers()?.contains(c),
+            format!("container '{}' not found", &c)
+        );
+    }
+
+    let flags = (Filter { container }).apply(&flags_unfiltered);
+    let padding_info = PaddingInfo {
+        longest_flag_col: flags.iter().map(|f| f.qualified_name().len()).max().unwrap_or(0),
+        longest_val_col: flags.iter().map(|f| f.value.to_string().len()).max().unwrap_or(0),
+        longest_staged_val_col: flags
+            .iter()
+            .map(|f| f.display_staged_value().len())
+            .max()
+            .unwrap_or(0),
+        longest_value_picked_from_col: flags
+            .iter()
+            .map(|f| f.value_picked_from.to_string().len())
+            .max()
+            .unwrap_or(0),
+        longest_permission_col: flags
+            .iter()
+            .map(|f| f.permission.to_string().len())
+            .max()
+            .unwrap_or(0),
+    };
+
+    let mut result = String::from("");
+    for flag in flags {
+        let row = format_flag_row(&flag, &padding_info);
+        result.push_str(&row);
+    }
+    Ok(result)
+}
+
+fn unset(qualified_name: &str, immediate: bool) -> Result<()> {
+    let flags_binding = AconfigStorageSource::list_flags()?;
+    let flag = flags_binding.iter().find(|f| f.qualified_name() == qualified_name).ok_or(
+        anyhow!("no aconfig flag '{qualified_name}'. Does the flag have an .aconfig definition?"),
+    )?;
+
+    AconfigStorageSource::unset_flag(&flag.namespace, qualified_name, immediate)
+}
+
+fn main() -> Result<()> {
+    ensure!(nix::unistd::Uid::current().is_root(), "must be root");
+
+    let cli = Cli::parse();
+    let output = match cli.command {
+        Command::List { container } => list(FlagSourceType::AconfigStorage, container)
+            .map_err(|err| anyhow!("could not list flags: {err}"))
+            .map(Some),
+        Command::Enable { qualified_name, immediate } => {
+            set_flag(&qualified_name, "true", immediate).map(|_| None)
+        }
+        Command::Disable { qualified_name, immediate } => {
+            set_flag(&qualified_name, "false", immediate).map(|_| None)
+        }
+        Command::Unset { qualified_name, immediate } => {
+            unset(&qualified_name, immediate).map(|_| None)
+        }
+    };
+    match output {
+        Ok(Some(text)) => println!("{text}"),
+        Ok(None) => (),
+        Err(message) => println!("Error: {message}"),
+    }
+
+    Ok(())
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_filter_container() {
+        let flags = vec![
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test1".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "system".to_string(),
+            },
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test2".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "not_system".to_string(),
+            },
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test3".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "system".to_string(),
+            },
+        ];
+
+        assert_eq!((Filter { container: Some("system".to_string()) }).apply(&flags).len(), 2);
+    }
+
+    #[test]
+    fn test_filter_no_container() {
+        let flags = vec![
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test1".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "system".to_string(),
+            },
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test2".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "not_system".to_string(),
+            },
+            Flag {
+                namespace: "namespace".to_string(),
+                name: "test3".to_string(),
+                package: "package".to_string(),
+                value: FlagValue::Disabled,
+                staged_value: None,
+                permission: FlagPermission::ReadWrite,
+                value_picked_from: ValuePickedFrom::Default,
+                container: "system".to_string(),
+            },
+        ];
+
+        assert_eq!((Filter { container: None }).apply(&flags).len(), 3);
+    }
+}
diff --git a/apex/Android.bp b/apex/Android.bp
index edaf6dd..aca2a5f 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -103,12 +103,12 @@ apex {
     file_contexts: ":com.android.configinfrastructure-file_contexts",
     binaries: [
         "aconfigd-mainline",
+        "aflags_updatable",
     ],
     prebuilts: [
         "com.android.configinfrastrcture.init.rc",
         "current_sdkinfo",
     ],
-    min_sdk_version: "34",
     key: "com.android.configinfrastructure.key",
     certificate: ":com.android.configinfrastructure.certificate",
     apps: [
diff --git a/framework/Android.bp b/framework/Android.bp
index 18e10bd..58476b7 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -45,15 +45,16 @@ java_sdk_library {
         "aconfig_storage_stub",
     ],
     static_libs: [
-        "aconfigd_java_proto_lite_lib",
+        "aconfigd_java_proto_lib_repackaged",
         "configinfra_framework_flags_java_lib",
         "modules-utils-build",
+        "modules-utils-proto",
         "aconfig_storage_file_java",
     ],
     aconfig_declarations: [
         "configinfra_framework_flags",
     ],
-    jarjar_rules: "jarjar-rules.txt",
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
     lint: {
         baseline_filename: "lint-baseline.xml",
     },
@@ -74,6 +75,7 @@ aconfig_declarations {
     srcs: [
         "flags.aconfig",
     ],
+    exportable: true,
 }
 
 java_aconfig_library {
@@ -92,3 +94,28 @@ java_aconfig_library {
         "fake_device_config",
     ],
 }
+
+java_aconfig_library {
+    name: "configinfra_framework_flags_java_exported_lib",
+    mode: "exported",
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+        "//apex_available:platform", // Used by DeviceConfigService
+    ],
+    visibility: [
+        "//visibility:public",
+    ],
+    aconfig_declarations: "configinfra_framework_flags",
+    sdk_version: "core_platform",
+    libs: [
+        "fake_device_config",
+    ],
+}
+
+filegroup {
+    name: "framework-configinfrastructure-jarjar",
+    srcs: [
+        "jarjar-rules.txt",
+    ],
+}
diff --git a/framework/api/module-lib-current.txt b/framework/api/module-lib-current.txt
index f62dcc7..8295801 100644
--- a/framework/api/module-lib-current.txt
+++ b/framework/api/module-lib-current.txt
@@ -1,8 +1,8 @@
 // Signature format: 2.0
 package android.os.flagging {
 
-  @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class ConfigInfrastructureFrameworkInitializer {
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public static void registerServiceWrappers();
+  @FlaggedApi("android.provider.flags.new_storage_public_api") public final class ConfigInfrastructureFrameworkInitializer {
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public static void registerServiceWrappers();
   }
 
 }
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index 1d775ef..19e98ca 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -1,18 +1,18 @@
 // Signature format: 2.0
 package android.os.flagging {
 
-  @FlaggedApi("android.provider.flags.stage_flags_for_build") public class AconfigWriteException extends android.util.AndroidRuntimeException {
-    ctor @FlaggedApi("android.provider.flags.stage_flags_for_build") public AconfigWriteException(@NonNull String);
-    ctor @FlaggedApi("android.provider.flags.stage_flags_for_build") public AconfigWriteException(@NonNull String, @NonNull Throwable);
+  @FlaggedApi("android.provider.flags.new_storage_public_api") public class AconfigStorageWriteException extends android.util.AndroidRuntimeException {
+    ctor @FlaggedApi("android.provider.flags.new_storage_public_api") public AconfigStorageWriteException(@NonNull String);
+    ctor @FlaggedApi("android.provider.flags.new_storage_public_api") public AconfigStorageWriteException(@NonNull String, @NonNull Throwable);
   }
 
-  @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class FlagManager {
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void clearBooleanLocalOverridesImmediately(@Nullable java.util.Set<java.lang.String>);
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void clearBooleanLocalOverridesOnReboot(@Nullable java.util.Set<java.lang.String>);
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanLocalOverridesImmediately(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanLocalOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
-    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public void setBooleanOverridesOnSystemBuildFingerprint(@NonNull String, @NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+  @FlaggedApi("android.provider.flags.new_storage_public_api") public final class FlagManager {
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void clearBooleanLocalOverridesImmediately(@Nullable java.util.Set<java.lang.String>);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void clearBooleanLocalOverridesOnReboot(@Nullable java.util.Set<java.lang.String>);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void setBooleanLocalOverridesImmediately(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void setBooleanLocalOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void setBooleanOverridesOnReboot(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
+    method @FlaggedApi("android.provider.flags.new_storage_public_api") public void setBooleanOverridesOnSystemBuildFingerprint(@NonNull String, @NonNull java.util.Map<java.lang.String,java.lang.Boolean>);
   }
 
 }
@@ -88,6 +88,8 @@ package android.provider {
     field public static final String NAMESPACE_LOCATION = "location";
     field public static final String NAMESPACE_MEDIA = "media";
     field public static final String NAMESPACE_MEDIA_NATIVE = "media_native";
+    field @FlaggedApi("android.provider.flags.mmd_device_config") public static final String NAMESPACE_MM = "mm";
+    field @FlaggedApi("android.provider.flags.mmd_device_config") public static final String NAMESPACE_MMD_NATIVE = "mmd_native";
     field public static final String NAMESPACE_NEARBY = "nearby";
     field public static final String NAMESPACE_NETD_NATIVE = "netd_native";
     field public static final String NAMESPACE_NFC = "nfc";
diff --git a/framework/flags.aconfig b/framework/flags.aconfig
index 9f314a8..6264f63 100644
--- a/framework/flags.aconfig
+++ b/framework/flags.aconfig
@@ -1,6 +1,23 @@
 package: "android.provider.flags"
 container: "com.android.configinfrastructure"
 
+flag {
+  name: "new_storage_writer_system_api"
+  namespace: "core_experiments_team_internal"
+  description: "API flag for writing new storage"
+  bug: "367765164"
+  is_fixed_read_only: true
+  is_exported: true
+}
+
+flag {
+  name: "read_platform_from_platform_api"
+  namespace: "core_experiments_team_internal"
+  description: "read the platform related flags from the platform api"
+  bug: "383743394"
+  is_fixed_read_only: true
+}
+
 flag {
   name: "stage_flags_for_build"
   namespace: "core_experiments_team_internal"
@@ -34,3 +51,38 @@ flag {
   bug: "364083026"
   is_exported: true
 }
+
+flag {
+  name: "enable_immediate_clear_override_bugfix"
+  namespace: "core_experiments_team_internal"
+  description: "Bugfix flag to allow clearing a local override immediately"
+  bug: "387316969"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "mmd_device_config"
+  namespace: "core_experiments_team_internal"
+  description: "Enable device config usages for mmd"
+  bug: "375431994"
+  is_exported: true
+}
+
+flag {
+  name: "use_proto_input_stream"
+  namespace: "core_experiments_team_internal"
+  description: "Use ProtoInputStream to deserialize protos instead of proto lite lib."
+  bug: "390667838"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "flag_manager_unit_test_flag"
+  namespace: "core_experiments_team_internal"
+  description: "Used in FlagManagerUnitTests to test flipping flags with public write APIs"
+  bug: "384572622"
+}
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
index 2108e8f..1e61916 100644
--- a/framework/jarjar-rules.txt
+++ b/framework/jarjar-rules.txt
@@ -1,5 +1,9 @@
 rule com.android.modules.utils.** android.provider.internal.modules.utils.@1
 rule android.aconfig.storage.** android.provider.internal.aconfig.storage.@1
+rule com.google.errorprone.annotations.** android.provider.internal.aconfig.storage.com.google.errorprone.annotations.@1
+rule android.util.configinfrastructure.** android.provider.internal.aconfig.storage.android.util.@1
+rule android.util.LongArray android.provider.internal.aconfig.storage.android.util.@0
+rule com.android.internal.util.** android.provider.internal.aconfig.storage.com.android.internal.util.@1
 rule com.google.protobuf.** android.provider.configinfra.internal.protobuf.@1
 rule android.aconfigd.** android.internal.configinfra.aconfigd.@1
 
diff --git a/framework/java/android/os/flagging/AconfigPackage.java b/framework/java/android/os/flagging/AconfigPackage.java
index acb6d9b..4291c4d 100644
--- a/framework/java/android/os/flagging/AconfigPackage.java
+++ b/framework/java/android/os/flagging/AconfigPackage.java
@@ -16,14 +16,18 @@
 
 package android.os.flagging;
 
+import static android.aconfig.storage.TableUtils.StorageFilesBundle;
 import static android.provider.flags.Flags.FLAG_NEW_STORAGE_PUBLIC_API;
+import static android.provider.flags.Flags.readPlatformFromPlatformApi;
 
+import android.aconfig.storage.AconfigStorageException;
 import android.aconfig.storage.FlagTable;
 import android.aconfig.storage.FlagValueList;
 import android.aconfig.storage.PackageTable;
 import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
-import android.os.StrictMode;
+import android.os.Build;
+import android.util.Log;
 
 import java.io.Closeable;
 import java.io.File;
@@ -31,6 +35,8 @@ import java.nio.MappedByteBuffer;
 import java.nio.channels.FileChannel;
 import java.nio.file.Paths;
 import java.nio.file.StandardOpenOption;
+import java.util.HashMap;
+import java.util.Map;
 
 /**
  * An {@code aconfig} package containing the enabled state of its flags.
@@ -44,20 +50,58 @@ import java.nio.file.StandardOpenOption;
  */
 @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
 public class AconfigPackage {
-
+    private static final String TAG = "AconfigPackage";
     private static final String MAP_PATH = "/metadata/aconfig/maps/";
     private static final String BOOT_PATH = "/metadata/aconfig/boot/";
-    private static final String SYSTEM_MAP = "/metadata/aconfig/maps/system.package.map";
     private static final String PMAP_FILE_EXT = ".package.map";
 
+    private static final boolean READ_PLATFORM_FROM_PLATFORM_API =
+            readPlatformFromPlatformApi() && Build.VERSION.SDK_INT > 35;
+
     private FlagTable mFlagTable;
     private FlagValueList mFlagValueList;
 
     private int mPackageBooleanStartOffset = -1;
     private int mPackageId = -1;
 
+    private PlatformAconfigPackage mPlatformAconfigPackage = null;
+
+    /** @hide */
+    static final Map<String, StorageFilesBundle> sStorageFilesCache = new HashMap<>();
+
     private AconfigPackage() {}
 
+    static {
+        File mapDir = new File(MAP_PATH);
+        String[] mapFiles = mapDir.list();
+        if (mapFiles != null) {
+            for (String file : mapFiles) {
+                if (!file.endsWith(PMAP_FILE_EXT)
+                        || (READ_PLATFORM_FROM_PLATFORM_API
+                                && PlatformAconfigPackage.PLATFORM_PACKAGE_MAP_FILES.contains(
+                                        file))) {
+                    continue;
+                }
+                try {
+                    PackageTable pTable = PackageTable.fromBytes(mapStorageFile(MAP_PATH + file));
+                    String container = pTable.getHeader().getContainer();
+                    FlagTable fTable =
+                            FlagTable.fromBytes(mapStorageFile(MAP_PATH + container + ".flag.map"));
+                    FlagValueList fValueList =
+                            FlagValueList.fromBytes(mapStorageFile(BOOT_PATH + container + ".val"));
+                    StorageFilesBundle files = new StorageFilesBundle(pTable, fTable, fValueList);
+                    for (String packageName : pTable.getPackageList()) {
+                        Log.i(TAG, packageName + " is mapped to " + container);
+                        sStorageFilesCache.put(packageName, files);
+                    }
+                } catch (Exception e) {
+                    // pass
+                    Log.w(TAG, "failed to map some package from " + file + ": " + e.toString());
+                }
+            }
+        }
+    }
+
     /**
      * Loads an Aconfig Package from Aconfig Storage.
      *
@@ -73,61 +117,37 @@ public class AconfigPackage {
      */
     @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
     public static @NonNull AconfigPackage load(@NonNull String packageName) {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
         try {
             AconfigPackage aconfigPackage = new AconfigPackage();
-            PackageTable pTable = null;
-            PackageTable.Node pNode = null;
-
-            try {
-                pTable = PackageTable.fromBytes(mapStorageFile(SYSTEM_MAP));
-                pNode = pTable.get(packageName);
-            } catch (Exception e) {
-                // Ignore exceptions when loading the system map file.
-            }
 
-            if (pNode == null) {
-                File mapDir = new File(MAP_PATH);
-                String[] mapFiles = mapDir.list();
-                if (mapFiles == null) {
-                    throw new AconfigStorageReadException(
-                            AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
-                            "package " + packageName + " cannot be found on the device");
-                }
-
-                for (String file : mapFiles) {
-                    if (!file.endsWith(PMAP_FILE_EXT)) {
-                        continue;
-                    }
-                    pTable = PackageTable.fromBytes(mapStorageFile(MAP_PATH + file));
-                    pNode = pTable.get(packageName);
-                    if (pNode != null) {
-                        break;
-                    }
+            if (READ_PLATFORM_FROM_PLATFORM_API) {
+                aconfigPackage.mPlatformAconfigPackage = PlatformAconfigPackage.load(packageName);
+                if (aconfigPackage.mPlatformAconfigPackage != null) {
+                    return aconfigPackage;
                 }
             }
 
-            if (pNode == null) {
+            StorageFilesBundle files = sStorageFilesCache.get(packageName);
+            if (files == null) {
                 throw new AconfigStorageReadException(
                         AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
                         "package " + packageName + " cannot be found on the device");
             }
 
-            String container = pTable.getHeader().getContainer();
-            aconfigPackage.mFlagTable =
-                    FlagTable.fromBytes(mapStorageFile(MAP_PATH + container + ".flag.map"));
-            aconfigPackage.mFlagValueList =
-                    FlagValueList.fromBytes(mapStorageFile(BOOT_PATH + container + ".val"));
+            PackageTable.Node pNode = files.packageTable.get(packageName);
+            aconfigPackage.mFlagTable = files.flagTable;
+            aconfigPackage.mFlagValueList = files.flagValueList;
             aconfigPackage.mPackageBooleanStartOffset = pNode.getBooleanStartIndex();
             aconfigPackage.mPackageId = pNode.getPackageId();
             return aconfigPackage;
         } catch (AconfigStorageReadException e) {
             throw e;
+        } catch (AconfigStorageException e) {
+            throw new AconfigStorageReadException(
+                    e.getErrorCode(), "Fail to create AconfigPackage", e);
         } catch (Exception e) {
             throw new AconfigStorageReadException(
                     AconfigStorageReadException.ERROR_GENERIC, "Fail to create AconfigPackage", e);
-        } finally {
-            StrictMode.setThreadPolicy(oldPolicy);
         }
     }
 
@@ -144,6 +164,10 @@ public class AconfigPackage {
      */
     @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
     public boolean getBooleanFlagValue(@NonNull String flagName, boolean defaultValue) {
+        if (READ_PLATFORM_FROM_PLATFORM_API && mPlatformAconfigPackage != null) {
+            return mPlatformAconfigPackage.getBooleanFlagValue(flagName, defaultValue);
+        }
+
         FlagTable.Node fNode = mFlagTable.get(mPackageId, flagName);
         if (fNode == null) {
             return defaultValue;
diff --git a/framework/java/android/os/flagging/AconfigPackageInternal.java b/framework/java/android/os/flagging/AconfigPackageInternal.java
index 5d16ccc..e531199 100644
--- a/framework/java/android/os/flagging/AconfigPackageInternal.java
+++ b/framework/java/android/os/flagging/AconfigPackageInternal.java
@@ -16,13 +16,13 @@
 
 package android.os.flagging;
 
+import static android.aconfig.storage.TableUtils.StorageFilesBundle;
+
 import android.aconfig.storage.AconfigStorageException;
 import android.aconfig.storage.FlagValueList;
 import android.aconfig.storage.PackageTable;
-import android.aconfig.storage.StorageFileProvider;
 import android.annotation.NonNull;
 import android.compat.annotation.UnsupportedAppUsage;
-import android.os.StrictMode;
 
 /**
  * An {@code aconfig} package containing the enabled state of its flags.
@@ -56,7 +56,6 @@ public class AconfigPackageInternal {
      * <p>This method is intended for internal use only and may be changed or removed without
      * notice.
      *
-     * @param container The name of the container.
      * @param packageName The name of the Aconfig package.
      * @param packageFingerprint The expected fingerprint of the package.
      * @return An instance of {@link AconfigPackageInternal} representing the loaded package.
@@ -64,52 +63,20 @@ public class AconfigPackageInternal {
      */
     @UnsupportedAppUsage
     public static @NonNull AconfigPackageInternal load(
-            @NonNull String container, @NonNull String packageName, long packageFingerprint) {
-        return load(
-                container,
-                packageName,
-                packageFingerprint,
-                StorageFileProvider.getDefaultProvider());
-    }
-
-    /** @hide */
-    public static @NonNull AconfigPackageInternal load(
-            @NonNull String container,
-            @NonNull String packageName,
-            long packageFingerprint,
-            @NonNull StorageFileProvider fileProvider) {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
-        PackageTable.Node pNode = null;
-        FlagValueList vList = null;
-        try {
-            pNode = fileProvider.getPackageTable(container).get(packageName);
-            vList = fileProvider.getFlagValueList(container);
-        } catch (AconfigStorageException e) {
-            throw new AconfigStorageReadException(e.getErrorCode(), e.toString());
-        } finally {
-            StrictMode.setThreadPolicy(oldPolicy);
-        }
-
-        if (pNode == null || vList == null) {
-            throw new AconfigStorageReadException(
-                    AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
-                    String.format(
-                            "package "
-                                    + packageName
-                                    + " in container "
-                                    + container
-                                    + " cannot be found on the device"));
+            @NonNull String packageName, long packageFingerprint) {
+        StorageFilesBundle files = AconfigPackage.sStorageFilesCache.get(packageName);
+        if (files == null) {
+            throw new AconfigStorageException(
+                    AconfigStorageException.ERROR_PACKAGE_NOT_FOUND,
+                    "package " + packageName + " cannot be found on the device");
         }
+        PackageTable.Node pNode = files.packageTable.get(packageName);
+        FlagValueList vList = files.flagValueList;
 
         if (pNode.hasPackageFingerprint() && packageFingerprint != pNode.getPackageFingerprint()) {
-            throw new AconfigStorageReadException(
-                    5, // AconfigStorageReadException.ERROR_FILE_FINGERPRINT_MISMATCH,
-                    String.format(
-                            "package "
-                                    + packageName
-                                    + " in container "
-                                    + container
-                                    + " cannot be found on the device"));
+            throw new AconfigStorageException(
+                    AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    "package " + packageName + "fingerprint doesn't match the one on device");
         }
 
         return new AconfigPackageInternal(vList, pNode.getBooleanStartIndex());
diff --git a/framework/java/android/os/flagging/AconfigWriteException.java b/framework/java/android/os/flagging/AconfigStorageWriteException.java
similarity index 72%
rename from framework/java/android/os/flagging/AconfigWriteException.java
rename to framework/java/android/os/flagging/AconfigStorageWriteException.java
index 57aabc9..71c88c9 100644
--- a/framework/java/android/os/flagging/AconfigWriteException.java
+++ b/framework/java/android/os/flagging/AconfigStorageWriteException.java
@@ -28,15 +28,15 @@ import android.util.AndroidRuntimeException;
  * @hide
  */
 @SystemApi
-@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
-public class AconfigWriteException extends AndroidRuntimeException {
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
-    public AconfigWriteException(@NonNull String message) {
+@FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+public class AconfigStorageWriteException extends AndroidRuntimeException {
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+    public AconfigStorageWriteException(@NonNull String message) {
         super(message);
     }
 
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
-    public AconfigWriteException(@NonNull String message, @NonNull Throwable cause) {
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+    public AconfigStorageWriteException(@NonNull String message, @NonNull Throwable cause) {
         super(message, cause);
     }
 }
diff --git a/framework/java/android/os/flagging/AconfigdProtoStreamer.java b/framework/java/android/os/flagging/AconfigdProtoStreamer.java
new file mode 100644
index 0000000..05ada88
--- /dev/null
+++ b/framework/java/android/os/flagging/AconfigdProtoStreamer.java
@@ -0,0 +1,291 @@
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
+package android.os.flagging;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage;
+import android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessages;
+import android.internal.configinfra.aconfigd.x.Aconfigd.StorageReturnMessage;
+import android.internal.configinfra.aconfigd.x.Aconfigd.StorageReturnMessages;
+import android.net.LocalSocket;
+import android.net.LocalSocketAddress;
+import android.util.Slog;
+import android.util.configinfrastructure.proto.ProtoInputStream;
+import android.util.proto.ProtoOutputStream;
+
+import java.io.DataInputStream;
+import java.io.DataOutputStream;
+import java.io.IOException;
+import java.io.InputStream;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * Writes messages to aconfigd, and parses responses.
+ *
+ * <p>Uses ProtoInputStream, rather than a proto lite lib.
+ *
+ * @hide
+ */
+public final class AconfigdProtoStreamer {
+    private static final String SYSTEM_SOCKET_ADDRESS = "aconfigd_system";
+    private static final String MAINLINE_SOCKET_ADDRESS = "aconfigd_mainline";
+
+    private static final String TAG = "FlagManager";
+
+    /**
+     * Create a new AconfigdProtoStreamer.
+     *
+     * @hide
+     */
+    public AconfigdProtoStreamer() {}
+
+    /**
+     * Send override removal requests to aconfigd.
+     *
+     * @param flags the set of flag names to remove local overrides for
+     * @param removeType the type of removal: immediately, or on reboot
+     * @hide
+     */
+    public void sendClearFlagOverrideRequests(@NonNull Set<String> flags, long removeType)
+            throws IOException {
+        ProtoOutputStream requestOutputStream = new ProtoOutputStream();
+        for (Flag flag : Flag.buildFlagsWithoutValues(flags)) {
+            long msgsToken = requestOutputStream.start(StorageRequestMessages.MSGS);
+            long msgToken =
+                    requestOutputStream.start(StorageRequestMessage.REMOVE_LOCAL_OVERRIDE_MESSAGE);
+            requestOutputStream.write(
+                    StorageRequestMessage.RemoveLocalOverrideMessage.PACKAGE_NAME,
+                    flag.packageName);
+            requestOutputStream.write(
+                    StorageRequestMessage.RemoveLocalOverrideMessage.FLAG_NAME, flag.flagName);
+            requestOutputStream.write(
+                    StorageRequestMessage.RemoveLocalOverrideMessage.REMOVE_ALL, false);
+            requestOutputStream.write(
+                    StorageRequestMessage.RemoveLocalOverrideMessage.REMOVE_OVERRIDE_TYPE,
+                    removeType);
+            requestOutputStream.end(msgToken);
+            requestOutputStream.end(msgsToken);
+        }
+
+        sendBytesAndParseResponse(
+                requestOutputStream.getBytes(), StorageReturnMessage.REMOVE_LOCAL_OVERRIDE_MESSAGE);
+    }
+
+    /**
+     * Send OTA flag-staging requests to aconfigd.
+     *
+     * @param flags a map from flag names to the values that will be staged
+     * @param buildFingerprint the build fingerprint on which the values will be un-staged
+     * @hide
+     */
+    public void sendOtaFlagOverrideRequests(
+            @NonNull Map<String, Boolean> flags, @NonNull String buildFingerprint)
+            throws IOException {
+        ProtoOutputStream requestOutputStream = new ProtoOutputStream();
+        long msgsToken = requestOutputStream.start(StorageRequestMessages.MSGS);
+        long msgToken = requestOutputStream.start(StorageRequestMessage.OTA_STAGING_MESSAGE);
+        requestOutputStream.write(
+                StorageRequestMessage.OTAFlagStagingMessage.BUILD_ID, buildFingerprint);
+        for (Flag flag : Flag.buildFlags(flags)) {
+            long flagOverrideMsgToken =
+                    requestOutputStream.start(StorageRequestMessage.FLAG_OVERRIDE_MESSAGE);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.PACKAGE_NAME, flag.packageName);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.FLAG_NAME, flag.flagName);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.FLAG_VALUE, flag.value);
+            requestOutputStream.end(flagOverrideMsgToken);
+        }
+        requestOutputStream.end(msgToken);
+        requestOutputStream.end(msgsToken);
+
+        sendBytesAndParseResponse(
+                requestOutputStream.getBytes(), StorageReturnMessage.OTA_STAGING_MESSAGE);
+    }
+
+    /**
+     * Send flag override requests to aconfigd, and parse the response.
+     *
+     * @hide
+     */
+    public void sendFlagOverrideRequests(@NonNull Map<String, Boolean> flags, long overrideType)
+            throws IOException {
+        ProtoOutputStream requestOutputStream = new ProtoOutputStream();
+        for (Flag flag : Flag.buildFlags(flags)) {
+            long msgsToken = requestOutputStream.start(StorageRequestMessages.MSGS);
+            long msgToken = requestOutputStream.start(StorageRequestMessage.FLAG_OVERRIDE_MESSAGE);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.PACKAGE_NAME, flag.packageName);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.FLAG_NAME, flag.flagName);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.FLAG_VALUE, flag.value);
+            requestOutputStream.write(
+                    StorageRequestMessage.FlagOverrideMessage.OVERRIDE_TYPE, overrideType);
+            requestOutputStream.end(msgToken);
+            requestOutputStream.end(msgsToken);
+        }
+
+        sendBytesAndParseResponse(
+                requestOutputStream.getBytes(), StorageReturnMessage.FLAG_OVERRIDE_MESSAGE);
+    }
+
+    private void sendBytesAndParseResponse(byte[] requestBytes, long responseMessageToken)
+            throws IOException {
+        try {
+            LocalSocket systemSocket = new LocalSocket();
+            LocalSocketAddress systemAddress =
+                    new LocalSocketAddress(
+                            SYSTEM_SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
+            if (!systemSocket.isConnected()) {
+                systemSocket.connect(systemAddress);
+            }
+
+            InputStream inputStream = sendBytesOverSocket(requestBytes, systemSocket);
+            parseAconfigdResponse(inputStream, responseMessageToken);
+
+            systemSocket.shutdownInput();
+            systemSocket.shutdownOutput();
+            systemSocket.close();
+
+        } catch (IOException systemException) {
+            Slog.i(
+                    TAG,
+                    "failed to send request to system socket; trying mainline socket",
+                    systemException);
+
+            LocalSocket mainlineSocket = new LocalSocket();
+            LocalSocketAddress mainlineAddress =
+                    new LocalSocketAddress(
+                            MAINLINE_SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
+            if (!mainlineSocket.isConnected()) {
+                mainlineSocket.connect(mainlineAddress);
+            }
+
+            InputStream inputStream = sendBytesOverSocket(requestBytes, mainlineSocket);
+            parseAconfigdResponse(inputStream, responseMessageToken);
+
+            mainlineSocket.shutdownInput();
+            mainlineSocket.shutdownOutput();
+            mainlineSocket.close();
+        }
+    }
+
+    private InputStream sendBytesOverSocket(byte[] requestBytes, LocalSocket socket)
+            throws IOException {
+        InputStream responseInputStream = null;
+
+        DataInputStream inputStream = new DataInputStream(socket.getInputStream());
+        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
+        outputStream.writeInt(requestBytes.length);
+        outputStream.write(requestBytes);
+        responseInputStream = socket.getInputStream();
+
+        return responseInputStream;
+    }
+
+    private void parseAconfigdResponse(InputStream inputStream, long responseMessageToken)
+            throws IOException {
+        ProtoInputStream proto = new ProtoInputStream(inputStream);
+        while (true) {
+            long currentToken = proto.nextField();
+
+            if (currentToken == ProtoInputStream.NO_MORE_FIELDS) {
+                return;
+            }
+
+            if (currentToken != ((int) StorageReturnMessages.MSGS)) {
+                continue;
+            }
+
+            long msgsToken = proto.start(StorageReturnMessages.MSGS);
+            long nextToken = proto.nextField();
+
+            if (nextToken == ((int) responseMessageToken)) {
+                long msgToken = proto.start(responseMessageToken);
+                proto.end(msgToken);
+            } else if (nextToken == ((int) StorageReturnMessage.ERROR_MESSAGE)) {
+                String errmsg = proto.readString(StorageReturnMessage.ERROR_MESSAGE);
+                throw new IOException("override request failed: " + errmsg);
+            } else if (nextToken == ProtoInputStream.NO_MORE_FIELDS) {
+                // Do nothing.
+            } else {
+                throw new IOException(
+                        "invalid message type, expecting only return message"
+                                + " or error message");
+            }
+
+            proto.end(msgsToken);
+        }
+    }
+
+    private static class Flag {
+        public final String packageName;
+        public final String flagName;
+        public final String value;
+
+        public Flag(
+                @NonNull String packageName, @NonNull String flagName, @Nullable Boolean value) {
+            this.packageName = packageName;
+            this.flagName = flagName;
+
+            if (value != null) {
+                this.value = Boolean.toString(value);
+            } else {
+                this.value = null;
+            }
+        }
+
+        public static Set<Flag> buildFlags(@NonNull Map<String, Boolean> flags) {
+            HashSet<Flag> flagSet = new HashSet();
+            for (Map.Entry<String, Boolean> flagAndValue : flags.entrySet()) {
+                String packageName = "";
+                String flagName = flagAndValue.getKey();
+
+                int periodIndex = flagName.lastIndexOf(".");
+                if (periodIndex != -1) {
+                    packageName = flagName.substring(0, flagName.lastIndexOf("."));
+                    flagName = flagName.substring(flagName.lastIndexOf(".") + 1);
+                }
+
+                flagSet.add(new Flag(packageName, flagName, flagAndValue.getValue()));
+            }
+            return flagSet;
+        }
+
+        public static Set<Flag> buildFlagsWithoutValues(@NonNull Set<String> flags) {
+            HashSet<Flag> flagSet = new HashSet();
+            for (String qualifiedFlagName : flags) {
+                String packageName = "";
+                String flagName = qualifiedFlagName;
+                int periodIndex = qualifiedFlagName.lastIndexOf(".");
+                if (periodIndex != -1) {
+                    packageName =
+                            qualifiedFlagName.substring(0, qualifiedFlagName.lastIndexOf("."));
+                    flagName = qualifiedFlagName.substring(qualifiedFlagName.lastIndexOf(".") + 1);
+                }
+
+                flagSet.add(new Flag(packageName, flagName, null));
+            }
+            return flagSet;
+        }
+    }
+}
diff --git a/framework/java/android/os/flagging/AconfigdSocketWriter.java b/framework/java/android/os/flagging/AconfigdSocketWriter.java
deleted file mode 100644
index eac4b70..0000000
--- a/framework/java/android/os/flagging/AconfigdSocketWriter.java
+++ /dev/null
@@ -1,96 +0,0 @@
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
-package android.os.flagging;
-
-import android.aconfigd.Aconfigd.StorageRequestMessages;
-import android.aconfigd.Aconfigd.StorageReturnMessages;
-import android.annotation.NonNull;
-import android.net.LocalSocket;
-import android.net.LocalSocketAddress;
-
-import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
-import java.util.Arrays;
-
-/**
- * Writes messages to aconfigd, and parses responses.
- *
- * @hide
- */
-final class AconfigdSocketWriter {
-    private static final String SOCKET_ADDRESS = "aconfigd_system";
-
-    private final LocalSocket mSocket;
-
-    /**
-     * Create a new aconfigd socket connection.
-     *
-     * @hide
-     */
-    public AconfigdSocketWriter() throws IOException {
-        mSocket = new LocalSocket();
-        LocalSocketAddress address =
-                new LocalSocketAddress(SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
-        if (!mSocket.isConnected()) {
-            mSocket.connect(address);
-        }
-    }
-
-    /**
-     * Serialize {@code messages}, send to aconfigd, then receive and parse response.
-     *
-     * @param messages messages to send to aconfigd
-     * @return a {@code StorageReturnMessages} received from the socket
-     * @throws IOException if there is an IOException communicating with the socket
-     * @hide
-     */
-    public StorageReturnMessages sendMessages(@NonNull StorageRequestMessages messages)
-            throws IOException {
-        OutputStream outputStream = mSocket.getOutputStream();
-        byte[] requestMessageBytes = messages.toByteArray();
-        outputStream.write(ByteBuffer.allocate(4).putInt(requestMessageBytes.length).array());
-        outputStream.write(requestMessageBytes);
-        outputStream.flush();
-
-        InputStream inputStream = mSocket.getInputStream();
-        byte[] lengthBytes = new byte[4];
-        int bytesRead = inputStream.read(lengthBytes);
-        if (bytesRead != 4) {
-            throw new IOException(
-                    "Failed to read message length. Expected 4 bytes, read "
-                            + bytesRead
-                            + " bytes, with content: "
-                            + Arrays.toString(lengthBytes));
-        }
-        int messageLength = ByteBuffer.wrap(lengthBytes).order(ByteOrder.BIG_ENDIAN).getInt();
-        byte[] responseMessageBytes = new byte[messageLength];
-        bytesRead = inputStream.read(responseMessageBytes);
-        if (bytesRead != messageLength) {
-            throw new IOException(
-                    "Failed to read complete message. Expected "
-                            + messageLength
-                            + " bytes, read "
-                            + bytesRead
-                            + " bytes");
-        }
-
-        return StorageReturnMessages.parseFrom(responseMessageBytes);
-    }
-}
diff --git a/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java b/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java
index 3d7e655..814a095 100644
--- a/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java
+++ b/framework/java/android/os/flagging/ConfigInfrastructureFrameworkInitializer.java
@@ -27,7 +27,7 @@ import android.provider.flags.Flags;
  * @hide
  */
 @SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
-@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+@FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
 public final class ConfigInfrastructureFrameworkInitializer {
     /** Prevent instantiation. */
     private ConfigInfrastructureFrameworkInitializer() {}
@@ -40,7 +40,7 @@ public final class ConfigInfrastructureFrameworkInitializer {
      * <p>If this is called from other places, it throws a {@link IllegalStateException).
      *
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public static void registerServiceWrappers() {
         SystemServiceRegistry.registerContextAwareService(
                 FlagManager.FLAG_SERVICE_NAME,
diff --git a/framework/java/android/os/flagging/FlagManager.java b/framework/java/android/os/flagging/FlagManager.java
index 1566e15..a582d8f 100644
--- a/framework/java/android/os/flagging/FlagManager.java
+++ b/framework/java/android/os/flagging/FlagManager.java
@@ -16,13 +16,6 @@
 
 package android.os.flagging;
 
-import android.aconfigd.Aconfigd.FlagOverride;
-import android.aconfigd.Aconfigd.StorageRequestMessage;
-import android.aconfigd.Aconfigd.StorageRequestMessage.FlagOverrideType;
-import android.aconfigd.Aconfigd.StorageRequestMessage.RemoveOverrideType;
-import android.aconfigd.Aconfigd.StorageRequestMessages;
-import android.aconfigd.Aconfigd.StorageReturnMessage;
-import android.aconfigd.Aconfigd.StorageReturnMessages;
 import android.annotation.FlaggedApi;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -32,7 +25,6 @@ import android.content.Context;
 import android.provider.flags.Flags;
 
 import java.io.IOException;
-import java.util.HashSet;
 import java.util.Map;
 import java.util.Set;
 
@@ -42,7 +34,7 @@ import java.util.Set;
  * @hide
  */
 @SystemApi
-@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+@FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
 @SystemService(FlagManager.FLAG_SERVICE_NAME)
 public final class FlagManager {
     /**
@@ -50,7 +42,7 @@ public final class FlagManager {
      *
      * @hide
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public FlagManager(@NonNull Context unusedContext) {}
 
     /**
@@ -58,10 +50,9 @@ public final class FlagManager {
      * android.os.flagging.FlagManager} for pushing flag values to aconfig.
      *
      * @see Context#getSystemService(String)
-     *
      * @hide
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public static final String FLAG_SERVICE_NAME = "flag";
 
     /**
@@ -81,15 +72,18 @@ public final class FlagManager {
      *
      * @param buildFingerprint a system build fingerprint identifier.
      * @param flags map from flag qualified name to new value.
-     * @throws AconfigWriteException if the write fails.
+     * @throws AconfigStorageWriteException if the write fails.
      * @see android.os.Build.FINGERPRINT
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void setBooleanOverridesOnSystemBuildFingerprint(
             @NonNull String buildFingerprint, @NonNull Map<String, Boolean> flags) {
-        StorageRequestMessages requestMessages =
-                buildOtaFlagStagingMessages(Flag.buildFlags(flags), buildFingerprint);
-        sendMessages(requestMessages);
+        try {
+            (new AconfigdProtoStreamer()).sendOtaFlagOverrideRequests(flags, buildFingerprint);
+        } catch (IOException e) {
+            throw new AconfigStorageWriteException(
+                    "failed to set boolean overrides on system build fingerprint", e);
+        }
     }
 
     /**
@@ -100,15 +94,19 @@ public final class FlagManager {
      * set of flags to take effect is determined on the next boot.
      *
      * @param flags map from flag qualified name to new value.
-     * @throws AconfigWriteException if the write fails.
-     *
+     * @throws AconfigStorageWriteException if the write fails.
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void setBooleanOverridesOnReboot(@NonNull Map<String, Boolean> flags) {
-        StorageRequestMessages requestMessages =
-                buildFlagOverrideMessages(
-                        Flag.buildFlags(flags), FlagOverrideType.SERVER_ON_REBOOT);
-        sendMessages(requestMessages);
+        try {
+            (new AconfigdProtoStreamer())
+                    .sendFlagOverrideRequests(
+                            flags,
+                            android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage
+                                    .SERVER_ON_REBOOT);
+        } catch (IOException e) {
+            throw new AconfigStorageWriteException("failed to set boolean overrides on reboot", e);
+        }
     }
 
     /**
@@ -121,11 +119,17 @@ public final class FlagManager {
      * @see clearBooleanLocalOverridesOnReboot
      * @see clearBooleanLocalOverridesImmediately
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void setBooleanLocalOverridesOnReboot(@NonNull Map<String, Boolean> flags) {
-        StorageRequestMessages requestMessages =
-                buildFlagOverrideMessages(Flag.buildFlags(flags), FlagOverrideType.LOCAL_ON_REBOOT);
-        sendMessages(requestMessages);
+        try {
+            (new AconfigdProtoStreamer())
+                    .sendFlagOverrideRequests(
+                            flags,
+                            android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage
+                                    .LOCAL_ON_REBOOT);
+        } catch (IOException e) {
+            throw new AconfigStorageWriteException("failed to set boolean overrides on reboot", e);
+        }
     }
 
     /**
@@ -141,11 +145,17 @@ public final class FlagManager {
      * @see clearBooleanLocalOverridesOnReboot
      * @see clearBooleanLocalOverridesImmediately
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void setBooleanLocalOverridesImmediately(@NonNull Map<String, Boolean> flags) {
-        StorageRequestMessages requestMessages =
-                buildFlagOverrideMessages(Flag.buildFlags(flags), FlagOverrideType.LOCAL_IMMEDIATE);
-        sendMessages(requestMessages);
+        try {
+            (new AconfigdProtoStreamer())
+                    .sendFlagOverrideRequests(
+                            flags,
+                            android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage
+                                    .LOCAL_IMMEDIATE);
+        } catch (IOException e) {
+            throw new AconfigStorageWriteException("failed to set boolean overrides on reboot", e);
+        }
     }
 
     /**
@@ -157,13 +167,17 @@ public final class FlagManager {
      * @see setBooleanLocalOverridesOnReboot
      * @see setBooleanLocalOverridesImmediately
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void clearBooleanLocalOverridesOnReboot(@Nullable Set<String> flags) {
-        StorageRequestMessages requestMessages =
-                buildClearFlagOverridesMessages(
-                        Flag.buildFlagsWithoutValues(flags),
-                        RemoveOverrideType.REMOVE_LOCAL_ON_REBOOT);
-        sendMessages(requestMessages);
+        try {
+            (new AconfigdProtoStreamer())
+                    .sendClearFlagOverrideRequests(
+                            flags,
+                            android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage
+                                    .REMOVE_LOCAL_ON_REBOOT);
+        } catch (IOException e) {
+            throw new AconfigStorageWriteException("failed to set boolean overrides on reboot", e);
+        }
     }
 
     /**
@@ -178,135 +192,16 @@ public final class FlagManager {
      * @see setBooleanLocalOverridesOnReboot
      * @see setBooleanLocalOverridesImmediately
      */
-    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void clearBooleanLocalOverridesImmediately(@Nullable Set<String> flags) {
-        StorageRequestMessages requestMessages =
-                buildClearFlagOverridesMessages(
-                        Flag.buildFlagsWithoutValues(flags),
-                        RemoveOverrideType.REMOVE_LOCAL_IMMEDIATE);
-        sendMessages(requestMessages);
-    }
-
-    private void sendMessages(StorageRequestMessages messages) {
         try {
-            StorageReturnMessages returnMessages =
-                    (new AconfigdSocketWriter()).sendMessages(messages);
-
-            String errorMessage = "";
-            for (StorageReturnMessage message : returnMessages.getMsgsList()) {
-                if (message.hasErrorMessage()) {
-                    errorMessage += message.getErrorMessage() + "\n";
-                }
-            }
-
-            if (!errorMessage.isEmpty()) {
-                throw new AconfigWriteException("error(s) writing aconfig flags: " + errorMessage);
-            }
+            (new AconfigdProtoStreamer())
+                    .sendClearFlagOverrideRequests(
+                            flags,
+                            android.internal.configinfra.aconfigd.x.Aconfigd.StorageRequestMessage
+                                    .REMOVE_LOCAL_IMMEDIATE);
         } catch (IOException e) {
-            throw new AconfigWriteException("IO error writing aconfig flags", e);
-        }
-    }
-
-    private static class Flag {
-        public final String packageName;
-        public final String flagName;
-        public final String value;
-
-        public Flag(@NonNull String qualifiedName, @Nullable Boolean value) {
-            packageName = qualifiedName.substring(0, qualifiedName.lastIndexOf("."));
-            flagName = qualifiedName.substring(qualifiedName.lastIndexOf(".") + 1);
-            this.value = Boolean.toString(value);
-        }
-
-        public static Set<Flag> buildFlags(@NonNull Map<String, Boolean> flags) {
-            HashSet<Flag> flagSet = new HashSet();
-            for (Map.Entry<String, Boolean> flagAndValue : flags.entrySet()) {
-                flagSet.add(new Flag(flagAndValue.getKey(), flagAndValue.getValue()));
-            }
-            return flagSet;
-        }
-
-        public static Set<Flag> buildFlagsWithoutValues(@NonNull Set<String> flags) {
-            HashSet<Flag> flagSet = new HashSet();
-            for (String flag : flags) {
-                flagSet.add(new Flag(flag, null));
-            }
-            return flagSet;
-        }
-    }
-
-    private static StorageRequestMessages buildFlagOverrideMessages(
-            @NonNull Set<Flag> flagSet, FlagOverrideType overrideType) {
-        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
-        for (Flag flag : flagSet) {
-            StorageRequestMessage.FlagOverrideMessage message =
-                    StorageRequestMessage.FlagOverrideMessage.newBuilder()
-                            .setPackageName(flag.packageName)
-                            .setFlagName(flag.flagName)
-                            .setFlagValue(flag.value)
-                            .setOverrideType(overrideType)
-                            .build();
-            StorageRequestMessage requestMessage =
-                    StorageRequestMessage.newBuilder().setFlagOverrideMessage(message).build();
-            requestMessagesBuilder.addMsgs(requestMessage);
-        }
-        return requestMessagesBuilder.build();
-    }
-
-    private static StorageRequestMessages buildOtaFlagStagingMessages(
-            @NonNull Set<Flag> flagSet, @NonNull String buildFingerprint) {
-        StorageRequestMessage.OTAFlagStagingMessage.Builder otaMessageBuilder =
-                StorageRequestMessage.OTAFlagStagingMessage.newBuilder()
-                        .setBuildId(buildFingerprint);
-        for (Flag flag : flagSet) {
-            FlagOverride override =
-                    FlagOverride.newBuilder()
-                            .setPackageName(flag.packageName)
-                            .setFlagName(flag.flagName)
-                            .setFlagValue(flag.value)
-                            .build();
-            otaMessageBuilder.addOverrides(override);
-        }
-        StorageRequestMessage.OTAFlagStagingMessage otaMessage = otaMessageBuilder.build();
-        StorageRequestMessage requestMessage =
-                StorageRequestMessage.newBuilder().setOtaStagingMessage(otaMessage).build();
-        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
-        requestMessagesBuilder.addMsgs(requestMessage);
-        return requestMessagesBuilder.build();
-    }
-
-    private static StorageRequestMessages buildClearFlagOverridesMessages(
-            @Nullable Set<Flag> flagSet, RemoveOverrideType removeOverrideType) {
-        StorageRequestMessages.Builder requestMessagesBuilder = StorageRequestMessages.newBuilder();
-
-        if (flagSet == null) {
-            StorageRequestMessage.RemoveLocalOverrideMessage message =
-                    StorageRequestMessage.RemoveLocalOverrideMessage.newBuilder()
-                            .setRemoveAll(true)
-                            .setRemoveOverrideType(removeOverrideType)
-                            .build();
-            StorageRequestMessage requestMessage =
-                    StorageRequestMessage.newBuilder()
-                            .setRemoveLocalOverrideMessage(message)
-                            .build();
-            requestMessagesBuilder.addMsgs(requestMessage);
-            return requestMessagesBuilder.build();
-        }
-
-        for (Flag flag : flagSet) {
-            StorageRequestMessage.RemoveLocalOverrideMessage message =
-                    StorageRequestMessage.RemoveLocalOverrideMessage.newBuilder()
-                            .setPackageName(flag.packageName)
-                            .setFlagName(flag.flagName)
-                            .setRemoveOverrideType(removeOverrideType)
-                            .setRemoveAll(false)
-                            .build();
-            StorageRequestMessage requestMessage =
-                    StorageRequestMessage.newBuilder()
-                            .setRemoveLocalOverrideMessage(message)
-                            .build();
-            requestMessagesBuilder.addMsgs(requestMessage);
+            throw new AconfigStorageWriteException("failed to set boolean overrides on reboot", e);
         }
-        return requestMessagesBuilder.build();
     }
 }
diff --git a/framework/java/android/provider/DeviceConfig.java b/framework/java/android/provider/DeviceConfig.java
index 5133ed7..f399eb7 100644
--- a/framework/java/android/provider/DeviceConfig.java
+++ b/framework/java/android/provider/DeviceConfig.java
@@ -445,6 +445,24 @@ public final class DeviceConfig {
     @SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
     public static final String NAMESPACE_MGLRU_NATIVE = "mglru_native";
 
+    /**
+     * Namespace for all memory management related features.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(Flags.FLAG_MMD_DEVICE_CONFIG)
+    public static final String NAMESPACE_MM = "mm";
+
+    /**
+     * Namespace for all mmd native related features.
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(Flags.FLAG_MMD_DEVICE_CONFIG)
+    public static final String NAMESPACE_MMD_NATIVE = "mmd_native";
+
     /**
      * Namespace for all netd related features.
      *
@@ -1560,17 +1578,13 @@ public final class DeviceConfig {
         }
     }
 
-    // TODO(b/364399200): should provide a getOnPropertiesChangedListeners() methods instead and let
-    // caller implement dump() instead
-
     // NOTE: this API is only used by the framework code, but using MODULE_LIBRARIES causes a
     // build-time error on CtsDeviceConfigTestCases, so it's using PRIVILEGED_APPS.
     /**
      * Dumps internal state into the given {@code fd} or {@code printWriter}.
      *
-     * <p><b>Note:</b> Currently the only supported argument is
-     * {@link DeviceConfig#DUMP_ARG_NAMESPACE}, which will filter the output using a substring of
-     * the next argument. But other arguments might be
+     * <p><b>Note:</b> Currently the only supported argument is {@link #DUMP_ARG_NAMESPACE} which
+     * will filter the output using a substring of the next argument. But other arguments might be
      * dynamically added in the future, without documentation - this method is meant only for
      * debugging purposes, and should not be used as a formal API.
      *
diff --git a/framework/java/android/provider/OWNERS b/framework/java/android/provider/OWNERS
index 66438db..7132c3e 100644
--- a/framework/java/android/provider/OWNERS
+++ b/framework/java/android/provider/OWNERS
@@ -1,2 +1,2 @@
-per-file WritableFlags.java = mpgroover@google.com,tedbauer@google.com
-per-file WritableNamespaces.java = mpgroover@google.com,tedbauer@google.com
+per-file WritableFlags.java = mpgroover@google.com
+per-file WritableNamespaces.java = mpgroover@google.com
diff --git a/framework/java/android/provider/StageOtaFlags.java b/framework/java/android/provider/StageOtaFlags.java
index 74d697b..09e85b3 100644
--- a/framework/java/android/provider/StageOtaFlags.java
+++ b/framework/java/android/provider/StageOtaFlags.java
@@ -15,159 +15,75 @@
  */
 package android.provider;
 
-import android.aconfigd.Aconfigd.FlagOverride;
-import android.aconfigd.Aconfigd.StorageRequestMessage;
-import android.aconfigd.Aconfigd.StorageRequestMessages;
-import android.aconfigd.Aconfigd.StorageReturnMessages;
-import android.annotation.IntDef;
 import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.SystemApi;
-import android.net.LocalSocket;
-import android.net.LocalSocketAddress;
+import android.os.flagging.AconfigdProtoStreamer;
 import android.provider.flags.Flags;
 import android.util.AndroidRuntimeException;
 import android.util.Log;
+
 import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.io.File;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
-import java.util.Map;
-import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.Map;
 
 /** @hide */
 @SystemApi
 @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
 public final class StageOtaFlags {
-  private static String LOG_TAG = "StageOtaFlags";
-  private static final String SOCKET_ADDRESS = "aconfigd_system";
-  private static final String STORAGE_MARKER_FILE_PATH
-        = "/metadata/aconfig/boot/enable_only_new_storage";
-
-  /** Aconfig storage is disabled and unavailable for writes. @hide */
-  @SystemApi public static final int STATUS_STORAGE_NOT_ENABLED = -1;
-  /** Stage request was successful. @hide */
-  @SystemApi public static final int STATUS_STAGE_SUCCESS = 0;
-
-  /** @hide */
-  @IntDef(prefix = { "STATUS_" }, value = {
-    STATUS_STORAGE_NOT_ENABLED,
-    STATUS_STAGE_SUCCESS,
-  })
-  @Retention(RetentionPolicy.SOURCE)
-  public @interface StageStatus {}
-
-  private StageOtaFlags() {}
-
-  /**
-   * Stage aconfig flags to be applied when booting into {@code buildId}.
-   *
-   * <p>Only a single {@code buildId} and its corresponding flags are stored at once. Every
-   * invocation of this method will overwrite whatever mapping was previously stored.
-   *
-   * <p>It is an implementation error to call this if the storage is not initialized and ready to
-   * receive writes. Callers must ensure that it is available before invoking.
-   *
-   * <p>TODO(b/361783454): create an isStorageAvailable API and mention it in this docstring.
-   *
-   * @param flags a map from {@code <packagename>.<flagname>} to flag values
-   * @param buildId when the device boots into buildId, it will apply {@code flags}
-   * @throws AndroidRuntimeException if communication with aconfigd fails
-   * @hide
-   */
-  @SystemApi
-  @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
-  @StageStatus
-  public static int stageBooleanAconfigFlagsForBuild(
-      @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
-    int flagCount = flags.size();
-    Log.d(LOG_TAG, "stageFlagsForBuild invoked for " + flagCount + " flags");
-
-    try {
-      LocalSocket socket = new LocalSocket();
-      LocalSocketAddress address =
-          new LocalSocketAddress(SOCKET_ADDRESS, LocalSocketAddress.Namespace.RESERVED);
-      if (!socket.isConnected()) {
-        socket.connect(address);
-      }
-      InputStream inputStream = socket.getInputStream();
-      OutputStream outputStream = socket.getOutputStream();
-
-      StorageRequestMessages requestMessages = buildRequestMessages(flags, buildId);
-
-      writeToSocket(outputStream, requestMessages);
-      readFromSocket(inputStream);
-    } catch (IOException e) {
-      throw new AndroidRuntimeException(e);
-    }
-
-    return STATUS_STAGE_SUCCESS;
-  }
-
-  private static void writeToSocket(
-      OutputStream outputStream, StorageRequestMessages requestMessages) throws IOException {
-    byte[] messageBytes = requestMessages.toByteArray();
-    outputStream.write(ByteBuffer.allocate(4).putInt(messageBytes.length).array());
-    outputStream.write(messageBytes);
-    outputStream.flush();
-  }
-
-  private static StorageReturnMessages readFromSocket(InputStream inputStream) throws IOException {
-    byte[] lengthBytes = new byte[4];
-    int bytesRead = inputStream.read(lengthBytes);
-    if (bytesRead != 4) {
-      throw new IOException("Failed to read message length");
-    }
-
-    int messageLength = ByteBuffer.wrap(lengthBytes).order(ByteOrder.BIG_ENDIAN).getInt();
-
-    byte[] messageBytes = new byte[messageLength];
-    bytesRead = inputStream.read(messageBytes);
-    if (bytesRead != messageLength) {
-      throw new IOException("Failed to read complete message");
-    }
-
-    return StorageReturnMessages.parseFrom(messageBytes);
-  }
-
-  private static StorageRequestMessages buildRequestMessages(
-      @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
-    StorageRequestMessage.OTAFlagStagingMessage.Builder otaMessageBuilder =
-        StorageRequestMessage.OTAFlagStagingMessage.newBuilder().setBuildId(buildId);
-    for (Map.Entry<String, Boolean> flagAndValue : flags.entrySet()) {
-      String qualifiedFlagName = flagAndValue.getKey();
-
-      // aconfig flags follow a package_name [dot] flag_name convention and will always have
-      // a [dot] character in the flag name.
-      //
-      // If a [dot] character wasn't found it's likely because this was a legacy flag. We make no
-      // assumptions here and still attempt to stage these flags with aconfigd and let it decide
-      // whether to use the flag / discard it.
-      String packageName = "";
-      String flagName = qualifiedFlagName;
-      int idx = qualifiedFlagName.lastIndexOf(".");
-      if (idx != -1) {
-        packageName = qualifiedFlagName.substring(0, qualifiedFlagName.lastIndexOf("."));
-        flagName = qualifiedFlagName.substring(qualifiedFlagName.lastIndexOf(".") + 1);
-      }
-
-      String value = flagAndValue.getValue() ? "true" : "false";
-      FlagOverride override =
-          FlagOverride.newBuilder()
-              .setPackageName(packageName)
-              .setFlagName(flagName)
-              .setFlagValue(value)
-              .build();
-      otaMessageBuilder.addOverrides(override);
+    private static String LOG_TAG = "StageOtaFlags";
+    private static final String SOCKET_ADDRESS = "aconfigd_system";
+    private static final String STORAGE_MARKER_FILE_PATH =
+            "/metadata/aconfig/boot/enable_only_new_storage";
+
+    /** Aconfig storage is disabled and unavailable for writes. @hide */
+    @SystemApi public static final int STATUS_STORAGE_NOT_ENABLED = -1;
+
+    /** Stage request was successful. @hide */
+    @SystemApi public static final int STATUS_STAGE_SUCCESS = 0;
+
+    /** @hide */
+    @IntDef(
+            prefix = {"STATUS_"},
+            value = {
+                STATUS_STORAGE_NOT_ENABLED,
+                STATUS_STAGE_SUCCESS,
+            })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface StageStatus {}
+
+    private StageOtaFlags() {}
+
+    /**
+     * Stage aconfig flags to be applied when booting into {@code buildId}.
+     *
+     * <p>Only a single {@code buildId} and its corresponding flags are stored at once. Every
+     * invocation of this method will overwrite whatever mapping was previously stored.
+     *
+     * <p>It is an implementation error to call this if the storage is not initialized and ready to
+     * receive writes. Callers must ensure that it is available before invoking.
+     *
+     * <p>TODO(b/361783454): create an isStorageAvailable API and mention it in this docstring.
+     *
+     * @param flags a map from {@code <packagename>.<flagname>} to flag values
+     * @param buildId when the device boots into buildId, it will apply {@code flags}
+     * @throws AndroidRuntimeException if communication with aconfigd fails
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+    @StageStatus
+    public static int stageBooleanAconfigFlagsForBuild(
+            @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
+        int flagCount = flags.size();
+        Log.d(LOG_TAG, "stageFlagsForBuild invoked for " + flagCount + " flags");
+        try {
+            (new AconfigdProtoStreamer()).sendOtaFlagOverrideRequests(flags, buildId);
+        } catch (IOException e) {
+            throw new AndroidRuntimeException(e);
+        }
+        return STATUS_STAGE_SUCCESS;
     }
-    StorageRequestMessage.OTAFlagStagingMessage otaMessage = otaMessageBuilder.build();
-    StorageRequestMessage requestMessage =
-        StorageRequestMessage.newBuilder().setOtaStagingMessage(otaMessage).build();
-    StorageRequestMessages requestMessages =
-        StorageRequestMessages.newBuilder().addMsgs(requestMessage).build();
-    return requestMessages;
-  }
 }
diff --git a/framework/java/android/provider/WritableFlags.java b/framework/java/android/provider/WritableFlags.java
index e6c1f77..a75de8a 100644
--- a/framework/java/android/provider/WritableFlags.java
+++ b/framework/java/android/provider/WritableFlags.java
@@ -26,12 +26,39 @@ final class WritableFlags {
                 "activity_manager/am_block_activity_starts_after_home",
                 "activity_manager/android_app_data_isolation_min_sdk",
                 "activity_manager/background_activity_starts_package_names_whitelist",
+                "activity_manager/bg_battery_exemption_enabled",
                 "activity_manager/bg_abusive_notification_minimal_interval",
                 "activity_manager/bg_auto_restricted_bucket_on_bg_restricted",
+                "activity_manager/bg_bind_svc_monitor_enabled",
+                "activity_manager/bg_bind_svc_window",
+                "activity_manager/bg_broadcast_monitor_enabled",
+                "activity_manager/bg_broadcast_window",
                 "activity_manager/bg_current_drain_auto_restrict_abusive_apps_enabled",
+                "activity_manager/bg_current_drain_decouple_thresholds",
+                "activity_manager/bg_current_drain_event_duration_based_threshold_enabled",
+                "activity_manager/bg_current_drain_exempted_types",
+                "activity_manager/bg_current_drain_high_threshold_by_bg_location",
+                "activity_manager/bg_current_drain_high_threshold_to_bg_restricted",
+                "activity_manager/bg_current_drain_high_threshold_to_restricted_bucket",
+                "activity_manager/bg_current_drain_interaction_grace_period",
+                "activity_manager/bg_current_drain_location_min_duration",
+                "activity_manager/bg_current_drain_media_playback_min_duration",
+                "activity_manager/bg_current_drain_monitor_enabled",
                 "activity_manager/bg_current_drain_threshold_to_bg_restricted",
+                "activity_manager/bg_current_drain_threshold_to_restricted_bucket",
+                "activity_manager/bg_current_drain_window",
+                "activity_manager/bg_ex_bind_svc_threshold",
+                "activity_manager/bg_ex_broadcast_threshold",
+                "activity_manager/bg_fgs_location_threshold",
+                "activity_manager/bg_fgs_long_running_threshold",
+                "activity_manager/bg_fgs_long_running_window",
+                "activity_manager/bg_fgs_media_playback_threshold",
+                "activity_manager/bg_fgs_monitor_enabled",
+                "activity_manager/bg_permission_monitor_enabled",
                 "activity_manager/bg_prompt_abusive_apps_to_bg_restricted",
                 "activity_manager/bg_prompt_fgs_on_long_running",
+                "activity_manager/bg_prompt_fgs_with_noti_on_long_running",
+                "activity_manager/bg_prompt_fgs_with_noti_to_bg_restricted",
                 "activity_manager/compact_full_delta_rss_throttle_kb",
                 "activity_manager/compact_full_rss_throttle_kb",
                 "activity_manager/compact_proc_state_throttle",
@@ -40,9 +67,15 @@ final class WritableFlags {
                 "activity_manager/data_sync_fgs_timeout_duration",
                 "activity_manager/default_background_activity_starts_enabled",
                 "activity_manager/default_background_fgs_starts_restriction_enabled",
+                "activity_manager/default_fgs_starts_restriction_enabled",
                 "activity_manager/enable_app_start_info",
+                "activity_manager/enable_extra_delay_svc_restart_mem_pressure",
                 "activity_manager/enforce_exported_flag_requirement",
+                "activity_manager/extra_delay_svc_restart_mem_pressure",
                 "activity_manager/fgs_crash_extra_wait_duration",
+                "activity_manager/fgs_saw_restrictions_enabled",
+                "activity_manager/fgs_start_foreground_timeout",
+                "activity_manager/fgs_type_fg_perm_enforcement_flag",
                 "activity_manager/fgs_type_perm_enforcement_flag_camera",
                 "activity_manager/fgs_type_perm_enforcement_flag_connected_device",
                 "activity_manager/fgs_type_perm_enforcement_flag_data_sync",
@@ -90,11 +123,14 @@ final class WritableFlags {
                 "alarm_manager/app_standby_restricted_window",
                 "alarm_manager/app_standby_window",
                 "alarm_manager/lazy_batching",
-                "alarm_manager/max_alarm_managers_per_uid",
+                "alarm_manager/max_alarms_per_uid",
                 "alarm_manager/min_futurity",
                 "alarm_manager/min_interval",
                 "alarm_manager/min_window",
-                "alarm_manager/priority_alarm_manager_delay",
+                "alarm_manager/priority_alarm_delay",
+                "alarm_manager/standby_quota_frequent",
+                "alarm_manager/standby_quota_rare",
+                "alarm_manager/standby_quota_working",
                 "alarm_manager/temporary_quota_bump",
                 "ambient_context/service_enabled",
                 "android/system_gesture_exclusion_limit_dp",
@@ -103,50 +139,6 @@ final class WritableFlags {
                 "app_compat/hidden_api_access_statslog_sampling_rate",
                 "app_compat/hidden_api_log_sampling_rate",
                 "app_compat/hidden_api_statslog_sampling_rate",
-                "app_compat_overrides/cn_wps_moffice_eng_flag",
-                "app_compat_overrides/com_amanotes_beathopper_flag",
-                "app_compat_overrides/com.android.cts.appcompat.preinstalloverride",
-                "app_compat_overrides/com_balaji_alt_flag",
-                "app_compat_overrides/com_camerasideas_instashot_flag",
-                "app_compat_overrides/com_facebook_lite_flag",
-                "app_compat_overrides/com_facebook_orca_flag",
-                "app_compat_overrides/com_facebook_pages_app_flag",
-                "app_compat_overrides/com_gaana_flag",
-                "app_compat_overrides/com_instagram_android_flag",
-                "app_compat_overrides/com_kakao_talk_flag",
-                "app_compat_overrides/com_korail_talk_flag",
-                "app_compat_overrides/com_ludo_king_flag",
-                "app_compat_overrides/com_microsoft_appmanager_flag",
-                "app_compat_overrides/com_microsoft_office_officehubrow_flag",
-                "app_compat_overrides/com_myairtelapp_flag",
-                "app_compat_overrides/com_opera_browser_flag",
-                "app_compat_overrides/com_picsart_studio_flag",
-                "app_compat_overrides/com_pinterest_flag",
-                "app_compat_overrides/com_reddit_frontpage_flag",
-                "app_compat_overrides/com_roblox_client_flag",
-                "app_compat_overrides/com_rsupport_mvagent_flag",
-                "app_compat_overrides/com_sh_smart_caller_flag",
-                "app_compat_overrides/com_skype_raider_flag",
-                "app_compat_overrides/com_teacapps_barcodescanner_flag",
-                "app_compat_overrides/com_tencent_mm_flag",
-                "app_compat_overrides/com_teslamotors_tesla_flag",
-                "app_compat_overrides/com_tinder_flag",
-                "app_compat_overrides/com_truecaller_flag",
-                "app_compat_overrides/com_ucmobile_intl_flag",
-                "app_compat_overrides/com_verizon_messaging_vzmsgs_flag",
-                "app_compat_overrides/com_zhiliaoapp_musically_flag",
-                "app_compat_overrides/fake_for_testing_flag",
-                "app_compat_overrides/net_sourceforge_opencamera_flag",
-                "app_compat_overrides/net_zedge_android_flag",
-                "app_compat_overrides/org_telegram_messenger_flag",
-                "app_compat_overrides/org_zwanoo_android_speedtest_flag",
-                "app_compat_overrides/owned_change_ids",
-                "app_compat_overrides/owned_change_ids_flag",
-                "app_compat_overrides/remove_overrides",
-                "app_compat_overrides/remove_overrides_flag",
-                "app_compat_overrides/sg_bigo_live_flag",
-                "app_compat_overrides/tw_mobileapp_qrcode_banner_flag",
-                "app_compat_overrides/us_zoom_videomeetings_flag",
                 "appfunctions/execute_app_function_cancellation_timeout_millis",
                 "appfunctions/execute_app_function_timeout_millis",
                 "app_hibernation/app_hibernation_enabled",
@@ -165,6 +157,7 @@ final class WritableFlags {
                 "app_standby/notification_seen_duration_millis",
                 "app_standby/notification_seen_promoted_bucket",
                 "app_standby/retain_notification_seen_impact_for_pre_t_apps",
+                "app_standby/strong_usage_duration",
                 "app_standby/trigger_quota_bump_on_notification_seen",
                 "attention_manager_service/enable_flip_to_screen_off",
                 "attention_manager_service/keep_screen_on_enabled",
@@ -173,39 +166,7 @@ final class WritableFlags {
                 "attention_manager_service/post_dim_check_duration_millis",
                 "attention_manager_service/pre_dim_check_duration_millis",
                 "attention_manager_service/service_enabled",
-                "autofill/autofill_credential_manager_enabled",
-                "autofill/autofill_credential_manager_ignore_views",
-                "autofill/autofill_credential_manager_suppress_fill_dialog",
-                "autofill/autofill_credential_manager_suppress_save_dialog",
-                "autofill/autofill_dialog_enabled",
-                "autofill/autofill_dialog_hints",
-                "autofill/enable_relative_location_for_relayout",
-                "autofill/enable_relayout",
-                "autofill/fill_dialog_min_wait_after_animation_end_ms",
-                "autofill/fill_dialog_timeout_ms",
-                "autofill/compat_mode_allowed_packages",
-                "autofill/fill_fields_from_current_session_only",
-                "autofill/ignore_view_state_reset_to_empty",
-                "autofill/improve_fill_dialog",
-                "autofill/include_all_autofill_type_not_none_views_in_assist_structure",
-                "autofill/include_all_views_in_assist_structure",
-                "autofill/include_invisible_view_group_in_assist_structure",
-                "autofill/landscape_body_height_max_percent",
-                "autofill/legacy_augmented_autofill_mode",
-                "autofill/max_input_length_for_autofill",
-                "autofill/multiline_filter_enabled",
-                "autofill/non_autofillable_ime_action_ids",
-                "autofill/package_and_activity_allowlist_for_triggering_fill_request",
-                "autofill/package_deny_list_for_unimportant_view",
-                "autofill/pcc_classification_enabled",
-                "autofill/pcc_classification_hints",
-                "autofill/pcc_use_fallback",
-                "autofill/portrait_body_height_max_percent",
-                "autofill/prefer_provider_over_pcc",
-                "autofill/should_enable_autofill_on_all_view_types",
-                "autofill/smart_suggestion_supported_modes",
-                "autofill/trigger_fill_request_on_filtered_important_views",
-                "autofill/trigger_fill_request_on_unimportant_view",
+                "attention_manager_service/stale_after_millis",
                 "auto_pin_confirmation/enable_auto_pin_confirmation",
                 "b.b.b/c.c",
                 "backstage_power/min_consumed_power_threshold",
@@ -217,8 +178,16 @@ final class WritableFlags {
                 "backup_and_restore/full_backup_write_to_transport_buffer_size_bytes",
                 "battery_saver/enable_night_mode",
                 "battery_saver/location_mode",
+                "biometrics/android.adaptiveauth.enable_adaptive_auth",
+                "biometrics/android.adaptiveauth.report_biometric_auth_attempts",
+                "biometrics/android.hardware.biometrics.add_key_agreement_crypto_object",
+                "biometrics/android.security.clear_strong_auth_on_add_primary_credential",
+                "biometrics/android.security.report_primary_auth_attempts",
+                "biometrics/android.security.secure_lockdown",
+                "biometrics/android.security.should_trust_manager_listen_for_primary_auth",
                 "biometrics/biometric_strengths",
                 "biometrics/enable_biometric_property_verification",
+                "biometrics_framework/com.android.server.biometrics.face_vhal_feature",
                 "blobstore/delete_on_last_lease_delay_ms",
                 "blobstore/lease_acquisition_wait_time_ms",
                 "blobstore/max_active_sessions",
@@ -233,6 +202,7 @@ final class WritableFlags {
                 "bluetooth/bt_audio_policy_ag",
                 "bluetooth/bt_audio_policy_hf",
                 "bluetooth/bt_default_apm_state",
+                "bluetooth/com.android.bluetooth.flags.le_ase_read_multiple_variable",
                 "bluetooth/controller",
                 "bluetooth/device_name_bloomfilter",
                 "bluetooth/enable_hci_logging",
@@ -270,816 +240,26 @@ final class WritableFlags {
                 "constrain_display_apis/always_constrain_display_apis",
                 "constrain_display_apis/never_constrain_display_apis",
                 "constrain_display_apis/never_constrain_display_apis_all_packages",
+                "contacts/android.provider.new_default_account_api_enabled",
+                "contacts/com.android.providers.contacts.flags.disable_cp2_account_move_flag",
+                "content_capture/enable_activity_start_assist_content",
                 "content_capture/idle_flush_frequency",
                 "content_capture/legacy_enable_contentcapture",
                 "content_capture/logging_level",
                 "content_capture/service_explicitly_enabled",
                 "credential_manager/enable_credential_description_api",
                 "credential_manager/enable_credential_manager",
+                "cts/android.cts.flags.tests.readwrite_enabled_flag",
                 "DeviceConfigBootstrapValues/processed_values",
-                "device_config_overrides/namespace3:key3",
-                "device_config_overrides/namespace3:key4",
-                "device_config_overrides/namespace4:key3",
-                "device_config_overrides/namespace4:key4",
+                "device_config_overrides/",
+                "device_config_overrides/:",
+                "device_config_overrides/namespace1:",
+                "device_idle/light_idle_to",
+                "device_idle/light_idle_to_initial_flex",
                 "device_idle/notification_allowlist_duration_ms",
-                "device_personalization_services/accel_sensor_collection_enabled",
-                "device_personalization_services/accel_sensor_enabled",
-                "device_personalization_services/accel_sensor_max_extension_millis",
-                "device_personalization_services/accel_sensor_threshold_mss",
-                "device_personalization_services/action_ranking_irrelevant_device_selection_prob",
-                "device_personalization_services/action_ranking_random_ranking_prob",
-                "device_personalization_services/action_ranking_type",
-                "device_personalization_services/action_ranking_type_by_entity_type",
-                "device_personalization_services/activate_people_shortcuts_app_disabling",
-                "device_personalization_services/active_users_logger_enabled",
-                "device_personalization_services/active_users_logger_non_persistent",
-                "device_personalization_services/all_chronicle_enabled",
-                "device_personalization_services/allowlisted_feature_dimension_ids",
-                "device_personalization_services/allowlisted_feature_dimension_values",
-                "device_personalization_services/allow_use_public_speech_recognition",
-                "device_personalization_services/ambient_audio_recording_cycle_duration_seconds",
-                "device_personalization_services/ambient_audio_recording_duration_seconds",
-                "device_personalization_services/ambient_music_action_packages_whitelist",
-                "device_personalization_services/ambient_music_apk_music_detector_min_score",
-                "device_personalization_services/ambient_music_audio_playback_blacklist",
-                "device_personalization_services/ambient_music_audio_recording_ignorelist",
-                "device_personalization_services/ambient_music_check_last_match_enabled",
-                "device_personalization_services/ambient_music_collect_debug_context_data",
-                "device_personalization_services/ambient_music_dogfood_donation_allowed",
-                "device_personalization_services/ambient_music_dsp_model_config",
-                "device_personalization_services/ambient_music_dsp_music_break_model_enabled",
-                "device_personalization_services/ambient_music_dynamic_model_updates_enabled",
-                "device_personalization_services/ambient_music_dynamic_model_updates_params",
-                "device_personalization_services/ambient_music_enable_history",
-                "device_personalization_services/ambient_music_enable_history_context",
-                "device_personalization_services/ambient_music_enable_user_feedback",
-                "device_personalization_services/ambient_music_error_codes_to_squelch",
-                "device_personalization_services/ambient_music_extra_language_limit",
-                "device_personalization_services/ambient_music_fast_detector_restart",
-                "device_personalization_services/ambient_music_get_model_state_enabled",
-                "device_personalization_services/ambient_music_gp_max_shards_to_fetch",
-                "device_personalization_services/ambient_music_initial_index_download_on_battery",
-                "device_personalization_services/ambient_music_intent_trigger_restart_full",
-                "device_personalization_services/ambient_music_intent_trigger_restart_interval_millis",
-                "device_personalization_services/ambient_music_internal_build_crash_frequency_days",
-                "device_personalization_services/ambient_music_long_squelch_experiment",
-                "device_personalization_services/ambient_music_on_demand_classic_enabled_by_default",
-                "device_personalization_services/ambient_music_on_demand_enabled",
-                "device_personalization_services/ambient_music_on_demand_music_confidence",
-                "device_personalization_services/ambient_music_run_apk_music_detector",
-                "device_personalization_services/ambient_music_run_on_small_cores",
-                "device_personalization_services/ambient_music_show_debug_context_data",
-                "device_personalization_services/ambient_music_show_history_album_art",
-                "device_personalization_services/ambient_music_show_history_kg_action_links",
-                "device_personalization_services/ambient_music_smart_audio_playback_detection",
-                "device_personalization_services/ambient_music_store_previous_matches",
-                "device_personalization_services/ambient_music_use_latest_track_offset",
-                "device_personalization_services/annotation_confidence_cutoff",
-                "device_personalization_services/app_blocklist",
-                "device_personalization_services/app_prediction_active_model",
-                "device_personalization_services/app_prediction_active_predictor",
-                "device_personalization_services/app_prediction_enable_taskbar_deduping",
-                "device_personalization_services/appsearch_photos_corpus_package_allowlist",
-                "device_personalization_services/app_suggestion_max_boost",
-                "device_personalization_services/app_suggestion_penalty",
-                "device_personalization_services/app_suggestions_in_memory_target_count",
-                "device_personalization_services/app_suggestions_refraction_manifest_config",
-                "device_personalization_services/assist_timeout_ms",
-                "device_personalization_services/attestation_mode",
-                "device_personalization_services/audio_device_predictor_weight",
-                "device_personalization_services/audio_to_text_language_list",
-                "device_personalization_services/available_for_download",
-                "device_personalization_services/beta_audio_to_text_languages_in_live_caption",
-                "device_personalization_services/bias_name_options",
-                "device_personalization_services/blue_chip_translate_enabled",
-                "device_personalization_services/brella_model_version",
-                "device_personalization_services/brella_population_name",
-                "device_personalization_services/brief_media_stop_duration_seconds",
-                "device_personalization_services/bypass_qpr_check",
-                "device_personalization_services/cached_shortcuts_disabled_packages",
-                "device_personalization_services/cache_max_size",
-                "device_personalization_services/cache_size",
-                "device_personalization_services/caching_strategy",
-                "device_personalization_services/calendar_attendance_rerank_limit_min",
-                "device_personalization_services/candidates_fetch_time_out",
-                "device_personalization_services/can_use_gms_core_to_save_boarding_pass",
-                "device_personalization_services/can_use_gpay_to_save_boarding_pass",
-                "device_personalization_services/capture_interval_millis",
-                "device_personalization_services/characterset_lang_detection_enabled",
-                "device_personalization_services/chat_translate_languages",
-                "device_personalization_services/chronicle_enabled",
-                "device_personalization_services/cinematic_models_mdd_manifest_config",
-                "device_personalization_services/clear_logging_events_if_too_much_memory",
-                "device_personalization_services/clipboard_foreground_package_delay_ms",
-                "device_personalization_services/close_camera_after_idle_millis",
-                "device_personalization_services/cloud_api_allowed",
-                "device_personalization_services/c_lower_threshold",
-                "device_personalization_services/c_max_episode_duration_seconds",
-                "device_personalization_services/c_maximum_tolerance_duration_seconds",
-                "device_personalization_services/c_max_inactivity_duration_seconds",
-                "device_personalization_services/c_min_episode_density",
-                "device_personalization_services/c_min_episode_duration_seconds",
-                "device_personalization_services/const_ctr",
-                "device_personalization_services/const_impression",
-                "device_personalization_services/const_val",
-                "device_personalization_services/const_val_screen_session_id",
-                "device_personalization_services/contacts_biasing_boost",
-                "device_personalization_services/copy_to_translate_enabled",
-                "device_personalization_services/correction_alternatives_max_alternatives_per_span",
-                "device_personalization_services/correction_alternatives_max_learned_corrections",
-                "device_personalization_services/correction_alternatives_max_percentage_words",
-                "device_personalization_services/correction_classifier_max_abs_edit_distance",
-                "device_personalization_services/correction_classifier_max_abs_phonetic_distance",
-                "device_personalization_services/correction_classifier_max_rel_edit_distance",
-                "device_personalization_services/correction_classifier_max_rel_phonetic_distance",
-                "device_personalization_services/country_source_languages_list",
-                "device_personalization_services/crash_on_error",
-                "device_personalization_services/ctr_beta_alpha",
-                "device_personalization_services/ctr_beta_beta",
-                "device_personalization_services/ctr_sampling",
-                "device_personalization_services/c_upper_threshold",
-                "device_personalization_services/database_ttl_days",
-                "device_personalization_services/deep_dialogue_superpacks_manifest_url_template",
-                "device_personalization_services/default_log_sample_interval",
-                "device_personalization_services/dev_population_override",
-                "device_personalization_services/diffbased_entity_insertion",
-                "device_personalization_services/differentiate_simplified_and_traditional_chinese",
-                "device_personalization_services/disable_ambient_context_dao_provider",
-                "device_personalization_services/disable_autofill_dao_provider",
-                "device_personalization_services/disable_chronicle_data_removal_request_listener",
-                "device_personalization_services/disable_content_capture_dao_provider",
-                "device_personalization_services/disable_content_suggestions_dao_provider",
-                "device_personalization_services/disabled_feature_list",
-                "device_personalization_services/disabled_packages",
-                "device_personalization_services/disable_echo_dao_provider",
-                "device_personalization_services/disable_live_translate_dao_provider",
-                "device_personalization_services/disable_next_conversation_dao_provider",
-                "device_personalization_services/disable_now_playing_dao_provider",
-                "device_personalization_services/disable_pecan_conversation_fragment_events_dao_provider",
-                "device_personalization_services/disable_pecan_conversation_session_events_dao_provider",
-                "device_personalization_services/disable_pecan_conversation_thread_events_dao_provider",
-                "device_personalization_services/disable_pecan_latency_analytics_events_dao_provider",
-                "device_personalization_services/disable_pecan_message_events_dao_provider",
-                "device_personalization_services/disable_pecan_search_query_events_dao_provider",
-                "device_personalization_services/disable_pecan_usage_events_dao_provider",
-                "device_personalization_services/disable_people_suggest_dao_provider",
-                "device_personalization_services/disable_quick_tap_dao_provider",
-                "device_personalization_services/disable_safecomms_dao_provider",
-                "device_personalization_services/disable_search_dao_provider",
-                "device_personalization_services/disable_session_state",
-                "device_personalization_services/disable_simple_storage_trainer",
-                "device_personalization_services/disable_smart_select_dao_provider",
-                "device_personalization_services/disable_toast_query_dao_provider",
-                "device_personalization_services/disable_translate_without_system_animation",
-                "device_personalization_services/doorbell_allowlist_packages",
-                "device_personalization_services/doorbell_loading_screen_state",
-                "device_personalization_services/doorbell_when_for_update_time",
-                "device_personalization_services/downloadable_language_packs_raw",
-                "device_personalization_services/downloadable_training_plans_config",
-                "device_personalization_services/download_job_enabled",
-                "device_personalization_services/download_system_language_pack_on_start_enabled",
-                "device_personalization_services/duplicates_time_frame_in_seconds",
-                "device_personalization_services/emergency_disable",
-                "device_personalization_services/emergency_disable_feature_bc_translate",
-                "device_personalization_services/emergency_disable_feature_interests_model_kg_entity",
-                "device_personalization_services/emergency_disable_feature_live_caption_asr_biasing",
-                "device_personalization_services/emergency_disable_feature_next_conversation",
-                "device_personalization_services/emergency_disable_feature_people_suggest",
-                "device_personalization_services/emergency_disable_feature_safecomm",
-                "device_personalization_services/emergency_disable_feature_smart_dictation",
-                "device_personalization_services/enable",
-                "device_personalization_services/enable_action_boost_generator",
-                "device_personalization_services/enable_adaptive_audio",
-                "device_personalization_services/enable_adaptive_media_volume",
-                "device_personalization_services/enable_add_contextual_feedback_button_on_long_press",
-                "device_personalization_services/enable_add_internal_feedback_button",
-                "device_personalization_services/enable_add_to_wallet_title",
-                "device_personalization_services/enable_agsa_settings_read",
-                "device_personalization_services/enable_aiai_clearcut_logging",
-                "device_personalization_services/enable_aiai_tc_generator",
-                "device_personalization_services/enable_alternatives_from_past_corrections",
-                "device_personalization_services/enable_alternatives_from_speech_hypotheses",
-                "device_personalization_services/enable_app_search_app_suggestion_boost",
-                "device_personalization_services/enable_appsearch_photos_corpus",
-                "device_personalization_services/enable_appsearch_photos_corpus_app_preview",
-                "device_personalization_services/enable_appsearch_photos_corpus_app_srp_preview",
-                "device_personalization_services/enable_appsearch_photos_corpus_package_filtering",
-                "device_personalization_services/enable_appsearch_universal_fetcher",
-                "device_personalization_services/enable_appsearch_universal_fetcher_clock_corpus",
-                "device_personalization_services/enable_appsearch_universal_fetcher_clock_corpus_app_srp_preview",
-                "device_personalization_services/enable_app_widget_cache",
-                "device_personalization_services/enable_assistant_geller_data_index",
-                "device_personalization_services/enable_assistant_memory_generator",
-                "device_personalization_services/enable_assist_parser",
-                "device_personalization_services/enable_audio_device_event_usage",
-                "device_personalization_services/enable_augmented_modality",
-                "device_personalization_services/enable_augmented_modality_input",
-                "device_personalization_services/enable_augmented_modality_language_detection",
-                "device_personalization_services/enable_augmented_music",
-                "device_personalization_services/enable_barhopper_late_loading",
-                "device_personalization_services/enable_biasing_for_commands",
-                "device_personalization_services/enable_biasing_for_contact_fields",
-                "device_personalization_services/enable_biasing_for_contacts",
-                "device_personalization_services/enable_biasing_for_contacts_learned_from_past_corrections",
-                "device_personalization_services/enable_biasing_for_interests_model",
-                "device_personalization_services/enable_biasing_for_past_corrections",
-                "device_personalization_services/enable_biasing_for_screen_context",
-                "device_personalization_services/enable_blobstore_bitmap_fetch_in_launcher",
-                "device_personalization_services/enable_brella_in_astrea",
-                "device_personalization_services/enable_call_log_signals",
-                "device_personalization_services/enable_chat_app_biasing",
-                "device_personalization_services/enable_chronicle_eventbuffer",
-                "device_personalization_services/enable_chronicle_migration",
-                "device_personalization_services/enable_cinematic_effect",
-                "device_personalization_services/enable_cinematic_mdd",
-                "device_personalization_services/enable_clearcut_log",
-                "device_personalization_services/enable_clearcut_logging",
-                "device_personalization_services/enable_clipboard_entity_type_logging",
-                "device_personalization_services/enable_cloud_search",
-                "device_personalization_services/enable_connector",
-                "device_personalization_services/enable_contacts",
-                "device_personalization_services/enable_context_shadow_predictors",
-                "device_personalization_services/enable_context_signals",
-                "device_personalization_services/enable_contextual_chip",
-                "device_personalization_services/enable_contextual_chip_related_apps",
-                "device_personalization_services/enable_control_system",
-                "device_personalization_services/enable_correction_learning",
-                "device_personalization_services/enable_correction_learning_with_context_detection",
-                "device_personalization_services/enable_covid_card_action",
-                "device_personalization_services/enable_covid_card_inflate_buffer",
-                "device_personalization_services/enable_cross_device_timers",
-                "device_personalization_services/enabled",
-                "device_personalization_services/enable_dark_launch_outlook_events",
-                "device_personalization_services/enable_data_capture",
-                "device_personalization_services/enable_data_fetch",
-                "device_personalization_services/enable_debug_hprof_dumps",
-                "device_personalization_services/enable_deep_clu",
-                "device_personalization_services/enable_deepclu_for_tc",
-                "device_personalization_services/enable_deeplinks_latency_improvement",
-                "device_personalization_services/enable_default_langid_model",
-                "device_personalization_services/enable_device_config_overrides",
-                "device_personalization_services/enable_dictation_client",
-                "device_personalization_services/enable_dictionary_langid_detection",
-                "device_personalization_services/enable_dimensional_logging",
-                "device_personalization_services/enable_direct_share",
-                "device_personalization_services/enable_doorbell",
-                "device_personalization_services/enable_dota",
-                "device_personalization_services/enable_dota_asset",
-                "device_personalization_services/enable_dota_download",
-                "device_personalization_services/enable_dynamic_interactions",
-                "device_personalization_services/enable_dynamic_kg_collections",
-                "device_personalization_services/enable_dynamic_web",
-                "device_personalization_services/enable_ekho",
-                "device_personalization_services/enable_email_snippet_interactions",
-                "device_personalization_services/enable_encode_subcard_into_smartspace_target_id",
-                "device_personalization_services/enable_enhanced_voice_dictation_biasing",
-                "device_personalization_services/enable_eta_lyft",
-                "device_personalization_services/enable_example_consumption_recording",
-                "device_personalization_services/enable_example_store",
-                "device_personalization_services/enable_fa",
-                "device_personalization_services/enable_face_detection_from_camera",
-                "device_personalization_services/enable_face_detection_when_phone_in_portrait",
-                "device_personalization_services/enable_face_only_mode",
-                "device_personalization_services/enable_fa_synthetic",
-                "device_personalization_services/enable_fedex",
-                "device_personalization_services/enable_fed_sql",
-                "device_personalization_services/enable_feedback_ranking",
-                "device_personalization_services/enable_flight_landing_smartspace_aiai",
-                "device_personalization_services/enable_foldable_hotseat",
-                "device_personalization_services/enable_gboard_suggestion",
-                "device_personalization_services/enable_gleams",
-                "device_personalization_services/enable_gleams_cease_on_long_press",
-                "device_personalization_services/enable_gleams_dark_launch",
-                "device_personalization_services/enable_grocery",
-                "device_personalization_services/enable_grpc_filecopy",
-                "device_personalization_services/enable_headphones_suggestions_from_agsa",
-                "device_personalization_services/enable_headphone_suggestions_from_habits_profiles",
-                "device_personalization_services/enable_hopper_tracker",
-                "device_personalization_services/enable_horizontal_people_shortcuts",
-                "device_personalization_services/enable_hotel_smartspace_aiai",
-                "device_personalization_services/enable_hybrid_hotseat_client",
-                "device_personalization_services/enable_image_selection",
-                "device_personalization_services/enable_image_selection_adjustments",
-                "device_personalization_services/enable_indirect_insights",
-                "device_personalization_services/enable_input_context_snapshot_capture",
-                "device_personalization_services/enable_interactions_scoring_table",
-                "device_personalization_services/enable_interests_model",
-                "device_personalization_services/enable_interests_model_asr_biasing",
-                "device_personalization_services/enable_internal_settings",
-                "device_personalization_services/enable_in_work_profile",
-                "device_personalization_services/enable_japanese_ocr",
-                "device_personalization_services/enable_kg_collections_thresholds_table",
-                "device_personalization_services/enable_language_detection",
-                "device_personalization_services/enable_language_profile_quick_update",
-                "device_personalization_services/enable_legibility",
-                "device_personalization_services/enable_lens",
-                "device_personalization_services/enable_lens_r_overview_long_press",
-                "device_personalization_services/enable_lens_r_overview_select_mode",
-                "device_personalization_services/enable_lens_r_overview_similar_styles_action",
-                "device_personalization_services/enable_lens_r_overview_translate_action",
-                "device_personalization_services/enable_lens_screenshots_protected_deeplink",
-                "device_personalization_services/enable_lens_screenshots_search_action",
-                "device_personalization_services/enable_lens_screenshots_similar_styles_action",
-                "device_personalization_services/enable_lens_screenshots_translate_action",
-                "device_personalization_services/enable_lens_suggestions",
-                "device_personalization_services/enable_location_scorer",
-                "device_personalization_services/enable_matchmaker",
-                "device_personalization_services/enable_matchmaker_generator",
-                "device_personalization_services/enable_mdd_download_notifications",
-                "device_personalization_services/enable_media_recs_for_driving",
-                "device_personalization_services/enable_min_training_interval",
-                "device_personalization_services/enable_name_detection_with_ner",
-                "device_personalization_services/enable_network_usage_log",
-                "device_personalization_services/enable_new_logger_api",
-                "device_personalization_services/enable_next_conversation",
-                "device_personalization_services/enable_nextdoor",
-                "device_personalization_services/enable_non_synthetic_logs",
-                "device_personalization_services/enable_notification_common",
-                "device_personalization_services/enable_notification_expiration",
-                "device_personalization_services/enable_notification_signals",
-                "device_personalization_services/enable_notification_tracker",
-                "device_personalization_services/enable_nudges_learning",
-                "device_personalization_services/enable_on_ready_handler",
-                "device_personalization_services/enable_outlook_events",
-                "device_personalization_services/enable_overview",
-                "device_personalization_services/enable_package_delivery",
-                "device_personalization_services/enable_package_tracker",
-                "device_personalization_services/enable_pecan",
-                "device_personalization_services/enable_pecan_async_data_storage",
-                "device_personalization_services/enable_pecan_context_examples_generator",
-                "device_personalization_services/enable_pecan_context_recorder",
-                "device_personalization_services/enable_pecan_context_text_classifier",
-                "device_personalization_services/enable_pecan_persistence",
-                "device_personalization_services/enable_pecan_plugins",
-                "device_personalization_services/enable_pecan_scroll",
-                "device_personalization_services/enable_pecan_search_suggestion",
-                "device_personalization_services/enable_people_module",
-                "device_personalization_services/enable_people_pecan",
-                "device_personalization_services/enable_people_search",
-                "device_personalization_services/enable_people_search_block",
-                "device_personalization_services/enable_people_search_content",
-                "device_personalization_services/enable_people_shortcuts",
-                "device_personalization_services/enable_performance_westworld_log",
-                "device_personalization_services/enable_personalized_biasing_on_locked_device",
-                "device_personalization_services/enable_personalized_smart_reply",
-                "device_personalization_services/enable_pipeline_westworld_log",
-                "device_personalization_services/enable_pir_clearcut_logging",
-                "device_personalization_services/enable_pir_download_constraints",
-                "device_personalization_services/enable_pir_westworld_logging",
-                "device_personalization_services/enable_plugin_application",
-                "device_personalization_services/enable_pnb",
-                "device_personalization_services/enable_pnb_ranking",
-                "device_personalization_services/enable_pnb_recency_score",
-                "device_personalization_services/enable_prediction_westworld_log",
-                "device_personalization_services/enable_predictor_expiration",
-                "device_personalization_services/enable_priority_suggestion",
-                "device_personalization_services/enable_priority_suggestion_client",
-                "device_personalization_services/enable_proactive_hints",
-                "device_personalization_services/enable_profile_signals",
-                "device_personalization_services/enable_proximity",
-                "device_personalization_services/enable_punctuations",
-                "device_personalization_services/enable_query_intent_bloom_filter",
-                "device_personalization_services/enable_quick_share_smart_action",
-                "device_personalization_services/enable_quick_tap",
-                "device_personalization_services/enable_quick_tap_mdd",
-                "device_personalization_services/enable_reconcile_job",
-                "device_personalization_services/enable_reflection_generator",
-                "device_personalization_services/enable_refraction",
-                "device_personalization_services/enable_result_handling_callback_for_federated_computation",
-                "device_personalization_services/enable_ridesharing_eta",
-                "device_personalization_services/enable_save_and_copy",
-                "device_personalization_services/enable_scheduled_tasks",
-                "device_personalization_services/enable_screenshot_notification_smart_actions",
-                "device_personalization_services/enable_search_fa_logging",
-                "device_personalization_services/enable_search_on_contacts",
-                "device_personalization_services/enable_search_on_files",
-                "device_personalization_services/enable_search_on_photos",
-                "device_personalization_services/enable_search_system_pointer_generator",
-                "device_personalization_services/enable_selection_filtering",
-                "device_personalization_services/enable_service",
-                "device_personalization_services/enable_setting_page",
-                "device_personalization_services/enable_settings_card_generator",
-                "device_personalization_services/enable_settings_opt_in_switch",
-                "device_personalization_services/enable_shade_reduction_metric",
-                "device_personalization_services/enable_shade_time_metric",
-                "device_personalization_services/enable_share_activity",
-                "device_personalization_services/enable_sharesheet_client",
-                "device_personalization_services/enable_sharesheet_ranking",
-                "device_personalization_services/enable_sideload_lp_inference",
-                "device_personalization_services/enable_similarity_score",
-                "device_personalization_services/enable_simple_storage",
-                "device_personalization_services/enable_simple_storage_trainer_raksha_integration",
-                "device_personalization_services/enable_smartrec_for_overview_chips",
-                "device_personalization_services/enable_smart_select_example_cache_on_suggest_selection",
-                "device_personalization_services/enable_smart_select_example_collection",
-                "device_personalization_services/enable_smart_select_example_store_connector",
-                "device_personalization_services/enable_smart_select_locked_bootloader_check",
-                "device_personalization_services/enable_smart_select_paste_package_signal",
-                "device_personalization_services/enable_smart_select_training_manager_populations",
-                "device_personalization_services/enable_sms_signals",
-                "device_personalization_services/enable_spa_setting",
-                "device_personalization_services/enable_speech_personalization_caching",
-                "device_personalization_services/enable_speech_personalization_inference",
-                "device_personalization_services/enable_speech_personalization_training",
-                "device_personalization_services/enable_spelling_correction",
-                "device_personalization_services/enable_store_suggestions_from_agsa",
-                "device_personalization_services/enable_stronger_boost_for_generic_phrases_biasing",
-                "device_personalization_services/enable_superpacks_custom_bin_processing",
-                "device_personalization_services/enable_superpacks_download",
-                "device_personalization_services/enable_superpacks_kg_actions_ranking",
-                "device_personalization_services/enable_superpacks_multi_bulks_request",
-                "device_personalization_services/enable_superpacks_pir_protocol",
-                "device_personalization_services/enable_tc_easter_egg",
-                "device_personalization_services/enable_tc_easter_egg_logging",
-                "device_personalization_services/enable_tclib",
-                "device_personalization_services/enable_tclib_download_using_superpacks",
-                "device_personalization_services/enable_text_classifier_chronicle_ingress",
-                "device_personalization_services/enable_text_transform",
-                "device_personalization_services/enable_throttling",
-                "device_personalization_services/enable_toast_integration_for_apps",
-                "device_personalization_services/enable_toast_integration_for_virtual_assistants",
-                "device_personalization_services/enable_toast_query_fa_logging",
-                "device_personalization_services/enable_travel_features_type_merge",
-                "device_personalization_services/enable_typing_interactions",
-                "device_personalization_services/enable_uncaught_exception_counter",
-                "device_personalization_services/enable_upgrade_importance",
-                "device_personalization_services/enable_uptime_logger",
-                "device_personalization_services/enable_usage_fa",
-                "device_personalization_services/enable_view_on_screen_interactions",
-                "device_personalization_services/enable_vkp",
-                "device_personalization_services/enable_westworld_log",
-                "device_personalization_services/enable_westworld_logging",
-                "device_personalization_services/enable_westworld_logging_override",
-                "device_personalization_services/enable_whitelist_packages",
-                "device_personalization_services/enable_widget_recommendations",
-                "device_personalization_services/enable_write_feature_status_to_simple_storage",
-                "device_personalization_services/enable_zero_day",
-                "device_personalization_services/event_throttle_seconds",
-                "device_personalization_services/example_logging_enabled",
-                "device_personalization_services/example_resource_manifest_config",
-                "device_personalization_services/example_store_db_max_num_rows",
-                "device_personalization_services/example_store_db_ttl_days",
-                "device_personalization_services/exclude_contacts_from_generic_biasing",
-                "device_personalization_services/expiration_predictor_timer_in_minutes",
-                "device_personalization_services/expiration_time_in_minutes",
-                "device_personalization_services/face_detection_confidence_threshold_landscape",
-                "device_personalization_services/face_detection_confidence_threshold_portrait",
-                "device_personalization_services/face_pose_num_frames",
-                "device_personalization_services/fa_example_store_db_cleanup_interval_ms",
-                "device_personalization_services/fa_example_store_db_max_num_rows",
-                "device_personalization_services/fa_example_store_db_ttl_days",
-                "device_personalization_services/fail_new_connections",
-                "device_personalization_services/fa_min_training_interval_ms",
-                "device_personalization_services/fa_population_name",
-                "device_personalization_services/fast_recognition_ui_cleanup_enabled",
-                "device_personalization_services/favorites_enabled",
-                "device_personalization_services/feature_users_count_enabled",
-                "device_personalization_services/federated_analytics_allowed",
-                "device_personalization_services/federated_analytics_attestation_mode",
-                "device_personalization_services/federated_analytics_population_name_suffix",
-                "device_personalization_services/fedex_log_enabled",
-                "device_personalization_services/flag_for_dogfood",
-                "device_personalization_services/flag_for_extended_dogfood",
-                "device_personalization_services/flag_for_fishfood",
-                "device_personalization_services/fl_population_name",
-                "device_personalization_services/garbage_collection_job_hours_interval",
-                "device_personalization_services/gleaming_interval_minutes",
-                "device_personalization_services/gleam_presentation",
-                "device_personalization_services/gleams_buffer_interval_seconds",
-                "device_personalization_services/group_stats_log_sample_interval",
-                "device_personalization_services/hades_config_url",
-                "device_personalization_services/handle_ambient_music_results_with_history",
-                "device_personalization_services/headphone_suggestions_from_agsa_audio_boost",
-                "device_personalization_services/history_summary_enabled",
-                "device_personalization_services/hopper_manifest_config",
-                "device_personalization_services/hourly_bucket_expiration_days",
-                "device_personalization_services/idle_timeout_seconds",
-                "device_personalization_services/image_to_text_language_list",
-                "device_personalization_services/importance_model_download_url",
-                "device_personalization_services/importance_model_type",
-                "device_personalization_services/importance_model_version",
-                "device_personalization_services/importas",
-                "device_personalization_services/impression_sampling",
-                "device_personalization_services/inapp_training_blacklist",
-                "device_personalization_services/include_home_launches_all_apps",
-                "device_personalization_services/include_lc_inputs_in_selector_context",
-                "device_personalization_services/interactions_enabled",
-                "device_personalization_services/interactions_scoring_table_superpacks_manifest_url_template",
-                "device_personalization_services/interactions_scoring_table_superpacks_manifest_version",
-                "device_personalization_services/interests_model_asr_biasing_package_list",
-                "device_personalization_services/interpreter_source_languages",
-                "device_personalization_services/interpreter_target_languages",
-                "device_personalization_services/ipc_streaming_throttle_ms",
-                "device_personalization_services/kg_actions_ranking_superpacks_manifest_version",
-                "device_personalization_services/kg_actions_ranking_superpacks_url_template",
-                "device_personalization_services/kg_collections_thresholds_table_superpacks_manifest_url_template",
-                "device_personalization_services/kg_collections_thresholds_table_superpacks_manifest_version",
-                "device_personalization_services/kill_switch_lens_r_overview",
-                "device_personalization_services/kill_switch_lens_screenshot",
-                "device_personalization_services/killswitch_screen_content_provider",
-                "device_personalization_services/knowledge_graph_collections_table_superpacks_manifest_url_template",
-                "device_personalization_services/knowledge_graph_collections_table_superpacks_manifest_version",
-                "device_personalization_services/labs_personalized_shard_allowed",
-                "device_personalization_services/large_max_bucket_size",
-                "device_personalization_services/large_refresh_period",
-                "device_personalization_services/lc_asr_biasing_boost_value",
-                "device_personalization_services/lc_asr_biasing_max_num_entities",
-                "device_personalization_services/lc_asr_biasing_min_cumulative_interactions_score",
-                "device_personalization_services/lc_asr_biasing_model_version",
-                "device_personalization_services/lifetime_in_millis",
-                "device_personalization_services/listener_use_arcs_delete_propagation",
-                "device_personalization_services/live_captions_translate_languages",
-                "device_personalization_services/local_slices_radius_km",
-                "device_personalization_services/local_time_buffer_in_millis",
-                "device_personalization_services/logging_job_hours_interval",
-                "device_personalization_services/log_latency",
-                "device_personalization_services/log_sampling_percentage",
-                "device_personalization_services/manifest_url_template",
-                "device_personalization_services/margin_horizontal_px",
-                "device_personalization_services/margin_vertical_px",
-                "device_personalization_services/max_allowable_bin_size",
-                "device_personalization_services/max_allowable_bins_requests",
-                "device_personalization_services/max_allowable_global_slice_size",
-                "device_personalization_services/max_allowable_local_slice_size",
-                "device_personalization_services/max_allowable_new_slices_size",
-                "device_personalization_services/max_contact_count",
-                "device_personalization_services/max_face_pose_request_duration_millis",
-                "device_personalization_services/max_gleams_on_screen",
-                "device_personalization_services/max_gleams_per_day",
-                "device_personalization_services/max_importance_variance",
-                "device_personalization_services/max_per_contact_event_count",
-                "device_personalization_services/max_phonesky_result_number",
-                "device_personalization_services/max_play_latency_in_millis",
-                "device_personalization_services/max_request_duration_millis",
-                "device_personalization_services/max_shortcut_count",
-                "device_personalization_services/max_stored_inferences",
-                "device_personalization_services/max_yaw_allowed_degrees",
-                "device_personalization_services/measure_ambient_loudness",
-                "device_personalization_services/medium_max_bucket_size",
-                "device_personalization_services/medium_refresh_period",
-                "device_personalization_services/memory_reduction",
-                "device_personalization_services/min_delay_between_requests_millis",
-                "device_personalization_services/min_entity_topicality_score",
-                "device_personalization_services/min_image_size",
-                "device_personalization_services/min_lens_agsa_app_version",
-                "device_personalization_services/min_lens_screenshots_agsa_app_version",
-                "device_personalization_services/min_number_of_frames_required_for_single_check",
-                "device_personalization_services/min_tc_entity_confidence",
-                "device_personalization_services/min_tc_entity_topicality",
-                "device_personalization_services/min_trained_events_to_log",
-                "device_personalization_services/min_training_interval_millis",
-                "device_personalization_services/min_travel_distance_meters",
-                "device_personalization_services/min_update_interval_seconds",
-                "device_personalization_services/model_url",
-                "device_personalization_services/model_version",
-                "device_personalization_services/module_enable",
-                "device_personalization_services/music_break_mode_update_policy",
-                "device_personalization_services/music_model_generate_negative_events",
-                "device_personalization_services/music_model_negative_threshold",
-                "device_personalization_services/music_model_negative_time_before_event_ms",
-                "device_personalization_services/music_model_positive_event_timeout_ms",
-                "device_personalization_services/music_model_positive_state_is_persistent",
-                "device_personalization_services/nasa_superpacks_manifest_url",
-                "device_personalization_services/nasa_superpacks_manifest_ver",
-                "device_personalization_services/nasa_superpacks_manifest_version",
-                "device_personalization_services/new_model_version_advanced",
-                "device_personalization_services/norm_mean",
-                "device_personalization_services/norm_std",
-                "device_personalization_services/norm_val_screen_session_id",
-                "device_personalization_services/now_playing_allowed",
-                "device_personalization_services/nudges_amplification",
-                "device_personalization_services/num_frames",
-                "device_personalization_services/num_simple_draws_per_job",
-                "device_personalization_services/oak_url",
-                "device_personalization_services/ocr_model_download_enabled",
-                "device_personalization_services/on_demand_enable_eager_prompt",
-                "device_personalization_services/on_demand_fingerprinter_being_setup_warning",
-                "device_personalization_services/on_demand_hide_if_fingerprinter_install_not_confirmed",
-                "device_personalization_services/on_demand_min_supported_aga_version",
-                "device_personalization_services/on_demand_retry_fingerprinter_install",
-                "device_personalization_services/on_device_biasing_params",
-                "device_personalization_services/outlook_event_source_of_truth",
-                "device_personalization_services/package_delivery_card_delay_seconds",
-                "device_personalization_services/paired_device_expiration_minutes",
-                "device_personalization_services/paired_device_expiration_seconds",
-                "device_personalization_services/paired_device_low_battery_level",
-                "device_personalization_services/param",
-                "device_personalization_services/parameter",
-                "device_personalization_services/parameters",
-                "device_personalization_services/participation_window_days",
-                "device_personalization_services/pause_camera_after_screen_on_period_millis",
-                "device_personalization_services/people_shortcuts_disabled_packages",
-                "device_personalization_services/personalized_slice_info_mdh_sync_footprints_corpus_id",
-                "device_personalization_services/personalized_slice_info_mdh_sync_throttle_seconds",
-                "device_personalization_services/personalized_slice_info_mdh_use_standalone",
-                "device_personalization_services/play_snapshot_manifest_url",
-                "device_personalization_services/play_snapshot_version",
-                "device_personalization_services/poisson_gamma_alpha",
-                "device_personalization_services/poisson_gamma_beta",
-                "device_personalization_services/poisson_lambda",
-                "device_personalization_services/postprocessing_rules_csv",
-                "device_personalization_services/prediction_backend_for_all_apps",
-                "device_personalization_services/primary_predictor_weight",
-                "device_personalization_services/probe_slice_id",
-                "device_personalization_services/process_seen_messages_in_message_expiring_apps",
-                "device_personalization_services/profile_app_suggestions_enable",
-                "device_personalization_services/promote_sys_pointer_in_psb",
-                "device_personalization_services/proximity_configs",
-                "device_personalization_services/proximity_sensor_enabled",
-                "device_personalization_services/query_app_search_for_contacts",
-                "device_personalization_services/quick_tap_manifest_config",
-                "device_personalization_services/recent_shot_bitmap_cache_enabled",
-                "device_personalization_services/recent_shot_suggestions_enabled",
-                "device_personalization_services/recent_top_shot_suggestions_enabled",
-                "device_personalization_services/recognition_session_logging_uses_word_separator",
-                "device_personalization_services/reconcile_use_arcs_delete_propagation",
-                "device_personalization_services/refraction_enable_mdd",
-                "device_personalization_services/refraction_last_app_override",
-                "device_personalization_services/refraction_max_prediction_spots",
-                "device_personalization_services/reject_unknown_requests",
-                "device_personalization_services/remove_smartspace_weather_and_date",
-                "device_personalization_services/replace_auto_translate_copied_text_enabled",
-                "device_personalization_services/require_battery_not_low_by_default",
-                "device_personalization_services/require_charging_by_default",
-                "device_personalization_services/require_idle_by_default",
-                "device_personalization_services/require_wifi_by_default",
-                "device_personalization_services/resource_version",
-                "device_personalization_services/resumable_diarization_enabled",
-                "device_personalization_services/return_texturedmesh_with_error_status",
-                "device_personalization_services/reuse",
-                "device_personalization_services/ring_channels_regex",
-                "device_personalization_services/ring_lockscreen_delay_seconds",
-                "device_personalization_services/ring_on_aod_only",
-                "device_personalization_services/rotation_memorization_timeout_millis",
-                "device_personalization_services/samesong_dsp_fake_event_interval_ms",
-                "device_personalization_services/samesong_dsp_initial_squelch_ms",
-                "device_personalization_services/sampling_rate",
-                "device_personalization_services/sampling_without_replacement_enabled",
-                "device_personalization_services/sampling_without_replacement_population_name",
-                "device_personalization_services/screenshot_boarding_pass_tsa_precheck_url",
-                "device_personalization_services/scroll_delay_in_millis",
-                "device_personalization_services/search_allapps_result_types",
-                "device_personalization_services/search_enable_application_header_type",
-                "device_personalization_services/search_enable_apps",
-                "device_personalization_services/search_enable_app_search_tips",
-                "device_personalization_services/search_enable_appsearch_tips_ranking_improvement",
-                "device_personalization_services/search_enable_app_token_indexing",
-                "device_personalization_services/search_enable_app_usage_stats_ranking",
-                "device_personalization_services/search_enable_assistant_quick_phrases_settings",
-                "device_personalization_services/search_enable_bc_smartspace_settings",
-                "device_personalization_services/search_enable_bc_translate_settings",
-                "device_personalization_services/search_enable_deprioritize_slow_corpus",
-                "device_personalization_services/search_enable_everything_else_above_web",
-                "device_personalization_services/search_enable_filter_pending_jobs",
-                "device_personalization_services/search_enable_info_logging",
-                "device_personalization_services/search_enable_mdp_play_results",
-                "device_personalization_services/search_enable_play_alleyoop",
-                "device_personalization_services/search_enable_search_in_app_icon",
-                "device_personalization_services/search_enable_shortcut_prefix_match",
-                "device_personalization_services/search_enable_static_shortcuts",
-                "device_personalization_services/search_enable_superpacks_app_terms",
-                "device_personalization_services/search_enable_superpacks_play_results",
-                "device_personalization_services/search_enable_top_hit_row",
-                "device_personalization_services/search_max_people_count",
-                "device_personalization_services/search_qsb_result_types",
-                "device_personalization_services/search_root_pack_budget_time_millis",
-                "device_personalization_services/search_screenshot_content",
-                "device_personalization_services/sensors_only_budget_millis",
-                "device_personalization_services/sentence_piece_tokenizer_superpacks_manifest_url_template",
-                "device_personalization_services/sentence_piece_tokenizer_superpacks_manifest_version",
-                "device_personalization_services/session_name_prefix_for_debug_override",
-                "device_personalization_services/sharesheet_enable_base_score_adjustment",
-                "device_personalization_services/sharesheet_enable_nearby_share_exp",
-                "device_personalization_services/sharesheet_enable_pin_direct_share",
-                "device_personalization_services/sharesheet_enable_screenshot_predictor",
-                "device_personalization_services/sharesheet_enable_shortcut_usage",
-                "device_personalization_services/sharesheet_enable_whatsapp_pecan",
-                "device_personalization_services/shopping_model_download_enabled",
-                "device_personalization_services/should_enable_for_common_packages",
-                "device_personalization_services/show_cross_device_timer_label",
-                "device_personalization_services/show_debug_notification",
-                "device_personalization_services/show_enabled_apps_list_in_settings",
-                "device_personalization_services/show_promo_notification",
-                "device_personalization_services/show_user_settings",
-                "device_personalization_services/silent_feedback_crash_rate_percent",
-                "device_personalization_services/sim_event_screen_session_id",
-                "device_personalization_services/s_lower_threshold",
-                "device_personalization_services/small_max_bucket_size",
-                "device_personalization_services/small_refresh_period",
-                "device_personalization_services/smart_select_brella_population_name",
-                "device_personalization_services/smart_select_brella_population_name_prefix",
-                "device_personalization_services/smart_select_brella_register_to_eval_populations",
-                "device_personalization_services/smart_select_brella_session_name",
-                "device_personalization_services/smart_select_brella_session_name_prefix",
-                "device_personalization_services/smart_select_example_ttl_ms",
-                "device_personalization_services/smartspace_doorbell_aiai_loading_screen",
-                "device_personalization_services/smartspace_enable_battery_notification_parser",
-                "device_personalization_services/smartspace_enable_bedtime_active_predictor",
-                "device_personalization_services/smartspace_enable_bedtime_reminder_predictor",
-                "device_personalization_services/smartspace_enable_bluetooth_metadata_parser",
-                "device_personalization_services/smartspace_enable_daily_forecast",
-                "device_personalization_services/smartspace_enable_dwb_bedtime_predictor",
-                "device_personalization_services/smartspace_enable_earthquake_alert_predictor",
-                "device_personalization_services/smartspace_enable_echo_settings",
-                "device_personalization_services/smartspace_enable_light_off_predictor",
-                "device_personalization_services/smartspace_enable_light_predictor",
-                "device_personalization_services/smartspace_enable_paired_device_predictor",
-                "device_personalization_services/smartspace_enable_safety_check_predictor",
-                "device_personalization_services/smartspace_enable_score_ranker",
-                "device_personalization_services/smartspace_enable_step_predictor",
-                "device_personalization_services/smartspace_enable_subcard_logging",
-                "device_personalization_services/smartspace_enable_timely_reminder",
-                "device_personalization_services/smartspace_enable_weather_data_pull_scheduler",
-                "device_personalization_services/smartspace_use_card_expire_as_dismiss_ttl",
-                "device_personalization_services/smartspace_weather_data_pull_interval_min",
-                "device_personalization_services/s_max_episode_duration_seconds",
-                "device_personalization_services/s_maximum_tolerance_duration_seconds",
-                "device_personalization_services/s_max_inactivity_duration_seconds",
-                "device_personalization_services/s_min_episode_density",
-                "device_personalization_services/s_min_episode_duration_seconds",
-                "device_personalization_services/soda_audio_dump_to_disk_enabled",
-                "device_personalization_services/sound_model_id",
-                "device_personalization_services/speech_recognition_service_settings_enabled",
-                "device_personalization_services/speech_threshold",
-                "device_personalization_services/spelling_checker_frequency_score_overrides_map",
-                "device_personalization_services/split_text_by_newline",
-                "device_personalization_services/storage_stats_log_sample_interval",
-                "device_personalization_services/superpacks_manifest_url",
-                "device_personalization_services/superpacks_manifest_ver",
-                "device_personalization_services/s_upper_threshold",
-                "device_personalization_services/supported_app_packages",
-                "device_personalization_services/supported_languages",
-                "device_personalization_services/supported_speech_personalization_locales",
-                "device_personalization_services/suppress_aiai_textclassifiers",
-                "device_personalization_services/surface_sound_events",
-                "device_personalization_services/switch_to_smartrec_flow",
-                "device_personalization_services/synthetic_fa_screen_session_id",
-                "device_personalization_services/tc_easter_egg_action_name",
-                "device_personalization_services/tc_easter_egg_activity_name",
-                "device_personalization_services/tc_easter_egg_package_name",
-                "device_personalization_services/tc_easter_egg_templates",
-                "device_personalization_services/tc_easter_egg_url",
-                "device_personalization_services/tc_easter_egg_url_param",
-                "device_personalization_services/tclib_actions_superpacks_manifest_url_template",
-                "device_personalization_services/tclib_actions_superpacks_manifest_version",
-                "device_personalization_services/tclib_annotator_superpacks_manifest_url_template",
-                "device_personalization_services/tclib_annotator_superpacks_manifest_version",
-                "device_personalization_services/tclib_langid_superpacks_manifest_url_template",
-                "device_personalization_services/tclib_langid_superpacks_manifest_version",
-                "device_personalization_services/template_table_superpacks_manifest_url_template",
-                "device_personalization_services/text_and_particle_overlap_tolerance",
-                "device_personalization_services/text_to_text_language_list",
-                "device_personalization_services/text_transform_augmented_input",
-                "device_personalization_services/timeout_seconds",
-                "device_personalization_services/tng_recognition_service_enabled",
-                "device_personalization_services/tng_recognition_service_first_party_app_whitelist",
-                "device_personalization_services/tng_transcription_domain_id_map",
-                "device_personalization_services/tng_transcription_soda_ttl_sec",
-                "device_personalization_services/toast_dota_manifest_config",
-                "device_personalization_services/toast_enable_mdd",
-                "device_personalization_services/training_brella_model_enabled",
-                "device_personalization_services/translate_ambiguous_languages_enabled",
-                "device_personalization_services/translate_chinese_script_threshold",
-                "device_personalization_services/translate_devanagari_script_threshold",
-                "device_personalization_services/translate_hebrew_script_threshold",
-                "device_personalization_services/translate_japanese_script_threshold",
-                "device_personalization_services/translate_korean_script_threshold",
-                "device_personalization_services/translate_language_confidence_threshold",
-                "device_personalization_services/translate_language_denylist",
-                "device_personalization_services/translate_overview_small_image_thresholds_enabled",
-                "device_personalization_services/translation_service_enabled",
-                "device_personalization_services/translator_expiration_enabled",
-                "device_personalization_services/trim_visual_property_set",
-                "device_personalization_services/ttl_job_hours_interval",
-                "device_personalization_services/uniform_lower_bound",
-                "device_personalization_services/uniform_upper_bound",
-                "device_personalization_services/uniform_val_screen_session_id",
-                "device_personalization_services/update_policy",
-                "device_personalization_services/use_astrea_http_downloader_transport",
-                "device_personalization_services/use_astrea_pir_downloader_transport",
-                "device_personalization_services/use_common_store_for_search",
-                "device_personalization_services/use_flow_for_callback",
-                "device_personalization_services/use_gpu",
-                "device_personalization_services/use_in_memory_storage",
-                "device_personalization_services/use_installed_apps_for_visual_cortex",
-                "device_personalization_services/use_logging_listener",
-                "device_personalization_services/use_mdd_download_system",
-                "device_personalization_services/use_people_db_entities",
-                "device_personalization_services/user_setting_default_value",
-                "device_personalization_services/use_silence_detector_state_bug_fix",
-                "device_personalization_services/use_translate_kit_streaming_api",
-                "device_personalization_services/use_vocab_annotator",
-                "device_personalization_services/view_tree_event_delay_in_mills",
-                "device_personalization_services/visibility_playing_duration_millis",
-                "device_personalization_services/visibility_stopped_duration_millis",
-                "device_personalization_services/volume_adjust_delay_seconds",
-                "device_personalization_services/volume_change_after_media_starts_reaction_time_seconds",
-                "device_personalization_services/webref_superpacks_manifest_url_template",
-                "device_personalization_services/webref_supported_locales",
-                "device_personalization_services/webref_url_template",
-                "device_personalization_services/wifi_predictor_weight",
-                "device_personalization_services/write_to_pfd",
-                "device_personalization_services/youtube_export_enabled",
+                "device_personalization_services/Captions__disable_prod",
+                "device_personalization_services/Echo__smartspace_enable_doorbell",
+                "device_personalization_services/Overview__enable_superpacks_download",
                 "device_policy_manager/add-isfinanced-device",
                 "device_policy_manager/deprecate_usermanagerinternal_devicepolicy",
                 "device_policy_manager/enable_coexistence",
@@ -1098,118 +278,15 @@ final class WritableFlags {
                 "flipendo/flipendo_enabled_launch",
                 "flipendo/grayscale_enabled_launch",
                 "flipendo/is_ask_feature_enabled_launch",
+                "flipendo/lever_ble_scanning_enabled_launch",
                 "flipendo/lever_hotspot_enabled_launch",
                 "flipendo/lever_work_profile_enabled_launch",
                 "flipendo/resuspend_delay_minutes",
                 "flipendo/work_profile_tab_enabled",
                 "game_driver/crosshatch_blacklists",
-                "game_overlay/bubbleshooter.orig",
-                "game_overlay/com.activision.callofduty.shooter",
-                "game_overlay/com.aim.racing",
+                "game_overlay/android.gameframerate.cts",
+                "game_overlay/android.gamemanager.cts.app.gametestapp.performance",
                 "game_overlay/com.android.server.cts.device.statsdatom",
-                "game_overlay/com.aniplex.fategrandorder",
-                "game_overlay/com.aniplex.twst.jp",
-                "game_overlay/com.ansangha.drdriving",
-                "game_overlay/com.archosaur.sea.dr.gp",
-                "game_overlay/com.bandainamcoent.dblegends_ww",
-                "game_overlay/com.bethsoft.blade",
-                "game_overlay/com.bhvr.deadbydaylight",
-                "game_overlay/com.blizzard.diablo.immortal",
-                "game_overlay/com.blizzard.wtcg.hearthstone",
-                "game_overlay/com.craftsman.go",
-                "game_overlay/com.devsisters.ck",
-                "game_overlay/com.droidhang.ad",
-                "game_overlay/com.dts.freefiremax",
-                "game_overlay/com.dts.freefireth",
-                "game_overlay/com.ea.gp.fifamobile",
-                "game_overlay/com.epicgames.fortnite",
-                "game_overlay/com.fingersoft.hillclimb",
-                "game_overlay/com.firsttouchgames.story",
-                "game_overlay/com.fun.games.commando.black.shadow",
-                "game_overlay/com.gameloft.anmp.lego.heroes",
-                "game_overlay/com.garena.game.codm",
-                "game_overlay/com.garena.game.kgid",
-                "game_overlay/com.garena.game.kgth",
-                "game_overlay/com.garena.game.kgtw",
-                "game_overlay/com.garena.game.kgvn",
-                "game_overlay/com.gravity.romg",
-                "game_overlay/com.gta.real.gangster.crime",
-                "game_overlay/com.idle.heroes",
-                "game_overlay/com.innersloth.spacemafia",
-                "game_overlay/com.jamcity.wwd",
-                "game_overlay/com.kabam.marvelbattle",
-                "game_overlay/com.kiloo.subwaysurf",
-                "game_overlay/com.king.candycrushsaga",
-                "game_overlay/com.king.candycrushsodasaga",
-                "game_overlay/com.king.farmheroessaga",
-                "game_overlay/com.lilithgame.roc.gp",
-                "game_overlay/com.lockwoodpublishing.avakinlife",
-                "game_overlay/com.ludo.king",
-                "game_overlay/com.maleo.bussimulatorid",
-                "game_overlay/com.miniclip.carrom",
-                "game_overlay/com.miniclip.eightballpool",
-                "game_overlay/com.mobile.legends",
-                "game_overlay/com.mojang.minecraftpe",
-                "game_overlay/com.moonactive.coinmaster",
-                "game_overlay/com.moonfrog.ludo.club",
-                "game_overlay/com.nekki.shadowfight",
-                "game_overlay/com.neowiz.games.newmatgo",
-                "game_overlay/com.neptune.domino",
-                "game_overlay/com.netease.eve.en",
-                "game_overlay/com.netmarble.bnsmasia",
-                "game_overlay/com.netmarble.nanagb",
-                "game_overlay/com.netmarble.sknightsmmo",
-                "game_overlay/com.nexon.kart",
-                "game_overlay/com.ngame.allstar.eu",
-                "game_overlay/com.nianticlabs.pokemongo",
-                "game_overlay/com.nintendo.zaca",
-                "game_overlay/com.olzhas.carparking.multyplayer",
-                "game_overlay/com.onepunchman.ggplay.sea",
-                "game_overlay/com.pearlabyss.blackdesertm.gl",
-                "game_overlay/com.peoplefun.wordcross",
-                "game_overlay/com.pieyel.scrabble",
-                "game_overlay/com.pixel.art.coloring.color.number",
-                "game_overlay/com.plarium.raidlegends",
-                "game_overlay/com.playmini.miniworld",
-                "game_overlay/com.playrix.gardenscapes",
-                "game_overlay/com.playrix.homescapes",
-                "game_overlay/com.playrix.township",
-                "game_overlay/com.pubg.krmobile",
-                "game_overlay/com.rioo.runnersubway",
-                "game_overlay/com.riotgames.league.wildrift",
-                "game_overlay/com.riotgames.league.wildrifttw",
-                "game_overlay/com.roblox.client",
-                "game_overlay/com.rockstargames.gtasa",
-                "game_overlay/com.sandboxol.blockymods",
-                "game_overlay/com.square.enix.android.googleplay.dqtactj",
-                "game_overlay/com.square.enix.android.googleplay.dqwalkj",
-                "game_overlay/com.square.enix.android.googleplay.finalfantasy",
-                "game_overlay/com.square.enix.android.googleplay.nierspjp",
-                "game_overlay/com.supercell.brawlstars",
-                "game_overlay/com.supercell.clashofclans",
-                "game_overlay/com.supercell.clashroyale",
-                "game_overlay/com.supercell.hayday",
-                "game_overlay/com.superking.parchisi.star",
-                "game_overlay/com.tencent.ig",
-                "game_overlay/com.tencent.iglite",
-                "game_overlay/com.tencent.tmgp.sskeus",
-                "game_overlay/com.tencent.tmgp.sskjp",
-                "game_overlay/com.tencent.tmgp.ssktw",
-                "game_overlay/com.valvesoftware.underlords",
-                "game_overlay/com.vectorunit.purple.googleplay",
-                "game_overlay/com.vizorapps.klondike",
-                "game_overlay/com.vng.pubgmobile",
-                "game_overlay/com.wildspike.wormszone",
-                "game_overlay/com.youmusic.magictiles",
-                "game_overlay/com.zakg.scaryteacher.hellgame",
-                "game_overlay/com.zeeron.callbreak",
-                "game_overlay/jp.co.mixi.monsterstrike",
-                "game_overlay/jp.garud.ssimulator",
-                "game_overlay/jp.konami.pesam",
-                "game_overlay/jp.konami.prospia",
-                "game_overlay/net.peakgames.toonblast",
-                "game_overlay/net.wargaming.wot.blitz",
-                "game_overlay/net.wooga.junes_journey_hidden_object_mystery_game",
                 "halyard_demo/enable_test_param",
                 "halyard_demo/enable_test_param_beta",
                 "hdmi_control/enable_earc_tx",
@@ -1294,14 +371,15 @@ final class WritableFlags {
                 "launcher/show_search_educard_qsb",
                 "launcher/use_app_search_for_web",
                 "launcher/use_fallback_app_search",
+                "lmkd_native/filecache_min_kb",
                 "lmkd_native/thrashing_limit_critical",
-                "location/adas_settings_allowlist",
-                "location/enable_location_provider_manager_msl",
-                "location/ignore_settings_allowlist",
                 "low_power_standby/enable_policy",
                 "low_power_standby/enable_standby_ports",
                 "media_better_together/scanning_package_minimum_importance",
+                "media_tv/android.media.tv.flags.enable_ad_service_fw",
+                "media_tv/android.media.tv.flags.tiaf_v_apis",
                 "media/media_metrics_mode",
+                "media/media_session_temp_user_engaged_duration_ms",
                 "media/player_metrics_app_allowlist",
                 "media/player_metrics_app_blocklist",
                 "media/player_metrics_per_app_attribution_allowlist",
@@ -1312,6 +390,7 @@ final class WritableFlags {
                 "media/player_metrics_per_app_use_time_blocklist",
                 "mediaprovider/allowed_cloud_providers",
                 "mediaprovider/cloud_media_feature_enabled",
+                "mediaprovider/com.android.providers.media.flags.enable_modern_photopicker",
                 "mediaprovider/picker_pick_images_preload_selected",
                 "memory_safety_native_boot/bootloader_override",
                 "mglru_native/lru_gen_config",
@@ -1324,45 +403,13 @@ final class WritableFlags {
                 "namespace2/key3",
                 "namespace3/key3",
                 "namespace3/key4",
+                "namespace4/key3",
                 "namespace4/key4",
                 "namespace/key",
                 "nnapi_native/current_feature_level",
                 "nnapi_native/telemetry_enable",
                 "notification_assistant/generate_actions",
                 "notification_assistant/generate_replies",
-                "odad/app_ops_feature_killswitch",
-                "odad/binary_transparency_log_signature_verification_key",
-                "odad/cached_app_ops_killswitch",
-                "odad/cached_feature_encryption_killswitch",
-                "odad/enable_astrea_moirai",
-                "odad/enable_fa_particiation_rule",
-                "odad/enable_hades_testing_classifier",
-                "odad/enable_refactored_install_attribution",
-                "odad/enable_sample_param",
-                "odad/fa_model_score_thresholds_csv",
-                "odad/fa_participation_random_bias",
-                "odad/full_killswitch",
-                "odad/heuristic_classifier_killswitch",
-                "odad/launch_appop_permission_odad",
-                "odad/launch_odad",
-                "odad/log_classification_latency_westworld",
-                "odad/log_error_model_id_westworld_enabled",
-                "odad/log_model_id_westworld",
-                "odad/log_model_version_westworld",
-                "odad/max_classification_reports",
-                "odad/max_lightweight_executor_threads",
-                "odad/max_low_cost_scanning_apps",
-                "odad/mck_result_random_bias",
-                "odad/moirai_ml_score_version_enabled",
-                "odad/moirai_sw_master_feature",
-                "odad/moirai_use_testing_client_id",
-                "odad/num_low_classification_count_packages_to_scan",
-                "odad/num_recent_packages_to_scan",
-                "odad/only_scan_offmarket",
-                "odad/reputation_classifier_killswitch",
-                "odad/scan_least_scanned",
-                "odad/sw_scn",
-                "odad/westworld_logging",
                 "ondeviceintelligence/service_enabled",
                 "oslo/mcc_whitelist",
                 "oslo/media_app_whitelist",
@@ -1384,6 +431,7 @@ final class WritableFlags {
                 "package_manager_service/MinInstallableTargetSdk__install_block_enabled",
                 "package_manager_service/MinInstallableTargetSdk__install_block_strict_mode_enabled",
                 "package_manager_service/MinInstallableTargetSdk__min_installable_target_sdk",
+                "package_manager_service/MinInstallableTargetSdk__strict_mode_target_sdk",
                 "package_manager_service/strict_mode_target_sdk",
                 "package_manager_service/verification_request_timeout_millis",
                 "package_manager_service/verifier_connection_timeout_millis",
@@ -1392,8 +440,8 @@ final class WritableFlags {
                 "permissions/one_time_permissions_killed_delay_millis",
                 "permissions/one_time_permissions_timeout_millis",
                 "permissions/permission_changes_store_exact_time",
+                "pmw/vendor.google.aam.flags.enable_aam",
                 "privacy/bg_location_check_is_enabled",
-                "privacy/camera_mic_icons_enabled",
                 "privacy/camera_toggle_enabled",
                 "privacy/data_sharing_update_period_millis",
                 "privacy/discrete_history_cutoff_millis",
@@ -1454,6 +502,7 @@ final class WritableFlags {
                 "profiling/cost_java_heap_dump",
                 "profiling/cost_stack_sampling",
                 "profiling/cost_system_trace",
+                "profiling/cost_system_triggered_system_trace",
                 "profiling/heap_profile_duration_ms_default",
                 "profiling/heap_profile_duration_ms_max",
                 "profiling/heap_profile_duration_ms_min",
@@ -1478,7 +527,10 @@ final class WritableFlags {
                 "profiling/system_trace_duration_ms_default",
                 "profiling/system_trace_duration_ms_max",
                 "profiling/system_trace_duration_ms_min",
+                "profiling/system_triggered_trace_max_period_seconds",
+                "profiling/system_triggered_trace_min_period_seconds",
                 "profiling_testing/rate_limiter.disabled",
+                "profiling_testing/system_triggered_profiling.testing_package_name",
                 "reboot_readiness/active_polling_interval_ms",
                 "reboot_readiness/alarm_clock_threshold_ms",
                 "reboot_readiness/disable_app_activity_check",
@@ -1525,9 +577,14 @@ final class WritableFlags {
                 "runtime_native/use_app_image_startup_cache",
                 "settings_stats/boolean_whitelist",
                 "settings_stats/float_whitelist",
+                "settings_stats/GlobalFeature__boolean_whitelist",
+                "settings_stats/GlobalFeature__float_whitelist",
                 "settings_stats/GlobalFeature__integer_whitelist",
+                "settings_stats/GlobalFeature__string_whitelist",
                 "settings_stats/integer_whitelist",
                 "settings_stats/string_whitelist",
+                "settings_stats/testflag",
+                "settings_ui/banner_message_pref_hide_resolved_content_delay_millis",
                 "statsd_java/include_certificate_hash",
                 "statsd_java/use_file_descriptor",
                 "statsd_native/app_upgrade_bucket_split",
@@ -1592,6 +649,7 @@ final class WritableFlags {
                 "systemui/back_gesture_ml_name",
                 "systemui/back_gesture_ml_threshold",
                 "systemui/behavior_mode",
+                "systemui/cursor_hover_states_enabled",
                 "systemui/dark_launch_remote_prediction_service_enabled",
                 "systemui/duration_per_px_fast",
                 "systemui/duration_per_px_regular",
@@ -1637,10 +695,16 @@ final class WritableFlags {
                 "systemui/suppress_on_lockscreen",
                 "systemui/tap_to_edit",
                 "systemui/task_manager_enabled",
+                "systemui/test_key",
                 "systemui/use_back_gesture_ml",
                 "systemui/use_unbundled_sharesheet",
                 "systemui/volume_separate_notification",
                 "tare/enable_tare",
+                "telecom/com.android.server.telecom.flags.cache_call_audio_callbacks",
+                "telecom/com.android.server.telecom.flags.get_registered_phone_accounts",
+                "telecom/com.android.server.telecom.flags.telecom_main_user_in_block_check",
+                "telecom/com.android.server.telecom.flags.telecom_main_user_in_get_respond_message_app",
+                "telecom/com.android.server.telecom.flags.unregister_unresolvable_accounts",
                 "telephony/anomaly_apn_config_enabled",
                 "telephony/anomaly_ims_release_request",
                 "telephony/anomaly_network_connecting_timeout",
@@ -1652,6 +716,10 @@ final class WritableFlags {
                 "telephony/anomaly_setup_data_call_failure",
                 "telephony/auto_data_switch_availability_stability_time_threshold",
                 "telephony/auto_data_switch_validation_max_retry",
+                "telephony/com.android.internal.telephony.flags.carrier_enabled_satellite_flag",
+                "telephony/com.android.internal.telephony.flags.carrier_roaming_nb_iot_ntn",
+                "telephony/com.android.internal.telephony.flags.oem_enabled_satellite_flag",
+                "telephony/config_satellite_carrier_roaming_esos_provisioned_class",
                 "telephony/enable_logcat_collection_for_emergency_call_diagnostics",
                 "telephony/enable_new_data_stack",
                 "telephony/enable_slicing_upsell",
@@ -1665,6 +733,7 @@ final class WritableFlags {
                 "telephony/ramping_ringer_enabled",
                 "telephony/ramping_ringer_vibration_duration",
                 "test_od_namespace/key1",
+                "test_namespace/test_key",
                 "testspace/another",
                 "testspace/flagname",
                 "textclassifier/ar_manifest",
@@ -1683,6 +752,41 @@ final class WritableFlags {
                 "textclassifier/local_textclassifier_enabled",
                 "textclassifier/manifest_download_max_attempts",
                 "textclassifier/manifest_download_required_network_type",
+                "textclassifier/manifest_url_actions_suggestions_de",
+                "textclassifier/manifest_url_actions_suggestions_de-ch",
+                "textclassifier/manifest_url_actions_suggestions_de-li",
+                "textclassifier/manifest_url_actions_suggestions_en",
+                "textclassifier/manifest_url_actions_suggestions_es",
+                "textclassifier/manifest_url_actions_suggestions_fr",
+                "textclassifier/manifest_url_actions_suggestions_it",
+                "textclassifier/manifest_url_actions_suggestions_ja",
+                "textclassifier/manifest_url_actions_suggestions_ko",
+                "textclassifier/manifest_url_actions_suggestions_pt-br",
+                "textclassifier/manifest_url_actions_suggestions_universal",
+                "textclassifier/manifest_url_actions_suggestions_zh",
+                "textclassifier/manifest_url_actions_suggestions_zh-hant",
+                "textclassifier/manifest_url_annotator_ar",
+                "textclassifier/manifest_url_annotator_da",
+                "textclassifier/manifest_url_annotator_de",
+                "textclassifier/manifest_url_annotator_en",
+                "textclassifier/manifest_url_annotator_es",
+                "textclassifier/manifest_url_annotator_fr",
+                "textclassifier/manifest_url_annotator_it",
+                "textclassifier/manifest_url_annotator_ja",
+                "textclassifier/manifest_url_annotator_ko",
+                "textclassifier/manifest_url_annotator_nb",
+                "textclassifier/manifest_url_annotator_nl",
+                "textclassifier/manifest_url_annotator_nn",
+                "textclassifier/manifest_url_annotator_no",
+                "textclassifier/manifest_url_annotator_pl",
+                "textclassifier/manifest_url_annotator_pt",
+                "textclassifier/manifest_url_annotator_ru",
+                "textclassifier/manifest_url_annotator_sv",
+                "textclassifier/manifest_url_annotator_th",
+                "textclassifier/manifest_url_annotator_tr",
+                "textclassifier/manifest_url_annotator_universal",
+                "textclassifier/manifest_url_annotator_zh",
+                "textclassifier/manifest_url_lang_id_universal",
                 "textclassifier/model_download_backoff_delay_in_millis",
                 "textclassifier/model_download_manager_enabled",
                 "textclassifier/model_download_worker_max_attempts",
@@ -1771,26 +875,16 @@ final class WritableFlags {
                 "wifi/stationary_scan_rssi_valid_time_ms",
                 "wifi/wfd_failure_bugreport_enabled",
                 "window_manager/ActivitySecurity__asm_restrictions_enabled",
-                "window_manager/asm_exempted_packages",
+                "window_manager/AlwaysOnMagnifier__enable_always_on_magnifier",
                 "window_manager/asm_restrictions_enabled",
                 "window_manager/asm_toasts_enabled",
                 "window_manager/enable_always_on_magnifier",
                 "window_manager/enable_camera_compat_treatment",
                 "window_manager/enable_compat_fake_focus",
-                "window_manager/enabled",
-                "window_manager/enable_default_rescind_bal_privileges_from_pending_intent_sender",
                 "window_manager/enable_letterbox_reachability_education",
                 "window_manager/enable_letterbox_restart_dialog",
-                "window_manager/enable_magnification_joystick",
                 "window_manager/enable_non_linear_font_scaling",
                 "window_manager/enable_translucent_activity_letterbox",
-                "window_manager/log_raw_sensor_data",
-                "window_manager_native_boot/use_blast_adapter",
-                "window_manager/record_task_content",
-                "window_manager/rotation_memorization_timeout_millis",
-                "window_manager/rotation_resolver_timeout_millis",
-                "window_manager/screen_record_enterprise_policies",
-                "window_manager/single_use_token",
                 "window_manager/splash_screen_exception_list",
                 "wrong/nas_generate_replies"
             ));
diff --git a/framework/java/android/provider/WritableNamespaces.java b/framework/java/android/provider/WritableNamespaces.java
index e3ea00b..c9c21d8 100644
--- a/framework/java/android/provider/WritableNamespaces.java
+++ b/framework/java/android/provider/WritableNamespaces.java
@@ -37,13 +37,17 @@ final class WritableNamespaces {
     public static final Set<String> ALLOWLIST =
             new ArraySet<String>(Arrays.asList(
                     "adservices",
+                    "autofill",
+                    "app_compat_overrides",
                     "captive_portal_login",
                     "connectivity",
                     "exo",
+                    "location",
                     "nearby",
                     "netd_native",
                     "network_security",
                     "on_device_personalization",
+                    "testing",
                     "tethering",
                     "tethering_u_or_later_native",
                     "thread_network"
diff --git a/framework/java/android/util/configinfrastructure/Android.bp b/framework/java/android/util/configinfrastructure/Android.bp
new file mode 100644
index 0000000..c7032d6
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/Android.bp
@@ -0,0 +1,46 @@
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "modules-utils-longarray",
+    defaults: ["framework-module-defaults"],
+    srcs: ["LongArray.java"],
+    libs: [
+        "unsupportedappusage",
+        "error_prone_annotations",
+    ],
+    static_libs: [
+        "modules-utils-preconditions",
+        "modules-utils-arrayutils",
+    ],
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+    ],
+}
+
+java_library {
+    name: "modules-utils-emptyarray",
+    defaults: ["framework-module-defaults"],
+    srcs: ["EmptyArray.java"],
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+    ],
+}
diff --git a/framework/java/android/util/configinfrastructure/EmptyArray.java b/framework/java/android/util/configinfrastructure/EmptyArray.java
new file mode 100644
index 0000000..e89700f
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/EmptyArray.java
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.util.configinfrastructure;
+
+import android.annotation.NonNull;
+
+/**
+ * Empty array is immutable. Use a shared empty array to avoid allocation.
+ *
+ * This is copied from frameworks/base/core/java/android/util/EmptyArray.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * EmptyArray should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public final class EmptyArray {
+    private EmptyArray() {}
+
+    public static final @NonNull boolean[] BOOLEAN = new boolean[0];
+    public static final @NonNull byte[] BYTE = new byte[0];
+    public static final @NonNull char[] CHAR = new char[0];
+    public static final @NonNull double[] DOUBLE = new double[0];
+    public static final @NonNull float[] FLOAT = new float[0];
+    public static final @NonNull int[] INT = new int[0];
+    public static final @NonNull long[] LONG = new long[0];
+    public static final @NonNull Object[] OBJECT = new Object[0];
+    public static final @NonNull String[] STRING = new String[0];
+}
diff --git a/framework/java/android/util/configinfrastructure/LongArray.java b/framework/java/android/util/configinfrastructure/LongArray.java
new file mode 100644
index 0000000..1deeb3d
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/LongArray.java
@@ -0,0 +1,240 @@
+/*
+ * Copyright (C) 2013 The Android Open Source Project
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
+package android.util.configinfrastructure;
+
+import android.annotation.Nullable;
+import android.compat.annotation.UnsupportedAppUsage;
+import android.os.Build;
+
+import com.android.internal.util.configinfrastructure.ArrayUtils;
+import com.android.internal.util.Preconditions;
+
+import java.util.Arrays;
+
+/**
+ * Implements a growing array of long primitives.
+ *
+ * This is copied from frameworks/base/core/java/android/util/LongArray.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * LongArray should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class LongArray implements Cloneable {
+    private static final int MIN_CAPACITY_INCREMENT = 12;
+
+    private long[] mValues;
+    private int mSize;
+
+    private  LongArray(long[] array, int size) {
+        mValues = array;
+        mSize = Preconditions.checkArgumentInRange(size, 0, array.length, "size");
+    }
+
+    /**
+     * Creates an empty LongArray with the default initial capacity.
+     */
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    public LongArray() {
+        this(0);
+    }
+
+    /**
+     * Creates an empty LongArray with the specified initial capacity.
+     */
+    public LongArray(int initialCapacity) {
+        if (initialCapacity == 0) {
+            mValues = EmptyArray.LONG;
+        } else {
+            mValues = ArrayUtils.newUnpaddedLongArray(initialCapacity);
+        }
+        mSize = 0;
+    }
+
+    /**
+     * Creates an LongArray wrapping the given primitive long array.
+     */
+    public static LongArray wrap(long[] array) {
+        return new LongArray(array, array.length);
+    }
+
+    /**
+     * Creates an LongArray from the given primitive long array, copying it.
+     */
+    public static LongArray fromArray(long[] array, int size) {
+        return wrap(Arrays.copyOf(array, size));
+    }
+
+    /**
+     * Changes the size of this LongArray. If this LongArray is shrinked, the backing array capacity
+     * is unchanged. If the new size is larger than backing array capacity, a new backing array is
+     * created from the current content of this LongArray padded with 0s.
+     */
+    public void resize(int newSize) {
+        Preconditions.checkArgumentNonnegative(newSize);
+        if (newSize <= mValues.length) {
+            Arrays.fill(mValues, newSize, mValues.length, 0);
+        } else {
+            ensureCapacity(newSize - mSize);
+        }
+        mSize = newSize;
+    }
+
+    /**
+     * Appends the specified value to the end of this array.
+     */
+    public void add(long value) {
+        add(mSize, value);
+    }
+
+    /**
+     * Inserts a value at the specified position in this array. If the specified index is equal to
+     * the length of the array, the value is added at the end.
+     *
+     * @throws IndexOutOfBoundsException when index &lt; 0 || index &gt; size()
+     */
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    public void add(int index, long value) {
+        ensureCapacity(1);
+        int rightSegment = mSize - index;
+        mSize++;
+        ArrayUtils.checkBounds(mSize, index);
+
+        if (rightSegment != 0) {
+            // Move by 1 all values from the right of 'index'
+            System.arraycopy(mValues, index, mValues, index + 1, rightSegment);
+        }
+
+        mValues[index] = value;
+    }
+
+    /**
+     * Adds the values in the specified array to this array.
+     */
+    public void addAll(LongArray values) {
+        final int count = values.mSize;
+        ensureCapacity(count);
+
+        System.arraycopy(values.mValues, 0, mValues, mSize, count);
+        mSize += count;
+    }
+
+    /**
+     * Ensures capacity to append at least <code>count</code> values.
+     */
+    private void ensureCapacity(int count) {
+        final int currentSize = mSize;
+        final int minCapacity = currentSize + count;
+        if (minCapacity >= mValues.length) {
+            final int targetCap = currentSize + (currentSize < (MIN_CAPACITY_INCREMENT / 2) ?
+                    MIN_CAPACITY_INCREMENT : currentSize >> 1);
+            final int newCapacity = targetCap > minCapacity ? targetCap : minCapacity;
+            final long[] newValues = ArrayUtils.newUnpaddedLongArray(newCapacity);
+            System.arraycopy(mValues, 0, newValues, 0, currentSize);
+            mValues = newValues;
+        }
+    }
+
+    /**
+     * Removes all values from this array.
+     */
+    public void clear() {
+        mSize = 0;
+    }
+
+    @Override
+    public LongArray clone() {
+        LongArray clone = null;
+        try {
+            clone = (LongArray) super.clone();
+            clone.mValues = mValues.clone();
+        } catch (CloneNotSupportedException cnse) {
+            /* ignore */
+        }
+        return clone;
+    }
+
+    /**
+     * Returns the value at the specified position in this array.
+     */
+    @UnsupportedAppUsage
+    public long get(int index) {
+        ArrayUtils.checkBounds(mSize, index);
+        return mValues[index];
+    }
+
+    /**
+     * Sets the value at the specified position in this array.
+     */
+    public void set(int index, long value) {
+        ArrayUtils.checkBounds(mSize, index);
+        mValues[index] = value;
+    }
+
+    /**
+     * Returns the index of the first occurrence of the specified value in this
+     * array, or -1 if this array does not contain the value.
+     */
+    public int indexOf(long value) {
+        final int n = mSize;
+        for (int i = 0; i < n; i++) {
+            if (mValues[i] == value) {
+                return i;
+            }
+        }
+        return -1;
+    }
+
+    /**
+     * Removes the value at the specified index from this array.
+     */
+    public void remove(int index) {
+        ArrayUtils.checkBounds(mSize, index);
+        System.arraycopy(mValues, index + 1, mValues, index, mSize - index - 1);
+        mSize--;
+    }
+
+    /**
+     * Returns the number of values in this array.
+     */
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    public int size() {
+        return mSize;
+    }
+
+    /**
+     * Returns a new array with the contents of this LongArray.
+     */
+    public long[] toArray() {
+        return Arrays.copyOf(mValues, mSize);
+    }
+
+    /**
+     * Test if each element of {@code a} equals corresponding element from {@code b}
+     */
+    public static boolean elementsEqual(@Nullable LongArray a, @Nullable LongArray b) {
+        if (a == null || b == null) return a == b;
+        if (a.mSize != b.mSize) return false;
+        for (int i = 0; i < a.mSize; i++) {
+            if (a.get(i) != b.get(i)) {
+                return false;
+            }
+        }
+        return true;
+    }
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/Android.bp b/framework/java/android/util/configinfrastructure/proto/Android.bp
new file mode 100644
index 0000000..434dd14
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/Android.bp
@@ -0,0 +1,31 @@
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "modules-utils-proto",
+    defaults: ["framework-module-defaults"],
+    srcs: ["*.java"],
+    static_libs: [
+        "modules-utils-longarray",
+    ],
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+    ],
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/EncodedBuffer.java b/framework/java/android/util/configinfrastructure/proto/EncodedBuffer.java
new file mode 100644
index 0000000..6be2858
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/EncodedBuffer.java
@@ -0,0 +1,690 @@
+/*
+ * Copyright (C) 2012 The Android Open Source Project
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
+package android.util.configinfrastructure.proto;
+
+import android.util.Log;
+
+import java.util.ArrayList;
+
+/**
+ * A stream of bytes containing a read pointer and a write pointer,
+ * backed by a set of fixed-size buffers.  There are write functions for the
+ * primitive types stored by protocol buffers, but none of the logic
+ * for tags, inner objects, or any of that.
+ *
+ * Terminology:
+ *      *Pos:       Position in the whole data set (as if it were a single buffer).
+ *      *Index:     Position within a buffer.
+ *      *BufIndex:  Index of a buffer within the mBuffers list
+ *
+ * This is copied from frameworks/base/core/java/android/util/proto/EncodedBuffer.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * EncodedBuffer should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public final class EncodedBuffer {
+    private static final String TAG = "EncodedBuffer";
+
+    private final ArrayList<byte[]> mBuffers = new ArrayList<byte[]>();
+
+    private final int mChunkSize;
+
+    /**
+     * The number of buffers in mBuffers. Stored separately to avoid the extra
+     * function call to size() everywhere for bounds checking.
+     */
+    private int mBufferCount;
+
+    /**
+     * The buffer we are currently writing to.
+     */
+    private byte[] mWriteBuffer;
+
+    /**
+     * The index into mWriteBuffer that we will write to next.
+     * It may point to the end of the buffer, in which case,
+     * the NEXT write will allocate a new buffer.
+     */
+    private int mWriteIndex;
+
+    /**
+     * The index of mWriteBuffer in mBuffers.
+     */
+    private int mWriteBufIndex;
+
+    /**
+     * The buffer we are currently reading from.
+     */
+    private byte[] mReadBuffer;
+
+    /**
+     * The index of mReadBuffer in mBuffers.
+     */
+    private int mReadBufIndex;
+
+    /**
+     * The index into mReadBuffer that we will read from next.
+     * It may point to the end of the buffer, in which case,
+     * the NEXT read will advance to the next buffer.
+     */
+    private int mReadIndex;
+
+    /**
+     * The amount of data in the last buffer.
+     */
+    private int mReadLimit = -1;
+
+    /**
+     * How much data there is total.
+     */
+    private int mReadableSize = -1;
+
+    public EncodedBuffer() {
+        this(0);
+    }
+
+    /**
+     * Construct an EncodedBuffer object.
+     *
+     * @param chunkSize The size of the buffers to use.  If chunkSize &lt;= 0, a default
+     *                  size will be used instead.
+     */
+    public EncodedBuffer(int chunkSize) {
+        if (chunkSize <= 0) {
+            chunkSize = 8 * 1024;
+        }
+        mChunkSize = chunkSize;
+        mWriteBuffer = new byte[mChunkSize];
+        mBuffers.add(mWriteBuffer);
+        mBufferCount = 1;
+    }
+
+    //
+    // Buffer management.
+    //
+
+    /**
+     * Rewind the read and write pointers, and record how much data was last written.
+     */
+    public void startEditing() {
+        mReadableSize = ((mWriteBufIndex) * mChunkSize) + mWriteIndex;
+        mReadLimit = mWriteIndex;
+
+        mWriteBuffer = mBuffers.get(0);
+        mWriteIndex = 0;
+        mWriteBufIndex = 0;
+
+        mReadBuffer = mWriteBuffer;
+        mReadBufIndex = 0;
+        mReadIndex = 0;
+    }
+
+    /**
+     * Rewind the read pointer. Don't touch the write pointer.
+     */
+    public void rewindRead() {
+        mReadBuffer = mBuffers.get(0);
+        mReadBufIndex = 0;
+        mReadIndex = 0;
+    }
+
+    /**
+     * Only valid after startEditing. Returns -1 before that.
+     */
+    public int getReadableSize() {
+        return mReadableSize;
+    }
+
+    /**
+     * Returns the buffer size
+     * @return the buffer size
+     */
+    public int getSize() {
+        return ((mBufferCount - 1) * mChunkSize) + mWriteIndex;
+    }
+
+    //
+    // Reading from the read position.
+    //
+
+    /**
+     * Only valid after startEditing.
+     */
+    public int getReadPos() {
+        return ((mReadBufIndex) * mChunkSize) + mReadIndex;
+    }
+
+    /**
+     * Skip over _amount_ bytes.
+     */
+    public void skipRead(int amount) {
+        if (amount < 0) {
+            throw new RuntimeException("skipRead with negative amount=" + amount);
+        }
+        if (amount == 0) {
+            return;
+        }
+        if (amount <= mChunkSize - mReadIndex) {
+            mReadIndex += amount;
+        } else {
+            amount -= mChunkSize - mReadIndex;
+            mReadIndex = amount % mChunkSize;
+            if (mReadIndex == 0) {
+                mReadIndex = mChunkSize;
+                mReadBufIndex += (amount / mChunkSize);
+            } else {
+                mReadBufIndex += 1 + (amount / mChunkSize);
+            }
+            mReadBuffer = mBuffers.get(mReadBufIndex);
+        }
+    }
+
+    /**
+     * Read one byte from the stream and advance the read pointer.
+     *
+     * @throws IndexOutOfBoundsException if the read point is past the end of
+     * the buffer or past the read limit previously set by startEditing().
+     */
+    public byte readRawByte() {
+        if (mReadBufIndex > mBufferCount
+                || (mReadBufIndex == mBufferCount - 1 && mReadIndex >= mReadLimit)) {
+            throw new IndexOutOfBoundsException("Trying to read too much data"
+                    + " mReadBufIndex=" + mReadBufIndex + " mBufferCount=" + mBufferCount
+                    + " mReadIndex=" + mReadIndex + " mReadLimit=" + mReadLimit);
+        }
+        if (mReadIndex >= mChunkSize) {
+            mReadBufIndex++;
+            mReadBuffer = mBuffers.get(mReadBufIndex);
+            mReadIndex = 0;
+        }
+        return mReadBuffer[mReadIndex++];
+    }
+
+    /**
+     * Read an unsigned varint. The value will be returend in a java signed long.
+     */
+    public long readRawUnsigned() {
+        int bits = 0;
+        long result = 0;
+        while (true) {
+            final byte b = readRawByte();
+            result |= ((long)(b & 0x7F)) << bits;
+            if ((b & 0x80) == 0) {
+                return result;
+            }
+            bits += 7;
+            if (bits > 64) {
+                throw new ProtoParseException("Varint too long -- " + getDebugString());
+            }
+        }
+    }
+
+    /**
+     * Read 32 little endian bits from the stream.
+     */
+    public int readRawFixed32() {
+        return (readRawByte() & 0x0ff)
+                | ((readRawByte() & 0x0ff) << 8)
+                | ((readRawByte() & 0x0ff) << 16)
+                | ((readRawByte() & 0x0ff) << 24);
+    }
+
+    //
+    // Writing at a the end of the stream.
+    //
+
+    /**
+     * Advance to the next write buffer, allocating it if necessary.
+     *
+     * Must be called immediately <b>before</b> the next write, not after a write,
+     * so that a dangling empty buffer is not created.  Doing so will interfere
+     * with the expectation that mWriteIndex will point past the end of the buffer
+     * until the next read happens.
+     */
+    private void nextWriteBuffer() {
+        mWriteBufIndex++;
+        if (mWriteBufIndex >= mBufferCount) {
+            mWriteBuffer = new byte[mChunkSize];
+            mBuffers.add(mWriteBuffer);
+            mBufferCount++;
+        } else {
+            mWriteBuffer = mBuffers.get(mWriteBufIndex);
+        }
+        mWriteIndex = 0;
+    }
+
+    /**
+     * Write a single byte to the stream.
+     */
+    public void writeRawByte(byte val) {
+        if (mWriteIndex >= mChunkSize) {
+            nextWriteBuffer();
+        }
+        mWriteBuffer[mWriteIndex++] = val;
+    }
+
+    /**
+     * Return how many bytes a 32 bit unsigned varint will take when written to the stream.
+     */
+    public static int getRawVarint32Size(int val) {
+        if ((val & (0xffffffff << 7)) == 0) return 1;
+        if ((val & (0xffffffff << 14)) == 0) return 2;
+        if ((val & (0xffffffff << 21)) == 0) return 3;
+        if ((val & (0xffffffff << 28)) == 0) return 4;
+        return 5;
+    }
+
+    /**
+     * Write an unsigned varint to the stream. A signed value would need to take 10 bytes.
+     *
+     * @param val treated as unsigned.
+     */
+    public void writeRawVarint32(int val) {
+        while (true) {
+            if ((val & ~0x7F) == 0) {
+                writeRawByte((byte)val);
+                return;
+            } else {
+                writeRawByte((byte)((val & 0x7F) | 0x80));
+                val >>>= 7;
+            }
+        }
+    }
+
+    /**
+     * Return how many bytes a 32 bit signed zig zag value will take when written to the stream.
+     */
+    public static int getRawZigZag32Size(int val) {
+        return getRawVarint32Size(zigZag32(val));
+    }
+
+    /**
+     *  Write a zig-zag encoded value.
+     *
+     *  @param val treated as signed
+     */
+    public void writeRawZigZag32(int val) {
+        writeRawVarint32(zigZag32(val));
+    }
+
+    /**
+     * Return how many bytes a 64 bit varint will take when written to the stream.
+     */
+    public static int getRawVarint64Size(long val) {
+        if ((val & (0xffffffffffffffffL << 7)) == 0) return 1;
+        if ((val & (0xffffffffffffffffL << 14)) == 0) return 2;
+        if ((val & (0xffffffffffffffffL << 21)) == 0) return 3;
+        if ((val & (0xffffffffffffffffL << 28)) == 0) return 4;
+        if ((val & (0xffffffffffffffffL << 35)) == 0) return 5;
+        if ((val & (0xffffffffffffffffL << 42)) == 0) return 6;
+        if ((val & (0xffffffffffffffffL << 49)) == 0) return 7;
+        if ((val & (0xffffffffffffffffL << 56)) == 0) return 8;
+        if ((val & (0xffffffffffffffffL << 63)) == 0) return 9;
+        return 10;
+    }
+
+    /**
+     * Write a 64 bit varint to the stream.
+     */
+    public void writeRawVarint64(long val) {
+        while (true) {
+            if ((val & ~0x7FL) == 0) {
+                writeRawByte((byte)val);
+                return;
+            } else {
+                writeRawByte((byte)((val & 0x7F) | 0x80));
+                val >>>= 7;
+            }
+        }
+    }
+
+    /**
+     * Return how many bytes a signed 64 bit zig zag value will take when written to the stream.
+     */
+    public static int getRawZigZag64Size(long val) {
+        return getRawVarint64Size(zigZag64(val));
+    }
+
+    /**
+     * Write a 64 bit signed zig zag value to the stream.
+     */
+    public void writeRawZigZag64(long val) {
+        writeRawVarint64(zigZag64(val));
+    }
+
+    /**
+     * Write 4 little endian bytes to the stream.
+     */
+    public void writeRawFixed32(int val) {
+        writeRawByte((byte)(val));
+        writeRawByte((byte)(val >> 8));
+        writeRawByte((byte)(val >> 16));
+        writeRawByte((byte)(val >> 24));
+    }
+
+    /**
+     * Write 8 little endian bytes to the stream.
+     */
+    public void writeRawFixed64(long val) {
+        writeRawByte((byte)(val));
+        writeRawByte((byte)(val >> 8));
+        writeRawByte((byte)(val >> 16));
+        writeRawByte((byte)(val >> 24));
+        writeRawByte((byte)(val >> 32));
+        writeRawByte((byte)(val >> 40));
+        writeRawByte((byte)(val >> 48));
+        writeRawByte((byte)(val >> 56));
+    }
+
+    /**
+     * Write a buffer to the stream. Writes nothing if val is null or zero-length.
+     */
+    public void writeRawBuffer(byte[] val) {
+        if (val != null && val.length > 0) {
+            writeRawBuffer(val, 0, val.length);
+        }
+    }
+
+    /**
+     * Write part of an array of bytes.
+     */
+    public void writeRawBuffer(byte[] val, int offset, int length) {
+        if (val == null) {
+            return;
+        }
+        // Write up to the amount left in the first chunk to write.
+        int amt = length < (mChunkSize - mWriteIndex) ? length : (mChunkSize - mWriteIndex);
+        if (amt > 0) {
+            System.arraycopy(val, offset, mWriteBuffer, mWriteIndex, amt);
+            mWriteIndex += amt;
+            length -= amt;
+            offset += amt;
+        }
+        while (length > 0) {
+            // We know we're now at the beginning of a chunk
+            nextWriteBuffer();
+            amt = length < mChunkSize ? length : mChunkSize;
+            System.arraycopy(val, offset, mWriteBuffer, mWriteIndex, amt);
+            mWriteIndex += amt;
+            length -= amt;
+            offset += amt;
+        }
+    }
+
+    /**
+     * Copies data _size_ bytes of data within this buffer from _srcOffset_
+     * to the current write position. Like memmov but handles the chunked buffer.
+     */
+    public void writeFromThisBuffer(int srcOffset, int size) {
+        if (mReadLimit < 0) {
+            throw new IllegalStateException("writeFromThisBuffer before startEditing");
+        }
+        if (srcOffset < getWritePos()) {
+            throw new IllegalArgumentException("Can only move forward in the buffer --"
+                    + " srcOffset=" + srcOffset + " size=" + size + " " + getDebugString());
+        }
+        if (srcOffset + size > mReadableSize) {
+            throw new IllegalArgumentException("Trying to move more data than there is --"
+                    + " srcOffset=" + srcOffset + " size=" + size + " " + getDebugString());
+        }
+        if (size == 0) {
+            return;
+        }
+        if (srcOffset == ((mWriteBufIndex) * mChunkSize) + mWriteIndex /* write pos */) {
+            // Writing to the same location. Just advance the write pointer.  We already
+            // checked that size is in bounds, so we don't need to do any more range
+            // checking.
+            if (size <= mChunkSize - mWriteIndex) {
+                mWriteIndex += size;
+            } else {
+                size -= mChunkSize - mWriteIndex;
+                mWriteIndex = size % mChunkSize;
+                if (mWriteIndex == 0) {
+                    // Roll it back so nextWriteBuffer can do its job
+                    // on the next call (also makes mBuffers.get() not
+                    // fail if we're at the end).
+                    mWriteIndex = mChunkSize;
+                    mWriteBufIndex += (size / mChunkSize);
+                } else {
+                    mWriteBufIndex += 1 + (size / mChunkSize);
+                }
+                mWriteBuffer = mBuffers.get(mWriteBufIndex);
+            }
+        } else {
+            // Loop through the buffer, copying as much as we can each time.
+            // We already bounds checked so we don't need to do it again here,
+            // and nextWriteBuffer will never allocate.
+            int readBufIndex = srcOffset / mChunkSize;
+            byte[] readBuffer = mBuffers.get(readBufIndex);
+            int readIndex = srcOffset % mChunkSize;
+            while (size > 0) {
+                if (mWriteIndex >= mChunkSize) {
+                    nextWriteBuffer();
+                }
+                if (readIndex >= mChunkSize) {
+                    readBufIndex++;
+                    readBuffer = mBuffers.get(readBufIndex);
+                    readIndex = 0;
+                }
+                final int spaceInWriteBuffer = mChunkSize - mWriteIndex;
+                final int availableInReadBuffer = mChunkSize - readIndex;
+                final int amt = Math.min(size, Math.min(spaceInWriteBuffer, availableInReadBuffer));
+                System.arraycopy(readBuffer, readIndex, mWriteBuffer, mWriteIndex, amt);
+                mWriteIndex += amt;
+                readIndex += amt;
+                size -= amt;
+            }
+        }
+    }
+
+    //
+    // Writing at a particular location.
+    //
+
+    /**
+     * Returns the index into the virtual array of the write pointer.
+     */
+    public int getWritePos() {
+        return ((mWriteBufIndex) * mChunkSize) + mWriteIndex;
+    }
+
+    /**
+     * Resets the write pointer to a virtual location as returned by getWritePos.
+     */
+    public void rewindWriteTo(int writePos) {
+        if (writePos > getWritePos()) {
+            throw new RuntimeException("rewindWriteTo only can go backwards" + writePos);
+        }
+        mWriteBufIndex = writePos / mChunkSize;
+        mWriteIndex = writePos % mChunkSize;
+        if (mWriteIndex == 0 && mWriteBufIndex != 0) {
+            // Roll back so nextWriteBuffer can do its job on the next call
+            // but at the first write we're at 0.
+            mWriteIndex = mChunkSize;
+            mWriteBufIndex--;
+        }
+        mWriteBuffer = mBuffers.get(mWriteBufIndex);
+    }
+
+    /**
+     * Read a 32 bit value from the stream.
+     *
+     * Doesn't touch or affect mWritePos.
+     */
+    public int getRawFixed32At(int pos) {
+        return (0x00ff & (int)mBuffers.get(pos / mChunkSize)[pos % mChunkSize])
+                | ((0x0ff & (int)mBuffers.get((pos+1) / mChunkSize)[(pos+1) % mChunkSize]) << 8)
+                | ((0x0ff & (int)mBuffers.get((pos+2) / mChunkSize)[(pos+2) % mChunkSize]) << 16)
+                | ((0x0ff & (int)mBuffers.get((pos+3) / mChunkSize)[(pos+3) % mChunkSize]) << 24);
+    }
+
+    /**
+     * Overwrite a 32 bit value in the stream.
+     *
+     * Doesn't touch or affect mWritePos.
+     */
+    public void editRawFixed32(int pos, int val) {
+        mBuffers.get(pos / mChunkSize)[pos % mChunkSize] = (byte)(val);
+        mBuffers.get((pos+1) / mChunkSize)[(pos+1) % mChunkSize] = (byte)(val >> 8);
+        mBuffers.get((pos+2) / mChunkSize)[(pos+2) % mChunkSize] = (byte)(val >> 16);
+        mBuffers.get((pos+3) / mChunkSize)[(pos+3) % mChunkSize] = (byte)(val >> 24);
+    }
+
+    //
+    // Zigging and zagging
+    //
+
+    /**
+     * Zig-zag encode a 32 bit value.
+     */
+    private static int zigZag32(int val) {
+        return (val << 1) ^ (val >> 31);
+    }
+
+    /**
+     * Zig-zag encode a 64 bit value.
+     */
+    private static long zigZag64(long val) {
+        return (val << 1) ^ (val >> 63);
+    }
+
+    //
+    // Debugging / testing
+    //
+    // VisibleForTesting
+
+    /**
+     * Get a copy of the first _size_ bytes of data. This is not range
+     * checked, and if the bounds are outside what has been written you will
+     * get garbage and if it is outside the buffers that have been allocated,
+     * you will get an exception.
+     */
+    public byte[] getBytes(int size) {
+        final byte[] result = new byte[size];
+
+        final int bufCount = size / mChunkSize;
+        int bufIndex;
+        int writeIndex = 0;
+
+        for (bufIndex=0; bufIndex<bufCount; bufIndex++) {
+            System.arraycopy(mBuffers.get(bufIndex), 0, result, writeIndex, mChunkSize);
+            writeIndex += mChunkSize;
+        }
+
+        final int lastSize = size - (bufCount * mChunkSize);
+        if (lastSize > 0) {
+            System.arraycopy(mBuffers.get(bufIndex), 0, result, writeIndex, lastSize);
+        }
+
+        return result;
+    }
+
+    /**
+     * Get the number of chunks allocated.
+     */
+    // VisibleForTesting
+    public int getChunkCount() {
+        return mBuffers.size();
+    }
+
+    /**
+     * Get the write position inside the current write chunk.
+     */
+     // VisibleForTesting
+    public int getWriteIndex() {
+        return mWriteIndex;
+    }
+
+    /**
+     * Get the index of the current write chunk in the list of chunks.
+     */
+    // VisibleForTesting
+    public int getWriteBufIndex() {
+        return mWriteBufIndex;
+    }
+
+    /**
+     * Return debugging information about this EncodedBuffer object.
+     */
+    public String getDebugString() {
+        return "EncodedBuffer( mChunkSize=" + mChunkSize + " mBuffers.size=" + mBuffers.size()
+                + " mBufferCount=" + mBufferCount + " mWriteIndex=" + mWriteIndex
+                + " mWriteBufIndex=" + mWriteBufIndex + " mReadBufIndex=" + mReadBufIndex
+                + " mReadIndex=" + mReadIndex + " mReadableSize=" + mReadableSize
+                + " mReadLimit=" + mReadLimit + " )";
+    }
+
+    /**
+     * Print the internal buffer chunks.
+     */
+    public void dumpBuffers(String tag) {
+        final int N = mBuffers.size();
+        int start = 0;
+        for (int i=0; i<N; i++) {
+            start += dumpByteString(tag, "{" + i + "} ", start, mBuffers.get(i));
+        }
+    }
+
+    /**
+     * Print the internal buffer chunks.
+     */
+    public static void dumpByteString(String tag, String prefix, byte[] buf) {
+        dumpByteString(tag, prefix, 0, buf);
+    }
+
+    /**
+     * Print the internal buffer chunks.
+     */
+    private static int dumpByteString(String tag, String prefix, int start, byte[] buf) {
+        StringBuilder sb = new StringBuilder();
+        final int length = buf.length;
+        final int lineLen = 16;
+        int i;
+        for (i=0; i<length; i++) {
+            if (i % lineLen == 0) {
+                if (i != 0) {
+                    Log.d(tag, sb.toString());
+                    sb = new StringBuilder();
+                }
+                sb.append(prefix);
+                sb.append('[');
+                sb.append(start + i);
+                sb.append(']');
+                sb.append(' ');
+            } else {
+                sb.append(' ');
+            }
+            byte b = buf[i];
+            byte c = (byte)((b >> 4) & 0x0f);
+            if (c < 10) {
+                sb.append((char)('0' + c));
+            } else {
+                sb.append((char)('a' - 10 + c));
+            }
+            byte d = (byte)(b & 0x0f);
+            if (d < 10) {
+                sb.append((char)('0' + d));
+            } else {
+                sb.append((char)('a' - 10 + d));
+            }
+        }
+        Log.d(tag, sb.toString());
+        return length;
+    }
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/ProtoInputStream.java b/framework/java/android/util/configinfrastructure/proto/ProtoInputStream.java
new file mode 100644
index 0000000..2e2e98d
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/ProtoInputStream.java
@@ -0,0 +1,992 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.util.configinfrastructure.proto;
+
+import android.util.configinfrastructure.LongArray;
+
+import java.io.IOException;
+import java.io.InputStream;
+import java.nio.charset.StandardCharsets;
+import java.util.Arrays;
+import java.util.Objects;
+
+/**
+ * Class to read to a protobuf stream.
+ *
+ * Each read method takes an ID code from the protoc generated classes
+ * and return a value of the field. To read a nested object, call #start
+ * and then #end when you are done.
+ *
+ * The ID codes have type information embedded into them, so if you call
+ * the incorrect function you will get an IllegalArgumentException.
+ *
+ * nextField will return the field number of the next field, which can be
+ * matched to the protoc generated ID code and used to determine how to
+ * read the next field.
+ *
+ * It is STRONGLY RECOMMENDED to read from the ProtoInputStream with a switch
+ * statement wrapped in a while loop. Additionally, it is worth logging or
+ * storing unexpected fields or ones that do not match the expected wire type
+ *
+ * ex:
+ * void parseFromProto(ProtoInputStream stream) {
+ *     while(stream.nextField() != ProtoInputStream.NO_MORE_FIELDS) {
+ *         try {
+ *             switch (stream.getFieldNumber()) {
+ *                 case (int) DummyProto.NAME:
+ *                     mName = stream.readString(DummyProto.NAME);
+ *                     break;
+ *                 case (int) DummyProto.VALUE:
+ *                     mValue = stream.readInt(DummyProto.VALUE);
+ *                     break;
+ *                 default:
+ *                     LOG(TAG, "Unhandled field in proto!\n"
+ *                              + ProtoUtils.currentFieldToString(stream));
+ *             }
+ *         } catch (WireTypeMismatchException wtme) {
+ *             LOG(TAG, "Wire Type mismatch in proto!\n" + ProtoUtils.currentFieldToString(stream));
+ *         }
+ *     }
+ * }
+ *
+ * This is copied from frameworks/base/core/java/android/util/proto/ProtoInputStream.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * ProtoInputStream should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public final class ProtoInputStream extends ProtoStream {
+
+    public static final int NO_MORE_FIELDS = -1;
+
+    /**
+     * Our stream.  If there is one.
+     */
+    private InputStream mStream;
+
+    /**
+     * The field number of the current field. Will be equal to NO_MORE_FIELDS if end of message is
+     * reached
+     */
+    private int mFieldNumber;
+
+    /**
+     * The wire type of the current field
+     */
+    private int mWireType;
+
+    private static final byte STATE_STARTED_FIELD_READ = 1 << 0;
+    private static final byte STATE_READING_PACKED = 1 << 1;
+    private static final byte STATE_FIELD_MISS = 2 << 1;
+
+    /**
+     * Tracks some boolean states for the proto input stream
+     * bit 0: Started Field Read, true - tag has been read, ready to read field data.
+     * false - field data has been read, reading to start next field.
+     * bit 1: Reading Packed Field, true - currently reading values from a packed field
+     * false - not reading from packed field.
+     */
+    private byte mState = 0;
+
+    /**
+     * Keeps track of the currently read nested Objects, for end object checking and debug
+     */
+    private LongArray mExpectedObjectTokenStack = null;
+
+    /**
+     * Current nesting depth of start calls.
+     */
+    private int mDepth = -1;
+
+    /**
+     * Buffer for the to be read data. If mStream is not null, it will be constantly refilled from
+     * the stream.
+     */
+    private byte[] mBuffer;
+
+    private static final int DEFAULT_BUFFER_SIZE = 8192;
+
+    /**
+     * Size of the buffer if reading from a stream.
+     */
+    private final int mBufferSize;
+
+    /**
+     * The number of bytes that have been skipped or dropped from the buffer.
+     */
+    private int mDiscardedBytes = 0;
+
+    /**
+     * Current offset in the buffer
+     * mOffset + mDiscardedBytes = current offset in proto binary
+     */
+    private int mOffset = 0;
+
+    /**
+     * Note the offset of the last byte in the buffer. Usually will equal the size of the buffer.
+     * mEnd + mDiscardedBytes = the last known byte offset + 1
+     */
+    private int mEnd = 0;
+
+    /**
+     * Packed repeated fields are not read in one go. mPackedEnd keeps track of where the packed
+     * field ends in the proto binary if current field is packed.
+     */
+    private int mPackedEnd = 0;
+
+    /**
+     * Construct a ProtoInputStream on top of an InputStream to read a proto. Also specify the
+     * number of bytes the ProtoInputStream will buffer from the input stream
+     *
+     * @param stream from which the proto is read
+     */
+    public ProtoInputStream(InputStream stream, int bufferSize) {
+        mStream = stream;
+        if (bufferSize > 0) {
+            mBufferSize = bufferSize;
+        } else {
+            mBufferSize = DEFAULT_BUFFER_SIZE;
+        }
+        mBuffer = new byte[mBufferSize];
+    }
+
+    /**
+     * Construct a ProtoInputStream on top of an InputStream to read a proto
+     *
+     * @param stream from which the proto is read
+     */
+    public ProtoInputStream(InputStream stream) {
+        this(stream, DEFAULT_BUFFER_SIZE);
+    }
+
+    /**
+     * Construct a ProtoInputStream to read a proto directly from a byte array
+     *
+     * @param buffer - the byte array to be parsed
+     */
+    public ProtoInputStream(byte[] buffer) {
+        mBufferSize = buffer.length;
+        mEnd = buffer.length;
+        mBuffer = buffer;
+        mStream = null;
+    }
+
+    /**
+     * Get the field number of the current field.
+     */
+    public int getFieldNumber() {
+        return mFieldNumber;
+    }
+
+    /**
+     * Get the wire type of the current field.
+     *
+     * @return an int that matches one of the ProtoStream WIRE_TYPE_ constants
+     */
+    public int getWireType() {
+        if ((mState & STATE_READING_PACKED) == STATE_READING_PACKED) {
+            // mWireType got overwritten when STATE_READING_PACKED was set. Send length delimited
+            // constant instead
+            return WIRE_TYPE_LENGTH_DELIMITED;
+        }
+        return mWireType;
+    }
+
+    /**
+     * Get the current offset in the proto binary.
+     */
+    public int getOffset() {
+        return mOffset + mDiscardedBytes;
+    }
+
+    /**
+     * Reads the tag of the next field from the stream. If previous field value was not read, its
+     * data will be skipped over.
+     *
+     * @return the field number of the next field
+     * @throws IOException if an I/O error occurs
+     */
+    public int nextField() throws IOException {
+
+        if ((mState & STATE_FIELD_MISS) == STATE_FIELD_MISS) {
+            // Data from the last nextField was not used, reuse the info
+            mState &= ~STATE_FIELD_MISS;
+            return mFieldNumber;
+        }
+        if ((mState & STATE_STARTED_FIELD_READ) == STATE_STARTED_FIELD_READ) {
+            // Field data was not read, skip to the next field
+            skip();
+            mState &= ~STATE_STARTED_FIELD_READ;
+        }
+        if ((mState & STATE_READING_PACKED) == STATE_READING_PACKED) {
+            if (getOffset() < mPackedEnd) {
+                // In the middle of a packed field, return the same tag until last packed value
+                // has been read
+                mState |= STATE_STARTED_FIELD_READ;
+                return mFieldNumber;
+            } else if (getOffset() == mPackedEnd) {
+                // Reached the end of the packed field
+                mState &= ~STATE_READING_PACKED;
+            } else {
+                throw new ProtoParseException(
+                        "Unexpectedly reached end of packed field at offset 0x"
+                                + Integer.toHexString(mPackedEnd)
+                                + dumpDebugData());
+            }
+        }
+
+        if ((mDepth >= 0) && (getOffset() == getOffsetFromToken(
+                mExpectedObjectTokenStack.get(mDepth)))) {
+            // reached end of a embedded message
+            mFieldNumber = NO_MORE_FIELDS;
+        } else {
+            readTag();
+        }
+        return mFieldNumber;
+    }
+
+    /**
+     * Reads the tag of the next field from the stream. If previous field value was not read, its
+     * data will be skipped over. If {@code fieldId} matches the next field ID, the field data will
+     * be ready to read. If it does not match, {@link #nextField()} or {@link #nextField(long)} will
+     * need to be called again before the field data can be read.
+     *
+     * @return true if fieldId matches the next field, false if not
+     */
+    public boolean nextField(long fieldId) throws IOException {
+        if (nextField() == (int) fieldId) {
+            return true;
+        }
+        // Note to reuse the info from the nextField call in the next call.
+        mState |= STATE_FIELD_MISS;
+        return false;
+    }
+
+    /**
+     * Read a single double.
+     * Will throw if the current wire type is not fixed64
+     *
+     * @param fieldId - must match the current field number and field type
+     */
+    public double readDouble(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        checkPacked(fieldId);
+
+        double value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_DOUBLE >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_FIXED64);
+                value = Double.longBitsToDouble(readFixed64());
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id (" + getFieldIdString(fieldId)
+                                + ") cannot be read as a double"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a single float.
+     * Will throw if the current wire type is not fixed32
+     *
+     * @param fieldId - must match the current field number and field type
+     */
+    public float readFloat(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        checkPacked(fieldId);
+
+        float value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_FLOAT >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_FIXED32);
+                value = Float.intBitsToFloat(readFixed32());
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id (" + getFieldIdString(fieldId) + ") is not a float"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a single 32bit or varint proto type field as an int.
+     * Will throw if the current wire type is not varint or fixed32
+     *
+     * @param fieldId - must match the current field number and field type
+     */
+    public int readInt(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        checkPacked(fieldId);
+
+        int value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_FIXED32 >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_SFIXED32 >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_FIXED32);
+                value = readFixed32();
+                break;
+            case (int) (FIELD_TYPE_SINT32 >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_VARINT);
+                value = decodeZigZag32((int) readVarint());
+                break;
+            case (int) (FIELD_TYPE_INT32 >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_UINT32 >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_ENUM >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_VARINT);
+                value = (int) readVarint();
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id (" + getFieldIdString(fieldId) + ") is not an int"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a single 64bit or varint proto type field as an long.
+     *
+     * @param fieldId - must match the current field number
+     */
+    public long readLong(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        checkPacked(fieldId);
+
+        long value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_FIXED64 >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_SFIXED64 >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_FIXED64);
+                value = readFixed64();
+                break;
+            case (int) (FIELD_TYPE_SINT64 >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_VARINT);
+                value = decodeZigZag64(readVarint());
+                break;
+            case (int) (FIELD_TYPE_INT64 >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_UINT64 >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_VARINT);
+                value = readVarint();
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id (" + getFieldIdString(fieldId) + ") is not an long"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a single 32bit or varint proto type field as an boolean.
+     *
+     * @param fieldId - must match the current field number
+     */
+    public boolean readBoolean(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        checkPacked(fieldId);
+
+        boolean value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_BOOL >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_VARINT);
+                value = readVarint() != 0;
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id (" + getFieldIdString(fieldId) + ") is not an boolean"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a string field
+     *
+     * @param fieldId - must match the current field number
+     */
+    public String readString(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+
+        String value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK) >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_STRING >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_LENGTH_DELIMITED);
+                int len = (int) readVarint();
+                value = readRawString(len);
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field id(" + getFieldIdString(fieldId)
+                                + ") is not an string"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Read a bytes field
+     *
+     * @param fieldId - must match the current field number
+     */
+    public byte[] readBytes(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+
+        byte[] value;
+        switch ((int) ((fieldId & FIELD_TYPE_MASK) >>> FIELD_TYPE_SHIFT)) {
+            case (int) (FIELD_TYPE_MESSAGE >>> FIELD_TYPE_SHIFT):
+            case (int) (FIELD_TYPE_BYTES >>> FIELD_TYPE_SHIFT):
+                assertWireType(WIRE_TYPE_LENGTH_DELIMITED);
+                int len = (int) readVarint();
+                value = readRawBytes(len);
+                break;
+            default:
+                throw new IllegalArgumentException(
+                        "Requested field type (" + getFieldIdString(fieldId)
+                                + ") cannot be read as raw bytes"
+                                + dumpDebugData());
+        }
+        // Successfully read the field
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return value;
+    }
+
+    /**
+     * Start the read of an embedded Object
+     *
+     * @param fieldId - must match the current field number
+     * @return a token. The token must be handed back when finished reading embedded Object
+     */
+    public long start(long fieldId) throws IOException {
+        assertFreshData();
+        assertFieldNumber(fieldId);
+        assertWireType(WIRE_TYPE_LENGTH_DELIMITED);
+
+        int messageSize = (int) readVarint();
+
+        if (mExpectedObjectTokenStack == null) {
+            mExpectedObjectTokenStack = new LongArray();
+        }
+        if (++mDepth == mExpectedObjectTokenStack.size()) {
+            // Create a token to keep track of nested Object and extend the object stack
+            mExpectedObjectTokenStack.add(makeToken(0,
+                    (fieldId & FIELD_COUNT_REPEATED) == FIELD_COUNT_REPEATED, mDepth,
+                    (int) fieldId, getOffset() + messageSize));
+
+        } else {
+            // Create a token to keep track of nested Object
+            mExpectedObjectTokenStack.set(mDepth, makeToken(0,
+                    (fieldId & FIELD_COUNT_REPEATED) == FIELD_COUNT_REPEATED, mDepth,
+                    (int) fieldId, getOffset() + messageSize));
+        }
+
+        // Validation check
+        if (mDepth > 0
+                && getOffsetFromToken(mExpectedObjectTokenStack.get(mDepth))
+                > getOffsetFromToken(mExpectedObjectTokenStack.get(mDepth - 1))) {
+            throw new ProtoParseException("Embedded Object ("
+                    + token2String(mExpectedObjectTokenStack.get(mDepth))
+                    + ") ends after of parent Objects's ("
+                    + token2String(mExpectedObjectTokenStack.get(mDepth - 1))
+                    + ") end"
+                    + dumpDebugData());
+        }
+        mState &= ~STATE_STARTED_FIELD_READ;
+        return mExpectedObjectTokenStack.get(mDepth);
+    }
+
+    /**
+     * Note the end of a nested object. Must be called to continue streaming the rest of the proto.
+     * end can be called mid object parse. The offset will be moved to the next field outside the
+     * object.
+     *
+     * @param token - token
+     */
+    public void end(long token) {
+        // Make sure user is keeping track of their embedded messages
+        if (mExpectedObjectTokenStack.get(mDepth) != token) {
+            throw new ProtoParseException(
+                    "end token " + token + " does not match current message token "
+                            + mExpectedObjectTokenStack.get(mDepth)
+                            + dumpDebugData());
+        }
+        if (getOffsetFromToken(mExpectedObjectTokenStack.get(mDepth)) > getOffset()) {
+            // Did not read all of the message, skip to the end
+            incOffset(getOffsetFromToken(mExpectedObjectTokenStack.get(mDepth)) - getOffset());
+        }
+        mDepth--;
+        mState &= ~STATE_STARTED_FIELD_READ;
+    }
+
+    /**
+     * Read the tag at the start of the next field and collect field number and wire type.
+     * Will set mFieldNumber to NO_MORE_FIELDS if end of buffer/stream reached.
+     */
+    private void readTag() throws IOException {
+        fillBuffer();
+        if (mOffset >= mEnd) {
+            // reached end of the stream
+            mFieldNumber = NO_MORE_FIELDS;
+            return;
+        }
+        int tag = (int) readVarint();
+        mFieldNumber = tag >>> FIELD_ID_SHIFT;
+        mWireType = tag & WIRE_TYPE_MASK;
+        mState |= STATE_STARTED_FIELD_READ;
+    }
+
+    /**
+     * Decode a 32 bit ZigZag encoded signed int.
+     *
+     * @param n - int to decode
+     * @return the decoded signed int
+     */
+    public int decodeZigZag32(final int n) {
+        return (n >>> 1) ^ -(n & 1);
+    }
+
+    /**
+     * Decode a 64 bit ZigZag encoded signed long.
+     *
+     * @param n - long to decode
+     * @return the decoded signed long
+     */
+    public long decodeZigZag64(final long n) {
+        return (n >>> 1) ^ -(n & 1);
+    }
+
+    /**
+     * Read a varint from the buffer
+     *
+     * @return the varint as a long
+     */
+    private long readVarint() throws IOException {
+        long value = 0;
+        int shift = 0;
+        while (true) {
+            fillBuffer();
+            // Limit how much bookkeeping is done by checking how far away the end of the buffer is
+            // and directly accessing buffer up until the end.
+            final int fragment = mEnd - mOffset;
+            if (fragment < 0) {
+                throw new ProtoParseException(
+                        "Incomplete varint at offset 0x"
+                                + Integer.toHexString(getOffset())
+                                + dumpDebugData());
+            }
+            for (int i = 0; i < fragment; i++) {
+                byte b = mBuffer[(mOffset + i)];
+                value |= (b & 0x7FL) << shift;
+                if ((b & 0x80) == 0) {
+                    incOffset(i + 1);
+                    return value;
+                }
+                shift += 7;
+                if (shift > 63) {
+                    throw new ProtoParseException(
+                            "Varint is too large at offset 0x"
+                                    + Integer.toHexString(getOffset() + i)
+                                    + dumpDebugData());
+                }
+            }
+            // Hit the end of the buffer, do some incrementing and checking, then continue
+            incOffset(fragment);
+        }
+    }
+
+    /**
+     * Read a fixed 32 bit int from the buffer
+     *
+     * @return the fixed32 as a int
+     */
+    private int readFixed32() throws IOException {
+        // check for fast path, which is likely with a reasonable buffer size
+        if (mOffset + 4 <= mEnd) {
+            // don't bother filling buffer since we know the end is plenty far away
+            incOffset(4);
+            return (mBuffer[mOffset - 4] & 0xFF)
+                    | ((mBuffer[mOffset - 3] & 0xFF) << 8)
+                    | ((mBuffer[mOffset - 2] & 0xFF) << 16)
+                    | ((mBuffer[mOffset - 1] & 0xFF) << 24);
+        }
+
+        // the Fixed32 crosses the edge of a chunk, read the Fixed32 in multiple fragments.
+        // There will be two fragment reads except when the chunk size is 2 or less.
+        int value = 0;
+        int shift = 0;
+        int bytesLeft = 4;
+        while (bytesLeft > 0) {
+            fillBuffer();
+            // Find the number of bytes available until the end of the chunk or Fixed32
+            int fragment = (mEnd - mOffset) < bytesLeft ? (mEnd - mOffset) : bytesLeft;
+            if (fragment < 0) {
+                throw new ProtoParseException(
+                        "Incomplete fixed32 at offset 0x"
+                                + Integer.toHexString(getOffset())
+                                + dumpDebugData());
+            }
+            incOffset(fragment);
+            bytesLeft -= fragment;
+            while (fragment > 0) {
+                value |= ((mBuffer[mOffset - fragment] & 0xFF) << shift);
+                fragment--;
+                shift += 8;
+            }
+        }
+        return value;
+    }
+
+    /**
+     * Read a fixed 64 bit long from the buffer
+     *
+     * @return the fixed64 as a long
+     */
+    private long readFixed64() throws IOException {
+        // check for fast path, which is likely with a reasonable buffer size
+        if (mOffset + 8 <= mEnd) {
+            // don't bother filling buffer since we know the end is plenty far away
+            incOffset(8);
+            return (mBuffer[mOffset - 8] & 0xFFL)
+                    | ((mBuffer[mOffset - 7] & 0xFFL) << 8)
+                    | ((mBuffer[mOffset - 6] & 0xFFL) << 16)
+                    | ((mBuffer[mOffset - 5] & 0xFFL) << 24)
+                    | ((mBuffer[mOffset - 4] & 0xFFL) << 32)
+                    | ((mBuffer[mOffset - 3] & 0xFFL) << 40)
+                    | ((mBuffer[mOffset - 2] & 0xFFL) << 48)
+                    | ((mBuffer[mOffset - 1] & 0xFFL) << 56);
+        }
+
+        // the Fixed64 crosses the edge of a chunk, read the Fixed64 in multiple fragments.
+        // There will be two fragment reads except when the chunk size is 6 or less.
+        long value = 0;
+        int shift = 0;
+        int bytesLeft = 8;
+        while (bytesLeft > 0) {
+            fillBuffer();
+            // Find the number of bytes available until the end of the chunk or Fixed64
+            int fragment = (mEnd - mOffset) < bytesLeft ? (mEnd - mOffset) : bytesLeft;
+            if (fragment < 0) {
+                throw new ProtoParseException(
+                        "Incomplete fixed64 at offset 0x"
+                                + Integer.toHexString(getOffset())
+                                + dumpDebugData());
+            }
+            incOffset(fragment);
+            bytesLeft -= fragment;
+            while (fragment > 0) {
+                value |= ((mBuffer[(mOffset - fragment)] & 0xFFL) << shift);
+                fragment--;
+                shift += 8;
+            }
+        }
+        return value;
+    }
+
+    /**
+     * Read raw bytes from the buffer
+     *
+     * @param n - number of bytes to read
+     * @return a byte array with raw bytes
+     */
+    private byte[] readRawBytes(int n) throws IOException {
+        byte[] buffer = new byte[n];
+        int pos = 0;
+        while (mOffset + n - pos > mEnd) {
+            int fragment = mEnd - mOffset;
+            if (fragment > 0) {
+                System.arraycopy(mBuffer, mOffset, buffer, pos, fragment);
+                incOffset(fragment);
+                pos += fragment;
+            }
+            fillBuffer();
+            if (mOffset >= mEnd) {
+                throw new ProtoParseException(
+                        "Unexpectedly reached end of the InputStream at offset 0x"
+                                + Integer.toHexString(mEnd)
+                                + dumpDebugData());
+            }
+        }
+        System.arraycopy(mBuffer, mOffset, buffer, pos, n - pos);
+        incOffset(n - pos);
+        return buffer;
+    }
+
+    /**
+     * Read raw string from the buffer
+     *
+     * @param n - number of bytes to read
+     * @return a string
+     */
+    private String readRawString(int n) throws IOException {
+        fillBuffer();
+        if (mOffset + n <= mEnd) {
+            // fast path read. String is well within the current buffer
+            String value = new String(mBuffer, mOffset, n, StandardCharsets.UTF_8);
+            incOffset(n);
+            return value;
+        } else if (n <= mBufferSize) {
+            // String extends past buffer, but can be encapsulated in a buffer. Copy the first chunk
+            // of the string to the start of the buffer and then fill the rest of the buffer from
+            // the stream.
+            final int stringHead = mEnd - mOffset;
+            System.arraycopy(mBuffer, mOffset, mBuffer, 0, stringHead);
+            mEnd = stringHead + mStream.read(mBuffer, stringHead, n - stringHead);
+
+            mDiscardedBytes += mOffset;
+            mOffset = 0;
+
+            String value = new String(mBuffer, mOffset, n, StandardCharsets.UTF_8);
+            incOffset(n);
+            return value;
+        }
+        // Otherwise, the string is too large to use the buffer. Create the string from a
+        // separate byte array.
+        return new String(readRawBytes(n), 0, n, StandardCharsets.UTF_8);
+    }
+
+    /**
+     * Fill the buffer with a chunk from the stream if need be.
+     * Will skip chunks until mOffset is reached
+     */
+    private void fillBuffer() throws IOException {
+        if (mOffset >= mEnd && mStream != null) {
+            mOffset -= mEnd;
+            mDiscardedBytes += mEnd;
+            if (mOffset >= mBufferSize) {
+                int skipped = (int) mStream.skip((mOffset / mBufferSize) * mBufferSize);
+                mDiscardedBytes += skipped;
+                mOffset -= skipped;
+            }
+            mEnd = mStream.read(mBuffer);
+        }
+    }
+
+    /**
+     * Skips the rest of current field and moves to the start of the next field. This should only be
+     * called while state is STATE_STARTED_FIELD_READ
+     */
+    public void skip() throws IOException {
+        if ((mState & STATE_READING_PACKED) == STATE_READING_PACKED) {
+            incOffset(mPackedEnd - getOffset());
+        } else {
+            switch (mWireType) {
+                case WIRE_TYPE_VARINT:
+                    byte b;
+                    do {
+                        fillBuffer();
+                        b = mBuffer[mOffset];
+                        incOffset(1);
+                    } while ((b & 0x80) != 0);
+                    break;
+                case WIRE_TYPE_FIXED64:
+                    incOffset(8);
+                    break;
+                case WIRE_TYPE_LENGTH_DELIMITED:
+                    fillBuffer();
+                    int length = (int) readVarint();
+                    incOffset(length);
+                    break;
+                /*
+            case WIRE_TYPE_START_GROUP:
+                // Not implemented
+                break;
+            case WIRE_TYPE_END_GROUP:
+                // Not implemented
+                break;
+                */
+                case WIRE_TYPE_FIXED32:
+                    incOffset(4);
+                    break;
+                default:
+                    throw new ProtoParseException(
+                            "Unexpected wire type: " + mWireType + " at offset 0x"
+                                    + Integer.toHexString(mOffset)
+                                    + dumpDebugData());
+            }
+        }
+        mState &= ~STATE_STARTED_FIELD_READ;
+    }
+
+    /**
+     * Increment the offset and handle all the relevant bookkeeping
+     * Refilling the buffer when its end is reached will be handled elsewhere (ideally just before
+     * a read, to avoid unnecessary reads from stream)
+     *
+     * @param n - number of bytes to increment
+     */
+    private void incOffset(int n) {
+        mOffset += n;
+
+        if (mDepth >= 0 && getOffset() > getOffsetFromToken(
+                mExpectedObjectTokenStack.get(mDepth))) {
+            throw new ProtoParseException("Unexpectedly reached end of embedded object.  "
+                    + token2String(mExpectedObjectTokenStack.get(mDepth))
+                    + dumpDebugData());
+        }
+    }
+
+    /**
+     * Check the current wire type to determine if current numeric field is packed. If it is packed,
+     * set up to deal with the field
+     * This should only be called for primitive numeric field types.
+     *
+     * @param fieldId - used to determine what the packed wire type is.
+     */
+    private void checkPacked(long fieldId) throws IOException {
+        if (mWireType == WIRE_TYPE_LENGTH_DELIMITED) {
+            // Primitive Field is length delimited, must be a packed field.
+            final int length = (int) readVarint();
+            mPackedEnd = getOffset() + length;
+            mState |= STATE_READING_PACKED;
+
+            // Fake the wire type, based on the field type
+            switch ((int) ((fieldId & FIELD_TYPE_MASK)
+                    >>> FIELD_TYPE_SHIFT)) {
+                case (int) (FIELD_TYPE_FLOAT >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_FIXED32 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_SFIXED32 >>> FIELD_TYPE_SHIFT):
+                    if (length % 4 != 0) {
+                        throw new IllegalArgumentException(
+                                "Requested field id (" + getFieldIdString(fieldId)
+                                        + ") packed length " + length
+                                        + " is not aligned for fixed32"
+                                        + dumpDebugData());
+                    }
+                    mWireType = WIRE_TYPE_FIXED32;
+                    break;
+                case (int) (FIELD_TYPE_DOUBLE >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_FIXED64 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_SFIXED64 >>> FIELD_TYPE_SHIFT):
+                    if (length % 8 != 0) {
+                        throw new IllegalArgumentException(
+                                "Requested field id (" + getFieldIdString(fieldId)
+                                        + ") packed length " + length
+                                        + " is not aligned for fixed64"
+                                        + dumpDebugData());
+                    }
+                    mWireType = WIRE_TYPE_FIXED64;
+                    break;
+                case (int) (FIELD_TYPE_SINT32 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_INT32 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_UINT32 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_SINT64 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_INT64 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_UINT64 >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_ENUM >>> FIELD_TYPE_SHIFT):
+                case (int) (FIELD_TYPE_BOOL >>> FIELD_TYPE_SHIFT):
+                    mWireType = WIRE_TYPE_VARINT;
+                    break;
+                default:
+                    throw new IllegalArgumentException(
+                            "Requested field id (" + getFieldIdString(fieldId)
+                                    + ") is not a packable field"
+                                    + dumpDebugData());
+            }
+        }
+    }
+
+
+    /**
+     * Check a field id constant against current field number
+     *
+     * @param fieldId - throws if fieldId does not match mFieldNumber
+     */
+    private void assertFieldNumber(long fieldId) {
+        if ((int) fieldId != mFieldNumber) {
+            throw new IllegalArgumentException("Requested field id (" + getFieldIdString(fieldId)
+                    + ") does not match current field number (0x" + Integer.toHexString(
+                    mFieldNumber)
+                    + ") at offset 0x" + Integer.toHexString(getOffset())
+                    + dumpDebugData());
+        }
+    }
+
+
+    /**
+     * Check a wire type against current wire type.
+     *
+     * @param wireType - throws if wireType does not match mWireType.
+     */
+    private void assertWireType(int wireType) {
+        if (wireType != mWireType) {
+            throw new WireTypeMismatchException(
+                    "Current wire type " + getWireTypeString(mWireType)
+                            + " does not match expected wire type " + getWireTypeString(wireType)
+                            + " at offset 0x" + Integer.toHexString(getOffset())
+                            + dumpDebugData());
+        }
+    }
+
+    /**
+     * Check if there is data ready to be read.
+     */
+    private void assertFreshData() {
+        if ((mState & STATE_STARTED_FIELD_READ) != STATE_STARTED_FIELD_READ) {
+            throw new ProtoParseException(
+                    "Attempting to read already read field at offset 0x" + Integer.toHexString(
+                            getOffset()) + dumpDebugData());
+        }
+    }
+
+    /**
+     * Dump debugging data about the buffer.
+     */
+    public String dumpDebugData() {
+        StringBuilder sb = new StringBuilder();
+
+        sb.append("\nmFieldNumber : 0x").append(Integer.toHexString(mFieldNumber));
+        sb.append("\nmWireType : 0x").append(Integer.toHexString(mWireType));
+        sb.append("\nmState : 0x").append(Integer.toHexString(mState));
+        sb.append("\nmDiscardedBytes : 0x").append(Integer.toHexString(mDiscardedBytes));
+        sb.append("\nmOffset : 0x").append(Integer.toHexString(mOffset));
+        sb.append("\nmExpectedObjectTokenStack : ")
+                .append(Objects.toString(mExpectedObjectTokenStack));
+        sb.append("\nmDepth : 0x").append(Integer.toHexString(mDepth));
+        sb.append("\nmBuffer : ").append(Arrays.toString(mBuffer));
+        sb.append("\nmBufferSize : 0x").append(Integer.toHexString(mBufferSize));
+        sb.append("\nmEnd : 0x").append(Integer.toHexString(mEnd));
+
+        return sb.toString();
+    }
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/ProtoParseException.java b/framework/java/android/util/configinfrastructure/proto/ProtoParseException.java
new file mode 100644
index 0000000..d9075de
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/ProtoParseException.java
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2012 The Android Open Source Project
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
+package android.util.configinfrastructure.proto;
+
+/**
+ * Thrown when there is an error parsing protobuf data.
+ *
+ *
+ * This is copied from frameworks/base/core/java/android/util/proto/ProtoParseException.java.
+ * Any major bugfixes in the original ProtoParseException should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class ProtoParseException extends RuntimeException {
+
+    /**
+     * Construct a ProtoParseException.
+     *
+     * @param msg The message.
+     */
+    public ProtoParseException(String msg) {
+        super(msg);
+    }
+}
+
diff --git a/framework/java/android/util/configinfrastructure/proto/ProtoStream.java b/framework/java/android/util/configinfrastructure/proto/ProtoStream.java
new file mode 100644
index 0000000..d1cd55f
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/ProtoStream.java
@@ -0,0 +1,641 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.util.configinfrastructure.proto;
+
+import android.annotation.IntDef;
+import android.annotation.LongDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+/**
+ * Base utility class for protobuf streams.
+ *
+ * Contains a set of constants and methods used in generated code for
+ * {@link ProtoOutputStream}.
+ *
+ * This is copied from frameworks/base/core/java/android/util/proto/ProtoStream.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * ProtoStream should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class ProtoStream {
+
+    /**
+     * A protobuf wire type.  All application-level types are represented using
+     * varint, fixed64, length-delimited and fixed32 wire types. The start-group
+     * and end-group types are unused in modern protobuf versions (proto2 and proto3),
+     * but are included here for completeness.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef({
+        WIRE_TYPE_VARINT,
+        WIRE_TYPE_FIXED64,
+        WIRE_TYPE_LENGTH_DELIMITED,
+        WIRE_TYPE_START_GROUP,
+        WIRE_TYPE_END_GROUP,
+        WIRE_TYPE_FIXED32
+    })
+    public @interface WireType {}
+
+    /**
+     * Application-level protobuf field types, as would be used in a .proto file.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    @Retention(RetentionPolicy.SOURCE)
+    @LongDef({
+        FIELD_TYPE_UNKNOWN,
+        FIELD_TYPE_DOUBLE,
+        FIELD_TYPE_FLOAT,
+        FIELD_TYPE_INT64,
+        FIELD_TYPE_UINT64,
+        FIELD_TYPE_INT32,
+        FIELD_TYPE_FIXED64,
+        FIELD_TYPE_FIXED32,
+        FIELD_TYPE_BOOL,
+        FIELD_TYPE_STRING,
+        FIELD_TYPE_MESSAGE,
+        FIELD_TYPE_BYTES,
+        FIELD_TYPE_UINT32,
+        FIELD_TYPE_ENUM,
+        FIELD_TYPE_SFIXED32,
+        FIELD_TYPE_SFIXED64,
+        FIELD_TYPE_SINT32,
+        FIELD_TYPE_SINT64,
+    })
+    public @interface FieldType {}
+
+
+    /**
+     * Represents the cardinality of a protobuf field.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    @Retention(RetentionPolicy.SOURCE)
+    @LongDef({
+        FIELD_COUNT_UNKNOWN,
+        FIELD_COUNT_SINGLE,
+        FIELD_COUNT_REPEATED,
+        FIELD_COUNT_PACKED,
+    })
+    public @interface FieldCount {}
+
+    /**
+     * Number of bits to shift the field number to form a tag.
+     *
+     * <pre>
+     * // Reading a field number from a tag.
+     * int fieldNumber = tag &gt;&gt;&gt; FIELD_ID_SHIFT;
+     *
+     * // Building a tag from a field number and a wire type.
+     * int tag = (fieldNumber &lt;&lt; FIELD_ID_SHIFT) | wireType;
+     * </pre>
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int FIELD_ID_SHIFT = 3;
+
+    /**
+     * Mask to select the wire type from a tag.
+     *
+     * <pre>
+     * // Reading a wire type from a tag.
+     * int wireType = tag &amp; WIRE_TYPE_MASK;
+     *
+     * // Building a tag from a field number and a wire type.
+     * int tag = (fieldNumber &lt;&lt; FIELD_ID_SHIFT) | wireType;
+     * </pre>
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_MASK = (1 << FIELD_ID_SHIFT) - 1;
+
+    /**
+     * Mask to select the field id from a tag.
+     * @hide (not used by anything, and not actually useful, because you also want
+     * to shift when you mask the field id).
+     */
+    public static final int FIELD_ID_MASK = ~WIRE_TYPE_MASK;
+
+    /**
+     * Varint wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_VARINT = 0;
+
+    /**
+     * Fixed64 wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_FIXED64 = 1;
+
+    /**
+     * Length delimited wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_LENGTH_DELIMITED = 2;
+
+    /**
+     * Start group wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_START_GROUP = 3;
+
+    /**
+     * End group wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_END_GROUP = 4;
+
+    /**
+     * Fixed32 wire type code.
+     *
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final int WIRE_TYPE_FIXED32 = 5;
+
+    /**
+     * Position of the field type in a (long) fieldId.
+     */
+    public static final int FIELD_TYPE_SHIFT = 32;
+
+    /**
+     * Mask for the field types stored in a fieldId.  Leaves a whole
+     * byte for future expansion, even though there are currently only 17 types.
+     */
+    public static final long FIELD_TYPE_MASK = 0x0ffL << FIELD_TYPE_SHIFT;
+
+    /**
+     * Not a real field type.
+     * @hide
+     */
+    public static final long FIELD_TYPE_UNKNOWN = 0;
+
+
+    /*
+     * The FIELD_TYPE_ constants are copied from
+     * external/protobuf/src/google/protobuf/descriptor.h directly, so no
+     * extra mapping needs to be maintained in this case.
+     */
+
+    /**
+     * Field type code for double fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, double)
+     * ProtoOutputStream.write(long, double)} method.
+     */
+    public static final long FIELD_TYPE_DOUBLE = 1L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for float fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, float)
+     * ProtoOutputStream.write(long, float)} method.
+     */
+    public static final long FIELD_TYPE_FLOAT = 2L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for int64 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, long)
+     * ProtoOutputStream.write(long, long)} method.
+     */
+    public static final long FIELD_TYPE_INT64 = 3L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for uint64 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, long)
+     * ProtoOutputStream.write(long, long)} method.
+     */
+    public static final long FIELD_TYPE_UINT64 = 4L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for int32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_INT32 = 5L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for fixed64 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, long)
+     * ProtoOutputStream.write(long, long)} method.
+     */
+    public static final long FIELD_TYPE_FIXED64 = 6L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for fixed32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+
+    /**
+     * Field type code for fixed32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_FIXED32 = 7L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for bool fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, boolean)
+     * ProtoOutputStream.write(long, boolean)} method.
+     */
+    public static final long FIELD_TYPE_BOOL = 8L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for string fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, String)
+     * ProtoOutputStream.write(long, String)} method.
+     */
+    public static final long FIELD_TYPE_STRING = 9L << FIELD_TYPE_SHIFT;
+
+    //  public static final long FIELD_TYPE_GROUP = 10L << FIELD_TYPE_SHIFT; // Deprecated.
+
+    /**
+     * Field type code for message fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#start(long)
+     * ProtoOutputStream.start(long)} method.
+     */
+    public static final long FIELD_TYPE_MESSAGE = 11L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for bytes fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, byte[])
+     * ProtoOutputStream.write(long, byte[])} method.
+     */
+    public static final long FIELD_TYPE_BYTES = 12L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for uint32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_UINT32 = 13L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for enum fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_ENUM = 14L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for sfixed32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_SFIXED32 = 15L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for sfixed64 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, long)
+     * ProtoOutputStream.write(long, long)} method.
+     */
+    public static final long FIELD_TYPE_SFIXED64 = 16L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for sint32 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, int)
+     * ProtoOutputStream.write(long, int)} method.
+     */
+    public static final long FIELD_TYPE_SINT32 = 17L << FIELD_TYPE_SHIFT;
+
+    /**
+     * Field type code for sint64 fields. Used to build constants in generated
+     * code for use with the {@link ProtoOutputStream#write(long, long)
+     * ProtoOutputStream.write(long, long)} method.
+     */
+    public static final long FIELD_TYPE_SINT64 = 18L << FIELD_TYPE_SHIFT;
+
+    private static final @NonNull String[] FIELD_TYPE_NAMES = new String[]{
+            "Double",
+            "Float",
+            "Int64",
+            "UInt64",
+            "Int32",
+            "Fixed64",
+            "Fixed32",
+            "Bool",
+            "String",
+            "Group",  // This field is deprecated but reserved here for indexing.
+            "Message",
+            "Bytes",
+            "UInt32",
+            "Enum",
+            "SFixed32",
+            "SFixed64",
+            "SInt32",
+            "SInt64",
+    };
+
+    //
+    // FieldId flags for whether the field is single, repeated or packed.
+    //
+    /**
+     * Bit offset for building a field id to be used with a
+     * <code>{@link ProtoOutputStream}.write(...)</code>.
+     *
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_UNKNOWN
+     * @see #FIELD_COUNT_SINGLE
+     * @see #FIELD_COUNT_REPEATED
+     * @see #FIELD_COUNT_PACKED
+     */
+    public static final int FIELD_COUNT_SHIFT = 40;
+
+    /**
+     * Bit mask for selecting the field count when reading a field id that
+     * is used with a <code>{@link ProtoOutputStream}.write(...)</code> method.
+     *
+     * @see #FIELD_COUNT_SHIFT
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_UNKNOWN
+     * @see #FIELD_COUNT_SINGLE
+     * @see #FIELD_COUNT_REPEATED
+     * @see #FIELD_COUNT_PACKED
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final long FIELD_COUNT_MASK = 0x0fL << FIELD_COUNT_SHIFT;
+
+    /**
+     * Unknown field count, encoded into a field id used with a
+     * <code>{@link ProtoOutputStream}.write(...)</code> method.
+     *
+     * @see #FIELD_COUNT_SHIFT
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_SINGLE
+     * @see #FIELD_COUNT_REPEATED
+     * @see #FIELD_COUNT_PACKED
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final long FIELD_COUNT_UNKNOWN = 0;
+
+    /**
+     * Single field count, encoded into a field id used with a
+     * <code>{@link ProtoOutputStream}.write(...)</code> method.
+     *
+     * @see #FIELD_COUNT_SHIFT
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_UNKNOWN
+     * @see #FIELD_COUNT_REPEATED
+     * @see #FIELD_COUNT_PACKED
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final long FIELD_COUNT_SINGLE = 1L << FIELD_COUNT_SHIFT;
+
+    /**
+     * Repeated field count, encoded into a field id used with a
+     * <code>{@link ProtoOutputStream}.write(...)</code> method.
+     *
+     * @see #FIELD_COUNT_SHIFT
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_UNKNOWN
+     * @see #FIELD_COUNT_SINGLE
+     * @see #FIELD_COUNT_PACKED
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final long FIELD_COUNT_REPEATED = 2L << FIELD_COUNT_SHIFT;
+
+    /**
+     * Repeated packed field count, encoded into a field id used with a
+     * <code>{@link ProtoOutputStream}.write(...)</code> method.
+     *
+     * @see #FIELD_COUNT_SHIFT
+     * @see #FIELD_COUNT_MASK
+     * @see #FIELD_COUNT_UNKNOWN
+     * @see #FIELD_COUNT_SINGLE
+     * @see #FIELD_COUNT_REPEATED
+     * @see <a href="https://developers.google.com/protocol-buffers/docs/encoding">Protobuf
+     * Encoding</a>
+     */
+    public static final long FIELD_COUNT_PACKED = 5L << FIELD_COUNT_SHIFT;
+
+
+    /**
+     * Get the developer-usable name of a field type.
+     */
+    public static @Nullable String getFieldTypeString(@FieldType long fieldType) {
+        int index = ((int) ((fieldType & FIELD_TYPE_MASK) >>> FIELD_TYPE_SHIFT)) - 1;
+        if (index >= 0 && index < FIELD_TYPE_NAMES.length) {
+            return FIELD_TYPE_NAMES[index];
+        } else {
+            return null;
+        }
+    }
+
+    /**
+     * Get the developer-usable name of a field count.
+     */
+    public static @Nullable String getFieldCountString(long fieldCount) {
+        if (fieldCount == FIELD_COUNT_SINGLE) {
+            return "";
+        } else if (fieldCount == FIELD_COUNT_REPEATED) {
+            return "Repeated";
+        } else if (fieldCount == FIELD_COUNT_PACKED) {
+            return "Packed";
+        } else {
+            return null;
+        }
+    }
+
+    /**
+     * Get the developer-usable name of a wire type.
+     */
+    public static @Nullable String getWireTypeString(@WireType int wireType) {
+        switch (wireType) {
+            case WIRE_TYPE_VARINT:
+                return "Varint";
+            case WIRE_TYPE_FIXED64:
+                return "Fixed64";
+            case WIRE_TYPE_LENGTH_DELIMITED:
+                return "Length Delimited";
+            case WIRE_TYPE_START_GROUP:
+                return "Start Group";
+            case WIRE_TYPE_END_GROUP:
+                return "End Group";
+            case WIRE_TYPE_FIXED32:
+                return "Fixed32";
+            default:
+                return null;
+        }
+    }
+
+    /**
+     * Get a debug string for a fieldId.
+     */
+    public static @NonNull String getFieldIdString(long fieldId) {
+        final long fieldCount = fieldId & FIELD_COUNT_MASK;
+        String countString = getFieldCountString(fieldCount);
+        if (countString == null) {
+            countString = "fieldCount=" + fieldCount;
+        }
+        if (countString.length() > 0) {
+            countString += " ";
+        }
+
+        final long fieldType = fieldId & FIELD_TYPE_MASK;
+        String typeString = getFieldTypeString(fieldType);
+        if (typeString == null) {
+            typeString = "fieldType=" + fieldType;
+        }
+
+        return countString + typeString + " tag=" + ((int) fieldId)
+                + " fieldId=0x" + Long.toHexString(fieldId);
+    }
+
+    /**
+     * Combine a fieldId (the field keys in the proto file) and the field flags.
+     * Mostly useful for testing because the generated code contains the fieldId
+     * constants.
+     */
+    public static long makeFieldId(int id, long fieldFlags) {
+        return fieldFlags | (((long) id) & 0x0ffffffffL);
+    }
+
+    //
+    // Child objects
+    //
+
+    /**
+     * Make a token.
+     * Bits 61-63 - tag size (So we can go backwards later if the object had not data)
+     *            - 3 bits, max value 7, max value needed 5
+     * Bit  60    - true if the object is repeated (lets us require endObject or endRepeatedObject)
+     * Bits 59-51 - depth (For error checking)
+     *            - 9 bits, max value 512, when checking, value is masked (if we really
+     *              are more than 512 levels deep)
+     * Bits 32-50 - objectId (For error checking)
+     *            - 19 bits, max value 524,288. that's a lot of objects. IDs will wrap
+     *              because of the overflow, and only the tokens are compared.
+     * Bits  0-31 - offset of interest for the object.
+     */
+    public static long makeToken(int tagSize, boolean repeated, int depth, int objectId,
+            int offset) {
+        return ((0x07L & (long) tagSize) << 61)
+                | (repeated ? (1L << 60) : 0)
+                | (0x01ffL & (long) depth) << 51
+                | (0x07ffffL & (long) objectId) << 32
+                | (0x0ffffffffL & (long) offset);
+    }
+
+    /**
+     * Get the encoded tag size from the token.
+     *
+     * @hide
+     */
+    public static int getTagSizeFromToken(long token) {
+        return (int) (0x7 & (token >> 61));
+    }
+
+    /**
+     * Get whether the token has the repeated bit set to true or false
+     *
+     * @hide
+     */
+    public static boolean getRepeatedFromToken(long token) {
+        return (0x1 & (token >> 60)) != 0;
+    }
+
+    /**
+     * Get the nesting depth from the token.
+     *
+     * @hide
+     */
+    public static int getDepthFromToken(long token) {
+        return (int) (0x01ff & (token >> 51));
+    }
+
+    /**
+     * Get the object ID from the token.
+     *
+     * <p>The object ID is a serial number for the
+     * startObject calls that have happened on this object.  The values are truncated
+     * to 9 bits, but that is sufficient for error checking.
+     *
+     * @hide
+     */
+    public static int getObjectIdFromToken(long token) {
+        return (int) (0x07ffff & (token >> 32));
+    }
+
+    /**
+     * Get the location of the offset recorded in the token.
+     *
+     * @hide
+     */
+    public static int getOffsetFromToken(long token) {
+        return (int) token;
+    }
+
+    /**
+     * Convert the object ID to the ordinal value -- the n-th call to startObject.
+     *
+     * <p>The object IDs start at -1 and count backwards, so that the value is unlikely
+     * to alias with an actual size field that had been written.
+     *
+     * @hide
+     */
+    public static int convertObjectIdToOrdinal(int objectId) {
+        return (-1 & 0x07ffff) - objectId;
+    }
+
+    /**
+     * Return a debugging string of a token.
+     */
+    public static @NonNull String token2String(long token) {
+        if (token == 0L) {
+            return "Token(0)";
+        } else {
+            return "Token(val=0x" + Long.toHexString(token)
+                    + " depth=" + getDepthFromToken(token)
+                    + " object=" + convertObjectIdToOrdinal(getObjectIdFromToken(token))
+                    + " tagSize=" + getTagSizeFromToken(token)
+                    + " offset=" + getOffsetFromToken(token)
+                    + ')';
+        }
+    }
+
+    /**
+     * @hide
+     */
+    protected ProtoStream() {}
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/TEST_MAPPING b/framework/java/android/util/configinfrastructure/proto/TEST_MAPPING
new file mode 100644
index 0000000..1261743
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/TEST_MAPPING
@@ -0,0 +1,16 @@
+{
+  "presubmit": [
+    {
+      "name": "ProtoInputStreamTests"
+    },
+    {
+      "name": "CtsProtoTestCases"
+    }
+  ],
+  "ravenwood-presubmit": [
+    {
+      "name": "CtsProtoTestCasesRavenwood",
+      "host": true
+    }
+  ]
+}
diff --git a/framework/java/android/util/configinfrastructure/proto/WireTypeMismatchException.java b/framework/java/android/util/configinfrastructure/proto/WireTypeMismatchException.java
new file mode 100644
index 0000000..6f75a63
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/WireTypeMismatchException.java
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.util.configinfrastructure.proto;
+
+/**
+ * Thrown when there is an error parsing protobuf data.
+ *
+ * This is copied from frameworks/base/core/java/android/util/proto/WireTypeMismatchException.java
+ * so ConfigInfra can use ProtoInputStream. Any major bugfixes in the original
+ * WireTypeMismatchException should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class WireTypeMismatchException extends ProtoParseException {
+
+    /**
+     * Construct a WireTypeMismatchException.
+     *
+     * @param msg The message.
+     */
+    public WireTypeMismatchException(String msg) {
+        super(msg);
+    }
+}
+
diff --git a/framework/java/android/util/configinfrastructure/proto/package.html b/framework/java/android/util/configinfrastructure/proto/package.html
new file mode 100644
index 0000000..ef1125b
--- /dev/null
+++ b/framework/java/android/util/configinfrastructure/proto/package.html
@@ -0,0 +1,5 @@
+<html>
+<body>
+Provides utility classes to export protocol buffers from the system.
+</body>
+</html>
\ No newline at end of file
diff --git a/framework/java/com/android/internal/util/configinfrastructure/Android.bp b/framework/java/com/android/internal/util/configinfrastructure/Android.bp
new file mode 100644
index 0000000..96c33c2
--- /dev/null
+++ b/framework/java/com/android/internal/util/configinfrastructure/Android.bp
@@ -0,0 +1,35 @@
+//
+// Copyright (C) 2021 The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "modules-utils-arrayutils",
+    defaults: ["framework-module-defaults"],
+    srcs: ["*.java"],
+    libs: [
+        "unsupportedappusage",
+    ],
+    static_libs: [
+        "modules-utils-emptyarray",
+        "error_prone_annotations",
+    ],
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+    ],
+}
diff --git a/framework/java/com/android/internal/util/configinfrastructure/ArrayUtils.java b/framework/java/com/android/internal/util/configinfrastructure/ArrayUtils.java
new file mode 100644
index 0000000..54db86d
--- /dev/null
+++ b/framework/java/com/android/internal/util/configinfrastructure/ArrayUtils.java
@@ -0,0 +1,1038 @@
+/*
+ * Copyright (C) 2006 The Android Open Source Project
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
+package com.android.internal.util.configinfrastructure;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.compat.annotation.UnsupportedAppUsage;
+import android.os.Build;
+import android.ravenwood.annotation.RavenwoodReplace;
+import android.util.ArraySet;
+import android.util.configinfrastructure.EmptyArray;
+
+import dalvik.system.VMRuntime;
+
+import java.io.File;
+import java.lang.reflect.Array;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collection;
+import java.util.Collections;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+import java.util.Set;
+import java.util.function.IntFunction;
+
+/**
+ * Static utility methods for arrays that aren't already included in {@link java.util.Arrays}.
+ * <p>
+ * Test with:
+ * <code>atest FrameworksUtilTests:com.android.internal.util.ArrayUtilsTest</code>
+ * <code>atest FrameworksUtilTestsRavenwood:com.android.internal.util.ArrayUtilsTest</code>
+ *
+ * This is copied from frameworks/base/core/java/com/android/internal/util/ArrayUtils.java.
+ * Any major bugfixes in the original ArrayUtils should be copied here.
+ *
+ * @hide
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class ArrayUtils {
+    private static final int CACHE_SIZE = 73;
+    private static Object[] sCache = new Object[CACHE_SIZE];
+
+    public static final File[] EMPTY_FILE = new File[0];
+
+    private ArrayUtils() { /* cannot be instantiated */ }
+
+    public static byte[] newUnpaddedByteArray(int minLen) {
+        return (byte[])VMRuntime.getRuntime().newUnpaddedArray(byte.class, minLen);
+    }
+
+    public static char[] newUnpaddedCharArray(int minLen) {
+        return (char[])VMRuntime.getRuntime().newUnpaddedArray(char.class, minLen);
+    }
+
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    public static int[] newUnpaddedIntArray(int minLen) {
+        return (int[])VMRuntime.getRuntime().newUnpaddedArray(int.class, minLen);
+    }
+
+    public static boolean[] newUnpaddedBooleanArray(int minLen) {
+        return (boolean[])VMRuntime.getRuntime().newUnpaddedArray(boolean.class, minLen);
+    }
+
+    public static long[] newUnpaddedLongArray(int minLen) {
+        return (long[])VMRuntime.getRuntime().newUnpaddedArray(long.class, minLen);
+    }
+
+    public static float[] newUnpaddedFloatArray(int minLen) {
+        return (float[])VMRuntime.getRuntime().newUnpaddedArray(float.class, minLen);
+    }
+
+    public static Object[] newUnpaddedObjectArray(int minLen) {
+        return (Object[])VMRuntime.getRuntime().newUnpaddedArray(Object.class, minLen);
+    }
+
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    @SuppressWarnings("unchecked")
+    public static <T> T[] newUnpaddedArray(Class<T> clazz, int minLen) {
+        return (T[])VMRuntime.getRuntime().newUnpaddedArray(clazz, minLen);
+    }
+
+    /**
+     * This is like <code>new byte[length]</code>, but it allocates the array as non-movable. This
+     * prevents copies of the data from being left on the Java heap as a result of heap compaction.
+     * Use this when the array will contain sensitive data such as a password or cryptographic key
+     * that needs to be wiped from memory when no longer needed. The owner of the array is still
+     * responsible for the zeroization; {@link #zeroize(byte[])} should be used to do so.
+     *
+     * @param length the length of the array to allocate
+     * @return the new array
+     */
+    public static byte[] newNonMovableByteArray(int length) {
+        return (byte[]) VMRuntime.getRuntime().newNonMovableArray(byte.class, length);
+    }
+
+    /**
+     * Like {@link #newNonMovableByteArray(int)}, but allocates a char array.
+     *
+     * @param length the length of the array to allocate
+     * @return the new array
+     */
+    public static char[] newNonMovableCharArray(int length) {
+        return (char[]) VMRuntime.getRuntime().newNonMovableArray(char.class, length);
+    }
+
+    /**
+     * Zeroizes a byte array as securely as possible. Use this when the array contains sensitive
+     * data such as a password or cryptographic key.
+     * <p>
+     * This zeroizes the array in a way that is guaranteed to not be optimized out by the compiler.
+     * If supported by the architecture, it zeroizes the data not just in the L1 data cache but also
+     * in other levels of the memory hierarchy up to and including main memory (but not above that).
+     * <p>
+     * This works on any <code>byte[]</code>, but to ensure that copies of the array aren't left on
+     * the Java heap the array should have been allocated with {@link #newNonMovableByteArray(int)}.
+     * Use on other arrays might also introduce performance anomalies.
+     *
+     * @param array the array to zeroize. If null, this method has no effect.
+     */
+    @RavenwoodReplace public static native void zeroize(byte[] array);
+
+    /**
+     * Replacement of the above method for host-side unit testing that doesn't support JNI yet.
+     */
+    public static void zeroize$ravenwood(byte[] array) {
+        if (array != null) {
+            Arrays.fill(array, (byte) 0);
+        }
+    }
+
+    /**
+     * Like {@link #zeroize(byte[])}, but for char arrays.
+     */
+    @RavenwoodReplace public static native void zeroize(char[] array);
+
+    /**
+     * Replacement of the above method for host-side unit testing that doesn't support JNI yet.
+     */
+    public static void zeroize$ravenwood(char[] array) {
+        if (array != null) {
+            Arrays.fill(array, (char) 0);
+        }
+    }
+
+    /**
+     * Checks if the beginnings of two byte arrays are equal.
+     *
+     * @param array1 the first byte array
+     * @param array2 the second byte array
+     * @param length the number of bytes to check
+     * @return true if they're equal, false otherwise
+     */
+    public static boolean equals(byte[] array1, byte[] array2, int length) {
+        if (length < 0) {
+            throw new IllegalArgumentException();
+        }
+
+        if (array1 == array2) {
+            return true;
+        }
+        if (array1 == null || array2 == null || array1.length < length || array2.length < length) {
+            return false;
+        }
+        for (int i = 0; i < length; i++) {
+            if (array1[i] != array2[i]) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    /**
+     * Returns an empty array of the specified type.  The intent is that
+     * it will return the same empty array every time to avoid reallocation,
+     * although this is not guaranteed.
+     */
+    @UnsupportedAppUsage
+    @SuppressWarnings("unchecked")
+    public static <T> T[] emptyArray(Class<T> kind) {
+        if (kind == Object.class) {
+            return (T[]) EmptyArray.OBJECT;
+        }
+
+        int bucket = (kind.hashCode() & 0x7FFFFFFF) % CACHE_SIZE;
+        Object cache = sCache[bucket];
+
+        if (cache == null || cache.getClass().getComponentType() != kind) {
+            cache = Array.newInstance(kind, 0);
+            sCache[bucket] = cache;
+
+            // Log.e("cache", "new empty " + kind.getName() + " at " + bucket);
+        }
+
+        return (T[]) cache;
+    }
+
+    /**
+     * Returns the same array or an empty one if it's null.
+     */
+    public static @NonNull <T> T[] emptyIfNull(@Nullable T[] items, Class<T> kind) {
+        return items != null ? items : emptyArray(kind);
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable Collection<?> array) {
+        return array == null || array.isEmpty();
+    }
+
+    /**
+     * Checks if given map is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable Map<?, ?> map) {
+        return map == null || map.isEmpty();
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    @UnsupportedAppUsage
+    public static <T> boolean isEmpty(@Nullable T[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable int[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable long[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable byte[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * Checks if given array is null or has zero elements.
+     */
+    public static boolean isEmpty(@Nullable boolean[] array) {
+        return array == null || array.length == 0;
+    }
+
+    /**
+     * Length of the given array or 0 if it's null.
+     */
+    public static int size(@Nullable Object[] array) {
+        return array == null ? 0 : array.length;
+    }
+
+    /**
+     * Length of the given collection or 0 if it's null.
+     */
+    public static int size(@Nullable Collection<?> collection) {
+        return collection == null ? 0 : collection.size();
+    }
+
+    /**
+     * Length of the given map or 0 if it's null.
+     */
+    public static int size(@Nullable Map<?, ?> map) {
+        return map == null ? 0 : map.size();
+    }
+
+    /**
+     * Checks that value is present as at least one of the elements of the array.
+     * @param array the array to check in
+     * @param value the value to check for
+     * @return true if the value is present in the array
+     */
+    @UnsupportedAppUsage
+    public static <T> boolean contains(@Nullable T[] array, T value) {
+        return indexOf(array, value) != -1;
+    }
+
+    /**
+     * Return first index of {@code value} in {@code array}, or {@code -1} if
+     * not found.
+     */
+    @UnsupportedAppUsage
+    public static <T> int indexOf(@Nullable T[] array, T value) {
+        if (array == null) return -1;
+        for (int i = 0; i < array.length; i++) {
+            if (Objects.equals(array[i], value)) return i;
+        }
+        return -1;
+    }
+
+    /**
+     * Test if all {@code check} items are contained in {@code array}.
+     */
+    public static <T> boolean containsAll(@Nullable T[] array, T[] check) {
+        if (check == null) return true;
+        for (T checkItem : check) {
+            if (!contains(array, checkItem)) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    /**
+     * Test if any {@code check} items are contained in {@code array}.
+     */
+    public static <T> boolean containsAny(@Nullable T[] array, T[] check) {
+        if (check == null) return false;
+        for (T checkItem : check) {
+            if (contains(array, checkItem)) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    @UnsupportedAppUsage
+    public static boolean contains(@Nullable int[] array, int value) {
+        if (array == null) return false;
+        for (int element : array) {
+            if (element == value) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    public static boolean contains(@Nullable long[] array, long value) {
+        if (array == null) return false;
+        for (long element : array) {
+            if (element == value) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    public static boolean contains(@Nullable char[] array, char value) {
+        if (array == null) return false;
+        for (char element : array) {
+            if (element == value) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Test if all {@code check} items are contained in {@code array}.
+     */
+    public static <T> boolean containsAll(@Nullable char[] array, char[] check) {
+        if (check == null) return true;
+        for (char checkItem : check) {
+            if (!contains(array, checkItem)) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    public static long total(@Nullable long[] array) {
+        long total = 0;
+        if (array != null) {
+            for (long value : array) {
+                total += value;
+            }
+        }
+        return total;
+    }
+
+    /**
+     * @deprecated use {@code IntArray} instead
+     */
+    @Deprecated
+    public static int[] convertToIntArray(List<Integer> list) {
+        int[] array = new int[list.size()];
+        for (int i = 0; i < list.size(); i++) {
+            array[i] = list.get(i);
+        }
+        return array;
+    }
+
+    @NonNull
+    public static int[] convertToIntArray(@NonNull ArraySet<Integer> set) {
+        final int size = set.size();
+        int[] array = new int[size];
+        for (int i = 0; i < size; i++) {
+            array[i] = set.valueAt(i);
+        }
+        return array;
+    }
+
+    public static @Nullable long[] convertToLongArray(@Nullable int[] intArray) {
+        if (intArray == null) return null;
+        long[] array = new long[intArray.length];
+        for (int i = 0; i < intArray.length; i++) {
+            array[i] = (long) intArray[i];
+        }
+        return array;
+    }
+
+    /**
+     * Returns the concatenation of the given arrays.  Only works for object arrays, not for
+     * primitive arrays.  See {@link #concat(byte[]...)} for a variant that works on byte arrays.
+     *
+     * @param kind The class of the array elements
+     * @param arrays The arrays to concatenate.  Null arrays are treated as empty.
+     * @param <T> The class of the array elements (inferred from kind).
+     * @return A single array containing all the elements of the parameter arrays.
+     */
+    @SuppressWarnings("unchecked")
+    public static @NonNull <T> T[] concat(Class<T> kind, @Nullable T[]... arrays) {
+        if (arrays == null || arrays.length == 0) {
+            return createEmptyArray(kind);
+        }
+
+        int totalLength = 0;
+        for (T[] item : arrays) {
+            if (item == null) {
+                continue;
+            }
+
+            totalLength += item.length;
+        }
+
+        // Optimization for entirely empty arrays.
+        if (totalLength == 0) {
+            return createEmptyArray(kind);
+        }
+
+        final T[] all = (T[]) Array.newInstance(kind, totalLength);
+        int pos = 0;
+        for (T[] item : arrays) {
+            if (item == null || item.length == 0) {
+                continue;
+            }
+            System.arraycopy(item, 0, all, pos, item.length);
+            pos += item.length;
+        }
+        return all;
+    }
+
+    private static @NonNull <T> T[] createEmptyArray(Class<T> kind) {
+        if (kind == String.class) {
+            return (T[]) EmptyArray.STRING;
+        } else if (kind == Object.class) {
+            return (T[]) EmptyArray.OBJECT;
+        }
+
+        return (T[]) Array.newInstance(kind, 0);
+    }
+
+    /**
+     * Returns the concatenation of the given byte arrays.  Null arrays are treated as empty.
+     */
+    public static @NonNull byte[] concat(@Nullable byte[]... arrays) {
+        if (arrays == null) {
+            return new byte[0];
+        }
+        int totalLength = 0;
+        for (byte[] a : arrays) {
+            if (a != null) {
+                totalLength += a.length;
+            }
+        }
+        final byte[] result = new byte[totalLength];
+        int pos = 0;
+        for (byte[] a : arrays) {
+            if (a != null) {
+                System.arraycopy(a, 0, result, pos, a.length);
+                pos += a.length;
+            }
+        }
+        return result;
+    }
+
+    /**
+     * Adds value to given array if not already present, providing set-like
+     * behavior.
+     */
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    @SuppressWarnings("unchecked")
+    public static @NonNull <T> T[] appendElement(Class<T> kind, @Nullable T[] array, T element) {
+        return appendElement(kind, array, element, false);
+    }
+
+    /**
+     * Adds value to given array.
+     */
+    @SuppressWarnings("unchecked")
+    public static @NonNull <T> T[] appendElement(Class<T> kind, @Nullable T[] array, T element,
+            boolean allowDuplicates) {
+        final T[] result;
+        final int end;
+        if (array != null) {
+            if (!allowDuplicates && contains(array, element)) return array;
+            end = array.length;
+            result = (T[])Array.newInstance(kind, end + 1);
+            System.arraycopy(array, 0, result, 0, end);
+        } else {
+            end = 0;
+            result = (T[])Array.newInstance(kind, 1);
+        }
+        result[end] = element;
+        return result;
+    }
+
+    /**
+     * Removes value from given array if present, providing set-like behavior.
+     */
+    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
+    @SuppressWarnings("unchecked")
+    public static @Nullable <T> T[] removeElement(Class<T> kind, @Nullable T[] array, T element) {
+        if (array != null) {
+            if (!contains(array, element)) return array;
+            final int length = array.length;
+            for (int i = 0; i < length; i++) {
+                if (Objects.equals(array[i], element)) {
+                    if (length == 1) {
+                        return null;
+                    }
+                    T[] result = (T[])Array.newInstance(kind, length - 1);
+                    System.arraycopy(array, 0, result, 0, i);
+                    System.arraycopy(array, i + 1, result, i, length - i - 1);
+                    return result;
+                }
+            }
+        }
+        return array;
+    }
+
+    /**
+     * Adds value to given array.
+     */
+    public static @NonNull int[] appendInt(@Nullable int[] cur, int val,
+            boolean allowDuplicates) {
+        if (cur == null) {
+            return new int[] { val };
+        }
+        final int N = cur.length;
+        if (!allowDuplicates) {
+            for (int i = 0; i < N; i++) {
+                if (cur[i] == val) {
+                    return cur;
+                }
+            }
+        }
+        int[] ret = new int[N + 1];
+        System.arraycopy(cur, 0, ret, 0, N);
+        ret[N] = val;
+        return ret;
+    }
+
+    /**
+     * Adds value to given array if not already present, providing set-like
+     * behavior.
+     */
+    @UnsupportedAppUsage
+    public static @NonNull int[] appendInt(@Nullable int[] cur, int val) {
+        return appendInt(cur, val, false);
+    }
+
+    /**
+     * Removes value from given array if present, providing set-like behavior.
+     */
+    public static @Nullable int[] removeInt(@Nullable int[] cur, int val) {
+        if (cur == null) {
+            return null;
+        }
+        final int N = cur.length;
+        for (int i = 0; i < N; i++) {
+            if (cur[i] == val) {
+                int[] ret = new int[N - 1];
+                if (i > 0) {
+                    System.arraycopy(cur, 0, ret, 0, i);
+                }
+                if (i < (N - 1)) {
+                    System.arraycopy(cur, i + 1, ret, i, N - i - 1);
+                }
+                return ret;
+            }
+        }
+        return cur;
+    }
+
+    /**
+     * Removes value from given array if present, providing set-like behavior.
+     */
+    public static @Nullable String[] removeString(@Nullable String[] cur, String val) {
+        if (cur == null) {
+            return null;
+        }
+        final int N = cur.length;
+        for (int i = 0; i < N; i++) {
+            if (Objects.equals(cur[i], val)) {
+                String[] ret = new String[N - 1];
+                if (i > 0) {
+                    System.arraycopy(cur, 0, ret, 0, i);
+                }
+                if (i < (N - 1)) {
+                    System.arraycopy(cur, i + 1, ret, i, N - i - 1);
+                }
+                return ret;
+            }
+        }
+        return cur;
+    }
+
+    /**
+     * Adds value to given array if not already present, providing set-like
+     * behavior.
+     */
+    public static @NonNull long[] appendLong(@Nullable long[] cur, long val,
+            boolean allowDuplicates) {
+        if (cur == null) {
+            return new long[] { val };
+        }
+        final int N = cur.length;
+        if (!allowDuplicates) {
+            for (int i = 0; i < N; i++) {
+                if (cur[i] == val) {
+                    return cur;
+                }
+            }
+        }
+        long[] ret = new long[N + 1];
+        System.arraycopy(cur, 0, ret, 0, N);
+        ret[N] = val;
+        return ret;
+    }
+
+    /**
+     * Adds value to given array. The method allows duplicate values.
+     */
+    public static boolean[] appendBooleanDuplicatesAllowed(@Nullable boolean[] cur,
+            boolean val) {
+        if (cur == null) {
+            return new boolean[] { val };
+        }
+        final int N = cur.length;
+        boolean[] ret = new boolean[N + 1];
+        System.arraycopy(cur, 0, ret, 0, N);
+        ret[N] = val;
+        return ret;
+    }
+
+    /**
+     * Adds value to given array if not already present, providing set-like
+     * behavior.
+     */
+    public static @NonNull long[] appendLong(@Nullable long[] cur, long val) {
+        return appendLong(cur, val, false);
+    }
+
+    /**
+     * Removes value from given array if present, providing set-like behavior.
+     */
+    public static @Nullable long[] removeLong(@Nullable long[] cur, long val) {
+        if (cur == null) {
+            return null;
+        }
+        final int N = cur.length;
+        for (int i = 0; i < N; i++) {
+            if (cur[i] == val) {
+                long[] ret = new long[N - 1];
+                if (i > 0) {
+                    System.arraycopy(cur, 0, ret, 0, i);
+                }
+                if (i < (N - 1)) {
+                    System.arraycopy(cur, i + 1, ret, i, N - i - 1);
+                }
+                return ret;
+            }
+        }
+        return cur;
+    }
+
+    public static @Nullable long[] cloneOrNull(@Nullable long[] array) {
+        return (array != null) ? array.clone() : null;
+    }
+
+    /**
+     * Clones an array or returns null if the array is null.
+     */
+    public static @Nullable <T> T[] cloneOrNull(@Nullable T[] array) {
+        return (array != null) ? array.clone() : null;
+    }
+
+    public static @Nullable <T> ArraySet<T> cloneOrNull(@Nullable ArraySet<T> array) {
+        return (array != null) ? new ArraySet<T>(array) : null;
+    }
+
+    public static @NonNull <T> ArraySet<T> add(@Nullable ArraySet<T> cur, T val) {
+        if (cur == null) {
+            cur = new ArraySet<>();
+        }
+        cur.add(val);
+        return cur;
+    }
+
+    /**
+     * Similar to {@link Set#addAll(Collection)}}, but with support for set values of {@code null}.
+     */
+    public static @NonNull <T> ArraySet<T> addAll(@Nullable ArraySet<T> cur,
+            @Nullable Collection<T> val) {
+        if (cur == null) {
+            cur = new ArraySet<>();
+        }
+        if (val != null) {
+            cur.addAll(val);
+        }
+        return cur;
+    }
+
+    public static @Nullable <T> ArraySet<T> remove(@Nullable ArraySet<T> cur, T val) {
+        if (cur == null) {
+            return null;
+        }
+        cur.remove(val);
+        if (cur.isEmpty()) {
+            return null;
+        } else {
+            return cur;
+        }
+    }
+
+    public static @NonNull <T> ArrayList<T> add(@Nullable ArrayList<T> cur, T val) {
+        if (cur == null) {
+            cur = new ArrayList<>();
+        }
+        cur.add(val);
+        return cur;
+    }
+
+    public static @NonNull <T> ArrayList<T> add(@Nullable ArrayList<T> cur, int index, T val) {
+        if (cur == null) {
+            cur = new ArrayList<>();
+        }
+        cur.add(index, val);
+        return cur;
+    }
+
+    public static @Nullable <T> ArrayList<T> remove(@Nullable ArrayList<T> cur, T val) {
+        if (cur == null) {
+            return null;
+        }
+        cur.remove(val);
+        if (cur.isEmpty()) {
+            return null;
+        } else {
+            return cur;
+        }
+    }
+
+    public static <T> boolean contains(@Nullable Collection<T> cur, T val) {
+        return (cur != null) ? cur.contains(val) : false;
+    }
+
+    public static @Nullable <T> T[] trimToSize(@Nullable T[] array, int size) {
+        if (array == null || size == 0) {
+            return null;
+        } else if (array.length == size) {
+            return array;
+        } else {
+            return Arrays.copyOf(array, size);
+        }
+    }
+
+    /**
+     * Returns true if the two ArrayLists are equal with respect to the objects they contain.
+     * The objects must be in the same order and be reference equal (== not .equals()).
+     */
+    public static <T> boolean referenceEquals(ArrayList<T> a, ArrayList<T> b) {
+        if (a == b) {
+            return true;
+        }
+
+        final int sizeA = a.size();
+        final int sizeB = b.size();
+        if (a == null || b == null || sizeA != sizeB) {
+            return false;
+        }
+
+        boolean diff = false;
+        for (int i = 0; i < sizeA && !diff; i++) {
+            diff |= a.get(i) != b.get(i);
+        }
+        return !diff;
+    }
+
+    /**
+     * Removes elements that match the predicate in an efficient way that alters the order of
+     * elements in the collection. This should only be used if order is not important.
+     * @param collection The ArrayList from which to remove elements.
+     * @param predicate The predicate that each element is tested against.
+     * @return the number of elements removed.
+     */
+    public static <T> int unstableRemoveIf(@Nullable ArrayList<T> collection,
+                                           @NonNull java.util.function.Predicate<T> predicate) {
+        if (collection == null) {
+            return 0;
+        }
+
+        final int size = collection.size();
+        int leftIdx = 0;
+        int rightIdx = size - 1;
+        while (leftIdx <= rightIdx) {
+            // Find the next element to remove moving left to right.
+            while (leftIdx < size && !predicate.test(collection.get(leftIdx))) {
+                leftIdx++;
+            }
+
+            // Find the next element to keep moving right to left.
+            while (rightIdx > leftIdx && predicate.test(collection.get(rightIdx))) {
+                rightIdx--;
+            }
+
+            if (leftIdx >= rightIdx) {
+                // Done.
+                break;
+            }
+
+            Collections.swap(collection, leftIdx, rightIdx);
+            leftIdx++;
+            rightIdx--;
+        }
+
+        // leftIdx is now at the end.
+        for (int i = size - 1; i >= leftIdx; i--) {
+            collection.remove(i);
+        }
+        return size - leftIdx;
+    }
+
+    public static @NonNull int[] defeatNullable(@Nullable int[] val) {
+        return (val != null) ? val : EmptyArray.INT;
+    }
+
+    public static @NonNull String[] defeatNullable(@Nullable String[] val) {
+        return (val != null) ? val : EmptyArray.STRING;
+    }
+
+    public static @NonNull File[] defeatNullable(@Nullable File[] val) {
+        return (val != null) ? val : EMPTY_FILE;
+    }
+
+    /**
+     * Throws {@link ArrayIndexOutOfBoundsException} if the index is out of bounds.
+     *
+     * @param len length of the array. Must be non-negative
+     * @param index the index to check
+     * @throws ArrayIndexOutOfBoundsException if the {@code index} is out of bounds of the array
+     */
+    public static void checkBounds(int len, int index) {
+        if (index < 0 || len <= index) {
+            throw new ArrayIndexOutOfBoundsException("length=" + len + "; index=" + index);
+        }
+    }
+
+    /**
+     * Throws {@link ArrayIndexOutOfBoundsException} if the range is out of bounds.
+     * @param len length of the array. Must be non-negative
+     * @param offset start index of the range. Must be non-negative
+     * @param count length of the range. Must be non-negative
+     * @throws ArrayIndexOutOfBoundsException if the range from {@code offset} with length
+     * {@code count} is out of bounds of the array
+     */
+    public static void throwsIfOutOfBounds(int len, int offset, int count) {
+        if (len < 0) {
+            throw new ArrayIndexOutOfBoundsException("Negative length: " + len);
+        }
+
+        if ((offset | count) < 0 || offset > len - count) {
+            throw new ArrayIndexOutOfBoundsException(
+                    "length=" + len + "; regionStart=" + offset + "; regionLength=" + count);
+        }
+    }
+
+    /**
+     * Returns an array with values from {@code val} minus {@code null} values
+     *
+     * @param arrayConstructor typically {@code T[]::new} e.g. {@code String[]::new}
+     */
+    public static <T> T[] filterNotNull(T[] val, IntFunction<T[]> arrayConstructor) {
+        int nullCount = 0;
+        int size = size(val);
+        for (int i = 0; i < size; i++) {
+            if (val[i] == null) {
+                nullCount++;
+            }
+        }
+        if (nullCount == 0) {
+            return val;
+        }
+        T[] result = arrayConstructor.apply(size - nullCount);
+        int outIdx = 0;
+        for (int i = 0; i < size; i++) {
+            if (val[i] != null) {
+                result[outIdx++] = val[i];
+            }
+        }
+        return result;
+    }
+
+    /**
+     * Returns an array containing elements from the given one that match the given predicate.
+     * The returned array may, in some cases, be the reference to the input array.
+     */
+    public static @Nullable <T> T[] filter(@Nullable T[] items,
+            @NonNull IntFunction<T[]> arrayConstructor,
+            @NonNull java.util.function.Predicate<T> predicate) {
+        if (isEmpty(items)) {
+            return items;
+        }
+
+        int matchesCount = 0;
+        int size = size(items);
+        final boolean[] tests = new boolean[size];
+        for (int i = 0; i < size; i++) {
+            tests[i] = predicate.test(items[i]);
+            if (tests[i]) {
+                matchesCount++;
+            }
+        }
+        if (matchesCount == items.length) {
+            return items;
+        }
+        T[] result = arrayConstructor.apply(matchesCount);
+        if (matchesCount == 0) {
+            return result;
+        }
+        int outIdx = 0;
+        for (int i = 0; i < size; i++) {
+            if (tests[i]) {
+                result[outIdx++] = items[i];
+            }
+        }
+        return result;
+    }
+
+    public static boolean startsWith(byte[] cur, byte[] val) {
+        if (cur == null || val == null) return false;
+        if (cur.length < val.length) return false;
+        for (int i = 0; i < val.length; i++) {
+            if (cur[i] != val[i]) return false;
+        }
+        return true;
+    }
+
+    /**
+     * Returns the first element from the array for which
+     * condition {@code predicate} is true, or null if there is no such element
+     */
+    public static @Nullable <T> T find(@Nullable T[] items,
+            @NonNull java.util.function.Predicate<T> predicate) {
+        if (isEmpty(items)) return null;
+        for (final T item : items) {
+            if (predicate.test(item)) return item;
+        }
+        return null;
+    }
+
+    public static String deepToString(Object value) {
+        if (value != null && value.getClass().isArray()) {
+            if (value.getClass() == boolean[].class) {
+                return Arrays.toString((boolean[]) value);
+            } else if (value.getClass() == byte[].class) {
+                return Arrays.toString((byte[]) value);
+            } else if (value.getClass() == char[].class) {
+                return Arrays.toString((char[]) value);
+            } else if (value.getClass() == double[].class) {
+                return Arrays.toString((double[]) value);
+            } else if (value.getClass() == float[].class) {
+                return Arrays.toString((float[]) value);
+            } else if (value.getClass() == int[].class) {
+                return Arrays.toString((int[]) value);
+            } else if (value.getClass() == long[].class) {
+                return Arrays.toString((long[]) value);
+            } else if (value.getClass() == short[].class) {
+                return Arrays.toString((short[]) value);
+            } else {
+                return Arrays.deepToString((Object[]) value);
+            }
+        } else {
+            return String.valueOf(value);
+        }
+    }
+
+    /**
+     * Returns the {@code i}-th item in {@code items}, if it exists and {@code items} is not {@code
+     * null}, otherwise returns {@code null}.
+     */
+    @Nullable
+    public static <T> T getOrNull(@Nullable T[] items, int i) {
+        return (items != null && items.length > i) ? items[i] : null;
+    }
+
+    public static @Nullable <T> T firstOrNull(T[] items) {
+        return items.length > 0 ? items[0] : null;
+    }
+
+    /**
+     * Creates a {@link List} from an array. Different from {@link Arrays#asList(Object[])} as that
+     * will use the parameter as the backing array, meaning changes are not isolated.
+     */
+    public static <T> List<T> toList(T[] array) {
+        List<T> list = new ArrayList<>(array.length);
+        //noinspection ManualArrayToCollectionCopy
+        for (T item : array) {
+            //noinspection UseBulkOperation
+            list.add(item);
+        }
+        return list;
+    }
+}
diff --git a/framework/tests/Android.bp b/framework/tests/Android.bp
index 77bbfdd..f138dbe 100644
--- a/framework/tests/Android.bp
+++ b/framework/tests/Android.bp
@@ -17,20 +17,75 @@ package {
 }
 
 android_test {
-    name: "AconfigPackageTests",
-    srcs: ["src/**/*.java"],
+    name: "FlagManagerUnitTests",
+    srcs: [
+        "src/FlagManagerUnitTests.java",
+    ],
+    static_libs: [
+        "aconfig_device_paths_java",
+        "androidx.test.rules",
+        "aconfig_storage_file_java",
+        "configinfra_framework_flags_java_lib",
+        "junit",
+        "flag-junit",
+    ],
+    libs: [
+        "framework-configinfrastructure.impl",
+    ],
+    sdk_version: "module_current",
+    test_suites: [
+        "general-tests",
+    ],
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
+    team: "trendy_team_android_core_experiments",
+    test_config: "AndroidUnitTest.xml",
+}
+
+android_test {
+    name: "AconfigPublicApiCtsTests",
+    srcs: [
+        "src/AconfigPublicApiCtsTests.java",
+    ],
     static_libs: [
         "aconfig_device_paths_java",
         "androidx.test.rules",
         "aconfig_storage_file_java",
+        "configinfra_framework_flags_java_lib",
+        "junit",
+        "flag-junit",
+    ],
+    libs: [
+        "framework-configinfrastructure.impl",
+    ],
+    sdk_version: "module_current",
+    test_suites: [
+        "general-tests",
+        "cts",
+    ],
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
+    team: "trendy_team_android_core_experiments",
+    test_config: "AndroidCtsTest.xml",
+}
+
+android_test {
+    name: "AconfigPackageTests",
+    srcs: [
+        "src/AconfigPackageInternalTests.java",
+        "src/AconfigPackageTests.java",
+    ],
+    static_libs: [
+        "aconfig_device_paths_java_util",
+        "androidx.test.rules",
+        "aconfig_storage_file_java",
         "junit",
     ],
     libs: [
-        "framework-configinfrastructure.impl"
+        "framework-configinfrastructure.impl",
     ],
     sdk_version: "module_current",
     test_suites: [
         "general-tests",
     ],
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
     team: "trendy_team_android_core_experiments",
 }
diff --git a/framework/tests/AndroidCtsTest.xml b/framework/tests/AndroidCtsTest.xml
new file mode 100644
index 0000000..06d97df
--- /dev/null
+++ b/framework/tests/AndroidCtsTest.xml
@@ -0,0 +1,34 @@
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
+<configuration description="Configuration for aconfigd CTS tests">
+    <option name="test-suite-tag" value="cts" />
+    <option name="config-descriptor:metadata" key="component" value="framework" />
+    <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
+    <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.configinfrastructure.apex" />
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="AconfigPublicApiCtsTests.apk" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.os.flagging.test" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+    </test>
+</configuration>
diff --git a/framework/tests/AndroidUnitTest.xml b/framework/tests/AndroidUnitTest.xml
new file mode 100644
index 0000000..735b0e3
--- /dev/null
+++ b/framework/tests/AndroidUnitTest.xml
@@ -0,0 +1,39 @@
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
+<configuration description="Configuration for FlagManager unit tests">
+    <option name="config-descriptor:metadata" key="component" value="framework" />
+    <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
+    <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.configinfrastructure.apex" />
+
+      <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+    <option name="run-command" value="setenforce 0" />
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="FlagManagerUnitTests.apk" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.os.flagging.test" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+    </test>
+
+
+</configuration>
diff --git a/framework/tests/src/AconfigPackageInternalTests.java b/framework/tests/src/AconfigPackageInternalTests.java
index e6a8db8..5d5d362 100644
--- a/framework/tests/src/AconfigPackageInternalTests.java
+++ b/framework/tests/src/AconfigPackageInternalTests.java
@@ -19,15 +19,15 @@ package android.os.flagging.test;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertThrows;
 
-import android.aconfig.DeviceProtos;
+import android.aconfig.DeviceProtosTestUtil;
 import android.aconfig.nano.Aconfig;
 import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.storage.AconfigStorageException;
 import android.aconfig.storage.FlagTable;
 import android.aconfig.storage.FlagValueList;
 import android.aconfig.storage.PackageTable;
 import android.aconfig.storage.StorageFileProvider;
 import android.os.flagging.AconfigPackageInternal;
-import android.os.flagging.AconfigStorageReadException;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -42,7 +42,7 @@ import java.util.Map;
 public class AconfigPackageInternalTests {
     @Test
     public void testAconfigPackageInternal_load() throws IOException {
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         Map<String, AconfigPackageInternal> readerMap = new HashMap<>();
         StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
 
@@ -67,7 +67,7 @@ public class AconfigPackageInternalTests {
 
             AconfigPackageInternal reader = readerMap.get(packageName);
             if (reader == null) {
-                reader = AconfigPackageInternal.load(container, packageName, fingerprint);
+                reader = AconfigPackageInternal.load(packageName, fingerprint);
                 readerMap.put(packageName, reader);
             }
             boolean jVal = reader.getBooleanFlagValue(fNode.getFlagIndex());
@@ -77,30 +77,22 @@ public class AconfigPackageInternalTests {
     }
 
     @Test
-    public void testAconfigPackage_load_withError() throws IOException {
-        // container not found fake_container
-        AconfigStorageReadException e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () -> AconfigPackageInternal.load("fake_container", "fake_package", 0));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-
+    public void testAconfigPackageInternal_load_withError() throws IOException {
         // package not found
-        e =
+        AconfigStorageException e =
                 assertThrows(
-                        AconfigStorageReadException.class,
-                        () -> AconfigPackageInternal.load("system", "fake_container", 0));
-        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+                        AconfigStorageException.class,
+                        () -> AconfigPackageInternal.load("fake_package", 0));
+        assertEquals(AconfigStorageException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
 
         // fingerprint doesn't match
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
 
         parsed_flag flag = flags.get(0);
 
         String container = flag.container;
         String packageName = flag.package_;
-        boolean value = flag.state == Aconfig.ENABLED;
 
         PackageTable pTable = fp.getPackageTable(container);
         PackageTable.Node pNode = pTable.get(packageName);
@@ -108,13 +100,9 @@ public class AconfigPackageInternalTests {
             long fingerprint = pNode.getPackageFingerprint();
             e =
                     assertThrows(
-                            AconfigStorageReadException.class,
-                            () ->
-                                    AconfigPackageInternal.load(
-                                            container, packageName, fingerprint + 1));
-            assertEquals(
-                    // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
-                    5, e.getErrorCode());
+                            AconfigStorageException.class,
+                            () -> AconfigPackageInternal.load(packageName, fingerprint + 1));
+            assertEquals(AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH, e.getErrorCode());
         }
     }
 }
diff --git a/framework/tests/src/AconfigPackageTests.java b/framework/tests/src/AconfigPackageTests.java
index 99243d2..45c0fdb 100644
--- a/framework/tests/src/AconfigPackageTests.java
+++ b/framework/tests/src/AconfigPackageTests.java
@@ -17,9 +17,10 @@
 package android.os.flagging.test;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertThrows;
 
-import android.aconfig.DeviceProtos;
+import android.aconfig.DeviceProtosTestUtil;
 import android.aconfig.nano.Aconfig;
 import android.aconfig.nano.Aconfig.parsed_flag;
 import android.aconfig.storage.FlagTable;
@@ -40,9 +41,23 @@ import java.util.Map;
 
 @RunWith(JUnit4.class)
 public class AconfigPackageTests {
+
+    @Test
+    public void testAconfigPackage_StorageFilesCache() throws IOException {
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
+        for (parsed_flag flag : flags) {
+            if (flag.permission == Aconfig.READ_ONLY && flag.state == Aconfig.DISABLED) {
+                continue;
+            }
+            String container = flag.container;
+            String packageName = flag.package_;
+            assertNotNull(AconfigPackage.load(packageName));
+        }
+    }
+
     @Test
     public void testExternalAconfigPackageInstance() throws IOException {
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         Map<String, AconfigPackage> readerMap = new HashMap<>();
         StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
 
diff --git a/framework/tests/src/AconfigPublicApiCtsTests.java b/framework/tests/src/AconfigPublicApiCtsTests.java
new file mode 100644
index 0000000..0237c07
--- /dev/null
+++ b/framework/tests/src/AconfigPublicApiCtsTests.java
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
+package android.os.flagging.test;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.junit.Rule;
+
+import android.os.flagging.AconfigStorageWriteException;
+import android.os.flagging.FlagManager;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.provider.flags.Flags;
+import androidx.test.InstrumentationRegistry;
+
+import java.io.IOException;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+
+@RunWith(JUnit4.class)
+public class AconfigPublicApiCtsTests {
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+    public void testTestProcessCannotCallWriteApis() throws IOException {
+        FlagManager flagManager =
+                InstrumentationRegistry.getInstrumentation()
+                        .getContext()
+                        .getSystemService(FlagManager.class);
+        assertNotEquals(flagManager, null);
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () ->
+                        flagManager.setBooleanOverridesOnSystemBuildFingerprint(
+                                "test_fingerprint", new HashMap()));
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () -> flagManager.setBooleanOverridesOnReboot(new HashMap()));
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () -> flagManager.setBooleanLocalOverridesOnReboot(new HashMap()));
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () -> flagManager.setBooleanLocalOverridesImmediately(new HashMap()));
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () -> flagManager.clearBooleanLocalOverridesImmediately(new HashSet()));
+
+        assertThrows(
+                AconfigStorageWriteException.class,
+                () -> flagManager.clearBooleanLocalOverridesOnReboot(new HashSet()));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+    public void testAconfigStorageWriteException(){
+        // create new instance of AconfigStorageWriteException
+        AconfigStorageWriteException exception =
+            new AconfigStorageWriteException("test message");
+        assertEquals(exception.getMessage(), "test message");
+
+        Exception cause = new Exception("test cause");
+        exception = new AconfigStorageWriteException("test message", cause);
+        assertEquals(exception.getMessage(), "test message");
+        assertEquals(exception.getCause(), cause);
+    }
+}
diff --git a/framework/tests/src/FlagManagerUnitTests.java b/framework/tests/src/FlagManagerUnitTests.java
new file mode 100644
index 0000000..d5c05c6
--- /dev/null
+++ b/framework/tests/src/FlagManagerUnitTests.java
@@ -0,0 +1,75 @@
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
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertTrue;
+
+import android.os.flagging.AconfigPackage;
+import android.os.flagging.FlagManager;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.provider.flags.Flags;
+
+import androidx.test.InstrumentationRegistry;
+
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.IOException;
+import java.util.HashMap;
+import java.util.HashSet;
+
+@RunWith(JUnit4.class)
+public class FlagManagerUnitTests {
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+    public void testSetBooleanLocalOverrideImmediately() throws IOException {
+        FlagManager flagManager =
+                InstrumentationRegistry.getInstrumentation()
+                        .getContext()
+                        .getSystemService(FlagManager.class);
+        assertNotEquals(flagManager, null);
+
+        HashMap<String, Boolean> flagsToValues = new HashMap();
+        flagsToValues.put("android.provider.flags.flag_manager_unit_test_flag", true);
+        flagManager.setBooleanLocalOverridesImmediately(flagsToValues);
+
+        AconfigPackage aconfigPackage = AconfigPackage.load("android.provider.flags");
+        boolean value = aconfigPackage.getBooleanFlagValue("flag_manager_unit_test_flag", false);
+
+        assertTrue(value);
+
+        HashSet<String> flagNames = new HashSet();
+        flagNames.add("android.provider.flags.flag_manager_unit_test_flag");
+        flagManager.clearBooleanLocalOverridesImmediately(flagNames);
+
+        AconfigPackage aconfigPackageAfterClearing = AconfigPackage.load("android.provider.flags");
+        boolean valueAfterClearing =
+                aconfigPackageAfterClearing.getBooleanFlagValue(
+                        "flag_manager_unit_test_flag", false);
+
+        assertFalse(valueAfterClearing);
+    }
+}
diff --git a/service/java/com/android/server/deviceconfig/DeviceConfigInit.java b/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
index 465d241..0f02bdb 100644
--- a/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
+++ b/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
@@ -40,6 +40,7 @@ public class DeviceConfigInit {
 
     private static final String SYSTEM_FLAGS_PATH = "/system/etc/aconfig_flags.pb";
     private static final String SYSTEM_EXT_FLAGS_PATH = "/system_ext/etc/aconfig_flags.pb";
+    private static final String PRODUCT_FLAGS_PATH = "/product/etc/aconfig_flags.pb";
     private static final String VENDOR_FLAGS_PATH = "/vendor/etc/aconfig_flags.pb";
 
     private static final String CONFIGURATION_NAMESPACE = "configuration";
@@ -95,6 +96,7 @@ public class DeviceConfigInit {
                 try {
                     addAconfigFlagsFromFile(aconfigFlags, SYSTEM_FLAGS_PATH);
                     addAconfigFlagsFromFile(aconfigFlags, SYSTEM_EXT_FLAGS_PATH);
+                    addAconfigFlagsFromFile(aconfigFlags, PRODUCT_FLAGS_PATH);
                     addAconfigFlagsFromFile(aconfigFlags, VENDOR_FLAGS_PATH);
                 } catch (IOException e) {
                     Slog.e(TAG, "error loading aconfig flags", e);
```

