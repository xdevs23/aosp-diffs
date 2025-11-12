```diff
diff --git a/aconfigd/src/aconfigd.rs b/aconfigd/src/aconfigd.rs
index a6177b3..e204e7d 100644
--- a/aconfigd/src/aconfigd.rs
+++ b/aconfigd/src/aconfigd.rs
@@ -66,34 +66,19 @@ impl Aconfigd {
         Ok(())
     }
 
-    /// Remove non platform boot storage file copies
-    pub fn remove_non_platform_boot_files(&mut self) -> Result<(), AconfigdError> {
+    /// Remove inactive boot storage file copies
+    pub fn remove_inactive_boot_files(&mut self) -> Result<(), AconfigdError> {
+        let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&self.persist_storage_records)?;
         let boot_dir = self.root_dir.join("boot");
-        for entry in std::fs::read_dir(&boot_dir)
-            .map_err(|errmsg| AconfigdError::FailToReadBootDir { errmsg })?
-        {
-            match entry {
-                Ok(entry) => {
-                    let path = entry.path();
-                    if !path.is_file() {
-                        continue;
-                    }
-                    if let Some(base_name) = path.file_name() {
-                        if let Some(file_name) = base_name.to_str() {
-                            if file_name.starts_with("system")
-                                || file_name.starts_with("system_ext")
-                                || file_name.starts_with("product")
-                                || file_name.starts_with("vendor")
-                            {
-                                continue;
-                            }
-                            remove_file(&path);
-                        }
-                    }
-                }
-                Err(errmsg) => {
-                    warn!("failed to visit entry: {}", errmsg);
-                }
+        for entry in pb.records.iter() {
+            if !Path::new(entry.package_map()).exists()
+                || !Path::new(entry.flag_map()).exists()
+                || !Path::new(entry.flag_val()).exists()
+                || !Path::new(entry.flag_info()).exists()
+            {
+                debug!("remove boot storage files for container {}", entry.container());
+                remove_file(&boot_dir.join(String::from(entry.container()) + ".val"))?;
+                remove_file(&boot_dir.join(String::from(entry.container()) + ".info"))?;
             }
         }
         Ok(())
@@ -101,7 +86,6 @@ impl Aconfigd {
 
     /// Initialize aconfigd from persist storage records
     pub fn initialize_from_storage_record(&mut self) -> Result<(), AconfigdError> {
-        let boot_dir = self.root_dir.join("boot");
         let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&self.persist_storage_records)?;
         for entry in pb.records.iter() {
             self.storage_manager.add_storage_files_from_pb(entry);
@@ -150,11 +134,11 @@ impl Aconfigd {
                 &default_flag_val,
                 &default_flag_info,
             )?;
-
-            self.storage_manager
-                .write_persist_storage_records_to_file(&self.persist_storage_records)?;
         }
 
+        self.storage_manager
+            .write_persist_storage_records_to_file(&self.persist_storage_records)?;
+
         self.storage_manager.apply_staged_ota_flags()?;
 
         for container in ["system", "system_ext", "product", "vendor"] {
@@ -237,12 +221,12 @@ impl Aconfigd {
                 &default_flag_info,
             )?;
 
-            self.storage_manager
-                .write_persist_storage_records_to_file(&self.persist_storage_records)?;
-
             self.storage_manager.apply_all_staged_overrides(container)?;
         }
 
+        self.storage_manager
+            .write_persist_storage_records_to_file(&self.persist_storage_records)?;
+
         Ok(())
     }
 
@@ -1011,6 +995,7 @@ mod tests {
         flag.set_is_readwrite(true);
         flag.set_has_server_override(false);
         flag.set_has_local_override(false);
+        flag.set_has_boot_local_override(false);
         assert_eq!(flags.flags[0], flag);
 
         flag.set_flag_name("enabled_ro".to_string());
@@ -1126,7 +1111,7 @@ mod tests {
         assert!(aconfigd.persist_storage_records.exists());
         let pb = read_pb_from_file::<ProtoPersistStorageRecords>(&aconfigd.persist_storage_records)
             .unwrap();
-        assert_eq!(pb.records.len(), 3);
+        assert_eq!(pb.records.len(), 4);
 
         for container in ["system", "system_ext", "product", "vendor"] {
             let aconfig_dir = PathBuf::from("/".to_string() + container + "/etc/aconfig");
@@ -1154,7 +1139,7 @@ mod tests {
             assert!(local_overrides.exists());
 
             let mut entry = ProtoPersistStorageRecord::new();
-            entry.set_version(1);
+            entry.set_version(2);
             entry.set_container(container.to_string());
             entry.set_package_map(default_package_map.display().to_string());
             entry.set_flag_map(default_flag_map.display().to_string());
diff --git a/aconfigd/src/aconfigd_commands.rs b/aconfigd/src/aconfigd_commands.rs
index 3b8f92d..0007565 100644
--- a/aconfigd/src/aconfigd_commands.rs
+++ b/aconfigd/src/aconfigd_commands.rs
@@ -61,22 +61,15 @@ pub fn start_socket() -> Result<()> {
 /// initialize mainline module storage files
 pub fn init() -> Result<()> {
     let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(STORAGE_RECORDS));
-    aconfigd.remove_boot_files()?;
-
-    // One time clean up to remove the boot value and info file for mainline modules
-    // that are not in the pb records file. For those mainline modules already in the
-    // records pb file, the above code should remove their boot copy already. Here
-    // we add additional enforcement to ensure that we clear up all mainline boot
-    // copies, regardless if a mainline module is in records or not.
-    // NOTE: this is a one time operation to be removed once the flag is finalized.
-    // as we will add the second change that block boot copy from inactive container
-    // to be generated in the first place.
-    if aconfig_new_storage_flags::bluetooth_flag_value_bug_fix() {
-        aconfigd.remove_non_platform_boot_files()?
+    if !aconfig_new_storage_flags::optimize_boot_copy_creation() {
+        aconfigd.remove_boot_files()?;
     }
-
     aconfigd.initialize_from_storage_record()?;
     aconfigd.initialize_mainline_storage()?;
+    if aconfig_new_storage_flags::optimize_boot_copy_creation() {
+        aconfigd.remove_inactive_boot_files()?;
+    }
+
     Ok(())
 }
 
diff --git a/aconfigd/src/lib.rs b/aconfigd/src/lib.rs
index 865ca71..7f73c87 100644
--- a/aconfigd/src/lib.rs
+++ b/aconfigd/src/lib.rs
@@ -128,6 +128,12 @@ pub enum AconfigdError {
     #[error("fail to get metadata of file {}: {:?}", .file, .errmsg)]
     FailToGetFileMetadata { file: String, errmsg: std::io::Error },
 
+    #[error("fail to get last modified time of file {}: {:?}", .file, .errmsg)]
+    FailToGetFileModifiedTime { file: String, errmsg: std::io::Error },
+
+    #[error("fail to get system time duration since epoch for file {}: {:?}", .file, .errmsg)]
+    FailToGetSystemTimeDuration { file: String, errmsg: std::time::SystemTimeError },
+
     #[error("fail to read /apex dir: {:?}", .errmsg)]
     FailToReadApexDir { errmsg: std::io::Error },
 
diff --git a/aconfigd/src/storage_files.rs b/aconfigd/src/storage_files.rs
index 81b001e..3d6d01c 100644
--- a/aconfigd/src/storage_files.rs
+++ b/aconfigd/src/storage_files.rs
@@ -15,8 +15,8 @@
  */
 
 use crate::utils::{
-    copy_file, copy_file_without_fsync, get_files_digest, read_pb_from_file, remove_file,
-    write_pb_to_file,
+    copy_file, copy_file_without_fsync, get_file_mtime, get_files_digest, read_pb_from_file,
+    remove_file, write_pb_to_file,
 };
 use crate::AconfigdError;
 use aconfig_storage_file::{
@@ -562,6 +562,7 @@ impl StorageFiles {
                         value: value.to_string(),
                     });
                 }
+
                 set_boolean_flag_value(file, context.flag_index, value == "true").map_err(
                     |errmsg| AconfigdError::FailToSetFlagValue {
                         flag: context.package.to_string() + "." + &context.flag,
@@ -625,10 +626,21 @@ impl StorageFiles {
         }
 
         let flag_val_file = self.get_persist_flag_val()?;
-        Self::set_flag_value_to_file(flag_val_file, context, value)?;
+        let current_value =
+            get_boolean_flag_value(flag_val_file, context.flag_index).map_err(|errmsg| {
+                AconfigdError::FailToGetFlagValue {
+                    flag: context.package.to_string() + "." + &context.flag,
+                    errmsg,
+                }
+            })?;
+        if current_value != (value == "true") {
+            Self::set_flag_value_to_file(flag_val_file, context, value)?;
+        }
 
-        let flag_info_file = self.get_persist_flag_info()?;
-        Self::set_flag_has_server_override_to_file(flag_info_file, context, true)?;
+        if (attribute & FlagInfoBit::HasServerOverride as u8) == 0 {
+            let flag_info_file = self.get_persist_flag_info()?;
+            Self::set_flag_has_server_override_to_file(flag_info_file, context, true)?;
+        }
 
         Ok(())
     }
@@ -651,28 +663,37 @@ impl StorageFiles {
             });
         }
 
-        let mut exist = false;
         let mut pb =
             read_pb_from_file::<ProtoLocalFlagOverrides>(&self.storage_record.local_overrides)?;
-        for entry in &mut pb.overrides {
-            if entry.package_name() == context.package && entry.flag_name() == context.flag {
-                entry.set_flag_value(String::from(value));
-                exist = true;
-                break;
+        match pb.overrides.iter_mut().find(|entry| {
+            entry.package_name() == context.package && entry.flag_name() == context.flag
+        }) {
+            Some(entry) => {
+                if entry.flag_value() != value {
+                    entry.set_flag_value(String::from(value));
+                    write_pb_to_file::<ProtoLocalFlagOverrides>(
+                        &pb,
+                        &self.storage_record.local_overrides,
+                    )?;
+                }
+            }
+            None => {
+                let mut new_entry = ProtoFlagOverride::new();
+                new_entry.set_package_name(context.package.clone());
+                new_entry.set_flag_name(context.flag.clone());
+                new_entry.set_flag_value(String::from(value));
+                pb.overrides.push(new_entry);
+                write_pb_to_file::<ProtoLocalFlagOverrides>(
+                    &pb,
+                    &self.storage_record.local_overrides,
+                )?;
             }
         }
-        if !exist {
-            let mut new_entry = ProtoFlagOverride::new();
-            new_entry.set_package_name(context.package.clone());
-            new_entry.set_flag_name(context.flag.clone());
-            new_entry.set_flag_value(String::from(value));
-            pb.overrides.push(new_entry);
-        }
-
-        write_pb_to_file::<ProtoLocalFlagOverrides>(&pb, &self.storage_record.local_overrides)?;
 
-        let flag_info_file = self.get_persist_flag_info()?;
-        Self::set_flag_has_local_override_to_file(flag_info_file, context, true)?;
+        if (attribute & FlagInfoBit::HasLocalOverride as u8) == 0 {
+            let flag_info_file = self.get_persist_flag_info()?;
+            Self::set_flag_has_local_override_to_file(flag_info_file, context, true)?;
+        }
 
         Ok(())
     }
@@ -712,8 +733,38 @@ impl StorageFiles {
         Ok(())
     }
 
+    /// Check if current boot files can be reused
+    fn reuse_boot_storage_files(&self) -> Result<bool, AconfigdError> {
+        if !self.storage_record.boot_flag_val.exists()
+            || !self.storage_record.boot_flag_info.exists()
+        {
+            return Ok(false);
+        }
+
+        let persist_mtime = *[
+            get_file_mtime(&self.storage_record.persist_flag_val)?,
+            get_file_mtime(&self.storage_record.persist_flag_info)?,
+            get_file_mtime(&self.storage_record.local_overrides)?,
+        ]
+        .iter()
+        .max()
+        .unwrap();
+
+        let boot_mtime = std::cmp::min(
+            get_file_mtime(&self.storage_record.boot_flag_val)?,
+            get_file_mtime(&self.storage_record.boot_flag_info)?,
+        );
+
+        Ok(boot_mtime > persist_mtime)
+    }
+
     /// Apply both server and local overrides
     pub(crate) fn apply_all_staged_overrides(&mut self) -> Result<(), AconfigdError> {
+        if self.reuse_boot_storage_files()? {
+            debug!("reuse boot storage files for container {}", &self.storage_record.container);
+            return Ok(());
+        }
+
         debug!("apply staged server overrides for container {}", &self.storage_record.container);
         copy_file_without_fsync(
             &self.storage_record.persist_flag_val,
@@ -1090,6 +1141,7 @@ impl StorageFiles {
 mod tests {
     use super::*;
     use crate::test_utils::{has_same_content, ContainerMock, StorageRootDirMock};
+    use crate::utils::get_file_mtime;
     use aconfig_storage_file::StoredFlagType;
 
     fn create_mock_storage_files(
@@ -1383,6 +1435,18 @@ mod tests {
         assert_eq!(&storage_files.get_server_flag_value(&context).unwrap(), "false");
         let attribute = storage_files.get_flag_attribute(&context).unwrap();
         assert!(attribute & (FlagInfoBit::HasServerOverride as u8) != 0);
+
+        let val_metadata = std::fs::metadata(&storage_files.storage_record.boot_flag_val).unwrap();
+        let info_metadata =
+            std::fs::metadata(&storage_files.storage_record.boot_flag_info).unwrap();
+        let val_mtime = val_metadata.modified().unwrap();
+        let info_mtime = info_metadata.modified().unwrap();
+        storage_files.stage_server_override(&context, "false").unwrap();
+        let val_metadata = std::fs::metadata(&storage_files.storage_record.boot_flag_val).unwrap();
+        let info_metadata =
+            std::fs::metadata(&storage_files.storage_record.boot_flag_info).unwrap();
+        assert_eq!(val_mtime, val_metadata.modified().unwrap());
+        assert_eq!(info_mtime, info_metadata.modified().unwrap());
     }
 
     #[test]
@@ -1397,6 +1461,25 @@ mod tests {
         assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "false");
         let attribute = storage_files.get_flag_attribute(&context).unwrap();
         assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) != 0);
+
+        storage_files.stage_local_override(&context, "true").unwrap();
+        assert_eq!(&storage_files.get_local_flag_value(&context).unwrap(), "true");
+        let attribute = storage_files.get_flag_attribute(&context).unwrap();
+        assert!(attribute & (FlagInfoBit::HasLocalOverride as u8) != 0);
+
+        let val_metadata =
+            std::fs::metadata(&storage_files.storage_record.local_overrides).unwrap();
+        let info_metadata =
+            std::fs::metadata(&storage_files.storage_record.boot_flag_info).unwrap();
+        let val_mtime = val_metadata.modified().unwrap();
+        let info_mtime = info_metadata.modified().unwrap();
+        storage_files.stage_local_override(&context, "true").unwrap();
+        let val_metadata =
+            std::fs::metadata(&storage_files.storage_record.local_overrides).unwrap();
+        let info_metadata =
+            std::fs::metadata(&storage_files.storage_record.boot_flag_info).unwrap();
+        assert_eq!(val_mtime, val_metadata.modified().unwrap());
+        assert_eq!(info_mtime, info_metadata.modified().unwrap());
     }
 
     #[test]
@@ -1438,6 +1521,42 @@ mod tests {
 
         assert_eq!(storage_files.get_boot_flag_value(&context_one).unwrap(), "false");
         assert_eq!(storage_files.get_boot_flag_value(&context_two).unwrap(), "true");
+
+        // reuse boot file case 1: reuse
+        let boot_val_mtime = get_file_mtime(&storage_files.storage_record.boot_flag_val).unwrap();
+        let boot_info_mtime = get_file_mtime(&storage_files.storage_record.boot_flag_info).unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+        assert_eq!(
+            boot_val_mtime,
+            get_file_mtime(&storage_files.storage_record.boot_flag_val).unwrap()
+        );
+        assert_eq!(
+            boot_info_mtime,
+            get_file_mtime(&storage_files.storage_record.boot_flag_info).unwrap()
+        );
+
+        // reuse boot file case 2: persist file is newer, do not reuse
+        let f = std::fs::File::open(&storage_files.storage_record.persist_flag_val).unwrap();
+        f.set_modified(std::time::SystemTime::now()).unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+        let new_boot_val_mtime =
+            get_file_mtime(&storage_files.storage_record.boot_flag_val).unwrap();
+        let new_boot_info_mtime =
+            get_file_mtime(&storage_files.storage_record.boot_flag_info).unwrap();
+        assert!(new_boot_val_mtime > boot_val_mtime);
+        assert!(new_boot_info_mtime > boot_info_mtime);
+
+        // reuse boot file case 3: no boot file
+        remove_file(&storage_files.storage_record.boot_flag_val).unwrap();
+        storage_files.apply_all_staged_overrides().unwrap();
+        assert!(
+            get_file_mtime(&storage_files.storage_record.boot_flag_val).unwrap()
+                > new_boot_val_mtime
+        );
+        assert!(
+            get_file_mtime(&storage_files.storage_record.boot_flag_info).unwrap()
+                > new_boot_info_mtime
+        );
     }
 
     #[test]
@@ -1655,7 +1774,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
-            has_boot_local_override: false,
+            has_boot_local_override: true,
         };
         assert_eq!(flags[0], flag);
 
@@ -1736,7 +1855,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
-            has_boot_local_override: false,
+            has_boot_local_override: true,
         };
         assert_eq!(flags[3], flag);
     }
diff --git a/aconfigd/src/storage_files_manager.rs b/aconfigd/src/storage_files_manager.rs
index 8fc890d..ac724ee 100644
--- a/aconfigd/src/storage_files_manager.rs
+++ b/aconfigd/src/storage_files_manager.rs
@@ -61,22 +61,15 @@ impl StorageFilesManager {
             return Ok(());
         }
 
-        if aconfig_new_storage_flags::bluetooth_flag_value_bug_fix() {
-            // Only create storage file object if the container is active. This is to
-            // ensure that for inactive containers, the storage files object will not
-            // be created and thus their boot copy will not be produced. And thus we
-            // can prevent them from being used.
-            if PathBuf::from(pb.package_map()).exists()
-                && PathBuf::from(pb.flag_map()).exists()
-                && PathBuf::from(pb.flag_val()).exists()
-                && PathBuf::from(pb.flag_info()).exists()
-            {
-                self.all_storage_files.insert(
-                    String::from(pb.container()),
-                    StorageFiles::from_pb(pb, &self.root_dir)?,
-                );
-            }
-        } else {
+        // Only create storage file object if the container is active. This is to
+        // ensure that for inactive containers, the storage files object will not
+        // be created and thus their boot copy will not be produced. And thus we
+        // can prevent them from being used.
+        if PathBuf::from(pb.package_map()).exists()
+            && PathBuf::from(pb.flag_map()).exists()
+            && PathBuf::from(pb.flag_val()).exists()
+            && PathBuf::from(pb.flag_info()).exists()
+        {
             self.all_storage_files
                 .insert(String::from(pb.container()), StorageFiles::from_pb(pb, &self.root_dir)?);
         }
@@ -1185,7 +1178,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
-            has_boot_local_override: false,
+            has_boot_local_override: true,
         };
         assert_eq!(flags[0], flag);
 
@@ -1258,7 +1251,7 @@ mod tests {
             is_readwrite: true,
             has_server_override: true,
             has_local_override: true,
-            has_boot_local_override: false,
+            has_boot_local_override: true,
         };
         assert_eq!(flags[0], flag);
     }
diff --git a/aconfigd/src/utils.rs b/aconfigd/src/utils.rs
index 7370ee6..2597a55 100644
--- a/aconfigd/src/utils.rs
+++ b/aconfigd/src/utils.rs
@@ -20,6 +20,7 @@ use std::fs::File;
 use std::io::Read;
 use std::os::unix::fs::PermissionsExt;
 use std::path::Path;
+use std::time::{SystemTime, UNIX_EPOCH};
 
 /// Set file permission
 pub(crate) fn set_file_permission(file: &Path, mode: u32) -> Result<(), AconfigdError> {
@@ -173,6 +174,21 @@ pub(crate) fn get_files_digest(paths: &[&Path]) -> Result<String, AconfigdError>
     Ok(xdigest)
 }
 
+/// Get file last modified time (macro seconds) with respect to UNIX_EPOCH
+pub(crate) fn get_file_mtime(file: &Path) -> Result<u128, AconfigdError> {
+    let metadata = std::fs::metadata(file).map_err(|errmsg| {
+        AconfigdError::FailToGetFileMetadata { file: file.display().to_string(), errmsg }
+    })?;
+    let mtime = metadata.modified().map_err(|errmsg| AconfigdError::FailToGetFileModifiedTime {
+        file: file.display().to_string(),
+        errmsg,
+    })?;
+    let duration = mtime.duration_since(UNIX_EPOCH).map_err(|errmsg| {
+        AconfigdError::FailToGetSystemTimeDuration { file: file.display().to_string(), errmsg }
+    })?;
+    Ok(duration.as_nanos())
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
diff --git a/aflags/Android.bp b/aflags/Android.bp
index ff74350..7e28974 100644
--- a/aflags/Android.bp
+++ b/aflags/Android.bp
@@ -33,8 +33,10 @@ rust_binary {
     min_sdk_version: "34",
 }
 
-rust_test_host {
+rust_test {
     name: "aflags_updatable.test",
     defaults: ["aflags_updatable.defaults"],
+    rustlibs: ["librand"],
     test_suites: ["general-tests"],
+    require_root: true
 }
diff --git a/aflags/Cargo.toml b/aflags/Cargo.toml
index 794eb54..e66dbd2 100644
--- a/aflags/Cargo.toml
+++ b/aflags/Cargo.toml
@@ -16,3 +16,8 @@ aconfig_storage_read_api = { version = "0.1.0", path = "../../../../build/make/t
 clap = {version = "4.5.2" }
 aconfig_device_paths = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_device_paths" }
 aconfig_flags = { version = "0.1.0", path = "../../../../build/make/tools/aconfig/aconfig_flags" }
+rand = "0.9.1"
+
+[features]
+default = ["cargo"]
+cargo = []
diff --git a/aflags/src/aconfig_storage_source.rs b/aflags/src/aconfig_storage_source.rs
index d9370de..dc6cfc3 100644
--- a/aflags/src/aconfig_storage_source.rs
+++ b/aflags/src/aconfig_storage_source.rs
@@ -1,6 +1,6 @@
 use crate::load_protos;
 use crate::{Flag, FlagSource};
-use crate::{FlagPermission, FlagValue, ValuePickedFrom};
+use crate::{FlagPermission, FlagStorageBackend, FlagValue, ValuePickedFrom};
 use aconfigd_protos::{
     ProtoFlagOverrideMessage, ProtoFlagOverrideType, ProtoFlagQueryReturnMessage,
     ProtoListStorageMessage, ProtoListStorageMessageMsg, ProtoRemoveLocalOverrideMessage,
@@ -104,6 +104,7 @@ fn convert(msg: ProtoFlagQueryReturnMessage, containers: &HashMap<String, String
             .to_string(),
         // TODO: remove once DeviceConfig is not in the CLI.
         namespace: "-".to_string(),
+        storage_backend: FlagStorageBackend::Unspecified,
     })
 }
 
@@ -223,7 +224,13 @@ impl FlagSource for AconfigStorageSource {
             socket_flags?.into_iter().map(|p| (p.qualified_name(), p)).collect();
         flags.iter_mut().for_each(|flag| {
             if let Some(socket_flag) = name_to_socket_flag.get(&flag.qualified_name()) {
+                // socket flags do not contain storage backend and namespace  information,
+                // copy these fields and assign back
+                let namespace = flag.namespace.clone();
+                let storage_backend = flag.storage_backend.clone();
                 *flag = socket_flag.clone();
+                flag.storage_backend = storage_backend;
+                flag.namespace = namespace;
             }
         });
 
diff --git a/aflags/src/device_config_source.rs b/aflags/src/device_config_source.rs
new file mode 100644
index 0000000..6476ad5
--- /dev/null
+++ b/aflags/src/device_config_source.rs
@@ -0,0 +1,157 @@
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
+use crate::{Flag, FlagSource, FlagValue};
+
+use anyhow::{anyhow, bail, Result};
+use regex::Regex;
+use std::collections::HashMap;
+use std::process::Command;
+use std::str;
+
+pub struct DeviceConfigSource {}
+
+#[allow(dead_code)]
+pub(crate) fn parse_device_config_output(raw: &str) -> Result<HashMap<String, FlagValue>> {
+    let mut flags = HashMap::new();
+    let regex = Regex::new(r"(?m)^([[[:alnum:]]:_/\.]+)=(true|false)$")?;
+    for capture in regex.captures_iter(raw) {
+        let key =
+            capture.get(1).ok_or(anyhow!("invalid device_config output"))?.as_str().to_string();
+        let value = FlagValue::try_from(
+            capture.get(2).ok_or(anyhow!("invalid device_config output"))?.as_str(),
+        )?;
+        flags.insert(key, value);
+    }
+    Ok(flags)
+}
+
+pub(crate) fn execute_device_config_command(command: &[&str]) -> Result<String> {
+    let output = Command::new("/system/bin/device_config").args(command).output()?;
+    if !output.status.success() {
+        let reason = match output.status.code() {
+            Some(code) => {
+                let output = str::from_utf8(&output.stdout)?;
+                if !output.is_empty() {
+                    format!("exit code {code}, output was {output}")
+                } else {
+                    format!("exit code {code}")
+                }
+            }
+            None => "terminated by signal".to_string(),
+        };
+        bail!("failed to access flag storage: {}", reason);
+    }
+    Ok(str::from_utf8(&output.stdout)?.to_string())
+}
+
+impl FlagSource for DeviceConfigSource {
+    fn list_flags() -> Result<Vec<Flag>> {
+        Err(anyhow!("new storage should be source of truth"))
+    }
+
+    fn override_flag(
+        namespace: &str,
+        qualified_name: &str,
+        value: &str,
+        _immediate: bool,
+    ) -> Result<()> {
+        // device config override command always immediate change the boot value
+        execute_device_config_command(&["override", namespace, qualified_name, value]).map(|_| ())
+    }
+
+    fn unset_flag(namespace: &str, qualified_name: &str, _immediate: bool) -> Result<()> {
+        // device config clear_override command always clear the boot value as well
+        execute_device_config_command(&["clear_override", namespace, qualified_name]).map(|_| ())
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use rand::Rng;
+
+    #[test]
+    fn test_parse_device_config_output() {
+        let input = r#"
+namespace_one/com.foo.bar.flag_one=true
+com.foo.bar.flag_two=false
+random_noise;
+namespace_two:android.flag_one=true
+android.flag_two=nonsense
+"#;
+        let expected = HashMap::from([
+            ("namespace_one/com.foo.bar.flag_one".to_string(), FlagValue::Enabled),
+            ("com.foo.bar.flag_two".to_string(), FlagValue::Disabled),
+            ("namespace_two:android.flag_one".to_string(), FlagValue::Enabled),
+        ]);
+        let actual = parse_device_config_output(input).unwrap();
+        assert_eq!(expected, actual);
+    }
+
+    #[test]
+    #[cfg(not(feature = "cargo"))]
+    fn test_override_flag() {
+        let mut rng = rand::thread_rng();
+        let namespace = rng.gen::<u32>().to_string();
+        DeviceConfigSource::override_flag(
+            &namespace,
+            "aflags_test_package.aflags_test_flag",
+            "false",
+            false,
+        )
+        .unwrap();
+
+        let result = execute_device_config_command(&["list", &namespace]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        let flag_value = flags.get("aflags_test_package.aflags_test_flag").unwrap();
+        assert_eq!(*flag_value, FlagValue::Disabled);
+
+        let result = execute_device_config_command(&["list", "device_config_overrides"]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        println!("{:?}", flags);
+        let flag_value =
+            flags.get(&format!("{namespace}:aflags_test_package.aflags_test_flag")).unwrap();
+        assert_eq!(*flag_value, FlagValue::Disabled);
+
+        DeviceConfigSource::unset_flag(&namespace, "aflags_test_package.aflags_test_flag", false)
+            .unwrap();
+    }
+
+    #[test]
+    #[cfg(not(feature = "cargo"))]
+    fn test_unset_flag() {
+        let mut rng = rand::thread_rng();
+        let namespace = rng.gen::<u32>().to_string();
+        DeviceConfigSource::override_flag(
+            &namespace,
+            "aflags_test_package.aflags_test_flag",
+            "false",
+            false,
+        )
+        .unwrap();
+        DeviceConfigSource::unset_flag(&namespace, "aflags_test_package.aflags_test_flag", false)
+            .unwrap();
+
+        let result = execute_device_config_command(&["list", &namespace]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key("aflags_test_package.aflags_test_flag"));
+
+        let result = execute_device_config_command(&["list", "device_config_overrides"]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key(&format!("{namespace}:aflags_test_package.aflags_test_flag")));
+    }
+}
diff --git a/aflags/src/load_protos.rs b/aflags/src/load_protos.rs
index c5ac8ff..93d14cf 100644
--- a/aflags/src/load_protos.rs
+++ b/aflags/src/load_protos.rs
@@ -1,6 +1,7 @@
-use crate::{Flag, FlagPermission, FlagValue, ValuePickedFrom};
+use crate::{Flag, FlagPermission, FlagStorageBackend, FlagValue, ValuePickedFrom};
 use aconfig_protos::ProtoFlagPermission as ProtoPermission;
 use aconfig_protos::ProtoFlagState as ProtoState;
+use aconfig_protos::ProtoFlagStorageBackend;
 use aconfig_protos::ProtoParsedFlag;
 use aconfig_protos::ProtoParsedFlags;
 use anyhow::Result;
@@ -34,6 +35,13 @@ fn convert_parsed_flag(path: &Path, flag: &ProtoParsedFlag) -> Flag {
         ProtoPermission::READ_WRITE => FlagPermission::ReadWrite,
     };
 
+    let storage_backend = match flag.metadata.storage() {
+        ProtoFlagStorageBackend::NONE => FlagStorageBackend::None,
+        ProtoFlagStorageBackend::ACONFIGD => FlagStorageBackend::Aconfigd,
+        ProtoFlagStorageBackend::DEVICE_CONFIG => FlagStorageBackend::DeviceConfig,
+        ProtoFlagStorageBackend::UNSPECIFIED => FlagStorageBackend::Unspecified,
+    };
+
     Flag {
         namespace,
         package,
@@ -43,6 +51,7 @@ fn convert_parsed_flag(path: &Path, flag: &ProtoParsedFlag) -> Flag {
         staged_value: None,
         permission,
         value_picked_from: ValuePickedFrom::Default,
+        storage_backend,
     }
 }
 
diff --git a/aflags/src/main.rs b/aflags/src/main.rs
index e18c0eb..fadf81f 100644
--- a/aflags/src/main.rs
+++ b/aflags/src/main.rs
@@ -20,7 +20,9 @@ use anyhow::{anyhow, ensure, Result};
 use clap::Parser;
 
 mod aconfig_storage_source;
+mod device_config_source;
 use aconfig_storage_source::AconfigStorageSource;
+use device_config_source::DeviceConfigSource;
 
 mod load_protos;
 
@@ -50,6 +52,14 @@ enum ValuePickedFrom {
     Local,
 }
 
+#[derive(Clone, Debug, PartialEq)]
+enum FlagStorageBackend {
+    Unspecified,
+    None,
+    Aconfigd,
+    DeviceConfig,
+}
+
 impl std::fmt::Display for ValuePickedFrom {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         write!(
@@ -105,6 +115,7 @@ struct Flag {
     staged_value: Option<FlagValue>,
     permission: FlagPermission,
     value_picked_from: ValuePickedFrom,
+    storage_backend: FlagStorageBackend,
 }
 
 impl Flag {
@@ -132,10 +143,6 @@ trait FlagSource {
     fn unset_flag(namespace: &str, qualified_name: &str, immediate: bool) -> Result<()>;
 }
 
-enum FlagSourceType {
-    AconfigStorage,
-}
-
 const ABOUT_TEXT: &str = "Tool for reading and writing flags.
 
 Rows in the table from the `list` command follow this format:
@@ -262,24 +269,45 @@ fn format_flag_row(flag: &Flag, info: &PaddingInfo) -> String {
     )
 }
 
-fn set_flag(qualified_name: &str, value: &str, immediate: bool) -> Result<()> {
+fn get_flag(qualified_name: &str) -> Result<Flag> {
     let flags_binding = AconfigStorageSource::list_flags()?;
     let flag = flags_binding.iter().find(|f| f.qualified_name() == qualified_name).ok_or(
         anyhow!("no aconfig flag '{qualified_name}'. Does the flag have an .aconfig definition?"),
     )?;
+    Ok(flag.clone())
+}
 
-    ensure!(flag.permission == FlagPermission::ReadWrite,
-            format!("could not write flag '{qualified_name}', it is read-only for the current release configuration."));
-
-    AconfigStorageSource::override_flag(&flag.namespace, qualified_name, value, immediate)?;
+fn set_flag(flag: &Flag, value: &str, immediate: bool) -> Result<()> {
+    ensure!(
+        flag.permission == FlagPermission::ReadWrite,
+        format!(
+            "could not write flag '{}', it is read-only for the current release configuration.",
+            flag.qualified_name()
+        )
+    );
+
+    AconfigStorageSource::override_flag(&flag.namespace, &flag.qualified_name(), value, immediate)?;
+    if flag.storage_backend == FlagStorageBackend::DeviceConfig {
+        DeviceConfigSource::override_flag(
+            &flag.namespace,
+            &flag.qualified_name(),
+            value,
+            immediate,
+        )?;
+    }
+    Ok(())
+}
 
+fn unset(flag: &Flag, immediate: bool) -> Result<()> {
+    AconfigStorageSource::unset_flag(&flag.namespace, &flag.qualified_name(), immediate)?;
+    if flag.storage_backend == FlagStorageBackend::DeviceConfig {
+        DeviceConfigSource::unset_flag(&flag.namespace, &flag.qualified_name(), immediate)?;
+    }
     Ok(())
 }
 
-fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String> {
-    let flags_unfiltered = match source_type {
-        FlagSourceType::AconfigStorage => AconfigStorageSource::list_flags()?,
-    };
+fn list(container: Option<String>) -> Result<String> {
+    let flags_unfiltered = AconfigStorageSource::list_flags()?;
 
     if let Some(ref c) = container {
         ensure!(
@@ -317,31 +345,25 @@ fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String
     Ok(result)
 }
 
-fn unset(qualified_name: &str, immediate: bool) -> Result<()> {
-    let flags_binding = AconfigStorageSource::list_flags()?;
-    let flag = flags_binding.iter().find(|f| f.qualified_name() == qualified_name).ok_or(
-        anyhow!("no aconfig flag '{qualified_name}'. Does the flag have an .aconfig definition?"),
-    )?;
-
-    AconfigStorageSource::unset_flag(&flag.namespace, qualified_name, immediate)
-}
-
 fn main() -> Result<()> {
     ensure!(nix::unistd::Uid::current().is_root(), "must be root");
 
     let cli = Cli::parse();
     let output = match cli.command {
-        Command::List { container } => list(FlagSourceType::AconfigStorage, container)
-            .map_err(|err| anyhow!("could not list flags: {err}"))
-            .map(Some),
+        Command::List { container } => {
+            list(container).map_err(|err| anyhow!("could not list flags: {err}")).map(Some)
+        }
         Command::Enable { qualified_name, immediate } => {
-            set_flag(&qualified_name, "true", immediate).map(|_| None)
+            let flag = get_flag(&qualified_name)?;
+            set_flag(&flag, "true", immediate).map(|_| None)
         }
         Command::Disable { qualified_name, immediate } => {
-            set_flag(&qualified_name, "false", immediate).map(|_| None)
+            let flag = get_flag(&qualified_name)?;
+            set_flag(&flag, "false", immediate).map(|_| None)
         }
         Command::Unset { qualified_name, immediate } => {
-            unset(&qualified_name, immediate).map(|_| None)
+            let flag = get_flag(&qualified_name)?;
+            unset(&flag, immediate).map(|_| None)
         }
     };
     match output {
@@ -356,6 +378,9 @@ fn main() -> Result<()> {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use crate::device_config_source::execute_device_config_command;
+    use crate::device_config_source::parse_device_config_output;
+    use rand::Rng;
 
     #[test]
     fn test_filter_container() {
@@ -369,6 +394,7 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
             Flag {
                 namespace: "namespace".to_string(),
@@ -379,6 +405,7 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "not_system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
             Flag {
                 namespace: "namespace".to_string(),
@@ -389,6 +416,7 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
         ];
 
@@ -407,6 +435,7 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
             Flag {
                 namespace: "namespace".to_string(),
@@ -417,6 +446,7 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "not_system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
             Flag {
                 namespace: "namespace".to_string(),
@@ -427,9 +457,64 @@ mod tests {
                 permission: FlagPermission::ReadWrite,
                 value_picked_from: ValuePickedFrom::Default,
                 container: "system".to_string(),
+                storage_backend: FlagStorageBackend::Aconfigd,
             },
         ];
 
         assert_eq!((Filter { container: None }).apply(&flags).len(), 3);
     }
+
+    #[test]
+    #[cfg(not(feature = "cargo"))]
+    fn test_set_unset_mainline_beta_flag() {
+        let mut rng = rand::thread_rng();
+        let namespace = rng.gen::<u32>().to_string();
+        let mut flag = Flag {
+            namespace: namespace.clone(),
+            name: String::from("some_flag"),
+            package: String::from("some_package"),
+            container: String::from("system"),
+            value: FlagValue::Disabled,
+            staged_value: None,
+            permission: FlagPermission::ReadWrite,
+            value_picked_from: ValuePickedFrom::Default,
+            storage_backend: FlagStorageBackend::Aconfigd,
+        };
+
+        // negative test to ensure value is not synced over to device config
+        assert!(set_flag(&flag, "false", false).is_ok());
+
+        let result = execute_device_config_command(&["list", &namespace]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key(&String::from("some_package.some_flag")));
+
+        let result = execute_device_config_command(&["list", "device_config_overrides"]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key(&format!("{namespace}:some_package.some_flag")));
+
+        // test setting mainline beta flag
+        flag.storage_backend = FlagStorageBackend::DeviceConfig;
+        assert!(set_flag(&flag, "true", false).is_ok());
+
+        let result = execute_device_config_command(&["list", &namespace]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        let value = flags.get(&String::from("some_package.some_flag")).unwrap();
+        assert_eq!(*value, FlagValue::Enabled);
+
+        let result = execute_device_config_command(&["list", "device_config_overrides"]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        let value = flags.get(&format!("{namespace}:some_package.some_flag")).unwrap();
+        assert_eq!(*value, FlagValue::Enabled);
+
+        // test unset mainline beta flag
+        assert!(unset(&flag, false).is_ok());
+
+        let result = execute_device_config_command(&["list", &namespace]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key(&String::from("some_package.some_flag")));
+
+        let result = execute_device_config_command(&["list", "device_config_overrides"]).unwrap();
+        let flags = parse_device_config_output(&result).unwrap();
+        assert!(!flags.contains_key(&format!("{namespace}:some_package.some_flag")));
+    }
 }
diff --git a/apex/Android.bp b/apex/Android.bp
index aca2a5f..15f3aaa 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -46,6 +46,7 @@ bootclasspath_fragment {
             "android.provider.flags",
             "android.provider.internal.aconfig.storage",
             "android.provider.internal.modules.utils.build",
+            "android.provider.internal.modules.utils.ravenwood",
 
             "android.os.flagging",
             "android.provider.x.android.provider.flags",
@@ -114,6 +115,10 @@ apex {
     apps: [
         "DeviceConfigServiceResources",
     ],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 sdk {
diff --git a/framework/Android.bp b/framework/Android.bp
index 58476b7..5ce43c3 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -49,6 +49,7 @@ java_sdk_library {
         "configinfra_framework_flags_java_lib",
         "modules-utils-build",
         "modules-utils-proto",
+        "modules-utils-ravenwood",
         "aconfig_storage_file_java",
     ],
     aconfig_declarations: [
diff --git a/framework/java/android/os/flagging/AconfigPackage.java b/framework/java/android/os/flagging/AconfigPackage.java
index 4291c4d..67d3ea1 100644
--- a/framework/java/android/os/flagging/AconfigPackage.java
+++ b/framework/java/android/os/flagging/AconfigPackage.java
@@ -29,6 +29,8 @@ import android.annotation.NonNull;
 import android.os.Build;
 import android.util.Log;
 
+import com.android.modules.utils.ravenwood.RavenwoodHelper;
+
 import java.io.Closeable;
 import java.io.File;
 import java.nio.MappedByteBuffer;
@@ -49,14 +51,40 @@ import java.util.Map;
  * of this class should be {@link #load loaded}.
  */
 @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class AconfigPackage {
     private static final String TAG = "AconfigPackage";
-    private static final String MAP_PATH = "/metadata/aconfig/maps/";
-    private static final String BOOT_PATH = "/metadata/aconfig/boot/";
+
+    private static final String MAP_PATH = getStorageRootPath() + "/metadata/aconfig/maps/";
+    private static final String BOOT_PATH =  getStorageRootPath() + "/metadata/aconfig/boot/";
+
     private static final String PMAP_FILE_EXT = ".package.map";
 
+    /** Returns "" on the device side, but on Ravenwood, we use a storage root path. */
+    @android.ravenwood.annotation.RavenwoodReplace
+    private static String getStorageRootPath() {
+        return "";
+    }
+
+    private static String getStorageRootPath$ravenwood() {
+        return RavenwoodHelper.getRavenwoodAconfigStoragePath();
+    }
+
     private static final boolean READ_PLATFORM_FROM_PLATFORM_API =
-            readPlatformFromPlatformApi() && Build.VERSION.SDK_INT > 35;
+            getReadPlatformFromPlatformApi();
+
+    /**
+     * On ravenwood, we don't use {@link PlatformAconfigPackage} and read all the storage files
+     * in the storage directory directly by this class.
+     */
+    @android.ravenwood.annotation.RavenwoodReplace
+    private static boolean getReadPlatformFromPlatformApi() {
+        return readPlatformFromPlatformApi() && Build.VERSION.SDK_INT > 35;
+    }
+
+    private static boolean getReadPlatformFromPlatformApi$ravenwood() {
+        return false; // Don't use PlatformAconfigPackage.
+    }
 
     private FlagTable mFlagTable;
     private FlagValueList mFlagValueList;
diff --git a/framework/java/android/os/flagging/AconfigPackageInternal.java b/framework/java/android/os/flagging/AconfigPackageInternal.java
index e531199..d7644ce 100644
--- a/framework/java/android/os/flagging/AconfigPackageInternal.java
+++ b/framework/java/android/os/flagging/AconfigPackageInternal.java
@@ -39,6 +39,7 @@ import android.compat.annotation.UnsupportedAppUsage;
  *
  * @hide
  */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class AconfigPackageInternal {
 
     private final FlagValueList mFlagValueList;
diff --git a/framework/java/android/os/flagging/AconfigStorageReadException.java b/framework/java/android/os/flagging/AconfigStorageReadException.java
index 999a6f9..549bad7 100644
--- a/framework/java/android/os/flagging/AconfigStorageReadException.java
+++ b/framework/java/android/os/flagging/AconfigStorageReadException.java
@@ -41,6 +41,7 @@ import java.lang.annotation.RetentionPolicy;
  * </ul>
  */
 @FlaggedApi(FLAG_NEW_STORAGE_PUBLIC_API)
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class AconfigStorageReadException extends RuntimeException {
 
     /** Generic error code indicating an unspecified Aconfig Storage error. */
diff --git a/framework/java/android/os/flagging/AconfigStorageWriteException.java b/framework/java/android/os/flagging/AconfigStorageWriteException.java
index 71c88c9..5bbd016 100644
--- a/framework/java/android/os/flagging/AconfigStorageWriteException.java
+++ b/framework/java/android/os/flagging/AconfigStorageWriteException.java
@@ -29,6 +29,7 @@ import android.util.AndroidRuntimeException;
  */
 @SystemApi
 @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class AconfigStorageWriteException extends AndroidRuntimeException {
     @FlaggedApi(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public AconfigStorageWriteException(@NonNull String message) {
diff --git a/framework/java/android/provider/StageOtaFlags.java b/framework/java/android/provider/StageOtaFlags.java
index 09e85b3..249aa18 100644
--- a/framework/java/android/provider/StageOtaFlags.java
+++ b/framework/java/android/provider/StageOtaFlags.java
@@ -34,9 +34,6 @@ import java.util.Map;
 @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
 public final class StageOtaFlags {
     private static String LOG_TAG = "StageOtaFlags";
-    private static final String SOCKET_ADDRESS = "aconfigd_system";
-    private static final String STORAGE_MARKER_FILE_PATH =
-            "/metadata/aconfig/boot/enable_only_new_storage";
 
     /** Aconfig storage is disabled and unavailable for writes. @hide */
     @SystemApi public static final int STATUS_STORAGE_NOT_ENABLED = -1;
diff --git a/framework/java/android/provider/WritableFlags.java b/framework/java/android/provider/WritableFlags.java
index a75de8a..54572f2 100644
--- a/framework/java/android/provider/WritableFlags.java
+++ b/framework/java/android/provider/WritableFlags.java
@@ -136,6 +136,7 @@ final class WritableFlags {
                 "android/system_gesture_exclusion_limit_dp",
                 "app_cloning/cloned_apps_enabled",
                 "app_cloning/enable_app_cloning_building_blocks",
+                "app_compat/appcompat_sysprop_override_pkgs",
                 "app_compat/hidden_api_access_statslog_sampling_rate",
                 "app_compat/hidden_api_log_sampling_rate",
                 "app_compat/hidden_api_statslog_sampling_rate",
@@ -178,8 +179,6 @@ final class WritableFlags {
                 "backup_and_restore/full_backup_write_to_transport_buffer_size_bytes",
                 "battery_saver/enable_night_mode",
                 "battery_saver/location_mode",
-                "biometrics/android.adaptiveauth.enable_adaptive_auth",
-                "biometrics/android.adaptiveauth.report_biometric_auth_attempts",
                 "biometrics/android.hardware.biometrics.add_key_agreement_crypto_object",
                 "biometrics/android.security.clear_strong_auth_on_add_primary_credential",
                 "biometrics/android.security.report_primary_auth_attempts",
@@ -321,6 +320,7 @@ final class WritableFlags {
                 "jobscheduler/conn_transport_batch_threshold",
                 "jobscheduler/enable_api_quotas",
                 "jobscheduler/fc_applied_constraints",
+                "jobscheduler/min_linear_backoff_time_ms",
                 "jobscheduler/min_ready_cpu_only_jobs_count",
                 "jobscheduler/min_ready_non_active_jobs_count",
                 "jobscheduler/qc_allowed_time_per_period_rare_ms",
@@ -379,6 +379,8 @@ final class WritableFlags {
                 "media_tv/android.media.tv.flags.enable_ad_service_fw",
                 "media_tv/android.media.tv.flags.tiaf_v_apis",
                 "media/media_metrics_mode",
+                "media/media_session_calback_fgs_allowlist_duration_ms",
+                "media/media_session_callback_fgs_while_in_use_temp_allow_duration_ms",
                 "media/media_session_temp_user_engaged_duration_ms",
                 "media/player_metrics_app_allowlist",
                 "media/player_metrics_app_blocklist",
@@ -543,6 +545,7 @@ final class WritableFlags {
                 "rollback_boot/rollback_lifetime_in_millis",
                 "rollback/containing",
                 "rollback/enable_rollback_timeout",
+                "rollback/observer_rollback_availability_in_millis",
                 "rollback/watchdog_explicit_health_check_enabled",
                 "rollback/watchdog_request_timeout_millis",
                 "rollback/watchdog_trigger_failure_count",
@@ -575,6 +578,7 @@ final class WritableFlags {
                 "runtime_native/usap_pool_size_max",
                 "runtime_native/usap_pool_size_min",
                 "runtime_native/use_app_image_startup_cache",
+                "serial/android.hardware.serial.flags.enable_serial_api",
                 "settings_stats/boolean_whitelist",
                 "settings_stats/float_whitelist",
                 "settings_stats/GlobalFeature__boolean_whitelist",
@@ -699,6 +703,7 @@ final class WritableFlags {
                 "systemui/use_back_gesture_ml",
                 "systemui/use_unbundled_sharesheet",
                 "systemui/volume_separate_notification",
+                "systemui/widget_events_report_interval_ms",
                 "tare/enable_tare",
                 "telecom/com.android.server.telecom.flags.cache_call_audio_callbacks",
                 "telecom/com.android.server.telecom.flags.get_registered_phone_accounts",
diff --git a/framework/tests/Android.bp b/framework/tests/Android.bp
index f138dbe..fd6aa55 100644
--- a/framework/tests/Android.bp
+++ b/framework/tests/Android.bp
@@ -16,6 +16,26 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+android_ravenwood_test {
+    name: "InternalArrayUtilsTest",
+    srcs: [
+        "src/com/android/internal/util/ArrayUtilsTest.java",
+    ],
+    static_libs: [
+        "androidx.test.rules",
+        "junit",
+        "flag-junit",
+        "modules-utils-arrayutils",
+    ],
+    sdk_version: "module_current",
+    test_suites: [
+        "general-tests",
+        "mts-configinfrastructure",
+    ],
+    team: "trendy_team_android_core_experiments",
+}
+
+// FlagManager isn't supported on Ravenwood, so there's no ravenwood version for it.
 android_test {
     name: "FlagManagerUnitTests",
     srcs: [
@@ -41,34 +61,45 @@ android_test {
     test_config: "AndroidUnitTest.xml",
 }
 
-android_test {
-    name: "AconfigPublicApiCtsTests",
+java_defaults {
+    name: "AconfigPublicApiCtsTests_defaults",
     srcs: [
         "src/AconfigPublicApiCtsTests.java",
     ],
     static_libs: [
-        "aconfig_device_paths_java",
         "androidx.test.rules",
         "aconfig_storage_file_java",
         "configinfra_framework_flags_java_lib",
         "junit",
         "flag-junit",
+        "ravenwood-junit",
     ],
     libs: [
         "framework-configinfrastructure.impl",
     ],
     sdk_version: "module_current",
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
+    team: "trendy_team_android_core_experiments",
+}
+
+android_test {
+    name: "AconfigPublicApiCtsTests",
+    defaults: ["AconfigPublicApiCtsTests_defaults"],
     test_suites: [
         "general-tests",
         "cts",
     ],
-    jarjar_rules: ":framework-configinfrastructure-jarjar",
-    team: "trendy_team_android_core_experiments",
     test_config: "AndroidCtsTest.xml",
 }
 
-android_test {
-    name: "AconfigPackageTests",
+android_ravenwood_test {
+    name: "AconfigPublicApiCtsTestsRavenwood",
+    defaults: ["AconfigPublicApiCtsTests_defaults"],
+    auto_gen_config: true,
+}
+
+java_defaults {
+    name: "AconfigPackageTests_default",
     srcs: [
         "src/AconfigPackageInternalTests.java",
         "src/AconfigPackageTests.java",
@@ -78,14 +109,35 @@ android_test {
         "androidx.test.rules",
         "aconfig_storage_file_java",
         "junit",
+        "ravenwood-junit",
     ],
     libs: [
         "framework-configinfrastructure.impl",
     ],
+    jarjar_rules: ":framework-configinfrastructure-jarjar",
+    team: "trendy_team_android_core_experiments",
+
+    // Commented out for AconfigPackageTestsRavenwood, see below comment.
+    // sdk_version: "module_current",
+}
+
+android_test {
+    name: "AconfigPackageTests",
+    defaults: ["AconfigPackageTests_default"],
     sdk_version: "module_current",
     test_suites: [
         "general-tests",
     ],
-    jarjar_rules: ":framework-configinfrastructure-jarjar",
-    team: "trendy_team_android_core_experiments",
+}
+
+android_ravenwood_test {
+    name: "AconfigPackageTestsRavenwood",
+    defaults: ["AconfigPackageTests_default"],
+    auto_gen_config: true,
+
+    // We can't have a sdk_version here, because aconfig_device_paths_java_util's
+    // sdk_version isn't actually compatible with "module_current".
+    // AconfigPackageTests is using aconfig_device_paths_java_util but
+    // that's allowed because of a soong bug: b/413039369
+    // sdk_version: "module_current",
 }
diff --git a/framework/tests/src/AconfigPublicApiCtsTests.java b/framework/tests/src/AconfigPublicApiCtsTests.java
index 0237c07..6f3a7a6 100644
--- a/framework/tests/src/AconfigPublicApiCtsTests.java
+++ b/framework/tests/src/AconfigPublicApiCtsTests.java
@@ -46,6 +46,7 @@ public class AconfigPublicApiCtsTests {
             DeviceFlagsValueProvider.createCheckFlagsRule();
 
     @Test
+    @android.platform.test.annotations.DisabledOnRavenwood(blockedBy = FlagManager.class)
     @RequiresFlagsEnabled(Flags.FLAG_NEW_STORAGE_PUBLIC_API)
     public void testTestProcessCannotCallWriteApis() throws IOException {
         FlagManager flagManager =
diff --git a/framework/tests/src/com/android/internal/util/ArrayUtilsTest.java b/framework/tests/src/com/android/internal/util/ArrayUtilsTest.java
new file mode 100644
index 0000000..1deea9f
--- /dev/null
+++ b/framework/tests/src/com/android/internal/util/ArrayUtilsTest.java
@@ -0,0 +1,553 @@
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
+package com.android.internal.util.configinfrastructure;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
+import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collections;
+
+/**
+ * Tests for {@link ArrayUtils}
+ */
+@RunWith(AndroidJUnit4.class)
+public class ArrayUtilsTest {
+    @Test
+    public void testContains() throws Exception {
+        final Object A = new Object();
+        final Object B = new Object();
+        final Object C = new Object();
+        final Object D = new Object();
+
+        assertTrue(ArrayUtils.contains(new Object[] { A, B, C }, A));
+        assertTrue(ArrayUtils.contains(new Object[] { A, B, C }, B));
+        assertTrue(ArrayUtils.contains(new Object[] { A, B, C }, C));
+        assertTrue(ArrayUtils.contains(new Object[] { A, null, C }, null));
+
+        assertFalse(ArrayUtils.contains(new Object[] { A, B, C }, null));
+        assertFalse(ArrayUtils.contains(new Object[] { }, null));
+        assertFalse(ArrayUtils.contains(new Object[] { null }, A));
+    }
+
+    @Test
+    public void testIndexOf() throws Exception {
+        final Object A = new Object();
+        final Object B = new Object();
+        final Object C = new Object();
+        final Object D = new Object();
+
+        assertEquals(0, ArrayUtils.indexOf(new Object[] { A, B, C }, A));
+        assertEquals(1, ArrayUtils.indexOf(new Object[] { A, B, C }, B));
+        assertEquals(2, ArrayUtils.indexOf(new Object[] { A, B, C }, C));
+        assertEquals(-1, ArrayUtils.indexOf(new Object[] { A, B, C }, D));
+
+        assertEquals(-1, ArrayUtils.indexOf(new Object[] { A, B, C }, null));
+        assertEquals(-1, ArrayUtils.indexOf(new Object[] { }, A));
+        assertEquals(-1, ArrayUtils.indexOf(new Object[] { }, null));
+
+        assertEquals(0, ArrayUtils.indexOf(new Object[] { null, null }, null));
+        assertEquals(1, ArrayUtils.indexOf(new Object[] { A, null, B }, null));
+        assertEquals(2, ArrayUtils.indexOf(new Object[] { A, null, B }, B));
+    }
+
+    @Test
+    public void testContainsAll() throws Exception {
+        final Object A = new Object();
+        final Object B = new Object();
+        final Object C = new Object();
+
+        assertTrue(ArrayUtils.containsAll(new Object[] { C, B, A }, new Object[] { A, B, C }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { A, B }, new Object[] { A }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { A }, new Object[] { A }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { A }, new Object[] { }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { }, new Object[] { }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { null }, new Object[] { }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { null }, new Object[] { null }));
+        assertTrue(ArrayUtils.containsAll(new Object[] { A, null, C }, new Object[] { C, null }));
+
+        assertFalse(ArrayUtils.containsAll(new Object[] { }, new Object[] { A }));
+        assertFalse(ArrayUtils.containsAll(new Object[] { B }, new Object[] { A }));
+        assertFalse(ArrayUtils.containsAll(new Object[] { }, new Object[] { null }));
+        assertFalse(ArrayUtils.containsAll(new Object[] { A }, new Object[] { null }));
+    }
+
+    @Test
+    public void testContainsInt() throws Exception {
+        assertTrue(ArrayUtils.contains(new int[] { 1, 2, 3 }, 1));
+        assertTrue(ArrayUtils.contains(new int[] { 1, 2, 3 }, 2));
+        assertTrue(ArrayUtils.contains(new int[] { 1, 2, 3 }, 3));
+
+        assertFalse(ArrayUtils.contains(new int[] { 1, 2, 3 }, 0));
+        assertFalse(ArrayUtils.contains(new int[] { 1, 2, 3 }, 4));
+        assertFalse(ArrayUtils.contains(new int[] { }, 2));
+    }
+
+    @Test
+    public void testAppendInt() throws Exception {
+        assertArrayEquals(new int[] { 1 },
+                ArrayUtils.appendInt(null, 1));
+        assertArrayEquals(new int[] { 1 },
+                ArrayUtils.appendInt(new int[] { }, 1));
+        assertArrayEquals(new int[] { 1, 2 },
+                ArrayUtils.appendInt(new int[] { 1 }, 2));
+        assertArrayEquals(new int[] { 1, 2 },
+                ArrayUtils.appendInt(new int[] { 1, 2 }, 1));
+    }
+
+    @Test
+    public void testRemoveInt() throws Exception {
+        assertNull(ArrayUtils.removeInt(null, 1));
+        assertArrayEquals(new int[] { },
+                ArrayUtils.removeInt(new int[] { }, 1));
+        assertArrayEquals(new int[] { 1, 2, 3, },
+                ArrayUtils.removeInt(new int[] { 1, 2, 3}, 4));
+        assertArrayEquals(new int[] { 2, 3, },
+                ArrayUtils.removeInt(new int[] { 1, 2, 3}, 1));
+        assertArrayEquals(new int[] { 1, 3, },
+                ArrayUtils.removeInt(new int[] { 1, 2, 3}, 2));
+        assertArrayEquals(new int[] { 1, 2, },
+                ArrayUtils.removeInt(new int[] { 1, 2, 3}, 3));
+        assertArrayEquals(new int[] { 2, 3, 1 },
+                ArrayUtils.removeInt(new int[] { 1, 2, 3, 1 }, 1));
+    }
+
+    @Test
+    public void testContainsLong() throws Exception {
+        assertTrue(ArrayUtils.contains(new long[] { 1, 2, 3 }, 1));
+        assertTrue(ArrayUtils.contains(new long[] { 1, 2, 3 }, 2));
+        assertTrue(ArrayUtils.contains(new long[] { 1, 2, 3 }, 3));
+
+        assertFalse(ArrayUtils.contains(new long[] { 1, 2, 3 }, 0));
+        assertFalse(ArrayUtils.contains(new long[] { 1, 2, 3 }, 4));
+        assertFalse(ArrayUtils.contains(new long[] { }, 2));
+    }
+
+    @Test
+    public void testAppendLong() throws Exception {
+        assertArrayEquals(new long[] { 1 },
+                ArrayUtils.appendLong(null, 1));
+        assertArrayEquals(new long[] { 1 },
+                ArrayUtils.appendLong(new long[] { }, 1));
+        assertArrayEquals(new long[] { 1, 2 },
+                ArrayUtils.appendLong(new long[] { 1 }, 2));
+        assertArrayEquals(new long[] { 1, 2 },
+                ArrayUtils.appendLong(new long[] { 1, 2 }, 1));
+    }
+
+    @Test
+    public void testAppendBooleanDuplicatesAllowed() throws Exception {
+        assertArrayEquals(new boolean[] { true },
+                ArrayUtils.appendBooleanDuplicatesAllowed(null, true));
+        assertArrayEquals(new boolean[] { true },
+                ArrayUtils.appendBooleanDuplicatesAllowed(new boolean[] { }, true));
+        assertArrayEquals(new boolean[] { true, false },
+                ArrayUtils.appendBooleanDuplicatesAllowed(new boolean[] { true }, false));
+        assertArrayEquals(new boolean[] { true, true },
+                ArrayUtils.appendBooleanDuplicatesAllowed(new boolean[] { true }, true));
+    }
+
+    @Test
+    public void testRemoveLong() throws Exception {
+        assertNull(ArrayUtils.removeLong(null, 1));
+        assertArrayEquals(new long[] { },
+                ArrayUtils.removeLong(new long[] { }, 1));
+        assertArrayEquals(new long[] { 1, 2, 3, },
+                ArrayUtils.removeLong(new long[] { 1, 2, 3}, 4));
+        assertArrayEquals(new long[] { 2, 3, },
+                ArrayUtils.removeLong(new long[] { 1, 2, 3}, 1));
+        assertArrayEquals(new long[] { 1, 3, },
+                ArrayUtils.removeLong(new long[] { 1, 2, 3}, 2));
+        assertArrayEquals(new long[] { 1, 2, },
+                ArrayUtils.removeLong(new long[] { 1, 2, 3}, 3));
+        assertArrayEquals(new long[] { 2, 3, 1 },
+                ArrayUtils.removeLong(new long[] { 1, 2, 3, 1 }, 1));
+    }
+
+    @Test
+    public void testConcat_zeroObjectArrays() {
+        // empty varargs array
+        assertArrayEquals(new String[] {}, ArrayUtils.concat(String.class));
+        // null varargs array
+        assertArrayEquals(new String[] {}, ArrayUtils.concat(String.class, (String[][]) null));
+    }
+
+    @Test
+    public void testConcat_oneObjectArray() {
+        assertArrayEquals(new String[] { "1", "2" },
+                ArrayUtils.concat(String.class, new String[] { "1", "2" }));
+    }
+
+    @Test
+    public void testConcat_oneEmptyObjectArray() {
+        assertArrayEquals(new String[] {}, ArrayUtils.concat(String.class, (String[]) null));
+        assertArrayEquals(new String[] {}, ArrayUtils.concat(String.class, new String[] {}));
+    }
+
+    @Test
+    public void testConcat_twoObjectArrays() {
+        assertArrayEquals(new Long[] { 1L },
+                ArrayUtils.concat(Long.class, new Long[] { 1L }, new Long[] {}));
+        assertArrayEquals(new Long[] { 1L },
+                ArrayUtils.concat(Long.class, new Long[] {}, new Long[] { 1L }));
+        assertArrayEquals(new Long[] { 1L, 2L },
+                ArrayUtils.concat(Long.class, new Long[] { 1L }, new Long[] { 2L }));
+        assertArrayEquals(new Long[] { 1L, 2L, 3L, 4L },
+                ArrayUtils.concat(Long.class, new Long[] { 1L, 2L }, new Long[] { 3L, 4L }));
+    }
+
+    @Test
+    public void testConcat_twoEmptyObjectArrays() {
+        assertArrayEquals(new Long[] {}, ArrayUtils.concat(Long.class, null, null));
+        assertArrayEquals(new Long[] {}, ArrayUtils.concat(Long.class, new Long[] {}, null));
+        assertArrayEquals(new Long[] {}, ArrayUtils.concat(Long.class, null, new Long[] {}));
+        assertArrayEquals(new Long[] {},
+                ArrayUtils.concat(Long.class, new Long[] {}, new Long[] {}));
+    }
+
+    @Test
+    public void testConcat_threeObjectArrays() {
+        String[] array1 = { "1", "2" };
+        String[] array2 = { "3", "4" };
+        String[] array3 = { "5", "6" };
+        String[] expectation = { "1", "2", "3", "4", "5", "6" };
+
+        assertArrayEquals(expectation, ArrayUtils.concat(String.class, array1, array2, array3));
+    }
+
+    @Test
+    public void testConcat_threeObjectArraysWithNull() {
+        String[] array1 = { "1", "2" };
+        String[] array2 = null;
+        String[] array3 = { "5", "6" };
+        String[] expectation = { "1", "2", "5", "6" };
+
+        assertArrayEquals(expectation, ArrayUtils.concat(String.class, array1, array2, array3));
+    }
+
+    @Test
+    public void testConcat_zeroByteArrays() {
+        // empty varargs array
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat());
+        // null varargs array
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat((byte[][]) null));
+    }
+
+    @Test
+    public void testConcat_oneByteArray() {
+        assertArrayEquals(new byte[] { 1, 2 }, ArrayUtils.concat(new byte[] { 1, 2 }));
+    }
+
+    @Test
+    public void testConcat_oneEmptyByteArray() {
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat((byte[]) null));
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat(new byte[] {}));
+    }
+
+    @Test
+    public void testConcat_twoByteArrays() {
+        assertArrayEquals(new byte[] { 1 }, ArrayUtils.concat(new byte[] { 1 }, new byte[] {}));
+        assertArrayEquals(new byte[] { 1 }, ArrayUtils.concat(new byte[] {}, new byte[] { 1 }));
+        assertArrayEquals(new byte[] { 1, 2 },
+                ArrayUtils.concat(new byte[] { 1 }, new byte[] { 2 }));
+        assertArrayEquals(new byte[] { 1, 2, 3, 4 },
+                ArrayUtils.concat(new byte[] { 1, 2 }, new byte[] { 3, 4 }));
+    }
+
+    @Test
+    public void testConcat_twoEmptyByteArrays() {
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat((byte[]) null, null));
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat(new byte[] {}, null));
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat((byte[]) null, new byte[] {}));
+        assertArrayEquals(new byte[] {}, ArrayUtils.concat(new byte[] {}, new byte[] {}));
+    }
+
+    @Test
+    public void testConcat_threeByteArrays() {
+        byte[] array1 = { 1, 2 };
+        byte[] array2 = { 3, 4 };
+        byte[] array3 = { 5, 6 };
+        byte[] expectation = { 1, 2, 3, 4, 5, 6 };
+
+        assertArrayEquals(expectation, ArrayUtils.concat(array1, array2, array3));
+    }
+
+    @Test
+    public void testConcat_threeByteArraysWithNull() {
+        byte[] array1 = { 1, 2 };
+        byte[] array2 = null;
+        byte[] array3 = { 5, 6 };
+        byte[] expectation = { 1, 2, 5, 6 };
+
+        assertArrayEquals(expectation, ArrayUtils.concat(array1, array2, array3));
+    }
+
+    @Test
+    @SmallTest
+    public void testUnstableRemoveIf() throws Exception {
+        java.util.function.Predicate<Object> isNull = new java.util.function.Predicate<Object>() {
+            @Override
+            public boolean test(Object o) {
+                return o == null;
+            }
+        };
+
+        final Object a = new Object();
+        final Object b = new Object();
+        final Object c = new Object();
+
+        ArrayList<Object> collection = null;
+        assertEquals(0, ArrayUtils.unstableRemoveIf(collection, isNull));
+
+        collection = new ArrayList<>();
+        assertEquals(0, ArrayUtils.unstableRemoveIf(collection, isNull));
+
+        collection = new ArrayList<>(Collections.singletonList(a));
+        assertEquals(0, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Collections.singletonList(null));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(0, collection.size());
+
+        collection = new ArrayList<>(Arrays.asList(a, b));
+        assertEquals(0, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(2, collection.size());
+        assertTrue(collection.contains(a));
+        assertTrue(collection.contains(b));
+
+        collection = new ArrayList<>(Arrays.asList(a, null));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Arrays.asList(null, a));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Arrays.asList(null, null));
+        assertEquals(2, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(0, collection.size());
+
+        collection = new ArrayList<>(Arrays.asList(a, b, c));
+        assertEquals(0, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(3, collection.size());
+        assertTrue(collection.contains(a));
+        assertTrue(collection.contains(b));
+        assertTrue(collection.contains(c));
+
+        collection = new ArrayList<>(Arrays.asList(a, b, null));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(2, collection.size());
+        assertTrue(collection.contains(a));
+        assertTrue(collection.contains(b));
+
+        collection = new ArrayList<>(Arrays.asList(a, null, b));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(2, collection.size());
+        assertTrue(collection.contains(a));
+        assertTrue(collection.contains(b));
+
+        collection = new ArrayList<>(Arrays.asList(null, a, b));
+        assertEquals(1, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(2, collection.size());
+        assertTrue(collection.contains(a));
+        assertTrue(collection.contains(b));
+
+        collection = new ArrayList<>(Arrays.asList(a, null, null));
+        assertEquals(2, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Arrays.asList(null, null, a));
+        assertEquals(2, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Arrays.asList(null, a, null));
+        assertEquals(2, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(1, collection.size());
+        assertTrue(collection.contains(a));
+
+        collection = new ArrayList<>(Arrays.asList(null, null, null));
+        assertEquals(3, ArrayUtils.unstableRemoveIf(collection, isNull));
+        assertEquals(0, collection.size());
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_passesWhenRangeInsideArray() {
+        ArrayUtils.throwsIfOutOfBounds(10, 2, 6);
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_passesWhenRangeIsWholeArray() {
+        ArrayUtils.throwsIfOutOfBounds(10, 0, 10);
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_passesWhenEmptyRangeAtStart() {
+        ArrayUtils.throwsIfOutOfBounds(10, 0, 0);
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_passesWhenEmptyRangeAtEnd() {
+        ArrayUtils.throwsIfOutOfBounds(10, 10, 0);
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_passesWhenEmptyArray() {
+        ArrayUtils.throwsIfOutOfBounds(0, 0, 0);
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenRangeStartNegative() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(10, -1, 5);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenCountNegative() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(10, 5, -1);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenRangeStartTooHigh() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(10, 11, 0);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenRangeEndTooHigh() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(10, 5, 6);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenLengthNegative() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(-1, 0, 0);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testThrowsIfOutOfBounds_failsWhenOverflowRangeEndTooHigh() {
+        try {
+            ArrayUtils.throwsIfOutOfBounds(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);
+            fail();
+        } catch (ArrayIndexOutOfBoundsException expected) {
+            // expected
+        }
+    }
+
+    // Note: the zeroize() tests only test the behavior that can be tested from a Java test.
+    // They do not verify that no copy of the data is left anywhere.
+
+    @Test
+    @SmallTest
+    public void testZeroizeNonMovableByteArray() {
+        final int length = 10;
+        byte[] array = ArrayUtils.newNonMovableByteArray(length);
+        assertArrayEquals(array, new byte[length]);
+        Arrays.fill(array, (byte) 0xff);
+        ArrayUtils.zeroize(array);
+        assertArrayEquals(array, new byte[length]);
+    }
+
+    @Test
+    @SmallTest
+    public void testZeroizeRegularByteArray() {
+        final int length = 10;
+        byte[] array = new byte[length];
+        assertArrayEquals(array, new byte[length]);
+        Arrays.fill(array, (byte) 0xff);
+        ArrayUtils.zeroize(array);
+        assertArrayEquals(array, new byte[length]);
+    }
+
+    @Test
+    @SmallTest
+    public void testZeroizeNonMovableCharArray() {
+        final int length = 10;
+        char[] array = ArrayUtils.newNonMovableCharArray(length);
+        assertArrayEquals(array, new char[length]);
+        Arrays.fill(array, (char) 0xff);
+        ArrayUtils.zeroize(array);
+        assertArrayEquals(array, new char[length]);
+    }
+
+    @Test
+    @SmallTest
+    public void testZeroizeRegularCharArray() {
+        final int length = 10;
+        char[] array = new char[length];
+        assertArrayEquals(array, new char[length]);
+        Arrays.fill(array, (char) 0xff);
+        ArrayUtils.zeroize(array);
+        assertArrayEquals(array, new char[length]);
+    }
+
+    @Test
+    @SmallTest
+    public void testZeroize_acceptsNull() {
+        ArrayUtils.zeroize((byte[]) null);
+        ArrayUtils.zeroize((char[]) null);
+    }
+}
```

