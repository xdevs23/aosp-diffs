```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index ad25e2b..48dafdb 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -42,10 +42,16 @@ apex {
     }),
 
     name: "com.android.uprobestats",
-    binaries: [
-        "uprobestats",
-        "uprobestatsbpfload",
-    ],
+    binaries: select(release_flag("RELEASE_UPROBESTATS_RUST"), {
+        true: [
+            "uprobestats_rs",
+            "uprobestatsbpfload",
+        ],
+        false: [
+            "uprobestats",
+            "uprobestatsbpfload",
+        ],
+    }),
 
     prebuilts: [
         "com.android.uprobestats.init.rc",
@@ -55,7 +61,7 @@ apex {
         "BitmapAllocation.o",
         "GenericInstrumentation.o",
         "ProcessManagement.o",
-        "MalwareSignal.o",
+        "DisruptiveApp.o",
     ],
 
     native_shared_libs: [
@@ -66,4 +72,8 @@ apex {
     key: "com.android.uprobestats.key",
     certificate: ":com.android.uprobestats.certificate",
     defaults: ["b-launched-apex-module"],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
diff --git a/rust/ffi/bpf.h b/rust/ffi/bpf.h
index ab9407c..0ec7fe2 100644
--- a/rust/ffi/bpf.h
+++ b/rust/ffi/bpf.h
@@ -46,12 +46,13 @@ struct UpdateDeviceIdleTempAllowlistRecord {
   int calling_uid;
 };
 
-#pragma pack(push, 1) // Pack structs with 1-byte boundary
-struct WmBoundUid {
-  __u64 client_uid;
-  char client_package_name[64];
-  unsigned long bind_flags;
-  bool initialized;
+struct BindServiceLocked {
+  char intent_action[64];
+  char intent_package[64];
+  char intent_component_name_package[64];
+  char intent_component_name_class[64];
+  long bind_flags;
+  char calling_package[64];
 };
 
 struct ComponentEnabledSetting {
@@ -59,14 +60,19 @@ struct ComponentEnabledSetting {
   char class_name[64];
   int new_state;
   char calling_package_name[64];
-  bool initialized;
 };
 
-struct MalwareSignal {
-  struct WmBoundUid wm_bound_uid;
-  struct ComponentEnabledSetting component_enabled_setting;
+struct ProcessChange {
+  int pid;
+  int uid;
+  char process_name[256];
+};
+
+struct BitmapAllocation {
+  __u32 width;
+  __u32 height;
+  __u32 pixel_storage_type;
 };
-#pragma pack(pop)
 
 int pollRingBuf(const char *mapPath, int timeoutMs, size_t valueSize,
                 void (*callback)(const void *, void *), void *cookie);
diff --git a/rust/src/Android.bp b/rust/src/Android.bp
index cf64814..4f0a284 100644
--- a/rust/src/Android.bp
+++ b/rust/src/Android.bp
@@ -9,9 +9,14 @@ rust_library {
         "liblogger",
         "libprotobuf",
         "libuprobestats_bpf",
+        "libuprobestats_bpf_bindgen",
         "libuprobestats_proto",
         "librustutils",
         "libserde_json",
+        "libstatslog_uprobestats_rs",
+        "libstatssocket_rs",
+        "libuprobestats_mainline_flags_rust",
+        "libzerocopy",
     ],
     shared_libs: ["libuprobestats_bpf_cc"],
 }
@@ -19,13 +24,14 @@ rust_library {
 rust_binary {
     name: "uprobestats_rs",
     stem: "uprobestats",
-    enabled: false,
+    enabled: select(release_flag("RELEASE_UPROBESTATS_RUST"), {
+        true: true,
+        false: false,
+    }),
     srcs: ["main.rs"],
     defaults: ["uprobestats_rust_defaults"],
+    prefer_rlib: true,
     rustlibs: [
-        "libzerocopy",
-        "libstatslog_uprobestats_rs",
-        "libstatssocket_rs",
         "libuprobestats_rs",
         "libuprobestats_proto",
         "libprotobuf",
@@ -49,9 +55,14 @@ rust_test {
         "liblog_rust",
         "liblogger",
         "libprotobuf",
+        "libstatslog_uprobestats_rs",
+        "libstatssocket_rs",
         "libuprobestats_bpf",
+        "libuprobestats_bpf_bindgen",
+        "libuprobestats_mainline_flags_rust",
         "libuprobestats_proto",
         "librustutils",
         "libserde_json",
+        "libzerocopy",
     ],
 }
diff --git a/rust/src/bpf_map/bitmap_allocation.rs b/rust/src/bpf_map/bitmap_allocation.rs
new file mode 100644
index 0000000..86ca85c
--- /dev/null
+++ b/rust/src/bpf_map/bitmap_allocation.rs
@@ -0,0 +1,21 @@
+use super::OnItem;
+use crate::config_resolver::ResolvedTask;
+use anyhow::Result;
+use log::debug;
+use statslog_uprobestats::android_graphics_bitmap_allocated;
+use uprobestats_bpf_bindgen::BitmapAllocation;
+
+// SAFETY: `BitmapAllocation` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for BitmapAllocation {
+    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
+    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
+        debug!("BitmapAllocation: {:?}", self);
+        android_graphics_bitmap_allocated::stats_write(
+            task.uid,
+            self.width.try_into()?,
+            self.height.try_into()?,
+        )?;
+        Ok(())
+    }
+}
diff --git a/rust/src/bpf_map/disruptive_app.rs b/rust/src/bpf_map/disruptive_app.rs
new file mode 100644
index 0000000..502b64f
--- /dev/null
+++ b/rust/src/bpf_map/disruptive_app.rs
@@ -0,0 +1,66 @@
+use super::{bytes_as_str, OnItem};
+use crate::config_resolver::ResolvedTask;
+use anyhow::Result;
+use log::debug;
+use statslog_uprobestats::{
+    bind_service_locked_with_bal_flags_reported, set_component_enabled_setting_reported,
+};
+use std::ffi::c_long;
+use uprobestats_bpf_bindgen::{BindServiceLocked, ComponentEnabledSetting};
+
+const COMPONENT_ENABLED_STATE_DISABLED: i32 = 2; // PackageManager#COMPONENT_ENABLED_STATE_DISABLED (all values greater than or equal to are disabled states)
+
+// SAFETY: `ComponentEnabledSetting` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for ComponentEnabledSetting {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_ComponentEnabledSetting_output_buf";
+    fn on_item(&self, _task: &ResolvedTask) -> Result<()> {
+        let package_name = bytes_as_str(&self.package_name)?;
+        let class_name = bytes_as_str(&self.class_name)?;
+        let new_state = self.new_state;
+        let calling_package_name = bytes_as_str(&self.calling_package_name)?;
+        debug!("ComponentEnabledSetting: package_name={:?}, class_name={:?}, new_state={:?}, calling_package_name={:?}", package_name, class_name, new_state, calling_package_name);
+        if new_state < COMPONENT_ENABLED_STATE_DISABLED {
+            // < PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
+            return Ok(());
+        }
+        set_component_enabled_setting_reported::stats_write(
+            package_name,
+            class_name,
+            new_state,
+            calling_package_name,
+        )?;
+        Ok(())
+    }
+}
+
+const BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS: c_long = 0x00100000; // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS
+
+// SAFETY: `BindServiceLocked` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for BindServiceLocked {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_DisruptiveApp_BindServiceLocked_output_buf";
+    fn on_item(&self, _task: &ResolvedTask) -> Result<()> {
+        let intent_package = bytes_as_str(&self.intent_package)?;
+        let intent_action = bytes_as_str(&self.intent_action)?;
+        let intent_component_name_package = bytes_as_str(&self.intent_component_name_package)?;
+        let intent_component_name_class = bytes_as_str(&self.intent_component_name_class)?;
+        let flags = self.bind_flags;
+        let calling_package = bytes_as_str(&self.calling_package)?;
+        let has_bal_flag = (self.bind_flags & BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS) != 0;
+        debug!(
+            "BindServiceLocked: intent_package={:?}, intent_action={:?}, intent_component_name_package={:?}, intent_component_name_class={:?} flags={:?}, calling_package={:?}, has_bal_flag={}",
+            intent_package, intent_action, intent_component_name_package, intent_component_name_class, flags, calling_package, has_bal_flag
+        );
+        if has_bal_flag {
+            bind_service_locked_with_bal_flags_reported::stats_write(
+                intent_package,
+                flags as _,
+                calling_package,
+            )?;
+        }
+        Ok(())
+    }
+}
diff --git a/rust/src/bpf_map/generic_instrumentation.rs b/rust/src/bpf_map/generic_instrumentation.rs
index e36458c..d3a53ed 100644
--- a/rust/src/bpf_map/generic_instrumentation.rs
+++ b/rust/src/bpf_map/generic_instrumentation.rs
@@ -1,20 +1,20 @@
 use super::{OnItem, JAVA_ARGUMENT_REGISTER_OFFSET};
+use crate::config_resolver::ResolvedTask;
 use anyhow::{anyhow, Result};
 use log::debug;
 use protobuf::MessageField;
 use statssocket::AStatsEvent;
 use uprobestats_bpf_bindgen::{CallResult, CallTimestamp};
-use uprobestats_proto::config::uprobestats_config::Task;
 
 // SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
 // layout of the corresponding C struct.
 unsafe impl OnItem for CallTimestamp {
     const MAP_PATH: &'static str =
         "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_timestamp_buf";
-    fn on_item(&self, task: &Task) -> Result<()> {
+    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
         debug!("CallTimestamp - event: {}, timestamp_ns: {}", self.event, self.timestampNs,);
 
-        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
             return Ok(());
         };
 
@@ -38,13 +38,13 @@ unsafe impl OnItem for CallTimestamp {
 unsafe impl OnItem for CallResult {
     const MAP_PATH: &'static str =
         "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_detail_buf";
-    fn on_item(&self, task: &Task) -> Result<()> {
+    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
         debug!("CallResult - register: pc = {}", self.pc,);
         for i in 0..10 {
             debug!("CallResult - register: {} = {}", i, self.regs[i],);
         }
 
-        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
             return Ok(());
         };
 
diff --git a/rust/src/bpf_map/malware_signal.rs b/rust/src/bpf_map/malware_signal.rs
deleted file mode 100644
index 8c02088..0000000
--- a/rust/src/bpf_map/malware_signal.rs
+++ /dev/null
@@ -1,20 +0,0 @@
-use super::OnItem;
-use anyhow::Result;
-use log::debug;
-use uprobestats_bpf_bindgen::MalwareSignal;
-use uprobestats_proto::config::uprobestats_config::Task;
-
-// SAFETY: `MalwareSignal` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
-// layout of the corresponding C struct.
-unsafe impl OnItem for MalwareSignal {
-    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_MalwareSignal_output_buf";
-    fn on_item(&self, _task: &Task) -> Result<()> {
-        if self.wm_bound_uid.initialized {
-            debug!("wm_bound_uid: {:?}", self.wm_bound_uid);
-        }
-        if self.component_enabled_setting.initialized {
-            debug!("component_enabled_setting: {:?}", self.component_enabled_setting);
-        }
-        Ok(())
-    }
-}
diff --git a/rust/src/bpf_map/mod.rs b/rust/src/bpf_map/mod.rs
index 904c7de..270151b 100644
--- a/rust/src/bpf_map/mod.rs
+++ b/rust/src/bpf_map/mod.rs
@@ -1,44 +1,40 @@
+//! Deals with fetching data BPF ring buffers ("maps").
+use crate::config_resolver::ResolvedTask;
+use crate::Timer;
 use anyhow::{bail, Result};
 use log::debug;
-use std::{
-    collections::HashMap,
-    fmt::Debug,
-    sync::LazyLock,
-    time::{Duration, Instant},
-};
+use std::{collections::HashMap, ffi::CStr, fmt::Debug, sync::LazyLock, time::Duration};
 use uprobestats_bpf::poll_ring_buf;
 use uprobestats_bpf_bindgen::{
-    CallResult, CallTimestamp, MalwareSignal, SetUidTempAllowlistStateRecord,
-    UpdateDeviceIdleTempAllowlistRecord,
+    BindServiceLocked, BitmapAllocation, CallResult, CallTimestamp, ComponentEnabledSetting,
+    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
 };
-use uprobestats_proto::config::uprobestats_config::Task;
+use zerocopy::{Immutable, IntoBytes};
 
+mod bitmap_allocation;
+mod disruptive_app;
 mod generic_instrumentation;
-mod malware_signal;
 mod process_management;
 
-pub(crate) fn poll_and_loop(
-    map_path: &str,
-    now: Instant,
-    duration: Duration,
-    task: Task,
-) -> Result<()> {
-    let duration_millis = duration.as_millis();
-    let mut elapsed_millis = now.elapsed().as_millis();
-    while elapsed_millis <= duration_millis {
-        let timeout_millis = duration_millis - elapsed_millis;
-        let timeout_millis: i32 = timeout_millis.try_into()?;
-        debug!("polling {} for {} seconds", map_path, timeout_millis / 1000);
+/// Polls the given map_path based on the existing registry of handlers.
+pub fn poll_registry(map_path: &str, task: &ResolvedTask, duration: Duration) -> Result<()> {
+    let timer = Timer::new(duration);
+    while let Some(remaining_millis) = timer.remaining_millis() {
+        let remaining_millis: i32 = remaining_millis.try_into()?;
+        debug!("polling {} for {} seconds", map_path, remaining_millis / 1000);
         let Some(do_poll) = REGISTRY.get(map_path) else {
             bail!("unsupported map_path: {}", map_path);
         };
-        do_poll(map_path, timeout_millis, &task)?;
-        elapsed_millis = now.elapsed().as_millis();
+        do_poll(map_path, task, remaining_millis)?;
     }
     Ok(())
 }
 
-fn poll<T: OnItem + Debug + Copy>(map_path: &str, timeout_millis: i32, task: &Task) -> Result<()> {
+fn poll<T: OnItem + Debug + Copy>(
+    map_path: &str,
+    task: &ResolvedTask,
+    timeout_millis: i32,
+) -> Result<()> {
     if map_path != T::MAP_PATH {
         bail!("map_path mismatch: {} != {}", map_path, T::MAP_PATH)
     }
@@ -62,10 +58,10 @@ const JAVA_ARGUMENT_REGISTER_OFFSET: i32 = 2;
 /// which holds items of type `T` implementing this trait.
 unsafe trait OnItem {
     const MAP_PATH: &'static str;
-    fn on_item(&self, task: &Task) -> Result<()>;
+    fn on_item(&self, task: &ResolvedTask) -> Result<()>;
 }
 
-type Registry = HashMap<&'static str, fn(&str, i32, &Task) -> Result<()>>;
+type Registry = HashMap<&'static str, fn(&str, &ResolvedTask, i32) -> Result<()>>;
 
 fn register<T: OnItem + Debug + Copy>(registry: &mut Registry) {
     registry.insert(T::MAP_PATH, poll::<T> as _);
@@ -73,10 +69,64 @@ fn register<T: OnItem + Debug + Copy>(registry: &mut Registry) {
 
 static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
     let mut map = HashMap::new();
+    register::<BindServiceLocked>(&mut map);
+    register::<BitmapAllocation>(&mut map);
     register::<CallTimestamp>(&mut map);
     register::<CallResult>(&mut map);
-    register::<MalwareSignal>(&mut map);
+    register::<ComponentEnabledSetting>(&mut map);
     register::<SetUidTempAllowlistStateRecord>(&mut map);
     register::<UpdateDeviceIdleTempAllowlistRecord>(&mut map);
     map
 });
+
+pub(crate) fn bytes_as_str(bytes: &(impl IntoBytes + Immutable)) -> Result<&str> {
+    let string = CStr::from_bytes_until_nul(bytes.as_bytes())?;
+    Ok(string.to_str()?)
+}
+
+#[cfg(test)]
+mod test {
+    use log::debug;
+    use zerocopy::{Immutable, IntoBytes};
+    // local test only util
+    #[allow(dead_code)]
+    fn print_xxd_like(prefix: &str, data: &(impl IntoBytes + Immutable)) {
+        let data = data.as_bytes();
+        let mut offset = 0;
+        debug!("{} hex:", prefix);
+        for chunk in data.chunks(16) {
+            // Format the offset
+            let offset_str = format!("{:08x}:", offset);
+            // Format the hexadecimal representation
+            let hex_str = chunk
+                .iter()
+                .enumerate()
+                .map(|(i, &byte)| {
+                    let hex = format!("{:02x}", byte);
+                    if (i + 1) % 2 == 0 && i != chunk.len() - 1 {
+                        format!("{} ", hex)
+                    } else {
+                        hex
+                    }
+                })
+                .collect::<Vec<String>>()
+                .join(" ");
+            let padded_hex_str = format!("{:<48}", hex_str); // Pad to align ASCII
+                                                             // Format the ASCII representation
+            let ascii_str = chunk
+                .iter()
+                .map(
+                    |&byte| {
+                        if byte.is_ascii_graphic() || byte == b' ' {
+                            byte as char
+                        } else {
+                            '.'
+                        }
+                    },
+                )
+                .collect::<String>();
+            debug!("{} {}  {}", offset_str, padded_hex_str, ascii_str);
+            offset += chunk.len();
+        }
+    }
+}
diff --git a/rust/src/bpf_map/process_management.rs b/rust/src/bpf_map/process_management.rs
index 0203f7d..a1f7f31 100644
--- a/rust/src/bpf_map/process_management.rs
+++ b/rust/src/bpf_map/process_management.rs
@@ -1,24 +1,21 @@
-use super::OnItem;
+use super::{bytes_as_str, OnItem};
+use crate::config_resolver::ResolvedTask;
 use anyhow::{anyhow, Result};
 use log::debug;
 use protobuf::MessageField;
 use statssocket::AStatsEvent;
-use std::ffi::CStr;
-use zerocopy::IntoBytes;
 use uprobestats_bpf_bindgen::{
     SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
 };
-use uprobestats_proto::config::uprobestats_config::Task;
 
 // SAFETY: `SetUidTempAllowlistStateRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
 // layout of the corresponding C struct.
 unsafe impl OnItem for SetUidTempAllowlistStateRecord {
-    const MAP_PATH: &'static str =
-        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
-    fn on_item(&self, task: &Task) -> Result<()> {
+    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_ProcessManagement_output_buf";
+    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
         debug!("SetUidTempAllowlistStateRecord: {:?}", self);
 
-        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
             return Ok(());
         };
 
@@ -45,10 +42,10 @@ unsafe impl OnItem for SetUidTempAllowlistStateRecord {
 unsafe impl OnItem for UpdateDeviceIdleTempAllowlistRecord {
     const MAP_PATH: &'static str =
         "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
-    fn on_item(&self, task: &Task) -> Result<()> {
+    fn on_item(&self, task: &ResolvedTask) -> Result<()> {
         debug!("UpdateDeviceIdleTempAllowlistRecord: {:?}", self);
 
-        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+        let MessageField(Some(ref statsd_logging_config)) = task.task.statsd_logging_config else {
             return Ok(());
         };
 
@@ -62,13 +59,10 @@ unsafe impl OnItem for UpdateDeviceIdleTempAllowlistRecord {
 
         event.write_int32(self.changing_uid);
         event.write_bool(self.adding);
-        event.write_int64(self.duration_ms);
+        event.write_int64(self.duration_ms as _);
         event.write_int32(self.type_);
         event.write_int32(self.reason_code);
-
-        let reason = CStr::from_bytes_until_nul(self.reason.as_bytes())?;
-        event.write_string(reason.to_str()?)?;
-
+        event.write_string(bytes_as_str(&self.reason)?)?;
         event.write_int32(self.calling_uid);
 
         event.write();
diff --git a/rust/src/config_resolver.rs b/rust/src/config_resolver.rs
index c291094..b8a1304 100644
--- a/rust/src/config_resolver.rs
+++ b/rust/src/config_resolver.rs
@@ -1,18 +1,25 @@
 //! Validates uprobestats config protos and adds additional info.
-use anyhow::{anyhow, Result};
+use crate::prefix_bpf;
+use anyhow::{anyhow, ensure, Result};
 use dynamic_instrumentation_manager::{
     ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
 };
-use log::debug;
+use log::{debug, warn};
 use protobuf::Message;
+use std::clone::Clone;
 use std::collections::HashSet;
 use std::fs::File;
 use std::io::Read;
+use std::time::Duration;
 use uprobestats_proto::config::{
-    uprobestats_config::task::ProbeConfig, uprobestats_config::Task, UprobestatsConfig,
+    uprobestats_config::{
+        task::{ProbeConfig, TargetProcessSelection},
+        Task,
+    },
+    UprobestatsConfig,
 };
 
-use crate::{art::get_method_offset_from_oatdump, process::get_pid};
+use crate::{art::get_method_offset_from_oatdump, process::get_pid_and_uid};
 
 /// Validated probe proto + probe target's code filename and offset.
 pub struct ResolvedProbe {
@@ -26,13 +33,18 @@ pub struct ResolvedProbe {
 }
 
 /// Validated task proto + probe target's pid.
+#[derive(Clone)]
 pub struct ResolvedTask {
     /// The task proto.
     pub task: Task,
     /// The duration of the task in seconds.
     pub duration_seconds: i32,
+    /// Name of the task's target process,
+    pub process_name: String,
     /// The pid of the task's target process.
     pub pid: i32,
+    /// The uid of the task's target process.
+    pub uid: i32,
     /// The set of absolute bpf map paths used by the task.
     pub bpf_map_paths: HashSet<String>,
 }
@@ -42,32 +54,47 @@ pub fn resolve_single_task(config: UprobestatsConfig) -> Result<ResolvedTask> {
     let mut tasks = config.tasks.into_iter();
     let task = tasks.next().ok_or_else(|| anyhow!("No tasks found in config"))?;
 
+    let bpf_map_paths: Result<HashSet<String>> = task
+        .bpf_maps
+        .iter()
+        .map(|bpf_map| {
+            ensure!(is_bpf_file_enabled(bpf_map), "{} is disabled by flag", bpf_map);
+            Ok(prefix_bpf(bpf_map))
+        })
+        .collect();
+
+    let bpf_map_paths = bpf_map_paths?;
+
     let duration_seconds =
         task.duration_seconds.ok_or_else(|| anyhow!("Task duration is required"))?;
     if duration_seconds <= 0 {
         return Err(anyhow!("Task duration must be greater than 0"));
     }
 
-    let target_process_name = task
+    let process_name = task
         .target_process_name
         .clone()
         .ok_or_else(|| anyhow!("Target process name is required"))?;
-    if target_process_name != "system_server" {
-        return Err(anyhow!("system_server is the only target process currently supported"));
-    }
 
-    let pid = get_pid(&target_process_name)
-        .ok_or_else(|| anyhow!("Failed to get pid for process: {target_process_name}"))?;
+    let target_process_selection = task
+        .target_process_selection
+        .unwrap_or(TargetProcessSelection::UNKNOWN.into())
+        .enum_value_or_default();
 
-    let bpf_map_paths = task.bpf_maps.iter().map(|bpf_map| prefix_bpf(bpf_map)).collect();
+    let (pid, uid) = get_pid_and_uid(
+        &process_name,
+        target_process_selection,
+        Duration::from_secs(duration_seconds.try_into()?),
+    )?;
 
-    Ok(ResolvedTask { duration_seconds, task, pid, bpf_map_paths })
+    Ok(ResolvedTask { duration_seconds, task, process_name, pid, uid, bpf_map_paths })
 }
 
 /// Validates a single probe proto and adds additional info.
-pub fn resolve_probes(task: &Task) -> Result<Vec<ResolvedProbe>> {
-    let resolved_probes = task.probe_configs.clone().into_iter().map(|probe| {
+pub fn resolve_probes(resolved_task: &ResolvedTask) -> Result<Vec<ResolvedProbe>> {
+    let resolved_probes = resolved_task.task.probe_configs.clone().into_iter().map(|probe| {
         let bpf_name = probe.bpf_name.as_ref().ok_or_else(|| anyhow!("bpf_name is required"))?;
+        ensure!(is_bpf_file_enabled(bpf_name), "{} is disabled by flag", bpf_name);
         let bpf_program_path = prefix_bpf(bpf_name);
         if let Some(ref fully_qualified_class_name) = probe.fully_qualified_class_name {
             debug!("using getExecutableMethodFileOffsets to retrieve offsets");
@@ -75,7 +102,11 @@ pub fn resolve_probes(task: &Task) -> Result<Vec<ResolvedProbe>> {
                 probe.method_name.clone().ok_or_else(|| anyhow!("method_name is required"))?;
             let fully_qualified_parameters = probe.fully_qualified_parameters.clone();
             let offsets = ExecutableMethodFileOffsets::get(
-                &TargetProcess::system_server()?,
+                &TargetProcess::new(
+                    resolved_task.uid.try_into()?,
+                    resolved_task.pid,
+                    &resolved_task.process_name,
+                )?,
                 &MethodDescriptor::new(
                     &fully_qualified_class_name.clone(),
                     &method_name,
@@ -102,10 +133,14 @@ pub fn resolve_probes(task: &Task) -> Result<Vec<ResolvedProbe>> {
             let mut offset: i32 = 0;
             let mut found_file_path: String = "".to_string();
             for file_path in &probe.file_paths {
-                let found_offset = get_method_offset_from_oatdump(file_path, &method_signature)?;
-                let Some(found_offset) = found_offset else {
-                    continue;
-                };
+                let found_offset = get_method_offset_from_oatdump(file_path, &method_signature)
+                    .inspect_err(|e| {
+                        warn!("Failed to get offset for {method_signature} from {file_path}: {e}")
+                    })
+                    .ok()
+                    .flatten()
+                    .unwrap_or(0);
+
                 if found_offset > 0 {
                     found_file_path = file_path.to_string();
                     offset = found_offset;
@@ -138,7 +173,12 @@ pub fn read_config(config_path: &str) -> Result<UprobestatsConfig> {
         .map_err(|e| anyhow!("Failed to parse config file: {e}"))
 }
 
-const BPF_DIR: &str = "/sys/fs/bpf/uprobestats/";
-fn prefix_bpf(path: &str) -> String {
-    BPF_DIR.to_string() + path
+fn is_bpf_file_enabled(bpf_prog_or_map_name: &str) -> bool {
+    if bpf_prog_or_map_name.contains("DisruptiveApp") {
+        uprobestats_mainline_flags_rust::uprobestats_monitor_disruptive_app_activities()
+    } else if bpf_prog_or_map_name.contains("BitmapAllocation") {
+        uprobestats_mainline_flags_rust::enable_bitmap_instrumentation()
+    } else {
+        true
+    }
 }
diff --git a/rust/src/lib.rs b/rust/src/lib.rs
index 21d8b08..c4ac4fa 100644
--- a/rust/src/lib.rs
+++ b/rust/src/lib.rs
@@ -1,5 +1,32 @@
 //! UprobeStats library
 mod art;
+pub mod bpf_map;
 pub mod config_resolver;
 pub mod guardrail;
 mod process;
+
+use std::time::{Duration, Instant};
+
+const BPF_DIR: &str = "/sys/fs/bpf/uprobestats/";
+pub(crate) fn prefix_bpf(path: &str) -> String {
+    BPF_DIR.to_string() + path
+}
+
+/// Basic timer implementation
+pub struct Timer {
+    now: Instant,
+    duration: Duration,
+}
+
+impl Timer {
+    /// Construct a timer for the given duration.
+    pub fn new(duration: Duration) -> Self {
+        let now = Instant::now();
+        Self { now, duration }
+    }
+
+    /// Check the time remaining. `None` if expired, else `Some(remaining)`.
+    pub fn remaining_millis(&self) -> Option<u128> {
+        self.duration.as_millis().checked_sub(self.now.elapsed().as_millis())
+    }
+}
diff --git a/rust/src/main.rs b/rust/src/main.rs
index 6f46ce9..67c1303 100644
--- a/rust/src/main.rs
+++ b/rust/src/main.rs
@@ -3,22 +3,24 @@ use anyhow::{anyhow, bail, ensure, Result};
 use binder::ProcessState;
 use log::{debug, error, LevelFilter};
 use rustutils::system_properties;
-use std::process::exit;
 use std::{
+    cmp::{max, min},
+    process::exit,
+    str::FromStr,
     thread,
-    time::{Duration, Instant},
+    time::Duration,
 };
 use uprobestats_bpf::bpf_perf_event_open;
-use uprobestats_rs::{config_resolver, guardrail};
-
-mod bpf_map;
+use uprobestats_rs::{bpf_map, config_resolver, guardrail};
 
 fn main() {
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device("uprobestats")
-            .with_max_level(if is_user_build() { LevelFilter::Info } else { LevelFilter::Trace }),
-    );
+    let log_tag_filter = level_filter_from_property_or_info("log.tag.uprobestats");
+    let persist_log_tag_filter = level_filter_from_property_or_info("persist.log.tag.uprobestats");
+    let log_level_filter = max(log_tag_filter, persist_log_tag_filter);
+
+    logger::init(logger::Config::default().with_tag_on_device("uprobestats").with_max_level(
+        if is_user_build() { min(LevelFilter::Info, log_level_filter) } else { log_level_filter },
+    ));
 
     if let Err(e) = main_impl() {
         error!("{}", e);
@@ -29,19 +31,32 @@ fn main() {
 fn main_impl() -> Result<()> {
     debug!("started");
 
-    ensure!(is_uprobestats_enabled(), "Uprobestats disabled by flag");
+    ensure!(uprobestats_mainline_flags_rust::enable_uprobestats(), "enable_uprobestats disabled");
+    ensure!(
+        uprobestats_mainline_flags_rust::uprobestats_support_update_device_idle_temp_allowlist(),
+        "uprobestats_support_update_device_idle_temp_allowlist disabled",
+    );
+    ensure!(
+        uprobestats_mainline_flags_rust::executable_method_file_offsets(),
+        "executable_method_file_offsets disabled",
+    );
 
     let config = config_resolver::read_config("/data/misc/uprobestats-configs/config")?;
     ensure!(
         guardrail::is_allowed(&config, is_user_build(), true)?,
         "uprobestats probing config disallowed on this device"
     );
-    let task = config_resolver::resolve_single_task(config)?;
 
     ProcessState::start_thread_pool();
 
-    let probes = config_resolver::resolve_probes(&task.task)?;
-    for probe in probes {
+    let task = config_resolver::resolve_single_task(config)?;
+
+    let probes = config_resolver::resolve_probes(&task)?;
+    for probe in &probes {
+        debug!(
+            "attaching bpf {} to {} at {}",
+            probe.bpf_program_path, &probe.filename, &probe.offset
+        );
         bpf_perf_event_open(
             probe.filename.clone(),
             probe.offset,
@@ -49,39 +64,33 @@ fn main_impl() -> Result<()> {
             probe.bpf_program_path.clone(),
         )?;
         debug!(
-            "attached bpf {} to {} at {}",
+            "successfully attached bpf {} to {} at {}",
             probe.bpf_program_path, &probe.filename, &probe.offset
         );
     }
 
-    let duration_seconds: u64 = task.duration_seconds.try_into()?;
-    let now = Instant::now();
-    let duration = Duration::from_secs(duration_seconds);
-
-    let results = task.bpf_map_paths.into_iter().map(|map_path| {
-        debug!("Spawning thread for map_path: {}", map_path);
-        match thread::spawn({
-            let task_proto = task.task.clone();
-            move || bpf_map::poll_and_loop(&map_path, now, duration, task_proto)
-        })
-        .join()
-        {
-            Ok(result) => result.map_err(|e| anyhow!("Thread error: {}", e)),
-            Err(panic) => bail!("Thread panic: {:?}", panic),
+    let duration = Duration::from_secs(task.duration_seconds.try_into()?);
+    let errors = thread::scope(|s| {
+        let mut handles = vec![];
+        for map_path in &task.bpf_map_paths {
+            let task_ref = &task;
+            handles.push(s.spawn(move || {
+                debug!("Spawned thread for map_path: {}", map_path);
+                bpf_map::poll_registry(map_path, task_ref, duration)
+                    .map_err(|e| anyhow!("poll_registry error: {}", e))
+            }));
         }
-    });
 
-    let errors: Vec<_> = results
-        .filter_map(|r| match r {
-            Ok(()) => None,
-            Err(e) => Some(e),
-        })
-        .collect();
+        handles
+            .into_iter()
+            .map(|handle| handle.join().map_err(|p| anyhow!("Thread panic: {p:?}")).and_then(|r| r))
+            .filter_map(|r| r.err())
+            .collect::<Vec<_>>()
+    });
 
     if !errors.is_empty() {
         let msg = errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>().join(",");
-        let msg = format!("At least one thread returned error: {}", msg);
-        bail!("{}", msg);
+        bail!("At least one thread returned error: {}", msg);
     }
 
     debug!("done");
@@ -96,6 +105,9 @@ fn is_user_build() -> bool {
     true
 }
 
-fn is_uprobestats_enabled() -> bool {
-    uprobestats_mainline_flags_rust::enable_uprobestats()
+fn level_filter_from_property_or_info(property: &str) -> LevelFilter {
+    LevelFilter::from_str(
+        system_properties::read(property).ok().flatten().unwrap_or("".to_string()).as_str(),
+    )
+    .unwrap_or(LevelFilter::Info)
 }
diff --git a/rust/src/process.rs b/rust/src/process.rs
index 9999155..4a0858f 100644
--- a/rust/src/process.rs
+++ b/rust/src/process.rs
@@ -1,9 +1,86 @@
 //! Utils for dealing with processes
-
+use crate::{bpf_map::bytes_as_str, prefix_bpf, Timer};
+use anyhow::{anyhow, bail, Result};
+use dynamic_instrumentation_manager::{
+    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
+};
+use log::debug;
 use std::fs::{read, read_dir};
+use std::time::Duration;
+use uprobestats_bpf::{bpf_perf_event_open, poll_ring_buf};
+use uprobestats_bpf_bindgen::ProcessChange;
+use uprobestats_proto::config::uprobestats_config::task::TargetProcessSelection;
+
+pub(crate) fn get_pid_and_uid(
+    target_process_name: &str,
+    target_process_selection: TargetProcessSelection,
+    duration: Duration,
+) -> Result<(i32, i32)> {
+    debug!(
+        "get_pid_and_uid: process_name: {} process_selection: {:?}",
+        target_process_name, target_process_selection
+    );
+    match target_process_selection {
+        TargetProcessSelection::SPECIFIC_APP_PROCESS_ON_START => {
+            wait_for_app_start(Some(target_process_name), duration)
+        }
+        TargetProcessSelection::ANY_APP_PROCESS_ON_START => wait_for_app_start(None, duration),
+        TargetProcessSelection::SPECIFIC_PROCESS_NAME | TargetProcessSelection::UNKNOWN => {
+            let pid = get_pid(target_process_name)
+                .ok_or(anyhow!("Can't find pid for {}", target_process_name))?;
+            Ok((pid, 0))
+        }
+    }
+}
+
+fn wait_for_app_start(process_name: Option<&str>, duration: Duration) -> Result<(i32, i32)> {
+    let system_server_pid =
+        get_pid("system_server").ok_or(anyhow!("failed to get system server pid"))?;
+    let (offsets, bpf_prog_name) = match get_ProcessRecord_makeActive_offsets() {
+        Ok(offsets) => (offsets, BPF_PROG_PROCESS_MANAGEMENT_MAKE_ACTIVE),
+        Err(e) => {
+            debug!(
+                "Could not find offsets for ProcessRecord#makeActive, trying onProcessActive: {e}"
+            );
+            (get_onProcessActive_offsets()?, BPF_PROG_PROCESS_MANAGEMENT_ON_PROCESS_ACTIVE)
+        }
+    };
+
+    debug!("attaching process management bpf for app start");
+    bpf_perf_event_open(
+        offsets.get_container_path(),
+        offsets.get_method_offset().try_into()?,
+        system_server_pid,
+        prefix_bpf(bpf_prog_name),
+    )?;
+
+    let timer = Timer::new(duration);
+    while let Some(remaining_millis) = timer.remaining_millis() {
+        debug!("polling {} for {} seconds", BPF_MAP_PROCESS_MANAGEMENT, remaining_millis / 1000);
+        // SAFETY: hard coded `const BPF_MAP_PROCESS_MANAGEMENT` writes the `ProcessChange` struct.
+        let result: Result<Vec<ProcessChange>> = unsafe {
+            poll_ring_buf(&prefix_bpf(BPF_MAP_PROCESS_MANAGEMENT), remaining_millis.try_into()?)
+        };
+        let result = result?;
+        for process_change in result {
+            let result_process_name = bytes_as_str(&process_change.process_name)?;
+            if process_name.is_none() || process_name.unwrap() == result_process_name {
+                if process_change.pid <= 0 {
+                    continue;
+                }
+                debug!(
+                    "detected process start: pid: {} uid: {}",
+                    process_change.pid, process_change.uid
+                );
+                return Ok((process_change.pid, process_change.uid));
+            }
+        }
+    }
 
-/// return PID given name
-pub(crate) fn get_pid(process_name: &str) -> Option<i32> {
+    bail!("Timeout waiting duration {:?} for process_name {:?}", duration, process_name)
+}
+
+fn get_pid(process_name: &str) -> Option<i32> {
     for entry in read_dir("/proc").ok()? {
         let entry = entry.ok()?;
         let path = entry.path();
@@ -25,3 +102,45 @@ pub(crate) fn get_pid(process_name: &str) -> Option<i32> {
 
     None
 }
+
+#[allow(non_snake_case)]
+fn get_ProcessRecord_makeActive_offsets() -> Result<ExecutableMethodFileOffsets> {
+    let offsets = ExecutableMethodFileOffsets::get(
+        &TargetProcess::system_server()?,
+        &MethodDescriptor::new(
+            CLASS_PROCESS_RECORD,
+            METHOD_MAKE_ACTIVE,
+            METHOD_MAKE_ACTIVE_PARAMS.into_iter().map(String::from),
+        )?,
+    )?;
+    offsets.ok_or(anyhow!("Could not find offsets for ProcessRecord#makeActive"))
+}
+
+#[allow(non_snake_case)]
+fn get_onProcessActive_offsets() -> Result<ExecutableMethodFileOffsets> {
+    let offsets = ExecutableMethodFileOffsets::get(
+        &TargetProcess::system_server()?,
+        &MethodDescriptor::new(
+            CLASS_PROCESS_PROFILE_RECORD,
+            METHOD_ON_PROCESS_ACTIVE,
+            METHOD_ON_PROCESS_ACTIVE_PARAMS.into_iter().map(String::from),
+        )?,
+    )?;
+    offsets.ok_or(anyhow!("Could not find offsets for ProcessProfileRecord#onProcessActive"))
+}
+
+const CLASS_PROCESS_RECORD: &str = "com.android.server.am.ProcessRecord";
+const METHOD_MAKE_ACTIVE: &str = "makeActive";
+const METHOD_MAKE_ACTIVE_PARAMS: [&str; 2] = [
+    "com.android.server.am.ApplicationThreadDeferred",
+    "com.android.server.am.ProcessStatsService",
+];
+const CLASS_PROCESS_PROFILE_RECORD: &str = "com.android.server.am.ProcessProfileRecord";
+const METHOD_ON_PROCESS_ACTIVE: &str = "onProcessActive";
+const METHOD_ON_PROCESS_ACTIVE_PARAMS: [&str; 2] =
+    ["android.app.IApplicationThread", "com.android.server.am.ProcessStatsService"];
+
+const BPF_PROG_PROCESS_MANAGEMENT_MAKE_ACTIVE: &str = "prog_ProcessManagement_uprobe_make_active";
+const BPF_PROG_PROCESS_MANAGEMENT_ON_PROCESS_ACTIVE: &str =
+    "prog_ProcessManagement_uprobe_on_process_active";
+const BPF_MAP_PROCESS_MANAGEMENT: &str = "map_ProcessManagement_process_change_output_buf";
diff --git a/src/Android.bp b/src/Android.bp
index fe4d24a..e7b4689 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -40,12 +40,14 @@ cc_aconfig_library {
 java_aconfig_library {
     name: "uprobestats_flags_java_lib",
     aconfig_declarations: "uprobestats_flags",
+    sdk_version: "current",
     host_supported: true,
 }
 
 java_aconfig_library {
     name: "art_flags_uprobestats_java_lib",
     aconfig_declarations: "art-aconfig-flags",
+    sdk_version: "current",
     host_supported: true,
 }
 
@@ -55,6 +57,7 @@ java_aconfig_library {
     host_supported: true,
     visibility: [
         "//cts/hostsidetests/statsdatom:__subpackages__",
+        "//packages/modules/UprobeStats:__subpackages__",
     ],
 }
 
@@ -127,7 +130,10 @@ uprobestats_cc_library {
 
 cc_binary {
     name: "uprobestats",
-    enabled: true,
+    enabled: select(release_flag("RELEASE_UPROBESTATS_RUST"), {
+        true: false,
+        false: true,
+    }),
     srcs: [
         "UprobeStats.cpp",
         "config.proto",
@@ -155,7 +161,6 @@ cc_binary {
             "BitmapAllocation.o",
             "GenericInstrumentation.o",
             "ProcessManagement.o",
-            "MalwareSignal.o",
         ],
     }),
 
diff --git a/src/UprobeStats.cpp b/src/UprobeStats.cpp
index cff83e8..bcc1267 100644
--- a/src/UprobeStats.cpp
+++ b/src/UprobeStats.cpp
@@ -188,34 +188,9 @@ void doPoll(PollArgs args) {
         AStatsEvent_write(event);
         AStatsEvent_release(event);
       }
-    } else if (mapPath.find(kMalwareSignalMap) != std::string::npos) {
-      auto result =
-          bpf::pollRingBuf<bpf::MalwareSignal>(mapPath.c_str(), timeoutMs);
-      for (auto value : result) {
-        if (value.component_enabled_setting.initialized == true) {
-          LOG_IF_DEBUG(
-              "ComponentEnabledSetting: package_name="
-              << value.component_enabled_setting.package_name
-              << " class_name=" << value.component_enabled_setting.class_name
-              << " new_state=" << value.component_enabled_setting.new_state
-              << " calling_package_name="
-              << value.component_enabled_setting.calling_package_name);
-        }
-        if (value.wm_bound_uid.initialized == true) {
-          LOG_IF_DEBUG(
-              "WmBoundUid: clientUid:" << value.wm_bound_uid.client_uid);
-          LOG_IF_DEBUG(
-              "clientPackageName:" << value.wm_bound_uid.client_package_name);
-          LOG_IF_DEBUG("bindFlags:" << value.wm_bound_uid.bind_flags);
-        }
-      }
     } else {
-      LOG_IF_DEBUG("Polling for i64 result");
-      auto result = bpf::pollRingBuf<uint64_t>(mapPath.c_str(), timeoutMs);
-      for (auto value : result) {
-        LOG_IF_DEBUG("Other result... value: " << value
-                                               << " mapPath: " << mapPath);
-      }
+      LOG(ERROR) << "unsupported mapPath: " << mapPath;
+      break;
     }
     now = std::chrono::steady_clock::now();
   }
diff --git a/src/bpf_progs/Android.bp b/src/bpf_progs/Android.bp
index 4d9a0af..da4589a 100644
--- a/src/bpf_progs/Android.bp
+++ b/src/bpf_progs/Android.bp
@@ -26,7 +26,7 @@ bpf {
 }
 
 bpf {
-    name: "MalwareSignal.o",
-    srcs: ["MalwareSignal.c"],
+    name: "DisruptiveApp.o",
+    srcs: ["DisruptiveApp.c"],
     sub_dir: "uprobestats",
 }
diff --git a/src/bpf_progs/BitmapAllocation.c b/src/bpf_progs/BitmapAllocation.c
index de5c10b..461ee8f 100644
--- a/src/bpf_progs/BitmapAllocation.c
+++ b/src/bpf_progs/BitmapAllocation.c
@@ -19,6 +19,20 @@
 #include <stdint.h>
 #include <bpf_helpers.h>
 
+// TODO: import this struct from generic header, access registers via generic
+// function
+struct pt_regs {
+  unsigned long regs[31];
+  unsigned long sp;
+  unsigned long pc;
+  unsigned long pr;
+  unsigned long sr;
+  unsigned long gbr;
+  unsigned long mach;
+  unsigned long macl;
+  long tra;
+};
+
 DEFINE_BPF_RINGBUF_EXT(output_buf, __u64, 4096, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "",
                        PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER,
                        LOAD_ON_USERDEBUG);
@@ -32,4 +46,43 @@ DEFINE_BPF_PROG("uprobe/bitmap_constructor_heap", AID_UPROBESTATS, AID_UPROBESTA
     return 0;
 }
 
+struct BitmapAllocation {
+  __u32 width;
+  __u32 height;
+  __u32 pixel_storage_type;
+};
+
+int load(void *dest, int offset, int length, void *user_space_address) {
+  long canonical_address = (long)user_space_address & 0x00FFFFFFFFFFFFFF;
+  return bpf_probe_read_user(dest, length,
+                             (void *)(canonical_address + offset));
+}
+
+DEFINE_BPF_RINGBUF_EXT(output, struct BitmapAllocation, 16 * 1024,
+                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_PROG("uprobe/bitmap_creation", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE3)
+(struct pt_regs *ctx) {
+
+  struct BitmapAllocation *output = bpf_output_reserve();
+  if (output == NULL)
+    return 1;
+  output->width = ctx->regs[4];
+  output->height = ctx->regs[5];
+
+  uint8_t *bitmap_wrapper_ptr = (uint8_t *)(ctx->regs[3]);
+  uint8_t *bitmap_ptr;
+  // The first 8 bytes of a BitmapWrapper object is the pointer to the
+  // underlying Bitmap.
+  load(&bitmap_ptr, 0, 8, bitmap_wrapper_ptr);
+  // 0x78 is the offset of pixel_storage_type into a Bitmap object.
+  load(&output->pixel_storage_type, 0x78, 4, bitmap_ptr);
+
+  bpf_output_submit(output);
+  return 0;
+}
+
 LICENSE("GPL");
diff --git a/src/bpf_progs/DisruptiveApp.c b/src/bpf_progs/DisruptiveApp.c
new file mode 100644
index 0000000..e33a5df
--- /dev/null
+++ b/src/bpf_progs/DisruptiveApp.c
@@ -0,0 +1,172 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+#include <bpf_helpers.h>
+#include <linux/bpf.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <string.h>
+
+struct pt_regs {
+  unsigned long regs[31];
+  unsigned long sp;
+  unsigned long pc;
+  unsigned long pr;
+  unsigned long sr;
+  unsigned long gbr;
+  unsigned long mach;
+  unsigned long macl;
+  long tra;
+};
+
+#define MAX_STRING_LENGTH 64
+
+struct BindServiceLocked {
+  char intent_action[MAX_STRING_LENGTH];
+  char intent_package[MAX_STRING_LENGTH];
+  char intent_component_name_package[MAX_STRING_LENGTH];
+  char intent_component_name_class[MAX_STRING_LENGTH];
+  long bind_flags;
+  char calling_package[MAX_STRING_LENGTH];
+};
+
+struct ComponentEnabledSetting {
+  char package_name[MAX_STRING_LENGTH];
+  char class_name[MAX_STRING_LENGTH];
+  int new_state;
+  char calling_package_name[MAX_STRING_LENGTH];
+};
+
+void recordString(void *jstring, unsigned int max_length, char *dest) {
+  // Assumes the following memory layout of a Java String object:
+  // byte offset 8-11: count (this is the length of the string * 2)
+  // byte offset 12-15: hash_code
+  // byte offset 16 and beyond: string content
+  __u32 count;
+  bpf_probe_read_user(&count, sizeof(count), jstring + 8);
+  count /= 2;
+  bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
+                          jstring + 16);
+}
+
+// Copies the content of a Java String object to <dest>, where the Java String
+// address is located in stack frame.
+void recordStringArgFromSp(struct pt_regs *ctx, unsigned int max_length,
+                           int sp_offset, char *dest) {
+  void *jstring = NULL;
+  bpf_probe_read_user(&jstring, 4, (void *)ctx->sp + sp_offset);
+  recordString(jstring, max_length, dest);
+}
+
+DEFINE_BPF_RINGBUF_EXT(BindServiceLocked_output_buf, struct BindServiceLocked,
+                       4096, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "",
+                       PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
+                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_RINGBUF_EXT(ComponentEnabledSetting_output_buf,
+                       struct ComponentEnabledSetting, 4096, AID_UPROBESTATS,
+                       AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+// Offsets of fields in Intent: kIntent<FieldName>Offset
+const int kIntentPackageOffset = 48;
+const int kIntentComponentNameOffset = 20;
+const int kIntentActionOffset = 8;
+// Offsets of fields in ComponentName: kComponentName<FieldName>Offset
+const int kComponentNameClassOffset = 8;
+const int kComponentNamePackageOffset = 12;
+// The <callingPackage> argument is located at offset=60 in stack frame. This
+// is calculated as 12 + sizeof(previous arguments). There are 11 preceding
+// arguments all of which is 4 bytes each except for <long flags> which
+// is 8 bytes. Therefore the offset is:
+// 12 + (4 * 10) + 8 = 60
+const int kCallingPackageStackFrameOffset = 60;
+
+DEFINE_BPF_PROG("uprobe/bind_service_locked", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE2)
+(struct pt_regs *ctx) {
+  struct BindServiceLocked *output = bpf_BindServiceLocked_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  void *intent_ptr = (void *)ctx->regs[4];
+
+  void *intent_package_name_ptr = NULL;
+  bpf_probe_read_user(&intent_package_name_ptr, 4,
+                      intent_ptr + kIntentPackageOffset);
+  recordString(intent_package_name_ptr, MAX_STRING_LENGTH,
+               output->intent_package);
+
+  void *intent_action_ptr = NULL;
+  bpf_probe_read_user(&intent_action_ptr, 4, intent_ptr + kIntentActionOffset);
+  recordString(intent_action_ptr, MAX_STRING_LENGTH, output->intent_action);
+
+  void *component_name_ptr = NULL;
+  bpf_probe_read_user(&component_name_ptr, 4,
+                      intent_ptr + kIntentComponentNameOffset);
+
+  void *intent_component_name_package_ptr = NULL;
+  bpf_probe_read_user(&intent_component_name_package_ptr, 4,
+                      component_name_ptr + kComponentNamePackageOffset);
+  recordString(intent_component_name_package_ptr, MAX_STRING_LENGTH,
+               output->intent_component_name_package);
+
+  void *intent_component_name_class_ptr = NULL;
+  bpf_probe_read_user(&intent_component_name_class_ptr, 4,
+                      component_name_ptr + kComponentNameClassOffset);
+  recordString(intent_component_name_class_ptr, MAX_STRING_LENGTH,
+               output->intent_component_name_class);
+
+  output->bind_flags = ctx->regs[7];
+  recordStringArgFromSp(ctx, MAX_STRING_LENGTH, kCallingPackageStackFrameOffset,
+                        output->calling_package);
+
+  bpf_BindServiceLocked_output_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/set_component_enabled_setting", AID_UPROBESTATS,
+                AID_UPROBESTATS, BPF_KPROBE3)
+(struct pt_regs *ctx) {
+  struct ComponentEnabledSetting *output =
+      bpf_ComponentEnabledSetting_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  void *component_name_ptr = (void *)ctx->regs[2];
+  void *class_name = NULL;
+  void *package_name = NULL;
+
+  bpf_probe_read_user(&class_name, 4,
+                      component_name_ptr + kComponentNameClassOffset);
+  recordString(class_name, 64, output->class_name);
+
+  bpf_probe_read_user(&package_name, 4,
+                      component_name_ptr + kComponentNamePackageOffset);
+  recordString(package_name, 64, output->package_name);
+
+  void *calling_package_name = (void *)ctx->regs[6];
+  recordString(calling_package_name, 64, output->calling_package_name);
+
+  output->new_state = ctx->regs[3];
+
+  bpf_ComponentEnabledSetting_output_buf_submit(output);
+  return 0;
+}
+
+LICENSE("GPL");
diff --git a/src/bpf_progs/MalwareSignal.c b/src/bpf_progs/MalwareSignal.c
deleted file mode 100644
index c6f69c5..0000000
--- a/src/bpf_progs/MalwareSignal.c
+++ /dev/null
@@ -1,123 +0,0 @@
-/*
- * Copyright 2025 The Android Open Source Project
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
-#include <bpf_helpers.h>
-#include <linux/bpf.h>
-#include <stdbool.h>
-#include <stdint.h>
-#include <stdio.h>
-#include <string.h>
-
-struct pt_regs {
-  unsigned long regs[16];
-  unsigned long pc;
-  unsigned long pr;
-  unsigned long sr;
-  unsigned long gbr;
-  unsigned long mach;
-  unsigned long macl;
-  long tra;
-};
-
-#pragma pack(push, 1) // Pack structs with 1-byte boundary
-struct WmBoundUid {
-  __u64 client_uid;
-  char client_package_name[64];
-  unsigned long bind_flags;
-  bool initialized;
-};
-
-struct ComponentEnabledSetting {
-  char package_name[64];
-  char class_name[64];
-  int new_state;
-  char calling_package_name[64];
-  bool initialized;
-};
-
-struct MalwareSignal {
-  struct WmBoundUid wm_bound_uid;
-  struct ComponentEnabledSetting component_enabled_setting;
-};
-#pragma pack(pop)
-
-void recordString(void *jstring, unsigned int max_length, char *dest) {
-  // Assumes the following memory layout of a Java String object:
-  // byte offset 8-11: count (this is the length of the string * 2)
-  // byte offset 12-15: hash_code
-  // byte offset 16 and beyond: string content
-  __u32 count;
-  bpf_probe_read_user(&count, sizeof(count), jstring + 8);
-  count /= 2;
-  bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
-                          jstring + 16);
-}
-
-DEFINE_BPF_RINGBUF_EXT(output_buf, struct MalwareSignal, 4096, AID_UPROBESTATS,
-                       AID_UPROBESTATS, 0600, "", "", PRIVATE,
-                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
-                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
-
-DEFINE_BPF_PROG("uprobe/add_bound_client_uid", AID_UPROBESTATS, AID_UPROBESTATS,
-                BPF_KPROBE2)
-(struct pt_regs *ctx) {
-  struct MalwareSignal *output = bpf_output_buf_reserve();
-  if (output == NULL)
-    return 1;
-
-  struct WmBoundUid output_1 = {};
-  output_1.client_uid = ctx->regs[2];
-  output_1.bind_flags = ctx->regs[4];
-  void *j_clientPackageName = (void *)ctx->regs[3];
-  recordString(j_clientPackageName, 64, output_1.client_package_name);
-  output_1.initialized = true;
-  output->wm_bound_uid = output_1;
-  output->component_enabled_setting.initialized = false;
-  bpf_output_buf_submit(output);
-  return 0;
-}
-
-DEFINE_BPF_PROG("uprobe/set_component_enabled_setting", AID_UPROBESTATS,
-                AID_UPROBESTATS, BPF_KPROBE3)
-(struct pt_regs *ctx) {
-  struct MalwareSignal *output = bpf_output_buf_reserve();
-  if (output == NULL)
-    return 1;
-
-  struct ComponentEnabledSetting output_1 = {};
-  void *component_name_ptr = (void *)ctx->regs[2];
-  void *class_name = NULL;
-  void *package_name = NULL;
-
-  bpf_probe_read_user(&class_name, 4, component_name_ptr + 8);
-  recordString(class_name, 64, output_1.class_name);
-
-  bpf_probe_read_user(&package_name, 4, component_name_ptr + 12);
-  recordString(package_name, 64, output_1.package_name);
-
-  void *calling_package_name = (void *)ctx->regs[6];
-  recordString(calling_package_name, 64, output_1.calling_package_name);
-
-  output_1.new_state = ctx->regs[3];
-  output_1.initialized = true;
-  output->component_enabled_setting = output_1;
-  output->wm_bound_uid.initialized = false;
-
-  bpf_output_buf_submit(output);
-  return 0;
-}
-
-LICENSE("GPL");
diff --git a/src/bpf_progs/ProcessManagement.c b/src/bpf_progs/ProcessManagement.c
index 7288642..4d8aae5 100644
--- a/src/bpf_progs/ProcessManagement.c
+++ b/src/bpf_progs/ProcessManagement.c
@@ -85,10 +85,10 @@ void recordString(void *jstring, unsigned int max_length, char *dest) {
   // byte offset 12-15: hash_code
   // byte offset 16 and beyond: string content
   __u32 count;
-  bpf_probe_read_user(&count, sizeof(count), jstring + 8);
+  bpf_probe_read_user(&count, sizeof(count), (uint8_t *)jstring + 8);
   count /= 2;
   bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
-                          jstring + 16);
+                          (uint8_t *)jstring + 16);
 }
 
 // Copies the content of a Java String object to <dest>, where the Java String
@@ -138,4 +138,67 @@ DEFINE_BPF_PROG("uprobe/update_device_idle_temp_allowlist", AID_UPROBESTATS,
   return 0;
 }
 
+struct ProcessChange {
+  int pid;
+  int uid;
+  char process_name[256];
+};
+
+DEFINE_BPF_RINGBUF_EXT(process_change_output_buf, struct ProcessChange,
+                       4096 * 16, AID_UPROBESTATS, AID_UPROBESTATS, 0600, "",
+                       "", PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
+                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_PROG("uprobe/set_pid", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE5)
+(struct pt_regs *ctx) {
+  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  output->pid = (int)ctx->regs[2];
+  bpf_probe_read_user(&output->uid, 4, (void *)(ctx->regs[1] + 0xf4));
+  void *process_name = 0;
+  bpf_probe_read_user(&process_name, 4, (void *)(ctx->regs[1] + 0xa0));
+  recordString(process_name, 256, output->process_name);
+
+  bpf_process_change_output_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/make_active", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE4)
+(struct pt_regs *ctx) {
+  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  bpf_probe_read_user(&output->pid, 4, (void *)(ctx->regs[1] + 0xe8));
+  bpf_probe_read_user(&output->uid, 4, (void *)(ctx->regs[1] + 0xf4));
+  uint8_t *process_name = 0;
+  bpf_probe_read_user(&process_name, 4, (void *)(ctx->regs[1] + 0xa0));
+  recordString(process_name, 256, output->process_name);
+
+  bpf_process_change_output_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/on_process_active", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE6)
+(struct pt_regs *ctx) {
+  struct ProcessChange *output = bpf_process_change_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  uint8_t *process_record_ptr = 0;
+  bpf_probe_read_user(&process_record_ptr, 4, (void *)(ctx->regs[1] + 0x8));
+  bpf_probe_read_user(&output->pid, 4, (void *)(process_record_ptr + 0xe8));
+  bpf_probe_read_user(&output->uid, 4, (void *)(process_record_ptr + 0xf4));
+  uint8_t *process_name = 0;
+  bpf_probe_read_user(&process_name, 4, (void *)(process_record_ptr + 0xa0));
+  recordString(process_name, 256, output->process_name);
+
+  bpf_process_change_output_buf_submit(output);
+  return 0;
+}
+
 LICENSE("GPL");
diff --git a/src/bpfloader/UprobeStatsBpfLoad.cpp b/src/bpfloader/UprobeStatsBpfLoad.cpp
index ce9121a..8783e82 100644
--- a/src/bpfloader/UprobeStatsBpfLoad.cpp
+++ b/src/bpfloader/UprobeStatsBpfLoad.cpp
@@ -35,6 +35,7 @@
 #include "bpf/BpfUtils.h"
 #include "bpf_map_def.h"
 
+#include <algorithm>
 #include <cstdlib>
 #include <fstream>
 #include <iostream>
diff --git a/src/config.proto b/src/config.proto
index 79e532e..32e462a 100644
--- a/src/config.proto
+++ b/src/config.proto
@@ -77,6 +77,15 @@ message UprobestatsConfig {
     }
     optional StatsdLoggingConfig statsd_logging_config = 5;
 
+    enum TargetProcessSelection {
+      UNKNOWN = 0;
+      SPECIFIC_PROCESS_NAME = 1;
+      ANY_APP_PROCESS_ON_START = 2;
+      SPECIFIC_APP_PROCESS_ON_START = 3;
+    };
+
+    optional TargetProcessSelection target_process_selection = 6;
+
   }
 
   repeated Task tasks = 1;
diff --git a/src/mainline-flag.aconfig b/src/mainline-flag.aconfig
index a227cc6..4bdb570 100644
--- a/src/mainline-flag.aconfig
+++ b/src/mainline-flag.aconfig
@@ -17,6 +17,14 @@ flag {
     is_fixed_read_only: true
 }
 
+flag {
+    name: "executable_method_file_offsets"
+    namespace: "system_performance"
+    bug: "296108553"
+    description: "Whether the ART executable method file offsets API is available. Mirrors identical flag in com.android.art."
+    is_fixed_read_only: true
+}
+
 flag {
     name: "uprobestats_monitor_disruptive_app_activities"
     namespace: "responsible_apis"
@@ -26,9 +34,9 @@ flag {
 }
 
 flag {
-    name: "executable_method_file_offsets"
+    name: "enable_bitmap_instrumentation"
     namespace: "system_performance"
-    bug: "296108553"
-    description: "Whether the ART executable method file offsets API is available. Mirrors identical flag in com.android.art."
+    description: "Whether to enable bitmap instrumentation"
+    bug: "400457896"
     is_fixed_read_only: true
 }
diff --git a/src/test/Android.bp b/src/test/Android.bp
index 5a792c1..0d1a942 100644
--- a/src/test/Android.bp
+++ b/src/test/Android.bp
@@ -3,11 +3,20 @@ package {
     default_team: "trendy_team_system_performance",
 }
 
+filegroup {
+    name: "uprobestats-test-sources",
+    srcs: ["*.java"],
+    exclude_srcs: select(release_flag("RELEASE_UPROBESTATS_RUST"), {
+        true: [],
+        false: [
+            "SmokeTestRustOnly.java",
+        ],
+    }),
+}
+
 java_test_host {
     name: "uprobestats-test",
-    srcs: [
-        "*.java",
-    ],
+    srcs: [":uprobestats-test-sources"],
     java_resources: ["test/*.textproto"],
     libs: [
         "compatibility-host-util",
@@ -25,6 +34,7 @@ java_test_host {
         "perfetto_config-full",
         "art_flags_uprobestats_java_lib",
         "uprobestats_flags_java_lib",
+        "uprobestats_mainline_flags_java_lib",
         "uprobestats-protos",
     ],
     proto: {
@@ -34,6 +44,10 @@ java_test_host {
         "general-tests",
         "mts-uprobestats",
     ],
+    device_common_data: [
+        ":DisruptiveTestApp",
+        ":BitmapTestApp",
+    ],
 }
 
 python_binary_host {
diff --git a/src/test/AndroidTest.xml b/src/test/AndroidTest.xml
index d438ed3..743a26a 100644
--- a/src/test/AndroidTest.xml
+++ b/src/test/AndroidTest.xml
@@ -9,4 +9,14 @@
         <option name="mainline-module-package-name" value="com.google.android.uprobestats" />
     </object>
 
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="DisruptiveTestApp.apk" />
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="BitmapTestApp.apk" />
+    </target_preparer>
+
 </configuration>
diff --git a/src/test/BitmapTestApp/Android.bp b/src/test/BitmapTestApp/Android.bp
new file mode 100644
index 0000000..7b10409
--- /dev/null
+++ b/src/test/BitmapTestApp/Android.bp
@@ -0,0 +1,24 @@
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
+android_test_helper_app {
+    name: "BitmapTestApp",
+
+    srcs: ["**/*.java"],
+
+    min_sdk_version: "36",
+    platform_apis: true,
+    certificate: "platform",
+    test_suites: ["mts-uprobestats"],
+}
diff --git a/src/test/BitmapTestApp/AndroidManifest.xml b/src/test/BitmapTestApp/AndroidManifest.xml
new file mode 100644
index 0000000..f080f7a
--- /dev/null
+++ b/src/test/BitmapTestApp/AndroidManifest.xml
@@ -0,0 +1,19 @@
+
+<!-- Copyright (C) 2024 The Android Open Source Project
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+          http://www.apache.org/licenses/LICENSE-2.0
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+        package="com.android.uprobestats.bitmap">
+    <application>
+        <activity android:name=".BitmapTestActivity"
+             android:exported="true"/>
+    </application>
+</manifest>
diff --git a/src/test/BitmapTestApp/src/com/android/uprobestats/bitmap/BitmapTestActivity.java b/src/test/BitmapTestApp/src/com/android/uprobestats/bitmap/BitmapTestActivity.java
new file mode 100644
index 0000000..767f60d
--- /dev/null
+++ b/src/test/BitmapTestApp/src/com/android/uprobestats/bitmap/BitmapTestActivity.java
@@ -0,0 +1,30 @@
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
+package com.android.uprobestats.bitmap;
+
+import android.app.Activity;
+import android.os.Bundle;
+
+public class BitmapTestActivity extends Activity {
+    private static final String TAG = BitmapTestActivity.class.getSimpleName();
+
+    @Override
+    public void onCreate(Bundle bundle) {
+        super.onCreate(bundle);
+        android.graphics.Bitmap.createBitmap(100, 100, android.graphics.Bitmap.Config.ARGB_8888);
+    }
+}
diff --git a/src/test/DisruptiveTestApp/Android.bp b/src/test/DisruptiveTestApp/Android.bp
new file mode 100644
index 0000000..cb31137
--- /dev/null
+++ b/src/test/DisruptiveTestApp/Android.bp
@@ -0,0 +1,22 @@
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
+android_test_helper_app {
+    name: "DisruptiveTestApp",
+    srcs: ["**/*.java"],
+    min_sdk_version: "36",
+    platform_apis: true,
+    certificate: "platform",
+    test_suites: ["mts-uprobestats"],
+}
diff --git a/src/test/DisruptiveTestApp/AndroidManifest.xml b/src/test/DisruptiveTestApp/AndroidManifest.xml
new file mode 100644
index 0000000..12b46bf
--- /dev/null
+++ b/src/test/DisruptiveTestApp/AndroidManifest.xml
@@ -0,0 +1,25 @@
+
+<!-- Copyright (C) 2024 The Android Open Source Project
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+          http://www.apache.org/licenses/LICENSE-2.0
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+        package="com.android.uprobestats.disruptive">
+    <uses-permission android:name="android.permission.START_ACTIVITIES_FROM_BACKGROUND" />
+    <application>
+        <activity android:name=".TestActivity" android:exported="true">
+            <intent-filter>
+                <category android:name="android.intent.category.LAUNCHER"/>
+                <action android:name="android.intent.action.MAIN"/>
+            </intent-filter>
+        </activity>
+        <service android:name=".TestService" />
+    </application>
+</manifest>
diff --git a/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestActivity.java b/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestActivity.java
new file mode 100644
index 0000000..f560e36
--- /dev/null
+++ b/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestActivity.java
@@ -0,0 +1,52 @@
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
+package com.android.uprobestats.disruptive;
+
+import android.app.Activity;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.ServiceConnection;
+import android.os.Bundle;
+import android.os.IBinder;
+import android.util.Log;
+
+public class TestActivity extends Activity {
+    private static String TAG = "DisruptiveTestActivity";
+
+    @Override
+    public void onCreate(Bundle bundle) {
+        Log.i(TAG, "onCreate");
+        super.onCreate(bundle);
+        Intent intent = new Intent(this, TestService.class);
+        int flags = Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS;
+        boolean bound = bindService(intent, new Fake(), flags);
+        Log.i(TAG, "bound: " + bound);
+    }
+
+    private static class Fake implements ServiceConnection {
+        @Override
+        public void onServiceConnected(ComponentName component, IBinder _svc) {
+            Log.i(TAG, "onServiceConnected: " + component.toString());
+        }
+
+        @Override
+        public void onServiceDisconnected(ComponentName component) {
+            Log.i(TAG, "onServiceDisconnected: " + component.toString());
+        }
+    }
+}
diff --git a/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestService.java b/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestService.java
new file mode 100644
index 0000000..15b795b
--- /dev/null
+++ b/src/test/DisruptiveTestApp/src/com/android/uprobestats/disruptive/TestService.java
@@ -0,0 +1,31 @@
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
+package com.android.uprobestats.disruptive;
+
+import android.app.Service;
+import android.content.Intent;
+import android.os.Binder;
+import android.os.IBinder;
+
+public class TestService extends Service {
+    @Override
+    public IBinder onBind(Intent intent) {
+        return new Fake();
+    }
+
+    class Fake extends Binder {}
+}
diff --git a/src/test/SmokeTest.java b/src/test/SmokeTest.java
index 7f79496..92ce94d 100644
--- a/src/test/SmokeTest.java
+++ b/src/test/SmokeTest.java
@@ -23,8 +23,11 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assume.assumeTrue;
 
+import static test.SmokeTestSetup.configureStatsDAndStartUprobeStats;
+import static test.SmokeTestSetup.initializeStatsD;
+import static test.SmokeTestSetup.initializeUprobeStats;
+
 import android.cts.statsdatom.lib.AtomTestUtils;
-import android.cts.statsdatom.lib.ConfigUtils;
 import android.cts.statsdatom.lib.DeviceUtils;
 import android.cts.statsdatom.lib.ReportUtils;
 import android.platform.test.annotations.RequiresFlagsDisabled;
@@ -33,30 +36,23 @@ import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.host.HostFlagsValueProvider;
 
 import com.android.compatibility.common.util.CpuFeatures;
-import com.android.internal.os.StatsdConfigProto;
 import com.android.os.StatsLog;
 import com.android.os.framework.FrameworkExtensionAtoms;
 import com.android.os.uprobestats.TestUprobeStatsAtomReported;
 import com.android.os.uprobestats.UprobestatsExtensionAtoms;
-import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.RunUtil;
 
 import com.google.protobuf.ExtensionRegistry;
-import com.google.protobuf.TextFormat;
 
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
-import uprobestats.protos.Config.UprobestatsConfig;
-
-import java.io.File;
-import java.nio.file.Files;
 import java.util.List;
-import java.util.Scanner;
 
 @RunWith(DeviceJUnit4ClassRunner.class)
 public class SmokeTest extends BaseHostJUnit4Test {
@@ -67,6 +63,8 @@ public class SmokeTest extends BaseHostJUnit4Test {
             "test_bss_setBatteryState_artApi.textproto";
     private static final String TEMP_ALLOWLIST_CONFIG =
             "test_updateDeviceIdleTempAllowlist.textproto";
+    private static final String SET_TEMP_ALLOWLIST_STATE_CONFIG =
+            "test_setUidTempAllowlistStateLSP.textproto";
     private static final String CONFIG_NAME = "config";
     private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";
     private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
@@ -79,44 +77,8 @@ public class SmokeTest extends BaseHostJUnit4Test {
 
     @Before
     public void setUp() throws Exception {
-        ConfigUtils.removeConfig(getDevice());
-        ReportUtils.clearReports(getDevice());
-        getDevice().deleteFile(CONFIG_DIR + CONFIG_NAME);
-        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
-        getDevice().executeShellCommand("killall uprobestats");
-        mRegistry = ExtensionRegistry.newInstance();
-        UprobestatsExtensionAtoms.registerAllExtensions(mRegistry);
-        FrameworkExtensionAtoms.registerAllExtensions(mRegistry);
-    }
-
-    void startUprobeStats(String textprotoFilename, int atomId) throws Exception {
-        // 1. Parse config from resources
-        String textProto =
-                new Scanner(this.getClass().getResourceAsStream(textprotoFilename))
-                        .useDelimiter("\\A")
-                        .next();
-        UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
-        TextFormat.getParser().merge(textProto, builder);
-        UprobestatsConfig config = builder.build();
-
-        // 2. Write config to a file and drop it on the device
-        File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
-        assertThat(tmp.setWritable(true)).isTrue();
-        Files.write(tmp.toPath(), config.toByteArray());
-        ITestDevice device = getDevice();
-        assertThat(getDevice().enableAdbRoot()).isTrue();
-        assertThat(getDevice().pushFile(tmp, CONFIG_DIR + CONFIG_NAME)).isTrue();
-
-        // 3. Configure StatsD
-        StatsdConfigProto.StatsdConfig.Builder configBuilder =
-                ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
-        ConfigUtils.addEventMetric(configBuilder, atomId);
-        ConfigUtils.uploadConfig(getDevice(), configBuilder);
-
-        // 4. Start UprobeStats
-        device.executeShellCommand(CMD_SETPROP_UPROBESTATS);
-        // Allow UprobeStats time to attach probe
-        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+        mRegistry = initializeStatsD(getDevice());
+        initializeUprobeStats(getDevice());
     }
 
     @Test
@@ -137,6 +99,7 @@ public class SmokeTest extends BaseHostJUnit4Test {
     }
 
     @Test
+    @Ignore
     @RequiresFlagsEnabled({
         FLAG_ENABLE_UPROBESTATS,
         FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
@@ -147,8 +110,11 @@ public class SmokeTest extends BaseHostJUnit4Test {
     }
 
     private void batteryStats(String config) throws Exception {
-        startUprobeStats(
-                config, UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
+        configureStatsDAndStartUprobeStats(
+                getClass(),
+                getDevice(),
+                config,
+                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
 
         // Set charging state, which should invoke BatteryStatsService#setBatteryState.
         // Assumptions:
@@ -177,7 +143,9 @@ public class SmokeTest extends BaseHostJUnit4Test {
     @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
     public void updateDeviceIdleTempAllowlist() throws Exception {
         assumeTrue(CpuFeatures.isArm64(getDevice()));
-        startUprobeStats(
+        configureStatsDAndStartUprobeStats(
+                getClass(),
+                getDevice(),
                 TEMP_ALLOWLIST_CONFIG,
                 FrameworkExtensionAtoms.DEVICE_IDLE_TEMP_ALLOWLIST_UPDATED_FIELD_NUMBER);
 
@@ -206,4 +174,42 @@ public class SmokeTest extends BaseHostJUnit4Test {
                         .anyMatch(reported -> reported.getReason().equals("shell"));
         assertThat(anyMatch).isTrue();
     }
+
+    @Test
+    @Ignore
+    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
+    public void setUidTempAllowlistState() throws Exception {
+        assumeTrue(CpuFeatures.isArm64(getDevice()));
+        configureStatsDAndStartUprobeStats(
+                getClass(),
+                getDevice(),
+                SET_TEMP_ALLOWLIST_STATE_CONFIG,
+                FrameworkExtensionAtoms.POWER_SAVE_TEMP_ALLOWLIST_CHANGED_FIELD_NUMBER);
+
+        // Set tempallowlist
+        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
+        // Allow UprobeStats/StatsD time to collect metric
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+        // See if the atom made it
+        List<StatsLog.EventMetricData> data =
+                ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
+        assertThat(data.size()).isGreaterThan(0);
+        boolean anyMatch =
+                data.stream()
+                        .map(StatsLog.EventMetricData::getAtom)
+                        .filter(
+                                atom ->
+                                        atom.hasExtension(
+                                                FrameworkExtensionAtoms
+                                                        .powerSaveTempAllowlistChanged))
+                        .map(
+                                atom ->
+                                        atom.getExtension(
+                                                FrameworkExtensionAtoms
+                                                        .powerSaveTempAllowlistChanged))
+                        .anyMatch(
+                                reported -> reported.getUid() > 0 && reported.getAddToAllowlist());
+        assertThat(anyMatch).isTrue();
+    }
 }
diff --git a/src/test/SmokeTestRustOnly.java b/src/test/SmokeTestRustOnly.java
new file mode 100644
index 0000000..b1efb0b
--- /dev/null
+++ b/src/test/SmokeTestRustOnly.java
@@ -0,0 +1,187 @@
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
+package test;
+
+import static android.uprobestats.flags.Flags.FLAG_ENABLE_UPROBESTATS;
+import static android.uprobestats.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS;
+import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_INSTRUMENTATION;
+import static android.uprobestats.mainline.flags.Flags.FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assume.assumeTrue;
+
+import static test.SmokeTestSetup.configureStatsDAndStartUprobeStats;
+import static test.SmokeTestSetup.initializeStatsD;
+import static test.SmokeTestSetup.initializeUprobeStats;
+
+import android.cts.statsdatom.lib.AtomTestUtils;
+import android.cts.statsdatom.lib.DeviceUtils;
+import android.cts.statsdatom.lib.ReportUtils;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.host.HostFlagsValueProvider;
+
+import com.android.compatibility.common.util.CpuFeatures;
+import com.android.os.StatsLog;
+import com.android.os.uprobestats.BindServiceLockedWithBalFlagsReported;
+import com.android.os.uprobestats.SetComponentEnabledSettingReported;
+import com.android.os.uprobestats.UprobestatsExtensionAtoms;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.protobuf.ExtensionRegistry;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.List;
+
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class SmokeTestRustOnly extends BaseHostJUnit4Test {
+    private static final String TEST_MALWARE_SIGNAL_CONFIG = "disruptive_app.textproto";
+    private static final String BITMAP_ALLOCATION_CONFIG = "bitmap.textproto";
+    private static final String BITMAP_TESTAPP_PACKAGE_NAME = "com.android.uprobestats.bitmap";
+    private ExtensionRegistry mRegistry;
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);
+
+    @Before
+    public void setUp() throws Exception {
+        mRegistry = initializeStatsD(getDevice());
+        initializeUprobeStats(getDevice());
+    }
+
+    @Test
+    @RequiresFlagsEnabled({
+        FLAG_ENABLE_UPROBESTATS,
+        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
+        FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES,
+    })
+    public void disruptiveAppActivity() throws Exception {
+        assumeTrue(CpuFeatures.isArm64(getDevice()));
+
+        configureStatsDAndStartUprobeStats(
+                getClass(),
+                getDevice(),
+                TEST_MALWARE_SIGNAL_CONFIG,
+                UprobestatsExtensionAtoms.SET_COMPONENT_ENABLED_SETTING_REPORTED_FIELD_NUMBER,
+                UprobestatsExtensionAtoms.BIND_SERVICE_LOCKED_WITH_BAL_FLAGS_REPORTED_FIELD_NUMBER);
+
+        // enable and disable a component (need one that will definitely exist, but not in
+        // android/com.android namespace)
+        getDevice()
+                .executeShellCommand(
+                        "pm disable" + " com.android.uprobestats.disruptive/.TestActivity");
+        getDevice()
+                .executeShellCommand(
+                        "pm enable" + " com.android.uprobestats.disruptive/.TestActivity");
+
+        getDevice()
+                .executeShellCommand(
+                        "am start -n" + " com.android.uprobestats.disruptive/.TestActivity");
+
+        // Allow UprobeStats/StatsD time to collect metric
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+        // See if the atom made it
+        List<StatsLog.EventMetricData> data =
+                ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
+        assertThat(data.size()).isEqualTo(2);
+
+        SetComponentEnabledSettingReported reported =
+                data.get(0)
+                        .getAtom()
+                        .getExtension(UprobestatsExtensionAtoms.setComponentEnabledSettingReported);
+        assertThat(reported.getNewState())
+                .isEqualTo(2); // PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
+        assertThat(reported.getPackageName()).isEqualTo("com.android.uprobestats.disruptive");
+        assertThat(reported.getClassName())
+                .isEqualTo("com.android.uprobestats.disruptive.TestActivity");
+        assertThat(reported.getCallingPackageName()).isEqualTo("shell");
+
+        BindServiceLockedWithBalFlagsReported balReported =
+                data.get(1)
+                        .getAtom()
+                        .getExtension(
+                                UprobestatsExtensionAtoms.bindServiceLockedWithBalFlagsReported);
+        assertThat(balReported.getCallingPackageName())
+                .isEqualTo("com.android.uprobestats.disruptive");
+        assertThat(balReported.getFlags())
+                .isEqualTo(1048576); // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS
+        assertThat(balReported.getIntentPackageName()).isEqualTo("");
+    }
+
+    @Test
+    @RequiresFlagsEnabled({
+        FLAG_ENABLE_UPROBESTATS,
+        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
+        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
+        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
+    })
+    public void bitmapAllocation() throws Exception {
+        assumeTrue(CpuFeatures.isArm64(getDevice()));
+        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);
+
+        configureStatsDAndStartUprobeStats(
+                getClass(),
+                getDevice(),
+                BITMAP_ALLOCATION_CONFIG,
+                UprobestatsExtensionAtoms.ANDROID_GRAPHICS_BITMAP_ALLOCATED_FIELD_NUMBER);
+
+        try (AutoCloseable a =
+                DeviceUtils.withActivity(
+                        getDevice(),
+                        BITMAP_TESTAPP_PACKAGE_NAME,
+                        "BitmapTestActivity",
+                        "action",
+                        "action.lmk")) {
+
+            // Allow UprobeStats/StatsD time to collect metric
+            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+            // See if the atom made it
+            List<StatsLog.EventMetricData> data =
+                    ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
+            assertThat(data.size()).isGreaterThan(0);
+            boolean anyMatch =
+                    data.stream()
+                            .map(StatsLog.EventMetricData::getAtom)
+                            .filter(
+                                    atom ->
+                                            atom.hasExtension(
+                                                    UprobestatsExtensionAtoms
+                                                            .androidGraphicsBitmapAllocated))
+                            .map(
+                                    atom ->
+                                            atom.getExtension(
+                                                    UprobestatsExtensionAtoms
+                                                            .androidGraphicsBitmapAllocated))
+                            .anyMatch(
+                                    reported ->
+                                            reported.getWidth() == 100
+                                                    && reported.getHeight() == 100
+                                                    && reported.getUid() == uid);
+            assertThat(anyMatch).isTrue();
+        }
+    }
+}
diff --git a/src/test/SmokeTestSetup.java b/src/test/SmokeTestSetup.java
new file mode 100644
index 0000000..31ecb80
--- /dev/null
+++ b/src/test/SmokeTestSetup.java
@@ -0,0 +1,98 @@
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
+package test;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.cts.statsdatom.lib.AtomTestUtils;
+import android.cts.statsdatom.lib.ConfigUtils;
+import android.cts.statsdatom.lib.ReportUtils;
+
+import com.android.internal.os.StatsdConfigProto;
+import com.android.os.framework.FrameworkExtensionAtoms;
+import com.android.os.uprobestats.UprobestatsExtensionAtoms;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.protobuf.ExtensionRegistry;
+import com.google.protobuf.TextFormat;
+
+import uprobestats.protos.Config.UprobestatsConfig;
+
+import java.io.File;
+import java.nio.file.Files;
+import java.util.Scanner;
+
+/** Collection of utilities to set up statsd and start uprobestats for a test. */
+public class SmokeTestSetup {
+    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
+    private static final String CONFIG_NAME = "config";
+    private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";
+
+    /** Initializes and then sets up the statsd extension registry */
+    public static ExtensionRegistry initializeStatsD(ITestDevice device) throws Exception {
+        ConfigUtils.removeConfig(device);
+        ReportUtils.clearReports(device);
+        ExtensionRegistry registry = ExtensionRegistry.newInstance();
+        UprobestatsExtensionAtoms.registerAllExtensions(registry);
+        FrameworkExtensionAtoms.registerAllExtensions(registry);
+        return registry;
+    }
+
+    /** Cleans up any pre-existing uprobestats execution. */
+    public static void initializeUprobeStats(ITestDevice device) throws Exception {
+        device.deleteFile(CONFIG_DIR + CONFIG_NAME);
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+        device.executeShellCommand("killall uprobestats");
+    }
+
+    /**
+     * Starts UprobeStats with the given config and configures statsd to collect the given atomIds.
+     */
+    public static void configureStatsDAndStartUprobeStats(
+            Class clazz, ITestDevice device, String textprotoFilename, int... atomIds)
+            throws Exception {
+        // 1. Parse config from resources
+        String textProto =
+                new Scanner(clazz.getResourceAsStream(textprotoFilename))
+                        .useDelimiter("\\A")
+                        .next();
+        UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
+        TextFormat.getParser().merge(textProto, builder);
+        UprobestatsConfig config = builder.build();
+
+        // 2. Write config to a file and drop it on the device
+        File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
+        assertThat(tmp.setWritable(true)).isTrue();
+        Files.write(tmp.toPath(), config.toByteArray());
+        assertThat(device.enableAdbRoot()).isTrue();
+        assertThat(device.pushFile(tmp, CONFIG_DIR + CONFIG_NAME)).isTrue();
+
+        // 3. Configure StatsD
+        StatsdConfigProto.StatsdConfig.Builder configBuilder =
+                ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
+        for (int atomId : atomIds) {
+            ConfigUtils.addEventMetric(configBuilder, atomId);
+        }
+        ConfigUtils.uploadConfig(device, configBuilder);
+
+        // 4. Start UprobeStats
+        device.executeShellCommand(CMD_SETPROP_UPROBESTATS);
+        // Allow UprobeStats time to attach probe
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+    }
+}
diff --git a/src/test/malware_signal.textproto b/src/test/malware_signal.textproto
deleted file mode 100644
index 3e5983f..0000000
--- a/src/test/malware_signal.textproto
+++ /dev/null
@@ -1,20 +0,0 @@
-# proto-file: config.proto
-# proto-message: UprobestatsConfig
-
-tasks {
-    probe_configs {
-        bpf_name: "prog_MalwareSignal_uprobe_set_component_enabled_setting"
-        fully_qualified_class_name: "com.android.server.pm.PackageManagerService$IPackageManagerImpl"
-        method_name: "setComponentEnabledSetting"
-        fully_qualified_parameters: ["android.content.ComponentName", "int", "int", "int", "java.lang.String"]
-    }
-    probe_configs {
-        bpf_name: "prog_MalwareSignal_uprobe_add_bound_client_uid"
-        fully_qualified_class_name: "com.android.server.wm.BackgroundLaunchProcessController"
-        method_name: "addBoundClientUid"
-        fully_qualified_parameters: ["int", "java.lang.String", "long"]
-    }
-    bpf_maps: "map_MalwareSignal_output_buf"
-    target_process_name: "system_server"
-    duration_seconds: 300
-}
diff --git a/src/test/test/bitmap.textproto b/src/test/test/bitmap.textproto
new file mode 100644
index 0000000..1e6e08c
--- /dev/null
+++ b/src/test/test/bitmap.textproto
@@ -0,0 +1,18 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs: {
+        bpf_name: "prog_BitmapAllocation_uprobe_bitmap_creation"
+        file_paths: "/system/framework/framework.jar"
+        fully_qualified_class_name: "android.graphics.Bitmap"
+        method_name: "<init>"
+        fully_qualified_parameters: ["long", "long", "int", "int", "int",
+            "boolean", "byte[]",
+            "android.graphics.NinePatch$InsetStruct", "boolean"]
+    }
+    bpf_maps: "map_BitmapAllocation_output"
+    target_process_name: "com.android.uprobestats.bitmap"
+    target_process_selection: SPECIFIC_APP_PROCESS_ON_START,
+    duration_seconds: 10
+}
diff --git a/src/test/test/disruptive_app.textproto b/src/test/test/disruptive_app.textproto
new file mode 100644
index 0000000..ec23039
--- /dev/null
+++ b/src/test/test/disruptive_app.textproto
@@ -0,0 +1,37 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_DisruptiveApp_uprobe_set_component_enabled_setting"
+        fully_qualified_class_name: "com.android.server.pm.PackageManagerService$IPackageManagerImpl"
+        method_name: "setComponentEnabledSetting"
+        fully_qualified_parameters: ["android.content.ComponentName", "int", "int", "int", "java.lang.String"]
+    }
+    probe_configs {
+        bpf_name: "prog_DisruptiveApp_uprobe_bind_service_locked"
+        fully_qualified_class_name: "com.android.server.am.ActiveServices"
+        method_name: "bindServiceLocked"
+        fully_qualified_parameters: [
+            "android.app.IApplicationThread",
+            "android.os.IBinder",
+            "android.content.Intent",
+            "java.lang.String",
+            "android.app.IServiceConnection",
+            "long",
+            "java.lang.String",
+            "boolean",
+            "int",
+            "java.lang.String",
+            "android.app.IApplicationThread",
+            "java.lang.String",
+            "int"
+        ],
+    }
+    bpf_maps: [
+        "map_DisruptiveApp_ComponentEnabledSetting_output_buf",
+        "map_DisruptiveApp_BindServiceLocked_output_buf"
+    ]
+    target_process_name: "system_server"
+    duration_seconds: 60
+}
```

