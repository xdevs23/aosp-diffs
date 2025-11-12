```diff
diff --git a/Android.bp b/Android.bp
index 0c38559..21484c7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,6 +37,7 @@ rust_defaults {
         "liblibc",
         "libnix",
         "libthiserror",
+        "liblog_rust",
     ],
 }
 
diff --git a/OWNERS b/OWNERS
index 94df79d..353041c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,5 @@
 surenb@google.com
 bgeffon@google.com
 hungmn@google.com
-kawasin@google.com
\ No newline at end of file
+kawasin@google.com
+stevensd@google.com
\ No newline at end of file
diff --git a/README.md b/README.md
index 6852f39..a531dfb 100644
--- a/README.md
+++ b/README.md
@@ -1,11 +1,167 @@
-# mmd
+# Android Memory Management Daemon
 
-TBD
+## Overview
 
-## Apply rustfmt
+The Android Memory Management Daemon (mmd) is a new native daemon designed to
+handle Android memory management configuration and tunables.
+
+## Background
+
+Before mmd, Android ZRAM configurations were fragmented and offered limited
+customization. mmd addresses this by centralizing ZRAM management, enabling more
+complex configuration logic. This unified approach simplifies adding new
+features and improvements to ZRAM management. Another motivation for mmd is a
+separation of concerns between system server and swap management.
+
+## ZRAM management
+
+On boot complete, mmd will try to set up ZRAM with specified configuration. Once
+the ZRAM setup is done, mmd service is enabled to handle ZRAM maintenance tasks.
+
+With mmd ZRAM setup, ZRAM maintenance is initiated from system server by sending
+Binder requests to mmd via the
+[IMmd interface](https://cs.android.com/android/platform/superproject/main/+/main:system/memory/mmd/aidl/android/os/IMmd.aidl).
+mmd handles the actual maintenance tasks of doing ZRAM writeback and
+recompression based on its own policy. Both the scheduling from system server
+and the ZRAM maintenance policies can be configured via system properties as
+mentioned in the ZRAM maintenance section.
+
+### ZRAM setup configuration
+
+mmd ZRAM setup can be configured using following system properties:
+
+*   `mmd.zram.enabled`: whether mmd ZRAM setup is enabled. Default = `false`.
+*   `mmd.zram.comp_algorithm`: ZRAM compression algorithm. Kernel default
+    compression algorithm will be used if not specified[^zram-comp-algo].
+*   `mmd.zram.size`: ZRAM device size in bytes, or a percentage of device RAM
+    size (eg: 75%). Default = `50%`.
+*   `mmd.zram.writeback.enabled`: whether to enable ZRAM writeback. Default =
+    `false`.
+*   `mmd.zram.writeback.device_size`: the size of the writeback device in bytes
+    or percentage of the data partition. The actual device size can be adjusted
+    based on available space of the data partition. Default = `1073741824` (1
+    GiB).
+*   `mmd.zram.writeback.min_free_space_mib`: minimum free space in MiB that
+    needs to be available after the writeback device is set up. Default = `1536`
+    (1.5 GiB).
+*   `mmd.zram.recompression.enabled`: whether to enable ZRAM recompression
+    feature. Default = `false`.
+*   `mmd.zram.recompression.algorithm`: ZRAM recompression algorithm. Default =
+    `zstd`[^zram-comp-algo].
+
+### ZRAM maintenance configuration
+
+ZRAM maintenance should work out of the box, but it can be finetuned further
+using below system properties:
+
+**ZRAM maintenance scheduling:**
+
+*   `mm.zram.maintenance.first_delay_seconds`: the delay before the first ZRAM
+    maintenance is initiated. Default = `3600` (1 hour).
+*   `mm.zram.maintenance.periodic_delay_seconds`: the delay between subsequent
+    ZRAM maintenance scheduling. Default = `3600` (1 hour).
+*   `mm.zram.maintenance.idle_only`: whether to only initiate ZRAM maintenance
+    when the device is idle. Default = `true`.
+*   `mm.zram.maintenance.require_battery_not_low`: whether to require battery
+    not low before initiating ZRAM maintenance. Default = `true`.
+
+**mmd ZRAM writeback policy:**
+
+*   `mmd.zram.writeback.backoff_seconds`: the backoff time since the last
+    writeback. Default = `600` (10 minutes).
+*   `mmd.zram.writeback.idle_min_seconds`: minimum seconds to be used for
+    calculating idle page age dynamically based on memory utilization. A fixed
+    idle age will be used when this is the same as idle_max_seconds system
+    property. Default = `72000` (20 hours).
+*   `mmd.zram.writeback.idle_max_seconds`: maximum seconds to be used for
+    calculating idle page age dynamically based on memory utilization. A fixed
+    idle age will be used when this is the same as idle_min_seconds system
+    property. Default = `90000` (25 hours).
+*   `mmd.zram.writeback.huge_enabled`: whether to enable HUGE page writeback.
+    Default = `false`.
+*   `mmd.zram.writeback.idle_enabled`: whether to enable IDLE page writeback.
+    Default = `true`.
+*   `mmd.zram.writeback.huge_idle_enabled`: whether to enable HUGE_IDLE page
+    writeback. Default = `true`.
+*   `mmd.zram.writeback.min_bytes`: minimum bytes to write back in 1 round.
+    Default = `5242880` (5 MiB).
+*   `mmd.zram.writeback.max_bytes`: maximum bytes to write back in 1 round.
+    Default = `314572800` (300 MiB).
+*   `mmd.zram.writeback.max_bytes_per_day`: maximum bytes to write back in 1
+    day. Default = `1073741824` (1 GiB).
+
+**mmd ZRAM recompression policy:**
+
+*   `mmd.zram.recompression.backoff_seconds`: the backoff time since the last
+    recompression. Default = `1800` (30 minutes).
+*   `mmd.zram.recompression.min_idle_seconds`: minimum seconds to be used for
+    calculating idle page age dynamically based on memory utilization. A fixed
+    idle age will be used when this is the same as idle_max_seconds system
+    property. Default = `7200` (2 hours).
+*   `mmd.zram.recompression.max_idle_seconds`: maximum seconds to be used for
+    calculating idle page age dynamically based on memory utilization. A fixed
+    idle age will be used when this is the same as idle_min_seconds system
+    property. Default = `14400` (4 hours).
+*   `mmd.zram.recompression.threshold_bytes`: the minimum size in bytes of ZRAM
+    pages to be considered for recompression. Default = `1024` (1 KiB).
+*   `mmd.zram.recompression.huge_enabled`: whether to enable HUGE page
+    recompression. Default = `true`.
+*   `mmd.zram.recompression.idle_enabled`:`whether to enable IDLE page
+    recompression. Default =`true`.
+*   `mmd.zram.recompression.huge_idle_enabled`: whether to enable HUGE_IDLE page
+    recompression. Default = `true`.
+
+### Zram idle pages tracking
+
+mmd ZRAM maintenance marks ZRAM pages as idle based on how long it has been
+since they were last accessed. This feature requires the
+`CONFIG_ZRAM_TRACK_ENTRY_ACTIME` or `CONFIG_ZRAM_MEMORY_TRACKING` kernel configs
+to be enabled.
+
+If the kernel config is not enabled, mmd ZRAM maintenance falls back to a
+substitute logic to get idle zram pages.
+
+1.  Mark all zram pages as idle when mmd starts.
+2.  Skip next zram maintenances until required idle duration has passed.
+3.  Zram writeback/recompress idle pages. If there are remaining idle pages due
+    to writeback limit, mmd continues to writeback pages on the next zram
+    maintenance without marking pages as idle (i.e. without moving to step 4).
+4.  If all idle pages are written back, mark all zram pages as idle again and
+    move back to the step 2. If zram writeback is disabled, mmd marks all zram
+    pages as idle when zram recompression happens after the idle duration of
+    recompression.
+
+Note that idle duration of zram writeback and recompression is usually different
+and recompression is shorter. Some zram maintenances can just recompress idle
+pages and skip writeback until writeback idle duration has passed at the step 3.
+
+### Caveats
+
+mmd ZRAM maintenance is only guaranteed to work with the ZRAM device set up by
+`mmd --setup-zram`.
+
+### Existing ZRAM setup deprecation
+
+While swapon_all is still available to set up ZRAM and disk-based swap space,
+mmd is the preferred approach for ZRAM management for easier configuration and
+additional features like ZRAM recompression.
+
+When mmd ZRAM setup is enabled via mmd.zram.enabled system property:
+
+*   ZRAM setup in swapon_all implementation is a no-op.
+*   Existing ZRAM configuration such as config_zramWriteback feature in the
+    overlay config.xml file, and ro.zram.* writeback system properties are
+    ignored.
+
+## Development guide
+
+### Apply rustfmt
 
 Before upload your changes, please apply rustfmt.
 
 ```bash
 rustfmt +nightly **/*.rs
 ```
+
+[^zram-comp-algo] `cat /sys/block/zram0/comp_algorithm` gives the available
+compression algorithms (as well as the current one included in brackets).
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 88354a1..80829c1 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,5 +1,5 @@
 {
-  "postsubmit": [
+  "presubmit": [
     {
       "name": "mmd_unit_tests"
     },
diff --git a/src/atom.rs b/src/atom.rs
index c218557..b9fc2e2 100644
--- a/src/atom.rs
+++ b/src/atom.rs
@@ -19,12 +19,14 @@ use mmd::os::get_page_size;
 use mmd::zram::recompression::Error as ZramRecompressionError;
 use mmd::zram::setup::ZramActivationError;
 use mmd::zram::stats::ZramBdStat;
+use mmd::zram::stats::ZramIoStat;
 use mmd::zram::stats::ZramMmStat;
 use mmd::zram::writeback::Error as ZramWritebackError;
 use mmd::zram::writeback::WritebackDetails;
 use mmd::zram::SysfsZramApi;
 use mmd::zram::SysfsZramApiImpl;
 use statslog_rust::zram_bd_stat_mmd::ZramBdStatMmd;
+use statslog_rust::zram_io_stat_mmd::ZramIoStatMmd;
 use statslog_rust::zram_maintenance_executed::RecompressionResult;
 use statslog_rust::zram_maintenance_executed::WritebackResult;
 use statslog_rust::zram_maintenance_executed::ZramMaintenanceExecuted;
@@ -76,6 +78,7 @@ pub fn update_writeback_metrics(
         Err(ZramWritebackError::InvalidWritebackLimit) => WritebackResult::WritebackInvalidLimit,
         Err(ZramWritebackError::CalculateIdle(_)) => WritebackResult::WritebackCalculateIdleFail,
         Err(ZramWritebackError::MarkIdle(_)) => WritebackResult::WritebackMarkIdleFail,
+        Err(ZramWritebackError::TryMarkIdleAgain) => WritebackResult::WritebackTryMarkIdleAgain,
         Err(ZramWritebackError::Writeback(_)) => WritebackResult::WritebackTriggerFail,
         Err(ZramWritebackError::WritebackLimit(_)) => {
             WritebackResult::WritebackAccessWritebackLimitFail
@@ -115,6 +118,9 @@ pub fn update_recompress_metrics(
             RecompressionResult::RecompressionCalculateIdleFail
         }
         Err(ZramRecompressionError::MarkIdle(_)) => RecompressionResult::RecompressionMarkIdleFail,
+        Err(ZramRecompressionError::TryMarkIdleAgain) => {
+            RecompressionResult::RecompressionTryMarkIdleAgain
+        }
         Err(ZramRecompressionError::Recompress(_)) => RecompressionResult::RecompressionTriggerFail,
     };
 }
@@ -133,6 +139,9 @@ pub fn report_zram_mm_stat() -> StatsPullResult {
 fn generate_zram_mm_stat_atom<Z: SysfsZramApi>() -> Result<ZramMmStatMmd, mmd::zram::stats::Error> {
     let stat = ZramMmStat::load::<Z>()?;
     let kb_per_page = get_page_size() / KB;
+    let huge_pages_kb = stat.huge_pages.unwrap_or(0).saturating_mul(kb_per_page);
+    let huge_pages_since_kb = stat.huge_pages_since.unwrap_or(0).saturating_mul(kb_per_page);
+    let huge_pages_removed_since_kb = huge_pages_since_kb.saturating_sub(huge_pages_kb);
     Ok(ZramMmStatMmd {
         orig_data_kb: u64_to_i64(stat.orig_data_size / KB),
         compr_data_kb: u64_to_i64(stat.compr_data_size / KB),
@@ -141,10 +150,9 @@ fn generate_zram_mm_stat_atom<Z: SysfsZramApi>() -> Result<ZramMmStatMmd, mmd::z
         mem_used_max_kb: stat.mem_used_max / (KB as i64),
         same_pages_kb: u64_to_i64(stat.same_pages.saturating_mul(kb_per_page)),
         pages_compacted_kb: (stat.pages_compacted as i64).saturating_mul(kb_per_page as i64),
-        huge_pages_kb: u64_to_i64(stat.huge_pages.unwrap_or(0).saturating_mul(kb_per_page)),
-        huge_pages_since_kb: u64_to_i64(
-            stat.huge_pages_since.unwrap_or(0).saturating_mul(kb_per_page),
-        ),
+        huge_pages_kb: u64_to_i64(huge_pages_kb),
+        huge_pages_since_kb: u64_to_i64(huge_pages_since_kb),
+        huge_pages_removed_since_kb: u64_to_i64(huge_pages_removed_since_kb),
     })
 }
 
@@ -169,6 +177,27 @@ fn generate_zram_bd_stat_atom<Z: SysfsZramApi>() -> Result<ZramBdStatMmd, mmd::z
     })
 }
 
+/// Reports ZramIoStatMmd atom.
+pub fn report_zram_io_stat() -> StatsPullResult {
+    match generate_zram_io_stat_atom::<SysfsZramApiImpl>() {
+        Ok(atom) => vec![Box::new(atom)],
+        Err(e) => {
+            error!("failed to load io stat atom: {:?}", e);
+            vec![]
+        }
+    }
+}
+
+fn generate_zram_io_stat_atom<Z: SysfsZramApi>() -> Result<ZramIoStatMmd, mmd::zram::stats::Error> {
+    let stat = ZramIoStat::load::<Z>()?;
+    Ok(ZramIoStatMmd {
+        failed_reads: u64_to_i64(stat.failed_reads),
+        failed_writes: u64_to_i64(stat.failed_writes),
+        invalid_io: u64_to_i64(stat.invalid_io),
+        notify_free: u64_to_i64(stat.notify_free),
+    })
+}
+
 /// Update [ZramSetupExecuted] based on the result of zram activation.
 pub fn update_zram_setup_metrics(
     atom: &mut ZramSetupExecuted,
@@ -222,7 +251,7 @@ mod tests {
             }),
         );
 
-        assert!(matches!(atom.writeback_result, WritebackResult::WritebackSuccess));
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
         assert_eq!(atom.writeback_huge_idle_pages, 1);
         assert_eq!(atom.writeback_idle_pages, 12345);
         assert_eq!(atom.writeback_huge_pages, i64::MAX);
@@ -255,21 +284,27 @@ mod tests {
     fn test_update_writeback_metrics_on_failure() {
         let mut atom = create_default_maintenance_atom();
         update_writeback_metrics(&mut atom, &Err(ZramWritebackError::BackoffTime));
-        assert!(matches!(atom.writeback_result, WritebackResult::WritebackBackoffTime));
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackBackoffTime as i32);
     }
 
     #[test]
     fn test_update_recompress_metrics_success() {
         let mut atom = create_default_maintenance_atom();
         update_recompress_metrics(&mut atom, &Ok(()));
-        assert!(matches!(atom.recompression_result, RecompressionResult::RecompressionSuccess));
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
     }
 
     #[test]
     fn test_update_recompress_metrics_on_failure() {
         let mut atom = create_default_maintenance_atom();
         update_recompress_metrics(&mut atom, &Err(ZramRecompressionError::BackoffTime));
-        assert!(matches!(atom.recompression_result, RecompressionResult::RecompressionBackoffTime));
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionBackoffTime as i32
+        );
     }
 
     #[test]
@@ -277,7 +312,7 @@ mod tests {
         let _m = ZRAM_API_MTX.lock();
         let mock = MockSysfsZramApi::read_mm_stat_context();
         mock.expect().returning(move || {
-            Ok(format!("123456 {} 1023 1024 1235 1 {} 12345 {}", u64::MAX, u32::MAX, u64::MAX))
+            Ok(format!("123456 {} 1023 1024 1235 1 {} 12345 23456", u64::MAX, u32::MAX))
         });
 
         let result = generate_zram_mm_stat_atom::<MockSysfsZramApi>();
@@ -293,7 +328,8 @@ mod tests {
         assert_eq!(atom.same_pages_kb, kb_per_page);
         assert_eq!(atom.pages_compacted_kb, u32::MAX as i64 * kb_per_page);
         assert_eq!(atom.huge_pages_kb, 12345 * kb_per_page);
-        assert_eq!(atom.huge_pages_since_kb, i64::MAX);
+        assert_eq!(atom.huge_pages_since_kb, 23456 * kb_per_page);
+        assert_eq!(atom.huge_pages_removed_since_kb, 11111 * kb_per_page);
     }
 
     #[test]
@@ -311,6 +347,7 @@ mod tests {
         assert_eq!(atom.pages_compacted_kb, 7 * kb_per_page);
         assert_eq!(atom.huge_pages_kb, 0);
         assert_eq!(atom.huge_pages_since_kb, 0);
+        assert_eq!(atom.huge_pages_removed_since_kb, 0);
     }
 
     #[test]
diff --git a/src/block_dev.rs b/src/block_dev.rs
index 91d9ed7..7012ca6 100644
--- a/src/block_dev.rs
+++ b/src/block_dev.rs
@@ -19,6 +19,8 @@ use std::os::unix::fs::MetadataExt;
 use std::path::Path;
 use std::path::PathBuf;
 
+use log::debug;
+
 /// Error from block device operations.
 #[derive(Debug, thiserror::Error)]
 pub enum BlockDeviceError {
@@ -79,12 +81,15 @@ fn configure_block_device_queue_depth_with_sysfs(
 /// which the file exists.
 fn find_backing_block_device(file_path: &Path, sysfs_path: &str) -> Result<String> {
     let mut device_name = get_block_device_name(file_path, sysfs_path)?;
+    debug!("{file_path:?} is backed by {device_name}");
 
     while let Some(parent_device) = get_parent_block_device(&device_name, sysfs_path)? {
+        debug!("{device_name} -> {parent_device}");
         device_name = parent_device;
     }
 
     device_name = partition_parent(&device_name, sysfs_path)?;
+    debug!("Partition parent: {device_name}");
 
     Ok(device_name)
 }
@@ -98,6 +103,7 @@ fn get_block_device_name(file_path: &Path, sysfs_path: &str) -> Result<String> {
     // TODO: b/388993276 - Use nix::sys::stat::major|minor once they are configured to be built for Android.
     // SAFETY: devnum should be valid because it's from file metadata.
     let (major, minor) = unsafe { (libc::major(devnum), libc::minor(devnum)) };
+    debug!("{file_path:?} device numbers: {major}:{minor}");
     let device_path = std::fs::canonicalize(format!("{sysfs_path}/dev/block/{major}:{minor}"))?;
     Ok(device_path
         .file_name()
diff --git a/src/main.rs b/src/main.rs
index 6655c76..51785b7 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -41,13 +41,18 @@ use mmd::os::get_page_size;
 use mmd::size_spec::parse_size_spec;
 use mmd::suspend_history::SuspendHistory;
 use mmd::suspend_history::SuspendMonitor;
+use mmd::time::TimeApi;
 use mmd::time::TimeApiImpl;
+use mmd::zram::idle::IdleMarker;
+use mmd::zram::idle::TrackedIdleMarker;
+use mmd::zram::idle::UntrackedIdleMarker;
 use mmd::zram::recompression::get_zram_recompression_status;
 use mmd::zram::recompression::ZramRecompression;
 use mmd::zram::recompression::ZramRecompressionStatus;
 use mmd::zram::setup::activate_zram;
 use mmd::zram::setup::create_zram_writeback_device;
 use mmd::zram::setup::enable_zram_writeback_limit;
+use mmd::zram::setup::get_supported_compression_algorithms;
 use mmd::zram::setup::is_zram_swap_activated;
 use mmd::zram::setup::SetupApiImpl;
 use mmd::zram::setup::WritebackDeviceSetupError;
@@ -71,16 +76,40 @@ use statspull_rust::set_pull_atom_callback;
 
 use crate::atom::create_default_setup_atom;
 use crate::atom::report_zram_bd_stat;
+use crate::atom::report_zram_io_stat;
 use crate::atom::report_zram_mm_stat;
 use crate::atom::update_zram_setup_metrics;
 use crate::properties::is_zram_enabled;
 use crate::properties::BoolProp;
 use crate::properties::StringProp;
 
-struct ZramContext {
+enum ZramIdleMarker<Z: SysfsZramApi, T: TimeApi> {
+    /// When zram is built with idle tracking support via CONFIG_ZRAM_MEMORY_TRACKING or
+    /// CONFIG_ZRAM_TRACK_ENTRY_ACTIME, we will mark blocks as idle based on the calculations
+    /// performed by mmd.
+    Tracked(TrackedIdleMarker<Z>),
+
+    /// If zram does not support tracking our only option for idle, writeback is periodically
+    /// marking all blocks in zram as idle. Any blocks remaining after another idle period will
+    /// be known to be at least the idle period in age. This approach has the limitation that
+    /// we can never writeback more frequently than the idle period.
+    Untracked(UntrackedIdleMarker<T>),
+}
+
+impl<Z: SysfsZramApi, T: TimeApi> ZramIdleMarker<Z, T> {
+    fn as_idle_marker(&self) -> &dyn IdleMarker {
+        match self {
+            ZramIdleMarker::Tracked(m) => m,
+            ZramIdleMarker::Untracked(m) => m,
+        }
+    }
+}
+
+struct ZramContext<Z: SysfsZramApi, T: TimeApi> {
     zram_writeback: Option<ZramWriteback>,
     zram_recompression: Option<ZramRecompression>,
     suspend_history: SuspendHistory,
+    idle_marker: ZramIdleMarker<Z, T>,
     last_maintenance_at: Instant,
 }
 
@@ -325,6 +354,24 @@ fn setup_zram_recompression() -> Result<(), RecompressionError> {
 
     let recompression_algorithm =
         StringProp::ZramRecompressionAlgorithm.get(DEFAULT_ZRAM_RECOMPRESSION_ALGORITHM);
+    let supported_algorithms = get_supported_compression_algorithms::<SysfsZramApiImpl>()
+        .context("failed to get supported zram compression algorithms")
+        .map_err(|e| RecompressionError {
+            source: e,
+            // TODO: b/402163036 - Add ReadSupportedAlgorithms error code for recompression setup result.
+            reason: RecompressionSetupResult::RecompressionSetupUnspecified,
+        })?;
+    if !supported_algorithms.contains(&recompression_algorithm) {
+        return Err(RecompressionError {
+            source: anyhow!(
+                "zram recompression algorithm {recompression_algorithm} is not supported by the \
+                kernel, please use one of the following algorithms: {supported_algorithms:?}"
+            ),
+            // TODO: b/402163036 - Add InvalidInput error code for recompression setup result.
+            reason: RecompressionSetupResult::RecompressionSetupUnspecified,
+        });
+    }
+
     let recomp_algo_config = format!("algo={recompression_algorithm}");
     SysfsZramApiImpl::write_recomp_algorithm(&recomp_algo_config)
         .context(format!(
@@ -338,6 +385,47 @@ fn setup_zram_recompression() -> Result<(), RecompressionError> {
     Ok(())
 }
 
+#[derive(thiserror::Error)]
+#[error("{source}")]
+struct CompressionAlgoSetupError {
+    source: anyhow::Error,
+    reason: CompAlgorithmSetupResult,
+}
+
+impl std::fmt::Debug for CompressionAlgoSetupError {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "{0:?}", self.source)
+    }
+}
+
+fn setup_zram_comp_algorithm(comp_algorithm: String) -> Result<(), CompressionAlgoSetupError> {
+    let supported_algorithms = get_supported_compression_algorithms::<SysfsZramApiImpl>()
+        .context("failed to get supported zram compression algorithms")
+        .map_err(|e| CompressionAlgoSetupError {
+            source: e,
+            // TODO: b/402163036 - Add ReadSupportedAlgorithms error code for compression algo setup
+            // result.
+            reason: CompAlgorithmSetupResult::CompAlgorithmSetupUnspecified,
+        })?;
+    if !supported_algorithms.contains(&comp_algorithm) {
+        return Err(CompressionAlgoSetupError {
+            source: anyhow!(
+                "zram compression algorithm {comp_algorithm} is not supported by the \
+                kernel, please use one of the following algorithms: {supported_algorithms:?}"
+            ),
+            // TODO: b/402163036 - Add InvalidInput error code for compression algo setup result.
+            reason: CompAlgorithmSetupResult::CompAlgorithmSetupUnspecified,
+        });
+    }
+    SysfsZramApiImpl::write_comp_algorithm(&comp_algorithm)
+        .context(format!("Failed to set up compression algorithm with config {comp_algorithm}"))
+        .map_err(|e| CompressionAlgoSetupError {
+            source: e,
+            reason: CompAlgorithmSetupResult::CompAlgorithmSetupFail,
+        })?;
+    Ok(())
+}
+
 fn setup_zram(zram_setup_atom: &mut ZramSetupExecuted) -> anyhow::Result<()> {
     zram_setup_atom.zram_setup_result = ZramSetupResult::ZramSetupCheckStatus;
     let zram_activated = is_zram_swap_activated::<SetupApiImpl>()?;
@@ -396,17 +484,15 @@ fn setup_zram(zram_setup_atom: &mut ZramSetupExecuted) -> anyhow::Result<()> {
     )?;
     let comp_algorithm = StringProp::ZramCompAlgorithm.get("");
     if !comp_algorithm.is_empty() {
-        match SysfsZramApiImpl::write_comp_algorithm(&comp_algorithm) {
+        match setup_zram_comp_algorithm(comp_algorithm) {
             Ok(_) => {
                 zram_setup_atom.comp_algorithm_setup_result =
                     CompAlgorithmSetupResult::CompAlgorithmSetupSuccess;
             }
             Err(e) => {
-                // Continue to utilize zram with default algorithm if specifying algorithm fails
-                // (e.g. the algorithm is not supported by the kernel).
+                // Continue to utilize zram with default algorithm if specifying algorithm fails.
                 error!("failed to update zram comp algorithm: {e:?}");
-                zram_setup_atom.comp_algorithm_setup_result =
-                    CompAlgorithmSetupResult::CompAlgorithmSetupFail;
+                zram_setup_atom.comp_algorithm_setup_result = e.reason;
             }
         }
     }
@@ -432,6 +518,8 @@ fn main() {
     }
 
     let _init_success = logger::init(
+        // TODO: b/376123745 - Update logging level to Info before releasing mmd to avoid logging
+        // spams.
         logger::Config::default().with_tag_on_device("mmd").with_max_level(LevelFilter::Trace),
     );
 
@@ -461,7 +549,7 @@ fn main() {
         return;
     }
 
-    let mut zram_writeback = match load_zram_writeback_disk_size() {
+    let zram_writeback = match load_zram_writeback_disk_size() {
         Ok(Some(zram_writeback_disk_size)) => {
             info!("zram writeback is activated");
             match load_total_zram_size::<SysfsZramApiImpl>() {
@@ -484,7 +572,7 @@ fn main() {
         }
     };
 
-    let mut zram_recompression = match get_zram_recompression_status::<SysfsZramApiImpl>() {
+    let zram_recompression = match get_zram_recompression_status::<SysfsZramApiImpl>() {
         Ok(status) => {
             if status == ZramRecompressionStatus::Activated {
                 info!("zram recompression is activated");
@@ -500,21 +588,20 @@ fn main() {
         }
     };
 
+    let mut idle_marker = ZramIdleMarker::Tracked(TrackedIdleMarker::<SysfsZramApiImpl>::new());
     if zram_writeback.is_some() || zram_recompression.is_some() {
         match is_idle_aging_supported() {
             Ok(idle_aging_supported) => {
                 if !idle_aging_supported {
                     warn!(
-                        "mmd zram maintenance is disabled due to missing kernel config. mmd zram \
-                        maintenance requires either CONFIG_ZRAM_TRACK_ENTRY_ACTIME or \
-                        CONFIG_ZRAM_MEMORY_TRACKING kernel config enabled for tracking idle pages \
-                        based on last accessed time."
+                        "Neither CONFIG_ZRAM_MEMORY_TRACKING nor CONFIG_ZRAM_TRACK_ENTRY_ACTIME \
+                        kernel config is enabled. Fallback to untracked idle page marker."
                     );
-                    // TODO: b/396439110 - Implement some zram maintenance fallback logic to
-                    // support the case when idle aging is not supported by the kernel. Eg: only
-                    // handle huge pages.
-                    zram_writeback = None;
-                    zram_recompression = None;
+                    let mut marker = UntrackedIdleMarker::<TimeApiImpl>::new();
+                    if let Err(e) = marker.refresh::<SysfsZramApiImpl>() {
+                        error!("failed to refresh untracked idle page marker on start: {e:?}");
+                    }
+                    idle_marker = ZramIdleMarker::Untracked(marker);
                 }
             }
             Err(e) => {
@@ -524,12 +611,13 @@ fn main() {
                 );
             }
         }
-    };
+    }
 
     let ctx = Arc::new(Mutex::new(ZramContext {
         zram_writeback,
         zram_recompression,
         suspend_history: SuspendHistory::new(),
+        idle_marker,
         last_maintenance_at: Instant::now(),
     }));
 
@@ -574,6 +662,11 @@ fn main() {
             None,
             report_zram_bd_stat,
         );
+        set_pull_atom_callback(
+            statslog_rust_header::Atoms::ZramIoStatMmd,
+            None,
+            report_zram_io_stat,
+        );
     }
 
     info!("mmd started");
diff --git a/src/os.rs b/src/os.rs
index 4579d4e..30862e9 100644
--- a/src/os.rs
+++ b/src/os.rs
@@ -23,7 +23,7 @@ use nix::unistd::SysconfVar;
 const MEMINFO_PATH: &str = "/proc/meminfo";
 
 /// [MeminfoApi] is a mockable interface for access to "/proc/meminfo".
-#[cfg_attr(test, mockall::automock)]
+#[cfg_attr(any(test, feature = "test_utils"), mockall::automock)]
 pub trait MeminfoApi {
     /// read "/proc/meminfo".
     fn read_meminfo() -> io::Result<String>;
@@ -43,7 +43,7 @@ impl MeminfoApi for MeminfoApiImpl {
 /// mockall for static functions requires synchronization.
 ///
 /// https://docs.rs/mockall/latest/mockall/#static-methods
-#[cfg(test)]
+#[cfg(any(test, feature = "test_utils"))]
 pub static MEMINFO_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
 
 /// Returns the page size of the system.
diff --git a/src/service.rs b/src/service.rs
index 0e29c3b..5728906 100644
--- a/src/service.rs
+++ b/src/service.rs
@@ -12,6 +12,9 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#[cfg(test)]
+mod tests;
+
 use std::ops::DerefMut;
 use std::sync::Arc;
 use std::sync::Mutex;
@@ -22,15 +25,16 @@ use binder::Interface;
 use binder::Result as BinderResult;
 use log::error;
 use log::info;
+use mmd::os::MeminfoApi;
 use mmd::os::MeminfoApiImpl;
 use mmd::suspend_history::SuspendHistory;
 use mmd::time::TimeApi;
-use mmd::time::TimeApiImpl;
+use mmd::zram::idle::IdleMarker;
 use mmd::zram::recompression::Error as ZramRecompressionError;
 use mmd::zram::recompression::ZramRecompression;
 use mmd::zram::writeback::Error as ZramWritebackError;
 use mmd::zram::writeback::ZramWriteback;
-use mmd::zram::SysfsZramApiImpl;
+use mmd::zram::SysfsZramApi;
 use mmd_aidl_interface::aidl::android::os::IMmd::IMmd;
 use statslog_rust::zram_maintenance_executed::ZramMaintenanceExecuted;
 
@@ -41,22 +45,28 @@ use crate::properties::BoolProp;
 use crate::properties::SecondsProp;
 use crate::properties::U64Prop;
 use crate::ZramContext;
+use crate::ZramIdleMarker;
 use crate::DEFAULT_ZRAM_RECOMPRESSION_ENABLED;
 use crate::DEFAULT_ZRAM_WRITEBACK_ENABLED;
 
-pub struct MmdService {
-    ctx: Arc<Mutex<ZramContext>>,
+pub struct MmdService<Z: SysfsZramApi, T: TimeApi> {
+    ctx: Arc<Mutex<ZramContext<Z, T>>>,
 }
 
-impl MmdService {
-    pub fn new(ctx: Arc<Mutex<ZramContext>>) -> Self {
+impl<Z: SysfsZramApi, T: TimeApi> MmdService<Z, T> {
+    pub fn new(ctx: Arc<Mutex<ZramContext<Z, T>>>) -> Self {
         Self { ctx }
     }
 }
 
-impl Interface for MmdService {}
+impl<Z: SysfsZramApi + std::marker::Send + 'static, T: TimeApi + std::marker::Send + 'static>
+    Interface for MmdService<Z, T>
+{
+}
 
-impl IMmd for MmdService {
+impl<Z: SysfsZramApi + std::marker::Send + 'static, T: TimeApi + std::marker::Send + 'static> IMmd
+    for MmdService<Z, T>
+{
     fn doZramMaintenanceAsync(&self) -> BinderResult<()> {
         let mut atom = create_default_maintenance_atom();
         let mut ctx = self.ctx.lock().expect("mmd aborts on panics");
@@ -66,22 +76,17 @@ impl IMmd for MmdService {
             now.duration_since(ctx.last_maintenance_at).as_secs().try_into().unwrap_or(i64::MAX);
         ctx.last_maintenance_at = now;
 
-        let ZramContext { zram_writeback, zram_recompression, suspend_history, .. } =
-            ctx.deref_mut();
-
-        // Execute writeback before recompression. Current kernel decompresses
-        // pages in zram before writing it back to disk.
-        if BoolProp::ZramWritebackEnabled.get(DEFAULT_ZRAM_WRITEBACK_ENABLED) {
-            if let Some(zram_writeback) = zram_writeback.as_mut() {
-                handle_zram_writeback(zram_writeback, suspend_history, &mut atom);
-            }
-        }
-
-        if BoolProp::ZramRecompressionEnabled.get(DEFAULT_ZRAM_RECOMPRESSION_ENABLED) {
-            if let Some(zram_recompression) = zram_recompression.as_mut() {
-                handle_zram_recompression(zram_recompression, suspend_history, &mut atom);
-            }
-        }
+        // Pass the loaded system properties here for the testability of
+        // `handle_zram_maintenance()`. Loading parameters may be useless if the zram maintenance
+        // context (i.e. ZramWriteback or ZramRecompression) is none. However it is rare when the
+        // feature system prop (i.e. BoolProp::ZramWritebackEnabled,
+        // BoolProp::ZramRecompressionEnabled) is enabled.
+        handle_zram_maintenance::<Z, MeminfoApiImpl, T>(
+            ctx.deref_mut(),
+            &mut atom,
+            &load_zram_writeback_params(),
+            &load_zram_recompression_params(),
+        );
 
         if let Err(e) = atom.stats_write() {
             error!("failed to submit ZramMaintenanceExecuted atom: {e:?}");
@@ -96,51 +101,121 @@ impl IMmd for MmdService {
     }
 }
 
-fn handle_zram_recompression(
-    zram_recompression: &mut ZramRecompression,
-    suspend_history: &SuspendHistory,
+/// This function executes zram writeback and zram recompression if possible and update passed
+/// [ZramMaintenanceExecuted] with the results.
+///
+/// This handles any errors from zram writeback/recompression within this function and does not
+/// return anything.
+fn handle_zram_maintenance<Z: SysfsZramApi, M: MeminfoApi, T: TimeApi>(
+    ctx: &mut ZramContext<Z, T>,
     atom: &mut ZramMaintenanceExecuted,
+    writeback_params: &Option<mmd::zram::writeback::Params>,
+    recompression_params: &Option<mmd::zram::recompression::Params>,
 ) {
-    let params = load_zram_recompression_params();
+    let ZramContext { zram_writeback, zram_recompression, suspend_history, idle_marker, .. } = ctx;
+
+    let mut refresh_idle_pages = true;
+    let mut zram_maintenance_active = false;
+
+    // Execute writeback before recompression. Current kernel decompresses
+    // pages in zram before writing it back to disk.
+    if let (Some(zram_writeback), Some(params)) =
+        (zram_writeback.as_mut(), writeback_params.as_ref())
+    {
+        if !handle_zram_writeback::<Z, M, T>(
+            zram_writeback,
+            params,
+            suspend_history,
+            idle_marker.as_idle_marker(),
+            atom,
+        ) {
+            refresh_idle_pages = false;
+        }
+        zram_maintenance_active = true;
+    }
 
+    if let (Some(zram_recompression), Some(params)) =
+        (zram_recompression.as_mut(), recompression_params.as_ref())
+    {
+        if !handle_zram_recompression::<Z, M, T>(
+            zram_recompression,
+            params,
+            suspend_history,
+            idle_marker.as_idle_marker(),
+            atom,
+        ) {
+            refresh_idle_pages = false;
+        }
+        zram_maintenance_active = true;
+    }
+
+    if refresh_idle_pages && zram_maintenance_active {
+        if let ZramIdleMarker::Untracked(marker) = idle_marker {
+            if let Err(e) = marker.refresh::<Z>() {
+                error!("failed to refresh untracked idle marker: {e:?}");
+            }
+        }
+    }
+}
+
+/// Return whether it is okay to refresh IdleMarker.
+fn handle_zram_recompression<Z: SysfsZramApi, M: MeminfoApi, T: TimeApi>(
+    zram_recompression: &mut ZramRecompression,
+    params: &mmd::zram::recompression::Params,
+    suspend_history: &SuspendHistory,
+    idle_marker: &dyn IdleMarker,
+    atom: &mut ZramMaintenanceExecuted,
+) -> bool {
     let start = Instant::now();
-    let result = zram_recompression.mark_and_recompress::<SysfsZramApiImpl, MeminfoApiImpl>(
-        &params,
+    let result = zram_recompression.mark_and_recompress::<Z, M>(
+        params,
         suspend_history,
-        TimeApiImpl::get_boot_time(),
+        idle_marker,
+        T::get_boot_time(),
     );
     atom.recompress_latency_millis = start.elapsed().as_millis().try_into().unwrap_or(i64::MAX);
 
     update_recompress_metrics(atom, &result);
 
     match result {
-        Ok(_) | Err(ZramRecompressionError::BackoffTime) => {}
-        Err(e) => error!("failed to zram recompress: {e:?}"),
+        Ok(_) => true,
+        Err(ZramRecompressionError::BackoffTime)
+        | Err(ZramRecompressionError::TryMarkIdleAgain) => false,
+        Err(e) => {
+            error!("failed to zram recompress: {e:?}");
+            // If zram recompression feature is broken, this allows to refresh idle marker so that
+            // zram writeback can continue to work. Note that zram writeback don't want to refresh
+            // (e.g. there are idle pages remaining), it does refresh IdleMarker.
+            true
+        }
     }
 }
 
-fn handle_zram_writeback(
+/// Return whether it is okay to refresh IdleMarker.
+fn handle_zram_writeback<Z: SysfsZramApi, M: MeminfoApi, T: TimeApi>(
     zram_writeback: &mut ZramWriteback,
+    params: &mmd::zram::writeback::Params,
     suspend_history: &SuspendHistory,
+    idle_marker: &dyn IdleMarker,
     atom: &mut ZramMaintenanceExecuted,
-) {
-    let params = load_zram_writeback_params();
-    let stats = match load_zram_writeback_stats() {
+) -> bool {
+    let stats = match load_zram_writeback_stats::<Z>() {
         Ok(v) => v,
         Err(e) => {
             error!("failed to load zram writeback stats: {e:?}");
             atom.writeback_result =
                 statslog_rust::zram_maintenance_executed::WritebackResult::WritebackLoadStatsFail;
-            return;
+            return false;
         }
     };
 
     let start = Instant::now();
-    let result = zram_writeback.mark_and_flush_pages::<SysfsZramApiImpl, MeminfoApiImpl>(
-        &params,
+    let result = zram_writeback.mark_and_flush_pages::<Z, M>(
+        params,
         &stats,
         suspend_history,
-        TimeApiImpl::get_boot_time(),
+        idle_marker,
+        T::get_boot_time(),
     );
     atom.writeback_latency_millis = start.elapsed().as_millis().try_into().unwrap_or(i64::MAX);
 
@@ -161,13 +236,27 @@ fn handle_zram_writeback(
                     details.huge.written_pages
                 );
             }
+            // If one writeback attempt reaches the writeback_limit, it means there are still idle
+            // pages in zram. Even in that case, if huge pages are written back, it means there is
+            // no idle pages remaining because mmd always write back huge pages last.
+            details.actual_limit_pages != total_written_pages || details.huge.written_pages > 0
+        }
+        Err(ZramWritebackError::BackoffTime)
+        | Err(ZramWritebackError::Limit)
+        | Err(ZramWritebackError::TryMarkIdleAgain) => false,
+        Err(e) => {
+            error!("failed to zram writeback: {e:?}");
+            // If zram writeback feature is broken, this allows to refresh idle marker so that zram
+            // recompression can continue to work.
+            true
         }
-        Err(ZramWritebackError::BackoffTime) | Err(ZramWritebackError::Limit) => {}
-        Err(e) => error!("failed to zram writeback: {e:?}"),
     }
 }
 
-fn load_zram_writeback_params() -> mmd::zram::writeback::Params {
+fn load_zram_writeback_params() -> Option<mmd::zram::writeback::Params> {
+    if !BoolProp::ZramWritebackEnabled.get(DEFAULT_ZRAM_WRITEBACK_ENABLED) {
+        return None;
+    }
     let mut params = mmd::zram::writeback::Params::default();
     params.backoff_duration = SecondsProp::ZramWritebackBackoff.get(params.backoff_duration);
     params.min_idle = SecondsProp::ZramWritebackMinIdle.get(params.min_idle);
@@ -178,21 +267,22 @@ fn load_zram_writeback_params() -> mmd::zram::writeback::Params {
     params.min_bytes = U64Prop::ZramWritebackMinBytes.get(params.min_bytes);
     params.max_bytes = U64Prop::ZramWritebackMaxBytes.get(params.max_bytes);
     params.max_bytes_per_day = U64Prop::ZramWritebackMaxBytesPerDay.get(params.max_bytes_per_day);
-    params
+    Some(params)
 }
 
-fn load_zram_writeback_stats() -> anyhow::Result<mmd::zram::writeback::Stats> {
-    let mm_stat =
-        mmd::zram::stats::ZramMmStat::load::<SysfsZramApiImpl>().context("load mm_stat")?;
-    let bd_stat =
-        mmd::zram::stats::ZramBdStat::load::<SysfsZramApiImpl>().context("load bd_stat")?;
+fn load_zram_writeback_stats<Z: SysfsZramApi>() -> anyhow::Result<mmd::zram::writeback::Stats> {
+    let mm_stat = mmd::zram::stats::ZramMmStat::load::<Z>().context("load mm_stat")?;
+    let bd_stat = mmd::zram::stats::ZramBdStat::load::<Z>().context("load bd_stat")?;
     Ok(mmd::zram::writeback::Stats {
         orig_data_size: mm_stat.orig_data_size,
         current_writeback_pages: bd_stat.bd_count_pages,
     })
 }
 
-fn load_zram_recompression_params() -> mmd::zram::recompression::Params {
+fn load_zram_recompression_params() -> Option<mmd::zram::recompression::Params> {
+    if !BoolProp::ZramRecompressionEnabled.get(DEFAULT_ZRAM_RECOMPRESSION_ENABLED) {
+        return None;
+    }
     let mut params = mmd::zram::recompression::Params::default();
     params.backoff_duration = SecondsProp::ZramRecompressionBackoff.get(params.backoff_duration);
     params.min_idle = SecondsProp::ZramRecompressionMinIdle.get(params.min_idle);
@@ -201,50 +291,5 @@ fn load_zram_recompression_params() -> mmd::zram::recompression::Params {
     params.idle = BoolProp::ZramRecompressionIdleEnabled.get(params.idle);
     params.huge = BoolProp::ZramRecompressionHugeEnabled.get(params.huge);
     params.threshold_bytes = U64Prop::ZramRecompressionThresholdBytes.get(params.threshold_bytes);
-    params
-}
-
-#[cfg(test)]
-mod tests {
-    use mmd::suspend_history::SuspendHistory;
-    use mmd::zram::recompression::ZramRecompression;
-    use mmd::zram::writeback::ZramWriteback;
-
-    use super::*;
-
-    #[test]
-    fn test_is_zram_maintenance_supported() {
-        assert!(!MmdService::new(Arc::new(Mutex::new(ZramContext {
-            zram_writeback: None,
-            zram_recompression: None,
-            suspend_history: SuspendHistory::new(),
-            last_maintenance_at: Instant::now(),
-        })))
-        .isZramMaintenanceSupported()
-        .unwrap());
-        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
-            zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
-            zram_recompression: None,
-            suspend_history: SuspendHistory::new(),
-            last_maintenance_at: Instant::now(),
-        })))
-        .isZramMaintenanceSupported()
-        .unwrap());
-        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
-            zram_writeback: None,
-            zram_recompression: Some(ZramRecompression::new()),
-            suspend_history: SuspendHistory::new(),
-            last_maintenance_at: Instant::now(),
-        })))
-        .isZramMaintenanceSupported()
-        .unwrap());
-        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
-            zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
-            zram_recompression: Some(ZramRecompression::new()),
-            suspend_history: SuspendHistory::new(),
-            last_maintenance_at: Instant::now(),
-        })))
-        .isZramMaintenanceSupported()
-        .unwrap());
-    }
+    Some(params)
 }
diff --git a/src/service/tests.rs b/src/service/tests.rs
new file mode 100644
index 0000000..eeae7ab
--- /dev/null
+++ b/src/service/tests.rs
@@ -0,0 +1,805 @@
+// Copyright 2025, The Android Open Source Project
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
+use std::sync::LockResult;
+use std::sync::MutexGuard;
+use std::time::Duration;
+
+use mmd::os::MockMeminfoApi;
+use mmd::os::MEMINFO_API_MTX;
+use mmd::suspend_history::SuspendHistory;
+use mmd::time::BootTime;
+use mmd::time::MockTimeApi;
+use mmd::time::TimeApiImpl;
+use mmd::time::TIME_API_MTX;
+use mmd::zram::idle::TrackedIdleMarker;
+use mmd::zram::idle::UntrackedIdleMarker;
+use mmd::zram::recompression::ZramRecompression;
+use mmd::zram::writeback::ZramWriteback;
+use mmd::zram::MockSysfsZramApi;
+use mmd::zram::SysfsZramApiImpl;
+use mmd::zram::ZRAM_API_MTX;
+use mockall::predicate::*;
+use statslog_rust::zram_maintenance_executed::RecompressionResult;
+use statslog_rust::zram_maintenance_executed::WritebackResult;
+
+use super::*;
+
+const DEFAULT_TOTAL_ZRAM_SIZE: u64 = 4 << 30;
+const DEFAULT_ZRAM_WRITEBACK_SIZE: u64 = 1 << 30;
+const INITIAL_TIME: BootTime = BootTime::from_duration(Duration::from_secs(100));
+
+struct MockContext<'a> {
+    read_mm_stat: mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_mm_stat::Context,
+    read_bd_stat: mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_bd_stat::Context,
+    writeback: mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__writeback::Context,
+    write_writeback_limit:
+        mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__write_writeback_limit::Context,
+    read_writeback_limit:
+        mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_writeback_limit::Context,
+    recompress: mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__recompress::Context,
+    set_idle: mmd::zram::__mock_MockSysfsZramApi_SysfsZramApi::__set_idle::Context,
+    get_boot_time: mmd::time::__mock_MockTimeApi_TimeApi::__get_boot_time::Context,
+    read_meminfo: mmd::os::__mock_MockMeminfoApi_MeminfoApi::__read_meminfo::Context,
+    // Lock will be released after mock contexts are dropped.
+    _meminfo_lock: LockResult<MutexGuard<'a, ()>>,
+    _time_lock: LockResult<MutexGuard<'a, ()>>,
+    _zram_lock: LockResult<MutexGuard<'a, ()>>,
+}
+
+impl MockContext<'_> {
+    fn new() -> Self {
+        let _zram_lock = ZRAM_API_MTX.lock();
+        let _time_lock = TIME_API_MTX.lock();
+        let _meminfo_lock = MEMINFO_API_MTX.lock();
+        Self {
+            read_mm_stat: MockSysfsZramApi::read_mm_stat_context(),
+            read_bd_stat: MockSysfsZramApi::read_bd_stat_context(),
+            writeback: MockSysfsZramApi::writeback_context(),
+            write_writeback_limit: MockSysfsZramApi::write_writeback_limit_context(),
+            read_writeback_limit: MockSysfsZramApi::read_writeback_limit_context(),
+            recompress: MockSysfsZramApi::recompress_context(),
+            set_idle: MockSysfsZramApi::set_idle_context(),
+            get_boot_time: MockTimeApi::get_boot_time_context(),
+            read_meminfo: MockMeminfoApi::read_meminfo_context(),
+            _meminfo_lock,
+            _time_lock,
+            _zram_lock,
+        }
+    }
+
+    fn setup_zram_maintenance(&self) {
+        self.setup_default_meminfo();
+        self.setup_default_mm_stat();
+        self.setup_default_bd_stat();
+        self.write_writeback_limit.expect().returning(|_| Ok(()));
+        self.writeback.expect().returning(|_| Ok(()));
+        self.recompress.expect().returning(|_| Ok(()));
+    }
+
+    fn setup_default_meminfo(&self) {
+        let meminfo = "MemTotal: 8144296 kB
+            MemAvailable: 346452 kB";
+        self.read_meminfo.expect().returning(|| Ok(meminfo.to_string()));
+    }
+
+    fn setup_default_mm_stat(&self) {
+        // orig_data_size = 1 GB
+        self.read_mm_stat
+            .expect()
+            .returning(|| Ok(format!("{} 2 3 4 5 6 7 8 9", 1024 * 1024 * 1024)));
+    }
+
+    fn setup_default_bd_stat(&self) {
+        let bd_stat = "1 2 3";
+        self.read_bd_stat.expect().returning(|| Ok(bd_stat.to_string()));
+    }
+}
+
+fn create_zram_context_with_untracked_marker() -> ZramContext<MockSysfsZramApi, MockTimeApi> {
+    ZramContext {
+        zram_writeback: Some(ZramWriteback::new(
+            DEFAULT_TOTAL_ZRAM_SIZE,
+            DEFAULT_ZRAM_WRITEBACK_SIZE,
+        )),
+        zram_recompression: Some(ZramRecompression::new()),
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::Untracked(UntrackedIdleMarker::new()),
+        last_maintenance_at: Instant::now(),
+    }
+}
+
+fn initialize_untracked_idle_marker(
+    idle_marker: &mut ZramIdleMarker<MockSysfsZramApi, MockTimeApi>,
+    mock: &MockContext,
+) {
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time.expect().times(1).return_const(INITIAL_TIME);
+    let ZramIdleMarker::Untracked(idle_marker) = idle_marker else {
+        unreachable!();
+    };
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+}
+
+#[test]
+fn handle_zram_maintenance_success() {
+    let mut ctx = ZramContext {
+        zram_writeback: Some(ZramWriteback::new(
+            DEFAULT_TOTAL_ZRAM_SIZE,
+            DEFAULT_ZRAM_WRITEBACK_SIZE,
+        )),
+        zram_recompression: Some(ZramRecompression::new()),
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::<_, TimeApiImpl>::Tracked(
+            TrackedIdleMarker::<MockSysfsZramApi>::new(),
+        ),
+        last_maintenance_at: Instant::now(),
+    };
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
+        ..Default::default()
+    });
+    let recompression_params = Some(mmd::zram::recompression::Params::default());
+
+    let mock = MockContext::new();
+    mock.setup_zram_maintenance();
+    mock.set_idle.expect().returning(|_| Ok(()));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("99\n".to_string()));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("97\n".to_string()));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("92\n".to_string()));
+
+    handle_zram_maintenance::<_, MockMeminfoApi, _>(
+        &mut ctx,
+        &mut atom,
+        &writeback_params,
+        &recompression_params,
+    );
+
+    assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+    assert_eq!(atom.writeback_huge_idle_pages, 1);
+    assert_eq!(atom.writeback_idle_pages, 2);
+    assert_eq!(atom.writeback_huge_pages, 5);
+    assert_eq!(atom.recompression_result as i32, RecompressionResult::RecompressionSuccess as i32);
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(4000),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    });
+    let recompression_params = Some(mmd::zram::recompression::Params {
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(2000),
+        max_idle: Duration::from_secs(2000),
+        ..Default::default()
+    });
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        // Just idle duration of recompression has passed, but still waiting for writeback idle
+        // duration.
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(2000)).unwrap());
+        // Do not refresh idle marker.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTryMarkIdleAgain as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("99\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("97\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("92\n".to_string()));
+        // Refresh idle marker again.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(atom.writeback_huge_idle_pages, 1);
+        assert_eq!(atom.writeback_idle_pages, 2);
+        assert_eq!(atom.writeback_huge_pages, 5);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        // Zram maintenance again should fail due to idle marker.
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        // + 1000 seconds to avoid backoff duration failure
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(5000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTryMarkIdleAgain as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTryMarkIdleAgain as i32
+        );
+    }
+}
+
+// If there are idle pages, which is applicable for zram writeback, remaining even after zram
+// writeback, handle_zram_maintenance() does not refresh idle marker but tries to write back the
+// idle pages at the next handle_zram_maintenance().
+#[test]
+fn handle_zram_maintenance_untracked_marker_remaining_idle_page() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(4000),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    });
+    let recompression_params = Some(mmd::zram::recompression::Params {
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(2000),
+        max_idle: Duration::from_secs(2000),
+        ..Default::default()
+    });
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("70\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("0\n".to_string()));
+        // Skip huge page writeback if writeback_limit becomes 0 before huge page writeback.
+        // Do not refresh idle marker if idle page remains for writeback.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(atom.writeback_huge_idle_pages, 30);
+        assert_eq!(atom.writeback_idle_pages, 70);
+        assert_eq!(atom.writeback_huge_pages, 0);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        // Zram maintenance again should continue writeback.
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        // + 1000 seconds to avoid backoff duration failure
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(5000)).unwrap());
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("60\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("0\n".to_string()));
+        // Refresh idle marker again when huge page writeback starts.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(atom.writeback_huge_idle_pages, 0);
+        assert_eq!(atom.writeback_idle_pages, 40);
+        assert_eq!(atom.writeback_huge_pages, 60);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        // Zram maintenance again should fail due to idle marker.
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        // + 1000 seconds to avoid backoff duration failure
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(6000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTryMarkIdleAgain as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTryMarkIdleAgain as i32
+        );
+    }
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker_writeback_only() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(4000),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    });
+    let recompression_params = None;
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("0\n".to_string()));
+        // Do not refresh idle marker.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(atom.writeback_huge_idle_pages, 100);
+        assert_eq!(atom.writeback_idle_pages, 0);
+        assert_eq!(atom.writeback_huge_pages, 0);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionNotSupported as i32
+        );
+    }
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(5000)).unwrap());
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("90\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("70\n".to_string()));
+        mock.read_writeback_limit.expect().times(1).returning(|| Ok("40\n".to_string()));
+        // Refresh idle marker again.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(atom.writeback_huge_idle_pages, 10);
+        assert_eq!(atom.writeback_idle_pages, 20);
+        assert_eq!(atom.writeback_huge_pages, 30);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionNotSupported as i32
+        );
+    }
+
+    {
+        // Zram maintenance again should fail due to idle marker.
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        // + 1000 seconds to avoid backoff duration failure
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(6000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTryMarkIdleAgain as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionNotSupported as i32
+        );
+    }
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker_recompression_only() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = None;
+    let recompression_params = Some(mmd::zram::recompression::Params {
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(2000),
+        max_idle: Duration::from_secs(2000),
+        ..Default::default()
+    });
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(2000)).unwrap());
+        // Refresh idle marker again.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackNotSupported as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        // Zram maintenance again should fail due to idle marker.
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        // + 1000 seconds to avoid backoff duration failure
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(3000)).unwrap());
+        mock.set_idle.expect().with(eq("all")).times(0);
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackNotSupported as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTryMarkIdleAgain as i32
+        );
+    }
+
+    {
+        let mock = MockContext::new();
+        mock.setup_zram_maintenance();
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        // Refresh idle marker again.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackNotSupported as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker_refresh_regardless_of_writeback_failure() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(2000),
+        max_idle: Duration::from_secs(2000),
+        ..Default::default()
+    });
+    let recompression_params = Some(mmd::zram::recompression::Params {
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(4000),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    });
+
+    {
+        let mock = MockContext::new();
+        mock.setup_default_meminfo();
+        mock.setup_default_mm_stat();
+        mock.setup_default_bd_stat();
+        mock.write_writeback_limit.expect().returning(|_| Ok(()));
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+        mock.writeback.expect().returning(|_| Err(std::io::Error::other("error")));
+        mock.recompress.expect().returning(|_| Ok(()));
+        // Refresh idle marker again even if zram writeback fails.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTriggerFail as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionSuccess as i32
+        );
+    }
+
+    {
+        let mock = MockContext::new();
+        mock.setup_default_meminfo();
+        mock.setup_default_mm_stat();
+        mock.setup_default_bd_stat();
+        mock.write_writeback_limit.expect().returning(|_| Ok(()));
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(7000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+        mock.writeback.expect().returning(|_| Err(std::io::Error::other("error")));
+        // It does not refresh idle marker if zram recompression is waiting for idle duration to
+        // pass even if zram writeback fails.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTriggerFail as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTryMarkIdleAgain as i32
+        );
+    }
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker_refresh_regardless_of_recompression_failure() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = Some(mmd::zram::writeback::Params {
+        huge_idle: true,
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(4000),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    });
+    let recompression_params = Some(mmd::zram::recompression::Params {
+        backoff_duration: Duration::from_secs(1000),
+        min_idle: Duration::from_secs(2000),
+        max_idle: Duration::from_secs(2000),
+        ..Default::default()
+    });
+
+    {
+        let mock = MockContext::new();
+        mock.setup_default_meminfo();
+        mock.setup_default_mm_stat();
+        mock.setup_default_bd_stat();
+        mock.write_writeback_limit.expect().returning(|_| Ok(()));
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+        mock.writeback.expect().returning(|_| Ok(()));
+        mock.recompress.expect().returning(|_| Err(std::io::Error::other("error")));
+        // Refresh idle marker again even if zram writeback fails.
+        mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackSuccess as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTriggerFail as i32
+        );
+    }
+
+    {
+        let mock = MockContext::new();
+        mock.setup_default_meminfo();
+        mock.setup_default_mm_stat();
+        mock.setup_default_bd_stat();
+        mock.write_writeback_limit.expect().returning(|_| Ok(()));
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(7000)).unwrap());
+        mock.read_writeback_limit.expect().returning(|| Ok("100\n".to_string()));
+        mock.recompress.expect().returning(|_| Err(std::io::Error::other("error")));
+        // It does not refresh idle marker if zram recompression is waiting for idle duration to
+        // pass even if zram writeback fails.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackTryMarkIdleAgain as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionTriggerFail as i32
+        );
+    }
+}
+
+#[test]
+fn handle_zram_maintenance_untracked_marker_skip_if_writeback_and_recompress_disabled() {
+    let mut ctx = create_zram_context_with_untracked_marker();
+    let mut atom = create_default_maintenance_atom();
+    let writeback_params = None;
+    let recompression_params = None;
+
+    {
+        let mock = MockContext::new();
+        initialize_untracked_idle_marker(&mut ctx.idle_marker, &mock);
+
+        mock.get_boot_time
+            .expect()
+            .return_const(INITIAL_TIME.checked_add(Duration::from_secs(4000)).unwrap());
+        // Skip refreshing idle marker.
+        mock.set_idle.expect().with(eq("all")).times(0);
+        handle_zram_maintenance::<_, MockMeminfoApi, _>(
+            &mut ctx,
+            &mut atom,
+            &writeback_params,
+            &recompression_params,
+        );
+
+        assert_eq!(atom.writeback_result as i32, WritebackResult::WritebackNotSupported as i32);
+        assert_eq!(
+            atom.recompression_result as i32,
+            RecompressionResult::RecompressionNotSupported as i32
+        );
+    }
+}
+
+#[test]
+fn test_is_zram_maintenance_supported() {
+    assert!(!MmdService::new(Arc::new(Mutex::new(ZramContext {
+        zram_writeback: None,
+        zram_recompression: None,
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::<_, TimeApiImpl>::Tracked(
+            TrackedIdleMarker::<SysfsZramApiImpl>::new()
+        ),
+        last_maintenance_at: Instant::now(),
+    })))
+    .isZramMaintenanceSupported()
+    .unwrap());
+    assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+        zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
+        zram_recompression: None,
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::<_, TimeApiImpl>::Tracked(
+            TrackedIdleMarker::<SysfsZramApiImpl>::new()
+        ),
+        last_maintenance_at: Instant::now(),
+    })))
+    .isZramMaintenanceSupported()
+    .unwrap());
+    assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+        zram_writeback: None,
+        zram_recompression: Some(ZramRecompression::new()),
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::<_, TimeApiImpl>::Tracked(
+            TrackedIdleMarker::<SysfsZramApiImpl>::new()
+        ),
+        last_maintenance_at: Instant::now(),
+    })))
+    .isZramMaintenanceSupported()
+    .unwrap());
+    assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+        zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
+        zram_recompression: Some(ZramRecompression::new()),
+        suspend_history: SuspendHistory::new(),
+        idle_marker: ZramIdleMarker::<_, TimeApiImpl>::Tracked(
+            TrackedIdleMarker::<SysfsZramApiImpl>::new()
+        ),
+        last_maintenance_at: Instant::now(),
+    })))
+    .isZramMaintenanceSupported()
+    .unwrap());
+}
diff --git a/src/time.rs b/src/time.rs
index c0f6874..d51a7b7 100644
--- a/src/time.rs
+++ b/src/time.rs
@@ -28,7 +28,7 @@ use std::time::Duration;
 use nix::time::clock_gettime;
 
 /// [TimeApi] is the mockable interface of clock_gettime(3).
-#[cfg_attr(test, mockall::automock)]
+#[cfg_attr(any(test, feature = "test_utils"), mockall::automock)]
 pub trait TimeApi {
     /// Get the current monotonic time.
     fn get_monotonic_time() -> MonotonicTime;
@@ -58,7 +58,7 @@ impl TimeApi for TimeApiImpl {
 /// mockall for static functions requires synchronization.
 ///
 /// https://docs.rs/mockall/latest/mockall/#static-methods
-#[cfg(test)]
+#[cfg(any(test, feature = "test_utils"))]
 pub static TIME_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
 
 /// The representation of monotonic time.
diff --git a/src/zram.rs b/src/zram.rs
index 384255d..cfbfb4e 100644
--- a/src/zram.rs
+++ b/src/zram.rs
@@ -41,6 +41,8 @@ const ZRAM_BD_STAT_PATH: &str = "/sys/block/zram0/bd_stat";
 const ZRAM_RECOMP_ALGORITHM_PATH: &str = "/sys/block/zram0/recomp_algorithm";
 const ZRAM_RECOMPRESS_PATH: &str = "/sys/block/zram0/recompress";
 
+const ZRAM_IO_STAT_PATH: &str = "/sys/block/zram0/io_stat";
+
 /// [SysfsZramApi] is a mockable interface for access to files under
 /// "/sys/block/zram0" which is system global.
 ///
@@ -59,6 +61,8 @@ pub trait SysfsZramApi {
     /// Read "/sys/block/zram0/mm_stat".
     fn read_mm_stat() -> io::Result<String>;
 
+    /// Read "/sys/block/zram0/comp_algorithm"
+    fn read_comp_algorithm() -> io::Result<String>;
     /// Set compression algorithm.
     fn write_comp_algorithm(contents: &str) -> io::Result<()>;
 
@@ -86,6 +90,9 @@ pub trait SysfsZramApi {
     fn write_recomp_algorithm(contents: &str) -> io::Result<()>;
     /// Write contents to "/sys/block/zram0/recompress".
     fn recompress(contents: &str) -> io::Result<()>;
+
+    /// Read "/sys/block/zram0/io_stat".
+    fn read_io_stat() -> io::Result<String>;
 }
 
 /// The implementation of [SysfsZramApi].
@@ -148,9 +155,17 @@ impl SysfsZramApi for SysfsZramApiImpl {
         std::fs::write(ZRAM_RECOMPRESS_PATH, contents)
     }
 
+    fn read_comp_algorithm() -> io::Result<String> {
+        std::fs::read_to_string(ZRAM_COMP_ALGORITHM_PATH)
+    }
+
     fn write_comp_algorithm(contents: &str) -> io::Result<()> {
         std::fs::write(ZRAM_COMP_ALGORITHM_PATH, contents)
     }
+
+    fn read_io_stat() -> io::Result<String> {
+        std::fs::read_to_string(ZRAM_IO_STAT_PATH)
+    }
 }
 
 /// Mutex to synchronize tests using [MockSysfsZramApi].
@@ -158,4 +173,5 @@ impl SysfsZramApi for SysfsZramApiImpl {
 /// mockall for static functions requires synchronization.
 ///
 /// https://docs.rs/mockall/latest/mockall/#static-methods
+#[cfg(any(test, feature = "test_utils"))]
 pub static ZRAM_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
diff --git a/src/zram/idle.rs b/src/zram/idle.rs
index 70ff953..d785e57 100644
--- a/src/zram/idle.rs
+++ b/src/zram/idle.rs
@@ -14,16 +14,95 @@
 
 //! This module provides the interface for CONFIG_ZRAM_MEMORY_TRACKING feature.
 
+#[cfg(test)]
+mod tests;
+
+use std::error::Error;
+use std::marker::PhantomData;
 use std::time::Duration;
 
 use crate::os::MeminfoApi;
+use crate::time::BootTime;
+use crate::time::TimeApi;
 use crate::zram::SysfsZramApi;
 
-/// Sets idle duration in seconds to "/sys/block/zram0/idle".
+/// IdleMarker marks pages in zram for longer than a specified time as idle.
+///
+/// libmmd provides [TrackedIdleMarker] and [UntrackedIdleMarker] for both system enabling
+/// CONFIG_ZRAM_MEMORY_TRACKING or CONFIG_ZRAM_TRACK_ENTRY_ACTIME and system disabling them.
+pub trait IdleMarker {
+    /// Ensures that all zram pages marked as idle are older than `idle_age`.
+    ///
+    /// This returns `true` if all zram pages marked as idle are older than `idle_age`.
+    ///
+    /// If some zram pages are not eligible for writeback/recompress may be marked as idle, this
+    /// returns `false`.
+    fn ensure_idle_pages_marked(&self, idle_age: Duration) -> Result<bool, Box<dyn Error>>;
+}
+
+/// [TrackedIdleMarker] marks idle pages by writing specified idle duration to
+/// "/sys/block/zram0/idle".
+///
+/// This requires CONFIG_ZRAM_MEMORY_TRACKING or CONFIG_ZRAM_TRACK_ENTRY_ACTIME kernel config is
+/// enabled.
+#[derive(Default, Debug)]
+pub struct TrackedIdleMarker<Z: SysfsZramApi> {
+    _phantom: PhantomData<Z>,
+}
+
+impl<Z: SysfsZramApi> TrackedIdleMarker<Z> {
+    /// Creates a new [TrackedIdleMarker].
+    pub fn new() -> Self {
+        Self { _phantom: PhantomData }
+    }
+}
+
+impl<Z: SysfsZramApi> IdleMarker for TrackedIdleMarker<Z> {
+    /// Sets idle duration in seconds to "/sys/block/zram0/idle".
+    ///
+    /// Fractions of a second are truncated.
+    fn ensure_idle_pages_marked(&self, idle_age: Duration) -> Result<bool, Box<dyn Error>> {
+        match Z::set_idle(&idle_age.as_secs().to_string()) {
+            Ok(()) => Ok(true),
+            Err(e) => Err(Box::new(e)),
+        }
+    }
+}
+
+/// [UntrackedIdleMarker] marks all pages as idle and waits until specified time has passed.
 ///
-/// Fractions of a second are truncated.
-pub fn set_zram_idle_time<Z: SysfsZramApi>(idle_age: Duration) -> std::io::Result<()> {
-    Z::set_idle(&idle_age.as_secs().to_string())
+/// The wait is unblocking and ensure_idle_pages_marked() just returns [MarkIdleResult::NotReady].
+#[derive(Default, Debug)]
+pub struct UntrackedIdleMarker<T: TimeApi> {
+    last_marked_at: Option<BootTime>,
+    _phantom: PhantomData<T>,
+}
+
+impl<T: TimeApi> UntrackedIdleMarker<T> {
+    /// Creates a new [UntrackedIdleMarker].
+    pub fn new() -> Self {
+        Self { last_marked_at: None, _phantom: PhantomData }
+    }
+
+    /// Marks all pages as idle.
+    ///
+    /// [ensure_idle_pages_marked()] starts returning [MarkIdleResult::NotReady] until specified
+    /// time has passed.
+    pub fn refresh<Z: SysfsZramApi>(&mut self) -> std::io::Result<()> {
+        Z::set_idle("all")?;
+        self.last_marked_at = Some(T::get_boot_time());
+        Ok(())
+    }
+}
+
+impl<T: TimeApi> IdleMarker for UntrackedIdleMarker<T> {
+    fn ensure_idle_pages_marked(&self, idle_age: Duration) -> Result<bool, Box<dyn Error>> {
+        let Some(last_marked_at) = self.last_marked_at else {
+            return Err(Box::<dyn Error>::from("last_marked_at is not set"));
+        };
+        let now = T::get_boot_time();
+        Ok(now.saturating_duration_since(last_marked_at) >= idle_age)
+    }
 }
 
 /// This parses the content of "/proc/meminfo" and returns the number of "MemTotal" and
@@ -106,182 +185,3 @@ pub fn calculate_idle_time<M: MeminfoApi>(
 
     Ok(Duration::from_secs(seconds as u64))
 }
-
-#[cfg(test)]
-mod tests {
-    use mockall::predicate::*;
-
-    use super::*;
-    use crate::os::MockMeminfoApi;
-    use crate::os::MEMINFO_API_MTX;
-    use crate::zram::MockSysfsZramApi;
-    use crate::zram::ZRAM_API_MTX;
-
-    #[test]
-    fn test_set_zram_idle_time() {
-        let _m = ZRAM_API_MTX.lock();
-        let mock = MockSysfsZramApi::set_idle_context();
-        mock.expect().with(eq("3600")).returning(|_| Ok(()));
-
-        assert!(set_zram_idle_time::<MockSysfsZramApi>(Duration::from_secs(3600)).is_ok());
-    }
-
-    #[test]
-    fn test_set_zram_idle_time_in_seconds() {
-        let _m = ZRAM_API_MTX.lock();
-        let mock = MockSysfsZramApi::set_idle_context();
-        mock.expect().with(eq("3600")).returning(|_| Ok(()));
-
-        assert!(set_zram_idle_time::<MockSysfsZramApi>(Duration::from_millis(3600567)).is_ok());
-    }
-
-    #[test]
-    fn test_parse_meminfo() {
-        let content = "MemTotal:       123456789 kB
-MemFree:        12345 kB
-MemAvailable:   67890 kB
-    ";
-        assert_eq!(parse_meminfo(content).unwrap(), (123456789, 67890));
-    }
-
-    #[test]
-    fn test_parse_meminfo_invalid_format() {
-        // empty
-        assert!(parse_meminfo("").is_none());
-        // no number
-        let content = "MemTotal:
-MemFree:        12345 kB
-MemAvailable:   67890 kB
-    ";
-        assert!(parse_meminfo(content).is_none());
-        // no number
-        let content = "MemTotal:       kB
-MemFree:        12345 kB
-MemAvailable:   67890 kB
-    ";
-        assert!(parse_meminfo(content).is_none());
-        // total memory missing
-        let content = "MemFree:        12345 kB
-MemAvailable:   67890 kB
-    ";
-        assert!(parse_meminfo(content).is_none());
-        // available memory missing
-        let content = "MemTotal:       123456789 kB
-MemFree:        12345 kB
-    ";
-        assert!(parse_meminfo(content).is_none());
-    }
-
-    #[test]
-    fn test_calculate_idle_time() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        let meminfo = "MemTotal: 8144296 kB
-    MemAvailable: 346452 kB";
-        mock.expect().returning(|| Ok(meminfo.to_string()));
-
-        assert_eq!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(72000),
-                Duration::from_secs(90000)
-            )
-            .unwrap(),
-            Duration::from_secs(72150)
-        );
-    }
-
-    #[test]
-    fn test_calculate_idle_time_same_min_max() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        let meminfo = "MemTotal: 8144296 kB
-    MemAvailable: 346452 kB";
-        mock.expect().returning(|| Ok(meminfo.to_string()));
-
-        assert_eq!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(90000),
-                Duration::from_secs(90000)
-            )
-            .unwrap(),
-            Duration::from_secs(90000)
-        );
-    }
-
-    #[test]
-    fn test_calculate_idle_time_min_is_bigger_than_max() {
-        assert!(matches!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(90000),
-                Duration::from_secs(72000)
-            ),
-            Err(CalculateError::InvalidMinAndMax)
-        ));
-    }
-
-    #[test]
-    fn test_calculate_idle_time_no_available() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        let meminfo = "MemTotal: 8144296 kB
-    MemAvailable: 0 kB";
-        mock.expect().returning(|| Ok(meminfo.to_string()));
-
-        assert_eq!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(72000),
-                Duration::from_secs(90000)
-            )
-            .unwrap(),
-            Duration::from_secs(72121)
-        );
-    }
-
-    #[test]
-    fn test_calculate_idle_time_meminfo_fail() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        mock.expect().returning(|| Err(std::io::Error::other("error")));
-
-        assert!(matches!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(72000),
-                Duration::from_secs(90000)
-            ),
-            Err(CalculateError::ReadMeminfo(_))
-        ));
-    }
-
-    #[test]
-    fn test_calculate_idle_time_invalid_meminfo() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        let meminfo = "";
-        mock.expect().returning(|| Ok(meminfo.to_string()));
-
-        assert!(matches!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(72000),
-                Duration::from_secs(90000)
-            ),
-            Err(CalculateError::InvalidMeminfo)
-        ));
-    }
-
-    #[test]
-    fn test_calculate_idle_time_zero_total_memory() {
-        let _m = MEMINFO_API_MTX.lock();
-        let mock = MockMeminfoApi::read_meminfo_context();
-        let meminfo = "MemTotal: 0 kB
-    MemAvailable: 346452 kB";
-        mock.expect().returning(|| Ok(meminfo.to_string()));
-
-        assert!(matches!(
-            calculate_idle_time::<MockMeminfoApi>(
-                Duration::from_secs(72000),
-                Duration::from_secs(90000)
-            ),
-            Err(CalculateError::InvalidMeminfo)
-        ));
-    }
-}
diff --git a/src/zram/idle/tests.rs b/src/zram/idle/tests.rs
new file mode 100644
index 0000000..0517e91
--- /dev/null
+++ b/src/zram/idle/tests.rs
@@ -0,0 +1,275 @@
+// Copyright 2025, The Android Open Source Project
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
+use std::sync::LockResult;
+use std::sync::MutexGuard;
+
+use mockall::predicate::*;
+
+use super::*;
+use crate::os::MockMeminfoApi;
+use crate::os::MEMINFO_API_MTX;
+use crate::time::BootTime;
+use crate::time::MockTimeApi;
+use crate::time::TIME_API_MTX;
+use crate::zram::MockSysfsZramApi;
+use crate::zram::ZRAM_API_MTX;
+
+struct MockContext<'a> {
+    set_idle: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__set_idle::Context,
+    get_boot_time: crate::time::__mock_MockTimeApi_TimeApi::__get_boot_time::Context,
+    // Lock will be released after mock contexts are dropped.
+    _time_lock: LockResult<MutexGuard<'a, ()>>,
+    _zram_lock: LockResult<MutexGuard<'a, ()>>,
+}
+
+impl MockContext<'_> {
+    fn new() -> Self {
+        let _zram_lock = ZRAM_API_MTX.lock();
+        let _time_lock = TIME_API_MTX.lock();
+        Self {
+            set_idle: MockSysfsZramApi::set_idle_context(),
+            get_boot_time: MockTimeApi::get_boot_time_context(),
+            _time_lock,
+            _zram_lock,
+        }
+    }
+}
+
+#[test]
+fn test_tracked_idle_marker_ensure_idle_pages_marked() {
+    let mock = MockContext::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
+
+    mock.set_idle.expect().with(eq("3600")).returning(|_| Ok(()));
+
+    assert!(idle_marker.ensure_idle_pages_marked(Duration::from_secs(3600)).unwrap());
+}
+
+#[test]
+fn test_tracked_idle_marker_ensure_idle_pages_marked_in_seconds() {
+    let mock = MockContext::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
+
+    mock.set_idle.expect().with(eq("3600")).returning(|_| Ok(()));
+
+    assert!(idle_marker.ensure_idle_pages_marked(Duration::from_millis(3600567)).unwrap());
+}
+
+#[test]
+fn test_untracked_idle_marker_refresh() {
+    let mock = MockContext::new();
+    let mut idle_marker = UntrackedIdleMarker::<MockTimeApi>::new();
+
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time
+        .expect()
+        .times(1)
+        .return_const(BootTime::from_duration(Duration::from_secs(100)));
+
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+}
+
+#[test]
+fn test_untracked_idle_marker_ensure_idle_pages_marked() {
+    let mock = MockContext::new();
+    let mut idle_marker = UntrackedIdleMarker::<MockTimeApi>::new();
+    const INITIAL_TIME: BootTime = BootTime::from_duration(Duration::from_secs(100));
+
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time.expect().times(1).return_const(INITIAL_TIME);
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+
+    mock.get_boot_time
+        .expect()
+        .times(1)
+        .return_const(INITIAL_TIME.checked_add(Duration::from_secs(3599)).unwrap());
+    assert!(!idle_marker.ensure_idle_pages_marked(Duration::from_secs(3600)).unwrap());
+
+    mock.get_boot_time
+        .expect()
+        .times(1)
+        .return_const(INITIAL_TIME.checked_add(Duration::from_secs(3600)).unwrap());
+    assert!(idle_marker.ensure_idle_pages_marked(Duration::from_secs(3600)).unwrap());
+
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time
+        .expect()
+        .times(1)
+        .return_const(INITIAL_TIME.checked_add(Duration::from_secs(3600)).unwrap());
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+
+    mock.get_boot_time
+        .expect()
+        .times(1)
+        .return_const(INITIAL_TIME.checked_add(Duration::from_secs(3600)).unwrap());
+    assert!(!idle_marker.ensure_idle_pages_marked(Duration::from_secs(3600)).unwrap());
+}
+
+#[test]
+fn test_untracked_idle_marker_ensure_idle_pages_marked_without_refresh() {
+    let idle_marker = UntrackedIdleMarker::<MockTimeApi>::new();
+
+    assert!(idle_marker.ensure_idle_pages_marked(Duration::from_secs(3600)).is_err());
+}
+
+#[test]
+fn test_parse_meminfo() {
+    let content = "MemTotal:       123456789 kB
+MemFree:        12345 kB
+MemAvailable:   67890 kB
+";
+    assert_eq!(parse_meminfo(content).unwrap(), (123456789, 67890));
+}
+
+#[test]
+fn test_parse_meminfo_invalid_format() {
+    // empty
+    assert!(parse_meminfo("").is_none());
+    // no number
+    let content = "MemTotal:
+MemFree:        12345 kB
+MemAvailable:   67890 kB
+";
+    assert!(parse_meminfo(content).is_none());
+    // no number
+    let content = "MemTotal:       kB
+MemFree:        12345 kB
+MemAvailable:   67890 kB
+";
+    assert!(parse_meminfo(content).is_none());
+    // total memory missing
+    let content = "MemFree:        12345 kB
+MemAvailable:   67890 kB
+";
+    assert!(parse_meminfo(content).is_none());
+    // available memory missing
+    let content = "MemTotal:       123456789 kB
+MemFree:        12345 kB
+";
+    assert!(parse_meminfo(content).is_none());
+}
+
+#[test]
+fn test_calculate_idle_time() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    let meminfo = "MemTotal: 8144296 kB
+MemAvailable: 346452 kB";
+    mock.expect().returning(|| Ok(meminfo.to_string()));
+
+    assert_eq!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(72000),
+            Duration::from_secs(90000)
+        )
+        .unwrap(),
+        Duration::from_secs(72150)
+    );
+}
+
+#[test]
+fn test_calculate_idle_time_same_min_max() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    let meminfo = "MemTotal: 8144296 kB
+MemAvailable: 346452 kB";
+    mock.expect().returning(|| Ok(meminfo.to_string()));
+
+    assert_eq!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(90000),
+            Duration::from_secs(90000)
+        )
+        .unwrap(),
+        Duration::from_secs(90000)
+    );
+}
+
+#[test]
+fn test_calculate_idle_time_min_is_bigger_than_max() {
+    assert!(matches!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(90000),
+            Duration::from_secs(72000)
+        ),
+        Err(CalculateError::InvalidMinAndMax)
+    ));
+}
+
+#[test]
+fn test_calculate_idle_time_no_available() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    let meminfo = "MemTotal: 8144296 kB
+MemAvailable: 0 kB";
+    mock.expect().returning(|| Ok(meminfo.to_string()));
+
+    assert_eq!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(72000),
+            Duration::from_secs(90000)
+        )
+        .unwrap(),
+        Duration::from_secs(72121)
+    );
+}
+
+#[test]
+fn test_calculate_idle_time_meminfo_fail() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    mock.expect().returning(|| Err(std::io::Error::other("error")));
+
+    assert!(matches!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(72000),
+            Duration::from_secs(90000)
+        ),
+        Err(CalculateError::ReadMeminfo(_))
+    ));
+}
+
+#[test]
+fn test_calculate_idle_time_invalid_meminfo() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    let meminfo = "";
+    mock.expect().returning(|| Ok(meminfo.to_string()));
+
+    assert!(matches!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(72000),
+            Duration::from_secs(90000)
+        ),
+        Err(CalculateError::InvalidMeminfo)
+    ));
+}
+
+#[test]
+fn test_calculate_idle_time_zero_total_memory() {
+    let _m = MEMINFO_API_MTX.lock();
+    let mock = MockMeminfoApi::read_meminfo_context();
+    let meminfo = "MemTotal: 0 kB
+MemAvailable: 346452 kB";
+    mock.expect().returning(|| Ok(meminfo.to_string()));
+
+    assert!(matches!(
+        calculate_idle_time::<MockMeminfoApi>(
+            Duration::from_secs(72000),
+            Duration::from_secs(90000)
+        ),
+        Err(CalculateError::InvalidMeminfo)
+    ));
+}
diff --git a/src/zram/recompression.rs b/src/zram/recompression.rs
index 3f3124a..6a96602 100644
--- a/src/zram/recompression.rs
+++ b/src/zram/recompression.rs
@@ -27,7 +27,7 @@ use crate::os::MeminfoApi;
 use crate::suspend_history::SuspendHistory;
 use crate::time::BootTime;
 use crate::zram::idle::calculate_idle_time;
-use crate::zram::idle::set_zram_idle_time;
+use crate::zram::idle::IdleMarker;
 use crate::zram::SysfsZramApi;
 
 /// Error from [ZramRecompression].
@@ -41,7 +41,10 @@ pub enum Error {
     CalculateIdle(#[from] crate::zram::idle::CalculateError),
     /// failure on setting zram idle
     #[error("set zram idle {0}")]
-    MarkIdle(std::io::Error),
+    MarkIdle(Box<dyn std::error::Error>),
+    /// you need to mark idle later again.
+    #[error("idle pages are not ready to mark yet")]
+    TryMarkIdleAgain,
     /// failure on writing to /sys/block/zram0/recompress
     #[error("recompress: {0}")]
     Recompress(std::io::Error),
@@ -136,6 +139,7 @@ impl ZramRecompression {
         &mut self,
         params: &Params,
         suspend_history: &SuspendHistory,
+        idle_marker: &dyn IdleMarker,
         now: BootTime,
     ) -> Result<()> {
         if let Some(last_at) = self.last_recompress_at {
@@ -145,13 +149,31 @@ impl ZramRecompression {
         }
 
         if params.huge_idle {
-            self.initiate_recompress::<Z, M>(params, Mode::HugeIdle, suspend_history, now)?;
+            self.initiate_recompress::<Z, M>(
+                params,
+                Mode::HugeIdle,
+                suspend_history,
+                idle_marker,
+                now,
+            )?;
         }
         if params.idle {
-            self.initiate_recompress::<Z, M>(params, Mode::Idle, suspend_history, now)?;
+            self.initiate_recompress::<Z, M>(
+                params,
+                Mode::Idle,
+                suspend_history,
+                idle_marker,
+                now,
+            )?;
         }
         if params.huge {
-            self.initiate_recompress::<Z, M>(params, Mode::Huge, suspend_history, now)?;
+            self.initiate_recompress::<Z, M>(
+                params,
+                Mode::Huge,
+                suspend_history,
+                idle_marker,
+                now,
+            )?;
         }
 
         Ok(())
@@ -162,6 +184,7 @@ impl ZramRecompression {
         params: &Params,
         mode: Mode,
         suspend_history: &SuspendHistory,
+        idle_marker: &dyn IdleMarker,
         now: BootTime,
     ) -> Result<()> {
         match mode {
@@ -171,7 +194,11 @@ impl ZramRecompression {
                 let idle_age = idle_age.saturating_add(
                     suspend_history.calculate_total_suspend_duration(idle_age, now),
                 );
-                set_zram_idle_time::<Z>(idle_age).map_err(Error::MarkIdle)?;
+                match idle_marker.ensure_idle_pages_marked(idle_age) {
+                    Ok(true) => Ok(()),
+                    Ok(false) => Err(Error::TryMarkIdleAgain),
+                    Err(e) => Err(Error::MarkIdle(e)),
+                }?;
             }
             Mode::Huge => {}
         }
diff --git a/src/zram/recompression/tests.rs b/src/zram/recompression/tests.rs
index 88e38a1..8da6f68 100644
--- a/src/zram/recompression/tests.rs
+++ b/src/zram/recompression/tests.rs
@@ -21,8 +21,13 @@ use mockall::Sequence;
 use super::*;
 use crate::os::MockMeminfoApi;
 use crate::os::MEMINFO_API_MTX;
+use crate::time::BootTime;
+use crate::time::MockTimeApi;
 use crate::time::TimeApi;
 use crate::time::TimeApiImpl;
+use crate::time::TIME_API_MTX;
+use crate::zram::idle::TrackedIdleMarker;
+use crate::zram::idle::UntrackedIdleMarker;
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
@@ -31,22 +36,27 @@ struct MockContext<'a> {
         crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_recomp_algorithm::Context,
     recompress: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__recompress::Context,
     set_idle: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__set_idle::Context,
+    get_boot_time: crate::time::__mock_MockTimeApi_TimeApi::__get_boot_time::Context,
     read_meminfo: crate::os::__mock_MockMeminfoApi_MeminfoApi::__read_meminfo::Context,
     // Lock will be released after mock contexts are dropped.
     _meminfo_lock: LockResult<MutexGuard<'a, ()>>,
+    _time_lock: LockResult<MutexGuard<'a, ()>>,
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
 }
 
 impl MockContext<'_> {
     fn new() -> Self {
         let _zram_lock = ZRAM_API_MTX.lock();
+        let _time_lock = TIME_API_MTX.lock();
         let _meminfo_lock = MEMINFO_API_MTX.lock();
         Self {
             read_recomp_algorithm: MockSysfsZramApi::read_recomp_algorithm_context(),
             recompress: MockSysfsZramApi::recompress_context(),
             set_idle: MockSysfsZramApi::set_idle_context(),
+            get_boot_time: MockTimeApi::get_boot_time_context(),
             read_meminfo: MockMeminfoApi::read_meminfo_context(),
             _meminfo_lock,
+            _time_lock,
             _zram_lock,
         }
     }
@@ -105,6 +115,7 @@ fn mark_and_recompress() {
     mock.setup_default_meminfo();
     let params = Params { threshold_bytes: 0, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().times(1).in_sequence(&mut seq).returning(|_| Ok(()));
@@ -132,6 +143,7 @@ fn mark_and_recompress() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -144,6 +156,7 @@ fn mark_and_recompress_with_threshold() {
     mock.setup_default_meminfo();
     let params = Params { threshold_bytes: 12345, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress
@@ -158,6 +171,7 @@ fn mark_and_recompress_with_threshold() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time(),
         )
         .is_ok());
@@ -175,12 +189,14 @@ fn mark_and_recompress_before_backoff() {
         ..Default::default()
     };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let base_time = TimeApiImpl::get_boot_time();
     let mut zram_recompression = ZramRecompression::new();
     assert!(zram_recompression
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             base_time,
         )
         .is_ok());
@@ -192,6 +208,7 @@ fn mark_and_recompress_before_backoff() {
         zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             base_time.checked_add(Duration::from_secs(99)).unwrap(),
         ),
         Err(Error::BackoffTime)
@@ -210,12 +227,14 @@ fn mark_and_recompress_after_backoff() {
         ..Default::default()
     };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let base_time = TimeApiImpl::get_boot_time();
     let mut zram_recompression = ZramRecompression::new();
     assert!(zram_recompression
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             base_time,
         )
         .is_ok());
@@ -229,6 +248,7 @@ fn mark_and_recompress_after_backoff() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             base_time.checked_add(Duration::from_secs(100)).unwrap()
         )
         .is_ok());
@@ -248,6 +268,7 @@ fn mark_and_recompress_idle_time() {
         ..Default::default()
     };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().with(eq("3747")).times(2).returning(|_| Ok(()));
@@ -256,11 +277,60 @@ fn mark_and_recompress_idle_time() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
 }
 
+#[test]
+fn mark_and_recompress_try_mark_idle_again() {
+    let mock = MockContext::new();
+    mock.recompress.expect().returning(|_| Ok(()));
+    let meminfo = "MemTotal: 10000 kB
+        MemAvailable: 8000 kB";
+    mock.read_meminfo.expect().returning(|| Ok(meminfo.to_string()));
+    let params = Params {
+        min_idle: Duration::from_secs(3600),
+        max_idle: Duration::from_secs(4000),
+        threshold_bytes: 0,
+        ..Default::default()
+    };
+    let suspend_history = SuspendHistory::new();
+    let mut idle_marker = UntrackedIdleMarker::<MockTimeApi>::new();
+    let mut zram_recompression = ZramRecompression::new();
+    const INITIAL_TIME: BootTime = BootTime::from_duration(Duration::from_secs(100));
+
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time.expect().times(1).return_const(INITIAL_TIME);
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+
+    let time_before_threshold = INITIAL_TIME.checked_add(Duration::from_secs(3746)).unwrap();
+    mock.get_boot_time.expect().times(1).return_const(time_before_threshold);
+
+    assert!(matches!(
+        zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            &idle_marker,
+            time_before_threshold
+        ),
+        Err(Error::TryMarkIdleAgain)
+    ));
+
+    let time_after_threshold = INITIAL_TIME.checked_add(Duration::from_secs(3747)).unwrap();
+    mock.get_boot_time.expect().times(2).return_const(time_after_threshold);
+
+    assert!(zram_recompression
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            &idle_marker,
+            time_after_threshold
+        )
+        .is_ok());
+}
+
 #[test]
 fn mark_and_recompress_idle_time_adjusted_by_suspend_duration() {
     let mock = MockContext::new();
@@ -275,6 +345,7 @@ fn mark_and_recompress_idle_time_adjusted_by_suspend_duration() {
         ..Default::default()
     };
     let mut suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let boot_now = BootTime::from_duration(Duration::from_secs(12345));
     suspend_history.record_suspend_duration(Duration::from_secs(1000), boot_now, params.max_idle);
     let mut zram_recompression = ZramRecompression::new();
@@ -285,6 +356,7 @@ fn mark_and_recompress_idle_time_adjusted_by_suspend_duration() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             boot_now
         )
         .is_ok());
@@ -301,12 +373,14 @@ fn mark_and_recompress_calculate_idle_failure() {
         ..Default::default()
     };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     assert!(matches!(
         zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         ),
         Err(Error::CalculateIdle(_))
@@ -319,6 +393,7 @@ fn mark_and_recompress_mark_idle_failure() {
     mock.setup_default_meminfo();
     let params = Params { threshold_bytes: 0, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().returning(|_| Err(std::io::Error::other("error")));
@@ -327,6 +402,7 @@ fn mark_and_recompress_mark_idle_failure() {
         zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         ),
         Err(Error::MarkIdle(_))
@@ -340,6 +416,7 @@ fn mark_and_recompress_skip_huge_idle() {
     mock.setup_default_meminfo();
     let params = Params { huge_idle: false, threshold_bytes: 0, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(0).returning(|_| Ok(()));
@@ -350,6 +427,7 @@ fn mark_and_recompress_skip_huge_idle() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -362,6 +440,7 @@ fn mark_and_recompress_skip_idle() {
     mock.setup_default_meminfo();
     let params = Params { idle: false, threshold_bytes: 0, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(1).returning(|_| Ok(()));
@@ -372,6 +451,7 @@ fn mark_and_recompress_skip_idle() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -384,6 +464,7 @@ fn mark_and_recompress_skip_huge() {
     mock.setup_default_meminfo();
     let params = Params { huge: false, threshold_bytes: 0, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(1).returning(|_| Ok(()));
@@ -394,6 +475,7 @@ fn mark_and_recompress_skip_huge() {
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
diff --git a/src/zram/setup.rs b/src/zram/setup.rs
index 7611c2c..114b764 100644
--- a/src/zram/setup.rs
+++ b/src/zram/setup.rs
@@ -38,7 +38,7 @@ const ZRAM_DEVICE_PATH: &str = "/dev/block/zram0";
 const PROC_SWAPS_PATH: &str = "/proc/swaps";
 
 /// [SetupApi] is the mockable interface for swap operations.
-#[cfg_attr(test, mockall::automock)]
+#[cfg_attr(any(test, feature = "test_utils"), mockall::automock)]
 pub trait SetupApi {
     /// Set up zram swap device, returning whether the command succeeded and its output.
     fn mkswap(device_path: &str) -> io::Result<std::process::Output>;
@@ -88,6 +88,14 @@ impl SetupApi for SetupApiImpl {
     }
 }
 
+/// Mutex to synchronize tests using [MockSetupApi].
+///
+/// mockall for static functions requires synchronization.
+///
+/// https://docs.rs/mockall/latest/mockall/#static-methods
+#[cfg(any(test, feature = "test_utils"))]
+pub static SETUP_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
+
 /// Whether or not zram is already set up on the device.
 pub fn is_zram_swap_activated<S: SetupApi>() -> io::Result<bool> {
     let swaps = S::read_swap_areas()?;
@@ -173,3 +181,17 @@ pub fn create_zram_writeback_device<S: SetupApi>(
 pub fn enable_zram_writeback_limit<Z: SysfsZramApi>() -> std::io::Result<()> {
     Z::write_writeback_limit_enable("1")
 }
+
+/// Gets supported compression algorithms
+pub fn get_supported_compression_algorithms<Z: SysfsZramApi>() -> std::io::Result<Vec<String>> {
+    let contents = Z::read_comp_algorithm()?;
+    let supported_algorithms = contents.split_whitespace().map(|s|
+        // Selected algorithm is in square brackets
+        if s.starts_with("[") && s.ends_with("]") {
+            s[1..s.len() - 1].to_string()
+        } else {
+            s.to_string()
+        }
+    ).collect();
+    Ok(supported_algorithms)
+}
diff --git a/src/zram/setup/tests.rs b/src/zram/setup/tests.rs
index fc93d83..53a4818 100644
--- a/src/zram/setup/tests.rs
+++ b/src/zram/setup/tests.rs
@@ -15,7 +15,6 @@
 use std::os::unix::process::ExitStatusExt;
 use std::path::PathBuf;
 use std::sync::LockResult;
-use std::sync::Mutex;
 use std::sync::MutexGuard;
 
 use mockall::predicate::*;
@@ -45,13 +44,6 @@ fn failure_command_output() -> std::process::Output {
     }
 }
 
-/// Mutex to synchronize tests using [MockSetupApi].
-///
-/// mockall for static functions requires synchronization.
-///
-/// https://docs.rs/mockall/latest/mockall/#static-methods
-pub static SETUP_API_MTX: Mutex<()> = Mutex::new(());
-
 struct MockContext<'a> {
     write_disksize: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__write_disksize::Context,
     write_backing_dev:
@@ -61,6 +53,8 @@ struct MockContext<'a> {
     swapon: crate::zram::setup::__mock_MockSetupApi_SetupApi::__swapon::Context,
     attach_loop_device:
         crate::zram::setup::__mock_MockSetupApi_SetupApi::__attach_loop_device::Context,
+    read_comp_algorithm:
+        crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_comp_algorithm::Context,
     // Lock will be released after mock contexts are dropped.
     _setup_lock: LockResult<MutexGuard<'a, ()>>,
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
@@ -77,6 +71,7 @@ impl MockContext<'_> {
             mkswap: MockSetupApi::mkswap_context(),
             swapon: MockSetupApi::swapon_context(),
             attach_loop_device: MockSetupApi::attach_loop_device_context(),
+            read_comp_algorithm: MockSysfsZramApi::read_comp_algorithm_context(),
             _setup_lock,
             _zram_lock,
         }
@@ -237,3 +232,39 @@ fn enable_zram_writeback_limit_success() {
 
     assert!(enable_zram_writeback_limit::<MockSysfsZramApi>().is_ok());
 }
+
+#[test]
+fn get_supported_compression_algorithms_multiple() {
+    let mock = MockContext::new();
+    mock.read_comp_algorithm.expect().returning(|| Ok("[lzo] lz4 zstd lzo-rle".to_string()));
+
+    let algorithms = get_supported_compression_algorithms::<MockSysfsZramApi>().unwrap();
+    assert_eq!(algorithms, vec!["lzo", "lz4", "zstd", "lzo-rle"]);
+}
+
+#[test]
+fn get_supported_compression_algorithms_single() {
+    let mock = MockContext::new();
+    mock.read_comp_algorithm.expect().returning(|| Ok("[zstd]".to_string()));
+
+    let algorithms = get_supported_compression_algorithms::<MockSysfsZramApi>().unwrap();
+    assert_eq!(algorithms, vec!["zstd"]);
+}
+
+#[test]
+fn get_supported_compression_algorithms_empty() {
+    let mock = MockContext::new();
+    mock.read_comp_algorithm.expect().returning(|| Ok("".to_string()));
+
+    let algorithms = get_supported_compression_algorithms::<MockSysfsZramApi>().unwrap();
+    assert!(algorithms.is_empty());
+}
+
+#[test]
+fn get_supported_compression_algorithms_read_error() {
+    let mock = MockContext::new();
+    mock.read_comp_algorithm.expect().returning(|| Err(io::Error::other("read failed")));
+
+    let result = get_supported_compression_algorithms::<MockSysfsZramApi>();
+    assert!(result.is_err());
+}
diff --git a/src/zram/stats.rs b/src/zram/stats.rs
index aa138a8..5b6b304 100644
--- a/src/zram/stats.rs
+++ b/src/zram/stats.rs
@@ -126,3 +126,30 @@ impl ZramBdStat {
         })
     }
 }
+
+/// Stats from /sys/block/zram0/io_stat
+#[derive(Debug, Default, PartialEq, Eq)]
+pub struct ZramIoStat {
+    /// The number of failed read requests.
+    pub failed_reads: u64,
+    /// The number of failed write requests.
+    pub failed_writes: u64,
+    /// The number of non-page-aligned requests.
+    pub invalid_io: u64,
+    /// A page is freed by page reclaim.
+    pub notify_free: u64,
+}
+
+impl ZramIoStat {
+    /// Parse /sys/block/zram0/io_stat.
+    pub fn load<Z: SysfsZramApi>() -> Result<Self> {
+        let contents = Z::read_io_stat()?;
+        let mut values = contents.split_whitespace();
+        Ok(ZramIoStat {
+            failed_reads: parse_next(&mut values)?,
+            failed_writes: parse_next(&mut values)?,
+            invalid_io: parse_next(&mut values)?,
+            notify_free: parse_next(&mut values)?,
+        })
+    }
+}
diff --git a/src/zram/stats/tests.rs b/src/zram/stats/tests.rs
index add0709..bafadeb 100644
--- a/src/zram/stats/tests.rs
+++ b/src/zram/stats/tests.rs
@@ -207,3 +207,43 @@ fn test_zram_bd_stat_invalid_value() {
 
     assert!(ZramBdStat::load::<MockSysfsZramApi>().is_err());
 }
+
+#[test]
+fn test_zram_io_stat_load() {
+    let _m = ZRAM_API_MTX.lock();
+    let mock = MockSysfsZramApi::read_io_stat_context();
+    mock.expect().returning(|| Ok("1 2 3 4".to_string()));
+
+    let stat = ZramIoStat::load::<MockSysfsZramApi>().unwrap();
+    assert_eq!(
+        stat,
+        ZramIoStat { failed_reads: 1, failed_writes: 2, invalid_io: 3, notify_free: 4 }
+    );
+}
+
+#[test]
+fn test_zram_io_stat_load_parse_error() {
+    let _m = ZRAM_API_MTX.lock();
+    let mock = MockSysfsZramApi::read_io_stat_context();
+    mock.expect().returning(|| Ok("1 2 3 four".to_string()));
+
+    assert!(matches!(ZramIoStat::load::<MockSysfsZramApi>(), Err(Error::Parse)));
+}
+
+#[test]
+fn test_zram_io_stat_load_too_few_fields() {
+    let _m = ZRAM_API_MTX.lock();
+    let mock = MockSysfsZramApi::read_io_stat_context();
+    mock.expect().returning(|| Ok("1 2 3".to_string())); // Missing notify_free
+
+    assert!(matches!(ZramIoStat::load::<MockSysfsZramApi>(), Err(Error::Parse)));
+}
+
+#[test]
+fn test_zram_io_stat_load_io_error() {
+    let _m = ZRAM_API_MTX.lock();
+    let mock = MockSysfsZramApi::read_io_stat_context();
+    mock.expect().returning(|| Err(std::io::Error::other("read error")));
+
+    assert!(matches!(ZramIoStat::load::<MockSysfsZramApi>(), Err(Error::Io(_))));
+}
diff --git a/src/zram/writeback.rs b/src/zram/writeback.rs
index cfdaea6..0771c58 100644
--- a/src/zram/writeback.rs
+++ b/src/zram/writeback.rs
@@ -29,7 +29,7 @@ use crate::os::MeminfoApi;
 use crate::suspend_history::SuspendHistory;
 use crate::time::BootTime;
 use crate::zram::idle::calculate_idle_time;
-use crate::zram::idle::set_zram_idle_time;
+use crate::zram::idle::IdleMarker;
 use crate::zram::writeback::history::ZramWritebackHistory;
 use crate::zram::SysfsZramApi;
 
@@ -50,7 +50,10 @@ pub enum Error {
     CalculateIdle(#[from] crate::zram::idle::CalculateError),
     /// failure on setting zram idle
     #[error("set zram idle {0}")]
-    MarkIdle(std::io::Error),
+    MarkIdle(Box<dyn std::error::Error>),
+    /// you need to mark idle later again.
+    #[error("idle pages are not ready to mark yet")]
+    TryMarkIdleAgain,
     /// failure on writing to /sys/block/zram0/writeback
     #[error("writeback: {0}")]
     Writeback(std::io::Error),
@@ -123,7 +126,7 @@ impl Default for Params {
             max_idle: Duration::from_secs(25 * 3600),
             huge_idle: true,
             idle: true,
-            huge: true,
+            huge: false,
             // 5 MiB
             min_bytes: 5 << 20,
             // 300 MiB
@@ -223,6 +226,7 @@ impl ZramWriteback {
         params: &Params,
         stats: &Stats,
         suspend_history: &SuspendHistory,
+        idle_marker: &dyn IdleMarker,
         now: BootTime,
     ) -> Result<WritebackDetails> {
         if let Some(last_at) = self.last_writeback_at {
@@ -251,6 +255,7 @@ impl ZramWriteback {
                 params,
                 Mode::HugeIdle,
                 suspend_history,
+                idle_marker,
                 &mut details.huge_idle,
                 now,
             )?;
@@ -261,6 +266,7 @@ impl ZramWriteback {
                 params,
                 Mode::Idle,
                 suspend_history,
+                idle_marker,
                 &mut details.idle,
                 now,
             )?;
@@ -271,6 +277,7 @@ impl ZramWriteback {
                 params,
                 Mode::Huge,
                 suspend_history,
+                idle_marker,
                 &mut details.huge,
                 now,
             )?;
@@ -307,12 +314,15 @@ impl ZramWriteback {
         std::cmp::min(limit_pages, max_pages)
     }
 
+    // TODO: b/408364803 - resolve clippy::too_many_arguments.
+    #[allow(clippy::too_many_arguments)]
     fn writeback<Z: SysfsZramApi, M: MeminfoApi>(
         &mut self,
         writeback_limit: u64,
         params: &Params,
         mode: Mode,
         suspend_history: &SuspendHistory,
+        idle_marker: &dyn IdleMarker,
         details: &mut WritebackModeDetails,
         now: BootTime,
     ) -> Result<u64> {
@@ -323,7 +333,11 @@ impl ZramWriteback {
                 let idle_age = idle_age.saturating_add(
                     suspend_history.calculate_total_suspend_duration(idle_age, now),
                 );
-                set_zram_idle_time::<Z>(idle_age).map_err(Error::MarkIdle)?;
+                match idle_marker.ensure_idle_pages_marked(idle_age) {
+                    Ok(true) => Ok(()),
+                    Ok(false) => Err(Error::TryMarkIdleAgain),
+                    Err(e) => Err(Error::MarkIdle(e)),
+                }?;
             }
             Mode::Huge => {}
         }
diff --git a/src/zram/writeback/tests.rs b/src/zram/writeback/tests.rs
index 1beba9d..7ce9b61 100644
--- a/src/zram/writeback/tests.rs
+++ b/src/zram/writeback/tests.rs
@@ -21,8 +21,13 @@ use mockall::Sequence;
 use super::*;
 use crate::os::MockMeminfoApi;
 use crate::os::MEMINFO_API_MTX;
+use crate::time::BootTime;
+use crate::time::MockTimeApi;
 use crate::time::TimeApi;
 use crate::time::TimeApiImpl;
+use crate::time::TIME_API_MTX;
+use crate::zram::idle::TrackedIdleMarker;
+use crate::zram::idle::UntrackedIdleMarker;
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
@@ -39,15 +44,18 @@ struct MockContext<'a> {
     read_writeback_limit:
         crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__read_writeback_limit::Context,
     set_idle: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__set_idle::Context,
+    get_boot_time: crate::time::__mock_MockTimeApi_TimeApi::__get_boot_time::Context,
     read_meminfo: crate::os::__mock_MockMeminfoApi_MeminfoApi::__read_meminfo::Context,
     // Lock will be released after mock contexts are dropped.
     _meminfo_lock: LockResult<MutexGuard<'a, ()>>,
+    _time_lock: LockResult<MutexGuard<'a, ()>>,
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
 }
 
 impl MockContext<'_> {
     fn new() -> Self {
         let _zram_lock = ZRAM_API_MTX.lock();
+        let _time_lock = TIME_API_MTX.lock();
         let _meminfo_lock = MEMINFO_API_MTX.lock();
         Self {
             read_backing_dev: MockSysfsZramApi::read_backing_dev_context(),
@@ -55,8 +63,10 @@ impl MockContext<'_> {
             write_writeback_limit: MockSysfsZramApi::write_writeback_limit_context(),
             read_writeback_limit: MockSysfsZramApi::read_writeback_limit_context(),
             set_idle: MockSysfsZramApi::set_idle_context(),
+            get_boot_time: MockTimeApi::get_boot_time_context(),
             read_meminfo: MockMeminfoApi::read_meminfo_context(),
             _meminfo_lock,
+            _time_lock,
             _zram_lock,
         }
     }
@@ -125,9 +135,10 @@ fn mark_and_flush_pages() {
     let mut seq = Sequence::new();
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
-    let params = Params::default();
+    let params = Params { huge_idle: true, idle: true, huge: true, ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -143,6 +154,7 @@ fn mark_and_flush_pages() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -159,6 +171,7 @@ fn mark_and_flush_pages_before_backoff() {
     let params = Params { backoff_duration: Duration::from_secs(100), ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let base_time = TimeApiImpl::get_boot_time();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
@@ -167,6 +180,7 @@ fn mark_and_flush_pages_before_backoff() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_time
         )
         .is_ok());
@@ -179,6 +193,7 @@ fn mark_and_flush_pages_before_backoff() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_time.checked_add(Duration::from_secs(99)).unwrap()
         ),
         Err(Error::BackoffTime)
@@ -193,9 +208,16 @@ fn mark_and_flush_pages_after_backoff() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
-    let params = Params { backoff_duration: Duration::from_secs(100), ..Default::default() };
+    let params = Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
+        backoff_duration: Duration::from_secs(100),
+        ..Default::default()
+    };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let base_time = TimeApiImpl::get_boot_time();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
@@ -204,6 +226,7 @@ fn mark_and_flush_pages_after_backoff() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_time
         )
         .is_ok());
@@ -220,6 +243,7 @@ fn mark_and_flush_pages_after_backoff() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_time.checked_add(Duration::from_secs(100)).unwrap()
         )
         .is_ok());
@@ -235,12 +259,15 @@ fn mark_and_flush_pages_idle_time() {
     mock.read_meminfo.expect().returning(|| Ok(meminfo.to_string()));
     mock.setup_default_writeback_limit_read();
     let params = Params {
+        huge_idle: true,
+        idle: true,
         min_idle: Duration::from_secs(3600),
         max_idle: Duration::from_secs(4000),
         ..Default::default()
     };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -251,11 +278,65 @@ fn mark_and_flush_pages_idle_time() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
 }
 
+#[test]
+fn mark_and_flush_pages_try_mark_idle_again() {
+    let mock = MockContext::new();
+    mock.write_writeback_limit.expect().returning(|_| Ok(()));
+    mock.writeback.expect().returning(|_| Ok(()));
+    let meminfo = "MemTotal: 10000 kB
+        MemAvailable: 8000 kB";
+    mock.read_meminfo.expect().returning(|| Ok(meminfo.to_string()));
+    mock.setup_default_writeback_limit_read();
+    let params = Params {
+        min_idle: Duration::from_secs(3600),
+        max_idle: Duration::from_secs(4000),
+        ..Default::default()
+    };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
+    let mut idle_marker = UntrackedIdleMarker::<MockTimeApi>::new();
+    let mut zram_writeback =
+        ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
+    const INITIAL_TIME: BootTime = BootTime::from_duration(Duration::from_secs(100));
+
+    mock.set_idle.expect().with(eq("all")).times(1).returning(|_| Ok(()));
+    mock.get_boot_time.expect().times(1).return_const(INITIAL_TIME);
+    idle_marker.refresh::<MockSysfsZramApi>().unwrap();
+
+    let time_before_threshold = INITIAL_TIME.checked_add(Duration::from_secs(3746)).unwrap();
+    mock.get_boot_time.expect().times(1).return_const(time_before_threshold);
+
+    assert!(matches!(
+        zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            &idle_marker,
+            time_before_threshold
+        ),
+        Err(Error::TryMarkIdleAgain)
+    ));
+
+    let time_after_threshold = INITIAL_TIME.checked_add(Duration::from_secs(3747)).unwrap();
+    mock.get_boot_time.expect().times(2).return_const(time_after_threshold);
+
+    assert!(zram_writeback
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            &idle_marker,
+            time_after_threshold
+        )
+        .is_ok());
+}
+
 #[test]
 fn mark_and_flush_pages_idle_time_adjusted_by_suspend_duration() {
     let mock = MockContext::new();
@@ -266,12 +347,15 @@ fn mark_and_flush_pages_idle_time_adjusted_by_suspend_duration() {
     mock.read_meminfo.expect().returning(|| Ok(meminfo.to_string()));
     mock.setup_default_writeback_limit_read();
     let params = Params {
+        huge_idle: true,
+        idle: true,
         min_idle: Duration::from_secs(3600),
         max_idle: Duration::from_secs(4000),
         ..Default::default()
     };
     let stats = default_stats(&params);
     let mut suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let boot_now = BootTime::from_duration(Duration::from_secs(12345));
     suspend_history.record_suspend_duration(Duration::from_secs(1000), boot_now, params.max_idle);
     let mut zram_writeback =
@@ -284,6 +368,7 @@ fn mark_and_flush_pages_idle_time_adjusted_by_suspend_duration() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             boot_now
         )
         .is_ok());
@@ -302,6 +387,7 @@ fn mark_and_flush_pages_calculate_idle_failure() {
     };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -310,6 +396,7 @@ fn mark_and_flush_pages_calculate_idle_failure() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         ),
         Err(Error::CalculateIdle(_))
@@ -326,6 +413,7 @@ fn mark_and_flush_pages_mark_idle_failure() {
     let params = Params::default();
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -336,6 +424,7 @@ fn mark_and_flush_pages_mark_idle_failure() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         ),
         Err(Error::MarkIdle(_))
@@ -349,9 +438,10 @@ fn mark_and_flush_pages_skip_huge_idle() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
-    let params = Params { huge_idle: false, ..Default::default() };
+    let params = Params { huge_idle: false, idle: true, huge: true, ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -364,6 +454,7 @@ fn mark_and_flush_pages_skip_huge_idle() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -376,9 +467,10 @@ fn mark_and_flush_pages_skip_idle() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
-    let params = Params { idle: false, ..Default::default() };
+    let params = Params { huge_idle: true, idle: false, huge: true, ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -391,6 +483,7 @@ fn mark_and_flush_pages_skip_idle() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -403,9 +496,10 @@ fn mark_and_flush_pages_skip_huge() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
-    let params = Params { huge: false, ..Default::default() };
+    let params = Params { huge_idle: true, idle: true, huge: false, ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -418,6 +512,7 @@ fn mark_and_flush_pages_skip_huge() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -438,6 +533,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size() {
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -452,6 +548,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -470,6 +567,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size_with_big_page_size() {
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * page_size, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback =
         ZramWriteback::new_with_page_size(2000 * page_size, 1000 * page_size, page_size);
 
@@ -481,6 +579,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size_with_big_page_size() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -502,6 +601,7 @@ fn mark_and_flush_pages_write_limit_capped_by_current_writeback_size() {
     let stats =
         Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 1000 - 50 };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -516,6 +616,7 @@ fn mark_and_flush_pages_write_limit_capped_by_current_writeback_size() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -536,6 +637,7 @@ fn mark_and_flush_pages_write_limit_capped_by_min_pages() {
     // zram utilization is 1%
     let stats = Stats { orig_data_size: 20 * DEFAULT_PAGE_SIZE, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -550,6 +652,7 @@ fn mark_and_flush_pages_write_limit_capped_by_min_pages() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         ),
         Err(Error::Limit)
@@ -572,6 +675,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_with_no_log() {
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -586,6 +690,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_with_no_log() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -598,6 +703,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params {
+        huge_idle: true,
         max_bytes: 600 * DEFAULT_PAGE_SIZE,
         min_bytes: 10 * DEFAULT_PAGE_SIZE,
         max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
@@ -605,6 +711,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
     };
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -624,6 +731,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_ok());
@@ -636,6 +744,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(Duration::from_secs(3600)).unwrap()
         )
         .is_ok());
@@ -648,6 +757,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params {
+        huge_idle: true,
         max_bytes: 600 * DEFAULT_PAGE_SIZE,
         min_bytes: 10 * DEFAULT_PAGE_SIZE,
         max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
@@ -655,6 +765,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
     };
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -674,6 +785,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_ok());
@@ -685,6 +797,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(Duration::from_secs(24 * 3600)).unwrap()
         )
         .is_ok());
@@ -696,9 +809,10 @@ fn mark_and_flush_pages_skip_on_write_limit() {
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params::default();
+    let params = Params { huge_idle: true, idle: true, huge: true, ..Default::default() };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -718,6 +832,7 @@ fn mark_and_flush_pages_skip_on_write_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             TimeApiImpl::get_boot_time()
         )
         .is_ok());
@@ -730,9 +845,14 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let params = Params {
+        huge_idle: true,
+        max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
+        ..Default::default()
+    };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -749,6 +869,7 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_ok());
@@ -760,6 +881,7 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
@@ -777,6 +899,7 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(Duration::from_secs(24 * 3600)).unwrap()
         )
         .is_ok());
@@ -787,9 +910,14 @@ fn mark_and_flush_pages_fails_to_record_history_by_writeback_error() {
     let mock = MockContext::new();
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let params = Params {
+        huge_idle: true,
+        max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
+        ..Default::default()
+    };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -806,6 +934,7 @@ fn mark_and_flush_pages_fails_to_record_history_by_writeback_error() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_err());
@@ -820,6 +949,7 @@ fn mark_and_flush_pages_fails_to_record_history_by_writeback_error() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(params.backoff_duration).unwrap(),
         )
         .unwrap();
@@ -832,9 +962,14 @@ fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let params = Params {
+        huge_idle: true,
+        max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
+        ..Default::default()
+    };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -850,6 +985,7 @@ fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_ok());
@@ -861,6 +997,7 @@ fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
@@ -873,9 +1010,14 @@ fn mark_and_flush_pages_eio_due_consuming_writeback_limit() {
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let params = Params {
+        huge_idle: true,
+        max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
+        ..Default::default()
+    };
     let stats = default_stats(&params);
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -892,6 +1034,7 @@ fn mark_and_flush_pages_eio_due_consuming_writeback_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point
         )
         .is_ok());
@@ -903,6 +1046,7 @@ fn mark_and_flush_pages_eio_due_consuming_writeback_limit() {
             &params,
             &stats,
             &suspend_history,
+            &idle_marker,
             base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
@@ -916,6 +1060,9 @@ fn mark_and_flush_pages_output_details() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params {
+        huge_idle: true,
+        idle: true,
+        huge: true,
         max_bytes: 600 * DEFAULT_PAGE_SIZE,
         min_bytes: 10 * DEFAULT_PAGE_SIZE,
         max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
@@ -924,6 +1071,7 @@ fn mark_and_flush_pages_output_details() {
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, ..Default::default() };
     let suspend_history = SuspendHistory::new();
+    let idle_marker = TrackedIdleMarker::<MockSysfsZramApi>::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -943,6 +1091,7 @@ fn mark_and_flush_pages_output_details() {
         &params,
         &stats,
         &suspend_history,
+        &idle_marker,
         TimeApiImpl::get_boot_time(),
     );
     assert!(result.is_ok());
```

