```diff
diff --git a/Android.bp b/Android.bp
index 098b802..0c38559 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,10 +13,14 @@ rust_defaults {
         "libflags_rust",
         "liblogger",
         "liblog_rust",
-        "libmmd",
         "libmmd_flags_rust",
-        "libmockall",
+        "libmmdproperties_rust",
+        "libnix",
         "librustutils",
+        "libstatslog_rust",
+        "libstatslog_rust_header",
+        "libstatspull_rust",
+        "libthiserror",
         "mmd_aidl_interface-rust",
     ],
 }
@@ -27,8 +31,10 @@ rust_defaults {
         "src/lib.rs",
     ],
     rustlibs: [
+        "libanyhow",
+        "libscopeguard",
+        "libdm_rust",
         "liblibc",
-        "libmockall",
         "libnix",
         "libthiserror",
     ],
@@ -39,6 +45,9 @@ rust_binary {
     defaults: ["mmd_defaults"],
     stem: "mmd",
     init_rc: ["mmd.rc"],
+    rustlibs: [
+        "libmmd",
+    ],
 }
 
 rust_library {
@@ -48,17 +57,38 @@ rust_library {
     host_supported: true,
 }
 
+rust_library {
+    name: "libmmd_test_utils",
+    crate_name: "mmd",
+    features: [
+        "test_utils",
+    ],
+    defaults: ["libmmd_defaults"],
+    host_supported: true,
+    rustlibs: [
+        "libmockall",
+    ],
+}
+
 rust_test {
     name: "mmd_unit_tests",
     defaults: ["mmd_defaults"],
     test_suites: ["general-tests"],
     auto_gen_config: true,
+    rustlibs: [
+        "libmockall",
+        "libmmd_test_utils",
+    ],
 }
 
 rust_test_host {
     name: "libmmd_unit_tests",
     defaults: ["libmmd_defaults"],
     test_suites: ["general-tests"],
+    rustlibs: [
+        "libtempfile",
+        "libmockall",
+    ],
 }
 
 aconfig_declarations {
@@ -79,6 +109,11 @@ java_aconfig_library {
     aconfig_declarations: "mmd_flags",
 }
 
+cc_aconfig_library {
+    name: "mmd_flags_c_lib",
+    aconfig_declarations: "mmd_flags",
+}
+
 aidl_interface {
     name: "mmd_aidl_interface",
     unstable: true,
@@ -98,3 +133,14 @@ filegroup {
     ],
     path: "aidl",
 }
+
+sysprop_library {
+    name: "MmdProperties",
+    srcs: ["MmdProperties.sysprop"],
+    property_owner: "Platform",
+    vendor_available: true,
+    ramdisk_available: true,
+    vendor_ramdisk_available: true,
+    recovery_available: true,
+    api_packages: ["android.sysprop"],
+}
diff --git a/MmdProperties.sysprop b/MmdProperties.sysprop
new file mode 100644
index 0000000..17d0653
--- /dev/null
+++ b/MmdProperties.sysprop
@@ -0,0 +1,41 @@
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
+owner: Platform
+module: "android.sysprop.MmdProperties"
+
+# Whether mmd manages zram or not.
+#
+# If this is empty, it means either:
+#
+# * swapon_all command or other system manages zram or,
+# * zram is disabled on the system
+prop {
+    api_name: "mmd_zram_enabled"
+    type: Boolean
+    prop_name: "mmd.zram.enabled"
+    scope: Internal
+    access: Readonly
+}
+
+# The actual zram backing device size that was set up by mmd.
+# This value might be different from the requested size due to mmd adjustments
+# based on current available disk space.
+prop {
+    api_name: "actual_zram_backing_device_size"
+    type: ULong
+    prop_name: "mmd.status.zram.writeback.device_size"
+    scope: Internal
+    access: ReadWrite
+}
diff --git a/README.md b/README.md
new file mode 100644
index 0000000..6852f39
--- /dev/null
+++ b/README.md
@@ -0,0 +1,11 @@
+# mmd
+
+TBD
+
+## Apply rustfmt
+
+Before upload your changes, please apply rustfmt.
+
+```bash
+rustfmt +nightly **/*.rs
+```
diff --git a/aidl/android/os/IMmd.aidl b/aidl/android/os/IMmd.aidl
index 251f02e..569c6da 100644
--- a/aidl/android/os/IMmd.aidl
+++ b/aidl/android/os/IMmd.aidl
@@ -22,13 +22,24 @@ package android.os;
  * IMmd is oneway asynchronous API. mmd uses any information passed from outside (e.g.
  * system_server) as hints. Hint producers don't need to wait until mmd consumes the hists.
  */
-oneway interface IMmd {
+interface IMmd {
     /**
      * mmd starts zram maintenance operation (e.g. zram writeback, zram recompression) if
      * applicable.
      *
      * mmd expects this Binder is called on a good timing to execute the maintenance (e.g. while the
      * system is idle).
+     *
+     * This is oneway asynchronous API. mmd uses any information passed from outside (e.g.
+     * system_server) as hints. Hint producers don't need to wait until mmd consumes the hists.
+     */
+    oneway void doZramMaintenanceAsync();
+
+    /**
+     * Whether mmd supports doZramMaintenance() call on the device.
+     *
+     * System, which don't utilize zram, should not call doZramMaintenance() because it is no-op and
+     * useless.
      */
-    void doZramMaintenance();
+    boolean isZramMaintenanceSupported();
 }
diff --git a/api/mmd_sysprop-current.txt b/api/mmd_sysprop-current.txt
new file mode 100644
index 0000000..e69de29
diff --git a/api/mmd_sysprop-latest.txt b/api/mmd_sysprop-latest.txt
new file mode 100644
index 0000000..e69de29
diff --git a/mmd.rc b/mmd.rc
index 276f6ab..f814ce8 100644
--- a/mmd.rc
+++ b/mmd.rc
@@ -22,14 +22,6 @@ on boot
     chown root system /sys/block/zram0/writeback
     chmod 0220 /sys/block/zram0/writeback
 
-on boot && property:mmd.zram.enabled=true
-    # Allow mmd to run mkswap on zram device
-    chown root mmd /dev/block/zram0
-    chmod 0664 /dev/block/zram0
-    # Allow mmd to update zram disk size
-    chown root mmd /sys/block/zram0/disksize
-    chmod 0664 /sys/block/zram0/disksize
-
 on property:sys.boot_completed=1
     # Copy AConfig flag value to "mmd.enabled_aconfig" system property because
     # AConfig flag does not support init "on property" trigger.
@@ -41,4 +33,12 @@ on property:sys.boot_completed=1
 on property:mmd.enabled_aconfig=true
     # Enable mmd daemon if the system property copied from AConfig flag by
     # "/system/bin/mmd --set-property" is enabled.
+
+    # Zram setup requires permissions to the /dev/loop-control device and
+    # other zram sysfs files. Doing the setup as root to avoid granting mmd
+    # too many permissions for one time setup.
+    # This will be a no-op if mmd zram setup is disabled via system properties.
+    exec u:r:su:s0 root -- /system/bin/mmd --setup-zram
+
+    # Start mmd service after zram is set up.
     enable mmd
diff --git a/rustfmt.toml b/rustfmt.toml
deleted file mode 120000
index 475ba8f..0000000
--- a/rustfmt.toml
+++ /dev/null
@@ -1 +0,0 @@
-../../../build/soong/scripts/rustfmt.toml
\ No newline at end of file
diff --git a/rustfmt.toml b/rustfmt.toml
new file mode 100644
index 0000000..47df6ef
--- /dev/null
+++ b/rustfmt.toml
@@ -0,0 +1,12 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
+
+# Unstable formatter features
+# This may break the codebase in the future rust update. Let kawasin@google.com know the breakage if
+# you find, or delete these breaking formatter features if the fix is too costy.
+
+imports_granularity = "item"
+group_imports = "StdExternalCrate"
diff --git a/src/atom.rs b/src/atom.rs
new file mode 100644
index 0000000..c218557
--- /dev/null
+++ b/src/atom.rs
@@ -0,0 +1,331 @@
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
+//! This module provides utilities to report Atoms for mmd managed resources.
+
+use log::error;
+use mmd::os::get_page_size;
+use mmd::zram::recompression::Error as ZramRecompressionError;
+use mmd::zram::setup::ZramActivationError;
+use mmd::zram::stats::ZramBdStat;
+use mmd::zram::stats::ZramMmStat;
+use mmd::zram::writeback::Error as ZramWritebackError;
+use mmd::zram::writeback::WritebackDetails;
+use mmd::zram::SysfsZramApi;
+use mmd::zram::SysfsZramApiImpl;
+use statslog_rust::zram_bd_stat_mmd::ZramBdStatMmd;
+use statslog_rust::zram_maintenance_executed::RecompressionResult;
+use statslog_rust::zram_maintenance_executed::WritebackResult;
+use statslog_rust::zram_maintenance_executed::ZramMaintenanceExecuted;
+use statslog_rust::zram_mm_stat_mmd::ZramMmStatMmd;
+use statslog_rust::zram_setup_executed::CompAlgorithmSetupResult;
+use statslog_rust::zram_setup_executed::RecompressionSetupResult;
+use statslog_rust::zram_setup_executed::WritebackSetupResult;
+use statslog_rust::zram_setup_executed::ZramSetupExecuted;
+use statslog_rust::zram_setup_executed::ZramSetupResult;
+use statspull_rust::StatsPullResult;
+
+const KB: u64 = 1024;
+
+/// Converts u64 number to i64
+///
+/// If the value is more than i64::MAX, i64::MAX is returned.
+fn u64_to_i64(v: u64) -> i64 {
+    // The try_into() conversion fails only if the value is more than i64::MAX.
+    v.try_into().unwrap_or(i64::MAX)
+}
+
+/// Create the default ZramMaintenanceExecuted
+pub fn create_default_maintenance_atom() -> ZramMaintenanceExecuted {
+    ZramMaintenanceExecuted {
+        writeback_result: WritebackResult::WritebackNotSupported,
+        writeback_huge_idle_pages: 0,
+        writeback_huge_pages: 0,
+        writeback_idle_pages: 0,
+        writeback_latency_millis: 0,
+        writeback_limit_kb: 0,
+        writeback_daily_limit_kb: 0,
+        writeback_actual_limit_kb: 0,
+        writeback_total_kb: 0,
+        recompression_result: RecompressionResult::RecompressionNotSupported,
+        recompress_latency_millis: 0,
+        interval_from_previous_seconds: 0,
+    }
+}
+
+/// Update [ZramMaintenanceExecuted] based on the result of zram writeback.
+pub fn update_writeback_metrics(
+    atom: &mut ZramMaintenanceExecuted,
+    result: &Result<WritebackDetails, ZramWritebackError>,
+) {
+    atom.writeback_result = match result {
+        Ok(_) => WritebackResult::WritebackSuccess,
+        Err(ZramWritebackError::BackoffTime) => WritebackResult::WritebackBackoffTime,
+        Err(ZramWritebackError::Limit) => WritebackResult::WritebackLimit,
+        Err(ZramWritebackError::InvalidWritebackLimit) => WritebackResult::WritebackInvalidLimit,
+        Err(ZramWritebackError::CalculateIdle(_)) => WritebackResult::WritebackCalculateIdleFail,
+        Err(ZramWritebackError::MarkIdle(_)) => WritebackResult::WritebackMarkIdleFail,
+        Err(ZramWritebackError::Writeback(_)) => WritebackResult::WritebackTriggerFail,
+        Err(ZramWritebackError::WritebackLimit(_)) => {
+            WritebackResult::WritebackAccessWritebackLimitFail
+        }
+    };
+
+    if let Ok(details) = result {
+        let kb_per_page = get_page_size() / KB;
+        atom.writeback_huge_idle_pages = u64_to_i64(details.huge_idle.written_pages);
+        atom.writeback_idle_pages = u64_to_i64(details.idle.written_pages);
+        atom.writeback_huge_pages = u64_to_i64(details.huge.written_pages);
+        atom.writeback_limit_kb = u64_to_i64(details.limit_pages.saturating_mul(kb_per_page));
+        atom.writeback_daily_limit_kb =
+            u64_to_i64(details.daily_limit_pages.saturating_mul(kb_per_page));
+        atom.writeback_actual_limit_kb =
+            u64_to_i64(details.actual_limit_pages.saturating_mul(kb_per_page));
+        atom.writeback_total_kb = u64_to_i64(
+            (details
+                .huge_idle
+                .written_pages
+                .saturating_add(details.idle.written_pages)
+                .saturating_add(details.huge.written_pages))
+            .saturating_mul(kb_per_page),
+        );
+    }
+}
+
+/// Update [ZramMaintenanceExecuted] based on the result of zram recompression.
+pub fn update_recompress_metrics(
+    atom: &mut ZramMaintenanceExecuted,
+    result: &Result<(), ZramRecompressionError>,
+) {
+    atom.recompression_result = match result {
+        Ok(_) => RecompressionResult::RecompressionSuccess,
+        Err(ZramRecompressionError::BackoffTime) => RecompressionResult::RecompressionBackoffTime,
+        Err(ZramRecompressionError::CalculateIdle(_)) => {
+            RecompressionResult::RecompressionCalculateIdleFail
+        }
+        Err(ZramRecompressionError::MarkIdle(_)) => RecompressionResult::RecompressionMarkIdleFail,
+        Err(ZramRecompressionError::Recompress(_)) => RecompressionResult::RecompressionTriggerFail,
+    };
+}
+
+/// Reports ZramMmStatMmd atom.
+pub fn report_zram_mm_stat() -> StatsPullResult {
+    match generate_zram_mm_stat_atom::<SysfsZramApiImpl>() {
+        Ok(atom) => vec![Box::new(atom)],
+        Err(e) => {
+            error!("failed to load mm stat atom: {:?}", e);
+            vec![]
+        }
+    }
+}
+
+fn generate_zram_mm_stat_atom<Z: SysfsZramApi>() -> Result<ZramMmStatMmd, mmd::zram::stats::Error> {
+    let stat = ZramMmStat::load::<Z>()?;
+    let kb_per_page = get_page_size() / KB;
+    Ok(ZramMmStatMmd {
+        orig_data_kb: u64_to_i64(stat.orig_data_size / KB),
+        compr_data_kb: u64_to_i64(stat.compr_data_size / KB),
+        mem_used_total_kb: u64_to_i64(stat.mem_used_total / KB),
+        mem_limit_kb: (stat.mem_limit / (KB as u32)).into(),
+        mem_used_max_kb: stat.mem_used_max / (KB as i64),
+        same_pages_kb: u64_to_i64(stat.same_pages.saturating_mul(kb_per_page)),
+        pages_compacted_kb: (stat.pages_compacted as i64).saturating_mul(kb_per_page as i64),
+        huge_pages_kb: u64_to_i64(stat.huge_pages.unwrap_or(0).saturating_mul(kb_per_page)),
+        huge_pages_since_kb: u64_to_i64(
+            stat.huge_pages_since.unwrap_or(0).saturating_mul(kb_per_page),
+        ),
+    })
+}
+
+/// Reports ZramBdStatMmd atom.
+pub fn report_zram_bd_stat() -> StatsPullResult {
+    match generate_zram_bd_stat_atom::<SysfsZramApiImpl>() {
+        Ok(atom) => vec![Box::new(atom)],
+        Err(e) => {
+            error!("failed to load bd stat atom: {:?}", e);
+            vec![]
+        }
+    }
+}
+
+fn generate_zram_bd_stat_atom<Z: SysfsZramApi>() -> Result<ZramBdStatMmd, mmd::zram::stats::Error> {
+    let stat = ZramBdStat::load::<Z>()?;
+    let kb_per_page = get_page_size() / KB;
+    Ok(ZramBdStatMmd {
+        bd_count_kb: u64_to_i64(stat.bd_count_pages.saturating_mul(kb_per_page)),
+        bd_reads_kb: u64_to_i64(stat.bd_reads_pages.saturating_mul(kb_per_page)),
+        bd_writes_kb: u64_to_i64(stat.bd_writes_pages.saturating_mul(kb_per_page)),
+    })
+}
+
+/// Update [ZramSetupExecuted] based on the result of zram activation.
+pub fn update_zram_setup_metrics(
+    atom: &mut ZramSetupExecuted,
+    result: &Result<(), ZramActivationError>,
+) {
+    atom.zram_setup_result = match result {
+        Ok(_) => ZramSetupResult::ZramSetupSuccess,
+        Err(ZramActivationError::UpdateZramDiskSize(_)) => {
+            ZramSetupResult::ZramSetupUpdateDiskSizeFail
+        }
+        Err(ZramActivationError::SwapOn(_)) => ZramSetupResult::ZramSetupSwapOnFail,
+        Err(ZramActivationError::ExecuteMkSwap(_)) | Err(ZramActivationError::MkSwap(_)) => {
+            ZramSetupResult::ZramSetupMkSwapFail
+        }
+    };
+}
+
+/// Create the default ZramSetupExecuted atom.
+pub fn create_default_setup_atom() -> ZramSetupExecuted {
+    ZramSetupExecuted {
+        zram_setup_result: ZramSetupResult::ZramSetupUnspecified,
+        comp_algorithm_setup_result: CompAlgorithmSetupResult::CompAlgorithmSetupUnspecified,
+        writeback_setup_result: WritebackSetupResult::WritebackSetupUnspecified,
+        recompression_setup_result: RecompressionSetupResult::RecompressionSetupUnspecified,
+        zram_size_mb: 0,
+        writeback_size_mb: 0,
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use mmd::zram::writeback::WritebackModeDetails;
+    use mmd::zram::MockSysfsZramApi;
+    use mmd::zram::ZRAM_API_MTX;
+
+    use super::*;
+
+    #[test]
+    fn test_update_writeback_metrics_success() {
+        let mut atom = create_default_maintenance_atom();
+
+        update_writeback_metrics(
+            &mut atom,
+            &Ok(WritebackDetails {
+                huge_idle: WritebackModeDetails { written_pages: 1 },
+                idle: WritebackModeDetails { written_pages: 12345 },
+                huge: WritebackModeDetails { written_pages: u64::MAX },
+                limit_pages: 1,
+                daily_limit_pages: 6789,
+                actual_limit_pages: u64::MAX,
+            }),
+        );
+
+        assert!(matches!(atom.writeback_result, WritebackResult::WritebackSuccess));
+        assert_eq!(atom.writeback_huge_idle_pages, 1);
+        assert_eq!(atom.writeback_idle_pages, 12345);
+        assert_eq!(atom.writeback_huge_pages, i64::MAX);
+        let kb_per_page = get_page_size() as i64 / 1024;
+        assert_eq!(atom.writeback_limit_kb, kb_per_page);
+        assert_eq!(atom.writeback_daily_limit_kb, 6789 * kb_per_page);
+        assert_eq!(atom.writeback_actual_limit_kb, i64::MAX);
+        assert_eq!(atom.writeback_total_kb, i64::MAX);
+    }
+
+    #[test]
+    fn test_update_writeback_metrics_writeback_total_kb() {
+        let mut atom = create_default_maintenance_atom();
+
+        update_writeback_metrics(
+            &mut atom,
+            &Ok(WritebackDetails {
+                huge_idle: WritebackModeDetails { written_pages: 10 },
+                idle: WritebackModeDetails { written_pages: 200 },
+                huge: WritebackModeDetails { written_pages: 3000 },
+                ..Default::default()
+            }),
+        );
+
+        let kb_per_page = get_page_size() as i64 / 1024;
+        assert_eq!(atom.writeback_total_kb, 3210 * kb_per_page);
+    }
+
+    #[test]
+    fn test_update_writeback_metrics_on_failure() {
+        let mut atom = create_default_maintenance_atom();
+        update_writeback_metrics(&mut atom, &Err(ZramWritebackError::BackoffTime));
+        assert!(matches!(atom.writeback_result, WritebackResult::WritebackBackoffTime));
+    }
+
+    #[test]
+    fn test_update_recompress_metrics_success() {
+        let mut atom = create_default_maintenance_atom();
+        update_recompress_metrics(&mut atom, &Ok(()));
+        assert!(matches!(atom.recompression_result, RecompressionResult::RecompressionSuccess));
+    }
+
+    #[test]
+    fn test_update_recompress_metrics_on_failure() {
+        let mut atom = create_default_maintenance_atom();
+        update_recompress_metrics(&mut atom, &Err(ZramRecompressionError::BackoffTime));
+        assert!(matches!(atom.recompression_result, RecompressionResult::RecompressionBackoffTime));
+    }
+
+    #[test]
+    fn test_generate_zram_mm_stat_atom() {
+        let _m = ZRAM_API_MTX.lock();
+        let mock = MockSysfsZramApi::read_mm_stat_context();
+        mock.expect().returning(move || {
+            Ok(format!("123456 {} 1023 1024 1235 1 {} 12345 {}", u64::MAX, u32::MAX, u64::MAX))
+        });
+
+        let result = generate_zram_mm_stat_atom::<MockSysfsZramApi>();
+
+        assert!(result.is_ok());
+        let kb_per_page = get_page_size() as i64 / 1024;
+        let atom = result.unwrap();
+        assert_eq!(atom.orig_data_kb, 120);
+        assert_eq!(atom.compr_data_kb, (u64::MAX / KB) as i64);
+        assert_eq!(atom.mem_used_total_kb, 0);
+        assert_eq!(atom.mem_limit_kb, 1);
+        assert_eq!(atom.mem_used_max_kb, 1);
+        assert_eq!(atom.same_pages_kb, kb_per_page);
+        assert_eq!(atom.pages_compacted_kb, u32::MAX as i64 * kb_per_page);
+        assert_eq!(atom.huge_pages_kb, 12345 * kb_per_page);
+        assert_eq!(atom.huge_pages_since_kb, i64::MAX);
+    }
+
+    #[test]
+    fn test_generate_zram_mm_stat_atom_without_huge_pages() {
+        let _m = ZRAM_API_MTX.lock();
+        let mock = MockSysfsZramApi::read_mm_stat_context();
+        mock.expect().returning(|| Ok("12345 2 3 4 5 6 7".to_string()));
+
+        let result = generate_zram_mm_stat_atom::<MockSysfsZramApi>();
+
+        assert!(result.is_ok());
+        let kb_per_page = get_page_size() as i64 / 1024;
+        let atom = result.unwrap();
+        assert_eq!(atom.orig_data_kb, 12);
+        assert_eq!(atom.pages_compacted_kb, 7 * kb_per_page);
+        assert_eq!(atom.huge_pages_kb, 0);
+        assert_eq!(atom.huge_pages_since_kb, 0);
+    }
+
+    #[test]
+    fn test_generate_zram_bd_stat_atom() {
+        let _m = ZRAM_API_MTX.lock();
+        let mock = MockSysfsZramApi::read_bd_stat_context();
+        mock.expect().returning(move || Ok(format!("1 12345 {}", u64::MAX)));
+
+        let result = generate_zram_bd_stat_atom::<MockSysfsZramApi>();
+
+        assert!(result.is_ok());
+        let kb_per_page = get_page_size() as i64 / 1024;
+        let atom = result.unwrap();
+        assert_eq!(atom.bd_count_kb, kb_per_page);
+        assert_eq!(atom.bd_reads_kb, 12345 * kb_per_page);
+        assert_eq!(atom.bd_writes_kb, i64::MAX);
+    }
+}
diff --git a/src/block_dev.rs b/src/block_dev.rs
new file mode 100644
index 0000000..91d9ed7
--- /dev/null
+++ b/src/block_dev.rs
@@ -0,0 +1,314 @@
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
+//! This module defines block device utilities used for mmd.
+
+use std::fs;
+use std::os::unix::fs::MetadataExt;
+use std::path::Path;
+use std::path::PathBuf;
+
+/// Error from block device operations.
+#[derive(Debug, thiserror::Error)]
+pub enum BlockDeviceError {
+    /// Failed to perform an IO operation on some block device file
+    #[error("failed to perform IOs on a block device file: {0}")]
+    DeviceFileIo(#[from] std::io::Error),
+    /// Failed to get input file metadata
+    #[error("failed to get input file metadata: {0}")]
+    InputFileMetadata(std::io::Error),
+    /// Failed to parse device queue depth
+    #[error("failed to parse device queue depth: {0}")]
+    ParseDeviceQueueDepth(#[from] std::num::ParseIntError),
+    /// Block dev path is invalid
+    #[error("block device path {0} is invalid: {1}")]
+    InvalidBlockDevicePath(PathBuf, String),
+}
+
+type Result<T> = std::result::Result<T, BlockDeviceError>;
+
+/// Clear device IO scheduler by setting the scheduler to none.
+///
+/// Only works for Kernels version v4.1 and after. Kernels before v4.1 only support 'noop'.
+/// However, Android does not need to support kernels lower than v4.1 because v6.1 is the minimum
+/// version on Android 15.
+pub fn clear_block_device_scheduler(device_name: &str) -> std::io::Result<()> {
+    fs::write(format!("/sys/block/{device_name}/queue/scheduler"), "none")
+}
+
+/// Configure block device `nr_requests` to be the same as the queue depth of the block device backing `file_path`.
+pub fn configure_block_device_queue_depth<P: AsRef<Path>>(
+    device_name: &str,
+    file_path: P,
+) -> Result<()> {
+    configure_block_device_queue_depth_with_sysfs(device_name, file_path.as_ref(), "/sys")
+}
+
+// Using `&str` type instead of `&Path` for `sysfs_path` to make it easier for formatting block
+// device paths. It should be fince since this is a private method introduced for testability only.
+fn configure_block_device_queue_depth_with_sysfs(
+    device_name: &str,
+    file_path: &Path,
+    sysfs_path: &str,
+) -> Result<()> {
+    let file_backing_device = find_backing_block_device(file_path, sysfs_path)?;
+
+    let backing_device_queue_depth =
+        fs::read_to_string(format!("{sysfs_path}/class/block/{file_backing_device}/mq/0/nr_tags"))?;
+    let backing_device_queue_depth = backing_device_queue_depth.trim().parse::<u32>()?;
+
+    fs::write(
+        format!("{sysfs_path}/class/block/{device_name}/queue/nr_requests"),
+        backing_device_queue_depth.to_string(),
+    )?;
+    Ok(())
+}
+
+/// For file `file_path`, retrieve the block device backing the filesystem on
+/// which the file exists.
+fn find_backing_block_device(file_path: &Path, sysfs_path: &str) -> Result<String> {
+    let mut device_name = get_block_device_name(file_path, sysfs_path)?;
+
+    while let Some(parent_device) = get_parent_block_device(&device_name, sysfs_path)? {
+        device_name = parent_device;
+    }
+
+    device_name = partition_parent(&device_name, sysfs_path)?;
+
+    Ok(device_name)
+}
+
+/// Get immediate block device name backing `file_path`.
+///
+/// By following the symlink `/sys/dev/block/{major}:{minor}` to the actual device path.
+fn get_block_device_name(file_path: &Path, sysfs_path: &str) -> Result<String> {
+    let devnum =
+        fs::metadata(file_path).map_err(BlockDeviceError::InputFileMetadata)?.dev() as libc::dev_t;
+    // TODO: b/388993276 - Use nix::sys::stat::major|minor once they are configured to be built for Android.
+    // SAFETY: devnum should be valid because it's from file metadata.
+    let (major, minor) = unsafe { (libc::major(devnum), libc::minor(devnum)) };
+    let device_path = std::fs::canonicalize(format!("{sysfs_path}/dev/block/{major}:{minor}"))?;
+    Ok(device_path
+        .file_name()
+        .ok_or_else(|| {
+            BlockDeviceError::InvalidBlockDevicePath(
+                device_path.clone(),
+                "block device real path doesn't have a file name".to_string(),
+            )
+        })?
+        .to_str()
+        .ok_or_else(|| {
+            BlockDeviceError::InvalidBlockDevicePath(
+                device_path.clone(),
+                "block device name is not valid Unicode".to_string(),
+            )
+        })?
+        .to_string())
+}
+
+/// Returns a parent block device of a dm device with the given name.
+///
+/// None will be returned if:
+///  * Given path doesn't correspond to a dm device.
+///  * A dm device is based on top of more than one block devices.
+fn get_parent_block_device(device_name: &str, sysfs_path: &str) -> std::io::Result<Option<String>> {
+    if !device_name.starts_with("dm-") {
+        // Reached bottom of the device mapper stack.
+        return Ok(None);
+    }
+    let mut sub_device_name = None;
+    for entry in fs::read_dir(format!("{sysfs_path}/block/{device_name}/slaves"))? {
+        let entry = entry?;
+        if entry.file_type()?.is_symlink() {
+            if sub_device_name.is_some() {
+                // Too many slaves. Returning None to be consistent with fs_mgr's libdm implementation:
+                // https://cs.android.com/android/platform/superproject/main/+/main:system/core/fs_mgr/libdm/dm.cpp;l=677-678;drc=2bd1c1b20871bcf4ef4660beaa218f2c2bce4630
+                return Ok(None);
+            }
+            sub_device_name = Some(entry.file_name().to_string_lossy().to_string());
+        }
+    }
+    Ok(sub_device_name)
+}
+
+/// Returns the parent device of a partition.
+///
+/// Converts e.g. "sda26" into "sda".
+fn partition_parent(device_name: &str, sysfs_path: &str) -> std::io::Result<String> {
+    for entry in fs::read_dir(format!("{sysfs_path}/class/block"))? {
+        let name = entry?.file_name();
+        let name = name.to_string_lossy();
+
+        if name.starts_with('.') {
+            continue;
+        }
+
+        if fs::exists(format!("{sysfs_path}/class/block/{name}/{device_name}"))? {
+            return Ok(name.to_string());
+        }
+    }
+    Ok(device_name.to_string())
+}
+
+#[cfg(test)]
+mod tests {
+    use std::os::unix::fs::symlink;
+
+    use tempfile::tempdir;
+    use tempfile::TempDir;
+
+    use super::*;
+
+    enum FakeFs<'a> {
+        Symlink(&'a str, &'a str),
+        File(&'a str, &'a str),
+        Dir(&'a str),
+        BackingDevice(&'a Path, &'a str),
+    }
+
+    impl FakeFs<'_> {
+        fn build(entries: &[Self]) -> TempDir {
+            let tempdir = tempdir().unwrap();
+            let root = tempdir.path();
+            for entry in entries {
+                match entry {
+                    Self::Symlink(link, original) => {
+                        let link = root.join(link.trim_start_matches("/"));
+                        let original = root.join(original.trim_start_matches("/"));
+                        fs::create_dir_all(link.parent().unwrap()).unwrap();
+                        symlink(original, link).unwrap();
+                    }
+                    Self::File(path, content) => {
+                        let path = root.join(path.trim_start_matches("/"));
+                        fs::create_dir_all(path.parent().unwrap()).unwrap();
+                        fs::write(path, content).unwrap();
+                    }
+                    Self::Dir(path) => {
+                        fs::create_dir_all(root.join(path.trim_start_matches("/"))).unwrap();
+                    }
+                    Self::BackingDevice(file_path, device_path) => {
+                        let device_path = root.join(device_path.trim_start_matches("/"));
+                        let devnum = fs::metadata(file_path).unwrap().dev() as libc::dev_t;
+                        // TODO: b/388993276 - Use nix::sys::stat::major|minor once they are configured to be built for Android.
+                        // SAFETY: devnum should be valid because it's from file metadata.
+                        let (major, minor) = unsafe { (libc::major(devnum), libc::minor(devnum)) };
+                        let link = root.join(format!("sys/dev/block/{major}:{minor}"));
+                        fs::create_dir_all(link.parent().unwrap()).unwrap();
+                        symlink(device_path, link).unwrap();
+                    }
+                }
+            }
+            tempdir
+        }
+    }
+
+    #[test]
+    fn find_backing_block_device_simple() {
+        let file = tempfile::NamedTempFile::new().unwrap();
+        let fake_fs = FakeFs::build(&[
+            FakeFs::Dir("/sys/devices/platform/block/vda/"),
+            FakeFs::Symlink("/sys/class/block/vda", "/sys/devices/platform/block/vda/"),
+            FakeFs::BackingDevice(file.path(), "/sys/devices/platform/block/vda"),
+        ]);
+
+        assert_eq!(
+            find_backing_block_device(file.path(), fake_fs.path().join("sys").to_str().unwrap())
+                .unwrap(),
+            "vda"
+        );
+    }
+
+    #[test]
+    fn find_backing_block_device_device_mapper() {
+        let file = tempfile::NamedTempFile::new().unwrap();
+        let fake_fs = FakeFs::build(&[
+            FakeFs::Dir("/sys/devices/platform/block/vda/"),
+            FakeFs::Dir("/sys/devices/virtual/block/dm-0/"),
+            FakeFs::Dir("/sys/devices/virtual/block/dm-7/"),
+            FakeFs::Symlink("/sys/block/dm-0/slaves/vda", "/sys/devices/platform/block/vda"),
+            FakeFs::Symlink("/sys/block/dm-7/slaves/dm-0", "/sys/devices/virtual/block/dm-0"),
+            FakeFs::Symlink("/sys/class/block/vda", "/sys/devices/platform/block/vda"),
+            FakeFs::BackingDevice(file.path(), "/sys/devices/virtual/block/dm-7"),
+        ]);
+
+        assert_eq!(
+            find_backing_block_device(file.path(), fake_fs.path().join("sys").to_str().unwrap())
+                .unwrap(),
+            "vda"
+        );
+    }
+
+    #[test]
+    fn find_backing_block_device_parent_partition() {
+        let file = tempfile::NamedTempFile::new().unwrap();
+        let fake_fs = FakeFs::build(&[
+            FakeFs::Dir("/sys/devices/platform/block/vda/vda2"),
+            FakeFs::Symlink("/sys/class/block/vda", "/sys/devices/platform/block/vda"),
+            FakeFs::Symlink("/sys/class/block/vda2", "/sys/devices/platform/block/vda/vda2"),
+            FakeFs::BackingDevice(file.path(), "/sys/devices/platform/block/vda/vda2"),
+        ]);
+
+        assert_eq!(
+            find_backing_block_device(file.path(), fake_fs.path().join("sys").to_str().unwrap())
+                .unwrap(),
+            "vda"
+        );
+    }
+
+    #[test]
+    fn configure_block_device_queue_depth() {
+        let file = tempfile::NamedTempFile::new().unwrap();
+        let fake_fs = FakeFs::build(&[
+            FakeFs::File("/sys/devices/platform/block/vda/mq/0/nr_tags", "31"),
+            FakeFs::File("/sys/devices/virtual/block/loop97/queue/nr_requests", "128"),
+            FakeFs::Symlink("/sys/class/block/vda", "/sys/devices/platform/block/vda"),
+            FakeFs::Symlink("/sys/class/block/loop97", "/sys/devices/virtual/block/loop97"),
+            FakeFs::BackingDevice(file.path(), "/sys/devices/platform/block/vda/"),
+        ]);
+
+        configure_block_device_queue_depth_with_sysfs(
+            "loop97",
+            file.path(),
+            fake_fs.path().join("sys").to_str().unwrap(),
+        )
+        .unwrap();
+
+        assert_eq!(
+            fs::read_to_string(fake_fs.path().join("sys/class/block/loop97/queue/nr_requests"))
+                .unwrap(),
+            "31"
+        );
+    }
+
+    #[test]
+    fn configure_block_device_queue_depth_error() {
+        let file = tempfile::NamedTempFile::new().unwrap();
+        let fake_fs = FakeFs::build(&[
+            FakeFs::Dir("/sys/devices/platform/block/vda/"),
+            FakeFs::File("/sys/devices/virtual/block/loop97/queue/nr_requests", "128"),
+            FakeFs::Symlink("/sys/class/block/vda", "/sys/devices/platform/block/vda"),
+            FakeFs::Symlink("/sys/class/block/loop97", "/sys/devices/virtual/block/loop97"),
+            FakeFs::BackingDevice(file.path(), "/sys/devices/platform/block/vda/"),
+        ]);
+
+        assert!(matches!(
+            configure_block_device_queue_depth_with_sysfs(
+                "loop97",
+                file.path(),
+                fake_fs.path().join("sys").to_str().unwrap()
+            ),
+            Err(BlockDeviceError::DeviceFileIo(_))
+        ));
+    }
+}
diff --git a/src/lib.rs b/src/lib.rs
index 3536c99..2ae9166 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -14,5 +14,9 @@
 
 //! This is library part of mmd which does not depends on Android specific APIs.
 
+pub mod block_dev;
 pub mod os;
+pub mod size_spec;
+pub mod suspend_history;
+pub mod time;
 pub mod zram;
diff --git a/src/main.rs b/src/main.rs
index 859d5d7..6655c76 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -16,53 +16,416 @@
 //!
 //! * zram
 
+mod atom;
 mod properties;
 mod service;
 
+use std::fmt;
+use std::path::Path;
+use std::sync::Arc;
+use std::sync::Mutex;
+use std::time::Duration;
+use std::time::Instant;
+
+use anyhow::anyhow;
+use anyhow::Context;
 use binder::BinderFeatures;
 use log::error;
 use log::info;
 use log::warn;
 use log::LevelFilter;
-use mmd::zram::recompression::is_zram_recompression_activated;
+use mmd::block_dev::clear_block_device_scheduler;
+use mmd::block_dev::configure_block_device_queue_depth;
+use mmd::os::get_page_count;
+use mmd::os::get_page_size;
+use mmd::size_spec::parse_size_spec;
+use mmd::suspend_history::SuspendHistory;
+use mmd::suspend_history::SuspendMonitor;
+use mmd::time::TimeApiImpl;
+use mmd::zram::recompression::get_zram_recompression_status;
 use mmd::zram::recompression::ZramRecompression;
+use mmd::zram::recompression::ZramRecompressionStatus;
 use mmd::zram::setup::activate_zram;
+use mmd::zram::setup::create_zram_writeback_device;
+use mmd::zram::setup::enable_zram_writeback_limit;
 use mmd::zram::setup::is_zram_swap_activated;
-use mmd::zram::setup::parse_zram_size_spec;
 use mmd::zram::setup::SetupApiImpl;
+use mmd::zram::setup::WritebackDeviceSetupError;
 use mmd::zram::stats::load_total_zram_size;
-use mmd::zram::writeback::is_zram_writeback_activated;
+use mmd::zram::writeback::get_zram_writeback_status;
 use mmd::zram::writeback::ZramWriteback;
+use mmd::zram::writeback::ZramWritebackStatus;
+use mmd::zram::SysfsZramApi;
 use mmd::zram::SysfsZramApiImpl;
 use mmd_aidl_interface::aidl::android::os::IMmd::BnMmd;
+use nix::sys::statvfs::statvfs;
+use properties::SecondsProp;
+use properties::U64Prop;
 use rustutils::system_properties;
+use statslog_rust::zram_setup_executed::CompAlgorithmSetupResult;
+use statslog_rust::zram_setup_executed::RecompressionSetupResult;
+use statslog_rust::zram_setup_executed::WritebackSetupResult;
+use statslog_rust::zram_setup_executed::ZramSetupExecuted;
+use statslog_rust::zram_setup_executed::ZramSetupResult;
+use statspull_rust::set_pull_atom_callback;
 
+use crate::atom::create_default_setup_atom;
+use crate::atom::report_zram_bd_stat;
+use crate::atom::report_zram_mm_stat;
+use crate::atom::update_zram_setup_metrics;
+use crate::properties::is_zram_enabled;
 use crate::properties::BoolProp;
 use crate::properties::StringProp;
 
+struct ZramContext {
+    zram_writeback: Option<ZramWriteback>,
+    zram_recompression: Option<ZramRecompression>,
+    suspend_history: SuspendHistory,
+    last_maintenance_at: Instant,
+}
+
+const DEFAULT_ZRAM_WRITEBACK_ENABLED: bool = false;
+
 // In Android zram writeback file is always "/data/per_boot/zram_swap".
 const ZRAM_WRITEBACK_FILE_PATH: &str = "/data/per_boot/zram_swap";
 
-fn setup_zram() -> anyhow::Result<()> {
+// Default writeback device size of 1G.
+const DEFAULT_WRITEBACK_DEVICE_SIZE: u64 = 1 << 30;
+
+// Default minimum freespace for writeback file setup is 1.5G.
+const DEFAULT_WRITEBACK_MIN_FREE_SPACE_MIB: u64 = 1536;
+
+// The default minimum size a zram writeback device may be.
+// This prevents a writeback device of 1MiB from being created, for example.
+const DEFAULT_WRITEBACK_MIN_VOLUME_SIZE: u64 = 128 << 20; // 128 MiB.
+
+const DEFAULT_ZRAM_RECOMPRESSION_ENABLED: bool = false;
+const DEFAULT_ZRAM_RECOMPRESSION_ALGORITHM: &str = "zstd";
+
+const MAX_ZRAM_PERCENTAGE_ALLOWED: u64 = 500;
+const MAX_WRITEBACK_SIZE_PERCENTAGE_ALLOWED: u64 = 100;
+
+// MiB in bytes.
+const MIB: u64 = 1 << 20;
+
+fn adjust_writeback_device_size(
+    requested_device_size: u64,
+    min_free_space: u64,
+    free_space: u64,
+    block_size: u64,
+) -> u64 {
+    if free_space <= min_free_space {
+        info!("there is not enough free space to meet the minimum space requirement of {min_free_space} bytes to set up zram writeback device");
+        return 0;
+    }
+
+    let mut adjusted_device_size = if requested_device_size + min_free_space > free_space {
+        let adjusted_device_size = free_space - min_free_space;
+        info!("adjusting zram writeback device size from {requested_device_size} to {adjusted_device_size} bytes to meet the minimum space requirement of {min_free_space} bytes");
+        adjusted_device_size
+    } else {
+        requested_device_size
+    };
+
+    if adjusted_device_size < DEFAULT_WRITEBACK_MIN_VOLUME_SIZE {
+        info!("adjusting zram writeback device size to 0, since the device size of {adjusted_device_size} is less than the minimum device size of {DEFAULT_WRITEBACK_MIN_VOLUME_SIZE} bytes");
+        return 0;
+    }
+
+    if adjusted_device_size % block_size != 0 {
+        adjusted_device_size = adjusted_device_size - adjusted_device_size % block_size;
+        info!("adjusting zram writeback device size to {adjusted_device_size} for block size alignment");
+    }
+    adjusted_device_size
+}
+
+#[derive(thiserror::Error)]
+#[error("{source}")]
+struct WritebackSetupError {
+    source: anyhow::Error,
+    reason: WritebackSetupResult,
+}
+
+impl fmt::Debug for WritebackSetupError {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        write!(f, "{0:?}", self.source)
+    }
+}
+
+fn setup_zram_writeback() -> Result<u64, WritebackSetupError> {
+    let zram_writeback_status =
+        get_zram_writeback_status::<SysfsZramApiImpl>().map_err(|e| WritebackSetupError {
+            source: e.into(),
+            reason: WritebackSetupResult::WritebackSetupCheckStatus,
+        })?;
+    match zram_writeback_status {
+        ZramWritebackStatus::Unsupported => {
+            return Err(WritebackSetupError {
+                source: anyhow!(
+                    "zram writeback is not supported by the kernel, skipping zram \
+                    writeback device setup"
+                ),
+                reason: WritebackSetupResult::WritebackSetupNotSupported,
+            });
+        }
+        ZramWritebackStatus::Activated => {
+            return Err(WritebackSetupError {
+                source: anyhow!(
+                    "zram writeback is already activated, skipping zram writeback device setup"
+                ),
+                reason: WritebackSetupResult::WritebackSetupActivated,
+            });
+        }
+        ZramWritebackStatus::NotConfigured => {
+            // Do nothing, we should proceed to set up the writeback device.
+        }
+    };
+
+    enable_zram_writeback_limit::<SysfsZramApiImpl>()
+        .context("failed to enable zram writeback limit")
+        .map_err(|e| WritebackSetupError {
+            source: e,
+            reason: WritebackSetupResult::WritebackSetupWritebackLimitEnableFail,
+        })?;
+
+    let backing_device_size_spec =
+        StringProp::ZramWritebackDeviceSize.get(&DEFAULT_WRITEBACK_DEVICE_SIZE);
+    let partition_stat =
+        statvfs("/data").context("failed to get /data partition stats").map_err(|e| {
+            WritebackSetupError { source: e, reason: WritebackSetupResult::WritebackSetupParseSpec }
+        })?;
+    // Fragment size isn't a commonly used term in file systems on linux, in most other cases
+    // than NFS they are equal to block size. However POSIX defines the unit of f_blocks as
+    // f_frsize.
+    // https://man7.org/linux/man-pages/man3/statvfs.3.html
+    // We prioritize following POSIX compatibility than readability on codebase here.
+    // libc::c_ulong and libc::fsblkcnt_t can be non-u64 on some platforms for statvfs fields.
+    #[allow(clippy::useless_conversion)]
+    let partition_block_size = u64::from(partition_stat.fragment_size());
+    let requested_device_size = parse_size_spec(
+        &backing_device_size_spec,
+        partition_block_size,
+        // libc::c_ulong and libc::fsblkcnt_t can be non-u64 on some platforms for statvfs fields.
+        #[allow(clippy::useless_conversion)]
+        u64::from(partition_stat.blocks()),
+        MAX_WRITEBACK_SIZE_PERCENTAGE_ALLOWED,
+    )
+    .context("failed to parse device size spec")
+    .map_err(|e| WritebackSetupError {
+        source: e,
+        reason: WritebackSetupResult::WritebackSetupParseSpec,
+    })?;
+    // libc::c_ulong and libc::fsblkcnt_t can be non-u64 on some platforms for statvfs fields.
+    #[allow(clippy::useless_conversion)]
+    let backing_device_size = adjust_writeback_device_size(
+        requested_device_size,
+        U64Prop::ZramWritebackMinFreeSpaceMib.get(DEFAULT_WRITEBACK_MIN_FREE_SPACE_MIB) * MIB,
+        partition_block_size * u64::from(partition_stat.blocks_free()),
+        partition_block_size,
+    );
+    if backing_device_size == 0 {
+        warn!("zram writeback is enabled but backing device size is 0, skipping zram writeback device setup");
+        return Ok(backing_device_size);
+    }
+
+    mmdproperties::mmdproperties::set_actual_zram_backing_device_size(backing_device_size)
+        .context("failed to update actual zram writeback device size")
+        .map_err(|e| WritebackSetupError {
+            source: e,
+            reason: WritebackSetupResult::WritebackSetupSetActualDeviceSizeFail,
+        })?;
+
+    info!("setting up zram writeback device with size {}", backing_device_size);
+    let writeback_device = create_zram_writeback_device::<SetupApiImpl>(
+        Path::new(ZRAM_WRITEBACK_FILE_PATH),
+        backing_device_size,
+    )
+    .map_err(|e| match e {
+        WritebackDeviceSetupError::CreateBackingFile(_) => WritebackSetupError {
+            source: e.into(),
+            reason: WritebackSetupResult::WritebackSetupCreateBackingFileFail,
+        },
+        WritebackDeviceSetupError::CreateBackingDevice(_) => WritebackSetupError {
+            source: e.into(),
+            reason: WritebackSetupResult::WritebackSetupCreateBackingDeviceFail,
+        },
+    })?;
+
+    let device_path = writeback_device.path;
+    let device_name = device_path
+        .file_name()
+        .and_then(std::ffi::OsStr::to_str)
+        .context("failed to get backing device name")
+        .map_err(|e| WritebackSetupError {
+            source: e,
+            reason: WritebackSetupResult::WritebackSetupCreateBackingDeviceFail,
+        })?;
+    if let Err(e) = clear_block_device_scheduler(device_name) {
+        warn!("failed to clear writeback device scheduler: {e:?}");
+    }
+    if let Err(e) = configure_block_device_queue_depth(device_name, "/") {
+        warn!("failed to configure device queue depth: {e:?}");
+    }
+
+    let device_path_str = device_path
+        .to_str()
+        .context("failed to get backing device path")
+        .map_err(|e| WritebackSetupError {
+            source: e,
+            reason: WritebackSetupResult::WritebackSetupCreateBackingDeviceFail,
+        })?;
+    SysfsZramApiImpl::write_backing_dev(device_path_str)
+        .context("failed to set zram backing device")
+        .map_err(|e| WritebackSetupError {
+            source: e,
+            reason: WritebackSetupResult::WritebackSetupSetWritebackDeviceFail,
+        })?;
+    Ok(backing_device_size)
+}
+
+#[derive(thiserror::Error)]
+#[error("{source}")]
+struct RecompressionError {
+    source: anyhow::Error,
+    reason: RecompressionSetupResult,
+}
+
+impl fmt::Debug for RecompressionError {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        write!(f, "{0:?}", self.source)
+    }
+}
+
+fn setup_zram_recompression() -> Result<(), RecompressionError> {
+    match get_zram_recompression_status::<SysfsZramApiImpl>().map_err(|e| RecompressionError {
+        source: e.into(),
+        reason: RecompressionSetupResult::RecompressionSetupCheckStatus,
+    })? {
+        ZramRecompressionStatus::Unsupported => {
+            return Err(RecompressionError {
+                source: anyhow!(
+                    "zram recompression is not supported by the kernel, skipping zram \
+                    recompression setup"
+                ),
+                reason: RecompressionSetupResult::RecompressionSetupNotSupported,
+            });
+        }
+        ZramRecompressionStatus::Activated => {
+            return Err(RecompressionError {
+                source: anyhow!(
+                    "zram recompression is already activated, skipping zram recompression setup"
+                ),
+                reason: RecompressionSetupResult::RecompressionSetupActivated,
+            });
+        }
+        ZramRecompressionStatus::NotConfigured => {
+            // Do nothing, we should proceed to set up recompression algorithm.
+        }
+    };
+
+    let recompression_algorithm =
+        StringProp::ZramRecompressionAlgorithm.get(DEFAULT_ZRAM_RECOMPRESSION_ALGORITHM);
+    let recomp_algo_config = format!("algo={recompression_algorithm}");
+    SysfsZramApiImpl::write_recomp_algorithm(&recomp_algo_config)
+        .context(format!(
+            "Failed to set up recompression algorithm with config {recomp_algo_config}"
+        ))
+        .map_err(|e| RecompressionError {
+            source: e,
+            reason: RecompressionSetupResult::RecompressionSetupSetRecompAlgorithmFail,
+        })?;
+
+    Ok(())
+}
+
+fn setup_zram(zram_setup_atom: &mut ZramSetupExecuted) -> anyhow::Result<()> {
+    zram_setup_atom.zram_setup_result = ZramSetupResult::ZramSetupCheckStatus;
     let zram_activated = is_zram_swap_activated::<SetupApiImpl>()?;
     if zram_activated {
         info!("zram is already on, skipping zram setup");
+        zram_setup_atom.zram_setup_result = ZramSetupResult::ZramSetupActivated;
         return Ok(());
     }
 
+    if BoolProp::ZramWritebackEnabled.get(DEFAULT_ZRAM_WRITEBACK_ENABLED) {
+        match setup_zram_writeback() {
+            Ok(device_size) => {
+                if device_size > 0 {
+                    // u64 bytes in MiB should fit int64.
+                    zram_setup_atom.writeback_size_mb = (device_size / MIB) as i64;
+                    zram_setup_atom.writeback_setup_result =
+                        WritebackSetupResult::WritebackSetupSuccess;
+                } else {
+                    zram_setup_atom.writeback_setup_result =
+                        WritebackSetupResult::WritebackSetupDeviceSizeZero;
+                }
+            }
+            Err(e) => {
+                error!(
+                    "failed to set up zram writeback: {e:?}, zram device will be set up with no \
+                    backing device"
+                );
+                zram_setup_atom.writeback_setup_result = e.reason;
+            }
+        }
+    }
+
+    if BoolProp::ZramRecompressionEnabled.get(DEFAULT_ZRAM_RECOMPRESSION_ENABLED) {
+        match setup_zram_recompression() {
+            Ok(()) => {
+                zram_setup_atom.recompression_setup_result =
+                    RecompressionSetupResult::RecompressionSetupSuccess;
+            }
+            Err(e) => {
+                error!(
+                    "failed to set up zram recompression: {e:?}, zram device will be set up \
+                    without recompression feature"
+                );
+                zram_setup_atom.recompression_setup_result = e.reason;
+            }
+        }
+    }
+
+    zram_setup_atom.zram_setup_result = ZramSetupResult::ZramSetupParseSpec;
     let zram_size_spec = StringProp::ZramSize.get("50%");
-    let zram_size = parse_zram_size_spec(&zram_size_spec)?;
-    activate_zram::<SysfsZramApiImpl, SetupApiImpl>(zram_size)?;
+    let zram_size = parse_size_spec(
+        &zram_size_spec,
+        get_page_size(),
+        get_page_count(),
+        MAX_ZRAM_PERCENTAGE_ALLOWED,
+    )?;
+    let comp_algorithm = StringProp::ZramCompAlgorithm.get("");
+    if !comp_algorithm.is_empty() {
+        match SysfsZramApiImpl::write_comp_algorithm(&comp_algorithm) {
+            Ok(_) => {
+                zram_setup_atom.comp_algorithm_setup_result =
+                    CompAlgorithmSetupResult::CompAlgorithmSetupSuccess;
+            }
+            Err(e) => {
+                // Continue to utilize zram with default algorithm if specifying algorithm fails
+                // (e.g. the algorithm is not supported by the kernel).
+                error!("failed to update zram comp algorithm: {e:?}");
+                zram_setup_atom.comp_algorithm_setup_result =
+                    CompAlgorithmSetupResult::CompAlgorithmSetupFail;
+            }
+        }
+    }
+    let activate_result = activate_zram::<SysfsZramApiImpl, SetupApiImpl>(zram_size);
+    update_zram_setup_metrics(zram_setup_atom, &activate_result);
+    activate_result?;
+    // u64 bytes in MiB should fit int64.
+    zram_setup_atom.zram_size_mb = (zram_size / MIB) as i64;
     Ok(())
 }
 
 fn main() {
+    let cmd = std::env::args().nth(1).unwrap_or_default();
     // "mmd --set-property" command copies the AConfig flag to "mmd.enabled_aconfig" system
     // property as either "true" or "false".
     // This is the workaround for init language which does not support AConfig integration.
     // TODO: b/380365026 - Remove "--set-property" command when init language supports AConfig
     // integration.
-    if std::env::args().nth(1).map(|s| &s == "--set-property").unwrap_or(false) {
+    if cmd == "--set-property" {
         let value = if mmd_flags::mmd_enabled() { "true" } else { "false" };
         system_properties::write("mmd.enabled_aconfig", value).expect("set system property");
         return;
@@ -79,74 +442,257 @@ fn main() {
         return;
     }
 
-    if BoolProp::ZramEnabled.get(false) {
-        setup_zram().expect("zram setup");
+    if cmd == "--setup-zram" {
+        if !is_zram_enabled() {
+            warn!("mmd zram setup is disabled");
+            return;
+        }
+        let mut zram_setup_atom = create_default_setup_atom();
+        let setup_zram_result = setup_zram(&mut zram_setup_atom);
+        if let Err(e) = zram_setup_atom.stats_write() {
+            error!("failed to submit ZramSetupExecuted atom: {e:?}");
+        }
+        setup_zram_result.expect("zram setup");
+        return;
+    } else if !cmd.is_empty() {
+        error!(
+            "unexpected command {cmd}. mmd only supports either --set-property or --setup-zram."
+        );
+        return;
     }
 
-    let total_zram_size = match load_total_zram_size::<SysfsZramApiImpl>() {
-        Ok(v) => v,
+    let mut zram_writeback = match load_zram_writeback_disk_size() {
+        Ok(Some(zram_writeback_disk_size)) => {
+            info!("zram writeback is activated");
+            match load_total_zram_size::<SysfsZramApiImpl>() {
+                Ok(total_zram_size) => {
+                    Some(ZramWriteback::new(total_zram_size, zram_writeback_disk_size))
+                }
+                Err(e) => {
+                    error!("failed to load total zram size: {e:?}");
+                    None
+                }
+            }
+        }
+        Ok(None) => {
+            info!("zram writeback is not activated");
+            None
+        }
         Err(e) => {
-            error!("failed to load total zram size: {e:?}");
-            std::process::exit(1);
+            error!("failed to load zram writeback file size: {e:?}");
+            None
         }
     };
-    let zram_writeback = if BoolProp::ZramWritebackEnabled.get(true) {
-        match load_zram_writeback_disk_size() {
-            Ok(Some(zram_writeback_disk_size)) => {
-                info!("zram writeback is activated");
-                Some(ZramWriteback::new(total_zram_size, zram_writeback_disk_size))
-            }
-            Ok(None) => {
-                info!("zram writeback is not activated");
-                None
-            }
-            Err(e) => {
-                error!("failed to load zram writeback file size: {e:?}");
+
+    let mut zram_recompression = match get_zram_recompression_status::<SysfsZramApiImpl>() {
+        Ok(status) => {
+            if status == ZramRecompressionStatus::Activated {
+                info!("zram recompression is activated");
+                Some(ZramRecompression::new())
+            } else {
+                info!("zram recompression is not activated");
                 None
             }
         }
-    } else {
-        info!("zram writeback is disabled");
-        None
+        Err(e) => {
+            error!("failed to check zram recompression is activated: {e:?}");
+            None
+        }
     };
 
-    let zram_recompression = if BoolProp::ZramRecompressionEnabled.get(true) {
-        match is_zram_recompression_activated::<SysfsZramApiImpl>() {
-            Ok(is_activated) => {
-                if is_activated {
-                    info!("zram recompression is activated");
-                    Some(ZramRecompression::new())
-                } else {
-                    info!("zram recompression is not activated");
-                    None
+    if zram_writeback.is_some() || zram_recompression.is_some() {
+        match is_idle_aging_supported() {
+            Ok(idle_aging_supported) => {
+                if !idle_aging_supported {
+                    warn!(
+                        "mmd zram maintenance is disabled due to missing kernel config. mmd zram \
+                        maintenance requires either CONFIG_ZRAM_TRACK_ENTRY_ACTIME or \
+                        CONFIG_ZRAM_MEMORY_TRACKING kernel config enabled for tracking idle pages \
+                        based on last accessed time."
+                    );
+                    // TODO: b/396439110 - Implement some zram maintenance fallback logic to
+                    // support the case when idle aging is not supported by the kernel. Eg: only
+                    // handle huge pages.
+                    zram_writeback = None;
+                    zram_recompression = None;
                 }
             }
             Err(e) => {
-                error!("failed to check zram recompression is activated: {e:?}");
-                None
+                error!(
+                    "failed to check whether idle aging is supported, mmd zram maintenance is \
+                    enabled but might not work properly: {e:?}"
+                );
             }
         }
-    } else {
-        info!("zram recompression is disabled");
-        None
     };
 
-    let mmd_service = service::MmdService::new(zram_writeback, zram_recompression);
+    let ctx = Arc::new(Mutex::new(ZramContext {
+        zram_writeback,
+        zram_recompression,
+        suspend_history: SuspendHistory::new(),
+        last_maintenance_at: Instant::now(),
+    }));
+
+    let mmd_service = service::MmdService::new(ctx.clone());
     let mmd_service_binder = BnMmd::new_binder(mmd_service, BinderFeatures::default());
     binder::add_service("mmd", mmd_service_binder.as_binder()).expect("register service");
 
+    let suspend_monitor_thread_handle = std::thread::spawn(move || {
+        let mut suspend_monitor = SuspendMonitor::<TimeApiImpl>::new();
+        loop {
+            // Storing suspend duration log in 1 hour interval has a good enough resolution to
+            // adjust 2 (for zram recompression) ~ 25 (for zram writeback) hours idle duration at
+            // SuspendHistory.
+            std::thread::sleep(Duration::from_secs(3600));
+
+            let max_idle_duration = std::cmp::max(
+                SecondsProp::ZramWritebackMaxIdle
+                    .get(mmd::zram::writeback::Params::default().max_idle),
+                SecondsProp::ZramRecompressionMaxIdle
+                    .get(mmd::zram::recompression::Params::default().max_idle),
+            );
+            let (suspend_duration, now_boot) = suspend_monitor.generate_suspend_duration();
+            let mut ctx = ctx.lock().expect("mmd aborts on panics");
+            ctx.suspend_history.record_suspend_duration(
+                suspend_duration,
+                now_boot,
+                max_idle_duration,
+            );
+        }
+    });
+
+    // mmd sends reports of zram stats if zram is activated on the device regardless of who (mmd or
+    // others) manages zram.
+    if is_zram_swap_activated::<SetupApiImpl>().unwrap_or(false) {
+        set_pull_atom_callback(
+            statslog_rust_header::Atoms::ZramMmStatMmd,
+            None,
+            report_zram_mm_stat,
+        );
+        set_pull_atom_callback(
+            statslog_rust_header::Atoms::ZramBdStatMmd,
+            None,
+            report_zram_bd_stat,
+        );
+    }
+
     info!("mmd started");
 
     binder::ProcessState::join_thread_pool();
+
+    suspend_monitor_thread_handle.join().expect("thread join");
+}
+
+/// Whether zram idle aging is supported.
+///
+/// Idle aging requires either CONFIG_ZRAM_MEMORY_TRACKING or CONFIG_ZRAM_TRACK_ENTRY_ACTIME
+/// kernel config enabled to work. If it's not supported by the kernel, -EINVAL will be
+/// returned from writing a number to the idle file after the zram device is initialized.
+fn is_idle_aging_supported() -> std::io::Result<bool> {
+    if let Err(e) = SysfsZramApiImpl::set_idle(&u32::MAX.to_string()) {
+        if e.kind() == std::io::ErrorKind::InvalidInput {
+            Ok(false)
+        } else {
+            Err(e)
+        }
+    } else {
+        Ok(true)
+    }
 }
 
 /// Loads the zram writeback disk size.
 ///
 /// If zram writeback is not enabled, this returns `Ok(None)`.
 pub fn load_zram_writeback_disk_size() -> std::io::Result<Option<u64>> {
-    if is_zram_writeback_activated::<SysfsZramApiImpl>()? {
-        Ok(Some(std::fs::metadata(ZRAM_WRITEBACK_FILE_PATH)?.len()))
+    if get_zram_writeback_status::<SysfsZramApiImpl>()? == ZramWritebackStatus::Activated {
+        Ok(mmdproperties::mmdproperties::actual_zram_backing_device_size().unwrap_or(None))
     } else {
         Ok(None)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    // GiB in bytes.
+    const GIB: u64 = 1 << 30;
+    const DEFAULT_BLOCK_SIZE: u64 = 4096;
+
+    #[test]
+    fn adjust_writeback_device_size_enough_disk_space() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ GIB,
+            /* min_free_space */ GIB,
+            /* free_space */ 3 * GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, GIB);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_enough_disk_space_but_size_too_small() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ 127 * MIB,
+            /* min_free_space */ GIB,
+            /* free_space */ 3 * GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, 0);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_enough_disk_space_meeting_min_size_requirement() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ 128 * MIB,
+            /* min_free_space */ GIB,
+            /* free_space */ 3 * GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, 128 * MIB);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_disk_space_too_low() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ GIB,
+            /* min_free_space */ 2 * GIB,
+            /* free_space */ GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, 0);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_needs_adjusted() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ 2 * GIB,
+            /* min_free_space */ GIB,
+            /* free_space */ 2 * GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, GIB);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_too_small_after_adjusted() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ 2 * GIB,
+            /* min_free_space */ GIB,
+            /* free_space */ GIB + MIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, 0);
+    }
+
+    #[test]
+    fn adjust_writeback_device_size_block_size_alignment() {
+        let size = adjust_writeback_device_size(
+            /* requested_device_size */ GIB + 1,
+            /* min_free_space */ GIB,
+            /* free_space */ 3 * GIB,
+            DEFAULT_BLOCK_SIZE,
+        );
+        assert_eq!(size, GIB);
+    }
+}
diff --git a/src/os.rs b/src/os.rs
index 337692f..4579d4e 100644
--- a/src/os.rs
+++ b/src/os.rs
@@ -15,6 +15,7 @@
 //! This module provides os layer utilities.
 
 use std::io;
+use std::os::fd::AsRawFd;
 
 use nix::unistd::sysconf;
 use nix::unistd::SysconfVar;
@@ -57,3 +58,24 @@ pub fn get_page_count() -> u64 {
         .expect("PHYS_PAGES should be a valid sysconf variable")
         .expect("PHYS_PAGES variable should be supported") as u64
 }
+
+/// Allocates file with the specified size.
+/// Similar function nix::fcntl::fallocate is available but it was not compiled on android.
+/// TODO: b/388993276 - Replace this with nix::fcntl::fallocate.
+pub fn fallocate<F: AsRawFd>(file: &F, size: u64) -> std::io::Result<()> {
+    let len = if size > libc::off64_t::MAX as u64 {
+        return Err(io::Error::new(
+            io::ErrorKind::InvalidInput,
+            format!("File size too large: should be less than {}", libc::off64_t::MAX),
+        ));
+    } else {
+        size as libc::off64_t
+    };
+
+    // SAFETY: fd should be valid; fallocate mode and offset are harcoded valid values; len was validated
+    let res = unsafe { libc::fallocate64(file.as_raw_fd(), 0, 0, len) };
+    if res < 0 {
+        return Err(std::io::Error::last_os_error());
+    }
+    Ok(())
+}
diff --git a/src/properties.rs b/src/properties.rs
index 9169412..e4fca48 100644
--- a/src/properties.rs
+++ b/src/properties.rs
@@ -32,12 +32,30 @@ fn generate_property_name(flag_name: &str) -> String {
     format!("mmd.{flag_name}")
 }
 
+/// Returns whether mmd manages zram or not.
+///
+/// If this is false, zram is managed by other system (e.g. swapon_all) or zram
+/// is disabled on the device.
+///
+/// Mmd checks mmd.zram.enabled without the overlay of DeviceConfig because we
+/// don't plan any experiments toggling zram enabled/disabled. Taking
+/// DeviceConfig into account rather makes the logic to switch zram management
+/// system complex.
+pub fn is_zram_enabled() -> bool {
+    match mmdproperties::mmdproperties::mmd_zram_enabled() {
+        Ok(v) => v.unwrap_or(false),
+        Err(e) => {
+            error!("failed to load mmd.zram.enabled: {e:?}");
+            false
+        }
+    }
+}
+
 /// bool system properties for mmd.
 ///
 /// clippy::enum_variant_names is allowed because we may add more properties.
 #[allow(clippy::enum_variant_names)]
 pub enum BoolProp {
-    ZramEnabled,
     ZramWritebackEnabled,
     ZramWritebackHugeIdleEnabled,
     ZramWritebackIdleEnabled,
@@ -51,7 +69,6 @@ pub enum BoolProp {
 impl BoolProp {
     fn flag_name(&self) -> &'static str {
         match self {
-            Self::ZramEnabled => "zram.enabled",
             Self::ZramWritebackEnabled => "zram.writeback.enabled",
             Self::ZramWritebackHugeIdleEnabled => "zram.writeback.huge_idle.enabled",
             Self::ZramWritebackIdleEnabled => "zram.writeback.idle.enabled",
@@ -80,7 +97,8 @@ pub enum U64Prop {
     ZramWritebackMinBytes,
     ZramWritebackMaxBytes,
     ZramWritebackMaxBytesPerDay,
-    ZramRecompressionThresholdMib,
+    ZramRecompressionThresholdBytes,
+    ZramWritebackMinFreeSpaceMib,
 }
 
 impl U64Prop {
@@ -89,7 +107,8 @@ impl U64Prop {
             Self::ZramWritebackMinBytes => "zram.writeback.min_bytes",
             Self::ZramWritebackMaxBytes => "zram.writeback.max_bytes",
             Self::ZramWritebackMaxBytesPerDay => "zram.writeback.max_bytes_per_day",
-            Self::ZramRecompressionThresholdMib => "zram.recompression.threshold_mib",
+            Self::ZramRecompressionThresholdBytes => "zram.recompression.threshold_bytes",
+            Self::ZramWritebackMinFreeSpaceMib => "zram.writeback.min_free_space_mib",
         }
     }
 
@@ -142,16 +161,22 @@ impl SecondsProp {
 #[allow(clippy::enum_variant_names)]
 pub enum StringProp {
     ZramSize,
+    ZramCompAlgorithm,
+    ZramWritebackDeviceSize,
+    ZramRecompressionAlgorithm,
 }
 
 impl StringProp {
     fn flag_name(&self) -> &'static str {
         match self {
             Self::ZramSize => "zram.size",
+            Self::ZramCompAlgorithm => "zram.comp_algorithm",
+            Self::ZramWritebackDeviceSize => "zram.writeback.device_size",
+            Self::ZramRecompressionAlgorithm => "zram.recompression.algorithm",
         }
     }
 
-    pub fn get(&self, default: &str) -> String {
+    pub fn get<T: ToString + ?Sized>(&self, default: &T) -> String {
         read(self.flag_name()).unwrap_or_else(|| default.to_string())
     }
 }
@@ -212,4 +237,12 @@ mod tests {
             Duration::from_secs(12345)
         );
     }
+
+    #[test]
+    fn string_prop_from_default() {
+        // We can't test system properties directly. Just a unit test for
+        // default value.
+        assert_eq!(StringProp::ZramSize.get("1%"), "1%");
+        assert_eq!(StringProp::ZramSize.get(&1024), "1024");
+    }
 }
diff --git a/src/service.rs b/src/service.rs
index c7d67fc..0e29c3b 100644
--- a/src/service.rs
+++ b/src/service.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use std::ops::DerefMut;
+use std::sync::Arc;
 use std::sync::Mutex;
 use std::time::Instant;
 
@@ -19,75 +21,150 @@ use anyhow::Context;
 use binder::Interface;
 use binder::Result as BinderResult;
 use log::error;
-use mmd_aidl_interface::aidl::android::os::IMmd::IMmd;
-
+use log::info;
 use mmd::os::MeminfoApiImpl;
+use mmd::suspend_history::SuspendHistory;
+use mmd::time::TimeApi;
+use mmd::time::TimeApiImpl;
 use mmd::zram::recompression::Error as ZramRecompressionError;
 use mmd::zram::recompression::ZramRecompression;
 use mmd::zram::writeback::Error as ZramWritebackError;
 use mmd::zram::writeback::ZramWriteback;
 use mmd::zram::SysfsZramApiImpl;
+use mmd_aidl_interface::aidl::android::os::IMmd::IMmd;
+use statslog_rust::zram_maintenance_executed::ZramMaintenanceExecuted;
 
+use crate::atom::create_default_maintenance_atom;
+use crate::atom::update_recompress_metrics;
+use crate::atom::update_writeback_metrics;
 use crate::properties::BoolProp;
 use crate::properties::SecondsProp;
 use crate::properties::U64Prop;
-
-struct ZramContext {
-    zram_writeback: Option<ZramWriteback>,
-    zram_recompression: Option<ZramRecompression>,
-}
+use crate::ZramContext;
+use crate::DEFAULT_ZRAM_RECOMPRESSION_ENABLED;
+use crate::DEFAULT_ZRAM_WRITEBACK_ENABLED;
 
 pub struct MmdService {
-    ctx: Mutex<ZramContext>,
+    ctx: Arc<Mutex<ZramContext>>,
 }
 
 impl MmdService {
-    pub fn new(
-        zram_writeback: Option<ZramWriteback>,
-        zram_recompression: Option<ZramRecompression>,
-    ) -> Self {
-        Self { ctx: Mutex::new(ZramContext { zram_writeback, zram_recompression }) }
+    pub fn new(ctx: Arc<Mutex<ZramContext>>) -> Self {
+        Self { ctx }
     }
 }
 
 impl Interface for MmdService {}
 
 impl IMmd for MmdService {
-    fn doZramMaintenance(&self) -> BinderResult<()> {
+    fn doZramMaintenanceAsync(&self) -> BinderResult<()> {
+        let mut atom = create_default_maintenance_atom();
         let mut ctx = self.ctx.lock().expect("mmd aborts on panics");
 
-        // Execute recompression before writeback.
-        if let Some(zram_recompression) = ctx.zram_recompression.as_mut() {
-            let params = load_zram_recompression_params();
-            match zram_recompression
-                .mark_and_recompress::<SysfsZramApiImpl, MeminfoApiImpl>(&params, Instant::now())
-            {
-                Ok(_) | Err(ZramRecompressionError::BackoffTime) => {}
-                Err(e) => error!("failed to zram recompress: {e:?}"),
+        let now = Instant::now();
+        atom.interval_from_previous_seconds =
+            now.duration_since(ctx.last_maintenance_at).as_secs().try_into().unwrap_or(i64::MAX);
+        ctx.last_maintenance_at = now;
+
+        let ZramContext { zram_writeback, zram_recompression, suspend_history, .. } =
+            ctx.deref_mut();
+
+        // Execute writeback before recompression. Current kernel decompresses
+        // pages in zram before writing it back to disk.
+        if BoolProp::ZramWritebackEnabled.get(DEFAULT_ZRAM_WRITEBACK_ENABLED) {
+            if let Some(zram_writeback) = zram_writeback.as_mut() {
+                handle_zram_writeback(zram_writeback, suspend_history, &mut atom);
             }
         }
 
-        if let Some(zram_writeback) = ctx.zram_writeback.as_mut() {
-            let params = load_zram_writeback_params();
-            let stats = match load_zram_writeback_stats() {
-                Ok(v) => v,
-                Err(e) => {
-                    error!("failed to load zram writeback stats: {e:?}");
-                    return Ok(());
-                }
-            };
-            match zram_writeback.mark_and_flush_pages::<SysfsZramApiImpl, MeminfoApiImpl>(
-                &params,
-                &stats,
-                Instant::now(),
-            ) {
-                Ok(_) | Err(ZramWritebackError::BackoffTime) | Err(ZramWritebackError::Limit) => {}
-                Err(e) => error!("failed to zram writeback: {e:?}"),
+        if BoolProp::ZramRecompressionEnabled.get(DEFAULT_ZRAM_RECOMPRESSION_ENABLED) {
+            if let Some(zram_recompression) = zram_recompression.as_mut() {
+                handle_zram_recompression(zram_recompression, suspend_history, &mut atom);
             }
         }
 
+        if let Err(e) = atom.stats_write() {
+            error!("failed to submit ZramMaintenanceExecuted atom: {e:?}");
+        }
+
         Ok(())
     }
+
+    fn isZramMaintenanceSupported(&self) -> BinderResult<bool> {
+        let ctx = self.ctx.lock().expect("mmd aborts on panics");
+        Ok(ctx.zram_writeback.is_some() || ctx.zram_recompression.is_some())
+    }
+}
+
+fn handle_zram_recompression(
+    zram_recompression: &mut ZramRecompression,
+    suspend_history: &SuspendHistory,
+    atom: &mut ZramMaintenanceExecuted,
+) {
+    let params = load_zram_recompression_params();
+
+    let start = Instant::now();
+    let result = zram_recompression.mark_and_recompress::<SysfsZramApiImpl, MeminfoApiImpl>(
+        &params,
+        suspend_history,
+        TimeApiImpl::get_boot_time(),
+    );
+    atom.recompress_latency_millis = start.elapsed().as_millis().try_into().unwrap_or(i64::MAX);
+
+    update_recompress_metrics(atom, &result);
+
+    match result {
+        Ok(_) | Err(ZramRecompressionError::BackoffTime) => {}
+        Err(e) => error!("failed to zram recompress: {e:?}"),
+    }
+}
+
+fn handle_zram_writeback(
+    zram_writeback: &mut ZramWriteback,
+    suspend_history: &SuspendHistory,
+    atom: &mut ZramMaintenanceExecuted,
+) {
+    let params = load_zram_writeback_params();
+    let stats = match load_zram_writeback_stats() {
+        Ok(v) => v,
+        Err(e) => {
+            error!("failed to load zram writeback stats: {e:?}");
+            atom.writeback_result =
+                statslog_rust::zram_maintenance_executed::WritebackResult::WritebackLoadStatsFail;
+            return;
+        }
+    };
+
+    let start = Instant::now();
+    let result = zram_writeback.mark_and_flush_pages::<SysfsZramApiImpl, MeminfoApiImpl>(
+        &params,
+        &stats,
+        suspend_history,
+        TimeApiImpl::get_boot_time(),
+    );
+    atom.writeback_latency_millis = start.elapsed().as_millis().try_into().unwrap_or(i64::MAX);
+
+    update_writeback_metrics(atom, &result);
+
+    match result {
+        Ok(details) => {
+            let total_written_pages = details
+                .huge_idle
+                .written_pages
+                .saturating_add(details.idle.written_pages)
+                .saturating_add(details.huge.written_pages);
+            if total_written_pages > 0 {
+                info!(
+                    "zram writeback: huge_idle: {} pages, idle: {} pages, huge: {} pages",
+                    details.huge_idle.written_pages,
+                    details.idle.written_pages,
+                    details.huge.written_pages
+                );
+            }
+        }
+        Err(ZramWritebackError::BackoffTime) | Err(ZramWritebackError::Limit) => {}
+        Err(e) => error!("failed to zram writeback: {e:?}"),
+    }
 }
 
 fn load_zram_writeback_params() -> mmd::zram::writeback::Params {
@@ -123,6 +200,51 @@ fn load_zram_recompression_params() -> mmd::zram::recompression::Params {
     params.huge_idle = BoolProp::ZramRecompressionHugeIdleEnabled.get(params.huge_idle);
     params.idle = BoolProp::ZramRecompressionIdleEnabled.get(params.idle);
     params.huge = BoolProp::ZramRecompressionHugeEnabled.get(params.huge);
-    params.max_mib = U64Prop::ZramRecompressionThresholdMib.get(params.max_mib);
+    params.threshold_bytes = U64Prop::ZramRecompressionThresholdBytes.get(params.threshold_bytes);
     params
 }
+
+#[cfg(test)]
+mod tests {
+    use mmd::suspend_history::SuspendHistory;
+    use mmd::zram::recompression::ZramRecompression;
+    use mmd::zram::writeback::ZramWriteback;
+
+    use super::*;
+
+    #[test]
+    fn test_is_zram_maintenance_supported() {
+        assert!(!MmdService::new(Arc::new(Mutex::new(ZramContext {
+            zram_writeback: None,
+            zram_recompression: None,
+            suspend_history: SuspendHistory::new(),
+            last_maintenance_at: Instant::now(),
+        })))
+        .isZramMaintenanceSupported()
+        .unwrap());
+        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+            zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
+            zram_recompression: None,
+            suspend_history: SuspendHistory::new(),
+            last_maintenance_at: Instant::now(),
+        })))
+        .isZramMaintenanceSupported()
+        .unwrap());
+        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+            zram_writeback: None,
+            zram_recompression: Some(ZramRecompression::new()),
+            suspend_history: SuspendHistory::new(),
+            last_maintenance_at: Instant::now(),
+        })))
+        .isZramMaintenanceSupported()
+        .unwrap());
+        assert!(MmdService::new(Arc::new(Mutex::new(ZramContext {
+            zram_writeback: Some(ZramWriteback::new(1024 * 1024, 1024 * 1024)),
+            zram_recompression: Some(ZramRecompression::new()),
+            suspend_history: SuspendHistory::new(),
+            last_maintenance_at: Instant::now(),
+        })))
+        .isZramMaintenanceSupported()
+        .unwrap());
+    }
+}
diff --git a/src/size_spec.rs b/src/size_spec.rs
new file mode 100644
index 0000000..1738434
--- /dev/null
+++ b/src/size_spec.rs
@@ -0,0 +1,119 @@
+// Copyright 2024, The Android Open Source Project
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
+//! This module implement size spec parsing for mmd.
+
+/// Error from [parse_size_spec].
+#[derive(Debug, thiserror::Error)]
+pub enum ParsingError {
+    /// Size spec was not specified
+    #[error("Size spec is empty")]
+    EmptySpec,
+    /// Specified percentage is out of range
+    #[error("Percentage out of range: {0} (expected to be less than {1})")]
+    PercentageOutOfRange(u64, u64),
+    /// Parsing int error
+    #[error("Size spec is not a valid integer: {0}")]
+    ParsingInt(#[from] std::num::ParseIntError),
+}
+
+/// Parse zram size that can be specified by a percentage or an absolute value.
+pub fn parse_size_spec(
+    spec: &str,
+    block_size: u64,
+    block_count: u64,
+    max_percentage_allowed: u64,
+) -> Result<u64, ParsingError> {
+    if spec.is_empty() {
+        return Err(ParsingError::EmptySpec);
+    }
+
+    if let Some(percentage_str) = spec.strip_suffix('%') {
+        let percentage = percentage_str.parse::<u64>()?;
+
+        if percentage > max_percentage_allowed {
+            return Err(ParsingError::PercentageOutOfRange(percentage, max_percentage_allowed));
+        }
+        return Ok(block_count * percentage / 100 * block_size);
+    }
+
+    let size = spec.parse::<u64>()?;
+    Ok(size)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    const DEFAULT_BLOCK_SIZE: u64 = 4096;
+    const DEFAULT_BLOCK_COUNT: u64 = 998875;
+    const MAX_PERCENTAGE_ALLOWED: u64 = 500;
+
+    #[test]
+    fn parse_size_spec_invalid() {
+        assert!(parse_size_spec(
+            "",
+            DEFAULT_BLOCK_SIZE,
+            DEFAULT_BLOCK_COUNT,
+            MAX_PERCENTAGE_ALLOWED
+        )
+        .is_err());
+        assert!(parse_size_spec(
+            "not_int%",
+            DEFAULT_BLOCK_SIZE,
+            DEFAULT_BLOCK_COUNT,
+            MAX_PERCENTAGE_ALLOWED
+        )
+        .is_err());
+        assert!(parse_size_spec(
+            "not_int",
+            DEFAULT_BLOCK_SIZE,
+            DEFAULT_BLOCK_COUNT,
+            MAX_PERCENTAGE_ALLOWED
+        )
+        .is_err());
+    }
+
+    #[test]
+    fn parse_size_spec_percentage_out_of_range() {
+        assert!(parse_size_spec("201%", DEFAULT_BLOCK_SIZE, DEFAULT_BLOCK_COUNT, 200).is_err());
+    }
+
+    #[test]
+    fn parse_size_spec_percentage() {
+        assert_eq!(parse_size_spec("0%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 0);
+        assert_eq!(parse_size_spec("33%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 4096);
+        assert_eq!(parse_size_spec("50%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 8192);
+        assert_eq!(parse_size_spec("90%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 16384);
+        assert_eq!(parse_size_spec("100%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 20480);
+        assert_eq!(parse_size_spec("200%", 4096, 5, MAX_PERCENTAGE_ALLOWED).unwrap(), 40960);
+        assert_eq!(
+            parse_size_spec("100%", 4096, 3995500, MAX_PERCENTAGE_ALLOWED).unwrap(),
+            16365568000
+        );
+    }
+
+    #[test]
+    fn parse_size_spec_bytes() {
+        assert_eq!(
+            parse_size_spec(
+                "1234567",
+                DEFAULT_BLOCK_SIZE,
+                DEFAULT_BLOCK_COUNT,
+                MAX_PERCENTAGE_ALLOWED
+            )
+            .unwrap(),
+            1234567
+        );
+    }
+}
diff --git a/src/suspend_history.rs b/src/suspend_history.rs
new file mode 100644
index 0000000..460af80
--- /dev/null
+++ b/src/suspend_history.rs
@@ -0,0 +1,218 @@
+// Copyright 2024, The Android Open Source Project
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
+//! `/sys/block/zram0/idle` marks idle pages based on boottime clock timestamp which keeps ticking
+//! even while the device is suspended. This can end up marking relatively new pages as idle. For
+//! example, when the threshold for idle page is 25 hours and the user suspends the device whole the
+//! weekend (i.e. 2days), all pages in zram are marked as idle which is too aggressive.
+//!
+//! [SuspendHistory] mitigates the issue by adjusting the idle threshold by the actual duration of
+//! the device is suspended because fixing the kernel to use monotonic clock instead of boottime
+//! clock can break existing user space behavior.
+//!
+//! In this module, we don't use [std::time::Instant] because the Rust standard
+//! library used in Android uses [libc::CLOCK_BOOTTIME] while the official Rust
+//! standard library implementation uses [libc::CLOCK_MONOTONIC].
+
+#[cfg(test)]
+mod tests;
+
+use std::collections::VecDeque;
+use std::marker::PhantomData;
+use std::time::Duration;
+
+use crate::time::BootTime;
+use crate::time::MonotonicTime;
+use crate::time::TimeApi;
+
+/// Estimates the suspend duration by comparing the elapsed times on monotonic clock and boot time
+/// clock.
+///
+/// In Linux kernel, boot time is calculated as <monotonic time> + <boot time offset>. However the
+/// kernel does not provides API to expose the boot time offset (The internal API is
+/// `ktime_get_offs_boot_ns()`).
+pub struct SuspendMonitor<T: TimeApi> {
+    monitonic_time: MonotonicTime,
+    boot_time: BootTime,
+    negative_adjustment: Duration,
+    _phantom_data: PhantomData<T>,
+}
+
+impl<T: TimeApi> SuspendMonitor<T> {
+    /// Creates [SuspendMonitor].
+    pub fn new() -> Self {
+        Self {
+            monitonic_time: T::get_monotonic_time(),
+            boot_time: T::get_boot_time(),
+            negative_adjustment: Duration::ZERO,
+            _phantom_data: PhantomData,
+        }
+    }
+
+    /// Estimate suspend duration by comparing the elapsed time between monotonic clock and boottime
+    /// clock.
+    ///
+    /// This returns the estimated suspend duration and the boot time timestamp of now.
+    pub fn generate_suspend_duration(&mut self) -> (Duration, BootTime) {
+        let monotonic_time = T::get_monotonic_time();
+        let boot_time = T::get_boot_time();
+
+        let monotonic_diff = monotonic_time.saturating_duration_since(self.monitonic_time);
+        let boot_diff = boot_time.saturating_duration_since(self.boot_time);
+
+        let suspend_duration = if boot_diff < monotonic_diff {
+            // Since kernel does not provide API to get both boot time and
+            // monotonic time atomically, the elapsed time on monotonic time
+            // can be longer than boot time. Store the diff in
+            // negative_adjustment and adjust it at the next call.
+            self.negative_adjustment =
+                self.negative_adjustment.saturating_add(monotonic_diff - boot_diff);
+            Duration::ZERO
+        } else {
+            let suspend_duration = boot_diff - monotonic_diff;
+            if suspend_duration >= self.negative_adjustment {
+                let negative_adjustment = self.negative_adjustment;
+                self.negative_adjustment = Duration::ZERO;
+                suspend_duration - negative_adjustment
+            } else {
+                self.negative_adjustment =
+                    self.negative_adjustment.saturating_sub(suspend_duration);
+                Duration::ZERO
+            }
+        };
+
+        self.monitonic_time = monotonic_time;
+        self.boot_time = boot_time;
+
+        (suspend_duration, boot_time)
+    }
+}
+
+impl<T: TimeApi> Default for SuspendMonitor<T> {
+    fn default() -> Self {
+        Self::new()
+    }
+}
+
+struct Entry {
+    suspend_duration: Duration,
+    time: BootTime,
+}
+
+/// [SuspendHistory] tracks the duration of suspends.
+///
+/// The adjustment duration is calculated by [SuspendHistory::calculate_total_suspend_duration].
+/// For example, if the idle threshold is 4 hours just after these usage log:
+///
+/// * User suspends 1 hours (A) and use the device for 2 hours and,
+/// * User suspends 5 hours (B) and use the device for 1 hours and,
+/// * User suspends 2 hours (C) and use the device for 1 hours and,
+/// * User suspends 1 hours (D) and use the device for 1 hours
+///
+/// In this case, the threshold need to be adjusted by 8 hours (B + C + D).
+///
+/// ```
+///                                                      now
+/// log       : |-A-|     |----B----|   |--C--|   |-D-|   |
+/// threshold :                            |---original---|
+/// adjustment:        |----B----|--C--|-D-|
+/// ```
+///
+/// SuspendHistory uses deque to store the suspend logs. Each entry is 32 bytes. mmd will add a
+/// record every hour and evict obsolete records. At worst case, Even if a user uses the device only
+/// 10 seconds per hour and device is in suspend for 59 min 50 seconds, the history consumes only
+/// 281KiB (= 32 bytes * 25 hours / (10 seconds / 3600 seconds)). Traversing < 300KiB on each zram
+/// maintenance is an acceptable cost.
+pub struct SuspendHistory {
+    history: VecDeque<Entry>,
+    total_awake_duration: Duration,
+}
+
+impl SuspendHistory {
+    /// Creates [SuspendHistory].
+    pub fn new() -> Self {
+        let mut history = VecDeque::new();
+        history.push_front(Entry { suspend_duration: Duration::ZERO, time: BootTime::ZERO });
+        Self { history, total_awake_duration: Duration::ZERO }
+    }
+
+    /// Add a record of suspended duration.
+    ///
+    /// This also evicts records which will exceeds `max_idle_duration`.
+    pub fn record_suspend_duration(
+        &mut self,
+        suspend_duration: Duration,
+        time: BootTime,
+        max_idle_duration: Duration,
+    ) {
+        // self.history never be empty while expired entries are popped out in the following loop
+        // because the loop pop one entry at a time only when self.history has at least 2 entries.
+        assert!(!self.history.is_empty());
+        let awake_duration = time
+            .saturating_duration_since(self.history.front().expect("history is not empty").time)
+            .saturating_sub(suspend_duration);
+        self.total_awake_duration = self.total_awake_duration.saturating_add(awake_duration);
+
+        while self.total_awake_duration > max_idle_duration && self.history.len() >= 2 {
+            // The oldest entry must not None because the history had at least 2 entries.
+            let oldest_wake_at = self.history.pop_back().expect("history is not empty").time;
+
+            // oldest_entry must not None because the history had at least 2 entries.
+            let oldest_entry = self.history.back().expect("history had at least 2 entries");
+            let oldest_awake_duration = oldest_entry
+                .time
+                .saturating_duration_since(oldest_wake_at)
+                .saturating_sub(oldest_entry.suspend_duration);
+            self.total_awake_duration =
+                self.total_awake_duration.saturating_sub(oldest_awake_duration);
+        }
+
+        self.history.push_front(Entry { suspend_duration, time });
+    }
+
+    /// Calculates total suspend duration which overlaps the target_idle_duration.
+    ///
+    /// See the comment of [SuspendHistory] for details.
+    pub fn calculate_total_suspend_duration(
+        &self,
+        target_idle_duration: Duration,
+        now: BootTime,
+    ) -> Duration {
+        let Some(target_time) = now.checked_sub(target_idle_duration) else {
+            return Duration::ZERO;
+        };
+
+        let mut total_suspend_duration = Duration::ZERO;
+
+        for entry in self.history.iter() {
+            let Some(adjusted_target_time) = target_time.checked_sub(total_suspend_duration) else {
+                break;
+            };
+            if entry.time > adjusted_target_time {
+                total_suspend_duration =
+                    total_suspend_duration.saturating_add(entry.suspend_duration);
+            } else {
+                break;
+            }
+        }
+
+        total_suspend_duration
+    }
+}
+
+impl Default for SuspendHistory {
+    fn default() -> Self {
+        Self::new()
+    }
+}
diff --git a/src/suspend_history/tests.rs b/src/suspend_history/tests.rs
new file mode 100644
index 0000000..375dad4
--- /dev/null
+++ b/src/suspend_history/tests.rs
@@ -0,0 +1,261 @@
+// Copyright 2024, The Android Open Source Project
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
+use super::*;
+use crate::time::MockTimeApi;
+use crate::time::TIME_API_MTX;
+
+const BASE_RAW_MONOTONIC_TIME: Duration = Duration::from_secs(12345);
+const BASE_RAW_BOOT_TIME: Duration = Duration::from_secs(67890);
+const HOUR_IN_SECONDS: u64 = 3600;
+const DEFAULT_MAX_IDLE_DURATION: Duration = Duration::from_secs(25 * HOUR_IN_SECONDS);
+
+#[test]
+fn test_suspend_monitor() {
+    let _m = TIME_API_MTX.lock();
+    let mock_monitonic = MockTimeApi::get_monotonic_time_context();
+    let mock_boot = MockTimeApi::get_boot_time_context();
+    mock_monitonic
+        .expect()
+        .times(1)
+        .return_const(MonotonicTime::from_duration(BASE_RAW_MONOTONIC_TIME));
+    mock_boot.expect().times(1).return_const(BootTime::from_duration(BASE_RAW_BOOT_TIME));
+    let mut suspend_monitor = SuspendMonitor::<MockTimeApi>::new();
+
+    // + 100s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(100),
+    ));
+    // + 300s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(300));
+    mock_boot.expect().times(1).return_const(boot_now);
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::from_secs(200), boot_now));
+
+    // + 900s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(1000),
+    ));
+    // + 1000s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(1300));
+    mock_boot.expect().times(1).return_const(boot_now);
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::from_secs(100), boot_now));
+}
+
+#[test]
+fn test_suspend_monitor_negative_adjustment() {
+    let _m = TIME_API_MTX.lock();
+    let mock_monitonic = MockTimeApi::get_monotonic_time_context();
+    let mock_boot = MockTimeApi::get_boot_time_context();
+    mock_monitonic
+        .expect()
+        .times(1)
+        .return_const(MonotonicTime::from_duration(BASE_RAW_MONOTONIC_TIME));
+    mock_boot.expect().times(1).return_const(BootTime::from_duration(BASE_RAW_BOOT_TIME));
+    let mut suspend_monitor = SuspendMonitor::<MockTimeApi>::new();
+
+    // + 400s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(400),
+    ));
+    // + 100s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(100));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // 300s of negative adjustment is stored.
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::ZERO, boot_now));
+
+    // + 100s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(500),
+    ));
+    // + 1000s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(1100));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // suspend duration is 900s - 300s (negative adjustment from the last call)
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::from_secs(600), boot_now));
+
+    // + 100s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(600),
+    ));
+    // + 400s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(1500));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // suspend duration is 300s without negative adjustment
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::from_secs(300), boot_now));
+}
+
+#[test]
+fn test_suspend_monitor_big_negative_adjustment() {
+    let _m = TIME_API_MTX.lock();
+    let mock_monitonic = MockTimeApi::get_monotonic_time_context();
+    let mock_boot = MockTimeApi::get_boot_time_context();
+    mock_monitonic
+        .expect()
+        .times(1)
+        .return_const(MonotonicTime::from_duration(BASE_RAW_MONOTONIC_TIME));
+    mock_boot.expect().times(1).return_const(BootTime::from_duration(BASE_RAW_BOOT_TIME));
+    let mut suspend_monitor = SuspendMonitor::<MockTimeApi>::new();
+
+    // + 400s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(400),
+    ));
+    // + 100s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(100));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // 300s of negative adjustment is stored.
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::ZERO, boot_now));
+
+    // + 100s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(500),
+    ));
+    // + 300s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(400));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // suspend duration is 200s is shorter than negative adjustment. 100s of negative adjustment is
+    // left.
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::ZERO, boot_now));
+
+    // + 100s on monotonic clock
+    mock_monitonic.expect().times(1).return_const(MonotonicTime::from_duration(
+        BASE_RAW_MONOTONIC_TIME + Duration::from_secs(600),
+    ));
+    // + 400s on boottime clock
+    let boot_now = BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(800));
+    mock_boot.expect().times(1).return_const(boot_now);
+    // suspend duration is 300s - 100s (negative adjustment).
+    assert_eq!(suspend_monitor.generate_suspend_duration(), (Duration::from_secs(200), boot_now));
+}
+
+#[test]
+fn test_calculate_total_suspend_duration() {
+    let mut history = SuspendHistory::new();
+
+    history.record_suspend_duration(
+        Duration::from_secs(2 * HOUR_IN_SECONDS),
+        BootTime::from_duration(BASE_RAW_BOOT_TIME),
+        DEFAULT_MAX_IDLE_DURATION,
+    );
+    history.record_suspend_duration(
+        Duration::from_secs(5 * HOUR_IN_SECONDS),
+        BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(7 * HOUR_IN_SECONDS)),
+        DEFAULT_MAX_IDLE_DURATION,
+    );
+    history.record_suspend_duration(
+        Duration::from_secs(2 * HOUR_IN_SECONDS),
+        BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(10 * HOUR_IN_SECONDS)),
+        DEFAULT_MAX_IDLE_DURATION,
+    );
+    history.record_suspend_duration(
+        Duration::from_secs(HOUR_IN_SECONDS),
+        BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(12 * HOUR_IN_SECONDS)),
+        DEFAULT_MAX_IDLE_DURATION,
+    );
+
+    assert_eq!(
+        history.calculate_total_suspend_duration(
+            Duration::from_secs(4 * HOUR_IN_SECONDS),
+            BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(13 * HOUR_IN_SECONDS))
+        ),
+        Duration::from_secs(8 * HOUR_IN_SECONDS)
+    );
+}
+
+#[test]
+fn test_calculate_total_suspend_duration_empty() {
+    let history = SuspendHistory::new();
+
+    assert_eq!(
+        history.calculate_total_suspend_duration(
+            Duration::from_secs(4 * HOUR_IN_SECONDS),
+            BootTime::from_duration(BASE_RAW_BOOT_TIME + Duration::from_secs(13 * HOUR_IN_SECONDS))
+        ),
+        Duration::ZERO
+    );
+}
+
+#[test]
+fn test_calculate_total_suspend_duration_negative_target() {
+    let history = SuspendHistory::new();
+
+    // now - target_duration is negative.
+    assert_eq!(
+        history.calculate_total_suspend_duration(
+            Duration::from_secs(4 * HOUR_IN_SECONDS),
+            BootTime::from_duration(Duration::from_secs(HOUR_IN_SECONDS))
+        ),
+        Duration::ZERO
+    );
+}
+
+#[test]
+fn test_suspend_history_gc_entries() {
+    let max_idle_duration = Duration::from_secs(25 * HOUR_IN_SECONDS);
+    let base_raw_boot_time: Duration = Duration::ZERO;
+    let mut history = SuspendHistory::new();
+
+    assert_eq!(history.history.len(), 1);
+
+    // awake for 26 hours.
+    history.record_suspend_duration(
+        Duration::from_secs(HOUR_IN_SECONDS),
+        BootTime::from_duration(base_raw_boot_time + Duration::from_secs(27 * HOUR_IN_SECONDS)),
+        max_idle_duration,
+    );
+    // Does not pop entry if there was only 1 entry.
+    assert_eq!(history.history.len(), 2);
+
+    // awake for 1 hour.
+    history.record_suspend_duration(
+        Duration::from_secs(HOUR_IN_SECONDS),
+        BootTime::from_duration(base_raw_boot_time + Duration::from_secs(29 * HOUR_IN_SECONDS)),
+        max_idle_duration,
+    );
+    // The first entry is GC-ed.
+    assert_eq!(history.history.len(), 2);
+
+    // awake for 2 hour.
+    history.record_suspend_duration(
+        Duration::from_secs(HOUR_IN_SECONDS),
+        BootTime::from_duration(base_raw_boot_time + Duration::from_secs(32 * HOUR_IN_SECONDS)),
+        max_idle_duration,
+    );
+    assert_eq!(history.history.len(), 3);
+
+    // awake for 10 hour.
+    history.record_suspend_duration(
+        Duration::from_secs(11 * HOUR_IN_SECONDS),
+        BootTime::from_duration(base_raw_boot_time + Duration::from_secs(53 * HOUR_IN_SECONDS)),
+        max_idle_duration,
+    );
+    assert_eq!(history.history.len(), 4);
+
+    // awake for 20 hours.
+    history.record_suspend_duration(
+        Duration::from_secs(12 * HOUR_IN_SECONDS),
+        BootTime::from_duration(base_raw_boot_time + Duration::from_secs(85 * HOUR_IN_SECONDS)),
+        max_idle_duration,
+    );
+    // The entries except last 2 entries are GC-ed.
+    assert_eq!(history.history.len(), 2);
+
+    assert_eq!(
+        history.calculate_total_suspend_duration(
+            Duration::from_secs(25 * HOUR_IN_SECONDS),
+            BootTime::from_duration(base_raw_boot_time + Duration::from_secs(85 * HOUR_IN_SECONDS))
+        ),
+        Duration::from_secs(23 * HOUR_IN_SECONDS)
+    );
+}
diff --git a/src/time.rs b/src/time.rs
new file mode 100644
index 0000000..c0f6874
--- /dev/null
+++ b/src/time.rs
@@ -0,0 +1,121 @@
+// Copyright 2024, The Android Open Source Project
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
+//! The time library of libmmd.
+//!
+//! libmmd cares about the type of clock is boot time or monotonic time to calculate suspend
+//! duration of the system at `crate::suspend_history` module.
+//!
+//! In Android [std::time::Instant] is based on boot time clock unlike the official rust standard
+//! library is based on monotonic clock. libmmd defines its own [BootTime] and [MonotonicTime]
+//! explicitly and refrain from depending on [std::time::Instant].
+//!
+//! https://android.googlesource.com/toolchain/android_rust/+/refs/heads/main/patches/longterm/rustc-0018-Switch-Instant-to-use-CLOCK_BOOTTIME.patch
+
+use std::time::Duration;
+
+use nix::time::clock_gettime;
+
+/// [TimeApi] is the mockable interface of clock_gettime(3).
+#[cfg_attr(test, mockall::automock)]
+pub trait TimeApi {
+    /// Get the current monotonic time.
+    fn get_monotonic_time() -> MonotonicTime;
+    /// Get the current boot time.
+    fn get_boot_time() -> BootTime;
+}
+
+/// The implementation of [TimeApi].
+pub struct TimeApiImpl;
+
+impl TimeApi for TimeApiImpl {
+    fn get_monotonic_time() -> MonotonicTime {
+        clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
+            .map(|t| MonotonicTime(t.into()))
+            .expect("clock_gettime(CLOCK_MONOTONIC) never fails")
+    }
+
+    fn get_boot_time() -> BootTime {
+        clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
+            .map(|t| BootTime(t.into()))
+            .expect("clock_gettime(CLOCK_BOOTTIME) never fails")
+    }
+}
+
+/// Mutex to synchronize tests using [MockTimeApi].
+///
+/// mockall for static functions requires synchronization.
+///
+/// https://docs.rs/mockall/latest/mockall/#static-methods
+#[cfg(test)]
+pub static TIME_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
+
+/// The representation of monotonic time.
+#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
+pub struct MonotonicTime(Duration);
+
+impl MonotonicTime {
+    /// This returns the durtion elapsed from `earlier` time.
+    ///
+    /// This returns zero duration if `earlier` is later than this.
+    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
+        self.0.saturating_sub(earlier.0)
+    }
+
+    /// Creates [MonotonicTime] from [Duration].
+    ///
+    /// This will be mainly used for testing purpose. Otherwise, [TimeApiImpl::get_monotonic_time]
+    /// is recommended.
+    pub const fn from_duration(value: Duration) -> Self {
+        Self(value)
+    }
+}
+
+/// The representation of boot time.
+#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
+pub struct BootTime(Duration);
+
+impl BootTime {
+    /// The zero boot time.
+    pub const ZERO: BootTime = BootTime(Duration::ZERO);
+
+    /// This returns the durtion elapsed from `earlier` time.
+    ///
+    /// This returns zero duration if `earlier` is later than this.
+    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
+        self.0.saturating_sub(earlier.0)
+    }
+
+    /// Returns the `BootTime` added by the duration.
+    ///
+    /// Returns `None` if overflow occurs.
+    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
+        self.0.checked_add(duration).map(Self)
+    }
+
+    /// Returns the `BootTime` subtracted by the duration.
+    ///
+    /// Returns `None` if the duration is bigger than the boot time.
+    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
+        self.0.checked_sub(duration).map(Self)
+    }
+
+    /// Creates [BootTime] from [Duration].
+    ///
+    /// This will be mainly used for testing purpose. Otherwise, [TimeApiImpl::get_boot_time] is
+    /// recommended.
+    pub const fn from_duration(value: Duration) -> Self {
+        Self(value)
+    }
+}
diff --git a/src/zram.rs b/src/zram.rs
index 7aeb4a2..384255d 100644
--- a/src/zram.rs
+++ b/src/zram.rs
@@ -25,6 +25,7 @@ use std::io;
 // Files for zram general information
 const ZRAM_DISKSIZE_PATH: &str = "/sys/block/zram0/disksize";
 const ZRAM_MM_STAT_PATH: &str = "/sys/block/zram0/mm_stat";
+const ZRAM_COMP_ALGORITHM_PATH: &str = "/sys/block/zram0/comp_algorithm";
 
 // Files for memory tracking
 const ZRAM_IDLE_PATH: &str = "/sys/block/zram0/idle";
@@ -32,6 +33,7 @@ const ZRAM_IDLE_PATH: &str = "/sys/block/zram0/idle";
 // Files for writeback
 const ZRAM_BACKING_DEV_PATH: &str = "/sys/block/zram0/backing_dev";
 const ZRAM_WRITEBACK_PATH: &str = "/sys/block/zram0/writeback";
+const ZRAM_WRITEBACK_LIMIT_ENABLE_PATH: &str = "/sys/block/zram0/writeback_limit_enable";
 const ZRAM_WRITEBACK_LIMIT_PATH: &str = "/sys/block/zram0/writeback_limit";
 const ZRAM_BD_STAT_PATH: &str = "/sys/block/zram0/bd_stat";
 
@@ -48,7 +50,7 @@ const ZRAM_RECOMPRESS_PATH: &str = "/sys/block/zram0/recompress";
 /// * fn write_<file_name>(contents: &str) -> io::Result<()>
 ///
 /// We don't have naming conventions for files which is writable only.
-#[cfg_attr(test, mockall::automock)]
+#[cfg_attr(any(test, feature = "test_utils"), mockall::automock)]
 pub trait SysfsZramApi {
     /// Read "/sys/block/zram0/disksize".
     fn read_disksize() -> io::Result<String>;
@@ -57,13 +59,20 @@ pub trait SysfsZramApi {
     /// Read "/sys/block/zram0/mm_stat".
     fn read_mm_stat() -> io::Result<String>;
 
+    /// Set compression algorithm.
+    fn write_comp_algorithm(contents: &str) -> io::Result<()>;
+
     /// Write contents to "/sys/block/zram0/idle".
     fn set_idle(contents: &str) -> io::Result<()>;
 
     /// Read "/sys/block/zram0/backing_dev".
     fn read_backing_dev() -> io::Result<String>;
+    /// Write "/sys/block/zram0/backing_dev".
+    fn write_backing_dev(contents: &str) -> io::Result<()>;
     /// Write contents to "/sys/block/zram0/writeback".
     fn writeback(contents: &str) -> io::Result<()>;
+    /// Write contents to "/sys/block/zram0/writeback_limit_enable".
+    fn write_writeback_limit_enable(contents: &str) -> io::Result<()>;
     /// Write contents to "/sys/block/zram0/writeback_limit".
     fn write_writeback_limit(contents: &str) -> io::Result<()>;
     /// Read "/sys/block/zram0/writeback_limit".
@@ -73,6 +82,8 @@ pub trait SysfsZramApi {
 
     /// Read "/sys/block/zram0/recomp_algorithm".
     fn read_recomp_algorithm() -> io::Result<String>;
+    /// Write "/sys/block/zram0/recomp_algorithm".
+    fn write_recomp_algorithm(contents: &str) -> io::Result<()>;
     /// Write contents to "/sys/block/zram0/recompress".
     fn recompress(contents: &str) -> io::Result<()>;
 }
@@ -101,6 +112,10 @@ impl SysfsZramApi for SysfsZramApiImpl {
         std::fs::read_to_string(ZRAM_BACKING_DEV_PATH)
     }
 
+    fn write_backing_dev(contents: &str) -> io::Result<()> {
+        std::fs::write(ZRAM_BACKING_DEV_PATH, contents)
+    }
+
     fn writeback(contents: &str) -> io::Result<()> {
         std::fs::write(ZRAM_WRITEBACK_PATH, contents)
     }
@@ -109,6 +124,10 @@ impl SysfsZramApi for SysfsZramApiImpl {
         std::fs::write(ZRAM_WRITEBACK_LIMIT_PATH, contents)
     }
 
+    fn write_writeback_limit_enable(contents: &str) -> io::Result<()> {
+        std::fs::write(ZRAM_WRITEBACK_LIMIT_ENABLE_PATH, contents)
+    }
+
     fn read_writeback_limit() -> io::Result<String> {
         std::fs::read_to_string(ZRAM_WRITEBACK_LIMIT_PATH)
     }
@@ -121,9 +140,17 @@ impl SysfsZramApi for SysfsZramApiImpl {
         std::fs::read_to_string(ZRAM_RECOMP_ALGORITHM_PATH)
     }
 
+    fn write_recomp_algorithm(contents: &str) -> io::Result<()> {
+        std::fs::write(ZRAM_RECOMP_ALGORITHM_PATH, contents)
+    }
+
     fn recompress(contents: &str) -> io::Result<()> {
         std::fs::write(ZRAM_RECOMPRESS_PATH, contents)
     }
+
+    fn write_comp_algorithm(contents: &str) -> io::Result<()> {
+        std::fs::write(ZRAM_COMP_ALGORITHM_PATH, contents)
+    }
 }
 
 /// Mutex to synchronize tests using [MockSysfsZramApi].
@@ -131,5 +158,4 @@ impl SysfsZramApi for SysfsZramApiImpl {
 /// mockall for static functions requires synchronization.
 ///
 /// https://docs.rs/mockall/latest/mockall/#static-methods
-#[cfg(test)]
 pub static ZRAM_API_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());
diff --git a/src/zram/idle.rs b/src/zram/idle.rs
index c2173c4..70ff953 100644
--- a/src/zram/idle.rs
+++ b/src/zram/idle.rs
@@ -109,10 +109,9 @@ pub fn calculate_idle_time<M: MeminfoApi>(
 
 #[cfg(test)]
 mod tests {
-    use super::*;
-
     use mockall::predicate::*;
 
+    use super::*;
     use crate::os::MockMeminfoApi;
     use crate::os::MEMINFO_API_MTX;
     use crate::zram::MockSysfsZramApi;
diff --git a/src/zram/recompression.rs b/src/zram/recompression.rs
index fa1bb18..3f3124a 100644
--- a/src/zram/recompression.rs
+++ b/src/zram/recompression.rs
@@ -22,9 +22,10 @@
 mod tests;
 
 use std::time::Duration;
-use std::time::Instant;
 
 use crate::os::MeminfoApi;
+use crate::suspend_history::SuspendHistory;
+use crate::time::BootTime;
 use crate::zram::idle::calculate_idle_time;
 use crate::zram::idle::set_zram_idle_time;
 use crate::zram::SysfsZramApi;
@@ -48,11 +49,31 @@ pub enum Error {
 
 type Result<T> = std::result::Result<T, Error>;
 
-/// Check whether zram recompression is activated by checking "/sys/block/zram0/recomp_algorithm".
-pub fn is_zram_recompression_activated<Z: SysfsZramApi>() -> std::io::Result<bool> {
+/// Current zram recompression setup status
+#[derive(Debug, PartialEq)]
+pub enum ZramRecompressionStatus {
+    /// Zram writeback is not supported by the kernel.
+    Unsupported,
+    /// Zram recompression is supported but not configured yet.
+    NotConfigured,
+    /// Zram recompression was already activated.
+    Activated,
+}
+
+/// Check zram recompression setup status by reading `/sys/block/zram0/recomp_algorithm`.
+pub fn get_zram_recompression_status<Z: SysfsZramApi>() -> std::io::Result<ZramRecompressionStatus>
+{
     match Z::read_recomp_algorithm() {
-        Ok(recomp_algorithm) => Ok(!recomp_algorithm.is_empty()),
-        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
+        Ok(recomp_algorithm) => {
+            if recomp_algorithm.is_empty() {
+                Ok(ZramRecompressionStatus::NotConfigured)
+            } else {
+                Ok(ZramRecompressionStatus::Activated)
+            }
+        }
+        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
+            Ok(ZramRecompressionStatus::Unsupported)
+        }
         Err(e) => Err(e),
     }
 }
@@ -71,8 +92,8 @@ pub struct Params {
     pub idle: bool,
     /// Whether recompress huge pages or not.
     pub huge: bool,
-    /// Maximum size in MiB to recompress.
-    pub max_mib: u64,
+    /// The minimum size in bytes of zram pages to be considered for recompression.
+    pub threshold_bytes: u64,
 }
 
 impl Default for Params {
@@ -87,8 +108,8 @@ impl Default for Params {
             huge_idle: true,
             idle: true,
             huge: true,
-            // 1 GiB
-            max_mib: 1024,
+            // 1 KiB
+            threshold_bytes: 1024,
         }
     }
 }
@@ -101,7 +122,7 @@ enum Mode {
 
 /// [ZramRecompression] manages zram recompression policies.
 pub struct ZramRecompression {
-    last_recompress_at: Option<Instant>,
+    last_recompress_at: Option<BootTime>,
 }
 
 impl ZramRecompression {
@@ -114,22 +135,23 @@ impl ZramRecompression {
     pub fn mark_and_recompress<Z: SysfsZramApi, M: MeminfoApi>(
         &mut self,
         params: &Params,
-        now: Instant,
+        suspend_history: &SuspendHistory,
+        now: BootTime,
     ) -> Result<()> {
         if let Some(last_at) = self.last_recompress_at {
-            if now - last_at < params.backoff_duration {
+            if now.saturating_duration_since(last_at) < params.backoff_duration {
                 return Err(Error::BackoffTime);
             }
         }
 
         if params.huge_idle {
-            self.initiate_recompress::<Z, M>(params, Mode::HugeIdle, now)?;
+            self.initiate_recompress::<Z, M>(params, Mode::HugeIdle, suspend_history, now)?;
         }
         if params.idle {
-            self.initiate_recompress::<Z, M>(params, Mode::Idle, now)?;
+            self.initiate_recompress::<Z, M>(params, Mode::Idle, suspend_history, now)?;
         }
         if params.huge {
-            self.initiate_recompress::<Z, M>(params, Mode::Huge, now)?;
+            self.initiate_recompress::<Z, M>(params, Mode::Huge, suspend_history, now)?;
         }
 
         Ok(())
@@ -139,12 +161,16 @@ impl ZramRecompression {
         &mut self,
         params: &Params,
         mode: Mode,
-        now: Instant,
+        suspend_history: &SuspendHistory,
+        now: BootTime,
     ) -> Result<()> {
         match mode {
             Mode::HugeIdle | Mode::Idle => {
                 let idle_age = calculate_idle_time::<M>(params.min_idle, params.max_idle)?;
-                // TODO: adjust the idle_age by suspend duration.
+                // Adjust idle age by suspend duration.
+                let idle_age = idle_age.saturating_add(
+                    suspend_history.calculate_total_suspend_duration(idle_age, now),
+                );
                 set_zram_idle_time::<Z>(idle_age).map_err(Error::MarkIdle)?;
             }
             Mode::Huge => {}
@@ -156,8 +182,8 @@ impl ZramRecompression {
             Mode::Huge => "huge",
         };
 
-        let trigger = if params.max_mib > 0 {
-            format!("type={} threshold={}", mode, params.max_mib)
+        let trigger = if params.threshold_bytes > 0 {
+            format!("type={} threshold={}", mode, params.threshold_bytes)
         } else {
             format!("type={mode}")
         };
diff --git a/src/zram/recompression/tests.rs b/src/zram/recompression/tests.rs
index 342fc38..88e38a1 100644
--- a/src/zram/recompression/tests.rs
+++ b/src/zram/recompression/tests.rs
@@ -12,16 +12,17 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::*;
-
 use std::sync::LockResult;
 use std::sync::MutexGuard;
 
 use mockall::predicate::*;
 use mockall::Sequence;
 
+use super::*;
 use crate::os::MockMeminfoApi;
 use crate::os::MEMINFO_API_MTX;
+use crate::time::TimeApi;
+use crate::time::TimeApiImpl;
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
@@ -36,7 +37,7 @@ struct MockContext<'a> {
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
 }
 
-impl<'a> MockContext<'a> {
+impl MockContext<'_> {
     fn new() -> Self {
         let _zram_lock = ZRAM_API_MTX.lock();
         let _meminfo_lock = MEMINFO_API_MTX.lock();
@@ -58,37 +59,43 @@ impl<'a> MockContext<'a> {
 }
 
 #[test]
-fn test_is_zram_recompression_activated() {
+fn get_zram_recompression_status_not_configured() {
     let mock = MockContext::new();
-    mock.read_recomp_algorithm.expect().returning(|| Ok("#1: lzo lzo-rle lz4 [zstd]".to_string()));
-
-    assert!(is_zram_recompression_activated::<MockSysfsZramApi>().unwrap());
+    mock.read_recomp_algorithm.expect().returning(|| Ok("".to_string()));
+    assert_eq!(
+        get_zram_recompression_status::<MockSysfsZramApi>().unwrap(),
+        ZramRecompressionStatus::NotConfigured
+    );
 }
 
 #[test]
-fn test_is_zram_recompression_activated_not_activated() {
+fn get_zram_recompression_status_activated() {
     let mock = MockContext::new();
-    mock.read_recomp_algorithm.expect().returning(|| Ok("".to_string()));
-
-    assert!(!is_zram_recompression_activated::<MockSysfsZramApi>().unwrap());
+    mock.read_recomp_algorithm.expect().returning(|| Ok("zstd".to_string()));
+    assert_eq!(
+        get_zram_recompression_status::<MockSysfsZramApi>().unwrap(),
+        ZramRecompressionStatus::Activated
+    );
 }
 
 #[test]
-fn test_is_zram_recompression_activated_not_supported() {
+fn get_zram_recompression_status_unsupported() {
     let mock = MockContext::new();
     mock.read_recomp_algorithm
         .expect()
-        .returning(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found")));
-
-    assert!(!is_zram_recompression_activated::<MockSysfsZramApi>().unwrap());
+        .returning(|| Err(std::io::Error::from_raw_os_error(libc::ENOENT)));
+    assert_eq!(
+        get_zram_recompression_status::<MockSysfsZramApi>().unwrap(),
+        ZramRecompressionStatus::Unsupported
+    );
 }
 
 #[test]
-fn test_is_zram_recompression_activated_failure() {
+fn test_get_zram_recompression_status_failure() {
     let mock = MockContext::new();
     mock.read_recomp_algorithm.expect().returning(|| Err(std::io::Error::other("error")));
 
-    assert!(is_zram_recompression_activated::<MockSysfsZramApi>().is_err());
+    assert!(get_zram_recompression_status::<MockSysfsZramApi>().is_err());
 }
 
 #[test]
@@ -96,7 +103,8 @@ fn mark_and_recompress() {
     let mock = MockContext::new();
     let mut seq = Sequence::new();
     mock.setup_default_meminfo();
-    let params = Params { max_mib: 0, ..Default::default() };
+    let params = Params { threshold_bytes: 0, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().times(1).in_sequence(&mut seq).returning(|_| Ok(()));
@@ -121,7 +129,11 @@ fn mark_and_recompress() {
         .returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -130,7 +142,8 @@ fn mark_and_recompress_with_threshold() {
     let mock = MockContext::new();
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { max_mib: 12345, ..Default::default() };
+    let params = Params { threshold_bytes: 12345, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress
@@ -142,7 +155,11 @@ fn mark_and_recompress_with_threshold() {
     mock.recompress.expect().with(eq("type=huge threshold=12345")).times(1).returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time(),
+        )
         .is_ok());
 }
 
@@ -152,12 +169,20 @@ fn mark_and_recompress_before_backoff() {
     mock.recompress.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params =
-        Params { backoff_duration: Duration::from_secs(100), max_mib: 0, ..Default::default() };
-    let base_time = Instant::now();
+    let params = Params {
+        backoff_duration: Duration::from_secs(100),
+        threshold_bytes: 0,
+        ..Default::default()
+    };
+    let suspend_history = SuspendHistory::new();
+    let base_time = TimeApiImpl::get_boot_time();
     let mut zram_recompression = ZramRecompression::new();
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, base_time)
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            base_time,
+        )
         .is_ok());
     mock.recompress.checkpoint();
 
@@ -166,7 +191,8 @@ fn mark_and_recompress_before_backoff() {
     assert!(matches!(
         zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
-            base_time + Duration::from_secs(99)
+            &suspend_history,
+            base_time.checked_add(Duration::from_secs(99)).unwrap(),
         ),
         Err(Error::BackoffTime)
     ));
@@ -178,12 +204,20 @@ fn mark_and_recompress_after_backoff() {
     mock.recompress.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params =
-        Params { backoff_duration: Duration::from_secs(100), max_mib: 0, ..Default::default() };
-    let base_time = Instant::now();
+    let params = Params {
+        backoff_duration: Duration::from_secs(100),
+        threshold_bytes: 0,
+        ..Default::default()
+    };
+    let suspend_history = SuspendHistory::new();
+    let base_time = TimeApiImpl::get_boot_time();
     let mut zram_recompression = ZramRecompression::new();
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, base_time)
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            base_time,
+        )
         .is_ok());
     mock.recompress.checkpoint();
     mock.set_idle.expect().returning(|_| Ok(()));
@@ -194,7 +228,8 @@ fn mark_and_recompress_after_backoff() {
     assert!(zram_recompression
         .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
-            base_time + Duration::from_secs(100)
+            &suspend_history,
+            base_time.checked_add(Duration::from_secs(100)).unwrap()
         )
         .is_ok());
 }
@@ -209,15 +244,49 @@ fn mark_and_recompress_idle_time() {
     let params = Params {
         min_idle: Duration::from_secs(3600),
         max_idle: Duration::from_secs(4000),
-        max_mib: 0,
+        threshold_bytes: 0,
         ..Default::default()
     };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().with(eq("3747")).times(2).returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
+        .is_ok());
+}
+
+#[test]
+fn mark_and_recompress_idle_time_adjusted_by_suspend_duration() {
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
+    let mut suspend_history = SuspendHistory::new();
+    let boot_now = BootTime::from_duration(Duration::from_secs(12345));
+    suspend_history.record_suspend_duration(Duration::from_secs(1000), boot_now, params.max_idle);
+    let mut zram_recompression = ZramRecompression::new();
+
+    mock.set_idle.expect().with(eq("4747")).times(2).returning(|_| Ok(()));
+
+    assert!(zram_recompression
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            boot_now
+        )
         .is_ok());
 }
 
@@ -228,14 +297,18 @@ fn mark_and_recompress_calculate_idle_failure() {
     let params = Params {
         min_idle: Duration::from_secs(4000),
         max_idle: Duration::from_secs(3600),
-        max_mib: 0,
+        threshold_bytes: 0,
         ..Default::default()
     };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     assert!(matches!(
-        zram_recompression
-            .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now()),
+        zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        ),
         Err(Error::CalculateIdle(_))
     ));
 }
@@ -244,14 +317,18 @@ fn mark_and_recompress_calculate_idle_failure() {
 fn mark_and_recompress_mark_idle_failure() {
     let mock = MockContext::new();
     mock.setup_default_meminfo();
-    let params = Params { max_mib: 0, ..Default::default() };
+    let params = Params { threshold_bytes: 0, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.set_idle.expect().returning(|_| Err(std::io::Error::other("error")));
 
     assert!(matches!(
-        zram_recompression
-            .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now()),
+        zram_recompression.mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        ),
         Err(Error::MarkIdle(_))
     ));
 }
@@ -261,7 +338,8 @@ fn mark_and_recompress_skip_huge_idle() {
     let mock = MockContext::new();
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { huge_idle: false, max_mib: 0, ..Default::default() };
+    let params = Params { huge_idle: false, threshold_bytes: 0, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(0).returning(|_| Ok(()));
@@ -269,7 +347,11 @@ fn mark_and_recompress_skip_huge_idle() {
     mock.recompress.expect().with(eq("type=huge")).times(1).returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -278,7 +360,8 @@ fn mark_and_recompress_skip_idle() {
     let mock = MockContext::new();
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { idle: false, max_mib: 0, ..Default::default() };
+    let params = Params { idle: false, threshold_bytes: 0, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(1).returning(|_| Ok(()));
@@ -286,7 +369,11 @@ fn mark_and_recompress_skip_idle() {
     mock.recompress.expect().with(eq("type=huge")).times(1).returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -295,7 +382,8 @@ fn mark_and_recompress_skip_huge() {
     let mock = MockContext::new();
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
-    let params = Params { huge: false, max_mib: 0, ..Default::default() };
+    let params = Params { huge: false, threshold_bytes: 0, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_recompression = ZramRecompression::new();
 
     mock.recompress.expect().with(eq("type=huge_idle")).times(1).returning(|_| Ok(()));
@@ -303,6 +391,10 @@ fn mark_and_recompress_skip_huge() {
     mock.recompress.expect().with(eq("type=huge")).times(0).returning(|_| Ok(()));
 
     assert!(zram_recompression
-        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(&params, Instant::now())
+        .mark_and_recompress::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
diff --git a/src/zram/setup.rs b/src/zram/setup.rs
index 6e78039..7611c2c 100644
--- a/src/zram/setup.rs
+++ b/src/zram/setup.rs
@@ -21,18 +21,22 @@
 #[cfg(test)]
 mod tests;
 
+use std::fs::File;
+use std::fs::Permissions;
 use std::io;
+use std::os::unix::fs::PermissionsExt;
+use std::path::Path;
 
-use crate::os::get_page_count;
-use crate::os::get_page_size;
+use dm::loopdevice;
+use dm::loopdevice::LoopDevice;
+
+use crate::os::fallocate;
 use crate::zram::SysfsZramApi;
 
 const MKSWAP_BIN_PATH: &str = "/system/bin/mkswap";
 const ZRAM_DEVICE_PATH: &str = "/dev/block/zram0";
 const PROC_SWAPS_PATH: &str = "/proc/swaps";
 
-const MAX_ZRAM_PERCENTAGE_ALLOWED: u64 = 500;
-
 /// [SetupApi] is the mockable interface for swap operations.
 #[cfg_attr(test, mockall::automock)]
 pub trait SetupApi {
@@ -42,6 +46,11 @@ pub trait SetupApi {
     fn swapon(device_path: &std::ffi::CStr) -> io::Result<()>;
     /// Read swaps areas in use.
     fn read_swap_areas() -> io::Result<String>;
+    /// Set up a new loop device for a backing file with size.
+    fn attach_loop_device(
+        file_path: &Path,
+        device_size: u64,
+    ) -> anyhow::Result<loopdevice::LoopDevice>;
 }
 
 /// The implementation of [SetupApi].
@@ -65,6 +74,18 @@ impl SetupApi for SetupApiImpl {
     fn read_swap_areas() -> io::Result<String> {
         std::fs::read_to_string(PROC_SWAPS_PATH)
     }
+
+    fn attach_loop_device(
+        file_path: &Path,
+        device_size: u64,
+    ) -> anyhow::Result<loopdevice::LoopDevice> {
+        loopdevice::attach(
+            file_path,
+            0,
+            device_size,
+            &loopdevice::LoopConfigOptions { direct_io: true, writable: true, autoclear: true },
+        )
+    }
 }
 
 /// Whether or not zram is already set up on the device.
@@ -81,49 +102,6 @@ pub fn is_zram_swap_activated<S: SetupApi>() -> io::Result<bool> {
     Ok(false)
 }
 
-/// Error from [parse_zram_size_spec].
-#[derive(Debug, thiserror::Error)]
-pub enum ZramSpecError {
-    /// Zram size was not specified
-    #[error("zram size is not specified")]
-    EmptyZramSizeSpec,
-    /// Zram size percentage needs to be between 1 and 500%
-    #[error(
-        "zram size percentage {0} is out of range (expected the between 1 and {})",
-        MAX_ZRAM_PERCENTAGE_ALLOWED
-    )]
-    ZramPercentageOutOfRange(u64),
-    /// Parsing zram size error
-    #[error("zram size is not an int: {0}")]
-    ParseZramSize(#[from] std::num::ParseIntError),
-}
-
-/// Parse zram size that can be specified by a percentage or an absolute value.
-pub fn parse_zram_size_spec(spec: &str) -> Result<u64, ZramSpecError> {
-    parse_size_spec_with_page_info(spec, get_page_size(), get_page_count())
-}
-
-fn parse_size_spec_with_page_info(
-    spec: &str,
-    system_page_size: u64,
-    system_page_count: u64,
-) -> Result<u64, ZramSpecError> {
-    if spec.is_empty() {
-        return Err(ZramSpecError::EmptyZramSizeSpec);
-    }
-
-    if let Some(percentage_str) = spec.strip_suffix('%') {
-        let percentage = percentage_str.parse::<u64>()?;
-        if percentage == 0 || percentage > MAX_ZRAM_PERCENTAGE_ALLOWED {
-            return Err(ZramSpecError::ZramPercentageOutOfRange(percentage));
-        }
-        return Ok(system_page_count * percentage / 100 * system_page_size);
-    }
-
-    let zram_size = spec.parse::<u64>()?;
-    Ok(zram_size)
-}
-
 /// Error from [activate].
 #[derive(Debug, thiserror::Error)]
 pub enum ZramActivationError {
@@ -158,3 +136,40 @@ pub fn activate_zram<Z: SysfsZramApi, S: SetupApi>(
 
     Ok(())
 }
+
+/// Error from [create_zram_writeback_device].
+#[derive(Debug, thiserror::Error)]
+pub enum WritebackDeviceSetupError {
+    /// Failed to create backing file
+    #[error("failed to create backing file: {0}")]
+    CreateBackingFile(std::io::Error),
+    /// Failed to create the backing device
+    #[error("failed to create backing device: {0}")]
+    CreateBackingDevice(anyhow::Error),
+}
+
+/// Create a zram backing device with provided file path and size.
+pub fn create_zram_writeback_device<S: SetupApi>(
+    file_path: &Path,
+    device_size: u64,
+) -> std::result::Result<LoopDevice, WritebackDeviceSetupError> {
+    let swap_file =
+        File::create(file_path).map_err(WritebackDeviceSetupError::CreateBackingFile)?;
+    scopeguard::defer! {
+        let _ = std::fs::remove_file(file_path);
+    }
+    std::fs::set_permissions(file_path, Permissions::from_mode(0o600))
+        .map_err(WritebackDeviceSetupError::CreateBackingFile)?;
+
+    fallocate(&swap_file, device_size).map_err(WritebackDeviceSetupError::CreateBackingFile)?;
+
+    let loop_device = S::attach_loop_device(file_path, device_size)
+        .map_err(WritebackDeviceSetupError::CreateBackingDevice)?;
+
+    Ok(loop_device)
+}
+
+/// Enables zram writeback limit.
+pub fn enable_zram_writeback_limit<Z: SysfsZramApi>() -> std::io::Result<()> {
+    Z::write_writeback_limit_enable("1")
+}
diff --git a/src/zram/setup/tests.rs b/src/zram/setup/tests.rs
index 2f9c28f..fc93d83 100644
--- a/src/zram/setup/tests.rs
+++ b/src/zram/setup/tests.rs
@@ -12,21 +12,22 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::*;
-use mockall::predicate::*;
-use mockall::Sequence;
 use std::os::unix::process::ExitStatusExt;
+use std::path::PathBuf;
 use std::sync::LockResult;
 use std::sync::Mutex;
 use std::sync::MutexGuard;
 
+use mockall::predicate::*;
+use mockall::Sequence;
+
+use super::*;
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
 const PROC_SWAP_HEADER: &str = "Filename                                Type            Size            Used            Priority\n";
-const DEFAULT_PAGE_SIZE: u64 = 4096;
-const DEFAULT_PAGE_COUNT: u64 = 998875;
 const DEFAULT_ZRAM_SIZE: u64 = 1000000;
+const DEFAULT_WRITEBACK_DEVICE_SIZE: u64 = 1 << 20;
 
 fn success_command_output() -> std::process::Output {
     std::process::Output {
@@ -53,23 +54,29 @@ pub static SETUP_API_MTX: Mutex<()> = Mutex::new(());
 
 struct MockContext<'a> {
     write_disksize: crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__write_disksize::Context,
+    write_backing_dev:
+        crate::zram::__mock_MockSysfsZramApi_SysfsZramApi::__write_backing_dev::Context,
     read_swap_areas: crate::zram::setup::__mock_MockSetupApi_SetupApi::__read_swap_areas::Context,
     mkswap: crate::zram::setup::__mock_MockSetupApi_SetupApi::__mkswap::Context,
     swapon: crate::zram::setup::__mock_MockSetupApi_SetupApi::__swapon::Context,
+    attach_loop_device:
+        crate::zram::setup::__mock_MockSetupApi_SetupApi::__attach_loop_device::Context,
     // Lock will be released after mock contexts are dropped.
     _setup_lock: LockResult<MutexGuard<'a, ()>>,
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
 }
 
-impl<'a> MockContext<'a> {
+impl MockContext<'_> {
     fn new() -> Self {
         let _zram_lock = ZRAM_API_MTX.lock();
         let _setup_lock = SETUP_API_MTX.lock();
         Self {
             write_disksize: MockSysfsZramApi::write_disksize_context(),
+            write_backing_dev: MockSysfsZramApi::write_backing_dev_context(),
             read_swap_areas: MockSetupApi::read_swap_areas_context(),
             mkswap: MockSetupApi::mkswap_context(),
             swapon: MockSetupApi::swapon_context(),
+            attach_loop_device: MockSetupApi::attach_loop_device_context(),
             _setup_lock,
             _zram_lock,
         }
@@ -93,40 +100,6 @@ fn is_zram_swap_activated_zram_on() {
     assert!(is_zram_swap_activated::<MockSetupApi>().unwrap());
 }
 
-#[test]
-fn parse_zram_spec_invalid() {
-    assert!(parse_size_spec_with_page_info("", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).is_err());
-    assert!(
-        parse_size_spec_with_page_info("not_int%", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).is_err()
-    );
-    assert!(
-        parse_size_spec_with_page_info("not_int", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).is_err()
-    );
-}
-
-#[test]
-fn parse_zram_spec_percentage_out_of_range() {
-    assert!(parse_size_spec_with_page_info("0%", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).is_err());
-    assert!(parse_size_spec_with_page_info("501%", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).is_err());
-}
-
-#[test]
-fn parse_zram_spec_percentage() {
-    assert_eq!(parse_size_spec_with_page_info("33%", 4096, 5).unwrap(), 4096);
-    assert_eq!(parse_size_spec_with_page_info("50%", 4096, 5).unwrap(), 8192);
-    assert_eq!(parse_size_spec_with_page_info("100%", 4096, 5).unwrap(), 20480);
-    assert_eq!(parse_size_spec_with_page_info("200%", 4096, 5).unwrap(), 40960);
-    assert_eq!(parse_size_spec_with_page_info("100%", 4096, 3995500).unwrap(), 16365568000);
-}
-
-#[test]
-fn parse_zram_spec_bytes() {
-    assert_eq!(
-        parse_size_spec_with_page_info("1234567", DEFAULT_PAGE_SIZE, DEFAULT_PAGE_COUNT).unwrap(),
-        1234567
-    );
-}
-
 #[test]
 fn activate_success() {
     let mock = MockContext::new();
@@ -189,3 +162,78 @@ fn activate_failed_swapon() {
         Err(ZramActivationError::SwapOn(_))
     ));
 }
+
+#[test]
+fn set_up_zram_backing_device_success() {
+    let mock = MockContext::new();
+    let backing_file_dir = tempfile::tempdir().unwrap();
+    let backing_file_path = backing_file_dir.path().join("zram_swap");
+    let loop_file_path = "/dev/block/loop97";
+    let writeback_device_size = 2 << 20;
+
+    mock.attach_loop_device
+        .expect()
+        .withf(move |path, size| {
+            std::fs::metadata(path).unwrap().len() == writeback_device_size
+                && *size == writeback_device_size
+        })
+        .returning(move |_, _| {
+            Ok(loopdevice::LoopDevice {
+                file: tempfile::tempfile().unwrap(),
+                path: PathBuf::from(loop_file_path),
+            })
+        });
+    assert!(create_zram_writeback_device::<MockSetupApi>(
+        &backing_file_path,
+        writeback_device_size
+    )
+    .is_ok());
+    assert!(!std::fs::exists(&backing_file_path).unwrap());
+}
+
+#[test]
+fn set_up_zram_backing_device_failed_to_create_backing_file() {
+    let mock = MockContext::new();
+    let backing_file_path = Path::new("/dev/null");
+
+    mock.attach_loop_device.expect().times(0);
+    mock.write_backing_dev.expect().times(0);
+
+    assert!(matches!(
+        create_zram_writeback_device::<MockSetupApi>(
+            backing_file_path,
+            DEFAULT_WRITEBACK_DEVICE_SIZE
+        ),
+        Err(WritebackDeviceSetupError::CreateBackingFile(_))
+    ));
+}
+
+#[test]
+fn set_up_zram_backing_device_failed_to_create_backing_device() {
+    let mock = MockContext::new();
+    let backing_file = tempfile::NamedTempFile::new().unwrap();
+
+    mock.attach_loop_device
+        .expect()
+        .returning(|_, _| Err(anyhow::anyhow!("failed to create loop device")));
+    mock.write_backing_dev.expect().times(0);
+
+    assert!(matches!(
+        create_zram_writeback_device::<MockSetupApi>(
+            backing_file.path(),
+            DEFAULT_WRITEBACK_DEVICE_SIZE
+        ),
+        Err(WritebackDeviceSetupError::CreateBackingDevice(_))
+    ));
+    assert!(!std::fs::exists(backing_file).unwrap());
+}
+
+#[test]
+fn enable_zram_writeback_limit_success() {
+    let _m = ZRAM_API_MTX.lock();
+    let mock = MockSysfsZramApi::write_writeback_limit_enable_context();
+
+    mock.expect().with(eq("1")).times(1).returning(|_| Ok(()));
+
+    assert!(enable_zram_writeback_limit::<MockSysfsZramApi>().is_ok());
+}
diff --git a/src/zram/stats/tests.rs b/src/zram/stats/tests.rs
index 1cf3d25..add0709 100644
--- a/src/zram/stats/tests.rs
+++ b/src/zram/stats/tests.rs
@@ -13,7 +13,6 @@
 // limitations under the License.
 
 use super::*;
-
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
diff --git a/src/zram/writeback.rs b/src/zram/writeback.rs
index 000da7a..cfdaea6 100644
--- a/src/zram/writeback.rs
+++ b/src/zram/writeback.rs
@@ -23,10 +23,11 @@ mod history;
 mod tests;
 
 use std::time::Duration;
-use std::time::Instant;
 
 use crate::os::get_page_size;
 use crate::os::MeminfoApi;
+use crate::suspend_history::SuspendHistory;
+use crate::time::BootTime;
 use crate::zram::idle::calculate_idle_time;
 use crate::zram::idle::set_zram_idle_time;
 use crate::zram::writeback::history::ZramWritebackHistory;
@@ -60,14 +61,31 @@ pub enum Error {
 
 type Result<T> = std::result::Result<T, Error>;
 
+/// Current zram writeback setup status
+#[derive(Debug, PartialEq)]
+pub enum ZramWritebackStatus {
+    /// Zram writeback is not supported by the kernel.
+    Unsupported,
+    /// Zram writeback is supported but not configured yet.
+    NotConfigured,
+    /// Zram writeback was already activated.
+    Activated,
+}
+
 /// Whether the zram writeback is activated on the device or not.
-pub fn is_zram_writeback_activated<Z: SysfsZramApi>() -> std::io::Result<bool> {
+pub fn get_zram_writeback_status<Z: SysfsZramApi>() -> std::io::Result<ZramWritebackStatus> {
     match Z::read_backing_dev() {
         // If /sys/block/zram0/backing_dev is "none", zram writeback is not configured yet.
-        Ok(backing_dev) => Ok(backing_dev != "none"),
+        Ok(backing_dev) => {
+            if backing_dev.trim() == "none" {
+                Ok(ZramWritebackStatus::NotConfigured)
+            } else {
+                Ok(ZramWritebackStatus::Activated)
+            }
+        }
         // If it can't access /sys/block/zram0/backing_dev, zram writeback feature is disabled on
         // the kernel.
-        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
+        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ZramWritebackStatus::Unsupported),
         Err(e) => Err(e),
     }
 }
@@ -125,6 +143,35 @@ pub struct Stats {
     pub current_writeback_pages: u64,
 }
 
+/// The detailed results of a zram writeback attempt.
+#[derive(Debug, Default)]
+pub struct WritebackDetails {
+    /// WritebackModeDetails for huge idle pages.
+    pub huge_idle: WritebackModeDetails,
+    /// WritebackModeDetails for idle pages.
+    pub idle: WritebackModeDetails,
+    /// WritebackModeDetails for huge pages.
+    pub huge: WritebackModeDetails,
+    /// Calculated writeback limit pages.
+    pub limit_pages: u64,
+    /// Writeback daily limit pages. This is calculated from the total written
+    /// back page per day.
+    pub daily_limit_pages: u64,
+    /// The content of /sys/block/zram0/writeback_limit just before starting
+    /// zram writeback. This is usually equals to the smaller of limit_pages and
+    /// daily_limit_pages unless kernel tweaks the updated writeback_limit
+    /// value.
+    pub actual_limit_pages: u64,
+}
+
+/// The detailed results of a zram writeback attempt per zram page type (i.e.
+/// huge_idle, idle, huge pages).
+#[derive(Debug, Default)]
+pub struct WritebackModeDetails {
+    /// Number of pages written back.
+    pub written_pages: u64,
+}
+
 enum Mode {
     HugeIdle,
     Idle,
@@ -139,7 +186,7 @@ fn load_current_writeback_limit<Z: SysfsZramApi>() -> Result<u64> {
 /// ZramWriteback manages zram writeback policies.
 pub struct ZramWriteback {
     history: ZramWritebackHistory,
-    last_writeback_at: Option<Instant>,
+    last_writeback_at: Option<BootTime>,
     total_zram_pages: u64,
     zram_writeback_pages: u64,
     page_size: u64,
@@ -175,10 +222,11 @@ impl ZramWriteback {
         &mut self,
         params: &Params,
         stats: &Stats,
-        now: Instant,
-    ) -> Result<()> {
+        suspend_history: &SuspendHistory,
+        now: BootTime,
+    ) -> Result<WritebackDetails> {
         if let Some(last_at) = self.last_writeback_at {
-            if now - last_at < params.backoff_duration {
+            if now.saturating_duration_since(last_at) < params.backoff_duration {
                 return Err(Error::BackoffTime);
             }
         }
@@ -187,25 +235,48 @@ impl ZramWriteback {
         let daily_limit_pages =
             self.history.calculate_daily_limit(params.max_bytes_per_day / self.page_size, now);
         let limit_pages = self.calculate_writeback_limit(params, stats);
+        let mut details = WritebackDetails { limit_pages, daily_limit_pages, ..Default::default() };
+
         let limit_pages = std::cmp::min(limit_pages, daily_limit_pages);
         if limit_pages == 0 {
             return Err(Error::Limit);
         }
         Z::write_writeback_limit(&limit_pages.to_string()).map_err(Error::WritebackLimit)?;
         let mut writeback_limit = load_current_writeback_limit::<Z>()?;
+        details.actual_limit_pages = writeback_limit;
 
         if params.huge_idle && writeback_limit > 0 {
-            writeback_limit =
-                self.writeback::<Z, M>(writeback_limit, params, Mode::HugeIdle, now)?;
+            writeback_limit = self.writeback::<Z, M>(
+                writeback_limit,
+                params,
+                Mode::HugeIdle,
+                suspend_history,
+                &mut details.huge_idle,
+                now,
+            )?;
         }
         if params.idle && writeback_limit > 0 {
-            writeback_limit = self.writeback::<Z, M>(writeback_limit, params, Mode::Idle, now)?;
+            writeback_limit = self.writeback::<Z, M>(
+                writeback_limit,
+                params,
+                Mode::Idle,
+                suspend_history,
+                &mut details.idle,
+                now,
+            )?;
         }
         if params.huge && writeback_limit > 0 {
-            self.writeback::<Z, M>(writeback_limit, params, Mode::Huge, now)?;
+            self.writeback::<Z, M>(
+                writeback_limit,
+                params,
+                Mode::Huge,
+                suspend_history,
+                &mut details.huge,
+                now,
+            )?;
         }
 
-        Ok(())
+        Ok(details)
     }
 
     fn calculate_writeback_limit(&self, params: &Params, stats: &Stats) -> u64 {
@@ -241,12 +312,17 @@ impl ZramWriteback {
         writeback_limit: u64,
         params: &Params,
         mode: Mode,
-        now: Instant,
+        suspend_history: &SuspendHistory,
+        details: &mut WritebackModeDetails,
+        now: BootTime,
     ) -> Result<u64> {
         match mode {
             Mode::HugeIdle | Mode::Idle => {
                 let idle_age = calculate_idle_time::<M>(params.min_idle, params.max_idle)?;
-                // TODO: adjust the idle_age by suspend duration.
+                // Adjust idle age by suspend duration.
+                let idle_age = idle_age.saturating_add(
+                    suspend_history.calculate_total_suspend_duration(idle_age, now),
+                );
                 set_zram_idle_time::<Z>(idle_age).map_err(Error::MarkIdle)?;
             }
             Mode::Huge => {}
@@ -258,18 +334,26 @@ impl ZramWriteback {
             Mode::Huge => "huge",
         };
 
-        if let Err(e) = Z::writeback(mode) {
-            // If writeback fails, we assume that all writeback_limit was consumed conservatively.
-            self.history.record(writeback_limit, now);
-            return Err(Error::Writeback(e));
-        }
-
-        self.last_writeback_at = Some(now);
+        let result = Z::writeback(mode);
 
         // If reading writeback_limit fails, we assume that all writeback_limit was consumed
         // conservatively.
         let current_writeback_limit = load_current_writeback_limit::<Z>().unwrap_or(0);
-        self.history.record(writeback_limit.saturating_sub(current_writeback_limit), now);
+        let pages_written = writeback_limit.saturating_sub(current_writeback_limit);
+        self.history.record(pages_written, now);
+        details.written_pages = pages_written;
+
+        if let Err(e) = result {
+            // When zram writeback reaches the writeback_limit, kernel stop writing back and returns
+            // EIO. EIO with zero writeback_limit is not an error.
+            let is_writeback_limit_reached =
+                e.raw_os_error() == Some(libc::EIO) && current_writeback_limit == 0;
+            if !is_writeback_limit_reached {
+                return Err(Error::Writeback(e));
+            }
+        }
+
+        self.last_writeback_at = Some(now);
 
         Ok(current_writeback_limit)
     }
diff --git a/src/zram/writeback/history.rs b/src/zram/writeback/history.rs
index e874f8f..61e33fb 100644
--- a/src/zram/writeback/history.rs
+++ b/src/zram/writeback/history.rs
@@ -14,14 +14,15 @@
 
 use std::collections::VecDeque;
 use std::time::Duration;
-use std::time::Instant;
+
+use crate::time::BootTime;
 
 // 24 hours.
 const HISTORY_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);
 
 /// Stores the log of zram writeback size to calculate daily limit.
 pub struct ZramWritebackHistory {
-    history: VecDeque<(u64, Instant)>,
+    history: VecDeque<(u64, BootTime)>,
 }
 
 impl ZramWritebackHistory {
@@ -31,19 +32,21 @@ impl ZramWritebackHistory {
     }
 
     /// Records a new log of zram writeback.
-    pub fn record(&mut self, pages: u64, now: Instant) {
+    pub fn record(&mut self, pages: u64, now: BootTime) {
         self.history.push_back((pages, now));
     }
 
     /// Evicts expired records.
-    pub fn cleanup(&mut self, now: Instant) {
-        while !self.history.is_empty() && now - self.history.front().unwrap().1 > HISTORY_EXPIRY {
+    pub fn cleanup(&mut self, now: BootTime) {
+        while !self.history.is_empty()
+            && now.saturating_duration_since(self.history.front().unwrap().1) > HISTORY_EXPIRY
+        {
             self.history.pop_front();
         }
     }
 
     /// Calculates the daily limit of zram writeback left.
-    pub fn calculate_daily_limit(&self, max_pages_per_day: u64, now: Instant) -> u64 {
+    pub fn calculate_daily_limit(&self, max_pages_per_day: u64, now: BootTime) -> u64 {
         let pages_written = self
             .history
             .iter()
@@ -60,56 +63,82 @@ impl ZramWritebackHistory {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use crate::time::TimeApi;
+    use crate::time::TimeApiImpl;
 
     #[test]
     fn test_calculate_daily_limit() {
         let mut history = ZramWritebackHistory::new();
-        let base_time = Instant::now();
+        let base_time = TimeApiImpl::get_boot_time();
 
         // records 1 day before is ignored.
         history.record(1, base_time);
         history.record(1, base_time);
-        history.record(2, base_time + Duration::from_secs(1));
-        history.record(3, base_time + HISTORY_EXPIRY);
-        assert_eq!(history.calculate_daily_limit(100, base_time + HISTORY_EXPIRY), 95);
+        history.record(2, base_time.checked_add(Duration::from_secs(1)).unwrap());
+        history.record(3, base_time.checked_add(HISTORY_EXPIRY).unwrap());
+        assert_eq!(
+            history.calculate_daily_limit(100, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            95
+        );
     }
 
     #[test]
     fn test_calculate_daily_limit_empty() {
         let history = ZramWritebackHistory::new();
-        assert_eq!(history.calculate_daily_limit(100, Instant::now()), 100);
+        assert_eq!(history.calculate_daily_limit(100, TimeApiImpl::get_boot_time()), 100);
     }
 
     #[test]
     fn test_calculate_daily_limit_exceeds_max() {
         let mut history = ZramWritebackHistory::new();
-        let base_time = Instant::now();
+        let base_time = TimeApiImpl::get_boot_time();
         // records 1 day before is ignored.
         history.record(1, base_time);
-        history.record(2, base_time + Duration::from_secs(1));
-        history.record(3, base_time + HISTORY_EXPIRY);
-
-        assert_eq!(history.calculate_daily_limit(1, base_time + HISTORY_EXPIRY), 0);
-        assert_eq!(history.calculate_daily_limit(2, base_time + HISTORY_EXPIRY), 0);
-        assert_eq!(history.calculate_daily_limit(3, base_time + HISTORY_EXPIRY), 0);
-        assert_eq!(history.calculate_daily_limit(4, base_time + HISTORY_EXPIRY), 0);
-        assert_eq!(history.calculate_daily_limit(5, base_time + HISTORY_EXPIRY), 0);
-        assert_eq!(history.calculate_daily_limit(6, base_time + HISTORY_EXPIRY), 1);
+        history.record(2, base_time.checked_add(Duration::from_secs(1)).unwrap());
+        history.record(3, base_time.checked_add(HISTORY_EXPIRY).unwrap());
+
+        assert_eq!(
+            history.calculate_daily_limit(1, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            0
+        );
+        assert_eq!(
+            history.calculate_daily_limit(2, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            0
+        );
+        assert_eq!(
+            history.calculate_daily_limit(3, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            0
+        );
+        assert_eq!(
+            history.calculate_daily_limit(4, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            0
+        );
+        assert_eq!(
+            history.calculate_daily_limit(5, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            0
+        );
+        assert_eq!(
+            history.calculate_daily_limit(6, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            1
+        );
     }
 
     #[test]
     fn test_calculate_daily_limit_after_cleanup() {
         let mut history = ZramWritebackHistory::new();
-        let base_time = Instant::now();
+        let base_time = TimeApiImpl::get_boot_time();
         // records 1 day before will be cleaned up.
         history.record(1, base_time);
         history.record(1, base_time);
-        history.record(2, base_time + Duration::from_secs(1));
-        history.record(3, base_time + HISTORY_EXPIRY);
+        history.record(2, base_time.checked_add(Duration::from_secs(1)).unwrap());
+        history.record(3, base_time.checked_add(HISTORY_EXPIRY).unwrap());
 
-        history.cleanup(base_time + HISTORY_EXPIRY);
+        history.cleanup(base_time.checked_add(HISTORY_EXPIRY).unwrap());
 
         // The same result as test_calculate_daily_limit
-        assert_eq!(history.calculate_daily_limit(100, base_time + HISTORY_EXPIRY), 95);
+        assert_eq!(
+            history.calculate_daily_limit(100, base_time.checked_add(HISTORY_EXPIRY).unwrap()),
+            95
+        );
     }
 }
diff --git a/src/zram/writeback/tests.rs b/src/zram/writeback/tests.rs
index eaea88b..1beba9d 100644
--- a/src/zram/writeback/tests.rs
+++ b/src/zram/writeback/tests.rs
@@ -12,16 +12,17 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::*;
-
 use std::sync::LockResult;
 use std::sync::MutexGuard;
 
 use mockall::predicate::*;
 use mockall::Sequence;
 
+use super::*;
 use crate::os::MockMeminfoApi;
 use crate::os::MEMINFO_API_MTX;
+use crate::time::TimeApi;
+use crate::time::TimeApiImpl;
 use crate::zram::MockSysfsZramApi;
 use crate::zram::ZRAM_API_MTX;
 
@@ -44,7 +45,7 @@ struct MockContext<'a> {
     _zram_lock: LockResult<MutexGuard<'a, ()>>,
 }
 
-impl<'a> MockContext<'a> {
+impl MockContext<'_> {
     fn new() -> Self {
         let _zram_lock = ZRAM_API_MTX.lock();
         let _meminfo_lock = MEMINFO_API_MTX.lock();
@@ -71,12 +72,19 @@ impl<'a> MockContext<'a> {
     }
 }
 
+fn default_stats(params: &Params) -> Stats {
+    Stats { orig_data_size: params.max_bytes, ..Default::default() }
+}
+
 #[test]
-fn test_is_zram_writeback_activated() {
+fn test_get_zram_writeback_status() {
     let mock = MockContext::new();
     mock.read_backing_dev.expect().returning(|| Ok("/dev/dm-1".to_string()));
 
-    assert!(is_zram_writeback_activated::<MockSysfsZramApi>().unwrap());
+    assert_eq!(
+        get_zram_writeback_status::<MockSysfsZramApi>().unwrap(),
+        ZramWritebackStatus::Activated
+    );
 }
 
 #[test]
@@ -84,25 +92,31 @@ fn test_load_zram_writeback_disk_size_writeback_is_not_enabled() {
     let mock = MockContext::new();
     mock.read_backing_dev.expect().returning(|| Ok("none".to_string()));
 
-    assert!(!is_zram_writeback_activated::<MockSysfsZramApi>().unwrap());
+    assert_eq!(
+        get_zram_writeback_status::<MockSysfsZramApi>().unwrap(),
+        ZramWritebackStatus::NotConfigured
+    );
 }
 
 #[test]
-fn test_is_zram_writeback_activated_writeback_is_not_supported() {
+fn test_get_zram_writeback_status_writeback_is_not_supported() {
     let mock = MockContext::new();
     mock.read_backing_dev
         .expect()
         .returning(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found")));
 
-    assert!(!is_zram_writeback_activated::<MockSysfsZramApi>().unwrap());
+    assert_eq!(
+        get_zram_writeback_status::<MockSysfsZramApi>().unwrap(),
+        ZramWritebackStatus::Unsupported
+    );
 }
 
 #[test]
-fn test_is_zram_writeback_activated_failure() {
+fn test_get_zram_writeback_status_failure() {
     let mock = MockContext::new();
     mock.read_backing_dev.expect().returning(|| Err(std::io::Error::other("error")));
 
-    assert!(is_zram_writeback_activated::<MockSysfsZramApi>().is_err());
+    assert!(get_zram_writeback_status::<MockSysfsZramApi>().is_err());
 }
 
 #[test]
@@ -112,7 +126,8 @@ fn mark_and_flush_pages() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params::default();
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -124,7 +139,12 @@ fn mark_and_flush_pages() {
     mock.writeback.expect().times(1).in_sequence(&mut seq).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -137,12 +157,18 @@ fn mark_and_flush_pages_before_backoff() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params { backoff_duration: Duration::from_secs(100), ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
-    let base_time = Instant::now();
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
+    let base_time = TimeApiImpl::get_boot_time();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_time)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_time
+        )
         .is_ok());
     mock.writeback.checkpoint();
 
@@ -152,7 +178,8 @@ fn mark_and_flush_pages_before_backoff() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_time + Duration::from_secs(99)
+            &suspend_history,
+            base_time.checked_add(Duration::from_secs(99)).unwrap()
         ),
         Err(Error::BackoffTime)
     ));
@@ -167,12 +194,18 @@ fn mark_and_flush_pages_after_backoff() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params { backoff_duration: Duration::from_secs(100), ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
-    let base_time = Instant::now();
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
+    let base_time = TimeApiImpl::get_boot_time();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_time)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_time
+        )
         .is_ok());
     mock.writeback.checkpoint();
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
@@ -186,7 +219,8 @@ fn mark_and_flush_pages_after_backoff() {
         .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_time + Duration::from_secs(100)
+            &suspend_history,
+            base_time.checked_add(Duration::from_secs(100)).unwrap()
         )
         .is_ok());
 }
@@ -205,14 +239,53 @@ fn mark_and_flush_pages_idle_time() {
         max_idle: Duration::from_secs(4000),
         ..Default::default()
     };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
     mock.set_idle.expect().with(eq("3747")).times(2).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
+        .is_ok());
+}
+
+#[test]
+fn mark_and_flush_pages_idle_time_adjusted_by_suspend_duration() {
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
+    let mut suspend_history = SuspendHistory::new();
+    let boot_now = BootTime::from_duration(Duration::from_secs(12345));
+    suspend_history.record_suspend_duration(Duration::from_secs(1000), boot_now, params.max_idle);
+    let mut zram_writeback =
+        ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
+
+    mock.set_idle.expect().with(eq("4747")).times(2).returning(|_| Ok(()));
+
+    assert!(zram_writeback
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            boot_now
+        )
         .is_ok());
 }
 
@@ -227,7 +300,8 @@ fn mark_and_flush_pages_calculate_idle_failure() {
         max_idle: Duration::from_secs(3600),
         ..Default::default()
     };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -235,7 +309,8 @@ fn mark_and_flush_pages_calculate_idle_failure() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            Instant::now()
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
         ),
         Err(Error::CalculateIdle(_))
     ));
@@ -249,7 +324,8 @@ fn mark_and_flush_pages_mark_idle_failure() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params::default();
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -259,7 +335,8 @@ fn mark_and_flush_pages_mark_idle_failure() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            Instant::now()
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
         ),
         Err(Error::MarkIdle(_))
     ));
@@ -273,7 +350,8 @@ fn mark_and_flush_pages_skip_huge_idle() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params { huge_idle: false, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -282,7 +360,12 @@ fn mark_and_flush_pages_skip_huge_idle() {
     mock.writeback.expect().with(eq("huge")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -294,7 +377,8 @@ fn mark_and_flush_pages_skip_idle() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params { idle: false, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -303,7 +387,12 @@ fn mark_and_flush_pages_skip_idle() {
     mock.writeback.expect().with(eq("huge")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -315,7 +404,8 @@ fn mark_and_flush_pages_skip_huge() {
     mock.setup_default_meminfo();
     mock.setup_default_writeback_limit_read();
     let params = Params { huge: false, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new(DEFAULT_TOTAL_ZRAM_SIZE, DEFAULT_ZRAM_WRITEBACK_SIZE);
 
@@ -324,7 +414,12 @@ fn mark_and_flush_pages_skip_huge() {
     mock.writeback.expect().with(eq("huge")).times(0).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -342,6 +437,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size() {
     };
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -352,7 +448,12 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size() {
     mock.write_writeback_limit.expect().with(eq("150")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -368,6 +469,7 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size_with_big_page_size() {
         Params { max_bytes: 600 * page_size, min_bytes: 10 * page_size, ..Default::default() };
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * page_size, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback =
         ZramWriteback::new_with_page_size(2000 * page_size, 1000 * page_size, page_size);
 
@@ -375,7 +477,12 @@ fn mark_and_flush_pages_write_limit_from_orig_data_size_with_big_page_size() {
     mock.write_writeback_limit.expect().with(eq("150")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -394,6 +501,7 @@ fn mark_and_flush_pages_write_limit_capped_by_current_writeback_size() {
     // zram utilization is 25%
     let stats =
         Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 1000 - 50 };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -404,7 +512,12 @@ fn mark_and_flush_pages_write_limit_capped_by_current_writeback_size() {
     mock.write_writeback_limit.expect().with(eq("50")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -422,6 +535,7 @@ fn mark_and_flush_pages_write_limit_capped_by_min_pages() {
     };
     // zram utilization is 1%
     let stats = Stats { orig_data_size: 20 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -435,7 +549,8 @@ fn mark_and_flush_pages_write_limit_capped_by_min_pages() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            Instant::now()
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
         ),
         Err(Error::Limit)
     ));
@@ -456,6 +571,7 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_with_no_log() {
     };
     // zram utilization is 25%
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
@@ -466,7 +582,12 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_with_no_log() {
     mock.write_writeback_limit.expect().with(eq("100")).times(1).returning(|_| Ok(()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -483,12 +604,13 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
         ..Default::default()
     };
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
         DEFAULT_PAGE_SIZE,
     );
-    let base_point = Instant::now();
+    let base_point = TimeApiImpl::get_boot_time();
 
     // Sets 100 as the daily limit for the first time.
     mock.write_writeback_limit.expect().with(eq("100")).times(1).returning(|_| Ok(()));
@@ -498,7 +620,12 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
     mock.read_writeback_limit.expect().returning(|| Ok("60".to_string()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_point)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
         .is_ok());
 
     // Daily limit with the history is applied on second markAndFlushPages.
@@ -508,7 +635,8 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit() {
         .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + Duration::from_secs(3600)
+            &suspend_history,
+            base_point.checked_add(Duration::from_secs(3600)).unwrap()
         )
         .is_ok());
 }
@@ -526,12 +654,13 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
         ..Default::default()
     };
     let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, current_writeback_pages: 0 };
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         2000 * DEFAULT_PAGE_SIZE,
         1000 * DEFAULT_PAGE_SIZE,
         DEFAULT_PAGE_SIZE,
     );
-    let base_point = Instant::now();
+    let base_point = TimeApiImpl::get_boot_time();
 
     // Sets 100 as the daily limit for the first time.
     mock.write_writeback_limit.expect().with(eq("100")).times(1).returning(|_| Ok(()));
@@ -541,7 +670,12 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
     mock.read_writeback_limit.expect().returning(|| Ok("60\n".to_string()));
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_point)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
         .is_ok());
 
     // On second time, the history is expired after 24 hours.
@@ -550,7 +684,8 @@ fn mark_and_flush_pages_write_limit_capped_by_daily_limit_expired() {
         .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + Duration::from_secs(24 * 3600)
+            &suspend_history,
+            base_point.checked_add(Duration::from_secs(24 * 3600)).unwrap()
         )
         .is_ok());
 }
@@ -562,7 +697,8 @@ fn mark_and_flush_pages_skip_on_write_limit() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params::default();
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
@@ -578,7 +714,12 @@ fn mark_and_flush_pages_skip_on_write_limit() {
     mock.writeback.expect().with(eq("huge")).times(0);
 
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, Instant::now())
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            TimeApiImpl::get_boot_time()
+        )
         .is_ok());
 }
 
@@ -590,20 +731,26 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
         DEFAULT_PAGE_SIZE,
     );
-    let base_point = Instant::now();
+    let base_point = TimeApiImpl::get_boot_time();
 
     // Load updated writeback_limit as the initial value.
     mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
     // On first writeback, writeback limit becomes zero and skip following writeback.
     mock.read_writeback_limit.expect().returning(|| Ok("0\n".to_string()));
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_point)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
         .is_ok());
 
     mock.write_writeback_limit.checkpoint();
@@ -612,7 +759,8 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + params.backoff_duration
+            &suspend_history,
+            base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
     ));
@@ -628,7 +776,8 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
         .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + Duration::from_secs(24 * 3600)
+            &suspend_history,
+            base_point.checked_add(Duration::from_secs(24 * 3600)).unwrap()
         )
         .is_ok());
 }
@@ -636,58 +785,115 @@ fn mark_and_flush_pages_skip_next_by_daily_limit() {
 #[test]
 fn mark_and_flush_pages_fails_to_record_history_by_writeback_error() {
     let mock = MockContext::new();
-    mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
         DEFAULT_PAGE_SIZE,
     );
-    let base_point = Instant::now();
+    let base_point = TimeApiImpl::get_boot_time();
 
-    // Load updated writeback_limit as the initial value.
+    mock.write_writeback_limit.expect().with(eq("100")).times(1).returning(|_| Ok(()));
     mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
-    mock.writeback.expect().returning(|_| Err(std::io::Error::other("error")));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("30\n".to_string()));
+    mock.writeback.expect().times(1).returning(|_| Err(std::io::Error::other("error")));
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_point)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
         .is_err());
 
+    mock.write_writeback_limit.checkpoint();
+    // 70 pages of previous writeback is discounted.
+    mock.write_writeback_limit.expect().with(eq("30")).times(1).returning(|_| Ok(()));
+    mock.read_writeback_limit.expect().returning(|| Ok("30\n".to_string()));
+    mock.writeback.expect().returning(|_| Ok(()));
+    zram_writeback
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point.checked_add(params.backoff_duration).unwrap(),
+        )
+        .unwrap();
+}
+
+#[test]
+fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
+    let mock = MockContext::new();
+    mock.writeback.expect().returning(|_| Ok(()));
+    mock.write_writeback_limit.expect().returning(|_| Ok(()));
+    mock.set_idle.expect().returning(|_| Ok(()));
+    mock.setup_default_meminfo();
+    let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
+    let mut zram_writeback = ZramWriteback::new_with_page_size(
+        DEFAULT_TOTAL_ZRAM_SIZE,
+        DEFAULT_ZRAM_WRITEBACK_SIZE,
+        DEFAULT_PAGE_SIZE,
+    );
+    let base_point = TimeApiImpl::get_boot_time();
+
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
+    // read writeback_limit fails just after writeback.
+    mock.read_writeback_limit.expect().returning(|| Err(std::io::Error::other("error")));
+    assert!(zram_writeback
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
+        .is_ok());
+
     mock.write_writeback_limit.checkpoint();
     mock.write_writeback_limit.expect().times(0);
     assert!(matches!(
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + params.backoff_duration
+            &suspend_history,
+            base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
     ));
 }
 
 #[test]
-fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
+fn mark_and_flush_pages_eio_due_consuming_writeback_limit() {
     let mock = MockContext::new();
-    mock.writeback.expect().returning(|_| Ok(()));
     mock.write_writeback_limit.expect().returning(|_| Ok(()));
     mock.set_idle.expect().returning(|_| Ok(()));
     mock.setup_default_meminfo();
     let params = Params { max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE, ..Default::default() };
-    let stats = Stats { orig_data_size: params.max_bytes, ..Default::default() };
+    let stats = default_stats(&params);
+    let suspend_history = SuspendHistory::new();
     let mut zram_writeback = ZramWriteback::new_with_page_size(
         DEFAULT_TOTAL_ZRAM_SIZE,
         DEFAULT_ZRAM_WRITEBACK_SIZE,
         DEFAULT_PAGE_SIZE,
     );
-    let base_point = Instant::now();
+    let base_point = TimeApiImpl::get_boot_time();
 
     mock.read_writeback_limit.expect().times(1).returning(|| Ok("100\n".to_string()));
-    // read writeback_limit fails just after writeback.
-    mock.read_writeback_limit.expect().returning(|| Err(std::io::Error::other("error")));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("0\n".to_string()));
+    mock.writeback.expect().returning(|_| Err(std::io::Error::from_raw_os_error(libc::EIO)));
+    // EIO with zero writeback limit is not considered as an error.
     assert!(zram_writeback
-        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(&params, &stats, base_point)
+        .mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+            &params,
+            &stats,
+            &suspend_history,
+            base_point
+        )
         .is_ok());
 
     mock.write_writeback_limit.checkpoint();
@@ -696,8 +902,55 @@ fn mark_and_flush_pages_fails_to_record_history_by_limit_load_error() {
         zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
             &params,
             &stats,
-            base_point + params.backoff_duration
+            &suspend_history,
+            base_point.checked_add(params.backoff_duration).unwrap()
         ),
         Err(Error::Limit)
     ));
 }
+
+#[test]
+fn mark_and_flush_pages_output_details() {
+    let mock = MockContext::new();
+    mock.writeback.expect().returning(|_| Ok(()));
+    mock.set_idle.expect().returning(|_| Ok(()));
+    mock.setup_default_meminfo();
+    let params = Params {
+        max_bytes: 600 * DEFAULT_PAGE_SIZE,
+        min_bytes: 10 * DEFAULT_PAGE_SIZE,
+        max_bytes_per_day: 100 * DEFAULT_PAGE_SIZE,
+        ..Default::default()
+    };
+    // zram utilization is 25%
+    let stats = Stats { orig_data_size: 500 * DEFAULT_PAGE_SIZE, ..Default::default() };
+    let suspend_history = SuspendHistory::new();
+    let mut zram_writeback = ZramWriteback::new_with_page_size(
+        2000 * DEFAULT_PAGE_SIZE,
+        1000 * DEFAULT_PAGE_SIZE,
+        DEFAULT_PAGE_SIZE,
+    );
+
+    mock.write_writeback_limit.expect().with(eq("100")).times(1).returning(|_| Ok(()));
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("90\n".to_string()));
+    // 10 huge_idle pages were written back.
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("80\n".to_string()));
+    // 20 idle pages were written back.
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("60\n".to_string()));
+    // 25 huge pages were written back.
+    mock.read_writeback_limit.expect().times(1).returning(|| Ok("35\n".to_string()));
+
+    let result = zram_writeback.mark_and_flush_pages::<MockSysfsZramApi, MockMeminfoApi>(
+        &params,
+        &stats,
+        &suspend_history,
+        TimeApiImpl::get_boot_time(),
+    );
+    assert!(result.is_ok());
+    let details = result.unwrap();
+    assert_eq!(details.limit_pages, 150);
+    assert_eq!(details.daily_limit_pages, 100);
+    assert_eq!(details.actual_limit_pages, 90);
+    assert_eq!(details.huge_idle.written_pages, 10);
+    assert_eq!(details.idle.written_pages, 20);
+    assert_eq!(details.huge.written_pages, 25);
+}
```

