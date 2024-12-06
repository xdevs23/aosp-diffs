```diff
diff --git a/Android.bp b/Android.bp
index 60c83273..87859d98 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,11 +22,28 @@ python_library_host {
     srcs: [
         "atest/proto/*.proto",
     ],
+    libs: [
+        "asuite_adb_host_proto_py",
+    ],
     proto: {
         canonical_path_from_root: false,
     },
 }
 
+python_library_host {
+    name: "asuite_adb_host_proto_py",
+    srcs: [
+        ":adb_host_proto",
+    ],
+    proto: {
+        type: "full",
+        include_dirs: ["external/protobuf/src"],
+    },
+    visibility: [
+        "//tools/asuite:__subpackages__",
+    ],
+}
+
 java_library_host {
     name: "asuite_proto_java",
     srcs: [
diff --git a/adevice/Android.bp b/adevice/Android.bp
index c52f5c29..4b5bf240 100644
--- a/adevice/Android.bp
+++ b/adevice/Android.bp
@@ -86,7 +86,6 @@ rust_defaults {
         "libclap",
         "libhex",
         "libitertools",
-        "liblazy_static",
         "librayon",
         "libregex",
         "libring",
diff --git a/adevice/Cargo.toml b/adevice/Cargo.toml
index 1bd3ec7c..1f07c78d 100644
--- a/adevice/Cargo.toml
+++ b/adevice/Cargo.toml
@@ -16,7 +16,6 @@ clap = { features = ["derive"]}
 googletest = {path = "../../../external/rust/crates/googletest" }
 hex = { path = "../../../external/rust/crates/hex" }
 itertools = { path = "../../../external/rust/crates/itertools"}
-lazy_static = { path = "../../../external/rust/crates/lazy_static"}
 protobuf = { path = "../../../external/rust/crates/protobuf" }
 rayon = { path = "../../../external/rust/crates/rayon"}
 regex = { path = "../../../external/rust/crates/regex"}
@@ -45,5 +44,3 @@ path = "src/main.rs"
 [[bin]]
 name = "adevice_fingerprint"
 path = "src/adevice_fingerprint.rs"
-
-
diff --git a/adevice/integration_tests/build_adevice_integration_tests.sh b/adevice/integration_tests/build_adevice_integration_tests.sh
index d706f97f..9574b8fd 100755
--- a/adevice/integration_tests/build_adevice_integration_tests.sh
+++ b/adevice/integration_tests/build_adevice_integration_tests.sh
@@ -16,8 +16,8 @@
 
 # This script is dedicated to build the atest integration test in build server.
 # To run the test locally, it's recommended to invoke the test via
-# `atest atest_integration_tests` or `python atest_integration_tests.py`.
-# For usage examples please run `python atest_integration_tests.py --help`.
+# `atest adevice_integration_tests` or `python adevice_integration_tests.py`.
+# For usage examples please run `python adevice_integration_tests.py --help`.
 
 set -eo pipefail
 set -x
@@ -98,4 +98,6 @@ export PATH=${PWD}/prebuilts/build-tools/path/linux-x86:${PWD}/build/bazel/bin:$
 # build with minimal reliance on host tools.
 export PATH=${ANDROID_JAVA_HOME}/bin:${PATH}
 
-python3 tools/asuite/atest/integration_tests/adevice_integration_tests.py "${filtered_args[@]}" --build --tar_snapshot
+echo "Starting Adevice Integration Tests"
+
+python3 tools/asuite/atest/integration_tests/adevice_integration_tests.py "${filtered_args[@]}" --build --tar_snapshot --use-prebuilt-atest-binary
diff --git a/adevice/src/adevice.rs b/adevice/src/adevice.rs
index a22d260b..563eb1dd 100644
--- a/adevice/src/adevice.rs
+++ b/adevice/src/adevice.rs
@@ -9,7 +9,6 @@ use crate::tracking::Config;
 use anyhow::{anyhow, bail, Context, Result};
 use fingerprint::{DiffMode, FileMetadata};
 use itertools::Itertools;
-use lazy_static::lazy_static;
 use metrics::MetricSender;
 use rayon::prelude::*;
 use regex::Regex;
@@ -22,7 +21,7 @@ use std::fs;
 use std::fs::File;
 use std::io::{stdin, Write};
 use std::path::{Path, PathBuf};
-use std::sync::Mutex;
+use std::sync::{LazyLock, Mutex};
 use std::time::Duration;
 
 /// Methods that interact with the host, like fingerprinting and calling ninja to get deps.
@@ -200,6 +199,7 @@ pub fn adevice(
         &device.get_installed_apks()?,
         diff_mode,
         &partition_paths,
+        cli.global_options.force,
         stdout,
     )?;
     progress::stop();
@@ -306,6 +306,7 @@ fn get_update_commands(
     installed_packages: &HashSet<String>,
     diff_mode: DiffMode,
     partitions: &[PathBuf],
+    force: bool,
     stdout: &mut impl Write,
 ) -> Result<commands::Commands> {
     // NOTE: The Ninja deps list can be _ahead_of_ the product tree output list.
@@ -345,7 +346,11 @@ fn get_update_commands(
 
     #[allow(clippy::len_zero)]
     if needs_building.len() > 0 {
-        println!("WARNING: Please build needed [unbuilt] modules before updating.");
+        if force {
+            println!("UNSAFE: The above modules should be built, but were not. This may cause the device to crash:\nProceeding due to \"--force\" flag.");
+        } else {
+            bail!("ERROR: Please build the above modules before updating.\nIf you want to continue anyway (which may cause the device to crash), rerun adevice with the \"--force\" flag.");
+        }
     }
 
     // Restrict the host set down to the ones that are in the tracked set and not installed in the data partition.
@@ -516,10 +521,8 @@ fn is_apk_installed(host_path: &Path, installed_packages: &HashSet<String>) -> R
     }
 }
 
-lazy_static! {
-    static ref AAPT_PACKAGE_MATCHER: Regex =
-        Regex::new(r"^package: (.+)$").expect("regex does not compile");
-}
+static AAPT_PACKAGE_MATCHER: LazyLock<Regex> =
+    LazyLock::new(|| Regex::new(r"^package: (.+)$").expect("regex does not compile"));
 
 /// Filter aapt2 dump output to parse out the package name for the apk.
 fn package_from_aapt_dump_output(stdout: Vec<u8>) -> Result<String> {
@@ -714,7 +717,9 @@ impl std::fmt::Display for Profiler {
                 format!("Wait For boot completed - {}", self.wait_for_boot_completed.as_secs()),
                 format!("First remount RW - {}", self.first_remount_rw.as_secs()),
                 format!("TOTAL - {}", self.total.as_secs()),
-            ].join("\n\t"))
+            ]
+            .join("\n\t")
+        )
     }
 }
 
@@ -735,6 +740,7 @@ mod tests {
         let product_out = PathBuf::from("");
         let installed_apks = HashSet::<String>::new();
         let partitions = Vec::new();
+        let force = false;
         let mut stdout = Vec::new();
 
         let results = get_update_commands(
@@ -745,6 +751,7 @@ mod tests {
             &installed_apks,
             DiffMode::UsePermissions,
             &partitions,
+            force,
             &mut stdout,
         )?;
         assert_eq!(results.upserts.values().len(), 0);
@@ -758,6 +765,7 @@ mod tests {
         let installed_apks = HashSet::<String>::new();
         let partitions = Vec::new();
         let mut stdout = Vec::new();
+        let force = true;
 
         let results = get_update_commands(
             // Device files
@@ -773,12 +781,47 @@ mod tests {
             &installed_apks,
             DiffMode::UsePermissions,
             &partitions,
+            force,
             &mut stdout,
         )?;
         assert_eq!(results.upserts.values().len(), 2);
         Ok(())
     }
 
+    #[test]
+    fn host_and_ninja_file_not_on_device_force_false() -> Result<()> {
+        let product_out = PathBuf::from("");
+        let installed_apks = HashSet::<String>::new();
+        let partitions = Vec::new();
+        let mut stdout = Vec::new();
+        let force = false;
+
+        let results = get_update_commands(
+            // Device files
+            &HashMap::new(),
+            // Host files
+            &HashMap::from([
+                (PathBuf::from("system/myfile"), file_metadata("digest1")),
+                (PathBuf::from("system"), dir_metadata()),
+            ]),
+            // Ninja deps
+            &["system".to_string(), "system/myfile".to_string()],
+            product_out,
+            &installed_apks,
+            DiffMode::UsePermissions,
+            &partitions,
+            force,
+            &mut stdout,
+        );
+        assert!(results.is_err());
+        if let Err(e) = results {
+            assert!(e
+                .to_string()
+                .contains("ERROR: Please build the above modules before updating."));
+        }
+        Ok(())
+    }
+
     #[test]
     fn test_shadow_apk_check_no_shadowing_apks() -> Result<()> {
         let mut output = Vec::new();
@@ -923,7 +966,7 @@ mod tests {
         let product_out = PathBuf::from("");
         let installed_apks = HashSet::<String>::new();
         let partitions = Vec::new();
-
+        let force = false;
         let mut device_files: HashMap<PathBuf, FileMetadata> = HashMap::new();
         let mut host_files: HashMap<PathBuf, FileMetadata> = HashMap::new();
         for d in fake_state.device_data {
@@ -948,6 +991,7 @@ mod tests {
             &installed_apks,
             DiffMode::UsePermissions,
             &partitions,
+            force,
             &mut stdout,
         )
     }
diff --git a/adevice/src/cli.rs b/adevice/src/cli.rs
index 928c7360..5b8ead21 100644
--- a/adevice/src/cli.rs
+++ b/adevice/src/cli.rs
@@ -59,6 +59,11 @@ pub struct GlobalOptions {
     // TODO(rbraunstein): Add system_other to the default list, but deal gracefully
     // with it not being on the device.
     /// Partitions in the product tree to sync. Repeat arg or comma-separate.
+    ///
+    /// By default this includes: "system", "system_ext", "odm", "product"
+    ///
+    /// If a partition is explicitly passed in but that does not exist in the
+    /// tracked files then adevice will error.
     #[clap(long, short, global = true, value_delimiter = ',')]
     pub partitions: Option<Vec<String>>,
     // TODO(rbraunstein): Validate relative, not absolute paths.
@@ -77,6 +82,9 @@ pub struct GlobalOptions {
     /// Path to config file.  Uses $HOME/.config/asuite/adevice-tracking.json if unset.
     #[clap(long = "config", global = true)]
     pub config_path: Option<String>,
+    #[clap(long = "force", global = true, alias = "force", alias = "force")]
+    // Force device update even if unbuilt modules are detected.
+    pub force: bool,
     // Don't wait for device to become available after restarting it.
     #[clap(long = "nowait", global = true, alias = "no_wait", alias = "no-wait")]
     pub nowait: bool,
@@ -138,6 +146,18 @@ mod tests {
     use super::Cli;
     use clap::Parser;
 
+    #[test]
+    fn force_default_false() {
+        let cli = Cli::parse_from(["fake_prog", "update"]);
+        assert!(!cli.global_options.force);
+    }
+
+    #[test]
+    fn force_works() {
+        let cli = Cli::parse_from(["fake_prog", "update", "--force"]);
+        assert!(cli.global_options.force);
+    }
+
     #[test]
     fn nowait_works() {
         let cli = Cli::parse_from(["fake_prog", "update", "--nowait"]);
diff --git a/adevice/src/device.rs b/adevice/src/device.rs
index 50e12391..3b006e7e 100644
--- a/adevice/src/device.rs
+++ b/adevice/src/device.rs
@@ -6,13 +6,13 @@ use crate::{fingerprint, time};
 
 use anyhow::{anyhow, bail, Context, Result};
 use itertools::Itertools;
-use lazy_static::lazy_static;
 use regex::Regex;
 use serde::__private::ToString;
 use std::cmp::Ordering;
 use std::collections::{HashMap, HashSet};
 use std::path::PathBuf;
 use std::process;
+use std::sync::LazyLock;
 use std::thread::sleep;
 use std::time::Duration;
 use std::time::Instant;
@@ -64,13 +64,13 @@ impl Device for RealDevice {
     /// First ask adb to wait for the device, then poll for sys.boot_completed on the device.
     fn wait(&self, profiler: &mut Profiler) -> Result<String> {
         // Typically the reboot on acloud is 25 secs
-        // And another 50 for fully booted
-        // Wait up to 3 times as long for either'
+        // It can take 130 seconds after for a full boot.
+        // Setting timeouts to have at least 2x that.
         progress::start(" * [1/2] Waiting for device to connect.");
         time!(
             {
                 let args = self.adjust_adb_args(&["wait-for-device".to_string()]);
-                self.wait_for_adb_with_timeout(&args, Duration::from_secs(70))?;
+                self.wait_for_adb_with_timeout(&args, Duration::from_secs(75))?;
             },
             profiler.wait_for_device
         );
@@ -83,7 +83,7 @@ impl Device for RealDevice {
                     "shell".to_string(),
                     "while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done".to_string(),
                 ]);
-                let result = self.wait_for_adb_with_timeout(&args, Duration::from_secs(100));
+                let result = self.wait_for_adb_with_timeout(&args, Duration::from_secs(260));
                 progress::stop();
                 result
             },
@@ -151,15 +151,14 @@ impl Device for RealDevice {
     }
 }
 
-lazy_static! {
-    // Sample output, one installed, one not:
-    // % adb exec-out pm list packages  -s -f  | grep shell
-    //   package:/product/app/Browser2/Browser2.apk=org.chromium.webview_shell
-    //   package:/data/app/~~PxHDtZDEgAeYwRyl-R3bmQ==/com.android.shell--R0z7ITsapIPKnt4BT0xkg==/base.apk=com.android.shell
-    // # capture the package name (com.android.shell)
-    static ref PM_LIST_PACKAGE_MATCHER: Regex =
-        Regex::new(r"^package:/data/app/.*/base.apk=(.+)$").expect("regex does not compile");
-}
+// Sample output, one installed, one not:
+// % adb exec-out pm list packages  -s -f  | grep shell
+//   package:/product/app/Browser2/Browser2.apk=org.chromium.webview_shell
+//   package:/data/app/~~PxHDtZDEgAeYwRyl-R3bmQ==/com.android.shell--R0z7ITsapIPKnt4BT0xkg==/base.apk=com.android.shell
+// # capture the package name (com.android.shell)
+static PM_LIST_PACKAGE_MATCHER: LazyLock<Regex> = LazyLock::new(|| {
+    Regex::new(r"^package:/data/app/.*/base.apk=(.+)$").expect("regex does not compile")
+});
 
 /// Filter package manager output to figure out if the apk is installed in /data.
 fn apks_from_pm_list_output(stdout: &str) -> HashSet<String> {
@@ -218,7 +217,7 @@ impl RealDevice {
             } else {
                 // If pontis is running, add to the error message to check pontis UI
                 let pontis_status = process::Command::new("pontis")
-                    .args(&vec!["status".to_string()])
+                    .args(vec!["status".to_string()])
                     .output()
                     .context("Error checking pontis status")?;
 
diff --git a/adevice/src/metrics.rs b/adevice/src/metrics.rs
index bddab2a6..a5bd2e87 100644
--- a/adevice/src/metrics.rs
+++ b/adevice/src/metrics.rs
@@ -21,7 +21,8 @@ const ENV_OUT: &str = "OUT";
 const ENV_USER: &str = "USER";
 const ENV_TARGET: &str = "TARGET_PRODUCT";
 const ENV_SURVEY_BANNER: &str = "ADEVICE_SURVEY_BANNER";
-const METRICS_UPLOADER: &str = "/google/bin/releases/adevice-dev/metrics_uploader";
+const METRICS_UPLOADER: &str = "/google/bin/releases/adevice-dev/
+";
 const ADEVICE_LOG_SOURCE: i32 = 2265;
 
 pub trait MetricSender {
@@ -43,6 +44,7 @@ pub struct Metrics {
     events: Vec<LogEvent>,
     user: String,
     invocation_id: String,
+    hostname: String,
 }
 
 impl MetricSender for Metrics {
@@ -51,6 +53,7 @@ impl MetricSender for Metrics {
         start_event.set_command_line(command_line.to_string());
         start_event.set_source_root(source_root.to_string());
         start_event.set_target(env::var(ENV_TARGET).unwrap_or("".to_string()));
+        start_event.set_hostname(self.hostname.to_string());
 
         let mut event = self.default_log_event();
         event.set_adevice_start_event(start_event);
@@ -147,6 +150,7 @@ impl Default for Metrics {
             events: Vec::new(),
             user: env::var(ENV_USER).unwrap_or("".to_string()),
             invocation_id: Uuid::new_v4().to_string(),
+            hostname: get_hostname(),
         }
     }
 }
@@ -157,7 +161,9 @@ impl Metrics {
         if fs::metadata(METRICS_UPLOADER).is_err() {
             return Err(anyhow!("Not internal user: Metrics not sent since uploader not found"));
         }
-
+        if self.user.is_empty() {
+            return Err(anyhow!("USER env not set: Metrics not sent since no user set"));
+        }
         // Serialize
         let body = {
             let mut log_request = LogRequest::default();
@@ -175,14 +181,15 @@ impl Metrics {
         let temp_file_path = format!("{}/adevice/adevice.bin", out);
         fs::create_dir_all(temp_dir).expect("Failed to create folder for metrics");
         fs::write(temp_file_path.clone(), body).expect("Failed to write to metrics file");
-        Command::new(METRICS_UPLOADER)
+        if let Err(e) = Command::new(METRICS_UPLOADER)
             .args([&temp_file_path])
             .stdin(Stdio::null())
             .stdout(Stdio::null())
             .stderr(Stdio::null())
             .spawn()
-            .expect("Failed to send metrics");
-
+        {
+            return Err(anyhow!("Failed to send metrics {}", e));
+        }
         // TODO implement next_request_wait_millis that comes back in response
 
         Ok(())
@@ -196,6 +203,19 @@ impl Metrics {
     }
 }
 
+fn get_hostname() -> String {
+    Command::new("hostname").output().map_or_else(
+        |_err| String::new(),
+        |output| {
+            if output.status.success() {
+                String::from_utf8_lossy(&output.stdout).trim().to_string()
+            } else {
+                String::new()
+            }
+        },
+    )
+}
+
 impl Drop for Metrics {
     fn drop(&mut self) {
         match self.send() {
diff --git a/adevice/src/progress.rs b/adevice/src/progress.rs
index d5ecf152..f6343fc8 100644
--- a/adevice/src/progress.rs
+++ b/adevice/src/progress.rs
@@ -1,16 +1,12 @@
 use std::io::{self, Write};
-use std::sync::{Arc, Mutex};
+use std::sync::{Arc, LazyLock, Mutex};
 use std::thread;
 use std::time::{Duration, Instant};
 
-use lazy_static::lazy_static;
-
-lazy_static! {
-    static ref PROGRESS: Progress = Progress {
-        message: Arc::new(Mutex::new("".to_string())),
-        is_complete: Arc::new(Mutex::new(false))
-    };
-}
+static PROGRESS: LazyLock<Progress> = LazyLock::new(|| Progress {
+    message: Arc::new(Mutex::new("".to_string())),
+    is_complete: Arc::new(Mutex::new(false)),
+});
 
 pub struct Progress {
     message: Arc<Mutex<String>>,
diff --git a/adevice/src/protos/user_log.proto b/adevice/src/protos/user_log.proto
index 1b7e20d9..e936abf4 100644
--- a/adevice/src/protos/user_log.proto
+++ b/adevice/src/protos/user_log.proto
@@ -18,6 +18,7 @@ message AdeviceLogEvent {
     optional string os = 4;
     optional string target = 5;
     optional string source_root = 6;
+    optional string hostname = 7;
   }
   // Occurs when adevice exits for any reason
   message AdeviceExitEvent {
diff --git a/adevice/src/tracking.rs b/adevice/src/tracking.rs
index d0d3fc6a..114fe3fd 100644
--- a/adevice/src/tracking.rs
+++ b/adevice/src/tracking.rs
@@ -5,13 +5,13 @@
 ///  2) Integration with ninja to derive "installed" files from
 ///     this module set.
 use anyhow::{bail, Context, Result};
-use lazy_static::lazy_static;
 use regex::Regex;
 use serde::{Deserialize, Serialize};
 use std::fs;
 use std::io::BufReader;
 use std::path::PathBuf;
 use std::process;
+use std::sync::LazyLock;
 use tracing::{debug, warn};
 
 #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
@@ -298,10 +298,9 @@ fn tracked_files(output: &process::Output) -> Result<Vec<String>> {
 //     innie/target/product/vsoc_x86_64/system/app/CameraExtensionsProxy/CameraExtensionsProxy.apk
 // Match any files with target/product as the second and third dir paths and capture
 // everything from 5th path element to the end.
-lazy_static! {
-    static ref NINJA_OUT_PATH_MATCHER: Regex =
-        Regex::new(r"^[^/]+/target/product/[^/]+/(.+)$").expect("regex does not compile");
-}
+static NINJA_OUT_PATH_MATCHER: LazyLock<Regex> = LazyLock::new(|| {
+    Regex::new(r"^[^/]+/target/product/[^/]+/(.+)$").expect("regex does not compile")
+});
 
 fn strip_product_prefix(path: &str) -> Option<String> {
     NINJA_OUT_PATH_MATCHER.captures(path).map(|x| x[1].to_string())
diff --git a/aidegen/lib/ide_util.py b/aidegen/lib/ide_util.py
index 0bc3dd43..2fec0baf 100644
--- a/aidegen/lib/ide_util.py
+++ b/aidegen/lib/ide_util.py
@@ -77,12 +77,12 @@ _INFO_IMPORT_CONFIG = ('{} needs to import the application configuration for '
                        '\n\n')
 CONFIG_DIR = 'config'
 LINUX_JDK_PATH = os.path.join(common_util.get_android_root_dir(),
-                              'prebuilts/jdk/jdk17/linux-x86')
+                              'prebuilts/jdk/jdk21/linux-x86')
 LINUX_JDK_TABLE_PATH = 'config/options/jdk.table.xml'
 LINUX_FILE_TYPE_PATH = 'config/options/filetypes.xml'
 LINUX_ANDROID_SDK_PATH = os.path.join(os.getenv('HOME'), 'Android/Sdk')
 MAC_JDK_PATH = os.path.join(common_util.get_android_root_dir(),
-                            'prebuilts/jdk/jdk17/darwin-x86')
+                            'prebuilts/jdk/jdk21/darwin-x86')
 ALTERNATIVE_JDK_TABLE_PATH = 'options/jdk.table.xml'
 ALTERNATIVE_FILE_TYPE_XML_PATH = 'options/filetypes.xml'
 MAC_ANDROID_SDK_PATH = os.path.join(os.getenv('HOME'), 'Library/Android/sdk')
diff --git a/aidegen/sdk/jdk_table.py b/aidegen/sdk/jdk_table.py
index d3325944..36ade946 100644
--- a/aidegen/sdk/jdk_table.py
+++ b/aidegen/sdk/jdk_table.py
@@ -70,7 +70,7 @@ class JDKTableXML:
     _ADDITIONAL = 'additional'
     _ANDROID_SDK = 'Android SDK'
     _JAVA_SDK = 'JavaSDK'
-    _JDK_VERSION = 'JDK17'
+    _JDK_VERSION = 'JDK21'
     _APPLICATION = 'application'
     _COMPONENT = 'component'
     _PROJECTJDKTABLE = 'ProjectJdkTable'
@@ -162,11 +162,11 @@ class JDKTableXML:
             return True
         return False
 
-    def _check_jdk17_in_xml(self):
-        """Checks if the JDK17 is already set in jdk.table.xml.
+    def _check_jdk21_in_xml(self):
+        """Checks if the JDK21 is already set in jdk.table.xml.
 
         Returns:
-            Boolean: True if the JDK17 exists else False.
+            Boolean: True if the JDK21 exists else False.
         """
         for jdk in self._xml.iter(self._JDK):
             _name = jdk.find(self._NAME)
@@ -230,7 +230,7 @@ class JDKTableXML:
 
     def _generate_jdk_config_string(self):
         """Generates the default JDK configuration."""
-        if self._check_jdk17_in_xml():
+        if self._check_jdk21_in_xml():
             return
         self._append_config(self._jdk_content.format(JDKpath=self._jdk_path))
         self._modify_config = True
@@ -258,10 +258,10 @@ class JDKTableXML:
     def config_jdk_table_xml(self):
         """Configures the jdk.table.xml.
 
-        1. Generate the JDK17 configuration if it does not exist.
+        1. Generate the JDK21 configuration if it does not exist.
         2. Generate the Android SDK configuration if it does not exist and
            save the Android SDK path.
-        3. Update the jdk.table.xml if AIDEGen needs to append JDK17 or
+        3. Update the jdk.table.xml if AIDEGen needs to append JDK21 or
            Android SDK configuration.
 
         Returns:
diff --git a/aidegen/sdk/jdk_table_unittest.py b/aidegen/sdk/jdk_table_unittest.py
index 7a55edd2..9a9ac428 100644
--- a/aidegen/sdk/jdk_table_unittest.py
+++ b/aidegen/sdk/jdk_table_unittest.py
@@ -101,7 +101,7 @@ class JDKTableXMLUnittests(unittest.TestCase):
         self.jdk_table_xml._xml = ElementTree.parse(tmp_file)
         self.assertTrue(self.jdk_table_xml._check_structure())
 
-    @mock.patch.object(jdk_table.JDKTableXML, '_check_jdk17_in_xml')
+    @mock.patch.object(jdk_table.JDKTableXML, '_check_jdk21_in_xml')
     def test_generate_jdk_config_string(self, mock_jdk_exists):
         """Test _generate_jdk_config_string."""
         mock_jdk_exists.return_value = True
@@ -171,19 +171,19 @@ class JDKTableXMLUnittests(unittest.TestCase):
         mock_override.return_value = True
         self.assertTrue(mock_gen_jdk.called)
 
-    def test_check_jdk17_in_xml(self):
-        """Test _check_jdk17_in_xml."""
-        xml_str = ('<test><jdk><name value="JDK17" /><type value="JavaSDK" />'
+    def test_check_jdk21_in_xml(self):
+        """Test _check_jdk21_in_xml."""
+        xml_str = ('<test><jdk><name value="JDK21" /><type value="JavaSDK" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
-        self.assertTrue(self.jdk_table_xml._check_jdk17_in_xml())
+        self.assertTrue(self.jdk_table_xml._check_jdk21_in_xml())
         xml_str = ('<test><jdk><name value="test" /><type value="JavaSDK" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
-        self.assertFalse(self.jdk_table_xml._check_jdk17_in_xml())
+        self.assertFalse(self.jdk_table_xml._check_jdk21_in_xml())
         xml_str = ('<test><jdk><name value="test" /></jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
-        self.assertFalse(self.jdk_table_xml._check_jdk17_in_xml())
+        self.assertFalse(self.jdk_table_xml._check_jdk21_in_xml())
 
     @mock.patch.object(android_sdk.AndroidSDK, 'is_android_sdk_path')
     def test_check_android_sdk_in_xml(self, mock_is_android_sdk):
@@ -195,27 +195,27 @@ class JDKTableXMLUnittests(unittest.TestCase):
             },
         }
         mock_is_android_sdk.return_value = True
-        xml_str = ('<test><jdk><name value="JDK17" /><type value="JavaSDK" />'
+        xml_str = ('<test><jdk><name value="JDK21" /><type value="JavaSDK" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
         self.assertFalse(self.jdk_table_xml._check_android_sdk_in_xml())
         xml_str = ('<test><jdk><name value="Android SDK 29 platform" />'
                    '<type value="Android SDK" />'
-                   '<additional jdk="JDK17" sdk="android-29" />'
+                   '<additional jdk="JDK21" sdk="android-29" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
         self.assertFalse(self.jdk_table_xml._check_android_sdk_in_xml())
         xml_str = ('<test><jdk><name value="Android SDK 28 platform" />'
                    '<type value="Android SDK" />'
                    '<homePath value="/path/to/Android/SDK" />'
-                   '<additional jdk="JDK17" sdk="android-28" />'
+                   '<additional jdk="JDK21" sdk="android-28" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
         self.assertFalse(self.jdk_table_xml._check_android_sdk_in_xml())
         xml_str = ('<test><jdk><name value="Android SDK 29 platform" />'
                    '<type value="Android SDK" />'
                    '<homePath value="/path/to/Android/SDK" />'
-                   '<additional jdk="JDK17" sdk="android-29" />'
+                   '<additional jdk="JDK21" sdk="android-29" />'
                    '</jdk></test>')
         self.jdk_table_xml._xml = ElementTree.fromstring(xml_str)
         self.assertTrue(self.jdk_table_xml._check_android_sdk_in_xml())
diff --git a/aidegen/templates.py b/aidegen/templates.py
index d90d9fc9..4298db72 100644
--- a/aidegen/templates.py
+++ b/aidegen/templates.py
@@ -146,7 +146,7 @@ XML_MISC = """\
         </default-html-doctype>
     </component>
     <component name="ProjectRootManager" version="2" languageLevel="JDK_17"
-               assert-keyword="true" project-jdk-name="JDK17"
+               assert-keyword="true" project-jdk-name="JDK21"
                project-jdk-type="JavaSDK"/>
     <component name="WebServicesPlugin" addRequiredLibraries="true"/>
 </project>
@@ -243,7 +243,7 @@ XML_INSPECTIONS = """\
 # The configuration of JDK on Linux.
 LINUX_JDK_XML = """\
     <jdk version="2">
-      <name value="JDK17" />
+      <name value="JDK21" />
       <type value="JavaSDK" />
       <version value="java version &quot;17.0.4&quot;" />
       <homePath value="{JDKpath}" />
@@ -412,7 +412,7 @@ LINUX_JDK_XML = """\
 # The configuration of JDK on Mac.
 MAC_JDK_XML = """\
     <jdk version="2">
-      <name value="JDK17" />
+      <name value="JDK21" />
       <type value="JavaSDK" />
       <version value="java version &quot;17.0.4&quot;" />
       <homePath value="{JDKpath}" />
@@ -619,7 +619,7 @@ ANDROID_SDK_XML = """\
           <root type="composite" />
         </sourcePath>
       </roots>
-      <additional jdk="JDK17" sdk="android-{CODE_NAME}" />
+      <additional jdk="JDK21" sdk="android-{CODE_NAME}" />
     </jdk>
 """
 
diff --git a/aidegen/test_data/jdk_table_xml/android_sdk.xml b/aidegen/test_data/jdk_table_xml/android_sdk.xml
index 54f85e3d..39da7e8d 100644
--- a/aidegen/test_data/jdk_table_xml/android_sdk.xml
+++ b/aidegen/test_data/jdk_table_xml/android_sdk.xml
@@ -26,7 +26,7 @@
           <root type="composite" />
         </sourcePath>
       </roots>
-      <additional jdk="JDK17" sdk="android-28" />
+      <additional jdk="JDK21" sdk="android-28" />
     </jdk>
   </component>
 </application>
diff --git a/aidegen/test_data/jdk_table_xml/android_sdk_nonexistent.xml b/aidegen/test_data/jdk_table_xml/android_sdk_nonexistent.xml
index f7f564cd..406b2c9d 100644
--- a/aidegen/test_data/jdk_table_xml/android_sdk_nonexistent.xml
+++ b/aidegen/test_data/jdk_table_xml/android_sdk_nonexistent.xml
@@ -26,7 +26,7 @@
           <root type="composite" />
         </sourcePath>
       </roots>
-      <additional jdk="JDK17" sdk="android-28" />
+      <additional jdk="JDK21" sdk="android-28" />
     </jdk>
   </component>
 </application>
diff --git a/aidegen/test_data/jdk_table_xml/jdk17.xml b/aidegen/test_data/jdk_table_xml/jdk21.xml
similarity index 55%
rename from aidegen/test_data/jdk_table_xml/jdk17.xml
rename to aidegen/test_data/jdk_table_xml/jdk21.xml
index 72cddfcb..bdf067cc 100644
--- a/aidegen/test_data/jdk_table_xml/jdk17.xml
+++ b/aidegen/test_data/jdk_table_xml/jdk21.xml
@@ -1,10 +1,10 @@
 <application>
   <component name="ProjectJdkTable">
     <jdk version="2">
-      <name value="JDK17" />
+      <name value="JDK21" />
       <type value="JavaSDK" />
       <version value="java version &quot;17.0.4&quot;" />
-      <homePath value="/path/to/android/root/prebuilts/jdk/jdk17/linux-x86" />
+      <homePath value="/path/to/android/root/prebuilts/jdk/jdk21/linux-x86" />
       <roots>
         <annotationsPath>
           <root type="composite">
@@ -13,76 +13,76 @@
         </annotationsPath>
         <classPath>
           <root type="composite">
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.base" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.datatransfer" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.desktop" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.instrument" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.logging" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.management.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.naming" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.net.http" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.prefs" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.scripting" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.se" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.security.jgss" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.security.sasl" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.smartcardio" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.sql" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.sql.rowset" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.transaction.xa" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.xml" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.xml.crypto" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.accessibility" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.attach" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.charsets" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.crypto.cryptoki" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.crypto.ec" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.dynalink" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.editpad" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.hotspot.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.httpserver" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.incubator.foreign" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.incubator.vector" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.ed" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.jvmstat" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.le" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.opt" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.ci" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.compiler.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jartool" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.javadoc" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jcmd" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jconsole" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdeps" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdwp.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jfr" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jlink" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jpackage" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jshell" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jsobject" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jstatd" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.localedata" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management.jfr" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.naming.dns" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.naming.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.net" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.nio.mapmode" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.random" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.sctp" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.security.auth" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.security.jgss" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.unsupported" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.unsupported.desktop" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.xml.dom" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.zipfs" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.base" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.datatransfer" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.desktop" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.instrument" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.logging" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.management.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.naming" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.net.http" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.prefs" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.scripting" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.se" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.security.jgss" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.security.sasl" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.smartcardio" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.sql" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.sql.rowset" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.transaction.xa" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.xml" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.xml.crypto" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.accessibility" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.attach" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.charsets" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.crypto.cryptoki" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.crypto.ec" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.dynalink" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.editpad" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.hotspot.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.httpserver" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.incubator.foreign" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.incubator.vector" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.ed" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.jvmstat" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.le" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.opt" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.ci" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.compiler.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jartool" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.javadoc" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jcmd" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jconsole" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdeps" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdwp.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jfr" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jlink" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jpackage" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jshell" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jsobject" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jstatd" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.localedata" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management.jfr" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.naming.dns" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.naming.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.net" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.nio.mapmode" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.random" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.sctp" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.security.auth" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.security.jgss" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.unsupported" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.unsupported.desktop" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.xml.dom" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.zipfs" type="simple" />
           </root>
         </classPath>
         <javadocPath>
@@ -90,76 +90,76 @@
         </javadocPath>
         <sourcePath>
           <root type="composite">
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.se" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jfr" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.net" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.sql" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.xml" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jcmd" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.sctp" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.base" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdeps" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jlink" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.zipfs" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.prefs" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.attach" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jshell" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jstatd" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.random" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.naming" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.editpad" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jartool" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.javadoc" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.xml.dom" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.desktop" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.logging" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.charsets" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.dynalink" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jconsole" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jpackage" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jsobject" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.net.http" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.crypto.ec" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.scripting" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.httpserver" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdwp.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.localedata" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.naming.dns" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.naming.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.instrument" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.management" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.sql.rowset" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.xml.crypto" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.ed" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.le" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.nio.mapmode" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.unsupported" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.smartcardio" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.opt" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.datatransfer" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.accessibility" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.hotspot.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.security.auth" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.security.jgss" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.security.jgss" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.security.sasl" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.ci" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management.jfr" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.management.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.transaction.xa" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.crypto.cryptoki" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.incubator.vector" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.jvmstat" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.incubator.foreign" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.unsupported.desktop" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.compiler.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.se" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jfr" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.net" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.sql" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.xml" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jcmd" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.sctp" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.base" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdeps" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jlink" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.zipfs" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.prefs" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.attach" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jshell" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jstatd" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.random" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.naming" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.editpad" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jartool" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.javadoc" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.xml.dom" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.desktop" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.logging" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.charsets" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.dynalink" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jconsole" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jpackage" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jsobject" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.net.http" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.crypto.ec" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.scripting" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.httpserver" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdwp.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.localedata" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.naming.dns" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.naming.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.instrument" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.sql.rowset" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.xml.crypto" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.ed" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.le" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.nio.mapmode" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.unsupported" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.smartcardio" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.opt" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.datatransfer" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.accessibility" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.hotspot.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.security.auth" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.security.jgss" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.security.jgss" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.security.sasl" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.ci" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management.jfr" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.management.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.transaction.xa" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.crypto.cryptoki" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.incubator.vector" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.jvmstat" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.incubator.foreign" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.unsupported.desktop" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.compiler.management" type="simple" />
           </root>
         </sourcePath>
       </roots>
diff --git a/aidegen/test_data/jdk_table_xml/jdk_nonexistent.xml b/aidegen/test_data/jdk_table_xml/jdk_nonexistent.xml
index a85094ac..300c2d37 100644
--- a/aidegen/test_data/jdk_table_xml/jdk_nonexistent.xml
+++ b/aidegen/test_data/jdk_table_xml/jdk_nonexistent.xml
@@ -5,10 +5,10 @@
       <type value="JavaSDK" />
     </jdk>
     <jdk version="2">
-      <name value="JDK17" />
+      <name value="JDK21" />
       <type value="JavaSDK" />
       <version value="java version &quot;17.0.4&quot;" />
-      <homePath value="/path/to/android/root/prebuilts/jdk/jdk17/linux-x86" />
+      <homePath value="/path/to/android/root/prebuilts/jdk/jdk21/linux-x86" />
       <roots>
         <annotationsPath>
           <root type="composite">
@@ -17,76 +17,76 @@
         </annotationsPath>
         <classPath>
           <root type="composite">
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.base" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.datatransfer" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.desktop" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.instrument" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.logging" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.management.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.naming" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.net.http" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.prefs" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.scripting" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.se" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.security.jgss" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.security.sasl" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.smartcardio" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.sql" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.sql.rowset" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.transaction.xa" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.xml" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/java.xml.crypto" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.accessibility" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.attach" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.charsets" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.crypto.cryptoki" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.crypto.ec" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.dynalink" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.editpad" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.hotspot.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.httpserver" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.incubator.foreign" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.incubator.vector" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.ed" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.jvmstat" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.le" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.opt" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.ci" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.compiler" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.internal.vm.compiler.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jartool" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.javadoc" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jcmd" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jconsole" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdeps" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jdwp.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jfr" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jlink" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jpackage" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jshell" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jsobject" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.jstatd" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.localedata" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management.agent" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.management.jfr" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.naming.dns" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.naming.rmi" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.net" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.nio.mapmode" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.random" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.sctp" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.security.auth" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.security.jgss" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.unsupported" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.unsupported.desktop" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.xml.dom" type="simple" />
-            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86!/jdk.zipfs" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.base" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.datatransfer" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.desktop" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.instrument" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.logging" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.management.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.naming" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.net.http" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.prefs" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.scripting" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.se" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.security.jgss" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.security.sasl" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.smartcardio" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.sql" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.sql.rowset" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.transaction.xa" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.xml" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/java.xml.crypto" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.accessibility" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.attach" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.charsets" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.crypto.cryptoki" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.crypto.ec" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.dynalink" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.editpad" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.hotspot.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.httpserver" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.incubator.foreign" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.incubator.vector" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.ed" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.jvmstat" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.le" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.opt" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.ci" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.compiler" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.internal.vm.compiler.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jartool" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.javadoc" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jcmd" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jconsole" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdeps" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jdwp.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jfr" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jlink" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jpackage" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jshell" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jsobject" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.jstatd" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.localedata" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management.agent" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.management.jfr" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.naming.dns" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.naming.rmi" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.net" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.nio.mapmode" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.random" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.sctp" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.security.auth" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.security.jgss" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.unsupported" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.unsupported.desktop" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.xml.dom" type="simple" />
+            <root url="jrt:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86!/jdk.zipfs" type="simple" />
           </root>
         </classPath>
         <javadocPath>
@@ -94,76 +94,76 @@
         </javadocPath>
         <sourcePath>
           <root type="composite">
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.se" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jfr" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.net" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.sql" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.xml" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jcmd" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.sctp" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.base" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdeps" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jlink" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.zipfs" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.prefs" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.attach" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jshell" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jstatd" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.random" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.naming" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.editpad" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jartool" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.javadoc" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.xml.dom" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.desktop" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.logging" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.charsets" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.dynalink" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jconsole" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jpackage" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jsobject" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.net.http" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.crypto.ec" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.scripting" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.httpserver" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.jdwp.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.localedata" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.naming.dns" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.naming.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.instrument" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.management" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.sql.rowset" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.xml.crypto" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.ed" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.le" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.nio.mapmode" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.unsupported" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.smartcardio" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.opt" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.datatransfer" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.accessibility" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.hotspot.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.security.auth" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.security.jgss" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.security.jgss" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.security.sasl" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.ci" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management.jfr" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.management.rmi" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/java.transaction.xa" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.crypto.cryptoki" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.incubator.vector" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.jvmstat" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.management.agent" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.incubator.foreign" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.unsupported.desktop" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.compiler" type="simple" />
-            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk17/linux-x86/lib/src.zip!/jdk.internal.vm.compiler.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.se" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jfr" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.net" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.sql" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.xml" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jcmd" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.sctp" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.base" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdeps" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jlink" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.zipfs" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.prefs" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.attach" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jshell" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jstatd" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.random" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.naming" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.editpad" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jartool" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.javadoc" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.xml.dom" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.desktop" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.logging" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.charsets" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.dynalink" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jconsole" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jpackage" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jsobject" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.net.http" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.crypto.ec" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.scripting" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.httpserver" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.jdwp.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.localedata" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.naming.dns" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.naming.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.instrument" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.management" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.sql.rowset" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.xml.crypto" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.ed" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.le" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.nio.mapmode" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.unsupported" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.smartcardio" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.opt" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.datatransfer" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.accessibility" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.hotspot.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.security.auth" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.security.jgss" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.security.jgss" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.security.sasl" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.ci" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management.jfr" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.management.rmi" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/java.transaction.xa" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.crypto.cryptoki" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.incubator.vector" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.jvmstat" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.management.agent" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.incubator.foreign" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.unsupported.desktop" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.compiler" type="simple" />
+            <root url="jar:///path/to/android/root/prebuilts/jdk/jdk21/linux-x86/lib/src.zip!/jdk.internal.vm.compiler.management" type="simple" />
           </root>
         </sourcePath>
       </roots>
diff --git a/atest/arg_parser.py b/atest/arg_parser.py
index c698f58c..ee9a209d 100644
--- a/atest/arg_parser.py
+++ b/atest/arg_parser.py
@@ -144,7 +144,13 @@ def create_atest_arg_parser():
       '-d',
       '--disable-teardown',
       action='store_true',
-      help='Disable test teardown and cleanup.',
+      help=(
+          'Disable teardown phase implemented using TradeFed interfaces. Note'
+          " if a test contains teardown logic without implementing TradeFed's"
+          ' teardown interface methods or puts its cleanup steps within the'
+          " test phase then setting this flag won't prevent those cleanup steps"
+          ' from being executed.'
+      ),
   )
 
   parser.add_argument(
@@ -432,9 +438,10 @@ def create_atest_arg_parser():
       # TODO(b/326141263): TradeFed to support wildcard in include-filter for
       # parametrized JarHostTests
       help=(
-          'Run only the tests which are specified with this option. '
-          'Filtering by method and with wildcard is not yet supported for '
-          'all test types.'
+          'Run only the tests which are specified with this option. This value'
+          ' is passed directly to the testing framework so you should use'
+          " appropriate syntax (e.g. JUnit supports regex, while python's"
+          ' unittest supports fnmatch syntax).'
       ),
   )
   parser.add_argument(
diff --git a/atest/asuite_lib_test/Android.bp b/atest/asuite_lib_test/Android.bp
index 7f0a7cbd..633d9a9d 100644
--- a/atest/asuite_lib_test/Android.bp
+++ b/atest/asuite_lib_test/Android.bp
@@ -27,7 +27,6 @@ python_test_host {
     pkg_path: "asuite_test",
     srcs: [
         "asuite_lib_run_tests.py",
-        "asuite_cc_client_test.py",
     ],
     libs: [
         "asuite_cc_client",
diff --git a/atest/asuite_lib_test/asuite_cc_client_test.py b/atest/asuite_lib_test/asuite_cc_client_test.py
deleted file mode 100644
index e57a3726..00000000
--- a/atest/asuite_lib_test/asuite_cc_client_test.py
+++ /dev/null
@@ -1,48 +0,0 @@
-#!/usr/bin/env python3
-#
-# Copyright 2019, The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-
-"""Unittest for atest_execution_info."""
-
-import unittest
-
-
-class AsuiteCCLibTest(unittest.TestCase):
-  """Tests for verify asuite_metrics libs"""
-
-  def test_import_asuite_cc_lib(self):
-    """Test asuite_cc_lib."""
-    # pylint: disable=unused-variable
-    # pylint: disable=import-outside-toplevel
-    # pylint: disable=unused-import
-    from atest.metrics import metrics
-    from atest.metrics import metrics_base
-    from atest.metrics import metrics_utils
-
-    # TODO (b/132602907): Add the real usage for checking if metrics pass or
-    #  fail.
-    metrics_base.MetricsBase.tool_name = 'MyTestTool'
-    metrics_utils.get_start_time()
-    metrics.AtestStartEvent(
-        command_line='test_command',
-        test_references='test_reference',
-        cwd='test_cwd',
-        os='test_os',
-    )
-
-
-if __name__ == '__main__':
-  unittest.main()
diff --git a/atest/atest_enum.py b/atest/atest_enum.py
index 82493931..33b98613 100644
--- a/atest/atest_enum.py
+++ b/atest/atest_enum.py
@@ -105,6 +105,18 @@ class DetectType(IntEnum):
   ROBOLEAF_NON_MODULE_FINDER = 57  # Deprecated.
   ROBOLEAF_UNSUPPORTED_FLAG = 58  # Deprecated.
   INDEX_TARGETS_MS = 59
+  # An int representing the negotiated speed (in Mbits per seconds) the
+  # device is operating at.
+  USB_NEGOTIATED_SPEED = 60
+  # An int representing the maximum speed (in Mbits per seconds) of which the
+  # device is capable.
+  USB_MAX_SPEED = 61
+  # Time spent on waiting indexing to complete.
+  WAIT_FOR_INDEXING_MS = 62
+  # Whether procate db is locked. Value 1 means True, otherwise is False.
+  IS_PLOCATEDB_LOCKED = 63
+  # Device update duration
+  DEVICE_UPDATE_MS = 64
 
 
 @unique
diff --git a/atest/atest_execution_info.py b/atest/atest_execution_info.py
index 8b19d870..5012c23c 100644
--- a/atest/atest_execution_info.py
+++ b/atest/atest_execution_info.py
@@ -23,15 +23,18 @@ import json
 import logging
 import os
 import pathlib
+import shutil
 import sys
+import time
 from typing import List
 
-from atest import atest_utils as au
+from atest import atest_enum
 from atest import atest_utils
 from atest import constants
-from atest import feedback
+from atest import usb_speed_detect as usb
 from atest.atest_enum import ExitCode
 from atest.logstorage import log_uploader
+from atest.metrics import metrics
 from atest.metrics import metrics_utils
 
 _ARGS_KEY = 'args'
@@ -130,7 +133,7 @@ def print_test_result(root, history_arg):
     )
   for path in paths[0 : int(history_arg) + 1]:
     result_path = os.path.join(path, 'test_result')
-    result = au.load_json_safely(result_path)
+    result = atest_utils.load_json_safely(result_path)
     total_summary = result.get(_TOTAL_SUMMARY_KEY, {})
     summary_str = ', '.join(
         [k[:1] + ':' + str(v) for k, v in total_summary.items()]
@@ -169,27 +172,27 @@ def print_test_result_by_path(path):
   Args:
       path: A string of test result path.
   """
-  result = au.load_json_safely(path)
+  result = atest_utils.load_json_safely(path)
   if not result:
     return
   print('\natest {}'.format(result.get(_ARGS_KEY, '')))
   test_result_url = result.get(_TEST_RESULT_LINK, '')
   if test_result_url:
     print('\nTest Result Link: {}'.format(test_result_url))
-  print('\nTotal Summary:\n{}'.format(au.delimiter('-')))
+  print('\nTotal Summary:\n{}'.format(atest_utils.delimiter('-')))
   total_summary = result.get(_TOTAL_SUMMARY_KEY, {})
   print(', '.join([(k + ':' + str(v)) for k, v in total_summary.items()]))
   fail_num = total_summary.get(_STATUS_FAILED_KEY)
   if fail_num > 0:
     message = '%d test failed' % fail_num
-    print(f'\n{au.mark_red(message)}\n{"-" * len(message)}')
+    print(f'\n{atest_utils.mark_red(message)}\n{"-" * len(message)}')
     test_runner = result.get(_TEST_RUNNER_KEY, {})
     for runner_name in test_runner.keys():
       test_dict = test_runner.get(runner_name, {})
       for test_name in test_dict:
         test_details = test_dict.get(test_name, {})
         for fail in test_details.get(_STATUS_FAILED_KEY):
-          print(au.mark_red(f'{fail.get(_TEST_NAME_KEY)}'))
+          print(atest_utils.mark_red(f'{fail.get(_TEST_NAME_KEY)}'))
           failure_files = glob.glob(
               _LOGCAT_FMT.format(
                   os.path.dirname(path), fail.get(_TEST_NAME_KEY)
@@ -198,12 +201,14 @@ def print_test_result_by_path(path):
           if failure_files:
             print(
                 '{} {}'.format(
-                    au.mark_cyan('LOGCAT-ON-FAILURES:'), failure_files[0]
+                    atest_utils.mark_cyan('LOGCAT-ON-FAILURES:'),
+                    failure_files[0],
                 )
             )
           print(
               '{} {}'.format(
-                  au.mark_cyan('STACKTRACE:\n'), fail.get(_TEST_DETAILS_KEY)
+                  atest_utils.mark_cyan('STACKTRACE:\n'),
+                  fail.get(_TEST_DETAILS_KEY),
               )
           )
 
@@ -235,7 +240,7 @@ def has_url_results():
       if file != 'test_result':
         continue
       json_file = os.path.join(root, 'test_result')
-      result = au.load_json_safely(json_file)
+      result = atest_utils.load_json_safely(json_file)
       url_link = result.get(_TEST_RESULT_LINK, '')
       if url_link:
         return True
@@ -282,7 +287,12 @@ class AtestExecutionInfo:
   result_reporters = []
 
   def __init__(
-      self, args: List[str], work_dir: str, args_ns: argparse.ArgumentParser
+      self,
+      args: List[str],
+      work_dir: str,
+      args_ns: argparse.ArgumentParser,
+      start_time: float = None,
+      repo_out_dir: pathlib.Path = None,
   ):
     """Initialise an AtestExecutionInfo instance.
 
@@ -290,6 +300,8 @@ class AtestExecutionInfo:
         args: Command line parameters.
         work_dir: The directory for saving information.
         args_ns: An argparse.ArgumentParser class instance holding parsed args.
+        start_time: The execution start time. Can be None.
+        repo_out_dir: The repo output directory. Can be None.
 
     Returns:
            A json format string.
@@ -305,6 +317,12 @@ class AtestExecutionInfo:
         args,
         work_dir,
     )
+    self._start_time = start_time if start_time is not None else time.time()
+    self._repo_out_dir = (
+        repo_out_dir
+        if repo_out_dir is not None
+        else atest_utils.get_build_out_dir()
+    )
 
   def __enter__(self):
     """Create and return information file object."""
@@ -316,13 +334,31 @@ class AtestExecutionInfo:
 
   def __exit__(self, exit_type, value, traceback):
     """Write execution information and close information file."""
+
+    # Read the USB speed and send usb metrics.
+    device_proto = usb.get_device_proto_binary()
+    usb.verify_and_print_usb_speed_warning(device_proto)
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.USB_NEGOTIATED_SPEED,
+        result=device_proto.negotiated_speed
+        if device_proto.negotiated_speed
+        else 0,
+    )
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.USB_MAX_SPEED,
+        result=device_proto.max_speed if device_proto.max_speed else 0,
+    )
+
+    log_path = pathlib.Path(self.work_dir)
+    html_path = None
+
     if self.result_file_obj and not has_non_test_options(self.args_ns):
       self.result_file_obj.write(
           AtestExecutionInfo._generate_execution_detail(self.args)
       )
       self.result_file_obj.close()
-      au.prompt_suggestions(self.test_result)
-      au.generate_print_result_html(self.test_result)
+      atest_utils.prompt_suggestions(self.test_result)
+      html_path = atest_utils.generate_result_html(self.test_result)
       symlink_latest_result(self.work_dir)
     main_module = sys.modules.get(_MAIN_MODULE_KEY)
     main_exit_code = (
@@ -330,6 +366,16 @@ class AtestExecutionInfo:
         if isinstance(value, SystemExit)
         else (getattr(main_module, _EXIT_CODE_ATTR, ExitCode.ERROR))
     )
+
+    print()
+    log_link = html_path if html_path else log_path
+    if log_link:
+      print(f'Logs: {atest_utils.mark_magenta(f"file://{log_link}")}')
+    bug_report_url = AtestExecutionInfo._create_bug_report_url()
+    if bug_report_url:
+      print(f'Issue report: {bug_report_url}')
+    print()
+
     # Do not send stacktrace with send_exit_event when exit code is not
     # ERROR.
     if main_exit_code != ExitCode.ERROR:
@@ -339,9 +385,35 @@ class AtestExecutionInfo:
       logging.debug('handle_exc_and_send_exit_event:%s', main_exit_code)
       metrics_utils.handle_exc_and_send_exit_event(main_exit_code)
 
+    AtestExecutionInfo._copy_build_trace_to_log_dir(
+        self._start_time, time.time(), self._repo_out_dir, log_path
+    )
     if log_uploader.is_uploading_logs():
-      log_uploader.upload_logs_detached(pathlib.Path(self.work_dir))
-    feedback.print_feedback_message()
+      log_uploader.upload_logs_detached(log_path)
+
+  @staticmethod
+  def _create_bug_report_url() -> str:
+    if not metrics.is_internal_user():
+      return ''
+    if not log_uploader.is_uploading_logs():
+      return 'http://go/new-atest-issue'
+    return f'http://go/from-atest-runid/{metrics.get_run_id()}'
+
+  @staticmethod
+  def _copy_build_trace_to_log_dir(
+      start_time: float,
+      end_time: float,
+      repo_out_path: pathlib.Path,
+      log_path: pathlib.Path,
+  ):
+
+    for file in repo_out_path.iterdir():
+      if (
+          file.is_file()
+          and file.name.startswith('build.trace')
+          and start_time <= file.stat().st_mtime <= end_time
+      ):
+        shutil.copy(file, log_path)
 
   @staticmethod
   def _generate_execution_detail(args):
diff --git a/atest/atest_execution_info_unittest.py b/atest/atest_execution_info_unittest.py
index 532c7c6d..3c176f31 100755
--- a/atest/atest_execution_info_unittest.py
+++ b/atest/atest_execution_info_unittest.py
@@ -17,12 +17,18 @@
 """Unittest for atest_execution_info."""
 
 
+import os
+import pathlib
 import time
 import unittest
-
+from unittest.mock import patch
+from atest import arg_parser
 from atest import atest_execution_info as aei
+from atest import constants
 from atest import result_reporter
+from atest.metrics import metrics
 from atest.test_runners import test_runner_base
+from pyfakefs import fake_filesystem_unittest
 
 RESULT_TEST_TEMPLATE = test_runner_base.TestResult(
     runner_name='someRunner',
@@ -39,10 +45,119 @@ RESULT_TEST_TEMPLATE = test_runner_base.TestResult(
 )
 
 
+class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+    self.fs.create_dir(constants.ATEST_RESULT_ROOT)
+
+  def test_copy_build_trace_to_log_dir_new_trace_copy(self):
+    start_time = 10
+    log_path = pathlib.Path('/logs')
+    self.fs.create_dir(log_path)
+    out_path = pathlib.Path('/out')
+    build_trace_path = out_path / 'build.trace'
+    self.fs.create_file(build_trace_path)
+    # Set the trace file's mtime greater than start time
+    os.utime(build_trace_path, (20, 20))
+    end_time = 30
+
+    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
+        start_time, end_time, out_path, log_path
+    )
+
+    self.assertTrue(
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace')
+    )
+
+  def test_copy_build_trace_to_log_dir_old_trace_does_not_copy(self):
+    start_time = 10
+    log_path = pathlib.Path('/logs')
+    self.fs.create_dir(log_path)
+    out_path = pathlib.Path('/out')
+    build_trace_path = out_path / 'build.trace'
+    self.fs.create_file(build_trace_path)
+    # Set the trace file's mtime smaller than start time
+    os.utime(build_trace_path, (5, 5))
+    end_time = 30
+
+    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
+        start_time, end_time, out_path, log_path
+    )
+
+    self.assertFalse(
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace')
+    )
+
+  def test_copy_multiple_build_trace_to_log_dir(self):
+    start_time = 10
+    log_path = pathlib.Path('/logs')
+    self.fs.create_dir(log_path)
+    out_path = pathlib.Path('/out')
+    build_trace_path1 = out_path / 'build.trace.1'
+    build_trace_path2 = out_path / 'build.trace.2'
+    self.fs.create_file(build_trace_path1)
+    self.fs.create_file(build_trace_path2)
+    # Set the trace file's mtime greater than start time
+    os.utime(build_trace_path1, (20, 20))
+    os.utime(build_trace_path2, (20, 20))
+    end_time = 30
+
+    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
+        start_time, end_time, out_path, log_path
+    )
+
+    self.assertTrue(
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.1')
+    )
+    self.assertTrue(
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.2')
+    )
+
+  def _is_dir_contains_files_with_prefix(
+      self, dir: pathlib.Path, prefix: str
+  ) -> bool:
+    for file in dir.iterdir():
+      if file.is_file() and file.name.startswith(prefix):
+        return True
+    return False
+
+
 # pylint: disable=protected-access
-class AtestRunInfoUnittests(unittest.TestCase):
+class AtestExecutionInfoUnittests(unittest.TestCase):
   """Unit tests for atest_execution_info.py"""
 
+  @patch('atest.metrics.metrics.is_internal_user', return_value=False)
+  def test_create_bug_report_url_is_external_user_return_empty(self, _):
+    url = aei.AtestExecutionInfo._create_bug_report_url()
+
+    self.assertFalse(url)
+
+  @patch('atest.metrics.metrics.is_internal_user', return_value=True)
+  def test_create_bug_report_url_is_internal_user_return_url(self, _):
+    url = aei.AtestExecutionInfo._create_bug_report_url()
+
+    self.assertTrue(url)
+
+  @patch('atest.metrics.metrics.is_internal_user', return_value=True)
+  @patch('atest.logstorage.log_uploader.is_uploading_logs', return_value=True)
+  def test_create_bug_report_url_is_uploading_logs_use_contains_run_id(
+      self, _, __
+  ):
+    url = aei.AtestExecutionInfo._create_bug_report_url()
+
+    self.assertIn(metrics.get_run_id(), url)
+
+  @patch('atest.metrics.metrics.is_internal_user', return_value=True)
+  @patch('atest.logstorage.log_uploader.is_uploading_logs', return_value=False)
+  def test_create_bug_report_url_is_not_uploading_logs_use_contains_run_id(
+      self, _, __
+  ):
+    url = aei.AtestExecutionInfo._create_bug_report_url()
+
+    self.assertNotIn(metrics.get_run_id(), url)
+
   def test_arrange_test_result_one_module(self):
     """Test _arrange_test_result method with only one module."""
     pass_1 = self._create_test_result(status=test_runner_base.PASSED_STATUS)
diff --git a/atest/atest_main.py b/atest/atest_main.py
index 2eb59562..d98cda18 100755
--- a/atest/atest_main.py
+++ b/atest/atest_main.py
@@ -27,14 +27,16 @@ atest is designed to support any test types that can be ran by TradeFederation.
 from __future__ import annotations
 from __future__ import print_function
 
-from abc import ABC, abstractmethod
+import abc
 import argparse
 import collections
-from dataclasses import dataclass
+import dataclasses
+import functools
 import itertools
 import logging
 import os
 import platform
+import subprocess
 import sys
 import tempfile
 import time
@@ -53,7 +55,8 @@ from atest import device_update
 from atest import module_info
 from atest import result_reporter
 from atest import test_runner_handler
-from atest.atest_enum import DetectType, ExitCode
+from atest.atest_enum import DetectType
+from atest.atest_enum import ExitCode
 from atest.coverage import coverage
 from atest.metrics import metrics
 from atest.metrics import metrics_base
@@ -99,42 +102,13 @@ _RESULTS_DIR_PRINT_PREFIX = 'Atest results and logs directory: '
 _DRY_RUN_COMMAND_LOG_PREFIX = 'Internal run command from dry-run: '
 
 
-@dataclass
+@dataclasses.dataclass
 class Steps:
-  """A Dataclass that stores steps and shows step assignments."""
+  """A dataclass that stores enabled steps."""
 
-  _build: bool
-  _device_update: bool
-  _install: bool
-  _test: bool
-
-  def has_build(self):
-    """Return whether build is in steps."""
-    return self._build
-
-  def is_build_only(self):
-    """Return whether build is the only one in steps."""
-    return self._build and not any(
-        (self._test, self._install, self._device_update)
-    )
-
-  def has_device_update(self):
-    """Return whether device update is in steps."""
-    return self._device_update
-
-  def has_install(self):
-    """Return whether install is in steps."""
-    return self._install
-
-  def has_test(self):
-    """Return whether install is the only one in steps."""
-    return self._test
-
-  def is_test_only(self):
-    """Return whether build is not in steps but test."""
-    return self._test and not any(
-        (self._build, self._install, self._device_update)
-    )
+  build: bool
+  install: bool
+  test: bool
 
 
 def parse_steps(args: arg_parser.AtestArgParser) -> Steps:
@@ -148,7 +122,7 @@ def parse_steps(args: arg_parser.AtestArgParser) -> Steps:
   """
   # Implicitly running 'build', 'install' and 'test' when args.steps is None.
   if not args.steps:
-    return Steps(True, args.update_device, True, True)
+    return Steps(True, True, True)
   build = constants.BUILD_STEP in args.steps
   test = constants.TEST_STEP in args.steps
   install = constants.INSTALL_STEP in args.steps
@@ -158,7 +132,7 @@ def parse_steps(args: arg_parser.AtestArgParser) -> Steps:
         'supported; Atest will proceed testing!'
     )
     test = True
-  return Steps(build, args.update_device, install, test)
+  return Steps(build, install, test)
 
 
 def _get_args_from_config():
@@ -182,7 +156,7 @@ def _get_args_from_config():
   print(
       '\n{} {}'.format(
           atest_utils.mark_cyan('Reading config:'),
-          atest_utils.mark_yellow(_config),
+          _config,
       )
   )
   # pylint: disable=global-statement:
@@ -217,14 +191,14 @@ def _get_args_from_config():
   return args
 
 
-def _parse_args(argv: List[Any]) -> Tuple[argparse.ArgumentParser, List[str]]:
+def _parse_args(argv: List[str]) -> argparse.Namespace:
   """Parse command line arguments.
 
   Args:
       argv: A list of arguments.
 
   Returns:
-      A tuple of an argparse.ArgumentParser class instance holding parsed args
+      A Namespace holding parsed args
   """
   # Store everything after '--' in custom_args.
   pruned_argv = argv
@@ -309,7 +283,7 @@ def _missing_environment_variables():
   return missing
 
 
-def make_test_run_dir():
+def make_test_run_dir() -> str:
   """Make the test run dir in ATEST_RESULT_ROOT.
 
   Returns:
@@ -337,7 +311,7 @@ def get_extra_args(args):
   extra_args = {}
   if args.wait_for_debugger:
     extra_args[constants.WAIT_FOR_DEBUGGER] = None
-  if not parse_steps(args).has_install():
+  if not parse_steps(args).install:
     extra_args[constants.DISABLE_INSTALL] = None
   # The key and its value of the dict can be called via:
   # if args.aaaa:
@@ -445,7 +419,7 @@ def _validate_adb_devices(args, test_infos):
       test_infos: TestInfo object.
   """
   # No need to check device availability if the user does not acquire to test.
-  if not parse_steps(args).has_test():
+  if not parse_steps(args).test:
     return
   if args.no_checking_device:
     return
@@ -532,48 +506,6 @@ def _has_valid_test_mapping_args(args):
   return True
 
 
-def _validate_args(args):
-  """Validate setups and args.
-
-  Exit the program with error code if any setup or arg is invalid.
-
-  Args:
-      args: parsed args object.
-  """
-  if _missing_environment_variables():
-    sys.exit(ExitCode.ENV_NOT_SETUP)
-  if not _has_valid_test_mapping_args(args):
-    sys.exit(ExitCode.INVALID_TM_ARGS)
-
-
-def _print_module_info_from_module_name(mod_info, module_name):
-  """print out the related module_info for a module_name.
-
-  Args:
-      mod_info: ModuleInfo object.
-      module_name: A string of module.
-
-  Returns:
-      True if the module_info is found.
-  """
-  title_mapping = collections.OrderedDict()
-  title_mapping[constants.MODULE_COMPATIBILITY_SUITES] = 'Compatibility suite'
-  title_mapping[constants.MODULE_PATH] = 'Source code path'
-  title_mapping[constants.MODULE_INSTALLED] = 'Installed path'
-  target_module_info = mod_info.get_module_info(module_name)
-  is_module_found = False
-  if target_module_info:
-    atest_utils.colorful_print(module_name, constants.GREEN)
-    for title_key in title_mapping:
-      atest_utils.colorful_print(
-          '\t%s' % title_mapping[title_key], constants.CYAN
-      )
-      for info_value in target_module_info[title_key]:
-        print('\t\t{}'.format(info_value))
-    is_module_found = True
-  return is_module_found
-
-
 def _print_deprecation_warning(arg_to_deprecate: str):
   """For features that are up for deprecation in the near future, print a message
 
@@ -627,156 +559,6 @@ def _split_test_mapping_tests(test_infos):
   return device_test_infos, host_test_infos
 
 
-# pylint: disable=too-many-locals
-def _run_test_mapping_tests(
-    test_type_to_invocations: Dict[str, List[TestRunnerInvocation]],
-    extra_args: Dict[str, Any],
-) -> ExitCode:
-  """Run all tests in TEST_MAPPING files.
-
-  Args:
-      test_type_to_invocations: A dict mapping test runner invocations to test
-        types.
-      extra_args: A dict of extra args for others to utilize.
-
-  Returns:
-      Exit code.
-  """
-
-  test_results = []
-  for test_type, invocations in test_type_to_invocations.items():
-    tests = list(
-        itertools.chain.from_iterable(i.test_infos for i in invocations)
-    )
-    if not tests:
-      continue
-    header = RUN_HEADER_FMT % {TEST_COUNT: len(tests), TEST_TYPE: test_type}
-    atest_utils.colorful_print(header, constants.MAGENTA)
-    logging.debug('\n'.join([str(info) for info in tests]))
-
-    reporter = result_reporter.ResultReporter(
-        collect_only=extra_args.get(constants.COLLECT_TESTS_ONLY),
-        wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
-    )
-    reporter.print_starting_text()
-
-    tests_exit_code = ExitCode.SUCCESS
-    for invocation in invocations:
-      tests_exit_code |= invocation.run_all_tests(reporter)
-
-    atest_execution_info.AtestExecutionInfo.result_reporters.append(reporter)
-    test_results.append((tests_exit_code, reporter, test_type))
-
-  all_tests_exit_code = ExitCode.SUCCESS
-  failed_tests = []
-  for tests_exit_code, reporter, test_type in test_results:
-    atest_utils.colorful_print(
-        RESULT_HEADER_FMT % {TEST_TYPE: test_type}, constants.MAGENTA
-    )
-    result = tests_exit_code | reporter.print_summary()
-    if result:
-      failed_tests.append(test_type)
-    all_tests_exit_code |= result
-
-  # List failed tests at the end as a reminder.
-  if failed_tests:
-    atest_utils.colorful_print(
-        atest_utils.delimiter('=', 30, prenl=1), constants.YELLOW
-    )
-    atest_utils.colorful_print('\nFollowing tests failed:', constants.MAGENTA)
-    for failure in failed_tests:
-      atest_utils.colorful_print(failure, constants.RED)
-
-  return all_tests_exit_code
-
-
-def _dry_run(results_dir, extra_args, test_infos, mod_info):
-  """Only print the commands of the target tests rather than running them in
-
-  actual.
-
-  Args:
-      results_dir: Path for saving atest logs.
-      extra_args: Dict of extra args for test runners to utilize.
-      test_infos: A list of TestInfos.
-      mod_info: ModuleInfo object.
-
-  Returns:
-      A successful exit code.
-  """
-  all_run_cmds = []
-  for test_runner, tests in test_runner_handler.group_tests_by_test_runners(
-      test_infos
-  ):
-    runner = test_runner(results_dir, mod_info=mod_info, extra_args=extra_args)
-    run_cmds = runner.generate_run_commands(tests, extra_args)
-    for run_cmd in run_cmds:
-      all_run_cmds.append(run_cmd)
-      logging.debug(_DRY_RUN_COMMAND_LOG_PREFIX + run_cmd)
-      print(
-          'Would run test via command: %s' % (atest_utils.mark_green(run_cmd))
-      )
-  return ExitCode.SUCCESS
-
-
-def _print_testable_modules(mod_info, suite):
-  """Print the testable modules for a given suite.
-
-  Args:
-      mod_info: ModuleInfo object.
-      suite: A string of suite name.
-  """
-  testable_modules = mod_info.get_testable_modules(suite)
-  print(
-      '\n%s'
-      % atest_utils.mark_cyan(
-          '%s Testable %s modules' % (len(testable_modules), suite)
-      )
-  )
-  print(atest_utils.delimiter('-'))
-  for module in sorted(testable_modules):
-    print('\t%s' % module)
-
-
-def _is_inside_android_root():
-  """Identify whether the cwd is inside of Android source tree.
-
-  Returns:
-      False if the cwd is outside of the source tree, True otherwise.
-  """
-  build_top = os.getenv(constants.ANDROID_BUILD_TOP, ' ')
-  return build_top in os.getcwd()
-
-
-def _non_action_validator(args: argparse.ArgumentParser):
-  """Method for non-action arguments such as --version, --history,
-
-  --latest_result, etc.
-
-  Args:
-      args: An argparse.ArgumentParser object.
-  """
-  if not _is_inside_android_root():
-    atest_utils.colorful_print(
-        '\nAtest must always work under ${}!'.format(
-            constants.ANDROID_BUILD_TOP
-        ),
-        constants.RED,
-    )
-    sys.exit(ExitCode.OUTSIDE_ROOT)
-  if args.version:
-    print(atest_utils.get_atest_version())
-    sys.exit(ExitCode.SUCCESS)
-  if args.history:
-    atest_execution_info.print_test_result(
-        constants.ATEST_RESULT_ROOT, args.history
-    )
-    sys.exit(ExitCode.SUCCESS)
-  if args.latest_result:
-    atest_execution_info.print_test_result_by_path(constants.LATEST_RESULT_FILE)
-    sys.exit(ExitCode.SUCCESS)
-
-
 def _exclude_modules_in_targets(build_targets):
   """Method that excludes MODULES-IN-* targets.
 
@@ -797,97 +579,6 @@ def _exclude_modules_in_targets(build_targets):
   return shrank_build_targets
 
 
-# pylint: disable=protected-access
-def need_rebuild_module_info(args: arg_parser.AtestArgParser) -> bool:
-  """Method that tells whether we need to rebuild module-info.json or not.
-
-  Args:
-      args: an AtestArgParser object.
-
-  Returns:
-      True for forcely/smartly rebuild, otherwise False without rebuilding.
-  """
-  # +-----------------+
-  # | Explicitly pass |  yes
-  # |    '--test'     +-------> False (won't rebuild)
-  # +--------+--------+
-  #          | no
-  #          V
-  # +-------------------------+
-  # | Explicitly pass         |  yes
-  # | '--rebuild-module-info' +-------> True (forcely rebuild)
-  # +--------+----------------+
-  #          | no
-  #          V
-  # +-------------------+
-  # |    Build files    |  no
-  # | integrity is good +-------> True (smartly rebuild)
-  # +--------+----------+
-  #          | yes
-  #          V
-  #        False (won't rebuild)
-  if not parse_steps(args).has_build():
-    logging.debug('"--test" mode detected, will not rebuild module-info.')
-    return False
-  if args.rebuild_module_info:
-    msg = (
-        f'`{constants.REBUILD_MODULE_INFO_FLAG}` is no longer needed '
-        f'since Atest can smartly rebuild {module_info._MODULE_INFO} '
-        r'only when needed.'
-    )
-    atest_utils.colorful_print(msg, constants.YELLOW)
-    return True
-  logging.debug('Examinating the consistency of build files...')
-  if not atest_utils.build_files_integrity_is_ok():
-    logging.debug('Found build files were changed.')
-    return True
-  return False
-
-
-def need_run_index_targets(args: argparse.ArgumentParser):
-  """Method that determines whether Atest need to run index_targets or not.
-
-  The decision flow is as follows: If no build is required, returns False.
-  Otherwise, if some index files are missing, returns True. Otherwise, if
-  some arguments that doesn't require indexing is present, returns False.
-  Otherwise, returns True.
-
-  Args:
-      args: An argparse.ArgumentParser object.
-
-  Returns:
-      True when none of the above conditions were found.
-  """
-  has_build_step = parse_steps(args).has_build()
-  if not has_build_step:
-    logging.debug("Skip indexing because there's no build required.")
-    return False
-
-  if not indexing.Indices().has_all_indices():
-    logging.debug(
-        'Indexing targets is required because some index files do not exist.'
-    )
-    return True
-
-  no_indexing_args = (
-      args.dry_run,
-      args.list_modules,
-  )
-  if any(no_indexing_args):
-    logging.debug('Skip indexing for no_indexing_args=%s.', no_indexing_args)
-    return False
-
-  return True
-
-
-def set_build_output_mode(mode: atest_utils.BuildOutputMode):
-  """Update environment variable dict accordingly to args.build_output."""
-  # Changing this variable does not retrigger builds.
-  atest_utils.update_build_env(
-      {'ANDROID_QUIET_BUILD': 'true', 'BUILD_OUTPUT_MODE': mode.value}
-  )
-
-
 def get_device_count_config(test_infos, mod_info):
   """Get the amount of desired devices from the test config.
 
@@ -908,31 +599,6 @@ def get_device_count_config(test_infos, mod_info):
   return max_count
 
 
-def _send_start_event(argv: List[Any], tests: List[str]):
-  """Send AtestStartEvent to metrics"""
-  os_pyver = (
-      f'{platform.platform()}:{platform.python_version()}/'
-      f'{atest_utils.get_manifest_branch(True)}:'
-      f'{atest_utils.get_atest_version()}'
-  )
-  metrics.AtestStartEvent(
-      command_line=' '.join(argv),
-      test_references=tests,
-      cwd=os.getcwd(),
-      os=os_pyver,
-  )
-
-
-def _get_acloud_proc_and_log(
-    args: argparse.ArgumentParser, results_dir: str
-) -> Tuple[Any, Any]:
-  """Return tuple of acloud process ID and report file."""
-  if any((args.acloud_create, args.start_avd)):
-    logging.debug('Creating acloud or avd.')
-    return avd.acloud_create_validator(results_dir, args)
-  return None, None
-
-
 def has_set_sufficient_devices(
     required_amount: int, serial: List[str] = None
 ) -> bool:
@@ -971,294 +637,688 @@ def setup_metrics_tool_name(no_metrics: bool = False):
     )
 
 
-# pylint: disable=too-many-statements
-# pylint: disable=too-many-branches
-# pylint: disable=too-many-return-statements
-def _main(
-    argv: List[Any],
-    results_dir: str,
-    args: argparse.Namespace,
-    banner_printer: banner.BannerPrinter,
-):
-  """Entry point of atest script.
+class _AtestMain:
+  """Entry point of atest script."""
 
-  Args:
-      argv: A list of arguments.
-      results_dir: A directory which stores the ATest execution information.
-      args: An argparse.Namespace class instance holding parsed args.
-      banner_printer: A BannerPrinter object used to collect banners and print
-        banners at the end of this invocation.
+  def __init__(
+      self,
+      argv: list[str],
+  ):
+    """Initializes the _AtestMain object.
 
-  Returns:
-      Exit code.
-  """
-  _begin_time = time.time()
-  logging.debug(
-      'Running atest script with argv %s, results_dir %s, args %s.',
-      argv,
-      results_dir,
-      args,
-  )
+    Args:
+        argv: A list of command line arguments.
+    """
+    self._argv: list[str] = argv
+
+    self._banner_printer: banner.BannerPrinter = None
+    self._steps: Steps = None
+    self._results_dir: str = None
+    self._mod_info: module_info.ModuleInfo = None
+    self._test_infos: list[test_info.TestInfo] = None
+    self._test_execution_plan: _TestExecutionPlan = None
+
+    self._acloud_proc: subprocess.Popen = None
+    self._acloud_report_file: str = None
+    self._test_info_loading_duration: float = 0
+    self._build_duration: float = 0
+    self._module_info_rebuild_required: bool = False
+    self._is_out_clean_before_module_info_build: bool = False
+    self._invocation_begin_time: float = None
+
+  def run(self):
+    self._results_dir = make_test_run_dir()
+
+    if END_OF_OPTION in self._argv:
+      end_position = self._argv.index(END_OF_OPTION)
+      final_args = [
+          *self._argv[1:end_position],
+          *_get_args_from_config(),
+          *self._argv[end_position:],
+      ]
+    else:
+      final_args = [*self._argv[1:], *_get_args_from_config()]
+    if final_args != self._argv[1:]:
+      print(
+          'The actual cmd will be: \n\t{}\n'.format(
+              atest_utils.mark_cyan('atest ' + ' '.join(final_args))
+          )
+      )
+      metrics.LocalDetectEvent(detect_type=DetectType.ATEST_CONFIG, result=1)
+      if HAS_IGNORED_ARGS:
+        atest_utils.colorful_print(
+            'Please correct the config and try again.', constants.YELLOW
+        )
+        sys.exit(ExitCode.EXIT_BEFORE_MAIN)
+    else:
+      metrics.LocalDetectEvent(detect_type=DetectType.ATEST_CONFIG, result=0)
+
+    self._args = _parse_args(final_args)
+    atest_configs.GLOBAL_ARGS = self._args
+    _configure_logging(self._args.verbose, self._results_dir)
 
-  # Sets coverage environment variables.
-  if args.experimental_coverage:
-    atest_utils.update_build_env(coverage.build_env_vars())
-  set_build_output_mode(args.build_output)
+    logging.debug(
+        'Start of atest run. sys.argv: %s, final_args: %s',
+        self._argv,
+        final_args,
+    )
 
-  _validate_args(args)
-  metrics_utils.get_start_time()
-  _send_start_event(argv, args.tests)
-  _non_action_validator(args)
+    self._steps = parse_steps(self._args)
 
-  proc_acloud, report_file = _get_acloud_proc_and_log(args, results_dir)
-  is_clean = not os.path.exists(
-      os.environ.get(constants.ANDROID_PRODUCT_OUT, '')
-  )
+    self._banner_printer = banner.BannerPrinter.create()
+
+    with atest_execution_info.AtestExecutionInfo(
+        final_args, self._results_dir, atest_configs.GLOBAL_ARGS
+    ):
+      setup_metrics_tool_name(atest_configs.GLOBAL_ARGS.no_metrics)
+
+      logging.debug(
+          'Creating atest script with argv: %s\n  results_dir: %s\n  args: %s\n'
+          '  run id: %s',
+          self._argv,
+          self._results_dir,
+          self._args,
+          metrics.get_run_id(),
+      )
+      exit_code = self._run_all_steps()
+      detector = bug_detector.BugDetector(final_args, exit_code)
+      if exit_code not in EXIT_CODES_BEFORE_TEST:
+        metrics.LocalDetectEvent(
+            detect_type=DetectType.BUG_DETECTED, result=detector.caught_result
+        )
+
+    self._banner_printer.print()
+
+    sys.exit(exit_code)
+
+  def _check_no_action_argument(self) -> int:
+    """Method for non-action arguments such as --version, --history, --latest_result, etc.
+
+    Returns:
+        Exit code if no action. None otherwise.
+    """
+    if self._args.version:
+      print(atest_utils.get_atest_version())
+      return ExitCode.SUCCESS
+    if self._args.history:
+      atest_execution_info.print_test_result(
+          constants.ATEST_RESULT_ROOT, self._args.history
+      )
+      return ExitCode.SUCCESS
+    if self._args.latest_result:
+      atest_execution_info.print_test_result_by_path(
+          constants.LATEST_RESULT_FILE
+      )
+      return ExitCode.SUCCESS
+    return None
+
+  def _check_envs_and_args(self) -> int:
+    """Validate environment variables and args.
+
+    Returns:
+        Exit code if any setup or arg is invalid. None otherwise.
+    """
+    if (
+        not os.getenv(constants.ANDROID_BUILD_TOP, ' ') in os.getcwd()
+    ):  # Not under android root.
+      atest_utils.colorful_print(
+          '\nAtest must always work under ${}!'.format(
+              constants.ANDROID_BUILD_TOP
+          ),
+          constants.RED,
+      )
+      return ExitCode.OUTSIDE_ROOT
+    if _missing_environment_variables():
+      return ExitCode.ENV_NOT_SETUP
+    if not _has_valid_test_mapping_args(self._args):
+      return ExitCode.INVALID_TM_ARGS
+
+    # Checks whether ANDROID_SERIAL environment variable is set to an empty string.
+    if 'ANDROID_SERIAL' in os.environ and not os.environ['ANDROID_SERIAL']:
+      atest_utils.print_and_log_warning(
+          'Empty device serial detected in the ANDROID_SERIAL environment'
+          ' variable. This may causes unexpected behavior in TradeFed. If not'
+          ' targeting a specific device, consider unset the ANDROID_SERIAL'
+          ' environment variable. See b/330365573 for details.'
+      )
 
-  # Run Test Mapping or coverage by no-bazel-mode.
-  if atest_utils.is_test_mapping(args) or args.experimental_coverage:
-    logging.debug('Running test mapping or coverage, disabling bazel mode.')
-    atest_utils.colorful_print(
-        'Not running using bazel-mode.', constants.YELLOW
+    # Checks whether any empty serial strings exist in the argument array.
+    if self._args.serial and not all(self._args.serial):
+      atest_utils.print_and_log_warning(
+          'Empty device serial specified via command-line argument. This may'
+          ' cause unexpected behavior in TradeFed. If not targeting a specific'
+          ' device, consider remove the serial argument. See b/330365573 for'
+          ' details.'
+      )
+
+    return None
+
+  def _update_build_env(self):
+    """Updates build environment variables."""
+    # Sets coverage environment variables.
+    if self._args.experimental_coverage:
+      atest_utils.update_build_env(coverage.build_env_vars())
+
+    # Update environment variable dict accordingly to args.build_output
+    atest_utils.update_build_env({
+        'ANDROID_QUIET_BUILD': 'true',
+        'BUILD_OUTPUT_MODE': self._args.build_output.value,
+    })
+
+  def _start_acloud_if_requested(self) -> None:
+    if not self._args.acloud_create and not self._args.start_avd:
+      return
+    if not parse_steps(self._args).test:
+      print('acloud/avd is requested but ignored because no test is requested.')
+      return
+    print('Creating acloud/avd...')
+    self._acloud_proc, self._acloud_report_file = avd.acloud_create_validator(
+        self._results_dir, self._args
     )
-    args.bazel_mode = False
 
-  proc_idx = atest_utils.start_threading(lambda: print)
-  # Do not index targets while the users intend to dry-run tests.
-  if need_run_index_targets(args):
+  def _check_acloud_status(self) -> int:
+    """Checks acloud status if acloud is requested.
+
+    Returns:
+        acloud status code. None if no acloud requested.
+    """
+    if self._acloud_proc:
+      self._acloud_proc.join()
+      status = avd.probe_acloud_status(
+          self._acloud_report_file,
+          self._test_info_loading_duration + self._build_duration,
+      )
+      return status
+    return None
+
+  def _start_indexing_if_required(self) -> None:
+    """Starts indexing if required.
+
+    The decision flow is as follows: If no build is required, returns False.
+    Otherwise, if some index files are missing, returns True. Otherwise, if
+    some arguments that doesn't require indexing is present, returns False.
+    Otherwise, returns True.
+    """
+    self._indexing_proc = None
+    if not self._steps.build:
+      logging.debug("Skip indexing because there's no build required.")
+      return
+
+    if indexing.Indices().has_all_indices():
+      no_indexing_args = (
+          self._args.dry_run,
+          self._args.list_modules,
+      )
+      if any(no_indexing_args):
+        logging.debug(
+            'Skip indexing for no_indexing_args=%s.', no_indexing_args
+        )
+        return
+    else:
+      logging.debug(
+          'Indexing targets is required because some index files do not exist.'
+      )
+
     logging.debug('Starting to index targets in a background thread.')
-    proc_idx = atest_utils.start_threading(
+    self._indexing_proc = atest_utils.start_threading(
         indexing.index_targets,
         daemon=True,
     )
-  smart_rebuild = need_rebuild_module_info(args)
-  logging.debug('need_rebuild_module_info returned %s', smart_rebuild)
 
-  mod_info = module_info.load(
-      force_build=smart_rebuild,
-      sqlite_module_cache=args.sqlite_module_cache,
-  )
-  logging.debug('Obtained module info object: %s', mod_info)
-
-  translator = cli_translator.CLITranslator(
-      mod_info=mod_info,
-      print_cache_msg=not args.clear_cache,
-      bazel_mode_enabled=args.bazel_mode,
-      host=args.host,
-      bazel_mode_features=args.bazel_mode_features,
-  )
-  if args.list_modules:
-    _print_testable_modules(mod_info, args.list_modules)
+  def _check_indexing_status(self) -> None:
+    """Checks indexing status and wait for it to complete if necessary."""
+    if (
+        not self._indexing_proc
+        or not self._indexing_proc.is_alive()
+        or indexing.Indices().has_all_indices()
+    ):
+      return
+    start_wait_for_indexing = time.time()
+    print('Waiting for the module indexing to complete.')
+    self._indexing_proc.join()
+    metrics.LocalDetectEvent(
+        detect_type=DetectType.WAIT_FOR_INDEXING_MS,
+        result=int(round((time.time() - start_wait_for_indexing) * 1000)),
+    )
+
+  @functools.cache
+  def _get_device_update_method(self) -> device_update.AdeviceUpdateMethod:
+    """Creates a device update method."""
+    return device_update.AdeviceUpdateMethod(
+        targets=set(self._args.update_modules or [])
+    )
+
+  def _get_device_update_dependencies(self) -> set[str]:
+    """Gets device update dependencies.
+
+    Returns:
+        A set of dependencies for the device update method.
+    """
+    if not self._args.update_device:
+      return set()
+
+    if (
+        self._test_execution_plan
+        and not self._test_execution_plan.requires_device_update()
+    ):
+      return set()
+
+    return self._get_device_update_method().dependencies()
+
+  def _need_rebuild_module_info(self) -> bool:
+    """Method that tells whether we need to rebuild module-info.json or not.
+
+    Returns:
+        True for forcely/smartly rebuild, otherwise False without rebuilding.
+    """
+    # +-----------------+
+    # | Explicitly pass |  yes
+    # |    '--test'     +-------> False (won't rebuild)
+    # +--------+--------+
+    #          | no
+    #          V
+    # +-------------------------+
+    # | Explicitly pass         |  yes
+    # | '--rebuild-module-info' +-------> True (forcely rebuild)
+    # +--------+----------------+
+    #          | no
+    #          V
+    # +-------------------+
+    # |    Build files    |  no
+    # | integrity is good +-------> True (smartly rebuild)
+    # +--------+----------+
+    #          | yes
+    #          V
+    #        False (won't rebuild)
+    if not self._steps.build:
+      logging.debug('"--test" mode detected, will not rebuild module-info.')
+      return False
+    if self._args.rebuild_module_info:
+      msg = (
+          f'`{constants.REBUILD_MODULE_INFO_FLAG}` is no longer needed '
+          f'since Atest can smartly rebuild {module_info._MODULE_INFO} '
+          r'only when needed.'
+      )
+      atest_utils.colorful_print(msg, constants.YELLOW)
+      return True
+    logging.debug('Examinating the consistency of build files...')
+    if not atest_utils.build_files_integrity_is_ok():
+      logging.debug('Found build files were changed.')
+      return True
+    return False
+
+  def _load_module_info(self):
+    self._is_out_clean_before_module_info_build = not os.path.exists(
+        os.environ.get(constants.ANDROID_PRODUCT_OUT, '')
+    )
+    self._module_info_rebuild_required = self._need_rebuild_module_info()
+    logging.debug(
+        'need_rebuild_module_info returned %s',
+        self._module_info_rebuild_required,
+    )
+
+    self._mod_info = module_info.load(
+        force_build=self._module_info_rebuild_required,
+        sqlite_module_cache=self._args.sqlite_module_cache,
+    )
+    logging.debug('Obtained module info object: %s', self._mod_info)
+
+  def _load_test_info_and_execution_plan(self) -> int | None:
+    """Loads test info and execution plan.
+
+    Returns:
+        Exit code if anything went wrong. None otherwise.
+    """
+    self._start_indexing_if_required()
+    self._load_module_info()
+
+    translator = cli_translator.CLITranslator(
+        mod_info=self._mod_info,
+        print_cache_msg=not self._args.clear_cache,
+        bazel_mode_enabled=self._args.bazel_mode,
+        host=self._args.host,
+        bazel_mode_features=self._args.bazel_mode_features,
+    )
+
+    self._check_indexing_status()
+
+    find_start = time.time()
+    self._test_infos = translator.translate(self._args)
+
+    # Only check for sufficient devices if not dry run.
+    self._args.device_count_config = get_device_count_config(
+        self._test_infos, self._mod_info
+    )
+    if not self._args.dry_run and not has_set_sufficient_devices(
+        self._args.device_count_config, self._args.serial
+    ):
+      return ExitCode.INSUFFICIENT_DEVICES
+
+    self._test_info_loading_duration = time.time() - find_start
+    if not self._test_infos:
+      return ExitCode.TEST_NOT_FOUND
+
+    self._test_execution_plan = _TestExecutionPlan.create(
+        test_infos=self._test_infos,
+        results_dir=self._results_dir,
+        mod_info=self._mod_info,
+        args=self._args,
+    )
+
+    return None
+
+  def _handle_list_modules(self) -> int:
+    """Print the testable modules for a given suite.
+
+    Returns:
+        Exit code.
+    """
+    self._load_module_info()
+
+    testable_modules = self._mod_info.get_testable_modules(
+        self._args.list_modules
+    )
+    print(
+        '\n%s'
+        % atest_utils.mark_cyan(
+            '%s Testable %s modules'
+            % (len(testable_modules), self._args.list_modules)
+        )
+    )
+    print(atest_utils.delimiter('-'))
+    for module in sorted(testable_modules):
+      print('\t%s' % module)
+
     return ExitCode.SUCCESS
-  test_infos = set()
-  # (b/242567487) index_targets may finish after cli_translator; to
-  # mitigate the overhead, the main waits until it finished when no index
-  # files are available (e.g. fresh repo sync)
-  if proc_idx.is_alive() and not indexing.Indices().has_all_indices():
-    proc_idx.join()
-  find_start = time.time()
-  test_infos = translator.translate(args)
-
-  # Only check for sufficient devices if not dry run.
-  args.device_count_config = get_device_count_config(test_infos, mod_info)
-  if not args.dry_run and not has_set_sufficient_devices(
-      args.device_count_config, args.serial
-  ):
-    return ExitCode.INSUFFICIENT_DEVICES
-
-  find_duration = time.time() - find_start
-  if not test_infos:
-    return ExitCode.TEST_NOT_FOUND
-
-  test_execution_plan = _create_test_execution_plan(
-      test_infos=test_infos,
-      results_dir=results_dir,
-      mod_info=mod_info,
-      args=args,
-      dry_run=args.dry_run,
-  )
 
-  extra_args = test_execution_plan.extra_args
+  def _handle_dry_run(self) -> int:
+    """Only print the commands of the target tests rather than running them.
 
-  build_targets = test_execution_plan.required_build_targets()
+    Returns:
+        Exit code.
+    """
+    error_code = self._load_test_info_and_execution_plan()
+    if error_code is not None:
+      return error_code
 
-  # Remove MODULE-IN-* from build targets by default.
-  if not args.use_modules_in:
-    build_targets = _exclude_modules_in_targets(build_targets)
+    print(
+        'Would build the following targets: %s'
+        % (atest_utils.mark_green('%s' % self._get_build_targets()))
+    )
 
-  if args.dry_run:
-    return _dry_run(results_dir, extra_args, test_infos, mod_info)
+    all_run_cmds = []
+    for test_runner, tests in test_runner_handler.group_tests_by_test_runners(
+        self._test_infos
+    ):
+      runner = test_runner(
+          self._results_dir,
+          mod_info=self._mod_info,
+          extra_args=self._test_execution_plan.extra_args,
+      )
+      run_cmds = runner.generate_run_commands(
+          tests, self._test_execution_plan.extra_args
+      )
+      for run_cmd in run_cmds:
+        all_run_cmds.append(run_cmd)
+        logging.debug(_DRY_RUN_COMMAND_LOG_PREFIX + run_cmd)
+        print(
+            'Would run test via command: %s' % (atest_utils.mark_green(run_cmd))
+        )
 
-  steps = parse_steps(args)
-  device_update_method = _configure_update_method(
-      steps=steps,
-      plan=test_execution_plan,
-      update_modules=set(args.update_modules or []),
-      banner_printer=banner_printer,
-  )
+    return ExitCode.SUCCESS
+
+  def _update_device_if_requested(self) -> None:
+    """Runs the device update step."""
+    if not self._args.update_device:
+      if self._test_execution_plan.requires_device_update():
+        self._banner_printer.register(
+            'Tips: If your test requires device update, consider '
+            'http://go/atest-single-command to simplify your workflow!'
+        )
+      return
+    if not self._steps.test:
+      print(
+          'Device update requested but skipped due to running in build only'
+          ' mode.'
+      )
+      return
+
+    if not self._test_execution_plan.requires_device_update():
+      atest_utils.colorful_print(
+          '\nWarning: Device update ignored because it is not required by '
+          'tests in this invocation.',
+          constants.YELLOW,
+      )
+      return
+
+    device_update_start = time.time()
+    self._get_device_update_method().update(
+        self._test_execution_plan.extra_args.get(constants.SERIAL, [])
+    )
+    device_update_duration = time.time() - device_update_start
+    logging.debug('Updating device took %ss', device_update_duration)
+    metrics.LocalDetectEvent(
+        detect_type=DetectType.DEVICE_UPDATE_MS,
+        result=int(round(device_update_duration * 1000)),
+    )
 
-  if build_targets and steps.has_build():
-    if args.experimental_coverage:
+  def _get_build_targets(self) -> set[str]:
+    """Gets the build targets."""
+    build_targets = self._test_execution_plan.required_build_targets()
+
+    # Remove MODULE-IN-* from build targets by default.
+    if not self._args.use_modules_in:
+      build_targets = _exclude_modules_in_targets(build_targets)
+
+    if not build_targets:
+      return None
+
+    if self._args.experimental_coverage:
       build_targets.update(coverage.build_modules())
 
     # Add module-info.json target to the list of build targets to keep the
     # file up to date.
     build_targets.add(module_info.get_module_info_target())
 
-    build_targets |= device_update_method.dependencies()
+    build_targets |= self._get_device_update_dependencies()
+    return build_targets
+
+  def _run_build_step(self) -> int:
+    """Runs the build step.
+
+    Returns:
+        Exit code if failed. None otherwise.
+    """
+    build_targets = self._get_build_targets()
 
     # Add the -jx as a build target if user specify it.
-    if args.build_j:
-      build_targets.add(f'-j{args.build_j}')
+    if self._args.build_j:
+      build_targets.add(f'-j{self._args.build_j}')
 
     build_start = time.time()
     success = atest_utils.build(build_targets)
-    build_duration = time.time() - build_start
+    self._build_duration = time.time() - build_start
     metrics.BuildFinishEvent(
-        duration=metrics_utils.convert_duration(build_duration),
+        duration=metrics_utils.convert_duration(self._build_duration),
         success=success,
         targets=build_targets,
     )
     metrics.LocalDetectEvent(
         detect_type=DetectType.BUILD_TIME_PER_TARGET,
-        result=int(build_duration / len(build_targets)),
+        result=int(round(self._build_duration / len(build_targets))),
     )
     rebuild_module_info = DetectType.NOT_REBUILD_MODULE_INFO
-    if is_clean:
+    if self._is_out_clean_before_module_info_build:
       rebuild_module_info = DetectType.CLEAN_BUILD
-    elif args.rebuild_module_info:
+    elif self._args.rebuild_module_info:
       rebuild_module_info = DetectType.REBUILD_MODULE_INFO
-    elif smart_rebuild:
+    elif self._module_info_rebuild_required:
       rebuild_module_info = DetectType.SMART_REBUILD_MODULE_INFO
     metrics.LocalDetectEvent(
-        detect_type=rebuild_module_info, result=int(build_duration)
+        detect_type=rebuild_module_info, result=int(round(self._build_duration))
     )
     if not success:
       return ExitCode.BUILD_FAILURE
-    if proc_acloud:
-      proc_acloud.join()
-      status = avd.probe_acloud_status(
-          report_file, find_duration + build_duration
-      )
-      if status != 0:
-        return status
-    # After build step 'adb' command will be available, and stop forward to
-    # Tradefed if the tests require a device.
-    _validate_adb_devices(args, test_infos)
 
-  device_update_method.update(extra_args.get(constants.SERIAL, []))
+  def _run_test_step(self) -> int:
+    """Runs the test step.
 
-  tests_exit_code = ExitCode.SUCCESS
-  test_start = time.time()
-  if steps.has_test():
+    Returns:
+        Exit code.
+    """
+    # Stop calling Tradefed if the tests require a device.
+    _validate_adb_devices(self._args, self._test_infos)
+
+    test_start = time.time()
     # Only send duration to metrics when no --build.
-    if not steps.has_build():
-      _init_and_find = time.time() - _begin_time
+    if not self._steps.build:
+      _init_and_find = time.time() - self._invocation_begin_time
       logging.debug('Initiation and finding tests took %ss', _init_and_find)
       metrics.LocalDetectEvent(
           detect_type=DetectType.INIT_AND_FIND_MS,
-          result=int(_init_and_find * 1000),
+          result=int(round(_init_and_find * 1000)),
       )
 
-    tests_exit_code = test_execution_plan.execute()
+    tests_exit_code = self._test_execution_plan.execute()
 
-    if args.experimental_coverage:
+    if self._args.experimental_coverage:
       coverage.generate_coverage_report(
-          results_dir,
-          test_infos,
-          mod_info,
-          extra_args.get(constants.HOST, False),
-          args.code_under_test,
+          self._results_dir,
+          self._test_infos,
+          self._mod_info,
+          self._test_execution_plan.extra_args.get(constants.HOST, False),
+          self._args.code_under_test,
       )
 
-  metrics.RunTestsFinishEvent(
-      duration=metrics_utils.convert_duration(time.time() - test_start)
-  )
-  preparation_time = atest_execution_info.preparation_time(test_start)
-  if preparation_time:
-    # Send the preparation time only if it's set.
-    metrics.RunnerFinishEvent(
-        duration=metrics_utils.convert_duration(preparation_time),
-        success=True,
-        runner_name=constants.TF_PREPARATION,
-        test=[],
+    metrics.RunTestsFinishEvent(
+        duration=metrics_utils.convert_duration(time.time() - test_start)
+    )
+    preparation_time = atest_execution_info.preparation_time(test_start)
+    if preparation_time:
+      # Send the preparation time only if it's set.
+      metrics.RunnerFinishEvent(
+          duration=metrics_utils.convert_duration(preparation_time),
+          success=True,
+          runner_name=constants.TF_PREPARATION,
+          test=[],
+      )
+
+    return tests_exit_code
+
+  def _send_start_event(self) -> None:
+    metrics_utils.send_start_event(
+        command_line=' '.join(self._argv),
+        test_references=self._args.tests,
+        cwd=os.getcwd(),
+        operating_system=(
+            f'{platform.platform()}:{platform.python_version()}/'
+            f'{atest_utils.get_manifest_branch(True)}:'
+            f'{atest_utils.get_atest_version()}'
+        ),
+        source_root=os.environ.get('ANDROID_BUILD_TOP', ''),
+        hostname=platform.node(),
     )
-  if tests_exit_code != ExitCode.SUCCESS:
-    tests_exit_code = ExitCode.TEST_FAILURE
 
-  return tests_exit_code
+  def _disable_bazel_mode_if_unsupported(self) -> None:
+    if (
+        atest_utils.is_test_mapping(self._args)
+        or self._args.experimental_coverage
+    ):
+      logging.debug('Running test mapping or coverage, disabling bazel mode.')
+      atest_utils.colorful_print(
+          'Not running using bazel-mode.', constants.YELLOW
+      )
+      self._args.bazel_mode = False
 
+  def _run_all_steps(self) -> int:
+    """Executes the atest script.
 
-def _configure_update_method(
-    *,
-    steps: Steps,
-    plan: TestExecutionPlan,
-    update_modules: set[str],
-    banner_printer: banner.BannerPrinter,
-) -> device_update.DeviceUpdateMethod:
+    Returns:
+        Exit code.
+    """
+    self._invocation_begin_time = time.time()
 
-  requires_device_update = plan.requires_device_update()
+    self._update_build_env()
 
-  if not steps.has_device_update():
-    if requires_device_update:
-      banner_printer.register(
-          'Tips: If your test requires device update, consider '
-          'http://go/atest-single-command to simplify your workflow!'
-      )
-    return device_update.NoopUpdateMethod()
+    invalid_arg_exit_code = self._check_envs_and_args()
+    if invalid_arg_exit_code is not None:
+      sys.exit(invalid_arg_exit_code)
 
-  if not requires_device_update:
-    atest_utils.colorful_print(
-        '\nWarning: Device update ignored because it is not required by '
-        'tests in this invocation.',
-        constants.YELLOW,
-    )
-    return device_update.NoopUpdateMethod()
+    self._send_start_event()
 
-  return device_update.AdeviceUpdateMethod(targets=update_modules)
+    no_action_exit_code = self._check_no_action_argument()
+    if no_action_exit_code is not None:
+      sys.exit(no_action_exit_code)
 
+    if self._args.list_modules:
+      return self._handle_list_modules()
 
-def _create_test_execution_plan(
-    *,
-    test_infos: List[test_info.TestInfo],
-    results_dir: str,
-    mod_info: module_info.ModuleInfo,
-    args: argparse.Namespace,
-    dry_run: bool,
-) -> TestExecutionPlan:
-  """Creates a plan to execute the tests.
+    self._disable_bazel_mode_if_unsupported()
 
-  Args:
-      test_infos: A list of instances of TestInfo.
-      results_dir: A directory which stores the ATest execution information.
-      mod_info: An instance of ModuleInfo.
-      args: An argparse.Namespace instance holding parsed args.
-      dry_run: A boolean of whether this invocation is a dry run.
+    if self._args.dry_run:
+      return self._handle_dry_run()
 
-  Returns:
-      An instance of TestExecutionPlan.
-  """
+    self._start_acloud_if_requested()
+
+    error_code = self._load_test_info_and_execution_plan()
+    if error_code is not None:
+      return error_code
+
+    if self._steps.build:
+      error_code = self._run_build_step()
+      if error_code is not None:
+        return error_code
+
+    acloud_status = self._check_acloud_status()
+    if acloud_status:
+      return acloud_status
+
+    self._update_device_if_requested()
+
+    if self._steps.test and self._run_test_step() != ExitCode.SUCCESS:
+      return ExitCode.TEST_FAILURE
+
+    return ExitCode.SUCCESS
+
+
+class _TestExecutionPlan(abc.ABC):
+  """Represents how an Atest invocation's tests will execute."""
+
+  @staticmethod
+  def create(
+      *,
+      test_infos: List[test_info.TestInfo],
+      results_dir: str,
+      mod_info: module_info.ModuleInfo,
+      args: argparse.Namespace,
+  ) -> _TestExecutionPlan:
+    """Creates a plan to execute the tests.
+
+    Args:
+        test_infos: A list of instances of TestInfo.
+        results_dir: A directory which stores the ATest execution information.
+        mod_info: An instance of ModuleInfo.
+        args: An argparse.Namespace instance holding parsed args.
+
+    Returns:
+        An instance of _TestExecutionPlan.
+    """
+
+    if is_from_test_mapping(test_infos):
+      return _TestMappingExecutionPlan.create(
+          test_infos=test_infos,
+          results_dir=results_dir,
+          mod_info=mod_info,
+          args=args,
+      )
 
-  if is_from_test_mapping(test_infos):
-    return TestMappingExecutionPlan.create(
+    return _TestModuleExecutionPlan.create(
         test_infos=test_infos,
         results_dir=results_dir,
         mod_info=mod_info,
         args=args,
     )
 
-  return TestModuleExecutionPlan.create(
-      test_infos=test_infos,
-      results_dir=results_dir,
-      mod_info=mod_info,
-      args=args,
-      dry_run=dry_run,
-  )
-
-
-class TestExecutionPlan(ABC):
-  """Represents how an Atest invocation's tests will execute."""
-
   def __init__(
       self,
       *,
@@ -1270,20 +1330,20 @@ class TestExecutionPlan(ABC):
   def extra_args(self) -> Dict[str, Any]:
     return self._extra_args
 
-  @abstractmethod
+  @abc.abstractmethod
   def execute(self) -> ExitCode:
     """Executes all test runner invocations in this plan."""
 
-  @abstractmethod
+  @abc.abstractmethod
   def required_build_targets(self) -> Set[str]:
     """Returns the list of build targets required by this plan."""
 
-  @abstractmethod
+  @abc.abstractmethod
   def requires_device_update(self) -> bool:
     """Checks whether this plan requires device update."""
 
 
-class TestMappingExecutionPlan(TestExecutionPlan):
+class _TestMappingExecutionPlan(_TestExecutionPlan):
   """A plan to execute Test Mapping tests."""
 
   def __init__(
@@ -1302,8 +1362,8 @@ class TestMappingExecutionPlan(TestExecutionPlan):
       results_dir: str,
       mod_info: module_info.ModuleInfo,
       args: argparse.Namespace,
-  ) -> TestMappingExecutionPlan:
-    """Creates an instance of TestMappingExecutionPlan.
+  ) -> _TestMappingExecutionPlan:
+    """Creates an instance of _TestMappingExecutionPlan.
 
     Args:
         test_infos: A list of instances of TestInfo.
@@ -1312,7 +1372,7 @@ class TestMappingExecutionPlan(TestExecutionPlan):
         args: An argparse.Namespace instance holding parsed args.
 
     Returns:
-        An instance of TestMappingExecutionPlan.
+        An instance of _TestMappingExecutionPlan.
     """
 
     device_test_infos, host_test_infos = _split_test_mapping_tests(test_infos)
@@ -1368,14 +1428,17 @@ class TestMappingExecutionPlan(TestExecutionPlan):
           create_invocations(extra_args, device_test_infos)
       )
 
-    return TestMappingExecutionPlan(
+    return _TestMappingExecutionPlan(
         test_type_to_invocations=test_type_to_invocations,
         extra_args=extra_args,
     )
 
   def requires_device_update(self) -> bool:
-    return _requires_device_update(
-        [i for invs in self._test_type_to_invocations.values() for i in invs]
+    return any(
+        inv.requires_device_update()
+        for inv in itertools.chain.from_iterable(
+            self._test_type_to_invocations.values()
+        )
     )
 
   def required_build_targets(self) -> Set[str]:
@@ -1388,12 +1451,60 @@ class TestMappingExecutionPlan(TestExecutionPlan):
     return build_targets
 
   def execute(self) -> ExitCode:
-    return _run_test_mapping_tests(
-        self._test_type_to_invocations, self.extra_args
-    )
+    """Run all tests in TEST_MAPPING files.
+
+    Returns:
+        Exit code.
+    """
 
+    test_results = []
+    for test_type, invocations in self._test_type_to_invocations.items():
+      tests = list(
+          itertools.chain.from_iterable(i.test_infos for i in invocations)
+      )
+      if not tests:
+        continue
+      header = RUN_HEADER_FMT % {TEST_COUNT: len(tests), TEST_TYPE: test_type}
+      atest_utils.colorful_print(header, constants.MAGENTA)
+      logging.debug('\n'.join([str(info) for info in tests]))
+
+      reporter = result_reporter.ResultReporter(
+          collect_only=self._extra_args.get(constants.COLLECT_TESTS_ONLY),
+          wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
+      )
+      reporter.print_starting_text()
 
-class TestModuleExecutionPlan(TestExecutionPlan):
+      tests_exit_code = ExitCode.SUCCESS
+      for invocation in invocations:
+        tests_exit_code |= invocation.run_all_tests(reporter)
+
+      atest_execution_info.AtestExecutionInfo.result_reporters.append(reporter)
+      test_results.append((tests_exit_code, reporter, test_type))
+
+    all_tests_exit_code = ExitCode.SUCCESS
+    failed_tests = []
+    for tests_exit_code, reporter, test_type in test_results:
+      atest_utils.colorful_print(
+          RESULT_HEADER_FMT % {TEST_TYPE: test_type}, constants.MAGENTA
+      )
+      result = tests_exit_code | reporter.print_summary()
+      if result:
+        failed_tests.append(test_type)
+      all_tests_exit_code |= result
+
+    # List failed tests at the end as a reminder.
+    if failed_tests:
+      atest_utils.colorful_print(
+          atest_utils.delimiter('=', 30, prenl=1), constants.YELLOW
+      )
+      atest_utils.colorful_print('\nFollowing tests failed:', constants.MAGENTA)
+      for failure in failed_tests:
+        atest_utils.colorful_print(failure, constants.RED)
+
+    return all_tests_exit_code
+
+
+class _TestModuleExecutionPlan(_TestExecutionPlan):
   """A plan to execute the test modules explicitly passed on the command-line."""
 
   def __init__(
@@ -1412,9 +1523,8 @@ class TestModuleExecutionPlan(TestExecutionPlan):
       results_dir: str,
       mod_info: module_info.ModuleInfo,
       args: argparse.Namespace,
-      dry_run: bool,
-  ) -> TestModuleExecutionPlan:
-    """Creates an instance of TestModuleExecutionPlan.
+  ) -> _TestModuleExecutionPlan:
+    """Creates an instance of _TestModuleExecutionPlan.
 
     Args:
         test_infos: A list of instances of TestInfo.
@@ -1424,10 +1534,10 @@ class TestModuleExecutionPlan(TestExecutionPlan):
         dry_run: A boolean of whether this invocation is a dry run.
 
     Returns:
-        An instance of TestModuleExecutionPlan.
+        An instance of _TestModuleExecutionPlan.
     """
 
-    if not dry_run:
+    if not args.dry_run:
       _validate_exec_mode(args, test_infos)
 
     # _validate_exec_mode appends --host automatically when pure
@@ -1442,13 +1552,15 @@ class TestModuleExecutionPlan(TestExecutionPlan):
         minimal_build=args.minimal_build,
     )
 
-    return TestModuleExecutionPlan(
+    return _TestModuleExecutionPlan(
         test_runner_invocations=invocations,
         extra_args=extra_args,
     )
 
   def requires_device_update(self) -> bool:
-    return _requires_device_update(self._test_runner_invocations)
+    return any(
+        inv.requires_device_update() for inv in self._test_runner_invocations
+    )
 
   def required_build_targets(self) -> Set[str]:
     build_targets = set()
@@ -1473,66 +1585,5 @@ class TestModuleExecutionPlan(TestExecutionPlan):
     return reporter.print_summary() | exit_code
 
 
-def _requires_device_update(invocations: List[TestRunnerInvocation]) -> bool:
-  """Checks if any invocation requires device update."""
-  return any(i.requires_device_update() for i in invocations)
-
-
 if __name__ == '__main__':
-  results_dir = make_test_run_dir()
-  if END_OF_OPTION in sys.argv:
-    end_position = sys.argv.index(END_OF_OPTION)
-    final_args = [
-        *sys.argv[1:end_position],
-        *_get_args_from_config(),
-        *sys.argv[end_position:],
-    ]
-  else:
-    final_args = [*sys.argv[1:], *_get_args_from_config()]
-  if final_args != sys.argv[1:]:
-    print(
-        'The actual cmd will be: \n\t{}\n'.format(
-            atest_utils.mark_cyan('atest ' + ' '.join(final_args))
-        )
-    )
-    metrics.LocalDetectEvent(detect_type=DetectType.ATEST_CONFIG, result=1)
-    if HAS_IGNORED_ARGS:
-      atest_utils.colorful_print(
-          'Please correct the config and try again.', constants.YELLOW
-      )
-      sys.exit(ExitCode.EXIT_BEFORE_MAIN)
-  else:
-    metrics.LocalDetectEvent(detect_type=DetectType.ATEST_CONFIG, result=0)
-
-  args = _parse_args(final_args)
-  atest_configs.GLOBAL_ARGS = args
-  _configure_logging(args.verbose, results_dir)
-
-  logging.debug(
-      'Start of atest run. sys.argv: %s, final_args: %s', sys.argv, final_args
-  )
-
-  banner_printer = banner.BannerPrinter.create()
-
-  with atest_execution_info.AtestExecutionInfo(
-      final_args, results_dir, atest_configs.GLOBAL_ARGS
-  ) as result_file:
-    setup_metrics_tool_name(atest_configs.GLOBAL_ARGS.no_metrics)
-
-    exit_code = _main(
-        final_args,
-        results_dir,
-        atest_configs.GLOBAL_ARGS,
-        banner_printer,
-    )
-    detector = bug_detector.BugDetector(final_args, exit_code)
-    if exit_code not in EXIT_CODES_BEFORE_TEST:
-      metrics.LocalDetectEvent(
-          detect_type=DetectType.BUG_DETECTED, result=detector.caught_result
-      )
-      if result_file:
-        print("Run 'atest --history' to review test result history.")
-
-  banner_printer.print()
-
-  sys.exit(exit_code)
+  _AtestMain(sys.argv).run()
diff --git a/atest/atest_main_unittest.py b/atest/atest_main_unittest.py
index 4f42d7ce..611a63ed 100755
--- a/atest/atest_main_unittest.py
+++ b/atest/atest_main_unittest.py
@@ -287,35 +287,6 @@ class PrintModuleInfoTest(AtestUnittestFixture):
   def tearDown(self):
     sys.stdout = sys.__stdout__
 
-  @mock.patch('atest.atest_utils._has_colors', return_value=True)
-  def test_print_module_info_from_module_name(self, _):
-    """Test _print_module_info_from_module_name method."""
-    mod_info = self.create_module_info([
-        module(
-            name='mod1',
-            path=['src/path/mod1'],
-            installed=['installed/path/mod1'],
-            compatibility_suites=['device_test_mod1', 'native_test_mod1'],
-        )
-    ])
-    correct_output = (
-        f'{GREEN}mod1{END}\n'
-        f'{CYAN}\tCompatibility suite{END}\n'
-        '\t\tdevice_test_mod1\n'
-        '\t\tnative_test_mod1\n'
-        f'{CYAN}\tSource code path{END}\n'
-        "\t\t['src/path/mod1']\n"
-        f'{CYAN}\tInstalled path{END}\n'
-        '\t\tinstalled/path/mod1\n'
-    )
-    capture_output = StringIO()
-    sys.stdout = capture_output
-
-    atest_main._print_module_info_from_module_name(mod_info, 'mod1')
-
-    # Check the function correctly printed module_info in color to stdout
-    self.assertEqual(correct_output, capture_output.getvalue())
-
   def test_has_valid_test_mapping_args_is_test_mapping_detect_event_send_1(
       self,
   ):
diff --git a/atest/atest_utils.py b/atest/atest_utils.py
index e21071cb..36e7004f 100644
--- a/atest/atest_utils.py
+++ b/atest/atest_utils.py
@@ -95,8 +95,6 @@ _WILDCARD_CHARS = {'?', '*'}
 
 _WILDCARD_FILTER_RE = re.compile(r'.*[?|*]$')
 _REGULAR_FILTER_RE = re.compile(r'.*\w$')
-# Printed before the html log line. May be used in tests to parse the html path.
-_HTML_LOG_PRINT_PREFIX = 'To access logs, press "ctrl" and click on'
 
 SUGGESTIONS = {
     # (b/177626045) If Atest does not install target application properly.
@@ -221,7 +219,12 @@ def get_build_cmd(dump=False):
   )
   if dump:
     return [make_cmd, '--dumpvar-mode', 'report_config']
-  return [make_cmd, '--make-mode', 'WRAPPER_TOOL=atest']
+  return [
+      make_cmd,
+      '--make-mode',
+      'WRAPPER_TOOL=atest',
+      f'ATEST_RUN_ID={metrics.get_run_id()}',
+  ]
 
 
 def _capture_fail_section(full_log):
@@ -498,7 +501,6 @@ def is_test_mapping(args):
   return all((len(args.tests) == 1, args.tests[0][0] == ':'))
 
 
-@atest_decorator.static_var('cached_has_colors', {})
 def _has_colors(stream):
   """Check the output stream is colorful.
 
@@ -508,21 +510,11 @@ def _has_colors(stream):
   Returns:
       True if the file stream can interpreter the ANSI color code.
   """
-  cached_has_colors = _has_colors.cached_has_colors
-  if stream in cached_has_colors:
-    return cached_has_colors[stream]
-  cached_has_colors[stream] = True
   # Following from Python cookbook, #475186
-  if not hasattr(stream, 'isatty'):
-    cached_has_colors[stream] = False
-    return False
-  if not stream.isatty():
-    # Auto color only on TTYs
-    cached_has_colors[stream] = False
-    return False
+  # Auto color only on TTYs
   # curses.tigetnum() cannot be used for telling supported color numbers
   # because it does not come with the prebuilt py3-cmd.
-  return cached_has_colors[stream]
+  return getattr(stream, 'isatty', lambda: False)()
 
 
 def colorize(text, color, bp_color=None):
@@ -591,7 +583,7 @@ def mark_blue(text):
   return colorize(text, constants.BLUE)
 
 
-def colorful_print(text, color, bp_color=None, auto_wrap=True):
+def colorful_print(text, color=None, bp_color=None, auto_wrap=True):
   """Print out the text with color.
 
   Args:
@@ -601,7 +593,7 @@ def colorful_print(text, color, bp_color=None, auto_wrap=True):
       bp_color: Backgroud color which is an ANSI code shift for colorful print.
       auto_wrap: If True, Text wraps while print.
   """
-  output = colorize(text, color, bp_color)
+  output = colorize(text, color, bp_color) if color else text
   if auto_wrap:
     print(output)
   else:
@@ -609,7 +601,7 @@ def colorful_print(text, color, bp_color=None, auto_wrap=True):
 
 
 def _print_to_console(
-    prefix: str, color: int, msg: Any, *fmt_args: list[Any]
+    prefix: str, msg: Any, *fmt_args: list[Any], color: int = None
 ) -> None:
   """Print a message to the console.
 
@@ -636,7 +628,7 @@ def print_and_log_error(msg, *fmt_args):
     *fmt_args: Format arguments for the message.
   """
   logging.error(msg, *fmt_args)
-  _print_to_console('Error: ', constants.RED, msg, *fmt_args)
+  _print_to_console('Error: ', msg, *fmt_args, color=constants.RED)
 
 
 def print_and_log_warning(msg, *fmt_args):
@@ -647,7 +639,7 @@ def print_and_log_warning(msg, *fmt_args):
     *fmt_args: Format arguments for the message.
   """
   logging.warning(msg, *fmt_args)
-  _print_to_console('Warning: ', constants.YELLOW, msg, *fmt_args)
+  _print_to_console('Warning: ', msg, *fmt_args, color=constants.MAGENTA)
 
 
 def print_and_log_info(msg, *fmt_args):
@@ -658,7 +650,7 @@ def print_and_log_info(msg, *fmt_args):
     *fmt_args: Format arguments for the message.
   """
   logging.info(msg, *fmt_args)
-  _print_to_console('Info: ', constants.WHITE, msg, *fmt_args)
+  _print_to_console(mark_cyan('Info: '), msg, *fmt_args)
 
 
 def get_terminal_size():
@@ -1916,11 +1908,11 @@ def get_manifest_info(manifest: Path) -> Dict[str, Any]:
 
 
 # pylint: disable=broad-except
-def generate_print_result_html(result_file: Path):
+def generate_result_html(result_file: Path) -> Path:
   """Generate a html that collects all log files."""
   result_file = Path(result_file)
-  search_dir = Path(result_file).parent.joinpath('log')
-  result_html = Path(search_dir, 'test_logs.html')
+  search_dir = Path(result_file).parent
+  result_html = Path(result_file.parent, 'local_log_file_list.html')
   try:
     logs = sorted(find_files(str(search_dir), file_name='*', followlinks=True))
     with open(result_html, 'w', encoding='utf-8') as cache:
@@ -1933,15 +1925,14 @@ def generate_print_result_html(result_file: Path):
       for log in logs:
         cache.write(
             f'<p><a href="{urllib.parse.quote(log)}">'
-            f'{html.escape(Path(log).name)}</a></p>'
+            f'{html.escape(Path(log).relative_to(search_dir).as_posix())}</a></p>'
         )
       cache.write('</body></html>')
-    print(
-        f'\n{_HTML_LOG_PRINT_PREFIX}\n{mark_magenta(f"file://{result_html}")}\n'
-    )
     send_tradeded_elapsed_time_metric(search_dir)
+    return result_html
   except Exception as e:
     logging.debug('Did not generate log html for reason: %s', e)
+    return None
 
 
 def send_tradeded_elapsed_time_metric(search_dir: Path):
diff --git a/atest/banner.py b/atest/banner.py
index 939e3c52..59e94c6a 100644
--- a/atest/banner.py
+++ b/atest/banner.py
@@ -86,7 +86,7 @@ class BannerPrinter:
       return
 
     if not print_func:
-      print_func = lambda m: atest_utils.colorful_print(m, constants.YELLOW)
+      print_func = lambda m: atest_utils.colorful_print(m, constants.MAGENTA)
 
     if not date_supplier:
       date_supplier = lambda: str(date.today())
diff --git a/atest/bazel/resources/WORKSPACE b/atest/bazel/resources/WORKSPACE
index 225c0c72..22ff80ff 100644
--- a/atest/bazel/resources/WORKSPACE
+++ b/atest/bazel/resources/WORKSPACE
@@ -1,6 +1,6 @@
 register_toolchains(
     "//prebuilts/build-tools:py_toolchain",
-    "//prebuilts/jdk/jdk17:runtime_toolchain_definition",
+    "//prebuilts/jdk/jdk21:runtime_toolchain_definition",
 )
 
 # `device_infra` repository provides rules needed to start cuttlefish devices
@@ -16,6 +16,10 @@ local_repository(
     path = "external/bazelbuild-rules_python",
 )
 
+load("@rules_python//python:repositories.bzl", "py_repositories")
+
+py_repositories()
+
 local_repository(
     name = "rules_java",
     path = "external/bazelbuild-rules_java",
diff --git a/atest/bazel/resources/bazel.sh b/atest/bazel/resources/bazel.sh
index 66fcfce3..cf7131f0 100755
--- a/atest/bazel/resources/bazel.sh
+++ b/atest/bazel/resources/bazel.sh
@@ -10,7 +10,7 @@ set -eo pipefail
 
 SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
 
-JDK_PATH="${SCRIPT_DIR}"/prebuilts/jdk/jdk17/linux-x86
+JDK_PATH="${SCRIPT_DIR}"/prebuilts/jdk/jdk21/linux-x86
 BAZEL_BINARY="${SCRIPT_DIR}"/prebuilts/bazel/linux-x86_64/bazel
 
 PROCESS_PATH="${JDK_PATH}"/bin:"${PATH}"
diff --git a/atest/bazel/resources/bazelrc b/atest/bazel/resources/bazelrc
index bbb1da0e..29585515 100644
--- a/atest/bazel/resources/bazelrc
+++ b/atest/bazel/resources/bazelrc
@@ -13,7 +13,7 @@ common --noenable_bzlmod
 build --incompatible_strict_action_env
 
 # Use the JDK defined by local_java_runtime in //prebuilts/jdk/jdk<VERSION>
-build --java_runtime_version=jdk17
+build --java_runtime_version=jdk21
 
 # Depending on how many machines are in the remote execution instance, setting
 # this higher can make builds faster by allowing more jobs to run in parallel.
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java
index 0f26a09e..deb88507 100644
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java
+++ b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java
@@ -40,6 +40,7 @@ import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
 import com.android.tradefed.result.proto.TestRecordProto.TestRecord;
 import com.android.tradefed.testtype.IRemoteTest;
 import com.android.tradefed.util.AbiUtils;
+import com.android.tradefed.util.FileUtil;
 import com.android.tradefed.util.ZipUtil;
 import com.android.tradefed.util.proto.TestRecordProtoUtil;
 
@@ -689,7 +690,7 @@ public final class BazelTest implements IRemoteTest {
                     new BazelTestListener(listener, extraLogCalls, isTestResultCached(result));
             parseResultsToListener(bazelListener, context, record, filePrefix);
         } finally {
-            MoreFiles.deleteRecursively(outputFilesDir);
+            FileUtil.recursiveDelete(outputFilesDir.toFile());
         }
     }
 
@@ -840,11 +841,7 @@ public final class BazelTest implements IRemoteTest {
     }
 
     private void cleanup() {
-        try {
-            MoreFiles.deleteRecursively(mRunTemporaryDirectory);
-        } catch (IOException e) {
-            CLog.e(e);
-        }
+        FileUtil.recursiveDelete(mRunTemporaryDirectory.toFile());
     }
 
     interface ProcessStarter {
diff --git a/atest/bazel_mode.py b/atest/bazel_mode.py
index 6c9f0af9..97a4c624 100644
--- a/atest/bazel_mode.py
+++ b/atest/bazel_mode.py
@@ -717,16 +717,17 @@ class WorkspaceGenerator:
     self.workspace_out_path.joinpath('BUILD.bazel').touch()
 
   def _add_bazel_bootstrap_files(self):
+    self._add_workspace_resource(src='bazel.sh', dst='bazel.sh')
+    # Restore permissions as execute permissions are not preserved by soong
+    # packaging.
+    os.chmod(self.workspace_out_path.joinpath('bazel.sh'), 0o755)
     self._symlink(
-        src='tools/asuite/atest/bazel/resources/bazel.sh', target='bazel.sh'
+        src='prebuilts/jdk/jdk21/BUILD.bazel',
+        target='prebuilts/jdk/jdk21/BUILD.bazel',
     )
     self._symlink(
-        src='prebuilts/jdk/jdk17/BUILD.bazel',
-        target='prebuilts/jdk/jdk17/BUILD.bazel',
-    )
-    self._symlink(
-        src='prebuilts/jdk/jdk17/linux-x86',
-        target='prebuilts/jdk/jdk17/linux-x86',
+        src='prebuilts/jdk/jdk21/linux-x86',
+        target='prebuilts/jdk/jdk21/linux-x86',
     )
     self._symlink(
         src='prebuilts/bazel/linux-x86_64/bazel',
diff --git a/atest/bazel_mode_unittest.py b/atest/bazel_mode_unittest.py
index db34829e..a819afa0 100755
--- a/atest/bazel_mode_unittest.py
+++ b/atest/bazel_mode_unittest.py
@@ -82,6 +82,7 @@ class GenerationTestFixture(fake_filesystem_unittest.TestCase):
 
     self.resource_manager.get_resource_file_path('WORKSPACE').touch()
     self.resource_manager.get_resource_file_path('bazelrc').touch()
+    self.resource_manager.get_resource_file_path('bazel.sh').touch()
 
     rules_python = self.resource_manager.get_src_file_path(
         'external/bazelbuild-rules_python'
diff --git a/atest/coverage/coverage.py b/atest/coverage/coverage.py
index 2aa4e7e8..b99cbb4d 100644
--- a/atest/coverage/coverage.py
+++ b/atest/coverage/coverage.py
@@ -35,6 +35,7 @@ def build_env_vars():
       'CLANG_COVERAGE': 'true',
       'NATIVE_COVERAGE_PATHS': '*',
       'EMMA_INSTRUMENT': 'true',
+      'EMMA_INSTRUMENT_FRAMEWORK': 'true',
       'LLVM_PROFILE_FILE': '/dev/null',
   }
   return env_vars
@@ -130,6 +131,7 @@ def _deduce_code_under_test(
     mod_info: module_info.ModuleInfo,
 ) -> Set[str]:
   """Deduces the code-under-test from the test info and module info.
+
   If the test info contains code-under-test information, that is used.
   Otherwise, the dependencies of the test are used.
 
@@ -273,10 +275,14 @@ def _find_native_binaries(module_dir):
   # the actual output binary.
   # Exclude .d and .d.raw files. These are Rust dependency files and are also
   # stored in the unstripped directory.
+  # Exclude .toc files. These are just a table of conents of a shared library,
+  # but are also stored in the unstripped directory.
   return [
       str(file)
       for file in files
-      if '.rsp' not in file.suffixes and '.d' not in file.suffixes
+      if '.rsp' not in file.suffixes
+      and '.d' not in file.suffixes
+      and '.toc' not in file.suffixes
   ]
 
 
@@ -327,6 +333,7 @@ def _generate_java_coverage_report(
       cmd.append('-sourcepath')
       cmd.append(src_path)
     cmd.extend(jacoco_files)
+    logging.debug(f'Running jacoco_lcov to generate coverage report: {cmd}.')
     try:
       subprocess.run(
           cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
@@ -363,6 +370,7 @@ def _generate_native_coverage_report(unstripped_native_binaries, results_dir):
   for binary in unstripped_native_binaries:
     cmd.append(f'--object={str(binary)}')
 
+  logging.debug(f'Running llvm-cov to generate coverage report: {cmd}.')
   try:
     subprocess.run(
         cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
@@ -378,10 +386,20 @@ def _generate_native_coverage_report(unstripped_native_binaries, results_dir):
 
 
 def _generate_lcov_report(out_dir, reports, root_dir=None):
-  cmd = ['genhtml', '-q', '-o', out_dir, '--ignore-errors', 'unmapped']
+  cmd = [
+      'genhtml',
+      '-q',
+      '-o',
+      out_dir,
+      # TODO(b/361334044): These errors are ignored to continue to generate a
+      # flawed result but ultimately need to be resolved, see bug for details.
+      '--ignore-errors',
+      'unmapped,range,empty,corrupt',
+  ]
   if root_dir:
     cmd.extend(['-p', root_dir])
   cmd.extend(reports)
+  logging.debug(f'Running genhtml to generate coverage report: {cmd}.')
   try:
     subprocess.run(
         cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
diff --git a/atest/coverage/coverage_unittest.py b/atest/coverage/coverage_unittest.py
index f68b3683..36194ae8 100755
--- a/atest/coverage/coverage_unittest.py
+++ b/atest/coverage/coverage_unittest.py
@@ -175,7 +175,7 @@ class CollectNativeReportBinariesUnittests(unittest.TestCase):
       return_value=PosixPath('/out/soong/.intermediates'),
   )
   @mock.patch.object(PosixPath, 'glob')
-  def test_skip_rsp_and_d_files(self, _glob, _get_build_out_dir):
+  def test_skip_rsp_and_d_and_toc_files(self, _glob, _get_build_out_dir):
     _glob.return_value = [
         PosixPath(
             '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin'
@@ -186,6 +186,9 @@ class CollectNativeReportBinariesUnittests(unittest.TestCase):
         PosixPath(
             '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin.d'
         ),
+        PosixPath(
+            '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin.toc'
+        ),
     ]
     code_under_test = {'native_bin'}
     mod_info = create_module_info([
diff --git a/atest/feedback.py b/atest/feedback.py
deleted file mode 100644
index 167428cc..00000000
--- a/atest/feedback.py
+++ /dev/null
@@ -1,67 +0,0 @@
-# Copyright 2024, The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Module to assist users providing feedback."""
-
-import sys
-from atest.logstorage import log_uploader
-from atest.metrics import metrics
-
-
-# Keep it disabled until we can tell the capability of tmux.
-_DISABLE_HYPER_LINK_FORMAT_BY_DEFAULT = True
-
-
-_non_redirected_sys_stdout = sys.stdout
-
-
-def print_feedback_message(
-    is_internal_user=None, is_uploading_logs=None, use_hyper_link=None
-):
-  """Print the feedback message to console."""
-  if is_internal_user is None:
-    is_internal_user = metrics.is_internal_user()
-  if is_uploading_logs is None:
-    is_uploading_logs = log_uploader.is_uploading_logs()
-  if use_hyper_link is None:
-    use_hyper_link = (
-        not _DISABLE_HYPER_LINK_FORMAT_BY_DEFAULT
-        and getattr(_non_redirected_sys_stdout, 'isatty', lambda: False)()
-    )
-
-  if not is_internal_user:
-    return
-
-  if use_hyper_link:
-    print_link = lambda text, target: print(
-        f'\u001b]8;;{target}\u001b\\{text}\u001b]8;;\u001b\\'
-    )
-    if is_uploading_logs:
-      print_link(
-          'Click here to share feedback about this atest run.',
-          f'http://go/atest-feedback/{metrics.get_run_id()}',
-      )
-    else:
-      print_link(
-          'Click here to share feedback about atest.',
-          'http://go/atest-feedback-aosp',
-      )
-  else:
-    if is_uploading_logs:
-      print(
-          'To share feedback about this run:\n'
-          f'http://go/atest-feedback/{metrics.get_run_id()}'
-      )
-    else:
-      print('To share feedback about atest: http://go/atest-feedback-aosp')
diff --git a/atest/feedback_unittest.py b/atest/feedback_unittest.py
deleted file mode 100644
index be35a5ed..00000000
--- a/atest/feedback_unittest.py
+++ /dev/null
@@ -1,79 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-import unittest
-from unittest.mock import patch
-from atest import feedback
-from atest.metrics import metrics
-
-
-class FeedbackTest(unittest.TestCase):
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_internal_user_prints_feedback(self, mock_print):
-    feedback.print_feedback_message(
-        is_internal_user=True, is_uploading_logs=True
-    )
-
-    mock_print.assert_called_once()
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_external_user_no_prints(self, mock_print):
-    feedback.print_feedback_message(
-        is_internal_user=False, is_uploading_logs=True
-    )
-
-    mock_print.assert_not_called()
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_is_uploading_logs_use_contains_run_id(
-      self, mock_print
-  ):
-    feedback.print_feedback_message(
-        is_internal_user=True, is_uploading_logs=True
-    )
-
-    mock_print.assert_called_once()
-    self.assertIn(metrics.get_run_id(), mock_print.call_args[0][0])
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_is_not_uploading_logs_does_use_contains_run_id(
-      self, mock_print
-  ):
-    feedback.print_feedback_message(
-        is_internal_user=True, is_uploading_logs=False
-    )
-
-    mock_print.assert_called_once()
-    self.assertNotIn(metrics.get_run_id(), mock_print.call_args[0][0])
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_use_hyper_link_use_hyper_link(self, mock_print):
-    feedback.print_feedback_message(
-        is_internal_user=True, is_uploading_logs=False, use_hyper_link=True
-    )
-
-    mock_print.assert_called_once()
-    self.assertIn('\u001b]8;;\u001b\\', mock_print.call_args[0][0])
-
-  @patch('builtins.print')
-  def test_get_buganizer_url_does_not_use_hyper_link_does_not_use_hyper_link(
-      self, mock_print
-  ):
-    feedback.print_feedback_message(
-        is_internal_user=True, is_uploading_logs=False, use_hyper_link=False
-    )
-
-    mock_print.assert_called_once()
-    self.assertNotIn('\u001b]8;;\u001b\\', mock_print.call_args[0][0])
diff --git a/atest/integration_tests/adevice_command_success_tests.py b/atest/integration_tests/adevice_command_success_tests.py
index 6585d9c4..e64ac8cd 100644
--- a/atest/integration_tests/adevice_command_success_tests.py
+++ b/atest/integration_tests/adevice_command_success_tests.py
@@ -16,6 +16,8 @@
 
 """Tests to check if adevice commands were executed with success exit codes."""
 
+
+import subprocess
 import atest_integration_test
 
 
@@ -24,52 +26,100 @@ class AdeviceCommandSuccessTests(atest_integration_test.AtestTestCase):
 
   def setUp(self):
     super().setUp()
-    self._default_snapshot_include_paths += [
-        '$OUT_DIR/combined-*.ninja',
-        '$OUT_DIR/build-*.ninja',
-        '$OUT_DIR/soong/*.ninja',
-        '$OUT_DIR/target/',
+    self._default_snapshot_include_paths = [
+        '$OUT_DIR/combined-*.ninja*',
+        '$OUT_DIR/*.ninja*',
+        '$OUT_DIR/target/product/',
+        '$OUT_DIR/host/linux-x86/bin/adevice',
+        '$OUT_DIR/host/linux-x86/bin/adb',
+        '$OUT_DIR/host/linux-x86/bin/aapt2',
+        '$OUT_DIR/target/product/*/module-info*',
+        '$OUT_DIR/target/product/*/all_modules.txt',
+        '$OUT_DIR/soong/module_bp*',
+        '.repo/manifest.xml',
+        'build/soong/soong_ui.bash',
+        'prebuilts/build-tools/linux-x86',
     ]
 
     self._default_snapshot_env_keys += ['TARGET_PRODUCT', 'ANDROID_BUILD_TOP']
-    self._default_snapshot_exclude_paths = []
+    self._default_snapshot_exclude_paths += [
+        '$OUT_DIR/**/*.img',
+        '$OUT_DIR/**/symbols',
+        '$OUT_DIR/target/product/**/obj',
+        '$OUT_DIR/target/product/**/tmpfvcx759x',
+        '$OUT_DIR/host/linux-x86/bin/go',
+        '$OUT_DIR/host/linux-x86/bin/soong_build',
+        '$OUT_DIR/host/linux-x86/obj',
+        '$OUT_DIR/host/linux-x86/cvd-host_package',
+        '$OUT_DIR/host/linux-x86/testcases',
+        'prebuilts/jdk',
+    ]
 
-  def test_status(self):
+  def test_1_status(self):
     """Test if status command runs successfully on latest repo sync."""
-    self._verify_adevice_command_success('adevice status'.split())
+    self._verify_adevice_command(
+        build_cmd='build/soong/soong_ui.bash --make-mode droid adevice'.split(),
+        build_clean_up_cmd=[],
+        test_cmd='adevice status'.split(),
+        expected_in_log=[],
+        expected_not_in_log=[],
+    )
 
-  def test_update(self):
+  # TODO: b/359849846 - renable restart when device reliably comes back
+  def test_2_update(self):
     """Test if update command runs successfully on latest repo sync."""
     self._verify_adevice_command_success(
-        'adevice update --max-allowed-changes=6000'.split()
+        'adevice update --max-allowed-changes=6000 --restart=none'.split()
     )
 
-  def test_system_server_change_expect_soft_restart(self):
-    """Test if adevice update on system server update results in a soft restart."""
-    log_string_to_find = 'Entered the Android system server'
-    filename = (
-        'frameworks/base/services/java/com/android/server/SystemServer.java'
+  def test_3_status_no_changes(self):
+    """Test if status command doesn't perform any updates after adevice update."""
+    self._verify_adevice_command(
+        build_cmd=[],
+        build_clean_up_cmd=[],
+        test_cmd='adevice status'.split(),
+        expected_in_log=['Adb Cmds - 0'],
+        expected_not_in_log=['push'],
     )
-    build_pre_cmd = [
-        'sed',
-        '-i',
-        f's#{log_string_to_find}#{log_string_to_find}ADEVICE_TEST#g',
-        filename,
-    ]
-    build_clean_up_cmd = f'sed -i s#ADEVICE_TEST##g {filename}'.split()
 
+  def test_4_update_no_changes(self):
+    """Test if update command doesn't perform any updates after adevice update."""
     self._verify_adevice_command(
-        build_pre_cmd=build_pre_cmd,
-        build_clean_up_cmd=build_clean_up_cmd,
-        test_cmd='adevice update'.split(),
-        expected_in_log=['push', 'systemserver', 'restart'],
-        expected_not_in_log=['reboot'],
+        build_cmd=[],
+        build_clean_up_cmd=[],
+        test_cmd='adevice update --restart=none'.split(),
+        expected_in_log=['Adb Cmds - 0'],
+        expected_not_in_log=['push'],
     )
 
+  #   Skipping test that has additional build_pre_cmd until rest are working.
+  #   def test_5_system_server_change_expect_soft_restart(self):
+  #     """Test if adevice update on system server update results in a soft
+  #     restart."""
+  #     log_string_to_find = 'Entered the Android system server'
+  #     filename = (
+  #         'frameworks/base/services/java/com/android/server/SystemServer.java'
+  #     )
+  #     build_pre_cmd = [
+  #         'sed',
+  #         '-i',
+  #         f's#{log_string_to_find}#{log_string_to_find}ADEVICE_TEST#g',
+  #         filename,
+  #     ]
+  #     build_clean_up_cmd = f'sed -i s#ADEVICE_TEST##g {filename}'.split()
+
+  #     self._verify_adevice_command(
+  #         build_pre_cmd=build_pre_cmd,
+  #         build_clean_up_cmd=build_clean_up_cmd,
+  #         test_cmd='adevice update'.split(),
+  #         expected_in_log=['push', 'services.jar', 'SoftRestart'],
+  #         expected_not_in_log=['reboot'],
+  #     )
+
   def _verify_adevice_command_success(self, test_cmd: list[str]):
     """Verifies whether an adevice command run completed with exit code 0."""
     self._verify_adevice_command(
-        build_pre_cmd=[],
+        build_cmd=[],
         build_clean_up_cmd=[],
         test_cmd=test_cmd,
         expected_in_log=[],
@@ -78,7 +128,7 @@ class AdeviceCommandSuccessTests(atest_integration_test.AtestTestCase):
 
   def _verify_adevice_command(
       self,
-      build_pre_cmd: list[str],
+      build_cmd: list[str],
       build_clean_up_cmd: list[str],
       test_cmd: list[str],
       expected_in_log: list[str],
@@ -92,22 +142,15 @@ class AdeviceCommandSuccessTests(atest_integration_test.AtestTestCase):
     ) -> atest_integration_test.StepOutput:
 
       try:
-        if build_pre_cmd:
+        if build_cmd:
           self._run_shell_command(
-              build_pre_cmd,
+              build_cmd,
               env=step_in.get_env(),
               cwd=step_in.get_repo_root(),
               print_output=True,
           ).check_returncode()
-        self._run_shell_command(
-            'build/soong/soong_ui.bash --make-mode'.split(),
-            env=step_in.get_env(),
-            cwd=step_in.get_repo_root(),
-            print_output=True,
-        ).check_returncode()
-        return self.create_step_output()
-      except Exception as e:
-        raise e
+      except subprocess.CalledProcessError as e:
+        self.fail(e)
       finally:
         # Always attempt to clean up
         if build_clean_up_cmd:
@@ -116,26 +159,35 @@ class AdeviceCommandSuccessTests(atest_integration_test.AtestTestCase):
               env=step_in.get_env(),
               cwd=step_in.get_repo_root(),
               print_output=True,
-          ).check_returncode()
+          )
+      return self.create_step_output()
 
     def test_step(step_in: atest_integration_test.StepInput) -> None:
+      product = step_in.get_env()['TARGET_PRODUCT']
       self._run_shell_command(
+          f'touch out/soong/build.{product}.ninja'.split(),
+          env=step_in.get_env(),
+          cwd=step_in.get_repo_root(),
+          print_output=False,
+      )
+      result = self._run_shell_command(
           test_cmd,
           env=step_in.get_env(),
           cwd=step_in.get_repo_root(),
-          print_output=True,
-      ).check_returncode()
-
+          print_output=False,
+      )
       check_log_process = self._run_shell_command(
-          'cat $ANDROID_BUILD_TOP/out/adevice.log'.split(),
+          f'cat {step_in.get_env()["ANDROID_BUILD_TOP"]}/out/adevice.log'.split(),
           env=step_in.get_env(),
+          cwd=step_in.get_repo_root(),
       )
+
+      # Check for error exit
+      result.check_returncode()
       for s in expected_in_log:
-        if s not in check_log_process.stdout:
-          raise f'Expected {s} in adevice log. Got {check_log_process.stdout}'
+        self.assertIn(s, check_log_process.stdout, f'{s} was not found in log')
       for s in expected_not_in_log:
-        if s in check_log_process.stdout:
-          raise f'Expected {s} to be NOT in adevice log. Got {check_log_process.stdout}'
+        self.assertNotIn(s, check_log_process.stdout, f'{s} was found in log')
 
     script.add_build_step(build_step)
     script.add_test_step(test_step)
diff --git a/atest/integration_tests/atest_command_verification_tests.py b/atest/integration_tests/atest_command_verification_tests.py
index 134e823c..0cbc9306 100644
--- a/atest/integration_tests/atest_command_verification_tests.py
+++ b/atest/integration_tests/atest_command_verification_tests.py
@@ -57,115 +57,120 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         expected_cmd=expected_cmd,
     )
 
-  @atest_integration_test.run_in_parallel
-  def test_cts_animation_test_cases_animator_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = 'CtsAnimationTestCases:AnimatorTest'
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --module CtsAnimationTestCases'
-        ' --atest-include-filter'
-        ' CtsAnimationTestCases:android.animation.cts.AnimatorTest'
-        ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
-        ' VERBOSE --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-        ' --enable-parameterized-modules --exclude-module-parameters multi_abi'
-        ' --exclude-module-parameters instant_app --exclude-module-parameters'
-        ' secondary_user'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
-
-  @atest_integration_test.run_in_parallel
-  def test_cts_sample_device_cases_shared_prefs_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = (
-        'CtsSampleDeviceTestCases:SampleDeviceTest#testSharedPreferences'
-    )
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter'
-        ' CtsSampleDeviceTestCases --atest-include-filter'
-        ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceTest#testSharedPreferences'
-        ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
-        ' VERBOSE --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
-
-  @atest_integration_test.run_in_parallel
-  def test_cts_sample_device_cases_android_sample_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = 'CtsSampleDeviceTestCases:android.sample.cts'
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter'
-        ' CtsSampleDeviceTestCases --atest-include-filter'
-        ' CtsSampleDeviceTestCases:android.sample.cts --skip-loading-config-jar'
-        ' --log-level-display VERBOSE --log-level VERBOSE'
-        ' --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
-
-  @atest_integration_test.run_in_parallel
-  def test_cts_sample_device_cases_device_report_log_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = (
-        'CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
-    )
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter'
-        ' CtsSampleDeviceTestCases --atest-include-filter'
-        ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
-        ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
-        ' VERBOSE --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
-
-  @atest_integration_test.run_in_parallel
-  def test_cts_animation_cases_sample_device_cases_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = 'CtsAnimationTestCases CtsSampleDeviceTestCases'
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter CtsAnimationTestCases'
-        ' --include-filter CtsSampleDeviceTestCases --skip-loading-config-jar'
-        ' --log-level-display VERBOSE --log-level VERBOSE'
-        ' --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_cts_animation_test_cases_animator_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = 'CtsAnimationTestCases:AnimatorTest'
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --module CtsAnimationTestCases'
+  #       ' --atest-include-filter'
+  #       ' CtsAnimationTestCases:android.animation.cts.AnimatorTest'
+  #       ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
+  #       ' VERBOSE --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #       ' --enable-parameterized-modules --exclude-module-parameters multi_abi'
+  #       ' --exclude-module-parameters instant_app --exclude-module-parameters'
+  #       ' secondary_user'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
+
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_cts_sample_device_cases_shared_prefs_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = (
+  #       'CtsSampleDeviceTestCases:SampleDeviceTest#testSharedPreferences'
+  #   )
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter'
+  #       ' CtsSampleDeviceTestCases --atest-include-filter'
+  #       ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceTest#testSharedPreferences'
+  #       ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
+  #       ' VERBOSE --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
+
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_cts_sample_device_cases_android_sample_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = 'CtsSampleDeviceTestCases:android.sample.cts'
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter'
+  #       ' CtsSampleDeviceTestCases --atest-include-filter'
+  #       ' CtsSampleDeviceTestCases:android.sample.cts --skip-loading-config-jar'
+  #       ' --log-level-display VERBOSE --log-level VERBOSE'
+  #       ' --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
+
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_cts_sample_device_cases_device_report_log_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = (
+  #       'CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
+  #   )
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter'
+  #       ' CtsSampleDeviceTestCases --atest-include-filter'
+  #       ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
+  #       ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
+  #       ' VERBOSE --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
+
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_cts_animation_cases_sample_device_cases_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = 'CtsAnimationTestCases CtsSampleDeviceTestCases'
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter CtsAnimationTestCases'
+  #       ' --include-filter CtsSampleDeviceTestCases --skip-loading-config-jar'
+  #       ' --log-level-display VERBOSE --log-level VERBOSE'
+  #       ' --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
 
   @atest_integration_test.run_in_parallel
   def test_hello_world_tests_test(self):
@@ -382,7 +387,7 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
   @atest_integration_test.run_in_parallel
   def test_quick_access_wallet_robo_test(self):
     """Verify that the test's command runs correctly."""
-    test_cmd = 'QuickAccessWalletRoboTests'
+    atest_cmd = 'QuickAccessWalletRoboTests'
     expected_cmd = (
         'atest_tradefed.sh template/atest_device_test_base --template:map'
         ' test=atest --template:map log_saver=template/log/atest_log_saver'
@@ -392,7 +397,7 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         ' --no-early-device-release'
     )
     self._verify_atest_internal_runner_command(
-        test_cmd,
+        atest_cmd,
         self._assert_equivalent_cmds,
         expected_cmd=expected_cmd,
     )
diff --git a/atest/integration_tests/atest_integration_test.py b/atest/integration_tests/atest_integration_test.py
index 20cf4988..971b77ec 100644
--- a/atest/integration_tests/atest_integration_test.py
+++ b/atest/integration_tests/atest_integration_test.py
@@ -45,8 +45,6 @@ setup_parallel_in_build_env = (
 #       local integration test execution. If value changes in the source code
 #       breaking the integration test becomes a problem in the future, we can
 #       reconsider importing these constants.
-# Printed before the html log line. Defined in atest/atest_utils.py.
-_HTML_LOG_PRINT_PREFIX = 'To access logs, press "ctrl" and click on'
 # Stdout print prefix for results directory. Defined in atest/atest_main.py
 _RESULTS_DIR_PRINT_PREFIX = 'Atest results and logs directory: '
 
@@ -113,11 +111,17 @@ class AtestRunResult:
       env: dict[str, str],
       repo_root: str,
       config: split_build_test_script.IntegrationTestConfiguration,
+      elapsed_time: float,
   ):
     self._completed_process = completed_process
     self._env = env
     self._repo_root = repo_root
     self._config = config
+    self._elapsed_time = elapsed_time
+
+  def get_elapsed_time(self) -> float:
+    """Returns the elapsed time of the atest command execution."""
+    return self._elapsed_time
 
   def get_returncode(self) -> int:
     """Returns the return code of the completed process."""
@@ -376,16 +380,20 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
     logging.debug(
         '%sCommand environment variables: %s', indentation, step_in.get_env()
     )
+    start_time = time.time()
+    shell_result = cls._run_shell_command(
+        complete_cmd.split(),
+        env=step_in.get_env(),
+        cwd=step_in.get_repo_root(),
+        print_output=print_output,
+    )
+    elapsed_time = time.time() - start_time
     result = AtestRunResult(
-        cls._run_shell_command(
-            complete_cmd.split(),
-            env=step_in.get_env(),
-            cwd=step_in.get_repo_root(),
-            print_output=print_output,
-        ),
+        shell_result,
         step_in.get_env(),
         step_in.get_repo_root(),
         step_in.get_config(),
+        elapsed_time,
     )
 
     wrap_output_lines = lambda output_str: ''.join((
diff --git a/atest/integration_tests/atest_test_archetype_integration_tests.py b/atest/integration_tests/atest_test_archetype_integration_tests.py
index 1068b031..7476f175 100644
--- a/atest/integration_tests/atest_test_archetype_integration_tests.py
+++ b/atest/integration_tests/atest_test_archetype_integration_tests.py
@@ -16,6 +16,7 @@
 
 """Integration tests to make sure selected test archetypes works in atest."""
 
+from dataclasses import dataclass
 from typing import Callable
 
 import atest_integration_test
@@ -25,61 +26,72 @@ class DevicelessJavaTestHostTest(atest_integration_test.AtestTestCase):
   _TARGET_NAME = 'deviceless_java_test_host'
 
   def test_passed_failed_counts(self):
-    _verify_test_passed_failed_ignored_counts(
+    _run_and_verify(
         self,
         atest_command=self._TARGET_NAME + ' --no-bazel-mode --host',
         is_device_required=False,
-        expected_passed_count=2,
-        expected_failed_count=1,
-        expected_ignored_count=0,
+        verifiers=_create_pass_fail_ignore_verifiers(
+            expected_passed_count=2,
+            expected_failed_count=1,
+            expected_ignored_count=0,
+        )
+        + _create_elapsed_time_verifiers(max_sec=10),
     )
 
 
-class DeviceLessPythonTestHostTest(atest_integration_test.AtestTestCase):
+class DevicelessPythonTestHostTest(atest_integration_test.AtestTestCase):
   _TARGET_NAME = 'deviceless_python_test_host'
 
   def test_passed_failed_counts(self):
-    _verify_test_passed_failed_ignored_counts(
+    _run_and_verify(
         self,
         atest_command=self._TARGET_NAME + ' --no-bazel-mode --host',
         is_device_required=False,
-        expected_passed_count=2,
-        expected_failed_count=1,
-        expected_ignored_count=0,
+        verifiers=_create_pass_fail_ignore_verifiers(
+            expected_passed_count=2,
+            expected_failed_count=1,
+            expected_ignored_count=0,
+        )
+        + _create_elapsed_time_verifiers(max_sec=10),
     )
 
 
 class DeviceAndroidTestTest(atest_integration_test.AtestTestCase):
 
   def test_passed_failed_counts(self):
-    _verify_test_passed_failed_ignored_counts(
+    _run_and_verify(
         self,
         atest_command='device_android_test',
         is_device_required=True,
-        expected_passed_count=2,
-        expected_failed_count=1,
-        expected_ignored_count=0,
+        verifiers=_create_pass_fail_ignore_verifiers(
+            expected_passed_count=2,
+            expected_failed_count=1,
+            expected_ignored_count=0,
+        )
+        + _create_elapsed_time_verifiers(max_sec=20),
     )
 
-  def test_early_tradefed_exit_shows_useful_output(self):
+  def test_instrumentation_early_exit_shows_useful_output(self):
+    verifiers = [
+        _Verifier(
+            lambda test_case, result: test_case.assertIn(
+                'instrumentation app process died',
+                result.get_stdout(),
+            ),
+            'process_died',
+        ),
+        _Verifier(
+            lambda test_case, result: test_case.assertNotIn(
+                'Traceback (most recent call last)', result.get_stdout()
+            ),
+            'no_traceback',
+        ),
+    ]
     _run_and_verify(
         self,
         atest_command='device_android_test_non_starting',
         is_device_required=True,
-        verifier=self._verify_stdout_on_early_termination,
-    )
-
-  def _verify_stdout_on_early_termination(
-      self,
-      test_case: atest_integration_test.AtestTestCase,
-      result: atest_integration_test.AtestRunResult,
-  ):
-    """Assert we see the message we expect and that we do not see a stacktrace."""
-    test_case.assertIn(
-        'Test failed because instrumentation process died.', result.get_stdout()
-    )
-    test_case.assertNotIn(
-        'Traceback (most recent call last)', result.get_stdout()
+        verifiers=verifiers,
     )
 
 
@@ -87,73 +99,80 @@ class DeviceCcTestTest(atest_integration_test.AtestTestCase):
   _TARGET_NAME = 'device_cc_test'
 
   def test_passed_failed_counts(self):
-    _verify_test_passed_failed_ignored_counts(
+    _run_and_verify(
         self,
         atest_command=self._TARGET_NAME,
         is_device_required=True,
-        expected_passed_count=2,
-        expected_failed_count=1,
-        expected_ignored_count=0,
+        verifiers=_create_pass_fail_ignore_verifiers(
+            expected_passed_count=2,
+            expected_failed_count=1,
+            expected_ignored_count=0,
+        )
+        + _create_elapsed_time_verifiers(max_sec=20),
     )
 
 
-def _verify_test_passed_failed_ignored_counts(
-    test_case: atest_integration_test.AtestTestCase,
-    atest_command: str,
-    is_device_required: bool,
+@dataclass
+class _Verifier:
+  """Wrapper class to store a verifier function with a subtest name."""
+
+  do_verify: Callable[
+      atest_integration_test.AtestTestCase,
+      atest_integration_test.AtestRunResult,
+  ]
+  name: str
+
+
+def _create_elapsed_time_verifiers(max_sec: float) -> list[_Verifier]:
+  return [
+      _Verifier(
+          lambda test_case, result: test_case.assertLessEqual(
+              result.get_elapsed_time(), max_sec
+          ),
+          'elapsed_time',
+      )
+  ]
+
+
+def _create_pass_fail_ignore_verifiers(
     expected_passed_count: int,
     expected_failed_count: int,
     expected_ignored_count: int,
-):
-  """Verify an atest command finished with expected result counts.
+) -> list[_Verifier]:
+  """Create a list of verifiers that verify an atest command finished with expected result counts.
 
   Args:
-      test_case: The reference to the calling test case.
-      atest_command: The atest command to execute. Note: exclude 'atest',
-        'atest-dev', '-b', '-i', and '-t' from it.
-      is_device_required: Whether the test requires a device.
       expected_passed_count: Number of expected passed count.
       expected_failed_count: Number of expected failed count.
       expected_ignored_count: Number of expected ignored count.
   """
-
-  script = test_case.create_atest_script()
-
-  def build_step(
-      step_in: atest_integration_test.StepInput,
-  ) -> atest_integration_test.StepOutput:
-
-    test_case.run_atest_command(
-        atest_command + ' -cb', step_in, include_device_serial=False
-    ).check_returncode()
-
-    return test_case.create_step_output()
-
-  def test_step(step_in: atest_integration_test.StepInput) -> None:
-    result = test_case.run_atest_command(
-        atest_command + ' -it',
-        step_in,
-        include_device_serial=is_device_required,
-        print_output=False,
-    )
-
-    test_case.assertEqual(result.get_passed_count(), expected_passed_count)
-    test_case.assertEqual(result.get_failed_count(), expected_failed_count)
-    test_case.assertEqual(result.get_ignored_count(), expected_ignored_count)
-
-  script.add_build_step(build_step)
-  script.add_test_step(test_step)
-  script.run()
+  return [
+      _Verifier(
+          lambda test_case, result: test_case.assertEqual(
+              result.get_passed_count(), expected_passed_count
+          ),
+          'pass_count',
+      ),
+      _Verifier(
+          lambda test_case, result: test_case.assertEqual(
+              result.get_failed_count(), expected_failed_count
+          ),
+          'fail_count',
+      ),
+      _Verifier(
+          lambda test_case, result: test_case.assertEqual(
+              result.get_ignored_count(), expected_ignored_count
+          ),
+          'ignore_count',
+      ),
+  ]
 
 
 def _run_and_verify(
     test_case: atest_integration_test.AtestTestCase,
     atest_command: str,
     is_device_required: bool,
-    verifier: Callable[
-        atest_integration_test.AtestTestCase,
-        atest_integration_test.AtestRunResult,
-    ],
+    verifiers: list[_Verifier],
 ):
   """Verify an atest command finished with expected result counts.
 
@@ -162,7 +181,7 @@ def _run_and_verify(
       atest_command: The atest command to execute. Note: exclude 'atest',
         'atest-dev', '-b', '-i', and '-t' from it.
       is_device_required: Whether the test requires a device.
-      verifier: function to call to verify the result.
+      verifiers: A list of verifiers to call to verify the result.
   """
 
   script = test_case.create_atest_script()
@@ -185,7 +204,9 @@ def _run_and_verify(
         print_output=False,
     )
 
-    verifier(test_case, result)
+    for verifier in verifiers:
+      with test_case.subTest(verifier.name):
+        verifier.do_verify(test_case, result)
 
   script.add_build_step(build_step)
   script.add_test_step(test_step)
diff --git a/atest/integration_tests/device_android_test/src/com.android.atest.example/DeviceAndroidTestNonStarting.java b/atest/integration_tests/device_android_test/src/com.android.atest.example/DeviceAndroidTestNonStarting.java
index 3e54fcb2..1298652a 100644
--- a/atest/integration_tests/device_android_test/src/com.android.atest.example/DeviceAndroidTestNonStarting.java
+++ b/atest/integration_tests/device_android_test/src/com.android.atest.example/DeviceAndroidTestNonStarting.java
@@ -16,7 +16,6 @@
 
 package com.android.atest.example;
 
-import android.util.Log;
 
 import org.junit.Assert;
 import org.junit.BeforeClass;
@@ -27,16 +26,13 @@ import org.junit.runners.JUnit4;
 @RunWith(JUnit4.class)
 public class DeviceAndroidTestNonStarting {
 
-    private static final String TAG = DeviceAndroidTestNonStarting.class.getSimpleName();
-
     @BeforeClass
     public static void beforeClass() {
         System.exit(1);
     }
 
     @Test
-    public void testPassingTest2of2() {
-        Log.d(TAG, "testPassingTest2of2()");
-        Assert.assertTrue(true);
+    public void testNotReachedDueToCrash() {
+        Assert.assertTrue(false);
     }
 }
diff --git a/atest/integration_tests/deviceless_python_test_host_multiclass/Android.bp b/atest/integration_tests/deviceless_python_test_host_multiclass/Android.bp
new file mode 100644
index 00000000..2fefb13c
--- /dev/null
+++ b/atest/integration_tests/deviceless_python_test_host_multiclass/Android.bp
@@ -0,0 +1,12 @@
+python_test_host {
+    name: "deviceless_python_test_host_multiclass",
+    main: "python_unittest_with_multiple_classes.py",
+    srcs: [
+        "python_unittest_with_multiple_classes.py",
+    ],
+    test_config: "python_unittest_config_example.xml",
+    test_suites: ["general-tests"],
+    test_options: {
+        unit_test: false,
+    },
+}
diff --git a/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_config_example.xml b/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_config_example.xml
new file mode 100644
index 00000000..cf9b83b6
--- /dev/null
+++ b/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_config_example.xml
@@ -0,0 +1,26 @@
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
+<configuration
+    description="Config for an example python binary host test suite">
+    <option name="test-suite-tag"
+        value="example_python_unittest_with_multiple_classes" />
+
+    <test class="com.android.tradefed.testtype.python.PythonBinaryHostTest" >
+        <option name="python-options" value="-vv" />
+        <option name="par-file-name" value="deviceless_python_test_host_multiclass" />
+        <option name="test-timeout" value="2m" />
+    </test>
+</configuration>
diff --git a/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_with_multiple_classes.py b/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_with_multiple_classes.py
new file mode 100644
index 00000000..c8b17966
--- /dev/null
+++ b/atest/integration_tests/deviceless_python_test_host_multiclass/python_unittest_with_multiple_classes.py
@@ -0,0 +1,46 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""A python unittest script that contains multiple test classes."""
+
+
+import unittest
+
+
+class ExampleOneTest(unittest.TestCase):
+
+  def test_example1_pass(self):
+    """A test which passes its assertion."""
+    self.assertEqual(1, 1)
+
+  def test_example1_fail(self):
+    """A test which fails its assertion."""
+    self.assertEqual(1, 2, 'Intentional fail')
+
+
+class ExampleTwoTest(unittest.TestCase):
+
+  def test_example2_pass(self):
+    """A test which passes its assertion."""
+    self.assertEqual(1, 1)
+
+  def test_example2_fail(self):
+    """A test which fails its assertion."""
+    self.assertEqual(1, 2, 'Intentional fail')
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/integration_tests/result_compare_test.py b/atest/integration_tests/result_compare_test.py
index 2da77cee..a71bce23 100755
--- a/atest/integration_tests/result_compare_test.py
+++ b/atest/integration_tests/result_compare_test.py
@@ -96,13 +96,10 @@ class ResultCompareTest(unittest.TestCase):
       )
 
     result_file_path = None
+    log_dir_prefix = 'Atest results and logs directory: '
     for line in completed_process.stdout.decode().splitlines():
-      if line.startswith('Test Logs have been saved in '):
-        result_file_path = Path(
-            re.sub('Test Logs have been saved in ', '', line).replace(
-                'log', result_file_name
-            )
-        )
+      if line.startswith(log_dir_prefix):
+        result_file_path = Path(line[len(log_dir_prefix) :]) / result_file_name
         break
 
     if not result_file_path:
diff --git a/atest/integration_tests/split_build_test_script.py b/atest/integration_tests/split_build_test_script.py
index bae93d29..c308c881 100644
--- a/atest/integration_tests/split_build_test_script.py
+++ b/atest/integration_tests/split_build_test_script.py
@@ -778,8 +778,13 @@ def _run_test(
           ' exist. Have you run the build mode with --tar_snapshot'
           ' option enabled?'
       )
+    logging.info(
+        'Extracting tar file %s',
+        config.snapshot_storage_tar_path,
+    )
     with tarfile.open(config.snapshot_storage_tar_path, 'r') as tar:
       tar.extractall(config.snapshot_storage_path.parent.as_posix())
+    logging.info('Done extracting tar file')
 
     logging.info(
         'Decompressing the snapshot storage with %s threads...',
diff --git a/atest/metrics/metrics.py b/atest/metrics/metrics.py
index ab654983..eb612107 100644
--- a/atest/metrics/metrics.py
+++ b/atest/metrics/metrics.py
@@ -13,7 +13,6 @@
 # limitations under the License.
 
 """Metrics class."""
-
 from atest import constants
 from atest.metrics import metrics_base
 
@@ -34,6 +33,8 @@ class AtestStartEvent(metrics_base.MetricsBase):
   test_references = constants.INTERNAL
   cwd = constants.INTERNAL
   os = constants.INTERNAL
+  source_root = constants.INTERNAL
+  hostname = constants.INTERNAL
 
 
 class AtestExitEvent(metrics_base.MetricsBase):
@@ -145,6 +146,8 @@ class LocalDetectEvent(metrics_base.MetricsBase):
       metrics.LocalDetectEvent(
           detect_type=0,
           result=0)
+      detect_type: a value from atest_enum.DetectType.
+      result: the value corresponding to the result of the detected event.
   """
 
   _EVENT_NAME = 'local_detect_event'
diff --git a/atest/metrics/metrics_base.py b/atest/metrics/metrics_base.py
index a6cfa2f7..370af201 100644
--- a/atest/metrics/metrics_base.py
+++ b/atest/metrics/metrics_base.py
@@ -179,6 +179,6 @@ class MetricsBase:
         A clientanalytics_pb2.LogEvent instance.
     """
     log_event = clientanalytics_pb2.LogEvent()
-    log_event.event_time_ms = int((time.time() - random.randint(1, 600)) * 1000)
+    log_event.event_time_ms = int(time.time() * 1000)
     log_event.source_extension = atest_event.SerializeToString()
     return log_event
diff --git a/atest/metrics/metrics_utils.py b/atest/metrics/metrics_utils.py
index a1944fbb..bd772af4 100644
--- a/atest/metrics/metrics_utils.py
+++ b/atest/metrics/metrics_utils.py
@@ -14,8 +14,6 @@
 
 """Utility functions for metrics."""
 
-import os
-import platform
 import sys
 import time
 import traceback
@@ -23,6 +21,7 @@ import traceback
 from atest.metrics import metrics
 from atest.metrics import metrics_base
 
+
 CONTENT_LICENSES_URL = 'https://source.android.com/setup/start/licenses'
 CONTRIBUTOR_AGREEMENT_URL = {
     'INTERNAL': 'https://cla.developers.google.com/',
@@ -112,34 +111,31 @@ def send_exit_event(exit_code, stacktrace='', logs=''):
 
 
 def send_start_event(
-    tool_name,
-    command_line='',
-    test_references='',
-    cwd=None,
-    operating_system=None,
+    command_line,
+    test_references,
+    cwd,
+    operating_system,
+    source_root,
+    hostname,
 ):
   """Log start event of clearcut.
 
   Args:
-      tool_name: A string of the asuite product name.
       command_line: A string of the user input command.
       test_references: A string of the input tests.
       cwd: A string of current path.
       operating_system: A string of user's operating system.
+      source_root: A string of the Android build source.
+      hostname: A string of the host workstation name.
   """
-  if not cwd:
-    cwd = os.getcwd()
-  if not operating_system:
-    operating_system = platform.platform()
-  # Without tool_name information, asuite's clearcut client will not send
-  # event to server.
-  metrics_base.MetricsBase.tool_name = tool_name
   get_start_time()
   metrics.AtestStartEvent(
       command_line=command_line,
       test_references=test_references,
       cwd=cwd,
       os=operating_system,
+      source_root=source_root,
+      hostname=hostname,
   )
 
 
diff --git a/atest/metrics/metrics_utils_unittest.py b/atest/metrics/metrics_utils_unittest.py
index c4463db8..2d6be117 100755
--- a/atest/metrics/metrics_utils_unittest.py
+++ b/atest/metrics/metrics_utils_unittest.py
@@ -23,7 +23,9 @@ import sys
 import unittest
 from unittest import mock
 
+from atest.metrics import metrics_base
 from atest.metrics import metrics_utils
+from atest.proto import internal_user_log_pb2
 
 
 class MetricsUtilsUnittests(unittest.TestCase):
@@ -65,3 +67,49 @@ class MetricsUtilsUnittests(unittest.TestCase):
     metrics_utils.print_data_collection_notice()
     sys.stdout = sys.__stdout__
     self.assertEqual(capture_output.getvalue(), notice_str)
+
+  def test_send_start_event(self):
+    metrics_base.MetricsBase.tool_name = 'test_tool'
+    metrics_base.MetricsBase.user_type = metrics_base.INTERNAL_USER
+    fake_cc = FakeClearcutClient()
+    metrics_base.MetricsBase.cc = fake_cc
+
+    metrics_utils.send_start_event(
+        command_line='test_command',
+        test_references=['test'],
+        cwd='cwd',
+        operating_system='test system',
+        source_root='test_source',
+        hostname='test_host',
+    )
+
+    logged_events = fake_cc.get_logged_events()
+    expected_start_event = (
+        internal_user_log_pb2.AtestLogEventInternal.AtestStartEvent(
+            command_line='test_command',
+            test_references=['test'],
+            cwd='cwd',
+            os='test system',
+            source_root='test_source',
+            hostname='test_host',
+        )
+    )
+    self.assertEqual(len(logged_events), 1)
+    self.assertEqual(
+        expected_start_event,
+        internal_user_log_pb2.AtestLogEventInternal.FromString(
+            logged_events[0].source_extension
+        ).atest_start_event,
+    )
+
+
+class FakeClearcutClient:
+
+  def __init__(self):
+    self.logged_event = []
+
+  def log(self, event):
+    self.logged_event.extend([event])
+
+  def get_logged_events(self):
+    return self.logged_event
diff --git a/atest/module_info.py b/atest/module_info.py
index d440e427..bee0bd61 100644
--- a/atest/module_info.py
+++ b/atest/module_info.py
@@ -1104,13 +1104,18 @@ class ModuleInfo:
 
     return modules
 
-  def get_modules_by_path(self, path: str, testable_modules_only: bool = False):
+  def get_modules_by_path(
+      self, path: str, testable_modules_only: bool = False
+  ) -> set[str]:
     """Get the module names that the give path belongs to.
 
     Args:
         path: dir path for searching among `path` in module information.
         testable_modules_only: boolean flag which determines whether search
           testable modules only or not.
+
+    Returns:
+        A set of module names.
     """
     modules = set()
     is_testable_module_fn = (
diff --git a/atest/module_info_unittest_base.py b/atest/module_info_unittest_base.py
index 6c1809c5..dd2fb8a6 100644
--- a/atest/module_info_unittest_base.py
+++ b/atest/module_info_unittest_base.py
@@ -22,6 +22,7 @@ object, for use in unit tests.
 import pathlib
 import tempfile
 
+from atest import atest_utils
 from atest import constants
 from atest import module_info
 from atest.test_finders import test_info
@@ -54,6 +55,13 @@ class ModuleInfoTest(fake_filesystem_unittest.TestCase):
     for m in modules:
       mod_info.name_to_module_info[m[constants.MODULE_INFO_ID]] = m
 
+    for m in modules:
+      for path in m[constants.MODULE_PATH]:
+        if not mod_info.path_to_module_info.get(path, []):
+          mod_info.path_to_module_info[path] = [m]
+        else:
+          mod_info.path_to_module_info[path].append(m)
+
     return mod_info
 
   def assertContainsSubset(self, expected_subset, actual_set):
@@ -87,10 +95,13 @@ def device_driven_test_module(
     host_deps=None,
     class_type=None,
     is_unit_test=None,
+    module_path=None,
+    srcs=None,
+    test_configs=None,
 ):
 
   name = name or 'hello_world_test'
-  module_path = 'example_module/project'
+  module_path = module_path or 'example_module/project'
 
   return test_module(
       name=name,
@@ -101,6 +112,8 @@ def device_driven_test_module(
       class_type=class_type or ['APP'],
       module_path=module_path,
       is_unit_test=is_unit_test,
+      srcs=srcs,
+      test_configs=test_configs,
   )
 
 
@@ -110,9 +123,11 @@ def device_driven_multi_config_test_module(
     compatibility_suites=None,
     host_deps=None,
     class_type=None,
+    module_path=None,
+    srcs=None,
 ):
 
-  module_path = 'example_module/project'
+  module_path = module_path or 'example_module/project'
   return test_module(
       name=name,
       supported_variants=['DEVICE'],
@@ -126,6 +141,7 @@ def device_driven_multi_config_test_module(
       host_deps=host_deps,
       class_type=class_type or ['APP'],
       module_path=module_path,
+      srcs=srcs,
   )
 
 
@@ -178,6 +194,7 @@ def test_module(
     class_type=None,
     module_path=None,
     is_unit_test=None,
+    srcs=None,
 ):
   """Creates a module object which with properties specific to a test module."""
   return module(
@@ -192,6 +209,7 @@ def test_module(
       class_type=class_type,
       module_path=[module_path],
       is_unit_test=is_unit_test,
+      srcs=srcs,
   )
 
 
@@ -207,6 +225,7 @@ def module(
     class_type=None,
     module_path=None,
     is_unit_test=None,
+    srcs=None,
 ):
   """Creates a ModuleInfo object.
 
@@ -227,5 +246,6 @@ def module(
   m[constants.MODULE_CLASS] = class_type or []
   m[constants.MODULE_PATH] = module_path or []
   m[constants.MODULE_IS_UNIT_TEST] = is_unit_test or 'false'
+  m[constants.MODULE_SRCS] = srcs or []
 
   return m
diff --git a/atest/proto/internal_user_log.proto b/atest/proto/internal_user_log.proto
index 0da92fff..f4bb6495 100644
--- a/atest/proto/internal_user_log.proto
+++ b/atest/proto/internal_user_log.proto
@@ -16,6 +16,8 @@ message AtestLogEventInternal {
     repeated string test_references = 2;
     optional string cwd = 3;
     optional string os = 4;
+    optional string source_root = 5;
+    optional string hostname = 6;
   }
 
   // Occurs when atest exits for any reason
@@ -75,7 +77,7 @@ message AtestLogEventInternal {
   optional UserType user_type = 3;
   optional string tool_name = 10;
   optional string sub_tool_name = 12;
-  optional string user_name = 13; // ldap of the internal users
+  optional string user_name = 13 [deprecated = true];
   oneof event {
     AtestStartEvent atest_start_event = 4;
     AtestExitEvent atest_exit_event = 5;
diff --git a/atest/result_reporter.py b/atest/result_reporter.py
index f83702cf..56ef7ee4 100644
--- a/atest/result_reporter.py
+++ b/atest/result_reporter.py
@@ -97,8 +97,6 @@ INT_KEYS = {}
 ITER_SUMMARY = {}
 ITER_COUNTS = {}
 
-_TEST_LOG_PATH_PRINT_PREFIX = 'Test Logs have been saved in '
-
 
 class PerfInfo:
   """Class for storing performance test of a test run."""
@@ -484,7 +482,6 @@ class ResultReporter:
     if self.log_path:
       # Print aggregate result if any.
       self._print_aggregate_test_metrics()
-      print(f'{_TEST_LOG_PATH_PRINT_PREFIX}{self.log_path}')
     # TODO(b/174535786) Error handling while uploading test results has
     # unexpected exceptions.
     # TODO (b/174627499) Saving this information in atest history.
@@ -567,9 +564,6 @@ class ResultReporter:
       for group_name, _ in groups.items():
         name = group_name if group_name else runner_name
         print(name)
-    print()
-    if self.log_path:
-      print(f'{_TEST_LOG_PATH_PRINT_PREFIX}{self.log_path}')
     return ExitCode.SUCCESS
 
   def print_failed_tests(self):
diff --git a/atest/result_reporter_unittest.py b/atest/result_reporter_unittest.py
index f79f5818..7281b827 100755
--- a/atest/result_reporter_unittest.py
+++ b/atest/result_reporter_unittest.py
@@ -21,7 +21,9 @@ from io import StringIO
 import sys
 import unittest
 from unittest import mock
+from unittest.mock import patch
 
+from atest import arg_parser
 from atest import atest_configs
 from atest import result_reporter
 from atest.test_runners import test_runner_base
@@ -452,11 +454,13 @@ class ResultReporterUnittests(unittest.TestCase):
     self.rr._update_stats(RESULT_ASSUMPTION_FAILED_TEST, group)
     self.assertEqual(group.assumption_failed, 2)
 
+  @patch.object(
+      atest_configs,
+      'GLOBAL_ARGS',
+      arg_parser.create_atest_arg_parser().parse_args([]),
+  )
   def test_print_summary_ret_val(self):
     """Test print_summary method's return value."""
-    atest_configs.GLOBAL_ARGS = mock.Mock()
-    atest_configs.GLOBAL_ARGS.aggregate_metric_filter = None
-
     # PASS Case
     self.rr.process_test_result(RESULT_PASSED_TEST)
     self.assertEqual(0, self.rr.print_summary())
@@ -467,11 +471,13 @@ class ResultReporterUnittests(unittest.TestCase):
     self.rr.process_test_result(RESULT_PASSED_TEST_MODULE_2)
     self.assertNotEqual(0, self.rr.print_summary())
 
+  @patch.object(
+      atest_configs,
+      'GLOBAL_ARGS',
+      arg_parser.create_atest_arg_parser().parse_args([]),
+  )
   def test_print_summary_ret_val_err_stat(self):
     """Test print_summary method's return value."""
-    atest_configs.GLOBAL_ARGS = mock.Mock()
-    atest_configs.GLOBAL_ARGS.aggregate_metric_filter = None
-
     # PASS Case
     self.rr.process_test_result(RESULT_PASSED_TEST)
     self.assertEqual(0, self.rr.print_summary())
@@ -482,6 +488,12 @@ class ResultReporterUnittests(unittest.TestCase):
     self.rr.process_test_result(RESULT_PASSED_TEST_MODULE_2)
     self.assertNotEqual(0, self.rr.print_summary())
 
+  def test_collect_tests_only_no_throw(self):
+    rr = result_reporter.ResultReporter(collect_only=True)
+    rr.process_test_result(RESULT_PASSED_TEST)
+
+    self.assertEqual(0, self.rr.print_collect_tests())
+
   def test_update_perf_info(self):
     """Test update_perf_info method."""
     group = result_reporter.RunStat()
diff --git a/atest/test_finders/module_finder.py b/atest/test_finders/module_finder.py
index bcbfc359..77756687 100644
--- a/atest/test_finders/module_finder.py
+++ b/atest/test_finders/module_finder.py
@@ -54,30 +54,35 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     self.module_info = module_info
 
   def _determine_modules_to_test(
-      self, path: str, file_path: str = None
-  ) -> List:
+      self, module_path: str, test_file_path: str = None
+  ) -> set[str]:
     """Determine which module the user is trying to test.
 
     Returns the modules to test. If there are multiple possibilities, will
     ask the user. Otherwise will return the only module found.
 
     Args:
-        path: String path of module to look for.
-        file_path: String path of input file.
+        module_path: String path of module to look for.
+        test_file_path: String path of input file where the test is found.
 
     Returns:
-        A list of the module names.
+        A set of the module names.
     """
     modules_to_test = set()
 
-    if file_path:
+    if test_file_path:
       modules_to_test = self.module_info.get_modules_by_path_in_srcs(
-          path=file_path,
+          path=test_file_path,
           testable_modules_only=True,
       )
 
+    # If a single module path matches contains the path of the given test file
+    # in its MODULE_SRCS, do not continue to extract modules.
+    if len(modules_to_test) == 1:
+      return modules_to_test
+
     modules_to_test |= self.module_info.get_modules_by_path(
-        path=path,
+        path=module_path,
         testable_modules_only=True,
     )
 
@@ -577,9 +582,9 @@ class ModuleFinder(test_finder_base.TestFinderBase):
       self,
       class_name: str,
       module_name: str = None,
-      rel_config: str = None,
+      rel_config_path: str = None,
       is_native_test: bool = False,
-  ) -> list[test_info.TestInfo]:
+  ) -> list[test_info.TestInfo] | None:
     """Find test files given a class name.
 
     If module_name and rel_config not given it will calculate it determine
@@ -588,7 +593,7 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     Args:
         class_name: A string of the test's class name.
         module_name: Optional. A string of the module name to use.
-        rel_config: Optional. A string of module dir no-absolute to repo root.
+        rel_config_path: Optional. A string of module dir relative to repo root.
         is_native_test: A boolean variable of whether to search for a native
           test or not.
 
@@ -602,24 +607,28 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     # matched TEST_P to make sure test class is matched.
     if '/' in search_class_name:
       search_class_name = str(search_class_name).split('/')[-1]
-    if rel_config:
-      search_dir = os.path.join(self.root_dir, os.path.dirname(rel_config))
-    else:
-      search_dir = self.root_dir
-    test_paths = test_finder_utils.find_class_file(
-        search_dir, search_class_name, is_native_test, methods
-    )
-    if not test_paths and rel_config:
-      atest_utils.print_and_log_info(
-          'Did not find class (%s) under module path (%s), '
-          'researching from repo root.',
-          class_name,
-          rel_config,
+
+    test_paths = []
+    # Search using the path where the config file is located.
+    if rel_config_path:
+      test_paths = test_finder_utils.find_class_file(
+          os.path.join(self.root_dir, os.path.dirname(rel_config_path)),
+          search_class_name,
+          is_native_test,
+          methods,
       )
+      if not test_paths:
+        atest_utils.print_and_log_info(
+            'Did not find class (%s) under module path (%s), '
+            'researching from repo root.',
+            class_name,
+            rel_config_path,
+        )
+    # Search from the root dir.
+    if not test_paths:
       test_paths = test_finder_utils.find_class_file(
           self.root_dir, search_class_name, is_native_test, methods
       )
-    test_paths = test_paths if test_paths is not None else []
     # If we already have module name, use path in module-info as test_path.
     if not test_paths:
       if not module_name:
@@ -629,6 +638,7 @@ class ModuleFinder(test_finder_base.TestFinderBase):
       test_paths = []
       for rel_module_path in module_paths:
         test_paths.append(os.path.join(self.root_dir, rel_module_path))
+
     tinfos = []
     for test_path in test_paths:
       test_filter = self._get_test_info_filter(
@@ -638,13 +648,14 @@ class ModuleFinder(test_finder_base.TestFinderBase):
           is_native_test=is_native_test,
       )
       test_infos = self._get_test_infos(
-          test_path, rel_config, module_name, test_filter
+          test_path, rel_config_path, module_name, test_filter
       )
       # If input include methods, check if tinfo match.
       if test_infos and len(test_infos) > 1 and methods:
         test_infos = self._get_matched_test_infos(test_infos, methods)
       if test_infos:
         tinfos.extend(test_infos)
+
     return tinfos if tinfos else None
 
   def _get_matched_test_infos(self, test_infos, methods):
diff --git a/atest/test_finders/module_finder_unittest.py b/atest/test_finders/module_finder_unittest.py
index 0bcaa8df..fc6db565 100755
--- a/atest/test_finders/module_finder_unittest.py
+++ b/atest/test_finders/module_finder_unittest.py
@@ -119,7 +119,7 @@ def classoutside_side_effect(find_cmd, shell=False):
   return None
 
 
-class ModuleFinderFindTestByModuleName(
+class ModuleFinderFindTestByModuleClassName(
     module_info_unittest_base.ModuleInfoTest
 ):
 
@@ -148,18 +148,13 @@ class ModuleFinderFindTestByModuleName(
           'example_module-project',
       )
 
-  @mock.patch.object(
-      test_finder_utils, 'find_parent_module_dir', return_value='/main'
-  )
   @mock.patch(
       'subprocess.check_output',
       return_value=(
           'path/to/testmodule/src/com/android/myjavatests/MyJavaTestClass.java'
       ),
   )
-  def test_find_test_by_module_class_name_native_found(
-      self, find_cmd, found_file_path
-  ):
+  def test_find_test_by_module_class_name_native_found(self, find_cmd):
     module_name = 'MyModuleTestCases'
     test_module = module_info_unittest_base.device_driven_test_module(
         name=module_name, class_type=['NATIVE_TESTS']
@@ -184,33 +179,31 @@ class ModuleFinderFindTestByModuleName(
           'example_module-project',
       )
 
-  @mock.patch.object(
-      test_finder_utils, 'find_parent_module_dir', return_value='/main'
-  )
   @mock.patch(
       'subprocess.check_output',
-      return_value=(
-          'path/to/testmodule/src/com/android/myjavatests/MyJavaTestClass.java'
-      ),
   )
-  def test_find_test_by_module_class_name_unknown_test_info_is_none(
-      self, find_cmd, found_file_path
+  def test_find_test_by_module_class_module_name_unknown_test_info_is_none(
+      self, find_cmd
   ):
-    test_class_name = 'MyJavaTestClass'
+    self.create_module_paths(['/project/module'])
+    test_file_src = self.create_class_in_module(
+        module_path='/project/module', class_name='MyJavaTestClass.java'
+    )
     test_module = module_info_unittest_base.device_driven_test_module(
-        name='MyModuleTestCases', class_type=['NATIVE_TESTS']
+        name='MyModuleTestCases',
+        class_type=['NATIVE_TESTS'],
+        module_path='project/module',
+        srcs=[test_file_src],
     )
+    find_cmd.return_value = test_file_src
     finder = self.create_finder_with_module(test_module)
 
     t_infos = finder.find_test_by_class_name(
-        class_name=test_class_name, module_name='Unknown'
+        class_name='MyJavaTestClass', module_name='Unknown'
     )
 
     self.assertIsNone(t_infos)
 
-  @mock.patch.object(
-      test_finder_utils, 'find_parent_module_dir', return_value='/main'
-  )
   @mock.patch(
       'subprocess.check_output',
       return_value=[
@@ -218,15 +211,10 @@ class ModuleFinderFindTestByModuleName(
       ],
   )
   @mock.patch.object(
-      test_finder_utils,
-      'extract_selected_tests',
-      return_value=[
-          'example_module/project/configs/Config1.xml',
-          'example_module/project/configs/Config2.xml',
-      ],
+      test_finder_utils, 'get_multiple_selection_answer', return_value='A'
   )
   def test_find_test_by_module_class_multiple_configs_tests_found(
-      self, mock_user_selection, mock_run_cmd, mock_parent_dir
+      self, mock_test_selection, mock_run_cmd
   ):
     module_name = 'MyModuleTestCases'
     test_module = (
@@ -273,9 +261,233 @@ class ModuleFinderFindTestByModuleName(
           'example_module-project',
       )
 
-  def create_finder_with_module(self, test_module):
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_class_unique_class_name_finds_class(self, mock_run_cmd):
+    self.create_module_paths(['/project/tests/module1'])
+    test_file_src = self.create_class_in_module(
+        '/project/tests/module1', 'ClassOneTest.java'
+    )
+    mock_run_cmd.return_value = test_file_src
+    test_module = module_info_unittest_base.device_driven_test_module(
+        name='module_name',
+        module_path='project/tests/module1',
+        srcs=[
+            test_file_src,
+            '/project/tests/module1/src/tests/test2/ClassTwoTest.java',
+        ],
+    )
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_class_name(class_name='ClassOneTest')
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+    with self.subTest(name='test_info_has_expected_module_name'):
+      self.assert_test_info_has_test_name(
+          t_infos[0], test_module.get(constants.MODULE_NAME, [])
+      )
+    with self.subTest(name='contains_expected_class_filter'):
+      self.assert_test_info_has_class_filter(
+          t_infos[0], 'project.tests.module1.ClassOneTest'
+      )
+
+  @mock.patch.object(test_finder_utils, 'get_multiple_selection_answer')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_class_multiple_class_names_returns_selection_menu(
+      self, mock_run_cmd, mock_test_selection
+  ):
+    self.create_module_paths(
+        ['/tests/android/module1', '/tests/android/module2']
+    )
+    test1_file_src = self.create_class_in_module(
+        '/tests/android/module1', 'ClassOneTest.java'
+    )
+    test2_file_src = self.create_class_in_module(
+        '/tests/android/module2', 'ClassOneTest.java'
+    )
+    mock_run_cmd.return_value = test1_file_src + '\n' + test2_file_src
+    mock_test_selection.return_value = '0'
+    test1_module = module_info_unittest_base.device_driven_test_module(
+        name='module1',
+        module_path='tests/android/module1',
+        srcs=[test1_file_src],
+    )
+    test2_module = module_info_unittest_base.device_driven_test_module(
+        name='module2',
+        module_path='tests/android/module2',
+        srcs=[test2_file_src],
+    )
+    finder = self.create_finder_with_multiple_modules(
+        [test1_module, test2_module]
+    )
+
+    t_infos = finder.find_test_by_class_name(class_name='ClassOneTest')
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+    with self.subTest(name='test_info_has_expected_module_name'):
+      self.assert_test_info_has_test_name(
+          t_infos[0], test1_module.get(constants.MODULE_NAME, [])
+      )
+    with self.subTest(name='contains_expected_class_filter'):
+      self.assert_test_info_has_class_filter(
+          t_infos[0], 'tests.android.module1.ClassOneTest'
+      )
+
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_class_multiple_classes_in_module_finds_class(
+      self, mock_run_cmd
+  ):
+    self.create_module_paths(['/tests/android/module'])
+    test1_file_src = self.create_class_in_module(
+        '/tests/android/module', 'ClassOneTest.java'
+    )
+    test2_file_src = self.create_class_in_module(
+        '/tests/android/module', 'ClassTwoTest.java'
+    )
+    mock_run_cmd.return_value = test1_file_src
+    test_module = module_info_unittest_base.device_driven_test_module(
+        name='module1',
+        module_path='tests/android/module',
+        srcs=[test1_file_src, test2_file_src],
+    )
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_class_name(class_name='ClassOneTest')
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+    with self.subTest(name='test_info_has_expected_module_name'):
+      self.assert_test_info_has_test_name(
+          t_infos[0], test_module.get(constants.MODULE_NAME, [])
+      )
+    with self.subTest(name='contains_expected_class_filter'):
+      self.assert_test_info_has_class_filter(
+          t_infos[0], 'tests.android.module.ClassOneTest'
+      )
+
+  @mock.patch('atest.module_info.Loader.get_testable_module_from_memory')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_class_multiple_modules_with_same_path_finds_class(
+      self, mock_run_cmd, mock_loader
+  ):
+    self.create_module_paths(['/tests/android/multi_module'])
+    test1_file_src = self.create_class_in_module(
+        '/tests/android/multi_module', 'ClassOneTest.java'
+    )
+    test2_file_src = self.create_class_in_module(
+        '/tests/android/multi_module', 'ClassTwoTest.java'
+    )
+    mock_run_cmd.return_value = test1_file_src
+    test1_module = module_info_unittest_base.device_driven_test_module(
+        name='multi_module1',
+        module_path='tests/android/multi_module',
+        srcs=[test1_file_src],
+    )
+    test2_module = module_info_unittest_base.device_driven_test_module(
+        name='multi_module2',
+        module_path='tests/android/multi_module',
+        srcs=[test2_file_src],
+    )
+    finder = self.create_finder_with_multiple_modules(
+        [test1_module, test2_module]
+    )
+    mock_loader.return_value = set(
+        finder.module_info.name_to_module_info.keys()
+    )
+
+    t_infos = finder.find_test_by_class_name(class_name='ClassOneTest')
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+    with self.subTest(name='test_info_has_expected_module_name'):
+      self.assert_test_info_has_test_name(
+          t_infos[0], test1_module.get(constants.MODULE_NAME, [])
+      )
+    with self.subTest(name='contains_expected_class_filter'):
+      self.assert_test_info_has_class_filter(
+          t_infos[0], 'tests.android.multi_module.ClassOneTest'
+      )
+
+  @mock.patch.object(test_finder_utils, 'get_multiple_selection_answer')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_class_multiple_configs_one_test_per_config_found(
+      self, mock_run_cmd, mock_test_selection
+  ):
+    module_name = 'multi_config_module'
+    module_path = 'tests/android/multi_config_module'
+    mock_test_selection.return_value = 'A'
+    test1_file_src = self.create_class_in_module(
+        '/tests/android/multi_config_module', 'ClassOneTest.java'
+    )
+    test_module = (
+        module_info_unittest_base.device_driven_multi_config_test_module(
+            name=module_name,
+            module_path=module_path,
+            srcs=[test1_file_src],
+        )
+    )
+    mock_run_cmd.return_value = test1_file_src
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_class_name(class_name='ClassOneTest')
+
+    with self.subTest(name='returns_two_test_info'):
+      self.assertEqual(len(t_infos), 2)
+    with self.subTest(name='first_test_name_corresponds_to_module_name'):
+      self.assert_test_info_has_test_name(t_infos[0], module_name)
+    with self.subTest(name='second_test_name_corresponds_to_config_name'):
+      self.assert_test_info_has_test_name(t_infos[1], 'Config2')
+    with self.subTest(name='contains_expected_class_filter'):
+      self.assert_test_info_has_class_filter(
+          t_infos[0], 'tests.android.multi_config_module.ClassOneTest'
+      )
+      self.assert_test_info_has_config(
+          t_infos[0], f'{module_path}/configs/Config1.xml'
+      )
+      self.assert_test_info_has_class_filter(
+          t_infos[1], 'tests.android.multi_config_module.ClassOneTest'
+      )
+      self.assert_test_info_has_config(
+          t_infos[1], f'{module_path}/configs/Config2.xml'
+      )
+    with self.subTest(name='raw_test_name_corresponds_to_module_name'):
+      self.assert_test_info_has_raw_test_name(t_infos[0], module_name)
+      self.assert_test_info_has_raw_test_name(t_infos[1], module_name)
+    with self.subTest(name='contains_expected_build_targets'):
+      self.assert_test_info_contains_build_targets(t_infos[0], module_name)
+      self.assert_test_info_contains_build_targets(
+          t_infos[0],
+          module_name,
+      )
+      self.assert_test_info_contains_build_targets(t_infos[1], module_name)
+      self.assert_test_info_contains_build_targets(
+          t_infos[1],
+          module_name,
+      )
+
+  def create_class_in_module(self, module_path: str, class_name: str) -> str:
+    file_path = module_path + '/src/' + class_name
+    self.fs.create_file(
+        file_path, contents='package ' + module_path[1:].replace('/', '.')
+    )
+    return file_path
+
+  def create_module_paths(self, modules: list[str]):
+    for m in modules:
+      module_path = pathlib.Path(m)
+      module_path.mkdir(parents=True, exist_ok=True)
+
+  def create_finder_with_module(
+      self, test_module: dict
+  ) -> module_finder.ModuleFinder:
     return module_finder.ModuleFinder(self.create_module_info([test_module]))
 
+  def create_finder_with_multiple_modules(
+      self, test_modules: list[dict]
+  ) -> module_finder.ModuleFinder:
+    return module_finder.ModuleFinder(self.create_module_info(test_modules))
+
   def assert_test_info_has_test_name(
       self, t_info: test_info.TestInfo, test_name: str
   ):
@@ -1138,7 +1350,7 @@ class ModuleFinderUnittests(unittest.TestCase):
     t_infos = self.mod_finder.find_test_by_class_name(
         uc.FULL_CLASS_NAME,
         module_name=uc.MODULE_NAME,
-        rel_config=uc.CONFIG_FILE,
+        rel_config_path=uc.CONFIG_FILE,
     )
     unittest_utils.assert_equal_testinfos(self, t_infos[0], uc.CLASS_INFO)
 
diff --git a/atest/test_finders/test_finder_utils.py b/atest/test_finders/test_finder_utils.py
index d8a6fb72..2ffd0134 100644
--- a/atest/test_finders/test_finder_utils.py
+++ b/atest/test_finders/test_finder_utils.py
@@ -154,6 +154,10 @@ _VTS_APK = 'apk'
 _VTS_BINARY_SRC_DELIM_RE = re.compile(r'.*::(?P<target>.*)$')
 _VTS_OUT_DATA_APP_PATH = 'DATA/app'
 
+# Auxiliary options for multiple test selector
+_ALL_OPTION = 'A'
+_CANCEL_OPTION = 'C'
+
 
 def has_cc_class(test_path):
   """Find out if there is any test case in the cc file.
@@ -313,6 +317,7 @@ def extract_selected_tests(tests: Iterable, default_all=False) -> List[str]:
 
   Return the test to run from tests. If more than one option, prompt the user
   to select multiple ones. Supporting formats:
+  - A string for the auxiliary menu: A for All, C for Cancel
   - An integer. E.g. 0
   - Comma-separated integers. E.g. 1,3,5
   - A range of integers denoted by the starting integer separated from
@@ -330,25 +335,26 @@ def extract_selected_tests(tests: Iterable, default_all=False) -> List[str]:
     return tests if count else None
 
   extracted_tests = set()
-  # Establish 'All' and 'Quit' options in the numbered test menu.
-  auxiliary_menu = ['All', 'Quit']
-  _tests = tests.copy()
-  _tests.extend(auxiliary_menu)
-  numbered_list = ['%s: %s' % (i, t) for i, t in enumerate(_tests)]
-  all_index = len(numbered_list) - auxiliary_menu[::-1].index('All') - 1
-  quit_index = len(numbered_list) - auxiliary_menu[::-1].index('Quit') - 1
-  print('Multiple tests found:\n{0}'.format('\n'.join(numbered_list)))
+  auxiliary_menu = [f'{_ALL_OPTION}: All', f'{_CANCEL_OPTION}: Cancel']
+  numbered_list = ['%s: %s' % (i, t) for i, t in enumerate(tests)]
+  print(
+      'Multiple tests found:\n{0}'.format(
+          '\n'.join(auxiliary_menu + numbered_list)
+      )
+  )
 
   start_prompt = time.time()
-  test_indices = get_multiple_selection_answer(quit_index)
-  selections = get_selected_indices(test_indices, limit=len(numbered_list) - 1)
-  if all_index in selections:
+  answer = get_multiple_selection_answer()
+  if _ALL_OPTION in answer.upper():
     extracted_tests = tests
-  elif quit_index in selections:
+  elif _CANCEL_OPTION in answer.upper():
     atest_utils.colorful_print('Abort selection.', constants.RED)
     sys.exit(0)
   else:
-    extracted_tests = {tests[s] for s in selections}
+    extracted_tests = {
+        tests[index]
+        for index in get_selected_indices(answer, limit=len(numbered_list) - 1)
+    }
   metrics.LocalDetectEvent(
       detect_type=DetectType.INTERACTIVE_SELECTION,
       result=int(time.time() - start_prompt),
@@ -357,17 +363,16 @@ def extract_selected_tests(tests: Iterable, default_all=False) -> List[str]:
   return list(extracted_tests)
 
 
-def get_multiple_selection_answer(quit_index) -> str:
+def get_multiple_selection_answer() -> str:
   """Get the answer from the user input."""
   try:
     return input(
-        'Please enter numbers of test to use. If none of the above'
-        'options matched, keep searching for other possible tests.'
+        'Please select an option.'
         '\n(multiple selection is supported, '
         "e.g. '1' or '0,1' or '0-2'): "
     )
   except KeyboardInterrupt:
-    return str(quit_index)
+    return _CANCEL_OPTION
 
 
 def get_selected_indices(string: str, limit: int = None) -> Set[int]:
@@ -526,6 +531,8 @@ def find_parent_module_dir(root_dir, start_dir, module_info):
     raise ValueError('%s not in repo %s' % (start_dir, root_dir))
   auto_gen_dir = None
   current_dir = start_dir
+  # Look for AndroidTest.xml config starting in the current dir up to the root
+  # dir.
   while current_dir != root_dir:
     # TODO (b/112904944) - migrate module_finder functions to here and
     # reuse them.
@@ -541,7 +548,7 @@ def find_parent_module_dir(root_dir, start_dir, module_info):
       if module_info.is_legacy_robolectric_class(mod):
         return rel_dir
       for test_config in mod.get(constants.MODULE_TEST_CONFIG, []):
-        # If the test config doesn's exist until it was auto-generated
+        # If the test config doesn't exist until it was auto-generated
         # in the build time(under <android_root>/out), atest still
         # recognizes it testable.
         if test_config:
diff --git a/atest/test_finders/test_finder_utils_unittest.py b/atest/test_finders/test_finder_utils_unittest.py
index d89a27a6..36b21b63 100755
--- a/atest/test_finders/test_finder_utils_unittest.py
+++ b/atest/test_finders/test_finder_utils_unittest.py
@@ -21,6 +21,7 @@
 
 import os
 from pathlib import Path
+import sys
 import tempfile
 import unittest
 from unittest import mock
@@ -229,46 +230,72 @@ class TestFinderUtilsUnittests(unittest.TestCase):
         test_finder_utils.extract_selected_tests(uc.CLASS_NAME), []
     )
 
-  @mock.patch('builtins.input', return_value='1')
+  @mock.patch('builtins.input')
   def test_extract_test_from_multiselect(self, mock_input):
     """Test method extract_selected_tests method."""
-    # selecting 'All'
-    paths = ['/a/b/c.java', '/d/e/f.java', '/g/h/i.java']
-    mock_input.return_value = '3'
-    unittest_utils.assert_strict_equal(
-        self,
-        sorted(test_finder_utils.extract_selected_tests(FIND_THREE_LIST)),
-        sorted(paths),
-    )
     # multi-select
     paths = ['/a/b/c.java', '/g/h/i.java']
     mock_input.return_value = '0,2'
+
     unittest_utils.assert_strict_equal(
         self,
         sorted(test_finder_utils.extract_selected_tests(FIND_THREE_LIST)),
         sorted(paths),
     )
+
     # selecting a range
     paths = ['/d/e/f.java', '/g/h/i.java']
     mock_input.return_value = '1-2'
+
     unittest_utils.assert_strict_equal(
         self, test_finder_utils.extract_selected_tests(FIND_THREE_LIST), paths
     )
+
     # mixed formats
     paths = ['/a/b/c.java', '/d/e/f.java', '/g/h/i.java']
     mock_input.return_value = '0,1-2'
+
     unittest_utils.assert_strict_equal(
         self,
         sorted(test_finder_utils.extract_selected_tests(FIND_THREE_LIST)),
         sorted(paths),
     )
+
     # input unsupported formats, return empty
     paths = []
     mock_input.return_value = '?/#'
+
     unittest_utils.assert_strict_equal(
         self, test_finder_utils.extract_test_path(FIND_THREE), paths
     )
 
+  @mock.patch('builtins.input')
+  @mock.patch.object(test_finder_utils, 'get_selected_indices')
+  def test_multiselect_auxiliary_menu_all_returns_all_tests(
+      self, mock_get_selected_indices, mock_input):
+    paths = ['/a/b/c.java', '/d/e/f.java', '/g/h/i.java']
+    mock_input.return_value = 'A'
+
+    unittest_utils.assert_strict_equal(
+        self,
+        sorted(test_finder_utils.extract_selected_tests(FIND_THREE_LIST)),
+        sorted(paths),
+    )
+    mock_get_selected_indices.assert_not_called()
+
+  @mock.patch('builtins.input')
+  @mock.patch.object(sys, 'exit')
+  @mock.patch.object(test_finder_utils, 'get_selected_indices')
+  def test_multiselect_auxiliary_menu_lowercase_cancel_returns_empty_list(
+      self, mock_get_selected_indices, mock_exit, mock_input):
+    # Cancelling the command
+    mock_input.return_value = 'c'
+
+    test_finder_utils.extract_selected_tests(FIND_THREE_LIST)
+
+    mock_exit.assert_called_once_with(0)
+    mock_get_selected_indices.assert_not_called()
+
   @mock.patch('os.path.isdir')
   def test_is_equal_or_sub_dir(self, mock_isdir):
     """Test is_equal_or_sub_dir method."""
diff --git a/atest/test_runner_invocation.py b/atest/test_runner_invocation.py
index 56e76495..e225f612 100644
--- a/atest/test_runner_invocation.py
+++ b/atest/test_runner_invocation.py
@@ -16,7 +16,6 @@
 
 from __future__ import annotations
 
-import os
 import time
 import traceback
 from typing import Any, Dict, List, Set
@@ -27,18 +26,6 @@ from atest.metrics import metrics
 from atest.metrics import metrics_utils
 from atest.test_finders import test_info
 from atest.test_runners import test_runner_base
-from atest.test_runners.event_handler import EventHandleError
-
-# Look for this in tradefed log messages.
-TRADEFED_EARLY_EXIT_LOG_SIGNAL = (
-    'INSTRUMENTATION_RESULT: shortMsg=Process crashed'
-)
-
-# Print this to user.
-TRADEFED_EARLY_EXIT_ATEST_MSG = (
-    'Test failed because instrumentation process died.'
-    ' Please check your device logs.'
-)
 
 
 class TestRunnerInvocation:
@@ -81,13 +68,6 @@ class TestRunnerInvocation:
       tests_ret_code = self._test_runner.run_tests(
           self._test_infos, self._extra_args, reporter
       )
-    except EventHandleError:
-      is_success = False
-      if self.log_shows_early_exit():
-        err_msg = TRADEFED_EARLY_EXIT_ATEST_MSG
-      else:
-        err_msg = traceback.format_exc()
-
     except Exception:  # pylint: disable=broad-except
       is_success = False
       err_msg = traceback.format_exc()
@@ -120,16 +100,3 @@ class TestRunnerInvocation:
     )
 
     return tests_ret_code
-
-  def log_shows_early_exit(self) -> bool:
-    """Grep the log file for TF process crashed message."""
-    # Ensure file exists and is readable.
-    if not os.access(self._test_runner.test_log_file.name, os.R_OK):
-      return False
-
-    with open(self._test_runner.test_log_file.name, 'r') as log_file:
-      for line in log_file:
-        if TRADEFED_EARLY_EXIT_LOG_SIGNAL in line:
-          return True
-
-    return False
diff --git a/atest/test_runners/atest_tf_test_runner.py b/atest/test_runners/atest_tf_test_runner.py
index e0a98244..cd15f293 100644
--- a/atest/test_runners/atest_tf_test_runner.py
+++ b/atest/test_runners/atest_tf_test_runner.py
@@ -46,6 +46,7 @@ from atest.logstorage import logstorage_utils
 from atest.metrics import metrics
 from atest.test_finders import test_finder_utils
 from atest.test_finders import test_info
+from atest.test_finders.test_info import TestInfo
 from atest.test_runner_invocation import TestRunnerInvocation
 from atest.test_runners import test_runner_base as trb
 from atest.test_runners.event_handler import EventHandler
@@ -848,7 +849,7 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
           else self._TF_DEVICE_TEST_TEMPLATE
       )
 
-    args = self._create_test_args(test_infos)
+    args = self._create_test_args(test_infos, extra_args)
 
     # Create a copy of args as more args could be added to the list.
     test_args = list(args)
@@ -931,7 +932,7 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
       test_args.extend(atest_utils.get_result_server_args(for_test_mapping))
     self.run_cmd_dict['args'] = ' '.join(test_args)
     self.run_cmd_dict['tf_customize_template'] = (
-        self._extract_customize_tf_templates(extra_args, test_infos)
+        self._extract_customize_tf_templates(extra_args)
     )
 
     # By default using ATestFileSystemLogSaver no matter what running under
@@ -1061,11 +1062,14 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
         return False
     return True
 
-  def _create_test_args(self, test_infos):
+  def _create_test_args(
+      self, test_infos: list[TestInfo], extra_args: Dict[str, Any]
+  ) -> list[str]:
     """Compile TF command line args based on the given test infos.
 
     Args:
         test_infos: A list of TestInfo instances.
+        extra_args: A Dict of extra args for test runners to utilize.
 
     Returns: A list of TF arguments to run the tests.
     """
@@ -1122,7 +1126,11 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
           args.extend([constants.TF_MODULE_ARG, module_arg])
 
     # Add ATest include filter
-    args.extend(get_include_filter(test_infos))
+    args.extend(
+        get_include_filter(
+            test_infos, extra_args.get(constants.TEST_FILTER, None)
+        )
+    )
 
     # TODO (b/141090547) Pass the config path to TF to load configs.
     # Compile option in TF if finder is not INTEGRATION or not set.
@@ -1145,27 +1153,16 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     ]
     return ' '.join(extracted_options)
 
-  def _extract_customize_tf_templates(self, extra_args, test_infos):
+  def _extract_customize_tf_templates(self, extra_args: dict[str]) -> str:
     """Extract tradefed template options to a string for output.
 
     Args:
         extra_args: Dict of extra args for test runners to use.
-        test_infos: A set of TestInfo instances.
 
-    Returns: A string of tradefed template options.
+    Returns:
+        A string of tradefed template options.
     """
     tf_templates = extra_args.get(constants.TF_TEMPLATE, [])
-    tf_template_keys = [i.split('=')[0] for i in tf_templates]
-    for info in test_infos:
-      if (
-          info.aggregate_metrics_result
-          and 'metric_post_processor' not in tf_template_keys
-      ):
-        template_key = 'metric_post_processor'
-        template_value = (
-            'google/template/postprocessors/metric-file-aggregate-disabled'
-        )
-        tf_templates.append(f'{template_key}={template_value}')
     return ' '.join(['--template:map %s' % x for x in tf_templates])
 
   def _handle_log_associations(self, event_handlers):
@@ -1495,11 +1492,15 @@ def extra_args_to_tf_args(
   return supported_args, unsupported_args
 
 
-def get_include_filter(test_infos: List[test_info.TestInfo]) -> List[str]:
+def get_include_filter(
+    test_infos: List[test_info.TestInfo], test_filter_arg: str = None
+) -> List[str]:
   """Generate a list of tradefed filter argument from TestInfos.
 
   Args:
       test_infos: a List of TestInfo object.
+      test_filter_arg: the value of the desired test filter passed by the user
+        using the --test-filter flag.
 
   The include filter pattern looks like:
       --atest-include-filter <module-name>:<include-filter-value>
@@ -1507,19 +1508,27 @@ def get_include_filter(test_infos: List[test_info.TestInfo]) -> List[str]:
   Returns:
       List of Tradefed command args.
   """
-  instrumentation_filters = []
   tf_args = []
   for info in test_infos:
+    # If a --test-filter is specified by the user, use the test filter in addition to the
+    # fully qualified module:test#method name for each test.
+    if test_filter_arg:
+      formatted_test_filter_arg = (
+          constants.TF_ATEST_INCLUDE_FILTER_VALUE_FMT.format(
+              test_name=info.test_name, test_filter=test_filter_arg
+          )
+      )
+      tf_args.extend(
+          [constants.TF_ATEST_INCLUDE_FILTER, formatted_test_filter_arg]
+      )
     filters = []
     for test_info_filter in info.data.get(constants.TI_FILTER, []):
       filters.extend(test_info_filter.to_list_of_tf_strings())
-
     for test_filter in filters:
       filter_arg = constants.TF_ATEST_INCLUDE_FILTER_VALUE_FMT.format(
           test_name=info.test_name, test_filter=test_filter
       )
       tf_args.extend([constants.TF_ATEST_INCLUDE_FILTER, filter_arg])
-
   return tf_args
 
 
@@ -1619,8 +1628,7 @@ class DeviceTest(Test):
     # can't determine whether they require device update or not. So that we
     # treat them as they require device update to avoid disabling the device
     # update mistakenly.
-    return not self._info or not module_info.ModuleInfo.is_unit_test(
-        self._info)
+    return not self._info or not module_info.ModuleInfo.is_unit_test(self._info)
 
   def _get_test_build_targets(self) -> Set[Target]:
     module_name = self._info[constants.MODULE_INFO_ID]
diff --git a/atest/test_runners/atest_tf_test_runner_unittest.py b/atest/test_runners/atest_tf_test_runner_unittest.py
index d93e596b..f44b079e 100755
--- a/atest/test_runners/atest_tf_test_runner_unittest.py
+++ b/atest/test_runners/atest_tf_test_runner_unittest.py
@@ -20,7 +20,6 @@
 # pylint: disable=too-many-lines
 # pylint: disable=unused-argument
 
-from argparse import Namespace
 from io import StringIO
 import json
 import os
@@ -30,6 +29,8 @@ import sys
 import tempfile
 import unittest
 from unittest import mock
+
+from atest import arg_parser
 from atest import atest_configs
 from atest import atest_utils
 from atest import constants
@@ -287,9 +288,9 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     self.tr = atf_tr.AtestTradefedTestRunner(
         results_dir=uc.TEST_INFO_DIR, extra_args={constants.HOST: False}
     )
-    if not atest_configs.GLOBAL_ARGS:
-      atest_configs.GLOBAL_ARGS = Namespace()
-    atest_configs.GLOBAL_ARGS.device_count_config = None
+    self._global_args = arg_parser.create_atest_arg_parser().parse_args([])
+    self._global_args.device_count_config = 0
+    mock.patch.object(atest_configs, 'GLOBAL_ARGS', self._global_args).start()
 
   def tearDown(self):
     mock.patch.stopall()
@@ -793,26 +794,41 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     # Only compile '--skip-loading-config-jar' in TF if it's not
     # INTEGRATION finder or the finder property isn't set.
     mock_config.return_value = '', ''
-    args = self.tr._create_test_args([MOD_INFO])
+    args = self.tr._create_test_args([MOD_INFO], {})
     self.assertTrue(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
-    args = self.tr._create_test_args([INT_INFO])
+    args = self.tr._create_test_args([INT_INFO], {})
     self.assertFalse(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
-    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER])
+    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER], {})
     self.assertFalse(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
-    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER, INT_INFO])
+    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER, INT_INFO], {})
     self.assertFalse(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
-    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER])
+    args = self.tr._create_test_args([MOD_INFO_NO_TEST_FINDER], {})
     self.assertFalse(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
     args = self.tr._create_test_args(
-        [MOD_INFO_NO_TEST_FINDER, INT_INFO, MOD_INFO]
+        [MOD_INFO_NO_TEST_FINDER, INT_INFO, MOD_INFO], {}
     )
     self.assertFalse(constants.TF_SKIP_LOADING_CONFIG_JAR in args)
 
+  @mock.patch.object(test_finder_utils, 'get_test_config_and_srcs')
+  def test_create_test_args_with_test_filter_appends_to_atest_include_filter(
+      self, mock_config
+  ):
+    mock_config.return_value = '', ''
+    args = self.tr._create_test_args(
+        [MOD_INFO], {constants.TEST_FILTER: '*MyTestFilter*'}
+    )
+
+    self.assertEqual(args.count(constants.TF_ATEST_INCLUDE_FILTER), 1)
+    self.assertEqual(
+        args[args.index(constants.TF_ATEST_INCLUDE_FILTER) + 1],
+        uc.MODULE_NAME + ':*MyTestFilter*',
+    )
+
   @mock.patch.object(
       atf_tr.AtestTradefedTestRunner,
       '_is_all_tests_parameter_auto_enabled',
@@ -1029,7 +1045,7 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     """Test _create_test_args method with auto enabled parameter config."""
     # Should have --m on args and should not have --include-filter.
     mock_config.return_value = '', ''
-    args = self.tr._create_test_args([MOD_INFO])
+    args = self.tr._create_test_args([MOD_INFO], {})
     self.assertTrue(constants.TF_MODULE_FILTER in args)
     self.assertFalse(constants.TF_INCLUDE_FILTER in args)
 
@@ -1111,40 +1127,6 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
 
     self.assertTrue(str(prebuilt_sdk_dir) + ':' in env_vars.get('PATH', ''))
 
-  @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_handle_native_tests')
-  @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_parse_extra_args')
-  @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_create_test_args')
-  @mock.patch('os.environ.get', return_value=None)
-  @mock.patch('atest.atest_utils.get_result_server_args')
-  def test_generate_run_commands_for_aggregate_metric_result(
-      self,
-      mock_resultargs,
-      _mock_env,
-      _mock_create,
-      _mock_parse,
-      _mock_handle_native,
-  ):
-    """Test generate_run_command method for test need aggregate metric."""
-    mock_resultargs.return_value = []
-    _mock_create.return_value = []
-    _mock_parse.return_value = [], []
-    test_info_with_aggregate_metrics = test_info.TestInfo(
-        test_name='perf_test', test_runner='test_runner', build_targets=set()
-    )
-    test_info_with_aggregate_metrics.aggregate_metrics_result = True
-
-    run_cmd = self.tr.generate_run_commands(
-        [test_info_with_aggregate_metrics], extra_args={}
-    )
-
-    self.assertTrue(
-        str(run_cmd).find(
-            'metric_post_processor='
-            'google/template/postprocessors/metric-file-aggregate-disabled'
-        )
-        > 0
-    )
-
   @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_handle_native_tests')
   @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_parse_extra_args')
   @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_create_test_args')
@@ -1197,7 +1179,7 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     """
     # Should not --m on args and should have --include-filter.
     mock_config.return_value = '', ''
-    args = self.tr._create_test_args([MOD_INFO])
+    args = self.tr._create_test_args([MOD_INFO], {})
 
     self.assertFalse(constants.TF_MODULE_FILTER in args)
     self.assertTrue(constants.TF_INCLUDE_FILTER in args)
@@ -1332,19 +1314,19 @@ class ExtraArgsTest(AtestTradefedTestRunnerUnittests):
     self.assertTokensIn(['--disable-target-preparers'], cmd[0])
 
   def test_multidevice_in_config_and_generate_in_run_cmd(self):
-    atest_configs.GLOBAL_ARGS.device_count_config = 2
+    self._global_args.device_count_config = 2
     cmd = self.tr.generate_run_commands([], {})
     self.assertTokensIn(
         ['--replicate-parent-setup', '--multi-device-count', '2'], cmd[0]
     )
 
-    atest_configs.GLOBAL_ARGS.device_count_config = 1
+    self._global_args.device_count_config = 1
     cmd = self.tr.generate_run_commands([], {})
     self.assertTokensNotIn(
         ['--replicate-parent-setup', '--multi-device-count'], cmd[0]
     )
 
-    atest_configs.GLOBAL_ARGS.device_count_config = None
+    self._global_args.device_count_config = None
     cmd = self.tr.generate_run_commands([], {})
     self.assertTokensNotIn(
         ['--replicate-parent-setup', '--multi-device-count'], cmd[0]
diff --git a/atest/test_runners/event_handler.py b/atest/test_runners/event_handler.py
index 66715d82..080568a4 100644
--- a/atest/test_runners/event_handler.py
+++ b/atest/test_runners/event_handler.py
@@ -22,6 +22,7 @@ import logging
 import time
 
 from atest import atest_execution_info
+from atest import atest_utils
 from atest import result_reporter
 from atest.test_runners import test_runner_base
 
@@ -53,9 +54,6 @@ EVENT_PAIRS = {
 START_EVENTS = list(EVENT_PAIRS.keys())
 END_EVENTS = list(EVENT_PAIRS.values())
 TEST_NAME_TEMPLATE = '%s#%s'
-EVENTS_NOT_BALANCED = (
-    'Error: Saw %s Start event and %s End event. These should be equal!'
-)
 
 # time in millisecond.
 ONE_SECOND = 1000
@@ -269,7 +267,7 @@ class EventHandler:
     if event_name in START_EVENTS:
       self.event_stack.append(event_name)
     elif event_name in END_EVENTS:
-      self._check_events_are_balanced(event_name, self.reporter)
+      self._check_events_are_balanced(event_name, self.reporter, event_data)
     if event_name in self.switch_handler:
       self.switch_handler[event_name](self, event_data)
     else:
@@ -277,27 +275,51 @@ class EventHandler:
       # TF event.
       logging.debug('Event[%s] is not processable.', event_name)
 
-  def _check_events_are_balanced(self, event_name, reporter):
-    """Check Start events and End events. They should be balanced.
+  def _check_events_are_balanced(
+      self, end_event_name, reporter, end_event_data
+  ):
+    """Check whether the Start events and End events are balanced.
 
-    If they are not balanced, print the error message in
-    state['last_failed'], then raise TradeFedExitError.
+    When imbalance events are detected, and we understand the case of imbalance,
+    the events will handled without throwing error; otherwise EventHandleError
+    will raise.
 
     Args:
-        event_name: A string of the event name.
+        end_event_name: A string of the event name.
         reporter: A ResultReporter instance.
+        end_event_data: A dict of event data.
 
     Raises:
-        TradeFedExitError if we doesn't have a balance of START/END events.
+        EventHandleError if we can't handle the imbalance of START/END events.
     """
     start_event = self.event_stack.pop() if self.event_stack else None
-    if not start_event or EVENT_PAIRS[start_event] != event_name:
+
+    def _handle_crashed_test(message):
+      atest_utils.print_and_log_error(message)
+
+      self.reporter.process_test_result(
+          test_runner_base.TestResult(
+              runner_name=self.runner_name,
+              group_name=self.state['current_group'],
+              test_name=self.state['current_test'],
+              status=test_runner_base.ERROR_STATUS,
+              details=message,
+              test_count=self.state['test_count'],
+              test_time='',
+              runner_total=None,
+              group_total=self.state['current_group_total'],
+              additional_info={},
+              test_run_name=self.state['test_run_name'],
+          )
+      )
+
+    if not start_event or EVENT_PAIRS[start_event] != end_event_name:
       # Here bubble up the failed trace in the situation having
       # TEST_FAILED but never receiving TEST_ENDED.
       if self.state['last_failed'] and (
           start_event == EVENT_NAMES['test_started']
       ):
-        reporter.process_test_result(
+        self.reporter.process_test_result(
             test_runner_base.TestResult(
                 runner_name=self.runner_name,
                 group_name=self.state['current_group'],
@@ -312,7 +334,37 @@ class EventHandler:
                 test_run_name=self.state['test_run_name'],
             )
         )
-      raise EventHandleError(EVENTS_NOT_BALANCED % (start_event, event_name))
+        # Even though we have proceessed the test result here, we still consider
+        # this case unhandled as we don't have a full understanding about the cause.
+        # So we don't return here.
+        raise EventHandleError(
+            'Error: Test failed without receiving a test end event'
+        )
+      elif (
+          end_event_name == EVENT_NAMES['module_ended']
+          and start_event == EVENT_NAMES['run_started']
+      ):
+        _handle_crashed_test(
+            'Test run started but did not end. This often happens when the test'
+            ' binary/app such as android instrumentation app process died.'
+            ' Test count might be inaccurate.'
+        )
+        return
+      elif (
+          end_event_name == EVENT_NAMES['run_ended']
+          and start_event == EVENT_NAMES['test_started']
+      ):
+        _handle_crashed_test(
+            'Test started but did not end. This often happens when the test'
+            ' binary/app such as android instrumentation app process died.'
+            ' Test count might be inaccurate.'
+        )
+        return
+      else:
+        raise EventHandleError(
+            'Error: Saw %s Start event and %s End event. These should be equal!'
+            % (start_event, end_event_name)
+        )
 
   @staticmethod
   def _calc_duration(duration):
diff --git a/atest/test_runners/event_handler_unittest.py b/atest/test_runners/event_handler_unittest.py
index 49275d48..f63f9363 100755
--- a/atest/test_runners/event_handler_unittest.py
+++ b/atest/test_runners/event_handler_unittest.py
@@ -26,277 +26,104 @@ from atest.test_runners import event_handler as e_h
 from atest.test_runners import test_runner_base
 
 
-EVENTS_NORMAL = [
-    (
-        'TEST_MODULE_STARTED',
-        {
-            'moduleContextFileName': 'serial-util1146216{974}2772610436.ser',
-            'moduleName': 'someTestModule',
-        },
-    ),
-    ('TEST_RUN_STARTED', {'testCount': 2, 'runName': 'com.android.UnitTests'}),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 52,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 1048,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 48,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-        },
-    ),
-    (
-        'TEST_FAILED',
-        {
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-            'trace': 'someTrace',
-        },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 9876450,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-        },
-    ),
-    ('TEST_RUN_ENDED', {}),
-    ('TEST_MODULE_ENDED', {'foo': 'bar'}),
-]
+class _Event:
+
+  def __init__(self):
+    self.events = []
 
-EVENTS_RUN_FAILURE = [
-    (
+  def get_events(self):
+    return self.events
+
+  def add_test_module_started(self, name):
+    self.events.append((
         'TEST_MODULE_STARTED',
         {
-            'moduleContextFileName': 'serial-util11462169742772610436.ser',
-            'moduleName': 'someTestModule',
-        },
-    ),
-    ('TEST_RUN_STARTED', {'testCount': 2, 'runName': 'com.android.UnitTests'}),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 10,
-            'className': 'someClassName',
-            'testName': 'someTestName',
+            'moduleContextFileName': 'serial-util1146216{974}2772610436.ser',
+            'moduleName': name,
         },
-    ),
-    ('TEST_RUN_FAILED', {'reason': 'someRunFailureReason'}),
-]
+    ))
+    return self
 
+  def add_test_module_ended(self, data):
+    self.events.append(('TEST_MODULE_ENDED', data))
+    return self
 
-EVENTS_INVOCATION_FAILURE = [
-    (
+  def add_test_run_started(self, name, count):
+    self.events.append((
         'TEST_RUN_STARTED',
-        {'testCount': None, 'runName': 'com.android.UnitTests'},
-    ),
-    ('INVOCATION_FAILED', {'cause': 'someInvocationFailureReason'}),
-]
-
-EVENTS_MISSING_TEST_RUN_STARTED_EVENT = [
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 52,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_ENDED',
         {
-            'end_time': 1048,
-            'className': 'someClassName',
-            'testName': 'someTestName',
+            'testCount': count,
+            'runName': name,
         },
-    ),
-]
+    ))
+    return self
 
-EVENTS_NOT_BALANCED_BEFORE_RAISE = [
-    (
-        'TEST_MODULE_STARTED',
-        {
-            'moduleContextFileName': 'serial-util1146216{974}2772610436.ser',
-            'moduleName': 'someTestModule',
-        },
-    ),
-    ('TEST_RUN_STARTED', {'testCount': 2, 'runName': 'com.android.UnitTests'}),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 10,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 18,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_STARTED',
+  def add_test_run_failed(self, reason):
+    self.events.append((
+        'TEST_RUN_FAILED',
         {
-            'start_time': 19,
-            'className': 'someClassName',
-            'testName': 'someTestName',
+            'reason': reason,
         },
-    ),
-    (
-        'TEST_FAILED',
-        {
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-            'trace': 'someTrace',
-        },
-    ),
-]
+    ))
+    return self
 
-EVENTS_IGNORE = [
-    (
-        'TEST_MODULE_STARTED',
-        {
-            'moduleContextFileName': 'serial-util1146216{974}2772610436.ser',
-            'moduleName': 'someTestModule',
-        },
-    ),
-    ('TEST_RUN_STARTED', {'testCount': 2, 'runName': 'com.android.UnitTests'}),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 8,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 18,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
+  def add_test_run_ended(self, data):
+    self.events.append(('TEST_RUN_ENDED', data))
+    return self
+
+  def add_test_started(self, start_time, class_name, test_name):
+    self.events.append((
         'TEST_STARTED',
         {
-            'start_time': 28,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
+            'start_time': start_time,
+            'className': class_name,
+            'testName': test_name,
         },
-    ),
-    (
+    ))
+    return self
+
+  def add_test_ignored(self, class_name, test_name, trace):
+    self.events.append((
         'TEST_IGNORED',
         {
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-            'trace': 'someTrace',
-        },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 90,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
+            'className': class_name,
+            'testName': test_name,
+            'trace': trace,
         },
-    ),
-    ('TEST_RUN_ENDED', {}),
-    ('TEST_MODULE_ENDED', {'foo': 'bar'}),
-]
+    ))
+    return self
 
-EVENTS_WITH_PERF_INFO = [
-    (
-        'TEST_MODULE_STARTED',
-        {
-            'moduleContextFileName': 'serial-util1146216{974}2772610436.ser',
-            'moduleName': 'someTestModule',
-        },
-    ),
-    ('TEST_RUN_STARTED', {'testCount': 2, 'runName': 'com.android.UnitTests'}),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 52,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
+  def add_test_ended(self, end_time, class_name, test_name, **kwargs):
+    self.events.append((
         'TEST_ENDED',
         {
-            'end_time': 1048,
-            'className': 'someClassName',
-            'testName': 'someTestName',
-        },
-    ),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 48,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-        },
-    ),
-    (
+            'end_time': end_time,
+            'className': class_name,
+            'testName': test_name,
+        }
+        | kwargs,
+    ))
+    return self
+
+  def add_test_failed(self, class_name, test_name, trace):
+    self.events.append((
         'TEST_FAILED',
         {
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-            'trace': 'someTrace',
+            'className': class_name,
+            'testName': test_name,
+            'trace': trace,
         },
-    ),
-    (
-        'TEST_ENDED',
-        {
-            'end_time': 9876450,
-            'className': 'someClassName2',
-            'testName': 'someTestName2',
-            'cpu_time': '1234.1234(ns)',
-            'real_time': '5678.5678(ns)',
-            'iterations': '6666',
-        },
-    ),
-    (
-        'TEST_STARTED',
-        {
-            'start_time': 10,
-            'className': 'someClassName3',
-            'testName': 'someTestName3',
-        },
-    ),
-    (
-        'TEST_ENDED',
+    ))
+    return self
+
+  def add_invocation_failed(self, reason):
+    self.events.append((
+        'INVOCATION_FAILED',
         {
-            'end_time': 70,
-            'className': 'someClassName3',
-            'testName': 'someTestName3',
-            'additional_info_min': '102773',
-            'additional_info_mean': '105973',
-            'additional_info_median': '103778',
+            'cause': reason,
         },
-    ),
-    ('TEST_RUN_ENDED', {}),
-    ('TEST_MODULE_ENDED', {'foo': 'bar'}),
-]
+    ))
+    return self
 
 
 class EventHandlerUnittests(unittest.TestCase):
@@ -314,7 +141,20 @@ class EventHandlerUnittests(unittest.TestCase):
 
   def test_process_event_normal_results(self):
     """Test process_event method for normal test results."""
-    for name, data in EVENTS_NORMAL:
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(52, 'someClassName', 'someTestName')
+        .add_test_ended(1048, 'someClassName', 'someTestName')
+        .add_test_started(48, 'someClassName2', 'someTestName2')
+        .add_test_failed('someClassName2', 'someTestName2', 'someTrace')
+        .add_test_ended(9876450, 'someClassName2', 'someTestName2')
+        .add_test_run_ended({})
+        .add_test_module_ended({'foo': 'bar'})
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call1 = mock.call(
         test_runner_base.TestResult(
@@ -350,7 +190,15 @@ class EventHandlerUnittests(unittest.TestCase):
 
   def test_process_event_run_failure(self):
     """Test process_event method run failure."""
-    for name, data in EVENTS_RUN_FAILURE:
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(10, 'someClassName', 'someTestName')
+        .add_test_run_failed('someRunFailureReason')
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call = mock.call(
         test_runner_base.TestResult(
@@ -371,7 +219,13 @@ class EventHandlerUnittests(unittest.TestCase):
 
   def test_process_event_invocation_failure(self):
     """Test process_event method with invocation failure."""
-    for name, data in EVENTS_INVOCATION_FAILURE:
+    events = (
+        _Event()
+        .add_test_run_started('com.android.UnitTests', None)
+        .add_invocation_failed('someInvocationFailureReason')
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call = mock.call(
         test_runner_base.TestResult(
@@ -392,7 +246,13 @@ class EventHandlerUnittests(unittest.TestCase):
 
   def test_process_event_missing_test_run_started_event(self):
     """Test process_event method for normal test results."""
-    for name, data in EVENTS_MISSING_TEST_RUN_STARTED_EVENT:
+    events = (
+        _Event()
+        .add_test_started(52, 'someClassName', 'someTestName')
+        .add_test_ended(1048, 'someClassName', 'someTestName')
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call = mock.call(
         test_runner_base.TestResult(
@@ -412,9 +272,20 @@ class EventHandlerUnittests(unittest.TestCase):
     self.mock_reporter.process_test_result.assert_has_calls([call])
 
   # pylint: disable=protected-access
-  def test_process_event_not_balanced(self):
+  def test_process_event_test_run_end_without_test_end_throws(self):
     """Test process_event method with start/end event name not balanced."""
-    for name, data in EVENTS_NOT_BALANCED_BEFORE_RAISE:
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(10, 'someClassName', 'someTestName')
+        .add_test_ended(18, 'someClassName', 'someTestName')
+        .add_test_started(19, 'someClassName', 'someTestName')
+        .add_test_failed('someClassName2', 'someTestName2', 'someTrace')
+        .get_events()
+    )
+
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call = mock.call(
         test_runner_base.TestResult(
@@ -440,22 +311,55 @@ class EventHandlerUnittests(unittest.TestCase):
         e_h.EventHandleError,
         self.fake_eh._check_events_are_balanced,
         name,
+        data,
         self.mock_reporter,
     )
-    # Event pair: TEST_RUN_STARTED -> TEST_MODULE_ENDED
-    # It should raise TradeFedExitError in _check_events_are_balanced()
-    name = 'TEST_MODULE_ENDED'
-    data = {'foo': 'bar'}
-    self.assertRaises(
-        e_h.EventHandleError,
-        self.fake_eh._check_events_are_balanced,
-        name,
-        self.mock_reporter,
+
+  def test_process_event_module_end_without_test_run_end_no_throw(self):
+    """Test process_event method with start/end event name not balanced."""
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_module_ended({'foo': 'bar'})
+        .get_events()
     )
+    for name, data in events[:-1]:
+      self.fake_eh.process_event(name, data)
+
+    self.fake_eh.process_event(*events[-1])
+
+  def test_process_event_run_end_without_test_end_no_throw(self):
+    """Test process_event method with start/end event name not balanced."""
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(10, 'someClassName', 'someTestName')
+        .add_test_run_ended({})
+        .get_events()
+    )
+    for name, data in events[:-1]:
+      self.fake_eh.process_event(name, data)
+
+    self.fake_eh.process_event(*events[-1])
 
   def test_process_event_ignore(self):
     """Test _process_event method for normal test results."""
-    for name, data in EVENTS_IGNORE:
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(8, 'someClassName', 'someTestName')
+        .add_test_ended(18, 'someClassName', 'someTestName')
+        .add_test_started(28, 'someClassName2', 'someTestName2')
+        .add_test_ignored('someClassName2', 'someTestName2', 'someTrace')
+        .add_test_ended(90, 'someClassName2', 'someTestName2')
+        .add_test_run_ended({})
+        .add_test_module_ended({'foo': 'bar'})
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call1 = mock.call(
         test_runner_base.TestResult(
@@ -491,7 +395,36 @@ class EventHandlerUnittests(unittest.TestCase):
 
   def test_process_event_with_additional_info(self):
     """Test process_event method with perf information."""
-    for name, data in EVENTS_WITH_PERF_INFO:
+    events = (
+        _Event()
+        .add_test_module_started('someTestModule')
+        .add_test_run_started('com.android.UnitTests', 2)
+        .add_test_started(52, 'someClassName', 'someTestName')
+        .add_test_ended(1048, 'someClassName', 'someTestName')
+        .add_test_started(48, 'someClassName2', 'someTestName2')
+        .add_test_failed('someClassName2', 'someTestName2', 'someTrace')
+        .add_test_ended(
+            9876450,
+            'someClassName2',
+            'someTestName2',
+            cpu_time='1234.1234(ns)',
+            real_time='5678.5678(ns)',
+            iterations='6666',
+        )
+        .add_test_started(10, 'someClassName3', 'someTestName3')
+        .add_test_ended(
+            70,
+            'someClassName3',
+            'someTestName3',
+            additional_info_min='102773',
+            additional_info_mean='105973',
+            additional_info_median='103778',
+        )
+        .add_test_run_ended({})
+        .add_test_module_ended({'foo': 'bar'})
+        .get_events()
+    )
+    for name, data in events:
       self.fake_eh.process_event(name, data)
     call1 = mock.call(
         test_runner_base.TestResult(
diff --git a/atest/test_runners/mobly_test_runner_unittest.py b/atest/test_runners/mobly_test_runner_unittest.py
index a992ea81..55516b75 100644
--- a/atest/test_runners/mobly_test_runner_unittest.py
+++ b/atest/test_runners/mobly_test_runner_unittest.py
@@ -22,6 +22,8 @@ import pathlib
 import unittest
 from unittest import mock
 
+from atest import arg_parser
+from atest import atest_configs
 from atest import constants
 from atest import result_reporter
 from atest import unittest_constants
@@ -305,14 +307,16 @@ class MoblyTestRunnerUnittests(unittest.TestCase):
     }
     self.assertEqual(yaml_dump.call_args.args[0], expected_config)
 
-  @mock.patch('atest.atest_configs.GLOBAL_ARGS.acloud_create', True)
   @mock.patch('atest.atest_utils.get_adb_devices')
   def test_get_cvd_serials(self, get_adb_devices) -> None:
     """Tests _get_cvd_serials returns correct serials."""
-    devices = ['localhost:1234', '127.0.0.1:5678', 'AD12345']
-    get_adb_devices.return_value = devices
+    global_args = arg_parser.create_atest_arg_parser().parse_args([])
+    global_args.acloud_create = True
+    with mock.patch.object(atest_configs, 'GLOBAL_ARGS', global_args):
+      devices = ['localhost:1234', '127.0.0.1:5678', 'AD12345']
+      get_adb_devices.return_value = devices
 
-    self.assertEqual(self.runner._get_cvd_serials(), devices[:2])
+      self.assertEqual(self.runner._get_cvd_serials(), devices[:2])
 
   @mock.patch('atest.atest_utils.get_adb_devices', return_value=[ADB_DEVICE])
   @mock.patch('subprocess.check_call')
diff --git a/atest/tools/indexing.py b/atest/tools/indexing.py
index e2364605..7b9c5c5e 100755
--- a/atest/tools/indexing.py
+++ b/atest/tools/indexing.py
@@ -100,12 +100,15 @@ def debug_log(func):
   return wrapper
 
 
-def run_updatedb(output_cache: Path, prunepaths: List[str] = None):
+def run_updatedb(output_cache: Path, prunepaths: List[str] = None) -> bool:
   """Run updatedb and generate cache in $ANDROID_HOST_OUT/indices/plocate.db
 
   Args:
-      output_cache: The file path of the updatedb cache.
-      prunepaths: a list of paths that are relative to the build top.
+    output_cache: The file path of the updatedb cache.
+    prunepaths: a list of paths that are relative to the build top.
+
+  Returns:
+    True for success; false otherwise.
   """
   search_root = str(au.get_build_top())
   prunepaths = prunepaths if prunepaths else PRUNEPATHS
@@ -126,21 +129,27 @@ def run_updatedb(output_cache: Path, prunepaths: List[str] = None):
   try:
     full_env_vars = os.environ.copy()
     logging.debug('Executing: %s', updatedb_cmd)
-    result = subprocess.run(updatedb_cmd, env=full_env_vars, check=True)
+    result = subprocess.run(
+        updatedb_cmd, env=full_env_vars, capture_output=True, check=True
+    )
+    logging.debug('Completed executing updatedb: %s', result.stdout)
+    return True
   except (KeyboardInterrupt, SystemExit):
     atest_utils.print_and_log_error('Process interrupted or failure.')
   # Delete indices when plocate.db is locked() or other CalledProcessError.
   # (b/141588997)
   except subprocess.CalledProcessError as err:
     atest_utils.print_and_log_error(
-        'Executing %s error.', ' '.join(updatedb_cmd)
+        '%s\nStdout: %s\nstderr: %s', err, err.stdout, err.stderr
+    )
+    metrics.LocalDetectEvent(
+        detect_type=DetectType.IS_PLOCATEDB_LOCKED, result=1
     )
-    metrics_utils.handle_exc_and_send_exit_event(constants.PLOCATEDB_LOCKED)
-    if err.output:
-      atest_utils.print_and_log_error(err.output)
-    output_cache.unlink()
+    output_cache.unlink(missing_ok=True)
+  except FileNotFoundError:
+    atest_utils.print_and_log_error('updatedb is not available on this host.')
 
-  return result.returncode == 0
+  return False
 
 
 def _dump_index(dump_file, output, output_re, key, value):
diff --git a/atest/usb_speed_detect.py b/atest/usb_speed_detect.py
new file mode 100644
index 00000000..4db5b7ab
--- /dev/null
+++ b/atest/usb_speed_detect.py
@@ -0,0 +1,113 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Module that detects device attributes and USB speed using adb commands."""
+
+import logging
+import subprocess
+from atest import atest_utils
+from atest import constants
+from packages.modules.adb.proto import adb_host_pb2
+
+
+def verify_and_print_usb_speed_warning(device: adb_host_pb2.Device) -> bool:
+  """Checks whether the connection speed is optimal for the given device.
+
+  Args:
+      device: The proto representation of a device.
+
+  Returns:
+      True if the warning was printed, False otherwise.
+  """
+  if (
+      device.connection_type != adb_host_pb2.ConnectionType.USB
+      or device.state != adb_host_pb2.ConnectionState.DEVICE
+  ):
+    return False
+
+  # If a USB-2 is used with a USB-3 capable device, the speed will be
+  # downgraded to 480 Mbps and never 12 Mbps, so this is the only case we
+  # check.
+  if (
+      device.negotiated_speed == 480
+      and device.negotiated_speed < device.max_speed
+  ):
+    _print_usb_speed_warning(
+        device.serial, device.negotiated_speed, device.max_speed
+    )
+    return True
+  return False
+
+
+def _print_usb_speed_warning(
+    serial: str, negotiated_speed: int, max_speed: int
+):
+  """Prints a warning about the device's operating speed if it's suboptimal.
+
+  Args:
+    serial: The serial number of the device.
+    negotiated_speed: The negotiated speed (in Mbits per seconds) the device is
+      operating at.
+    max_speed: The maximum speed (in Mbits per seconds) of which the device is
+      capable.
+  """
+  atest_utils.colorful_print(
+      f'Warning: The device with serial {serial} is using'
+      f' {_speed_to_string(negotiated_speed)} while'
+      f' {_speed_to_string(max_speed)} capable. Check the USB cables/hubs.',
+      constants.MAGENTA,
+  )
+
+
+def _speed_to_string(speed: int) -> str:
+  """Converts a speed in Mbps to a string."""
+  return {
+      480: 'USB-2 (480 Mbps)',
+      5000: 'USB-3.0 (5,000 Mbps)',
+      10000: 'USB-3.1 (10,000 Mbps)',
+      20000: 'USB-3.2 (20,000 Mbps)',
+      40000: 'USB-4.0 (40,000 Mbps)',
+  }.get(speed, f'{speed:,} Mbps')
+
+
+def get_device_proto_binary() -> adb_host_pb2.Device:
+  """Run `adb track-devices --proto-binary` to fetch the device info.
+
+  Returns:
+     A Device object with the attributes of the given device.
+  """
+  if not atest_utils.has_command('adb'):
+    return adb_host_pb2.Device()
+  proc = subprocess.Popen(
+      ['adb', 'track-devices', '--proto-binary'],
+      stdin=subprocess.PIPE,
+      stdout=subprocess.PIPE,
+  )
+  devices = None
+  try:
+    devices = adb_host_pb2.Devices.FromString(
+        proc.stdout.read(int(proc.stdout.read(4).decode('utf-8'), 16))
+    )
+  except ValueError as ve:
+    logging.debug(
+        'Exception raised while running `adb track-devices`. USB speed will'
+        ' not be read. Error: %s',
+        ve,
+    )
+  # Make sure the process is terminated even though an exception is thrown.
+  proc.terminate()
+  # When multiple devices are available, only one will be used.
+  return (
+      devices.device[0] if devices and devices.device else adb_host_pb2.Device()
+  )
diff --git a/atest/usb_speed_detect_unittest.py b/atest/usb_speed_detect_unittest.py
new file mode 100644
index 00000000..db1eda82
--- /dev/null
+++ b/atest/usb_speed_detect_unittest.py
@@ -0,0 +1,58 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import unittest
+from atest import usb_speed_detect
+from packages.modules.adb.proto import adb_host_pb2
+
+
+class UsbSpeedDetectTest(unittest.TestCase):
+
+  def test_non_usb_device_doesnt_print(self):
+    device = adb_host_pb2.Device()
+    device.connection_type = adb_host_pb2.ConnectionType.SOCKET
+    device.state = adb_host_pb2.ConnectionState.DEVICE
+
+    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+
+    self.assertFalse(warning)
+
+  def test_usb_device_expected_speed_doesnt_print(self):
+    device = adb_host_pb2.Device()
+    device.connection_type = adb_host_pb2.ConnectionType.USB
+    device.state = adb_host_pb2.ConnectionState.DEVICE
+    device.negotiated_speed = 5000
+    device.max_speed = 5000
+
+    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+
+    self.assertFalse(warning)
+
+  def test_usb_device_slow_speed_prints_warning(self):
+    device = adb_host_pb2.Device()
+    device.connection_type = adb_host_pb2.ConnectionType.USB
+    device.state = adb_host_pb2.ConnectionState.DEVICE
+    device.negotiated_speed = 480
+    device.max_speed = 5000
+
+    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+
+    self.assertTrue(warning)
+
+  def test_adb_unavailable_doesnt_print(self):
+    device = adb_host_pb2.Device()
+
+    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+
+    self.assertFalse(warning)
diff --git a/experiments/README.md b/experiments/README.md
new file mode 100644
index 00000000..0047e5d9
--- /dev/null
+++ b/experiments/README.md
@@ -0,0 +1,5 @@
+This folder contains a collection of experimental tools and scripts. These tools are under active development and may be unstable or buggy. Use them at your own risk.
+
+Contributing:
+
+Contributions are welcome!
diff --git a/experiments/a/Android.bp b/experiments/a/Android.bp
new file mode 100644
index 00000000..57b8556c
--- /dev/null
+++ b/experiments/a/Android.bp
@@ -0,0 +1,41 @@
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
+python_binary_host {
+    name: "a",
+    main: "a.py",
+    srcs: [
+        "a.py",
+        "**/*.py",
+    ],
+    libs: [],
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+}
+
+python_test_host {
+    name: "a_tests",
+    main: "tests.py",
+    srcs: [
+        "tests.py",
+        "**/*.py",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    test_suites: ["general-tests"],
+}
diff --git a/experiments/a/README.md b/experiments/a/README.md
new file mode 100644
index 00000000..e94742ad
--- /dev/null
+++ b/experiments/a/README.md
@@ -0,0 +1,22 @@
+# A tool
+
+A tool is a command-line tool that can run android workflows and productivity tools
+go/a-tool-design-doc
+
+Contributions welcome!
+
+### To Run
+```a {config_name}```
+or
+```python3 a.py {config_name}```
+
+### To develop
+```python3 a.py {config_name}```
+
+### To Test:
+or
+```python3 -m unittest **/*_test.py```
+or
+```python3 tests.py``
+or
+```atest .```
diff --git a/experiments/a/__init__.py b/experiments/a/__init__.py
new file mode 100644
index 00000000..e69de29b
diff --git a/experiments/a/a.py b/experiments/a/a.py
new file mode 100644
index 00000000..6069062f
--- /dev/null
+++ b/experiments/a/a.py
@@ -0,0 +1,68 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Command line utility for running Android workflows and productivity tools."""
+
+import argparse
+import logging
+import os
+import sys
+
+from tools.update import Update
+
+logger = logging.getLogger(__name__)
+os.environ['PYTHONUNBUFFERED'] = '1'  # No latency for output.
+
+
+tools_map = {
+    'update': Update,
+}
+
+
+def run():
+  """Entry point for tool."""
+  parser = argparse.ArgumentParser(
+      description='Run workflows to build update and test modules',
+      formatter_class=argparse.RawDescriptionHelpFormatter,
+  )
+  parser.add_argument(
+      '-q',
+      '--quiet',
+      action='store_true',
+      help='Do not display progress updates',
+  )
+  subparsers = parser.add_subparsers(dest='name')
+  for name in tools_map:
+    tools_map[name].add_parser(subparsers)
+
+  args = parser.parse_args()
+  name = args.name.lower()
+
+  # Tools
+  if name in tools_map:
+    tool = tools_map[name]()
+    return tool.main(args)
+
+
+if __name__ == '__main__':
+  logging.basicConfig(
+      level=logging.ERROR,
+      handlers=[
+          logging.FileHandler(f"{os.environ.get('OUT', '/tmp')}/a_tool.log"),
+          logging.StreamHandler(sys.stderr),
+      ],
+  )
+  run()
diff --git a/experiments/a/core/__init__.py b/experiments/a/core/__init__.py
new file mode 100644
index 00000000..e69de29b
diff --git a/experiments/a/core/errors.py b/experiments/a/core/errors.py
new file mode 100644
index 00000000..8fed22c3
--- /dev/null
+++ b/experiments/a/core/errors.py
@@ -0,0 +1,30 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+"""Error definitions."""
+
+
+class AtoolError(Exception):
+  """General A tool error."""
+
+
+class WorkflowError(AtoolError):
+  """Error when building tasks from workflow."""
+
+
+class TaskError(AtoolError):
+  """Error running task."""
diff --git a/experiments/a/core/task_runner.py b/experiments/a/core/task_runner.py
new file mode 100644
index 00000000..1b0eb2d3
--- /dev/null
+++ b/experiments/a/core/task_runner.py
@@ -0,0 +1,195 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+"""Classes to help coordinate running tasks and displaying progress."""
+
+import os
+import subprocess
+import threading
+import time
+
+from .errors import TaskError
+
+
+class TaskResult:
+  """Holds result and status code of a task."""
+
+  def __init__(self, status_code, result=''):
+    self.status_code = status_code
+    self.result = result
+
+
+class TaskRunner:
+  """Runs a set of tasks and displays progress."""
+
+  def __init__(self):
+    self.tasks = {}
+    self.task_queue = []
+    self.fall_back_tasks = []
+
+    self.running = False
+
+    # UI
+    self.quiet = False
+    self.output = ''
+    self.running_indicator_thread = None
+    self.running_indicator_chars = ['◢', '◣', '◤', '◥']
+    self.running_indicator_index = 0
+
+  def add_task(self, name, function, *args, **kwargs):
+    """Adds a task to the queue."""
+    self.tasks[name] = {
+        'status': 'pending',
+        'function': function,
+        'output': '',
+        'args': args,
+        'kwargs': kwargs,
+    }
+    self.task_queue.append(name)
+
+  def start(self):
+    """Starts running all the tasks in the queue."""
+    self.running = True
+    self._run_next_task()
+    self.start_running_indicator()
+
+  def run_task(self, name):
+    """Run this task in the queue."""
+    task = self.tasks[name]
+    try:
+      for line in task['function'](*task['args'], **task['kwargs']):
+        if isinstance(line, TaskResult):
+          result = line
+          if result.status_code != 0:
+            raise TaskError(f'status_code: {result.status_code}')
+        else:
+          self.tasks[name]['output'] += line
+        if self.running:
+          self.render_output()
+      self.tasks[name]['status'] = 'completed'
+      if self.running:
+        self._run_next_task()
+    except TaskError as e:
+      self.tasks[name]['status'] = 'failed'
+      self.tasks[name]['output'] += f'Error: {e}\n'
+
+      if self.fall_back_tasks:
+        self.task_queue = []
+        for t in self.fall_back_tasks:
+          if isinstance(t, str):
+            self.add_shell_command_task(t)
+        self.fall_back_tasks = []
+        self._run_next_task()
+      else:
+        if self.running:
+          self.render_output()
+          self.running = False
+
+  def _run_next_task(self):
+    """Runs the next task in the queue."""
+    if self.task_queue and self.running:
+      name = self.task_queue.pop(0)
+      self.tasks[name]['status'] = 'running'
+      threading.Thread(target=self.run_task, args=(name,)).start()
+    elif self.running:
+      self.running = False
+      self.render_output()
+
+      if self.quiet:
+        return
+
+      print('')
+      print(
+          'Add workflows/tools: go/atool Join http://g/atool-discuss to discuss'
+          ' and stay up to date'
+      )
+      print('')
+      print('Run Completed Successfully!')
+
+  def add_shell_command_task(self, command):
+    """Adds a shell command to the task queue."""
+    self.add_task(command, run_shell_command, command)
+
+  def start_running_indicator(self):
+    """Starts the progress indicator thread."""
+    if (
+        self.running_indicator_thread is None
+        or not self.running_indicator_thread.is_alive()
+    ):
+      self.running_indicator_thread = threading.Thread(
+          target=self._update_running_indicator
+      )
+      self.running_indicator_thread.start()
+
+  def _update_running_indicator(self):
+    """Updates the progress indicator thread."""
+    while self.running:
+      self.running_indicator_index = (self.running_indicator_index + 1) % len(
+          self.running_indicator_chars
+      )
+      self.render_output()
+      time.sleep(0.15)
+
+  def render_output(self):
+    """Prints the output of the tasks as well as a table showing the progres on the task queue."""
+    if self.quiet:
+      return
+
+    os.system('cls' if os.name == 'nt' else 'clear')
+    print(f'{self.output}', end='')
+    for name, command_data in self.tasks.items():
+      print(f"{command_data['output']}", end='')
+
+    print('')
+    print('-' * 20)
+    for name, command_data in self.tasks.items():
+      status_icon = '.'
+      status_color = '\033[94m'  # Blue
+      if command_data['status'] == 'completed':
+        status_icon = '✓'
+        status_color = '\033[32m'  # Green
+      elif command_data['status'] == 'running':
+        status_icon = self.running_indicator_chars[self.running_indicator_index]
+        status_color = '\033[32m'  # Green
+      elif command_data['status'] == 'failed':
+        status_icon = '✗'
+        status_color = '\033[91m'  # Red
+      print(f'{status_color}{status_icon}\033[0m {status_color}{name}\033[0m')
+    print('-' * 20)
+
+
+def run_shell_command(command):
+  """Run a shell command and yield output."""
+  last_line = ''
+  with subprocess.Popen(
+      command,
+      shell=True,
+      stdout=subprocess.PIPE,
+      stderr=subprocess.STDOUT,
+      text=True,
+  ) as process:
+    yield f'Running: {command}\n'
+    for line in iter(process.stdout.readline, ''):
+      if line.strip() == last_line:
+        continue
+      last_line = line.strip()
+      yield line
+    process.stdout.flush()
+    process.stdout.close()
+    status_code = process.wait()
+    yield f'Command finished with exit code: {status_code}\n'
+    yield TaskResult(status_code=status_code)
diff --git a/experiments/a/tests.py b/experiments/a/tests.py
new file mode 100644
index 00000000..ef87a2b2
--- /dev/null
+++ b/experiments/a/tests.py
@@ -0,0 +1,30 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+"""Gathers and runs all tests."""
+
+import importlib
+import unittest
+
+if __name__ == '__main__':
+  test_modules = ['tools.update_test']
+
+  for mod in test_modules:
+    importlib.import_module(mod)
+  loader = unittest.defaultTestLoader
+  test_suite = loader.loadTestsFromNames(test_modules)
+  runner = unittest.TextTestRunner(verbosity=2)
+  runner.run(test_suite)
diff --git a/experiments/a/tools/__init__.py b/experiments/a/tools/__init__.py
new file mode 100644
index 00000000..e69de29b
diff --git a/experiments/a/tools/update.py b/experiments/a/tools/update.py
new file mode 100644
index 00000000..62542602
--- /dev/null
+++ b/experiments/a/tools/update.py
@@ -0,0 +1,233 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+"""Update Tool."""
+
+import inspect
+import os
+import sys
+
+from core.errors import WorkflowError
+from core.task_runner import TaskRunner
+
+
+class Update:
+  """Updates a device."""
+
+  @classmethod
+  def add_parser(cls, subparsers):
+    """Parse update alias/arguments."""
+    parser = subparsers.add_parser('update', help='Updates a device')
+    parser.add_argument(
+        'alias', nargs='?', default='default', type=str, help='alias'
+    )
+
+  def main(self, args):
+    """Main entrypoint for Update."""
+    alias = args.alias
+    tasks, fall_back_tasks = self.gather_tasks(alias)
+    self.run_tasks(tasks, fall_back_tasks)
+
+  def gather_tasks(self, alias):
+    """Gathers tasks to run based on alias."""
+    tasks = []
+    fall_back_tasks = []
+
+    aliases = get_aliases()
+    if alias in aliases:
+      config = aliases[alias]()
+      tasks += config.build()
+      tasks += config.update()
+    else:
+      # default
+      tasks = [
+          'm sync',
+          'adevice update',
+      ]
+      fall_back_tasks = [
+          'm droid',
+          'flashall',
+      ]
+    return (tasks, fall_back_tasks)
+
+  def run_tasks(self, tasks, fall_back_tasks):
+    """Runs tasks."""
+    task_runner = TaskRunner()
+    task_runner.quiet = False
+    for task in tasks:
+      if isinstance(task, str):
+        task_runner.add_shell_command_task(task)
+      else:
+        task_runner.add_task(task)
+    task_runner.fall_back_tasks = fall_back_tasks
+    task_runner.start()
+
+
+class Alias:
+  """Base class for defining an alias."""
+
+  def build(self):
+    return []
+
+  def update(self):
+    return []
+
+
+class Core(Alias):
+  """Alias for Core."""
+
+  def build(self):
+    return ['m framework framework-minus-apex']
+
+  def update(self):
+    return [
+        'adevice update',
+    ]
+
+
+class SystemServer(Alias):
+  """Alias for SystemServer."""
+
+  def update(self):
+    return [
+        'adevice update --restart=none',
+        'adb kill systemserver',
+    ]
+
+
+class SysUI(Alias):
+  """Alias for SystemUI."""
+
+  def build(self):
+    if is_nexus():
+      raise WorkflowError(
+          "Target 'sysui' is not allowed on Nexus Experience devices.\n"
+          'Try sysuig (with g at the end) or sysuititan'
+      )
+    return ['m framework framework-minus-apex SystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class SysUIG(Alias):
+  """Alias for SystemUI for Google Devices."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuig' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no g at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUIGoogle']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class SysUITitan(Alias):
+  """Alias for SystemUI Titan devices."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuititan' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no g at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUITitan']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class SysUIGo(Alias):
+  """Alias for SystemUI."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuigo' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no go at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUIGo']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class CarSysUI(Alias):
+  """Alias for CarSystemUI."""
+
+  def build(self):
+    return ['m framework framework-minus-apex CarSystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class CarSysUIG(Alias):
+  """Alias for CarSystemUI."""
+
+  def build(self):
+    return ['m framework framework-minus-apex AAECarSystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+# Utilities to get type of target
+def is_nexus():
+  target_product = os.getenv('TARGET_PRODUCT')
+  return (
+      target_product.startswith('.aosp')
+      or 'wembley' in target_product
+      or 'gms_humuhumu' in target_product
+  )
+
+
+def get_aliases():
+  return {
+      name.lower(): cls
+      for name, cls in inspect.getmembers(
+          sys.modules[__name__], inspect.isclass
+      )
+      if issubclass(cls, Alias) and cls != Alias
+  }
diff --git a/experiments/a/tools/update_test.py b/experiments/a/tools/update_test.py
new file mode 100644
index 00000000..e56a4dfb
--- /dev/null
+++ b/experiments/a/tools/update_test.py
@@ -0,0 +1,53 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+import unittest
+from .update import Core
+from .update import get_aliases
+from .update import SystemServer
+from .update import SysUI
+from .update import Update
+
+
+class UpdateTest(unittest.TestCase):
+
+  def test_get_aliases(self):
+    aliases = get_aliases()
+    self.assertIn('core', aliases)
+    self.assertIn('systemserver', aliases)
+    self.assertIn('sysui', aliases)
+
+    self.assertIs(aliases['core'], Core)
+    self.assertIs(aliases['systemserver'], SystemServer)
+    self.assertIs(aliases['sysui'], SysUI)
+
+  def test_gather_tasks_default(self):
+    update = Update()
+    tasks, fall_back_tasks = update.gather_tasks('')
+    self.assertEqual(tasks, ['m sync', 'adevice update'])
+    self.assertEqual(fall_back_tasks, ['m droid', 'flashall'])
+
+  def test_gather_tasks_alias(self):
+    update = Update()
+    tasks, fall_back_tasks = update.gather_tasks('core')
+    self.assertEqual(
+        tasks, ['m framework framework-minus-apex', 'adevice update']
+    )
+    self.assertEqual(fall_back_tasks, [])
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/preupload_hook_script.py b/preupload_hook_script.py
index 6f6e6197..f9aba527 100755
--- a/preupload_hook_script.py
+++ b/preupload_hook_script.py
@@ -186,7 +186,7 @@ if __name__ == '__main__':
   preupload_files = get_preupload_files()
 
   gpylint_project_files, other_files = _filter_files_for_projects(
-      preupload_files, ['atest'], root_files=True
+      preupload_files, ['atest', 'experiments/a'], root_files=True
   )
   _run_pylint(other_files)
   _run_pyformat(gpylint_project_files)
```

