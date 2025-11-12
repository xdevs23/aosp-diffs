```diff
diff --git a/Android.bp b/Android.bp
index 28043d5d2..ae52babf0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -97,7 +97,6 @@ soong_config_module_type {
     name: "cf_cc_defaults",
     module_type: "cc_defaults",
     config_namespace: "cvdhost",
-    bool_variables: ["enforce_mac80211_hwsim"],
     value_variables: [
         "board_f2fs_blocksize",
         "default_userdata_fs_type",
@@ -109,13 +108,6 @@ soong_config_module_type {
 cf_cc_defaults {
     name: "cvd_cc_defaults",
     soong_config_variables: {
-        // PRODUCT_ENFORCE_MAC80211_HWSIM sets this
-        enforce_mac80211_hwsim: {
-            cflags: ["-DENFORCE_MAC80211_HWSIM=true"],
-            conditions_default: {
-                cflags: [],
-            },
-        },
         // TARGET_USERDATAIMAGE_FILE_SYSTEM_TYPE sets this from BoardConfig.mk
         // The only user is the page agnostic cf target
         default_userdata_fs_type: {
diff --git a/README.md b/README.md
index 40eddb3c4..1d9b6a7be 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,8 @@
+**Note**
+
+For all host tools development please refer to
+https://github.com/google/android-cuttlefish/blob/main/docs/HostToolsMigration.md for more information.
+
 # Cuttlefish Getting Started
 
 ## Try Cuttlefish
diff --git a/apex/com.google.cf.disabled/Android.bp b/apex/com.google.cf.disabled/Android.bp
new file mode 100644
index 000000000..9fa6612d7
--- /dev/null
+++ b/apex/com.google.cf.disabled/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+apex {
+    name: "com.google.cf.disabled",
+    manifest: "manifest.json",
+    file_contexts: "file_contexts",
+    key: "com.google.cf.apex.key",
+    certificate: ":com.google.cf.apex.certificate",
+    updatable: false,
+    soc_specific: true,
+}
diff --git a/apex/com.google.cf.disabled/file_contexts b/apex/com.google.cf.disabled/file_contexts
new file mode 100644
index 000000000..fa109d05e
--- /dev/null
+++ b/apex/com.google.cf.disabled/file_contexts
@@ -0,0 +1 @@
+(/.*)?     u:object_r:vendor_file:s0
diff --git a/apex/com.google.cf.disabled/manifest.json b/apex/com.google.cf.disabled/manifest.json
new file mode 100644
index 000000000..4b205f8fe
--- /dev/null
+++ b/apex/com.google.cf.disabled/manifest.json
@@ -0,0 +1,4 @@
+{
+  "name": "com.google.cf.disabled",
+  "version": 1
+}
diff --git a/build/Android.bp b/build/Android.bp
index c8847e58b..7607b1955 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -17,6 +17,36 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+install_symlink_host {
+    name: "avbtool.py",
+    installed_location: "bin/avbtool.py",
+    symlink_target: "avbtool",
+}
+
+install_symlink_host {
+    name: "cpio",
+    installed_location: "bin/cpio",
+    symlink_target: "toybox",
+}
+
+install_symlink_host {
+    name: "mkbootimg.py",
+    installed_location: "bin/mkbootimg.py",
+    symlink_target: "mkbootimg",
+}
+
+install_symlink_host {
+    name: "mkuserimg_mke2fs.py",
+    installed_location: "bin/mkuserimg_mke2fs.py",
+    symlink_target: "mkuserimg_mke2fs",
+}
+
+install_symlink_host {
+    name: "unpack_bootimg.py",
+    installed_location: "bin/unpack_bootimg.py",
+    symlink_target: "unpack_bootimg",
+}
+
 bootstrap_go_package {
     name: "cuttlefish-soong-rules",
     pkgPath: "android/soong/cuttlefish",
@@ -105,6 +135,7 @@ cvd_host_tools = [
     "assemble_cvd",
     "automotive_vsock_proxy",
     "avbtool",
+    "avbtool.py",
     "build_super_image",
     "casimir",
     "casimir_control_server",
@@ -112,6 +143,7 @@ cvd_host_tools = [
     "common_crosvm",
     "console_forwarder",
     "control_env_proxy_server",
+    "cpio",
     "crosvm",
     "cvd_host_bugreport",
     "cvd_import_locations",
@@ -127,6 +159,7 @@ cvd_host_tools = [
     "cvd_update_location",
     "cvd_update_security_algorithm",
     "cvdremote",
+    "e2fsck",
     "e2fsdroid",
     "echo_server",
     "extract-ikconfig",
@@ -144,7 +177,6 @@ cvd_host_tools = [
     "logcat_receiver",
     "lpadd",
     "lpmake",
-    "lpunpack",
     "lz4",
     "make_f2fs",
     "mcopy",
@@ -152,9 +184,11 @@ cvd_host_tools = [
     "metrics_launcher",
     "mkbootfs",
     "mkbootimg",
+    "mkbootimg.py",
     "mke2fs",
     "mkenvimage_slim",
     "mkuserimg_mke2fs",
+    "mkuserimg_mke2fs.py",
     "mmd",
     "modem_simulator",
     "ms-tpm-20-ref",
@@ -170,6 +204,8 @@ cvd_host_tools = [
     "process_restarter",
     "process_sandboxer",
     "record_cvd",
+    "resize2fs",
+    "resize.f2fs",
     "restart_cvd",
     "root-canal",
     "run_cvd",
@@ -187,6 +223,7 @@ cvd_host_tools = [
     "tombstone_receiver",
     "toybox",
     "unpack_bootimg",
+    "unpack_bootimg.py",
     "vhal_proxy_server",
     "vhost_device_vsock",
     "vulkan.lvp",
@@ -499,7 +536,8 @@ cvd_debian_marker = [
 cvd_host_package_customization {
     name: "cvd-host_package",
     deps: cvd_host_tools +
-        cvd_host_tests,
+        cvd_host_tests +
+        ["jcardsim"],
     multilib: {
         common: {
             deps: cvd_default_input_device_specs +
diff --git a/common/libs/sensors/sensors.h b/common/libs/sensors/sensors.h
index 15a87e333..82861346a 100644
--- a/common/libs/sensors/sensors.h
+++ b/common/libs/sensors/sensors.h
@@ -25,8 +25,14 @@ namespace sensors {
 inline constexpr int kAccelerationId = 0;
 inline constexpr int kGyroscopeId = 1;
 inline constexpr int kMagneticId = 2;
+inline constexpr int kTemperatureId = 4;
+inline constexpr int kProximityId = 5;
+inline constexpr int kLightId = 6;
+inline constexpr int kPressureId = 7;
+inline constexpr int kHumidityId = 8;
 inline constexpr int kUncalibMagneticId = 9;
 inline constexpr int kUncalibGyroscopeId = 10;
+inline constexpr int kHingeAngle0Id = 11;
 inline constexpr int kUncalibAccelerationId = 17;
 /*
   This is reserved specifically for Cuttlefish to identify the device
@@ -49,6 +55,7 @@ inline constexpr char OUTER_DELIM = ' ';
 /* Sensors Commands */
 inline constexpr int kUpdateRotationVec = 0;
 inline constexpr int kGetSensorsData = 1;
+inline constexpr int kUpdateHal = 2;
 
 using SensorsCmd = int;
 
diff --git a/common/libs/utils/tee_logging.cpp b/common/libs/utils/tee_logging.cpp
index cd5349c34..ed3f3fe9a 100644
--- a/common/libs/utils/tee_logging.cpp
+++ b/common/libs/utils/tee_logging.cpp
@@ -173,10 +173,7 @@ std::string StderrOutputGenerator(const struct tm& now, int pid, uint64_t tid,
   char timestamp[32];
   strftime(timestamp, sizeof(timestamp), "%m-%d %H:%M:%S", &now);
 
-  static const char log_characters[] = "VDIWEFF";
-  static_assert(arraysize(log_characters) - 1 == FATAL + 1,
-                "Mismatch in size of log_characters and values in LogSeverity");
-  char severity_char = log_characters[severity];
+  char severity_char = android::base::kSeverityChars[severity];
   std::string line_prefix;
   if (file != nullptr) {
     line_prefix = StringPrintf("%s %c %s %5d %5" PRIu64 " %s:%u] ", tag ? tag : "nullptr",
diff --git a/debian_substitution_marker b/debian_substitution_marker
index e69de29bb..15895af5c 100644
--- a/debian_substitution_marker
+++ b/debian_substitution_marker
@@ -0,0 +1,201 @@
+# cuttlefish debian_substitution_marker v1
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/acloud_translator"
+  link_name: "bin/acloud_translator"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/adb_connector"
+  link_name: "bin/adb_connector"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/allocd_client"
+  link_name: "bin/allocd_client"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/console_forwarder"
+  link_name: "bin/console_forwarder"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_import_locations"
+  link_name: "bin/cvd_import_locations"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_internal_display"
+  link_name: "bin/cvd_internal_display"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_internal_host_bugreport"
+  link_name: "bin/cvd_internal_host_bugreport"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_internal_start"
+  link_name: "bin/cvd_internal_start"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_internal_status"
+  link_name: "bin/cvd_internal_status"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_internal_stop"
+  link_name: "bin/cvd_internal_stop"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_send_id_disclosure"
+  link_name: "bin/cvd_send_id_disclosure"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/cvd_update_security_algorithm"
+  link_name: "bin/cvd_update_security_algorithm"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/echo_server"
+  link_name: "bin/echo_server"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/extract-ikconfig"
+  link_name: "bin/extract-ikconfig"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/extract-vmlinux"
+  link_name: "bin/extract-vmlinux"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/gnss_grpc_proxy"
+  link_name: "bin/gnss_grpc_proxy"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/health"
+  link_name: "bin/health"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/kernel_log_monitor"
+  link_name: "bin/kernel_log_monitor"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/log_tee"
+  link_name: "bin/log_tee"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/logcat_receiver"
+  link_name: "bin/logcat_receiver"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/metrics_launcher"
+  link_name: "bin/metrics_launcher"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/mkbootfs"
+  link_name: "bin/mkbootfs"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/mkenvimage_slim"
+  link_name: "bin/mkenvimage_slim"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/modem_simulator"
+  link_name: "bin/modem_simulator"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/openwrt_control_server"
+  link_name: "bin/openwrt_control_server"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/operator_proxy"
+  link_name: "bin/operator_proxy"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/powerbtn_cvd"
+  link_name: "bin/powerbtn_cvd"
+}
+
+symlinks {
+  target: "/usr/lib/cuttlefish-common/bin/powerwash_cvd"
+  link_name: "bin/powerwash_cvd"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/process_restarter"
+  link_name: "bin/process_restarter"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/record_cvd"
+  link_name: "bin/record_cvd"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/restart_cvd"
+  link_name: "bin/restart_cvd"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/screen_recording_server"
+  link_name: "bin/screen_recording_server"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/sensors_simulator"
+  link_name: "bin/sensors_simulator"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/simg2img"
+  link_name: "bin/simg2img"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/snapshot_util_cvd"
+  link_name: "bin/snapshot_util_cvd"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/tcp_connector"
+  link_name: "bin/tcp_connector"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/bin/tombstone_receiver"
+  link_name: "bin/tombstone_receiver"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/etc/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml"
+  link_name: "etc/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/etc/modem_simulator/files/iccprofile_for_sim0.xml"
+  link_name: "etc/modem_simulator/files/iccprofile_for_sim0.xml"
+}
+
+symlinks: {
+  target: "/usr/lib/cuttlefish-common/etc/modem_simulator/files/numeric_operator.xml"
+  link_name: "etc/modem_simulator/files/numeric_operator.xml"
+}
diff --git a/guest/commands/init_dev_config/Android.bp b/guest/commands/init_dev_config/Android.bp
new file mode 100644
index 000000000..8ddbd084c
--- /dev/null
+++ b/guest/commands/init_dev_config/Android.bp
@@ -0,0 +1,33 @@
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
+cc_binary {
+    name: "com.google.cf.init_dev_config",
+    stem: "init_dev_config",
+    srcs: [
+        "main.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+    ],
+    // Must use bootstrap bionic because this runs before apexd-bootstrap.
+    bootstrap: true,
+    vendor: true,
+    defaults: ["cuttlefish_guest_only"],
+}
diff --git a/guest/commands/init_dev_config/main.cpp b/guest/commands/init_dev_config/main.cpp
new file mode 100644
index 000000000..5584523eb
--- /dev/null
+++ b/guest/commands/init_dev_config/main.cpp
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <android-base/properties.h>
+
+int main() {
+  // This is to demonstrate an APEX can be disabled with "none"
+  android::base::SetProperty("ro.boot.vendor.apex.com.google.cf.disabled",
+                             "none");
+}
diff --git a/guest/commands/v4l2_streamer/yuv2rgb.cpp b/guest/commands/v4l2_streamer/yuv2rgb.cpp
index 1a21cd7ca..b7dc73874 100644
--- a/guest/commands/v4l2_streamer/yuv2rgb.cpp
+++ b/guest/commands/v4l2_streamer/yuv2rgb.cpp
@@ -69,11 +69,14 @@ void Yuv2Rgb(unsigned char *src, unsigned char *dst, int width, int height) {
       int r = *y + T1[*vline];
       int g = *y + T2[*vline] + T3[*uline];
       int b = *y + T4[*uline];
-      // Note: going BGRA here not RGBA
-      dst[0] = clamp(b);  // 16-bit to 8-bit, chuck precision
-      dst[1] = clamp(g);
-      dst[2] = clamp(r);
-      dst[3] = 255;
+
+      // Store bytes in XBGR (byte 0..3).
+      // See https://docs.kernel.org/userspace-api/media/v4l/pixfmt-rgb.html
+      // for details on byte order of various formats.
+      dst[0] = 255;
+      dst[1] = clamp(b);  // 16-bit to 8-bit, chuck precision
+      dst[2] = clamp(g);
+      dst[3] = clamp(r);
       dst += ZOF_RGB;
       if (w & 0x01) {
         uline++;
@@ -87,4 +90,4 @@ void Yuv2Rgb(unsigned char *src, unsigned char *dst, int width, int height) {
   }
 }
 
-}  // End namespace cuttlefish
\ No newline at end of file
+}  // End namespace cuttlefish
diff --git a/guest/hals/bluetooth/Android.bp b/guest/hals/bluetooth/Android.bp
index 4445a431b..638bc9f6a 100644
--- a/guest/hals/bluetooth/Android.bp
+++ b/guest/hals/bluetooth/Android.bp
@@ -28,6 +28,8 @@ rust_binary {
         "libargh",
         "libbinder_rs",
         "libbinder_tokio_rs",
+        "libbluetooth_offload_hal",
+        "libbluetooth_offload_leaudio_hci",
         "libbytes",
         "liblibc",
         "liblog_rust",
diff --git a/guest/hals/bluetooth/src/hci.rs b/guest/hals/bluetooth/src/hci.rs
index 3a4275a27..0c696c02c 100644
--- a/guest/hals/bluetooth/src/hci.rs
+++ b/guest/hals/bluetooth/src/hci.rs
@@ -19,6 +19,7 @@ use android_hardware_bluetooth::aidl::android::hardware::bluetooth::{
 };
 
 use binder::{DeathRecipient, IBinder, Interface, Strong};
+use bluetooth_offload_hal::{HciHal, HciHalStatus, HciProxyCallbacks};
 use log::{error, info, trace, warn};
 use std::fs;
 use std::io::{Read, Write};
@@ -45,11 +46,7 @@ impl Idc {
 
 enum ClientState {
     Closed,
-    Opened {
-        initialized: bool,
-        callbacks: Strong<dyn IBluetoothHciCallbacks>,
-        _death_recipient: DeathRecipient,
-    },
+    Opened { initialized: bool, callbacks: HciProxyCallbacks },
 }
 
 struct ServiceState {
@@ -173,18 +170,17 @@ impl BluetoothHci {
                             ) {
                                 // The initialization of the controller is now complete,
                                 // report the status to the Host stack.
-                                callbacks.initializationComplete(Status::SUCCESS).unwrap();
+                                callbacks.initialization_complete(HciHalStatus::Success);
                                 *initialized = true;
                             }
                         }
                         ClientState::Opened { ref callbacks, .. } => match idc {
-                            Idc::ACL_DATA => callbacks.aclDataReceived(&data[1..packet_size]),
-                            Idc::SCO_DATA => callbacks.scoDataReceived(&data[1..packet_size]),
-                            Idc::ISO_DATA => callbacks.isoDataReceived(&data[1..packet_size]),
-                            Idc::EVENT => callbacks.hciEventReceived(&data[1..packet_size]),
+                            Idc::ACL_DATA => callbacks.acl_received(&data[1..packet_size]),
+                            Idc::SCO_DATA => callbacks.sco_received(&data[1..packet_size]),
+                            Idc::ISO_DATA => callbacks.iso_received(&data[1..packet_size]),
+                            Idc::EVENT => callbacks.event_received(&data[1..packet_size]),
                             _ => unreachable!(),
-                        }
-                        .expect("failed to send HCI packet to host"),
+                        },
                         ClientState::Closed => (),
                     }
                 }
@@ -194,51 +190,32 @@ impl BluetoothHci {
         BluetoothHci { _handle: handle, service_state }
     }
 
-    fn send(&self, idc: Idc, data: &[u8]) -> binder::Result<()> {
+    fn send(&self, idc: Idc, data: &[u8]) {
         let mut service_state = self.service_state.lock().unwrap();
 
         if !matches!(service_state.client_state, ClientState::Opened { .. }) {
             error!("IBluetoothHci::sendXX: not initialized");
-            return Err(binder::ExceptionCode::ILLEGAL_STATE.into());
+            return;
         }
 
         service_state.writer.write_all(&[idc as u8]).unwrap();
         service_state.writer.write_all(data).unwrap();
-
-        Ok(())
     }
 }
 
-impl Interface for BluetoothHci {}
-
-impl IBluetoothHci for BluetoothHci {
-    fn initialize(&self, callbacks: &Strong<dyn IBluetoothHciCallbacks>) -> binder::Result<()> {
+impl HciHal for BluetoothHci {
+    fn initialize(&self, callbacks: HciProxyCallbacks) {
         info!("IBluetoothHci::initialize");
 
         let mut service_state = self.service_state.lock().unwrap();
 
         if matches!(service_state.client_state, ClientState::Opened { .. }) {
             error!("IBluetoothHci::initialize: already initialized");
-            callbacks.initializationComplete(Status::ALREADY_INITIALIZED)?;
-            return Ok(());
+            callbacks.initialization_complete(HciHalStatus::AlreadyInitialized);
+            return;
         }
 
-        let mut death_recipient = {
-            let service_state = self.service_state.clone();
-            DeathRecipient::new(move || {
-                warn!("IBluetoothHci service has died");
-                let mut service_state = service_state.lock().unwrap();
-                service_state.client_state = ClientState::Closed;
-            })
-        };
-
-        callbacks.as_binder().link_to_death(&mut death_recipient)?;
-
-        service_state.client_state = ClientState::Opened {
-            initialized: false,
-            callbacks: callbacks.clone(),
-            _death_recipient: death_recipient,
-        };
+        service_state.client_state = ClientState::Opened { initialized: false, callbacks };
 
         // In order to emulate hardware reset of the controller,
         // the HCI Reset command is sent from the HAL directly to clear
@@ -246,38 +223,40 @@ impl IBluetoothHci for BluetoothHci {
         // IBluetoothHciCallback.initializationComplete will be invoked
         // the HCI Reset complete event is received.
         service_state.writer.write_all(&[0x01, 0x03, 0x0c, 0x00]).unwrap();
+    }
 
-        Ok(())
+    fn client_died(&self) {
+        warn!("IBluetoothHci service has died");
+        let mut service_state = self.service_state.lock().unwrap();
+        service_state.client_state = ClientState::Closed;
     }
 
-    fn close(&self) -> binder::Result<()> {
+    fn close(&self) {
         info!("IBluetoothHci::close");
 
         let mut service_state = self.service_state.lock().unwrap();
         service_state.client_state = ClientState::Closed;
-
-        Ok(())
     }
 
-    fn sendAclData(&self, data: &[u8]) -> binder::Result<()> {
+    fn send_acl(&self, data: &[u8]) {
         info!("IBluetoothHci::sendAclData");
 
         self.send(Idc::AclData, data)
     }
 
-    fn sendHciCommand(&self, data: &[u8]) -> binder::Result<()> {
+    fn send_command(&self, data: &[u8]) {
         info!("IBluetoothHci::sendHciCommand");
 
         self.send(Idc::Command, data)
     }
 
-    fn sendIsoData(&self, data: &[u8]) -> binder::Result<()> {
+    fn send_iso(&self, data: &[u8]) {
         info!("IBluetoothHci::sendIsoData");
 
         self.send(Idc::IsoData, data)
     }
 
-    fn sendScoData(&self, data: &[u8]) -> binder::Result<()> {
+    fn send_sco(&self, data: &[u8]) {
         info!("IBluetoothHci::sendScoData");
 
         self.send(Idc::ScoData, data)
diff --git a/guest/hals/bluetooth/src/main.rs b/guest/hals/bluetooth/src/main.rs
index a2973a6c2..d4f27a7fd 100644
--- a/guest/hals/bluetooth/src/main.rs
+++ b/guest/hals/bluetooth/src/main.rs
@@ -19,6 +19,8 @@
 
 use android_hardware_bluetooth::aidl::android::hardware::bluetooth::IBluetoothHci::BnBluetoothHci;
 use binder::{self, BinderFeatures, ProcessState};
+use bluetooth_offload_hal::HciProxy;
+use bluetooth_offload_leaudio_hci::LeAudioModuleBuilder;
 use log::{error, info};
 
 mod hci;
@@ -51,8 +53,10 @@ fn main() {
     ProcessState::set_thread_pool_max_thread_count(0);
     ProcessState::start_thread_pool();
 
-    let hci_binder =
-        BnBluetoothHci::new_binder(hci::BluetoothHci::new(&opt.serial), BinderFeatures::default());
+    let hci_binder = BnBluetoothHci::new_binder(
+        HciProxy::new(vec![Box::new(LeAudioModuleBuilder {})], hci::BluetoothHci::new(&opt.serial)),
+        binder::BinderFeatures::default(),
+    );
 
     info!("Starting ..IBluetoothHci/default");
     binder::add_service("android.hardware.bluetooth.IBluetoothHci/default", hci_binder.as_binder())
diff --git a/guest/hals/ril/reference-libril/RefRadioIms.cpp b/guest/hals/ril/reference-libril/RefRadioIms.cpp
index d9b09fe84..733b0cbc1 100644
--- a/guest/hals/ril/reference-libril/RefRadioIms.cpp
+++ b/guest/hals/ril/reference-libril/RefRadioIms.cpp
@@ -72,4 +72,10 @@ ScopedAStatus RefRadioIms::updateImsCallStatus(
     respond()->updateImsCallStatusResponse(responseInfo(serial));
     return ok();
 }
+ScopedAStatus RefRadioIms::updateAllowedServices(
+        int32_t serial,
+        const std::vector<::aidl::android::hardware::radio::ims::ImsService>& imsServices) {
+    respond()->updateAllowedServicesResponse(responseInfo(serial));
+    return ok();
+}
 }  // namespace cf::ril
diff --git a/guest/hals/ril/reference-libril/RefRadioIms.h b/guest/hals/ril/reference-libril/RefRadioIms.h
index d3d4e72f4..841d7ac36 100644
--- a/guest/hals/ril/reference-libril/RefRadioIms.h
+++ b/guest/hals/ril/reference-libril/RefRadioIms.h
@@ -49,6 +49,10 @@ class RefRadioIms : public android::hardware::radio::compat::RadioIms {
     ::ndk::ScopedAStatus updateImsCallStatus(
             int32_t serial,
             const std::vector<::aidl::android::hardware::radio::ims::ImsCall>& imsCalls) override;
+    ::ndk::ScopedAStatus updateAllowedServices(
+            int32_t serial,
+            const std::vector<::aidl::android::hardware::radio::ims::ImsService>& imsServices)
+            override;
 };
 
 }  // namespace cf::ril
diff --git a/guest/hals/vehicle/README.md b/guest/hals/vehicle/README.md
new file mode 100644
index 000000000..9aab39a5d
--- /dev/null
+++ b/guest/hals/vehicle/README.md
@@ -0,0 +1,113 @@
+# Cuttlefish auto vehicle HAL implementation
+
+This folder contains the cuttlefish auto (cf_auto) vehicle HAL (VHAL)
+implementation. The 'android.hardware.automotive.vehicle@V3-cf-service' target
+is the VHAL binary. 'apex' folder defines the
+[vendor APEX](https://source.android.com/docs/core/ota/vendor-apex) for VHAL.
+
+## Architecture
+
+cf_auto VHAL is based on [Grpc VHAL architecture](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/automotive/vehicle/aidl/impl/current/README.md#grpc).
+The cvd launcher will starts a VHAL proxy server running on the host machine
+and the VHAL binary running on the client Android VM connects to the proxy
+server using GRPC.
+
+We support both Ethernet and Vsock as the communication channel.
+
+### Ethernet as communication channel
+
+By default Ethernet is used. We use a ethernet setup script
+(device/google/cuttlefish/shared/auto/auto_ethernet/ethernet.rc)
+running during AAOS (client) boot that sets up the Ethernet environment.
+
+It creates a network namespace: 'auto_eth' and move 'eth1' (which is the default
+Ethernet interface that connects to the host) to the network namespace. We use
+the network namespace to hide 'eth1' from the Android network stack to prevent
+Android network daemon configuring it after we manually configure the IP
+address. We then manually assign IP address and routing rule.
+
+The default Ethernet IP address for the host is '192.168.98.1'. The Ethernet IP
+address for each cf_auto clients are 192.168.98.[instance_id + 2], starting
+from 192.168.98.3, 192.168.98.4, etc. This is passed to AAOS using the boot
+argument "ro.boot.auto_eth_guest_addr".
+
+For each launch_cvd command, we start one VHAL proxy server instance by
+default. If multiple cf_auto instances are started in one command via
+'--instance_nums', then they all connect to the same server. The VHAL proxy
+server starts at the port: 9300 + [base_instance_num - 1].
+
+Clients may specify '--vhal_proxy_server_instance_num' to specify which server
+to connect to. If this is specified, no VHAL proxy server will be started,
+instead, the instances will connect to the VHAL proxy server started by
+the 'vhal_proxy-server_instance_num'.
+
+For example, if we want to start two instances that all connects to the same
+VHAL proxy server (meaning they share VHAL data), we can use:
+
+```
+launch_cvd --instance_nums 2
+```
+
+This starts two cf_auto instances and starts a VHAL proxy server running at
+`192.168.98.1:9300`. The two instaces will have IP address: `192.168.98.3`,
+`192.168.98.4`. Their VHALs connect to the VHAL proxy server.
+
+If we want to start a third instance that connects to the same VHAL proxy
+server using a separate command, we can use:
+
+```
+launch_cvd --base_instance_num=3 --vhal_proxy_server_instance_num=1
+```
+
+This starts another cf_auto instance at `192.168.98.5` and connects to the
+VHAL proxy server at `192.168.98.1:9300`.
+
+If we want to start a fourth instance that connects to a new VHAL proxy server,
+we can use:
+
+```
+launch_cvd --base_instance_num=4
+```
+
+This starts another cf_auto instance at `192.168.98.5` and starts a new VHAL
+proxy server at `192.168.98.1:9303`. The new instance connects to this new
+server.
+
+These options apply for 'vsock' as communication as well, except that vsock
+address takes a different format.
+
+### Vsock as communication channel
+
+If 'ethernet.rc' is not included in the build (by configuring
+`ENABLE_AUTO_ETHERNET` to false in mk file), we fallback to using vsock as
+the communication channel.
+
+The VHAL proxy server implementation serves as both an Ethernet server and
+as a vsock server. In fact, `vhal_proxy_server_cmd` always connects to the
+server using vsock.
+
+The concept is the same except that vsock uses a different address schema.
+
+The VHAL proxy server address is at `vsock:[VMADDR_CID_HOST]:port`, where port
+is the ethernet port (e.g. 9300).
+
+We do not need to assign vsock address to each client instance.
+
+## Debug
+
+Similar to regular VHAL, you could use the following debug command on the
+cf_auto instance:
+
+```
+dumpsys android.hardware.automotive.vehicle.IVehicle/default
+```
+
+Alternatively, you may also directly issue debug command to the VHAL proxy
+server. You could use the binary `vhal_proxy_server_cmd` on the host which will
+connects to the server. It takes the same argument as the VHAL debug command
+with an additional optional argument port, which specifies the server port.
+For example, you could use:
+
+```
+vhal_proxy_server_cmd --port 9300 --set PERF_VEHICLE_SPEED -f 1.234
+```
\ No newline at end of file
diff --git a/guest/monitoring/cuttlefish_service/Android.bp b/guest/monitoring/cuttlefish_service/Android.bp
index 05c24c68c..3d594baf0 100644
--- a/guest/monitoring/cuttlefish_service/Android.bp
+++ b/guest/monitoring/cuttlefish_service/Android.bp
@@ -20,8 +20,11 @@ android_app {
     name: "CuttlefishService",
     vendor: true,
     srcs: ["java/**/*.java"],
-    static_libs: ["guava"],
-    sdk_version: "28",
+    static_libs: [
+        "cuttlefish_properties",
+        "guava",
+    ],
+    sdk_version: "current",
     privileged: true,
     optimize: {
         proguard_flags_files: ["proguard.flags"],
diff --git a/guest/monitoring/cuttlefish_service/AndroidManifest.xml b/guest/monitoring/cuttlefish_service/AndroidManifest.xml
index 428445a42..0ea63b1b3 100644
--- a/guest/monitoring/cuttlefish_service/AndroidManifest.xml
+++ b/guest/monitoring/cuttlefish_service/AndroidManifest.xml
@@ -2,23 +2,24 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.google.gce.gceservice">
 
-    <uses-sdk android:minSdkVersion="5" />
-
     <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
     <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
+    <uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
+    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
     <uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />
     <uses-permission android:name="android.permission.INTERNET" />
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
-    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
+    <uses-permission android:name="android.permission.USE_EXACT_ALARM" />
     <uses-permission android:name="android.permission.WRITE_SETTINGS" />
-    <uses-permission android:name="android.permission.BLUETOOTH" />
 
     <application
         android:label="GceService"
         android:allowBackup="false">
 
-        <receiver android:name=".GceBroadcastReceiver">
+        <receiver android:name=".GceBroadcastReceiver"
+                  android:exported="true">
             <intent-filter android:priority="1000">
                 <!--
                    Do not register for other events here.
@@ -28,9 +29,12 @@
             </intent-filter>
         </receiver>
 
-        <service android:name=".GceService">
+        <service android:name=".GceService"
+                 android:exported="false"
+                 android:foregroundServiceType="systemExempted">
             <intent-filter>
-                <action android:name="com.android.google.gce.gceservice.CONFIGURE" />
+                <action android:name="com.android.google.gce.gceservice.BOOT_COMPLETED" />
+                <action android:name="com.android.google.gce.gceservice.CONFIGURATION_CHANGED" />
                 <action android:name="com.android.google.gce.gceservice.CONNECTIVITY_CHANGE" />
                 <action android:name="com.android.google.gce.gceservice.BLUETOOTH_CHANGED" />
             </intent-filter>
diff --git a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
index 54146cd47..6dd6b9fd6 100644
--- a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
+++ b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
@@ -21,6 +21,10 @@ import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.util.Log;
 
+import java.util.Optional;
+
+import com.google.cuttlefish.DeviceProperties;
+
 /*
  * A job that checks for Bluetooth being enabled before reporting VIRTUAL_DEVICE_BOOT_COMPLETED. Our
  * devices should always boot with bt enabled, it can be configured in
@@ -39,7 +43,13 @@ public class BluetoothChecker extends JobBase {
         PackageManager pm = context.getPackageManager();
         boolean hasBluetooth = pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH);
         if (!hasBluetooth) {
-            Log.i(LOG_TAG, "Bluetooth checker disabled");
+            Log.i(LOG_TAG, "Bluetooth checker disabled (feature missing)");
+            mEnabled.set(false);
+        }
+        Optional<Boolean> wantsBluetooth =
+            DeviceProperties.cuttlefish_service_bluetooth_checker();
+        if (wantsBluetooth.isPresent() && !wantsBluetooth.get()) {
+            Log.i(LOG_TAG, "Bluetooth checker disabled (by property)");
             mEnabled.set(false);
         }
     }
diff --git a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceBroadcastReceiver.java b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceBroadcastReceiver.java
index 7b8d864fb..52c0b51bc 100644
--- a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceBroadcastReceiver.java
+++ b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceBroadcastReceiver.java
@@ -41,7 +41,9 @@ public class GceBroadcastReceiver extends BroadcastReceiver {
             Log.i(LOG_TAG, "Received broadcast: " + action);
 
             if (action.equals(Intent.ACTION_BOOT_COMPLETED)) {
-                reportIntent(context, GceService.INTENT_ACTION_CONFIGURE);
+                reportIntent(context, GceService.INTENT_ACTION_BOOT_COMPLETED);
+            } else if (action.equals(Intent.ACTION_CONFIGURATION_CHANGED)) {
+                reportIntent(context, GceService.INTENT_ACTION_CONFIGURATION_CHANGED);
             } else if (action.equals(ConnectivityManager.CONNECTIVITY_ACTION)) {
                 reportIntent(context, GceService.INTENT_ACTION_NETWORK_CHANGED);
             } else if (action.equals(BluetoothAdapter.ACTION_STATE_CHANGED)) {
diff --git a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceService.java b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceService.java
index 0290679de..30df87e52 100644
--- a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceService.java
+++ b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/GceService.java
@@ -23,14 +23,16 @@ import android.bluetooth.BluetoothAdapter;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.content.pm.ServiceInfo;
 import android.content.res.Configuration;
 import android.graphics.Point;
+import android.hardware.display.DisplayManager;
 import android.net.ConnectivityManager;
-import android.util.Log;
 import android.os.IBinder;
+import android.util.Log;
+import android.util.DisplayMetrics;
 import android.view.Display;
 import android.view.Surface;
-import android.view.WindowManager;
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
 import java.util.List;
@@ -42,7 +44,8 @@ import java.util.List;
 public class GceService extends Service {
     private static final String LOG_TAG = "GceService";
     /* Intent sent by the BootCompletedReceiver upon receiving ACTION_BOOT_COMPLETED broadcast. */
-    public static final String INTENT_ACTION_CONFIGURE = "com.android.google.gce.gceservice.CONFIGURE";
+    public static final String INTENT_ACTION_BOOT_COMPLETED = "com.android.google.gce.gceservice.BOOT_COMPLETED";
+    public static final String INTENT_ACTION_CONFIGURATION_CHANGED = "com.android.google.gce.gceservice.CONFIGURATION_CHANGED";
     public static final String INTENT_ACTION_NETWORK_CHANGED = "com.android.google.gce.gceservice.NETWORK_CHANGED";
     public static final String INTENT_ACTION_BLUETOOTH_CHANGED = "com.android.google.gce.gceservice.BLUETOOTH_CHANGED";
     private static final String NOTIFICATION_CHANNEL_ID = "cuttlefish-service";
@@ -57,13 +60,10 @@ public class GceService extends Service {
     private ConnectivityChecker mConnChecker;
     private GceWifiManager mWifiManager = null;
     private String mMostRecentAction = null;
-    private WindowManager mWindowManager;
 
+    private DisplayMetrics mPreviousDisplayMetrics;
+    private Display mDefaultDisplay;
     private int mPreviousRotation;
-    private Point mPreviousScreenBounds;
-    private int mPreviousDpi;
-
-
     public GceService() {}
 
 
@@ -74,15 +74,14 @@ public class GceService extends Service {
             mEventReporter.reportBootStarted();
             registerBroadcastReceivers();
 
-            mWindowManager = getSystemService(WindowManager.class);
+            mPreviousDisplayMetrics = getResources().getDisplayMetrics();
+            mDefaultDisplay = getSystemService(DisplayManager.class).getDisplay(0);
+            mPreviousRotation = getRotation();
+
             mConnChecker = new ConnectivityChecker(this, mEventReporter);
             mWifiManager = new GceWifiManager(this, mEventReporter, mExecutor);
             mBluetoothChecker = new BluetoothChecker(this);
 
-            mPreviousRotation = getRotation();
-            mPreviousScreenBounds = getScreenBounds();
-            mPreviousDpi = getResources().getConfiguration().densityDpi;
-
             mExecutor.schedule(mWifiManager);
             mExecutor.schedule(mBluetoothChecker);
             mExecutor.schedule(mConnChecker);
@@ -117,20 +116,14 @@ public class GceService extends Service {
      */
     private void registerBroadcastReceivers() {
         IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_CONFIGURATION_CHANGED);
         filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
         filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
         this.registerReceiver(mBroadcastReceiver, filter);
     }
 
-    private Point getScreenBounds() {
-        Display display = mWindowManager.getDefaultDisplay();
-        Point screenBounds = new Point();
-        display.getRealSize(screenBounds);
-        return screenBounds;
-    }
-
     private int getRotation() {
-      int rot = mWindowManager.getDefaultDisplay().getRotation();
+      int rot = mDefaultDisplay.getRotation();
       switch (rot) {
         case Surface.ROTATION_0:
           return 0;
@@ -144,32 +137,6 @@ public class GceService extends Service {
       throw new IllegalStateException("Rotation should be one of 0,90,180,270");
     }
 
-    @Override
-    public void onConfigurationChanged(Configuration config) {
-        super.onConfigurationChanged(config);
-
-        int rotation = getRotation();
-        Point screenBounds = getScreenBounds();
-        int dpi = config.densityDpi;
-        // NOTE: We cannot rely on config.diff(previous config) here because
-        // diff shows CONFIG_SCREEN_SIZE changes when changing between 3-button
-        // and gesture navigation. We only care about the display bounds.
-        if (rotation == mPreviousRotation &&
-            screenBounds.equals(mPreviousScreenBounds) &&
-            dpi == mPreviousDpi) {
-            return;
-        }
-
-        int width = screenBounds.x;
-        int height = screenBounds.y;
-        mEventReporter.reportScreenChanged(width, height, dpi, rotation);
-
-        mPreviousRotation = rotation;
-        mPreviousScreenBounds = screenBounds;
-        mPreviousDpi = dpi;
-    }
-
-
     /** StartService entry point.
      */
     @Override
@@ -193,10 +160,22 @@ public class GceService extends Service {
                         .build();
         // Start in the Foreground (and do not stop) so that this service
         // continues running and reporting events without being killed.
-        startForeground(NOTIFICATION_ID, notification);
+        startForeground(NOTIFICATION_ID, notification,
+                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
 
-        if (INTENT_ACTION_CONFIGURE.equals(mMostRecentAction)) {
+        if (INTENT_ACTION_BOOT_COMPLETED.equals(mMostRecentAction)) {
             mExecutor.schedule(mConnChecker);
+        } else if (INTENT_ACTION_CONFIGURATION_CHANGED.equals(mMostRecentAction)) {
+            DisplayMetrics displayMetrics = getResources().getDisplayMetrics();
+            int rotation = getRotation();
+            if (!displayMetrics.equals(mPreviousDisplayMetrics) || rotation != mPreviousRotation) {
+                int dpi = displayMetrics.densityDpi;
+                int width = displayMetrics.widthPixels;
+                int height = displayMetrics.heightPixels;
+                mEventReporter.reportScreenChanged(width, height, dpi, rotation);
+                mPreviousDisplayMetrics = displayMetrics;
+                mPreviousRotation = rotation;
+            }
         } else if (INTENT_ACTION_NETWORK_CHANGED.equals(mMostRecentAction)) {
             mExecutor.schedule(mConnChecker);
         } else if (INTENT_ACTION_BLUETOOTH_CHANGED.equals(mMostRecentAction)) {
diff --git a/guest/sysprops/Android.bp b/guest/sysprops/Android.bp
new file mode 100644
index 000000000..670c18401
--- /dev/null
+++ b/guest/sysprops/Android.bp
@@ -0,0 +1,24 @@
+// Copyright 2025 Google Inc. All Rights Reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
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
+sysprop_library {
+    name: "cuttlefish_properties",
+    srcs: ["cuttlefish.sysprop"],
+    property_owner: "Vendor",
+    vendor: true,
+}
diff --git a/guest/sysprops/cuttlefish.sysprop b/guest/sysprops/cuttlefish.sysprop
new file mode 100644
index 000000000..bd624e8f9
--- /dev/null
+++ b/guest/sysprops/cuttlefish.sysprop
@@ -0,0 +1,10 @@
+owner: Vendor
+module: "com.google.cuttlefish.DeviceProperties"
+
+prop {
+    api_name: "cuttlefish_service_bluetooth_checker"
+    type: Boolean
+    prop_name: "ro.vendor.cuttlefish_service_bluetooth_checker"
+    scope: Internal
+    access: Readonly
+}
diff --git a/host/commands/assemble_cvd/boot_image_utils.cc b/host/commands/assemble_cvd/boot_image_utils.cc
index ff7a6518b..054ce1e08 100644
--- a/host/commands/assemble_cvd/boot_image_utils.cc
+++ b/host/commands/assemble_cvd/boot_image_utils.cc
@@ -180,8 +180,7 @@ void UnpackRamdisk(const std::string& original_ramdisk_path,
   int cpio_status;
   do {
     LOG(ERROR) << "Running";
-    cpio_status = Command(HostBinaryPath("toybox"))
-                      .AddParameter("cpio")
+    cpio_status = Command(CpioBinary())
                       .AddParameter("-idu")
                       .SetWorkingDirectory(ramdisk_stage_dir)
                       .RedirectStdIO(Subprocess::StdIOChannel::kStdIn, input)
diff --git a/host/commands/assemble_cvd/bootconfig_args.cpp b/host/commands/assemble_cvd/bootconfig_args.cpp
index 7180c7090..499d48ab3 100644
--- a/host/commands/assemble_cvd/bootconfig_args.cpp
+++ b/host/commands/assemble_cvd/bootconfig_args.cpp
@@ -209,6 +209,21 @@ Result<std::unordered_map<std::string, std::string>> BootconfigArgsFromConfig(
           ? "com.android.hardware.gatekeeper.nonsecure"
           : "com.android.hardware.gatekeeper.cf_remote";
 
+  // jcardsimulator
+  if (secure_hals.count(SecureHal::kGuestStrongboxInsecure)) {
+    bootconfig_args
+        ["androidboot.vendor.apex.com.android.hardware.secure_element"] =
+            "com.android.hardware.secure_element_jcardsim";
+    bootconfig_args["androidboot.vendor.apex.com.android.hardware.strongbox"] =
+        "com.android.hardware.strongbox";
+  } else {
+    bootconfig_args
+        ["androidboot.vendor.apex.com.android.hardware.secure_element"] =
+            "com.android.hardware.secure_element";
+    bootconfig_args["androidboot.vendor.apex.com.android.hardware.strongbox"] =
+        "none";
+  }
+
   bootconfig_args
       ["androidboot.vendor.apex.com.android.hardware.graphics.composer"] =
           instance.hwcomposer() == kHwComposerDrm
@@ -226,6 +241,12 @@ Result<std::unordered_map<std::string, std::string>> BootconfigArgsFromConfig(
         fmt::format("192.168.98.{}", instance_id + 2);
   }
 
+  if (config.virtio_mac80211_hwsim()) {
+    bootconfig_args["androidboot.wifi_impl"] = "mac80211_hwsim_virtio";
+  } else {
+    bootconfig_args["androidboot.wifi_impl"] = "virt_wifi";
+  }
+
   if (!instance.vcpu_config_path().empty()) {
     auto vcpu_config_json =
         CF_EXPECT(LoadFromFile(instance.vcpu_config_path()));
diff --git a/host/commands/assemble_cvd/flags.cc b/host/commands/assemble_cvd/flags.cc
index 74b5dc530..22c55a984 100644
--- a/host/commands/assemble_cvd/flags.cc
+++ b/host/commands/assemble_cvd/flags.cc
@@ -485,6 +485,10 @@ DEFINE_vec(enable_audio, fmt::format("{}", CF_DEFAULTS_ENABLE_AUDIO),
 DEFINE_vec(enable_usb, fmt::format("{}", CF_DEFAULTS_ENABLE_USB),
            "Whether to allow USB passthrough on the device");
 
+DEFINE_vec(enable_jcard_simulator,
+           fmt::format("{}", CF_DEFAULTS_ENABLE_JCARD_SIMULATOR),
+           "Whether to allow host jcard simulator on the device");
+
 DEFINE_vec(camera_server_port, std::to_string(CF_DEFAULTS_CAMERA_SERVER_PORT),
               "camera vsock port");
 
@@ -793,6 +797,16 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
                                      << "\" for output audio stream count");
     }
 
+    Result<std::string> enforce_mac80211_hwsim = GetAndroidInfoConfig(
+        instance_android_info_txt, "enforce_mac80211_hwsim");
+    if (enforce_mac80211_hwsim.ok()) {
+      if (*enforce_mac80211_hwsim == "true") {
+        guest_config.enforce_mac80211_hwsim = true;
+      } else if (*enforce_mac80211_hwsim == "false") {
+        guest_config.enforce_mac80211_hwsim = false;
+      }
+    }
+
     guest_configs.push_back(guest_config);
   }
   return guest_configs;
@@ -947,7 +961,7 @@ Result<std::vector<bool>> GetFlagBoolValueForInstances(
 
   for (int instance_index=0; instance_index<instances_size; instance_index++) {
     if (instance_index >= flag_vec.size()) {
-      value_vec[instance_index] = CF_EXPECT(ParseBool(flag_vec[0], flag_name));
+      value_vec[instance_index] = value_vec[0];
     } else {
       if (flag_vec[instance_index] == "unset" || flag_vec[instance_index] == "\"unset\"") {
         std::string default_value = default_value_vec[0];
@@ -974,8 +988,7 @@ Result<std::vector<int>> GetFlagIntValueForInstances(
 
   for (int instance_index=0; instance_index<instances_size; instance_index++) {
     if (instance_index >= flag_vec.size()) {
-      CF_EXPECT(android::base::ParseInt(flag_vec[0].c_str(), &value_vec[instance_index]),
-      "Failed to parse value \"" << flag_vec[0] << "\" for " << flag_name);
+      value_vec[instance_index] = value_vec[0];
     } else {
       if (flag_vec[instance_index] == "unset" || flag_vec[instance_index] == "\"unset\"") {
         std::string default_value = default_value_vec[0];
@@ -1006,7 +1019,7 @@ Result<std::vector<std::string>> GetFlagStrValueForInstances(
 
   for (int instance_index=0; instance_index<instances_size; instance_index++) {
     if (instance_index >= flag_vec.size()) {
-      value_vec[instance_index] = flag_vec[0];
+      value_vec[instance_index] = value_vec[0];
     } else {
       if (flag_vec[instance_index] == "unset" || flag_vec[instance_index] == "\"unset\"") {
         std::string default_value = default_value_vec[0];
@@ -1189,11 +1202,13 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   tmp_config_obj.set_enable_metrics(FLAGS_report_anonymous_usage_stats);
   // TODO(moelsherif): Handle this flag (set_metrics_binary) in the future
 
-#ifdef ENFORCE_MAC80211_HWSIM
-  tmp_config_obj.set_virtio_mac80211_hwsim(true);
-#else
-  tmp_config_obj.set_virtio_mac80211_hwsim(false);
-#endif
+  std::optional<bool> guest_config_mac80211_hwsim =
+      guest_configs[0].enforce_mac80211_hwsim;
+  if (guest_config_mac80211_hwsim.has_value()) {
+    tmp_config_obj.set_virtio_mac80211_hwsim(*guest_config_mac80211_hwsim);
+  } else {
+    tmp_config_obj.set_virtio_mac80211_hwsim(true);
+  }
 
   if ((FLAGS_ap_rootfs_image.empty()) != (FLAGS_ap_kernel_image.empty())) {
     LOG(FATAL) << "Either both ap_rootfs_image and ap_kernel_image should be "
@@ -1316,6 +1331,8 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
       CF_EXPECT(GET_FLAG_STR_VALUE(vhost_user_vsock));
   std::vector<std::string> ril_dns_vec =
       CF_EXPECT(GET_FLAG_STR_VALUE(ril_dns));
+  std::vector<bool> enable_jcard_simulator_vec =
+      CF_EXPECT(GET_FLAG_BOOL_VALUE(enable_jcard_simulator));
 
   // At this time, FLAGS_enable_sandbox comes from SetDefaultFlagsForCrosvm
   std::vector<bool> enable_sandbox_vec = CF_EXPECT(GET_FLAG_BOOL_VALUE(
@@ -1594,6 +1611,25 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     instance.set_audio_output_streams_count(
         guest_configs[instance_index].output_audio_streams_count);
 
+    // jcardsim
+    instance.set_enable_jcard_simulator(
+        enable_jcard_simulator_vec[instance_index]);
+
+    if (enable_jcard_simulator_vec[instance_index]) {
+      const auto& secure_hals = CF_EXPECT(tmp_config_obj.secure_hals());
+      if (0 == secure_hals.count(SecureHal::kGuestStrongboxInsecure)) {
+        // When the enable_jcard_simulator flag is enabled, include the keymint
+        // and secure_element hals, which interact with jcard simulator.
+        static constexpr char kDefaultSecure[] =
+            "oemlock,guest_keymint_insecure,guest_gatekeeper_insecure,guest_"
+            "strongbox_insecure";
+
+        auto secure_hals = CF_EXPECT(ParseSecureHals(kDefaultSecure));
+        CF_EXPECT(ValidateSecureHals(secure_hals));
+        tmp_config_obj.set_secure_hals(secure_hals);
+      }
+    }
+
     if (vhost_user_vsock_vec[instance_index] == kVhostUserVsockModeAuto) {
       std::set<Arch> default_on_arch = {Arch::Arm64};
       if (guest_configs[instance_index].vhost_user_vsock) {
diff --git a/host/commands/assemble_cvd/flags.h b/host/commands/assemble_cvd/flags.h
index 42a01a106..e491b0ad1 100644
--- a/host/commands/assemble_cvd/flags.h
+++ b/host/commands/assemble_cvd/flags.h
@@ -44,6 +44,7 @@ struct GuestConfig {
   std::optional<std::string> custom_keyboard_config;
   std::optional<std::string> domkey_mapping_config;
   int output_audio_streams_count = 1;
+  std::optional<bool> enforce_mac80211_hwsim;
 };
 
 Result<std::vector<GuestConfig>> GetGuestConfigAndSetDefaults();
diff --git a/host/commands/assemble_cvd/flags_defaults.h b/host/commands/assemble_cvd/flags_defaults.h
index 22ef2d963..8cd8f3ca8 100644
--- a/host/commands/assemble_cvd/flags_defaults.h
+++ b/host/commands/assemble_cvd/flags_defaults.h
@@ -37,7 +37,7 @@
 #define CF_DEFAULTS_DISPLAY_WIDTH 720
 #define CF_DEFAULTS_DISPLAY_HEIGHT 1280
 #define CF_DEFAULTS_DISPLAYS_TEXTPROTO ""
-#define CF_DEFAULTS_CPUS 2
+#define CF_DEFAULTS_CPUS 4
 #define CF_DEFAULTS_RESUME true
 #define CF_DEFAULTS_DAEMON false
 #define CF_DEFAULTS_VM_MANAGER CF_DEFAULTS_DYNAMIC_STRING
@@ -211,6 +211,9 @@
 // USB Passhtrough default parameters
 #define CF_DEFAULTS_ENABLE_USB false
 
+// Jcardsim default parameters
+#define CF_DEFAULTS_ENABLE_JCARD_SIMULATOR false
+
 // Streaming default parameters
 #define CF_DEFAULTS_START_WEBRTC false
 #define CF_DEFAULTS_START_WEBRTC_SIG_SERVER true
diff --git a/host/commands/control_env_proxy_server/Android.bp b/host/commands/control_env_proxy_server/Android.bp
index 3639d1410..088ce2c68 100644
--- a/host/commands/control_env_proxy_server/Android.bp
+++ b/host/commands/control_env_proxy_server/Android.bp
@@ -54,8 +54,8 @@ cc_binary_host {
         "libprotobuf-cpp-full",
     ],
     static_libs: [
+        "absl_flags_parse",
         "grpc_cli_libs",
-        "libabsl_host",
         "libcontrol_env_proxy_server",
         "libcuttlefish_control_env",
         "libcuttlefish_host_config",
diff --git a/host/commands/cvd_env/Android.bp b/host/commands/cvd_env/Android.bp
index 36162ac71..ba347c477 100644
--- a/host/commands/cvd_env/Android.bp
+++ b/host/commands/cvd_env/Android.bp
@@ -32,8 +32,8 @@ cc_binary_host {
         "libprotobuf-cpp-full",
     ],
     static_libs: [
+        "absl_flags_parse",
         "grpc_cli_libs",
-        "libabsl_host",
         "libcuttlefish_control_env",
     ],
     cflags: [
diff --git a/host/commands/kernel_log_monitor/kernel_log_server.cc b/host/commands/kernel_log_monitor/kernel_log_server.cc
index e7df6c40f..b3b5505df 100644
--- a/host/commands/kernel_log_monitor/kernel_log_server.cc
+++ b/host/commands/kernel_log_monitor/kernel_log_server.cc
@@ -59,6 +59,7 @@ constexpr struct {
     {kAdbdStartedMessage, Event::AdbdStarted, kBare},
     {kFastbootdStartedMessage, Event::FastbootStarted, kBare},
     {kFastbootStartedMessage, Event::FastbootStarted, kBare},
+    {kGblFastbootStartedMessage, Event::FastbootStarted, kBare},
     {kScreenChangedMessage, Event::ScreenChanged, kKeyValuePair},
     {kBootloaderLoadedMessage, Event::BootloaderLoaded, kBare},
     {kKernelLoadedMessage, Event::KernelLoaded, kBare},
diff --git a/host/commands/process_sandboxer/Android.bp b/host/commands/process_sandboxer/Android.bp
index e84e245b3..e78bbf960 100644
--- a/host/commands/process_sandboxer/Android.bp
+++ b/host/commands/process_sandboxer/Android.bp
@@ -70,7 +70,22 @@ cc_binary_host {
     ],
     shared_libs: ["sandboxed_api_sandbox2"],
     static_libs: [
-        "libabsl_host",
+        "absl_container_flat_hash_map",
+        "absl_container_flat_hash_set",
+        "absl_flags_flag",
+        "absl_flags_parse",
+        "absl_functional_bind_front",
+        "absl_log",
+        "absl_log_check",
+        "absl_log_die_if_null",
+        "absl_log_initialize",
+        "absl_random",
+        "absl_random_bit_gen_ref",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_strings_string_view",
+        "absl_types_optional",
+        "absl_types_span",
         "libcap",
         "libprocess_sandboxer_proxy_common",
     ],
@@ -88,7 +103,10 @@ cc_library_static {
     name: "libprocess_sandboxer_proxy_common",
     defaults: ["cuttlefish_buildhost_only"],
     srcs: ["proxy_common.cpp"],
-    static_libs: ["libabsl_host"],
+    static_libs: [
+        "absl_status",
+        "absl_status_statusor",
+    ],
     target: {
         darwin: {
             enabled: false,
@@ -106,7 +124,9 @@ cc_binary_host {
         "sandboxer_proxy.cpp",
     ],
     static_libs: [
-        "libabsl_host",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_strings",
         "libprocess_sandboxer_proxy_common",
     ],
     target: {
diff --git a/host/commands/run_cvd/boot_state_machine.cc b/host/commands/run_cvd/boot_state_machine.cc
index d9fb1e511..784c9ec9e 100644
--- a/host/commands/run_cvd/boot_state_machine.cc
+++ b/host/commands/run_cvd/boot_state_machine.cc
@@ -55,6 +55,19 @@ DEFINE_int32(reboot_notification_fd, CF_DEFAULTS_REBOOT_NOTIFICATION_FD,
 namespace cuttlefish {
 namespace {
 
+Result<void> MoveSelfToCgroup(const std::string& id) {
+  auto to_path_file = "/sys/fs/cgroup/vsoc-" + id + "-cf/cgroup.procs";
+  auto pid = std::to_string(getpid());
+  SharedFD fd = SharedFD::Open(to_path_file, O_WRONLY | O_APPEND);
+  CF_EXPECT(fd->IsOpen(),
+            "failed to open " << to_path_file << ": " << fd->StrError());
+  if (WriteAll(fd, pid) != pid.size()) {
+    return CF_ERR("failed to write to" << to_path_file);
+  }
+
+  return {};
+}
+
 Result<void> MoveThreadsToCgroup(const std::string& from_path,
                                  const std::string& to_path) {
   std::string file_path = from_path + "/cgroup.threads";
@@ -210,6 +223,12 @@ Result<SharedFD> ProcessLeader(
     CF_EXPECT(SharedFD::Fifo(instance.restore_adbd_pipe_name(), 0600),
               "Unable to create adbd restore fifo");
   }
+
+  // Move to designated cgroup path when running with vcpufreq enabled.
+  if (!instance.vcpu_config_path().empty()) {
+    CF_EXPECT(MoveSelfToCgroup(instance.id()));
+  }
+
   /* These two paths result in pretty different process state, but both
    * achieve the same goal of making the current process the leader of a
    * process group, and are therefore grouped together. */
@@ -511,6 +530,15 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
         if (!read_result) {
           return;
         }
+        if ((*read_result)->event == monitor::Event::BootCompleted) {
+          LOG(INFO) << "Virtual device rebooted successfully";
+          if (!instance_.vcpu_config_path().empty()) {
+            auto res = WattsonRebalanceThreads(instance_.id());
+            if (!res.ok()) {
+              LOG(ERROR) << res.error().FormatForEnv();
+            }
+          }
+        }
       }
     }
   }
diff --git a/host/commands/run_cvd/launch/launch.h b/host/commands/run_cvd/launch/launch.h
index decc226cf..0b88a06f8 100644
--- a/host/commands/run_cvd/launch/launch.h
+++ b/host/commands/run_cvd/launch/launch.h
@@ -150,5 +150,5 @@ Ti50EmulatorComponent();
 
 Result<MonitorCommand> SensorsSimulator(
     const CuttlefishConfig::InstanceSpecific&,
-    AutoSensorsSocketPair::Type& sensors_socket_pair);
+    AutoSensorsSocketPair::Type& sensors_socket_pair, KernelLogPipeProvider&);
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/sensors_simulator.cpp b/host/commands/run_cvd/launch/sensors_simulator.cpp
index 0792bf2af..3b5cfdb21 100644
--- a/host/commands/run_cvd/launch/sensors_simulator.cpp
+++ b/host/commands/run_cvd/launch/sensors_simulator.cpp
@@ -20,7 +20,8 @@ namespace cuttlefish {
 
 Result<MonitorCommand> SensorsSimulator(
     const CuttlefishConfig::InstanceSpecific& instance,
-    AutoSensorsSocketPair::Type& sensors_socket_pair) {
+    AutoSensorsSocketPair::Type& sensors_socket_pair,
+    KernelLogPipeProvider& kernel_log_pipe_provider) {
   std::string to_guest_pipe_path =
       instance.PerInstanceInternalPath("sensors_fifo_vm.in");
   std::string from_guest_pipe_path =
@@ -32,7 +33,10 @@ Result<MonitorCommand> SensorsSimulator(
   Command command(SensorsSimulatorBinary());
   command.AddParameter("--sensors_in_fd=", from_guest_fd)
       .AddParameter("--sensors_out_fd=", to_guest_fd)
-      .AddParameter("--webrtc_fd=", sensors_socket_pair->webrtc_socket);
+      .AddParameter("--webrtc_fd=", sensors_socket_pair->webrtc_socket)
+      .AddParameter("-kernel_events_fd=",
+                    kernel_log_pipe_provider.KernelLogPipe())
+      .AddParameter("--device_type=", static_cast<int>(instance.device_type()));
   return command;
 }
 
diff --git a/host/commands/secure_env/Android.bp b/host/commands/secure_env/Android.bp
index 41b3b2f23..2cf18bc53 100644
--- a/host/commands/secure_env/Android.bp
+++ b/host/commands/secure_env/Android.bp
@@ -113,9 +113,12 @@ cc_library {
         "libcuttlefish_run_cvd_proto",
         "libprotobuf-cpp-full",
     ],
+    header_libs: ["jni_headers"],
     srcs: common_libsecure_srcs + [
         "confui_sign_server.cpp",
         "device_tpm.cpp",
+        "jcardsim_interface.cpp",
+        "jcardsim_responder.cpp",
         "oemlock/oemlock.cpp",
         "oemlock/oemlock_responder.cpp",
         "storage/insecure_json_storage.cpp",
@@ -154,6 +157,7 @@ cc_binary_host {
     static_libs: [
         "libgflags_cuttlefish",
     ],
+    header_libs: ["jni_headers"],
     target: {
         windows: {
             enabled: true,
@@ -198,6 +202,7 @@ cc_library {
     ],
     header_libs: [
         "cuttlefish_common_headers",
+        "jni_headers",
     ],
     target: {
         windows: {
diff --git a/host/commands/secure_env/jcardsim_interface.cpp b/host/commands/secure_env/jcardsim_interface.cpp
new file mode 100644
index 000000000..480e144e4
--- /dev/null
+++ b/host/commands/secure_env/jcardsim_interface.cpp
@@ -0,0 +1,275 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "host/commands/secure_env/jcardsim_interface.h"
+
+#include <dlfcn.h>
+#include <string>
+
+#include <android-base/logging.h>
+
+#include "common/libs/utils/environment.h"
+#include "common/libs/utils/files.h"
+#include "host/commands/secure_env/tpm_ffi.h"
+#include "host/libs/config/config_utils.h"
+
+namespace cuttlefish {
+
+constexpr uint8_t kKeyMintAppletAid[] = {0xa0, 0x00, 0x00, 0x00, 0x62, 0x03,
+                                         0x02, 0x0c, 0x01, 0x01, 0x01};
+
+constexpr uint8_t kManageChannel[] = {0x00, 0x70, 0x00, 0x00, 0x01};
+constexpr uint8_t KM3_P1 = 0x60;
+constexpr int32_t kSuccess = 0x9000;
+constexpr std::string kLibJvm = "lib/server/libjvm.so";
+constexpr std::string kDefaultJavaPath = "/usr/lib/jvm/jdk-64";
+constexpr std::string kJcardsimJar = "framework/jcardsim.jar";
+
+namespace {
+
+std::string JVMLibrary() {
+  return StringFromEnv("JAVA_HOME", kDefaultJavaPath) + "/" + kLibJvm;
+}
+
+std::string JcardSimLib() { return DefaultHostArtifactsPath(kJcardsimJar); }
+
+Result<void> ResponseOK(const std::vector<uint8_t>& response) {
+  CF_EXPECT(response.size() >= 2, "Response Size less than 2");
+  size_t size = response.size();
+  CF_EXPECT(((response[size - 2] << 8) | response[size - 1]) == kSuccess);
+  return {};
+}
+
+Result<JNIEnv*> GetOrAttachJNIEnvironment(JavaVM* jvm) {
+  JNIEnv* env;
+  auto resp = jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
+  if (resp != JNI_OK) {
+    resp = jvm->AttachCurrentThread(&env, nullptr);
+    CF_EXPECT(resp == JNI_OK, "JVM thread attach failed.");
+    struct VmThreadDetacher {
+      VmThreadDetacher(JavaVM* vm) : mVm(vm) {}
+      ~VmThreadDetacher() { mVm->DetachCurrentThread(); }
+
+     private:
+      JavaVM* const mVm;
+    };
+    static thread_local VmThreadDetacher detacher(jvm);
+  }
+  return env;
+}
+
+}  // namespace
+
+Result<std::unique_ptr<JCardSimInterface>> JCardSimInterface::Create() {
+  std::string jvm_lib = JVMLibrary();
+  void* handle = dlopen(jvm_lib.c_str(), RTLD_NOW | RTLD_NODELETE);
+  CF_EXPECT(handle != nullptr, "Failed to open JVM library");
+
+  JavaVMInitArgs args;
+  JavaVMOption options[1];
+
+  args.version = JNI_VERSION_1_6;
+  args.nOptions = 1;
+  std::string option_str = std::string("-Djava.class.path=") + JcardSimLib();
+  options[0].optionString = option_str.c_str();
+  args.options = options;
+  args.ignoreUnrecognized = JNI_FALSE;
+
+  typedef jint (*p_JNI_CreateJavaVM)(JavaVM**, void**, void**);
+  p_JNI_CreateJavaVM jni_create_java_vm =
+      (p_JNI_CreateJavaVM)dlsym(handle, "JNI_CreateJavaVM");
+  CF_EXPECT(jni_create_java_vm != nullptr, "JNI_CreateJavaVM Symbol not found");
+
+  JavaVM* jvm;
+  JNIEnv* env;
+  jint ret = jni_create_java_vm(&jvm, (void**)&env, (void**)&args);
+  CF_EXPECT(ret == JNI_OK, "Failed to create JavaVM");
+
+  auto jcardsim_interface =
+      std::unique_ptr<JCardSimInterface>(new JCardSimInterface(jvm));
+  CF_EXPECT(jcardsim_interface->PersonalizeKeymintApplet(env));
+  CF_EXPECT(jcardsim_interface->ProvisionPresharedSecret(env));
+  return jcardsim_interface;
+}
+
+JCardSimInterface::JCardSimInterface(JavaVM* jvm)
+    : jcardsim_proxy_inst_(nullptr),
+      jcardsim_proxy_class_(nullptr),
+      jvm_(jvm) {}
+
+JCardSimInterface::~JCardSimInterface() {
+  auto result = GetOrAttachJNIEnvironment(jvm_);
+  if (result.ok()) {
+    JNIEnv* env = result.value();
+    if (jcardsim_proxy_class_) {
+      env->DeleteGlobalRef(jcardsim_proxy_class_);
+      jcardsim_proxy_class_ = nullptr;
+    }
+    if (jcardsim_proxy_inst_) {
+      env->DeleteGlobalRef(jcardsim_proxy_inst_);
+      jcardsim_proxy_inst_ = nullptr;
+    }
+  }
+}
+
+Result<void> JCardSimInterface::PersonalizeKeymintApplet(JNIEnv* env) {
+  jclass jcardsim_proxy_class =
+      env->FindClass("com/android/javacard/jcproxy/JCardSimProxy");
+  CF_EXPECT(jcardsim_proxy_class != nullptr, "JCardSimProxy class not found");
+
+  // Create Global reference to JCardSimProxy class
+  jcardsim_proxy_class_ =
+      reinterpret_cast<jclass>(env->NewGlobalRef(jcardsim_proxy_class));
+
+  jmethodID constructor =
+      env->GetMethodID(jcardsim_proxy_class, "<init>", "()V");
+  CF_EXPECT(constructor != nullptr, "Constructor method not found");
+
+  // Create Object
+  jobject main_obj = env->NewObject(jcardsim_proxy_class, constructor);
+  CF_EXPECT(main_obj != nullptr, "Failed to create JCardSimProxy instance");
+
+  // Create Global reference to JCardSimProxy instance
+  jcardsim_proxy_inst_ = reinterpret_cast<jobject>(env->NewGlobalRef(main_obj));
+
+  jmethodID init_method =
+      env->GetMethodID(jcardsim_proxy_class, "initialize", "()V");
+  CF_EXPECT(init_method != nullptr, "Initialize method not found");
+
+  // Call initialize method on JCardSimProxy
+  env->CallVoidMethod(jcardsim_proxy_inst_, init_method);
+  return {};
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::OpenChannel(JNIEnv* env) {
+  int size = sizeof(kManageChannel) / sizeof(kManageChannel[0]);
+  std::vector<uint8_t> manage_channel(kManageChannel, kManageChannel + size);
+  return CF_EXPECT(
+      InternalTransmit(env, manage_channel.data(), manage_channel.size()));
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::SelectKeymintApplet(
+    JNIEnv* env, uint8_t cla) {
+  uint8_t aid_size = sizeof(kKeyMintAppletAid) / sizeof(kKeyMintAppletAid[0]);
+  std::vector<uint8_t> select_cmd = {
+      cla,
+      0xA4, /* Instruction code */
+      0x04, /* Instruction parameter 1 */
+      0x00, /* Instruction parameter 2 */
+      static_cast<uint8_t>(aid_size),
+  };
+  select_cmd.insert(select_cmd.end(), kKeyMintAppletAid,
+                    kKeyMintAppletAid + aid_size);
+  select_cmd.push_back((uint8_t)0x00);
+  return CF_EXPECT(InternalTransmit(env, select_cmd.data(), select_cmd.size()));
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::CloseChannel(
+    JNIEnv* env, uint8_t channel_number) {
+  std::vector<uint8_t> close_channel = {0x00, 0x70, 0x80, channel_number, 0x00};
+  return CF_EXPECT(
+      InternalTransmit(env, close_channel.data(), close_channel.size()));
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::PreSharedKey() {
+  return std::vector<uint8_t>(32, 0);
+}
+
+Result<void> JCardSimInterface::ProvisionPresharedSecret(JNIEnv* env) {
+  std::vector<uint8_t> key =
+      CF_EXPECT(PreSharedKey(), "Failed to get pre-shared key");
+
+  auto response = CF_EXPECT(OpenChannel(env));
+  CF_EXPECT(ResponseOK(response), "Open Channel command failed");
+
+  uint8_t cla = 0xff;
+  if ((response[0] > 0x03) && (response[0] < 0x14)) {
+    // update CLA byte according to GP spec Table 11-12
+    cla = (0x40 + (response[0] - 4));
+  } else if ((response[0] > 0x00) && (response[0] < 0x04)) {
+    // update CLA byte according to GP spec Table 11-11
+    cla = response[0];
+  } else {
+    CF_ERR("Invalid Channel " << response[0]);
+  }
+  uint8_t channel_number = response[0];
+
+  do {
+    auto response = SelectKeymintApplet(env, cla);
+    if (!response.ok() || !ResponseOK(*response).ok()) {
+      LOG(ERROR) << "Failed to select the Applet";
+      break;
+    }
+
+    // send preshared secret apdu
+    std::vector<uint8_t> shared_secret_apdu = {
+        static_cast<uint8_t>(0x80 | channel_number),  // CLA
+        0x0F,                                         // INS
+        KM3_P1,                                       // P1
+        0x00,                                         // P2
+        0x00,                                         // Lc - 0x000023
+        0x00,
+        0x23,
+        0x81,  // Array of size 1
+        0x58,  // byte string with additional information(24)
+        0x20,  // length of the bytestring(32)
+    };
+    shared_secret_apdu.insert(shared_secret_apdu.end(), key.begin(), key.end());
+    shared_secret_apdu.push_back(0x00);  // Le 0x0000
+    shared_secret_apdu.push_back(0x00);
+    response = InternalTransmit(env, shared_secret_apdu.data(),
+                                shared_secret_apdu.size());
+    if (!response.ok() || !ResponseOK(*response).ok()) {
+      LOG(ERROR) << "Failed to provision preshared secret";
+      break;
+    }
+  } while (false);
+
+  response = CF_EXPECT(CloseChannel(env, channel_number));
+  CF_EXPECT(ResponseOK(response), "Close Channel command failed");
+  return {};
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::InternalTransmit(
+    JNIEnv* env, const uint8_t* bytes, size_t len) const {
+  std::vector<uint8_t> out;
+  jmethodID transmit =
+      env->GetMethodID(jcardsim_proxy_class_, "transmit", "([B)[B");
+  if (transmit == nullptr) {
+    LOG(ERROR) << "ERROR: transmit method not found !";
+    return out;
+  }
+  jbyteArray java_array = env->NewByteArray(len);
+  env->SetByteArrayRegion(java_array, 0, len,
+                          reinterpret_cast<const jbyte*>(bytes));
+  jbyteArray resp_array = (jbyteArray)env->CallObjectMethod(
+      jcardsim_proxy_inst_, transmit, java_array);
+  jsize num_bytes = env->GetArrayLength(resp_array);
+  uint8_t* data = (uint8_t*)env->GetByteArrayElements(resp_array, NULL);
+  std::copy(data, data + num_bytes, std::back_inserter(out));
+  env->ReleaseByteArrayElements(resp_array, (jbyte*)data, JNI_ABORT);
+  env->DeleteLocalRef(java_array);
+  return out;
+}
+
+Result<std::vector<uint8_t>> JCardSimInterface::Transmit(const uint8_t* bytes,
+                                                         size_t len) const {
+  JNIEnv* env =
+      CF_EXPECT(GetOrAttachJNIEnvironment(jvm_), "Failed to get JNIEnv");
+  return InternalTransmit(env, bytes, len);
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/secure_env/jcardsim_interface.h b/host/commands/secure_env/jcardsim_interface.h
new file mode 100644
index 000000000..a799449ae
--- /dev/null
+++ b/host/commands/secure_env/jcardsim_interface.h
@@ -0,0 +1,62 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <iostream>
+#include <memory>
+#include <vector>
+
+#include "common/libs/utils/result.h"
+
+#include <jni.h>
+
+namespace cuttlefish {
+
+// This class helps to interact with JCardSimulator
+class JCardSimInterface {
+  // Private Constructor
+  JCardSimInterface(JavaVM* jvm);
+
+ public:
+  ~JCardSimInterface();
+
+  // This function Loads and initializes a Java VM. Installs and
+  // personalizes the required applets.
+  static Result<std::unique_ptr<JCardSimInterface>> Create();
+
+  // This function transmits the data to JCardSimulator and
+  // returns the response from simulator back to the caller.
+  Result<std::vector<uint8_t>> Transmit(const uint8_t* data, size_t len) const;
+
+ private:
+  Result<void> PersonalizeKeymintApplet(JNIEnv* env);
+  Result<void> ProvisionPresharedSecret(JNIEnv* env);
+  Result<std::vector<uint8_t>> OpenChannel(JNIEnv* env);
+  Result<std::vector<uint8_t>> SelectKeymintApplet(JNIEnv* env, uint8_t cla);
+  Result<std::vector<uint8_t>> CloseChannel(JNIEnv* env,
+                                            uint8_t channel_number);
+  Result<std::vector<uint8_t>> PreSharedKey();
+  Result<std::vector<uint8_t>> InternalTransmit(JNIEnv* env,
+                                                const uint8_t* data,
+                                                size_t len) const;
+
+  jobject jcardsim_proxy_inst_;
+  jclass jcardsim_proxy_class_;
+  JavaVM* jvm_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/commands/secure_env/jcardsim_responder.cpp b/host/commands/secure_env/jcardsim_responder.cpp
new file mode 100644
index 000000000..6adf730e9
--- /dev/null
+++ b/host/commands/secure_env/jcardsim_responder.cpp
@@ -0,0 +1,46 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "jcardsim_responder.h"
+
+#include <android-base/logging.h>
+#include <keymaster/android_keymaster_messages.h>
+
+namespace cuttlefish {
+constexpr const int kUnusedCommandField = 0;
+
+JcardSimResponder::JcardSimResponder(SharedFdChannel& channel,
+                                     const JCardSimInterface& jcs_interface)
+    : channel_(channel), jcs_interface_(jcs_interface) {}
+
+Result<ManagedMessage> JcardSimResponder::ToMessage(
+    const std::vector<uint8_t>& data) {
+  auto msg = CF_EXPECT(
+      transport::CreateMessage(kUnusedCommandField, true, data.size()));
+  std::copy(data.begin(), data.end(), msg->payload);
+  return msg;
+}
+
+Result<void> JcardSimResponder::ProcessMessage() {
+  auto request =
+      CF_EXPECT(channel_.ReceiveMessage(), "Could not receive message");
+  auto resp = CF_EXPECT(
+      jcs_interface_.Transmit(request->payload, request->payload_size));
+  auto msg = CF_EXPECT(ToMessage(resp), "Failed to convert to Message");
+  return channel_.SendResponse(*msg);
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/secure_env/jcardsim_responder.h b/host/commands/secure_env/jcardsim_responder.h
new file mode 100644
index 000000000..e22819c74
--- /dev/null
+++ b/host/commands/secure_env/jcardsim_responder.h
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "common/libs/transport/channel_sharedfd.h"
+#include "jcardsim_interface.h"
+
+namespace cuttlefish {
+using cuttlefish::transport::ManagedMessage;
+using cuttlefish::transport::SharedFdChannel;
+
+class JcardSimResponder {
+ public:
+  JcardSimResponder(SharedFdChannel& channel,
+                    const JCardSimInterface& jcs_interface);
+
+  Result<void> ProcessMessage();
+
+ private:
+  Result<ManagedMessage> ToMessage(const std::vector<uint8_t>& data);
+  SharedFdChannel& channel_;
+  const JCardSimInterface& jcs_interface_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/commands/secure_env/secure_env_not_windows_main.cpp b/host/commands/secure_env/secure_env_not_windows_main.cpp
index 6c4272cc5..122beb006 100644
--- a/host/commands/secure_env/secure_env_not_windows_main.cpp
+++ b/host/commands/secure_env/secure_env_not_windows_main.cpp
@@ -39,6 +39,8 @@
 #include "host/commands/secure_env/device_tpm.h"
 #include "host/commands/secure_env/gatekeeper_responder.h"
 #include "host/commands/secure_env/in_process_tpm.h"
+#include "host/commands/secure_env/jcardsim_interface.h"
+#include "host/commands/secure_env/jcardsim_responder.h"
 #include "host/commands/secure_env/keymaster_responder.h"
 #include "host/commands/secure_env/oemlock/oemlock.h"
 #include "host/commands/secure_env/oemlock/oemlock_responder.h"
@@ -87,6 +89,10 @@ DEFINE_string(gatekeeper_impl, "tpm",
 DEFINE_string(oemlock_impl, "tpm",
               "The oemlock implementation. \"tpm\" or \"software\"");
 
+DEFINE_int32(jcardsim_fd_in, -1, "A pipe for jcardsim communication");
+DEFINE_int32(jcardsim_fd_out, -1, "A pipe for jcardsim communication");
+DEFINE_bool(enable_jcard_simulator, false, "Whether to enable jcardsimulator.");
+
 namespace cuttlefish {
 namespace {
 
@@ -265,6 +271,12 @@ Result<void> SecureEnvMain(int argc, char** argv) {
   oemlock::OemLock* oemlock = injector.get<oemlock::OemLock*>();
   keymaster::KeymasterEnforcement* keymaster_enforcement =
       injector.get<keymaster::KeymasterEnforcement*>();
+  std::unique_ptr<JCardSimInterface> jcs_interface = nullptr;
+  bool enable_jcard_simulator = FLAGS_enable_jcard_simulator;
+  if (enable_jcard_simulator) {
+    jcs_interface = CF_EXPECT(JCardSimInterface::Create(),
+                              "Failed to initialize JCardSimulator");
+  }
   std::unique_ptr<keymaster::KeymasterContext> keymaster_context;
   std::unique_ptr<keymaster::AndroidKeymaster> keymaster;
   std::timed_mutex oemlock_lock;
@@ -288,6 +300,15 @@ Result<void> SecureEnvMain(int argc, char** argv) {
       CF_EXPECT(SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0));
   auto [oemlock_snapshot_socket1, oemlock_snapshot_socket2] =
       CF_EXPECT(SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0));
+  // jcardsim snapshot
+  std::optional<SharedFD> jcardsim_snapshot_socket1 = std::nullopt;
+  std::optional<SharedFD> jcardsim_snapshot_socket2 = std::nullopt;
+  if (enable_jcard_simulator) {
+    std::pair<SharedFD, SharedFD> jcardsim_snapshots =
+        CF_EXPECT(SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0));
+    jcardsim_snapshot_socket1 = jcardsim_snapshots.first;
+    jcardsim_snapshot_socket2 = jcardsim_snapshots.second;
+  }
   SharedFD channel_to_run_cvd = DupFdFlag(FLAGS_snapshot_control_fd);
 
   SnapshotCommandHandler suspend_resume_handler(
@@ -297,6 +318,7 @@ Result<void> SecureEnvMain(int argc, char** argv) {
           .keymaster = std::move(keymaster_snapshot_socket1),
           .gatekeeper = std::move(gatekeeper_snapshot_socket1),
           .oemlock = std::move(oemlock_snapshot_socket1),
+          .jcardsim = std::move(jcardsim_snapshot_socket1),
       });
 
   // The guest image may have either the C++ implementation of
@@ -413,6 +435,32 @@ Result<void> SecureEnvMain(int argc, char** argv) {
           }
         }
       });
+  if (enable_jcard_simulator) {
+    auto jcardsim_in = DupFdFlag(FLAGS_jcardsim_fd_in);
+    auto jcardsim_out = DupFdFlag(FLAGS_jcardsim_fd_out);
+    threads.emplace_back([jcardsim_in, jcardsim_out,
+                          jcs_interface = std::move(jcs_interface),
+                          jcardsim_snapshot_socket2 =
+                              std::move(jcardsim_snapshot_socket2.value())]() {
+      while (true) {
+        SharedFdChannel jcardsim_channel(jcardsim_in, jcardsim_out);
+
+        JcardSimResponder jcardsim_responder(jcardsim_channel,
+                                             *jcs_interface.get());
+
+        std::function<bool()> jcardsim_process_cb = [&jcardsim_responder]() {
+          return (jcardsim_responder.ProcessMessage().ok());
+        };
+
+        // infinite loop that returns if resetting responder is needed
+        auto result = secure_env_impl::WorkerInnerLoop(
+            jcardsim_process_cb, jcardsim_in, jcardsim_snapshot_socket2);
+        if (!result.ok()) {
+          LOG(FATAL) << "jcardsim worker failed: " << result.error().Trace();
+        }
+      }
+    });
+  }
 
   auto confui_server_fd = DupFdFlag(FLAGS_confui_server_fd);
   threads.emplace_back([confui_server_fd, resource_manager]() {
diff --git a/host/commands/secure_env/suspend_resume_handler.cpp b/host/commands/secure_env/suspend_resume_handler.cpp
index b7b09c061..b86087ed6 100644
--- a/host/commands/secure_env/suspend_resume_handler.cpp
+++ b/host/commands/secure_env/suspend_resume_handler.cpp
@@ -91,11 +91,17 @@ Result<void> SnapshotCommandHandler::SuspendResumeHandler() {
       CF_EXPECT(WriteSuspendRequest(snapshot_sockets_.keymaster));
       CF_EXPECT(WriteSuspendRequest(snapshot_sockets_.gatekeeper));
       CF_EXPECT(WriteSuspendRequest(snapshot_sockets_.oemlock));
+      if (snapshot_sockets_.jcardsim.has_value()) {
+        CF_EXPECT(WriteSuspendRequest(snapshot_sockets_.jcardsim.value()));
+      }
       // Wait for ACKs from worker threads.
       CF_EXPECT(ReadSuspendAck(snapshot_sockets_.rust));
       CF_EXPECT(ReadSuspendAck(snapshot_sockets_.keymaster));
       CF_EXPECT(ReadSuspendAck(snapshot_sockets_.gatekeeper));
       CF_EXPECT(ReadSuspendAck(snapshot_sockets_.oemlock));
+      if (snapshot_sockets_.jcardsim.has_value()) {
+        CF_EXPECT(ReadSuspendAck(snapshot_sockets_.jcardsim.value()));
+      }
       // Write response to run_cvd.
       auto response = LauncherResponse::kSuccess;
       const auto n_written =
@@ -110,6 +116,9 @@ Result<void> SnapshotCommandHandler::SuspendResumeHandler() {
       CF_EXPECT(WriteResumeRequest(snapshot_sockets_.keymaster));
       CF_EXPECT(WriteResumeRequest(snapshot_sockets_.gatekeeper));
       CF_EXPECT(WriteResumeRequest(snapshot_sockets_.oemlock));
+      if (snapshot_sockets_.jcardsim.has_value()) {
+        CF_EXPECT(WriteResumeRequest(snapshot_sockets_.jcardsim.value()));
+      }
       // Write response to run_cvd.
       auto response = LauncherResponse::kSuccess;
       const auto n_written =
diff --git a/host/commands/secure_env/suspend_resume_handler.h b/host/commands/secure_env/suspend_resume_handler.h
index cd542d7b8..6e0bdcf27 100644
--- a/host/commands/secure_env/suspend_resume_handler.h
+++ b/host/commands/secure_env/suspend_resume_handler.h
@@ -59,6 +59,9 @@ class SnapshotCommandHandler {
     SharedFD keymaster;
     SharedFD gatekeeper;
     SharedFD oemlock;
+    // The jcardsim is optional. It is only required if
+    // FLAGS_enable_jcard_simulator is enabled.
+    std::optional<SharedFD> jcardsim;
   };
 
   ~SnapshotCommandHandler();
diff --git a/host/commands/sensors_simulator/Android.bp b/host/commands/sensors_simulator/Android.bp
index 17221f379..6f5cd0294 100644
--- a/host/commands/sensors_simulator/Android.bp
+++ b/host/commands/sensors_simulator/Android.bp
@@ -21,6 +21,7 @@ cc_binary_host {
     name: "sensors_simulator",
     srcs: [
         "main.cpp",
+        "sensors_hal_proxy.cpp",
         "sensors_simulator.cpp",
     ],
     header_libs: [
@@ -29,6 +30,7 @@ cc_binary_host {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libcuttlefish_kernel_log_monitor_utils",
         "libcuttlefish_transport",
         "libcuttlefish_utils",
         "libjsoncpp",
diff --git a/host/commands/sensors_simulator/main.cpp b/host/commands/sensors_simulator/main.cpp
index b2a9ce29a..34afb6a23 100644
--- a/host/commands/sensors_simulator/main.cpp
+++ b/host/commands/sensors_simulator/main.cpp
@@ -21,12 +21,18 @@
 #include <gflags/gflags.h>
 
 #include "common/libs/transport/channel_sharedfd.h"
+#include "host/commands/sensors_simulator/sensors_hal_proxy.h"
 #include "host/commands/sensors_simulator/sensors_simulator.h"
 #include "host/libs/config/logging.h"
 
 DEFINE_int32(sensors_in_fd, -1, "Sensors virtio-console from host to guest");
 DEFINE_int32(sensors_out_fd, -1, "Sensors virtio-console from guest to host");
 DEFINE_int32(webrtc_fd, -1, "A file descriptor to communicate with webrtc");
+DEFINE_int32(kernel_events_fd, -1,
+             "A pipe for monitoring events based on messages "
+             "written to the kernel log. This is used by "
+             "SensorsHalProxy to monitor for device reboots.");
+DEFINE_int32(device_type, 0, "The form factor of the Cuttlefish instance.");
 
 namespace cuttlefish {
 namespace sensors {
@@ -34,6 +40,7 @@ namespace sensors {
 namespace {
 
 static constexpr char kReqMisFormatted[] = "The request is mis-formatted.";
+static constexpr char kFdNotOpen[] = "Unable to connect: ";
 
 Result<void> ProcessWebrtcRequest(transport::SharedFdChannel& channel,
                                   SensorsSimulator& sensors_simulator) {
@@ -79,13 +86,31 @@ Result<void> ProcessWebrtcRequest(transport::SharedFdChannel& channel,
 int SensorsSimulatorMain(int argc, char** argv) {
   DefaultSubprocessLogging(argv);
   gflags::ParseCommandLineFlags(&argc, &argv, true);
-  auto webrtc_fd = SharedFD::Dup(FLAGS_webrtc_fd);
+  SharedFD webrtc_fd = SharedFD::Dup(FLAGS_webrtc_fd);
   close(FLAGS_webrtc_fd);
   if (!webrtc_fd->IsOpen()) {
-    LOG(FATAL) << "Unable to connect webrtc: " << webrtc_fd->StrError();
+    LOG(FATAL) << kFdNotOpen << webrtc_fd->StrError();
   }
+  SharedFD sensors_in_fd = SharedFD::Dup(FLAGS_sensors_in_fd);
+  close(FLAGS_sensors_in_fd);
+  if (!sensors_in_fd->IsOpen()) {
+    LOG(FATAL) << kFdNotOpen << sensors_in_fd->StrError();
+  }
+  SharedFD sensors_out_fd = SharedFD::Dup(FLAGS_sensors_out_fd);
+  close(FLAGS_sensors_out_fd);
+  if (!sensors_out_fd->IsOpen()) {
+    LOG(FATAL) << kFdNotOpen << sensors_out_fd->StrError();
+  }
+  SharedFD kernel_events_fd = SharedFD::Dup(FLAGS_kernel_events_fd);
+  close(FLAGS_kernel_events_fd);
+
   transport::SharedFdChannel channel(webrtc_fd, webrtc_fd);
-  SensorsSimulator sensors_simulator;
+
+  auto device_type = static_cast<DeviceType>(FLAGS_device_type);
+  SensorsSimulator sensors_simulator(device_type == DeviceType::Auto);
+  SensorsHalProxy sensors_hal_proxy(sensors_in_fd, sensors_out_fd,
+                                    kernel_events_fd, sensors_simulator,
+                                    device_type);
   while (true) {
     auto result = ProcessWebrtcRequest(channel, sensors_simulator);
     if (!result.ok()) {
diff --git a/host/commands/sensors_simulator/sensors_hal_proxy.cpp b/host/commands/sensors_simulator/sensors_hal_proxy.cpp
new file mode 100644
index 000000000..2b590e690
--- /dev/null
+++ b/host/commands/sensors_simulator/sensors_hal_proxy.cpp
@@ -0,0 +1,180 @@
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
+#include "host/commands/sensors_simulator/sensors_hal_proxy.h"
+
+#include <android-base/logging.h>
+
+namespace cuttlefish {
+namespace sensors {
+
+namespace {
+static constexpr char END_OF_MSG = '\n';
+static constexpr uint32_t kIntervalMs = 1000;
+
+Result<std::string> SensorIdToName(int id) {
+  switch (id) {
+    case kAccelerationId:
+      return "acceleration";
+    case kGyroscopeId:
+      return "gyroscope";
+    case kMagneticId:
+      return "magnetic";
+    case kTemperatureId:
+      return "temperature";
+    case kProximityId:
+      return "proximity";
+    case kLightId:
+      return "light";
+    case kPressureId:
+      return "pressure";
+    case kHumidityId:
+      return "humidity";
+    case kUncalibMagneticId:
+      return "magnetic-uncalibrated";
+    case kUncalibGyroscopeId:
+      return "gyroscope-uncalibrated";
+    case kHingeAngle0Id:
+      return "hinge-angle0";
+    case kUncalibAccelerationId:
+      return "acceleration-uncalibrated";
+    case kRotationVecId:
+      return "rotation";
+    default:
+      return CF_ERR("Unsupported sensor id: " << id);
+  }
+}
+
+Result<void> SendResponseHelper(transport::SharedFdChannel& channel,
+                                const std::string& msg) {
+  auto size = msg.size();
+  auto cmd = sensors::kUpdateHal;
+  auto response = CF_EXPECT(transport::CreateMessage(cmd, msg.size()),
+                            "Failed to allocate message.");
+  std::memcpy(response->payload, msg.data(), size);
+  CF_EXPECT(channel.SendResponse(*response), "Can't update sensor HAL.");
+  return {};
+}
+
+Result<void> ProcessHalRequest(transport::SharedFdChannel& channel,
+                               std::atomic<bool>& hal_activated,
+                               uint32_t mask) {
+  auto request =
+      CF_EXPECT(channel.ReceiveMessage(), "Couldn't receive message.");
+  std::string payload(reinterpret_cast<const char*>(request->payload),
+                      request->payload_size);
+  if (payload.starts_with("list-sensors")) {
+    auto msg = std::to_string(mask) + END_OF_MSG;
+    CF_EXPECT(SendResponseHelper(channel, msg));
+    hal_activated = true;
+  }
+  return {};
+}
+
+Result<void> UpdateSensorsHal(const std::string& sensors_data,
+                              transport::SharedFdChannel& channel,
+                              uint32_t mask) {
+  std::vector<std::string> reports;
+  std::string report;
+  std::stringstream sensors_data_stream(sensors_data);
+  int id = 0;
+
+  while (mask) {
+    if (mask & 1) {
+      CF_EXPECT(static_cast<bool>(sensors_data_stream >> report));
+      auto result = SensorIdToName(id);
+      if (result.ok()) {
+        reports.push_back(result.value() + INNER_DELIM + report + END_OF_MSG);
+      }
+    }
+    id += 1;
+    mask >>= 1;
+  }
+  for (const auto& r : reports) {
+    CF_EXPECT(SendResponseHelper(channel, r));
+  }
+  return {};
+}
+
+}  // namespace
+
+SensorsHalProxy::SensorsHalProxy(SharedFD sensors_in_fd,
+                                 SharedFD sensors_out_fd,
+                                 SharedFD kernel_events_fd,
+                                 SensorsSimulator& sensors_simulator,
+                                 DeviceType device_type)
+    : channel_(std::move(sensors_in_fd), std::move(sensors_out_fd)),
+      kernel_events_fd_(std::move(kernel_events_fd)),
+      sensors_simulator_(sensors_simulator) {
+  SensorsMask host_enabled_sensors;
+  switch (device_type) {
+    case DeviceType::Foldable:
+      host_enabled_sensors =
+          (1 << kAccelerationId) | (1 << kGyroscopeId) | (1 << kMagneticId) |
+          (1 << kTemperatureId) | (1 << kProximityId) | (1 << kLightId) |
+          (1 << kPressureId) | (1 << kHumidityId) | (1 << kHingeAngle0Id);
+      break;
+    case DeviceType::Auto:
+      host_enabled_sensors = (1 << kAccelerationId) | (1 << kGyroscopeId) |
+                             (1 << kUncalibGyroscopeId) |
+                             (1 << kUncalibAccelerationId);
+      break;
+    default:
+      host_enabled_sensors = (1 << kAccelerationId) | (1 << kGyroscopeId) |
+                             (1 << kMagneticId) | (1 << kTemperatureId) |
+                             (1 << kProximityId) | (1 << kLightId) |
+                             (1 << kPressureId) | (1 << kHumidityId);
+  }
+
+  req_responder_thread_ = std::thread([this, host_enabled_sensors] {
+    while (running_) {
+      auto result =
+          ProcessHalRequest(channel_, hal_activated_, host_enabled_sensors);
+      if (!result.ok()) {
+        running_ = false;
+        LOG(ERROR) << result.error().FormatForEnv();
+      }
+    }
+  });
+  data_reporter_thread_ = std::thread([this, host_enabled_sensors] {
+    while (running_) {
+      if (hal_activated_) {
+        auto sensors_data =
+            sensors_simulator_.GetSensorsData(host_enabled_sensors);
+        auto result =
+            UpdateSensorsHal(sensors_data, channel_, host_enabled_sensors);
+        if (!result.ok()) {
+          running_ = false;
+          LOG(ERROR) << result.error().FormatForEnv();
+        }
+      }
+      std::this_thread::sleep_for(std::chrono::milliseconds(kIntervalMs));
+    }
+  });
+  reboot_monitor_thread_ = std::thread([this] {
+    while (kernel_events_fd_->IsOpen()) {
+      auto read_result = monitor::ReadEvent(kernel_events_fd_);
+      CHECK(read_result.ok()) << read_result.error().FormatForEnv();
+      CHECK(read_result->has_value()) << "EOF in kernel log monitor";
+      if ((*read_result)->event == monitor::Event::BootloaderLoaded) {
+        hal_activated_ = false;
+      }
+    }
+  });
+}
+
+}  // namespace sensors
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/sensors_simulator/sensors_hal_proxy.h b/host/commands/sensors_simulator/sensors_hal_proxy.h
new file mode 100644
index 000000000..c4a502430
--- /dev/null
+++ b/host/commands/sensors_simulator/sensors_hal_proxy.h
@@ -0,0 +1,50 @@
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
+#include <atomic>
+#include <thread>
+
+#include "common/libs/sensors/sensors.h"
+#include "common/libs/transport/channel_sharedfd.h"
+#include "common/libs/utils/device_type.h"
+#include "host/commands/kernel_log_monitor/kernel_log_server.h"
+#include "host/commands/kernel_log_monitor/utils.h"
+#include "host/commands/sensors_simulator/sensors_simulator.h"
+
+namespace cuttlefish {
+namespace sensors {
+
+class SensorsHalProxy {
+ public:
+  SensorsHalProxy(SharedFD sensors_in_fd, SharedFD sensors_out_fd,
+                  SharedFD kernel_events_fd,
+                  SensorsSimulator& sensors_simulator, DeviceType device_type);
+
+ private:
+  std::thread req_responder_thread_;
+  std::thread data_reporter_thread_;
+  std::thread reboot_monitor_thread_;
+  transport::SharedFdChannel channel_;
+  SharedFD kernel_events_fd_;
+  SensorsSimulator& sensors_simulator_;
+  std::atomic<bool> hal_activated_ = false;
+  std::atomic<bool> running_ = true;
+};
+
+}  // namespace sensors
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/sensors_simulator/sensors_simulator.cpp b/host/commands/sensors_simulator/sensors_simulator.cpp
index f8d5b6dab..ed920b565 100644
--- a/host/commands/sensors_simulator/sensors_simulator.cpp
+++ b/host/commands/sensors_simulator/sensors_simulator.cpp
@@ -24,12 +24,22 @@ namespace cuttlefish {
 namespace sensors {
 
 namespace {
-
+constexpr float kTemperature = 25.0f;   // celsius
+constexpr float kProximity = 1.0f;      // cm
+constexpr float kLight = 1000.0f;       // lux
+constexpr float kPressure = 1013.25f;   // hpa
+constexpr float kHumidity = 40.0f;      // percent
+constexpr float kHingeAngle0 = 180.0f;  // degree
 constexpr double kG = 9.80665;  // meter per second^2
-const Eigen::Vector3d kGravityVec{0, kG, 0}, kMagneticField{0, 5.9, -48.4};
-
+const Eigen::Vector3d kMagneticField{0, 5.9, -48.4};
 inline double ToRadians(double x) { return x * M_PI / 180; }
 
+// Check if a given sensor id provides scalar data
+static bool IsScalarSensor(int id) {
+  return (id == kTemperatureId) || (id == kProximityId) || (id == kLightId) ||
+         (id == kPressureId) || (id == kHumidityId) || (id == kHingeAngle0Id);
+}
+
 // Calculate the rotation matrix of the pitch, roll, and yaw angles.
 static Eigen::Matrix3d GetRotationMatrix(double x, double y, double z) {
   x = ToRadians(-x);
@@ -48,8 +58,12 @@ static Eigen::Matrix3d GetRotationMatrix(double x, double y, double z) {
 
 // Calculate new Accelerometer values of the new rotation degrees.
 static inline Eigen::Vector3d CalculateAcceleration(
-    Eigen::Matrix3d current_rotation_matrix) {
-  return current_rotation_matrix * kGravityVec;
+    Eigen::Matrix3d current_rotation_matrix, bool is_auto) {
+  // For automotive devices, the Z-axis of the reference frame is aligned to
+  // gravity. See
+  // https://source.android.com/docs/core/interaction/sensors/sensor-types#auto_axes
+  return current_rotation_matrix *
+         (is_auto ? Eigen::Vector3d(0, 0, kG) : Eigen::Vector3d(0, kG, 0));
 }
 
 // Calculate new Magnetometer values of the new rotation degrees.
@@ -79,16 +93,24 @@ static Eigen::Vector3d CalculateGyroscope(
 }
 }  // namespace
 
-SensorsSimulator::SensorsSimulator()
+SensorsSimulator::SensorsSimulator(bool is_auto)
     : current_rotation_matrix_(GetRotationMatrix(0, 0, 0)),
-      last_event_timestamp_(std::chrono::high_resolution_clock::now()) {
+      last_event_timestamp_(std::chrono::high_resolution_clock::now()),
+      is_auto_(is_auto) {
   // Initialize sensors_data_ based on rotation vector = (0, 0, 0)
   RefreshSensors(0, 0, 0);
+  // Set constant values for the sensors that are independent of rotation vector
+  sensors_data_[kTemperatureId].f = kTemperature;
+  sensors_data_[kProximityId].f = kProximity;
+  sensors_data_[kLightId].f = kLight;
+  sensors_data_[kPressureId].f = kPressure;
+  sensors_data_[kHumidityId].f = kHumidity;
+  sensors_data_[kHingeAngle0Id].f = kHingeAngle0;
 }
 
 void SensorsSimulator::RefreshSensors(double x, double y, double z) {
   auto rotation_matrix_update = GetRotationMatrix(x, y, z);
-  auto acc_update = CalculateAcceleration(rotation_matrix_update);
+  auto acc_update = CalculateAcceleration(rotation_matrix_update, is_auto_);
   auto mgn_update = CalculateMagnetometer(rotation_matrix_update);
 
   std::lock_guard<std::mutex> lock(sensors_data_mtx_);
@@ -101,15 +123,15 @@ void SensorsSimulator::RefreshSensors(double x, double y, double z) {
 
   current_rotation_matrix_ = rotation_matrix_update;
 
-  sensors_data_[kRotationVecId] << x, y, z;
-  sensors_data_[kAccelerationId] = acc_update;
-  sensors_data_[kGyroscopeId] = gyro_update;
-  sensors_data_[kMagneticId] = mgn_update;
+  sensors_data_[kRotationVecId].v << x, y, z;
+  sensors_data_[kAccelerationId].v = acc_update;
+  sensors_data_[kGyroscopeId].v = gyro_update;
+  sensors_data_[kMagneticId].v = mgn_update;
 
   // Copy the calibrated sensor data over for uncalibrated sensor support
-  sensors_data_[kUncalibAccelerationId] = acc_update;
-  sensors_data_[kUncalibGyroscopeId] = gyro_update;
-  sensors_data_[kUncalibMagneticId] = mgn_update;
+  sensors_data_[kUncalibAccelerationId].v = acc_update;
+  sensors_data_[kUncalibGyroscopeId].v = gyro_update;
+  sensors_data_[kUncalibMagneticId].v = mgn_update;
 }
 
 std::string SensorsSimulator::GetSensorsData(const SensorsMask mask) {
@@ -117,9 +139,14 @@ std::string SensorsSimulator::GetSensorsData(const SensorsMask mask) {
   std::lock_guard<std::mutex> lock(sensors_data_mtx_);
   for (int id = 0; id <= kMaxSensorId; id++) {
     if (mask & (1 << id)) {
-      auto v = sensors_data_[id];
-      sensors_msg << v(0) << INNER_DELIM << v(1) << INNER_DELIM << v(2)
-                  << OUTER_DELIM;
+      if (IsScalarSensor(id)) {
+        float f = sensors_data_[id].f;
+        sensors_msg << f << OUTER_DELIM;
+      } else {
+        Eigen::Vector3d v = sensors_data_[id].v;
+        sensors_msg << v(0) << INNER_DELIM << v(1) << INNER_DELIM << v(2)
+                    << OUTER_DELIM;
+      }
     }
   }
   return sensors_msg.str();
diff --git a/host/commands/sensors_simulator/sensors_simulator.h b/host/commands/sensors_simulator/sensors_simulator.h
index ff658e765..0a926e034 100644
--- a/host/commands/sensors_simulator/sensors_simulator.h
+++ b/host/commands/sensors_simulator/sensors_simulator.h
@@ -26,9 +26,16 @@
 namespace cuttlefish {
 namespace sensors {
 
+struct SensorsData {
+  Eigen::Vector3d v;
+  float f;
+
+  SensorsData() : v(Eigen::Vector3d::Zero()), f(0.0f) {}
+};
+
 class SensorsSimulator {
  public:
-  SensorsSimulator();
+  SensorsSimulator(bool is_auto);
   // Update sensor values based on new rotation status.
   void RefreshSensors(double x, double y, double z);
 
@@ -42,10 +49,11 @@ class SensorsSimulator {
 
  private:
   std::mutex sensors_data_mtx_;
-  Eigen::Vector3d sensors_data_[kMaxSensorId + 1];
+  SensorsData sensors_data_[kMaxSensorId + 1];
   Eigen::Matrix3d prior_rotation_matrix_, current_rotation_matrix_;
   std::chrono::time_point<std::chrono::high_resolution_clock>
       last_event_timestamp_;
+  bool is_auto_;
 };
 
 }  // namespace sensors
diff --git a/host/commands/vhal_proxy_server/README.md b/host/commands/vhal_proxy_server/README.md
new file mode 100644
index 000000000..f0d934b08
--- /dev/null
+++ b/host/commands/vhal_proxy_server/README.md
@@ -0,0 +1,4 @@
+# VHAL proxy server
+
+This is the host-side VHAL proxy server for cf_auto VHAL. For detail, see
+device/google/cuttlefish/guest/hals/vehicle/README.md.
\ No newline at end of file
diff --git a/host/frontend/webrtc/Android.bp b/host/frontend/webrtc/Android.bp
index 6c411284b..fbce0c3ba 100644
--- a/host/frontend/webrtc/Android.bp
+++ b/host/frontend/webrtc/Android.bp
@@ -105,7 +105,7 @@ cc_binary_host {
         "webrtc_signaling_headers",
     ],
     static_libs: [
-        "libabsl_host",
+        "absl_container_inlined_vector",
         "libaom",
         "libcap",
         "libcn-cbor",
diff --git a/host/frontend/webrtc/cvd_video_frame_buffer.cpp b/host/frontend/webrtc/cvd_video_frame_buffer.cpp
index 8d0aeea3e..7bfef72b4 100644
--- a/host/frontend/webrtc/cvd_video_frame_buffer.cpp
+++ b/host/frontend/webrtc/cvd_video_frame_buffer.cpp
@@ -79,8 +79,4 @@ int CvdVideoFrameBuffer::StrideV() const {
   return AlignStride((width_ + 1) / 2);
 }
 
-const uint8_t *CvdVideoFrameBuffer::DataY() const { return y_.data(); }
-const uint8_t *CvdVideoFrameBuffer::DataU() const { return u_.data(); }
-const uint8_t *CvdVideoFrameBuffer::DataV() const { return v_.data(); }
-
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/cvd_video_frame_buffer.h b/host/frontend/webrtc/cvd_video_frame_buffer.h
index 7247928a6..b1b96040e 100644
--- a/host/frontend/webrtc/cvd_video_frame_buffer.h
+++ b/host/frontend/webrtc/cvd_video_frame_buffer.h
@@ -18,11 +18,11 @@
 
 #include <vector>
 
-#include "host/frontend/webrtc/libdevice/video_frame_buffer.h"
+#include "host/libs/screen_connector/video_frame_buffer.h"
 
 namespace cuttlefish {
 
-class CvdVideoFrameBuffer : public webrtc_streaming::VideoFrameBuffer {
+class CvdVideoFrameBuffer : public VideoFrameBuffer {
  public:
   CvdVideoFrameBuffer(int width, int height);
   CvdVideoFrameBuffer(CvdVideoFrameBuffer&& cvd_frame_buf) = default;
@@ -41,13 +41,9 @@ class CvdVideoFrameBuffer : public webrtc_streaming::VideoFrameBuffer {
   int StrideU() const override;
   int StrideV() const override;
 
-  const uint8_t *DataY() const override;
-  const uint8_t *DataU() const override;
-  const uint8_t *DataV() const override;
-
-  uint8_t *DataY() { return y_.data(); }
-  uint8_t *DataU() { return u_.data(); }
-  uint8_t *DataV() { return v_.data(); }
+  uint8_t *DataY() override { return y_.data(); }
+  uint8_t *DataU() override { return u_.data(); }
+  uint8_t *DataV() override { return v_.data(); }
 
   std::size_t DataSizeY() const override { return y_.size(); }
   std::size_t DataSizeU() const override { return u_.size(); }
diff --git a/host/frontend/webrtc/display_handler.cpp b/host/frontend/webrtc/display_handler.cpp
index ac010023a..2c3e884cf 100644
--- a/host/frontend/webrtc/display_handler.cpp
+++ b/host/frontend/webrtc/display_handler.cpp
@@ -142,9 +142,7 @@ DisplayHandler::GetScreenConnectorCallback() {
       display_last_buffers_[display_number] =
           std::make_shared<BufferInfo>(BufferInfo{
               .last_sent_time_stamp = std::chrono::system_clock::now(),
-              .buffer =
-                  std::static_pointer_cast<webrtc_streaming::VideoFrameBuffer>(
-                      buffer),
+              .buffer = std::static_pointer_cast<VideoFrameBuffer>(buffer),
           });
     }
     if (processed_frame.is_success_) {
@@ -262,6 +260,7 @@ void DisplayHandler::RepeatFramesPeriodically() {
     SendBuffers(buffers);
     {
       std::lock_guard last_buffers_lock(last_buffers_mutex_);
+      next_send = std::chrono::system_clock::now() + kRepeatingInterval;
       for (const auto& [_, buffer_info] : display_last_buffers_) {
         next_send = std::min(
             next_send, buffer_info->last_sent_time_stamp + kRepeatingInterval);
diff --git a/host/frontend/webrtc/display_handler.h b/host/frontend/webrtc/display_handler.h
index c3627d902..ab4357a76 100644
--- a/host/frontend/webrtc/display_handler.h
+++ b/host/frontend/webrtc/display_handler.h
@@ -78,7 +78,7 @@ class DisplayHandler {
  private:
   struct BufferInfo {
     std::chrono::system_clock::time_point last_sent_time_stamp;
-    std::shared_ptr<webrtc_streaming::VideoFrameBuffer> buffer;
+    std::shared_ptr<VideoFrameBuffer> buffer;
   };
   enum class RepeaterState {
     RUNNING,
diff --git a/host/frontend/webrtc/libcommon/Android.bp b/host/frontend/webrtc/libcommon/Android.bp
index 0e2974a79..9fb4b0a2d 100644
--- a/host/frontend/webrtc/libcommon/Android.bp
+++ b/host/frontend/webrtc/libcommon/Android.bp
@@ -35,7 +35,13 @@ cc_library {
         "-Wno-unused-parameter",
     ],
     static_libs: [
-        "libabsl_host",
+        "absl_algorithm_container",
+        "absl_container_inlined_vector",
+        "absl_functional_any_invocable",
+        "absl_strings",
+        "absl_strings_string_view",
+        "absl_types_optional",
+        "absl_types_variant",
         "libevent",
         "libopus",
         "libsrtp2",
diff --git a/host/frontend/webrtc/libdevice/Android.bp b/host/frontend/webrtc/libdevice/Android.bp
index e0420ceeb..71f06b160 100644
--- a/host/frontend/webrtc/libdevice/Android.bp
+++ b/host/frontend/webrtc/libdevice/Android.bp
@@ -43,7 +43,7 @@ cc_library {
         "webrtc_signaling_headers",
     ],
     static_libs: [
-        "libabsl_host",
+        "absl_container_inlined_vector",
         "libcap",
         "libcuttlefish_host_config",
         "libcuttlefish_screen_connector",
diff --git a/host/frontend/webrtc/libdevice/video_sink.h b/host/frontend/webrtc/libdevice/video_sink.h
index 14eee41db..7a083cc79 100644
--- a/host/frontend/webrtc/libdevice/video_sink.h
+++ b/host/frontend/webrtc/libdevice/video_sink.h
@@ -18,7 +18,7 @@
 
 #include <memory>
 
-#include "host/frontend/webrtc/libdevice/video_frame_buffer.h"
+#include "host/libs/screen_connector/video_frame_buffer.h"
 
 namespace cuttlefish {
 namespace webrtc_streaming {
diff --git a/host/frontend/webrtc/libdevice/video_track_source_impl.cpp b/host/frontend/webrtc/libdevice/video_track_source_impl.cpp
index 8770f6729..b748220b6 100644
--- a/host/frontend/webrtc/libdevice/video_track_source_impl.cpp
+++ b/host/frontend/webrtc/libdevice/video_track_source_impl.cpp
@@ -26,7 +26,7 @@ namespace {
 class VideoFrameWrapper : public webrtc::I420BufferInterface {
  public:
   VideoFrameWrapper(
-      std::shared_ptr<::cuttlefish::webrtc_streaming::VideoFrameBuffer>
+      std::shared_ptr<::cuttlefish::VideoFrameBuffer>
           frame_buffer)
       : frame_buffer_(frame_buffer) {}
   ~VideoFrameWrapper() override = default;
@@ -45,8 +45,7 @@ class VideoFrameWrapper : public webrtc::I420BufferInterface {
   const uint8_t *DataV() const override { return frame_buffer_->DataV(); }
 
  private:
-  std::shared_ptr<::cuttlefish::webrtc_streaming::VideoFrameBuffer>
-      frame_buffer_;
+  std::shared_ptr<::cuttlefish::VideoFrameBuffer> frame_buffer_;
 };
 
 }  // namespace
diff --git a/host/frontend/webrtc/screenshot_handler.cpp b/host/frontend/webrtc/screenshot_handler.cpp
index 0405266ab..66998fda5 100644
--- a/host/frontend/webrtc/screenshot_handler.cpp
+++ b/host/frontend/webrtc/screenshot_handler.cpp
@@ -16,9 +16,6 @@
 
 #include "host/frontend/webrtc/screenshot_handler.h"
 
-#include <filesystem>
-#include <fstream>
-
 #include <SkData.h>
 #include <SkImage.h>
 #include <SkJpegEncoder.h>
@@ -31,8 +28,7 @@
 namespace cuttlefish {
 namespace {
 
-Result<sk_sp<SkImage>> GetSkImage(
-    const webrtc_streaming::VideoFrameBuffer& frame) {
+Result<sk_sp<SkImage>> GetSkImage(VideoFrameBuffer& frame) {
   const int w = frame.width();
   const int h = frame.height();
 
diff --git a/host/frontend/webrtc/screenshot_handler.h b/host/frontend/webrtc/screenshot_handler.h
index b84b7b787..584f42f3b 100644
--- a/host/frontend/webrtc/screenshot_handler.h
+++ b/host/frontend/webrtc/screenshot_handler.h
@@ -18,12 +18,11 @@
 
 #include <future>
 #include <mutex>
-#include <unordered_set>
 
 #include <fmt/format.h>
 
 #include "common/libs/utils/result.h"
-#include "host/frontend/webrtc/libdevice/video_frame_buffer.h"
+#include "host/libs/screen_connector/video_frame_buffer.h"
 
 namespace cuttlefish {
 
@@ -32,7 +31,7 @@ class ScreenshotHandler {
   ScreenshotHandler() = default;
   ~ScreenshotHandler() = default;
 
-  using SharedFrame = std::shared_ptr<webrtc_streaming::VideoFrameBuffer>;
+  using SharedFrame = std::shared_ptr<VideoFrameBuffer>;
   using SharedFrameFuture = std::shared_future<SharedFrame>;
   using SharedFramePromise = std::promise<SharedFrame>;
 
diff --git a/host/libs/config/config_constants.h b/host/libs/config/config_constants.h
index a26e4f703..c7e56cec6 100644
--- a/host/libs/config/config_constants.h
+++ b/host/libs/config/config_constants.h
@@ -45,6 +45,8 @@ inline constexpr char kHibernationExitMessage[] =
     "PM: hibernation: hibernation exit";
 inline constexpr char kFastbootStartedMessage[] =
     "Listening for fastboot command on tcp";
+inline constexpr char kGblFastbootStartedMessage[] =
+    "Started Fastboot over TCP";
 inline constexpr char kScreenChangedMessage[] = "VIRTUAL_DEVICE_SCREEN_CHANGED";
 inline constexpr char kDisplayPowerModeChangedMessage[] =
     "VIRTUAL_DEVICE_DISPLAY_POWER_MODE_CHANGED";
diff --git a/host/libs/config/cuttlefish_config.h b/host/libs/config/cuttlefish_config.h
index e2d9e8b43..9f4031486 100644
--- a/host/libs/config/cuttlefish_config.h
+++ b/host/libs/config/cuttlefish_config.h
@@ -637,6 +637,7 @@ class CuttlefishConfig {
     bool fail_fast() const;
     bool vhost_user_block() const;
     std::string ti50_emulator() const;
+    bool enable_jcard_simulator() const;
 
     // Kernel and bootloader logging
     bool enable_kernel_log() const;
@@ -875,6 +876,8 @@ class CuttlefishConfig {
     void set_fail_fast(bool fail_fast);
     void set_vhost_user_block(bool qemu_vhost_user_block);
     void set_ti50_emulator(const std::string& ti50_emulator);
+    // jcardsimulator
+    void set_enable_jcard_simulator(bool enable);
 
     // Kernel and bootloader logging
     void set_enable_kernel_log(bool enable_kernel_log);
diff --git a/host/libs/config/cuttlefish_config_instance.cpp b/host/libs/config/cuttlefish_config_instance.cpp
index af5ea28d5..1fce29393 100644
--- a/host/libs/config/cuttlefish_config_instance.cpp
+++ b/host/libs/config/cuttlefish_config_instance.cpp
@@ -1150,6 +1150,16 @@ std::string CuttlefishConfig::InstanceSpecific::ti50_emulator() const {
   return (*Dictionary())[kTi50].asString();
 }
 
+// jcardsim
+static constexpr char kEnableJcardSimulator[] = "enable_jcard_simulator";
+void CuttlefishConfig::MutableInstanceSpecific::set_enable_jcard_simulator(
+    bool enable_jcard_simulator) {
+  (*Dictionary())[kEnableJcardSimulator] = enable_jcard_simulator;
+}
+bool CuttlefishConfig::InstanceSpecific::enable_jcard_simulator() const {
+  return (*Dictionary())[kEnableJcardSimulator].asBool();
+}
+
 static constexpr char kEnableWebRTC[] = "enable_webrtc";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_webrtc(bool enable_webrtc) {
   (*Dictionary())[kEnableWebRTC] = enable_webrtc;
@@ -1657,8 +1667,6 @@ void CuttlefishConfig::MutableInstanceSpecific::set_mobile_mac(
   (*Dictionary())[kMobileMac] = mac;
 }
 
-// TODO(b/199103204): remove this as well when
-// PRODUCT_ENFORCE_MAC80211_HWSIM is removed
 static constexpr char kWifiTapName[] = "wifi_tap_name";
 std::string CuttlefishConfig::InstanceSpecific::wifi_tap_name() const {
   return (*Dictionary())[kWifiTapName].asString();
diff --git a/host/libs/config/data_image.cpp b/host/libs/config/data_image.cpp
index 6109834af..92c064c01 100644
--- a/host/libs/config/data_image.cpp
+++ b/host/libs/config/data_image.cpp
@@ -49,7 +49,7 @@ Result<void> ForceFsckImage(
   if (instance.userdata_format() == "f2fs") {
     fsck_path = HostBinaryPath("fsck.f2fs");
   } else if (instance.userdata_format() == "ext4") {
-    fsck_path = "/sbin/e2fsck";
+    fsck_path = HostBinaryPath("e2fsck");
   }
   int fsck_status = Execute({fsck_path, "-y", "-f", data_image});
   CF_EXPECTF(!(fsck_status &
@@ -78,7 +78,7 @@ Result<void> ResizeImage(const std::string& data_image, int data_image_mb,
   if (instance.userdata_format() == "f2fs") {
     resize_path = HostBinaryPath("resize.f2fs");
   } else if (instance.userdata_format() == "ext4") {
-    resize_path = "/sbin/resize2fs";
+    resize_path = HostBinaryPath("resize2fs");
   }
   if (resize_path != "") {
     CF_EXPECT_EQ(Execute({resize_path, data_image}), 0,
diff --git a/host/libs/config/fastboot/launch.cpp b/host/libs/config/fastboot/launch.cpp
index 36863787e..c6b8daf2f 100644
--- a/host/libs/config/fastboot/launch.cpp
+++ b/host/libs/config/fastboot/launch.cpp
@@ -37,8 +37,8 @@ class FastbootProxy : public CommandSource, public KernelLogPipeConsumer {
         log_pipe_provider_(log_pipe_provider) {}
 
   Result<std::vector<MonitorCommand>> Commands() override {
-    const std::string ethernet_host = instance_.ethernet_ipv6() + "%" +
-                                      instance_.ethernet_bridge_name();
+    const std::string ethernet_host =
+        instance_.ethernet_ipv6() + "%" + instance_.ethernet_bridge_name();
 
     Command tunnel(SocketVsockProxyBinary());
     tunnel.AddParameter("--events_fd=", kernel_log_pipe_);
@@ -58,8 +58,13 @@ class FastbootProxy : public CommandSource, public KernelLogPipeConsumer {
 
   std::string Name() const override { return "FastbootProxy"; }
   bool Enabled() const override {
-    return instance_.boot_flow() == CuttlefishConfig::InstanceSpecific::BootFlow::Android &&
-           fastboot_config_.ProxyFastboot();
+    const auto boot_flow = instance_.boot_flow();
+    const bool is_android_boot =
+        boot_flow == CuttlefishConfig::InstanceSpecific::BootFlow::Android ||
+        boot_flow ==
+            CuttlefishConfig::InstanceSpecific::BootFlow::AndroidEfiLoader;
+
+    return is_android_boot && fastboot_config_.ProxyFastboot();
   }
 
  private:
diff --git a/host/libs/config/known_paths.cpp b/host/libs/config/known_paths.cpp
index ed6ff0053..3b67d39b8 100644
--- a/host/libs/config/known_paths.cpp
+++ b/host/libs/config/known_paths.cpp
@@ -42,6 +42,8 @@ std::string ControlEnvProxyServerBinary() {
   return HostBinaryPath("control_env_proxy_server");
 }
 
+std::string CpioBinary() { return HostBinaryPath("cpio"); }
+
 std::string DefaultKeyboardSpec() {
   return DefaultHostArtifactsPath("etc/default_input_devices/keyboard.json");
 }
diff --git a/host/libs/config/known_paths.h b/host/libs/config/known_paths.h
index 2d6ee2006..91ae0cf45 100644
--- a/host/libs/config/known_paths.h
+++ b/host/libs/config/known_paths.h
@@ -26,6 +26,7 @@ std::string CasimirBinary();
 std::string CasimirControlServerBinary();
 std::string ConsoleForwarderBinary();
 std::string ControlEnvProxyServerBinary();
+std::string CpioBinary();
 std::string DefaultKeyboardSpec();
 std::string DefaultMouseSpec();
 std::string DefaultMultiTouchpadSpecTemplate();
diff --git a/host/libs/config/secure_hals.cpp b/host/libs/config/secure_hals.cpp
index adb322083..c8722f2ca 100644
--- a/host/libs/config/secure_hals.cpp
+++ b/host/libs/config/secure_hals.cpp
@@ -50,6 +50,7 @@ NoDestructor<std::unordered_map<std::string_view, SecureHal>> kMapping([] {
       {"oemlock", SecureHal::kHostOemlockSecure},
       {"host_oemlock_secure", SecureHal::kHostOemlockSecure},
       {"host_secure_oemlock", SecureHal::kHostOemlockSecure},
+      {"guest_strongbox_insecure", SecureHal::kGuestStrongboxInsecure},
   };
 }());
 
@@ -114,6 +115,8 @@ std::string ToString(SecureHal hal_in) {
       return "host_oemlock_insecure";
     case SecureHal::kHostOemlockSecure:
       return "host_oemlock_secure";
+    case SecureHal::kGuestStrongboxInsecure:
+      return "guest_strongbox_insecure";
   }
 }
 
diff --git a/host/libs/config/secure_hals.h b/host/libs/config/secure_hals.h
index 94c9a6589..dc33af2b6 100644
--- a/host/libs/config/secure_hals.h
+++ b/host/libs/config/secure_hals.h
@@ -26,6 +26,7 @@ enum class SecureHal {
   kGuestGatekeeperInsecure,
   kGuestKeymintInsecure,
   kGuestKeymintTrustyInsecure,
+  kGuestStrongboxInsecure,
   kHostKeymintInsecure,
   kHostKeymintSecure,
   kHostGatekeeperInsecure,
diff --git a/host/libs/control_env/Android.bp b/host/libs/control_env/Android.bp
index 15c5dd82d..9972665df 100644
--- a/host/libs/control_env/Android.bp
+++ b/host/libs/control_env/Android.bp
@@ -30,8 +30,8 @@ cc_library {
         "libprotobuf-cpp-full",
     ],
     static_libs: [
+        "absl_flags_parse",
         "grpc_cli_libs",
-        "libabsl_host",
         "libgflags",
     ],
     cflags: [
diff --git a/host/libs/screen_connector/composition_manager.cpp b/host/libs/screen_connector/composition_manager.cpp
index dd0435c0a..7d7e6594c 100644
--- a/host/libs/screen_connector/composition_manager.cpp
+++ b/host/libs/screen_connector/composition_manager.cpp
@@ -32,7 +32,6 @@
 #include <libyuv.h>
 
 #include <drm/drm_fourcc.h>
-#include "host/frontend/webrtc/display_handler.h"
 #include "host/libs/screen_connector/ring_buffer_manager.h"
 
 static const int kRedIdx = 0;
@@ -209,7 +208,7 @@ void CompositionManager::OnFrame(std::uint32_t display_number,
 // triggered by a thread to force displays to constantly update so that when
 // layers are updated, the user will see the blended result.
 void CompositionManager::ComposeFrame(
-    int display_index, std::shared_ptr<CvdVideoFrameBuffer> buffer) {
+    int display_index, std::shared_ptr<VideoFrameBuffer> buffer) {
   if (!last_frame_info_map_.contains(display_index)) {
     return;
   }
@@ -258,7 +257,7 @@ std::uint8_t* CompositionManager::AlphaBlendLayers(std::uint8_t* frame_pixels,
 void CompositionManager::ComposeFrame(
     int display, int width, int height, std::uint32_t frame_fourcc_format,
     std::uint32_t frame_stride_bytes,
-    std::shared_ptr<CvdVideoFrameBuffer> buffer) {
+    std::shared_ptr<VideoFrameBuffer> buffer) {
   std::uint8_t* shmem_local_display = display_ring_buffer_manager_.ReadFrame(
       cluster_index_, display, width, height);
 
@@ -283,4 +282,4 @@ void CompositionManager::ComposeFrame(
   }
 }
 
-}  // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/composition_manager.h b/host/libs/screen_connector/composition_manager.h
index c63d2bfa2..02ec7364e 100644
--- a/host/libs/screen_connector/composition_manager.h
+++ b/host/libs/screen_connector/composition_manager.h
@@ -17,13 +17,11 @@
 
 #include <android-base/logging.h>
 #include "common/libs/utils/result.h"
-#include "host/frontend/webrtc/cvd_video_frame_buffer.h"
-#include "host/frontend/webrtc/display_handler.h"
-#include "host/frontend/webrtc/libdevice/video_sink.h"
+#include "host/libs/screen_connector/ring_buffer_manager.h"
 #include "host/libs/screen_connector/screen_connector.h"
+#include "host/libs/screen_connector/video_frame_buffer.h"
 
 namespace cuttlefish {
-class DisplayHandler;
 
 class CompositionManager {
  public:
@@ -41,7 +39,7 @@ class CompositionManager {
                std::uint32_t frame_stride_bytes, std::uint8_t* frame_pixels);
 
   void ComposeFrame(int display_index,
-                    std::shared_ptr<CvdVideoFrameBuffer> buffer);
+                    std::shared_ptr<VideoFrameBuffer> buffer);
 
  private:
   explicit CompositionManager(
@@ -76,7 +74,7 @@ class CompositionManager {
   void ComposeFrame(int display, int width, int height,
                     std::uint32_t frame_fourcc_format,
                     std::uint32_t frame_stride_bytes,
-                    std::shared_ptr<CvdVideoFrameBuffer> buffer);
+                    std::shared_ptr<VideoFrameBuffer> buffer);
   DisplayRingBufferManager display_ring_buffer_manager_;
   int cluster_index_;
   std::string group_uuid_;
@@ -85,4 +83,4 @@ class CompositionManager {
   std::map<int, std::vector<std::uint8_t>> frame_work_buffer_;
 };
 
-}  // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/frontend/webrtc/libdevice/video_frame_buffer.h b/host/libs/screen_connector/video_frame_buffer.h
similarity index 83%
rename from host/frontend/webrtc/libdevice/video_frame_buffer.h
rename to host/libs/screen_connector/video_frame_buffer.h
index a40eb75b0..d9d8710de 100644
--- a/host/frontend/webrtc/libdevice/video_frame_buffer.h
+++ b/host/libs/screen_connector/video_frame_buffer.h
@@ -16,10 +16,10 @@
 
 #pragma once
 
-#include <cinttypes>
+#include <stdint.h>
+#include <cstddef>
 
 namespace cuttlefish {
-namespace webrtc_streaming {
 
 class VideoFrameBuffer {
  public:
@@ -30,13 +30,12 @@ class VideoFrameBuffer {
   virtual int StrideY() const = 0;
   virtual int StrideU() const = 0;
   virtual int StrideV() const = 0;
-  virtual const uint8_t* DataY() const = 0;
-  virtual const uint8_t* DataU() const = 0;
-  virtual const uint8_t* DataV() const = 0;
+  virtual uint8_t* DataY() = 0;
+  virtual uint8_t* DataU() = 0;
+  virtual uint8_t* DataV() = 0;
   virtual std::size_t DataSizeY() const = 0;
   virtual std::size_t DataSizeU() const = 0;
   virtual std::size_t DataSizeV() const = 0;
 };
 
-}  // namespace webrtc_streaming
 }  // namespace cuttlefish
diff --git a/host/libs/vm_manager/crosvm_manager.cpp b/host/libs/vm_manager/crosvm_manager.cpp
index 9548c4560..32edc96e3 100644
--- a/host/libs/vm_manager/crosvm_manager.cpp
+++ b/host/libs/vm_manager/crosvm_manager.cpp
@@ -915,6 +915,15 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.AddHvcSink();
   }
 
+  if (instance.enable_jcard_simulator()) {
+    // /dev/hvc17 = JCardSimulator
+    crosvm_cmd.AddHvcReadWrite(
+        instance.PerInstanceInternalPath("jcardsim_fifo_vm.out"),
+        instance.PerInstanceInternalPath("jcardsim_fifo_vm.in"));
+  } else {
+    crosvm_cmd.AddHvcSink();
+  }
+
   for (auto i = 0; i < VmManager::kMaxDisks - disk_num; i++) {
     crosvm_cmd.AddHvcSink();
   }
diff --git a/host/libs/vm_manager/qemu_manager.cpp b/host/libs/vm_manager/qemu_manager.cpp
index 1908bd2b6..bd313eba0 100644
--- a/host/libs/vm_manager/qemu_manager.cpp
+++ b/host/libs/vm_manager/qemu_manager.cpp
@@ -654,6 +654,13 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
     add_hvc_sink();
   }
 
+  if (instance.enable_jcard_simulator()) {
+    // /dev/hvc17 = keymint (jcardsim implementation)
+    add_hvc(instance.PerInstanceInternalPath("jcardsim_fifo_vm"));
+  } else {
+    add_hvc_sink();
+  }
+
   auto disk_num = instance.virtual_disk_paths().size();
 
   for (auto i = 0; i < VmManager::kMaxDisks - disk_num; i++) {
diff --git a/host/libs/vm_manager/vm_manager.h b/host/libs/vm_manager/vm_manager.h
index 3fa286f31..ebb8da501 100644
--- a/host/libs/vm_manager/vm_manager.h
+++ b/host/libs/vm_manager/vm_manager.h
@@ -64,7 +64,8 @@ class VmManager {
   // - /dev/hvc14 = MCU control
   // - /dev/hvc15 = MCU UART
   // - /dev/hvc16 = Ti50 TPM FIFO
-  static const int kDefaultNumHvcs = 17;
+  // - /dev/hvc17 = jcardsimulator
+  static const int kDefaultNumHvcs = 18;
 
   // This is the number of virtual disks (block devices) that should be
   // configured by the VmManager. Related to the description above regarding
diff --git a/required_images b/required_images
index 837224b75..02fcd9e9f 100644
--- a/required_images
+++ b/required_images
@@ -1,6 +1,5 @@
 android-info.txt
 boot.img
-bootloader
 init_boot.img
 super.img
 userdata.img
diff --git a/shared/BoardConfig.mk b/shared/BoardConfig.mk
index 056e9456f..afe0fcf6f 100644
--- a/shared/BoardConfig.mk
+++ b/shared/BoardConfig.mk
@@ -20,12 +20,19 @@
 
 # Some targets still require 32 bit, and 6.6 kernels don't support
 # 32 bit devices
-ifeq (true,$(CLOCKWORK_EMULATOR_PRODUCT))
+
+ifneq (,$(findstring cf_gwear_arm,$(PRODUCT_NAME)))
+TARGET_KERNEL_USE ?= 6.6
+else ifeq (true,$(CLOCKWORK_EMULATOR_PRODUCT))
 TARGET_KERNEL_USE ?= 6.1
 else ifneq (,$(findstring x86_tv,$(PRODUCT_NAME)))
 TARGET_KERNEL_USE ?= 6.1
-else ifneq (,$(findstring _desktop,$(PRODUCT_NAME)))
-TARGET_KERNEL_USE ?= 6.6
+else ifneq (,$(findstring cf_x86_64_desktop,$(PRODUCT_NAME)))
+TARGET_KERNEL_USE ?= $(RELEASE_KERNEL_CUTTLEFISH_X86_64_VERSION)
+TARGET_KERNEL_DIR ?= $(RELEASE_KERNEL_CUTTLEFISH_X86_64_DIR)
+else ifneq (,$(findstring cf_arm64_desktop,$(PRODUCT_NAME)))
+TARGET_KERNEL_USE ?= $(RELEASE_KERNEL_CUTTLEFISH_ARM64_VERSION)
+TARGET_KERNEL_DIR ?= $(RELEASE_KERNEL_CUTTLEFISH_ARM64_DIR)
 else
 TARGET_KERNEL_USE ?= 6.12
 endif
@@ -33,8 +40,8 @@ endif
 TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
 
 ifneq (,$(filter cf_x86_64_desktop cf_arm64_desktop,$(PRODUCT_NAME)))
-SYSTEM_DLKM_SRC ?= device/google/cuttlefish_prebuilts/kernel/6.6-$(TARGET_KERNEL_ARCH)-desktop/system_dlkm
-KERNEL_MODULES_PATH ?= device/google/cuttlefish_prebuilts/kernel/6.6-$(TARGET_KERNEL_ARCH)-desktop/vendor_dlkm
+SYSTEM_DLKM_SRC ?= device/google/desktop/cuttlefish-$(TARGET_KERNEL_ARCH)-kernels/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_DIR)/system_dlkm
+KERNEL_MODULES_PATH ?= device/google/desktop/cuttlefish-$(TARGET_KERNEL_ARCH)-kernels/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_DIR)/vendor_dlkm
 else
 SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
 KERNEL_MODULES_PATH ?= \
@@ -44,7 +51,24 @@ endif
 TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
 PRODUCT_COPY_FILES += $(TARGET_KERNEL_PATH):kernel
 
+# This check prevents the $(shell grep ...) subexpression below from printing
+# "grep: ... No such file or directory" to stdout. Explanation:
+#
+# - For some reason BOARD_KERNEL_VERSION seems to be evaluated twice, once
+#   before the RELEASE_KERNEL_CUTTLEFISH_* variables are loaded, and again
+#   after they are loaded. The first evaluation results in KERNEL_MODULES_PATH
+#   having an invalid path, causing grep to fail with the above message.
+#
+# - The build still works without this workaround (e.g. "m" and "m dist"
+#   complete successfully). The goal of the workaround is just to prevent the
+#   spurious grep error message.
+#
+# - The check uses the RELEASE_KERNEL_CUTTLEFISH_X86_64_VERSION variable, which
+#   was chosen arbirarily. Any other RELEASE_KERNEL_CUTTLEFISH_* flag works,
+#   even when building for Arm64.
+ifneq (,$(RELEASE_KERNEL_CUTTLEFISH_X86_64_VERSION))
 BOARD_KERNEL_VERSION := $(word 1,$(subst vermagic=,,$(shell grep -E -h -ao -m 1 'vermagic=.*' $(KERNEL_MODULES_PATH)/nd_virtio.ko)))
+endif
 
 ifneq (,$(findstring auto, $(PRODUCT_NAME)))
 HIB_SWAP_IMAGE_SIZE_GB ?= 4
diff --git a/shared/auto/audio/effects/audio_effects_config.xml b/shared/auto/audio/effects/audio_effects_config.xml
index e2c37bd43..6989a01a0 100644
--- a/shared/auto/audio/effects/audio_effects_config.xml
+++ b/shared/auto/audio/effects/audio_effects_config.xml
@@ -1,4 +1,18 @@
 <?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
 <audio_effects_conf version="2.0" xmlns="http://schemas.android.com/audio/audio_effects_conf/v2_0">
     <!-- Overview.
          This example config file was copy from existing one: frameworks/av/media/libeffects/data/
diff --git a/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml b/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml
index 824083cc8..98fe77efd 100644
--- a/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml
+++ b/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml
@@ -150,9 +150,6 @@
         <AttributesGroup streamType="AUDIO_STREAM_TTS" volumeGroup="tts">
             <Attributes> <Flags value="AUDIO_FLAG_BEACON"/> </Attributes>
         </AttributesGroup>
-        <AttributesGroup streamType="AUDIO_STREAM_ACCESSIBILITY" volumeGroup="tts">
-            <Attributes> <Usage value="AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY"/> </Attributes>
-        </AttributesGroup>
     </ProductStrategy>
 
 </ProductStrategies>
diff --git a/shared/auto/device_vendor.mk b/shared/auto/device_vendor.mk
index 773b4dc2b..03eb83163 100644
--- a/shared/auto/device_vendor.mk
+++ b/shared/auto/device_vendor.mk
@@ -45,11 +45,12 @@ PRODUCT_COPY_FILES += \
     packages/services/Car/car_product/init/init.bootstat.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.bootstat.rc \
     packages/services/Car/car_product/init/init.car.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.car.rc
 
-ifneq ($(LOCAL_SENSOR_FILE_OVERRIDES),true)
-    PRODUCT_COPY_FILES += \
-        frameworks/native/data/etc/android.hardware.sensor.accelerometer.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.accelerometer.xml \
-        frameworks/native/data/etc/android.hardware.sensor.compass.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.compass.xml
-endif
+# Override default sensor files in device_vendor.mk
+LOCAL_SENSOR_FILE_OVERRIDES := true
+# Add the sensor files that are supported on Automotive
+PRODUCT_COPY_FILES += \
+    frameworks/native/data/etc/android.hardware.sensor.accelerometer.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.accelerometer.xml \
+    frameworks/native/data/etc/android.hardware.sensor.gyroscope.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.gyroscope.xml
 
 PRODUCT_PRODUCT_PROPERTIES += \
     ro.boot.uwbcountrycode=US
@@ -169,3 +170,6 @@ GOOGLE_CAR_SERVICE_OVERLAY += ConnectivityOverlayCuttleFishGoogle
 
 TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/shared/auto/android-info.txt
 BOARD_BOOTCONFIG += androidboot.hibernation_resume_device=259:3
+
+# TODO (b/405655265) Remove once the BT issue is fixed
+BOARD_BOOTCONFIG += androidboot.cuttlefish_service_bluetooth_checker=false
\ No newline at end of file
diff --git a/shared/auto_md/android-info.txt b/shared/auto_md/android-info.txt
index c4b6eefc2..e684bef1d 100644
--- a/shared/auto_md/android-info.txt
+++ b/shared/auto_md/android-info.txt
@@ -1,4 +1,4 @@
 config=auto_md
 gfxstream=supported
 gfxstream_gl_program_binary_link_status=supported
-output_audio_streams_count=6
\ No newline at end of file
+output_audio_streams_count=13
\ No newline at end of file
diff --git a/shared/auto_md/audio/Android.bp b/shared/auto_md/audio/Android.bp
new file mode 100644
index 000000000..61681db0a
--- /dev/null
+++ b/shared/auto_md/audio/Android.bp
@@ -0,0 +1,21 @@
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
+soong_namespace {
+    imports: [
+        "frameworks/av/services/audiopolicy/config",
+        "frameworks/av/services/audiopolicy/engineconfigurable/parameter-framework/examples/Car",
+    ],
+}
diff --git a/shared/auto_md/audio/audio.mk b/shared/auto_md/audio/audio.mk
new file mode 100644
index 000000000..f06140a08
--- /dev/null
+++ b/shared/auto_md/audio/audio.mk
@@ -0,0 +1,26 @@
+#
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
+PRODUCT_PACKAGES += audio_policy_configuration.xml
+
+#
+# Audio HAL / AudioEffect HAL
+#
+PRODUCT_PACKAGES += audio_effects_config.xml
+
+#
+# CarService
+#
+PRODUCT_PACKAGES += car_audio_configuration.xml
diff --git a/shared/auto_md/audio/carservice/Android.bp b/shared/auto_md/audio/carservice/Android.bp
new file mode 100644
index 000000000..2a853c6e6
--- /dev/null
+++ b/shared/auto_md/audio/carservice/Android.bp
@@ -0,0 +1,25 @@
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
+prebuilt_etc {
+    name: "car_audio_configuration.xml",
+    vendor: true,
+    src: ":car_audio_configuration",
+}
+
+filegroup {
+    name: "car_audio_configuration",
+    srcs: ["car_audio_configuration.xml"],
+}
diff --git a/shared/auto_md/audio/carservice/car_audio_configuration.xml b/shared/auto_md/audio/carservice/car_audio_configuration.xml
new file mode 100644
index 000000000..f7eb9a560
--- /dev/null
+++ b/shared/auto_md/audio/carservice/car_audio_configuration.xml
@@ -0,0 +1,189 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+
+<!--
+  Defines the audio configuration in a car, including
+    - Audio zones
+    - Zone configurations (in each audio zone)
+    - Volume groups (in each zone configuration)
+    - Context to audio bus mappings (in each volume group)
+  in the car environment.
+-->
+<carAudioConfiguration version="4">
+    <deviceConfigurations>
+        <deviceConfiguration name="useHalDuckingSignals" value="true" />
+        <deviceConfiguration name="useCoreAudioRouting" value="false" />
+        <deviceConfiguration name="useCoreAudioVolume" value="false" />
+        <deviceConfiguration name="useCarVolumeGroupMuting" value="true" />
+    </deviceConfigurations>
+    <activationVolumeConfigs>
+        <activationVolumeConfig name="activation_volume_on_boot_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="90" invocationType="onPlaybackChanged" />
+        </activationVolumeConfig>
+        <activationVolumeConfig name="activation_volume_on_source_changed_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="80" invocationType="onSourceChanged" />
+        </activationVolumeConfig>
+        <activationVolumeConfig name="activation_volume_on_playback_changed_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="80" />
+        </activationVolumeConfig>
+    </activationVolumeConfigs>
+    <mirroringDevices>
+        <mirroringDevice address="BUS1000_MIRROR_CARD_0_DEV_12"/>
+    </mirroringDevices>
+    <zones>
+        <zone isPrimary="true" name="primary zone" audioZoneId="0" occupantZoneId="0">
+            <zoneConfigs>
+                <zoneConfig  name="primary zone config 1" isDefault="true">
+                    <volumeGroups>
+                        <group name="entertainment" activationConfig="activation_volume_on_boot_config">
+                            <device address="BUS00_MEDIA_CARD_0_DEV_0">
+                                <context context="music"/>
+                                <context context="announcement"/>
+                            </device>
+                        </group>
+                        <group name="navvol" activationConfig="activation_volume_on_source_changed_config">
+                            <device address="BUS01_NAV_GUIDANCE_CARD_0_DEV_1">
+                                <context context="navigation"/>
+                            </device>
+                            <device address="BUS02_NOTIFICATION_CARD_0_DEV_2">
+                                <context context="notification"/>
+                            </device>
+                        </group>
+                        <group name="sdsvol" activationConfig="activation_volume_on_playback_changed_config">
+                            <device address="BUS04_ASSISTANT_CARD_0_DEV_4">
+                                <context context="voice_command"/>
+                            </device>
+                        </group>
+                        <group name="system" activationConfig="activation_volume_on_source_changed_config">
+                            <device address="BUS05_SYSTEM_CARD_0_DEV_5">
+                                <context context="system_sound"/>
+                                <context context="emergency"/>
+                                <context context="safety"/>
+                                <context context="vehicle_status"/>
+                            </device>
+                        </group>
+                        <group name="telringvol" activationConfig="activation_volume_on_playback_changed_config">
+                            <device address="BUS03_PHONE_CARD_0_DEV_3">
+                                <context context="call"/>
+                                <context context="call_ring"/>
+                                <context context="alarm"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+            </zoneConfigs>
+        </zone>
+        <zone name="rear seat zone 1" audioZoneId="1" occupantZoneId="1">
+            <zoneConfigs>
+                <zoneConfig name="rear seat zone 1 config 0" isDefault="true">
+                    <volumeGroups>
+                        <group>
+                            <device address="BUS100_ZONE_1_CARD_0_DEV_6">
+                                <context context="music"/>
+                            </device>
+                        </group>
+                        <group>
+                            <device address="BUS101_ZONE_1_CARD_0_DEV_7">
+                                <context context="navigation"/>
+                                <context context="voice_command"/>
+                                <context context="call_ring"/>
+                                <context context="call"/>
+                                <context context="alarm"/>
+                                <context context="notification"/>
+                                <context context="system_sound"/>
+                                <context context="emergency"/>
+                                <context context="safety"/>
+                                <context context="vehicle_status"/>
+                                <context context="announcement"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+                <zoneConfig name="rear seat zone 1 config 1">
+                    <volumeGroups>
+                        <group>
+                            <device address="BUS110_ZONE_1_CARD_0_DEV_8">
+                                <context context="music"/>
+                                <context context="navigation"/>
+                                <context context="voice_command"/>
+                                <context context="call_ring"/>
+                                <context context="call"/>
+                                <context context="alarm"/>
+                                <context context="notification"/>
+                                <context context="system_sound"/>
+                                <context context="emergency"/>
+                                <context context="safety"/>
+                                <context context="vehicle_status"/>
+                                <context context="announcement"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+            </zoneConfigs>
+        </zone>
+        <zone name="rear seat zone 2" audioZoneId="2"  occupantZoneId="2">
+            <zoneConfigs>
+                <zoneConfig name="rear seat zone 2 config 0" isDefault="true">
+                    <volumeGroups>
+                        <group>
+                            <device address="BUS200_ZONE_2_CARD_0_DEV_9">
+                                <context context="music"/>
+                            </device>
+                        </group>
+                        <group>
+                            <device address="BUS201_ZONE_2_CARD_0_DEV_10">
+                                <context context="navigation"/>
+                                <context context="voice_command"/>
+                                <context context="call_ring"/>
+                                <context context="call"/>
+                                <context context="alarm"/>
+                                <context context="notification"/>
+                                <context context="system_sound"/>
+                                <context context="emergency"/>
+                                <context context="safety"/>
+                                <context context="vehicle_status"/>
+                                <context context="announcement"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+                <zoneConfig name="rear seat zone 2 config 1">
+                    <volumeGroups>
+                        <group>
+                            <device address="BUS210_ZONE_2_CARD_0_DEV_11">
+                                <context context="music"/>
+                                <context context="navigation"/>
+                                <context context="voice_command"/>
+                                <context context="call_ring"/>
+                                <context context="call"/>
+                                <context context="alarm"/>
+                                <context context="notification"/>
+                                <context context="system_sound"/>
+                                <context context="emergency"/>
+                                <context context="safety"/>
+                                <context context="vehicle_status"/>
+                                <context context="announcement"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+            </zoneConfigs>
+        </zone>
+    </zones>
+</carAudioConfiguration>
diff --git a/shared/auto_md/audio/effects/Android.bp b/shared/auto_md/audio/effects/Android.bp
new file mode 100644
index 000000000..95d968c8e
--- /dev/null
+++ b/shared/auto_md/audio/effects/Android.bp
@@ -0,0 +1,25 @@
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
+prebuilt_etc {
+    name: "audio_effects_config.xml",
+    vendor: true,
+    src: ":audio_effects_config",
+}
+
+filegroup {
+    name: "audio_effects_config",
+    srcs: ["audio_effects_config.xml"],
+}
diff --git a/shared/auto_md/audio/effects/audio_effects_config.xml b/shared/auto_md/audio/effects/audio_effects_config.xml
new file mode 100644
index 000000000..6989a01a0
--- /dev/null
+++ b/shared/auto_md/audio/effects/audio_effects_config.xml
@@ -0,0 +1,148 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<audio_effects_conf version="2.0" xmlns="http://schemas.android.com/audio/audio_effects_conf/v2_0">
+    <!-- Overview.
+         This example config file was copy from existing one: frameworks/av/media/libeffects/data/
+         audio_effects.xml, with effect library names updated to AIDL libraries we currently have.
+
+         All "library" attributes in "effect" element must must match a "library" element with the
+         same value of the "name" attribute.
+         All "effect" attributes in "preprocess" and "postprocess" element must match an "effect"
+         element with the same value of the "name" attribute.
+
+         AIDL EffectFactory are relying on the "name" attribute in "effect" element to identify the
+         effect type, so it's necessary to have the mapping from name to effect type UUID. Make
+         sure to either use existing effect name as key of
+         ::android::hardware::audio::effect::kUuidNameTypeMap, or add a new {name, typeUUID} map
+         item to the kUuidNameTypeMap.
+
+         Existing audio_effects.xml should working without any change as long as:
+         1. "path" attribute of "library" element matches with the actual effect library name.
+         2. "name" attribute of "effect" and "effectProxy" element correctly added as key of
+            kUuidNameTypeMap, with value matches Identity.type in Descriptor.aidl.
+         3. "uuid" attribute of "effect" element matches Identity.uuid in Descriptor.aidl.
+         4. "uuid" attribute of "effectProxy" element matches Identity.proxy in Descriptor.aidl.
+    -->
+
+    <!-- List of effect libraries to load.
+         Each library element must contain a "name" attribute and a "path" attribute giving the
+         name of a library .so file on the target device.
+    -->
+    <libraries>
+        <library name="aecsw" path="libaecsw.so"/>
+        <library name="agc1sw" path="libagc1sw.so"/>
+        <library name="agc2sw" path="libagc2sw.so"/>
+        <library name="bassboostsw" path="libbassboostsw.so"/>
+        <library name="bundle" path="libbundleaidl.so"/>
+        <library name="downmix" path="libdownmixaidl.so"/>
+        <library name="dynamics_processing" path="libdynamicsprocessingaidl.so"/>
+        <library name="equalizersw" path="libequalizersw.so"/>
+        <library name="haptic_generator" path="libhapticgeneratoraidl.so"/>
+        <library name="loudness_enhancer" path="libloudnessenhanceraidl.so"/>
+        <library name="nssw" path="libnssw.so"/>
+        <library name="env_reverbsw" path="libenvreverbsw.so"/>
+        <library name="preset_reverbsw" path="libpresetreverbsw.so"/>
+        <library name="reverb" path="libreverbaidl.so"/>
+        <library name="virtualizersw" path="libvirtualizersw.so"/>
+        <library name="visualizer" path="libvisualizeraidl.so"/>
+        <library name="volumesw" path="libvolumesw.so"/>
+        <library name="extensioneffect" path="libextensioneffect.so"/>
+    </libraries>
+
+    <!-- list of effects to load.
+         Each "effect" element must contain a "name", "library" and a "uuid" attribute, an optional
+         "type" attribute can be used to add any customized effect type.
+         The value of the "library" attribute must correspond to the name of one library element in
+         the "libraries" element.
+         The "name" attribute used to specific effect type, and should be mapping to a key of
+         aidl::android::hardware::audio::effect::kUuidNameTypeMap.
+         The "uuid" attribute is the implementation specific UUID as specified by the effect vendor.
+
+         Effect proxy can be supported with "effectProxy" element, each sub-element should contain
+         "library" and "uuid" attribute, all other attributes were ignored. Framework side use
+         result of IFactory.queryEffects() to decide which effect implementation should be part of
+         proxy and which not.
+
+         Only "name", "library", "uuid", and "type" attributes in "effects" element are meaningful
+          and parsed out by EffectConfig class, all other attributes are ignored.
+         Only "name" and "uuid" attributes in "effectProxy" element are meaningful and parsed out
+         by EffectConfig class, all other attributes are ignored.
+    -->
+
+    <effects>
+        <effect name="automatic_gain_control_v2" library="pre_processing" uuid="89f38e65-d4d2-4d64-ad0e-2b3e799ea886"/>
+        <effect name="bassboost" library="bundle" uuid="8631f300-72e2-11df-b57e-0002a5d5c51b"/>
+        <effect name="downmix" library="downmix" uuid="93f04452-e4fe-41cc-91f9-e475b6d1d69f"/>
+        <effect name="dynamics_processing" library="dynamics_processing" uuid="e0e6539b-1781-7261-676f-6d7573696340"/>
+        <effect name="haptic_generator" library="haptic_generator" uuid="97c4acd1-8b82-4f2f-832e-c2fe5d7a9931"/>
+        <effect name="loudness_enhancer" library="loudness_enhancer" uuid="fa415329-2034-4bea-b5dc-5b381c8d1e2c"/>
+        <effect name="env_reverb" library="env_reverbsw" uuid="fa819886-588b-11ed-9b6a-0242ac120002"/>
+        <effect name="preset_reverb" library="preset_reverbsw" uuid="fa8199c6-588b-11ed-9b6a-0242ac120002"/>
+        <effect name="reverb_env_aux" library="reverb" uuid="4a387fc0-8ab3-11df-8bad-0002a5d5c51b"/>
+        <effect name="reverb_env_ins" library="reverb" uuid="c7a511a0-a3bb-11df-860e-0002a5d5c51b"/>
+        <effect name="reverb_pre_aux" library="reverb" uuid="f29a1400-a3bb-11df-8ddc-0002a5d5c51b"/>
+        <effect name="reverb_pre_ins" library="reverb" uuid="172cdf00-a3bc-11df-a72f-0002a5d5c51b"/>
+        <effect name="virtualizer" library="bundle" uuid="1d4033c0-8557-11df-9f2d-0002a5d5c51b"/>
+        <effect name="visualizer" library="visualizer" uuid="d069d9e0-8329-11df-9168-0002a5d5c51b"/>
+        <effect name="volume" library="bundle" uuid="119341a0-8469-11df-81f9-0002a5d5c51b"/>
+        <effect name="equalizer" library="bundle" uuid="ce772f20-847d-11df-bb17-0002a5d5c51b"/>
+        <effect name="extension_effect" library="extensioneffect" uuid="fa81dd00-588b-11ed-9b6a-0242ac120002" type="fa81de0e-588b-11ed-9b6a-0242ac120002"/>
+    </effects>
+
+    <!-- Audio pre processor configurations.
+         The pre processor configuration is described in a "preprocess" element and consists in a
+         list of elements each describing pre processor settings for a given use case or "stream".
+         Each stream element has a "type" attribute corresponding to the input source used.
+         Valid types are these defined in system/hardware/interfaces/media/aidl/android/media/audio/
+         common/AudioSource.aidl.
+         Each "stream" element contains a list of "apply" elements indicating one effect to apply.
+         The effect to apply is designated by its name in the "effects" elements.
+         If there are more than one effect apply to one stream, the audio framework will apply them
+         in the same equence as they listed in "stream" element.
+
+        <preprocess>
+            <stream type="voice_communication">
+                <apply effect="aec"/>
+                <apply effect="ns"/>
+            </stream>
+        </preprocess>
+    -->
+
+    <!-- Audio post processor configurations.
+         The post processor configuration is described in a "postprocess" element and consists in a
+         list of elements each describing post processor settings for a given use case or "stream".
+         Each stream element has a "type" attribute corresponding to the stream type used.
+         Valid types are these defined in system/hardware/interfaces/media/aidl/android/media/audio/
+         common/AudioStreamType.aidl.
+         Each "stream" element contains a list of "apply" elements indicating one effect to apply.
+         The effect to apply is designated by its name in the "effects" elements.
+         If there are more than one effect apply to one stream, the audio framework will apply them
+         in the same equence as they listed in "stream" element.
+
+        <postprocess>
+            <stream type="music">
+                <apply effect="music_post_proc"/>
+            </stream>
+            <stream type="voice_call">
+                <apply effect="voice_post_proc"/>
+            </stream>
+            <stream type="notification">
+                <apply effect="notification_post_proc"/>
+            </stream>
+        </postprocess>
+    -->
+
+</audio_effects_conf>
diff --git a/shared/auto_md/audio/policy/Android.bp b/shared/auto_md/audio/policy/Android.bp
new file mode 100644
index 000000000..8cd1a1ae6
--- /dev/null
+++ b/shared/auto_md/audio/policy/Android.bp
@@ -0,0 +1,82 @@
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
+/////////////////////////////////////////////////////////////
+//
+// Audio Policy Configuration files
+//
+//////////////////////////////////////////////////////////////
+
+prebuilt_etc {
+    name: "audio_policy_configuration.xml",
+    vendor: true,
+    src: ":audio_policy_configuration_top_file",
+    required: [
+        "audio_policy_volumes.xml",
+        "bluetooth_with_le_audio_policy_configuration_7_0.xml",
+        "default_volume_tables.xml",
+        "primary_audio_policy_configuration.xml",
+        "r_submix_audio_policy_configuration.xml",
+        "surround_sound_configuration_5_0.xml",
+    ],
+}
+
+filegroup {
+    name: "primary_audio_policy_configuration",
+    srcs: [
+        "primary_audio_policy_configuration.xml",
+    ],
+}
+
+prebuilt_etc {
+    name: "primary_audio_policy_configuration.xml",
+    src: ":primary_audio_policy_configuration",
+    vendor: true,
+}
+
+prebuilt_etc {
+    name: "r_submix_audio_policy_configuration.xml",
+    vendor: true,
+    src: ":r_submix_audio_policy_configuration",
+}
+
+prebuilt_etc {
+    name: "audio_policy_volumes.xml",
+    vendor: true,
+    src: ":audio_policy_volumes",
+}
+
+prebuilt_etc {
+    name: "default_volume_tables.xml",
+    vendor: true,
+    src: ":default_volume_tables",
+}
+
+prebuilt_etc {
+    name: "surround_sound_configuration_5_0.xml",
+    vendor: true,
+    src: ":surround_sound_configuration_5_0",
+}
+
+prebuilt_etc {
+    name: "bluetooth_with_le_audio_policy_configuration_7_0.xml",
+    vendor: true,
+    src: ":bluetooth_with_le_audio_policy_configuration_7_0",
+}
+
+filegroup {
+    name: "audio_policy_configuration_top_file",
+    srcs: ["audio_policy_configuration.xml"],
+}
diff --git a/shared/auto_md/audio/policy/audio_policy_configuration.xml b/shared/auto_md/audio/policy/audio_policy_configuration.xml
new file mode 100644
index 000000000..a9db5eb24
--- /dev/null
+++ b/shared/auto_md/audio/policy/audio_policy_configuration.xml
@@ -0,0 +1,44 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+
+<audioPolicyConfiguration version="1.0" xmlns:xi="http://www.w3.org/2001/XInclude">
+    <!-- version section contains a “version” tag in the form “major.minor” e.g. version=”1.0” -->
+
+    <modules>
+        <!-- Primary Audio HAL -->
+        <xi:include href="primary_audio_policy_configuration.xml"/>
+
+        <!-- Remote Submix Audio HAL -->
+        <xi:include href="r_submix_audio_policy_configuration.xml"/>
+
+        <!-- Bluetooth Audio HAL -->
+        <xi:include href="bluetooth_with_le_audio_policy_configuration_7_0.xml"/>
+    </modules>
+    <!-- End of Modules section -->
+
+    <xi:include href="audio_policy_volumes.xml"/>
+
+    <xi:include href="default_volume_tables.xml"/>
+
+    <!-- End of Volume section -->
+
+    <!-- Surround Sound configuration -->
+
+    <xi:include href="surround_sound_configuration_5_0.xml"/>
+
+    <!-- End of Surround Sound configuration -->
+
+</audioPolicyConfiguration>
diff --git a/shared/auto_md/audio/policy/primary_audio_policy_configuration.xml b/shared/auto_md/audio/policy/primary_audio_policy_configuration.xml
new file mode 100644
index 000000000..a046d8b0b
--- /dev/null
+++ b/shared/auto_md/audio/policy/primary_audio_policy_configuration.xml
@@ -0,0 +1,227 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+
+<module name="primary" halVersion="7.0">
+    <attachedDevices>
+        <item>BUS00_MEDIA_CARD_0_DEV_0</item>
+        <item>BUS01_NAV_GUIDANCE_CARD_0_DEV_1</item>
+        <item>BUS02_NOTIFICATION_CARD_0_DEV_2</item>
+        <item>BUS03_PHONE_CARD_0_DEV_3</item>
+        <item>BUS04_ASSISTANT_CARD_0_DEV_4</item>
+        <item>BUS05_SYSTEM_CARD_0_DEV_5</item>
+        <item>BUS100_ZONE_1_CARD_0_DEV_6</item>
+        <item>BUS101_ZONE_1_CARD_0_DEV_7</item>
+        <item>BUS110_ZONE_1_CARD_0_DEV_8</item>
+        <item>BUS200_ZONE_2_CARD_0_DEV_9</item>
+        <item>BUS201_ZONE_2_CARD_0_DEV_10</item>
+        <item>BUS210_ZONE_2_CARD_0_DEV_11</item>
+        <item>BUS1000_MIRROR_CARD_0_DEV_12</item>
+        <item>builtin_mic</item>
+        <item>fm_tuner</item>
+        <item>telephony_tx</item>
+        <item>telephony_rx</item>
+    </attachedDevices>
+
+    <defaultOutputDevice>BUS00_MEDIA_CARD_0_DEV_0</defaultOutputDevice>
+    <mixPorts>
+        <mixPort name="primary_input" role="sink" maxActiveCount="1" maxOpenCount="1">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="8000 11025 16000 44100 48000"
+                channelMasks="AUDIO_CHANNEL_IN_STEREO AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_FRONT_BACK" />
+        </mixPort>
+        <mixPort name="radio_input" role="sink">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus0_usage_main_output" role="source" flags="AUDIO_OUTPUT_FLAG_PRIMARY">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus1_usage_nav_guidance_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus2_usage_notification_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus3_usage_voice_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus4_usage_assistant_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus5_usage_system_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus100_zone_1_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus101_zone_1_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus110_zone_1_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus200_zone_2_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus201_zone_2_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus210_zone_2_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus1000_mirror_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="hfp_tx_mix" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="hfp_rx_mix" role="sink" flags="AUDIO_INPUT_FLAG_PRIMARY">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+        </mixPort>
+    </mixPorts>
+
+    <devicePorts>
+        <devicePort tagName="builtin_mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" role="source" address="bottom_CARD_0_DEV_0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="16000 48000" channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO" />
+        </devicePort>
+        <devicePort tagName="fm_tuner" type="AUDIO_DEVICE_IN_FM_TUNER" role="source" address="tuner0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-3200" maxValueMB="600" defaultValueMB="0" stepValueMB="100" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS00_MEDIA_CARD_0_DEV_0" type="AUDIO_DEVICE_OUT_BUS" role="sink" address="BUS00_MEDIA_CARD_0_DEV_0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS01_NAV_GUIDANCE_CARD_0_DEV_1" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS01_NAV_GUIDANCE_CARD_0_DEV_1">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS02_NOTIFICATION_CARD_0_DEV_2" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS02_NOTIFICATION_CARD_0_DEV_2">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS03_PHONE_CARD_0_DEV_3" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS03_PHONE_CARD_0_DEV_3">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS04_ASSISTANT_CARD_0_DEV_4" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS04_ASSISTANT_CARD_0_DEV_4">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS05_SYSTEM_CARD_0_DEV_5" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS05_SYSTEM_CARD_0_DEV_5">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS100_ZONE_1_CARD_0_DEV_6" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS100_ZONE_1_CARD_0_DEV_6">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS101_ZONE_1_CARD_0_DEV_7" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS101_ZONE_1_CARD_0_DEV_7">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS110_ZONE_1_CARD_0_DEV_8" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS110_ZONE_1_CARD_0_DEV_8">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS200_ZONE_2_CARD_0_DEV_9" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS200_ZONE_2_CARD_0_DEV_9">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS201_ZONE_2_CARD_0_DEV_10" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS201_ZONE_2_CARD_0_DEV_10">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS210_ZONE_2_CARD_0_DEV_11" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS210_ZONE_2_CARD_0_DEV_11">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS1000_MIRROR_CARD_0_DEV_12" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS1000_MIRROR_CARD_0_DEV_12">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250"/>
+            </gains>
+        </devicePort>
+        <devicePort tagName="telephony_tx" type="AUDIO_DEVICE_OUT_TELEPHONY_TX" role="sink" address="hfp_client_out">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain defaultValueMB="0" maxValueMB="4000" minValueMB="-8800" mode="AUDIO_GAIN_MODE_JOINT" name="" stepValueMB="100" useForVolume="false" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="telephony_rx" type="AUDIO_DEVICE_IN_TELEPHONY_RX" role="source" address="hfp_client_in">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO" />
+            <gains>
+                <gain defaultValueMB="0" maxValueMB="4000" minValueMB="-8400" mode="AUDIO_GAIN_MODE_JOINT" name="" stepValueMB="100" useForVolume="false" />
+            </gains>
+        </devicePort>
+    </devicePorts>
+
+    <routes>
+        <route type="mix" sink="primary_input" sources="builtin_mic" />
+        <route type="mix" sink="radio_input" sources="fm_tuner" />
+        <route type="mix" sink="BUS00_MEDIA_CARD_0_DEV_0" sources="mixport_bus0_usage_main_output"/>
+        <route type="mix" sink="BUS01_NAV_GUIDANCE_CARD_0_DEV_1" sources="mixport_bus1_usage_nav_guidance_output"/>
+        <route type="mix" sink="BUS02_NOTIFICATION_CARD_0_DEV_2" sources="mixport_bus2_usage_notification_output"/>
+        <route type="mix" sink="BUS03_PHONE_CARD_0_DEV_3" sources="mixport_bus3_usage_voice_output"/>
+        <route type="mix" sink="BUS04_ASSISTANT_CARD_0_DEV_4" sources="mixport_bus4_usage_assistant_output"/>
+        <route type="mix" sink="BUS05_SYSTEM_CARD_0_DEV_5" sources="mixport_bus5_usage_system_output"/>
+        <route type="mix" sink="BUS100_ZONE_1_CARD_0_DEV_6" sources="mixport_bus100_zone_1_output"/>
+        <route type="mix" sink="BUS101_ZONE_1_CARD_0_DEV_7" sources="mixport_bus101_zone_1_output"/>
+        <route type="mix" sink="BUS110_ZONE_1_CARD_0_DEV_8" sources="mixport_bus110_zone_1_output"/>
+        <route type="mix" sink="BUS200_ZONE_2_CARD_0_DEV_9" sources="mixport_bus200_zone_2_output"/>
+        <route type="mix" sink="BUS201_ZONE_2_CARD_0_DEV_10" sources="mixport_bus201_zone_2_output"/>
+        <route type="mix" sink="BUS210_ZONE_2_CARD_0_DEV_11" sources="mixport_bus210_zone_2_output"/>
+        <route type="mix" sink="BUS1000_MIRROR_CARD_0_DEV_12" sources="mixport_bus1000_mirror_output"/>
+        <route type="mix" sink="telephony_tx" sources="builtin_mic,hfp_tx_mix" />
+        <route type="mix" sink="hfp_rx_mix" sources="telephony_rx" />
+    </routes>
+</module>
diff --git a/shared/auto_md/audio_policy_engine.mk b/shared/auto_md/audio_policy_engine.mk
new file mode 100644
index 000000000..74f6c6835
--- /dev/null
+++ b/shared/auto_md/audio_policy_engine.mk
@@ -0,0 +1,20 @@
+#
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
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/cuttlefish/shared/auto_md/audio
+
+# Car Audio Policy Configurable emulator
+$(call inherit-product, device/google/cuttlefish/shared/auto_md/audio/audio.mk)
diff --git a/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml b/shared/auto_md/overlay/frameworks/base/core/res/res/xml/config_user_types.xml
similarity index 50%
rename from vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml
rename to shared/auto_md/overlay/frameworks/base/core/res/res/xml/config_user_types.xml
index 612843084..f9102f394 100644
--- a/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml
+++ b/shared/auto_md/overlay/frameworks/base/core/res/res/xml/config_user_types.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2024 The Android Open Source Project
+<!-- Copyright (C) 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -14,11 +14,8 @@
      limitations under the License.
 -->
 
-<permissions>
-    <!-- Uncalibrated acceleromter and gyroscope aren't supported on cuttlefish. Until support is
-    added, the limited axes versions of these sensors won't be generated and as a result should not
-    be included in the device through package manager features. Removing these until support is
-    added for these sensors. -->
-    <unavailable-feature name="android.hardware.sensor.accelerometer_limited_axes_uncalibrated" />
-    <unavailable-feature name="android.hardware.sensor.gyroscope_limited_axes_uncalibrated" />
-</permissions>
+<!-- See frameworks/base/core/res/res/xml/config_user_types.xml -->
+<user-types>
+    <full-type name="android.os.usertype.full.SECONDARY"
+                max-allowed="9" />
+</user-types>
\ No newline at end of file
diff --git a/shared/camera/config/external.mk b/shared/camera/config/external.mk
index c9886993d..c161d8e82 100644
--- a/shared/camera/config/external.mk
+++ b/shared/camera/config/external.mk
@@ -23,5 +23,4 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.vendor.camera.config=external
 
 # Load the non-APEX external camera config. The APEX loads all the configs by default, which the HAl picks from.
-PRODUCT_COPY_FILES += \
-	hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_external.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_external.json
+PRODUCT_PACKAGES += emu_camera_external.json
diff --git a/shared/camera/config/standard.mk b/shared/camera/config/standard.mk
index ff6c3f3fe..018dfb993 100644
--- a/shared/camera/config/standard.mk
+++ b/shared/camera/config/standard.mk
@@ -27,7 +27,8 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.camerax.extensions.enabled=true
 
 # Loads the non-APEX config files. The APEX loads all the configs by default, which the HAl picks from.
-PRODUCT_COPY_FILES += \
-	hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_back.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_back.json \
-	hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_front.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_front.json \
-	hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_depth.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_depth.json
+PRODUCT_SOONG_NAMESPACES += hardware/google/camera/devices/EmulatedCamera
+PRODUCT_PACKAGES += \
+    emu_camera_back.json \
+    emu_camera_front.json \
+    emu_camera_depth.json
diff --git a/shared/camera/device_vendor.mk b/shared/camera/device_vendor.mk
index 3e9c4f29e..7dee6c349 100644
--- a/shared/camera/device_vendor.mk
+++ b/shared/camera/device_vendor.mk
@@ -26,7 +26,6 @@ else
 PRODUCT_PACKAGES += androidx.camera.extensions.impl sample_camera_extensions.xml
 endif
 
-PRODUCT_SOONG_NAMESPACES += hardware/google/camera
 PRODUCT_SOONG_NAMESPACES += hardware/google/camera/devices/EmulatedCamera
 
 # TODO(b/257379485): 3A is incrementally enabling cuttlefish build for native
diff --git a/shared/config/Android.bp b/shared/config/Android.bp
index 346e819db..ddd1da8ab 100644
--- a/shared/config/Android.bp
+++ b/shared/config/Android.bp
@@ -17,10 +17,16 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-filegroup {
+prebuilt_root {
     name: "device_google_cuttlefish_shared_config_pci_ids",
-    srcs: ["pci.ids"],
+    src: "pci.ids",
+    vendor: true,
+    filename_from_src: true,
     licenses: ["device_google_cuttlefish_shared_config_pci_ids_license"],
+    enabled: select(soong_config_variable("cuttlefish_config", "use_pci_ids"), {
+        true: true,
+        default: false,
+    }),
 }
 
 license {
@@ -124,17 +130,6 @@ prebuilt_etc {
     vendor_ramdisk: true,
 }
 
-prebuilt_etc {
-    name: "fstab.cf.f2fs.cts.recovery",
-    srcs: [
-        ":gen_fstab_cf_f2fs_cts",
-    ],
-    dsts: [
-        "recovery.fstab",
-    ],
-    recovery: true,
-}
-
 prebuilt_etc {
     name: "fstab.cf.ext4.hctr2",
     src: ":gen_fstab_cf_ext4_hctr2",
@@ -168,3 +163,102 @@ prebuilt_etc {
     ],
     vendor_ramdisk: true,
 }
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_audio_policy",
+    srcs: [
+        "audio/policy/audio_policy_configuration.xml",
+        "audio/policy/primary_audio_policy_configuration.xml",
+    ],
+    vendor: true,
+    enabled: select(soong_config_variable("cuttlefish_config", "use_audio_policy"), {
+        true: true,
+        default: false,
+    }),
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_init_graphics_vendor_rc",
+    srcs: ["graphics/init_graphics.vendor.rc"],
+    vendor: true,
+    relative_install_path: "init",
+    enabled: select(soong_config_variable("cuttlefish_config", "use_init_graphics_vendor_rc"), {
+        true: true,
+        default: false,
+    }),
+}
+
+prebuilt_defaults {
+    name: "cuttlefish_config_general_files_defaults",
+    enabled: select(soong_config_variable("cuttlefish_config", "use_general_files"), {
+        true: true,
+        default: false,
+    }),
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_init_vendor_rc",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: ["init.vendor.rc"],
+    dsts: ["init.cutf_cvm.rc"],
+    vendor: true,
+    relative_install_path: "init",
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_init_product_rc",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: ["init.product.rc"],
+    dsts: ["init.rc"],
+    product_specific: true,
+    relative_install_path: "init",
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_media_files",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "media_codecs.xml",
+        "media_codecs_google_video.xml",
+        "media_codecs_performance.xml",
+        "media_profiles.xml",
+    ],
+    dsts: [
+        "media_codecs.xml",
+        "media_codecs_google_video.xml",
+        "media_codecs_performance.xml",
+        "media_profiles_V1_0.xml",
+    ],
+    vendor: true,
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_media_profiles_vendor",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "media_profiles.xml",
+    ],
+    dsts: [
+        "media_profiles_vendor.xml",
+    ],
+    vendor: true,
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_seriallogging_rc",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "seriallogging.rc",
+    ],
+    relative_install_path: "init",
+    vendor: true,
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_config_ueventd_rc",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "ueventd.rc",
+    ],
+    vendor: true,
+}
diff --git a/shared/config/audio/policy/primary_audio_policy_configuration.xml b/shared/config/audio/policy/primary_audio_policy_configuration.xml
index 8376decc3..d4f75af3e 100644
--- a/shared/config/audio/policy/primary_audio_policy_configuration.xml
+++ b/shared/config/audio/policy/primary_audio_policy_configuration.xml
@@ -36,12 +36,21 @@
                      samplingRates="44100 48000"
                      channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
         </mixPort>
+        <mixPort name="mmap_no_irq_out" role="source" flags="AUDIO_OUTPUT_FLAG_DIRECT AUDIO_OUTPUT_FLAG_MMAP_NOIRQ">
+             <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                      samplingRates="44100 48000"
+                      channelMasks="AUDIO_CHANNEL_OUT_STEREO"/>
+        </mixPort>
         <mixPort name="primary input" role="sink">
             <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
                      samplingRates="8000 11025 16000 32000 44100 48000"
                      channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO"/>
         </mixPort>
-
+        <mixPort name="mmap_no_irq_in" role="sink" flags="AUDIO_INPUT_FLAG_MMAP_NOIRQ">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                             samplingRates="44100 48000"
+                             channelMasks="AUDIO_CHANNEL_IN_STEREO"/>
+        </mixPort>
         <mixPort name="telephony_tx" role="source">
             <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
                      samplingRates="8000 11025 16000 32000 44100 48000"
@@ -65,7 +74,7 @@
         <devicePort tagName="Telephony Tx" type="AUDIO_DEVICE_OUT_TELEPHONY_TX" role="sink">
         </devicePort>
 
-        <devicePort tagName="Built-In Mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" role="source">
+        <devicePort tagName="Built-In Mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" address="bottom" role="source">
         </devicePort>
         <devicePort tagName="Telephony Rx" type="AUDIO_DEVICE_IN_TELEPHONY_RX" role="source">
         </devicePort>
@@ -75,9 +84,11 @@
     </devicePorts>
     <routes>
         <route type="mix" sink="Speaker"
-               sources="primary output,compressed_offload"/>
+               sources="primary output,compressed_offload,mmap_no_irq_out"/>
         <route type="mix" sink="primary input"
                sources="Built-In Mic"/>
+        <route type="mix" sink="mmap_no_irq_in"
+               sources="Built-In Mic"/>
 
         <route type="mix" sink="telephony_rx"
                sources="Telephony Rx"/>
diff --git a/shared/config/init.vendor.rc b/shared/config/init.vendor.rc
index 676740244..b39e855ea 100644
--- a/shared/config/init.vendor.rc
+++ b/shared/config/init.vendor.rc
@@ -59,7 +59,7 @@ on post-fs-data && property:ro.vendor.disable_rename_eth0=
     # TODO(b/202731768): Add this `start rename_eth0` command to the init.rc for rename_netiface
     start rename_eth0
 
-on post-fs-data && property:ro.vendor.wifi_impl=virt_wifi
+on post-fs-data && property:ro.boot.wifi_impl=virt_wifi
     # TODO(b/202731768): Add this `start setup_wifi` command to the init.rc for setup_wifi
     start setup_wifi
 
@@ -73,7 +73,7 @@ on late-fs
 
     write /dev/kmsg "GUEST_BUILD_FINGERPRINT: ${ro.build.fingerprint}"
 
-on post-fs-data && property:ro.vendor.wifi_impl=mac80211_hwsim_virtio
+on post-fs-data && property:ro.boot.wifi_impl=mac80211_hwsim_virtio
     mkdir /data/vendor/wifi 0770 wifi wifi
     mkdir /data/vendor/wifi/hostapd 0770 wifi wifi
     mkdir /data/vendor/wifi/hostapd/sockets 0770 wifi wifi
@@ -89,10 +89,6 @@ on boot
     symlink /dev/hvc6 /dev/gnss0
     symlink /dev/hvc7 /dev/gnss1
 
-    # enable f2fs sanity check to dump more metadata info to kmsg
-    # once it detects inode corruption
-    write /dev/sys/fs/by-name/userdata/sanity_check 1
-
 on property:sys.boot_completed=1
     trigger sys-boot-completed-set
     mkdir /mnt/vendor/custom 0755 root root
@@ -135,6 +131,8 @@ service suspend_blocker /vendor/bin/suspend_blocker
 on early-init
     setprop ro.setupwizard.mode ${ro.boot.setupwizard_mode}
 
+on early-init
+    setprop ro.vendor.cuttlefish_service_bluetooth_checker ${ro.boot.cuttlefish_service_bluetooth_checker}
+
 on early-init && property:ro.boot.enable_bootanimation=0
     setprop debug.sf.nobootanimation 1
-
diff --git a/shared/config/recovery.fstab/Android.bp b/shared/config/recovery.fstab/Android.bp
new file mode 100644
index 000000000..2b3f3d02b
--- /dev/null
+++ b/shared/config/recovery.fstab/Android.bp
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
+soong_namespace {}
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc {
+    name: "fstab.cf.f2fs.cts.recovery",
+    srcs: [
+        ":gen_fstab_cf_f2fs_cts",
+    ],
+    dsts: [
+        "recovery.fstab",
+    ],
+    recovery: true,
+}
diff --git a/shared/config/ueventd.rc b/shared/config/ueventd.rc
index 7d8f217a2..eeb7c8ccc 100644
--- a/shared/config/ueventd.rc
+++ b/shared/config/ueventd.rc
@@ -58,6 +58,9 @@
 # Ti50 emulator
 /dev/hvc16 0666 hsm hsm
 
+# jcardsimulator
+/dev/hvc17 0666 system system
+
 # Factory Reset Protection
 /dev/block/by-name/frp 0660 system system
 
diff --git a/shared/desktop/device_vendor.mk b/shared/desktop/device_vendor.mk
index a1e51a4f1..067d0f323 100644
--- a/shared/desktop/device_vendor.mk
+++ b/shared/desktop/device_vendor.mk
@@ -19,7 +19,6 @@ SYSTEM_EXT_MANIFEST_FILES += device/google/cuttlefish/shared/config/system_ext_m
 
 # Extend cuttlefish common sepolicy with desktop-specific functionality.
 BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy
-SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy/system_ext/private
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
 
diff --git a/shared/desktop/sepolicy/system_ext/private/gscd.te b/shared/desktop/sepolicy/gscd.te
similarity index 100%
rename from shared/desktop/sepolicy/system_ext/private/gscd.te
rename to shared/desktop/sepolicy/gscd.te
diff --git a/shared/desktop/sepolicy/system_ext/private/empty.te b/shared/desktop/sepolicy/system_ext/private/empty.te
deleted file mode 100644
index fc679a4f3..000000000
--- a/shared/desktop/sepolicy/system_ext/private/empty.te
+++ /dev/null
@@ -1 +0,0 @@
-# This file is left intentionally blank so this directory exists on all branches.
diff --git a/shared/device.mk b/shared/device.mk
index a86613508..f934adfed 100644
--- a/shared/device.mk
+++ b/shared/device.mk
@@ -29,26 +29,17 @@ VENDOR_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 # Set boot SPL
 BOOT_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 
-# Use EROFS APEX as default
-ifeq (true,$(RELEASE_APEX_USE_EROFS_PREINSTALLED))
-PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := erofs
-endif
-
 PRODUCT_VENDOR_PROPERTIES += \
     ro.vendor.boot_security_patch=$(BOOT_SECURITY_PATCH)
 
 PRODUCT_SOONG_NAMESPACES += device/generic/goldfish # for audio, wifi and sensors
+PRODUCT_SOONG_NAMESPACES += device/google/cuttlefish/shared/config/recovery.fstab # for recovery.fstab
 
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 DISABLE_RILD_OEM_HOOK := true
 # For customize cflags for libril share library building by soong.
 $(call soong_config_set,ril,disable_rild_oem_hook,true)
 
-# TODO(b/294888357) Remove this condition when OpenWRT is supported for RISC-V.
-ifndef PRODUCT_ENFORCE_MAC80211_HWSIM
-PRODUCT_ENFORCE_MAC80211_HWSIM := true
-endif
-
 PRODUCT_SET_DEBUGFS_RESTRICTIONS := true
 
 PRODUCT_FS_COMPRESSION := 1
@@ -85,8 +76,7 @@ PRODUCT_PRODUCT_PROPERTIES += \
 # spawn adbd by default without authorization for "adb logcat"
 ifeq ($(TARGET_BUILD_VARIANT),user)
 PRODUCT_PRODUCT_PROPERTIES += \
-    ro.adb.secure=0 \
-    ro.debuggable=1
+    ro.adb.secure=0
 
 PRODUCT_PACKAGES += \
     logpersist.start
@@ -203,8 +193,6 @@ PRODUCT_PACKAGES += \
     cuttlefish_overlay_frameworks_base_core \
     cuttlefish_overlay_nfc \
     cuttlefish_overlay_settings_provider \
-    cuttlefish_overlay_uwb \
-    cuttlefish_overlay_uwb_gsi \
 
 #
 # Satellite vendor service for CF
@@ -233,23 +221,23 @@ PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE := true
 # General files
 #
 
+$(call soong_config_set_bool,cuttlefish_config,use_general_files,true)
+PRODUCT_PACKAGES += \
+    device_google_cuttlefish_shared_config_init_vendor_rc \
+    device_google_cuttlefish_shared_config_init_product_rc \
+    device_google_cuttlefish_shared_config_media_files \
+    device_google_cuttlefish_shared_config_media_profiles_vendor \
+    device_google_cuttlefish_shared_config_seriallogging_rc \
+    device_google_cuttlefish_shared_config_ueventd_rc \
+    device_google_cuttlefish_shared_default_permissions_cuttlefish \
+    device_google_cuttlefish_shared_privapp_permissions_cuttlefish
+
 PRODUCT_COPY_FILES += \
-    device/google/cuttlefish/shared/config/init.product.rc:$(TARGET_COPY_OUT_PRODUCT)/etc/init/init.rc \
-    device/google/cuttlefish/shared/config/init.vendor.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.cutf_cvm.rc \
-    device/google/cuttlefish/shared/config/media_codecs_google_video.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_video.xml \
-    device/google/cuttlefish/shared/config/media_codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
-    device/google/cuttlefish/shared/config/media_codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
-    device/google/cuttlefish/shared/config/media_profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml \
-    device/google/cuttlefish/shared/config/media_profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_vendor.xml \
-    device/google/cuttlefish/shared/config/seriallogging.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/seriallogging.rc \
-    device/google/cuttlefish/shared/config/ueventd.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
-    device/google/cuttlefish/shared/permissions/privapp-permissions-cuttlefish.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/privapp-permissions-cuttlefish.xml \
     frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
     frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_telephony.xml \
     frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.ethernet.xml \
     frameworks/native/data/etc/android.hardware.usb.accessory.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.accessory.xml \
     frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml \
-    frameworks/native/data/etc/android.hardware.uwb.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.uwb.xml \
     frameworks/native/data/etc/android.hardware.wifi.direct.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.direct.xml \
     frameworks/native/data/etc/android.hardware.wifi.passpoint.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.passpoint.xml \
     frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.xml \
@@ -258,13 +246,7 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.software.verified_boot.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.verified_boot.xml \
 
 ifneq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),true)
-PRODUCT_COPY_FILES += \
-    frameworks/av/media/libeffects/data/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml \
-    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
-    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml \
-    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/surround_sound_configuration_5_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/surround_sound_configuration_5_0.xml \
-    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/usb_audio_policy_configuration.xml
+$(call inherit-product, frameworks/av/services/audiopolicy/audio_policy_config_vendor_1.mk)
 endif
 
 #
@@ -313,15 +295,18 @@ LOCAL_AUDIO_PRODUCT_PACKAGE += \
     com.android.hardware.audio
 PRODUCT_SYSTEM_EXT_PROPERTIES += \
     ro.audio.ihaladaptervendorextension_enabled=true
+PRODUCT_PRODUCT_PROPERTIES += \
+    aaudio.mmap_policy=2 \
+    aaudio.mmap_exclusive_policy=2 \
+    aaudio.hw_burst_min_usec=2000
 endif
 
 ifneq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),true)
 ifndef LOCAL_AUDIO_PRODUCT_COPY_FILES
-LOCAL_AUDIO_PRODUCT_COPY_FILES := \
-    device/google/cuttlefish/shared/config/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    device/google/cuttlefish/shared/config/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml
-LOCAL_AUDIO_PRODUCT_COPY_FILES += \
-    hardware/interfaces/audio/aidl/default/audio_effects_config.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects_config.xml
+PRODUCT_PACKAGES += device_google_cuttlefish_shared_config_audio_policy
+$(call soong_config_set_bool,cuttlefish_config,use_audio_policy,true)
+
+$(call inherit-product, hardware/interfaces/audio/aidl/default/audio_effects.mk)
 endif
 endif
 
@@ -546,17 +531,6 @@ PRODUCT_PACKAGES += \
     CuttlefishTetheringOverlay \
     CuttlefishWifiOverlay
 
-ifeq ($(PRODUCT_ENFORCE_MAC80211_HWSIM),true)
-PRODUCT_VENDOR_PROPERTIES += ro.vendor.wifi_impl=mac80211_hwsim_virtio
-$(call soong_config_append,cvdhost,enforce_mac80211_hwsim,true)
-else
-PRODUCT_VENDOR_PROPERTIES += ro.vendor.wifi_impl=virt_wifi
-endif
-
-# UWB HAL
-PRODUCT_PACKAGES += com.android.hardware.uwb
-PRODUCT_VENDOR_PROPERTIES += ro.vendor.uwb.dev=/dev/hvc9
-
 # Host packages to install
 PRODUCT_HOST_PACKAGES += socket_vsock_proxy
 
@@ -592,16 +566,51 @@ PRODUCT_PACKAGES += \
 PRODUCT_PACKAGES += \
     com.android.hardware.cas
 
+PRODUCT_PACKAGES += \
+    device_google_cuttlefish_shared_config_pci_ids
+$(call soong_config_set_bool,cuttlefish_config,use_pci_ids,true)
+
+ifneq ($(CF_VENDOR_NO_UWB), true)
+# Enable UWB
+PRODUCT_PACKAGES += \
+    cuttlefish_overlay_uwb \
+    cuttlefish_overlay_uwb_gsi
+
 PRODUCT_COPY_FILES += \
-    device/google/cuttlefish/shared/config/pci.ids:$(TARGET_COPY_OUT_VENDOR)/pci.ids
+    frameworks/native/data/etc/android.hardware.uwb.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.uwb.xml
 
+PRODUCT_PACKAGES += com.android.hardware.uwb
+PRODUCT_VENDOR_PROPERTIES += ro.vendor.uwb.dev=/dev/hvc9
+endif
+
+ifneq ($(CF_VENDOR_NO_THREADNETWORK), true)
 # Thread Network AIDL HAL and Demo App
 PRODUCT_PACKAGES += \
     com.android.hardware.threadnetwork \
     ThreadNetworkDemoApp
+endif
+
+# Enable adb debugging
+PRODUCT_PACKAGES += set_adb
+
+#
+# virtio-media utils
+#
+PRODUCT_PACKAGES += \
+    v4l2-ctl
 
 PRODUCT_CHECK_VENDOR_SEAPP_VIOLATIONS := true
 
 PRODUCT_CHECK_DEV_TYPE_VIOLATIONS := true
 
 TARGET_BOARD_FASTBOOT_INFO_FILE = device/google/cuttlefish/shared/fastboot-info.txt
+
+PRODUCT_ENFORCE_SELINUX_TREBLE_LABELING := true
+
+# Install com.google.cf.disabled APEX to demonstrate init_dev_config
+PRODUCT_PACKAGES += \
+    com.google.cf.disabled \
+    com.google.cf.init_dev_config
+
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.vendor.init_dev_config.path=/vendor/bin/init_dev_config
diff --git a/shared/graphics/device_vendor.mk b/shared/graphics/device_vendor.mk
index a44886f99..8a21b7fff 100644
--- a/shared/graphics/device_vendor.mk
+++ b/shared/graphics/device_vendor.mk
@@ -17,11 +17,10 @@
 # If a downstream target does not want any graphics support, do not
 # include this file!
 
-PRODUCT_COPY_FILES += \
-    device/google/cuttlefish/shared/config/graphics/init_graphics.vendor.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init_graphics.vendor.rc \
+PRODUCT_PACKAGES += device_google_cuttlefish_shared_config_init_graphics_vendor_rc
+$(call soong_config_set_bool,cuttlefish_config,use_init_graphics_vendor_rc,true)
 
 # Gfxstream common libraries:
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish-opengl
 PRODUCT_PACKAGES += \
     libandroidemu \
     libOpenglCodecCommon \
diff --git a/shared/overlays/core/res/values/config.xml b/shared/overlays/core/res/values/config.xml
index b9d31ed56..cd86d5fcc 100644
--- a/shared/overlays/core/res/values/config.xml
+++ b/shared/overlays/core/res/values/config.xml
@@ -27,4 +27,53 @@
     <string name="config_extensionFallbackServiceName" translatable="false">
             android.camera.extensions.impl.service.EyesFreeVidService
     </string>
+    <!-- List of country codes where oem-enabled satellite services are either allowed or disallowed
+             by the device. Each country code is a lowercase 2 character ISO-3166-1 alpha-2. -->
+    <string-array name="config_oem_enabled_satellite_country_codes">
+        <item>US</item>
+        <item>PR</item>
+        <item>CA</item>
+        <item>AU</item>
+        <item>AT</item>
+        <item>BE</item>
+        <item>BG</item>
+        <item>HR</item>
+        <item>CY</item>
+        <item>CZ</item>
+        <item>DK</item>
+        <item>EE</item>
+        <item>FI</item>
+        <item>FR</item>
+        <item>DE</item>
+        <item>GR</item>
+        <item>HU</item>
+        <item>IE</item>
+        <item>IT</item>
+        <item>LI</item>
+        <item>LV</item>
+        <item>LT</item>
+        <item>LU</item>
+        <item>NL</item>
+        <item>NO</item>
+        <item>PL</item>
+        <item>PT</item>
+        <item>RO</item>
+        <item>SK</item>
+        <item>SI</item>
+        <item>ES</item>
+        <item>SE</item>
+        <item>CH</item>
+        <item>GB</item>
+    </string-array>
+    <!-- The file storing S2-cell-based satellite access restriction of the countries defined by
+         config_oem_enabled_satellite_countries. -->
+    <string name="config_oem_enabled_satellite_s2cell_file">/vendor/etc/telephony/sats2.dat</string>
+    <!-- The absolute path to the satellite config file. -->
+    <string name="satellite_access_config_file">/vendor/etc/telephony/satellite_access_config.json</string>
+	<!-- The package name of the app to handle oem-enabled satellite SOS messaging. -->
+    <string name="config_oem_enabled_satellite_sos_handover_app">com.google.android.apps.stargate;com.google.android.apps.stargate.questionnaire.QuestionnaireHomeActivity</string>
+    <!-- The intent action to handle oem-enabled satellite SOS messaging. -->
+    <string name="config_satellite_emergency_handover_intent_action">com.google.android.apps.stargate.ACTION_ESOS_QUESTIONNAIRE</string>
+    <!-- The intent action to handle esp loopback eSOS messaging. -->
+    <string name="config_satellite_test_with_esp_replies_intent_action">com.google.android.apps.stargate.ACTION_ESOS_QUESTIONNAIRE_TEST_WITH_ESP_REPLIES</string>
 </resources>
\ No newline at end of file
diff --git a/shared/overlays/uwb/res/values/config.xml b/shared/overlays/uwb/res/values/config.xml
index 9bd3d621e..361d5cba3 100644
--- a/shared/overlays/uwb/res/values/config.xml
+++ b/shared/overlays/uwb/res/values/config.xml
@@ -15,4 +15,6 @@
 -->
 <resources>
   <bool name="is_multicast_list_update_ntf_v2_supported">true</bool>
+  <bool name="is_multicast_list_update_rsp_v2_supported">true</bool>
 </resources>
+
diff --git a/shared/permissions/Android.bp b/shared/permissions/Android.bp
index e73383939..1c9706e64 100644
--- a/shared/permissions/Android.bp
+++ b/shared/permissions/Android.bp
@@ -16,3 +16,23 @@
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_privapp_permissions_cuttlefish",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "privapp-permissions-cuttlefish.xml",
+    ],
+    vendor: true,
+    relative_install_path: "permissions",
+}
+
+prebuilt_etc {
+    name: "device_google_cuttlefish_shared_default_permissions_cuttlefish",
+    defaults: ["cuttlefish_config_general_files_defaults"],
+    srcs: [
+        "default-permissions-cuttlefish.xml",
+    ],
+    vendor: true,
+    relative_install_path: "default-permissions",
+}
diff --git a/shared/permissions/default-permissions-cuttlefish.xml b/shared/permissions/default-permissions-cuttlefish.xml
new file mode 100644
index 000000000..f40323d0c
--- /dev/null
+++ b/shared/permissions/default-permissions-cuttlefish.xml
@@ -0,0 +1,20 @@
+<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
+<!-- Copyright (C) 2025 Google Inc.
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+<exceptions>
+    <exception package="com.android.google.gce.gceservice">
+        <permission name="android.permission.BLUETOOTH_CONNECT" fixed="false"/>
+    </exception>
+</exceptions>
diff --git a/shared/permissions/privapp-permissions-cuttlefish.xml b/shared/permissions/privapp-permissions-cuttlefish.xml
index 7c3dcaa93..d33197849 100644
--- a/shared/permissions/privapp-permissions-cuttlefish.xml
+++ b/shared/permissions/privapp-permissions-cuttlefish.xml
@@ -17,12 +17,13 @@
     <privapp-permissions package="com.android.google.gce.gceservice">
         <permission name="android.permission.ACCESS_NETWORK_STATE" />
         <permission name="android.permission.ACCESS_WIFI_STATE" />
+        <permission name="android.permission.BLUETOOTH_ADMIN" />
         <permission name="android.permission.CHANGE_WIFI_STATE" />
         <permission name="android.permission.FOREGROUND_SERVICE" />
+        <permission name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />
         <permission name="android.permission.INTERNET" />
         <permission name="android.permission.RECEIVE_BOOT_COMPLETED" />
-        <permission name="android.permission.WRITE_EXTERNAL_STORAGE" />
+        <permission name="android.permission.USE_EXACT_ALARM" />
         <permission name="android.permission.WRITE_SETTINGS" />
-        <permission name="android.permission.BLUETOOTH" />
     </privapp-permissions>
 </permissions>
diff --git a/shared/sensors/device_vendor.mk b/shared/sensors/device_vendor.mk
index f497fb9b7..eedfcfd31 100644
--- a/shared/sensors/device_vendor.mk
+++ b/shared/sensors/device_vendor.mk
@@ -21,7 +21,7 @@ ifneq ($(LOCAL_SENSOR_FILE_OVERRIDES),true)
         frameworks/native/data/etc/android.hardware.sensor.ambient_temperature.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.ambient_temperature.xml \
         frameworks/native/data/etc/android.hardware.sensor.barometer.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.barometer.xml \
         frameworks/native/data/etc/android.hardware.sensor.gyroscope.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.gyroscope.xml \
-        frameworks/native/data/etc/android.hardware.sensor.hinge_angle.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.hinge_angle.xml \
+	frameworks/native/data/etc/android.hardware.sensor.hinge_angle.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.hinge_angle.xml \
         frameworks/native/data/etc/android.hardware.sensor.light.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.light.xml \
         frameworks/native/data/etc/android.hardware.sensor.proximity.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.proximity.xml \
         frameworks/native/data/etc/android.hardware.sensor.relative_humidity.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.relative_humidity.xml
@@ -39,4 +39,4 @@ PRODUCT_PACKAGES += \
     $(LOCAL_SENSOR_PRODUCT_PACKAGE)
 
 PRODUCT_PACKAGES += \
-    cuttlefish_sensor_injection
\ No newline at end of file
+    cuttlefish_sensor_injection
diff --git a/shared/sensors/multihal/entry.cpp b/shared/sensors/multihal/entry.cpp
index 88d764c6a..18f849300 100644
--- a/shared/sensors/multihal/entry.cpp
+++ b/shared/sensors/multihal/entry.cpp
@@ -18,6 +18,7 @@
 #include <multihal_sensors.h>
 #include <multihal_sensors_transport.h>
 
+#include "common/libs/fs/shared_buf.h"
 #include "common/libs/transport/channel_sharedfd.h"
 
 using ::android::hardware::sensors::V2_1::implementation::ISensorsSubHal;
@@ -29,7 +30,16 @@ class VconsoleSensorsTransport : public goldfish::SensorsTransport {
   VconsoleSensorsTransport(cuttlefish::SharedFD fd)
       : console_sensors_fd_(std::move(fd)),
         pure_sensors_fd_(console_sensors_fd_->UNMANAGED_Dup()),
-        sensors_channel_(console_sensors_fd_, console_sensors_fd_) {}
+        sensors_channel_(console_sensors_fd_, console_sensors_fd_) {
+    // When the guest reboots, sensors_simulator on the host would continue
+    // writing sensor data to FIFO till BootloaderLoaded kernel event fires. The
+    // residual sensor data in sensor FIFO could interfere with sensor HAL init
+    // process. Hence, to be safe, let's clean up the FIFO when instantiating
+    // the transport.
+    if (Drain() < 0) {
+      LOG(FATAL) << "Failed to drain FIFO: " << console_sensors_fd_->StrError();
+    }
+  }
 
   ~VconsoleSensorsTransport() override { close(pure_sensors_fd_); }
 
@@ -76,6 +86,34 @@ class VconsoleSensorsTransport : public goldfish::SensorsTransport {
     return message->payload_size;
   }
 
+  int Drain() {
+    int original_flags = console_sensors_fd_->Fcntl(F_GETFL, 0);
+    if (original_flags == -1) {
+      LOG(ERROR) << "Failed to get current file descriptor flags.";
+      return -1;
+    }
+
+    if (console_sensors_fd_->Fcntl(F_SETFL, original_flags | O_NONBLOCK) ==
+        -1) {
+      LOG(ERROR) << "Failed to set O_NONBLOCK.";
+      return -1;
+    }
+
+    std::string data;
+    if (ReadAll(console_sensors_fd_, &data) < 0 &&
+        console_sensors_fd_->GetErrno() != EAGAIN) {
+      LOG(ERROR) << "Failed to read the file.";
+      return -1;
+    }
+
+    if (console_sensors_fd_->Fcntl(F_SETFL, original_flags) == -1) {
+      LOG(ERROR) << "Failed to restore to original file descriptor flags.";
+      return -1;
+    }
+
+    return 0;
+  }
+
   bool Ok() const override { return console_sensors_fd_->IsOpen(); }
 
   int Fd() const override { return pure_sensors_fd_; }
diff --git a/shared/sepolicy/system_ext/private/file_contexts b/shared/sepolicy/system_ext/private/file_contexts
index 9499114d5..7775a6af7 100644
--- a/shared/sepolicy/system_ext/private/file_contexts
+++ b/shared/sepolicy/system_ext/private/file_contexts
@@ -9,6 +9,7 @@ is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
 /(system_ext|system/system_ext)/bin/rpmb_dev\.test\.system   u:object_r:rpmb_dev_system_exec:s0
 /(system_ext|system/system_ext)/bin/storageproxyd\.system     u:object_r:storageproxyd_system_exec:s0
 /(system_ext|system/system_ext)/bin/rpmb_dev\.wv\.system   u:object_r:rpmb_dev_wv_system_exec:s0
+/(system_ext|system/system_ext)/bin/set_adb.sh u:object_r:set_adb_exec:s0
 
 #############################
 # sockets
diff --git a/shared/sepolicy/system_ext/private/platform_app.te b/shared/sepolicy/system_ext/private/platform_app.te
index 8eb3c3af7..11cf47e91 100644
--- a/shared/sepolicy/system_ext/private/platform_app.te
+++ b/shared/sepolicy/system_ext/private/platform_app.te
@@ -6,3 +6,6 @@ set_prop(platform_app, bootanim_system_prop);
 # allow platform_app/systemui access to fingerprint
 hal_client_domain(platform_app, hal_fingerprint)
 hal_client_domain(platform_app, hal_face)
+
+# allow systemui access to bluetooth_lea_prop
+get_prop(platform_app, bluetooth_lea_prop)
diff --git a/shared/sepolicy/system_ext/private/set_adb.te b/shared/sepolicy/system_ext/private/set_adb.te
new file mode 100644
index 000000000..e66a3fa73
--- /dev/null
+++ b/shared/sepolicy/system_ext/private/set_adb.te
@@ -0,0 +1,11 @@
+type set_adb, coredomain, domain;
+type set_adb_exec, exec_type, system_file_type, file_type;
+
+init_daemon_domain(set_adb)
+
+allow set_adb shell_exec:file rx_file_perms;
+allow set_adb system_file:file execute_no_trans;
+allow set_adb servicemanager:binder call;
+allow set_adb settings_service:service_manager find;
+allow set_adb system_server:binder { call transfer };
+allow system_server set_adb:binder call;
diff --git a/shared/sepolicy/system_ext/public/file.te b/shared/sepolicy/system_ext/public/file.te
deleted file mode 100644
index 2fd615044..000000000
--- a/shared/sepolicy/system_ext/public/file.te
+++ /dev/null
@@ -1 +0,0 @@
-type ti50_char_device, dev_type;
diff --git a/shared/sepolicy/vendor/file.te b/shared/sepolicy/vendor/file.te
index c6d5ae659..e30a8ece8 100644
--- a/shared/sepolicy/vendor/file.te
+++ b/shared/sepolicy/vendor/file.te
@@ -3,3 +3,4 @@ type sysfs_iio_devices, fs_type, sysfs_type;
 type mediadrm_vendor_data_file, file_type, data_file_type;
 type mcu_control_device, dev_type;
 type mcu_uart_device, dev_type;
+type ti50_char_device, dev_type;
diff --git a/shared/sepolicy/vendor/file_contexts b/shared/sepolicy/vendor/file_contexts
index b290a629b..f6f9594eb 100644
--- a/shared/sepolicy/vendor/file_contexts
+++ b/shared/sepolicy/vendor/file_contexts
@@ -49,6 +49,9 @@
 # hvc16 for Ti50 emulator
 /dev/hvc16  u:object_r:ti50_char_device:s0
 
+# hvc17 jcardsimulator
+/dev/hvc17 u:object_r:secure_element_jcardsim_device:s0
+
 # ARM serial console device
 /dev/ttyAMA[0-9]*  u:object_r:serial_device:s0
 
@@ -118,6 +121,9 @@
 /vendor/bin/hw/android\.hardware\.authsecret-service.example u:object_r:hal_authsecret_default_exec:s0
 /vendor/bin/dlkm_loader  u:object_r:dlkm_loader_exec:s0
 /vendor/bin/init\.wifi    u:object_r:init_wifi_sh_exec:s0
+starting_at_board_api(202604, `
+    /vendor/bin/init_dev_config u:object_r:init_dev_config_exec:s0
+')
 /vendor/bin/snapshot_hook_post_resume u:object_r:snapshot_hook_sh:s0
 /vendor/bin/snapshot_hook_pre_suspend u:object_r:snapshot_hook_sh:s0
 
diff --git a/shared/sepolicy/vendor/gceservice.te b/shared/sepolicy/vendor/gceservice.te
index 57181eca8..9224cc665 100644
--- a/shared/sepolicy/vendor/gceservice.te
+++ b/shared/sepolicy/vendor/gceservice.te
@@ -5,19 +5,9 @@ app_domain(gceservice)
 # Use system services exposed as part of Android framework public API
 allow gceservice app_api_service:service_manager find;
 
-# Read and write /data/data subdirectory (for its app-private persistent data).
-allow gceservice app_data_file:dir create_dir_perms;
-allow gceservice app_data_file:{ file lnk_file } create_file_perms;
-
 # Write to kernel log (/dev/kmsg)
 allow gceservice kmsg_device:chr_file w_file_perms;
 allow gceservice kmsg_device:chr_file getattr;
 
-# Communicate with GCE Metadata Proxy over Unix domain sockets
-# The proxy process uses the default label ("kernel") because it is
-# started before Android init and thus before SELinux rule are applied.
-# TODO(b/65049764): Update once GCE metadata proxy is moved outside of the emulator or gets labelled
-allow gceservice kernel:unix_stream_socket connectto;
-
-# gceservice writes to /dev/stune/foreground/tasks
-allow gceservice cgroup:file w_file_perms;
+# Read-only vendor property access
+get_prop(gceservice, vendor_cuttlefish_service_prop)
diff --git a/shared/sepolicy/vendor/hal_keymint_strongbox.te b/shared/sepolicy/vendor/hal_keymint_strongbox.te
new file mode 100644
index 000000000..35f535f90
--- /dev/null
+++ b/shared/sepolicy/vendor/hal_keymint_strongbox.te
@@ -0,0 +1,15 @@
+type hal_keymint_strongbox, domain;
+hal_server_domain(hal_keymint_strongbox, hal_keymint)
+
+type hal_keymint_strongbox_exec, exec_type, vendor_file_type, file_type;
+init_daemon_domain(hal_keymint_strongbox)
+
+vndbinder_use(hal_keymint_strongbox)
+
+binder_call(hal_keymint_strongbox, secure_element)
+allow hal_keymint_strongbox secure_element_service:service_manager find;
+
+get_prop(hal_keymint_strongbox, vendor_security_patch_level_prop);
+get_prop(hal_keymint_strongbox, vendor_boot_security_patch_level_prop)
+get_prop(hal_keymint_strongbox, serialno_prop)
+
diff --git a/shared/sepolicy/vendor/hal_neuralnetworks_sample.te b/shared/sepolicy/vendor/hal_neuralnetworks_sample.te
index 44b5c8453..7e023f84f 100644
--- a/shared/sepolicy/vendor/hal_neuralnetworks_sample.te
+++ b/shared/sepolicy/vendor/hal_neuralnetworks_sample.te
@@ -3,3 +3,5 @@ hal_server_domain(hal_neuralnetworks_sample, hal_neuralnetworks)
 
 type hal_neuralnetworks_sample_exec, exec_type, vendor_file_type, file_type;
 init_daemon_domain(hal_neuralnetworks_sample)
+
+hal_client_domain(hal_neuralnetworks_sample, hal_graphics_allocator)
diff --git a/shared/sepolicy/vendor/hal_secure_element_jcardsim.te b/shared/sepolicy/vendor/hal_secure_element_jcardsim.te
new file mode 100644
index 000000000..015e05dc3
--- /dev/null
+++ b/shared/sepolicy/vendor/hal_secure_element_jcardsim.te
@@ -0,0 +1,18 @@
+type hal_secure_element_jcardsim, domain;
+hal_server_domain(hal_secure_element_jcardsim, hal_secure_element)
+
+type hal_secure_element_jcardsim_exec, exec_type, vendor_file_type, file_type;
+init_daemon_domain(hal_secure_element_jcardsim)
+
+type secure_element_jcardsim_device, dev_type;
+
+allow hal_secure_element_jcardsim device:dir r_dir_perms;
+allow hal_secure_element_jcardsim secure_element_jcardsim_device:chr_file rw_file_perms;
+
+# Write to kernel log (/dev/kmsg)
+allow hal_secure_element_jcardsim kmsg_device:chr_file w_file_perms;
+allow hal_secure_element_jcardsim kmsg_device:chr_file getattr;
+
+get_prop(hal_secure_element_jcardsim, vendor_security_patch_level_prop);
+get_prop(hal_secure_element_jcardsim, vendor_boot_security_patch_level_prop)
+
diff --git a/shared/sepolicy/vendor/init_dev_config.te b/shared/sepolicy/vendor/init_dev_config.te
new file mode 100644
index 000000000..b04ad44fb
--- /dev/null
+++ b/shared/sepolicy/vendor/init_dev_config.te
@@ -0,0 +1,4 @@
+starting_at_board_api(202604, `
+    # Allow setting APEX selection properties.
+    set_prop(init_dev_config, apexd_select_prop)
+')
diff --git a/shared/sepolicy/vendor/property.te b/shared/sepolicy/vendor/property.te
index ba1bf4598..a30a0b00f 100644
--- a/shared/sepolicy/vendor/property.te
+++ b/shared/sepolicy/vendor/property.te
@@ -2,6 +2,7 @@ vendor_internal_prop(vendor_modem_simulator_ports_prop)
 vendor_internal_prop(vendor_boot_security_patch_level_prop)
 vendor_internal_prop(vendor_hwcomposer_prop)
 vendor_restricted_prop(vendor_wlan_versions_prop)
+vendor_internal_prop(vendor_cuttlefish_service_prop)
 vendor_internal_prop(vendor_device_prop)
 vendor_internal_prop(vendor_uwb_prop)
 vendor_internal_prop(vendor_otsim_local_interface_prop)
diff --git a/shared/sepolicy/vendor/property_contexts b/shared/sepolicy/vendor/property_contexts
index 44a8b8761..ae62d31a5 100644
--- a/shared/sepolicy/vendor/property_contexts
+++ b/shared/sepolicy/vendor/property_contexts
@@ -2,8 +2,9 @@ ro.boot.enable_confirmationui  u:object_r:vendor_enable_confirmationui_prop:s0
 ro.boot.modem_simulator_ports  u:object_r:vendor_modem_simulator_ports_prop:s0
 ro.boot.wifi_mac_prefix  u:object_r:vendor_wifi_mac_prefix:s0 exact string
 ro.boot.vhal_proxy_server_port  u:object_r:vendor_vhal_proxy_server_port_prop:s0
-ro.vendor.wifi_impl u:object_r:vendor_wifi_impl:s0 exact string
+ro.boot.wifi_impl u:object_r:vendor_wifi_impl:s0 exact string
 ro.vendor.boot_security_patch u:object_r:vendor_boot_security_patch_level_prop:s0
+ro.vendor.cuttlefish_service_bluetooth_checker u:object_r:vendor_cuttlefish_service_prop:s0 exact bool
 ro.vendor.uwb.dev              u:object_r:vendor_uwb_prop:s0 exact string
 vendor.wlan.firmware.version   u:object_r:vendor_wlan_versions_prop:s0 exact string
 vendor.wlan.driver.version     u:object_r:vendor_wlan_versions_prop:s0 exact string
diff --git a/shared/sepolicy/vendor/service_contexts b/shared/sepolicy/vendor/service_contexts
index 03940b166..43e03e0b0 100644
--- a/shared/sepolicy/vendor/service_contexts
+++ b/shared/sepolicy/vendor/service_contexts
@@ -2,6 +2,10 @@ android.hardware.drm.IDrmFactory/widevine    u:object_r:hal_drm_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_all u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_quant    u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_sl_shim  u:object_r:hal_neuralnetworks_service:s0
+android.hardware.security.keymint.IKeyMintDevice/strongbox      u:object_r:hal_keymint_service:s0
+android.hardware.security.sharedsecret.ISharedSecret/strongbox  u:object_r:hal_sharedsecret_service:s0
+android.hardware.security.keymint.IRemotelyProvisionedComponent/strongbox u:object_r:hal_keymint_service:s0
+android.hardware.secure_element.ISecureElement/eSE1 u:object_r:hal_secure_element_service:s0
 
 # Binder service mappings
 gce                                       u:object_r:gce_service:s0
diff --git a/shared/sepolicy/system_ext/public/uevent.te b/shared/sepolicy/vendor/uevent.te
similarity index 100%
rename from shared/sepolicy/system_ext/public/uevent.te
rename to shared/sepolicy/vendor/uevent.te
diff --git a/shared/sepolicy/vendor/vendor_init.te b/shared/sepolicy/vendor/vendor_init.te
index 0122fab9a..e0438c54d 100644
--- a/shared/sepolicy/vendor/vendor_init.te
+++ b/shared/sepolicy/vendor/vendor_init.te
@@ -14,3 +14,5 @@ set_prop(vendor_init, vendor_wifi_impl)
 set_prop(vendor_init, vendor_uwb_prop)
 
 set_prop(vendor_init, vendor_boot_security_patch_level_prop)
+
+set_prop(vendor_init, vendor_cuttlefish_service_prop)
diff --git a/shared/set_adb/Android.bp b/shared/set_adb/Android.bp
new file mode 100644
index 000000000..dea81b671
--- /dev/null
+++ b/shared/set_adb/Android.bp
@@ -0,0 +1,22 @@
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
+sh_binary {
+    name: "set_adb",
+    src: "set_adb.sh",
+    system_ext_specific: true,
+    filename_from_src: true,
+    init_rc: ["set_adb.rc"],
+}
diff --git a/shared/set_adb/set_adb.rc b/shared/set_adb/set_adb.rc
new file mode 100644
index 000000000..f3a5f1f63
--- /dev/null
+++ b/shared/set_adb/set_adb.rc
@@ -0,0 +1,9 @@
+service set_adb /system_ext/bin/set_adb.sh
+    class core
+    user root
+    group shell
+    oneshot
+    disabled
+
+on sys-boot-completed-set
+    start set_adb
diff --git a/shared/set_adb/set_adb.sh b/shared/set_adb/set_adb.sh
new file mode 100644
index 000000000..67aece73f
--- /dev/null
+++ b/shared/set_adb/set_adb.sh
@@ -0,0 +1,2 @@
+#!/system/bin/sh
+settings put global adb_enabled 1
diff --git a/shared/telephony/device_vendor.mk b/shared/telephony/device_vendor.mk
index 2038ee4ad..d70f46c82 100644
--- a/shared/telephony/device_vendor.mk
+++ b/shared/telephony/device_vendor.mk
@@ -20,6 +20,15 @@ ifneq ($(TARGET_NO_TELEPHONY), true)
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
 
+# Include the package for Cuttlefish telephony satellite configurations.
+PRODUCT_PACKAGES += \
+    cuttlefish_telephony_satellite_configs
+
+# Include the Soong namespace for Cuttlefish satellite telephony configurations.
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/cuttlefish/shared/telephony/satellite
+
+
 # If downstream target provides its own RILD, set TARGET_USES_CF_RILD := false
 TARGET_USES_CF_RILD ?= true
 ifeq ($(TARGET_USES_CF_RILD),true)
diff --git a/shared/telephony/satellite/Android.bp b/shared/telephony/satellite/Android.bp
new file mode 100644
index 000000000..fad84fbf1
--- /dev/null
+++ b/shared/telephony/satellite/Android.bp
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
+soong_namespace {
+}
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc {
+    name: "cuttlefish_telephony_satellite_configs",
+    srcs: [
+        "satellite_access_config.json",
+        "sats2.dat",
+    ],
+    relative_install_path: "telephony",
+    vendor: true,
+}
diff --git a/shared/telephony/satellite/README.md b/shared/telephony/satellite/README.md
new file mode 100644
index 000000000..873e4466f
--- /dev/null
+++ b/shared/telephony/satellite/README.md
@@ -0,0 +1,8 @@
+# Geofence Data Description
+- The file `sats2.dat` contains the geofence data for the intersection of the territories of US, CA,
+PR, AU, EU and Skylo satellite coverage.
+- Please refer [here](https://googleplex-android-review.git.corp.google.com/c/device/google/cuttlefish/+/33018164/3/shared/overlays/core/res/values/config.xml#32:~:text=config_oem_enabled_satellite_country_codes) for more detail country information.
+- This data has better fidelity than previous versions.
+
+- The file `satellite_access_config.json` contains satellite information(name, position,
+band, earfcn, tagId) for each region.
\ No newline at end of file
diff --git a/shared/telephony/satellite/satellite_access_config.json b/shared/telephony/satellite/satellite_access_config.json
new file mode 100644
index 000000000..379cf2346
--- /dev/null
+++ b/shared/telephony/satellite/satellite_access_config.json
@@ -0,0 +1,231 @@
+{
+  "access_control_configs": [
+    {
+      "config_id": 0,
+      "satellite_infos": [
+        {
+          "satellite_id": "967f8e86-fc27-4673-9343-a820280a14dd",
+          "satellite_position": {
+            "longitude": 10.25,
+            "altitude": 35793.1
+          },
+          "bands": [
+            256
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229360,
+              "end_earfcn": 229360
+            },
+            {
+              "start_earfcn": 229362,
+              "end_earfcn": 229362
+            },
+            {
+              "start_earfcn": 229364,
+              "end_earfcn": 229364
+            },
+            {
+              "start_earfcn": 229366,
+              "end_earfcn": 229366
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        101
+      ]
+    },
+    {
+      "config_id": 1,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 2,
+      "satellite_infos": [
+        {
+          "satellite_id": "bd81e265-b8fb-4780-a6fb-6e6fbf5cda55",
+          "satellite_position": {
+            "longitude": 143.5,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229001,
+              "end_earfcn": 229001
+            },
+            {
+              "start_earfcn": 229003,
+              "end_earfcn": 229003
+            },
+            {
+              "start_earfcn": 229005,
+              "end_earfcn": 229005
+            },
+            {
+              "start_earfcn": 229007,
+              "end_earfcn": 229007
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        101
+      ]
+    },
+    {
+      "config_id": 3,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228837,
+              "end_earfcn": 228837
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 4,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            },
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11
+      ]
+    },
+    {
+      "config_id": 5,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        12
+      ]
+    },
+    {
+      "config_id": 6,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            },
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/shared/telephony/satellite/sats2.dat b/shared/telephony/satellite/sats2.dat
new file mode 100644
index 000000000..e0c8b546a
Binary files /dev/null and b/shared/telephony/satellite/sats2.dat differ
diff --git a/shared/virgl/device_vendor.mk b/shared/virgl/device_vendor.mk
index b4c8b3455..347eb163c 100644
--- a/shared/virgl/device_vendor.mk
+++ b/shared/virgl/device_vendor.mk
@@ -14,6 +14,5 @@
 # limitations under the License.
 #
 
-PRODUCT_SOONG_NAMESPACES += external/mesa3d
 
 PRODUCT_PACKAGES += libGLES_mesa
diff --git a/shared/wear/aosp_vendor.mk b/shared/wear/aosp_vendor.mk
index 831e7f01e..8a1ee82e8 100644
--- a/shared/wear/aosp_vendor.mk
+++ b/shared/wear/aosp_vendor.mk
@@ -33,6 +33,6 @@ PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true
 TARGET_SYSTEM_PROP += device/google/cuttlefish/shared/wear/wearable-1024.prop
 
 # Use the low memory allocator outside of eng builds to save RSS.
-ifneq (,$(filter eng, $(TARGET_BUILD_VARIANT)))
+ifeq (,$(filter eng, $(TARGET_BUILD_VARIANT)))
     MALLOC_LOW_MEMORY := true
 endif
diff --git a/shared/wear/overlays/core/res/values/config.xml b/shared/wear/overlays/core/res/values/config.xml
index 4a20b3a3f..df61b94e0 100644
--- a/shared/wear/overlays/core/res/values/config.xml
+++ b/shared/wear/overlays/core/res/values/config.xml
@@ -131,4 +131,8 @@
   <!-- Colon separated list of package names that should be granted Notification Listener access -->
   <string name="config_defaultListenerAccessPackages" translatable="false">com.google.android.wearable.media.sessions:com.google.wear.services</string>
 
+  <!-- Disable mic and camera muting on Wear CF emulator due to feature missing. -->
+  <bool name="config_supportsMicToggle">false</bool>
+  <bool name="config_supportsCamToggle">false</bool>
+
 </resources>
diff --git a/shared/x86_16kb/android-info.txt b/shared/x86_16kb/android-info.txt
new file mode 100644
index 000000000..cc7213392
--- /dev/null
+++ b/shared/x86_16kb/android-info.txt
@@ -0,0 +1,2 @@
+config=phone
+gfxstream=unsupported
diff --git a/tests/fastboot/Android.bp b/tests/fastboot/Android.bp
index 842039693..0785601fe 100644
--- a/tests/fastboot/Android.bp
+++ b/tests/fastboot/Android.bp
@@ -22,7 +22,7 @@ java_test_host {
         "src/com/android/cuttlefish/tests/FastbootRebootTest.java",
     ],
     test_suites: [
-        "device-tests",
+        "general-tests",
     ],
     libs: [
         "tradefed",
@@ -36,7 +36,7 @@ java_test_host {
         "src/com/android/cuttlefish/tests/FastbootFlashingTest.java",
     ],
     test_suites: [
-        "device-tests",
+        "general-tests",
     ],
     libs: [
         "tradefed",
@@ -50,7 +50,7 @@ java_test_host {
         "src/com/android/cuttlefish/tests/OemlockTest.java",
     ],
     test_suites: [
-        "device-tests",
+        "general-tests",
     ],
     libs: [
         "tradefed",
diff --git a/tests/graphics/display/Android.bp b/tests/graphics/display/Android.bp
index 961ac38f1..f04683ab1 100644
--- a/tests/graphics/display/Android.bp
+++ b/tests/graphics/display/Android.bp
@@ -14,6 +14,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_core_graphics_stack",
 }
 
 cc_binary {
@@ -67,3 +68,61 @@ java_test_host {
     ],
     test_config_template: "display_config_template.xml",
 }
+
+java_test_host {
+    name: "CfVkmsConnectorsTest",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
+    srcs: [
+        "CfVkmsConnectorsTest.java",
+    ],
+    static_libs: [
+        "CfVkmsTestUtils",
+    ],
+    test_options: {
+        unit_test: false,
+    },
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "compatibility-host-util",
+        "cts-tradefed",
+        "tradefed",
+    ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
+    test_config_template: "display_config_template.xml",
+}
+
+java_test_host {
+    name: "CfVkmsDisplaysTest",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
+    srcs: [
+        "CfVkmsDisplaysTest.java",
+    ],
+    static_libs: [
+        "CfVkmsTestUtils",
+    ],
+    test_options: {
+        unit_test: false,
+    },
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "compatibility-host-util",
+        "cts-tradefed",
+        "tradefed",
+    ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
+    test_config_template: "display_config_template.xml",
+}
diff --git a/tests/graphics/display/CfVkmsConnectorsTest.java b/tests/graphics/display/CfVkmsConnectorsTest.java
new file mode 100644
index 000000000..f92eb0fbb
--- /dev/null
+++ b/tests/graphics/display/CfVkmsConnectorsTest.java
@@ -0,0 +1,198 @@
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
+package com.android.cuttlefish.tests;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import java.util.ArrayList;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+/**
+ * Tests for VKMS display connector configuration and detection in Cuttlefish.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class CfVkmsConnectorsTest extends BaseHostJUnit4Test {
+    private CfVkmsTester mVkmsTester;
+    private String mSurfaceFlingerDumpsys;
+    private int mExpectedDisplayCount;
+
+    @Before
+    public void setUp() throws Exception {
+        List<CfVkmsTester.VkmsConnectorSetup> mConnectorConfigs = new ArrayList<>();
+        mConnectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.EDP)
+                .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                .setEnabledAtStart(true)
+                .build());
+        mConnectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(1)
+                .setMonitor(CfVkmsEdidHelper.DpMonitor.HP_SPECTRE32_4K_DP)
+                .build());
+        mConnectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(2)
+                .setMonitor(CfVkmsEdidHelper.HdmiMonitor.ACI_9155_ASUS_VH238_HDMI)
+                .build());
+        mConnectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(3)
+                .setMonitor(CfVkmsEdidHelper.HdmiMonitor.HWP_12447_HP_Z24i_HDMI)
+                .build());
+        mConnectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(4)
+                .setMonitor(CfVkmsEdidHelper.DpMonitor.DEL_61463_DELL_U2410_DP)
+                .build());
+        mExpectedDisplayCount = mConnectorConfigs.size();
+
+        // Initialize VKMS with our configuration
+        mVkmsTester = CfVkmsTester.createWithConfig(getDevice(), mConnectorConfigs);
+        assertNotNull("Failed to initialize VKMS tester", mVkmsTester);
+
+        // Wait for displays to be detected. UI might take some time to turn on. When on, we should
+        // expect more than 1 display.
+        long startTime = System.currentTimeMillis();
+        int displayCount = 0;
+        while (displayCount < 2 && System.currentTimeMillis() - startTime < 500) {
+            String command = "dumpsys SurfaceFlinger --displays";
+            CommandResult result = getDevice().executeShellV2Command(command);
+            assertEquals(
+                "Failed to execute dumpsys command", CommandStatus.SUCCESS, result.getStatus());
+            mSurfaceFlingerDumpsys = result.getStdout();
+            displayCount = getNumberOfDisplays(mSurfaceFlingerDumpsys);
+        }
+        assertTrue("Displays were not detected", displayCount >= 1);
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        if (mVkmsTester != null) {
+            mVkmsTester.close();
+            mVkmsTester = null;
+        }
+    }
+
+    /**
+     * Test to verify that all configured displays are detected by SurfaceFlinger.
+     * Parses the output of "dumpsys SurfaceFlinger --displays" to count the number of displays.
+     */
+    @Test
+    public void testConnectorDisplayCountCheck() throws Exception {
+        // Count the number of displays in the output
+        int displayCount = 0;
+        if (mSurfaceFlingerDumpsys != null && !mSurfaceFlingerDumpsys.isEmpty()) {
+            // Use regex to find lines starting with "Display"
+            // This pattern matches lines like "Display 0" or "Display 4621520188814754049"
+            Pattern pattern = Pattern.compile("^Display\\s+\\d+", Pattern.MULTILINE);
+            Matcher matcher = pattern.matcher(mSurfaceFlingerDumpsys);
+
+            while (matcher.find()) {
+                displayCount++;
+            }
+        }
+
+        // Log the output for debugging
+        CLog.i("Found %d displays in SurfaceFlinger", displayCount);
+
+        // Verify the number of displays matches the expected count
+        assertEquals("Number of displays does not match expected count", mExpectedDisplayCount,
+            displayCount);
+    }
+
+    /**
+     * Test to verify that all expected display names are present in the SurfaceFlinger output.
+     * Parses the output of "dumpsys SurfaceFlinger --displays" to extract display names.
+     */
+    @Test
+    public void testConnectorDisplayNamesCheck() throws Exception {
+        // Define expected display names based on the configured monitors
+        Set<String> expectedDisplayNames = new HashSet<>();
+        expectedDisplayNames.add("Primary display");
+        expectedDisplayNames.add("HP Spectre 32");
+        expectedDisplayNames.add("ASUS VH238");
+        expectedDisplayNames.add("HP Z24i");
+        expectedDisplayNames.add("DELL U2410");
+
+        // Extract display names from the output
+        Set<String> actualDisplayNames = new HashSet<>();
+        if (mSurfaceFlingerDumpsys != null && !mSurfaceFlingerDumpsys.isEmpty()) {
+            // Pattern to match name="DisplayName" in the output
+            Pattern pattern = Pattern.compile("name=\"([^\"]*)\"", Pattern.MULTILINE);
+            Matcher matcher = pattern.matcher(mSurfaceFlingerDumpsys);
+
+            while (matcher.find()) {
+                actualDisplayNames.add(matcher.group(1));
+            }
+        }
+
+        // Log the found display names for debugging
+        CLog.i("Found display names: %s", actualDisplayNames);
+
+        // Verify that all expected display names are present
+        for (String expectedName : expectedDisplayNames) {
+            boolean found = false;
+            for (String actualName : actualDisplayNames) {
+                if (actualName.contains(expectedName)) {
+                    found = true;
+                    break;
+                }
+            }
+            assertTrue("Expected display name not found: " + expectedName, found);
+        }
+
+        // Verify the count matches
+        assertEquals("Number of displays does not match expected count",
+            expectedDisplayNames.size(), actualDisplayNames.size());
+    }
+
+    private int getNumberOfDisplays(String dumpsysOutput) {
+        int displayCount = 0;
+        if (dumpsysOutput != null && !dumpsysOutput.isEmpty()) {
+            // Use regex to find lines starting with "Display"
+            // This pattern matches lines like "Display 0" or "Display 4621520188814754049"
+            Pattern pattern = Pattern.compile("^Display\\s+\\d+", Pattern.MULTILINE);
+            Matcher matcher = pattern.matcher(dumpsysOutput);
+
+            while (matcher.find()) {
+                displayCount++;
+            }
+        }
+        return displayCount;
+    }
+}
diff --git a/tests/graphics/display/CfVkmsDisplaysTest.java b/tests/graphics/display/CfVkmsDisplaysTest.java
new file mode 100644
index 000000000..ff0168fdb
--- /dev/null
+++ b/tests/graphics/display/CfVkmsDisplaysTest.java
@@ -0,0 +1,643 @@
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
+package com.android.cuttlefish.tests;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+/**
+ * Tests for VKMS display ID uniqueness and related properties in Cuttlefish.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class CfVkmsDisplaysTest extends BaseHostJUnit4Test {
+    private CfVkmsTester mVkmsTester;
+
+    private static class DisplayInfo {
+        public String id;
+        public String hwcId;
+        public String port;
+        public String pnpId;
+        public String displayName;
+
+        @Override
+        public String toString() {
+            return String.format(
+                "ID=%s, HWC=%s, port=%s, pnpId=%s, name=%s", id, hwcId, port, pnpId, displayName);
+        }
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        if (mVkmsTester != null) {
+            mVkmsTester.close();
+            mVkmsTester = null;
+        }
+    }
+
+    /**
+     * Test to verify that all display IDs are unique.
+     * Parses the output of "dumpsys SurfaceFlinger --display-id" to extract display IDs.
+     */
+    @Test
+    public void testDisplayIdsAreUnique() throws Exception {
+        // Setup the VKMS configuration for this test
+        List<CfVkmsTester.VkmsConnectorSetup> connectorConfigs = new ArrayList<>();
+        connectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.EDP)
+                .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                .setEnabledAtStart(true)
+                .build());
+        connectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(1)
+                .setMonitor(CfVkmsEdidHelper.DpMonitor.HP_SPECTRE32_4K_DP)
+                .build());
+        connectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(2)
+                .setMonitor(CfVkmsEdidHelper.HdmiMonitor.ACI_9155_ASUS_VH238_HDMI)
+                .build());
+        connectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(3)
+                .setMonitor(CfVkmsEdidHelper.HdmiMonitor.HWP_12447_HP_Z24i_HDMI)
+                .build());
+        connectorConfigs.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                .setEnabledAtStart(true)
+                .setAdditionalOverlayPlanes(4)
+                .setMonitor(CfVkmsEdidHelper.DpMonitor.DEL_61463_DELL_U2410_DP)
+                .build());
+
+        // Initialize VKMS with our configuration
+        mVkmsTester = CfVkmsTester.createWithConfig(getDevice(), connectorConfigs);
+        assertNotNull("Failed to initialize VKMS tester", mVkmsTester);
+
+        waitForUiToBeOn(connectorConfigs.size());
+        String command = "dumpsys SurfaceFlinger --display-id";
+        CommandResult result = getDevice().executeShellV2Command(command);
+        assertEquals(
+            "Failed to execute dumpsys command", CommandStatus.SUCCESS, result.getStatus());
+        List<DisplayInfo> displays = parseDisplayInfo(result.getStdout());
+        // Verify we have the expected number of displays
+        assertEquals("Number of displays does not match expected count", connectorConfigs.size(),
+            displays.size());
+
+        // Check that all display IDs are unique
+        Set<String> displayIds = new HashSet<>();
+        for (DisplayInfo info : displays) {
+            boolean wasAdded = displayIds.add(info.id);
+            assertTrue("Display ID is not unique: " + info.id, wasAdded);
+        }
+    }
+
+    /**
+     * Test to verify that the same monitor maintains the same display ID across different
+     * configurations. This ensures that the display ID is determined by the monitor's EDID
+     * rather than by connection order or port number.
+     */
+    @Test
+    public void testDisplayIdConsistencyAtDifferentPorts() throws Exception {
+        // We'll use the HP Spectre 32 as our reference monitor to track across configurations
+        CfVkmsEdidHelper.Monitor referenceMonitor = CfVkmsEdidHelper.DpMonitor.HP_SPECTRE32_4K_DP;
+        String referenceDisplayName = "HP Spectre 32";
+
+        // Map to store the display ID for each configuration
+        Map<String, String> displayIdsByConfig = new HashMap<>();
+
+        // Test multiple configurations
+        String configName = "unknown";
+        try {
+            // First configuration: Just the reference monitor
+            configName = "single_display";
+            List<CfVkmsTester.VkmsConnectorSetup> config = new ArrayList<>();
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            String displayId =
+                testConfigurationAndGetDisplayId(config, referenceDisplayName, configName);
+            displayIdsByConfig.put(configName, displayId);
+
+            // Second configuration: Reference monitor in second position
+            configName = "second_position";
+            config = new ArrayList<>();
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.EDP)
+                    .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                    .setEnabledAtStart(true)
+                    .build());
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            displayId = testConfigurationAndGetDisplayId(config, referenceDisplayName, configName);
+            displayIdsByConfig.put(configName, displayId);
+
+            // Third configuration: Reference monitor with different connector type
+            configName = "different_connector";
+            config = new ArrayList<>();
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            displayId = testConfigurationAndGetDisplayId(config, referenceDisplayName, configName);
+            displayIdsByConfig.put(configName, displayId);
+
+            // Fourth configuration: Many displays including reference
+            configName = "many_displays";
+            config = new ArrayList<>();
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.EDP)
+                    .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                    .setEnabledAtStart(true)
+                    .build());
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                    .setMonitor(CfVkmsEdidHelper.HdmiMonitor.ACI_9155_ASUS_VH238_HDMI)
+                    .setEnabledAtStart(true)
+                    .build());
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                    .setMonitor(CfVkmsEdidHelper.HdmiMonitor.HWP_12447_HP_Z24i_HDMI)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            displayId = testConfigurationAndGetDisplayId(config, referenceDisplayName, configName);
+            displayIdsByConfig.put(configName, displayId);
+        } catch (Exception e) {
+            CLog.e("Exception during configuration %s: %s", configName, e.toString());
+            throw e;
+        }
+
+        // Verify all display IDs for the reference monitor are the same
+        CLog.i("Display IDs by configuration:");
+        String referenceId = null;
+        for (Map.Entry<String, String> entry : displayIdsByConfig.entrySet()) {
+            CLog.i("  %s: %s", entry.getKey(), entry.getValue());
+            if (referenceId == null) {
+                referenceId = entry.getValue();
+            } else {
+                assertEquals("Display ID should be consistent across configurations", referenceId,
+                    entry.getValue());
+            }
+        }
+    }
+
+    /**
+     * Test to verify that identical monitors (same EDID) still receive unique display IDs.
+     * This tests the collision handling in Android's display ID generation system.
+     */
+    @Test
+    public void testIdenticalMonitorsGetUniqueIds() throws Exception {
+        // Use the HP Spectre 32 monitor for our test
+        CfVkmsEdidHelper.Monitor referenceMonitor = CfVkmsEdidHelper.DpMonitor.HP_SPECTRE32_4K_DP;
+        String referenceDisplayName = "HP Spectre 32";
+
+        // Create a configuration with multiple identical monitors
+        List<CfVkmsTester.VkmsConnectorSetup> collisionConfig = new ArrayList<>();
+
+        // Add three identical monitors on different ports
+        // First on DisplayPort
+        collisionConfig.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                .setMonitor(referenceMonitor)
+                .setEnabledAtStart(true)
+                .build());
+
+        // Second on HDMI-A
+        collisionConfig.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                .setMonitor(referenceMonitor)
+                .setEnabledAtStart(true)
+                .build());
+
+        // Third on HDMI-B
+        collisionConfig.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                .setType(CfVkmsTester.ConnectorType.HDMI_B)
+                .setMonitor(referenceMonitor)
+                .setEnabledAtStart(true)
+                .build());
+
+        // Initialize VKMS with our collision test configuration
+        try {
+            mVkmsTester = CfVkmsTester.createWithConfig(getDevice(), collisionConfig);
+            assertNotNull("Failed to initialize VKMS for collision test", mVkmsTester);
+            waitForUiToBeOn(collisionConfig.size());
+
+            // Get all displays with the reference name
+            List<String> identicalDisplayIds = getDisplayIdsForName(referenceDisplayName);
+
+            // Log what we found
+            CLog.i("Found %d displays with name '%s'", identicalDisplayIds.size(),
+                referenceDisplayName);
+            for (int i = 0; i < identicalDisplayIds.size(); i++) {
+                CLog.i("  Display #%d ID: %s", i + 1, identicalDisplayIds.get(i));
+            }
+
+            // Verify that we found the expected number of displays
+            assertEquals("Number of identical displays does not match expected count", 3,
+                identicalDisplayIds.size());
+
+            // Verify that all display IDs are unique even for identical monitors
+            Set<String> uniqueIds = new HashSet<>(identicalDisplayIds);
+            assertEquals("Identical monitors should still get unique display IDs",
+                identicalDisplayIds.size(), uniqueIds.size());
+        } finally {
+            if (mVkmsTester != null) {
+                mVkmsTester.close();
+                mVkmsTester = null;
+            }
+        }
+    }
+
+    /**
+     * Test to verify that a display maintains the same display ID when connected
+     * to the same port (index) across different configurations.
+     */
+    @Test
+    public void testDisplayIdConsistencyAtSamePort() throws Exception {
+        // We'll use the HP Spectre 32 as our reference monitor to track across configurations
+        CfVkmsEdidHelper.Monitor referenceMonitor = CfVkmsEdidHelper.DpMonitor.HP_SPECTRE32_4K_DP;
+        String referenceDisplayName = "HP Spectre 32";
+
+        // The constant port position for our reference monitor (index 1, which is the second
+        // position)
+        final int referencePortIndex = 1;
+
+        // Map to store the display ID for each configuration
+        Map<String, String> displayIdsByConfig = new HashMap<>();
+
+        // Test multiple configurations
+        String configName = "unknown";
+        try {
+            // Configuration 1: Two displays with reference at port index 1
+            configName = "two_displays";
+            List<CfVkmsTester.VkmsConnectorSetup> config = new ArrayList<>();
+
+            // First display (port 0)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.EDP)
+                    .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Reference display at port 1
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            String displayId = testConfigurationAndGetDisplayIdAtPort(
+                config, referenceDisplayName, configName, referencePortIndex);
+            displayIdsByConfig.put(configName, displayId);
+
+            // Configuration 2: Three displays with reference at port index 1
+            configName = "three_displays";
+            config = new ArrayList<>();
+
+            // First display (port 0)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(CfVkmsEdidHelper.DpMonitor.DEL_61463_DELL_U2410_DP)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Reference display at port 1
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT) // Same type
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Third display (port 2)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                    .setMonitor(CfVkmsEdidHelper.HdmiMonitor.ACI_9155_ASUS_VH238_HDMI)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            displayId = testConfigurationAndGetDisplayIdAtPort(
+                config, referenceDisplayName, configName, referencePortIndex);
+            displayIdsByConfig.put(configName, displayId);
+
+            // Configuration 3: Four displays with reference at port index 1 with different
+            // connector type
+            configName = "four_displays_different_connector";
+            config = new ArrayList<>();
+
+            // First display (port 0)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A)
+                    .setMonitor(CfVkmsEdidHelper.HdmiMonitor.HWP_12447_HP_Z24i_HDMI)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Reference display at port 1 (different connector type from previous configs)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.HDMI_A) // Different connector type
+                    .setMonitor(referenceMonitor)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Third display (port 2)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.DISPLAY_PORT)
+                    .setMonitor(CfVkmsEdidHelper.DpMonitor.ACI_9713_ASUS_VE258_DP)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            // Fourth display (port 3)
+            config.add(CfVkmsTester.VkmsConnectorSetup.builder()
+                    .setType(CfVkmsTester.ConnectorType.EDP)
+                    .setMonitor(CfVkmsEdidHelper.EdpDisplay.REDRIX)
+                    .setEnabledAtStart(true)
+                    .build());
+
+            displayId = testConfigurationAndGetDisplayIdAtPort(
+                config, referenceDisplayName, configName, referencePortIndex);
+            displayIdsByConfig.put(configName, displayId);
+
+        } catch (Exception e) {
+            CLog.e("Exception during configuration %s: %s", configName, e.toString());
+            throw e;
+        }
+
+        // Verify all display IDs for the reference monitor at the same port are the same
+        CLog.i("Display IDs by configuration (reference at port %d):", referencePortIndex);
+        String referenceId = null;
+        for (Map.Entry<String, String> entry : displayIdsByConfig.entrySet()) {
+            CLog.i("  %s: %s", entry.getKey(), entry.getValue());
+            if (referenceId == null) {
+                referenceId = entry.getValue();
+            } else {
+                assertEquals("Display ID should be consistent at the same port", referenceId,
+                    entry.getValue());
+            }
+        }
+    }
+
+    /**
+     * Parses the output of "dumpsys SurfaceFlinger --display-id" to extract display information.
+     *
+     * Example output:
+     * Display 0 (HWC display 0): invalid EDID
+     * Display 4621520188814754049 (HWC display 1): port=1 pnpId=HWP displayName="HP Spectre 32"
+     *
+     * @param output The output of the dumpsys command
+     * @return A list of DisplayInfo objects containing the parsed information
+     */
+    private List<DisplayInfo> parseDisplayInfo(String output) {
+        List<DisplayInfo> result = new ArrayList<>();
+
+        if (output == null || output.isEmpty()) {
+            return result;
+        }
+
+        // This pattern matches the display ID line format
+        Pattern pattern =
+            Pattern.compile("Display (\\d+|\\w+) \\(HWC display (\\d+)\\): (?:port=(\\d+) "
+                    + "pnpId=(\\w+) displayName=\"([^\"]+)\"|.*)",
+                Pattern.MULTILINE);
+
+        Matcher matcher = pattern.matcher(output);
+
+        while (matcher.find()) {
+            DisplayInfo info = new DisplayInfo();
+            info.id = matcher.group(1);
+            info.hwcId = matcher.group(2);
+
+            // The port, pnpId, and displayName may not be present for all displays (e.g., invalid
+            // EDID)
+            if (matcher.groupCount() >= 5 && matcher.group(3) != null) {
+                info.port = matcher.group(3);
+                info.pnpId = matcher.group(4);
+                info.displayName = matcher.group(5);
+            }
+
+            result.add(info);
+        }
+
+        return result;
+    }
+
+    /**
+     * Tests a specific display configuration and returns the display ID for a given display name.
+     *
+     * @param config The VKMS connector configuration to test
+     * @param displayName The display name to look for
+     * @param configName A name for this configuration (for logging)
+     * @return The display ID for the given display name
+     * @throws Exception If an error occurs during testing
+     */
+    private String testConfigurationAndGetDisplayId(List<CfVkmsTester.VkmsConnectorSetup> config,
+        String displayName, String configName) throws Exception {
+        CLog.i("Testing configuration: %s", configName);
+
+        CfVkmsTester tester = null;
+        try {
+            tester = CfVkmsTester.createWithConfig(getDevice(), config);
+            assertNotNull("Failed to initialize VKMS configuration: " + configName, tester);
+            waitForUiToBeOn(config.size());
+            // Get the display ID for our reference monitor
+            String displayId = getDisplayIdForName(displayName);
+            assertNotNull(
+                "Display ID not found for " + displayName + " in config: " + configName, displayId);
+            return displayId;
+        } finally {
+            if (tester != null) {
+                tester.close();
+            }
+        }
+    }
+
+    /**
+     * Helper method to get the display ID for a display with a specific name.
+     *
+     * @param displayName The name of the display to find
+     * @return The display ID, or null if not found
+     * @throws Exception If there's an error executing the command
+     */
+    private String getDisplayIdForName(String displayName) throws Exception {
+        // Run the command to get display IDs
+        String command = "dumpsys SurfaceFlinger --display-id";
+        CommandResult result = getDevice().executeShellV2Command(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to execute dumpsys command: %s", result.getStderr());
+            return null;
+        }
+
+        // Parse the output
+        List<DisplayInfo> displays = parseDisplayInfo(result.getStdout());
+
+        // Find the display with the matching name
+        for (DisplayInfo info : displays) {
+            if (info.displayName != null && info.displayName.contains(displayName)) {
+                return info.id;
+            }
+        }
+
+        return null;
+    }
+
+    /**
+     * Helper method to get all display IDs for displays with a specific name.
+     *
+     * @param displayName The display name to find
+     * @return A list of display IDs for displays with the given name
+     * @throws Exception If there's an error executing the command
+     */
+    private List<String> getDisplayIdsForName(String displayName) throws Exception {
+        List<String> displayIds = new ArrayList<>();
+
+        // Run the command to get display IDs
+        String command = "dumpsys SurfaceFlinger --display-id";
+        CommandResult result = getDevice().executeShellV2Command(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to execute dumpsys command: %s", result.getStderr());
+            return displayIds;
+        }
+
+        // Parse the output
+        List<DisplayInfo> displays = parseDisplayInfo(result.getStdout());
+
+        // Find all displays with the matching name
+        for (DisplayInfo info : displays) {
+            if (info.displayName != null && info.displayName.contains(displayName)) {
+                displayIds.add(info.id);
+            }
+        }
+
+        return displayIds;
+    }
+
+    /**
+     * Tests a specific display configuration and returns the display ID for the display at a given
+     * port.
+     *
+     * @param config The VKMS connector configuration to test
+     * @param displayName The display name to look for
+     * @param configName A name for this configuration (for logging)
+     * @param portIndex The port index to check
+     * @return The display ID for the display at the given port
+     * @throws Exception If an error occurs during testing
+     */
+    private String testConfigurationAndGetDisplayIdAtPort(
+        List<CfVkmsTester.VkmsConnectorSetup> config, String displayName, String configName,
+        int portIndex) throws Exception {
+        CLog.i("Testing configuration: %s (reference at port %d)", configName, portIndex);
+
+        CfVkmsTester tester = null;
+        try {
+            tester = CfVkmsTester.createWithConfig(getDevice(), config);
+            assertNotNull("Failed to initialize VKMS configuration: " + configName, tester);
+            waitForUiToBeOn(config.size());
+
+            // Run the command to get display IDs
+            String command = "dumpsys SurfaceFlinger --display-id";
+            CommandResult result = getDevice().executeShellV2Command(command);
+            assertEquals(
+                "Failed to execute dumpsys command", CommandStatus.SUCCESS, result.getStatus());
+
+            // Parse the output to extract display IDs
+            List<DisplayInfo> displays = parseDisplayInfo(result.getStdout());
+
+            // Log the output for debugging
+            CLog.i(
+                "Found %d displays in SurfaceFlinger for config %s", displays.size(), configName);
+            for (DisplayInfo info : displays) {
+                CLog.i("Display: %s", info);
+            }
+
+            // Find the display with the matching name and port
+            for (DisplayInfo info : displays) {
+                if (info.displayName != null && info.displayName.contains(displayName)) {
+                    // Verify this is the correct port (HWC IDs generally match port indices + 1)
+                    int hwcPortIndex = Integer.parseInt(info.hwcId) - 1;
+                    if (hwcPortIndex == portIndex) {
+                        return info.id;
+                    }
+                }
+            }
+
+            // If we didn't find the display with matching port, look by name only
+            String displayId = getDisplayIdForName(displayName);
+            assertNotNull(
+                "Display ID not found for " + displayName + " in config: " + configName, displayId);
+            return displayId;
+        } finally {
+            if (tester != null) {
+                tester.close();
+            }
+        }
+    }
+
+    /**
+     * Helper method to wait for displays to turn on by periodically checking SurfaceFlinger.
+     *
+     * @param minimumExpectedDisplays The minimum number of displays expected to be detected
+     * @throws Exception If an error occurs while executing shell commands
+     */
+    private void waitForUiToBeOn(int minimumExpectedDisplays) throws Exception {
+        long startTime = System.currentTimeMillis();
+        List<DisplayInfo> displays = new ArrayList<>();
+        while (displays.size() < minimumExpectedDisplays
+            && System.currentTimeMillis() - startTime < 500) {
+            String command = "dumpsys SurfaceFlinger --display-id";
+            CommandResult result = getDevice().executeShellV2Command(command);
+            assertEquals(
+                "Failed to execute dumpsys command", CommandStatus.SUCCESS, result.getStatus());
+            displays = parseDisplayInfo(result.getStdout());
+        }
+    }
+}
diff --git a/tests/graphics/display/display_config_template.xml b/tests/graphics/display/display_config_template.xml
index c28eed247..e5bbac5b2 100644
--- a/tests/graphics/display/display_config_template.xml
+++ b/tests/graphics/display/display_config_template.xml
@@ -23,6 +23,8 @@
 
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
         <option name="run-command" value="stop" />
+        <option name="run-command" value="stop vendor.hwcomposer-3" />
+        <option name="teardown-command" value="start vendor.hwcomposer-3" />
         <option name="teardown-command" value="start" />
     </target_preparer>
 
diff --git a/tests/graphics/display/utils/Android.bp b/tests/graphics/display/utils/Android.bp
new file mode 100644
index 000000000..524df74c3
--- /dev/null
+++ b/tests/graphics/display/utils/Android.bp
@@ -0,0 +1,27 @@
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
+java_library_host {
+    name: "CfVkmsTestUtils",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
+    srcs: [
+        "CfVkmsEdidHelper.java",
+        "CfVkmsTester.java",
+    ],
+    libs: [
+        "tradefed",
+    ],
+}
diff --git a/tests/graphics/display/utils/CfVkmsEdidHelper.java b/tests/graphics/display/utils/CfVkmsEdidHelper.java
new file mode 100644
index 000000000..b0e5da458
--- /dev/null
+++ b/tests/graphics/display/utils/CfVkmsEdidHelper.java
@@ -0,0 +1,252 @@
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
+package com.android.cuttlefish.tests;
+
+import com.android.tradefed.log.LogUtil.CLog;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Map;
+
+public final class CfVkmsEdidHelper {
+    private CfVkmsEdidHelper() {}
+
+    public interface Monitor {
+        byte[] getBinaryEdid();
+    }
+
+    public enum EdpDisplay implements Monitor {
+        REDRIX("00ffffffffffff0009e5760a00000000"
+            + "191f0104a51c137803ee95a3544c9926"
+            + "0f505400000001010101010101010101"
+            + "010101010101125cd01881e02d503020"
+            + "36001dbe1000001a623dd01881e02d50"
+            + "302036001dbe1000001a000000000000"
+            + "00000000000000000000000000000002"
+            + "000d28ff0a3cc80f0b23c800000000cc");
+
+        private final String edidHex;
+
+        EdpDisplay(String edidHex) {
+            this.edidHex = edidHex;
+        }
+
+        @Override
+        public byte[] getBinaryEdid() {
+            return hexStringToBinary(edidHex);
+        }
+    }
+
+    public enum DpMonitor implements Monitor {
+        ACI_9713_ASUS_VE258_DP("00ffffffffffff000469f125f3c60100"
+            + "1d150104a5371f783a7695a5544ba226"
+            + "115054bfef00714f81c0814081809500"
+            + "950fb300d1c0023a801871382d40582c"
+            + "450029372100001e000000ff0042374c"
+            + "4d54463131363436370a000000fd0032"
+            + "4b185311041100f0f838f03c000000fc"
+            + "00415355532056453235380a202001b7"
+            + "020322714f0102031112130414051f90"
+            + "0e0f1d1e2309170783010000656e0c00"
+            + "10008c0ad08a20e02d10103e96002937"
+            + "21000018011d007251d01e206e285500"
+            + "29372100001e011d00bc52d01e20b828"
+            + "554029372100001e8c0ad09020403120"
+            + "0c405500293721000018000000000000"
+            + "000000000000000000000000000000aa"),
+
+        DEL_61463_DELL_U2410_DP("00ffffffffffff0010ac17f04c334a31"
+            + "08150104b53420783a1ec5ae4f34b126"
+            + "0e5054a54b008180a940d100714f0101"
+            + "010101010101283c80a070b023403020"
+            + "360006442100001a000000ff00463532"
+            + "354d313247314a334c0a000000fc0044"
+            + "454c4c2055323431300a2020000000fd"
+            + "00384c1e5111000a20202020202001ff"
+            + "02031df15090050403020716011f1213"
+            + "14201511062309070783010000023a80"
+            + "1871382d40582c450006442100001e01"
+            + "1d8018711c1620582c25000644210000"
+            + "9e011d007251d01e206e285500064421"
+            + "00001e8c0ad08a20e02d10103e960006"
+            + "44210000180000000000000000000000"
+            + "00000000000000000000000000000021"),
+
+        HP_SPECTRE32_4K_DP("00ffffffffffff0022F01A3200000000"
+            + "2E180104B54728783A87D5A8554D9F25"
+            + "0E5054210800D1C0A9C081C0D100B300"
+            + "9500A94081804DD000A0F0703E803020"
+            + "3500C48F2100001A000000FD00183C1E"
+            + "873C000A202020202020000000FC0048"
+            + "502053706563747265203332000000FF"
+            + "00434E43393430303030310A2020018F"
+            + "020318F14B101F041303120211010514"
+            + "2309070783010000A36600A0F0701F80"
+            + "30203500C48F2100001A565E00A0A0A0"
+            + "295030203500C48F2100001AEF5100A0"
+            + "F070198030203500C48F2100001AB339"
+            + "00A080381F4030203A00C48F2100001A"
+            + "283C80A070B0234030203600C48F2100"
+            + "001A00000000000000000000000000C4"),
+
+        HWP_12446_HP_Z24i_DP("00ffffffffffff0022f09e3000000000"
+            + "15180104a5342078264ca5a7554da226"
+            + "105054a10800b30095008100a9408180"
+            + "d1c081c00101283c80a070b023403020"
+            + "360006442100001a000000fd00324c18"
+            + "5e11000a202020202020000000fc0048"
+            + "50205a3234690a2020202020000000ff"
+            + "00434e343432313050334b0a2020006f");
+
+        private final String edidHex;
+
+        DpMonitor(String edidHex) {
+            this.edidHex = edidHex;
+        }
+
+        @Override
+        public byte[] getBinaryEdid() {
+            return hexStringToBinary(edidHex);
+        }
+    }
+
+    public enum HdmiMonitor implements Monitor {
+        ACI_9155_ASUS_VH238_HDMI("00ffffffffffff000469c323fccc0000"
+            + "2017010380331d782add45a3554fa027"
+            + "125054bfef00714f814081809500b300"
+            + "d1c001010101023a801871382d40582c"
+            + "4500fd1e1100001e000000ff0044384c"
+            + "4d54463035323437360a000000fd0032"
+            + "4b1e5011000a202020202020000000fc"
+            + "00415355532056483233380a202000be"),
+
+        DEL_61462_DELL_U2410_HDMI("00ffffffffffff0010ac16f04c4e4332"
+            + "1f13010380342078ea1ec5ae4f34b126"
+            + "0e5054a54b008180a940d100714f0101"
+            + "010101010101283c80a070b023403020"
+            + "360006442100001a000000ff00463532"
+            + "354d39375332434e4c0a000000fc0044"
+            + "454c4c2055323431300a2020000000fd"
+            + "00384c1e5111000a202020202020012e"
+            + "020329f15090050403020716011f1213"
+            + "14201511062309070767030c00100038"
+            + "2d83010000e3050301023a801871382d"
+            + "40582c450006442100001e011d801871"
+            + "1c1620582c250006442100009e011d00"
+            + "7251d01e206e28550006442100001e8c"
+            + "0ad08a20e02d10103e96000644210000"
+            + "1800000000000000000000000000003e"),
+
+        HP_SPECTRE32_4K_HDMI("00ffffffffffff0022f01c3201010101"
+            + "04190103804728782a87d5a8554d9f25"
+            + "0e5054210800d1c0a9c081c0d100b300"
+            + "9500a94081804dd000a0f0703e803020"
+            + "3500c48f2100001a000000fd00183c1b"
+            + "873c000a202020202020000000fc0048"
+            + "702053706563747265203332000000ff"
+            + "00434e43393430303030310a202001fb"
+            + "02033df15361605f5d101f0413031202"
+            + "11010514070616152309070783010000"
+            + "6c030c001000383c200040010367d85d"
+            + "c401788000e40f030000e2002b047400"
+            + "30f2705a80b0588a00c48f2100001a56"
+            + "5e00a0a0a0295030203500c48f210000"
+            + "1eef5100a0f070198030203500c48f21"
+            + "00001e000000000000000000000000a8"),
+
+        HWP_12447_HP_Z24i_HDMI("00ffffffffffff0022f09f3001010101"
+            + "1a180103803420782e3c50a7544da226"
+            + "105054a1080081009500b3008180a940"
+            + "81c0d1c00101283c80a070b023403020"
+            + "360006442100001a000000fd00324c18"
+            + "5e11000a202020202020000000fc0048"
+            + "50205a3234690a2020202020000000ff"
+            + "00434e4b343236304c47320a202000d6");
+
+        private final String edidHex;
+
+        HdmiMonitor(String edidHex) {
+            this.edidHex = edidHex;
+        }
+
+        @Override
+        public byte[] getBinaryEdid() {
+            return hexStringToBinary(edidHex);
+        }
+    }
+
+    /**
+     * Convert a hex string to binary data.
+     *
+     * @param hexString The hex string to convert
+     * @return The binary data as a byte array
+     */
+    private static byte[] hexStringToBinary(String hexString) {
+        int len = hexString.length();
+
+        byte[] data = new byte[len / 2];
+
+        for (int i = 0; i < len; i += 2) {
+            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
+                + Character.digit(hexString.charAt(i + 1), 16));
+        }
+
+        return data;
+    }
+
+    /**
+     * Utility method to get the hex string representation of EDID data.
+     *
+     * @param monitor The monitor to get EDID hex string from
+     * @return The EDID data as a hex string
+     */
+    public static String getEdidHexString(Monitor monitor) {
+        if (monitor == null) {
+            return null;
+        }
+
+        byte[] edidData = monitor.getBinaryEdid();
+        StringBuilder hexString = new StringBuilder();
+        for (byte b : edidData) {
+            hexString.append(String.format("%02x", b));
+        }
+        return hexString.toString();
+    }
+
+    /**
+     * Formats EDID data for use in a printf shell command with proper hex escaping.
+     *
+     * @param monitor The monitor to get EDID data from
+     * @return A string with escaped hex values for use in printf
+     */
+    public static String getEdidForPrintf(Monitor monitor) {
+        if (monitor == null) {
+            return null;
+        }
+
+        byte[] edidData = monitor.getBinaryEdid();
+        if (edidData == null || edidData.length == 0) {
+            return null;
+        }
+
+        StringBuilder hexDump = new StringBuilder();
+        for (byte b : edidData) {
+            hexDump.append(String.format("\\\\x%02x", b & 0xFF));
+        }
+
+        return hexDump.toString();
+    }
+}
diff --git a/tests/graphics/display/utils/CfVkmsTester.java b/tests/graphics/display/utils/CfVkmsTester.java
new file mode 100644
index 000000000..55b86a6aa
--- /dev/null
+++ b/tests/graphics/display/utils/CfVkmsTester.java
@@ -0,0 +1,665 @@
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
+package com.android.cuttlefish.tests;
+
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import java.io.Closeable;
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.Base64;
+import java.util.EnumMap;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Manages setup and configuration of Virtual KMS (VKMS) for display emulation
+ * through shell commands. Provides an interface for creating and managing
+ * displays in CF
+ */
+public class CfVkmsTester implements Closeable {
+    private static final String VKMS_BASE_DIR = "/config/vkms/my-vkms";
+
+    // DRM resource types
+    private enum DrmResource {
+        CONNECTOR("connectors/CON_"),
+        CRTC("crtcs/CRTC_"),
+        ENCODER("encoders/ENC_"),
+        PLANE("planes/PLA_");
+
+        private final String basePath;
+
+        DrmResource(String basePath) {
+            this.basePath = basePath;
+        }
+
+        public String getBasePath() {
+            return basePath;
+        }
+    }
+
+    /**
+     * Connector types as defined in libdrm's drm_mode.h.
+     * @see <a
+     *     href="https://cs.android.com/android/platform/superproject/main/+/main:external/libdrm/include/drm/drm_mode.h;l=403">drm_mode.h</a>
+     */
+    public enum ConnectorType {
+        UNKNOWN(0),
+        VGA(1),
+        DISPLAY_PORT(10),
+        HDMI_A(11),
+        HDMI_B(12),
+        EDP(14),
+        VIRTUAL(15),
+        DSI(16),
+        DPI(17),
+        WRITEBACK(18);
+
+        private final int value;
+
+        ConnectorType(int value) {
+            this.value = value;
+        }
+
+        public int getValue() {
+            return value;
+        }
+
+        /**
+         * Converts a string representation to a ConnectorType.
+         *
+         * @param typeStr String representation of connector type
+         * @return The corresponding ConnectorType, or UNKNOWN if not recognized
+         */
+        public static ConnectorType fromString(String typeStr) {
+            if (typeStr == null) {
+                return UNKNOWN;
+            }
+
+            switch (typeStr.toUpperCase(java.util.Locale.ROOT)) {
+                case "DP":
+                    return DISPLAY_PORT;
+                case "HDMIA":
+                    return HDMI_A;
+                case "HDMIB":
+                    return HDMI_B;
+                case "EDP":
+                    return EDP;
+                case "VGA":
+                    return VGA;
+                case "DSI":
+                    return DSI;
+                case "DPI":
+                    return DPI;
+                case "VIRTUAL":
+                    return VIRTUAL;
+                case "WRITEBACK":
+                    return WRITEBACK;
+                default:
+                    return UNKNOWN;
+            }
+        }
+    }
+
+    /**
+     * https://cs.android.com/android/platform/superproject/main/+/main:external/libdrm/xf86drmMode.h;l=190
+     */
+    private enum ConnectorStatus {
+        CONNECTED(1),
+        DISCONNECTED(2),
+        UNKNOWN(3);
+
+        private final int value;
+
+        ConnectorStatus(int value) {
+            this.value = value;
+        }
+
+        public int getValue() {
+            return value;
+        }
+    }
+
+    /**
+     * Plane types as defined in libdrm's xf86drmMode.h.
+     * @see <a
+     *     href="https://cs.android.com/android/platform/superproject/main/+/main:external/libdrm/xf86drmMode.h;l=225">xf86drmMode.h</a>
+     */
+    private enum PlaneType {
+        OVERLAY(0),
+        PRIMARY(1),
+        CURSOR(2);
+
+        private final int value;
+
+        PlaneType(int value) {
+            this.value = value;
+        }
+
+        public int getValue() {
+            return value;
+        }
+    }
+
+    /**
+     * Configuration for a VKMS connector using the builder pattern.
+     */
+    public static class VkmsConnectorSetup {
+        private ConnectorType type;
+        private boolean enabledAtStart;
+        private int additionalOverlayPlanes;
+        private CfVkmsEdidHelper.Monitor monitor;
+
+        public static Builder builder() {
+            return new Builder();
+        }
+
+        public static class Builder {
+            private ConnectorType type = ConnectorType.DISPLAY_PORT;
+            private boolean enabledAtStart = true;
+            private int additionalOverlayPlanes = 0;
+            private CfVkmsEdidHelper.Monitor monitor = null;
+
+            /**
+             * Sets the connector type.
+             *
+             * @param type The connector type
+             */
+            public Builder setType(ConnectorType type) {
+                this.type = type;
+                return this;
+            }
+
+            /**
+             * Sets whether the connector is initially enabled.
+             *
+             * @param enabled True if the connector should be enabled at startup
+             */
+            public Builder setEnabledAtStart(boolean enabled) {
+                this.enabledAtStart = enabled;
+                return this;
+            }
+
+            /**
+             * Sets the number of additional overlay planes.
+             *
+             * @param count Number of additional overlay planes
+             */
+            public Builder setAdditionalOverlayPlanes(int count) {
+                if (count < 0) {
+                    throw new IllegalArgumentException("Overlay plane count must be non-negative");
+                }
+                this.additionalOverlayPlanes = count;
+                return this;
+            }
+
+            /**
+             * Sets the monitor (defines EDID).
+             *
+             * @param monitor The monitor to use its EDID for this connector
+             */
+            public Builder setMonitor(CfVkmsEdidHelper.Monitor monitor) {
+                this.monitor = monitor;
+                return this;
+            }
+
+            public VkmsConnectorSetup build() {
+                VkmsConnectorSetup setup = new VkmsConnectorSetup();
+                setup.type = this.type;
+                setup.enabledAtStart = this.enabledAtStart;
+                setup.additionalOverlayPlanes = this.additionalOverlayPlanes;
+                setup.monitor = this.monitor;
+                return setup;
+            }
+        }
+
+        // Private constructor - use builder
+        private VkmsConnectorSetup() {}
+
+        public ConnectorType getType() {
+            return type;
+        }
+
+        public boolean isEnabledAtStart() {
+            return enabledAtStart;
+        }
+
+        public int getAdditionalOverlayPlanes() {
+            return additionalOverlayPlanes;
+        }
+
+        public CfVkmsEdidHelper.Monitor getMonitor() {
+            return monitor;
+        }
+    }
+
+    private final ITestDevice device; // Used to execute shell commands
+    private int latestPlaneId = 0;
+    private boolean initialized = false;
+
+    /**
+     * Creates a VKMS configuration with a specified number of virtual displays,
+     * each with a default setup.
+     *
+     * @param device The test device to run commands on
+     * @param displaysCount The number of virtual displays to configure
+     * @return A new instance of CfVkmsTester, or null if creation failed
+     */
+    public static CfVkmsTester createWithGenericConnectors(ITestDevice device, int displaysCount) {
+        if (displaysCount < 0) {
+            CLog.e("Invalid number of displays: %d. At least one connector must be specified.",
+                displaysCount);
+            return null;
+        }
+
+        CfVkmsTester tester = new CfVkmsTester(device, displaysCount);
+
+        if (!tester.initialized) {
+            CLog.e("Failed to initialize CfVkmsTester with Generic Connectors");
+            return null;
+        }
+
+        return tester;
+    }
+
+    /**
+     * Creates a VKMS configuration based on a provided list of VkmsConnectorSetup.
+     *
+     * @param device The test device to run commands on
+     * @param config A list of VkmsConnectorSetup objects defining the displays
+     * @return A new instance of CfVkmsTester, or null if creation failed
+     */
+    public static CfVkmsTester createWithConfig(
+        ITestDevice device, List<VkmsConnectorSetup> config) {
+        if (config == null || config.isEmpty()) {
+            CLog.e("Empty configuration provided. At least one connector must be specified.");
+            return null;
+        }
+
+        CfVkmsTester tester = new CfVkmsTester(device, config.size(), config);
+
+        if (!tester.initialized) {
+            CLog.e("Failed to initialize CfVkmsTester with Config");
+            return null;
+        }
+
+        return tester;
+    }
+
+    /**
+     * Private constructor to initialize VKMS configuration.
+     */
+    private CfVkmsTester(ITestDevice device, int displaysCount) {
+        this(device, displaysCount, null);
+    }
+
+    /**
+     * Private constructor with explicit configuration.
+     */
+    private CfVkmsTester(
+        ITestDevice device, int displaysCount, List<VkmsConnectorSetup> explicitConfig) {
+        this.device = device;
+        boolean success = false;
+        try {
+            success = toggleSystemUi(false) && configureVkmsAsDisplayDriver()
+                && setupDisplayConnectors(displaysCount, explicitConfig) && toggleVkms(true)
+                && toggleSystemUi(true);
+        } catch (Exception e) {
+            CLog.e("Failed to set up VKMS: %s", e.toString());
+        }
+
+        if (!success) {
+            CLog.e("Failed to set up VKMS");
+            try {
+                shutdownAndCleanUpVkms();
+            } catch (Exception e) {
+                CLog.e("Error during cleanup: %s", e.toString());
+            }
+            return;
+        }
+
+        initialized = true;
+    }
+
+    private boolean toggleSystemUi(boolean enable) throws Exception {
+        String command =
+            enable ? "start vendor.hwcomposer-3 && start" : "stop && stop vendor.hwcomposer-3";
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to %s HWC3 service: %s", enable ? "start" : "stop", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully %s UI service", enable ? "started" : "stopped");
+        return true;
+    }
+
+    private boolean toggleVkms(boolean enable) throws Exception {
+        String path = VKMS_BASE_DIR + "/enabled";
+        String value = enable ? "1" : "0";
+        String command = "echo " + value + " > " + path;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to toggle VKMS: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully toggled VKMS to %s", enable ? "enabled" : "disabled");
+        return true;
+    }
+
+    private boolean configureVkmsAsDisplayDriver() throws Exception {
+        String command = "setprop vendor.hwc.drm.device /dev/dri/card1";
+        CommandResult result = executeCommand(command);
+
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to set vendor.hwc.drm.device property: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully set vendor.hwc.drm.device property");
+
+        command = "mkdir " + VKMS_BASE_DIR;
+        result = executeCommand(command);
+
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to create VKMS directory: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully created directory %s", VKMS_BASE_DIR);
+        return true;
+    }
+
+    private boolean setupDisplayConnectors(
+        int displaysCount, List<VkmsConnectorSetup> explicitConfig) throws Exception {
+        boolean isExplicitConfig = explicitConfig != null && !explicitConfig.isEmpty();
+        if (isExplicitConfig && displaysCount != explicitConfig.size()) {
+            CLog.e("Mismatch between requested displays count and explicit config size");
+            return false;
+        }
+
+        for (int i = 0; i < displaysCount; i++) {
+            createResource(DrmResource.CRTC, i);
+            createResource(DrmResource.ENCODER, i);
+            linkToCrtc(DrmResource.ENCODER, i, i);
+
+            createResource(DrmResource.CONNECTOR, i);
+
+            // Configure connector based on explicit config or defaults
+            VkmsConnectorSetup config = null;
+            if (isExplicitConfig) {
+                config = explicitConfig.get(i);
+                setConnectorStatus(i, config.isEnabledAtStart());
+                setConnectorType(i, config.getType());
+                if (config.getMonitor() != null) {
+                    setConnectorEdid(i, config.getMonitor());
+                }
+            } else {
+                setConnectorStatus(i, false); // Default to disconnected
+                setConnectorType(i, i == 0 ? ConnectorType.EDP : ConnectorType.DISPLAY_PORT);
+            }
+
+            linkConnectorToEncoder(i, i);
+
+            // Create planes for each connector
+            int additionalOverlays = isExplicitConfig ? config.getAdditionalOverlayPlanes() : 0;
+            setupPlanesForConnector(i, additionalOverlays);
+
+            CLog.i("Successfully set up display %d", i);
+        }
+
+        return true;
+    }
+
+    /**
+     * Creates a DRM resource directory.
+     *
+     * @param resource The type of resource to create
+     * @param index The index of the resource
+     * @return true if successful, false otherwise
+     * @throws Exception If an error occurs during directory creation
+     */
+    private boolean createResource(DrmResource resource, int index) throws Exception {
+        String resourceDir = VKMS_BASE_DIR + "/" + resource.getBasePath() + index;
+        String command = "mkdir " + resourceDir;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to create directory %s: %s", resourceDir, result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully created directory %s", resourceDir);
+        return true;
+    }
+
+    private void setupPlanesForConnector(int connectorIndex, int additionalOverlays)
+        throws Exception {
+        // Basic planes: cursor (0) and primary (1)
+        for (int j = 0; j < 2 + additionalOverlays; j++) {
+            createResource(DrmResource.PLANE, latestPlaneId);
+
+            // Set plane type
+            PlaneType type;
+            switch (j) {
+                case 0:
+                    type = PlaneType.CURSOR;
+                    break;
+                case 1:
+                    type = PlaneType.PRIMARY;
+                    break;
+                default:
+                    type = PlaneType.OVERLAY;
+                    break;
+            }
+
+            setPlaneType(latestPlaneId, type);
+            setPlaneFormat(latestPlaneId);
+            linkToCrtc(DrmResource.PLANE, latestPlaneId, connectorIndex);
+
+            latestPlaneId++;
+        }
+    }
+
+    private boolean setConnectorStatus(int index, boolean enable) throws Exception {
+        String connectorDir = VKMS_BASE_DIR + "/" + DrmResource.CONNECTOR.getBasePath() + index;
+        String statusPath = connectorDir + "/status";
+        ConnectorStatus status = enable ? ConnectorStatus.CONNECTED : ConnectorStatus.DISCONNECTED;
+        String command = "echo " + status.getValue() + " > " + statusPath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to set connector status: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully set connector %d status to %s", index,
+            enable ? "connected" : "disconnected");
+        return true;
+    }
+
+    private boolean setConnectorType(int index, ConnectorType type) throws Exception {
+        String connectorDir = VKMS_BASE_DIR + "/" + DrmResource.CONNECTOR.getBasePath() + index;
+        String typePath = connectorDir + "/type";
+        String command = "echo " + type.getValue() + " > " + typePath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to set connector type: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully set connector %d type to %d", index, type.getValue());
+        return true;
+    }
+
+    private boolean setConnectorEdid(int index, CfVkmsEdidHelper.Monitor monitor) throws Exception {
+        if (monitor == null) {
+            CLog.e("Monitor is null for connector %d", index);
+            return false;
+        }
+
+        String connectorDir = VKMS_BASE_DIR + "/" + DrmResource.CONNECTOR.getBasePath() + index;
+        String edidPath = connectorDir + "/edid";
+
+        // Get the formatted EDID data from the helper
+        String edidHexEscaped = CfVkmsEdidHelper.getEdidForPrintf(monitor);
+        if (edidHexEscaped == null || edidHexEscaped.isEmpty()) {
+            CLog.e("Failed to get formatted EDID data for connector %d", index);
+            return false;
+        }
+
+        // Create the command to write EDID data
+        String command = String.format("printf \"%s\" > %s", edidHexEscaped, edidPath);
+
+        // Execute the command
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to write EDID data: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully wrote EDID data to connector %d", index);
+        return true;
+    }
+
+    private boolean setPlaneType(int index, PlaneType type) throws Exception {
+        String planeDir = VKMS_BASE_DIR + "/" + DrmResource.PLANE.getBasePath() + index;
+        String typePath = planeDir + "/type";
+        String command = "echo " + type.getValue() + " > " + typePath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to set plane type: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully set plane %d type to %d", index, type.getValue());
+        return true;
+    }
+
+    private boolean setPlaneFormat(int index) throws Exception {
+        String planeDir = VKMS_BASE_DIR + "/" + DrmResource.PLANE.getBasePath() + index;
+        String formatPath = planeDir + "/supported_formats";
+        // TODO: This is now hardcoded to all formats. Extend this later.
+        String command = "echo +* > " + formatPath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to set plane format: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully set plane %d format", index);
+        return true;
+    }
+
+    private boolean linkToCrtc(DrmResource resource, int resourceIdx, int crtcIdx)
+        throws Exception {
+        String crtcName = DrmResource.CRTC.getBasePath() + crtcIdx;
+        String resourceDir = VKMS_BASE_DIR + "/" + resource.getBasePath() + resourceIdx;
+        String possibleCrtcPath = resourceDir + "/possible_crtcs";
+        String crtcDir = VKMS_BASE_DIR + "/" + crtcName;
+
+        String command = "ln -s " + crtcDir + " " + possibleCrtcPath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            String err = result.getStderr();
+            CLog.e("Failed to link to CRTC: %s", err);
+            return false;
+        }
+
+        CLog.i("Successfully linked %s to %s", possibleCrtcPath, crtcDir);
+        return true;
+    }
+
+    private boolean linkConnectorToEncoder(int connectorIdx, int encoderIdx) throws Exception {
+        String encoderName = DrmResource.ENCODER.getBasePath() + encoderIdx;
+        String connectorDir =
+            VKMS_BASE_DIR + "/" + DrmResource.CONNECTOR.getBasePath() + connectorIdx;
+        String possibleEncoderPath = connectorDir + "/possible_encoders";
+        String encoderDir = VKMS_BASE_DIR + "/" + encoderName;
+
+        String command = "ln -s " + encoderDir + " " + possibleEncoderPath;
+
+        CommandResult result = executeCommand(command);
+        if (result.getStatus() != CommandStatus.SUCCESS) {
+            CLog.e("Failed to link connector to encoder: %s", result.getStderr());
+            return false;
+        }
+
+        CLog.i("Successfully linked %s to %s", possibleEncoderPath, encoderDir);
+        return true;
+    }
+
+    private void shutdownAndCleanUpVkms() throws Exception {
+        toggleSystemUi(false);
+        toggleVkms(false);
+
+        // Remove all links first (possible_crtcs and possible_encoders)
+        device.executeShellCommand("rm -f " + VKMS_BASE_DIR + "/planes/*/possible_crtcs/*");
+        device.executeShellCommand("rm -f " + VKMS_BASE_DIR + "/encoders/*/possible_crtcs/*");
+        device.executeShellCommand("rm -f " + VKMS_BASE_DIR + "/connectors/*/possible_encoders/*");
+
+        // Remove resource directories in order
+        device.executeShellCommand("rmdir " + VKMS_BASE_DIR + "/planes/*");
+        device.executeShellCommand("rmdir " + VKMS_BASE_DIR + "/crtcs/*");
+        device.executeShellCommand("rmdir " + VKMS_BASE_DIR + "/encoders/*");
+        device.executeShellCommand("rmdir " + VKMS_BASE_DIR + "/connectors/*");
+
+        // Remove the base directory
+        device.executeShellCommand("rmdir " + VKMS_BASE_DIR);
+
+        CLog.i("VKMS cleanup completed");
+    }
+
+    private CommandResult executeCommand(String command) throws Exception {
+        CommandResult result = null;
+        long startTime = System.currentTimeMillis();
+        long maxDurationMs = 500;
+
+        while (System.currentTimeMillis() - startTime < maxDurationMs) {
+            result = device.executeShellV2Command(command);
+            if (result.getStatus() == CommandStatus.SUCCESS) {
+                return result;
+            }
+        }
+        CLog.w("Command '%s' failed after %dms", command, maxDurationMs);
+        return result;
+    }
+
+    /**
+     * Implements the close method required by Closeable interface.
+     * Cleans up VKMS resources when the tester is closed.
+     */
+    @Override
+    public void close() throws IOException {
+        try {
+            shutdownAndCleanUpVkms();
+        } catch (Exception e) {
+            throw new IOException("Failed to clean up VKMS: " + e.getMessage(), e);
+        }
+    }
+}
diff --git a/tests/hal/hal_implementation_test.cpp b/tests/hal/hal_implementation_test.cpp
index 09f0e0196..f3a22d407 100644
--- a/tests/hal/hal_implementation_test.cpp
+++ b/tests/hal/hal_implementation_test.cpp
@@ -64,8 +64,6 @@ static const std::set<std::string> kKnownMissingHidl = {
     "android.hardware.audio.effect@6.0",
     "android.hardware.audio.effect@7.0", // converted to AIDL, see b/264712385
     "android.hardware.authsecret@1.0", // converted to AIDL, see b/182976659
-    "android.hardware.automotive.audiocontrol@1.0",
-    "android.hardware.automotive.audiocontrol@2.0",
     "android.hardware.automotive.can@1.0",  // converted to AIDL, see b/170405615
     "android.hardware.automotive.evs@1.1",
     "android.hardware.automotive.sv@1.0",
diff --git a/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java b/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
index c9b95256d..49fb56f56 100644
--- a/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
+++ b/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
@@ -50,7 +50,7 @@ public class SnapshotTest extends BaseHostJUnit4Test {
 
     @Test
     public void testSnapshot() throws Exception {
-        String snapshotId = "snapshot_" + UUID.randomUUID().toString();
+        String snapshotId = UUID.randomUUID().toString();
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device
@@ -96,7 +96,7 @@ public class SnapshotTest extends BaseHostJUnit4Test {
     // reboot and so it can be easy for change to one to break the other.
     @Test
     public void testSnapshotReboot() throws Exception {
-        String snapshotId = "snapshot_" + UUID.randomUUID().toString();
+        String snapshotId = UUID.randomUUID().toString();
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device.
@@ -116,7 +116,7 @@ public class SnapshotTest extends BaseHostJUnit4Test {
     // Test powerwash after restoring
     @Test
     public void testSnapshotPowerwash() throws Exception {
-        String snapshotId = "snapshot_" + UUID.randomUUID().toString();
+        String snapshotId = UUID.randomUUID().toString();
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device.
@@ -140,7 +140,7 @@ public class SnapshotTest extends BaseHostJUnit4Test {
     // Test powerwash the device, then snapshot and restore
     @Test
     public void testPowerwashSnapshot() throws Exception {
-        String snapshotId = "snapshot_" + UUID.randomUUID().toString();
+        String snapshotId = UUID.randomUUID().toString();
         CLog.d("Powerwash attempt before restore");
         long start = System.currentTimeMillis();
         boolean success = new DeviceResetHandler(getInvocationContext()).resetDevice(getDevice());
diff --git a/tools/create_base_image.go b/tools/create_base_image.go
index a5ba91a1c..f6498523b 100644
--- a/tools/create_base_image.go
+++ b/tools/create_base_image.go
@@ -141,8 +141,7 @@ func init() {
 	flag.IntVar(&image_disk_size_gb, "image_disk_size_gb", 10, "Image disk size in GB")
 	flag.Var(&ssh_flags, "ssh_flag",
 		"Values for --ssh-flag and --scp_flag for gcloud compute ssh/scp respectively. This flag may be repeated")
-	flag.BoolVar(&host_orchestration_flag, "host_orchestration", false,
-		"assembles image with host orchestration capabilities")
+	flag.BoolVar(&host_orchestration_flag, "host_orchestration", false, "DEPRECATED")
 	flag.Parse()
 }
 
@@ -370,12 +369,8 @@ func main() {
 	gce(ExitOnFail, `compute ssh `+internal_ip_flag+` `+PZ+` "`+build_instance+
 		`"`+` -- `+ssh_flags.AsArgs()+` ./remove_old_gce_kernel.sh`)
 
-	ho_arg := ""
-	if host_orchestration_flag {
-		ho_arg = "-o"
-	}
 	gce(ExitOnFail, `compute ssh `+internal_ip_flag+` `+PZ+` "`+build_instance+
-		`"`+` -- `+ssh_flags.AsArgs()+` ./create_base_image_gce.sh `+ho_arg)
+		`"`+` -- `+ssh_flags.AsArgs()+` ./create_base_image_gce.sh`)
 
 	// Reboot the instance to force a clean umount of the disk's file system.
 	gce(WarnOnFail, `compute ssh `+internal_ip_flag+` `+PZ+` "`+build_instance+
diff --git a/tools/create_base_image_gce.sh b/tools/create_base_image_gce.sh
index 4e1c6e6f1..705958195 100755
--- a/tools/create_base_image_gce.sh
+++ b/tools/create_base_image_gce.sh
@@ -18,15 +18,6 @@ set -x
 set -o errexit
 shopt -s extglob
 
-# If "true" install host orchestration capabilities.
-host_orchestration_flag="false"
-
-while getopts ":o" flag; do
-    case "${flag}" in
-        o) host_orchestration_flag="true";;
-    esac
-done
-
 sudo apt-get update
 
 sudo apt install -y debconf-utils
@@ -80,11 +71,7 @@ for dsc in *.dsc; do
 done
 
 # Now gather all of the relevant .deb files to copy them into the image
-debs=(!(cuttlefish-orchestration*).deb)
-if [[ "${host_orchestration_flag}" == "true" ]]; then
-  debs+=( cuttlefish-orchestration*.deb )
-fi
-
+debs=(*.deb)
 tmp_debs=()
 for i in "${debs[@]}"; do
   tmp_debs+=(/tmp/"$(basename "$i")")
@@ -120,9 +107,11 @@ if ! echo "$JDK21_SHA256SUM /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz" | sud
 fi
 sudo chroot /mnt/image /usr/bin/tar xvzf /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz -C /usr/java
 sudo chroot /mnt/image /usr/bin/rm /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz
-echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/environment >/dev/null
-echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
+ENV_JAVA_HOME='/usr/java/jdk-21.0.2'
+echo "JAVA_HOME=$ENV_JAVA_HOME" | sudo chroot /mnt/image /usr/bin/tee -a /etc/environment >/dev/null
+echo "JAVA_HOME=$ENV_JAVA_HOME" | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
 echo 'PATH=$JAVA_HOME/bin:$PATH' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
+echo "PATH=$ENV_JAVA_HOME/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games" | sudo chroot /mnt/image /usr/bin/tee -a /etc/environment >/dev/null
 
 # install tools dependencies
 sudo chroot /mnt/image /usr/bin/apt install -y unzip bzip2 lzop
diff --git a/vsoc_arm64_only/phone/aosp_cf_fullmte.mk b/vsoc_arm64_only/phone/aosp_cf_fullmte.mk
index 5d72902b6..5573de5c9 100644
--- a/vsoc_arm64_only/phone/aosp_cf_fullmte.mk
+++ b/vsoc_arm64_only/phone/aosp_cf_fullmte.mk
@@ -18,3 +18,15 @@ $(call inherit-product, device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.m
 $(call inherit-product, $(SRC_TARGET_DIR)/product/fullmte.mk)
 
 PRODUCT_NAME := aosp_cf_arm64_phone_fullmte
+
+ifneq ($(CLANG_COVERAGE),true)
+ifneq ($(NATIVE_COVERAGE),true)
+ifeq ($(TARGET_PRODUCT),aosp_cf_arm64_phone_fullmte)
+ifeq (,$(TARGET_BUILD_APPS))
+ifeq (,$(UNBUNDLED_BUILD))
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_CUTTLEFISH)
+endif
+endif
+endif
+endif
+endif
diff --git a/vsoc_arm64_only/phone/aosp_cf_hwasan.mk b/vsoc_arm64_only/phone/aosp_cf_hwasan.mk
index c261662ce..3e4a492d6 100644
--- a/vsoc_arm64_only/phone/aosp_cf_hwasan.mk
+++ b/vsoc_arm64_only/phone/aosp_cf_hwasan.mk
@@ -22,3 +22,15 @@ PRODUCT_NAME := aosp_cf_arm64_only_phone_hwasan
 ifeq ($(filter hwaddress,$(SANITIZE_TARGET)),)
   SANITIZE_TARGET := $(strip $(SANITIZE_TARGET) hwaddress)
 endif
+
+ifneq ($(CLANG_COVERAGE),true)
+ifneq ($(NATIVE_COVERAGE),true)
+ifeq ($(TARGET_PRODUCT),aosp_cf_arm64_only_phone_hwasan)
+ifeq (,$(TARGET_BUILD_APPS))
+ifeq (,$(UNBUNDLED_BUILD))
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_CUTTLEFISH)
+endif
+endif
+endif
+endif
+endif
diff --git a/vsoc_arm64_pgagnostic/BoardConfig.mk b/vsoc_arm64_pgagnostic/BoardConfig.mk
index ec1e47934..04affcab6 100644
--- a/vsoc_arm64_pgagnostic/BoardConfig.mk
+++ b/vsoc_arm64_pgagnostic/BoardConfig.mk
@@ -25,7 +25,6 @@ TARGET_CPU_ABI := arm64-v8a
 TARGET_CPU_VARIANT := cortex-a53
 
 # Use 16K page size kernel
-TARGET_KERNEL_USE ?= 6.6
 TARGET_KERNEL_ARCH ?= arm64
 SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)/16k
 TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
diff --git a/vsoc_riscv64/phone/android-info.txt b/vsoc_riscv64/phone/android-info.txt
new file mode 100644
index 000000000..3f61af27d
--- /dev/null
+++ b/vsoc_riscv64/phone/android-info.txt
@@ -0,0 +1,4 @@
+config=phone
+enforce_mac80211_hwsim=false
+gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
diff --git a/vsoc_riscv64/phone/aosp_cf.mk b/vsoc_riscv64/phone/aosp_cf.mk
index 998f8810a..c41ee8cdc 100644
--- a/vsoc_riscv64/phone/aosp_cf.mk
+++ b/vsoc_riscv64/phone/aosp_cf.mk
@@ -39,8 +39,6 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
 LOCAL_ENABLE_WIDEVINE := false
 $(call inherit-product, device/google/cuttlefish/shared/phone/device_vendor.mk)
 
-PRODUCT_ENFORCE_MAC80211_HWSIM := false
-
 # TODO: Nested virtualization support
 # $(call inherit-product, packages/modules/Virtualization/apex/product_packages.mk)
 
@@ -77,3 +75,17 @@ PRODUCT_VENDOR_PROPERTIES += \
 # Ignore all Android.mk files
 PRODUCT_IGNORE_ALL_ANDROIDMK := true
 PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
+
+TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/vsoc_riscv64/phone/android-info.txt
+
+ifneq ($(CLANG_COVERAGE),true)
+ifneq ($(NATIVE_COVERAGE),true)
+ifeq ($(TARGET_PRODUCT),aosp_cf_riscv64_phone)
+ifeq (,$(TARGET_BUILD_APPS))
+ifeq (,$(UNBUNDLED_BUILD))
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_CUTTLEFISH)
+endif
+endif
+endif
+endif
+endif
diff --git a/vsoc_riscv64/slim/android-info.txt b/vsoc_riscv64/slim/android-info.txt
new file mode 100644
index 000000000..5ae20857a
--- /dev/null
+++ b/vsoc_riscv64/slim/android-info.txt
@@ -0,0 +1,4 @@
+config=slim
+enforce_mac80211_hwsim=false
+gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
diff --git a/vsoc_riscv64/slim/aosp_cf.mk b/vsoc_riscv64/slim/aosp_cf.mk
index 285317ae2..ff2b060c4 100644
--- a/vsoc_riscv64/slim/aosp_cf.mk
+++ b/vsoc_riscv64/slim/aosp_cf.mk
@@ -40,8 +40,6 @@ PRODUCT_PACKAGES += FakeSystemApp
 LOCAL_ENABLE_WIDEVINE := false
 $(call inherit-product, device/google/cuttlefish/shared/slim/device_vendor.mk)
 
-PRODUCT_ENFORCE_MAC80211_HWSIM := false
-
 #
 # Special settings for the target
 #
@@ -65,3 +63,5 @@ PRODUCT_MODEL := Cuttlefish riscv64 slim
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/vsoc_riscv64/slim/android-info.txt
diff --git a/vsoc_riscv64/wear/android-info.txt b/vsoc_riscv64/wear/android-info.txt
new file mode 100644
index 000000000..d913fd979
--- /dev/null
+++ b/vsoc_riscv64/wear/android-info.txt
@@ -0,0 +1,4 @@
+config=wear
+enforce_mac80211_hwsim=false
+gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
diff --git a/vsoc_riscv64/wear/aosp_cf.mk b/vsoc_riscv64/wear/aosp_cf.mk
index a79e48940..dd62a464f 100644
--- a/vsoc_riscv64/wear/aosp_cf.mk
+++ b/vsoc_riscv64/wear/aosp_cf.mk
@@ -37,8 +37,6 @@ PRODUCT_PACKAGES += \
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.software.app_widgets.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.app_widgets.xml \
 
-PRODUCT_ENFORCE_MAC80211_HWSIM := false
-
 #
 # All components inherited here go to system_ext image
 #
@@ -79,3 +77,5 @@ PRODUCT_MODEL := Cuttlefish riscv64 wearable
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/vsoc_riscv64/wear/android-info.txt
diff --git a/vsoc_riscv64_minidroid/android-info.txt b/vsoc_riscv64_minidroid/android-info.txt
new file mode 100644
index 000000000..a18f80fa3
--- /dev/null
+++ b/vsoc_riscv64_minidroid/android-info.txt
@@ -0,0 +1,4 @@
+config=minidroid
+enforce_mac80211_hwsim=false
+gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
diff --git a/vsoc_riscv64_minidroid/aosp_cf.mk b/vsoc_riscv64_minidroid/aosp_cf.mk
index 8436a7b6b..3b1c3e427 100644
--- a/vsoc_riscv64_minidroid/aosp_cf.mk
+++ b/vsoc_riscv64_minidroid/aosp_cf.mk
@@ -24,8 +24,8 @@ PRODUCT_DEVICE := vsoc_riscv64_minidroid
 PRODUCT_MANUFACTURER := Google
 PRODUCT_MODEL := Cuttlefish riscv64 minidroid
 
-PRODUCT_ENFORCE_MAC80211_HWSIM := false
-
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/vsoc_riscv64_minidroid/android-info.txt
diff --git a/vsoc_x86_64_only/auto/aosp_cf.mk b/vsoc_x86_64_only/auto/aosp_cf.mk
index 625fcf398..859f30ff3 100644
--- a/vsoc_x86_64_only/auto/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto/aosp_cf.mk
@@ -29,6 +29,7 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := true
 # Telephony: Use Minradio RIL instead of Cuttlefish RIL
 TARGET_USES_CF_RILD := false
 PRODUCT_PACKAGES += com.android.hardware.radio.minradio.virtual
+PRODUCT_PACKAGES += ConnectivityOverlayMinradio
 
 #
 # All components inherited here go to system_ext image
@@ -65,12 +66,6 @@ $(call inherit-product, device/google/cuttlefish/vsoc_x86_64/bootloader.mk)
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml
 
-# Exclude features that are not available on automotive cuttlefish devices.
-# TODO(b/351896700): Remove this workaround once support for uncalibrated accelerometer and
-# uncalibrated gyroscope are added to automotive cuttlefish.
-PRODUCT_COPY_FILES += \
-    device/google/cuttlefish/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/exclude_unavailable_imu_features.xml
-
 PRODUCT_NAME := aosp_cf_x86_64_only_auto
 PRODUCT_DEVICE := vsoc_x86_64_only
 PRODUCT_MANUFACTURER := Google
diff --git a/vsoc_x86_64_only/auto_md/aosp_cf.mk b/vsoc_x86_64_only/auto_md/aosp_cf.mk
index cb13870a8..cbffd44fd 100644
--- a/vsoc_x86_64_only/auto_md/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_md/aosp_cf.mk
@@ -37,8 +37,6 @@ PRODUCT_PACKAGES += \
 
 PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
     com.android.car.internal.debug.num_auto_populated_users=1 # 1 passenger only (so 2nd display shows user picker)
-# TODO(b/233370174): add audio multi-zone
-#   ro.vendor.simulateMultiZoneAudio=true \
 
 # enables the rro package for passenger(secondary) user.
 ENABLE_PASSENGER_SYSTEMUI_RRO := true
@@ -53,6 +51,14 @@ $(call inherit-product, device/generic/car/emulator/cluster/cluster-hwserviceman
 # Disable shared system image checking
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := false
 
+# Prevent the base aosp_cf.mk from including its audio configuration
+LOCAL_USE_VENDOR_AUDIO_CONFIGURATION?= false
+ifeq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),false)
+LOCAL_USE_VENDOR_AUDIO_CONFIGURATION := true
+# Audio configuration for multi-display
+$(call inherit-product, device/google/cuttlefish/shared/auto_md/audio_policy_engine.mk)
+endif
+
 # Add the regular stuff.
 $(call inherit-product, device/google/cuttlefish/vsoc_x86_64_only/auto/aosp_cf.mk)
 
diff --git a/vsoc_x86_64_only/phone/aosp_cf.mk b/vsoc_x86_64_only/phone/aosp_cf.mk
index 4667f4382..a1d37a3a7 100644
--- a/vsoc_x86_64_only/phone/aosp_cf.mk
+++ b/vsoc_x86_64_only/phone/aosp_cf.mk
@@ -66,3 +66,15 @@ PRODUCT_VENDOR_PROPERTIES += \
 PRODUCT_IGNORE_ALL_ANDROIDMK := true
 # TODO(b/342327756, b/342330305): Allow the following Android.mk files
 PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
+
+ifneq ($(CLANG_COVERAGE),true)
+ifneq ($(NATIVE_COVERAGE),true)
+ifeq ($(TARGET_PRODUCT),aosp_cf_x86_64_only_phone)
+ifeq (,$(TARGET_BUILD_APPS))
+ifeq (,$(UNBUNDLED_BUILD))
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_CUTTLEFISH)
+endif
+endif
+endif
+endif
+endif
diff --git a/vsoc_x86_64_pgagnostic/BoardConfig.mk b/vsoc_x86_64_pgagnostic/BoardConfig.mk
index ae9082936..0d17ce85a 100644
--- a/vsoc_x86_64_pgagnostic/BoardConfig.mk
+++ b/vsoc_x86_64_pgagnostic/BoardConfig.mk
@@ -28,8 +28,6 @@ TARGET_NATIVE_BRIDGE_ARCH_VARIANT := armv8-a
 TARGET_NATIVE_BRIDGE_CPU_VARIANT := generic
 TARGET_NATIVE_BRIDGE_ABI := arm64-v8a
 
-# Use 6.6 kernel
-TARGET_KERNEL_USE ?= 6.6
 TARGET_KERNEL_ARCH ?= x86_64
 SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
 TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
@@ -59,3 +57,6 @@ AUDIOSERVER_MULTILIB := first
 ifneq ($(BOARD_IS_AUTOMOTIVE), true)
 -include device/google/cuttlefish/shared/virgl/BoardConfig.mk
 endif
+
+# Override for gfxstream support
+TARGET_BOARD_INFO_FILE := device/google/cuttlefish/shared/x86_16kb/android-info.txt
```

