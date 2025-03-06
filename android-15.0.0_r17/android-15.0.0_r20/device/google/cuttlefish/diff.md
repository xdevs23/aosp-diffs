```diff
diff --git a/apex/com.google.cf.bt/Android.bp b/apex/com.google.cf.bt/Android.bp
index 6fa580ced..eff9ca6c9 100644
--- a/apex/com.google.cf.bt/Android.bp
+++ b/apex/com.google.cf.bt/Android.bp
@@ -50,6 +50,13 @@ prebuilt_etc {
     installable: false,
 }
 
+prebuilt_etc {
+    name: "android.hardware.bluetooth.socket-service.default.xml",
+    src: ":manifest_android.hardware.bluetooth.socket-service.default.xml",
+    sub_dir: "vintf",
+    installable: false,
+}
+
 apex {
     name: "com.google.cf.bt",
     manifest: "manifest.json",
@@ -62,19 +69,21 @@ apex {
     binaries: [
         "android.hardware.bluetooth-service.default",
         "android.hardware.bluetooth.finder-service.default",
-        "android.hardware.bluetooth.ranging-service.default",
         "android.hardware.bluetooth.lmp_event-service.default",
+        "android.hardware.bluetooth.ranging-service.default",
+        "android.hardware.bluetooth.socket-service.default",
         "bt_vhci_forwarder",
     ],
     prebuilts: [
         // permissions
-        "android.hardware.bluetooth_le.prebuilt.xml",
         "android.hardware.bluetooth.prebuilt.xml",
+        "android.hardware.bluetooth_le.prebuilt.xml",
         // vintf
         "android.hardware.bluetooth-service.default.xml",
         "android.hardware.bluetooth.finder-service.default.xml",
-        "android.hardware.bluetooth.ranging-service.default.xml",
         "android.hardware.bluetooth.lmp_event-service.default.xml",
+        "android.hardware.bluetooth.ranging-service.default.xml",
+        "android.hardware.bluetooth.socket-service.default.xml",
         // init rc
         "com.google.cf.bt.rc",
     ],
diff --git a/apex/com.google.cf.bt/com.google.cf.bt.rc b/apex/com.google.cf.bt/com.google.cf.bt.rc
index 9401dda82..ec7597ced 100644
--- a/apex/com.google.cf.bt/com.google.cf.bt.rc
+++ b/apex/com.google.cf.bt/com.google.cf.bt.rc
@@ -29,3 +29,9 @@ service bt_lmp_event /apex/com.google.cf.bt/bin/hw/android.hardware.bluetooth.lm
     user bluetooth
     group bluetooth net_admin net_bt_admin
     capabilities NET_ADMIN
+
+service bt_socket /apex/com.google.cf.bt/bin/hw/android.hardware.bluetooth.socket-service.default
+    class hal
+    user bluetooth
+    group bluetooth net_admin net_bt_admin
+    capabilities NET_ADMIN
diff --git a/apex/com.google.cf.bt/file_contexts b/apex/com.google.cf.bt/file_contexts
index a3e9dfbae..8136019e3 100644
--- a/apex/com.google.cf.bt/file_contexts
+++ b/apex/com.google.cf.bt/file_contexts
@@ -3,5 +3,6 @@
 /bin/hw/android.hardware.bluetooth.finder-service.default     u:object_r:hal_bluetooth_btlinux_exec:s0
 /bin/hw/android.hardware.bluetooth.ranging-service.default    u:object_r:hal_bluetooth_btlinux_exec:s0
 /bin/hw/android.hardware.bluetooth.lmp_event-service.default  u:object_r:hal_bluetooth_btlinux_exec:s0
+/bin/hw/android.hardware.bluetooth.socket-service.default    u:object_r:hal_bluetooth_btlinux_exec:s0
 /bin/bt_vhci_forwarder                                        u:object_r:bt_vhci_forwarder_exec:s0
 /etc(/.*)?                                                    u:object_r:vendor_configs_file:s0
diff --git a/apex/com.google.cf.rild/Android.bp b/apex/com.google.cf.rild/Android.bp
index 44bbeae02..6e253cf82 100644
--- a/apex/com.google.cf.rild/Android.bp
+++ b/apex/com.google.cf.rild/Android.bp
@@ -53,8 +53,8 @@ apex {
         "com.google.cf.rild.xml",
     ],
     overrides: [
-        "libril",
         "libreference-ril",
+        "libril",
         "rild",
     ],
 }
diff --git a/apex/com.google.cf.wifi/Android.bp b/apex/com.google.cf.wifi/Android.bp
index e9564409c..becb3cb17 100644
--- a/apex/com.google.cf.wifi/Android.bp
+++ b/apex/com.google.cf.wifi/Android.bp
@@ -32,9 +32,9 @@ apex {
     // Install the apex in /vendor/apex
     soc_specific: true,
     binaries: [
+        "//device/generic/goldfish:mac80211_create_radios",
         "rename_netiface",
         "setup_wifi",
-        "//device/generic/goldfish:mac80211_create_radios",
     ],
     sh_binaries: ["init.wifi_apex"],
     prebuilts: [
diff --git a/apex/com.google.cf.wpa_supplicant/Android.bp b/apex/com.google.cf.wpa_supplicant/Android.bp
index 19ec13ad0..495ed8d36 100644
--- a/apex/com.google.cf.wpa_supplicant/Android.bp
+++ b/apex/com.google.cf.wpa_supplicant/Android.bp
@@ -30,13 +30,11 @@ apex {
         "//external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant:wpa_supplicant",
     ],
     prebuilts: [
+        "android.hardware.wifi.hostapd.xml.prebuilt",
+        "android.hardware.wifi.supplicant.xml.prebuilt",
         "com.google.cf.wpa_supplicant.rc",
         "p2p_supplicant.conf.cf",
         "wpa_supplicant.conf.cf",
         "wpa_supplicant_overlay.conf.cf",
     ],
-    vintf_fragment_modules: [
-        "android.hardware.wifi.hostapd.xml",
-        "android.hardware.wifi.supplicant.xml",
-    ],
 }
diff --git a/build/Android.bp b/build/Android.bp
index 639ffeac8..03beadd0a 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -218,6 +218,7 @@ cvd_host_webrtc_assets = [
     "webrtc_index.html",
     "webrtc_index.js",
     "webrtc_location.js",
+    "webrtc_mouse.js",
     "webrtc_rootcanal.js",
     "webrtc_server.crt",
     "webrtc_server.key",
diff --git a/common/frontend/socket_vsock_proxy/Android.bp b/common/frontend/socket_vsock_proxy/Android.bp
index 366b53296..7b7180503 100644
--- a/common/frontend/socket_vsock_proxy/Android.bp
+++ b/common/frontend/socket_vsock_proxy/Android.bp
@@ -27,14 +27,14 @@ cc_binary {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
-        "libcuttlefish_utils",
         "libcuttlefish_kernel_log_monitor_utils",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "liblog",
     ],
     static_libs: [
-        "libgflags",
         "libcuttlefish_utils",
+        "libgflags",
     ],
     target: {
         host: {
diff --git a/common/libs/confui/Android.bp b/common/libs/confui/Android.bp
index fca008bda..194cd23ca 100644
--- a/common/libs/confui/Android.bp
+++ b/common/libs/confui/Android.bp
@@ -20,10 +20,10 @@ package {
 cc_library {
     name: "libcuttlefish_confui",
     srcs: [
-        "packet_types.cpp",
         "packet.cpp",
-        "protocol_types.cpp",
+        "packet_types.cpp",
         "protocol.cpp",
+        "protocol_types.cpp",
     ],
     static_libs: [
         "libteeui",
diff --git a/common/libs/fs/Android.bp b/common/libs/fs/Android.bp
index 180a23a43..a5c23d9da 100644
--- a/common/libs/fs/Android.bp
+++ b/common/libs/fs/Android.bp
@@ -69,8 +69,8 @@ cc_test {
         "shared_fd_test.cpp",
     ],
     shared_libs: [
-        "libcuttlefish_fs",
         "libbase",
+        "libcuttlefish_fs",
     ],
     static_libs: [
         "libgmock",
diff --git a/common/libs/net/Android.bp b/common/libs/net/Android.bp
index 802141e53..4b9c437f2 100644
--- a/common/libs/net/Android.bp
+++ b/common/libs/net/Android.bp
@@ -24,8 +24,8 @@ cc_library_shared {
         "network_interface_manager.cpp",
     ],
     shared_libs: [
-        "libcuttlefish_fs",
         "libbase",
+        "libcuttlefish_fs",
     ],
     defaults: ["cuttlefish_host"],
 }
@@ -36,9 +36,9 @@ cc_test {
         "netlink_request_test.cpp",
     ],
     shared_libs: [
-        "libcuttlefish_fs",
         "cuttlefish_net",
         "libbase",
+        "libcuttlefish_fs",
     ],
     static_libs: [
         "libgmock",
diff --git a/common/libs/security/Android.bp b/common/libs/security/Android.bp
index c278bb82a..c03ead7bb 100644
--- a/common/libs/security/Android.bp
+++ b/common/libs/security/Android.bp
@@ -19,7 +19,10 @@ package {
 
 cc_library {
     name: "libcuttlefish_security",
-    defaults: ["hidl_defaults", "cuttlefish_host"],
+    defaults: [
+        "cuttlefish_host",
+        "hidl_defaults",
+    ],
     srcs: [
         "keymaster_channel.cpp",
     ],
@@ -72,8 +75,8 @@ cc_test {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
-        "libcuttlefish_utils_result",
         "libcuttlefish_security",
+        "libcuttlefish_utils_result",
         "libgatekeeper",
         "libkeymaster_messages",
         "liblog",
diff --git a/common/libs/transport/Android.bp b/common/libs/transport/Android.bp
index c4e1b9c9c..bb5651f64 100644
--- a/common/libs/transport/Android.bp
+++ b/common/libs/transport/Android.bp
@@ -30,12 +30,12 @@ cc_library {
     target: {
         linux: {
             srcs: ["channel_sharedfd.cpp"],
-            shared_libs: ["libcuttlefish_fs"]
+            shared_libs: ["libcuttlefish_fs"],
         },
         darwin: {
             enabled: true,
             srcs: ["channel_sharedfd.cpp"],
-            shared_libs: ["libcuttlefish_fs"]
+            shared_libs: ["libcuttlefish_fs"],
         },
         windows: {
             enabled: true,
diff --git a/common/libs/utils/flag_parser.cpp b/common/libs/utils/flag_parser.cpp
index b02500026..9e1c975f5 100644
--- a/common/libs/utils/flag_parser.cpp
+++ b/common/libs/utils/flag_parser.cpp
@@ -36,7 +36,7 @@
 #include <android-base/parsebool.h>
 #include <android-base/scopeguard.h>
 #include <android-base/strings.h>
-#include <fmt/format.h>
+#include <fmt/ranges.h>
 
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/tee_logging.h"
diff --git a/common/libs/utils/network.cpp b/common/libs/utils/network.cpp
index e99266c53..eeceeb75c 100644
--- a/common/libs/utils/network.cpp
+++ b/common/libs/utils/network.cpp
@@ -41,7 +41,7 @@
 
 #include <android-base/logging.h>
 #include <android-base/strings.h>
-#include <fmt/format.h>
+#include <fmt/ranges.h>
 
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/subprocess.h"
@@ -100,11 +100,11 @@ bool NetworkInterfaceExists(const std::string& interface_name) {
 }
 
 #ifdef __linux__
-static std::optional<Command> EgrepCommand() {
-  if (FileExists("/usr/bin/egrep")) {
-    return Command("/usr/bin/egrep");
-  } else if (FileExists("/bin/egrep")) {
-    return Command("/bin/egrep");
+static std::optional<Command> GrepCommand() {
+  if (FileExists("/usr/bin/grep")) {
+    return Command("/usr/bin/grep");
+  } else if (FileExists("/bin/grep")) {
+    return Command("/bin/grep");
   } else {
     return {};
   }
@@ -131,12 +131,13 @@ std::set<std::string> TapInterfacesInUse() {
     }
   }
 
-  std::optional<Command> cmd = EgrepCommand();
+  std::optional<Command> cmd = GrepCommand();
   if (!cmd) {
     LOG(WARNING) << "Unable to test TAP interface usage";
     return {};
   }
-  cmd->AddParameter("-h").AddParameter("-e").AddParameter("^iff:.*");
+  cmd->AddParameter("-E").AddParameter("-h").AddParameter("-e").AddParameter(
+      "^iff:.*");
 
   for (const std::string& fdinfo : fdinfo_list) {
     cmd->AddParameter(fdinfo);
diff --git a/guest/commands/bt_vhci_forwarder/Android.bp b/guest/commands/bt_vhci_forwarder/Android.bp
index 45308bacf..9cf85dab1 100644
--- a/guest/commands/bt_vhci_forwarder/Android.bp
+++ b/guest/commands/bt_vhci_forwarder/Android.bp
@@ -32,5 +32,5 @@ cc_binary {
     static_libs: [
         "libgflags",
     ],
-    defaults: ["cuttlefish_guest_only"]
+    defaults: ["cuttlefish_guest_only"],
 }
diff --git a/guest/commands/dlkm_loader/Android.bp b/guest/commands/dlkm_loader/Android.bp
index ae91c0248..fbbc01882 100644
--- a/guest/commands/dlkm_loader/Android.bp
+++ b/guest/commands/dlkm_loader/Android.bp
@@ -29,5 +29,5 @@ cc_binary {
     shared_libs: [
         "liblog",
     ],
-    defaults: ["cuttlefish_guest_only"]
+    defaults: ["cuttlefish_guest_only"],
 }
diff --git a/guest/commands/rename_netiface/Android.bp b/guest/commands/rename_netiface/Android.bp
index 3cf422503..a35d5b8e5 100644
--- a/guest/commands/rename_netiface/Android.bp
+++ b/guest/commands/rename_netiface/Android.bp
@@ -13,7 +13,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -27,5 +26,5 @@ cc_binary {
     shared_libs: [
         "cuttlefish_net",
     ],
-    defaults: ["cuttlefish_guest_only"]
+    defaults: ["cuttlefish_guest_only"],
 }
diff --git a/guest/commands/setup_wifi/Android.bp b/guest/commands/setup_wifi/Android.bp
index e7a85bb84..9b3c05e72 100644
--- a/guest/commands/setup_wifi/Android.bp
+++ b/guest/commands/setup_wifi/Android.bp
@@ -13,7 +13,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -33,5 +32,5 @@ cc_binary {
     static_libs: [
         "libgflags",
     ],
-    defaults: ["cuttlefish_guest_only"]
+    defaults: ["cuttlefish_guest_only"],
 }
diff --git a/guest/commands/v4l2_streamer/Android.bp b/guest/commands/v4l2_streamer/Android.bp
index 02cab5675..96bf01d77 100644
--- a/guest/commands/v4l2_streamer/Android.bp
+++ b/guest/commands/v4l2_streamer/Android.bp
@@ -22,21 +22,21 @@ cc_binary {
     srcs: [
         "main.cpp",
         "v4l2_helpers.cpp",
-        "yuv2rgb.cpp",
         "vsock_frame_source.cpp",
+        "yuv2rgb.cpp",
     ],
     shared_libs: [
         "libbase",
         "libbinder_ndk",
+        "libcuttlefish_fs",
+        "libjsoncpp",
         "liblog",
         "libutils",
         "libvsock_utils",
-        "libjsoncpp",
-        "libcuttlefish_fs",
     ],
     static_libs: [
-        "libgflags",
         "libcuttlefish_utils",
+        "libgflags",
     ],
     defaults: ["cuttlefish_guest_only"],
 }
diff --git a/guest/hals/camera/Android.bp b/guest/hals/camera/Android.bp
index c6c87329f..abda341ca 100644
--- a/guest/hals/camera/Android.bp
+++ b/guest/hals/camera/Android.bp
@@ -40,14 +40,14 @@ cc_library_shared {
     proprietary: true,
     relative_install_path: "hw",
     srcs: [
-        "vsock_camera_provider_2_7.cpp",
+        "cached_stream_buffer.cpp",
+        "stream_buffer_cache.cpp",
         "vsock_camera_device_3_4.cpp",
         "vsock_camera_device_session_3_4.cpp",
         "vsock_camera_metadata.cpp",
+        "vsock_camera_provider_2_7.cpp",
         "vsock_camera_server.cpp",
         "vsock_frame_provider.cpp",
-        "cached_stream_buffer.cpp",
-        "stream_buffer_cache.cpp",
     ],
     shared_libs: [
         "android.hardware.camera.common@1.0",
@@ -57,11 +57,11 @@ cc_library_shared {
         "android.hardware.camera.device@3.4",
         "android.hardware.camera.device@3.5",
         "android.hardware.camera.provider@2.4",
+        "android.hardware.camera.provider@2.4-external",
+        "android.hardware.camera.provider@2.4-legacy",
         "android.hardware.camera.provider@2.5",
         "android.hardware.camera.provider@2.6",
         "android.hardware.camera.provider@2.7",
-        "android.hardware.camera.provider@2.4-external",
-        "android.hardware.camera.provider@2.4-legacy",
         "android.hardware.graphics.mapper@2.0",
         "android.hardware.graphics.mapper@3.0",
         "android.hardware.graphics.mapper@4.0",
@@ -73,18 +73,18 @@ cc_library_shared {
         "camera.device@3.4-impl",
         "libcamera_metadata",
         "libcutils",
+        "libcuttlefish_fs",
+        "libfmq",
+        "libgralloctypes",
         "libhardware",
         "libhidlbase",
+        "libjsoncpp",
         "liblog",
-        "libutils",
+        "libsync",
         "libui",
+        "libutils",
         "libvsock_utils",
-        "libcuttlefish_fs",
-        "libjsoncpp",
         "libyuv",
-        "libsync",
-        "libfmq",
-        "libgralloctypes",
     ],
     header_libs: [
         "camera.device@3.4-external-impl_headers",
diff --git a/guest/hals/confirmationui/Android.bp b/guest/hals/confirmationui/Android.bp
index 4ead768c9..84b1ed8e1 100644
--- a/guest/hals/confirmationui/Android.bp
+++ b/guest/hals/confirmationui/Android.bp
@@ -25,7 +25,10 @@ package {
 
 cc_binary {
     name: "android.hardware.confirmationui-service.cuttlefish",
-    defaults: ["cuttlefish_guest_only"],
+    defaults: [
+        "cuttlefish_guest_only",
+        "keymint_use_latest_hal_aidl_ndk_static",
+    ],
     relative_install_path: "hw",
     vendor: true,
 
@@ -37,17 +40,16 @@ cc_binary {
     ],
 
     static_libs: [
-        "android.hardware.confirmationui-lib.cuttlefish",
         "android.hardware.confirmationui-V1-ndk",
-        "android.hardware.security.keymint-V3-ndk",
+        "android.hardware.confirmationui-lib.cuttlefish",
         "android.hardware.security.secureclock-V1-ndk",
         "libbase",
         "libcutils",
         "libcuttlefish_confui",
-        "libteeui_hal_support",
-        "libutils",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libteeui_hal_support",
+        "libutils",
     ],
 
     srcs: [
@@ -55,9 +57,9 @@ cc_binary {
     ],
 
     cflags: [
+        "-DTEEUI_USE_STD_VECTOR",
         "-Wall",
         "-Werror",
-        "-DTEEUI_USE_STD_VECTOR",
     ],
 
     installable: false, // installed in APEX
@@ -93,9 +95,9 @@ cc_library {
         "libcuttlefish_utils",
     ],
     cflags: [
+        "-DTEEUI_USE_STD_VECTOR",
         "-Wall",
         "-Werror",
-        "-DTEEUI_USE_STD_VECTOR",
     ],
 }
 
diff --git a/guest/hals/gatekeeper/remote/Android.bp b/guest/hals/gatekeeper/remote/Android.bp
index 3b35ae75e..be9d0a035 100644
--- a/guest/hals/gatekeeper/remote/Android.bp
+++ b/guest/hals/gatekeeper/remote/Android.bp
@@ -29,9 +29,9 @@ cc_binary {
     ],
 
     cflags: [
-        "-fvisibility=hidden",
         "-Wall",
         "-Werror",
+        "-fvisibility=hidden",
     ],
 
     static_libs: [
@@ -40,18 +40,18 @@ cc_binary {
 
     shared_libs: [
         "android.hardware.gatekeeper-V1-ndk",
-        "libbinder_ndk",
-        "libhardware",
         "libbase",
+        "libbinder_ndk",
+        "libcutils",
         "libcuttlefish_fs",
         "libcuttlefish_security",
         "libcuttlefish_transport",
-        "libhidlbase",
         "libgatekeeper",
-        "libutils",
+        "libhardware",
+        "libhidlbase",
         "liblog",
-        "libcutils",
         "libtrusty",
+        "libutils",
     ],
 }
 
@@ -81,7 +81,7 @@ apex {
         "android.hardware.gatekeeper-service.remote",
     ],
     prebuilts: [
-        "android.hardware.gatekeeper-service.remote.xml",
         "android.hardware.gatekeeper-service.remote.rc",
+        "android.hardware.gatekeeper-service.remote.xml",
     ],
 }
diff --git a/guest/hals/health/Android.bp b/guest/hals/health/Android.bp
index f24ea4aaa..704921fcd 100644
--- a/guest/hals/health/Android.bp
+++ b/guest/hals/health/Android.bp
@@ -31,7 +31,7 @@ cc_defaults {
     ],
 
     static_libs: [
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libbase",
         "libbatterymonitor",
         "libcutils",
@@ -115,16 +115,16 @@ cc_library_shared {
     static_libs: [
         "android.hardware.health@1.0-convert",
         "libbatterymonitor",
-        "libhealthloop",
         "libhealth2impl",
+        "libhealthloop",
     ],
 
     shared_libs: [
+        "android.hardware.health@2.0",
+        "android.hardware.health@2.1",
         "libbase",
         "libcutils",
         "libhidlbase",
         "libutils",
-        "android.hardware.health@2.0",
-        "android.hardware.health@2.1",
     ],
 }
diff --git a/guest/hals/health/android.hardware.health-service.cuttlefish.xml b/guest/hals/health/android.hardware.health-service.cuttlefish.xml
index 2acaabacb..8ddfbdaae 100644
--- a/guest/hals/health/android.hardware.health-service.cuttlefish.xml
+++ b/guest/hals/health/android.hardware.health-service.cuttlefish.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.health</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IHealth/default</fqname>
     </hal>
 </manifest>
diff --git a/guest/hals/identity/Android.bp b/guest/hals/identity/Android.bp
index 30d0d67a8..865522a26 100644
--- a/guest/hals/identity/Android.bp
+++ b/guest/hals/identity/Android.bp
@@ -28,38 +28,38 @@ cc_binary {
     ],
     stl: "c++_static",
     shared_libs: [
-        "liblog",
-        "libcrypto",
         "libbinder_ndk",
+        "libcrypto",
+        "liblog",
     ],
     static_libs: [
+        "android.hardware.identity-V3-ndk",
+        "android.hardware.identity-support-lib",
+        "android.hardware.keymaster-V3-ndk",
+        "android.hardware.security.keymint-V1-ndk",
         "libbase",
         "libcppbor",
         "libcppcose_rkp",
-        "libutils",
-        "libsoft_attestation_cert",
         "libkeymaster_portable",
-        "libsoft_attestation_cert",
         "libpuresoftkeymasterdevice",
-        "android.hardware.identity-support-lib",
-        "android.hardware.identity-V3-ndk",
-        "android.hardware.keymaster-V3-ndk",
-        "android.hardware.security.keymint-V1-ndk",
+        "libsoft_attestation_cert",
+        "libsoft_attestation_cert",
+        "libutils",
     ],
     local_include_dirs: [
         "common",
         "libeic",
     ],
     srcs: [
-        "service.cpp",
         "RemoteSecureHardwareProxy.cpp",
         "common/IdentityCredential.cpp",
         "common/IdentityCredentialStore.cpp",
         "common/WritableIdentityCredential.cpp",
         "libeic/EicCbor.c",
+        "libeic/EicOpsImpl.cc",
         "libeic/EicPresentation.c",
         "libeic/EicProvisioning.c",
-        "libeic/EicOpsImpl.cc",
+        "service.cpp",
     ],
     installable: false, // installed in APEX
 }
diff --git a/guest/hals/keymint/remote/Android.bp b/guest/hals/keymint/remote/Android.bp
index 3f66420ae..ed8dcc397 100644
--- a/guest/hals/keymint/remote/Android.bp
+++ b/guest/hals/keymint/remote/Android.bp
@@ -23,8 +23,8 @@ cc_binary {
     init_rc: ["android.hardware.security.keymint-service.remote.rc"],
     vintf_fragments: [
         "android.hardware.security.keymint-service.remote.xml",
-        "android.hardware.security.sharedsecret-service.remote.xml",
         "android.hardware.security.secureclock-service.remote.xml",
+        "android.hardware.security.sharedsecret-service.remote.xml",
     ],
     vendor: true,
     cflags: [
@@ -32,10 +32,11 @@ cc_binary {
         "-Wextra",
     ],
     shared_libs: [
+        "android.hardware.security.keymint-V3-ndk",
         "android.hardware.security.rkp-V3-ndk",
         "android.hardware.security.secureclock-V1-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
-        "lib_android_keymaster_keymint_utils",
+        "lib_android_keymaster_keymint_utils_V3",
         "libbase",
         "libbinder_ndk",
         "libcppbor",
@@ -44,14 +45,14 @@ cc_binary {
         "libcuttlefish_security",
         "libhardware",
         "libkeymaster_messages",
-        "libkeymint",
+        "libkeymasterconfig_V3",
         "liblog",
         "libutils",
     ],
     srcs: [
+        "remote_keymaster.cpp",
         "remote_keymint_device.cpp",
         "remote_keymint_operation.cpp",
-        "remote_keymaster.cpp",
         "remote_remotely_provisioned_component.cpp",
         "remote_secure_clock.cpp",
         "remote_shared_secret.cpp",
@@ -59,7 +60,6 @@ cc_binary {
     ],
     defaults: [
         "cuttlefish_guest_only",
-        "keymint_use_latest_hal_aidl_ndk_shared",
     ],
     required: [
         "android.hardware.hardware_keystore.remote-keymint.xml",
diff --git a/guest/hals/keymint/remote/remote_keymint_device.cpp b/guest/hals/keymint/remote/remote_keymint_device.cpp
index 0fc9c5d88..51ee10933 100644
--- a/guest/hals/keymint/remote/remote_keymint_device.cpp
+++ b/guest/hals/keymint/remote/remote_keymint_device.cpp
@@ -116,6 +116,7 @@ vector<KeyCharacteristics> convertKeyCharacteristics(
       case KM_TAG_RESET_SINCE_ID_ROTATION:
       case KM_TAG_ROOT_OF_TRUST:
       case KM_TAG_UNIQUE_ID:
+      case KM_TAG_MODULE_HASH:
         break;
 
       /* KeyMint-enforced */
diff --git a/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml b/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml
index 4c755969e..1ab21336d 100644
--- a/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml
+++ b/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml
@@ -14,5 +14,5 @@
      limitations under the License.
 -->
 <permissions>
-  <feature name="android.hardware.hardware_keystore" version="300" />
+  <feature name="android.hardware.hardware_keystore" version="400" />
 </permissions>
diff --git a/guest/hals/keymint/rust/android.hardware.security.keymint-service.rust.xml b/guest/hals/keymint/rust/android.hardware.security.keymint-service.rust.xml
index 0568ae643..6bdd33ebf 100644
--- a/guest/hals/keymint/rust/android.hardware.security.keymint-service.rust.xml
+++ b/guest/hals/keymint/rust/android.hardware.security.keymint-service.rust.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.security.keymint</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IKeyMintDevice/default</fqname>
     </hal>
     <hal format="aidl">
diff --git a/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
index 5b493c4d4..3bef1d1ed 100644
--- a/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
+++ b/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl" updatable-via-system="true">
         <name>android.hardware.security.keymint</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IKeyMintDevice/default</fqname>
     </hal>
     <hal format="aidl" updatable-via-system="true">
diff --git a/guest/hals/light/Android.bp b/guest/hals/light/Android.bp
index 37bef51cd..04516735f 100644
--- a/guest/hals/light/Android.bp
+++ b/guest/hals/light/Android.bp
@@ -8,18 +8,18 @@ rust_binary {
     vendor: true,
     prefer_rlib: true,
     rustlibs: [
-        "liblogger",
-        "liblog_rust",
-        "libbinder_rs",
         "android.hardware.light-V2-rust",
-        "libvsock",
-        "librustutils",
-        "libserde_json",
         "libanyhow",
-        "libserde",
+        "libbinder_rs",
+        "liblog_rust",
+        "liblogger",
         "libnix",
+        "librustutils",
+        "libserde",
+        "libserde_json",
+        "libvsock",
     ],
-    srcs: [ "main.rs" ],
+    srcs: ["main.rs"],
     installable: false, // installed in APEX
 }
 
diff --git a/guest/hals/nfc/Android.bp b/guest/hals/nfc/Android.bp
index 79ecb6b82..d3bf7d808 100644
--- a/guest/hals/nfc/Android.bp
+++ b/guest/hals/nfc/Android.bp
@@ -23,19 +23,19 @@ rust_binary {
     vendor: true,
     prefer_rlib: true,
     rustlibs: [
+        "android.hardware.nfc-V2-rust",
         "libandroid_logger",
-        "liblog_rust",
+        "libanyhow",
         "libbinder_rs",
         "libbinder_tokio_rs",
-        "libtokio",
+        "libbytes",
+        "libclap",
         "liblibc",
+        "liblog_rust",
         "libnix",
-        "libclap",
-        "android.hardware.nfc-V2-rust",
-        "libanyhow",
-        "libthiserror",
-        "libbytes",
         "libpdl_runtime",
+        "libthiserror",
+        "libtokio",
     ],
     proc_macros: [
         "libasync_trait",
@@ -43,6 +43,7 @@ rust_binary {
     features: ["rt"],
     srcs: [
         "src/main.rs",
+        // TODO(b/381337280): src/main.rs must come first but bpfmt breaks this order without this comment.
         ":casimir_nci_packets_rust_gen",
     ],
 }
@@ -71,10 +72,10 @@ apex {
 
     binaries: ["android.hardware.nfc-service.cuttlefish"],
     prebuilts: [
-        "nfc-service-cuttlefish.rc", // init_rc
-        "nfc-service-cuttlefish.xml", // vintf_fragments
-        "android.hardware.nfc.prebuilt.xml", // permission
         "android.hardware.nfc.hce.prebuilt.xml", // permission
+        "android.hardware.nfc.prebuilt.xml", // permission
         "libnfc-hal-cf.conf-default", // conf
+        "nfc-service-cuttlefish.rc", // init_rc
+        "nfc-service-cuttlefish.xml", // vintf_fragments
     ],
 }
diff --git a/guest/hals/oemlock/remote/Android.bp b/guest/hals/oemlock/remote/Android.bp
index 1df5aae58..a0bdc85c8 100644
--- a/guest/hals/oemlock/remote/Android.bp
+++ b/guest/hals/oemlock/remote/Android.bp
@@ -33,9 +33,9 @@ cc_binary {
         "android.hardware.oemlock-V1-ndk",
         "libbase",
         "libcuttlefish_fs",
-        "libcuttlefish_utils",
         "libcuttlefish_security",
         "libcuttlefish_transport",
+        "libcuttlefish_utils",
     ],
 
     stl: "c++_static",
diff --git a/guest/hals/ril/reference-libril/Android.bp b/guest/hals/ril/reference-libril/Android.bp
index e73d56348..0ff8dfcf4 100644
--- a/guest/hals/ril/reference-libril/Android.bp
+++ b/guest/hals/ril/reference-libril/Android.bp
@@ -18,21 +18,22 @@ package {
 
 cc_library {
     name: "libril-modem-lib",
+    defaults: ["android.hardware.radio-library.aidl_deps"],
     vendor: true,
     cflags: [
         "-Wextra",
         "-Wno-unused-parameter",
     ],
     srcs: [
-        "RefRadioSim.cpp",
-        "RefRadioModem.cpp",
-        "RefRadioIms.cpp",
         "RefImsMedia.cpp",
         "RefImsMediaSession.cpp",
-        "RefRadioNetwork.cpp",
         "RefRadioConfig.cpp",
-        "ril.cpp",
+        "RefRadioIms.cpp",
+        "RefRadioModem.cpp",
+        "RefRadioNetwork.cpp",
+        "RefRadioSim.cpp",
         "RilSapSocket.cpp",
+        "ril.cpp",
         "ril_config.cpp",
         "ril_event.cpp",
         "ril_service.cpp",
@@ -44,16 +45,11 @@ cc_library {
     ],
     shared_libs: [
         "android.hardware.radio-library.compat",
-        "android.hardware.radio.config-V3-ndk",
-        "android.hardware.radio.data-V3-ndk",
-        "android.hardware.radio.ims-V2-ndk",
-        "android.hardware.radio.ims.media-V2-ndk",
-        "android.hardware.radio.messaging-V3-ndk",
-        "android.hardware.radio.modem-V3-ndk",
-        "android.hardware.radio.network-V3-ndk",
-        "android.hardware.radio.sap-V1-ndk",
-        "android.hardware.radio.sim-V3-ndk",
-        "android.hardware.radio.voice-V3-ndk",
+        "android.hardware.radio.config@1.0",
+        "android.hardware.radio.config@1.1",
+        "android.hardware.radio.config@1.2",
+        "android.hardware.radio.config@1.3",
+        "android.hardware.radio.deprecated@1.0",
         "android.hardware.radio@1.0",
         "android.hardware.radio@1.1",
         "android.hardware.radio@1.2",
@@ -61,11 +57,6 @@ cc_library {
         "android.hardware.radio@1.4",
         "android.hardware.radio@1.5",
         "android.hardware.radio@1.6",
-        "android.hardware.radio.config@1.0",
-        "android.hardware.radio.config@1.1",
-        "android.hardware.radio.config@1.2",
-        "android.hardware.radio.config@1.3",
-        "android.hardware.radio.deprecated@1.0",
         "libbase",
         "libbinder_ndk",
         "libcutils",
diff --git a/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml b/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
index a581292ec..5409b9bf8 100644
--- a/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
+++ b/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
@@ -1,42 +1,42 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.radio.config</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioConfig/default</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.data</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioData/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.ims</name>
-        <version>2</version>
+        <version>3</version>
         <fqname>IRadioIms/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.ims.media</name>
-        <version>2</version>
+        <version>3</version>
         <fqname>IImsMedia/default</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.messaging</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioMessaging/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.modem</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioModem/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.network</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioNetwork/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.sim</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioSim/slot1</fqname>
     </hal>
     <hal format="aidl">
@@ -45,7 +45,7 @@
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.voice</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioVoice/slot1</fqname>
     </hal>
 </manifest>
diff --git a/guest/hals/ril/reference-libril/ril.cpp b/guest/hals/ril/reference-libril/ril.cpp
index a40ec5062..d56d7a49c 100644
--- a/guest/hals/ril/reference-libril/ril.cpp
+++ b/guest/hals/ril/reference-libril/ril.cpp
@@ -1057,17 +1057,17 @@ callStateToString(RIL_CallState s) {
 
 const char *
 requestToString(int request) {
-/*
- cat guest/hals/ril/reference-libril/ril_commands.h \
- | egrep "^ *{RIL_" \
- | sed -re 's/\{RIL_([^,]+),[^,]+,([^}]+).+/case RIL_\1: return "\1";/'
+    /*
+     cat guest/hals/ril/reference-libril/ril_commands.h \
+     | grep -E "^ *{RIL_" \
+     | sed -re 's/\{RIL_([^,]+),[^,]+,([^}]+).+/case RIL_\1: return "\1";/'
 
 
- cat guest/hals/ril/reference-libril/ril_unsol_commands.h \
- | egrep "^ *{RIL_" \
- | sed -re 's/\{RIL_([^,]+),([^}]+).+/case RIL_\1: return "\1";/'
+     cat guest/hals/ril/reference-libril/ril_unsol_commands.h \
+     | grep -E "^ *{RIL_" \
+     | sed -re 's/\{RIL_([^,]+),([^}]+).+/case RIL_\1: return "\1";/'
 
-*/
+    */
     switch(request) {
         case RIL_REQUEST_GET_SIM_STATUS: return "GET_SIM_STATUS";
         case RIL_REQUEST_ENTER_SIM_PIN: return "ENTER_SIM_PIN";
diff --git a/guest/hals/ril/reference-ril/Android.bp b/guest/hals/ril/reference-ril/Android.bp
index de01ae131..c0f7df4fb 100644
--- a/guest/hals/ril/reference-ril/Android.bp
+++ b/guest/hals/ril/reference-ril/Android.bp
@@ -35,18 +35,18 @@ cc_library {
     name: "libcuttlefish-ril-2",
     vendor: true,
     cflags: [
-        "-D_GNU_SOURCE",
         "-DCUTTLEFISH_ENABLE",
         "-DRIL_SHLIB",
+        "-D_GNU_SOURCE",
         "-Wall",
+        "-Werror",
         "-Wextra",
-        "-Wno-unused-variable",
         "-Wno-unused-function",
-        "-Werror",
+        "-Wno-unused-variable",
     ],
     srcs: [
-        "atchannel.c",
         "at_tok.c",
+        "atchannel.c",
         "base64util.cpp",
         "misc.c",
         "reference-ril.c",
@@ -60,8 +60,8 @@ cc_library {
         "libcuttlefish_fs",
         "libcuttlefish_utils",
         "liblog",
-        "librilutils",
         "libril-modem-lib",
+        "librilutils",
         "libutils",
     ],
 }
diff --git a/guest/hals/ril/reference-ril/reference-ril.c b/guest/hals/ril/reference-ril/reference-ril.c
index bcb8ba333..c96365b37 100644
--- a/guest/hals/ril/reference-ril/reference-ril.c
+++ b/guest/hals/ril/reference-ril/reference-ril.c
@@ -4396,7 +4396,7 @@ void getConfigSlotStatus(RIL_SimSlotStatus_V1_2 *pSimSlotStatus) {
     pSimSlotStatus->eid = "";
 }
 
-void sendUnsolNetworkScanResult() {
+void sendUnsolNetworkScanResult(void *param __unused) {
     RIL_NetworkScanResult scanr;
     memset(&scanr, 0, sizeof(scanr));
     scanr.status = COMPLETE;
diff --git a/guest/hals/vehicle/Android.bp b/guest/hals/vehicle/Android.bp
index ac18d07fe..ad092c09f 100644
--- a/guest/hals/vehicle/Android.bp
+++ b/guest/hals/vehicle/Android.bp
@@ -25,7 +25,6 @@ vintf_fragment {
 cc_binary {
     name: "android.hardware.automotive.vehicle@V3-cf-service",
     defaults: ["VehicleHalDefaults"],
-    init_rc: ["android.hardware.automotive.vehicle@V3-cf-service.rc"],
     vendor: true,
     relative_install_path: "hw",
     srcs: [
diff --git a/guest/hals/vehicle/VehicleService.cpp b/guest/hals/vehicle/VehicleService.cpp
index 173eea0aa..b70b421a3 100644
--- a/guest/hals/vehicle/VehicleService.cpp
+++ b/guest/hals/vehicle/VehicleService.cpp
@@ -34,11 +34,30 @@ using ::android::hardware::automotive::vehicle::DefaultVehicleHal;
 using ::android::hardware::automotive::vehicle::virtualization::
     GRPCVehicleHardware;
 
-const char* SERVICE_NAME =
+const char* kServiceName =
     "android.hardware.automotive.vehicle.IVehicle/default";
-const char* BOOTCONFIG_PORT = "ro.boot.vhal_proxy_server_port";
+const char* kBootConfigPort = "ro.boot.vhal_proxy_server_port";
+const char* kAutoEthNamespaceSetupProp =
+    "android.car.auto_eth_namespace_setup_complete";
+const char* kVsockServiceName = "vendor.vehicle-cf-vsock";
+const char* kEthServerAddr = "192.168.98.1";
+
+int main(int argc, char* argv[]) {
+  bool useVsock = false;
+
+  if (argc > 1 && strcmp(argv[1], "vsock") == 0) {
+    if (property_get_bool(kAutoEthNamespaceSetupProp, false)) {
+      LOG(INFO) << "Skip starting VHAL in vsock mode since ethernet is enabled";
+      return 0;
+    }
+
+    // If we are not exiting intentionally, we need to turn off oneshot so that
+    // VHAL will be restarted in case it exits. vendor.vehicle-cf-eth does not
+    // have oneshot in the rc file so nothing to do here.
+    property_set("ctl.oneshot_off", kVsockServiceName);
+    useVsock = true;
+  }
 
-int main(int /* argc */, char* /* argv */[]) {
   LOG(INFO) << "Starting thread pool...";
   if (!ABinderProcess_setThreadPoolMaxThreadCount(4)) {
     LOG(ERROR) << "Failed to set thread pool max thread count.";
@@ -46,24 +65,30 @@ int main(int /* argc */, char* /* argv */[]) {
   }
   ABinderProcess_startThreadPool();
 
-  VsockConnectionInfo vsock = {
-      .cid = VMADDR_CID_HOST,
-      .port =
-          static_cast<unsigned int>(property_get_int32(BOOTCONFIG_PORT, -1)),
-  };
-  CHECK(vsock.port >= 0) << "Failed to read port number from: "
-                         << BOOTCONFIG_PORT;
-  std::string vsockStr = vsock.str();
+  unsigned int port =
+      static_cast<unsigned int>(property_get_int32(kBootConfigPort, -1));
+  CHECK(port >= 0) << "Failed to read port number from: " << kBootConfigPort;
 
-  LOG(INFO) << "Connecting to vsock server at " << vsockStr;
+  std::string serverAddr;
+  if (useVsock) {
+    VsockConnectionInfo vsock = {
+        .cid = VMADDR_CID_HOST,
+        .port = port,
+    };
+    serverAddr = vsock.str();
+    LOG(INFO) << "Connecting to vsock server at " << serverAddr;
+  } else {
+    serverAddr = fmt::format("{}:{}", kEthServerAddr, port);
+    LOG(INFO) << "Connecting to ethernet server at " << serverAddr;
+  }
 
   constexpr auto maxConnectWaitTime = std::chrono::seconds(5);
-  auto hardware = std::make_unique<GRPCVehicleHardware>(vsockStr);
+  auto hardware = std::make_unique<GRPCVehicleHardware>(serverAddr);
   if (const auto connected = hardware->waitForConnected(maxConnectWaitTime)) {
-    LOG(INFO) << "Connected to vsock server at " << vsockStr;
+    LOG(INFO) << "Connected to GRPC server at " << serverAddr;
   } else {
     LOG(INFO)
-        << "Failed to connect to vsock server at " << vsockStr
+        << "Failed to connect to GRPC server at " << serverAddr
         << ", check if it is working, or maybe the server is coming up late.";
     return 1;
   }
@@ -72,15 +97,15 @@ int main(int /* argc */, char* /* argv */[]) {
       ::ndk::SharedRefBase::make<DefaultVehicleHal>(std::move(hardware));
   LOG(INFO) << "Registering as service...";
   binder_exception_t err =
-      AServiceManager_addService(vhal->asBinder().get(), SERVICE_NAME);
-  CHECK(err == EX_NONE) << "Failed to register " << SERVICE_NAME
+      AServiceManager_addService(vhal->asBinder().get(), kServiceName);
+  CHECK(err == EX_NONE) << "Failed to register " << kServiceName
                         << " service, exception: " << err << ".";
 
   LOG(INFO) << "Vehicle Service Ready.";
 
   ABinderProcess_joinThreadPool();
 
-  LOG(INFO) << "Vehicle Service Exiting.";
+  LOG(INFO) << "Vehicle Service Exiting, must not happen!.";
 
   return 0;
 }
diff --git a/guest/hals/vehicle/android.hardware.automotive.vehicle@V3-cf-service.rc b/guest/hals/vehicle/android.hardware.automotive.vehicle@V3-cf-service.rc
deleted file mode 100644
index 5196c8dec..000000000
--- a/guest/hals/vehicle/android.hardware.automotive.vehicle@V3-cf-service.rc
+++ /dev/null
@@ -1,4 +0,0 @@
-service vendor.vehicle-hal-trout /vendor/bin/hw/android.hardware.automotive.vehicle@V3-cf-service
-    class early_hal
-    user vehicle_network
-    group system inet
\ No newline at end of file
diff --git a/guest/hals/vehicle/apex/com.android.hardware.automotive.vehicle.cf.rc b/guest/hals/vehicle/apex/com.android.hardware.automotive.vehicle.cf.rc
index ad2c193a8..93fcaf647 100644
--- a/guest/hals/vehicle/apex/com.android.hardware.automotive.vehicle.cf.rc
+++ b/guest/hals/vehicle/apex/com.android.hardware.automotive.vehicle.cf.rc
@@ -1,4 +1,27 @@
-service vendor.vehicle-cf /apex/com.android.hardware.automotive.vehicle/bin/hw/android.hardware.automotive.vehicle@V3-cf-service
+# This is the regular VHAL using ethernet. It runs in regular build.
+service vendor.vehicle-cf-eth /apex/com.android.hardware.automotive.vehicle/bin/hw/android.hardware.automotive.vehicle@V3-cf-service eth
     class early_hal
     user vehicle_network
-    group system inet
\ No newline at end of file
+    group system inet
+    enter_namespace net /mnt/run/auto_eth
+    disabled
+
+# This is the VHAL running in vsock mode in case ethernet namespace is not set
+# up, e.g. in GSI build.
+# Set this as one-shot because this service will do nothing and exit if
+# property:android.car.auto_eth_namespace_setup_complete is 1.
+service vendor.vehicle-cf-vsock /apex/com.android.hardware.automotive.vehicle/bin/hw/android.hardware.automotive.vehicle@V3-cf-service vsock
+    class early_hal
+    user vehicle_network
+    group system inet
+    oneshot
+
+# Only enable vendor.vehicle-cf-eth when we know network namespace is set up.
+# Otherwise, enter_namespace will fail.
+# Ideally we should only enable vendor.vehicle-cf when we know network namespace
+# is not set up. However, init does not have a check if a property is unset.
+# As a result, we will run both vendor.vehicle-cf and vendor.vehicle-cf-eth
+# if the network namespace is set up. vendor.vehicle-cf will exit if it detects
+# the network namespace property is set.
+on late-fs && property:android.car.auto_eth_namespace_setup_complete=1
+    enable vendor.vehicle-cf-eth
diff --git a/guest/hals/vulkan/Android.bp b/guest/hals/vulkan/Android.bp
index 8d974dafb..43f359efc 100644
--- a/guest/hals/vulkan/Android.bp
+++ b/guest/hals/vulkan/Android.bp
@@ -58,13 +58,13 @@ apex {
         "vulkan.ranchu",
     ],
     prebuilts: [
-        "com.google.cf.vulkan.rc",
-        "com.google.cf.vulkan-linker-config",
-        "android.hardware.vulkan.level-1.prebuilt.xml",
         "android.hardware.vulkan.compute-0.prebuilt.xml",
+        "android.hardware.vulkan.level-1.prebuilt.xml",
         "android.hardware.vulkan.version-1_3.prebuilt.xml",
-        "android.software.vulkan.deqp.level-latest.prebuilt.xml",
         "android.software.opengles.deqp.level-latest.prebuilt.xml",
+        "android.software.vulkan.deqp.level-latest.prebuilt.xml",
+        "com.google.cf.vulkan-linker-config",
+        "com.google.cf.vulkan.rc",
     ],
 }
 
diff --git a/guest/monitoring/cuttlefish_service/Android.bp b/guest/monitoring/cuttlefish_service/Android.bp
index 133d233c2..05c24c68c 100644
--- a/guest/monitoring/cuttlefish_service/Android.bp
+++ b/guest/monitoring/cuttlefish_service/Android.bp
@@ -26,5 +26,5 @@ android_app {
     optimize: {
         proguard_flags_files: ["proguard.flags"],
         enabled: true,
-    }
+    },
 }
diff --git a/guest/monitoring/tombstone_transmit/Android.bp b/guest/monitoring/tombstone_transmit/Android.bp
index add2ace10..95d6867c1 100644
--- a/guest/monitoring/tombstone_transmit/Android.bp
+++ b/guest/monitoring/tombstone_transmit/Android.bp
@@ -20,9 +20,9 @@ package {
 cc_defaults {
     name: "tombstone_transmit_defaults",
     static_libs: [
-        "libgflags",
         "libbase",
         "libcutils",
+        "libgflags",
     ],
     shared_libs: [
         "liblog",
@@ -40,8 +40,8 @@ cc_binary {
         "libcuttlefish_utils",
     ],
     defaults: [
+        "cuttlefish_guest_product_only",
         "tombstone_transmit_defaults",
-        "cuttlefish_guest_product_only"
     ],
 }
 
@@ -57,8 +57,8 @@ cc_binary {
         "libcuttlefish_utils",
     ],
     defaults: [
-        "tombstone_transmit_defaults",
         "cuttlefish_base",
+        "tombstone_transmit_defaults",
     ],
     cflags: [
         "-DMICRODROID",
diff --git a/guest/services/trusty_security_vm_launcher/Android.bp b/guest/services/trusty_security_vm_launcher/Android.bp
new file mode 100644
index 000000000..b88004fdf
--- /dev/null
+++ b/guest/services/trusty_security_vm_launcher/Android.bp
@@ -0,0 +1,7 @@
+prebuilt_etc {
+    name: "cf-trusty_security_vm_launcher.rc",
+    src: "trusty_security_vm_launcher.rc",
+    filename: "trusty_security_vm_launcher.rc",
+    relative_install_path: "init",
+    system_ext_specific: true,
+}
diff --git a/guest/services/trusty_security_vm_launcher/trusty_security_vm_launcher.rc b/guest/services/trusty_security_vm_launcher/trusty_security_vm_launcher.rc
new file mode 100644
index 000000000..111d0a103
--- /dev/null
+++ b/guest/services/trusty_security_vm_launcher/trusty_security_vm_launcher.rc
@@ -0,0 +1,15 @@
+service trusty_security_vm_launcher /system_ext/bin/trusty_security_vm_launcher \
+--kernel /system_ext/etc/vm/trusty_vm/lk_trusty.elf \
+--memory-size-mib 16
+    disabled
+    user system
+    group system virtualmachine
+    capabilities IPC_LOCK NET_BIND_SERVICE SYS_RESOURCE SYS_NICE
+    stdio_to_kmsg
+
+# Starts the non-secure Trusty VM in /system_ext when the feature is enabled through
+# the system property set in vendor init.
+on init && property:trusty.security_vm.enabled=1
+    setprop trusty.security_vm.nonsecure_vm_ready 1
+    setprop trusty.security_vm.vm_cid 200
+    start trusty_security_vm_launcher
diff --git a/guest/services/trusty_vm_launcher/Android.bp b/guest/services/trusty_vm_launcher/Android.bp
deleted file mode 100644
index a77da1113..000000000
--- a/guest/services/trusty_vm_launcher/Android.bp
+++ /dev/null
@@ -1,36 +0,0 @@
-rust_binary {
-    name: "trusty_vm_launcher",
-    crate_name: "trusty_vm_launcher",
-    srcs: ["src/main.rs"],
-    edition: "2021",
-    prefer_rlib: true,
-    rustlibs: [
-        "android.system.virtualizationservice-rust",
-        "libanyhow",
-        "libvmclient",
-    ],
-    init_rc: ["trusty_vm_launcher.rc"],
-    bootstrap: true,
-    apex_available: ["//apex_available:platform"],
-    system_ext_specific: true,
-    required: [
-        "cf-early_vms.xml",
-        "lk_trusty.elf",
-    ],
-    enabled: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
-        true: true,
-        false: false,
-    }),
-}
-
-prebuilt_etc {
-    name: "cf-early_vms.xml",
-    src: "early_vms.xml",
-    filename: "early_vms.xml",
-    relative_install_path: "avf",
-    system_ext_specific: true,
-    enabled: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
-        true: true,
-        false: false,
-    }),
-}
diff --git a/guest/services/trusty_vm_launcher/src/main.rs b/guest/services/trusty_vm_launcher/src/main.rs
deleted file mode 100644
index a459318f2..000000000
--- a/guest/services/trusty_vm_launcher/src/main.rs
+++ /dev/null
@@ -1,70 +0,0 @@
-// Copyright 2024, The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-//! A client for early boot VM running trusty.
-
-use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
-    IVirtualizationService::IVirtualizationService, VirtualMachineConfig::VirtualMachineConfig,
-    VirtualMachineRawConfig::VirtualMachineRawConfig,
-};
-use android_system_virtualizationservice::binder::{ParcelFileDescriptor, Strong};
-use anyhow::{Context, Result};
-use std::fs::File;
-use vmclient::VmInstance;
-
-const KERNEL_PATH: &str = "/system_ext/etc/hw/lk_trusty.elf";
-
-fn get_service() -> Result<Strong<dyn IVirtualizationService>> {
-    let virtmgr = vmclient::VirtualizationService::new_early()
-        .context("Failed to spawn VirtualizationService")?;
-    virtmgr.connect().context("Failed to connect to VirtualizationService")
-}
-
-fn main() -> Result<()> {
-    let service = get_service()?;
-
-    let kernel =
-        File::open(KERNEL_PATH).with_context(|| format!("Failed to open {KERNEL_PATH}"))?;
-
-    let vm_config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
-        name: "trusty_vm_launcher".to_owned(),
-        kernel: Some(ParcelFileDescriptor::new(kernel)),
-        protectedVm: false,
-        memoryMib: 128,
-        platformVersion: "~1.0".to_owned(),
-        // TODO: add instanceId
-        ..Default::default()
-    });
-
-    println!("creating VM");
-    let vm = VmInstance::create(
-        service.as_ref(),
-        &vm_config,
-        // console_in, console_out, and log will be redirected to the kernel log by virtmgr
-        None, // console_in
-        None, // console_out
-        None, // log
-        None, // callback
-    )
-    .context("Failed to create VM")?;
-    vm.start().context("Failed to start VM")?;
-
-    println!("started trusty_vm_launcher VM");
-    let death_reason = vm.wait_for_death();
-    eprintln!("trusty_vm_launcher ended: {:?}", death_reason);
-
-    // TODO(b/331320802): we may want to use android logger instead of stdio_to_kmsg?
-
-    Ok(())
-}
diff --git a/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc b/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc
deleted file mode 100644
index 4bdf41c56..000000000
--- a/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc
+++ /dev/null
@@ -1,13 +0,0 @@
-service trusty_vm_launcher /system_ext/bin/trusty_vm_launcher
-    disabled
-    user system
-    group system virtualmachine
-    capabilities IPC_LOCK NET_BIND_SERVICE SYS_RESOURCE SYS_NICE
-    stdio_to_kmsg
-
-# Starts the non-secure Trusty VM in /system_ext when the feature is enabled through
-# the system property set in vendor init.
-on init && property:ro.hardware.security.trusty_vm.system=1
-    setprop trusty_vm_system_nonsecure.ready 1
-    setprop trusty_vm_system.vm_cid 200
-    start trusty_vm_launcher
diff --git a/host/commands/acloud_translator/Android.bp b/host/commands/acloud_translator/Android.bp
index 8aa15bdc2..fd5aec623 100644
--- a/host/commands/acloud_translator/Android.bp
+++ b/host/commands/acloud_translator/Android.bp
@@ -24,9 +24,9 @@ cc_binary_host {
     ],
     static_libs: [
         "libbase",
-        "liblog",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "liblog",
     ],
     symlinks: ["acloud"],
     defaults: [
diff --git a/host/commands/assemble_cvd/Android.bp b/host/commands/assemble_cvd/Android.bp
index b90a8be0b..85a52b778 100644
--- a/host/commands/assemble_cvd/Android.bp
+++ b/host/commands/assemble_cvd/Android.bp
@@ -22,9 +22,9 @@ cc_binary_host {
     srcs: [
         "alloc.cc",
         "assemble_cvd.cc",
-        "bootconfig_args.cpp",
         "boot_config.cc",
         "boot_image_utils.cc",
+        "bootconfig_args.cpp",
         "clean.cc",
         "disk/factory_reset_protected.cc",
         "disk/gem5_image_unpacker.cpp",
@@ -35,8 +35,8 @@ cc_binary_host {
         "disk_builder.cpp",
         "disk_flags.cc",
         "display.cpp",
-        "flags.cc",
         "flag_feature.cpp",
+        "flags.cc",
         "graphics_flags.cc",
         "kernel_module_parser.cc",
         "misc_info.cc",
@@ -64,9 +64,9 @@ cc_binary_host {
     static_libs: [
         "libcdisk_spec",
         "libcuttlefish_avb",
+        "libcuttlefish_host_config",
         "libcuttlefish_host_config_adb",
         "libcuttlefish_host_config_fastboot",
-        "libcuttlefish_host_config",
         "libcuttlefish_launch_cvd_proto",
         "libcuttlefish_vm_manager",
         "libext2_uuid",
@@ -77,18 +77,18 @@ cc_binary_host {
     ],
     required: [
         "avbtool",
-        "bootloader_qemu_aarch64",
-        "bootloader_qemu_x86_64",
         "bootloader_crosvm_aarch64",
         "bootloader_crosvm_x86_64",
+        "bootloader_qemu_aarch64",
+        "bootloader_qemu_x86_64",
         "cvd_avb_pubkey_rsa2048",
         "cvd_avb_pubkey_rsa4096",
         "cvd_avb_testkey_rsa2048",
         "cvd_avb_testkey_rsa4096",
         "cvd_config_phone.json",
         "extract-ikconfig",
-        "mkenvimage_slim",
         "lz4",
+        "mkenvimage_slim",
         "simg2img",
         "unpack_bootimg",
     ],
diff --git a/host/commands/assemble_cvd/assemble_cvd.cc b/host/commands/assemble_cvd/assemble_cvd.cc
index 56fc6c170..0bfaea3a9 100644
--- a/host/commands/assemble_cvd/assemble_cvd.cc
+++ b/host/commands/assemble_cvd/assemble_cvd.cc
@@ -192,8 +192,10 @@ Result<void> RestoreHostFiles(const std::string& cuttlefish_root_dir,
       CF_EXPECT(GuestSnapshotDirectories(snapshot_dir_path));
   auto filter_guest_dir =
       [&guest_snapshot_dirs](const std::string& src_dir) -> bool {
-    return !(Contains(guest_snapshot_dirs, src_dir) ||
-             src_dir.ends_with("logs"));
+    if (src_dir.ends_with("logs") && Contains(guest_snapshot_dirs, src_dir)) {
+      return false;
+    }
+    return !Contains(guest_snapshot_dirs, src_dir);
   };
   // cp -r snapshot_dir_path HOME
   CF_EXPECT(CopyDirectoryRecursively(snapshot_dir_path, cuttlefish_root_dir,
@@ -263,6 +265,7 @@ Result<std::set<std::string>> PreservingOnResume(
   preserving.insert("uboot_env.img");
   preserving.insert("factory_reset_protected.img");
   preserving.insert("misc.img");
+  preserving.insert("vmmtruststore.img");
   preserving.insert("metadata.img");
   preserving.insert("persistent_vbmeta.img");
   preserving.insert("oemlock_secure");
@@ -454,7 +457,8 @@ Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
       auto vsock_dir =
           fmt::format("/tmp/vsock_{0}_{1}", instance.vsock_guest_cid(),
                       std::to_string(getuid()));
-      if (DirectoryExists(vsock_dir, /* follow_symlinks */ false)) {
+      if (DirectoryExists(vsock_dir, /* follow_symlinks */ false) &&
+          !IsDirectoryEmpty(vsock_dir)) {
         CF_EXPECT(RecursivelyRemoveDirectory(vsock_dir));
       }
       CF_EXPECT(EnsureDirectoryExists(vsock_dir, default_mode, default_group));
diff --git a/host/commands/assemble_cvd/boot_image_utils.cc b/host/commands/assemble_cvd/boot_image_utils.cc
index ae1171c56..27508ad3f 100644
--- a/host/commands/assemble_cvd/boot_image_utils.cc
+++ b/host/commands/assemble_cvd/boot_image_utils.cc
@@ -27,6 +27,7 @@
 #include <android-base/logging.h>
 #include <android-base/strings.h>
 
+#include "android-base/scopeguard.h"
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
@@ -481,27 +482,25 @@ void RepackGem5BootImage(const std::string& initrd_path,
 // the os version field in the boot image header.
 // https://source.android.com/docs/core/architecture/bootloader/boot-image-header
 Result<std::string> ReadAndroidVersionFromBootImage(
-    const std::string& boot_image_path) {
-  // temp dir path length is chosen to be larger than sun_path_length (108)
-  char tmp_dir[200];
-  sprintf(tmp_dir, "%s/XXXXXX", StringFromEnv("TEMP", "/tmp").c_str());
-  char* unpack_dir = mkdtemp(tmp_dir);
-  if (!unpack_dir) {
+    const std::string& temp_dir_parent, const std::string& boot_image_path) {
+  std::string tmp_dir = temp_dir_parent + "/XXXXXXX";
+  if (!mkdtemp(tmp_dir.data())) {
     return CF_ERR("boot image unpack dir could not be created");
   }
-  bool unpack_status = GetAvbMetadataFromBootImage(boot_image_path, unpack_dir);
-  if (!unpack_status) {
-    RecursivelyRemoveDirectory(unpack_dir);
-    return CF_ERR("\"" + boot_image_path + "\" boot image unpack into \"" +
-                  unpack_dir + "\" failed");
-  }
+  android::base::ScopeGuard delete_dir([tmp_dir]() {
+    Result<void> remove_res = RecursivelyRemoveDirectory(tmp_dir);
+    if (!remove_res.ok()) {
+      LOG(ERROR) << "Failed to delete temp dir '" << tmp_dir << '"';
+      LOG(ERROR) << remove_res.error().FormatForEnv();
+    }
+  });
+
+  CF_EXPECTF(GetAvbMetadataFromBootImage(boot_image_path, tmp_dir),
+             "'{}' boot image unpack into '{}' failed", boot_image_path,
+             tmp_dir);
 
-  // dirty hack to read out boot params
-  size_t dir_path_len = strlen(tmp_dir);
-  std::string boot_params = ReadFile(strcat(unpack_dir, "/boot_params"));
-  unpack_dir[dir_path_len] = '\0';
+  std::string boot_params = ReadFile(tmp_dir + "/boot_params");
 
-  RecursivelyRemoveDirectory(unpack_dir);
   std::string os_version =
       ExtractValue(boot_params, "Prop: com.android.build.boot.os_version -> ");
   // if the OS version is "None", or the prop does not exist, it wasn't set
diff --git a/host/commands/assemble_cvd/boot_image_utils.h b/host/commands/assemble_cvd/boot_image_utils.h
index 377fa0275..036c4f3ff 100644
--- a/host/commands/assemble_cvd/boot_image_utils.h
+++ b/host/commands/assemble_cvd/boot_image_utils.h
@@ -48,7 +48,7 @@ void RepackGem5BootImage(const std::string& initrd_path,
                          const std::string& unpack_dir,
                          const std::string& input_ramdisk_path);
 Result<std::string> ReadAndroidVersionFromBootImage(
-    const std::string& boot_image_path);
+    const std::string& tmp_dir_parent, const std::string& boot_image_path);
 
 void UnpackRamdisk(const std::string& original_ramdisk_path,
                    const std::string& ramdisk_stage_dir);
diff --git a/host/commands/assemble_cvd/bootconfig_args.cpp b/host/commands/assemble_cvd/bootconfig_args.cpp
index 1c4d3ccb1..7180c7090 100644
--- a/host/commands/assemble_cvd/bootconfig_args.cpp
+++ b/host/commands/assemble_cvd/bootconfig_args.cpp
@@ -21,8 +21,11 @@
 #include <string>
 #include <vector>
 
+#include <android-base/parseint.h>
+
 #include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/json.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
 #include "host/libs/vm_manager/crosvm_manager.h"
@@ -206,9 +209,31 @@ Result<std::unordered_map<std::string, std::string>> BootconfigArgsFromConfig(
           ? "com.android.hardware.gatekeeper.nonsecure"
           : "com.android.hardware.gatekeeper.cf_remote";
 
+  bootconfig_args
+      ["androidboot.vendor.apex.com.android.hardware.graphics.composer"] =
+          instance.hwcomposer() == kHwComposerDrm
+              ? "com.android.hardware.graphics.composer.drm_hwcomposer"
+              : "com.android.hardware.graphics.composer.ranchu";
+
   if (config.vhal_proxy_server_port()) {
     bootconfig_args["androidboot.vhal_proxy_server_port"] =
         std::to_string(config.vhal_proxy_server_port());
+    int32_t instance_id;
+    CF_EXPECT(android::base::ParseInt(instance.id(), &instance_id),
+              "instance id: " << instance.id() << " is not a valid int");
+    // The static ethernet IP address assigned for the guest.
+    bootconfig_args["androidboot.auto_eth_guest_addr"] =
+        fmt::format("192.168.98.{}", instance_id + 2);
+  }
+
+  if (!instance.vcpu_config_path().empty()) {
+    auto vcpu_config_json =
+        CF_EXPECT(LoadFromFile(instance.vcpu_config_path()));
+
+    const auto guest_soc =
+        CF_EXPECT(GetValue<std::string>(vcpu_config_json, {"guest_soc"}));
+
+    bootconfig_args["androidboot.guest_soc.model"] = guest_soc;
   }
 
   std::vector<std::string> args = instance.extra_bootconfig_args();
diff --git a/host/commands/assemble_cvd/disk_flags.cc b/host/commands/assemble_cvd/disk_flags.cc
index 91430bfd3..b8debb981 100644
--- a/host/commands/assemble_cvd/disk_flags.cc
+++ b/host/commands/assemble_cvd/disk_flags.cc
@@ -87,6 +87,8 @@ DEFINE_string(
     "to "
     "be vbmeta_system_dlkm.img in the directory specified by "
     "-system_image_dir.");
+DEFINE_string(vvmtruststore_path, CF_DEFAULTS_VVMTRUSTSTORE_PATH,
+              "Location of the vvmtruststore image");
 
 DEFINE_string(
     default_target_zip, CF_DEFAULTS_DEFAULT_TARGET_ZIP,
@@ -119,9 +121,13 @@ DEFINE_string(fuchsia_multiboot_bin_path, CF_DEFAULTS_FUCHSIA_MULTIBOOT_BIN_PATH
 DEFINE_string(fuchsia_root_image, CF_DEFAULTS_FUCHSIA_ROOT_IMAGE,
               "Location of fuchsia root filesystem image for cuttlefish otheros flow.");
 
-DEFINE_string(custom_partition_path, CF_DEFAULTS_CUSTOM_PARTITION_PATH,
-              "Location of custom image that will be passed as a \"custom\" partition"
-              "to rootfs and can be used by /dev/block/by-name/custom");
+DEFINE_string(
+    custom_partition_path, CF_DEFAULTS_CUSTOM_PARTITION_PATH,
+    "Location of custom image that will be passed as a \"custom\" partition"
+    "to rootfs and can be used by /dev/block/by-name/custom. Multiple images "
+    "can be passed, separated by semicolons and can be used as "
+    "/dev/block/by-name/custom_1, /dev/block/by-name/custom_2, etc. Example: "
+    "--custom_partition_path=\"/path/to/custom.img;/path/to/other.img\"");
 
 DEFINE_string(
     hibernation_image, CF_DEFAULTS_HIBERNATION_IMAGE,
@@ -458,15 +464,29 @@ std::vector<ImagePartition> android_composite_disk_config(
         .read_only = FLAGS_use_overlay,
     });
   }
-  const auto custom_partition_path = instance.custom_partition_path();
-  if (!custom_partition_path.empty()) {
+
+  const auto vvmtruststore_path = instance.vvmtruststore_path();
+  if (!vvmtruststore_path.empty()) {
     partitions.push_back(ImagePartition{
-        .label = "custom",
-        .image_file_path = AbsolutePath(custom_partition_path),
+        .label = "vvmtruststore",
+        .image_file_path = AbsolutePath(vvmtruststore_path),
         .read_only = FLAGS_use_overlay,
     });
   }
 
+  const auto custom_partition_path = instance.custom_partition_path();
+  if (!custom_partition_path.empty()) {
+    auto custom_partition_paths =
+        android::base::Split(custom_partition_path, ";");
+    for (int i = 0; i < custom_partition_paths.size(); i++) {
+      partitions.push_back(ImagePartition{
+          .label = i > 0 ? "custom_" + std::to_string(i) : "custom",
+          .image_file_path = AbsolutePath(custom_partition_paths[i]),
+          .read_only = FLAGS_use_overlay,
+      });
+    }
+  }
+
   return partitions;
 }
 
@@ -706,7 +726,7 @@ static fruit::Component<> DiskChangesComponent(
       .install(AutoSetup<Gem5ImageUnpacker>::Component)
       .install(AutoSetup<InitializeMiscImage>::Component)
       // Create esp if necessary
-      .install(InitializeEspImageComponent)
+      .install(AutoSetup<InitializeEspImage>::Component)
       .install(SuperImageRebuilderComponent);
 }
 
@@ -751,6 +771,7 @@ Result<void> DiskImageFlagsVectorization(CuttlefishConfig& config, const Fetcher
       android::base::Split(FLAGS_vbmeta_vendor_dlkm_image, ",");
   auto vbmeta_system_dlkm_image =
       android::base::Split(FLAGS_vbmeta_system_dlkm_image, ",");
+  auto vvmtruststore_path = android::base::Split(FLAGS_vvmtruststore_path, ",");
 
   std::vector<std::string> default_target_zip_vec =
       android::base::Split(FLAGS_default_target_zip, ",");
@@ -857,6 +878,11 @@ Result<void> DiskImageFlagsVectorization(CuttlefishConfig& config, const Fetcher
       instance.set_vbmeta_system_dlkm_image(
           vbmeta_system_dlkm_image[instance_index]);
     }
+    if (instance_index >= vvmtruststore_path.size()) {
+      instance.set_vvmtruststore_path(vvmtruststore_path[0]);
+    } else {
+      instance.set_vvmtruststore_path(vvmtruststore_path[instance_index]);
+    }
     if (instance_index >= super_image.size()) {
       cur_super_image = super_image[0];
     } else {
diff --git a/host/commands/assemble_cvd/flags.cc b/host/commands/assemble_cvd/flags.cc
index 4a385bd3a..d0a81355d 100644
--- a/host/commands/assemble_cvd/flags.cc
+++ b/host/commands/assemble_cvd/flags.cc
@@ -63,6 +63,7 @@
 #include "host/libs/config/instance_nums.h"
 #include "host/libs/config/secure_hals.h"
 #include "host/libs/config/touchpad.h"
+#include "host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h"
 #include "host/libs/vm_manager/crosvm_manager.h"
 #include "host/libs/vm_manager/gem5_manager.h"
 #include "host/libs/vm_manager/qemu_manager.h"
@@ -520,6 +521,9 @@ DEFINE_vec(
 DEFINE_vec(vhost_user_block, CF_DEFAULTS_VHOST_USER_BLOCK ? "true" : "false",
            "(experimental) use crosvm vhost-user block device implementation ");
 
+DEFINE_string(early_tmp_dir, cuttlefish::StringFromEnv("TEMP", "/tmp"),
+              "Parent directory to use for temporary files in early startup");
+
 DECLARE_string(assembly_dir);
 DECLARE_string(boot_image);
 DECLARE_string(system_image_dir);
@@ -622,9 +626,9 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
     }
 
     GuestConfig guest_config;
-    guest_config.android_version_number =
-        CF_EXPECT(ReadAndroidVersionFromBootImage(cur_boot_image),
-                  "Failed to read guest's android version");
+    guest_config.android_version_number = CF_EXPECT(
+        ReadAndroidVersionFromBootImage(FLAGS_early_tmp_dir, cur_boot_image),
+        "Failed to read guest's android version");
 
     if (InSandbox()) {
       // TODO: b/359309462 - real sandboxing for extract-ikconfig
@@ -636,8 +640,7 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
       ikconfig_cmd.AddParameter(kernel_image_path);
       ikconfig_cmd.UnsetFromEnvironment("PATH").AddEnvironmentVariable(
           "PATH", new_path);
-      std::string ikconfig_path =
-          StringFromEnv("TEMP", "/tmp") + "/ikconfig.XXXXXX";
+      std::string ikconfig_path = FLAGS_early_tmp_dir + "/ikconfig.XXXXXX";
       auto ikconfig_fd = SharedFD::Mkstemp(&ikconfig_path);
       CF_EXPECT(ikconfig_fd->IsOpen(),
                 "Unable to create ikconfig file: " << ikconfig_fd->StrError());
@@ -698,6 +701,11 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
     guest_config.gfxstream_gl_program_binary_link_status_supported =
         res.ok() && res.value() == "supported";
 
+    auto res_mouse_support =
+        GetAndroidInfoConfig(instance_android_info_txt, "mouse");
+    guest_config.mouse_supported =
+        res_mouse_support.ok() && res_mouse_support.value() == "supported";
+
     auto res_bgra_support = GetAndroidInfoConfig(instance_android_info_txt,
                                                  "supports_bgra_framebuffers");
     guest_config.supports_bgra_framebuffers =
@@ -707,6 +715,11 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
         GetAndroidInfoConfig(instance_android_info_txt, "vhost_user_vsock");
     guest_config.vhost_user_vsock = res_vhost_user_vsock.value_or("") == "true";
 
+    auto res_prefer_drm_virgl_when_supported = GetAndroidInfoConfig(
+        instance_android_info_txt, "prefer_drm_virgl_when_supported");
+    guest_config.prefer_drm_virgl_when_supported =
+        res_prefer_drm_virgl_when_supported.value_or("") == "true";
+
     guest_configs.push_back(guest_config);
   }
   return guest_configs;
@@ -1336,8 +1349,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   if (FLAGS_vhal_proxy_server_instance_num > 0) {
     vhal_proxy_server_instance_num = FLAGS_vhal_proxy_server_instance_num - 1;
   }
-  tmp_config_obj.set_vhal_proxy_server_port(9300 +
-                                            vhal_proxy_server_instance_num);
+  tmp_config_obj.set_vhal_proxy_server_port(
+      cuttlefish::vhal_proxy_server::kDefaultEthPort +
+      vhal_proxy_server_instance_num);
   LOG(DEBUG) << "launch vhal proxy server: "
              << (FLAGS_enable_vhal_proxy_server &&
                  vhal_proxy_server_instance_num <= 0);
@@ -1408,6 +1422,7 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     instance.set_crosvm_use_rng(use_rng_vec[instance_index]);
     instance.set_use_pmem(use_pmem_vec[instance_index]);
     instance.set_bootconfig_supported(guest_configs[instance_index].bootconfig_supported);
+    instance.set_enable_mouse(guest_configs[instance_index].mouse_supported);
     instance.set_filename_encryption_mode(
       guest_configs[instance_index].hctr2_supported ? "hctr2" : "cts");
     instance.set_use_allocd(use_allocd_vec[instance_index]);
diff --git a/host/commands/assemble_cvd/flags.h b/host/commands/assemble_cvd/flags.h
index 9b70c024f..8501311b8 100644
--- a/host/commands/assemble_cvd/flags.h
+++ b/host/commands/assemble_cvd/flags.h
@@ -37,6 +37,8 @@ struct GuestConfig {
   bool gfxstream_gl_program_binary_link_status_supported = false;
   bool vhost_user_vsock = false;
   bool supports_bgra_framebuffers = false;
+  bool prefer_drm_virgl_when_supported = false;
+  bool mouse_supported = false;
 };
 
 Result<std::vector<GuestConfig>> GetGuestConfigAndSetDefaults();
diff --git a/host/commands/assemble_cvd/flags_defaults.h b/host/commands/assemble_cvd/flags_defaults.h
index 1e019b196..d1110bdcd 100644
--- a/host/commands/assemble_cvd/flags_defaults.h
+++ b/host/commands/assemble_cvd/flags_defaults.h
@@ -125,6 +125,7 @@
 #define CF_DEFAULTS_VBMETA_VENDOR_DLKM_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VBMETA_SYSTEM_DLKM_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VENDOR_BOOT_IMAGE CF_DEFAULTS_DYNAMIC_STRING
+#define CF_DEFAULTS_VVMTRUSTSTORE_PATH CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_DEFAULT_TARGET_ZIP CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_SYSTEM_TARGET_ZIP CF_DEFAULTS_DYNAMIC_STRING
 
diff --git a/host/commands/assemble_cvd/graphics_flags.cc b/host/commands/assemble_cvd/graphics_flags.cc
index 7cf8caff2..995ac8484 100644
--- a/host/commands/assemble_cvd/graphics_flags.cc
+++ b/host/commands/assemble_cvd/graphics_flags.cc
@@ -88,6 +88,12 @@ struct AngleFeatures {
   // b/264575911: Nvidia seems to have issues with YUV samplers with
   // 'lowp' and 'mediump' precision qualifiers.
   bool ignore_precision_qualifiers = false;
+
+  // ANGLE has a feature to expose 3.2 early even if the device does
+  // not fully support all of the 3.2 features. This should be
+  // disabled for Cuttlefish as SwiftShader does not have geometry
+  // shader nor tesselation shader support.
+  bool disable_expose_opengles_3_2_for_testing = false;
 };
 
 std::ostream& operator<<(std::ostream& stream, const AngleFeatures& features) {
@@ -116,6 +122,12 @@ Result<AngleFeatures> GetNeededAngleFeaturesBasedOnQuirks(
       features.ignore_precision_qualifiers = true;
     }
   }
+
+  if (mode == RenderingMode::kGuestSwiftShader ||
+      mode == RenderingMode::kGfxstreamGuestAngleHostSwiftshader) {
+    features.disable_expose_opengles_3_2_for_testing = true;
+  }
+
   return features;
 }
 
@@ -174,6 +186,9 @@ Result<AngleFeatureOverrides> GetNeededAngleFeatures(
   if (features.ignore_precision_qualifiers) {
     disable_feature_strings.push_back("enablePrecisionQualifiers");
   }
+  if (features.disable_expose_opengles_3_2_for_testing) {
+    disable_feature_strings.push_back("exposeES32ForTesting");
+  }
 
   return AngleFeatureOverrides{
       .angle_feature_overrides_enabled =
@@ -270,6 +285,9 @@ Result<std::string> SelectGpuMode(
       if (vmm == VmmMode::kQemu && !UseQemuPrebuilt()) {
         LOG(INFO) << "Not using QEMU prebuilt (QEMU 8+): selecting guest swiftshader";
         return kGpuModeGuestSwiftshader;
+      } else if (guest_config.prefer_drm_virgl_when_supported) {
+        LOG(INFO) << "GPU mode from guest config: drm_virgl";
+        return kGpuModeDrmVirgl;
       } else if (!guest_config.gfxstream_supported) {
         LOG(INFO) << "GPU auto mode: guest does not support gfxstream, "
                      "enabling --gpu_mode=guest_swiftshader";
diff --git a/host/commands/assemble_cvd/super_image_mixer.cc b/host/commands/assemble_cvd/super_image_mixer.cc
index ee2324484..afd767f5f 100644
--- a/host/commands/assemble_cvd/super_image_mixer.cc
+++ b/host/commands/assemble_cvd/super_image_mixer.cc
@@ -63,6 +63,14 @@ constexpr std::array kVendorTargetBuildProps = {
     "VENDOR/etc/build.prop",
 };
 
+struct RebuildPaths {
+  std::string vendor_target_zip;
+  std::string system_target_zip;
+  std::string combined_target_zip;
+  std::string super_image_output;
+  std::string vbmeta_image_output;
+};
+
 struct TargetFiles {
   Archive vendor_zip;
   Archive system_zip;
@@ -81,7 +89,7 @@ void FindImports(Archive* archive, const std::string& build_prop_file) {
   for (const auto& line : lines) {
     auto parts = android::base::Split(line, " ");
     if (parts.size() >= 2 && parts[0] == "import") {
-      LOG(INFO) << build_prop_file << ": " << line;
+      LOG(DEBUG) << build_prop_file << ": " << line;
     }
   }
 }
@@ -171,7 +179,7 @@ Result<Extracted> ExtractTargetFiles(TargetFiles& target_files,
     } else if (!Contains(kVendorTargetImages, name)) {
       continue;
     }
-    LOG(INFO) << "Writing " << name << " from vendor target";
+    LOG(DEBUG) << "Writing " << name << " from vendor target";
     CF_EXPECT(
         target_files.vendor_zip.ExtractFiles({name}, combined_output_path),
         "Failed to extract " << name << " from the vendor target zip");
@@ -184,11 +192,12 @@ Result<Extracted> ExtractTargetFiles(TargetFiles& target_files,
       continue;
     }
     FindImports(&target_files.vendor_zip, name);
-    LOG(INFO) << "Writing " << name << " from vendor target";
+    LOG(DEBUG) << "Writing " << name << " from vendor target";
     CF_EXPECT(
         target_files.vendor_zip.ExtractFiles({name}, combined_output_path),
         "Failed to extract " << name << " from the vendor target zip");
   }
+  LOG(INFO) << "Completed extracting images from vendor.";
 
   for (const auto& name : target_files.system_contents) {
     if (!IsTargetFilesImage(name)) {
@@ -196,7 +205,7 @@ Result<Extracted> ExtractTargetFiles(TargetFiles& target_files,
     } else if (Contains(kVendorTargetImages, name)) {
       continue;
     }
-    LOG(INFO) << "Writing " << name << " from system target";
+    LOG(DEBUG) << "Writing " << name << " from system target";
     CF_EXPECT(
         target_files.system_zip.ExtractFiles({name}, combined_output_path),
         "Failed to extract " << name << " from the system target zip");
@@ -211,11 +220,12 @@ Result<Extracted> ExtractTargetFiles(TargetFiles& target_files,
       continue;
     }
     FindImports(&target_files.system_zip, name);
-    LOG(INFO) << "Writing " << name << " from system target";
+    LOG(DEBUG) << "Writing " << name << " from system target";
     CF_EXPECT(
         target_files.system_zip.ExtractFiles({name}, combined_output_path),
         "Failed to extract " << name << " from the system target zip");
   }
+  LOG(INFO) << "Completed extracting images from system.";
   return extracted;
 }
 
@@ -230,22 +240,19 @@ Result<void> RegenerateVbmeta(const MiscInfo& misc_info,
   return {};
 }
 
-Result<void> CombineTargetZipFiles(const std::string& vendor_zip_path,
-                                   const std::string& system_zip_path,
-                                   const std::string& combined_target_path,
-                                   const std::string& vbmeta_output_path) {
-  CF_EXPECT(EnsureDirectoryExists(combined_target_path));
-  CF_EXPECT(EnsureDirectoryExists(combined_target_path + "/META"));
-  auto target_files =
-      CF_EXPECT(GetTargetFiles(vendor_zip_path, system_zip_path));
+Result<void> CombineTargetZipFiles(const RebuildPaths& paths) {
+  CF_EXPECT(EnsureDirectoryExists(paths.combined_target_zip));
+  CF_EXPECT(EnsureDirectoryExists(paths.combined_target_zip + "/META"));
+  auto target_files = CF_EXPECT(
+      GetTargetFiles(paths.vendor_target_zip, paths.system_target_zip));
   const auto extracted =
-      CF_EXPECT(ExtractTargetFiles(target_files, combined_target_path));
-  const auto misc_output_path = combined_target_path + "/" + kMiscInfoPath;
+      CF_EXPECT(ExtractTargetFiles(target_files, paths.combined_target_zip));
+  const auto misc_output_path = paths.combined_target_zip + "/" + kMiscInfoPath;
   const auto combined_info =
       CF_EXPECT(CombineMiscInfo(target_files, misc_output_path,
                                 extracted.images, extracted.system_partitions));
-  CF_EXPECT(RegenerateVbmeta(combined_info, vbmeta_output_path,
-                             combined_target_path));
+  CF_EXPECT(RegenerateVbmeta(combined_info, paths.vbmeta_image_output,
+                             paths.combined_target_zip));
   return {};
 }
 
@@ -281,16 +288,14 @@ std::string TargetFilesZip(const FetcherConfig& fetcher_config,
   return "";
 }
 
-Result<void> RebuildSuperImage(const FetcherConfig& fetcher_config,
-                               const CuttlefishConfig& config,
-                               const std::string& super_image_output,
-                               const std::string& vbmeta_image_output) {
-  auto instance = config.ForDefaultInstance();
-  // In SuperImageNeedsRebuilding, it already checked both
-  // has_default_target_zip and has_system_target_zip are the same.
-  // Here, we only check if there is an input path
-  std::string default_target_zip = instance.default_target_zip();
-  std::string system_target_zip = instance.system_target_zip();
+Result<RebuildPaths> GetRebuildPaths(
+    const FetcherConfig& fetcher_config,
+    const CuttlefishConfig::InstanceSpecific& instance_config) {
+  // In SuperImageNeedsRebuilding, it already checked that both paths either
+  // exist or do not exist, together Here, we only check if there is an input
+  // path
+  std::string default_target_zip = instance_config.default_target_zip();
+  std::string system_target_zip = instance_config.system_target_zip();
   if (default_target_zip == "" || default_target_zip == "unset") {
     default_target_zip =
         TargetFilesZip(fetcher_config, FileSource::DEFAULT_BUILD);
@@ -301,28 +306,36 @@ Result<void> RebuildSuperImage(const FetcherConfig& fetcher_config,
         TargetFilesZip(fetcher_config, FileSource::SYSTEM_BUILD);
     CF_EXPECT(system_target_zip != "", "Unable to find system target zip file.");
   }
+  return RebuildPaths{
+      .vendor_target_zip = default_target_zip,
+      .system_target_zip = system_target_zip,
+      // TODO(schuffelen): Use cuttlefish_assembly
+      .combined_target_zip =
+          instance_config.PerInstanceInternalPath("target_combined"),
+      .super_image_output = instance_config.new_super_image(),
+      .vbmeta_image_output = instance_config.new_vbmeta_image(),
+  };
+}
 
-  // TODO(schuffelen): Use cuttlefish_assembly
-  std::string combined_target_path = instance.PerInstanceInternalPath("target_combined");
+Result<void> RebuildSuperImage(const RebuildPaths& paths) {
   // TODO(schuffelen): Use otatools/bin/merge_target_files
-  CF_EXPECT(CombineTargetZipFiles(default_target_zip, system_target_zip,
-                                  combined_target_path, vbmeta_image_output),
+  CF_EXPECT(CombineTargetZipFiles(paths),
             "Could not combine target zip files.");
 
-  CF_EXPECT(BuildSuperImage(combined_target_path, super_image_output),
-            "Could not write the final output super image.");
+  CF_EXPECT(
+      BuildSuperImage(paths.combined_target_zip, paths.super_image_output),
+      "Could not write the final output super image.");
   return {};
 }
 
 class SuperImageRebuilderImpl : public SuperImageRebuilder {
  public:
   INJECT(SuperImageRebuilderImpl(
-      const FetcherConfig& fetcher_config, const CuttlefishConfig& config,
+      const FetcherConfig& fetcher_config,
       const CuttlefishConfig::InstanceSpecific& instance))
-      : fetcher_config_(fetcher_config), config_(config), instance_(instance) {}
+      : fetcher_config_(fetcher_config), instance_(instance) {}
 
   std::string Name() const override { return "SuperImageRebuilderImpl"; }
-  bool Enabled() const override { return true; }
 
  private:
   std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
@@ -330,15 +343,22 @@ class SuperImageRebuilderImpl : public SuperImageRebuilder {
     if (CF_EXPECT(SuperImageNeedsRebuilding(fetcher_config_,
                                             instance_.default_target_zip(),
                                             instance_.system_target_zip()))) {
-      CF_EXPECT(RebuildSuperImage(fetcher_config_, config_,
-                                  instance_.new_super_image(),
-                                  instance_.new_vbmeta_image()));
+      const RebuildPaths paths =
+          CF_EXPECT(GetRebuildPaths(fetcher_config_, instance_));
+      LOG(INFO) << "The super.img is being rebuilt with provided vendor and "
+                   "system target files.";
+      LOG(INFO) << "Vendor target files at: " << paths.vendor_target_zip;
+      LOG(INFO) << "System target files at: " << paths.system_target_zip;
+      CF_EXPECT(RebuildSuperImage(paths));
+      LOG(INFO) << "Rebuild complete.";
+      LOG(INFO) << "Combined target files at: " << paths.combined_target_zip;
+      LOG(INFO) << "New super.img at: " << paths.super_image_output;
+      LOG(INFO) << "New vbmeta.img at: " << paths.vbmeta_image_output;
     }
     return {};
   }
 
   const FetcherConfig& fetcher_config_;
-  const CuttlefishConfig& config_;
   const CuttlefishConfig::InstanceSpecific& instance_;
 };
 
@@ -376,7 +396,7 @@ Result<bool> SuperImageNeedsRebuilding(const FetcherConfig& fetcher_config,
   return has_default_build && has_system_build;
 }
 
-fruit::Component<fruit::Required<const FetcherConfig, const CuttlefishConfig,
+fruit::Component<fruit::Required<const FetcherConfig,
                                  const CuttlefishConfig::InstanceSpecific>,
                  SuperImageRebuilder>
 SuperImageRebuilderComponent() {
diff --git a/host/commands/assemble_cvd/super_image_mixer.h b/host/commands/assemble_cvd/super_image_mixer.h
index 57dfbb32b..9c2a8cd80 100644
--- a/host/commands/assemble_cvd/super_image_mixer.h
+++ b/host/commands/assemble_cvd/super_image_mixer.h
@@ -24,7 +24,7 @@ namespace cuttlefish {
 
 class SuperImageRebuilder : public SetupFeature {};
 
-fruit::Component<fruit::Required<const FetcherConfig, const CuttlefishConfig,
+fruit::Component<fruit::Required<const FetcherConfig,
                                  const CuttlefishConfig::InstanceSpecific>,
                  SuperImageRebuilder>
 SuperImageRebuilderComponent();
diff --git a/host/commands/casimir_control_server/Android.bp b/host/commands/casimir_control_server/Android.bp
index 2bcd74ead..afaddb4de 100644
--- a/host/commands/casimir_control_server/Android.bp
+++ b/host/commands/casimir_control_server/Android.bp
@@ -19,8 +19,8 @@ package {
 cc_library {
     name: "libcasimir_control_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libgflags",
@@ -55,18 +55,19 @@ cc_binary_host {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
+        "libcasimir_control_server",
         "libcuttlefish_host_config",
         "libgflags",
-        "libcasimir_control_server",
         "libgrpc++_reflection",
     ],
     header_libs: ["casimir_rf_packets_cxx"],
     srcs: [
         "casimir_controller.cpp",
+        "hex.cpp",
         "main.cpp",
     ],
     cflags: [
@@ -83,8 +84,8 @@ cc_binary_host {
 filegroup {
     name: "CasimirControlServerProto",
     srcs: [
-        "casimir_control.proto",
         ":libprotobuf-internal-protos",
+        "casimir_control.proto",
     ],
 }
 
diff --git a/host/commands/casimir_control_server/casimir_control.proto b/host/commands/casimir_control_server/casimir_control.proto
index 3e0d566ac..a5434e907 100644
--- a/host/commands/casimir_control_server/casimir_control.proto
+++ b/host/commands/casimir_control_server/casimir_control.proto
@@ -20,12 +20,33 @@ import "google/protobuf/empty.proto";
 
 service CasimirControlService {
   rpc SendApdu (SendApduRequest) returns (SendApduReply) {}
+  rpc PollA (Void) returns (SenderId) {}
+  rpc SetRadioState(RadioState) returns (Void) {}
+  rpc SetPowerLevel(PowerLevel) returns (Void) {}
+  rpc Init(Void) returns (Void) {}
+  rpc Close(Void) returns (Void) {}
 }
 
 message SendApduRequest {
   repeated string apdu_hex_strings = 1;
+  optional uint32 sender_id = 2;
 }
 
 message SendApduReply {
   repeated string response_hex_strings = 1;
 }
+
+message SenderId {
+  uint32 sender_id = 1;
+}
+
+message Void {
+}
+
+message RadioState {
+  bool radio_on = 1;
+}
+
+message PowerLevel {
+  uint32 power_level = 1;
+}
\ No newline at end of file
diff --git a/host/commands/casimir_control_server/casimir_controller.cpp b/host/commands/casimir_control_server/casimir_controller.cpp
index 0f4bdbb36..fdf214f56 100644
--- a/host/commands/casimir_control_server/casimir_controller.cpp
+++ b/host/commands/casimir_control_server/casimir_controller.cpp
@@ -16,6 +16,7 @@
 
 #include <fcntl.h>
 #include <chrono>
+#include <cstdint>
 
 #include "casimir_controller.h"
 
@@ -25,23 +26,68 @@ using namespace casimir::rf;
 using namespace std::literals::chrono_literals;
 using pdl::packet::slice;
 
-Result<void> CasimirController::Init(int casimir_rf_port) {
-  CF_EXPECT(!sock_->IsOpen());
+Result<void> CasimirController::Mute() {
+  if (!sock_->IsOpen()) {
+    return {};
+  }
+  FieldInfoBuilder rf_off;
+  rf_off.field_status_ = FieldStatus::FieldOff;
+  rf_off.power_level_ = power_level;
+  CF_EXPECT(Write(rf_off));
+  return {};
+}
+
+CasimirController::CasimirController(SharedFD sock)
+    : sock_(sock), power_level(10) {}
+
+/* static */
+Result<CasimirController> CasimirController::ConnectToTcpPort(int rf_port) {
+  SharedFD sock = SharedFD::SocketLocalClient(rf_port, SOCK_STREAM);
+  CF_EXPECT(sock->IsOpen(),
+            "Failed to connect to casimir with RF port" << rf_port);
+
+  int flags = sock->Fcntl(F_GETFL, 0);
+  CF_EXPECT_GE(flags, 0, "Failed to get FD flags of casimir socket");
+  CF_EXPECT_EQ(sock->Fcntl(F_SETFL, flags | O_NONBLOCK), 0,
+               "Failed to set casimir socket nonblocking");
 
-  sock_ = cuttlefish::SharedFD::SocketLocalClient(casimir_rf_port, SOCK_STREAM);
-  CF_EXPECT(sock_->IsOpen(),
-            "Failed to connect to casimir with RF port" << casimir_rf_port);
+  return CasimirController(sock);
+}
+
+/* static */
+Result<CasimirController> CasimirController::ConnectToUnixSocket(
+    const std::string& rf_path) {
+  SharedFD sock = SharedFD::SocketLocalClient(rf_path, false, SOCK_STREAM);
+  CF_EXPECT(sock->IsOpen(),
+            "Failed to connect to casimir with RF path" << rf_path);
 
-  int flags = sock_->Fcntl(F_GETFL, 0);
+  int flags = sock->Fcntl(F_GETFL, 0);
   CF_EXPECT_GE(flags, 0, "Failed to get FD flags of casimir socket");
-  CF_EXPECT_EQ(sock_->Fcntl(F_SETFL, flags | O_NONBLOCK), 0,
+  CF_EXPECT_EQ(sock->Fcntl(F_SETFL, flags | O_NONBLOCK), 0,
                "Failed to set casimir socket nonblocking");
+  return CasimirController(sock);
+}
+
+Result<void> CasimirController::Unmute() {
+  if (!sock_->IsOpen()) {
+    return {};
+  }
+  FieldInfoBuilder rf_on;
+  rf_on.field_status_ = FieldStatus::FieldOn;
+  rf_on.power_level_ = power_level;
+  CF_EXPECT(Write(rf_on));
+  return {};
+}
+
+Result<void> CasimirController::SetPowerLevel(uint32_t power_level) {
+  this->power_level = power_level;
   return {};
 }
 
 Result<uint16_t> CasimirController::SelectNfcA() {
   PollCommandBuilder poll_command;
   poll_command.technology_ = Technology::NFC_A;
+  poll_command.power_level_ = power_level;
   CF_EXPECT(Write(poll_command), "Failed to send NFC-A poll command");
 
   auto res = CF_EXPECT(ReadRfPacket(10s), "Failed to get NFC-A poll response");
@@ -83,12 +129,12 @@ Result<uint16_t> CasimirController::Poll() {
   return sender_id;
 }
 
-Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::SendApdu(
-    uint16_t receiver_id, const std::shared_ptr<std::vector<uint8_t>>& apdu) {
+Result<std::vector<uint8_t>> CasimirController::SendApdu(
+    uint16_t receiver_id, std::vector<uint8_t> apdu) {
   CF_EXPECT(sock_->IsOpen());
 
   DataBuilder data_builder;
-  data_builder.data_ = *apdu.get();
+  data_builder.data_ = std::move(apdu);
   data_builder.receiver_ = receiver_id;
   data_builder.technology_ = Technology::NFC_A;
   data_builder.protocol_ = Protocol::ISO_DEP;
@@ -100,7 +146,7 @@ Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::SendApdu(
   if (rf_packet.IsValid()) {
     auto data = DataView::Create(rf_packet);
     if (data.IsValid() && rf_packet.GetSender() == receiver_id) {
-      return std::make_shared<std::vector<uint8_t>>(data.GetData());
+      return data.GetData();
     }
   }
   return CF_ERR("Invalid APDU response");
diff --git a/host/commands/casimir_control_server/casimir_controller.h b/host/commands/casimir_control_server/casimir_controller.h
index 96019e7fe..3603cd7e9 100644
--- a/host/commands/casimir_control_server/casimir_controller.h
+++ b/host/commands/casimir_control_server/casimir_controller.h
@@ -30,17 +30,24 @@ using namespace casimir::rf;
 
 class CasimirController {
  public:
-  Result<void> Init(int casimir_rf_port);
+  static Result<CasimirController> ConnectToTcpPort(int rf_port);
+  static Result<CasimirController> ConnectToUnixSocket(const std::string& rf);
+
+  Result<void> Mute();
+  Result<void> Unmute();
+
+  Result<void> SetPowerLevel(uint32_t power_level);
 
   /*
    * Poll for NFC-A + ISO-DEP
    */
   Result<uint16_t> Poll();
 
-  Result<std::shared_ptr<std::vector<uint8_t>>> SendApdu(
-      uint16_t receiver_id, const std::shared_ptr<std::vector<uint8_t>>& apdu);
+  Result<std::vector<uint8_t>> SendApdu(uint16_t receiver_id,
+                                        std::vector<uint8_t> apdu);
 
  private:
+  CasimirController(SharedFD sock);
   /*
    * Select NFC-A, and returns sender id.
    */
@@ -58,8 +65,8 @@ class CasimirController {
   Result<std::shared_ptr<std::vector<uint8_t>>> ReadRfPacket(
       std::chrono::milliseconds timeout);
 
- private:
   SharedFD sock_;
+  uint8_t power_level;
 };
 
-}  // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/commands/casimir_control_server/utils.h b/host/commands/casimir_control_server/hex.cpp
similarity index 83%
rename from host/commands/casimir_control_server/utils.h
rename to host/commands/casimir_control_server/hex.cpp
index cbbe56a16..67adaf569 100644
--- a/host/commands/casimir_control_server/utils.h
+++ b/host/commands/casimir_control_server/hex.cpp
@@ -14,11 +14,12 @@
  * limitations under the License.
  */
 
-#pragma once
+#include "host/commands/casimir_control_server/hex.h"
 
 #include "common/libs/utils/result.h"
 
 namespace cuttlefish {
+namespace {
 
 static int ByteNumber(char x) {
   x = tolower(x);
@@ -30,22 +31,23 @@ static int ByteNumber(char x) {
   return -1;
 }
 
-Result<std::shared_ptr<std::vector<uint8_t>>> BytesArray(
-    const std::string& hex_string) {
+}  // namespace
+
+Result<std::vector<uint8_t>> HexToBytes(const std::string& hex_string) {
   CF_EXPECT(hex_string.size() % 2 == 0,
             "Failed to parse input. Must be even size");
 
   int len = hex_string.size() / 2;
-  auto out = std::make_shared<std::vector<uint8_t>>(len);
+  std::vector<uint8_t> out(len);
   for (int i = 0; i < len; i++) {
     int num_h = ByteNumber(hex_string[i * 2]);
     int num_l = ByteNumber(hex_string[i * 2 + 1]);
     CF_EXPECT(num_h >= 0 && num_l >= 0,
               "Failed to parse input. Must only contain [0-9a-fA-F]");
-    (*out.get())[i] = num_h * 16 + num_l;
+    out[i] = num_h * 16 + num_l;
   }
 
   return out;
 }
 
-}  // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/commands/casimir_control_server/hex.h b/host/commands/casimir_control_server/hex.h
new file mode 100644
index 000000000..ae28580b5
--- /dev/null
+++ b/host/commands/casimir_control_server/hex.h
@@ -0,0 +1,25 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+Result<std::vector<uint8_t>> HexToBytes(const std::string& hex_string);
+
+}  // namespace cuttlefish
diff --git a/host/commands/casimir_control_server/main.cpp b/host/commands/casimir_control_server/main.cpp
index 422fa0474..b54692d9a 100644
--- a/host/commands/casimir_control_server/main.cpp
+++ b/host/commands/casimir_control_server/main.cpp
@@ -25,12 +25,18 @@
 #include <grpcpp/health_check_service_interface.h>
 
 #include "casimir_control.grpc.pb.h"
-#include "casimir_controller.h"
-#include "utils.h"
+
+#include "common/libs/utils/result.h"
+#include "host/commands/casimir_control_server/casimir_controller.h"
+#include "host/commands/casimir_control_server/hex.h"
 
 using casimircontrolserver::CasimirControlService;
+using casimircontrolserver::PowerLevel;
+using casimircontrolserver::RadioState;
 using casimircontrolserver::SendApduReply;
 using casimircontrolserver::SendApduRequest;
+using casimircontrolserver::SenderId;
+using casimircontrolserver::Void;
 
 using cuttlefish::CasimirController;
 
@@ -45,64 +51,179 @@ using std::vector;
 
 DEFINE_string(grpc_uds_path, "", "grpc_uds_path");
 DEFINE_int32(casimir_rf_port, -1, "RF port to control Casimir");
+DEFINE_string(casimir_rf_path, "", "RF unix server path to control Casimir");
+
+namespace cuttlefish {
+namespace {
+
+Result<CasimirController> ConnectToCasimir() {
+  if (FLAGS_casimir_rf_port >= 0) {
+    return CF_EXPECT(
+        CasimirController::ConnectToTcpPort(FLAGS_casimir_rf_port));
+  } else if (!FLAGS_casimir_rf_path.empty()) {
+    return CF_EXPECT(
+        CasimirController::ConnectToUnixSocket(FLAGS_casimir_rf_path));
+  } else {
+    return CF_ERR("`--casimir_rf_port` or `--casimir_rf_path` must be set");
+  }
+}
+
+Status ResultToStatus(Result<void> res) {
+  if (res.ok()) {
+    return Status::OK;
+  } else {
+    LOG(ERROR) << "RPC failed: " << res.error().FormatForEnv();
+    return Status(StatusCode::INTERNAL,
+                  res.error().FormatForEnv(/* color = */ false));
+  }
+}
 
 class CasimirControlServiceImpl final : public CasimirControlService::Service {
-  Status SendApdu(ServerContext* context, const SendApduRequest* request,
-                  SendApduReply* response) override {
-    // Step 0: Parse input
-    std::vector<std::shared_ptr<std::vector<uint8_t>>> apdu_bytes;
-    for (int i = 0; i < request->apdu_hex_strings_size(); i++) {
-      auto apdu_bytes_res =
-          cuttlefish::BytesArray(request->apdu_hex_strings(i));
-      if (!apdu_bytes_res.ok()) {
-        LOG(ERROR) << "Failed to parse input " << request->apdu_hex_strings(i)
-                   << ", " << apdu_bytes_res.error().FormatForEnv();
-        return Status(StatusCode::INVALID_ARGUMENT,
-                      "Failed to parse input. Must only contain [0-9a-fA-F]");
-      }
-      apdu_bytes.push_back(apdu_bytes_res.value());
+ private:
+  Status SetPowerLevel(ServerContext* context, const PowerLevel* power_level,
+                       Void*) override {
+    return ResultToStatus(SetPowerLevelResult(power_level));
+  }
+
+  Result<void> SetPowerLevelResult(const PowerLevel* power_level) {
+    if (!device_) {
+      return {};
     }
+    CF_EXPECT(device_->SetPowerLevel(power_level->power_level()),
+              "Failed to set power level");
+    return {};
+  }
 
+  Status Close(ServerContext* context, const Void*, Void* senderId) override {
+    device_ = std::nullopt;
+    return Status::OK;
+  }
+
+  Status Init(ServerContext*, const Void*, Void*) override {
+    return ResultToStatus(Init());
+  }
+
+  Result<void> Init() {
+    if (device_.has_value()) {
+      return {};
+    }
     // Step 1: Initialize connection with casimir
-    CasimirController device;
-    auto init_res = device.Init(FLAGS_casimir_rf_port);
-    if (!init_res.ok()) {
-      LOG(ERROR) << "Failed to initialize connection to casimir: "
-                 << init_res.error().FormatForEnv();
-      return Status(StatusCode::FAILED_PRECONDITION,
-                    "Failed to connect with casimir");
+    device_ = CF_EXPECT(ConnectToCasimir());
+    return {};
+  }
+
+  Result<void> Mute() {
+    if (!device_.has_value()) {
+      return {};
+    }
+
+    if (is_radio_on_) {
+      CF_EXPECT(device_->Mute(), "Failed to mute radio");
+      is_radio_on_ = false;
     }
+    return {};
+  }
 
+  Result<void> Unmute() {
+    if (!is_radio_on_) {
+      CF_EXPECT(device_->Unmute(), "Failed to unmute radio");
+      is_radio_on_ = true;
+    }
+    return {};
+  }
+
+  Status SetRadioState(ServerContext* context, const RadioState* radio_state,
+                       Void*) override {
+    return ResultToStatus(SetRadioStateResult(radio_state));
+  }
+
+  Result<void> SetRadioStateResult(const RadioState* radio_state) {
+    if (radio_state->radio_on()) {
+      CF_EXPECT(Init());
+      CF_EXPECT(Unmute());
+      return {};
+    } else {
+      if (!device_.has_value()) {
+        return {};
+      }
+      CF_EXPECT(Mute());
+      return {};
+    }
+  }
+
+  Result<void> PollAResult(SenderId* sender_id) {
+    // Step 1: Initialize connection with casimir
+    if (!device_.has_value()) {
+      device_ = CF_EXPECT(ConnectToCasimir(), "Failed to connect with casimir");
+      CF_EXPECT(Unmute(), "failed to unmute the device");
+    }
     // Step 2: Poll
-    auto poll_res = device.Poll();
-    if (!poll_res.ok()) {
-      LOG(ERROR) << "Failed to poll(): " << poll_res.error().FormatForEnv();
-      return Status(StatusCode::FAILED_PRECONDITION,
-                    "Failed to poll and select NFC-A and ISO-DEP");
+    /* Casimir control server seems to be dropping integer values of zero.
+      This works around that issue by translating the 0-based sender IDs to
+      be 1-based.*/
+    sender_id->set_sender_id(
+
+        CF_EXPECT(device_->Poll(),
+                  "Failed to poll and select NFC-A and ISO-DEP") +
+        1);
+    return {};
+  }
+
+  Status PollA(ServerContext*, const Void*, SenderId* sender_id) override {
+    return ResultToStatus(PollAResult(sender_id));
+  }
+
+  Result<void> SendApduResult(const SendApduRequest* request,
+                              SendApduReply* response) {
+    // Step 0: Parse input
+    std::vector<std::vector<uint8_t>> apdu_bytes;
+    for (const std::string& apdu_hex_string : request->apdu_hex_strings()) {
+      apdu_bytes.emplace_back(
+          CF_EXPECT(HexToBytes(apdu_hex_string),
+                    "Failed to parse input. Must only contain [0-9a-fA-F]"));
+    }
+    // Step 1: Initialize connection with casimir
+    CF_EXPECT(Init());
+
+    int16_t id;
+    if (request->has_sender_id()) {
+      /* Casimir control server seems to be dropping integer values of zero.
+        This works around that issue by translating the 0-based sender IDs to
+        be 1-based.*/
+      id = request->sender_id() - 1;
+    } else {
+      // Step 2: Poll
+      SenderId sender_id;
+      CF_EXPECT(PollAResult(&sender_id));
+      id = sender_id.sender_id();
     }
-    uint16_t id = poll_res.value();
 
     // Step 3: Send APDU bytes
     response->clear_response_hex_strings();
     for (int i = 0; i < apdu_bytes.size(); i++) {
-      auto send_res = device.SendApdu(id, apdu_bytes[i]);
-      if (!send_res.ok()) {
-        LOG(ERROR) << "Failed to send APDU bytes: "
-                   << send_res.error().FormatForEnv();
-        return Status(StatusCode::UNKNOWN, "Failed to send APDU bytes");
-      }
-      auto bytes = *(send_res.value());
-      auto resp = android::base::HexString(
+      std::vector<uint8_t> bytes =
+          CF_EXPECT(device_->SendApdu(id, std::move(apdu_bytes[i])),
+                    "Failed to send APDU bytes");
+      std::string resp = android::base::HexString(
           reinterpret_cast<void*>(bytes.data()), bytes.size());
-      response->add_response_hex_strings(resp);
+      response->add_response_hex_strings(std::move(resp));
     }
 
     // Returns OK although returned bytes is valids if ends with [0x90, 0x00].
-    return Status::OK;
+    return {};
+  }
+
+  Status SendApdu(ServerContext*, const SendApduRequest* request,
+                  SendApduReply* response) override {
+    return ResultToStatus(SendApduResult(request, response));
   }
+
+  std::optional<CasimirController> device_;
+  bool is_radio_on_ = false;
 };
 
-void RunServer() {
+void RunServer(int argc, char** argv) {
+  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
   std::string server_address("unix:" + FLAGS_grpc_uds_path);
   CasimirControlServiceImpl service;
 
@@ -123,9 +244,11 @@ void RunServer() {
   server->Wait();
 }
 
+}  // namespace
+}  // namespace cuttlefish
+
 int main(int argc, char** argv) {
-  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
-  RunServer();
+  cuttlefish::RunServer(argc, argv);
 
   return 0;
 }
diff --git a/host/commands/console_forwarder/Android.bp b/host/commands/console_forwarder/Android.bp
index aa41e934f..b52b736ca 100644
--- a/host/commands/console_forwarder/Android.bp
+++ b/host/commands/console_forwarder/Android.bp
@@ -24,9 +24,9 @@ cc_binary {
     ],
     shared_libs: [
         "libbase",
-        "libjsoncpp",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libjsoncpp",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/commands/control_env_proxy_server/Android.bp b/host/commands/control_env_proxy_server/Android.bp
index 0783d31e4..3639d1410 100644
--- a/host/commands/control_env_proxy_server/Android.bp
+++ b/host/commands/control_env_proxy_server/Android.bp
@@ -19,8 +19,8 @@ package {
 cc_library {
     name: "libcontrol_env_proxy_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libgflags",
@@ -49,17 +49,17 @@ cc_binary_host {
     shared_libs: [
         "libbase",
         "libcuttlefish_utils",
-        "libprotobuf-cpp-full",
         "libgrpc++",
         "libjsoncpp",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "grpc_cli_libs",
         "libabsl_host",
+        "libcontrol_env_proxy_server",
         "libcuttlefish_control_env",
         "libcuttlefish_host_config",
         "libgflags",
-        "libcontrol_env_proxy_server",
         "libgrpc++_reflection",
     ],
     srcs: [
diff --git a/host/commands/cvd_import_locations/Android.bp b/host/commands/cvd_import_locations/Android.bp
index 4f152c332..63b051203 100644
--- a/host/commands/cvd_import_locations/Android.bp
+++ b/host/commands/cvd_import_locations/Android.bp
@@ -22,9 +22,9 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libgrpc++_unsecure",
         "liblog",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
@@ -35,23 +35,23 @@ cc_binary {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
         "libxml2",
     ],
     static_libs: [
         "libcuttlefish_host_config",
-        "libgflags",
         "libcvd_gnss_grpc_proxy",
+        "libgflags",
         "liblocation",
     ],
     srcs: [
         "main.cc",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     defaults: ["cvd_import_locations_defaults"],
     target: {
@@ -70,17 +70,17 @@ cc_test_host {
         "libxml2",
     ],
     static_libs: [
-        "liblocation",
         "libgmock",
+        "liblocation",
     ],
     srcs: [
-        "unittest/main_test.cc",
-        "unittest/kml_parser_test.cc",
         "unittest/gpx_parser_test.cc",
+        "unittest/kml_parser_test.cc",
+        "unittest/main_test.cc",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     defaults: ["cvd_import_locations_defaults"],
     target: {
diff --git a/host/commands/cvd_send_id_disclosure/Android.bp b/host/commands/cvd_send_id_disclosure/Android.bp
index 2184bd969..760bc7f19 100644
--- a/host/commands/cvd_send_id_disclosure/Android.bp
+++ b/host/commands/cvd_send_id_disclosure/Android.bp
@@ -21,9 +21,9 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
-        "liblog",
         "libcuttlefish_utils",
         "libjsoncpp",
+        "liblog",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
@@ -43,8 +43,8 @@ cc_binary {
         "libgflags",
     ],
     srcs: [
-        "main.cc",
         "cellular_identifier_disclosure_command_builder.cc",
+        "main.cc",
     ],
     defaults: ["cvd_send_id_disclosure_defaults"],
 }
@@ -57,5 +57,8 @@ cc_test_host {
     shared_libs: [
         "libcvd_id_disclosure_builder",
     ],
-    defaults: ["cuttlefish_host", "cvd_send_id_disclosure_defaults"],
+    defaults: [
+        "cuttlefish_host",
+        "cvd_send_id_disclosure_defaults",
+    ],
 }
diff --git a/host/commands/cvd_send_sms/Android.bp b/host/commands/cvd_send_sms/Android.bp
index d280cd6b8..c0821c93b 100644
--- a/host/commands/cvd_send_sms/Android.bp
+++ b/host/commands/cvd_send_sms/Android.bp
@@ -22,8 +22,8 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
-        "liblog",
         "libicuuc",
+        "liblog",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
@@ -31,8 +31,8 @@ cc_defaults {
 cc_library {
     name: "libcvd_send_sms",
     srcs: [
+        "pdu_format_builder.cc",
         "sms_sender.cc",
-        "pdu_format_builder.cc"
     ],
     defaults: ["cvd_send_sms_defaults"],
 }
@@ -40,7 +40,7 @@ cc_library {
 cc_binary {
     name: "cvd_send_sms",
     srcs: [
-        "main.cc"
+        "main.cc",
     ],
     static_libs: [
         "libcvd_send_sms",
@@ -53,12 +53,12 @@ cc_test_host {
     name: "cvd_send_sms_test",
     srcs: [
         "unittest/main_test.cc",
-        "unittest/sms_sender_test.cc",
         "unittest/pdu_format_builder_test.cc",
+        "unittest/sms_sender_test.cc",
     ],
     static_libs: [
-        "libgmock",
         "libcvd_send_sms",
+        "libgmock",
     ],
     defaults: ["cvd_send_sms_defaults"],
 }
diff --git a/host/commands/cvd_update_location/Android.bp b/host/commands/cvd_update_location/Android.bp
index 19fb4e94b..217decf77 100644
--- a/host/commands/cvd_update_location/Android.bp
+++ b/host/commands/cvd_update_location/Android.bp
@@ -22,9 +22,9 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libgrpc++_unsecure",
         "liblog",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
@@ -35,22 +35,22 @@ cc_binary {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     static_libs: [
         "libcuttlefish_host_config",
-        "libgflags",
         "libcvd_gnss_grpc_proxy",
+        "libgflags",
         "liblocation",
     ],
     srcs: [
         "main.cc",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     defaults: ["cvd_update_location_defaults"],
     target: {
diff --git a/host/commands/cvd_update_security_algorithm/Android.bp b/host/commands/cvd_update_security_algorithm/Android.bp
index 650e5898c..d08deb5bf 100644
--- a/host/commands/cvd_update_security_algorithm/Android.bp
+++ b/host/commands/cvd_update_security_algorithm/Android.bp
@@ -21,9 +21,9 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
-        "liblog",
         "libcuttlefish_utils",
         "libjsoncpp",
+        "liblog",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
@@ -57,5 +57,8 @@ cc_test_host {
     shared_libs: [
         "libcvd_update_security_algorithm_builder",
     ],
-    defaults: ["cuttlefish_host", "cvd_update_security_algorithm_defaults"],
+    defaults: [
+        "cuttlefish_host",
+        "cvd_update_security_algorithm_defaults",
+    ],
 }
diff --git a/host/commands/display/Android.bp b/host/commands/display/Android.bp
index 786e5d91b..c64139c22 100644
--- a/host/commands/display/Android.bp
+++ b/host/commands/display/Android.bp
@@ -25,12 +25,15 @@ cc_binary_host {
     stl: "libc++_static",
     static_libs: [
         "libbase",
+        "libcuttlefish_command_util",
         "libcuttlefish_fs",
-        "libcuttlefish_utils",
         "libcuttlefish_host_config",
+        "libcuttlefish_run_cvd_proto",
+        "libcuttlefish_utils",
         "libgflags",
         "libjsoncpp",
         "liblog",
+        "libprotobuf-cpp-full",
     ],
     defaults: ["cuttlefish_host"],
 }
diff --git a/host/commands/display/main.cpp b/host/commands/display/main.cpp
index 990bd3ea2..8320a78c6 100644
--- a/host/commands/display/main.cpp
+++ b/host/commands/display/main.cpp
@@ -22,11 +22,14 @@
 
 #include <android-base/logging.h>
 #include <android-base/no_destructor.h>
+#include <android-base/parseint.h>
 #include <android-base/strings.h>
 
 #include "common/libs/utils/flag_parser.h"
 #include "common/libs/utils/subprocess.h"
+#include "device/google/cuttlefish/host/libs/command_util/runner/run_cvd.pb.h"
 #include "host/commands/assemble_cvd/flags_defaults.h"
+#include "host/libs/command_util/util.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/display.h"
 
@@ -61,6 +64,15 @@ usage: cvd display remove \\
         --display=<display id> ...
 )";
 
+static const char kScreenshotUsage[] =
+    R"(
+Screenshots the contents of a given display.
+
+Currently supported output formats: jpg, png, webp.
+
+usage: cvd display screenshot <display id> <screenshot path>
+)";
+
 Result<int> RunCrosvmDisplayCommand(int instance_num,
                                     const std::vector<std::string>& args) {
   auto config = cuttlefish::CuttlefishConfig::Get();
@@ -110,6 +122,7 @@ Result<int> DoHelp(std::vector<std::string>& args) {
           {"add", kAddUsage},
           {"list", kListUsage},
           {"remove", kRemoveUsage},
+          {"screenshot", kScreenshotUsage},
       });
 
   const std::string& subcommand_str = args[0];
@@ -201,16 +214,61 @@ Result<int> DoRemove(std::vector<std::string>& args) {
       RunCrosvmDisplayCommand(instance_num, remove_displays_command_args));
 }
 
+Result<int> DoScreenshot(std::vector<std::string>& args) {
+  const int instance_num = CF_EXPECT(GetInstanceNum(args));
+
+  auto config = cuttlefish::CuttlefishConfig::Get();
+  if (!config) {
+    return CF_ERR("Failed to get Cuttlefish config.");
+  }
+
+  int display_number = 0;
+  std::string screenshot_path;
+
+  std::vector<std::string> displays;
+  const std::vector<Flag> screenshot_flags = {
+      GflagsCompatFlag(kDisplayFlag, display_number)
+          .Help("Display id of a display to screenshot."),
+      GflagsCompatFlag("screenshot_path", screenshot_path)
+          .Help("Path for the resulting screenshot file."),
+  };
+  auto parse_res = ConsumeFlags(screenshot_flags, args);
+  if (!parse_res.ok()) {
+    std::cerr << parse_res.error().FormatForEnv() << std::endl;
+    std::cerr << "Failed to parse flags. Usage:" << std::endl;
+    std::cerr << kScreenshotUsage << std::endl;
+    return 1;
+  }
+  CF_EXPECT(!screenshot_path.empty(),
+            "Must provide --screenshot_path. Usage:" << kScreenshotUsage);
+
+  run_cvd::ExtendedLauncherAction extended_action;
+  extended_action.mutable_screenshot_display()->set_display_number(
+      display_number);
+  extended_action.mutable_screenshot_display()->set_screenshot_path(
+      screenshot_path);
+
+  std::cout << "Requesting to save screenshot for display " << display_number
+            << " to " << screenshot_path << "." << std::endl;
+
+  auto socket = CF_EXPECT(
+      GetLauncherMonitor(*config, instance_num, /*timeout_seconds=*/5));
+  CF_EXPECT(RunLauncherAction(socket, extended_action, std::nullopt),
+            "Failed to get success response from launcher.");
+  return 0;
+}
+
 using DisplaySubCommand = Result<int> (*)(std::vector<std::string>&);
 
 int DisplayMain(int argc, char** argv) {
   ::android::base::InitLogging(argv, android::base::StderrLogger);
 
   const std::unordered_map<std::string, DisplaySubCommand> kSubCommands = {
-      {"add", DoAdd},
-      {"list", DoList},
-      {"help", DoHelp},
-      {"remove", DoRemove},
+      {"add", DoAdd},                //
+      {"list", DoList},              //
+      {"help", DoHelp},              //
+      {"remove", DoRemove},          //
+      {"screenshot", DoScreenshot},  //
   };
 
   auto args = ArgsToVec(argc - 1, argv + 1);
diff --git a/host/commands/echo_server/Android.bp b/host/commands/echo_server/Android.bp
index 504d6c8da..833dd30ab 100644
--- a/host/commands/echo_server/Android.bp
+++ b/host/commands/echo_server/Android.bp
@@ -19,8 +19,8 @@ package {
 cc_library {
     name: "libecho_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libgflags",
@@ -52,13 +52,13 @@ cc_library {
 cc_binary_host {
     name: "echo_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libcuttlefish_host_config",
-        "libgflags",
         "libecho_server",
+        "libgflags",
         "libgrpc++_reflection",
     ],
     srcs: [
diff --git a/host/commands/gnss_grpc_proxy/Android.bp b/host/commands/gnss_grpc_proxy/Android.bp
index 2b4ac8450..b21242c12 100644
--- a/host/commands/gnss_grpc_proxy/Android.bp
+++ b/host/commands/gnss_grpc_proxy/Android.bp
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -23,17 +22,17 @@ cc_library {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     static_libs: [
         "libcuttlefish_host_config",
         "libgflags",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     generated_headers: [
         "GnssGrpcProxyStub_h",
@@ -62,22 +61,22 @@ cc_binary_host {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     static_libs: [
         "libcuttlefish_host_config",
-        "libgflags",
         "libcvd_gnss_grpc_proxy",
+        "libgflags",
         "libgrpc++_reflection",
     ],
     srcs: [
         "gnss_grpc_proxy.cpp",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     defaults: ["cuttlefish_host"],
     target: {
diff --git a/host/commands/host_bugreport/Android.bp b/host/commands/host_bugreport/Android.bp
index 24c9b68ff..41fad01b9 100644
--- a/host/commands/host_bugreport/Android.bp
+++ b/host/commands/host_bugreport/Android.bp
@@ -25,7 +25,7 @@ cc_binary {
     ],
     shared_libs: [
         "libbase",
-	    "libcuttlefish_command_util",
+        "libcuttlefish_command_util",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
         "libfruit",
diff --git a/host/commands/host_bugreport/main.cc b/host/commands/host_bugreport/main.cc
index 7767fe1ad..042c13411 100644
--- a/host/commands/host_bugreport/main.cc
+++ b/host/commands/host_bugreport/main.cc
@@ -212,7 +212,9 @@ Result<void> CvdHostBugreportMain(int argc, char** argv) {
 
   AddNetsimdLogs(writer);
 
-  SaveFile(writer, "cvd_host_bugreport.log", log_filename);
+  LOG(INFO) << "Building cvd bugreport completed";
+
+  SaveFile(writer, "cvd_bugreport_builder.log", log_filename);
 
   writer.Finish();
 
diff --git a/host/commands/kernel_log_monitor/Android.bp b/host/commands/kernel_log_monitor/Android.bp
index 960883377..b833c16ef 100644
--- a/host/commands/kernel_log_monitor/Android.bp
+++ b/host/commands/kernel_log_monitor/Android.bp
@@ -20,14 +20,14 @@ package {
 cc_binary {
     name: "kernel_log_monitor",
     srcs: [
-        "main.cc",
         "kernel_log_server.cc",
+        "main.cc",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
-        "libcuttlefish_utils",
         "libcuttlefish_kernel_log_monitor_utils",
-        "libbase",
+        "libcuttlefish_utils",
         "libjsoncpp",
     ],
     static_libs: [
@@ -48,9 +48,9 @@ cc_library {
         "utils.cc",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libbase",
         "libjsoncpp",
     ],
     target: {
diff --git a/host/commands/log_tee/Android.bp b/host/commands/log_tee/Android.bp
index c17d71e14..d37042d81 100644
--- a/host/commands/log_tee/Android.bp
+++ b/host/commands/log_tee/Android.bp
@@ -31,9 +31,9 @@ cc_binary {
         "libjsoncpp",
     ],
     static_libs: [
-        "libgflags",
         "libcuttlefish_host_config",
         "libcuttlefish_vm_manager",
+        "libgflags",
     ],
     target: {
         darwin: {
diff --git a/host/commands/logcat_receiver/Android.bp b/host/commands/logcat_receiver/Android.bp
index b5cde9a67..308620b61 100644
--- a/host/commands/logcat_receiver/Android.bp
+++ b/host/commands/logcat_receiver/Android.bp
@@ -25,9 +25,9 @@ cc_binary {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "liblog",
-        "libcuttlefish_utils",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/commands/metrics/Android.bp b/host/commands/metrics/Android.bp
index 3209c9339..e17e53e24 100644
--- a/host/commands/metrics/Android.bp
+++ b/host/commands/metrics/Android.bp
@@ -44,8 +44,8 @@ cc_binary {
     static_libs: [
         "libcuttlefish_host_config",
         "libcuttlefish_msg_queue",
-        "libgflags",
         "libext2_uuid",
+        "libgflags",
     ],
     defaults: ["cuttlefish_host"],
 }
@@ -65,9 +65,9 @@ cc_test_host {
         "libprotobuf-cpp-full",
     ],
     srcs: [
-        "utils.cc",
         "unittest/main_test.cc",
         "unittest/utils_tests.cpp",
+        "utils.cc",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/commands/metrics/proto/Android.bp b/host/commands/metrics/proto/Android.bp
index 54436b883..48bbd3446 100644
--- a/host/commands/metrics/proto/Android.bp
+++ b/host/commands/metrics/proto/Android.bp
@@ -21,10 +21,10 @@ cc_library_shared {
     vendor_available: true,
 
     srcs: [
-        "common.proto",
         "cf_log.proto",
         "cf_metrics_event.proto",
         "clientanalytics.proto",
+        "common.proto",
     ],
 
     shared_libs: [
@@ -40,16 +40,16 @@ cc_library_shared {
 
     cppflags: [
         "-Werror",
-        "-Wno-unused-parameter",
-        "-Wno-format",
         "-Wno-c++98-compat-pedantic",
-        "-Wno-float-conversion",
         "-Wno-disabled-macro-expansion",
+        "-Wno-float-conversion",
         "-Wno-float-equal",
-        "-Wno-sign-conversion",
-        "-Wno-padded",
+        "-Wno-format",
         "-Wno-old-style-cast",
+        "-Wno-padded",
+        "-Wno-sign-conversion",
         "-Wno-undef",
+        "-Wno-unused-parameter",
     ],
 
     defaults: ["cuttlefish_host"],
diff --git a/host/commands/modem_simulator/Android.bp b/host/commands/modem_simulator/Android.bp
index 9dec221a3..2ae447872 100644
--- a/host/commands/modem_simulator/Android.bp
+++ b/host/commands/modem_simulator/Android.bp
@@ -20,27 +20,27 @@ package {
 cc_defaults {
     name: "modem_simulator_base",
     srcs: [
+        "call_service.cpp",
+        "cf_device_config.cpp",
         "channel_monitor.cpp",
-        "thread_looper.cpp",
         "command_parser.cpp",
-        "modem_simulator.cpp",
+        "data_service.cpp",
+        "misc_service.cpp",
         "modem_service.cpp",
-        "sim_service.cpp",
+        "modem_simulator.cpp",
         "network_service.cpp",
-        "misc_service.cpp",
-        "call_service.cpp",
-        "data_service.cpp",
+        "nvram_config.cpp",
+        "pdu_parser.cpp",
+        "sim_service.cpp",
         "sms_service.cpp",
-        "sup_service.cpp",
         "stk_service.cpp",
-        "pdu_parser.cpp",
-        "cf_device_config.cpp",
-        "nvram_config.cpp"
+        "sup_service.cpp",
+        "thread_looper.cpp",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libbase",
         "libjsoncpp",
         "libnl",
     ],
@@ -49,16 +49,23 @@ cc_defaults {
         "libgflags",
         "libtinyxml2",
     ],
-    cflags: ["-Werror", "-Wall", "-fexceptions"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-fexceptions",
+    ],
     defaults: ["cuttlefish_host"],
 }
 
 cc_binary {
     name: "modem_simulator",
     srcs: [
-        "main.cpp"
+        "main.cpp",
+    ],
+    defaults: [
+        "cuttlefish_host",
+        "modem_simulator_base",
     ],
-    defaults: ["cuttlefish_host", "modem_simulator_base"],
 }
 
 prebuilt_etc {
@@ -109,13 +116,16 @@ prebuilt_etc_host {
 cc_test_host {
     name: "modem_simulator_test",
     srcs: [
-        "unittest/main_test.cpp",
-        "unittest/service_test.cpp",
         "unittest/command_parser_test.cpp",
+        "unittest/main_test.cpp",
         "unittest/pdu_parser_test.cpp",
+        "unittest/service_test.cpp",
     ],
     include_dirs: [
         "device/google/cuttlefish/host/commands",
     ],
-    defaults: ["cuttlefish_host", "modem_simulator_base"],
+    defaults: [
+        "cuttlefish_host",
+        "modem_simulator_base",
+    ],
 }
diff --git a/host/commands/openwrt_control_server/Android.bp b/host/commands/openwrt_control_server/Android.bp
index 5458cb465..fc25b2eb2 100644
--- a/host/commands/openwrt_control_server/Android.bp
+++ b/host/commands/openwrt_control_server/Android.bp
@@ -19,8 +19,8 @@ package {
 cc_library {
     name: "libopenwrt_control_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libgflags",
@@ -50,15 +50,15 @@ cc_binary_host {
         "libbase",
         "libcuttlefish_utils",
         "libcuttlefish_web",
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libcuttlefish_host_config",
         "libgflags",
+        "libgrpc++_reflection",
         "libjsoncpp",
         "libopenwrt_control_server",
-        "libgrpc++_reflection",
     ],
     srcs: [
         "main.cpp",
@@ -72,8 +72,8 @@ cc_binary_host {
 filegroup {
     name: "OpenwrtControlServerProto",
     srcs: [
-        "openwrt_control.proto",
         ":libprotobuf-internal-protos",
+        "openwrt_control.proto",
     ],
 }
 
diff --git a/host/commands/process_sandboxer/main.cpp b/host/commands/process_sandboxer/main.cpp
index 9197c046f..824c29765 100644
--- a/host/commands/process_sandboxer/main.cpp
+++ b/host/commands/process_sandboxer/main.cpp
@@ -32,6 +32,7 @@
 #include <absl/log/initialize.h>
 #include <absl/log/log.h>
 #include <absl/status/status.h>
+#include <absl/strings/match.h>
 #include <absl/strings/numbers.h>
 #include <absl/strings/str_cat.h>
 
@@ -50,7 +51,7 @@ ABSL_FLAG(std::string, environments_dir, "", "Cross-instance environment dir");
 ABSL_FLAG(std::string, environments_uds_dir, "", "Environment unix sockets");
 ABSL_FLAG(std::string, instance_uds_dir, "", "Instance unix domain sockets");
 ABSL_FLAG(std::string, guest_image_path, "", "Directory with `system.img`");
-ABSL_FLAG(std::string, log_dir, "", "Where to write log files");
+ABSL_FLAG(std::string, sandboxer_log_dir, "", "Where to write log files");
 ABSL_FLAG(std::vector<std::string>, log_files, std::vector<std::string>(),
           "File paths outside the sandbox to write logs to");
 ABSL_FLAG(std::string, runtime_dir, "",
@@ -85,10 +86,17 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
     return absl::ErrnoToStatus(errno, "prctl(PR_SET_CHILD_SUBREAPER failed");
   }
 
+  std::string early_tmp_dir(FromEnv("TEMP").value_or("/tmp"));
+  early_tmp_dir += "/XXXXXX";
+  if (mkdtemp(early_tmp_dir.data()) == nullptr) {
+    return absl::ErrnoToStatus(errno, "mkdtemp failed");
+  }
+
   HostInfo host{
       .assembly_dir = CleanPath(absl::GetFlag(FLAGS_assembly_dir)),
       .cuttlefish_config_path =
           CleanPath(FromEnv(kCuttlefishConfigEnvVarName).value_or("")),
+      .early_tmp_dir = early_tmp_dir,
       .environments_dir = CleanPath(absl::GetFlag(FLAGS_environments_dir)),
       .environments_uds_dir =
           CleanPath(absl::GetFlag(FLAGS_environments_uds_dir)),
@@ -96,7 +104,7 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
       .host_artifacts_path =
           CleanPath(absl::GetFlag(FLAGS_host_artifacts_path)),
       .instance_uds_dir = CleanPath(absl::GetFlag(FLAGS_instance_uds_dir)),
-      .log_dir = CleanPath(absl::GetFlag(FLAGS_log_dir)),
+      .log_dir = CleanPath(absl::GetFlag(FLAGS_sandboxer_log_dir)),
       .runtime_dir = CleanPath(absl::GetFlag(FLAGS_runtime_dir)),
       .vsock_device_dir = CleanPath(absl::GetFlag(FLAGS_vsock_device_dir)),
   };
@@ -184,6 +192,10 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
   std::string exe = CleanPath(args[1]);
   std::vector<std::string> exe_argv(++args.begin(), args.end());
 
+  if (absl::EndsWith(exe, "cvd_internal_start")) {
+    exe_argv.emplace_back("--early_tmp_dir=" + host.early_tmp_dir);
+  }
+
   auto sandbox_manager_res = SandboxManager::Create(std::move(host));
   if (!sandbox_manager_res.ok()) {
     return sandbox_manager_res.status();
diff --git a/host/commands/process_sandboxer/pidfd.cpp b/host/commands/process_sandboxer/pidfd.cpp
index c67480368..1a6f488ac 100644
--- a/host/commands/process_sandboxer/pidfd.cpp
+++ b/host/commands/process_sandboxer/pidfd.cpp
@@ -45,7 +45,7 @@
 namespace cuttlefish::process_sandboxer {
 
 absl::StatusOr<PidFd> PidFd::FromRunningProcess(pid_t pid) {
-  UniqueFd fd(syscall(SYS_pidfd_open, pid, 0));  // Always CLOEXEC
+  UniqueFd fd(syscall(__NR_pidfd_open, pid, 0));  // Always CLOEXEC
   if (fd.Get() < 0) {
     return absl::ErrnoToStatus(errno, "`pidfd_open` failed");
   }
@@ -62,7 +62,7 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
       .pidfd = reinterpret_cast<std::uintptr_t>(&pidfd),
   };
 
-  pid_t res = syscall(SYS_clone3, &args_for_clone, sizeof(args_for_clone));
+  pid_t res = syscall(__NR_clone3, &args_for_clone, sizeof(args_for_clone));
   if (res < 0) {
     std::string argv_str = absl::StrJoin(argv, "','");
     std::string error = absl::StrCat("clone3 failed: argv=['", argv_str, "']");
@@ -147,7 +147,7 @@ absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> PidFd::AllFds() {
       return absl::InternalError(error);
     }
     // Always CLOEXEC
-    UniqueFd our_fd(syscall(SYS_pidfd_getfd, fd_.Get(), other_fd, 0));
+    UniqueFd our_fd(syscall(__NR_pidfd_getfd, fd_.Get(), other_fd, 0));
     if (our_fd.Get() < 0) {
       return absl::ErrnoToStatus(errno, "`pidfd_getfd` failed");
     }
@@ -262,7 +262,7 @@ absl::Status PidFd::HaltChildHierarchy() {
 }
 
 absl::Status PidFd::SendSignal(int signal) {
-  if (syscall(SYS_pidfd_send_signal, fd_.Get(), signal, nullptr, 0) < 0) {
+  if (syscall(__NR_pidfd_send_signal, fd_.Get(), signal, nullptr, 0) < 0) {
     return absl::ErrnoToStatus(errno, "pidfd_send_signal failed");
   }
   return absl::OkStatus();
diff --git a/host/commands/process_sandboxer/policies.cpp b/host/commands/process_sandboxer/policies.cpp
index 12e197c16..6e54e1c9d 100644
--- a/host/commands/process_sandboxer/policies.cpp
+++ b/host/commands/process_sandboxer/policies.cpp
@@ -50,6 +50,9 @@ absl::Status HostInfo::EnsureOutputDirectoriesExist() {
   if (!CreateDirectoryRecursively(runtime_dir, 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + runtime_dir);
   }
+  if (!CreateDirectoryRecursively(vsock_device_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + runtime_dir);
+  }
   return absl::OkStatus();
 }
 
@@ -62,6 +65,7 @@ std::ostream& operator<<(std::ostream& out, const HostInfo& host) {
   out << "\tassembly_dir: \"" << host.assembly_dir << "\"\n";
   out << "\tcuttlefish_config_path: \"" << host.cuttlefish_config_path
       << "\"\n";
+  out << "\tearly_tmp_dir: \"" << host.early_tmp_dir << "\"\n";
   out << "\tenvironments_dir: \"" << host.environments_dir << "\"\n";
   out << "\tenvironments_uds_dir: " << host.environments_uds_dir << "\"\n";
   out << "\tguest_image_path: " << host.guest_image_path << "\t\n";
diff --git a/host/commands/process_sandboxer/policies.h b/host/commands/process_sandboxer/policies.h
index 8ba2348ab..94bcd754b 100644
--- a/host/commands/process_sandboxer/policies.h
+++ b/host/commands/process_sandboxer/policies.h
@@ -34,6 +34,7 @@ struct HostInfo {
 
   std::string assembly_dir;
   std::string cuttlefish_config_path;
+  std::string early_tmp_dir;
   std::string environments_dir;
   std::string environments_uds_dir;
   std::string guest_image_path;
diff --git a/host/commands/process_sandboxer/policies/assemble_cvd.cpp b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
index fb8730ec5..0e7d6cbb8 100644
--- a/host/commands/process_sandboxer/policies/assemble_cvd.cpp
+++ b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
@@ -38,12 +38,13 @@ sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo& host) {
       // TODO(schuffelen): Copy these files before modifying them
       .AddDirectory(JoinPath(host.host_artifacts_path, "etc", "openwrt"),
                     /* is_ro= */ false)
-      // TODO(schuffelen): Premake the directory for boot image unpack outputs
-      .AddDirectory("/tmp", /* is_ro= */ false)
+      .AddDirectory(host.early_tmp_dir, /* is_ro= */ false)
       .AddDirectory(host.environments_dir, /* is_ro= */ false)
       .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
       .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory("/tmp/cf_avd_1000", /* is_ro= */ false)
       .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
       // `webRTC` actually uses this file, but `assemble_cvd` first checks
       // whether it exists in order to decide whether to connect to it.
       .AddFile("/run/cuttlefish/operator")
@@ -52,20 +53,6 @@ sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo& host) {
       .AddFileAt(sandboxer_proxy, host.HostToolExe("mkenvimage_slim"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("newfs_msdos"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("simg2img"))
-      .AddDirectory(host.environments_dir)
-      .AddDirectory(host.environments_uds_dir, false)
-      .AddDirectory(host.instance_uds_dir, false)
-      // The UID inside the sandbox2 namespaces is always 1000.
-      .AddDirectoryAt(host.environments_uds_dir,
-                      absl::StrReplaceAll(
-                          host.environments_uds_dir,
-                          {{absl::StrCat("cf_env_", getuid()), "cf_env_1000"}}),
-                      false)
-      .AddDirectoryAt(host.instance_uds_dir,
-                      absl::StrReplaceAll(
-                          host.instance_uds_dir,
-                          {{absl::StrCat("cf_avd_", getuid()), "cf_avd_1000"}}),
-                      false)
       .AddPolicyOnSyscall(__NR_madvise,
                           {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
       .AddPolicyOnSyscall(__NR_prctl,
diff --git a/host/commands/process_sandboxer/policies/avbtool.cpp b/host/commands/process_sandboxer/policies/avbtool.cpp
index 5a3e04da1..d5bedd6b8 100644
--- a/host/commands/process_sandboxer/policies/avbtool.cpp
+++ b/host/commands/process_sandboxer/policies/avbtool.cpp
@@ -69,9 +69,6 @@ sandbox2::PolicyBuilder AvbToolPolicy(const HostInfo& host) {
       .AddDirectory(host.guest_image_path)
       .AddDirectory(host.runtime_dir, /* is_ro= */ false)
       .AddDirectoryAt(fake_proc_self, "/proc/self")
-      // `assemble_cvd` uses `mkdtemp` in `/tmp` and passes the path to avbtool.
-      // TODO: schuffelen - make this more predictable
-      .AddDirectory("/tmp", /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For Python
       .AddFileAt(host.HostToolExe("sandboxer_proxy"), "/usr/bin/openssl")
       // The executable `open`s itself to load the python files.
diff --git a/host/commands/process_sandboxer/policies/casimir.cpp b/host/commands/process_sandboxer/policies/casimir.cpp
index 481ce65a5..4c33ff90e 100644
--- a/host/commands/process_sandboxer/policies/casimir.cpp
+++ b/host/commands/process_sandboxer/policies/casimir.cpp
@@ -17,11 +17,11 @@
 #include "host/commands/process_sandboxer/policies.h"
 
 #include <netinet/ip_icmp.h>
+#include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
 #include <sys/syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -29,6 +29,10 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder CasimirPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("casimir"))
+      // `librustutils::inherited_fd` scans `/proc/self/fd` for open FDs.
+      // Mounting a subset of `/proc/` is invalid.
+      .AddDirectory("/proc", /* is_ro = */ false)
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
       .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
         return {
             ARG_32(2),  // prot
@@ -49,13 +53,14 @@ sandbox2::PolicyBuilder CasimirPolicy(const HostInfo& host) {
                 JEQ32(ICMP_REDIR_NETTOS, ALLOW),
                 LABEL(&labels, cf_casimir_setsockopt_end)};
           })
-      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW)})
-      .Allow(sandbox2::UnrestrictedNetworking())
+      .AddPolicyOnSyscall(__NR_ioctl, {ARG_32(1), JEQ32(FIONBIO, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
       .AllowEpoll()
       .AllowEpollWait()
       .AllowEventFd()
       .AllowHandleSignals()
       .AllowPrctlSetName()
+      .AllowReaddir()
       .AllowSafeFcntl()
       .AllowSyscall(__NR_accept4)
       .AllowSyscall(__NR_bind)
diff --git a/host/commands/process_sandboxer/policies/casimir_control_server.cpp b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
index cabce4c5c..bebfe7c33 100644
--- a/host/commands/process_sandboxer/policies/casimir_control_server.cpp
+++ b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
@@ -20,7 +20,6 @@
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -28,9 +27,9 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("casimir_control_server"))
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
       .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
-      .AddFile("/dev/urandom")                    // For gRPC
-      .Allow(sandbox2::UnrestrictedNetworking())  // Communicate with casimir
+      .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscall(__NR_madvise,
                           {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
       .AddPolicyOnSyscall(
@@ -63,7 +62,8 @@ sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo& host) {
       .AllowSyscall(__NR_sched_getscheduler)
       .AllowSyscall(__NR_sched_yield)
       .AllowSyscall(__NR_sendmsg)
-      .AllowSyscall(__NR_shutdown);
+      .AllowSyscall(__NR_shutdown)
+      .AllowTCGETS();
 }
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/modem_simulator.cpp b/host/commands/process_sandboxer/policies/modem_simulator.cpp
index 97aefe04c..9f6f8a8cc 100644
--- a/host/commands/process_sandboxer/policies/modem_simulator.cpp
+++ b/host/commands/process_sandboxer/policies/modem_simulator.cpp
@@ -21,11 +21,13 @@
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
+#include "host/commands/process_sandboxer/filesystem.h"
+
 namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder ModemSimulatorPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("modem_simulator"))
-      .AddDirectory(host.host_artifacts_path + "/etc/modem_simulator")
+      .AddDirectory(JoinPath(host.host_artifacts_path, "/etc/modem_simulator"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddDirectory(host.runtime_dir, /* is_ro= */ false)  // modem_nvram.json
       .AddFile(host.cuttlefish_config_path)
diff --git a/host/commands/process_sandboxer/policies/netsimd.cpp b/host/commands/process_sandboxer/policies/netsimd.cpp
index e9620e17f..e9799f185 100644
--- a/host/commands/process_sandboxer/policies/netsimd.cpp
+++ b/host/commands/process_sandboxer/policies/netsimd.cpp
@@ -34,7 +34,6 @@ namespace cuttlefish::process_sandboxer {
 sandbox2::PolicyBuilder NetsimdPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("netsimd"))
       .AddDirectory(JoinPath(host.host_artifacts_path, "bin", "netsim-ui"))
-      .AddDirectory("/tmp", /* is_ro= */ false)  // to create new directories
       .AddDirectory(JoinPath(host.runtime_dir, "internal"), /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscalls(
@@ -69,6 +68,7 @@ sandbox2::PolicyBuilder NetsimdPolicy(const HostInfo& host) {
                           {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
       .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW),
                                         JEQ32(AF_INET6, ALLOW)})
+      .AddTmpfs("/tmp", 1 << 20)
       .Allow(sandbox2::UnrestrictedNetworking())
       .AllowDup()
       .AllowEpoll()
diff --git a/host/commands/process_sandboxer/policies/tcp_connector.cpp b/host/commands/process_sandboxer/policies/tcp_connector.cpp
index ea683f759..63eadb5da 100644
--- a/host/commands/process_sandboxer/policies/tcp_connector.cpp
+++ b/host/commands/process_sandboxer/policies/tcp_connector.cpp
@@ -26,9 +26,11 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder TcpConnectorPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("tcp_connector"))
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
-      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW),
+                                        JEQ32(AF_UNIX, ALLOW)})
       .Allow(sandbox2::UnrestrictedNetworking())
       .AllowSafeFcntl()
       .AllowSleep()
diff --git a/host/commands/process_sandboxer/policies/webrtc.cpp b/host/commands/process_sandboxer/policies/webrtc.cpp
index 3272ad059..c9117e4aa 100644
--- a/host/commands/process_sandboxer/policies/webrtc.cpp
+++ b/host/commands/process_sandboxer/policies/webrtc.cpp
@@ -16,6 +16,7 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/sockios.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <sys/ioctl.h>
@@ -35,7 +36,8 @@ namespace cuttlefish::process_sandboxer {
 sandbox2::PolicyBuilder WebRtcPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("webRTC"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
-      .AddDirectory(host.host_artifacts_path + "/usr/share/webrtc/assets")
+      .AddDirectory(
+          JoinPath(host.host_artifacts_path, "/usr/share/webrtc/assets"))
       .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
       .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
       .AddDirectory(JoinPath(host.runtime_dir, "recording"), /* is_ro= */ false)
diff --git a/host/commands/process_sandboxer/proxy_common.cpp b/host/commands/process_sandboxer/proxy_common.cpp
index 4b12cb281..82212e728 100644
--- a/host/commands/process_sandboxer/proxy_common.cpp
+++ b/host/commands/process_sandboxer/proxy_common.cpp
@@ -13,21 +13,21 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#include "proxy_common.h"
+#include "host/commands/process_sandboxer/proxy_common.h"
 
 #include <sys/socket.h>
 
-#include <absl/status/statusor.h>
-#include <absl/strings/numbers.h>
-
 #include <cstdlib>
 #include <string>
-#include "absl/status/status.h"
+
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+#include <absl/strings/numbers.h>
 
 namespace cuttlefish::process_sandboxer {
 
 absl::StatusOr<Message> Message::RecvFrom(int sock) {
-  msghdr empty_hdr;
+  msghdr empty_hdr = {};
   int len = recvmsg(sock, &empty_hdr, MSG_PEEK | MSG_TRUNC);
   if (len < 0) {
     return absl::ErrnoToStatus(errno, "recvmsg with MSG_PEEK failed");
diff --git a/host/commands/process_sandboxer/proxy_common.h b/host/commands/process_sandboxer/proxy_common.h
index fe80c0656..9e2629a0f 100644
--- a/host/commands/process_sandboxer/proxy_common.h
+++ b/host/commands/process_sandboxer/proxy_common.h
@@ -19,12 +19,12 @@
 #include <sys/socket.h>
 #include <sys/un.h>
 
-#include "absl/status/statusor.h"
-
 #include <optional>
 #include <string>
 #include <string_view>
 
+#include <absl/status/statusor.h>
+
 namespace cuttlefish {
 namespace process_sandboxer {
 
diff --git a/host/commands/process_sandboxer/sandbox_manager.cpp b/host/commands/process_sandboxer/sandbox_manager.cpp
index e6cf6fd64..929bc3a80 100644
--- a/host/commands/process_sandboxer/sandbox_manager.cpp
+++ b/host/commands/process_sandboxer/sandbox_manager.cpp
@@ -29,12 +29,15 @@
 
 #include <memory>
 #include <sstream>
+#include <thread>
 #include <utility>
 
 #include <absl/functional/bind_front.h>
 #include <absl/log/log.h>
 #include <absl/log/vlog_is_on.h>
 #include <absl/memory/memory.h>
+#include <absl/random/bit_gen_ref.h>
+#include <absl/random/uniform_int_distribution.h>
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
 #include <absl/strings/numbers.h>
@@ -45,7 +48,6 @@
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wunused-parameter"
 #include <sandboxed_api/sandbox2/executor.h>
-#include <sandboxed_api/sandbox2/notify.h>
 #include <sandboxed_api/sandbox2/policy.h>
 #include <sandboxed_api/sandbox2/sandbox2.h>
 #include <sandboxed_api/sandbox2/util.h>
@@ -152,6 +154,15 @@ class SandboxManager::SandboxedProcess : public SandboxManager::ManagedProcess {
   std::unique_ptr<Sandbox2> sandbox_;
 };
 
+std::string RandomString(absl::BitGenRef gen, std::size_t size) {
+  std::stringstream output;
+  absl::uniform_int_distribution<char> distribution;
+  for (std::size_t i = 0; i < size; i++) {
+    output << distribution(gen);
+  }
+  return output.str();
+}
+
 class SandboxManager::SocketClient {
  public:
   SocketClient(SandboxManager& manager, UniqueFd client_fd)
@@ -191,11 +202,13 @@ class SandboxManager::SocketClient {
     switch (client_state_) {
       case ClientState::kInitial: {
         if (message != kHandshakeBegin) {
-          auto err = absl::StrFormat("'%v' != '%v'", kHandshakeBegin, message);
+          std::string err =
+              absl::StrFormat("'%v' != '%v'", kHandshakeBegin, message);
           return absl::InternalError(err);
         }
-        pingback_ = std::chrono::steady_clock::now().time_since_epoch().count();
-        auto stat = SendStringMsg(client_fd_.Get(), std::to_string(pingback_));
+        pingback_ = RandomString(manager_.bit_gen_, 32);
+        absl::StatusOr<std::size_t> stat =
+            SendStringMsg(client_fd_.Get(), pingback_);
         if (stat.ok()) {
           client_state_ = ClientState::kIgnoredFd;
         }
@@ -203,18 +216,16 @@ class SandboxManager::SocketClient {
       }
       case ClientState::kIgnoredFd:
         if (!absl::SimpleAtoi(message, &ignored_fd_)) {
-          auto error = absl::StrFormat("Expected integer, got '%v'", message);
+          std::string error =
+              absl::StrFormat("Expected integer, got '%v'", message);
           return absl::InternalError(error);
         }
         client_state_ = ClientState::kPingback;
         return absl::OkStatus();
       case ClientState::kPingback: {
-        size_t comp;
-        if (!absl::SimpleAtoi(message, &comp)) {
-          auto error = absl::StrFormat("Expected integer, got '%v'", message);
-          return absl::InternalError(error);
-        } else if (comp != pingback_) {
-          auto err = absl::StrFormat("Incorrect '%v' != '%v'", comp, pingback_);
+        if (message != pingback_) {
+          std::string err =
+              absl::StrFormat("Incorrect '%v' != '%v'", message, pingback_);
           return absl::InternalError(err);
         }
         client_state_ = ClientState::kWaitingForExit;
@@ -295,7 +306,7 @@ class SandboxManager::SocketClient {
   std::optional<PidFd> pid_fd_;
 
   ClientState client_state_ = ClientState::kInitial;
-  size_t pingback_;
+  std::string pingback_;
   int ignored_fd_ = -1;
 };
 
@@ -378,17 +389,6 @@ absl::Status SandboxManager::RunProcess(
   }
 }
 
-class TraceAndAllow : public sandbox2::Notify {
- public:
-  TraceAction EventSyscallTrace(const Syscall& syscall) override {
-    std::string prog_name = GetProgName(syscall.pid());
-    LOG(WARNING) << "[PERMITTED]: SYSCALL ::: PID: " << syscall.pid()
-                 << ", PROG: '" << prog_name
-                 << "' : " << syscall.GetDescription();
-    return TraceAction::kAllow;
-  }
-};
-
 absl::Status SandboxManager::RunSandboxedProcess(
     std::optional<int> client_fd, absl::Span<const std::string> argv,
     std::vector<std::pair<UniqueFd, int>> fds,
@@ -427,11 +427,7 @@ absl::Status SandboxManager::RunSandboxedProcess(
     return absl::ErrnoToStatus(errno, "`eventfd` failed");
   }
 
-  // TODO: b/318576505 - Don't allow unknown system calls.
-  std::unique_ptr<sandbox2::Notify> notify(new TraceAndAllow());
-
-  auto sbx = std::make_unique<Sandbox2>(std::move(executor), std::move(policy),
-                                        std::move(notify));
+  auto sbx = std::make_unique<Sandbox2>(std::move(executor), std::move(policy));
   if (!sbx->RunAsync()) {
     return sbx->AwaitResult().ToStatus();
   }
diff --git a/host/commands/process_sandboxer/sandbox_manager.h b/host/commands/process_sandboxer/sandbox_manager.h
index 8051ba60a..5711f68cc 100644
--- a/host/commands/process_sandboxer/sandbox_manager.h
+++ b/host/commands/process_sandboxer/sandbox_manager.h
@@ -23,6 +23,7 @@
 #include <utility>
 #include <vector>
 
+#include <absl/random/random.h>
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
 #include <absl/types/span.h>
@@ -97,6 +98,7 @@ class SandboxManager {
   std::list<std::unique_ptr<SocketClient>> clients_;
   SignalFd signals_;
   CredentialedUnixServer server_;
+  absl::BitGen bit_gen_;
 };
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/sandboxer_proxy.cpp b/host/commands/process_sandboxer/sandboxer_proxy.cpp
index a99c0798f..48b82d99b 100644
--- a/host/commands/process_sandboxer/sandboxer_proxy.cpp
+++ b/host/commands/process_sandboxer/sandboxer_proxy.cpp
@@ -21,8 +21,8 @@
 
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
+#include <absl/strings/numbers.h>
 
-#include "absl/strings/numbers.h"
 #include "proxy_common.h"
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/run_cvd/Android.bp b/host/commands/run_cvd/Android.bp
index e1d0355e7..d13798f5a 100644
--- a/host/commands/run_cvd/Android.bp
+++ b/host/commands/run_cvd/Android.bp
@@ -23,35 +23,35 @@ cc_binary_host {
         "boot_state_machine.cc",
         "launch/automotive_proxy.cpp",
         "launch/bluetooth_connector.cpp",
-        "launch/nfc_connector.cpp",
-        "launch/uwb_connector.cpp",
+        "launch/casimir.cpp",
         "launch/casimir_control_server.cpp",
         "launch/console_forwarder.cpp",
         "launch/control_env_proxy_server.cpp",
+        "launch/echo_server.cpp",
         "launch/gnss_grpc_proxy.cpp",
+        "launch/grpc_socket_creator.cpp",
         "launch/kernel_log_monitor.cpp",
-        "launch/logcat_receiver.cpp",
         "launch/log_tee_creator.cpp",
-        "launch/grpc_socket_creator.cpp",
+        "launch/logcat_receiver.cpp",
         "launch/metrics.cpp",
+        "launch/netsim_server.cpp",
+        "launch/nfc_connector.cpp",
         "launch/openwrt_control_server.cpp",
-        "launch/echo_server.cpp",
-        "launch/root_canal.cpp",
-        "launch/casimir.cpp",
         "launch/pica.cpp",
+        "launch/root_canal.cpp",
         "launch/screen_recording_server.cpp",
         "launch/secure_env.cpp",
         "launch/snapshot_control_files.cpp",
-        "launch/webrtc_recorder.cpp",
         "launch/streamer.cpp",
-        "launch/netsim_server.cpp",
+        "launch/uwb_connector.cpp",
         "launch/vhal_proxy_server.cpp",
+        "launch/webrtc_controller.cpp",
         "main.cc",
         "reporting.cpp",
         "server_loop.cpp",
         "server_loop_impl.cpp",
-        "server_loop_impl_record.cpp",
         "server_loop_impl_snapshot.cpp",
+        "server_loop_impl_webrtc.cpp",
         "validate.cpp",
     ],
     shared_libs: [
@@ -60,11 +60,14 @@ cc_binary_host {
         "libcuttlefish_kernel_log_monitor_utils",
         "libcuttlefish_run_cvd_proto",
         "libcuttlefish_utils",
+        "libcuttlefish_webrtc_command_channel",
+        "libcuttlefish_webrtc_commands_proto",
         "libext2_blkid",
         "libfruit",
+        "libgoogleapis-status-proto",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
     ],
     static_libs: [
         "libbuildversion",
@@ -77,14 +80,14 @@ cc_binary_host {
         "libcuttlefish_process_monitor",
         "libcuttlefish_utils",
         "libcuttlefish_vm_manager",
-        "libopenwrt_control_server",
         "libgflags",
+        "libopenwrt_control_server",
     ],
     required: [
         "console_forwarder",
         "kernel_log_monitor",
-        "logcat_receiver",
         "log_tee",
+        "logcat_receiver",
         "secure_env",
         "tcp_connector",
     ],
diff --git a/host/commands/run_cvd/boot_state_machine.cc b/host/commands/run_cvd/boot_state_machine.cc
index 733ed2e04..03f05e0ba 100644
--- a/host/commands/run_cvd/boot_state_machine.cc
+++ b/host/commands/run_cvd/boot_state_machine.cc
@@ -30,7 +30,9 @@
 #include <grpcpp/create_channel.h>
 #include "common/libs/utils/result.h"
 
+#include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/files.h"
 #include "common/libs/utils/tee_logging.h"
 #include "host/commands/assemble_cvd/flags_defaults.h"
 #include "host/commands/kernel_log_monitor/kernel_log_server.h"
@@ -53,6 +55,65 @@ DEFINE_int32(reboot_notification_fd, CF_DEFAULTS_REBOOT_NOTIFICATION_FD,
 namespace cuttlefish {
 namespace {
 
+Result<void> MoveThreadsToCgroup(const std::string& from_path,
+                                 const std::string& to_path) {
+  std::string file_path = from_path + "/cgroup.threads";
+
+  if (FileExists(file_path)) {
+    Result<std::string> content_result = ReadFileContents(file_path);
+    if (!content_result.ok()) {
+      LOG(INFO) << "Failed to open threads file and assume it is empty: "
+                << file_path;
+      return {};
+    }
+
+    std::istringstream is(content_result.value());
+    std::string each_id;
+    while (std::getline(is, each_id)) {
+      std::string proc_status_path = "/proc/" + each_id;
+      proc_status_path.append("/status");
+      Result<std::string> proc_status = ReadFileContents(proc_status_path);
+      if (!proc_status.ok()) {
+        LOG(INFO) << "Failed to open proc status file and skip: "
+                  << proc_status_path;
+        continue;
+      }
+
+      std::string proc_status_str = proc_status.value();
+      if (proc_status_str.find("crosvm_vcpu") == std::string::npos &&
+          proc_status_str.find("vcpu_throttle") == std::string::npos) {
+        // other proc moved to workers cgroup
+        std::string to_path_file = to_path + "/cgroup.threads";
+        SharedFD fd = SharedFD::Open(to_path_file, O_WRONLY | O_APPEND);
+        CF_EXPECT(fd->IsOpen(),
+                  "failed to open " << to_path_file << ": " << fd->StrError());
+        if (WriteAll(fd, each_id) != each_id.size()) {
+          return CF_ERR("failed to write to" << to_path_file);
+        }
+      }
+    }
+  }
+
+  return {};
+}
+
+// See go/vcpuinheritance for more context on why this Rebalance is
+// required and what the stop gap/longterm solutions are.
+Result<void> WattsonRebalanceThreads(const std::string& id) {
+  auto root_path = "/sys/fs/cgroup/vsoc-" + id + "-cf";
+  const auto files = CF_EXPECT(DirectoryContents(root_path));
+
+  CF_EXPECT(MoveThreadsToCgroup(root_path, root_path + "/workers"));
+
+  for (const auto& filename : files) {
+    if (filename.find("vcpu-domain") != std::string::npos) {
+      CF_EXPECT(MoveThreadsToCgroup(root_path + "/" + filename,
+                                    root_path + "/workers"));
+    }
+  }
+  return {};
+}
+
 // Forks run_cvd into a daemonized child process. The current process continues
 // only until the child has signalled that the boot is finished.
 //
@@ -78,6 +139,9 @@ Result<SharedFD> DaemonizeLauncher(const CuttlefishConfig& config) {
         LOG(INFO) << "Virtual device restored successfully";
       } else {
         LOG(INFO) << "Virtual device booted successfully";
+        if (!instance.vcpu_config_path().empty()) {
+          CF_EXPECT(WattsonRebalanceThreads(instance.id()));
+        }
       }
     } else if (exit_code == RunnerExitCodes::kVirtualDeviceBootFailed) {
       if (IsRestoring(config)) {
@@ -200,7 +264,6 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
 
   // SetupFeature
   std::string Name() const override { return "CvdBootStateMachine"; }
-  bool Enabled() const override { return true; }
 
  private:
   std::unordered_set<SetupFeature*> Dependencies() const {
@@ -416,6 +479,12 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
     if ((*read_result)->event == monitor::Event::BootCompleted) {
       LOG(INFO) << "Virtual device booted successfully";
       state_ |= kGuestBootCompleted;
+      if (!instance_.vcpu_config_path().empty()) {
+        auto res = WattsonRebalanceThreads(instance_.id());
+        if (!res.ok()) {
+          LOG(ERROR) << res.error().FormatForEnv();
+        }
+      }
     } else if ((*read_result)->event == monitor::Event::BootFailed) {
       LOG(ERROR) << "Virtual device failed to boot";
       state_ |= kGuestBootFailed;
diff --git a/host/commands/run_cvd/launch/auto_cmd.h b/host/commands/run_cvd/launch/auto_cmd.h
index 59ed22239..902102499 100644
--- a/host/commands/run_cvd/launch/auto_cmd.h
+++ b/host/commands/run_cvd/launch/auto_cmd.h
@@ -70,10 +70,6 @@ class GenericCommandSource : public CommandSource,
     return {};
   }
 
-  bool Enabled() const override {
-    return true;  // TODO(schuffelen): Delete `Enabled()`, it hasn't been useful
-  }
-
   std::string Name() const override {
     static constexpr auto kName = ValueName<Fn>();
     return std::string(kName);
diff --git a/host/commands/run_cvd/launch/casimir.cpp b/host/commands/run_cvd/launch/casimir.cpp
index f889bf757..fffff1ff3 100644
--- a/host/commands/run_cvd/launch/casimir.cpp
+++ b/host/commands/run_cvd/launch/casimir.cpp
@@ -16,12 +16,12 @@
 #include "host/commands/run_cvd/launch/launch.h"
 
 #include <string>
-#include <unordered_set>
 #include <utility>
 #include <vector>
 
 #include <fruit/fruit.h>
 
+#include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/result.h"
 #include "host/commands/run_cvd/launch/log_tee_creator.h"
 #include "host/libs/config/command_source.h"
@@ -32,30 +32,39 @@ namespace cuttlefish {
 
 Result<std::vector<MonitorCommand>> Casimir(
     const CuttlefishConfig& config,
+    const CuttlefishConfig::EnvironmentSpecific& environment,
     const CuttlefishConfig::InstanceSpecific& instance,
     LogTeeCreator& log_tee) {
   if (!(config.enable_host_nfc() && instance.start_casimir())) {
     return {};
   }
 
-  Command command(ProcessRestarterBinary());
-  command.AddParameter("-when_killed");
-  command.AddParameter("-when_dumped");
-  command.AddParameter("-when_exited_with_failure");
-  command.AddParameter("--");
-
-  command.AddParameter(CasimirBinary());
-  command.AddParameter("--nci-port");
-  command.AddParameter(config.casimir_nci_port());
-  command.AddParameter("--rf-port");
-  command.AddParameter(config.casimir_rf_port());
+  SharedFD nci_server = SharedFD::SocketLocalServer(
+      environment.casimir_nci_socket_path(), false, SOCK_STREAM, 0600);
+  CF_EXPECTF(nci_server->IsOpen(), "{}", nci_server->StrError());
+
+  SharedFD rf_server = SharedFD::SocketLocalServer(
+      environment.casimir_rf_socket_path(), false, SOCK_STREAM, 0600);
+  CF_EXPECTF(rf_server->IsOpen(), "{}", rf_server->StrError());
+
+  Command casimir = Command(ProcessRestarterBinary())
+                        .AddParameter("-when_killed")
+                        .AddParameter("-when_dumped")
+                        .AddParameter("-when_exited_with_failure")
+                        .AddParameter("--")
+                        .AddParameter(CasimirBinary())
+                        .AddParameter("--nci-unix-fd")
+                        .AddParameter(nci_server)
+                        .AddParameter("--rf-unix-fd")
+                        .AddParameter(rf_server);
+
   for (auto const& arg : config.casimir_args()) {
-    command.AddParameter(arg);
+    casimir.AddParameter(arg);
   }
 
   std::vector<MonitorCommand> commands;
-  commands.emplace_back(CF_EXPECT(log_tee.CreateLogTee(command, "casimir")));
-  commands.emplace_back(std::move(command));
+  commands.emplace_back(CF_EXPECT(log_tee.CreateLogTee(casimir, "casimir")));
+  commands.emplace_back(std::move(casimir));
   return commands;
 }
 
diff --git a/host/commands/run_cvd/launch/casimir_control_server.cpp b/host/commands/run_cvd/launch/casimir_control_server.cpp
index 841b88841..7d533ddbd 100644
--- a/host/commands/run_cvd/launch/casimir_control_server.cpp
+++ b/host/commands/run_cvd/launch/casimir_control_server.cpp
@@ -33,6 +33,7 @@ namespace cuttlefish {
 
 Result<std::optional<MonitorCommand>> CasimirControlServer(
     const CuttlefishConfig& config,
+    const CuttlefishConfig::EnvironmentSpecific& environment,
     const CuttlefishConfig::InstanceSpecific& instance,
     GrpcSocketCreator& grpc_socket) {
   if (!config.enable_host_nfc()) {
@@ -45,8 +46,8 @@ Result<std::optional<MonitorCommand>> CasimirControlServer(
   Command casimir_control_server_cmd(CasimirControlServerBinary());
   casimir_control_server_cmd.AddParameter(
       "-grpc_uds_path=", grpc_socket.CreateGrpcSocket("CasimirControlServer"));
-  casimir_control_server_cmd.AddParameter("-casimir_rf_port=",
-                                          config.casimir_rf_port());
+  casimir_control_server_cmd.AddParameter("-casimir_rf_path=",
+                                          environment.casimir_rf_socket_path());
   return casimir_control_server_cmd;
 }
 
diff --git a/host/commands/run_cvd/launch/control_env_proxy_server.cpp b/host/commands/run_cvd/launch/control_env_proxy_server.cpp
index 9c03b781d..db3f88643 100644
--- a/host/commands/run_cvd/launch/control_env_proxy_server.cpp
+++ b/host/commands/run_cvd/launch/control_env_proxy_server.cpp
@@ -50,7 +50,6 @@ class ControlEnvProxyServer : public CommandSource {
 
   // SetupFeature
   std::string Name() const override { return "ControlEnvProxyServer"; }
-  bool Enabled() const override { return true; }
 
  private:
   std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
diff --git a/host/commands/run_cvd/launch/kernel_log_monitor.cpp b/host/commands/run_cvd/launch/kernel_log_monitor.cpp
index be3ed690f..d40921410 100644
--- a/host/commands/run_cvd/launch/kernel_log_monitor.cpp
+++ b/host/commands/run_cvd/launch/kernel_log_monitor.cpp
@@ -81,7 +81,6 @@ class KernelLogMonitor : public CommandSource,
 
  private:
   // SetupFeature
-  bool Enabled() const override { return true; }
   std::string Name() const override { return "KernelLogMonitor"; }
 
  private:
diff --git a/host/commands/run_cvd/launch/launch.h b/host/commands/run_cvd/launch/launch.h
index 01abfbba0..b68a03476 100644
--- a/host/commands/run_cvd/launch/launch.h
+++ b/host/commands/run_cvd/launch/launch.h
@@ -27,7 +27,7 @@
 #include "host/commands/run_cvd/launch/grpc_socket_creator.h"
 #include "host/commands/run_cvd/launch/log_tee_creator.h"
 #include "host/commands/run_cvd/launch/snapshot_control_files.h"
-#include "host/commands/run_cvd/launch/webrtc_recorder.h"
+#include "host/commands/run_cvd/launch/webrtc_controller.h"
 #include "host/commands/run_cvd/launch/wmediumd_server.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/custom_actions.h"
@@ -50,8 +50,9 @@ VhostDeviceVsockComponent();
 Result<std::optional<MonitorCommand>> BluetoothConnector(
     const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&);
 
-Result<MonitorCommand> NfcConnector(const CuttlefishConfig&,
-                                    const CuttlefishConfig::InstanceSpecific&);
+Result<MonitorCommand> NfcConnector(
+    const CuttlefishConfig::EnvironmentSpecific&,
+    const CuttlefishConfig::InstanceSpecific&);
 
 fruit::Component<fruit::Required<const CuttlefishConfig::InstanceSpecific>,
                  KernelLogPipeProvider>
@@ -62,8 +63,8 @@ Result<MonitorCommand> LogcatReceiver(
 std::string LogcatInfo(const CuttlefishConfig::InstanceSpecific&);
 
 Result<std::optional<MonitorCommand>> CasimirControlServer(
-    const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&,
-    GrpcSocketCreator&);
+    const CuttlefishConfig&, const CuttlefishConfig::EnvironmentSpecific&,
+    const CuttlefishConfig::InstanceSpecific&, GrpcSocketCreator&);
 
 Result<std::optional<MonitorCommand>> ConsoleForwarder(
     const CuttlefishConfig::InstanceSpecific&);
@@ -94,8 +95,8 @@ fruit::Component<
 RootCanalComponent();
 
 Result<std::vector<MonitorCommand>> Casimir(
-    const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&,
-    LogTeeCreator&);
+    const CuttlefishConfig&, const CuttlefishConfig::EnvironmentSpecific&,
+    const CuttlefishConfig::InstanceSpecific&, LogTeeCreator&);
 
 Result<std::vector<MonitorCommand>> Pica(
     const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&,
@@ -128,10 +129,10 @@ Result<std::optional<MonitorCommand>> ModemSimulator(
 fruit::Component<
     fruit::Required<const CuttlefishConfig, KernelLogPipeProvider,
                     const CuttlefishConfig::InstanceSpecific,
-                    const CustomActionConfigProvider, WebRtcRecorder>>
+                    const CustomActionConfigProvider, WebRtcController>>
 launchStreamerComponent();
 
-fruit::Component<WebRtcRecorder> WebRtcRecorderComponent();
+fruit::Component<WebRtcController> WebRtcControllerComponent();
 
 fruit::Component<
     fruit::Required<const CuttlefishConfig,
diff --git a/host/commands/run_cvd/launch/nfc_connector.cpp b/host/commands/run_cvd/launch/nfc_connector.cpp
index ede35fa09..7b5ef875f 100644
--- a/host/commands/run_cvd/launch/nfc_connector.cpp
+++ b/host/commands/run_cvd/launch/nfc_connector.cpp
@@ -24,6 +24,7 @@
 
 #include "common/libs/utils/result.h"
 #include "host/libs/config/command_source.h"
+#include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
 
 constexpr const size_t kBufferSize = 1024;
@@ -31,7 +32,7 @@ constexpr const size_t kBufferSize = 1024;
 namespace cuttlefish {
 
 Result<MonitorCommand> NfcConnector(
-    const CuttlefishConfig& config,
+    const CuttlefishConfig::EnvironmentSpecific& environment,
     const CuttlefishConfig::InstanceSpecific& instance) {
   std::vector<std::string> fifo_paths = {
       instance.PerInstanceInternalPath("nfc_fifo_vm.in"),
@@ -44,7 +45,7 @@ Result<MonitorCommand> NfcConnector(
   return Command(TcpConnectorBinary())
       .AddParameter("-fifo_out=", fifos[0])
       .AddParameter("-fifo_in=", fifos[1])
-      .AddParameter("-data_port=", config.casimir_nci_port())
+      .AddParameter("-data_path=", environment.casimir_nci_socket_path())
       .AddParameter("-buffer_size=", kBufferSize);
 }
 
diff --git a/host/commands/run_cvd/launch/streamer.cpp b/host/commands/run_cvd/launch/streamer.cpp
index b27fb7bd8..126bb86b6 100644
--- a/host/commands/run_cvd/launch/streamer.cpp
+++ b/host/commands/run_cvd/launch/streamer.cpp
@@ -111,6 +111,9 @@ class StreamerSockets : public virtual SetupFeature {
         cmd.AppendToLastParameter(",", touch_servers_[i]);
       }
     }
+    if (instance_.enable_mouse()) {
+      cmd.AddParameter("-mouse_fd=", mouse_server_);
+    }
     cmd.AddParameter("-rotary_fd=", rotary_server_);
     cmd.AddParameter("-keyboard_fd=", keyboard_server_);
     cmd.AddParameter("-frame_server_fd=", frames_server_);
@@ -143,6 +146,10 @@ class StreamerSockets : public virtual SetupFeature {
       CF_EXPECT(touch_socket->IsOpen(), touch_socket->StrError());
       touch_servers_.emplace_back(std::move(touch_socket));
     }
+    if (instance_.enable_mouse()) {
+      mouse_server_ = CreateUnixInputServer(instance_.mouse_socket_path());
+      CF_EXPECT(mouse_server_->IsOpen(), mouse_server_->StrError());
+    }
     rotary_server_ =
         CreateUnixInputServer(instance_.rotary_socket_path());
 
@@ -187,6 +194,7 @@ class StreamerSockets : public virtual SetupFeature {
   const CuttlefishConfig& config_;
   const CuttlefishConfig::InstanceSpecific& instance_;
   std::vector<SharedFD> touch_servers_;
+  SharedFD mouse_server_;
   SharedFD rotary_server_;
   SharedFD keyboard_server_;
   SharedFD frames_server_;
@@ -206,13 +214,13 @@ class WebRtcServer : public virtual CommandSource,
                       StreamerSockets& sockets,
                       KernelLogPipeProvider& log_pipe_provider,
                       const CustomActionConfigProvider& custom_action_config,
-                      WebRtcRecorder& webrtc_recorder))
+                      WebRtcController& webrtc_controller))
       : config_(config),
         instance_(instance),
         sockets_(sockets),
         log_pipe_provider_(log_pipe_provider),
         custom_action_config_(custom_action_config),
-        webrtc_recorder_(webrtc_recorder) {}
+        webrtc_controller_(webrtc_controller) {}
   // DiagnosticInformation
   std::vector<std::string> Diagnostics() const override {
     if (!Enabled() ||
@@ -250,8 +258,8 @@ class WebRtcServer : public virtual CommandSource,
       commands.emplace_back(std::move(sig_proxy));
     }
 
-    auto stopper = [webrtc_recorder = webrtc_recorder_]() {
-      webrtc_recorder.SendStopRecordingCommand();
+    auto stopper = [webrtc_controller = webrtc_controller_]() mutable {
+      (void)webrtc_controller.SendStopRecordingCommand();
       return StopperResult::kStopFailure;
     };
 
@@ -271,7 +279,7 @@ class WebRtcServer : public virtual CommandSource,
     // issue is mitigated slightly by doing some retrying and backoff in the
     // webrtc process when connecting to the websocket, so it shouldn't be an
     // issue most of the time.
-    webrtc.AddParameter("--command_fd=", webrtc_recorder_.GetClientSocket());
+    webrtc.AddParameter("--command_fd=", webrtc_controller_.GetClientSocket());
     webrtc.AddParameter("-kernel_log_events_fd=", kernel_log_events_pipe_);
     webrtc.AddParameter("-client_dir=",
                         DefaultHostArtifactsPath("usr/share/webrtc/assets"));
@@ -296,7 +304,7 @@ class WebRtcServer : public virtual CommandSource,
   std::unordered_set<SetupFeature*> Dependencies() const override {
     return {static_cast<SetupFeature*>(&sockets_),
             static_cast<SetupFeature*>(&log_pipe_provider_),
-            static_cast<SetupFeature*>(&webrtc_recorder_)};
+            static_cast<SetupFeature*>(&webrtc_controller_)};
   }
 
   Result<void> ResultSetup() override {
@@ -316,7 +324,7 @@ class WebRtcServer : public virtual CommandSource,
   StreamerSockets& sockets_;
   KernelLogPipeProvider& log_pipe_provider_;
   const CustomActionConfigProvider& custom_action_config_;
-  WebRtcRecorder& webrtc_recorder_;
+  WebRtcController& webrtc_controller_;
   SharedFD kernel_log_events_pipe_;
   SharedFD switches_server_;
 };
@@ -326,7 +334,7 @@ class WebRtcServer : public virtual CommandSource,
 fruit::Component<
     fruit::Required<const CuttlefishConfig, KernelLogPipeProvider,
                     const CuttlefishConfig::InstanceSpecific,
-                    const CustomActionConfigProvider, WebRtcRecorder>>
+                    const CustomActionConfigProvider, WebRtcController>>
 launchStreamerComponent() {
   return fruit::createComponent()
       .addMultibinding<CommandSource, WebRtcServer>()
diff --git a/host/commands/run_cvd/launch/vhal_proxy_server.cpp b/host/commands/run_cvd/launch/vhal_proxy_server.cpp
index a2bd5c1ba..296950bb1 100644
--- a/host/commands/run_cvd/launch/vhal_proxy_server.cpp
+++ b/host/commands/run_cvd/launch/vhal_proxy_server.cpp
@@ -19,6 +19,7 @@
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/known_paths.h"
+#include "host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h"
 
 #include <linux/vm_sockets.h>
 
@@ -33,7 +34,8 @@ std::optional<MonitorCommand> VhalProxyServer(
   int port = config.vhal_proxy_server_port();
   Command command = Command(VhalProxyServerBinary())
                         .AddParameter(VhalProxyServerConfig())
-                        .AddParameter(fmt::format("localhost:{}", port));
+                        .AddParameter(fmt::format(
+                            "{}:{}", vhal_proxy_server::kEthAddr, port));
   if (instance.vhost_user_vsock()) {
     command.AddParameter(
         fmt::format("unix://{}", SharedFD::GetVhostUserVsockServerAddr(
diff --git a/host/commands/run_cvd/launch/webrtc_controller.cpp b/host/commands/run_cvd/launch/webrtc_controller.cpp
new file mode 100644
index 000000000..13c5ae567
--- /dev/null
+++ b/host/commands/run_cvd/launch/webrtc_controller.cpp
@@ -0,0 +1,96 @@
+//
+// Copyright (C) 2023 The Android Open Source Project
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
+#include "host/commands/run_cvd/launch/webrtc_controller.h"
+
+#include <android-base/logging.h>
+#include <fruit/fruit.h>
+
+#include "common/libs/fs/shared_buf.h"
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/transport/channel_sharedfd.h"
+#include "common/libs/utils/result.h"
+#include "google/rpc/code.pb.h"
+#include "host/commands/run_cvd/launch/launch.h"
+#include "webrtc_commands.pb.h"
+
+namespace cuttlefish {
+namespace {
+
+Result<void> IsSuccess(const webrtc::WebrtcCommandResponse& response) {
+  CF_EXPECT(response.has_status(), "Webrtc command response missing status?");
+  const auto& response_status = response.status();
+  CF_EXPECT_EQ(response_status.code(), google::rpc::Code::OK,
+               "Webrtc command failed: " << response_status.message());
+  return {};
+}
+
+}  // namespace
+
+using webrtc::WebrtcCommandRequest;
+using webrtc::WebrtcCommandResponse;
+
+Result<void> WebRtcController::ResultSetup() {
+  LOG(DEBUG) << "Initializing the WebRTC command sockets.";
+  SharedFD host_socket;
+  CF_EXPECT(SharedFD::SocketPair(AF_LOCAL, SOCK_STREAM, 0, &client_socket_,
+                                 &host_socket),
+            client_socket_->StrError());
+
+  command_channel_.emplace(host_socket);
+  return {};
+}
+
+SharedFD WebRtcController::GetClientSocket() const { return client_socket_; }
+
+Result<void> WebRtcController::SendStartRecordingCommand() {
+  CF_EXPECT(command_channel_.has_value(), "Not initialized?");
+  WebrtcCommandRequest request;
+  request.mutable_start_recording_request();
+  WebrtcCommandResponse response =
+      CF_EXPECT(command_channel_->SendCommand(request));
+  CF_EXPECT(IsSuccess(response), "Failed to start recording.");
+  return {};
+}
+
+Result<void> WebRtcController::SendStopRecordingCommand() {
+  CF_EXPECT(command_channel_.has_value(), "Not initialized?");
+  WebrtcCommandRequest request;
+  request.mutable_stop_recording_request();
+  WebrtcCommandResponse response =
+      CF_EXPECT(command_channel_->SendCommand(request));
+  CF_EXPECT(IsSuccess(response), "Failed to stop recording.");
+  return {};
+}
+
+Result<void> WebRtcController::SendScreenshotDisplayCommand(
+    int display_number, const std::string& screenshot_path) {
+  CF_EXPECT(command_channel_.has_value(), "Not initialized?");
+  WebrtcCommandRequest request;
+  auto* screenshot_request = request.mutable_screenshot_display_request();
+  screenshot_request->set_display_number(display_number);
+  screenshot_request->set_screenshot_path(screenshot_path);
+  WebrtcCommandResponse response =
+      CF_EXPECT(command_channel_->SendCommand(request));
+  CF_EXPECT(IsSuccess(response), "Failed to screenshot display.");
+  return {};
+}
+
+fruit::Component<WebRtcController> WebRtcControllerComponent() {
+  return fruit::createComponent()
+      .addMultibinding<SetupFeature, WebRtcController>();
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/webrtc_recorder.h b/host/commands/run_cvd/launch/webrtc_controller.h
similarity index 64%
rename from host/commands/run_cvd/launch/webrtc_recorder.h
rename to host/commands/run_cvd/launch/webrtc_controller.h
index 4344f27fd..a703fcccb 100644
--- a/host/commands/run_cvd/launch/webrtc_recorder.h
+++ b/host/commands/run_cvd/launch/webrtc_controller.h
@@ -18,36 +18,35 @@
 #include <android-base/logging.h>
 #include <fruit/fruit.h>
 
-#include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/config/feature.h"
 
+#include "host/frontend/webrtc/webrtc_command_channel.h"
+#include "webrtc_commands.pb.h"
+
 namespace cuttlefish {
 
-class WebRtcRecorder : public SetupFeature {
+class WebRtcController : public SetupFeature {
  public:
-  INJECT(WebRtcRecorder()) {};
-  std::string Name() const override { return "WebRtcRecorder"; }
-  bool Enabled() const override { return true; }
+  INJECT(WebRtcController()) {};
+  std::string Name() const override { return "WebRtcController"; }
   Result<void> ResultSetup() override;
 
   SharedFD GetClientSocket() const;
-  Result<void> SendStartRecordingCommand() const;
-  Result<void> SendStopRecordingCommand() const;
-
+  Result<void> SendStartRecordingCommand();
+  Result<void> SendStopRecordingCommand();
+  Result<void> SendScreenshotDisplayCommand(int display_number,
+                                            const std::string& screenshot_path);
 
  protected:
   SharedFD client_socket_;
-  SharedFD host_socket_;
-
+  std::optional<WebrtcClientCommandChannel> command_channel_;
 
  private:
   std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
-
-  Result<void> SendCommandAndVerifyResponse(std::string message) const;
 };
 
-fruit::Component<WebRtcRecorder> WebRtcRecorderComponent();
+fruit::Component<WebRtcController> WebRtcControllerComponent();
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/webrtc_recorder.cpp b/host/commands/run_cvd/launch/webrtc_recorder.cpp
deleted file mode 100644
index b97955a41..000000000
--- a/host/commands/run_cvd/launch/webrtc_recorder.cpp
+++ /dev/null
@@ -1,71 +0,0 @@
-//
-// Copyright (C) 2023 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host/commands/run_cvd/launch/webrtc_recorder.h"
-
-#include <android-base/logging.h>
-#include <fruit/fruit.h>
-
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/result.h"
-#include "common/libs/utils/result.h"
-#include "host/commands/run_cvd/launch/launch.h"
-
-namespace cuttlefish {
-
-Result<void> WebRtcRecorder::ResultSetup() {
- LOG(DEBUG) << "Initializing the WebRTC recording sockets.";
- CF_EXPECT(SharedFD::SocketPair(AF_LOCAL, SOCK_STREAM, 0, &client_socket_,
-                                &host_socket_),
-           client_socket_->StrError());
- struct timeval timeout;
- timeout.tv_sec = 3;
- timeout.tv_usec = 0;
- CHECK(host_socket_->SetSockOpt(SOL_SOCKET, SO_RCVTIMEO, &timeout,
-                                sizeof(timeout)) == 0)
-     << "Could not set receive timeout";
- return {};
-}
-
-SharedFD WebRtcRecorder::GetClientSocket() const { return client_socket_;}
-
-Result<void> WebRtcRecorder::SendStartRecordingCommand() const {
- CF_EXPECT(SendCommandAndVerifyResponse("T"));
- return {};
-}
-
-Result<void> WebRtcRecorder::SendStopRecordingCommand() const {
- CF_EXPECT(SendCommandAndVerifyResponse("C"));
- return {};
-}
-
-Result<void> WebRtcRecorder::SendCommandAndVerifyResponse(std::string message) const {
- CF_EXPECTF(WriteAll(host_socket_, message) == message.size(),
-            "Failed to send message:  '{}'", message);
- char response[1];
- int read_ret = host_socket_->Read(response, sizeof(response));
- CF_EXPECT_NE(read_ret, 0,
-              "Failed to read response from the recording manager.");
- CF_EXPECT_EQ(response[0], 'Y',
-              "Did not receive expected success response from the recording "
-              "manager.");
- return {};
-}
-
-fruit::Component<WebRtcRecorder> WebRtcRecorderComponent() {
-  return fruit::createComponent().addMultibinding<SetupFeature, WebRtcRecorder>();
-}
-
-}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/run_cvd/main.cc b/host/commands/run_cvd/main.cc
index 1cbe1439d..0b5860c0c 100644
--- a/host/commands/run_cvd/main.cc
+++ b/host/commands/run_cvd/main.cc
@@ -118,6 +118,11 @@ fruit::Component<> runCvdComponent(
     const CuttlefishConfig* config,
     const CuttlefishConfig::EnvironmentSpecific* environment,
     const CuttlefishConfig::InstanceSpecific* instance) {
+  // WARNING: The install order indirectly controls the order that processes
+  // are started and stopped. The start order shouldn't matter, but if the stop
+  // order is inccorect, then some processes may crash on shutdown. For
+  // example, vhost-user processes must be stopped *after* VMM processes (so,
+  // sort vhost-user before VMM in this list).
   return fruit::createComponent()
       .addMultibinding<DiagnosticInformation, CuttlefishEnvironment>()
       .addMultibinding<InstanceLifecycle, InstanceLifecycle>()
@@ -130,7 +135,6 @@ fruit::Component<> runCvdComponent(
       .install(AutoCmd<ModemSimulator>::Component)
       .install(AutoCmd<TombstoneReceiver>::Component)
       .install(McuComponent)
-      .install(OpenWrtComponent)
       .install(VhostDeviceVsockComponent)
       .install(WmediumdServerComponent)
       .install(launchStreamerComponent)
@@ -167,10 +171,15 @@ fruit::Component<> runCvdComponent(
       .install(AutoSnapshotControlFiles::Component)
       .install(AutoCmd<SecureEnv>::Component)
       .install(serverLoopComponent)
-      .install(WebRtcRecorderComponent)
+      .install(WebRtcControllerComponent)
       .install(AutoSetup<ValidateTapDevices>::Component)
       .install(AutoSetup<ValidateHostConfiguration>::Component)
       .install(AutoSetup<ValidateHostKernel>::Component)
+#ifdef __linux__
+      // OpenWrtComponent spawns a VMM and so has similar install order
+      // requirements to VmManagerComponent.
+      .install(OpenWrtComponent)
+#endif
       .install(vm_manager::VmManagerComponent);
 }
 
diff --git a/host/commands/run_cvd/server_loop.cpp b/host/commands/run_cvd/server_loop.cpp
index 81fd0ee6f..840308788 100644
--- a/host/commands/run_cvd/server_loop.cpp
+++ b/host/commands/run_cvd/server_loop.cpp
@@ -18,7 +18,7 @@
 
 #include <fruit/fruit.h>
 
-#include "host/commands/run_cvd/launch/webrtc_recorder.h"
+#include "host/commands/run_cvd/launch/webrtc_controller.h"
 #include "host/commands/run_cvd/server_loop_impl.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/feature.h"
@@ -31,7 +31,7 @@ ServerLoop::~ServerLoop() = default;
 fruit::Component<
     fruit::Required<const CuttlefishConfig,
                     const CuttlefishConfig::InstanceSpecific,
-                    AutoSnapshotControlFiles::Type, WebRtcRecorder>,
+                    AutoSnapshotControlFiles::Type, WebRtcController>,
     ServerLoop>
 serverLoopComponent() {
   using run_cvd_impl::ServerLoopImpl;
diff --git a/host/commands/run_cvd/server_loop.h b/host/commands/run_cvd/server_loop.h
index 0ceeee0cb..a307a3ffd 100644
--- a/host/commands/run_cvd/server_loop.h
+++ b/host/commands/run_cvd/server_loop.h
@@ -19,7 +19,7 @@
 #include <fruit/fruit.h>
 
 #include "host/commands/run_cvd/launch/snapshot_control_files.h"
-#include "host/commands/run_cvd/launch/webrtc_recorder.h"
+#include "host/commands/run_cvd/launch/webrtc_controller.h"
 #include "host/libs/config/cuttlefish_config.h"
 
 namespace cuttlefish {
@@ -33,7 +33,7 @@ class ServerLoop {
 fruit::Component<
     fruit::Required<const CuttlefishConfig,
                     const CuttlefishConfig::InstanceSpecific,
-                    AutoSnapshotControlFiles::Type, WebRtcRecorder>,
+                    AutoSnapshotControlFiles::Type, WebRtcController>,
     ServerLoop>
 serverLoopComponent();
 }
diff --git a/host/commands/run_cvd/server_loop_impl.cpp b/host/commands/run_cvd/server_loop_impl.cpp
index f326ac2e8..b411e5ef3 100644
--- a/host/commands/run_cvd/server_loop_impl.cpp
+++ b/host/commands/run_cvd/server_loop_impl.cpp
@@ -63,11 +63,11 @@ ServerLoopImpl::ServerLoopImpl(
     const CuttlefishConfig& config,
     const CuttlefishConfig::InstanceSpecific& instance,
     AutoSnapshotControlFiles::Type& snapshot_control_files,
-    WebRtcRecorder& webrtc_recorder)
+    WebRtcController& webrtc_controller)
     : config_(config),
       instance_(instance),
       snapshot_control_files_(snapshot_control_files),
-      webrtc_recorder_(webrtc_recorder),
+      webrtc_controller_(webrtc_controller),
       vm_name_to_control_sock_{InitializeVmToControlSockPath(instance)},
       device_status_{DeviceStatus::kUnknown} {}
 
@@ -78,16 +78,18 @@ Result<void> ServerLoopImpl::LateInject(fruit::Injector<>& injector) {
 
 Result<void> ServerLoopImpl::Run() {
   // Monitor and restart host processes supporting the CVD
-  auto process_monitor_properties =
-      ProcessMonitor::Properties()
-          .RestartSubprocesses(instance_.restart_subprocesses())
-          .StraceLogDir(instance_.PerInstanceLogPath(""))
-          .StraceCommands(config_.straced_host_executables());
+  auto process_monitor_properties = ProcessMonitor::Properties();
+  process_monitor_properties.RestartSubprocesses(
+      instance_.restart_subprocesses());
+  process_monitor_properties.StraceLogDir(instance_.PerInstanceLogPath(""));
+  process_monitor_properties.StraceCommands(config_.straced_host_executables());
 
   for (auto& command_source : command_sources_) {
     if (command_source->Enabled()) {
       auto commands = CF_EXPECT(command_source->Commands());
-      process_monitor_properties.AddCommands(std::move(commands));
+      for (auto& command : commands) {
+        process_monitor_properties.AddCommand(std::move(command));
+      }
     }
   }
   const auto& channel_to_secure_env =
@@ -186,6 +188,12 @@ Result<void> ServerLoopImpl::HandleExtended(
       CF_EXPECT(HandleStopScreenRecording());
       return {};
     }
+    case ActionsCase::kScreenshotDisplay: {
+      LOG(DEBUG) << "Run_cvd received screenshot display request.";
+      const auto& request = action_info.extended_action.screenshot_display();
+      CF_EXPECT(HandleScreenshotDisplay(request));
+      return {};
+    }
     default:
       return CF_ERR("Unsupported ExtendedLauncherAction");
   }
@@ -333,6 +341,7 @@ bool ServerLoopImpl::PowerwashFiles() {
 
   // TODO(b/269669405): Figure out why this file is not being deleted
   unlink(instance_.CrosvmSocketPath().c_str());
+  unlink(instance_.OpenwrtCrosvmSocketPath().c_str());
 
   // TODO(schuffelen): Clean up duplication with assemble_cvd
   unlink(instance_.PerInstancePath("NVChip").c_str());
diff --git a/host/commands/run_cvd/server_loop_impl.h b/host/commands/run_cvd/server_loop_impl.h
index dde74b05f..4703cce07 100644
--- a/host/commands/run_cvd/server_loop_impl.h
+++ b/host/commands/run_cvd/server_loop_impl.h
@@ -27,7 +27,7 @@
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/json.h"
 #include "common/libs/utils/result.h"
-#include "host/commands/run_cvd/launch/webrtc_recorder.h"
+#include "host/commands/run_cvd/launch/webrtc_controller.h"
 #include "host/commands/run_cvd/server_loop.h"
 #include "host/libs/command_util/runner/defs.h"
 #include "host/libs/command_util/util.h"
@@ -47,7 +47,7 @@ class ServerLoopImpl : public ServerLoop,
   INJECT(ServerLoopImpl(const CuttlefishConfig& config,
                         const CuttlefishConfig::InstanceSpecific& instance,
                         AutoSnapshotControlFiles::Type& snapshot_control_files,
-                        WebRtcRecorder& webrtc_recorder));
+                        WebRtcController& webrtc_controller));
 
   Result<void> LateInject(fruit::Injector<>& injector) override;
 
@@ -64,7 +64,6 @@ class ServerLoopImpl : public ServerLoop,
   };
 
  private:
-  bool Enabled() const override { return true; }
   std::unordered_set<SetupFeature*> Dependencies() const override {
     return {&snapshot_control_files_};
   }
@@ -76,6 +75,8 @@ class ServerLoopImpl : public ServerLoop,
   Result<void> HandleSnapshotTake(const run_cvd::SnapshotTake& snapshot_take);
   Result<void> HandleStartScreenRecording();
   Result<void> HandleStopScreenRecording();
+  Result<void> HandleScreenshotDisplay(
+      const run_cvd::ScreenshotDisplay& request);
 
   void HandleActionWithNoData(const LauncherAction action,
                               const SharedFD& client,
@@ -105,7 +106,7 @@ class ServerLoopImpl : public ServerLoop,
    * secure_env, and get the responses.
    */
   AutoSnapshotControlFiles::Type& snapshot_control_files_;
-  WebRtcRecorder& webrtc_recorder_;
+  WebRtcController& webrtc_controller_;
   std::vector<CommandSource*> command_sources_;
   SharedFD server_;
   // mapping from the name of vm_manager to control_sock path
diff --git a/host/commands/run_cvd/server_loop_impl_snapshot.cpp b/host/commands/run_cvd/server_loop_impl_snapshot.cpp
index f9ccc3c13..11eccb79b 100644
--- a/host/commands/run_cvd/server_loop_impl_snapshot.cpp
+++ b/host/commands/run_cvd/server_loop_impl_snapshot.cpp
@@ -147,18 +147,24 @@ Result<void> ServerLoopImpl::ResumeGuest() {
 static Result<void> RunAdbShellCommand(
     const CuttlefishConfig::InstanceSpecific& ins,
     const std::vector<std::string>& command_args) {
-  Command adb_command(SubtoolPath("adb"));
+  // Make sure device is connected, otherwise the following `adb -s SERIAL
+  // wait-for-device shell ...` would get stuck.
+  Command connect_cmd(SubtoolPath("adb"));
   // Avoid the adb server being started in the runtime directory and looking
   // like a process that is still using the directory.
-  adb_command.SetWorkingDirectory("/");
-  adb_command.AddParameter("-s").AddParameter(ins.adb_ip_and_port());
-  adb_command.AddParameter("wait-for-device");
+  connect_cmd.SetWorkingDirectory("/");
+  connect_cmd.AddParameter("connect");
+  connect_cmd.AddParameter(ins.adb_ip_and_port());
+  CF_EXPECT_EQ(connect_cmd.Start().Wait(), 0);
 
-  adb_command.AddParameter("shell");
+  // Run the shell commands.
+  Command shell_cmd(SubtoolPath("adb"));
+  shell_cmd.AddParameter("-s").AddParameter(ins.adb_ip_and_port());
+  shell_cmd.AddParameter("shell");
   for (const auto& argument : command_args) {
-    adb_command.AddParameter(argument);
+    shell_cmd.AddParameter(argument);
   }
-  CF_EXPECT_EQ(adb_command.Start().Wait(), 0);
+  CF_EXPECT_EQ(shell_cmd.Start().Wait(), 0);
   return {};
 }
 
diff --git a/host/commands/run_cvd/server_loop_impl_record.cpp b/host/commands/run_cvd/server_loop_impl_webrtc.cpp
similarity index 72%
rename from host/commands/run_cvd/server_loop_impl_record.cpp
rename to host/commands/run_cvd/server_loop_impl_webrtc.cpp
index 3feb852f1..21d5d1d05 100644
--- a/host/commands/run_cvd/server_loop_impl_record.cpp
+++ b/host/commands/run_cvd/server_loop_impl_webrtc.cpp
@@ -28,7 +28,7 @@ namespace run_cvd_impl {
 Result<void> ServerLoopImpl::HandleStartScreenRecording() {
   LOG(INFO) << "Sending the request to start screen recording.";
 
-  CF_EXPECT(webrtc_recorder_.SendStartRecordingCommand(),
+  CF_EXPECT(webrtc_controller_.SendStartRecordingCommand(),
             "Failed to send start recording command.");
   return {};
 }
@@ -36,10 +36,19 @@ Result<void> ServerLoopImpl::HandleStartScreenRecording() {
 Result<void> ServerLoopImpl::HandleStopScreenRecording() {
   LOG(INFO) << "Sending the request to stop screen recording.";
 
-  CF_EXPECT(webrtc_recorder_.SendStopRecordingCommand(),
+  CF_EXPECT(webrtc_controller_.SendStopRecordingCommand(),
             "Failed to send stop recording command.");
   return {};
 }
 
+Result<void> ServerLoopImpl::HandleScreenshotDisplay(
+    const cuttlefish::run_cvd::ScreenshotDisplay& request) {
+  LOG(INFO) << "Sending the request to screenshot display to webrtc.";
+  CF_EXPECT(webrtc_controller_.SendScreenshotDisplayCommand(
+                request.display_number(), request.screenshot_path()),
+            "Failed to send start screenshot display command to webrtc.");
+  return {};
+}
+
 }  // namespace run_cvd_impl
 }  // namespace cuttlefish
diff --git a/host/commands/screen_recording_server/Android.bp b/host/commands/screen_recording_server/Android.bp
index 3ff8d626f..4cc1dd8cc 100644
--- a/host/commands/screen_recording_server/Android.bp
+++ b/host/commands/screen_recording_server/Android.bp
@@ -19,8 +19,8 @@ package {
 cc_library {
     name: "libscreen_recording_server",
     shared_libs: [
-        "libprotobuf-cpp-full",
         "libgrpc++_unsecure",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libgflags",
@@ -53,20 +53,20 @@ cc_binary_host {
     name: "screen_recording_server",
     shared_libs: [
         "libbase",
-        "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
         "libcuttlefish_fs",
         "libcuttlefish_run_cvd_proto",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "libprotobuf-cpp-full",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "libcuttlefish_command_util",
         "libcuttlefish_host_config",
         "libgflags",
-        "libscreen_recording_server",
         "libgrpc++_reflection",
+        "libscreen_recording_server",
     ],
     srcs: [
         "main.cpp",
@@ -85,8 +85,8 @@ cc_binary_host {
 filegroup {
     name: "ScreenRecordingServerProto",
     srcs: [
-        "screen_recording.proto",
         ":libprotobuf-internal-protos",
+        "screen_recording.proto",
     ],
 }
 
diff --git a/host/commands/secure_env/Android.bp b/host/commands/secure_env/Android.bp
index 92d65b5fe..41b3b2f23 100644
--- a/host/commands/secure_env/Android.bp
+++ b/host/commands/secure_env/Android.bp
@@ -23,17 +23,17 @@ cc_defaults {
         "libbase",
         "libcppbor",
         "libcppcose_rkp",
+        "libcrypto",
+        "libcutils",
         "libcuttlefish_security",
         "libcuttlefish_transport",
         "libgatekeeper",
         "libjsoncpp",
-        "libkeymaster_portable",
         "libkeymaster_messages",
-        "libsoft_attestation_cert",
+        "libkeymaster_portable",
         "liblog",
-        "libcrypto",
-        "libcutils",
         "libpuresoftkeymasterdevice_host",
+        "libsoft_attestation_cert",
         "tpm2-tss2-esys",
         "tpm2-tss2-mu",
         "tpm2-tss2-rc",
@@ -78,7 +78,6 @@ cc_defaults {
 common_libsecure_srcs = [
     "composite_serialization.cpp",
     "encrypted_serializable.cpp",
-    "storage/tpm_storage.cpp",
     "gatekeeper_responder.cpp",
     "hmac_serializable.cpp",
     "in_process_tpm.cpp",
@@ -86,6 +85,7 @@ common_libsecure_srcs = [
     "keymaster_responder.cpp",
     "primary_key_builder.cpp",
     "storage/storage.cpp",
+    "storage/tpm_storage.cpp",
     "tpm_attestation_record.cpp",
     "tpm_auth.cpp",
     "tpm_commands.cpp",
@@ -218,8 +218,8 @@ cc_library {
 cc_test_host {
     name: "libsecure_env_test",
     srcs: [
-        "test_tpm.cpp",
         "encrypted_serializable_test.cpp",
+        "test_tpm.cpp",
     ],
     static_libs: [
         "libsecure_env_not_windows",
diff --git a/host/commands/secure_env/tpm_key_blob_maker.cpp b/host/commands/secure_env/tpm_key_blob_maker.cpp
index 4a3031f72..12cf99eda 100644
--- a/host/commands/secure_env/tpm_key_blob_maker.cpp
+++ b/host/commands/secure_env/tpm_key_blob_maker.cpp
@@ -54,7 +54,8 @@ static keymaster_error_t SplitEnforcedProperties(
       case KM_TAG_OS_VERSION:
       case KM_TAG_ROOT_OF_TRUST:
       case KM_TAG_VENDOR_PATCHLEVEL:
-        LOG(DEBUG) << "Root of trust and origin tags may not be specified";
+      case KM_TAG_MODULE_HASH:
+        LOG(DEBUG) << "Tag " << entry.tag << " may not be specified";
         return KM_ERROR_INVALID_TAG;
 
       // These are hidden
diff --git a/host/commands/stop/Android.bp b/host/commands/stop/Android.bp
index 86ded2f44..acc026a0c 100644
--- a/host/commands/stop/Android.bp
+++ b/host/commands/stop/Android.bp
@@ -25,17 +25,17 @@ cc_binary {
     ],
     shared_libs: [
         "libbase",
+        "libcuttlefish_allocd_utils",
         "libcuttlefish_command_util",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libcuttlefish_allocd_utils",
         "libjsoncpp",
     ],
     static_libs: [
         "libcuttlefish_host_config",
-        "libgflags",
-        "libcuttlefish_msg_queue",
         "libcuttlefish_metrics",
+        "libcuttlefish_msg_queue",
+        "libgflags",
     ],
     target: {
         darwin: {
diff --git a/host/commands/tcp_connector/Android.bp b/host/commands/tcp_connector/Android.bp
index 8a3791eb1..8ea633fc7 100644
--- a/host/commands/tcp_connector/Android.bp
+++ b/host/commands/tcp_connector/Android.bp
@@ -13,7 +13,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -26,9 +25,9 @@ cc_binary {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "liblog",
-        "libcuttlefish_utils",
     ],
     static_libs: [
         "libcuttlefish_host_config",
@@ -39,5 +38,5 @@ cc_binary {
             enabled: true,
         },
     },
-    defaults: ["cuttlefish_buildhost_only"]
+    defaults: ["cuttlefish_buildhost_only"],
 }
diff --git a/host/commands/tcp_connector/main.cpp b/host/commands/tcp_connector/main.cpp
index 1a6296692..f685b6af8 100644
--- a/host/commands/tcp_connector/main.cpp
+++ b/host/commands/tcp_connector/main.cpp
@@ -29,7 +29,8 @@
 
 DEFINE_int32(fifo_in, -1, "A pipe for incoming communication");
 DEFINE_int32(fifo_out, -1, "A pipe for outgoing communication");
-DEFINE_int32(data_port, -1, "A port for data");
+DEFINE_int32(data_port, -1, "TCP port to connect to");
+DEFINE_string(data_path, "", "Unix server socket path to connect to");
 DEFINE_int32(buffer_size, -1, "The buffer size");
 DEFINE_int32(dump_packet_size, -1,
              "Dump incoming/outgoing packets up to given size");
@@ -51,6 +52,20 @@ SharedFD OpenSocket(int port) {
   }
 }
 
+SharedFD OpenSocket(const std::string& path) {
+  static std::mutex mutex;
+  std::unique_lock<std::mutex> lock(mutex);
+  for (;;) {
+    SharedFD fd = SharedFD::SocketLocalClient(path, false, SOCK_STREAM);
+    if (fd->IsOpen()) {
+      return fd;
+    }
+    LOG(ERROR) << "Failed to open socket: " << fd->StrError();
+    // Wait a little and try again
+    sleep(1);
+  }
+}
+
 void DumpPackets(const char* prefix, char* buf, int size) {
   if (FLAGS_dump_packet_size < 0 || size <= 0) {
     return;
@@ -91,7 +106,15 @@ int TcpConnectorMain(int argc, char** argv) {
     return 1;
   }
   close(FLAGS_fifo_out);
-  SharedFD sock = OpenSocket(FLAGS_data_port);
+  SharedFD sock;
+
+  if (FLAGS_data_port >= 0) {
+    sock = OpenSocket(FLAGS_data_port);
+  } else if (!FLAGS_data_path.empty()) {
+    sock = OpenSocket(FLAGS_data_path);
+  } else {
+    LOG(FATAL) << "Need `--data_port` or `--data_path`";
+  }
 
   auto guest_to_host = std::thread([&]() {
     while (true) {
diff --git a/host/commands/tombstone_receiver/Android.bp b/host/commands/tombstone_receiver/Android.bp
index 51830fc7d..a919a1480 100644
--- a/host/commands/tombstone_receiver/Android.bp
+++ b/host/commands/tombstone_receiver/Android.bp
@@ -25,9 +25,9 @@ cc_binary {
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "liblog",
-        "libcuttlefish_utils",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/commands/vhal_proxy_server/Android.bp b/host/commands/vhal_proxy_server/Android.bp
index f0499f361..6716dda27 100644
--- a/host/commands/vhal_proxy_server/Android.bp
+++ b/host/commands/vhal_proxy_server/Android.bp
@@ -16,12 +16,12 @@
 cc_binary_host {
     name: "vhal_proxy_server",
     defaults: [
-        "cuttlefish_host",
         "FakeVehicleHardwareDefaults",
         "VehicleHalDefaults",
+        "cuttlefish_host",
     ],
     srcs: [
-        "VhalProxyServer.cpp",
+        "vhal_proxy_server.cpp",
     ],
     required: [
         "Host_Prebuilt_VehicleHalDefaultProperties_JSON",
@@ -29,8 +29,8 @@ cc_binary_host {
         "Host_Prebuilt_VehicleHalVendorClusterTestProperties_JSON",
     ],
     static_libs: [
-        "android.hardware.automotive.vehicle@default-grpc-server-lib",
         "FakeVehicleHardware",
+        "android.hardware.automotive.vehicle@default-grpc-server-lib",
     ],
     shared_libs: [
         "libbase",
diff --git a/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp b/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp
index 8cb65a2de..ff0726c26 100644
--- a/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp
+++ b/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp
@@ -20,6 +20,9 @@
 #include <android-base/logging.h>
 #include <grpc++/grpc++.h>
 #include "common/libs/utils/flag_parser.h"
+#include "host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h"
+
+namespace {
 
 using ::android::hardware::automotive::vehicle::proto::DumpOptions;
 using ::android::hardware::automotive::vehicle::proto::DumpResult;
@@ -27,12 +30,14 @@ using ::android::hardware::automotive::vehicle::proto::VehicleServer;
 using ::cuttlefish::Flag;
 using ::cuttlefish::FlagAliasMode;
 using ::cuttlefish::GflagsCompatFlag;
+using ::cuttlefish::vhal_proxy_server::kDefaultEthPort;
+using ::cuttlefish::vhal_proxy_server::kEthAddr;
 using ::grpc::ClientContext;
 using ::grpc::CreateChannel;
 using ::grpc::InsecureChannelCredentials;
 using ::grpc::Status;
 
-static constexpr int DEFAULT_ETH_PORT = 9300;
+}  // namespace
 
 // A GRPC server for VHAL running on the guest Android.
 // argv[1]: Config directory path containing property config file (e.g.
@@ -44,7 +49,7 @@ int main(int argc, char* argv[]) {
     args.push_back(std::string(argv[i]));
   }
 
-  int32_t eth_port = DEFAULT_ETH_PORT;
+  int32_t eth_port = kDefaultEthPort;
   std::vector<Flag> flags{GflagsCompatFlag("port", eth_port)};
   CHECK(cuttlefish::ConsumeFlags(flags, args).ok()) << "Failed to parse flags";
 
@@ -54,7 +59,7 @@ int main(int argc, char* argv[]) {
     dump_options.add_options(arg);
   }
 
-  auto eth_addr = fmt::format("localhost:{}", eth_port);
+  auto eth_addr = fmt::format("{}:{}", kEthAddr, eth_port);
 
   auto channel = CreateChannel(eth_addr, InsecureChannelCredentials());
   auto stub = VehicleServer::NewStub(channel);
diff --git a/host/commands/vhal_proxy_server/VhalProxyServer.cpp b/host/commands/vhal_proxy_server/vhal_proxy_server.cpp
similarity index 98%
rename from host/commands/vhal_proxy_server/VhalProxyServer.cpp
rename to host/commands/vhal_proxy_server/vhal_proxy_server.cpp
index e9f46f0b3..76aa256a4 100644
--- a/host/commands/vhal_proxy_server/VhalProxyServer.cpp
+++ b/host/commands/vhal_proxy_server/vhal_proxy_server.cpp
@@ -25,6 +25,8 @@
 
 #include <memory>
 
+namespace {
+
 using ::aidl::android::hardware::automotive::vehicle::
     VehicleApPowerStateConfigFlag;
 using ::android::hardware::automotive::utils::VsockConnectionInfo;
@@ -33,6 +35,8 @@ using ::android::hardware::automotive::vehicle::fake::FakeVehicleHardware;
 using ::android::hardware::automotive::vehicle::virtualization::
     GrpcVehicleProxyServer;
 
+}  // namespace
+
 // A GRPC server for VHAL running on the guest Android.
 // argv[1]: Config directory path containing property config file (e.g.
 // DefaultProperties.json).
diff --git a/host/example_custom_actions/Android.bp b/host/example_custom_actions/Android.bp
index e159899cb..06ddc94bf 100644
--- a/host/example_custom_actions/Android.bp
+++ b/host/example_custom_actions/Android.bp
@@ -25,11 +25,11 @@ cc_binary_host {
     ],
     shared_libs: [
         "libbase",
-        "liblog",
-        "libutils",
-        "libjsoncpp",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libjsoncpp",
+        "liblog",
+        "libutils",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/frontend/adb_connector/Android.bp b/host/frontend/adb_connector/Android.bp
index d0927afd6..3363c439f 100644
--- a/host/frontend/adb_connector/Android.bp
+++ b/host/frontend/adb_connector/Android.bp
@@ -21,7 +21,7 @@ cc_binary {
     name: "adb_connector",
     srcs: [
         "adb_connection_maintainer.cpp",
-        "main.cpp"
+        "main.cpp",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/frontend/adb_connector/adb_connection_maintainer.cpp b/host/frontend/adb_connector/adb_connection_maintainer.cpp
index e8777713b..09a33b6c5 100644
--- a/host/frontend/adb_connector/adb_connection_maintainer.cpp
+++ b/host/frontend/adb_connector/adb_connection_maintainer.cpp
@@ -43,6 +43,10 @@ std::string MakeShellUptimeMessage() {
   return MakeMessage("shell,raw:cut -d. -f1 /proc/uptime");
 }
 
+std::string MakeShellTradeInModeGetStatusMessage() {
+  return MakeMessage("shell,raw:tradeinmode getstatus");
+}
+
 std::string MakeTransportMessage(const std::string& address) {
   return MakeMessage("host:transport:" + address);
 }
@@ -78,6 +82,7 @@ bool AdbSendMessage(const SharedFD& sock, const std::string& message) {
     LOG(WARNING) << "failed to send all bytes to adb daemon";
     return false;
   }
+
   return RecvAll(sock, kAdbStatusResponseLength) == kAdbOkayStatusResponse;
 }
 
@@ -146,6 +151,32 @@ int RecvUptimeResult(const SharedFD& sock) {
   return std::stoi(uptime_str);
 }
 
+// Returns a negative value if getstatus result couldn't be read for
+// any reason.
+int RecvGetStatusResult(const SharedFD& sock) {
+  std::vector<char> status_vec{};
+  std::vector<char> just_read(16);
+  do {
+    auto count = sock->Read(just_read.data(), just_read.size());
+    if (count < 0) {
+      LOG(WARNING) << "couldn't receive adb shell output";
+      return -1;
+    }
+    just_read.resize(count);
+    status_vec.insert(status_vec.end(), just_read.begin(), just_read.end());
+  } while (!just_read.empty());
+
+  if (status_vec.empty()) {
+    LOG(WARNING) << "empty adb shell result";
+    return -1;
+  }
+
+  auto status_str = std::string{status_vec.data(), status_vec.size()};
+  LOG(DEBUG) << "Status received " << status_str;
+
+  return 0;
+}
+
 // Check if the connection state is waiting for authorization. This function
 // returns true only when explicitly receiving the unauthorized error message,
 // while returns false for all the other error cases because we need to call
@@ -204,6 +235,7 @@ void WaitForAdbDisconnection(const std::string& address) {
   // sleeps stabilize the communication.
   LOG(DEBUG) << "Watching for disconnect on " << address;
   while (true) {
+    // First try uptime
     auto sock = SharedFD::SocketLocalClient(kAdbDaemonPort, SOCK_STREAM);
     if (!sock->IsOpen()) {
       LOG(ERROR) << "failed to open adb connection: " << sock->StrError();
@@ -214,17 +246,35 @@ void WaitForAdbDisconnection(const std::string& address) {
                    << RecvAdbResponse(sock);
       break;
     }
-    if (!AdbSendMessage(sock, MakeShellUptimeMessage())) {
-      LOG(WARNING) << "adb shell uptime message failed";
-      break;
-    }
 
-    auto uptime = RecvUptimeResult(sock);
-    if (uptime < 0) {
-      LOG(WARNING) << "couldn't read uptime result";
-      break;
+    if (AdbSendMessage(sock, MakeShellUptimeMessage())) {
+      auto uptime = RecvUptimeResult(sock);
+      if (uptime < 0) {
+        LOG(WARNING) << "couldn't read uptime result";
+        break;
+      }
+      LOG(VERBOSE) << "device on " << address << " uptime " << uptime;
+    } else {
+      // If uptime fails, maybe we are in trade-in mode
+      // Try adb shell tradeinmode getstatus
+      auto sock = SharedFD::SocketLocalClient(kAdbDaemonPort, SOCK_STREAM);
+      if (!AdbSendMessage(sock, MakeTransportMessage(address))) {
+        LOG(WARNING) << "transport message failed, response body: "
+                     << RecvAdbResponse(sock);
+        break;
+      }
+      if (!AdbSendMessage(sock, MakeShellTradeInModeGetStatusMessage())) {
+        LOG(WARNING) << "transport message failed, response body: "
+                     << RecvAdbResponse(sock);
+        break;
+      }
+      auto status = RecvGetStatusResult(sock);
+      if (status < 0) {
+        LOG(WARNING) << "transport message failed, response body: "
+                     << RecvAdbResponse(sock);
+        break;
+      }
     }
-    LOG(VERBOSE) << "device on " << address << " uptime " << uptime;
     sleep(kAdbCommandGapTime);
   }
   LOG(DEBUG) << "Sending adb disconnect";
diff --git a/host/frontend/operator_proxy/Android.bp b/host/frontend/operator_proxy/Android.bp
index bae80c0dc..d4db459a8 100644
--- a/host/frontend/operator_proxy/Android.bp
+++ b/host/frontend/operator_proxy/Android.bp
@@ -24,17 +24,15 @@ cc_binary_host {
     ],
     shared_libs: [
         "libbase",
-        "liblog",
-        "libjsoncpp",
         "libcuttlefish_fs",
+        "libjsoncpp",
+        "liblog",
     ],
     static_libs: [
-        "libgflags",
-        "libcuttlefish_utils",
         "libcuttlefish_host_config",
+        "libcuttlefish_utils",
+        "libgflags",
         "libprotobuf-cpp-full",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
-
-
diff --git a/host/frontend/webrtc/Android.bp b/host/frontend/webrtc/Android.bp
index 3dbc31518..72925ea62 100644
--- a/host/frontend/webrtc/Android.bp
+++ b/host/frontend/webrtc/Android.bp
@@ -17,39 +17,97 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+cc_library {
+    name: "libcuttlefish_webrtc_commands_proto",
+    host_supported: true,
+    proto: {
+        export_proto_headers: true,
+        canonical_path_from_root: false,
+        include_dirs: [
+            "external/googleapis",
+            "external/protobuf/src",
+        ],
+        type: "full",
+    },
+    srcs: [
+        "webrtc_commands.proto",
+    ],
+    target: {
+        darwin: {
+            enabled: true,
+        },
+    },
+    shared_libs: [
+        "libgoogleapis-status-proto",
+        "libprotobuf-cpp-full",
+    ],
+    defaults: [
+        "cuttlefish_host",
+        "cvd_cc_defaults",
+    ],
+}
+
+cc_library {
+    name: "libcuttlefish_webrtc_command_channel",
+    srcs: [
+        "webrtc_command_channel.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+        "libgoogleapis-status-proto",
+        "libprotobuf-cpp-full",
+    ],
+    static_libs: [
+        "libcuttlefish_fs",
+        "libcuttlefish_transport",
+        "libcuttlefish_utils",
+        "libcuttlefish_webrtc_commands_proto",
+    ],
+    target: {
+        darwin: {
+            enabled: true,
+        },
+    },
+    defaults: [
+        "cuttlefish_host",
+        "cvd_cc_defaults",
+    ],
+}
+
 cc_binary_host {
     name: "webRTC",
     srcs: [
         "adb_handler.cpp",
         "audio_handler.cpp",
         "bluetooth_handler.cpp",
-        "sensors_handler.cpp",
-        "sensors_simulator.cpp",
-        "location_handler.cpp",
-        "gpx_locations_handler.cpp",
-        "kml_locations_handler.cpp",
         "client_server.cpp",
         "connection_observer.cpp",
         "cvd_video_frame_buffer.cpp",
         "display_handler.cpp",
+        "gpx_locations_handler.cpp",
         "kernel_log_events_handler.cpp",
+        "kml_locations_handler.cpp",
+        "location_handler.cpp",
         "main.cpp",
+        "screenshot_handler.cpp",
+        "sensors_handler.cpp",
+        "sensors_simulator.cpp",
     ],
     cflags: [
         // libwebrtc headers need this
-        "-Wno-unused-parameter",
-        "-D_XOPEN_SOURCE",
-        "-DWEBRTC_POSIX",
         "-DWEBRTC_LINUX",
+        "-DWEBRTC_POSIX",
+        "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     header_libs: [
-        "webrtc_signaling_headers",
-        "libdrm_headers",
-        "libwebrtc_absl_headers",
         "libcuttlefish_confui_host_headers",
+        "libdrm_headers",
         "libeigen",
+        "webrtc_signaling_headers",
     ],
     static_libs: [
+        "libabsl_host",
         "libaom",
         "libcap",
         "libcn-cbor",
@@ -58,30 +116,34 @@ cc_binary_host {
         "libcuttlefish_confui_host",
         "libcuttlefish_host_config",
         "libcuttlefish_input_connector",
-        "libcuttlefish_security",
         "libcuttlefish_screen_connector",
+        "libcuttlefish_security",
+        "libcuttlefish_transport",
         "libcuttlefish_utils",
         "libcuttlefish_wayland_server",
-        "libft2.nodep",
-        "libteeui",
-        "libteeui_localization",
+        "libcuttlefish_webrtc_command_channel",
+        "libcuttlefish_webrtc_commands_proto",
+        "libcuttlefish_webrtc_common",
+        "libcuttlefish_webrtc_device",
+        "libcvd_gnss_grpc_proxy",
         "libdrm",
         "libevent",
         "libffi",
+        "libft2.nodep",
         "libgflags",
+        "liblocation",
         "libopus",
+        "libskia",
         "libsrtp2",
+        "libteeui",
+        "libteeui_localization",
         "libvpx",
         "libwayland_crosvm_gpu_display_extension_server_protocols",
         "libwayland_extension_server_protocols",
         "libwayland_server",
         "libwebrtc",
-        "libcuttlefish_webrtc_device",
-        "libcuttlefish_webrtc_common",
         "libwebsockets",
         "libyuv",
-        "libcvd_gnss_grpc_proxy",
-        "liblocation",
     ],
     shared_libs: [
         "android.hardware.keymaster@4.0",
@@ -89,17 +151,20 @@ cc_binary_host {
         "libcrypto",
         "libcuttlefish_fs",
         "libcuttlefish_kernel_log_monitor_utils",
-        "libjsoncpp",
         "libfruit",
+        "libgoogleapis-status-proto",
+        "libgrpc++_unsecure",
+        "libjsoncpp",
         "libopus",
+        "libprotobuf-cpp-full",
         "libssl",
         "libvpx",
-        "libyuv",
         "libwebm_mkvmuxer",
-        "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
         "libxml2",
+        "libyuv",
+    ],
+    defaults: [
+        "cuttlefish_buildhost_only",
+        "skia_deps",
     ],
-    defaults: ["cuttlefish_buildhost_only"],
 }
-
diff --git a/host/frontend/webrtc/connection_observer.cpp b/host/frontend/webrtc/connection_observer.cpp
index 08de3d29c..52e2194d5 100644
--- a/host/frontend/webrtc/connection_observer.cpp
+++ b/host/frontend/webrtc/connection_observer.cpp
@@ -85,6 +85,21 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
     SendLastFrameAsync(/*all displays*/ std::nullopt);
   }
 
+  Result<void> OnMouseMoveEvent(int x, int y) override {
+    CF_EXPECT(input_events_sink_->SendMouseMoveEvent(x, y));
+    return {};
+  }
+
+  Result<void> OnMouseButtonEvent(int button, bool down) override {
+    CF_EXPECT(input_events_sink_->SendMouseButtonEvent(button, down));
+    return {};
+  }
+
+  Result<void> OnMouseWheelEvent(int pixels) override {
+    CF_EXPECT(input_events_sink_->SendMouseWheelEvent(pixels));
+    return {};
+  }
+
   Result<void> OnTouchEvent(const std::string &device_label, int x, int y,
                             bool down) override {
     CF_EXPECT(input_events_sink_->SendTouchEvent(device_label, x, y, down));
@@ -111,7 +126,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
     return {};
   }
 
-  Result<void> OnWheelEvent(int pixels) {
+  Result<void> OnRotaryWheelEvent(int pixels) {
     CF_EXPECT(input_events_sink_->SendRotaryEvent(pixels));
     return {};
   }
diff --git a/host/frontend/webrtc/cvd_video_frame_buffer.h b/host/frontend/webrtc/cvd_video_frame_buffer.h
index 04f81aa6a..7247928a6 100644
--- a/host/frontend/webrtc/cvd_video_frame_buffer.h
+++ b/host/frontend/webrtc/cvd_video_frame_buffer.h
@@ -49,6 +49,10 @@ class CvdVideoFrameBuffer : public webrtc_streaming::VideoFrameBuffer {
   uint8_t *DataU() { return u_.data(); }
   uint8_t *DataV() { return v_.data(); }
 
+  std::size_t DataSizeY() const override { return y_.size(); }
+  std::size_t DataSizeU() const override { return u_.size(); }
+  std::size_t DataSizeV() const override { return v_.size(); }
+
  private:
   const int width_;
   const int height_;
diff --git a/host/frontend/webrtc/display_handler.cpp b/host/frontend/webrtc/display_handler.cpp
index 185e34a0b..4cbbd064f 100644
--- a/host/frontend/webrtc/display_handler.cpp
+++ b/host/frontend/webrtc/display_handler.cpp
@@ -27,8 +27,10 @@
 namespace cuttlefish {
 
 DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
+                               ScreenshotHandler& screenshot_handler,
                                ScreenConnector& screen_connector)
     : streamer_(streamer),
+      screenshot_handler_(screenshot_handler),
       screen_connector_(screen_connector),
       frame_repeater_([this]() { RepeatFramesPeriodically(); }) {
   screen_connector_.SetCallback(GetScreenConnectorCallback());
@@ -51,6 +53,7 @@ DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
               return;
             }
 
+            std::lock_guard<std::mutex> lock(send_mutex_);
             display_sinks_[display_number] = display;
           } else if constexpr (std::is_same_v<DisplayDestroyedEvent, T>) {
             LOG(VERBOSE) << "Display:" << e.display_number << " destroyed.";
@@ -58,8 +61,9 @@ DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
             const auto display_number = e.display_number;
             const auto display_id =
                 "display_" + std::to_string(e.display_number);
-            streamer_.RemoveDisplay(display_id);
+            std::lock_guard<std::mutex> lock(send_mutex_);
             display_sinks_.erase(display_number);
+            streamer_.RemoveDisplay(display_id);
           } else {
             static_assert("Unhandled display event.");
           }
@@ -181,6 +185,8 @@ void DisplayHandler::SendBuffers(
           .count();
 
   for (const auto& [display_number, buffer_info] : buffers) {
+    screenshot_handler_.OnFrame(display_number, buffer_info->buffer);
+
     auto it = display_sinks_.find(display_number);
     if (it != display_sinks_.end()) {
       it->second->OnFrame(buffer_info->buffer, time_stamp_since_epoch);
@@ -195,15 +201,32 @@ void DisplayHandler::RepeatFramesPeriodically() {
   // protects writing the BufferInfo timestamps.
   const std::chrono::milliseconds kRepeatingInterval(20);
   auto next_send = std::chrono::system_clock::now() + kRepeatingInterval;
-  std::unique_lock lock(repeater_state_mutex_);
-  while (repeater_state_ != RepeaterState::STOPPED) {
-    if (repeater_state_ == RepeaterState::REPEATING) {
-      repeater_state_condvar_.wait_until(lock, next_send);
-    } else {
-      repeater_state_condvar_.wait(lock);
-    }
-    if (repeater_state_ != RepeaterState::REPEATING) {
-      continue;
+  while (true) {
+    {
+      std::unique_lock lock(repeater_state_mutex_);
+      if (repeater_state_ == RepeaterState::STOPPED) {
+        break;
+      }
+      if (num_active_clients_ > 0) {
+        bool stopped =
+            repeater_state_condvar_.wait_until(lock, next_send, [this]() {
+              // Wait until time interval completes or asked to stop. Continue
+              // waiting even if the number of active clients drops to 0.
+              return repeater_state_ == RepeaterState::STOPPED;
+            });
+        if (stopped || num_active_clients_ == 0) {
+          continue;
+        }
+      } else {
+        repeater_state_condvar_.wait(lock, [this]() {
+          // Wait until asked to stop or have clients
+          return repeater_state_ == RepeaterState::STOPPED ||
+                 num_active_clients_ > 0;
+        });
+        // Need to break the loop if stopped or wait for the interval if have
+        // clients.
+        continue;
+      }
     }
 
     std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers;
@@ -231,20 +254,14 @@ void DisplayHandler::RepeatFramesPeriodically() {
 
 void DisplayHandler::AddDisplayClient() {
   std::lock_guard lock(repeater_state_mutex_);
-  ++num_active_clients_;
-  if (num_active_clients_ == 1) {
-    repeater_state_ = RepeaterState::REPEATING;
+  if (++num_active_clients_ == 1) {
     repeater_state_condvar_.notify_one();
-  }
+  };
 }
 
 void DisplayHandler::RemoveDisplayClient() {
   std::lock_guard lock(repeater_state_mutex_);
   --num_active_clients_;
-  if (num_active_clients_ == 0) {
-    repeater_state_ = RepeaterState::PAUSED;
-    repeater_state_condvar_.notify_one();
-  }
 }
 
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/display_handler.h b/host/frontend/webrtc/display_handler.h
index 334a0ae2c..c2739c82a 100644
--- a/host/frontend/webrtc/display_handler.h
+++ b/host/frontend/webrtc/display_handler.h
@@ -24,6 +24,7 @@
 
 #include "host/frontend/webrtc/cvd_video_frame_buffer.h"
 #include "host/frontend/webrtc/libdevice/video_sink.h"
+#include "host/frontend/webrtc/screenshot_handler.h"
 #include "host/libs/screen_connector/screen_connector.h"
 
 namespace cuttlefish {
@@ -60,6 +61,7 @@ class DisplayHandler {
   using WebRtcScProcessedFrame = cuttlefish::WebRtcScProcessedFrame;
 
   DisplayHandler(webrtc_streaming::Streamer& streamer,
+                 ScreenshotHandler& screenshot_handler,
                  ScreenConnector& screen_connector);
   ~DisplayHandler();
 
@@ -76,10 +78,9 @@ class DisplayHandler {
     std::chrono::system_clock::time_point last_sent_time_stamp;
     std::shared_ptr<webrtc_streaming::VideoFrameBuffer> buffer;
   };
-  enum class RepeaterState: int {
-    PAUSED = 0,
-    REPEATING = 1,
-    STOPPED = 2,
+  enum class RepeaterState {
+    RUNNING,
+    STOPPED,
   };
 
   GenerateProcessedFrameCallback GetScreenConnectorCallback();
@@ -89,12 +90,15 @@ class DisplayHandler {
   std::map<uint32_t, std::shared_ptr<webrtc_streaming::VideoSink>>
       display_sinks_;
   webrtc_streaming::Streamer& streamer_;
+  ScreenshotHandler& screenshot_handler_;
   ScreenConnector& screen_connector_;
   std::map<uint32_t, std::shared_ptr<BufferInfo>> display_last_buffers_;
   std::mutex last_buffers_mutex_;
   std::mutex send_mutex_;
   std::thread frame_repeater_;
-  RepeaterState repeater_state_ = RepeaterState::PAUSED;
+  // Protected by repeater_state_mutex
+  RepeaterState repeater_state_ = RepeaterState::RUNNING;
+  // Protected by repeater_state_mutex
   int num_active_clients_ = 0;
   std::mutex repeater_state_mutex_;
   std::condition_variable repeater_state_condvar_;
diff --git a/host/frontend/webrtc/html_client/Android.bp b/host/frontend/webrtc/html_client/Android.bp
index b389f2d96..3b2220d8b 100644
--- a/host/frontend/webrtc/html_client/Android.bp
+++ b/host/frontend/webrtc/html_client/Android.bp
@@ -93,3 +93,10 @@ prebuilt_usr_share_host {
     filename: "touch.js",
     sub_dir: "webrtc/assets/js",
 }
+
+prebuilt_usr_share_host {
+    name: "webrtc_mouse.js",
+    src: "js/mouse.js",
+    filename: "mouse.js",
+    sub_dir: "webrtc/assets/js",
+}
diff --git a/host/frontend/webrtc/html_client/client.html b/host/frontend/webrtc/html_client/client.html
index 7cd1d472e..13d36b095 100644
--- a/host/frontend/webrtc/html_client/client.html
+++ b/host/frontend/webrtc/html_client/client.html
@@ -41,6 +41,7 @@
             <button id='back_btn' title='Back' disabled='true' class='material-icons'>arrow_back</button>
             <button id='home_btn' title='Home' disabled='true' class='material-icons'>home</button>
             <button id='menu_btn' title='Menu' disabled='true' class='material-icons'>menu</button>
+            <button id='mouse_btn' title='Mouse' disabled='true' style="display:none" class='material-icons'>mouse</button>
             <button id='touchpad-modal-button' title='Touchpads' class='material-icons'>touch_app</button>
             <button id='rotate_left_btn' title='Rotate left' disabled='true' class='material-icons' data-adb="true">rotate_90_degrees_ccw</button>
             <button id='rotate_right_btn' title='Rotate right' disabled='true' class='material-icons' data-adb="true">rotate_90_degrees_cw</button>
@@ -261,6 +262,7 @@
       <script src="js/cf_webrtc.js" type="module"></script>
       <script src="js/controls.js"></script>
       <script src="js/touch.js"></script>
+      <script src="js/mouse.js"></script>
       <script src="js/app.js"></script>
       <template id="display-template">
         <div class="device-display">
diff --git a/host/frontend/webrtc/html_client/js/app.js b/host/frontend/webrtc/html_client/js/app.js
index 52c37872e..d3a0e3ff1 100644
--- a/host/frontend/webrtc/html_client/js/app.js
+++ b/host/frontend/webrtc/html_client/js/app.js
@@ -334,6 +334,11 @@ class DeviceControlApp {
       }
     }
 
+    if (this.#deviceConnection.description.mouse_enabled) {
+      // Enable mouse button conditionally.
+      enableMouseButton(this.#deviceConnection);
+    }
+
     // Set up displays
     this.#updateDeviceDisplays();
     this.#deviceConnection.onStreamChange(stream => this.#onStreamChange(stream));
@@ -351,8 +356,8 @@ class DeviceControlApp {
     }
 
     // Set up keyboard and wheel capture
-    this.#startKeyboardCapture();
-    this.#startWheelCapture();
+    this.#startKeyboardCapture(document.querySelector('#device-displays'));
+    this.#startWheelCapture(document.querySelector('#device-displays'));
 
     this.#updateDeviceHardwareDetails(
         this.#deviceConnection.description.hardware);
@@ -976,10 +981,9 @@ class DeviceControlApp {
     }));
   }
 
-  #startKeyboardCapture() {
-    const deviceArea = document.querySelector('#device-displays');
-    deviceArea.addEventListener('keydown', evt => this.#onKeyEvent(evt));
-    deviceArea.addEventListener('keyup', evt => this.#onKeyEvent(evt));
+  #startKeyboardCapture(elem) {
+    elem.addEventListener('keydown', evt => this.#onKeyEvent(evt));
+    elem.addEventListener('keyup', evt => this.#onKeyEvent(evt));
   }
 
   #onKeyEvent(e) {
@@ -991,9 +995,8 @@ class DeviceControlApp {
     this.#deviceConnection.sendKeyEvent(e.code, e.type);
   }
 
-  #startWheelCapture() {
-    const deviceArea = document.querySelector('#device-displays');
-    deviceArea.addEventListener('wheel', evt => this.#onWheelEvent(evt),
+  #startWheelCapture(elm) {
+    elm.addEventListener('wheel', evt => this.#onWheelEvent(evt),
                                 { passive: false });
   }
 
diff --git a/host/frontend/webrtc/html_client/js/cf_webrtc.js b/host/frontend/webrtc/html_client/js/cf_webrtc.js
index 1be5c846c..13ec42e3b 100644
--- a/host/frontend/webrtc/html_client/js/cf_webrtc.js
+++ b/host/frontend/webrtc/html_client/js/cf_webrtc.js
@@ -276,13 +276,19 @@ class DeviceConnection {
     this.#inputChannel.send(JSON.stringify(evt));
   }
 
-  sendMousePosition({x, y, down, display_label}) {
+  sendMouseMove({x, y}) {
     this.#sendJsonInput({
-      type: 'mouse',
-      down: down ? 1 : 0,
+      type: 'mouseMove',
       x,
       y,
-      display_label,
+    });
+  }
+
+  sendMouseButton({button, down}) {
+    this.#sendJsonInput({
+      type: 'mouseButton',
+      button: button,
+      down: down ? 1 : 0,
     });
   }
 
@@ -312,6 +318,14 @@ class DeviceConnection {
     });
   }
 
+  sendMouseWheelEvent(pixels) {
+    this.#sendJsonInput({
+      type: 'mouseWheel',
+      // convert double to int, forcing a base 10 conversion. pixels can be fractional.
+      pixels: parseInt(pixels, 10),
+    });
+  }
+
   disconnect() {
     this.#pc.close();
   }
diff --git a/host/frontend/webrtc/html_client/js/mouse.js b/host/frontend/webrtc/html_client/js/mouse.js
new file mode 100644
index 000000000..066482d54
--- /dev/null
+++ b/host/frontend/webrtc/html_client/js/mouse.js
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+'use strict';
+
+function trackMouseEvents(dc, mouseElement) {
+  function onMouseDown(evt) {
+    if (!document.pointerLockElement) {
+      mouseElement.requestPointerLock({});
+      return;
+    }
+    dc.sendMouseButton({button: evt.button, down: true});
+  }
+
+  function onMouseUp(evt) {
+    if (document.pointerLockElement) {
+      dc.sendMouseButton({button: evt.button, down: false});
+    }
+  }
+
+  function onMouseMove(evt) {
+    if (document.pointerLockElement) {
+      dc.sendMouseMove({x: evt.movementX, y: evt.movementY});
+      dc.sendMouseButton({button: evt.button, down: evt.buttons > 0});
+    }
+  }
+  mouseElement.addEventListener('mousedown', onMouseDown);
+  mouseElement.addEventListener('mouseup', onMouseUp);
+  mouseElement.addEventListener('mousemove', onMouseMove);
+}
+
+function enableMouseButton(dc) {
+  function onMouseKey(evt) {
+    if (evt.cancelable) {
+      // Some keyboard events cause unwanted side effects, like elements losing
+      // focus, if the default behavior is not prevented.
+      evt.preventDefault();
+    }
+    dc.sendKeyEvent(evt.code, evt.type);
+  }
+  function onMouseWheel(evt) {
+    evt.preventDefault();
+    // Vertical wheel pixel events only
+    if (evt.deltaMode == WheelEvent.DOM_DELTA_PIXEL && evt.deltaY != 0.0) {
+      dc.sendMouseWheelEvent(evt.deltaY);
+    }
+  }
+  let button = document.getElementById("mouse_btn");
+  button.style.display = "";
+  button.disabled = false;
+  trackMouseEvents(dc, button);
+  button.addEventListener('keydown', onMouseKey);
+  button.addEventListener('keyup', onMouseKey);
+  button.addEventListener('wheel', onMouseWheel,
+                                { passive: false });
+  return button;
+}
+
diff --git a/host/frontend/webrtc/libcommon/Android.bp b/host/frontend/webrtc/libcommon/Android.bp
index 44815d53a..0e2974a79 100644
--- a/host/frontend/webrtc/libcommon/Android.bp
+++ b/host/frontend/webrtc/libcommon/Android.bp
@@ -24,20 +24,18 @@ cc_library {
         "connection_controller.cpp",
         "peer_connection_utils.cpp",
         "port_range_socket_factory.cpp",
-        "vp8only_encoder_factory.cpp",
         "utils.cpp",
+        "vp8only_encoder_factory.cpp",
     ],
     cflags: [
         // libwebrtc headers need this
-        "-Wno-unused-parameter",
-        "-D_XOPEN_SOURCE",
-        "-DWEBRTC_POSIX",
         "-DWEBRTC_LINUX",
-    ],
-    header_libs: [
-        "libwebrtc_absl_headers",
+        "-DWEBRTC_POSIX",
+        "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     static_libs: [
+        "libabsl_host",
         "libevent",
         "libopus",
         "libsrtp2",
@@ -47,8 +45,8 @@ cc_library {
     ],
     shared_libs: [
         "libbase",
-        "libcuttlefish_utils",
         "libcrypto",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "libssl",
     ],
diff --git a/host/frontend/webrtc/libdevice/Android.bp b/host/frontend/webrtc/libdevice/Android.bp
index bb928496c..f6ee9b679 100644
--- a/host/frontend/webrtc/libdevice/Android.bp
+++ b/host/frontend/webrtc/libdevice/Android.bp
@@ -27,43 +27,43 @@ cc_library {
         "keyboard.cpp",
         "lights_observer.cpp",
         "local_recorder.cpp",
+        "recording_manager.cpp",
+        "server_connection.cpp",
         "streamer.cpp",
         "video_track_source_impl.cpp",
-        "server_connection.cpp",
-        "recording_manager.cpp",
     ],
     cflags: [
         // libwebrtc headers need this
-        "-Wno-unused-parameter",
-        "-D_XOPEN_SOURCE",
-        "-DWEBRTC_POSIX",
         "-DWEBRTC_LINUX",
+        "-DWEBRTC_POSIX",
+        "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     header_libs: [
         "webrtc_signaling_headers",
-        "libwebrtc_absl_headers",
     ],
     static_libs: [
-        "libsrtp2",
+        "libabsl_host",
+        "libcap",
         "libcuttlefish_host_config",
         "libcuttlefish_screen_connector",
+        "libcuttlefish_utils",
         "libcuttlefish_wayland_server",
         "libcuttlefish_webrtc_common",
-        "libgflags",
+        "libcvd_gnss_grpc_proxy",
         "libdrm",
         "libevent",
         "libffi",
+        "libgflags",
+        "liblocation",
+        "libopus",
+        "libsrtp2",
+        "libvpx",
         "libwayland_crosvm_gpu_display_extension_server_protocols",
         "libwayland_extension_server_protocols",
         "libwayland_server",
-        "libwebsockets",
-        "libcap",
-        "libcuttlefish_utils",
         "libwebrtc",
-        "libcvd_gnss_grpc_proxy",
-        "liblocation",
-        "libopus",
-        "libvpx",
+        "libwebsockets",
         "libyuv",
     ],
     shared_libs: [
@@ -72,13 +72,12 @@ cc_library {
         "libcrypto",
         "libcuttlefish_fs",
         "libfruit",
+        "libgrpc++_unsecure",
         "libjsoncpp",
+        "libprotobuf-cpp-full",
         "libssl",
         "libwebm_mkvmuxer",
-        "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
         "libxml2",
     ],
     defaults: ["cuttlefish_buildhost_only"],
 }
-
diff --git a/host/frontend/webrtc/libdevice/connection_observer.h b/host/frontend/webrtc/libdevice/connection_observer.h
index 7dfe072bb..d06fd4b70 100644
--- a/host/frontend/webrtc/libdevice/connection_observer.h
+++ b/host/frontend/webrtc/libdevice/connection_observer.h
@@ -44,6 +44,9 @@ class ConnectionObserver {
 
   virtual void OnConnected() = 0;
 
+  virtual Result<void> OnMouseMoveEvent(int x, int y) = 0;
+  virtual Result<void> OnMouseButtonEvent(int button, bool down) = 0;
+  virtual Result<void> OnMouseWheelEvent(int pixels) = 0;
   virtual Result<void> OnTouchEvent(const std::string& device_label, int x,
                                     int y, bool down) = 0;
   virtual Result<void> OnMultiTouchEvent(const std::string& label,
@@ -53,7 +56,7 @@ class ConnectionObserver {
 
   virtual Result<void> OnKeyboardEvent(uint16_t keycode, bool down) = 0;
 
-  virtual Result<void> OnWheelEvent(int pixels) = 0;
+  virtual Result<void> OnRotaryWheelEvent(int pixels) = 0;
 
   virtual void OnAdbChannelOpen(
       std::function<bool(const uint8_t*, size_t)> adb_message_sender) = 0;
diff --git a/host/frontend/webrtc/libdevice/data_channels.cpp b/host/frontend/webrtc/libdevice/data_channels.cpp
index 9c459a542..85316ab70 100644
--- a/host/frontend/webrtc/libdevice/data_channels.cpp
+++ b/host/frontend/webrtc/libdevice/data_channels.cpp
@@ -97,19 +97,27 @@ class InputChannelHandler : public DataChannelHandler {
                evt.toStyledString());
     auto event_type = evt["type"].asString();
 
-    if (event_type == "mouse") {
-      CF_EXPECT(ValidateJsonObject(
-          evt, "mouse",
-          {{"down", Json::ValueType::intValue},
-           {"x", Json::ValueType::intValue},
-           {"y", Json::ValueType::intValue},
-           {"display_label", Json::ValueType::stringValue}}));
-      auto label = evt["device_label"].asString();
-      int32_t down = evt["down"].asInt();
+    if (event_type == "mouseMove") {
+      CF_EXPECT(ValidateJsonObject(evt, "mouseMove",
+                                   {{"x", Json::ValueType::intValue},
+                                    {"y", Json::ValueType::intValue}}));
       int32_t x = evt["x"].asInt();
       int32_t y = evt["y"].asInt();
 
-      CF_EXPECT(observer()->OnTouchEvent(label, x, y, down));
+      CF_EXPECT(observer()->OnMouseMoveEvent(x, y));
+    } else if (event_type == "mouseButton") {
+      CF_EXPECT(ValidateJsonObject(evt, "mouseButton",
+                                   {{"button", Json::ValueType::intValue},
+                                    {"down", Json::ValueType::intValue}}));
+      int32_t button = evt["button"].asInt();
+      int32_t down = evt["down"].asInt();
+
+      CF_EXPECT(observer()->OnMouseButtonEvent(button, down));
+    } else if (event_type == "mouseWheel") {
+      CF_EXPECT(ValidateJsonObject(evt, "mouseWheel",
+                                   {{"pixels", Json::ValueType::intValue}}));
+      auto pixels = evt["pixels"].asInt();
+      CF_EXPECT(observer()->OnMouseWheelEvent(pixels));
     } else if (event_type == "multi-touch") {
       CF_EXPECT(
           ValidateJsonObject(evt, "multi-touch",
@@ -141,7 +149,7 @@ class InputChannelHandler : public DataChannelHandler {
       CF_EXPECT(ValidateJsonObject(evt, "wheel",
                                    {{"pixels", Json::ValueType::intValue}}));
       auto pixels = evt["pixels"].asInt();
-      CF_EXPECT(observer()->OnWheelEvent(pixels));
+      CF_EXPECT(observer()->OnRotaryWheelEvent(pixels));
     } else {
       return CF_ERRF("Unrecognized event type: '{}'", event_type);
     }
diff --git a/host/frontend/webrtc/libdevice/streamer.cpp b/host/frontend/webrtc/libdevice/streamer.cpp
index b07a70840..14994a7b2 100644
--- a/host/frontend/webrtc/libdevice/streamer.cpp
+++ b/host/frontend/webrtc/libdevice/streamer.cpp
@@ -71,6 +71,7 @@ constexpr auto kControlPanelButtonDeviceStates = "device_states";
 constexpr auto kControlPanelButtonLidSwitchOpen = "lid_switch_open";
 constexpr auto kControlPanelButtonHingeAngleValue = "hinge_angle_value";
 constexpr auto kCustomControlPanelButtonsField = "custom_control_panel_buttons";
+constexpr auto kMouseEnabled = "mouse_enabled";
 constexpr auto kGroupIdField = "group_id";
 
 constexpr int kRegistrationRetries = 3;
@@ -482,6 +483,9 @@ void Streamer::Impl::OnOpen() {
       }
       custom_control_panel_buttons.append(button_entry);
     }
+    // Add mouse button conditionally.
+    device_info[kMouseEnabled] = config_.enable_mouse;
+
     device_info[kCustomControlPanelButtonsField] = custom_control_panel_buttons;
     register_obj[cuttlefish::webrtc_signaling::kDeviceInfoField] = device_info;
     server_connection_->Send(register_obj);
diff --git a/host/frontend/webrtc/libdevice/streamer.h b/host/frontend/webrtc/libdevice/streamer.h
index d153f2943..8dc9a8899 100644
--- a/host/frontend/webrtc/libdevice/streamer.h
+++ b/host/frontend/webrtc/libdevice/streamer.h
@@ -61,6 +61,8 @@ struct StreamerConfig {
   int adb_port;
   // Path of ControlEnvProxyServer for serving Rest API in WebUI.
   std::string control_env_proxy_server_path;
+  // Whether mouse is enabled.
+  bool enable_mouse;
 };
 
 class OperatorObserver {
diff --git a/host/frontend/webrtc/libdevice/video_frame_buffer.h b/host/frontend/webrtc/libdevice/video_frame_buffer.h
index b8240585a..a40eb75b0 100644
--- a/host/frontend/webrtc/libdevice/video_frame_buffer.h
+++ b/host/frontend/webrtc/libdevice/video_frame_buffer.h
@@ -33,6 +33,9 @@ class VideoFrameBuffer {
   virtual const uint8_t* DataY() const = 0;
   virtual const uint8_t* DataU() const = 0;
   virtual const uint8_t* DataV() const = 0;
+  virtual std::size_t DataSizeY() const = 0;
+  virtual std::size_t DataSizeU() const = 0;
+  virtual std::size_t DataSizeV() const = 0;
 };
 
 }  // namespace webrtc_streaming
diff --git a/host/frontend/webrtc/main.cpp b/host/frontend/webrtc/main.cpp
index b60333455..002ac16b7 100644
--- a/host/frontend/webrtc/main.cpp
+++ b/host/frontend/webrtc/main.cpp
@@ -25,6 +25,7 @@
 
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/files.h"
+#include "google/rpc/code.pb.h"
 #include "host/frontend/webrtc/audio_handler.h"
 #include "host/frontend/webrtc/client_server.h"
 #include "host/frontend/webrtc/connection_observer.h"
@@ -35,19 +36,23 @@
 #include "host/frontend/webrtc/libdevice/local_recorder.h"
 #include "host/frontend/webrtc/libdevice/streamer.h"
 #include "host/frontend/webrtc/libdevice/video_sink.h"
+#include "host/frontend/webrtc/screenshot_handler.h"
+#include "host/frontend/webrtc/webrtc_command_channel.h"
 #include "host/libs/audio_connector/server.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/logging.h"
 #include "host/libs/config/openwrt_args.h"
 #include "host/libs/confui/host_mode_ctrl.h"
 #include "host/libs/confui/host_server.h"
-#include "host/libs/input_connector/socket_input_connector.h"
+#include "host/libs/input_connector/input_connector.h"
 #include "host/libs/screen_connector/screen_connector.h"
+#include "webrtc_commands.pb.h"
 
 DEFINE_bool(multitouch, true,
             "Whether to send multi-touch or single-touch events");
 DEFINE_string(touch_fds, "",
               "A list of fds to listen on for touch connections.");
+DEFINE_int32(mouse_fd, -1, "An fd to listen on for mouse connections.");
 DEFINE_int32(rotary_fd, -1, "An fd to listen on for rotary connections.");
 DEFINE_int32(keyboard_fd, -1, "An fd to listen on for keyboard connections.");
 DEFINE_int32(switches_fd, -1, "An fd to listen on for switch connections.");
@@ -71,22 +76,19 @@ DEFINE_int32(camera_streamer_fd, -1, "An fd to send client camera frames");
 DEFINE_string(client_dir, "webrtc", "Location of the client files");
 DEFINE_string(group_id, "", "The group id of device");
 
-using cuttlefish::AudioHandler;
-using cuttlefish::CfConnectionObserverFactory;
-using cuttlefish::DisplayHandler;
-using cuttlefish::KernelLogEventsHandler;
-using cuttlefish::webrtc_streaming::RecordingManager;
-using cuttlefish::webrtc_streaming::ServerConfig;
-using cuttlefish::webrtc_streaming::Streamer;
-using cuttlefish::webrtc_streaming::StreamerConfig;
-using cuttlefish::webrtc_streaming::VideoSink;
+namespace cuttlefish {
+
+using webrtc_streaming::RecordingManager;
+using webrtc_streaming::ServerConfig;
+using webrtc_streaming::Streamer;
+using webrtc_streaming::StreamerConfig;
+using webrtc_streaming::VideoSink;
 
 constexpr auto kOpewnrtWanIpAddressName = "wan_ipaddr";
 constexpr auto kTouchscreenPrefix = "display_";
 constexpr auto kTouchpadPrefix = "touch_";
 
-class CfOperatorObserver
-    : public cuttlefish::webrtc_streaming::OperatorObserver {
+class CfOperatorObserver : public webrtc_streaming::OperatorObserver {
  public:
   virtual ~CfOperatorObserver() = default;
   virtual void OnRegistered() override {
@@ -99,51 +101,94 @@ class CfOperatorObserver
     LOG(ERROR) << "Error encountered in connection with Operator";
   }
 };
-std::unique_ptr<cuttlefish::AudioServer> CreateAudioServer() {
-  cuttlefish::SharedFD audio_server_fd =
-      cuttlefish::SharedFD::Dup(FLAGS_audio_server_fd);
+std::unique_ptr<AudioServer> CreateAudioServer() {
+  SharedFD audio_server_fd = SharedFD::Dup(FLAGS_audio_server_fd);
   close(FLAGS_audio_server_fd);
-  return std::make_unique<cuttlefish::AudioServer>(audio_server_fd);
+  return std::make_unique<AudioServer>(audio_server_fd);
 }
 
-fruit::Component<cuttlefish::CustomActionConfigProvider> WebRtcComponent() {
+fruit::Component<CustomActionConfigProvider> WebRtcComponent() {
   return fruit::createComponent()
-      .install(cuttlefish::ConfigFlagPlaceholder)
-      .install(cuttlefish::CustomActionsComponent);
+      .install(ConfigFlagPlaceholder)
+      .install(CustomActionsComponent);
 };
 
-fruit::Component<
-    cuttlefish::ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
-    cuttlefish::confui::HostServer, cuttlefish::confui::HostVirtualInput>
-CreateConfirmationUIComponent(
-    int* frames_fd, bool* frames_are_rgba,
-    cuttlefish::confui::PipeConnectionPair* pipe_io_pair,
-    cuttlefish::InputConnector* input_connector) {
-  using cuttlefish::ScreenConnectorFrameRenderer;
-  using ScreenConnector = cuttlefish::DisplayHandler::ScreenConnector;
+fruit::Component<ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
+                 confui::HostServer, confui::HostVirtualInput>
+CreateConfirmationUIComponent(int* frames_fd, bool* frames_are_rgba,
+                              confui::PipeConnectionPair* pipe_io_pair,
+                              InputConnector* input_connector) {
+  using ScreenConnector = DisplayHandler::ScreenConnector;
   return fruit::createComponent()
-      .bindInstance<
-          fruit::Annotated<cuttlefish::WaylandScreenConnector::FramesFd, int>>(
+      .bindInstance<fruit::Annotated<WaylandScreenConnector::FramesFd, int>>(
           *frames_fd)
-      .bindInstance<fruit::Annotated<
-          cuttlefish::WaylandScreenConnector::FramesAreRgba, bool>>(
+      .bindInstance<
+          fruit::Annotated<WaylandScreenConnector::FramesAreRgba, bool>>(
           *frames_are_rgba)
       .bindInstance(*pipe_io_pair)
       .bind<ScreenConnectorFrameRenderer, ScreenConnector>()
       .bindInstance(*input_connector);
 }
 
-int main(int argc, char** argv) {
-  cuttlefish::DefaultSubprocessLogging(argv);
-  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
+Result<void> ControlLoop(SharedFD control_socket,
+                         DisplayHandler& display_handler,
+                         RecordingManager& recording_manager,
+                         ScreenshotHandler& screenshot_handler) {
+  WebrtcServerCommandChannel channel(control_socket);
+  while (true) {
+    webrtc::WebrtcCommandRequest request = CF_EXPECT(channel.ReceiveRequest());
+
+    Result<void> command_result = {};
+    if (request.has_start_recording_request()) {
+      LOG(INFO) << "Received command to start recording in main.cpp.";
+      recording_manager.Start();
+    } else if (request.has_stop_recording_request()) {
+      LOG(INFO) << "Received command to stop recording in main.cpp.";
+      recording_manager.Stop();
+    } else if (request.has_screenshot_display_request()) {
+      const auto& screenshot_request = request.screenshot_display_request();
+      LOG(INFO) << "Received command to screenshot display "
+                << screenshot_request.display_number() << "in main.cpp.";
+
+      display_handler.AddDisplayClient();
+
+      command_result =
+          screenshot_handler.Screenshot(screenshot_request.display_number(),
+                                        screenshot_request.screenshot_path());
+
+      display_handler.RemoveDisplayClient();
+
+      if (!command_result.ok()) {
+        LOG(ERROR) << "Failed to screenshot display "
+                   << screenshot_request.display_number() << " to "
+                   << screenshot_request.screenshot_path() << ":"
+                   << command_result.error().Message();
+      }
+    } else {
+      LOG(FATAL) << "Unhandled request: " << request.DebugString();
+    }
+
+    webrtc::WebrtcCommandResponse response;
+    auto* response_status = response.mutable_status();
+    if (command_result.ok()) {
+      response_status->set_code(google::rpc::Code::OK);
+    } else {
+      response_status->set_code(google::rpc::Code::INTERNAL);
+      response_status->set_message(command_result.error().Message());
+    }
 
-  auto control_socket = cuttlefish::SharedFD::Dup(FLAGS_command_fd);
+    CF_EXPECT(channel.SendResponse(response));
+  }
+}
+
+int CuttlefishMain() {
+  auto control_socket = SharedFD::Dup(FLAGS_command_fd);
   close(FLAGS_command_fd);
 
-  auto cvd_config = cuttlefish::CuttlefishConfig::Get();
+  auto cvd_config = CuttlefishConfig::Get();
   auto instance = cvd_config->ForDefaultInstance();
 
-  cuttlefish::InputSocketsConnectorBuilder inputs_builder(
+  cuttlefish::InputConnectorBuilder inputs_builder(
       FLAGS_write_virtio_input ? cuttlefish::InputEventType::Virtio
                                : cuttlefish::InputEventType::Evdev);
 
@@ -161,7 +206,7 @@ int main(int argc, char** argv) {
         i < display_count ? kTouchscreenPrefix : kTouchpadPrefix;
     auto device_idx = i < display_count ? i : i - display_count;
     auto device_label = fmt::format("{}{}", label_prefix, device_idx);
-    auto touch_shared_fd = cuttlefish::SharedFD::Dup(touch_fd);
+    auto touch_shared_fd = SharedFD::Dup(touch_fd);
     if (FLAGS_multitouch) {
       inputs_builder.WithMultitouchDevice(device_label, touch_shared_fd);
     } else {
@@ -170,35 +215,37 @@ int main(int argc, char** argv) {
     close(touch_fd);
   }
   if (FLAGS_rotary_fd >= 0) {
-    inputs_builder.WithRotary(cuttlefish::SharedFD::Dup(FLAGS_rotary_fd));
+    inputs_builder.WithRotary(SharedFD::Dup(FLAGS_rotary_fd));
     close(FLAGS_rotary_fd);
   }
+  if (FLAGS_mouse_fd >= 0) {
+    inputs_builder.WithMouse(SharedFD::Dup(FLAGS_mouse_fd));
+    close(FLAGS_mouse_fd);
+  }
   if (FLAGS_keyboard_fd >= 0) {
-    inputs_builder.WithKeyboard(cuttlefish::SharedFD::Dup(FLAGS_keyboard_fd));
+    inputs_builder.WithKeyboard(SharedFD::Dup(FLAGS_keyboard_fd));
     close(FLAGS_keyboard_fd);
   }
   if (FLAGS_switches_fd >= 0) {
-    inputs_builder.WithSwitches(cuttlefish::SharedFD::Dup(FLAGS_switches_fd));
+    inputs_builder.WithSwitches(SharedFD::Dup(FLAGS_switches_fd));
     close(FLAGS_switches_fd);
   }
 
   auto input_connector = std::move(inputs_builder).Build();
 
-  auto kernel_log_events_client =
-      cuttlefish::SharedFD::Dup(FLAGS_kernel_log_events_fd);
+  auto kernel_log_events_client = SharedFD::Dup(FLAGS_kernel_log_events_fd);
   close(FLAGS_kernel_log_events_fd);
 
-  cuttlefish::confui::PipeConnectionPair conf_ui_comm_fd_pair{
-      .from_guest_ = cuttlefish::SharedFD::Dup(FLAGS_confui_out_fd),
-      .to_guest_ = cuttlefish::SharedFD::Dup(FLAGS_confui_in_fd)};
+  confui::PipeConnectionPair conf_ui_comm_fd_pair{
+      .from_guest_ = SharedFD::Dup(FLAGS_confui_out_fd),
+      .to_guest_ = SharedFD::Dup(FLAGS_confui_in_fd)};
   close(FLAGS_confui_in_fd);
   close(FLAGS_confui_out_fd);
 
   int frames_fd = FLAGS_frame_server_fd;
   bool frames_are_rgba = true;
-  fruit::Injector<
-      cuttlefish::ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
-      cuttlefish::confui::HostServer, cuttlefish::confui::HostVirtualInput>
+  fruit::Injector<ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
+                  confui::HostServer, confui::HostVirtualInput>
       conf_ui_components_injector(CreateConfirmationUIComponent,
                                   std::addressof(frames_fd),
                                   std::addressof(frames_are_rgba),
@@ -206,12 +253,12 @@ int main(int argc, char** argv) {
   auto& screen_connector =
       conf_ui_components_injector.get<DisplayHandler::ScreenConnector&>();
 
-  auto client_server = cuttlefish::ClientFilesServer::New(FLAGS_client_dir);
+  auto client_server = ClientFilesServer::New(FLAGS_client_dir);
   CHECK(client_server) << "Failed to initialize client files server";
   auto& host_confui_server =
-      conf_ui_components_injector.get<cuttlefish::confui::HostServer&>();
+      conf_ui_components_injector.get<confui::HostServer&>();
   auto& confui_virtual_input =
-      conf_ui_components_injector.get<cuttlefish::confui::HostVirtualInput&>();
+      conf_ui_components_injector.get<confui::HostVirtualInput&>();
 
   StreamerConfig streamer_config;
 
@@ -239,15 +286,15 @@ int main(int argc, char** argv) {
     streamer_config.operator_server.security =
         ServerConfig::Security::kInsecure;
   }
+  streamer_config.enable_mouse = instance.enable_mouse();
 
   KernelLogEventsHandler kernel_logs_event_handler(kernel_log_events_client);
 
-  std::shared_ptr<cuttlefish::webrtc_streaming::LightsObserver> lights_observer;
+  std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer;
   if (instance.lights_server_port()) {
-    lights_observer =
-        std::make_shared<cuttlefish::webrtc_streaming::LightsObserver>(
-            instance.lights_server_port(), instance.vsock_guest_cid(),
-            instance.vhost_user_vsock());
+    lights_observer = std::make_shared<webrtc_streaming::LightsObserver>(
+        instance.lights_server_port(), instance.vsock_guest_cid(),
+        instance.vhost_user_vsock());
     lights_observer->Start();
   }
 
@@ -256,12 +303,14 @@ int main(int argc, char** argv) {
 
   RecordingManager recording_manager;
 
+  ScreenshotHandler screenshot_handler;
+
   auto streamer =
       Streamer::Create(streamer_config, recording_manager, observer_factory);
   CHECK(streamer) << "Could not create streamer";
 
-  auto display_handler =
-      std::make_shared<DisplayHandler>(*streamer, screen_connector);
+  auto display_handler = std::make_shared<DisplayHandler>(
+      *streamer, screenshot_handler, screen_connector);
 
   if (instance.camera_server_port()) {
     auto camera_controller = streamer->AddCamera(instance.camera_server_port(),
@@ -284,15 +333,15 @@ int main(int argc, char** argv) {
   streamer->SetHardwareSpec("RAM", std::to_string(instance.memory_mb()) + " mb");
 
   std::string user_friendly_gpu_mode;
-  if (instance.gpu_mode() == cuttlefish::kGpuModeGuestSwiftshader) {
+  if (instance.gpu_mode() == kGpuModeGuestSwiftshader) {
     user_friendly_gpu_mode = "SwiftShader (Guest CPU Rendering)";
-  } else if (instance.gpu_mode() == cuttlefish::kGpuModeDrmVirgl) {
+  } else if (instance.gpu_mode() == kGpuModeDrmVirgl) {
     user_friendly_gpu_mode =
         "VirglRenderer (Accelerated Rendering using Host OpenGL)";
-  } else if (instance.gpu_mode() == cuttlefish::kGpuModeGfxstream) {
+  } else if (instance.gpu_mode() == kGpuModeGfxstream) {
     user_friendly_gpu_mode =
         "Gfxstream (Accelerated Rendering using Host OpenGL and Vulkan)";
-  } else if (instance.gpu_mode() == cuttlefish::kGpuModeGfxstreamGuestAngle) {
+  } else if (instance.gpu_mode() == kGpuModeGfxstreamGuestAngle) {
     user_friendly_gpu_mode =
         "Gfxstream (Accelerated Rendering using Host Vulkan)";
   } else {
@@ -325,16 +374,13 @@ int main(int argc, char** argv) {
     action_server_fds[server] = fd;
   }
 
-  fruit::Injector<cuttlefish::CustomActionConfigProvider> injector(
-      WebRtcComponent);
-  for (auto& fragment :
-       injector.getMultibindings<cuttlefish::ConfigFragment>()) {
+  fruit::Injector<CustomActionConfigProvider> injector(WebRtcComponent);
+  for (auto& fragment : injector.getMultibindings<ConfigFragment>()) {
     CHECK(cvd_config->LoadFragment(*fragment))
         << "Failed to load config fragment";
   }
 
-  const auto& actions_provider =
-      injector.get<cuttlefish::CustomActionConfigProvider&>();
+  const auto& actions_provider = injector.get<CustomActionConfigProvider&>();
 
   for (const auto& custom_action :
        actions_provider.CustomShellActions(instance.id())) {
@@ -355,7 +401,7 @@ int main(int argc, char** argv) {
     LOG(INFO) << "Connecting to custom action server " << custom_action.server;
 
     int fd = action_server_fds[custom_action.server];
-    cuttlefish::SharedFD custom_action_server = cuttlefish::SharedFD::Dup(fd);
+    SharedFD custom_action_server = SharedFD::Dup(fd);
     close(fd);
 
     if (custom_action_server->IsOpen()) {
@@ -381,27 +427,17 @@ int main(int argc, char** argv) {
         custom_action.device_states);
   }
 
-  std::shared_ptr<cuttlefish::webrtc_streaming::OperatorObserver> operator_observer(
+  std::shared_ptr<webrtc_streaming::OperatorObserver> operator_observer(
       new CfOperatorObserver());
   streamer->Register(operator_observer);
 
-  std::thread control_thread([control_socket, &recording_manager]() {
-    std::string message = "_";
-    int read_ret;
-    while ((read_ret = cuttlefish::ReadExact(control_socket, &message)) > 0) {
-      LOG(VERBOSE) << "received control message: " << message;
-      if (message[0] == 'T') {
-        LOG(INFO) << "Received command to start recording in main.cpp.";
-        recording_manager.Start();
-      } else if (message[0] == 'C') {
-        LOG(INFO) << "Received command to stop recording in main.cpp.";
-        recording_manager.Stop();
-      }
-      // Send feedback an indication of command received.
-      CHECK(cuttlefish::WriteAll(control_socket, "Y") == 1) << "Failed to send response: "
-                                                            << control_socket->StrError();
+  std::thread control_thread([&]() {
+    auto result = ControlLoop(control_socket, *display_handler,
+                              recording_manager, screenshot_handler);
+    if (!result.ok()) {
+      LOG(ERROR) << "Webrtc control loop error: " << result.error().Message();
     }
-    LOG(DEBUG) << "control socket closed";
+    LOG(DEBUG) << "Webrtc control thread exiting.";
   });
 
   if (audio_handler) {
@@ -419,3 +455,11 @@ int main(int argc, char** argv) {
 
   return 0;
 }
+
+}  // namespace cuttlefish
+
+int main(int argc, char** argv) {
+  cuttlefish::DefaultSubprocessLogging(argv);
+  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
+  return cuttlefish::CuttlefishMain();
+}
\ No newline at end of file
diff --git a/host/frontend/webrtc/screenshot_handler.cpp b/host/frontend/webrtc/screenshot_handler.cpp
new file mode 100644
index 000000000..0405266ab
--- /dev/null
+++ b/host/frontend/webrtc/screenshot_handler.cpp
@@ -0,0 +1,133 @@
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
+#include "host/frontend/webrtc/screenshot_handler.h"
+
+#include <filesystem>
+#include <fstream>
+
+#include <SkData.h>
+#include <SkImage.h>
+#include <SkJpegEncoder.h>
+#include <SkPngEncoder.h>
+#include <SkRefCnt.h>
+#include <SkStream.h>
+#include <SkWebpEncoder.h>
+#include <libyuv.h>
+
+namespace cuttlefish {
+namespace {
+
+Result<sk_sp<SkImage>> GetSkImage(
+    const webrtc_streaming::VideoFrameBuffer& frame) {
+  const int w = frame.width();
+  const int h = frame.height();
+
+  sk_sp<SkData> rgba_data = SkData::MakeUninitialized(w * h * 4);
+  const int rgba_stride = w * 4;
+
+  int ret = libyuv::I420ToABGR(
+      frame.DataY(), frame.StrideY(),                                       //
+      frame.DataU(), frame.StrideU(),                                       //
+      frame.DataV(), frame.StrideV(),                                       //
+      reinterpret_cast<uint8_t*>(rgba_data->writable_data()), rgba_stride,  //
+      w, h);
+  CF_EXPECT_EQ(ret, 0, "Failed to convert input frame to RGBA.");
+
+  const SkImageInfo& image_info =
+      SkImageInfo::Make(w, h, kRGBA_8888_SkColorType, kOpaque_SkAlphaType);
+
+  sk_sp<SkImage> image =
+      SkImages::RasterFromData(image_info, rgba_data, rgba_stride);
+  CF_EXPECT(image != nullptr, "Failed to raster RGBA data.");
+
+  return image;
+}
+
+}  // namespace
+
+Result<void> ScreenshotHandler::Screenshot(std::uint32_t display_number,
+                                           const std::string& screenshot_path) {
+  SharedFrameFuture frame_future;
+  {
+    std::lock_guard<std::mutex> lock(pending_screenshot_displays_mutex_);
+
+    auto [it, inserted] = pending_screenshot_displays_.emplace(
+        display_number, SharedFramePromise{});
+    if (!inserted) {
+      return CF_ERRF("Screenshot already pending for display {}",
+                     display_number);
+    }
+
+    frame_future = it->second.get_future().share();
+  }
+
+  static constexpr const int kScreenshotTimeoutSeconds = 5;
+  auto result =
+      frame_future.wait_for(std::chrono::seconds(kScreenshotTimeoutSeconds));
+  CF_EXPECT(result == std::future_status::ready,
+            "Failed to get screenshot from webrtc display handler within "
+                << kScreenshotTimeoutSeconds << " seconds.");
+
+  SharedFrame frame = frame_future.get();
+
+  sk_sp<SkImage> screenshot_image =
+      CF_EXPECT(GetSkImage(*frame), "Failed to get skia image from raw frame.");
+
+  sk_sp<SkData> screenshot_data;
+  if (screenshot_path.ends_with(".jpg")) {
+    screenshot_data =
+        SkJpegEncoder::Encode(nullptr, screenshot_image.get(), {});
+    CF_EXPECT(screenshot_data != nullptr, "Failed to encode to JPEG.");
+  } else if (screenshot_path.ends_with(".png")) {
+    screenshot_data = SkPngEncoder::Encode(nullptr, screenshot_image.get(), {});
+    CF_EXPECT(screenshot_data != nullptr, "Failed to encode to PNG.");
+  } else if (screenshot_path.ends_with(".webp")) {
+    screenshot_data =
+        SkWebpEncoder::Encode(nullptr, screenshot_image.get(), {});
+    CF_EXPECT(screenshot_data != nullptr, "Failed to encode to WEBP.");
+  } else {
+    return CF_ERR("Unsupport file format: " << screenshot_path);
+  }
+
+  SkFILEWStream screenshot_file(screenshot_path.c_str());
+  CF_EXPECT(screenshot_file.isValid(),
+            "Failed to open " << screenshot_path << " for writing.");
+
+  CF_EXPECT(
+      screenshot_file.write(screenshot_data->data(), screenshot_data->size()),
+      "Failed to fully write png content to " << screenshot_path << ".");
+
+  return {};
+}
+
+void ScreenshotHandler::OnFrame(std::uint32_t display_number,
+                                SharedFrame& frame) {
+  std::lock_guard<std::mutex> lock(pending_screenshot_displays_mutex_);
+
+  auto pending_screenshot_it =
+      pending_screenshot_displays_.find(display_number);
+  if (pending_screenshot_it == pending_screenshot_displays_.end()) {
+    return;
+  }
+  SharedFramePromise& frame_promise = pending_screenshot_it->second;
+
+  frame_promise.set_value(frame);
+
+  pending_screenshot_displays_.erase(pending_screenshot_it);
+}
+
+}  // namespace cuttlefish
diff --git a/host/frontend/webrtc/screenshot_handler.h b/host/frontend/webrtc/screenshot_handler.h
new file mode 100644
index 000000000..6fe71f036
--- /dev/null
+++ b/host/frontend/webrtc/screenshot_handler.h
@@ -0,0 +1,53 @@
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
+#include <future>
+#include <mutex>
+#include <unordered_set>
+
+#include <fmt/format.h>
+#include <rtc_base/time_utils.h>
+
+#include "common/libs/utils/result.h"
+#include "host/frontend/webrtc/libdevice/video_frame_buffer.h"
+
+namespace cuttlefish {
+
+class ScreenshotHandler {
+ public:
+  ScreenshotHandler() = default;
+  ~ScreenshotHandler() = default;
+
+  using SharedFrame = std::shared_ptr<webrtc_streaming::VideoFrameBuffer>;
+  using SharedFrameFuture = std::shared_future<SharedFrame>;
+  using SharedFramePromise = std::promise<SharedFrame>;
+
+  Result<void> Screenshot(std::uint32_t display_number,
+                          const std::string& screenshot_path);
+
+  void OnFrame(std::uint32_t display_number, SharedFrame& buffer);
+
+ private:
+  std::mutex pending_screenshot_displays_mutex_;
+  // Promises used to share a frame for a given display from the display handler
+  // thread to the snapshot thread for processing.
+  std::unordered_map<std::uint32_t, SharedFramePromise>
+      pending_screenshot_displays_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/frontend/webrtc/webrtc_command_channel.cpp b/host/frontend/webrtc/webrtc_command_channel.cpp
new file mode 100644
index 000000000..afb8221fa
--- /dev/null
+++ b/host/frontend/webrtc/webrtc_command_channel.cpp
@@ -0,0 +1,97 @@
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
+#include "host/frontend/webrtc/webrtc_command_channel.h"
+
+#include <android-base/logging.h>
+
+namespace cuttlefish {
+namespace {
+
+constexpr const uint32_t kUnusedCommandField = 0;
+
+template <typename ProtoT>
+Result<transport::ManagedMessage> ToMessage(const ProtoT& proto) {
+  std::string proto_str;
+  CF_EXPECT(proto.SerializeToString(&proto_str), "Failed to serialize proto.");
+
+  auto msg = CF_EXPECT(
+      transport::CreateMessage(kUnusedCommandField, proto_str.size()));
+  std::memcpy(msg->payload, proto_str.data(), proto_str.size());
+  return msg;
+}
+
+template <typename ProtoT>
+Result<ProtoT> ToProto(transport::ManagedMessage msg) {
+  ProtoT proto;
+  CF_EXPECT(proto.ParseFromArray(msg->payload, msg->payload_size),
+            "Failed to serialize proto from message.");
+  return proto;
+}
+
+}  // namespace
+
+WebrtcClientCommandChannel::WebrtcClientCommandChannel(SharedFD fd)
+    : channel_(fd, fd) {}
+
+Result<webrtc::WebrtcCommandResponse> WebrtcClientCommandChannel::SendCommand(
+    const webrtc::WebrtcCommandRequest& request) {
+  auto request_msg = CF_EXPECT(
+      ToMessage(request),
+      "Failed to convert webrtc command request to transport message.");
+
+  CF_EXPECT(channel_.SendRequest(*request_msg),
+            "Failed to send webrtc command request.");
+
+  CF_EXPECT(channel_.WaitForMessage(),
+            "Failed to wait for webrtc command response.");
+
+  auto response_msg = CF_EXPECT(channel_.ReceiveMessage(),
+                                "Failed to receive webrtc command response.");
+
+  return CF_EXPECT(
+      ToProto<webrtc::WebrtcCommandResponse>(std::move(response_msg)));
+}
+
+Result<webrtc::WebrtcCommandRequest>
+WebrtcServerCommandChannel::ReceiveRequest() {
+  CF_EXPECT(channel_.WaitForMessage(),
+            "Failed to wait for webrtc command response.");
+
+  auto request_msg = CF_EXPECT(channel_.ReceiveMessage(),
+                               "Failed to receive webrtc command request.");
+
+  return CF_EXPECT(
+      ToProto<webrtc::WebrtcCommandRequest>(std::move(request_msg)),
+      "Failed to deserialize webrtc command request.");
+}
+
+WebrtcServerCommandChannel::WebrtcServerCommandChannel(SharedFD fd)
+    : channel_(fd, fd) {}
+
+Result<void> WebrtcServerCommandChannel::SendResponse(
+    const webrtc::WebrtcCommandResponse& response) {
+  auto response_msg = CF_EXPECT(
+      ToMessage(response),
+      "Failed to convert webrtc command response to transport message.");
+
+  CF_EXPECT(channel_.SendRequest(*response_msg),
+            "Failed to send webrtc command response.");
+
+  return {};
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/frontend/webrtc/webrtc_command_channel.h b/host/frontend/webrtc/webrtc_command_channel.h
new file mode 100644
index 000000000..6517a71bc
--- /dev/null
+++ b/host/frontend/webrtc/webrtc_command_channel.h
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
+#pragma once
+
+#include "common/libs/transport/channel_sharedfd.h"
+#include "webrtc_commands.pb.h"
+
+namespace cuttlefish {
+
+class WebrtcClientCommandChannel {
+ public:
+  WebrtcClientCommandChannel(SharedFD fd);
+
+  Result<webrtc::WebrtcCommandResponse> SendCommand(
+      const webrtc::WebrtcCommandRequest& request);
+
+ private:
+  transport::SharedFdChannel channel_;
+};
+
+class WebrtcServerCommandChannel {
+ public:
+  WebrtcServerCommandChannel(SharedFD fd);
+
+  Result<webrtc::WebrtcCommandRequest> ReceiveRequest();
+  Result<void> SendResponse(const webrtc::WebrtcCommandResponse& response);
+
+ private:
+  transport::SharedFdChannel channel_;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/frontend/webrtc/webrtc_commands.proto b/host/frontend/webrtc/webrtc_commands.proto
new file mode 100644
index 000000000..a5a27535a
--- /dev/null
+++ b/host/frontend/webrtc/webrtc_commands.proto
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
+syntax = "proto3";
+
+import "google/rpc/status.proto";
+
+package cuttlefish.webrtc;
+
+message StartRecordingDisplayRequest {}
+
+message StopRecordingDisplayRequest {}
+
+message ScreenshotDisplayRequest {
+  int32 display_number = 1;
+  string screenshot_path = 2;
+}
+
+message WebrtcCommandRequest {
+  oneof actions {
+    StartRecordingDisplayRequest start_recording_request = 1;
+    StopRecordingDisplayRequest stop_recording_request = 2;
+    ScreenshotDisplayRequest screenshot_display_request = 3;
+  }
+}
+
+message WebrtcCommandResponse {
+  google.rpc.Status status = 1;
+}
diff --git a/host/frontend/webrtc_operator/Android.bp b/host/frontend/webrtc_operator/Android.bp
index 97a976f6f..0c872b056 100644
--- a/host/frontend/webrtc_operator/Android.bp
+++ b/host/frontend/webrtc_operator/Android.bp
@@ -27,11 +27,11 @@ cc_binary_host {
     name: "webrtc_operator",
     srcs: [
         "client_handler.cpp",
-        "device_registry.cpp",
         "device_handler.cpp",
         "device_list_handler.cpp",
-        "server_config.cpp",
+        "device_registry.cpp",
         "server.cpp",
+        "server_config.cpp",
         "signal_handler.cpp",
     ],
     header_libs: [
@@ -39,18 +39,18 @@ cc_binary_host {
     ],
     shared_libs: [
         "libbase",
-        "liblog",
         "libcrypto",
+        "libcuttlefish_fs",
         "libjsoncpp",
+        "liblog",
         "libssl",
-        "libcuttlefish_fs",
     ],
     static_libs: [
         "libcap",
-        "libgflags",
-        "libcuttlefish_utils",
         "libcuttlefish_host_config",
         "libcuttlefish_host_websocket",
+        "libcuttlefish_utils",
+        "libgflags",
         "libprotobuf-cpp-full",
         "libwebsockets",
     ],
diff --git a/host/libs/allocd/Android.bp b/host/libs/allocd/Android.bp
index d1cbedcd7..91354a310 100644
--- a/host/libs/allocd/Android.bp
+++ b/host/libs/allocd/Android.bp
@@ -24,8 +24,8 @@ cc_library {
     ],
     shared_libs: [
         "libbase",
-        "libcuttlefish_utils",
         "libcuttlefish_fs",
+        "libcuttlefish_utils",
         "libjsoncpp",
         "liblog",
     ],
@@ -47,8 +47,8 @@ cc_binary {
         "libcuttlefish_allocd_utils",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "liblog",
         "libjsoncpp",
+        "liblog",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/libs/audio_connector/Android.bp b/host/libs/audio_connector/Android.bp
index 7da54ad59..cea919ea2 100644
--- a/host/libs/audio_connector/Android.bp
+++ b/host/libs/audio_connector/Android.bp
@@ -25,8 +25,8 @@ cc_library {
         "server.cpp",
     ],
     shared_libs: [
-        "libcuttlefish_fs",
         "libbase",
+        "libcuttlefish_fs",
         "libjsoncpp",
         "liblog",
     ],
diff --git a/host/libs/audio_connector/server.cpp b/host/libs/audio_connector/server.cpp
index f98621c3b..0cfa6acf1 100644
--- a/host/libs/audio_connector/server.cpp
+++ b/host/libs/audio_connector/server.cpp
@@ -157,8 +157,8 @@ std::unique_ptr<AudioClientConnection> AudioClientConnection::Create(
   }
 
   return std::unique_ptr<AudioClientConnection>(new AudioClientConnection(
-      std::move(tx_shm), std::move(rx_shm), client_socket,
-      event_socket, tx_socket, rx_socket));
+      std::move(tx_shm), std::move(rx_shm), client_socket, event_socket,
+      tx_socket, rx_socket));
 }
 
 bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
@@ -187,12 +187,14 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       std::unique_ptr<virtio_snd_pcm_info[]> reply(
           new virtio_snd_pcm_info[info_count]);
       StreamInfoCommand cmd(start_id, info_count, reply.get());
+      LOG(DEBUG) << "VIRTIO_SND_PCM_INFO: start=" << start_id
+                 << ", count=" << info_count;
 
       executor.StreamsInfo(cmd);
-      return CmdReply(cmd.status(), reply.get(),
-                      info_count * sizeof(reply[0]));
+      return CmdReply(cmd.status(), reply.get(), info_count * sizeof(reply[0]));
     }
     case AudioCommandType::VIRTIO_SND_R_PCM_SET_PARAMS: {
+      LOG(DEBUG) << "IVRTIO_SND_R_PCM_SET_PARAM";
       if (recv_size < sizeof(virtio_snd_pcm_set_params)) {
         LOG(ERROR) << "Received SET_PARAMS message is too small: " << recv_size;
         return false;
@@ -216,6 +218,8 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       auto pcm_op_msg = reinterpret_cast<const virtio_snd_pcm_hdr*>(cmd_hdr);
       StreamControlCommand cmd(AudioCommandType::VIRTIO_SND_R_PCM_PREPARE,
                                pcm_op_msg->stream_id.as_uint32_t());
+      LOG(DEBUG) << "VRTIO_SND_R_PCM_PREPARE: stream_id="
+                 << pcm_op_msg->stream_id.as_uint32_t();
       executor.PrepareStream(cmd);
       return CmdReply(cmd.status());
     }
@@ -227,6 +231,8 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       auto pcm_op_msg = reinterpret_cast<const virtio_snd_pcm_hdr*>(cmd_hdr);
       StreamControlCommand cmd(AudioCommandType::VIRTIO_SND_R_PCM_RELEASE,
                                pcm_op_msg->stream_id.as_uint32_t());
+      LOG(DEBUG) << "VRTIO_SND_R_PCM_RELEASE: stream_id="
+                 << pcm_op_msg->stream_id.as_uint32_t();
       executor.ReleaseStream(cmd);
       return CmdReply(cmd.status());
     }
@@ -236,8 +242,11 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
         return false;
       }
       auto pcm_op_msg = reinterpret_cast<const virtio_snd_pcm_hdr*>(cmd_hdr);
+      uint32_t stream_id = pcm_op_msg->stream_id.as_uint32_t();
       StreamControlCommand cmd(AudioCommandType::VIRTIO_SND_R_PCM_START,
-                               pcm_op_msg->stream_id.as_uint32_t());
+                               stream_id);
+      LOG(DEBUG) << "VRTIO_SND_R_PCM_START: stream_id=" << stream_id;
+      frame_counters_[stream_id] = {0, 1};
       executor.StartStream(cmd);
       return CmdReply(cmd.status());
     }
@@ -249,6 +258,8 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       auto pcm_op_msg = reinterpret_cast<const virtio_snd_pcm_hdr*>(cmd_hdr);
       StreamControlCommand cmd(AudioCommandType::VIRTIO_SND_R_PCM_STOP,
                                pcm_op_msg->stream_id.as_uint32_t());
+      LOG(DEBUG) << "VRTIO_SND_R_PCM_STOP: stream_id="
+                 << pcm_op_msg->stream_id.as_uint32_t();
       executor.StopStream(cmd);
       return CmdReply(cmd.status());
     }
@@ -263,10 +274,11 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       std::unique_ptr<virtio_snd_chmap_info[]> reply(
           new virtio_snd_chmap_info[info_count]);
       ChmapInfoCommand cmd(start_id, info_count, reply.get());
+      LOG(DEBUG) << "VRTIO_SND_R_CHMAP_INFO: start_id=" << start_id
+                 << ", count=" << info_count;
 
       executor.ChmapsInfo(cmd);
-      return CmdReply(cmd.status(), reply.get(),
-                      info_count * sizeof(reply[0]));
+      return CmdReply(cmd.status(), reply.get(), info_count * sizeof(reply[0]));
     }
     case AudioCommandType::VIRTIO_SND_R_JACK_INFO: {
       if (recv_size < sizeof(virtio_snd_query_info)) {
@@ -279,10 +291,11 @@ bool AudioClientConnection::ReceiveCommands(AudioServerExecutor& executor) {
       std::unique_ptr<virtio_snd_jack_info[]> reply(
           new virtio_snd_jack_info[info_count]);
       JackInfoCommand cmd(start_id, info_count, reply.get());
+      LOG(DEBUG) << "VRTIO_SND_R_JACK_INFO: start_id=" << start_id
+                 << ", count=" << info_count;
 
       executor.JacksInfo(cmd);
-      return CmdReply(cmd.status(), reply.get(),
-                      info_count * sizeof(reply[0]));
+      return CmdReply(cmd.status(), reply.get(), info_count * sizeof(reply[0]));
     }
     case AudioCommandType::VIRTIO_SND_R_JACK_REMAP:
       LOG(ERROR) << "Unsupported command type: " << cmd_hdr->code.as_uint32_t();
@@ -308,6 +321,12 @@ bool AudioClientConnection::ReceivePlayback(AudioServerExecutor& executor) {
     LOG(ERROR) << "Received PCM_XFER message is too small: " << recv_size;
     return false;
   }
+  const uint32_t stream_id = msg_hdr->io_xfer.stream_id.as_uint32_t();
+  auto& [frame_count, log_at] = frame_counters_[stream_id];
+  if (++frame_count >= log_at) {
+    LOG(DEBUG) << "Stream id=" << stream_id << ": " << frame_count << " frames";
+    log_at *= 16;
+  }
   TxBuffer buffer(
       msg_hdr->io_xfer,
       BufferAt(tx_shm_, msg_hdr->buffer_offset, msg_hdr->buffer_len),
@@ -328,6 +347,12 @@ bool AudioClientConnection::ReceiveCapture(AudioServerExecutor& executor) {
     LOG(ERROR) << "Received PCM_XFER message is too small: " << recv_size;
     return false;
   }
+  const uint32_t stream_id = msg_hdr->io_xfer.stream_id.as_uint32_t();
+  auto& [frame_count, log_at] = frame_counters_[stream_id];
+  if (++frame_count >= log_at) {
+    LOG(DEBUG) << "Stream id=" << stream_id << ": " << frame_count << " frames";
+    log_at *= 16;
+  }
   RxBuffer buffer(
       msg_hdr->io_xfer,
       BufferAt(rx_shm_, msg_hdr->buffer_offset, msg_hdr->buffer_len),
diff --git a/host/libs/audio_connector/server.h b/host/libs/audio_connector/server.h
index fec36dcb2..bf4c3e839 100644
--- a/host/libs/audio_connector/server.h
+++ b/host/libs/audio_connector/server.h
@@ -17,7 +17,9 @@
 #include <cinttypes>
 
 #include <functional>
+#include <map>
 #include <memory>
+#include <utility>
 
 #include "common/libs/fs/shared_fd.h"
 #include "host/libs/audio_connector/buffers.h"
@@ -94,6 +96,8 @@ class AudioClientConnection {
   SharedFD event_socket_;
   SharedFD tx_socket_;
   SharedFD rx_socket_;
+  // Hold the number of frames since START and when to log it for each stream.
+  std::map<uint32_t, std::pair<uint64_t, uint64_t>> frame_counters_;
 };
 
 class AudioServer {
diff --git a/host/libs/avb/Android.bp b/host/libs/avb/Android.bp
index 3c198acef..a3a10e783 100644
--- a/host/libs/avb/Android.bp
+++ b/host/libs/avb/Android.bp
@@ -20,7 +20,7 @@ package {
 cc_library {
     name: "libcuttlefish_avb",
     srcs: [
-        "avb.cpp"
+        "avb.cpp",
     ],
     shared_libs: [
         "libcuttlefish_fs",
@@ -31,7 +31,7 @@ cc_library {
     ],
     static_libs: [
         "libbase",
-        "libcuttlefish_host_config"
+        "libcuttlefish_host_config",
     ],
     defaults: ["cuttlefish_host"],
     target: {
diff --git a/host/libs/command_util/Android.bp b/host/libs/command_util/Android.bp
index 056d4dfc5..9abf9232d 100644
--- a/host/libs/command_util/Android.bp
+++ b/host/libs/command_util/Android.bp
@@ -24,11 +24,11 @@ cc_library {
         "util.cc",
     ],
     shared_libs: [
-        "liblog",
         "libcuttlefish_fs",
-        "libcuttlefish_utils",
         "libcuttlefish_run_cvd_proto",
+        "libcuttlefish_utils",
         "libjsoncpp",
+        "liblog",
         "libprotobuf-cpp-full",
     ],
     export_shared_lib_headers: [
diff --git a/host/libs/command_util/runner/run_cvd.proto b/host/libs/command_util/runner/run_cvd.proto
index a017dd205..05d7d0de2 100644
--- a/host/libs/command_util/runner/run_cvd.proto
+++ b/host/libs/command_util/runner/run_cvd.proto
@@ -25,6 +25,7 @@ message ExtendedLauncherAction {
     StartScreenRecording start_screen_recording = 7;
     StopScreenRecording stop_screen_recording = 8;
     SnapshotTake snapshot_take = 9;
+    ScreenshotDisplay screenshot_display = 10;
   }
   string verbosity = 20;
 }
@@ -35,3 +36,7 @@ message StopScreenRecording {}
 message SnapshotTake {
   string snapshot_path = 1;
 }
+message ScreenshotDisplay {
+  int32 display_number = 1;
+  string screenshot_path = 2;
+}
\ No newline at end of file
diff --git a/host/libs/config/adb/Android.bp b/host/libs/config/adb/Android.bp
index 7ebc01fc1..58a103774 100644
--- a/host/libs/config/adb/Android.bp
+++ b/host/libs/config/adb/Android.bp
@@ -57,8 +57,8 @@ cc_test_host {
         "libcuttlefish_utils",
     ],
     shared_libs: [
-        "libgflags",
         "libfruit",
+        "libgflags",
         "libjsoncpp",
         "liblog",
     ],
diff --git a/host/libs/config/cuttlefish_config.cpp b/host/libs/config/cuttlefish_config.cpp
index 6bc5d6564..9492ee819 100644
--- a/host/libs/config/cuttlefish_config.cpp
+++ b/host/libs/config/cuttlefish_config.cpp
@@ -64,7 +64,7 @@ const char* const kGpuVhostUserModeOn = "on";
 const char* const kGpuVhostUserModeOff = "off";
 
 const char* const kHwComposerAuto = "auto";
-const char* const kHwComposerDrm = "drm";
+const char* const kHwComposerDrm = "drm_hwcomposer";
 const char* const kHwComposerRanchu = "ranchu";
 const char* const kHwComposerNone = "none";
 
diff --git a/host/libs/config/cuttlefish_config.h b/host/libs/config/cuttlefish_config.h
index c28f337f8..ed8cde7c9 100644
--- a/host/libs/config/cuttlefish_config.h
+++ b/host/libs/config/cuttlefish_config.h
@@ -377,6 +377,7 @@ class CuttlefishConfig {
     std::string instance_internal_uds_dir() const;
 
     std::string touch_socket_path(int touch_dev_idx) const;
+    std::string mouse_socket_path() const;
     std::string rotary_socket_path() const;
     std::string keyboard_socket_path() const;
     std::string switches_socket_path() const;
@@ -564,6 +565,7 @@ class CuttlefishConfig {
     bool pause_in_bootloader() const;
     bool run_as_daemon() const;
     bool enable_audio() const;
+    bool enable_mouse() const;
     bool enable_gnss_grpc_proxy() const;
     bool enable_bootanimation() const;
     bool enable_usb() const;
@@ -651,6 +653,7 @@ class CuttlefishConfig {
     std::string new_vbmeta_vendor_dlkm_image() const;
     std::string vbmeta_system_dlkm_image() const;
     std::string new_vbmeta_system_dlkm_image() const;
+    std::string vvmtruststore_path() const;
     std::string default_target_zip() const;
     std::string system_target_zip() const;
 
@@ -785,6 +788,7 @@ class CuttlefishConfig {
     void set_pause_in_bootloader(bool pause_in_bootloader);
     void set_run_as_daemon(bool run_as_daemon);
     void set_enable_audio(bool enable);
+    void set_enable_mouse(bool enable);
     void set_enable_usb(bool enable);
     void set_enable_gnss_grpc_proxy(const bool enable_gnss_grpc_proxy);
     void set_enable_bootanimation(const bool enable_bootanimation);
@@ -875,6 +879,7 @@ class CuttlefishConfig {
         const std::string& vbmeta_system_dlkm_image);
     void set_new_vbmeta_system_dlkm_image(
         const std::string& vbmeta_system_dlkm_image);
+    void set_vvmtruststore_path(const std::string& vvmtruststore_path);
     void set_default_target_zip(const std::string& default_target_zip);
     void set_system_target_zip(const std::string& system_target_zip);
     void set_otheros_esp_image(const std::string& otheros_esp_image);
@@ -952,6 +957,9 @@ class CuttlefishConfig {
     std::string control_socket_path() const;
     std::string launcher_log_path() const;
 
+    std::string casimir_nci_socket_path() const;
+    std::string casimir_rf_socket_path() const;
+
     // wmediumd related configs
     bool enable_wifi() const;
     bool start_wmediumd() const;
diff --git a/host/libs/config/cuttlefish_config_environment.cpp b/host/libs/config/cuttlefish_config_environment.cpp
index aa798827a..94614a07a 100644
--- a/host/libs/config/cuttlefish_config_environment.cpp
+++ b/host/libs/config/cuttlefish_config_environment.cpp
@@ -84,6 +84,16 @@ std::string CuttlefishConfig::EnvironmentSpecific::launcher_log_path() const {
   return AbsolutePath(PerEnvironmentLogPath("launcher.log"));
 }
 
+std::string CuttlefishConfig::EnvironmentSpecific::casimir_nci_socket_path()
+    const {
+  return PerEnvironmentUdsPath("casimir_nci.sock");
+}
+
+std::string CuttlefishConfig::EnvironmentSpecific::casimir_rf_socket_path()
+    const {
+  return PerEnvironmentUdsPath("casimir_rf.sock");
+}
+
 static constexpr char kEnableWifi[] = "enable_wifi";
 void CuttlefishConfig::MutableEnvironmentSpecific::set_enable_wifi(
     bool enable_wifi) {
diff --git a/host/libs/config/cuttlefish_config_instance.cpp b/host/libs/config/cuttlefish_config_instance.cpp
index af17eb56a..1c6e35df5 100644
--- a/host/libs/config/cuttlefish_config_instance.cpp
+++ b/host/libs/config/cuttlefish_config_instance.cpp
@@ -423,6 +423,14 @@ void CuttlefishConfig::MutableInstanceSpecific::set_kernel_path(
     const std::string& kernel_path) {
   (*Dictionary())[kKernelPath] = kernel_path;
 }
+static constexpr char kVvmtruststorePath[] = "vvmtruststore_path";
+void CuttlefishConfig::MutableInstanceSpecific::set_vvmtruststore_path(
+    const std::string& vvmtruststore_path) {
+  (*Dictionary())[kVvmtruststorePath] = vvmtruststore_path;
+}
+std::string CuttlefishConfig::InstanceSpecific::vvmtruststore_path() const {
+  return (*Dictionary())[kVvmtruststorePath].asString();
+}
 // end of system image files
 
 static constexpr char kDefaultTargetZip[] = "default_target_zip";
@@ -885,6 +893,14 @@ bool CuttlefishConfig::InstanceSpecific::enable_audio() const {
   return (*Dictionary())[kEnableAudio].asBool();
 }
 
+static constexpr char kEnableMouse[] = "enable_mouse";
+void CuttlefishConfig::MutableInstanceSpecific::set_enable_mouse(bool enable) {
+  (*Dictionary())[kEnableMouse] = enable;
+}
+bool CuttlefishConfig::InstanceSpecific::enable_mouse() const {
+  return (*Dictionary())[kEnableMouse].asBool();
+}
+
 static constexpr char kEnableGnssGrpcProxy[] = "enable_gnss_grpc_proxy";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_gnss_grpc_proxy(const bool enable_gnss_grpc_proxy) {
   (*Dictionary())[kEnableGnssGrpcProxy] = enable_gnss_grpc_proxy;
@@ -1847,6 +1863,10 @@ std::string CuttlefishConfig::InstanceSpecific::touch_socket_path(
       ("touch_" + std::to_string(touch_dev_idx) + ".sock").c_str());
 }
 
+std::string CuttlefishConfig::InstanceSpecific::mouse_socket_path() const {
+  return PerInstanceInternalPath("mouse.sock");
+}
+
 std::string CuttlefishConfig::InstanceSpecific::rotary_socket_path() const {
   return PerInstanceInternalPath("rotary.sock");
 }
diff --git a/host/libs/config/data_image.cpp b/host/libs/config/data_image.cpp
index ad389fe91..f2a2b680f 100644
--- a/host/libs/config/data_image.cpp
+++ b/host/libs/config/data_image.cpp
@@ -32,6 +32,9 @@
 
 namespace cuttlefish {
 
+using APBootFlow = CuttlefishConfig::InstanceSpecific::APBootFlow;
+using BootFlow = CuttlefishConfig::InstanceSpecific::BootFlow;
+
 namespace {
 
 static constexpr std::string_view kDataPolicyUseExisting = "use_existing";
@@ -250,171 +253,140 @@ Result<void> InitializeMiscImage(
   return {};
 }
 
-class InitializeEspImageImpl : public InitializeEspImage {
- public:
-  INJECT(InitializeEspImageImpl(
-      const CuttlefishConfig& config,
-      const CuttlefishConfig::InstanceSpecific& instance))
-      : config_(config), instance_(instance) {}
+static bool EspRequiredForBootFlow(BootFlow flow) {
+  return flow == BootFlow::AndroidEfiLoader || flow == BootFlow::ChromeOs ||
+         flow == BootFlow::Linux || flow == BootFlow::Fuchsia;
+}
 
-  // SetupFeature
-  std::string Name() const override { return "InitializeEspImageImpl"; }
-  std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
+static bool EspRequiredForAPBootFlow(APBootFlow ap_boot_flow) {
+  return ap_boot_flow == APBootFlow::Grub;
+}
 
-  bool Enabled() const override {
-    return EspRequiredForBootFlow() || EspRequiredForAPBootFlow();
+static void InitLinuxArgs(Arch target_arch, LinuxEspBuilder& linux) {
+  linux.Root("/dev/vda2");
+
+  linux.Argument("console", "hvc0").Argument("panic", "-1").Argument("noefi");
+
+  switch (target_arch) {
+    case Arch::Arm:
+    case Arch::Arm64:
+      linux.Argument("console", "ttyAMA0");
+      break;
+    case Arch::RiscV64:
+      linux.Argument("console", "ttyS0");
+      break;
+    case Arch::X86:
+    case Arch::X86_64:
+      linux.Argument("console", "ttyS0")
+          .Argument("pnpacpi", "off")
+          .Argument("acpi", "noirq")
+          .Argument("reboot", "k")
+          .Argument("noexec", "off");
+      break;
   }
+}
 
- protected:
-  Result<void> ResultSetup() override {
-    if (EspRequiredForAPBootFlow()) {
-      LOG(DEBUG) << "creating esp_image: " << instance_.ap_esp_image_path();
-      CF_EXPECT(BuildAPImage());
-    }
-    const auto is_not_gem5 = config_.vm_manager() != VmmMode::kGem5;
-    const auto esp_required_for_boot_flow = EspRequiredForBootFlow();
-    if (is_not_gem5 && esp_required_for_boot_flow) {
-      LOG(DEBUG) << "creating esp_image: " << instance_.esp_image_path();
-      CF_EXPECT(BuildOSImage());
-    }
-    return {};
-  }
+static void InitChromeOsArgs(LinuxEspBuilder& linux) {
+  linux.Root("/dev/vda2")
+      .Argument("console", "ttyS0")
+      .Argument("panic", "-1")
+      .Argument("noefi")
+      .Argument("init=/sbin/init")
+      .Argument("boot=local")
+      .Argument("rootwait")
+      .Argument("noresume")
+      .Argument("noswap")
+      .Argument("loglevel=7")
+      .Argument("noinitrd")
+      .Argument("cros_efi")
+      .Argument("cros_debug")
+      .Argument("earlyprintk=serial,ttyS0,115200")
+      .Argument("earlycon=uart8250,io,0x3f8")
+      .Argument("pnpacpi", "off")
+      .Argument("acpi", "noirq")
+      .Argument("reboot", "k")
+      .Argument("noexec", "off");
+}
 
- private:
+static bool BuildAPImage(const CuttlefishConfig& config,
+                         const CuttlefishConfig::InstanceSpecific& instance) {
+  auto linux = LinuxEspBuilder(instance.ap_esp_image_path());
+  InitLinuxArgs(instance.target_arch(), linux);
 
-  bool EspRequiredForBootFlow() const {
-    const auto flow = instance_.boot_flow();
-    using BootFlow = CuttlefishConfig::InstanceSpecific::BootFlow;
-    return flow == BootFlow::AndroidEfiLoader || flow == BootFlow::ChromeOs ||
-           flow == BootFlow::Linux || flow == BootFlow::Fuchsia;
+  auto openwrt_args = OpenwrtArgsFromConfig(instance);
+  for (auto& openwrt_arg : openwrt_args) {
+    linux.Argument(openwrt_arg.first, openwrt_arg.second);
   }
 
-  bool EspRequiredForAPBootFlow() const {
-    return instance_.ap_boot_flow() == CuttlefishConfig::InstanceSpecific::APBootFlow::Grub;
-  }
+  linux.Root("/dev/vda2")
+      .Architecture(instance.target_arch())
+      .Kernel(config.ap_kernel_image());
 
-  bool BuildAPImage() {
-    auto linux = LinuxEspBuilder(instance_.ap_esp_image_path());
-    InitLinuxArgs(linux);
+  return linux.Build();
+}
 
-    auto openwrt_args = OpenwrtArgsFromConfig(instance_);
-    for (auto& openwrt_arg : openwrt_args) {
-      linux.Argument(openwrt_arg.first, openwrt_arg.second);
+static bool BuildOSImage(const CuttlefishConfig::InstanceSpecific& instance) {
+  switch (instance.boot_flow()) {
+    case BootFlow::AndroidEfiLoader: {
+      auto android_efi_loader =
+          AndroidEfiLoaderEspBuilder(instance.esp_image_path());
+      android_efi_loader.EfiLoaderPath(instance.android_efi_loader())
+          .Architecture(instance.target_arch());
+      return android_efi_loader.Build();
     }
+    case BootFlow::ChromeOs: {
+      auto linux = LinuxEspBuilder(instance.esp_image_path());
+      InitChromeOsArgs(linux);
 
-    linux.Root("/dev/vda2")
-         .Architecture(instance_.target_arch())
-         .Kernel(config_.ap_kernel_image());
+      linux.Root("/dev/vda3")
+          .Architecture(instance.target_arch())
+          .Kernel(instance.chromeos_kernel_path());
 
-    return linux.Build();
-  }
-
-  bool BuildOSImage() {
-    switch (instance_.boot_flow()) {
-      case CuttlefishConfig::InstanceSpecific::BootFlow::AndroidEfiLoader: {
-        auto android_efi_loader =
-            AndroidEfiLoaderEspBuilder(instance_.esp_image_path());
-        android_efi_loader.EfiLoaderPath(instance_.android_efi_loader())
-            .Architecture(instance_.target_arch());
-        return android_efi_loader.Build();
-      }
-      case CuttlefishConfig::InstanceSpecific::BootFlow::ChromeOs: {
-        auto linux = LinuxEspBuilder(instance_.esp_image_path());
-        InitChromeOsArgs(linux);
+      return linux.Build();
+    }
+    case BootFlow::Linux: {
+      auto linux = LinuxEspBuilder(instance.esp_image_path());
+      InitLinuxArgs(instance.target_arch(), linux);
 
-        linux.Root("/dev/vda3")
-            .Architecture(instance_.target_arch())
-            .Kernel(instance_.chromeos_kernel_path());
+      linux.Root("/dev/vda2")
+          .Architecture(instance.target_arch())
+          .Kernel(instance.linux_kernel_path());
 
-        return linux.Build();
+      if (!instance.linux_initramfs_path().empty()) {
+        linux.Initrd(instance.linux_initramfs_path());
       }
-      case CuttlefishConfig::InstanceSpecific::BootFlow::Linux: {
-        auto linux = LinuxEspBuilder(instance_.esp_image_path());
-        InitLinuxArgs(linux);
-
-        linux.Root("/dev/vda2")
-             .Architecture(instance_.target_arch())
-             .Kernel(instance_.linux_kernel_path());
 
-        if (!instance_.linux_initramfs_path().empty()) {
-          linux.Initrd(instance_.linux_initramfs_path());
-        }
-
-        return linux.Build();
-      }
-      case CuttlefishConfig::InstanceSpecific::BootFlow::Fuchsia: {
-        auto fuchsia = FuchsiaEspBuilder(instance_.esp_image_path());
-        return fuchsia.Architecture(instance_.target_arch())
-                      .Zedboot(instance_.fuchsia_zedboot_path())
-                      .MultibootBinary(instance_.fuchsia_multiboot_bin_path())
-                      .Build();
-      }
-      default:
-        break;
+      return linux.Build();
     }
-
-    return true;
-  }
-
-  void InitLinuxArgs(LinuxEspBuilder& linux) {
-    linux.Root("/dev/vda2");
-
-    linux.Argument("console", "hvc0")
-         .Argument("panic", "-1")
-         .Argument("noefi");
-
-    switch (instance_.target_arch()) {
-      case Arch::Arm:
-      case Arch::Arm64:
-        linux.Argument("console", "ttyAMA0");
-        break;
-      case Arch::RiscV64:
-        linux.Argument("console", "ttyS0");
-        break;
-      case Arch::X86:
-      case Arch::X86_64:
-        linux.Argument("console", "ttyS0")
-             .Argument("pnpacpi", "off")
-             .Argument("acpi", "noirq")
-             .Argument("reboot", "k")
-             .Argument("noexec", "off");
-        break;
+    case BootFlow::Fuchsia: {
+      auto fuchsia = FuchsiaEspBuilder(instance.esp_image_path());
+      return fuchsia.Architecture(instance.target_arch())
+          .Zedboot(instance.fuchsia_zedboot_path())
+          .MultibootBinary(instance.fuchsia_multiboot_bin_path())
+          .Build();
     }
+    default:
+      break;
   }
 
-  void InitChromeOsArgs(LinuxEspBuilder& linux) {
-    linux.Root("/dev/vda2")
-        .Argument("console", "ttyS0")
-        .Argument("panic", "-1")
-        .Argument("noefi")
-        .Argument("init=/sbin/init")
-        .Argument("boot=local")
-        .Argument("rootwait")
-        .Argument("noresume")
-        .Argument("noswap")
-        .Argument("loglevel=7")
-        .Argument("noinitrd")
-        .Argument("cros_efi")
-        .Argument("cros_debug")
-        .Argument("earlyprintk=serial,ttyS0,115200")
-        .Argument("earlycon=uart8250,io,0x3f8")
-        .Argument("pnpacpi", "off")
-        .Argument("acpi", "noirq")
-        .Argument("reboot", "k")
-        .Argument("noexec", "off");
-  }
+  return true;
+}
 
-  const CuttlefishConfig& config_;
-  const CuttlefishConfig::InstanceSpecific& instance_;
-};
-
-fruit::Component<fruit::Required<const CuttlefishConfig,
-                                 const CuttlefishConfig::InstanceSpecific>,
-                 InitializeEspImage>
-InitializeEspImageComponent() {
-  return fruit::createComponent()
-      .addMultibinding<SetupFeature, InitializeEspImage>()
-      .bind<InitializeEspImage, InitializeEspImageImpl>();
+Result<void> InitializeEspImage(
+    const CuttlefishConfig& config,
+    const CuttlefishConfig::InstanceSpecific& instance) {
+  if (EspRequiredForAPBootFlow(instance.ap_boot_flow())) {
+    LOG(DEBUG) << "creating esp_image: " << instance.ap_esp_image_path();
+    CF_EXPECT(BuildAPImage(config, instance));
+  }
+  const auto is_not_gem5 = config.vm_manager() != VmmMode::kGem5;
+  const auto esp_required_for_boot_flow =
+      EspRequiredForBootFlow(instance.boot_flow());
+  if (is_not_gem5 && esp_required_for_boot_flow) {
+    LOG(DEBUG) << "creating esp_image: " << instance.esp_image_path();
+    CF_EXPECT(BuildOSImage(instance));
+  }
+  return {};
 }
 
 } // namespace cuttlefish
diff --git a/host/libs/config/data_image.h b/host/libs/config/data_image.h
index c60b14958..e91dad78a 100644
--- a/host/libs/config/data_image.h
+++ b/host/libs/config/data_image.h
@@ -17,22 +17,15 @@
 
 #include <string>
 
-#include <fruit/fruit.h>
-
 #include "common/libs/utils/result.h"
 #include "host/libs/config/cuttlefish_config.h"
-#include "host/libs/config/feature.h"
 
 namespace cuttlefish {
 
 Result<void> InitializeDataImage(const CuttlefishConfig::InstanceSpecific&);
 
-class InitializeEspImage : public SetupFeature {};
-
-fruit::Component<fruit::Required<const CuttlefishConfig,
-                                 const CuttlefishConfig::InstanceSpecific>,
-                 InitializeEspImage>
-InitializeEspImageComponent();
+Result<void> InitializeEspImage(const CuttlefishConfig&,
+                                const CuttlefishConfig::InstanceSpecific&);
 
 Result<void> CreateBlankImage(const std::string& image, int num_mb,
                               const std::string& image_fmt);
diff --git a/host/libs/config/fastboot/Android.bp b/host/libs/config/fastboot/Android.bp
index c2fb04124..2787727d9 100644
--- a/host/libs/config/fastboot/Android.bp
+++ b/host/libs/config/fastboot/Android.bp
@@ -23,7 +23,7 @@ cc_library {
         "config.cpp",
         "data.cpp",
         "flags.cpp",
-        "launch.cpp"
+        "launch.cpp",
     ],
     shared_libs: [
         "libbase",
diff --git a/host/libs/config/feature.h b/host/libs/config/feature.h
index 1538e46cb..cbc33abe8 100644
--- a/host/libs/config/feature.h
+++ b/host/libs/config/feature.h
@@ -51,7 +51,7 @@ class SetupFeature : public virtual Feature<SetupFeature> {
 
   static Result<void> RunSetup(const std::vector<SetupFeature*>& features);
 
-  virtual bool Enabled() const = 0;
+  virtual bool Enabled() const { return true; }
 
  private:
   virtual Result<void> ResultSetup() = 0;
diff --git a/host/libs/confui/Android.bp b/host/libs/confui/Android.bp
index 24cdfc31d..30265d901 100644
--- a/host/libs/confui/Android.bp
+++ b/host/libs/confui/Android.bp
@@ -33,6 +33,7 @@ cc_library {
     name: "libcuttlefish_confui_host",
     srcs: [
         "cbor.cc",
+        "fonts.S",
         "host_renderer.cc",
         "host_server.cc",
         "host_utils.cc",
@@ -41,28 +42,27 @@ cc_library {
         "server_common.cc",
         "session.cc",
         "sign.cc",
-        "fonts.S",
     ],
     shared_libs: [
+        "android.hardware.keymaster@4.0",
+        "libbase",
         "libcn-cbor",
+        "libcrypto",
         "libcuttlefish_fs",
-        "libbase",
         "libfruit",
         "libjsoncpp",
         "liblog",
-        "libcrypto",
-        "android.hardware.keymaster@4.0",
     ],
     header_libs: [
         "libcuttlefish_confui_host_headers",
         "libdrm_headers",
     ],
     static_libs: [
-        "libcuttlefish_host_config",
-        "libcuttlefish_utils",
         "libcuttlefish_confui",
+        "libcuttlefish_host_config",
         "libcuttlefish_input_connector",
         "libcuttlefish_security",
+        "libcuttlefish_utils",
         "libcuttlefish_wayland_server",
         "libft2.nodep",
         "libteeui",
diff --git a/host/libs/confui/host_virtual_input.cc b/host/libs/confui/host_virtual_input.cc
index 511688680..125994480 100644
--- a/host/libs/confui/host_virtual_input.cc
+++ b/host/libs/confui/host_virtual_input.cc
@@ -42,6 +42,9 @@ class HostVirtualInputEventSink : public InputConnector::EventSink {
         host_virtual_input_(host_virtual_input) {}
 
   // EventSink implementation
+  Result<void> SendMouseMoveEvent(int x, int y) override;
+  Result<void> SendMouseButtonEvent(int button, bool down) override;
+  Result<void> SendMouseWheelEvent(int pixels) override;
   Result<void> SendTouchEvent(const std::string& device_label, int x, int y,
                               bool down) override;
   Result<void> SendMultiTouchEvent(const std::string& device_label,
@@ -56,6 +59,22 @@ class HostVirtualInputEventSink : public InputConnector::EventSink {
   HostVirtualInput& host_virtual_input_;
 };
 
+Result<void> HostVirtualInputEventSink::SendMouseMoveEvent(int x, int y) {
+  ConfUiLog(INFO) << "Sending mouse move event: " << x << "," << y;
+  return android_mode_input_->SendMouseMoveEvent(x, y);
+}
+
+Result<void> HostVirtualInputEventSink::SendMouseButtonEvent(int button,
+                                                             bool down) {
+  ConfUiLog(INFO) << "Sending mouse button event: " << button << "," << down;
+  return android_mode_input_->SendMouseButtonEvent(button, down);
+}
+
+Result<void> HostVirtualInputEventSink::SendMouseWheelEvent(int pixels) {
+  ConfUiLog(INFO) << "Sending mouse wheel event: " << pixels;
+  return android_mode_input_->SendMouseWheelEvent(pixels);
+}
+
 Result<void> HostVirtualInputEventSink::SendTouchEvent(
     const std::string& device_label, int x, int y, bool down) {
   if (!host_virtual_input_.IsConfUiActive()) {
diff --git a/host/libs/control_env/Android.bp b/host/libs/control_env/Android.bp
index 5b5264f75..15c5dd82d 100644
--- a/host/libs/control_env/Android.bp
+++ b/host/libs/control_env/Android.bp
@@ -25,9 +25,9 @@ cc_library {
     shared_libs: [
         "libbase",
         "libcuttlefish_utils",
-        "libprotobuf-cpp-full",
         "libgrpc++",
         "libjsoncpp",
+        "libprotobuf-cpp-full",
     ],
     static_libs: [
         "grpc_cli_libs",
diff --git a/host/libs/image_aggregator/Android.bp b/host/libs/image_aggregator/Android.bp
index 11ba0c107..1a65f0947 100644
--- a/host/libs/image_aggregator/Android.bp
+++ b/host/libs/image_aggregator/Android.bp
@@ -45,9 +45,9 @@ cc_library {
     ],
     export_include_dirs: ["."],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libbase",
         "libjsoncpp",
         "libprotobuf-cpp-lite",
         "libz",
diff --git a/host/libs/input_connector/Android.bp b/host/libs/input_connector/Android.bp
index ec7e5b7a7..62f341ac6 100644
--- a/host/libs/input_connector/Android.bp
+++ b/host/libs/input_connector/Android.bp
@@ -20,7 +20,10 @@ package {
 cc_library {
     name: "libcuttlefish_input_connector",
     srcs: [
-        "socket_input_connector.cpp",
+        "event_buffer.cpp",
+        "input_connector.cpp",
+        "input_devices.cpp",
+        "server_input_connection.cpp",
     ],
     shared_libs: [
         "libbase",
diff --git a/host/libs/input_connector/event_buffer.cpp b/host/libs/input_connector/event_buffer.cpp
new file mode 100644
index 000000000..ccc845f1d
--- /dev/null
+++ b/host/libs/input_connector/event_buffer.cpp
@@ -0,0 +1,62 @@
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
+#include "host/libs/input_connector/event_buffer.h"
+
+#include <cstdint>
+#include <cstdlib>
+#include <memory>
+#include <vector>
+
+#include <linux/input.h>
+
+namespace cuttlefish {
+namespace {
+
+struct virtio_input_event {
+  uint16_t type;
+  uint16_t code;
+  int32_t value;
+};
+
+template <typename T>
+struct EventBufferImpl : public EventBuffer {
+  EventBufferImpl(size_t num_events) { buffer_.reserve(num_events); }
+  void AddEvent(uint16_t type, uint16_t code, int32_t value) override {
+    buffer_.push_back({.type = type, .code = code, .value = value});
+  }
+  const void* data() const override { return buffer_.data(); }
+  std::size_t size() const override { return buffer_.size() * sizeof(T); }
+
+ private:
+  std::vector<T> buffer_;
+};
+
+}  // namespace
+
+std::unique_ptr<EventBuffer> CreateBuffer(InputEventType event_type,
+                                          size_t num_events) {
+  switch (event_type) {
+    case InputEventType::Virtio:
+      return std::unique_ptr<EventBuffer>(
+          new EventBufferImpl<virtio_input_event>(num_events));
+    case InputEventType::Evdev:
+      return std::unique_ptr<EventBuffer>(
+          new EventBufferImpl<input_event>(num_events));
+  }
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/event_buffer.h b/host/libs/input_connector/event_buffer.h
new file mode 100644
index 000000000..e027dd6cf
--- /dev/null
+++ b/host/libs/input_connector/event_buffer.h
@@ -0,0 +1,41 @@
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
+#pragma once
+
+#include <cstdint>
+#include <cstdlib>
+
+#include <memory>
+
+namespace cuttlefish {
+enum class InputEventType {
+  Virtio,
+  Evdev,
+};
+
+class EventBuffer {
+ public:
+  virtual ~EventBuffer() = default;
+  virtual void AddEvent(uint16_t type, uint16_t code, int32_t value) = 0;
+  virtual size_t size() const = 0;
+  virtual const void* data() const = 0;
+};
+
+std::unique_ptr<EventBuffer> CreateBuffer(InputEventType event_type,
+                                          size_t num_events);
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connection.h b/host/libs/input_connector/input_connection.h
new file mode 100644
index 000000000..2b573d1ee
--- /dev/null
+++ b/host/libs/input_connector/input_connection.h
@@ -0,0 +1,36 @@
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
+#pragma once
+
+#include <memory>
+
+#include "common/libs/fs/shared_fd.h"
+
+namespace cuttlefish {
+
+class InputConnection {
+ public:
+  virtual ~InputConnection() = default;
+
+  virtual Result<void> WriteEvents(const void* data, size_t len) = 0;
+};
+
+// Create an input device that accepts connection on a socket (TCP or UNIX) and
+// writes input events to its client (typically crosvm).
+std::unique_ptr<InputConnection> NewServerInputConnection(SharedFD server_fd);
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connector.cpp b/host/libs/input_connector/input_connector.cpp
new file mode 100644
index 000000000..fc8d82f9c
--- /dev/null
+++ b/host/libs/input_connector/input_connector.cpp
@@ -0,0 +1,220 @@
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
+#include "host/libs/input_connector/input_connector.h"
+
+#include <memory>
+#include <optional>
+#include <utility>
+#include <vector>
+
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+#include "host/libs/input_connector/event_buffer.h"
+#include "host/libs/input_connector/input_connection.h"
+#include "host/libs/input_connector/input_devices.h"
+
+namespace cuttlefish {
+
+struct InputDevices {
+  // TODO (b/186773052): Finding strings in a map for every input event may
+  // introduce unwanted latency.
+  std::map<std::string, TouchDevice> multitouch_devices;
+  std::map<std::string, TouchDevice> touch_devices;
+
+  std::optional<KeyboardDevice> keyboard;
+  std::optional<SwitchesDevice> switches;
+  std::optional<RotaryDevice> rotary;
+  std::optional<MouseDevice> mouse;
+};
+
+class EventSinkImpl : public InputConnector::EventSink {
+ public:
+  EventSinkImpl(InputDevices&, std::atomic<int>&);
+  ~EventSinkImpl() override;
+
+  Result<void> SendMouseMoveEvent(int x, int y) override;
+  Result<void> SendMouseButtonEvent(int button, bool down) override;
+  Result<void> SendMouseWheelEvent(int pixels) override;
+  Result<void> SendTouchEvent(const std::string& device_label, int x, int y,
+                              bool down) override;
+  Result<void> SendMultiTouchEvent(const std::string& device_label,
+                                   const std::vector<MultitouchSlot>& slots,
+                                   bool down) override;
+  Result<void> SendKeyboardEvent(uint16_t code, bool down) override;
+  Result<void> SendRotaryEvent(int pixels) override;
+  Result<void> SendSwitchesEvent(uint16_t code, bool state) override;
+
+ private:
+  InputDevices& input_devices_;
+  std::atomic<int>& sinks_count_;
+};
+
+EventSinkImpl::EventSinkImpl(InputDevices& devices, std::atomic<int>& count)
+    : input_devices_(devices), sinks_count_(count) {
+  ++sinks_count_;
+}
+
+EventSinkImpl::~EventSinkImpl() {
+  for (auto& it : input_devices_.multitouch_devices) {
+    it.second.OnDisconnectedSource(this);
+  }
+  for (auto& it : input_devices_.touch_devices) {
+    it.second.OnDisconnectedSource(this);
+  }
+  --sinks_count_;
+}
+
+Result<void> EventSinkImpl::SendMouseMoveEvent(int x, int y) {
+  CF_EXPECT(input_devices_.mouse.has_value(), "No mouse device setup");
+  CF_EXPECT(input_devices_.mouse->SendMoveEvent(x, y));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendMouseButtonEvent(int button, bool down) {
+  CF_EXPECT(input_devices_.mouse.has_value(), "No mouse device setup");
+  CF_EXPECT(input_devices_.mouse->SendButtonEvent(button, down));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendMouseWheelEvent(int pixels) {
+  CF_EXPECT(input_devices_.mouse.has_value(), "No mouse device setup");
+  CF_EXPECT(input_devices_.mouse->SendWheelEvent(pixels));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendTouchEvent(const std::string& device_label,
+                                           int x, int y, bool down) {
+  auto ts_it = input_devices_.touch_devices.find(device_label);
+  CF_EXPECT(ts_it != input_devices_.touch_devices.end(),
+            "Unknown touch device: " << device_label);
+  auto& ts = ts_it->second;
+  CF_EXPECT(ts.SendTouchEvent(x, y, down));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendMultiTouchEvent(
+    const std::string& device_label, const std::vector<MultitouchSlot>& slots,
+    bool down) {
+  auto ts_it = input_devices_.multitouch_devices.find(device_label);
+  if (ts_it == input_devices_.multitouch_devices.end()) {
+    for (const auto& slot : slots) {
+      CF_EXPECT(SendTouchEvent(device_label, slot.x, slot.y, down));
+    }
+    return {};
+  }
+  auto& ts = ts_it->second;
+  CF_EXPECT(ts.SendMultiTouchEvent(slots, down));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendKeyboardEvent(uint16_t code, bool down) {
+  CF_EXPECT(input_devices_.keyboard.has_value(), "No keyboard device setup");
+  CF_EXPECT(input_devices_.keyboard->SendEvent(code, down));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendRotaryEvent(int pixels) {
+  CF_EXPECT(input_devices_.rotary.has_value(), "No rotary device setup");
+  CF_EXPECT(input_devices_.rotary->SendEvent(pixels));
+  return {};
+}
+
+Result<void> EventSinkImpl::SendSwitchesEvent(uint16_t code, bool state) {
+  CF_EXPECT(input_devices_.switches.has_value(), "No switches device setup");
+  CF_EXPECT(input_devices_.switches->SendEvent(code, state));
+  return {};
+}
+
+class InputConnectorImpl : public InputConnector {
+ public:
+  InputConnectorImpl() = default;
+  ~InputConnectorImpl();
+
+  std::unique_ptr<EventSink> CreateSink() override;
+
+ private:
+  InputDevices devices_;
+  // Counts the number of events sinks to make sure the class is not destroyed
+  // while any of its sinks still exists.
+  std::atomic<int> sinks_count_ = 0;
+  friend class InputConnectorBuilder;
+};
+
+InputConnectorImpl::~InputConnectorImpl() {
+  CHECK(sinks_count_ == 0) << "Input connector destroyed with " << sinks_count_
+                           << " event sinks left";
+}
+
+std::unique_ptr<InputConnector::EventSink> InputConnectorImpl::CreateSink() {
+  return std::unique_ptr<InputConnector::EventSink>(
+      new EventSinkImpl(devices_, sinks_count_));
+}
+
+InputConnectorBuilder::InputConnectorBuilder(InputEventType type)
+    : connector_(new InputConnectorImpl()), event_type_(type) {}
+
+InputConnectorBuilder::~InputConnectorBuilder() = default;
+
+void InputConnectorBuilder::WithMultitouchDevice(
+    const std::string& device_label, SharedFD server) {
+  CHECK(connector_->devices_.multitouch_devices.find(device_label) ==
+        connector_->devices_.multitouch_devices.end())
+      << "Multiple touch devices with same label: " << device_label;
+  connector_->devices_.multitouch_devices.emplace(
+      std::piecewise_construct, std::forward_as_tuple(device_label),
+      std::forward_as_tuple(NewServerInputConnection(server), event_type_));
+}
+
+void InputConnectorBuilder::WithTouchDevice(const std::string& device_label,
+                                            SharedFD server) {
+  CHECK(connector_->devices_.touch_devices.find(device_label) ==
+        connector_->devices_.touch_devices.end())
+      << "Multiple touch devices with same label: " << device_label;
+  connector_->devices_.touch_devices.emplace(
+      std::piecewise_construct, std::forward_as_tuple(device_label),
+      std::forward_as_tuple(NewServerInputConnection(server), event_type_));
+}
+
+void InputConnectorBuilder::WithKeyboard(SharedFD server) {
+  CHECK(!connector_->devices_.keyboard) << "Keyboard already specified";
+  connector_->devices_.keyboard.emplace(NewServerInputConnection(server),
+                                        event_type_);
+}
+
+void InputConnectorBuilder::WithSwitches(SharedFD server) {
+  CHECK(!connector_->devices_.switches) << "Switches already specified";
+  connector_->devices_.switches.emplace(NewServerInputConnection(server),
+                                        event_type_);
+}
+
+void InputConnectorBuilder::WithRotary(SharedFD server) {
+  CHECK(!connector_->devices_.rotary) << "Rotary already specified";
+  connector_->devices_.rotary.emplace(NewServerInputConnection(server),
+                                      event_type_);
+}
+
+void InputConnectorBuilder::WithMouse(SharedFD server) {
+  CHECK(!connector_->devices_.mouse) << "Mouse already specified";
+  connector_->devices_.mouse.emplace(NewServerInputConnection(server),
+                                     event_type_);
+}
+
+std::unique_ptr<InputConnector> InputConnectorBuilder::Build() && {
+  return std::move(connector_);
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connector.h b/host/libs/input_connector/input_connector.h
index ccd38c85d..02a37e04d 100644
--- a/host/libs/input_connector/input_connector.h
+++ b/host/libs/input_connector/input_connector.h
@@ -19,7 +19,9 @@
 #include <memory>
 #include <vector>
 
+#include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/result.h"
+#include "host/libs/input_connector/event_buffer.h"
 
 namespace cuttlefish {
 
@@ -39,6 +41,9 @@ class InputConnector {
   class EventSink {
    public:
     virtual ~EventSink() = default;
+    virtual Result<void> SendMouseMoveEvent(int x, int y) = 0;
+    virtual Result<void> SendMouseButtonEvent(int button, bool down) = 0;
+    virtual Result<void> SendMouseWheelEvent(int pixels) = 0;
     virtual Result<void> SendTouchEvent(const std::string& display, int x,
                                         int y, bool down) = 0;
     virtual Result<void> SendMultiTouchEvent(
@@ -54,4 +59,29 @@ class InputConnector {
   virtual std::unique_ptr<EventSink> CreateSink() = 0;
 };
 
+class InputConnectorImpl;
+
+class InputConnectorBuilder {
+ public:
+  explicit InputConnectorBuilder(InputEventType type);
+  ~InputConnectorBuilder();
+  InputConnectorBuilder(const InputConnectorBuilder&) = delete;
+  InputConnectorBuilder(InputConnectorBuilder&&) = delete;
+  InputConnectorBuilder& operator=(const InputConnectorBuilder&) = delete;
+
+  void WithMultitouchDevice(const std::string& device_label, SharedFD server);
+  void WithTouchDevice(const std::string& device_label, SharedFD server);
+  void WithKeyboard(SharedFD server);
+  void WithSwitches(SharedFD server);
+  void WithRotary(SharedFD server);
+  void WithMouse(SharedFD server);
+  // This object becomes invalid after calling Build(), the rvalue reference
+  // makes it explicit that it shouldn't be used after.
+  std::unique_ptr<InputConnector> Build() &&;
+
+ private:
+  std::unique_ptr<InputConnectorImpl> connector_;
+  InputEventType event_type_;
+};
+
 }  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_devices.cpp b/host/libs/input_connector/input_devices.cpp
new file mode 100644
index 000000000..4389b7d8a
--- /dev/null
+++ b/host/libs/input_connector/input_devices.cpp
@@ -0,0 +1,191 @@
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
+#include "host/libs/input_connector/input_devices.h"
+
+#include <linux/input.h>
+
+#include "host/libs/input_connector/event_buffer.h"
+
+namespace cuttlefish {
+
+Result<void> TouchDevice::SendTouchEvent(int x, int y, bool down) {
+  auto buffer = CreateBuffer(event_type(), 4);
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  buffer->AddEvent(EV_ABS, ABS_X, x);
+  buffer->AddEvent(EV_ABS, ABS_Y, y);
+  buffer->AddEvent(EV_KEY, BTN_TOUCH, down);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(*buffer));
+  return {};
+}
+
+Result<void> TouchDevice::SendMultiTouchEvent(
+    const std::vector<MultitouchSlot>& slots, bool down) {
+  auto buffer = CreateBuffer(event_type(), 1 + 7 * slots.size());
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+
+  for (auto& f : slots) {
+    auto this_id = f.id;
+    auto this_x = f.x;
+    auto this_y = f.y;
+
+    auto is_new_contact = !HasSlot(this, this_id);
+
+    // Make sure to call HasSlot before this line or it will always return true
+    auto this_slot = GetOrAcquireSlot(this, this_id);
+
+    // BTN_TOUCH DOWN must be the first event in a series
+    if (down && is_new_contact) {
+      buffer->AddEvent(EV_KEY, BTN_TOUCH, 1);
+    }
+
+    buffer->AddEvent(EV_ABS, ABS_MT_SLOT, this_slot);
+    if (down) {
+      if (is_new_contact) {
+        // We already assigned this slot to this source and id combination, we
+        // could use any tracking id for the slot as long as it's greater than 0
+        buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, NewTrackingId());
+      }
+      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_X, this_x);
+      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_Y, this_y);
+    } else {
+      // released touch
+      buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
+      ReleaseSlot(this, this_id);
+      buffer->AddEvent(EV_KEY, BTN_TOUCH, 0);
+    }
+  }
+
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(*buffer));
+  return {};
+}
+
+bool TouchDevice::HasSlot(void* source, int32_t id) {
+  std::lock_guard<std::mutex> lock(slots_mtx_);
+  return slots_by_source_and_id_.find({source, id}) !=
+         slots_by_source_and_id_.end();
+}
+
+int32_t TouchDevice::GetOrAcquireSlot(void* source, int32_t id) {
+  std::lock_guard<std::mutex> lock(slots_mtx_);
+  auto slot_it = slots_by_source_and_id_.find({source, id});
+  if (slot_it != slots_by_source_and_id_.end()) {
+    return slot_it->second;
+  }
+  return slots_by_source_and_id_[std::make_pair(source, id)] = UseNewSlot();
+}
+
+void TouchDevice::ReleaseSlot(void* source, int32_t id) {
+  std::lock_guard<std::mutex> lock(slots_mtx_);
+  auto slot_it = slots_by_source_and_id_.find({source, id});
+  if (slot_it == slots_by_source_and_id_.end()) {
+    return;
+  }
+  active_slots_[slot_it->second] = false;
+  slots_by_source_and_id_.erase(slot_it);
+}
+
+void TouchDevice::OnDisconnectedSource(void* source) {
+  std::lock_guard<std::mutex> lock(slots_mtx_);
+  auto it = slots_by_source_and_id_.begin();
+  while (it != slots_by_source_and_id_.end()) {
+    if (it->first.first == source) {
+      active_slots_[it->second] = false;
+      it = slots_by_source_and_id_.erase(it);
+    } else {
+      ++it;
+    }
+  }
+}
+
+int32_t TouchDevice::UseNewSlot() {
+  // This is not the most efficient implementation for a large number of
+  // slots, but that case should be extremely rare. For the typical number of
+  // slots iterating over a vector is likely faster than using other data
+  // structures.
+  for (auto slot = 0; slot < active_slots_.size(); ++slot) {
+    if (!active_slots_[slot]) {
+      active_slots_[slot] = true;
+      return slot;
+    }
+  }
+  active_slots_.push_back(true);
+  return active_slots_.size() - 1;
+}
+
+Result<void> MouseDevice::SendMoveEvent(int x, int y) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr,
+            "Failed to allocate input events buffer for mouse move event !");
+  buffer->AddEvent(EV_REL, REL_X, x);
+  buffer->AddEvent(EV_REL, REL_Y, y);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+Result<void> MouseDevice::SendButtonEvent(int button, bool down) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr,
+            "Failed to allocate input events buffer for mouse button event !");
+  std::vector<int> buttons = {BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_BACK,
+                              BTN_FORWARD};
+  CF_EXPECT(button < (int)buttons.size(),
+            "Unknown mouse event button: " << button);
+  buffer->AddEvent(EV_KEY, buttons[button], down);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+Result<void> MouseDevice::SendWheelEvent(int pixels) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  buffer->AddEvent(EV_REL, REL_WHEEL, pixels);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+Result<void> KeyboardDevice::SendEvent(uint16_t code, bool down) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  buffer->AddEvent(EV_KEY, code, down);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+Result<void> RotaryDevice::SendEvent(int pixels) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  buffer->AddEvent(EV_REL, REL_WHEEL, pixels);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+Result<void> SwitchesDevice::SendEvent(uint16_t code, bool state) {
+  auto buffer = CreateBuffer(event_type(), 2);
+  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  buffer->AddEvent(EV_SW, code, state);
+  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  return {};
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_devices.h b/host/libs/input_connector/input_devices.h
new file mode 100644
index 000000000..c86bdde4e
--- /dev/null
+++ b/host/libs/input_connector/input_devices.h
@@ -0,0 +1,131 @@
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
+#pragma once
+
+#include <atomic>
+#include <cstdint>
+#include <cstdlib>
+#include <map>
+#include <memory>
+#include <mutex>
+#include <utility>
+#include <vector>
+
+#include "common/libs/utils/result.h"
+#include "host/libs/input_connector/event_buffer.h"
+#include "host/libs/input_connector/input_connection.h"
+#include "host/libs/input_connector/input_connector.h"
+
+namespace cuttlefish {
+
+class InputDevice {
+ public:
+  InputDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
+      : conn_(std::move(conn)), event_type_(event_type) {}
+  virtual ~InputDevice() = default;
+
+ protected:
+  InputConnection& conn() { return *conn_; }
+  InputEventType event_type() const { return event_type_; }
+
+ private:
+  std::unique_ptr<InputConnection> conn_;
+  InputEventType event_type_;
+};
+
+class TouchDevice : public InputDevice {
+ public:
+  TouchDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
+      : InputDevice(std::move(conn), event_type) {}
+
+  Result<void> SendTouchEvent(int x, int y, bool down);
+
+  Result<void> SendMultiTouchEvent(const std::vector<MultitouchSlot>& slots,
+                                   bool down);
+
+  // The InputConnector holds state of on-going touch contacts. Event sources
+  // that can't produce multi touch events should call this function when it's
+  // known they won't produce any more events (because, for example, the
+  // streaming client disconnected) to make sure no stale touch contacts
+  // remain. This addresses issues arising from clients disconnecting in the
+  // middle of a touch action.
+  void OnDisconnectedSource(void* source);
+
+ private:
+  Result<void> WriteEvents(const EventBuffer& buffer) {
+    CF_EXPECT(conn().WriteEvents(buffer.data(), buffer.size()));
+    return {};
+  }
+
+  bool HasSlot(void* source, int32_t id);
+
+  int32_t GetOrAcquireSlot(void* source, int32_t id);
+
+  void ReleaseSlot(void* source, int32_t id);
+
+  size_t NumActiveSlots() {
+    std::lock_guard<std::mutex> lock(slots_mtx_);
+    return slots_by_source_and_id_.size();
+  }
+
+  int NewTrackingId() { return ++tracking_id_; }
+
+  int32_t UseNewSlot();
+
+  std::mutex slots_mtx_;
+  std::map<std::pair<void*, int32_t>, int32_t> slots_by_source_and_id_;
+  std::vector<bool> active_slots_;
+  std::atomic<int> tracking_id_ = 0;
+};
+
+class MouseDevice : public InputDevice {
+ public:
+  MouseDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
+      : InputDevice(std::move(conn), event_type) {}
+
+  Result<void> SendMoveEvent(int x, int y);
+  Result<void> SendButtonEvent(int button, bool down);
+  Result<void> SendWheelEvent(int pixels);
+};
+
+class KeyboardDevice : public InputDevice {
+ public:
+  KeyboardDevice(std::unique_ptr<InputConnection> conn,
+                 InputEventType event_type)
+      : InputDevice(std::move(conn), event_type) {}
+
+  Result<void> SendEvent(uint16_t code, bool down);
+};
+
+class RotaryDevice : public InputDevice {
+ public:
+  RotaryDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
+      : InputDevice(std::move(conn), event_type) {}
+
+  Result<void> SendEvent(int pixels);
+};
+
+class SwitchesDevice : public InputDevice {
+ public:
+  SwitchesDevice(std::unique_ptr<InputConnection> conn,
+                 InputEventType event_type)
+      : InputDevice(std::move(conn), event_type) {}
+
+  Result<void> SendEvent(uint16_t code, bool state);
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/server_input_connection.cpp b/host/libs/input_connector/server_input_connection.cpp
new file mode 100644
index 000000000..c67ee3b2a
--- /dev/null
+++ b/host/libs/input_connector/server_input_connection.cpp
@@ -0,0 +1,81 @@
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
+#include "host/libs/input_connector/input_connection.h"
+
+#include "common/libs/fs/shared_buf.h"
+#include "common/libs/fs/shared_fd.h"
+
+namespace cuttlefish {
+namespace {
+class ServerInputConnection : public InputConnection {
+ public:
+  ServerInputConnection(SharedFD server);
+
+  Result<void> WriteEvents(const void* data, size_t len) override;
+
+ private:
+  SharedFD server_;
+  SharedFD client_;
+  std::mutex client_mtx_;
+  std::thread monitor_;
+
+  void MonitorLoop();
+};
+
+ServerInputConnection::ServerInputConnection(SharedFD server)
+    : server_(server), monitor_(std::thread([this]() { MonitorLoop(); })) {}
+
+void ServerInputConnection::MonitorLoop() {
+  for (;;) {
+    client_ = SharedFD::Accept(*server_);
+    if (!client_->IsOpen()) {
+      LOG(ERROR) << "Failed to accept on input socket: " << client_->StrError();
+      continue;
+    }
+    do {
+      // Keep reading from the fd to detect when it closes.
+      char buf[128];
+      auto res = client_->Read(buf, sizeof(buf));
+      if (res < 0) {
+        LOG(ERROR) << "Failed to read from input client: "
+                   << client_->StrError();
+      } else if (res > 0) {
+        LOG(VERBOSE) << "Received " << res << " bytes on input socket";
+      } else {
+        std::lock_guard<std::mutex> lock(client_mtx_);
+        client_->Close();
+      }
+    } while (client_->IsOpen());
+  }
+}
+
+Result<void> ServerInputConnection::WriteEvents(const void* data, size_t len) {
+  std::lock_guard<std::mutex> lock(client_mtx_);
+  CF_EXPECT(client_->IsOpen(), "No input client connected");
+  auto res = WriteAll(client_, reinterpret_cast<const char*>(data), len);
+  CF_EXPECT(res == len, "Failed to write entire event buffer: wrote "
+                            << res << " of " << len << "bytes");
+  return {};
+}
+
+}  // namespace
+
+std::unique_ptr<InputConnection> NewServerInputConnection(SharedFD server_fd) {
+  return std::unique_ptr<InputConnection>(new ServerInputConnection(server_fd));
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/socket_input_connector.cpp b/host/libs/input_connector/socket_input_connector.cpp
deleted file mode 100644
index bba93cbab..000000000
--- a/host/libs/input_connector/socket_input_connector.cpp
+++ /dev/null
@@ -1,431 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include "host/libs/input_connector/socket_input_connector.h"
-
-#include <linux/input.h>
-
-#include <functional>
-#include <map>
-#include <memory>
-#include <mutex>
-#include <set>
-#include <thread>
-#include <vector>
-
-#include "common/libs/fs/shared_buf.h"
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/result.h"
-#include "host/libs/config/cuttlefish_config.h"
-
-namespace cuttlefish {
-
-namespace {
-
-struct virtio_input_event {
-  uint16_t type;
-  uint16_t code;
-  int32_t value;
-};
-
-struct InputEventsBuffer {
-  virtual ~InputEventsBuffer() = default;
-  virtual void AddEvent(uint16_t type, uint16_t code, int32_t value) = 0;
-  virtual size_t size() const = 0;
-  virtual const void* data() const = 0;
-};
-
-template <typename T>
-struct InputEventsBufferImpl : public InputEventsBuffer {
-  InputEventsBufferImpl(size_t num_events) { buffer_.reserve(num_events); }
-  void AddEvent(uint16_t type, uint16_t code, int32_t value) override {
-    buffer_.push_back({.type = type, .code = code, .value = value});
-  }
-  T* data() { return buffer_.data(); }
-  const void* data() const override { return buffer_.data(); }
-  std::size_t size() const override { return buffer_.size() * sizeof(T); }
-
- private:
-  std::vector<T> buffer_;
-};
-
-std::unique_ptr<InputEventsBuffer> CreateBuffer(InputEventType event_type,
-                                                size_t num_events) {
-  switch (event_type) {
-    case InputEventType::Virtio:
-      return std::unique_ptr<InputEventsBuffer>(
-          new InputEventsBufferImpl<virtio_input_event>(num_events));
-    case InputEventType::Evdev:
-      return std::unique_ptr<InputEventsBuffer>(
-          new InputEventsBufferImpl<input_event>(num_events));
-  }
-}
-
-}  // namespace
-
-class InputSocket {
- public:
-  InputSocket(SharedFD server)
-      : server_(server), monitor_(std::thread([this]() { MonitorLoop(); })) {}
-
-  Result<void> WriteEvents(std::unique_ptr<InputEventsBuffer> buffer);
-
- private:
-  SharedFD server_;
-  SharedFD client_;
-  std::mutex client_mtx_;
-  std::thread monitor_;
-
-  void MonitorLoop();
-};
-
-void InputSocket::MonitorLoop() {
-  for (;;) {
-    client_ = SharedFD::Accept(*server_);
-    if (!client_->IsOpen()) {
-      LOG(ERROR) << "Failed to accept on input socket: " << client_->StrError();
-      continue;
-    }
-    do {
-      // Keep reading from the fd to detect when it closes.
-      char buf[128];
-      auto res = client_->Read(buf, sizeof(buf));
-      if (res < 0) {
-        LOG(ERROR) << "Failed to read from input client: "
-                   << client_->StrError();
-      } else if (res > 0) {
-        LOG(VERBOSE) << "Received " << res << " bytes on input socket";
-      } else {
-        std::lock_guard<std::mutex> lock(client_mtx_);
-        client_->Close();
-      }
-    } while (client_->IsOpen());
-  }
-}
-
-Result<void> InputSocket::WriteEvents(
-    std::unique_ptr<InputEventsBuffer> buffer) {
-  std::lock_guard<std::mutex> lock(client_mtx_);
-  CF_EXPECT(client_->IsOpen(), "No input client connected");
-  auto res = WriteAll(client_, reinterpret_cast<const char*>(buffer->data()),
-                      buffer->size());
-  CF_EXPECT(res == buffer->size(), "Failed to write entire event buffer: wrote "
-                                       << res << " of " << buffer->size()
-                                       << "bytes");
-  return {};
-}
-
-class TouchDevice {
- public:
-  TouchDevice(std::unique_ptr<InputSocket> s) : socket_(std::move(s)) {}
-
-  Result<void> WriteEvents(std::unique_ptr<InputEventsBuffer> buffer) {
-    return socket_->WriteEvents(std::move(buffer));
-  }
-
-  bool HasSlot(void* source, int32_t id) {
-    std::lock_guard<std::mutex> lock(slots_mtx_);
-    return slots_by_source_and_id_.find({source, id}) !=
-           slots_by_source_and_id_.end();
-  }
-
-  int32_t GetOrAcquireSlot(void* source, int32_t id) {
-    std::lock_guard<std::mutex> lock(slots_mtx_);
-    auto slot_it = slots_by_source_and_id_.find({source, id});
-    if (slot_it != slots_by_source_and_id_.end()) {
-      return slot_it->second;
-    }
-    return slots_by_source_and_id_[std::make_pair(source, id)] = UseNewSlot();
-  }
-
-  void ReleaseSlot(void* source, int32_t id) {
-    std::lock_guard<std::mutex> lock(slots_mtx_);
-    auto slot_it = slots_by_source_and_id_.find({source, id});
-    if (slot_it == slots_by_source_and_id_.end()) {
-      return;
-    }
-    slots_by_source_and_id_.erase(slot_it);
-    active_slots_[slot_it->second] = false;
-  }
-
-  size_t NumActiveSlots() {
-    std::lock_guard<std::mutex> lock(slots_mtx_);
-    return slots_by_source_and_id_.size();
-  }
-
-  // The InputConnector holds state of on-going touch contacts. Event sources
-  // that can produce multi touch events should call this function when it's
-  // known they won't produce any more events (because, for example, the
-  // streaming client disconnected) to make sure no stale touch contacts
-  // remain. This addresses issues arising from clients disconnecting in the
-  // middle of a touch action.
-  void OnDisconnectedSource(void* source) {
-    std::lock_guard<std::mutex> lock(slots_mtx_);
-    auto it = slots_by_source_and_id_.begin();
-    while (it != slots_by_source_and_id_.end()) {
-      if (it->first.first == source) {
-        active_slots_[it->second] = false;
-        it = slots_by_source_and_id_.erase(it);
-      } else {
-        ++it;
-      }
-    }
-  }
-
- private:
-  int32_t UseNewSlot() {
-    // This is not the most efficient implementation for a large number of
-    // slots, but that case should be extremely rare. For the typical number of
-    // slots iterating over a vector is likely faster than using other data
-    // structures.
-    for (auto slot = 0; slot < active_slots_.size(); ++slot) {
-      if (!active_slots_[slot]) {
-        active_slots_[slot] = true;
-        return slot;
-      }
-    }
-    active_slots_.push_back(true);
-    return active_slots_.size() - 1;
-  }
-
-  std::unique_ptr<InputSocket> socket_;
-
-  std::mutex slots_mtx_;
-  std::map<std::pair<void*, int32_t>, int32_t> slots_by_source_and_id_;
-  std::vector<bool> active_slots_;
-};
-
-struct InputDevices {
-  InputEventType event_type;
-  // TODO (b/186773052): Finding strings in a map for every input event may
-  // introduce unwanted latency.
-  std::map<std::string, TouchDevice> multitouch_devices;
-  std::map<std::string, TouchDevice> touch_devices;
-
-  std::unique_ptr<InputSocket> keyboard;
-  std::unique_ptr<InputSocket> switches;
-  std::unique_ptr<InputSocket> rotary;
-};
-
-// Implements the InputConnector::EventSink interface using unix socket based
-// virtual input devices.
-class InputSocketsEventSink : public InputConnector::EventSink {
- public:
-  InputSocketsEventSink(InputDevices&, std::atomic<int>&);
-  ~InputSocketsEventSink() override;
-
-  Result<void> SendTouchEvent(const std::string& device_label, int x, int y,
-                              bool down) override;
-  Result<void> SendMultiTouchEvent(const std::string& device_label,
-                                   const std::vector<MultitouchSlot>& slots,
-                                   bool down) override;
-  Result<void> SendKeyboardEvent(uint16_t code, bool down) override;
-  Result<void> SendRotaryEvent(int pixels) override;
-  Result<void> SendSwitchesEvent(uint16_t code, bool state) override;
-
- private:
-  InputDevices& input_devices_;
-  std::atomic<int>& sinks_count_;
-};
-
-InputSocketsEventSink::InputSocketsEventSink(InputDevices& devices,
-                                             std::atomic<int>& count)
-    : input_devices_(devices), sinks_count_(count) {
-  ++sinks_count_;
-}
-
-InputSocketsEventSink::~InputSocketsEventSink() {
-  for (auto& it : input_devices_.multitouch_devices) {
-    it.second.OnDisconnectedSource(this);
-  }
-  for (auto& it : input_devices_.touch_devices) {
-    it.second.OnDisconnectedSource(this);
-  }
-  --sinks_count_;
-}
-
-Result<void> InputSocketsEventSink::SendTouchEvent(
-    const std::string& device_label, int x, int y, bool down) {
-  auto buffer = CreateBuffer(input_devices_.event_type, 4);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_ABS, ABS_X, x);
-  buffer->AddEvent(EV_ABS, ABS_Y, y);
-  buffer->AddEvent(EV_KEY, BTN_TOUCH, down);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  auto ts_it = input_devices_.touch_devices.find(device_label);
-  CF_EXPECT(ts_it != input_devices_.touch_devices.end(),
-            "Unknown touch device: " << device_label);
-  auto& ts = ts_it->second;
-  ts.WriteEvents(std::move(buffer));
-  return {};
-}
-
-Result<void> InputSocketsEventSink::SendMultiTouchEvent(
-    const std::string& device_label, const std::vector<MultitouchSlot>& slots,
-    bool down) {
-  auto buffer = CreateBuffer(input_devices_.event_type, 1 + 7 * slots.size());
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-
-  auto ts_it = input_devices_.multitouch_devices.find(device_label);
-  if (ts_it == input_devices_.multitouch_devices.end()) {
-    for (const auto& slot : slots) {
-      CF_EXPECT(SendTouchEvent(device_label, slot.x, slot.y, down));
-    }
-    return {};
-  }
-  auto& ts = ts_it->second;
-
-  for (auto& f : slots) {
-    auto this_id = f.id;
-    auto this_x = f.x;
-    auto this_y = f.y;
-
-    auto is_new_contact = !ts.HasSlot(this, this_id);
-    auto was_down = ts.NumActiveSlots() > 0;
-
-    // Make sure to call HasSlot before this line or it will always return true
-    auto this_slot = ts.GetOrAcquireSlot(this, this_id);
-
-    // BTN_TOUCH DOWN must be the first event in a series
-    if (down && !was_down) {
-      buffer->AddEvent(EV_KEY, BTN_TOUCH, 1);
-    }
-
-    buffer->AddEvent(EV_ABS, ABS_MT_SLOT, this_slot);
-    if (down) {
-      if (is_new_contact) {
-        // We already assigned this slot to this source and id combination, we
-        // could use any tracking id for the slot as long as it's greater than 0
-        buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, this_id);
-      }
-      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_X, this_x);
-      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_Y, this_y);
-    } else {
-      // released touch
-      buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
-      ts.ReleaseSlot(this, this_id);
-    }
-    // Send BTN_TOUCH UP when no more contacts are detected
-    if (was_down && ts.NumActiveSlots() == 0) {
-      buffer->AddEvent(EV_KEY, BTN_TOUCH, 0);
-    }
-  }
-
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  ts.WriteEvents(std::move(buffer));
-  return {};
-}
-
-Result<void> InputSocketsEventSink::SendKeyboardEvent(uint16_t code,
-                                                      bool down) {
-  CF_EXPECT(input_devices_.keyboard != nullptr, "No keyboard device setup");
-  auto buffer = CreateBuffer(input_devices_.event_type, 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_KEY, code, down);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  input_devices_.keyboard->WriteEvents(std::move(buffer));
-  return {};
-}
-
-Result<void> InputSocketsEventSink::SendRotaryEvent(int pixels) {
-  CF_EXPECT(input_devices_.rotary != nullptr, "No rotary device setup");
-  auto buffer = CreateBuffer(input_devices_.event_type, 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_REL, REL_WHEEL, pixels);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  input_devices_.rotary->WriteEvents(std::move(buffer));
-  return {};
-}
-
-Result<void> InputSocketsEventSink::SendSwitchesEvent(uint16_t code,
-                                                      bool state) {
-  CF_EXPECT(input_devices_.switches != nullptr, "No switches device setup");
-  auto buffer = CreateBuffer(input_devices_.event_type, 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_SW, code, state);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  input_devices_.switches->WriteEvents(std::move(buffer));
-  return {};
-}
-
-class InputSocketsConnector : public InputConnector {
- public:
-  InputSocketsConnector(InputEventType type) : devices_{.event_type = type} {}
-  ~InputSocketsConnector();
-
-  std::unique_ptr<EventSink> CreateSink() override;
-
- private:
-  InputDevices devices_;
-  // Counts the number of events sinks to make sure the class is not destroyed
-  // while any of its sinks still exists.
-  std::atomic<int> sinks_count_ = 0;
-  friend class InputSocketsConnectorBuilder;
-};
-
-InputSocketsConnector::~InputSocketsConnector() {
-  CHECK(sinks_count_ == 0) << "Input connector destroyed with " << sinks_count_
-                           << " event sinks left";
-}
-
-std::unique_ptr<InputConnector::EventSink> InputSocketsConnector::CreateSink() {
-  return std::unique_ptr<InputConnector::EventSink>(
-      new InputSocketsEventSink(devices_, sinks_count_));
-}
-
-InputSocketsConnectorBuilder::InputSocketsConnectorBuilder(InputEventType type)
-    : connector_(new InputSocketsConnector(type)) {}
-
-InputSocketsConnectorBuilder::~InputSocketsConnectorBuilder() = default;
-
-void InputSocketsConnectorBuilder::WithMultitouchDevice(
-    const std::string& device_label, SharedFD server) {
-  CHECK(connector_->devices_.multitouch_devices.find(device_label) ==
-        connector_->devices_.multitouch_devices.end())
-      << "Multiple touch devices with same label: " << device_label;
-  connector_->devices_.multitouch_devices.emplace(
-      device_label, std::make_unique<InputSocket>(server));
-}
-
-void InputSocketsConnectorBuilder::WithTouchDevice(
-    const std::string& device_label, SharedFD server) {
-  CHECK(connector_->devices_.touch_devices.find(device_label) ==
-        connector_->devices_.touch_devices.end())
-      << "Multiple touch devices with same label: " << device_label;
-  connector_->devices_.touch_devices.emplace(device_label,
-                                     std::make_unique<InputSocket>(server));
-}
-
-void InputSocketsConnectorBuilder::WithKeyboard(SharedFD server) {
-  CHECK(!connector_->devices_.keyboard) << "Keyboard already specified";
-  connector_->devices_.keyboard.reset(new InputSocket(server));
-}
-
-void InputSocketsConnectorBuilder::WithSwitches(SharedFD server) {
-  CHECK(!connector_->devices_.switches) << "Switches already specified";
-  connector_->devices_.switches.reset(new InputSocket(server));
-}
-
-void InputSocketsConnectorBuilder::WithRotary(SharedFD server) {
-  CHECK(!connector_->devices_.rotary) << "Rotary already specified";
-  connector_->devices_.rotary.reset(new InputSocket(server));
-}
-
-std::unique_ptr<InputConnector> InputSocketsConnectorBuilder::Build() && {
-  return std::move(connector_);
-}
-
-}  // namespace cuttlefish
diff --git a/host/libs/input_connector/socket_input_connector.h b/host/libs/input_connector/socket_input_connector.h
deleted file mode 100644
index 7f6589b0c..000000000
--- a/host/libs/input_connector/socket_input_connector.h
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#pragma once
-
-#include <memory>
-
-#include "common/libs/fs/shared_fd.h"
-
-#include "host/libs/input_connector/input_connector.h"
-
-namespace cuttlefish{
-
-enum class InputEventType {
-  Virtio,
-  Evdev,
-};
-
-class InputSocketsConnector;
-
-class InputSocketsConnectorBuilder {
- public:
-  InputSocketsConnectorBuilder(InputEventType type);
-  ~InputSocketsConnectorBuilder();
-  InputSocketsConnectorBuilder(const InputSocketsConnectorBuilder&) = delete;
-  InputSocketsConnectorBuilder(InputSocketsConnectorBuilder&&) = delete;
-  InputSocketsConnectorBuilder& operator=(const InputSocketsConnectorBuilder&) = delete;
-
-  void WithMultitouchDevice(const std::string& device_label, SharedFD server);
-  void WithTouchDevice(const std::string& device_label, SharedFD server);
-  void WithKeyboard(SharedFD server);
-  void WithSwitches(SharedFD server);
-  void WithRotary(SharedFD server);
-  // This object becomes invalid after calling Build(), the rvalue reference
-  // makes it explicit that it shouldn't be used after.
-  std::unique_ptr<InputConnector> Build() &&;
-
- private:
-  std::unique_ptr<InputSocketsConnector> connector_;
-};
-
-}
diff --git a/host/libs/location/Android.bp b/host/libs/location/Android.bp
index 96e58b0df..1e7dc9695 100644
--- a/host/libs/location/Android.bp
+++ b/host/libs/location/Android.bp
@@ -20,32 +20,32 @@ package {
 cc_library {
     name: "liblocation",
     srcs: [
-        "StringParse.cpp",
+        "GnssClient.cpp",
         "GpxParser.cpp",
         "KmlParser.cpp",
-        "GnssClient.cpp",
+        "StringParse.cpp",
     ],
     export_include_dirs: ["."],
     shared_libs: [
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
+        "libgrpc++_unsecure",
         "libjsoncpp",
         "liblog",
         "libprotobuf-cpp-full",
-        "libgrpc++_unsecure",
         "libxml2",
     ],
     static_libs: [
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libjsoncpp",
         "libcvd_gnss_grpc_proxy",
+        "libjsoncpp",
     ],
     cflags: [
-        "-Wno-unused-parameter",
         "-D_XOPEN_SOURCE",
+        "-Wno-unused-parameter",
     ],
     defaults: ["cuttlefish_host"],
     include_dirs: [
diff --git a/host/libs/metrics/Android.bp b/host/libs/metrics/Android.bp
index 9a8196d34..19a828bc9 100644
--- a/host/libs/metrics/Android.bp
+++ b/host/libs/metrics/Android.bp
@@ -23,15 +23,15 @@ cc_library {
         "metrics_receiver.cc",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libjsoncpp",
-        "libbase",
         "libfruit",
+        "libjsoncpp",
     ],
     static_libs: [
-        "libcuttlefish_msg_queue",
         "libcuttlefish_host_config",
+        "libcuttlefish_msg_queue",
         "libgflags",
     ],
     target: {
diff --git a/host/libs/msg_queue/Android.bp b/host/libs/msg_queue/Android.bp
index 41ae7a351..aaee6d99d 100644
--- a/host/libs/msg_queue/Android.bp
+++ b/host/libs/msg_queue/Android.bp
@@ -23,9 +23,9 @@ cc_library {
         "msg_queue.cc",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libbase",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/libs/process_monitor/Android.bp b/host/libs/process_monitor/Android.bp
index 3eed2e3e2..0c2534189 100644
--- a/host/libs/process_monitor/Android.bp
+++ b/host/libs/process_monitor/Android.bp
@@ -24,10 +24,10 @@ cc_library {
         "process_monitor_channel.cc",
     ],
     shared_libs: [
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_run_cvd_proto",
         "libcuttlefish_utils",
-        "libbase",
         "libfruit",
         "libjsoncpp",
         "libprotobuf-cpp-full",
diff --git a/host/libs/process_monitor/process_monitor.cc b/host/libs/process_monitor/process_monitor.cc
index c14e60412..b58ca8fac 100644
--- a/host/libs/process_monitor/process_monitor.cc
+++ b/host/libs/process_monitor/process_monitor.cc
@@ -301,41 +301,23 @@ ProcessMonitor::Properties& ProcessMonitor::Properties::RestartSubprocesses(
   return *this;
 }
 
-ProcessMonitor::Properties ProcessMonitor::Properties::RestartSubprocesses(
-    bool r) && {
-  return std::move(RestartSubprocesses(r));
-}
-
 ProcessMonitor::Properties& ProcessMonitor::Properties::AddCommand(
     MonitorCommand cmd) & {
   entries_.emplace_back(std::move(cmd.command), cmd.is_critical);
   return *this;
 }
 
-ProcessMonitor::Properties ProcessMonitor::Properties::AddCommand(
-    MonitorCommand cmd) && {
-  return std::move(AddCommand(std::move(cmd)));
-}
-
 ProcessMonitor::Properties& ProcessMonitor::Properties::StraceCommands(
     std::set<std::string> strace) & {
   strace_commands_ = std::move(strace);
   return *this;
 }
-ProcessMonitor::Properties ProcessMonitor::Properties::StraceCommands(
-    std::set<std::string> strace) && {
-  return std::move(StraceCommands(std::move(strace)));
-}
 
 ProcessMonitor::Properties& ProcessMonitor::Properties::StraceLogDir(
     std::string log_dir) & {
   strace_log_dir_ = std::move(log_dir);
   return *this;
 }
-ProcessMonitor::Properties ProcessMonitor::Properties::StraceLogDir(
-    std::string log_dir) && {
-  return std::move(StraceLogDir(std::move(log_dir)));
-}
 
 ProcessMonitor::ProcessMonitor(ProcessMonitor::Properties&& properties,
                                const SharedFD& secure_env_fd)
diff --git a/host/libs/process_monitor/process_monitor.h b/host/libs/process_monitor/process_monitor.h
index 2f14a150b..0431ad377 100644
--- a/host/libs/process_monitor/process_monitor.h
+++ b/host/libs/process_monitor/process_monitor.h
@@ -45,29 +45,9 @@ class ProcessMonitor {
   class Properties {
    public:
     Properties& RestartSubprocesses(bool) &;
-    Properties RestartSubprocesses(bool) &&;
-
     Properties& AddCommand(MonitorCommand) &;
-    Properties AddCommand(MonitorCommand) &&;
-
     Properties& StraceCommands(std::set<std::string>) &;
-    Properties StraceCommands(std::set<std::string>) &&;
-
     Properties& StraceLogDir(std::string) &;
-    Properties StraceLogDir(std::string) &&;
-
-    template <typename T>
-    Properties& AddCommands(T commands) & {
-      for (auto& command : commands) {
-        AddCommand(std::move(command));
-      }
-      return *this;
-    }
-
-    template <typename T>
-    Properties AddCommands(T commands) && {
-      return std::move(AddCommands(std::move(commands)));
-    }
 
    private:
     bool restart_subprocesses_;
diff --git a/host/libs/screen_connector/Android.bp b/host/libs/screen_connector/Android.bp
index a0c63a6f3..1496033d9 100644
--- a/host/libs/screen_connector/Android.bp
+++ b/host/libs/screen_connector/Android.bp
@@ -23,8 +23,8 @@ cc_library {
         "wayland_screen_connector.cpp",
     ],
     shared_libs: [
-        "libcuttlefish_fs",
         "libbase",
+        "libcuttlefish_fs",
         "libfruit",
         "libjsoncpp",
         "liblog",
@@ -33,11 +33,11 @@ cc_library {
         "libcuttlefish_confui_host_headers",
     ],
     static_libs: [
+        "libcuttlefish_confui",
+        "libcuttlefish_confui_host",
         "libcuttlefish_host_config",
         "libcuttlefish_utils",
-        "libcuttlefish_confui",
         "libcuttlefish_wayland_server",
-        "libcuttlefish_confui_host",
         "libffi",
         "libft2.nodep",
         "libteeui",
diff --git a/host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h b/host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h
new file mode 100644
index 000000000..eec776a87
--- /dev/null
+++ b/host/libs/vhal_proxy_server/vhal_proxy_server_eth_addr.h
@@ -0,0 +1,28 @@
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
+namespace cuttlefish::vhal_proxy_server {
+
+// Host-side VHAL GRPC server ethernet address.
+constexpr std::string_view kEthAddr = "192.168.98.1";
+
+// Host-side VHAL GRPC server default ethernet port, if there are multiple
+// VHAL server instances (by default, a new instance is created for launch_cvd
+// call unless vhal_proxy_server_instance_num is specified to reuse an
+// existing instance), then the port number will be 9300, 9301, etc.
+constexpr int kDefaultEthPort = 9300;
+
+}  // namespace cuttlefish::vhal_proxy_server
\ No newline at end of file
diff --git a/host/libs/vm_manager/Android.bp b/host/libs/vm_manager/Android.bp
index aa6b18e8e..ca6632979 100644
--- a/host/libs/vm_manager/Android.bp
+++ b/host/libs/vm_manager/Android.bp
@@ -21,6 +21,7 @@ cc_library {
     name: "libcuttlefish_vm_manager",
     srcs: [
         "crosvm_builder.cpp",
+        "crosvm_cpu.cpp",
         "crosvm_manager.cpp",
         "gem5_manager.cpp",
         "host_configuration.cpp",
diff --git a/host/libs/vm_manager/crosvm_builder.cpp b/host/libs/vm_manager/crosvm_builder.cpp
index 1a631c285..efb51c682 100644
--- a/host/libs/vm_manager/crosvm_builder.cpp
+++ b/host/libs/vm_manager/crosvm_builder.cpp
@@ -26,6 +26,7 @@
 #include "host/libs/command_util/snapshot_utils.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
+#include "host/libs/vm_manager/crosvm_cpu.h"
 
 namespace cuttlefish {
 namespace {
@@ -70,6 +71,32 @@ void CrosvmBuilder::AddControlSocket(const std::string& control_socket,
   command_.AddParameter("--socket=", control_socket);
 }
 
+Result<void> CrosvmBuilder::AddCpus(size_t cpus,
+                                    const std::string& vcpu_config_path) {
+  if (!vcpu_config_path.empty()) {
+    Json::Value vcpu_config_json = CF_EXPECT(LoadFromFile(vcpu_config_path));
+
+    CF_EXPECT(AddCpus(vcpu_config_json));
+  } else {
+    AddCpus(cpus);
+  }
+  return {};
+}
+
+Result<void> CrosvmBuilder::AddCpus(const Json::Value& vcpu_config_json) {
+  std::vector<std::string> cpu_args =
+      CF_EXPECT(CrosvmCpuArguments(vcpu_config_json));
+
+  for (const std::string& cpu_arg : cpu_args) {
+    command_.AddParameter(cpu_arg);
+  }
+  return {};
+}
+
+void CrosvmBuilder::AddCpus(size_t cpus) {
+  command_.AddParameter("--cpus=", cpus);
+}
+
 // TODO: b/243198718 - switch to virtio-console
 void CrosvmBuilder::AddHvcSink() {
   command_.AddParameter(
diff --git a/host/libs/vm_manager/crosvm_builder.h b/host/libs/vm_manager/crosvm_builder.h
index 4d473b3a6..3e1aef9cf 100644
--- a/host/libs/vm_manager/crosvm_builder.h
+++ b/host/libs/vm_manager/crosvm_builder.h
@@ -18,6 +18,9 @@
 #include <optional>
 #include <string>
 
+#include <json/value.h>
+
+#include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/vm_manager/pci.h"
 
@@ -32,6 +35,10 @@ class CrosvmBuilder {
                              int exit_code);
   void AddControlSocket(const std::string&, const std::string&);
 
+  Result<void> AddCpus(size_t cpus, const std::string& freq_domain_file);
+  Result<void> AddCpus(const Json::Value&);
+  void AddCpus(size_t cpus);
+
   void AddHvcSink();
   void AddHvcReadOnly(const std::string& output, bool console = false);
   void AddHvcReadWrite(const std::string& output, const std::string& input);
diff --git a/host/libs/vm_manager/crosvm_cpu.cpp b/host/libs/vm_manager/crosvm_cpu.cpp
new file mode 100644
index 000000000..8facd5544
--- /dev/null
+++ b/host/libs/vm_manager/crosvm_cpu.cpp
@@ -0,0 +1,123 @@
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
+#include "host/libs/vm_manager/crosvm_cpu.h"
+
+#include <string>
+#include <vector>
+
+#include <android-base/strings.h>
+#include <json/value.h>
+
+#include "common/libs/utils/json.h"
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+namespace {
+
+std::string SerializeFreqDomains(
+    const std::map<std::string, std::vector<int>>& freq_domains) {
+  std::stringstream freq_domain_arg;
+  bool first_vector = true;
+
+  for (const std::pair<std::string, std::vector<int>>& pair : freq_domains) {
+    if (!first_vector) {
+      freq_domain_arg << ",";
+    }
+    first_vector = false;
+
+    freq_domain_arg << "[" << android::base::Join(pair.second, ",") << "]";
+  }
+
+  return {std::format("[{}]", freq_domain_arg.str())};
+}
+
+}  // namespace
+
+Result<std::vector<std::string>> CrosvmCpuArguments(
+    const Json::Value& vcpu_config_json) {
+  std::vector<std::string> cpu_arguments;
+
+  std::map<std::string, std::vector<int>> freq_domains;
+  std::string affinity_arg = "--cpu-affinity=";
+  std::string capacity_arg = "--cpu-capacity=";
+  std::string frequencies_arg = "--cpu-frequencies-khz=";
+  std::string cgroup_path_arg = "--vcpu-cgroup-path=";
+  std::string freq_domain_arg;
+
+  const std::string parent_cgroup_path =
+      CF_EXPECT(GetValue<std::string>(vcpu_config_json, {"cgroup_path"}));
+  cgroup_path_arg += parent_cgroup_path;
+
+  const Json::Value cpus_json =
+      CF_EXPECT(GetValue<Json::Value>(vcpu_config_json, {"cpus"}),
+                "Missing vCPUs config!");
+
+  // Get the number of vCPUs from the number of cpu configurations.
+  auto cpus = cpus_json.size();
+
+  for (size_t i = 0; i < cpus; i++) {
+    if (i != 0) {
+      capacity_arg += ",";
+      affinity_arg += ":";
+      frequencies_arg += ";";
+    }
+
+    std::string cpu_cluster = fmt::format("--cpu-cluster={}", i);
+
+    // Assume that non-contiguous logical CPU ids are malformed.
+    std::string cpu = fmt::format("cpu{}", i);
+    const Json::Value cpu_json = CF_EXPECT(
+        GetValue<Json::Value>(cpus_json, {cpu}), "Missing vCPU config!");
+
+    const std::string affinity =
+        CF_EXPECT(GetValue<std::string>(cpu_json, {"affinity"}));
+    std::string affine_arg = fmt::format("{}={}", i, affinity);
+
+    const std::string freqs =
+        CF_EXPECT(GetValue<std::string>(cpu_json, {"frequencies"}));
+    std::string freq_arg = fmt::format("{}={}", i, freqs);
+
+    const std::string capacity =
+        CF_EXPECT(GetValue<std::string>(cpu_json, {"capacity"}));
+    std::string cap_arg = fmt::format("{}={}", i, capacity);
+
+    const std::string domain =
+        CF_EXPECT(GetValue<std::string>(cpu_json, {"freq_domain"}));
+
+    freq_domains[domain].push_back(i);
+
+    freq_domain_arg = SerializeFreqDomains(freq_domains);
+
+    capacity_arg += cap_arg;
+    affinity_arg += affine_arg;
+    frequencies_arg += freq_arg;
+
+    cpu_arguments.emplace_back(std::move(cpu_cluster));
+  }
+
+  cpu_arguments.emplace_back(std::move(affinity_arg));
+  cpu_arguments.emplace_back(std::move(capacity_arg));
+  cpu_arguments.emplace_back(std::move(frequencies_arg));
+  cpu_arguments.emplace_back(std::move(cgroup_path_arg));
+  cpu_arguments.emplace_back("--virt-cpufreq-upstream");
+
+  cpu_arguments.emplace_back(
+      fmt::format("--cpus={},freq-domains={}", cpus, freq_domain_arg));
+
+  return cpu_arguments;
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/vm_manager/crosvm_cpu.h b/host/libs/vm_manager/crosvm_cpu.h
new file mode 100644
index 000000000..31bdec07b
--- /dev/null
+++ b/host/libs/vm_manager/crosvm_cpu.h
@@ -0,0 +1,29 @@
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
+#pragma once
+
+#include <string>
+#include <vector>
+
+#include <json/value.h>
+
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+Result<std::vector<std::string>> CrosvmCpuArguments(
+    const Json::Value& vcpu_config);
+}
diff --git a/host/libs/vm_manager/crosvm_manager.cpp b/host/libs/vm_manager/crosvm_manager.cpp
index 16ae525c3..7932f16fc 100644
--- a/host/libs/vm_manager/crosvm_manager.cpp
+++ b/host/libs/vm_manager/crosvm_manager.cpp
@@ -22,6 +22,7 @@
 #include <sys/types.h>
 
 #include <cassert>
+#include <map>
 #include <string>
 #include <unordered_map>
 #include <utility>
@@ -71,7 +72,7 @@ CrosvmManager::ConfigureGraphics(
 
   if (instance.gpu_mode() == kGpuModeGuestSwiftshader) {
     bootconfig_args = {
-        {"androidboot.cpuvulkan.version", std::to_string(VK_API_VERSION_1_2)},
+        {"androidboot.cpuvulkan.version", std::to_string(VK_API_VERSION_1_3)},
         {"androidboot.hardware.gralloc", "minigbm"},
         {"androidboot.hardware.hwcomposer", instance.hwcomposer()},
         {"androidboot.hardware.hwcomposer.display_finder_mode", "drm"},
@@ -553,56 +554,11 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
 
   // crosvm_cmd.Cmd().AddParameter("--null-audio");
   crosvm_cmd.Cmd().AddParameter("--mem=", instance.memory_mb());
-  crosvm_cmd.Cmd().AddParameter("--cpus=", instance.cpus());
   if (instance.mte()) {
     crosvm_cmd.Cmd().AddParameter("--mte");
   }
 
-  if (!instance.vcpu_config_path().empty()) {
-    auto vcpu_config_json =
-        CF_EXPECT(LoadFromFile(instance.vcpu_config_path()));
-    std::string affinity_arg = "--cpu-affinity=";
-    std::string capacity_arg = "--cpu-capacity=";
-    std::string frequencies_arg = "--cpu-frequencies-khz=";
-
-    for (int i = 0; i < instance.cpus(); i++) {
-      if (i != 0) {
-        capacity_arg += ",";
-        affinity_arg += ":";
-        frequencies_arg += ";";
-      }
-
-      auto cpu_cluster = fmt::format("--cpu-cluster={}", i);
-
-      auto cpu = fmt::format("cpu{}", i);
-      const auto cpu_json =
-          CF_EXPECT(GetValue<Json::Value>(vcpu_config_json, {cpu}),
-                    "Missing vCPU config!");
-
-      const auto affinity =
-          CF_EXPECT(GetValue<std::string>(cpu_json, {"affinity"}));
-      auto affine_arg = fmt::format("{}={}", i, affinity);
-
-      const auto freqs =
-          CF_EXPECT(GetValue<std::string>(cpu_json, {"frequencies"}));
-      auto freq_arg = fmt::format("{}={}", i, freqs);
-
-      const auto capacity =
-          CF_EXPECT(GetValue<std::string>(cpu_json, {"capacity"}));
-      auto cap_arg = fmt::format("{}={}", i, capacity);
-
-      capacity_arg += cap_arg;
-      affinity_arg += affine_arg;
-      frequencies_arg += freq_arg;
-
-      crosvm_cmd.Cmd().AddParameter(cpu_cluster);
-    }
-
-    crosvm_cmd.Cmd().AddParameter(affinity_arg);
-    crosvm_cmd.Cmd().AddParameter(capacity_arg);
-    crosvm_cmd.Cmd().AddParameter(frequencies_arg);
-    crosvm_cmd.Cmd().AddParameter("--virt-cpufreq");
-  }
+  CF_EXPECT(crosvm_cmd.AddCpus(instance.cpus(), instance.vcpu_config_path()));
 
   auto disk_num = instance.virtual_disk_paths().size();
   CF_EXPECT(VmManager::kMaxDisks >= disk_num,
@@ -665,6 +621,10 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
           ",height=", touchpad_config.height,
           ",name=", kTouchpadDefaultPrefix, i, "]");
     }
+    if (instance.enable_mouse()) {
+      crosvm_cmd.Cmd().AddParameter(
+          "--input=mouse[path=", instance.mouse_socket_path(), "]");
+    }
     crosvm_cmd.Cmd().AddParameter("--input=rotary[path=",
                                   instance.rotary_socket_path(), "]");
     crosvm_cmd.Cmd().AddParameter("--input=keyboard[path=",
diff --git a/host/libs/vm_manager/vm_manager.cpp b/host/libs/vm_manager/vm_manager.cpp
index 7860d3cb2..1b70bdcb9 100644
--- a/host/libs/vm_manager/vm_manager.cpp
+++ b/host/libs/vm_manager/vm_manager.cpp
@@ -86,7 +86,6 @@ class VmmCommands : public CommandSource, public LateInjected {
 
   // SetupFeature
   std::string Name() const override { return "VirtualMachineManager"; }
-  bool Enabled() const override { return true; }
 
   // LateInjected
   Result<void> LateInject(fruit::Injector<>& injector) override {
diff --git a/host/libs/wayland/Android.bp b/host/libs/wayland/Android.bp
index d54fcce9d..74bcb590d 100644
--- a/host/libs/wayland/Android.bp
+++ b/host/libs/wayland/Android.bp
@@ -23,8 +23,8 @@ cc_library {
         "wayland_compositor.cpp",
         "wayland_dmabuf.cpp",
         "wayland_seat.cpp",
-        "wayland_shell.cpp",
         "wayland_server.cpp",
+        "wayland_shell.cpp",
         "wayland_subcompositor.cpp",
         "wayland_surface.cpp",
         "wayland_surfaces.cpp",
@@ -42,8 +42,8 @@ cc_library {
         "libdrm",
         "libffi",
         "libwayland_crosvm_gpu_display_extension_server_protocols",
-        "libwayland_server",
         "libwayland_extension_server_protocols",
+        "libwayland_server",
     ],
     defaults: ["cuttlefish_host"],
 }
diff --git a/host/libs/web/Android.bp b/host/libs/web/Android.bp
index 847b71c80..0118ef440 100644
--- a/host/libs/web/Android.bp
+++ b/host/libs/web/Android.bp
@@ -30,27 +30,27 @@ cc_library {
         host: {
             static_libs: [
                 "libbase",
+                "libcrypto",
+                "libcurl",
                 "libcuttlefish_fs",
                 "libcuttlefish_utils",
-                "libcurl",
-                "libcrypto",
+                "libjsoncpp",
                 "liblog",
                 "libssl",
                 "libz",
-                "libjsoncpp",
             ],
         },
         android: {
             shared_libs: [
                 "libbase",
+                "libcrypto",
+                "libcurl",
                 "libcuttlefish_fs",
                 "libcuttlefish_utils",
-                "libcurl",
-                "libcrypto",
+                "libjsoncpp",
                 "liblog",
                 "libssl",
                 "libz",
-                "libjsoncpp",
             ],
         },
     },
@@ -64,17 +64,17 @@ cc_test_host {
         "http_client/unittest/main_test.cc",
     ],
     static_libs: [
-       "libbase",
-       "libcurl",
-       "libcrypto",
-       "libcuttlefish_fs",
-       "libcuttlefish_utils",
-       "libcuttlefish_web",
-       "libgmock",
-       "libjsoncpp",
-       "liblog",
-       "libssl",
-       "libz",
+        "libbase",
+        "libcrypto",
+        "libcurl",
+        "libcuttlefish_fs",
+        "libcuttlefish_utils",
+        "libcuttlefish_web",
+        "libgmock",
+        "libjsoncpp",
+        "liblog",
+        "libssl",
+        "libz",
     ],
     defaults: ["cuttlefish_host"],
 }
diff --git a/host/libs/websocket/Android.bp b/host/libs/websocket/Android.bp
index 640e37dd1..28418afe5 100644
--- a/host/libs/websocket/Android.bp
+++ b/host/libs/websocket/Android.bp
@@ -25,10 +25,10 @@ cc_library {
     ],
     shared_libs: [
         "libbase",
-        "liblog",
-        "libssl",
         "libcrypto",
         "libcuttlefish_utils",
+        "liblog",
+        "libssl",
     ],
     static_libs: [
         "libcap",
diff --git a/recovery/Android.bp b/recovery/Android.bp
index 4392c4e0a..ebc8e3fca 100644
--- a/recovery/Android.bp
+++ b/recovery/Android.bp
@@ -23,8 +23,8 @@ cc_library {
     owner: "google",
     cflags: [
         "-Wall",
-        "-Wextra",
         "-Werror",
+        "-Wextra",
         "-pedantic",
     ],
     srcs: [
diff --git a/shared/BoardConfig.mk b/shared/BoardConfig.mk
index b9f1bcb36..45d377a6b 100644
--- a/shared/BoardConfig.mk
+++ b/shared/BoardConfig.mk
@@ -29,13 +29,21 @@ TARGET_KERNEL_USE ?= 6.6
 endif
 
 TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
+
+ifneq (, $(filter $(PRODUCT_NAME),cf_x86_64_desktop))
+# TODO: b/357660371 - cf_arm64_desktop should use the desktop kernel, too
+SYSTEM_DLKM_SRC ?= device/google/cuttlefish_prebuilts/kernel/6.6-x86_64-desktop/system_dlkm
+KERNEL_MODULES_PATH ?= device/google/cuttlefish_prebuilts/kernel/6.6-x86_64-desktop/vendor_dlkm
+else
 SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
-TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
 KERNEL_MODULES_PATH ?= \
     kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
+endif
+
+TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
 PRODUCT_COPY_FILES += $(TARGET_KERNEL_PATH):kernel
 
-BOARD_KERNEL_VERSION := $(word 1,$(subst vermagic=,,$(shell egrep -h -ao -m 1 'vermagic=.*' $(KERNEL_MODULES_PATH)/nd_virtio.ko)))
+BOARD_KERNEL_VERSION := $(word 1,$(subst vermagic=,,$(shell grep -E -h -ao -m 1 'vermagic=.*' $(KERNEL_MODULES_PATH)/nd_virtio.ko)))
 
 ifneq (,$(findstring auto, $(PRODUCT_NAME)))
 HIB_SWAP_IMAGE_SIZE_GB ?= 4
@@ -51,42 +59,51 @@ RAMDISK_KERNEL_MODULES ?= \
     failover.ko \
     nd_virtio.ko \
     net_failover.ko \
-    virtio_blk.ko \
-    virtio_console.ko \
     virtio_dma_buf.ko \
     virtio-gpu.ko \
     virtio_input.ko \
     virtio_net.ko \
-    virtio_pci.ko \
     virtio-rng.ko \
-    vmw_vsock_virtio_transport.ko \
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(patsubst %,$(KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
 
-# GKI >5.15 will have and require virtio_pci_legacy_dev.ko
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/virtio_pci_legacy_dev.ko)
-# GKI >5.10 will have and require virtio_pci_modern_dev.ko
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/virtio_pci_modern_dev.ko)
-# GKI >6.4 will have an required vmw_vsock_virtio_transport_common.ko and vsock.ko
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += \
-	$(wildcard $(KERNEL_MODULES_PATH)/vmw_vsock_virtio_transport_common.ko) \
-	$(wildcard $(KERNEL_MODULES_PATH)/vsock.ko)
-
-
 # TODO(b/294888357) once virt_wifi is deprecated we can stop loading mac80211 in
 # first stage init. To minimize scope of modules options to first stage init,
 # mac80211_hwsim.radios=0 has to be specified in the modules options file (which we
 # only read in first stage) and mac80211_hwsim has to be loaded in first stage consequently..
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/libarc4.ko)
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/rfkill.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/cfg80211.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/libarc4.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/mac80211.ko)
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/libarc4.ko)
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/rfkill.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/rfkill.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/cfg80211.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/libarc4.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/mac80211.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/mac80211_hwsim.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/rfkill.ko)
+
+# virtio_blk/console/pci.ko + vmw_vsock_virtio_transport.ko are moved to
+# SYSTEM_DLKM_SRC (from KERNEL_MODULES_PATH), but exist under both paths in
+# some early kernel 6.6 prebuilt drops.
+ifeq ($(TARGET_KERNEL_USE),6.1)
+	SYSTEM_VIRTIO_PREBUILTS_PATH ?= $(KERNEL_MODULES_PATH)
+else
+	SYSTEM_VIRTIO_PREBUILTS_PATH ?= $(SYSTEM_DLKM_SRC)
+endif
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_blk.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_console.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_pci.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/vmw_vsock_virtio_transport.ko
+
+# GKI >5.15 will have and require virtio_pci_legacy_dev.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_pci_legacy_dev.ko)
+# GKI >5.10 will have and require virtio_pci_modern_dev.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_pci_modern_dev.ko)
+# GKI >6.4 will have an required vmw_vsock_virtio_transport_common.ko and vsock.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += \
+	$(wildcard $(SYSTEM_VIRTIO_PREBUILTS_PATH)/vmw_vsock_virtio_transport_common.ko) \
+	$(wildcard $(SYSTEM_VIRTIO_PREBUILTS_PATH)/vsock.ko)
+
 BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES := true
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
@@ -108,8 +125,13 @@ TARGET_NO_BOOTLOADER := $(__TARGET_NO_BOOTLOADER)
 # For now modules are only blocked in second stage init.
 # If a module ever needs to blocked in first stage init - add a new blocklist to
 # BOARD_VENDOR_RAMDISK_KERNEL_MODULES_BLOCKLIST_FILE
+ifeq ($(TARGET_KERNEL_ARCH),arm64)
+BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
+    device/google/cuttlefish/shared/modules_aarch64.blocklist
+else
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/google/cuttlefish/shared/modules.blocklist
+endif
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES_OPTIONS_FILE := \
     device/google/cuttlefish/shared/config/first_stage_modules.options
diff --git a/shared/auto/TEST_MAPPING b/shared/auto/TEST_MAPPING
index d938af55c..6686d0ef9 100644
--- a/shared/auto/TEST_MAPPING
+++ b/shared/auto/TEST_MAPPING
@@ -64,7 +64,82 @@
       "name": "CarServiceTelemetryTest"
     },
     {
-      "name": "CarServiceUnitTest"
+      "name": "CarServiceCarUnitTest"
+    },
+    {
+      "name": "CarServiceWifiUnitTest"
+    },
+    {
+      "name": "CarServiceWatchdogUnitTest"
+    },
+    {
+      "name": "CarServiceVmsUnitTest"
+    },
+    {
+      "name": "CarServiceUtilUnitTest"
+    },
+    {
+      "name": "CarServiceUserUnitTest"
+    },
+    {
+      "name": "CarServiceTelemetryUnitTest"
+    },
+    {
+      "name": "CarServiceSystemUiUnitTest"
+    },
+    {
+      "name": "CarServiceSystemInterfaceUnitTest"
+    },
+    {
+      "name": "CarServiceStorageMonitoringUnitTest"
+    },
+    {
+      "name": "CarServiceStatsUnitTest"
+    },
+    {
+      "name": "CarServiceRemoteAccessUnitTest"
+    },
+    {
+      "name": "CarServicePropertyUnitTest"
+    },
+    {
+      "name": "CarServicePowerUnitTest"
+    },
+    {
+      "name": "CarServicePmUnitTest"
+    },
+    {
+      "name": "CarServiceOsUnitTest"
+    },
+    {
+      "name": "CarServiceOemUnitTest"
+    },
+    {
+      "name": "CarServiceOccupantConnectionUnitTest"
+    },
+    {
+      "name": "CarServiceHalUnitTest"
+    },
+    {
+      "name": "CarServiceGarageModeUnitTest"
+    },
+    {
+      "name": "CarServiceEvsUnitTest"
+    },
+    {
+      "name": "CarServiceClusterUnitTest"
+    },
+    {
+      "name": "CarServiceBluetoothUnitTest"
+    },
+    {
+      "name": "CarServiceAudioUnitTest"
+    },
+    {
+      "name": "CarServiceAmUnitTest"
+    },
+    {
+      "name": "CarServiceAdminUnitTest"
     },
     {
       "name": "CarServiceVmsTest"
diff --git a/shared/auto/auto_ethernet/Android.bp b/shared/auto/auto_ethernet/Android.bp
new file mode 100644
index 000000000..d35641843
--- /dev/null
+++ b/shared/auto/auto_ethernet/Android.bp
@@ -0,0 +1,38 @@
+//
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
+sh_binary {
+    name: "auto_ethernet_setup_script",
+    src: "ethernet.sh",
+    sub_dir: "ethernet",
+    system_ext_specific: true,
+    filename_from_src: true,
+    init_rc: ["ethernet.rc"],
+    visibility: [
+        "//device/google/cuttlefish/shared/auto:__subpackages__",
+    ],
+}
+
+sh_binary {
+    name: "auto_ethernet_config_script",
+    src: "ethernet_auto_eth.sh",
+    sub_dir: "ethernet",
+    system_ext_specific: true,
+    filename_from_src: true,
+    init_rc: ["ethernet.rc"],
+    visibility: [
+        "//device/google/cuttlefish/shared/auto:__subpackages__",
+    ],
+}
diff --git a/shared/auto/auto_ethernet/ethernet.rc b/shared/auto/auto_ethernet/ethernet.rc
new file mode 100644
index 000000000..8666405f3
--- /dev/null
+++ b/shared/auto/auto_ethernet/ethernet.rc
@@ -0,0 +1,37 @@
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
+# Initialize network configuration before init so that routes are configured
+# before services are started
+
+on post-fs
+    exec_start auto-ethernet-setup
+    exec_start auto-ethernet-namespace-setup
+    setprop android.car.auto_eth_namespace_setup_complete 1
+
+# Set up the main ethernet ip address and routing
+# Create network namespace auto_eth
+service auto-ethernet-setup /system_ext/bin/ethernet/ethernet.sh
+    class core
+    user root
+    group shell
+    oneshot
+
+# Set up routing rule for network namespace auto_eth
+service auto-ethernet-namespace-setup /system_ext/bin/ethernet/ethernet_auto_eth.sh
+    enter_namespace net /mnt/run/auto_eth
+    class core
+    user root
+    group shell
+    oneshot
\ No newline at end of file
diff --git a/shared/auto/auto_ethernet/ethernet.sh b/shared/auto/auto_ethernet/ethernet.sh
new file mode 100644
index 000000000..13fe403ed
--- /dev/null
+++ b/shared/auto/auto_ethernet/ethernet.sh
@@ -0,0 +1,22 @@
+#!/system/bin/sh
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
+# Create a namespace specifically for auto ethernet usage.
+ip netns add auto_eth
+
+# Move network interface eth1 to network namespace auto_eth
+# Once moved, we no longer be able to see the network interface eth1 here
+# without entering auto_eth network namespace
+ip link set eth1 netns auto_eth
\ No newline at end of file
diff --git a/shared/auto/auto_ethernet/ethernet_auto_eth.sh b/shared/auto/auto_ethernet/ethernet_auto_eth.sh
new file mode 100644
index 000000000..83a9f319b
--- /dev/null
+++ b/shared/auto/auto_ethernet/ethernet_auto_eth.sh
@@ -0,0 +1,26 @@
+#!/system/bin/sh
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
+# Set IP address for eth1 that corresponds to virtual ethernet in Cuttlefish.
+# Default to 192.168.98.3
+IP=$(getprop ro.boot.auto_eth_guest_addr "192.168.98.3")
+
+echo Setting IP address for eth1: $IP > /dev/kmsg
+
+ifconfig eth1 "$IP"
+ip route add 192.168.98.0/24 dev eth1
+
+## This allow loopback support
+ip link set dev lo up
\ No newline at end of file
diff --git a/shared/auto/device_vendor.mk b/shared/auto/device_vendor.mk
index 2cd311fe7..faff823a5 100644
--- a/shared/auto/device_vendor.mk
+++ b/shared/auto/device_vendor.mk
@@ -31,7 +31,10 @@ $(call inherit-product, device/google/cuttlefish/shared/device.mk)
 
 # Extend cuttlefish common sepolicy with auto-specific functionality
 BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy \
-                       device/google/cuttlefish/shared/auto/sepolicy/vendor
+                       device/google/cuttlefish/shared/auto/sepolicy/vendor \
+
+SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/system_ext/private
+SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/system_ext/public
 
 ################################################
 # Begin general Android Auto Embedded configurations
@@ -94,6 +97,13 @@ ifeq ($(LOCAL_VHAL_PRODUCT_PACKAGE),)
 endif
 PRODUCT_PACKAGES += $(LOCAL_VHAL_PRODUCT_PACKAGE)
 
+# Ethernet setup script for vehicle HAL
+ENABLE_AUTO_ETHERNET ?= true
+ifeq ($(ENABLE_AUTO_ETHERNET), true)
+    PRODUCT_PACKAGES += auto_ethernet_setup_script
+    PRODUCT_PACKAGES += auto_ethernet_config_script
+endif
+
 # Remote access HAL
 PRODUCT_PACKAGES += android.hardware.automotive.remoteaccess@V2-default-service
 
diff --git a/shared/auto/rro_overlay/CarServiceOverlay/Android.bp b/shared/auto/rro_overlay/CarServiceOverlay/Android.bp
index 305e983b6..95422c558 100644
--- a/shared/auto/rro_overlay/CarServiceOverlay/Android.bp
+++ b/shared/auto/rro_overlay/CarServiceOverlay/Android.bp
@@ -23,7 +23,7 @@ runtime_resource_overlay {
     resource_dirs: ["res"],
     manifest: "AndroidManifest.xml",
     sdk_version: "current",
-    product_specific: true
+    product_specific: true,
 }
 
 override_runtime_resource_overlay {
@@ -32,4 +32,3 @@ override_runtime_resource_overlay {
     package_name: "com.google.android.car.resources.cuttlefish",
     target_package_name: "com.google.android.car.updatable",
 }
-
diff --git a/shared/auto/rro_overlay/ConnectivityOverlay/Android.bp b/shared/auto/rro_overlay/ConnectivityOverlay/Android.bp
index 218d4438b..63dee024f 100644
--- a/shared/auto/rro_overlay/ConnectivityOverlay/Android.bp
+++ b/shared/auto/rro_overlay/ConnectivityOverlay/Android.bp
@@ -23,7 +23,7 @@ runtime_resource_overlay {
     resource_dirs: ["res"],
     manifest: "AndroidManifest.xml",
     sdk_version: "current",
-    product_specific: true
+    product_specific: true,
 }
 
 override_runtime_resource_overlay {
@@ -32,4 +32,3 @@ override_runtime_resource_overlay {
     package_name: "com.google.android.connectivity.resources.cuttlefish",
     target_package_name: "com.google.android.connectivity.resources",
 }
-
diff --git a/shared/auto/rro_overlay/ConnectivityOverlay/res/values/config.xml b/shared/auto/rro_overlay/ConnectivityOverlay/res/values/config.xml
index 7033e83dc..01f56c0a7 100644
--- a/shared/auto/rro_overlay/ConnectivityOverlay/res/values/config.xml
+++ b/shared/auto/rro_overlay/ConnectivityOverlay/res/values/config.xml
@@ -26,7 +26,6 @@
     <string-array translatable="false" name="config_ethernet_interfaces">
         <!-- Not metered, trusted, not vpn, vehicle, not vcn managed, restricted -->
         <item>macsec0;11,14,15,27,28;</item>
-        <item>eth1;11,14,15,27,28;</item>
     </string-array>
     <string translatable="false" name="config_ethernet_iface_regex">(eth|macsec)\\d+</string>
 </resources>
diff --git a/shared/auto/sepolicy/system_ext/private/ethernet.te b/shared/auto/sepolicy/system_ext/private/ethernet.te
new file mode 100644
index 000000000..73fb3e475
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/ethernet.te
@@ -0,0 +1,40 @@
+type auto_ethernet_setup, domain;
+typeattribute auto_ethernet_setup coredomain;
+type auto_ethernet_setup_exec, exec_type, system_file_type, file_type;
+
+init_daemon_domain(auto_ethernet_setup)
+
+# Required for `#!/system/bin/sh`
+allow auto_ethernet_setup shell_exec:file rx_file_perms;
+
+# Required for `getprop`
+allow auto_ethernet_setup toolbox_exec:file { execute execute_no_trans getattr map open read };
+get_prop(auto_ethernet_setup, auto_eth_guest_addr_prop)
+
+# Required for logging to /dev/kmsg
+allow auto_ethernet_setup kmsg_device:chr_file w_file_perms;
+
+# Required for `ifconfig eth1 $IP`
+allow auto_ethernet_setup self:capability { net_admin sys_module };
+allow auto_ethernet_setup self:udp_socket create;
+# Allow the application to do ioctl() syscalls on the udp_socket.
+allow auto_ethernet_setup self:udp_socket ioctl;
+# Allow the application to do privileged ioctls on the udp_socket, such as `SIOCSIFADDR`, which is
+# for setting an IP address of an interface.
+# WARNING: `allowxperm` alone will not grant the access: it must be used in combination with
+# `allow`. See `allow auto_ethernet_setup self:udp_socket ioctl` above.
+allowxperm auto_ethernet_setup self:udp_socket ioctl priv_sock_ioctls;
+
+# Required for executing `ip`.
+allow auto_ethernet_setup system_file:file execute_no_trans;
+
+# Required for `ip route` operations.
+allow auto_ethernet_setup self:netlink_route_socket { bind create getattr nlmsg_write read setopt write };
+
+# Required for `ip netns` and move ethernet interface into a particular network namespace operations.
+allow auto_ethernet_setup self:netlink_route_socket nlmsg_read;
+allow auto_ethernet_setup tmpfs:dir { add_name create mounton write };
+allow auto_ethernet_setup tmpfs:file { create mounton open read };
+allow auto_ethernet_setup nsfs:file { open read };
+allow auto_ethernet_setup proc_filesystems:file { getattr open read };
+allow auto_ethernet_setup self:capability sys_admin;
\ No newline at end of file
diff --git a/shared/auto/sepolicy/system_ext/private/file.te b/shared/auto/sepolicy/system_ext/private/file.te
new file mode 100644
index 000000000..fe8f6fc78
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/file.te
@@ -0,0 +1 @@
+type nsfs, fs_type;
\ No newline at end of file
diff --git a/shared/auto/sepolicy/system_ext/private/file_contexts b/shared/auto/sepolicy/system_ext/private/file_contexts
new file mode 100644
index 000000000..5cda12453
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/file_contexts
@@ -0,0 +1,2 @@
+# The ethernet setup script.
+/(system_ext|system/system_ext)/bin/ethernet/ethernet(.*)\.sh        u:object_r:auto_ethernet_setup_exec:s0
\ No newline at end of file
diff --git a/shared/auto/sepolicy/system_ext/private/genfs_contexts b/shared/auto/sepolicy/system_ext/private/genfs_contexts
new file mode 100644
index 000000000..e79c63074
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/genfs_contexts
@@ -0,0 +1,2 @@
+# /proc/<pid>/ns
+genfscon nsfs / u:object_r:nsfs:s0
\ No newline at end of file
diff --git a/shared/auto/sepolicy/system_ext/private/property.te b/shared/auto/sepolicy/system_ext/private/property.te
new file mode 100644
index 000000000..d86838e8a
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/property.te
@@ -0,0 +1 @@
+system_internal_prop(auto_eth_guest_addr_prop)
diff --git a/shared/auto/sepolicy/system_ext/private/property_contexts b/shared/auto/sepolicy/system_ext/private/property_contexts
new file mode 100644
index 000000000..4dfd4ea86
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/private/property_contexts
@@ -0,0 +1,2 @@
+ro.boot.auto_eth_guest_addr  u:object_r:auto_eth_guest_addr_prop:s0
+android.car.auto_eth_namespace_setup_complete  u:object_r:auto_eth_namespace_setup_complete_prop:s0 exact bool
\ No newline at end of file
diff --git a/shared/auto/sepolicy/system_ext/public/property.te b/shared/auto/sepolicy/system_ext/public/property.te
new file mode 100644
index 000000000..dc8e3c2ff
--- /dev/null
+++ b/shared/auto/sepolicy/system_ext/public/property.te
@@ -0,0 +1,2 @@
+# Need to be read by vendor domain and vendor_init
+system_restricted_prop(auto_eth_namespace_setup_complete_prop)
diff --git a/shared/auto/sepolicy/vendor/hal_vehicle_default.te b/shared/auto/sepolicy/vendor/hal_vehicle_default.te
index 96c447aee..973ca221e 100644
--- a/shared/auto/sepolicy/vendor/hal_vehicle_default.te
+++ b/shared/auto/sepolicy/vendor/hal_vehicle_default.te
@@ -3,3 +3,6 @@ typeattribute hal_vehicle_default hal_automotive_socket_exemption;
 
 net_domain(hal_vehicle_default)
 get_prop(hal_vehicle_default, vendor_vhal_proxy_server_port_prop)
+get_prop(hal_vehicle_default, auto_eth_namespace_setup_complete_prop)
+# Required for set ctl.oneshot_off
+set_prop(hal_vehicle_default, ctl_default_prop)
diff --git a/shared/auto/sepolicy/vendor/vendor_init.te b/shared/auto/sepolicy/vendor/vendor_init.te
new file mode 100644
index 000000000..5911ecd15
--- /dev/null
+++ b/shared/auto/sepolicy/vendor/vendor_init.te
@@ -0,0 +1 @@
+get_prop(vendor_init, auto_eth_namespace_setup_complete_prop)
diff --git a/shared/auto_portrait/config_auto_portrait.json b/shared/auto_portrait/config_auto_portrait.json
index a322dc407..27835135a 100644
--- a/shared/auto_portrait/config_auto_portrait.json
+++ b/shared/auto_portrait/config_auto_portrait.json
@@ -1,5 +1,5 @@
 {
-	"display0": "width=1224,height=2175,dpi=140",
+	"display0": "width=1080,height=1920,dpi=140",
 	"memory_mb" : 4096,
 	"enable_vhal_proxy_server": true
 }
diff --git a/shared/config/Android.bp b/shared/config/Android.bp
index 877b37a13..6dd17b0c3 100644
--- a/shared/config/Android.bp
+++ b/shared/config/Android.bp
@@ -50,7 +50,10 @@ genrule {
     name: "gen_fstab_cf_f2fs_hctr2",
     srcs: ["fstab.in"],
     out: ["fstab.cf.f2fs.hctr2"],
-    tool_files: [ "sed.f2fs", "sed.hctr2" ],
+    tool_files: [
+        "sed.f2fs",
+        "sed.hctr2",
+    ],
     cmd: "sed -f $(location sed.f2fs) -f $(location sed.hctr2) $(in) > $(out)",
 }
 
@@ -58,7 +61,10 @@ genrule {
     name: "gen_fstab_cf_f2fs_cts",
     srcs: ["fstab.in"],
     out: ["fstab.cf.f2fs.cts"],
-    tool_files: [ "sed.f2fs", "sed.cts" ],
+    tool_files: [
+        "sed.cts",
+        "sed.f2fs",
+    ],
     cmd: "sed -f $(location sed.f2fs) -f $(location sed.cts) $(in) > $(out)",
 }
 
@@ -66,7 +72,10 @@ genrule {
     name: "gen_fstab_cf_ext4_hctr2",
     srcs: ["fstab.in"],
     out: ["fstab.cf.ext4.hctr2"],
-    tool_files: [ "sed.ext4", "sed.hctr2" ],
+    tool_files: [
+        "sed.ext4",
+        "sed.hctr2",
+    ],
     cmd: "sed -f $(location sed.ext4) -f $(location sed.hctr2) $(in) > $(out)",
 }
 
@@ -74,7 +83,10 @@ genrule {
     name: "gen_fstab_cf_ext4_cts",
     srcs: ["fstab.in"],
     out: ["fstab.cf.ext4.cts"],
-    tool_files: [ "sed.ext4", "sed.cts" ],
+    tool_files: [
+        "sed.cts",
+        "sed.ext4",
+    ],
     cmd: "sed -f $(location sed.ext4) -f $(location sed.cts) $(in) > $(out)",
 }
 
@@ -82,26 +94,66 @@ prebuilt_etc {
     name: "fstab.cf.f2fs.hctr2",
     src: ":gen_fstab_cf_f2fs_hctr2",
     vendor: true,
-    vendor_ramdisk_available: true,
+}
+
+prebuilt_etc {
+    name: "fstab.cf.f2fs.hctr2.vendor_ramdisk",
+    srcs: [
+        ":gen_fstab_cf_f2fs_hctr2",
+    ],
+    dsts: [
+        "fstab.cf.f2fs.hctr2",
+    ],
+    vendor_ramdisk: true,
 }
 
 prebuilt_etc {
     name: "fstab.cf.f2fs.cts",
     src: ":gen_fstab_cf_f2fs_cts",
     vendor: true,
-    vendor_ramdisk_available: true,
+}
+
+prebuilt_etc {
+    name: "fstab.cf.f2fs.cts.vendor_ramdisk",
+    srcs: [
+        ":gen_fstab_cf_f2fs_cts",
+    ],
+    dsts: [
+        "fstab.cf.f2fs.cts",
+    ],
+    vendor_ramdisk: true,
 }
 
 prebuilt_etc {
     name: "fstab.cf.ext4.hctr2",
     src: ":gen_fstab_cf_ext4_hctr2",
     vendor: true,
-    vendor_ramdisk_available: true,
+}
+
+prebuilt_etc {
+    name: "fstab.cf.ext4.hctr2.vendor_ramdisk",
+    srcs: [
+        ":gen_fstab_cf_ext4_hctr2",
+    ],
+    dsts: [
+        "fstab.cf.ext4.hctr2",
+    ],
+    vendor_ramdisk: true,
 }
 
 prebuilt_etc {
     name: "fstab.cf.ext4.cts",
     src: ":gen_fstab_cf_ext4_cts",
     vendor: true,
-    vendor_ramdisk_available: true,
+}
+
+prebuilt_etc {
+    name: "fstab.cf.ext4.cts.vendor_ramdisk",
+    srcs: [
+        ":gen_fstab_cf_ext4_cts",
+    ],
+    dsts: [
+        "fstab.cf.ext4.cts",
+    ],
+    vendor_ramdisk: true,
 }
diff --git a/shared/config/init.vendor.rc b/shared/config/init.vendor.rc
index 4c2fbad84..e0b09104d 100644
--- a/shared/config/init.vendor.rc
+++ b/shared/config/init.vendor.rc
@@ -12,9 +12,10 @@ on early-init
 
 on early-init && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
 com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure
-    # Enable Trusty VM and KeyMint VM
-    setprop ro.hardware.security.trusty_vm.system 1
-    setprop ro.hardware.security.keymint.trusty.system 1
+    # Enable the Trusty Security VM
+    setprop trusty.security_vm.enabled 1
+    # Enable KeyMint that connects to the Trusty Security VM
+    setprop trusty.security_vm.keymint.enabled 1
 
 on init
     # ZRAM setup
diff --git a/shared/desktop/OWNERS b/shared/desktop/OWNERS
new file mode 100644
index 000000000..275fd603a
--- /dev/null
+++ b/shared/desktop/OWNERS
@@ -0,0 +1,3 @@
+shaochuan@google.com
+ruki@google.com
+oribe@google.com
diff --git a/shared/desktop/device_vendor.mk b/shared/desktop/device_vendor.mk
new file mode 100644
index 000000000..1674846f7
--- /dev/null
+++ b/shared/desktop/device_vendor.mk
@@ -0,0 +1,35 @@
+#
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
+#
+
+PRODUCT_MANIFEST_FILES += device/google/cuttlefish/shared/config/product_manifest.xml
+SYSTEM_EXT_MANIFEST_FILES += device/google/cuttlefish/shared/config/system_ext_manifest.xml
+
+$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
+
+$(call inherit-product, frameworks/native/build/tablet-7in-xhdpi-2048-dalvik-heap.mk)
+$(call inherit-product, device/google/cuttlefish/shared/bluetooth/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/gnss/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/graphics/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/reboot_escrow/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/secure_element/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/swiftshader/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/sensors/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/virgl/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/device.mk)
+
+# Loads the camera HAL and which set of cameras is required.
+$(call inherit-product, device/google/cuttlefish/shared/camera/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/camera/config/standard.mk)
diff --git a/shared/device.mk b/shared/device.mk
index f9107ffc6..693a675ce 100644
--- a/shared/device.mk
+++ b/shared/device.mk
@@ -421,7 +421,15 @@ ifeq ($(RELEASE_AVF_ENABLE_EARLY_VM),true)
 endif
 ifeq ($(TRUSTY_SYSTEM_VM),nonsecure)
     $(call inherit-product, system/core/trusty/keymint/trusty-keymint.mk)
-    PRODUCT_PACKAGES += lk_trusty.elf trusty_vm_launcher cf-early_vms.xml
+    $(call inherit-product, system/core/trusty/trusty-storage-cf.mk)
+    PRODUCT_PACKAGES += \
+        lk_trusty.elf \
+        trusty_security_vm_launcher \
+        early_vms.xml \
+        cf-trusty_security_vm_launcher.rc \
+        lk_trusty.elf \
+        trusty-ut-ctrl.system \
+
 endif
 
 #
diff --git a/shared/foldable/device_state_configuration.xml b/shared/foldable/device_state_configuration.xml
index 88f443fee..f6377c66a 100644
--- a/shared/foldable/device_state_configuration.xml
+++ b/shared/foldable/device_state_configuration.xml
@@ -1,4 +1,5 @@
 <device-state-config>
+
   <device-state>
     <identifier>0</identifier>
     <name>CLOSED</name>
@@ -14,6 +15,7 @@
       </lid-switch>
     </conditions>
   </device-state>
+
   <device-state>
     <identifier>1</identifier>
     <name>HALF_OPENED</name>
@@ -36,6 +38,7 @@
       </sensor>
     </conditions>
   </device-state>
+
   <device-state>
     <identifier>2</identifier>
     <name>OPENED</name>
@@ -50,6 +53,7 @@
       </lid-switch>
     </conditions>
   </device-state>
+
   <device-state>
     <identifier>3</identifier>
     <name>REAR_DISPLAY_MODE</name>
@@ -60,4 +64,17 @@
       <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY</property>
     </properties>
   </device-state>
+
+  <device-state>
+    <identifier>5</identifier>
+    <name>REAR_DISPLAY_OUTER_DEFAULT</name>
+    <properties>
+      <property>com.android.server.policy.PROPERTY_EMULATED_ONLY</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+      <property>com.android.server.policy.PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
+      <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY</property>
+      <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY_OUTER_DEFAULT</property>
+    </properties>
+  </device-state>
+
 </device-state-config>
diff --git a/shared/graphics/device_vendor.mk b/shared/graphics/device_vendor.mk
index d13904d93..6f2052abd 100644
--- a/shared/graphics/device_vendor.mk
+++ b/shared/graphics/device_vendor.mk
@@ -51,11 +51,20 @@ endif
 # Hardware Composer HAL
 #
 PRODUCT_PACKAGES += \
-    com.android.hardware.graphics.composer.ranchu
+    com.android.hardware.graphics.composer.drm_hwcomposer \
+    com.android.hardware.graphics.composer.ranchu \
 
 PRODUCT_VENDOR_PROPERTIES += \
     ro.vendor.hwcomposer.pmem=/dev/block/pmem1
 
+# drm_hwcomposer configuration
+# The virtio gpu module sends frames to the host as fast as possible and
+# does not emulate "real display timing".
+PRODUCT_VENDOR_PROPERTIES += ro.vendor.hwc.drm.present_fence_not_reliable=true
+
+PRODUCT_SYSTEM_PROPERTIES += \
+    service.sf.prime_shader_cache=0
+
 # Gralloc implementation
 $(call soong_config_set,cvd,RELEASE_SM_OPEN_DECLARED_PASSTHROUGH_HAL,$(RELEASE_SM_OPEN_DECLARED_PASSTHROUGH_HAL))
 PRODUCT_PACKAGES += com.google.cf.gralloc
diff --git a/shared/minidroid/BoardConfig.mk b/shared/minidroid/BoardConfig.mk
index 3aff9a020..6af12fae4 100644
--- a/shared/minidroid/BoardConfig.mk
+++ b/shared/minidroid/BoardConfig.mk
@@ -23,19 +23,16 @@ KERNEL_MODULES_PATH ?= \
     kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
 PRODUCT_COPY_FILES += $(TARGET_KERNEL_PATH):kernel
 
+SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
+
 # The list of modules strictly/only required either to reach second stage
 # init, OR for recovery. Do not use this list to workaround second stage
 # issues.
 RAMDISK_KERNEL_MODULES := \
     failover.ko \
     net_failover.ko \
-    virtio_blk.ko \
-    virtio_console.ko \
     virtio_net.ko \
-    virtio_pci.ko \
-    virtio_pci_modern_dev.ko \
     virtio-rng.ko \
-    vmw_vsock_virtio_transport.ko \
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(patsubst %,$(KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
@@ -47,6 +44,12 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES += \
 	$(wildcard $(KERNEL_MODULES_PATH)/vmw_vsock_virtio_transport_common.ko) \
 	$(wildcard $(KERNEL_MODULES_PATH)/vsock.ko)
 
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_DLKM_SRC)/virtio_blk.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_DLKM_SRC)/virtio_console.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_DLKM_SRC)/virtio_pci.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_DLKM_SRC)/virtio_pci_modern_dev.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_DLKM_SRC)/vmw_vsock_virtio_transport.ko
+
 TARGET_NO_RECOVERY := true
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES_BLOCKLIST_FILE := \
@@ -141,8 +144,8 @@ BOARD_GOOGLE_SYSTEM_DYNAMIC_PARTITIONS_PARTITION_LIST := system vendor
 # reserve 256MiB for dynamic partition metadata
 BOARD_GOOGLE_SYSTEM_DYNAMIC_PARTITIONS_SIZE := 268435456
 
-# 1MiB bigger than the dynamic partition to make build happy...
-BOARD_SUPER_PARTITION_SIZE := 269484032
+# 1MiB bigger than twice the dynamic partition to make build happy...
+BOARD_SUPER_PARTITION_SIZE := 537919488
 BOARD_SUPER_PARTITION_GROUPS := google_system_dynamic_partitions
 BOARD_BUILD_SUPER_IMAGE_BY_DEFAULT := true
 BOARD_SUPER_IMAGE_IN_UPDATE_PACKAGE := true
diff --git a/shared/minidroid/device.mk b/shared/minidroid/device.mk
index 086285f0c..f7d0f2a9f 100644
--- a/shared/minidroid/device.mk
+++ b/shared/minidroid/device.mk
@@ -118,11 +118,13 @@ PRODUCT_PACKAGES += \
 
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/minidroid/init.rc:system/etc/init/hw/init.minidroid.rc \
-    packages/modules/Virtualization/microdroid/ueventd.rc:vendor/etc/ueventd.rc \
+    packages/modules/Virtualization/build/microdroid/ueventd.rc:vendor/etc/ueventd.rc \
     device/google/cuttlefish/shared/config/seriallogging.rc:vendor/etc/init/seriallogging.rc \
 
 DEVICE_MANIFEST_FILE := \
     device/google/cuttlefish/shared/minidroid/minidroid_vendor_manifest.xml
-PRODUCT_PACKAGES += vendor_compatibility_matrix.xml
+PRODUCT_PACKAGES += \
+    vendor_compatibility_matrix.xml \
+    vendor_manifest.xml \
 
 TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/shared/minidroid/android-info.txt
diff --git a/shared/minidroid/sample/Android.bp b/shared/minidroid/sample/Android.bp
index d360dd636..0cc278951 100644
--- a/shared/minidroid/sample/Android.bp
+++ b/shared/minidroid/sample/Android.bp
@@ -12,8 +12,8 @@ cc_binary {
     srcs: ["server.cpp"],
     shared_libs: [
         "libbinder_ndk",
-        "minidroid_sd",
         "liblog",
+        "minidroid_sd",
     ],
     static_libs: [
         "com.android.minidroid.testservice-ndk",
@@ -29,8 +29,8 @@ cc_binary {
     srcs: ["client.cpp"],
     shared_libs: [
         "libbinder_ndk",
-        "minidroid_sd",
         "liblog",
+        "minidroid_sd",
     ],
     static_libs: [
         "com.android.minidroid.testservice-ndk",
diff --git a/shared/minidroid/sample/aidl/Android.bp b/shared/minidroid/sample/aidl/Android.bp
index ed78c9ee7..edbcdb282 100644
--- a/shared/minidroid/sample/aidl/Android.bp
+++ b/shared/minidroid/sample/aidl/Android.bp
@@ -15,6 +15,6 @@ aidl_interface {
         },
         rust: {
             enabled: true,
-        }
+        },
     },
 }
diff --git a/shared/minidroid/sample/servicediscovery/Android.bp b/shared/minidroid/sample/servicediscovery/Android.bp
index 9d0247978..8a022af04 100644
--- a/shared/minidroid/sample/servicediscovery/Android.bp
+++ b/shared/minidroid/sample/servicediscovery/Android.bp
@@ -11,16 +11,16 @@ cc_library {
     name: "minidroid_sd",
     srcs: ["minidroid_sd.cpp"],
     shared_libs: [
+        "libbase",
         "libbinder_ndk",
         "libbinder_rpc_unstable",
-        "libbase",
     ],
     static_libs: [
         "libprotobuf-cpp-lite-ndk",
     ],
 
     export_include_dirs: [
-    	"include",
+        "include",
     ],
 
     apex_available: [
diff --git a/shared/minidroid/sample/servicediscovery/minidroid_sd.cpp b/shared/minidroid/sample/servicediscovery/minidroid_sd.cpp
index 5a9f7ecd7..dd6f31ac5 100644
--- a/shared/minidroid/sample/servicediscovery/minidroid_sd.cpp
+++ b/shared/minidroid/sample/servicediscovery/minidroid_sd.cpp
@@ -26,7 +26,8 @@
 
 void bi::sd::setupRpcServer(ndk::SpAIBinder service, int port) {
   ABinderProcess_startThreadPool();
-  ARpcServer* server = ARpcServer_newVsock(service.get(), VMADDR_CID_ANY, port);
+  ARpcServer* server =
+      ARpcServer_newVsock(service.get(), VMADDR_CID_ANY, port, nullptr);
 
   AServiceManager_addService(service.get(), "TestService");
   printf("Calling join on server!\n");
diff --git a/shared/modules.blocklist b/shared/modules.blocklist
index 20fc5c7c6..4295354a0 100644
--- a/shared/modules.blocklist
+++ b/shared/modules.blocklist
@@ -1,3 +1,13 @@
 # ptp_kvm.ko should only load when the kvm hypervisor is available on the target
 blocklist ptp_kvm.ko
 blocklist vkms.ko
+
+# Cuttlefish assumes /dev/snd/pcmC0D0p, the first ALSA playback device,
+# represents a virtio-snd playback device.
+#
+# When audio loopback device gets loaded earlier, that device becomes a
+# loopback audio device, and no output from audio HAL gets forwarded to the
+# host.
+#
+# Prevent it from loading completely as it's not needed in Cuttlefish.
+blocklist snd-aloop.ko
diff --git a/shared/modules_aarch64.blocklist b/shared/modules_aarch64.blocklist
new file mode 100644
index 000000000..86a57c3e6
--- /dev/null
+++ b/shared/modules_aarch64.blocklist
@@ -0,0 +1,4 @@
+blocklist dummy-cpufreq.ko
+# ptp_kvm.ko should only load when the kvm hypervisor is available on the target
+blocklist ptp_kvm.ko
+blocklist vkms.ko
diff --git a/shared/overlays/foldable/core/Android.bp b/shared/overlays/foldable/core/Android.bp
index 4db50d1f5..b578a5bc7 100644
--- a/shared/overlays/foldable/core/Android.bp
+++ b/shared/overlays/foldable/core/Android.bp
@@ -21,5 +21,8 @@ runtime_resource_overlay {
     name: "aosp_cuttlefish_foldable_overlay_frameworks_base",
     soc_specific: true,
     sdk_version: "current",
-    aaptflags: ["--auto-add-overlay", "--keep-raw-values"],
+    aaptflags: [
+        "--auto-add-overlay",
+        "--keep-raw-values",
+    ],
 }
diff --git a/guest/services/trusty_vm_launcher/early_vms.xml b/shared/phone/overlay/packages/apps/Settings/res/values/arrays.xml
similarity index 57%
rename from guest/services/trusty_vm_launcher/early_vms.xml
rename to shared/phone/overlay/packages/apps/Settings/res/values/arrays.xml
index 9019d511d..797cfc1f2 100644
--- a/guest/services/trusty_vm_launcher/early_vms.xml
+++ b/shared/phone/overlay/packages/apps/Settings/res/values/arrays.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2024 The Android Open Source Project
+<!-- Copyright (C) 2019 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,10 +13,16 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<early_vms>
-    <early_vm>
-        <name>trusty_vm_launcher</name>
-        <cid>200</cid>
-        <path>/system_ext/bin/trusty_vm_launcher</path>
-    </early_vm>
-</early_vms>
+
+<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string-array name="enabled_networks_except_gsm_values" translatable="false">
+        <item>10</item>
+        <item>0</item>
+    </string-array>
+
+    <string-array name="enabled_networks_values" translatable="false">
+        <item>10</item>
+        <item>0</item>
+        <item>1</item>
+    </string-array>
+</resources>
diff --git a/shared/sepolicy/system_ext/private/file_contexts b/shared/sepolicy/system_ext/private/file_contexts
index 26eaa40d2..57b3a5aa9 100644
--- a/shared/sepolicy/system_ext/private/file_contexts
+++ b/shared/sepolicy/system_ext/private/file_contexts
@@ -2,5 +2,31 @@
 /(system_ext|system/system_ext)/bin/hw/android\.hardware\.audio\.parameter_parser\.example_service u:object_r:audio_vendor_parameter_parser_exec:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hardware\.security\.keymint-service\.rust\.trusty\.system\.nonsecure  u:object_r:hal_keymint_system_exec:s0
 is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
-    /(system_ext|system/system_ext)/bin/trusty_vm_launcher u:object_r:trusty_vm_launcher_exec:s0
+    /(system_ext|system/system_ext)/bin/trusty_security_vm_launcher u:object_r:trusty_security_vm_launcher_exec:s0
 ')
+/(system_ext|system/system_ext)/bin/rpmb_dev\.system   u:object_r:rpmb_dev_system_exec:s0
+/(system_ext|system/system_ext)/bin/rpmb_dev\.test\.system   u:object_r:rpmb_dev_system_exec:s0
+/(system_ext|system/system_ext)/bin/storageproxyd\.system     u:object_r:storageproxyd_system_exec:s0
+/(system_ext|system/system_ext)/bin/rpmb_dev\.wv\.system   u:object_r:rpmb_dev_wv_system_exec:s0
+
+#############################
+# sockets
+/dev/socket/rpmb_mock_system  u:object_r:rpmb_dev_system_socket:s0
+/dev/socket/rpmb_mock_test_system  u:object_r:rpmb_dev_system_socket:s0
+/dev/socket/rpmb_mock_wv_system  u:object_r:rpmb_dev_system_socket:s0
+
+#############################
+# persist files
+/mnt/secure_storage_rpmb_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+
+/mnt/secure_storage_rpmb_test_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_test_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+/mnt/secure_storage_rpmb_wv_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_wv_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+
+#############################
+# data files
+/data/secure_storage_system(/.*)?        u:object_r:secure_storage_system_file:s0
+/data/secure_storage_test_system(/.*)?        u:object_r:secure_storage_system_file:s0
+/data/secure_storage_wv_system(/.*)?        u:object_r:secure_storage_system_file:s0
diff --git a/shared/sepolicy/system_ext/private/secure_storage_system.te b/shared/sepolicy/system_ext/private/secure_storage_system.te
new file mode 100644
index 000000000..4d7e653ed
--- /dev/null
+++ b/shared/sepolicy/system_ext/private/secure_storage_system.te
@@ -0,0 +1,47 @@
+#============= rpmb_dev_system ==============
+type rpmb_dev_system, domain, coredomain;
+type rpmb_dev_system_exec, exec_type, system_file_type, file_type;
+type secure_storage_rpmb_system_file, file_type, data_file_type, core_data_file_type;
+type rpmb_dev_system_socket, file_type, data_file_type, core_data_file_type;
+init_daemon_domain(rpmb_dev_system)
+allow rpmb_dev_system metadata_file:dir { search add_name write };
+allow rpmb_dev_system metadata_file:file { create open read write };
+allow rpmb_dev_system tmpfs:lnk_file read;
+allow rpmb_dev_system secure_storage_rpmb_system_file:dir rw_dir_perms;
+allow rpmb_dev_system secure_storage_rpmb_system_file:{file sock_file} create_file_perms;
+allow rpmb_dev_system secure_storage_rpmb_system_file:lnk_file read;
+allow rpmb_dev_system rpmb_dev_system_socket:sock_file rw_file_perms;
+
+#============= rpmb_dev_wv_system ==============
+type rpmb_dev_wv_system, domain, coredomain;
+type rpmb_dev_wv_system_exec, exec_type, system_file_type, file_type;
+type rpmb_dev_wv_system_socket, file_type, data_file_type, core_data_file_type;
+init_daemon_domain(rpmb_dev_wv_system)
+allow rpmb_dev_wv_system metadata_file:dir { search add_name write };
+allow rpmb_dev_wv_system metadata_file:file { create open read write };
+allow rpmb_dev_wv_system tmpfs:lnk_file read;
+allow rpmb_dev_wv_system secure_storage_rpmb_system_file:dir rw_dir_perms;
+allow rpmb_dev_wv_system secure_storage_rpmb_system_file:{file sock_file} create_file_perms;
+allow rpmb_dev_wv_system secure_storage_rpmb_system_file:lnk_file read;
+allow rpmb_dev_wv_system rpmb_dev_wv_system_socket:sock_file rw_file_perms;
+allow rpmb_dev_wv_system rpmb_dev_system_socket:sock_file rw_file_perms;
+
+#============= storageproxyd_system ==============
+type storageproxyd_system, domain, coredomain;
+type storageproxyd_system_exec, exec_type, system_file_type, file_type;
+type secure_storage_persist_system_file, file_type, data_file_type, core_data_file_type;
+type secure_storage_system_file, file_type, data_file_type, core_data_file_type;
+
+init_daemon_domain(storageproxyd_system)
+allow storageproxyd_system metadata_file:dir search;
+allow storageproxyd_system secure_storage_persist_system_file:dir rw_dir_perms;
+allow storageproxyd_system secure_storage_persist_system_file:file { create open read write };
+allow storageproxyd_system secure_storage_system_file:dir rw_dir_perms;
+allow storageproxyd_system secure_storage_system_file:file { create open read write getattr };
+allow storageproxyd_system self:vsock_socket { create_socket_perms_no_ioctl };
+
+unix_socket_connect(storageproxyd_system, rpmb_dev_system, rpmb_dev_system)
+unix_socket_connect(storageproxyd_system, rpmb_dev_wv_system, rpmb_dev_wv_system)
+
+# Allow storageproxyd_system access to gsi_public_metadata_file
+read_fstab(storageproxyd_system)
diff --git a/shared/sepolicy/system_ext/private/trusty_security_vm_launcher.te b/shared/sepolicy/system_ext/private/trusty_security_vm_launcher.te
new file mode 100644
index 000000000..aded08470
--- /dev/null
+++ b/shared/sepolicy/system_ext/private/trusty_security_vm_launcher.te
@@ -0,0 +1,18 @@
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    type trusty_security_vm_launcher, domain, coredomain;
+    type trusty_security_vm_launcher_exec, system_file_type, exec_type, file_type;
+    type trusty_security_vm_launcher_tmpfs, file_type;
+
+    init_daemon_domain(trusty_security_vm_launcher)
+    domain_auto_trans(init, trusty_security_vm_launcher_exec, trusty_security_vm_launcher)
+
+    early_virtmgr_use(trusty_security_vm_launcher)
+    binder_use(trusty_security_vm_launcher)
+
+    allow trusty_security_vm_launcher kmsg_debug_device:chr_file rw_file_perms;
+    use_bootstrap_libs(trusty_security_vm_launcher)
+
+    allow trusty_security_vm_launcher self:global_capability_class_set { net_bind_service ipc_lock sys_resource };
+
+    tmpfs_domain(trusty_security_vm_launcher)
+')
diff --git a/shared/sepolicy/system_ext/private/trusty_vm_launcher.te b/shared/sepolicy/system_ext/private/trusty_vm_launcher.te
deleted file mode 100644
index a5d16b749..000000000
--- a/shared/sepolicy/system_ext/private/trusty_vm_launcher.te
+++ /dev/null
@@ -1,18 +0,0 @@
-is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
-    type trusty_vm_launcher, domain, coredomain;
-    type trusty_vm_launcher_exec, system_file_type, exec_type, file_type;
-    type trusty_vm_launcher_tmpfs, file_type;
-
-    init_daemon_domain(trusty_vm_launcher)
-    domain_auto_trans(init, trusty_vm_launcher_exec, trusty_vm_launcher)
-
-    early_virtmgr_use(trusty_vm_launcher)
-    binder_use(trusty_vm_launcher)
-
-    allow trusty_vm_launcher kmsg_debug_device:chr_file rw_file_perms;
-    use_bootstrap_libs(trusty_vm_launcher)
-
-    allow trusty_vm_launcher self:global_capability_class_set { net_bind_service ipc_lock sys_resource };
-
-    tmpfs_domain(trusty_vm_launcher)
-')
diff --git a/shared/sepolicy/vendor/hal_gatekeeper_default.te b/shared/sepolicy/vendor/hal_gatekeeper_default.te
new file mode 100644
index 000000000..d1de11e08
--- /dev/null
+++ b/shared/sepolicy/vendor/hal_gatekeeper_default.te
@@ -0,0 +1,3 @@
+# Write to kernel log (/dev/kmsg)
+allow hal_gatekeeper_default kmsg_device:chr_file w_file_perms;
+allow hal_gatekeeper_default kmsg_device:chr_file getattr;
diff --git a/shared/sepolicy/vendor/hal_keymint_default.te b/shared/sepolicy/vendor/hal_keymint_default.te
new file mode 100644
index 000000000..a48e71b5e
--- /dev/null
+++ b/shared/sepolicy/vendor/hal_keymint_default.te
@@ -0,0 +1,2 @@
+get_prop(hal_keymint_default, serialno_prop)
+get_prop(hal_keymint_default, vendor_boot_security_patch_level_prop)
diff --git a/shared/sepolicy/vendor/property.te b/shared/sepolicy/vendor/property.te
index 589e7297b..ba1bf4598 100644
--- a/shared/sepolicy/vendor/property.te
+++ b/shared/sepolicy/vendor/property.te
@@ -6,3 +6,7 @@ vendor_internal_prop(vendor_device_prop)
 vendor_internal_prop(vendor_uwb_prop)
 vendor_internal_prop(vendor_otsim_local_interface_prop)
 vendor_internal_prop(vendor_vhal_proxy_server_port_prop)
+
+# Ignore KeyMint VM HAL's access to vendor_boot_security_patch_level_prop
+# See b/366132108 for more context.
+dontaudit coredomain vendor_boot_security_patch_level_prop:file read;
diff --git a/shared/tv/device_vendor.mk b/shared/tv/device_vendor.mk
index 6b1de331f..f8b48b693 100644
--- a/shared/tv/device_vendor.mk
+++ b/shared/tv/device_vendor.mk
@@ -25,7 +25,6 @@ $(call inherit-product, device/google/cuttlefish/shared/graphics/device_vendor.m
 $(call inherit-product, device/google/cuttlefish/shared/swiftshader/device_vendor.mk)
 $(call inherit-product, device/google/cuttlefish/shared/virgl/device_vendor.mk)
 $(call inherit-product, device/google/cuttlefish/shared/device.mk)
-$(call inherit-product-if-exists, vendor/google/tv/gcbs/projects/reference-v4/dtvstack.mk)
 
 # Loads the camera HAL and which set of cameras is required.
 $(call inherit-product, device/google/cuttlefish/shared/camera/device_vendor.mk)
@@ -70,6 +69,9 @@ PRODUCT_PROPERTY_OVERRIDES += \
 PRODUCT_PACKAGES += android.hardware.tv.tuner-service.example-lazy
 PRODUCT_VENDOR_PROPERTIES += ro.tuner.lazyhal=true
 
+# Media Quality HAL
+PRODUCT_PACKAGES += android.hardware.tv.mediaquality-service.example
+
 # TV Input HAL
 PRODUCT_PACKAGES += android.hardware.tv.input-service.example
 
diff --git a/shared/wear/aosp_vendor.mk b/shared/wear/aosp_vendor.mk
index 4609ec742..c837fb119 100644
--- a/shared/wear/aosp_vendor.mk
+++ b/shared/wear/aosp_vendor.mk
@@ -21,9 +21,6 @@ PRODUCT_SYSTEM_SERVER_COMPILER_FILTER := speed-profile
 
 PRODUCT_ALWAYS_PREOPT_EXTRACTED_APK := true
 
-PRODUCT_USE_PROFILE_FOR_BOOT_IMAGE := true
-PRODUCT_DEX_PREOPT_BOOT_IMAGE_PROFILE_LOCATION := frameworks/base/config/boot-image-profile.txt
-
 PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false
 
 PRODUCT_PACKAGES += \
diff --git a/system_image/Android.bp b/system_image/Android.bp
deleted file mode 100644
index 0220f22b5..000000000
--- a/system_image/Android.bp
+++ /dev/null
@@ -1,821 +0,0 @@
-android_rootdirs = [
-    "acct",
-    "apex",
-    "bootstrap-apex",
-    "config",
-    "data",
-    "data_mirror",
-    "debug_ramdisk",
-    "dev",
-    "linkerconfig",
-    "metadata",
-    "mnt",
-    "odm",
-    "odm_dlkm",
-    "oem",
-    "postinstall",
-    "proc",
-    "product",
-    "second_stage_resources",
-    "storage",
-    "sys",
-    "system",
-    "system_dlkm",
-    "system_ext",
-    "tmp",
-    "vendor",
-    "vendor_dlkm",
-]
-
-android_symlinks = [
-    {
-        target: "/system/bin/init",
-        name: "init",
-    },
-    {
-        target: "/system/etc",
-        name: "etc",
-    },
-    {
-        target: "/system/bin",
-        name: "bin",
-    },
-    {
-        target: "/product",
-        name: "system/product",
-    },
-    {
-        target: "/vendor",
-        name: "system/vendor",
-    },
-    {
-        target: "/system_ext",
-        name: "system/system_ext",
-    },
-    {
-        target: "/system_dlkm/lib/modules",
-        name: "system/lib/modules",
-    },
-    {
-        target: "/data/user_de/0/com.android.shell/files/bugreports",
-        name: "bugreports",
-    },
-    {
-        target: "/data/cache",
-        name: "cache",
-    },
-    {
-        target: "/sys/kernel/debug",
-        name: "d",
-    },
-    {
-        target: "/storage/self/primary",
-        name: "sdcard",
-    },
-    {
-        target: "/product/etc/security/adb_keys",
-        name: "adb_keys",
-    },
-]
-
-phony {
-    name: "fonts",
-    required: [
-        "AndroidClock.ttf",
-        "CarroisGothicSC-Regular.ttf",
-        "ComingSoon.ttf",
-        "CutiveMono.ttf",
-        "DancingScript-Regular.ttf",
-        "DroidSansMono.ttf",
-        "NotoColorEmoji.ttf",
-        "NotoColorEmojiFlags.ttf",
-        "NotoNaskhArabic-Bold.ttf",
-        "NotoNaskhArabic-Regular.ttf",
-        "NotoNaskhArabicUI-Bold.ttf",
-        "NotoNaskhArabicUI-Regular.ttf",
-        "NotoSansAdlam-VF.ttf",
-        "NotoSansAhom-Regular.otf",
-        "NotoSansAnatolianHieroglyphs-Regular.otf",
-        "NotoSansArmenian-VF.ttf",
-        "NotoSansAvestan-Regular.ttf",
-        "NotoSansBalinese-Regular.ttf",
-        "NotoSansBamum-Regular.ttf",
-        "NotoSansBassaVah-Regular.otf",
-        "NotoSansBatak-Regular.ttf",
-        "NotoSansBengali-VF.ttf",
-        "NotoSansBengaliUI-VF.ttf",
-        "NotoSansBhaiksuki-Regular.otf",
-        "NotoSansBrahmi-Regular.ttf",
-        "NotoSansBuginese-Regular.ttf",
-        "NotoSansBuhid-Regular.ttf",
-        "NotoSansCJK-Regular.ttc",
-        "NotoSansCanadianAboriginal-Regular.ttf",
-        "NotoSansCarian-Regular.ttf",
-        "NotoSansChakma-Regular.otf",
-        "NotoSansCham-Bold.ttf",
-        "NotoSansCham-Regular.ttf",
-        "NotoSansCherokee-Regular.ttf",
-        "NotoSansCoptic-Regular.ttf",
-        "NotoSansCuneiform-Regular.ttf",
-        "NotoSansCypriot-Regular.ttf",
-        "NotoSansDeseret-Regular.ttf",
-        "NotoSansDevanagari-VF.ttf",
-        "NotoSansDevanagariUI-VF.ttf",
-        "NotoSansEgyptianHieroglyphs-Regular.ttf",
-        "NotoSansElbasan-Regular.otf",
-        "NotoSansEthiopic-VF.ttf",
-        "NotoSansGeorgian-VF.ttf",
-        "NotoSansGlagolitic-Regular.ttf",
-        "NotoSansGothic-Regular.ttf",
-        "NotoSansGrantha-Regular.ttf",
-        "NotoSansGujarati-Bold.ttf",
-        "NotoSansGujarati-Regular.ttf",
-        "NotoSansGujaratiUI-Bold.ttf",
-        "NotoSansGujaratiUI-Regular.ttf",
-        "NotoSansGunjalaGondi-Regular.otf",
-        "NotoSansGurmukhi-VF.ttf",
-        "NotoSansGurmukhiUI-VF.ttf",
-        "NotoSansHanifiRohingya-Regular.otf",
-        "NotoSansHanunoo-Regular.ttf",
-        "NotoSansHatran-Regular.otf",
-        "NotoSansHebrew-Bold.ttf",
-        "NotoSansHebrew-Regular.ttf",
-        "NotoSansImperialAramaic-Regular.ttf",
-        "NotoSansInscriptionalPahlavi-Regular.ttf",
-        "NotoSansInscriptionalParthian-Regular.ttf",
-        "NotoSansJavanese-Regular.otf",
-        "NotoSansKaithi-Regular.ttf",
-        "NotoSansKannada-VF.ttf",
-        "NotoSansKannadaUI-VF.ttf",
-        "NotoSansKayahLi-Regular.ttf",
-        "NotoSansKharoshthi-Regular.ttf",
-        "NotoSansKhmer-VF.ttf",
-        "NotoSansKhmerUI-Bold.ttf",
-        "NotoSansKhmerUI-Regular.ttf",
-        "NotoSansKhojki-Regular.otf",
-        "NotoSansLao-Bold.ttf",
-        "NotoSansLao-Regular.ttf",
-        "NotoSansLaoUI-Bold.ttf",
-        "NotoSansLaoUI-Regular.ttf",
-        "NotoSansLepcha-Regular.ttf",
-        "NotoSansLimbu-Regular.ttf",
-        "NotoSansLinearA-Regular.otf",
-        "NotoSansLinearB-Regular.ttf",
-        "NotoSansLisu-Regular.ttf",
-        "NotoSansLycian-Regular.ttf",
-        "NotoSansLydian-Regular.ttf",
-        "NotoSansMalayalam-VF.ttf",
-        "NotoSansMalayalamUI-VF.ttf",
-        "NotoSansMandaic-Regular.ttf",
-        "NotoSansManichaean-Regular.otf",
-        "NotoSansMarchen-Regular.otf",
-        "NotoSansMasaramGondi-Regular.otf",
-        "NotoSansMedefaidrin-VF.ttf",
-        "NotoSansMeeteiMayek-Regular.ttf",
-        "NotoSansMeroitic-Regular.otf",
-        "NotoSansMiao-Regular.otf",
-        "NotoSansModi-Regular.ttf",
-        "NotoSansMongolian-Regular.ttf",
-        "NotoSansMro-Regular.otf",
-        "NotoSansMultani-Regular.otf",
-        "NotoSansMyanmar-Bold.otf",
-        "NotoSansMyanmar-Medium.otf",
-        "NotoSansMyanmar-Regular.otf",
-        "NotoSansMyanmarUI-Bold.otf",
-        "NotoSansMyanmarUI-Medium.otf",
-        "NotoSansMyanmarUI-Regular.otf",
-        "NotoSansNKo-Regular.ttf",
-        "NotoSansNabataean-Regular.otf",
-        "NotoSansNewTaiLue-Regular.ttf",
-        "NotoSansNewa-Regular.otf",
-        "NotoSansOgham-Regular.ttf",
-        "NotoSansOlChiki-Regular.ttf",
-        "NotoSansOldItalic-Regular.ttf",
-        "NotoSansOldNorthArabian-Regular.otf",
-        "NotoSansOldPermic-Regular.otf",
-        "NotoSansOldPersian-Regular.ttf",
-        "NotoSansOldSouthArabian-Regular.ttf",
-        "NotoSansOldTurkic-Regular.ttf",
-        "NotoSansOriya-Bold.ttf",
-        "NotoSansOriya-Regular.ttf",
-        "NotoSansOriyaUI-Bold.ttf",
-        "NotoSansOriyaUI-Regular.ttf",
-        "NotoSansOsage-Regular.ttf",
-        "NotoSansOsmanya-Regular.ttf",
-        "NotoSansPahawhHmong-Regular.otf",
-        "NotoSansPalmyrene-Regular.otf",
-        "NotoSansPauCinHau-Regular.otf",
-        "NotoSansPhagsPa-Regular.ttf",
-        "NotoSansPhoenician-Regular.ttf",
-        "NotoSansRejang-Regular.ttf",
-        "NotoSansRunic-Regular.ttf",
-        "NotoSansSamaritan-Regular.ttf",
-        "NotoSansSaurashtra-Regular.ttf",
-        "NotoSansSharada-Regular.otf",
-        "NotoSansShavian-Regular.ttf",
-        "NotoSansSinhala-VF.ttf",
-        "NotoSansSinhalaUI-VF.ttf",
-        "NotoSansSoraSompeng-Regular.otf",
-        "NotoSansSoyombo-VF.ttf",
-        "NotoSansSundanese-Regular.ttf",
-        "NotoSansSylotiNagri-Regular.ttf",
-        "NotoSansSymbols-Regular-Subsetted.ttf",
-        "NotoSansSymbols-Regular-Subsetted2.ttf",
-        "NotoSansSyriacEastern-Regular.ttf",
-        "NotoSansSyriacEstrangela-Regular.ttf",
-        "NotoSansSyriacWestern-Regular.ttf",
-        "NotoSansTagalog-Regular.ttf",
-        "NotoSansTagbanwa-Regular.ttf",
-        "NotoSansTaiLe-Regular.ttf",
-        "NotoSansTaiTham-Regular.ttf",
-        "NotoSansTaiViet-Regular.ttf",
-        "NotoSansTakri-VF.ttf",
-        "NotoSansTamil-VF.ttf",
-        "NotoSansTamilUI-VF.ttf",
-        "NotoSansTelugu-VF.ttf",
-        "NotoSansTeluguUI-VF.ttf",
-        "NotoSansThaana-Bold.ttf",
-        "NotoSansThaana-Regular.ttf",
-        "NotoSansThai-Bold.ttf",
-        "NotoSansThai-Regular.ttf",
-        "NotoSansThaiUI-Bold.ttf",
-        "NotoSansThaiUI-Regular.ttf",
-        "NotoSansTifinagh-Regular.otf",
-        "NotoSansUgaritic-Regular.ttf",
-        "NotoSansVai-Regular.ttf",
-        "NotoSansWancho-Regular.otf",
-        "NotoSansWarangCiti-Regular.otf",
-        "NotoSansYi-Regular.ttf",
-        "NotoSerif-Bold.ttf",
-        "NotoSerif-BoldItalic.ttf",
-        "NotoSerif-Italic.ttf",
-        "NotoSerif-Regular.ttf",
-        "NotoSerifArmenian-VF.ttf",
-        "NotoSerifBengali-VF.ttf",
-        "NotoSerifCJK-Regular.ttc",
-        "NotoSerifDevanagari-VF.ttf",
-        "NotoSerifDogra-Regular.ttf",
-        "NotoSerifEthiopic-VF.ttf",
-        "NotoSerifGeorgian-VF.ttf",
-        "NotoSerifGujarati-VF.ttf",
-        "NotoSerifGurmukhi-VF.ttf",
-        "NotoSerifHebrew-Bold.ttf",
-        "NotoSerifHebrew-Regular.ttf",
-        "NotoSerifHentaigana.ttf",
-        "NotoSerifKannada-VF.ttf",
-        "NotoSerifKhmer-Bold.otf",
-        "NotoSerifKhmer-Regular.otf",
-        "NotoSerifLao-Bold.ttf",
-        "NotoSerifLao-Regular.ttf",
-        "NotoSerifMalayalam-VF.ttf",
-        "NotoSerifMyanmar-Bold.otf",
-        "NotoSerifMyanmar-Regular.otf",
-        "NotoSerifNyiakengPuachueHmong-VF.ttf",
-        "NotoSerifSinhala-VF.ttf",
-        "NotoSerifTamil-VF.ttf",
-        "NotoSerifTelugu-VF.ttf",
-        "NotoSerifThai-Bold.ttf",
-        "NotoSerifThai-Regular.ttf",
-        "NotoSerifTibetan-VF.ttf",
-        "NotoSerifYezidi-VF.ttf",
-        "Roboto-Regular.ttf",
-        "RobotoFlex-Regular.ttf",
-        "RobotoStatic-Regular.ttf",
-        "SourceSansPro-Bold.ttf",
-        "SourceSansPro-BoldItalic.ttf",
-        "SourceSansPro-Italic.ttf",
-        "SourceSansPro-Regular.ttf",
-        "SourceSansPro-SemiBold.ttf",
-        "SourceSansPro-SemiBoldItalic.ttf",
-        "font_fallback.xml",
-        "fonts.xml",
-    ],
-}
-
-android_system_image {
-    name: "aosp_cf_system_x86_64",
-
-    partition_name: "system",
-    base_dir: "system",
-    dirs: android_rootdirs,
-    symlinks: android_symlinks,
-    file_contexts: ":plat_file_contexts",
-    linker_config_src: "linker.config.json",
-    fsverity: {
-        inputs: [
-            "etc/boot-image.prof",
-            "etc/classpaths/*.pb",
-            "etc/dirty-image-objects",
-            "etc/preloaded-classes",
-            "framework/*",
-            "framework/*/*", // framework/{arch}
-            "framework/oat/*/*", // framework/oat/{arch}
-        ],
-        libs: [":framework-res{.export-package.apk}"],
-    },
-    build_logtags: true,
-    gen_aconfig_flags_pb: true,
-
-    compile_multilib: "both",
-
-    use_avb: true,
-    avb_private_key: ":microdroid_sign_key",
-    avb_algorithm: "SHA256_RSA4096",
-    avb_hash_algorithm: "sha256",
-
-    deps: [
-        "abx",
-        "aconfigd",
-        "aflags",
-        "am",
-        "android.software.credentials.prebuilt.xml", // generic_system
-        "android.software.webview.prebuilt.xml", // media_system
-        "android.software.window_magnification.prebuilt.xml", // handheld_system
-        "android.system.suspend-service",
-        "android_vintf_manifest",
-        "apexd",
-        "appops",
-        "approved-ogki-builds.xml", // base_system
-        "appwidget",
-        "atrace",
-        "audioserver",
-        "bcc",
-        "blank_screen",
-        "blkid",
-        "bmgr",
-        "bootanimation",
-        "bootstat",
-        "bpfloader",
-        "bu",
-        "bugreport",
-        "bugreportz",
-        "cameraserver",
-        "cgroups.json",
-        "cmd",
-        "content",
-        "cppreopts.sh", // generic_system
-        "credstore",
-        "debuggerd",
-        "device_config",
-        "dirty-image-objects",
-        "dmctl",
-        "dmesgd",
-        "dnsmasq",
-        "dpm",
-        "dump.erofs",
-        "dumpstate",
-        "dumpsys",
-        "e2fsck",
-        "enhanced-confirmation.xml", // base_system
-        "etc_hosts",
-        "flags_health_check",
-        "framework-audio_effects.xml", // for handheld // handheld_system
-        "framework-sysconfig.xml",
-        "fs_config_dirs_system",
-        "fs_config_files_system",
-        "fsck.erofs",
-        "fsck.f2fs", // for media_system
-        "fsck_msdos",
-        "fsverity-release-cert-der",
-        "gatekeeperd",
-        "gpu_counter_producer",
-        "gpuservice",
-        "group_system",
-        "gsi_tool",
-        "gsid",
-        "heapprofd",
-        "hid",
-        "hiddenapi-package-whitelist.xml", // from runtime_libart
-        "idc_data",
-        "idmap2",
-        "idmap2d",
-        "ime",
-        "incident",
-        "incident-helper-cmd",
-        "incident_helper",
-        "incidentd",
-        "init.environ.rc-soong",
-        "init.usb.configfs.rc",
-        "init.usb.rc",
-        "init.zygote32.rc",
-        "init.zygote64.rc",
-        "init.zygote64_32.rc",
-        "init_first_stage", // for boot partition
-        "initial-package-stopped-states.xml",
-        "input",
-        "installd",
-        "ip", // base_system
-        "iptables",
-        "kcmdlinectrl",
-        "kernel-lifetimes.xml", // base_system
-        "keychars_data",
-        "keylayout_data",
-        "keystore2",
-        "ld.mc",
-        "llkd", // base_system
-        "lmkd", // base_system
-        "local_time.default", // handheld_vendo
-        "locksettings", // base_system
-        "logcat", // base_system
-        "logd", // base_system
-        "logpersist.start",
-        "lpdump", // base_system
-        "lshal", // base_system
-        "make_f2fs", // media_system
-        "mdnsd", // base_system
-        "media_profiles_V1_0.dtd", // base_system
-        "mediacodec.policy", // base_system
-        "mediaextractor", // base_system
-        "mediametrics", // base_system
-        "misctrl", // from base_system
-        "mke2fs", // base_system
-        "mkfs.erofs", // base_system
-        "monkey", // base_system
-        "mtectrl", // base_system
-        "ndc", // base_system
-        "netd", // base_system
-        "netutils-wrapper-1.0", // full_base
-        "notice_xml_system",
-        "odsign", // base_system
-        "otapreopt_script", // generic_system
-        "package-shareduid-allowlist.xml", // base_system
-        "passwd_system", // base_system
-        "perfetto", // base_system
-        "ping", // base_system
-        "ping6", // base_system
-        "pintool", // base_system
-        "platform.xml", // base_system
-        "pm", // base_system
-        "preinstalled-packages-asl-files.xml", // base_system
-        "preinstalled-packages-platform-generic-system.xml", // generic_system
-        "preinstalled-packages-platform-handheld-system.xml", // handheld_system
-        "preinstalled-packages-platform.xml", // base_system
-        "preinstalled-packages-strict-signature.xml", // base_system
-        "preloaded-classes", // ok
-        "printflags", // base_system
-        "privapp-permissions-platform.xml", // base_system
-        "prng_seeder", // base_system
-        "public.libraries.android.txt",
-        "recovery-persist", // base_system
-        "recovery-refresh", // generic_system
-        "requestsync", // media_system
-        "resize2fs", // base_system
-        "rss_hwm_reset", // base_system
-        "run-as", // base_system
-        "schedtest", // base_system
-        "screencap", // base_system
-        "screenrecord", // handheld_system
-        "sdcard", // base_system
-        "secdiscard", // base_system
-        "sensorservice", // base_system
-        "service", // base_system
-        "servicemanager", // base_system
-        "settings", // base_system
-        "sfdo", // base_system
-        "sgdisk", // base_system
-        "sm", // base_system
-        "snapshotctl", // base_system
-        "snapuserd", // base_system
-        "snapuserd_ramdisk", // ramdisk
-        "storaged", // base_system
-        "surfaceflinger", // base_system
-        "svc", // base_system
-        "task_profiles.json", // base_system
-        "tc", // base_system
-        "telecom", // base_system
-        "tombstoned", // base_system
-        "traced", // base_system
-        "traced_probes", // base_system
-        "tune2fs", // base_system
-        "uiautomator", // base_system
-        "uinput", // base_system
-        "uncrypt", // base_system
-        "update_engine", // generic_system
-        "update_engine_sideload", // recovery
-        "update_verifier", // generic_system
-        "usbd", // base_system
-        "vdc", // base_system
-        "virtual_camera", // handheld_system // release_package_virtual_camera
-        "vold", // base_system
-        "vr", // handheld_system
-        "watchdogd", // base_system
-        "wifi.rc", // base_system
-        "wificond", // base_system
-        "wm", // base_system
-    ] + select(release_flag("RELEASE_PLATFORM_VERSION_CODENAME"), {
-        "REL": [],
-        default: [
-            "android.software.preview_sdk.prebuilt.xml", // media_system
-        ],
-    }) + select(soong_config_variable("ANDROID", "release_package_profiling_module"), {
-        "true": [
-            "trace_redactor", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
-        ],
-        default: [],
-    }) + select(product_variable("debuggable"), {
-        true: [
-            "adevice_fingerprint",
-            "arping",
-            "avbctl",
-            "bootctl",
-            "dmuserd",
-            "evemu-record",
-            "idlcli",
-            "init-debug.rc",
-            "iotop",
-            "iperf3",
-            "iw",
-            "layertracegenerator",
-            "logtagd.rc",
-            "ot-cli-ftd",
-            "ot-ctl",
-            "procrank",
-            "profcollectctl",
-            "profcollectd",
-            "record_binder",
-            "sanitizer-status",
-            "servicedispatcher",
-            "showmap",
-            "sqlite3",
-            "ss",
-            "start_with_lockagent",
-            "strace",
-            "su",
-            "tinycap",
-            "tinyhostless",
-            "tinymix",
-            "tinypcminfo",
-            "tinyplay", // host
-            "tracepath",
-            "tracepath6",
-            "traceroute6",
-            "unwind_info",
-            "unwind_reg_info",
-            "unwind_symbols",
-            "update_engine_client",
-        ],
-        default: [],
-    }),
-    multilib: {
-        common: {
-            deps: [
-                "BackupRestoreConfirmation", // base_system
-                "BasicDreams", // handheld_system
-                "BlockedNumberProvider", // handheld_system
-                "BluetoothMidiService", // handheld_system
-                "BookmarkProvider", // handheld_system
-                "BuiltInPrintService", // handheld_system
-                "CalendarProvider", // handheld_system
-                "CallLogBackup", // telephony_system
-                "CameraExtensionsProxy", // handheld_system
-                "CaptivePortalLogin", // handheld_system
-                "CarrierDefaultApp", // telephony_system
-                "CellBroadcastLegacyApp", // telephony_system
-                "CertInstaller", // handheld_system
-                "CompanionDeviceManager", // media_system
-                "ContactsProvider", // base_system
-                "CredentialManager", // handheld_system
-                "DeviceAsWebcam", // handheld_system
-                "DocumentsUI", // handheld_system
-                "DownloadProvider", // base_system
-                "DownloadProviderUi", // handheld_system
-                "DynamicSystemInstallationService", // base_system
-                "E2eeContactKeysProvider", // base_system
-                "EasterEgg", // handheld_system
-                "ExtShared", // base_system
-                "ExternalStorageProvider", // handheld_system
-                "FusedLocation", // handheld_system
-                "HTMLViewer", // media_system
-                "InputDevices", // handheld_system
-                "IntentResolver", // base_system
-                "KeyChain", // handheld_system
-                "LiveWallpapersPicker", // generic_system, full_base
-                "LocalTransport", // base_system
-                "ManagedProvisioning", // handheld_system
-                "MediaProviderLegacy", // base_system
-                "MmsService", // handheld_system
-                "MtpService", // handheld_system
-                "MusicFX", // handheld_system
-                "NetworkStack", // base_system
-                "ONS", // telephony_system
-                "PacProcessor", // handheld_system
-                "PackageInstaller", // base_system
-                "PartnerBookmarksProvider", // generic_system
-                "PhotoTable", // full_base
-                "PrintRecommendationService", // handheld_system
-                "PrintSpooler", // handheld_system
-                "ProxyHandler", // handheld_system
-                "SecureElement", // handheld_system
-                "SettingsProvider", // base_system
-                "SharedStorageBackup", // handheld_system
-                "Shell", // base_system
-                "SimAppDialog", // handheld_system
-                "SoundPicker", // not installed by anyone
-                "StatementService", // media_system
-                "Stk", // generic_system
-                "Tag", // generic_system
-                "TeleService", // handheld_system
-                "Telecom", // handheld_system
-                "TelephonyProvider", // handheld_system
-                "Traceur", // handheld_system
-                "UserDictionaryProvider", // handheld_system
-                "VpnDialogs", // handheld_system
-                "WallpaperBackup", // base_system
-                "adbd_system_api", // base_system
-                "android.hidl.base-V1.0-java", // base_system
-                "android.hidl.manager-V1.0-java", // base_system
-                "android.test.base", // from runtime_libart
-                "android.test.mock", // base_system
-                "android.test.runner", // base_system
-                "aosp_mainline_modules", // ok
-                "build_flag_system", // base_system
-                "charger_res_images", // generic_system
-                "com.android.apex.cts.shim.v1_prebuilt", // ok
-                "com.android.cellbroadcast", // telephony_system
-                "com.android.future.usb.accessory", // media_system
-                "com.android.location.provider", // base_system
-                "com.android.media.remotedisplay", // media_system
-                "com.android.media.remotedisplay.xml", // media_system
-                "com.android.mediadrm.signer", // media_system
-                "com.android.nfc_extras", // ok
-                "com.android.nfcservices", // base_system (RELEASE_PACKAGE_NFC_STACK != NfcNci)
-                "com.android.runtime", // ok
-                "dex_bootjars",
-                "ext", // from runtime_libart
-                "fonts", // ok
-                "framework-graphics", // base_system
-                "framework-location", // base_system
-                "framework-minus-apex-install-dependencies", // base_system
-                "framework_compatibility_matrix.device.xml",
-                "hwservicemanager_compat_symlink_module", // base_system
-                "hyph-data",
-                "ims-common", // base_system
-                "init_system", // base_system
-                "javax.obex", // base_system
-                "llndk.libraries.txt", //ok
-                "org.apache.http.legacy", // base_system
-                "perfetto-extras", // system
-                "sanitizer.libraries.txt", // base_system
-                "selinux_policy_system_soong", // ok
-                "services", // base_system
-                "shell_and_utilities_system", // ok
-                "system-build.prop",
-                "system_compatibility_matrix.xml", //base_system
-                "telephony-common", // libs from TeleService
-                "voip-common", // base_system
-            ] + select(soong_config_variable("ANDROID", "release_crashrecovery_module"), {
-                "true": [
-                    "com.android.crashrecovery", // base_system (RELEASE_CRASHRECOVERY_MODULE)
-                ],
-                default: [],
-            }) + select(soong_config_variable("ANDROID", "release_package_profiling_module"), {
-                "true": [
-                    "com.android.profiling", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
-                ],
-                default: [],
-            }) + select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
-                true: [
-                    "AvatarPicker", // generic_system (RELEASE_AVATAR_PICKER_APP)
-                ],
-                default: [],
-            }),
-        },
-        prefer32: {
-            deps: [
-                "drmserver", // media_system
-                "mediaserver", // base_system
-            ],
-        },
-        lib64: {
-            deps: [
-                "android.system.virtualizationcommon-ndk",
-                "android.system.virtualizationservice-ndk",
-                "libgsi",
-                "servicemanager",
-            ],
-        },
-        both: {
-            deps: [
-                "android.hardware.biometrics.fingerprint@2.1", // generic_system
-                "android.hardware.radio.config@1.0", // generic_system
-                "android.hardware.radio.deprecated@1.0", // generic_system
-                "android.hardware.radio@1.0", // generic_system
-                "android.hardware.radio@1.1", // generic_system
-                "android.hardware.radio@1.2", // generic_system
-                "android.hardware.radio@1.3", // generic_system
-                "android.hardware.radio@1.4", // generic_system
-                "android.hardware.secure_element@1.0", // generic_system
-                "app_process", // base_system
-                "boringssl_self_test", // base_system
-                "heapprofd_client", // base_system
-                "libEGL", // base_system
-                "libEGL_angle", // base_system
-                "libETC1", // base_system
-                "libFFTEm", // base_system
-                "libGLESv1_CM", // base_system
-                "libGLESv1_CM_angle", // base_system
-                "libGLESv2", // base_system
-                "libGLESv2_angle", // base_system
-                "libGLESv3", // base_system
-                "libOpenMAXAL", // base_system
-                "libOpenSLES", // base_system
-                "libaaudio", // base_system
-                "libalarm_jni", // base_system
-                "libamidi", // base_system
-                "libandroid",
-                "libandroid_runtime",
-                "libandroid_servers",
-                "libandroidfw",
-                "libartpalette-system",
-                "libaudio-resampler", // generic-system
-                "libaudioeffect_jni",
-                "libaudiohal", // generic-system
-                "libaudiopolicyengineconfigurable", // generic-system
-                "libbinder",
-                "libbinder_ndk",
-                "libbinder_rpc_unstable",
-                "libcamera2ndk",
-                "libclang_rt.asan",
-                "libcompiler_rt",
-                "libcutils", // used by many libs
-                "libdmabufheap", // used by many libs
-                "libdrm", // used by many libs // generic_system
-                "libdrmframework", // base_system
-                "libdrmframework_jni", // base_system
-                "libfdtrack", // base_system
-                "libfilterfw", // base_system
-                "libfilterpack_imageproc", // media_system
-                "libfwdlockengine", // generic_system
-                "libgatekeeper", // base_system
-                "libgui", // base_system
-                "libhardware", // base_system
-                "libhardware_legacy", // base_system
-                "libhidltransport", // generic_system
-                "libhwbinder", // generic_system
-                "libinput", // base_system
-                "libinputflinger", // base_system
-                "libiprouteutil", // base_system
-                "libjnigraphics", // base_system
-                "libjpeg", // base_system
-                "liblog", // base_system
-                "liblogwrap", // generic_system
-                "liblz4", // generic_system
-                "libmedia", // base_system
-                "libmedia_jni", // base_system
-                "libmediandk", // base_system
-                "libminui", // generic_system
-                "libmonkey_jni", // base_system
-                "libmtp", // base_system
-                "libnetd_client", // base_system
-                "libnetlink", // base_system
-                "libnetutils", // base_system
-                "libneuralnetworks_packageinfo", // base_system
-                "libnl", // generic_system
-                "libpdfium", // base_system
-                "libpolicy-subsystem", // generic_system
-                "libpower", // base_system
-                "libpowermanager", // base_system
-                "libprotobuf-cpp-full", // generic_system
-                "libradio_metadata", // base_system
-                "librs_jni", // handheld_system
-                "librtp_jni", // base_system
-                "libsensorservice", // base_system
-                "libsfplugin_ccodec", // base_system
-                "libskia", // base_system
-                "libsonic", // base_system
-                "libsonivox", // base_system
-                "libsoundpool", // base_system
-                "libspeexresampler", // base_system
-                "libsqlite", // base_system
-                "libstagefright", // base_system
-                "libstagefright_foundation", // base_system
-                "libstagefright_omx", // base_system
-                "libstdc++", // base_system
-                "libsysutils", // base_system
-                "libui", // base_system
-                "libusbhost", // base_system
-                "libutils", // base_system
-                "libvintf_jni", // base_system
-                "libvulkan", // base_system
-                "libwebviewchromium_loader", // media_system
-                "libwebviewchromium_plat_support", // media_system
-                "libwilhelm", // base_system
-                "linker", // base_system
-            ] + select(soong_config_variable("ANDROID", "TARGET_DYNAMIC_64_32_DRMSERVER"), {
-                "true": ["drmserver"],
-                default: [],
-            }) + select(soong_config_variable("ANDROID", "TARGET_DYNAMIC_64_32_MEDIASERVER"), {
-                "true": ["mediaserver"],
-                default: [],
-            }),
-        },
-    },
-}
-
-prebuilt_etc {
-    name: "android_vintf_manifest",
-    src: "manifest.xml",
-    filename: "manifest.xml",
-    relative_install_path: "vintf",
-    no_full_install: true,
-}
diff --git a/system_image/OWNERS b/system_image/OWNERS
deleted file mode 100644
index 6d1446f09..000000000
--- a/system_image/OWNERS
+++ /dev/null
@@ -1,6 +0,0 @@
-# Bug component: 1322713
-inseob@google.com
-jeongik@google.com
-jiyong@google.com
-justinyun@google.com
-kiyoungkim@google.com
diff --git a/system_image/linker.config.json b/system_image/linker.config.json
deleted file mode 100644
index 7253033e4..000000000
--- a/system_image/linker.config.json
+++ /dev/null
@@ -1,14 +0,0 @@
-{
-  "requireLibs": [
-    "libdexfiled.so",
-    "libjdwp.so",
-    // TODO(b/120786417 or b/134659294): libicuuc.so
-    // and libicui18n.so are kept for app compat.
-    "libicui18n.so",
-    "libicuuc.so"
-  ],
-  "provideLibs": [
-    "libaptX_encoder.so",
-    "libaptXHD_encoder.so"
-  ]
-}
diff --git a/system_image/manifest.xml b/system_image/manifest.xml
deleted file mode 100644
index 1df2c0d0c..000000000
--- a/system_image/manifest.xml
+++ /dev/null
@@ -1,54 +0,0 @@
-<!--
-    Input:
-        system/libhidl/vintfdata/manifest.xml
--->
-<manifest version="8.0" type="framework">
-    <hal format="hidl" max-level="6">
-        <name>android.frameworks.displayservice</name>
-        <transport>hwbinder</transport>
-        <fqname>@1.0::IDisplayService/default</fqname>
-    </hal>
-    <hal format="hidl" max-level="5">
-        <name>android.frameworks.schedulerservice</name>
-        <transport>hwbinder</transport>
-        <fqname>@1.0::ISchedulingPolicyService/default</fqname>
-    </hal>
-    <hal format="aidl">
-        <name>android.frameworks.sensorservice</name>
-        <fqname>ISensorManager/default</fqname>
-    </hal>
-    <hal format="hidl" max-level="8">
-        <name>android.frameworks.sensorservice</name>
-        <transport>hwbinder</transport>
-        <fqname>@1.0::ISensorManager/default</fqname>
-    </hal>
-    <hal format="hidl" max-level="8">
-        <name>android.hidl.memory</name>
-        <transport arch="32+64">passthrough</transport>
-        <fqname>@1.0::IMapper/ashmem</fqname>
-    </hal>
-    <hal format="hidl" max-level="7">
-        <name>android.system.net.netd</name>
-        <transport>hwbinder</transport>
-        <fqname>@1.1::INetd/default</fqname>
-    </hal>
-    <hal format="hidl" max-level="7">
-        <name>android.system.wifi.keystore</name>
-        <transport>hwbinder</transport>
-        <fqname>@1.0::IKeystore/default</fqname>
-    </hal>
-    <hal format="native">
-        <name>netutils-wrapper</name>
-        <version>1.0</version>
-    </hal>
-    <system-sdk>
-        <version>29</version>
-        <version>30</version>
-        <version>31</version>
-        <version>32</version>
-        <version>33</version>
-        <version>34</version>
-        <version>35</version>
-        <version>VanillaIceCream</version>
-    </system-sdk>
-</manifest>
diff --git a/tests/graphics/Android.bp b/tests/graphics/Android.bp
index 1f9735c34..e489161fd 100644
--- a/tests/graphics/Android.bp
+++ b/tests/graphics/Android.bp
@@ -31,9 +31,9 @@ java_test_host {
         "device-tests",
     ],
     libs: [
+        "compatibility-host-util",
         "cts-tradefed",
         "tradefed",
-        "compatibility-host-util",
     ],
     static_libs: [
         "cuttlefish_host_test_utils",
@@ -42,7 +42,7 @@ java_test_host {
         "auto_annotation_plugin",
         "auto_value_plugin",
     ],
-    data: [
+    device_common_data: [
         ":CuttlefishDisplayHotplugHelperApp",
     ],
 }
@@ -62,3 +62,25 @@ java_test_host {
         "tradefed",
     ],
 }
+
+java_test_host {
+    name: "CuttlefishVulkanSnapshotTests",
+    srcs: [
+        "src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java",
+    ],
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "tradefed",
+    ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
+    device_common_data: [
+        ":CuttlefishVulkanSamplesFullscreenColor",
+        ":CuttlefishVulkanSamplesFullscreenTexture",
+        ":CuttlefishVulkanSamplesSecondaryCommandBuffer",
+    ],
+}
diff --git a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java
new file mode 100644
index 000000000..f0f45e73c
--- /dev/null
+++ b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java
@@ -0,0 +1,297 @@
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
+package com.android.cuttlefish.tests;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.android.tradefed.config.Option;
+import com.android.tradefed.device.internal.DeviceResetHandler;
+import com.android.tradefed.device.internal.DeviceSnapshotHandler;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.ByteArrayInputStreamSource;
+import com.android.tradefed.result.InputStreamSource;
+import com.android.tradefed.result.LogDataType;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.google.auto.value.AutoValue;
+import java.awt.Color;
+import java.awt.image.BufferedImage;
+import java.io.ByteArrayOutputStream;
+import java.io.File;
+import java.util.Arrays;
+import java.util.List;
+import java.util.UUID;
+import javax.annotation.Nullable;
+import javax.imageio.ImageIO;
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.Description;
+import org.junit.runner.RunWith;
+import org.junit.runners.model.Statement;
+
+/**
+ * Test snapshot/restore function.
+ *
+ * <p>* This test resets the device thus it should not run with other tests in the same test suite
+ * to avoid unexpected behavior.
+ *
+ * <p>* The test logic relies on cvd and snapshot_util_cvd tools, so it can only run in a test lab
+ * setup.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
+    private static final String VK_SAMPLES_MAIN_ACTIVITY = "android.app.NativeActivity";
+
+    private static final String VK_SAMPLES_FULLSCREEN_COLOR_APK =
+        "CuttlefishVulkanSamplesFullscreenColor.apk";
+    private static final String VK_SAMPLES_FULLSCREEN_COLOR_PKG =
+        "com.android.cuttlefish.vulkan_samples.fullscreen_color";
+
+    private static final String VK_SAMPLES_FULLSCREEN_TEXTURE_APK =
+        "CuttlefishVulkanSamplesFullscreenTexture.apk";
+    private static final String VK_SAMPLES_FULLSCREEN_TEXTURE_PKG =
+        "com.android.cuttlefish.vulkan_samples.fullscreen_texture";
+
+    private static final String VK_SAMPLES_SECONDARY_COMMAND_BUFFER_APK =
+        "CuttlefishVulkanSamplesSecondaryCommandBuffer.apk";
+    private static final String VK_SAMPLES_SECONDARY_COMMAND_BUFFER_PKG =
+        "com.android.cuttlefish.vulkan_samples.secondary_command_buffer";
+
+    private static final List<String> VK_SAMPLE_APKS =
+        Arrays.asList(VK_SAMPLES_FULLSCREEN_COLOR_APK, //
+            VK_SAMPLES_FULLSCREEN_TEXTURE_APK, //
+            VK_SAMPLES_SECONDARY_COMMAND_BUFFER_APK);
+
+    private static final List<String> VK_SAMPLE_PKGS =
+        Arrays.asList(VK_SAMPLES_FULLSCREEN_COLOR_PKG, //
+            VK_SAMPLES_FULLSCREEN_TEXTURE_PKG, //
+            VK_SAMPLES_SECONDARY_COMMAND_BUFFER_PKG);
+
+    private static final int SCREENSHOT_CHECK_ATTEMPTS = 5;
+
+    private static final int SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS = 1000;
+
+    @Rule
+    public TestLogData mLogs = new TestLogData();
+
+    private void unlockDevice() throws Exception {
+        getDevice().executeShellCommand("input keyevent KEYCODE_WAKEUP");
+        getDevice().executeShellCommand("input keyevent KEYCODE_MENU");
+    }
+
+    // TODO: Move this into `device/google/cuttlefish/tests/utils` if it works?
+    @Rule
+    public final TestRule mUnlockScreenRule = new TestRule() {
+        @Override
+        public Statement apply(Statement base, Description description) {
+            return new Statement() {
+                @Override
+                public void evaluate() throws Throwable {
+                    unlockDevice();
+                    base.evaluate();
+                }
+            };
+        }
+    };
+
+    @Before
+    public void setUp() throws Exception {
+        for (String apk : VK_SAMPLE_PKGS) {
+            getDevice().uninstallPackage(apk);
+        }
+        for (String apk : VK_SAMPLE_APKS) {
+            installPackage(apk);
+        }
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        for (String apk : VK_SAMPLE_PKGS) {
+            getDevice().uninstallPackage(apk);
+        }
+    }
+
+    private void saveScreenshotToTestResults(String name, BufferedImage screenshot) throws Exception {
+        ByteArrayOutputStream bytesOutputStream = new ByteArrayOutputStream();
+        ImageIO.write(screenshot, "png", bytesOutputStream);
+        byte[] bytes = bytesOutputStream.toByteArray();
+        ByteArrayInputStreamSource bytesInputStream = new ByteArrayInputStreamSource(bytes);
+        mLogs.addTestLog(name, LogDataType.PNG, bytesInputStream);
+    }
+
+    private BufferedImage getScreenshot() throws Exception {
+        InputStreamSource screenshotStream = getDevice().getScreenshot();
+
+        assertThat(screenshotStream).isNotNull();
+
+        return ImageIO.read(screenshotStream.createInputStream());
+    }
+
+    // Vulkan implementations can support different levels of precision which can
+    // result in slight pixel differences. This threshold should be small but was
+    // otherwise chosen arbitrarily to allow for small differences.
+    private static final int PIXEL_DIFFERENCE_THRESHOLD = 16;
+
+    private boolean isApproximatelyEqual(Color actual, Color expected) {
+        int diff = Math.abs(actual.getRed() - expected.getRed())
+            + Math.abs(actual.getGreen() - expected.getGreen())
+            + Math.abs(actual.getBlue() - expected.getBlue());
+        return diff <= PIXEL_DIFFERENCE_THRESHOLD;
+    }
+
+    @AutoValue
+    public static abstract class ExpectedColor {
+        static ExpectedColor create(float u, float v, Color color) {
+            return new AutoValue_CuttlefishVulkanSnapshotTests_ExpectedColor(u, v, color);
+        }
+
+        abstract float u();
+        abstract float v();
+        abstract Color color();
+    }
+
+    @AutoValue
+    public static abstract class WaitForColorsResult {
+        static WaitForColorsResult create(@Nullable BufferedImage image) {
+            return new AutoValue_CuttlefishVulkanSnapshotTests_WaitForColorsResult(image);
+        }
+
+        @Nullable abstract BufferedImage failureImage();
+
+        boolean succeeded() { return failureImage() == null; }
+    }
+
+
+    private WaitForColorsResult waitForColors(List<ExpectedColor> expectedColors) throws Exception {
+        assertThat(expectedColors).isNotEmpty();
+
+        BufferedImage screenshot = null;
+
+        for (int attempt = 0; attempt < SCREENSHOT_CHECK_ATTEMPTS; attempt++) {
+            CLog.i("Grabbing screenshot (attempt %d of %d)", attempt, SCREENSHOT_CHECK_ATTEMPTS);
+
+            screenshot = getScreenshot();
+
+            final int screenshotW = screenshot.getWidth();
+            final int screenshotH = screenshot.getHeight();
+
+            boolean foundAllExpectedColors = true;
+            for (ExpectedColor expected : expectedColors) {
+                final float sampleU = expected.u();
+
+                // Images from `getDevice().getScreenshot()` seem to use the top left as the
+                // the origin. Flip-y here for what is (subjectively) the more natural origin.
+                final float sampleV = 1.0f - expected.v();
+
+                final int sampleX = (int) (sampleU * (float) screenshotW);
+                final int sampleY = (int) (sampleV * (float) screenshotH);
+
+                final Color sampledColor = new Color(screenshot.getRGB(sampleX, sampleY));
+                final Color expectedColor = expected.color();
+
+                if (!isApproximatelyEqual(sampledColor, expectedColor)) {
+                    CLog.i("Screenshot check %d failed at u:%f v:%f (x:%d y:%d with w:%d h:%d) "
+                            + "expected:%s actual:%s",
+                        attempt, sampleU, sampleV, sampleX, sampleY, screenshotW, screenshotH,
+                        expectedColor, sampledColor);
+                    foundAllExpectedColors = false;
+                }
+            }
+
+            if (foundAllExpectedColors) {
+                CLog.i("Screenshot attempt %d found all expected colors.", attempt);
+                return WaitForColorsResult.create(null);
+            }
+
+            CLog.i("Screenshot attempt %d did not find all expected colors. Sleeping for %d ms and "
+                    + "trying again.",
+                attempt, SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
+
+            Thread.sleep(SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
+        }
+
+        return WaitForColorsResult.create(screenshot);
+    }
+
+    private void runOneSnapshotTest(String pkg, List<ExpectedColor> expectedColors)
+        throws Exception {
+        final String snapshotId = "snapshot_" + UUID.randomUUID().toString();
+
+        // Reboot to make sure device isn't dirty from previous tests.
+        getDevice().reboot();
+
+        unlockDevice();
+
+        getDevice().executeShellCommand(
+            String.format("am start -n %s/%s", pkg, VK_SAMPLES_MAIN_ACTIVITY));
+
+        final WaitForColorsResult beforeSnapshotResult = waitForColors(expectedColors);
+        if (!beforeSnapshotResult.succeeded()) {
+            saveScreenshotToTestResults("before_snapshot_restore_screenshot", beforeSnapshotResult.failureImage());
+        }
+        assertThat(beforeSnapshotResult.succeeded()).isTrue();
+
+        // Snapshot the device
+        new DeviceSnapshotHandler().snapshotDevice(getDevice(), snapshotId);
+
+        try {
+            new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
+        } finally {
+            new DeviceSnapshotHandler().deleteSnapshot(getDevice(), snapshotId);
+        }
+
+        final WaitForColorsResult afterSnapshotRestoreResult = waitForColors(expectedColors);
+        if (!afterSnapshotRestoreResult.succeeded()) {
+            saveScreenshotToTestResults("after_snapshot_restore_screenshot", afterSnapshotRestoreResult.failureImage());
+        }
+        assertThat(afterSnapshotRestoreResult.succeeded()).isTrue();
+    }
+
+    @Test
+    public void testFullscreenColorSample() throws Exception {
+        final List<ExpectedColor> expectedColors =
+            Arrays.asList(ExpectedColor.create(0.5f, 0.5f, Color.RED));
+        runOneSnapshotTest(VK_SAMPLES_FULLSCREEN_COLOR_PKG, expectedColors);
+    }
+
+    @Test
+    public void testFullscreenTextureSample() throws Exception {
+        final List<ExpectedColor> expectedColors = Arrays.asList(
+            // clang-format off
+                ExpectedColor.create(0.25f, 0.25f, Color.RED),    // bottomLeft
+                ExpectedColor.create(0.75f, 0.25f, Color.GREEN),  // bottomRight
+                ExpectedColor.create(0.25f, 0.75f, Color.BLUE),   // topLeft
+                ExpectedColor.create(0.75f, 0.75f, Color.WHITE)   // topRight
+            // clang-format on
+        );
+        runOneSnapshotTest(VK_SAMPLES_FULLSCREEN_TEXTURE_PKG, expectedColors);
+    }
+
+    @Test
+    public void testSecondaryCommandBufferSample() throws Exception {
+        final List<ExpectedColor> expectedColors = Arrays.asList(
+            // clang-format off
+                ExpectedColor.create(0.5f, 0.5f, Color.RED)
+            // clang-format on
+        );
+        runOneSnapshotTest(VK_SAMPLES_SECONDARY_COMMAND_BUFFER_PKG, expectedColors);
+    }
+}
diff --git a/tests/graphics/vulkan/Android.bp b/tests/graphics/vulkan/Android.bp
new file mode 100644
index 000000000..4d4d42aa5
--- /dev/null
+++ b/tests/graphics/vulkan/Android.bp
@@ -0,0 +1,62 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+filegroup {
+    name: "libcuttlefish_vulkan_samples_default_srcs",
+    srcs: [
+        "image.cpp",
+        "main.cpp",
+        "sample_base.cpp",
+    ],
+}
+
+cc_library_headers {
+    name: "libcuttlefish_vulkan_samples_default_headers",
+    export_include_dirs: ["."],
+    min_sdk_version: "34",
+    sdk_version: "current",
+}
+
+cc_defaults {
+    name: "libcuttlefish_vulkan_samples_defaults",
+    srcs: [
+        ":libcuttlefish_vulkan_samples_default_srcs",
+    ],
+    header_libs: [
+        "libcuttlefish_vulkan_samples_default_headers",
+        "vulkan_headers",
+    ],
+    shared_libs: [
+        "libandroid",
+        "libc++",
+        "libjnigraphics",
+        "liblog",
+        "libnativehelper",
+    ],
+    static_libs: [
+        "libbase_ndk",
+    ],
+    whole_static_libs: [
+        "android_native_app_glue",
+    ],
+    cflags: [
+        "-DVK_USE_PLATFORM_ANDROID_KHR=1",
+    ],
+    min_sdk_version: "34",
+    sdk_version: "current",
+}
diff --git a/tests/graphics/vulkan/common.h b/tests/graphics/vulkan/common.h
new file mode 100644
index 000000000..1f34da46b
--- /dev/null
+++ b/tests/graphics/vulkan/common.h
@@ -0,0 +1,19 @@
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
+#pragma once
+
+#define LOG_TAG "VulkanSample"
+#include <android/log.h>
+#include <android/log_macros.h>
diff --git a/tests/graphics/vulkan/fullscreen_color/Android.bp b/tests/graphics/vulkan/fullscreen_color/Android.bp
new file mode 100644
index 000000000..5ad0fa6ad
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/Android.bp
@@ -0,0 +1,29 @@
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
+cc_library_shared {
+    name: "libcuttlefish_vulkan_samples_fullscreen_color",
+    defaults: ["libcuttlefish_vulkan_samples_defaults"],
+    srcs: [
+        "fullscreen_color.cpp",
+    ],
+}
+
+android_app {
+    name: "CuttlefishVulkanSamplesFullscreenColor",
+    min_sdk_version: "34",
+    sdk_version: "current",
+    jni_libs: ["libcuttlefish_vulkan_samples_fullscreen_color"],
+    use_embedded_native_libs: true,
+}
diff --git a/tests/graphics/vulkan/fullscreen_color/AndroidManifest.xml b/tests/graphics/vulkan/fullscreen_color/AndroidManifest.xml
new file mode 100644
index 000000000..dfdeb6b0e
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/AndroidManifest.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+ -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.cuttlefish.vulkan_samples.fullscreen_color">
+
+    <application android:appCategory="game">
+        <activity android:name="android.app.NativeActivity"
+                  android:label="Fullscreen Color"
+                  android:exported="true"
+                  android:turnScreenOn="true"
+                  android:configChanges="keyboardHidden"
+                  android:theme="@android:style/Theme.Holo.NoActionBar.Fullscreen">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
+            </intent-filter>
+            <meta-data
+                    android:name="android.app.lib_name"
+                    android:value="cuttlefish_vulkan_samples_fullscreen_color" />
+        </activity>
+    </application>
+</manifest>
\ No newline at end of file
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.cpp b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.cpp
new file mode 100644
index 000000000..f2c9c863d
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.cpp
@@ -0,0 +1,347 @@
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
+#include "fullscreen_color.h"
+
+namespace cuttlefish {
+namespace {
+
+#include "fullscreen_color.frag.inl"
+#include "fullscreen_color.vert.inl"
+
+}  // namespace
+
+Result<std::unique_ptr<SampleBase>> BuildVulkanSampleApp() {
+  return FullscreenColor::Create();
+}
+
+/*static*/
+Result<std::unique_ptr<SampleBase>> FullscreenColor::Create() {
+  std::unique_ptr<SampleBase> sample(new FullscreenColor());
+  VK_EXPECT(sample->StartUp());
+  return sample;
+}
+
+Result<Ok> FullscreenColor::StartUp() {
+  VK_EXPECT(StartUpBase());
+
+  const vkhpp::PipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
+      .setLayoutCount = 0,
+  };
+  mPipelineLayout = VK_EXPECT_RV(
+      mDevice->createPipelineLayoutUnique(pipelineLayoutCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo vertShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kFullscreenColorVert.size()),
+      .pCode = reinterpret_cast<const uint32_t*>(kFullscreenColorVert.data()),
+  };
+  mVertShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(vertShaderCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo fragShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kFullscreenColorFrag.size()),
+      .pCode = reinterpret_cast<const uint32_t*>(kFullscreenColorFrag.data()),
+  };
+  mFragShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(fragShaderCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenColor::CleanUp() {
+  VK_EXPECT(CleanUpBase());
+
+  mDevice->waitIdle();
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenColor::CreateSwapchainDependents(
+    const SwapchainInfo& swapchainInfo) {
+  const std::vector<vkhpp::AttachmentDescription> renderpassAttachments = {
+      {
+          .format = swapchainInfo.swapchainFormat,
+          .samples = vkhpp::SampleCountFlagBits::e1,
+          .loadOp = vkhpp::AttachmentLoadOp::eClear,
+          .storeOp = vkhpp::AttachmentStoreOp::eStore,
+          .stencilLoadOp = vkhpp::AttachmentLoadOp::eClear,
+          .stencilStoreOp = vkhpp::AttachmentStoreOp::eStore,
+          .initialLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+          .finalLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+      },
+  };
+  const vkhpp::AttachmentReference renderpassColorAttachmentRef = {
+      .attachment = 0,
+      .layout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+  };
+  const vkhpp::SubpassDescription renderpassSubpass = {
+      .pipelineBindPoint = vkhpp::PipelineBindPoint::eGraphics,
+      .inputAttachmentCount = 0,
+      .pInputAttachments = nullptr,
+      .colorAttachmentCount = 1,
+      .pColorAttachments = &renderpassColorAttachmentRef,
+      .pResolveAttachments = nullptr,
+      .pDepthStencilAttachment = nullptr,
+      .pPreserveAttachments = nullptr,
+  };
+  const vkhpp::SubpassDependency renderpassSubpassDependency = {
+      .srcSubpass = VK_SUBPASS_EXTERNAL,
+      .dstSubpass = 0,
+      .srcStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .srcAccessMask = {},
+      .dstStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .dstAccessMask = vkhpp::AccessFlagBits::eColorAttachmentWrite,
+  };
+  const vkhpp::RenderPassCreateInfo renderpassCreateInfo = {
+      .attachmentCount = static_cast<uint32_t>(renderpassAttachments.size()),
+      .pAttachments = renderpassAttachments.data(),
+      .subpassCount = 1,
+      .pSubpasses = &renderpassSubpass,
+      .dependencyCount = 1,
+      .pDependencies = &renderpassSubpassDependency,
+  };
+  mRenderpass =
+      VK_EXPECT_RV(mDevice->createRenderPassUnique(renderpassCreateInfo));
+
+  for (const auto imageView : swapchainInfo.swapchainImageViews) {
+    const std::vector<vkhpp::ImageView> framebufferAttachments = {
+        imageView,
+    };
+    const vkhpp::FramebufferCreateInfo framebufferCreateInfo = {
+        .renderPass = *mRenderpass,
+        .attachmentCount = static_cast<uint32_t>(framebufferAttachments.size()),
+        .pAttachments = framebufferAttachments.data(),
+        .width = swapchainInfo.swapchainExtent.width,
+        .height = swapchainInfo.swapchainExtent.height,
+        .layers = 1,
+    };
+    auto framebuffer =
+        VK_EXPECT_RV(mDevice->createFramebufferUnique(framebufferCreateInfo));
+    mSwapchainImageObjects.push_back(SwapchainImageObjects{
+        .extent = swapchainInfo.swapchainExtent,
+        .framebuffer = std::move(framebuffer),
+    });
+  }
+
+  const std::vector<vkhpp::PipelineShaderStageCreateInfo> pipelineStages = {
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eVertex,
+          .module = *mVertShaderModule,
+          .pName = "main",
+      },
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eFragment,
+          .module = *mFragShaderModule,
+          .pName = "main",
+      },
+  };
+
+  const vkhpp::PipelineVertexInputStateCreateInfo
+      pipelineVertexInputStateCreateInfo = {};
+  const vkhpp::PipelineInputAssemblyStateCreateInfo
+      pipelineInputAssemblyStateCreateInfo = {
+          .topology = vkhpp::PrimitiveTopology::eTriangleStrip,
+      };
+  const vkhpp::PipelineViewportStateCreateInfo pipelineViewportStateCreateInfo =
+      {
+          .viewportCount = 1,
+          .pViewports = nullptr,
+          .scissorCount = 1,
+          .pScissors = nullptr,
+      };
+  const vkhpp::PipelineRasterizationStateCreateInfo
+      pipelineRasterStateCreateInfo = {
+          .depthClampEnable = VK_FALSE,
+          .rasterizerDiscardEnable = VK_FALSE,
+          .polygonMode = vkhpp::PolygonMode::eFill,
+          .cullMode = {},
+          .frontFace = vkhpp::FrontFace::eCounterClockwise,
+          .depthBiasEnable = VK_FALSE,
+          .depthBiasConstantFactor = 0.0f,
+          .depthBiasClamp = 0.0f,
+          .depthBiasSlopeFactor = 0.0f,
+          .lineWidth = 1.0f,
+      };
+  const vkhpp::SampleMask pipelineSampleMask = 65535;
+  const vkhpp::PipelineMultisampleStateCreateInfo
+      pipelineMultisampleStateCreateInfo = {
+          .rasterizationSamples = vkhpp::SampleCountFlagBits::e1,
+          .sampleShadingEnable = VK_FALSE,
+          .minSampleShading = 1.0f,
+          .pSampleMask = &pipelineSampleMask,
+          .alphaToCoverageEnable = VK_FALSE,
+          .alphaToOneEnable = VK_FALSE,
+      };
+  const vkhpp::PipelineDepthStencilStateCreateInfo
+      pipelineDepthStencilStateCreateInfo = {
+          .depthTestEnable = VK_FALSE,
+          .depthWriteEnable = VK_FALSE,
+          .depthCompareOp = vkhpp::CompareOp::eLess,
+          .depthBoundsTestEnable = VK_FALSE,
+          .stencilTestEnable = VK_FALSE,
+          .front =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .back =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .minDepthBounds = 0.0f,
+          .maxDepthBounds = 0.0f,
+      };
+  const std::vector<vkhpp::PipelineColorBlendAttachmentState>
+      pipelineColorBlendAttachments = {
+          vkhpp::PipelineColorBlendAttachmentState{
+              .blendEnable = VK_FALSE,
+              .srcColorBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstColorBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .colorBlendOp = vkhpp::BlendOp::eAdd,
+              .srcAlphaBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstAlphaBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .alphaBlendOp = vkhpp::BlendOp::eAdd,
+              .colorWriteMask = vkhpp::ColorComponentFlagBits::eR |
+                                vkhpp::ColorComponentFlagBits::eG |
+                                vkhpp::ColorComponentFlagBits::eB |
+                                vkhpp::ColorComponentFlagBits::eA,
+          },
+      };
+  const vkhpp::PipelineColorBlendStateCreateInfo
+      pipelineColorBlendStateCreateInfo = {
+          .logicOpEnable = VK_FALSE,
+          .logicOp = vkhpp::LogicOp::eCopy,
+          .attachmentCount =
+              static_cast<uint32_t>(pipelineColorBlendAttachments.size()),
+          .pAttachments = pipelineColorBlendAttachments.data(),
+          .blendConstants = {{
+              0.0f,
+              0.0f,
+              0.0f,
+              0.0f,
+          }},
+      };
+  const std::vector<vkhpp::DynamicState> pipelineDynamicStates = {
+      vkhpp::DynamicState::eViewport,
+      vkhpp::DynamicState::eScissor,
+  };
+  const vkhpp::PipelineDynamicStateCreateInfo pipelineDynamicStateCreateInfo = {
+      .dynamicStateCount = static_cast<uint32_t>(pipelineDynamicStates.size()),
+      .pDynamicStates = pipelineDynamicStates.data(),
+  };
+  const vkhpp::GraphicsPipelineCreateInfo pipelineCreateInfo = {
+      .stageCount = static_cast<uint32_t>(pipelineStages.size()),
+      .pStages = pipelineStages.data(),
+      .pVertexInputState = &pipelineVertexInputStateCreateInfo,
+      .pInputAssemblyState = &pipelineInputAssemblyStateCreateInfo,
+      .pTessellationState = nullptr,
+      .pViewportState = &pipelineViewportStateCreateInfo,
+      .pRasterizationState = &pipelineRasterStateCreateInfo,
+      .pMultisampleState = &pipelineMultisampleStateCreateInfo,
+      .pDepthStencilState = &pipelineDepthStencilStateCreateInfo,
+      .pColorBlendState = &pipelineColorBlendStateCreateInfo,
+      .pDynamicState = &pipelineDynamicStateCreateInfo,
+      .layout = *mPipelineLayout,
+      .renderPass = *mRenderpass,
+      .subpass = 0,
+      .basePipelineHandle = VK_NULL_HANDLE,
+      .basePipelineIndex = 0,
+  };
+  mPipeline = VK_EXPECT_RV(
+      mDevice->createGraphicsPipelineUnique({}, pipelineCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenColor::DestroySwapchainDependents() {
+  mPipeline.reset();
+  mSwapchainImageObjects.clear();
+  mRenderpass.reset();
+  return Ok{};
+}
+
+Result<Ok> FullscreenColor::RecordFrame(const FrameInfo& frame) {
+  vkhpp::CommandBuffer commandBuffer = frame.commandBuffer;
+
+  const SwapchainImageObjects& swapchainObjects =
+      mSwapchainImageObjects[frame.swapchainImageIndex];
+
+  const std::vector<vkhpp::ClearValue> renderPassBeginClearValues = {
+      vkhpp::ClearValue{
+          .color =
+              {
+                  .float32 = {{1.0f, 0.0f, 0.0f, 1.0f}},
+              },
+      },
+  };
+  const vkhpp::RenderPassBeginInfo renderPassBeginInfo = {
+      .renderPass = *mRenderpass,
+      .framebuffer = *swapchainObjects.framebuffer,
+      .renderArea =
+          {
+              .offset =
+                  {
+                      .x = 0,
+                      .y = 0,
+                  },
+              .extent = swapchainObjects.extent,
+          },
+      .clearValueCount =
+          static_cast<uint32_t>(renderPassBeginClearValues.size()),
+      .pClearValues = renderPassBeginClearValues.data(),
+  };
+  commandBuffer.beginRenderPass(renderPassBeginInfo,
+                                vkhpp::SubpassContents::eInline);
+
+  commandBuffer.bindPipeline(vkhpp::PipelineBindPoint::eGraphics, *mPipeline);
+
+  const vkhpp::Viewport viewport = {
+      .x = 0.0f,
+      .y = 0.0f,
+      .width = static_cast<float>(swapchainObjects.extent.width),
+      .height = static_cast<float>(swapchainObjects.extent.height),
+      .minDepth = 0.0f,
+      .maxDepth = 1.0f,
+  };
+  commandBuffer.setViewport(0, {viewport});
+
+  const vkhpp::Rect2D scissor = {
+      .offset =
+          {
+              .x = 0,
+              .y = 0,
+          },
+      .extent = swapchainObjects.extent,
+  };
+  commandBuffer.setScissor(0, {scissor});
+
+  commandBuffer.draw(4, 1, 0, 0);
+
+  commandBuffer.endRenderPass();
+
+  return Ok{};
+}
+
+}  // namespace cuttlefish
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag
new file mode 100644
index 000000000..dcaea2749
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag
@@ -0,0 +1,7 @@
+#version 460
+
+layout(location = 0) out vec4 oColor;
+
+void main() {
+    oColor = vec4(1.0, 0.0, 0.0, 1.0);
+}
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.inl b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.inl
new file mode 100644
index 000000000..98b888ca6
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.inl
@@ -0,0 +1,39 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// layout(location = 0) out vec4 oColor;
+// 
+// void main() {
+//     oColor = vec4(1.0, 0.0, 0.0, 1.0);
+// }
+const std::vector<uint8_t> kFullscreenColorFrag = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x0d, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 
+	0x04, 0x00, 0x0a, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x63, 0x70, 
+	0x70, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x64, 0x69, 0x72, 
+	0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x47, 0x4c, 0x5f, 0x47, 
+	0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x64, 0x69, 
+	0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 
+	0x6f, 0x43, 0x6f, 0x6c, 0x6f, 0x72, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 
+	0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x0a, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 
+	0x3e, 0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x01, 0x00, 
+	0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.spv b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.spv
new file mode 100644
index 000000000..e51084af8
Binary files /dev/null and b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.frag.spv differ
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.h b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.h
new file mode 100644
index 000000000..94282995a
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.h
@@ -0,0 +1,50 @@
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
+#pragma once
+
+#include "common.h"
+#include "sample_base.h"
+
+namespace cuttlefish {
+
+class FullscreenColor : public SampleBase {
+ public:
+  static Result<std::unique_ptr<SampleBase>> Create();
+
+  Result<Ok> StartUp() override;
+  Result<Ok> CleanUp() override;
+
+  Result<Ok> CreateSwapchainDependents(const SwapchainInfo& /*info*/) override;
+  Result<Ok> DestroySwapchainDependents() override;
+
+  Result<Ok> RecordFrame(const FrameInfo& frame) override;
+
+ private:
+  FullscreenColor() = default;
+
+  vkhpp::UniqueRenderPass mRenderpass;
+  struct SwapchainImageObjects {
+    vkhpp::Extent2D extent;
+    vkhpp::UniqueFramebuffer framebuffer;
+  };
+  std::vector<SwapchainImageObjects> mSwapchainImageObjects;
+
+  vkhpp::UniqueShaderModule mVertShaderModule;
+  vkhpp::UniqueShaderModule mFragShaderModule;
+  vkhpp::UniquePipelineLayout mPipelineLayout;
+  vkhpp::UniquePipeline mPipeline;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert
new file mode 100644
index 000000000..6cc43e7b0
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert
@@ -0,0 +1,12 @@
+#version 460
+
+vec2 kPositions[4] = vec2[](
+    vec2(-1.0,  1.0),
+    vec2(-1.0, -1.0),
+    vec2( 1.0,  1.0),
+    vec2( 1.0, -1.0)
+);
+
+void main() {
+    gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+}
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.inl b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.inl
new file mode 100644
index 000000000..c45e123e0
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.inl
@@ -0,0 +1,91 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// vec2 kPositions[4] = vec2[](
+//     vec2(-1.0,  1.0),
+//     vec2(-1.0, -1.0),
+//     vec2( 1.0,  1.0),
+//     vec2( 1.0, -1.0)
+// );
+// 
+// void main() {
+//     gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+// }
+const std::vector<uint8_t> kFullscreenColorVert = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 
+	0x02, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x47, 0x4c, 0x5f, 0x47, 
+	0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x63, 0x70, 0x70, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x5f, 
+	0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x00, 
+	0x04, 0x00, 0x08, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x69, 0x6e, 
+	0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 
+	0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 
+	0x05, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x6b, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 
+	0x6e, 0x73, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x17, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 
+	0x65, 0x72, 0x56, 0x65, 0x72, 0x74, 0x65, 0x78, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 0x6f, 0x73, 0x69, 0x74, 
+	0x69, 0x6f, 0x6e, 0x00, 0x06, 0x00, 0x07, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x67, 0x6c, 0x5f, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x07, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x43, 
+	0x6c, 0x69, 0x70, 0x44, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x06, 0x00, 0x07, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x43, 0x75, 0x6c, 0x6c, 0x44, 
+	0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x05, 0x00, 0x03, 0x00, 0x19, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x56, 
+	0x65, 0x72, 0x74, 0x65, 0x78, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
+	0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x47, 0x00, 0x03, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xbf, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 
+	0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
+	0x12, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x04, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x16, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x15, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x06, 0x00, 0x17, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x18, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 
+	0x18, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x1f, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x26, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 
+	0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
+	0xf8, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x41, 0x00, 0x05, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x51, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x23, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x00, 0x05, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x50, 0x00, 0x07, 0x00, 0x14, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x24, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x41, 0x00, 0x05, 0x00, 
+	0x26, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 
+	0x3e, 0x00, 0x03, 0x00, 0x27, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x01, 0x00, 
+	0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.spv b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.spv
new file mode 100644
index 000000000..b7c2cd77e
Binary files /dev/null and b/tests/graphics/vulkan/fullscreen_color/fullscreen_color.vert.spv differ
diff --git a/tests/graphics/vulkan/fullscreen_texture/Android.bp b/tests/graphics/vulkan/fullscreen_texture/Android.bp
new file mode 100644
index 000000000..d945b01c4
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/Android.bp
@@ -0,0 +1,29 @@
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
+cc_library_shared {
+    name: "libcuttlefish_vulkan_samples_fullscreen_texture",
+    defaults: ["libcuttlefish_vulkan_samples_defaults"],
+    srcs: [
+        "fullscreen_texture.cpp",
+    ],
+}
+
+android_app {
+    name: "CuttlefishVulkanSamplesFullscreenTexture",
+    min_sdk_version: "34",
+    sdk_version: "current",
+    jni_libs: ["libcuttlefish_vulkan_samples_fullscreen_texture"],
+    use_embedded_native_libs: true,
+}
diff --git a/tests/graphics/vulkan/fullscreen_texture/AndroidManifest.xml b/tests/graphics/vulkan/fullscreen_texture/AndroidManifest.xml
new file mode 100644
index 000000000..d10bf6151
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/AndroidManifest.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+ -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.cuttlefish.vulkan_samples.fullscreen_texture">
+
+    <application android:appCategory="game">
+        <activity android:name="android.app.NativeActivity"
+                  android:label="Fullscreen Texture"
+                  android:exported="true"
+                  android:turnScreenOn="true"
+                  android:configChanges="keyboardHidden"
+                  android:theme="@android:style/Theme.Holo.NoActionBar.Fullscreen">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
+            </intent-filter>
+            <meta-data
+                    android:name="android.app.lib_name"
+                    android:value="cuttlefish_vulkan_samples_fullscreen_texture" />
+        </activity>
+    </application>
+</manifest>
\ No newline at end of file
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.cpp b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.cpp
new file mode 100644
index 000000000..9a7eb8c34
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.cpp
@@ -0,0 +1,467 @@
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
+#include "fullscreen_texture.h"
+
+#include "image.h"
+
+namespace cuttlefish {
+namespace {
+
+#include "fullscreen_texture.frag.inl"
+#include "fullscreen_texture.vert.inl"
+
+}  // namespace
+
+Result<std::unique_ptr<SampleBase>> BuildVulkanSampleApp() {
+  return FullscreenTexture::Create();
+}
+
+/*static*/
+Result<std::unique_ptr<SampleBase>> FullscreenTexture::Create() {
+  std::unique_ptr<SampleBase> sample(new FullscreenTexture());
+  VK_EXPECT(sample->StartUp());
+  return sample;
+}
+
+Result<Ok> FullscreenTexture::StartUp() {
+  VK_EXPECT(StartUpBase());
+
+  const uint32_t imageWidth = 32;
+  const uint32_t imageHeight = 32;
+
+  mTexture = VK_EXPECT(CreateImage(imageWidth, imageHeight,
+                                   vkhpp::Format::eR8G8B8A8Unorm,
+                                   vkhpp::ImageUsageFlagBits::eSampled |
+                                       vkhpp::ImageUsageFlagBits::eTransferDst,
+                                   vkhpp::MemoryPropertyFlagBits::eDeviceLocal,
+                                   vkhpp::ImageLayout::eTransferDstOptimal));
+
+  const std::vector<uint8_t> imageContents = CreateImageContentsWithFourCorners(
+      imageWidth, imageHeight,
+      // clang-format off
+        /*bottomLeft=*/  RGBA8888{.r = 255, .g =    0, .b =   0, .a = 255},
+        /*bottomRight=*/ RGBA8888{.r =   0, .g =  255, .b =   0, .a = 255},
+        /*topLeft=*/     RGBA8888{.r =   0, .g =    0, .b = 255, .a = 255},
+        /*topRight=*/    RGBA8888{.r = 255, .g =  255, .b = 255, .a = 255}  // clang-format on
+  );
+
+  VK_EXPECT(
+      LoadImage(mTexture.image, imageWidth, imageHeight, imageContents,
+                /*currentLayout=*/vkhpp::ImageLayout::eTransferDstOptimal,
+                /*returnedLayout=*/vkhpp::ImageLayout::eShaderReadOnlyOptimal));
+
+  const vkhpp::SamplerCreateInfo samplerCreateInfo = {
+      .magFilter = vkhpp::Filter::eNearest,
+      .minFilter = vkhpp::Filter::eNearest,
+      .mipmapMode = vkhpp::SamplerMipmapMode::eNearest,
+      .addressModeU = vkhpp::SamplerAddressMode::eClampToEdge,
+      .addressModeV = vkhpp::SamplerAddressMode::eClampToEdge,
+      .addressModeW = vkhpp::SamplerAddressMode::eClampToEdge,
+      .mipLodBias = 0.0f,
+      .anisotropyEnable = VK_FALSE,
+      .maxAnisotropy = 1.0f,
+      .compareEnable = VK_FALSE,
+      .compareOp = vkhpp::CompareOp::eLessOrEqual,
+      .minLod = 0.0f,
+      .maxLod = 0.25f,
+      .borderColor = vkhpp::BorderColor::eIntTransparentBlack,
+      .unnormalizedCoordinates = VK_FALSE,
+  };
+  mTextureSampler =
+      VK_EXPECT_RV(mDevice->createSamplerUnique(samplerCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo vertShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kFullscreenTextureVert.size()),
+      .pCode = reinterpret_cast<const uint32_t*>(kFullscreenTextureVert.data()),
+  };
+  mVertShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(vertShaderCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo fragShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kFullscreenTextureFrag.size()),
+      .pCode = reinterpret_cast<const uint32_t*>(kFullscreenTextureFrag.data()),
+  };
+  mFragShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(fragShaderCreateInfo));
+
+  const vkhpp::Sampler descriptorSet0Binding0Sampler = *mTextureSampler;
+  const std::vector<vkhpp::DescriptorSetLayoutBinding> descriptorSet0Bindings =
+      {
+          vkhpp::DescriptorSetLayoutBinding{
+              .binding = 0,
+              .descriptorType = vkhpp::DescriptorType::eCombinedImageSampler,
+              .descriptorCount = 1,
+              .stageFlags = vkhpp::ShaderStageFlagBits::eFragment,
+              .pImmutableSamplers = &descriptorSet0Binding0Sampler,
+          },
+      };
+  const vkhpp::DescriptorSetLayoutCreateInfo descriptorSet0CreateInfo = {
+      .bindingCount = static_cast<uint32_t>(descriptorSet0Bindings.size()),
+      .pBindings = descriptorSet0Bindings.data(),
+  };
+  mDescriptorSet0Layout = VK_EXPECT_RV(
+      mDevice->createDescriptorSetLayoutUnique(descriptorSet0CreateInfo));
+
+  const std::vector<vkhpp::DescriptorPoolSize> descriptorPoolSizes = {
+      vkhpp::DescriptorPoolSize{
+          .type = vkhpp::DescriptorType::eCombinedImageSampler,
+          .descriptorCount = 1,
+      },
+  };
+  const vkhpp::DescriptorPoolCreateInfo descriptorPoolCreateInfo = {
+      .flags = vkhpp::DescriptorPoolCreateFlagBits::eFreeDescriptorSet,
+      .maxSets = 1,
+      .poolSizeCount = static_cast<uint32_t>(descriptorPoolSizes.size()),
+      .pPoolSizes = descriptorPoolSizes.data(),
+  };
+  mDescriptorSet0Pool = VK_EXPECT_RV(
+      mDevice->createDescriptorPoolUnique(descriptorPoolCreateInfo));
+
+  const vkhpp::DescriptorSetLayout descriptorSet0LayoutHandle =
+      *mDescriptorSet0Layout;
+  const vkhpp::DescriptorSetAllocateInfo descriptorSet0AllocateInfo = {
+      .descriptorPool = *mDescriptorSet0Pool,
+      .descriptorSetCount = 1,
+      .pSetLayouts = &descriptorSet0LayoutHandle,
+  };
+  auto descriptorSets = VK_EXPECT_RV(
+      mDevice->allocateDescriptorSetsUnique(descriptorSet0AllocateInfo));
+  mDescriptorSet0 = std::move(descriptorSets[0]);
+
+  const vkhpp::DescriptorImageInfo descriptorSet0Binding0ImageInfo = {
+      .sampler = VK_NULL_HANDLE,
+      .imageView = *mTexture.imageView,
+      .imageLayout = vkhpp::ImageLayout::eShaderReadOnlyOptimal,
+  };
+  const std::vector<vkhpp::WriteDescriptorSet> descriptorSet0Writes = {
+      vkhpp::WriteDescriptorSet{
+          .dstSet = *mDescriptorSet0,
+          .dstBinding = 0,
+          .dstArrayElement = 0,
+          .descriptorCount = 1,
+          .descriptorType = vkhpp::DescriptorType::eCombinedImageSampler,
+          .pImageInfo = &descriptorSet0Binding0ImageInfo,
+          .pBufferInfo = nullptr,
+          .pTexelBufferView = nullptr,
+      },
+  };
+  mDevice->updateDescriptorSets(descriptorSet0Writes, {});
+
+  const std::vector<vkhpp::DescriptorSetLayout>
+      pipelineLayoutDescriptorSetLayouts = {
+          *mDescriptorSet0Layout,
+      };
+  const vkhpp::PipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
+      .setLayoutCount =
+          static_cast<uint32_t>(pipelineLayoutDescriptorSetLayouts.size()),
+      .pSetLayouts = pipelineLayoutDescriptorSetLayouts.data(),
+  };
+  mPipelineLayout = VK_EXPECT_RV(
+      mDevice->createPipelineLayoutUnique(pipelineLayoutCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenTexture::CleanUp() {
+  VK_EXPECT(CleanUpBase());
+
+  mDevice->waitIdle();
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenTexture::CreateSwapchainDependents(
+    const SwapchainInfo& swapchainInfo) {
+  const std::vector<vkhpp::AttachmentDescription> renderpassAttachments = {
+      {
+          .format = swapchainInfo.swapchainFormat,
+          .samples = vkhpp::SampleCountFlagBits::e1,
+          .loadOp = vkhpp::AttachmentLoadOp::eClear,
+          .storeOp = vkhpp::AttachmentStoreOp::eStore,
+          .stencilLoadOp = vkhpp::AttachmentLoadOp::eClear,
+          .stencilStoreOp = vkhpp::AttachmentStoreOp::eStore,
+          .initialLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+          .finalLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+      },
+  };
+  const vkhpp::AttachmentReference renderpassColorAttachmentRef = {
+      .attachment = 0,
+      .layout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+  };
+  const vkhpp::SubpassDescription renderpassSubpass = {
+      .pipelineBindPoint = vkhpp::PipelineBindPoint::eGraphics,
+      .inputAttachmentCount = 0,
+      .pInputAttachments = nullptr,
+      .colorAttachmentCount = 1,
+      .pColorAttachments = &renderpassColorAttachmentRef,
+      .pResolveAttachments = nullptr,
+      .pDepthStencilAttachment = nullptr,
+      .pPreserveAttachments = nullptr,
+  };
+  const vkhpp::SubpassDependency renderpassSubpassDependency = {
+      .srcSubpass = VK_SUBPASS_EXTERNAL,
+      .dstSubpass = 0,
+      .srcStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .srcAccessMask = {},
+      .dstStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .dstAccessMask = vkhpp::AccessFlagBits::eColorAttachmentWrite,
+  };
+  const vkhpp::RenderPassCreateInfo renderpassCreateInfo = {
+      .attachmentCount = static_cast<uint32_t>(renderpassAttachments.size()),
+      .pAttachments = renderpassAttachments.data(),
+      .subpassCount = 1,
+      .pSubpasses = &renderpassSubpass,
+      .dependencyCount = 1,
+      .pDependencies = &renderpassSubpassDependency,
+  };
+  mRenderpass =
+      VK_EXPECT_RV(mDevice->createRenderPassUnique(renderpassCreateInfo));
+
+  for (const auto imageView : swapchainInfo.swapchainImageViews) {
+    const std::vector<vkhpp::ImageView> framebufferAttachments = {
+        imageView,
+    };
+    const vkhpp::FramebufferCreateInfo framebufferCreateInfo = {
+        .renderPass = *mRenderpass,
+        .attachmentCount = static_cast<uint32_t>(framebufferAttachments.size()),
+        .pAttachments = framebufferAttachments.data(),
+        .width = swapchainInfo.swapchainExtent.width,
+        .height = swapchainInfo.swapchainExtent.height,
+        .layers = 1,
+    };
+    auto framebuffer =
+        VK_EXPECT_RV(mDevice->createFramebufferUnique(framebufferCreateInfo));
+    mSwapchainImageObjects.push_back(SwapchainImageObjects{
+        .extent = swapchainInfo.swapchainExtent,
+        .framebuffer = std::move(framebuffer),
+    });
+  }
+
+  const std::vector<vkhpp::PipelineShaderStageCreateInfo> pipelineStages = {
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eVertex,
+          .module = *mVertShaderModule,
+          .pName = "main",
+      },
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eFragment,
+          .module = *mFragShaderModule,
+          .pName = "main",
+      },
+  };
+
+  const vkhpp::PipelineVertexInputStateCreateInfo
+      pipelineVertexInputStateCreateInfo = {};
+  const vkhpp::PipelineInputAssemblyStateCreateInfo
+      pipelineInputAssemblyStateCreateInfo = {
+          .topology = vkhpp::PrimitiveTopology::eTriangleStrip,
+      };
+  const vkhpp::PipelineViewportStateCreateInfo pipelineViewportStateCreateInfo =
+      {
+          .viewportCount = 1,
+          .pViewports = nullptr,
+          .scissorCount = 1,
+          .pScissors = nullptr,
+      };
+  const vkhpp::PipelineRasterizationStateCreateInfo
+      pipelineRasterStateCreateInfo = {
+          .depthClampEnable = VK_FALSE,
+          .rasterizerDiscardEnable = VK_FALSE,
+          .polygonMode = vkhpp::PolygonMode::eFill,
+          .cullMode = {},
+          .frontFace = vkhpp::FrontFace::eCounterClockwise,
+          .depthBiasEnable = VK_FALSE,
+          .depthBiasConstantFactor = 0.0f,
+          .depthBiasClamp = 0.0f,
+          .depthBiasSlopeFactor = 0.0f,
+          .lineWidth = 1.0f,
+      };
+  const vkhpp::SampleMask pipelineSampleMask = 65535;
+  const vkhpp::PipelineMultisampleStateCreateInfo
+      pipelineMultisampleStateCreateInfo = {
+          .rasterizationSamples = vkhpp::SampleCountFlagBits::e1,
+          .sampleShadingEnable = VK_FALSE,
+          .minSampleShading = 1.0f,
+          .pSampleMask = &pipelineSampleMask,
+          .alphaToCoverageEnable = VK_FALSE,
+          .alphaToOneEnable = VK_FALSE,
+      };
+  const vkhpp::PipelineDepthStencilStateCreateInfo
+      pipelineDepthStencilStateCreateInfo = {
+          .depthTestEnable = VK_FALSE,
+          .depthWriteEnable = VK_FALSE,
+          .depthCompareOp = vkhpp::CompareOp::eLess,
+          .depthBoundsTestEnable = VK_FALSE,
+          .stencilTestEnable = VK_FALSE,
+          .front =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .back =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .minDepthBounds = 0.0f,
+          .maxDepthBounds = 0.0f,
+      };
+  const std::vector<vkhpp::PipelineColorBlendAttachmentState>
+      pipelineColorBlendAttachments = {
+          vkhpp::PipelineColorBlendAttachmentState{
+              .blendEnable = VK_FALSE,
+              .srcColorBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstColorBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .colorBlendOp = vkhpp::BlendOp::eAdd,
+              .srcAlphaBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstAlphaBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .alphaBlendOp = vkhpp::BlendOp::eAdd,
+              .colorWriteMask = vkhpp::ColorComponentFlagBits::eR |
+                                vkhpp::ColorComponentFlagBits::eG |
+                                vkhpp::ColorComponentFlagBits::eB |
+                                vkhpp::ColorComponentFlagBits::eA,
+          },
+      };
+  const vkhpp::PipelineColorBlendStateCreateInfo
+      pipelineColorBlendStateCreateInfo = {
+          .logicOpEnable = VK_FALSE,
+          .logicOp = vkhpp::LogicOp::eCopy,
+          .attachmentCount =
+              static_cast<uint32_t>(pipelineColorBlendAttachments.size()),
+          .pAttachments = pipelineColorBlendAttachments.data(),
+          .blendConstants = {{
+              0.0f,
+              0.0f,
+              0.0f,
+              0.0f,
+          }},
+      };
+  const std::vector<vkhpp::DynamicState> pipelineDynamicStates = {
+      vkhpp::DynamicState::eViewport,
+      vkhpp::DynamicState::eScissor,
+  };
+  const vkhpp::PipelineDynamicStateCreateInfo pipelineDynamicStateCreateInfo = {
+      .dynamicStateCount = static_cast<uint32_t>(pipelineDynamicStates.size()),
+      .pDynamicStates = pipelineDynamicStates.data(),
+  };
+  const vkhpp::GraphicsPipelineCreateInfo pipelineCreateInfo = {
+      .stageCount = static_cast<uint32_t>(pipelineStages.size()),
+      .pStages = pipelineStages.data(),
+      .pVertexInputState = &pipelineVertexInputStateCreateInfo,
+      .pInputAssemblyState = &pipelineInputAssemblyStateCreateInfo,
+      .pTessellationState = nullptr,
+      .pViewportState = &pipelineViewportStateCreateInfo,
+      .pRasterizationState = &pipelineRasterStateCreateInfo,
+      .pMultisampleState = &pipelineMultisampleStateCreateInfo,
+      .pDepthStencilState = &pipelineDepthStencilStateCreateInfo,
+      .pColorBlendState = &pipelineColorBlendStateCreateInfo,
+      .pDynamicState = &pipelineDynamicStateCreateInfo,
+      .layout = *mPipelineLayout,
+      .renderPass = *mRenderpass,
+      .subpass = 0,
+      .basePipelineHandle = VK_NULL_HANDLE,
+      .basePipelineIndex = 0,
+  };
+  mPipeline = VK_EXPECT_RV(
+      mDevice->createGraphicsPipelineUnique({}, pipelineCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> FullscreenTexture::DestroySwapchainDependents() {
+  mPipeline.reset();
+  mSwapchainImageObjects.clear();
+  mRenderpass.reset();
+  return Ok{};
+}
+
+Result<Ok> FullscreenTexture::RecordFrame(const FrameInfo& frame) {
+  vkhpp::CommandBuffer commandBuffer = frame.commandBuffer;
+
+  const SwapchainImageObjects& swapchainObjects =
+      mSwapchainImageObjects[frame.swapchainImageIndex];
+
+  const std::vector<vkhpp::ClearValue> renderPassBeginClearValues = {
+      vkhpp::ClearValue{
+          .color =
+              {
+                  .float32 = {{1.0f, 0.0f, 0.0f, 1.0f}},
+              },
+      },
+  };
+  const vkhpp::RenderPassBeginInfo renderPassBeginInfo = {
+      .renderPass = *mRenderpass,
+      .framebuffer = *swapchainObjects.framebuffer,
+      .renderArea =
+          {
+              .offset =
+                  {
+                      .x = 0,
+                      .y = 0,
+                  },
+              .extent = swapchainObjects.extent,
+          },
+      .clearValueCount =
+          static_cast<uint32_t>(renderPassBeginClearValues.size()),
+      .pClearValues = renderPassBeginClearValues.data(),
+  };
+  commandBuffer.beginRenderPass(renderPassBeginInfo,
+                                vkhpp::SubpassContents::eInline);
+
+  commandBuffer.bindPipeline(vkhpp::PipelineBindPoint::eGraphics, *mPipeline);
+
+  commandBuffer.bindDescriptorSets(vkhpp::PipelineBindPoint::eGraphics,
+                                   *mPipelineLayout,
+                                   /*firstSet=*/0, {*mDescriptorSet0},
+                                   /*dynamicOffsets=*/{});
+
+  const vkhpp::Viewport viewport = {
+      .x = 0.0f,
+      .y = 0.0f,
+      .width = static_cast<float>(swapchainObjects.extent.width),
+      .height = static_cast<float>(swapchainObjects.extent.height),
+      .minDepth = 0.0f,
+      .maxDepth = 1.0f,
+  };
+  commandBuffer.setViewport(0, {viewport});
+
+  const vkhpp::Rect2D scissor = {
+      .offset =
+          {
+              .x = 0,
+              .y = 0,
+          },
+      .extent = swapchainObjects.extent,
+  };
+  commandBuffer.setScissor(0, {scissor});
+
+  commandBuffer.draw(4, 1, 0, 0);
+
+  commandBuffer.endRenderPass();
+
+  return Ok{};
+}
+
+}  // namespace cuttlefish
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag
new file mode 100644
index 000000000..4e1af09dc
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag
@@ -0,0 +1,11 @@
+#version 460
+
+layout(set = 0, binding = 0) uniform sampler2D uTexture;
+
+layout(location = 0) noperspective in vec2 iUV;
+
+layout(location = 0) out vec4 oColor;
+
+void main() {
+    oColor = texture(uTexture, iUV);
+}
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.inl b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.inl
new file mode 100644
index 000000000..513036b6c
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.inl
@@ -0,0 +1,56 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// layout(set = 0, binding = 0) uniform sampler2D uTexture;
+// 
+// layout(location = 0) noperspective in vec2 iUV;
+// 
+// layout(location = 0) out vec4 oColor;
+// 
+// void main() {
+//     oColor = texture(uTexture, iUV);
+// }
+const std::vector<uint8_t> kFullscreenTextureFrag = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 
+	0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0xcc, 0x01, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 
+	0x45, 0x5f, 0x63, 0x70, 0x70, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 
+	0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 
+	0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 
+	0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x05, 0x00, 0x04, 0x00, 
+	0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x6f, 0x43, 0x6f, 0x6c, 0x6f, 0x72, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x75, 0x54, 0x65, 0x78, 0x74, 0x75, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 
+	0x05, 0x00, 0x03, 0x00, 0x11, 0x00, 0x00, 0x00, 0x69, 0x55, 0x56, 0x00, 0x47, 0x00, 0x04, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x03, 0x00, 
+	0x11, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00, 0x00, 
+	0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x19, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x03, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 
+	0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x02, 0x00, 
+	0x05, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 
+	0x11, 0x00, 0x00, 0x00, 0x57, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.spv b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.spv
new file mode 100644
index 000000000..8fdde8b01
Binary files /dev/null and b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.frag.spv differ
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.h b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.h
new file mode 100644
index 000000000..5440aad0c
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.h
@@ -0,0 +1,55 @@
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
+#pragma once
+
+#include "common.h"
+#include "sample_base.h"
+
+namespace cuttlefish {
+
+class FullscreenTexture : public SampleBase {
+ public:
+  static Result<std::unique_ptr<SampleBase>> Create();
+
+  Result<Ok> StartUp() override;
+  Result<Ok> CleanUp() override;
+
+  Result<Ok> CreateSwapchainDependents(const SwapchainInfo& /*info*/) override;
+  Result<Ok> DestroySwapchainDependents() override;
+
+  Result<Ok> RecordFrame(const FrameInfo& frame) override;
+
+ private:
+  FullscreenTexture() = default;
+
+  vkhpp::UniqueRenderPass mRenderpass;
+  struct SwapchainImageObjects {
+    vkhpp::Extent2D extent;
+    vkhpp::UniqueFramebuffer framebuffer;
+  };
+  std::vector<SwapchainImageObjects> mSwapchainImageObjects;
+
+  ImageWithMemory mTexture;
+  vkhpp::UniqueSampler mTextureSampler;
+  vkhpp::UniqueShaderModule mVertShaderModule;
+  vkhpp::UniqueShaderModule mFragShaderModule;
+  vkhpp::UniquePipelineLayout mPipelineLayout;
+  vkhpp::UniqueDescriptorSetLayout mDescriptorSet0Layout;
+  vkhpp::UniqueDescriptorPool mDescriptorSet0Pool;
+  vkhpp::UniqueDescriptorSet mDescriptorSet0;
+  vkhpp::UniquePipeline mPipeline;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert
new file mode 100644
index 000000000..0df16d272
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert
@@ -0,0 +1,22 @@
+#version 460
+
+vec2 kPositions[4] = vec2[](
+    vec2(-1.0,  1.0),
+    vec2(-1.0, -1.0),
+    vec2( 1.0,  1.0),
+    vec2( 1.0, -1.0)
+);
+
+vec2 kUVs[4] = vec2[](
+    vec2(0.0, 1.0),
+    vec2(0.0, 0.0),
+    vec2(1.0, 1.0),
+    vec2(1.0, 0.0)
+);
+
+layout (location = 0) out vec2 oUV;
+
+void main() {
+    gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+    oUV = kUVs[gl_VertexIndex];
+}
\ No newline at end of file
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.inl b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.inl
new file mode 100644
index 000000000..2959065dc
--- /dev/null
+++ b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.inl
@@ -0,0 +1,117 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// vec2 kPositions[4] = vec2[](
+//     vec2(-1.0,  1.0),
+//     vec2(-1.0, -1.0),
+//     vec2( 1.0,  1.0),
+//     vec2( 1.0, -1.0)
+// );
+// 
+// vec2 kUVs[4] = vec2[](
+//     vec2(0.0, 1.0),
+//     vec2(0.0, 0.0),
+//     vec2(1.0, 1.0),
+//     vec2(1.0, 0.0)
+// );
+// 
+// layout (location = 0) out vec2 oUV;
+// 
+// void main() {
+//     gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+//     oUV = kUVs[gl_VertexIndex];
+// }
+const std::vector<uint8_t> kFullscreenTextureVert = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x32, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 
+	0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x63, 0x70, 0x70, 0x5f, 0x73, 0x74, 
+	0x79, 0x6c, 0x65, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 
+	0x76, 0x65, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 
+	0x45, 0x5f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 
+	0x69, 0x76, 0x65, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x6b, 0x50, 0x6f, 0x73, 
+	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x6b, 0x55, 0x56, 0x73, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x00, 0x00, 
+	0x67, 0x6c, 0x5f, 0x50, 0x65, 0x72, 0x56, 0x65, 0x72, 0x74, 0x65, 0x78, 0x00, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 
+	0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x06, 0x00, 0x07, 0x00, 0x1d, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x53, 0x69, 0x7a, 0x65, 
+	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x07, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x67, 0x6c, 0x5f, 0x43, 0x6c, 0x69, 0x70, 0x44, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 
+	0x06, 0x00, 0x07, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x43, 
+	0x75, 0x6c, 0x6c, 0x44, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x05, 0x00, 0x03, 0x00, 
+	0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x67, 0x6c, 0x5f, 0x56, 0x65, 0x72, 0x74, 0x65, 0x78, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x00, 
+	0x05, 0x00, 0x03, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x6f, 0x55, 0x56, 0x00, 0x48, 0x00, 0x05, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
+	0x48, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x47, 0x00, 0x03, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x2e, 0x00, 0x00, 0x00, 
+	0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xbf, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 
+	0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
+	0x12, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 
+	0x15, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
+	0x2c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 
+	0x08, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x06, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x20, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x25, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 
+	0x3e, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 
+	0x14, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 
+	0x24, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x41, 0x00, 0x05, 0x00, 0x25, 0x00, 0x00, 0x00, 
+	0x26, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x51, 0x00, 0x05, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
+	0x51, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x50, 0x00, 0x07, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 
+	0x28, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
+	0x41, 0x00, 0x05, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 
+	0x3d, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x41, 0x00, 0x05, 0x00, 0x25, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x2f, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 
+	0x30, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 
+	0xfd, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.spv b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.spv
new file mode 100644
index 000000000..bacfb21a5
Binary files /dev/null and b/tests/graphics/vulkan/fullscreen_texture/fullscreen_texture.vert.spv differ
diff --git a/tests/graphics/vulkan/image.cpp b/tests/graphics/vulkan/image.cpp
new file mode 100644
index 000000000..52bcfd750
--- /dev/null
+++ b/tests/graphics/vulkan/image.cpp
@@ -0,0 +1,48 @@
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
+#include "image.h"
+
+#include <vector>
+
+namespace cuttlefish {
+
+std::vector<uint8_t> CreateImageContentsWithFourCorners(
+    uint32_t width, uint32_t height, const RGBA8888& bottomLeft,
+    const RGBA8888& bottomRight, const RGBA8888& topLeft,
+    const RGBA8888& topRight) {
+  std::vector<uint8_t> ret;
+  ret.reserve(width * height * 4);
+
+  const RGBA8888* grid[2][2] = {
+      {&topLeft, &bottomLeft},
+      {&topRight, &bottomRight},
+  };
+
+  for (uint32_t y = 0; y < height; y++) {
+    const bool isBotHalf = (y <= (height / 2));
+    for (uint32_t x = 0; x < width; x++) {
+      const bool isLeftHalf = (x <= (width / 2));
+
+      const RGBA8888* color = grid[isLeftHalf ? 0 : 1][isBotHalf ? 0 : 1];
+      ret.push_back(color->r);
+      ret.push_back(color->g);
+      ret.push_back(color->b);
+      ret.push_back(color->a);
+    }
+  }
+  return ret;
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/image.h b/tests/graphics/vulkan/image.h
new file mode 100644
index 000000000..edbc9da7e
--- /dev/null
+++ b/tests/graphics/vulkan/image.h
@@ -0,0 +1,47 @@
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
+#pragma once
+
+#include <vector>
+
+namespace cuttlefish {
+
+struct RGBA8888 {
+  uint8_t r;
+  uint8_t g;
+  uint8_t b;
+  uint8_t a;
+};
+
+// NOTE: Adjusts for the Vulkan coordinate system with (-1, -1) at the top left:
+//
+//   const std::vector<uint8_t> contents = CreateImageContentsWithFourCorners(
+//          /*width=*/2,
+//          /*height=*/2,
+//          /*bottomLeft=*/<RED>,
+//          /*bottomRight=*/<BLUE>,
+//          /*topLeft=*/<GREEN>,
+//          /*topRight=*/<BLACK>);
+//
+//   contents[ 0 through  3] == <GREEN>
+//   contents[ 4 through  7] == <BLACK>
+//   contents[ 8 through 11] == <RED>
+//   contents[12 through 15] == <BLUE>
+std::vector<uint8_t> CreateImageContentsWithFourCorners(
+    uint32_t width, uint32_t height, const RGBA8888& bottomLeft,
+    const RGBA8888& bottomRight, const RGBA8888& topLeft,
+    const RGBA8888& topRight);
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/main.cpp b/tests/graphics/vulkan/main.cpp
new file mode 100644
index 000000000..6e21b3d40
--- /dev/null
+++ b/tests/graphics/vulkan/main.cpp
@@ -0,0 +1,105 @@
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
+#include <cstdlib>
+#include <memory>
+
+#include <android_native_app_glue.h>
+#include <assert.h>
+
+#include "common.h"
+#include "sample_base.h"
+
+namespace cuttlefish {
+
+struct AppState {
+  bool drawing = false;
+  std::unique_ptr<SampleBase> sample;
+};
+
+static void OnAppCmd(struct android_app* app, int32_t cmd) {
+  auto* state = reinterpret_cast<AppState*>(app->userData);
+
+  switch (cmd) {
+    case APP_CMD_START: {
+      ALOGD("APP_CMD_START");
+      if (app->window != nullptr) {
+        state->drawing = true;
+        VK_ASSERT(state->sample->SetWindow(app->window));
+      }
+      break;
+    }
+    case APP_CMD_INIT_WINDOW: {
+      ALOGD("APP_CMD_INIT_WINDOW");
+      if (app->window != nullptr) {
+        state->drawing = true;
+        VK_ASSERT(state->sample->SetWindow(app->window));
+      }
+      break;
+    }
+    case APP_CMD_TERM_WINDOW: {
+      ALOGD("APP_CMD_TERM_WINDOW");
+      state->drawing = false;
+      VK_ASSERT(state->sample->SetWindow(nullptr));
+      break;
+    }
+    case APP_CMD_DESTROY: {
+      ALOGD("APP_CMD_DESTROY");
+      state->drawing = false;
+      break;
+    }
+    default:
+      break;
+  }
+}
+
+void Main(struct android_app* app) {
+  AppState state;
+  state.sample = VK_ASSERT(BuildVulkanSampleApp());
+
+  app->userData = &state;
+
+  // Invoked from the source->process() below:
+  app->onAppCmd = OnAppCmd;
+
+  while (true) {
+    int ident;
+    android_poll_source* source;
+    while ((ident = ALooper_pollOnce(state.drawing ? 0 : -1, nullptr, nullptr,
+                                     (void**)&source)) > ALOOPER_POLL_TIMEOUT) {
+      if (source != nullptr) {
+        source->process(app, source);
+      }
+      if (app->destroyRequested != 0) {
+        break;
+      }
+    }
+
+    if (app->destroyRequested != 0) {
+      ANativeActivity_finish(app->activity);
+      break;
+    }
+
+    if (state.drawing) {
+      VK_ASSERT(state.sample->Render());
+    }
+  }
+
+  state.sample->CleanUp();
+  state.sample.reset();
+}
+
+}  // namespace cuttlefish
+
+void android_main(struct android_app* app) { cuttlefish::Main(app); }
diff --git a/tests/graphics/vulkan/process_shaders.sh b/tests/graphics/vulkan/process_shaders.sh
new file mode 100755
index 000000000..c7a923124
--- /dev/null
+++ b/tests/graphics/vulkan/process_shaders.sh
@@ -0,0 +1,29 @@
+if ! command -v generate_shader_embed_header 2>&1 >/dev/null; then
+    m generate_shader_embed_header
+fi
+
+for file in **/*.{frag,vert}; do
+    [ -f "${file}" ] || break
+
+    SHADER_GLSL="${file}"
+    echo "Found ${SHADER_GLSL}"
+
+    SHADER_SPV="${file}.spv"
+    SHADER_EMBED="${file}.inl"
+    SHADER_BASENAME="$(basename ${file})"
+    SHADER_EMBED_VARNAME=$(sed -r 's/\./_/g' <<< $SHADER_BASENAME)
+    SHADER_EMBED_VARNAME=$(sed -r 's/(^|_)([a-z])/\U\2/g' <<< $SHADER_EMBED_VARNAME)
+    SHADER_EMBED_VARNAME="k${SHADER_EMBED_VARNAME}"
+
+    glslc \
+        "${SHADER_GLSL}" \
+        -o "${SHADER_SPV}"
+
+    generate_shader_embed_header \
+        "${SHADER_GLSL}" \
+        "${SHADER_SPV}" \
+        "${SHADER_EMBED_VARNAME}" \
+        "${SHADER_EMBED}"
+
+    echo "Generated ${SHADER_EMBED}"
+done
diff --git a/tests/graphics/vulkan/sample_base.cpp b/tests/graphics/vulkan/sample_base.cpp
new file mode 100644
index 000000000..580994000
--- /dev/null
+++ b/tests/graphics/vulkan/sample_base.cpp
@@ -0,0 +1,1378 @@
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
+#include "sample_base.h"
+
+#include <string>
+#include <unordered_map>
+#include <unordered_set>
+#include <vector>
+
+VULKAN_HPP_DEFAULT_DISPATCH_LOADER_DYNAMIC_STORAGE
+
+namespace cuttlefish {
+namespace {
+
+constexpr const bool kEnableValidationLayers = false;
+
+static VKAPI_ATTR VkBool32 VKAPI_CALL VulkanDebugCallback(
+    VkDebugUtilsMessageSeverityFlagBitsEXT severity,
+    VkDebugUtilsMessageTypeFlagsEXT,
+    const VkDebugUtilsMessengerCallbackDataEXT* pCallbackData, void*) {
+  if (severity == VK_DEBUG_UTILS_MESSAGE_SEVERITY_VERBOSE_BIT_EXT) {
+    ALOGV("%s", pCallbackData->pMessage);
+  } else if (severity == VK_DEBUG_UTILS_MESSAGE_SEVERITY_INFO_BIT_EXT) {
+    ALOGI("%s", pCallbackData->pMessage);
+  } else if (severity == VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT) {
+    ALOGW("%s", pCallbackData->pMessage);
+  } else if (severity == VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT) {
+    ALOGE("%s", pCallbackData->pMessage);
+  }
+  return VK_FALSE;
+}
+
+Result<uint32_t> GetMemoryType(const vkhpp::PhysicalDevice& physical_device,
+                               uint32_t memory_type_mask,
+                               vkhpp::MemoryPropertyFlags memoryProperties) {
+  const auto props = physical_device.getMemoryProperties();
+  for (uint32_t i = 0; i < props.memoryTypeCount; i++) {
+    if (!(memory_type_mask & (1 << i))) {
+      continue;
+    }
+    if ((props.memoryTypes[i].propertyFlags & memoryProperties) !=
+        memoryProperties) {
+      continue;
+    }
+    return i;
+  }
+  return Err("Failed to find memory type matching " +
+             vkhpp::to_string(memoryProperties));
+}
+
+}  // namespace
+
+Result<Ok> SampleBase::StartUpBase(
+    const std::vector<std::string>& requestedInstanceExtensions,
+    const std::vector<std::string>& requestedInstanceLayers,
+    const std::vector<std::string>& requestedDeviceExtensions) {
+  VULKAN_HPP_DEFAULT_DISPATCHER.init(
+      mLoader.getProcAddress<PFN_vkGetInstanceProcAddr>(
+          "vkGetInstanceProcAddr"));
+
+  std::vector<const char*> requestedInstanceExtensionsChars;
+  requestedInstanceExtensionsChars.reserve(requestedInstanceExtensions.size());
+  for (const auto& e : requestedInstanceExtensions) {
+    requestedInstanceExtensionsChars.push_back(e.c_str());
+  }
+  if (kEnableValidationLayers) {
+    requestedInstanceExtensionsChars.push_back(
+        VK_EXT_DEBUG_UTILS_EXTENSION_NAME);
+  }
+
+  std::vector<const char*> requestedInstanceLayersChars;
+  requestedInstanceLayersChars.reserve(requestedInstanceLayers.size());
+  for (const auto& l : requestedInstanceLayers) {
+    requestedInstanceLayersChars.push_back(l.c_str());
+  }
+
+  const vkhpp::ApplicationInfo applicationInfo = {
+      .pApplicationName = "cuttlefish Sample App",
+      .applicationVersion = 1,
+      .pEngineName = "cuttlefish Sample App",
+      .engineVersion = 1,
+      .apiVersion = VK_API_VERSION_1_2,
+  };
+  const vkhpp::InstanceCreateInfo instanceCreateInfo = {
+      .pApplicationInfo = &applicationInfo,
+      .enabledLayerCount =
+          static_cast<uint32_t>(requestedInstanceLayersChars.size()),
+      .ppEnabledLayerNames = requestedInstanceLayersChars.data(),
+      .enabledExtensionCount =
+          static_cast<uint32_t>(requestedInstanceExtensionsChars.size()),
+      .ppEnabledExtensionNames = requestedInstanceExtensionsChars.data(),
+  };
+  mInstance = VK_EXPECT_RV(vkhpp::createInstanceUnique(instanceCreateInfo));
+
+  VULKAN_HPP_DEFAULT_DISPATCHER.init(*mInstance);
+
+  std::optional<vkhpp::UniqueDebugUtilsMessengerEXT> debugMessenger;
+  if (kEnableValidationLayers) {
+    const vkhpp::DebugUtilsMessengerCreateInfoEXT debugCreateInfo = {
+        .messageSeverity =
+            vkhpp::DebugUtilsMessageSeverityFlagBitsEXT::eVerbose |
+            vkhpp::DebugUtilsMessageSeverityFlagBitsEXT::eWarning |
+            vkhpp::DebugUtilsMessageSeverityFlagBitsEXT::eError,
+        .messageType = vkhpp::DebugUtilsMessageTypeFlagBitsEXT::eGeneral |
+                       vkhpp::DebugUtilsMessageTypeFlagBitsEXT::eValidation |
+                       vkhpp::DebugUtilsMessageTypeFlagBitsEXT::ePerformance,
+        .pfnUserCallback = VulkanDebugCallback,
+        .pUserData = nullptr,
+    };
+    debugMessenger = VK_EXPECT_RV(
+        mInstance->createDebugUtilsMessengerEXTUnique(debugCreateInfo));
+  }
+
+  const auto physicalDevices =
+      VK_EXPECT_RV(mInstance->enumeratePhysicalDevices());
+  mPhysicalDevice = std::move(physicalDevices[0]);
+
+  std::unordered_set<std::string> availableDeviceExtensions;
+  {
+    const auto exts =
+        VK_EXPECT_RV(mPhysicalDevice.enumerateDeviceExtensionProperties());
+    for (const auto& ext : exts) {
+      availableDeviceExtensions.emplace(ext.extensionName);
+    }
+  }
+  const auto features2 =
+      mPhysicalDevice
+          .getFeatures2<vkhpp::PhysicalDeviceFeatures2,  //
+                        vkhpp::PhysicalDeviceSamplerYcbcrConversionFeatures>();
+
+  bool ycbcr_conversion_needed = false;
+
+  std::vector<const char*> requestedDeviceExtensionsChars;
+  requestedDeviceExtensionsChars.reserve(requestedDeviceExtensions.size());
+  for (const auto& e : requestedDeviceExtensions) {
+    if (e == std::string(VK_KHR_SAMPLER_YCBCR_CONVERSION_EXTENSION_NAME)) {
+      // The interface of VK_KHR_sampler_ycbcr_conversion was promoted to core
+      // in Vulkan 1.1 but the feature/functionality is still optional. Check
+      // here:
+      const auto& sampler_features =
+          features2.get<vkhpp::PhysicalDeviceSamplerYcbcrConversionFeatures>();
+
+      if (sampler_features.samplerYcbcrConversion == VK_FALSE) {
+        return Err("Physical device doesn't support samplerYcbcrConversion");
+      }
+      ycbcr_conversion_needed = true;
+    } else {
+      if (availableDeviceExtensions.find(e) ==
+          availableDeviceExtensions.end()) {
+        return Err("Physical device doesn't support extension " +
+                   std::string(e));
+      }
+      requestedDeviceExtensionsChars.push_back(e.c_str());
+    }
+  }
+
+  mQueueFamilyIndex = -1;
+  {
+    const auto props = mPhysicalDevice.getQueueFamilyProperties();
+    for (uint32_t i = 0; i < props.size(); i++) {
+      const auto& prop = props[i];
+      if (prop.queueFlags & vkhpp::QueueFlagBits::eGraphics) {
+        mQueueFamilyIndex = i;
+        break;
+      }
+    }
+  }
+
+  const float queue_priority = 1.0f;
+  const vkhpp::DeviceQueueCreateInfo device_queue_create_info = {
+      .queueFamilyIndex = mQueueFamilyIndex,
+      .queueCount = 1,
+      .pQueuePriorities = &queue_priority,
+  };
+  const vkhpp::PhysicalDeviceVulkan11Features device_enable_features = {
+      .samplerYcbcrConversion = ycbcr_conversion_needed,
+  };
+  const vkhpp::DeviceCreateInfo deviceCreateInfo = {
+      .pNext = &device_enable_features,
+      .queueCreateInfoCount = 1,
+      .pQueueCreateInfos = &device_queue_create_info,
+      .enabledLayerCount =
+          static_cast<uint32_t>(requestedInstanceLayersChars.size()),
+      .ppEnabledLayerNames = requestedInstanceLayersChars.data(),
+      .enabledExtensionCount =
+          static_cast<uint32_t>(requestedDeviceExtensionsChars.size()),
+      .ppEnabledExtensionNames = requestedDeviceExtensionsChars.data(),
+  };
+  mDevice = VK_EXPECT_RV(mPhysicalDevice.createDeviceUnique(deviceCreateInfo));
+  mQueue = mDevice->getQueue(mQueueFamilyIndex, 0);
+
+  mStagingBuffer =
+      VK_EXPECT(CreateBuffer(kStagingBufferSize,
+                             vkhpp::BufferUsageFlagBits::eTransferDst |
+                                 vkhpp::BufferUsageFlagBits::eTransferSrc,
+                             vkhpp::MemoryPropertyFlagBits::eHostVisible |
+                                 vkhpp::MemoryPropertyFlagBits::eHostCoherent));
+
+  const vkhpp::FenceCreateInfo fenceCreateInfo = {
+      .flags = vkhpp::FenceCreateFlagBits::eSignaled,
+  };
+  const vkhpp::SemaphoreCreateInfo semaphoreCreateInfo = {};
+  const vkhpp::CommandPoolCreateInfo commandPoolCreateInfo = {
+      .flags = vkhpp::CommandPoolCreateFlagBits::eResetCommandBuffer,
+      .queueFamilyIndex = mQueueFamilyIndex,
+  };
+  for (uint32_t i = 0; i < kMaxFramesInFlight; i++) {
+    auto fence = VK_EXPECT_RV(mDevice->createFenceUnique(fenceCreateInfo));
+    auto readyForRender =
+        VK_EXPECT_RV(mDevice->createSemaphoreUnique(semaphoreCreateInfo));
+    auto readyForPresent =
+        VK_EXPECT_RV(mDevice->createSemaphoreUnique(semaphoreCreateInfo));
+    auto commandPool =
+        VK_EXPECT_RV(mDevice->createCommandPoolUnique(commandPoolCreateInfo));
+    const vkhpp::CommandBufferAllocateInfo commandBufferAllocateInfo = {
+        .commandPool = *commandPool,
+        .level = vkhpp::CommandBufferLevel::ePrimary,
+        .commandBufferCount = 1,
+    };
+    auto commandBuffers = VK_EXPECT_RV(
+        mDevice->allocateCommandBuffersUnique(commandBufferAllocateInfo));
+    auto commandBuffer = std::move(commandBuffers[0]);
+    mFrameObjects.push_back(PerFrameObjects{
+        .readyFence = std::move(fence),
+        .readyForRender = std::move(readyForRender),
+        .readyForPresent = std::move(readyForPresent),
+        .commandPool = std::move(commandPool),
+        .commandBuffer = std::move(commandBuffer),
+    });
+  }
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::CleanUpBase() {
+  mDevice->waitIdle();
+
+  return Ok{};
+}
+
+Result<SampleBase::BufferWithMemory> SampleBase::CreateBuffer(
+    vkhpp::DeviceSize bufferSize, vkhpp::BufferUsageFlags bufferUsages,
+    vkhpp::MemoryPropertyFlags bufferMemoryProperties) {
+  const vkhpp::BufferCreateInfo bufferCreateInfo = {
+      .size = static_cast<VkDeviceSize>(bufferSize),
+      .usage = bufferUsages,
+      .sharingMode = vkhpp::SharingMode::eExclusive,
+  };
+  auto buffer = VK_EXPECT_RV(mDevice->createBufferUnique(bufferCreateInfo));
+
+  vkhpp::MemoryRequirements bufferMemoryRequirements{};
+  mDevice->getBufferMemoryRequirements(*buffer, &bufferMemoryRequirements);
+
+  const auto bufferMemoryType = VK_EXPECT(
+      GetMemoryType(mPhysicalDevice, bufferMemoryRequirements.memoryTypeBits,
+                    bufferMemoryProperties));
+
+  const vkhpp::MemoryAllocateInfo bufferMemoryAllocateInfo = {
+      .allocationSize = bufferMemoryRequirements.size,
+      .memoryTypeIndex = bufferMemoryType,
+  };
+  auto bufferMemory =
+      VK_EXPECT_RV(mDevice->allocateMemoryUnique(bufferMemoryAllocateInfo));
+
+  VK_EXPECT_RESULT(mDevice->bindBufferMemory(*buffer, *bufferMemory, 0));
+
+  return SampleBase::BufferWithMemory{
+      .buffer = std::move(buffer),
+      .bufferMemory = std::move(bufferMemory),
+  };
+}
+
+Result<SampleBase::BufferWithMemory> SampleBase::CreateBufferWithData(
+    vkhpp::DeviceSize bufferSize, vkhpp::BufferUsageFlags bufferUsages,
+    vkhpp::MemoryPropertyFlags bufferMemoryProperties,
+    const uint8_t* bufferData) {
+  auto buffer = VK_EXPECT(CreateBuffer(
+      bufferSize, bufferUsages | vkhpp::BufferUsageFlagBits::eTransferDst,
+      bufferMemoryProperties));
+
+  void* mapped = VK_EXPECT_RV(
+      mDevice->mapMemory(*mStagingBuffer.bufferMemory, 0, kStagingBufferSize));
+
+  std::memcpy(mapped, bufferData, bufferSize);
+
+  mDevice->unmapMemory(*mStagingBuffer.bufferMemory);
+
+  DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    const std::vector<vkhpp::BufferCopy> regions = {
+        vkhpp::BufferCopy{
+            .srcOffset = 0,
+            .dstOffset = 0,
+            .size = bufferSize,
+        },
+    };
+    cmd->copyBuffer(*mStagingBuffer.buffer, *buffer.buffer, regions);
+    return Ok{};
+  });
+
+  return std::move(buffer);
+}
+
+Result<SampleBase::ImageWithMemory> SampleBase::CreateImage(
+    uint32_t width, uint32_t height, vkhpp::Format format,
+    vkhpp::ImageUsageFlags usages, vkhpp::MemoryPropertyFlags memoryProperties,
+    vkhpp::ImageLayout returnedLayout) {
+  const vkhpp::ImageCreateInfo imageCreateInfo = {
+      .imageType = vkhpp::ImageType::e2D,
+      .format = format,
+      .extent =
+          {
+              .width = width,
+              .height = height,
+              .depth = 1,
+          },
+      .mipLevels = 1,
+      .arrayLayers = 1,
+      .samples = vkhpp::SampleCountFlagBits::e1,
+      .tiling = vkhpp::ImageTiling::eOptimal,
+      .usage = usages,
+      .sharingMode = vkhpp::SharingMode::eExclusive,
+      .initialLayout = vkhpp::ImageLayout::eUndefined,
+  };
+  auto image = VK_EXPECT_RV(mDevice->createImageUnique(imageCreateInfo));
+
+  const auto memoryRequirements = mDevice->getImageMemoryRequirements(*image);
+  const uint32_t memoryIndex = VK_EXPECT(GetMemoryType(
+      mPhysicalDevice, memoryRequirements.memoryTypeBits, memoryProperties));
+
+  const vkhpp::MemoryAllocateInfo imageMemoryAllocateInfo = {
+      .allocationSize = memoryRequirements.size,
+      .memoryTypeIndex = memoryIndex,
+  };
+  auto imageMemory =
+      VK_EXPECT_RV(mDevice->allocateMemoryUnique(imageMemoryAllocateInfo));
+
+  mDevice->bindImageMemory(*image, *imageMemory, 0);
+
+  const vkhpp::ImageViewCreateInfo imageViewCreateInfo = {
+      .image = *image,
+      .viewType = vkhpp::ImageViewType::e2D,
+      .format = format,
+      .components =
+          {
+              .r = vkhpp::ComponentSwizzle::eIdentity,
+              .g = vkhpp::ComponentSwizzle::eIdentity,
+              .b = vkhpp::ComponentSwizzle::eIdentity,
+              .a = vkhpp::ComponentSwizzle::eIdentity,
+          },
+      .subresourceRange =
+          {
+              .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+              .baseMipLevel = 0,
+              .levelCount = 1,
+              .baseArrayLayer = 0,
+              .layerCount = 1,
+          },
+  };
+  auto imageView =
+      VK_EXPECT_RV(mDevice->createImageViewUnique(imageViewCreateInfo));
+
+  VK_EXPECT(DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+        vkhpp::ImageMemoryBarrier{
+            .srcAccessMask = {},
+            .dstAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+            .oldLayout = vkhpp::ImageLayout::eUndefined,
+            .newLayout = returnedLayout,
+            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+            .image = *image,
+            .subresourceRange =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                    .baseMipLevel = 0,
+                    .levelCount = 1,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+        },
+    };
+    cmd->pipelineBarrier(
+        /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+        /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+        /*dependencyFlags=*/{},
+        /*memoryBarriers=*/{},
+        /*bufferMemoryBarriers=*/{},
+        /*imageMemoryBarriers=*/imageMemoryBarriers);
+
+    return Ok{};
+  }));
+
+  return ImageWithMemory{
+      .image = std::move(image),
+      .imageMemory = std::move(imageMemory),
+      .imageView = std::move(imageView),
+  };
+}
+
+Result<Ok> SampleBase::LoadImage(const vkhpp::UniqueImage& image,
+                                 uint32_t width, uint32_t height,
+                                 const std::vector<uint8_t>& imageData,
+                                 vkhpp::ImageLayout currentLayout,
+                                 vkhpp::ImageLayout returnedLayout) {
+  if (imageData.size() > kStagingBufferSize) {
+    return Err("Failed to load image: staging buffer not large enough.");
+  }
+
+  auto* mapped = reinterpret_cast<uint8_t*>(VK_TRY_RV(
+      mDevice->mapMemory(*mStagingBuffer.bufferMemory, 0, kStagingBufferSize)));
+
+  std::memcpy(mapped, imageData.data(), imageData.size());
+
+  mDevice->unmapMemory(*mStagingBuffer.bufferMemory);
+
+  return DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    if (currentLayout != vkhpp::ImageLayout::eTransferDstOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .dstAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+              .oldLayout = currentLayout,
+              .newLayout = vkhpp::ImageLayout::eTransferDstOptimal,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+
+    const std::vector<vkhpp::BufferImageCopy> imageCopyRegions = {
+        vkhpp::BufferImageCopy{
+            .bufferOffset = 0,
+            .bufferRowLength = 0,
+            .bufferImageHeight = 0,
+            .imageSubresource =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                    .mipLevel = 0,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+            .imageOffset =
+                {
+                    .x = 0,
+                    .y = 0,
+                    .z = 0,
+                },
+            .imageExtent =
+                {
+                    .width = width,
+                    .height = height,
+                    .depth = 1,
+                },
+        },
+    };
+    cmd->copyBufferToImage(*mStagingBuffer.buffer, *image,
+                           vkhpp::ImageLayout::eTransferDstOptimal,
+                           imageCopyRegions);
+
+    if (returnedLayout != vkhpp::ImageLayout::eTransferDstOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+              .dstAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .oldLayout = vkhpp::ImageLayout::eTransferDstOptimal,
+              .newLayout = returnedLayout,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+    return Ok{};
+  });
+}
+
+Result<std::vector<uint8_t>> SampleBase::DownloadImage(
+    uint32_t width, uint32_t height, const vkhpp::UniqueImage& image,
+    vkhpp::ImageLayout currentLayout, vkhpp::ImageLayout returnedLayout) {
+  VK_EXPECT(DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    if (currentLayout != vkhpp::ImageLayout::eTransferSrcOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .dstAccessMask = vkhpp::AccessFlagBits::eTransferRead,
+              .oldLayout = currentLayout,
+              .newLayout = vkhpp::ImageLayout::eTransferSrcOptimal,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+
+    const std::vector<vkhpp::BufferImageCopy> regions = {
+        vkhpp::BufferImageCopy{
+            .bufferOffset = 0,
+            .bufferRowLength = 0,
+            .bufferImageHeight = 0,
+            .imageSubresource =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                    .mipLevel = 0,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+            .imageOffset =
+                {
+                    .x = 0,
+                    .y = 0,
+                    .z = 0,
+                },
+            .imageExtent =
+                {
+                    .width = width,
+                    .height = height,
+                    .depth = 1,
+                },
+        },
+    };
+    cmd->copyImageToBuffer(*image, vkhpp::ImageLayout::eTransferSrcOptimal,
+                           *mStagingBuffer.buffer, regions);
+
+    if (returnedLayout != vkhpp::ImageLayout::eTransferSrcOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eTransferRead,
+              .dstAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .oldLayout = vkhpp::ImageLayout::eTransferSrcOptimal,
+              .newLayout = returnedLayout,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+
+    return Ok{};
+  }));
+
+  auto* mapped = reinterpret_cast<uint8_t*>(VK_EXPECT_RV(
+      mDevice->mapMemory(*mStagingBuffer.bufferMemory, 0, kStagingBufferSize)));
+
+  std::vector<uint8_t> outPixels;
+  outPixels.resize(width * height * 4);
+
+  std::memcpy(outPixels.data(), mapped, outPixels.size());
+
+  mDevice->unmapMemory(*mStagingBuffer.bufferMemory);
+
+  return outPixels;
+}
+
+Result<SampleBase::YuvImageWithMemory> SampleBase::CreateYuvImage(
+    uint32_t width, uint32_t height, vkhpp::ImageUsageFlags usages,
+    vkhpp::MemoryPropertyFlags memoryProperties, vkhpp::ImageLayout layout) {
+  const vkhpp::SamplerYcbcrConversionCreateInfo conversionCreateInfo = {
+      .format = vkhpp::Format::eG8B8R83Plane420Unorm,
+      .ycbcrModel = vkhpp::SamplerYcbcrModelConversion::eYcbcr601,
+      .ycbcrRange = vkhpp::SamplerYcbcrRange::eItuNarrow,
+      .components =
+          {
+              .r = vkhpp::ComponentSwizzle::eIdentity,
+              .g = vkhpp::ComponentSwizzle::eIdentity,
+              .b = vkhpp::ComponentSwizzle::eIdentity,
+              .a = vkhpp::ComponentSwizzle::eIdentity,
+          },
+      .xChromaOffset = vkhpp::ChromaLocation::eMidpoint,
+      .yChromaOffset = vkhpp::ChromaLocation::eMidpoint,
+      .chromaFilter = vkhpp::Filter::eLinear,
+      .forceExplicitReconstruction = VK_FALSE,
+  };
+  auto imageSamplerConversion = VK_EXPECT_RV(
+      mDevice->createSamplerYcbcrConversionUnique(conversionCreateInfo));
+
+  const vkhpp::SamplerYcbcrConversionInfo samplerConversionInfo = {
+      .conversion = *imageSamplerConversion,
+  };
+  const vkhpp::SamplerCreateInfo samplerCreateInfo = {
+      .pNext = &samplerConversionInfo,
+      .magFilter = vkhpp::Filter::eLinear,
+      .minFilter = vkhpp::Filter::eLinear,
+      .mipmapMode = vkhpp::SamplerMipmapMode::eNearest,
+      .addressModeU = vkhpp::SamplerAddressMode::eClampToEdge,
+      .addressModeV = vkhpp::SamplerAddressMode::eClampToEdge,
+      .addressModeW = vkhpp::SamplerAddressMode::eClampToEdge,
+      .mipLodBias = 0.0f,
+      .anisotropyEnable = VK_FALSE,
+      .maxAnisotropy = 1.0f,
+      .compareEnable = VK_FALSE,
+      .compareOp = vkhpp::CompareOp::eLessOrEqual,
+      .minLod = 0.0f,
+      .maxLod = 0.25f,
+      .borderColor = vkhpp::BorderColor::eIntTransparentBlack,
+      .unnormalizedCoordinates = VK_FALSE,
+  };
+  auto imageSampler =
+      VK_EXPECT_RV(mDevice->createSamplerUnique(samplerCreateInfo));
+
+  const vkhpp::ImageCreateInfo imageCreateInfo = {
+      .imageType = vkhpp::ImageType::e2D,
+      .format = vkhpp::Format::eG8B8R83Plane420Unorm,
+      .extent =
+          {
+              .width = width,
+              .height = height,
+              .depth = 1,
+          },
+      .mipLevels = 1,
+      .arrayLayers = 1,
+      .samples = vkhpp::SampleCountFlagBits::e1,
+      .tiling = vkhpp::ImageTiling::eOptimal,
+      .usage = usages,
+      .sharingMode = vkhpp::SharingMode::eExclusive,
+      .initialLayout = vkhpp::ImageLayout::eUndefined,
+  };
+  auto image = VK_EXPECT_RV(mDevice->createImageUnique(imageCreateInfo));
+
+  const auto memoryRequirements = mDevice->getImageMemoryRequirements(*image);
+
+  const uint32_t memoryIndex = VK_EXPECT(GetMemoryType(
+      mPhysicalDevice, memoryRequirements.memoryTypeBits, memoryProperties));
+
+  const vkhpp::MemoryAllocateInfo imageMemoryAllocateInfo = {
+      .allocationSize = memoryRequirements.size,
+      .memoryTypeIndex = memoryIndex,
+  };
+  auto imageMemory =
+      VK_EXPECT_RV(mDevice->allocateMemoryUnique(imageMemoryAllocateInfo));
+
+  mDevice->bindImageMemory(*image, *imageMemory, 0);
+
+  const vkhpp::ImageViewCreateInfo imageViewCreateInfo = {
+      .pNext = &samplerConversionInfo,
+      .image = *image,
+      .viewType = vkhpp::ImageViewType::e2D,
+      .format = vkhpp::Format::eG8B8R83Plane420Unorm,
+      .components =
+          {
+              .r = vkhpp::ComponentSwizzle::eIdentity,
+              .g = vkhpp::ComponentSwizzle::eIdentity,
+              .b = vkhpp::ComponentSwizzle::eIdentity,
+              .a = vkhpp::ComponentSwizzle::eIdentity,
+          },
+      .subresourceRange =
+          {
+              .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+              .baseMipLevel = 0,
+              .levelCount = 1,
+              .baseArrayLayer = 0,
+              .layerCount = 1,
+          },
+  };
+  auto imageView =
+      VK_EXPECT_RV(mDevice->createImageViewUnique(imageViewCreateInfo));
+
+  VK_EXPECT(DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+        vkhpp::ImageMemoryBarrier{
+            .srcAccessMask = {},
+            .dstAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+            .oldLayout = vkhpp::ImageLayout::eUndefined,
+            .newLayout = layout,
+            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+            .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+            .image = *image,
+            .subresourceRange =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                    .baseMipLevel = 0,
+                    .levelCount = 1,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+
+        },
+    };
+    cmd->pipelineBarrier(
+        /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+        /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+        /*dependencyFlags=*/{},
+        /*memoryBarriers=*/{},
+        /*bufferMemoryBarriers=*/{},
+        /*imageMemoryBarriers=*/imageMemoryBarriers);
+    return Ok{};
+  }));
+
+  return YuvImageWithMemory{
+      .imageSamplerConversion = std::move(imageSamplerConversion),
+      .imageSampler = std::move(imageSampler),
+      .imageMemory = std::move(imageMemory),
+      .image = std::move(image),
+      .imageView = std::move(imageView),
+  };
+}
+
+Result<Ok> SampleBase::LoadYuvImage(const vkhpp::UniqueImage& image,
+                                    uint32_t width, uint32_t height,
+                                    const std::vector<uint8_t>& imageDataY,
+                                    const std::vector<uint8_t>& imageDataU,
+                                    const std::vector<uint8_t>& imageDataV,
+                                    vkhpp::ImageLayout currentLayout,
+                                    vkhpp::ImageLayout returnedLayout) {
+  auto* mapped = reinterpret_cast<uint8_t*>(VK_TRY_RV(
+      mDevice->mapMemory(*mStagingBuffer.bufferMemory, 0, kStagingBufferSize)));
+
+  const VkDeviceSize yOffset = 0;
+  const VkDeviceSize uOffset = imageDataY.size();
+  const VkDeviceSize vOffset = imageDataY.size() + imageDataU.size();
+  std::memcpy(mapped + yOffset, imageDataY.data(), imageDataY.size());
+  std::memcpy(mapped + uOffset, imageDataU.data(), imageDataU.size());
+  std::memcpy(mapped + vOffset, imageDataV.data(), imageDataV.size());
+  mDevice->unmapMemory(*mStagingBuffer.bufferMemory);
+
+  return DoCommandsImmediate([&](vkhpp::UniqueCommandBuffer& cmd) {
+    if (currentLayout != vkhpp::ImageLayout::eTransferDstOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .dstAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+              .oldLayout = currentLayout,
+              .newLayout = vkhpp::ImageLayout::eTransferDstOptimal,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+
+    const std::vector<vkhpp::BufferImageCopy> imageCopyRegions = {
+        vkhpp::BufferImageCopy{
+            .bufferOffset = yOffset,
+            .bufferRowLength = 0,
+            .bufferImageHeight = 0,
+            .imageSubresource =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::ePlane0,
+                    .mipLevel = 0,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+            .imageOffset =
+                {
+                    .x = 0,
+                    .y = 0,
+                    .z = 0,
+                },
+            .imageExtent =
+                {
+                    .width = width,
+                    .height = height,
+                    .depth = 1,
+                },
+        },
+        vkhpp::BufferImageCopy{
+            .bufferOffset = uOffset,
+            .bufferRowLength = 0,
+            .bufferImageHeight = 0,
+            .imageSubresource =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::ePlane1,
+                    .mipLevel = 0,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+            .imageOffset =
+                {
+                    .x = 0,
+                    .y = 0,
+                    .z = 0,
+                },
+            .imageExtent =
+                {
+                    .width = width / 2,
+                    .height = height / 2,
+                    .depth = 1,
+                },
+        },
+        vkhpp::BufferImageCopy{
+            .bufferOffset = vOffset,
+            .bufferRowLength = 0,
+            .bufferImageHeight = 0,
+            .imageSubresource =
+                {
+                    .aspectMask = vkhpp::ImageAspectFlagBits::ePlane2,
+                    .mipLevel = 0,
+                    .baseArrayLayer = 0,
+                    .layerCount = 1,
+                },
+            .imageOffset =
+                {
+                    .x = 0,
+                    .y = 0,
+                    .z = 0,
+                },
+            .imageExtent =
+                {
+                    .width = width / 2,
+                    .height = height / 2,
+                    .depth = 1,
+                },
+        },
+    };
+    cmd->copyBufferToImage(*mStagingBuffer.buffer, *image,
+                           vkhpp::ImageLayout::eTransferDstOptimal,
+                           imageCopyRegions);
+
+    if (returnedLayout != vkhpp::ImageLayout::eTransferDstOptimal) {
+      const std::vector<vkhpp::ImageMemoryBarrier> imageMemoryBarriers = {
+          vkhpp::ImageMemoryBarrier{
+              .srcAccessMask = vkhpp::AccessFlagBits::eTransferWrite,
+              .dstAccessMask = vkhpp::AccessFlagBits::eMemoryRead |
+                               vkhpp::AccessFlagBits::eMemoryWrite,
+              .oldLayout = vkhpp::ImageLayout::eTransferDstOptimal,
+              .newLayout = returnedLayout,
+              .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
+              .image = *image,
+              .subresourceRange =
+                  {
+                      .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                      .baseMipLevel = 0,
+                      .levelCount = 1,
+                      .baseArrayLayer = 0,
+                      .layerCount = 1,
+                  },
+          },
+      };
+      cmd->pipelineBarrier(
+          /*srcStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dstStageMask=*/vkhpp::PipelineStageFlagBits::eAllCommands,
+          /*dependencyFlags=*/{},
+          /*memoryBarriers=*/{},
+          /*bufferMemoryBarriers=*/{},
+          /*imageMemoryBarriers=*/imageMemoryBarriers);
+    }
+    return Ok{};
+  });
+}
+
+Result<SampleBase::FramebufferWithAttachments> SampleBase::CreateFramebuffer(
+    uint32_t width, uint32_t height, vkhpp::Format color_format,
+    vkhpp::Format depth_format) {
+  std::optional<SampleBase::ImageWithMemory> colorAttachment;
+  if (color_format != vkhpp::Format::eUndefined) {
+    colorAttachment =
+        VK_EXPECT(CreateImage(width, height, color_format,
+                              vkhpp::ImageUsageFlagBits::eColorAttachment |
+                                  vkhpp::ImageUsageFlagBits::eTransferSrc,
+                              vkhpp::MemoryPropertyFlagBits::eDeviceLocal,
+                              vkhpp::ImageLayout::eColorAttachmentOptimal));
+  }
+
+  std::optional<SampleBase::ImageWithMemory> depthAttachment;
+  if (depth_format != vkhpp::Format::eUndefined) {
+    depthAttachment = VK_EXPECT(
+        CreateImage(width, height, depth_format,
+                    vkhpp::ImageUsageFlagBits::eDepthStencilAttachment |
+                        vkhpp::ImageUsageFlagBits::eTransferSrc,
+                    vkhpp::MemoryPropertyFlagBits::eDeviceLocal,
+                    vkhpp::ImageLayout::eDepthStencilAttachmentOptimal));
+  }
+
+  std::vector<vkhpp::AttachmentDescription> attachments;
+
+  std::optional<vkhpp::AttachmentReference> colorAttachment_reference;
+  if (color_format != vkhpp::Format::eUndefined) {
+    attachments.push_back(vkhpp::AttachmentDescription{
+        .format = color_format,
+        .samples = vkhpp::SampleCountFlagBits::e1,
+        .loadOp = vkhpp::AttachmentLoadOp::eClear,
+        .storeOp = vkhpp::AttachmentStoreOp::eStore,
+        .stencilLoadOp = vkhpp::AttachmentLoadOp::eClear,
+        .stencilStoreOp = vkhpp::AttachmentStoreOp::eStore,
+        .initialLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+        .finalLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+    });
+
+    colorAttachment_reference = vkhpp::AttachmentReference{
+        .attachment = static_cast<uint32_t>(attachments.size() - 1),
+        .layout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+    };
+  }
+
+  std::optional<vkhpp::AttachmentReference> depthAttachment_reference;
+  if (depth_format != vkhpp::Format::eUndefined) {
+    attachments.push_back(vkhpp::AttachmentDescription{
+        .format = depth_format,
+        .samples = vkhpp::SampleCountFlagBits::e1,
+        .loadOp = vkhpp::AttachmentLoadOp::eClear,
+        .storeOp = vkhpp::AttachmentStoreOp::eStore,
+        .stencilLoadOp = vkhpp::AttachmentLoadOp::eClear,
+        .stencilStoreOp = vkhpp::AttachmentStoreOp::eStore,
+        .initialLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+        .finalLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+    });
+
+    depthAttachment_reference = vkhpp::AttachmentReference{
+        .attachment = static_cast<uint32_t>(attachments.size() - 1),
+        .layout = vkhpp::ImageLayout::eDepthStencilAttachmentOptimal,
+    };
+  }
+
+  vkhpp::SubpassDependency dependency = {
+      .srcSubpass = 0,
+      .dstSubpass = 0,
+      .srcStageMask = {},
+      .dstStageMask = vkhpp::PipelineStageFlagBits::eFragmentShader,
+      .srcAccessMask = {},
+      .dstAccessMask = vkhpp::AccessFlagBits::eInputAttachmentRead,
+      .dependencyFlags = vkhpp::DependencyFlagBits::eByRegion,
+  };
+  if (color_format != vkhpp::Format::eUndefined) {
+    dependency.srcStageMask |=
+        vkhpp::PipelineStageFlagBits::eColorAttachmentOutput;
+    dependency.dstStageMask |=
+        vkhpp::PipelineStageFlagBits::eColorAttachmentOutput;
+    dependency.srcAccessMask |= vkhpp::AccessFlagBits::eColorAttachmentWrite;
+  }
+  if (depth_format != vkhpp::Format::eUndefined) {
+    dependency.srcStageMask |=
+        vkhpp::PipelineStageFlagBits::eColorAttachmentOutput;
+    dependency.dstStageMask |=
+        vkhpp::PipelineStageFlagBits::eColorAttachmentOutput;
+    dependency.srcAccessMask |= vkhpp::AccessFlagBits::eColorAttachmentWrite;
+  }
+
+  vkhpp::SubpassDescription subpass = {
+      .pipelineBindPoint = vkhpp::PipelineBindPoint::eGraphics,
+      .inputAttachmentCount = 0,
+      .pInputAttachments = nullptr,
+      .colorAttachmentCount = 0,
+      .pColorAttachments = nullptr,
+      .pResolveAttachments = nullptr,
+      .pDepthStencilAttachment = nullptr,
+      .pPreserveAttachments = nullptr,
+  };
+  if (color_format != vkhpp::Format::eUndefined) {
+    subpass.colorAttachmentCount = 1;
+    subpass.pColorAttachments = &*colorAttachment_reference;
+  }
+  if (depth_format != vkhpp::Format::eUndefined) {
+    subpass.pDepthStencilAttachment = &*depthAttachment_reference;
+  }
+
+  const vkhpp::RenderPassCreateInfo renderpassCreateInfo = {
+      .attachmentCount = static_cast<uint32_t>(attachments.size()),
+      .pAttachments = attachments.data(),
+      .subpassCount = 1,
+      .pSubpasses = &subpass,
+      .dependencyCount = 1,
+      .pDependencies = &dependency,
+  };
+  auto renderpass =
+      VK_EXPECT_RV(mDevice->createRenderPassUnique(renderpassCreateInfo));
+
+  std::vector<vkhpp::ImageView> framebufferAttachments;
+  if (colorAttachment) {
+    framebufferAttachments.push_back(*colorAttachment->imageView);
+  }
+  if (depthAttachment) {
+    framebufferAttachments.push_back(*depthAttachment->imageView);
+  }
+  const vkhpp::FramebufferCreateInfo framebufferCreateInfo = {
+      .renderPass = *renderpass,
+      .attachmentCount = static_cast<uint32_t>(framebufferAttachments.size()),
+      .pAttachments = framebufferAttachments.data(),
+      .width = width,
+      .height = height,
+      .layers = 1,
+  };
+  auto framebuffer =
+      VK_EXPECT_RV(mDevice->createFramebufferUnique(framebufferCreateInfo));
+
+  return SampleBase::FramebufferWithAttachments{
+      .colorAttachment = std::move(colorAttachment),
+      .depthAttachment = std::move(depthAttachment),
+      .renderpass = std::move(renderpass),
+      .framebuffer = std::move(framebuffer),
+  };
+}
+
+Result<Ok> SampleBase::DoCommandsImmediate(
+    const std::function<Result<Ok>(vkhpp::UniqueCommandBuffer&)>& func,
+    const std::vector<vkhpp::UniqueSemaphore>& semaphores_wait,
+    const std::vector<vkhpp::UniqueSemaphore>& semaphores_signal) {
+  const vkhpp::CommandPoolCreateInfo commandPoolCreateInfo = {
+      .queueFamilyIndex = mQueueFamilyIndex,
+  };
+  auto commandPool =
+      VK_EXPECT_RV(mDevice->createCommandPoolUnique(commandPoolCreateInfo));
+  const vkhpp::CommandBufferAllocateInfo commandBufferAllocateInfo = {
+      .commandPool = *commandPool,
+      .level = vkhpp::CommandBufferLevel::ePrimary,
+      .commandBufferCount = 1,
+  };
+  auto commandBuffers = VK_TRY_RV(
+      mDevice->allocateCommandBuffersUnique(commandBufferAllocateInfo));
+  auto commandBuffer = std::move(commandBuffers[0]);
+
+  const vkhpp::CommandBufferBeginInfo commandBufferBeginInfo = {
+      .flags = vkhpp::CommandBufferUsageFlagBits::eOneTimeSubmit,
+  };
+  commandBuffer->begin(commandBufferBeginInfo);
+  VK_EXPECT(func(commandBuffer));
+  commandBuffer->end();
+
+  std::vector<vkhpp::CommandBuffer> commandBufferHandles;
+  commandBufferHandles.push_back(*commandBuffer);
+
+  std::vector<vkhpp::Semaphore> semaphoreHandlesWait;
+  semaphoreHandlesWait.reserve(semaphores_wait.size());
+  for (const auto& s : semaphores_wait) {
+    semaphoreHandlesWait.emplace_back(*s);
+  }
+
+  std::vector<vkhpp::Semaphore> semaphoreHandlesSignal;
+  semaphoreHandlesSignal.reserve(semaphores_signal.size());
+  for (const auto& s : semaphores_signal) {
+    semaphoreHandlesSignal.emplace_back(*s);
+  }
+
+  vkhpp::SubmitInfo submitInfo = {
+      .commandBufferCount = static_cast<uint32_t>(commandBufferHandles.size()),
+      .pCommandBuffers = commandBufferHandles.data(),
+  };
+  if (!semaphoreHandlesWait.empty()) {
+    submitInfo.waitSemaphoreCount =
+        static_cast<uint32_t>(semaphoreHandlesWait.size());
+    submitInfo.pWaitSemaphores = semaphoreHandlesWait.data();
+  }
+  if (!semaphoreHandlesSignal.empty()) {
+    submitInfo.signalSemaphoreCount =
+        static_cast<uint32_t>(semaphoreHandlesSignal.size());
+    submitInfo.pSignalSemaphores = semaphoreHandlesSignal.data();
+  }
+  mQueue.submit(submitInfo);
+  mQueue.waitIdle();
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::SetWindow(ANativeWindow* window) {
+  mDevice->waitIdle();
+
+  VK_EXPECT(DestroySwapchain());
+  VK_EXPECT(DestroySurface());
+
+  mWindow = window;
+
+  if (mWindow != nullptr) {
+    VK_EXPECT(CreateSurface());
+    VK_EXPECT(CreateSwapchain());
+  }
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::RecreateSwapchain() {
+  mDevice->waitIdle();
+
+  VK_EXPECT(DestroySwapchain());
+  VK_EXPECT(CreateSwapchain());
+  return Ok{};
+}
+
+Result<Ok> SampleBase::CreateSurface() {
+  if (mWindow == nullptr) {
+    return Err("Failed to create VkSurface: no window!");
+  }
+
+  const vkhpp::AndroidSurfaceCreateInfoKHR surfaceCreateInfo = {
+      .window = mWindow,
+  };
+  mSurface =
+      VK_EXPECT_RV(mInstance->createAndroidSurfaceKHR(surfaceCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::DestroySurface() {
+  mSurface.reset();
+  return Ok{};
+}
+
+Result<Ok> SampleBase::CreateSwapchain() {
+  if (!mSurface) {
+    return Err("Failed to CreateSwapchain(): missing VkSurface?");
+  }
+
+  const auto capabilities =
+      VK_EXPECT_RV(mPhysicalDevice.getSurfaceCapabilitiesKHR(*mSurface));
+  const vkhpp::Extent2D swapchainExtent = capabilities.currentExtent;
+
+  const auto formats =
+      VK_EXPECT_RV(mPhysicalDevice.getSurfaceFormatsKHR(*mSurface));
+  ALOGI("Supported surface formats:");
+  for (const auto& format : formats) {
+    const std::string formatStr = vkhpp::to_string(format.format);
+    const std::string colorspaceStr = vkhpp::to_string(format.colorSpace);
+    ALOGI(" - format:%s colorspace:%s", formatStr.c_str(),
+          colorspaceStr.c_str());
+  }
+  // Always supported by Android:
+  const vkhpp::SurfaceFormatKHR swapchainFormat = vkhpp::SurfaceFormatKHR{
+      .format = vkhpp::Format::eR8G8B8A8Unorm,
+      .colorSpace = vkhpp::ColorSpaceKHR::eSrgbNonlinear,
+  };
+
+  const auto modes =
+      VK_EXPECT_RV(mPhysicalDevice.getSurfacePresentModesKHR(*mSurface));
+  ALOGI("Supported surface present modes:");
+  for (const auto& mode : modes) {
+    const std::string modeStr = vkhpp::to_string(mode);
+    ALOGI(" - %s", modeStr.c_str());
+  }
+
+  uint32_t imageCount = capabilities.minImageCount + 1;
+  if (capabilities.maxImageCount > 0 &&
+      imageCount > capabilities.maxImageCount) {
+    imageCount = capabilities.maxImageCount;
+  }
+
+  const vkhpp::SwapchainCreateInfoKHR swapchainCreateInfo = {
+      .surface = *mSurface,
+      .minImageCount = imageCount,
+      .imageFormat = swapchainFormat.format,
+      .imageColorSpace = swapchainFormat.colorSpace,
+      .imageExtent = swapchainExtent,
+      .imageArrayLayers = 1,
+      .imageUsage = vkhpp::ImageUsageFlagBits::eColorAttachment,
+      .imageSharingMode = vkhpp::SharingMode::eExclusive,
+      .queueFamilyIndexCount = 0,
+      .pQueueFamilyIndices = nullptr,
+      .preTransform = capabilities.currentTransform,
+      .compositeAlpha = vkhpp::CompositeAlphaFlagBitsKHR::eInherit,
+      .presentMode = vkhpp::PresentModeKHR::eFifo,
+      .clipped = VK_TRUE,
+  };
+  auto swapchain =
+      VK_EXPECT_RV(mDevice->createSwapchainKHRUnique(swapchainCreateInfo));
+
+  auto swapchainImages =
+      VK_EXPECT_RV(mDevice->getSwapchainImagesKHR(*swapchain));
+
+  std::vector<vkhpp::UniqueImageView> swapchainImageViews;  // Owning
+  std::vector<vkhpp::ImageView> swapchainImageViewHandles;  // Unowning
+  for (const auto& image : swapchainImages) {
+    const vkhpp::ImageViewCreateInfo imageViewCreateInfo = {
+        .image = image,
+        .viewType = vkhpp::ImageViewType::e2D,
+        .format = swapchainFormat.format,
+        .components =
+            {
+                .r = vkhpp::ComponentSwizzle::eIdentity,
+                .g = vkhpp::ComponentSwizzle::eIdentity,
+                .b = vkhpp::ComponentSwizzle::eIdentity,
+                .a = vkhpp::ComponentSwizzle::eIdentity,
+            },
+        .subresourceRange =
+            {
+                .aspectMask = vkhpp::ImageAspectFlagBits::eColor,
+                .baseMipLevel = 0,
+                .levelCount = 1,
+                .baseArrayLayer = 0,
+                .layerCount = 1,
+            },
+    };
+    auto imageView =
+        VK_EXPECT_RV(mDevice->createImageViewUnique(imageViewCreateInfo));
+    swapchainImageViewHandles.push_back(*imageView);
+    swapchainImageViews.push_back(std::move(imageView));
+  }
+
+  mSwapchainObjects = SwapchainObjects{
+      .swapchainFormat = swapchainFormat,
+      .swapchainExtent = swapchainExtent,
+      .swapchain = std::move(swapchain),
+      .swapchainImages = std::move(swapchainImages),
+      .swapchainImageViews = std::move(swapchainImageViews),
+  };
+
+  const SwapchainInfo swapchainInfo = {
+      .swapchainFormat = swapchainFormat.format,
+      .swapchainExtent = swapchainExtent,
+      .swapchainImageViews = swapchainImageViewHandles,
+  };
+  VK_EXPECT(CreateSwapchainDependents(swapchainInfo));
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::DestroySwapchain() {
+  VK_EXPECT(DestroySwapchainDependents());
+
+  mSwapchainObjects.reset();
+
+  return Ok{};
+}
+
+Result<Ok> SampleBase::Render() {
+  if (!mSwapchainObjects) {
+    return Ok{};
+  }
+
+  mCurrentFrame = (mCurrentFrame + 1) % mFrameObjects.size();
+  PerFrameObjects& perFrame = mFrameObjects[mCurrentFrame];
+
+  VK_EXPECT_RESULT(
+      mDevice->waitForFences({*perFrame.readyFence}, VK_TRUE, UINT64_MAX));
+  VK_EXPECT_RESULT(mDevice->resetFences({*perFrame.readyFence}));
+
+  const vkhpp::SwapchainKHR swapchain = *mSwapchainObjects->swapchain;
+
+  uint32_t swapchainImageIndex = -1;
+  vkhpp::Result result = mDevice->acquireNextImageKHR(swapchain, UINT64_MAX,
+                                                      *perFrame.readyForRender,
+                                                      {}, &swapchainImageIndex);
+  if (result == vkhpp::Result::eErrorOutOfDateKHR) {
+    return RecreateSwapchain();
+  } else if (result != vkhpp::Result::eSuccess &&
+             result != vkhpp::Result::eSuboptimalKHR) {
+    return Err("Failed to acquire next image: " + vkhpp::to_string(result));
+  }
+
+  VK_EXPECT_RESULT(perFrame.commandBuffer->reset());
+  const vkhpp::CommandBufferBeginInfo commandBufferBeginInfo = {
+      .flags = vkhpp::CommandBufferUsageFlagBits::eOneTimeSubmit,
+  };
+  VK_EXPECT_RESULT(perFrame.commandBuffer->begin(commandBufferBeginInfo));
+  const FrameInfo frameInfo = {
+      .swapchainImageIndex = swapchainImageIndex,
+      .commandBuffer = *perFrame.commandBuffer,
+  };
+  VK_EXPECT(RecordFrame(frameInfo));
+  VK_EXPECT_RESULT(perFrame.commandBuffer->end());
+
+  const std::vector<vkhpp::CommandBuffer> commandBufferHandles = {
+      *perFrame.commandBuffer,
+  };
+  const std::vector<vkhpp::Semaphore> renderWaitSemaphores = {
+      *perFrame.readyForRender,
+  };
+  const std::vector<vkhpp::PipelineStageFlags> renderWaitStages = {
+      vkhpp::PipelineStageFlagBits::eBottomOfPipe,
+  };
+  const std::vector<vkhpp::Semaphore> renderSignalSemaphores = {
+      *perFrame.readyForPresent,
+  };
+  const vkhpp::SubmitInfo submitInfo = {
+      .commandBufferCount = static_cast<uint32_t>(commandBufferHandles.size()),
+      .pCommandBuffers = commandBufferHandles.data(),
+      .waitSemaphoreCount = static_cast<uint32_t>(renderWaitSemaphores.size()),
+      .pWaitSemaphores = renderWaitSemaphores.data(),
+      .pWaitDstStageMask = renderWaitStages.data(),
+      .signalSemaphoreCount =
+          static_cast<uint32_t>(renderSignalSemaphores.size()),
+      .pSignalSemaphores = renderSignalSemaphores.data(),
+  };
+  mQueue.submit(submitInfo, *perFrame.readyFence);
+
+  const std::vector<vkhpp::Semaphore> presentReadySemaphores = {
+      *perFrame.readyForPresent};
+  const vkhpp::PresentInfoKHR presentInfo = {
+      .waitSemaphoreCount =
+          static_cast<uint32_t>(presentReadySemaphores.size()),
+      .pWaitSemaphores = presentReadySemaphores.data(),
+      .swapchainCount = 1,
+      .pSwapchains = &swapchain,
+      .pImageIndices = &swapchainImageIndex,
+  };
+  result = mQueue.presentKHR(presentInfo);
+  if (result == vkhpp::Result::eErrorOutOfDateKHR ||
+      result == vkhpp::Result::eSuboptimalKHR) {
+    VK_EXPECT(RecreateSwapchain());
+  } else if (result != vkhpp::Result::eSuccess) {
+    return Err("Failed to present image: " + vkhpp::to_string(result));
+  }
+
+  return Ok{};
+}
+
+}  // namespace cuttlefish
diff --git a/tests/graphics/vulkan/sample_base.h b/tests/graphics/vulkan/sample_base.h
new file mode 100644
index 000000000..abf038369
--- /dev/null
+++ b/tests/graphics/vulkan/sample_base.h
@@ -0,0 +1,269 @@
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
+#pragma once
+
+#include <memory>
+#include <optional>
+#include <string>
+#include <vector>
+
+#include <android-base/expected.h>
+#include <android/native_window_jni.h>
+#define VULKAN_HPP_NAMESPACE vkhpp
+#define VULKAN_HPP_DISPATCH_LOADER_DYNAMIC 1
+#define VULKAN_HPP_ENABLE_DYNAMIC_LOADER_TOOL 1
+#define VULKAN_HPP_NO_CONSTRUCTORS
+#define VULKAN_HPP_NO_EXCEPTIONS
+#define VULKAN_HPP_ASSERT_ON_RESULT
+#include <vulkan/vulkan.hpp>
+#include <vulkan/vulkan_to_string.hpp>
+
+#include "common.h"
+
+namespace cuttlefish {
+
+template <typename T>
+using Result = android::base::expected<T, std::string>;
+
+// Empty object for `Result<Ok>` that allows using the below macros.
+struct Ok {};
+
+inline android::base::unexpected<std::string> Err(const std::string& msg) {
+  return android::base::unexpected(msg);
+}
+
+#define VK_ASSERT(x)                                          \
+  ({                                                          \
+    auto result = (x);                                        \
+    if (!result.ok()) {                                       \
+      ALOGE("Failed to " #x ": %s.", result.error().c_str()); \
+      std::abort();                                           \
+    };                                                        \
+    std::move(result.value());                                \
+  })
+
+#define VK_EXPECT(x)                \
+  ({                                \
+    auto expected = (x);            \
+    if (!expected.ok()) {           \
+      return Err(expected.error()); \
+    };                              \
+    std::move(expected.value());    \
+  })
+
+#define VK_EXPECT_RESULT(x)                          \
+  do {                                               \
+    vkhpp::Result result = (x);                      \
+    if (result != vkhpp::Result::eSuccess) {         \
+      return Err(std::string("Failed to " #x ": ") + \
+                 vkhpp::to_string(result));          \
+    }                                                \
+  } while (0);
+
+#define VK_EXPECT_RV(x)                               \
+  ({                                                  \
+    auto vkhpp_rv = (x);                              \
+    if (vkhpp_rv.result != vkhpp::Result::eSuccess) { \
+      return Err(std::string("Failed to " #x ": ") +  \
+                 vkhpp::to_string(vkhpp_rv.result));  \
+    };                                                \
+    std::move(vkhpp_rv.value);                        \
+  })
+
+#define VK_TRY(x)                                    \
+  do {                                               \
+    vkhpp::Result result = (x);                      \
+    if (result != vkhpp::Result::eSuccess) {         \
+      return Err(std::string("Failed to " #x ": ") + \
+                 vkhpp::to_string(result));          \
+    }                                                \
+  } while (0);
+
+#define VK_TRY_RV(x)                                  \
+  ({                                                  \
+    auto vkhpp_rv = (x);                              \
+    if (vkhpp_rv.result != vkhpp::Result::eSuccess) { \
+      return Err(std::string("Failed to " #x ": ") +  \
+                 vkhpp::to_string(vkhpp_rv.result));  \
+    };                                                \
+    std::move(vkhpp_rv.value);                        \
+  })
+
+class SampleBase {
+ public:
+  virtual ~SampleBase() {}
+
+  SampleBase(const SampleBase&) = delete;
+  SampleBase& operator=(const SampleBase&) = delete;
+
+  SampleBase(SampleBase&&) = default;
+  SampleBase& operator=(SampleBase&&) = default;
+
+  virtual Result<Ok> StartUp() = 0;
+  virtual Result<Ok> CleanUp() = 0;
+
+  struct SwapchainInfo {
+    vkhpp::Format swapchainFormat;
+    vkhpp::Extent2D swapchainExtent;
+    std::vector<vkhpp::ImageView> swapchainImageViews;
+  };
+  virtual Result<Ok> CreateSwapchainDependents(const SwapchainInfo& /*info*/) {
+    return Ok{};
+  }
+
+  virtual Result<Ok> DestroySwapchainDependents() { return Ok{}; }
+
+  struct FrameInfo {
+    uint32_t swapchainImageIndex = -1;
+    vkhpp::CommandBuffer commandBuffer;
+  };
+  virtual Result<Ok> RecordFrame(const FrameInfo& /*frame*/) { return Ok{}; }
+
+  Result<Ok> Render();
+
+  Result<Ok> SetWindow(ANativeWindow* window = nullptr);
+
+ protected:
+  SampleBase() = default;
+
+  Result<Ok> StartUpBase(const std::vector<std::string>& instance_extensions =
+                             {
+                                 VK_KHR_ANDROID_SURFACE_EXTENSION_NAME,
+                                 VK_KHR_SURFACE_EXTENSION_NAME,
+                             },
+                         const std::vector<std::string>& instance_layers = {},
+                         const std::vector<std::string>& device_extensions = {
+                             VK_KHR_SWAPCHAIN_EXTENSION_NAME,
+                         });
+  Result<Ok> CleanUpBase();
+
+  Result<Ok> CreateSurface();
+  Result<Ok> DestroySurface();
+
+  Result<Ok> CreateSwapchain();
+  Result<Ok> DestroySwapchain();
+  Result<Ok> RecreateSwapchain();
+
+  struct BufferWithMemory {
+    vkhpp::UniqueBuffer buffer;
+    vkhpp::UniqueDeviceMemory bufferMemory;
+  };
+  Result<BufferWithMemory> CreateBuffer(
+      vkhpp::DeviceSize buffer_size, vkhpp::BufferUsageFlags buffer_usages,
+      vkhpp::MemoryPropertyFlags buffer_memory_properties);
+  Result<BufferWithMemory> CreateBufferWithData(
+      vkhpp::DeviceSize buffer_size, vkhpp::BufferUsageFlags buffer_usages,
+      vkhpp::MemoryPropertyFlags buffer_memory_properties,
+      const uint8_t* buffer_data);
+
+  Result<Ok> DoCommandsImmediate(
+      const std::function<Result<Ok>(vkhpp::UniqueCommandBuffer&)>& func,
+      const std::vector<vkhpp::UniqueSemaphore>& semaphores_wait = {},
+      const std::vector<vkhpp::UniqueSemaphore>& semaphores_signal = {});
+
+  struct ImageWithMemory {
+    vkhpp::UniqueImage image;
+    vkhpp::UniqueDeviceMemory imageMemory;
+    vkhpp::UniqueImageView imageView;
+  };
+  Result<ImageWithMemory> CreateImage(
+      uint32_t width, uint32_t height, vkhpp::Format format,
+      vkhpp::ImageUsageFlags usages,
+      vkhpp::MemoryPropertyFlags memory_properties,
+      vkhpp::ImageLayout returned_layout);
+
+  Result<Ok> LoadImage(const vkhpp::UniqueImage& image, uint32_t width,
+                       uint32_t height, const std::vector<uint8_t>& imageData,
+                       vkhpp::ImageLayout currentLayout,
+                       vkhpp::ImageLayout returnedLayout);
+
+  Result<std::vector<uint8_t>> DownloadImage(
+      uint32_t width, uint32_t height, const vkhpp::UniqueImage& image,
+      vkhpp::ImageLayout current_layout, vkhpp::ImageLayout returned_layout);
+
+  struct YuvImageWithMemory {
+    vkhpp::UniqueSamplerYcbcrConversion imageSamplerConversion;
+    vkhpp::UniqueSampler imageSampler;
+    vkhpp::UniqueDeviceMemory imageMemory;
+    vkhpp::UniqueImage image;
+    vkhpp::UniqueImageView imageView;
+  };
+  Result<YuvImageWithMemory> CreateYuvImage(
+      uint32_t width, uint32_t height, vkhpp::ImageUsageFlags usages,
+      vkhpp::MemoryPropertyFlags memory_properties,
+      vkhpp::ImageLayout returned_layout);
+
+  Result<Ok> LoadYuvImage(const vkhpp::UniqueImage& image, uint32_t width,
+                          uint32_t height,
+                          const std::vector<uint8_t>& image_data_y,
+                          const std::vector<uint8_t>& image_data_u,
+                          const std::vector<uint8_t>& image_data_v,
+                          vkhpp::ImageLayout current_layout,
+                          vkhpp::ImageLayout returned_layout);
+
+  struct FramebufferWithAttachments {
+    std::optional<ImageWithMemory> colorAttachment;
+    std::optional<ImageWithMemory> depthAttachment;
+    vkhpp::UniqueRenderPass renderpass;
+    vkhpp::UniqueFramebuffer framebuffer;
+  };
+  Result<FramebufferWithAttachments> CreateFramebuffer(
+      uint32_t width, uint32_t height,
+      vkhpp::Format colorAttachmentFormat = vkhpp::Format::eUndefined,
+      vkhpp::Format depthAttachmentFormat = vkhpp::Format::eUndefined);
+
+ private:
+  vkhpp::DynamicLoader mLoader;
+  vkhpp::UniqueInstance mInstance;
+  std::optional<vkhpp::UniqueDebugUtilsMessengerEXT> mDebugMessenger;
+
+ protected:
+  vkhpp::PhysicalDevice mPhysicalDevice;
+  vkhpp::UniqueDevice mDevice;
+  vkhpp::Queue mQueue;
+  uint32_t mQueueFamilyIndex = 0;
+
+ private:
+  static constexpr const VkDeviceSize kStagingBufferSize = 32 * 1024 * 1024;
+  BufferWithMemory mStagingBuffer;
+
+  struct PerFrameObjects {
+    vkhpp::UniqueFence readyFence;
+    vkhpp::UniqueSemaphore readyForRender;
+    vkhpp::UniqueSemaphore readyForPresent;
+    vkhpp::UniqueCommandPool commandPool;
+    vkhpp::UniqueCommandBuffer commandBuffer;
+  };
+  static constexpr const uint32_t kMaxFramesInFlight = 3;
+  uint32_t mCurrentFrame = 0;
+  std::vector<PerFrameObjects> mFrameObjects;
+
+  ANativeWindow* mWindow = nullptr;
+
+  std::optional<vkhpp::SurfaceKHR> mSurface;
+
+  struct SwapchainObjects {
+    vkhpp::SurfaceFormatKHR swapchainFormat;
+    vkhpp::Extent2D swapchainExtent;
+    vkhpp::UniqueSwapchainKHR swapchain;
+    std::vector<vkhpp::Image> swapchainImages;
+    std::vector<vkhpp::UniqueImageView> swapchainImageViews;
+  };
+  std::optional<SwapchainObjects> mSwapchainObjects;
+};
+
+Result<std::unique_ptr<SampleBase>> BuildVulkanSampleApp();
+
+}  // namespace cuttlefish
diff --git a/tests/graphics/vulkan/secondary_command_buffer/Android.bp b/tests/graphics/vulkan/secondary_command_buffer/Android.bp
new file mode 100644
index 000000000..48f6baa17
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/Android.bp
@@ -0,0 +1,29 @@
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
+cc_library_shared {
+    name: "libcuttlefish_vulkan_samples_secondary_command_buffer",
+    defaults: ["libcuttlefish_vulkan_samples_defaults"],
+    srcs: [
+        "secondary_command_buffer.cpp",
+    ],
+}
+
+android_app {
+    name: "CuttlefishVulkanSamplesSecondaryCommandBuffer",
+    min_sdk_version: "34",
+    sdk_version: "current",
+    jni_libs: ["libcuttlefish_vulkan_samples_secondary_command_buffer"],
+    use_embedded_native_libs: true,
+}
diff --git a/tests/graphics/vulkan/secondary_command_buffer/AndroidManifest.xml b/tests/graphics/vulkan/secondary_command_buffer/AndroidManifest.xml
new file mode 100644
index 000000000..e11a562ab
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/AndroidManifest.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+ -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.cuttlefish.vulkan_samples.secondary_command_buffer">
+
+    <application android:appCategory="game">
+        <activity android:name="android.app.NativeActivity"
+                  android:label="Secondary Command Buffer"
+                  android:exported="true"
+                  android:turnScreenOn="true"
+                  android:configChanges="keyboardHidden"
+                  android:theme="@android:style/Theme.Holo.NoActionBar.Fullscreen">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
+            </intent-filter>
+            <meta-data
+                    android:name="android.app.lib_name"
+                    android:value="cuttlefish_vulkan_samples_secondary_command_buffer" />
+        </activity>
+    </application>
+</manifest>
\ No newline at end of file
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.cpp b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.cpp
new file mode 100644
index 000000000..d42acaec6
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.cpp
@@ -0,0 +1,382 @@
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
+#include "secondary_command_buffer.h"
+
+namespace cuttlefish {
+namespace {
+
+#include "secondary_command_buffer.frag.inl"
+#include "secondary_command_buffer.vert.inl"
+
+}  // namespace
+
+Result<std::unique_ptr<SampleBase>> BuildVulkanSampleApp() {
+  return SecondaryCommandBuffer::Create();
+}
+
+/*static*/
+Result<std::unique_ptr<SampleBase>> SecondaryCommandBuffer::Create() {
+  std::unique_ptr<SampleBase> sample(new SecondaryCommandBuffer());
+  VK_EXPECT(sample->StartUp());
+  return sample;
+}
+
+Result<Ok> SecondaryCommandBuffer::StartUp() {
+  VK_EXPECT(StartUpBase());
+
+  const vkhpp::PipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
+      .setLayoutCount = 0,
+  };
+  mPipelineLayout = VK_EXPECT_RV(
+      mDevice->createPipelineLayoutUnique(pipelineLayoutCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo vertShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kSecondaryCommandBufferVert.size()),
+      .pCode =
+          reinterpret_cast<const uint32_t*>(kSecondaryCommandBufferVert.data()),
+  };
+  mVertShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(vertShaderCreateInfo));
+
+  const vkhpp::ShaderModuleCreateInfo fragShaderCreateInfo = {
+      .codeSize = static_cast<uint32_t>(kSecondaryCommandBufferFrag.size()),
+      .pCode =
+          reinterpret_cast<const uint32_t*>(kSecondaryCommandBufferFrag.data()),
+  };
+  mFragShaderModule =
+      VK_EXPECT_RV(mDevice->createShaderModuleUnique(fragShaderCreateInfo));
+
+  return Ok{};
+}
+
+Result<Ok> SecondaryCommandBuffer::CleanUp() {
+  VK_EXPECT(CleanUpBase());
+
+  mDevice->waitIdle();
+
+  return Ok{};
+}
+
+Result<Ok> SecondaryCommandBuffer::CreateSwapchainDependents(
+    const SwapchainInfo& swapchainInfo) {
+  const std::vector<vkhpp::AttachmentDescription> renderpassAttachments = {
+      {
+          .format = swapchainInfo.swapchainFormat,
+          .samples = vkhpp::SampleCountFlagBits::e1,
+          .loadOp = vkhpp::AttachmentLoadOp::eClear,
+          .storeOp = vkhpp::AttachmentStoreOp::eStore,
+          .stencilLoadOp = vkhpp::AttachmentLoadOp::eClear,
+          .stencilStoreOp = vkhpp::AttachmentStoreOp::eStore,
+          .initialLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+          .finalLayout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+      },
+  };
+  const vkhpp::AttachmentReference renderpassColorAttachmentRef = {
+      .attachment = 0,
+      .layout = vkhpp::ImageLayout::eColorAttachmentOptimal,
+  };
+  const vkhpp::SubpassDescription renderpassSubpass = {
+      .pipelineBindPoint = vkhpp::PipelineBindPoint::eGraphics,
+      .inputAttachmentCount = 0,
+      .pInputAttachments = nullptr,
+      .colorAttachmentCount = 1,
+      .pColorAttachments = &renderpassColorAttachmentRef,
+      .pResolveAttachments = nullptr,
+      .pDepthStencilAttachment = nullptr,
+      .pPreserveAttachments = nullptr,
+  };
+  const vkhpp::SubpassDependency renderpassSubpassDependency = {
+      .srcSubpass = VK_SUBPASS_EXTERNAL,
+      .dstSubpass = 0,
+      .srcStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .srcAccessMask = {},
+      .dstStageMask = vkhpp::PipelineStageFlagBits::eColorAttachmentOutput,
+      .dstAccessMask = vkhpp::AccessFlagBits::eColorAttachmentWrite,
+  };
+  const vkhpp::RenderPassCreateInfo renderpassCreateInfo = {
+      .attachmentCount = static_cast<uint32_t>(renderpassAttachments.size()),
+      .pAttachments = renderpassAttachments.data(),
+      .subpassCount = 1,
+      .pSubpasses = &renderpassSubpass,
+      .dependencyCount = 1,
+      .pDependencies = &renderpassSubpassDependency,
+  };
+  mRenderpass =
+      VK_EXPECT_RV(mDevice->createRenderPassUnique(renderpassCreateInfo));
+
+  const std::vector<vkhpp::PipelineShaderStageCreateInfo> pipelineStages = {
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eVertex,
+          .module = *mVertShaderModule,
+          .pName = "main",
+      },
+      vkhpp::PipelineShaderStageCreateInfo{
+          .stage = vkhpp::ShaderStageFlagBits::eFragment,
+          .module = *mFragShaderModule,
+          .pName = "main",
+      },
+  };
+
+  const vkhpp::PipelineVertexInputStateCreateInfo
+      pipelineVertexInputStateCreateInfo = {};
+  const vkhpp::PipelineInputAssemblyStateCreateInfo
+      pipelineInputAssemblyStateCreateInfo = {
+          .topology = vkhpp::PrimitiveTopology::eTriangleStrip,
+      };
+  const vkhpp::PipelineViewportStateCreateInfo pipelineViewportStateCreateInfo =
+      {
+          .viewportCount = 1,
+          .pViewports = nullptr,
+          .scissorCount = 1,
+          .pScissors = nullptr,
+      };
+  const vkhpp::PipelineRasterizationStateCreateInfo
+      pipelineRasterStateCreateInfo = {
+          .depthClampEnable = VK_FALSE,
+          .rasterizerDiscardEnable = VK_FALSE,
+          .polygonMode = vkhpp::PolygonMode::eFill,
+          .cullMode = {},
+          .frontFace = vkhpp::FrontFace::eCounterClockwise,
+          .depthBiasEnable = VK_FALSE,
+          .depthBiasConstantFactor = 0.0f,
+          .depthBiasClamp = 0.0f,
+          .depthBiasSlopeFactor = 0.0f,
+          .lineWidth = 1.0f,
+      };
+  const vkhpp::SampleMask pipelineSampleMask = 65535;
+  const vkhpp::PipelineMultisampleStateCreateInfo
+      pipelineMultisampleStateCreateInfo = {
+          .rasterizationSamples = vkhpp::SampleCountFlagBits::e1,
+          .sampleShadingEnable = VK_FALSE,
+          .minSampleShading = 1.0f,
+          .pSampleMask = &pipelineSampleMask,
+          .alphaToCoverageEnable = VK_FALSE,
+          .alphaToOneEnable = VK_FALSE,
+      };
+  const vkhpp::PipelineDepthStencilStateCreateInfo
+      pipelineDepthStencilStateCreateInfo = {
+          .depthTestEnable = VK_FALSE,
+          .depthWriteEnable = VK_FALSE,
+          .depthCompareOp = vkhpp::CompareOp::eLess,
+          .depthBoundsTestEnable = VK_FALSE,
+          .stencilTestEnable = VK_FALSE,
+          .front =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .back =
+              {
+                  .failOp = vkhpp::StencilOp::eKeep,
+                  .passOp = vkhpp::StencilOp::eKeep,
+                  .depthFailOp = vkhpp::StencilOp::eKeep,
+                  .compareOp = vkhpp::CompareOp::eAlways,
+                  .compareMask = 0,
+                  .writeMask = 0,
+                  .reference = 0,
+              },
+          .minDepthBounds = 0.0f,
+          .maxDepthBounds = 0.0f,
+      };
+  const std::vector<vkhpp::PipelineColorBlendAttachmentState>
+      pipelineColorBlendAttachments = {
+          vkhpp::PipelineColorBlendAttachmentState{
+              .blendEnable = VK_FALSE,
+              .srcColorBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstColorBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .colorBlendOp = vkhpp::BlendOp::eAdd,
+              .srcAlphaBlendFactor = vkhpp::BlendFactor::eOne,
+              .dstAlphaBlendFactor = vkhpp::BlendFactor::eOneMinusSrcAlpha,
+              .alphaBlendOp = vkhpp::BlendOp::eAdd,
+              .colorWriteMask = vkhpp::ColorComponentFlagBits::eR |
+                                vkhpp::ColorComponentFlagBits::eG |
+                                vkhpp::ColorComponentFlagBits::eB |
+                                vkhpp::ColorComponentFlagBits::eA,
+          },
+      };
+  const vkhpp::PipelineColorBlendStateCreateInfo
+      pipelineColorBlendStateCreateInfo = {
+          .logicOpEnable = VK_FALSE,
+          .logicOp = vkhpp::LogicOp::eCopy,
+          .attachmentCount =
+              static_cast<uint32_t>(pipelineColorBlendAttachments.size()),
+          .pAttachments = pipelineColorBlendAttachments.data(),
+          .blendConstants = {{
+              0.0f,
+              0.0f,
+              0.0f,
+              0.0f,
+          }},
+      };
+  const std::vector<vkhpp::DynamicState> pipelineDynamicStates = {
+      vkhpp::DynamicState::eViewport,
+      vkhpp::DynamicState::eScissor,
+  };
+  const vkhpp::PipelineDynamicStateCreateInfo pipelineDynamicStateCreateInfo = {
+      .dynamicStateCount = static_cast<uint32_t>(pipelineDynamicStates.size()),
+      .pDynamicStates = pipelineDynamicStates.data(),
+  };
+  const vkhpp::GraphicsPipelineCreateInfo pipelineCreateInfo = {
+      .stageCount = static_cast<uint32_t>(pipelineStages.size()),
+      .pStages = pipelineStages.data(),
+      .pVertexInputState = &pipelineVertexInputStateCreateInfo,
+      .pInputAssemblyState = &pipelineInputAssemblyStateCreateInfo,
+      .pTessellationState = nullptr,
+      .pViewportState = &pipelineViewportStateCreateInfo,
+      .pRasterizationState = &pipelineRasterStateCreateInfo,
+      .pMultisampleState = &pipelineMultisampleStateCreateInfo,
+      .pDepthStencilState = &pipelineDepthStencilStateCreateInfo,
+      .pColorBlendState = &pipelineColorBlendStateCreateInfo,
+      .pDynamicState = &pipelineDynamicStateCreateInfo,
+      .layout = *mPipelineLayout,
+      .renderPass = *mRenderpass,
+      .subpass = 0,
+      .basePipelineHandle = VK_NULL_HANDLE,
+      .basePipelineIndex = 0,
+  };
+  mPipeline = VK_EXPECT_RV(
+      mDevice->createGraphicsPipelineUnique({}, pipelineCreateInfo));
+
+  for (const auto imageView : swapchainInfo.swapchainImageViews) {
+    const std::vector<vkhpp::ImageView> framebufferAttachments = {
+        imageView,
+    };
+    const vkhpp::FramebufferCreateInfo framebufferCreateInfo = {
+        .renderPass = *mRenderpass,
+        .attachmentCount = static_cast<uint32_t>(framebufferAttachments.size()),
+        .pAttachments = framebufferAttachments.data(),
+        .width = swapchainInfo.swapchainExtent.width,
+        .height = swapchainInfo.swapchainExtent.height,
+        .layers = 1,
+    };
+    auto framebuffer =
+        VK_EXPECT_RV(mDevice->createFramebufferUnique(framebufferCreateInfo));
+
+    const vkhpp::CommandPoolCreateInfo commandPoolCreateInfo = {
+        .flags = vkhpp::CommandPoolCreateFlagBits::eResetCommandBuffer,
+        .queueFamilyIndex = mQueueFamilyIndex,
+    };
+    auto commandPool =
+        VK_EXPECT_RV(mDevice->createCommandPoolUnique(commandPoolCreateInfo));
+
+    const vkhpp::CommandBufferAllocateInfo commandBufferAllocateInfo = {
+        .commandPool = *commandPool,
+        .level = vkhpp::CommandBufferLevel::eSecondary,
+        .commandBufferCount = 1,
+    };
+    auto commandBuffers = VK_EXPECT_RV(
+        mDevice->allocateCommandBuffersUnique(commandBufferAllocateInfo));
+    auto commandBuffer = std::move(commandBuffers[0]);
+
+    {
+      const vkhpp::CommandBufferInheritanceInfo commandBufferInheritanceInfo =
+          {};
+      const vkhpp::CommandBufferBeginInfo commandBufferBeginInfo = {
+          .pInheritanceInfo = &commandBufferInheritanceInfo,
+      };
+      commandBuffer->begin(commandBufferBeginInfo);
+
+      const std::vector<vkhpp::ClearValue> renderPassBeginClearValues = {
+          vkhpp::ClearValue{
+              .color =
+                  {
+                      .float32 = {{1.0f, 0.0f, 0.0f, 1.0f}},
+                  },
+          },
+      };
+      const vkhpp::RenderPassBeginInfo renderPassBeginInfo = {
+          .renderPass = *mRenderpass,
+          .framebuffer = *framebuffer,
+          .renderArea =
+              {
+                  .offset =
+                      {
+                          .x = 0,
+                          .y = 0,
+                      },
+                  .extent = swapchainInfo.swapchainExtent,
+              },
+          .clearValueCount =
+              static_cast<uint32_t>(renderPassBeginClearValues.size()),
+          .pClearValues = renderPassBeginClearValues.data(),
+      };
+      commandBuffer->beginRenderPass(renderPassBeginInfo,
+                                     vkhpp::SubpassContents::eInline);
+
+      commandBuffer->bindPipeline(vkhpp::PipelineBindPoint::eGraphics,
+                                  *mPipeline);
+
+      const vkhpp::Viewport viewport = {
+          .x = 0.0f,
+          .y = 0.0f,
+          .width = static_cast<float>(swapchainInfo.swapchainExtent.width),
+          .height = static_cast<float>(swapchainInfo.swapchainExtent.height),
+          .minDepth = 0.0f,
+          .maxDepth = 1.0f,
+      };
+      commandBuffer->setViewport(0, {viewport});
+
+      const vkhpp::Rect2D scissor = {
+          .offset =
+              {
+                  .x = 0,
+                  .y = 0,
+              },
+          .extent = swapchainInfo.swapchainExtent,
+      };
+      commandBuffer->setScissor(0, {scissor});
+
+      commandBuffer->draw(4, 1, 0, 0);
+
+      commandBuffer->endRenderPass();
+
+      commandBuffer->end();
+    }
+
+    mSwapchainImageObjects.push_back(SwapchainImageObjects{
+        .extent = swapchainInfo.swapchainExtent,
+        .framebuffer = std::move(framebuffer),
+        .secondaryCommandPool = std::move(commandPool),
+        .secondaryCommandBuffer = std::move(commandBuffer),
+    });
+  }
+
+  return Ok{};
+}
+
+Result<Ok> SecondaryCommandBuffer::DestroySwapchainDependents() {
+  mSwapchainImageObjects.clear();
+  mPipeline.reset();
+  mRenderpass.reset();
+  return Ok{};
+}
+
+Result<Ok> SecondaryCommandBuffer::RecordFrame(const FrameInfo& frame) {
+  vkhpp::CommandBuffer commandBuffer = frame.commandBuffer;
+
+  const SwapchainImageObjects& swapchainObjects =
+      mSwapchainImageObjects[frame.swapchainImageIndex];
+
+  commandBuffer.executeCommands({*swapchainObjects.secondaryCommandBuffer});
+
+  return Ok{};
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag
new file mode 100644
index 000000000..dcaea2749
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag
@@ -0,0 +1,7 @@
+#version 460
+
+layout(location = 0) out vec4 oColor;
+
+void main() {
+    oColor = vec4(1.0, 0.0, 0.0, 1.0);
+}
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.inl b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.inl
new file mode 100644
index 000000000..83ff74597
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.inl
@@ -0,0 +1,39 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// layout(location = 0) out vec4 oColor;
+// 
+// void main() {
+//     oColor = vec4(1.0, 0.0, 0.0, 1.0);
+// }
+const std::vector<uint8_t> kSecondaryCommandBufferFrag = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x0d, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 
+	0x04, 0x00, 0x0a, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x63, 0x70, 
+	0x70, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x64, 0x69, 0x72, 
+	0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x47, 0x4c, 0x5f, 0x47, 
+	0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x64, 0x69, 
+	0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 
+	0x6f, 0x43, 0x6f, 0x6c, 0x6f, 0x72, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 
+	0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x0a, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 
+	0x3e, 0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x01, 0x00, 
+	0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.spv b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.spv
new file mode 100644
index 000000000..e51084af8
Binary files /dev/null and b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.frag.spv differ
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.h b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.h
new file mode 100644
index 000000000..6d68d2af4
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.h
@@ -0,0 +1,52 @@
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
+#pragma once
+
+#include "common.h"
+#include "sample_base.h"
+
+namespace cuttlefish {
+
+class SecondaryCommandBuffer : public SampleBase {
+ public:
+  static Result<std::unique_ptr<SampleBase>> Create();
+
+  Result<Ok> StartUp() override;
+  Result<Ok> CleanUp() override;
+
+  Result<Ok> CreateSwapchainDependents(const SwapchainInfo& /*info*/) override;
+  Result<Ok> DestroySwapchainDependents() override;
+
+  Result<Ok> RecordFrame(const FrameInfo& frame) override;
+
+ private:
+  SecondaryCommandBuffer() = default;
+
+  vkhpp::UniqueRenderPass mRenderpass;
+  struct SwapchainImageObjects {
+    vkhpp::Extent2D extent;
+    vkhpp::UniqueFramebuffer framebuffer;
+    vkhpp::UniqueCommandPool secondaryCommandPool;
+    vkhpp::UniqueCommandBuffer secondaryCommandBuffer;
+  };
+  std::vector<SwapchainImageObjects> mSwapchainImageObjects;
+
+  vkhpp::UniqueShaderModule mVertShaderModule;
+  vkhpp::UniqueShaderModule mFragShaderModule;
+  vkhpp::UniquePipelineLayout mPipelineLayout;
+  vkhpp::UniquePipeline mPipeline;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert
new file mode 100644
index 000000000..6cc43e7b0
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert
@@ -0,0 +1,12 @@
+#version 460
+
+vec2 kPositions[4] = vec2[](
+    vec2(-1.0,  1.0),
+    vec2(-1.0, -1.0),
+    vec2( 1.0,  1.0),
+    vec2( 1.0, -1.0)
+);
+
+void main() {
+    gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+}
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.inl b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.inl
new file mode 100644
index 000000000..fbce9412c
--- /dev/null
+++ b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.inl
@@ -0,0 +1,91 @@
+// Generated from GLSL:
+//
+// #version 460
+// 
+// vec2 kPositions[4] = vec2[](
+//     vec2(-1.0,  1.0),
+//     vec2(-1.0, -1.0),
+//     vec2( 1.0,  1.0),
+//     vec2( 1.0, -1.0)
+// );
+// 
+// void main() {
+//     gl_Position = vec4(kPositions[gl_VertexIndex], 0.0, 1.0);
+// }
+const std::vector<uint8_t> kSecondaryCommandBufferVert = {
+	0x03, 0x02, 0x23, 0x07, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x06, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x47, 0x4c, 0x53, 0x4c, 0x2e, 0x73, 0x74, 0x64, 0x2e, 0x34, 0x35, 0x30, 
+	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 
+	0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 
+	0x02, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x47, 0x4c, 0x5f, 0x47, 
+	0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x63, 0x70, 0x70, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x5f, 
+	0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 0x00, 
+	0x04, 0x00, 0x08, 0x00, 0x47, 0x4c, 0x5f, 0x47, 0x4f, 0x4f, 0x47, 0x4c, 0x45, 0x5f, 0x69, 0x6e, 
+	0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x00, 
+	0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 
+	0x05, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x6b, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 
+	0x6e, 0x73, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x17, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 
+	0x65, 0x72, 0x56, 0x65, 0x72, 0x74, 0x65, 0x78, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x50, 0x6f, 0x73, 0x69, 0x74, 
+	0x69, 0x6f, 0x6e, 0x00, 0x06, 0x00, 0x07, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x67, 0x6c, 0x5f, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x07, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x43, 
+	0x6c, 0x69, 0x70, 0x44, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x06, 0x00, 0x07, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x43, 0x75, 0x6c, 0x6c, 0x44, 
+	0x69, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x05, 0x00, 0x03, 0x00, 0x19, 0x00, 0x00, 0x00, 
+	0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x67, 0x6c, 0x5f, 0x56, 
+	0x65, 0x72, 0x74, 0x65, 0x78, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
+	0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x48, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00, 
+	0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x47, 0x00, 0x03, 0x00, 
+	0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x47, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x00, 0x00, 
+	0x0b, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 
+	0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xbf, 0x2b, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 
+	0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 
+	0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 
+	0x0e, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
+	0x12, 0x00, 0x00, 0x00, 0x17, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x04, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 
+	0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x16, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x15, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x06, 0x00, 0x17, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x18, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 
+	0x18, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x15, 0x00, 0x04, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 
+	0x1a, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x04, 0x00, 
+	0x1c, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x1f, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x04, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 
+	0x26, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x36, 0x00, 0x05, 0x00, 
+	0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
+	0xf8, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 
+	0x13, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 
+	0x1d, 0x00, 0x00, 0x00, 0x41, 0x00, 0x05, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 
+	0x0c, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 
+	0x21, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x51, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 
+	0x23, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x00, 0x05, 0x00, 
+	0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
+	0x50, 0x00, 0x07, 0x00, 0x14, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 
+	0x24, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x41, 0x00, 0x05, 0x00, 
+	0x26, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 
+	0x3e, 0x00, 0x03, 0x00, 0x27, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x01, 0x00, 
+	0x38, 0x00, 0x01, 0x00, 
+};
+
diff --git a/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.spv b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.spv
new file mode 100644
index 000000000..b7c2cd77e
Binary files /dev/null and b/tests/graphics/vulkan/secondary_command_buffer/secondary_command_buffer.vert.spv differ
diff --git a/tests/hal/Android.bp b/tests/hal/Android.bp
index acf49bf1e..6d1d771aa 100644
--- a/tests/hal/Android.bp
+++ b/tests/hal/Android.bp
@@ -22,14 +22,14 @@ cc_test {
     srcs: ["hal_implementation_test.cpp"],
     static_libs: [
         "libaidlmetadata",
-        "libhidlmetadata",
         "libhidl-gen-utils",
+        "libhidlmetadata",
     ],
     shared_libs: [
         "libbase",
         "libbinder",
-        "libvintf",
         "libutils",
+        "libvintf",
         "packagemanager_aidl-cpp",
     ],
     product_variables: {
@@ -42,7 +42,7 @@ cc_test {
         "-Werror",
     ],
     test_suites: [
-        "device-tests",
         "automotive-tests",
+        "device-tests",
     ],
 }
diff --git a/tests/hal/hal_implementation_test.cpp b/tests/hal/hal_implementation_test.cpp
index 1b6667087..fd5721e87 100644
--- a/tests/hal/hal_implementation_test.cpp
+++ b/tests/hal/hal_implementation_test.cpp
@@ -191,7 +191,7 @@ static const std::set<std::string> kTvOnlyAidl = {
      */
     "android.hardware.tv.hdmi.cec",        "android.hardware.tv.hdmi.earc",
     "android.hardware.tv.hdmi.connection", "android.hardware.tv.tuner",
-    "android.hardware.tv.input",
+    "android.hardware.tv.input",           "android.hardware.tv.mediaquality",
 };
 
 static const std::set<std::string> kRadioOnlyAidl = {
@@ -225,6 +225,7 @@ static const std::set<std::string> kAlwaysMissingAidl = {
     "android.hardware.graphics.common",
     "android.hardware.input.common",
     "android.media.audio.common.types",
+    "android.media.audio.eraser.types",
     "android.hardware.radio",
     "android.hardware.uwb.fira_android",
     "android.hardware.wifi.common",
@@ -249,6 +250,11 @@ static const std::set<std::string> kAlwaysMissingAidl = {
      * Context: (b/130076572, g/android-idl-discuss/c/0SaiY0p-vJw/)
      */
     "android.hardware.usb.gadget",
+    // Currently this HAL only implements a feature for protected VMs, and the
+    // reference implementation of this HAL only works with pKVM hypervisor.
+    // TODO(b/360102915): remove this after implementing no-op version of HAL
+    //  for cuttlefish.
+    "android.hardware.virtualization.capabilities.capabilities_service",
 };
 
 /*
@@ -270,6 +276,11 @@ static const std::vector<VersionedAidlPackage> kKnownMissingAidl = {
     {"android.automotive.computepipe.registry.", 2, 273549907},
     {"android.automotive.computepipe.runner.", 2, 273549907},
     {"android.hardware.automotive.evs.", 2, 274162534},
+    {"android.hardware.security.see.authmgr.", 1, 379940224},
+    {"android.hardware.security.see.storage.", 1, 379940224},
+    {"android.hardware.security.see.hwcrypto.", 1, 379940224},
+    {"android.hardware.security.see.hdcp.", 1, 379940224},
+    {"android.system.vold.", 1, 362567323},
 };
 
 // android.hardware.foo.IFoo -> android.hardware.foo.
diff --git a/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java b/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
index 1f147abee..c9b95256d 100644
--- a/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
+++ b/tests/snapshot/src/com/android/cuttlefish/tests/SnapshotTest.java
@@ -51,39 +51,42 @@ public class SnapshotTest extends BaseHostJUnit4Test {
     @Test
     public void testSnapshot() throws Exception {
         String snapshotId = "snapshot_" + UUID.randomUUID().toString();
-
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device
         new DeviceSnapshotHandler().snapshotDevice(getDevice(), snapshotId);
 
-        // Create a file in tmp directory
-        final String tmpFile = "/data/local/tmp/snapshot_tmp";
-        getDevice().executeShellCommand("touch " + tmpFile);
-
-        // Reboot the device to make sure the file persists.
-        getDevice().reboot();
-        File file = getDevice().pullFile(tmpFile);
-        if (file == null) {
-            Assert.fail("Setup failed: tmp file failed to persist after device reboot.");
-        }
-
-        long startAllRuns = System.currentTimeMillis();
-        for (int i = 0; i < mTestCount; i++) {
-            CLog.d("Restore snapshot attempt #%d", i);
-            long start = System.currentTimeMillis();
-            new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
-            long duration = System.currentTimeMillis() - start;
-            CLog.d("Restore snapshot took %dms to finish", duration);
-        }
-        CLog.d(
-                "%d Restore snapshot runs finished successfully, with average time of %dms",
-                mTestCount, (System.currentTimeMillis() - startAllRuns) / mTestCount);
-
-        // Verify that the device is back online and pre-existing file is gone.
-        file = getDevice().pullFile(tmpFile);
-        if (file != null) {
-            Assert.fail("Restore snapshot failed: pre-existing file still exists.");
+        try {
+            // Create a file in tmp directory
+            final String tmpFile = "/data/local/tmp/snapshot_tmp";
+            getDevice().executeShellCommand("touch " + tmpFile);
+
+            // Reboot the device to make sure the file persists.
+            getDevice().reboot();
+            File file = getDevice().pullFile(tmpFile);
+            if (file == null) {
+                Assert.fail("Setup failed: tmp file failed to persist after device reboot.");
+            }
+
+            long startAllRuns = System.currentTimeMillis();
+            for (int i = 0; i < mTestCount; i++) {
+                CLog.d("Restore snapshot attempt #%d", i);
+                long start = System.currentTimeMillis();
+                new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
+                long duration = System.currentTimeMillis() - start;
+                CLog.d("Restore snapshot took %dms to finish", duration);
+            }
+            CLog.d(
+                    "%d Restore snapshot runs finished successfully, with average time of %dms",
+                    mTestCount, (System.currentTimeMillis() - startAllRuns) / mTestCount);
+
+            // Verify that the device is back online and pre-existing file is gone.
+            file = getDevice().pullFile(tmpFile);
+            if (file != null) {
+                Assert.fail("Restore snapshot failed: pre-existing file still exists.");
+            }
+        } finally {
+            new DeviceSnapshotHandler().deleteSnapshot(getDevice(), snapshotId);
         }
     }
 
@@ -94,45 +97,50 @@ public class SnapshotTest extends BaseHostJUnit4Test {
     @Test
     public void testSnapshotReboot() throws Exception {
         String snapshotId = "snapshot_" + UUID.randomUUID().toString();
-
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device.
         new DeviceSnapshotHandler().snapshotDevice(getDevice(), snapshotId);
-        // Restore the device.
-        new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
-        // Reboot the device.
-        getDevice().reboot();
-        // Verify that the device is back online.
-        getDevice().executeShellCommand("echo test");
+        try {
+            // Restore the device.
+            new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
+            // Reboot the device.
+            getDevice().reboot();
+            // Verify that the device is back online.
+            getDevice().executeShellCommand("echo test");
+        } finally {
+            new DeviceSnapshotHandler().deleteSnapshot(getDevice(), snapshotId);
+        }
     }
 
     // Test powerwash after restoring
     @Test
     public void testSnapshotPowerwash() throws Exception {
         String snapshotId = "snapshot_" + UUID.randomUUID().toString();
-
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
         // Snapshot the device.
         new DeviceSnapshotHandler().snapshotDevice(getDevice(), snapshotId);
-        // Restore the device.
-        new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
-        CLog.d("Powerwash attempt after restore");
-        long start = System.currentTimeMillis();
-        boolean success = new DeviceResetHandler(getInvocationContext()).resetDevice(getDevice());
-        assertTrue(String.format("Powerwash reset failed during attempt after restore"), success);
-        long duration = System.currentTimeMillis() - start;
-        CLog.d("Powerwash took %dms to finish", duration);
-        // Verify that the device is back online.
-        getDevice().executeShellCommand("echo test");
+        try {
+            // Restore the device.
+            new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
+            CLog.d("Powerwash attempt after restore");
+            long start = System.currentTimeMillis();
+            boolean success = new DeviceResetHandler(getInvocationContext()).resetDevice(getDevice());
+            assertTrue(String.format("Powerwash reset failed during attempt after restore"), success);
+            long duration = System.currentTimeMillis() - start;
+            CLog.d("Powerwash took %dms to finish", duration);
+            // Verify that the device is back online.
+            getDevice().executeShellCommand("echo test");
+        } finally {
+            new DeviceSnapshotHandler().deleteSnapshot(getDevice(), snapshotId);
+        }
     }
 
     // Test powerwash the device, then snapshot and restore
     @Test
     public void testPowerwashSnapshot() throws Exception {
         String snapshotId = "snapshot_" + UUID.randomUUID().toString();
-
         CLog.d("Powerwash attempt before restore");
         long start = System.currentTimeMillis();
         boolean success = new DeviceResetHandler(getInvocationContext()).resetDevice(getDevice());
@@ -143,9 +151,13 @@ public class SnapshotTest extends BaseHostJUnit4Test {
         getDevice().executeShellCommand("echo test");
         // Snapshot the device>
         new DeviceSnapshotHandler().snapshotDevice(getDevice(), snapshotId);
-        // Restore the device.
-        new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
-        // Verify that the device is back online.
-        getDevice().executeShellCommand("echo test");
+        try {
+            // Restore the device.
+            new DeviceSnapshotHandler().restoreSnapshotDevice(getDevice(), snapshotId);
+            // Verify that the device is back online.
+            getDevice().executeShellCommand("echo test");
+        } finally {
+            new DeviceSnapshotHandler().deleteSnapshot(getDevice(), snapshotId);
+        }
     }
 }
diff --git a/tests/utils/Android.bp b/tests/utils/Android.bp
index 5bdcb7d48..92856522a 100644
--- a/tests/utils/Android.bp
+++ b/tests/utils/Android.bp
@@ -25,4 +25,4 @@ java_library_host {
         "compatibility-host-util",
         "tradefed",
     ],
-}
\ No newline at end of file
+}
diff --git a/tests/wmediumd_control/Android.bp b/tests/wmediumd_control/Android.bp
index e62321b32..57f67b743 100644
--- a/tests/wmediumd_control/Android.bp
+++ b/tests/wmediumd_control/Android.bp
@@ -32,9 +32,9 @@ java_test_host {
         "tradefed",
     ],
     static_libs: [
-        "cuttlefish_host_test_utils",
-        "platform-test-annotations",
         "WmediumdServerProto_java",
+        "cuttlefish_host_test_utils",
         "libprotobuf-java-util-full",
+        "platform-test-annotations",
     ],
 }
diff --git a/tools/gigabyte-ampere-cuttlefish-installer/addpreseed.sh b/tools/gigabyte-ampere-cuttlefish-installer/addpreseed.sh
index c0bc88a2c..4fea2db56 100755
--- a/tools/gigabyte-ampere-cuttlefish-installer/addpreseed.sh
+++ b/tools/gigabyte-ampere-cuttlefish-installer/addpreseed.sh
@@ -14,9 +14,9 @@ AFTERINSTALLSCRIPT=$(realpath "${BASEDIR}"/preseed/after_install_1.sh)
 
 part_img_ready=1
 if test "$auto_extract_efi" = 1; then
-  start_block=$(/sbin/fdisk -l "$orig_iso" | fgrep "$orig_iso"2 | \
+  start_block=$(/sbin/fdisk -l "$orig_iso" | grep -F "$orig_iso"2 | \
                 awk '{print $2}')
-  block_count=$(/sbin/fdisk -l "$orig_iso" | fgrep "$orig_iso"2 | \
+  block_count=$(/sbin/fdisk -l "$orig_iso" | grep -F "$orig_iso"2 | \
                 awk '{print $4}')
   if test "$start_block" -gt 0 -a "$block_count" -gt 0 2>/dev/null
   then
diff --git a/tools/gigabyte-ampere-cuttlefish-installer/preseed/preseed.cfg b/tools/gigabyte-ampere-cuttlefish-installer/preseed/preseed.cfg
index fe096d7aa..6da5ad305 100644
--- a/tools/gigabyte-ampere-cuttlefish-installer/preseed/preseed.cfg
+++ b/tools/gigabyte-ampere-cuttlefish-installer/preseed/preseed.cfg
@@ -71,7 +71,7 @@ d-i partman/early_command string \
     debconf-set partman-auto/disk "$DEVICE_FINAL"; \
   fi; \
   if [ x"$DEVICE_FINAL" != x ]; then \
-    NUMOFPARTS=$(list-devices partition | egrep ^"$DEVICE_FINAL" | wc -l); \
+    NUMOFPARTS=$(list-devices partition | grep -E ^"$DEVICE_FINAL" | wc -l); \
     if [ "$NUMOFPARTS" -lt 3 ]; then \
       debconf-set partman-auto/expert_recipe "$(debconf-get partman-auto/expert_recipe_linaro_home_format)"; \
     else \
@@ -123,7 +123,7 @@ d-i partman-auto/expert_recipe_linaro_home string             \
                       mountpoint{ /home }                     \
               .
 
-# 
+#
 d-i partman-auto/choose_recipe select efiroot
 d-i partman-basicfilesystems/no_swap boolean false
 
diff --git a/vsoc_arm/BoardConfig.mk b/vsoc_arm/BoardConfig.mk
new file mode 100644
index 000000000..2991f8f5b
--- /dev/null
+++ b/vsoc_arm/BoardConfig.mk
@@ -0,0 +1,40 @@
+#
+# Copyright 2024 The Android Open-Source Project
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
+#
+
+#
+# arm target for Cuttlefish
+#
+
+TARGET_KERNEL_USE ?= 6.6
+TARGET_KERNEL_ARCH ?= arm64
+SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
+TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
+KERNEL_MODULES_PATH ?= \
+    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
+
+-include device/google/cuttlefish/vsoc_arm64/BoardConfig.mk
+
+TARGET_BOARD_PLATFORM := vsoc_arm
+TARGET_ARCH := arm
+TARGET_ARCH_VARIANT := armv8-a
+TARGET_CPU_ABI := armeabi-v7a
+TARGET_CPU_ABI2 := armeabi
+TARGET_CPU_VARIANT := cortex-a53
+TARGET_2ND_ARCH :=
+TARGET_2ND_ARCH_VARIANT :=
+TARGET_2ND_CPU_ABI :=
+TARGET_2ND_CPU_ABI2 :=
+TARGET_2ND_CPU_VARIANT :=
diff --git a/vsoc_arm/bootloader.mk b/vsoc_arm/bootloader.mk
new file mode 100644
index 000000000..ce2944390
--- /dev/null
+++ b/vsoc_arm/bootloader.mk
@@ -0,0 +1,20 @@
+#
+# Copyright (C) 2020 The Android Open Source Project
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
+#
+
+TARGET_NO_BOOTLOADER := false
+# FIXME: Copying the QEMU bootloader for now, but this should be updated..
+BOARD_PREBUILT_BOOTLOADER := \
+    device/google/cuttlefish_prebuilts/bootloader/crosvm_aarch64/u-boot.bin
diff --git a/vsoc_riscv64/BoardConfig.mk b/vsoc_riscv64/BoardConfig.mk
index ddf2b7aa3..8ab40c073 100644
--- a/vsoc_riscv64/BoardConfig.mk
+++ b/vsoc_riscv64/BoardConfig.mk
@@ -42,6 +42,7 @@ TARGET_KERNEL_USE ?= mainline
 KERNEL_MODULES_PATH := device/google/cuttlefish_prebuilts/kernel/$(TARGET_KERNEL_USE)-$(TARGET_KERNEL_ARCH)
 TARGET_KERNEL_PATH := $(KERNEL_MODULES_PATH)/kernel-$(TARGET_KERNEL_USE)
 SYSTEM_DLKM_SRC ?= $(KERNEL_MODULES_PATH)/system_dlkm
+SYSTEM_VIRTIO_PREBUILTS_PATH := $(KERNEL_MODULES_PATH)
 
 -include device/google/cuttlefish/shared/BoardConfig.mk
 -include device/google/cuttlefish/shared/bluetooth/BoardConfig.mk
diff --git a/vsoc_x86/BoardConfig.mk b/vsoc_x86/BoardConfig.mk
index 61abe4fd7..a26749037 100644
--- a/vsoc_x86/BoardConfig.mk
+++ b/vsoc_x86/BoardConfig.mk
@@ -46,5 +46,4 @@ TARGET_KERNEL_ARCH := x86_64
 -include device/google/cuttlefish/shared/swiftshader/BoardConfig.mk
 -include device/google/cuttlefish/shared/telephony/BoardConfig.mk
 -include device/google/cuttlefish/shared/vibrator/BoardConfig.mk
--include device/google/cuttlefish/shared/virgl/BoardConfig.mk
--include vendor/google/tv/gcbs/projects/reference-v4/dtvBoardConfig.mk
+-include device/google/cuttlefish/shared/virgl/BoardConfig.mk
\ No newline at end of file
diff --git a/vsoc_x86_64/phone/aosp_cf.mk b/vsoc_x86_64/phone/aosp_cf.mk
index 52aaec465..e7c7dc2bc 100644
--- a/vsoc_x86_64/phone/aosp_cf.mk
+++ b/vsoc_x86_64/phone/aosp_cf.mk
@@ -62,12 +62,19 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
 
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+# Allow the following Android.mk files
+PRODUCT_ALLOWED_ANDROIDMK_FILES := bootable/recovery/Android.mk
+PRODUCT_ANDROIDMK_ALLOWLIST_FILE := vendor/google/build/androidmk/aosp_cf_allowlist.mk
+
 # Compare target product name directly to avoid this from any product inherits aosp_cf.mk
-ifneq ($(filter aosp_cf_x86_64_phone aosp_cf_x86_64_phone_soong_system,$(TARGET_PRODUCT)),)
+ifneq ($(filter aosp_cf_x86_64_phone aosp_cf_x86_64_phone_soong_system aosp_cf_x86_64_foldable,$(TARGET_PRODUCT)),)
 # TODO(b/350000347) Enable Soong defined system image from coverage build
 ifneq ($(CLANG_COVERAGE),true)
 ifneq ($(NATIVE_COVERAGE),true)
-PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_cf_system_x86_64
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_shared_system_image
 endif # NATIVE_COVERAGE
 endif # CLANG_COVERAGE
-endif # aosp_cf_x86_64_phone
+endif # aosp_cf_x86_64_phone aosp_cf_x86_64_foldable
diff --git a/vsoc_x86_64_only/phone/aosp_cf.mk b/vsoc_x86_64_only/phone/aosp_cf.mk
index d8435746f..eb36473b0 100644
--- a/vsoc_x86_64_only/phone/aosp_cf.mk
+++ b/vsoc_x86_64_only/phone/aosp_cf.mk
@@ -61,3 +61,9 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+# Allow the following Android.mk files
+PRODUCT_ALLOWED_ANDROIDMK_FILES := bootable/recovery/Android.mk
+PRODUCT_ANDROIDMK_ALLOWLIST_FILE := vendor/google/build/androidmk/aosp_cf_allowlist.mk
```

