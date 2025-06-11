```diff
diff --git a/Android.bp b/Android.bp
index 7a176ec4..6c5556ad 100644
--- a/Android.bp
+++ b/Android.bp
@@ -122,22 +122,6 @@ genrule {
     out: ["netsim-daemon/src/ffi.rs.h"],
 }
 
-genrule {
-    name: "netsim_cli_cc",
-    tools: ["cxxbridge"],
-    cmd: "$(location cxxbridge) $(in) >> $(out)",
-    srcs: ["rust/cli/src/ffi.rs"],
-    out: ["netsim-cli/src/ffi.rs.cc"],
-}
-
-genrule {
-    name: "netsim_cli_h",
-    tools: ["cxxbridge"],
-    cmd: "$(location cxxbridge) $(in) --header >> $(out)",
-    srcs: ["rust/cli/src/ffi.rs"],
-    out: ["netsim-cli/src/ffi.rs.h"],
-}
-
 genrule {
     name: "netsim_netlink_rust_gen",
     defaults: ["pdl_rust_generator_defaults"],
@@ -374,33 +358,14 @@ rust_test_host {
     test_suites: ["general_tests"],
 }
 
-cc_library_host_static {
-    name: "lib-netsim-frontend-client",
-    defaults: ["netsim_defaults"],
-    srcs: [
-        "src/frontend/frontend_client.cc",
-        "src/util/ini_file.cc",
-        "src/util/log.cc",
-        "src/util/os_utils.cc",
-        "src/util/string_utils.cc",
-    ],
-    generated_headers: [
-        "cxx-bridge-header",
-        "netsim_cli_h",
-    ],
-    shared_libs: ["libgrpc++"],
-    generated_sources: ["netsim_cli_cc"],
-    static_libs: [
-        "libprotobuf-cpp-full",
-        "lib-netsim-frontend-proto",
-    ],
-}
-
 rust_defaults {
     name: "netsim_cli_defaults",
     rustlibs: [
+        "libanyhow",
         "libclap",
-        "libcxx",
+        "libfutures",
+        "libfutures_util",
+        "libgrpcio",
         "libhex",
         "libnetsim_common",
         "libnetsim_proto",
@@ -409,16 +374,6 @@ rust_defaults {
     ],
 }
 
-rust_defaults {
-    name: "netsim_cli_cc_defaults",
-    shared_libs: ["libgrpc++"],
-    static_libs: [
-        "lib-netsim-frontend-client",
-        "lib-netsim-frontend-proto",
-        "libprotobuf-cpp-full",
-    ],
-}
-
 rust_test_host {
     name: "libnetsim_cli_tests",
     srcs: ["rust/cli/src/lib.rs"],
@@ -432,7 +387,6 @@ rust_library_host {
     srcs: ["rust/cli/src/lib.rs"],
     defaults: [
         "netsim_cli_defaults",
-        "netsim_cli_cc_defaults",
     ],
 }
 
@@ -443,26 +397,3 @@ rust_binary_host {
         "libnetsim_cli",
     ],
 }
-
-rust_binary_host {
-    name: "netsim_test_client",
-    srcs: ["rust/frontend/src/netsim_test_client.rs"],
-    rustlibs: [
-        "libgrpcio",
-        "libnetsim_proto",
-        "libprotobuf",
-        "libnetsim_common",
-    ],
-}
-
-rust_binary_host {
-    name: "netsim_test_server",
-    srcs: ["rust/frontend/src/netsim_test_server.rs"],
-    rustlibs: [
-        "libgrpcio",
-        "libnetsim_proto",
-        "libprotobuf",
-        "libnetsim_common",
-        "libfutures",
-    ],
-}
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 9db7b218..b56f89d1 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -40,8 +40,7 @@ add_subdirectory(src)
 if(TARGET Rust::Rustc)
   android_add_executable(
     TARGET netsim LICENSE Apache-2.0 INSTALL . SRC rust/netsim.cc
-    DEPS frontend-client grpc++ netsim-cli-proto-lib netsim-cli-rust-lib
-         protobuf::libprotobuf util-lib)
+    DEPS netsim-cli-proto-lib netsim-cli-rust-lib)
 
   android_add_executable(
     TARGET netsimd
diff --git a/cmake/netsim_dependencies.cmake b/cmake/netsim_dependencies.cmake
index 39236c97..72f814ec 100644
--- a/cmake/netsim_dependencies.cmake
+++ b/cmake/netsim_dependencies.cmake
@@ -47,6 +47,7 @@ if(WINDOWS_MSVC_X86_64)
   add_cxx_flag("-std:c++17")
 else()
   add_cxx_flag("-std=c++17")
+  add_cxx_flag("-fno-exceptions")
 endif()
 set(CMAKE_CXX_STANDARD 17)
 set(CMAKE_CXX_STANDARD_REQUIRED ON)
@@ -121,13 +122,6 @@ endif()
 
 prebuilt(Threads)
 
-# We need the auto generated header for some components, so let's set the
-# ANDROID_HW_CONFIG_H variable to point to the generated header. Those that need
-# it can add it to their sources list, and it will be there.
-set(HW_PROPERTIES_INI
-    ${EXTERNAL_QEMU}/android/emu/avd/src/android/avd/hardware-properties.ini)
-android_generate_hw_config()
-
 if(DARWIN_AARCH64 AND NOT Rust_COMPILER)
   message(
     STATUS
@@ -199,21 +193,13 @@ add_subdirectory(${EXTERNAL_QEMU}/android/third_party/libslirp libslirp)
 add_subdirectory(${EXTERNAL_QEMU}/android/third_party/googletest/ gtest)
 add_subdirectory(${EXTERNAL_QEMU}/android/third_party/lz4 lz4)
 add_subdirectory(${EXTERNAL_QEMU}/android/third_party/re2 re2)
-add_subdirectory(${EXTERNAL_QEMU}/android/third_party/libselinux libselinux)
-add_subdirectory(${EXTERNAL_QEMU}/android/third_party/libsparse libsparse)
-add_subdirectory(${EXTERNAL_QEMU}/android/third_party/ext4_utils ext4_utils)
 add_subdirectory(${EXTERNAL}/cares cares)
 add_subdirectory(${EXTERNAL}/glib/glib glib2)
 add_subdirectory(${EXTERNAL}/grpc/emulator grpc)
 add_subdirectory(${EXTERNAL}/qemu/android/android-emu-base android-emu-base)
 add_subdirectory(${EXTERNAL}/qemu/android/android-net/android android-emu-net)
-add_subdirectory(${EXTERNAL}/qemu/android-qemu2-glue/netsim
-                 android-wifi-service)
 add_subdirectory(${EXTERNAL}/qemu/android/emu/base emu-base)
 add_subdirectory(${EXTERNAL}/qemu/android/emu/utils android-emu-utils)
-add_subdirectory(${EXTERNAL}/qemu/android/emu/files android-emu-files)
-add_subdirectory(${EXTERNAL}/qemu/android/emu/agents android-emu-agents)
-add_subdirectory(${EXTERNAL}/qemu/android/emu/proxy android-emu-proxy)
 add_subdirectory(${EXTERNAL}/webrtc/third_party/jsoncpp jsoncpp)
 
 # Short term fix for missing glib2 dll for Windows build
diff --git a/dummy.c b/dummy.c
deleted file mode 100644
index e69de29b..00000000
diff --git a/guide/src/development/README.md b/guide/src/development/README.md
index 7262b84b..783e7831 100644
--- a/guide/src/development/README.md
+++ b/guide/src/development/README.md
@@ -6,10 +6,10 @@ Netsim can be built as part of emulator or cuttlefish and best practice is to
 setup both and switch between repo directories to test each build environment.
 
 * To build with emulator, follow the [netsim with emulator](#netsim_with_emulator)
-section to build netsim by `cmake` in `emu-master-dev` manifest branch.
+section to build netsim by `cmake` in `emu-master-dev` and `netsim-dev` manifest branch.
 
 * To build with cuttlefish, follow the [netsim with
-cuttlefish](#netsim_with_cuttlefish) to build netsim by `soong` in `aosp-master`
+cuttlefish](#netsim_with_cuttlefish) to build netsim by `soong` in `aosp-main`
 manifest branch.
 
 ## Emulator and cuttlefish build branches
@@ -35,9 +35,9 @@ AOSP builds](https://source.android.com/docs/setup/create/cuttlefish-use).
 
 The table below summarizes the two virtual device environments:
 
-|                 |      emulator         | cuttlefish         |
-|:----------------|:---------------------:|:----------------:  |
-| AOSP branch     | `emu-master-dev`      | `aosp-master`      |
+|                 |      emulator                        | cuttlefish         |
+|:----------------|:------------------------------------:|:----------------:  |
+| AOSP branch     | `emu-master-dev` & `netsim-dev`      | `aosp-main`      |
 | launcher        | `emulator` app and<br>Android Studio | `launch_cvd` and<br>`cvd` app |
 | best for        | App developer         | Platform developer |
 | Supported OS    | Linux, MacOS, Windows | Linux              |
@@ -63,16 +63,7 @@ https://android.googlesource.com/platform/external/qemu/+/refs/heads/emu-master-
 
 In general changes should be built and tested on all three operating systems.
 
-Follow the instructions above links for workstation setup. Linux setup and build
-is summarized below:
-
-### Linux workstation set up
-
-Install cmake and ninja:
-
-```
-sudo apt-get install -y cmake ninja-build
-```
+Follow the instructions above links for workstation setup.
 
 ### Initialize and sync the code
 
@@ -93,7 +84,7 @@ repo sync -j8
 Use Android emulator toolchain script to run the build:
 ```
 cd /repo/emu-master-dev/external/qemu
-sh android/rebuild.sh
+sh android/rebuild.sh --gfxstream
 ```
 
 The output can be found in:
@@ -101,18 +92,28 @@ The output can be found in:
 /repo/emu-master-dev/external/qemu/objs/distribution/emulator
 ```
 
-### Emulator incremental netsim build
+### Netsim incremental build
+
+Currently the netsim binaries in
+`/repo/emu-master-dev/prebuilts/android-emulator-build/common/netsim/*` does get weekly updates with the latest binary. If you want to build netsim from source, you must sync and build from a separate branch `netsim-dev`.
+
+Download the netsim-dev branch:
 
-The `emulator` rebuild script does a complete clean build of all emulator components.
-For incrmental builds of the `netsimd` component, you can use the `cmake_setup` script:
 ```
-cd /repo/emu-master-dev/tools/netsim
-sh scripts/cmake_setup.sh
+mkdir /repo/netsim-dev; cd /repo/netsim-dev
+repo init -u https://android.googlesource.com/platform/manifest -b netsim-dev
 ```
+Sync the source code:
 
-Then use `ninja` for a partial netsim build:
 ```
-ninja -C objs netsimd
+repo sync -j8
+```
+
+The `emulator` rebuild script does a complete clean build of all emulator components.
+For incrmental builds of the `netsimd` component, you can use the `cmake_setup` script:
+```
+cd /repo/netsim-dev/tools/netsim
+scripts/build_tools.py --task configure compileinstall
 ```
 
 If the build fails with rust errors it may be necessary to issue this command:
@@ -121,16 +122,16 @@ If the build fails with rust errors it may be necessary to issue this command:
 rm rust/Cargo.lock
 ```
 
-Copy Web UI assets into `objs/netsim-ui`.
+The output can be found in
+
 ```
-sh scripts/build_ui.sh
+/repo/netsim-dev/tools/netsim/objs/distribution/emulator
 ```
-If you wish to change the source code of the ui and rebuild, use the `-b` flag.
 
-The output can be found in
+You can copy the netsim binaries into `emu-master-dev`
 
 ```
-/repo/emu-master-dev/tools/netsim/objs
+cp -r /repo/netsim-dev/tools/netsim/objs/distribution/emulator/* /repo/emu-master-dev/external/qemu/objs/distribution/emulator
 ```
 
 ## <a name="netsim_with_cuttlefish"></a>Build netsim with cuttlefish
@@ -144,8 +145,8 @@ Follow the instructions in the codelab for workstation setup.
 
 Initialize the repo:
 ```
-mkdir /repo/aosp-master; cd /repo/aosp-master
-repo init -u https://android.googlesource.com/platform/manifest -b aosp-master
+mkdir /repo/aosp-main; cd /repo/aosp-main
+repo init -u https://android.googlesource.com/platform/manifest -b aosp-main
 ```
 
 Sync the source code:
@@ -172,7 +173,7 @@ m -j64
 
 The netsim executable can be found in:
 ```
-/repo/aosp-master/out/host/linux-x86/bin
+/repo/aosp-main/out/host/linux-x86/bin
 ```
 
 ### Cuttlefish incremental netsim build
@@ -185,29 +186,14 @@ m netsimd -j64
 
 ## Unit Testing
 
-Unit tests can be run from the `aosp-master` branch using the `atest` command:
+Unit tests can be run from the `aosp-main` branch using the `atest` command:
 ```
 atest --host-unit-test-only --test-filter netsim
 ```
 
-Rust tests can also be run for individual Rust modules using the `cargo test` command:
-```
-cd tools/netsim/rust/netsim-cxx/
-cargo test transport
-```
-
-## Build Tips
-
-### Building across repository directories
-
-You will need to verify that any changes in `tools/netsim` can be built from
-both manifest branches. To temporarily copy changes between repositories we often
-use:
-
+Unit tests can be run from the `netsim-dev` branch using the following command
 ```
-git diff HEAD^ > /tmp/git.diff
-cd /repo/emu-master-dev
-git apply /tmp/git.diff
+scripts/build_tools.py --task runtest
 ```
 
 ### Repo workflow
diff --git a/proto/netsim/frontend.proto b/proto/netsim/frontend.proto
index f48378a7..03e473d9 100644
--- a/proto/netsim/frontend.proto
+++ b/proto/netsim/frontend.proto
@@ -158,8 +158,7 @@ message PatchCaptureRequest {
   // Capture Identifier
   uint32 id = 1;
 
-  // Body of PatchCapture that will be channeled into
-  // body for HandleCaptureCxx
+  // Valid capture field(s) to patch
   message PatchCapture {
     // Capture state
     optional bool state = 1;
diff --git a/rust/CMakeLists.txt b/rust/CMakeLists.txt
index 94266da7..a323913d 100644
--- a/rust/CMakeLists.txt
+++ b/rust/CMakeLists.txt
@@ -43,6 +43,8 @@ corrosion_set_env_vars(
   GRPCIO_SYS_GRPC_INCLUDE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../../../external/grpc/include"
 )
 
+set_prebuilt_packets_env_vars(netsim-daemon)
+
 add_custom_target(
   netsim_rust_packets
   DEPENDS pdl_gen-RootCanalGeneratedPackets_rs pdl_gen-NetlinkPackets_rs
@@ -66,7 +68,6 @@ if(WIN32)
   # 4. This isn't needed in mac and Linux because corrosion doesn't pass
   #    -fno-exception flag.
   set(CXXFLAGS "${CMAKE_CXX_FLAGS} /DRUST_CXX_NO_EXCEPTIONS")
-  corrosion_set_env_vars(netsim-cli CXXFLAGS=${CXXFLAGS})
   corrosion_set_env_vars(netsim-daemon CXXFLAGS=${CXXFLAGS})
 endif()
 
diff --git a/rust/capture/src/lib.rs b/rust/capture/src/lib.rs
index a5d3ecd7..03594f23 100644
--- a/rust/capture/src/lib.rs
+++ b/rust/capture/src/lib.rs
@@ -29,4 +29,5 @@
 //!   compatibility with other pcap tools.
 //!
 
+/// This module contains the core functionality for reading and writing pcap files.
 pub mod pcap;
diff --git a/rust/capture/src/pcap.rs b/rust/capture/src/pcap.rs
index 0dfc8f89..c291e3b8 100644
--- a/rust/capture/src/pcap.rs
+++ b/rust/capture/src/pcap.rs
@@ -57,12 +57,19 @@ type Result<A> = std::result::Result<A, std::io::Error>;
 #[derive(AsBytes, FromBytes, FromZeroes)]
 /// Represents the global header of a pcap capture file.
 pub struct FileHeader {
+    /// Magic number identifying the file format.
     pub magic: u32,
+    /// Major version of the pcap format.
     pub version_major: u16,
+    /// Minor version of the pcap format.
     pub version_minor: u16,
+    /// Time zone offset.
     pub thiszone: i32,
+    /// Timestamp accuracy.
     pub sigfigs: u32,
+    /// Maximum packet length in bytes.
     pub snaplen: u32,
+    /// Data link type of packets.
     pub linktype: u32,
 }
 
@@ -100,6 +107,7 @@ impl Default for FileHeader {
 /// https://www.tcpdump.org/linktypes.html
 #[repr(u32)]
 pub enum LinkType {
+    /// Null link type (BSD loopback)
     Null = 0,
     /// Ethernet
     Ethernet = 1,
@@ -153,9 +161,11 @@ impl From<LinkType> for u32 {
 #[derive(AsBytes, FromBytes, FromZeroes)]
 /// Represents the header prepended to each packet in a pcap capture file.
 pub struct PacketHeader {
-    /// Timestamp of the captured packet.
+    /// Timestamp of the captured packet (seconds).
     pub tv_sec: u32,
+    /// Timestamp of the captured packet (microseconds).
     pub tv_usec: u32,
+    /// Number of bytes captured from the packet.
     pub caplen: u32,
     /// Original length of the packet on the network.
     pub len: u32,
diff --git a/rust/cli/Cargo.toml b/rust/cli/Cargo.toml
index d350bc1d..4653fc3a 100644
--- a/rust/cli/Cargo.toml
+++ b/rust/cli/Cargo.toml
@@ -1,16 +1,14 @@
 [package]
 name = "netsim-cli"
-version = "0.3.37"
+version = "0.3.50"
 edition = "2021"
-build = "build.rs"
 
 [lib]
 crate-type = ["staticlib", "lib"]
 doctest = false
-test = false
 
 [dependencies]
-hex = "0.4.3"
+anyhow = "1"
 clap = { version = "4.1.8", default-features = false, features = [
     "derive",
     "error-context",
@@ -18,13 +16,12 @@ clap = { version = "4.1.8", default-features = false, features = [
     "std",
     "usage",
 ] }
+futures = "0.3.30"
+futures-util = { version = "0.3.30", default-features = false, features = ["sink"] }
+grpcio =  {version= "0.13.0", default-features = false, features = ["protobufv3-codec"]}
+hex = "0.4.3"
+log = "0.4.17"
 netsim-proto = { path = "../proto" }
 netsim-common = { path = "../common" }
 protobuf = "3.2.0"
-cxx = { version = ">=1.0.85", features = ["c++17"] }
-log = "0.4.17"
 tracing = "0.1"
-grpcio =  {version= "0.13.0", default-features = false, features = ["protobufv3-codec"]}
-
-[build-dependencies]
-cxx-build = "1.0.92"
diff --git a/rust/cli/src/args.rs b/rust/cli/src/args.rs
index 3727024f..98bfd7b2 100644
--- a/rust/cli/src/args.rs
+++ b/rust/cli/src/args.rs
@@ -12,15 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::ffi::frontend_client_ffi::{FrontendClient, GrpcMethod};
+use anyhow::Result;
 use clap::builder::{PossibleValue, TypedValueParser};
 use clap::{Args, Parser, Subcommand, ValueEnum};
 use hex::{decode as hex_to_bytes, FromHexError};
-use netsim_common::util::time_display::TimeDisplay;
-use netsim_proto::common::ChipKind;
-use netsim_proto::frontend;
-use netsim_proto::frontend::patch_capture_request::PatchCapture as PatchCaptureProto;
-use netsim_proto::frontend::patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto;
 use netsim_proto::model::chip::ble_beacon::advertise_settings::{
     AdvertiseMode as AdvertiseModeProto, AdvertiseTxPower as AdvertiseTxPowerProto,
     Interval as IntervalProto, Tx_power as TxPowerProto,
@@ -28,21 +23,10 @@ use netsim_proto::model::chip::ble_beacon::advertise_settings::{
 use netsim_proto::model::chip::ble_beacon::{
     AdvertiseData as AdvertiseDataProto, AdvertiseSettings as AdvertiseSettingsProto,
 };
-use netsim_proto::model::chip::{
-    BleBeacon as Chip_Ble_Beacon, Bluetooth as Chip_Bluetooth, Chip as Chip_Type,
-    Radio as Chip_Radio,
-};
-use netsim_proto::model::{
-    self, chip_create, Chip, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
-    Position,
-};
-use protobuf::{Message, MessageField};
+
 use std::fmt;
 use std::iter;
 use std::str::FromStr;
-use tracing::error;
-
-pub type BinaryProtobuf = Vec<u8>;
 
 #[derive(Debug, Parser)]
 pub struct NetsimArgs {
@@ -62,7 +46,7 @@ pub struct NetsimArgs {
     pub vsock: Option<String>,
 }
 
-#[derive(Debug, Subcommand)]
+#[derive(Debug, Subcommand, PartialEq)]
 #[command(infer_subcommands = true)]
 pub enum Command {
     /// Print Netsim version information
@@ -89,218 +73,7 @@ pub enum Command {
     Bumble,
 }
 
-impl Command {
-    /// Return the generated request protobuf as a byte vector
-    /// The parsed command parameters are used to construct the request protobuf which is
-    /// returned as a byte vector that can be sent to the server.
-    pub fn get_request_bytes(&self) -> BinaryProtobuf {
-        match self {
-            Command::Version => Vec::new(),
-            Command::Radio(cmd) => {
-                let mut chip = Chip { ..Default::default() };
-                let chip_state = match cmd.status {
-                    UpDownStatus::Up => true,
-                    UpDownStatus::Down => false,
-                };
-                if cmd.radio_type == RadioType::Wifi {
-                    let mut wifi_chip = Chip_Radio::new();
-                    wifi_chip.state = chip_state.into();
-                    chip.set_wifi(wifi_chip);
-                    chip.kind = ChipKind::WIFI.into();
-                } else if cmd.radio_type == RadioType::Uwb {
-                    let mut uwb_chip = Chip_Radio::new();
-                    uwb_chip.state = chip_state.into();
-                    chip.set_uwb(uwb_chip);
-                    chip.kind = ChipKind::UWB.into();
-                } else {
-                    let mut bt_chip = Chip_Bluetooth::new();
-                    let mut bt_chip_radio = Chip_Radio::new();
-                    bt_chip_radio.state = chip_state.into();
-                    if cmd.radio_type == RadioType::Ble {
-                        bt_chip.low_energy = Some(bt_chip_radio).into();
-                    } else {
-                        bt_chip.classic = Some(bt_chip_radio).into();
-                    }
-                    chip.kind = ChipKind::BLUETOOTH.into();
-                    chip.set_bt(bt_chip);
-                }
-                let mut result = frontend::PatchDeviceRequest::new();
-                let mut device = PatchDeviceFieldsProto::new();
-                device.name = Some(cmd.name.clone());
-                device.chips.push(chip);
-                result.device = Some(device).into();
-                result.write_to_bytes().unwrap()
-            }
-            Command::Move(cmd) => {
-                let mut result = frontend::PatchDeviceRequest::new();
-                let mut device = PatchDeviceFieldsProto::new();
-                let position = Position {
-                    x: cmd.x,
-                    y: cmd.y,
-                    z: cmd.z.unwrap_or_default(),
-                    ..Default::default()
-                };
-                device.name = Some(cmd.name.clone());
-                device.position = Some(position).into();
-                result.device = Some(device).into();
-                result.write_to_bytes().unwrap()
-            }
-            Command::Devices(_) => Vec::new(),
-            Command::Reset => Vec::new(),
-            Command::Gui => {
-                unimplemented!("get_request_bytes is not implemented for Gui Command.");
-            }
-            Command::Capture(cmd) => match cmd {
-                Capture::List(_) => Vec::new(),
-                Capture::Get(_) => {
-                    unimplemented!("get_request_bytes not implemented for Capture Get command. Use get_requests instead.")
-                }
-                Capture::Patch(_) => {
-                    unimplemented!("get_request_bytes not implemented for Capture Patch command. Use get_requests instead.")
-                }
-            },
-            Command::Artifact => {
-                unimplemented!("get_request_bytes is not implemented for Artifact Command.");
-            }
-            Command::Beacon(action) => match action {
-                Beacon::Create(kind) => match kind {
-                    BeaconCreate::Ble(args) => {
-                        let device = MessageField::some(DeviceCreateProto {
-                            name: args.device_name.clone().unwrap_or_default(),
-                            chips: vec![ChipCreateProto {
-                                name: args.chip_name.clone().unwrap_or_default(),
-                                kind: ChipKind::BLUETOOTH_BEACON.into(),
-                                chip: Some(chip_create::Chip::BleBeacon(
-                                    chip_create::BleBeaconCreate {
-                                        address: args.address.clone().unwrap_or_default(),
-                                        settings: MessageField::some((&args.settings).into()),
-                                        adv_data: MessageField::some((&args.advertise_data).into()),
-                                        scan_response: MessageField::some(
-                                            (&args.scan_response_data).into(),
-                                        ),
-                                        ..Default::default()
-                                    },
-                                )),
-                                ..Default::default()
-                            }],
-                            ..Default::default()
-                        });
-
-                        let result = frontend::CreateDeviceRequest { device, ..Default::default() };
-                        result.write_to_bytes().unwrap()
-                    }
-                },
-                Beacon::Patch(kind) => match kind {
-                    BeaconPatch::Ble(args) => {
-                        let device = MessageField::some(PatchDeviceFieldsProto {
-                            name: Some(args.device_name.clone()),
-                            chips: vec![Chip {
-                                name: args.chip_name.clone(),
-                                kind: ChipKind::BLUETOOTH_BEACON.into(),
-                                chip: Some(Chip_Type::BleBeacon(Chip_Ble_Beacon {
-                                    bt: MessageField::some(Chip_Bluetooth::new()),
-                                    address: args.address.clone().unwrap_or_default(),
-                                    settings: MessageField::some((&args.settings).into()),
-                                    adv_data: MessageField::some((&args.advertise_data).into()),
-                                    scan_response: MessageField::some(
-                                        (&args.scan_response_data).into(),
-                                    ),
-                                    ..Default::default()
-                                })),
-                                ..Default::default()
-                            }],
-                            ..Default::default()
-                        });
-
-                        let result = frontend::PatchDeviceRequest { device, ..Default::default() };
-                        result.write_to_bytes().unwrap()
-                    }
-                },
-                Beacon::Remove(_) => Vec::new(),
-            },
-            Command::Bumble => {
-                unimplemented!("get_request_bytes is not implemented for Bumble Command.");
-            }
-        }
-    }
-
-    /// Create and return the request protobuf(s) for the command.
-    /// In the case of a command with pattern argument(s) there may be multiple gRPC requests.
-    /// The parsed command parameters are used to construct the request protobuf.
-    /// The client is used to send gRPC call(s) to retrieve information needed for request protobufs.
-    pub fn get_requests(&mut self, client: &cxx::UniquePtr<FrontendClient>) -> Vec<BinaryProtobuf> {
-        match self {
-            Command::Capture(Capture::Patch(cmd)) => {
-                let mut reqs = Vec::new();
-                let filtered_captures = Self::get_filtered_captures(client, &cmd.patterns);
-                // Create a request for each capture
-                for capture in &filtered_captures {
-                    let mut result = frontend::PatchCaptureRequest::new();
-                    result.id = capture.id;
-                    let capture_state = match cmd.state {
-                        OnOffState::On => true,
-                        OnOffState::Off => false,
-                    };
-                    let mut patch_capture = PatchCaptureProto::new();
-                    patch_capture.state = capture_state.into();
-                    result.patch = Some(patch_capture).into();
-                    reqs.push(result.write_to_bytes().unwrap())
-                }
-                reqs
-            }
-            Command::Capture(Capture::Get(cmd)) => {
-                let mut reqs = Vec::new();
-                let filtered_captures = Self::get_filtered_captures(client, &cmd.patterns);
-                // Create a request for each capture
-                for capture in &filtered_captures {
-                    let mut result = frontend::GetCaptureRequest::new();
-                    result.id = capture.id;
-                    reqs.push(result.write_to_bytes().unwrap());
-                    let time_display = TimeDisplay::new(
-                        capture.timestamp.get_or_default().seconds,
-                        capture.timestamp.get_or_default().nanos as u32,
-                    );
-                    let file_extension = "pcap";
-                    cmd.filenames.push(format!(
-                        "netsim-{:?}-{}-{}-{}.{}",
-                        capture.id,
-                        capture.device_name.to_owned().replace(' ', "_"),
-                        Self::chip_kind_to_string(capture.chip_kind.enum_value_or_default()),
-                        time_display.utc_display(),
-                        file_extension
-                    ));
-                }
-                reqs
-            }
-            _ => {
-                unimplemented!(
-                    "get_requests not implemented for this command. Use get_request_bytes instead."
-                )
-            }
-        }
-    }
-
-    fn get_filtered_captures(
-        client: &cxx::UniquePtr<FrontendClient>,
-        patterns: &[String],
-    ) -> Vec<model::Capture> {
-        // Get list of captures
-        let result = client.send_grpc(&GrpcMethod::ListCapture, &Vec::new());
-        if !result.is_ok() {
-            error!("ListCapture Grpc call error: {}", result.err());
-            return Vec::new();
-        }
-        let mut response =
-            frontend::ListCaptureResponse::parse_from_bytes(result.byte_vec().as_slice()).unwrap();
-        if !patterns.is_empty() {
-            // Filter out list of captures with matching patterns
-            Self::filter_captures(&mut response.captures, patterns)
-        }
-        response.captures
-    }
-}
-
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq)]
 pub struct Radio {
     /// Radio type
     #[arg(value_enum, ignore_case = true)]
@@ -338,7 +111,7 @@ impl fmt::Display for UpDownStatus {
     }
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq)]
 pub struct Move {
     /// Device name
     pub name: String,
@@ -350,20 +123,21 @@ pub struct Move {
     pub z: Option<f32>,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq)]
 pub struct Devices {
     /// Continuously print device(s) information every second
     #[arg(short, long)]
     pub continuous: bool,
 }
 
-#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Default)]
 pub enum OnOffState {
+    #[default]
     On,
     Off,
 }
 
-#[derive(Debug, Subcommand)]
+#[derive(Debug, Subcommand, PartialEq)]
 pub enum Beacon {
     /// Create a beacon chip
     #[command(subcommand)]
@@ -375,13 +149,13 @@ pub enum Beacon {
     Remove(BeaconRemove),
 }
 
-#[derive(Debug, Subcommand)]
+#[derive(Debug, Subcommand, PartialEq)]
 pub enum BeaconCreate {
     /// Create a Bluetooth low-energy beacon chip
     Ble(BeaconCreateBle),
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct BeaconCreateBle {
     /// Name of the device to create
     pub device_name: Option<String>,
@@ -398,13 +172,13 @@ pub struct BeaconCreateBle {
     pub scan_response_data: BeaconBleScanResponseData,
 }
 
-#[derive(Debug, Subcommand)]
+#[derive(Debug, Subcommand, PartialEq)]
 pub enum BeaconPatch {
     /// Modify a Bluetooth low-energy beacon chip
     Ble(BeaconPatchBle),
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct BeaconPatchBle {
     /// Name of the device that contains the chip
     pub device_name: String,
@@ -421,7 +195,7 @@ pub struct BeaconPatchBle {
     pub scan_response_data: BeaconBleScanResponseData,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq)]
 pub struct BeaconRemove {
     /// Name of the device to remove
     pub device_name: String,
@@ -429,7 +203,7 @@ pub struct BeaconRemove {
     pub chip_name: Option<String>,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct BeaconBleAdvertiseData {
     /// Whether the device name should be included in the advertise packet
     #[arg(long, required = false)]
@@ -442,8 +216,8 @@ pub struct BeaconBleAdvertiseData {
     pub manufacturer_data: Option<ParsableBytes>,
 }
 
-#[derive(Debug, Clone)]
-pub struct ParsableBytes(Vec<u8>);
+#[derive(Debug, Clone, PartialEq)]
+pub struct ParsableBytes(pub Vec<u8>);
 
 impl ParsableBytes {
     fn unwrap(self) -> Vec<u8> {
@@ -458,7 +232,7 @@ impl FromStr for ParsableBytes {
     }
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct BeaconBleScanResponseData {
     /// Whether the device name should be included in the scan response packet
     #[arg(long, required = false)]
@@ -471,7 +245,7 @@ pub struct BeaconBleScanResponseData {
     pub scan_response_manufacturer_data: Option<ParsableBytes>,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct BeaconBleSettings {
     /// Set advertise mode to control the advertising latency
     #[arg(long, value_parser = IntervalParser)]
@@ -487,7 +261,7 @@ pub struct BeaconBleSettings {
     pub timeout: Option<u64>,
 }
 
-#[derive(Clone, Debug)]
+#[derive(Clone, Debug, PartialEq)]
 pub enum Interval {
     Mode(AdvertiseMode),
     Milliseconds(u64),
@@ -525,7 +299,7 @@ impl TypedValueParser for IntervalParser {
     }
 }
 
-#[derive(Clone, Debug)]
+#[derive(Clone, Debug, PartialEq)]
 pub enum TxPower {
     Level(TxPowerLevel),
     Dbm(i8),
@@ -563,7 +337,7 @@ impl TypedValueParser for TxPowerParser {
     }
 }
 
-#[derive(Debug, Clone, ValueEnum)]
+#[derive(Debug, Clone, ValueEnum, PartialEq)]
 pub enum AdvertiseMode {
     /// Lowest power consumption, preferred advertising mode
     LowPower,
@@ -573,7 +347,7 @@ pub enum AdvertiseMode {
     LowLatency,
 }
 
-#[derive(Debug, Clone, ValueEnum)]
+#[derive(Debug, Clone, ValueEnum, PartialEq)]
 pub enum TxPowerLevel {
     /// Lowest transmission power level
     UltraLow,
@@ -585,7 +359,7 @@ pub enum TxPowerLevel {
     High,
 }
 
-#[derive(Debug, Subcommand)]
+#[derive(Debug, Subcommand, PartialEq)]
 pub enum Capture {
     /// List currently available Captures (packet captures)
     List(ListCapture),
@@ -595,7 +369,7 @@ pub enum Capture {
     Get(GetCapture),
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct ListCapture {
     /// Optional strings of pattern for captures to list. Possible filter fields include Capture ID, Device Name, and Chip Kind
     pub patterns: Vec<String>,
@@ -604,7 +378,7 @@ pub struct ListCapture {
     pub continuous: bool,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct PatchCapture {
     /// Packet capture state
     #[arg(value_enum, ignore_case = true)]
@@ -613,7 +387,7 @@ pub struct PatchCapture {
     pub patterns: Vec<String>,
 }
 
-#[derive(Debug, Args)]
+#[derive(Debug, Args, PartialEq, Default)]
 pub struct GetCapture {
     /// Optional strings of pattern for captures to get. Possible filter fields include Capture ID, Device Name, and Chip Kind
     pub patterns: Vec<String>,
diff --git a/rust/cli/src/ffi.rs b/rust/cli/src/ffi.rs
deleted file mode 100644
index 86eb822a..00000000
--- a/rust/cli/src/ffi.rs
+++ /dev/null
@@ -1,97 +0,0 @@
-//! Frontend-client library for rust.
-///
-/// Rust to C++ Grpc frontend.proto for Windows, linux and mac.
-///
-/// This can be replaced with grpcio native implementation when the
-/// Windows build works.
-
-/// Wrapper struct for application defined ClientResponseReader
-pub struct ClientResponseReader {
-    /// Delegated handler for reading responses
-    pub handler: Box<dyn ClientResponseReadable>,
-}
-
-/// Delegating functions to handler
-impl ClientResponseReader {
-    fn handle_chunk(&self, chunk: &[u8]) {
-        self.handler.handle_chunk(chunk);
-    }
-    fn handle_error(&self, error_code: u32, error_message: &str) {
-        self.handler.handle_error(error_code, error_message);
-    }
-}
-
-/// Trait for ClientResponseReader handler functions
-pub trait ClientResponseReadable {
-    /// Process each chunk of streaming response
-    fn handle_chunk(&self, chunk: &[u8]);
-    /// Process errors in response
-    fn handle_error(&self, error_code: u32, error_message: &str);
-}
-
-#[cxx::bridge(namespace = "netsim::frontend")]
-#[allow(clippy::needless_maybe_sized)]
-#[allow(missing_docs)]
-#[allow(unsafe_op_in_unsafe_fn)]
-pub mod frontend_client_ffi {
-    // Shared enum GrpcMethod
-    #[derive(Debug, PartialEq, Eq)]
-    pub enum GrpcMethod {
-        GetVersion,
-        CreateDevice,
-        DeleteChip,
-        PatchDevice,
-        ListDevice,
-        Reset,
-        ListCapture,
-        PatchCapture,
-        GetCapture,
-    }
-
-    extern "Rust" {
-        type ClientResponseReader;
-        fn handle_chunk(&self, chunk: &[u8]);
-        fn handle_error(&self, error_code: u32, error_message: &str);
-    }
-
-    // C++ types and signatures exposed to Rust.
-    unsafe extern "C++" {
-        include!("frontend/frontend_client.h");
-
-        type FrontendClient;
-        type ClientResult;
-
-        #[allow(dead_code)]
-        #[rust_name = "new_frontend_client"]
-        pub fn NewFrontendClient(server: &CxxString) -> UniquePtr<FrontendClient>;
-
-        #[allow(dead_code)]
-        #[rust_name = "get_capture"]
-        pub fn GetCapture(
-            self: &FrontendClient,
-            request: &Vec<u8>,
-            client_reader: &ClientResponseReader,
-        ) -> UniquePtr<ClientResult>;
-
-        #[allow(dead_code)]
-        #[rust_name = "send_grpc"]
-        pub fn SendGrpc(
-            self: &FrontendClient,
-            grpc_method: &GrpcMethod,
-            request: &Vec<u8>,
-        ) -> UniquePtr<ClientResult>;
-
-        #[allow(dead_code)]
-        #[rust_name = "is_ok"]
-        pub fn IsOk(self: &ClientResult) -> bool;
-
-        #[allow(dead_code)]
-        #[rust_name = "err"]
-        pub fn Err(self: &ClientResult) -> String;
-
-        #[allow(dead_code)]
-        #[rust_name = "byte_vec"]
-        pub fn ByteVec(self: &ClientResult) -> &CxxVector<u8>;
-
-    }
-}
diff --git a/rust/cli/src/file_handler.rs b/rust/cli/src/file_handler.rs
index fcefb044..8dd330a8 100644
--- a/rust/cli/src/file_handler.rs
+++ b/rust/cli/src/file_handler.rs
@@ -12,12 +12,11 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::ffi::ClientResponseReadable;
+use crate::grpc_client::ClientResponseReadable;
 use std::fs::File;
 /// Implements handler for pcap operations
 use std::io::Write;
 use std::path::PathBuf;
-use tracing::error;
 
 pub struct FileHandler {
     pub file: File,
@@ -31,13 +30,4 @@ impl ClientResponseReadable for FileHandler {
             .write_all(chunk)
             .unwrap_or_else(|_| panic!("Unable to write to file: {}", self.path.display()));
     }
-    // function to handle error response
-    fn handle_error(&self, error_code: u32, error_message: &str) {
-        error!(
-            "Handling error code: {}, msg: {}, on file: {}",
-            error_code,
-            error_message,
-            self.path.display()
-        );
-    }
 }
diff --git a/rust/cli/src/grpc_client.rs b/rust/cli/src/grpc_client.rs
new file mode 100644
index 00000000..9cc9917f
--- /dev/null
+++ b/rust/cli/src/grpc_client.rs
@@ -0,0 +1,108 @@
+//! gRPC frontend client library for netsim.
+use anyhow::{anyhow, Result};
+use futures_util::StreamExt;
+use netsim_proto::frontend;
+use netsim_proto::frontend_grpc::FrontendServiceClient;
+use protobuf::well_known_types::empty;
+
+/// Wrapper struct for application defined ClientResponseReader
+pub struct ClientResponseReader {
+    /// Delegated handler for reading responses
+    pub handler: Box<dyn ClientResponseReadable>,
+}
+
+/// Delegating functions to handler
+impl ClientResponseReader {
+    fn handle_chunk(&self, chunk: &[u8]) {
+        self.handler.handle_chunk(chunk);
+    }
+}
+
+/// Trait for ClientResponseReader handler functions
+pub trait ClientResponseReadable {
+    /// Process each chunk of streaming response
+    fn handle_chunk(&self, chunk: &[u8]);
+}
+
+// Enum of Grpc Requests holding the request proto as applicable
+#[derive(Debug, PartialEq)]
+pub enum GrpcRequest {
+    GetVersion,
+    ListDevice,
+    Reset,
+    ListCapture,
+    CreateDevice(frontend::CreateDeviceRequest),
+    DeleteChip(frontend::DeleteChipRequest),
+    PatchDevice(frontend::PatchDeviceRequest),
+    PatchCapture(frontend::PatchCaptureRequest),
+    GetCapture(frontend::GetCaptureRequest),
+}
+
+// Enum of Grpc Responses holding the response proto as applicable
+#[derive(Debug, PartialEq)]
+pub enum GrpcResponse {
+    GetVersion(frontend::VersionResponse),
+    ListDevice(frontend::ListDeviceResponse),
+    Reset,
+    ListCapture(frontend::ListCaptureResponse),
+    CreateDevice(frontend::CreateDeviceResponse),
+    DeleteChip,
+    PatchDevice,
+    PatchCapture,
+    Unknown,
+}
+
+pub fn get_capture(
+    client: &FrontendServiceClient,
+    req: &frontend::GetCaptureRequest,
+    client_reader: &mut ClientResponseReader,
+) -> Result<()> {
+    let mut stream = client.get_capture(req)?;
+    // Use block_on to run the async block handling all chunks
+    futures::executor::block_on(async {
+        // Read every available chunk from gRPC stream
+        while let Some(Ok(chunk)) = stream.next().await {
+            let bytes = chunk.capture_stream;
+            client_reader.handle_chunk(&bytes);
+        }
+    });
+
+    Ok(())
+}
+
+pub fn send_grpc(
+    client: &FrontendServiceClient,
+    grpc_request: &GrpcRequest,
+) -> Result<GrpcResponse> {
+    match grpc_request {
+        GrpcRequest::GetVersion => {
+            Ok(GrpcResponse::GetVersion(client.get_version(&empty::Empty::new())?))
+        }
+        GrpcRequest::ListDevice => {
+            Ok(GrpcResponse::ListDevice(client.list_device(&empty::Empty::new())?))
+        }
+        GrpcRequest::Reset => {
+            client.reset(&empty::Empty::new())?;
+            Ok(GrpcResponse::Reset)
+        }
+        GrpcRequest::ListCapture => {
+            Ok(GrpcResponse::ListCapture(client.list_capture(&empty::Empty::new())?))
+        }
+        GrpcRequest::CreateDevice(req) => {
+            Ok(GrpcResponse::CreateDevice(client.create_device(req)?))
+        }
+        GrpcRequest::DeleteChip(req) => {
+            client.delete_chip(req)?;
+            Ok(GrpcResponse::DeleteChip)
+        }
+        GrpcRequest::PatchDevice(req) => {
+            client.patch_device(req)?;
+            Ok(GrpcResponse::PatchDevice)
+        }
+        GrpcRequest::PatchCapture(req) => {
+            client.patch_capture(req)?;
+            Ok(GrpcResponse::PatchCapture)
+        }
+        _ => Err(anyhow!(grpcio::RpcStatus::new(grpcio::RpcStatusCode::INVALID_ARGUMENT,))),
+    }
+}
diff --git a/rust/cli/src/lib.rs b/rust/cli/src/lib.rs
index c4294b35..027f7d95 100644
--- a/rust/cli/src/lib.rs
+++ b/rust/cli/src/lib.rs
@@ -17,36 +17,37 @@
 mod args;
 mod browser;
 mod display;
-mod ffi;
 mod file_handler;
+mod grpc_client;
 mod requests;
 mod response;
 
-use netsim_common::util::os_utils::{get_instance, get_server_address};
-use netsim_proto::frontend::{DeleteChipRequest, ListDeviceResponse};
-use protobuf::Message;
+use netsim_common::util::ini_file::get_server_address;
+use netsim_common::util::os_utils::get_instance;
+use netsim_proto::frontend;
+
+use anyhow::{anyhow, Result};
+use grpcio::{ChannelBuilder, EnvBuilder};
 use std::env;
 use std::fs::File;
 use std::path::PathBuf;
 use tracing::error;
 
-use crate::ffi::frontend_client_ffi::{
-    new_frontend_client, ClientResult, FrontendClient, GrpcMethod,
-};
-use crate::ffi::ClientResponseReader;
-use args::{BinaryProtobuf, GetCapture, NetsimArgs};
+use crate::grpc_client::{ClientResponseReader, GrpcRequest, GrpcResponse};
+use netsim_proto::frontend_grpc::FrontendServiceClient;
+
+use args::{GetCapture, NetsimArgs};
 use clap::Parser;
-use cxx::{let_cxx_string, UniquePtr};
 use file_handler::FileHandler;
 use netsim_common::util::netsim_logger;
 
 // helper function to process streaming Grpc request
 fn perform_streaming_request(
-    client: &cxx::UniquePtr<FrontendClient>,
+    client: &FrontendServiceClient,
     cmd: &mut GetCapture,
-    req: &BinaryProtobuf,
+    req: &frontend::GetCaptureRequest,
     filename: &str,
-) -> UniquePtr<ClientResult> {
+) -> Result<()> {
     let dir = if cmd.location.is_some() {
         PathBuf::from(cmd.location.to_owned().unwrap())
     } else {
@@ -54,9 +55,10 @@ fn perform_streaming_request(
     };
     let output_file = dir.join(filename);
     cmd.current_file = output_file.display().to_string();
-    client.get_capture(
+    grpc_client::get_capture(
+        client,
         req,
-        &ClientResponseReader {
+        &mut ClientResponseReader {
             handler: Box::new(FileHandler {
                 file: File::create(&output_file).unwrap_or_else(|_| {
                     panic!("Failed to create file: {}", &output_file.display())
@@ -70,19 +72,18 @@ fn perform_streaming_request(
 /// helper function to send the Grpc request(s) and handle the response(s) per the given command
 fn perform_command(
     command: &mut args::Command,
-    client: cxx::UniquePtr<FrontendClient>,
-    grpc_method: GrpcMethod,
+    client: FrontendServiceClient,
     verbose: bool,
-) -> Result<(), String> {
+) -> anyhow::Result<()> {
     // Get command's gRPC request(s)
     let requests = match command {
         args::Command::Capture(args::Capture::Patch(_) | args::Capture::Get(_)) => {
             command.get_requests(&client)
         }
         args::Command::Beacon(args::Beacon::Remove(_)) => {
-            vec![args::Command::Devices(args::Devices { continuous: false }).get_request_bytes()]
+            vec![args::Command::Devices(args::Devices { continuous: false }).get_request()]
         }
-        _ => vec![command.get_request_bytes()],
+        _ => vec![command.get_request()],
     };
     let mut process_error = false;
     // Process each request
@@ -90,26 +91,41 @@ fn perform_command(
         let result = match command {
             // Continuous option sends the gRPC call every second
             args::Command::Devices(ref cmd) if cmd.continuous => {
-                continuous_perform_command(command, &client, grpc_method, req, verbose)?
+                continuous_perform_command(command, &client, req, verbose)?;
+                panic!("Continuous command interrupted. Exiting.");
             }
             args::Command::Capture(args::Capture::List(ref cmd)) if cmd.continuous => {
-                continuous_perform_command(command, &client, grpc_method, req, verbose)?
+                continuous_perform_command(command, &client, req, verbose)?;
+                panic!("Continuous command interrupted. Exiting.");
             }
             // Get Capture use streaming gRPC reader request
             args::Command::Capture(args::Capture::Get(ref mut cmd)) => {
-                perform_streaming_request(&client, cmd, req, &cmd.filenames[i].to_owned())
+                let GrpcRequest::GetCapture(request) = req else {
+                    panic!("Expected to find GetCaptureRequest. Got: {:?}", req);
+                };
+                perform_streaming_request(&client, cmd, request, &cmd.filenames[i].to_owned())?;
+                Ok(None)
             }
             args::Command::Beacon(args::Beacon::Remove(ref cmd)) => {
-                let devices = client.send_grpc(&GrpcMethod::ListDevice, req);
-                let id = find_id_for_remove(devices.byte_vec().as_slice(), cmd)?;
-                let req = &DeleteChipRequest { id, ..Default::default() }
-                    .write_to_bytes()
-                    .map_err(|err| format!("{err}"))?;
-
-                client.send_grpc(&grpc_method, req)
+                let response = grpc_client::send_grpc(&client, &GrpcRequest::ListDevice)?;
+                let GrpcResponse::ListDevice(response) = response else {
+                    panic!("Expected to find ListDeviceResponse. Got: {:?}", response);
+                };
+                let id = find_id_for_remove(response, cmd)?;
+                let res = grpc_client::send_grpc(
+                    &client,
+                    &GrpcRequest::DeleteChip(frontend::DeleteChipRequest {
+                        id,
+                        ..Default::default()
+                    }),
+                )?;
+                Ok(Some(res))
             }
             // All other commands use a single gRPC call
-            _ => client.send_grpc(&grpc_method, req),
+            _ => {
+                let response = grpc_client::send_grpc(&client, req)?;
+                Ok(Some(response))
+            }
         };
         if let Err(e) = process_result(command, result, verbose) {
             error!("{}", e);
@@ -117,13 +133,16 @@ fn perform_command(
         };
     }
     if process_error {
-        return Err("Not all requests were processed successfully.".to_string());
+        return Err(anyhow!("Not all requests were processed successfully."));
     }
     Ok(())
 }
 
-fn find_id_for_remove(response: &[u8], cmd: &args::BeaconRemove) -> Result<u32, String> {
-    let devices = ListDeviceResponse::parse_from_bytes(response).unwrap().devices;
+fn find_id_for_remove(
+    response: frontend::ListDeviceResponse,
+    cmd: &args::BeaconRemove,
+) -> anyhow::Result<u32> {
+    let devices = response.devices;
     let id = devices
         .iter()
         .find(|device| device.name == cmd.device_name)
@@ -131,9 +150,18 @@ fn find_id_for_remove(response: &[u8], cmd: &args::BeaconRemove) -> Result<u32,
             (device.chips.len() == 1).then_some(&device.chips[0]),
             |chip_name| device.chips.iter().find(|chip| &chip.name == chip_name)
         ))
-        .ok_or(cmd.chip_name.as_ref().map_or(
-            format!("failed to delete chip: device '{}' has multiple possible candidates, please specify a chip name", cmd.device_name),
-            |chip_name| format!("failed to delete chip: could not find chip '{}' on device '{}'", chip_name, cmd.device_name))
+        .ok_or(
+            cmd.chip_name
+                .as_ref()
+                .map_or(
+                    anyhow!("failed to delete chip: device '{}' has multiple possible candidates, please specify a chip name", cmd.device_name),
+                    |chip_name| {
+                        anyhow!(
+                            "failed to delete chip: could not find chip '{}' on device '{}'",
+                            chip_name, cmd.device_name
+                        )
+                    },
+                )
         )?
         .id;
 
@@ -143,28 +171,30 @@ fn find_id_for_remove(response: &[u8], cmd: &args::BeaconRemove) -> Result<u32,
 /// Check and handle the gRPC call result
 fn continuous_perform_command(
     command: &args::Command,
-    client: &cxx::UniquePtr<FrontendClient>,
-    grpc_method: GrpcMethod,
-    request: &Vec<u8>,
+    client: &FrontendServiceClient,
+    grpc_request: &GrpcRequest,
     verbose: bool,
-) -> Result<UniquePtr<ClientResult>, String> {
+) -> anyhow::Result<()> {
     loop {
-        process_result(command, client.send_grpc(&grpc_method, request), verbose)?;
+        let response = grpc_client::send_grpc(client, grpc_request)?;
+        process_result(command, Ok(Some(response)), verbose)?;
         std::thread::sleep(std::time::Duration::from_secs(1));
     }
 }
 /// Check and handle the gRPC call result
 fn process_result(
     command: &args::Command,
-    result: UniquePtr<ClientResult>,
+    result: anyhow::Result<Option<GrpcResponse>>,
     verbose: bool,
-) -> Result<(), String> {
-    if result.is_ok() {
-        command.print_response(result.byte_vec().as_slice(), verbose);
-    } else {
-        return Err(format!("Grpc call error: {}", result.err()));
+) -> anyhow::Result<()> {
+    match result {
+        Ok(grpc_response) => {
+            let response = grpc_response.unwrap_or(GrpcResponse::Unknown);
+            command.print_response(&response, verbose);
+            Ok(())
+        }
+        Err(e) => Err(anyhow!("Grpc call error: {}", e)),
     }
-    Ok(())
 }
 #[no_mangle]
 /// main Rust netsim CLI function to be called by C wrapper netsim.cc
@@ -185,23 +215,15 @@ pub extern "C" fn rust_main() {
         browser::open("https://google.github.io/bumble/hive/index.html");
         return;
     }
-    let grpc_method = args.command.grpc_method();
     let server = match (args.vsock, args.port) {
         (Some(vsock), _) => format!("vsock:{vsock}"),
         (_, Some(port)) => format!("localhost:{port}"),
         _ => get_server_address(get_instance(args.instance)).unwrap_or_default(),
     };
-    let_cxx_string!(server = server);
-    let client = new_frontend_client(&server);
-    if client.is_null() {
-        if !server.is_empty() {
-            error!("Unable to create frontend client. Please ensure netsimd is running and listening on {server:?}.");
-        } else {
-            error!("Unable to create frontend client. Please ensure netsimd is running.");
-        }
-        return;
-    }
-    if let Err(e) = perform_command(&mut args.command, client, grpc_method, args.verbose) {
+    let channel =
+        ChannelBuilder::new(std::sync::Arc::new(EnvBuilder::new().build())).connect(&server);
+    let client = FrontendServiceClient::new(channel);
+    if let Err(e) = perform_command(&mut args.command, client, args.verbose) {
         error!("{e}");
     }
 }
@@ -213,7 +235,6 @@ mod tests {
         frontend::ListDeviceResponse,
         model::{Chip as ChipProto, Device as DeviceProto},
     };
-    use protobuf::Message;
 
     use crate::find_id_for_remove;
 
@@ -234,7 +255,7 @@ mod tests {
             ..Default::default()
         };
 
-        let id = find_id_for_remove(response.write_to_bytes().unwrap().as_slice(), cmd);
+        let id = find_id_for_remove(response, cmd);
         assert!(id.is_ok(), "{}", id.unwrap_err());
         let id = id.unwrap();
 
@@ -268,7 +289,7 @@ mod tests {
             ..Default::default()
         };
 
-        let id = find_id_for_remove(response.write_to_bytes().unwrap().as_slice(), cmd);
+        let id = find_id_for_remove(response, cmd);
         assert!(id.is_ok(), "{}", id.unwrap_err());
         let id = id.unwrap();
 
@@ -295,7 +316,7 @@ mod tests {
             ..Default::default()
         };
 
-        let id = find_id_for_remove(response.write_to_bytes().unwrap().as_slice(), cmd);
+        let id = find_id_for_remove(response, cmd);
         assert!(id.is_err());
     }
 
@@ -323,7 +344,7 @@ mod tests {
             ..Default::default()
         };
 
-        let id = find_id_for_remove(response.write_to_bytes().unwrap().as_slice(), cmd);
+        let id = find_id_for_remove(response, cmd);
         assert!(id.is_err());
     }
 }
diff --git a/rust/cli/src/requests.rs b/rust/cli/src/requests.rs
index 861ff0fb..017f4bd0 100644
--- a/rust/cli/src/requests.rs
+++ b/rust/cli/src/requests.rs
@@ -11,46 +11,255 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-
-use crate::args::{self, Beacon, Command};
-use crate::ffi::frontend_client_ffi::GrpcMethod;
-
-impl args::Command {
-    /// Return the respective GrpcMethod for the command
-    pub fn grpc_method(&self) -> GrpcMethod {
+use crate::args::{
+    Beacon, BeaconCreate, BeaconPatch, Capture, Command, OnOffState, RadioType, UpDownStatus,
+};
+use crate::grpc_client::{self, GrpcRequest, GrpcResponse};
+use netsim_common::util::time_display::TimeDisplay;
+use netsim_proto::common::ChipKind;
+use netsim_proto::frontend;
+use netsim_proto::frontend::patch_capture_request::PatchCapture as PatchCaptureProto;
+use netsim_proto::frontend::patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto;
+use netsim_proto::frontend_grpc::FrontendServiceClient;
+use netsim_proto::model::chip::{
+    BleBeacon as Chip_Ble_Beacon, Bluetooth as Chip_Bluetooth, Chip as Chip_Type,
+    Radio as Chip_Radio,
+};
+use netsim_proto::model::{
+    self, chip_create, Chip, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
+    Position,
+};
+use protobuf::MessageField;
+use tracing::error;
+
+impl Command {
+    /// Return the generated request protobuf message
+    /// The parsed command parameters are used to construct the request protobuf
+    pub fn get_request(&self) -> GrpcRequest {
         match self {
-            Command::Version => GrpcMethod::GetVersion,
-            Command::Radio(_) => GrpcMethod::PatchDevice,
-            Command::Move(_) => GrpcMethod::PatchDevice,
-            Command::Devices(_) => GrpcMethod::ListDevice,
-            Command::Reset => GrpcMethod::Reset,
-            Command::Capture(cmd) => match cmd {
-                args::Capture::List(_) => GrpcMethod::ListCapture,
-                args::Capture::Get(_) => GrpcMethod::GetCapture,
-                args::Capture::Patch(_) => GrpcMethod::PatchCapture,
-            },
+            Command::Version => GrpcRequest::GetVersion,
+            Command::Radio(cmd) => {
+                let mut chip = Chip { ..Default::default() };
+                let chip_state = match cmd.status {
+                    UpDownStatus::Up => true,
+                    UpDownStatus::Down => false,
+                };
+                if cmd.radio_type == RadioType::Wifi {
+                    let mut wifi_chip = Chip_Radio::new();
+                    wifi_chip.state = chip_state.into();
+                    chip.set_wifi(wifi_chip);
+                    chip.kind = ChipKind::WIFI.into();
+                } else if cmd.radio_type == RadioType::Uwb {
+                    let mut uwb_chip = Chip_Radio::new();
+                    uwb_chip.state = chip_state.into();
+                    chip.set_uwb(uwb_chip);
+                    chip.kind = ChipKind::UWB.into();
+                } else {
+                    let mut bt_chip = Chip_Bluetooth::new();
+                    let mut bt_chip_radio = Chip_Radio::new();
+                    bt_chip_radio.state = chip_state.into();
+                    if cmd.radio_type == RadioType::Ble {
+                        bt_chip.low_energy = Some(bt_chip_radio).into();
+                    } else {
+                        bt_chip.classic = Some(bt_chip_radio).into();
+                    }
+                    chip.kind = ChipKind::BLUETOOTH.into();
+                    chip.set_bt(bt_chip);
+                }
+                let mut result = frontend::PatchDeviceRequest::new();
+                let mut device = PatchDeviceFieldsProto::new();
+                device.name = Some(cmd.name.clone());
+                device.chips.push(chip);
+                result.device = Some(device).into();
+                GrpcRequest::PatchDevice(result)
+            }
+            Command::Move(cmd) => {
+                let mut result = frontend::PatchDeviceRequest::new();
+                let mut device = PatchDeviceFieldsProto::new();
+                let position = Position {
+                    x: cmd.x,
+                    y: cmd.y,
+                    z: cmd.z.unwrap_or_default(),
+                    ..Default::default()
+                };
+                device.name = Some(cmd.name.clone());
+                device.position = Some(position).into();
+                result.device = Some(device).into();
+                GrpcRequest::PatchDevice(result)
+            }
+            Command::Devices(_) => GrpcRequest::ListDevice,
+            Command::Reset => GrpcRequest::Reset,
             Command::Gui => {
-                panic!("No GrpcMethod for Ui Command.");
+                unimplemented!("get_request is not implemented for Gui Command.");
             }
+            Command::Capture(cmd) => match cmd {
+                Capture::List(_) => GrpcRequest::ListCapture,
+                Capture::Get(_) => {
+                    unimplemented!("get_request not implemented for Capture Get command. Use get_requests instead.")
+                }
+                Capture::Patch(_) => {
+                    unimplemented!("get_request not implemented for Capture Patch command. Use get_requests instead.")
+                }
+            },
             Command::Artifact => {
-                panic!("No GrpcMethod for Artifact Command.");
+                unimplemented!("get_request is not implemented for Artifact Command.");
             }
             Command::Beacon(action) => match action {
-                Beacon::Create(_) => GrpcMethod::CreateDevice,
-                Beacon::Patch(_) => GrpcMethod::PatchDevice,
-                Beacon::Remove(_) => GrpcMethod::DeleteChip,
+                Beacon::Create(kind) => match kind {
+                    BeaconCreate::Ble(args) => {
+                        let device = MessageField::some(DeviceCreateProto {
+                            name: args.device_name.clone().unwrap_or_default(),
+                            chips: vec![ChipCreateProto {
+                                name: args.chip_name.clone().unwrap_or_default(),
+                                kind: ChipKind::BLUETOOTH_BEACON.into(),
+                                chip: Some(chip_create::Chip::BleBeacon(
+                                    chip_create::BleBeaconCreate {
+                                        address: args.address.clone().unwrap_or_default(),
+                                        settings: MessageField::some((&args.settings).into()),
+                                        adv_data: MessageField::some((&args.advertise_data).into()),
+                                        scan_response: MessageField::some(
+                                            (&args.scan_response_data).into(),
+                                        ),
+                                        ..Default::default()
+                                    },
+                                )),
+                                ..Default::default()
+                            }],
+                            ..Default::default()
+                        });
+
+                        let result = frontend::CreateDeviceRequest { device, ..Default::default() };
+                        GrpcRequest::CreateDevice(result)
+                    }
+                },
+                Beacon::Patch(kind) => match kind {
+                    BeaconPatch::Ble(args) => {
+                        let device = MessageField::some(PatchDeviceFieldsProto {
+                            name: Some(args.device_name.clone()),
+                            chips: vec![Chip {
+                                name: args.chip_name.clone(),
+                                kind: ChipKind::BLUETOOTH_BEACON.into(),
+                                chip: Some(Chip_Type::BleBeacon(Chip_Ble_Beacon {
+                                    bt: MessageField::some(Chip_Bluetooth::new()),
+                                    address: args.address.clone().unwrap_or_default(),
+                                    settings: MessageField::some((&args.settings).into()),
+                                    adv_data: MessageField::some((&args.advertise_data).into()),
+                                    scan_response: MessageField::some(
+                                        (&args.scan_response_data).into(),
+                                    ),
+                                    ..Default::default()
+                                })),
+                                ..Default::default()
+                            }],
+                            ..Default::default()
+                        });
+
+                        let result = frontend::PatchDeviceRequest { device, ..Default::default() };
+                        GrpcRequest::PatchDevice(result)
+                    }
+                },
+                Beacon::Remove(_) => {
+                    // Placeholder - actual DeleteChipRequest will be constructed later
+                    GrpcRequest::DeleteChip(frontend::DeleteChipRequest { ..Default::default() })
+                }
             },
             Command::Bumble => {
-                panic!("No GrpcMethod for Bumble Command.");
+                unimplemented!("get_request is not implemented for Bumble Command.");
+            }
+        }
+    }
+
+    /// Create and return the request protobuf(s) for the command.
+    /// In the case of a command with pattern argument(s) there may be multiple gRPC requests.
+    /// The parsed command parameters are used to construct the request protobuf.
+    /// The client is used to send gRPC call(s) to retrieve information needed for request protobufs.
+    pub fn get_requests(&mut self, client: &FrontendServiceClient) -> Vec<GrpcRequest> {
+        match self {
+            Command::Capture(Capture::Patch(cmd)) => {
+                let mut reqs = Vec::new();
+                let filtered_captures = Self::get_filtered_captures(client, &cmd.patterns);
+                // Create a request for each capture
+                for capture in &filtered_captures {
+                    let mut result = frontend::PatchCaptureRequest::new();
+                    result.id = capture.id;
+                    let capture_state = match cmd.state {
+                        OnOffState::On => true,
+                        OnOffState::Off => false,
+                    };
+                    let mut patch_capture = PatchCaptureProto::new();
+                    patch_capture.state = capture_state.into();
+                    result.patch = Some(patch_capture).into();
+                    reqs.push(GrpcRequest::PatchCapture(result))
+                }
+                reqs
+            }
+            Command::Capture(Capture::Get(cmd)) => {
+                let mut reqs = Vec::new();
+                let filtered_captures = Self::get_filtered_captures(client, &cmd.patterns);
+                // Create a request for each capture
+                for capture in &filtered_captures {
+                    let mut result = frontend::GetCaptureRequest::new();
+                    result.id = capture.id;
+                    reqs.push(GrpcRequest::GetCapture(result));
+                    let time_display = TimeDisplay::new(
+                        capture.timestamp.get_or_default().seconds,
+                        capture.timestamp.get_or_default().nanos as u32,
+                    );
+                    let file_extension = "pcap";
+                    cmd.filenames.push(format!(
+                        "netsim-{:?}-{}-{}-{}.{}",
+                        capture.id,
+                        capture.device_name.to_owned().replace(' ', "_"),
+                        Self::chip_kind_to_string(capture.chip_kind.enum_value_or_default()),
+                        time_display.utc_display(),
+                        file_extension
+                    ));
+                }
+                reqs
+            }
+            _ => {
+                unimplemented!(
+                    "get_requests not implemented for this command. Use get_request instead."
+                )
+            }
+        }
+    }
+
+    fn get_filtered_captures(
+        client: &FrontendServiceClient,
+        patterns: &[String],
+    ) -> Vec<model::Capture> {
+        // Get list of captures, with explicit type annotation for send_grpc
+        let mut result = match grpc_client::send_grpc(client, &GrpcRequest::ListCapture) {
+            Ok(GrpcResponse::ListCapture(response)) => response.captures,
+            Ok(grpc_response) => {
+                error!("Unexpected GrpcResponse: {:?}", grpc_response);
+                return Vec::new();
+            }
+            Err(err) => {
+                error!("ListCapture Grpc call error: {}", err);
+                return Vec::new();
             }
+        };
+
+        // Filter captures if patterns are provided
+        if !patterns.is_empty() {
+            Self::filter_captures(&mut result, patterns);
         }
+
+        result
     }
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
-    use args::{BinaryProtobuf, NetsimArgs};
+    use crate::args::{
+        AdvertiseMode, BeaconBleAdvertiseData, BeaconBleScanResponseData, BeaconBleSettings,
+        BeaconCreateBle, BeaconPatchBle, Command, Devices, Interval, ListCapture, Move, NetsimArgs,
+        ParsableBytes, Radio, RadioType, TxPower, TxPowerLevel,
+    };
+
     use clap::Parser;
     use netsim_proto::frontend::{
         patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto, CreateDeviceRequest,
@@ -82,26 +291,26 @@ mod tests {
             Position,
         },
     };
-    use protobuf::Message;
     use protobuf::MessageField;
 
-    fn test_command(
-        command: &str,
-        expected_grpc_method: GrpcMethod,
-        expected_request_byte_str: BinaryProtobuf,
-    ) {
+    // Helper to test parsing text command into expected Command and GrpcRequest
+    fn test_command(command: &str, expected_command: Command, expected_grpc_request: GrpcRequest) {
         let command = NetsimArgs::parse_from(command.split_whitespace()).command;
-        assert_eq!(expected_grpc_method, command.grpc_method());
-        let request = command.get_request_bytes();
-        assert_eq!(request, expected_request_byte_str);
+        assert_eq!(command, expected_command);
+        let request = command.get_request();
+        assert_eq!(request, expected_grpc_request);
     }
 
     #[test]
     fn test_version_request() {
-        test_command("netsim-cli version", GrpcMethod::GetVersion, Vec::new())
+        test_command("netsim-cli version", Command::Version, GrpcRequest::GetVersion)
     }
 
-    fn get_expected_radio(name: &str, radio_type: &str, state: &str) -> BinaryProtobuf {
+    fn get_expected_radio(
+        name: &str,
+        radio_type: &str,
+        state: &str,
+    ) -> frontend::PatchDeviceRequest {
         let mut chip = model::Chip { ..Default::default() };
         let chip_state = state == "up";
         if radio_type == "wifi" {
@@ -131,20 +340,28 @@ mod tests {
         device.name = Some(name.to_string());
         device.chips.push(chip);
         result.device = Some(device).into();
-        result.write_to_bytes().unwrap()
+        result
     }
 
     #[test]
     fn test_radio_ble() {
         test_command(
             "netsim-cli radio ble down 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Down,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "down")),
         );
         test_command(
             "netsim-cli radio ble up 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Up,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "up")),
         );
     }
 
@@ -152,23 +369,39 @@ mod tests {
     fn test_radio_ble_aliases() {
         test_command(
             "netsim-cli radio ble Down 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Down,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "down")),
         );
         test_command(
             "netsim-cli radio ble Up 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Up,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "up")),
         );
         test_command(
             "netsim-cli radio ble DOWN 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Down,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "down")),
         );
         test_command(
             "netsim-cli radio ble UP 1000",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("1000", "ble", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Ble,
+                status: UpDownStatus::Up,
+                name: "1000".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("1000", "ble", "up")),
         );
     }
 
@@ -176,13 +409,21 @@ mod tests {
     fn test_radio_classic() {
         test_command(
             "netsim-cli radio classic down 100",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("100", "classic", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Classic,
+                status: UpDownStatus::Down,
+                name: "100".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("100", "classic", "down")),
         );
         test_command(
             "netsim-cli radio classic up 100",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("100", "classic", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Classic,
+                status: UpDownStatus::Up,
+                name: "100".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("100", "classic", "up")),
         );
     }
 
@@ -190,13 +431,21 @@ mod tests {
     fn test_radio_wifi() {
         test_command(
             "netsim-cli radio wifi down a",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("a", "wifi", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Wifi,
+                status: UpDownStatus::Down,
+                name: "a".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("a", "wifi", "down")),
         );
         test_command(
             "netsim-cli radio wifi up b",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("b", "wifi", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Wifi,
+                status: UpDownStatus::Up,
+                name: "b".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("b", "wifi", "up")),
         );
     }
 
@@ -204,32 +453,45 @@ mod tests {
     fn test_radio_uwb() {
         test_command(
             "netsim-cli radio uwb down a",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("a", "uwb", "down"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Uwb,
+                status: UpDownStatus::Down,
+                name: "a".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("a", "uwb", "down")),
         );
         test_command(
             "netsim-cli radio uwb up b",
-            GrpcMethod::PatchDevice,
-            get_expected_radio("b", "uwb", "up"),
+            Command::Radio(Radio {
+                radio_type: RadioType::Uwb,
+                status: UpDownStatus::Up,
+                name: "b".to_string(),
+            }),
+            GrpcRequest::PatchDevice(get_expected_radio("b", "uwb", "up")),
         );
     }
 
-    fn get_expected_move(name: &str, x: f32, y: f32, z: Option<f32>) -> BinaryProtobuf {
+    fn get_expected_move(
+        name: &str,
+        x: f32,
+        y: f32,
+        z: Option<f32>,
+    ) -> frontend::PatchDeviceRequest {
         let mut result = frontend::PatchDeviceRequest::new();
         let mut device = PatchDeviceFieldsProto::new();
         let position = Position { x, y, z: z.unwrap_or_default(), ..Default::default() };
         device.name = Some(name.to_string());
         device.position = Some(position).into();
         result.device = Some(device).into();
-        result.write_to_bytes().unwrap()
+        result
     }
 
     #[test]
     fn test_move_int() {
         test_command(
             "netsim-cli move 1 1 2 3",
-            GrpcMethod::PatchDevice,
-            get_expected_move("1", 1.0, 2.0, Some(3.0)),
+            Command::Move(Move { name: "1".to_string(), x: 1.0, y: 2.0, z: Some(3.0) }),
+            GrpcRequest::PatchDevice(get_expected_move("1", 1.0, 2.0, Some(3.0))),
         )
     }
 
@@ -237,8 +499,8 @@ mod tests {
     fn test_move_float() {
         test_command(
             "netsim-cli move 1000 1.2 3.4 5.6",
-            GrpcMethod::PatchDevice,
-            get_expected_move("1000", 1.2, 3.4, Some(5.6)),
+            Command::Move(Move { name: "1000".to_string(), x: 1.2, y: 3.4, z: Some(5.6) }),
+            GrpcRequest::PatchDevice(get_expected_move("1000", 1.2, 3.4, Some(5.6))),
         )
     }
 
@@ -246,8 +508,8 @@ mod tests {
     fn test_move_mixed() {
         test_command(
             "netsim-cli move 1000 1.1 2 3.4",
-            GrpcMethod::PatchDevice,
-            get_expected_move("1000", 1.1, 2.0, Some(3.4)),
+            Command::Move(Move { name: "1000".to_string(), x: 1.1, y: 2.0, z: Some(3.4) }),
+            GrpcRequest::PatchDevice(get_expected_move("1000", 1.1, 2.0, Some(3.4))),
         )
     }
 
@@ -255,40 +517,52 @@ mod tests {
     fn test_move_no_z() {
         test_command(
             "netsim-cli move 1000 1.2 3.4",
-            GrpcMethod::PatchDevice,
-            get_expected_move("1000", 1.2, 3.4, None),
+            Command::Move(Move { name: "1000".to_string(), x: 1.2, y: 3.4, z: None }),
+            GrpcRequest::PatchDevice(get_expected_move("1000", 1.2, 3.4, None)),
         )
     }
 
     #[test]
     fn test_devices() {
-        test_command("netsim-cli devices", GrpcMethod::ListDevice, Vec::new())
+        test_command(
+            "netsim-cli devices",
+            Command::Devices(Devices { continuous: false }),
+            GrpcRequest::ListDevice,
+        )
     }
 
     #[test]
     fn test_reset() {
-        test_command("netsim-cli reset", GrpcMethod::Reset, Vec::new())
+        test_command("netsim-cli reset", Command::Reset, GrpcRequest::Reset)
     }
 
     #[test]
     fn test_capture_list() {
-        test_command("netsim-cli capture list", GrpcMethod::ListCapture, Vec::new())
+        test_command(
+            "netsim-cli capture list",
+            Command::Capture(Capture::List(ListCapture { ..Default::default() })),
+            GrpcRequest::ListCapture,
+        )
     }
 
     #[test]
     fn test_capture_list_alias() {
-        test_command("netsim-cli pcap list", GrpcMethod::ListCapture, Vec::new())
+        test_command(
+            "netsim-cli pcap list",
+            Command::Capture(Capture::List(ListCapture { ..Default::default() })),
+            GrpcRequest::ListCapture,
+        )
     }
 
-    //TODO: Add capture patch and get tests once able to run tests with cxx definitions
+    //TODO: Add capture patch and get tests
 
-    fn get_create_device_req_bytes(
+    fn get_create_device_req(
         device_name: &str,
         chip_name: &str,
         settings: AdvertiseSettingsProto,
         adv_data: AdvertiseDataProto,
         scan_response: AdvertiseDataProto,
-    ) -> Vec<u8> {
+    ) -> CreateDeviceRequest {
         let device = MessageField::some(DeviceCreateProto {
             name: String::from(device_name),
             chips: vec![ChipCreateProto {
@@ -305,16 +579,16 @@ mod tests {
             ..Default::default()
         });
 
-        CreateDeviceRequest { device, ..Default::default() }.write_to_bytes().unwrap()
+        CreateDeviceRequest { device, ..Default::default() }
     }
 
-    fn get_patch_device_req_bytes(
+    fn get_patch_device_req(
         device_name: &str,
         chip_name: &str,
         settings: AdvertiseSettingsProto,
         adv_data: AdvertiseDataProto,
         scan_response: AdvertiseDataProto,
-    ) -> Vec<u8> {
+    ) -> PatchDeviceRequest {
         let device = MessageField::some(PatchDeviceFieldsProto {
             name: Some(String::from(device_name)),
             chips: vec![ChipProto {
@@ -332,7 +606,7 @@ mod tests {
             ..Default::default()
         });
 
-        PatchDeviceRequest { device, ..Default::default() }.write_to_bytes().unwrap()
+        PatchDeviceRequest { device, ..Default::default() }
     }
 
     #[test]
@@ -354,17 +628,30 @@ mod tests {
         let adv_data = AdvertiseDataProto {
             include_device_name: true,
             include_tx_power_level: true,
-            manufacturer_data,
+            manufacturer_data: manufacturer_data.clone(),
             ..Default::default()
         };
 
-        let request = get_create_device_req_bytes(
-            &device_name,
-            &chip_name,
-            settings,
-            adv_data,
-            Default::default(),
-        );
+        let request =
+            get_create_device_req(&device_name, &chip_name, settings, adv_data, Default::default());
+
+        let command = Command::Beacon(Beacon::Create(BeaconCreate::Ble(BeaconCreateBle {
+            device_name: Some(device_name.clone()),
+            chip_name: Some(chip_name.clone()),
+            address: None,
+            settings: BeaconBleSettings {
+                advertise_mode: Some(Interval::Mode(AdvertiseMode::Balanced)),
+                tx_power_level: Some(TxPower::Level(TxPowerLevel::UltraLow)),
+                scannable: true,
+                timeout: Some(1234),
+            },
+            advertise_data: BeaconBleAdvertiseData {
+                include_device_name: true,
+                include_tx_power_level: true,
+                manufacturer_data: Some(ParsableBytes(manufacturer_data.clone())),
+            },
+            scan_response_data: BeaconBleScanResponseData { ..Default::default() },
+        })));
 
         test_command(
             format!(
@@ -372,8 +659,8 @@ mod tests {
                 device_name, chip_name, timeout,
             )
             .as_str(),
-            GrpcMethod::CreateDevice,
-            request,
+            command,
+            GrpcRequest::CreateDevice(request),
         )
     }
 
@@ -397,17 +684,30 @@ mod tests {
         let adv_data = AdvertiseDataProto {
             include_device_name: true,
             include_tx_power_level: true,
-            manufacturer_data,
+            manufacturer_data: manufacturer_data.clone(),
             ..Default::default()
         };
 
-        let request = get_patch_device_req_bytes(
-            &device_name,
-            &chip_name,
-            settings,
-            adv_data,
-            Default::default(),
-        );
+        let request =
+            get_patch_device_req(&device_name, &chip_name, settings, adv_data, Default::default());
+
+        let command = Command::Beacon(Beacon::Patch(BeaconPatch::Ble(BeaconPatchBle {
+            device_name: device_name.clone(),
+            chip_name: chip_name.clone(),
+            address: None,
+            settings: BeaconBleSettings {
+                advertise_mode: Some(Interval::Milliseconds(interval)),
+                tx_power_level: Some(TxPower::Dbm(tx_power_level as i8)),
+                scannable: true,
+                timeout: Some(timeout),
+            },
+            advertise_data: BeaconBleAdvertiseData {
+                include_device_name: true,
+                include_tx_power_level: true,
+                manufacturer_data: Some(ParsableBytes(manufacturer_data)),
+            },
+            scan_response_data: BeaconBleScanResponseData { ..Default::default() },
+        })));
 
         test_command(
             format!(
@@ -415,8 +715,8 @@ mod tests {
                 device_name, chip_name, interval, timeout, tx_power_level
             )
             .as_str(),
-            GrpcMethod::PatchDevice,
-            request,
+            command,
+            GrpcRequest::PatchDevice(request),
         )
     }
 
@@ -424,15 +724,16 @@ mod tests {
     fn test_beacon_create_scan_response() {
         let device_name = String::from("device");
         let chip_name = String::from("chip");
+        let manufacturer_data = vec![0x21, 0xbe, 0xef];
 
         let scan_response = AdvertiseDataProto {
             include_device_name: true,
             include_tx_power_level: true,
-            manufacturer_data: vec![0x21, 0xbe, 0xef],
+            manufacturer_data: manufacturer_data.clone(),
             ..Default::default()
         };
 
-        let request = get_create_device_req_bytes(
+        let request = get_create_device_req(
             &device_name,
             &chip_name,
             Default::default(),
@@ -440,14 +741,25 @@ mod tests {
             scan_response,
         );
 
+        let command = Command::Beacon(Beacon::Create(BeaconCreate::Ble(BeaconCreateBle {
+            device_name: Some(device_name.clone()),
+            chip_name: Some(chip_name.clone()),
+            scan_response_data: BeaconBleScanResponseData {
+                scan_response_include_device_name: true,
+                scan_response_include_tx_power_level: true,
+                scan_response_manufacturer_data: Some(ParsableBytes(manufacturer_data)),
+            },
+            ..Default::default()
+        })));
+
         test_command(
             format!(
                 "netsim-cli beacon create ble {} {} --scan-response-include-device-name --scan-response-include-tx-power-level --scan-response-manufacturer-data 0x21beef",
                 device_name, chip_name
             )
             .as_str(),
-            GrpcMethod::CreateDevice,
-            request,
+            command,
+            GrpcRequest::CreateDevice(request),
         );
     }
 
@@ -455,15 +767,16 @@ mod tests {
     fn test_beacon_patch_scan_response() {
         let device_name = String::from("device");
         let chip_name = String::from("chip");
+        let manufacturer_data = vec![0x59, 0xbe, 0xac, 0x09];
 
         let scan_response = AdvertiseDataProto {
             include_device_name: true,
             include_tx_power_level: true,
-            manufacturer_data: vec![0x59, 0xbe, 0xac, 0x09],
+            manufacturer_data: manufacturer_data.clone(),
             ..Default::default()
         };
 
-        let request = get_patch_device_req_bytes(
+        let request = get_patch_device_req(
             &device_name,
             &chip_name,
             Default::default(),
@@ -471,14 +784,27 @@ mod tests {
             scan_response,
         );
 
+        let command = Command::Beacon(Beacon::Patch(BeaconPatch::Ble(BeaconPatchBle {
+            device_name: device_name.clone(),
+            chip_name: chip_name.clone(),
+            address: None,
+            settings: BeaconBleSettings { ..Default::default() },
+            advertise_data: BeaconBleAdvertiseData { ..Default::default() },
+            scan_response_data: BeaconBleScanResponseData {
+                scan_response_include_device_name: true,
+                scan_response_include_tx_power_level: true,
+                scan_response_manufacturer_data: Some(ParsableBytes(manufacturer_data)),
+            },
+        })));
+
         test_command(
             format!(
                 "netsim-cli beacon patch ble {} {} --scan-response-include-device-name --scan-response-include-tx-power-level --scan-response-manufacturer-data 59beac09",
                 device_name, chip_name
             )
             .as_str(),
-            GrpcMethod::PatchDevice,
-            request,
+            command,
+            GrpcRequest::PatchDevice(request),
         );
     }
 
@@ -493,13 +819,23 @@ mod tests {
         };
         let adv_data = AdvertiseDataProto { include_tx_power_level: true, ..Default::default() };
 
-        let request = get_create_device_req_bytes(
-            &device_name,
-            &chip_name,
-            settings,
-            adv_data,
-            Default::default(),
-        );
+        let request =
+            get_create_device_req(&device_name, &chip_name, settings, adv_data, Default::default());
+
+        let command = Command::Beacon(Beacon::Create(BeaconCreate::Ble(BeaconCreateBle {
+            device_name: Some(device_name.clone()),
+            chip_name: Some(chip_name.clone()),
+            address: None,
+            settings: BeaconBleSettings {
+                tx_power_level: Some(TxPower::Level(TxPowerLevel::High)),
+                ..Default::default()
+            },
+            advertise_data: BeaconBleAdvertiseData {
+                include_tx_power_level: true,
+                ..Default::default()
+            },
+            scan_response_data: BeaconBleScanResponseData { ..Default::default() },
+        })));
 
         test_command(
             format!(
@@ -507,14 +843,14 @@ mod tests {
                 device_name, chip_name
             )
             .as_str(),
-            GrpcMethod::CreateDevice,
-            request,
+            command,
+            GrpcRequest::CreateDevice(request),
         )
     }
 
     #[test]
     fn test_beacon_create_default() {
-        let request = get_create_device_req_bytes(
+        let request = get_create_device_req(
             Default::default(),
             Default::default(),
             Default::default(),
@@ -522,7 +858,11 @@ mod tests {
             Default::default(),
         );
 
-        test_command("netsim-cli beacon create ble", GrpcMethod::CreateDevice, request)
+        let command = Command::Beacon(Beacon::Create(BeaconCreate::Ble(BeaconCreateBle {
+            ..Default::default()
+        })));
+
+        test_command("netsim-cli beacon create ble", command, GrpcRequest::CreateDevice(request))
     }
 
     #[test]
@@ -535,13 +875,23 @@ mod tests {
             ..Default::default()
         };
 
-        let request = get_patch_device_req_bytes(
+        let request = get_patch_device_req(
             &device_name,
             &chip_name,
             settings,
             Default::default(),
             Default::default(),
         );
+        let command = Command::Beacon(Beacon::Patch(BeaconPatch::Ble(BeaconPatchBle {
+            device_name: device_name.clone(),
+            chip_name: chip_name.clone(),
+            address: None,
+            settings: BeaconBleSettings {
+                advertise_mode: Some(Interval::Mode(AdvertiseMode::LowLatency)),
+                ..Default::default()
+            },
+            ..Default::default()
+        })));
 
         test_command(
             format!(
@@ -549,8 +899,8 @@ mod tests {
                 device_name, chip_name
             )
             .as_str(),
-            GrpcMethod::PatchDevice,
-            request,
+            command,
+            GrpcRequest::PatchDevice(request),
         )
     }
 
@@ -573,14 +923,16 @@ mod tests {
             ..Default::default()
         });
 
-        let request = frontend::CreateDeviceRequest { device, ..Default::default() }
-            .write_to_bytes()
-            .unwrap();
+        let request = frontend::CreateDeviceRequest { device, ..Default::default() };
+        let command = Command::Beacon(Beacon::Create(BeaconCreate::Ble(BeaconCreateBle {
+            address: Some(address.clone()),
+            ..Default::default()
+        })));
 
         test_command(
             format!("netsim-cli beacon create ble --address {}", address).as_str(),
-            GrpcMethod::CreateDevice,
-            request,
+            command,
+            GrpcRequest::CreateDevice(request),
         )
     }
 
@@ -608,8 +960,14 @@ mod tests {
             ..Default::default()
         });
 
-        let request =
-            frontend::PatchDeviceRequest { device, ..Default::default() }.write_to_bytes().unwrap();
+        let request = frontend::PatchDeviceRequest { device, ..Default::default() };
+
+        let command = Command::Beacon(Beacon::Patch(BeaconPatch::Ble(BeaconPatchBle {
+            device_name: device_name.clone(),
+            chip_name: chip_name.clone(),
+            address: Some(address.clone()),
+            ..Default::default()
+        })));
 
         test_command(
             format!(
@@ -617,8 +975,8 @@ mod tests {
                 device_name, chip_name, address
             )
             .as_str(),
-            GrpcMethod::PatchDevice,
-            request,
+            command,
+            GrpcRequest::PatchDevice(request),
         )
     }
 
diff --git a/rust/cli/src/response.rs b/rust/cli/src/response.rs
index 92a6580a..09c0511f 100644
--- a/rust/cli/src/response.rs
+++ b/rust/cli/src/response.rs
@@ -16,20 +16,19 @@ use std::cmp::max;
 
 use crate::args::{self, Beacon, BeaconCreate, BeaconPatch, Capture, Command, OnOffState};
 use crate::display::Displayer;
+use crate::grpc_client::GrpcResponse;
 use netsim_common::util::time_display::TimeDisplay;
-use netsim_proto::{
-    common::ChipKind,
-    frontend::{CreateDeviceResponse, ListCaptureResponse, ListDeviceResponse, VersionResponse},
-    model,
-};
-use protobuf::Message;
+use netsim_proto::{common::ChipKind, frontend, model};
 
 impl args::Command {
     /// Format and print the response received from the frontend server for the command
-    pub fn print_response(&self, response: &[u8], verbose: bool) {
+    pub fn print_response(&self, response: &GrpcResponse, verbose: bool) {
         match self {
             Command::Version => {
-                Self::print_version_response(VersionResponse::parse_from_bytes(response).unwrap());
+                let GrpcResponse::GetVersion(res) = response else {
+                    panic!("Expected to print VersionResponse. Got: {:?}", response);
+                };
+                Self::print_version_response(res);
             }
             Command::Radio(cmd) => {
                 if verbose {
@@ -53,24 +52,26 @@ impl args::Command {
                 }
             }
             Command::Devices(_) => {
-                println!(
-                    "{}",
-                    Displayer::new(
-                        ListDeviceResponse::parse_from_bytes(response).unwrap(),
-                        verbose
-                    )
-                );
+                let GrpcResponse::ListDevice(res) = response else {
+                    panic!("Expected to print ListDeviceResponse. Got: {:?}", response);
+                };
+                println!("{}", Displayer::new(res.clone(), verbose));
             }
             Command::Reset => {
                 if verbose {
                     println!("All devices have been reset.");
                 }
             }
-            Command::Capture(Capture::List(cmd)) => Self::print_list_capture_response(
-                ListCaptureResponse::parse_from_bytes(response).unwrap(),
-                verbose,
-                cmd.patterns.to_owned(),
-            ),
+            Command::Capture(Capture::List(cmd)) => {
+                let GrpcResponse::ListCapture(res) = response else {
+                    panic!("Expected to print ListCaptureResponse. Got: {:?}", response);
+                };
+                Self::print_list_capture_response(
+                    &mut res.clone(),
+                    verbose,
+                    cmd.patterns.to_owned(),
+                )
+            }
             Command::Capture(Capture::Patch(cmd)) => {
                 if verbose {
                     println!(
@@ -96,10 +97,10 @@ impl args::Command {
                         if !verbose {
                             return;
                         }
-                        let device = CreateDeviceResponse::parse_from_bytes(response)
-                            .expect("could not read device from response")
-                            .device;
-
+                        let GrpcResponse::CreateDevice(res) = response else {
+                            panic!("Expected to print CreateDeviceResponse. Got: {:?}", response);
+                        };
+                        let device = &res.device;
                         if device.chips.len() == 1 {
                             println!(
                                 "Created device '{}' with ble beacon chip '{}'",
@@ -189,13 +190,13 @@ impl args::Command {
     }
 
     /// Helper function to format and print VersionResponse
-    fn print_version_response(response: VersionResponse) {
+    fn print_version_response(response: &frontend::VersionResponse) {
         println!("Netsim version: {}", response.version);
     }
 
     /// Helper function to format and print ListCaptureResponse
     fn print_list_capture_response(
-        mut response: ListCaptureResponse,
+        response: &mut frontend::ListCaptureResponse,
         verbose: bool,
         patterns: Vec<String>,
     ) {
diff --git a/rust/common/Cargo.toml b/rust/common/Cargo.toml
index 4f8a5f9a..c9904a1c 100644
--- a/rust/common/Cargo.toml
+++ b/rust/common/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-common"
-version = "0.3.37"
+version = "0.3.50"
 edition = "2021"
 
 [lib]
diff --git a/rust/common/src/lib.rs b/rust/common/src/lib.rs
index 504d177e..fc65b2e5 100644
--- a/rust/common/src/lib.rs
+++ b/rust/common/src/lib.rs
@@ -19,3 +19,10 @@
 
 pub mod system;
 pub mod util;
+
+#[cfg(test)]
+mod tests {
+    use std::sync::Mutex;
+    // Shared mutex to ensure environment is not modified by multiple tests simultaneously
+    pub static ENV_MUTEX: Mutex<()> = Mutex::new(());
+}
diff --git a/rust/common/src/system/mod.rs b/rust/common/src/system/mod.rs
index adfadb8d..d499e470 100644
--- a/rust/common/src/system/mod.rs
+++ b/rust/common/src/system/mod.rs
@@ -58,12 +58,10 @@ fn netsimd_temp_dir_pathbuf() -> PathBuf {
 
 #[cfg(not(target_os = "windows"))]
 #[cfg(test)]
-pub mod tests {
+mod tests {
     use super::netsimd_temp_dir_pathbuf;
+    use crate::tests::ENV_MUTEX;
     use std::env;
-    use std::sync::Mutex;
-
-    pub static ENV_MUTEX: Mutex<()> = Mutex::new(());
 
     #[test]
     fn test_forge() {
diff --git a/rust/common/src/util/ini_file.rs b/rust/common/src/util/ini_file.rs
index 2ec132ab..5ecb84be 100644
--- a/rust/common/src/util/ini_file.rs
+++ b/rust/common/src/util/ini_file.rs
@@ -22,9 +22,13 @@ use std::io::prelude::*;
 use std::io::BufReader;
 use std::path::PathBuf;
 
+use log::error;
+
+use super::os_utils::get_discovery_directory;
+
 /// A simple class to process init file. Based on
 /// external/qemu/android/android-emu-base/android/base/files/IniFile.h
-pub struct IniFile {
+struct IniFile {
     /// The data stored in the ini file.
     data: HashMap<String, String>,
     /// The path to the ini file.
@@ -37,7 +41,7 @@ impl IniFile {
     /// # Arguments
     ///
     /// * `filepath` - The path to the ini file.
-    pub fn new(filepath: PathBuf) -> IniFile {
+    fn new(filepath: PathBuf) -> IniFile {
         IniFile { data: HashMap::new(), filepath }
     }
 
@@ -47,7 +51,7 @@ impl IniFile {
     /// # Returns
     ///
     /// `Ok` if the write was successful, `Error` otherwise.
-    pub fn read(&mut self) -> Result<(), Box<dyn Error>> {
+    fn read(&mut self) -> Result<(), Box<dyn Error>> {
         self.data.clear();
 
         let mut f = File::open(self.filepath.clone())?;
@@ -72,8 +76,8 @@ impl IniFile {
     /// # Returns
     ///
     /// `Ok` if the write was successful, `Error` otherwise.
-    pub fn write(&self) -> Result<(), Box<dyn Error>> {
-        let mut f = File::create(self.filepath.clone())?;
+    fn write(&self) -> std::io::Result<()> {
+        let mut f = create_new(self.filepath.clone())?;
         for (key, value) in &self.data {
             writeln!(&mut f, "{}={}", key, value)?;
         }
@@ -81,19 +85,6 @@ impl IniFile {
         Ok(())
     }
 
-    /// Checks if a certain key exists in the file.
-    ///
-    /// # Arguments
-    ///
-    /// * `key` - The key to check.
-    ///
-    /// # Returns
-    ///
-    /// `true` if the key exists, `false` otherwise.
-    pub fn contains_key(&self, key: &str) -> bool {
-        self.data.contains_key(key)
-    }
-
     /// Gets value.
     ///
     /// # Arguments
@@ -103,7 +94,7 @@ impl IniFile {
     /// # Returns
     ///
     /// An `Option` containing the value if it exists, `None` otherwise.
-    pub fn get(&self, key: &str) -> Option<&str> {
+    fn get(&self, key: &str) -> Option<&str> {
         self.data.get(key).map(|v| v.as_str())
     }
 
@@ -113,11 +104,73 @@ impl IniFile {
     ///
     /// * `key` - The key to set the value for.
     /// * `value` - The value to set.
-    pub fn insert(&mut self, key: &str, value: &str) {
+    fn insert(&mut self, key: &str, value: &str) {
         self.data.insert(key.to_owned(), value.to_owned());
     }
 }
 
+// TODO: Replace with std::fs::File::create_new once Rust toolchain is upgraded to 1.77
+/// Create new file, errors if it already exists.
+fn create_new<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<File> {
+    std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(path.as_ref())
+}
+
+/// Write ports to ini file
+pub fn create_ini(instance_num: u16, grpc_port: u32, web_port: Option<u16>) -> std::io::Result<()> {
+    // Instantiate IniFile
+    let filepath = get_ini_filepath(instance_num);
+    let mut ini_file = IniFile::new(filepath);
+
+    // Write ports to ini file
+    if let Some(num) = web_port {
+        ini_file.insert("web.port", &num.to_string());
+    }
+    ini_file.insert("grpc.port", &grpc_port.to_string());
+    ini_file.write()
+}
+
+/// Remove netsim ini file
+pub fn remove_ini(instance_num: u16) -> std::io::Result<()> {
+    let filepath = get_ini_filepath(instance_num);
+    std::fs::remove_file(filepath)
+}
+
+/// Get the filepath of netsim.ini under discovery directory
+fn get_ini_filepath(instance_num: u16) -> PathBuf {
+    let mut discovery_dir = get_discovery_directory();
+    let filename = if instance_num == 1 {
+        "netsim.ini".to_string()
+    } else {
+        format!("netsim_{instance_num}.ini")
+    };
+    discovery_dir.push(filename);
+    discovery_dir
+}
+
+/// Get the grpc server address for netsim
+pub fn get_server_address(instance_num: u16) -> Option<String> {
+    let filepath = get_ini_filepath(instance_num);
+    if !filepath.exists() {
+        error!("Unable to find netsim ini file: {filepath:?}");
+        return None;
+    }
+    if !filepath.is_file() {
+        error!("Not a file: {filepath:?}");
+        return None;
+    }
+    let mut ini_file = IniFile::new(filepath);
+    if let Err(err) = ini_file.read() {
+        error!("Error reading ini file: {err:?}");
+    }
+    ini_file.get("grpc.port").map(|s: &str| {
+        if s.contains(':') {
+            s.to_string()
+        } else {
+            format!("localhost:{}", s)
+        }
+    })
+}
+
 #[cfg(test)]
 mod tests {
     use rand::{distributions::Alphanumeric, Rng};
@@ -126,8 +179,26 @@ mod tests {
     use std::io::{Read, Write};
     use std::path::PathBuf;
 
+    use super::get_ini_filepath;
     use super::IniFile;
 
+    use crate::tests::ENV_MUTEX;
+
+    impl IniFile {
+        /// Checks if a certain key exists in the file.
+        ///
+        /// # Arguments
+        ///
+        /// * `key` - The key to check.
+        ///
+        /// # Returns
+        ///
+        /// `true` if the key exists, `false` otherwise.
+        fn contains_key(&self, key: &str) -> bool {
+            self.data.contains_key(key)
+        }
+    }
+
     fn get_temp_ini_filepath(prefix: &str) -> PathBuf {
         env::temp_dir().join(format!(
             "{prefix}_{}.ini",
@@ -315,24 +386,14 @@ mod tests {
     }
 
     #[test]
-    fn test_overwrite() {
-        let filepath = get_temp_ini_filepath("test_overwrite");
-        {
-            let mut tmpfile = match File::create(&filepath) {
-                Ok(f) => f,
-                Err(_) => return,
-            };
-            write!(tmpfile, "port=123\nport2=456\n").unwrap();
-        }
+    fn test_get_ini_filepath() {
+        let _locked = ENV_MUTEX.lock();
 
-        let mut inifile = IniFile::new(filepath.clone());
-        inifile.insert("port3", "789");
-
-        inifile.write().unwrap();
-        let mut file = File::open(&filepath).unwrap();
-        let mut contents = String::new();
-        file.read_to_string(&mut contents).unwrap();
+        // Test with TMPDIR variable
+        std::env::set_var("TMPDIR", "/tmpdir");
 
-        assert_eq!(contents, "port3=789\n");
+        // Test get_netsim_ini_filepath
+        assert_eq!(get_ini_filepath(1), PathBuf::from("/tmpdir/netsim.ini"));
+        assert_eq!(get_ini_filepath(2), PathBuf::from("/tmpdir/netsim_2.ini"));
     }
 }
diff --git a/rust/common/src/util/netsim_logger.rs b/rust/common/src/util/netsim_logger.rs
index 2d15fb0f..df354ae2 100644
--- a/rust/common/src/util/netsim_logger.rs
+++ b/rust/common/src/util/netsim_logger.rs
@@ -77,7 +77,7 @@ fn format_file<'a>(record: &'a Record<'a>) -> &'a str {
                 return file.file_name().unwrap_or(OsStr::new("N/A")).to_str().unwrap();
             }
             // Print full path for all dependent crates
-            return file.to_str().unwrap();
+            file.to_str().unwrap()
         }
         None => "N/A",
     }
diff --git a/rust/common/src/util/os_utils.rs b/rust/common/src/util/os_utils.rs
index 7e1f7028..fe216905 100644
--- a/rust/common/src/util/os_utils.rs
+++ b/rust/common/src/util/os_utils.rs
@@ -21,14 +21,12 @@ use std::os::fd::AsRawFd;
 #[cfg(target_os = "windows")]
 use std::os::windows::io::AsRawHandle;
 
-use std::{fs::remove_file, path::PathBuf};
+use std::path::PathBuf;
 
-use log::{error, info, warn};
+use log::warn;
 
 use crate::system::netsimd_temp_dir;
 
-use super::ini_file::IniFile;
-
 const DEFAULT_HCI_PORT: u32 = 6402;
 
 struct DiscoveryDir {
@@ -63,50 +61,6 @@ pub fn get_discovery_directory() -> PathBuf {
     path
 }
 
-/// Get the filepath of netsim.ini under discovery directory
-pub fn get_netsim_ini_filepath(instance_num: u16) -> PathBuf {
-    let mut discovery_dir = get_discovery_directory();
-    let filename = if instance_num == 1 {
-        "netsim.ini".to_string()
-    } else {
-        format!("netsim_{instance_num}.ini")
-    };
-    discovery_dir.push(filename);
-    discovery_dir
-}
-
-/// Remove the ini file
-pub fn remove_netsim_ini(instance_num: u16) {
-    match remove_file(get_netsim_ini_filepath(instance_num)) {
-        Ok(_) => info!("Removed netsim ini file"),
-        Err(e) => error!("Failed to remove netsim ini file: {e:?}"),
-    }
-}
-
-/// Get the grpc server address for netsim
-pub fn get_server_address(instance_num: u16) -> Option<String> {
-    let filepath = get_netsim_ini_filepath(instance_num);
-    if !filepath.exists() {
-        error!("Unable to find netsim ini file: {filepath:?}");
-        return None;
-    }
-    if !filepath.is_file() {
-        error!("Not a file: {filepath:?}");
-        return None;
-    }
-    let mut ini_file = IniFile::new(filepath);
-    if let Err(err) = ini_file.read() {
-        error!("Error reading ini file: {err:?}");
-    }
-    ini_file.get("grpc.port").map(|s| {
-        if s.contains(':') {
-            s.to_string()
-        } else {
-            format!("localhost:{}", s)
-        }
-    })
-}
-
 const DEFAULT_INSTANCE: u16 = 1;
 
 /// Get the netsim instance number which is always > 0
@@ -209,15 +163,12 @@ pub fn redirect_std_stream(instance_name: &str) -> anyhow::Result<()> {
 }
 
 #[cfg(test)]
-mod tests {
-
+pub mod tests {
     use super::*;
-    #[cfg(not(target_os = "windows"))]
-    use crate::system::tests::ENV_MUTEX;
+    use crate::tests::ENV_MUTEX;
 
     #[test]
     fn test_get_discovery_directory() {
-        #[cfg(not(target_os = "windows"))]
         let _locked = ENV_MUTEX.lock();
         // Remove all environment variable
         std::env::remove_var(DISCOVERY.root_env);
@@ -239,10 +190,6 @@ mod tests {
         // Test with TMPDIR variable
         std::env::set_var("TMPDIR", "/tmpdir");
         assert_eq!(get_discovery_directory(), PathBuf::from("/tmpdir"));
-
-        // Test get_netsim_ini_filepath
-        assert_eq!(get_netsim_ini_filepath(1), PathBuf::from("/tmpdir/netsim.ini"));
-        assert_eq!(get_netsim_ini_filepath(2), PathBuf::from("/tmpdir/netsim_2.ini"));
     }
 
     #[test]
diff --git a/rust/daemon/Cargo.toml b/rust/daemon/Cargo.toml
index 9e50a22c..30f705ad 100644
--- a/rust/daemon/Cargo.toml
+++ b/rust/daemon/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-daemon"
-version = "0.3.37"
+version = "0.3.50"
 edition = "2021"
 build = "build.rs"
 
diff --git a/rust/daemon/build.rs b/rust/daemon/build.rs
index 931cb4bd..f7b4c578 100644
--- a/rust/daemon/build.rs
+++ b/rust/daemon/build.rs
@@ -13,7 +13,86 @@
 //  See the License for the specific language governing permissions and
 //  limitations under the License.
 
+//! Build script for linking `netsim-daemon` with dependencies.
+
+use std::env;
+use std::fs;
+use std::path::PathBuf;
+
+/// Adds all archive library dependencies from the specified `objs/archives` directory.
+fn _all_archives_dependencies(objs_path: &str) {
+    let archives_path = format!("{objs_path}/archives");
+    if let Ok(entry_lst) = fs::read_dir(&archives_path) {
+        println!("cargo:rustc-link-search=all={archives_path}");
+        for entry in entry_lst {
+            let entry = entry.unwrap();
+            let path = entry.path();
+            if path.is_file() {
+                if let Some(filename) = path.file_name() {
+                    if let Some(filename_str) = filename.to_str() {
+                        let lib_name = &filename_str[3..filename.len() - 2];
+                        // "rootcanal.configuration.ControllerFeatures" conflicting symbols
+                        if lib_name == "librootcanal_config" {
+                            println!("cargo:warning=skip linking librootcanal_config to avoid conflicting symbols on rootcanal.configuration.ControllerFeatures");
+                            continue;
+                        }
+                        println!("cargo:rustc-link-lib=static={lib_name}");
+                    }
+                }
+            }
+        }
+    }
+}
+/// Configures linking for Linux test builds, including prebuilt PDL files and Rootcanal library.
+fn _run_test_link() {
+    // Linking libraries in objs/archives & objs/lib64
+    let objs_path = std::env::var("OBJS_PATH").unwrap_or("../objs".to_string());
+    println!("cargo:rustc-link-arg=-Wl,--allow-multiple-definition");
+    _all_archives_dependencies(&objs_path);
+    println!("cargo:rustc-link-lib=dylib=abseil_dll");
+
+    // Locate prebuilt pdl generated rust packet definition files
+    let prebuilts: [[&str; 2]; 5] = [
+        ["LINK_LAYER_PACKETS_PREBUILT", "link_layer_packets.rs"],
+        ["MAC80211_HWSIM_PACKETS_PREBUILT", "mac80211_hwsim_packets.rs"],
+        ["IEEE80211_PACKETS_PREBUILT", "ieee80211_packets.rs"],
+        ["LLC_PACKETS_PREBUILT", "llc_packets.rs"],
+        ["NETLINK_PACKETS_PREBUILT", "netlink_packets.rs"],
+    ];
+    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
+    for [var, name] in prebuilts {
+        let env_prebuilt = env::var(var);
+        let out_file = out_dir.join(name);
+        // Check and use prebuilt pdl generated rust file from env var
+        if let Ok(prebuilt_path) = env_prebuilt {
+            println!("cargo:rerun-if-changed={}", prebuilt_path);
+            std::fs::copy(prebuilt_path.as_str(), out_file.as_os_str().to_str().unwrap()).unwrap();
+        // Prebuilt env var not set - check and use pdl generated file that is already present in out_dir
+        } else if out_file.exists() {
+            println!(
+                "cargo:warning=env var {} not set. Using prebuilt found at: {}",
+                var,
+                out_file.display()
+            );
+        } else {
+            panic!("Unable to find env var or prebuilt pdl generated rust file for: {}.", name);
+        };
+    }
+
+    // Linking Rootcanal Rust Library
+    if std::path::Path::new(&format!("{objs_path}/rootcanal/rust")).exists() {
+        println!("cargo:rustc-link-search=all={objs_path}/rootcanal/rust");
+        println!("cargo:rustc-link-lib=static=rootcanal_rs");
+    }
+}
+
+/// Configures C++ FFI bindings and Linux test linking.
 fn main() {
+    // Linking for FFI
     let _build = cxx_build::bridge("src/ffi.rs");
     println!("cargo:rerun-if-changed=src/ffi.rs");
+
+    // TODO(379708365): Link libraries for Mac and Windows for integration test
+    #[cfg(target_os = "linux")]
+    _run_test_link()
 }
diff --git a/rust/daemon/src/args.rs b/rust/daemon/src/args.rs
index d24442f3..c6582b5d 100644
--- a/rust/daemon/src/args.rs
+++ b/rust/daemon/src/args.rs
@@ -86,11 +86,15 @@ pub struct NetsimdArgs {
     #[cfg_attr(not(feature = "cuttlefish"), arg(env = "http_proxy"))]
     pub http_proxy: Option<String>,
 
-    // Use TAP interface instead of libslirp for Wi-Fi
+    /// Use TAP interface instead of libslirp for Wi-Fi
     /// WARNING: This flag is still working in progress.
     #[arg(long)]
     pub wifi_tap: Option<String>,
 
+    /// Customize Wi-Fi with a required SSID and optional password (min 8 characters)
+    #[arg(short, long, num_args = 1..=2, value_names = &["ssid", "password"])]
+    pub wifi: Option<Vec<String>>,
+
     /// Start with test beacons
     #[arg(long, alias = "test_beacons", overrides_with("no_test_beacons"))]
     pub test_beacons: bool,
diff --git a/rust/daemon/src/captures/captures_handler.rs b/rust/daemon/src/captures/captures_handler.rs
index 14b525fa..3c111b16 100644
--- a/rust/daemon/src/captures/captures_handler.rs
+++ b/rust/daemon/src/captures/captures_handler.rs
@@ -20,7 +20,6 @@
 //!
 //! /v1/captures/{id} --> handle_capture_patch, handle_capture_get
 //!
-//! handle_capture_cxx calls handle_capture, which calls handle_capture_* based on uri.
 //! handle_packet_request and handle_packet_response is invoked by packet_hub
 //! to write packets to files if capture state is on.
 
@@ -28,7 +27,7 @@
 // and more descriptive error messages with proper error codes.
 
 use bytes::Bytes;
-use http::{Request, Version};
+use http::Request;
 use log::warn;
 use netsim_common::util::time_display::TimeDisplay;
 use netsim_proto::common::ChipKind;
@@ -36,12 +35,9 @@ use netsim_proto::frontend::ListCaptureResponse;
 use protobuf_json_mapping::{print_to_string_with_options, PrintOptions};
 use std::fs::File;
 use std::io::{Read, Result};
-use std::pin::Pin;
 use std::time::{SystemTime, UNIX_EPOCH};
 
 use crate::devices::chip::ChipIdentifier;
-use crate::ffi::ffi_response_writable::CxxServerResponseWriter;
-use crate::ffi::CxxServerResponseWriterWrapper;
 use crate::http_server::server_response::ResponseWritable;
 use crate::resource::clone_captures;
 use crate::wifi::radiotap;
@@ -210,7 +206,7 @@ fn handle_capture_patch(
     Ok(())
 }
 
-/// The Rust capture handler used directly by Http frontend or handle_capture_cxx for LIST, GET, and PATCH
+/// The Rust capture handler used directly by Http frontend for LIST, GET, and PATCH
 pub fn handle_capture(request: &Request<Vec<u8>>, param: &str, writer: ResponseWritable) {
     if let Err(e) = handle_capture_internal(request, param, writer) {
         writer.put_error(404, &e.to_string());
@@ -252,34 +248,6 @@ fn handle_capture_internal(
     }
 }
 
-/// Capture handler cxx for grpc server to call
-pub fn handle_capture_cxx(
-    responder: Pin<&mut CxxServerResponseWriter>,
-    method: String,
-    param: String,
-    body: String,
-) {
-    let mut builder = Request::builder().method(method.as_str());
-    if param.is_empty() {
-        builder = builder.uri("/v1/captures");
-    } else {
-        builder = builder.uri(format!("/v1/captures/{}", param));
-    }
-    builder = builder.version(Version::HTTP_11);
-    let request = match builder.body(body.as_bytes().to_vec()) {
-        Ok(request) => request,
-        Err(err) => {
-            warn!("{err:?}");
-            return;
-        }
-    };
-    handle_capture(
-        &request,
-        param.as_str(),
-        &mut CxxServerResponseWriterWrapper { writer: responder },
-    );
-}
-
 /// A common code for handle_request and handle_response methods.
 pub(super) fn handle_packet(
     chip_id: ChipIdentifier,
diff --git a/rust/daemon/src/captures/pcap_util.rs b/rust/daemon/src/captures/pcap_util.rs
index 86d5e683..dd8842b9 100644
--- a/rust/daemon/src/captures/pcap_util.rs
+++ b/rust/daemon/src/captures/pcap_util.rs
@@ -23,14 +23,22 @@ use std::{
     time::Duration,
 };
 
-macro_rules! be_vec {
+macro_rules! ne_vec {
     ( $( $x:expr ),* ) => {
          Vec::<u8>::new().iter().copied()
-         $( .chain($x.to_be_bytes()) )*
+         $( .chain($x.to_ne_bytes()) )*
          .collect()
        };
     }
 
+macro_rules! be_vec {
+        ( $( $x:expr ),* ) => {
+             Vec::<u8>::new().iter().copied()
+             $( .chain($x.to_be_bytes()) )*
+             .collect()
+           };
+        }
+
 macro_rules! le_vec {
     ( $( $x:expr ),* ) => {
             Vec::<u8>::new().iter().copied()
@@ -63,7 +71,7 @@ pub enum LinkType {
 /// pcap file.
 pub fn write_pcap_header<W: Write>(link_type: LinkType, output: &mut W) -> Result<usize> {
     // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-file-header
-    let header: Vec<u8> = be_vec![
+    let header: Vec<u8> = ne_vec![
         0xa1b2c3d4u32, // magic number
         2u16,          // major version
         4u16,          // minor version
@@ -126,7 +134,7 @@ pub fn append_record<W: Write>(
 ) -> Result<usize> {
     // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-packet-record
     let length = packet.len();
-    let header: Vec<u8> = be_vec![
+    let header: Vec<u8> = ne_vec![
         timestamp.as_secs() as u32, // seconds
         timestamp.subsec_micros(),  // microseconds
         length as u32,              // Captured Packet Length
@@ -148,15 +156,16 @@ pub fn append_record_pcapng<W: Write>(
 ) -> Result<usize> {
     let packet_data_padding: usize = 4 - packet.len() % 4;
     let block_total_length: u32 = (packet.len() + packet_data_padding + 32) as u32;
+    let timestamp_micro = timestamp.as_micros() as u64;
     // Wrap the packet inside an Enhanced Packet Block.
     let header: Vec<u8> = le_vec![
-        0x00000006_u32,             // Block Type
-        block_total_length,         // Block Total Length
-        0_u32,                      // Interface ID
-        timestamp.as_secs() as u32, // seconds
-        timestamp.subsec_micros(),  // microseconds
-        packet.len() as u32,        // Captured Packet Length
-        packet.len() as u32         // Original Packet Length
+        0x00000006_u32,                            // Block Type
+        block_total_length,                        // Block Total Length
+        0_u32,                                     // Interface ID
+        (timestamp_micro >> 32) as u32,            // Timestamp Upper
+        (timestamp_micro & 0xFFFFFFFF_u64) as u32, // Timestamp Lower
+        packet.len() as u32,                       // Captured Packet Length
+        packet.len() as u32                        // Original Packet Length
     ];
     output.write_all(&header)?;
     output.write_all(packet)?;
@@ -173,12 +182,17 @@ mod tests {
     use super::*;
 
     static EXPECTED_PCAP: &[u8; 76] = include_bytes!("sample.pcap");
-    static EXPECTED_PCAPNG: &[u8; 88] = include_bytes!("sample.pcapng");
+    static EXPECTED_PCAP_LE: &[u8; 76] = include_bytes!("sample_le.pcap");
+    static EXPECTED_PCAPNG: &[u8; 136] = include_bytes!("sample.pcapng");
+
+    fn is_little_endian() -> bool {
+        0x12345678u32.to_le_bytes()[0] == 0x78
+    }
 
     #[test]
     /// The test is done with the golden file sample.pcap with following packets:
     /// Packet 1: HCI_EVT from Controller to Host (Sent Command Complete (LE Set Advertise Enable))
-    /// Packet 2: HCI_CMD from Host to Controller (Rcvd LE Set Advertise Enable) [250 milisecs later]
+    /// Packet 2: HCI_CMD from Host to Controller (Rcvd LE Set Advertise Enable) [250 millisecs later]
     fn test_pcap_file() {
         let mut actual = Vec::<u8>::new();
         write_pcap_header(LinkType::BluetoothHciH4WithPhdr, &mut actual).unwrap();
@@ -196,15 +210,26 @@ mod tests {
             &wrap_bt_packet(PacketDirection::ControllerToHost, 1, &[10, 32, 1, 0]),
         )
         .unwrap();
-        assert_eq!(actual, EXPECTED_PCAP);
+        match is_little_endian() {
+            true => assert_eq!(actual, EXPECTED_PCAP_LE),
+            false => assert_eq!(actual, EXPECTED_PCAP),
+        }
     }
 
     #[test]
+    // This test is done with the golden file sample.pcapng with following packets:
+    // Packet 1: UCI Core Get Device Info Cmd
+    // Packet 2: UCI Core Get Device Info Rsp [250 millisecs later]
     fn test_pcapng_file() {
         let mut actual = Vec::<u8>::new();
         write_pcapng_header(LinkType::FiraUci, &mut actual).unwrap();
-        // Appending a UCI packet: Core Get Device Info Cmd
-        let _ = append_record_pcapng(Duration::new(0, 0), &mut actual, &[32, 2, 0, 0]).unwrap();
+        let _ = append_record_pcapng(Duration::from_secs(0), &mut actual, &[32, 2, 0, 0]).unwrap();
+        let _ = append_record_pcapng(
+            Duration::from_millis(250),
+            &mut actual,
+            &[64, 2, 0, 10, 0, 2, 0, 1, 48, 1, 48, 1, 16, 0],
+        )
+        .unwrap();
         assert_eq!(actual, EXPECTED_PCAPNG);
     }
 }
diff --git a/rust/daemon/src/captures/sample.pcapng b/rust/daemon/src/captures/sample.pcapng
index 05929408..e7ce601b 100644
Binary files a/rust/daemon/src/captures/sample.pcapng and b/rust/daemon/src/captures/sample.pcapng differ
diff --git a/rust/daemon/src/captures/sample_le.pcap b/rust/daemon/src/captures/sample_le.pcap
new file mode 100644
index 00000000..6fcd4813
Binary files /dev/null and b/rust/daemon/src/captures/sample_le.pcap differ
diff --git a/rust/daemon/src/devices/chip.rs b/rust/daemon/src/devices/chip.rs
index 29028f10..4bb048dc 100644
--- a/rust/daemon/src/devices/chip.rs
+++ b/rust/daemon/src/devices/chip.rs
@@ -13,13 +13,13 @@
 // limitations under the License.
 
 /// A `Chip` is a generic struct that wraps a radio specific
-/// WirelessAdaptor.` The Chip layer provides for common operations and
+/// WirelessChip.` The Chip layer provides for common operations and
 /// data.
 ///
 /// The emulated chip facade is a library that implements the
 /// controller protocol.
 ///
-use crate::wireless::WirelessAdaptorImpl;
+use crate::wireless::WirelessChipImpl;
 use netsim_proto::common::ChipKind as ProtoChipKind;
 use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::stats::NetsimRadioStats as ProtoRadioStats;
@@ -83,11 +83,11 @@ pub struct CreateParams {
 }
 
 /// Chip contains the common information for each Chip/Controller.
-/// Radio-specific information is contained in the wireless_adaptor.
+/// Radio-specific information is contained in the wireless_chip.
 pub struct Chip {
     pub id: ChipIdentifier,
     pub device_id: DeviceIdentifier,
-    pub wireless_adaptor: WirelessAdaptorImpl,
+    pub wireless_chip: WirelessChipImpl,
     pub kind: ProtoChipKind,
     #[allow(dead_code)]
     pub address: String,
@@ -117,12 +117,12 @@ impl Chip {
         device_id: DeviceIdentifier,
         device_name: &str,
         create_params: &CreateParams,
-        wireless_adaptor: WirelessAdaptorImpl,
+        wireless_chip: WirelessChipImpl,
     ) -> Self {
         Self {
             id,
             device_id,
-            wireless_adaptor,
+            wireless_chip,
             kind: create_params.kind,
             address: create_params.address.clone(),
             name: create_params.name.clone().unwrap_or(format!("chip-{}", id.0)),
@@ -139,12 +139,12 @@ impl Chip {
     // counts are phy level. We need a vec since Bluetooth reports
     // stats for BLE and CLASSIC.
     pub fn get_stats(&self) -> Vec<ProtoRadioStats> {
-        self.wireless_adaptor.get_stats(self.start.elapsed().as_secs())
+        self.wireless_chip.get_stats(self.start.elapsed().as_secs())
     }
 
     /// Create the model protobuf
     pub fn get(&self) -> Result<ProtoChip, String> {
-        let mut proto_chip = self.wireless_adaptor.get();
+        let mut proto_chip = self.wireless_chip.get();
         proto_chip.kind = EnumOrUnknown::new(self.kind);
         proto_chip.id = self.id.0;
         proto_chip.name.clone_from(&self.name);
@@ -162,12 +162,12 @@ impl Chip {
         if !patch.product_name.is_empty() {
             self.product_name.write().unwrap().clone_from(&patch.product_name);
         }
-        self.wireless_adaptor.patch(patch);
+        self.wireless_chip.patch(patch);
         Ok(())
     }
 
     pub fn reset(&self) -> Result<(), String> {
-        self.wireless_adaptor.reset();
+        self.wireless_chip.reset();
         Ok(())
     }
 }
@@ -192,9 +192,9 @@ pub fn new(
     device_id: DeviceIdentifier,
     device_name: &str,
     create_params: &CreateParams,
-    wireless_adaptor: WirelessAdaptorImpl,
+    wireless_chip: WirelessChipImpl,
 ) -> Result<Arc<Chip>, String> {
-    get_chip_manager().new_chip(id, device_id, device_name, create_params, wireless_adaptor)
+    get_chip_manager().new_chip(id, device_id, device_name, create_params, wireless_chip)
 }
 
 impl ChipManager {
@@ -204,9 +204,9 @@ impl ChipManager {
         device_id: DeviceIdentifier,
         device_name: &str,
         create_params: &CreateParams,
-        wireless_adaptor: WirelessAdaptorImpl,
+        wireless_chip: WirelessChipImpl,
     ) -> Result<Arc<Chip>, String> {
-        let chip = Arc::new(Chip::new(id, device_id, device_name, create_params, wireless_adaptor));
+        let chip = Arc::new(Chip::new(id, device_id, device_name, create_params, wireless_chip));
         self.chips.write().unwrap().insert(id, Arc::clone(&chip));
         Ok(chip)
     }
@@ -237,7 +237,7 @@ mod tests {
     const PRODUCT_NAME: &str = "product_name";
 
     impl ChipManager {
-        fn new_test_chip(&self, wireless_adaptor: WirelessAdaptorImpl) -> Arc<Chip> {
+        fn new_test_chip(&self, wireless_chip: WirelessChipImpl) -> Arc<Chip> {
             let create_params = CreateParams {
                 kind: CHIP_KIND,
                 address: ADDRESS.to_string(),
@@ -245,14 +245,13 @@ mod tests {
                 manufacturer: MANUFACTURER.to_string(),
                 product_name: PRODUCT_NAME.to_string(),
             };
-            self.new_chip(CHIP_ID, DEVICE_ID, DEVICE_NAME, &create_params, wireless_adaptor)
-                .unwrap()
+            self.new_chip(CHIP_ID, DEVICE_ID, DEVICE_NAME, &create_params, wireless_chip).unwrap()
         }
     }
 
     #[test]
     fn test_new_and_get_with_singleton() {
-        let mocked_adaptor = mocked::new(
+        let mocked_adaptor = mocked::add_chip(
             &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
             ChipIdentifier(0),
         );
@@ -280,8 +279,8 @@ mod tests {
 
     #[test]
     fn test_chip_get_stats() {
-        // When wireless_adaptor is constructed
-        let mocked_adaptor = mocked::new(
+        // When wireless_chip is constructed
+        let mocked_adaptor = mocked::add_chip(
             &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
             ChipIdentifier(0),
         );
@@ -293,7 +292,7 @@ mod tests {
 
     #[test]
     fn test_chip_get() {
-        let mocked_adaptor = mocked::new(
+        let mocked_adaptor = mocked::add_chip(
             &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
             ChipIdentifier(0),
         );
@@ -304,7 +303,7 @@ mod tests {
         let actual = chip.get().unwrap();
 
         // Construct expected ProtoChip
-        let mut expected = chip.wireless_adaptor.get();
+        let mut expected = chip.wireless_chip.get();
         expected.kind = EnumOrUnknown::new(chip.kind);
         expected.id = chip.id.0;
         expected.name.clone_from(&chip.name);
@@ -317,7 +316,7 @@ mod tests {
 
     #[test]
     fn test_chip_patch() {
-        let mocked_adaptor = mocked::new(
+        let mocked_adaptor = mocked::add_chip(
             &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
             ChipIdentifier(0),
         );
@@ -338,5 +337,5 @@ mod tests {
     }
 
     // TODO (b/309529194)
-    // Implement wireless/mocked.rs to test wireless_adaptor level of patch and resets.
+    // Implement wireless/mocked.rs to test wireless_chip level of patch and resets.
 }
diff --git a/rust/daemon/src/devices/device.rs b/rust/daemon/src/devices/device.rs
index d8e69218..be290c56 100644
--- a/rust/daemon/src/devices/device.rs
+++ b/rust/daemon/src/devices/device.rs
@@ -18,7 +18,7 @@ use crate::devices::chip;
 use crate::devices::chip::Chip;
 use crate::devices::chip::ChipIdentifier;
 use crate::devices::devices_handler::PoseManager;
-use crate::wireless::WirelessAdaptorImpl;
+use crate::wireless::WirelessChipImpl;
 use netsim_proto::common::ChipKind as ProtoChipKind;
 use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
 use netsim_proto::model::Device as ProtoDevice;
@@ -198,7 +198,7 @@ impl Device {
         &mut self,
         chip_create_params: &chip::CreateParams,
         chip_id: ChipIdentifier,
-        wireless_adaptor: WirelessAdaptorImpl,
+        wireless_chip: WirelessChipImpl,
     ) -> Result<(DeviceIdentifier, ChipIdentifier), String> {
         for chip in self.chips.read().unwrap().values() {
             if chip.kind == chip_create_params.kind
@@ -208,7 +208,7 @@ impl Device {
             }
         }
         let device_id = self.id;
-        let chip = chip::new(chip_id, device_id, &self.name, chip_create_params, wireless_adaptor)?;
+        let chip = chip::new(chip_id, device_id, &self.name, chip_create_params, wireless_chip)?;
         self.chips.write().unwrap().insert(chip_id, chip);
 
         Ok((device_id, chip_id))
@@ -248,7 +248,10 @@ mod tests {
                 product_name: "test_product_name".to_string(),
             },
             chip_id_1,
-            mocked::new(&mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED }, chip_id_1),
+            mocked::add_chip(
+                &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
+                chip_id_1,
+            ),
         )?;
         device.add_chip(
             &chip::CreateParams {
@@ -259,7 +262,10 @@ mod tests {
                 product_name: "test_product_name".to_string(),
             },
             chip_id_2,
-            mocked::new(&mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED }, chip_id_1),
+            mocked::add_chip(
+                &mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED },
+                chip_id_1,
+            ),
         )?;
         Ok(device)
     }
diff --git a/rust/daemon/src/devices/devices_handler.rs b/rust/daemon/src/devices/devices_handler.rs
index dcbab93e..b57c9d1b 100644
--- a/rust/daemon/src/devices/devices_handler.rs
+++ b/rust/daemon/src/devices/devices_handler.rs
@@ -26,20 +26,14 @@ use super::chip;
 use super::chip::ChipIdentifier;
 use super::device::DeviceIdentifier;
 use crate::devices::device::{AddChipResult, Device};
-use crate::events;
 use crate::events::{
     ChipAdded, ChipRemoved, DeviceAdded, DevicePatched, DeviceRemoved, Event, Events, ShutDown,
 };
-use crate::ffi::ffi_response_writable::CxxServerResponseWriter;
-use crate::ffi::CxxServerResponseWriterWrapper;
 use crate::http_server::server_response::ResponseWritable;
 use crate::wireless;
-use cxx::{CxxString, CxxVector};
 use http::Request;
-use http::Version;
 use log::{info, warn};
 use netsim_proto::common::ChipKind as ProtoChipKind;
-use netsim_proto::configuration::Controller;
 use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
 use netsim_proto::frontend::CreateDeviceRequest;
 use netsim_proto::frontend::CreateDeviceResponse;
@@ -55,18 +49,15 @@ use netsim_proto::model::Position as ProtoPosition;
 use netsim_proto::startup::DeviceInfo as ProtoDeviceInfo;
 use netsim_proto::stats::{NetsimDeviceStats as ProtoDeviceStats, NetsimRadioStats};
 use protobuf::well_known_types::timestamp::Timestamp;
-use protobuf::Message;
 use protobuf::MessageField;
 use protobuf_json_mapping::merge_from_str;
 use protobuf_json_mapping::print_to_string;
 use protobuf_json_mapping::print_to_string_with_options;
 use protobuf_json_mapping::PrintOptions;
 use std::collections::{BTreeMap, HashMap};
-use std::pin::Pin;
 use std::sync::atomic::{AtomicU32, Ordering};
 use std::sync::mpsc::Receiver;
 use std::sync::Arc;
-use std::sync::Mutex;
 use std::sync::OnceLock;
 use std::sync::RwLock;
 use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
@@ -133,22 +124,32 @@ impl PoseManager {
 static DEVICE_MANAGER: OnceLock<Arc<DeviceManager>> = OnceLock::new();
 
 fn get_manager() -> Arc<DeviceManager> {
-    DEVICE_MANAGER.get_or_init(|| Arc::new(DeviceManager::new())).clone()
+    DEVICE_MANAGER.get().unwrap().clone()
 }
 
 // TODO: last_modified atomic
 /// The Device resource is a singleton that manages all devices.
-struct DeviceManager {
+pub struct DeviceManager {
     // BTreeMap allows ListDevice to output devices in order of identifiers.
     devices: RwLock<BTreeMap<DeviceIdentifier, Device>>,
+    events: Arc<Events>,
     ids: AtomicU32,
     last_modified: RwLock<Duration>,
 }
 
 impl DeviceManager {
-    fn new() -> Self {
+    pub fn init(events: Arc<Events>) -> Arc<DeviceManager> {
+        let manager = Arc::new(Self::new(events));
+        if let Err(_e) = DEVICE_MANAGER.set(manager.clone()) {
+            panic!("Error setting device manager");
+        }
+        manager
+    }
+
+    fn new(events: Arc<Events>) -> Self {
         DeviceManager {
             devices: RwLock::new(BTreeMap::new()),
+            events,
             ids: AtomicU32::new(INITIAL_DEVICE_ID),
             last_modified: RwLock::new(
                 SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards"),
@@ -205,7 +206,7 @@ impl DeviceManager {
         };
         let event =
             Event::DeviceAdded(DeviceAdded { id, name: String::from(name), builtin, device_stats });
-        events::publish(event);
+        self.events.publish(event);
         (id, String::from(name))
     }
 }
@@ -236,7 +237,7 @@ pub fn add_chip(
 
     // Create
     let chip_id = chip::next_id();
-    let wireless_adaptor = wireless::new(wireless_create_params, chip_id);
+    let wireless_chip = wireless::add_chip(wireless_create_params, chip_id);
 
     // This is infrequent, so we can afford to do another lookup for the device.
     let _ = manager
@@ -245,7 +246,7 @@ pub fn add_chip(
         .unwrap()
         .get_mut(&device_id)
         .ok_or(format!("Device not found for device_id: {}", device_id))?
-        .add_chip(chip_create_params, chip_id, wireless_adaptor);
+        .add_chip(chip_create_params, chip_id, wireless_chip);
 
     // Update last modified timestamp for devices
     manager.update_timestamp();
@@ -257,142 +258,10 @@ pub fn add_chip(
         device_name: device_name.to_string(),
         builtin: chip_kind == ProtoChipKind::BLUETOOTH_BEACON,
     });
-    events::publish(event);
+    manager.events.publish(event);
     Ok(AddChipResult { device_id, chip_id })
 }
 
-/// AddChipResult for C++ to handle
-pub struct AddChipResultCxx {
-    device_id: u32,
-    chip_id: u32,
-    is_error: bool,
-}
-
-impl AddChipResultCxx {
-    pub fn get_device_id(&self) -> u32 {
-        self.device_id
-    }
-
-    pub fn get_chip_id(&self) -> u32 {
-        self.chip_id
-    }
-
-    pub fn is_error(&self) -> bool {
-        self.is_error
-    }
-}
-
-/// An AddChip function for Rust Device API.
-/// The backend gRPC code will be invoking this method.
-#[allow(clippy::too_many_arguments)]
-pub fn add_chip_cxx(
-    device_guid: &str,
-    device_name: &str,
-    chip_kind: &CxxString,
-    chip_address: &str,
-    chip_name: &str,
-    chip_manufacturer: &str,
-    chip_product_name: &str,
-    bt_properties: &CxxVector<u8>,
-    kind: &str,
-    version: &str,
-    sdk_version: &str,
-    build_id: &str,
-    variant: &str,
-    arch: &str,
-) -> Box<AddChipResultCxx> {
-    let _bt_properties_proto = Controller::parse_from_bytes(bt_properties.as_slice());
-    #[cfg(not(test))]
-    let (chip_kind_enum, wireless_create_param) = match chip_kind.to_string().as_str() {
-        "BLUETOOTH" => (
-            ProtoChipKind::BLUETOOTH,
-            wireless::CreateParam::Bluetooth(wireless::bluetooth::CreateParams {
-                address: chip_address.to_string(),
-                bt_properties: _bt_properties_proto
-                    .as_ref()
-                    .map_or(None, |p| Some(MessageField::some(p.clone()))),
-            }),
-        ),
-        "WIFI" => {
-            (ProtoChipKind::WIFI, wireless::CreateParam::Wifi(wireless::wifi::CreateParams {}))
-        }
-        "UWB" => (
-            ProtoChipKind::UWB,
-            wireless::CreateParam::Uwb(wireless::uwb::CreateParams {
-                address: chip_address.to_string(),
-            }),
-        ),
-        _ => {
-            return Box::new(AddChipResultCxx {
-                device_id: u32::MAX,
-                chip_id: u32::MAX,
-                is_error: true,
-            })
-        }
-    };
-    #[cfg(test)]
-    let (chip_kind_enum, wireless_create_param) = match chip_kind.to_string().as_str() {
-        "BLUETOOTH" => (
-            ProtoChipKind::BLUETOOTH,
-            wireless::CreateParam::Mock(wireless::mocked::CreateParams {
-                chip_kind: ProtoChipKind::BLUETOOTH,
-            }),
-        ),
-        "WIFI" => (
-            ProtoChipKind::WIFI,
-            wireless::CreateParam::Mock(wireless::mocked::CreateParams {
-                chip_kind: ProtoChipKind::WIFI,
-            }),
-        ),
-        "UWB" => (
-            ProtoChipKind::UWB,
-            wireless::CreateParam::Mock(wireless::mocked::CreateParams {
-                chip_kind: ProtoChipKind::UWB,
-            }),
-        ),
-        _ => {
-            return Box::new(AddChipResultCxx {
-                device_id: u32::MAX,
-                chip_id: u32::MAX,
-                is_error: true,
-            })
-        }
-    };
-    let chip_create_params = chip::CreateParams {
-        kind: chip_kind_enum,
-        address: chip_address.to_string(),
-        name: if chip_name.is_empty() { None } else { Some(chip_name.to_string()) },
-        manufacturer: chip_manufacturer.to_string(),
-        product_name: chip_product_name.to_string(),
-    };
-    let device_info = ProtoDeviceInfo {
-        kind: kind.to_string(),
-        version: version.to_string(),
-        sdk_version: sdk_version.to_string(),
-        build_id: build_id.to_string(),
-        variant: variant.to_string(),
-        arch: arch.to_string(),
-        ..Default::default()
-    };
-
-    match add_chip(
-        device_guid,
-        device_name,
-        &chip_create_params,
-        &wireless_create_param,
-        device_info,
-    ) {
-        Ok(result) => Box::new(AddChipResultCxx {
-            device_id: result.device_id.0,
-            chip_id: result.chip_id.0,
-            is_error: false,
-        }),
-        Err(_) => {
-            Box::new(AddChipResultCxx { device_id: u32::MAX, chip_id: u32::MAX, is_error: true })
-        }
-    }
-}
-
 /// Remove a chip from a device.
 ///
 /// Called when the packet transport for the chip shuts down.
@@ -409,7 +278,7 @@ pub fn remove_chip(device_id: DeviceIdentifier, chip_id: ChipIdentifier) -> Resu
         let device = guard
             .remove(&device_id)
             .ok_or(format!("RemoveChip device id {device_id} not found"))?;
-        events::publish(Event::DeviceRemoved(DeviceRemoved {
+        manager.events.publish(Event::DeviceRemoved(DeviceRemoved {
             id: device.id,
             name: device.name,
             builtin: device.builtin,
@@ -423,7 +292,7 @@ pub fn remove_chip(device_id: DeviceIdentifier, chip_id: ChipIdentifier) -> Resu
         get_pose_manager().remove(&device_id);
     }
 
-    events::publish(Event::ChipRemoved(ChipRemoved {
+    manager.events.publish(Event::ChipRemoved(ChipRemoved {
         chip_id,
         device_id,
         remaining_nonbuiltin_devices,
@@ -449,12 +318,6 @@ pub fn delete_chip(request: &DeleteChipRequest) -> Result<(), String> {
     remove_chip(device_id, chip_id)
 }
 
-/// A RemoveChip function for Rust Device API.
-/// The backend gRPC code will be invoking this method.
-pub fn remove_chip_cxx(device_id: u32, chip_id: u32) {
-    let _ = remove_chip(DeviceIdentifier(device_id), ChipIdentifier(chip_id));
-}
-
 /// Create a device from a CreateDeviceRequest.
 /// Uses a default name if none is provided.
 /// Returns an error if the device already exists.
@@ -492,11 +355,12 @@ pub fn create_device(create_device_request: &CreateDeviceRequest) -> Result<Prot
                 manufacturer: chip.manufacturer.clone(),
                 product_name: chip.product_name.clone(),
             };
-            let wireless_create_params =
-                wireless::CreateParam::BleBeacon(wireless::ble_beacon::CreateParams {
+            let wireless_create_params = wireless::wireless_manager::CreateParam::BleBeacon(
+                wireless::ble_beacon::CreateParams {
                     device_name: device_name.clone(),
                     chip_proto: chip.clone(),
-                });
+                },
+            );
 
             add_chip(
                 &device_name,
@@ -618,7 +482,7 @@ pub fn patch_device(patch_device_request: PatchDeviceRequest) -> Result<(), Stri
                         log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
 
                         // Publish Device Patched event
-                        events::publish(Event::DevicePatched(DevicePatched { id, name }));
+                        manager.events.publish(Event::DevicePatched(DevicePatched { id, name }));
                     }
                     result
                 }
@@ -643,7 +507,9 @@ pub fn patch_device(patch_device_request: PatchDeviceRequest) -> Result<(), Stri
                             log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
 
                             // Publish Device Patched event
-                            events::publish(Event::DevicePatched(DevicePatched { id, name }));
+                            manager
+                                .events
+                                .publish(Event::DevicePatched(DevicePatched { id, name }));
                         }
                         return result;
                     }
@@ -670,7 +536,7 @@ pub fn patch_device(patch_device_request: PatchDeviceRequest) -> Result<(), Stri
                         log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
 
                         // Publish Device Patched event
-                        events::publish(Event::DevicePatched(DevicePatched { id, name }));
+                        manager.events.publish(Event::DevicePatched(DevicePatched { id, name }));
                     }
                     result
                 }
@@ -758,7 +624,7 @@ pub fn reset_all() -> Result<(), String> {
     }
     // Update last modified timestamp for manager
     manager.update_timestamp();
-    events::publish(Event::DeviceReset);
+    manager.events.publish(Event::DeviceReset);
     Ok(())
 }
 
@@ -857,7 +723,8 @@ fn handle_device_subscribe(writer: ResponseWritable, subscribe_json: &str) {
         }
     }
 
-    let event_rx = events::subscribe();
+    let manager = get_manager();
+    let event_rx = manager.events.subscribe();
     // Timeout after 15 seconds with no event received
     match event_rx.recv_timeout(Duration::from_secs(15)) {
         Ok(Event::DeviceAdded(_))
@@ -871,7 +738,7 @@ fn handle_device_subscribe(writer: ResponseWritable, subscribe_json: &str) {
     }
 }
 
-/// The Rust device handler used directly by Http frontend or handle_device_cxx for LIST, GET, and PATCH
+/// The Rust device handler used directly by Http frontend for LIST, GET, and PATCH
 pub fn handle_device(request: &Request<Vec<u8>>, param: &str, writer: ResponseWritable) {
     // Route handling
     if request.uri() == "/v1/devices" {
@@ -925,34 +792,6 @@ pub fn handle_device(request: &Request<Vec<u8>>, param: &str, writer: ResponseWr
     }
 }
 
-/// Device handler cxx for grpc server to call
-pub fn handle_device_cxx(
-    responder: Pin<&mut CxxServerResponseWriter>,
-    method: String,
-    param: String,
-    body: String,
-) {
-    let mut builder = Request::builder().method(method.as_str());
-    if param.is_empty() {
-        builder = builder.uri("/v1/devices");
-    } else {
-        builder = builder.uri(format!("/v1/devices/{}", param));
-    }
-    builder = builder.version(Version::HTTP_11);
-    let request = match builder.body(body.as_bytes().to_vec()) {
-        Ok(request) => request,
-        Err(err) => {
-            warn!("{err:?}");
-            return;
-        }
-    };
-    handle_device(
-        &request,
-        param.as_str(),
-        &mut CxxServerResponseWriterWrapper { writer: responder },
-    )
-}
-
 /// return enum type for check_device_event
 #[derive(Debug, PartialEq)]
 enum DeviceWaitStatus {
@@ -973,7 +812,7 @@ fn check_device_event(
             DeviceWaitStatus::LastDeviceRemoved
         }
         // DeviceAdded (event from CreateDevice)
-        // ChipAdded (event from add_chip or add_chip_cxx)
+        // ChipAdded (event from add_chip)
         Ok(Event::DeviceAdded(DeviceAdded { builtin: false, .. }))
         | Ok(Event::ChipAdded(ChipAdded { builtin: false, .. })) => DeviceWaitStatus::DeviceAdded,
         Err(_) => DeviceWaitStatus::Timeout,
@@ -986,26 +825,23 @@ fn check_device_event(
 /// 1. Initial timeout before first device is added
 /// 2. Last Chip Removed from netsimd
 ///    this function should NOT be invoked if running in no-shutdown mode
-pub fn spawn_shutdown_publisher(events_rx: Receiver<Event>) {
-    spawn_shutdown_publisher_with_timeout(events_rx, IDLE_SECS_FOR_SHUTDOWN, events::get_events());
+pub fn spawn_shutdown_publisher(events_rx: Receiver<Event>, events: Arc<Events>) {
+    spawn_shutdown_publisher_with_timeout(events_rx, IDLE_SECS_FOR_SHUTDOWN, events);
 }
 
 // separate function for testability
 fn spawn_shutdown_publisher_with_timeout(
     events_rx: Receiver<Event>,
     timeout_duration_s: u64,
-    events_tx: Arc<Mutex<Events>>,
+    events: Arc<Events>,
 ) {
     let _ =
         std::thread::Builder::new().name("device_event_subscriber".to_string()).spawn(move || {
-            let publish_event =
-                |e: Event| events_tx.lock().expect("Failed to acquire lock on events").publish(e);
-
             let mut timeout_time = Some(Instant::now() + Duration::from_secs(timeout_duration_s));
             loop {
                 match check_device_event(&events_rx, timeout_time) {
                     DeviceWaitStatus::LastDeviceRemoved => {
-                        publish_event(Event::ShutDown(ShutDown {
+                        events.publish(Event::ShutDown(ShutDown {
                             reason: "last device disconnected".to_string(),
                         }));
                         return;
@@ -1014,7 +850,7 @@ fn spawn_shutdown_publisher_with_timeout(
                         timeout_time = None;
                     }
                     DeviceWaitStatus::Timeout => {
-                        publish_event(Event::ShutDown(ShutDown {
+                        events.publish(Event::ShutDown(ShutDown {
                             reason: format!(
                                 "no devices connected within {IDLE_SECS_FOR_SHUTDOWN}s"
                             ),
@@ -1030,7 +866,7 @@ fn spawn_shutdown_publisher_with_timeout(
 /// Return vector containing current radio chip stats from all devices
 pub fn get_radio_stats() -> Vec<NetsimRadioStats> {
     let mut result: Vec<NetsimRadioStats> = Vec::new();
-    // TODO: b/309805437 - optimize logic using get_stats for WirelessAdaptor
+    // TODO: b/309805437 - optimize logic using get_stats for WirelessChip
     for (device_id, device) in get_manager().devices.read().unwrap().iter() {
         for chip in device.chips.read().unwrap().values() {
             for mut radio_stats in chip.get_stats() {
@@ -1044,7 +880,7 @@ pub fn get_radio_stats() -> Vec<NetsimRadioStats> {
 
 #[cfg(test)]
 mod tests {
-    use crate::events;
+    use http::Version;
     use netsim_common::util::netsim_logger::init_for_test;
     use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
     use netsim_proto::model::{DeviceCreate as ProtoDeviceCreate, Orientation as ProtoOrientation};
@@ -1058,10 +894,11 @@ mod tests {
     // This allows Log init method to be invoked once when running all tests.
     static INIT: Once = Once::new();
 
-    /// Logger setup function that is only run once, even if called multiple times.
-    fn logger_setup() {
+    /// Module setup function that is only run once, even if called multiple times.
+    fn module_setup() {
         INIT.call_once(|| {
             init_for_test();
+            DeviceManager::init(Events::new());
         });
     }
 
@@ -1178,27 +1015,24 @@ mod tests {
         }
     }
 
-    fn spawn_shutdown_publisher_test_setup(timeout: u64) -> (Arc<Mutex<Events>>, Receiver<Event>) {
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
+    fn spawn_shutdown_publisher_test_setup(timeout: u64) -> (Arc<Events>, Receiver<Event>) {
+        let events = Events::new();
+        let events_rx = events.subscribe();
         spawn_shutdown_publisher_with_timeout(events_rx, timeout, events.clone());
 
-        let events_rx2 = events::test::subscribe(&mut events);
+        let events_rx2 = events.subscribe();
 
         (events, events_rx2)
     }
 
     #[test]
     fn test_spawn_shutdown_publisher_last_chip_removed() {
-        let (mut events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
+        let (events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
 
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
 
         // receive our own ChipRemoved
         assert!(matches!(events_rx.recv(), Ok(Event::ChipRemoved(ChipRemoved { .. }))));
@@ -1208,28 +1042,22 @@ mod tests {
 
     #[test]
     fn test_spawn_shutdown_publisher_chip_removed_which_is_not_last_chip() {
-        let (mut events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(1),
-                remaining_nonbuiltin_devices: 1,
-                ..Default::default()
-            }),
-        );
+        let (events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(1),
+            remaining_nonbuiltin_devices: 1,
+            ..Default::default()
+        }));
 
         // give other thread time to generate a ShutDown if it was going to
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // only the 2nd ChipRemoved should generate a ShutDown as it is marked the last one
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(0),
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(0),
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
 
         // receive our own ChipRemoved
         assert!(matches!(events_rx.recv(), Ok(Event::ChipRemoved(ChipRemoved { .. }))));
@@ -1241,15 +1069,12 @@ mod tests {
 
     #[test]
     fn test_spawn_shutdown_publisher_last_chip_removed_with_duplicate_event() {
-        let (mut events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(0),
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        let (events, events_rx) = spawn_shutdown_publisher_test_setup(IDLE_SECS_FOR_SHUTDOWN);
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(0),
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
 
         // give other thread time to generate a ShutDown if it was going to
         std::thread::sleep(std::time::Duration::from_secs(1));
@@ -1260,14 +1085,11 @@ mod tests {
         // we would receive ChipRemoved, ShutDown, ChipRemoved
         // but if first ChipRemoved has remaining_nonbuiltin_devices,
         // we instead receive ChipRemoved, ChipRemoved, ShutDown
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(0),
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(0),
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
 
         // receive our own ChipRemoved
         assert!(matches!(events_rx.recv(), Ok(Event::ChipRemoved(_))));
@@ -1290,30 +1112,24 @@ mod tests {
 
     #[test]
     fn test_spawn_shutdown_publisher_timeout_is_canceled_if_a_chip_is_added() {
-        let (mut events, events_rx) = spawn_shutdown_publisher_test_setup(1u64);
+        let (events, events_rx) = spawn_shutdown_publisher_test_setup(1u64);
 
-        events::test::publish(
-            &mut events,
-            Event::ChipAdded(ChipAdded {
-                chip_id: ChipIdentifier(0),
-                chip_kind: ProtoChipKind::BLUETOOTH,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipAdded(ChipAdded {
+            chip_id: ChipIdentifier(0),
+            chip_kind: ProtoChipKind::BLUETOOTH,
+            ..Default::default()
+        }));
         assert!(matches!(events_rx.recv(), Ok(Event::ChipAdded(_))));
 
         // should NO longer receive the ShutDown emitted by the function under test
         // based on timeout removed when chip added
         assert!(events_rx.recv_timeout(Duration::from_secs(2)).is_err());
 
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(0),
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(0),
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
         // receive our own ChipRemoved
         assert!(matches!(events_rx.recv(), Ok(Event::ChipRemoved(_))));
         // receive the ShutDown emitted by the function under test
@@ -1332,13 +1148,14 @@ mod tests {
 
     #[test]
     fn test_add_chip() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+
+        let manager = get_manager();
 
         // Adding a chip
         let chip_params = test_chip_1_bt();
         let chip_result = chip_params.add_chip().unwrap();
-        match get_manager().devices.read().unwrap().get(&chip_result.device_id) {
+        match manager.devices.read().unwrap().get(&chip_result.device_id) {
             Some(device) => {
                 let chips = device.chips.read().unwrap();
                 let chip = chips.get(&chip_result.chip_id).unwrap();
@@ -1355,13 +1172,14 @@ mod tests {
                 assert_eq!(chip_params.device_name, device.name);
             }
             None => unreachable!(),
-        }
+        };
     }
 
     #[test]
     fn test_get_or_create_device() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+
+        let manager = get_manager();
 
         // Creating a device and getting device
         let bt_chip_params = test_chip_1_bt();
@@ -1369,13 +1187,12 @@ mod tests {
         let wifi_chip_params = test_chip_1_wifi();
         let device_id_2 = wifi_chip_params.get_or_create_device();
         assert_eq!(device_id_1, device_id_2);
-        assert!(get_manager().devices.read().unwrap().get(&device_id_1).is_some())
+        assert!(manager.devices.read().unwrap().get(&device_id_1).is_some())
     }
 
     #[test]
     fn test_patch_device_json() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
 
         // Patching device position and orientation by id
         let chip_params = test_chip_1_bt();
@@ -1425,8 +1242,7 @@ mod tests {
 
     #[test]
     fn test_patch_error() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
 
         // Patch Error Testing
         let bt_chip_params = test_chip_1_bt();
@@ -1486,8 +1302,8 @@ mod tests {
 
     #[test]
     fn test_adding_two_chips() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         // Adding two chips of the same device
         let bt_chip_params = test_chip_1_bt();
@@ -1495,7 +1311,6 @@ mod tests {
         let bt_chip_result = bt_chip_params.add_chip().unwrap();
         let wifi_chip_result = wifi_chip_params.add_chip().unwrap();
         assert_eq!(bt_chip_result.device_id, wifi_chip_result.device_id);
-        let manager = get_manager();
         let devices = manager.devices.read().unwrap();
         let device = devices.get(&bt_chip_result.device_id).unwrap();
         assert_eq!(device.id, bt_chip_result.device_id);
@@ -1515,8 +1330,8 @@ mod tests {
 
     #[test]
     fn test_reset() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         // Patching Device and Resetting scene
         let chip_params = test_chip_1_bt();
@@ -1535,7 +1350,7 @@ mod tests {
             print_to_string(&patch_device_request).unwrap().as_str(),
         )
         .unwrap();
-        match get_manager().devices.read().unwrap().get(&chip_result.device_id) {
+        match manager.devices.read().unwrap().get(&chip_result.device_id) {
             Some(device) => {
                 assert!(!device.visible.load(Ordering::SeqCst));
             }
@@ -1557,7 +1372,7 @@ mod tests {
         }
 
         reset(chip_result.device_id).unwrap();
-        match get_manager().devices.read().unwrap().get(&chip_result.device_id) {
+        match manager.devices.read().unwrap().get(&chip_result.device_id) {
             Some(device) => {
                 assert!(device.visible.load(Ordering::SeqCst));
             }
@@ -1585,8 +1400,8 @@ mod tests {
 
     #[test]
     fn test_remove_chip() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         // Add 2 chips of same device and 1 chip of different device
         let bt_chip_params = test_chip_1_bt();
@@ -1598,7 +1413,7 @@ mod tests {
 
         // Remove a bt chip of first device
         remove_chip(bt_chip_result.device_id, bt_chip_result.chip_id).unwrap();
-        match get_manager().devices.read().unwrap().get(&bt_chip_result.device_id) {
+        match manager.devices.read().unwrap().get(&bt_chip_result.device_id) {
             Some(device) => {
                 assert_eq!(device.chips.read().unwrap().len(), 1);
                 assert_eq!(
@@ -1611,17 +1426,17 @@ mod tests {
 
         // Remove a wifi chip of first device
         remove_chip(wifi_chip_result.device_id, wifi_chip_result.chip_id).unwrap();
-        assert!(!get_manager().devices.read().unwrap().contains_key(&wifi_chip_result.device_id));
+        assert!(!manager.devices.read().unwrap().contains_key(&wifi_chip_result.device_id));
 
         // Remove a bt chip of second device
         remove_chip(bt_chip_2_result.device_id, bt_chip_2_result.chip_id).unwrap();
-        assert!(!get_manager().devices.read().unwrap().contains_key(&bt_chip_2_result.device_id));
+        assert!(!manager.devices.read().unwrap().contains_key(&bt_chip_2_result.device_id));
     }
 
     #[test]
     fn test_remove_chip_error() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         // Add 2 chips of same device and 1 chip of different device
         let bt_chip_params = test_chip_1_bt();
@@ -1638,13 +1453,12 @@ mod tests {
             Ok(_) => unreachable!(),
             Err(err) => assert_eq!(err, "RemoveChip device id 9999 not found"),
         }
-        assert!(get_manager().devices.read().unwrap().contains_key(&bt_chip_result.device_id));
+        assert!(manager.devices.read().unwrap().contains_key(&bt_chip_result.device_id));
     }
 
     #[test]
     fn test_get_distance() {
-        // Initializing Logger
-        logger_setup();
+        module_setup();
 
         // Add 2 chips of different devices
         let bt_chip_params = test_chip_1_bt();
@@ -1720,7 +1534,7 @@ mod tests {
 
     #[test]
     fn test_create_device_succeeds() {
-        logger_setup();
+        module_setup();
 
         let request = get_test_create_device_request(Some(format!(
             "bob-the-beacon-{:?}",
@@ -1737,7 +1551,7 @@ mod tests {
 
     #[test]
     fn test_create_chipless_device_fails() {
-        logger_setup();
+        module_setup();
 
         let request = CreateDeviceRequest {
             device: MessageField::some(ProtoDeviceCreate { ..Default::default() }),
@@ -1750,7 +1564,7 @@ mod tests {
 
     #[test]
     fn test_create_radioless_device_fails() {
-        logger_setup();
+        module_setup();
 
         let request = CreateDeviceRequest {
             device: MessageField::some(ProtoDeviceCreate {
@@ -1766,7 +1580,7 @@ mod tests {
 
     #[test]
     fn test_get_beacon_device() {
-        logger_setup();
+        module_setup();
 
         let request = get_test_create_device_request(Some(format!(
             "bob-the-beacon-{:?}",
@@ -1783,7 +1597,7 @@ mod tests {
 
     #[test]
     fn test_create_device_default_name() {
-        logger_setup();
+        module_setup();
 
         let request = get_test_create_device_request(None);
 
@@ -1795,7 +1609,7 @@ mod tests {
 
     #[test]
     fn test_create_existing_device_fails() {
-        logger_setup();
+        module_setup();
 
         let request = get_test_create_device_request(Some(format!(
             "existing-device-{:?}",
@@ -1812,7 +1626,8 @@ mod tests {
 
     #[test]
     fn test_patch_beacon_device() {
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         let request = get_test_create_device_request(Some(format!(
             "bob-the-beacon-{:?}",
@@ -1822,7 +1637,6 @@ mod tests {
         let device_proto = create_device(&request);
         assert!(device_proto.is_ok(), "{}", device_proto.unwrap_err());
         let device_proto = device_proto.unwrap();
-        let manager = get_manager();
         let mut devices = manager.devices.write().unwrap();
         let device = devices
             .get_mut(&DeviceIdentifier(device_proto.id))
@@ -1853,7 +1667,8 @@ mod tests {
 
     #[test]
     fn test_remove_beacon_device_succeeds() {
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         let create_request = get_test_create_device_request(None);
         let device_proto = create_device(&create_request);
@@ -1861,7 +1676,6 @@ mod tests {
 
         let device_proto = device_proto.unwrap();
         let chip_id = {
-            let manager = get_manager();
             let devices = manager.devices.read().unwrap();
             let device = devices.get(&DeviceIdentifier(device_proto.id)).unwrap();
             let chips = device.chips.read().unwrap();
@@ -1872,23 +1686,20 @@ mod tests {
         let delete_result = delete_chip(&delete_request);
         assert!(delete_result.is_ok(), "{}", delete_result.unwrap_err());
 
-        assert!(!get_manager()
-            .devices
-            .read()
-            .unwrap()
-            .contains_key(&DeviceIdentifier(device_proto.id)))
+        assert!(!manager.devices.read().unwrap().contains_key(&DeviceIdentifier(device_proto.id)))
     }
 
     #[test]
     fn test_remove_beacon_device_fails() {
-        logger_setup();
+        module_setup();
+        let manager = get_manager();
 
         let create_request = get_test_create_device_request(None);
         let device_proto = create_device(&create_request);
         assert!(device_proto.is_ok(), "{}", device_proto.unwrap_err());
 
         let device_proto = device_proto.unwrap();
-        let chip_id = get_manager()
+        let chip_id = manager
             .devices
             .read()
             .unwrap()
@@ -1911,10 +1722,10 @@ mod tests {
 
     #[test]
     fn test_check_device_event_initial_timeout() {
-        logger_setup();
+        module_setup();
 
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
+        let events = get_manager().events.clone();
+        let events_rx = events.subscribe();
         assert_eq!(
             check_device_event(&events_rx, Some(std::time::Instant::now())),
             DeviceWaitStatus::Timeout
@@ -1923,74 +1734,59 @@ mod tests {
 
     #[test]
     fn test_check_device_event_last_device_removed() {
-        logger_setup();
-
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                remaining_nonbuiltin_devices: 0,
-                ..Default::default()
-            }),
-        );
+        module_setup();
+
+        let events = Events::new();
+        let events_rx = events.subscribe();
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            remaining_nonbuiltin_devices: 0,
+            ..Default::default()
+        }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::LastDeviceRemoved);
     }
 
     #[test]
     fn test_check_device_event_device_chip_added() {
-        logger_setup();
-
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
-        events::test::publish(
-            &mut events,
-            Event::DeviceAdded(DeviceAdded {
-                id: DeviceIdentifier(0),
-                name: "".to_string(),
-                builtin: false,
-                device_stats: ProtoDeviceStats::new(),
-            }),
-        );
+        module_setup();
+
+        let events = Events::new();
+        let events_rx = events.subscribe();
+        events.publish(Event::DeviceAdded(DeviceAdded {
+            id: DeviceIdentifier(0),
+            name: "".to_string(),
+            builtin: false,
+            device_stats: ProtoDeviceStats::new(),
+        }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::DeviceAdded);
-        events::test::publish(
-            &mut events,
-            Event::ChipAdded(ChipAdded { builtin: false, ..Default::default() }),
-        );
+        events.publish(Event::ChipAdded(ChipAdded { builtin: false, ..Default::default() }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::DeviceAdded);
     }
 
     #[test]
     fn test_check_device_event_ignore_event() {
-        logger_setup();
+        module_setup();
 
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
-        events::test::publish(
-            &mut events,
-            Event::DevicePatched(DevicePatched { id: DeviceIdentifier(0), name: "".to_string() }),
-        );
+        let events = Events::new();
+        let events_rx = events.subscribe();
+        events.publish(Event::DevicePatched(DevicePatched {
+            id: DeviceIdentifier(0),
+            name: "".to_string(),
+        }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::IgnoreEvent);
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                remaining_nonbuiltin_devices: 1,
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            remaining_nonbuiltin_devices: 1,
+            ..Default::default()
+        }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::IgnoreEvent);
     }
 
     #[test]
     fn test_check_device_event_ignore_chip_added_for_builtin() {
-        logger_setup();
+        module_setup();
 
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
-        events::test::publish(
-            &mut events,
-            Event::ChipAdded(ChipAdded { builtin: true, ..Default::default() }),
-        );
+        let events = Events::new();
+        let events_rx = events.subscribe();
+        events.publish(Event::ChipAdded(ChipAdded { builtin: true, ..Default::default() }));
         assert_eq!(check_device_event(&events_rx, None), DeviceWaitStatus::IgnoreEvent);
     }
 }
diff --git a/rust/daemon/src/events.rs b/rust/daemon/src/events.rs
index c5c1a817..3fc11aa7 100644
--- a/rust/daemon/src/events.rs
+++ b/rust/daemon/src/events.rs
@@ -23,17 +23,7 @@ use netsim_proto::stats::{
     NetsimDeviceStats as ProtoDeviceStats, NetsimRadioStats as ProtoRadioStats,
 };
 
-use std::sync::{Arc, Mutex, OnceLock};
-
-// Publish the event to all subscribers
-pub fn publish(event: Event) {
-    get_events().lock().expect("Failed to acquire lock on events").publish(event);
-}
-
-// Subscribe to events over the receiver
-pub fn subscribe() -> Receiver<Event> {
-    get_events().lock().expect("Failed to acquire locks on events").subscribe()
-}
+use std::sync::{Arc, Mutex};
 
 #[derive(Clone, Debug, Default)]
 pub struct DeviceAdded {
@@ -90,12 +80,6 @@ pub enum Event {
     ShutDown(ShutDown),
 }
 
-static EVENTS: OnceLock<Arc<Mutex<Events>>> = OnceLock::new();
-
-pub fn get_events() -> Arc<Mutex<Events>> {
-    EVENTS.get_or_init(Events::new).clone()
-}
-
 /// A multi-producer, multi-consumer broadcast queue based on
 /// `std::sync::mpsc`.
 ///
@@ -107,56 +91,41 @@ pub fn get_events() -> Arc<Mutex<Events>> {
 pub struct Events {
     // For each subscriber this module retrain the sender half and the
     // subscriber reads events from the receiver half.
-    subscribers: Vec<Sender<Event>>,
+    subscribers: Mutex<Vec<Sender<Event>>>,
 }
 
 impl Events {
-    // Events is always owned by multiple publishers and subscribers
-    // across threads so return an Arc type.
-    fn new() -> Arc<Mutex<Events>> {
-        Arc::new(Mutex::new(Self { subscribers: Vec::new() }))
+    // Events held by multiple publishers and subscribers across
+    // threads so return an Arc type.
+    pub fn new() -> Arc<Events> {
+        Arc::new(Self { subscribers: Mutex::new(Vec::new()) })
     }
 
     // Creates a new asynchronous channel, returning the receiver
     // half. All `Event` messages sent through `publish` will become
     // available on the receiver in the same order as it was sent.
-    fn subscribe(&mut self) -> Receiver<Event> {
+    pub fn subscribe(&self) -> Receiver<Event> {
         let (tx, rx) = channel::<Event>();
-        self.subscribers.push(tx);
+        self.subscribers.lock().expect("failed to lock subscribers").push(tx);
         rx
     }
 
     // Attempts to send an Event on the events channel.
-    pub fn publish(&mut self, msg: Event) {
-        if self.subscribers.is_empty() {
+    pub fn publish(&self, msg: Event) {
+        if self.subscribers.lock().expect("failed to lock subscribers").is_empty() {
             log::warn!("No Subscribers to the event: {msg:?}");
         } else {
             // Any channel with a disconnected receiver will return an
             // error and be removed by retain.
             log::info!("{msg:?}");
-            self.subscribers.retain(|subscriber| subscriber.send(msg.clone()).is_ok())
+            self.subscribers
+                .lock()
+                .expect("failed to lock subscribers")
+                .retain(|subscriber| subscriber.send(msg.clone()).is_ok())
         }
     }
 }
 
-// Test public functions to allow testing with local Events struct.
-#[cfg(test)]
-pub mod test {
-    use super::*;
-
-    pub fn new() -> Arc<Mutex<Events>> {
-        Events::new()
-    }
-
-    pub fn publish(s: &mut Arc<Mutex<Events>>, msg: Event) {
-        s.lock().unwrap().publish(msg);
-    }
-
-    pub fn subscribe(s: &mut Arc<Mutex<Events>>) -> Receiver<Event> {
-        s.lock().unwrap().subscribe()
-    }
-}
-
 #[cfg(test)]
 mod tests {
     use super::Events;
@@ -164,12 +133,18 @@ mod tests {
     use std::sync::Arc;
     use std::thread;
 
+    impl Events {
+        pub fn subscriber_count(&self) -> usize {
+            self.subscribers.lock().expect("events subscribers lock").len()
+        }
+    }
+
     #[test]
     fn test_subscribe_and_publish() {
         let events = Events::new();
 
         let events_clone = Arc::clone(&events);
-        let rx = events_clone.lock().unwrap().subscribe();
+        let rx = events_clone.subscribe();
         let handle = thread::spawn(move || match rx.recv() {
             Ok(Event::DeviceAdded(DeviceAdded { id, name, builtin, device_stats })) => {
                 assert_eq!(id.0, 123);
@@ -180,7 +155,7 @@ mod tests {
             _ => panic!("Unexpected event"),
         });
 
-        events.lock().unwrap().publish(Event::DeviceAdded(DeviceAdded {
+        events.publish(Event::DeviceAdded(DeviceAdded {
             id: DeviceIdentifier(123),
             name: "Device1".into(),
             builtin: false,
@@ -199,7 +174,7 @@ mod tests {
         let mut handles = Vec::with_capacity(num_subscribers);
         for _ in 0..num_subscribers {
             let events_clone = Arc::clone(&events);
-            let rx = events_clone.lock().unwrap().subscribe();
+            let rx = events_clone.subscribe();
             let handle = thread::spawn(move || match rx.recv() {
                 Ok(Event::DeviceAdded(DeviceAdded { id, name, builtin, device_stats })) => {
                     assert_eq!(id.0, 123);
@@ -212,7 +187,7 @@ mod tests {
             handles.push(handle);
         }
 
-        events.lock().unwrap().publish(Event::DeviceAdded(DeviceAdded {
+        events.publish(Event::DeviceAdded(DeviceAdded {
             id: DeviceIdentifier(123),
             name: "Device1".into(),
             builtin: false,
@@ -231,15 +206,15 @@ mod tests {
     // removed when send() notices an error.
     fn test_publish_to_dropped_subscriber() {
         let events = Events::new();
-        let rx = events.lock().unwrap().subscribe();
-        assert_eq!(events.lock().unwrap().subscribers.len(), 1);
+        let rx = events.subscribe();
+        assert_eq!(events.subscriber_count(), 1);
         std::mem::drop(rx);
-        events.lock().unwrap().publish(Event::DeviceAdded(DeviceAdded {
+        events.publish(Event::DeviceAdded(DeviceAdded {
             id: DeviceIdentifier(123),
             name: "Device1".into(),
             builtin: false,
             device_stats: ProtoDeviceStats::new(),
         }));
-        assert_eq!(events.lock().unwrap().subscribers.len(), 0);
+        assert_eq!(events.subscriber_count(), 0);
     }
 }
diff --git a/rust/daemon/src/ffi.rs b/rust/daemon/src/ffi.rs
index 148db0cb..f123e870 100644
--- a/rust/daemon/src/ffi.rs
+++ b/rust/daemon/src/ffi.rs
@@ -14,21 +14,12 @@
 
 //! Netsim daemon cxx libraries.
 
-use std::pin::Pin;
-
 use crate::bluetooth::chip::{
     create_add_rust_device_result, AddRustDeviceResult, RustBluetoothChipCallbacks,
 };
-use crate::http_server::server_response::ServerResponseWritable;
-use crate::http_server::server_response::StrHeaders;
-use cxx::let_cxx_string;
 
-use crate::captures::captures_handler::handle_capture_cxx;
-use crate::devices::devices_handler::{
-    add_chip_cxx, get_distance_cxx, handle_device_cxx, remove_chip_cxx, AddChipResultCxx,
-};
+use crate::devices::devices_handler::get_distance_cxx;
 use crate::ranging::*;
-use crate::version::*;
 use crate::wireless::{
     bluetooth::report_invalid_packet_cxx, handle_request_cxx, handle_response_cxx,
 };
@@ -211,87 +202,11 @@ pub mod ffi_bluetooth {
 #[cxx::bridge(namespace = "netsim::device")]
 pub mod ffi_devices {
     extern "Rust" {
-
-        // Device Resource
-        type AddChipResultCxx;
-        #[cxx_name = "GetDeviceId"]
-        fn get_device_id(self: &AddChipResultCxx) -> u32;
-        #[cxx_name = "GetChipId"]
-        fn get_chip_id(self: &AddChipResultCxx) -> u32;
-        #[cxx_name = "IsError"]
-        fn is_error(self: &AddChipResultCxx) -> bool;
-
-        #[allow(clippy::too_many_arguments)]
-        #[cxx_name = AddChipCxx]
-        fn add_chip_cxx(
-            device_guid: &str,
-            device_name: &str,
-            chip_kind: &CxxString,
-            chip_address: &str,
-            chip_name: &str,
-            chip_manufacturer: &str,
-            chip_product_name: &str,
-            bt_properties: &CxxVector<u8>,
-            kind: &str,
-            version: &str,
-            sdk_version: &str,
-            build_id: &str,
-            variant: &str,
-            arch: &str,
-        ) -> Box<AddChipResultCxx>;
-
-        #[cxx_name = RemoveChipCxx]
-        fn remove_chip_cxx(device_id: u32, chip_id: u32);
-
         #[cxx_name = GetDistanceCxx]
         fn get_distance_cxx(a: u32, b: u32) -> f32;
     }
 }
 
-#[allow(unsafe_op_in_unsafe_fn)]
-#[cxx::bridge(namespace = "netsim")]
-pub mod ffi_response_writable {
-    extern "Rust" {
-        // handlers for gRPC server's invocation of API calls
-
-        #[cxx_name = "HandleCaptureCxx"]
-        fn handle_capture_cxx(
-            responder: Pin<&mut CxxServerResponseWriter>,
-            method: String,
-            param: String,
-            body: String,
-        );
-
-        #[cxx_name = "HandleDeviceCxx"]
-        fn handle_device_cxx(
-            responder: Pin<&mut CxxServerResponseWriter>,
-            method: String,
-            param: String,
-            body: String,
-        );
-    }
-    unsafe extern "C++" {
-        /// A C++ class which can be used to respond to a request.
-        include!("frontend/server_response_writable.h");
-
-        #[namespace = "netsim::frontend"]
-        type CxxServerResponseWriter;
-
-        #[namespace = "netsim::frontend"]
-        fn put_ok_with_length(self: &CxxServerResponseWriter, mime_type: &CxxString, length: usize);
-
-        #[namespace = "netsim::frontend"]
-        fn put_chunk(self: &CxxServerResponseWriter, chunk: &[u8]);
-
-        #[namespace = "netsim::frontend"]
-        fn put_ok(self: &CxxServerResponseWriter, mime_type: &CxxString, body: &CxxString);
-
-        #[namespace = "netsim::frontend"]
-        fn put_error(self: &CxxServerResponseWriter, error_code: u32, error_message: &CxxString);
-
-    }
-}
-
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "netsim")]
 pub mod ffi_util {
@@ -300,11 +215,6 @@ pub mod ffi_util {
 
         #[cxx_name = "DistanceToRssi"]
         fn distance_to_rssi(tx_power: i8, distance: f32) -> i8;
-
-        // Version
-
-        #[cxx_name = "GetVersion"]
-        fn get_version() -> String;
     }
 
     #[allow(dead_code)]
@@ -344,35 +254,3 @@ fn receive_link_layer_packet(
         packet,
     );
 }
-
-/// CxxServerResponseWriter is defined in server_response_writable.h
-/// Wrapper struct allows the impl to discover the respective C++ methods
-pub struct CxxServerResponseWriterWrapper<'a> {
-    pub writer: Pin<&'a mut ffi_response_writable::CxxServerResponseWriter>,
-}
-
-impl ServerResponseWritable for CxxServerResponseWriterWrapper<'_> {
-    fn put_ok_with_length(&mut self, mime_type: &str, length: usize, _headers: StrHeaders) {
-        let_cxx_string!(mime_type = mime_type);
-        self.writer.put_ok_with_length(&mime_type, length);
-    }
-    fn put_chunk(&mut self, chunk: &[u8]) {
-        self.writer.put_chunk(chunk);
-    }
-    fn put_ok(&mut self, mime_type: &str, body: &str, _headers: StrHeaders) {
-        let_cxx_string!(mime_type = mime_type);
-        let_cxx_string!(body = body);
-        self.writer.put_ok(&mime_type, &body);
-    }
-    fn put_error(&mut self, error_code: u16, error_message: &str) {
-        let_cxx_string!(error_message = error_message);
-        self.writer.put_error(error_code.into(), &error_message);
-    }
-
-    fn put_ok_with_vec(&mut self, _mime_type: &str, _body: Vec<u8>, _headers: StrHeaders) {
-        todo!()
-    }
-    fn put_ok_switch_protocol(&mut self, _connection: &str, _headers: StrHeaders) {
-        todo!()
-    }
-}
diff --git a/rust/daemon/src/grpc_server/backend.rs b/rust/daemon/src/grpc_server/backend.rs
index 1e47b6a2..e125cd21 100644
--- a/rust/daemon/src/grpc_server/backend.rs
+++ b/rust/daemon/src/grpc_server/backend.rs
@@ -42,7 +42,7 @@ fn add_chip(initial_info: &ChipInfo, device_guid: &str) -> anyhow::Result<AddChi
                 bt_properties: Some(chip.bt_properties.clone()),
             })
         }
-        ProtoChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi::CreateParams {}),
+        ProtoChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi_chip::CreateParams {}),
         ProtoChipKind::UWB => wireless::CreateParam::Uwb(wireless::uwb::CreateParams {
             address: chip.address.clone(),
         }),
diff --git a/rust/daemon/src/grpc_server/server.rs b/rust/daemon/src/grpc_server/server.rs
index b94e2612..7d81164e 100644
--- a/rust/daemon/src/grpc_server/server.rs
+++ b/rust/daemon/src/grpc_server/server.rs
@@ -27,7 +27,7 @@ pub fn start(port: u32, no_cli_ui: bool, _vsock: u16) -> anyhow::Result<(Server,
     let backend_service = create_packet_streamer(PacketStreamerService);
     let frontend_service = create_frontend_service(FrontendClient);
     let quota = ResourceQuota::new(Some("NetsimGrpcServerQuota")).resize_memory(1024 * 1024);
-    let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);
+    let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota).reuse_port(false);
     let mut server_builder = ServerBuilder::new(env);
     if !no_cli_ui {
         server_builder = server_builder.register_service(frontend_service);
diff --git a/rust/daemon/src/http_server/server_response.rs b/rust/daemon/src/http_server/server_response.rs
index 020f265b..19a06db5 100644
--- a/rust/daemon/src/http_server/server_response.rs
+++ b/rust/daemon/src/http_server/server_response.rs
@@ -49,7 +49,7 @@ pub struct ServerResponseWriter<'a> {
     response: Option<Response<Vec<u8>>>,
 }
 
-impl<'a> ServerResponseWriter<'a> {
+impl ServerResponseWriter<'_> {
     pub fn new<W: Write>(writer: &mut W) -> ServerResponseWriter {
         ServerResponseWriter { writer, response: None }
     }
diff --git a/rust/daemon/src/lib.rs b/rust/daemon/src/lib.rs
index a2129f3b..5e94a8ff 100644
--- a/rust/daemon/src/lib.rs
+++ b/rust/daemon/src/lib.rs
@@ -14,6 +14,16 @@
 
 //! Netsim daemon libraries.
 
+use std::sync::OnceLock;
+use tokio::runtime::{Handle, Runtime};
+
+static RUNTIME: OnceLock<Runtime> = OnceLock::new();
+
+/// Retrieves a handle to a shared, lazily initialized Tokio runtime.
+pub fn get_runtime() -> Handle {
+    RUNTIME.get_or_init(|| Runtime::new().unwrap()).handle().clone()
+}
+
 mod args;
 mod bluetooth;
 pub mod captures;
diff --git a/rust/daemon/src/openssl/sha.rs b/rust/daemon/src/openssl/sha.rs
index b2254a24..eaf61fb4 100644
--- a/rust/daemon/src/openssl/sha.rs
+++ b/rust/daemon/src/openssl/sha.rs
@@ -19,7 +19,9 @@ extern "C" {
     fn SHA1(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar;
 }
 
+/// FFI to C SHA1 utility for websocket accept
 pub fn sha1(data: &[u8]) -> [u8; 20] {
+    // Safety: data is valid bytes
     unsafe {
         let mut hash = MaybeUninit::<[u8; 20]>::uninit();
         SHA1(data.as_ptr(), data.len(), hash.as_mut_ptr() as *mut _);
diff --git a/rust/daemon/src/ranging.rs b/rust/daemon/src/ranging.rs
index 18bc6f75..80c460bf 100644
--- a/rust/daemon/src/ranging.rs
+++ b/rust/daemon/src/ranging.rs
@@ -14,6 +14,8 @@
 
 //! Ranging library
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use glam::{EulerRot, Quat, Vec3};
 
 /// The Free Space Path Loss (FSPL) model is considered as the standard
diff --git a/rust/daemon/src/rust_main.rs b/rust/daemon/src/rust_main.rs
index be32ee78..fdbcc190 100644
--- a/rust/daemon/src/rust_main.rs
+++ b/rust/daemon/src/rust_main.rs
@@ -14,24 +14,23 @@
 
 use clap::Parser;
 use grpcio::{ChannelBuilder, Deadline, EnvBuilder};
-use log::warn;
-use log::{error, info};
+use log::{error, info, warn};
 use netsim_common::system::netsimd_temp_dir;
+use netsim_common::util::ini_file::{create_ini, get_server_address, remove_ini};
 use netsim_common::util::os_utils::{
-    get_hci_port, get_instance, get_instance_name, get_server_address, redirect_std_stream,
-    remove_netsim_ini,
+    get_hci_port, get_instance, get_instance_name, redirect_std_stream,
 };
 use netsim_common::util::zip_artifact::zip_artifacts;
 use netsim_proto::frontend_grpc::FrontendServiceClient;
 
 use crate::captures::capture::spawn_capture_event_subscriber;
 use crate::config_file;
-use crate::devices::devices_handler::spawn_shutdown_publisher;
-use crate::events;
-use crate::events::{Event, ShutDown};
+use crate::devices::devices_handler::{spawn_shutdown_publisher, DeviceManager};
+use crate::events::{Event, Events, ShutDown};
 use crate::session::Session;
 use crate::version::get_version;
 use crate::wireless;
+
 use netsim_common::util::netsim_logger;
 
 use crate::args::NetsimdArgs;
@@ -260,6 +259,26 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
             http_proxy;
     }
 
+    // Create all Event Receivers before any events are posted
+    let events = Events::new();
+    let capture_events_rx = events.subscribe();
+    let device_events_rx = events.subscribe();
+    let main_events_rx = events.subscribe();
+    let session_events_rx = events.subscribe();
+
+    DeviceManager::init(events.clone());
+
+    // Start radio facades
+    wireless::bluetooth::bluetooth_start(&config.bluetooth, instance_num);
+    wireless::wifi_manager::wifi_start(
+        &config.wifi,
+        args.forward_host_mdns,
+        args.wifi,
+        args.wifi_tap,
+    );
+    wireless::uwb::uwb_start();
+
+    // Instantiate ServiceParams
     let service_params = ServiceParams::new(
         fd_startup_str,
         args.no_cli_ui,
@@ -273,13 +292,48 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     // SAFETY: The caller guaranteed that the file descriptors in `fd_startup_str` would remain
     // valid and open for as long as the program runs.
     let mut service = unsafe { Service::new(service_params) };
-    service.set_up();
 
-    // Create all Event Receivers
-    let capture_events_rx = events::subscribe();
-    let device_events_rx = events::subscribe();
-    let main_events_rx = events::subscribe();
-    let session_events_rx = events::subscribe();
+    // Run all netsimd services (grpc, socket, web)
+    match service.run() {
+        Err(e) => {
+            error!("service.run() -> Err({e:?})");
+            return;
+        }
+        Ok((grpc_port, web_port)) => {
+            // If create_ini fails, check if there is another netsimd instance.
+            // If there isn't another netsimd instance, remove_ini and create_ini once more.
+            for _ in 0..2 {
+                if let Err(e) = create_ini(instance_num, grpc_port, web_port) {
+                    warn!("create_ini error with {e:?}");
+                    // Continue if the address overlaps to support Oxygen CF Boot.
+                    // The pre-warmed device may leave stale netsim ini with the same grpc port.
+                    if let Some(address) = get_server_address(instance_num) {
+                        // If the address matches, break the loop and continue running netsimd.
+                        if address == format!("localhost:{grpc_port}") {
+                            info!("Reusing existing netsim ini with grpc_port: {grpc_port}");
+                            break;
+                        }
+                    }
+                    // Checkes if a different netsimd instance exists
+                    if is_netsimd_alive(instance_num) {
+                        warn!("netsimd already running, exiting...");
+                        service.shut_down();
+                        return;
+                    } else {
+                        info!("Removing stale netsim ini");
+                        if let Err(e) = remove_ini(instance_num) {
+                            error!("{e:?}");
+                        }
+                    }
+                } else {
+                    break;
+                }
+            }
+        }
+    }
+
+    // Gets rid of old artifacts (pcap and zip files)
+    service.remove_artifacts();
 
     // Start Session Event listener
     let mut session = Session::new();
@@ -290,23 +344,15 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     spawn_capture_event_subscriber(capture_events_rx, capture);
 
     if !args.no_shutdown {
-        spawn_shutdown_publisher(device_events_rx);
+        spawn_shutdown_publisher(device_events_rx, events);
     }
 
-    // Start radio facades
-    wireless::bluetooth::bluetooth_start(&config.bluetooth, instance_num);
-    wireless::wifi::wifi_start(&config.wifi, args.forward_host_mdns);
-    wireless::uwb::uwb_start();
-
     // Create test beacons if required
     if config.bluetooth.test_beacons == Some(true) {
         new_test_beacon(1, 1000);
         new_test_beacon(2, 1000);
     }
 
-    // Run all netsimd services (grpc, socket, web)
-    service.run();
-
     // Runs a synchronous main loop
     main_loop(main_events_rx);
 
@@ -322,19 +368,34 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     }
 
     // Once shutdown is complete, delete the netsim ini file
-    remove_netsim_ini(instance_num);
+    match remove_ini(instance_num) {
+        Ok(_) => info!("Removed netsim ini file"),
+        Err(e) => error!("Failed to remove netsim ini file: {e:?}"),
+    }
 }
 
 fn is_netsimd_alive(instance_num: u16) -> bool {
-    match get_server_address(instance_num) {
-        Some(address) => {
-            // Check if grpc server has started
-            let channel = ChannelBuilder::new(std::sync::Arc::new(EnvBuilder::new().build()))
-                .connect(&address);
-            let client = FrontendServiceClient::new(channel);
-            let deadline = Deadline::from(std::time::Duration::from_secs(1));
-            futures::executor::block_on(client.client.channel().wait_for_connected(deadline))
+    for i in 0..2 {
+        match get_server_address(instance_num) {
+            Some(address) => {
+                // Check if grpc server has started
+                let channel = ChannelBuilder::new(std::sync::Arc::new(EnvBuilder::new().build()))
+                    .connect(&address);
+                let client = FrontendServiceClient::new(channel);
+                let deadline = Deadline::from(std::time::Duration::from_secs(1));
+                return futures::executor::block_on(
+                    client.client.channel().wait_for_connected(deadline),
+                );
+            }
+            None => {
+                if i == 1 {
+                    warn!("get_server_address({instance_num}) returned None.");
+                    break;
+                }
+                info!("get_server_address({instance_num}) returned None. Retrying...");
+                std::thread::sleep(std::time::Duration::from_secs(1));
+            }
         }
-        None => false,
     }
+    false
 }
diff --git a/rust/daemon/src/service.rs b/rust/daemon/src/service.rs
index 3d95d80c..9d418ffb 100644
--- a/rust/daemon/src/service.rs
+++ b/rust/daemon/src/service.rs
@@ -12,20 +12,23 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use crate::bluetooth::advertise_settings as ble_advertise_settings;
 use crate::captures::captures_handler::clear_pcap_files;
 use crate::http_server::server::run_http_server;
 use crate::transport::socket::run_socket_transport;
 use crate::wireless;
 use log::{error, info, warn};
-use netsim_common::util::ini_file::IniFile;
-use netsim_common::util::os_utils::get_netsim_ini_filepath;
 use netsim_common::util::zip_artifact::remove_zip_files;
 use std::env;
 use std::time::Duration;
 
 /// Module to control startup, run, and cleanup netsimd services.
 
+type GrpcPort = u32;
+type WebPort = Option<u16>;
+
 pub struct ServiceParams {
     fd_startup_str: String,
     no_cli_ui: bool,
@@ -66,8 +69,8 @@ impl Service {
         Service { service_params, grpc_server: None }
     }
 
-    /// Sets up the states for netsimd.
-    pub fn set_up(&self) {
+    /// Remove old artifacts
+    pub fn remove_artifacts(&self) {
         // Clear all zip files
         match remove_zip_files() {
             Ok(()) => info!("netsim generated zip files in temp directory has been removed."),
@@ -108,22 +111,9 @@ impl Service {
         }
     }
 
-    /// Write ports to netsim.ini file
-    fn write_ports_to_ini(&self, grpc_port: u32, web_port: Option<u16>) {
-        let filepath = get_netsim_ini_filepath(self.service_params.instance_num);
-        let mut ini_file = IniFile::new(filepath);
-        if let Some(num) = web_port {
-            ini_file.insert("web.port", &num.to_string());
-        }
-        ini_file.insert("grpc.port", &grpc_port.to_string());
-        if let Err(err) = ini_file.write() {
-            error!("{err:?}");
-        }
-    }
-
     /// Runs the netsimd services.
     #[allow(unused_unsafe)]
-    pub fn run(&mut self) {
+    pub fn run(&mut self) -> anyhow::Result<(GrpcPort, WebPort)> {
         if !self.service_params.fd_startup_str.is_empty() {
             // SAFETY: When the `Service` was constructed by `Service::new` the caller guaranteed
             // that the file descriptors in `service_params.fd_startup_str` would remain valid and
@@ -138,18 +128,17 @@ impl Service {
             Ok(port) => port,
             Err(e) => {
                 error!("Failed to run netsimd: {e:?}");
-                return;
+                return Err(e);
             }
         };
 
         // Run frontend web server
         let web_port = self.run_web_server();
 
-        // Write the port numbers to ini file
-        self.write_ports_to_ini(grpc_port, web_port);
-
         // Run the socket server.
         run_socket_transport(self.service_params.hci_port);
+
+        Ok((grpc_port, web_port))
     }
 
     /// Shut down the netsimd services
@@ -157,7 +146,7 @@ impl Service {
         // TODO: shutdown other services in Rust
         self.grpc_server.as_mut().map(|server| server.shutdown());
         wireless::bluetooth::bluetooth_stop();
-        wireless::wifi::wifi_stop();
+        wireless::wifi_manager::wifi_stop();
     }
 }
 
diff --git a/rust/daemon/src/session.rs b/rust/daemon/src/session.rs
index 280ca244..1c06f74e 100644
--- a/rust/daemon/src/session.rs
+++ b/rust/daemon/src/session.rs
@@ -210,12 +210,10 @@ mod tests {
     use super::*;
     use crate::devices::chip::ChipIdentifier;
     use crate::devices::device::DeviceIdentifier;
-    use crate::events;
     use crate::events::{ChipAdded, ChipRemoved, DeviceRemoved, Event, Events, ShutDown};
     use netsim_proto::stats::{
         NetsimDeviceStats as ProtoDeviceStats, NetsimRadioStats as ProtoRadioStats,
     };
-    use std::sync::Mutex;
 
     const TEST_DEVICE_KIND: &str = "TEST_DEVICE";
 
@@ -233,10 +231,10 @@ mod tests {
         assert_eq!(lock.stats_proto.radio_stats.len(), 0);
     }
 
-    fn setup_session_start_test() -> (Session, Arc<Mutex<Events>>) {
+    fn setup_session_start_test() -> (Session, Arc<Events>) {
         let mut session = Session::new_internal(false);
-        let mut events = events::test::new();
-        let events_rx = events::test::subscribe(&mut events);
+        let events = Events::new();
+        let events_rx = events.subscribe();
         session.start(events_rx);
         (session, events)
     }
@@ -247,16 +245,13 @@ mod tests {
 
     #[test]
     fn test_start_and_shutdown() {
-        let (mut session, mut events) = setup_session_start_test();
+        let (mut session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // publish the shutdown afterwards to cause the separate thread to stop
-        events::test::publish(
-            &mut events,
-            Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }),
-        );
+        events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // join the handle
         session.handle.take().map(JoinHandle::join);
@@ -274,16 +269,13 @@ mod tests {
 
     #[test]
     fn test_start_and_stop() {
-        let (session, mut events) = setup_session_start_test();
+        let (session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // publish the shutdown which is required when using `session.stop()`
-        events::test::publish(
-            &mut events,
-            Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }),
-        );
+        events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // should not panic or deadlock
         session.stop().unwrap();
@@ -292,30 +284,24 @@ mod tests {
     // Tests for session.rs involving devices
     #[test]
     fn test_start_and_device_add() {
-        let (mut session, mut events) = setup_session_start_test();
+        let (mut session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // Create a device, publishing DeviceAdded event
-        events::test::publish(
-            &mut events,
-            Event::DeviceAdded(DeviceAdded {
-                builtin: false,
-                id: DeviceIdentifier(1),
-                device_stats: ProtoDeviceStats {
-                    kind: Some(TEST_DEVICE_KIND.to_string()),
-                    ..Default::default()
-                },
+        events.publish(Event::DeviceAdded(DeviceAdded {
+            builtin: false,
+            id: DeviceIdentifier(1),
+            device_stats: ProtoDeviceStats {
+                kind: Some(TEST_DEVICE_KIND.to_string()),
                 ..Default::default()
-            }),
-        );
+            },
+            ..Default::default()
+        }));
 
         // publish the shutdown afterwards to cause the separate thread to stop
-        events::test::publish(
-            &mut events,
-            Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }),
-        );
+        events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // join the handle
         session.handle.take().map(JoinHandle::join);
@@ -337,62 +323,47 @@ mod tests {
 
     #[test]
     fn test_start_and_device_add_and_remove() {
-        let (mut session, mut events) = setup_session_start_test();
+        let (mut session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // Create a device, publishing DeviceAdded event
-        events::test::publish(
-            &mut events,
-            Event::DeviceAdded(DeviceAdded {
-                builtin: false,
-                id: DeviceIdentifier(1),
-                device_stats: ProtoDeviceStats {
-                    kind: Some(TEST_DEVICE_KIND.to_string()),
-                    ..Default::default()
-                },
+        events.publish(Event::DeviceAdded(DeviceAdded {
+            builtin: false,
+            id: DeviceIdentifier(1),
+            device_stats: ProtoDeviceStats {
+                kind: Some(TEST_DEVICE_KIND.to_string()),
                 ..Default::default()
-            }),
-        );
+            },
+            ..Default::default()
+        }));
 
-        events::test::publish(
-            &mut events,
-            Event::DeviceRemoved(DeviceRemoved {
-                builtin: false,
-                id: DeviceIdentifier(1),
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::DeviceRemoved(DeviceRemoved {
+            builtin: false,
+            id: DeviceIdentifier(1),
+            ..Default::default()
+        }));
 
         // Create another device, publishing DeviceAdded event
-        events::test::publish(
-            &mut events,
-            Event::DeviceAdded(DeviceAdded {
-                builtin: false,
-                id: DeviceIdentifier(2),
-                device_stats: ProtoDeviceStats {
-                    kind: Some(TEST_DEVICE_KIND.to_string()),
-                    ..Default::default()
-                },
+        events.publish(Event::DeviceAdded(DeviceAdded {
+            builtin: false,
+            id: DeviceIdentifier(2),
+            device_stats: ProtoDeviceStats {
+                kind: Some(TEST_DEVICE_KIND.to_string()),
                 ..Default::default()
-            }),
-        );
+            },
+            ..Default::default()
+        }));
 
-        events::test::publish(
-            &mut events,
-            Event::DeviceRemoved(DeviceRemoved {
-                builtin: false,
-                id: DeviceIdentifier(2),
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::DeviceRemoved(DeviceRemoved {
+            builtin: false,
+            id: DeviceIdentifier(2),
+            ..Default::default()
+        }));
 
         // publish the shutdown afterwards to cause the separate thread to stop
-        events::test::publish(
-            &mut events,
-            Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }),
-        );
+        events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // join the handle
         session.handle.take().map(JoinHandle::join);
@@ -414,39 +385,30 @@ mod tests {
 
     #[test]
     fn test_start_and_chip_add_and_remove() {
-        let (mut session, mut events) = setup_session_start_test();
+        let (mut session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
         std::thread::sleep(std::time::Duration::from_secs(1));
 
-        events::test::publish(
-            &mut events,
-            Event::ChipAdded(ChipAdded {
-                builtin: false,
-                chip_id: ChipIdentifier(0),
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipAdded(ChipAdded {
+            builtin: false,
+            chip_id: ChipIdentifier(0),
+            ..Default::default()
+        }));
 
         std::thread::sleep(std::time::Duration::from_secs(1));
 
         // no radio stats until after we remove the chip
         assert_eq!(get_stats_proto(&session).radio_stats.len(), 0usize);
 
-        events::test::publish(
-            &mut events,
-            Event::ChipRemoved(ChipRemoved {
-                chip_id: ChipIdentifier(0),
-                radio_stats: vec![ProtoRadioStats { ..Default::default() }],
-                ..Default::default()
-            }),
-        );
+        events.publish(Event::ChipRemoved(ChipRemoved {
+            chip_id: ChipIdentifier(0),
+            radio_stats: vec![ProtoRadioStats { ..Default::default() }],
+            ..Default::default()
+        }));
 
         // publish the shutdown afterwards to cause the separate thread to stop
-        events::test::publish(
-            &mut events,
-            Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }),
-        );
+        events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // join the handle
         session.handle.take().map(JoinHandle::join);
diff --git a/rust/daemon/src/transport/fd.rs b/rust/daemon/src/transport/fd.rs
index 3a189fc7..06fed7c4 100644
--- a/rust/daemon/src/transport/fd.rs
+++ b/rust/daemon/src/transport/fd.rs
@@ -156,7 +156,7 @@ pub unsafe fn run_fd_transport(startup_json: &String) {
                         bt_properties: Some(chip.bt_properties.clone()),
                     })
                 }
-                ChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi::CreateParams {}),
+                ChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi_chip::CreateParams {}),
                 ChipKind::UWB => wireless::CreateParam::Uwb(wireless::uwb::CreateParams {
                     address: chip.address.clone(),
                 }),
diff --git a/rust/daemon/src/transport/socket.rs b/rust/daemon/src/transport/socket.rs
index a9f18e9f..9e9be494 100644
--- a/rust/daemon/src/transport/socket.rs
+++ b/rust/daemon/src/transport/socket.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use super::h4::PacketError;
 use crate::devices::chip::{self, ChipIdentifier};
 use crate::devices::devices_handler::{add_chip, remove_chip};
diff --git a/rust/daemon/src/transport/uci.rs b/rust/daemon/src/transport/uci.rs
index 6220531c..646e919b 100644
--- a/rust/daemon/src/transport/uci.rs
+++ b/rust/daemon/src/transport/uci.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use bytes::Bytes;
 
 use std::io::{Error, Read};
diff --git a/rust/daemon/src/version.rs b/rust/daemon/src/version.rs
index 4cb2384d..a4ec2b2c 100644
--- a/rust/daemon/src/version.rs
+++ b/rust/daemon/src/version.rs
@@ -12,9 +12,11 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 /// Version library.
 
-pub const VERSION: &str = "0.3.37";
+pub const VERSION: &str = "0.3.50";
 
 pub fn get_version() -> String {
     VERSION.to_owned()
diff --git a/rust/daemon/src/wifi/hostapd.rs b/rust/daemon/src/wifi/hostapd.rs
index f2e3f76d..822cfc71 100644
--- a/rust/daemon/src/wifi/hostapd.rs
+++ b/rust/daemon/src/wifi/hostapd.rs
@@ -17,12 +17,21 @@ use bytes::Bytes;
 pub use hostapd_rs::hostapd::Hostapd;
 use netsim_common::util::os_utils::get_discovery_directory;
 use netsim_proto::config::HostapdOptions as ProtoHostapdOptions;
-use std::sync::mpsc;
+use tokio::sync::mpsc;
 
-pub fn hostapd_run(_opt: ProtoHostapdOptions, tx: mpsc::Sender<Bytes>) -> anyhow::Result<Hostapd> {
+pub async fn hostapd_run(
+    _opt: ProtoHostapdOptions,
+    tx: mpsc::Sender<Bytes>,
+    wifi_args: Option<Vec<String>>,
+) -> anyhow::Result<Hostapd> {
     // Create hostapd.conf under discovery directory
     let config_path = get_discovery_directory().join("hostapd.conf");
     let mut hostapd = Hostapd::new(tx, true, config_path);
-    hostapd.run();
+    if let Some(wifi_values) = wifi_args {
+        let ssid = &wifi_values[0];
+        let password = wifi_values.get(1).cloned().unwrap_or_default();
+        hostapd.set_ssid(ssid, password).await?;
+    }
+    hostapd.run().await;
     Ok(hostapd)
 }
diff --git a/rust/daemon/src/wifi/hostapd_cf.rs b/rust/daemon/src/wifi/hostapd_cf.rs
index 9036a4a5..92e40dea 100644
--- a/rust/daemon/src/wifi/hostapd_cf.rs
+++ b/rust/daemon/src/wifi/hostapd_cf.rs
@@ -16,12 +16,12 @@
 use bytes::Bytes;
 use netsim_packets::ieee80211::{Ieee80211, MacAddress};
 use netsim_proto::config::HostapdOptions as ProtoHostapdOptions;
-use std::sync::mpsc;
+use tokio::sync::mpsc;
 
 // Provides a stub implementation while the hostapd-rs crate is not integrated into the aosp-main.
 pub struct Hostapd {}
 impl Hostapd {
-    pub fn input(&self, _bytes: Bytes) -> anyhow::Result<()> {
+    pub async fn input(&self, _bytes: Bytes) -> anyhow::Result<()> {
         Ok(())
     }
 
@@ -41,6 +41,10 @@ impl Hostapd {
     }
 }
 
-pub fn hostapd_run(_opt: ProtoHostapdOptions, _tx: mpsc::Sender<Bytes>) -> anyhow::Result<Hostapd> {
+pub async fn hostapd_run(
+    _opt: ProtoHostapdOptions,
+    _tx: mpsc::Sender<Bytes>,
+    _wifi_args: Option<Vec<String>>,
+) -> anyhow::Result<Hostapd> {
     Ok(Hostapd {})
 }
diff --git a/rust/daemon/src/wifi/hwsim_attr_set.rs b/rust/daemon/src/wifi/hwsim_attr_set.rs
index d7c8b3e0..d0575130 100644
--- a/rust/daemon/src/wifi/hwsim_attr_set.rs
+++ b/rust/daemon/src/wifi/hwsim_attr_set.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use std::fmt;
 
 use anyhow::{anyhow, Context};
diff --git a/rust/daemon/src/wifi/libslirp.rs b/rust/daemon/src/wifi/libslirp.rs
index e4211033..a25a8bc6 100644
--- a/rust/daemon/src/wifi/libslirp.rs
+++ b/rust/daemon/src/wifi/libslirp.rs
@@ -13,6 +13,8 @@
 // limitations under the License.
 
 /// LibSlirp Interface for Network Simulation
+use crate::get_runtime;
+
 use bytes::Bytes;
 use http_proxy::Manager;
 pub use libslirp_rs::libslirp::LibSlirp;
@@ -20,7 +22,6 @@ use libslirp_rs::libslirp::ProxyManager;
 use libslirp_rs::libslirp_config::{lookup_host_dns, SlirpConfig};
 use netsim_proto::config::SlirpOptions as ProtoSlirpOptions;
 use std::sync::mpsc;
-use tokio::runtime::Runtime;
 
 pub fn slirp_run(
     opt: ProtoSlirpOptions,
@@ -28,18 +29,22 @@ pub fn slirp_run(
 ) -> anyhow::Result<LibSlirp> {
     // TODO: Convert ProtoSlirpOptions to SlirpConfig.
     let http_proxy = Some(opt.http_proxy).filter(|s| !s.is_empty());
-    let proxy_manager = if let Some(proxy) = http_proxy {
-        Some(Box::new(Manager::new(&proxy)?) as Box<dyn ProxyManager + 'static>)
+    let (proxy_manager, tx_proxy_bytes) = if let Some(proxy) = http_proxy {
+        let (tx_proxy_bytes, rx_proxy_response) = mpsc::channel::<Bytes>();
+        (
+            Some(Box::new(Manager::new(&proxy, rx_proxy_response)?)
+                as Box<dyn ProxyManager + 'static>),
+            Some(tx_proxy_bytes),
+        )
     } else {
-        None
+        (None, None)
     };
 
     let mut config = SlirpConfig { http_proxy_on: proxy_manager.is_some(), ..Default::default() };
 
     if !opt.host_dns.is_empty() {
-        let rt = Runtime::new().unwrap();
-        config.host_dns = rt.block_on(lookup_host_dns(&opt.host_dns))?;
+        config.host_dns = get_runtime().block_on(lookup_host_dns(&opt.host_dns))?;
     }
 
-    Ok(LibSlirp::new(config, tx_bytes, proxy_manager))
+    Ok(LibSlirp::new(config, tx_bytes, proxy_manager, tx_proxy_bytes))
 }
diff --git a/rust/daemon/src/wifi/mdns_forwarder.rs b/rust/daemon/src/wifi/mdns_forwarder.rs
index 939d3abc..d158c7d8 100644
--- a/rust/daemon/src/wifi/mdns_forwarder.rs
+++ b/rust/daemon/src/wifi/mdns_forwarder.rs
@@ -233,7 +233,7 @@ pub fn run_mdns_forwarder(tx: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
     let socket = new_socket(addr.into(), false)?;
 
     // Typical max mDNS packet size
-    let mut buf: [MaybeUninit<u8>; 1500] = [MaybeUninit::new(0 as u8); 1500];
+    let mut buf: [MaybeUninit<u8>; 1500] = [MaybeUninit::new(0_u8); 1500];
     loop {
         let (size, src_addr) = socket.recv_from(&mut buf[..])?;
         // SAFETY: `recv_from` implementation promises not to write uninitialized bytes to `buf`.
diff --git a/rust/daemon/src/wifi/medium.rs b/rust/daemon/src/wifi/medium.rs
index 546387bb..69472f0f 100644
--- a/rust/daemon/src/wifi/medium.rs
+++ b/rust/daemon/src/wifi/medium.rs
@@ -59,20 +59,6 @@ impl Processor {
     }
 }
 
-#[allow(dead_code)]
-#[derive(Debug)]
-pub enum HwsimCmdEnum {
-    Unspec,
-    Register,
-    Frame(Box<Frame>),
-    TxInfoFrame,
-    NewRadio,
-    DelRadio,
-    GetRadio,
-    AddMacAddr,
-    DelMacAddr,
-}
-
 #[derive(Clone)]
 struct Station {
     client_id: u32,
@@ -278,7 +264,13 @@ impl Medium {
             } else if ieee80211.is_to_ap() {
                 // Don't forward Null Data frames to slirp because they are used to maintain an active connection and carry no user data.
                 if ieee80211.stype() != DataSubType::Nodata.into() {
-                    processor.network = true;
+                    processor.network = if self.enabled(client_id).unwrap() {
+                        true
+                    } else {
+                        // If the client is disabled, block all packets to the internet so it can connect to the AP but has no internet access.
+                        let destination = ieee80211.get_destination();
+                        destination.is_multicast() || destination == self.hostapd.get_bssid()
+                    };
                 }
             }
         } else {
@@ -466,7 +458,10 @@ impl Medium {
         source: &Station,
         destination: &Station,
     ) -> anyhow::Result<()> {
-        if self.enabled(source.client_id)? && self.enabled(destination.client_id)? {
+        if source.client_id != destination.client_id
+            && self.enabled(source.client_id)?
+            && self.enabled(destination.client_id)?
+        {
             if let Some(packet) = self.create_hwsim_msg(frame, ieee80211, &destination.hwsim_addr) {
                 self.incr_rx(destination.client_id)?;
                 (self.callback)(destination.client_id, &packet.encode_to_vec()?.into());
@@ -638,19 +633,6 @@ fn build_tx_info(hwsim_msg: &HwsimMsg) -> anyhow::Result<HwsimMsg> {
     Ok(new_hwsim_msg)
 }
 
-// It's used by radiotap.rs for packet capture.
-pub fn parse_hwsim_cmd(packet: &[u8]) -> anyhow::Result<HwsimCmdEnum> {
-    let hwsim_msg = HwsimMsg::decode_full(packet)?;
-    match hwsim_msg.hwsim_hdr.hwsim_cmd {
-        HwsimCmd::Frame => {
-            let frame = Frame::parse(&hwsim_msg)?;
-            Ok(HwsimCmdEnum::Frame(Box::new(frame)))
-        }
-        HwsimCmd::TxInfoFrame => Ok(HwsimCmdEnum::TxInfoFrame),
-        _ => Err(anyhow!("Unknown HwsimMsg cmd={:?}", hwsim_msg.hwsim_hdr.hwsim_cmd)),
-    }
-}
-
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -714,8 +696,8 @@ mod tests {
         );
     }
 
-    #[test]
-    fn test_remove() {
+    #[tokio::test]
+    async fn test_remove() {
         let test_client_id: u32 = 1234;
         let other_client_id: u32 = 5678;
         let addr: MacAddress = parse_mac_address("00:0b:85:71:20:00").unwrap();
@@ -724,8 +706,9 @@ mod tests {
         let other_hwsim_addr: MacAddress = parse_mac_address("00:0b:85:71:20:cf").unwrap();
 
         let hostapd_options = netsim_proto::config::HostapdOptions::new();
-        let (tx, _rx) = std::sync::mpsc::channel();
-        let hostapd = Arc::new(hostapd::hostapd_run(hostapd_options, tx).unwrap());
+        let (tx, _rx) = tokio::sync::mpsc::channel(100);
+        let hostapd_result = hostapd::hostapd_run(hostapd_options, tx, None).await;
+        let hostapd = Arc::new(hostapd_result.expect("hostapd_run failed"));
 
         // Create a test Medium object
         let callback: HwsimCmdCallback = |_, _| {};
@@ -767,27 +750,6 @@ mod tests {
         assert!(medium.contains_client(other_client_id));
     }
 
-    #[test]
-    fn test_netlink_attr() {
-        let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame.csv");
-        assert!(parse_hwsim_cmd(&packet).is_ok());
-
-        let tx_info_packet: Vec<u8> = include!("test_packets/hwsim_cmd_tx_info.csv");
-        assert!(parse_hwsim_cmd(&tx_info_packet).is_ok());
-    }
-
-    #[test]
-    fn test_netlink_attr_response_packet() {
-        // Response packet may not contain transmitter, flags, tx_info, or cookie fields.
-        let response_packet: Vec<u8> =
-            include!("test_packets/hwsim_cmd_frame_response_no_transmitter_flags_tx_info.csv");
-        assert!(parse_hwsim_cmd(&response_packet).is_ok());
-
-        let response_packet2: Vec<u8> =
-            include!("test_packets/hwsim_cmd_frame_response_no_cookie.csv");
-        assert!(parse_hwsim_cmd(&response_packet2).is_ok());
-    }
-
     #[test]
     fn test_is_mdns_packet() {
         let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame_mdns.csv");
diff --git a/rust/daemon/src/wifi/radiotap.rs b/rust/daemon/src/wifi/radiotap.rs
index b909055d..30b6b6ec 100644
--- a/rust/daemon/src/wifi/radiotap.rs
+++ b/rust/daemon/src/wifi/radiotap.rs
@@ -19,9 +19,10 @@
 ///
 /// See https://www.radiotap.org/
 use crate::wifi::frame::Frame;
-use crate::wifi::medium;
-use crate::wifi::medium::HwsimCmdEnum;
+use anyhow::anyhow;
 use log::info;
+use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg};
+use pdl_runtime::Packet;
 
 #[repr(C, packed)]
 struct RadiotapHeader {
@@ -39,8 +40,34 @@ struct ChannelInfo {
     flags: u16,
 }
 
+#[allow(dead_code)]
+#[derive(Debug)]
+enum HwsimCmdEnum {
+    Unspec,
+    Register,
+    Frame(Box<Frame>),
+    TxInfoFrame,
+    NewRadio,
+    DelRadio,
+    GetRadio,
+    AddMacAddr,
+    DelMacAddr,
+}
+
+fn parse_hwsim_cmd(packet: &[u8]) -> anyhow::Result<HwsimCmdEnum> {
+    let hwsim_msg = HwsimMsg::decode_full(packet)?;
+    match hwsim_msg.hwsim_hdr.hwsim_cmd {
+        HwsimCmd::Frame => {
+            let frame = Frame::parse(&hwsim_msg)?;
+            Ok(HwsimCmdEnum::Frame(Box::new(frame)))
+        }
+        HwsimCmd::TxInfoFrame => Ok(HwsimCmdEnum::TxInfoFrame),
+        _ => Err(anyhow!("Unknown HwsimMsg cmd={:?}", hwsim_msg.hwsim_hdr.hwsim_cmd)),
+    }
+}
+
 pub fn into_pcap(packet: &[u8]) -> Option<Vec<u8>> {
-    match medium::parse_hwsim_cmd(packet) {
+    match parse_hwsim_cmd(packet) {
         Ok(HwsimCmdEnum::Frame(frame)) => frame_into_pcap(*frame).ok(),
         Ok(_) => None,
         Err(e) => {
@@ -77,3 +104,23 @@ pub fn frame_into_pcap(frame: Frame) -> anyhow::Result<Vec<u8>> {
 
     Ok(buffer)
 }
+
+#[test]
+fn test_netlink_attr() {
+    let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame.csv");
+    assert!(parse_hwsim_cmd(&packet).is_ok());
+
+    let tx_info_packet: Vec<u8> = include!("test_packets/hwsim_cmd_tx_info.csv");
+    assert!(parse_hwsim_cmd(&tx_info_packet).is_ok());
+}
+
+#[test]
+fn test_netlink_attr_response_packet() {
+    // Response packet may not contain transmitter, flags, tx_info, or cookie fields.
+    let response_packet: Vec<u8> =
+        include!("test_packets/hwsim_cmd_frame_response_no_transmitter_flags_tx_info.csv");
+    assert!(parse_hwsim_cmd(&response_packet).is_ok());
+
+    let response_packet2: Vec<u8> = include!("test_packets/hwsim_cmd_frame_response_no_cookie.csv");
+    assert!(parse_hwsim_cmd(&response_packet2).is_ok());
+}
diff --git a/rust/daemon/src/wireless/ble_beacon.rs b/rust/daemon/src/wireless/ble_beacon.rs
index cdf23b37..d45a2f66 100644
--- a/rust/daemon/src/wireless/ble_beacon.rs
+++ b/rust/daemon/src/wireless/ble_beacon.rs
@@ -14,7 +14,7 @@
 
 use crate::bluetooth::{ble_beacon_add, ble_beacon_get, ble_beacon_patch, ble_beacon_remove};
 use crate::devices::chip::{ChipIdentifier, FacadeIdentifier};
-use crate::wireless::{WirelessAdaptor, WirelessAdaptorImpl};
+use crate::wireless::{WirelessChip, WirelessChipImpl};
 
 use bytes::Bytes;
 use log::{error, info};
@@ -45,7 +45,7 @@ impl Drop for BleBeacon {
     }
 }
 
-impl WirelessAdaptor for BleBeacon {
+impl WirelessChip for BleBeacon {
     fn handle_request(&self, packet: &Bytes) {
         #[cfg(not(test))]
         ffi_bluetooth::handle_bt_request(self.facade_id.0, packet[0], &packet[1..].to_vec());
@@ -89,12 +89,10 @@ impl WirelessAdaptor for BleBeacon {
 }
 
 /// Create a new Emulated BleBeacon Chip
-pub fn new(params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
+pub fn add_chip(params: &CreateParams, chip_id: ChipIdentifier) -> WirelessChipImpl {
     match ble_beacon_add(params.device_name.clone(), chip_id, &params.chip_proto) {
         Ok(facade_id) => {
-            info!(
-                "BleBeacon WirelessAdaptor created with facade_id: {facade_id} chip_id: {chip_id}"
-            );
+            info!("BleBeacon WirelessChip created with facade_id: {facade_id} chip_id: {chip_id}");
             Box::new(BleBeacon { facade_id, chip_id })
         }
         Err(err) => {
diff --git a/rust/daemon/src/wireless/bluetooth.rs b/rust/daemon/src/wireless/bluetooth.rs
index cb1bf645..f51f7cc8 100644
--- a/rust/daemon/src/wireless/bluetooth.rs
+++ b/rust/daemon/src/wireless/bluetooth.rs
@@ -14,7 +14,7 @@
 
 use crate::devices::chip::ChipIdentifier;
 use crate::ffi::ffi_bluetooth;
-use crate::wireless::{WirelessAdaptor, WirelessAdaptorImpl};
+use crate::wireless::{WirelessChip, WirelessChipImpl};
 
 use bytes::Bytes;
 use cxx::{let_cxx_string, CxxString, CxxVector};
@@ -89,7 +89,7 @@ impl Drop for Bluetooth {
     }
 }
 
-impl WirelessAdaptor for Bluetooth {
+impl WirelessChip for Bluetooth {
     fn handle_request(&self, packet: &Bytes) {
         // Lock to protect device_to_transport_ table in C++
         let _guard = WIRELESS_BT_MUTEX.lock().expect("Failed to acquire lock on WIRELESS_BT_MUTEX");
@@ -172,7 +172,7 @@ impl WirelessAdaptor for Bluetooth {
 /// Create a new Emulated Bluetooth Chip
 /// allow(dead_code) due to not being used in unit tests
 #[allow(dead_code)]
-pub fn new(create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
+pub fn add_chip(create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessChipImpl {
     // Lock to protect id_to_chip_info_ table in C++
     let _guard = WIRELESS_BT_MUTEX.lock().expect("Failed to acquire lock on WIRELESS_BT_MUTEX");
     let_cxx_string!(cxx_address = create_params.address.clone());
@@ -181,8 +181,8 @@ pub fn new(create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAda
         None => Vec::new(),
     };
     let rootcanal_id = ffi_bluetooth::bluetooth_add(chip_id.0, &cxx_address, &proto_bytes);
-    info!("Bluetooth WirelessAdaptor created with rootcanal_id: {rootcanal_id} chip_id: {chip_id}");
-    let wireless_adaptor = Bluetooth {
+    info!("Bluetooth WirelessChip created with rootcanal_id: {rootcanal_id} chip_id: {chip_id}");
+    let wireless_chip = Bluetooth {
         rootcanal_id,
         low_energy_enabled: AtomicBool::new(true),
         classic_enabled: AtomicBool::new(true),
@@ -191,7 +191,7 @@ pub fn new(create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAda
         .lock()
         .expect("invalid packets")
         .insert(rootcanal_id, Vec::new());
-    Box::new(wireless_adaptor)
+    Box::new(wireless_chip)
 }
 
 /// Starts the Bluetooth service.
@@ -229,7 +229,7 @@ pub fn report_invalid_packet(
                 // Log the report
                 info!("Invalid Packet for rootcanal_id: {rootcanal_id}, reason: {reason:?}, description: {description:?}, packet: {packet:?}");
             }
-            None => error!("Bluetooth WirelessAdaptor not created for rootcanal_id: {rootcanal_id}"),
+            None => error!("Bluetooth WirelessChip not created for rootcanal_id: {rootcanal_id}"),
         }
     });
 }
diff --git a/rust/daemon/src/wireless/mocked.rs b/rust/daemon/src/wireless/mocked.rs
index aaa76e00..d2c75200 100644
--- a/rust/daemon/src/wireless/mocked.rs
+++ b/rust/daemon/src/wireless/mocked.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use crate::devices::chip::ChipIdentifier;
-use crate::wireless::{WirelessAdaptor, WirelessAdaptorImpl};
+use crate::wireless::{WirelessChip, WirelessChipImpl};
 
 use bytes::Bytes;
 use netsim_proto::common::ChipKind as ProtoChipKind;
@@ -31,7 +31,7 @@ pub struct Mock {
     chip_kind: ProtoChipKind,
 }
 
-impl WirelessAdaptor for Mock {
+impl WirelessChip for Mock {
     fn handle_request(&self, _packet: &Bytes) {}
 
     fn reset(&self) {}
@@ -58,6 +58,6 @@ impl WirelessAdaptor for Mock {
 }
 
 /// Create a new MockedChip
-pub fn new(create_params: &CreateParams, _chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
+pub fn add_chip(create_params: &CreateParams, _chip_id: ChipIdentifier) -> WirelessChipImpl {
     Box::new(Mock { chip_kind: create_params.chip_kind })
 }
diff --git a/rust/daemon/src/wireless/mod.rs b/rust/daemon/src/wireless/mod.rs
index 26d33b7e..aaec9c85 100644
--- a/rust/daemon/src/wireless/mod.rs
+++ b/rust/daemon/src/wireless/mod.rs
@@ -17,11 +17,12 @@ pub mod bluetooth;
 pub mod mocked;
 pub mod packet;
 pub mod uwb;
-pub mod wifi;
-pub mod wireless_adaptor;
+pub mod wifi_chip;
+pub mod wifi_manager;
+pub mod wireless_chip;
+pub mod wireless_manager;
 
 pub use crate::wireless::packet::{handle_request, handle_request_cxx, handle_response_cxx};
-pub use crate::wireless::wireless_adaptor::new;
-pub use crate::wireless::wireless_adaptor::CreateParam;
-pub use crate::wireless::wireless_adaptor::WirelessAdaptor;
-pub use crate::wireless::wireless_adaptor::WirelessAdaptorImpl;
+pub use crate::wireless::wireless_chip::WirelessChip;
+pub use crate::wireless::wireless_chip::WirelessChipImpl;
+pub use crate::wireless::wireless_manager::{add_chip, CreateParam};
diff --git a/rust/daemon/src/wireless/packet.rs b/rust/daemon/src/wireless/packet.rs
index ebe30963..4205d934 100644
--- a/rust/daemon/src/wireless/packet.rs
+++ b/rust/daemon/src/wireless/packet.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+#![allow(clippy::empty_line_after_doc_comments)]
+
 use std::collections::HashMap;
 use std::sync::mpsc::{channel, Sender};
 use std::sync::{OnceLock, RwLock};
@@ -155,8 +157,8 @@ pub fn handle_request(chip_id: ChipIdentifier, packet: &Bytes, packet_type: u8)
 
     // Perform handle_request
     match chip::get_chip(&chip_id) {
-        Some(c) => c.wireless_adaptor.handle_request(&Bytes::from(packet_vec)),
-        None => warn!("SharedWirelessAdaptor doesn't exist for chip_id: {chip_id}"),
+        Some(c) => c.wireless_chip.handle_request(&Bytes::from(packet_vec)),
+        None => warn!("SharedWirelessChip doesn't exist for chip_id: {chip_id}"),
     }
 }
 
diff --git a/rust/daemon/src/wireless/uwb.rs b/rust/daemon/src/wireless/uwb.rs
index 5ea0da3d..1be2c732 100644
--- a/rust/daemon/src/wireless/uwb.rs
+++ b/rust/daemon/src/wireless/uwb.rs
@@ -21,6 +21,7 @@ use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::stats::{netsim_radio_stats, NetsimRadioStats as ProtoRadioStats};
 
 use crate::devices::chip::ChipIdentifier;
+use crate::get_runtime;
 use crate::uwb::ranging_estimator::{SharedState, UwbRangingEstimator};
 use crate::wireless::packet::handle_response;
 
@@ -28,9 +29,9 @@ use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
 use std::sync::{Arc, Mutex, OnceLock};
 use std::thread;
 
-use super::{WirelessAdaptor, WirelessAdaptorImpl};
+use super::{WirelessChip, WirelessChipImpl};
 
-// TODO(b/331267949): Construct Manager struct for each wireless_adaptor module
+// TODO(b/331267949): Construct Manager struct for each wireless_chip module
 static PICA_HANDLE_TO_STATE: OnceLock<SharedState> = OnceLock::new();
 
 fn get_pica_handle_to_state() -> &'static SharedState {
@@ -49,12 +50,6 @@ fn get_pica() -> Arc<Mutex<Pica>> {
     .clone()
 }
 
-static PICA_RUNTIME: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();
-
-fn get_pica_runtime() -> Arc<tokio::runtime::Runtime> {
-    PICA_RUNTIME.get_or_init(|| Arc::new(tokio::runtime::Runtime::new().unwrap())).clone()
-}
-
 /// Parameters for creating UWB chips
 pub struct CreateParams {
     #[allow(dead_code)]
@@ -76,7 +71,7 @@ impl Drop for Uwb {
     }
 }
 
-impl WirelessAdaptor for Uwb {
+impl WirelessChip for Uwb {
     fn handle_request(&self, packet: &Bytes) {
         // TODO(b/330788870): Increment tx_count
         self.uci_stream_writer
@@ -129,15 +124,15 @@ pub fn uwb_start() {
     // TODO: Provide TcpStream as UWB connector
     let _ = thread::Builder::new().name("pica_service".to_string()).spawn(move || {
         log::info!("PICA STARTED");
-        let _guard = get_pica_runtime().enter();
+        let _guard = get_runtime().enter();
         futures::executor::block_on(pica::run(&get_pica()))
     });
 }
 
-pub fn new(_create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
+pub fn add_chip(_create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessChipImpl {
     let (uci_stream_sender, uci_stream_receiver) = futures::channel::mpsc::unbounded();
     let (uci_sink_sender, uci_sink_receiver) = futures::channel::mpsc::unbounded();
-    let _guard = get_pica_runtime().enter();
+    let _guard = get_runtime().enter();
     let pica_id = get_pica()
         .lock()
         .unwrap()
@@ -155,7 +150,7 @@ pub fn new(_create_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAd
     };
 
     // Spawn a future for obtaining packet from pica and invoking handle_response_rust
-    get_pica_runtime().spawn(async move {
+    get_runtime().spawn(async move {
         let mut uci_sink_receiver = uci_sink_receiver;
         while let Some(packet) = uci_sink_receiver.next().await {
             handle_response(chip_id, &Bytes::from(packet));
@@ -170,8 +165,8 @@ mod tests {
 
     use super::*;
 
-    fn new_uwb_wireless_adaptor() -> WirelessAdaptorImpl {
-        new(&CreateParams { address: "test".to_string() }, ChipIdentifier(0))
+    fn add_uwb_wireless_chip() -> WirelessChipImpl {
+        add_chip(&CreateParams { address: "test".to_string() }, ChipIdentifier(0))
     }
 
     fn patch_chip_proto() -> ProtoChip {
@@ -183,19 +178,19 @@ mod tests {
 
     #[test]
     fn test_uwb_get() {
-        let wireless_adaptor = new_uwb_wireless_adaptor();
-        assert!(wireless_adaptor.get().has_uwb());
+        let wireless_chip = add_uwb_wireless_chip();
+        assert!(wireless_chip.get().has_uwb());
     }
 
     #[test]
     fn test_uwb_patch_and_reset() {
-        let wireless_adaptor = new_uwb_wireless_adaptor();
-        wireless_adaptor.patch(&patch_chip_proto());
-        let binding = wireless_adaptor.get();
+        let wireless_chip = add_uwb_wireless_chip();
+        wireless_chip.patch(&patch_chip_proto());
+        let binding = wireless_chip.get();
         let radio = binding.uwb();
         assert_eq!(radio.state, Some(false));
-        wireless_adaptor.reset();
-        let binding = wireless_adaptor.get();
+        wireless_chip.reset();
+        let binding = wireless_chip.get();
         let radio = binding.uwb();
         assert_eq!(radio.rx_count, 0);
         assert_eq!(radio.tx_count, 0);
@@ -204,8 +199,8 @@ mod tests {
 
     #[test]
     fn test_get_stats() {
-        let wireless_adaptor = new_uwb_wireless_adaptor();
-        let radio_stat_vec = wireless_adaptor.get_stats(0);
+        let wireless_chip = add_uwb_wireless_chip();
+        let radio_stat_vec = wireless_chip.get_stats(0);
         let radio_stat = radio_stat_vec.first().unwrap();
         assert_eq!(radio_stat.kind(), netsim_radio_stats::Kind::UWB);
         assert_eq!(radio_stat.duration_secs(), 0);
diff --git a/rust/daemon/src/wireless/wifi.rs b/rust/daemon/src/wireless/wifi.rs
deleted file mode 100644
index e423e8cd..00000000
--- a/rust/daemon/src/wireless/wifi.rs
+++ /dev/null
@@ -1,292 +0,0 @@
-// Copyright 2023 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-use crate::devices::chip::ChipIdentifier;
-use crate::wifi::hostapd;
-use crate::wifi::libslirp;
-#[cfg(not(feature = "cuttlefish"))]
-use crate::wifi::mdns_forwarder;
-use crate::wifi::medium::Medium;
-use crate::wireless::{packet::handle_response, WirelessAdaptor, WirelessAdaptorImpl};
-use anyhow;
-use bytes::Bytes;
-use log::{info, warn};
-use netsim_proto::config::WiFi as WiFiConfig;
-use netsim_proto::model::Chip as ProtoChip;
-use netsim_proto::stats::{netsim_radio_stats, NetsimRadioStats as ProtoRadioStats};
-use protobuf::MessageField;
-use std::sync::atomic::Ordering;
-use std::sync::{mpsc, Arc, OnceLock};
-use std::thread;
-use std::time::{Duration, Instant};
-
-/// Parameters for creating Wifi chips
-/// allow(dead_code) due to not being used in unit tests
-#[allow(dead_code)]
-pub struct CreateParams {}
-
-/// Wifi struct will keep track of chip_id
-pub struct Wifi {
-    chip_id: ChipIdentifier,
-}
-
-pub struct WifiManager {
-    medium: Medium,
-    tx_request: mpsc::Sender<(u32, Bytes)>,
-    slirp: libslirp::LibSlirp,
-    hostapd: Arc<hostapd::Hostapd>,
-}
-
-impl WifiManager {
-    pub fn new(
-        tx_request: mpsc::Sender<(u32, Bytes)>,
-        slirp: libslirp::LibSlirp,
-        hostapd: hostapd::Hostapd,
-    ) -> WifiManager {
-        let hostapd = Arc::new(hostapd);
-        WifiManager {
-            medium: Medium::new(medium_callback, hostapd.clone()),
-            tx_request,
-            slirp,
-            hostapd,
-        }
-    }
-
-    /// Starts background threads:
-    /// * One to handle requests from medium.
-    /// * One to handle IEEE802.3 responses from network.
-    /// * One to handle IEEE802.11 responses from hostapd.
-    pub fn start(
-        &self,
-        rx_request: mpsc::Receiver<(u32, Bytes)>,
-        rx_ieee8023_response: mpsc::Receiver<Bytes>,
-        rx_ieee80211_response: mpsc::Receiver<Bytes>,
-        tx_ieee8023_response: mpsc::Sender<Bytes>,
-        forward_host_mdns: bool,
-    ) -> anyhow::Result<()> {
-        self.start_request_thread(rx_request)?;
-        self.start_ieee8023_response_thread(rx_ieee8023_response)?;
-        self.start_ieee80211_response_thread(rx_ieee80211_response)?;
-        if forward_host_mdns {
-            self.start_mdns_forwarder_thread(tx_ieee8023_response)?;
-        }
-        Ok(())
-    }
-
-    fn start_request_thread(&self, rx_request: mpsc::Receiver<(u32, Bytes)>) -> anyhow::Result<()> {
-        thread::Builder::new().name("Wi-Fi HwsimMsg request".to_string()).spawn(move || {
-            const POLL_INTERVAL: Duration = Duration::from_millis(1);
-            let mut next_instant = Instant::now() + POLL_INTERVAL;
-
-            loop {
-                let this_instant = Instant::now();
-                let timeout = if next_instant > this_instant {
-                    next_instant - this_instant
-                } else {
-                    Duration::ZERO
-                };
-                match rx_request.recv_timeout(timeout) {
-                    Ok((chip_id, packet)) => {
-                        if let Some(processor) =
-                            get_wifi_manager().medium.get_processor(chip_id, &packet)
-                        {
-                            get_wifi_manager().medium.ack_frame(chip_id, &processor.frame);
-                            if processor.hostapd {
-                                let ieee80211: Bytes = processor.get_ieee80211_bytes();
-                                if let Err(err) = get_wifi_manager().hostapd.input(ieee80211) {
-                                    warn!("Failed to call hostapd input: {:?}", err);
-                                };
-                            }
-                            if processor.network {
-                                match processor.get_ieee80211().to_ieee8023() {
-                                    Ok(ethernet_frame) => {
-                                        get_wifi_manager().slirp.input(ethernet_frame.into())
-                                    }
-                                    Err(err) => {
-                                        warn!("Failed to convert 802.11 to 802.3: {}", err)
-                                    }
-                                }
-                            }
-                            if processor.wmedium {
-                                // Decrypt the frame using the sender's key and re-encrypt it using the receiver's key for peer-to-peer communication through hostapd (broadcast or unicast).
-                                let ieee80211 = processor.get_ieee80211().clone();
-                                get_wifi_manager().medium.queue_frame(processor.frame, ieee80211);
-                            }
-                        }
-                    }
-                    _ => {
-                        next_instant = Instant::now() + POLL_INTERVAL;
-                    }
-                };
-            }
-        })?;
-        Ok(())
-    }
-
-    /// Starts a dedicated thread to process IEEE 802.3 (Ethernet) responses from the network.
-    ///
-    /// This thread continuously receives IEEE 802.3 response packets from the `rx_ieee8023_response` channel
-    /// and forwards them to the Wi-Fi manager's medium.
-    fn start_ieee8023_response_thread(
-        &self,
-        rx_ieee8023_response: mpsc::Receiver<Bytes>,
-    ) -> anyhow::Result<()> {
-        thread::Builder::new().name("Wi-Fi IEEE802.3 response".to_string()).spawn(move || {
-            for packet in rx_ieee8023_response {
-                get_wifi_manager().medium.process_ieee8023_response(&packet);
-            }
-        })?;
-        Ok(())
-    }
-
-    /// Starts a dedicated thread to process IEEE 802.11 responses from hostapd.
-    ///
-    /// This thread continuously receives IEEE 802.11 response packets from the hostapd response channel
-    /// and forwards them to the Wi-Fi manager's medium.
-    fn start_ieee80211_response_thread(
-        &self,
-        rx_ieee80211_response: mpsc::Receiver<Bytes>,
-    ) -> anyhow::Result<()> {
-        thread::Builder::new().name("Wi-Fi IEEE802.11 response".to_string()).spawn(move || {
-            for packet in rx_ieee80211_response {
-                get_wifi_manager().medium.process_ieee80211_response(&packet);
-            }
-        })?;
-        Ok(())
-    }
-
-    #[cfg(feature = "cuttlefish")]
-    fn start_mdns_forwarder_thread(
-        &self,
-        _tx_ieee8023_response: mpsc::Sender<Bytes>,
-    ) -> anyhow::Result<()> {
-        Ok(())
-    }
-
-    #[cfg(not(feature = "cuttlefish"))]
-    fn start_mdns_forwarder_thread(
-        &self,
-        tx_ieee8023_response: mpsc::Sender<Bytes>,
-    ) -> anyhow::Result<()> {
-        info!("Start mDNS forwarder thread");
-        thread::Builder::new().name("Wi-Fi mDNS forwarder".to_string()).spawn(move || {
-            if let Err(e) = mdns_forwarder::run_mdns_forwarder(tx_ieee8023_response) {
-                warn!("Failed to start mDNS forwarder: {}", e);
-            }
-        })?;
-        Ok(())
-    }
-}
-
-// Allocator for chip identifiers.
-static WIFI_MANAGER: OnceLock<WifiManager> = OnceLock::new();
-
-fn get_wifi_manager() -> &'static WifiManager {
-    WIFI_MANAGER.get().expect("WifiManager not initialized")
-}
-
-impl Drop for Wifi {
-    fn drop(&mut self) {
-        get_wifi_manager().medium.remove(self.chip_id.0);
-    }
-}
-
-impl WirelessAdaptor for Wifi {
-    fn handle_request(&self, packet: &Bytes) {
-        if let Err(e) = get_wifi_manager().tx_request.send((self.chip_id.0, packet.clone())) {
-            warn!("Failed wifi handle_request: {:?}", e);
-        }
-    }
-
-    fn reset(&self) {
-        get_wifi_manager().medium.reset(self.chip_id.0);
-    }
-
-    fn get(&self) -> ProtoChip {
-        let mut chip_proto = ProtoChip::new();
-        if let Some(client) = get_wifi_manager().medium.get(self.chip_id.0) {
-            chip_proto.mut_wifi().state = Some(client.enabled.load(Ordering::Relaxed));
-            chip_proto.mut_wifi().tx_count = client.tx_count.load(Ordering::Relaxed) as i32;
-            chip_proto.mut_wifi().rx_count = client.rx_count.load(Ordering::Relaxed) as i32;
-        }
-        chip_proto
-    }
-
-    fn patch(&self, patch: &ProtoChip) {
-        if patch.wifi().state.is_some() {
-            get_wifi_manager().medium.set_enabled(self.chip_id.0, patch.wifi().state.unwrap());
-        }
-    }
-
-    fn get_stats(&self, duration_secs: u64) -> Vec<ProtoRadioStats> {
-        let mut stats_proto = ProtoRadioStats::new();
-        stats_proto.set_duration_secs(duration_secs);
-        stats_proto.set_kind(netsim_radio_stats::Kind::WIFI);
-        let chip_proto = self.get();
-        if chip_proto.has_wifi() {
-            stats_proto.set_tx_count(chip_proto.wifi().tx_count);
-            stats_proto.set_rx_count(chip_proto.wifi().rx_count);
-        }
-        vec![stats_proto]
-    }
-}
-
-fn medium_callback(id: u32, packet: &Bytes) {
-    handle_response(ChipIdentifier(id), packet);
-}
-
-/// Create a new Emulated Wifi Chip
-/// allow(dead_code) due to not being used in unit tests
-#[allow(dead_code)]
-pub fn new(_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
-    get_wifi_manager().medium.add(chip_id.0);
-    info!("WiFi WirelessAdaptor created chip_id: {chip_id}");
-    let wifi = Wifi { chip_id };
-    Box::new(wifi)
-}
-
-/// Starts the WiFi service.
-pub fn wifi_start(config: &MessageField<WiFiConfig>, forward_host_mdns: bool) {
-    let (tx_request, rx_request) = mpsc::channel::<(u32, Bytes)>();
-    let (tx_ieee8023_response, rx_ieee8023_response) = mpsc::channel::<Bytes>();
-    let (tx_ieee80211_response, rx_ieee80211_response) = mpsc::channel::<Bytes>();
-    let tx_ieee8023_response_clone = tx_ieee8023_response.clone();
-    let wifi_config = config.clone().unwrap_or_default();
-    let slirp_opt = wifi_config.slirp_options.as_ref().unwrap_or_default().clone();
-    let slirp = libslirp::slirp_run(slirp_opt, tx_ieee8023_response_clone)
-        .map_err(|e| warn!("Failed to run libslirp. {e}"))
-        .unwrap();
-
-    let hostapd_opt = wifi_config.hostapd_options.as_ref().unwrap_or_default().clone();
-    let hostapd = hostapd::hostapd_run(hostapd_opt, tx_ieee80211_response)
-        .map_err(|e| warn!("Failed to run hostapd. {e}"))
-        .unwrap();
-
-    let _ = WIFI_MANAGER.set(WifiManager::new(tx_request, slirp, hostapd));
-
-    if let Err(e) = get_wifi_manager().start(
-        rx_request,
-        rx_ieee8023_response,
-        rx_ieee80211_response,
-        tx_ieee8023_response,
-        forward_host_mdns,
-    ) {
-        warn!("Failed to start Wi-Fi manager: {}", e);
-    }
-}
-
-/// Stops the WiFi service.
-pub fn wifi_stop() {
-    // TODO: stop hostapd
-}
diff --git a/rust/daemon/src/wireless/wifi_chip.rs b/rust/daemon/src/wireless/wifi_chip.rs
new file mode 100644
index 00000000..382bcb4a
--- /dev/null
+++ b/rust/daemon/src/wireless/wifi_chip.rs
@@ -0,0 +1,80 @@
+// Copyright 2023 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use crate::devices::chip::ChipIdentifier;
+use crate::wireless::wifi_manager::WifiManager;
+use crate::wireless::WirelessChip;
+use bytes::Bytes;
+use log::warn;
+use netsim_proto::model::Chip as ProtoChip;
+use netsim_proto::stats::{netsim_radio_stats, NetsimRadioStats as ProtoRadioStats};
+use std::sync::atomic::Ordering;
+use std::sync::Arc;
+
+/// Parameters for creating WifiChips
+/// allow(dead_code) due to not being used in unit tests
+#[allow(dead_code)]
+pub struct CreateParams {}
+
+/// WifiChip struct will keep track of chip_id
+pub struct WifiChip {
+    pub chip_id: ChipIdentifier,
+    pub wifi_manager: Arc<WifiManager>,
+}
+
+impl Drop for WifiChip {
+    fn drop(&mut self) {
+        self.wifi_manager.medium.remove(self.chip_id.0);
+    }
+}
+
+impl WirelessChip for WifiChip {
+    fn handle_request(&self, packet: &Bytes) {
+        if let Err(e) = self.wifi_manager.tx_request.send((self.chip_id.0, packet.clone())) {
+            warn!("Failed wifi handle_request: {:?}", e);
+        }
+    }
+
+    fn reset(&self) {
+        self.wifi_manager.medium.reset(self.chip_id.0);
+    }
+
+    fn get(&self) -> ProtoChip {
+        let mut chip_proto = ProtoChip::new();
+        if let Some(client) = self.wifi_manager.medium.get(self.chip_id.0) {
+            chip_proto.mut_wifi().state = Some(client.enabled.load(Ordering::Relaxed));
+            chip_proto.mut_wifi().tx_count = client.tx_count.load(Ordering::Relaxed) as i32;
+            chip_proto.mut_wifi().rx_count = client.rx_count.load(Ordering::Relaxed) as i32;
+        }
+        chip_proto
+    }
+
+    fn patch(&self, patch: &ProtoChip) {
+        if patch.wifi().state.is_some() {
+            self.wifi_manager.medium.set_enabled(self.chip_id.0, patch.wifi().state.unwrap());
+        }
+    }
+
+    fn get_stats(&self, duration_secs: u64) -> Vec<ProtoRadioStats> {
+        let mut stats_proto = ProtoRadioStats::new();
+        stats_proto.set_duration_secs(duration_secs);
+        stats_proto.set_kind(netsim_radio_stats::Kind::WIFI);
+        let chip_proto = self.get();
+        if chip_proto.has_wifi() {
+            stats_proto.set_tx_count(chip_proto.wifi().tx_count);
+            stats_proto.set_rx_count(chip_proto.wifi().rx_count);
+        }
+        vec![stats_proto]
+    }
+}
diff --git a/rust/daemon/src/wireless/wifi_manager.rs b/rust/daemon/src/wireless/wifi_manager.rs
new file mode 100644
index 00000000..386e9cae
--- /dev/null
+++ b/rust/daemon/src/wireless/wifi_manager.rs
@@ -0,0 +1,278 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use crate::devices::chip::ChipIdentifier;
+use crate::get_runtime;
+use crate::wifi::hostapd;
+use crate::wifi::libslirp;
+#[cfg(not(feature = "cuttlefish"))]
+use crate::wifi::mdns_forwarder;
+use crate::wifi::medium::Medium;
+use crate::wireless::wifi_chip::{CreateParams, WifiChip};
+use crate::wireless::{packet::handle_response, WirelessChipImpl};
+use anyhow;
+use bytes::Bytes;
+use log::{info, warn};
+use netsim_proto::config::WiFi as WiFiConfig;
+use protobuf::MessageField;
+use std::sync::{mpsc, Arc, OnceLock};
+use std::thread;
+use std::time::{Duration, Instant};
+use tokio::sync::mpsc as tokio_mpsc;
+
+/// Starts the WiFi service.
+pub fn wifi_start(
+    config: &MessageField<WiFiConfig>,
+    forward_host_mdns: bool,
+    wifi_args: Option<Vec<String>>,
+    wifi_tap: Option<String>,
+) {
+    let (tx_request, rx_request) = mpsc::channel::<(u32, Bytes)>();
+    let (tx_ieee8023_response, rx_ieee8023_response) = mpsc::channel::<Bytes>();
+    let tx_ieee8023_response_clone = tx_ieee8023_response.clone();
+    let wifi_config = config.clone().unwrap_or_default();
+
+    let network: Box<dyn Network> = if wifi_tap.is_some() {
+        todo!();
+    } else {
+        SlirpNetwork::start(config, tx_ieee8023_response_clone)
+    };
+
+    let hostapd_opt = wifi_config.hostapd_options.as_ref().unwrap_or_default().clone();
+    // Create mpsc channel with fixed channel size
+    let (tx_ieee80211_response, rx_ieee80211_response) = tokio_mpsc::channel(100);
+    // Create the hostapd instance with global runtime
+    let hostapd_result =
+        get_runtime().block_on(hostapd::hostapd_run(hostapd_opt, tx_ieee80211_response, wifi_args));
+    let hostapd = hostapd_result.map_err(|e| warn!("Failed to run hostapd. {e}")).unwrap();
+
+    let _ = WIFI_MANAGER.set(Arc::new(WifiManager::new(tx_request, network, hostapd)));
+    let wifi_manager = get_wifi_manager();
+
+    if let Err(e) = start_threads(
+        wifi_manager,
+        rx_request,
+        rx_ieee8023_response,
+        rx_ieee80211_response,
+        tx_ieee8023_response,
+        forward_host_mdns,
+    ) {
+        warn!("Failed to start Wi-Fi manager: {}", e);
+    }
+}
+
+/// Stops the WiFi service.
+pub fn wifi_stop() {
+    // TODO: stop hostapd
+}
+
+fn medium_callback(id: u32, packet: &Bytes) {
+    handle_response(ChipIdentifier(id), packet);
+}
+
+/// Network interface for sending and receiving packets to/from the internet.
+trait Network: Send + Sync {
+    /// Sends the given bytes over the network to the internet.
+    fn input(&self, bytes: Bytes);
+}
+
+/// A network implementation using libslirp.
+struct SlirpNetwork {
+    slirp: libslirp::LibSlirp,
+}
+
+impl SlirpNetwork {
+    /// Starts a new SlirpNetwork instance.
+    fn start(
+        wifi_config: &WiFiConfig,
+        tx_ieee8023_response: mpsc::Sender<Bytes>,
+    ) -> Box<dyn Network> {
+        let slirp_opt = wifi_config.slirp_options.as_ref().unwrap_or_default().clone();
+        let slirp = libslirp::slirp_run(slirp_opt, tx_ieee8023_response)
+            .map_err(|e| warn!("Failed to run libslirp. {e}"))
+            .unwrap();
+        Box::new(SlirpNetwork { slirp })
+    }
+}
+
+impl Network for SlirpNetwork {
+    fn input(&self, bytes: Bytes) {
+        self.slirp.input(bytes);
+    }
+}
+
+pub struct WifiManager {
+    pub medium: Medium,
+    pub tx_request: mpsc::Sender<(u32, Bytes)>,
+    network: Box<dyn Network>,
+    hostapd: Arc<hostapd::Hostapd>,
+}
+
+impl WifiManager {
+    fn new(
+        tx_request: mpsc::Sender<(u32, Bytes)>,
+        network: Box<dyn Network>,
+        hostapd: hostapd::Hostapd,
+    ) -> WifiManager {
+        let hostapd = Arc::new(hostapd);
+        WifiManager {
+            medium: Medium::new(medium_callback, hostapd.clone()),
+            tx_request,
+            network,
+            hostapd,
+        }
+    }
+}
+
+/// Starts background threads:
+/// * One to handle requests from medium.
+/// * One to handle IEEE802.3 responses from network.
+/// * One to handle IEEE802.11 responses from hostapd.
+fn start_threads(
+    wifi_manager: Arc<WifiManager>,
+    rx_request: mpsc::Receiver<(u32, Bytes)>,
+    rx_ieee8023_response: mpsc::Receiver<Bytes>,
+    rx_ieee80211_response: tokio_mpsc::Receiver<Bytes>,
+    tx_ieee8023_response: mpsc::Sender<Bytes>,
+    forward_host_mdns: bool,
+) -> anyhow::Result<()> {
+    start_request_thread(wifi_manager.clone(), rx_request)?;
+    start_ieee8023_response_thread(wifi_manager.clone(), rx_ieee8023_response)?;
+    start_ieee80211_response_thread(wifi_manager.clone(), rx_ieee80211_response)?;
+    if forward_host_mdns {
+        start_mdns_forwarder_thread(tx_ieee8023_response)?;
+    }
+    Ok(())
+}
+
+fn start_request_thread(
+    wifi_manager: Arc<WifiManager>,
+    rx_request: mpsc::Receiver<(u32, Bytes)>,
+) -> anyhow::Result<()> {
+    let hostapd = wifi_manager.hostapd.clone(); // Arc clone for thread
+    thread::Builder::new().name("Wi-Fi HwsimMsg request".to_string()).spawn(move || {
+        const POLL_INTERVAL: Duration = Duration::from_millis(1);
+        let mut next_instant = Instant::now() + POLL_INTERVAL;
+
+        loop {
+            let this_instant = Instant::now();
+            let timeout = if next_instant > this_instant {
+                next_instant - this_instant
+            } else {
+                Duration::ZERO
+            };
+            match rx_request.recv_timeout(timeout) {
+                Ok((chip_id, packet)) => {
+                    if let Some(processor) = wifi_manager.medium.get_processor(chip_id, &packet) {
+                        wifi_manager.medium.ack_frame(chip_id, &processor.frame);
+                        if processor.hostapd {
+                            let ieee80211: Bytes = processor.get_ieee80211_bytes();
+                            let hostapd_clone = hostapd.clone();
+                            get_runtime().block_on(async move {
+                                if let Err(err) = hostapd_clone.input(ieee80211).await {
+                                    warn!("Failed to call hostapd input: {:?}", err);
+                                };
+                            });
+                        }
+                        if processor.network {
+                            match processor.get_ieee80211().to_ieee8023() {
+                                Ok(ethernet_frame) => {
+                                    wifi_manager.network.input(ethernet_frame.into())
+                                }
+                                Err(err) => {
+                                    warn!("Failed to convert 802.11 to 802.3: {}", err)
+                                }
+                            }
+                        }
+                        if processor.wmedium {
+                            // Decrypt the frame using the sender's key and re-encrypt it using the receiver's key for peer-to-peer communication through hostapd (broadcast or unicast).
+                            let ieee80211 = processor.get_ieee80211().clone();
+                            wifi_manager.medium.queue_frame(processor.frame, ieee80211);
+                        }
+                    }
+                }
+                _ => {
+                    next_instant = Instant::now() + POLL_INTERVAL;
+                }
+            };
+        }
+    })?;
+    Ok(())
+}
+
+/// Starts a dedicated thread to process IEEE 802.3 (Ethernet) responses from the network.
+///
+/// This thread continuously receives IEEE 802.3 response packets from the `rx_ieee8023_response` channel
+/// and forwards them to the Wi-Fi manager's medium.
+fn start_ieee8023_response_thread(
+    wifi_manager: Arc<WifiManager>,
+    rx_ieee8023_response: mpsc::Receiver<Bytes>,
+) -> anyhow::Result<()> {
+    thread::Builder::new().name("Wi-Fi IEEE802.3 response".to_string()).spawn(move || {
+        for packet in rx_ieee8023_response {
+            wifi_manager.medium.process_ieee8023_response(&packet);
+        }
+    })?;
+    Ok(())
+}
+
+/// Starts a dedicated thread to process IEEE 802.11 responses from hostapd.
+///
+/// This thread continuously receives IEEE 802.11 response packets from the hostapd response channel
+/// and forwards them to the Wi-Fi manager's medium.
+fn start_ieee80211_response_thread(
+    wifi_manager: Arc<WifiManager>,
+    mut rx_ieee80211_response: tokio_mpsc::Receiver<Bytes>,
+) -> anyhow::Result<()> {
+    thread::Builder::new().name("Wi-Fi IEEE802.11 response".to_string()).spawn(move || {
+        while let Some(packet) = get_runtime().block_on(rx_ieee80211_response.recv()) {
+            wifi_manager.medium.process_ieee80211_response(&packet);
+        }
+    })?;
+    Ok(())
+}
+
+#[cfg(feature = "cuttlefish")]
+fn start_mdns_forwarder_thread(_tx_ieee8023_response: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
+    Ok(())
+}
+
+#[cfg(not(feature = "cuttlefish"))]
+fn start_mdns_forwarder_thread(tx_ieee8023_response: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
+    info!("Start mDNS forwarder thread");
+    thread::Builder::new().name("Wi-Fi mDNS forwarder".to_string()).spawn(move || {
+        if let Err(e) = mdns_forwarder::run_mdns_forwarder(tx_ieee8023_response) {
+            warn!("Failed to start mDNS forwarder: {}", e);
+        }
+    })?;
+    Ok(())
+}
+
+// Allocator for chip identifiers.
+static WIFI_MANAGER: OnceLock<Arc<WifiManager>> = OnceLock::new();
+
+fn get_wifi_manager() -> Arc<WifiManager> {
+    WIFI_MANAGER.get().expect("WifiManager not initialized").clone()
+}
+
+/// Create a new Emulated Wifi Chip
+/// allow(dead_code) due to not being used in unit tests
+#[allow(dead_code)]
+pub fn add_chip(_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessChipImpl {
+    let wifi_manager = get_wifi_manager();
+    wifi_manager.medium.add(chip_id.0);
+    info!("WiFi WirelessChip created chip_id: {chip_id}");
+    let wifi = WifiChip { wifi_manager, chip_id };
+    Box::new(wifi)
+}
diff --git a/rust/daemon/src/wireless/wireless_adaptor.rs b/rust/daemon/src/wireless/wireless_chip.rs
similarity index 60%
rename from rust/daemon/src/wireless/wireless_adaptor.rs
rename to rust/daemon/src/wireless/wireless_chip.rs
index c3297410..14bbd4b3 100644
--- a/rust/daemon/src/wireless/wireless_adaptor.rs
+++ b/rust/daemon/src/wireless/wireless_chip.rs
@@ -14,35 +14,15 @@
 
 use bytes::Bytes;
 
-use crate::{
-    devices::chip::ChipIdentifier,
-    wireless::{ble_beacon, mocked},
-};
 use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::stats::NetsimRadioStats as ProtoRadioStats;
 
-pub type WirelessAdaptorImpl = Box<dyn WirelessAdaptor + Send + Sync>;
-
-#[cfg(not(test))]
-use crate::wireless::{bluetooth, uwb, wifi};
-
-/// Parameter for each constructor of Emulated Chips
-#[allow(clippy::large_enum_variant, dead_code)]
-pub enum CreateParam {
-    BleBeacon(ble_beacon::CreateParams),
-    #[cfg(not(test))]
-    Bluetooth(bluetooth::CreateParams),
-    #[cfg(not(test))]
-    Wifi(wifi::CreateParams),
-    #[cfg(not(test))]
-    Uwb(uwb::CreateParams),
-    Mock(mocked::CreateParams),
-}
+pub type WirelessChipImpl = Box<dyn WirelessChip + Send + Sync>;
 
 // TODO: Factory trait to include start, stop, and add
-/// WirelessAdaptor is a trait that provides interface between the generic Chip
+/// WirelessChip is a trait that provides interface between the generic Chip
 /// and Radio specific library (rootcanal, libslirp, pica).
-pub trait WirelessAdaptor {
+pub trait WirelessChip {
     /// This is the main entry for incoming host-to-controller packets
     /// from virtual devices called by the transport module. The format of the
     /// packet depends on the emulated chip kind:
@@ -71,29 +51,13 @@ pub trait WirelessAdaptor {
     fn get_stats(&self, duration_secs: u64) -> Vec<ProtoRadioStats>;
 }
 
-/// This is called when the transport module receives a new packet stream
-/// connection from a virtual device.
-pub fn new(create_param: &CreateParam, chip_id: ChipIdentifier) -> WirelessAdaptorImpl {
-    // Based on create_param, construct WirelessAdaptor.
-    match create_param {
-        CreateParam::BleBeacon(params) => ble_beacon::new(params, chip_id),
-        #[cfg(not(test))]
-        CreateParam::Bluetooth(params) => bluetooth::new(params, chip_id),
-        #[cfg(not(test))]
-        CreateParam::Wifi(params) => wifi::new(params, chip_id),
-        #[cfg(not(test))]
-        CreateParam::Uwb(params) => uwb::new(params, chip_id),
-        CreateParam::Mock(params) => mocked::new(params, chip_id),
-    }
-}
-
 // TODO(b/309529194):
 // 1. Create Mock wireless adaptor, patch and get
 // 2. Create Mock wireless adptor, patch and reset
 #[cfg(test)]
 mod tests {
     #[test]
-    fn test_wireless_adaptor_new() {
+    fn test_wireless_chip_new() {
         // TODO
     }
 }
diff --git a/rust/daemon/src/wireless/wireless_manager.rs b/rust/daemon/src/wireless/wireless_manager.rs
new file mode 100644
index 00000000..32fc1f07
--- /dev/null
+++ b/rust/daemon/src/wireless/wireless_manager.rs
@@ -0,0 +1,51 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use crate::{
+    devices::chip::ChipIdentifier,
+    wireless::WirelessChipImpl,
+    wireless::{ble_beacon, mocked},
+};
+
+#[cfg(not(test))]
+use crate::wireless::{bluetooth, uwb, wifi_chip, wifi_manager};
+
+/// Parameter for each constructor of Emulated Chips
+#[allow(clippy::large_enum_variant, dead_code)]
+pub enum CreateParam {
+    BleBeacon(ble_beacon::CreateParams),
+    #[cfg(not(test))]
+    Bluetooth(bluetooth::CreateParams),
+    #[cfg(not(test))]
+    Wifi(wifi_chip::CreateParams),
+    #[cfg(not(test))]
+    Uwb(uwb::CreateParams),
+    Mock(mocked::CreateParams),
+}
+
+/// This is called when the transport module receives a new packet stream
+/// connection from a virtual device.
+pub fn add_chip(create_param: &CreateParam, chip_id: ChipIdentifier) -> WirelessChipImpl {
+    // Based on create_param, construct WirelessChip.
+    match create_param {
+        CreateParam::BleBeacon(params) => ble_beacon::add_chip(params, chip_id),
+        #[cfg(not(test))]
+        CreateParam::Bluetooth(params) => bluetooth::add_chip(params, chip_id),
+        #[cfg(not(test))]
+        CreateParam::Wifi(params) => wifi_manager::add_chip(params, chip_id),
+        #[cfg(not(test))]
+        CreateParam::Uwb(params) => uwb::add_chip(params, chip_id),
+        CreateParam::Mock(params) => mocked::add_chip(params, chip_id),
+    }
+}
diff --git a/rust/cli/build.rs b/rust/daemon/tests/integration_test.rs
similarity index 79%
rename from rust/cli/build.rs
rename to rust/daemon/tests/integration_test.rs
index 931cb4bd..30ffa40d 100644
--- a/rust/cli/build.rs
+++ b/rust/daemon/tests/integration_test.rs
@@ -1,5 +1,5 @@
 //
-//  Copyright 2023 Google, Inc.
+//  Copyright 2024 Google, Inc.
 //
 //  Licensed under the Apache License, Version 2.0 (the "License");
 //  you may not use this file except in compliance with the License.
@@ -13,7 +13,6 @@
 //  See the License for the specific language governing permissions and
 //  limitations under the License.
 
-fn main() {
-    let _build = cxx_build::bridge("src/ffi.rs");
-    println!("cargo:rerun-if-changed=src/ffi.rs");
-}
+// TODO: Write netsim daemon integration tests
+#[test]
+fn test_netsimd() {}
diff --git a/rust/frontend/Cargo.toml b/rust/frontend/Cargo.toml
deleted file mode 100644
index 9d5f308d..00000000
--- a/rust/frontend/Cargo.toml
+++ /dev/null
@@ -1,23 +0,0 @@
-[package]
-name = "frontend"
-version = "0.1.0"
-edition = "2021"
-
-[dependencies]
-protobuf = "3.2.0"
-protoc-grpcio = "3.0.0"
-protoc-rust = "2.27"
-grpcio = "0.13.0"
-grpcio-sys = "0.12.1"
-futures = "0.3.26"
-
-##[build-dependencies]
-##protoc-grpcio = "3.0.0"
-
-##[[bin]]
-##name = "server"
-##path = "src/server.rs"
-
-##[[bin]]
-##name = "netsim-grpc"
-##path = "src/client.rs"
\ No newline at end of file
diff --git a/rust/frontend/src/netsim_test_client.rs b/rust/frontend/src/netsim_test_client.rs
deleted file mode 100644
index b65d256e..00000000
--- a/rust/frontend/src/netsim_test_client.rs
+++ /dev/null
@@ -1,30 +0,0 @@
-//! netsim Rust grpc test client
-
-use std::env;
-use std::sync::Arc;
-
-use grpcio::{ChannelBuilder, EnvBuilder};
-use netsim_common::util::os_utils::get_server_address;
-use netsim_proto::frontend_grpc::FrontendServiceClient;
-
-fn main() {
-    let args: Vec<String> = env::args().collect();
-    let server_addr: String = if args.len() > 1 {
-        args[1].to_owned()
-    } else {
-        match get_server_address(1) {
-            Some(addr) => addr,
-            None => {
-                println!("Unable to get server address.");
-                return;
-            }
-        }
-    };
-    let env = Arc::new(EnvBuilder::new().build());
-
-    let ch = ChannelBuilder::new(env).connect(&server_addr);
-    let client = FrontendServiceClient::new(ch);
-
-    let reply = client.get_version(&::protobuf::well_known_types::empty::Empty::new()).unwrap();
-    println!("Version: {}", reply.version);
-}
diff --git a/rust/frontend/src/netsim_test_server.rs b/rust/frontend/src/netsim_test_server.rs
deleted file mode 100644
index 6cbf4f94..00000000
--- a/rust/frontend/src/netsim_test_server.rs
+++ /dev/null
@@ -1,117 +0,0 @@
-//! netsim Rust grpc test server
-use std::io::Read;
-use std::sync::Arc;
-use std::{io, thread};
-
-use futures::channel::oneshot;
-use futures::executor::block_on;
-use futures::prelude::*;
-use grpcio::{
-    ChannelBuilder, Environment, ResourceQuota, RpcContext, ServerBuilder, ServerCredentials,
-    UnarySink,
-};
-
-use netsim_proto::frontend::VersionResponse;
-use netsim_proto::frontend_grpc::{create_frontend_service, FrontendService};
-
-#[derive(Clone)]
-struct FrontendClient;
-
-impl FrontendService for FrontendClient {
-    fn get_version(
-        &mut self,
-        ctx: RpcContext<'_>,
-        req: protobuf::well_known_types::empty::Empty,
-        sink: UnarySink<VersionResponse>,
-    ) {
-        let response = VersionResponse {
-            version: "netsim test server version 0.0.1".to_string(),
-            ..Default::default()
-        };
-        let f = sink
-            .success(response)
-            .map_err(move |e| eprintln!("failed to reply {:?}: {:?}", req, e))
-            .map(|_| ());
-        ctx.spawn(f)
-    }
-
-    fn list_device(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: protobuf::well_known_types::empty::Empty,
-        _sink: grpcio::UnarySink<netsim_proto::frontend::ListDeviceResponse>,
-    ) {
-        todo!()
-    }
-
-    fn patch_device(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: netsim_proto::frontend::PatchDeviceRequest,
-        _sink: grpcio::UnarySink<protobuf::well_known_types::empty::Empty>,
-    ) {
-        todo!()
-    }
-
-    fn reset(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: protobuf::well_known_types::empty::Empty,
-        _sink: grpcio::UnarySink<protobuf::well_known_types::empty::Empty>,
-    ) {
-        todo!()
-    }
-
-    fn patch_capture(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: netsim_proto::frontend::PatchCaptureRequest,
-        _sink: grpcio::UnarySink<protobuf::well_known_types::empty::Empty>,
-    ) {
-        todo!()
-    }
-
-    fn list_capture(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: protobuf::well_known_types::empty::Empty,
-        _sink: grpcio::UnarySink<netsim_proto::frontend::ListCaptureResponse>,
-    ) {
-        todo!()
-    }
-
-    fn get_capture(
-        &mut self,
-        _ctx: grpcio::RpcContext,
-        _req: netsim_proto::frontend::GetCaptureRequest,
-        _sink: grpcio::ServerStreamingSink<netsim_proto::frontend::GetCaptureResponse>,
-    ) {
-        todo!()
-    }
-}
-
-fn main() {
-    let env = Arc::new(Environment::new(1));
-    let service = create_frontend_service(FrontendClient);
-
-    let quota = ResourceQuota::new(Some("HelloServerQuota")).resize_memory(1024 * 1024);
-    let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);
-
-    let mut server = ServerBuilder::new(env)
-        .register_service(service)
-        .channel_args(ch_builder.build_args())
-        .build()
-        .unwrap();
-    let port = server.add_listening_port("127.0.0.1:50051", ServerCredentials::insecure()).unwrap();
-    server.start();
-    println!("listening on port {}", port);
-
-    let (tx, rx) = oneshot::channel();
-    thread::spawn(move || {
-        println!("Press ENTER to exit...");
-        let _ = io::stdin().read(&mut [0]).unwrap();
-        tx.send(())
-    });
-    let _ = block_on(rx);
-    let _ = block_on(server.shutdown());
-}
diff --git a/rust/hostapd-rs/Cargo.toml b/rust/hostapd-rs/Cargo.toml
index 4dc16eb9..6edf1659 100644
--- a/rust/hostapd-rs/Cargo.toml
+++ b/rust/hostapd-rs/Cargo.toml
@@ -24,13 +24,15 @@ crate-type = ["staticlib","lib"]
 doctest = false
 
 [dependencies]
+aes = { version = "0.8.4"}
 anyhow = "1"
 bytes = { version = "1.4.0"}
+ccm = "0.5.0"
 log = "0.4.17"
 netsim-common = { path = "../common" }
 netsim-packets = { path = "../packets" }
 pdl-runtime = "0.3.0"
-tokio = { version = "1.32.0", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "sync"] }
+tokio = { version = "1.32.0", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }
 
 [build-dependencies]
 ##bindgen = "0.69.4"
diff --git a/rust/hostapd-rs/build.rs b/rust/hostapd-rs/build.rs
index c24ee0e6..b84835b6 100644
--- a/rust/hostapd-rs/build.rs
+++ b/rust/hostapd-rs/build.rs
@@ -12,8 +12,9 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! Build script for linking `hostapd-rs` with the `hostapd` C library and its dependencies.
+//! Build script for linking `hostapd-rs` with dependencies.
 
+/// Build script for linking `hostapd-rs` with the `hostapd` C library and OS specific dependencies.
 pub fn main() {
     let objs_path = std::env::var("OBJS_PATH").unwrap_or("../objs".to_string());
 
diff --git a/rust/hostapd-rs/src/hostapd.rs b/rust/hostapd-rs/src/hostapd.rs
index e84d9d3e..185a77d8 100644
--- a/rust/hostapd-rs/src/hostapd.rs
+++ b/rust/hostapd-rs/src/hostapd.rs
@@ -14,10 +14,10 @@
 
 //! Controller interface for the `hostapd` C library.
 //!
-//! This module allows interaction with `hostapd` to manage WiFi access point and perform various wireless networking tasks directly from Rust code.
+//! This module allows interaction with `hostapd` to manage WiFi access point and various wireless networking tasks directly from Rust code.
 //!
-//! The main `hostapd` process is managed by a separate thread while responses from the `hostapd` process are handled
-//! by another thread, ensuring efficient and non-blocking communication.
+//! The main `hostapd` process is managed by a separate task while responses from the `hostapd` process are handled
+//! by another task, ensuring efficient and non-blocking communication.
 //!
 //! `hostapd` configuration consists of key-value pairs. The default configuration file is generated in the discovery directory.
 //!
@@ -37,58 +37,66 @@
 //! ```
 //! use hostapd_rs::hostapd::Hostapd;
 //! use std::path::PathBuf;
-//! use std::sync::mpsc;
+//! use tokio::sync::mpsc;
+//! use tokio::runtime::Runtime;
 //!
-//! fn main() {
+//! let rt = Runtime::new().unwrap();
+//! rt.block_on(async {
 //!     // Create a channel for receiving data from hostapd
-//!     let (tx, _) = mpsc::channel();
+//!     let (tx, _) = mpsc::channel(100);
 //!
 //!     // Create a new Hostapd instance
 //!     let mut hostapd = Hostapd::new(
 //!         tx,                                 // Sender for receiving data
-//!         true,                               // Verbose mode (optional)
+//!         false,                              // Verbose mode
 //!         PathBuf::from("/tmp/hostapd.conf"), // Path to the configuration file
 //!     );
 //!
 //!     // Start the hostapd process
-//!     hostapd.run();
-//! }
+//!     hostapd.run().await;
+//! });
 //! ```
 //!
-//! This starts `hostapd` in a separate thread, allowing interaction with it using the `Hostapd` struct's methods.
+//! This starts `hostapd` in a separate task, allowing interaction with it using the `Hostapd` struct's methods.
 
+use aes::Aes128;
 use anyhow::bail;
 use bytes::Bytes;
-use log::{info, warn};
-use netsim_packets::ieee80211::{Ieee80211, MacAddress};
+use ccm::{
+    aead::{generic_array::GenericArray, Aead, Payload},
+    consts::{U13, U8},
+    Ccm, KeyInit,
+};
+use log::{debug, info, warn};
+use netsim_packets::ieee80211::{parse_mac_address, Ieee80211, MacAddress, CCMP_HDR_LEN};
 use std::collections::HashMap;
 use std::ffi::{c_char, c_int, CStr, CString};
-use std::fs::File;
-use std::io::{BufWriter, Write};
 use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
 #[cfg(unix)]
 use std::os::fd::IntoRawFd;
 #[cfg(windows)]
 use std::os::windows::io::IntoRawSocket;
 use std::path::PathBuf;
-use std::sync::{mpsc, Arc, RwLock};
-use std::thread::{self, sleep};
-use std::time::Duration;
-use tokio::io::{AsyncReadExt, AsyncWriteExt};
+use std::sync::atomic::{AtomicI64, Ordering};
+use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
 use tokio::net::{
     tcp::{OwnedReadHalf, OwnedWriteHalf},
     TcpListener, TcpStream,
 };
-use tokio::runtime::Runtime;
-use tokio::sync::Mutex;
+use tokio::sync::{mpsc, Mutex, RwLock};
+use tokio::task::JoinHandle;
 
 use crate::hostapd_sys::{
-    run_hostapd_main, set_virtio_ctrl_sock, set_virtio_sock, VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG,
-    VIRTIO_WIFI_CTRL_CMD_TERMINATE,
+    get_active_gtk, get_active_ptk, run_hostapd_main, set_virtio_ctrl_sock, set_virtio_sock,
+    VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG, VIRTIO_WIFI_CTRL_CMD_TERMINATE,
 };
+use std::time::Duration;
+use tokio::fs::File;
+use tokio::time::sleep;
 
 /// Alias for RawFd on Unix or RawSocket on Windows (converted to i32)
 type RawDescriptor = i32;
+type KeyData = [u8; 32];
 
 /// Hostapd process interface.
 ///
@@ -96,17 +104,17 @@ type RawDescriptor = i32;
 /// such as starting and stopping the process, configuring the access point,
 /// and sending and receiving data.
 pub struct Hostapd {
-    // TODO: update to tokio based RwLock when usages are async
-    handle: RwLock<Option<thread::JoinHandle<()>>>,
+    task_handle: RwLock<Option<JoinHandle<()>>>,
     verbose: bool,
     config: HashMap<String, String>,
     config_path: PathBuf,
     data_writer: Option<Mutex<OwnedWriteHalf>>,
     ctrl_writer: Option<Mutex<OwnedWriteHalf>>,
     tx_bytes: mpsc::Sender<Bytes>,
-    runtime: Arc<Runtime>,
     // MAC address of the access point.
     bssid: MacAddress,
+    // Current transmit packet number (PN) used for encryption
+    tx_pn: AtomicI64,
 }
 
 impl Hostapd {
@@ -120,11 +128,12 @@ impl Hostapd {
 
     pub fn new(tx_bytes: mpsc::Sender<Bytes>, verbose: bool, config_path: PathBuf) -> Self {
         // Default Hostapd conf entries
+        let bssid = "00:13:10:85:fe:01";
         let config_data = [
             ("ssid", "AndroidWifi"),
             ("interface", "wlan1"),
             ("driver", "virtio_wifi"),
-            ("bssid", "00:13:10:95:fe:0b"),
+            ("bssid", bssid),
             ("country_code", "US"),
             ("hw_mode", "g"),
             ("channel", "8"),
@@ -143,81 +152,68 @@ impl Hostapd {
         let mut config: HashMap<String, String> = HashMap::new();
         config.extend(config_data.iter().map(|(k, v)| (k.to_string(), v.to_string())));
 
-        // TODO(b/381154253): Allow configuring BSSID in hostapd.conf.
-        // Currently, the BSSID is hardcoded in external/wpa_supplicant_8/src/drivers/driver_virtio_wifi.c. This should be configured by hostapd.conf and allow to be set by `Hostapd`.
-        let bssid_bytes: [u8; 6] = [0x00, 0x13, 0x10, 0x85, 0xfe, 0x01];
-        let bssid = MacAddress::from(&bssid_bytes);
         Hostapd {
-            handle: RwLock::new(None),
+            task_handle: RwLock::new(None),
             verbose,
             config,
             config_path,
             data_writer: None,
             ctrl_writer: None,
             tx_bytes,
-            runtime: Arc::new(Runtime::new().unwrap()),
-            bssid,
+            bssid: parse_mac_address(bssid).unwrap(),
+            tx_pn: AtomicI64::new(1),
         }
     }
 
-    /// Starts the `hostapd` main process and response thread.
+    /// Starts the `hostapd` main process and response task.
     ///
-    /// The "hostapd" thread manages the C `hostapd` process by running `run_hostapd_main`.
-    /// The "hostapd_response" thread manages traffic between `hostapd` and netsim.
+    /// The "hostapd" task manages the C `hostapd` process by running `run_hostapd_main`.
+    /// The "hostapd_response" task manages traffic between `hostapd` and netsim.
     ///
-    /// TODO:
-    /// * update as async fn.
-    pub fn run(&mut self) -> bool {
+    pub async fn run(&mut self) -> bool {
+        debug!("Running hostapd with config: {:?}", &self.config);
+
         // Check if already running
-        assert!(!self.is_running(), "hostapd is already running!");
+        if self.is_running().await {
+            panic!("hostapd is already running!");
+        }
         // Setup config file
-        self.gen_config_file().unwrap_or_else(|_| {
-            panic!("Failed to generate config file: {:?}.", self.config_path.display())
-        });
+        if let Err(e) = self.gen_config_file().await {
+            panic!(
+                "Failed to generate config file: {:?}. Error: {:?}",
+                self.config_path.display(),
+                e
+            );
+        }
 
         // Setup Sockets
         let (ctrl_listener, _ctrl_reader, ctrl_writer) =
-            self.create_pipe().expect("Failed to create ctrl pipe");
+            self.create_pipe().await.expect("Failed to create ctrl pipe");
         self.ctrl_writer = Some(Mutex::new(ctrl_writer));
         let (data_listener, data_reader, data_writer) =
-            self.create_pipe().expect("Failed to create data pipe");
+            self.create_pipe().await.expect("Failed to create data pipe");
         self.data_writer = Some(Mutex::new(data_writer));
 
-        // Start hostapd thread
+        // Start hostapd task
         let verbose = self.verbose;
         let config_path = self.config_path.to_string_lossy().into_owned();
-        *self.handle.write().unwrap() = Some(
-            thread::Builder::new()
-                .name("hostapd".to_string())
-                .spawn(move || Self::hostapd_thread(verbose, config_path))
-                .expect("Failed to spawn Hostapd thread"),
-        );
+        let task_handle = tokio::spawn(async move {
+            Self::hostapd_task(verbose, config_path).await;
+        });
+        *self.task_handle.write().await = Some(task_handle);
 
-        // Start hostapd response thread
+        // Start hostapd response task
         let tx_bytes = self.tx_bytes.clone();
-        let runtime = Arc::clone(&self.runtime);
-        let _ = thread::Builder::new()
-            .name("hostapd_response".to_string())
-            .spawn(move || {
-                Self::hostapd_response_thread(
-                    data_listener,
-                    ctrl_listener,
-                    data_reader,
-                    tx_bytes,
-                    runtime,
-                );
-            })
-            .expect("Failed to spawn hostapd_response thread");
+        let _response_handle = tokio::spawn(async move {
+            Self::hostapd_response_task(data_listener, ctrl_listener, data_reader, tx_bytes).await;
+        });
+        // We don't need to store response_handle as we don't need to explicitly manage it after start.
 
         true
     }
 
     /// Reconfigures `Hostapd` with the specified SSID (and password).
-    ///
-    /// TODO:
-    /// * implement password & encryption support
-    /// * update as async fn.
-    pub fn set_ssid(
+    pub async fn set_ssid(
         &mut self,
         ssid: impl Into<String>,
         password: impl Into<String>,
@@ -228,12 +224,8 @@ impl Hostapd {
             bail!("set_ssid must have a non-empty SSID");
         }
 
-        if !password.is_empty() {
-            bail!("set_ssid with password is not yet supported.");
-        }
-
-        if ssid == self.get_ssid() && password == self.get_config_val("password") {
-            info!("SSID and password matches current configuration.");
+        if ssid == self.get_ssid() && password == self.get_config_val("wpa_passphrase") {
+            debug!("SSID and password matches current configuration.");
             return Ok(());
         }
 
@@ -250,14 +242,18 @@ impl Hostapd {
         }
 
         // Update the config file.
-        self.gen_config_file()?;
+        self.gen_config_file().await?;
 
         // Send command for Hostapd to reload config file
-        if let Err(e) = self.runtime.block_on(Self::async_write(
-            self.ctrl_writer.as_ref().unwrap(),
-            c_string_to_bytes(VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG),
-        )) {
-            bail!("Failed to send VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG to hostapd to reload config: {:?}", e);
+        if self.is_running().await {
+            if let Err(e) = Self::async_write(
+                self.ctrl_writer.as_ref().unwrap(),
+                c_string_to_bytes(VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG),
+            )
+            .await
+            {
+                bail!("Failed to send VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG to hostapd to reload config: {:?}", e);
+            }
         }
 
         Ok(())
@@ -273,60 +269,178 @@ impl Hostapd {
         self.bssid
     }
 
+    /// Generate the next packet number
+    pub fn gen_packet_number(&self) -> [u8; 6] {
+        let tx_pn = self.tx_pn.fetch_add(1, Ordering::Relaxed);
+        tx_pn.to_be_bytes()[2..].try_into().unwrap()
+    }
+
+    /// Retrieve the current active GTK or PTK key data from Hostapd
+    #[cfg(not(test))]
+    fn get_key(&self, ieee80211: &Ieee80211) -> (KeyData, usize, u8) {
+        let key = if ieee80211.is_multicast() || ieee80211.is_broadcast() {
+            // SAFETY: get_active_gtk requires no input and returns a virtio_wifi_key_data struct
+            unsafe { get_active_gtk() }
+        } else {
+            // SAFETY: get_active_ptk requires no input and returns a virtio_wifi_key_data struct
+            unsafe { get_active_ptk() }
+        };
+
+        // Return key data, length, and index from virtio_wifi_key_data
+        (key.key_material, key.key_len as usize, key.key_idx as u8)
+    }
+
     /// Attempt to encrypt the given IEEE 802.11 frame.
-    pub fn try_encrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
-        // TODO
-        None
+    pub fn try_encrypt(&self, ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        if !ieee80211.needs_encryption() {
+            return None;
+        }
+
+        // Retrieve current active key & skip encryption if key is not available
+        let (key_material, key_len, key_id) = self.get_key(ieee80211);
+        if key_len == 0 {
+            return None;
+        }
+        let key = GenericArray::from_slice(&key_material[..key_len]);
+
+        // Prep encryption parameters
+        let cipher = Ccm::<Aes128, U8, U13>::new(key);
+        let pn = self.gen_packet_number();
+        let nonce_binding = &ieee80211.get_nonce(&pn);
+        let nonce = GenericArray::from_slice(nonce_binding);
+
+        // Encryption payload offset at header length - frame control (2) - duration id (2)
+        let payload_offset = ieee80211.hdr_length() - 4;
+        // Encrypt the data with nonce and aad
+        let ciphertext = match cipher.encrypt(
+            nonce,
+            Payload { msg: &ieee80211.payload[payload_offset..], aad: &ieee80211.get_aad() },
+        ) {
+            Ok(ciphertext) => ciphertext,
+            Err(e) => {
+                warn!("Encryption error: {:?}", e);
+                return None;
+            }
+        };
+
+        // Prepare the new encrypted frame with new payload size
+        let mut encrypted_ieee80211 = ieee80211.clone();
+        encrypted_ieee80211.payload.resize(payload_offset + CCMP_HDR_LEN + ciphertext.len(), 0);
+
+        // Fill in the CCMP header using the pn and key ID
+        encrypted_ieee80211.payload[payload_offset..payload_offset + 8].copy_from_slice(&[
+            pn[5],
+            pn[4],
+            0,                    // Reserved
+            0x20 | (key_id << 6), // Key ID + Ext IV
+            pn[3],
+            pn[2],
+            pn[1],
+            pn[0],
+        ]);
+
+        // Fill in the encrypted data and set protected bit
+        encrypted_ieee80211.payload[payload_offset + CCMP_HDR_LEN..].copy_from_slice(&ciphertext);
+        encrypted_ieee80211.set_protected(true);
+
+        Some(encrypted_ieee80211)
     }
 
     /// Attempt to decrypt the given IEEE 802.11 frame.
-    pub fn try_decrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
-        // TODO
-        None
+    pub fn try_decrypt(&self, ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        if !ieee80211.needs_decryption() {
+            return None;
+        }
+
+        // Retrieve current active key, skip decryption if key is not available
+        let (key_material, key_len, _) = self.get_key(ieee80211);
+        if key_len == 0 {
+            return None;
+        }
+        let key = GenericArray::from_slice(&key_material[..key_len]);
+
+        // Prep encryption parameters
+        let cipher = Ccm::<Aes128, U8, U13>::new(key);
+        let pn = &ieee80211.get_packet_number();
+        let nonce_binding = &ieee80211.get_nonce(pn);
+        let nonce = GenericArray::from_slice(nonce_binding);
+
+        // Calculate header position and extract data and AAD
+        let hdr_pos = ieee80211.hdr_length() - 4;
+        let data = &ieee80211.payload[(hdr_pos + CCMP_HDR_LEN)..];
+        let aad = ieee80211.get_aad();
+
+        // Decrypt the data
+        let plaintext = match cipher.decrypt(nonce, Payload { msg: data, aad: &aad }) {
+            Ok(plaintext) => plaintext,
+            Err(e) => {
+                warn!("Decryption error: {:?}", e);
+                return None;
+            }
+        };
+
+        // Construct the decrypted frame
+        let mut decrypted_ieee80211 = ieee80211.clone();
+        decrypted_ieee80211.payload.truncate(hdr_pos); // Keep only the 802.11 header
+        decrypted_ieee80211.payload.extend_from_slice(&plaintext); // Append the decrypted data
+
+        // Reset protected bit
+        decrypted_ieee80211.set_protected(false);
+
+        Some(decrypted_ieee80211)
     }
 
     /// Inputs data packet bytes from netsim to `hostapd`.
-    ///
-    /// TODO:
-    /// * update as async fn.
-    pub fn input(&self, bytes: Bytes) -> anyhow::Result<()> {
+    pub async fn input(&self, bytes: Bytes) -> anyhow::Result<()> {
         // Make sure hostapd is already running
-        assert!(self.is_running(), "Failed to send input. Hostapd is not running.");
-        self.runtime.block_on(Self::async_write(self.data_writer.as_ref().unwrap(), &bytes))
+        if !self.is_running().await {
+            panic!("Failed to send input. Hostapd is not running.");
+        }
+        Self::async_write(self.data_writer.as_ref().unwrap(), &bytes).await
     }
 
-    /// Checks whether the `hostapd` thread is running.
-    pub fn is_running(&self) -> bool {
-        let handle_lock = self.handle.read().unwrap();
-        handle_lock.is_some() && !handle_lock.as_ref().unwrap().is_finished()
+    /// Checks whether the `hostapd` task is running.
+    pub async fn is_running(&self) -> bool {
+        let task_handle_lock = self.task_handle.read().await;
+        task_handle_lock.is_some() && !task_handle_lock.as_ref().unwrap().is_finished()
     }
 
-    /// Terminates the `Hostapd` process thread by sending a control command.
-    pub fn terminate(&self) {
-        if !self.is_running() {
-            warn!("hostapd terminate() called when hostapd thread is not running");
+    /// Terminates the `Hostapd` process task by sending a control command.
+    pub async fn terminate(&self) {
+        if !self.is_running().await {
+            warn!("hostapd terminate() called when hostapd task is not running");
             return;
         }
 
         // Send terminate command to hostapd
-        if let Err(e) = self.runtime.block_on(Self::async_write(
+        if let Err(e) = Self::async_write(
             self.ctrl_writer.as_ref().unwrap(),
             c_string_to_bytes(VIRTIO_WIFI_CTRL_CMD_TERMINATE),
-        )) {
+        )
+        .await
+        {
             warn!("Failed to send VIRTIO_WIFI_CTRL_CMD_TERMINATE to hostapd to terminate: {:?}", e);
         }
+        // Wait for hostapd task to finish.
+        if let Some(task_handle) = self.task_handle.write().await.take() {
+            if let Err(e) = task_handle.await {
+                warn!("Failed to join hostapd task during terminate: {:?}", e);
+            }
+        }
     }
 
     /// Generates the `hostapd.conf` file in the discovery directory.
-    fn gen_config_file(&self) -> anyhow::Result<()> {
-        let conf_file = File::create(self.config_path.clone())?; // Create or overwrite the file
+    async fn gen_config_file(&self) -> anyhow::Result<()> {
+        let conf_file = File::create(self.config_path.clone()).await?; // Create or overwrite the file
         let mut writer = BufWriter::new(conf_file);
 
         for (key, value) in &self.config {
-            writeln!(&mut writer, "{}={}", key, value)?;
+            let line = format!("{}={}\n", key, value);
+            writer.write_all(line.as_bytes()).await?;
         }
 
-        Ok(writer.flush()?) // Ensure all data is written to the file
+        writer.flush().await?; // Ensure all data is written to the file
+        Ok(())
     }
 
     /// Gets the value of the given key in the config.
@@ -345,11 +459,11 @@ impl Hostapd {
     ///
     /// * `Ok((listener, read_half, write_half))` if the pipe creation is successful.
     /// * `Err(std::io::Error)` if an error occurs during pipe creation.
-    fn create_pipe(
+    async fn create_pipe(
         &self,
     ) -> anyhow::Result<(RawDescriptor, OwnedReadHalf, OwnedWriteHalf), std::io::Error> {
-        let (listener, stream) = self.runtime.block_on(Self::async_create_pipe())?;
-        let listener = into_raw_descriptor(listener);
+        let (listener_stream, stream) = Self::async_create_pipe().await?;
+        let listener = into_raw_descriptor(listener_stream);
         let (read_half, write_half) = stream.into_split();
         Ok((listener, read_half, write_half))
     }
@@ -366,8 +480,8 @@ impl Hostapd {
         };
         let addr = listener.local_addr()?;
         let stream = TcpStream::connect(addr).await?;
-        let (listener, _) = listener.accept().await?;
-        Ok((listener, stream))
+        let (listener_stream, _) = listener.accept().await?;
+        Ok((listener_stream, stream))
     }
 
     /// Writes data to a writer asynchronously.
@@ -380,8 +494,8 @@ impl Hostapd {
 
     /// Runs the C `hostapd` process with `run_hostapd_main`.
     ///
-    /// This function is meant to be spawned in a separate thread.
-    fn hostapd_thread(verbose: bool, config_path: String) {
+    /// This function is meant to be spawned in a separate task.
+    async fn hostapd_task(verbose: bool, config_path: String) {
         let mut args = vec![CString::new("hostapd").unwrap()];
         if verbose {
             args.push(CString::new("-dddd").unwrap());
@@ -410,26 +524,25 @@ impl Hostapd {
 
     /// Manages reading `hostapd` responses and sending them via `tx_bytes`.
     ///
-    /// The thread first attempts to set virtio driver sockets with retries until success.
-    /// Next, the thread reads `hostapd` responses and writes them to netsim.
-    fn hostapd_response_thread(
-        data_listener: RawDescriptor,
-        ctrl_listener: RawDescriptor,
+    /// The task first attempts to set virtio driver sockets with retries until success.
+    /// Next, the task reads `hostapd` responses and writes them to netsim.
+    async fn hostapd_response_task(
+        data_descriptor: RawDescriptor,
+        ctrl_descriptor: RawDescriptor,
         mut data_reader: OwnedReadHalf,
         tx_bytes: mpsc::Sender<Bytes>,
-        runtime: Arc<Runtime>,
     ) {
         let mut buf: [u8; 1500] = [0u8; 1500];
         loop {
-            if !Self::set_virtio_driver_socket(data_listener, ctrl_listener) {
+            if !Self::set_virtio_driver_socket(data_descriptor, ctrl_descriptor) {
                 warn!("Unable to set virtio driver socket. Retrying...");
-                sleep(Duration::from_millis(250));
+                sleep(Duration::from_millis(250)).await;
                 continue;
             };
             break;
         }
         loop {
-            let size = match runtime.block_on(async { data_reader.read(&mut buf[..]).await }) {
+            let size = match data_reader.read(&mut buf[..]).await {
                 Ok(size) => size,
                 Err(e) => {
                     warn!("Failed to read hostapd response: {:?}", e);
@@ -437,7 +550,7 @@ impl Hostapd {
                 }
             };
 
-            if let Err(e) = tx_bytes.send(Bytes::copy_from_slice(&buf[..size])) {
+            if let Err(e) = tx_bytes.send(Bytes::copy_from_slice(&buf[..size])).await {
                 warn!("Failed to send hostapd packet response: {:?}", e);
                 break;
             };
@@ -445,13 +558,6 @@ impl Hostapd {
     }
 }
 
-impl Drop for Hostapd {
-    /// Terminates the `hostapd` process when the `Hostapd` instance is dropped.
-    fn drop(&mut self) {
-        self.terminate();
-    }
-}
-
 /// Converts a `TcpStream` to a `RawDescriptor` (i32).
 fn into_raw_descriptor(stream: TcpStream) -> RawDescriptor {
     let std_stream = stream.into_std().expect("into_raw_descriptor's into_std() failed");
@@ -471,3 +577,131 @@ fn into_raw_descriptor(stream: TcpStream) -> RawDescriptor {
 fn c_string_to_bytes(c_string: &[u8]) -> &[u8] {
     CStr::from_bytes_with_nul(c_string).unwrap().to_bytes()
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use netsim_packets::ieee80211::{parse_mac_address, FrameType, Ieee80211, Ieee80211ToAp};
+    use pdl_runtime::Packet;
+    use std::env;
+    use std::sync::OnceLock;
+    use tokio::runtime::Runtime;
+
+    /// Initializes a basic Hostapd instance for testing.
+    fn init_hostapd() -> Hostapd {
+        let (tx, _rx) = mpsc::channel(100);
+        let config_path = env::temp_dir().join("hostapd.conf");
+        Hostapd::new(tx, true, config_path)
+    }
+
+    #[tokio::test]
+    async fn test_encrypt_decrypt_generic() {
+        // Sample 802.11 data frame for encryption/decryption test.
+        let ieee80211 = Ieee80211ToAp {
+            duration_id: 0,
+            ftype: FrameType::Data,
+            stype: 0,
+            destination: parse_mac_address("2:2:2:2:2:2").unwrap(),
+            source: parse_mac_address("1:1:1:1:1:1").unwrap(),
+            bssid: parse_mac_address("0:0:0:0:0:0").unwrap(),
+            seq_ctrl: 0,
+            protected: 0,
+            order: 0,
+            more_frags: 0,
+            retry: 0,
+            pm: 0,
+            more_data: 0,
+            version: 0,
+            payload: vec![0, 1, 2, 3, 4, 5], // Example payload
+        }
+        .try_into()
+        .expect("Failed to create Ieee80211 frame");
+
+        let hostapd = init_hostapd();
+
+        // Encrypt and then decrypt the frame.
+        let encrypted_frame = hostapd.try_encrypt(&ieee80211).expect("Encryption failed");
+        let decrypted_frame = hostapd.try_decrypt(&encrypted_frame).expect("Decryption failed");
+
+        // Verify that the decrypted frame is identical to the original frame.
+        assert_eq!(
+            decrypted_frame.encode_to_bytes().unwrap(),
+            ieee80211.encode_to_bytes().unwrap(),
+            "Decrypted frame does not match original frame" // More descriptive assertion message
+        );
+    }
+
+    // Implementation block for Hostapd specific to tests.
+    impl Hostapd {
+        /// Test-specific get_key: returns a fixed key for predictable encryption/decryption.
+        pub fn get_key(&self, _ieee80211: &Ieee80211) -> (KeyData, usize, u8) {
+            let mut key = [0u8; 32];
+            const TEST_KEY: [u8; 16] = [
+                // Defined test key as const for clarity
+                202, 238, 127, 166, 61, 206, 22, 214, 17, 180, 130, 229, 4, 249, 255, 122,
+            ];
+            key[..16].copy_from_slice(&TEST_KEY);
+            (key, 16, 0)
+        }
+    }
+
+    #[tokio::test]
+    async fn test_decrypt_encrypt_golden_frame() {
+        // Test vectors from C implementation for golden frame test.
+        const ENCRYPTED_FRAME_BYTES: [u8; 120] = [
+            // Corrected array size to 120
+            8, 65, 58, 1, 0, 19, 16, 133, 254, 1, 2, 21, 178, 0, 0, 0, 51, 51, 255, 197, 140, 97,
+            192, 70, 1, 0, 0, 32, 0, 0, 0, 0, 119, 72, 195, 215, 149, 122, 79, 220, 238, 60, 113,
+            167, 129, 55, 206, 110, 94, 178, 141, 180, 240, 63, 37, 182, 166, 61, 249, 112, 74, 78,
+            132, 238, 161, 210, 196, 91, 135, 234, 60, 234, 87, 75, 245, 43, 158, 205, 127, 101,
+            66, 180, 91, 220, 148, 42, 230, 210, 117, 207, 94, 106, 241, 213, 122, 104, 231, 25,
+            185, 174, 25, 5, 197, 116, 5, 168, 53, 71, 77, 26, 77, 94, 65, 159, 97, 218, 14, 238,
+            220, 157,
+        ];
+        const EXPECTED_DECRYPTED_FRAME_BYTES: [u8; 104] = [
+            // Corrected array size to 104
+            8, 1, 58, 1, 0, 19, 16, 133, 254, 1, 2, 21, 178, 0, 0, 0, 51, 51, 255, 197, 140, 97,
+            192, 70, 170, 170, 3, 0, 0, 0, 134, 221, 96, 0, 0, 0, 0, 32, 58, 255, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 197, 140, 97,
+            135, 0, 44, 90, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 121, 29, 23, 252, 71, 197, 140,
+            97, 14, 1, 27, 50, 219, 39, 89, 3,
+        ];
+
+        // Decode the encrypted frame from bytes.
+        let encrypted_ieee80211 = Ieee80211::decode(&ENCRYPTED_FRAME_BYTES)
+            .expect("Failed to decode encrypted Ieee80211 frame")
+            .0;
+        let hostapd = init_hostapd();
+
+        // Decrypt the golden encrypted frame.
+        let decrypted_ieee80211 =
+            hostapd.try_decrypt(&encrypted_ieee80211).expect("Decryption of golden frame failed");
+
+        // Verify decryption against expected decrypted bytes.
+        assert_eq!(
+            decrypted_ieee80211.encode_to_bytes().unwrap().to_vec(), // Changed to .to_vec() for direct Vec<u8> comparison
+            EXPECTED_DECRYPTED_FRAME_BYTES.to_vec(), // Changed to .to_vec() for direct Vec<u8> comparison
+            "Decrypted golden frame does not match expected bytes" // More descriptive assertion message
+        );
+
+        // Re-encrypt the decrypted frame to verify round-trip.
+        let reencrypted_frame = hostapd
+            .try_encrypt(&decrypted_ieee80211)
+            .expect("Re-encryption of decrypted frame failed");
+        assert_eq!(
+            reencrypted_frame.encode_to_bytes().unwrap().to_vec(), // Changed to .to_vec()
+            ENCRYPTED_FRAME_BYTES.to_vec(),                        // Changed to .to_vec()
+            "Re-encrypted frame does not match original encrypted frame" // More descriptive assertion message
+        );
+
+        // Re-decrypt again to ensure consistent round-trip decryption.
+        let redecrypted_frame = hostapd
+            .try_decrypt(&reencrypted_frame)
+            .expect("Re-decryption of re-encrypted frame failed");
+        assert_eq!(
+            redecrypted_frame.encode_to_bytes().unwrap().to_vec(), // Changed to .to_vec()
+            EXPECTED_DECRYPTED_FRAME_BYTES.to_vec(),               // Changed to .to_vec()
+            "Re-decrypted frame does not match expected bytes after re-encryption" // More descriptive assertion message
+        );
+    }
+}
diff --git a/rust/hostapd-rs/src/hostapd_sys/mod.rs b/rust/hostapd-rs/src/hostapd_sys/mod.rs
index 100256d9..3ca4fb4c 100644
--- a/rust/hostapd-rs/src/hostapd_sys/mod.rs
+++ b/rust/hostapd-rs/src/hostapd_sys/mod.rs
@@ -35,15 +35,13 @@
 //! use std::ffi::CString;
 //! use hostapd_rs::hostapd_sys; // Import the module
 //!
-//! fn main() {
-//!     let mut args = vec![CString::new("hostapd").unwrap()];
-//!     args.push(CString::new("/path/to/hostapd.conf").unwrap());
-//!     // Include any other args
-//!     let argv: Vec<*const std::os::raw::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
-//!
-//!     unsafe {
-//!         hostapd_sys::run_hostapd_main(argv.len() as i32, argv.as_ptr());
-//!     }
+//! let mut args = vec![CString::new("hostapd").unwrap()];
+//! args.push(CString::new("/path/to/hostapd.conf").unwrap());
+//! // Include any other args
+//! let argv: Vec<*const std::os::raw::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
+//!
+//! unsafe {
+//!     hostapd_sys::run_hostapd_main(argv.len() as i32, argv.as_ptr());
 //! }
 //! ```
 //!
@@ -77,6 +75,8 @@
 //! # fn main() {}
 //! ```
 
+#![allow(missing_docs)]
+
 #[cfg(target_os = "linux")]
 include!("linux/bindings.rs");
 
diff --git a/rust/hostapd-rs/tests/integration_test.rs b/rust/hostapd-rs/tests/integration_test.rs
index e8c332fc..b87ce65a 100644
--- a/rust/hostapd-rs/tests/integration_test.rs
+++ b/rust/hostapd-rs/tests/integration_test.rs
@@ -21,31 +21,31 @@ use netsim_packets::ieee80211::Ieee80211;
 use pdl_runtime::Packet;
 use std::{
     env,
-    sync::mpsc,
-    thread,
     time::{Duration, Instant},
 };
-
+use tokio::runtime::Runtime;
+use tokio::sync::mpsc;
+use tokio::time::{sleep, timeout};
 /// Initializes a `Hostapd` instance for testing.
 ///
 /// Returns a tuple containing the `Hostapd` instance and a receiver for
 /// receiving data from `hostapd`.
 fn init_test_hostapd() -> (Hostapd, mpsc::Receiver<Bytes>) {
-    let (tx, rx) = mpsc::channel();
+    let (tx, rx) = mpsc::channel(100);
     let config_path = env::temp_dir().join("hostapd.conf");
     (Hostapd::new(tx, true, config_path), rx)
 }
 
 /// Waits for the `Hostapd` process to terminate.
-fn terminate_hostapd(hostapd: &Hostapd) {
-    hostapd.terminate();
+async fn terminate_hostapd(hostapd: &Hostapd) {
+    hostapd.terminate().await;
     let max_wait_time = Duration::from_secs(30);
     let start_time = Instant::now();
     while start_time.elapsed() < max_wait_time {
-        if !hostapd.is_running() {
+        if !hostapd.is_running().await {
             break;
         }
-        thread::sleep(Duration::from_millis(250));
+        sleep(Duration::from_millis(250)).await; // Using tokio::time::sleep now
     }
     warn!("Hostapd failed to terminate successfully within 30s");
 }
@@ -55,72 +55,70 @@ fn terminate_hostapd(hostapd: &Hostapd) {
 /// A single test is used to avoid conflicts when multiple `hostapd` instances
 /// run in parallel.
 ///
+/// Multi threaded tokio runtime is required for hostapd.
+///
 /// TODO: Split up tests once feasible with `serial_test` crate or other methods.
-#[test]
-fn test_hostapd() {
+#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
+async fn test_hostapd() {
     // Initialize a single Hostapd instance to share across tests to avoid >5s startup &
     // shutdown overhead for every test
-    let (mut hostapd, receiver) = init_test_hostapd();
-    test_start(&mut hostapd);
-    test_receive_beacon_frame(&receiver);
-    test_get_and_set_ssid(&mut hostapd, &receiver);
-    test_terminate(&hostapd);
+    let (mut hostapd, mut receiver) = init_test_hostapd();
+    test_start(&mut hostapd).await;
+    test_receive_beacon_frame(&mut receiver).await;
+    test_get_and_set_ssid(&mut hostapd, &mut receiver).await;
+    test_terminate(&hostapd).await;
 }
 
 /// Tests that `Hostapd` starts successfully.
-fn test_start(hostapd: &mut Hostapd) {
-    hostapd.run();
-    assert!(hostapd.is_running());
+async fn test_start(hostapd: &mut Hostapd) {
+    hostapd.run().await;
+    assert!(hostapd.is_running().await);
 }
 
 /// Tests that `Hostapd` terminates successfully.
-fn test_terminate(hostapd: &Hostapd) {
-    terminate_hostapd(&hostapd);
-    assert!(!hostapd.is_running());
+async fn test_terminate(hostapd: &Hostapd) {
+    terminate_hostapd(&hostapd).await;
+    assert!(!hostapd.is_running().await);
 }
 
 /// Tests whether a beacon frame packet is received after `Hostapd` starts up.
-fn test_receive_beacon_frame(receiver: &mpsc::Receiver<Bytes>) {
-    let end_time = Instant::now() + Duration::from_secs(10);
-    loop {
-        // Try to receive a packet before end_time
-        match receiver.recv_timeout(end_time - Instant::now()) {
-            // Parse and verify received packet is beacon frame
-            Ok(packet) if Ieee80211::decode_full(&packet).unwrap().is_beacon() => break,
-            Ok(_) => continue, // Received a non beacon packet. Continue
-            _ => assert!(false, "Did not receive beacon frame in 10s"), // Error occurred
+async fn test_receive_beacon_frame(receiver: &mut mpsc::Receiver<Bytes>) {
+    let timeout_duration = Duration::from_secs(10);
+    match timeout(timeout_duration, receiver.recv()).await {
+        // Using tokio::time::timeout
+        Ok(Some(packet)) if Ieee80211::decode_full(&packet).unwrap().is_beacon() => {}
+        Ok(Some(_)) => assert!(false, "Received a non beacon packet within timeout"),
+        Ok(None) => {
+            assert!(false, "Sender closed unexpectedly before beacon received within timeout")
         }
+        Err(_timeout_err) => assert!(false, "Did not receive beacon frame in 10s timeout"),
     }
 }
 
 /// Checks if the receiver receives a beacon frame with the specified SSID within 10 seconds.
-fn verify_beacon_frame_ssid(receiver: &mpsc::Receiver<Bytes>, ssid: &str) {
-    let end_time = Instant::now() + Duration::from_secs(10);
-    loop {
-        // Try to receive a packet before end_time
-        match receiver.recv_timeout(end_time - Instant::now()) {
-            Ok(packet) => {
-                if let Ok(beacon_ssid) =
-                    Ieee80211::decode_full(&packet).unwrap().get_ssid_from_beacon_frame()
-                {
-                    if beacon_ssid == ssid {
-                        break; // Found expected beacon frame
-                    }
+async fn verify_beacon_frame_ssid(receiver: &mut mpsc::Receiver<Bytes>, ssid: &str) {
+    let timeout_duration = Duration::from_secs(10);
+    match timeout(timeout_duration, receiver.recv()).await {
+        // Using tokio::time::timeout
+        Ok(Some(packet)) => {
+            if let Ok(beacon_ssid) =
+                Ieee80211::decode_full(&packet).unwrap().get_ssid_from_beacon_frame()
+            {
+                if beacon_ssid == ssid {
+                    return; // Found expected beacon frame
                 }
-                // Not expected beacon frame. Continue...
-            }
-            Err(mpsc::RecvTimeoutError::Timeout) => {
-                assert!(false, "No Beacon frame received within 10s");
-            }
-            Err(mpsc::RecvTimeoutError::Disconnected) => {
-                assert!(false, "Receiver disconnected while waiting for Beacon frame.");
             }
+            assert!(false, "Received non-matching beacon frame within timeout");
+        }
+        Ok(None) => {
+            assert!(false, "Sender closed before expected beacon frame received within timeout")
         }
+        Err(_timeout_err) => assert!(false, "No Beacon frame received within 10s timeout"),
     }
 }
 
 /// Tests various ways to configure `Hostapd` SSID and password.
-fn test_get_and_set_ssid(hostapd: &mut Hostapd, receiver: &mpsc::Receiver<Bytes>) {
+async fn test_get_and_set_ssid(hostapd: &mut Hostapd, receiver: &mut mpsc::Receiver<Bytes>) {
     // Check default ssid is set
     let default_ssid = "AndroidWifi";
     assert_eq!(hostapd.get_ssid(), default_ssid);
@@ -128,22 +126,29 @@ fn test_get_and_set_ssid(hostapd: &mut Hostapd, receiver: &mpsc::Receiver<Bytes>
     let mut test_ssid = String::new();
     let mut test_password = String::new();
     // Verify set_ssid fails if SSID is empty
-    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_err());
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).await.is_err());
 
     // Verify set_ssid succeeds if SSID is not empty
     test_ssid = "TestSsid".to_string();
-    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_ok());
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).await.is_ok());
     // Verify hostapd sends new beacon frame with updated SSID
-    verify_beacon_frame_ssid(receiver, &test_ssid);
+    verify_beacon_frame_ssid(receiver, &test_ssid).await;
 
     // Verify ssid was set successfully
     assert_eq!(hostapd.get_ssid(), test_ssid);
 
     // Verify setting same ssid again succeeds
-    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_ok());
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).await.is_ok());
 
-    // Verify set_ssid fails if password is not empty
-    // TODO: Update once password support is implemented
+    test_ssid = "EncryptedSsid".to_string();
     test_password = "TestPassword".to_string();
-    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_err());
+
+    // Verify set_ssid with password succeeds
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).await.is_ok());
+
+    // Verify ssid was set successfully
+    assert_eq!(hostapd.get_ssid(), test_ssid);
+
+    // Verify hostapd sends new beacon frame with updated SSID
+    verify_beacon_frame_ssid(receiver, &test_ssid).await;
 }
diff --git a/rust/http-proxy/Cargo.toml b/rust/http-proxy/Cargo.toml
index a8bef7b3..e974c608 100644
--- a/rust/http-proxy/Cargo.toml
+++ b/rust/http-proxy/Cargo.toml
@@ -24,6 +24,7 @@ doctest = false
 
 [dependencies]
 base64 = "0.22.0"
+bytes = { version = ">=1.4.0"}
 regex = "1.6.0"
 httparse = "1.8.0"
 libslirp-rs = { path = "../libslirp-rs" }
@@ -33,3 +34,7 @@ etherparse = {version = "0.16" }
 
 [dev-dependencies]
 capture = { path = "../capture" }
+
+[[bench]]
+name = "dns_benchmark"
+harness = false
diff --git a/rust/http-proxy/benches/dns_benchmark.rs b/rust/http-proxy/benches/dns_benchmark.rs
new file mode 100644
index 00000000..23c4d11e
--- /dev/null
+++ b/rust/http-proxy/benches/dns_benchmark.rs
@@ -0,0 +1,60 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use capture::pcap;
+use std::io::Cursor;
+use std::time::Instant;
+use tokio;
+use tokio::io::BufReader;
+use tokio::runtime::Runtime;
+
+async fn dns_benchmark() {
+    const DATA: &[u8] = include_bytes!("../../capture/data/dns.cap");
+
+    let mut reader = BufReader::new(Cursor::new(DATA));
+    let header = pcap::read_file_header(&mut reader).await.unwrap();
+    assert_eq!(header.linktype, pcap::LinkType::Ethernet.into());
+    let mut dns_manager = http_proxy::DnsManager::new();
+    loop {
+        match pcap::read_record(&mut reader).await {
+            Ok((_hdr, record)) => {
+                dns_manager.add_from_ethernet_slice(&record);
+            }
+            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
+                break;
+            }
+            Err(e) => {
+                println!("Error: {:?}", e);
+                assert!(false);
+            }
+        }
+    }
+}
+
+fn main() {
+    let iterations = 50_000;
+    let rt = Runtime::new().unwrap();
+    let handle = rt.handle();
+    for _ in 0..5 {
+        let time_start = Instant::now();
+        for _ in 0..iterations {
+            handle.block_on(dns_benchmark());
+        }
+        let elapsed_time = time_start.elapsed();
+        println!(
+            "** Time per iteration {}us",
+            (elapsed_time.as_micros() as f64) / (iterations as f64)
+        );
+    }
+}
diff --git a/rust/http-proxy/src/connector.rs b/rust/http-proxy/src/connector.rs
index f24a6cb7..885c46dc 100644
--- a/rust/http-proxy/src/connector.rs
+++ b/rust/http-proxy/src/connector.rs
@@ -20,6 +20,7 @@ use tokio::net::TcpStream;
 
 const HTTP_VERSION: &str = "1.1";
 
+/// A alias for `Result` where the error type is this crate's `Error`.
 pub type Result<T> = core::result::Result<T, Error>;
 
 /// Establishes a TCP connection to a target address through an HTTP proxy.
@@ -34,10 +35,12 @@ pub struct Connector {
 }
 
 impl Connector {
+    /// Creates a new `Connector` with proxy address and optional authentication details
     pub fn new(proxy_addr: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
         Connector { proxy_addr, username, password }
     }
 
+    /// Establishes a TCP connection to the given address through the proxy.
     pub async fn connect(&self, addr: SocketAddr) -> Result<TcpStream> {
         let mut stream = TcpStream::connect(self.proxy_addr).await?;
 
diff --git a/rust/http-proxy/src/dns_manager.rs b/rust/http-proxy/src/dns_manager.rs
index 773808e3..fb84d9ac 100644
--- a/rust/http-proxy/src/dns_manager.rs
+++ b/rust/http-proxy/src/dns_manager.rs
@@ -25,33 +25,44 @@
 ///
 use crate::dns;
 use etherparse::{PacketHeaders, PayloadSlice, TransportHeader};
+use log::debug;
 use std::collections::HashMap;
 use std::net::IpAddr;
+use std::sync::Mutex;
 
+/// DNS Manager of IP addresses to FQDN
 pub struct DnsManager {
-    map: HashMap<IpAddr, String>,
+    map: Mutex<HashMap<IpAddr, String>>,
+}
+
+impl Default for DnsManager {
+    fn default() -> Self {
+        Self::new()
+    }
 }
 
 impl DnsManager {
     const DNS_PORT: u16 = 53;
 
+    /// Creates a new `DnsManager`.
     pub fn new() -> Self {
-        DnsManager { map: HashMap::new() }
+        DnsManager { map: Mutex::new(HashMap::new()) }
     }
 
     /// Add potential DNS entries to the cache.
-    pub fn add_from_packet_headers(&mut self, headers: &PacketHeaders) {
+    pub fn add_from_packet_headers(&self, headers: &PacketHeaders) {
         // Check if the packet contains a UDP header
         // with source port from DNS server
         // and DNS answers with A/AAAA records
         if let Some(TransportHeader::Udp(udp_header)) = &headers.transport {
             // with source port from DNS server
             if udp_header.source_port == Self::DNS_PORT {
-                if let PayloadSlice::Udp(ref payload) = headers.payload {
+                if let PayloadSlice::Udp(payload) = headers.payload {
                     // Add any A/AAAA domain names
                     if let Ok(answers) = dns::parse_answers(payload) {
                         for (ip_addr, name) in answers {
-                            self.map.insert(ip_addr, name);
+                            self.map.lock().unwrap().insert(ip_addr, name.clone());
+                            debug!("Added {} ({}) to DNS cache", name, ip_addr);
                         }
                     }
                 }
@@ -59,17 +70,24 @@ impl DnsManager {
         }
     }
 
-    pub fn add_from_ethernet_slice(&mut self, packet: &[u8]) {
+    /// Adds potential DNS entries from an Ethernet slice.
+    pub fn add_from_ethernet_slice(&self, packet: &[u8]) {
         let headers = PacketHeaders::from_ethernet_slice(packet).unwrap();
         self.add_from_packet_headers(&headers);
     }
 
     /// Return a FQDN from a prior DNS response for ip address
     pub fn get(&self, ip_addr: &IpAddr) -> Option<String> {
-        self.map.get(ip_addr).cloned()
+        self.map.lock().unwrap().get(ip_addr).cloned()
     }
 
+    /// Returns the number of entries in the cache.
     pub fn len(&self) -> usize {
-        self.map.len()
+        self.map.lock().unwrap().len()
+    }
+
+    /// Checks if the cache is empty.
+    pub fn is_empty(&self) -> bool {
+        self.map.lock().unwrap().len() == 0
     }
 }
diff --git a/rust/http-proxy/src/error.rs b/rust/http-proxy/src/error.rs
index a16a6663..e255123c 100644
--- a/rust/http-proxy/src/error.rs
+++ b/rust/http-proxy/src/error.rs
@@ -21,10 +21,15 @@ use std::net::SocketAddr;
 /// An enumeration of possible errors.
 #[derive(Debug)]
 pub enum Error {
+    /// An I/O error occurred.
     IoError(io::Error),
+    /// An error occurred during connection establishment.
     ConnectionError(SocketAddr, String),
+    /// The configuration string was malformed.
     MalformedConfigString,
+    /// The provided port number was invalid.
     InvalidPortNumber,
+    /// The provided host was invalid.
     InvalidHost,
 }
 
diff --git a/rust/http-proxy/src/lib.rs b/rust/http-proxy/src/lib.rs
index 4e316937..df6e9b05 100644
--- a/rust/http-proxy/src/lib.rs
+++ b/rust/http-proxy/src/lib.rs
@@ -48,6 +48,7 @@
 //!
 //! * Currently only supports HTTP proxies.
 //! * Usernames and passwords cannot contain `@` or `:`.
+#![allow(dead_code)] //TODO: Remove once implementation is complete
 
 mod connector;
 mod dns;
diff --git a/rust/http-proxy/src/manager.rs b/rust/http-proxy/src/manager.rs
index f554b4a8..4b11ca96 100644
--- a/rust/http-proxy/src/manager.rs
+++ b/rust/http-proxy/src/manager.rs
@@ -13,11 +13,13 @@
 // limitations under the License.
 
 use crate::util::{into_raw_descriptor, ProxyConfig};
-use crate::{connector::Connector, error::Error};
+use crate::{Connector, DnsManager, Error};
+use bytes::Bytes;
 use libslirp_rs::libslirp::{ProxyConnect, ProxyManager};
 use log::{debug, warn};
 use std::net::SocketAddr;
-use std::sync::Arc;
+use std::sync::{mpsc, Arc};
+use std::thread;
 use tokio::runtime::Runtime;
 
 /// # Manager
@@ -57,14 +59,28 @@ use tokio::runtime::Runtime;
 pub struct Manager {
     runtime: Arc<Runtime>,
     connector: Connector,
+    dns_manager: Arc<DnsManager>,
 }
 
 impl Manager {
-    pub fn new(proxy: &str) -> Result<Self, Error> {
-        let config = ProxyConfig::from_string(&proxy)?;
+    /// Creates a new `LibSlirp` instance.
+    ///
+    /// This function initializes the libslirp library and spawns the necessary threads
+    /// for handling network traffic and polling.
+    pub fn new(proxy: &str, rx_proxy_bytes: mpsc::Receiver<Bytes>) -> Result<Self, Error> {
+        let config = ProxyConfig::from_string(proxy)?;
+        let dns_manager = Arc::new(DnsManager::new());
+        let dns_manager_clone = dns_manager.clone();
+        let _ = thread::Builder::new().name("Dns Manager".to_string()).spawn(move || {
+            while let Ok(bytes) = rx_proxy_bytes.recv() {
+                dns_manager_clone.add_from_ethernet_slice(&bytes);
+            }
+        });
+
         Ok(Self {
             runtime: Arc::new(Runtime::new()?),
             connector: Connector::new(config.addr, config.username, config.password),
+            dns_manager,
         })
     }
 }
diff --git a/rust/libslirp-rs/build.rs b/rust/libslirp-rs/build.rs
index cb7c8ed1..3962ffd9 100644
--- a/rust/libslirp-rs/build.rs
+++ b/rust/libslirp-rs/build.rs
@@ -12,6 +12,12 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! Build script for linking `libslirp-rs` with dependencies.
+
+/// The main function of the build script.
+///
+/// Configures the build process to link against `libslirp` and other
+/// OS-dependent libraries.
 pub fn main() {
     let objs_path = std::env::var("OBJS_PATH").unwrap_or("../objs".to_string());
 
diff --git a/rust/libslirp-rs/src/libslirp.rs b/rust/libslirp-rs/src/libslirp.rs
index fe99addf..6db6b3b7 100644
--- a/rust/libslirp-rs/src/libslirp.rs
+++ b/rust/libslirp-rs/src/libslirp.rs
@@ -91,7 +91,10 @@
 
 use crate::libslirp_config;
 use crate::libslirp_config::SlirpConfigs;
-use crate::libslirp_sys;
+use crate::libslirp_sys::{
+    self, SlirpPollType, SlirpProxyConnectFunc, SlirpTimerId, SLIRP_POLL_ERR, SLIRP_POLL_HUP,
+    SLIRP_POLL_IN, SLIRP_POLL_OUT, SLIRP_POLL_PRI,
+};
 
 use bytes::Bytes;
 use core::sync::atomic::{AtomicUsize, Ordering};
@@ -119,19 +122,19 @@ struct TimerManager {
 
 #[derive(Clone)]
 struct Timer {
-    id: libslirp_sys::SlirpTimerId,
+    id: SlirpTimerId,
     cb_opaque: usize,
     expire_time: u64,
 }
 
-// The operations performed on the slirp thread
+/// The operations performed on the slirp thread
 #[derive(Debug)]
 enum SlirpCmd {
     Input(Bytes),
     PollResult(Vec<PollFd>, c_int),
     TimerModified,
     Shutdown,
-    ProxyConnect(libslirp_sys::SlirpProxyConnectFunc, usize, i32, i32),
+    ProxyConnect(SlirpProxyConnectFunc, usize, i32, i32),
 }
 
 /// Alias for io::fd::RawFd on Unix or RawSocket on Windows (converted to i32)
@@ -139,12 +142,14 @@ pub type RawFd = i32;
 
 /// HTTP Proxy callback trait
 pub trait ProxyManager: Send {
+    /// Attempts to establish a connection through the proxy.
     fn try_connect(
         &self,
         sockaddr: SocketAddr,
         connect_id: usize,
         connect_func: Box<dyn ProxyConnect + Send>,
     ) -> bool;
+    /// Removes a proxy connection.
     fn remove(&self, connect_id: usize);
 }
 
@@ -153,10 +158,11 @@ struct CallbackContext {
     tx_cmds: mpsc::Sender<SlirpCmd>,
     poll_fds: Rc<RefCell<Vec<PollFd>>>,
     proxy_manager: Option<Box<dyn ProxyManager>>,
+    tx_proxy_bytes: Option<mpsc::Sender<Bytes>>,
     timer_manager: Rc<TimerManager>,
 }
 
-// A poll thread request has a poll_fds and a timeout
+/// A poll thread request has a poll_fds and a timeout
 type PollRequest = (Vec<PollFd>, u32);
 
 /// API to LibSlirp
@@ -170,7 +176,7 @@ impl TimerManager {
         self.timers.fetch_add(1, Ordering::SeqCst) as TimerOpaque
     }
 
-    // Finds expired Timers, clears then clones them
+    /// Finds expired Timers, clears then clones them
     fn collect_expired(&self) -> Vec<Timer> {
         let now_ms = self.get_elapsed().as_millis() as u64;
         self.map
@@ -184,7 +190,7 @@ impl TimerManager {
             .collect()
     }
 
-    // Return the minimum duration until the next timer
+    /// Return the minimum duration until the next timer
     fn min_duration(&self) -> Duration {
         match self.map.borrow().iter().min_by_key(|(_, timer)| timer.expire_time) {
             Some((_, timer)) => {
@@ -209,7 +215,7 @@ impl TimerManager {
     }
 
     fn timer_mod(&self, timer_key: &TimerOpaque, expire_time: u64) {
-        if let Some(&mut ref mut timer) = self.map.borrow_mut().get_mut(&timer_key) {
+        if let Some(&mut ref mut timer) = self.map.borrow_mut().get_mut(timer_key) {
             // expire_time is >= 0
             timer.expire_time = expire_time;
         } else {
@@ -219,10 +225,12 @@ impl TimerManager {
 }
 
 impl LibSlirp {
+    /// Creates a new `LibSlirp` instance.
     pub fn new(
         config: libslirp_config::SlirpConfig,
         tx_bytes: mpsc::Sender<Bytes>,
         proxy_manager: Option<Box<dyn ProxyManager>>,
+        tx_proxy_bytes: Option<mpsc::Sender<Bytes>>,
     ) -> LibSlirp {
         let (tx_cmds, rx_cmds) = mpsc::channel::<SlirpCmd>();
         let (tx_poll, rx_poll) = mpsc::channel::<PollRequest>();
@@ -239,7 +247,15 @@ impl LibSlirp {
         let tx_cmds_slirp = tx_cmds.clone();
         // Create channels for command processor thread and launch
         if let Err(e) = thread::Builder::new().name("slirp".to_string()).spawn(move || {
-            slirp_thread(config, tx_bytes, tx_cmds_slirp, rx_cmds, tx_poll, proxy_manager)
+            slirp_thread(
+                config,
+                tx_bytes,
+                tx_cmds_slirp,
+                rx_cmds,
+                tx_poll,
+                proxy_manager,
+                tx_proxy_bytes,
+            )
         }) {
             warn!("Failed to start slirp thread: {}", e);
         }
@@ -247,12 +263,14 @@ impl LibSlirp {
         LibSlirp { tx_cmds }
     }
 
+    /// Shuts down the `LibSlirp` instance.
     pub fn shutdown(self) {
         if let Err(e) = self.tx_cmds.send(SlirpCmd::Shutdown) {
             warn!("Failed to send Shutdown cmd: {}", e);
         }
     }
 
+    /// Inputs network data into the `LibSlirp` instance.
     pub fn input(&self, bytes: Bytes) {
         if let Err(e) = self.tx_cmds.send(SlirpCmd::Input(bytes)) {
             warn!("Failed to send Input cmd: {}", e);
@@ -262,13 +280,15 @@ impl LibSlirp {
 
 struct ConnectRequest {
     tx_cmds: mpsc::Sender<SlirpCmd>,
-    connect_func: libslirp_sys::SlirpProxyConnectFunc,
+    connect_func: SlirpProxyConnectFunc,
     connect_id: usize,
     af: i32,
     start: Instant,
 }
 
+/// Trait for handling proxy connection results.
 pub trait ProxyConnect: Send {
+    /// Notifies libslirp about the result of a proxy connection attempt.
     fn proxy_connect(&self, fd: i32, addr: SocketAddr);
 }
 
@@ -291,23 +311,31 @@ impl ProxyConnect for ConnectRequest {
     }
 }
 
-// Converts a libslirp callback's `opaque` handle into a
-// `CallbackContext.`
-//
-// Wrapped in a `ManuallyDrop` because we do not want to release the
-// storage when the callback returns.
-//
-// SAFETY:
-//
-// * opaque is a CallbackContext passed to the slirp API
+/// Converts a libslirp callback's `opaque` handle into a
+/// `CallbackContext.`
+///
+/// Wrapped in a `ManuallyDrop` because we do not want to release the
+/// storage when the callback returns.
+///
+/// # Safety
+///
+/// * `opaque` must be a valid pointer to a `CallbackContext` originally passed
+///   to the slirp API.
 unsafe fn callback_context_from_raw(opaque: *mut c_void) -> ManuallyDrop<Box<CallbackContext>> {
-    ManuallyDrop::new(unsafe { Box::from_raw(opaque as *mut CallbackContext) })
+    ManuallyDrop::new(
+        // Safety:
+        //
+        // * `opaque` is a valid pointer to a `CallbackContext` originally passed
+        //    to the slirp API. The `callback_context_from_raw` function itself
+        //    is marked `unsafe` to enforce this precondition on its callers.
+        unsafe { Box::from_raw(opaque as *mut CallbackContext) },
+    )
 }
 
-// A Rust struct for the fields held by `slirp` C library through it's
-// lifetime.
-//
-// All libslirp C calls are impl on this struct.
+/// A Rust struct for the fields held by `slirp` C library through its
+/// lifetime.
+///
+/// All libslirp C calls are impl on this struct.
 struct Slirp {
     slirp: *mut libslirp_sys::Slirp,
     // These fields are held by slirp C library
@@ -341,18 +369,16 @@ impl Slirp {
         // Call libslrip "C" library to create a new instance of a slirp
         // protocol stack.
         //
-        // SAFETY: We ensure that:
+        // Safety: We ensure that:
         //
-        // * config is a valid pointer to the "C" config struct. It is
-        // held by the "C" slirp library for lifetime of the slirp
-        // instance.
+        // * `configs.c_slirp_config` is a valid pointer to the "C" config struct. It is
+        //   held by the "C" slirp library for lifetime of the slirp instance.
         //
-        // * callbacks is a valid pointer to an array of callback
-        // functions. It is held by the "C" slirp library for the lifetime
-        // of the slirp instance.
+        // * `callbacks` is a valid pointer to an array of callback functions.
+        //   It is held by the "C" slirp library for the lifetime of the slirp instance.
         //
-        // * callback_context is an arbitrary opaque type passed back
-        //  to callback functions by libslirp.
+        // * `callback_context` is an arbitrary opaque type passed back to
+        //   callback functions by libslirp.
         let slirp = unsafe {
             libslirp_sys::slirp_new(
                 &configs.c_slirp_config,
@@ -365,24 +391,27 @@ impl Slirp {
     }
 
     fn handle_timer(&self, timer: Timer) {
+        // Safety: We ensure that:
+        //
+        // * self.slirp is a valid state returned by `slirp_new()`
+        //
+        // * timer.id is a valid c_uint from "C" slirp library calling `timer_new_opaque_cb()`
+        //
+        // * timer.cb_opaque is an usize representing a pointer to callback function from
+        // "C" slirp library calling `timer_new_opaque_cb()`
         unsafe {
-            //
-            // SAFETY: We ensure that:
-            //
-            // *self.slirp is a valid state returned by `slirp_new()`
-            //
-            // * timer.id is a valid c_uint from "C" slirp library calling `timer_new_opaque_cb()`
-            //
-            // * timer.cb_opaque is an usize representing a pointer to callback function from
-            // "C" slirp library calling `timer_new_opaque_cb()`
             libslirp_sys::slirp_handle_timer(self.slirp, timer.id, timer.cb_opaque as *mut c_void);
         };
     }
 }
 
 impl Drop for Slirp {
+    /// # Safety
+    ///
+    /// * self.slirp is always slirp pointer initialized by slirp_new
+    ///   to the slirp API.
     fn drop(&mut self) {
-        // SAFETY:
+        // Safety:
         //
         // * self.slirp is a slirp pointer initialized by slirp_new;
         // it's private to the struct and is only constructed that
@@ -398,6 +427,7 @@ fn slirp_thread(
     rx: mpsc::Receiver<SlirpCmd>,
     tx_poll: mpsc::Sender<PollRequest>,
     proxy_manager: Option<Box<dyn ProxyManager>>,
+    tx_proxy_bytes: Option<mpsc::Sender<Bytes>>,
 ) {
     // Data structures wrapped in an RC are referenced through the
     // libslirp callbacks and this code (both in the same thread).
@@ -415,6 +445,7 @@ fn slirp_thread(
         tx_cmds,
         poll_fds: poll_fds.clone(),
         proxy_manager,
+        tx_proxy_bytes,
         timer_manager: timer_manager.clone(),
     });
 
@@ -447,14 +478,14 @@ fn slirp_thread(
             // Exit the while loop and shutdown
             Ok(SlirpCmd::Shutdown) => break,
 
-            // SAFETY: we ensure that func (`SlirpProxyConnectFunc`)
-            // and `connect_opaque` are valid because they originated
-            // from the libslirp call to `try_connect_cb.`
-            //
-            // Parameter `fd` will be >= 0 and the descriptor for the
-            // active socket to use, `af` will be either AF_INET or
-            // AF_INET6. On failure `fd` will be negative.
             Ok(SlirpCmd::ProxyConnect(func, connect_id, fd, af)) => match func {
+                // Safety: we ensure that func (`SlirpProxyConnectFunc`)
+                // and `connect_opaque` are valid because they originated
+                // from the libslirp call to `try_connect_cb.`
+                //
+                // Parameter `fd` will be >= 0 and the descriptor for the
+                // active socket to use, `af` will be either AF_INET or
+                // AF_INET6. On failure `fd` will be negative.
                 Some(func) => unsafe { func(connect_id as *mut c_void, fd as c_int, af as c_int) },
                 None => warn!("Proxy connect function not found"),
             },
@@ -489,25 +520,25 @@ fn slirp_thread(
 #[derive(Clone, Debug)]
 struct PollFd {
     fd: c_int,
-    events: libslirp_sys::SlirpPollType,
-    revents: libslirp_sys::SlirpPollType,
+    events: SlirpPollType,
+    revents: SlirpPollType,
 }
 
-// Fill the pollfds from libslirp and pass the request to the polling thread.
-//
-// This is called by the application when it is about to sleep through
-// poll().  *timeout is set to the amount of virtual time (in ms) that
-// the application intends to wait (UINT32_MAX if
-// infinite). slirp_pollfds_fill updates it according to e.g. TCP
-// timers, so the application knows it should sleep a smaller amount
-// of time. slirp_pollfds_fill calls add_poll for each file descriptor
-// that should be monitored along the sleep. The opaque pointer is
-// passed as such to add_poll, and add_poll returns an index.
-//
-// # Safety
-//
-// `slirp` must be a valid Slirp state returned by `slirp_new()`
 impl Slirp {
+    /// Fill the pollfds from libslirp and pass the request to the polling thread.
+    ///
+    /// This is called by the application when it is about to sleep through
+    /// poll().  *timeout is set to the amount of virtual time (in ms) that
+    /// the application intends to wait (UINT32_MAX if
+    /// infinite). slirp_pollfds_fill updates it according to e.g. TCP
+    /// timers, so the application knows it should sleep a smaller amount
+    /// of time. slirp_pollfds_fill calls add_poll for each file descriptor
+    /// that should be monitored along the sleep. The opaque pointer is
+    /// passed as such to add_poll, and add_poll returns an index.
+    ///
+    /// # Safety
+    ///
+    /// `slirp` must be a valid Slirp state returned by `slirp_new()`
     fn pollfds_fill_and_send(
         &self,
         poll_fds: &RefCell<Vec<PollFd>>,
@@ -516,13 +547,10 @@ impl Slirp {
         let mut timeout: u32 = u32::MAX;
         poll_fds.borrow_mut().clear();
 
-        // Call libslrip "C" library to fill poll information using
-        // slirp_add_poll_cb callback function.
-        //
-        // SAFETY: we ensure that:
+        // Safety: we ensure that:
         //
         // * self.slirp has a slirp pointer initialized by slirp_new,
-        // as it's private to the struct is only constructed that way
+        // as it's private to the struct and is only constructed that way.
         //
         // * timeout is a valid ptr to a mutable u32.  The "C" slirp
         // library stores into timeout.
@@ -544,50 +572,39 @@ impl Slirp {
     }
 }
 
-// "C" library callback that is called for each file descriptor that
-// should be monitored.
-//
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// "C" library callback that is called for each file descriptor that
+/// should be monitored.
+///
+/// # Safety
+///
+/// * opaque must be a CallbackContext
 unsafe extern "C" fn slirp_add_poll_cb(fd: c_int, events: c_int, opaque: *mut c_void) -> c_int {
+    // Safety:
+    //
+    // * opaque is a CallbackContext
     unsafe { callback_context_from_raw(opaque) }.add_poll(fd, events)
 }
 
 impl CallbackContext {
     fn add_poll(&mut self, fd: c_int, events: c_int) -> c_int {
         let idx = self.poll_fds.borrow().len();
-        self.poll_fds.borrow_mut().push(PollFd {
-            fd,
-            events: events as libslirp_sys::SlirpPollType,
-            revents: 0,
-        });
+        self.poll_fds.borrow_mut().push(PollFd { fd, events: events as SlirpPollType, revents: 0 });
         idx as i32
     }
 }
 
-// Pass the result from the polling thread back to libslirp
-
-// This is called by the application when it is about to sleep through
-// poll().  *timeout is set to the amount of virtual time (in ms) that
-// the application intends to wait (UINT32_MAX if
-// infinite). slirp_pollfds_fill updates it according to e.g. TCP
-// timers, so the application knows it should sleep a smaller amount
-// of time. slirp_pollfds_fill calls add_poll for each file descriptor
-// that should be monitored along the sleep. The opaque pointer is
-// passed as such to add_poll, and add_poll returns an index.
-//
-// * select_error should be 1 if poll() returned an error, else 0.
-
 impl Slirp {
+    /// Pass the result from the polling thread back to libslirp.
+    ///
+    /// * select_error should be 1 if poll() returned an error, else 0.
     fn pollfds_poll(&self, select_error: c_int) {
         // Call libslrip "C" library to fill poll return event information
         // using slirp_get_revents_cb callback function.
         //
-        // SAFETY: we ensure that:
+        // Safety: we ensure that:
         //
         // * self.slirp has a slirp pointer initialized by slirp_new,
-        // as it's private to the struct is only constructed that way
+        // as it's private to the struct and is only constructed that way.
         //
         // * slirp_get_revents_cb is a valid `SlirpGetREventsCb` callback
         // function.
@@ -606,13 +623,16 @@ impl Slirp {
     }
 }
 
-// "C" library callback that is called on each file descriptor, giving
-// it the index that add_poll returned.
-//
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// "C" library callback that is called on each file descriptor, giving
+/// it the index that add_poll returned.
+///
+/// # Safety
+///
+/// * opaque must be a CallbackContext
 unsafe extern "C" fn slirp_get_revents_cb(idx: c_int, opaque: *mut c_void) -> c_int {
+    // Safety:
+    //
+    // * opaque is a CallbackContext
     unsafe { callback_context_from_raw(opaque) }.get_events(idx)
 }
 
@@ -636,60 +656,50 @@ macro_rules! ternary {
     };
 }
 
-// Worker thread loops issuing blocking poll requests, sending the
-// results into the slirp thread
-
+/// Worker thread that performs blocking `poll` operations on file descriptors.
+///
+/// It receives polling requests from the `rx` channel, performs the `poll`, and sends the results
+/// back to the slirp thread via the `tx` channel. This allows the slirp stack to be notified about
+/// network events without busy waiting.
+///
+/// The function handles platform-specific differences in polling mechanisms between Linux/macOS
+/// and Windows. It also converts between Slirp's `SlirpPollType` and the OS-specific poll event types.
 fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>) {
     #[cfg(any(target_os = "linux", target_os = "macos"))]
     use libc::{
-        nfds_t as OsPollFdsLenType, poll, pollfd, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI,
+        nfds_t as OsPollFdsLenType, poll, pollfd, POLLERR as OS_POLL_ERR, POLLHUP as OS_POLL_HUP,
+        POLLIN as OS_POLL_IN, POLLNVAL as OS_POLL_NVAL, POLLOUT as OS_POLL_OUT,
+        POLLPRI as OS_POLL_PRI,
     };
     #[cfg(target_os = "windows")]
     use winapi::{
         shared::minwindef::ULONG as OsPollFdsLenType,
         um::winsock2::{
-            WSAPoll as poll, POLLERR, POLLHUP, POLLOUT, POLLPRI, POLLRDBAND, POLLRDNORM,
-            SOCKET as FdType, WSAPOLLFD as pollfd,
+            WSAPoll as poll, POLLERR as OS_POLL_ERR, POLLHUP as OS_POLL_HUP,
+            POLLNVAL as OS_POLL_NVAL, POLLRDBAND as OS_POLL_PRI, POLLRDNORM as OS_POLL_IN,
+            POLLWRNORM as OS_POLL_OUT, SOCKET as FdType, WSAPOLLFD as pollfd,
         },
     };
     #[cfg(any(target_os = "linux", target_os = "macos"))]
     type FdType = c_int;
 
-    #[cfg(any(target_os = "linux", target_os = "macos"))]
-    fn to_os_events(events: libslirp_sys::SlirpPollType) -> i16 {
-        ternary!(events & libslirp_sys::SLIRP_POLL_IN, POLLIN)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_OUT, POLLOUT)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_PRI, POLLPRI)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_ERR, POLLERR)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_HUP, POLLHUP)
+    // Convert Slirp poll (input) events to OS events definitions
+    fn to_os_events(events: SlirpPollType) -> i16 {
+        ternary!(events & SLIRP_POLL_IN, OS_POLL_IN)
+            | ternary!(events & SLIRP_POLL_OUT, OS_POLL_OUT)
+            | ternary!(events & SLIRP_POLL_PRI, OS_POLL_PRI)
     }
-
-    #[cfg(any(target_os = "linux", target_os = "macos"))]
-    fn to_slirp_events(events: i16) -> libslirp_sys::SlirpPollType {
-        ternary!(events & POLLIN, libslirp_sys::SLIRP_POLL_IN)
-            | ternary!(events & POLLOUT, libslirp_sys::SLIRP_POLL_OUT)
-            | ternary!(events & POLLPRI, libslirp_sys::SLIRP_POLL_PRI)
-            | ternary!(events & POLLOUT, libslirp_sys::SLIRP_POLL_ERR)
-            | ternary!(events & POLLHUP, libslirp_sys::SLIRP_POLL_HUP)
+    // Convert OS (input) "events" to Slirp (input) events definitions
+    fn to_slirp_events(events: i16) -> SlirpPollType {
+        ternary!(events & OS_POLL_IN, SLIRP_POLL_IN)
+            | ternary!(events & OS_POLL_OUT, SLIRP_POLL_OUT)
+            | ternary!(events & OS_POLL_PRI, SLIRP_POLL_PRI)
     }
-
-    #[cfg(target_os = "windows")]
-    fn to_os_events(events: libslirp_sys::SlirpPollType) -> i16 {
-        ternary!(events & libslirp_sys::SLIRP_POLL_IN, POLLRDNORM)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_OUT, POLLOUT)
-            | ternary!(events & libslirp_sys::SLIRP_POLL_PRI, POLLRDBAND)
-    }
-
-    #[cfg(target_os = "windows")]
-    fn to_slirp_events(events: i16) -> libslirp_sys::SlirpPollType {
-        ternary!(events & POLLRDNORM, libslirp_sys::SLIRP_POLL_IN)
-            | ternary!(events & POLLERR, libslirp_sys::SLIRP_POLL_IN)
-            | ternary!(events & POLLHUP, libslirp_sys::SLIRP_POLL_IN)
-            | ternary!(events & POLLOUT, libslirp_sys::SLIRP_POLL_OUT)
-            | ternary!(events & POLLERR, libslirp_sys::SLIRP_POLL_PRI)
-            | ternary!(events & POLLHUP, libslirp_sys::SLIRP_POLL_PRI)
-            | ternary!(events & POLLPRI, libslirp_sys::SLIRP_POLL_PRI)
-            | ternary!(events & POLLRDBAND, libslirp_sys::SLIRP_POLL_PRI)
+    // Convert OS (output) "revents" to Slirp revents definitions which includes ERR and HUP
+    fn to_slirp_revents(revents: i16) -> SlirpPollType {
+        to_slirp_events(revents)
+            | ternary!(revents & OS_POLL_ERR, SLIRP_POLL_ERR)
+            | ternary!(revents & OS_POLL_HUP, SLIRP_POLL_HUP)
     }
 
     let mut prev_poll_fds_len = 0;
@@ -709,31 +719,15 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
         }
 
         let mut poll_result = 0;
-        #[cfg(any(target_os = "linux", target_os = "macos"))]
-        {
-            // SAFETY: we ensure that:
-            //
-            // `os_poll_fds` is a valid ptr to a vector of pollfd which
-            // the `poll` system call can write into. Note `os_poll_fds`
-            // is created and allocated above.
-            poll_result = unsafe {
-                poll(
-                    os_poll_fds.as_mut_ptr(),
-                    os_poll_fds.len() as OsPollFdsLenType,
-                    timeout as i32,
-                )
-            };
-        }
         // WSAPoll requires an array of one or more POLLFD structures.
         // When nfds == 0, WSAPoll returns immediately with result -1, ignoring the timeout.
-        // This is different from poll on Linux/macOS, which will wait for the timeout.
-        // Therefore, on Windows, we don't call WSAPoll when nfds == 0, and instead explicitly sleep for the timeout.
-        #[cfg(target_os = "windows")]
+        // (This is different from poll on Linux/macOS, which will wait for the timeout.)
+        // Therefore when nfds == 0 we will explicitly sleep for the timeout regardless of OS.
         if os_poll_fds.is_empty() {
             // If there are no FDs to poll, sleep for the specified timeout.
             thread::sleep(Duration::from_millis(timeout as u64));
         } else {
-            // SAFETY: we ensure that:
+            // Safety: we ensure that:
             //
             // `os_poll_fds` is a valid ptr to a vector of pollfd which
             // the `poll` system call can write into. Note `os_poll_fds`
@@ -746,22 +740,20 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
                 )
             };
         }
-
+        // POLLHUP and POLLERR are always allowed revents.
+        // if other events were not requested, then don't return them in the revents.
+        let allowed_revents = OS_POLL_HUP | OS_POLL_ERR;
         let mut slirp_poll_fds: Vec<PollFd> = Vec::with_capacity(poll_fds.len());
-        #[cfg(any(target_os = "linux", target_os = "macos"))]
         for &fd in &os_poll_fds {
+            // Slrip does not handle POLLNVAL - print warning and skip
+            if fd.events & OS_POLL_NVAL != 0 {
+                warn!("POLLNVAL event - Skip poll for fd: {:?}", fd.fd);
+                continue;
+            }
             slirp_poll_fds.push(PollFd {
                 fd: fd.fd as c_int,
                 events: to_slirp_events(fd.events),
-                revents: to_slirp_events(fd.revents) & to_slirp_events(fd.events),
-            });
-        }
-        #[cfg(target_os = "windows")]
-        for (fd, poll_fd) in os_poll_fds.iter().zip(poll_fds.iter()) {
-            slirp_poll_fds.push(PollFd {
-                fd: fd.fd as c_int,
-                events: poll_fd.events,
-                revents: to_slirp_events(fd.revents) & poll_fd.events,
+                revents: to_slirp_revents(fd.revents & (fd.events | allowed_revents)),
             });
         }
 
@@ -772,63 +764,85 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
     }
 }
 
-// Call libslrip "C" library to send input.
-//
-// This is called by the application when the guest emits a packet on
-// the guest network, to be interpreted by slirp.
 impl Slirp {
+    /// Sends raw input bytes to the slirp stack.
+    ///
+    /// This function is called by the application to inject network data into the virtual network
+    /// stack. The `bytes` slice contains the raw packet data that should be processed by slirp.
     fn input(&self, bytes: &[u8]) {
-        // SAFETY: The "C" library ensure that the memory is not
+        // Safety: The "C" library ensure that the memory is not
         // referenced after the call and `bytes` does not need to remain
         // valid after the function returns.
         unsafe { libslirp_sys::slirp_input(self.slirp, bytes.as_ptr(), bytes.len() as i32) };
     }
 }
 
-// "C" library callback that is called to send an ethernet frame to
-// the guest network. If the guest is not ready to receive a frame,
-// the function can just drop the data. TCP will then handle
-// retransmissions at a lower pace.  A return of < 0 reports an IO
-// error.
-//
-// # Safety:
-//
-// * buf must be a valid pointer to `len` bytes of memory. The
-// contents of buf must be valid for the duration of this call.
-//
-// * len is > 0
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to send an ethernet frame to the guest network.
+///
+/// This function is called by the slirp stack when it has a network packet that needs to be
+/// delivered to the guest network. The `buf` pointer points to the raw packet data, and `len`
+/// specifies the length of the packet.
+///
+/// If the guest is not ready to receive the packet, the function can drop the data. TCP will
+/// handle retransmissions as needed.
+///
+/// # Safety
+///
+/// * `buf` must be a valid pointer to `len` bytes of memory.
+/// * `len` must be greater than 0.
+/// * `opaque` must be a valid `CallbackContext` pointer.
+///
+/// # Returns
+///
+/// The number of bytes sent (which should be equal to `len`).
 unsafe extern "C" fn send_packet_cb(
     buf: *const c_void,
     len: usize,
     opaque: *mut c_void,
 ) -> libslirp_sys::slirp_ssize_t {
+    // Safety:
+    //
+    // * `buf` is a valid pointer to `len` bytes of memory.
+    // * `len` is greater than 0.
+    // * `opaque` is a valid `CallbackContext` pointer.
     unsafe { callback_context_from_raw(opaque) }.send_packet(buf, len)
 }
 
 impl CallbackContext {
     fn send_packet(&self, buf: *const c_void, len: usize) -> libslirp_sys::slirp_ssize_t {
-        // SAFETY: The caller ensures that `buf` is contains `len` bytes of data.
+        // Safety: The caller ensures that `buf` is contains `len` bytes of data.
         let c_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
         // Bytes::from(slice: &'static [u8]) creates a Bytes object without copying the data.
         // To own its data, copy &'static [u8] to Vec<u8> before converting to Bytes.
-        let _ = self.tx_bytes.send(Bytes::from(c_slice.to_vec()));
+        let bytes = Bytes::from(c_slice.to_vec());
+        let _ = self.tx_bytes.send(bytes.clone());
+        // When HTTP Proxy is enabled, it tracks DNS packets.
+        if let Some(tx_proxy) = &self.tx_proxy_bytes {
+            let _ = tx_proxy.send(bytes);
+        }
         len as libslirp_sys::slirp_ssize_t
     }
 }
 
-// "C" library callback to print a message for an error due to guest
-// misbehavior.
-//
-// # Safety:
-//
-// * msg must be a valid nul-terminated utf8 string.
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to report an error caused by guest misbehavior.
+///
+/// This function is called by the slirp stack when it encounters an error condition that is
+/// attributed to incorrect or unexpected behavior from the guest network. The `msg` parameter
+/// contains a human-readable error message describing the issue.
+///
+/// # Safety
+///
+/// * `msg` must be a valid C string.
+/// * `opaque` must be a valid `CallbackContext` pointer.
 unsafe extern "C" fn guest_error_cb(msg: *const c_char, opaque: *mut c_void) {
-    // SAFETY: The caller ensures that `msg` is a nul-terminated string.
+    // Safety:
+    //  * `msg` is guaranteed to be a valid C string by the caller.
     let msg = String::from_utf8_lossy(unsafe { CStr::from_ptr(msg) }.to_bytes());
+    // Safety:
+    //  * `opaque` is guaranteed to be a valid, non-null pointer to a `CallbackContext` struct that was originally passed
+    //     to `slirp_new()` and is guaranteed to be valid for the lifetime of the Slirp instance.
+    //  * `callback_context_from_raw()` safely converts the raw `opaque` pointer back to a
+    //     `CallbackContext` reference. This is safe because the `opaque` pointer is guaranteed to be valid.
     unsafe { callback_context_from_raw(opaque) }.guest_error(msg.to_string());
 }
 
@@ -838,10 +852,23 @@ impl CallbackContext {
     }
 }
 
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to get the current time in nanoseconds.
+///
+/// This function is called by the slirp stack to obtain the current time, which is used for
+/// various timing-related operations within the virtual network stack.
+///
+/// # Safety
+///
+/// * `opaque` must be a valid `CallbackContext` pointer.
+///
+/// # Returns
+///
+/// The current time in nanoseconds.
 unsafe extern "C" fn clock_get_ns_cb(opaque: *mut c_void) -> i64 {
+    // Safety:
+    //
+    // * `opaque` is a valid `CallbackContext` pointer.
+    //
     unsafe { callback_context_from_raw(opaque) }.clock_get_ns()
 }
 
@@ -851,10 +878,20 @@ impl CallbackContext {
     }
 }
 
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to signal that initialization is complete.
+///
+/// This function is called by the slirp stack once it has finished its initialization process
+/// and is ready to handle network traffic.
+///
+/// # Safety
+///
+/// * `_slirp` is a raw pointer to the slirp instance, but it's not used in this callback.
+/// * `opaque` must be a valid `CallbackContext` pointer.
 unsafe extern "C" fn init_completed_cb(_slirp: *mut libslirp_sys::Slirp, opaque: *mut c_void) {
+    // Safety:
+    //
+    // * `_slirp` is a raw pointer to the slirp instance, but it's not used in this callback.
+    // * `opaque` is a valid `CallbackContext` pointer.
     unsafe { callback_context_from_raw(opaque) }.init_completed();
 }
 
@@ -864,28 +901,40 @@ impl CallbackContext {
     }
 }
 
-// Create a new timer
-//
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to create a new timer.
+///
+/// This function is called by the slirp stack when it needs to create a new timer. The `id`
+/// parameter is a unique identifier for the timer, and `cb_opaque` is an opaque pointer that
+/// will be passed back to the timer callback function when the timer expires.
+///
+/// # Safety
+///
+/// * `opaque` must be a valid `CallbackContext` pointer.
+/// * `cb_opaque` should be a valid pointer that can be passed back to libslirp.
+///
+/// # Returns
+///
+/// An opaque pointer to the newly created timer.
 unsafe extern "C" fn timer_new_opaque_cb(
-    id: libslirp_sys::SlirpTimerId,
+    id: SlirpTimerId,
     cb_opaque: *mut c_void,
     opaque: *mut c_void,
 ) -> *mut c_void {
-    unsafe { callback_context_from_raw(opaque) }.timer_new_opaque(id, cb_opaque)
+    // Safety:
+    //  * `opaque` is a valid, non-null pointer to a `CallbackContext` struct that was originally passed
+    //     to `slirp_new()` and is guaranteed to be valid for the lifetime of the Slirp instance.
+    //  * `callback_context_from_raw()` safely converts the raw `opaque` pointer back to a
+    //     `CallbackContext` reference. This is safe because the `opaque` pointer is guaranteed to be valid.
+    unsafe { callback_context_from_raw(opaque).timer_new_opaque(id, cb_opaque) }
 }
 
 impl CallbackContext {
-    // SAFETY:
-    //
-    // * cb_opaque is only passed back to libslirp
-    unsafe fn timer_new_opaque(
-        &self,
-        id: libslirp_sys::SlirpTimerId,
-        cb_opaque: *mut c_void,
-    ) -> *mut c_void {
+    /// Creates a new timer and stores it in the timer manager.
+    ///
+    /// # Safety
+    ///
+    /// * `cb_opaque` should be a valid pointer that can be passed back to libslirp.
+    unsafe fn timer_new_opaque(&self, id: SlirpTimerId, cb_opaque: *mut c_void) -> *mut c_void {
         let timer = self.timer_manager.next_timer();
         self.timer_manager
             .insert(timer, Timer { expire_time: u64::MAX, id, cb_opaque: cb_opaque as usize });
@@ -893,16 +942,28 @@ impl CallbackContext {
     }
 }
 
-// SAFETY:
-//
-// * timer is a TimerOpaque key for timer manager
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to free a timer.
+///
+/// This function is called by the slirp stack when a timer is no longer needed and should be
+/// removed. The `timer` parameter is an opaque pointer to the timer that was created previously
+/// using `timer_new_opaque_cb`.
+///
+/// # Safety
+///
+/// * `timer` must be a valid `TimerOpaque` key that was previously returned by `timer_new_opaque_cb`.
+/// * `opaque` must be a valid `CallbackContext` pointer.
 unsafe extern "C" fn timer_free_cb(timer: *mut c_void, opaque: *mut c_void) {
+    // Safety:
+    //
+    // * `timer` is a valid `TimerOpaque` key that was previously returned by `timer_new_opaque_cb`.
+    // * `opaque` is a valid `CallbackContext` pointer.
     unsafe { callback_context_from_raw(opaque) }.timer_free(timer);
 }
 
 impl CallbackContext {
+    /// Removes a timer from the timer manager.
+    ///
+    /// If the timer is not found in the manager, a warning is logged.
     fn timer_free(&self, timer: *mut c_void) {
         let timer = timer as TimerOpaque;
         if self.timer_manager.remove(&timer).is_none() {
@@ -911,16 +972,30 @@ impl CallbackContext {
     }
 }
 
-// SAFETY:
-//
-// * timer is a TimerOpaque key for timer manager
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to modify an existing timer.
+///
+/// This function is called by the slirp stack when it needs to change the expiration time of
+/// an existing timer. The `timer` parameter is an opaque pointer to the timer that was created
+/// previously using `timer_new_opaque_cb`. The `expire_time` parameter specifies the new
+/// expiration time for the timer, in nanoseconds.
+///
+/// # Safety
+///
+/// * `timer` must be a valid `TimerOpaque` key that was previously returned by `timer_new_opaque_cb`.
+/// * `opaque` must be a valid `CallbackContext` pointer.
 unsafe extern "C" fn timer_mod_cb(timer: *mut c_void, expire_time: i64, opaque: *mut c_void) {
+    // Safety:
+    //
+    // * `timer` is a valid `TimerOpaque` key that was previously returned by `timer_new_opaque_cb`.
+    // * `opaque` is a valid `CallbackContext` pointer.
     unsafe { callback_context_from_raw(opaque) }.timer_mod(timer, expire_time);
 }
 
 impl CallbackContext {
+    /// Modifies the expiration time of a timer in the timer manager.
+    ///
+    /// This function updates the expiration time of the specified timer. It also sends a
+    /// notification to the slirp command thread to wake it up and reset its sleep duration,
     fn timer_mod(&self, timer: *mut c_void, expire_time: i64) {
         let timer_key = timer as TimerOpaque;
         let expire_time = std::cmp::max(expire_time, 0) as u64;
@@ -942,35 +1017,60 @@ extern "C" fn notify_cb(_opaque: *mut c_void) {
     //TODO: Un-implemented
 }
 
-// Called by libslirp to initiate a proxy connection to address
-// `addr.` Eventually this will notify libslirp with a result by
-// calling the passed `connect_func.`
-//
-// SAFETY:
-//
-// * opaque is a CallbackContext
+/// Callback function invoked by the slirp stack to initiate a proxy connection.
+///
+/// This function is called by the slirp stack when it needs to establish a connection
+/// through a proxy. The `addr` parameter points to the address to connect to, `connect_func`
+/// is a callback function that should be called to notify libslirp of the connection result,
+/// and `connect_opaque` is an opaque pointer that will be passed back to `connect_func`.
+///
+/// # Safety
+///
+/// * `addr` must be a valid pointer to a `sockaddr_storage` structure.
+/// * `connect_func` must be a valid callback function pointer.
+/// * `connect_opaque` should be a valid pointer that can be passed back to libslirp.
+/// * `opaque` must be a valid `CallbackContext` pointer.
+///
+/// # Returns
+///
+/// `true` if the proxy connection request was initiated successfully, `false` otherwise.
 unsafe extern "C" fn try_connect_cb(
     addr: *const libslirp_sys::sockaddr_storage,
-    connect_func: libslirp_sys::SlirpProxyConnectFunc,
+    connect_func: SlirpProxyConnectFunc,
     connect_opaque: *mut c_void,
     opaque: *mut c_void,
 ) -> bool {
-    unsafe { callback_context_from_raw(opaque) }.try_connect(
-        addr,
-        connect_func,
-        connect_opaque as usize,
-    )
+    // Safety:
+    //
+    // * `addr` is a valid pointer to a `sockaddr_storage` structure.
+    // * `connect_func` is a valid callback function pointer.
+    // * `connect_opaque` is a valid pointer that can be passed back to libslirp.
+    // * `opaque` is a valid `CallbackContext` pointer.
+    unsafe {
+        callback_context_from_raw(opaque).try_connect(addr, connect_func, connect_opaque as usize)
+    }
 }
 
 impl CallbackContext {
-    fn try_connect(
+    /// Attempts to establish a proxy connection.
+    ///
+    /// This function uses the `proxy_manager` to initiate a connection to the specified address.
+    /// If the proxy manager is not available, it returns `false`.
+    ///
+    /// # Safety
+    ///
+    /// * `addr` must be a valid pointer to a `sockaddr_storage` structure.
+    unsafe fn try_connect(
         &self,
         addr: *const libslirp_sys::sockaddr_storage,
-        connect_func: libslirp_sys::SlirpProxyConnectFunc,
+        connect_func: SlirpProxyConnectFunc,
         connect_id: usize,
     ) -> bool {
         if let Some(proxy_manager) = &self.proxy_manager {
-            // SAFETY: We ensure that addr is valid when `try_connect` is called from libslirp
+            // Safety:
+            //
+            //  * `addr` is a valid pointer to a `sockaddr_storage` structure, as guaranteed by the caller
+            //  * Obtaining the `ss_family` field from a valid `sockaddr_storage` struct is safe
             let storage = unsafe { *addr };
             let af = storage.ss_family as i32;
             let socket_addr: SocketAddr = storage.into();
@@ -991,11 +1091,29 @@ impl CallbackContext {
     }
 }
 
+/// Callback function invoked by the slirp stack to remove a proxy connection.
+///
+/// This function is called by the slirp stack when a proxy connection is no longer needed
+/// and should be removed. The `connect_opaque` parameter is an opaque pointer that was
+/// originally passed to `try_connect_cb` when the connection was initiated.
+///
+/// # Safety
+///
+/// * `connect_opaque` must be a valid pointer that was previously passed to `try_connect_cb`.
+/// * `opaque` must be a valid `CallbackContext` pointer.
 unsafe extern "C" fn remove_cb(connect_opaque: *mut c_void, opaque: *mut c_void) {
+    //  Safety:
+    //
+    // * `connect_opaque` is a valid pointer that was previously passed to `try_connect_cb`.
+    // * `opaque` is a valid `CallbackContext` pointer.
     unsafe { callback_context_from_raw(opaque) }.remove(connect_opaque as usize);
 }
 
 impl CallbackContext {
+    /// Removes a proxy connection from the proxy manager.
+    ///
+    /// This function calls the `remove` method on the `proxy_manager` to remove the
+    /// connection associated with the given `connect_id`.
     fn remove(&self, connect_id: usize) {
         if let Some(proxy_connector) = &self.proxy_manager {
             proxy_connector.remove(connect_id);
@@ -1006,12 +1124,221 @@ impl CallbackContext {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use std::io::{Read, Write};
+    use std::net::{TcpListener, TcpStream};
+    #[cfg(any(target_os = "linux", target_os = "macos"))]
+    use std::os::unix::io::AsRawFd;
+    #[cfg(target_os = "windows")]
+    use std::os::windows::io::AsRawSocket;
 
     #[test]
     fn test_version_string() {
-        // Safety
+        // Safety:
         // Function returns a constant c_str
         let c_version_str = unsafe { CStr::from_ptr(crate::libslirp_sys::slirp_version_string()) };
         assert_eq!("4.7.0", c_version_str.to_str().unwrap());
     }
+
+    // Utility function to create and launch a slirp polling thread
+    fn launch_polling_thread() -> (
+        mpsc::Sender<SlirpCmd>,
+        mpsc::Receiver<SlirpCmd>,
+        mpsc::Sender<PollRequest>,
+        thread::JoinHandle<()>,
+    ) {
+        let (tx_cmds, rx_cmds) = mpsc::channel::<SlirpCmd>();
+        let (tx_poll, rx_poll) = mpsc::channel::<PollRequest>();
+
+        let tx_cmds_clone = tx_cmds.clone();
+        let handle = thread::Builder::new()
+            .name(format!("test_slirp_poll"))
+            .spawn(move || slirp_poll_thread(rx_poll, tx_cmds_clone))
+            .unwrap();
+
+        (tx_cmds, rx_cmds, tx_poll, handle)
+    }
+
+    #[cfg(any(target_os = "linux", target_os = "macos"))]
+    fn to_os_fd(stream: &impl AsRawFd) -> i32 {
+        return stream.as_raw_fd() as i32;
+    }
+    #[cfg(target_os = "windows")]
+    fn to_os_fd(stream: &impl AsRawSocket) -> i32 {
+        return stream.as_raw_socket() as i32;
+    }
+
+    // Utility function to send a poll request and receive the result
+    fn poll_and_assert_result(
+        tx_poll: &mpsc::Sender<PollRequest>,
+        rx_cmds: &mpsc::Receiver<SlirpCmd>,
+        fd: i32,
+        poll_events: SlirpPollType,
+        expected_revents: SlirpPollType,
+    ) {
+        assert!(
+            tx_poll.send((vec![PollFd { fd, events: poll_events, revents: 0 }], 1000)).is_ok(),
+            "Failed to send poll request"
+        );
+        if let Ok(SlirpCmd::PollResult(poll_fds, select_error)) = rx_cmds.recv() {
+            assert_eq!(poll_fds.len(), 1, "poll_fds len is not 1.");
+            let poll_fd = poll_fds.get(0).unwrap();
+            assert_eq!(poll_fd.fd, fd, "poll file descriptor mismatch.");
+            assert_eq!(poll_fd.revents, expected_revents, "poll revents mismatch.");
+        } else {
+            assert!(false, "Received unexpected command poll result");
+        }
+    }
+
+    // Create and return TcpListener and TcpStream of a connected pipe
+    fn create_stream_pipe() -> (TcpListener, TcpStream) {
+        // Create a TcpStream pipe for testing.
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let addr = listener.local_addr().unwrap();
+        let writer = TcpStream::connect(addr).unwrap();
+        (listener, writer)
+    }
+
+    // Create and return reader and writer TcpStreams of an accepted pipe
+    fn create_accepted_stream_pipe() -> (TcpStream, TcpStream) {
+        // Create a TcpStream pipe
+        let (listener, writer) = create_stream_pipe();
+        // Accept the connection
+        let (reader, _) = listener.accept().unwrap();
+        (reader, writer)
+    }
+
+    // Initialize an accepted TcpStream pipe with initial data
+    fn init_pipe() -> (TcpStream, TcpStream) {
+        // Create an accepted TcpStream pipe
+        let (reader, mut writer) = create_accepted_stream_pipe();
+        // Write initial data to pipe
+        #[cfg(any(target_os = "linux", target_os = "macos"))]
+        writer.write_all(&[1]).unwrap();
+        #[cfg(target_os = "windows")]
+        writer.write_all(b"1").unwrap();
+
+        (reader, writer)
+    }
+
+    #[test]
+    fn test_slirp_poll_thread_exit() {
+        let (_tx_cmds, _rx_cmds, tx_poll, handle) = launch_polling_thread();
+        // Drop the sender to end the polling thread and wait for the polling thread to exit
+        drop(tx_poll);
+        handle.join().unwrap();
+    }
+
+    #[test]
+    fn test_poll_invalid_fd() {
+        // Launch the slirp polling thread.
+        let (_tx_cmds, rx_cmds, tx_poll, handle) = launch_polling_thread();
+
+        let invalid_fd = -1;
+        // Check that the poll result indicates 0 (fd not ready).
+        poll_and_assert_result(&tx_poll, &rx_cmds, invalid_fd, SLIRP_POLL_IN, 0);
+
+        // Drop the sender to end the polling thread and wait for the polling thread to exit
+        drop(tx_poll);
+        handle.join().unwrap();
+    }
+
+    #[test]
+    fn test_close_fd_before_accept() {
+        // Launch the slirp polling thread.
+        let (_tx_cmds, rx_cmds, tx_poll, handle) = launch_polling_thread();
+
+        // Init a "broken" pipe that is closed before being accepted
+        let (listener, writer) = create_stream_pipe();
+
+        // Close the listener before accepting the connection
+        drop(listener);
+
+        // Check the expected result when file descriptor is not ready.
+        #[cfg(target_os = "linux")]
+        let expected_revents = SLIRP_POLL_IN | SLIRP_POLL_HUP | SLIRP_POLL_ERR;
+        // TODO: Identify way to trigger and test POLL_ERR for macOS
+        #[cfg(target_os = "macos")]
+        let expected_revents = SLIRP_POLL_IN | SLIRP_POLL_HUP;
+        #[cfg(target_os = "windows")]
+        let expected_revents = SLIRP_POLL_HUP | SLIRP_POLL_ERR;
+        poll_and_assert_result(
+            &tx_poll,
+            &rx_cmds,
+            to_os_fd(&writer),
+            SLIRP_POLL_IN,
+            expected_revents,
+        );
+
+        // Drop the sender to end the polling thread and wait for the polling thread to exit
+        drop(tx_poll);
+        handle.join().unwrap();
+    }
+
+    #[test]
+    fn test_accept_close_before_write() {
+        // Launch the slirp polling thread.
+        let (_tx_cmds, rx_cmds, tx_poll, handle) = launch_polling_thread();
+        // Init a "broken" pipe that is accepted but no initial data is written
+        let (mut reader, writer) = create_accepted_stream_pipe();
+        let reader_fd = to_os_fd(&reader);
+        // Close the writer end of the pipe
+        drop(writer);
+
+        // Check the expected poll result when writer is closed before data is written
+        #[cfg(target_os = "linux")]
+        let expected_revents = SLIRP_POLL_IN;
+        #[cfg(target_os = "macos")]
+        let expected_revents = SLIRP_POLL_IN | SLIRP_POLL_HUP;
+        #[cfg(target_os = "windows")]
+        let expected_revents = SLIRP_POLL_HUP;
+        poll_and_assert_result(&tx_poll, &rx_cmds, reader_fd, SLIRP_POLL_IN, expected_revents);
+
+        // Drop the sender to end the polling thread and wait for the polling thread to exit
+        drop(tx_poll);
+        handle.join().unwrap();
+    }
+
+    #[test]
+    fn test_accept_write_close() {
+        // Launch the slirp polling thread.
+        let (_tx_cmds, rx_cmds, tx_poll, handle) = launch_polling_thread();
+        // Init a pipe for testing and get its reader file descriptor.
+        let (mut reader, writer) = init_pipe();
+        let reader_fd = to_os_fd(&reader);
+
+        // --- Test polling for POLLIN event ---
+
+        // Send a poll request and check that the poll result has POLLIN only
+        poll_and_assert_result(&tx_poll, &rx_cmds, reader_fd, SLIRP_POLL_IN, SLIRP_POLL_IN);
+
+        // Read / remove the data from the pipe.
+        let mut buf = [0; 1];
+        reader.read_exact(&mut buf).unwrap();
+
+        // --- Test polling for no event after reading ---
+
+        // Check that the poll result contains no event since there is no more data
+        poll_and_assert_result(&tx_poll, &rx_cmds, reader_fd, SLIRP_POLL_IN, 0);
+
+        // --- Test polling for POLLHUP event when writer is closed ---
+
+        // Close the writer
+        drop(writer);
+
+        // Shutdown the write half of the reader
+        reader.shutdown(std::net::Shutdown::Write).unwrap();
+
+        // Check that expected poll result when writer end is dropped
+        #[cfg(any(target_os = "linux", target_os = "macos"))]
+        let expected_revents = SLIRP_POLL_IN | SLIRP_POLL_HUP;
+        #[cfg(target_os = "windows")]
+        let expected_revents = SLIRP_POLL_HUP;
+        poll_and_assert_result(&tx_poll, &rx_cmds, reader_fd, SLIRP_POLL_IN, expected_revents);
+
+        // Drop the sender to end the polling thread and wait for the polling thread to exit
+        drop(tx_poll);
+        handle.join().unwrap();
+    }
+
+    // TODO: Add testing for POLLNVAL case
 }
diff --git a/rust/libslirp-rs/src/libslirp_config.rs b/rust/libslirp-rs/src/libslirp_config.rs
index cf48a5b5..afc4f8a6 100644
--- a/rust/libslirp-rs/src/libslirp_config.rs
+++ b/rust/libslirp-rs/src/libslirp_config.rs
@@ -4,7 +4,7 @@
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 //
-//     https://www.apache.org/licenses/LICENSE-2.0
+//     https://www.apache.org/licenses/LICENSE-2.0
 //
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
@@ -22,44 +22,80 @@ use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
 use std::path::PathBuf;
 use tokio;
 
+/// The maximum number of DNS servers supported by libslirp.
 const MAX_DNS_SERVERS: usize = SLIRP_MAX_DNS_SERVERS as usize;
 
-/// Rust SlirpConfig
+/// Configuration options for the Slirp network stack.
 pub struct SlirpConfig {
+    /// Slirp version.
     pub version: u32,
+    /// Whether to run in restricted mode.
     pub restricted: i32,
+    /// Whether IPv4 is enabled.
     pub in_enabled: bool,
+    /// The virtual network address for IPv4.
     pub vnetwork: Ipv4Addr,
+    /// The virtual network mask for IPv4.
     pub vnetmask: Ipv4Addr,
+    /// The virtual host address for IPv4.
     pub vhost: Ipv4Addr,
+    /// Whether IPv6 is enabled.
     pub in6_enabled: bool,
+    /// The virtual prefix address for IPv6.
     pub vprefix_addr6: Ipv6Addr,
+    /// The length of the virtual prefix for IPv6.
     pub vprefix_len: u8,
+    /// The virtual host address for IPv6.
     pub vhost6: Ipv6Addr,
+    /// The virtual hostname.
     pub vhostname: Option<String>,
+    /// The TFTP server name.
     pub tftp_server_name: Option<String>,
+    /// The path to the TFTP root directory.
     pub tftp_path: Option<PathBuf>,
+    /// The bootfile name for DHCP.
     pub bootfile: Option<String>,
+    /// The starting IP address for the DHCP server.
     pub vdhcp_start: Ipv4Addr,
+    /// The primary DNS server address for IPv4.
     pub vnameserver: Ipv4Addr,
+    /// The primary DNS server address for IPv6.
     pub vnameserver6: Ipv6Addr,
+    /// A list of DNS search domains.
     pub vdnssearch: Vec<String>,
+    /// The virtual domain name.
     pub vdomainname: Option<String>,
+    /// The interface MTU (Maximum Transmission Unit).
     pub if_mtu: usize,
+    /// The interface MRU (Maximum Receive Unit).
     pub if_mru: usize,
+    /// Whether to disable the host loopback interface.
     pub disable_host_loopback: bool,
+    /// Whether to enable emulation features.
     pub enable_emu: bool,
+    /// The outbound IPv4 address to bind to (optional).
     pub outbound_addr: Option<SocketAddrV4>,
+    /// The outbound IPv6 address to bind to (optional).
     pub outbound_addr6: Option<SocketAddrV6>,
+    /// Whether to disable the built-in DNS server.
     pub disable_dns: bool,
+    /// Whether to disable the built-in DHCP server.
     pub disable_dhcp: bool,
+    /// The manufacturer ID.
     pub mfr_id: u32,
+    /// The out-of-band Ethernet address.
     pub oob_eth_addr: [u8; 6usize],
+    /// Whether the HTTP proxy is enabled.
     pub http_proxy_on: bool,
+    /// A list of host DNS servers to use.
     pub host_dns: Vec<SocketAddr>,
 }
 
 impl Default for SlirpConfig {
+    /// Creates a new `SlirpConfig` with default values.
+    ///
+    /// The default configuration has IPv4 and IPv6 enabled on a private network,
+    /// with DHCP starting at `10.0.2.16` and a DNS server at `10.0.2.3`.
     fn default() -> Self {
         SlirpConfig {
             version: 5,
@@ -71,7 +107,7 @@ impl Default for SlirpConfig {
             vnetmask: Ipv4Addr::new(255, 255, 255, 0),
             // Default host address
             vhost: Ipv4Addr::new(10, 0, 2, 2),
-            // IPv6 disabled by default
+            // IPv6 enabled by default
             in6_enabled: true,
             vprefix_addr6: "fec0::".parse().unwrap(),
             vprefix_len: 64,
@@ -105,10 +141,11 @@ impl Default for SlirpConfig {
     }
 }
 
-/// Struct to hold a "C" SlirpConfig and the Rust storage that is
-/// referenced by SlirpConfig.
+/// Struct to hold a "C" `SlirpConfig` and the Rust storage that is
+/// referenced by `SlirpConfig`.
 #[allow(dead_code)]
 pub struct SlirpConfigs {
+    /// The "C" representation of the Slirp configuration.
     pub c_slirp_config: libslirp_sys::SlirpConfig,
 
     // fields that hold the managed storage for "C" struct.
@@ -121,13 +158,25 @@ pub struct SlirpConfigs {
     // TODO: add other fields
 }
 
+/// Asynchronously looks up the IP addresses for a given hostname or comma-separated list of hostnames.
+///
+/// Each hostname in the input string is resolved using `tokio::net::lookup_host`.
+/// The port in the resolved `SocketAddr` will be 0.
+///
+/// # Arguments
+///
+/// * `host_dns` - A string containing a single hostname or a comma-separated list of hostnames.
+///
+/// # Returns
+///
+/// A `Result` containing a `Vec` of `SocketAddr` on success, or an `io::Error` on failure.
 pub async fn lookup_host_dns(host_dns: &str) -> io::Result<Vec<SocketAddr>> {
     let mut set = tokio::task::JoinSet::new();
     if host_dns.is_empty() {
         return Ok(Vec::new());
     }
 
-    for addr in host_dns.split(",") {
+    for addr in host_dns.split(',') {
         set.spawn(tokio::net::lookup_host(format!("{addr}:0")));
     }
 
@@ -138,6 +187,19 @@ pub async fn lookup_host_dns(host_dns: &str) -> io::Result<Vec<SocketAddr>> {
     Ok(addrs)
 }
 
+/// Converts a slice of `SocketAddr` into an array of `libslirp_sys::sockaddr_storage`.
+///
+/// If the input slice contains more than `MAX_DNS_SERVERS` addresses, a warning is logged,
+/// and only the first `MAX_DNS_SERVERS` addresses are converted. The remaining entries
+/// in the output array will be default-initialized.
+///
+/// # Arguments
+///
+/// * `dns` - A slice of `SocketAddr` representing DNS server addresses.
+///
+/// # Returns
+///
+/// An array of `libslirp_sys::sockaddr_storage` containing the converted addresses.
 fn to_socketaddr_storage(dns: &[SocketAddr]) -> [libslirp_sys::sockaddr_storage; MAX_DNS_SERVERS] {
     let mut result = [libslirp_sys::sockaddr_storage::default(); MAX_DNS_SERVERS];
     if dns.len() > MAX_DNS_SERVERS {
@@ -150,6 +212,15 @@ fn to_socketaddr_storage(dns: &[SocketAddr]) -> [libslirp_sys::sockaddr_storage;
 }
 
 impl SlirpConfigs {
+    /// Creates a new `SlirpConfigs` instance from a Rust `SlirpConfig`.
+    ///
+    /// This function converts the Rust configuration into the "C" representation
+    /// used by libslirp, handling string conversions and storing necessary Rust
+    /// data to be referenced by the "C" struct.
+    ///
+    /// # Arguments
+    ///
+    /// * `config` - A reference to the Rust `SlirpConfig`.
     pub fn new(config: &SlirpConfig) -> SlirpConfigs {
         let as_cstring =
             |s: &Option<String>| s.as_ref().and_then(|s| CString::new(s.as_bytes()).ok());
@@ -227,6 +298,7 @@ mod tests {
     use super::*;
     use tokio::runtime::Runtime;
 
+    /// Tests the default values of the `SlirpConfig` struct.
     #[test]
     fn test_slirp_config_default() {
         let config = SlirpConfig::default();
@@ -264,6 +336,7 @@ mod tests {
         assert_eq!(config.host_dns.len(), 0);
     }
 
+    /// Tests the creation of a `SlirpConfigs` instance from a default `SlirpConfig`.
     #[test]
     fn test_slirp_configs_new() {
         let rust_config = SlirpConfig::default();
@@ -279,6 +352,7 @@ mod tests {
         assert_eq!(c_configs.c_slirp_config.tftp_server_name, std::ptr::null());
     }
 
+    /// Tests the `lookup_host_dns` function with different inputs.
     #[test]
     fn test_lookup_host_dns() -> io::Result<()> {
         let rt = Runtime::new().unwrap();
@@ -296,6 +370,7 @@ mod tests {
         Ok(())
     }
 
+    /// Tests the `to_socketaddr_storage` function with an empty input slice.
     #[test]
     fn test_to_socketaddr_storage_empty_input() {
         let dns: [SocketAddr; 0] = [];
@@ -307,6 +382,7 @@ mod tests {
         }
     }
 
+    /// Tests the `to_socketaddr_storage` function with a valid input slice.
     #[test]
     fn test_to_socketaddr_storage() {
         let dns = ["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
@@ -320,6 +396,7 @@ mod tests {
         }
     }
 
+    /// Tests the `to_socketaddr_storage` function with a valid input slice at the maximum allowed size.
     #[test]
     fn test_to_socketaddr_storage_valid_input_at_max() {
         let dns = [
@@ -335,6 +412,7 @@ mod tests {
         }
     }
 
+    /// Tests the `to_socketaddr_storage` function when the input slice exceeds the maximum allowed size.
     #[test]
     fn test_to_socketaddr_storage_input_exceeds_max() {
         let dns = [
diff --git a/rust/libslirp-rs/src/libslirp_sys/mod.rs b/rust/libslirp-rs/src/libslirp_sys/mod.rs
index 17afb896..745e5346 100644
--- a/rust/libslirp-rs/src/libslirp_sys/mod.rs
+++ b/rust/libslirp-rs/src/libslirp_sys/mod.rs
@@ -34,6 +34,9 @@
 //! // Interact with the Slirp instance
 //! ```
 
+#![allow(missing_docs)]
+#![allow(clippy::missing_safety_doc)]
+#![allow(unsafe_op_in_unsafe_fn)]
 #![allow(non_upper_case_globals)]
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
@@ -208,11 +211,11 @@ impl From<in6_addr> for Ipv6Addr {
         #[cfg(target_os = "macos")]
         return Ipv6Addr::from(unsafe { item.__u6_addr.__u6_addr8 });
 
+        #[cfg(target_os = "linux")]
         // SAFETY: Access union field. This is safe because we are
         // accessing the underlying byte array representation of the
         // `in6_addr` struct on Linux and all variants have the same
         // size.
-        #[cfg(target_os = "linux")]
         return Ipv6Addr::from(unsafe { item.__in6_u.__u6_addr8 });
 
         // SAFETY: Access union field. This is safe because we are
diff --git a/rust/libslirp-rs/tests/integration_test.rs b/rust/libslirp-rs/tests/integration_test.rs
index 449dc65a..67fd33c4 100644
--- a/rust/libslirp-rs/tests/integration_test.rs
+++ b/rust/libslirp-rs/tests/integration_test.rs
@@ -28,7 +28,7 @@ fn it_shutdown() {
     let before_fd_count = count_open_fds().unwrap();
 
     let (tx, rx) = mpsc::channel::<Bytes>();
-    let slirp = LibSlirp::new(config, tx, None);
+    let slirp = LibSlirp::new(config, tx, None, None);
     slirp.shutdown();
     assert_eq!(
         rx.recv_timeout(Duration::from_millis(5)),
diff --git a/rust/libslirp-rs/tests/integration_udp.rs b/rust/libslirp-rs/tests/integration_udp.rs
index b169771c..2fd30f52 100644
--- a/rust/libslirp-rs/tests/integration_udp.rs
+++ b/rust/libslirp-rs/tests/integration_udp.rs
@@ -37,7 +37,7 @@ fn udp_echo() {
     let before_fd_count = count_open_fds().unwrap();
 
     let (tx, rx) = mpsc::channel::<Bytes>();
-    let slirp = LibSlirp::new(config, tx, None);
+    let slirp = LibSlirp::new(config, tx, None, None);
 
     // Start up an IPV4 UDP echo server
     let server_addr = one_shot_udp_echo_server().unwrap();
diff --git a/rust/packets/build.rs b/rust/packets/build.rs
index 1c2c3e7c..df3fdd96 100644
--- a/rust/packets/build.rs
+++ b/rust/packets/build.rs
@@ -13,9 +13,13 @@
 //  See the License for the specific language governing permissions and
 //  limitations under the License.
 
+//! Build script for linking `netsim-packets` crate with dependencies.
+
 use std::env;
 use std::path::PathBuf;
 
+/// Locates and copies prebuilt Rust packet definition files into the
+/// output directory (`OUT_DIR`).
 fn main() {
     // Locate prebuilt pdl generated rust packet definition files
     let prebuilts: [[&str; 2]; 5] = [
diff --git a/rust/packets/src/ieee80211.rs b/rust/packets/src/ieee80211.rs
index 5db8a255..87d2b7aa 100644
--- a/rust/packets/src/ieee80211.rs
+++ b/rust/packets/src/ieee80211.rs
@@ -23,7 +23,20 @@ include!(concat!(env!("OUT_DIR"), "/ieee80211_packets.rs"));
 use crate::llc::{EtherType, LlcCtrl, LlcSap, LlcSnapHeader};
 use anyhow::anyhow;
 
+// Constants for field lengths
 const ETHERTYPE_LEN: usize = 2;
+pub const CCMP_HDR_LEN: usize = 8;
+
+// Constants for Ieee80211 definitions.
+// Reference: external/wpa_supplicant_8/src/common/ieee802_11_defs.h
+const WLAN_FC_RETRY: u16 = 0x0800;
+const WLAN_FC_PWRMGT: u16 = 0x1000;
+const WLAN_FC_MOREDATA: u16 = 0x2000;
+const WLAN_FC_ISWEP: u16 = 0x4000;
+const WLAN_ACTION_PUBLIC: u8 = 4;
+const WLAN_ACTION_HT: u8 = 7;
+const WLAN_ACTION_SELF_PROTECTED: u8 = 15;
+const WLAN_ACTION_VENDOR_SPECIFIC: u8 = 127;
 
 /// A Ieee80211 MAC address
 
@@ -131,7 +144,7 @@ impl<'a> Ieee8023<'a> {
 }
 
 impl Ieee80211 {
-    // Create Ieee80211 from Ieee8023 frame.
+    /// Create Ieee80211 from Ieee8023 frame.
     pub fn from_ieee8023(packet: &[u8], bssid: MacAddress) -> anyhow::Result<Ieee80211> {
         let ieee8023 = Ieee8023::from(packet)?;
 
@@ -167,40 +180,216 @@ impl Ieee80211 {
         .try_into()?)
     }
 
-    // Frame has addr4 field
+    /// Frame has addr4 field
     pub fn has_a4(&self) -> bool {
-        self.to_ds == 1 || self.from_ds == 1
+        self.to_ds == 1 && self.from_ds == 1
     }
 
+    /// Frame is sent to ap
     pub fn is_to_ap(&self) -> bool {
         self.to_ds == 1 && self.from_ds == 0
     }
 
-    // Frame type is management
+    /// Frame type is management
     pub fn is_mgmt(&self) -> bool {
         self.ftype == FrameType::Mgmt
     }
 
-    // Frame is (management) beacon frame
+    /// Generates the Additional Authentication Data (AAD) for CCMP encryption.
+    ///
+    /// Reference Linux kernel net/mac80211/wpa.c
+    pub fn get_aad(&self) -> Vec<u8> {
+        // Initialize AAD with header length - 2 bytes (no duration id)
+        let hdr_len = self.hdr_length();
+        let mut aad = vec![0u8; hdr_len - 2];
+
+        // Construct the Frame Control bytes for the AAD:
+        aad[0] = (self.version as u8) | (self.ftype as u8) << 2 | (self.stype as u8) << 4;
+
+        if !self.is_mgmt() {
+            // Clear the first three bits of stype (bits 4, 5, and 6)
+            aad[0] &= !(0x07 << 4);
+        }
+
+        aad[1] = (self.to_ds as u8) << 0
+        | (self.from_ds as u8) << 1
+        | (self.more_frags as u8) << 2
+        | (0 << 3) // Clear Retry bit
+        | (0 << 4) // Clear Power Management bit
+        | (0 << 5) // Clear More Data bit
+        | (1 << 6) // Set Protected Frame bit
+        | (self.order as u8) << 7;
+
+        // Insert 3 MAC Addresses ( 3 * 6 = 18 bytes):
+        aad[2..20].copy_from_slice(&self.payload[..18]);
+        // Insert Masked Sequence Control.
+        aad[20] = (self.payload[18] & 0x0f) as u8;
+        // aad[21] is set to 0 by default
+
+        // Handle Address 4 and QoS Control field (TID) as applicable
+        if self.has_a4() {
+            aad[22..28].copy_from_slice(&self.payload[20..26]);
+            if self.is_qos_data() {
+                aad[28] = self.get_qos_tid();
+            }
+        } else if self.is_qos_data() {
+            aad[22] = self.get_qos_tid();
+        }
+
+        aad
+    }
+
+    /// Calculates the length of the IEEE 802.11 frame header.
+    pub fn hdr_length(&self) -> usize {
+        // Base header length is 24. +6 if Addr4 is used. +2 for QoS Data
+        24 + (6 * self.has_a4() as usize) + (2 * self.is_qos_data() as usize)
+    }
+
+    /// Frame is a QoS Data frame
+    pub fn is_qos_data(&self) -> bool {
+        self.is_data() && self.stype == DataSubType::Qos as u8
+    }
+
+    /// Retrieves the QoS TID (Traffic Identifier) from the IEEE 802.11 frame
+    pub fn get_qos_tid(&self) -> u8 {
+        if !self.is_qos_data() {
+            return 0; // No QoS Control field, return default TID 0
+        }
+
+        // QOS TID is last 2 bytes of header
+        let qos_offset = self.hdr_length() - 2;
+        // Extract the QoS TID
+        let qos_control = u16::from_be_bytes(
+            self.payload[qos_offset..qos_offset + 2]
+                .try_into()
+                .expect("Failed to convert QoS control bytes"),
+        );
+
+        (qos_control >> 8) as u8
+    }
+
+    /// Retrieves the QoS Control field from the IEEE 802.11 frame
+    pub fn get_qos_control(&self) -> u16 {
+        if !self.is_qos_data() {
+            return 0;
+        }
+        u16::from_be_bytes(
+            self.get_payload()[2..4].try_into().expect("Failed to convert QoS control bytes"),
+        )
+    }
+
+    /// Extracts the Packet Number (PN) from the IEEE 802.11 frame
+    pub fn get_packet_number(&self) -> [u8; 6] {
+        let body_pos = self.hdr_length() - 4;
+        let frame_body = &self.payload[body_pos..(body_pos + 8)]; // Get the packet num from frame
+
+        // Extract the PN bytes in the specified order
+        [frame_body[7], frame_body[6], frame_body[5], frame_body[4], frame_body[1], frame_body[0]]
+    }
+
+    /// Generates the Nonce for CCMP encryption
+    ///
+    /// Reference Linux kernel net/mac80211/wpa.c
+    pub fn get_nonce(&self, pn: &[u8]) -> [u8; 13] {
+        let qos_tid = self.get_qos_tid();
+        let mgmt_flag = self.is_mgmt() as u8;
+        let addr2 = self.get_addr2().to_vec();
+        let mut nonce = [0u8; 13];
+        // Construct the nonce using qos_tid, mgmt bit, addr2, and pn
+        nonce[0] = qos_tid | (mgmt_flag << 4);
+        nonce[1..7].copy_from_slice(&addr2);
+        nonce[7..].copy_from_slice(pn);
+        nonce
+    }
+
+    /// Check if the frame is multicast based on the destination address
+    pub fn is_multicast(&self) -> bool {
+        self.get_addr1().is_multicast()
+    }
+
+    /// Check if the frame is broadcast based on the destination address
+    pub fn is_broadcast(&self) -> bool {
+        self.get_addr1().is_broadcast()
+    }
+
+    /// Frame is Robust Management frame
+    ///
+    /// Reference Linux kernel include/linux/ieee80211.h
+    pub fn is_robust_mgmt(&self) -> bool {
+        if self.payload.len() < 21 || !self.is_mgmt() {
+            // 25 - 4 (fc and duration id)
+            return false;
+        }
+
+        match ManagementSubType::try_from(self.stype).unwrap() {
+            // Disassoc and Deauth are robust mgmt
+            ManagementSubType::Disassoc | ManagementSubType::Deauth => true,
+            /*
+             * Action frames, excluding Public Action frames, are Robust
+             * Management Frames. However, if we are looking at a Protected
+             * frame, skip the check since the data may be encrypted and
+             * the frame has already been found to be a Robust Management
+             * Frame (by the other end).
+             */
+            ManagementSubType::Action => {
+                if self.is_protected() {
+                    return true; // Assume protected Action frames are robust
+                }
+                // Access category at offset 20 (24 - 2 frame control - 2 dutation id)
+                let category = u8::from_be_bytes([self.payload[20]]);
+
+                !matches!(
+                    category,
+                    WLAN_ACTION_PUBLIC
+                        | WLAN_ACTION_HT
+                        | WLAN_ACTION_SELF_PROTECTED
+                        | WLAN_ACTION_VENDOR_SPECIFIC
+                )
+            }
+            _ => false, // Other management frames are not robust by default
+        }
+    }
+
+    /// Frame is (management) beacon frame
     pub fn is_beacon(&self) -> bool {
         self.ftype == FrameType::Mgmt && self.stype == (ManagementSubType::Beacon as u8)
     }
 
-    // Frame type is data
+    /// Frame type is data
     pub fn is_data(&self) -> bool {
         self.ftype == FrameType::Data
     }
 
-    // Frame is probe request
+    /// Frame is probe request
     pub fn is_probe_req(&self) -> bool {
         self.ftype == FrameType::Ctl && self.stype == (ManagementSubType::ProbeReq as u8)
     }
 
-    // Frame type is EAPoL
+    /// Frame is protected
+    pub fn is_protected(&self) -> bool {
+        self.protected != 0u8
+    }
+
+    /// Frame type is EAPoL
     pub fn is_eapol(&self) -> anyhow::Result<bool> {
         Ok(self.get_ethertype()? == EtherType::Eapol)
     }
 
+    /// Whether frame needs to be encrypted
+    pub fn needs_encryption(&self) -> bool {
+        !self.is_protected() && (self.is_data() || self.is_robust_mgmt())
+    }
+
+    /// Whether frame needs to be decrypted
+    pub fn needs_decryption(&self) -> bool {
+        self.is_protected() && (self.is_data() || self.is_robust_mgmt())
+    }
+
+    /// Set whether frame is protected
+    pub fn set_protected(&mut self, protected: bool) {
+        self.protected = protected.into();
+    }
+
     pub fn get_ds(&self) -> String {
         match self.specialize().unwrap() {
             Ieee80211Child::Ieee80211ToAp(hdr) => "ToAp",
@@ -255,6 +444,16 @@ impl Ieee80211 {
         }
     }
 
+    pub fn get_addr2(&self) -> MacAddress {
+        match self.specialize().unwrap() {
+            Ieee80211Child::Ieee80211Ibss(hdr) => hdr.source,
+            Ieee80211Child::Ieee80211FromAp(hdr) => hdr.bssid,
+            Ieee80211Child::Ieee80211ToAp(hdr) => hdr.source,
+            Ieee80211Child::Ieee80211Wds(hdr) => hdr.transmitter,
+            _ => panic!("unexpected specialized header"),
+        }
+    }
+
     pub fn get_ssid_from_beacon_frame(&self) -> anyhow::Result<String> {
         // Verify packet is a beacon frame
         if !self.is_beacon() {
@@ -630,6 +829,34 @@ mod tests {
         .unwrap()
     }
 
+    fn create_test_wds_ieee80211(
+        receiver: MacAddress,
+        transmitter: MacAddress,
+        destination: MacAddress,
+        source: MacAddress,
+    ) -> Ieee80211 {
+        Ieee80211Wds {
+            duration_id: 0,
+            ftype: FrameType::Mgmt,
+            more_data: 0,
+            more_frags: 0,
+            order: 0,
+            pm: 0,
+            protected: 0,
+            retry: 0,
+            stype: 0,
+            version: 0,
+            receiver,
+            transmitter,
+            destination,
+            seq_ctrl: 0,
+            source,
+            payload: Vec::new(),
+        }
+        .try_into()
+        .unwrap()
+    }
+
     fn test_with_address(
         create_test_ieee80211: fn(MacAddress, MacAddress, MacAddress) -> Ieee80211,
     ) {
@@ -718,4 +945,18 @@ mod tests {
         assert_eq!(&ethernet_frame[6..12], source.to_vec().as_slice()); // Source MAC
         assert_eq!(&ethernet_frame[12..14], [0x08, 0x00]); // EtherType
     }
+
+    #[test]
+    fn test_has_a4() {
+        let addr1 = parse_mac_address("01:02:03:00:00:01").unwrap();
+        let addr2 = parse_mac_address("01:02:03:00:00:02").unwrap();
+        let addr3 = parse_mac_address("01:02:03:00:00:03").unwrap();
+        let addr4 = parse_mac_address("01:02:03:00:00:04").unwrap();
+
+        // Only WDS has addr4
+        assert!(!create_test_from_ap_ieee80211(addr1, addr2, addr3).has_a4());
+        assert!(!create_test_ibss_ieee80211(addr1, addr2, addr3).has_a4());
+        assert!(!create_test_to_ap_ieee80211(addr1, addr2, addr3).has_a4());
+        assert!(create_test_wds_ieee80211(addr1, addr2, addr3, addr4).has_a4());
+    }
 }
diff --git a/scripts/cargo_env.sh b/scripts/cargo_env.sh
index 5fc99d3b..dc09e0ca 100755
--- a/scripts/cargo_env.sh
+++ b/scripts/cargo_env.sh
@@ -36,6 +36,13 @@ function setup_cargo_env {
   export CARGO_HOME=$OUT_PATH/rust/.cargo
   export OBJS_PATH=$OUT_PATH
   export GRPCIO_SYS_GRPC_INCLUDE_PATH=$REPO/external/grpc/include
+  if [[ "$OS" == "linux" ]]; then
+    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$OUT_PATH/toolchain/x86_64-linux-g++
+    env 'CC_x86_64-unknown-linux-gnu=$OUT_PATH/toolchain/x86_64-linux-gcc'
+    env 'CXX_x86_64-unknown-linux-gnu=$OUT_PATH/toolchain/x86_64-linux-g++'
+    env 'AR_x86_64-unknown-linux-gnu=$REPO/prebuilts/clang/host/linux-x86/llvm-binutils-stable/llvm-ar'
+    export CORROSION_BUILD_DIR=$OUT_PATH/rust
+  fi
 
   # Paths to pdl generated packets files
   local ROOTCANAL_PDL_PATH=$OUT_PATH/rootcanal/pdl_gen
diff --git a/scripts/cpu_usage.py b/scripts/cpu_usage.py
new file mode 100755
index 00000000..1bdd7959
--- /dev/null
+++ b/scripts/cpu_usage.py
@@ -0,0 +1,211 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the',  help="License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an',  help="AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+import argparse
+import csv
+import datetime
+import os
+import platform
+import subprocess
+import time
+import psutil
+import requests
+
+PLATFORM_SYSTEM = platform.system().lower()
+QEMU_ARCH_MAP = {'arm64': 'aarch64', 'AMD64': 'x86_64'}
+PLATFORM_MACHINE = QEMU_ARCH_MAP.get(platform.machine(), platform.machine())
+TEST_DURATION = 300
+CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
+EXE_SUFFIX = '.exe' if PLATFORM_SYSTEM == 'windows' else ''
+NETSIMD_BINARY = f'netsimd{EXE_SUFFIX}'
+NETSIM_FRONTEND_HTTP_URI = 'http://localhost:7681'
+EMULATOR_BINARY = f'emulator{EXE_SUFFIX}'
+QEMU_SYSTEM_BINARY = f'qemu-system-{PLATFORM_MACHINE}{EXE_SUFFIX}'
+
+
+def _get_cpu_usage():
+  """Retrieves CPU and memory usage for netsimd and qemu."""
+  netsimd_usage, qemu_usage = [], []
+
+  for process in psutil.process_iter(
+      ['name', 'cpu_percent', 'num_threads', 'memory_info']
+  ):
+    process_name = process.info['name']
+    if process_name == NETSIMD_BINARY:
+      netsimd_usage.append(process.info)
+    elif process_name == QEMU_SYSTEM_BINARY:
+      qemu_usage.append(process.info)
+
+  def _validate_and_extract(process_list, process_name):
+    if len(process_list) > 1:
+      raise LookupError(f'Multiple {process_name} processes found')
+    if not process_list:
+      raise LookupError(f'Process {process_name} not found')
+    return process_list[0]
+
+  netsimd_info = _validate_and_extract(netsimd_usage, NETSIMD_BINARY)
+  qemu_info = _validate_and_extract(qemu_usage, QEMU_SYSTEM_BINARY)
+
+  return (
+      netsimd_info['cpu_percent'],
+      qemu_info['cpu_percent'],
+      netsimd_info['num_threads'],
+      netsimd_info['memory_info'].rss / 1024 / 1024,
+  )
+
+
+def _process_usage_iteration(writer, avd, netsim_wifi, iteration):
+  """Collects and writes usage data for a single iteration."""
+  try:
+    netsimd_cpu, qemu_cpu, netsimd_threads, netsimd_mem = _get_cpu_usage()
+    if iteration == 0:
+      time.sleep(0.1)
+      return
+    data = [time.time(), netsimd_cpu, qemu_cpu, netsimd_threads, netsimd_mem]
+    if netsim_wifi:
+      data.extend(_get_wifi_packet_count(avd))
+    print(f'Got {data}')
+    writer.writerow(data)
+  except LookupError as e:
+    print(e)
+    time.sleep(1)
+  time.sleep(1)
+
+
+def _trace_usage(filename: str, avd: str, netsim_wifi: bool):
+  """Traces usage data and writes to a CSV file."""
+  with open(filename, 'w', newline='') as csvfile:
+    writer = csv.writer(csvfile)
+    headers = [
+        'Timestamp',
+        NETSIMD_BINARY,
+        QEMU_SYSTEM_BINARY,
+        'NetSimThreads',
+        'NetSimMemUsage(MB)',
+    ]
+    if netsim_wifi:
+      headers.extend(['txCount', 'rxCount'])
+    writer.writerow(headers)
+    for i in range(TEST_DURATION):
+      _process_usage_iteration(writer, avd, netsim_wifi, i)
+
+
+def _launch_emulator(cmd):
+  """Utility function for launching Emulator"""
+  if PLATFORM_SYSTEM == 'windows':
+    return subprocess.Popen(
+        cmd,
+        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
+    )
+  else:
+    return subprocess.Popen(cmd)
+
+
+def _terminate_emulator(process):
+  """Utility function for terminating Emulator"""
+  try:
+    if PLATFORM_SYSTEM == 'windows':
+      import signal
+
+      process.send_signal(signal.CTRL_BREAK_EVENT)
+      process.wait()
+    else:
+      process.terminate()
+  except OSError:
+    print('Process already termianted')
+
+
+def _get_wifi_packet_count(avd: str):
+  """Utility function for getting WiFi Packet Counts.
+
+  Returns (txCount, rxCount)
+  """
+  avd = avd.replace('_', ' ')
+  try:
+    response = requests.get(NETSIM_FRONTEND_HTTP_URI + '/v1/devices')
+    response.raise_for_status()
+    for device in response.json()['devices']:
+      if device['name'] == avd:
+        for chip in device['chips']:
+          if chip['kind'] == 'WIFI':
+            return (chip['wifi']['txCount'], chip['wifi']['rxCount'])
+  except requests.exceptions.RequestException as e:
+    print(f'Request Error: {e}')
+  except KeyError as e:
+    print(f'KeyError: {e}')
+  except IndexError as e:
+    print(f'IndexError: {e}')
+  return (0, 0)
+
+
+def _collect_cpu_usage(avd: str, netsim_wifi: bool):
+  """Utility function for running the CPU usage collection session"""
+  # Setup cmd and filename to trace
+  time_now = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
+  cmd = [f'{CURRENT_PATH}/{EMULATOR_BINARY}', '-avd', avd, '-wipe-data']
+  filename = (
+      f'netsimd_cpu_usage_{PLATFORM_SYSTEM}_{PLATFORM_MACHINE}_{time_now}.csv'
+  )
+  if netsim_wifi:
+    cmd.extend(['-feature', 'WiFiPacketStream'])
+    filename = f'netsimd_cpu_usage_{PLATFORM_SYSTEM}_{PLATFORM_MACHINE}_WiFiPacketStream_{time_now}.csv'
+
+  # Launch emulator
+  process = _launch_emulator(cmd)
+
+  # Enough time for Emulator to boot
+  time.sleep(10)
+
+  # Trace CPU usage
+  _trace_usage(filename, avd, netsim_wifi)
+
+  # Terminate Emulator Process
+  _terminate_emulator(process)
+
+
+def main():
+  # Check if ANDROID_SDK_ROOT env is defined
+  if 'ANDROID_SDK_ROOT' not in os.environ:
+    print('Please set ANDROID_SDK_ROOT')
+    return
+
+  # Check if Emulator Binary exists
+  emulator_path = f'{CURRENT_PATH}/{EMULATOR_BINARY}'
+  if not os.path.isfile(emulator_path):
+    print(
+        f"Can't find {emulator_path}. Please place the file with the binaries"
+        ' before executing.'
+    )
+    return
+
+  # Set avd provided by the user
+  parser = argparse.ArgumentParser()
+  parser.add_argument('avd', help='The AVD to use', type=str)
+  args = parser.parse_args()
+
+  # Collect CPU usage without netsim WiFi
+  _collect_cpu_usage(args.avd, False)
+
+  # Enough time for Emulator to terminate
+  time.sleep(10)
+
+  # Collect CPU usage with netsim WiFi
+  _collect_cpu_usage(args.avd, True)
+
+  print('CPU Usage Completed!')
+
+
+if __name__ == '__main__':
+  main()
diff --git a/scripts/rs-loc.sh b/scripts/rs-loc.sh
new file mode 100755
index 00000000..783b7e17
--- /dev/null
+++ b/scripts/rs-loc.sh
@@ -0,0 +1,29 @@
+#!/bin/bash
+
+# Copyright 2023 The Android Open Source Project
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
+
+# Report lines of code
+
+# git checkout `git rev-list -n 1 --before="2023-01-01 12:00" main`
+
+rust=`git ls-files | grep 'rs$' | xargs cat | wc -l`
+cc=`git ls-files | grep '\.h$\|\.cc$' | xargs cat | wc -l`
+cc_percent=$(( (${cc} * 100)/(${rust} + ${cc}) ))
+rust_percent=$(( (${rust} * 100)/(${rust} + ${cc}) ))
+
+echo "cc ${cc} ${cc_percent}%"
+echo "rs ${rust} ${rust_percent}%"
+
diff --git a/scripts/tasks/install_emulator_task.py b/scripts/tasks/install_emulator_task.py
index dfc6a5b4..9c23aebe 100644
--- a/scripts/tasks/install_emulator_task.py
+++ b/scripts/tasks/install_emulator_task.py
@@ -43,8 +43,8 @@ class InstallEmulatorTask(Task):
     super().__init__("InstallEmulator")
     self.buildbot = args.buildbot
     self.out_dir = args.out_dir
-    # Local fetching use only - default to emulator-linux_x64
-    self.target = args.emulator_target
+    # Local fetching use only - default to emulator-linux_x64_gfxstream
+    self.target = args.emulator_target + "_gfxstream"
     # Local Emulator directory
     self.local_emulator_dir = args.local_emulator_dir
 
@@ -186,20 +186,17 @@ class InstallEmulatorManager:
       shutil.copytree(
           Path(self.out_dir) / "distribution" / "emulator",
           emulator_filepath,
-          symlinks=True,
           dirs_exist_ok=True,
       )
     else:
       shutil.copytree(
           emulator_filepath,
           OBJS_DIR,
-          symlinks=True,
           dirs_exist_ok=True,
       )
       shutil.copytree(
           emulator_filepath,
           OBJS_DIR / "distribution" / "emulator",
-          symlinks=True,
           dirs_exist_ok=True,
       )
 
diff --git a/scripts/tasks/run_test_task.py b/scripts/tasks/run_test_task.py
index bd0aba65..b07a9fbc 100644
--- a/scripts/tasks/run_test_task.py
+++ b/scripts/tasks/run_test_task.py
@@ -20,6 +20,8 @@ import platform
 from tasks.task import Task
 from utils import (AOSP_ROOT, run, rust_version)
 
+PLATFORM_SYSTEM = platform.system()
+
 
 class RunTestTask(Task):
 
@@ -31,31 +33,50 @@ class RunTestTask(Task):
 
   def do_run(self):
     # TODO(b/379745416): Support clippy for Mac and Windows
-    if platform.system() == "Linux":
-      # Set Clippy flags
-      clippy_flags = [
+    if PLATFORM_SYSTEM == "Linux":
+
+      def run_clippy(flags):
+        run(
+            [
+                AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_clippy.sh",
+                str(self.out),
+                rust_version(),
+                " ".join(flags),
+            ],
+            self.env,
+            "clippy",
+        )
+
+      # Default Rust lints in Android. Reference: build/soong/rust/config/lints.go
+      default_clippy_flags = [
+          # Default rustc Lints from main build
+          "-A deprecated",
+          "-A unknown_lints",
+          "-D missing-docs",
+          "-D warnings",
+          "-D unsafe_op_in_unsafe_fn",
+          # Default Clippy lints from main build
           "-A clippy::disallowed_names",
+          "-A clippy::empty_line_after_doc_comments",
           "-A clippy::type-complexity",
+          # TODO: Enable once prebuilt clippy is updated to 1.75.0+
+          # "-A clippy::unnecessary_fallible_conversions",
           "-A clippy::unnecessary-wraps",
           "-A clippy::unusual-byte-groupings",
           "-A clippy::upper-case-acronyms",
-          "-W clippy::undocumented_unsafe_blocks",
+          "-D clippy::undocumented_unsafe_blocks",
+      ]
+      # Additional lints for our project.
+      additional_clippy_flags = [
           "-W clippy::cognitive-complexity",
       ]
-      # Run cargo clippy
-      run(
-          [
-              AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_clippy.sh",
-              str(self.out),
-              rust_version(),
-              " ".join(clippy_flags),
-          ],
-          self.env,
-          "clippy",
-      )
+      # Run cargo clippy with default flags
+      run_clippy(default_clippy_flags)
+      # Run cargo clippy with additional flags
+      run_clippy(additional_clippy_flags)
 
     # Set script for cargo Test
-    if platform.system() == "Windows":
+    if PLATFORM_SYSTEM == "Windows":
       script = AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_test.cmd"
     else:
       script = AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_test.sh"
@@ -65,13 +86,17 @@ class RunTestTask(Task):
         "hostapd-rs",
         "libslirp-rs",
         "http-proxy",
+        "netsim-cli",
         "netsim-common",
         "netsim-daemon",
         "netsim-packets",
         "capture",
     ]:
       # TODO(b/379708365): Resolve netsim-daemon test for Mac & Windows
-      if package == "netsim-daemon" and platform.system() != "Linux":
+      if (
+          package in ["netsim-daemon", "netsim-cli"]
+          and PLATFORM_SYSTEM != "Linux"
+      ):
         continue
       cmd = [script, package, str(self.out), rust_version()]
       run(cmd, self.env, f"{package}_unit_tests")
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 240d1f5e..84aed95a 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -17,29 +17,6 @@ if(NOT NETSIM_EXT)
 endif()
 
 if(TARGET Rust::Rustc)
-  set(cxx_bridge_binary_folder
-      ${CMAKE_BINARY_DIR}/cargo/build/${Rust_CARGO_TARGET_CACHED}/cxxbridge)
-  set(common_header ${cxx_bridge_binary_folder}/rust/cxx.h)
-  set(cxx_bridge_source_file "src/ffi.rs")
-  set(crate_name "netsim-cli")
-  set(binding_header
-      ${cxx_bridge_binary_folder}/${crate_name}/${cxx_bridge_source_file}.h)
-  set(binding_source
-      ${cxx_bridge_binary_folder}/${crate_name}/${cxx_bridge_source_file}.cc)
-
-  # Make sure we have the cxx files generated before we build them.
-  add_custom_command(OUTPUT ${common_header} ${binding_header} ${binding_source}
-                     COMMAND DEPENDS ${crate_name}-static)
-
-  android_add_library(
-    TARGET frontend-client
-    LICENSE Apache-2.0
-    SRC ${binding_header} ${binding_source} ${common_header}
-        frontend/frontend_client.cc frontend/frontend_client.h
-    DEPS grpc++ netsim-cli-proto-lib protobuf::libprotobuf util-lib)
-  target_include_directories(frontend-client PRIVATE .
-                             PUBLIC ${cxx_bridge_binary_folder})
-
   set(cxx_bridge_binary_folder
       ${CMAKE_BINARY_DIR}/cargo/build/${Rust_CARGO_TARGET_CACHED}/cxxbridge)
   set(common_header ${cxx_bridge_binary_folder}/rust/cxx.h)
@@ -60,7 +37,6 @@ if(TARGET Rust::Rustc)
     SRC ${binding_header}
         ${binding_source}
         ${common_header}
-        frontend/server_response_writable.h
         hci/async_manager.cc
         hci/bluetooth_facade.cc
         hci/bluetooth_facade.h
diff --git a/src/frontend/frontend_client.cc b/src/frontend/frontend_client.cc
deleted file mode 100644
index 9b3b3875..00000000
--- a/src/frontend/frontend_client.cc
+++ /dev/null
@@ -1,270 +0,0 @@
-// Copyright 2022 The Android Open Source Project
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
-// Frontend client
-#include "frontend/frontend_client.h"
-
-#include <google/protobuf/util/json_util.h>
-#include <grpcpp/support/status.h>
-
-#include <chrono>
-#include <cstdint>
-#include <memory>
-#include <string>
-
-#include "google/protobuf/empty.pb.h"
-#include "grpcpp/create_channel.h"
-#include "grpcpp/security/credentials.h"
-#include "grpcpp/support/status_code_enum.h"
-#include "netsim-cli/src/ffi.rs.h"
-#include "netsim/frontend.grpc.pb.h"
-#include "netsim/frontend.pb.h"
-#include "netsim/model.pb.h"
-#include "util/log.h"
-#include "util/os_utils.h"
-
-namespace netsim {
-namespace frontend {
-namespace {
-const std::chrono::duration kConnectionDeadline = std::chrono::seconds(1);
-
-std::unique_ptr<frontend::FrontendService::Stub> NewFrontendStub(
-    std::string server) {
-  if (server == "") {
-    return {};
-  }
-  std::shared_ptr<grpc::Channel> channel =
-      grpc::CreateChannel(server, grpc::InsecureChannelCredentials());
-
-  auto deadline = std::chrono::system_clock::now() + kConnectionDeadline;
-  if (!channel->WaitForConnected(deadline)) {
-    BtsLogWarn("Frontend gRPC channel not connected");
-    return nullptr;
-  }
-
-  return frontend::FrontendService::NewStub(channel);
-}
-
-// A synchronous client for the netsim frontend service.
-class FrontendClientImpl : public FrontendClient {
- public:
-  FrontendClientImpl(std::unique_ptr<frontend::FrontendService::Stub> stub)
-      : stub_(std::move(stub)) {}
-
-  std::unique_ptr<ClientResult> make_result(
-      const grpc::Status &status,
-      const google::protobuf::Message &message) const {
-    std::vector<unsigned char> message_vec(message.ByteSizeLong());
-    message.SerializeToArray(message_vec.data(), message_vec.size());
-    if (!status.ok()) {
-      return std::make_unique<ClientResult>(false, status.error_message(),
-                                            message_vec);
-    }
-    return std::make_unique<ClientResult>(true, "", message_vec);
-  }
-
-  // Gets the version of the network simulator service.
-  std::unique_ptr<ClientResult> GetVersion() const override {
-    frontend::VersionResponse response;
-    grpc::ClientContext context_;
-    auto status = stub_->GetVersion(&context_, {}, &response);
-    return make_result(status, response);
-  }
-
-  // Gets the list of device information
-  std::unique_ptr<ClientResult> ListDevice() const override {
-    frontend::ListDeviceResponse response;
-    grpc::ClientContext context_;
-    auto status = stub_->ListDevice(&context_, {}, &response);
-    return make_result(status, response);
-  }
-
-  std::unique_ptr<ClientResult> Reset() const override {
-    grpc::ClientContext context_;
-    google::protobuf::Empty response;
-    auto status = stub_->Reset(&context_, {}, &response);
-    return make_result(status, response);
-  }
-
-  std::unique_ptr<ClientResult> CreateDevice(
-      rust::Vec<::rust::u8> const &request_byte_vec) const {
-    frontend::CreateDeviceResponse response;
-    grpc::ClientContext context_;
-    frontend::CreateDeviceRequest request;
-    if (!request.ParseFromArray(request_byte_vec.data(),
-                                request_byte_vec.size())) {
-      return make_result(
-          grpc::Status(
-              grpc::StatusCode::INVALID_ARGUMENT,
-              "Error parsing CreateDevice request protobuf. request size:" +
-                  std::to_string(request_byte_vec.size())),
-          response);
-    }
-    auto status = stub_->CreateDevice(&context_, request, &response);
-    return make_result(status, response);
-  }
-
-  // Patchs the information of the device
-  std::unique_ptr<ClientResult> PatchDevice(
-      rust::Vec<::rust::u8> const &request_byte_vec) const override {
-    google::protobuf::Empty response;
-    grpc::ClientContext context_;
-    frontend::PatchDeviceRequest request;
-    if (!request.ParseFromArray(request_byte_vec.data(),
-                                request_byte_vec.size())) {
-      return make_result(
-          grpc::Status(
-              grpc::StatusCode::INVALID_ARGUMENT,
-              "Error parsing PatchDevice request protobuf. request size:" +
-                  std::to_string(request_byte_vec.size())),
-          response);
-    };
-    auto status = stub_->PatchDevice(&context_, request, &response);
-    return make_result(status, response);
-  }
-
-  std::unique_ptr<ClientResult> DeleteChip(
-      rust::Vec<::rust::u8> const &request_byte_vec) const {
-    google::protobuf::Empty response;
-    grpc::ClientContext context_;
-    frontend::DeleteChipRequest request;
-    if (!request.ParseFromArray(request_byte_vec.data(),
-                                request_byte_vec.size())) {
-      return make_result(
-          grpc::Status(
-              grpc::StatusCode::INVALID_ARGUMENT,
-              "Error parsing DeleteChip request protobuf. request size:" +
-                  std::to_string(request_byte_vec.size())),
-          response);
-    }
-    auto status = stub_->DeleteChip(&context_, request, &response);
-    return make_result(status, response);
-  }
-
-  // Get the list of Capture information
-  std::unique_ptr<ClientResult> ListCapture() const override {
-    frontend::ListCaptureResponse response;
-    grpc::ClientContext context_;
-    auto status = stub_->ListCapture(&context_, {}, &response);
-    return make_result(status, response);
-  }
-
-  // Patch the Capture
-  std::unique_ptr<ClientResult> PatchCapture(
-      rust::Vec<::rust::u8> const &request_byte_vec) const override {
-    google::protobuf::Empty response;
-    grpc::ClientContext context_;
-    frontend::PatchCaptureRequest request;
-    if (!request.ParseFromArray(request_byte_vec.data(),
-                                request_byte_vec.size())) {
-      return make_result(
-          grpc::Status(
-              grpc::StatusCode::INVALID_ARGUMENT,
-              "Error parsing PatchCapture request protobuf. request size:" +
-                  std::to_string(request_byte_vec.size())),
-          response);
-    };
-    auto status = stub_->PatchCapture(&context_, request, &response);
-    return make_result(status, response);
-  }
-
-  // Download capture file by using ClientResponseReader to handle streaming
-  // grpc
-  std::unique_ptr<ClientResult> GetCapture(
-      rust::Vec<::rust::u8> const &request_byte_vec,
-      ClientResponseReader const &client_reader) const override {
-    grpc::ClientContext context_;
-    frontend::GetCaptureRequest request;
-    if (!request.ParseFromArray(request_byte_vec.data(),
-                                request_byte_vec.size())) {
-      return make_result(
-          grpc::Status(
-              grpc::StatusCode::INVALID_ARGUMENT,
-              "Error parsing GetCapture request protobuf. request size:" +
-                  std::to_string(request_byte_vec.size())),
-          google::protobuf::Empty());
-    };
-    auto reader = stub_->GetCapture(&context_, request);
-    frontend::GetCaptureResponse chunk;
-    // Read every available chunks from grpc reader
-    while (reader->Read(&chunk)) {
-      // Using a mutable protobuf here so the move iterator can move
-      // the capture stream without copying.
-      auto mut_stream = chunk.mutable_capture_stream();
-      auto bytes =
-          std::vector<uint8_t>(std::make_move_iterator(mut_stream->begin()),
-                               std::make_move_iterator(mut_stream->end()));
-      client_reader.handle_chunk(
-          rust::Slice<const uint8_t>{bytes.data(), bytes.size()});
-    }
-    auto status = reader->Finish();
-    return make_result(status, google::protobuf::Empty());
-  }
-
-  // Helper function to redirect to the correct Grpc call
-  std::unique_ptr<ClientResult> SendGrpc(
-      frontend::GrpcMethod const &grpc_method,
-      rust::Vec<::rust::u8> const &request_byte_vec) const override {
-    switch (grpc_method) {
-      case frontend::GrpcMethod::GetVersion:
-        return GetVersion();
-      case frontend::GrpcMethod::CreateDevice:
-        return CreateDevice(request_byte_vec);
-      case frontend::GrpcMethod::DeleteChip:
-        return DeleteChip(request_byte_vec);
-      case frontend::GrpcMethod::PatchDevice:
-        return PatchDevice(request_byte_vec);
-      case frontend::GrpcMethod::ListDevice:
-        return ListDevice();
-      case frontend::GrpcMethod::Reset:
-        return Reset();
-      case frontend::GrpcMethod::ListCapture:
-        return ListCapture();
-      case frontend::GrpcMethod::PatchCapture:
-        return PatchCapture(request_byte_vec);
-      default:
-        return make_result(grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
-                                        "Unknown GrpcMethod found."),
-                           google::protobuf::Empty());
-    }
-  }
-
- private:
-  std::unique_ptr<frontend::FrontendService::Stub> stub_;
-
-  static bool CheckStatus(const grpc::Status &status,
-                          const std::string &message) {
-    if (status.ok()) return true;
-    if (status.error_code() == grpc::StatusCode::UNAVAILABLE)
-      BtsLogError(
-          "netsim frontend service is unavailable, "
-          "please restart.");
-    else
-      BtsLogError("request to frontend service failed (%d) - %s",
-                  status.error_code(), status.error_message().c_str());
-    return false;
-  }
-};
-
-}  // namespace
-
-std::unique_ptr<FrontendClient> NewFrontendClient(const std::string &server) {
-  auto stub = NewFrontendStub(server);
-  return (stub == nullptr
-              ? nullptr
-              : std::make_unique<FrontendClientImpl>(std::move(stub)));
-}
-
-}  // namespace frontend
-}  // namespace netsim
\ No newline at end of file
diff --git a/src/frontend/frontend_client.h b/src/frontend/frontend_client.h
deleted file mode 100644
index 4251aae0..00000000
--- a/src/frontend/frontend_client.h
+++ /dev/null
@@ -1,70 +0,0 @@
-/*
- * Copyright 2022 The Android Open Source Project
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
-// Frontend client
-#pragma once
-
-#include <cstdint>
-#include <memory>
-#include <vector>
-
-#include "rust/cxx.h"
-
-namespace netsim {
-namespace frontend {
-
-enum class GrpcMethod : ::std::uint8_t;
-struct ClientResponseReader;
-
-class ClientResult {
- public:
-  ClientResult(bool is_ok, const std::string &err,
-               const std::vector<unsigned char> &byte_vec)
-      : is_ok_(is_ok), err_(err), byte_vec_(byte_vec) {};
-
-  bool IsOk() const { return is_ok_; };
-  rust::String Err() const { return err_; };
-  const std::vector<unsigned char> &ByteVec() const { return byte_vec_; };
-
- private:
-  bool is_ok_;
-  std::string err_;
-  const std::vector<unsigned char> byte_vec_;
-};
-
-class FrontendClient {
- public:
-  virtual ~FrontendClient() {};
-  virtual std::unique_ptr<ClientResult> SendGrpc(
-      frontend::GrpcMethod const &grpc_method,
-      rust::Vec<rust::u8> const &request_byte_vec) const = 0;
-  virtual std::unique_ptr<ClientResult> GetVersion() const = 0;
-  virtual std::unique_ptr<ClientResult> ListDevice() const = 0;
-  virtual std::unique_ptr<ClientResult> PatchDevice(
-      rust::Vec<rust::u8> const &request_byte_vec) const = 0;
-  virtual std::unique_ptr<ClientResult> Reset() const = 0;
-  virtual std::unique_ptr<ClientResult> ListCapture() const = 0;
-  virtual std::unique_ptr<ClientResult> PatchCapture(
-      rust::Vec<rust::u8> const &request_byte_vec) const = 0;
-  virtual std::unique_ptr<ClientResult> GetCapture(
-      rust::Vec<::rust::u8> const &request_byte_vec,
-      ClientResponseReader const &client_reader) const = 0;
-};
-
-std::unique_ptr<FrontendClient> NewFrontendClient(const std::string &server);
-
-}  // namespace frontend
-}  // namespace netsim
diff --git a/src/frontend/server_response_writable.h b/src/frontend/server_response_writable.h
deleted file mode 100644
index 07913816..00000000
--- a/src/frontend/server_response_writable.h
+++ /dev/null
@@ -1,43 +0,0 @@
-// Copyright 2022 The Android Open Source Project
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
-#pragma once
-#include <string>
-
-#include "grpcpp/support/sync_stream.h"
-#include "netsim/frontend.pb.h"
-#include "rust/cxx.h"
-
-namespace netsim {
-namespace frontend {
-
-/// The C++ definition of the CxxServerResponseWriter interface for CXX.
-class CxxServerResponseWriter {
- public:
-  CxxServerResponseWriter() {};
-  CxxServerResponseWriter(
-      grpc::ServerWriter<netsim::frontend::GetCaptureResponse> *grpc_writer_) {
-  };
-  virtual ~CxxServerResponseWriter() = default;
-  virtual void put_error(unsigned int error_code,
-                         const std::string &response) const = 0;
-  virtual void put_ok_with_length(const std::string &mime_type,
-                                  std::size_t length) const = 0;
-  virtual void put_chunk(rust::Slice<const uint8_t> chunk) const = 0;
-  virtual void put_ok(const std::string &mime_type,
-                      const std::string &body) const = 0;
-};
-
-}  // namespace frontend
-}  // namespace netsim
diff --git a/testing/mobly/Android.bp b/testing/mobly/Android.bp
index 075ff73f..c81c8c08 100644
--- a/testing/mobly/Android.bp
+++ b/testing/mobly/Android.bp
@@ -33,10 +33,5 @@ python_test_host {
         // This tag is used to enable the ATest Mobly runner
         tags: ["mobly"],
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     // test_suites: ["general-tests"],
 }
diff --git a/testing/tests/wifi/nsd/Android.bp b/testing/tests/wifi/nsd/Android.bp
index a5357bfb..ce5d0b89 100644
--- a/testing/tests/wifi/nsd/Android.bp
+++ b/testing/tests/wifi/nsd/Android.bp
@@ -47,9 +47,4 @@ python_test_host {
         "mobly",
     ],
     test_suites: ["device-tests"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
```

