```diff
diff --git a/Android.bp b/Android.bp
index e4547cd2..7a176ec4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -70,9 +70,11 @@ rust_defaults {
         "libfutures_util",
         "libglam",
         "libgrpcio",
+        "liblibc",
         "libnetsim_proto",
         "libhttp",
         "libnetsim_common",
+        "libnetsim_packets",
         "libpdl_runtime",
         "libpica",
         "libprotobuf",
@@ -89,12 +91,6 @@ rust_defaults {
     static_libs: ["libgrpc_wrap"],
     srcs: [
         "rust/daemon/src/lib.rs",
-        ":netsim_netlink_rust_gen",
-        ":netsim_mac80211_hwsim_rust_gen",
-        ":netsim_ieee80211_rust_gen",
-        ":netsim_llc_rust_gen",
-        ":netsim_arp_rust_gen",
-        ":rootcanal_link_layer_packets_rust_gen",
     ],
 }
 
@@ -181,10 +177,6 @@ cc_library_host_static {
     name: "lib-netsim",
     defaults: ["netsim_defaults"],
     srcs: [
-        "src/core/server.cc",
-        "src/frontend/frontend_client_stub.cc",
-        "src/frontend/frontend_server.cc",
-        "src/backend/grpc_server.cc",
         "src/backend/grpc_client.cc",
         "src/hci/bluetooth_facade.cc",
         "src/hci/hci_packet_transport.cc",
@@ -194,7 +186,6 @@ cc_library_host_static {
         "src/util/log.cc",
         "src/util/os_utils.cc",
         "src/util/string_utils.cc",
-        "src/wifi/wifi_facade.cc",
     ],
     generated_headers: [
         "cxx-bridge-header",
@@ -353,6 +344,30 @@ rust_library_host {
     defaults: ["libnetsim_common_defaults"],
 }
 
+rust_defaults {
+    name: "libnetsim_packets_defaults",
+    srcs: [
+        "rust/packets/src/lib.rs",
+        ":netsim_netlink_rust_gen",
+        ":netsim_mac80211_hwsim_rust_gen",
+        ":netsim_ieee80211_rust_gen",
+        ":netsim_llc_rust_gen",
+        ":netsim_arp_rust_gen",
+        ":rootcanal_link_layer_packets_rust_gen",
+    ],
+    rustlibs: [
+        "libanyhow",
+        "libbytes",
+        "libpdl_runtime",
+    ],
+}
+
+rust_library_host {
+    name: "libnetsim_packets",
+    crate_name: "netsim_packets",
+    defaults: ["libnetsim_packets_defaults"],
+}
+
 rust_test_host {
     name: "libnetsim_common_inline_tests",
     defaults: ["libnetsim_common_defaults"],
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 709e7b58..da39911a 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,13 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsBluetoothTestCases",
-      "options": [
-        {
-          // TODO(b/303306195): Exclude a flaky test the other team is already working on from our check
-          "exclude-filter": "android.bluetooth.cts.LeL2capSocketTest#openInsecureLeL2capServerSocketRepeatedly"
-        }
-      ]
+      "name": "CtsBluetoothTestCases"
     },
     {
       "name": "net_test_bluetooth"
diff --git a/proto/netsim/frontend.proto b/proto/netsim/frontend.proto
index fb530d2b..f48378a7 100644
--- a/proto/netsim/frontend.proto
+++ b/proto/netsim/frontend.proto
@@ -103,10 +103,22 @@ message DeleteChipRequest {
 //
 // You may patch the device position, orientation, and the radio states.
 // For built-in devices, you may patch the specific configurations.
+// You may provide either the id or name to perform patching devices.
 message PatchDeviceRequest {
-  // Device proto. You must include either the id or name field to have
-  // a successful patch.
-  netsim.model.Device device = 2;
+  // Device Identifier
+  optional uint32 id = 1;
+
+  message PatchDeviceFields {
+    // Field numbers matches that of netsim.model.Device
+    optional string name = 2;
+    optional bool visible = 3;
+    optional netsim.model.Position position = 4;
+    optional netsim.model.Orientation orientation = 5;
+    // TODO: Replace with PatchChip that only includes modifiable fields
+    repeated netsim.model.Chip chips = 6;
+  }
+  // Patch Device proto
+  PatchDeviceFields device = 2;
 }
 
 // Response for ListDevice request.
diff --git a/rust/CMakeLists.txt b/rust/CMakeLists.txt
index c5739ab9..94266da7 100644
--- a/rust/CMakeLists.txt
+++ b/rust/CMakeLists.txt
@@ -5,17 +5,29 @@ file(REMOVE ${CMAKE_CURRENT_LIST_DIR}/Cargo.lock)
 
 # This will automatically register all the tests as well.
 corrosion_import_crate(MANIFEST_PATH Cargo.toml FLAGS --offline --verbose)
+
+# Set corrosion env vars
 corrosion_set_env_vars(netsim-common CARGO_HOME=${Rust_CARGO_HOME})
 corrosion_set_env_vars(http-proxy CARGO_HOME=${Rust_CARGO_HOME})
 corrosion_set_env_vars(libslirp-rs CARGO_HOME=${Rust_CARGO_HOME})
-corrosion_set_env_vars(hostapd-rs CARGO_HOME=${Rust_CARGO_HOME})
+corrosion_set_env_vars(capture CARGO_HOME=${Rust_CARGO_HOME})
+
+function(set_prebuilt_packets_env_vars target)
+  corrosion_set_env_vars(
+    ${target}
+    LINK_LAYER_PACKETS_PREBUILT=${RootCanalGeneratedPackets_rs}
+    NETLINK_PACKETS_PREBUILT=${NetlinkPackets_rs}
+    MAC80211_HWSIM_PACKETS_PREBUILT=${Mac80211HwsimPackets_rs}
+    IEEE80211_PACKETS_PREBUILT=${Ieee80211Packets_rs}
+    LLC_PACKETS_PREBUILT=${LlcPackets_rs}
+    CARGO_HOME=${Rust_CARGO_HOME})
+endfunction()
+
+set_prebuilt_packets_env_vars(hostapd-rs)
+set_prebuilt_packets_env_vars(netsim-packets)
+
 corrosion_set_env_vars(
   netsim-daemon
-  LINK_LAYER_PACKETS_PREBUILT=${RootCanalGeneratedPackets_rs}
-  NETLINK_PACKETS_PREBUILT=${NetlinkPackets_rs}
-  MAC80211_HWSIM_PACKETS_PREBUILT=${Mac80211HwsimPackets_rs}
-  IEEE80211_PACKETS_PREBUILT=${Ieee80211Packets_rs}
-  LLC_PACKETS_PREBUILT=${LlcPackets_rs}
   CARGO_HOME=${Rust_CARGO_HOME}
   GRPCIO_SYS_GRPC_INCLUDE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../../../external/grpc/include"
 )
@@ -38,7 +50,9 @@ add_custom_target(
           pdl_gen-Mac80211HwsimPackets_rs)
 
 # Make sure we have the rust packets generated before we build them.
-add_dependencies(cargo-build_netsim-daemon netsim_rust_packets)
+add_dependencies(cargo-build_netsim-packets netsim_rust_packets)
+add_dependencies(cargo-build_hostapd-rs cargo-build_netsim-packets)
+add_dependencies(cargo-build_netsim-daemon cargo-build_netsim-packets)
 
 # cxx crates
 if(WIN32)
diff --git a/rust/Cargo.toml b/rust/Cargo.toml
index 0140eb18..155d23a2 100644
--- a/rust/Cargo.toml
+++ b/rust/Cargo.toml
@@ -13,7 +13,6 @@
 # limitations under the License.
 
 [workspace]
-edition = "2021"
 members = [
     "proto",
     "cli",
@@ -22,4 +21,7 @@ members = [
     "http-proxy",
     "libslirp-rs",
     "hostapd-rs",
+    "packets",
+    "capture",
 ]
+resolver = "2"
diff --git a/rust/capture/Cargo.toml b/rust/capture/Cargo.toml
new file mode 100644
index 00000000..9556ffef
--- /dev/null
+++ b/rust/capture/Cargo.toml
@@ -0,0 +1,28 @@
+# Copyright 2024 The Android Open Source Project
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
+[package]
+name = "capture"
+version = "0.1.0"
+edition = "2021"
+
+[lib]
+path = "src/lib.rs"
+crate-type = ["staticlib","lib"]
+doctest = false
+
+[dependencies]
+zerocopy = "0.7.35"
+zerocopy-derive = "0.7.35"
+tokio = { version = "1.32.0", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "sync"] }
diff --git a/rust/capture/data/dns.cap b/rust/capture/data/dns.cap
new file mode 100644
index 00000000..911d77b5
Binary files /dev/null and b/rust/capture/data/dns.cap differ
diff --git a/rust/capture/src/lib.rs b/rust/capture/src/lib.rs
new file mode 100644
index 00000000..a5d3ecd7
--- /dev/null
+++ b/rust/capture/src/lib.rs
@@ -0,0 +1,32 @@
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
+//! A library for reading and writing pcap (packet capture) files in Rust.
+//!
+//! This crate provides an asynchronous API for working with pcap files,
+//! allowing you to read and write packet capture data efficiently.
+//! It supports both reading from and writing to pcap files, and it
+//! handles the parsing and serialization of pcap headers and packet records.
+//!
+//! # Features
+//!
+//! * **Asynchronous API:** Built on top of Tokio, enabling efficient asynchronous
+//!   reading and writing of pcap files.
+//! * **Zero-copy:** Uses the `zerocopy` crate for zero-cost conversions between
+//!   structs and byte slices, improving performance.
+//! * **Standard pcap format:**  Supports the standard pcap file format, ensuring
+//!   compatibility with other pcap tools.
+//!
+
+pub mod pcap;
diff --git a/rust/capture/src/pcap.rs b/rust/capture/src/pcap.rs
new file mode 100644
index 00000000..0dfc8f89
--- /dev/null
+++ b/rust/capture/src/pcap.rs
@@ -0,0 +1,272 @@
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
+use std::marker::Unpin;
+use std::mem::size_of;
+use std::time::Duration;
+use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
+use zerocopy::{AsBytes, FromBytes};
+use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};
+
+type Result<A> = std::result::Result<A, std::io::Error>;
+
+/// Represents the global header of a pcap capture file.
+///
+/// This struct defines the global header that appears at the beginning of a
+/// pcap capture file. It contains metadata about the capture, such as the
+/// file format version, the data link type, and the maximum snapshot length.
+///
+/// # File Header format
+/// ```text
+///                         1                   2                   3
+///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  0 |                          Magic Number                         |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  4 |          Major Version        |         Minor Version         |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  8 |                           Reserved1                           |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// 12 |                           Reserved2                           |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// 16 |                            SnapLen                            |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// 20 | FCS |f|0 0 0 0 0 0 0 0 0 0 0 0|         LinkType              |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// ```
+///
+/// * `magic`: A magic number that identifies the file format.
+/// * `version_major`: The major version number of the file format.
+/// * `version_minor`: The minor version number of the file format.
+/// * `thiszone`: The time zone offset of the capture.
+/// * `sigfigs`: The accuracy of the timestamps.
+/// * `snaplen`: The maximum number of bytes captured from each packet.
+/// * `linktype`: The data link type of the network interface used to capture the packets.
+#[repr(C)]
+#[derive(AsBytes, FromBytes, FromZeroes)]
+/// Represents the global header of a pcap capture file.
+pub struct FileHeader {
+    pub magic: u32,
+    pub version_major: u16,
+    pub version_minor: u16,
+    pub thiszone: i32,
+    pub sigfigs: u32,
+    pub snaplen: u32,
+    pub linktype: u32,
+}
+
+impl FileHeader {
+    const MAGIC: u32 = 0xa1b2c3d4;
+    const VERSION_MAJOR: u16 = 2u16;
+    const VERSION_MINOR: u16 = 4u16;
+    const RESERVED_1: i32 = 0;
+    const RESERVED_2: u32 = 0;
+    const SNAP_LEN: u32 = u32::MAX;
+}
+
+impl Default for FileHeader {
+    fn default() -> Self {
+        FileHeader {
+            magic: FileHeader::MAGIC,
+            version_major: FileHeader::VERSION_MAJOR,
+            version_minor: FileHeader::VERSION_MINOR,
+            thiszone: FileHeader::RESERVED_1,
+            sigfigs: FileHeader::RESERVED_2,
+            snaplen: FileHeader::SNAP_LEN,
+            linktype: LinkType::Null as u32,
+        }
+    }
+}
+
+/// Represents the link layer header type of a pcap capture.
+///
+/// This enum defines the different link layer types that can be used in a
+/// pcap capture file. These values specify the format of the link-layer
+/// header that precedes the network layer (e.g., IP) header in each packet.
+///
+/// For a complete list of supported link types and their descriptions,
+/// refer to the tcpdump documentation:
+/// https://www.tcpdump.org/linktypes.html
+#[repr(u32)]
+pub enum LinkType {
+    Null = 0,
+    /// Ethernet
+    Ethernet = 1,
+    /// Radiotap link-layer information followed by an 802.11
+    /// header. Radiotap is used with mac80211_hwsim networking.
+    Ieee80211RadioTap = 127,
+    /// Bluetooth HCI UART transport layer
+    BluetoothHciH4WithPhdr = 201,
+    /// Ultra-wideband controller interface protocol
+    FiraUci = 299,
+}
+
+impl From<LinkType> for u32 {
+    fn from(val: LinkType) -> Self {
+        val as u32
+    }
+}
+
+/// Represents the header prepended to each packet in a pcap capture file.
+///
+/// This struct defines the header that precedes each packet in a pcap
+/// capture file. It provides information about the timestamp and length
+/// of the captured packet.
+///
+/// # Fields
+/// ```text
+///                        1                   2                   3
+///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  0 |                      Timestamp (Seconds)                      |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  4 |            Timestamp (Microseconds or nanoseconds)            |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+///  8 |                    Captured Packet Length                     |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// 12 |                    Original Packet Length                     |
+///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+/// 16 /                                                               /
+///    /                          Packet Data                          /
+///    /                        variable length                        /
+///    /                                                               /
+///    +---------------------------------------------------------------+
+/// ```
+///
+/// * `tv_sec`:  The seconds component of the timestamp.
+/// * `tv_usec`: The microseconds component of the timestamp.
+/// * `caplen`: The number of bytes of packet data actually captured and saved in the file.
+/// * `len`: The original length of the packet on the network.
+//
+#[repr(C)]
+#[derive(AsBytes, FromBytes, FromZeroes)]
+/// Represents the header prepended to each packet in a pcap capture file.
+pub struct PacketHeader {
+    /// Timestamp of the captured packet.
+    pub tv_sec: u32,
+    pub tv_usec: u32,
+    pub caplen: u32,
+    /// Original length of the packet on the network.
+    pub len: u32,
+}
+
+/// Reads a pcap file header from the given reader.
+///
+/// # Arguments
+///
+/// * `reader` - A reader to read the header from.
+///
+/// # Returns
+///
+/// * `Ok(FileHeader)` - If the header was successfully read.
+/// * `Err(std::io::Error)` - If an error occurred while reading or parsing the header.
+pub async fn read_file_header(mut reader: impl AsyncRead + Unpin) -> Result<FileHeader> {
+    let mut header_bytes = [0u8; size_of::<FileHeader>()];
+    reader.read_exact(&mut header_bytes).await?;
+    let header = FileHeader::read_from(&header_bytes[..]).ok_or(std::io::Error::new(
+        std::io::ErrorKind::InvalidData,
+        "Failed to parse pcap file header",
+    ))?;
+    if header.magic != FileHeader::MAGIC {
+        return Err(std::io::Error::new(
+            std::io::ErrorKind::InvalidData,
+            format!("Invalid magic in pcap file 0x{:x}", header.magic),
+        ));
+    }
+    Ok(header)
+}
+
+/// Reads a pcap record from the given reader.
+/// A record consists of a packet header (`PacketHeader`) and the packet data itself.
+///
+/// # Arguments
+///
+/// * `reader` - A reader to read the record from.
+///
+/// # Returns
+///
+/// * `Ok((PacketHeader, Vec<u8>))` - If the record was successfully read.
+/// * `Err(std::io::Error)` - If an error occurred while reading or parsing the record.
+pub async fn read_record(mut reader: impl AsyncRead + Unpin) -> Result<(PacketHeader, Vec<u8>)> {
+    let mut pkt_hdr_bytes = [0u8; std::mem::size_of::<PacketHeader>()];
+    reader.read_exact(&mut pkt_hdr_bytes).await?;
+    let pkt_hdr = PacketHeader::read_from(&pkt_hdr_bytes[..]).ok_or(std::io::Error::new(
+        std::io::ErrorKind::InvalidData,
+        "Failed to parse pcap record header",
+    ))?;
+    let mut packet_data = vec![0u8; pkt_hdr.caplen as usize];
+    reader.read_exact(&mut packet_data).await?;
+    Ok((pkt_hdr, packet_data))
+}
+
+/// Writes the header of a pcap file to the output writer.
+///
+/// This function writes the global header of a pcap file to the provided
+/// asynchronous writer. It returns the size of the header written.
+///
+/// # Arguments
+///
+/// * `link_type` - The link type of the network interface used to capture the packets.
+/// * `output` - The asynchronous writer to write the header to.
+///
+/// # Returns
+///
+/// A `Result` containing the size of the header in bytes on success,
+/// or a `std::io::Error` on failure.
+pub async fn write_file_header(
+    link_type: LinkType,
+    mut output: impl AsyncWrite + Unpin,
+) -> Result<usize> {
+    // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-file-header
+    let header = FileHeader { linktype: link_type as u32, ..Default::default() };
+    output.write_all(header.as_bytes()).await?;
+    Ok(size_of::<FileHeader>())
+}
+
+/// Appends a single packet record to the output writer.
+///
+/// This function writes a packet record to the provided asynchronous writer,
+/// including the packet header and the packet data itself. It returns the
+/// total number of bytes written to the writer.
+///
+/// # Arguments
+///
+/// * `timestamp` - The timestamp of the packet.
+/// * `output` - The asynchronous writer to write the record to.
+/// * `packet` - The packet data as a byte slice.
+///
+/// # Returns
+///
+/// A `Result` containing the total number of bytes written on success,
+/// or a `std::io::Error` on failure.
+pub async fn write_record(
+    timestamp: Duration,
+    mut output: impl AsyncWrite + Unpin,
+    packet: &[u8],
+) -> Result<usize> {
+    // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-packet-record
+    let pkt_len = packet.len();
+    let pkt_hdr_len = size_of::<PacketHeader>();
+    let header = PacketHeader {
+        tv_sec: timestamp.as_secs() as u32,
+        tv_usec: timestamp.subsec_micros(),
+        caplen: pkt_len as u32,
+        len: pkt_len as u32,
+    };
+    let mut bytes = Vec::<u8>::with_capacity(pkt_hdr_len + pkt_len);
+    bytes.extend(header.as_bytes());
+    bytes.extend(packet);
+    output.write_all(&bytes).await?;
+    Ok(pkt_hdr_len + pkt_len)
+}
diff --git a/rust/capture/tests/integration_test.rs b/rust/capture/tests/integration_test.rs
new file mode 100644
index 00000000..f99fe3f1
--- /dev/null
+++ b/rust/capture/tests/integration_test.rs
@@ -0,0 +1,57 @@
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
+use tokio::io::{AsyncSeekExt, BufReader};
+
+fn timestamp(hdr: pcap::PacketHeader) -> f64 {
+    hdr.tv_sec as f64 + (hdr.tv_usec as f64 / 1_000_000.0)
+}
+
+// Read a file with a known number of records.
+//
+// Test magic numbers, record len, and timestamp fields
+#[tokio::test]
+async fn read_file() -> Result<(), std::io::Error> {
+    const DATA: &[u8] = include_bytes!("../data/dns.cap");
+    const RECORDS: i32 = 38;
+    let mut reader = BufReader::new(Cursor::new(DATA));
+    let header = pcap::read_file_header(&mut reader).await?;
+    assert_eq!(header.linktype, pcap::LinkType::Ethernet.into());
+    assert_eq!(header.snaplen, u16::MAX as u32);
+    let mut records = 0;
+    loop {
+        match pcap::read_record(&mut reader).await {
+            Ok((hdr, _record)) => {
+                records += 1;
+                if records == 1 {
+                    assert_eq!(1112172466.496046000f64, timestamp(hdr));
+                } else if records == 38 {
+                    assert_eq!(1112172745.375359000f64, timestamp(hdr));
+                }
+            }
+            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
+                assert_eq!(records, RECORDS);
+                assert_eq!(DATA.len() as u64, reader.stream_position().await?);
+                break;
+            }
+            _ => {
+                assert!(false, "Unexpected error");
+            }
+        }
+    }
+
+    Ok(())
+}
diff --git a/rust/cli/Cargo.toml b/rust/cli/Cargo.toml
index e378298f..d350bc1d 100644
--- a/rust/cli/Cargo.toml
+++ b/rust/cli/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-cli"
-version = "0.3.27"
+version = "0.3.37"
 edition = "2021"
 build = "build.rs"
 
diff --git a/rust/cli/src/args.rs b/rust/cli/src/args.rs
index b4f01db0..3727024f 100644
--- a/rust/cli/src/args.rs
+++ b/rust/cli/src/args.rs
@@ -20,6 +20,7 @@ use netsim_common::util::time_display::TimeDisplay;
 use netsim_proto::common::ChipKind;
 use netsim_proto::frontend;
 use netsim_proto::frontend::patch_capture_request::PatchCapture as PatchCaptureProto;
+use netsim_proto::frontend::patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto;
 use netsim_proto::model::chip::ble_beacon::advertise_settings::{
     AdvertiseMode as AdvertiseModeProto, AdvertiseTxPower as AdvertiseTxPowerProto,
     Interval as IntervalProto, Tx_power as TxPowerProto,
@@ -32,8 +33,8 @@ use netsim_proto::model::chip::{
     Radio as Chip_Radio,
 };
 use netsim_proto::model::{
-    self, chip_create, Chip, ChipCreate as ChipCreateProto, Device,
-    DeviceCreate as DeviceCreateProto, Position,
+    self, chip_create, Chip, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
+    Position,
 };
 use protobuf::{Message, MessageField};
 use std::fmt;
@@ -124,22 +125,22 @@ impl Command {
                     chip.set_bt(bt_chip);
                 }
                 let mut result = frontend::PatchDeviceRequest::new();
-                let mut device = Device::new();
-                cmd.name.clone_into(&mut device.name);
+                let mut device = PatchDeviceFieldsProto::new();
+                device.name = Some(cmd.name.clone());
                 device.chips.push(chip);
                 result.device = Some(device).into();
                 result.write_to_bytes().unwrap()
             }
             Command::Move(cmd) => {
                 let mut result = frontend::PatchDeviceRequest::new();
-                let mut device = Device::new();
+                let mut device = PatchDeviceFieldsProto::new();
                 let position = Position {
                     x: cmd.x,
                     y: cmd.y,
                     z: cmd.z.unwrap_or_default(),
                     ..Default::default()
                 };
-                cmd.name.clone_into(&mut device.name);
+                device.name = Some(cmd.name.clone());
                 device.position = Some(position).into();
                 result.device = Some(device).into();
                 result.write_to_bytes().unwrap()
@@ -191,8 +192,8 @@ impl Command {
                 },
                 Beacon::Patch(kind) => match kind {
                     BeaconPatch::Ble(args) => {
-                        let device = MessageField::some(Device {
-                            name: args.device_name.clone(),
+                        let device = MessageField::some(PatchDeviceFieldsProto {
+                            name: Some(args.device_name.clone()),
                             chips: vec![Chip {
                                 name: args.chip_name.clone(),
                                 kind: ChipKind::BLUETOOTH_BEACON.into(),
diff --git a/rust/cli/src/requests.rs b/rust/cli/src/requests.rs
index f6f57aec..861ff0fb 100644
--- a/rust/cli/src/requests.rs
+++ b/rust/cli/src/requests.rs
@@ -52,7 +52,10 @@ mod tests {
     use super::*;
     use args::{BinaryProtobuf, NetsimArgs};
     use clap::Parser;
-    use netsim_proto::frontend::{CreateDeviceRequest, PatchDeviceRequest};
+    use netsim_proto::frontend::{
+        patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto, CreateDeviceRequest,
+        PatchDeviceRequest,
+    };
     use netsim_proto::model::chip::ble_beacon::AdvertiseData as AdvertiseDataProto;
     use netsim_proto::model::chip::{
         ble_beacon::{
@@ -76,7 +79,7 @@ mod tests {
         model::{
             self,
             chip::{Bluetooth as Chip_Bluetooth, Radio as Chip_Radio},
-            Device, Position,
+            Position,
         },
     };
     use protobuf::Message;
@@ -124,8 +127,8 @@ mod tests {
             chip.set_bt(bt_chip);
         }
         let mut result = frontend::PatchDeviceRequest::new();
-        let mut device = Device::new();
-        name.clone_into(&mut device.name);
+        let mut device = PatchDeviceFieldsProto::new();
+        device.name = Some(name.to_string());
         device.chips.push(chip);
         result.device = Some(device).into();
         result.write_to_bytes().unwrap()
@@ -213,9 +216,9 @@ mod tests {
 
     fn get_expected_move(name: &str, x: f32, y: f32, z: Option<f32>) -> BinaryProtobuf {
         let mut result = frontend::PatchDeviceRequest::new();
-        let mut device = Device::new();
+        let mut device = PatchDeviceFieldsProto::new();
         let position = Position { x, y, z: z.unwrap_or_default(), ..Default::default() };
-        name.clone_into(&mut device.name);
+        device.name = Some(name.to_string());
         device.position = Some(position).into();
         result.device = Some(device).into();
         result.write_to_bytes().unwrap()
@@ -312,8 +315,8 @@ mod tests {
         adv_data: AdvertiseDataProto,
         scan_response: AdvertiseDataProto,
     ) -> Vec<u8> {
-        let device = MessageField::some(Device {
-            name: String::from(device_name),
+        let device = MessageField::some(PatchDeviceFieldsProto {
+            name: Some(String::from(device_name)),
             chips: vec![ChipProto {
                 name: String::from(chip_name),
                 kind: ChipKind::BLUETOOTH_BEACON.into(),
@@ -587,8 +590,8 @@ mod tests {
         let device_name = String::from("device");
         let chip_name = String::from("chip");
 
-        let device = MessageField::some(Device {
-            name: device_name.clone(),
+        let device = MessageField::some(PatchDeviceFieldsProto {
+            name: Some(device_name.clone()),
             chips: vec![ChipProto {
                 name: chip_name.clone(),
                 kind: ChipKind::BLUETOOTH_BEACON.into(),
diff --git a/rust/common/Cargo.toml b/rust/common/Cargo.toml
index 545a301e..4f8a5f9a 100644
--- a/rust/common/Cargo.toml
+++ b/rust/common/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-common"
-version = "0.3.27"
+version = "0.3.37"
 edition = "2021"
 
 [lib]
diff --git a/rust/common/src/system/mod.rs b/rust/common/src/system/mod.rs
index f7aa3fed..adfadb8d 100644
--- a/rust/common/src/system/mod.rs
+++ b/rust/common/src/system/mod.rs
@@ -58,12 +58,12 @@ fn netsimd_temp_dir_pathbuf() -> PathBuf {
 
 #[cfg(not(target_os = "windows"))]
 #[cfg(test)]
-mod tests {
+pub mod tests {
     use super::netsimd_temp_dir_pathbuf;
     use std::env;
     use std::sync::Mutex;
 
-    static ENV_MUTEX: Mutex<i32> = Mutex::new(0);
+    pub static ENV_MUTEX: Mutex<()> = Mutex::new(());
 
     #[test]
     fn test_forge() {
diff --git a/rust/common/src/util/os_utils.rs b/rust/common/src/util/os_utils.rs
index 50e81126..7e1f7028 100644
--- a/rust/common/src/util/os_utils.rs
+++ b/rust/common/src/util/os_utils.rs
@@ -212,9 +212,13 @@ pub fn redirect_std_stream(instance_name: &str) -> anyhow::Result<()> {
 mod tests {
 
     use super::*;
+    #[cfg(not(target_os = "windows"))]
+    use crate::system::tests::ENV_MUTEX;
 
     #[test]
     fn test_get_discovery_directory() {
+        #[cfg(not(target_os = "windows"))]
+        let _locked = ENV_MUTEX.lock();
         // Remove all environment variable
         std::env::remove_var(DISCOVERY.root_env);
         std::env::remove_var("TMPDIR");
diff --git a/rust/daemon/Cargo.toml b/rust/daemon/Cargo.toml
index 3854d8be..9e50a22c 100644
--- a/rust/daemon/Cargo.toml
+++ b/rust/daemon/Cargo.toml
@@ -1,17 +1,16 @@
 [package]
 name = "netsim-daemon"
-version = "0.3.27"
+version = "0.3.37"
 edition = "2021"
 build = "build.rs"
 
 [lib]
 crate-type = ["staticlib", "lib"]
 doctest = false
-test = false
 
 [dependencies]
 bytes = { version = ">=1.4.0"}
-clap = { version = "4.1.8", default-features = false, features = ["derive", "error-context", "help", "std", "usage"] }
+clap = { version = "4.1.8", default-features = false, features = ["derive", "error-context", "help", "std", "usage", "env" ] }
 cxx = { version = ">=1.0.85", features = ["c++17"] }
 data-encoding = "2.4.0"
 futures = "0.3.30"
@@ -21,6 +20,8 @@ http = "0.2.9"
 netsim-common = { path = "../common" }
 libslirp-rs = { path = "../libslirp-rs" }
 hostapd-rs = { path = "../hostapd-rs" }
+http-proxy = { path = "../http-proxy" }
+netsim-packets = { path = "../packets" }
 # Relax the version constraint for 'pica' to allow cargo to select a compatible version
 # from crates.io since 0.1.9 seems to be only available in AOSP.
 pica = { version = "0.1", default-features = false }
diff --git a/rust/daemon/build.rs b/rust/daemon/build.rs
index d99f2879..931cb4bd 100644
--- a/rust/daemon/build.rs
+++ b/rust/daemon/build.rs
@@ -13,25 +13,7 @@
 //  See the License for the specific language governing permissions and
 //  limitations under the License.
 
-use std::env;
-use std::path::PathBuf;
-
 fn main() {
     let _build = cxx_build::bridge("src/ffi.rs");
     println!("cargo:rerun-if-changed=src/ffi.rs");
-
-    let prebuilts: [[&str; 2]; 5] = [
-        ["LINK_LAYER_PACKETS_PREBUILT", "link_layer_packets.rs"],
-        ["MAC80211_HWSIM_PACKETS_PREBUILT", "mac80211_hwsim_packets.rs"],
-        ["IEEE80211_PACKETS_PREBUILT", "ieee80211_packets.rs"],
-        ["LLC_PACKETS_PREBUILT", "llc_packets.rs"],
-        ["NETLINK_PACKETS_PREBUILT", "netlink_packets.rs"],
-    ];
-
-    for [var, name] in prebuilts {
-        let prebuilt = env::var(var).unwrap();
-        println!("cargo:rerun-if-changed={}", prebuilt);
-        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
-        std::fs::copy(prebuilt.as_str(), out_dir.join(name).as_os_str().to_str().unwrap()).unwrap();
-    }
 }
diff --git a/rust/daemon/src/args.rs b/rust/daemon/src/args.rs
index 9cd4047c..d24442f3 100644
--- a/rust/daemon/src/args.rs
+++ b/rust/daemon/src/args.rs
@@ -56,21 +56,6 @@ pub struct NetsimdArgs {
     #[arg(short, long)]
     pub dev: bool,
 
-    /// Use Rust gRPC server.
-    /// WARNING: This flag is for development purpose.
-    #[arg(long)]
-    pub rust_grpc: bool,
-
-    /// Use hostapd-rs and disable c++ hostapd.
-    /// WARNING: This flag is for development purpose.
-    #[arg(long)]
-    pub rust_hostapd: bool,
-
-    /// Use libslirp-rs and disable qemu slirp.
-    /// WARNING: This flag is for development purpose.
-    #[arg(long)]
-    pub rust_slirp: bool,
-
     /// Forwards mDNS from the host to the guest, allowing emulator to discover mDNS services running on the host.
     ///
     /// # Limitations
@@ -98,6 +83,7 @@ pub struct NetsimdArgs {
     ///     (the 'http://' prefix can be omitted)
     /// WARNING: This flag is still working in progress.
     #[arg(long, verbatim_doc_comment)]
+    #[cfg_attr(not(feature = "cuttlefish"), arg(env = "http_proxy"))]
     pub http_proxy: Option<String>,
 
     // Use TAP interface instead of libslirp for Wi-Fi
diff --git a/rust/daemon/src/bluetooth/advertise_settings.rs b/rust/daemon/src/bluetooth/advertise_settings.rs
index 78a2cadd..3cc55ad9 100644
--- a/rust/daemon/src/bluetooth/advertise_settings.rs
+++ b/rust/daemon/src/bluetooth/advertise_settings.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::packets::link_layer::LegacyAdvertisingType;
+use netsim_packets::link_layer::LegacyAdvertisingType;
 use netsim_proto::model::chip::ble_beacon::{
     advertise_settings::{
         AdvertiseMode as Mode, AdvertiseTxPower as Level, Interval as IntervalProto,
diff --git a/rust/daemon/src/bluetooth/beacon.rs b/rust/daemon/src/bluetooth/beacon.rs
index c7d5620b..4b5c9a92 100644
--- a/rust/daemon/src/bluetooth/beacon.rs
+++ b/rust/daemon/src/bluetooth/beacon.rs
@@ -17,9 +17,6 @@ use super::advertise_settings::{
     AdvertiseMode, AdvertiseSettings, AdvertiseSettingsBuilder, TxPowerLevel,
 };
 use super::chip::{rust_bluetooth_add, RustBluetoothChipCallbacks};
-use super::packets::link_layer::{
-    Address, AddressType, LeLegacyAdvertisingPduBuilder, LeScanResponseBuilder, PacketType,
-};
 use crate::devices::chip::{ChipIdentifier, FacadeIdentifier};
 use crate::devices::device::{AddChipResult, DeviceIdentifier};
 use crate::devices::devices_handler::add_chip;
@@ -27,6 +24,9 @@ use crate::ffi::ffi_bluetooth;
 use crate::wireless;
 use cxx::{let_cxx_string, UniquePtr};
 use log::{error, info, warn};
+use netsim_packets::link_layer::{
+    Address, AddressType, LeLegacyAdvertisingPduBuilder, LeScanResponseBuilder, PacketType,
+};
 use netsim_proto::common::ChipKind;
 use netsim_proto::model::chip::Bluetooth;
 use netsim_proto::model::chip::{
diff --git a/rust/daemon/src/bluetooth/mod.rs b/rust/daemon/src/bluetooth/mod.rs
index 9e671ae9..eb967adb 100644
--- a/rust/daemon/src/bluetooth/mod.rs
+++ b/rust/daemon/src/bluetooth/mod.rs
@@ -25,4 +25,3 @@ pub(crate) use self::mocked::*;
 pub(crate) mod advertise_data;
 pub(crate) mod advertise_settings;
 pub(crate) mod chip;
-pub(crate) mod packets;
diff --git a/rust/daemon/src/bluetooth/packets.rs b/rust/daemon/src/bluetooth/packets.rs
deleted file mode 100644
index 2d97ae9c..00000000
--- a/rust/daemon/src/bluetooth/packets.rs
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2023 The Android Open Source Project
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
-pub mod link_layer {
-    #![allow(clippy::all)]
-    #![allow(unused)]
-    #![allow(missing_docs)]
-
-    include!(concat!(env!("OUT_DIR"), "/link_layer_packets.rs"));
-}
diff --git a/rust/daemon/src/captures/capture.rs b/rust/daemon/src/captures/capture.rs
index 98dfa6f9..c53a93f1 100644
--- a/rust/daemon/src/captures/capture.rs
+++ b/rust/daemon/src/captures/capture.rs
@@ -36,7 +36,6 @@ use log::{info, warn};
 use netsim_proto::{common::ChipKind, model::Capture as ProtoCapture};
 use protobuf::well_known_types::timestamp::Timestamp;
 
-use crate::config::get_pcap;
 use crate::events::{ChipAdded, ChipRemoved, Event};
 use crate::resource::clone_captures;
 
@@ -266,14 +265,14 @@ impl Default for Captures {
 /// connected to the simulation. This procedure monitors ChipAdded
 /// and ChipRemoved events and updates the collection of CaptureInfo.
 ///
-pub fn spawn_capture_event_subscriber(event_rx: Receiver<Event>) {
+pub fn spawn_capture_event_subscriber(event_rx: Receiver<Event>, capture: bool) {
     let _ =
         thread::Builder::new().name("capture_event_subscriber".to_string()).spawn(move || loop {
             match event_rx.recv() {
                 Ok(Event::ChipAdded(ChipAdded { chip_id, chip_kind, device_name, .. })) => {
                     let mut capture_info =
                         CaptureInfo::new(chip_kind, chip_id, device_name.clone());
-                    if get_pcap() {
+                    if capture {
                         if let Err(err) = capture_info.start_capture() {
                             warn!("{err:?}");
                         }
diff --git a/rust/daemon/src/config.rs b/rust/daemon/src/config.rs
deleted file mode 100644
index 419dbd1c..00000000
--- a/rust/daemon/src/config.rs
+++ /dev/null
@@ -1,93 +0,0 @@
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
-/// Configuration for netsim
-use std::sync::{Once, RwLock};
-
-static SET_DEV_CALLED: Once = Once::new();
-static SET_PCAP_CALLED: Once = Once::new();
-
-static CONFIG: RwLock<Config> = RwLock::new(Config::new());
-
-struct Config {
-    pub dev: Option<bool>,
-    pub pcap: Option<bool>,
-}
-
-impl Config {
-    pub const fn new() -> Self {
-        Self { dev: None, pcap: None }
-    }
-}
-
-/// Get the flag of dev
-pub fn get_dev() -> bool {
-    let config = CONFIG.read().unwrap();
-    config.dev.unwrap_or(false)
-}
-
-/// Set the flag of dev
-pub fn set_dev(flag: bool) {
-    SET_DEV_CALLED.call_once(|| {
-        let mut config = CONFIG.write().unwrap();
-        config.dev = Some(flag);
-    });
-}
-
-/// Get the flag of pcap
-pub fn get_pcap() -> bool {
-    let config = CONFIG.read().unwrap();
-    config.pcap.unwrap_or(false)
-}
-
-/// Set the flag of pcap
-pub fn set_pcap(flag: bool) {
-    SET_PCAP_CALLED.call_once(|| {
-        let mut config = CONFIG.write().unwrap();
-        config.pcap = Some(flag);
-    });
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test_dev() {
-        // Check if default dev boolean is false
-        assert!(!get_dev());
-
-        // Check if set_dev changes the flag to true
-        set_dev(true);
-        assert!(get_dev());
-
-        // Check if set_dev can only be called once
-        set_dev(false);
-        assert!(get_dev());
-    }
-
-    #[test]
-    fn test_pcap() {
-        // Check if default pcap boolean is false
-        assert!(!get_pcap());
-
-        // Check if set_pcap changes the flag to true
-        set_pcap(true);
-        assert!(get_pcap());
-
-        // Check if set_pcap can only be called once
-        set_pcap(false);
-        assert!(get_pcap());
-    }
-}
diff --git a/rust/daemon/src/devices/chip.rs b/rust/daemon/src/devices/chip.rs
index 13f64d95..29028f10 100644
--- a/rust/daemon/src/devices/chip.rs
+++ b/rust/daemon/src/devices/chip.rs
@@ -21,7 +21,6 @@
 ///
 use crate::wireless::WirelessAdaptorImpl;
 use netsim_proto::common::ChipKind as ProtoChipKind;
-use netsim_proto::configuration::Controller as ProtoController;
 use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::stats::NetsimRadioStats as ProtoRadioStats;
 use protobuf::EnumOrUnknown;
@@ -81,8 +80,6 @@ pub struct CreateParams {
     pub name: Option<String>,
     pub manufacturer: String,
     pub product_name: String,
-    #[allow(dead_code)]
-    pub bt_properties: Option<ProtoController>, // TODO: move to wireless_adaptor CreateParams
 }
 
 /// Chip contains the common information for each Chip/Controller.
@@ -247,7 +244,6 @@ mod tests {
                 name: None,
                 manufacturer: MANUFACTURER.to_string(),
                 product_name: PRODUCT_NAME.to_string(),
-                bt_properties: None,
             };
             self.new_chip(CHIP_ID, DEVICE_ID, DEVICE_NAME, &create_params, wireless_adaptor)
                 .unwrap()
diff --git a/rust/daemon/src/devices/device.rs b/rust/daemon/src/devices/device.rs
index 30a0b8fc..d8e69218 100644
--- a/rust/daemon/src/devices/device.rs
+++ b/rust/daemon/src/devices/device.rs
@@ -20,6 +20,7 @@ use crate::devices::chip::ChipIdentifier;
 use crate::devices::devices_handler::PoseManager;
 use crate::wireless::WirelessAdaptorImpl;
 use netsim_proto::common::ChipKind as ProtoChipKind;
+use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
 use netsim_proto::model::Device as ProtoDevice;
 use netsim_proto::stats::NetsimRadioStats as ProtoRadioStats;
 use std::collections::BTreeMap;
@@ -89,7 +90,11 @@ impl Device {
     }
 
     /// Patch a device and its chips.
-    pub fn patch(&self, patch: &ProtoDevice, pose_manager: Arc<PoseManager>) -> Result<(), String> {
+    pub fn patch(
+        &self,
+        patch: &ProtoPatchDeviceFields,
+        pose_manager: Arc<PoseManager>,
+    ) -> Result<(), String> {
         if patch.visible.is_some() {
             self.visible.store(patch.visible.unwrap(), Ordering::SeqCst);
         }
@@ -241,7 +246,6 @@ mod tests {
                 name: Some(TEST_CHIP_NAME_1.to_string()),
                 manufacturer: "test_manufacturer".to_string(),
                 product_name: "test_product_name".to_string(),
-                bt_properties: None,
             },
             chip_id_1,
             mocked::new(&mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED }, chip_id_1),
@@ -253,7 +257,6 @@ mod tests {
                 name: Some(TEST_CHIP_NAME_2.to_string()),
                 manufacturer: "test_manufacturer".to_string(),
                 product_name: "test_product_name".to_string(),
-                bt_properties: None,
             },
             chip_id_2,
             mocked::new(&mocked::CreateParams { chip_kind: ProtoChipKind::UNSPECIFIED }, chip_id_1),
diff --git a/rust/daemon/src/devices/devices_handler.rs b/rust/daemon/src/devices/devices_handler.rs
index 8d58d7e1..dcbab93e 100644
--- a/rust/daemon/src/devices/devices_handler.rs
+++ b/rust/daemon/src/devices/devices_handler.rs
@@ -40,6 +40,7 @@ use http::Version;
 use log::{info, warn};
 use netsim_proto::common::ChipKind as ProtoChipKind;
 use netsim_proto::configuration::Controller;
+use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
 use netsim_proto::frontend::CreateDeviceRequest;
 use netsim_proto::frontend::CreateDeviceResponse;
 use netsim_proto::frontend::DeleteChipRequest;
@@ -47,6 +48,7 @@ use netsim_proto::frontend::ListDeviceResponse;
 use netsim_proto::frontend::PatchDeviceRequest;
 use netsim_proto::frontend::SubscribeDeviceRequest;
 use netsim_proto::model::chip_create::Chip as ProtoBuiltin;
+use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::model::Device as ProtoDevice;
 use netsim_proto::model::Orientation as ProtoOrientation;
 use netsim_proto::model::Position as ProtoPosition;
@@ -299,14 +301,14 @@ pub fn add_chip_cxx(
     variant: &str,
     arch: &str,
 ) -> Box<AddChipResultCxx> {
-    let bt_properties_proto = Controller::parse_from_bytes(bt_properties.as_slice());
+    let _bt_properties_proto = Controller::parse_from_bytes(bt_properties.as_slice());
     #[cfg(not(test))]
     let (chip_kind_enum, wireless_create_param) = match chip_kind.to_string().as_str() {
         "BLUETOOTH" => (
             ProtoChipKind::BLUETOOTH,
             wireless::CreateParam::Bluetooth(wireless::bluetooth::CreateParams {
                 address: chip_address.to_string(),
-                bt_properties: bt_properties_proto
+                bt_properties: _bt_properties_proto
                     .as_ref()
                     .map_or(None, |p| Some(MessageField::some(p.clone()))),
             }),
@@ -362,7 +364,6 @@ pub fn add_chip_cxx(
         name: if chip_name.is_empty() { None } else { Some(chip_name.to_string()) },
         manufacturer: chip_manufacturer.to_string(),
         product_name: chip_product_name.to_string(),
-        bt_properties: bt_properties_proto.ok(),
     };
     let device_info = ProtoDeviceInfo {
         kind: kind.to_string(),
@@ -490,7 +491,6 @@ pub fn create_device(create_device_request: &CreateDeviceRequest) -> Result<Prot
                 name: if chip.name.is_empty() { None } else { Some(chip.name.to_string()) },
                 manufacturer: chip.manufacturer.clone(),
                 product_name: chip.product_name.clone(),
-                bt_properties: chip.bt_properties.as_ref().cloned(),
             };
             let wireless_create_params =
                 wireless::CreateParam::BleBeacon(wireless::ble_beacon::CreateParams {
@@ -516,36 +516,122 @@ pub fn create_device(create_device_request: &CreateDeviceRequest) -> Result<Prot
     Ok(device_proto)
 }
 
+struct ProtoChipDisplay(ProtoChip);
+
+// Due to the low readability of debug formatter for ProtoChip, we implemented our own fmt.
+impl std::fmt::Display for ProtoChipDisplay {
+    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
+        let chip = &self.0;
+        if let Ok(kind) = chip.kind.enum_value() {
+            match kind {
+                ProtoChipKind::BLUETOOTH => {
+                    chip.bt().low_energy.clone().map(|v| {
+                        write!(
+                            f,
+                            "{{ id: {}, kind: BLUETOOTH_LOW_ENERGY, state: {:?} }}",
+                            self.0.id, v.state
+                        )
+                    });
+                    chip.bt().classic.clone().map(|v| {
+                        write!(
+                            f,
+                            "{{ id: {}, kind: BLUETOOTH_CLASSIC, state: {:?} }}",
+                            chip.id, v.state
+                        )
+                    });
+                }
+                ProtoChipKind::BLUETOOTH_BEACON => {
+                    chip.ble_beacon().bt.low_energy.clone().map(|v| {
+                        write!(f, "{{ id: {}, kind: BLE_BEACON, state: {:?} }}", chip.id, v.state)
+                    });
+                    chip.ble_beacon().bt.classic.clone().map(|v| {
+                        write!(
+                            f,
+                            "{{ id: {}, kind: BLUETOOTH_CLASSIC_BEACON, state: {:?} }}",
+                            chip.id, v.state
+                        )
+                    });
+                }
+                ProtoChipKind::WIFI => {
+                    write!(f, "{{ id: {}, kind: WIFI, state: {:?} }}", chip.id, chip.wifi().state)?
+                }
+                ProtoChipKind::UWB => {
+                    write!(f, "{{ id: {}, kind: UWB, state: {:?} }}", chip.id, chip.uwb().state)?
+                }
+                _ => (),
+            }
+        }
+        Ok(())
+    }
+}
+
+struct PatchDeviceFieldsDisplay(DeviceIdentifier, ProtoPatchDeviceFields);
+
+// Due to the low readability of debug formatter for ProtoPatchDeviceFields, we implemented our own fmt.
+impl std::fmt::Display for PatchDeviceFieldsDisplay {
+    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
+        write!(f, "PatchDevice: ")?;
+        let mut fields = Vec::<String>::new();
+        fields.push(format!("id: {}", self.0));
+        if let Some(name) = &self.1.name {
+            fields.push(format!("name: {}", name));
+        }
+        if let Some(visible) = &self.1.visible {
+            fields.push(format!("visible: {}", visible));
+        }
+        if let Some(position) = &self.1.position.0 {
+            fields.push(format!("position: {{ {} }}", position));
+        }
+        if let Some(orientation) = &self.1.orientation.0 {
+            fields.push(format!("orientation: {{ {} }}", orientation));
+        }
+        if !self.1.chips.is_empty() {
+            let mut chip_field = Vec::<String>::new();
+            for chip in &self.1.chips {
+                chip_field.push(format!("{}", ProtoChipDisplay(chip.clone())));
+            }
+            fields.push(format!("chips: {{ {} }}", chip_field.join(", ")));
+        }
+        write!(f, "{}", fields.join(", "))
+    }
+}
+
 // lock the devices, find the id and call the patch function
-pub fn patch_device(
-    id_option: Option<DeviceIdentifier>,
-    patch_device_request: PatchDeviceRequest,
-) -> Result<(), String> {
+pub fn patch_device(patch_device_request: PatchDeviceRequest) -> Result<(), String> {
     let manager = get_manager();
-    let proto_device = patch_device_request.device;
-    match id_option {
-        Some(id) => match manager.devices.read().unwrap().get(&id) {
-            Some(device) => {
-                let result = device.patch(&proto_device, get_pose_manager());
-                let name = device.name.clone();
-                if result.is_ok() {
-                    // Update last modified timestamp for manager
-                    manager.update_timestamp();
-
-                    // Publish Device Patched event
-                    events::publish(Event::DevicePatched(DevicePatched { id, name }));
+    let proto_device = patch_device_request
+        .device
+        .into_option()
+        .ok_or("Missing PatchDevice in PatchDeviceRequest".to_string())?;
+    match (patch_device_request.id, proto_device.name.clone()) {
+        (Some(id), _) => {
+            let id = DeviceIdentifier(id);
+            match manager.devices.read().unwrap().get(&id) {
+                Some(device) => {
+                    let result = device.patch(&proto_device, get_pose_manager());
+                    let name = device.name.clone();
+                    if result.is_ok() {
+                        // Update last modified timestamp for manager
+                        manager.update_timestamp();
+
+                        // Log patched fields
+                        log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
+
+                        // Publish Device Patched event
+                        events::publish(Event::DevicePatched(DevicePatched { id, name }));
+                    }
+                    result
                 }
-                result
+                None => Err(format!("No such device with id {id}")),
             }
-            None => Err(format!("No such device with id {id}")),
-        },
-        None => {
+        }
+        (_, Some(name)) => {
             let mut multiple_matches = false;
             let mut target: Option<&Device> = None;
             let devices = manager.devices.read().unwrap();
             for device in devices.values() {
-                if device.name.contains(&proto_device.name) {
-                    if device.name == proto_device.name {
+                if device.name.contains(&name) {
+                    if device.name == name {
                         let result = device.patch(&proto_device, get_pose_manager());
                         let id = device.id;
                         let name = device.name.clone();
@@ -553,6 +639,9 @@ pub fn patch_device(
                             // Update last modified timestamp for manager
                             manager.update_timestamp();
 
+                            // Log patched fields
+                            log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
+
                             // Publish Device Patched event
                             events::publish(Event::DevicePatched(DevicePatched { id, name }));
                         }
@@ -565,7 +654,7 @@ pub fn patch_device(
             if multiple_matches {
                 return Err(format!(
                     "Multiple ambiguous matches were found with substring {}",
-                    proto_device.name
+                    name
                 ));
             }
             match target {
@@ -577,23 +666,29 @@ pub fn patch_device(
                         // Update last modified timestamp for devices
                         manager.update_timestamp();
 
+                        // Log patched fields
+                        log::info!("{}", PatchDeviceFieldsDisplay(id, proto_device));
+
                         // Publish Device Patched event
                         events::publish(Event::DevicePatched(DevicePatched { id, name }));
                     }
                     result
                 }
-                None => Err(format!("No such device with name {}", proto_device.name)),
+                None => Err(format!("No such device with name {}", name)),
             }
         }
+        (_, _) => Err("Both id and name are not provided".to_string()),
     }
 }
 
 // Parse from input json string to proto
-#[allow(dead_code)]
 fn patch_device_json(id_option: Option<DeviceIdentifier>, patch_json: &str) -> Result<(), String> {
     let mut patch_device_request = PatchDeviceRequest::new();
     if merge_from_str(&mut patch_device_request, patch_json).is_ok() {
-        patch_device(id_option, patch_device_request)
+        if patch_device_request.id.is_none() {
+            patch_device_request.id = id_option.map(|id| id.0);
+        }
+        patch_device(patch_device_request)
     } else {
         Err(format!("Incorrect format of patch json {}", patch_json))
     }
@@ -951,9 +1046,8 @@ pub fn get_radio_stats() -> Vec<NetsimRadioStats> {
 mod tests {
     use crate::events;
     use netsim_common::util::netsim_logger::init_for_test;
-    use netsim_proto::model::{
-        Device as ProtoDevice, DeviceCreate as ProtoDeviceCreate, Orientation as ProtoOrientation,
-    };
+    use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
+    use netsim_proto::model::{DeviceCreate as ProtoDeviceCreate, Orientation as ProtoOrientation};
     use protobuf_json_mapping::print_to_string;
     use std::{sync::Once, thread};
 
@@ -992,7 +1086,6 @@ mod tests {
                 name: Some(self.chip_name.clone()),
                 manufacturer: self.chip_manufacturer.clone(),
                 product_name: self.chip_product_name.clone(),
-                bt_properties: None,
             };
             let wireless_create_params =
                 wireless::CreateParam::Mock(wireless::mocked::CreateParams {
@@ -1288,10 +1381,10 @@ mod tests {
         let chip_params = test_chip_1_bt();
         let chip_result = chip_params.add_chip().unwrap();
         let mut patch_device_request = PatchDeviceRequest::new();
-        let mut proto_device = ProtoDevice::new();
+        let mut proto_device = ProtoPatchDeviceFields::new();
         let request_position = new_position(1.1, 2.2, 3.3);
         let request_orientation = new_orientation(4.4, 5.5, 6.6);
-        proto_device.name = chip_params.device_name;
+        proto_device.name = Some(chip_params.device_name);
         proto_device.visible = Some(false);
         proto_device.position = Some(request_position.clone()).into();
         proto_device.orientation = Some(request_orientation.clone()).into();
@@ -1324,7 +1417,7 @@ mod tests {
         }
 
         // Patch device by name with substring match
-        proto_device.name = format!("test-device-name-1-{:?}", thread::current().id());
+        proto_device.name = format!("test-device-name-1-{:?}", thread::current().id()).into();
         patch_device_request.device = Some(proto_device).into();
         let patch_json = print_to_string(&patch_device_request).unwrap();
         assert!(patch_device_json(None, patch_json.as_str()).is_ok());
@@ -1429,10 +1522,10 @@ mod tests {
         let chip_params = test_chip_1_bt();
         let chip_result = chip_params.add_chip().unwrap();
         let mut patch_device_request = PatchDeviceRequest::new();
-        let mut proto_device = ProtoDevice::new();
+        let mut proto_device = ProtoPatchDeviceFields::new();
         let request_position = new_position(10.0, 20.0, 30.0);
         let request_orientation = new_orientation(1.0, 2.0, 3.0);
-        proto_device.name = chip_params.device_name;
+        proto_device.name = Some(chip_params.device_name);
         proto_device.visible = Some(false);
         proto_device.position = Some(request_position).into();
         proto_device.orientation = Some(request_orientation).into();
@@ -1561,9 +1654,9 @@ mod tests {
 
         // Patch the first chip
         let mut patch_device_request = PatchDeviceRequest::new();
-        let mut proto_device = ProtoDevice::new();
+        let mut proto_device = ProtoPatchDeviceFields::new();
         let request_position = new_position(1.0, 1.0, 1.0);
-        proto_device.name = bt_chip_params.device_name;
+        proto_device.name = Some(bt_chip_params.device_name);
         proto_device.position = Some(request_position.clone()).into();
         patch_device_request.device = Some(proto_device.clone()).into();
         let patch_json = print_to_string(&patch_device_request).unwrap();
@@ -1571,9 +1664,9 @@ mod tests {
 
         // Patch the second chip
         let mut patch_device_request = PatchDeviceRequest::new();
-        let mut proto_device = ProtoDevice::new();
+        let mut proto_device = ProtoPatchDeviceFields::new();
         let request_position = new_position(1.0, 4.0, 5.0);
-        proto_device.name = bt_chip_2_params.device_name;
+        proto_device.name = Some(bt_chip_2_params.device_name);
         proto_device.position = Some(request_position.clone()).into();
         patch_device_request.device = Some(proto_device.clone()).into();
         let patch_json = print_to_string(&patch_device_request).unwrap();
@@ -1600,7 +1693,6 @@ mod tests {
     use netsim_proto::model::chip_create::{BleBeaconCreate, Chip as BuiltChipProto};
     use netsim_proto::model::Chip as ChipProto;
     use netsim_proto::model::ChipCreate as ProtoChipCreate;
-    use netsim_proto::model::Device as DeviceProto;
     use protobuf::{EnumOrUnknown, MessageField};
 
     fn get_test_create_device_request(device_name: Option<String>) -> CreateDeviceRequest {
@@ -1736,9 +1828,8 @@ mod tests {
             .get_mut(&DeviceIdentifier(device_proto.id))
             .expect("could not find test bluetooth beacon device");
         let patch_result = device.patch(
-            &DeviceProto {
-                name: device_proto.name.clone(),
-                id: device_proto.id,
+            &ProtoPatchDeviceFields {
+                name: Some(device_proto.name.clone()),
                 chips: vec![ChipProto {
                     name: request.device.chips[0].name.clone(),
                     kind: EnumOrUnknown::new(ProtoChipKind::BLUETOOTH_BEACON),
diff --git a/rust/daemon/src/ffi.rs b/rust/daemon/src/ffi.rs
index f5e4718a..148db0cb 100644
--- a/rust/daemon/src/ffi.rs
+++ b/rust/daemon/src/ffi.rs
@@ -28,9 +28,7 @@ use crate::devices::devices_handler::{
     add_chip_cxx, get_distance_cxx, handle_device_cxx, remove_chip_cxx, AddChipResultCxx,
 };
 use crate::ranging::*;
-use crate::transport::grpc::{register_grpc_transport, unregister_grpc_transport};
 use crate::version::*;
-use crate::wireless::wifi::handle_wifi_response;
 use crate::wireless::{
     bluetooth::report_invalid_packet_cxx, handle_request_cxx, handle_response_cxx,
 };
@@ -50,42 +48,7 @@ pub mod ffi_wireless {
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "netsim::transport")]
 pub mod ffi_transport {
-    extern "Rust" {
-        #[cxx_name = RegisterGrpcTransport]
-        fn register_grpc_transport(chip_id: u32);
-
-        #[cxx_name = UnregisterGrpcTransport]
-        fn unregister_grpc_transport(chip_id: u32);
-    }
-
     unsafe extern "C++" {
-        // Grpc server.
-        include!("backend/backend_packet_hub.h");
-
-        #[rust_name = handle_grpc_response]
-        #[namespace = "netsim::backend"]
-        fn HandleResponseCxx(chip_id: u32, packet: &Vec<u8>, packet_type: u8);
-
-        include!("core/server.h");
-
-        #[namespace = "netsim::server"]
-        type GrpcServer;
-        #[rust_name = shut_down]
-        #[namespace = "netsim::server"]
-        fn Shutdown(self: &GrpcServer);
-
-        #[rust_name = get_grpc_port]
-        #[namespace = "netsim::server"]
-        fn GetGrpcPort(self: &GrpcServer) -> u32;
-
-        #[rust_name = run_grpc_server_cxx]
-        #[namespace = "netsim::server"]
-        pub fn RunGrpcServerCxx(
-            netsim_grpc_port: u32,
-            no_cli_ui: bool,
-            vsock: u16,
-        ) -> UniquePtr<GrpcServer>;
-
         // Grpc client.
         // Expose functions in Cuttlefish only, because it's only used by CVDs and it's
         // unable to pass function pointers on Windows.
@@ -243,45 +206,6 @@ pub mod ffi_bluetooth {
     }
 }
 
-#[cxx::bridge(namespace = "netsim::wifi::facade")]
-pub mod ffi_wifi {
-    #[allow(dead_code)]
-    unsafe extern "C++" {
-        // WiFi facade.
-        include!("wifi/wifi_packet_hub.h");
-
-        #[rust_name = handle_wifi_request]
-        #[namespace = "netsim::wifi"]
-        fn HandleWifiRequestCxx(packet: &Vec<u8>);
-
-        #[rust_name = hostapd_send]
-        #[namespace = "netsim::wifi"]
-        fn HostapdSendCxx(packet: &Vec<u8>);
-
-        #[rust_name = libslirp_send]
-        #[namespace = "netsim::wifi"]
-        fn LibslirpSendCxx(packet: &Vec<u8>);
-
-        #[namespace = "netsim::wifi"]
-        pub fn libslirp_main_loop_wait();
-
-        include!("wifi/wifi_facade.h");
-
-        #[rust_name = wifi_start]
-        pub fn Start(proto_bytes: &[u8]);
-
-        #[rust_name = wifi_stop]
-        pub fn Stop();
-
-    }
-
-    #[allow(unsafe_op_in_unsafe_fn)]
-    extern "Rust" {
-        #[cxx_name = HandleWiFiResponse]
-        fn handle_wifi_response(packet: &[u8]);
-    }
-}
-
 #[allow(clippy::needless_maybe_sized)]
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "netsim::device")]
@@ -392,14 +316,6 @@ pub mod ffi_util {
         #[rust_name = set_up_crash_report]
         #[namespace = "netsim"]
         pub fn SetUpCrashReport();
-
-        // Frontend client.
-        include!("frontend/frontend_client_stub.h");
-
-        #[rust_name = is_netsimd_alive]
-        #[namespace = "netsim::frontend"]
-        pub fn IsNetsimdAlive(instance_num: u16) -> bool;
-
     }
 }
 
diff --git a/rust/daemon/src/grpc_server/backend.rs b/rust/daemon/src/grpc_server/backend.rs
index 7dc6adbe..1e47b6a2 100644
--- a/rust/daemon/src/grpc_server/backend.rs
+++ b/rust/daemon/src/grpc_server/backend.rs
@@ -39,7 +39,7 @@ fn add_chip(initial_info: &ChipInfo, device_guid: &str) -> anyhow::Result<AddChi
         ProtoChipKind::BLUETOOTH => {
             wireless::CreateParam::Bluetooth(wireless::bluetooth::CreateParams {
                 address: chip.address.clone(),
-                bt_properties: None,
+                bt_properties: Some(chip.bt_properties.clone()),
             })
         }
         ProtoChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi::CreateParams {}),
@@ -58,7 +58,6 @@ fn add_chip(initial_info: &ChipInfo, device_guid: &str) -> anyhow::Result<AddChi
         name: Some(chip.id.clone()),
         manufacturer: chip.manufacturer.clone(),
         product_name: chip.product_name.clone(),
-        bt_properties: None,
     };
 
     devices_handler::add_chip(
diff --git a/rust/daemon/src/grpc_server/frontend.rs b/rust/daemon/src/grpc_server/frontend.rs
index 4b357293..97054fb9 100644
--- a/rust/daemon/src/grpc_server/frontend.rs
+++ b/rust/daemon/src/grpc_server/frontend.rs
@@ -14,7 +14,6 @@
 
 use crate::captures::captures_handler;
 use crate::devices::chip::ChipIdentifier;
-use crate::devices::device::DeviceIdentifier;
 use crate::devices::devices_handler;
 use futures_util::{FutureExt as _, SinkExt as _, TryFutureExt as _};
 use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink, WriteFlags};
@@ -62,11 +61,7 @@ impl FrontendService for FrontendClient {
         req: netsim_proto::frontend::PatchDeviceRequest,
         sink: grpcio::UnarySink<Empty>,
     ) {
-        let id_option = match req.device.id {
-            0 => None,
-            v => Some(DeviceIdentifier(v)),
-        };
-        let response = match devices_handler::patch_device(id_option, req) {
+        let response = match devices_handler::patch_device(req) {
             Ok(_) => sink.success(Empty::new()),
             Err(e) => {
                 warn!("failed to patch device: {}", e);
@@ -172,7 +167,7 @@ impl FrontendService for FrontendClient {
                     break;
                 }
                 let mut response = netsim_proto::frontend::GetCaptureResponse::new();
-                response.capture_stream = buffer.to_vec();
+                response.capture_stream = buffer[..length].to_vec(); // Send only read data
                 sink.send((response, WriteFlags::default())).await?;
             }
             sink.close().await?;
diff --git a/rust/daemon/src/grpc_server/server.rs b/rust/daemon/src/grpc_server/server.rs
index 13286fbd..b94e2612 100644
--- a/rust/daemon/src/grpc_server/server.rs
+++ b/rust/daemon/src/grpc_server/server.rs
@@ -17,26 +17,41 @@ use super::frontend::FrontendClient;
 use grpcio::{
     ChannelBuilder, Environment, ResourceQuota, Server, ServerBuilder, ServerCredentials,
 };
-use log::info;
+use log::{info, warn};
 use netsim_proto::frontend_grpc::create_frontend_service;
 use netsim_proto::packet_streamer_grpc::create_packet_streamer;
 use std::sync::Arc;
 
-pub fn start(port: u32) -> (Server, u16) {
+pub fn start(port: u32, no_cli_ui: bool, _vsock: u16) -> anyhow::Result<(Server, u16)> {
     let env = Arc::new(Environment::new(1));
     let backend_service = create_packet_streamer(PacketStreamerService);
     let frontend_service = create_frontend_service(FrontendClient);
-    let addr = format!("127.0.0.1:{}", port);
     let quota = ResourceQuota::new(Some("NetsimGrpcServerQuota")).resize_memory(1024 * 1024);
     let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota);
-    let mut server = ServerBuilder::new(env)
-        .register_service(frontend_service)
+    let mut server_builder = ServerBuilder::new(env);
+    if !no_cli_ui {
+        server_builder = server_builder.register_service(frontend_service);
+    }
+    let mut server = server_builder
         .register_service(backend_service)
         .channel_args(ch_builder.build_args())
-        .build()
-        .unwrap();
-    let port = server.add_listening_port(addr.clone(), ServerCredentials::insecure()).unwrap();
+        .build()?;
+
+    let addr_v4 = format!("127.0.0.1:{}", port);
+    let addr_v6 = format!("[::1]:{}", port);
+    let port = server.add_listening_port(addr_v4, ServerCredentials::insecure()).or_else(|e| {
+        warn!("Failed to bind to 127.0.0.1:{port} in grpc server. Trying [::1]:{port}. {e:?}");
+        server.add_listening_port(addr_v6, ServerCredentials::insecure())
+    })?;
+
+    #[cfg(feature = "cuttlefish")]
+    if _vsock != 0 {
+        let vsock_uri = format!("vsock:{}:{}", libc::VMADDR_CID_ANY, _vsock);
+        info!("vsock_uri: {}", vsock_uri);
+        server.add_listening_port(vsock_uri, ServerCredentials::insecure())?;
+    }
+
     server.start();
-    info!("Rust gRPC listening on 127.0.0.1:{port}");
-    (server, port)
+    info!("Rust gRPC listening on localhost:{port}");
+    Ok((server, port))
 }
diff --git a/rust/daemon/src/http_server/http_handlers.rs b/rust/daemon/src/http_server/http_handlers.rs
index fa0aebec..1f61c981 100644
--- a/rust/daemon/src/http_server/http_handlers.rs
+++ b/rust/daemon/src/http_server/http_handlers.rs
@@ -39,7 +39,7 @@ use super::{
     server_response::{ResponseWritable, ServerResponseWritable, ServerResponseWriter},
 };
 
-const PATH_PREFIXES: [&str; 4] = ["js", "js/netsim", "assets", "node_modules/tslib"];
+const PATH_PREFIXES: [&str; 3] = ["js", "assets", "node_modules/tslib"];
 
 fn ui_path(suffix: &str) -> PathBuf {
     let mut path = std::env::current_exe().unwrap();
@@ -137,7 +137,7 @@ fn handle_dev(request: &Request<Vec<u8>>, _param: &str, writer: ResponseWritable
     handle_file(request.method().as_str(), "dev.html", writer)
 }
 
-pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>>) {
+pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>>, dev: bool) {
     let mut router = Router::new();
     router.add_route(Uri::from_static("/"), Box::new(handle_index));
     router.add_route(Uri::from_static("/version"), Box::new(handle_version));
@@ -148,7 +148,7 @@ pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>
     router.add_route(Uri::from_static(r"/v1/websocket/{radio}"), Box::new(handle_websocket));
 
     // Adding additional routes in dev mode.
-    if crate::config::get_dev() {
+    if dev {
         router.add_route(Uri::from_static("/dev"), Box::new(handle_dev));
     }
 
diff --git a/rust/daemon/src/http_server/server.rs b/rust/daemon/src/http_server/server.rs
index eece56ea..3bf94d1d 100644
--- a/rust/daemon/src/http_server/server.rs
+++ b/rust/daemon/src/http_server/server.rs
@@ -16,21 +16,29 @@ use crate::http_server::http_handlers::{create_filename_hash_set, handle_connect
 
 use crate::http_server::thread_pool::ThreadPool;
 use log::{info, warn};
-use std::net::TcpListener;
+use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
 use std::sync::Arc;
 use std::thread;
 
 const DEFAULT_HTTP_PORT: u16 = 7681;
 
-/// Start the HTTP Server.
+/// Bind HTTP Server to IPv4 or IPv6 based on availability.
+fn bind_listener(http_port: u16) -> Result<TcpListener, std::io::Error> {
+    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, http_port)))
+        .or_else(|e| {
+            warn!("Failed to bind to 127.0.0.1:{http_port} in netsimd frontend http server. Trying [::1]:{http_port}. {e:?}");
+            TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, http_port)))
+        })
+}
 
-pub fn run_http_server(instance_num: u16) -> u16 {
+/// Start the HTTP Server.
+pub fn run_http_server(instance_num: u16, dev: bool) -> u16 {
     let http_port = DEFAULT_HTTP_PORT + instance_num - 1;
     let _ = thread::Builder::new().name("http_server".to_string()).spawn(move || {
-        let listener = match TcpListener::bind(format!("127.0.0.1:{}", http_port)) {
+        let listener = match bind_listener(http_port) {
             Ok(listener) => listener,
             Err(e) => {
-                warn!("bind error in netsimd frontend http server. {}", e);
+                warn!("{e:?}");
                 return;
             }
         };
@@ -41,7 +49,7 @@ pub fn run_http_server(instance_num: u16) -> u16 {
             let stream = stream.unwrap();
             let valid_files = valid_files.clone();
             pool.execute(move || {
-                handle_connection(stream, valid_files);
+                handle_connection(stream, valid_files, dev);
             });
         }
         info!("Shutting down frontend http server.");
diff --git a/rust/daemon/src/lib.rs b/rust/daemon/src/lib.rs
index 3ccd4616..a2129f3b 100644
--- a/rust/daemon/src/lib.rs
+++ b/rust/daemon/src/lib.rs
@@ -17,7 +17,6 @@
 mod args;
 mod bluetooth;
 pub mod captures;
-mod config;
 mod config_file;
 mod devices;
 mod events;
diff --git a/rust/daemon/src/rust_main.rs b/rust/daemon/src/rust_main.rs
index 62bc6683..be32ee78 100644
--- a/rust/daemon/src/rust_main.rs
+++ b/rust/daemon/src/rust_main.rs
@@ -13,13 +13,16 @@
 // limitations under the License.
 
 use clap::Parser;
+use grpcio::{ChannelBuilder, Deadline, EnvBuilder};
 use log::warn;
 use log::{error, info};
 use netsim_common::system::netsimd_temp_dir;
 use netsim_common::util::os_utils::{
-    get_hci_port, get_instance, get_instance_name, redirect_std_stream, remove_netsim_ini,
+    get_hci_port, get_instance, get_instance_name, get_server_address, redirect_std_stream,
+    remove_netsim_ini,
 };
 use netsim_common::util::zip_artifact::zip_artifacts;
+use netsim_proto::frontend_grpc::FrontendServiceClient;
 
 use crate::captures::capture::spawn_capture_event_subscriber;
 use crate::config_file;
@@ -34,8 +37,6 @@ use netsim_common::util::netsim_logger;
 use crate::args::NetsimdArgs;
 use crate::ffi::ffi_util;
 use crate::service::{new_test_beacon, Service, ServiceParams};
-#[cfg(feature = "cuttlefish")]
-use netsim_common::util::os_utils::get_server_address;
 use netsim_proto::config::{Bluetooth as BluetoothConfig, Capture, Config};
 use std::env;
 use std::ffi::{c_char, c_int};
@@ -226,7 +227,7 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
         warn!("Warning: netsimd startup flag -s is empty, waiting for gRPC connections.");
     }
 
-    if ffi_util::is_netsimd_alive(instance_num) {
+    if is_netsimd_alive(instance_num) {
         warn!("Failed to start netsim daemon because a netsim daemon is already running");
         return;
     }
@@ -254,16 +255,19 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
             host_dns;
     }
 
+    if let Some(http_proxy) = args.http_proxy {
+        config.wifi.mut_or_insert_default().slirp_options.mut_or_insert_default().http_proxy =
+            http_proxy;
+    }
+
     let service_params = ServiceParams::new(
         fd_startup_str,
         args.no_cli_ui,
         args.no_web_ui,
-        config.capture.enabled.unwrap_or_default(),
         hci_port,
         instance_num,
         args.dev,
         args.vsock.unwrap_or_default(),
-        args.rust_grpc,
     );
 
     // SAFETY: The caller guaranteed that the file descriptors in `fd_startup_str` would remain
@@ -282,7 +286,8 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     session.start(session_events_rx);
 
     // Pass all event receivers to each modules
-    spawn_capture_event_subscriber(capture_events_rx);
+    let capture = config.capture.enabled.unwrap_or_default();
+    spawn_capture_event_subscriber(capture_events_rx, capture);
 
     if !args.no_shutdown {
         spawn_shutdown_publisher(device_events_rx);
@@ -290,12 +295,7 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
 
     // Start radio facades
     wireless::bluetooth::bluetooth_start(&config.bluetooth, instance_num);
-    wireless::wifi::wifi_start(
-        &config.wifi,
-        args.rust_slirp,
-        args.rust_hostapd,
-        args.forward_host_mdns,
-    );
+    wireless::wifi::wifi_start(&config.wifi, args.forward_host_mdns);
     wireless::uwb::uwb_start();
 
     // Create test beacons if required
@@ -324,3 +324,17 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     // Once shutdown is complete, delete the netsim ini file
     remove_netsim_ini(instance_num);
 }
+
+fn is_netsimd_alive(instance_num: u16) -> bool {
+    match get_server_address(instance_num) {
+        Some(address) => {
+            // Check if grpc server has started
+            let channel = ChannelBuilder::new(std::sync::Arc::new(EnvBuilder::new().build()))
+                .connect(&address);
+            let client = FrontendServiceClient::new(channel);
+            let deadline = Deadline::from(std::time::Duration::from_secs(1));
+            futures::executor::block_on(client.client.channel().wait_for_connected(deadline))
+        }
+        None => false,
+    }
+}
diff --git a/rust/daemon/src/service.rs b/rust/daemon/src/service.rs
index db1c1109..3d95d80c 100644
--- a/rust/daemon/src/service.rs
+++ b/rust/daemon/src/service.rs
@@ -14,12 +14,9 @@
 
 use crate::bluetooth::advertise_settings as ble_advertise_settings;
 use crate::captures::captures_handler::clear_pcap_files;
-use crate::config::{set_dev, set_pcap};
-use crate::ffi::ffi_transport::{run_grpc_server_cxx, GrpcServer};
 use crate::http_server::server::run_http_server;
 use crate::transport::socket::run_socket_transport;
 use crate::wireless;
-use cxx::UniquePtr;
 use log::{error, info, warn};
 use netsim_common::util::ini_file::IniFile;
 use netsim_common::util::os_utils::get_netsim_ini_filepath;
@@ -33,12 +30,10 @@ pub struct ServiceParams {
     fd_startup_str: String,
     no_cli_ui: bool,
     no_web_ui: bool,
-    pcap: bool,
     hci_port: u16,
     instance_num: u16,
     dev: bool,
     vsock: u16,
-    rust_grpc: bool,
 }
 
 impl ServiceParams {
@@ -47,33 +42,19 @@ impl ServiceParams {
         fd_startup_str: String,
         no_cli_ui: bool,
         no_web_ui: bool,
-        pcap: bool,
         hci_port: u16,
         instance_num: u16,
         dev: bool,
         vsock: u16,
-        rust_grpc: bool,
     ) -> Self {
-        ServiceParams {
-            fd_startup_str,
-            no_cli_ui,
-            no_web_ui,
-            pcap,
-            hci_port,
-            instance_num,
-            dev,
-            vsock,
-            rust_grpc,
-        }
+        ServiceParams { fd_startup_str, no_cli_ui, no_web_ui, hci_port, instance_num, dev, vsock }
     }
 }
 
 pub struct Service {
     // netsimd states, like device resource.
     service_params: ServiceParams,
-    // grpc server
-    grpc_server: UniquePtr<GrpcServer>,
-    rust_grpc_server: Option<grpcio::Server>,
+    grpc_server: Option<grpcio::Server>,
 }
 
 impl Service {
@@ -82,7 +63,7 @@ impl Service {
     /// The file descriptors in `service_params.fd_startup_str` must be valid and open, and must
     /// remain so for as long as the `Service` exists.
     pub unsafe fn new(service_params: ServiceParams) -> Service {
-        Service { service_params, grpc_server: UniquePtr::null(), rust_grpc_server: None }
+        Service { service_params, grpc_server: None }
     }
 
     /// Sets up the states for netsimd.
@@ -97,36 +78,22 @@ impl Service {
         if clear_pcap_files() {
             info!("netsim generated pcap files in temp directory has been removed.");
         }
-
-        set_pcap(self.service_params.pcap);
-        set_dev(self.service_params.dev);
     }
 
     /// Runs netsim gRPC server
-    fn run_grpc_server(&mut self) -> Option<u32> {
+    fn run_grpc_server(&mut self) -> anyhow::Result<u32> {
         // If NETSIM_GRPC_PORT is set, use the fixed port for grpc server.
         let mut netsim_grpc_port =
             env::var("NETSIM_GRPC_PORT").map(|val| val.parse::<u32>().unwrap_or(0)).unwrap_or(0);
-        if self.service_params.rust_grpc {
-            // Run netsim gRPC server
-            let (server, port) = crate::grpc_server::server::start(netsim_grpc_port);
-            self.rust_grpc_server = Some(server);
-            netsim_grpc_port = port.into();
-        } else {
-            let grpc_server = run_grpc_server_cxx(
-                netsim_grpc_port,
-                self.service_params.no_cli_ui,
-                self.service_params.vsock,
-            );
-            match grpc_server.is_null() {
-                true => return None,
-                false => {
-                    self.grpc_server = grpc_server;
-                    netsim_grpc_port = self.grpc_server.get_grpc_port();
-                }
-            }
-        }
-        Some(netsim_grpc_port)
+        // Run netsim gRPC server
+        let (server, port) = crate::grpc_server::server::start(
+            netsim_grpc_port,
+            self.service_params.no_cli_ui,
+            self.service_params.vsock,
+        )?;
+        self.grpc_server = Some(server);
+        netsim_grpc_port = port.into();
+        Ok(netsim_grpc_port)
     }
 
     /// Runs netsim web server
@@ -134,7 +101,9 @@ impl Service {
         // If NETSIM_NO_WEB_SERVER is set, don't start http server.
         let no_web_server = env::var("NETSIM_NO_WEB_SERVER").is_ok_and(|v| v == "1");
         match !no_web_server && !self.service_params.no_web_ui {
-            true => Some(run_http_server(self.service_params.instance_num)),
+            true => {
+                Some(run_http_server(self.service_params.instance_num, self.service_params.dev))
+            }
             false => None,
         }
     }
@@ -166,9 +135,9 @@ impl Service {
         }
 
         let grpc_port = match self.run_grpc_server() {
-            Some(port) => port,
-            None => {
-                error!("Failed to run netsimd because unable to start grpc server");
+            Ok(port) => port,
+            Err(e) => {
+                error!("Failed to run netsimd: {e:?}");
                 return;
             }
         };
@@ -186,10 +155,7 @@ impl Service {
     /// Shut down the netsimd services
     pub fn shut_down(&mut self) {
         // TODO: shutdown other services in Rust
-        if !self.grpc_server.is_null() {
-            self.grpc_server.shut_down();
-        }
-        self.rust_grpc_server.as_mut().map(|server| server.shutdown());
+        self.grpc_server.as_mut().map(|server| server.shutdown());
         wireless::bluetooth::bluetooth_stop();
         wireless::wifi::wifi_stop();
     }
diff --git a/rust/daemon/src/transport/fd.rs b/rust/daemon/src/transport/fd.rs
index 600f30e3..3a189fc7 100644
--- a/rust/daemon/src/transport/fd.rs
+++ b/rust/daemon/src/transport/fd.rs
@@ -153,7 +153,7 @@ pub unsafe fn run_fd_transport(startup_json: &String) {
                 ChipKind::BLUETOOTH => {
                     wireless::CreateParam::Bluetooth(wireless::bluetooth::CreateParams {
                         address: chip.address.clone(),
-                        bt_properties: None,
+                        bt_properties: Some(chip.bt_properties.clone()),
                     })
                 }
                 ChipKind::WIFI => wireless::CreateParam::Wifi(wireless::wifi::CreateParams {}),
@@ -174,7 +174,6 @@ pub unsafe fn run_fd_transport(startup_json: &String) {
                 name: Some(chip.id.clone()),
                 manufacturer: chip.manufacturer.clone(),
                 product_name: chip.product_name.clone(),
-                bt_properties: None,
             };
             let result = match add_chip(
                 &format!("fd-device-{}", &device.name.clone()),
diff --git a/rust/daemon/src/transport/grpc.rs b/rust/daemon/src/transport/grpc.rs
index 22b3f75e..d34be3fd 100644
--- a/rust/daemon/src/transport/grpc.rs
+++ b/rust/daemon/src/transport/grpc.rs
@@ -12,9 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::devices::chip::ChipIdentifier;
-use crate::ffi::ffi_transport::handle_grpc_response;
-use crate::wireless::packet::{register_transport, unregister_transport, Response};
+use crate::wireless::packet::Response;
 use bytes::Bytes;
 use futures_executor::block_on;
 use futures_util::SinkExt as _;
@@ -25,31 +23,6 @@ use protobuf::Enum;
 use protobuf::EnumOrUnknown;
 
 /// Grpc transport.
-///
-/// This module provides a wrapper around the C++ Grpc implementation. It
-/// provides a higher-level API that is easier to use from Rust.
-
-struct GrpcTransport {
-    chip_id: u32,
-}
-
-impl Response for GrpcTransport {
-    fn response(&mut self, packet: Bytes, packet_type: u8) {
-        handle_grpc_response(self.chip_id, &packet.to_vec(), packet_type)
-    }
-}
-
-// for grpc server in C++
-pub fn register_grpc_transport(chip_id: u32) {
-    register_transport(ChipIdentifier(chip_id), Box::new(GrpcTransport { chip_id }));
-}
-
-// for grpc server in C++
-pub fn unregister_grpc_transport(chip_id: u32) {
-    unregister_transport(ChipIdentifier(chip_id));
-}
-
-/// Rust grpc transport.s
 pub struct RustGrpcTransport {
     pub sink: grpcio::DuplexSink<PacketResponse>,
 }
diff --git a/rust/daemon/src/transport/socket.rs b/rust/daemon/src/transport/socket.rs
index bc8a14e5..a9f18e9f 100644
--- a/rust/daemon/src/transport/socket.rs
+++ b/rust/daemon/src/transport/socket.rs
@@ -23,7 +23,7 @@ use log::{error, info, warn};
 use netsim_proto::common::ChipKind;
 use netsim_proto::startup::DeviceInfo as ProtoDeviceInfo;
 use std::io::{ErrorKind, Write};
-use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
+use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
 use std::thread;
 
 // The HCI server implements the Bluetooth UART transport protocol
@@ -62,8 +62,11 @@ pub fn run_socket_transport(hci_port: u16) {
 }
 
 fn accept_incoming(hci_port: u16) -> std::io::Result<()> {
-    let hci_socket = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, hci_port);
-    let listener = TcpListener::bind(hci_socket)?;
+    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, hci_port))).or_else(|e| {
+            warn!("Failed to bind to 127.0.0.1:{hci_port} in netsimd socket server, Trying [::1]:{hci_port}. {e:?}");
+            TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, hci_port)))
+        }
+    )?;
     info!("Hci socket server is listening on: {}", hci_port);
 
     for stream in listener.incoming() {
@@ -88,7 +91,6 @@ fn handle_hci_client(stream: TcpStream) {
         name: Some(format!("socket-{}", stream.peer_addr().unwrap())),
         manufacturer: "Google".to_string(),
         product_name: "Google".to_string(),
-        bt_properties: None,
     };
     #[cfg(not(test))]
     let wireless_create_params =
diff --git a/rust/daemon/src/transport/websocket.rs b/rust/daemon/src/transport/websocket.rs
index cd32cb55..525d478e 100644
--- a/rust/daemon/src/transport/websocket.rs
+++ b/rust/daemon/src/transport/websocket.rs
@@ -96,7 +96,6 @@ pub fn run_websocket_transport(stream: TcpStream, queries: HashMap<&str, &str>)
         name: Some(format!("websocket-{}", stream.peer_addr().unwrap())),
         manufacturer: "Google".to_string(),
         product_name: "Google".to_string(),
-        bt_properties: None,
     };
     #[cfg(not(test))]
     let wireless_create_params =
diff --git a/rust/daemon/src/version.rs b/rust/daemon/src/version.rs
index 071c6f28..4cb2384d 100644
--- a/rust/daemon/src/version.rs
+++ b/rust/daemon/src/version.rs
@@ -14,7 +14,7 @@
 
 /// Version library.
 
-pub const VERSION: &str = "0.3.27";
+pub const VERSION: &str = "0.3.37";
 
 pub fn get_version() -> String {
     VERSION.to_owned()
diff --git a/rust/daemon/src/wifi/frame.rs b/rust/daemon/src/wifi/frame.rs
index 00acb989..d0862ab5 100644
--- a/rust/daemon/src/wifi/frame.rs
+++ b/rust/daemon/src/wifi/frame.rs
@@ -12,10 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::packets::ieee80211::{Ieee80211, MacAddress};
-use super::packets::mac80211_hwsim::{HwsimCmd, HwsimMsg, TxRate};
 use crate::wifi::hwsim_attr_set::HwsimAttrSet;
 use anyhow::Context;
+use netsim_packets::ieee80211::{Ieee80211, MacAddress};
+use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg, TxRate};
 use pdl_runtime::Packet;
 
 /// Parser for the hwsim Frame command (HWSIM_CMD_FRAME).
diff --git a/rust/daemon/src/wifi/hostapd.rs b/rust/daemon/src/wifi/hostapd.rs
index 94e244b1..f2e3f76d 100644
--- a/rust/daemon/src/wifi/hostapd.rs
+++ b/rust/daemon/src/wifi/hostapd.rs
@@ -14,24 +14,11 @@
 
 /// Hostapd Interface for Network Simulation
 use bytes::Bytes;
-#[cfg(not(feature = "cuttlefish"))]
 pub use hostapd_rs::hostapd::Hostapd;
-#[cfg(not(feature = "cuttlefish"))]
 use netsim_common::util::os_utils::get_discovery_directory;
 use netsim_proto::config::HostapdOptions as ProtoHostapdOptions;
 use std::sync::mpsc;
 
-// Provides a stub implementation while the hostapd-rs crate is not integrated into the aosp-main.
-#[cfg(feature = "cuttlefish")]
-pub struct Hostapd {}
-#[cfg(feature = "cuttlefish")]
-impl Hostapd {
-    pub fn input(&self, _bytes: Bytes) -> anyhow::Result<()> {
-        Ok(())
-    }
-}
-
-#[cfg(not(feature = "cuttlefish"))]
 pub fn hostapd_run(_opt: ProtoHostapdOptions, tx: mpsc::Sender<Bytes>) -> anyhow::Result<Hostapd> {
     // Create hostapd.conf under discovery directory
     let config_path = get_discovery_directory().join("hostapd.conf");
@@ -39,8 +26,3 @@ pub fn hostapd_run(_opt: ProtoHostapdOptions, tx: mpsc::Sender<Bytes>) -> anyhow
     hostapd.run();
     Ok(hostapd)
 }
-
-#[cfg(feature = "cuttlefish")]
-pub fn hostapd_run(_opt: ProtoHostapdOptions, _tx: mpsc::Sender<Bytes>) -> anyhow::Result<Hostapd> {
-    Ok(Hostapd {})
-}
diff --git a/rust/daemon/src/wifi/hostapd_cf.rs b/rust/daemon/src/wifi/hostapd_cf.rs
new file mode 100644
index 00000000..9036a4a5
--- /dev/null
+++ b/rust/daemon/src/wifi/hostapd_cf.rs
@@ -0,0 +1,46 @@
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
+/// Hostapd Interface for Network Simulation
+use bytes::Bytes;
+use netsim_packets::ieee80211::{Ieee80211, MacAddress};
+use netsim_proto::config::HostapdOptions as ProtoHostapdOptions;
+use std::sync::mpsc;
+
+// Provides a stub implementation while the hostapd-rs crate is not integrated into the aosp-main.
+pub struct Hostapd {}
+impl Hostapd {
+    pub fn input(&self, _bytes: Bytes) -> anyhow::Result<()> {
+        Ok(())
+    }
+
+    /// Retrieves the `Hostapd`'s BSSID.
+    pub fn get_bssid(&self) -> MacAddress {
+        MacAddress::try_from(0).unwrap()
+    }
+
+    /// Attempt to encrypt the given IEEE 802.11 frame.
+    pub fn try_encrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        None
+    }
+
+    /// Attempt to decrypt the given IEEE 802.11 frame.
+    pub fn try_decrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        None
+    }
+}
+
+pub fn hostapd_run(_opt: ProtoHostapdOptions, _tx: mpsc::Sender<Bytes>) -> anyhow::Result<Hostapd> {
+    Ok(Hostapd {})
+}
diff --git a/rust/daemon/src/wifi/hwsim_attr_set.rs b/rust/daemon/src/wifi/hwsim_attr_set.rs
index cd64cb6b..d7c8b3e0 100644
--- a/rust/daemon/src/wifi/hwsim_attr_set.rs
+++ b/rust/daemon/src/wifi/hwsim_attr_set.rs
@@ -14,10 +14,10 @@
 
 use std::fmt;
 
-use super::packets::ieee80211::MacAddress;
-use super::packets::mac80211_hwsim::{self, HwsimAttr, HwsimAttrChild::*, TxRate, TxRateFlag};
-use super::packets::netlink::NlAttrHdr;
 use anyhow::{anyhow, Context};
+use netsim_packets::ieee80211::MacAddress;
+use netsim_packets::mac80211_hwsim::{self, HwsimAttr, HwsimAttrChild::*, TxRate, TxRateFlag};
+use netsim_packets::netlink::NlAttrHdr;
 use pdl_runtime::Packet;
 use std::option::Option;
 
@@ -288,10 +288,10 @@ impl HwsimAttrSet {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::wifi::packets::ieee80211::parse_mac_address;
-    use crate::wifi::packets::mac80211_hwsim::{HwsimCmd, HwsimMsg};
     use anyhow::Context;
     use anyhow::Error;
+    use netsim_packets::ieee80211::parse_mac_address;
+    use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg};
 
     // Validate `HwsimAttrSet` attribute parsing from byte vector.
     #[test]
diff --git a/rust/daemon/src/wifi/libslirp.rs b/rust/daemon/src/wifi/libslirp.rs
index a8251b70..e4211033 100644
--- a/rust/daemon/src/wifi/libslirp.rs
+++ b/rust/daemon/src/wifi/libslirp.rs
@@ -14,35 +14,32 @@
 
 /// LibSlirp Interface for Network Simulation
 use bytes::Bytes;
-#[cfg(not(feature = "cuttlefish"))]
+use http_proxy::Manager;
 pub use libslirp_rs::libslirp::LibSlirp;
-#[cfg(not(feature = "cuttlefish"))]
-use libslirp_rs::libslirp_config::SlirpConfig;
+use libslirp_rs::libslirp::ProxyManager;
+use libslirp_rs::libslirp_config::{lookup_host_dns, SlirpConfig};
 use netsim_proto::config::SlirpOptions as ProtoSlirpOptions;
 use std::sync::mpsc;
+use tokio::runtime::Runtime;
 
-// Provides a stub implementation while the libslirp-rs crate is not integrated into the aosp-main.
-#[cfg(feature = "cuttlefish")]
-pub struct LibSlirp {}
-#[cfg(feature = "cuttlefish")]
-impl LibSlirp {
-    pub fn input(&self, _bytes: Bytes) {}
-}
-
-#[cfg(not(feature = "cuttlefish"))]
 pub fn slirp_run(
-    _opt: ProtoSlirpOptions,
+    opt: ProtoSlirpOptions,
     tx_bytes: mpsc::Sender<Bytes>,
 ) -> anyhow::Result<LibSlirp> {
     // TODO: Convert ProtoSlirpOptions to SlirpConfig.
-    let config = SlirpConfig { ..Default::default() };
-    Ok(LibSlirp::new(config, tx_bytes))
-}
+    let http_proxy = Some(opt.http_proxy).filter(|s| !s.is_empty());
+    let proxy_manager = if let Some(proxy) = http_proxy {
+        Some(Box::new(Manager::new(&proxy)?) as Box<dyn ProxyManager + 'static>)
+    } else {
+        None
+    };
 
-#[cfg(feature = "cuttlefish")]
-pub fn slirp_run(
-    _opt: ProtoSlirpOptions,
-    _tx_bytes: mpsc::Sender<Bytes>,
-) -> anyhow::Result<LibSlirp> {
-    Ok(LibSlirp {})
+    let mut config = SlirpConfig { http_proxy_on: proxy_manager.is_some(), ..Default::default() };
+
+    if !opt.host_dns.is_empty() {
+        let rt = Runtime::new().unwrap();
+        config.host_dns = rt.block_on(lookup_host_dns(&opt.host_dns))?;
+    }
+
+    Ok(LibSlirp::new(config, tx_bytes, proxy_manager))
 }
diff --git a/rust/daemon/src/wifi/libslirp_cf.rs b/rust/daemon/src/wifi/libslirp_cf.rs
new file mode 100644
index 00000000..96380480
--- /dev/null
+++ b/rust/daemon/src/wifi/libslirp_cf.rs
@@ -0,0 +1,31 @@
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
+/// LibSlirp Interface for Network Simulation
+use bytes::Bytes;
+use netsim_proto::config::SlirpOptions as ProtoSlirpOptions;
+use std::sync::mpsc;
+
+// Provides a stub implementation while the libslirp-rs crate is not integrated into the aosp-main.
+pub struct LibSlirp {}
+impl LibSlirp {
+    pub fn input(&self, _bytes: Bytes) {}
+}
+
+pub fn slirp_run(
+    _opt: ProtoSlirpOptions,
+    _tx_bytes: mpsc::Sender<Bytes>,
+) -> anyhow::Result<LibSlirp> {
+    Ok(LibSlirp {})
+}
diff --git a/rust/daemon/src/wifi/medium.rs b/rust/daemon/src/wifi/medium.rs
index d01c44c0..546387bb 100644
--- a/rust/daemon/src/wifi/medium.rs
+++ b/rust/daemon/src/wifi/medium.rs
@@ -12,15 +12,16 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use super::packets::ieee80211::{DataSubType, Ieee80211, MacAddress};
-use super::packets::mac80211_hwsim::{HwsimCmd, HwsimMsg, HwsimMsgHdr, NlMsgHdr};
 use crate::wifi::frame::Frame;
+use crate::wifi::hostapd::Hostapd;
 use crate::wifi::hwsim_attr_set::HwsimAttrSet;
 use anyhow::{anyhow, Context};
 use bytes::Bytes;
 use log::{debug, info, warn};
+use netsim_packets::ieee80211::{DataSubType, Ieee80211, MacAddress};
+use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg, HwsimMsgHdr, NlMsgHdr};
 use pdl_runtime::Packet;
-use std::collections::{HashMap, HashSet};
+use std::collections::HashMap;
 use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
 use std::sync::{Arc, RwLock};
 
@@ -37,6 +38,25 @@ pub struct Processor {
     pub network: bool,
     pub wmedium: bool,
     pub frame: Frame,
+    pub plaintext_ieee80211: Option<Ieee80211>,
+}
+
+impl Processor {
+    /// Returns the decrypted IEEE 802.11 frame if available.
+    /// Otherwise, returns the original IEEE 80211 frame.
+    pub fn get_ieee80211(&self) -> &Ieee80211 {
+        self.plaintext_ieee80211.as_ref().unwrap_or(&self.frame.ieee80211)
+    }
+
+    /// Returns the decrypted IEEE 802.11 frame as bytes if available.
+    /// Otherwise, returns the original IEEE 80211 frame as bytes.
+    pub fn get_ieee80211_bytes(&self) -> Bytes {
+        if let Some(ieee80211) = self.plaintext_ieee80211.as_ref() {
+            ieee80211.encode_to_vec().unwrap().into()
+        } else {
+            self.frame.data.clone().into()
+        }
+    }
 }
 
 #[allow(dead_code)]
@@ -98,24 +118,20 @@ pub struct Medium {
     // Ieee80211 source address
     stations: RwLock<HashMap<MacAddress, Arc<Station>>>,
     clients: RwLock<HashMap<u32, Client>>,
-    // BSSID. MAC address of the access point in WiFi Service.
-    hostapd_bssid: MacAddress,
     // Simulate the re-transmission of frames sent to hostapd
     ap_simulation: bool,
+    hostapd: Arc<Hostapd>,
 }
 
 type HwsimCmdCallback = fn(u32, &Bytes);
 impl Medium {
-    pub fn new(callback: HwsimCmdCallback) -> Medium {
-        // Defined in external/qemu/android-qemu2-glue/emulation/WifiService.cpp
-        // TODO: Use hostapd_bssid to initialize hostapd.
-        let bssid_bytes: [u8; 6] = [0x00, 0x13, 0x10, 0x85, 0xfe, 0x01];
+    pub fn new(callback: HwsimCmdCallback, hostapd: Arc<Hostapd>) -> Medium {
         Self {
             callback,
             stations: RwLock::new(HashMap::new()),
             clients: RwLock::new(HashMap::new()),
-            hostapd_bssid: MacAddress::from(&bssid_bytes),
             ap_simulation: true,
+            hostapd,
         }
     }
 
@@ -215,7 +231,15 @@ impl Medium {
             .map_err(|e| warn!("error upsert station for client {client_id}: {e}"))
             .ok()?;
 
-        let mut processor = Processor { hostapd: false, network: false, wmedium: false, frame };
+        let plaintext_ieee80211 = self.hostapd.try_decrypt(&frame.ieee80211);
+
+        let mut processor = Processor {
+            hostapd: false,
+            network: false,
+            wmedium: false,
+            frame,
+            plaintext_ieee80211,
+        };
 
         let dest_addr = processor.frame.ieee80211.get_destination();
 
@@ -227,7 +251,6 @@ impl Medium {
                 })
         });
 
-        let frame = &processor.frame;
         if self.contains_station(&dest_addr) {
             processor.wmedium = true;
             return Some(processor);
@@ -236,27 +259,33 @@ impl Medium {
             processor.wmedium = true;
         }
 
+        let ieee80211: &Ieee80211 = processor.get_ieee80211();
+        // If the BSSID is unicast and does not match the hostapd's BSSID, the packet is not handled by hostapd. Skip further checks.
+        if let Some(bssid) = ieee80211.get_bssid() {
+            if !bssid.is_multicast() && bssid != self.hostapd.get_bssid() {
+                return Some(processor);
+            }
+        }
         // Data frames
-        if frame.ieee80211.is_data() {
-            // TODO: Need to handle encrypted IEEE 802.11 frame.
+        if ieee80211.is_data() {
             // EAPoL is used in Wi-Fi 4-way handshake.
-            let is_eapol = frame.ieee80211.is_eapol().unwrap_or_else(|e| {
+            let is_eapol = ieee80211.is_eapol().unwrap_or_else(|e| {
                 debug!("Failed to get ether type for is_eapol(): {}", e);
                 false
             });
             if is_eapol {
                 processor.hostapd = true;
-            } else if frame.ieee80211.is_to_ap() {
+            } else if ieee80211.is_to_ap() {
                 // Don't forward Null Data frames to slirp because they are used to maintain an active connection and carry no user data.
-                if processor.frame.ieee80211.stype() != DataSubType::Nodata.into() {
+                if ieee80211.stype() != DataSubType::Nodata.into() {
                     processor.network = true;
                 }
             }
         } else {
             // Mgmt or Ctrl frames.
             // TODO: Refactor this check after verifying all packets sent to hostapd are of ToAP type.
-            let addr1 = frame.ieee80211.get_addr1();
-            if addr1.is_multicast() || addr1.is_broadcast() || addr1 == self.hostapd_bssid {
+            let addr1 = ieee80211.get_addr1();
+            if addr1.is_multicast() || addr1.is_broadcast() || addr1 == self.hostapd.get_bssid() {
                 processor.hostapd = true;
             }
         }
@@ -296,7 +325,7 @@ impl Medium {
     /// Handle Wi-Fi Ieee802.3 frame from network.
     /// Convert to HwsimMsg and send to clients.
     pub fn process_ieee8023_response(&self, packet: &Bytes) {
-        let result = Ieee80211::from_ieee8023(packet, self.hostapd_bssid)
+        let result = Ieee80211::from_ieee8023(packet, self.hostapd.get_bssid())
             .and_then(|ieee80211| self.handle_ieee80211_response(ieee80211));
 
         if let Err(e) = result {
@@ -317,7 +346,10 @@ impl Medium {
     }
 
     /// Determine the client id based on destination and send to client.
-    fn handle_ieee80211_response(&self, ieee80211: Ieee80211) -> anyhow::Result<()> {
+    fn handle_ieee80211_response(&self, mut ieee80211: Ieee80211) -> anyhow::Result<()> {
+        if let Some(encrypted_ieee80211) = self.hostapd.try_encrypt(&ieee80211) {
+            ieee80211 = encrypted_ieee80211;
+        }
         let dest_addr = ieee80211.get_destination();
         if let Ok(destination) = self.get_station(&dest_addr) {
             self.send_ieee80211_response(&ieee80211, &destination)?;
@@ -376,82 +408,6 @@ impl Medium {
         Ok(builder.build()?.attributes)
     }
 
-    /// Handle Wi-Fi MwsimMsg from libslirp and hostapd.
-    /// Send it to clients.
-    pub fn process_response(&self, packet: &Bytes) {
-        if let Err(e) = self.send_response(packet) {
-            warn!("{}", e);
-        }
-    }
-
-    /// Determine the client id based on Ieee80211 destination and send to client.
-    fn send_response(&self, packet: &Bytes) -> anyhow::Result<()> {
-        let hwsim_msg = HwsimMsg::decode_full(packet)?;
-        let hwsim_cmd = hwsim_msg.hwsim_hdr.hwsim_cmd;
-        match hwsim_cmd {
-            HwsimCmd::Frame => self.send_frame_response(packet, &hwsim_msg)?,
-            // TODO: Handle sending TxInfo frame for WifiService so we don't have to
-            // send duplicate HwsimMsg for all clients with the same Hwsim addr.
-            HwsimCmd::TxInfoFrame => self.send_tx_info_response(packet, &hwsim_msg)?,
-            _ => return Err(anyhow!("Invalid HwsimMsg cmd={:?}", hwsim_cmd)),
-        };
-        Ok(())
-    }
-
-    fn send_frame_response(&self, packet: &Bytes, hwsim_msg: &HwsimMsg) -> anyhow::Result<()> {
-        let frame = Frame::parse(hwsim_msg)?;
-        let dest_addr = frame.ieee80211.get_destination();
-        if let Ok(destination) = self.get_station(&dest_addr) {
-            self.send_from_ds_frame(packet, &frame, &destination)?;
-        } else if dest_addr.is_multicast() {
-            for destination in self.stations() {
-                self.send_from_ds_frame(packet, &frame, &destination)?;
-            }
-        } else {
-            warn!("Send frame response to unknown destination: {}", dest_addr);
-        }
-        Ok(())
-    }
-
-    /// Send frame from DS to STA.
-    fn send_from_ds_frame(
-        &self,
-        packet: &Bytes,
-        frame: &Frame,
-        destination: &Station,
-    ) -> anyhow::Result<()> {
-        if frame.attrs.receiver.context("receiver")? == destination.hwsim_addr {
-            (self.callback)(destination.client_id, packet);
-        } else {
-            // Broadcast: replace HwsimMsg destination but keep other attributes
-            let hwsim_msg = self
-                .create_hwsim_msg(frame, &destination.hwsim_addr)
-                .context("Create HwsimMsg from WifiService")?;
-            (self.callback)(destination.client_id, &hwsim_msg.encode_to_vec()?.into());
-        }
-        self.incr_rx(destination.client_id)?;
-        Ok(())
-    }
-
-    fn send_tx_info_response(&self, packet: &Bytes, hwsim_msg: &HwsimMsg) -> anyhow::Result<()> {
-        let attrs = HwsimAttrSet::parse(&hwsim_msg.attributes).context("HwsimAttrSet")?;
-        let hwsim_addr = attrs.transmitter.context("missing transmitter")?;
-        let client_ids = self
-            .stations()
-            .filter(|v| v.hwsim_addr == hwsim_addr)
-            .map(|v| v.client_id)
-            .collect::<HashSet<_>>();
-        if client_ids.len() > 1 {
-            warn!("multiple clients found for TxInfo frame");
-        }
-        for client_id in client_ids {
-            if self.enabled(client_id)? {
-                (self.callback)(client_id, packet);
-            }
-        }
-        Ok(())
-    }
-
     pub fn set_enabled(&self, client_id: u32, enabled: bool) {
         if let Some(client) = self.clients.read().unwrap().get(&client_id) {
             client.enabled.store(enabled, Ordering::Relaxed);
@@ -506,11 +462,12 @@ impl Medium {
     fn send_from_sta_frame(
         &self,
         frame: &Frame,
+        ieee80211: &Ieee80211,
         source: &Station,
         destination: &Station,
     ) -> anyhow::Result<()> {
         if self.enabled(source.client_id)? && self.enabled(destination.client_id)? {
-            if let Some(packet) = self.create_hwsim_msg(frame, &destination.hwsim_addr) {
+            if let Some(packet) = self.create_hwsim_msg(frame, ieee80211, &destination.hwsim_addr) {
                 self.incr_rx(destination.client_id)?;
                 (self.callback)(destination.client_id, &packet.encode_to_vec()?.into());
                 log_hwsim_msg(frame, source.client_id, destination.client_id);
@@ -521,37 +478,44 @@ impl Medium {
 
     // Broadcast an 802.11 frame to all stations.
     /// TODO: Compare with the implementations in mac80211_hwsim.c and wmediumd.c.
-    fn broadcast_from_sta_frame(&self, frame: &Frame, source: &Station) -> anyhow::Result<()> {
+    fn broadcast_from_sta_frame(
+        &self,
+        frame: &Frame,
+        ieee80211: &Ieee80211,
+        source: &Station,
+    ) -> anyhow::Result<()> {
         for destination in self.stations() {
             if source.addr != destination.addr {
-                self.send_from_sta_frame(frame, source, &destination)?;
+                self.send_from_sta_frame(frame, ieee80211, source, &destination)?;
             }
         }
         Ok(())
     }
-
-    pub fn queue_frame(&self, frame: Frame) {
-        self.queue_frame_internal(frame).unwrap_or_else(move |e| {
+    /// Queues the frame for sending to medium.
+    ///
+    /// The `frame` contains an `ieee80211` field, but it might be encrypted. This function uses the provided `ieee80211` parameter directly, as it's expected to be decrypted if necessary.
+    pub fn queue_frame(&self, frame: Frame, ieee80211: Ieee80211) {
+        self.queue_frame_internal(frame, ieee80211).unwrap_or_else(move |e| {
             // TODO: add this error to the netsim_session_stats
             warn!("queue frame error {e}");
         });
     }
 
-    fn queue_frame_internal(&self, frame: Frame) -> anyhow::Result<()> {
-        let source = self.get_station(&frame.ieee80211.get_source())?;
-        let dest_addr = frame.ieee80211.get_destination();
+    fn queue_frame_internal(&self, frame: Frame, ieee80211: Ieee80211) -> anyhow::Result<()> {
+        let source = self.get_station(&ieee80211.get_source())?;
+        let dest_addr = ieee80211.get_destination();
         if self.contains_station(&dest_addr) {
             debug!("Frame deliver from {} to {}", source.addr, dest_addr);
             let destination = self.get_station(&dest_addr)?;
-            self.send_from_sta_frame(&frame, &source, &destination)?;
+            self.send_from_sta_frame(&frame, &ieee80211, &source, &destination)?;
             return Ok(());
         } else if dest_addr.is_multicast() {
-            debug!("Frame multicast {}", frame.ieee80211);
-            self.broadcast_from_sta_frame(&frame, &source)?;
+            debug!("Frame multicast {}", ieee80211);
+            self.broadcast_from_sta_frame(&frame, &ieee80211, &source)?;
             return Ok(());
         }
 
-        Err(anyhow!("Dropped packet {}", &frame.ieee80211))
+        Err(anyhow!("Dropped packet {}", ieee80211))
     }
 
     // Simulate transmission through hostapd by rewriting frames with 802.11 ToDS
@@ -559,16 +523,22 @@ impl Medium {
     fn create_hwsim_attr(
         &self,
         frame: &Frame,
+        ieee80211: &Ieee80211,
         dest_hwsim_addr: &MacAddress,
     ) -> anyhow::Result<Vec<u8>> {
+        // Encrypt Ieee80211 if needed
         let attrs = &frame.attrs;
-        let frame = match self.ap_simulation
-            && frame.ieee80211.is_to_ap()
-            && frame.ieee80211.get_bssid() == Some(self.hostapd_bssid)
+        let mut ieee80211_response = match self.ap_simulation
+            && ieee80211.is_to_ap()
+            && ieee80211.get_bssid() == Some(self.hostapd.get_bssid())
         {
-            true => frame.ieee80211.into_from_ap()?.encode_to_vec()?,
-            false => attrs.frame.clone().unwrap(),
+            true => ieee80211.into_from_ap()?.try_into()?,
+            false => ieee80211.clone(),
         };
+        if let Some(encrypted_ieee80211) = self.hostapd.try_encrypt(&ieee80211_response) {
+            ieee80211_response = encrypted_ieee80211;
+        }
+        let frame = ieee80211_response.encode_to_vec()?;
 
         let mut builder = HwsimAttrSet::builder();
 
@@ -588,10 +558,15 @@ impl Medium {
     }
 
     // Simulates transmission through hostapd.
-    fn create_hwsim_msg(&self, frame: &Frame, dest_hwsim_addr: &MacAddress) -> Option<HwsimMsg> {
+    fn create_hwsim_msg(
+        &self,
+        frame: &Frame,
+        ieee80211: &Ieee80211,
+        dest_hwsim_addr: &MacAddress,
+    ) -> Option<HwsimMsg> {
         let hwsim_msg = &frame.hwsim_msg;
         assert_eq!(hwsim_msg.hwsim_hdr.hwsim_cmd, HwsimCmd::Frame);
-        let attributes_result = self.create_hwsim_attr(frame, dest_hwsim_addr);
+        let attributes_result = self.create_hwsim_attr(frame, ieee80211, dest_hwsim_addr);
         let attributes = match attributes_result {
             Ok(attributes) => attributes,
             Err(e) => {
@@ -679,11 +654,68 @@ pub fn parse_hwsim_cmd(packet: &[u8]) -> anyhow::Result<HwsimCmdEnum> {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::wifi::packets::ieee80211::parse_mac_address;
+    use crate::wifi::hostapd;
+    use netsim_packets::ieee80211::{parse_mac_address, FrameType, Ieee80211, Ieee80211ToAp};
+
     #[test]
-    fn test_remove() {
-        let hostapd_bssid: MacAddress = parse_mac_address("00:13:10:85:fe:01").unwrap();
+    fn test_get_plaintext_ieee80211() {
+        // Test Data (802.11 frame with LLC/SNAP)
+        let bssid = parse_mac_address("0:0:0:0:0:0").unwrap();
+        let source = parse_mac_address("1:1:1:1:1:1").unwrap();
+        let destination = parse_mac_address("2:2:2:2:2:2").unwrap();
+        let ieee80211: Ieee80211 = Ieee80211ToAp {
+            duration_id: 0,
+            ftype: FrameType::Data,
+            more_data: 0,
+            more_frags: 0,
+            order: 0,
+            pm: 0,
+            protected: 0,
+            retry: 0,
+            stype: 0,
+            version: 0,
+            bssid,
+            source,
+            destination,
+            seq_ctrl: 0,
+            payload: Vec::new(),
+        }
+        .try_into()
+        .unwrap();
 
+        let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame_mdns.csv");
+        let hwsim_msg = HwsimMsg::decode_full(&packet).unwrap();
+        let frame1 = Frame::parse(&hwsim_msg).unwrap();
+        let frame2 = Frame::parse(&hwsim_msg).unwrap();
+
+        // Case 1: plaintext_ieee80211 is None
+        let processor = Processor {
+            hostapd: false,
+            network: false,
+            wmedium: false,
+            frame: frame1,
+            plaintext_ieee80211: None,
+        };
+        assert_eq!(processor.get_ieee80211(), &processor.frame.ieee80211);
+        assert_eq!(processor.get_ieee80211_bytes(), Bytes::from(processor.frame.data.clone()));
+
+        // Case 2: plaintext_ieee80211 has a value
+        let processor = Processor {
+            hostapd: false,
+            network: false,
+            wmedium: false,
+            frame: frame2,
+            plaintext_ieee80211: Some(ieee80211),
+        };
+        assert_eq!(processor.get_ieee80211(), processor.plaintext_ieee80211.as_ref().unwrap());
+        assert_eq!(
+            processor.get_ieee80211_bytes(),
+            Bytes::from(processor.plaintext_ieee80211.as_ref().unwrap().encode_to_vec().unwrap())
+        );
+    }
+
+    #[test]
+    fn test_remove() {
         let test_client_id: u32 = 1234;
         let other_client_id: u32 = 5678;
         let addr: MacAddress = parse_mac_address("00:0b:85:71:20:00").unwrap();
@@ -691,6 +723,10 @@ mod tests {
         let hwsim_addr: MacAddress = parse_mac_address("00:0b:85:71:20:ce").unwrap();
         let other_hwsim_addr: MacAddress = parse_mac_address("00:0b:85:71:20:cf").unwrap();
 
+        let hostapd_options = netsim_proto::config::HostapdOptions::new();
+        let (tx, _rx) = std::sync::mpsc::channel();
+        let hostapd = Arc::new(hostapd::hostapd_run(hostapd_options, tx).unwrap());
+
         // Create a test Medium object
         let callback: HwsimCmdCallback = |_, _| {};
         let medium = Medium {
@@ -719,8 +755,8 @@ mod tests {
                 (test_client_id, Client::new()),
                 (other_client_id, Client::new()),
             ])),
-            hostapd_bssid,
             ap_simulation: true,
+            hostapd,
         };
 
         medium.remove(test_client_id);
diff --git a/rust/daemon/src/wifi/mod.rs b/rust/daemon/src/wifi/mod.rs
index 99bbfc0b..712ad1c5 100644
--- a/rust/daemon/src/wifi/mod.rs
+++ b/rust/daemon/src/wifi/mod.rs
@@ -16,11 +16,12 @@
 // [cfg(not(test))] avoids getting compiled during local Rust unit tests
 
 pub(crate) mod frame;
+#[cfg_attr(feature = "cuttlefish", path = "hostapd_cf.rs")]
 pub(crate) mod hostapd;
 pub(crate) mod hwsim_attr_set;
+#[cfg_attr(feature = "cuttlefish", path = "libslirp_cf.rs")]
 pub(crate) mod libslirp;
 #[cfg(not(feature = "cuttlefish"))]
 pub(crate) mod mdns_forwarder;
 pub(crate) mod medium;
-pub(crate) mod packets;
 pub(crate) mod radiotap;
diff --git a/rust/daemon/src/wireless/wifi.rs b/rust/daemon/src/wireless/wifi.rs
index c61ef690..e423e8cd 100644
--- a/rust/daemon/src/wireless/wifi.rs
+++ b/rust/daemon/src/wireless/wifi.rs
@@ -13,7 +13,6 @@
 // limitations under the License.
 
 use crate::devices::chip::ChipIdentifier;
-use crate::ffi::ffi_wifi;
 use crate::wifi::hostapd;
 use crate::wifi::libslirp;
 #[cfg(not(feature = "cuttlefish"))]
@@ -23,12 +22,12 @@ use crate::wireless::{packet::handle_response, WirelessAdaptor, WirelessAdaptorI
 use anyhow;
 use bytes::Bytes;
 use log::{info, warn};
-use netsim_proto::config::{HostapdOptions, SlirpOptions, WiFi as WiFiConfig};
+use netsim_proto::config::WiFi as WiFiConfig;
 use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::stats::{netsim_radio_stats, NetsimRadioStats as ProtoRadioStats};
-use protobuf::{Message, MessageField};
+use protobuf::MessageField;
 use std::sync::atomic::Ordering;
-use std::sync::{mpsc, OnceLock};
+use std::sync::{mpsc, Arc, OnceLock};
 use std::thread;
 use std::time::{Duration, Instant};
 
@@ -45,22 +44,20 @@ pub struct Wifi {
 pub struct WifiManager {
     medium: Medium,
     tx_request: mpsc::Sender<(u32, Bytes)>,
-    tx_response: mpsc::Sender<Bytes>,
-    slirp: Option<libslirp::LibSlirp>,
-    hostapd: Option<hostapd::Hostapd>,
+    slirp: libslirp::LibSlirp,
+    hostapd: Arc<hostapd::Hostapd>,
 }
 
 impl WifiManager {
     pub fn new(
         tx_request: mpsc::Sender<(u32, Bytes)>,
-        tx_response: mpsc::Sender<Bytes>,
-        slirp: Option<libslirp::LibSlirp>,
-        hostapd: Option<hostapd::Hostapd>,
+        slirp: libslirp::LibSlirp,
+        hostapd: hostapd::Hostapd,
     ) -> WifiManager {
+        let hostapd = Arc::new(hostapd);
         WifiManager {
-            medium: Medium::new(medium_callback),
+            medium: Medium::new(medium_callback, hostapd.clone()),
             tx_request,
-            tx_response,
             slirp,
             hostapd,
         }
@@ -68,20 +65,17 @@ impl WifiManager {
 
     /// Starts background threads:
     /// * One to handle requests from medium.
-    /// * One to handle responses from network.
     /// * One to handle IEEE802.3 responses from network.
     /// * One to handle IEEE802.11 responses from hostapd.
     pub fn start(
         &self,
         rx_request: mpsc::Receiver<(u32, Bytes)>,
-        rx_response: mpsc::Receiver<Bytes>,
         rx_ieee8023_response: mpsc::Receiver<Bytes>,
         rx_ieee80211_response: mpsc::Receiver<Bytes>,
         tx_ieee8023_response: mpsc::Sender<Bytes>,
         forward_host_mdns: bool,
     ) -> anyhow::Result<()> {
         self.start_request_thread(rx_request)?;
-        self.start_response_thread(rx_response)?;
         self.start_ieee8023_response_thread(rx_ieee8023_response)?;
         self.start_ieee80211_response_thread(rx_ieee80211_response)?;
         if forward_host_mdns {
@@ -91,8 +85,6 @@ impl WifiManager {
     }
 
     fn start_request_thread(&self, rx_request: mpsc::Receiver<(u32, Bytes)>) -> anyhow::Result<()> {
-        let rust_slirp = self.slirp.is_some();
-        let rust_hostapd = self.hostapd.is_some();
         thread::Builder::new().name("Wi-Fi HwsimMsg request".to_string()).spawn(move || {
             const POLL_INTERVAL: Duration = Duration::from_millis(1);
             let mut next_instant = Instant::now() + POLL_INTERVAL;
@@ -111,46 +103,29 @@ impl WifiManager {
                         {
                             get_wifi_manager().medium.ack_frame(chip_id, &processor.frame);
                             if processor.hostapd {
-                                if rust_hostapd {
-                                    let ieee80211: Bytes = processor.frame.data.clone().into();
-                                    if let Err(err) = get_wifi_manager()
-                                        .hostapd
-                                        .as_ref()
-                                        .expect("hostapd initialized")
-                                        .input(ieee80211)
-                                    {
-                                        warn!("Failed to call hostapd input: {:?}", err);
-                                    };
-                                } else {
-                                    ffi_wifi::hostapd_send(&packet.to_vec());
-                                }
+                                let ieee80211: Bytes = processor.get_ieee80211_bytes();
+                                if let Err(err) = get_wifi_manager().hostapd.input(ieee80211) {
+                                    warn!("Failed to call hostapd input: {:?}", err);
+                                };
                             }
                             if processor.network {
-                                if rust_slirp {
-                                    match processor.frame.ieee80211.to_ieee8023() {
-                                        Ok(ethernet_frame) => get_wifi_manager()
-                                            .slirp
-                                            .as_ref()
-                                            .expect("slirp initialized")
-                                            .input(ethernet_frame.into()),
-                                        Err(err) => {
-                                            warn!("Failed to convert 802.11 to 802.3: {}", err)
-                                        }
+                                match processor.get_ieee80211().to_ieee8023() {
+                                    Ok(ethernet_frame) => {
+                                        get_wifi_manager().slirp.input(ethernet_frame.into())
+                                    }
+                                    Err(err) => {
+                                        warn!("Failed to convert 802.11 to 802.3: {}", err)
                                     }
-                                } else {
-                                    ffi_wifi::libslirp_send(&packet.to_vec());
-                                    ffi_wifi::libslirp_main_loop_wait();
                                 }
                             }
                             if processor.wmedium {
-                                get_wifi_manager().medium.queue_frame(processor.frame);
+                                // Decrypt the frame using the sender's key and re-encrypt it using the receiver's key for peer-to-peer communication through hostapd (broadcast or unicast).
+                                let ieee80211 = processor.get_ieee80211().clone();
+                                get_wifi_manager().medium.queue_frame(processor.frame, ieee80211);
                             }
                         }
                     }
                     _ => {
-                        if !rust_slirp {
-                            ffi_wifi::libslirp_main_loop_wait();
-                        }
                         next_instant = Instant::now() + POLL_INTERVAL;
                     }
                 };
@@ -159,16 +134,6 @@ impl WifiManager {
         Ok(())
     }
 
-    /// Starts a dedicated thread to handle WifiService responses.
-    fn start_response_thread(&self, rx_response: mpsc::Receiver<Bytes>) -> anyhow::Result<()> {
-        thread::Builder::new().name("WifiService response".to_string()).spawn(move || {
-            for packet in rx_response {
-                get_wifi_manager().medium.process_response(&packet);
-            }
-        })?;
-        Ok(())
-    }
-
     /// Starts a dedicated thread to process IEEE 802.3 (Ethernet) responses from the network.
     ///
     /// This thread continuously receives IEEE 802.3 response packets from the `rx_ieee8023_response` channel
@@ -281,11 +246,6 @@ fn medium_callback(id: u32, packet: &Bytes) {
     handle_response(ChipIdentifier(id), packet);
 }
 
-pub fn handle_wifi_response(packet: &[u8]) {
-    let bytes = Bytes::copy_from_slice(packet);
-    get_wifi_manager().tx_response.send(bytes).unwrap();
-}
-
 /// Create a new Emulated Wifi Chip
 /// allow(dead_code) due to not being used in unit tests
 #[allow(dead_code)]
@@ -297,55 +257,26 @@ pub fn new(_params: &CreateParams, chip_id: ChipIdentifier) -> WirelessAdaptorIm
 }
 
 /// Starts the WiFi service.
-pub fn wifi_start(
-    config: &MessageField<WiFiConfig>,
-    rust_slirp: bool,
-    rust_hostapd: bool,
-    forward_host_mdns: bool,
-) {
+pub fn wifi_start(config: &MessageField<WiFiConfig>, forward_host_mdns: bool) {
     let (tx_request, rx_request) = mpsc::channel::<(u32, Bytes)>();
-    let (tx_response, rx_response) = mpsc::channel::<Bytes>();
     let (tx_ieee8023_response, rx_ieee8023_response) = mpsc::channel::<Bytes>();
     let (tx_ieee80211_response, rx_ieee80211_response) = mpsc::channel::<Bytes>();
     let tx_ieee8023_response_clone = tx_ieee8023_response.clone();
-    let mut slirp = None;
-    let mut wifi_config = config.clone().unwrap_or_default();
-    if rust_slirp {
-        let slirp_opt = wifi_config.slirp_options.as_ref().unwrap_or_default().clone();
-        slirp = Some(
-            libslirp::slirp_run(slirp_opt, tx_ieee8023_response_clone)
-                .map_err(|e| warn!("Failed to run libslirp. {e}"))
-                .unwrap(),
-        );
-
-        // Disable qemu slirp in WifiService
-        wifi_config.slirp_options =
-            MessageField::some(SlirpOptions { disabled: true, ..Default::default() });
-    }
-
-    let mut hostapd = None;
-    if rust_hostapd {
-        let hostapd_opt = wifi_config.hostapd_options.as_ref().unwrap_or_default().clone();
-        hostapd = Some(
-            hostapd::hostapd_run(hostapd_opt, tx_ieee80211_response)
-                .map_err(|e| warn!("Failed to run hostapd. {e}"))
-                .unwrap(),
-        );
-
-        // Disable qemu hostapd in WifiService
-        wifi_config.hostapd_options =
-            MessageField::some(HostapdOptions { disabled: Some(true), ..Default::default() });
-    }
+    let wifi_config = config.clone().unwrap_or_default();
+    let slirp_opt = wifi_config.slirp_options.as_ref().unwrap_or_default().clone();
+    let slirp = libslirp::slirp_run(slirp_opt, tx_ieee8023_response_clone)
+        .map_err(|e| warn!("Failed to run libslirp. {e}"))
+        .unwrap();
 
-    let _ = WIFI_MANAGER.set(WifiManager::new(tx_request, tx_response, slirp, hostapd));
+    let hostapd_opt = wifi_config.hostapd_options.as_ref().unwrap_or_default().clone();
+    let hostapd = hostapd::hostapd_run(hostapd_opt, tx_ieee80211_response)
+        .map_err(|e| warn!("Failed to run hostapd. {e}"))
+        .unwrap();
 
-    // WifiService
-    let proto_bytes = wifi_config.write_to_bytes().unwrap();
-    ffi_wifi::wifi_start(&proto_bytes);
+    let _ = WIFI_MANAGER.set(WifiManager::new(tx_request, slirp, hostapd));
 
     if let Err(e) = get_wifi_manager().start(
         rx_request,
-        rx_response,
         rx_ieee8023_response,
         rx_ieee80211_response,
         tx_ieee8023_response,
@@ -358,5 +289,4 @@ pub fn wifi_start(
 /// Stops the WiFi service.
 pub fn wifi_stop() {
     // TODO: stop hostapd
-    ffi_wifi::wifi_stop();
 }
diff --git a/rust/hostapd-rs/Cargo.toml b/rust/hostapd-rs/Cargo.toml
index ba453069..4dc16eb9 100644
--- a/rust/hostapd-rs/Cargo.toml
+++ b/rust/hostapd-rs/Cargo.toml
@@ -28,6 +28,8 @@ anyhow = "1"
 bytes = { version = "1.4.0"}
 log = "0.4.17"
 netsim-common = { path = "../common" }
+netsim-packets = { path = "../packets" }
+pdl-runtime = "0.3.0"
 tokio = { version = "1.32.0", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "sync"] }
 
 [build-dependencies]
diff --git a/rust/hostapd-rs/build.rs b/rust/hostapd-rs/build.rs
new file mode 100644
index 00000000..c24ee0e6
--- /dev/null
+++ b/rust/hostapd-rs/build.rs
@@ -0,0 +1,43 @@
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
+//! Build script for linking `hostapd-rs` with the `hostapd` C library and its dependencies.
+
+pub fn main() {
+    let objs_path = std::env::var("OBJS_PATH").unwrap_or("../objs".to_string());
+
+    // Shared dependencies
+    println!("cargo:rustc-link-search={objs_path}/archives");
+    println!("cargo:rustc-link-lib=hostapd");
+    println!("cargo:rustc-link-lib=crypto");
+    println!("cargo:rustc-link-lib=android-emu-base");
+    println!("cargo:rustc-link-lib=android-emu-utils");
+    println!("cargo:rustc-link-lib=logging-base");
+    println!("cargo:rustc-link-lib=android-emu-base-logging");
+    // Linux and Mac dependencies
+    #[cfg(unix)]
+    {
+        println!("cargo:rustc-link-search={objs_path}/lib64");
+        println!("cargo:rustc-link-lib=c++");
+    }
+    // Windows dependencies
+    #[cfg(windows)]
+    {
+        println!("cargo:rustc-link-lib=crypto_asm_lib");
+        println!("cargo:rustc-link-search={objs_path}/msvc-posix-compat/msvc-compat-layer");
+        println!("cargo:rustc-link-lib=msvc-posix-compat");
+        println!("cargo:rustc-link-search=C:/Windows/System32");
+        println!("cargo:rustc-link-lib=vcruntime140");
+    }
+}
diff --git a/rust/hostapd-rs/build_cargo.rs b/rust/hostapd-rs/build_cargo.rs
index bd7a336b..467e9ed7 100644
--- a/rust/hostapd-rs/build_cargo.rs
+++ b/rust/hostapd-rs/build_cargo.rs
@@ -12,6 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! Build script for generating `hostapd` bindings.
+
 use bindgen;
 use std::env;
 use std::path::PathBuf;
diff --git a/rust/hostapd-rs/src/hostapd.rs b/rust/hostapd-rs/src/hostapd.rs
index 67729ce8..e84d9d3e 100644
--- a/rust/hostapd-rs/src/hostapd.rs
+++ b/rust/hostapd-rs/src/hostapd.rs
@@ -12,25 +12,66 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-///
-/// This crate is a wrapper for hostapd C library.
-///
-/// Hostapd process is managed by a separate thread.
-///
-/// hostapd.conf file is generated under discovery directory.
-///
+//! Controller interface for the `hostapd` C library.
+//!
+//! This module allows interaction with `hostapd` to manage WiFi access point and perform various wireless networking tasks directly from Rust code.
+//!
+//! The main `hostapd` process is managed by a separate thread while responses from the `hostapd` process are handled
+//! by another thread, ensuring efficient and non-blocking communication.
+//!
+//! `hostapd` configuration consists of key-value pairs. The default configuration file is generated in the discovery directory.
+//!
+//! ## Features
+//!
+//! * **Asynchronous operation:** The module utilizes `tokio` for asynchronous communication with the `hostapd` process,
+//!   allowing for efficient and non-blocking operations.
+//! * **Platform support:** Supports Linux, macOS, and Windows.
+//! * **Configuration management:** Provides functionality to generate and manage `hostapd` configuration files.
+//! * **Easy integration:** Offers a high-level API to simplify interaction with `hostapd`, abstracting away
+//!   low-level details.
+//!
+//! ## Usage
+//!
+//! Here's a basic example of how to create a `Hostapd` instance and start the `hostapd` process:
+//!
+//! ```
+//! use hostapd_rs::hostapd::Hostapd;
+//! use std::path::PathBuf;
+//! use std::sync::mpsc;
+//!
+//! fn main() {
+//!     // Create a channel for receiving data from hostapd
+//!     let (tx, _) = mpsc::channel();
+//!
+//!     // Create a new Hostapd instance
+//!     let mut hostapd = Hostapd::new(
+//!         tx,                                 // Sender for receiving data
+//!         true,                               // Verbose mode (optional)
+//!         PathBuf::from("/tmp/hostapd.conf"), // Path to the configuration file
+//!     );
+//!
+//!     // Start the hostapd process
+//!     hostapd.run();
+//! }
+//! ```
+//!
+//! This starts `hostapd` in a separate thread, allowing interaction with it using the `Hostapd` struct's methods.
+
+use anyhow::bail;
 use bytes::Bytes;
-use log::warn;
+use log::{info, warn};
+use netsim_packets::ieee80211::{Ieee80211, MacAddress};
 use std::collections::HashMap;
-use std::ffi::{c_char, c_int, CString};
+use std::ffi::{c_char, c_int, CStr, CString};
 use std::fs::File;
 use std::io::{BufWriter, Write};
+use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
 #[cfg(unix)]
 use std::os::fd::IntoRawFd;
 #[cfg(windows)]
 use std::os::windows::io::IntoRawSocket;
 use std::path::PathBuf;
-use std::sync::{mpsc, Arc, OnceLock, RwLock};
+use std::sync::{mpsc, Arc, RwLock};
 use std::thread::{self, sleep};
 use std::time::Duration;
 use tokio::io::{AsyncReadExt, AsyncWriteExt};
@@ -41,14 +82,19 @@ use tokio::net::{
 use tokio::runtime::Runtime;
 use tokio::sync::Mutex;
 
-use crate::hostapd_sys::{run_hostapd_main, set_virtio_ctrl_sock, set_virtio_sock};
+use crate::hostapd_sys::{
+    run_hostapd_main, set_virtio_ctrl_sock, set_virtio_sock, VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG,
+    VIRTIO_WIFI_CTRL_CMD_TERMINATE,
+};
 
 /// Alias for RawFd on Unix or RawSocket on Windows (converted to i32)
 type RawDescriptor = i32;
 
-// TODO: Use a (global netsimd) tokio runtime from caller
-static HOSTAPD_RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();
-
+/// Hostapd process interface.
+///
+/// This struct provides methods for interacting with the `hostapd` process,
+/// such as starting and stopping the process, configuring the access point,
+/// and sending and receiving data.
 pub struct Hostapd {
     // TODO: update to tokio based RwLock when usages are async
     handle: RwLock<Option<thread::JoinHandle<()>>>,
@@ -56,14 +102,25 @@ pub struct Hostapd {
     config: HashMap<String, String>,
     config_path: PathBuf,
     data_writer: Option<Mutex<OwnedWriteHalf>>,
-    _ctrl_writer: Option<Mutex<OwnedWriteHalf>>,
+    ctrl_writer: Option<Mutex<OwnedWriteHalf>>,
     tx_bytes: mpsc::Sender<Bytes>,
+    runtime: Arc<Runtime>,
+    // MAC address of the access point.
+    bssid: MacAddress,
 }
 
 impl Hostapd {
+    /// Creates a new `Hostapd` instance.
+    ///
+    /// # Arguments
+    ///
+    /// * `tx_bytes`: Sender for transmitting data received from `hostapd`.
+    /// * `verbose`: Whether to run `hostapd` in verbose mode.
+    /// * `config_path`: Path to the `hostapd` configuration file.
+
     pub fn new(tx_bytes: mpsc::Sender<Bytes>, verbose: bool, config_path: PathBuf) -> Self {
         // Default Hostapd conf entries
-        let config_data = vec![
+        let config_data = [
             ("ssid", "AndroidWifi"),
             ("interface", "wlan1"),
             ("driver", "virtio_wifi"),
@@ -84,22 +141,29 @@ impl Hostapd {
             ("eapol_key_index_workaround", "0"),
         ];
         let mut config: HashMap<String, String> = HashMap::new();
-        config.extend(config_data.into_iter().map(|(k, v)| (k.to_string(), v.to_string())));
+        config.extend(config_data.iter().map(|(k, v)| (k.to_string(), v.to_string())));
 
+        // TODO(b/381154253): Allow configuring BSSID in hostapd.conf.
+        // Currently, the BSSID is hardcoded in external/wpa_supplicant_8/src/drivers/driver_virtio_wifi.c. This should be configured by hostapd.conf and allow to be set by `Hostapd`.
+        let bssid_bytes: [u8; 6] = [0x00, 0x13, 0x10, 0x85, 0xfe, 0x01];
+        let bssid = MacAddress::from(&bssid_bytes);
         Hostapd {
             handle: RwLock::new(None),
             verbose,
             config,
             config_path,
             data_writer: None,
-            _ctrl_writer: None,
+            ctrl_writer: None,
             tx_bytes,
+            runtime: Arc::new(Runtime::new().unwrap()),
+            bssid,
         }
     }
 
-    /// Start hostapd main process and pass responses to netsim
-    /// The "hostapd" thread manages the C hostapd process by running "run_hostapd_main"
-    /// The "hostapd_response" thread manages traffic between hostapd and netsim
+    /// Starts the `hostapd` main process and response thread.
+    ///
+    /// The "hostapd" thread manages the C `hostapd` process by running `run_hostapd_main`.
+    /// The "hostapd_response" thread manages traffic between `hostapd` and netsim.
     ///
     /// TODO:
     /// * update as async fn.
@@ -113,10 +177,10 @@ impl Hostapd {
 
         // Setup Sockets
         let (ctrl_listener, _ctrl_reader, ctrl_writer) =
-            Self::create_pipe().expect("Failed to create ctrl pipe");
-        self._ctrl_writer = Some(Mutex::new(ctrl_writer));
+            self.create_pipe().expect("Failed to create ctrl pipe");
+        self.ctrl_writer = Some(Mutex::new(ctrl_writer));
         let (data_listener, data_reader, data_writer) =
-            Self::create_pipe().expect("Failed to create data pipe");
+            self.create_pipe().expect("Failed to create data pipe");
         self.data_writer = Some(Mutex::new(data_writer));
 
         // Start hostapd thread
@@ -131,48 +195,129 @@ impl Hostapd {
 
         // Start hostapd response thread
         let tx_bytes = self.tx_bytes.clone();
+        let runtime = Arc::clone(&self.runtime);
         let _ = thread::Builder::new()
             .name("hostapd_response".to_string())
             .spawn(move || {
-                Self::hostapd_response_thread(data_listener, ctrl_listener, data_reader, tx_bytes);
+                Self::hostapd_response_thread(
+                    data_listener,
+                    ctrl_listener,
+                    data_reader,
+                    tx_bytes,
+                    runtime,
+                );
             })
             .expect("Failed to spawn hostapd_response thread");
 
         true
     }
 
-    pub fn set_ssid(&mut self, _ssid: String, _password: String) -> bool {
-        todo!();
+    /// Reconfigures `Hostapd` with the specified SSID (and password).
+    ///
+    /// TODO:
+    /// * implement password & encryption support
+    /// * update as async fn.
+    pub fn set_ssid(
+        &mut self,
+        ssid: impl Into<String>,
+        password: impl Into<String>,
+    ) -> anyhow::Result<()> {
+        let ssid = ssid.into();
+        let password = password.into();
+        if ssid.is_empty() {
+            bail!("set_ssid must have a non-empty SSID");
+        }
+
+        if !password.is_empty() {
+            bail!("set_ssid with password is not yet supported.");
+        }
+
+        if ssid == self.get_ssid() && password == self.get_config_val("password") {
+            info!("SSID and password matches current configuration.");
+            return Ok(());
+        }
+
+        // Update the config
+        self.config.insert("ssid".to_string(), ssid);
+        if !password.is_empty() {
+            let password_config = [
+                ("wpa", "2"),
+                ("wpa_key_mgmt", "WPA-PSK"),
+                ("rsn_pairwise", "CCMP"),
+                ("wpa_passphrase", &password),
+            ];
+            self.config.extend(password_config.iter().map(|(k, v)| (k.to_string(), v.to_string())));
+        }
+
+        // Update the config file.
+        self.gen_config_file()?;
+
+        // Send command for Hostapd to reload config file
+        if let Err(e) = self.runtime.block_on(Self::async_write(
+            self.ctrl_writer.as_ref().unwrap(),
+            c_string_to_bytes(VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG),
+        )) {
+            bail!("Failed to send VIRTIO_WIFI_CTRL_CMD_RELOAD_CONFIG to hostapd to reload config: {:?}", e);
+        }
+
+        Ok(())
+    }
+
+    /// Retrieves the current SSID in the `Hostapd` configuration.
+    pub fn get_ssid(&self) -> String {
+        self.get_config_val("ssid")
+    }
+
+    /// Retrieves the `Hostapd`'s BSSID.
+    pub fn get_bssid(&self) -> MacAddress {
+        self.bssid
     }
 
-    pub fn get_ssid(&self) -> Option<String> {
-        self.config.get("ssid").cloned()
+    /// Attempt to encrypt the given IEEE 802.11 frame.
+    pub fn try_encrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        // TODO
+        None
     }
 
-    /// Input data packet bytes from netsim to hostapd
+    /// Attempt to decrypt the given IEEE 802.11 frame.
+    pub fn try_decrypt(&self, _ieee80211: &Ieee80211) -> Option<Ieee80211> {
+        // TODO
+        None
+    }
+
+    /// Inputs data packet bytes from netsim to `hostapd`.
     ///
     /// TODO:
     /// * update as async fn.
     pub fn input(&self, bytes: Bytes) -> anyhow::Result<()> {
         // Make sure hostapd is already running
         assert!(self.is_running(), "Failed to send input. Hostapd is not running.");
-        Ok(get_runtime().block_on(async {
-            let mut writer_guard = self.data_writer.as_ref().unwrap().lock().await;
-            writer_guard.write_all(&bytes).await
-        })?)
+        self.runtime.block_on(Self::async_write(self.data_writer.as_ref().unwrap(), &bytes))
     }
 
-    /// Check whether the hostapd thread is running
+    /// Checks whether the `hostapd` thread is running.
     pub fn is_running(&self) -> bool {
         let handle_lock = self.handle.read().unwrap();
         handle_lock.is_some() && !handle_lock.as_ref().unwrap().is_finished()
     }
 
+    /// Terminates the `Hostapd` process thread by sending a control command.
     pub fn terminate(&self) {
-        todo!();
+        if !self.is_running() {
+            warn!("hostapd terminate() called when hostapd thread is not running");
+            return;
+        }
+
+        // Send terminate command to hostapd
+        if let Err(e) = self.runtime.block_on(Self::async_write(
+            self.ctrl_writer.as_ref().unwrap(),
+            c_string_to_bytes(VIRTIO_WIFI_CTRL_CMD_TERMINATE),
+        )) {
+            warn!("Failed to send VIRTIO_WIFI_CTRL_CMD_TERMINATE to hostapd to terminate: {:?}", e);
+        }
     }
 
-    /// Generate hostapd.conf in discovery directory
+    /// Generates the `hostapd.conf` file in the discovery directory.
     fn gen_config_file(&self) -> anyhow::Result<()> {
         let conf_file = File::create(self.config_path.clone())?; // Create or overwrite the file
         let mut writer = BufWriter::new(conf_file);
@@ -184,51 +329,75 @@ impl Hostapd {
         Ok(writer.flush()?) // Ensure all data is written to the file
     }
 
-    /// Creates a pipe of two connected TcpStream objects
+    /// Gets the value of the given key in the config.
     ///
-    /// Extracts the first stream's raw descriptor and splits the second stream as OwnedReadHalf and OwnedWriteHalf
+    /// Returns an empty String if the key is not found.
+    fn get_config_val(&self, key: &str) -> String {
+        self.config.get(key).cloned().unwrap_or_default()
+    }
+
+    /// Creates a pipe of two connected `TcpStream` objects.
+    ///
+    /// Extracts the first stream's raw descriptor and splits the second stream
+    /// into `OwnedReadHalf` and `OwnedWriteHalf`.
     ///
     /// # Returns
     ///
-    /// * `Ok((listener, read_half, write_half))` if the pipe creation is successful
-    /// * `Err(std::io::Error)` if an error occurs during the pipe creation.
+    /// * `Ok((listener, read_half, write_half))` if the pipe creation is successful.
+    /// * `Err(std::io::Error)` if an error occurs during pipe creation.
     fn create_pipe(
+        &self,
     ) -> anyhow::Result<(RawDescriptor, OwnedReadHalf, OwnedWriteHalf), std::io::Error> {
-        let (listener, stream) = get_runtime().block_on(Self::async_create_pipe())?;
+        let (listener, stream) = self.runtime.block_on(Self::async_create_pipe())?;
         let listener = into_raw_descriptor(listener);
         let (read_half, write_half) = stream.into_split();
         Ok((listener, read_half, write_half))
     }
 
+    /// Creates a pipe asynchronously.
     async fn async_create_pipe() -> anyhow::Result<(TcpStream, TcpStream), std::io::Error> {
-        let listener = TcpListener::bind("127.0.0.1:0").await?;
+        let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
+            Ok(listener) => listener,
+            Err(e) => {
+                // Support hosts that only have IPv6
+                info!("Failed to bind to 127.0.0.1:0. Try to bind to [::1]:0 next. Err: {:?}", e);
+                TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await?
+            }
+        };
         let addr = listener.local_addr()?;
         let stream = TcpStream::connect(addr).await?;
         let (listener, _) = listener.accept().await?;
         Ok((listener, stream))
     }
 
-    /// Run the C hostapd process with run_hostapd_main
+    /// Writes data to a writer asynchronously.
+    async fn async_write(writer: &Mutex<OwnedWriteHalf>, data: &[u8]) -> anyhow::Result<()> {
+        let mut writer_guard = writer.lock().await;
+        writer_guard.write_all(data).await?;
+        writer_guard.flush().await?;
+        Ok(())
+    }
+
+    /// Runs the C `hostapd` process with `run_hostapd_main`.
     ///
-    /// This function is meant to be spawn in a separate thread.
+    /// This function is meant to be spawned in a separate thread.
     fn hostapd_thread(verbose: bool, config_path: String) {
         let mut args = vec![CString::new("hostapd").unwrap()];
         if verbose {
-            args.push(CString::new("-dddd").unwrap())
+            args.push(CString::new("-dddd").unwrap());
         }
         args.push(
             CString::new(config_path.clone()).unwrap_or_else(|_| {
                 panic!("CString::new error on config file path: {}", config_path)
             }),
         );
-        let mut argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
-        argv.push(std::ptr::null());
-        let argc = argv.len() as c_int - 1;
+        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
+        let argc = argv.len() as c_int;
         // Safety: we ensure that argc is length of argv and argv.as_ptr() is a valid pointer of hostapd args
         unsafe { run_hostapd_main(argc, argv.as_ptr()) };
     }
 
-    /// Sets the virtio (driver) data and control sockets
+    /// Sets the virtio (driver) data and control sockets.
     fn set_virtio_driver_socket(
         data_descriptor: RawDescriptor,
         ctrl_descriptor: RawDescriptor,
@@ -239,15 +408,16 @@ impl Hostapd {
         }
     }
 
-    /// Manage reading hostapd responses and sending via tx_bytes
+    /// Manages reading `hostapd` responses and sending them via `tx_bytes`.
     ///
-    /// The thread first attempt to set virtio driver sockets with retries unitl success.
-    /// Next the thread reads hostapd responses and writes to netsim
+    /// The thread first attempts to set virtio driver sockets with retries until success.
+    /// Next, the thread reads `hostapd` responses and writes them to netsim.
     fn hostapd_response_thread(
         data_listener: RawDescriptor,
         ctrl_listener: RawDescriptor,
         mut data_reader: OwnedReadHalf,
         tx_bytes: mpsc::Sender<Bytes>,
+        runtime: Arc<Runtime>,
     ) {
         let mut buf: [u8; 1500] = [0u8; 1500];
         loop {
@@ -256,9 +426,10 @@ impl Hostapd {
                 sleep(Duration::from_millis(250));
                 continue;
             };
-
-            let size = match get_runtime().block_on(async { data_reader.read(&mut buf[..]).await })
-            {
+            break;
+        }
+        loop {
+            let size = match runtime.block_on(async { data_reader.read(&mut buf[..]).await }) {
                 Ok(size) => size,
                 Err(e) => {
                     warn!("Failed to read hostapd response: {:?}", e);
@@ -266,7 +437,7 @@ impl Hostapd {
                 }
             };
 
-            if let Err(e) = tx_bytes.send(Bytes::from(buf[..size].to_vec())) {
+            if let Err(e) = tx_bytes.send(Bytes::copy_from_slice(&buf[..size])) {
                 warn!("Failed to send hostapd packet response: {:?}", e);
                 break;
             };
@@ -274,9 +445,19 @@ impl Hostapd {
     }
 }
 
-/// Convert TcpStream to RawDescriptor (i32)
+impl Drop for Hostapd {
+    /// Terminates the `hostapd` process when the `Hostapd` instance is dropped.
+    fn drop(&mut self) {
+        self.terminate();
+    }
+}
+
+/// Converts a `TcpStream` to a `RawDescriptor` (i32).
 fn into_raw_descriptor(stream: TcpStream) -> RawDescriptor {
     let std_stream = stream.into_std().expect("into_raw_descriptor's into_std() failed");
+    // hostapd fd expects blocking, but rust set non-blocking for async
+    std_stream.set_nonblocking(false).expect("non-blocking");
+
     // Use into_raw_fd for Unix to pass raw file descriptor to C
     #[cfg(unix)]
     return std_stream.into_raw_fd();
@@ -286,9 +467,7 @@ fn into_raw_descriptor(stream: TcpStream) -> RawDescriptor {
     std_stream.into_raw_socket().try_into().expect("Failed to convert Raw Socket value into i32")
 }
 
-/// Get or init the hostapd tokio runtime
-/// TODO:
-/// * make Runtime the responsibility of the caller.
-fn get_runtime() -> &'static Arc<Runtime> {
-    HOSTAPD_RUNTIME.get_or_init(|| Arc::new(Runtime::new().unwrap()))
+/// Converts a null-terminated c-string slice into `&[u8]` bytes without the null terminator.
+fn c_string_to_bytes(c_string: &[u8]) -> &[u8] {
+    CStr::from_bytes_with_nul(c_string).unwrap().to_bytes()
 }
diff --git a/rust/hostapd-rs/src/hostapd_sys/mod.rs b/rust/hostapd-rs/src/hostapd_sys/mod.rs
index fe87b464..100256d9 100644
--- a/rust/hostapd-rs/src/hostapd_sys/mod.rs
+++ b/rust/hostapd-rs/src/hostapd_sys/mod.rs
@@ -19,6 +19,64 @@
 // Remove this once bindgen figures out how to do this correctly
 #![allow(deref_nullptr)]
 
+//! FFI bindings to hostapd for Linux, macOS, and Windows.
+//!
+//! This module allows interaction with hostapd's core functionalities directly from Rust code.
+//!
+//! ## Usage
+//!
+//! This module provides a function to start the hostapd process and includes platform-specific bindings.
+//!
+//! ### `run_hostapd_main`
+//!
+//! This function allows you to run the main hostapd process.
+//!
+//! ```
+//! use std::ffi::CString;
+//! use hostapd_rs::hostapd_sys; // Import the module
+//!
+//! fn main() {
+//!     let mut args = vec![CString::new("hostapd").unwrap()];
+//!     args.push(CString::new("/path/to/hostapd.conf").unwrap());
+//!     // Include any other args
+//!     let argv: Vec<*const std::os::raw::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
+//!
+//!     unsafe {
+//!         hostapd_sys::run_hostapd_main(argv.len() as i32, argv.as_ptr());
+//!     }
+//! }
+//! ```
+//!
+//! ### Platform-Specific Bindings
+//!
+//! This module provides bindings automatically generated by `rust-bindgen` for the following platforms:
+//!
+//! * **Linux (`linux/bindings.rs`)**
+//! * **macOS (`macos/bindings.rs`)**
+//! * **Windows (`windows/bindings.rs`)**
+//!
+//! These bindings expose constants, structures, and functions specific to each platform, allowing
+//! you to interact with the underlying hostapd implementation.
+//!
+//! **Example (Linux):**
+//!
+//! This example demonstrates how to access the active Pairwise Transient Key (PTK) from hostapd on Linux.
+//!
+//! ```
+//! # #[cfg(target_os = "linux")]
+//! # fn main() {
+//! use hostapd_rs::hostapd_sys; // Import the module
+//! use hostapd_sys::get_active_ptk;
+//!
+//! unsafe {
+//!     let ptk = get_active_ptk();
+//!     // Process the PTK data
+//! }
+//! # }
+//! # #[cfg(not(target_os = "linux"))]
+//! # fn main() {}
+//! ```
+
 #[cfg(target_os = "linux")]
 include!("linux/bindings.rs");
 
diff --git a/rust/hostapd-rs/src/lib.rs b/rust/hostapd-rs/src/lib.rs
index 2035727e..845b6cad 100644
--- a/rust/hostapd-rs/src/lib.rs
+++ b/rust/hostapd-rs/src/lib.rs
@@ -12,5 +12,19 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! # hostapd-rs
+//!
+//! This crate provides a Rust interface to the `hostapd` C library, allowing you to manage WiFi access points
+//! and perform various wireless networking tasks directly from your Rust code.
+//!
+//! It consists of two main modules:
+//!
+//! * **`hostapd`:** This module provides a high-level and safe interface to interact with the `hostapd` process.
+//!   It uses separate threads for managing the `hostapd` process and handling its responses, ensuring efficient
+//!   and non-blocking communication.
+//! * **`hostapd_sys`:** This module contains the low-level C FFI bindings to the `hostapd` library. It is
+//!   automatically generated using `rust-bindgen` and provides platform-specific bindings for Linux, macOS, and Windows.
+//!
+
 pub mod hostapd;
 pub mod hostapd_sys;
diff --git a/rust/hostapd-rs/tests/integration_test.rs b/rust/hostapd-rs/tests/integration_test.rs
new file mode 100644
index 00000000..e8c332fc
--- /dev/null
+++ b/rust/hostapd-rs/tests/integration_test.rs
@@ -0,0 +1,149 @@
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
+//! Integration tests for the `hostapd-rs` crate.
+
+use bytes::Bytes;
+use hostapd_rs::hostapd::Hostapd;
+use log::warn;
+use netsim_packets::ieee80211::Ieee80211;
+use pdl_runtime::Packet;
+use std::{
+    env,
+    sync::mpsc,
+    thread,
+    time::{Duration, Instant},
+};
+
+/// Initializes a `Hostapd` instance for testing.
+///
+/// Returns a tuple containing the `Hostapd` instance and a receiver for
+/// receiving data from `hostapd`.
+fn init_test_hostapd() -> (Hostapd, mpsc::Receiver<Bytes>) {
+    let (tx, rx) = mpsc::channel();
+    let config_path = env::temp_dir().join("hostapd.conf");
+    (Hostapd::new(tx, true, config_path), rx)
+}
+
+/// Waits for the `Hostapd` process to terminate.
+fn terminate_hostapd(hostapd: &Hostapd) {
+    hostapd.terminate();
+    let max_wait_time = Duration::from_secs(30);
+    let start_time = Instant::now();
+    while start_time.elapsed() < max_wait_time {
+        if !hostapd.is_running() {
+            break;
+        }
+        thread::sleep(Duration::from_millis(250));
+    }
+    warn!("Hostapd failed to terminate successfully within 30s");
+}
+
+/// Hostapd integration test.
+///
+/// A single test is used to avoid conflicts when multiple `hostapd` instances
+/// run in parallel.
+///
+/// TODO: Split up tests once feasible with `serial_test` crate or other methods.
+#[test]
+fn test_hostapd() {
+    // Initialize a single Hostapd instance to share across tests to avoid >5s startup &
+    // shutdown overhead for every test
+    let (mut hostapd, receiver) = init_test_hostapd();
+    test_start(&mut hostapd);
+    test_receive_beacon_frame(&receiver);
+    test_get_and_set_ssid(&mut hostapd, &receiver);
+    test_terminate(&hostapd);
+}
+
+/// Tests that `Hostapd` starts successfully.
+fn test_start(hostapd: &mut Hostapd) {
+    hostapd.run();
+    assert!(hostapd.is_running());
+}
+
+/// Tests that `Hostapd` terminates successfully.
+fn test_terminate(hostapd: &Hostapd) {
+    terminate_hostapd(&hostapd);
+    assert!(!hostapd.is_running());
+}
+
+/// Tests whether a beacon frame packet is received after `Hostapd` starts up.
+fn test_receive_beacon_frame(receiver: &mpsc::Receiver<Bytes>) {
+    let end_time = Instant::now() + Duration::from_secs(10);
+    loop {
+        // Try to receive a packet before end_time
+        match receiver.recv_timeout(end_time - Instant::now()) {
+            // Parse and verify received packet is beacon frame
+            Ok(packet) if Ieee80211::decode_full(&packet).unwrap().is_beacon() => break,
+            Ok(_) => continue, // Received a non beacon packet. Continue
+            _ => assert!(false, "Did not receive beacon frame in 10s"), // Error occurred
+        }
+    }
+}
+
+/// Checks if the receiver receives a beacon frame with the specified SSID within 10 seconds.
+fn verify_beacon_frame_ssid(receiver: &mpsc::Receiver<Bytes>, ssid: &str) {
+    let end_time = Instant::now() + Duration::from_secs(10);
+    loop {
+        // Try to receive a packet before end_time
+        match receiver.recv_timeout(end_time - Instant::now()) {
+            Ok(packet) => {
+                if let Ok(beacon_ssid) =
+                    Ieee80211::decode_full(&packet).unwrap().get_ssid_from_beacon_frame()
+                {
+                    if beacon_ssid == ssid {
+                        break; // Found expected beacon frame
+                    }
+                }
+                // Not expected beacon frame. Continue...
+            }
+            Err(mpsc::RecvTimeoutError::Timeout) => {
+                assert!(false, "No Beacon frame received within 10s");
+            }
+            Err(mpsc::RecvTimeoutError::Disconnected) => {
+                assert!(false, "Receiver disconnected while waiting for Beacon frame.");
+            }
+        }
+    }
+}
+
+/// Tests various ways to configure `Hostapd` SSID and password.
+fn test_get_and_set_ssid(hostapd: &mut Hostapd, receiver: &mpsc::Receiver<Bytes>) {
+    // Check default ssid is set
+    let default_ssid = "AndroidWifi";
+    assert_eq!(hostapd.get_ssid(), default_ssid);
+
+    let mut test_ssid = String::new();
+    let mut test_password = String::new();
+    // Verify set_ssid fails if SSID is empty
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_err());
+
+    // Verify set_ssid succeeds if SSID is not empty
+    test_ssid = "TestSsid".to_string();
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_ok());
+    // Verify hostapd sends new beacon frame with updated SSID
+    verify_beacon_frame_ssid(receiver, &test_ssid);
+
+    // Verify ssid was set successfully
+    assert_eq!(hostapd.get_ssid(), test_ssid);
+
+    // Verify setting same ssid again succeeds
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_ok());
+
+    // Verify set_ssid fails if password is not empty
+    // TODO: Update once password support is implemented
+    test_password = "TestPassword".to_string();
+    assert!(hostapd.set_ssid(&test_ssid, &test_password).is_err());
+}
diff --git a/rust/http-proxy/Cargo.toml b/rust/http-proxy/Cargo.toml
index 66bbef1f..a8bef7b3 100644
--- a/rust/http-proxy/Cargo.toml
+++ b/rust/http-proxy/Cargo.toml
@@ -23,5 +23,13 @@ path = "src/lib.rs"
 doctest = false
 
 [dependencies]
+base64 = "0.22.0"
 regex = "1.6.0"
 httparse = "1.8.0"
+libslirp-rs = { path = "../libslirp-rs" }
+log = "0.4.17"
+tokio = { version = "1.32.0", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "sync"] }
+etherparse = {version = "0.16" }
+
+[dev-dependencies]
+capture = { path = "../capture" }
diff --git a/rust/http-proxy/src/connector.rs b/rust/http-proxy/src/connector.rs
new file mode 100644
index 00000000..f24a6cb7
--- /dev/null
+++ b/rust/http-proxy/src/connector.rs
@@ -0,0 +1,168 @@
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
+use crate::error::Error;
+use base64::{engine::general_purpose, Engine as _};
+use std::net::SocketAddr;
+use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
+use tokio::net::TcpStream;
+
+const HTTP_VERSION: &str = "1.1";
+
+pub type Result<T> = core::result::Result<T, Error>;
+
+/// Establishes a TCP connection to a target address through an HTTP proxy.
+///
+/// The `Connector` handles the CONNECT request handshake with the proxy, including
+/// optional Basic authentication.
+#[derive(Clone)]
+pub struct Connector {
+    proxy_addr: SocketAddr,
+    username: Option<String>,
+    password: Option<String>,
+}
+
+impl Connector {
+    pub fn new(proxy_addr: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
+        Connector { proxy_addr, username, password }
+    }
+
+    pub async fn connect(&self, addr: SocketAddr) -> Result<TcpStream> {
+        let mut stream = TcpStream::connect(self.proxy_addr).await?;
+
+        // Construct the CONNECT request
+        let mut request = format!("CONNECT {} HTTP/{}\r\n", addr.to_string(), HTTP_VERSION);
+
+        // Authentication
+        if let (Some(username), Some(password)) = (&self.username, &self.password) {
+            let encoded_auth = base64_encode(format!("{}:{}", username, password).as_bytes());
+            let auth_header = format!(
+                "Proxy-Authorization: Basic {}\r\n",
+                String::from_utf8_lossy(&encoded_auth)
+            );
+            // Add the header to the request
+            request.push_str(&auth_header);
+        }
+
+        // Add the final CRLF
+        request.push_str("\r\n");
+        stream.write_all(request.as_bytes()).await?;
+
+        // Read the proxy's response
+        let mut reader = BufReader::new(stream);
+        let mut response = String::new();
+        reader.read_line(&mut response).await?;
+        if response.starts_with(&format!("HTTP/{} 200", HTTP_VERSION)) {
+            Ok(reader.into_inner())
+        } else {
+            Err(Error::ConnectionError(addr, response.trim_end_matches("\r\n").to_string()))
+        }
+    }
+}
+
+fn base64_encode(src: &[u8]) -> Vec<u8> {
+    general_purpose::STANDARD.encode(src).into_bytes()
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use tokio::io::AsyncReadExt;
+    use tokio::net::{lookup_host, TcpListener};
+
+    #[tokio::test]
+    async fn test_connect() -> Result<()> {
+        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
+        let proxy_addr = listener.local_addr().unwrap();
+
+        let addr: SocketAddr = lookup_host("localhost:8000").await.unwrap().next().unwrap();
+
+        let handle = tokio::spawn(async move {
+            let (stream, _) = listener.accept().await.unwrap();
+            // Server expects a client greeting with no auth methods
+            let expected_greeting = format!("CONNECT {} HTTP/1.1\r\n", &addr);
+
+            let mut reader = BufReader::new(stream);
+            let mut line = String::new();
+
+            reader.read_line(&mut line).await.unwrap();
+
+            assert_eq!(line, expected_greeting);
+
+            // Server sends a response with no auth method selected
+            let response = "HTTP/1.1 200 Connection established\r\n\r\n";
+            let mut stream = reader.into_inner();
+            stream.write_all(response.as_bytes()).await.unwrap();
+        });
+
+        let client = Connector::new(proxy_addr, None, None);
+
+        client.connect(addr).await.unwrap();
+
+        handle.await.unwrap(); // Wait for the task to complete
+
+        Ok(())
+    }
+
+    #[tokio::test]
+    async fn test_connect_with_auth() -> Result<()> {
+        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
+        let proxy_addr = listener.local_addr().unwrap();
+
+        let addr: SocketAddr = lookup_host("localhost:8000").await.unwrap().next().unwrap();
+
+        let handle = tokio::spawn(async move {
+            let (mut stream, _) = listener.accept().await.unwrap();
+
+            // Server expects a client greeting with auth header
+            let expected_greeting = format!(
+                "CONNECT {} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n",
+                &addr
+            );
+
+            let mut buf = [0; 1024];
+            let n = stream.read(&mut buf).await.unwrap();
+            let actual_greeting = String::from_utf8_lossy(&buf[..n]);
+
+            assert_eq!(actual_greeting, expected_greeting);
+
+            // Server sends a response
+            let response = "HTTP/1.1 200 Connection established\r\n\r\n";
+
+            stream.write_all(response.as_bytes()).await.unwrap();
+        });
+
+        let client = Connector::new(proxy_addr, Some("user".into()), Some("password".into()));
+
+        client.connect(addr).await.unwrap();
+
+        handle.await.unwrap(); // Wait for the task to complete
+
+        Ok(())
+    }
+
+    #[test]
+    fn test_proxy_base64_encode_success() {
+        let input = b"hello world";
+        let encoded = base64_encode(input);
+        assert_eq!(encoded, b"aGVsbG8gd29ybGQ=");
+    }
+
+    #[test]
+    fn test_proxy_base64_encode_empty_input() {
+        let input = b"";
+        let encoded = base64_encode(input);
+        assert_eq!(encoded, b"");
+    }
+}
diff --git a/rust/http-proxy/src/dns.rs b/rust/http-proxy/src/dns.rs
new file mode 100644
index 00000000..e464afdd
--- /dev/null
+++ b/rust/http-proxy/src/dns.rs
@@ -0,0 +1,623 @@
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
+/// This module parses DNS response records and extracts fully
+/// qualified domain names (FQDNs) along with their corresponding
+/// IP Addresses (IpAddr).
+///
+/// **Note:** This is not a general-purpose DNS response parser. It is
+/// designed to handle specific record types and response formats.
+use std::convert::TryFrom;
+use std::fmt;
+use std::io::{Cursor, Read, Seek, SeekFrom};
+use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
+use std::str;
+#[allow(unused_imports)]
+use std::str::FromStr;
+
+// REGION CURSOR
+
+/// Extension trait providing convenient methods for reading primitive
+/// data types used by DNS messages from a `Cursor<&[u8]>`.
+
+trait CursorExt: Read + Seek + Clone {
+    fn read_u8(&mut self) -> std::io::Result<u8>;
+    fn read_u16(&mut self) -> std::io::Result<u16>;
+    fn read_u32(&mut self) -> std::io::Result<u32>;
+    fn read_ipv4addr(&mut self) -> std::io::Result<Ipv4Addr>;
+    fn read_ipv6addr(&mut self) -> std::io::Result<Ipv6Addr>;
+    fn get_ref(&self) -> &[u8];
+    fn position(&self) -> u64;
+    fn set_position(&mut self, pos: u64);
+}
+
+impl CursorExt for Cursor<&[u8]> {
+    fn read_u8(&mut self) -> std::io::Result<u8> {
+        let mut buf = [0; 1];
+        self.read_exact(&mut buf)?;
+        Ok(buf[0])
+    }
+
+    fn read_u16(&mut self) -> std::io::Result<u16> {
+        let mut buf = [0; 2];
+        self.read_exact(&mut buf)?;
+        Ok(u16::from_be_bytes(buf))
+    }
+
+    fn read_u32(&mut self) -> std::io::Result<u32> {
+        let mut buf = [0; 4];
+        self.read_exact(&mut buf)?;
+        Ok(u32::from_be_bytes(buf))
+    }
+
+    fn read_ipv4addr(&mut self) -> std::io::Result<Ipv4Addr> {
+        let mut buf = [0; 4];
+        self.read_exact(&mut buf)?;
+        Ok(Ipv4Addr::from(buf))
+    }
+
+    fn read_ipv6addr(&mut self) -> std::io::Result<Ipv6Addr> {
+        let mut buf = [0; 16];
+        self.read_exact(&mut buf)?;
+        Ok(Ipv6Addr::from(buf))
+    }
+
+    fn get_ref(&self) -> &[u8] {
+        self.get_ref() // Call the original get_ref method
+    }
+    fn position(&self) -> u64 {
+        self.position()
+    }
+    fn set_position(&mut self, pos: u64) {
+        self.set_position(pos)
+    }
+}
+
+// END REGION CURSOR
+
+// REGION MESSAGE
+
+/// '''
+///  +---------------------+
+///  |        Header       |
+///  +---------------------+
+///  |       Question      | the question for the name server
+///  +---------------------+
+///  |        Answer       | RRs answering the question
+///  +---------------------+
+///  |      Authority      | RRs pointing toward an authority
+///  +---------------------+
+///  |      Additional     | RRs holding additional information
+///  +---------------------+
+/// '''
+
+#[derive(Debug)]
+struct Message {
+    #[allow(dead_code)]
+    header: Header,
+    #[allow(dead_code)]
+    questions: Vec<Question>,
+    answers: Vec<ResourceRecord>,
+    // Other types not needed
+    // Authority
+    // Additional
+}
+
+impl Message {
+    fn parse(cursor: &mut impl CursorExt) -> Result<Message> {
+        let header = Header::parse(cursor)?;
+
+        // Reject DNS messages that are not responses
+        if !header.response {
+            return Err(DnsError::ResponseExpected);
+        }
+        if header.opcode != Opcode::StandardQuery {
+            return Err(DnsError::StandardQueryExpected);
+        }
+        if header.response_code != ResponseCode::NoError {
+            return Err(DnsError::ResponseCodeExpected);
+        }
+
+        if header.answer_count == 0 {
+            return Err(DnsError::AnswerExpected);
+        }
+
+        let mut questions = Vec::with_capacity(header.question_count);
+        for _i in 0..header.question_count {
+            let question = Question::split_once(cursor)?;
+            questions.push(question);
+        }
+        let mut answers = Vec::with_capacity(header.answer_count);
+        for _i in 0..header.answer_count {
+            let answer = ResourceRecord::split_once(cursor)?;
+            answers.push(answer);
+        }
+        Ok(Message { header, questions, answers })
+    }
+}
+
+pub fn parse_answers(bytes: &[u8]) -> Result<Vec<(IpAddr, String)>> {
+    let mut cursor = Cursor::new(bytes);
+    let msg = Message::parse(&mut cursor)?;
+    let mut responses = Vec::with_capacity(msg.answers.len());
+    for answer in msg.answers {
+        responses.push((answer.resource_data.into(), answer.name));
+    }
+    Ok(responses)
+}
+
+// END REGION MESSAGE
+
+// REGION HEADER
+
+/// Represents parsed header of the packet.
+/// The header contains the following fields:
+/// '''
+///                                  1  1  1  1  1  1
+///    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                      ID                       |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                    QDCOUNT                    |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                    ANCOUNT                    |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                    NSCOUNT                    |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                    ARCOUNT                    |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// '''
+#[derive(Debug, PartialEq, Eq, Clone, Copy)]
+struct Header {
+    /// A 16 bit identifier assigned by the program that
+    /// generates any kind of query.  This identifier is copied
+    /// the corresponding reply and can be used by the requester
+    /// to match up replies to outstanding queries.
+    id: u16,
+    /// A one bit field that specifies whether this message is a
+    /// query (0), or a response (1).
+    response: bool,
+    /// A four bit field that specifies kind of query in this
+    /// message.  This value is set by the originator of a query
+    /// and copied into the response.
+    opcode: Opcode,
+    response_code: ResponseCode,
+    question_count: usize,
+    answer_count: usize,
+    nameserver_count: usize,
+    additional_count: usize,
+}
+
+#[derive(Debug, PartialEq, Eq, Clone, Copy)]
+enum Opcode {
+    /// Normal query
+    StandardQuery = 0,
+    /// Inverse query (query a name by IP)
+    InverseQuery = 1,
+    /// Server status request
+    ServerStatusRequest = 2,
+}
+
+/// The RCODE value according to RFC 1035
+#[derive(Debug, PartialEq, Eq, Clone, Copy)]
+enum ResponseCode {
+    NoError,
+    FormatError,
+    ServerFailure,
+    NameError,
+    NotImplemented,
+    Refused,
+}
+
+impl TryFrom<u16> for ResponseCode {
+    type Error = DnsError;
+
+    fn try_from(value: u16) -> Result<Self> {
+        match value {
+            0 => Ok(ResponseCode::NoError),
+            1 => Ok(ResponseCode::FormatError),
+            2 => Ok(ResponseCode::ServerFailure),
+            3 => Ok(ResponseCode::NameError),
+            4 => Ok(ResponseCode::NotImplemented),
+            5 => Ok(ResponseCode::Refused),
+            _ => Err(DnsError::InvalidResponseCode(value)),
+        }
+    }
+}
+
+impl TryFrom<u16> for Opcode {
+    type Error = DnsError;
+
+    fn try_from(value: u16) -> Result<Self> {
+        match value {
+            0 => Ok(Opcode::StandardQuery),
+            1 => Ok(Opcode::InverseQuery),
+            2 => Ok(Opcode::ServerStatusRequest),
+            _ => Err(DnsError::InvalidOpcode(value)),
+        }
+    }
+}
+
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+struct Flag(u16);
+
+impl Flag {
+    const RESPONSE: u16 = 0x8000;
+    const OPCODE_MASK: u16 = 0x7800;
+    const RESERVED_MASK: u16 = 0x0004;
+    const RESPONSE_CODE_MASK: u16 = 0x000F;
+
+    fn new(value: u16) -> Self {
+        Self(value)
+    }
+
+    fn is_set(&self, mask: u16) -> bool {
+        (self.0 & mask) == mask
+    }
+
+    fn get(&self, mask: u16) -> u16 {
+        (self.0 & mask) >> mask.trailing_zeros()
+    }
+}
+
+impl Header {
+    /// Parse the header into a header structure
+    fn parse(cursor: &mut impl CursorExt) -> Result<Header> {
+        let id = cursor.read_u16()?;
+        let f = cursor.read_u16()?;
+        let question_count = cursor.read_u16()? as usize;
+        let answer_count = cursor.read_u16()? as usize;
+        let nameserver_count = cursor.read_u16()? as usize;
+        let additional_count = cursor.read_u16()? as usize;
+        let flags = Flag::new(f);
+        if flags.get(Flag::RESERVED_MASK) != 0 {
+            return Err(DnsError::ReservedBitsAreNonZero);
+        }
+        let header = Header {
+            id,
+            response: flags.is_set(Flag::RESPONSE),
+            opcode: Opcode::try_from(flags.get(Flag::OPCODE_MASK))?,
+            response_code: ResponseCode::try_from(flags.get(Flag::RESPONSE_CODE_MASK))?,
+            question_count,
+            answer_count,
+            nameserver_count,
+            additional_count,
+        };
+        Ok(header)
+    }
+}
+
+// END REGION HEADER
+
+// REGION QUESTION
+
+/// 4.1.2. Question section format
+///
+/// The question section is used to carry the "question" in most queries,
+/// i.e., the parameters that define what is being asked.  The section
+/// contains QDCOUNT (usually 1) entries, each of the following format:
+/// '''
+///                               1  1  1  1  1  1
+/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                                               |
+/// /                     QNAME                     /
+/// /                                               /
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                     QTYPE                     |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// |                     QCLASS                    |
+/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// '''
+
+#[derive(Debug)]
+struct Question {
+    #[allow(dead_code)]
+    name: String,
+    #[allow(dead_code)]
+    qtype: u16,
+    #[allow(dead_code)]
+    qclass: u16,
+}
+
+impl Question {
+    fn split_once(cursor: &mut impl CursorExt) -> Result<Question> {
+        let name = Name::to_string(cursor)?;
+        let qtype = cursor.read_u16()?;
+        let qclass = cursor.read_u16()?;
+        Ok(Question { name, qtype, qclass })
+    }
+}
+
+// END REGION QUESTION
+
+// REGION RESOURCE RECORD
+
+/// All RRs have the same top level format shown below:
+///
+/// '''
+///                                1  1  1  1  1  1
+///  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                                               |
+///  /                                               /
+///  /                      NAME                     /
+///  |                                               |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                      TYPE                     |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                     CLASS                     |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                      TTL                      |
+///  |                                               |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  |                   RDLENGTH                    |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
+///  /                     RDATA                     /
+///  /                                               /
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// '''
+
+// DNS resource record classes.
+//
+// The only one we care about is Internet
+#[derive(Debug)]
+enum ResourceClass {
+    Internet = 1,
+}
+
+// Type fields in resource records.
+//
+// The only ones we care about are A and AAAA
+#[derive(Debug)]
+enum ResourceType {
+    // IPv4 address.
+    A = 1,
+    // IPv6 address, see RFC 3596.
+    Aaaa = 28,
+}
+
+#[derive(Debug)]
+struct ResourceRecord {
+    name: String,
+    #[allow(dead_code)]
+    resource_type: ResourceType,
+    #[allow(dead_code)]
+    resource_class: ResourceClass,
+    #[allow(dead_code)]
+    ttl: u32,
+    resource_data: ResourceData,
+}
+
+impl ResourceRecord {
+    fn split_once(cursor: &mut impl CursorExt) -> Result<ResourceRecord> {
+        let name = Name::to_string(cursor)?;
+        let rtype = cursor.read_u16()?;
+        let resource_type = match rtype {
+            x if x == ResourceType::A as u16 => ResourceType::A,
+            x if x == ResourceType::Aaaa as u16 => ResourceType::Aaaa,
+            _ => return Err(DnsError::InvalidResourceType),
+        };
+        let rclass = cursor.read_u16()?;
+        let resource_class = match rclass {
+            x if x == ResourceClass::Internet as u16 => ResourceClass::Internet,
+            _ => return Err(DnsError::InvalidResourceClass),
+        };
+        let ttl = cursor.read_u32()?;
+        let _ = cursor.read_u16()?;
+        let resource_data = ResourceData::split_once(cursor, &resource_type)?;
+        Ok(ResourceRecord { name, resource_type, resource_class, ttl, resource_data })
+    }
+}
+
+// Only interested in IpAddr resource data
+#[derive(Debug, PartialEq)]
+struct ResourceData(IpAddr);
+
+impl From<ResourceData> for IpAddr {
+    fn from(resource_data: ResourceData) -> Self {
+        resource_data.0
+    }
+}
+
+impl ResourceData {
+    fn split_once(
+        cursor: &mut impl CursorExt,
+        resource_type: &ResourceType,
+    ) -> Result<ResourceData> {
+        match resource_type {
+            ResourceType::A => Ok(ResourceData(cursor.read_ipv4addr()?.into())),
+            ResourceType::Aaaa => Ok(ResourceData(cursor.read_ipv6addr()?.into())),
+        }
+    }
+}
+
+// END REGION RESOURCE RECORD
+
+// REGION LABEL
+
+type Result<T> = core::result::Result<T, DnsError>;
+
+#[derive(Debug)]
+pub enum DnsError {
+    ResponseExpected,
+    StandardQueryExpected,
+    ResponseCodeExpected,
+    AnswerExpected,
+    PointerLoop,
+    InvalidLength,
+    Utf8Error(str::Utf8Error),
+    InvalidResourceType,
+    InvalidResourceClass,
+    AddrParseError(std::net::AddrParseError),
+    InvalidOpcode(u16),
+    InvalidResponseCode(u16),
+    ReservedBitsAreNonZero,
+    IoError(std::io::Error),
+}
+
+impl std::error::Error for DnsError {}
+
+impl fmt::Display for DnsError {
+    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
+        write!(fmt, "{self:?}")
+    }
+}
+
+impl From<std::io::Error> for DnsError {
+    fn from(err: std::io::Error) -> Self {
+        DnsError::IoError(err)
+    }
+}
+impl From<str::Utf8Error> for DnsError {
+    fn from(err: str::Utf8Error) -> Self {
+        DnsError::Utf8Error(err)
+    }
+}
+
+impl From<std::net::AddrParseError> for DnsError {
+    fn from(err: std::net::AddrParseError) -> Self {
+        DnsError::AddrParseError(err)
+    }
+}
+
+// REGION NAME
+
+/// RFC 1035 4.1.4. Message compression
+///
+/// In order to reduce the size of messages, the domain system
+/// utilizes a compression scheme which eliminates the repetition of
+/// domain names in a message.  In this scheme, an entire domain name
+/// or a list of labels at the end of a domain name is replaced with a
+/// pointer to a prior occurrence of the same name.
+///
+/// The pointer takes the form of a two octet sequence:
+///
+/// '''
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+///  | 1  1|                OFFSET                   |
+///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+/// '''
+
+enum NamePart {
+    Label(String),
+    Pointer(u64),
+    Root,
+}
+
+const PTR_MASK: u8 = 0b11000000;
+
+impl NamePart {
+    /// Domain name labels have a maximum length of 63 octets.
+    const MAX: u8 = 63;
+
+    #[allow(dead_code)]
+    fn split_once(cursor: &mut impl CursorExt) -> Result<NamePart> {
+        let size = cursor.read_u8()?;
+        if size & PTR_MASK == PTR_MASK {
+            let two = cursor.read_u8()?;
+            let offset: u64 = u16::from_be_bytes([size & !PTR_MASK, two]).into();
+            return Ok(NamePart::Pointer(offset));
+        }
+        if size == 0 {
+            return Ok(NamePart::Root);
+        }
+        if size > Self::MAX {
+            return Err(DnsError::InvalidLength);
+        }
+        let end = size as usize;
+        let buffer_ref: &[u8] = cursor.get_ref();
+        let start = cursor.position() as usize;
+        let label = str::from_utf8(&buffer_ref[start..start + end])?.to_string();
+        cursor.seek(SeekFrom::Current(end as i64))?;
+        Ok(NamePart::Label(label))
+    }
+}
+
+/// The Fully Qualitifed Domain Name from ANSWER and RR records
+
+struct Name();
+
+impl Name {
+    // Convert a variable length QNAME or NAME to a String.
+    //
+    // The cursor is updated to the end of the first sequence of
+    // labels, and not the position after a Pointer. This allows the
+    // cursor to be used for reading the remainder of the Question or
+    // ResourceRecord.
+    //
+    // Limit the number of Pointers in malificient messages to avoid
+    // looping.
+    //
+    fn to_string(cursor: &mut impl CursorExt) -> Result<String> {
+        Self::to_string_guard(cursor, 0)
+    }
+
+    fn to_string_guard(cursor: &mut impl CursorExt, jumps: usize) -> Result<String> {
+        if jumps > 2 {
+            return Err(DnsError::PointerLoop);
+        }
+        let mut name = String::with_capacity(255);
+        loop {
+            match NamePart::split_once(cursor)? {
+                NamePart::Root => return Ok(name),
+                NamePart::Pointer(offset) => {
+                    let mut pointer_cursor = cursor.clone();
+                    pointer_cursor.set_position(offset);
+                    let pointer_name = Name::to_string_guard(&mut pointer_cursor, jumps + 1)?;
+                    name.push_str(&pointer_name);
+                    return Ok(name);
+                }
+                NamePart::Label(label) => {
+                    if !name.is_empty() {
+                        name.push('.');
+                    }
+                    name.push_str(&label);
+                }
+            };
+        }
+    }
+}
+
+// END REGION NAME
+
+#[cfg(test)]
+mod test_message {
+    use super::*;
+
+    #[test]
+    fn test_dns_responses() -> Result<()> {
+        let bytes: [u8; 81] = [
+            0xc2, 0x87, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x3, 0x69, 0x62, 0x6d,
+            0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1c, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0,
+            0x0, 0x0, 0x8, 0x0, 0x10, 0x26, 0x0, 0x14, 0x6, 0x5e, 0x0, 0x2, 0x93, 0x0, 0x0, 0x0,
+            0x0, 0x0, 0x0, 0x38, 0x31, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x0, 0x8, 0x0,
+            0x10, 0x26, 0x0, 0x14, 0x6, 0x5e, 0x0, 0x2, 0xaa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38,
+            0x31,
+        ];
+        let bytes: &[u8] = &bytes;
+        let answers = parse_answers(bytes)?;
+        assert_eq!(
+            *answers.get(0).unwrap(),
+            (Ipv6Addr::from_str("2600:1406:5e00:293::3831")?.into(), "ibm.com".to_string())
+        );
+        assert_eq!(
+            *answers.get(1).unwrap(),
+            (Ipv6Addr::from_str("2600:1406:5e00:2aa::3831")?.into(), "ibm.com".to_string())
+        );
+        Ok(())
+    }
+}
diff --git a/rust/http-proxy/src/dns_manager.rs b/rust/http-proxy/src/dns_manager.rs
new file mode 100644
index 00000000..773808e3
--- /dev/null
+++ b/rust/http-proxy/src/dns_manager.rs
@@ -0,0 +1,75 @@
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
+/// This module provides a reverse-dns function that caches the domain
+/// name (FQDNs) and IpAddr from DNS answer records.
+///
+/// This manager exists for two reasons:
+///
+/// 1. RFC2817 Compliance (b/37055721): Requires converting IP address to
+/// hostname for HTTP CONNECT requests.
+///
+/// 2. Proxy bypass/exclusion list requires matching on host name
+/// patterns.
+///
+use crate::dns;
+use etherparse::{PacketHeaders, PayloadSlice, TransportHeader};
+use std::collections::HashMap;
+use std::net::IpAddr;
+
+pub struct DnsManager {
+    map: HashMap<IpAddr, String>,
+}
+
+impl DnsManager {
+    const DNS_PORT: u16 = 53;
+
+    pub fn new() -> Self {
+        DnsManager { map: HashMap::new() }
+    }
+
+    /// Add potential DNS entries to the cache.
+    pub fn add_from_packet_headers(&mut self, headers: &PacketHeaders) {
+        // Check if the packet contains a UDP header
+        // with source port from DNS server
+        // and DNS answers with A/AAAA records
+        if let Some(TransportHeader::Udp(udp_header)) = &headers.transport {
+            // with source port from DNS server
+            if udp_header.source_port == Self::DNS_PORT {
+                if let PayloadSlice::Udp(ref payload) = headers.payload {
+                    // Add any A/AAAA domain names
+                    if let Ok(answers) = dns::parse_answers(payload) {
+                        for (ip_addr, name) in answers {
+                            self.map.insert(ip_addr, name);
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    pub fn add_from_ethernet_slice(&mut self, packet: &[u8]) {
+        let headers = PacketHeaders::from_ethernet_slice(packet).unwrap();
+        self.add_from_packet_headers(&headers);
+    }
+
+    /// Return a FQDN from a prior DNS response for ip address
+    pub fn get(&self, ip_addr: &IpAddr) -> Option<String> {
+        self.map.get(ip_addr).cloned()
+    }
+
+    pub fn len(&self) -> usize {
+        self.map.len()
+    }
+}
diff --git a/rust/http-proxy/src/error.rs b/rust/http-proxy/src/error.rs
new file mode 100644
index 00000000..a16a6663
--- /dev/null
+++ b/rust/http-proxy/src/error.rs
@@ -0,0 +1,56 @@
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
+//! This module defines the Proxy error types.
+
+use std::fmt;
+use std::io;
+use std::net::SocketAddr;
+
+/// An enumeration of possible errors.
+#[derive(Debug)]
+pub enum Error {
+    IoError(io::Error),
+    ConnectionError(SocketAddr, String),
+    MalformedConfigString,
+    InvalidPortNumber,
+    InvalidHost,
+}
+
+impl fmt::Display for Error {
+    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        write!(f, "ProxyError: {self:?}")
+    }
+}
+
+impl std::error::Error for Error {}
+
+impl From<io::Error> for Error {
+    fn from(err: io::Error) -> Self {
+        Error::IoError(err)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_io_error_chaining() {
+        let inner_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
+        let outer_error = Error::IoError(inner_error);
+
+        assert!(outer_error.to_string().contains("file not found"));
+    }
+}
diff --git a/rust/http-proxy/src/lib.rs b/rust/http-proxy/src/lib.rs
index e2fd9792..4e316937 100644
--- a/rust/http-proxy/src/lib.rs
+++ b/rust/http-proxy/src/lib.rs
@@ -12,8 +12,53 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! # HTTP Proxy
+//!
+//! This crate provides a TCP proxy client that can be used to
+//! establish connections to a target address through an HTTP proxy
+//! server.
+//!
+//! The main component of this crate is the `Connector` struct, which
+//! handles the CONNECT request handshake with the proxy, including
+//! optional Basic authentication.
+//!
+//! The crate also includes a `Manager` struct that implements the
+//! `ProxyManager` trait from `libslirp_rs`, allowing it to be used
+//! with the `libslirp` library for managing TCP connections through
+//! the proxy.
+//!
+//! ## Example
+//!
+//! ```
+//! use std::net::SocketAddr;
+//!
+//! #[tokio::main]
+//! async fn main() {
+//!     let proxy_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
+//!
+//!     let connector = http_proxy::Connector::new(proxy_addr, None, None);
+//! }
+//! ```
+//!
+//! ## Features
+//!
+//! * **libslirp:** Enables integration with the `libslirp` library.
+//!
+//! ## Limitations
+//!
+//! * Currently only supports HTTP proxies.
+//! * Usernames and passwords cannot contain `@` or `:`.
+
+mod connector;
+mod dns;
+mod dns_manager;
+mod error;
+mod manager;
+mod pattern_vec;
 mod rewriter;
 mod util;
 
-pub use rewriter::*;
-pub use util::*;
+pub use connector::*;
+pub use dns_manager::*;
+pub use error::Error;
+pub use manager::*;
diff --git a/rust/http-proxy/src/manager.rs b/rust/http-proxy/src/manager.rs
new file mode 100644
index 00000000..f554b4a8
--- /dev/null
+++ b/rust/http-proxy/src/manager.rs
@@ -0,0 +1,121 @@
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
+use crate::util::{into_raw_descriptor, ProxyConfig};
+use crate::{connector::Connector, error::Error};
+use libslirp_rs::libslirp::{ProxyConnect, ProxyManager};
+use log::{debug, warn};
+use std::net::SocketAddr;
+use std::sync::Arc;
+use tokio::runtime::Runtime;
+
+/// # Manager
+///
+/// The `Manager` struct implements the `ProxyManager` trait from
+/// `libslirp_rs`.  It is responsible for managing TCP connections
+/// through an HTTP proxy using the `Connector` struct.
+///
+/// The `Manager` uses a `tokio::runtime::Runtime` to spawn tasks for
+/// establishing proxy connections.  It takes a proxy configuration
+/// string as input, which is parsed into a `ProxyConfig` to create a
+/// `Connector` instance.
+///
+/// The `try_connect` method attempts to establish a connection to the
+/// given `SocketAddr` through the proxy.  If successful, it calls the
+/// `proxy_connect` function with the raw file descriptor of the
+/// connected socket.
+///
+/// # Example
+///
+/// ```
+/// use std::net::SocketAddr;
+/// use libslirp_rs::libslirp::ProxyConnect;
+///
+/// struct MyProxyConnect;
+///
+/// impl ProxyConnect for MyProxyConnect {
+///     fn proxy_connect(&self, fd: i32, sockaddr: SocketAddr) {
+///         // Handle the connected socket
+///     }
+/// }
+///
+/// #[tokio::main]
+/// async fn main() {
+/// }
+/// ```
+pub struct Manager {
+    runtime: Arc<Runtime>,
+    connector: Connector,
+}
+
+impl Manager {
+    pub fn new(proxy: &str) -> Result<Self, Error> {
+        let config = ProxyConfig::from_string(&proxy)?;
+        Ok(Self {
+            runtime: Arc::new(Runtime::new()?),
+            connector: Connector::new(config.addr, config.username, config.password),
+        })
+    }
+}
+
+impl ProxyManager for Manager {
+    /// Attempts to establish a TCP connection to the given `sockaddr` through the proxy.
+    ///
+    /// This function spawns a new task in the `tokio` runtime to handle the connection process.
+    /// If the connection is successful, it calls the `proxy_connect` function of the provided
+    /// `ProxyConnect` object with the raw file descriptor of the connected socket.
+    ///
+    /// # Arguments
+    ///
+    /// * `sockaddr` - The target socket address to connect to.
+    /// * `connect_id` - An identifier for the connection.
+    /// * `connect_func` - A `ProxyConnect` object that will be called with the connected socket.
+    ///
+    /// # Returns
+    ///
+    /// `true` if the connection attempt was initiated, `false` otherwise.
+    fn try_connect(
+        &self,
+        sockaddr: SocketAddr,
+        connect_id: usize,
+        connect_func: Box<dyn ProxyConnect + Send>,
+    ) -> bool {
+        debug!("Connecting to {sockaddr:?} with connect ID {connect_id}");
+        let connector = self.connector.clone();
+
+        self.runtime.handle().spawn(async move {
+            let fd = match connector.connect(sockaddr).await {
+                Ok(tcp_stream) => into_raw_descriptor(tcp_stream),
+                Err(e) => {
+                    warn!("Failed to connect to proxy {}. {}", sockaddr, e);
+                    -1
+                }
+            };
+            connect_func.proxy_connect(fd, sockaddr);
+        });
+
+        true
+    }
+
+    /// Removes a connection with the given `connect_id`.
+    ///
+    /// Currently, this function only logs a debug message.
+    ///
+    /// # Arguments
+    ///
+    /// * `connect_id` - The identifier of the connection to remove.
+    fn remove(&self, connect_id: usize) {
+        debug!("Remove connect ID {}", connect_id);
+    }
+}
diff --git a/rust/http-proxy/src/pattern_vec.rs b/rust/http-proxy/src/pattern_vec.rs
new file mode 100644
index 00000000..30f7ccc6
--- /dev/null
+++ b/rust/http-proxy/src/pattern_vec.rs
@@ -0,0 +1,119 @@
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
+/// A vector of tuples representing wildcard patterns.
+/// Each tuple contains a prefix string and a suffix string.
+pub struct PatternVec {
+    patterns: Vec<(String, String)>,
+}
+
+impl PatternVec {
+    /// Creates a new PatternVec from a string containing semicolon (;) or comma (,)
+    /// separated wildcard patterns.
+    pub fn new(pattern_list: impl Into<String>) -> PatternVec {
+        let pattern_list = pattern_list.into();
+        let patterns = if pattern_list.trim().is_empty() {
+            Vec::new()
+        } else {
+            pattern_list
+                .split([';', ','])
+                // Splits a string at the first occurrence of '*', returning a tuple
+                // containing the prefix (before *) and suffix (after *).
+                // If no '*' is found, returns the entire string as prefix.
+                .map(|s| match s.find('*') {
+                    Some(i) => (String::from(&s[..i]), String::from(&s[i + 1..])),
+                    None => (String::from(s), String::new()),
+                })
+                .collect()
+        };
+        PatternVec { patterns }
+    }
+
+    /// Checks if a given string matches any of the patterns in the PatternVec.
+    /// A match occurs if the string starts with a pattern's prefix and ends with its suffix.
+    pub fn matches(&self, s: &str) -> bool {
+        self.patterns.iter().any(|(prefix, suffix)| s.starts_with(prefix) && s.ends_with(suffix))
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    macro_rules! tuple_str {
+        ($a:expr, $b:expr) => {
+            (String::from($a), String::from($b))
+        };
+    }
+
+    #[test]
+    fn test_new_empty_string() {
+        let pattern_vec = PatternVec::new("");
+        assert_eq!(pattern_vec.patterns.len(), 0);
+    }
+
+    #[test]
+    fn test_new_single_pattern() {
+        let pattern_vec = PatternVec::new("*.example.com");
+        assert_eq!(pattern_vec.patterns.len(), 1);
+        assert_eq!(pattern_vec.patterns[0], tuple_str!("", ".example.com"));
+    }
+
+    #[test]
+    fn test_new_multiple_patterns() {
+        let pattern_vec = PatternVec::new("*.example.com;*.org");
+        assert_eq!(pattern_vec.patterns.len(), 2);
+        assert_eq!(pattern_vec.patterns[0], tuple_str!("", ".example.com"));
+        assert_eq!(pattern_vec.patterns[1], tuple_str!("", ".org"));
+    }
+
+    #[test]
+    fn test_matches_exact_match() {
+        let pattern_vec = PatternVec::new("example.com");
+        assert!(pattern_vec.matches("example.com"));
+    }
+
+    #[test]
+    fn test_matches_prefix_match() {
+        let pattern_vec = PatternVec::new("*.google.com");
+        assert!(pattern_vec.matches("foo.google.com"));
+    }
+
+    #[test]
+    fn test_matches_suffix_match() {
+        let pattern_vec = PatternVec::new("*.com");
+        assert!(pattern_vec.matches("example.com"));
+    }
+
+    #[test]
+    fn test_matches_no_match() {
+        let pattern_vec = PatternVec::new("*.google.com");
+        assert!(!pattern_vec.matches("example.org"));
+    }
+
+    #[test]
+    fn test_matches_multiple_patterns() {
+        let pattern_vec = PatternVec::new("*.example.com;*.org");
+        assert!(pattern_vec.matches("some.example.com"));
+        assert!(pattern_vec.matches("another.org"));
+    }
+
+    #[test]
+    fn test_matches_middle_wildcard() {
+        let pattern_vec = PatternVec::new("some*.com");
+        assert!(pattern_vec.matches("somemiddle.com"));
+        assert!(pattern_vec.matches("some.middle.com"));
+        assert!(pattern_vec.matches("some.middle.example.com"));
+    }
+}
diff --git a/rust/http-proxy/src/rewriter.rs b/rust/http-proxy/src/rewriter.rs
index 56bcd843..447c46b9 100644
--- a/rust/http-proxy/src/rewriter.rs
+++ b/rust/http-proxy/src/rewriter.rs
@@ -12,11 +12,10 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use httparse;
+/// # Http Proxy Rewriter
 
 #[cfg(test)]
 mod tests {
-    use super::*;
     use httparse::Header;
 
     #[test]
diff --git a/rust/http-proxy/src/util.rs b/rust/http-proxy/src/util.rs
index c303eef2..fb81d7b4 100644
--- a/rust/http-proxy/src/util.rs
+++ b/rust/http-proxy/src/util.rs
@@ -12,52 +12,54 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// # Http Proxy Utils
+//
+// This module provides functionality for parsing proxy configuration
+// strings and converting `TcpStream` objects to raw file
+// descriptors.
+//
+// The `ProxyConfig` struct holds the parsed proxy configuration,
+// including protocol, address, username, and password. The
+// `from_string` function parses a proxy configuration string in the
+// format `[protocol://][username:password@]host:port` or
+// `[protocol://][username:password@]/[host/]:port` and returns a
+// `ProxyConfig` struct.
+//
+// The `into_raw_descriptor` function converts a `TcpStream` object
+// to a raw file descriptor (`RawDescriptor`), which is an `i32`
+// representing the underlying socket. This is used for compatibility
+// with libraries that require raw file descriptors, such as
+// `libslirp_rs`.
+
+use crate::Error;
 use regex::Regex;
-use std::fmt;
-use std::net::{IpAddr, ToSocketAddrs};
+use std::net::{SocketAddr, ToSocketAddrs};
+#[cfg(unix)]
+use std::os::fd::IntoRawFd;
+#[cfg(windows)]
+use std::os::windows::io::IntoRawSocket;
+use tokio::net::TcpStream;
+
+pub type RawDescriptor = i32;
 
 /// Proxy configuration
 pub struct ProxyConfig {
     pub protocol: String,
-    pub host: IpAddr,
-    pub port: u16,
+    pub addr: SocketAddr,
     pub username: Option<String>,
     pub password: Option<String>,
 }
 
-#[derive(Debug, PartialEq)]
-pub enum ProxyConfigError {
-    InvalidConfigString,
-    InvalidPortNumber,
-    InvalidHost,
-}
-
-impl fmt::Display for ProxyConfigError {
-    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
-        match self {
-            ProxyConfigError::InvalidConfigString => {
-                write!(f, "Invalid proxy configuration string")
-            }
-            ProxyConfigError::InvalidPortNumber => write!(f, "Invalid port number"),
-            ProxyConfigError::InvalidHost => write!(f, "Invalid host"),
-        }
-    }
-}
-
-impl std::error::Error for ProxyConfigError {}
-
 impl ProxyConfig {
     /// Parses a proxy configuration string and returns a `ProxyConfig` struct.
     ///
     /// The function expects the proxy configuration string to be in the following format:
     ///
-    /// ```
     /// [protocol://][username:password@]host:port
     /// [protocol://][username:password@]/[host/]:port
-    /// ```
     ///
     /// where:
-
+    ///
     /// * `protocol`: The network protocol (e.g., `http`, `https`,
     /// `socks5`). If not provided, defaults to `http`.
     /// * `username`: and `password` are optional credentials for authentication.
@@ -67,14 +69,14 @@ impl ProxyConfig {
     /// * `port`: The port number on which the proxy server is listening.
     ///
     /// # Errors
-    /// Returns a `ProxyConfigError` if the input string is not in a
+    /// Returns a `Error` if the input string is not in a
     /// valid format or if the hostname/port resolution fails.
     ///
     /// # Limitations
     /// * Usernames and passwords cannot contain `@` or `:`.
-    pub fn from_string(config_string: &str) -> Result<ProxyConfig, ProxyConfigError> {
+    pub fn from_string(config_string: &str) -> Result<ProxyConfig, Error> {
         let re = Regex::new(r"^(?:(?P<protocol>\w+)://)?(?:(?P<user>\w+):(?P<pass>\w+)@)?(?P<host>(?:[\w\.-]+|\[[^\]]+\])):(?P<port>\d+)$").unwrap();
-        let caps = re.captures(config_string).ok_or(ProxyConfigError::InvalidConfigString)?;
+        let caps = re.captures(config_string).ok_or(Error::MalformedConfigString)?;
 
         let protocol =
             caps.name("protocol").map_or_else(|| "http".to_string(), |m| m.as_str().to_string());
@@ -84,29 +86,44 @@ impl ProxyConfig {
         // Extract host, removing surrounding brackets if present
         let hostname = caps
             .name("host")
-            .ok_or(ProxyConfigError::InvalidConfigString)?
+            .ok_or(Error::MalformedConfigString)?
             .as_str()
             .trim_matches(|c| c == '[' || c == ']')
             .to_string();
 
         let port = caps
             .name("port")
-            .ok_or(ProxyConfigError::InvalidConfigString)?
+            .ok_or(Error::MalformedConfigString)?
             .as_str()
             .parse::<u16>()
-            .map_err(|_| ProxyConfigError::InvalidPortNumber)?;
+            .map_err(|_| Error::InvalidPortNumber)?;
 
         let host = (hostname, port)
             .to_socket_addrs()
-            .map_err(|_| ProxyConfigError::InvalidHost)?
+            .map_err(|_| Error::InvalidHost)?
             .next() // Take the first resolved address
-            .ok_or(ProxyConfigError::InvalidHost)?
+            .ok_or(Error::InvalidHost)?
             .ip();
 
-        Ok(ProxyConfig { protocol, username, password, host, port })
+        Ok(ProxyConfig { protocol, username, password, addr: SocketAddr::from((host, port)) })
     }
 }
 
+/// Convert TcpStream to RawDescriptor (i32)
+pub fn into_raw_descriptor(stream: TcpStream) -> RawDescriptor {
+    let std_stream = stream.into_std().expect("into_raw_descriptor's into_std() failed");
+
+    std_stream.set_nonblocking(false).expect("non-blocking");
+
+    // Use into_raw_fd for Unix to pass raw file descriptor to C
+    #[cfg(unix)]
+    return std_stream.into_raw_fd();
+
+    // Use into_raw_socket for Windows to pass raw socket to C
+    #[cfg(windows)]
+    std_stream.into_raw_socket().try_into().expect("Failed to convert Raw Socket value into i32")
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
@@ -120,8 +137,7 @@ mod tests {
                 "127.0.0.1:8080",
                 ProxyConfig {
                     protocol: "http".to_owned(),
-                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
-                    port: 8080,
+                    addr: SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)),
                     username: None,
                     password: None,
                 },
@@ -130,8 +146,7 @@ mod tests {
                 "http://127.0.0.1:8080",
                 ProxyConfig {
                     protocol: "http".to_owned(),
-                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
-                    port: 8080,
+                    addr: SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)),
                     username: None,
                     password: None,
                 },
@@ -140,8 +155,7 @@ mod tests {
                 "https://127.0.0.1:8080",
                 ProxyConfig {
                     protocol: "https".to_owned(),
-                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
-                    port: 8080,
+                    addr: SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)),
                     username: None,
                     password: None,
                 },
@@ -150,8 +164,7 @@ mod tests {
                 "sock5://127.0.0.1:8080",
                 ProxyConfig {
                     protocol: "sock5".to_owned(),
-                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
-                    port: 8080,
+                    addr: SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)),
                     username: None,
                     password: None,
                 },
@@ -160,8 +173,7 @@ mod tests {
                 "user:pass@192.168.0.18:3128",
                 ProxyConfig {
                     protocol: "http".to_owned(),
-                    host: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 18)),
-                    port: 3128,
+                    addr: SocketAddr::from((IpAddr::V4(Ipv4Addr::new(192, 168, 0, 18)), 3128)),
                     username: Some("user".to_string()),
                     password: Some("pass".to_string()),
                 },
@@ -170,8 +182,10 @@ mod tests {
                 "https://[::1]:7000",
                 ProxyConfig {
                     protocol: "https".to_owned(),
-                    host: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
-                    port: 7000,
+                    addr: SocketAddr::from((
+                        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
+                        7000,
+                    )),
                     username: None,
                     password: None,
                 },
@@ -180,8 +194,10 @@ mod tests {
                 "[::1]:7000",
                 ProxyConfig {
                     protocol: "http".to_owned(),
-                    host: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
-                    port: 7000,
+                    addr: SocketAddr::from((
+                        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
+                        7000,
+                    )),
                     username: None,
                     password: None,
                 },
@@ -198,8 +214,7 @@ mod tests {
                 input
             );
             let result = result.ok().unwrap();
-            assert_eq!(result.host, expected.host, "For input: {}", input);
-            assert_eq!(result.port, expected.port, "For input: {}", input);
+            assert_eq!(result.addr, expected.addr, "For input: {}", input);
             assert_eq!(result.username, expected.username, "For input: {}", input);
             assert_eq!(result.password, expected.password, "For input: {}", input);
         }
@@ -208,25 +223,29 @@ mod tests {
     #[test]
     fn parse_configuration_string_with_errors() {
         let data = [
-            ("http://", ProxyConfigError::InvalidConfigString),
-            ("", ProxyConfigError::InvalidConfigString),
-            ("256.0.0.1:8080", ProxyConfigError::InvalidHost),
-            ("127.0.0.1:foo", ProxyConfigError::InvalidConfigString),
-            ("127.0.0.1:-2", ProxyConfigError::InvalidConfigString),
-            ("127.0.0.1:100000", ProxyConfigError::InvalidPortNumber),
-            ("127.0.0.1", ProxyConfigError::InvalidConfigString),
-            ("http:127.0.0.1:8080", ProxyConfigError::InvalidConfigString),
-            ("::1:8080", ProxyConfigError::InvalidConfigString),
-            ("user@pass:127.0.0.1:8080", ProxyConfigError::InvalidConfigString),
-            ("user@127.0.0.1:8080", ProxyConfigError::InvalidConfigString),
-            ("proxy.example.com:7000", ProxyConfigError::InvalidHost),
-            ("[::1}:7000", ProxyConfigError::InvalidConfigString),
+            ("http://", Error::MalformedConfigString),
+            ("", Error::MalformedConfigString),
+            ("256.0.0.1:8080", Error::InvalidHost),
+            ("127.0.0.1:foo", Error::MalformedConfigString),
+            ("127.0.0.1:-2", Error::MalformedConfigString),
+            ("127.0.0.1:100000", Error::InvalidPortNumber),
+            ("127.0.0.1", Error::MalformedConfigString),
+            ("http:127.0.0.1:8080", Error::MalformedConfigString),
+            ("::1:8080", Error::MalformedConfigString),
+            ("user@pass:127.0.0.1:8080", Error::MalformedConfigString),
+            ("user@127.0.0.1:8080", Error::MalformedConfigString),
+            ("proxy.example.com:7000", Error::InvalidHost),
+            ("[::1}:7000", Error::MalformedConfigString),
         ];
 
         for (input, expected_error) in data {
             let result = ProxyConfig::from_string(input);
-            assert!(result.is_err(), "Expected an error for input: {}", input);
-            assert_eq!(result.err().unwrap(), expected_error, "For input: {}", input);
+            assert_eq!(
+                result.err().unwrap().to_string(),
+                expected_error.to_string(),
+                "Expected an error for input: {}",
+                input
+            );
         }
     }
 }
diff --git a/rust/http-proxy/tests/integration_test.rs b/rust/http-proxy/tests/integration_test.rs
new file mode 100644
index 00000000..ffbe2a8e
--- /dev/null
+++ b/rust/http-proxy/tests/integration_test.rs
@@ -0,0 +1,59 @@
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
+use std::net::{IpAddr, Ipv6Addr};
+use std::str::FromStr;
+use tokio::io::BufReader;
+
+fn ipv6_from_str(addr: &str) -> Result<IpAddr, std::io::Error> {
+    match Ipv6Addr::from_str(addr) {
+        Ok(addr) => Ok(addr.into()),
+        Err(err) => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())),
+    }
+}
+
+#[tokio::test]
+async fn dns_manager() -> Result<(), std::io::Error> {
+    const DATA: &[u8] = include_bytes!("../../capture/data/dns.cap");
+
+    let mut reader = BufReader::new(Cursor::new(DATA));
+    let header = pcap::read_file_header(&mut reader).await?;
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
+    assert_eq!(dns_manager.len(), 4);
+
+    //  0xf0d4 AAAA www.netbsd.org AAAA
+    assert_eq!(
+        dns_manager.get(&ipv6_from_str("2001:4f8:4:7:2e0:81ff:fe52:9a6b")?),
+        Some("www.netbsd.org".into())
+    );
+
+    Ok(())
+}
diff --git a/rust/libslirp-rs/Cargo.toml b/rust/libslirp-rs/Cargo.toml
index 6d64de55..a9b6e7ad 100644
--- a/rust/libslirp-rs/Cargo.toml
+++ b/rust/libslirp-rs/Cargo.toml
@@ -24,11 +24,12 @@ crate-type = ["staticlib","lib"]
 doctest = false
 
 [dependencies]
+etherparse = {version = "0.16" }
 bytes = { version = "1.4.0" }
-http-proxy = { path = "../http-proxy" }
 libc = "0.2"
 log = "0.4.17"
 winapi = { version = "0.3", features = ["winsock2"] }
+tokio = { version = "1.32.0", features = [ "net", "rt-multi-thread"] }
 
 [build-dependencies]
 ##bindgen = "0.69.4"
diff --git a/rust/libslirp-rs/build.rs b/rust/libslirp-rs/build.rs
index f247fbdb..cb7c8ed1 100644
--- a/rust/libslirp-rs/build.rs
+++ b/rust/libslirp-rs/build.rs
@@ -13,8 +13,10 @@
 // limitations under the License.
 
 pub fn main() {
-    println!("cargo:rustc-link-search=../objs/archives");
-    println!("cargo:rustc-link-search=../objs/lib64");
+    let objs_path = std::env::var("OBJS_PATH").unwrap_or("../objs".to_string());
+
+    println!("cargo:rustc-link-search={objs_path}/archives");
+    println!("cargo:rustc-link-search={objs_path}/lib64");
     println!("cargo:rustc-link-lib=libslirp");
     #[cfg(target_os = "linux")]
     println!("cargo:rustc-link-lib=glib2_linux-x86_64");
diff --git a/rust/libslirp-rs/src/lib.rs b/rust/libslirp-rs/src/lib.rs
index c7a6561e..9b4b78c6 100644
--- a/rust/libslirp-rs/src/lib.rs
+++ b/rust/libslirp-rs/src/lib.rs
@@ -12,6 +12,15 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! This crate is a wrapper for libslirp C library.
+//!
+//! All calls into libslirp are routed to and handled by a dedicated
+//! thread.
+//!
+//! Rust struct LibslirpConfig for conversion between Rust and C types
+//! (IpV4Addr, SocketAddrV4, etc.).
+//!
+//! Callbacks for libslirp send_packet are delivered on Channel.
 pub mod libslirp;
 pub mod libslirp_config;
 pub mod libslirp_sys;
diff --git a/rust/libslirp-rs/src/libslirp.rs b/rust/libslirp-rs/src/libslirp.rs
index d9626b09..fe99addf 100644
--- a/rust/libslirp-rs/src/libslirp.rs
+++ b/rust/libslirp-rs/src/libslirp.rs
@@ -12,56 +12,108 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! # This module provides a safe Rust wrapper for the libslirp library.
+
+//! It allows to embed a virtual network stack within your Rust applications.
+//!
+//! ## Features
+//!
+//! * **Safe API:**  Wraps the libslirp C API in a safe and idiomatic Rust interface.
+//! * **Networking:**  Provides functionality for virtual networking, including TCP/IP, UDP, and ICMP.
+//! * **Proxy Support:**  Allows integration with proxy managers for handling external connections.
+//! * **Threading:**  Handles communication between the Rust application and the libslirp event loop.
+//!
+//! ## Usage
+//!
+//! ```
+//! use bytes::Bytes;
+//! use libslirp_rs::libslirp_config::SlirpConfig;
+//! use libslirp_rs::libslirp::LibSlirp;
+//! use std::net::Ipv4Addr;
+//! use std::sync::mpsc;
+//!
+//! let (tx_cmds, _) = mpsc::channel();
+//! // Create a LibSlirp instance with default configuration
+//! let libslirp = LibSlirp::new(
+//!     SlirpConfig::default(),
+//!     tx_cmds,
+//!     None
+//! );
+//!
+//! let data = vec![0x01, 0x02, 0x03];
+//! // Input network data into libslirp
+//! libslirp.input(Bytes::from(data));
+//!
+//! // ... other operations ...
+//!
+//! // Shutdown libslirp
+//! libslirp.shutdown();
+//! ```
+//!
+//! ## Example with Proxy
+//!
+//! ```
+//! use libslirp_rs::libslirp::LibSlirp;
+//! use libslirp_rs::libslirp_config::SlirpConfig;
+//! use libslirp_rs::libslirp::{ProxyManager, ProxyConnect};
+//! use std::sync::mpsc;
+//! use std::net::SocketAddr;
+//! // Implement the ProxyManager trait for your proxy logic
+//! struct MyProxyManager;
+//!
+//! impl ProxyManager for MyProxyManager {
+//!     // ... implementation ...
+//!     fn try_connect(
+//!         &self,
+//!         sockaddr: SocketAddr,
+//!         connect_id: usize,
+//!         connect_func: Box<dyn ProxyConnect + Send>,
+//!     ) -> bool {
+//!         todo!()
+//!     }
+//!     fn remove(&self, connect_id: usize) {
+//!         todo!()
+//!     }
+//! }
+//! let (tx_cmds, _) = mpsc::channel();
+//! // Create a LibSlirp instance with a proxy manager
+//! let libslirp = LibSlirp::new(
+//!     SlirpConfig::default(),
+//!     tx_cmds,
+//!     Some(Box::new(MyProxyManager)),
+//! );
+//!
+//! // ...
+//! ```
+//!
+//! This module abstracts away the complexities of interacting with the libslirp C library,
+//! providing a more convenient and reliable way to use it in your Rust projects.
+
 use crate::libslirp_config;
 use crate::libslirp_config::SlirpConfigs;
-///
-/// This crate is a wrapper for libslirp C library.
-///
-/// All calls into libslirp are routed to and handled by a dedicated
-/// thread.
-///
-/// Rust struct LibslirpConfig for conversion between Rust and C types
-/// (IpV4Addr, SocketAddrV4, etc.).
-///
-/// Callbacks for libslirp send_packet are delivered on Channel.
-///
 use crate::libslirp_sys;
+
 use bytes::Bytes;
 use core::sync::atomic::{AtomicUsize, Ordering};
 use log::{debug, info, warn};
+use std::cell::RefCell;
 use std::collections::HashMap;
 use std::ffi::{c_char, c_int, c_void, CStr};
-use std::sync::{mpsc, Mutex, OnceLock};
+use std::mem::ManuallyDrop;
+use std::net::SocketAddr;
+use std::rc::Rc;
+use std::sync::mpsc;
 use std::thread;
 use std::time::Duration;
 use std::time::Instant;
 
-// Uses a static to hold callback state instead of the libslirp's
-// opaque parameter to limit the number of unsafe regions.
-static CONTEXT: Mutex<CallbackContext> =
-    Mutex::new(CallbackContext { tx_bytes: None, tx_cmds: None, poll_fds: Vec::new() });
-
-// Timers are managed across the ffi boundary using a unique usize ID
-// (TimerOpaque) and a hashmap rather than memory pointers to reduce
-// unsafe code.
-
-static TIMERS: OnceLock<Mutex<TimerManager>> = OnceLock::new();
-
-fn get_timers() -> &'static Mutex<TimerManager> {
-    TIMERS.get_or_init(|| {
-        Mutex::new(TimerManager {
-            clock: Instant::now(),
-            map: HashMap::new(),
-            timers: AtomicUsize::new(1),
-        })
-    })
-}
-
 type TimerOpaque = usize;
 
+const TIMEOUT_SECS: u64 = 1;
+
 struct TimerManager {
-    clock: Instant,
-    map: HashMap<TimerOpaque, Timer>,
+    clock: RefCell<Instant>,
+    map: RefCell<HashMap<TimerOpaque, Timer>>,
     timers: AtomicUsize,
 }
 
@@ -73,25 +125,41 @@ struct Timer {
 }
 
 // The operations performed on the slirp thread
-
+#[derive(Debug)]
 enum SlirpCmd {
     Input(Bytes),
     PollResult(Vec<PollFd>, c_int),
     TimerModified,
     Shutdown,
+    ProxyConnect(libslirp_sys::SlirpProxyConnectFunc, usize, i32, i32),
+}
+
+/// Alias for io::fd::RawFd on Unix or RawSocket on Windows (converted to i32)
+pub type RawFd = i32;
+
+/// HTTP Proxy callback trait
+pub trait ProxyManager: Send {
+    fn try_connect(
+        &self,
+        sockaddr: SocketAddr,
+        connect_id: usize,
+        connect_func: Box<dyn ProxyConnect + Send>,
+    ) -> bool;
+    fn remove(&self, connect_id: usize);
 }
 
-#[derive(Default)]
 struct CallbackContext {
-    tx_bytes: Option<mpsc::Sender<Bytes>>,
-    tx_cmds: Option<mpsc::Sender<SlirpCmd>>,
-    poll_fds: Vec<PollFd>,
+    tx_bytes: mpsc::Sender<Bytes>,
+    tx_cmds: mpsc::Sender<SlirpCmd>,
+    poll_fds: Rc<RefCell<Vec<PollFd>>>,
+    proxy_manager: Option<Box<dyn ProxyManager>>,
+    timer_manager: Rc<TimerManager>,
 }
 
 // A poll thread request has a poll_fds and a timeout
 type PollRequest = (Vec<PollFd>, u32);
 
-// API to LibSlirp
+/// API to LibSlirp
 
 pub struct LibSlirp {
     tx_cmds: mpsc::Sender<SlirpCmd>,
@@ -103,9 +171,10 @@ impl TimerManager {
     }
 
     // Finds expired Timers, clears then clones them
-    fn collect_expired(&mut self) -> Vec<Timer> {
-        let now_ms = self.clock.elapsed().as_millis() as u64;
+    fn collect_expired(&self) -> Vec<Timer> {
+        let now_ms = self.get_elapsed().as_millis() as u64;
         self.map
+            .borrow_mut()
             .iter_mut()
             .filter(|(_, timer)| timer.expire_time < now_ms)
             .map(|(_, &mut ref mut timer)| {
@@ -117,31 +186,47 @@ impl TimerManager {
 
     // Return the minimum duration until the next timer
     fn min_duration(&self) -> Duration {
-        match self.map.iter().min_by_key(|(_, timer)| timer.expire_time) {
+        match self.map.borrow().iter().min_by_key(|(_, timer)| timer.expire_time) {
             Some((_, timer)) => {
-                let now_ms = self.clock.elapsed().as_millis() as u64;
+                let now_ms = self.get_elapsed().as_millis() as u64;
                 // Duration is >= 0
                 Duration::from_millis(timer.expire_time.saturating_sub(now_ms))
             }
             None => Duration::from_millis(u64::MAX),
         }
     }
-}
 
-impl LibSlirp {
-    pub fn new(config: libslirp_config::SlirpConfig, tx_bytes: mpsc::Sender<Bytes>) -> LibSlirp {
-        // Initialize the callback context
-        let mut guard = CONTEXT.lock().unwrap();
-        if guard.tx_bytes.is_some() {
-            panic!("LibSlirp::new called twice");
+    fn get_elapsed(&self) -> Duration {
+        self.clock.borrow().elapsed()
+    }
+
+    fn remove(&self, timer_key: &TimerOpaque) -> Option<Timer> {
+        self.map.borrow_mut().remove(timer_key)
+    }
+
+    fn insert(&self, timer_key: TimerOpaque, value: Timer) {
+        self.map.borrow_mut().insert(timer_key, value);
+    }
+
+    fn timer_mod(&self, timer_key: &TimerOpaque, expire_time: u64) {
+        if let Some(&mut ref mut timer) = self.map.borrow_mut().get_mut(&timer_key) {
+            // expire_time is >= 0
+            timer.expire_time = expire_time;
+        } else {
+            warn!("Unknown timer {timer_key}");
         }
-        guard.tx_bytes = Some(tx_bytes);
+    }
+}
 
+impl LibSlirp {
+    pub fn new(
+        config: libslirp_config::SlirpConfig,
+        tx_bytes: mpsc::Sender<Bytes>,
+        proxy_manager: Option<Box<dyn ProxyManager>>,
+    ) -> LibSlirp {
         let (tx_cmds, rx_cmds) = mpsc::channel::<SlirpCmd>();
         let (tx_poll, rx_poll) = mpsc::channel::<PollRequest>();
 
-        guard.tx_cmds = Some(tx_cmds.clone());
-
         // Create channels for polling thread and launch
         let tx_cmds_poll = tx_cmds.clone();
         if let Err(e) = thread::Builder::new()
@@ -151,11 +236,11 @@ impl LibSlirp {
             warn!("Failed to start slirp poll thread: {}", e);
         }
 
+        let tx_cmds_slirp = tx_cmds.clone();
         // Create channels for command processor thread and launch
-        if let Err(e) = thread::Builder::new()
-            .name("slirp".to_string())
-            .spawn(move || slirp_thread(config, rx_cmds, tx_poll))
-        {
+        if let Err(e) = thread::Builder::new().name("slirp".to_string()).spawn(move || {
+            slirp_thread(config, tx_bytes, tx_cmds_slirp, rx_cmds, tx_poll, proxy_manager)
+        }) {
             warn!("Failed to start slirp thread: {}", e);
         }
 
@@ -175,55 +260,186 @@ impl LibSlirp {
     }
 }
 
+struct ConnectRequest {
+    tx_cmds: mpsc::Sender<SlirpCmd>,
+    connect_func: libslirp_sys::SlirpProxyConnectFunc,
+    connect_id: usize,
+    af: i32,
+    start: Instant,
+}
+
+pub trait ProxyConnect: Send {
+    fn proxy_connect(&self, fd: i32, addr: SocketAddr);
+}
+
+impl ProxyConnect for ConnectRequest {
+    fn proxy_connect(&self, fd: i32, addr: SocketAddr) {
+        // Send it to Slirp after try_connect() completed
+        let duration = self.start.elapsed().as_secs();
+        if duration > TIMEOUT_SECS {
+            warn!(
+                "ConnectRequest for connection ID {} to {} took too long: {:?}",
+                self.connect_id, addr, duration
+            );
+        }
+        let _ = self.tx_cmds.send(SlirpCmd::ProxyConnect(
+            self.connect_func,
+            self.connect_id,
+            fd,
+            self.af,
+        ));
+    }
+}
+
+// Converts a libslirp callback's `opaque` handle into a
+// `CallbackContext.`
+//
+// Wrapped in a `ManuallyDrop` because we do not want to release the
+// storage when the callback returns.
+//
+// SAFETY:
+//
+// * opaque is a CallbackContext passed to the slirp API
+unsafe fn callback_context_from_raw(opaque: *mut c_void) -> ManuallyDrop<Box<CallbackContext>> {
+    ManuallyDrop::new(unsafe { Box::from_raw(opaque as *mut CallbackContext) })
+}
+
+// A Rust struct for the fields held by `slirp` C library through it's
+// lifetime.
+//
+// All libslirp C calls are impl on this struct.
+struct Slirp {
+    slirp: *mut libslirp_sys::Slirp,
+    // These fields are held by slirp C library
+    #[allow(dead_code)]
+    configs: Box<SlirpConfigs>,
+    #[allow(dead_code)]
+    callbacks: Box<libslirp_sys::SlirpCb>,
+    // Passed to API calls and then to callbacks
+    callback_context: Box<CallbackContext>,
+}
+
+impl Slirp {
+    fn new(config: libslirp_config::SlirpConfig, callback_context: Box<CallbackContext>) -> Slirp {
+        let callbacks = Box::new(libslirp_sys::SlirpCb {
+            send_packet: Some(send_packet_cb),
+            guest_error: Some(guest_error_cb),
+            clock_get_ns: Some(clock_get_ns_cb),
+            timer_new: None,
+            timer_free: Some(timer_free_cb),
+            timer_mod: Some(timer_mod_cb),
+            register_poll_fd: Some(register_poll_fd_cb),
+            unregister_poll_fd: Some(unregister_poll_fd_cb),
+            notify: Some(notify_cb),
+            init_completed: Some(init_completed_cb),
+            timer_new_opaque: Some(timer_new_opaque_cb),
+            try_connect: Some(try_connect_cb),
+            remove: Some(remove_cb),
+        });
+        let configs = Box::new(SlirpConfigs::new(&config));
+
+        // Call libslrip "C" library to create a new instance of a slirp
+        // protocol stack.
+        //
+        // SAFETY: We ensure that:
+        //
+        // * config is a valid pointer to the "C" config struct. It is
+        // held by the "C" slirp library for lifetime of the slirp
+        // instance.
+        //
+        // * callbacks is a valid pointer to an array of callback
+        // functions. It is held by the "C" slirp library for the lifetime
+        // of the slirp instance.
+        //
+        // * callback_context is an arbitrary opaque type passed back
+        //  to callback functions by libslirp.
+        let slirp = unsafe {
+            libslirp_sys::slirp_new(
+                &configs.c_slirp_config,
+                &*callbacks,
+                &*callback_context as *const CallbackContext as *mut c_void,
+            )
+        };
+
+        Slirp { slirp, configs, callbacks, callback_context }
+    }
+
+    fn handle_timer(&self, timer: Timer) {
+        unsafe {
+            //
+            // SAFETY: We ensure that:
+            //
+            // *self.slirp is a valid state returned by `slirp_new()`
+            //
+            // * timer.id is a valid c_uint from "C" slirp library calling `timer_new_opaque_cb()`
+            //
+            // * timer.cb_opaque is an usize representing a pointer to callback function from
+            // "C" slirp library calling `timer_new_opaque_cb()`
+            libslirp_sys::slirp_handle_timer(self.slirp, timer.id, timer.cb_opaque as *mut c_void);
+        };
+    }
+}
+
+impl Drop for Slirp {
+    fn drop(&mut self) {
+        // SAFETY:
+        //
+        // * self.slirp is a slirp pointer initialized by slirp_new;
+        // it's private to the struct and is only constructed that
+        // way.
+        unsafe { libslirp_sys::slirp_cleanup(self.slirp) };
+    }
+}
+
 fn slirp_thread(
     config: libslirp_config::SlirpConfig,
+    tx_bytes: mpsc::Sender<Bytes>,
+    tx_cmds: mpsc::Sender<SlirpCmd>,
     rx: mpsc::Receiver<SlirpCmd>,
     tx_poll: mpsc::Sender<PollRequest>,
+    proxy_manager: Option<Box<dyn ProxyManager>>,
 ) {
-    let callbacks = libslirp_sys::SlirpCb {
-        send_packet: Some(send_packet_cb),
-        guest_error: Some(guest_error_cb),
-        clock_get_ns: Some(clock_get_ns_cb),
-        timer_new: None,
-        timer_free: Some(timer_free_cb),
-        timer_mod: Some(timer_mod_cb),
-        register_poll_fd: Some(register_poll_fd_cb),
-        unregister_poll_fd: Some(unregister_poll_fd_cb),
-        notify: Some(notify_cb),
-        init_completed: Some(init_completed),
-        remove: None,
-        timer_new_opaque: Some(timer_new_opaque_cb),
-        try_connect: None,
-    };
-    let configs = SlirpConfigs::new(&config);
-    // Call libslrip "C" library to create a new instance of a slirp
-    // protocol stack.
-    //
-    // SAFETY: We ensure that:
-    //
-    // `config` is a valid pointer to the "C" config struct. It is
-    // held by the "C" slirp library for lifetime of the slirp
-    // instance.
-    //
-    // `callbacks` is a valid pointer to an array of callback
-    // functions. It is held by the "C" slirp library for the lifetime
-    // of the slirp instance.
-    let slirp = unsafe {
-        libslirp_sys::slirp_new(&configs.c_slirp_config, &callbacks, std::ptr::null_mut())
-    };
+    // Data structures wrapped in an RC are referenced through the
+    // libslirp callbacks and this code (both in the same thread).
+
+    let timer_manager = Rc::new(TimerManager {
+        clock: RefCell::new(Instant::now()),
+        map: RefCell::new(HashMap::new()),
+        timers: AtomicUsize::new(1),
+    });
+
+    let poll_fds = Rc::new(RefCell::new(Vec::new()));
 
-    unsafe { slirp_pollfds_fill(slirp, &tx_poll) };
+    let callback_context = Box::new(CallbackContext {
+        tx_bytes,
+        tx_cmds,
+        poll_fds: poll_fds.clone(),
+        proxy_manager,
+        timer_manager: timer_manager.clone(),
+    });
 
-    let min_duration = get_timers().lock().unwrap().min_duration();
+    let slirp = Slirp::new(config, callback_context);
+
+    slirp.pollfds_fill_and_send(&poll_fds, &tx_poll);
+
+    let min_duration = timer_manager.min_duration();
     loop {
-        match rx.recv_timeout(min_duration) {
-            Ok(SlirpCmd::PollResult(poll_fds, select_error)) => {
-                // SAFETY: we ensure that slirp is a valid state returned by `slirp_new()`
-                unsafe { slirp_pollfds_poll(slirp, select_error, poll_fds) };
-                unsafe { slirp_pollfds_fill(slirp, &tx_poll) };
+        let command = rx.recv_timeout(min_duration);
+        let start = Instant::now();
+
+        let cmd_str = format!("{:?}", command);
+        match command {
+            // The dance to tell libslirp which FDs have IO ready
+            // starts with a response from a worker thread sending a
+            // PollResult, followed by pollfds_poll forwarding the FDs
+            // to libslirp, followed by giving the worker thread
+            // another set of fds to poll (and block).
+            Ok(SlirpCmd::PollResult(poll_fds_result, select_error)) => {
+                poll_fds.borrow_mut().clone_from_slice(&poll_fds_result);
+                slirp.pollfds_poll(select_error);
+                slirp.pollfds_fill_and_send(&poll_fds, &tx_poll);
             }
-            // SAFETY: we ensure that slirp is a valid state returned by `slirp_new()`
-            Ok(SlirpCmd::Input(bytes)) => unsafe { slirp_input(slirp, &bytes) },
+            Ok(SlirpCmd::Input(bytes)) => slirp.input(&bytes),
 
             // A timer has been modified, new expired_time value
             Ok(SlirpCmd::TimerModified) => continue,
@@ -231,36 +447,46 @@ fn slirp_thread(
             // Exit the while loop and shutdown
             Ok(SlirpCmd::Shutdown) => break,
 
+            // SAFETY: we ensure that func (`SlirpProxyConnectFunc`)
+            // and `connect_opaque` are valid because they originated
+            // from the libslirp call to `try_connect_cb.`
+            //
+            // Parameter `fd` will be >= 0 and the descriptor for the
+            // active socket to use, `af` will be either AF_INET or
+            // AF_INET6. On failure `fd` will be negative.
+            Ok(SlirpCmd::ProxyConnect(func, connect_id, fd, af)) => match func {
+                Some(func) => unsafe { func(connect_id as *mut c_void, fd as c_int, af as c_int) },
+                None => warn!("Proxy connect function not found"),
+            },
+
             // Timeout... process any timers
             Err(mpsc::RecvTimeoutError::Timeout) => continue,
 
             // Error
             _ => break,
         }
-        // Callback any expired timers in the slirp thread...
-        for timer in get_timers().lock().unwrap().collect_expired() {
-            unsafe {
-                libslirp_sys::slirp_handle_timer(slirp, timer.id, timer.cb_opaque as *mut c_void)
-            };
+
+        // Explicitly store expired timers to release lock
+        let timers = timer_manager.collect_expired();
+        // Handle any expired timers' callback in the slirp thread
+        for timer in timers {
+            slirp.handle_timer(timer);
+        }
+        let duration = start.elapsed().as_secs();
+        if duration > TIMEOUT_SECS {
+            warn!("libslirp command '{cmd_str}' took too long to complete: {duration:?}");
         }
     }
     // Shuts down the instance of a slirp stack and release slirp storage. No callbacks
-    // occur after `slirp_cleanup` is called.
+    // occur after this since it calls slirp_cleanup.
+    drop(slirp);
 
-    // SAFETY: we ensure that slirp is a valid state returned by `slirp_new()`
-    unsafe { libslirp_sys::slirp_cleanup(slirp) };
     // Shutdown slirp_poll_thread -- worst case it sends a PollResult that is ignored
     // since this thread is no longer processing Slirp commands.
     drop(tx_poll);
-
-    // Drop callback context
-    *CONTEXT.lock().unwrap() =
-        CallbackContext { tx_bytes: None, tx_cmds: None, poll_fds: Vec::new() };
-
-    // SAFETY: Slirp is shutdown. `slirp` `config` and `libslirp` can
-    // be released.
 }
 
+#[derive(Clone, Debug)]
 struct PollFd {
     fd: c_int,
     events: libslirp_sys::SlirpPollType,
@@ -281,44 +507,63 @@ struct PollFd {
 // # Safety
 //
 // `slirp` must be a valid Slirp state returned by `slirp_new()`
-unsafe fn slirp_pollfds_fill(slirp: *mut libslirp_sys::Slirp, tx: &mpsc::Sender<PollRequest>) {
-    let mut timeout: u32 = 0;
-    CONTEXT.lock().unwrap().poll_fds.clear();
-
-    // Call libslrip "C" library to fill poll information using
-    // slirp_add_poll_cb callback function.
-    //
-    // SAFETY: we ensure that:
-    //
-    // `slirp` is a valid Slirp state.
-    //
-    // `timeout` is a valid ptr to a mutable u32.  The "C" slirp
-    // library stores into timeout.
-    //
-    // `slirp_add_poll_cb` is a valid `SlirpAddPollCb` function.
-    unsafe {
-        libslirp_sys::slirp_pollfds_fill(
-            slirp,
-            &mut timeout,
-            Some(slirp_add_poll_cb),
-            std::ptr::null_mut(),
-        );
-    }
-    let poll_fds: Vec<PollFd> = CONTEXT.lock().unwrap().poll_fds.drain(..).collect();
-    debug!("got {} items", poll_fds.len());
-    if let Err(e) = tx.send((poll_fds, timeout)) {
-        warn!("Failed to send poll fds: {}", e);
+impl Slirp {
+    fn pollfds_fill_and_send(
+        &self,
+        poll_fds: &RefCell<Vec<PollFd>>,
+        tx: &mpsc::Sender<PollRequest>,
+    ) {
+        let mut timeout: u32 = u32::MAX;
+        poll_fds.borrow_mut().clear();
+
+        // Call libslrip "C" library to fill poll information using
+        // slirp_add_poll_cb callback function.
+        //
+        // SAFETY: we ensure that:
+        //
+        // * self.slirp has a slirp pointer initialized by slirp_new,
+        // as it's private to the struct is only constructed that way
+        //
+        // * timeout is a valid ptr to a mutable u32.  The "C" slirp
+        // library stores into timeout.
+        //
+        // * slirp_add_poll_cb is a valid `SlirpAddPollCb` function.
+        //
+        // * self.callback_context is a CallbackContext
+        unsafe {
+            libslirp_sys::slirp_pollfds_fill(
+                self.slirp,
+                &mut timeout,
+                Some(slirp_add_poll_cb),
+                &*self.callback_context as *const CallbackContext as *mut c_void,
+            );
+        }
+        if let Err(e) = tx.send((poll_fds.borrow().to_vec(), timeout)) {
+            warn!("Failed to send poll fds: {}", e);
+        }
     }
 }
 
 // "C" library callback that is called for each file descriptor that
 // should be monitored.
+//
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn slirp_add_poll_cb(fd: c_int, events: c_int, opaque: *mut c_void) -> c_int {
+    unsafe { callback_context_from_raw(opaque) }.add_poll(fd, events)
+}
 
-extern "C" fn slirp_add_poll_cb(fd: c_int, events: c_int, _opaque: *mut c_void) -> c_int {
-    let mut guard = CONTEXT.lock().unwrap();
-    let idx = guard.poll_fds.len();
-    guard.poll_fds.push(PollFd { fd, events: events as libslirp_sys::SlirpPollType, revents: 0 });
-    idx as i32
+impl CallbackContext {
+    fn add_poll(&mut self, fd: c_int, events: c_int) -> c_int {
+        let idx = self.poll_fds.borrow().len();
+        self.poll_fds.borrow_mut().push(PollFd {
+            fd,
+            events: events as libslirp_sys::SlirpPollType,
+            revents: 0,
+        });
+        idx as i32
+    }
 }
 
 // Pass the result from the polling thread back to libslirp
@@ -332,47 +577,53 @@ extern "C" fn slirp_add_poll_cb(fd: c_int, events: c_int, _opaque: *mut c_void)
 // that should be monitored along the sleep. The opaque pointer is
 // passed as such to add_poll, and add_poll returns an index.
 //
-// # Safety
-//
-// `slirp` must be a valid Slirp state returned by `slirp_new()`
-//
-// 'select_error' should be 1 if poll() returned an error, else 0.
-unsafe fn slirp_pollfds_poll(
-    slirp: *mut libslirp_sys::Slirp,
-    select_error: c_int,
-    poll_fds: Vec<PollFd>,
-) {
-    CONTEXT.lock().unwrap().poll_fds = poll_fds;
+// * select_error should be 1 if poll() returned an error, else 0.
 
-    // Call libslrip "C" library to fill poll return event information
-    // using slirp_get_revents_cb callback function.
-    //
-    // SAFETY: we ensure that:
-    //
-    // `slirp` is a valid Slirp state.
-    //
-    // `slirp_get_revents_cb` is a valid `SlirpGetREventsCb` callback
-    // function.
-    //
-    // 'select_error' should be 1 if poll() returned an error, else 0.
-    unsafe {
-        libslirp_sys::slirp_pollfds_poll(
-            slirp,
-            select_error,
-            Some(slirp_get_revents_cb),
-            std::ptr::null_mut(),
-        );
+impl Slirp {
+    fn pollfds_poll(&self, select_error: c_int) {
+        // Call libslrip "C" library to fill poll return event information
+        // using slirp_get_revents_cb callback function.
+        //
+        // SAFETY: we ensure that:
+        //
+        // * self.slirp has a slirp pointer initialized by slirp_new,
+        // as it's private to the struct is only constructed that way
+        //
+        // * slirp_get_revents_cb is a valid `SlirpGetREventsCb` callback
+        // function.
+        //
+        // * select_error should be 1 if poll() returned an error, else 0.
+        //
+        // * self.callback_context is a CallbackContext
+        unsafe {
+            libslirp_sys::slirp_pollfds_poll(
+                self.slirp,
+                select_error,
+                Some(slirp_get_revents_cb),
+                &*self.callback_context as *const CallbackContext as *mut c_void,
+            );
+        }
     }
 }
 
 // "C" library callback that is called on each file descriptor, giving
 // it the index that add_poll returned.
+//
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn slirp_get_revents_cb(idx: c_int, opaque: *mut c_void) -> c_int {
+    unsafe { callback_context_from_raw(opaque) }.get_events(idx)
+}
 
-extern "C" fn slirp_get_revents_cb(idx: c_int, _opaue: *mut c_void) -> c_int {
-    if let Some(poll_fd) = CONTEXT.lock().unwrap().poll_fds.get(idx as usize) {
-        return poll_fd.revents as c_int;
+impl CallbackContext {
+    fn get_events(&self, idx: c_int) -> c_int {
+        if let Some(poll_fd) = self.poll_fds.borrow().get(idx as usize) {
+            poll_fd.revents as c_int
+        } else {
+            0
+        }
     }
-    0
 }
 
 macro_rules! ternary {
@@ -385,7 +636,8 @@ macro_rules! ternary {
     };
 }
 
-// Loop issuing blocking poll requests, sending the results into the slirp thread
+// Worker thread loops issuing blocking poll requests, sending the
+// results into the slirp thread
 
 fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>) {
     #[cfg(any(target_os = "linux", target_os = "macos"))]
@@ -440,7 +692,12 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
             | ternary!(events & POLLRDBAND, libslirp_sys::SLIRP_POLL_PRI)
     }
 
+    let mut prev_poll_fds_len = 0;
     while let Ok((poll_fds, timeout)) = rx.recv() {
+        if poll_fds.len() != prev_poll_fds_len {
+            prev_poll_fds_len = poll_fds.len();
+            debug!("slirp_poll_thread recv poll_fds.len(): {:?}", prev_poll_fds_len);
+        }
         // Create a c format array with the same size as poll
         let mut os_poll_fds: Vec<pollfd> = Vec::with_capacity(poll_fds.len());
         for fd in &poll_fds {
@@ -451,14 +708,44 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
             });
         }
 
-        // SAFETY: we ensure that:
-        //
-        // `os_poll_fds` is a valid ptr to a vector of pollfd which
-        // the `poll` system call can write into. Note `os_poll_fds`
-        // is created and allocated above.
-        let poll_result = unsafe {
-            poll(os_poll_fds.as_mut_ptr(), os_poll_fds.len() as OsPollFdsLenType, timeout as i32)
-        };
+        let mut poll_result = 0;
+        #[cfg(any(target_os = "linux", target_os = "macos"))]
+        {
+            // SAFETY: we ensure that:
+            //
+            // `os_poll_fds` is a valid ptr to a vector of pollfd which
+            // the `poll` system call can write into. Note `os_poll_fds`
+            // is created and allocated above.
+            poll_result = unsafe {
+                poll(
+                    os_poll_fds.as_mut_ptr(),
+                    os_poll_fds.len() as OsPollFdsLenType,
+                    timeout as i32,
+                )
+            };
+        }
+        // WSAPoll requires an array of one or more POLLFD structures.
+        // When nfds == 0, WSAPoll returns immediately with result -1, ignoring the timeout.
+        // This is different from poll on Linux/macOS, which will wait for the timeout.
+        // Therefore, on Windows, we don't call WSAPoll when nfds == 0, and instead explicitly sleep for the timeout.
+        #[cfg(target_os = "windows")]
+        if os_poll_fds.is_empty() {
+            // If there are no FDs to poll, sleep for the specified timeout.
+            thread::sleep(Duration::from_millis(timeout as u64));
+        } else {
+            // SAFETY: we ensure that:
+            //
+            // `os_poll_fds` is a valid ptr to a vector of pollfd which
+            // the `poll` system call can write into. Note `os_poll_fds`
+            // is created and allocated above.
+            poll_result = unsafe {
+                poll(
+                    os_poll_fds.as_mut_ptr(),
+                    os_poll_fds.len() as OsPollFdsLenType,
+                    timeout as i32,
+                )
+            };
+        }
 
         let mut slirp_poll_fds: Vec<PollFd> = Vec::with_capacity(poll_fds.len());
         #[cfg(any(target_os = "linux", target_os = "macos"))]
@@ -489,15 +776,13 @@ fn slirp_poll_thread(rx: mpsc::Receiver<PollRequest>, tx: mpsc::Sender<SlirpCmd>
 //
 // This is called by the application when the guest emits a packet on
 // the guest network, to be interpreted by slirp.
-//
-// # Safety
-//
-// `slirp` must be a valid Slirp state returned by `slirp_new()`
-unsafe fn slirp_input(slirp: *mut libslirp_sys::Slirp, bytes: &[u8]) {
-    // SAFETY: The "C" library ensure that the memory is not
-    // referenced after the call and `bytes` does not need to remain
-    // valid after the function returns.
-    unsafe { libslirp_sys::slirp_input(slirp, bytes.as_ptr(), bytes.len() as i32) };
+impl Slirp {
+    fn input(&self, bytes: &[u8]) {
+        // SAFETY: The "C" library ensure that the memory is not
+        // referenced after the call and `bytes` does not need to remain
+        // valid after the function returns.
+        unsafe { libslirp_sys::slirp_input(self.slirp, bytes.as_ptr(), bytes.len() as i32) };
+    }
 }
 
 // "C" library callback that is called to send an ethernet frame to
@@ -508,24 +793,29 @@ unsafe fn slirp_input(slirp: *mut libslirp_sys::Slirp, bytes: &[u8]) {
 //
 // # Safety:
 //
-// `buf` must be a valid pointer to `len` bytes of memory. The
+// * buf must be a valid pointer to `len` bytes of memory. The
 // contents of buf must be valid for the duration of this call.
+//
+// * len is > 0
+//
+// * opaque is a CallbackContext
 unsafe extern "C" fn send_packet_cb(
     buf: *const c_void,
     len: usize,
-    _opaque: *mut c_void,
+    opaque: *mut c_void,
 ) -> libslirp_sys::slirp_ssize_t {
-    // SAFETY: The caller ensures that `buf` is contains `len` bytes of data.
-    let c_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
-    // Bytes::from(slice: &'static [u8]) creates a Bytes object without copying the data.
-    // To own its data, copy &'static [u8] to Vec<u8> before converting to Bytes.
-    CONTEXT
-        .lock()
-        .unwrap()
-        .tx_bytes
-        .as_ref()
-        .map(|sender| sender.send(Bytes::from(c_slice.to_vec())));
-    len as libslirp_sys::slirp_ssize_t
+    unsafe { callback_context_from_raw(opaque) }.send_packet(buf, len)
+}
+
+impl CallbackContext {
+    fn send_packet(&self, buf: *const c_void, len: usize) -> libslirp_sys::slirp_ssize_t {
+        // SAFETY: The caller ensures that `buf` is contains `len` bytes of data.
+        let c_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
+        // Bytes::from(slice: &'static [u8]) creates a Bytes object without copying the data.
+        // To own its data, copy &'static [u8] to Vec<u8> before converting to Bytes.
+        let _ = self.tx_bytes.send(Bytes::from(c_slice.to_vec()));
+        len as libslirp_sys::slirp_ssize_t
+    }
 }
 
 // "C" library callback to print a message for an error due to guest
@@ -533,82 +823,186 @@ unsafe extern "C" fn send_packet_cb(
 //
 // # Safety:
 //
-// `msg` must be a valid nul-terminated utf8 string.
-unsafe extern "C" fn guest_error_cb(msg: *const c_char, _opaque: *mut c_void) {
+// * msg must be a valid nul-terminated utf8 string.
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn guest_error_cb(msg: *const c_char, opaque: *mut c_void) {
     // SAFETY: The caller ensures that `msg` is a nul-terminated string.
     let msg = String::from_utf8_lossy(unsafe { CStr::from_ptr(msg) }.to_bytes());
-    warn!("libslirp: {msg}");
+    unsafe { callback_context_from_raw(opaque) }.guest_error(msg.to_string());
+}
+
+impl CallbackContext {
+    fn guest_error(&self, msg: String) {
+        warn!("libslirp: {msg}");
+    }
+}
+
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn clock_get_ns_cb(opaque: *mut c_void) -> i64 {
+    unsafe { callback_context_from_raw(opaque) }.clock_get_ns()
+}
+
+impl CallbackContext {
+    fn clock_get_ns(&self) -> i64 {
+        self.timer_manager.get_elapsed().as_nanos() as i64
+    }
 }
 
-extern "C" fn clock_get_ns_cb(_opaque: *mut c_void) -> i64 {
-    get_timers().lock().unwrap().clock.elapsed().as_nanos() as i64
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn init_completed_cb(_slirp: *mut libslirp_sys::Slirp, opaque: *mut c_void) {
+    unsafe { callback_context_from_raw(opaque) }.init_completed();
 }
 
-extern "C" fn init_completed(_slirp: *mut libslirp_sys::Slirp, _opaque: *mut c_void) {
-    info!("libslirp: initialization completed.");
+impl CallbackContext {
+    fn init_completed(&self) {
+        info!("libslirp: initialization completed.");
+    }
 }
 
 // Create a new timer
-extern "C" fn timer_new_opaque_cb(
+//
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn timer_new_opaque_cb(
     id: libslirp_sys::SlirpTimerId,
     cb_opaque: *mut c_void,
-    _opaque: *mut c_void,
+    opaque: *mut c_void,
 ) -> *mut c_void {
-    let timers = get_timers();
-    let mut guard = timers.lock().unwrap();
-    let timer = guard.next_timer();
-    debug!("timer_new_opaque {timer}");
-    guard.map.insert(timer, Timer { expire_time: u64::MAX, id, cb_opaque: cb_opaque as usize });
-    timer as *mut c_void
+    unsafe { callback_context_from_raw(opaque) }.timer_new_opaque(id, cb_opaque)
 }
 
-extern "C" fn timer_free_cb(
-    timer: *mut ::std::os::raw::c_void,
-    _opaque: *mut ::std::os::raw::c_void,
-) {
-    let timer = timer as TimerOpaque;
-    debug!("timer_free {timer}");
-    if get_timers().lock().unwrap().map.remove(&timer).is_none() {
-        warn!("Unknown timer {timer}");
+impl CallbackContext {
+    // SAFETY:
+    //
+    // * cb_opaque is only passed back to libslirp
+    unsafe fn timer_new_opaque(
+        &self,
+        id: libslirp_sys::SlirpTimerId,
+        cb_opaque: *mut c_void,
+    ) -> *mut c_void {
+        let timer = self.timer_manager.next_timer();
+        self.timer_manager
+            .insert(timer, Timer { expire_time: u64::MAX, id, cb_opaque: cb_opaque as usize });
+        timer as *mut c_void
     }
 }
 
-extern "C" fn timer_mod_cb(
-    timer: *mut ::std::os::raw::c_void,
-    expire_time: i64,
-    _opaque: *mut ::std::os::raw::c_void,
-) {
-    let timer_key = timer as TimerOpaque;
-    let now_ms = get_timers().lock().unwrap().clock.elapsed().as_millis() as u64;
-    if let Some(&mut ref mut timer) = get_timers().lock().unwrap().map.get_mut(&timer_key) {
-        // expire_time is > 0
-        timer.expire_time = std::cmp::max(expire_time, 0) as u64;
-        debug!("timer_mod {timer_key} expire_time: {}ms", timer.expire_time.saturating_sub(now_ms));
-    } else {
-        warn!("Unknown timer {timer_key}");
-    }
-    // Wake up slirp command thread to reset sleep duration
-    CONTEXT.lock().unwrap().tx_cmds.as_ref().map(|sender| sender.send(SlirpCmd::TimerModified));
-}
-
-extern "C" fn register_poll_fd_cb(
-    _fd: ::std::os::raw::c_int,
-    _opaque: *mut ::std::os::raw::c_void,
-) {
+// SAFETY:
+//
+// * timer is a TimerOpaque key for timer manager
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn timer_free_cb(timer: *mut c_void, opaque: *mut c_void) {
+    unsafe { callback_context_from_raw(opaque) }.timer_free(timer);
+}
+
+impl CallbackContext {
+    fn timer_free(&self, timer: *mut c_void) {
+        let timer = timer as TimerOpaque;
+        if self.timer_manager.remove(&timer).is_none() {
+            warn!("Unknown timer {timer}");
+        }
+    }
+}
+
+// SAFETY:
+//
+// * timer is a TimerOpaque key for timer manager
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn timer_mod_cb(timer: *mut c_void, expire_time: i64, opaque: *mut c_void) {
+    unsafe { callback_context_from_raw(opaque) }.timer_mod(timer, expire_time);
+}
+
+impl CallbackContext {
+    fn timer_mod(&self, timer: *mut c_void, expire_time: i64) {
+        let timer_key = timer as TimerOpaque;
+        let expire_time = std::cmp::max(expire_time, 0) as u64;
+        self.timer_manager.timer_mod(&timer_key, expire_time);
+        // Wake up slirp command thread to reset sleep duration
+        let _ = self.tx_cmds.send(SlirpCmd::TimerModified);
+    }
+}
+
+extern "C" fn register_poll_fd_cb(_fd: c_int, _opaque: *mut c_void) {
     //TODO: Need implementation for Windows
 }
 
-extern "C" fn unregister_poll_fd_cb(
-    _fd: ::std::os::raw::c_int,
-    _opaque: *mut ::std::os::raw::c_void,
-) {
+extern "C" fn unregister_poll_fd_cb(_fd: c_int, _opaque: *mut c_void) {
     //TODO: Need implementation for Windows
 }
 
-extern "C" fn notify_cb(_opaque: *mut ::std::os::raw::c_void) {
+extern "C" fn notify_cb(_opaque: *mut c_void) {
     //TODO: Un-implemented
 }
 
+// Called by libslirp to initiate a proxy connection to address
+// `addr.` Eventually this will notify libslirp with a result by
+// calling the passed `connect_func.`
+//
+// SAFETY:
+//
+// * opaque is a CallbackContext
+unsafe extern "C" fn try_connect_cb(
+    addr: *const libslirp_sys::sockaddr_storage,
+    connect_func: libslirp_sys::SlirpProxyConnectFunc,
+    connect_opaque: *mut c_void,
+    opaque: *mut c_void,
+) -> bool {
+    unsafe { callback_context_from_raw(opaque) }.try_connect(
+        addr,
+        connect_func,
+        connect_opaque as usize,
+    )
+}
+
+impl CallbackContext {
+    fn try_connect(
+        &self,
+        addr: *const libslirp_sys::sockaddr_storage,
+        connect_func: libslirp_sys::SlirpProxyConnectFunc,
+        connect_id: usize,
+    ) -> bool {
+        if let Some(proxy_manager) = &self.proxy_manager {
+            // SAFETY: We ensure that addr is valid when `try_connect` is called from libslirp
+            let storage = unsafe { *addr };
+            let af = storage.ss_family as i32;
+            let socket_addr: SocketAddr = storage.into();
+            proxy_manager.try_connect(
+                socket_addr,
+                connect_id,
+                Box::new(ConnectRequest {
+                    tx_cmds: self.tx_cmds.clone(),
+                    connect_func,
+                    connect_id,
+                    af,
+                    start: Instant::now(),
+                }),
+            )
+        } else {
+            false
+        }
+    }
+}
+
+unsafe extern "C" fn remove_cb(connect_opaque: *mut c_void, opaque: *mut c_void) {
+    unsafe { callback_context_from_raw(opaque) }.remove(connect_opaque as usize);
+}
+
+impl CallbackContext {
+    fn remove(&self, connect_id: usize) {
+        if let Some(proxy_connector) = &self.proxy_manager {
+            proxy_connector.remove(connect_id);
+        }
+    }
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
diff --git a/rust/libslirp-rs/src/libslirp_config.rs b/rust/libslirp-rs/src/libslirp_config.rs
index e802bff0..cf48a5b5 100644
--- a/rust/libslirp-rs/src/libslirp_config.rs
+++ b/rust/libslirp-rs/src/libslirp_config.rs
@@ -12,13 +12,19 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::libslirp_sys;
+//! Conversion between Rust and C configurations.
+use crate::libslirp_sys::{self, SLIRP_MAX_DNS_SERVERS};
+use log::warn;
 use std::ffi::CString;
+use std::io;
+use std::net::SocketAddr;
 use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
 use std::path::PathBuf;
+use tokio;
 
-// Rust SlirpConfig
+const MAX_DNS_SERVERS: usize = SLIRP_MAX_DNS_SERVERS as usize;
 
+/// Rust SlirpConfig
 pub struct SlirpConfig {
     pub version: u32,
     pub restricted: i32,
@@ -50,8 +56,7 @@ pub struct SlirpConfig {
     pub mfr_id: u32,
     pub oob_eth_addr: [u8; 6usize],
     pub http_proxy_on: bool,
-    pub host_dns_count: usize,
-    pub host_dns: [libslirp_sys::sockaddr_storage; 4usize],
+    pub host_dns: Vec<SocketAddr>,
 }
 
 impl Default for SlirpConfig {
@@ -95,14 +100,13 @@ impl Default for SlirpConfig {
             mfr_id: 0,
             oob_eth_addr: [0; 6usize],
             http_proxy_on: false,
-            host_dns_count: 0,
-            host_dns: [libslirp_sys::sockaddr_storage::default(); 4usize],
+            host_dns: Vec::new(),
         }
     }
 }
 
-// Struct to hold a "C" SlirpConfig and the Rust storage that is
-// referenced by SlirpConfig.
+/// Struct to hold a "C" SlirpConfig and the Rust storage that is
+/// referenced by SlirpConfig.
 #[allow(dead_code)]
 pub struct SlirpConfigs {
     pub c_slirp_config: libslirp_sys::SlirpConfig,
@@ -113,9 +117,38 @@ pub struct SlirpConfigs {
     c_vdomainname: Option<CString>,
     c_vhostname: Option<CString>,
     c_tftp_path: Option<CString>,
+    c_host_dns: [libslirp_sys::sockaddr_storage; MAX_DNS_SERVERS],
     // TODO: add other fields
 }
 
+pub async fn lookup_host_dns(host_dns: &str) -> io::Result<Vec<SocketAddr>> {
+    let mut set = tokio::task::JoinSet::new();
+    if host_dns.is_empty() {
+        return Ok(Vec::new());
+    }
+
+    for addr in host_dns.split(",") {
+        set.spawn(tokio::net::lookup_host(format!("{addr}:0")));
+    }
+
+    let mut addrs = Vec::new();
+    while let Some(result) = set.join_next().await {
+        addrs.push(result??.next().ok_or(io::Error::from(io::ErrorKind::NotFound))?);
+    }
+    Ok(addrs)
+}
+
+fn to_socketaddr_storage(dns: &[SocketAddr]) -> [libslirp_sys::sockaddr_storage; MAX_DNS_SERVERS] {
+    let mut result = [libslirp_sys::sockaddr_storage::default(); MAX_DNS_SERVERS];
+    if dns.len() > MAX_DNS_SERVERS {
+        warn!("Too many DNS servers, only keeping the first {} ones", MAX_DNS_SERVERS);
+    }
+    for i in 0..usize::min(dns.len(), MAX_DNS_SERVERS) {
+        result[i] = dns[i].into();
+    }
+    result
+}
+
 impl SlirpConfigs {
     pub fn new(config: &SlirpConfig) -> SlirpConfigs {
         let as_cstring =
@@ -129,6 +162,8 @@ impl SlirpConfigs {
         let c_bootfile = as_cstring(&config.bootfile);
         let c_vdomainname = as_cstring(&config.vdomainname);
 
+        let c_host_dns = to_socketaddr_storage(&config.host_dns);
+
         // Convert to a ptr::null() or a raw ptr to managed
         // memory. Whenever storing a ptr in "C" Struct using `as_ptr`
         // this code must have a Rust member is `SlirpConfigs` that
@@ -169,8 +204,8 @@ impl SlirpConfigs {
             mfr_id: config.mfr_id,
             oob_eth_addr: config.oob_eth_addr,
             http_proxy_on: config.http_proxy_on,
-            host_dns_count: config.host_dns_count,
-            host_dns: config.host_dns,
+            host_dns_count: config.host_dns.len(),
+            host_dns: c_host_dns,
         };
 
         // Return the "C" struct and Rust members holding the storage
@@ -182,6 +217,7 @@ impl SlirpConfigs {
             c_bootfile,
             c_vdomainname,
             c_tftp_path,
+            c_host_dns,
         }
     }
 }
@@ -189,6 +225,7 @@ impl SlirpConfigs {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use tokio::runtime::Runtime;
 
     #[test]
     fn test_slirp_config_default() {
@@ -224,7 +261,7 @@ mod tests {
         assert_eq!(config.mfr_id, 0);
         assert_eq!(config.oob_eth_addr, [0; 6]);
         assert!(!config.http_proxy_on);
-        assert_eq!(config.host_dns_count, 0);
+        assert_eq!(config.host_dns.len(), 0);
     }
 
     #[test]
@@ -241,4 +278,76 @@ mod tests {
         assert_eq!(c_configs.c_slirp_config.vhostname, std::ptr::null());
         assert_eq!(c_configs.c_slirp_config.tftp_server_name, std::ptr::null());
     }
+
+    #[test]
+    fn test_lookup_host_dns() -> io::Result<()> {
+        let rt = Runtime::new().unwrap();
+        let results = rt.block_on(lookup_host_dns(""))?;
+        assert_eq!(results.len(), 0);
+
+        let results = rt.block_on(lookup_host_dns("localhost"))?;
+        assert_eq!(results.len(), 1);
+
+        let results = rt.block_on(lookup_host_dns("example.com"))?;
+        assert_eq!(results.len(), 1);
+
+        let results = rt.block_on(lookup_host_dns("localhost,example.com"))?;
+        assert_eq!(results.len(), 2);
+        Ok(())
+    }
+
+    #[test]
+    fn test_to_socketaddr_storage_empty_input() {
+        let dns: [SocketAddr; 0] = [];
+        let result = to_socketaddr_storage(&dns);
+        assert_eq!(result.len(), MAX_DNS_SERVERS);
+        for entry in result {
+            // Assuming `sockaddr_storage::default()` initializes all fields to 0
+            assert_eq!(entry.ss_family, 0);
+        }
+    }
+
+    #[test]
+    fn test_to_socketaddr_storage() {
+        let dns = ["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
+        let result = to_socketaddr_storage(&dns);
+        assert_eq!(result.len(), MAX_DNS_SERVERS);
+        for i in 0..dns.len() {
+            assert_ne!(result[i].ss_family, 0); // Converted addresses should have a non-zero family
+        }
+        for i in dns.len()..MAX_DNS_SERVERS {
+            assert_eq!(result[i].ss_family, 0); // Remaining entries should be default
+        }
+    }
+
+    #[test]
+    fn test_to_socketaddr_storage_valid_input_at_max() {
+        let dns = [
+            "1.1.1.1:53".parse().unwrap(),
+            "8.8.8.8:53".parse().unwrap(),
+            "9.9.9.9:53".parse().unwrap(),
+            "1.0.0.1:53".parse().unwrap(),
+        ];
+        let result = to_socketaddr_storage(&dns);
+        assert_eq!(result.len(), MAX_DNS_SERVERS);
+        for i in 0..dns.len() {
+            assert_ne!(result[i].ss_family, 0);
+        }
+    }
+
+    #[test]
+    fn test_to_socketaddr_storage_input_exceeds_max() {
+        let dns = [
+            "1.1.1.1:53".parse().unwrap(),
+            "8.8.8.8:53".parse().unwrap(),
+            "9.9.9.9:53".parse().unwrap(),
+            "1.0.0.1:53".parse().unwrap(),
+            "1.2.3.4:53".parse().unwrap(), // Extra address
+        ];
+        let result = to_socketaddr_storage(&dns);
+        assert_eq!(result.len(), MAX_DNS_SERVERS);
+        for i in 0..MAX_DNS_SERVERS {
+            assert_ne!(result[i].ss_family, 0);
+        }
+    }
 }
diff --git a/rust/libslirp-rs/src/libslirp_sys/linux/bindings.rs b/rust/libslirp-rs/src/libslirp_sys/linux/bindings.rs
index e047e580..60f38e43 100644
--- a/rust/libslirp-rs/src/libslirp_sys/linux/bindings.rs
+++ b/rust/libslirp-rs/src/libslirp_sys/linux/bindings.rs
@@ -1,4 +1,4 @@
-/* automatically generated by rust-bindgen 0.69.4 */
+/* automatically generated by rust-bindgen 0.69.5 */
 
 #[repr(C)]
 #[derive(Default)]
@@ -56,6 +56,7 @@ pub const __USE_ATFILE: u32 = 1;
 pub const __USE_FORTIFY_LEVEL: u32 = 0;
 pub const __GLIBC_USE_DEPRECATED_GETS: u32 = 0;
 pub const __GLIBC_USE_DEPRECATED_SCANF: u32 = 0;
+pub const __GLIBC_USE_C2X_STRTOL: u32 = 0;
 pub const _STDC_PREDEF_H: u32 = 1;
 pub const __STDC_IEC_559__: u32 = 1;
 pub const __STDC_IEC_60559_BFP__: u32 = 201404;
@@ -64,7 +65,7 @@ pub const __STDC_IEC_60559_COMPLEX__: u32 = 201404;
 pub const __STDC_ISO_10646__: u32 = 201706;
 pub const __GNU_LIBRARY__: u32 = 6;
 pub const __GLIBC__: u32 = 2;
-pub const __GLIBC_MINOR__: u32 = 37;
+pub const __GLIBC_MINOR__: u32 = 38;
 pub const _SYS_CDEFS_H: u32 = 1;
 pub const __glibc_c99_flexarr_available: u32 = 1;
 pub const __LDOUBLE_REDIRECTS_TO_FLOAT128_ABI: u32 = 0;
@@ -302,6 +303,7 @@ pub const SOMAXCONN: u32 = 4096;
 pub const _BITS_SOCKADDR_H: u32 = 1;
 pub const _SS_SIZE: u32 = 128;
 pub const __BITS_PER_LONG: u32 = 64;
+pub const __BITS_PER_LONG_LONG: u32 = 64;
 pub const FIOSETOWN: u32 = 35073;
 pub const SIOCSPGRP: u32 = 35074;
 pub const FIOGETOWN: u32 = 35075;
@@ -456,6 +458,7 @@ pub const IP_PMTUDISC_DO: u32 = 2;
 pub const IP_PMTUDISC_PROBE: u32 = 3;
 pub const IP_PMTUDISC_INTERFACE: u32 = 4;
 pub const IP_PMTUDISC_OMIT: u32 = 5;
+pub const IP_LOCAL_PORT_RANGE: u32 = 51;
 pub const SOL_IP: u32 = 0;
 pub const IP_DEFAULT_MULTICAST_TTL: u32 = 1;
 pub const IP_DEFAULT_MULTICAST_LOOP: u32 = 1;
@@ -2917,10 +2920,15 @@ pub struct SlirpCb {
             addr: *const sockaddr_storage,
             connect_func: SlirpProxyConnectFunc,
             connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
         ) -> bool,
     >,
-    pub remove:
-        ::std::option::Option<unsafe extern "C" fn(connect_opaque: *mut ::std::os::raw::c_void)>,
+    pub remove: ::std::option::Option<
+        unsafe extern "C" fn(
+            connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
+        ),
+    >,
 }
 #[test]
 fn bindgen_test_layout_SlirpCb() {
diff --git a/rust/libslirp-rs/src/libslirp_sys/macos/bindings.rs b/rust/libslirp-rs/src/libslirp_sys/macos/bindings.rs
index f4659c11..6f255fc2 100644
--- a/rust/libslirp-rs/src/libslirp_sys/macos/bindings.rs
+++ b/rust/libslirp-rs/src/libslirp_sys/macos/bindings.rs
@@ -1,4 +1,4 @@
-/* automatically generated by rust-bindgen 0.69.4 */
+/* automatically generated by rust-bindgen 0.69.5 */
 
 pub const __WORDSIZE: u32 = 64;
 pub const __DARWIN_ONLY_64_BIT_INO_T: u32 = 1;
@@ -3159,10 +3159,15 @@ pub struct SlirpCb {
             addr: *const sockaddr_storage,
             connect_func: SlirpProxyConnectFunc,
             connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
         ) -> bool,
     >,
-    pub remove:
-        ::std::option::Option<unsafe extern "C" fn(connect_opaque: *mut ::std::os::raw::c_void)>,
+    pub remove: ::std::option::Option<
+        unsafe extern "C" fn(
+            connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
+        ),
+    >,
 }
 #[test]
 fn bindgen_test_layout_SlirpCb() {
diff --git a/rust/libslirp-rs/src/libslirp_sys/mod.rs b/rust/libslirp-rs/src/libslirp_sys/mod.rs
index 9f69213d..17afb896 100644
--- a/rust/libslirp-rs/src/libslirp_sys/mod.rs
+++ b/rust/libslirp-rs/src/libslirp_sys/mod.rs
@@ -12,6 +12,28 @@
 //  See the License for the specific language governing permissions and
 //  limitations under the License.
 
+//! FFI bindings for libslirp library.
+//!
+//! This allows for easy integration of user-mode networking into Rust applications.
+//!
+//! It offers functionality for:
+//!
+//! - Converting C sockaddr_in and sockaddr_in6 to Rust types per OS
+//! - Converting C sockaddr_storage type into the IPv6 and IPv4 variants
+//!
+//! # Example
+//!
+//! ```
+//! use libslirp_rs::libslirp_sys::sockaddr_storage;
+//! use std::net::Ipv4Addr;
+//! use std::net::SocketAddr;
+//!
+//! let sockaddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
+//! let storage: sockaddr_storage = sockaddr.into();
+//!
+//! // Interact with the Slirp instance
+//! ```
+
 #![allow(non_upper_case_globals)]
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
@@ -19,6 +41,9 @@
 // Remove this once bindgen figures out how to do this correctly
 #![allow(deref_nullptr)]
 
+use std::convert::From;
+use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
+
 #[cfg(target_os = "linux")]
 include!("linux/bindings.rs");
 
@@ -28,31 +53,46 @@ include!("macos/bindings.rs");
 #[cfg(target_os = "windows")]
 include!("windows/bindings.rs");
 
-use std::convert::From;
-use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
-
 impl Default for sockaddr_storage {
-    #[cfg(target_os = "macos")]
+    /// Returns a zeroed `sockaddr_storage`.
+    ///
+    /// This is useful for uninitialied libslirp_config fields.
+    ///
+    /// This is safe because `sockaddr_storage` is a plain old data
+    /// type with no padding or invariants, and a zeroed
+    /// `sockaddr_storage` is a valid representation of "no address".
     fn default() -> Self {
-        sockaddr_storage {
-            ss_len: 0,
-            ss_family: 0,
-            __ss_pad1: [0i8; 6],
-            __ss_align: 0,
-            __ss_pad2: [0i8; 112],
-        }
+        // Safety:
+        //  * sockaddr_storage is repr(C) and has no uninitialized padding bytes.
+        //  * Zeroing a sockaddr_storage is a valid initialization.
+        unsafe { std::mem::zeroed() }
     }
+}
 
-    #[cfg(target_os = "linux")]
-    fn default() -> Self {
-        sockaddr_storage { ss_family: 0, __ss_padding: [0i8; 118], __ss_align: 0 }
-    }
+fn v4_ref(storage: &sockaddr_storage) -> &sockaddr_in {
+    // SAFETY: `sockaddr_storage` has size and alignment that is at least that of `sockaddr_in`.
+    // Neither types have any padding.
+    unsafe { &*(storage as *const sockaddr_storage as *const sockaddr_in) }
+}
 
-    #[cfg(target_os = "windows")]
-    fn default() -> Self {
-        sockaddr_storage { ss_family: 0, __ss_pad1: [0i8; 6], __ss_align: 0, __ss_pad2: [0i8; 112] }
-    }
+fn v6_ref(storage: &sockaddr_storage) -> &sockaddr_in6 {
+    // SAFETY: `sockaddr_storage` has size and alignment that is at least that of `sockaddr_in6`.
+    // Neither types have any padding.
+    unsafe { &*(storage as *const sockaddr_storage as *const sockaddr_in6) }
 }
+
+fn v4_mut(storage: &mut sockaddr_storage) -> &mut sockaddr_in {
+    // SAFETY: `sockaddr_storage` has size and alignment that is at least that of `sockaddr_in`.
+    // Neither types have any padding.
+    unsafe { &mut *(storage as *mut sockaddr_storage as *mut sockaddr_in) }
+}
+
+fn v6_mut(storage: &mut sockaddr_storage) -> &mut sockaddr_in6 {
+    // SAFETY: `sockaddr_storage` has size and alignment that is at least that of `sockaddr_in6`.
+    // Neither types have any padding.
+    unsafe { &mut *(storage as *mut sockaddr_storage as *mut sockaddr_in6) }
+}
+
 // Type for libslirp poll bitfield mask SLIRP_POLL_nnn
 
 #[cfg(target_os = "linux")]
@@ -64,103 +104,301 @@ pub type SlirpPollType = _bindgen_ty_1;
 #[cfg(target_os = "windows")]
 pub type SlirpPollType = _bindgen_ty_5;
 
-impl From<Ipv4Addr> for in_addr {
-    #[cfg(target_os = "macos")]
-    fn from(item: Ipv4Addr) -> Self {
-        in_addr { s_addr: std::os::raw::c_uint::to_be(item.into()) }
+impl From<sockaddr_storage> for SocketAddr {
+    /// Converts a `sockaddr_storage` to a `SocketAddr`.
+    ///
+    /// This function safely converts a `sockaddr_storage` from the
+    /// `libslirp_sys` crate into a `std::net::SocketAddr`. It handles
+    /// both IPv4 and IPv6 addresses by checking the `ss_family` field
+    /// and casting the `sockaddr_storage` to the appropriate address
+    /// type (`sockaddr_in` or `sockaddr_in6`).
+    ///
+    /// # Panics
+    ///
+    /// This function will panic if the `ss_family` field of the
+    /// `sockaddr_storage` is not `AF_INET` or `AF_INET6`.
+    fn from(storage: sockaddr_storage) -> Self {
+        match storage.ss_family as u32 {
+            AF_INET => SocketAddr::V4((*v4_ref(&storage)).into()),
+            AF_INET6 => SocketAddr::V6((*v6_ref(&storage)).into()),
+            _ => panic!("Unsupported address family"),
+        }
     }
+}
 
-    #[cfg(target_os = "linux")]
-    fn from(item: Ipv4Addr) -> Self {
-        in_addr { s_addr: u32::to_be(item.into()) }
+impl From<SocketAddr> for sockaddr_storage {
+    /// Converts a `SocketAddr` to a `sockaddr_storage`.
+    ///
+    /// This function safely converts a `std::net::SocketAddr` into a
+    /// `libslirp_sys::sockaddr_storage`. It handles both IPv4 and
+    /// IPv6 addresses by writing the appropriate data into the
+    /// `sockaddr_storage` structure.
+    ///
+    /// This conversion is useful when interacting with
+    /// libslirp_config that expect a `sockaddr_storage` type.
+    fn from(sockaddr: SocketAddr) -> Self {
+        let mut storage = sockaddr_storage::default();
+
+        match sockaddr {
+            SocketAddr::V4(addr) => *v4_mut(&mut storage) = addr.into(),
+            SocketAddr::V6(addr) => *v6_mut(&mut storage) = addr.into(),
+        }
+        storage
     }
+}
 
-    #[cfg(target_os = "windows")]
-    fn from(item: Ipv4Addr) -> Self {
-        in_addr {
-            S_un: in_addr__bindgen_ty_1 { S_addr: std::os::raw::c_ulong::to_be(item.into()) },
+impl From<in_addr> for u32 {
+    fn from(val: in_addr) -> Self {
+        #[cfg(target_os = "windows")]
+        // SAFETY: This is safe because we are accessing a union field and
+        // all fields in the union have the same size.
+        unsafe {
+            val.S_un.S_addr
         }
+
+        #[cfg(any(target_os = "macos", target_os = "linux"))]
+        val.s_addr
     }
 }
 
-impl From<Ipv6Addr> for in6_addr {
-    #[cfg(target_os = "macos")]
-    fn from(item: Ipv6Addr) -> Self {
-        in6_addr { __u6_addr: in6_addr__bindgen_ty_1 { __u6_addr8: item.octets() } }
+mod net {
+    /// Converts a value from host byte order to network byte order.
+    #[inline]
+    pub fn htonl(hostlong: u32) -> u32 {
+        hostlong.to_be()
     }
 
-    #[cfg(target_os = "linux")]
-    fn from(item: Ipv6Addr) -> Self {
-        in6_addr { __in6_u: in6_addr__bindgen_ty_1 { __u6_addr8: item.octets() } }
+    /// Converts a value from network byte order to host byte order.
+    #[inline]
+    pub fn ntohl(netlong: u32) -> u32 {
+        u32::from_be(netlong)
+    }
+
+    /// Converts a value from host byte order to network byte order.
+    #[inline]
+    pub fn htons(hostshort: u16) -> u16 {
+        hostshort.to_be()
+    }
+
+    /// Converts a value from network byte order to host byte order.
+    #[inline]
+    pub fn ntohs(netshort: u16) -> u16 {
+        u16::from_be(netshort)
+    }
+}
+
+impl From<Ipv4Addr> for in_addr {
+    fn from(item: Ipv4Addr) -> Self {
+        #[cfg(target_os = "windows")]
+        return in_addr {
+            S_un: in_addr__bindgen_ty_1 { S_addr: std::os::raw::c_ulong::to_be(item.into()) },
+        };
+
+        #[cfg(any(target_os = "macos", target_os = "linux"))]
+        return in_addr { s_addr: net::htonl(item.into()) };
+    }
+}
+
+impl From<in6_addr> for Ipv6Addr {
+    fn from(item: in6_addr) -> Self {
+        // SAFETY: Access union field. This is safe because we are
+        // accessing the underlying byte array representation of the
+        // `in6_addr` struct on macOS and all variants have the same
+        // size.
+        #[cfg(target_os = "macos")]
+        return Ipv6Addr::from(unsafe { item.__u6_addr.__u6_addr8 });
+
+        // SAFETY: Access union field. This is safe because we are
+        // accessing the underlying byte array representation of the
+        // `in6_addr` struct on Linux and all variants have the same
+        // size.
+        #[cfg(target_os = "linux")]
+        return Ipv6Addr::from(unsafe { item.__in6_u.__u6_addr8 });
+
+        // SAFETY: Access union field. This is safe because we are
+        // accessing the underlying byte array representation of the
+        // `in6_addr` struct on Windows and all variants have the same
+        // size.
+        #[cfg(target_os = "windows")]
+        return Ipv6Addr::from(unsafe { item.u.Byte });
     }
+}
 
-    #[cfg(target_os = "windows")]
+impl From<Ipv6Addr> for in6_addr {
     fn from(item: Ipv6Addr) -> Self {
-        in6_addr { u: in6_addr__bindgen_ty_1 { Byte: item.octets() } }
+        #[cfg(target_os = "macos")]
+        return in6_addr { __u6_addr: in6_addr__bindgen_ty_1 { __u6_addr8: item.octets() } };
+
+        #[cfg(target_os = "linux")]
+        return in6_addr { __in6_u: in6_addr__bindgen_ty_1 { __u6_addr8: item.octets() } };
+
+        #[cfg(target_os = "windows")]
+        return in6_addr { u: in6_addr__bindgen_ty_1 { Byte: item.octets() } };
     }
 }
 
 impl From<SocketAddrV4> for sockaddr_in {
-    #[cfg(target_os = "macos")]
     fn from(item: SocketAddrV4) -> Self {
-        sockaddr_in {
+        #[cfg(target_os = "macos")]
+        return sockaddr_in {
             sin_len: 16u8,
             sin_family: AF_INET as u8,
-            sin_port: item.port().to_be(),
+            sin_port: net::htons(item.port()),
             sin_addr: (*item.ip()).into(),
             sin_zero: [0; 8],
-        }
-    }
-    #[cfg(target_os = "linux")]
-    fn from(item: SocketAddrV4) -> Self {
-        sockaddr_in {
+        };
+
+        #[cfg(any(target_os = "linux", target_os = "windows"))]
+        return sockaddr_in {
             sin_family: AF_INET as u16,
-            sin_port: item.port().to_be(),
+            sin_port: net::htons(item.port()),
             sin_addr: (*item.ip()).into(),
             sin_zero: [0; 8],
-        }
+        };
     }
-    #[cfg(target_os = "windows")]
-    fn from(item: SocketAddrV4) -> Self {
-        sockaddr_in {
-            sin_family: AF_INET as u16,
-            sin_port: item.port().to_be(),
-            sin_addr: (*item.ip()).into(),
-            sin_zero: [0; 8],
-        }
+}
+
+impl From<sockaddr_in> for SocketAddrV4 {
+    fn from(item: sockaddr_in) -> Self {
+        SocketAddrV4::new(
+            Ipv4Addr::from(net::ntohl(item.sin_addr.into())),
+            net::ntohs(item.sin_port),
+        )
+    }
+}
+
+impl From<sockaddr_in6> for SocketAddrV6 {
+    fn from(item: sockaddr_in6) -> Self {
+        #[cfg(any(target_os = "linux", target_os = "macos"))]
+        return SocketAddrV6::new(
+            Ipv6Addr::from(item.sin6_addr),
+            net::ntohs(item.sin6_port),
+            net::ntohl(item.sin6_flowinfo),
+            item.sin6_scope_id,
+        );
+
+        #[cfg(target_os = "windows")]
+        return SocketAddrV6::new(
+            Ipv6Addr::from(item.sin6_addr),
+            net::ntohs(item.sin6_port),
+            net::ntohl(item.sin6_flowinfo),
+            // SAFETY: This is safe because we are accessing a union
+            // field where all fields have the same size.
+            unsafe { item.__bindgen_anon_1.sin6_scope_id },
+        );
     }
 }
 
 impl From<SocketAddrV6> for sockaddr_in6 {
-    #[cfg(target_os = "windows")]
     fn from(item: SocketAddrV6) -> Self {
-        sockaddr_in6 {
+        #[cfg(target_os = "windows")]
+        return sockaddr_in6 {
             sin6_addr: (*item.ip()).into(),
             sin6_family: AF_INET6 as u16,
-            sin6_port: item.port().to_be(),
-            sin6_flowinfo: item.flowinfo(),
+            sin6_port: net::htons(item.port()),
+            sin6_flowinfo: net::htonl(item.flowinfo()),
             __bindgen_anon_1: sockaddr_in6__bindgen_ty_1 { sin6_scope_id: item.scope_id() },
-        }
-    }
-    #[cfg(target_os = "macos")]
-    fn from(item: SocketAddrV6) -> Self {
-        sockaddr_in6 {
-            sin6_len: 16,
+        };
+
+        #[cfg(target_os = "macos")]
+        return sockaddr_in6 {
             sin6_addr: (*item.ip()).into(),
             sin6_family: AF_INET6 as u8,
-            sin6_port: item.port().to_be(),
-            sin6_flowinfo: item.flowinfo(),
+            sin6_port: net::htons(item.port()),
+            sin6_flowinfo: net::htonl(item.flowinfo()),
             sin6_scope_id: item.scope_id(),
-        }
-    }
-    #[cfg(target_os = "linux")]
-    fn from(item: SocketAddrV6) -> Self {
-        sockaddr_in6 {
+            sin6_len: 16,
+        };
+
+        #[cfg(target_os = "linux")]
+        return sockaddr_in6 {
             sin6_addr: (*item.ip()).into(),
             sin6_family: AF_INET6 as u16,
-            sin6_port: item.port().to_be(),
-            sin6_flowinfo: item.flowinfo(),
+            sin6_port: net::htons(item.port()),
+            sin6_flowinfo: net::htonl(item.flowinfo()),
             sin6_scope_id: item.scope_id(),
-        }
+        };
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::mem;
+
+    // This tests a bidirectional conversion between sockaddr_storage
+    // and SocketAddr
+    #[test]
+    fn test_sockaddr_storage() {
+        let sockaddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
+        let storage: sockaddr_storage = sockaddr.into();
+
+        let sockaddr_from_storage: SocketAddr = storage.into();
+
+        assert_eq!(sockaddr, sockaddr_from_storage);
+    }
+
+    #[test]
+    fn test_sockaddr_storage_v6() {
+        let sockaddr = SocketAddr::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into(), 8080);
+        let storage: sockaddr_storage = sockaddr.into();
+
+        let sockaddr_from_storage: SocketAddr = storage.into();
+
+        assert_eq!(sockaddr, sockaddr_from_storage);
+    }
+
+    #[test]
+    fn test_sockaddr_v6() {
+        let sockaddr = SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into(), 8080, 1, 2);
+        let in_v6: sockaddr_in6 = sockaddr.into();
+
+        // Pointer to the sockaddr_in6 ip address raw octets
+        // SAFETY: this is safe because `sin6_addr` is type `in6_addr.`
+        let in_v6_ip_octets = unsafe {
+            std::slice::from_raw_parts(
+                &in_v6.sin6_addr as *const _ as *const u8,
+                mem::size_of::<in6_addr>(),
+            )
+        };
+        // Host order port and flowinfo
+        let in_v6_port = net::ntohs(in_v6.sin6_port);
+        let in_v6_flowinfo = net::ntohl(in_v6.sin6_flowinfo);
+
+        // Compare ip, port, flowinfo after conversion from SocketAddrV6 -> sockaddr_in6
+        assert_eq!(sockaddr.port(), in_v6_port);
+        assert_eq!(sockaddr.ip().octets(), in_v6_ip_octets);
+        assert_eq!(sockaddr.flowinfo(), in_v6_flowinfo);
+
+        // Effectively compares ip, port, flowinfo after conversion
+        // from sockaddr_in6 -> SocketAddrV6
+        let sockaddr_from: SocketAddrV6 = in_v6.into();
+        assert_eq!(sockaddr, sockaddr_from);
+    }
+
+    #[test]
+    fn test_sockaddr_v4() {
+        let sockaddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
+        let in_v4: sockaddr_in = sockaddr.into();
+
+        // Pointer to the sockaddr_in ip address raw octets
+        // SAFETY: this is safe because `sin_addr` is type `in_addr.`
+        let in_v4_ip_octets = unsafe {
+            std::slice::from_raw_parts(
+                &in_v4.sin_addr as *const _ as *const u8,
+                mem::size_of::<in_addr>(),
+            )
+        };
+        // Host order port
+        let in_v4_port = net::ntohs(in_v4.sin_port);
+
+        // Compare ip and port after conversion from SocketAddrV4 -> sockaddr_in
+        assert_eq!(sockaddr.port(), in_v4_port);
+        assert_eq!(sockaddr.ip().octets(), in_v4_ip_octets);
+
+        // Effectively compares ip and port after conversion from
+        // sockaddr_in -> SocketAddrV4
+        let sockaddr_from: SocketAddrV4 = in_v4.into();
+        assert_eq!(sockaddr, sockaddr_from);
     }
 }
diff --git a/rust/libslirp-rs/src/libslirp_sys/windows/bindings.rs b/rust/libslirp-rs/src/libslirp_sys/windows/bindings.rs
index 3dba0a6c..7d7867e7 100644
--- a/rust/libslirp-rs/src/libslirp_sys/windows/bindings.rs
+++ b/rust/libslirp-rs/src/libslirp_sys/windows/bindings.rs
@@ -1,4 +1,4 @@
-/* automatically generated by rust-bindgen 0.69.4 */
+/* automatically generated by rust-bindgen 0.69.5 */
 
 #[repr(C)]
 #[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
@@ -286691,10 +286691,15 @@ pub struct SlirpCb {
             addr: *const sockaddr_storage,
             connect_func: SlirpProxyConnectFunc,
             connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
         ) -> bool,
     >,
-    pub remove:
-        ::std::option::Option<unsafe extern "C" fn(connect_opaque: *mut ::std::os::raw::c_void)>,
+    pub remove: ::std::option::Option<
+        unsafe extern "C" fn(
+            connect_opaque: *mut ::std::os::raw::c_void,
+            opaque: *mut ::std::os::raw::c_void,
+        ),
+    >,
 }
 #[test]
 fn bindgen_test_layout_SlirpCb() {
diff --git a/rust/libslirp-rs/tests/integration_test.rs b/rust/libslirp-rs/tests/integration_test.rs
index 0f78c442..449dc65a 100644
--- a/rust/libslirp-rs/tests/integration_test.rs
+++ b/rust/libslirp-rs/tests/integration_test.rs
@@ -15,7 +15,7 @@
 use bytes::Bytes;
 use libslirp_rs::libslirp::LibSlirp;
 use libslirp_rs::libslirp_config::SlirpConfig;
-use std::fs;
+
 use std::io;
 use std::sync::mpsc;
 use std::time::Duration;
@@ -28,7 +28,7 @@ fn it_shutdown() {
     let before_fd_count = count_open_fds().unwrap();
 
     let (tx, rx) = mpsc::channel::<Bytes>();
-    let slirp = LibSlirp::new(config, tx);
+    let slirp = LibSlirp::new(config, tx, None);
     slirp.shutdown();
     assert_eq!(
         rx.recv_timeout(Duration::from_millis(5)),
@@ -41,6 +41,7 @@ fn it_shutdown() {
 
 #[cfg(target_os = "linux")]
 fn count_open_fds() -> io::Result<usize> {
+    use std::fs;
     let entries = fs::read_dir("/proc/self/fd")?;
     Ok(entries.count())
 }
diff --git a/rust/libslirp-rs/tests/integration_udp.rs b/rust/libslirp-rs/tests/integration_udp.rs
new file mode 100644
index 00000000..b169771c
--- /dev/null
+++ b/rust/libslirp-rs/tests/integration_udp.rs
@@ -0,0 +1,162 @@
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
+use bytes::Bytes;
+use etherparse::EtherType;
+use etherparse::LinkHeader::Ethernet2;
+use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TransportHeader};
+use libslirp_rs::libslirp::LibSlirp;
+use libslirp_rs::libslirp_config::SlirpConfig;
+use std::fs;
+use std::io;
+use std::net::{SocketAddr, UdpSocket};
+use std::sync::mpsc;
+use std::thread;
+use std::time::Duration;
+
+const PAYLOAD: &[u8; 23] = b"Hello, UDP echo server!";
+const PAYLOAD_PONG: &[u8; 23] = b"Hello, UDP echo client!";
+
+/// Test UDP packets sent through libslirp
+#[cfg(not(windows))] // TOOD: remove once test is working on windows.
+#[test]
+fn udp_echo() {
+    let config = SlirpConfig { ..Default::default() };
+
+    let before_fd_count = count_open_fds().unwrap();
+
+    let (tx, rx) = mpsc::channel::<Bytes>();
+    let slirp = LibSlirp::new(config, tx, None);
+
+    // Start up an IPV4 UDP echo server
+    let server_addr = one_shot_udp_echo_server().unwrap();
+
+    println!("server addr {:?}", server_addr);
+    let server_ip = match server_addr {
+        SocketAddr::V4(addr) => addr.ip().to_owned(),
+        _ => panic!("Unsupported address type"),
+    };
+    // Source address
+    let source_ip = server_ip.clone();
+
+    // Source and destination ports
+    let source_port: u16 = 20000;
+    let destination_port = server_addr.port();
+
+    // Build the UDP packet
+    // with abitrary source and destination mac addrs
+    // We use server address 0.0.0.0 to avoid ARP packets
+    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
+        .ipv4(source_ip.octets(), server_ip.octets(), 20)
+        .udp(source_port, destination_port);
+
+    // Get some memory to store the result
+    let mut result = Vec::<u8>::with_capacity(builder.size(PAYLOAD.len()));
+
+    // Serialize header and payload
+    builder.write(&mut result, PAYLOAD).unwrap();
+
+    let headers = PacketHeaders::from_ethernet_slice(&result).unwrap();
+    if let Some(Ethernet2(ether_header)) = headers.link {
+        assert_eq!(ether_header.ether_type, EtherType::IPV4);
+    } else {
+        panic!("expected ethernet2 header");
+    }
+
+    assert!(headers.net.is_some());
+    assert!(headers.transport.is_some());
+
+    // Send to oneshot_udp_echo_server (via libslirp)
+    slirp.input(Bytes::from(result));
+
+    // Read from oneshot_udp_echo server (via libslirp)
+    // No ARP packets will be seen
+
+    // Try to receive a packet before end_time
+    match rx.recv_timeout(Duration::from_secs(2)) {
+        Ok(packet) => {
+            let headers = PacketHeaders::from_ethernet_slice(&packet).unwrap();
+
+            if let Some(Ethernet2(ref ether_header)) = headers.link {
+                assert_eq!(ether_header.ether_type, EtherType::IPV4);
+            } else {
+                panic!("expected ethernet2 header");
+            }
+
+            if let Some(NetHeaders::Ipv4(ipv4_header, _)) = headers.net {
+                assert_eq!(ipv4_header.source, [127, 0, 0, 1]);
+                assert_eq!(ipv4_header.destination, [0, 0, 0, 0]);
+            } else {
+                panic!("expected IpV4 header, got {:?}", headers.net);
+            }
+
+            if let Some(TransportHeader::Udp(udp_header)) = headers.transport {
+                assert_eq!(udp_header.source_port, destination_port);
+                assert_eq!(udp_header.destination_port, source_port);
+            } else {
+                panic!("expected Udp header");
+            }
+
+            if let PayloadSlice::Udp(payload) = headers.payload {
+                assert_eq!(payload, PAYLOAD_PONG);
+            } else {
+                panic!("expected Udp payload");
+            }
+        }
+        Err(mpsc::RecvTimeoutError::Timeout) => {
+            assert!(false, "Timeout waiting for udp packet");
+        }
+        Err(e) => {
+            panic!("Failed to receive data in main thread: {}", e);
+        }
+    }
+
+    // validate data packet
+
+    slirp.shutdown();
+    assert_eq!(
+        rx.recv_timeout(Duration::from_millis(5)),
+        Err(mpsc::RecvTimeoutError::Disconnected)
+    );
+
+    let after_fd_count = count_open_fds().unwrap();
+    assert_eq!(before_fd_count, after_fd_count);
+}
+
+fn one_shot_udp_echo_server() -> std::io::Result<SocketAddr> {
+    let socket = UdpSocket::bind("0.0.0.0:0")?;
+    let addr = socket.local_addr()?;
+    thread::spawn(move || {
+        let mut buf = [0u8; 1024];
+        let (len, addr) = socket.recv_from(&mut buf).unwrap();
+        let data = &buf[..len];
+        if data != PAYLOAD {
+            panic!("mistmatch payload");
+        }
+        println!("sending to addr {addr:?}");
+        let _ = socket.send_to(PAYLOAD_PONG, addr);
+    });
+    Ok(addr)
+}
+
+#[cfg(target_os = "linux")]
+fn count_open_fds() -> io::Result<usize> {
+    let entries = fs::read_dir("/proc/self/fd")?;
+    Ok(entries.count())
+}
+
+#[cfg(not(target_os = "linux"))]
+fn count_open_fds() -> io::Result<usize> {
+    Ok(0)
+}
diff --git a/rust/packets/Cargo.toml b/rust/packets/Cargo.toml
new file mode 100644
index 00000000..1d557d00
--- /dev/null
+++ b/rust/packets/Cargo.toml
@@ -0,0 +1,30 @@
+# Copyright 2024 The Android Open Source Project
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
+[package]
+name = "netsim-packets"
+version = "0.1.0"
+edition = "2021"
+build = "build.rs"
+
+[lib]
+path = "src/lib.rs"
+crate-type = ["staticlib","lib"]
+doctest = false
+
+[dependencies]
+anyhow = "1"
+bytes = { version = ">=1.4.0"}
+pdl-runtime = "0.3.0"
+
diff --git a/rust/packets/build.rs b/rust/packets/build.rs
new file mode 100644
index 00000000..1c2c3e7c
--- /dev/null
+++ b/rust/packets/build.rs
@@ -0,0 +1,47 @@
+//
+//  Copyright 2024 Google, Inc.
+//
+//  Licensed under the Apache License, Version 2.0 (the "License");
+//  you may not use this file except in compliance with the License.
+//  You may obtain a copy of the License at:
+//
+//  http://www.apache.org/licenses/LICENSE-2.0
+//
+//  Unless required by applicable law or agreed to in writing, software
+//  distributed under the License is distributed on an "AS IS" BASIS,
+//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+//  See the License for the specific language governing permissions and
+//  limitations under the License.
+
+use std::env;
+use std::path::PathBuf;
+
+fn main() {
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
+}
diff --git a/rust/daemon/src/wifi/packets/ieee80211.rs b/rust/packets/src/ieee80211.rs
similarity index 90%
rename from rust/daemon/src/wifi/packets/ieee80211.rs
rename to rust/packets/src/ieee80211.rs
index 35e1e385..5db8a255 100644
--- a/rust/daemon/src/wifi/packets/ieee80211.rs
+++ b/rust/packets/src/ieee80211.rs
@@ -20,7 +20,7 @@
 #![allow(unused)]
 include!(concat!(env!("OUT_DIR"), "/ieee80211_packets.rs"));
 
-use super::llc::{EtherType, LlcCtrl, LlcSap, LlcSnapHeader};
+use crate::llc::{EtherType, LlcCtrl, LlcSap, LlcSnapHeader};
 use anyhow::anyhow;
 
 const ETHERTYPE_LEN: usize = 2;
@@ -181,6 +181,11 @@ impl Ieee80211 {
         self.ftype == FrameType::Mgmt
     }
 
+    // Frame is (management) beacon frame
+    pub fn is_beacon(&self) -> bool {
+        self.ftype == FrameType::Mgmt && self.stype == (ManagementSubType::Beacon as u8)
+    }
+
     // Frame type is data
     pub fn is_data(&self) -> bool {
         self.ftype == FrameType::Data
@@ -250,6 +255,26 @@ impl Ieee80211 {
         }
     }
 
+    pub fn get_ssid_from_beacon_frame(&self) -> anyhow::Result<String> {
+        // Verify packet is a beacon frame
+        if !self.is_beacon() {
+            return Err(anyhow!("Frame is not beacon frame."));
+        };
+
+        // SSID field starts after the first 36 bytes. Ieee80211 payload starts after 4 bytes.
+        let pos = 36 - 4;
+
+        // Check for SSID element ID (0) and extract the SSID
+        let payload = &self.payload;
+        if payload[pos] == 0 {
+            let ssid_len = payload[pos + 1] as usize;
+            let ssid_bytes = &payload[pos + 2..pos + 2 + ssid_len];
+            return Ok(String::from_utf8(ssid_bytes.to_vec())?);
+        }
+
+        Err(anyhow!("SSID not found."))
+    }
+
     fn get_payload(&self) -> Vec<u8> {
         match self.specialize().unwrap() {
             Ieee80211Child::Ieee80211ToAp(hdr) => hdr.payload,
@@ -453,6 +478,28 @@ mod tests {
         assert_eq!(a, b);
     }
 
+    #[test]
+    fn test_beacon_frame() {
+        // Example from actual beacon frame from Hostapd with "AndroidWifi" SSID
+        let frame: Vec<u8> = vec![
+            0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x10, 0x85,
+            0xfe, 0x01, 0x00, 0x13, 0x10, 0x85, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x01, 0x04, 0x00, 0x0b, 0x41, 0x6e, 0x64, 0x72,
+            0x6f, 0x69, 0x64, 0x57, 0x69, 0x66, 0x69, 0x01, 0x04, 0x82, 0x84, 0x8b, 0x96, 0x03,
+            0x01, 0x08, 0x2a, 0x01, 0x07, 0x2d, 0x1a, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x16, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x7f, 0x04, 0x00, 0x00, 0x00, 0x02,
+        ];
+        let decoded_frame = Ieee80211::decode_full(&frame).unwrap();
+        assert!(decoded_frame.is_mgmt());
+        assert!(decoded_frame.is_beacon());
+        let ssid = decoded_frame.get_ssid_from_beacon_frame();
+        assert!(ssid.is_ok());
+        assert_eq!(ssid.unwrap(), "AndroidWifi");
+    }
+
     #[test]
     fn test_is_multicast() {
         // Multicast MAC address: 01:00:5E:00:00:FB
diff --git a/rust/daemon/src/wifi/packets/mod.rs b/rust/packets/src/lib.rs
similarity index 79%
rename from rust/daemon/src/wifi/packets/mod.rs
rename to rust/packets/src/lib.rs
index 0c07383c..9e9a43e2 100644
--- a/rust/daemon/src/wifi/packets/mod.rs
+++ b/rust/packets/src/lib.rs
@@ -12,9 +12,21 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! # netsim-packets Crate
+//!
+//! A collection of packet definitions for netsimd.
+
 pub mod ieee80211;
 pub mod llc;
 
+pub mod link_layer {
+    #![allow(clippy::all)]
+    #![allow(unused)]
+    #![allow(missing_docs)]
+
+    include!(concat!(env!("OUT_DIR"), "/link_layer_packets.rs"));
+}
+
 pub mod netlink {
     #![allow(clippy::all)]
     #![allow(unused)]
diff --git a/rust/daemon/src/wifi/packets/llc.rs b/rust/packets/src/llc.rs
similarity index 100%
rename from rust/daemon/src/wifi/packets/llc.rs
rename to rust/packets/src/llc.rs
diff --git a/rust/proto/src/frontend.rs b/rust/proto/src/frontend.rs
index b5cf0e9f..0e5bf79c 100644
--- a/rust/proto/src/frontend.rs
+++ b/rust/proto/src/frontend.rs
@@ -518,8 +518,10 @@ impl ::protobuf::reflect::ProtobufValue for DeleteChipRequest {
 // @@protoc_insertion_point(message:netsim.frontend.PatchDeviceRequest)
 pub struct PatchDeviceRequest {
     // message fields
+    // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.id)
+    pub id: ::std::option::Option<u32>,
     // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.device)
-    pub device: ::protobuf::MessageField<super::model::Device>,
+    pub device: ::protobuf::MessageField<patch_device_request::PatchDeviceFields>,
     // special fields
     // @@protoc_insertion_point(special_field:netsim.frontend.PatchDeviceRequest.special_fields)
     pub special_fields: ::protobuf::SpecialFields,
@@ -537,9 +539,14 @@ impl PatchDeviceRequest {
     }
 
     fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
-        let mut fields = ::std::vec::Vec::with_capacity(1);
+        let mut fields = ::std::vec::Vec::with_capacity(2);
         let mut oneofs = ::std::vec::Vec::with_capacity(0);
-        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::model::Device>(
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "id",
+            |m: &PatchDeviceRequest| { &m.id },
+            |m: &mut PatchDeviceRequest| { &mut m.id },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, patch_device_request::PatchDeviceFields>(
             "device",
             |m: &PatchDeviceRequest| { &m.device },
             |m: &mut PatchDeviceRequest| { &mut m.device },
@@ -562,6 +569,9 @@ impl ::protobuf::Message for PatchDeviceRequest {
     fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
         while let Some(tag) = is.read_raw_tag_or_eof()? {
             match tag {
+                8 => {
+                    self.id = ::std::option::Option::Some(is.read_uint32()?);
+                },
                 18 => {
                     ::protobuf::rt::read_singular_message_into_field(is, &mut self.device)?;
                 },
@@ -577,6 +587,9 @@ impl ::protobuf::Message for PatchDeviceRequest {
     #[allow(unused_variables)]
     fn compute_size(&self) -> u64 {
         let mut my_size = 0;
+        if let Some(v) = self.id {
+            my_size += ::protobuf::rt::uint32_size(1, v);
+        }
         if let Some(v) = self.device.as_ref() {
             let len = v.compute_size();
             my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
@@ -587,6 +600,9 @@ impl ::protobuf::Message for PatchDeviceRequest {
     }
 
     fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if let Some(v) = self.id {
+            os.write_uint32(1, v)?;
+        }
         if let Some(v) = self.device.as_ref() {
             ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
         }
@@ -607,12 +623,14 @@ impl ::protobuf::Message for PatchDeviceRequest {
     }
 
     fn clear(&mut self) {
+        self.id = ::std::option::Option::None;
         self.device.clear();
         self.special_fields.clear();
     }
 
     fn default_instance() -> &'static PatchDeviceRequest {
         static instance: PatchDeviceRequest = PatchDeviceRequest {
+            id: ::std::option::Option::None,
             device: ::protobuf::MessageField::none(),
             special_fields: ::protobuf::SpecialFields::new(),
         };
@@ -637,6 +655,206 @@ impl ::protobuf::reflect::ProtobufValue for PatchDeviceRequest {
     type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
 }
 
+/// Nested message and enums of message `PatchDeviceRequest`
+pub mod patch_device_request {
+    #[derive(PartialEq,Clone,Default,Debug)]
+    // @@protoc_insertion_point(message:netsim.frontend.PatchDeviceRequest.PatchDeviceFields)
+    pub struct PatchDeviceFields {
+        // message fields
+        // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.name)
+        pub name: ::std::option::Option<::std::string::String>,
+        // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.visible)
+        pub visible: ::std::option::Option<bool>,
+        // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.position)
+        pub position: ::protobuf::MessageField<super::super::model::Position>,
+        // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.orientation)
+        pub orientation: ::protobuf::MessageField<super::super::model::Orientation>,
+        // @@protoc_insertion_point(field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.chips)
+        pub chips: ::std::vec::Vec<super::super::model::Chip>,
+        // special fields
+        // @@protoc_insertion_point(special_field:netsim.frontend.PatchDeviceRequest.PatchDeviceFields.special_fields)
+        pub special_fields: ::protobuf::SpecialFields,
+    }
+
+    impl<'a> ::std::default::Default for &'a PatchDeviceFields {
+        fn default() -> &'a PatchDeviceFields {
+            <PatchDeviceFields as ::protobuf::Message>::default_instance()
+        }
+    }
+
+    impl PatchDeviceFields {
+        pub fn new() -> PatchDeviceFields {
+            ::std::default::Default::default()
+        }
+
+        pub(in super) fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+            let mut fields = ::std::vec::Vec::with_capacity(5);
+            let mut oneofs = ::std::vec::Vec::with_capacity(0);
+            fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+                "name",
+                |m: &PatchDeviceFields| { &m.name },
+                |m: &mut PatchDeviceFields| { &mut m.name },
+            ));
+            fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+                "visible",
+                |m: &PatchDeviceFields| { &m.visible },
+                |m: &mut PatchDeviceFields| { &mut m.visible },
+            ));
+            fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::super::model::Position>(
+                "position",
+                |m: &PatchDeviceFields| { &m.position },
+                |m: &mut PatchDeviceFields| { &mut m.position },
+            ));
+            fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::super::model::Orientation>(
+                "orientation",
+                |m: &PatchDeviceFields| { &m.orientation },
+                |m: &mut PatchDeviceFields| { &mut m.orientation },
+            ));
+            fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
+                "chips",
+                |m: &PatchDeviceFields| { &m.chips },
+                |m: &mut PatchDeviceFields| { &mut m.chips },
+            ));
+            ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<PatchDeviceFields>(
+                "PatchDeviceRequest.PatchDeviceFields",
+                fields,
+                oneofs,
+            )
+        }
+    }
+
+    impl ::protobuf::Message for PatchDeviceFields {
+        const NAME: &'static str = "PatchDeviceFields";
+
+        fn is_initialized(&self) -> bool {
+            true
+        }
+
+        fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+            while let Some(tag) = is.read_raw_tag_or_eof()? {
+                match tag {
+                    18 => {
+                        self.name = ::std::option::Option::Some(is.read_string()?);
+                    },
+                    24 => {
+                        self.visible = ::std::option::Option::Some(is.read_bool()?);
+                    },
+                    34 => {
+                        ::protobuf::rt::read_singular_message_into_field(is, &mut self.position)?;
+                    },
+                    42 => {
+                        ::protobuf::rt::read_singular_message_into_field(is, &mut self.orientation)?;
+                    },
+                    50 => {
+                        self.chips.push(is.read_message()?);
+                    },
+                    tag => {
+                        ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                    },
+                };
+            }
+            ::std::result::Result::Ok(())
+        }
+
+        // Compute sizes of nested messages
+        #[allow(unused_variables)]
+        fn compute_size(&self) -> u64 {
+            let mut my_size = 0;
+            if let Some(v) = self.name.as_ref() {
+                my_size += ::protobuf::rt::string_size(2, &v);
+            }
+            if let Some(v) = self.visible {
+                my_size += 1 + 1;
+            }
+            if let Some(v) = self.position.as_ref() {
+                let len = v.compute_size();
+                my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+            }
+            if let Some(v) = self.orientation.as_ref() {
+                let len = v.compute_size();
+                my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+            }
+            for value in &self.chips {
+                let len = value.compute_size();
+                my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+            };
+            my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+            self.special_fields.cached_size().set(my_size as u32);
+            my_size
+        }
+
+        fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+            if let Some(v) = self.name.as_ref() {
+                os.write_string(2, v)?;
+            }
+            if let Some(v) = self.visible {
+                os.write_bool(3, v)?;
+            }
+            if let Some(v) = self.position.as_ref() {
+                ::protobuf::rt::write_message_field_with_cached_size(4, v, os)?;
+            }
+            if let Some(v) = self.orientation.as_ref() {
+                ::protobuf::rt::write_message_field_with_cached_size(5, v, os)?;
+            }
+            for v in &self.chips {
+                ::protobuf::rt::write_message_field_with_cached_size(6, v, os)?;
+            };
+            os.write_unknown_fields(self.special_fields.unknown_fields())?;
+            ::std::result::Result::Ok(())
+        }
+
+        fn special_fields(&self) -> &::protobuf::SpecialFields {
+            &self.special_fields
+        }
+
+        fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+            &mut self.special_fields
+        }
+
+        fn new() -> PatchDeviceFields {
+            PatchDeviceFields::new()
+        }
+
+        fn clear(&mut self) {
+            self.name = ::std::option::Option::None;
+            self.visible = ::std::option::Option::None;
+            self.position.clear();
+            self.orientation.clear();
+            self.chips.clear();
+            self.special_fields.clear();
+        }
+
+        fn default_instance() -> &'static PatchDeviceFields {
+            static instance: PatchDeviceFields = PatchDeviceFields {
+                name: ::std::option::Option::None,
+                visible: ::std::option::Option::None,
+                position: ::protobuf::MessageField::none(),
+                orientation: ::protobuf::MessageField::none(),
+                chips: ::std::vec::Vec::new(),
+                special_fields: ::protobuf::SpecialFields::new(),
+            };
+            &instance
+        }
+    }
+
+    impl ::protobuf::MessageFull for PatchDeviceFields {
+        fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+            static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+            descriptor.get(|| super::file_descriptor().message_by_package_relative_name("PatchDeviceRequest.PatchDeviceFields").unwrap()).clone()
+        }
+    }
+
+    impl ::std::fmt::Display for PatchDeviceFields {
+        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+            ::protobuf::text_format::fmt(self, f)
+        }
+    }
+
+    impl ::protobuf::reflect::ProtobufValue for PatchDeviceFields {
+        type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+    }
+}
+
 #[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:netsim.frontend.ListDeviceResponse)
 pub struct ListDeviceResponse {
@@ -1822,38 +2040,47 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     (\x0b2\x1a.netsim.model.DeviceCreateR\x06device\"D\n\x14CreateDeviceResp\
     onse\x12,\n\x06device\x18\x01\x20\x01(\x0b2\x14.netsim.model.DeviceR\x06\
     device\"#\n\x11DeleteChipRequest\x12\x0e\n\x02id\x18\x02\x20\x01(\rR\x02\
-    id\"B\n\x12PatchDeviceRequest\x12,\n\x06device\x18\x02\x20\x01(\x0b2\x14\
-    .netsim.model.DeviceR\x06device\"\x85\x01\n\x12ListDeviceResponse\x12.\n\
-    \x07devices\x18\x01\x20\x03(\x0b2\x14.netsim.model.DeviceR\x07devices\
-    \x12?\n\rlast_modified\x18\x02\x20\x01(\x0b2\x1a.google.protobuf.Timesta\
-    mpR\x0clastModified\"p\n\x16SubscribeDeviceRequest\x12D\n\rlast_modified\
-    \x18\x01\x20\x01(\x0b2\x1a.google.protobuf.TimestampH\0R\x0clastModified\
-    \x88\x01\x01B\x10\n\x0e_last_modified\"\xbf\x01\n\x17SubscribeDeviceResp\
-    onse\x12W\n\x14list_device_response\x18\x01\x20\x01(\x0b2#.netsim.fronte\
-    nd.ListDeviceResponseH\0R\x12listDeviceResponse\x12?\n\x0eempty_response\
-    \x18\x02\x20\x01(\x0b2\x16.google.protobuf.EmptyH\0R\remptyResponseB\n\n\
-    \x08response\"\xa3\x01\n\x13PatchCaptureRequest\x12\x0e\n\x02id\x18\x01\
-    \x20\x01(\rR\x02id\x12G\n\x05patch\x18\x02\x20\x01(\x0b21.netsim.fronten\
-    d.PatchCaptureRequest.PatchCaptureR\x05patch\x1a3\n\x0cPatchCapture\x12\
-    \x19\n\x05state\x18\x01\x20\x01(\x08H\0R\x05state\x88\x01\x01B\x08\n\x06\
-    _state\"H\n\x13ListCaptureResponse\x121\n\x08captures\x18\x01\x20\x03(\
-    \x0b2\x15.netsim.model.CaptureR\x08captures\"#\n\x11GetCaptureRequest\
-    \x12\x0e\n\x02id\x18\x01\x20\x01(\rR\x02id\";\n\x12GetCaptureResponse\
-    \x12%\n\x0ecapture_stream\x18\x01\x20\x01(\x0cR\rcaptureStream2\xaa\x06\
-    \n\x0fFrontendService\x12F\n\nGetVersion\x12\x16.google.protobuf.Empty\
-    \x1a\x20.netsim.frontend.VersionResponse\x12[\n\x0cCreateDevice\x12$.net\
-    sim.frontend.CreateDeviceRequest\x1a%.netsim.frontend.CreateDeviceRespon\
-    se\x12H\n\nDeleteChip\x12\".netsim.frontend.DeleteChipRequest\x1a\x16.go\
-    ogle.protobuf.Empty\x12J\n\x0bPatchDevice\x12#.netsim.frontend.PatchDevi\
-    ceRequest\x1a\x16.google.protobuf.Empty\x127\n\x05Reset\x12\x16.google.p\
-    rotobuf.Empty\x1a\x16.google.protobuf.Empty\x12I\n\nListDevice\x12\x16.g\
-    oogle.protobuf.Empty\x1a#.netsim.frontend.ListDeviceResponse\x12d\n\x0fS\
-    ubscribeDevice\x12'.netsim.frontend.SubscribeDeviceRequest\x1a(.netsim.f\
-    rontend.SubscribeDeviceResponse\x12L\n\x0cPatchCapture\x12$.netsim.front\
-    end.PatchCaptureRequest\x1a\x16.google.protobuf.Empty\x12K\n\x0bListCapt\
-    ure\x12\x16.google.protobuf.Empty\x1a$.netsim.frontend.ListCaptureRespon\
-    se\x12W\n\nGetCapture\x12\".netsim.frontend.GetCaptureRequest\x1a#.netsi\
-    m.frontend.GetCaptureResponse0\x01b\x06proto3\
+    id\"\xa4\x03\n\x12PatchDeviceRequest\x12\x13\n\x02id\x18\x01\x20\x01(\rH\
+    \0R\x02id\x88\x01\x01\x12M\n\x06device\x18\x02\x20\x01(\x0b25.netsim.fro\
+    ntend.PatchDeviceRequest.PatchDeviceFieldsR\x06device\x1a\xa2\x02\n\x11P\
+    atchDeviceFields\x12\x17\n\x04name\x18\x02\x20\x01(\tH\0R\x04name\x88\
+    \x01\x01\x12\x1d\n\x07visible\x18\x03\x20\x01(\x08H\x01R\x07visible\x88\
+    \x01\x01\x127\n\x08position\x18\x04\x20\x01(\x0b2\x16.netsim.model.Posit\
+    ionH\x02R\x08position\x88\x01\x01\x12@\n\x0borientation\x18\x05\x20\x01(\
+    \x0b2\x19.netsim.model.OrientationH\x03R\x0borientation\x88\x01\x01\x12(\
+    \n\x05chips\x18\x06\x20\x03(\x0b2\x12.netsim.model.ChipR\x05chipsB\x07\n\
+    \x05_nameB\n\n\x08_visibleB\x0b\n\t_positionB\x0e\n\x0c_orientationB\x05\
+    \n\x03_id\"\x85\x01\n\x12ListDeviceResponse\x12.\n\x07devices\x18\x01\
+    \x20\x03(\x0b2\x14.netsim.model.DeviceR\x07devices\x12?\n\rlast_modified\
+    \x18\x02\x20\x01(\x0b2\x1a.google.protobuf.TimestampR\x0clastModified\"p\
+    \n\x16SubscribeDeviceRequest\x12D\n\rlast_modified\x18\x01\x20\x01(\x0b2\
+    \x1a.google.protobuf.TimestampH\0R\x0clastModified\x88\x01\x01B\x10\n\
+    \x0e_last_modified\"\xbf\x01\n\x17SubscribeDeviceResponse\x12W\n\x14list\
+    _device_response\x18\x01\x20\x01(\x0b2#.netsim.frontend.ListDeviceRespon\
+    seH\0R\x12listDeviceResponse\x12?\n\x0eempty_response\x18\x02\x20\x01(\
+    \x0b2\x16.google.protobuf.EmptyH\0R\remptyResponseB\n\n\x08response\"\
+    \xa3\x01\n\x13PatchCaptureRequest\x12\x0e\n\x02id\x18\x01\x20\x01(\rR\
+    \x02id\x12G\n\x05patch\x18\x02\x20\x01(\x0b21.netsim.frontend.PatchCaptu\
+    reRequest.PatchCaptureR\x05patch\x1a3\n\x0cPatchCapture\x12\x19\n\x05sta\
+    te\x18\x01\x20\x01(\x08H\0R\x05state\x88\x01\x01B\x08\n\x06_state\"H\n\
+    \x13ListCaptureResponse\x121\n\x08captures\x18\x01\x20\x03(\x0b2\x15.net\
+    sim.model.CaptureR\x08captures\"#\n\x11GetCaptureRequest\x12\x0e\n\x02id\
+    \x18\x01\x20\x01(\rR\x02id\";\n\x12GetCaptureResponse\x12%\n\x0ecapture_\
+    stream\x18\x01\x20\x01(\x0cR\rcaptureStream2\xaa\x06\n\x0fFrontendServic\
+    e\x12F\n\nGetVersion\x12\x16.google.protobuf.Empty\x1a\x20.netsim.fronte\
+    nd.VersionResponse\x12[\n\x0cCreateDevice\x12$.netsim.frontend.CreateDev\
+    iceRequest\x1a%.netsim.frontend.CreateDeviceResponse\x12H\n\nDeleteChip\
+    \x12\".netsim.frontend.DeleteChipRequest\x1a\x16.google.protobuf.Empty\
+    \x12J\n\x0bPatchDevice\x12#.netsim.frontend.PatchDeviceRequest\x1a\x16.g\
+    oogle.protobuf.Empty\x127\n\x05Reset\x12\x16.google.protobuf.Empty\x1a\
+    \x16.google.protobuf.Empty\x12I\n\nListDevice\x12\x16.google.protobuf.Em\
+    pty\x1a#.netsim.frontend.ListDeviceResponse\x12d\n\x0fSubscribeDevice\
+    \x12'.netsim.frontend.SubscribeDeviceRequest\x1a(.netsim.frontend.Subscr\
+    ibeDeviceResponse\x12L\n\x0cPatchCapture\x12$.netsim.frontend.PatchCaptu\
+    reRequest\x1a\x16.google.protobuf.Empty\x12K\n\x0bListCapture\x12\x16.go\
+    ogle.protobuf.Empty\x1a$.netsim.frontend.ListCaptureResponse\x12W\n\nGet\
+    Capture\x12\".netsim.frontend.GetCaptureRequest\x1a#.netsim.frontend.Get\
+    CaptureResponse0\x01b\x06proto3\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
@@ -1874,7 +2101,7 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             deps.push(::protobuf::well_known_types::empty::file_descriptor().clone());
             deps.push(::protobuf::well_known_types::timestamp::file_descriptor().clone());
             deps.push(super::model::file_descriptor().clone());
-            let mut messages = ::std::vec::Vec::with_capacity(13);
+            let mut messages = ::std::vec::Vec::with_capacity(14);
             messages.push(VersionResponse::generated_message_descriptor_data());
             messages.push(CreateDeviceRequest::generated_message_descriptor_data());
             messages.push(CreateDeviceResponse::generated_message_descriptor_data());
@@ -1887,6 +2114,7 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             messages.push(ListCaptureResponse::generated_message_descriptor_data());
             messages.push(GetCaptureRequest::generated_message_descriptor_data());
             messages.push(GetCaptureResponse::generated_message_descriptor_data());
+            messages.push(patch_device_request::PatchDeviceFields::generated_message_descriptor_data());
             messages.push(patch_capture_request::PatchCapture::generated_message_descriptor_data());
             let mut enums = ::std::vec::Vec::with_capacity(0);
             ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
diff --git a/scripts/cargo_clippy.sh b/scripts/cargo_clippy.sh
new file mode 100755
index 00000000..284600f6
--- /dev/null
+++ b/scripts/cargo_clippy.sh
@@ -0,0 +1,23 @@
+#!/bin/bash -eu
+
+# Get the directory of the script
+REPO=$(dirname "$0")/../../..
+
+# The possible values are "linux" and "darwin".
+OS=$(uname | tr '[:upper:]' '[:lower:]')
+
+OUT_PATH="$1"
+RUST_VERSION="$2"
+CLIPPY_FLAGS="$3"
+
+source $REPO/tools/netsim/scripts/cargo_env.sh $OUT_PATH
+
+pushd $REPO/tools/netsim/rust
+# Run the cargo command
+# TODO(360874898): prebuilt rust toolchain for darwin-aarch64 is supported from 1.77.1
+if [[ "$OS" == "darwin" && $(uname -m) == "arm64" ]]; then
+  cargo clippy -- $CLIPPY_FLAGS
+else
+  $REPO/prebuilts/rust/$OS-x86/$RUST_VERSION/bin/cargo clippy -- $CLIPPY_FLAGS
+fi
+popd
diff --git a/scripts/cargo_env.sh b/scripts/cargo_env.sh
new file mode 100755
index 00000000..5fc99d3b
--- /dev/null
+++ b/scripts/cargo_env.sh
@@ -0,0 +1,57 @@
+#!/bin/bash
+# Copyright 2024 The Android Open Source Project
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
+# This script sets up the necessary environment variables for Cargo builds.
+# It determines the OUT_PATH, sets up CARGO_HOME and library paths,
+# and defines paths to prebuilt packet files.
+
+# Usage: scripts/cargo_env.sh [OUT_PATH]
+#   OUT_PATH: Optional. The output directory for build artifacts.
+#             Defaults to "tools/netsim/objs" if not specified.
+
+# Set up necessary env vars for Cargo
+function setup_cargo_env {
+  # Get the directory of the script
+  local REPO=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../../..")
+
+  # Determine the OUT_PATH
+  local OUT_PATH="${1:-$REPO/tools/netsim/objs}"
+
+  # Get OS name (lowercase)
+  local OS=$(uname | tr '[:upper:]' '[:lower:]')
+
+  # Set environment variables
+  export CARGO_HOME=$OUT_PATH/rust/.cargo
+  export OBJS_PATH=$OUT_PATH
+  export GRPCIO_SYS_GRPC_INCLUDE_PATH=$REPO/external/grpc/include
+
+  # Paths to pdl generated packets files
+  local ROOTCANAL_PDL_PATH=$OUT_PATH/rootcanal/pdl_gen
+  export LINK_LAYER_PACKETS_PREBUILT=$ROOTCANAL_PDL_PATH/link_layer_packets.rs
+  local PDL_PATH=$OUT_PATH/pdl/pdl_gen
+  export MAC80211_HWSIM_PACKETS_PREBUILT=$PDL_PATH/mac80211_hwsim_packets.rs
+  export IEEE80211_PACKETS_PREBUILT=$PDL_PATH/ieee80211_packets.rs
+  export LLC_PACKETS_PREBUILT=$PDL_PATH/llc_packets.rs
+  export NETLINK_PACKETS_PREBUILT=$PDL_PATH/netlink_packets.rs
+
+  # Set library path based on OS
+  if [[ "$OS" == "darwin" ]]; then
+    export DYLD_FALLBACK_LIBRARY_PATH=$OUT_PATH/lib64
+  else
+    export LD_LIBRARY_PATH=$OUT_PATH/lib64
+  fi
+}
+
+setup_cargo_env "$1"
diff --git a/scripts/cargo_test.cmd b/scripts/cargo_test.cmd
index 314ec07e..4e0b98be 100644
--- a/scripts/cargo_test.cmd
+++ b/scripts/cargo_test.cmd
@@ -5,16 +5,29 @@ setlocal
 set REPO=%~dp0\..\..\..
 
 :: Get the Rust version, package, and objs path from arguments
-set RUST_VERSION=%1
-set RUST_PKG=%2
-set OUT_PATH=%3
+set RUST_PKG=%1
+set OUT_PATH=%2
+set RUST_VERSION=%3
+set OBJS_PATH=%OUT_PATH%
 
 :: Set environment variables
-set %PATH%=%PATH%;%OUT_PATH%\lib64
+set PATH=%PATH%;%OUT_PATH%\lib64
+set PATH=%PATH%;%REPO%\prebuilts\gcc\linux-x86\host\x86_64-w64-mingw32-4.8\x86_64-w64-mingw32\lib;%REPO%\prebuilts\gcc\linux-x86\host\x86_64-w64-mingw32-4.8\x86_64-w64-mingw32\bin
+set CORROSION_BUILD_DIR=%OUT_PATH%/rust
+set CARGO_BUILD_RUSTC=%REPO%/prebuilts/rust/windows-x86/%RUST_VERSION%/bin/rustc
+set RUSTC=%REPO%/prebuilts/rust/windows-x86/%RUST_VERSION%/bin/rustc
 set CARGO_HOME=%OUT_PATH%\rust\.cargo
+set RUSTFLAGS=-Cdefault-linker-libraries=yes
+set GRPCIO_SYS_GRPC_INCLUDE_PATH=%REPO%/external/grpc/include
 
-:: Build the package
-cmake --build %OUT_PATH% %RUST_PKG%
+:: Paths to pdl generated packets files
+set ROOTCANAL_PDL_PATH=%OUT_PATH%\rootcanal\pdl_gen
+set LINK_LAYER_PACKETS_PREBUILT=%ROOTCANAL_PDL_PATH%\link_layer_packets.rs
+set PDL_PATH=%OUT_PATH%\pdl\pdl_gen
+set MAC80211_HWSIM_PACKETS_PREBUILT=%PDL_PATH%\mac80211_hwsim_packets.rs
+set IEEE80211_PACKETS_PREBUILT=%PDL_PATH%\ieee80211_packets.rs
+set LLC_PACKETS_PREBUILT=%PDL_PATH%\llc_packets.rs
+set NETLINK_PACKETS_PREBUILT=%PDL_PATH%\netlink_packets.rs
 
 :: Run the cargo command
-cargo.exe test -vv --package %RUST_PKG% --manifest-path %REPO%\tools\netsim\rust\Cargo.toml
\ No newline at end of file
+%REPO%\prebuilts\rust\windows-x86\%RUST_VERSION%\bin\cargo.exe test -vv --target=x86_64-pc-windows-gnu --config target.x86_64-pc-windows-gnu.linker='%OUT_PATH%\toolchain\ld-emu.cmd' --package %RUST_PKG% --manifest-path %REPO%\tools\netsim\rust\Cargo.toml --release -- --nocapture
\ No newline at end of file
diff --git a/scripts/cargo_test.sh b/scripts/cargo_test.sh
index bf349b8f..6f32e4fd 100755
--- a/scripts/cargo_test.sh
+++ b/scripts/cargo_test.sh
@@ -17,29 +17,22 @@
 REPO=$(dirname "$0")/../../..
 
 # Get the Rust version, package, and objs path from arguments
-RUST_VERSION="$1"
-RUST_PKG="$2"
-OUT_PATH="$3"
+RUST_PKG="$1"
+OUT_PATH="$2"
+RUST_VERSION="$3"
 
 # The possible values are "linux" and "darwin".
 OS=$(uname | tr '[:upper:]' '[:lower:]')
 
-# Set environment variables
-export CARGO_HOME=$OUT_PATH/rust/.cargo
+source $REPO/tools/netsim/scripts/cargo_env.sh $OUT_PATH
 
 # Build the package
 ninja -C $OUT_PATH $RUST_PKG
 
-if [[ "$OS" == "darwin" ]]; then
-  export DYLD_FALLBACK_LIBRARY_PATH=$OUT_PATH/lib64
-else
-  export LD_LIBRARY_PATH=$OUT_PATH/lib64
-fi
-
 # Run the cargo command
 # TODO(360874898): prebuilt rust toolchain for darwin-aarch64 is supported from 1.77.1
 if [[ "$OS" == "darwin" && $(uname -m) == "arm64" ]]; then
-  cargo test -vv --package $RUST_PKG --manifest-path $REPO/tools/netsim/rust/Cargo.toml
+  cargo test -vv --package $RUST_PKG --manifest-path $REPO/tools/netsim/rust/Cargo.toml -- --nocapture
 else
-  $REPO/prebuilts/rust/$OS-x86/$RUST_VERSION/bin/cargo test -vv --package $RUST_PKG --manifest-path $REPO/tools/netsim/rust/Cargo.toml
-fi
\ No newline at end of file
+  $REPO/prebuilts/rust/$OS-x86/$RUST_VERSION/bin/cargo test -vv --package $RUST_PKG --manifest-path $REPO/tools/netsim/rust/Cargo.toml -- --nocapture
+fi
diff --git a/scripts/tasks/__init__.py b/scripts/tasks/__init__.py
index b6d0a74b..f3bc8d1b 100644
--- a/scripts/tasks/__init__.py
+++ b/scripts/tasks/__init__.py
@@ -15,6 +15,7 @@
 # limitations under the License.
 
 import logging
+import platform
 from typing import Mapping
 
 from tasks.compile_install_task import CompileInstallTask
@@ -64,6 +65,7 @@ def get_tasks(args, env) -> Mapping[str, Task]:
     for task_name in [
         "Configure",
         "CompileInstall",
+        "RunTest",
         "ZipArtifact",
         "InstallEmulator",
         "RunPyTest",
diff --git a/scripts/tasks/run_pytest_task.py b/scripts/tasks/run_pytest_task.py
index 06113ea1..b01301ef 100644
--- a/scripts/tasks/run_pytest_task.py
+++ b/scripts/tasks/run_pytest_task.py
@@ -118,5 +118,5 @@ class RunPytestManager:
     # TODO: Resolve Windows PyTest failure
     if platform.system() != "Windows":
       cmd.append("--failures_as_errors")
-    run(cmd, get_default_environment(AOSP_ROOT), "e2e_pytests")
+      run(cmd, get_default_environment(AOSP_ROOT), "e2e_pytests")
     return True
diff --git a/scripts/tasks/run_test_task.py b/scripts/tasks/run_test_task.py
index f5696097..bd0aba65 100644
--- a/scripts/tasks/run_test_task.py
+++ b/scripts/tasks/run_test_task.py
@@ -14,7 +14,6 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-import logging
 from pathlib import Path
 import platform
 
@@ -31,13 +30,49 @@ class RunTestTask(Task):
     self.env = env
 
   def do_run(self):
+    # TODO(b/379745416): Support clippy for Mac and Windows
+    if platform.system() == "Linux":
+      # Set Clippy flags
+      clippy_flags = [
+          "-A clippy::disallowed_names",
+          "-A clippy::type-complexity",
+          "-A clippy::unnecessary-wraps",
+          "-A clippy::unusual-byte-groupings",
+          "-A clippy::upper-case-acronyms",
+          "-W clippy::undocumented_unsafe_blocks",
+          "-W clippy::cognitive-complexity",
+      ]
+      # Run cargo clippy
+      run(
+          [
+              AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_clippy.sh",
+              str(self.out),
+              rust_version(),
+              " ".join(clippy_flags),
+          ],
+          self.env,
+          "clippy",
+      )
+
+    # Set script for cargo Test
     if platform.system() == "Windows":
       script = AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_test.cmd"
     else:
       script = AOSP_ROOT / "tools" / "netsim" / "scripts" / "cargo_test.sh"
 
     # Run cargo Test
-    for package in ["hostapd-rs", "libslirp-rs"]:
-      cmd = [script, rust_version(), package, str(self.out)]
+    for package in [
+        "hostapd-rs",
+        "libslirp-rs",
+        "http-proxy",
+        "netsim-common",
+        "netsim-daemon",
+        "netsim-packets",
+        "capture",
+    ]:
+      # TODO(b/379708365): Resolve netsim-daemon test for Mac & Windows
+      if package == "netsim-daemon" and platform.system() != "Linux":
+        continue
+      cmd = [script, package, str(self.out), rust_version()]
       run(cmd, self.env, f"{package}_unit_tests")
     return True
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 9dc0b37c..240d1f5e 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -57,21 +57,9 @@ if(TARGET Rust::Rustc)
   android_add_library(
     TARGET netsimd-lib
     LICENSE Apache-2.0
-    SRC ${ANDROID_QEMU2_TOP_DIR}/android-qemu2-glue/emulation/VirtioWifiForwarder.cpp
-        ${ANDROID_QEMU2_TOP_DIR}/android-qemu2-glue/emulation/WifiService.cpp
-        ${ANDROID_QEMU2_TOP_DIR}/android-qemu2-glue/netsim/libslirp_driver.cpp
-        ${binding_header}
+    SRC ${binding_header}
         ${binding_source}
         ${common_header}
-        backend/backend_packet_hub.h
-        backend/grpc_server.cc
-        backend/grpc_server.h
-        core/server.cc
-        core/server.h
-        frontend/frontend_client_stub.cc
-        frontend/frontend_client_stub.h
-        frontend/frontend_server.cc
-        frontend/frontend_server.h
         frontend/server_response_writable.h
         hci/async_manager.cc
         hci/bluetooth_facade.cc
@@ -80,9 +68,6 @@ if(TARGET Rust::Rustc)
         hci/hci_packet_transport.h
         hci/rust_device.cc
         hci/rust_device.h
-        wifi/wifi_facade.cc
-        wifi/wifi_facade.h
-        wifi/wifi_packet_hub.h
     DEPS grpc++ libbt-rootcanal netsimd-proto-lib packet-streamer-proto-lib
          protobuf::libprotobuf util-lib)
 
@@ -93,13 +78,9 @@ if(TARGET Rust::Rustc)
   # Update to protobuf 26.x introduces some warnings.
   target_compile_options(netsimd-lib PRIVATE -Wno-unused-result)
 
-  target_include_directories(
-    netsimd-lib PRIVATE . ${PROTOBUF_INCLUDE_DIR}
-                        ${ANDROID_QEMU2_TOP_DIR}/include ${ANDROID_AUTOGEN}
-    PUBLIC ${cxx_bridge_binary_folder} ${ANDROID_QEMU2_TOP_DIR})
-  target_compile_definitions(netsimd-lib PUBLIC NETSIM_ANDROID_EMULATOR
-                                                -DNETSIM_WIFI)
+  target_include_directories(netsimd-lib PRIVATE . ${PROTOBUF_INCLUDE_DIR}
+                             PUBLIC ${cxx_bridge_binary_folder})
+  target_compile_definitions(netsimd-lib PUBLIC NETSIM_ANDROID_EMULATOR)
   # Make sure we have the cxx files generated before we build them.
   add_dependencies(netsimd-lib cargo-build_netsim-daemon)
-  android_target_compile_definitions(netsimd-lib windows PRIVATE "-DIOV_MAX=1")
 endif()
diff --git a/src/backend/backend_packet_hub.h b/src/backend/backend_packet_hub.h
deleted file mode 100644
index 56374843..00000000
--- a/src/backend/backend_packet_hub.h
+++ /dev/null
@@ -1,41 +0,0 @@
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
-#pragma once
-
-// Use gRPC HCI PacketType definitions so we don't expose Rootcanal's version
-// outside of the Bluetooth Facade.
-#include <cstdint>
-
-#include "netsim/common.pb.h"
-#include "netsim/hci_packet.pb.h"
-#include "rust/cxx.h"
-
-namespace netsim {
-namespace backend {
-
-using netsim::common::ChipKind;
-
-/* Handle packet responses for the backend. */
-
-void HandleResponse(uint32_t chip_id, const std::vector<uint8_t> &packet,
-                    /* optional */ packet::HCIPacket_PacketType packet_type);
-
-void HandleResponseCxx(uint32_t chip_id, const rust::Vec<rust::u8> &packet,
-                       /* optional */ uint8_t packet_type);
-
-}  // namespace backend
-}  // namespace netsim
diff --git a/src/backend/grpc_server.cc b/src/backend/grpc_server.cc
deleted file mode 100644
index 5b1362c3..00000000
--- a/src/backend/grpc_server.cc
+++ /dev/null
@@ -1,246 +0,0 @@
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
-#include "backend/grpc_server.h"
-
-#include <google/protobuf/util/json_util.h>
-#include <stdlib.h>
-
-#include <cstdint>
-#include <memory>
-#include <mutex>
-#include <string>
-#include <unordered_map>
-
-#include "google/protobuf/empty.pb.h"
-#include "grpcpp/server_context.h"
-#include "grpcpp/support/status.h"
-#include "netsim-daemon/src/ffi.rs.h"
-#include "netsim/common.pb.h"
-#include "netsim/packet_streamer.grpc.pb.h"
-#include "netsim/packet_streamer.pb.h"
-#include "util/log.h"
-
-namespace netsim {
-namespace backend {
-namespace {
-
-using netsim::common::ChipKind;
-
-using Stream =
-    ::grpc::ServerReaderWriter<packet::PacketResponse, packet::PacketRequest>;
-
-using netsim::startup::Chip;
-
-// Mapping from chip_id to streams.
-std::unordered_map<uint32_t, Stream *> chip_id_to_stream;
-
-// Libslirp is not thread safe. Use a lock to prevent concurrent access to
-// libslirp.
-std::mutex gSlirpMutex;
-
-// Service handles the gRPC StreamPackets requests.
-
-class ServiceImpl final : public packet::PacketStreamer::Service {
- public:
-  ::grpc::Status StreamPackets(::grpc::ServerContext *context,
-                               Stream *stream) override {
-    // Now connected to a peer issuing a bi-directional streaming grpc
-    auto peer = context->peer();
-    BtsLogInfo("grpc_server new packet_stream for peer %s", peer.c_str());
-
-    packet::PacketRequest request;
-
-    // First packet must have initial_info describing the peer
-    bool success = stream->Read(&request);
-    if (!success || !request.has_initial_info()) {
-      BtsLogError("ServiceImpl no initial information or stream closed");
-      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
-                            "Missing initial_info in first packet.");
-    }
-
-    auto device_name = request.initial_info().name();
-    auto chip_kind = request.initial_info().chip().kind();
-    // multiple chips of the same chip_kind for a device have a name
-    auto chip_name = request.initial_info().chip().id();
-    auto manufacturer = request.initial_info().chip().manufacturer();
-    auto product_name = request.initial_info().chip().product_name();
-    auto chip_address = request.initial_info().chip().address();
-    auto bt_properties = request.initial_info().chip().bt_properties();
-    // Add a new chip to the device
-    std::string chip_kind_string;
-    switch (chip_kind) {
-      case common::ChipKind::BLUETOOTH:
-        chip_kind_string = "BLUETOOTH";
-        break;
-      case common::ChipKind::WIFI:
-        chip_kind_string = "WIFI";
-        break;
-      case common::ChipKind::UWB:
-        chip_kind_string = "UWB";
-        break;
-      default:
-        chip_kind_string = "UNSPECIFIED";
-        break;
-    }
-
-    std::vector<unsigned char> message_vec(bt_properties.ByteSizeLong());
-    if (!bt_properties.SerializeToArray(message_vec.data(),
-                                        message_vec.size())) {
-      BtsLogError("Failed to serialize bt_properties to bytes");
-    }
-    auto device_info = request.initial_info().device_info();
-    auto kind = device_info.kind();
-    auto version = device_info.version();
-    auto sdk_version = device_info.sdk_version();
-    auto build_id = device_info.build_id();
-    auto variant = device_info.variant();
-    auto arch = device_info.arch();
-    auto result = netsim::device::AddChipCxx(
-        peer, device_name, chip_kind_string, chip_address, chip_name,
-        manufacturer, product_name, message_vec, kind, version, sdk_version,
-        build_id, variant, arch);
-    if (result->IsError()) {
-      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
-                            "AddChipCxx failed to add chip into netsim");
-    }
-    uint32_t device_id = result->GetDeviceId();
-    uint32_t chip_id = result->GetChipId();
-
-    BtsLogInfo(
-        "grpc_server: adding chip - chip_id: %d, "
-        "device_name: "
-        "%s",
-        chip_id, device_name.c_str());
-    // connect packet responses from chip facade to the peer
-    chip_id_to_stream[chip_id] = stream;
-    netsim::transport::RegisterGrpcTransport(chip_id);
-    this->ProcessRequests(stream, chip_id, chip_kind);
-
-    // no longer able to send responses to peer
-    netsim::transport::UnregisterGrpcTransport(chip_id);
-    chip_id_to_stream.erase(chip_id);
-
-    // Remove the chip from the device
-    netsim::device::RemoveChipCxx(device_id, chip_id);
-
-    BtsLogInfo(
-        "grpc_server: removing chip - chip_id: %d, "
-        "device_name: "
-        "%s",
-        chip_id, device_name.c_str());
-
-    return ::grpc::Status::OK;
-  }
-
-  // Convert a protobuf bytes field into shared_ptr<<vec<uint8_t>>.
-  //
-  // Release ownership of the bytes field and convert it to a vector using move
-  // iterators. No copy when called with a mutable reference.
-  std::shared_ptr<std::vector<uint8_t>> ToSharedVec(std::string *bytes_field) {
-    return std::make_shared<std::vector<uint8_t>>(
-        std::make_move_iterator(bytes_field->begin()),
-        std::make_move_iterator(bytes_field->end()));
-  }
-
-  // Process requests in a loop forwarding packets to the packet_hub and
-  // returning when the channel is closed.
-  void ProcessRequests(Stream *stream, uint32_t chip_id,
-                       common::ChipKind chip_kind) {
-    packet::PacketRequest request;
-    while (true) {
-      if (!stream->Read(&request)) {
-        BtsLogWarn("grpc_server: reading stopped - chip_id: %d", chip_id);
-        break;
-      }
-      // All kinds possible (bt, uwb, wifi), but each rpc only streames one.
-      if (chip_kind == common::ChipKind::BLUETOOTH) {
-        if (!request.has_hci_packet()) {
-          BtsLogWarn("grpc_server: unknown packet type from chip_id: %d",
-                     chip_id);
-          continue;
-        }
-        auto packet_type = request.hci_packet().packet_type();
-        auto packet =
-            ToSharedVec(request.mutable_hci_packet()->mutable_packet());
-        wireless::HandleRequestCxx(chip_id, *packet, packet_type);
-      } else if (chip_kind == common::ChipKind::WIFI) {
-        if (!request.has_packet()) {
-          BtsLogWarn("grpc_server: unknown packet type from chip_id: %d",
-                     chip_id);
-          continue;
-        }
-        auto packet = ToSharedVec(request.mutable_packet());
-        {
-          std::lock_guard<std::mutex> guard(gSlirpMutex);
-          wireless::HandleRequestCxx(chip_id, *packet,
-                                     packet::HCIPacket::HCI_PACKET_UNSPECIFIED);
-        }
-      } else if (chip_kind == common::ChipKind::UWB) {
-        if (!request.has_packet()) {
-          BtsLogWarn("grpc_server: unknown packet from chip_id: %d", chip_id);
-          continue;
-        }
-        auto packet = ToSharedVec(request.mutable_packet());
-        wireless::HandleRequestCxx(chip_id, *packet,
-                                   packet::HCIPacket::HCI_PACKET_UNSPECIFIED);
-
-      } else {
-        BtsLogWarn("grpc_server: unknown chip_kind");
-      }
-    }
-  }
-};
-}  // namespace
-
-// handle_response is called by packet_hub to forward a response to the gRPC
-// stream associated with chip_id.
-//
-// When writing, the packet is copied because is borrowed from a shared_ptr and
-// grpc++ doesn't know about smart pointers.
-void HandleResponse(uint32_t chip_id, const std::vector<uint8_t> &packet,
-                    packet::HCIPacket_PacketType packet_type) {
-  auto stream = chip_id_to_stream[chip_id];
-  if (stream) {
-    // TODO: lock or caller here because gRPC does not allow overlapping writes.
-    packet::PacketResponse response;
-    // Copies the borrowed packet for output
-    auto str_packet = std::string(packet.begin(), packet.end());
-    if (packet_type != packet::HCIPacket_PacketType_HCI_PACKET_UNSPECIFIED) {
-      response.mutable_hci_packet()->set_packet_type(packet_type);
-      response.mutable_hci_packet()->set_packet(str_packet);
-    } else {
-      response.set_packet(str_packet);
-    }
-    if (!stream->Write(response)) {
-      BtsLogWarn("grpc_server: write failed for chip_id: %d", chip_id);
-    }
-  } else {
-    BtsLogWarn("grpc_server: no stream for chip_id: %d", chip_id);
-  }
-}
-
-// for cxx
-void HandleResponseCxx(uint32_t chip_id, const rust::Vec<rust::u8> &packet,
-                       /* optional */ uint8_t packet_type) {
-  std::vector<uint8_t> vec(packet.begin(), packet.end());
-  HandleResponse(chip_id, vec, packet::HCIPacket_PacketType(packet_type));
-}
-
-}  // namespace backend
-
-std::unique_ptr<packet::PacketStreamer::Service> GetBackendService() {
-  return std::make_unique<backend::ServiceImpl>();
-}
-}  // namespace netsim
diff --git a/src/backend/grpc_server.h b/src/backend/grpc_server.h
deleted file mode 100644
index dd3d4e82..00000000
--- a/src/backend/grpc_server.h
+++ /dev/null
@@ -1,31 +0,0 @@
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
-// Grpc C++ Server implementation of PacketStreamer.
-//
-// Moves packets between Chip and Host with the help of a manager.
-
-#pragma once
-
-#include <memory>
-#include <utility>
-
-#include "netsim/packet_streamer.grpc.pb.h"
-
-namespace netsim {
-std::unique_ptr<packet::PacketStreamer::Service> GetBackendService();
-
-}  // namespace netsim
diff --git a/src/core/server.cc b/src/core/server.cc
deleted file mode 100644
index 8dadb39b..00000000
--- a/src/core/server.cc
+++ /dev/null
@@ -1,88 +0,0 @@
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
-#include "core/server.h"
-
-#include <chrono>
-#include <memory>
-#include <string>
-#include <utility>
-
-#include "backend/grpc_server.h"
-#include "frontend/frontend_server.h"
-#include "grpcpp/security/server_credentials.h"
-#include "grpcpp/server.h"
-#include "grpcpp/server_builder.h"
-#include "netsim-daemon/src/ffi.rs.h"
-#include "util/log.h"
-#ifdef _WIN32
-#include <Windows.h>
-#else
-#include <unistd.h>
-#endif
-#ifndef NETSIM_ANDROID_EMULATOR
-#include <sys/socket.h>
-
-// Needs to be below sys/socket.h
-#include <linux/vm_sockets.h>
-#endif
-namespace netsim::server {
-
-namespace {
-constexpr std::chrono::seconds InactivityCheckInterval(5);
-
-std::pair<std::unique_ptr<grpc::Server>, uint32_t> RunGrpcServer(
-    int netsim_grpc_port, bool no_cli_ui, int vsock) {
-  grpc::ServerBuilder builder;
-  int selected_port;
-  builder.AddListeningPort("0.0.0.0:" + std::to_string(netsim_grpc_port),
-                           grpc::InsecureServerCredentials(), &selected_port);
-  if (!no_cli_ui) {
-    static auto frontend_service = GetFrontendService();
-    builder.RegisterService(frontend_service.release());
-  }
-
-#ifndef NETSIM_ANDROID_EMULATOR
-  if (vsock != 0) {
-    std::string vsock_uri =
-        "vsock:" + std::to_string(VMADDR_CID_ANY) + ":" + std::to_string(vsock);
-    BtsLogInfo("vsock_uri: %s", vsock_uri.c_str());
-    builder.AddListeningPort(vsock_uri, grpc::InsecureServerCredentials());
-  }
-#endif
-
-  static auto backend_service = GetBackendService();
-  builder.RegisterService(backend_service.release());
-  builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
-  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
-  if (server == nullptr) {
-    return std::make_pair(nullptr, static_cast<uint32_t>(selected_port));
-  }
-
-  BtsLogInfo("Grpc server listening on localhost: %s",
-             std::to_string(selected_port).c_str());
-
-  return std::make_pair(std::move(server),
-                        static_cast<uint32_t>(selected_port));
-}
-}  // namespace
-
-std::unique_ptr<GrpcServer> RunGrpcServerCxx(uint32_t netsim_grpc_port,
-                                             bool no_cli_ui, uint16_t vsock) {
-  auto [grpc_server, port] = RunGrpcServer(netsim_grpc_port, no_cli_ui, vsock);
-  if (grpc_server == nullptr) return nullptr;
-  return std::make_unique<GrpcServer>(std::move(grpc_server), port);
-}
-
-}  // namespace netsim::server
diff --git a/src/core/server.h b/src/core/server.h
deleted file mode 100644
index 95f741bf..00000000
--- a/src/core/server.h
+++ /dev/null
@@ -1,43 +0,0 @@
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
-#pragma once
-
-#include <cstdint>
-#include <memory>
-
-#include "grpcpp/server.h"
-
-namespace netsim::server {
-
-class GrpcServer {
- public:
-  GrpcServer(std::unique_ptr<grpc::Server> server, std::uint32_t port)
-      : server(std::move(server)), port(port) {}
-
-  void Shutdown() const { server->Shutdown(); }
-  uint32_t GetGrpcPort() const { return port; };
-
- private:
-  std::unique_ptr<grpc::Server> server;
-  std::uint32_t port;
-};
-
-// Run grpc server.
-std::unique_ptr<GrpcServer> RunGrpcServerCxx(uint32_t netsim_grpc_port,
-                                             bool no_cli_ui, uint16_t vsock);
-
-}  // namespace netsim::server
diff --git a/src/frontend/frontend_client_stub.cc b/src/frontend/frontend_client_stub.cc
deleted file mode 100644
index 2dcd6df7..00000000
--- a/src/frontend/frontend_client_stub.cc
+++ /dev/null
@@ -1,57 +0,0 @@
-// Copyright 2023 The Android Open Source Project
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
-// Frontend client for netsimd.
-
-#include "frontend/frontend_client_stub.h"
-
-#include <chrono>
-#include <memory>
-
-#include "grpcpp/create_channel.h"
-#include "grpcpp/security/credentials.h"
-#include "netsim/frontend.grpc.pb.h"
-#include "netsim/frontend.pb.h"
-#include "util/os_utils.h"
-
-namespace netsim {
-namespace frontend {
-namespace {
-const std::chrono::duration kConnectionDeadline = std::chrono::seconds(1);
-
-std::unique_ptr<frontend::FrontendService::Stub> NewFrontendClient(
-    uint16_t instance_num) {
-  auto port = netsim::osutils::GetServerAddress(instance_num);
-  if (!port.has_value()) {
-    return nullptr;
-  }
-  auto server = "localhost:" + port.value();
-  std::shared_ptr<grpc::Channel> channel =
-      grpc::CreateChannel(server, grpc::InsecureChannelCredentials());
-
-  auto deadline = std::chrono::system_clock::now() + kConnectionDeadline;
-  if (!channel->WaitForConnected(deadline)) {
-    return nullptr;
-  }
-
-  return frontend::FrontendService::NewStub(channel);
-}
-}  // namespace
-
-bool IsNetsimdAlive(uint16_t instance_num) {
-  return NewFrontendClient(instance_num) != nullptr;
-}
-
-}  // namespace frontend
-}  // namespace netsim
diff --git a/src/frontend/frontend_client_stub.h b/src/frontend/frontend_client_stub.h
deleted file mode 100644
index 157c12bf..00000000
--- a/src/frontend/frontend_client_stub.h
+++ /dev/null
@@ -1,31 +0,0 @@
-/*
- * Copyright 2023 The Android Open Source Project
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
-// Frontend client for netsimd.
-#pragma once
-
-#include <memory>
-
-#include "netsim/frontend.grpc.pb.h"
-
-namespace netsim {
-namespace frontend {
-
-// Create a frontend grpc client to check if a netsimd is already running.
-bool IsNetsimdAlive(uint16_t instance_num);
-
-}  // namespace frontend
-}  // namespace netsim
diff --git a/src/frontend/frontend_server.cc b/src/frontend/frontend_server.cc
deleted file mode 100644
index 616a2148..00000000
--- a/src/frontend/frontend_server.cc
+++ /dev/null
@@ -1,200 +0,0 @@
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
-#include "frontend/frontend_server.h"
-
-#include <google/protobuf/util/json_util.h>
-
-#include <iostream>
-#include <memory>
-#include <string>
-#include <utility>
-
-#include "google/protobuf/empty.pb.h"
-#include "grpcpp/server_context.h"
-#include "grpcpp/support/status.h"
-#include "netsim-daemon/src/ffi.rs.h"
-#include "netsim/frontend.grpc.pb.h"
-#include "netsim/frontend.pb.h"
-
-namespace netsim {
-namespace {
-
-/// The C++ implementation of the CxxServerResponseWriter interface. This is
-/// used by the gRPC server to invoke the Rust pcap handler and process a
-/// responses.
-class CxxServerResponseWritable : public frontend::CxxServerResponseWriter {
- public:
-  CxxServerResponseWritable()
-      : grpc_writer_(nullptr), err(""), is_ok(false), body(""), length(0) {};
-  CxxServerResponseWritable(
-      grpc::ServerWriter<netsim::frontend::GetCaptureResponse> *grpc_writer)
-      : grpc_writer_(grpc_writer), err(""), is_ok(false), body(""), length(0) {
-        };
-
-  void put_error(unsigned int error_code,
-                 const std::string &response) const override {
-    err = std::to_string(error_code) + ": " + response;
-    is_ok = false;
-  }
-
-  void put_ok_with_length(const std::string &mime_type,
-                          std::size_t length) const override {
-    this->length = length;
-    is_ok = true;
-  }
-
-  void put_chunk(rust::Slice<const uint8_t> chunk) const override {
-    netsim::frontend::GetCaptureResponse response;
-    response.set_capture_stream(std::string(chunk.begin(), chunk.end()));
-    is_ok = grpc_writer_->Write(response);
-  }
-
-  void put_ok(const std::string &mime_type,
-              const std::string &body) const override {
-    this->body = body;
-    is_ok = true;
-  }
-
-  mutable grpc::ServerWriter<netsim::frontend::GetCaptureResponse>
-      *grpc_writer_;
-  mutable std::string err;
-  mutable bool is_ok;
-  mutable std::string body;
-  mutable std::size_t length;
-};
-
-class FrontendServer final : public frontend::FrontendService::Service {
- public:
-  grpc::Status GetVersion(grpc::ServerContext *context,
-                          const google::protobuf::Empty *empty,
-                          frontend::VersionResponse *reply) {
-    reply->set_version(std::string(netsim::GetVersion()));
-    return grpc::Status::OK;
-  }
-
-  grpc::Status ListDevice(grpc::ServerContext *context,
-                          const google::protobuf::Empty *empty,
-                          frontend::ListDeviceResponse *reply) {
-    CxxServerResponseWritable writer;
-    HandleDeviceCxx(writer, "GET", "", "");
-    if (writer.is_ok) {
-      google::protobuf::util::JsonStringToMessage(writer.body, reply);
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status CreateDevice(grpc::ServerContext *context,
-                            const frontend::CreateDeviceRequest *request,
-                            frontend::CreateDeviceResponse *response) {
-    CxxServerResponseWritable writer;
-    std::string request_json;
-    google::protobuf::util::MessageToJsonString(*request, &request_json);
-    HandleDeviceCxx(writer, "POST", "", request_json);
-    if (writer.is_ok) {
-      google::protobuf::util::JsonStringToMessage(writer.body, response);
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status DeleteChip(grpc::ServerContext *context,
-                          const frontend::DeleteChipRequest *request,
-                          google::protobuf::Empty *response) {
-    CxxServerResponseWritable writer;
-    std::string request_json;
-    google::protobuf::util::MessageToJsonString(*request, &request_json);
-    HandleDeviceCxx(writer, "DELETE", "", request_json);
-    if (writer.is_ok) {
-      google::protobuf::util::JsonStringToMessage(writer.body, response);
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status PatchDevice(grpc::ServerContext *context,
-                           const frontend::PatchDeviceRequest *request,
-                           google::protobuf::Empty *response) {
-    CxxServerResponseWritable writer;
-    std::string request_json;
-    google::protobuf::util::MessageToJsonString(*request, &request_json);
-    auto device = request->device();
-    // device.id() starts from 1.
-    // If you don't populate the id, you must fill the name field.
-    if (device.id() == 0) {
-      HandleDeviceCxx(writer, "PATCH", "", request_json);
-    } else {
-      HandleDeviceCxx(writer, "PATCH", std::to_string(device.id()),
-                      request_json);
-    }
-    if (writer.is_ok) {
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status Reset(grpc::ServerContext *context,
-                     const google::protobuf::Empty *request,
-                     google::protobuf::Empty *empty) {
-    CxxServerResponseWritable writer;
-    HandleDeviceCxx(writer, "PUT", "", "");
-    if (writer.is_ok) {
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status ListCapture(grpc::ServerContext *context,
-                           const google::protobuf::Empty *empty,
-                           frontend::ListCaptureResponse *reply) {
-    CxxServerResponseWritable writer;
-    HandleCaptureCxx(writer, "GET", "", "");
-    if (writer.is_ok) {
-      google::protobuf::util::JsonStringToMessage(writer.body, reply);
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-
-  grpc::Status PatchCapture(grpc::ServerContext *context,
-                            const frontend::PatchCaptureRequest *request,
-                            google::protobuf::Empty *response) {
-    CxxServerResponseWritable writer;
-    HandleCaptureCxx(writer, "PATCH", std::to_string(request->id()),
-                     std::to_string(request->patch().state()));
-    if (writer.is_ok) {
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-  grpc::Status GetCapture(
-      grpc::ServerContext *context,
-      const netsim::frontend::GetCaptureRequest *request,
-      grpc::ServerWriter<netsim::frontend::GetCaptureResponse> *grpc_writer) {
-    CxxServerResponseWritable writer(grpc_writer);
-    HandleCaptureCxx(writer, "GET", std::to_string(request->id()), "");
-    if (writer.is_ok) {
-      return grpc::Status::OK;
-    }
-    return grpc::Status(grpc::StatusCode::UNKNOWN, writer.err);
-  }
-};
-}  // namespace
-
-std::unique_ptr<frontend::FrontendService::Service> GetFrontendService() {
-  return std::make_unique<FrontendServer>();
-}
-
-}  // namespace netsim
diff --git a/src/frontend/frontend_server.h b/src/frontend/frontend_server.h
deleted file mode 100644
index b808d232..00000000
--- a/src/frontend/frontend_server.h
+++ /dev/null
@@ -1,30 +0,0 @@
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
-#pragma once
-// A synchronous Frontend server for the Network Simulator.
-
-#include <memory>
-#include <string>
-#include <utility>
-
-#include "netsim/frontend.grpc.pb.h"
-
-namespace netsim {
-
-std::unique_ptr<frontend::FrontendService::Service> GetFrontendService();
-
-}  // namespace netsim
diff --git a/src/wifi/wifi_facade.cc b/src/wifi/wifi_facade.cc
deleted file mode 100644
index 6e99580a..00000000
--- a/src/wifi/wifi_facade.cc
+++ /dev/null
@@ -1,146 +0,0 @@
-// Copyright 2023 The Android Open Source Project
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
-#include "wifi/wifi_facade.h"
-
-#include <memory>
-
-#include "netsim-daemon/src/ffi.rs.h"
-#include "netsim/config.pb.h"
-#include "rust/cxx.h"
-#include "util/log.h"
-#include "util/string_utils.h"
-#ifdef NETSIM_ANDROID_EMULATOR
-#include "android-qemu2-glue/emulation/VirtioWifiForwarder.h"
-#include "android-qemu2-glue/emulation/WifiService.h"
-#include "android-qemu2-glue/netsim/libslirp_driver.h"
-#endif
-
-namespace netsim::wifi {
-namespace {
-
-#ifdef NETSIM_ANDROID_EMULATOR
-std::shared_ptr<android::qemu2::WifiService> wifi_service;
-#endif
-;
-
-}  // namespace
-
-namespace facade {
-
-size_t HandleWifiCallback(const uint8_t *buf, size_t size) {
-  //  Broadcast the response to all WiFi chips.
-  std::vector<uint8_t> packet(buf, buf + size);
-  rust::Slice<const uint8_t> packet_slice(packet.data(), packet.size());
-  wifi::facade::HandleWiFiResponse(packet_slice);
-  return size;
-}
-
-void Start(const rust::Slice<::std::uint8_t const> proto_bytes) {
-#ifdef NETSIM_ANDROID_EMULATOR
-  // Initialize hostapd and slirp inside WiFi Service.
-  config::WiFi config;
-  config.ParseFromArray(proto_bytes.data(), proto_bytes.size());
-
-  android::qemu2::HostapdOptions hostapd = {
-      .disabled = config.hostapd_options().disabled(),
-      .ssid = config.hostapd_options().ssid(),
-      .passwd = config.hostapd_options().passwd()};
-
-  auto host_dns = stringutils::Split(config.slirp_options().host_dns(), ",");
-  android::qemu2::SlirpOptions slirpOpts = {
-      .disabled = config.slirp_options().disabled(),
-      .ipv4 = (config.slirp_options().has_ipv4() ? config.slirp_options().ipv4()
-                                                 : true),
-      .restricted = config.slirp_options().restricted(),
-      .vnet = config.slirp_options().vnet(),
-      .vhost = config.slirp_options().vhost(),
-      .vmask = config.slirp_options().vmask(),
-      .ipv6 = (config.slirp_options().has_ipv6() ? config.slirp_options().ipv6()
-                                                 : true),
-      .vprefix6 = config.slirp_options().vprefix6(),
-      .vprefixLen = (uint8_t)config.slirp_options().vprefixlen(),
-      .vhost6 = config.slirp_options().vhost6(),
-      .vhostname = config.slirp_options().vhostname(),
-      .tftpath = config.slirp_options().tftpath(),
-      .bootfile = config.slirp_options().bootfile(),
-      .dhcpstart = config.slirp_options().dhcpstart(),
-      .dns = config.slirp_options().dns(),
-      .dns6 = config.slirp_options().dns6(),
-      .host_dns = host_dns,
-  };
-  if (!config.slirp_options().host_dns().empty()) {
-    BtsLogInfo("Host DNS server: %s",
-               config.slirp_options().host_dns().c_str());
-  }
-  auto builder = android::qemu2::WifiService::Builder()
-                     .withHostapd(hostapd)
-                     .withSlirp(slirpOpts)
-                     .withOnReceiveCallback(HandleWifiCallback)
-                     .withVerboseLogging(true);
-  wifi_service = builder.build();
-  if (!wifi_service->init()) {
-    BtsLogWarn("Failed to initialize wifi service");
-  }
-#endif
-}
-void Stop() {
-#ifdef NETSIM_ANDROID_EMULATOR
-  wifi_service->stop();
-#endif
-}
-
-}  // namespace facade
-
-void libslirp_main_loop_wait() {
-#ifdef NETSIM_ANDROID_EMULATOR
-  // main_loop_wait is a non-blocking call where fds maintained by the
-  // WiFi service (slirp) are polled and serviced for I/O. When any fd
-  // become ready for I/O, slirp_pollfds_poll() will be invoked to read
-  // from the open sockets therefore incoming packets are serviced.
-  android::qemu2::libslirp_main_loop_wait(true);
-#endif
-}
-
-void HandleWifiRequestCxx(const rust::Vec<uint8_t> &packet) {
-#ifdef NETSIM_ANDROID_EMULATOR
-  // Send the packet to the WiFi service.
-  struct iovec iov[1];
-  iov[0].iov_base = (void *)packet.data();
-  iov[0].iov_len = packet.size();
-  wifi_service->send(android::base::IOVector(iov, iov + 1));
-#endif
-}
-
-void HostapdSendCxx(const rust::Vec<uint8_t> &packet) {
-#ifdef NETSIM_ANDROID_EMULATOR
-  // Send the packet to Hostapd.
-  struct iovec iov[1];
-  iov[0].iov_base = (void *)packet.data();
-  iov[0].iov_len = packet.size();
-  wifi_service->hostapd_send(android::base::IOVector(iov, iov + 1));
-#endif
-}
-
-void LibslirpSendCxx(const rust::Vec<uint8_t> &packet) {
-#ifdef NETSIM_ANDROID_EMULATOR
-  // Send the packet to libslirp.
-  struct iovec iov[1];
-  iov[0].iov_base = (void *)packet.data();
-  iov[0].iov_len = packet.size();
-  wifi_service->libslirp_send(android::base::IOVector(iov, iov + 1));
-#endif
-}
-
-}  // namespace netsim::wifi
diff --git a/src/wifi/wifi_facade.h b/src/wifi/wifi_facade.h
deleted file mode 100644
index c634bbb0..00000000
--- a/src/wifi/wifi_facade.h
+++ /dev/null
@@ -1,45 +0,0 @@
-/*
- * Copyright 2023 The Android Open Source Project
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
-#include <memory>
-#include <string>
-
-#include "netsim/model.pb.h"
-#include "rust/cxx.h"
-
-/** Manages the WiFi chip emulation provided by the WiFi service library.
- *
- * Owns the WiFi service, setup, and manages the packet flow into and out of
- * WiFi service.
- */
-
-namespace netsim::wifi::facade {
-
-void Reset(uint32_t);
-void Remove(uint32_t);
-void Patch(uint32_t, const model::Chip::Radio &);
-model::Chip::Radio Get(uint32_t);
-void Add(uint32_t chip_id);
-
-void Start(const rust::Slice<::std::uint8_t const> proto_bytes);
-void Stop();
-
-// Cxx functions for rust ffi.
-void PatchCxx(uint32_t, const rust::Slice<::std::uint8_t const> _proto_bytes);
-rust::Vec<uint8_t> GetCxx(uint32_t);
-
-}  // namespace netsim::wifi::facade
diff --git a/src/wifi/wifi_packet_hub.h b/src/wifi/wifi_packet_hub.h
deleted file mode 100644
index fbd733b2..00000000
--- a/src/wifi/wifi_packet_hub.h
+++ /dev/null
@@ -1,38 +0,0 @@
-/*
- * Copyright 2023 The Android Open Source Project
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
-#include <cstdint>
-#include <memory>
-#include <vector>
-
-#include "rust/cxx.h"
-
-namespace netsim::wifi {
-
-/* Handle packet requests for the WiFi Facade which may come over
-   different transports including gRPC. */
-
-void libslirp_main_loop_wait();
-
-void HandleWifiRequestCxx(const rust::Vec<uint8_t> &packet);
-
-void HostapdSendCxx(const rust::Vec<uint8_t> &packet);
-
-void LibslirpSendCxx(const rust::Vec<uint8_t> &packet);
-
-}  // namespace netsim::wifi
diff --git a/testing/mobly/Android.bp b/testing/mobly/Android.bp
index 737a7a36..075ff73f 100644
--- a/testing/mobly/Android.bp
+++ b/testing/mobly/Android.bp
@@ -24,7 +24,7 @@ python_test_host {
     ],
     main: "ble_gatt_test.py",
     libs: ["mobly"],
-    data: [
+    device_common_data: [
         // test APK module
         ":mobly-bundled-snippets",
     ],
diff --git a/testing/netsim-grpc/src/netsim_grpc/netsim_client.py b/testing/netsim-grpc/src/netsim_grpc/netsim_client.py
index 3c2ae7d6..21bb774c 100644
--- a/testing/netsim-grpc/src/netsim_grpc/netsim_client.py
+++ b/testing/netsim-grpc/src/netsim_grpc/netsim_client.py
@@ -138,6 +138,45 @@ class NetsimClient(object):
     request.device.chips.append(chip)
     self._stub.PatchDevice(request)
 
+  def get_captures(self) -> list[model.Capture]:
+    """Get info for all capture information in netsim.
+
+    Returns:
+      A List of all captures where capture is netsim.model.Capture.
+    """
+    return self._stub.ListCapture(_Empty()).captures
+
+  def set_capture(
+      self, device_name: str, radio: common.ChipKind, state: bool
+  ) -> None:
+    """Set the capture state of the specific device and radio.
+
+    Args:
+      device_name: The avd name of the specified device.
+      radio: The specified radio ChipKind, e.g. BLUETOOTH, WIFI, UWB
+      state: Set capture state UP if True, Down if False.
+    """
+    for capture in self.get_captures():
+      if capture.chip_kind == radio and capture.device_name == device_name:
+        request = frontend.PatchCaptureRequest()
+        request.id = capture.id
+        request.patch.state = state
+        logging.info(
+            'Setting capture state of radio %s for device %s to %s',
+            common.ChipKind.Name(radio),
+            device_name,
+            state,
+        )
+        self._stub.PatchCapture(request)
+
+  def set_capture_all(self, state: bool) -> None:
+    logging.info('Setting capture state for all devices: %s', state)
+    for capture in self.get_captures():
+      request = frontend.PatchCaptureRequest()
+      request.id = capture.id
+      request.patch.state = state
+      self._stub.PatchCapture(request)
+
   def reset(self) -> None:
     """Reset all devices."""
     self._stub.Reset(_Empty())
diff --git a/testing/tests/wifi/nsd/Android.bp b/testing/tests/wifi/nsd/Android.bp
index bff61f61..a5357bfb 100644
--- a/testing/tests/wifi/nsd/Android.bp
+++ b/testing/tests/wifi/nsd/Android.bp
@@ -37,7 +37,7 @@ python_test_host {
     main: "instrumentation_test.py",
     srcs: ["instrumentation_test.py"],
     test_config: "AndroidTest.xml",
-    data: [
+    device_common_data: [
         ":WifiNsdInstrumentationTest",
     ],
     test_options: {
diff --git a/ui/dist/js/device-observer.js b/ui/dist/js/device-observer.js
index 9d6e8a93..d90acfa3 100644
--- a/ui/dist/js/device-observer.js
+++ b/ui/dist/js/device-observer.js
@@ -1 +1 @@
-const e="./v1/devices",i="./v1/captures";class t{constructor(e){this.device=e}get name(){return this.device.name}set name(e){this.device.name=e}get position(){const e={x:0,y:0,z:0};return"position"in this.device&&this.device.position&&"object"==typeof this.device.position&&("x"in this.device.position&&"number"==typeof this.device.position.x&&(e.x=this.device.position.x),"y"in this.device.position&&"number"==typeof this.device.position.y&&(e.y=this.device.position.y),"z"in this.device.position&&"number"==typeof this.device.position.z&&(e.z=this.device.position.z)),e}set position(e){this.device.position=e}get orientation(){const e={yaw:0,pitch:0,roll:0};return"orientation"in this.device&&this.device.orientation&&"object"==typeof this.device.orientation&&("yaw"in this.device.orientation&&"number"==typeof this.device.orientation.yaw&&(e.yaw=this.device.orientation.yaw),"pitch"in this.device.orientation&&"number"==typeof this.device.orientation.pitch&&(e.pitch=this.device.orientation.pitch),"roll"in this.device.orientation&&"number"==typeof this.device.orientation.roll&&(e.roll=this.device.orientation.roll)),e}set orientation(e){this.device.orientation=e}get chips(){var e;return null!==(e=this.device.chips)&&void 0!==e?e:[]}set chips(e){this.device.chips=e}get visible(){return Boolean(this.device.visible)}set visible(e){this.device.visible=e}toggleChipState(e){e.state=!e.state}toggleCapture(e,i){"capture"in i&&i.capture&&(i.capture=!i.capture,o.patchDevice({device:{name:e.name,chips:e.chips}}))}}const o=new class{constructor(){this.observers=[],this.simulationInfo={devices:[],captures:[],selectedId:"",dimension:{x:10,y:10,z:0},lastModified:""},this.invokeGetDevice(),this.invokeListCaptures()}async invokeGetDevice(){await fetch(e,{method:"GET"}).then((e=>e.json())).then((e=>{this.fetchDevice(e.devices),this.updateLastModified(e.lastModified)})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}async invokeListCaptures(){await fetch(i,{method:"GET"}).then((e=>e.json())).then((e=>{this.simulationInfo.captures=e.captures,this.notifyObservers()})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}fetchDevice(e){this.simulationInfo.devices=[],e&&(this.simulationInfo.devices=e.map((e=>new t(e)))),this.notifyObservers()}getLastModified(){return this.simulationInfo.lastModified}updateLastModified(e){this.simulationInfo.lastModified=e}patchSelected(e){this.simulationInfo.selectedId=e,this.notifyObservers()}handleDrop(e,i,t){for(const o of this.simulationInfo.devices)if(e===o.name){o.position={x:i,y:t,z:o.position.z},this.patchDevice({device:{name:o.name,position:o.position}});break}}patchCapture(e,t){fetch(i+"/"+e,{method:"PATCH",headers:{"Content-Type":"text/plain","Content-Length":t.length.toString()},body:t}),this.notifyObservers()}patchDevice(i){const t=JSON.stringify(i);fetch(e,{method:"PATCH",headers:{"Content-Type":"application/json","Content-Length":t.length.toString()},body:t}).then((e=>e.json())).catch((e=>{console.error("Error:",e)})),this.notifyObservers()}registerObserver(e){this.observers.push(e),e.onNotify(this.simulationInfo)}removeObserver(e){const i=this.observers.indexOf(e);this.observers.splice(i,1)}notifyObservers(){for(const e of this.observers)e.onNotify(this.simulationInfo)}getDeviceList(){return this.simulationInfo.devices}};!async function(){const e=e=>new Promise((i=>setTimeout(i,e)));for(;;)await o.invokeListCaptures(),await o.invokeGetDevice(),await e(1e3)}(),async function(){for(await o.invokeGetDevice();;){const i=JSON.stringify({lastModified:o.getLastModified()});await fetch(e,{method:"SUBSCRIBE",headers:{"Content-Type":"application/json","Content-Length":i.length.toString()},body:i}).then((e=>e.json())).then((e=>{o.fetchDevice(e.devices),o.updateLastModified(e.lastModified)})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}}();export{t as Device,o as simulationState};
+const e="./v1/devices",i="./v1/captures";class t{constructor(e){this.device=e}get name(){return this.device.name}set name(e){this.device.name=e}get position(){const e={x:0,y:0,z:0};return"position"in this.device&&this.device.position&&"object"==typeof this.device.position&&("x"in this.device.position&&"number"==typeof this.device.position.x&&(e.x=this.device.position.x),"y"in this.device.position&&"number"==typeof this.device.position.y&&(e.y=this.device.position.y),"z"in this.device.position&&"number"==typeof this.device.position.z&&(e.z=this.device.position.z)),e}set position(e){this.device.position=e}get orientation(){const e={yaw:0,pitch:0,roll:0};return"orientation"in this.device&&this.device.orientation&&"object"==typeof this.device.orientation&&("yaw"in this.device.orientation&&"number"==typeof this.device.orientation.yaw&&(e.yaw=this.device.orientation.yaw),"pitch"in this.device.orientation&&"number"==typeof this.device.orientation.pitch&&(e.pitch=this.device.orientation.pitch),"roll"in this.device.orientation&&"number"==typeof this.device.orientation.roll&&(e.roll=this.device.orientation.roll)),e}set orientation(e){this.device.orientation=e}get chips(){var e;return null!==(e=this.device.chips)&&void 0!==e?e:[]}set chips(e){this.device.chips=e}get visible(){return Boolean(this.device.visible)}set visible(e){this.device.visible=e}toggleChipState(e){e.state=!e.state}toggleCapture(e,i){"capture"in i&&i.capture&&(i.capture=!i.capture,o.patchDevice({device:{name:e.name,chips:e.chips}}))}}const o=new class{constructor(){this.observers=[],this.simulationInfo={devices:[],captures:[],selectedId:"",dimension:{x:10,y:10,z:0},lastModified:""},this.invokeGetDevice(),this.invokeListCaptures()}async invokeGetDevice(){await fetch(e,{method:"GET"}).then((e=>e.json())).then((e=>{this.fetchDevice(e.devices),this.updateLastModified(e.lastModified)})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}async invokeListCaptures(){await fetch(i,{method:"GET"}).then((e=>e.json())).then((e=>{this.simulationInfo.captures=e.captures,this.notifyObservers()})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}fetchDevice(e){this.simulationInfo.devices=[],e&&(this.simulationInfo.devices=e.map((e=>new t(e)))),this.notifyObservers()}getLastModified(){return this.simulationInfo.lastModified}updateLastModified(e){this.simulationInfo.lastModified=e}patchSelected(e){this.simulationInfo.selectedId=e,this.notifyObservers()}handleDrop(e,i,t){this.simulationInfo.selectedId=e;for(const o of this.simulationInfo.devices)if(e===o.name){o.position={x:i,y:t,z:o.position.z},this.patchDevice({device:{name:o.name,position:o.position}});break}}patchCapture(e,t){fetch(i+"/"+e,{method:"PATCH",headers:{"Content-Type":"text/plain","Content-Length":t.length.toString()},body:t}),this.notifyObservers()}patchDevice(i){const t=JSON.stringify(i);fetch(e,{method:"PATCH",headers:{"Content-Type":"application/json","Content-Length":t.length.toString()},body:t}).then((e=>e.json())).catch((e=>{console.error("Error:",e)})),this.notifyObservers()}registerObserver(e){this.observers.push(e),e.onNotify(this.simulationInfo)}removeObserver(e){const i=this.observers.indexOf(e);this.observers.splice(i,1)}notifyObservers(){for(const e of this.observers)e.onNotify(this.simulationInfo)}getDeviceList(){return this.simulationInfo.devices}};!async function(){const e=e=>new Promise((i=>setTimeout(i,e)));for(;;)await o.invokeListCaptures(),await o.invokeGetDevice(),await e(1e3)}(),async function(){for(await o.invokeGetDevice();;){const i=JSON.stringify({lastModified:o.getLastModified()});await fetch(e,{method:"SUBSCRIBE",headers:{"Content-Type":"application/json","Content-Length":i.length.toString()},body:i}).then((e=>e.json())).then((e=>{o.fetchDevice(e.devices),o.updateLastModified(e.lastModified)})).catch((e=>{console.log("Cannot connect to netsim web server",e)}))}}();export{t as Device,o as simulationState};
diff --git a/ui/ts/device-observer.ts b/ui/ts/device-observer.ts
index 59ee0795..27acaa9a 100644
--- a/ui/ts/device-observer.ts
+++ b/ui/ts/device-observer.ts
@@ -199,6 +199,7 @@ class SimulationState implements Observable {
   }
 
   handleDrop(id: string, x: number, y: number) {
+    this.simulationInfo.selectedId = id;
     for (const device of this.simulationInfo.devices) {
       if (id === device.name) {
         device.position = {x, y, z: device.position.z};
```

