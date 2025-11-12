```diff
diff --git a/.gitignore b/.gitignore
index 19bba5cc..d1ff97ec 100644
--- a/.gitignore
+++ b/.gitignore
@@ -11,4 +11,7 @@ objs
 **/Cargo.lock
 # Android test
 **/.idea
-**/out
\ No newline at end of file
+**/out
+# Bazel build files
+bazel-*
+MODULE.bazel.lock
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 6c5556ad..28067d37 100644
--- a/Android.bp
+++ b/Android.bp
@@ -73,6 +73,7 @@ rust_defaults {
         "liblibc",
         "libnetsim_proto",
         "libhttp",
+        "libhttparse",
         "libnetsim_common",
         "libnetsim_packets",
         "libpdl_runtime",
@@ -317,6 +318,7 @@ rust_defaults {
         "librand",
         "liblibc",
         "liblog_rust",
+        "libprotobuf_json_mapping",
         "libenv_logger",
         "libzip",
     ],
@@ -361,16 +363,15 @@ rust_test_host {
 rust_defaults {
     name: "netsim_cli_defaults",
     rustlibs: [
-        "libanyhow",
         "libclap",
         "libfutures",
         "libfutures_util",
         "libgrpcio",
         "libhex",
+        "liblog_rust",
         "libnetsim_common",
         "libnetsim_proto",
         "libprotobuf",
-        "libtracing",
     ],
 }
 
diff --git a/BUILD.bazel b/BUILD.bazel
new file mode 100644
index 00000000..ee11f0c3
--- /dev/null
+++ b/BUILD.bazel
@@ -0,0 +1,35 @@
+# Copyright 2025 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the',  help='License');
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an',  help='AS IS' BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""netsim bazel build rule."""
+
+load("@rules_proto//proto:defs.bzl", "proto_library")
+
+proto_library(
+    name = "lib-netsimd-proto",
+    srcs = [
+        "proto/netsim/common.proto",
+        "proto/netsim/frontend.proto",
+        "proto/netsim/hci_packet.proto",
+        "proto/netsim/model.proto",
+        "proto/netsim/packet_streamer.proto",
+        "proto/netsim/startup.proto",
+        "proto/netsim/stats.proto",
+    ],
+    strip_import_prefix = "proto",
+    deps = [
+        "@protobuf//:empty_proto",
+        "@protobuf//:timestamp_proto",
+        "@rootcanal//:rootcanal-configuration-proto",
+    ],
+)
diff --git a/MODULE.bazel b/MODULE.bazel
new file mode 100644
index 00000000..bdfaf6b3
--- /dev/null
+++ b/MODULE.bazel
@@ -0,0 +1,22 @@
+# Copyright 2025 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the',  help='License');
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an',  help='AS IS' BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""netsim module"""
+
+module(
+    name = "netsim",
+    version = "0.0.1",
+)
+
+bazel_dep(name = "rules_proto", version = "7.0.2")
+bazel_dep(name = "protobuf", version = "30.2")
diff --git a/WORKSPACE b/WORKSPACE
new file mode 100644
index 00000000..d0509d2b
--- /dev/null
+++ b/WORKSPACE
@@ -0,0 +1,20 @@
+# Copyright 2025 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the',  help='License');
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an',  help='AS IS' BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""netsim workspace"""
+
+new_local_repository(
+    name = "rootcanal",
+    build_file = "//:rootcanal.BUILD.bazel",
+    path = "../../packages/modules/Bluetooth/tools/rootcanal",
+)
diff --git a/cmake/config.toml.in b/cmake/config.toml.in
new file mode 100644
index 00000000..c7b180e0
--- /dev/null
+++ b/cmake/config.toml.in
@@ -0,0 +1,181 @@
+# This is a cargo configuration that will make sure
+# all the crates are internal only.
+
+[net]
+offline = true
+
+[patch.crates-io]
+aho-corasick = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/aho-corasick" }
+anstyle = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/anstyle" }
+anyhow = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/anyhow" }
+argh = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/argh" }
+argh_derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/argh_derive" }
+argh_shared = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/argh_shared" }
+arrayvec = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/arrayvec" }
+atty = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/atty" }
+base64 = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/base64" }
+bindgen = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/bindgen" }
+bitflags = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/bitflags", package = "bitflags" }
+byteorder = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/byteorder" }
+bytes = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/bytes" }
+cexpr = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/cexpr" }
+cfg-if = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/cfg-if" }
+chrono = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/chrono" }
+clang-sys = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/clang-sys" }
+codespan-reporting = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/codespan-reporting" }
+crc32fast = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/crc32fast" }
+crossbeam-channel = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/crossbeam-channel" }
+crossbeam-deque = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/crossbeam-deque" }
+crossbeam-epoch = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/crossbeam-epoch" }
+crossbeam-utils = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/crossbeam-utils" }
+data-encoding = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/data-encoding" }
+either = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/either" }
+env_logger = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/env_logger" }
+errno = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/errno" }
+etherparse = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/etherparse" }
+fastrand = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/fastrand" }
+fnv = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/fnv" }
+futures = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures" }
+futures-channel = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-channel" }
+futures-core = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-core" }
+futures-executor = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-executor" }
+futures-io = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-io" }
+futures-macro = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-macro" }
+futures-sink = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-sink" }
+futures-task = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-task" }
+futures-util = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/futures-util" }
+getrandom = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/getrandom" }
+glam = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/glam" }
+glob = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/glob" }
+grpcio = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/grpcio" }
+hashbrown = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/hashbrown" }
+heck = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/heck" }
+hex = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/hex" }
+http = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/http" }
+httparse = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/httparse" }
+indexmap = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/indexmap" }
+instant = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/instant" }
+itoa = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/itoa" }
+lazycell = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/lazycell" }
+lazy_static = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/lazy_static" }
+libc = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/libc" }
+libloading = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/libloading" }
+libm = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/libm" }
+libz-sys = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/libz-sys" }
+lock_api = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/lock_api" }
+log = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/log" }
+memchr = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/memchr" }
+memoffset = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/memoffset" }
+minimal-lexical = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/minimal-lexical" }
+mio = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/mio" }
+nom = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/nom" }
+num_cpus = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/num_cpus" }
+num-derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/num-derive" }
+num-integer = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/num-integer" }
+num-traits = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/num-traits" }
+once_cell = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/once_cell" }
+os_str_bytes = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/os_str_bytes" }
+parking_lot = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/parking_lot" }
+parking_lot_core = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/parking_lot_core" }
+paste = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/paste" }
+pest = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pest" }
+pest_derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pest_derive" }
+pest_generator = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pest_generator" }
+pest_meta = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pest_meta" }
+pin-project-lite = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pin-project-lite" }
+pin-utils = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/pin-utils" }
+ppv-lite86 = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/ppv-lite86" }
+prettyplease = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/prettyplease" }
+proc-macro2 = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/proc-macro2" }
+protobuf = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/protobuf" }
+protobuf-codegen = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/protobuf-codegen" }
+protobuf-json-mapping = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/protobuf-json-mapping" }
+protobuf-parse = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/protobuf-parse" }
+protobuf-support = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/protobuf-support" }
+quote = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/quote" }
+rand = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rand" }
+rand_chacha = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rand_chacha" }
+rand_core = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rand_core" }
+rayon = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rayon" }
+rayon-core = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rayon-core" }
+regex = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/regex" }
+regex-syntax = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/regex-syntax" }
+rustc-hash = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rustc-hash" }
+rustix = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/rustix" }
+ryu = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/ryu" }
+same-file = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/same-file" }
+scopeguard = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/scopeguard" }
+serde = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/serde" }
+serde_derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/serde_derive" }
+serde_json = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/serde_json" }
+sharded-slab = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/sharded-slab" }
+shlex = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/shlex" }
+slab = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/slab" }
+smallvec = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/smallvec" }
+socket2 = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/socket2" }
+syn = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/syn" }
+tempfile = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tempfile" }
+termcolor = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/termcolor" }
+textwrap = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/textwrap" }
+thiserror = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/thiserror" }
+thiserror-impl = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/thiserror-impl" }
+thread_local = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/thread_local" }
+tokio-stream = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tokio-stream" }
+tracing = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tracing" }
+tracing-attributes = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tracing-attributes" }
+tracing-core = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tracing-core" }
+tracing-subscriber = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tracing-subscriber" }
+tokio = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tokio" }
+tokio-macros = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tokio-macros" }
+tokio-util = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tokio-util" }
+tungstenite = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/tungstenite" }
+ucd-trie = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/ucd-trie" }
+unicode-ident = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/unicode-ident" }
+unicode-width = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/unicode-width" }
+utf-8 = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/utf-8" }
+walkdir = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/walkdir" }
+which = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/which" }
+zerocopy = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/zerocopy" }
+zerocopy-derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/zerocopy-derive" }
+zip = { path = "${AOSP_ROOT}/external/rust/android-crates-io/crates/zip" }
+
+# TODO: Update Rust toolchain to use the latest clap crates.
+clap_derive = { path = "${AOSP_ROOT}/external/rust/android-crates-io-clap/crates/clap_derive" }
+clap_lex = { path = "${AOSP_ROOT}/external/rust/android-crates-io-clap/crates/clap_lex" }
+
+# TODO: Update Rust toolchain to use the latest pdl crates.
+pdl-compiler = { path = "${AOSP_ROOT}/external/rust/android-crates-io-pdl/crates/pdl-compiler" }
+pdl-runtime = { path = "${AOSP_ROOT}/external/rust/android-crates-io-pdl/crates/pdl-runtime" }
+
+# TODO (365637024): Migrate following crates to monorepo external/rust/android-crates-io
+bitflags1 = { path = "${AOSP_ROOT}/external/rust/crates/bitflags/1.3.2", package = "bitflags" }
+clap = { path = "${AOSP_ROOT}/external/rust/crates/clap" }
+cxx = { path = "${AOSP_ROOT}/external/rust/crates/cxx" }
+cxx-build = { path = "${AOSP_ROOT}/external/rust/crates/cxx/gen/build" }
+grpcio-sys = { path = "${AOSP_ROOT}/external/rust/crates/grpcio-sys" }
+itertools = { path = "${AOSP_ROOT}/external/rust/crates/itertools" }
+num-bigint = { path = "${AOSP_ROOT}/external/rust/crates/num-bigint" }
+pica = { path = "${AOSP_ROOT}/external/rust/crates/pica" }
+proc-macro-error = { path = "${AOSP_ROOT}/external/rust/crates/proc-macro-error" }
+proc-macro-error-attr = { path = "${AOSP_ROOT}/external/rust/crates/proc-macro-error-attr" }
+
+# Patch crates-io with dummy crates for dev dependencies
+# that are actually not required for building crates and not
+# added to the vendored crates.
+backtrace = { path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/backtrace" }
+googletest = { path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/googletest" }
+hermit-abi = { path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/hermit-abi" }
+redox_syscall = { version = "0.2.9", path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/redox_syscall" }
+redox_syscall2 = { version = "0.4.1", path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/redox_syscall2", package="redox_syscall" }
+remove_dir_all = { path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/remove_dir_all" }
+sha2 = { path = "${AOSP_ROOT}/external/qemu/android/build/cmake/rust/crates/sha2" }
+windows-sys = { path = "${AOSP_ROOT}/external/qemu/android/third_party/rust/crates/windows-sys-0.59.0" }
+
+# You will have to process this with the cmake configure_file command
+# and bin place it in the RUST_root
+[source.systembt]
+directory = "${VENDOR_CRATES}"
+
+[source.crates-io]
+replace-with = "systembt"
+local-registry = "/nonexistent"
diff --git a/proto/netsim/frontend.proto b/proto/netsim/frontend.proto
index 03e473d9..be889d47 100644
--- a/proto/netsim/frontend.proto
+++ b/proto/netsim/frontend.proto
@@ -64,6 +64,16 @@ service FrontendService {
 
   // Retrieve the contents of the packet capture as streaming bytes
   rpc GetCapture(GetCaptureRequest) returns (stream GetCaptureResponse);
+
+  // List all current links on netsim.
+  rpc ListLink(google.protobuf.Empty) returns (ListLinkResponse);
+
+  // Patch (add or modify) a link.
+  rpc PatchLink(PatchLinkRequest) returns (google.protobuf.Empty);
+
+  // Delete specified properties for the link. Deletes entire link if all
+  // properties are deleted.
+  rpc DeleteLink(DeleteLinkRequest) returns (google.protobuf.Empty);
 }
 
 // Response of GetVersion.
@@ -189,3 +199,21 @@ message GetCaptureResponse {
   // Max of 1024 bytes of capture file
   bytes capture_stream = 1;
 }
+
+// Response of ListLink
+message ListLinkResponse {
+  // Collection of current links
+  repeated netsim.model.Link links = 1;
+}
+
+// Request of PatchLink.
+message PatchLinkRequest {
+  // The link and properties to apply.
+  netsim.model.Link link = 1;
+}
+
+// Request of DeleteLink.
+message DeleteLinkRequest {
+  // The link containing properties to be removed.
+  netsim.model.Link link = 1;
+}
\ No newline at end of file
diff --git a/proto/netsim/hci_packet.proto b/proto/netsim/hci_packet.proto
index cf2ccbf3..f13b3b1b 100644
--- a/proto/netsim/hci_packet.proto
+++ b/proto/netsim/hci_packet.proto
@@ -19,7 +19,6 @@ option java_multiple_files = true;
 option java_package = "com.android.emulation.bluetooth";
 option csharp_namespace = "Android.Emulation.Bluetooth";
 option objc_class_prefix = "AEB";
-option cc_enable_arenas = true;
 
 // A packet that is exchanged between the bluetooth chip and higher layers.
 message HCIPacket {
diff --git a/proto/netsim/model.proto b/proto/netsim/model.proto
index 85a2f8de..6e70c843 100644
--- a/proto/netsim/model.proto
+++ b/proto/netsim/model.proto
@@ -293,3 +293,15 @@ message Capture {
   // False if chip has been detached from netsim.
   bool valid = 8;
 }
+
+// Link model for netsim
+message Link {
+  // Sender chip identifier. 0 acts as a wildcard, matching any chip.
+  uint32 sender_id = 1;
+  // Receiver chip identifier. 0 acts as a wildcard, matching any chip.
+  uint32 receiver_id = 2;
+  // Radio kind of link (i.e. BLE, WiFi, etc)
+  PhyKind link_kind = 3;
+  // Received Signal Strength Indicator (RSSI) value in dBm
+  int32 rssi = 4;
+}
diff --git a/proto/netsim/stats.proto b/proto/netsim/stats.proto
index 0702cfe6..dfb7c008 100644
--- a/proto/netsim/stats.proto
+++ b/proto/netsim/stats.proto
@@ -89,6 +89,54 @@ message NetsimDeviceStats {
   optional string arch = 7;
 }
 
+// Detailed Wi-Fi stats
+message WifiStats {
+  // === Error Counters ===
+  // Errors related to the hostapd.
+  optional int32 hostapd_errors = 1;
+  // Errors related to network connectivity (e.g., Slirp/Tap interface).
+  optional int32 network_errors = 2;
+  // Errors related to client-specific operations or state.
+  optional int32 client_errors = 3;
+  // Errors encountered while parsing, decoding, or handling IEEE 802.11
+  // frames.
+  optional int32 frame_errors = 4;
+  // Errors related to transmission or reception of frame.
+  optional int32 transmission_errors = 5;
+  // Other uncategorized errors.
+  optional int32 other_errors = 6;
+
+  // === Core Traffic Flow & Type Counters ===
+  // 802.11 frames received from clients via Hwsim messages.
+  optional int32 hwsim_frames_rx = 7;
+  // 802.11 frames transmitted to clients via Hwsim messages.
+  optional int32 hwsim_frames_tx = 8;
+  // L3 packets transmitted to external network (e.g., Slirp).
+  optional int32 network_packets_tx = 9;
+  // L3 packets received from external network.
+  optional int32 network_packets_rx = 10;
+  // 802.11 frames transmitted to hostapd process.
+  optional int32 hostapd_frames_tx = 11;
+  // 802.11 frames received from hostapd process.
+  optional int32 hostapd_frames_rx = 12;
+  // Station-to-station 802.11 frames transmitted via medium.
+  optional int32 wmedium_frames_tx = 13;
+  // Unicast 802.11 frames transmitted to another station via medium.
+  optional int32 wmedium_unicast_frames_tx = 14;
+  // 802.11 Management frames received by medium.
+  optional int32 mgmt_frames_rx = 15;
+
+  // === Specific Protocol Counters ===
+  // mDNS frames count.
+  optional int32 mdns_count = 16;
+
+  // === Performance Statistics ===
+  // Max Throughput from Internet to device(s) in Mbits per second
+  optional float max_download_throughput = 17;
+  // Max Throughput from device(s) to Internet in Mbits per second
+  optional float max_upload_throughput = 18;
+}
+
 // Statistics for a netsim session.
 message NetsimStats {
   // The length of the session in seconds
@@ -105,4 +153,6 @@ message NetsimStats {
   optional NetsimFrontendStats frontend_stats = 6;
   // Device statistics
   repeated NetsimDeviceStats device_stats = 7;
+  // Wi-Fi statistics
+  optional WifiStats wifi_stats = 8;
 }
\ No newline at end of file
diff --git a/rootcanal.BUILD.bazel b/rootcanal.BUILD.bazel
new file mode 100644
index 00000000..f2b0fbcb
--- /dev/null
+++ b/rootcanal.BUILD.bazel
@@ -0,0 +1,25 @@
+# Copyright 2025 - The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the',  help='License');
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an',  help='AS IS' BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""rootcanal bazel build rule"""
+
+load("@rules_proto//proto:defs.bzl", "proto_library")
+
+proto_library(
+    strip_import_prefix = "proto",
+    name = "rootcanal-configuration-proto",
+    srcs = [
+        "proto/rootcanal/configuration.proto",
+    ],
+    visibility = ["//visibility:public"],
+)
diff --git a/rust/cli/Cargo.toml b/rust/cli/Cargo.toml
index 4653fc3a..5857dd90 100644
--- a/rust/cli/Cargo.toml
+++ b/rust/cli/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-cli"
-version = "0.3.50"
+version = "0.3.60"
 edition = "2021"
 
 [lib]
@@ -8,7 +8,6 @@ crate-type = ["staticlib", "lib"]
 doctest = false
 
 [dependencies]
-anyhow = "1"
 clap = { version = "4.1.8", default-features = false, features = [
     "derive",
     "error-context",
@@ -24,4 +23,3 @@ log = "0.4.17"
 netsim-proto = { path = "../proto" }
 netsim-common = { path = "../common" }
 protobuf = "3.2.0"
-tracing = "0.1"
diff --git a/rust/cli/netsim-cli.md b/rust/cli/netsim-cli.md
index 4338c1cd..20bd28ac 100644
--- a/rust/cli/netsim-cli.md
+++ b/rust/cli/netsim-cli.md
@@ -29,7 +29,7 @@ Options:
     * Usage: `netsim devices [OPTIONS]`
     * Options:
         * `-c, --continuous`:    Continuously print device(s) information every second
-* ### `beacon`: A chip that sends advertisements at a set interval
+* ### `beacon`:     A chip that sends advertisements at a set interval
     * Usage: `netsim beacon <COMMAND>`
     * #### Commands:
         * `create`: Create a beacon
@@ -95,7 +95,7 @@ Options:
                 * \[CHIP_NAME\]: Optional name of the beacon to remove
 * ### `reset`:      Reset Netsim device scene
     * Usage: `netsim reset`
-* ### `capture`:       Control the packet capture functionalities with commands: list, patch, get [aliases: pcap]
+* ### `capture`:    Control the packet capture functionalities with commands: list, patch, get [aliases: pcap]
     * Usage: `netsim capture <COMMAND>`
     * #### Commands
         * `list`:   List currently available Captures (packet captures)
@@ -118,6 +118,28 @@ Options:
                                     include ID, Device Name, and Chip Kind
             * Options:
                 * `-o, --location`: Directory to store downloaded capture file(s)
-* ### `gui`:        Opens netsim Web UI
-* ### `artifact`:   Opens netsim artifacts directory (log, pcaps)
+* ### `link`:       Manage Link properties
+    * Usage: `netsim link <COMMAND>`
+    * #### Commands
+        * `list`:   List all current links and their properties
+        * `patch`:  Add or modify link properties
+            * Usage: `netsim link patch <COMMAND>`
+            * ##### Commands
+                * `rssi`:   Patch RSSI (Received Signal Strength Indication) for a link
+                    * Arguments:
+                        * \<RADIO_TYPE\>:   Radio type for the link [possible values: ble, classic, wifi, uwb]
+                        * \<VALUE\>:        RSSI value in dBm (e.g., -60). Must be between -128 and 127
+                        * [SENDER_ID]:      Identifier for the sender chip. Defaults to 0 (ANY_CHIP), affecting all senders to the specified receiver
+                        * [RECEIVER_ID]:    Identifier for the receiver chip. Defaults to 0 (ANY_CHIP), affecting all receivers from the specified sender
+        * `delete`: Remove link properties
+            * Usage: `netsim link patch <COMMAND>`
+            * ##### Commands
+                * `rssi`:   Delete RSSI (Received Signal Strength Indication) for a link
+                    * Arguments:
+                        * \<RADIO_TYPE\>:   Radio type for the link [possible values: ble, classic, wifi, uwb]
+                        * [SENDER_ID]:      Identifier for the sender chip. Defaults to 0 (ANY_CHIP)
+                        * [RECEIVER_ID]:    Identifier for the receiver chip. Defaults to 0 (ANY_CHIP)
+* ### `gui`:        Open netsim Web UI
+* ### `artifact`:   Open netsim artifacts directory (log, pcaps)
+* ### `bumble`:     Open Bumble Hive Web Page
 * ### `help`:       Print this message or the help of the given subcommand(s)
diff --git a/rust/cli/src/args.rs b/rust/cli/src/args.rs
index 98bfd7b2..fce62e20 100644
--- a/rust/cli/src/args.rs
+++ b/rust/cli/src/args.rs
@@ -12,7 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use anyhow::Result;
 use clap::builder::{PossibleValue, TypedValueParser};
 use clap::{Args, Parser, Subcommand, ValueEnum};
 use hex::{decode as hex_to_bytes, FromHexError};
@@ -71,6 +70,9 @@ pub enum Command {
     Beacon(Beacon),
     /// Open Bumble Hive Web Page
     Bumble,
+    /// Manage Link properties
+    #[command(subcommand)]
+    Link(Link),
 }
 
 #[derive(Debug, Args, PartialEq)]
@@ -216,6 +218,65 @@ pub struct BeaconBleAdvertiseData {
     pub manufacturer_data: Option<ParsableBytes>,
 }
 
+#[derive(Debug, Subcommand, PartialEq)]
+pub enum Link {
+    /// List all current links and their properties
+    List,
+    /// Add or modify link properties
+    Patch(LinkPatchCommand),
+    /// Remove link properties
+    Delete(LinkDeleteCommand),
+}
+
+#[derive(Debug, Args, PartialEq)]
+pub struct LinkPatchCommand {
+    #[command(subcommand)]
+    pub command: LinkPatch,
+}
+
+#[derive(Debug, Subcommand, PartialEq)]
+pub enum LinkPatch {
+    /// Patch RSSI (Received Signal Strength Indication) for a link.
+    Rssi(RssiPatch),
+}
+
+#[derive(Debug, Args, PartialEq)]
+pub struct LinkDeleteCommand {
+    #[command(subcommand)]
+    pub command: LinkDelete,
+}
+
+#[derive(Debug, Subcommand, PartialEq)]
+pub enum LinkDelete {
+    /// Delete RSSI (Received Signal Strength Indication) for a link.
+    Rssi(RssiDelete),
+}
+
+#[derive(Debug, Args, PartialEq)]
+pub struct RssiPatch {
+    /// Radio type for the link.
+    #[arg(value_enum, ignore_case = true)]
+    pub radio_type: RadioType,
+    /// RSSI value in dBm (e.g., -60). Must be between -128 and 127.
+    #[arg(allow_hyphen_values = true)]
+    pub value: i8,
+    /// Identifier for the sender chip. Defaults to 0 (ANY_CHIP), affecting all senders to the specified receiver.
+    pub sender_id: Option<u32>,
+    /// Identifier for the receiver chip. Defaults to 0 (ANY_CHIP), affecting all receivers from the specified sender.
+    pub receiver_id: Option<u32>,
+}
+
+#[derive(Debug, Args, PartialEq)]
+pub struct RssiDelete {
+    /// Radio type for the link.
+    #[arg(value_enum, ignore_case = true)]
+    pub radio_type: RadioType,
+    /// Identifier for the sender chip. Defaults to 0 (ANY_CHIP).
+    pub sender_id: Option<u32>,
+    /// Identifier for the receiver chip. Defaults to 0 (ANY_CHIP).
+    pub receiver_id: Option<u32>,
+}
+
 #[derive(Debug, Clone, PartialEq)]
 pub struct ParsableBytes(pub Vec<u8>);
 
diff --git a/rust/cli/src/display.rs b/rust/cli/src/display.rs
index 011bfea4..253b2d25 100644
--- a/rust/cli/src/display.rs
+++ b/rust/cli/src/display.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use netsim_proto::frontend::ListDeviceResponse;
+use netsim_proto::frontend::{ListDeviceResponse, ListLinkResponse};
 use netsim_proto::model::{
     self,
     chip::ble_beacon::advertise_settings,
@@ -367,3 +367,56 @@ impl fmt::Display for Displayer<&Option<bool>> {
         )
     }
 }
+
+// Helper struct to display link's chip IDs, showing "ALL" for ID 0.
+pub struct LinkChipIdDisplay(pub u32);
+
+impl fmt::Display for LinkChipIdDisplay {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        if self.0 == 0 {
+            write!(f, "ALL")
+        } else {
+            write!(f, "{}", self.0)
+        }
+    }
+}
+
+impl fmt::Display for Displayer<ListLinkResponse> {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        let indent = self.indent;
+        let chip_width = 10;
+        let rssi_width = 6;
+        let phykind_width = 20;
+
+        if self.value.links.is_empty() {
+            write!(f, "{:indent$}No links with properties are currently set.", "")?;
+        } else {
+            // Print a header for the table
+            write!(
+                f,
+                "{:indent$}{:chip_width$} | {:chip_width$} | {:phykind_width$} | {:rssi_width$}",
+                "", "Sender", "Receiver", "Type", "RSSI"
+            )?;
+            writeln!(f)?;
+            write!(
+                f,
+                "{:indent$}{:-<chip_width$}-+-{:-<chip_width$}-+-{:-<phykind_width$}-+-{:-<rssi_width$}",
+                "", "", "", "", ""
+            )?;
+            // Iterate through the links and print each one as a row
+            for link in self.value.links.iter() {
+                writeln!(f)?;
+                write!(
+                    f,
+                    "{:indent$}{:<chip_width$} | {:<chip_width$} | {:<phykind_width$} | {:<rssi_width$}",
+                    "",
+                    LinkChipIdDisplay(link.sender_id),
+                    LinkChipIdDisplay(link.receiver_id),
+                    format!("{:?}", link.link_kind.enum_value_or_default()),
+                    link.rssi
+                )?;
+            }
+        }
+        Ok(())
+    }
+}
diff --git a/rust/cli/src/error.rs b/rust/cli/src/error.rs
new file mode 100644
index 00000000..6556cfbd
--- /dev/null
+++ b/rust/cli/src/error.rs
@@ -0,0 +1,77 @@
+// Copyright 2022 Google LLC
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
+use std::fmt;
+
+#[derive(Debug)]
+pub enum Error {
+    Grpc(grpcio::Error),
+    Io(std::io::Error),
+    Hex(hex::FromHexError),
+    Message(String),
+}
+
+impl fmt::Display for Error {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        match self {
+            Error::Grpc(e) => write!(f, "gRPC error: {}", e),
+            Error::Io(e) => write!(f, "IO error: {}", e),
+            Error::Hex(e) => write!(f, "Hex parsing error: {}", e),
+            Error::Message(s) => write!(f, "{}", s),
+        }
+    }
+}
+
+impl std::error::Error for Error {
+    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
+        match self {
+            Error::Grpc(e) => Some(e),
+            Error::Io(e) => Some(e),
+            Error::Hex(e) => Some(e),
+            Error::Message(_) => None,
+        }
+    }
+}
+
+impl From<grpcio::Error> for Error {
+    fn from(err: grpcio::Error) -> Self {
+        Error::Grpc(err)
+    }
+}
+
+impl From<std::io::Error> for Error {
+    fn from(err: std::io::Error) -> Self {
+        Error::Io(err)
+    }
+}
+
+impl From<hex::FromHexError> for Error {
+    fn from(err: hex::FromHexError) -> Self {
+        Error::Hex(err)
+    }
+}
+
+impl From<&str> for Error {
+    fn from(s: &str) -> Self {
+        Error::Message(s.to_string())
+    }
+}
+
+impl From<String> for Error {
+    fn from(s: String) -> Self {
+        Error::Message(s)
+    }
+}
+
+pub type Result<T> = std::result::Result<T, Error>;
diff --git a/rust/cli/src/grpc_client.rs b/rust/cli/src/grpc_client.rs
index 9cc9917f..cb27d6ad 100644
--- a/rust/cli/src/grpc_client.rs
+++ b/rust/cli/src/grpc_client.rs
@@ -1,5 +1,5 @@
 //! gRPC frontend client library for netsim.
-use anyhow::{anyhow, Result};
+use crate::error::Result;
 use futures_util::StreamExt;
 use netsim_proto::frontend;
 use netsim_proto::frontend_grpc::FrontendServiceClient;
@@ -36,6 +36,9 @@ pub enum GrpcRequest {
     PatchDevice(frontend::PatchDeviceRequest),
     PatchCapture(frontend::PatchCaptureRequest),
     GetCapture(frontend::GetCaptureRequest),
+    ListLink,
+    PatchLink(frontend::PatchLinkRequest),
+    DeleteLink(frontend::DeleteLinkRequest),
 }
 
 // Enum of Grpc Responses holding the response proto as applicable
@@ -49,6 +52,9 @@ pub enum GrpcResponse {
     DeleteChip,
     PatchDevice,
     PatchCapture,
+    ListLink(frontend::ListLinkResponse),
+    PatchLink,
+    DeleteLink,
     Unknown,
 }
 
@@ -103,6 +109,20 @@ pub fn send_grpc(
             client.patch_capture(req)?;
             Ok(GrpcResponse::PatchCapture)
         }
-        _ => Err(anyhow!(grpcio::RpcStatus::new(grpcio::RpcStatusCode::INVALID_ARGUMENT,))),
+        GrpcRequest::ListLink => {
+            Ok(GrpcResponse::ListLink(client.list_link(&empty::Empty::new())?))
+        }
+        GrpcRequest::PatchLink(req) => {
+            client.patch_link(req)?;
+            Ok(GrpcResponse::PatchLink)
+        }
+        GrpcRequest::DeleteLink(req) => {
+            client.delete_link(req)?;
+            Ok(GrpcResponse::DeleteLink)
+        }
+        _ => Err(grpcio::Error::RpcFailure(grpcio::RpcStatus::new(
+            grpcio::RpcStatusCode::INVALID_ARGUMENT,
+        ))
+        .into()),
     }
 }
diff --git a/rust/cli/src/lib.rs b/rust/cli/src/lib.rs
index 027f7d95..6167d0f0 100644
--- a/rust/cli/src/lib.rs
+++ b/rust/cli/src/lib.rs
@@ -17,6 +17,7 @@
 mod args;
 mod browser;
 mod display;
+mod error;
 mod file_handler;
 mod grpc_client;
 mod requests;
@@ -26,13 +27,13 @@ use netsim_common::util::ini_file::get_server_address;
 use netsim_common::util::os_utils::get_instance;
 use netsim_proto::frontend;
 
-use anyhow::{anyhow, Result};
 use grpcio::{ChannelBuilder, EnvBuilder};
+use log::error;
 use std::env;
 use std::fs::File;
 use std::path::PathBuf;
-use tracing::error;
 
+use crate::error::{Error, Result};
 use crate::grpc_client::{ClientResponseReader, GrpcRequest, GrpcResponse};
 use netsim_proto::frontend_grpc::FrontendServiceClient;
 
@@ -74,7 +75,7 @@ fn perform_command(
     command: &mut args::Command,
     client: FrontendServiceClient,
     verbose: bool,
-) -> anyhow::Result<()> {
+) -> Result<()> {
     // Get command's gRPC request(s)
     let requests = match command {
         args::Command::Capture(args::Capture::Patch(_) | args::Capture::Get(_)) => {
@@ -133,7 +134,7 @@ fn perform_command(
         };
     }
     if process_error {
-        return Err(anyhow!("Not all requests were processed successfully."));
+        return Err("Not all requests were processed successfully.".into());
     }
     Ok(())
 }
@@ -141,7 +142,7 @@ fn perform_command(
 fn find_id_for_remove(
     response: frontend::ListDeviceResponse,
     cmd: &args::BeaconRemove,
-) -> anyhow::Result<u32> {
+) -> Result<u32> {
     let devices = response.devices;
     let id = devices
         .iter()
@@ -150,19 +151,19 @@ fn find_id_for_remove(
             (device.chips.len() == 1).then_some(&device.chips[0]),
             |chip_name| device.chips.iter().find(|chip| &chip.name == chip_name)
         ))
-        .ok_or(
+        .ok_or_else(|| {
             cmd.chip_name
                 .as_ref()
-                .map_or(
-                    anyhow!("failed to delete chip: device '{}' has multiple possible candidates, please specify a chip name", cmd.device_name),
+                .map_or_else(
+                    || Error::from(format!("failed to delete chip: device '{}' has multiple possible candidates, please specify a chip name", cmd.device_name)),
                     |chip_name| {
-                        anyhow!(
+                        Error::from(format!(
                             "failed to delete chip: could not find chip '{}' on device '{}'",
                             chip_name, cmd.device_name
-                        )
+                        ))
                     },
                 )
-        )?
+        })?
         .id;
 
     Ok(id)
@@ -174,7 +175,7 @@ fn continuous_perform_command(
     client: &FrontendServiceClient,
     grpc_request: &GrpcRequest,
     verbose: bool,
-) -> anyhow::Result<()> {
+) -> Result<()> {
     loop {
         let response = grpc_client::send_grpc(client, grpc_request)?;
         process_result(command, Ok(Some(response)), verbose)?;
@@ -184,16 +185,16 @@ fn continuous_perform_command(
 /// Check and handle the gRPC call result
 fn process_result(
     command: &args::Command,
-    result: anyhow::Result<Option<GrpcResponse>>,
+    result: Result<Option<GrpcResponse>>,
     verbose: bool,
-) -> anyhow::Result<()> {
+) -> Result<()> {
     match result {
         Ok(grpc_response) => {
             let response = grpc_response.unwrap_or(GrpcResponse::Unknown);
             command.print_response(&response, verbose);
             Ok(())
         }
-        Err(e) => Err(anyhow!("Grpc call error: {}", e)),
+        Err(e) => Err(format!("Grpc call error: {}", e).into()),
     }
 }
 #[no_mangle]
diff --git a/rust/cli/src/requests.rs b/rust/cli/src/requests.rs
index 017f4bd0..904b2bc4 100644
--- a/rust/cli/src/requests.rs
+++ b/rust/cli/src/requests.rs
@@ -12,9 +12,11 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 use crate::args::{
-    Beacon, BeaconCreate, BeaconPatch, Capture, Command, OnOffState, RadioType, UpDownStatus,
+    Beacon, BeaconCreate, BeaconPatch, Capture, Command, Link, LinkDelete, LinkPatch, OnOffState,
+    RadioType, UpDownStatus,
 };
 use crate::grpc_client::{self, GrpcRequest, GrpcResponse};
+use log::error;
 use netsim_common::util::time_display::TimeDisplay;
 use netsim_proto::common::ChipKind;
 use netsim_proto::frontend;
@@ -27,10 +29,18 @@ use netsim_proto::model::chip::{
 };
 use netsim_proto::model::{
     self, chip_create, Chip, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
-    Position,
+    PhyKind as PhyKindProto, Position,
 };
 use protobuf::MessageField;
-use tracing::error;
+
+fn radio_type_to_proto_phy_kind(radio_type: RadioType) -> PhyKindProto {
+    match radio_type {
+        RadioType::Ble => PhyKindProto::BLUETOOTH_LOW_ENERGY,
+        RadioType::Classic => PhyKindProto::BLUETOOTH_CLASSIC,
+        RadioType::Wifi => PhyKindProto::WIFI,
+        RadioType::Uwb => PhyKindProto::UWB,
+    }
+}
 
 impl Command {
     /// Return the generated request protobuf message
@@ -166,6 +176,40 @@ impl Command {
             Command::Bumble => {
                 unimplemented!("get_request is not implemented for Bumble Command.");
             }
+            Command::Link(link_cmd) => match link_cmd {
+                Link::List => GrpcRequest::ListLink,
+                Link::Patch(patch_struct) => match &patch_struct.command {
+                    LinkPatch::Rssi(args) => {
+                        let link = model::Link {
+                            sender_id: args.sender_id.unwrap_or(0),
+                            receiver_id: args.receiver_id.unwrap_or(0),
+                            link_kind: radio_type_to_proto_phy_kind(args.radio_type).into(),
+                            rssi: args.value as i32,
+                            ..Default::default()
+                        };
+                        let request = frontend::PatchLinkRequest {
+                            link: MessageField::some(link),
+                            ..Default::default()
+                        };
+                        GrpcRequest::PatchLink(request)
+                    }
+                },
+                Link::Delete(delete_struct) => match &delete_struct.command {
+                    LinkDelete::Rssi(args) => {
+                        let link = model::Link {
+                            sender_id: args.sender_id.unwrap_or(0),
+                            receiver_id: args.receiver_id.unwrap_or(0),
+                            link_kind: radio_type_to_proto_phy_kind(args.radio_type).into(),
+                            ..Default::default()
+                        };
+                        let request = frontend::DeleteLinkRequest {
+                            link: MessageField::some(link),
+                            ..Default::default()
+                        };
+                        GrpcRequest::DeleteLink(request)
+                    }
+                },
+            },
         }
     }
 
@@ -256,39 +300,36 @@ mod tests {
     use super::*;
     use crate::args::{
         AdvertiseMode, BeaconBleAdvertiseData, BeaconBleScanResponseData, BeaconBleSettings,
-        BeaconCreateBle, BeaconPatchBle, Command, Devices, Interval, ListCapture, Move, NetsimArgs,
-        ParsableBytes, Radio, RadioType, TxPower, TxPowerLevel,
+        BeaconCreateBle, BeaconPatchBle, Command, Devices, Interval, Link, LinkDelete,
+        LinkDeleteCommand, LinkPatch, LinkPatchCommand, ListCapture, Move, NetsimArgs,
+        ParsableBytes, Radio, RadioType, RssiDelete, RssiPatch, TxPower, TxPowerLevel,
     };
 
     use clap::Parser;
-    use netsim_proto::frontend::{
-        patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto, CreateDeviceRequest,
-        PatchDeviceRequest,
-    };
-    use netsim_proto::model::chip::ble_beacon::AdvertiseData as AdvertiseDataProto;
-    use netsim_proto::model::chip::{
-        ble_beacon::{
-            advertise_settings::{
-                AdvertiseMode as AdvertiseModeProto, AdvertiseTxPower as AdvertiseTxPowerProto,
-                Interval as IntervalProto, Tx_power as TxPowerProto,
-            },
-            AdvertiseSettings as AdvertiseSettingsProto,
-        },
-        BleBeacon as BleBeaconProto, Chip as ChipKindProto,
-    };
-    use netsim_proto::model::chip_create::{
-        BleBeaconCreate as BleBeaconCreateProto, Chip as ChipKindCreateProto,
-    };
-    use netsim_proto::model::{
-        Chip as ChipProto, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
-    };
     use netsim_proto::{
         common::ChipKind,
-        frontend,
+        frontend::{
+            patch_device_request::PatchDeviceFields as PatchDeviceFieldsProto, CreateDeviceRequest,
+            PatchDeviceRequest,
+        },
         model::{
             self,
-            chip::{Bluetooth as Chip_Bluetooth, Radio as Chip_Radio},
-            Position,
+            chip::{
+                ble_beacon::{
+                    advertise_settings::{
+                        AdvertiseMode as AdvertiseModeProto,
+                        AdvertiseTxPower as AdvertiseTxPowerProto, Interval as IntervalProto,
+                        Tx_power as TxPowerProto,
+                    },
+                    AdvertiseData as AdvertiseDataProto,
+                    AdvertiseSettings as AdvertiseSettingsProto,
+                },
+                BleBeacon as BleBeaconProto, Bluetooth as Chip_Bluetooth, Chip as ChipKindProto,
+                Radio as Chip_Radio,
+            },
+            chip_create::{BleBeaconCreate as BleBeaconCreateProto, Chip as ChipKindCreateProto},
+            Chip as ChipProto, ChipCreate as ChipCreateProto, DeviceCreate as DeviceCreateProto,
+            PhyKind as PhyKindProto, Position,
         },
     };
     use protobuf::MessageField;
@@ -1029,4 +1070,107 @@ mod tests {
         let command = String::from("netsim-cli beacon patch ble --manufacturer-data not-a-number");
         assert!(NetsimArgs::try_parse_from(command.split_whitespace()).is_err());
     }
+
+    #[test]
+    fn test_link_list_request() {
+        let command = Command::Link(Link::List);
+        let grpc_request = command.get_request();
+        assert_eq!(grpc_request, GrpcRequest::ListLink);
+    }
+
+    #[test]
+    fn test_link_patch_rssi_request_full() {
+        let command = Command::Link(Link::Patch(LinkPatchCommand {
+            command: LinkPatch::Rssi(RssiPatch {
+                radio_type: RadioType::Ble,
+                value: -60,
+                sender_id: Some(100),
+                receiver_id: Some(200),
+            }),
+        }));
+        let grpc_request = command.get_request();
+        let expected_link = model::Link {
+            sender_id: 100,
+            receiver_id: 200,
+            link_kind: PhyKindProto::BLUETOOTH_LOW_ENERGY.into(),
+            rssi: -60,
+            ..Default::default()
+        };
+        let expected_request = frontend::PatchLinkRequest {
+            link: MessageField::some(expected_link),
+            ..Default::default()
+        };
+        assert_eq!(grpc_request, GrpcRequest::PatchLink(expected_request));
+    }
+
+    #[test]
+    fn test_link_patch_rssi_request_no_ids() {
+        let command = Command::Link(Link::Patch(LinkPatchCommand {
+            command: LinkPatch::Rssi(RssiPatch {
+                radio_type: RadioType::Wifi,
+                value: -70,
+                sender_id: None,
+                receiver_id: None,
+            }),
+        }));
+        let grpc_request = command.get_request();
+        let expected_link = model::Link {
+            sender_id: 0,   // Default for None
+            receiver_id: 0, // Default for None
+            link_kind: PhyKindProto::WIFI.into(),
+            rssi: -70,
+            ..Default::default()
+        };
+        let expected_request = frontend::PatchLinkRequest {
+            link: MessageField::some(expected_link),
+            ..Default::default()
+        };
+        assert_eq!(grpc_request, GrpcRequest::PatchLink(expected_request));
+    }
+
+    #[test]
+    fn test_link_delete_rssi_request_full() {
+        let command = Command::Link(Link::Delete(LinkDeleteCommand {
+            command: LinkDelete::Rssi(RssiDelete {
+                radio_type: RadioType::Classic,
+                sender_id: Some(10),
+                receiver_id: Some(20),
+            }),
+        }));
+        let grpc_request = command.get_request();
+        let expected_link = model::Link {
+            sender_id: 10,
+            receiver_id: 20,
+            link_kind: PhyKindProto::BLUETOOTH_CLASSIC.into(),
+            ..Default::default() // RSSI is not part of delete request key
+        };
+        let expected_request = frontend::DeleteLinkRequest {
+            link: MessageField::some(expected_link),
+            ..Default::default()
+        };
+        assert_eq!(grpc_request, GrpcRequest::DeleteLink(expected_request));
+    }
+
+    #[test]
+    fn test_link_delete_rssi_request_no_ids() {
+        let command = Command::Link(Link::Delete(LinkDeleteCommand {
+            command: LinkDelete::Rssi(RssiDelete {
+                radio_type: RadioType::Ble,
+                sender_id: None,
+                receiver_id: None,
+            }),
+        }));
+        let grpc_request = command.get_request();
+        let expected_link = model::Link {
+            sender_id: 0,   // Default for None
+            receiver_id: 0, // Default for None
+            link_kind: PhyKindProto::BLUETOOTH_LOW_ENERGY.into(),
+            ..Default::default()
+        };
+        let expected_request = frontend::DeleteLinkRequest {
+            link: MessageField::some(expected_link),
+            ..Default::default()
+        };
+        assert_eq!(grpc_request, GrpcRequest::DeleteLink(expected_request));
+    }
 }
diff --git a/rust/cli/src/response.rs b/rust/cli/src/response.rs
index 09c0511f..20d015f0 100644
--- a/rust/cli/src/response.rs
+++ b/rust/cli/src/response.rs
@@ -14,8 +14,11 @@
 
 use std::cmp::max;
 
-use crate::args::{self, Beacon, BeaconCreate, BeaconPatch, Capture, Command, OnOffState};
-use crate::display::Displayer;
+use crate::args::{
+    self, Beacon, BeaconCreate, BeaconPatch, Capture, Command, Link, LinkDelete, LinkPatch,
+    OnOffState,
+};
+use crate::display::{Displayer, LinkChipIdDisplay};
 use crate::grpc_client::GrpcResponse;
 use netsim_common::util::time_display::TimeDisplay;
 use netsim_proto::{common::ChipKind, frontend, model};
@@ -175,6 +178,38 @@ impl args::Command {
             Command::Bumble => {
                 unimplemented!("No Grpc Response for Bumble Command.");
             }
+            Command::Link(link_cmd) => match link_cmd {
+                Link::List => {
+                    let GrpcResponse::ListLink(res) = response else {
+                        panic!("Expected to print ListLinkResponse. Got: {:?}", response);
+                    };
+                    println!("{}", Displayer::new(res.clone(), verbose));
+                }
+                Link::Patch(patch_struct) => match &patch_struct.command {
+                    LinkPatch::Rssi(args) => {
+                        if verbose {
+                            println!(
+                                "Successfully patched RSSI for link (Sender: {}, Receiver: {}, Type: {:?}) to {}.",
+                                LinkChipIdDisplay(args.sender_id.unwrap_or(0)),
+                                LinkChipIdDisplay(args.receiver_id.unwrap_or(0)),
+                                args.radio_type, args.value
+                            );
+                        }
+                    }
+                },
+                Link::Delete(delete_struct) => match &delete_struct.command {
+                    LinkDelete::Rssi(args) => {
+                        if verbose {
+                            println!(
+                                "Successfully deleted RSSI for link (Sender: {}, Receiver: {}, Type: {:?}).",
+                                LinkChipIdDisplay(args.sender_id.unwrap_or(0)),
+                                LinkChipIdDisplay(args.receiver_id.unwrap_or(0)),
+                                args.radio_type
+                            );
+                        }
+                    }
+                },
+            },
         }
     }
 
diff --git a/rust/common/Cargo.toml b/rust/common/Cargo.toml
index c9904a1c..fe0e4f35 100644
--- a/rust/common/Cargo.toml
+++ b/rust/common/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-common"
-version = "0.3.50"
+version = "0.3.60"
 edition = "2021"
 
 [lib]
@@ -13,5 +13,6 @@ chrono = { version = "0.4.19", default-features = false }
 env_logger = { version = "0.10.0", default-features = false }
 libc = "0.2.150"
 log = "0.4.17"
+protobuf-json-mapping = "3.2.0"
 rand = "0.8.5"
 zip = { version = "0.6.4", default-features = false }
\ No newline at end of file
diff --git a/rust/common/src/util/ini_file.rs b/rust/common/src/util/ini_file.rs
index 5ecb84be..1cd329ac 100644
--- a/rust/common/src/util/ini_file.rs
+++ b/rust/common/src/util/ini_file.rs
@@ -116,7 +116,12 @@ fn create_new<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<File> {
 }
 
 /// Write ports to ini file
-pub fn create_ini(instance_num: u16, grpc_port: u32, web_port: Option<u16>) -> std::io::Result<()> {
+pub fn create_ini(
+    instance_num: u16,
+    grpc_port: u32,
+    web_port: Option<u16>,
+    websocket_port: Option<u16>,
+) -> std::io::Result<()> {
     // Instantiate IniFile
     let filepath = get_ini_filepath(instance_num);
     let mut ini_file = IniFile::new(filepath);
@@ -125,6 +130,9 @@ pub fn create_ini(instance_num: u16, grpc_port: u32, web_port: Option<u16>) -> s
     if let Some(num) = web_port {
         ini_file.insert("web.port", &num.to_string());
     }
+    if let Some(num) = websocket_port {
+        ini_file.insert("ws.port", &num.to_string())
+    }
     ini_file.insert("grpc.port", &grpc_port.to_string());
     ini_file.write()
 }
@@ -173,11 +181,10 @@ pub fn get_server_address(instance_num: u16) -> Option<String> {
 
 #[cfg(test)]
 mod tests {
-    use rand::{distributions::Alphanumeric, Rng};
-    use std::env;
     use std::fs::File;
     use std::io::{Read, Write};
     use std::path::PathBuf;
+    use std::{env, time::SystemTime};
 
     use super::get_ini_filepath;
     use super::IniFile;
@@ -202,11 +209,13 @@ mod tests {
     fn get_temp_ini_filepath(prefix: &str) -> PathBuf {
         env::temp_dir().join(format!(
             "{prefix}_{}.ini",
-            rand::thread_rng()
-                .sample_iter(&Alphanumeric)
-                .take(8)
-                .map(char::from)
-                .collect::<String>()
+            SystemTime::now()
+                .duration_since(SystemTime::UNIX_EPOCH)
+                .unwrap()
+                .as_nanos()
+                .to_string()
+                + "_"
+                + &rand::random::<u64>().to_string()
         ))
     }
 
diff --git a/rust/common/src/util/mod.rs b/rust/common/src/util/mod.rs
index d20527c9..5fd101cd 100644
--- a/rust/common/src/util/mod.rs
+++ b/rust/common/src/util/mod.rs
@@ -18,5 +18,6 @@
 pub mod ini_file;
 pub mod netsim_logger;
 pub mod os_utils;
+pub mod proto_print_options;
 pub mod time_display;
 pub mod zip_artifact;
diff --git a/rust/common/src/util/proto_print_options.rs b/rust/common/src/util/proto_print_options.rs
new file mode 100644
index 00000000..a6d18eb3
--- /dev/null
+++ b/rust/common/src/util/proto_print_options.rs
@@ -0,0 +1,25 @@
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
+//! # Print options for protobuf JSON mapping
+
+use protobuf_json_mapping::PrintOptions;
+
+/// A commonly used protobuf JSON print options for devices_handler, captures_handler, and links_handler
+pub const JSON_PRINT_OPTION: PrintOptions = PrintOptions {
+    enum_values_int: false,
+    proto_field_name: false,
+    always_output_default_values: true,
+    _future_options: (),
+};
diff --git a/rust/common/src/util/zip_artifact.rs b/rust/common/src/util/zip_artifact.rs
index 6f9eebfd..1859cc0b 100644
--- a/rust/common/src/util/zip_artifact.rs
+++ b/rust/common/src/util/zip_artifact.rs
@@ -66,7 +66,7 @@ fn fetch_zip_files(root: &PathBuf) -> Result<Vec<PathBuf>> {
         .map(|e| e.path())
         .filter(|path| {
             path.is_file()
-                && path.file_name().and_then(|os_name| os_name.to_str()).map_or(false, |filename| {
+                && path.file_name().and_then(|os_name| os_name.to_str()).is_some_and(|filename| {
                     filename.starts_with("netsim_artifacts_") && filename.ends_with(".zip")
                 })
         })
diff --git a/rust/daemon/Cargo.toml b/rust/daemon/Cargo.toml
index 30f705ad..33c724ea 100644
--- a/rust/daemon/Cargo.toml
+++ b/rust/daemon/Cargo.toml
@@ -1,6 +1,6 @@
 [package]
 name = "netsim-daemon"
-version = "0.3.50"
+version = "0.3.60"
 edition = "2021"
 build = "build.rs"
 
@@ -17,6 +17,7 @@ futures = "0.3.30"
 glam = { version = "0.25.0", features = ["libm"] }
 netsim-proto = { path = "../proto" }
 http = "0.2.9"
+httparse = "1.9.5"
 netsim-common = { path = "../common" }
 libslirp-rs = { path = "../libslirp-rs" }
 hostapd-rs = { path = "../hostapd-rs" }
diff --git a/rust/daemon/src/args.rs b/rust/daemon/src/args.rs
index c6582b5d..ef51bec0 100644
--- a/rust/daemon/src/args.rs
+++ b/rust/daemon/src/args.rs
@@ -115,4 +115,14 @@ pub struct NetsimdArgs {
     /// Print Netsimd version information
     #[arg(long)]
     pub version: bool,
+
+    /// Set RSSI (in dBm) for all links on a specified PhyKind.
+    /// Accepts `PHY_KIND:RSSI_VALUE` (e.g., `BLE:-65`).
+    /// This flag can be specified multiple times for different PhyKinds (e.g., `--rssi=bt_classic:-65 --rssi=ble:-72`).
+    /// `PHY_KIND` is case-insensitive (aliases like "ble" supported). `RSSI_VALUE` must be an i8.
+    ///
+    /// # Limitations
+    /// * RSSI control is currently implemented for BLE and BT_CLASSIC only.
+    #[arg(long, value_name = "PHY_KIND:RSSI_VALUE", action = clap::ArgAction::Append, verbatim_doc_comment)]
+    pub rssi: Option<Vec<String>>,
 }
diff --git a/rust/daemon/src/captures/captures_handler.rs b/rust/daemon/src/captures/captures_handler.rs
index 3c111b16..c19b975f 100644
--- a/rust/daemon/src/captures/captures_handler.rs
+++ b/rust/daemon/src/captures/captures_handler.rs
@@ -29,10 +29,10 @@
 use bytes::Bytes;
 use http::Request;
 use log::warn;
-use netsim_common::util::time_display::TimeDisplay;
+use netsim_common::util::{proto_print_options::JSON_PRINT_OPTION, time_display::TimeDisplay};
 use netsim_proto::common::ChipKind;
 use netsim_proto::frontend::ListCaptureResponse;
-use protobuf_json_mapping::{print_to_string_with_options, PrintOptions};
+use protobuf_json_mapping::print_to_string_with_options;
 use std::fs::File;
 use std::io::{Read, Result};
 use std::time::{SystemTime, UNIX_EPOCH};
@@ -49,12 +49,6 @@ use super::PCAP_MIME_TYPE;
 
 /// Max Chunk length of capture file during get_capture
 pub const CHUNK_LEN: usize = 1024;
-const JSON_PRINT_OPTION: PrintOptions = PrintOptions {
-    enum_values_int: false,
-    proto_field_name: false,
-    always_output_default_values: true,
-    _future_options: (),
-};
 
 /// Helper function for getting file name from the given fields.
 fn get_file(id: ChipIdentifier, device_name: String, chip_kind: ChipKind) -> Result<File> {
diff --git a/rust/daemon/src/devices/devices_handler.rs b/rust/daemon/src/devices/devices_handler.rs
index b57c9d1b..dbc87d42 100644
--- a/rust/daemon/src/devices/devices_handler.rs
+++ b/rust/daemon/src/devices/devices_handler.rs
@@ -30,9 +30,12 @@ use crate::events::{
     ChipAdded, ChipRemoved, DeviceAdded, DevicePatched, DeviceRemoved, Event, Events, ShutDown,
 };
 use crate::http_server::server_response::ResponseWritable;
+use crate::links::link::{LinkManager, PhyKind};
+use crate::ranging;
 use crate::wireless;
 use http::Request;
 use log::{info, warn};
+use netsim_common::util::proto_print_options::JSON_PRINT_OPTION;
 use netsim_proto::common::ChipKind as ProtoChipKind;
 use netsim_proto::frontend::patch_device_request::PatchDeviceFields as ProtoPatchDeviceFields;
 use netsim_proto::frontend::CreateDeviceRequest;
@@ -45,15 +48,15 @@ use netsim_proto::model::chip_create::Chip as ProtoBuiltin;
 use netsim_proto::model::Chip as ProtoChip;
 use netsim_proto::model::Device as ProtoDevice;
 use netsim_proto::model::Orientation as ProtoOrientation;
+use netsim_proto::model::PhyKind as ProtoPhyKind; // For ProtoPhyKind
 use netsim_proto::model::Position as ProtoPosition;
 use netsim_proto::startup::DeviceInfo as ProtoDeviceInfo;
 use netsim_proto::stats::{NetsimDeviceStats as ProtoDeviceStats, NetsimRadioStats};
 use protobuf::well_known_types::timestamp::Timestamp;
-use protobuf::MessageField;
+use protobuf::{Enum, MessageField};
 use protobuf_json_mapping::merge_from_str;
 use protobuf_json_mapping::print_to_string;
 use protobuf_json_mapping::print_to_string_with_options;
-use protobuf_json_mapping::PrintOptions;
 use std::collections::{BTreeMap, HashMap};
 use std::sync::atomic::{AtomicU32, Ordering};
 use std::sync::mpsc::Receiver;
@@ -66,12 +69,6 @@ use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
 static IDLE_SECS_FOR_SHUTDOWN: u64 = 15;
 
 const INITIAL_DEVICE_ID: u32 = 1;
-const JSON_PRINT_OPTION: PrintOptions = PrintOptions {
-    enum_values_int: false,
-    proto_field_name: false,
-    always_output_default_values: true,
-    _future_options: (),
-};
 
 static POSE_MANAGER: OnceLock<Arc<PoseManager>> = OnceLock::new();
 
@@ -135,18 +132,19 @@ pub struct DeviceManager {
     events: Arc<Events>,
     ids: AtomicU32,
     last_modified: RwLock<Duration>,
+    pub link_manager: Arc<LinkManager>,
 }
 
 impl DeviceManager {
-    pub fn init(events: Arc<Events>) -> Arc<DeviceManager> {
-        let manager = Arc::new(Self::new(events));
+    pub fn init(events: Arc<Events>, link_manager: Arc<LinkManager>) -> Arc<DeviceManager> {
+        let manager = Arc::new(Self::new(events, link_manager));
         if let Err(_e) = DEVICE_MANAGER.set(manager.clone()) {
             panic!("Error setting device manager");
         }
         manager
     }
 
-    fn new(events: Arc<Events>) -> Self {
+    fn new(events: Arc<Events>, link_manager: Arc<LinkManager>) -> Self {
         DeviceManager {
             devices: RwLock::new(BTreeMap::new()),
             events,
@@ -154,6 +152,7 @@ impl DeviceManager {
             last_modified: RwLock::new(
                 SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards"),
             ),
+            link_manager,
         }
     }
 
@@ -270,6 +269,8 @@ pub fn remove_chip(device_id: DeviceIdentifier, chip_id: ChipIdentifier) -> Resu
     let mut guard = manager.devices.write().unwrap();
     let device =
         guard.get(&device_id).ok_or(format!("RemoveChip device id {device_id} not found"))?;
+    // Delete any links associated with this chip before removing it
+    manager.link_manager.delete_link_for_chip(chip_id);
     let radio_stats = device.remove_chip(&chip_id)?;
 
     let mut device_id_to_remove = None;
@@ -564,34 +565,32 @@ fn distance(a: &ProtoPosition, b: &ProtoPosition) -> f32 {
     ((b.x - a.x).powf(2.0) + (b.y - a.y).powf(2.0) + (b.z - a.z).powf(2.0)).sqrt()
 }
 
-#[allow(dead_code)]
-fn get_distance(id: &ChipIdentifier, other_id: &ChipIdentifier) -> Result<f32, String> {
-    let device_id = crate::devices::chip::get_chip(id)
-        .ok_or(format!("No such device with chip_id {id}"))?
-        .device_id;
-    let other_device_id = crate::devices::chip::get_chip(other_id)
-        .ok_or(format!("No such device with chip_id {other_id}"))?
-        .device_id;
-
-    let pose_manager = get_pose_manager();
-    let a = pose_manager
-        .get_position(&device_id)
-        .ok_or(format!("no position for device {device_id}"))?;
-    let b = pose_manager
-        .get_position(&other_device_id)
-        .ok_or(format!("no position for device {other_device_id}"))?;
-    Ok(distance(&a, &b))
+/// Gets the position of a chip identified by its ID.
+/// Returns None if the chip or its device/position cannot be found.
+fn get_position(chip_id: ChipIdentifier) -> Option<ProtoPosition> {
+    let chip = chip::get_chip(&chip_id).or_else(|| {
+        warn!("get_position error for chip {}: No such device", chip_id.0);
+        None
+    })?;
+
+    let pos = get_pose_manager().get_position(&chip.device_id).or_else(|| {
+        warn!(
+            "get_position error for chip {}: no position for device {}",
+            chip_id.0, chip.device_id
+        );
+        None
+    })?;
+
+    Some(pos)
 }
 
-/// A GetDistance function for Rust Device API.
-/// The backend gRPC code will be invoking this method.
-pub fn get_distance_cxx(a: u32, b: u32) -> f32 {
-    match get_distance(&ChipIdentifier(a), &ChipIdentifier(b)) {
-        Ok(distance) => distance,
-        Err(err) => {
-            warn!("get_distance Error: {err}");
-            0.0
-        }
+/// Calculates the distance between two chips identified by their IDs.
+/// Returns 0.0 if either chip or its device/position cannot be found.
+fn get_distance(a: u32, b: u32) -> f32 {
+    // Calculate distance only if both positions were successfully found.
+    match (get_position(ChipIdentifier(a)), get_position(ChipIdentifier(b))) {
+        (Some(pos_a), Some(pos_b)) => distance(&pos_a, &pos_b),
+        _ => 0.0, // Error already logged by get_position
     }
 }
 
@@ -622,6 +621,8 @@ pub fn reset_all() -> Result<(), String> {
     for device_id in device_ids {
         get_pose_manager().reset(device_id);
     }
+    // Reset all links
+    manager.link_manager.reset();
     // Update last modified timestamp for manager
     manager.update_timestamp();
     manager.events.publish(Event::DeviceReset);
@@ -878,6 +879,35 @@ pub fn get_radio_stats() -> Vec<NetsimRadioStats> {
     result
 }
 
+/// A GetRssi function for Rust Device API.
+/// Checks for RSSI override settings before calculating based on distance.
+/// The backend gRPC code will be invoking this method via FFI.
+pub fn get_rssi(sender_id: u32, receiver_id: u32, link_kind_i32: i32, tx_power: i8) -> i8 {
+    let proto_link_kind = ProtoPhyKind::from_i32(link_kind_i32).unwrap_or_default();
+    let link_kind = match PhyKind::try_from(proto_link_kind) {
+        Ok(kind) => kind,
+        Err(e) => {
+            warn!(
+                "FFI: Error converting ProtoPhyKind {:?} to internal: {}. Defaulting to None.",
+                proto_link_kind, e
+            );
+            PhyKind::None
+        }
+    };
+    // Check for link RSSI setting first.
+    if let Some(override_rssi) = get_manager().link_manager.get_rssi(
+        ChipIdentifier(sender_id),
+        ChipIdentifier(receiver_id),
+        link_kind,
+    ) {
+        info!("Using RSSI override for sender {sender_id} and receiver {receiver_id}: {override_rssi}",);
+        return override_rssi;
+    }
+
+    // Fallback to distance calculation
+    ranging::distance_to_rssi(tx_power, get_distance(sender_id, receiver_id))
+}
+
 #[cfg(test)]
 mod tests {
     use http::Version;
@@ -898,7 +928,7 @@ mod tests {
     fn module_setup() {
         INIT.call_once(|| {
             init_for_test();
-            DeviceManager::init(Events::new());
+            DeviceManager::init(Events::new(), LinkManager::new().into());
         });
     }
 
@@ -1488,7 +1518,7 @@ mod tests {
 
         // Verify the get_distance performs the correct computation of
         // sqrt((1-1)**2 + (4-1)**2 + (5-1)**2)
-        assert_eq!(Ok(5.0), get_distance(&bt_chip_result.chip_id, &bt_chip_2_result.chip_id))
+        assert_eq!(5.0, get_distance(bt_chip_result.chip_id.0, bt_chip_2_result.chip_id.0))
     }
 
     #[allow(dead_code)]
diff --git a/rust/daemon/src/ffi.rs b/rust/daemon/src/ffi.rs
index f123e870..dabc1230 100644
--- a/rust/daemon/src/ffi.rs
+++ b/rust/daemon/src/ffi.rs
@@ -17,9 +17,7 @@
 use crate::bluetooth::chip::{
     create_add_rust_device_result, AddRustDeviceResult, RustBluetoothChipCallbacks,
 };
-
-use crate::devices::devices_handler::get_distance_cxx;
-use crate::ranging::*;
+use crate::devices::devices_handler::get_rssi;
 use crate::wireless::{
     bluetooth::report_invalid_packet_cxx, handle_request_cxx, handle_response_cxx,
 };
@@ -197,24 +195,14 @@ pub mod ffi_bluetooth {
     }
 }
 
-#[allow(clippy::needless_maybe_sized)]
-#[allow(unsafe_op_in_unsafe_fn)]
-#[cxx::bridge(namespace = "netsim::device")]
-pub mod ffi_devices {
-    extern "Rust" {
-        #[cxx_name = GetDistanceCxx]
-        fn get_distance_cxx(a: u32, b: u32) -> f32;
-    }
-}
-
 #[allow(unsafe_op_in_unsafe_fn)]
 #[cxx::bridge(namespace = "netsim")]
 pub mod ffi_util {
     extern "Rust" {
         // Ranging
 
-        #[cxx_name = "DistanceToRssi"]
-        fn distance_to_rssi(tx_power: i8, distance: f32) -> i8;
+        #[cxx_name = "GetRssi"]
+        fn get_rssi(sender: u32, receiver: u32, link_kind: i32, tx_power: i8) -> i8;
     }
 
     #[allow(dead_code)]
diff --git a/rust/daemon/src/grpc_server/frontend.rs b/rust/daemon/src/grpc_server/frontend.rs
index 97054fb9..464aee18 100644
--- a/rust/daemon/src/grpc_server/frontend.rs
+++ b/rust/daemon/src/grpc_server/frontend.rs
@@ -15,17 +15,85 @@
 use crate::captures::captures_handler;
 use crate::devices::chip::ChipIdentifier;
 use crate::devices::devices_handler;
+use crate::links::link::{Link, LinkManager, PhyKind};
 use futures_util::{FutureExt as _, SinkExt as _, TryFutureExt as _};
 use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink, WriteFlags};
 use log::warn;
-use netsim_proto::frontend::VersionResponse;
+use netsim_proto::frontend::{
+    DeleteLinkRequest, ListLinkResponse, PatchLinkRequest, VersionResponse,
+};
 use netsim_proto::frontend_grpc::FrontendService;
+use netsim_proto::model::{Link as ProtoLink, PhyKind as ProtoPhyKind};
 use protobuf::well_known_types::empty::Empty;
 
 use std::io::Read;
+use std::sync::Arc;
 
 #[derive(Clone)]
-pub struct FrontendClient;
+pub struct FrontendClient {
+    link_manager: Arc<LinkManager>,
+}
+
+impl FrontendClient {
+    pub fn new(link_manager: Arc<LinkManager>) -> Self {
+        FrontendClient { link_manager }
+    }
+}
+
+/// Processes and validates fields from a Link protobuf message.
+///
+/// This function ensures:
+/// 1. The `link` field is present.
+/// 2. `link_kind` is specific (not `PhyKind::NONE`).
+///
+/// Returns a tuple of (sender_id, receiver_id, link_kind, rssi) if valid,
+/// otherwise an `RpcStatus` indicating the error.
+fn process_link_data(
+    link_opt: Option<&ProtoLink>,
+) -> Result<(ChipIdentifier, ChipIdentifier, PhyKind, i32), RpcStatus> {
+    let link_ref = link_opt.ok_or_else(|| {
+        RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, "Missing link field".to_string())
+    })?;
+
+    let proto_link_kind = link_ref.link_kind.enum_value_or_default();
+    if proto_link_kind == ProtoPhyKind::NONE {
+        return Err(RpcStatus::with_message(
+            RpcStatusCode::INVALID_ARGUMENT,
+            "Specific link_kind (other than NONE) must be provided for link".to_string(),
+        ));
+    }
+
+    let link_kind = PhyKind::try_from(proto_link_kind)
+        .map_err(|e| RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, e.to_string()))?;
+
+    Ok((
+        ChipIdentifier(link_ref.sender_id),
+        ChipIdentifier(link_ref.receiver_id),
+        link_kind,
+        link_ref.rssi,
+    ))
+}
+
+fn validate_patch_link_request(
+    req: &PatchLinkRequest,
+) -> Result<(ChipIdentifier, ChipIdentifier, PhyKind, i8), RpcStatus> {
+    let (sender_id, receiver_id, link_kind, rssi_opt) = process_link_data(req.link.0.as_deref())?;
+    // Validate and convert RSSI
+    let rssi_i8: i8 = rssi_opt.try_into().map_err(|_| {
+        RpcStatus::with_message(
+            RpcStatusCode::INVALID_ARGUMENT,
+            format!("RSSI value {} is out of range for i8 [{}, {}]", rssi_opt, i8::MIN, i8::MAX),
+        )
+    })?;
+    Ok((sender_id, receiver_id, link_kind, rssi_i8))
+}
+
+fn validate_delete_link_request(
+    req: &DeleteLinkRequest,
+) -> Result<(ChipIdentifier, ChipIdentifier, PhyKind), RpcStatus> {
+    let (sender_id, receiver_id, link_kind, _rssi_opt) = process_link_data(req.link.0.as_deref())?;
+    Ok((sender_id, receiver_id, link_kind))
+}
 
 impl FrontendService for FrontendClient {
     fn get_version(&mut self, ctx: RpcContext<'_>, req: Empty, sink: UnarySink<VersionResponse>) {
@@ -213,4 +281,65 @@ impl FrontendService for FrontendClient {
 
         ctx.spawn(response.map_err(move |e| warn!("client error: {:?}", e)).map(|_| ()))
     }
+
+    fn patch_link(
+        &mut self,
+        ctx: grpcio::RpcContext,
+        req: PatchLinkRequest,
+        sink: grpcio::UnarySink<Empty>,
+    ) {
+        // Validate request data
+        let validated_data = validate_patch_link_request(&req);
+        let response = match validated_data {
+            Ok((sender_id, receiver_id, link_kind, rssi)) => {
+                self.link_manager.set_rssi(sender_id, receiver_id, link_kind, rssi);
+                sink.success(Empty::new())
+            }
+            Err(status) => {
+                warn!("Invalid patch link request: {}", status.message());
+                sink.fail(status)
+            }
+        };
+
+        ctx.spawn(response.map_err(move |e| log::error!("client sink error: {:?}", e)).map(|_| ()))
+    }
+
+    fn delete_link(
+        &mut self,
+        ctx: grpcio::RpcContext,
+        req: DeleteLinkRequest,
+        sink: grpcio::UnarySink<Empty>,
+    ) {
+        let validated_data = validate_delete_link_request(&req);
+
+        let response = match validated_data {
+            Ok((sender_id, receiver_id, link_kind)) => {
+                if self.link_manager.delete_rssi(sender_id, receiver_id, link_kind) {
+                    sink.success(Empty::new())
+                } else {
+                    let msg = format!("Failed to delete link with sender: {sender_id}, receiver: {receiver_id}, link_kind: {link_kind:?}");
+                    warn!("{}", msg);
+                    sink.fail(RpcStatus::with_message(RpcStatusCode::NOT_FOUND, msg))
+                }
+            }
+            Err(status) => {
+                warn!("Invalid delete link request: {}", status.message());
+                sink.fail(status)
+            }
+        };
+
+        ctx.spawn(response.map_err(move |e| warn!("client error: {:?}", e)).map(|_| ()))
+    }
+
+    fn list_link(
+        &mut self,
+        ctx: grpcio::RpcContext,
+        req: Empty,
+        sink: grpcio::UnarySink<ListLinkResponse>,
+    ) {
+        let links: Vec<Link> = self.link_manager.list();
+        let proto_links: Vec<ProtoLink> = links.into_iter().map(ProtoLink::from).collect();
+        let response = sink.success(ListLinkResponse { links: proto_links, ..Default::default() });
+        ctx.spawn(response.map_err(move |e| warn!("client error {:?}: {:?}", req, e)).map(|_| ()))
+    }
 }
diff --git a/rust/daemon/src/grpc_server/server.rs b/rust/daemon/src/grpc_server/server.rs
index 7d81164e..9796ebeb 100644
--- a/rust/daemon/src/grpc_server/server.rs
+++ b/rust/daemon/src/grpc_server/server.rs
@@ -14,6 +14,7 @@
 
 use super::backend::PacketStreamerService;
 use super::frontend::FrontendClient;
+use crate::links::link::LinkManager;
 use grpcio::{
     ChannelBuilder, Environment, ResourceQuota, Server, ServerBuilder, ServerCredentials,
 };
@@ -22,10 +23,15 @@ use netsim_proto::frontend_grpc::create_frontend_service;
 use netsim_proto::packet_streamer_grpc::create_packet_streamer;
 use std::sync::Arc;
 
-pub fn start(port: u32, no_cli_ui: bool, _vsock: u16) -> anyhow::Result<(Server, u16)> {
+pub fn start(
+    port: u32,
+    no_cli_ui: bool,
+    link_manager: Arc<LinkManager>,
+    _vsock: u16,
+) -> anyhow::Result<(Server, u16)> {
     let env = Arc::new(Environment::new(1));
     let backend_service = create_packet_streamer(PacketStreamerService);
-    let frontend_service = create_frontend_service(FrontendClient);
+    let frontend_service = create_frontend_service(FrontendClient::new(link_manager));
     let quota = ResourceQuota::new(Some("NetsimGrpcServerQuota")).resize_memory(1024 * 1024);
     let ch_builder = ChannelBuilder::new(env.clone()).set_resource_quota(quota).reuse_port(false);
     let mut server_builder = ServerBuilder::new(env);
diff --git a/rust/daemon/src/http_server/http_handlers.rs b/rust/daemon/src/http_server/http_handlers.rs
index 1f61c981..7b7e16d7 100644
--- a/rust/daemon/src/http_server/http_handlers.rs
+++ b/rust/daemon/src/http_server/http_handlers.rs
@@ -29,6 +29,10 @@ use log::warn;
 use crate::{
     captures::captures_handler::handle_capture,
     devices::devices_handler::handle_device,
+    links::{
+        link::LinkManager,
+        links_handler::{handle_link_delete, handle_link_list, handle_link_patch},
+    },
     transport::websocket::{handle_websocket, run_websocket_transport},
     version::VERSION,
 };
@@ -137,7 +141,12 @@ fn handle_dev(request: &Request<Vec<u8>>, _param: &str, writer: ResponseWritable
     handle_file(request.method().as_str(), "dev.html", writer)
 }
 
-pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>>, dev: bool) {
+pub fn handle_connection(
+    mut stream: TcpStream,
+    valid_files: Arc<HashSet<String>>,
+    dev: bool,
+    link_manager: Arc<LinkManager>,
+) {
     let mut router = Router::new();
     router.add_route(Uri::from_static("/"), Box::new(handle_index));
     router.add_route(Uri::from_static("/version"), Box::new(handle_version));
@@ -145,7 +154,9 @@ pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>
     router.add_route(Uri::from_static(r"/v1/devices/{id}"), Box::new(handle_device));
     router.add_route(Uri::from_static("/v1/captures"), Box::new(handle_capture));
     router.add_route(Uri::from_static(r"/v1/captures/{id}"), Box::new(handle_capture));
-    router.add_route(Uri::from_static(r"/v1/websocket/{radio}"), Box::new(handle_websocket));
+    if std::env::var("NETSIM_WS_PORT").is_err() {
+        router.add_route(Uri::from_static(r"/v1/websocket/{radio}"), Box::new(handle_websocket));
+    }
 
     // Adding additional routes in dev mode.
     if dev {
@@ -174,6 +185,36 @@ pub fn handle_connection(mut stream: TcpStream, valid_files: Arc<HashSet<String>
         )
     }
 
+    // A closure for checking if path is link, and call methods in links_handler accordingly
+    let handle_link_wrapper = move |request: &Request<Vec<u8>>,
+                                    _path: &str,
+                                    writer: ResponseWritable| {
+        match request.method().as_str() {
+            "LIST" => match handle_link_list(&link_manager) {
+                Ok(response) => writer.put_ok("text/json", &response, vec![]),
+                Err(e) => writer.put_error(404, &e),
+            },
+            "PATCH" => {
+                let body = request.body();
+                let patch_json = String::from_utf8(body.to_vec()).unwrap();
+                match handle_link_patch(&link_manager, &patch_json) {
+                    Ok(response) => writer.put_ok("text/plain", &response, vec![]),
+                    Err(e) => writer.put_error(404, &e),
+                }
+            }
+            "DELETE" => {
+                let body = request.body();
+                let delete_json = String::from_utf8(body.to_vec()).unwrap();
+                match handle_link_delete(&link_manager, &delete_json) {
+                    Ok(response) => writer.put_ok("text/plain", &response, vec![]),
+                    Err(e) => writer.put_error(404, &e),
+                }
+            }
+            _ => writer.put_error(404, "Unsupported request method"),
+        }
+    };
+    router.add_route(Uri::from_static(r"/v1/link"), Box::new(handle_link_wrapper.clone()));
+
     if let Ok(request) = parse_http_request::<&TcpStream>(&mut BufReader::new(&stream)) {
         let mut response_writer = ServerResponseWriter::new(&mut stream);
         router.handle_request(&request, &mut response_writer);
diff --git a/rust/daemon/src/http_server/mod.rs b/rust/daemon/src/http_server/mod.rs
index 4913f7cc..3d6b5a95 100644
--- a/rust/daemon/src/http_server/mod.rs
+++ b/rust/daemon/src/http_server/mod.rs
@@ -17,4 +17,4 @@ pub(crate) mod http_request;
 mod http_router;
 pub(crate) mod server;
 pub(crate) mod server_response;
-mod thread_pool;
+pub(crate) mod thread_pool;
diff --git a/rust/daemon/src/http_server/server.rs b/rust/daemon/src/http_server/server.rs
index 3bf94d1d..4d9c07d2 100644
--- a/rust/daemon/src/http_server/server.rs
+++ b/rust/daemon/src/http_server/server.rs
@@ -15,6 +15,7 @@
 use crate::http_server::http_handlers::{create_filename_hash_set, handle_connection};
 
 use crate::http_server::thread_pool::ThreadPool;
+use crate::links::link::LinkManager;
 use log::{info, warn};
 use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
 use std::sync::Arc;
@@ -32,7 +33,7 @@ fn bind_listener(http_port: u16) -> Result<TcpListener, std::io::Error> {
 }
 
 /// Start the HTTP Server.
-pub fn run_http_server(instance_num: u16, dev: bool) -> u16 {
+pub fn run_http_server(instance_num: u16, dev: bool, link_manager: Arc<LinkManager>) -> u16 {
     let http_port = DEFAULT_HTTP_PORT + instance_num - 1;
     let _ = thread::Builder::new().name("http_server".to_string()).spawn(move || {
         let listener = match bind_listener(http_port) {
@@ -48,8 +49,9 @@ pub fn run_http_server(instance_num: u16, dev: bool) -> u16 {
         for stream in listener.incoming() {
             let stream = stream.unwrap();
             let valid_files = valid_files.clone();
+            let link_manager_clone = Arc::clone(&link_manager);
             pool.execute(move || {
-                handle_connection(stream, valid_files, dev);
+                handle_connection(stream, valid_files, dev, link_manager_clone);
             });
         }
         info!("Shutting down frontend http server.");
diff --git a/rust/daemon/src/lib.rs b/rust/daemon/src/lib.rs
index 5e94a8ff..ebf2339f 100644
--- a/rust/daemon/src/lib.rs
+++ b/rust/daemon/src/lib.rs
@@ -33,6 +33,8 @@ mod events;
 mod ffi;
 mod grpc_server;
 mod http_server;
+mod links;
+mod proto_mapping;
 mod ranging;
 mod resource;
 mod rust_main;
@@ -41,6 +43,7 @@ mod session;
 mod transport;
 mod uwb;
 mod version;
+mod websocket_server;
 mod wifi;
 mod wireless;
 
diff --git a/rust/daemon/src/links/link.rs b/rust/daemon/src/links/link.rs
new file mode 100644
index 00000000..6a0acb7a
--- /dev/null
+++ b/rust/daemon/src/links/link.rs
@@ -0,0 +1,487 @@
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
+//! Link library
+
+use crate::devices::chip::ChipIdentifier;
+use log::info;
+use std::collections::HashMap;
+use std::sync::RwLock;
+
+/// Wildcard chip ID for global RSSI is defined as 0.
+pub const ANY_CHIP: ChipIdentifier = ChipIdentifier(0);
+
+/// Internal representation of Physical Layer Kind.
+#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
+pub enum PhyKind {
+    None,
+    BluetoothClassic,
+    BluetoothLowEnergy,
+    Wifi,
+    Uwb,
+    WifiRtt,
+}
+
+/// Internal representation of a Link.
+#[derive(Debug, Clone)]
+pub struct Link {
+    pub sender_id: ChipIdentifier,
+    pub receiver_id: ChipIdentifier,
+    pub link_kind: PhyKind,
+    pub rssi: i8,
+}
+
+/// Manages link properties.
+pub struct LinkManager {
+    rssi: RwLock<HashMap<(ChipIdentifier, ChipIdentifier, PhyKind), i8>>,
+}
+
+impl Default for LinkManager {
+    fn default() -> Self {
+        Self::new()
+    }
+}
+
+impl LinkManager {
+    /// Creates a new LinkManager.
+    pub fn new() -> Self {
+        LinkManager { rssi: RwLock::new(HashMap::new()) }
+    }
+
+    /// List all current links.
+    pub fn list(&self) -> Vec<Link> {
+        self.rssi
+            .read()
+            .unwrap()
+            .iter()
+            .map(|((sender_id, receiver_id, link_kind), rssi)| Link {
+                sender_id: *sender_id,
+                receiver_id: *receiver_id,
+                link_kind: *link_kind,
+                rssi: *rssi,
+            })
+            .collect()
+    }
+
+    /// Sets or updates an RSSI between two chips.
+    pub fn set_rssi(
+        &self,
+        sender: ChipIdentifier,
+        receiver: ChipIdentifier,
+        link_kind: PhyKind,
+        rssi: i8,
+    ) {
+        self.rssi.write().unwrap().insert((sender, receiver, link_kind), rssi);
+        info!(
+            "Set RSSI between sender {} and receiver {} on {:?}: {}",
+            sender, receiver, link_kind, rssi
+        );
+    }
+
+    /// Gets the RSSI setting on the specified link if one exists.
+    /// This checks for RSSI setting in the following order of precedence:
+    /// 1. Exact match: (sender, receiver, phy_kind)
+    /// 2. Sender specific, receiver wildcard: (sender, ANY_CHIP, phy_kind)
+    /// 3. Receiver specific, sender wildcard: (ANY_CHIP, receiver, phy_kind)
+    /// 4. Global wildcard: (ANY_CHIP, ANY_CHIP, phy_kind)
+    pub fn get_rssi(
+        &self,
+        sender: ChipIdentifier,
+        receiver: ChipIdentifier,
+        link_kind: PhyKind,
+    ) -> Option<i8> {
+        let map = self.rssi.read().unwrap();
+
+        // Define checks in order of precedence
+        let keys_to_check = [
+            (sender, receiver, link_kind),   // 1. Exact match
+            (sender, ANY_CHIP, link_kind),   // 2. Sender specific, receiver wildcard
+            (ANY_CHIP, receiver, link_kind), // 3. Receiver specific, sender wildcard
+            (ANY_CHIP, ANY_CHIP, link_kind), // 4. Global wildcard
+        ];
+
+        for key in keys_to_check {
+            if let Some(rssi_val) = map.get(&key) {
+                return Some(*rssi_val);
+            }
+        }
+        None
+    }
+
+    /// Deletes an RSSI between two chips for a specific PhyKind.
+    /// Returns true if an RSSI was removed, false otherwise.
+    pub fn delete_rssi(
+        &self,
+        sender: ChipIdentifier,
+        receiver: ChipIdentifier,
+        link_kind: PhyKind,
+    ) -> bool {
+        let removed = self.rssi.write().unwrap().remove(&(sender, receiver, link_kind)).is_some();
+        if removed {
+            info!(
+                "Deleted RSSI between sender {} and receiver {} on {:?}",
+                sender, receiver, link_kind
+            );
+        }
+        removed
+    }
+
+    /// Delete all link properties associated with a specific chip.
+    pub fn delete_link_for_chip(&self, chip_id: ChipIdentifier) {
+        let mut rssis = self.rssi.write().unwrap();
+        let initial_count = rssis.len();
+        rssis.retain(|(sender, receiver, _), _| *sender != chip_id && *receiver != chip_id);
+        let removed_count = initial_count - rssis.len();
+        if removed_count > 0 {
+            info!("Removed {} RSSI(s) associated with chip {}", removed_count, chip_id);
+        }
+    }
+
+    /// Reset all link properties.
+    pub fn reset(&self) {
+        let mut rssis = self.rssi.write().unwrap();
+        let initial_count = rssis.len();
+        if initial_count > 0 {
+            rssis.clear();
+            info!("Cleared all {} RSSI(s).", initial_count);
+        }
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_set_and_get_rssi() {
+        let link_manager = LinkManager::new();
+
+        let sender = ChipIdentifier(1);
+        let receiver = ChipIdentifier(2);
+        let phy_kind_ble = PhyKind::BluetoothLowEnergy;
+        let phy_kind_wifi = PhyKind::Wifi;
+        let rssi_ble = -50;
+        let rssi_wifi = -60;
+
+        // Initially, no rssi set
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_ble), None);
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_wifi), None);
+
+        // Set BLE RSSI
+        link_manager.set_rssi(sender, receiver, phy_kind_ble, rssi_ble);
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_ble), Some(rssi_ble));
+        // WiFi RSSI should still be None for this pair with a different PhyKind
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_wifi), None);
+
+        // Set WiFi RSSI for the same pair
+        link_manager.set_rssi(sender, receiver, phy_kind_wifi, rssi_wifi);
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_ble), Some(rssi_ble)); // BLE should persist
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_wifi), Some(rssi_wifi));
+
+        // Set an existing value again
+        let new_rssi_ble = -55;
+        link_manager.set_rssi(sender, receiver, phy_kind_ble, new_rssi_ble);
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_kind_ble), Some(new_rssi_ble));
+
+        // Check non-existent pair
+        let other_sender = ChipIdentifier(3);
+        assert_eq!(link_manager.get_rssi(other_sender, receiver, phy_kind_ble), None);
+    }
+
+    #[test]
+    fn test_get_rssi_with_wildcards() {
+        let link_manager = LinkManager::new();
+
+        let s1 = ChipIdentifier(1);
+        let r1 = ChipIdentifier(2);
+        let r2 = ChipIdentifier(3);
+        let phy_ble = PhyKind::BluetoothLowEnergy;
+
+        // Precedence: (S,R) > (S,*) > (*,R) > (*,*)
+        link_manager.set_rssi(ANY_CHIP, ANY_CHIP, phy_ble, -40); // (*,*)
+        assert_eq!(link_manager.get_rssi(s1, r1, phy_ble), Some(-40));
+        link_manager.set_rssi(ANY_CHIP, r1, phy_ble, -30); // (*,R1)
+        assert_eq!(link_manager.get_rssi(s1, r1, phy_ble), Some(-30));
+        link_manager.set_rssi(s1, ANY_CHIP, phy_ble, -20); // (S1,*)
+        assert_eq!(link_manager.get_rssi(s1, r1, phy_ble), Some(-20)); // (S1,*) takes precedence over (*,R1) for (S1,R1)
+        assert_eq!(link_manager.get_rssi(s1, r2, phy_ble), Some(-20)); // (S1,R2) matches (S1,*)
+        link_manager.set_rssi(s1, r1, phy_ble, -10); // (S1,R1) - most specific
+        assert_eq!(link_manager.get_rssi(s1, r1, phy_ble), Some(-10));
+    }
+
+    #[test]
+    fn test_list_links() {
+        let link_manager = LinkManager::new();
+
+        assert!(link_manager.list().is_empty(), "Initially, links should be empty");
+
+        let s1 = ChipIdentifier(1);
+        let r1 = ChipIdentifier(2);
+        let phy1 = PhyKind::BluetoothLowEnergy;
+        let rssi1 = -50;
+        link_manager.set_rssi(s1, r1, phy1, rssi1);
+
+        let s2 = ChipIdentifier(3);
+        let r2 = ChipIdentifier(4);
+        let phy2 = PhyKind::Wifi;
+        let rssi2 = -60;
+        link_manager.set_rssi(s2, r2, phy2, rssi2);
+
+        // Same sender/receiver as the first, but different PhyKind
+        let phy3 = PhyKind::Uwb;
+        let rssi3 = -70;
+        link_manager.set_rssi(s1, r1, phy3, rssi3);
+
+        let links = link_manager.list();
+        assert_eq!(links.len(), 3, "Should have 3 links");
+
+        // Order isn't guaranteed, so check for presence of each link
+        assert!(
+            links.iter().any(|link| link.sender_id == s1
+                && link.receiver_id == r1
+                && link.link_kind == phy1
+                && link.rssi == rssi1),
+            "Link 1 (s1,r1,phy1) not found or incorrect"
+        );
+        assert!(
+            links.iter().any(|link| link.sender_id == s2
+                && link.receiver_id == r2
+                && link.link_kind == phy2
+                && link.rssi == rssi2),
+            "Link 2 (s2,r2,phy2) not found or incorrect"
+        );
+        assert!(
+            links.iter().any(|link| link.sender_id == s1
+                && link.receiver_id == r1
+                && link.link_kind == phy3
+                && link.rssi == rssi3),
+            "Link 3 (s1,r1,phy3) not found or incorrect"
+        );
+    }
+
+    #[test]
+    fn test_delete_rssi() {
+        let link_manager = LinkManager::new();
+
+        let sender = ChipIdentifier(1);
+        let receiver = ChipIdentifier(2);
+        let phy_ble = PhyKind::BluetoothLowEnergy;
+        let phy_wifi = PhyKind::Wifi;
+        let rssi_ble = -50;
+        let rssi_wifi = -60;
+
+        link_manager.set_rssi(sender, receiver, phy_ble, rssi_ble);
+        link_manager.set_rssi(sender, receiver, phy_wifi, rssi_wifi);
+        link_manager.set_rssi(ChipIdentifier(3), receiver, phy_ble, -70); // Another link
+
+        link_manager.set_rssi(sender, ANY_CHIP, phy_ble, -80); // Wildcard link for sender
+
+        assert_eq!(link_manager.list().len(), 4, "Should have 4 links initially");
+        assert_eq!(
+            link_manager.get_rssi(sender, ChipIdentifier(99), phy_ble),
+            Some(-80),
+            "Wildcard (S,*) should apply"
+        );
+
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_ble), Some(rssi_ble));
+        assert_eq!(link_manager.get_rssi(sender, receiver, phy_wifi), Some(rssi_wifi));
+
+        // Try to delete a non-existent sender/receiver pair for a specific PhyKind
+        assert!(!link_manager.delete_rssi(ChipIdentifier(10), ChipIdentifier(11), phy_ble));
+        assert_eq!(
+            link_manager.list().len(),
+            4,
+            "Deleting non-existent pair should not change link count"
+        );
+
+        // Try to delete for a PhyKind that doesn't exist for this pair
+        assert!(!link_manager.delete_rssi(sender, receiver, PhyKind::Uwb));
+        assert_eq!(
+            link_manager.list().len(),
+            4,
+            "Deleting non-existent PhyKind for existing pair should not change link count"
+        );
+
+        // Delete the BLE RSSI for (sender, receiver). WiFi RSSI should remain.
+        assert!(
+            link_manager.delete_rssi(sender, receiver, phy_ble),
+            "Deletion of existing BLE RSSI should return true"
+        );
+        assert_eq!(
+            link_manager.get_rssi(sender, receiver, phy_ble),
+            Some(-80),
+            "BLE RSSI should now fall back to (S,*)"
+        );
+        assert_eq!(
+            link_manager.get_rssi(sender, receiver, phy_wifi),
+            Some(rssi_wifi),
+            "WiFi RSSI should still exist"
+        );
+        assert_eq!(
+            link_manager.list().len(),
+            3,
+            "Remaining links: (S,R,WiFi), (3,R,BLE), (S,*,BLE)"
+        );
+
+        // Try deleting the BLE RSSI again, should return false as it's already removed
+        assert!(
+            !link_manager.delete_rssi(sender, receiver, phy_ble),
+            "Deleting already removed BLE RSSI should return false"
+        );
+
+        // Delete the WiFi RSSI
+        assert!(
+            link_manager.delete_rssi(sender, receiver, phy_wifi),
+            "Deletion of existing WiFi RSSI should return true"
+        );
+        assert_eq!(
+            link_manager.get_rssi(sender, receiver, phy_wifi),
+            None,
+            "WiFi RSSI should be gone"
+        );
+        assert_eq!(link_manager.list().len(), 2, "Remaining links: (3,R,BLE), (S,*,BLE)");
+
+        // Delete the wildcard RSSI (S, *, BLE)
+        assert!(
+            link_manager.delete_rssi(sender, ANY_CHIP, phy_ble),
+            "Deleting (S,*,BLE) should return true"
+        );
+        assert_eq!(
+            link_manager.get_rssi(sender, ChipIdentifier(99), phy_ble),
+            None,
+            "(S,*) RSSI should be gone"
+        );
+        // If a global (*,*) existed, it would be picked up here. Since it doesn't:
+        assert_eq!(
+            link_manager.get_rssi(sender, receiver, phy_ble),
+            None,
+            "No BLE RSSI should remain for (S,R)"
+        );
+        assert_eq!(link_manager.list().len(), 1, "Only the (3,R,BLE) link should remain");
+    }
+
+    #[test]
+    fn test_delete_link_for_chip() {
+        let link_manager = LinkManager::new();
+
+        let chip1 = ChipIdentifier(1);
+        let chip2 = ChipIdentifier(2);
+        let chip3 = ChipIdentifier(3);
+        let phy_ble = PhyKind::BluetoothLowEnergy;
+        let phy_wifi = PhyKind::Wifi;
+
+        // Set up some RSSIs
+        link_manager.set_rssi(chip1, chip2, phy_ble, -50); // Involves chip1 (sender)
+        link_manager.set_rssi(chip2, chip1, phy_wifi, -55); // Involves chip1 (receiver)
+        link_manager.set_rssi(chip1, chip3, phy_ble, -60); // Involves chip1 (sender)
+        link_manager.set_rssi(chip3, chip1, phy_wifi, -65); // Involves chip1 (receiver)
+        link_manager.set_rssi(chip2, chip3, phy_ble, -70); // Does NOT involve chip1 (C2->C3)
+        link_manager.set_rssi(ANY_CHIP, chip1, phy_ble, -75); // (*->C1) Involves chip1
+        link_manager.set_rssi(chip1, ANY_CHIP, phy_wifi, -80); // (C1->*) Involves chip1
+        link_manager.set_rssi(ANY_CHIP, ANY_CHIP, phy_ble, -85); // (*->*) Does NOT involve chip1 specifically
+
+        assert_eq!(link_manager.list().len(), 8, "Initial number of links should be 8");
+
+        link_manager.delete_link_for_chip(chip1);
+
+        let remaining_links = link_manager.list();
+        assert_eq!(remaining_links.len(), 2, "Expected (C2->C3) and (*,*) to remain");
+
+        assert!(
+            remaining_links.iter().any(|link| link.sender_id == chip2
+                && link.receiver_id == chip3
+                && link.link_kind == phy_ble
+                && link.rssi == -70),
+            "Link (C2->C3, BLE, -70) not found in remaining links: {:?}",
+            remaining_links
+        );
+
+        assert!(
+            remaining_links.iter().any(|link| link.sender_id == ANY_CHIP
+                && link.receiver_id == ANY_CHIP
+                && link.link_kind == phy_ble
+                && link.rssi == -85),
+            "Global wildcard link (*,*, BLE, -85) not found in remaining links: {:?}",
+            remaining_links
+        );
+        assert_eq!(
+            link_manager.get_rssi(ChipIdentifier(98), ChipIdentifier(99), phy_ble),
+            Some(-85),
+            "Global wildcard should be active"
+        );
+
+        assert_eq!(link_manager.get_rssi(chip1, chip2, phy_ble), Some(-85)); // Fallback to global wildcard entry
+        assert_eq!(link_manager.get_rssi(chip2, chip1, phy_wifi), None);
+        assert_eq!(link_manager.get_rssi(chip1, chip3, phy_ble), Some(-85)); // Fallback to global wildcard entry
+        assert_eq!(link_manager.get_rssi(chip3, chip1, phy_wifi), None);
+        assert_eq!(
+            link_manager.get_rssi(ANY_CHIP, chip1, phy_ble),
+            Some(-85),
+            "(*->C1) should be gone"
+        );
+        assert_eq!(
+            link_manager.get_rssi(chip1, ANY_CHIP, phy_wifi),
+            None,
+            "(C1->*) should be gone"
+        );
+
+        assert_eq!(link_manager.get_rssi(chip2, chip3, phy_ble), Some(-70));
+
+        link_manager.delete_link_for_chip(ChipIdentifier(99));
+        assert_eq!(link_manager.list().len(), 2, "Removing RSSI's for a chip not involved should not change link count (should be 2: C2->C3 and *,*)");
+
+        link_manager.reset();
+        link_manager.set_rssi(chip1, chip2, phy_ble, -50);
+        link_manager.set_rssi(chip1, ANY_CHIP, phy_ble, -55);
+        link_manager.set_rssi(ANY_CHIP, chip2, phy_ble, -60);
+        link_manager.set_rssi(ANY_CHIP, ANY_CHIP, phy_ble, -65);
+        assert_eq!(link_manager.list().len(), 4);
+
+        link_manager.delete_link_for_chip(ANY_CHIP);
+        assert_eq!(link_manager.get_rssi(chip1, chip2, phy_ble), Some(-50));
+    }
+
+    #[test]
+    fn test_reset() {
+        let link_manager = LinkManager::new();
+
+        let sender = ChipIdentifier(1);
+        let receiver = ChipIdentifier(2);
+        let phy_kind_ble = PhyKind::BluetoothLowEnergy;
+        let phy_kind_wifi = PhyKind::Wifi;
+
+        link_manager.set_rssi(sender, receiver, phy_kind_ble, -50);
+        link_manager.set_rssi(ChipIdentifier(3), ChipIdentifier(4), phy_kind_wifi, -60);
+        assert!(!link_manager.list().is_empty(), "Links should exist before clearing");
+
+        link_manager.reset();
+        assert!(link_manager.list().is_empty(), "All links should be cleared");
+        assert_eq!(
+            link_manager.get_rssi(sender, receiver, phy_kind_ble),
+            None,
+            "Specific RSSI should be gone after clear"
+        );
+        assert_eq!(
+            link_manager.get_rssi(ChipIdentifier(3), ChipIdentifier(4), phy_kind_wifi),
+            None,
+            "Another specific RSSI should be gone"
+        );
+
+        link_manager.reset();
+        assert!(
+            link_manager.list().is_empty(),
+            "Links should remain empty after clearing an already empty set"
+        );
+    }
+}
diff --git a/rust/daemon/src/links/links_handler.rs b/rust/daemon/src/links/links_handler.rs
new file mode 100644
index 00000000..17992683
--- /dev/null
+++ b/rust/daemon/src/links/links_handler.rs
@@ -0,0 +1,153 @@
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
+//! link_handlers for REST API to call
+
+use std::sync::Arc;
+
+use netsim_common::util::proto_print_options::JSON_PRINT_OPTION;
+use netsim_proto::{
+    frontend::{DeleteLinkRequest, ListLinkResponse, PatchLinkRequest},
+    model,
+};
+use protobuf_json_mapping::{merge_from_str, print_to_string_with_options};
+
+use crate::devices::chip::ChipIdentifier;
+
+use super::link::{LinkManager, PhyKind};
+
+pub fn handle_link_list(link_manager: &Arc<LinkManager>) -> Result<String, String> {
+    let mut response = ListLinkResponse::new();
+    for link in link_manager.list() {
+        response.links.push(model::Link {
+            sender_id: link.sender_id.0,
+            receiver_id: link.receiver_id.0,
+            link_kind: model::PhyKind::from(link.link_kind).into(),
+            rssi: link.rssi as i32,
+            ..Default::default()
+        });
+    }
+    print_to_string_with_options(&response, &JSON_PRINT_OPTION).map_err(|e| format!("{e}"))
+}
+
+pub fn handle_link_patch(
+    link_manager: &Arc<LinkManager>,
+    patch_json: &str,
+) -> Result<String, String> {
+    let mut patch_link_request = PatchLinkRequest::new();
+    if let Err(e) = merge_from_str(&mut patch_link_request, patch_json) {
+        return Err(format!("Incorrect format of patch link json: {e:?}"));
+    }
+    let sender = ChipIdentifier(patch_link_request.link.sender_id);
+    let receiver = ChipIdentifier(patch_link_request.link.receiver_id);
+    let link_kind =
+        PhyKind::try_from(patch_link_request.link.link_kind.enum_value_or_default()).unwrap();
+    let rssi = patch_link_request.link.rssi as i8;
+    link_manager.set_rssi(sender, receiver, link_kind, rssi);
+    Ok(format!("Successfully patched RSSI for link (Sender: {sender}, Receiver: {receiver}, Type: {link_kind:?}) to {rssi}."))
+}
+
+pub fn handle_link_delete(
+    link_manager: &Arc<LinkManager>,
+    delete_json: &str,
+) -> Result<String, String> {
+    let mut delete_link_request = DeleteLinkRequest::new();
+    if let Err(e) = merge_from_str(&mut delete_link_request, delete_json) {
+        return Err(format!("Incorrect format of patch delete json: {e:?}"));
+    }
+    let sender = ChipIdentifier(delete_link_request.link.sender_id);
+    let receiver = ChipIdentifier(delete_link_request.link.receiver_id);
+    let link_kind =
+        PhyKind::try_from(delete_link_request.link.link_kind.enum_value_or_default()).unwrap();
+    link_manager.delete_rssi(sender, receiver, link_kind);
+    Ok(format!("Successfully deleted RSSI for link (Sender: {sender}, Receiver: {receiver}, Type: {link_kind:?})."))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::devices::chip::ChipIdentifier;
+
+    fn create_link_manager() -> Arc<LinkManager> {
+        let link_manager = LinkManager::new();
+        link_manager.set_rssi(
+            ChipIdentifier(1),
+            ChipIdentifier(2),
+            PhyKind::BluetoothLowEnergy,
+            -50,
+        );
+        Arc::new(link_manager)
+    }
+
+    #[test]
+    fn test_handle_link_list() {
+        let link_manager = create_link_manager();
+        let result = handle_link_list(&link_manager);
+        assert!(result.is_ok());
+        assert_eq!(
+            result.unwrap(),
+            r#"{"links": [{"senderId": 1, "receiverId": 2, "linkKind": "BLUETOOTH_LOW_ENERGY", "rssi": -50}]}"#
+        );
+    }
+
+    #[test]
+    fn test_handle_link_patch() {
+        let link_manager = create_link_manager();
+        let patch_json = r#"{"link": {"senderId": 1, "receiverId": 2, "linkKind": "BLUETOOTH_LOW_ENERGY", "rssi": -60}}"#;
+        let result = handle_link_patch(&link_manager, patch_json);
+        assert!(result.is_ok());
+        assert_eq!(
+            result.unwrap(),
+            "Successfully patched RSSI for link (Sender: 1, Receiver: 2, Type: BluetoothLowEnergy) to -60."
+        );
+        let rssi = link_manager.get_rssi(
+            ChipIdentifier(1),
+            ChipIdentifier(2),
+            PhyKind::BluetoothLowEnergy,
+        );
+        assert_eq!(rssi, Some(-60));
+    }
+
+    #[test]
+    fn test_handle_link_patch_invalid_json() {
+        let link_manager = create_link_manager();
+        let patch_json = r#"{invalid_json}"#;
+        let result = handle_link_patch(&link_manager, patch_json);
+        assert!(result.is_err());
+        assert!(result.unwrap_err().starts_with("Incorrect format of patch link json"));
+    }
+
+    #[test]
+    fn test_handle_link_delete() {
+        let link_manager = create_link_manager();
+        let delete_json =
+            r#"{"link": {"senderId": 1, "receiverId": 2, "linkKind": "BLUETOOTH_LOW_ENERGY"}}"#;
+        let result = handle_link_delete(&link_manager, delete_json);
+        assert!(result.is_ok());
+        assert_eq!(
+            result.unwrap(),
+            "Successfully deleted RSSI for link (Sender: 1, Receiver: 2, Type: BluetoothLowEnergy)."
+        );
+        assert_eq!(link_manager.list().len(), 0);
+    }
+
+    #[test]
+    fn test_handle_link_delete_invalid_json() {
+        let link_manager = create_link_manager();
+        let delete_json = r#"{invalid_json}"#;
+        let result = handle_link_delete(&link_manager, delete_json);
+        assert!(result.is_err());
+        assert!(result.unwrap_err().starts_with("Incorrect format of patch delete json"));
+    }
+}
diff --git a/rust/daemon/src/links/mod.rs b/rust/daemon/src/links/mod.rs
new file mode 100644
index 00000000..3d69c4e6
--- /dev/null
+++ b/rust/daemon/src/links/mod.rs
@@ -0,0 +1,16 @@
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
+pub(crate) mod link;
+pub(crate) mod links_handler;
diff --git a/rust/daemon/src/proto_mapping.rs b/rust/daemon/src/proto_mapping.rs
new file mode 100644
index 00000000..4165f5f5
--- /dev/null
+++ b/rust/daemon/src/proto_mapping.rs
@@ -0,0 +1,80 @@
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
+//! Centralized conversion logic between Protobuf and internal types.
+
+use crate::links::link::{Link as InternalLink, PhyKind as InternalPhyKind};
+use netsim_proto::model::{Link as ProtoLink, PhyKind as ProtoPhyKind};
+use protobuf::EnumOrUnknown;
+
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub struct ProtoConversionError(String);
+
+impl std::fmt::Display for ProtoConversionError {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "Protobuf conversion error: {}", self.0)
+    }
+}
+impl std::error::Error for ProtoConversionError {}
+
+// --- PhyKind Conversions ---
+
+impl TryFrom<ProtoPhyKind> for InternalPhyKind {
+    type Error = ProtoConversionError;
+
+    fn try_from(proto_kind: ProtoPhyKind) -> Result<Self, Self::Error> {
+        match proto_kind {
+            ProtoPhyKind::NONE => Ok(InternalPhyKind::None),
+            ProtoPhyKind::BLUETOOTH_CLASSIC => Ok(InternalPhyKind::BluetoothClassic),
+            ProtoPhyKind::BLUETOOTH_LOW_ENERGY => Ok(InternalPhyKind::BluetoothLowEnergy),
+            ProtoPhyKind::WIFI => Ok(InternalPhyKind::Wifi),
+            ProtoPhyKind::UWB => Ok(InternalPhyKind::Uwb),
+            ProtoPhyKind::WIFI_RTT => Ok(InternalPhyKind::WifiRtt),
+        }
+    }
+}
+
+impl From<InternalPhyKind> for ProtoPhyKind {
+    fn from(internal_kind: InternalPhyKind) -> Self {
+        match internal_kind {
+            InternalPhyKind::None => ProtoPhyKind::NONE,
+            InternalPhyKind::BluetoothClassic => ProtoPhyKind::BLUETOOTH_CLASSIC,
+            InternalPhyKind::BluetoothLowEnergy => ProtoPhyKind::BLUETOOTH_LOW_ENERGY,
+            InternalPhyKind::Wifi => ProtoPhyKind::WIFI,
+            InternalPhyKind::Uwb => ProtoPhyKind::UWB,
+            InternalPhyKind::WifiRtt => ProtoPhyKind::WIFI_RTT,
+        }
+    }
+}
+
+// Helper for converting to EnumOrUnknown<ProtoPhyKind> which is used in ProtoLink
+impl From<InternalPhyKind> for EnumOrUnknown<ProtoPhyKind> {
+    fn from(internal_kind: InternalPhyKind) -> Self {
+        EnumOrUnknown::new(ProtoPhyKind::from(internal_kind))
+    }
+}
+
+// --- Link Conversions ---
+
+impl From<InternalLink> for ProtoLink {
+    fn from(internal_link: InternalLink) -> Self {
+        ProtoLink {
+            sender_id: internal_link.sender_id.0,
+            receiver_id: internal_link.receiver_id.0,
+            link_kind: internal_link.link_kind.into(), // Uses From<InternalPhyKind> for EnumOrUnknown
+            rssi: internal_link.rssi as i32,
+            ..Default::default()
+        }
+    }
+}
diff --git a/rust/daemon/src/rust_main.rs b/rust/daemon/src/rust_main.rs
index fdbcc190..12a920e7 100644
--- a/rust/daemon/src/rust_main.rs
+++ b/rust/daemon/src/rust_main.rs
@@ -27,6 +27,7 @@ use crate::captures::capture::spawn_capture_event_subscriber;
 use crate::config_file;
 use crate::devices::devices_handler::{spawn_shutdown_publisher, DeviceManager};
 use crate::events::{Event, Events, ShutDown};
+use crate::links::link::{LinkManager, PhyKind, ANY_CHIP};
 use crate::session::Session;
 use crate::version::get_version;
 use crate::wireless;
@@ -40,6 +41,7 @@ use netsim_proto::config::{Bluetooth as BluetoothConfig, Capture, Config};
 use std::env;
 use std::ffi::{c_char, c_int};
 use std::sync::mpsc::Receiver;
+use std::sync::Arc;
 
 /// Wireless network simulator for android (and other) emulated devices.
 ///
@@ -208,6 +210,59 @@ fn disambiguate_args(args: &mut NetsimdArgs, config: &mut Config) {
     };
 }
 
+/// Parses a single "PHY_KIND=RSSI_VALUE" string and sets the global RSSI.
+fn parse_and_set_rssi(link_manager: &Arc<LinkManager>, rssi_str: &str) -> Result<(), String> {
+    let parts: Vec<&str> = rssi_str.split(':').collect();
+    if parts.len() != 2 {
+        return Err(format!(
+            "Invalid RSSI default format: '{}'. Expected PHY_KIND:RSSI_VALUE",
+            rssi_str
+        ));
+    }
+
+    let phy_kind_input_str = parts[0].trim();
+    let rssi_input_str = parts[1].trim();
+    let phy_kind_str = phy_kind_input_str.to_uppercase();
+
+    // Match the uppercased input string against a list of known aliases and full names
+    // for PhyKind. This is case-insensitive due to the to_uppercase() call.
+    let phy_kind = match phy_kind_str.as_str() {
+        "BLE" | "BT_LE" | "BLUETOOTH_LOW_ENERGY" => Ok(PhyKind::BluetoothLowEnergy),
+        "CLASSIC" | "BT_CLASSIC" | "BLUETOOTH_CLASSIC" => Ok(PhyKind::BluetoothClassic),
+        "WIFI" => Ok(PhyKind::Wifi),
+        "UWB" => Ok(PhyKind::Uwb),
+        "WIFIRTT" | "WIFI_RTT" => Ok(PhyKind::WifiRtt),
+        "NONE" => Ok(PhyKind::None),
+        _ => Err(format!("Invalid or unhandled PhyKind string: '{}'", phy_kind_input_str)),
+    }?;
+
+    let rssi_value = rssi_input_str.parse::<i8>().map_err(|e| {
+        format!(
+            "Invalid RSSI for {}: '{}'. Expected i8 ({} to {}). Error: {}",
+            phy_kind_input_str,
+            rssi_input_str,
+            i8::MIN,
+            i8::MAX,
+            e
+        )
+    })?;
+    info!("Setting global RSSI default: {:?} = {}", phy_kind, rssi_value);
+
+    link_manager.set_rssi(ANY_CHIP, ANY_CHIP, phy_kind, rssi_value);
+    Ok(())
+}
+
+/// Processes the `rssi` command line arguments and configures the LinkManager.
+fn process_rssi_arg(rssi_opt: &Option<Vec<String>>, link_manager: &Arc<LinkManager>) {
+    if let Some(rssi) = rssi_opt {
+        for rssi_str in rssi {
+            if let Err(e) = parse_and_set_rssi(link_manager, rssi_str) {
+                panic!("{}", e);
+            }
+        }
+    }
+}
+
 fn run_netsimd_primary(mut args: NetsimdArgs) {
     info!(
         "Netsim Version: {}, OS: {}, Arch: {}",
@@ -265,12 +320,13 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     let device_events_rx = events.subscribe();
     let main_events_rx = events.subscribe();
     let session_events_rx = events.subscribe();
-
-    DeviceManager::init(events.clone());
+    let link_manager = Arc::new(LinkManager::new());
+    process_rssi_arg(&args.rssi, &link_manager);
+    DeviceManager::init(events.clone(), link_manager.clone());
 
     // Start radio facades
     wireless::bluetooth::bluetooth_start(&config.bluetooth, instance_num);
-    wireless::wifi_manager::wifi_start(
+    let wifi_stats = wireless::wifi_manager::wifi_start(
         &config.wifi,
         args.forward_host_mdns,
         args.wifi,
@@ -291,19 +347,21 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
 
     // SAFETY: The caller guaranteed that the file descriptors in `fd_startup_str` would remain
     // valid and open for as long as the program runs.
-    let mut service = unsafe { Service::new(service_params) };
+    let mut service = unsafe { Service::new(service_params, link_manager) };
 
     // Run all netsimd services (grpc, socket, web)
     match service.run() {
         Err(e) => {
             error!("service.run() -> Err({e:?})");
+            error!("Failed to run netsimd services, exiting...");
+            service.shut_down();
             return;
         }
-        Ok((grpc_port, web_port)) => {
+        Ok((grpc_port, web_port, websocket_port)) => {
             // If create_ini fails, check if there is another netsimd instance.
             // If there isn't another netsimd instance, remove_ini and create_ini once more.
             for _ in 0..2 {
-                if let Err(e) = create_ini(instance_num, grpc_port, web_port) {
+                if let Err(e) = create_ini(instance_num, grpc_port, web_port, websocket_port) {
                     warn!("create_ini error with {e:?}");
                     // Continue if the address overlaps to support Oxygen CF Boot.
                     // The pre-warmed device may leave stale netsim ini with the same grpc port.
@@ -337,7 +395,7 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
 
     // Start Session Event listener
     let mut session = Session::new();
-    session.start(session_events_rx);
+    session.start(session_events_rx, wifi_stats.clone());
 
     // Pass all event receivers to each modules
     let capture = config.capture.enabled.unwrap_or_default();
@@ -360,7 +418,7 @@ fn run_netsimd_primary(mut args: NetsimdArgs) {
     service.shut_down();
 
     // write out session stats
-    let _ = session.stop();
+    let _ = session.stop(wifi_stats);
 
     // zip all artifacts
     if let Err(err) = zip_artifacts() {
diff --git a/rust/daemon/src/service.rs b/rust/daemon/src/service.rs
index 9d418ffb..7559e27f 100644
--- a/rust/daemon/src/service.rs
+++ b/rust/daemon/src/service.rs
@@ -17,17 +17,20 @@
 use crate::bluetooth::advertise_settings as ble_advertise_settings;
 use crate::captures::captures_handler::clear_pcap_files;
 use crate::http_server::server::run_http_server;
+use crate::links::link::LinkManager;
 use crate::transport::socket::run_socket_transport;
+use crate::websocket_server::run_websocket_server;
 use crate::wireless;
 use log::{error, info, warn};
 use netsim_common::util::zip_artifact::remove_zip_files;
-use std::env;
 use std::time::Duration;
+use std::{env, sync::Arc};
 
 /// Module to control startup, run, and cleanup netsimd services.
 
 type GrpcPort = u32;
 type WebPort = Option<u16>;
+type WebSocketPort = Option<u16>;
 
 pub struct ServiceParams {
     fd_startup_str: String,
@@ -57,6 +60,7 @@ impl ServiceParams {
 pub struct Service {
     // netsimd states, like device resource.
     service_params: ServiceParams,
+    link_manager: Arc<LinkManager>,
     grpc_server: Option<grpcio::Server>,
 }
 
@@ -65,8 +69,8 @@ impl Service {
     ///
     /// The file descriptors in `service_params.fd_startup_str` must be valid and open, and must
     /// remain so for as long as the `Service` exists.
-    pub unsafe fn new(service_params: ServiceParams) -> Service {
-        Service { service_params, grpc_server: None }
+    pub unsafe fn new(service_params: ServiceParams, link_manager: Arc<LinkManager>) -> Service {
+        Service { service_params, link_manager, grpc_server: None }
     }
 
     /// Remove old artifacts
@@ -92,6 +96,7 @@ impl Service {
         let (server, port) = crate::grpc_server::server::start(
             netsim_grpc_port,
             self.service_params.no_cli_ui,
+            self.link_manager.clone(),
             self.service_params.vsock,
         )?;
         self.grpc_server = Some(server);
@@ -104,16 +109,18 @@ impl Service {
         // If NETSIM_NO_WEB_SERVER is set, don't start http server.
         let no_web_server = env::var("NETSIM_NO_WEB_SERVER").is_ok_and(|v| v == "1");
         match !no_web_server && !self.service_params.no_web_ui {
-            true => {
-                Some(run_http_server(self.service_params.instance_num, self.service_params.dev))
-            }
+            true => Some(run_http_server(
+                self.service_params.instance_num,
+                self.service_params.dev,
+                self.link_manager.clone(),
+            )),
             false => None,
         }
     }
 
     /// Runs the netsimd services.
     #[allow(unused_unsafe)]
-    pub fn run(&mut self) -> anyhow::Result<(GrpcPort, WebPort)> {
+    pub fn run(&mut self) -> anyhow::Result<(GrpcPort, WebPort, WebSocketPort)> {
         if !self.service_params.fd_startup_str.is_empty() {
             // SAFETY: When the `Service` was constructed by `Service::new` the caller guaranteed
             // that the file descriptors in `service_params.fd_startup_str` would remain valid and
@@ -135,10 +142,15 @@ impl Service {
         // Run frontend web server
         let web_port = self.run_web_server();
 
+        // Run the websocket server.
+        let websocket_port = run_websocket_server(self.service_params.instance_num)
+            .map_err(|e| warn!("run_websocket_server error: {e}"))
+            .ok();
+
         // Run the socket server.
         run_socket_transport(self.service_params.hci_port);
 
-        Ok((grpc_port, web_port))
+        Ok((grpc_port, web_port, websocket_port))
     }
 
     /// Shut down the netsimd services
diff --git a/rust/daemon/src/session.rs b/rust/daemon/src/session.rs
index 1c06f74e..8b8f93c6 100644
--- a/rust/daemon/src/session.rs
+++ b/rust/daemon/src/session.rs
@@ -22,6 +22,8 @@ use log::error;
 use log::info;
 use netsim_common::system::netsimd_temp_dir;
 use netsim_proto::stats::NetsimStats as ProtoNetsimStats;
+use netsim_proto::stats::WifiStats as ProtoWifiStats;
+use protobuf::MessageField;
 use protobuf_json_mapping::print_to_string;
 use std::fs::File;
 use std::io::Write;
@@ -72,7 +74,11 @@ impl Session {
     //
     // Starts the session monitor thread to handle events and
     // write session stats to json file on event and periodically.
-    pub fn start(&mut self, events_rx: Receiver<Event>) -> &mut Self {
+    pub fn start<T>(&mut self, events_rx: Receiver<Event>, wifi_stats: T) -> &mut Self
+    where
+        T: Send + Sync + 'static,
+        for<'a> &'a T: Into<ProtoWifiStats>,
+    {
         let info = Arc::clone(&self.info);
 
         // Start up session monitor thread
@@ -148,7 +154,8 @@ impl Session {
                         if write_stats {
                             update_session_duration(&mut lock);
                             if lock.write_json {
-                                let current_stats = get_current_stats(lock.stats_proto.clone());
+                                let current_stats =
+                                    get_current_stats(lock.stats_proto.clone(), &wifi_stats);
                                 if let Err(err) = write_stats_to_json(current_stats) {
                                     error!("Failed to write stats to json: {err:?}");
                                 }
@@ -166,7 +173,10 @@ impl Session {
     //
     // Waits for the session monitor thread to finish and writes
     // the session proto to a json file. Consumes the session.
-    pub fn stop(mut self) -> anyhow::Result<()> {
+    pub fn stop<T>(mut self, wifi_stats: T) -> anyhow::Result<()>
+    where
+        for<'a> &'a T: Into<ProtoWifiStats>,
+    {
         if !self.handle.as_ref().expect("no session monitor").is_finished() {
             info!("session monitor active, waiting...");
         }
@@ -176,7 +186,7 @@ impl Session {
 
         let lock = self.info.read().expect("Could not acquire session lock");
         if lock.write_json {
-            let current_stats = get_current_stats(lock.stats_proto.clone());
+            let current_stats = get_current_stats(lock.stats_proto.clone(), &wifi_stats);
             write_stats_to_json(current_stats)?;
         }
         Ok(())
@@ -190,8 +200,12 @@ fn update_session_duration(session_lock: &mut RwLockWriteGuard<'_, SessionInfo>)
 }
 
 /// Construct current radio stats
-fn get_current_stats(mut current_stats: ProtoNetsimStats) -> ProtoNetsimStats {
+fn get_current_stats<T>(mut current_stats: ProtoNetsimStats, wifi_stats: &T) -> ProtoNetsimStats
+where
+    for<'a> &'a T: Into<ProtoWifiStats>,
+{
     current_stats.radio_stats.extend(get_radio_stats());
+    current_stats.wifi_stats = MessageField::some(wifi_stats.into());
     current_stats
 }
 
@@ -211,6 +225,7 @@ mod tests {
     use crate::devices::chip::ChipIdentifier;
     use crate::devices::device::DeviceIdentifier;
     use crate::events::{ChipAdded, ChipRemoved, DeviceRemoved, Event, Events, ShutDown};
+    use crate::wifi::stats::WifiStats;
     use netsim_proto::stats::{
         NetsimDeviceStats as ProtoDeviceStats, NetsimRadioStats as ProtoRadioStats,
     };
@@ -232,10 +247,11 @@ mod tests {
     }
 
     fn setup_session_start_test() -> (Session, Arc<Events>) {
+        let wifi_stats = WifiStats::default();
         let mut session = Session::new_internal(false);
         let events = Events::new();
         let events_rx = events.subscribe();
-        session.start(events_rx);
+        session.start(events_rx, wifi_stats);
         (session, events)
     }
 
@@ -269,6 +285,7 @@ mod tests {
 
     #[test]
     fn test_start_and_stop() {
+        let wifi_stats = WifiStats::default();
         let (session, events) = setup_session_start_test();
 
         // we want to be able to check the session time gets incremented
@@ -278,7 +295,7 @@ mod tests {
         events.publish(Event::ShutDown(ShutDown { reason: "Stop the session".to_string() }));
 
         // should not panic or deadlock
-        session.stop().unwrap();
+        session.stop(wifi_stats).unwrap();
     }
 
     // Tests for session.rs involving devices
diff --git a/rust/daemon/src/transport/websocket.rs b/rust/daemon/src/transport/websocket.rs
index 525d478e..6a60d97d 100644
--- a/rust/daemon/src/transport/websocket.rs
+++ b/rust/daemon/src/transport/websocket.rs
@@ -35,7 +35,7 @@ use super::h4;
 use crate::openssl;
 
 /// Generate Sec-Websocket-Accept value from given Sec-Websocket-Key value
-fn generate_websocket_accept(websocket_key: String) -> String {
+pub fn generate_websocket_accept(websocket_key: String) -> String {
     let concat = websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
     let hashed = openssl::sha::sha1(concat.as_bytes());
     data_encoding::BASE64.encode(&hashed)
@@ -73,6 +73,7 @@ struct WebSocketTransport {
 }
 
 impl Response for WebSocketTransport {
+    #[allow(clippy::useless_conversion)]
     fn response(&mut self, packet: Bytes, packet_type: u8) {
         let mut buffer = Vec::new();
         buffer.push(packet_type);
@@ -81,7 +82,7 @@ impl Response for WebSocketTransport {
             .websocket_writer
             .lock()
             .expect("Failed to acquire lock on WebSocket")
-            .send(Message::Binary(buffer))
+            .send(Message::Binary(buffer.into()))
         {
             error!("{err}");
         };
diff --git a/rust/daemon/src/uwb/ranging_data.rs b/rust/daemon/src/uwb/ranging_data.rs
index 9c11d3cf..c463696a 100644
--- a/rust/daemon/src/uwb/ranging_data.rs
+++ b/rust/daemon/src/uwb/ranging_data.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use rand::{prelude::SliceRandom, rngs::ThreadRng, thread_rng};
+use rand::{prelude::*, rngs::ThreadRng, thread_rng};
 
 use std::collections::BTreeMap;
 
diff --git a/rust/daemon/src/version.rs b/rust/daemon/src/version.rs
index a4ec2b2c..c2f4be5f 100644
--- a/rust/daemon/src/version.rs
+++ b/rust/daemon/src/version.rs
@@ -16,7 +16,7 @@
 
 /// Version library.
 
-pub const VERSION: &str = "0.3.50";
+pub const VERSION: &str = "0.3.60";
 
 pub fn get_version() -> String {
     VERSION.to_owned()
diff --git a/rust/daemon/src/websocket_server.rs b/rust/daemon/src/websocket_server.rs
new file mode 100644
index 00000000..505d0815
--- /dev/null
+++ b/rust/daemon/src/websocket_server.rs
@@ -0,0 +1,209 @@
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
+use crate::http_server::thread_pool::ThreadPool;
+use crate::transport::websocket::{generate_websocket_accept, run_websocket_transport};
+
+use anyhow::Result;
+use http::{Response, StatusCode};
+use log::{info, warn};
+use std::collections::HashMap;
+use std::io::{Read, Write};
+use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
+
+static TARGET_PATH: &str = "/v1/websocket/bt";
+
+fn bind_listener(websocket_port: u16) -> Result<TcpListener> {
+    Ok(TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, websocket_port)))
+        .or_else(|e| {
+            warn!("Failed to bind to 127.0.0.1:{websocket_port} in netsimd frontend http server. Trying [::1]:{websocket_port}. {e:?}");
+            TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, websocket_port)))
+        })?)
+}
+
+fn handle_websocket(req: &httparse::Request) -> Result<Response<Vec<u8>>> {
+    info!("{:?}", req.headers);
+    let websocket_accept =
+        match req.headers.iter().find(|header| header.name.to_lowercase() == "sec-websocket-key") {
+            Some(header) => {
+                let key_str: &str = core::str::from_utf8(header.value)?;
+                generate_websocket_accept(key_str.to_string())
+            }
+            None => {
+                return Err(anyhow::anyhow!("Missing Sec-Websocket-Key in header"));
+            }
+        };
+    Ok(Response::builder()
+        .status(StatusCode::SWITCHING_PROTOCOLS)
+        .header("Upgrade", "websocket")
+        .header("Sec-WebSocket-Accept", websocket_accept)
+        .header("Connection", "Upgrade")
+        .body(Vec::new())?)
+}
+
+fn handle_connection(mut stream: TcpStream) -> Result<()> {
+    // HTTP Request Parsing
+    let mut buffer = vec![0u8; 2048];
+    // Use blocking read from std::io::Read
+    let bytes_read = stream.read(&mut buffer)?;
+    if bytes_read == 0 {
+        warn!("Client disconnected before sending data.");
+        return Ok(());
+    }
+
+    let mut headers = [httparse::EMPTY_HEADER; 64];
+    let mut req = httparse::Request::new(&mut headers);
+    let parse_status = req.parse(&buffer[..bytes_read])?;
+
+    if parse_status.is_partial() {
+        warn!("Request too large for buffer or incomplete.");
+        // Use blocking write_all and flush from std::io::Write
+        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
+        stream.flush()?;
+        return Ok(());
+    }
+
+    // Endpoint Validation
+    let path_str = match req.path {
+        Some(p) => p,
+        None => {
+            warn!("No path in request.");
+            // Use blocking write_all and flush
+            stream.write_all(
+                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
+            )?;
+            stream.flush()?;
+            return Err(anyhow::anyhow!("HTTP request path is missing"));
+        }
+    };
+    let (base_path, query_string_opt) = match path_str.split_once('?') {
+        Some((path, query)) => (path, Some(query)),
+        None => (path_str, None),
+    };
+
+    if base_path != TARGET_PATH {
+        warn!("Invalid path in request: {base_path}");
+        let response_str =
+            "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string();
+        // Use blocking write_all and flush
+        stream.write_all(response_str.as_bytes())?;
+        stream.flush()?;
+        return Ok(()); // Request handled (rejected), not a server error
+    }
+
+    // Parse optional query
+    let mut queries = HashMap::new();
+    if let Some(query_string) = query_string_opt {
+        if !query_string.is_empty() {
+            for pair in query_string.split('&') {
+                if pair.is_empty() {
+                    continue;
+                }
+                if let Some((key, value)) = pair.split_once('=') {
+                    // Note: In a real application, you'd want to URL-decode keys and values
+                    queries.insert(key, value);
+                }
+            }
+        }
+    }
+
+    // Proceed Websocket header check using the synchronous handler
+    let websocket_response = handle_websocket(&req)?;
+
+    if websocket_response.status() == StatusCode::SWITCHING_PROTOCOLS {
+        let status = websocket_response.status();
+        let headers = websocket_response.headers();
+        let body = websocket_response.body();
+        let status_line =
+            format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
+        stream.write_all(status_line.as_bytes())?;
+        for (name, value) in headers.iter() {
+            let header_line = format!("{}: {}\r\n", name, value.to_str()?);
+            stream.write_all(header_line.as_bytes())?;
+        }
+        stream.write_all(b"\r\n")?;
+        stream.write_all(body)?;
+        stream.flush()?;
+
+        // Now, the synchronous WebSocket transport takes over this blocking thread
+        run_websocket_transport(stream, queries);
+    } else {
+        // Send a bad request response if not a WebSocket upgrade
+        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
+        stream.flush()?;
+    }
+    Ok(())
+}
+
+pub fn run_websocket_server(instance_num: u16) -> Result<u16> {
+    let websocket_port = std::env::var("NETSIM_WS_PORT")?.parse::<u16>()? + instance_num - 1;
+    let _ = std::thread::Builder::new().name("ws_server".to_string()).spawn(move || {
+        let listener = match bind_listener(websocket_port) {
+            Ok(listener) => listener,
+            Err(e) => {
+                warn!("{e:?}");
+                return;
+            }
+        };
+        let pool = ThreadPool::new(4);
+        info!("Websocket server is listening on http://localhost:{websocket_port}");
+        for stream in listener.incoming() {
+            let stream = stream.unwrap();
+            pool.execute(move || {
+                let _ = handle_connection(stream).map_err(|e| warn!("{e:?}"));
+            })
+        }
+    });
+    Ok(websocket_port)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    use std::io::Cursor;
+
+    #[test]
+    fn test_handle_websocket_valid() {
+        let mut headers = [httparse::EMPTY_HEADER; 64];
+        let mut req = httparse::Request::new(&mut headers);
+        let request_str =
+            "GET /v1/websocket/bt HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
+        let buffer = Cursor::new(request_str.as_bytes());
+        let bytes_read = buffer.get_ref().len();
+        let parse_status = req.parse(&buffer.get_ref()[..bytes_read]).unwrap();
+        assert!(parse_status.is_complete());
+        let response = handle_websocket(&req).unwrap();
+        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
+        assert_eq!(response.headers().get("Upgrade").unwrap(), "websocket");
+        assert_eq!(
+            response.headers().get("Sec-WebSocket-Accept").unwrap(),
+            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
+        );
+        assert_eq!(response.headers().get("Connection").unwrap(), "Upgrade");
+    }
+
+    #[test]
+    fn test_handle_websocket_missing_key() {
+        let mut headers = [httparse::EMPTY_HEADER; 64];
+        let mut req = httparse::Request::new(&mut headers);
+        let request_str = "GET /v1/websocket/bt HTTP/1.1\r\n\r\n";
+        let buffer = Cursor::new(request_str.as_bytes());
+        let bytes_read = buffer.get_ref().len();
+        let parse_status = req.parse(&buffer.get_ref()[..bytes_read]).unwrap();
+        assert!(parse_status.is_complete());
+        let response = handle_websocket(&req);
+        assert!(response.is_err());
+    }
+}
diff --git a/rust/daemon/src/wifi/error.rs b/rust/daemon/src/wifi/error.rs
new file mode 100644
index 00000000..11ba6949
--- /dev/null
+++ b/rust/daemon/src/wifi/error.rs
@@ -0,0 +1,78 @@
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
+//! # Wi-Fi Error Handling
+//!
+//! This module defines the `WifiError` enum, which represents various error conditions that can occur
+//! within the Wi-Fi module. It also provides a `WifiResult` type alias for convenient error
+//! handling.
+use pdl_runtime::{DecodeError, EncodeError};
+
+#[derive(Debug, PartialEq, Eq, Hash, Clone)]
+pub enum WifiError {
+    /// Errors related to the hostapd.
+    Hostapd(String),
+    /// Errors related to network connectivity (e.g., slirp).
+    Network(String),
+    /// Errors related to client-specific operations or state.
+    Client(String),
+    /// Errors encountered while parsing, decoding, or handling IEEE 802.11 frames.
+    Frame(String),
+    /// Errors related to transmission or reception of frame.
+    Transmission(String),
+    /// Other uncategorized errors.
+    Other(String),
+}
+
+impl std::fmt::Display for WifiError {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            WifiError::Hostapd(msg) => write!(f, "Hostapd error: {}", msg),
+            WifiError::Network(msg) => write!(f, "Network error: {}", msg),
+            WifiError::Client(msg) => write!(f, "Client error: {}", msg),
+            WifiError::Frame(msg) => write!(f, "Frame error: {}", msg),
+            WifiError::Transmission(msg) => write!(f, "Transmission error: {}", msg),
+            WifiError::Other(msg) => write!(f, "Other error: {}", msg),
+        }
+    }
+}
+
+impl std::error::Error for WifiError {}
+
+#[cfg(not(feature = "cuttlefish"))]
+impl From<http_proxy::Error> for WifiError {
+    fn from(err: http_proxy::Error) -> Self {
+        WifiError::Network(format!("HTTP proxy error: {:?}", err))
+    }
+}
+
+impl From<std::io::Error> for WifiError {
+    fn from(err: std::io::Error) -> Self {
+        WifiError::Network(format!("IO error: {:?}", err))
+    }
+}
+
+impl From<DecodeError> for WifiError {
+    fn from(err: DecodeError) -> Self {
+        WifiError::Frame(format!("Frame decoding failed: {:?}", err))
+    }
+}
+
+impl From<EncodeError> for WifiError {
+    fn from(err: EncodeError) -> Self {
+        WifiError::Frame(format!("Frame encoding failed: {:?}", err))
+    }
+}
+
+pub type WifiResult<T> = Result<T, WifiError>;
diff --git a/rust/daemon/src/wifi/frame.rs b/rust/daemon/src/wifi/frame.rs
index d0862ab5..0a5e4875 100644
--- a/rust/daemon/src/wifi/frame.rs
+++ b/rust/daemon/src/wifi/frame.rs
@@ -12,8 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::wifi::error::WifiError;
 use crate::wifi::hwsim_attr_set::HwsimAttrSet;
-use anyhow::Context;
 use netsim_packets::ieee80211::{Ieee80211, MacAddress};
 use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg, TxRate};
 use pdl_runtime::Packet;
@@ -46,14 +46,15 @@ impl Frame {
     // Builds and validates the Frame from the attributes in the
     // packet. Called when a hwsim packet with HwsimCmd::Frame is
     // found.
-    pub fn parse(msg: &HwsimMsg) -> anyhow::Result<Frame> {
+    pub fn parse(msg: &HwsimMsg) -> Result<Frame, WifiError> {
         // Only expected to be called with HwsimCmd::Frame
         if msg.hwsim_hdr.hwsim_cmd != HwsimCmd::Frame {
             panic!("Invalid hwsim_cmd");
         }
-        let attrs = HwsimAttrSet::parse(&msg.attributes).context("HwsimAttrSet")?;
-        let frame = attrs.frame.clone().context("Frame")?;
-        let ieee80211 = Ieee80211::decode_full(&frame).context("Ieee80211")?;
+        let attrs = HwsimAttrSet::parse(&msg.attributes)?;
+        let frame =
+            attrs.frame.clone().ok_or(WifiError::Frame("Missing frame attribute".to_string()))?;
+        let ieee80211 = Ieee80211::decode_full(&frame)?;
         // Required attributes are unwrapped and return an error if
         // they are not present.
         Ok(Frame {
diff --git a/rust/daemon/src/wifi/hostapd.rs b/rust/daemon/src/wifi/hostapd.rs
index 822cfc71..e2dccbd4 100644
--- a/rust/daemon/src/wifi/hostapd.rs
+++ b/rust/daemon/src/wifi/hostapd.rs
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 /// Hostapd Interface for Network Simulation
+use crate::wifi::error::{WifiError, WifiResult};
 use bytes::Bytes;
 pub use hostapd_rs::hostapd::Hostapd;
 use netsim_common::util::os_utils::get_discovery_directory;
@@ -23,15 +24,21 @@ pub async fn hostapd_run(
     _opt: ProtoHostapdOptions,
     tx: mpsc::Sender<Bytes>,
     wifi_args: Option<Vec<String>>,
-) -> anyhow::Result<Hostapd> {
+) -> WifiResult<Hostapd> {
     // Create hostapd.conf under discovery directory
-    let config_path = get_discovery_directory().join("hostapd.conf");
+    let config_path =
+        get_discovery_directory().join(format!("hostapd_{}.conf", std::process::id()));
     let mut hostapd = Hostapd::new(tx, true, config_path);
     if let Some(wifi_values) = wifi_args {
         let ssid = &wifi_values[0];
         let password = wifi_values.get(1).cloned().unwrap_or_default();
-        hostapd.set_ssid(ssid, password).await?;
+        hostapd
+            .set_ssid(ssid, password)
+            .await
+            .map_err(|e| WifiError::Hostapd(format!("Failed to set SSID: {:?}", e)))?;
+    }
+    if !hostapd.run().await {
+        return Err(WifiError::Hostapd("Hostapd run failed".into()));
     }
-    hostapd.run().await;
     Ok(hostapd)
 }
diff --git a/rust/daemon/src/wifi/hostapd_cf.rs b/rust/daemon/src/wifi/hostapd_cf.rs
index 92e40dea..bebe6b45 100644
--- a/rust/daemon/src/wifi/hostapd_cf.rs
+++ b/rust/daemon/src/wifi/hostapd_cf.rs
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 /// Hostapd Interface for Network Simulation
+use crate::wifi::error::WifiResult;
 use bytes::Bytes;
 use netsim_packets::ieee80211::{Ieee80211, MacAddress};
 use netsim_proto::config::HostapdOptions as ProtoHostapdOptions;
@@ -21,7 +22,7 @@ use tokio::sync::mpsc;
 // Provides a stub implementation while the hostapd-rs crate is not integrated into the aosp-main.
 pub struct Hostapd {}
 impl Hostapd {
-    pub async fn input(&self, _bytes: Bytes) -> anyhow::Result<()> {
+    pub async fn input(&self, _bytes: Bytes) -> WifiResult<()> {
         Ok(())
     }
 
@@ -45,6 +46,6 @@ pub async fn hostapd_run(
     _opt: ProtoHostapdOptions,
     _tx: mpsc::Sender<Bytes>,
     _wifi_args: Option<Vec<String>>,
-) -> anyhow::Result<Hostapd> {
+) -> WifiResult<Hostapd> {
     Ok(Hostapd {})
 }
diff --git a/rust/daemon/src/wifi/hwsim_attr_set.rs b/rust/daemon/src/wifi/hwsim_attr_set.rs
index d0575130..9b853eb8 100644
--- a/rust/daemon/src/wifi/hwsim_attr_set.rs
+++ b/rust/daemon/src/wifi/hwsim_attr_set.rs
@@ -14,14 +14,12 @@
 
 #![allow(clippy::empty_line_after_doc_comments)]
 
-use std::fmt;
-
-use anyhow::{anyhow, Context};
+use crate::wifi::error::{WifiError, WifiResult};
 use netsim_packets::ieee80211::MacAddress;
 use netsim_packets::mac80211_hwsim::{self, HwsimAttr, HwsimAttrChild::*, TxRate, TxRateFlag};
 use netsim_packets::netlink::NlAttrHdr;
 use pdl_runtime::Packet;
-use std::option::Option;
+use std::fmt;
 
 /// Parse or Build the Hwsim attributes into a set.
 ///
@@ -184,7 +182,7 @@ impl HwsimAttrSetBuilder {
         self
     }
 
-    pub fn build(self) -> anyhow::Result<HwsimAttrSet> {
+    pub fn build(self) -> WifiResult<HwsimAttrSet> {
         Ok(HwsimAttrSet {
             transmitter: self.transmitter,
             receiver: self.receiver,
@@ -238,7 +236,7 @@ impl HwsimAttrSet {
     }
 
     /// Parse and validates the attributes from a HwsimMsg command.
-    pub fn parse(attributes: &[u8]) -> anyhow::Result<HwsimAttrSet> {
+    pub fn parse(attributes: &[u8]) -> WifiResult<HwsimAttrSet> {
         Self::parse_with_frame_transmitter(attributes, Option::None, Option::None)
     }
     /// Parse and validates the attributes from a HwsimMsg command.
@@ -247,18 +245,17 @@ impl HwsimAttrSet {
         attributes: &[u8],
         frame: Option<&[u8]>,
         transmitter: Option<&[u8; 6]>,
-    ) -> anyhow::Result<HwsimAttrSet> {
+    ) -> WifiResult<HwsimAttrSet> {
         let mut index: usize = 0;
         let mut builder = HwsimAttrSet::builder();
         while index < attributes.len() {
             // Parse a generic netlink attribute to get the size
-            let nla_hdr =
-                NlAttrHdr::decode_full(&attributes[index..index + 4]).context("NlAttrHdr")?;
+            let nla_hdr = NlAttrHdr::decode_full(&attributes[index..index + 4])?;
             let nla_len = nla_hdr.nla_len as usize;
             // Now parse a single attribute at a time from the
             // attributes to allow padding per attribute.
             let hwsim_attr = HwsimAttr::decode_full(&attributes[index..index + nla_len])?;
-            match hwsim_attr.specialize().context("HwsimAttr")? {
+            match hwsim_attr.specialize()? {
                 HwsimAttrAddrTransmitter(child) => {
                     builder.transmitter(transmitter.unwrap_or(child.address()))
                 }
@@ -272,10 +269,10 @@ impl HwsimAttrSet {
                 HwsimAttrTxInfo(child) => builder.tx_info(&child.tx_rates),
                 HwsimAttrTxInfoFlags(child) => builder.tx_info_flags(&child.tx_rate_flags),
                 _ => {
-                    return Err(anyhow!(
+                    return Err(WifiError::Frame(format!(
                         "Invalid attribute message: {:?}",
                         hwsim_attr.nla_type as u32
-                    ))
+                    )));
                 }
             };
             // Manually step through the attribute bytes aligning as
@@ -290,8 +287,6 @@ impl HwsimAttrSet {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use anyhow::Context;
-    use anyhow::Error;
     use netsim_packets::ieee80211::parse_mac_address;
     use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg};
 
@@ -333,12 +328,13 @@ mod tests {
     /// 2. Insert modified values, parse to bytes, and parse back again to check
     ///    if the round trip values are identical.
     #[test]
-    fn test_attr_set_parse_with_frame_transmitter() -> Result<(), Error> {
+    fn test_attr_set_parse_with_frame_transmitter() -> WifiResult<()> {
         let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame.csv");
         let hwsim_msg = HwsimMsg::decode_full(&packet)?;
         assert_eq!(hwsim_msg.hwsim_hdr().hwsim_cmd, HwsimCmd::Frame);
         let attrs = HwsimAttrSet::parse(hwsim_msg.attributes())?;
-        let transmitter: [u8; 6] = attrs.transmitter.context("transmitter")?.into();
+        let transmitter: [u8; 6] =
+            attrs.transmitter.ok_or(WifiError::Frame("Missing transmitter".to_string()))?.into();
         let mod_attrs = HwsimAttrSet::parse_with_frame_transmitter(
             hwsim_msg.attributes(),
             attrs.frame.as_deref(),
@@ -349,8 +345,9 @@ mod tests {
 
         // Change frame and transmitter.
         let mod_frame = Some(vec![0, 1, 2, 3]);
-        let mod_transmitter: Option<[u8; 6]> =
-            Some(parse_mac_address("00:0b:85:71:20:ce").context("transmitter")?.into());
+        let parsed_mac = parse_mac_address("00:0b:85:71:20:ce")
+            .ok_or(WifiError::Frame("Failed to parse MAC address".to_string()))?;
+        let mod_transmitter: Option<[u8; 6]> = Some(parsed_mac.into());
 
         let mod_attrs = HwsimAttrSet::parse_with_frame_transmitter(
             &attrs.attributes,
diff --git a/rust/daemon/src/wifi/libslirp.rs b/rust/daemon/src/wifi/libslirp.rs
index a25a8bc6..bebea673 100644
--- a/rust/daemon/src/wifi/libslirp.rs
+++ b/rust/daemon/src/wifi/libslirp.rs
@@ -14,6 +14,7 @@
 
 /// LibSlirp Interface for Network Simulation
 use crate::get_runtime;
+use crate::wifi::error::WifiResult;
 
 use bytes::Bytes;
 use http_proxy::Manager;
@@ -23,10 +24,7 @@ use libslirp_rs::libslirp_config::{lookup_host_dns, SlirpConfig};
 use netsim_proto::config::SlirpOptions as ProtoSlirpOptions;
 use std::sync::mpsc;
 
-pub fn slirp_run(
-    opt: ProtoSlirpOptions,
-    tx_bytes: mpsc::Sender<Bytes>,
-) -> anyhow::Result<LibSlirp> {
+pub fn slirp_run(opt: ProtoSlirpOptions, tx_bytes: mpsc::Sender<Bytes>) -> WifiResult<LibSlirp> {
     // TODO: Convert ProtoSlirpOptions to SlirpConfig.
     let http_proxy = Some(opt.http_proxy).filter(|s| !s.is_empty());
     let (proxy_manager, tx_proxy_bytes) = if let Some(proxy) = http_proxy {
diff --git a/rust/daemon/src/wifi/libslirp_cf.rs b/rust/daemon/src/wifi/libslirp_cf.rs
index 96380480..71c9ef4b 100644
--- a/rust/daemon/src/wifi/libslirp_cf.rs
+++ b/rust/daemon/src/wifi/libslirp_cf.rs
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 /// LibSlirp Interface for Network Simulation
+use crate::wifi::error::WifiResult;
 use bytes::Bytes;
 use netsim_proto::config::SlirpOptions as ProtoSlirpOptions;
 use std::sync::mpsc;
@@ -23,9 +24,6 @@ impl LibSlirp {
     pub fn input(&self, _bytes: Bytes) {}
 }
 
-pub fn slirp_run(
-    _opt: ProtoSlirpOptions,
-    _tx_bytes: mpsc::Sender<Bytes>,
-) -> anyhow::Result<LibSlirp> {
+pub fn slirp_run(_opt: ProtoSlirpOptions, _tx_bytes: mpsc::Sender<Bytes>) -> WifiResult<LibSlirp> {
     Ok(LibSlirp {})
 }
diff --git a/rust/daemon/src/wifi/mdns_forwarder.rs b/rust/daemon/src/wifi/mdns_forwarder.rs
index d158c7d8..a4c3acfd 100644
--- a/rust/daemon/src/wifi/mdns_forwarder.rs
+++ b/rust/daemon/src/wifi/mdns_forwarder.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use anyhow::anyhow;
+use crate::wifi::error::{WifiError, WifiResult};
 use bytes::Bytes;
 use log::{debug, warn};
 use socket2::{Protocol, Socket};
@@ -155,35 +155,45 @@ const ETHER_HEADER_LEN: usize = std::mem::size_of::<EtherHeader>();
 
 /// Creates a new UDP socket to bind to `port` with REUSEPORT option.
 /// `non_block` indicates whether to set O_NONBLOCK for the socket.
-fn new_socket(addr: SocketAddr, non_block: bool) -> anyhow::Result<Socket> {
+fn new_socket(addr: SocketAddr, non_block: bool) -> WifiResult<Socket> {
     let domain = match addr {
         SocketAddr::V4(_) => socket2::Domain::IPV4,
         SocketAddr::V6(_) => socket2::Domain::IPV6,
     };
 
     let socket = Socket::new(domain, socket2::Type::DGRAM, Some(Protocol::UDP))
-        .map_err(|e| anyhow!("create socket failed: {:?}", e))?;
+        .map_err(|e| WifiError::Network(format!("create socket failed: {:?}", e)))?;
 
-    socket.set_reuse_address(true).map_err(|e| anyhow!("set ReuseAddr failed: {:?}", e))?;
+    socket
+        .set_reuse_address(true)
+        .map_err(|e| WifiError::Network(format!("set ReuseAddr failed: {:?}", e)))?;
     #[cfg(not(windows))]
     socket.set_reuse_port(true)?;
 
     #[cfg(unix)] // this is currently restricted to Unix's in socket2
-    socket.set_reuse_port(true).map_err(|e| anyhow!("set ReusePort failed: {:?}", e))?;
+    socket
+        .set_reuse_port(true)
+        .map_err(|e| WifiError::Network(format!("set ReusePort failed: {:?}", e)))?;
 
     if non_block {
-        socket.set_nonblocking(true).map_err(|e| anyhow!("set O_NONBLOCK: {:?}", e))?;
+        socket
+            .set_nonblocking(true)
+            .map_err(|e| WifiError::Network(format!("set O_NONBLOCK: {:?}", e)))?;
     }
 
-    socket.join_multicast_v4(&MDNS_IP, &Ipv4Addr::UNSPECIFIED)?;
+    socket
+        .join_multicast_v4(&MDNS_IP, &Ipv4Addr::UNSPECIFIED)
+        .map_err(|e| WifiError::Network(format!("join_multicast_v4 failed: {:?}", e)))?;
     socket.set_multicast_loop_v4(false).expect("set_multicast_loop_v4 call failed");
 
-    socket.bind(&addr.into()).map_err(|e| anyhow!("socket bind to {} failed: {:?}", &addr, e))?;
+    socket
+        .bind(&addr.into())
+        .map_err(|e| WifiError::Network(format!("socket bind to {} failed: {:?}", &addr, e)))?;
 
     Ok(socket)
 }
 
-fn create_ethernet_frame(packet: &[u8], ip_addr: &Ipv4Addr) -> anyhow::Result<Vec<u8>> {
+fn create_ethernet_frame(packet: &[u8], ip_addr: &Ipv4Addr) -> WifiResult<Vec<u8>> {
     // TODO: Use the etherparse crate
     let ether_header = EtherHeader {
         // mDNS multicast IP address
@@ -228,14 +238,16 @@ fn create_ethernet_frame(packet: &[u8], ip_addr: &Ipv4Addr) -> anyhow::Result<Ve
     Ok(response_packet)
 }
 
-pub fn run_mdns_forwarder(tx: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
+pub fn run_mdns_forwarder(tx: mpsc::Sender<Bytes>) -> WifiResult<()> {
     let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), MDNS_PORT);
     let socket = new_socket(addr.into(), false)?;
 
     // Typical max mDNS packet size
     let mut buf: [MaybeUninit<u8>; 1500] = [MaybeUninit::new(0_u8); 1500];
     loop {
-        let (size, src_addr) = socket.recv_from(&mut buf[..])?;
+        let (size, src_addr) = socket
+            .recv_from(&mut buf[..])
+            .map_err(|e| WifiError::Network(format!("recv_from failed: {:?}", e)))?;
         // SAFETY: `recv_from` implementation promises not to write uninitialized bytes to `buf`.
         // Documentation: https://docs.rs/socket2/latest/socket2/struct.Socket.html#method.recv_from
         let packet = unsafe { &*(&buf[..size] as *const [MaybeUninit<u8>] as *const [u8]) };
@@ -244,7 +256,7 @@ pub fn run_mdns_forwarder(tx: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
             match create_ethernet_frame(packet, socket_addr_v4.ip()) {
                 Ok(ethernet_frame) => {
                     if let Err(e) = tx.send(ethernet_frame.into()) {
-                        warn!("Failed to send packet: {e}");
+                        warn!("Failed to send packet: {}", e);
                     }
                 }
                 Err(e) => warn!("Failed to create ethernet frame from UDP payload: {}", e),
diff --git a/rust/daemon/src/wifi/medium.rs b/rust/daemon/src/wifi/medium.rs
index 69472f0f..5db679fe 100644
--- a/rust/daemon/src/wifi/medium.rs
+++ b/rust/daemon/src/wifi/medium.rs
@@ -12,10 +12,11 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::wifi::error::{WifiError, WifiResult};
 use crate::wifi::frame::Frame;
 use crate::wifi::hostapd::Hostapd;
 use crate::wifi::hwsim_attr_set::HwsimAttrSet;
-use anyhow::{anyhow, Context};
+use crate::wifi::stats::WifiStats;
 use bytes::Bytes;
 use log::{debug, info, warn};
 use netsim_packets::ieee80211::{DataSubType, Ieee80211, MacAddress};
@@ -61,6 +62,7 @@ impl Processor {
 
 #[derive(Clone)]
 struct Station {
+    // The station's client_id. Equivalent to the chip_id of the WifiChip
     client_id: u32,
     // Ieee80211 source address
     addr: MacAddress,
@@ -101,40 +103,44 @@ impl Client {
 
 pub struct Medium {
     callback: HwsimCmdCallback,
-    // Ieee80211 source address
+    // Map of Ieee80211 source address to Station struct
     stations: RwLock<HashMap<MacAddress, Arc<Station>>>,
+    // Map of client_id (equivalent to chip_id) to Client struct
     clients: RwLock<HashMap<u32, Client>>,
     // Simulate the re-transmission of frames sent to hostapd
     ap_simulation: bool,
     hostapd: Arc<Hostapd>,
+    wifi_stats: WifiStats,
 }
 
 type HwsimCmdCallback = fn(u32, &Bytes);
 impl Medium {
-    pub fn new(callback: HwsimCmdCallback, hostapd: Arc<Hostapd>) -> Medium {
+    pub fn new(callback: HwsimCmdCallback, hostapd: Arc<Hostapd>, wifi_stats: WifiStats) -> Medium {
         Self {
             callback,
             stations: RwLock::new(HashMap::new()),
             clients: RwLock::new(HashMap::new()),
             ap_simulation: true,
             hostapd,
+            wifi_stats,
         }
     }
 
     pub fn add(&self, client_id: u32) {
-        let _ = self.clients.write().unwrap().entry(client_id).or_insert_with(|| {
-            info!("Insert client {}", client_id);
-            Client::new()
-        });
+        let _ =
+            self.clients.write().expect("RwLock poisoned").entry(client_id).or_insert_with(|| {
+                info!("Insert client {}", client_id);
+                Client::new()
+            });
     }
 
     pub fn remove(&self, client_id: u32) {
-        self.stations.write().unwrap().retain(|_, s| s.client_id != client_id);
-        self.clients.write().unwrap().remove(&client_id);
+        self.stations.write().expect("RwLock poisoned").retain(|_, s| s.client_id != client_id);
+        self.clients.write().expect("RwLock poisoned").remove(&client_id);
     }
 
     pub fn reset(&self, client_id: u32) {
-        if let Some(client) = self.clients.read().unwrap().get(&client_id) {
+        if let Some(client) = self.clients.read().expect("RwLock poisoned").get(&client_id) {
             client.enabled.store(true, Ordering::Relaxed);
             client.tx_count.store(0, Ordering::Relaxed);
             client.rx_count.store(0, Ordering::Relaxed);
@@ -142,7 +148,7 @@ impl Medium {
     }
 
     pub fn get(&self, client_id: u32) -> Option<Client> {
-        self.clients.read().unwrap().get(&client_id).map(|c| c.to_owned())
+        self.clients.read().expect("RwLock poisoned").get(&client_id).map(|c| c.to_owned())
     }
 
     fn contains_client(&self, client_id: u32) -> bool {
@@ -150,21 +156,28 @@ impl Medium {
     }
 
     fn stations(&self) -> impl Iterator<Item = Arc<Station>> {
-        self.stations.read().unwrap().clone().into_values()
+        self.stations.read().expect("RwLock poisoned").clone().into_values()
     }
 
     fn contains_station(&self, addr: &MacAddress) -> bool {
-        self.stations.read().unwrap().contains_key(addr)
+        self.stations.read().expect("RwLock poisoned").contains_key(addr)
     }
 
-    fn get_station(&self, addr: &MacAddress) -> anyhow::Result<Arc<Station>> {
-        self.stations.read().unwrap().get(addr).context("get station").cloned()
+    fn get_station(&self, addr: &MacAddress) -> WifiResult<Arc<Station>> {
+        self.stations
+            .read()
+            .expect("RwLock poisoned")
+            .get(addr)
+            .cloned()
+            .ok_or_else(|| WifiError::Client(format!("Station not found for address: {addr}")))
     }
 
-    fn upsert_station(&self, client_id: u32, frame: &Frame) -> anyhow::Result<()> {
+    fn upsert_station(&self, client_id: u32, frame: &Frame) -> WifiResult<()> {
         let src_addr = frame.ieee80211.get_source();
-        let hwsim_addr = frame.transmitter.context("transmitter")?;
-        self.stations.write().unwrap().entry(src_addr).or_insert_with(|| {
+        let hwsim_addr = frame.transmitter.ok_or(WifiError::Frame(format!(
+            "Missing transmitter attribute in frame for client: {client_id}"
+        )))?;
+        self.stations.write().expect("RwLock poisoned").entry(src_addr).or_insert_with(|| {
             info!(
                 "Insert station with client id {}, hwsimaddr: {}, \
                 Ieee80211 addr: {}",
@@ -179,18 +192,11 @@ impl Medium {
         Ok(())
     }
 
-    pub fn ack_frame(&self, client_id: u32, frame: &Frame) {
-        // Send Ack frame back to source
-        self.ack_frame_internal(client_id, frame).unwrap_or_else(move |e| {
-            // TODO: add this error to the netsim_session_stats
-            warn!("error ack frame {e}");
-        });
-    }
-
-    fn ack_frame_internal(&self, client_id: u32, frame: &Frame) -> anyhow::Result<()> {
-        self.send_tx_info_frame(frame)?;
-        self.incr_tx(client_id)?;
-        Ok(())
+    /// Send Ack frame (TX_INFO_FRAME) back to source.
+    pub fn ack_frame(&self, client_id: u32, frame: &Frame) -> WifiResult<()> {
+        let hwsim_msg_tx_info = build_tx_info(&frame.hwsim_msg)?.encode_to_vec()?;
+        (self.callback)(client_id, &hwsim_msg_tx_info.into());
+        self.incr_tx(client_id)
     }
 
     /// Process commands from the kernel's mac80211_hwsim subsystem.
@@ -204,18 +210,19 @@ impl Medium {
     /// * 802.11 frames sent between stations
     ///
     /// * 802.11 multicast frames are re-broadcast to connected stations.
-    pub fn get_processor(&self, client_id: u32, packet: &Bytes) -> Option<Processor> {
+    pub fn get_processor(&self, client_id: u32, packet: &Bytes) -> WifiResult<Processor> {
         let frame = self
             .validate(client_id, packet)
-            .map_err(|e| warn!("error validate for client {client_id}: {e}"))
-            .ok()?;
+            .map_err(|e| WifiError::Frame(format!("error validate for client {client_id}: {e}")))?;
+
+        self.wifi_stats.incr_hwsim_frames_rx();
 
         // Creates Stations on the fly when there is no config file.
         // WiFi Direct will use a randomized mac address for probing
         // new networks. This block associates the new mac with the station.
-        self.upsert_station(client_id, &frame)
-            .map_err(|e| warn!("error upsert station for client {client_id}: {e}"))
-            .ok()?;
+        self.upsert_station(client_id, &frame).map_err(|e| {
+            WifiError::Frame(format!("error upsert station for client {client_id}: {e}"))
+        })?;
 
         let plaintext_ieee80211 = self.hostapd.try_decrypt(&frame.ieee80211);
 
@@ -227,19 +234,22 @@ impl Medium {
             plaintext_ieee80211,
         };
 
+        if processor.get_ieee80211().is_mgmt() {
+            self.wifi_stats.incr_mgmt_frames_rx();
+        }
+
         let dest_addr = processor.frame.ieee80211.get_destination();
 
-        processor.frame.attrs.freq.map(|freq| {
+        if let Some(freq) = processor.frame.attrs.freq {
             self.get_station(&processor.frame.ieee80211.get_source())
                 .map(|sta| sta.update_freq(freq))
-                .map_err(|e| {
-                    warn!("Failed to get station for client {client_id} to update freq: {e}")
-                })
-        });
+                .map_err(|e| self.wifi_stats.log_and_incr_err_count(&e))
+                .ok();
+        };
 
         if self.contains_station(&dest_addr) {
             processor.wmedium = true;
-            return Some(processor);
+            return Ok(processor);
         }
         if dest_addr.is_multicast() {
             processor.wmedium = true;
@@ -249,7 +259,7 @@ impl Medium {
         // If the BSSID is unicast and does not match the hostapd's BSSID, the packet is not handled by hostapd. Skip further checks.
         if let Some(bssid) = ieee80211.get_bssid() {
             if !bssid.is_multicast() && bssid != self.hostapd.get_bssid() {
-                return Some(processor);
+                return Ok(processor);
             }
         }
         // Data frames
@@ -281,10 +291,10 @@ impl Medium {
                 processor.hostapd = true;
             }
         }
-        Some(processor)
+        Ok(processor)
     }
 
-    fn validate(&self, client_id: u32, packet: &Bytes) -> anyhow::Result<Frame> {
+    fn validate(&self, client_id: u32, packet: &Bytes) -> WifiResult<Frame> {
         let hwsim_msg = HwsimMsg::decode_full(packet)?;
 
         // The virtio handler only accepts HWSIM_CMD_FRAME, HWSIM_CMD_TX_INFO_FRAME and HWSIM_CMD_REPORT_PMSR
@@ -298,47 +308,50 @@ impl Medium {
                     || frame.cookie.is_none()
                     || frame.tx_info.is_none()
                 {
-                    return Err(anyhow!("Missing Hwsim attributes for incoming packet"));
+                    return Err(WifiError::Frame(format!(
+                        "Missing Hwsim attributes for incoming packet for client: {client_id}"
+                    )));
                 }
                 // Use as receiver for outgoing HwsimMsg.
-                let hwsim_addr = frame.transmitter.context("transmitter")?;
-                let flags = frame.flags.context("flags")?;
-                let cookie = frame.cookie.context("cookie")?;
+                let hwsim_addr = frame.transmitter.ok_or(WifiError::Frame(format!(
+                    "Missing transmitter attribute in frame for client: {client_id}"
+                )))?;
+                let flags = frame.flags.ok_or(WifiError::Frame(format!(
+                    "Missing flags attribute in frame for client: {client_id}"
+                )))?;
+                let cookie = frame.cookie.ok_or(WifiError::Frame(format!(
+                    "Missing cookie attribute in frame for client: {client_id}"
+                )))?;
                 debug!(
                     "Frame chip {}, transmitter {}, flags {}, cookie {}, ieee80211 {}",
                     client_id, hwsim_addr, flags, cookie, frame.ieee80211
                 );
                 Ok(frame)
             }
-            _ => Err(anyhow!("Another command found {:?}", hwsim_msg)),
+            _ => Err(WifiError::Frame(format!(
+                "Another command found {hwsim_msg:?} for client: {client_id}"
+            ))),
         }
     }
 
     /// Handle Wi-Fi Ieee802.3 frame from network.
     /// Convert to HwsimMsg and send to clients.
-    pub fn process_ieee8023_response(&self, packet: &Bytes) {
-        let result = Ieee80211::from_ieee8023(packet, self.hostapd.get_bssid())
-            .and_then(|ieee80211| self.handle_ieee80211_response(ieee80211));
-
-        if let Err(e) = result {
-            warn!("{}", e);
-        }
+    pub fn process_ieee8023_response(&self, packet: &Bytes) -> WifiResult<()> {
+        Ieee80211::from_ieee8023(packet, self.hostapd.get_bssid())
+            .map_err(|e| WifiError::Frame(format!("Failed to process IEEE 802.3 response: {}", e)))
+            .and_then(|ieee80211| self.handle_ieee80211_response(ieee80211))
     }
 
     /// Handle Wi-Fi Ieee802.11 frame from network.
     /// Convert to HwsimMsg and send to clients.
-    pub fn process_ieee80211_response(&self, packet: &Bytes) {
-        let result = Ieee80211::decode_full(packet)
-            .context("Ieee80211")
-            .and_then(|ieee80211| self.handle_ieee80211_response(ieee80211));
-
-        if let Err(e) = result {
-            warn!("{}", e);
-        }
+    pub fn process_ieee80211_response(&self, packet: &Bytes) -> WifiResult<()> {
+        Ieee80211::decode_full(packet)
+            .map_err(|e| WifiError::Frame(format!("Failed to process IEEE 802.11 response: {}", e)))
+            .and_then(|ieee80211| self.handle_ieee80211_response(ieee80211))
     }
 
     /// Determine the client id based on destination and send to client.
-    fn handle_ieee80211_response(&self, mut ieee80211: Ieee80211) -> anyhow::Result<()> {
+    fn handle_ieee80211_response(&self, mut ieee80211: Ieee80211) -> WifiResult<()> {
         if let Some(encrypted_ieee80211) = self.hostapd.try_encrypt(&ieee80211) {
             ieee80211 = encrypted_ieee80211;
         }
@@ -346,11 +359,20 @@ impl Medium {
         if let Ok(destination) = self.get_station(&dest_addr) {
             self.send_ieee80211_response(&ieee80211, &destination)?;
         } else if dest_addr.is_multicast() {
+            // Deduplicates based on (hwsim_addr, freq) as these are used to construct
+            // the HwsimMsg for the destination.
+            let mut sent_to_hwsim_addrs_freq = std::collections::HashSet::new();
             for destination in self.stations() {
-                self.send_ieee80211_response(&ieee80211, &destination)?;
+                let freq = destination.freq.load(Ordering::Relaxed);
+                if sent_to_hwsim_addrs_freq.insert((destination.hwsim_addr, freq)) {
+                    self.send_ieee80211_response(&ieee80211, &destination)?;
+                }
             }
         } else {
-            warn!("Send frame response to unknown destination: {}", dest_addr);
+            return Err(WifiError::Transmission(format!(
+                "Send frame response to unknown destination: {}",
+                dest_addr
+            )));
         }
         Ok(())
     }
@@ -359,8 +381,14 @@ impl Medium {
         &self,
         ieee80211: &Ieee80211,
         destination: &Station,
-    ) -> anyhow::Result<()> {
+    ) -> WifiResult<()> {
+        if !self.enabled(destination.client_id)? {
+            debug!("Dropping frame to disabled client {}", destination.client_id);
+            return Ok(());
+        }
+
         let hwsim_msg = self.create_hwsim_msg_from_ieee80211(ieee80211, destination)?;
+        self.wifi_stats.incr_hwsim_frames_tx();
         (self.callback)(destination.client_id, &hwsim_msg.encode_to_vec()?.into());
         self.incr_rx(destination.client_id)?;
         Ok(())
@@ -370,8 +398,16 @@ impl Medium {
         &self,
         ieee80211: &Ieee80211,
         destination: &Station,
-    ) -> anyhow::Result<HwsimMsg> {
-        let attributes = self.create_hwsim_msg_attr(ieee80211, destination)?;
+    ) -> WifiResult<HwsimMsg> {
+        let mut builder = HwsimAttrSet::builder();
+        // Attributes required by mac80211_hwsim.
+        builder.receiver(&destination.hwsim_addr.to_vec());
+        let frame_bytes = ieee80211.encode_to_vec()?;
+        builder.frame(&frame_bytes);
+        builder.rx_rate(RX_RATE);
+        builder.signal(SIGNAL);
+        builder.freq(destination.freq.load(Ordering::Relaxed));
+        let attributes = builder.build()?.attributes;
         let hwsim_hdr = HwsimMsgHdr { hwsim_cmd: HwsimCmd::Frame, hwsim_version: 0, reserved: 0 };
         let nlmsg_len = (NL_MSG_HDR_LEN + hwsim_hdr.encoded_len() + attributes.len()) as u32;
         let nl_hdr = NlMsgHdr {
@@ -384,67 +420,39 @@ impl Medium {
         Ok(HwsimMsg { nl_hdr, hwsim_hdr, attributes })
     }
 
-    fn create_hwsim_msg_attr(
-        &self,
-        ieee80211: &Ieee80211,
-        destination: &Station,
-    ) -> anyhow::Result<Vec<u8>> {
-        let mut builder = HwsimAttrSet::builder();
-        // Attributes required by mac80211_hwsim.
-        builder.receiver(&destination.hwsim_addr.to_vec());
-        let frame_bytes = ieee80211.encode_to_vec()?;
-        builder.frame(&frame_bytes);
-        builder.rx_rate(RX_RATE);
-        builder.signal(SIGNAL);
-        builder.freq(destination.freq.load(Ordering::Relaxed));
-        Ok(builder.build()?.attributes)
-    }
-
     pub fn set_enabled(&self, client_id: u32, enabled: bool) {
-        if let Some(client) = self.clients.read().unwrap().get(&client_id) {
+        if let Some(client) = self.clients.read().expect("RwLock poisoned").get(&client_id) {
             client.enabled.store(enabled, Ordering::Relaxed);
         }
     }
 
-    fn enabled(&self, client_id: u32) -> anyhow::Result<bool> {
-        Ok(self
-            .clients
+    fn enabled(&self, client_id: u32) -> WifiResult<bool> {
+        self.clients
             .read()
-            .unwrap()
+            .expect("RwLock poisoned")
             .get(&client_id)
-            .context(format!("client {client_id} is missing"))?
-            .enabled
-            .load(Ordering::Relaxed))
+            .map(|c| c.enabled.load(Ordering::Relaxed))
+            .ok_or_else(|| WifiError::Client(format!("client {client_id} is missing")))
     }
 
-    /// Create tx info frame to station to ack HwsimMsg.
-    fn send_tx_info_frame(&self, frame: &Frame) -> anyhow::Result<()> {
-        let client_id = self.get_station(&frame.ieee80211.get_source())?.client_id;
-        let hwsim_msg_tx_info = build_tx_info(&frame.hwsim_msg).unwrap().encode_to_vec()?;
-        (self.callback)(client_id, &hwsim_msg_tx_info.into());
-        Ok(())
-    }
-
-    fn incr_tx(&self, client_id: u32) -> anyhow::Result<()> {
-        self.clients
-            .read()
-            .unwrap()
-            .get(&client_id)
-            .context("incr_tx")?
-            .tx_count
-            .fetch_add(1, Ordering::Relaxed);
-        Ok(())
+    fn incr_tx(&self, client_id: u32) -> WifiResult<()> {
+        self.clients.read().expect("RwLock poisoned").get(&client_id).map_or(
+            Err(WifiError::Client(format!("client {client_id} is missing for incr_tx"))),
+            |c| {
+                c.tx_count.fetch_add(1, Ordering::Relaxed);
+                Ok(())
+            },
+        )
     }
 
-    fn incr_rx(&self, client_id: u32) -> anyhow::Result<()> {
-        self.clients
-            .read()
-            .unwrap()
-            .get(&client_id)
-            .context("incr_rx")?
-            .rx_count
-            .fetch_add(1, Ordering::Relaxed);
-        Ok(())
+    fn incr_rx(&self, client_id: u32) -> WifiResult<()> {
+        self.clients.read().expect("RwLock poisoned").get(&client_id).map_or(
+            Err(WifiError::Client(format!("client {client_id} is missing for incr_rx"))),
+            |c| {
+                c.rx_count.fetch_add(1, Ordering::Relaxed);
+                Ok(())
+            },
+        )
     }
 
     // Send an 802.11 frame from a station to a station after wrapping in HwsimMsg.
@@ -457,60 +465,72 @@ impl Medium {
         ieee80211: &Ieee80211,
         source: &Station,
         destination: &Station,
-    ) -> anyhow::Result<()> {
+    ) -> WifiResult<()> {
         if source.client_id != destination.client_id
             && self.enabled(source.client_id)?
             && self.enabled(destination.client_id)?
         {
-            if let Some(packet) = self.create_hwsim_msg(frame, ieee80211, &destination.hwsim_addr) {
-                self.incr_rx(destination.client_id)?;
-                (self.callback)(destination.client_id, &packet.encode_to_vec()?.into());
-                log_hwsim_msg(frame, source.client_id, destination.client_id);
+            match self.create_hwsim_msg(frame, ieee80211, &destination.hwsim_addr) {
+                Ok(packet) => {
+                    self.wifi_stats.incr_wmedium_frames_tx();
+                    self.wifi_stats.incr_hwsim_frames_tx();
+                    self.incr_rx(destination.client_id)?;
+                    (self.callback)(destination.client_id, &packet.encode_to_vec()?.into());
+                    log_hwsim_msg(frame, source.client_id, destination.client_id);
+                }
+                Err(e) => self.wifi_stats.log_and_incr_err_count(&e),
             }
         }
         Ok(())
     }
 
     // Broadcast an 802.11 frame to all stations.
-    /// TODO: Compare with the implementations in mac80211_hwsim.c and wmediumd.c.
+    // TODO: Compare with the implementations in mac80211_hwsim.c and wmediumd.c.
     fn broadcast_from_sta_frame(
         &self,
         frame: &Frame,
         ieee80211: &Ieee80211,
         source: &Station,
-    ) -> anyhow::Result<()> {
-        for destination in self.stations() {
-            if source.addr != destination.addr {
+    ) -> WifiResult<()> {
+        // Deduplicates based on (hwsim_addr, freq) as these are used to construct
+        // the HwsimMsg for the destination.
+        let mut sent_to_hwsim_addrs_freq = std::collections::HashSet::new();
+        for destination in self.stations().filter(|sta| sta.addr != source.addr) {
+            let current_freq = destination.freq.load(Ordering::Relaxed);
+            if sent_to_hwsim_addrs_freq.insert((destination.hwsim_addr, current_freq)) {
                 self.send_from_sta_frame(frame, ieee80211, source, &destination)?;
             }
         }
         Ok(())
     }
+
     /// Queues the frame for sending to medium.
     ///
     /// The `frame` contains an `ieee80211` field, but it might be encrypted. This function uses the provided `ieee80211` parameter directly, as it's expected to be decrypted if necessary.
-    pub fn queue_frame(&self, frame: Frame, ieee80211: Ieee80211) {
-        self.queue_frame_internal(frame, ieee80211).unwrap_or_else(move |e| {
-            // TODO: add this error to the netsim_session_stats
-            warn!("queue frame error {e}");
-        });
-    }
-
-    fn queue_frame_internal(&self, frame: Frame, ieee80211: Ieee80211) -> anyhow::Result<()> {
+    pub fn queue_frame(&self, frame: Frame, ieee80211: Ieee80211) -> WifiResult<()> {
         let source = self.get_station(&ieee80211.get_source())?;
         let dest_addr = ieee80211.get_destination();
         if self.contains_station(&dest_addr) {
-            debug!("Frame deliver from {} to {}", source.addr, dest_addr);
+            // Unicast to another station
+            debug!("Frame deliver unicast from {} to {}", source.addr, dest_addr);
+            self.wifi_stats.incr_wmedium_unicast_frames_tx();
             let destination = self.get_station(&dest_addr)?;
             self.send_from_sta_frame(&frame, &ieee80211, &source, &destination)?;
             return Ok(());
         } else if dest_addr.is_multicast() {
+            // Broadcast/Multicast from a station
             debug!("Frame multicast {}", ieee80211);
+            if dest_addr.is_mdns() {
+                self.wifi_stats.incr_mdns_count();
+            }
             self.broadcast_from_sta_frame(&frame, &ieee80211, &source)?;
             return Ok(());
         }
 
-        Err(anyhow!("Dropped packet {}", ieee80211))
+        Err(WifiError::Transmission(format!(
+            "Dropped packet from {} to {}",
+            source.addr, dest_addr
+        )))
     }
 
     // Simulate transmission through hostapd by rewriting frames with 802.11 ToDS
@@ -520,26 +540,30 @@ impl Medium {
         frame: &Frame,
         ieee80211: &Ieee80211,
         dest_hwsim_addr: &MacAddress,
-    ) -> anyhow::Result<Vec<u8>> {
+    ) -> WifiResult<Vec<u8>> {
         // Encrypt Ieee80211 if needed
         let attrs = &frame.attrs;
         let mut ieee80211_response = match self.ap_simulation
             && ieee80211.is_to_ap()
             && ieee80211.get_bssid() == Some(self.hostapd.get_bssid())
         {
-            true => ieee80211.into_from_ap()?.try_into()?,
+            true => ieee80211
+                .into_from_ap()
+                .map_err(|e| WifiError::Frame(format!("{}", e)))?
+                .try_into()
+                .map_err(|e| WifiError::Frame(format!("{}", e)))?,
             false => ieee80211.clone(),
         };
         if let Some(encrypted_ieee80211) = self.hostapd.try_encrypt(&ieee80211_response) {
             ieee80211_response = encrypted_ieee80211;
         }
-        let frame = ieee80211_response.encode_to_vec()?;
+        let frame_bytes = ieee80211_response.encode_to_vec()?;
 
         let mut builder = HwsimAttrSet::builder();
 
         // Attributes required by mac80211_hwsim.
         builder.receiver(&dest_hwsim_addr.to_vec());
-        builder.frame(&frame);
+        builder.frame(&frame_bytes);
         // Incoming HwsimMsg don't have rx_rate and signal.
         builder.rx_rate(attrs.rx_rate_idx.unwrap_or(RX_RATE));
         builder.signal(attrs.signal.unwrap_or(SIGNAL));
@@ -558,17 +582,12 @@ impl Medium {
         frame: &Frame,
         ieee80211: &Ieee80211,
         dest_hwsim_addr: &MacAddress,
-    ) -> Option<HwsimMsg> {
+    ) -> WifiResult<HwsimMsg> {
         let hwsim_msg = &frame.hwsim_msg;
         assert_eq!(hwsim_msg.hwsim_hdr.hwsim_cmd, HwsimCmd::Frame);
-        let attributes_result = self.create_hwsim_attr(frame, ieee80211, dest_hwsim_addr);
-        let attributes = match attributes_result {
-            Ok(attributes) => attributes,
-            Err(e) => {
-                warn!("Failed to create from_ap attributes. E: {}", e);
-                return None;
-            }
-        };
+        let attributes = self
+            .create_hwsim_attr(frame, ieee80211, dest_hwsim_addr)
+            .map_err(|e| WifiError::Frame(format!("Failed to create from_ap attributes. {}", e)))?;
 
         let nlmsg_len = hwsim_msg.nl_hdr.nlmsg_len + attributes.len() as u32
             - hwsim_msg.attributes.len() as u32;
@@ -583,7 +602,7 @@ impl Medium {
             hwsim_hdr: hwsim_msg.hwsim_hdr.clone(),
             attributes,
         };
-        Some(new_hwsim_msg)
+        Ok(new_hwsim_msg)
     }
 }
 
@@ -597,8 +616,8 @@ fn log_hwsim_msg(frame: &Frame, client_id: u32, dest_client_id: u32) {
 /// Build TxInfoFrame HwsimMsg from CmdFrame HwsimMsg.
 ///
 /// Reference to ackLocalFrame() in external/qemu/android-qemu2-glue/emulation/VirtioWifiForwarder.cpp
-fn build_tx_info(hwsim_msg: &HwsimMsg) -> anyhow::Result<HwsimMsg> {
-    let attrs = HwsimAttrSet::parse(&hwsim_msg.attributes).context("HwsimAttrSet").unwrap();
+fn build_tx_info(hwsim_msg: &HwsimMsg) -> WifiResult<HwsimMsg> {
+    let attrs = HwsimAttrSet::parse(&hwsim_msg.attributes)?;
 
     let hwsim_hdr = &hwsim_msg.hwsim_hdr;
     let nl_hdr = &hwsim_msg.nl_hdr;
@@ -606,13 +625,26 @@ fn build_tx_info(hwsim_msg: &HwsimMsg) -> anyhow::Result<HwsimMsg> {
     const HWSIM_TX_STAT_ACK: u32 = 1 << 2;
 
     new_attr_builder
-        .transmitter(&attrs.transmitter.context("transmitter")?.into())
-        .flags(attrs.flags.context("flags")? | HWSIM_TX_STAT_ACK)
-        .cookie(attrs.cookie.context("cookie")?)
+        .transmitter(
+            &attrs
+                .transmitter
+                .ok_or(WifiError::Frame("Missing transmitter in HwsimAttrSet".into()))?
+                .into(),
+        )
+        .flags(
+            attrs.flags.ok_or(WifiError::Frame("Missing flags in HwsimAttrSet".into()))?
+                | HWSIM_TX_STAT_ACK,
+        )
+        .cookie(attrs.cookie.ok_or(WifiError::Frame("Missing cookie in HwsimAttrSet".into()))?)
         .signal(attrs.signal.unwrap_or(SIGNAL))
-        .tx_info(attrs.tx_info.context("tx_info")?.as_slice());
+        .tx_info(
+            attrs
+                .tx_info
+                .ok_or(WifiError::Frame("Missing tx_info in HwsimAttrSet".into()))?
+                .as_slice(),
+        );
 
-    let new_attr = new_attr_builder.build().unwrap();
+    let new_attr = new_attr_builder.build()?;
     let nlmsg_len =
         nl_hdr.nlmsg_len + new_attr.attributes.len() as u32 - attrs.attributes.len() as u32;
     let new_hwsim_msg = HwsimMsg {
@@ -712,6 +744,7 @@ mod tests {
 
         // Create a test Medium object
         let callback: HwsimCmdCallback = |_, _| {};
+        let wifi_stats = WifiStats::default();
         let medium = Medium {
             callback,
             stations: RwLock::new(HashMap::from([
@@ -740,6 +773,7 @@ mod tests {
             ])),
             ap_simulation: true,
             hostapd,
+            wifi_stats,
         };
 
         medium.remove(test_client_id);
@@ -754,41 +788,59 @@ mod tests {
     fn test_is_mdns_packet() {
         let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame_mdns.csv");
         let hwsim_msg = HwsimMsg::decode_full(&packet).unwrap();
-        let mdns_frame = Frame::parse(&hwsim_msg).unwrap();
+        let mdns_frame_result = Frame::parse(&hwsim_msg);
+        assert!(mdns_frame_result.is_ok());
+        let mdns_frame = mdns_frame_result.unwrap();
         assert!(!mdns_frame.ieee80211.get_source().is_multicast());
         assert!(mdns_frame.ieee80211.get_destination().is_multicast());
+        // Check against the constant
+        assert!(mdns_frame.ieee80211.get_destination().is_mdns());
     }
 
     #[test]
-    fn test_build_tx_info_reconstruct() {
+    fn test_build_tx_info_reconstruct() -> WifiResult<()> {
         let packet: Vec<u8> = include!("test_packets/hwsim_cmd_tx_info.csv");
         let hwsim_msg = HwsimMsg::decode_full(&packet).unwrap();
         assert_eq!(hwsim_msg.hwsim_hdr().hwsim_cmd, HwsimCmd::TxInfoFrame);
 
-        let new_hwsim_msg = build_tx_info(&hwsim_msg).unwrap();
+        let new_hwsim_msg_result = build_tx_info(&hwsim_msg);
+        assert!(new_hwsim_msg_result.is_ok());
+        let new_hwsim_msg = new_hwsim_msg_result.unwrap();
         assert_eq!(hwsim_msg, new_hwsim_msg);
+        Ok(())
     }
 
     #[test]
-    fn test_build_tx_info() {
+    fn test_build_tx_info() -> WifiResult<()> {
         let packet: Vec<u8> = include!("test_packets/hwsim_cmd_frame.csv");
         let hwsim_msg = HwsimMsg::decode_full(&packet).unwrap();
-        let hwsim_msg_tx_info = build_tx_info(&hwsim_msg).unwrap();
+        let hwsim_msg_tx_info_result = build_tx_info(&hwsim_msg);
+        assert!(hwsim_msg_tx_info_result.is_ok());
+        let hwsim_msg_tx_info = hwsim_msg_tx_info_result.unwrap();
         assert_eq!(hwsim_msg_tx_info.hwsim_hdr().hwsim_cmd, HwsimCmd::TxInfoFrame);
+        Ok(())
     }
 
-    fn build_tx_info_and_compare(frame_bytes: &Bytes, tx_info_expected_bytes: &Bytes) {
+    fn build_tx_info_and_compare(
+        frame_bytes: &Bytes,
+        tx_info_expected_bytes: &Bytes,
+    ) -> WifiResult<()> {
         let frame = HwsimMsg::decode_full(frame_bytes).unwrap();
-        let tx_info = build_tx_info(&frame).unwrap();
+        let tx_info_result = build_tx_info(&frame);
+        assert!(tx_info_result.is_ok());
+        let tx_info = tx_info_result.unwrap();
 
         let tx_info_expected = HwsimMsg::decode_full(tx_info_expected_bytes).unwrap();
 
         assert_eq!(tx_info.hwsim_hdr(), tx_info_expected.hwsim_hdr());
         assert_eq!(tx_info.nl_hdr(), tx_info_expected.nl_hdr());
 
-        let attrs = HwsimAttrSet::parse(tx_info.attributes()).context("HwsimAttrSet").unwrap();
-        let attrs_expected =
-            HwsimAttrSet::parse(tx_info_expected.attributes()).context("HwsimAttrSet").unwrap();
+        let attrs_result = HwsimAttrSet::parse(tx_info.attributes());
+        assert!(attrs_result.is_ok());
+        let attrs = attrs_result.unwrap();
+        let attrs_expected_result = HwsimAttrSet::parse(tx_info_expected.attributes());
+        assert!(attrs_expected_result.is_ok());
+        let attrs_expected = attrs_expected_result.unwrap();
 
         // NOTE: TX info is different and the counts are all zeros in the TX info packet generated by WifiService.
         // TODO: Confirm if the behavior is intended in WifiService.
@@ -796,21 +848,24 @@ mod tests {
         assert_eq!(attrs.flags, attrs_expected.flags);
         assert_eq!(attrs.cookie, attrs_expected.cookie);
         assert_eq!(attrs.signal, attrs_expected.signal);
+        Ok(())
     }
 
     #[test]
-    fn test_build_tx_info_and_compare() {
+    fn test_build_tx_info_and_compare() -> WifiResult<()> {
         let frame_bytes = Bytes::from(include!("test_packets/hwsim_cmd_frame_request.csv"));
         let tx_info_expected_bytes =
             Bytes::from(include!("test_packets/hwsim_cmd_tx_info_response.csv"));
-        build_tx_info_and_compare(&frame_bytes, &tx_info_expected_bytes);
+        build_tx_info_and_compare(&frame_bytes, &tx_info_expected_bytes)?;
+        Ok(())
     }
 
     #[test]
-    fn test_build_tx_info_and_compare_mdns() {
+    fn test_build_tx_info_and_compare_mdns() -> WifiResult<()> {
         let frame_bytes = Bytes::from(include!("test_packets/hwsim_cmd_frame_request_mdns.csv"));
         let tx_info_expected_bytes =
             Bytes::from(include!("test_packets/hwsim_cmd_tx_info_response_mdns.csv"));
-        build_tx_info_and_compare(&frame_bytes, &tx_info_expected_bytes);
+        build_tx_info_and_compare(&frame_bytes, &tx_info_expected_bytes)?;
+        Ok(())
     }
 }
diff --git a/rust/daemon/src/wifi/mod.rs b/rust/daemon/src/wifi/mod.rs
index 712ad1c5..c9aa9c70 100644
--- a/rust/daemon/src/wifi/mod.rs
+++ b/rust/daemon/src/wifi/mod.rs
@@ -15,6 +15,7 @@
 // [cfg(test)] gets compiled during local Rust unit tests
 // [cfg(not(test))] avoids getting compiled during local Rust unit tests
 
+pub(crate) mod error;
 pub(crate) mod frame;
 #[cfg_attr(feature = "cuttlefish", path = "hostapd_cf.rs")]
 pub(crate) mod hostapd;
@@ -25,3 +26,4 @@ pub(crate) mod libslirp;
 pub(crate) mod mdns_forwarder;
 pub(crate) mod medium;
 pub(crate) mod radiotap;
+pub(crate) mod stats;
diff --git a/rust/daemon/src/wifi/radiotap.rs b/rust/daemon/src/wifi/radiotap.rs
index 30b6b6ec..eccdab11 100644
--- a/rust/daemon/src/wifi/radiotap.rs
+++ b/rust/daemon/src/wifi/radiotap.rs
@@ -18,8 +18,8 @@
 /// for logging 802.11 frames.
 ///
 /// See https://www.radiotap.org/
+use crate::wifi::error::{WifiError, WifiResult};
 use crate::wifi::frame::Frame;
-use anyhow::anyhow;
 use log::info;
 use netsim_packets::mac80211_hwsim::{HwsimCmd, HwsimMsg};
 use pdl_runtime::Packet;
@@ -54,7 +54,7 @@ enum HwsimCmdEnum {
     DelMacAddr,
 }
 
-fn parse_hwsim_cmd(packet: &[u8]) -> anyhow::Result<HwsimCmdEnum> {
+fn parse_hwsim_cmd(packet: &[u8]) -> WifiResult<HwsimCmdEnum> {
     let hwsim_msg = HwsimMsg::decode_full(packet)?;
     match hwsim_msg.hwsim_hdr.hwsim_cmd {
         HwsimCmd::Frame => {
@@ -62,7 +62,10 @@ fn parse_hwsim_cmd(packet: &[u8]) -> anyhow::Result<HwsimCmdEnum> {
             Ok(HwsimCmdEnum::Frame(Box::new(frame)))
         }
         HwsimCmd::TxInfoFrame => Ok(HwsimCmdEnum::TxInfoFrame),
-        _ => Err(anyhow!("Unknown HwsimMsg cmd={:?}", hwsim_msg.hwsim_hdr.hwsim_cmd)),
+        _ => Err(WifiError::Other(format!(
+            "Unknown HwsimMsg cmd={:?}",
+            hwsim_msg.hwsim_hdr.hwsim_cmd
+        ))),
     }
 }
 
@@ -77,7 +80,7 @@ pub fn into_pcap(packet: &[u8]) -> Option<Vec<u8>> {
     }
 }
 
-pub fn frame_into_pcap(frame: Frame) -> anyhow::Result<Vec<u8>> {
+pub fn frame_into_pcap(frame: Frame) -> WifiResult<Vec<u8>> {
     // Create an instance of the RadiotapHeader with fields for
     // Channel and Signal.  In the future add more fields from the
     // Frame.
diff --git a/rust/daemon/src/wifi/stats.rs b/rust/daemon/src/wifi/stats.rs
new file mode 100644
index 00000000..5d7e01e5
--- /dev/null
+++ b/rust/daemon/src/wifi/stats.rs
@@ -0,0 +1,200 @@
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
+//! Wi-Fi Statistics Module
+//! This module provides structures and functions for tracking and managing Wi-Fi related statistics.
+
+use crate::wifi::error::WifiError;
+use log::{debug, warn};
+use netsim_proto::stats::WifiStats as ProtoWifiStats;
+use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
+use std::sync::Arc;
+use std::time::{Duration, SystemTime, UNIX_EPOCH};
+
+#[derive(Debug, Default)]
+pub struct WifiStats {
+    counts: Arc<WifiCounts>,
+    values: Arc<WifiValues>,
+}
+
+impl Clone for WifiStats {
+    fn clone(&self) -> Self {
+        WifiStats { counts: self.counts.clone(), values: self.values.clone() }
+    }
+}
+
+#[derive(Debug, Default)]
+struct WifiCounts {
+    // === Error Counters (Proto fields 1-6) ===
+    hostapd_error: AtomicU32,
+    network_error: AtomicU32,
+    client_error: AtomicU32,
+    frame_error: AtomicU32,
+    transmission_error: AtomicU32,
+    other_error: AtomicU32,
+
+    // === Core Traffic Flow & Type Counters (Proto fields 7-14) ===
+    hwsim_frames_rx: AtomicU32,
+    hwsim_frames_tx: AtomicU32,
+    network_packets_tx: AtomicU32,
+    network_packets_rx: AtomicU32,
+    hostapd_frames_tx: AtomicU32,
+    hostapd_frames_rx: AtomicU32,
+    wmedium_frames_tx: AtomicU32,
+    wmedium_unicast_frames_tx: AtomicU32,
+    mgmt_frames_rx: AtomicU32,
+
+    // === Specific Protocol Counters (Proto fields 15-16) ===
+    // TODO: Identify Wi-Fi Direct (P2P) frames in medium.rs and increment this counter.
+    mdns_count: AtomicU32,
+}
+
+#[derive(Debug, Default)]
+struct ThroughputValues {
+    max_throughput: AtomicU32, // Max throughput in Mbits/sec
+    window_start: AtomicU64,   // Start of the current window as milliseconds since epoch
+    window_bytes: AtomicU64,   // Total number of bytes in the current window
+}
+
+#[derive(Debug, Default)]
+struct WifiValues {
+    // Fields for throughput values
+    download_throughput: ThroughputValues,
+    upload_throughput: ThroughputValues,
+}
+
+// Define the macro to generate incrementer methods
+macro_rules! impl_incr_method {
+    ($method:ident, $field:ident) => {
+        pub fn $method(&self) {
+            self.counts.$field.fetch_add(1, Ordering::Relaxed);
+        }
+    };
+}
+
+impl WifiStats {
+    fn record_throughput(&self, throughput_values: &ThroughputValues, bytes: usize, name: &str) {
+        const WINDOW_MILLIS: u64 = Duration::from_secs(5).as_millis() as u64;
+        let now =
+            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
+        let start_time = throughput_values.window_start.load(Ordering::Relaxed);
+
+        if start_time == 0 {
+            // First packet, initialize the window start time and bytes
+            throughput_values.window_start.store(now, Ordering::Relaxed);
+            throughput_values.window_bytes.store(bytes as u64, Ordering::Relaxed);
+        } else if now.saturating_sub(start_time) < WINDOW_MILLIS {
+            // Within the current window, just add the bytes
+            throughput_values.window_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
+        } else {
+            // Window expired, calculate throughput and reset window
+            let window_bytes = throughput_values.window_bytes.load(Ordering::Relaxed);
+            let elapsed = now.saturating_sub(start_time) as f64 / 1000.0;
+            let current_throughput = (window_bytes as f64 / elapsed) as u32;
+            debug!("{} Throughput Result: Interval: {:.2} sec, Transfer: {:.2} MBytes, Current Throughput: {:.1} Mbits/sec, Previous Max Throughput: {:.1} Mbits/s",
+                name,
+                elapsed,
+                (window_bytes as f64) / (1024.0 * 1024.0),
+                Self::bytes_ps_to_mbps(current_throughput),
+                Self::bytes_ps_to_mbps(throughput_values.max_throughput.load(Ordering::Relaxed))
+            );
+            // Store current max throughput
+            throughput_values.max_throughput.fetch_max(current_throughput, Ordering::Relaxed);
+
+            // Start a new window with the current packet's bytes
+            throughput_values.window_start.store(now, Ordering::Relaxed);
+            throughput_values.window_bytes.store(bytes as u64, Ordering::Relaxed);
+        }
+    }
+
+    pub fn record_download_bytes(&self, bytes: usize) {
+        self.record_throughput(&self.values.download_throughput, bytes, "Download");
+    }
+
+    pub fn record_upload_bytes(&self, bytes: usize) {
+        self.record_throughput(&self.values.upload_throughput, bytes, "Upload");
+    }
+
+    /// Logs the error and increments the corresponding counter.
+    pub fn log_and_incr_err_count(&self, error: &WifiError) {
+        warn!("{}", error);
+        let counter = match error {
+            WifiError::Hostapd(_) => &self.counts.hostapd_error,
+            WifiError::Network(_) => &self.counts.network_error,
+            WifiError::Client(_) => &self.counts.client_error,
+            WifiError::Frame(_) => &self.counts.frame_error,
+            WifiError::Transmission(_) => &self.counts.transmission_error,
+            _ => &self.counts.other_error,
+        };
+        counter.fetch_add(1, Ordering::Relaxed);
+    }
+
+    // Use the macro to generate the incrementer methods for usage counters
+    impl_incr_method!(incr_hwsim_frames_rx, hwsim_frames_rx);
+    impl_incr_method!(incr_hwsim_frames_tx, hwsim_frames_tx);
+    impl_incr_method!(incr_network_packets_tx, network_packets_tx);
+    impl_incr_method!(incr_network_packets_rx, network_packets_rx);
+    impl_incr_method!(incr_hostapd_frames_tx, hostapd_frames_tx);
+    impl_incr_method!(incr_hostapd_frames_rx, hostapd_frames_rx);
+    impl_incr_method!(incr_wmedium_frames_tx, wmedium_frames_tx);
+    impl_incr_method!(incr_wmedium_unicast_frames_tx, wmedium_unicast_frames_tx);
+    impl_incr_method!(incr_mgmt_frames_rx, mgmt_frames_rx);
+    impl_incr_method!(incr_mdns_count, mdns_count);
+
+    /// Helper function to convert bytes per second to megabits per second.
+    pub fn bytes_ps_to_mbps(bytes_per_second: u32) -> f32 {
+        ((bytes_per_second as f64 * 8.0) / (1_000_000.0)) as f32
+    }
+}
+
+fn load_as_option_i32(counter: &AtomicU32) -> Option<i32> {
+    Some(counter.load(Ordering::Relaxed) as i32)
+}
+
+impl From<&WifiStats> for ProtoWifiStats {
+    fn from(wifi_stats: &WifiStats) -> Self {
+        let counts = &wifi_stats.counts;
+        let values = &wifi_stats.values;
+        let to_mbps =
+            |bytes: &AtomicU32| Some(WifiStats::bytes_ps_to_mbps(bytes.load(Ordering::Relaxed)));
+        ProtoWifiStats {
+            // Errors
+            hostapd_errors: load_as_option_i32(&counts.hostapd_error),
+            network_errors: load_as_option_i32(&counts.network_error),
+            client_errors: load_as_option_i32(&counts.client_error),
+            frame_errors: load_as_option_i32(&counts.frame_error),
+            transmission_errors: load_as_option_i32(&counts.transmission_error),
+            other_errors: load_as_option_i32(&counts.other_error),
+
+            // Core Flow & Type
+            hwsim_frames_rx: load_as_option_i32(&counts.hwsim_frames_rx),
+            hwsim_frames_tx: load_as_option_i32(&counts.hwsim_frames_tx),
+            network_packets_tx: load_as_option_i32(&counts.network_packets_tx),
+            network_packets_rx: load_as_option_i32(&counts.network_packets_rx),
+            hostapd_frames_tx: load_as_option_i32(&counts.hostapd_frames_tx),
+            hostapd_frames_rx: load_as_option_i32(&counts.hostapd_frames_rx),
+            wmedium_frames_tx: load_as_option_i32(&counts.wmedium_frames_tx),
+            wmedium_unicast_frames_tx: load_as_option_i32(&counts.wmedium_unicast_frames_tx),
+            mgmt_frames_rx: load_as_option_i32(&counts.mgmt_frames_rx),
+
+            // Specific Protocols
+            mdns_count: load_as_option_i32(&counts.mdns_count),
+
+            // Performance data
+            max_download_throughput: to_mbps(&values.download_throughput.max_throughput),
+            max_upload_throughput: to_mbps(&values.upload_throughput.max_throughput),
+            ..Default::default()
+        }
+    }
+}
diff --git a/rust/daemon/src/wireless/wifi_manager.rs b/rust/daemon/src/wireless/wifi_manager.rs
index 386e9cae..e633c7ec 100644
--- a/rust/daemon/src/wireless/wifi_manager.rs
+++ b/rust/daemon/src/wireless/wifi_manager.rs
@@ -14,16 +14,18 @@
 
 use crate::devices::chip::ChipIdentifier;
 use crate::get_runtime;
+use crate::wifi::error::{WifiError, WifiResult};
 use crate::wifi::hostapd;
 use crate::wifi::libslirp;
 #[cfg(not(feature = "cuttlefish"))]
 use crate::wifi::mdns_forwarder;
 use crate::wifi::medium::Medium;
+use crate::wifi::stats::WifiStats;
 use crate::wireless::wifi_chip::{CreateParams, WifiChip};
 use crate::wireless::{packet::handle_response, WirelessChipImpl};
-use anyhow;
 use bytes::Bytes;
 use log::{info, warn};
+use netsim_packets::ieee80211;
 use netsim_proto::config::WiFi as WiFiConfig;
 use protobuf::MessageField;
 use std::sync::{mpsc, Arc, OnceLock};
@@ -37,7 +39,7 @@ pub fn wifi_start(
     forward_host_mdns: bool,
     wifi_args: Option<Vec<String>>,
     wifi_tap: Option<String>,
-) {
+) -> WifiStats {
     let (tx_request, rx_request) = mpsc::channel::<(u32, Bytes)>();
     let (tx_ieee8023_response, rx_ieee8023_response) = mpsc::channel::<Bytes>();
     let tx_ieee8023_response_clone = tx_ieee8023_response.clone();
@@ -46,7 +48,7 @@ pub fn wifi_start(
     let network: Box<dyn Network> = if wifi_tap.is_some() {
         todo!();
     } else {
-        SlirpNetwork::start(config, tx_ieee8023_response_clone)
+        SlirpNetwork::start(config, tx_ieee8023_response_clone).unwrap()
     };
 
     let hostapd_opt = wifi_config.hostapd_options.as_ref().unwrap_or_default().clone();
@@ -57,11 +59,18 @@ pub fn wifi_start(
         get_runtime().block_on(hostapd::hostapd_run(hostapd_opt, tx_ieee80211_response, wifi_args));
     let hostapd = hostapd_result.map_err(|e| warn!("Failed to run hostapd. {e}")).unwrap();
 
-    let _ = WIFI_MANAGER.set(Arc::new(WifiManager::new(tx_request, network, hostapd)));
+    let wifi_stats = WifiStats::default();
+    let _ = WIFI_MANAGER.set(Arc::new(WifiManager::new(
+        tx_request,
+        network,
+        hostapd,
+        wifi_stats.clone(),
+    )));
     let wifi_manager = get_wifi_manager();
 
     if let Err(e) = start_threads(
         wifi_manager,
+        wifi_stats.clone(),
         rx_request,
         rx_ieee8023_response,
         rx_ieee80211_response,
@@ -70,6 +79,7 @@ pub fn wifi_start(
     ) {
         warn!("Failed to start Wi-Fi manager: {}", e);
     }
+    wifi_stats
 }
 
 /// Stops the WiFi service.
@@ -97,12 +107,10 @@ impl SlirpNetwork {
     fn start(
         wifi_config: &WiFiConfig,
         tx_ieee8023_response: mpsc::Sender<Bytes>,
-    ) -> Box<dyn Network> {
+    ) -> WifiResult<Box<dyn Network>> {
         let slirp_opt = wifi_config.slirp_options.as_ref().unwrap_or_default().clone();
-        let slirp = libslirp::slirp_run(slirp_opt, tx_ieee8023_response)
-            .map_err(|e| warn!("Failed to run libslirp. {e}"))
-            .unwrap();
-        Box::new(SlirpNetwork { slirp })
+        let slirp = libslirp::slirp_run(slirp_opt, tx_ieee8023_response)?;
+        Ok(Box::new(SlirpNetwork { slirp }))
     }
 }
 
@@ -124,10 +132,11 @@ impl WifiManager {
         tx_request: mpsc::Sender<(u32, Bytes)>,
         network: Box<dyn Network>,
         hostapd: hostapd::Hostapd,
+        wifi_stats: WifiStats,
     ) -> WifiManager {
         let hostapd = Arc::new(hostapd);
         WifiManager {
-            medium: Medium::new(medium_callback, hostapd.clone()),
+            medium: Medium::new(medium_callback, hostapd.clone(), wifi_stats),
             tx_request,
             network,
             hostapd,
@@ -141,15 +150,16 @@ impl WifiManager {
 /// * One to handle IEEE802.11 responses from hostapd.
 fn start_threads(
     wifi_manager: Arc<WifiManager>,
+    wifi_stats: WifiStats,
     rx_request: mpsc::Receiver<(u32, Bytes)>,
     rx_ieee8023_response: mpsc::Receiver<Bytes>,
     rx_ieee80211_response: tokio_mpsc::Receiver<Bytes>,
     tx_ieee8023_response: mpsc::Sender<Bytes>,
     forward_host_mdns: bool,
-) -> anyhow::Result<()> {
-    start_request_thread(wifi_manager.clone(), rx_request)?;
-    start_ieee8023_response_thread(wifi_manager.clone(), rx_ieee8023_response)?;
-    start_ieee80211_response_thread(wifi_manager.clone(), rx_ieee80211_response)?;
+) -> WifiResult<()> {
+    start_request_thread(wifi_manager.clone(), rx_request, wifi_stats.clone())?;
+    start_ieee8023_response_thread(wifi_manager.clone(), rx_ieee8023_response, wifi_stats.clone())?;
+    start_ieee80211_response_thread(wifi_manager.clone(), rx_ieee80211_response, wifi_stats)?;
     if forward_host_mdns {
         start_mdns_forwarder_thread(tx_ieee8023_response)?;
     }
@@ -159,7 +169,8 @@ fn start_threads(
 fn start_request_thread(
     wifi_manager: Arc<WifiManager>,
     rx_request: mpsc::Receiver<(u32, Bytes)>,
-) -> anyhow::Result<()> {
+    wifi_stats: WifiStats,
+) -> WifiResult<()> {
     let hostapd = wifi_manager.hostapd.clone(); // Arc clone for thread
     thread::Builder::new().name("Wi-Fi HwsimMsg request".to_string()).spawn(move || {
         const POLL_INTERVAL: Duration = Duration::from_millis(1);
@@ -174,33 +185,52 @@ fn start_request_thread(
             };
             match rx_request.recv_timeout(timeout) {
                 Ok((chip_id, packet)) => {
-                    if let Some(processor) = wifi_manager.medium.get_processor(chip_id, &packet) {
-                        wifi_manager.medium.ack_frame(chip_id, &processor.frame);
-                        if processor.hostapd {
-                            let ieee80211: Bytes = processor.get_ieee80211_bytes();
-                            let hostapd_clone = hostapd.clone();
-                            get_runtime().block_on(async move {
-                                if let Err(err) = hostapd_clone.input(ieee80211).await {
-                                    warn!("Failed to call hostapd input: {:?}", err);
-                                };
-                            });
-                        }
-                        if processor.network {
-                            match processor.get_ieee80211().to_ieee8023() {
-                                Ok(ethernet_frame) => {
-                                    wifi_manager.network.input(ethernet_frame.into())
+                    match wifi_manager.medium.get_processor(chip_id, &packet) {
+                        Err(e) => wifi_stats.log_and_incr_err_count(&e),
+                        Ok(processor) => {
+                            if let Err(e) = wifi_manager.medium.ack_frame(chip_id, &processor.frame)
+                            {
+                                wifi_stats.log_and_incr_err_count(&e);
+                            }
+                            if processor.hostapd {
+                                let ieee80211: Bytes = processor.get_ieee80211_bytes();
+                                let hostapd_clone = hostapd.clone();
+                                let wifi_stats_clone = wifi_stats.clone();
+                                get_runtime().block_on(async move {
+                                    wifi_stats_clone.incr_hostapd_frames_tx();
+                                    if let Err(err) = hostapd_clone.input(ieee80211).await {
+                                        wifi_stats_clone.log_and_incr_err_count(
+                                            &WifiError::Hostapd(format!("Failed to call hostapd input from client: {chip_id}: {err}")),
+                                        );
+                                    }
+                                });
+                            }
+                            if processor.network {
+                                match processor.get_ieee80211().to_ieee8023() {
+                                    Ok(ethernet_frame) => {
+                                        wifi_stats.incr_network_packets_tx();
+                                        // Record throughput. Payload size is ieee802.3 frame len - header len
+                                        wifi_stats.record_upload_bytes(ethernet_frame.len() - ieee80211::Ieee8023::HDR_LEN);
+                                        wifi_manager.network.input(ethernet_frame.into())
+                                    }
+                                    Err(err) => {
+                                        wifi_stats.log_and_incr_err_count(&WifiError::Frame(
+                                            format!("Failed to convert 802.11 to 802.3 from client: {chip_id}: {err}"),
+                                        ));
+                                    }
                                 }
-                                Err(err) => {
-                                    warn!("Failed to convert 802.11 to 802.3: {}", err)
+                            }
+                            if processor.wmedium {
+                                // Decrypt the frame using the sender's key and re-encrypt it using the receiver's key for peer-to-peer communication through hostapd (broadcast or unicast).
+                                let ieee80211 = processor.get_ieee80211().clone();
+                                if let Err(e) =
+                                    wifi_manager.medium.queue_frame(processor.frame, ieee80211)
+                                {
+                                    wifi_stats.log_and_incr_err_count(&e);
                                 }
                             }
                         }
-                        if processor.wmedium {
-                            // Decrypt the frame using the sender's key and re-encrypt it using the receiver's key for peer-to-peer communication through hostapd (broadcast or unicast).
-                            let ieee80211 = processor.get_ieee80211().clone();
-                            wifi_manager.medium.queue_frame(processor.frame, ieee80211);
-                        }
-                    }
+                    };
                 }
                 _ => {
                     next_instant = Instant::now() + POLL_INTERVAL;
@@ -218,10 +248,16 @@ fn start_request_thread(
 fn start_ieee8023_response_thread(
     wifi_manager: Arc<WifiManager>,
     rx_ieee8023_response: mpsc::Receiver<Bytes>,
-) -> anyhow::Result<()> {
+    wifi_stats: WifiStats,
+) -> WifiResult<()> {
     thread::Builder::new().name("Wi-Fi IEEE802.3 response".to_string()).spawn(move || {
         for packet in rx_ieee8023_response {
-            wifi_manager.medium.process_ieee8023_response(&packet);
+            wifi_stats.incr_network_packets_rx();
+            // Record throughput. Actual data size is ieee802.3 frame len - header len
+            wifi_stats.record_download_bytes(packet.len() - ieee80211::Ieee8023::HDR_LEN);
+            if let Err(e) = wifi_manager.medium.process_ieee8023_response(&packet) {
+                wifi_stats.log_and_incr_err_count(&e);
+            }
         }
     })?;
     Ok(())
@@ -234,22 +270,26 @@ fn start_ieee8023_response_thread(
 fn start_ieee80211_response_thread(
     wifi_manager: Arc<WifiManager>,
     mut rx_ieee80211_response: tokio_mpsc::Receiver<Bytes>,
-) -> anyhow::Result<()> {
+    wifi_stats: WifiStats,
+) -> WifiResult<()> {
     thread::Builder::new().name("Wi-Fi IEEE802.11 response".to_string()).spawn(move || {
         while let Some(packet) = get_runtime().block_on(rx_ieee80211_response.recv()) {
-            wifi_manager.medium.process_ieee80211_response(&packet);
+            wifi_stats.incr_hostapd_frames_rx();
+            if let Err(e) = wifi_manager.medium.process_ieee80211_response(&packet) {
+                wifi_stats.log_and_incr_err_count(&e);
+            }
         }
     })?;
     Ok(())
 }
 
 #[cfg(feature = "cuttlefish")]
-fn start_mdns_forwarder_thread(_tx_ieee8023_response: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
+fn start_mdns_forwarder_thread(_tx_ieee8023_response: mpsc::Sender<Bytes>) -> WifiResult<()> {
     Ok(())
 }
 
 #[cfg(not(feature = "cuttlefish"))]
-fn start_mdns_forwarder_thread(tx_ieee8023_response: mpsc::Sender<Bytes>) -> anyhow::Result<()> {
+fn start_mdns_forwarder_thread(tx_ieee8023_response: mpsc::Sender<Bytes>) -> WifiResult<()> {
     info!("Start mDNS forwarder thread");
     thread::Builder::new().name("Wi-Fi mDNS forwarder".to_string()).spawn(move || {
         if let Err(e) = mdns_forwarder::run_mdns_forwarder(tx_ieee8023_response) {
diff --git a/rust/packets/src/ieee80211.rs b/rust/packets/src/ieee80211.rs
index 87d2b7aa..ad998720 100644
--- a/rust/packets/src/ieee80211.rs
+++ b/rust/packets/src/ieee80211.rs
@@ -41,9 +41,29 @@ const WLAN_ACTION_VENDOR_SPECIFIC: u8 = 127;
 /// A Ieee80211 MAC address
 
 impl MacAddress {
+    pub const LEN: usize = 6;
+
+    const MDNS_MULTICAST_V4: MacAddress =
+        MacAddress(u64::from_le_bytes([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0, 0]));
+    const MDNS_MULTICAST_V6: MacAddress =
+        MacAddress(u64::from_le_bytes([0x33, 0x33, 0x5e, 0x00, 0x00, 0xfb, 0, 0]));
+
     pub fn to_vec(&self) -> [u8; 6] {
         u64::to_le_bytes(self.0)[0..6].try_into().expect("slice with incorrect length")
     }
+
+    pub fn is_multicast(&self) -> bool {
+        let addr = u64::to_le_bytes(self.0);
+        (addr[0] & 0x1) == 1
+    }
+
+    pub fn is_broadcast(&self) -> bool {
+        self.0 == u64::MAX
+    }
+
+    pub fn is_mdns(&self) -> bool {
+        self == &Self::MDNS_MULTICAST_V4 || self == &Self::MDNS_MULTICAST_V6
+    }
 }
 
 // TODO: Add unit tests.
@@ -83,20 +103,7 @@ impl From<MacAddress> for [u8; 6] {
     }
 }
 
-impl MacAddress {
-    pub const LEN: usize = 6;
-
-    pub fn is_multicast(&self) -> bool {
-        let addr = u64::to_le_bytes(self.0);
-        (addr[0] & 0x1) == 1
-    }
-
-    pub fn is_broadcast(&self) -> bool {
-        self.0 == u64::MAX
-    }
-}
-
-struct Ieee8023<'a> {
+pub struct Ieee8023<'a> {
     destination: MacAddress,
     source: MacAddress,
     ethertype: EtherType,
diff --git a/rust/proto/src/configuration.rs b/rust/proto/src/configuration.rs
index 315dd9cb..0b3e0bb9 100644
--- a/rust/proto/src/configuration.rs
+++ b/rust/proto/src/configuration.rs
@@ -1286,6 +1286,8 @@ pub enum ControllerPreset {
     LAIRD_BL654 = 1,
     // @@protoc_insertion_point(enum_value:rootcanal.configuration.ControllerPreset.CSR_RCK_PTS_DONGLE)
     CSR_RCK_PTS_DONGLE = 2,
+    // @@protoc_insertion_point(enum_value:rootcanal.configuration.ControllerPreset.INTEL_BE200)
+    INTEL_BE200 = 3,
 }
 
 impl ::protobuf::Enum for ControllerPreset {
@@ -1300,6 +1302,7 @@ impl ::protobuf::Enum for ControllerPreset {
             0 => ::std::option::Option::Some(ControllerPreset::DEFAULT),
             1 => ::std::option::Option::Some(ControllerPreset::LAIRD_BL654),
             2 => ::std::option::Option::Some(ControllerPreset::CSR_RCK_PTS_DONGLE),
+            3 => ::std::option::Option::Some(ControllerPreset::INTEL_BE200),
             _ => ::std::option::Option::None
         }
     }
@@ -1308,6 +1311,7 @@ impl ::protobuf::Enum for ControllerPreset {
         ControllerPreset::DEFAULT,
         ControllerPreset::LAIRD_BL654,
         ControllerPreset::CSR_RCK_PTS_DONGLE,
+        ControllerPreset::INTEL_BE200,
     ];
 }
 
@@ -1359,9 +1363,9 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     \x19\n\x08tcp_port\x18\x01\x20\x02(\x05R\x07tcpPort\x12I\n\rconfiguratio\
     n\x18\x02\x20\x01(\x0b2#.rootcanal.configuration.ControllerR\rconfigurat\
     ion\"R\n\rConfiguration\x12A\n\ntcp_server\x18\x01\x20\x03(\x0b2\".rootc\
-    anal.configuration.TcpServerR\ttcpServer*H\n\x10ControllerPreset\x12\x0b\
+    anal.configuration.TcpServerR\ttcpServer*Y\n\x10ControllerPreset\x12\x0b\
     \n\x07DEFAULT\x10\0\x12\x0f\n\x0bLAIRD_BL654\x10\x01\x12\x16\n\x12CSR_RC\
-    K_PTS_DONGLE\x10\x02B\x02H\x02\
+    K_PTS_DONGLE\x10\x02\x12\x0f\n\x0bINTEL_BE200\x10\x03B\x02H\x02\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
diff --git a/rust/proto/src/frontend.rs b/rust/proto/src/frontend.rs
index 0e5bf79c..9d272b3c 100644
--- a/rust/proto/src/frontend.rs
+++ b/rust/proto/src/frontend.rs
@@ -2032,6 +2032,375 @@ impl ::protobuf::reflect::ProtobufValue for GetCaptureResponse {
     type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
 }
 
+#[derive(PartialEq,Clone,Default,Debug)]
+// @@protoc_insertion_point(message:netsim.frontend.ListLinkResponse)
+pub struct ListLinkResponse {
+    // message fields
+    // @@protoc_insertion_point(field:netsim.frontend.ListLinkResponse.links)
+    pub links: ::std::vec::Vec<super::model::Link>,
+    // special fields
+    // @@protoc_insertion_point(special_field:netsim.frontend.ListLinkResponse.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a ListLinkResponse {
+    fn default() -> &'a ListLinkResponse {
+        <ListLinkResponse as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl ListLinkResponse {
+    pub fn new() -> ListLinkResponse {
+        ::std::default::Default::default()
+    }
+
+    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+        let mut fields = ::std::vec::Vec::with_capacity(1);
+        let mut oneofs = ::std::vec::Vec::with_capacity(0);
+        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
+            "links",
+            |m: &ListLinkResponse| { &m.links },
+            |m: &mut ListLinkResponse| { &mut m.links },
+        ));
+        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ListLinkResponse>(
+            "ListLinkResponse",
+            fields,
+            oneofs,
+        )
+    }
+}
+
+impl ::protobuf::Message for ListLinkResponse {
+    const NAME: &'static str = "ListLinkResponse";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                10 => {
+                    self.links.push(is.read_message()?);
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        for value in &self.links {
+            let len = value.compute_size();
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+        };
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        for v in &self.links {
+            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
+        };
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> ListLinkResponse {
+        ListLinkResponse::new()
+    }
+
+    fn clear(&mut self) {
+        self.links.clear();
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static ListLinkResponse {
+        static instance: ListLinkResponse = ListLinkResponse {
+            links: ::std::vec::Vec::new(),
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+impl ::protobuf::MessageFull for ListLinkResponse {
+    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+        descriptor.get(|| file_descriptor().message_by_package_relative_name("ListLinkResponse").unwrap()).clone()
+    }
+}
+
+impl ::std::fmt::Display for ListLinkResponse {
+    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+        ::protobuf::text_format::fmt(self, f)
+    }
+}
+
+impl ::protobuf::reflect::ProtobufValue for ListLinkResponse {
+    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+}
+
+#[derive(PartialEq,Clone,Default,Debug)]
+// @@protoc_insertion_point(message:netsim.frontend.PatchLinkRequest)
+pub struct PatchLinkRequest {
+    // message fields
+    // @@protoc_insertion_point(field:netsim.frontend.PatchLinkRequest.link)
+    pub link: ::protobuf::MessageField<super::model::Link>,
+    // special fields
+    // @@protoc_insertion_point(special_field:netsim.frontend.PatchLinkRequest.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a PatchLinkRequest {
+    fn default() -> &'a PatchLinkRequest {
+        <PatchLinkRequest as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl PatchLinkRequest {
+    pub fn new() -> PatchLinkRequest {
+        ::std::default::Default::default()
+    }
+
+    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+        let mut fields = ::std::vec::Vec::with_capacity(1);
+        let mut oneofs = ::std::vec::Vec::with_capacity(0);
+        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::model::Link>(
+            "link",
+            |m: &PatchLinkRequest| { &m.link },
+            |m: &mut PatchLinkRequest| { &mut m.link },
+        ));
+        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<PatchLinkRequest>(
+            "PatchLinkRequest",
+            fields,
+            oneofs,
+        )
+    }
+}
+
+impl ::protobuf::Message for PatchLinkRequest {
+    const NAME: &'static str = "PatchLinkRequest";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                10 => {
+                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.link)?;
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        if let Some(v) = self.link.as_ref() {
+            let len = v.compute_size();
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+        }
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if let Some(v) = self.link.as_ref() {
+            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
+        }
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> PatchLinkRequest {
+        PatchLinkRequest::new()
+    }
+
+    fn clear(&mut self) {
+        self.link.clear();
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static PatchLinkRequest {
+        static instance: PatchLinkRequest = PatchLinkRequest {
+            link: ::protobuf::MessageField::none(),
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+impl ::protobuf::MessageFull for PatchLinkRequest {
+    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+        descriptor.get(|| file_descriptor().message_by_package_relative_name("PatchLinkRequest").unwrap()).clone()
+    }
+}
+
+impl ::std::fmt::Display for PatchLinkRequest {
+    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+        ::protobuf::text_format::fmt(self, f)
+    }
+}
+
+impl ::protobuf::reflect::ProtobufValue for PatchLinkRequest {
+    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+}
+
+#[derive(PartialEq,Clone,Default,Debug)]
+// @@protoc_insertion_point(message:netsim.frontend.DeleteLinkRequest)
+pub struct DeleteLinkRequest {
+    // message fields
+    // @@protoc_insertion_point(field:netsim.frontend.DeleteLinkRequest.link)
+    pub link: ::protobuf::MessageField<super::model::Link>,
+    // special fields
+    // @@protoc_insertion_point(special_field:netsim.frontend.DeleteLinkRequest.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a DeleteLinkRequest {
+    fn default() -> &'a DeleteLinkRequest {
+        <DeleteLinkRequest as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl DeleteLinkRequest {
+    pub fn new() -> DeleteLinkRequest {
+        ::std::default::Default::default()
+    }
+
+    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+        let mut fields = ::std::vec::Vec::with_capacity(1);
+        let mut oneofs = ::std::vec::Vec::with_capacity(0);
+        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::model::Link>(
+            "link",
+            |m: &DeleteLinkRequest| { &m.link },
+            |m: &mut DeleteLinkRequest| { &mut m.link },
+        ));
+        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<DeleteLinkRequest>(
+            "DeleteLinkRequest",
+            fields,
+            oneofs,
+        )
+    }
+}
+
+impl ::protobuf::Message for DeleteLinkRequest {
+    const NAME: &'static str = "DeleteLinkRequest";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                10 => {
+                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.link)?;
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        if let Some(v) = self.link.as_ref() {
+            let len = v.compute_size();
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+        }
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if let Some(v) = self.link.as_ref() {
+            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
+        }
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> DeleteLinkRequest {
+        DeleteLinkRequest::new()
+    }
+
+    fn clear(&mut self) {
+        self.link.clear();
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static DeleteLinkRequest {
+        static instance: DeleteLinkRequest = DeleteLinkRequest {
+            link: ::protobuf::MessageField::none(),
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+impl ::protobuf::MessageFull for DeleteLinkRequest {
+    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+        descriptor.get(|| file_descriptor().message_by_package_relative_name("DeleteLinkRequest").unwrap()).clone()
+    }
+}
+
+impl ::std::fmt::Display for DeleteLinkRequest {
+    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+        ::protobuf::text_format::fmt(self, f)
+    }
+}
+
+impl ::protobuf::reflect::ProtobufValue for DeleteLinkRequest {
+    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+}
+
 static file_descriptor_proto_data: &'static [u8] = b"\
     \n\x15netsim/frontend.proto\x12\x0fnetsim.frontend\x1a\x1bgoogle/protobu\
     f/empty.proto\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\x12netsim/model\
@@ -2066,10 +2435,14 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     \x13ListCaptureResponse\x121\n\x08captures\x18\x01\x20\x03(\x0b2\x15.net\
     sim.model.CaptureR\x08captures\"#\n\x11GetCaptureRequest\x12\x0e\n\x02id\
     \x18\x01\x20\x01(\rR\x02id\";\n\x12GetCaptureResponse\x12%\n\x0ecapture_\
-    stream\x18\x01\x20\x01(\x0cR\rcaptureStream2\xaa\x06\n\x0fFrontendServic\
-    e\x12F\n\nGetVersion\x12\x16.google.protobuf.Empty\x1a\x20.netsim.fronte\
-    nd.VersionResponse\x12[\n\x0cCreateDevice\x12$.netsim.frontend.CreateDev\
-    iceRequest\x1a%.netsim.frontend.CreateDeviceResponse\x12H\n\nDeleteChip\
+    stream\x18\x01\x20\x01(\x0cR\rcaptureStream\"<\n\x10ListLinkResponse\x12\
+    (\n\x05links\x18\x01\x20\x03(\x0b2\x12.netsim.model.LinkR\x05links\":\n\
+    \x10PatchLinkRequest\x12&\n\x04link\x18\x01\x20\x01(\x0b2\x12.netsim.mod\
+    el.LinkR\x04link\";\n\x11DeleteLinkRequest\x12&\n\x04link\x18\x01\x20\
+    \x01(\x0b2\x12.netsim.model.LinkR\x04link2\x83\x08\n\x0fFrontendService\
+    \x12F\n\nGetVersion\x12\x16.google.protobuf.Empty\x1a\x20.netsim.fronten\
+    d.VersionResponse\x12[\n\x0cCreateDevice\x12$.netsim.frontend.CreateDevi\
+    ceRequest\x1a%.netsim.frontend.CreateDeviceResponse\x12H\n\nDeleteChip\
     \x12\".netsim.frontend.DeleteChipRequest\x1a\x16.google.protobuf.Empty\
     \x12J\n\x0bPatchDevice\x12#.netsim.frontend.PatchDeviceRequest\x1a\x16.g\
     oogle.protobuf.Empty\x127\n\x05Reset\x12\x16.google.protobuf.Empty\x1a\
@@ -2080,7 +2453,11 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     reRequest\x1a\x16.google.protobuf.Empty\x12K\n\x0bListCapture\x12\x16.go\
     ogle.protobuf.Empty\x1a$.netsim.frontend.ListCaptureResponse\x12W\n\nGet\
     Capture\x12\".netsim.frontend.GetCaptureRequest\x1a#.netsim.frontend.Get\
-    CaptureResponse0\x01b\x06proto3\
+    CaptureResponse0\x01\x12E\n\x08ListLink\x12\x16.google.protobuf.Empty\
+    \x1a!.netsim.frontend.ListLinkResponse\x12F\n\tPatchLink\x12!.netsim.fro\
+    ntend.PatchLinkRequest\x1a\x16.google.protobuf.Empty\x12H\n\nDeleteLink\
+    \x12\".netsim.frontend.DeleteLinkRequest\x1a\x16.google.protobuf.Emptyb\
+    \x06proto3\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
@@ -2101,7 +2478,7 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             deps.push(::protobuf::well_known_types::empty::file_descriptor().clone());
             deps.push(::protobuf::well_known_types::timestamp::file_descriptor().clone());
             deps.push(super::model::file_descriptor().clone());
-            let mut messages = ::std::vec::Vec::with_capacity(14);
+            let mut messages = ::std::vec::Vec::with_capacity(17);
             messages.push(VersionResponse::generated_message_descriptor_data());
             messages.push(CreateDeviceRequest::generated_message_descriptor_data());
             messages.push(CreateDeviceResponse::generated_message_descriptor_data());
@@ -2114,6 +2491,9 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             messages.push(ListCaptureResponse::generated_message_descriptor_data());
             messages.push(GetCaptureRequest::generated_message_descriptor_data());
             messages.push(GetCaptureResponse::generated_message_descriptor_data());
+            messages.push(ListLinkResponse::generated_message_descriptor_data());
+            messages.push(PatchLinkRequest::generated_message_descriptor_data());
+            messages.push(DeleteLinkRequest::generated_message_descriptor_data());
             messages.push(patch_device_request::PatchDeviceFields::generated_message_descriptor_data());
             messages.push(patch_capture_request::PatchCapture::generated_message_descriptor_data());
             let mut enums = ::std::vec::Vec::with_capacity(0);
diff --git a/rust/proto/src/frontend_grpc.rs b/rust/proto/src/frontend_grpc.rs
index d8f529e3..dc69a34d 100644
--- a/rust/proto/src/frontend_grpc.rs
+++ b/rust/proto/src/frontend_grpc.rs
@@ -112,6 +112,36 @@ const METHOD_FRONTEND_SERVICE_GET_CAPTURE: ::grpcio::Method<
     resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
 };
 
+const METHOD_FRONTEND_SERVICE_LIST_LINK: ::grpcio::Method<
+    super::empty::Empty,
+    super::frontend::ListLinkResponse,
+> = ::grpcio::Method {
+    ty: ::grpcio::MethodType::Unary,
+    name: "/netsim.frontend.FrontendService/ListLink",
+    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+};
+
+const METHOD_FRONTEND_SERVICE_PATCH_LINK: ::grpcio::Method<
+    super::frontend::PatchLinkRequest,
+    super::empty::Empty,
+> = ::grpcio::Method {
+    ty: ::grpcio::MethodType::Unary,
+    name: "/netsim.frontend.FrontendService/PatchLink",
+    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+};
+
+const METHOD_FRONTEND_SERVICE_DELETE_LINK: ::grpcio::Method<
+    super::frontend::DeleteLinkRequest,
+    super::empty::Empty,
+> = ::grpcio::Method {
+    ty: ::grpcio::MethodType::Unary,
+    name: "/netsim.frontend.FrontendService/DeleteLink",
+    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
+};
+
 #[derive(Clone)]
 pub struct FrontendServiceClient {
     pub client: ::grpcio::Client,
@@ -409,6 +439,96 @@ impl FrontendServiceClient {
     {
         self.get_capture_opt(req, ::grpcio::CallOption::default())
     }
+
+    pub fn list_link_opt(
+        &self,
+        req: &super::empty::Empty,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<super::frontend::ListLinkResponse> {
+        self.client.unary_call(&METHOD_FRONTEND_SERVICE_LIST_LINK, req, opt)
+    }
+
+    pub fn list_link(
+        &self,
+        req: &super::empty::Empty,
+    ) -> ::grpcio::Result<super::frontend::ListLinkResponse> {
+        self.list_link_opt(req, ::grpcio::CallOption::default())
+    }
+
+    pub fn list_link_async_opt(
+        &self,
+        req: &super::empty::Empty,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::frontend::ListLinkResponse>> {
+        self.client.unary_call_async(&METHOD_FRONTEND_SERVICE_LIST_LINK, req, opt)
+    }
+
+    pub fn list_link_async(
+        &self,
+        req: &super::empty::Empty,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::frontend::ListLinkResponse>> {
+        self.list_link_async_opt(req, ::grpcio::CallOption::default())
+    }
+
+    pub fn patch_link_opt(
+        &self,
+        req: &super::frontend::PatchLinkRequest,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<super::empty::Empty> {
+        self.client.unary_call(&METHOD_FRONTEND_SERVICE_PATCH_LINK, req, opt)
+    }
+
+    pub fn patch_link(
+        &self,
+        req: &super::frontend::PatchLinkRequest,
+    ) -> ::grpcio::Result<super::empty::Empty> {
+        self.patch_link_opt(req, ::grpcio::CallOption::default())
+    }
+
+    pub fn patch_link_async_opt(
+        &self,
+        req: &super::frontend::PatchLinkRequest,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
+        self.client.unary_call_async(&METHOD_FRONTEND_SERVICE_PATCH_LINK, req, opt)
+    }
+
+    pub fn patch_link_async(
+        &self,
+        req: &super::frontend::PatchLinkRequest,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
+        self.patch_link_async_opt(req, ::grpcio::CallOption::default())
+    }
+
+    pub fn delete_link_opt(
+        &self,
+        req: &super::frontend::DeleteLinkRequest,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<super::empty::Empty> {
+        self.client.unary_call(&METHOD_FRONTEND_SERVICE_DELETE_LINK, req, opt)
+    }
+
+    pub fn delete_link(
+        &self,
+        req: &super::frontend::DeleteLinkRequest,
+    ) -> ::grpcio::Result<super::empty::Empty> {
+        self.delete_link_opt(req, ::grpcio::CallOption::default())
+    }
+
+    pub fn delete_link_async_opt(
+        &self,
+        req: &super::frontend::DeleteLinkRequest,
+        opt: ::grpcio::CallOption,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
+        self.client.unary_call_async(&METHOD_FRONTEND_SERVICE_DELETE_LINK, req, opt)
+    }
+
+    pub fn delete_link_async(
+        &self,
+        req: &super::frontend::DeleteLinkRequest,
+    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
+        self.delete_link_async_opt(req, ::grpcio::CallOption::default())
+    }
     pub fn spawn<F>(&self, f: F)
     where
         F: ::std::future::Future<Output = ()> + Send + 'static,
@@ -498,6 +618,30 @@ pub trait FrontendService {
     ) {
         grpcio::unimplemented_call!(ctx, sink)
     }
+    fn list_link(
+        &mut self,
+        ctx: ::grpcio::RpcContext,
+        _req: super::empty::Empty,
+        sink: ::grpcio::UnarySink<super::frontend::ListLinkResponse>,
+    ) {
+        grpcio::unimplemented_call!(ctx, sink)
+    }
+    fn patch_link(
+        &mut self,
+        ctx: ::grpcio::RpcContext,
+        _req: super::frontend::PatchLinkRequest,
+        sink: ::grpcio::UnarySink<super::empty::Empty>,
+    ) {
+        grpcio::unimplemented_call!(ctx, sink)
+    }
+    fn delete_link(
+        &mut self,
+        ctx: ::grpcio::RpcContext,
+        _req: super::frontend::DeleteLinkRequest,
+        sink: ::grpcio::UnarySink<super::empty::Empty>,
+    ) {
+        grpcio::unimplemented_call!(ctx, sink)
+    }
 }
 
 pub fn create_frontend_service<S: FrontendService + Send + Clone + 'static>(
@@ -548,10 +692,25 @@ pub fn create_frontend_service<S: FrontendService + Send + Clone + 'static>(
         .add_unary_handler(&METHOD_FRONTEND_SERVICE_LIST_CAPTURE, move |ctx, req, resp| {
             instance.list_capture(ctx, req, resp)
         });
-    let mut instance = s;
+    let mut instance = s.clone();
     builder = builder.add_server_streaming_handler(
         &METHOD_FRONTEND_SERVICE_GET_CAPTURE,
         move |ctx, req, resp| instance.get_capture(ctx, req, resp),
     );
+    let mut instance = s.clone();
+    builder = builder
+        .add_unary_handler(&METHOD_FRONTEND_SERVICE_LIST_LINK, move |ctx, req, resp| {
+            instance.list_link(ctx, req, resp)
+        });
+    let mut instance = s.clone();
+    builder = builder
+        .add_unary_handler(&METHOD_FRONTEND_SERVICE_PATCH_LINK, move |ctx, req, resp| {
+            instance.patch_link(ctx, req, resp)
+        });
+    let mut instance = s;
+    builder = builder
+        .add_unary_handler(&METHOD_FRONTEND_SERVICE_DELETE_LINK, move |ctx, req, resp| {
+            instance.delete_link(ctx, req, resp)
+        });
     builder.build()
 }
diff --git a/rust/proto/src/hci_packet.rs b/rust/proto/src/hci_packet.rs
index 9d7ca635..868796dc 100644
--- a/rust/proto/src/hci_packet.rs
+++ b/rust/proto/src/hci_packet.rs
@@ -243,9 +243,9 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     cketTypeR\npacketType\x12\x16\n\x06packet\x18\x02\x20\x01(\x0cR\x06packe\
     t\"[\n\nPacketType\x12\x1a\n\x16HCI_PACKET_UNSPECIFIED\x10\0\x12\x0b\n\
     \x07COMMAND\x10\x01\x12\x07\n\x03ACL\x10\x02\x12\x07\n\x03SCO\x10\x03\
-    \x12\t\n\x05EVENT\x10\x04\x12\x07\n\x03ISO\x10\x05BJ\n\x1fcom.android.em\
-    ulation.bluetoothP\x01\xf8\x01\x01\xa2\x02\x03AEB\xaa\x02\x1bAndroid.Emu\
-    lation.Bluetoothb\x06proto3\
+    \x12\t\n\x05EVENT\x10\x04\x12\x07\n\x03ISO\x10\x05BG\n\x1fcom.android.em\
+    ulation.bluetoothP\x01\xa2\x02\x03AEB\xaa\x02\x1bAndroid.Emulation.Bluet\
+    oothb\x06proto3\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
diff --git a/rust/proto/src/model.rs b/rust/proto/src/model.rs
index 8caef0b9..c882959e 100644
--- a/rust/proto/src/model.rs
+++ b/rust/proto/src/model.rs
@@ -3518,6 +3518,182 @@ impl ::protobuf::reflect::ProtobufValue for Capture {
     type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
 }
 
+#[derive(PartialEq,Clone,Default,Debug)]
+// @@protoc_insertion_point(message:netsim.model.Link)
+pub struct Link {
+    // message fields
+    // @@protoc_insertion_point(field:netsim.model.Link.sender_id)
+    pub sender_id: u32,
+    // @@protoc_insertion_point(field:netsim.model.Link.receiver_id)
+    pub receiver_id: u32,
+    // @@protoc_insertion_point(field:netsim.model.Link.link_kind)
+    pub link_kind: ::protobuf::EnumOrUnknown<PhyKind>,
+    // @@protoc_insertion_point(field:netsim.model.Link.rssi)
+    pub rssi: i32,
+    // special fields
+    // @@protoc_insertion_point(special_field:netsim.model.Link.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a Link {
+    fn default() -> &'a Link {
+        <Link as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl Link {
+    pub fn new() -> Link {
+        ::std::default::Default::default()
+    }
+
+    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+        let mut fields = ::std::vec::Vec::with_capacity(4);
+        let mut oneofs = ::std::vec::Vec::with_capacity(0);
+        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
+            "sender_id",
+            |m: &Link| { &m.sender_id },
+            |m: &mut Link| { &mut m.sender_id },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
+            "receiver_id",
+            |m: &Link| { &m.receiver_id },
+            |m: &mut Link| { &mut m.receiver_id },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
+            "link_kind",
+            |m: &Link| { &m.link_kind },
+            |m: &mut Link| { &mut m.link_kind },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
+            "rssi",
+            |m: &Link| { &m.rssi },
+            |m: &mut Link| { &mut m.rssi },
+        ));
+        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<Link>(
+            "Link",
+            fields,
+            oneofs,
+        )
+    }
+}
+
+impl ::protobuf::Message for Link {
+    const NAME: &'static str = "Link";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                8 => {
+                    self.sender_id = is.read_uint32()?;
+                },
+                16 => {
+                    self.receiver_id = is.read_uint32()?;
+                },
+                24 => {
+                    self.link_kind = is.read_enum_or_unknown()?;
+                },
+                32 => {
+                    self.rssi = is.read_int32()?;
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        if self.sender_id != 0 {
+            my_size += ::protobuf::rt::uint32_size(1, self.sender_id);
+        }
+        if self.receiver_id != 0 {
+            my_size += ::protobuf::rt::uint32_size(2, self.receiver_id);
+        }
+        if self.link_kind != ::protobuf::EnumOrUnknown::new(PhyKind::NONE) {
+            my_size += ::protobuf::rt::int32_size(3, self.link_kind.value());
+        }
+        if self.rssi != 0 {
+            my_size += ::protobuf::rt::int32_size(4, self.rssi);
+        }
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if self.sender_id != 0 {
+            os.write_uint32(1, self.sender_id)?;
+        }
+        if self.receiver_id != 0 {
+            os.write_uint32(2, self.receiver_id)?;
+        }
+        if self.link_kind != ::protobuf::EnumOrUnknown::new(PhyKind::NONE) {
+            os.write_enum(3, ::protobuf::EnumOrUnknown::value(&self.link_kind))?;
+        }
+        if self.rssi != 0 {
+            os.write_int32(4, self.rssi)?;
+        }
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> Link {
+        Link::new()
+    }
+
+    fn clear(&mut self) {
+        self.sender_id = 0;
+        self.receiver_id = 0;
+        self.link_kind = ::protobuf::EnumOrUnknown::new(PhyKind::NONE);
+        self.rssi = 0;
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static Link {
+        static instance: Link = Link {
+            sender_id: 0,
+            receiver_id: 0,
+            link_kind: ::protobuf::EnumOrUnknown::from_i32(0),
+            rssi: 0,
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+impl ::protobuf::MessageFull for Link {
+    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+        descriptor.get(|| file_descriptor().message_by_package_relative_name("Link").unwrap()).clone()
+    }
+}
+
+impl ::std::fmt::Display for Link {
+    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+        ::protobuf::text_format::fmt(self, f)
+    }
+}
+
+impl ::protobuf::reflect::ProtobufValue for Link {
+    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+}
+
 #[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
 // @@protoc_insertion_point(enum:netsim.model.PhyKind)
 pub enum PhyKind {
@@ -3670,9 +3846,13 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     \x05R\x04size\x12\x18\n\x07records\x18\x06\x20\x01(\x05R\x07records\x128\
     \n\ttimestamp\x18\x07\x20\x01(\x0b2\x1a.google.protobuf.TimestampR\ttime\
     stamp\x12\x14\n\x05valid\x18\x08\x20\x01(\x08R\x05validB\x08\n\x06_state\
-    *e\n\x07PhyKind\x12\x08\n\x04NONE\x10\0\x12\x15\n\x11BLUETOOTH_CLASSIC\
-    \x10\x01\x12\x18\n\x14BLUETOOTH_LOW_ENERGY\x10\x02\x12\x08\n\x04WIFI\x10\
-    \x03\x12\x07\n\x03UWB\x10\x04\x12\x0c\n\x08WIFI_RTT\x10\x05b\x06proto3\
+    \"\x8c\x01\n\x04Link\x12\x1b\n\tsender_id\x18\x01\x20\x01(\rR\x08senderI\
+    d\x12\x1f\n\x0breceiver_id\x18\x02\x20\x01(\rR\nreceiverId\x122\n\tlink_\
+    kind\x18\x03\x20\x01(\x0e2\x15.netsim.model.PhyKindR\x08linkKind\x12\x12\
+    \n\x04rssi\x18\x04\x20\x01(\x05R\x04rssi*e\n\x07PhyKind\x12\x08\n\x04NON\
+    E\x10\0\x12\x15\n\x11BLUETOOTH_CLASSIC\x10\x01\x12\x18\n\x14BLUETOOTH_LO\
+    W_ENERGY\x10\x02\x12\x08\n\x04WIFI\x10\x03\x12\x07\n\x03UWB\x10\x04\x12\
+    \x0c\n\x08WIFI_RTT\x10\x05b\x06proto3\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
@@ -3693,7 +3873,7 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             deps.push(super::common::file_descriptor().clone());
             deps.push(::protobuf::well_known_types::timestamp::file_descriptor().clone());
             deps.push(super::configuration::file_descriptor().clone());
-            let mut messages = ::std::vec::Vec::with_capacity(15);
+            let mut messages = ::std::vec::Vec::with_capacity(16);
             messages.push(Position::generated_message_descriptor_data());
             messages.push(Orientation::generated_message_descriptor_data());
             messages.push(Chip::generated_message_descriptor_data());
@@ -3702,6 +3882,7 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
             messages.push(DeviceCreate::generated_message_descriptor_data());
             messages.push(Scene::generated_message_descriptor_data());
             messages.push(Capture::generated_message_descriptor_data());
+            messages.push(Link::generated_message_descriptor_data());
             messages.push(chip::Radio::generated_message_descriptor_data());
             messages.push(chip::Bluetooth::generated_message_descriptor_data());
             messages.push(chip::BleBeacon::generated_message_descriptor_data());
diff --git a/rust/proto/src/stats.rs b/rust/proto/src/stats.rs
index 8d5dfe14..c042ecae 100644
--- a/rust/proto/src/stats.rs
+++ b/rust/proto/src/stats.rs
@@ -1746,6 +1746,776 @@ impl ::protobuf::reflect::ProtobufValue for NetsimDeviceStats {
     type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
 }
 
+#[derive(PartialEq,Clone,Default,Debug)]
+// @@protoc_insertion_point(message:netsim.stats.WifiStats)
+pub struct WifiStats {
+    // message fields
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.hostapd_errors)
+    pub hostapd_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.network_errors)
+    pub network_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.client_errors)
+    pub client_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.frame_errors)
+    pub frame_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.transmission_errors)
+    pub transmission_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.other_errors)
+    pub other_errors: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.hwsim_frames_rx)
+    pub hwsim_frames_rx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.hwsim_frames_tx)
+    pub hwsim_frames_tx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.network_packets_tx)
+    pub network_packets_tx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.network_packets_rx)
+    pub network_packets_rx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.hostapd_frames_tx)
+    pub hostapd_frames_tx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.hostapd_frames_rx)
+    pub hostapd_frames_rx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.wmedium_frames_tx)
+    pub wmedium_frames_tx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.wmedium_unicast_frames_tx)
+    pub wmedium_unicast_frames_tx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.mgmt_frames_rx)
+    pub mgmt_frames_rx: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.mdns_count)
+    pub mdns_count: ::std::option::Option<i32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.max_download_throughput)
+    pub max_download_throughput: ::std::option::Option<f32>,
+    // @@protoc_insertion_point(field:netsim.stats.WifiStats.max_upload_throughput)
+    pub max_upload_throughput: ::std::option::Option<f32>,
+    // special fields
+    // @@protoc_insertion_point(special_field:netsim.stats.WifiStats.special_fields)
+    pub special_fields: ::protobuf::SpecialFields,
+}
+
+impl<'a> ::std::default::Default for &'a WifiStats {
+    fn default() -> &'a WifiStats {
+        <WifiStats as ::protobuf::Message>::default_instance()
+    }
+}
+
+impl WifiStats {
+    pub fn new() -> WifiStats {
+        ::std::default::Default::default()
+    }
+
+    // optional int32 hostapd_errors = 1;
+
+    pub fn hostapd_errors(&self) -> i32 {
+        self.hostapd_errors.unwrap_or(0)
+    }
+
+    pub fn clear_hostapd_errors(&mut self) {
+        self.hostapd_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_hostapd_errors(&self) -> bool {
+        self.hostapd_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_hostapd_errors(&mut self, v: i32) {
+        self.hostapd_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 network_errors = 2;
+
+    pub fn network_errors(&self) -> i32 {
+        self.network_errors.unwrap_or(0)
+    }
+
+    pub fn clear_network_errors(&mut self) {
+        self.network_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_network_errors(&self) -> bool {
+        self.network_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_network_errors(&mut self, v: i32) {
+        self.network_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 client_errors = 3;
+
+    pub fn client_errors(&self) -> i32 {
+        self.client_errors.unwrap_or(0)
+    }
+
+    pub fn clear_client_errors(&mut self) {
+        self.client_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_client_errors(&self) -> bool {
+        self.client_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_client_errors(&mut self, v: i32) {
+        self.client_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 frame_errors = 4;
+
+    pub fn frame_errors(&self) -> i32 {
+        self.frame_errors.unwrap_or(0)
+    }
+
+    pub fn clear_frame_errors(&mut self) {
+        self.frame_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_frame_errors(&self) -> bool {
+        self.frame_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_frame_errors(&mut self, v: i32) {
+        self.frame_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 transmission_errors = 5;
+
+    pub fn transmission_errors(&self) -> i32 {
+        self.transmission_errors.unwrap_or(0)
+    }
+
+    pub fn clear_transmission_errors(&mut self) {
+        self.transmission_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_transmission_errors(&self) -> bool {
+        self.transmission_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_transmission_errors(&mut self, v: i32) {
+        self.transmission_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 other_errors = 6;
+
+    pub fn other_errors(&self) -> i32 {
+        self.other_errors.unwrap_or(0)
+    }
+
+    pub fn clear_other_errors(&mut self) {
+        self.other_errors = ::std::option::Option::None;
+    }
+
+    pub fn has_other_errors(&self) -> bool {
+        self.other_errors.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_other_errors(&mut self, v: i32) {
+        self.other_errors = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 hwsim_frames_rx = 7;
+
+    pub fn hwsim_frames_rx(&self) -> i32 {
+        self.hwsim_frames_rx.unwrap_or(0)
+    }
+
+    pub fn clear_hwsim_frames_rx(&mut self) {
+        self.hwsim_frames_rx = ::std::option::Option::None;
+    }
+
+    pub fn has_hwsim_frames_rx(&self) -> bool {
+        self.hwsim_frames_rx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_hwsim_frames_rx(&mut self, v: i32) {
+        self.hwsim_frames_rx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 hwsim_frames_tx = 8;
+
+    pub fn hwsim_frames_tx(&self) -> i32 {
+        self.hwsim_frames_tx.unwrap_or(0)
+    }
+
+    pub fn clear_hwsim_frames_tx(&mut self) {
+        self.hwsim_frames_tx = ::std::option::Option::None;
+    }
+
+    pub fn has_hwsim_frames_tx(&self) -> bool {
+        self.hwsim_frames_tx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_hwsim_frames_tx(&mut self, v: i32) {
+        self.hwsim_frames_tx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 network_packets_tx = 9;
+
+    pub fn network_packets_tx(&self) -> i32 {
+        self.network_packets_tx.unwrap_or(0)
+    }
+
+    pub fn clear_network_packets_tx(&mut self) {
+        self.network_packets_tx = ::std::option::Option::None;
+    }
+
+    pub fn has_network_packets_tx(&self) -> bool {
+        self.network_packets_tx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_network_packets_tx(&mut self, v: i32) {
+        self.network_packets_tx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 network_packets_rx = 10;
+
+    pub fn network_packets_rx(&self) -> i32 {
+        self.network_packets_rx.unwrap_or(0)
+    }
+
+    pub fn clear_network_packets_rx(&mut self) {
+        self.network_packets_rx = ::std::option::Option::None;
+    }
+
+    pub fn has_network_packets_rx(&self) -> bool {
+        self.network_packets_rx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_network_packets_rx(&mut self, v: i32) {
+        self.network_packets_rx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 hostapd_frames_tx = 11;
+
+    pub fn hostapd_frames_tx(&self) -> i32 {
+        self.hostapd_frames_tx.unwrap_or(0)
+    }
+
+    pub fn clear_hostapd_frames_tx(&mut self) {
+        self.hostapd_frames_tx = ::std::option::Option::None;
+    }
+
+    pub fn has_hostapd_frames_tx(&self) -> bool {
+        self.hostapd_frames_tx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_hostapd_frames_tx(&mut self, v: i32) {
+        self.hostapd_frames_tx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 hostapd_frames_rx = 12;
+
+    pub fn hostapd_frames_rx(&self) -> i32 {
+        self.hostapd_frames_rx.unwrap_or(0)
+    }
+
+    pub fn clear_hostapd_frames_rx(&mut self) {
+        self.hostapd_frames_rx = ::std::option::Option::None;
+    }
+
+    pub fn has_hostapd_frames_rx(&self) -> bool {
+        self.hostapd_frames_rx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_hostapd_frames_rx(&mut self, v: i32) {
+        self.hostapd_frames_rx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 wmedium_frames_tx = 13;
+
+    pub fn wmedium_frames_tx(&self) -> i32 {
+        self.wmedium_frames_tx.unwrap_or(0)
+    }
+
+    pub fn clear_wmedium_frames_tx(&mut self) {
+        self.wmedium_frames_tx = ::std::option::Option::None;
+    }
+
+    pub fn has_wmedium_frames_tx(&self) -> bool {
+        self.wmedium_frames_tx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_wmedium_frames_tx(&mut self, v: i32) {
+        self.wmedium_frames_tx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 wmedium_unicast_frames_tx = 14;
+
+    pub fn wmedium_unicast_frames_tx(&self) -> i32 {
+        self.wmedium_unicast_frames_tx.unwrap_or(0)
+    }
+
+    pub fn clear_wmedium_unicast_frames_tx(&mut self) {
+        self.wmedium_unicast_frames_tx = ::std::option::Option::None;
+    }
+
+    pub fn has_wmedium_unicast_frames_tx(&self) -> bool {
+        self.wmedium_unicast_frames_tx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_wmedium_unicast_frames_tx(&mut self, v: i32) {
+        self.wmedium_unicast_frames_tx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 mgmt_frames_rx = 15;
+
+    pub fn mgmt_frames_rx(&self) -> i32 {
+        self.mgmt_frames_rx.unwrap_or(0)
+    }
+
+    pub fn clear_mgmt_frames_rx(&mut self) {
+        self.mgmt_frames_rx = ::std::option::Option::None;
+    }
+
+    pub fn has_mgmt_frames_rx(&self) -> bool {
+        self.mgmt_frames_rx.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_mgmt_frames_rx(&mut self, v: i32) {
+        self.mgmt_frames_rx = ::std::option::Option::Some(v);
+    }
+
+    // optional int32 mdns_count = 16;
+
+    pub fn mdns_count(&self) -> i32 {
+        self.mdns_count.unwrap_or(0)
+    }
+
+    pub fn clear_mdns_count(&mut self) {
+        self.mdns_count = ::std::option::Option::None;
+    }
+
+    pub fn has_mdns_count(&self) -> bool {
+        self.mdns_count.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_mdns_count(&mut self, v: i32) {
+        self.mdns_count = ::std::option::Option::Some(v);
+    }
+
+    // optional float max_download_throughput = 17;
+
+    pub fn max_download_throughput(&self) -> f32 {
+        self.max_download_throughput.unwrap_or(0.)
+    }
+
+    pub fn clear_max_download_throughput(&mut self) {
+        self.max_download_throughput = ::std::option::Option::None;
+    }
+
+    pub fn has_max_download_throughput(&self) -> bool {
+        self.max_download_throughput.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_max_download_throughput(&mut self, v: f32) {
+        self.max_download_throughput = ::std::option::Option::Some(v);
+    }
+
+    // optional float max_upload_throughput = 18;
+
+    pub fn max_upload_throughput(&self) -> f32 {
+        self.max_upload_throughput.unwrap_or(0.)
+    }
+
+    pub fn clear_max_upload_throughput(&mut self) {
+        self.max_upload_throughput = ::std::option::Option::None;
+    }
+
+    pub fn has_max_upload_throughput(&self) -> bool {
+        self.max_upload_throughput.is_some()
+    }
+
+    // Param is passed by value, moved
+    pub fn set_max_upload_throughput(&mut self, v: f32) {
+        self.max_upload_throughput = ::std::option::Option::Some(v);
+    }
+
+    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
+        let mut fields = ::std::vec::Vec::with_capacity(18);
+        let mut oneofs = ::std::vec::Vec::with_capacity(0);
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "hostapd_errors",
+            |m: &WifiStats| { &m.hostapd_errors },
+            |m: &mut WifiStats| { &mut m.hostapd_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "network_errors",
+            |m: &WifiStats| { &m.network_errors },
+            |m: &mut WifiStats| { &mut m.network_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "client_errors",
+            |m: &WifiStats| { &m.client_errors },
+            |m: &mut WifiStats| { &mut m.client_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "frame_errors",
+            |m: &WifiStats| { &m.frame_errors },
+            |m: &mut WifiStats| { &mut m.frame_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "transmission_errors",
+            |m: &WifiStats| { &m.transmission_errors },
+            |m: &mut WifiStats| { &mut m.transmission_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "other_errors",
+            |m: &WifiStats| { &m.other_errors },
+            |m: &mut WifiStats| { &mut m.other_errors },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "hwsim_frames_rx",
+            |m: &WifiStats| { &m.hwsim_frames_rx },
+            |m: &mut WifiStats| { &mut m.hwsim_frames_rx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "hwsim_frames_tx",
+            |m: &WifiStats| { &m.hwsim_frames_tx },
+            |m: &mut WifiStats| { &mut m.hwsim_frames_tx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "network_packets_tx",
+            |m: &WifiStats| { &m.network_packets_tx },
+            |m: &mut WifiStats| { &mut m.network_packets_tx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "network_packets_rx",
+            |m: &WifiStats| { &m.network_packets_rx },
+            |m: &mut WifiStats| { &mut m.network_packets_rx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "hostapd_frames_tx",
+            |m: &WifiStats| { &m.hostapd_frames_tx },
+            |m: &mut WifiStats| { &mut m.hostapd_frames_tx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "hostapd_frames_rx",
+            |m: &WifiStats| { &m.hostapd_frames_rx },
+            |m: &mut WifiStats| { &mut m.hostapd_frames_rx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "wmedium_frames_tx",
+            |m: &WifiStats| { &m.wmedium_frames_tx },
+            |m: &mut WifiStats| { &mut m.wmedium_frames_tx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "wmedium_unicast_frames_tx",
+            |m: &WifiStats| { &m.wmedium_unicast_frames_tx },
+            |m: &mut WifiStats| { &mut m.wmedium_unicast_frames_tx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "mgmt_frames_rx",
+            |m: &WifiStats| { &m.mgmt_frames_rx },
+            |m: &mut WifiStats| { &mut m.mgmt_frames_rx },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "mdns_count",
+            |m: &WifiStats| { &m.mdns_count },
+            |m: &mut WifiStats| { &mut m.mdns_count },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "max_download_throughput",
+            |m: &WifiStats| { &m.max_download_throughput },
+            |m: &mut WifiStats| { &mut m.max_download_throughput },
+        ));
+        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
+            "max_upload_throughput",
+            |m: &WifiStats| { &m.max_upload_throughput },
+            |m: &mut WifiStats| { &mut m.max_upload_throughput },
+        ));
+        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<WifiStats>(
+            "WifiStats",
+            fields,
+            oneofs,
+        )
+    }
+}
+
+impl ::protobuf::Message for WifiStats {
+    const NAME: &'static str = "WifiStats";
+
+    fn is_initialized(&self) -> bool {
+        true
+    }
+
+    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
+        while let Some(tag) = is.read_raw_tag_or_eof()? {
+            match tag {
+                8 => {
+                    self.hostapd_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                16 => {
+                    self.network_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                24 => {
+                    self.client_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                32 => {
+                    self.frame_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                40 => {
+                    self.transmission_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                48 => {
+                    self.other_errors = ::std::option::Option::Some(is.read_int32()?);
+                },
+                56 => {
+                    self.hwsim_frames_rx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                64 => {
+                    self.hwsim_frames_tx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                72 => {
+                    self.network_packets_tx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                80 => {
+                    self.network_packets_rx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                88 => {
+                    self.hostapd_frames_tx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                96 => {
+                    self.hostapd_frames_rx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                104 => {
+                    self.wmedium_frames_tx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                112 => {
+                    self.wmedium_unicast_frames_tx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                120 => {
+                    self.mgmt_frames_rx = ::std::option::Option::Some(is.read_int32()?);
+                },
+                128 => {
+                    self.mdns_count = ::std::option::Option::Some(is.read_int32()?);
+                },
+                141 => {
+                    self.max_download_throughput = ::std::option::Option::Some(is.read_float()?);
+                },
+                149 => {
+                    self.max_upload_throughput = ::std::option::Option::Some(is.read_float()?);
+                },
+                tag => {
+                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
+                },
+            };
+        }
+        ::std::result::Result::Ok(())
+    }
+
+    // Compute sizes of nested messages
+    #[allow(unused_variables)]
+    fn compute_size(&self) -> u64 {
+        let mut my_size = 0;
+        if let Some(v) = self.hostapd_errors {
+            my_size += ::protobuf::rt::int32_size(1, v);
+        }
+        if let Some(v) = self.network_errors {
+            my_size += ::protobuf::rt::int32_size(2, v);
+        }
+        if let Some(v) = self.client_errors {
+            my_size += ::protobuf::rt::int32_size(3, v);
+        }
+        if let Some(v) = self.frame_errors {
+            my_size += ::protobuf::rt::int32_size(4, v);
+        }
+        if let Some(v) = self.transmission_errors {
+            my_size += ::protobuf::rt::int32_size(5, v);
+        }
+        if let Some(v) = self.other_errors {
+            my_size += ::protobuf::rt::int32_size(6, v);
+        }
+        if let Some(v) = self.hwsim_frames_rx {
+            my_size += ::protobuf::rt::int32_size(7, v);
+        }
+        if let Some(v) = self.hwsim_frames_tx {
+            my_size += ::protobuf::rt::int32_size(8, v);
+        }
+        if let Some(v) = self.network_packets_tx {
+            my_size += ::protobuf::rt::int32_size(9, v);
+        }
+        if let Some(v) = self.network_packets_rx {
+            my_size += ::protobuf::rt::int32_size(10, v);
+        }
+        if let Some(v) = self.hostapd_frames_tx {
+            my_size += ::protobuf::rt::int32_size(11, v);
+        }
+        if let Some(v) = self.hostapd_frames_rx {
+            my_size += ::protobuf::rt::int32_size(12, v);
+        }
+        if let Some(v) = self.wmedium_frames_tx {
+            my_size += ::protobuf::rt::int32_size(13, v);
+        }
+        if let Some(v) = self.wmedium_unicast_frames_tx {
+            my_size += ::protobuf::rt::int32_size(14, v);
+        }
+        if let Some(v) = self.mgmt_frames_rx {
+            my_size += ::protobuf::rt::int32_size(15, v);
+        }
+        if let Some(v) = self.mdns_count {
+            my_size += ::protobuf::rt::int32_size(16, v);
+        }
+        if let Some(v) = self.max_download_throughput {
+            my_size += 2 + 4;
+        }
+        if let Some(v) = self.max_upload_throughput {
+            my_size += 2 + 4;
+        }
+        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
+        self.special_fields.cached_size().set(my_size as u32);
+        my_size
+    }
+
+    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
+        if let Some(v) = self.hostapd_errors {
+            os.write_int32(1, v)?;
+        }
+        if let Some(v) = self.network_errors {
+            os.write_int32(2, v)?;
+        }
+        if let Some(v) = self.client_errors {
+            os.write_int32(3, v)?;
+        }
+        if let Some(v) = self.frame_errors {
+            os.write_int32(4, v)?;
+        }
+        if let Some(v) = self.transmission_errors {
+            os.write_int32(5, v)?;
+        }
+        if let Some(v) = self.other_errors {
+            os.write_int32(6, v)?;
+        }
+        if let Some(v) = self.hwsim_frames_rx {
+            os.write_int32(7, v)?;
+        }
+        if let Some(v) = self.hwsim_frames_tx {
+            os.write_int32(8, v)?;
+        }
+        if let Some(v) = self.network_packets_tx {
+            os.write_int32(9, v)?;
+        }
+        if let Some(v) = self.network_packets_rx {
+            os.write_int32(10, v)?;
+        }
+        if let Some(v) = self.hostapd_frames_tx {
+            os.write_int32(11, v)?;
+        }
+        if let Some(v) = self.hostapd_frames_rx {
+            os.write_int32(12, v)?;
+        }
+        if let Some(v) = self.wmedium_frames_tx {
+            os.write_int32(13, v)?;
+        }
+        if let Some(v) = self.wmedium_unicast_frames_tx {
+            os.write_int32(14, v)?;
+        }
+        if let Some(v) = self.mgmt_frames_rx {
+            os.write_int32(15, v)?;
+        }
+        if let Some(v) = self.mdns_count {
+            os.write_int32(16, v)?;
+        }
+        if let Some(v) = self.max_download_throughput {
+            os.write_float(17, v)?;
+        }
+        if let Some(v) = self.max_upload_throughput {
+            os.write_float(18, v)?;
+        }
+        os.write_unknown_fields(self.special_fields.unknown_fields())?;
+        ::std::result::Result::Ok(())
+    }
+
+    fn special_fields(&self) -> &::protobuf::SpecialFields {
+        &self.special_fields
+    }
+
+    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
+        &mut self.special_fields
+    }
+
+    fn new() -> WifiStats {
+        WifiStats::new()
+    }
+
+    fn clear(&mut self) {
+        self.hostapd_errors = ::std::option::Option::None;
+        self.network_errors = ::std::option::Option::None;
+        self.client_errors = ::std::option::Option::None;
+        self.frame_errors = ::std::option::Option::None;
+        self.transmission_errors = ::std::option::Option::None;
+        self.other_errors = ::std::option::Option::None;
+        self.hwsim_frames_rx = ::std::option::Option::None;
+        self.hwsim_frames_tx = ::std::option::Option::None;
+        self.network_packets_tx = ::std::option::Option::None;
+        self.network_packets_rx = ::std::option::Option::None;
+        self.hostapd_frames_tx = ::std::option::Option::None;
+        self.hostapd_frames_rx = ::std::option::Option::None;
+        self.wmedium_frames_tx = ::std::option::Option::None;
+        self.wmedium_unicast_frames_tx = ::std::option::Option::None;
+        self.mgmt_frames_rx = ::std::option::Option::None;
+        self.mdns_count = ::std::option::Option::None;
+        self.max_download_throughput = ::std::option::Option::None;
+        self.max_upload_throughput = ::std::option::Option::None;
+        self.special_fields.clear();
+    }
+
+    fn default_instance() -> &'static WifiStats {
+        static instance: WifiStats = WifiStats {
+            hostapd_errors: ::std::option::Option::None,
+            network_errors: ::std::option::Option::None,
+            client_errors: ::std::option::Option::None,
+            frame_errors: ::std::option::Option::None,
+            transmission_errors: ::std::option::Option::None,
+            other_errors: ::std::option::Option::None,
+            hwsim_frames_rx: ::std::option::Option::None,
+            hwsim_frames_tx: ::std::option::Option::None,
+            network_packets_tx: ::std::option::Option::None,
+            network_packets_rx: ::std::option::Option::None,
+            hostapd_frames_tx: ::std::option::Option::None,
+            hostapd_frames_rx: ::std::option::Option::None,
+            wmedium_frames_tx: ::std::option::Option::None,
+            wmedium_unicast_frames_tx: ::std::option::Option::None,
+            mgmt_frames_rx: ::std::option::Option::None,
+            mdns_count: ::std::option::Option::None,
+            max_download_throughput: ::std::option::Option::None,
+            max_upload_throughput: ::std::option::Option::None,
+            special_fields: ::protobuf::SpecialFields::new(),
+        };
+        &instance
+    }
+}
+
+impl ::protobuf::MessageFull for WifiStats {
+    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
+        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
+        descriptor.get(|| file_descriptor().message_by_package_relative_name("WifiStats").unwrap()).clone()
+    }
+}
+
+impl ::std::fmt::Display for WifiStats {
+    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
+        ::protobuf::text_format::fmt(self, f)
+    }
+}
+
+impl ::protobuf::reflect::ProtobufValue for WifiStats {
+    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
+}
+
 #[derive(PartialEq,Clone,Default,Debug)]
 // @@protoc_insertion_point(message:netsim.stats.NetsimStats)
 pub struct NetsimStats {
@@ -1764,6 +2534,8 @@ pub struct NetsimStats {
     pub frontend_stats: ::protobuf::MessageField<NetsimFrontendStats>,
     // @@protoc_insertion_point(field:netsim.stats.NetsimStats.device_stats)
     pub device_stats: ::std::vec::Vec<NetsimDeviceStats>,
+    // @@protoc_insertion_point(field:netsim.stats.NetsimStats.wifi_stats)
+    pub wifi_stats: ::protobuf::MessageField<WifiStats>,
     // special fields
     // @@protoc_insertion_point(special_field:netsim.stats.NetsimStats.special_fields)
     pub special_fields: ::protobuf::SpecialFields,
@@ -1874,7 +2646,7 @@ impl NetsimStats {
     }
 
     fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
-        let mut fields = ::std::vec::Vec::with_capacity(7);
+        let mut fields = ::std::vec::Vec::with_capacity(8);
         let mut oneofs = ::std::vec::Vec::with_capacity(0);
         fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
             "duration_secs",
@@ -1911,6 +2683,11 @@ impl NetsimStats {
             |m: &NetsimStats| { &m.device_stats },
             |m: &mut NetsimStats| { &mut m.device_stats },
         ));
+        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, WifiStats>(
+            "wifi_stats",
+            |m: &NetsimStats| { &m.wifi_stats },
+            |m: &mut NetsimStats| { &mut m.wifi_stats },
+        ));
         ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<NetsimStats>(
             "NetsimStats",
             fields,
@@ -1950,6 +2727,9 @@ impl ::protobuf::Message for NetsimStats {
                 58 => {
                     self.device_stats.push(is.read_message()?);
                 },
+                66 => {
+                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.wifi_stats)?;
+                },
                 tag => {
                     ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                 },
@@ -1986,6 +2766,10 @@ impl ::protobuf::Message for NetsimStats {
             let len = value.compute_size();
             my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
         };
+        if let Some(v) = self.wifi_stats.as_ref() {
+            let len = v.compute_size();
+            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
+        }
         my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
         self.special_fields.cached_size().set(my_size as u32);
         my_size
@@ -2013,6 +2797,9 @@ impl ::protobuf::Message for NetsimStats {
         for v in &self.device_stats {
             ::protobuf::rt::write_message_field_with_cached_size(7, v, os)?;
         };
+        if let Some(v) = self.wifi_stats.as_ref() {
+            ::protobuf::rt::write_message_field_with_cached_size(8, v, os)?;
+        }
         os.write_unknown_fields(self.special_fields.unknown_fields())?;
         ::std::result::Result::Ok(())
     }
@@ -2037,6 +2824,7 @@ impl ::protobuf::Message for NetsimStats {
         self.version = ::std::option::Option::None;
         self.frontend_stats.clear();
         self.device_stats.clear();
+        self.wifi_stats.clear();
         self.special_fields.clear();
     }
 
@@ -2049,6 +2837,7 @@ impl ::protobuf::Message for NetsimStats {
             version: ::std::option::Option::None,
             frontend_stats: ::protobuf::MessageField::none(),
             device_stats: ::std::vec::Vec::new(),
+            wifi_stats: ::protobuf::MessageField::none(),
             special_fields: ::protobuf::SpecialFields::new(),
         };
         &instance
@@ -2104,14 +2893,33 @@ static file_descriptor_proto_data: &'static [u8] = b"\
     sion\x12\x1f\n\x0bsdk_version\x18\x04\x20\x01(\tR\nsdkVersion\x12\x19\n\
     \x08build_id\x18\x05\x20\x01(\tR\x07buildId\x12\x18\n\x07variant\x18\x06\
     \x20\x01(\tR\x07variant\x12\x12\n\x04arch\x18\x07\x20\x01(\tR\x04arch\"\
-    \xf6\x02\n\x0bNetsimStats\x12#\n\rduration_secs\x18\x01\x20\x01(\x04R\
-    \x0cdurationSecs\x12!\n\x0cdevice_count\x18\x02\x20\x01(\x05R\x0bdeviceC\
-    ount\x126\n\x17peak_concurrent_devices\x18\x03\x20\x01(\x05R\x15peakConc\
-    urrentDevices\x12?\n\x0bradio_stats\x18\x04\x20\x03(\x0b2\x1e.netsim.sta\
-    ts.NetsimRadioStatsR\nradioStats\x12\x18\n\x07version\x18\x05\x20\x01(\t\
-    R\x07version\x12H\n\x0efrontend_stats\x18\x06\x20\x01(\x0b2!.netsim.stat\
-    s.NetsimFrontendStatsR\rfrontendStats\x12B\n\x0cdevice_stats\x18\x07\x20\
-    \x03(\x0b2\x1f.netsim.stats.NetsimDeviceStatsR\x0bdeviceStats\
+    \x91\x06\n\tWifiStats\x12%\n\x0ehostapd_errors\x18\x01\x20\x01(\x05R\rho\
+    stapdErrors\x12%\n\x0enetwork_errors\x18\x02\x20\x01(\x05R\rnetworkError\
+    s\x12#\n\rclient_errors\x18\x03\x20\x01(\x05R\x0cclientErrors\x12!\n\x0c\
+    frame_errors\x18\x04\x20\x01(\x05R\x0bframeErrors\x12/\n\x13transmission\
+    _errors\x18\x05\x20\x01(\x05R\x12transmissionErrors\x12!\n\x0cother_erro\
+    rs\x18\x06\x20\x01(\x05R\x0botherErrors\x12&\n\x0fhwsim_frames_rx\x18\
+    \x07\x20\x01(\x05R\rhwsimFramesRx\x12&\n\x0fhwsim_frames_tx\x18\x08\x20\
+    \x01(\x05R\rhwsimFramesTx\x12,\n\x12network_packets_tx\x18\t\x20\x01(\
+    \x05R\x10networkPacketsTx\x12,\n\x12network_packets_rx\x18\n\x20\x01(\
+    \x05R\x10networkPacketsRx\x12*\n\x11hostapd_frames_tx\x18\x0b\x20\x01(\
+    \x05R\x0fhostapdFramesTx\x12*\n\x11hostapd_frames_rx\x18\x0c\x20\x01(\
+    \x05R\x0fhostapdFramesRx\x12*\n\x11wmedium_frames_tx\x18\r\x20\x01(\x05R\
+    \x0fwmediumFramesTx\x129\n\x19wmedium_unicast_frames_tx\x18\x0e\x20\x01(\
+    \x05R\x16wmediumUnicastFramesTx\x12$\n\x0emgmt_frames_rx\x18\x0f\x20\x01\
+    (\x05R\x0cmgmtFramesRx\x12\x1d\n\nmdns_count\x18\x10\x20\x01(\x05R\tmdns\
+    Count\x126\n\x17max_download_throughput\x18\x11\x20\x01(\x02R\x15maxDown\
+    loadThroughput\x122\n\x15max_upload_throughput\x18\x12\x20\x01(\x02R\x13\
+    maxUploadThroughput\"\xae\x03\n\x0bNetsimStats\x12#\n\rduration_secs\x18\
+    \x01\x20\x01(\x04R\x0cdurationSecs\x12!\n\x0cdevice_count\x18\x02\x20\
+    \x01(\x05R\x0bdeviceCount\x126\n\x17peak_concurrent_devices\x18\x03\x20\
+    \x01(\x05R\x15peakConcurrentDevices\x12?\n\x0bradio_stats\x18\x04\x20\
+    \x03(\x0b2\x1e.netsim.stats.NetsimRadioStatsR\nradioStats\x12\x18\n\x07v\
+    ersion\x18\x05\x20\x01(\tR\x07version\x12H\n\x0efrontend_stats\x18\x06\
+    \x20\x01(\x0b2!.netsim.stats.NetsimFrontendStatsR\rfrontendStats\x12B\n\
+    \x0cdevice_stats\x18\x07\x20\x03(\x0b2\x1f.netsim.stats.NetsimDeviceStat\
+    sR\x0bdeviceStats\x126\n\nwifi_stats\x18\x08\x20\x01(\x0b2\x17.netsim.st\
+    ats.WifiStatsR\twifiStats\
 ";
 
 /// `FileDescriptorProto` object which was a source for this generated file
@@ -2129,11 +2937,12 @@ pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
     file_descriptor.get(|| {
         let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
             let mut deps = ::std::vec::Vec::with_capacity(0);
-            let mut messages = ::std::vec::Vec::with_capacity(5);
+            let mut messages = ::std::vec::Vec::with_capacity(6);
             messages.push(InvalidPacket::generated_message_descriptor_data());
             messages.push(NetsimRadioStats::generated_message_descriptor_data());
             messages.push(NetsimFrontendStats::generated_message_descriptor_data());
             messages.push(NetsimDeviceStats::generated_message_descriptor_data());
+            messages.push(WifiStats::generated_message_descriptor_data());
             messages.push(NetsimStats::generated_message_descriptor_data());
             let mut enums = ::std::vec::Vec::with_capacity(2);
             enums.push(invalid_packet::Reason::generated_enum_descriptor_data());
diff --git a/scripts/build_tools.py b/scripts/build_tools.py
index b738e505..fae80b71 100755
--- a/scripts/build_tools.py
+++ b/scripts/build_tools.py
@@ -100,10 +100,10 @@ def main():
   parser.add_argument(
       "--emulator_target",
       type=str,
-      default="emulator-linux_x64",
+      default="emulator-linux_x64_gfxstream",
       help=(
           "The emulator build target to install for local case, defaults to"
-          " emulator-linux_x64"
+          " emulator-linux_x64_gfxstream"
       ),
   )
   parser.add_argument(
diff --git a/scripts/format_code.sh b/scripts/format_code.sh
index 026f73ca..721c3482 100755
--- a/scripts/format_code.sh
+++ b/scripts/format_code.sh
@@ -58,3 +58,6 @@ if [ -f "$BPFMT" ]; then
   find $find \( -name "Android.bp" \) \
     -exec $BPFMT -w {} \;
 fi
+
+# Run buildifier to format Bazel build files
+buildifier -r $REPO/tools/netsim
diff --git a/scripts/proto_update.sh b/scripts/proto_update.sh
index 96cd9fdf..ca5d91ea 100755
--- a/scripts/proto_update.sh
+++ b/scripts/proto_update.sh
@@ -14,71 +14,117 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# Update the Rust protobuf files on netsim-dev branch
+# Update the Rust protobuf files on git_main-netsim-dev branch
 
 # Prerequisites:
 # - protobuf-compiler
 # Linux: sudo apt-get install protobuf-compiler
 # Mac:   brew install protobuf
 
+set -e # Exit immediately if a command exits with a non-zero status.
+
+echo "Starting Rust protobuf file update process..."
+
+# --- Configuration ---
 # Absolute path to tools/netsim using this scripts directory
 REPO_NETSIM=$(dirname $(readlink -f "$0"))/..
-CARGO_MANIFEST=$REPO_NETSIM/rust/proto/Cargo.toml
+CARGO_MANIFEST="$REPO_NETSIM/rust/proto/Cargo.toml"
+PROTO_SRC_DIR="$REPO_NETSIM/rust/proto/src"
+OS=$(uname | tr '[:upper:]' '[:lower:]')
 
-# -- Step 1. Generate gRPC protobuf files
-# NOTE: the files can not be generated by proto/build.rs because protoc-grpcio doesn't support protobuf v3 yet.
+# --- Step 1. Generate gRPC protobuf files ---
+echo "[Step 1] Generating gRPC protobuf files..."
+# NOTE: These files are generated by cargo build because protoc-grpcio doesn't support protobuf v3 yet.
+# They will be reverted and regenerated properly in Step 2 using the build script.
 # https://github.com/mtp401/protoc-grpcio/issues/41
 
 # Install compilers since the crates are not in AOSP
-# TODO: Add required crate mappings to work in netsim-dev
+# TODO: Add required crate mappings to work in git_main-netsim-dev
 export CARGO_HOME=""
-# Specify versions to use the correct protobuf version.
 cargo install protobuf-codegen --version 3.2.0
 cargo install grpcio-compiler --version 0.13.0
 
-PROTOC_CMD="protoc --rust_out=./rust/proto/src --grpc_out=./rust/proto/src\
- --plugin=protoc-gen-grpc=$(which grpc_rust_plugin)\
- -I./proto -I../../external/protobuf/src\
+PROTOC_PLUGIN_PATH=$(which grpc_rust_plugin)
+if [ -z "$PROTOC_PLUGIN_PATH" ]; then
+    echo "Error: grpc_rust_plugin not found in PATH after cargo install."
+    exit 1
+fi
+
+PROTOC_CMD="protoc --rust_out=$PROTO_SRC_DIR --grpc_out=$PROTO_SRC_DIR \
+ --plugin=protoc-gen-grpc=$PROTOC_PLUGIN_PATH \
+ -I./proto -I../../external/protobuf/src \
  -I../../packages/modules/Bluetooth/tools/rootcanal/proto"
 $PROTOC_CMD ./proto/netsim/frontend.proto
 $PROTOC_CMD ./proto/netsim/packet_streamer.proto
 
-# Revert the generate proto files to ensure they are re-generated by proto/build.rs.
-git checkout $REPO_NETSIM/rust/proto/src/packet_streamer.rs
-git checkout $REPO_NETSIM/rust/proto/src/frontend.rs
-rm $REPO_NETSIM/rust/proto/src/mod.rs
+# Revert the generated proto files so they can be properly re-generated by build.rs in Step 2.
+git checkout "$PROTO_SRC_DIR/packet_streamer.rs"
+git checkout "$PROTO_SRC_DIR/frontend.rs"
+if [ -f "$PROTO_SRC_DIR/mod.rs" ]; then
+    rm "$PROTO_SRC_DIR/mod.rs"
+fi
 
-# --- Step 2. Generate protobuf files using proto/build.rs
-# Uncomment lines starting with `##`
-OS=$(uname | tr '[:upper:]' '[:lower:]')
+# --- Step 2. Generate protobuf files using proto/build.rs ---
+echo "[Step 2] Generating protobuf files using Cargo build script..."
+
+# Temporarily uncomment build script lines in Cargo.toml
 if [[ "$OS" == "linux" ]]; then
-    sed -i 's/^##//g' $CARGO_MANIFEST
-fi
-if [[ "$OS" == "darwin" ]]; then
-    sed -i '' 's/^##//g' $CARGO_MANIFEST
+    # GNU sed
+    sed -i 's/^##//g' "$CARGO_MANIFEST"
+elif [[ "$OS" == "darwin" ]]; then
+    # BSD sed requires '' for in-place edit without backup
+    sed -i '' 's/^##//g' "$CARGO_MANIFEST"
+else
+     echo "Warning: Unrecognized OS '$OS'."
 fi
 
+# Build dependencies if .cargo directory doesn't exist
 if [ ! -d "$REPO_NETSIM/objs/rust/.cargo" ]; then
-    python3 $REPO_NETSIM/scripts/build_tools.py
+    python3 "$REPO_NETSIM/scripts/build_tools.py"
 fi
 
-# Use Rust dependency crates available on netsim-dev branch
-export CARGO_HOME=$REPO_NETSIM/objs/rust/.cargo
-
+# TODO: Use Rust dependency crates available on git_main-netsim-dev branch after Rust toolchain is upgraded.
+# export CARGO_HOME=$REPO_NETSIM/objs/rust/.cargo
 # For grpcio-sys
-export GRPCIO_SYS_GRPC_INCLUDE_PATH="$REPO_NETSIM/../../external/grpc/include"
+#export GRPCIO_SYS_GRPC_INCLUDE_PATH="$REPO_NETSIM/../../external/grpc/include"
 
-cd $REPO_NETSIM
-cargo build --manifest-path $CARGO_MANIFEST
+# Workaround: Use stable Rust temporarily and crates from crates.io due to potential `rustix` crate compile error with older toolchains.
+rustup default stable
+
+cd "$REPO_NETSIM"
+cargo build --manifest-path "$CARGO_MANIFEST"
+
+# Restore the default toolchain
+rustup default 1.73.0
 
 # Restore original Cargo.toml
-git checkout $CARGO_MANIFEST
+git checkout "$CARGO_MANIFEST"
 
-# Find the most recent rustfmt installed
-RUSTFMT=$(ls -d ../../prebuilts/rust/$OS-x86/*/bin/rustfmt | tail -1)
+# --- Step 3. Post-processing Rust Files ---
+echo "[Step 3] Post-processing generated Rust files..."
 
-# Format Rust code
-# Need to format manually because it's not supported in build.rs
-find $REPO_NETSIM/rust/proto -name '*.rs' -exec $RUSTFMT --files-with-diff {} \;
+# Remove #![allow(box_pointers)] attribute from generated files. This has been removed with latest toolchain.
+# TODO: Remove this step after Rust toolchain upgrade.
+echo "Removing #![allow(box_pointers)] attribute..."
+PATTERN_TO_REMOVE='^#\!\[allow(box_pointers)\]$'
+if [[ "$OS" == "linux" ]]; then
+    find "$PROTO_SRC_DIR" -name '*.rs' -exec sed -i "/${PATTERN_TO_REMOVE}/d" {} \;
+elif [[ "$OS" == "darwin" ]]; then
+    find "$PROTO_SRC_DIR" -name '*.rs' -exec sed -i '' "/${PATTERN_TO_REMOVE}/d" {} \;
+else
+    echo "Warning: Unsupported OS '$OS' for automatic removal of '#![allow(box_pointers)]'. Please check files manually."
+fi
 
-rm rust/Cargo.lock
+# Format generated code using prebuilt rustfmt
+# Find the most recent rustfmt available in prebuilts for the detected OS
+RUSTFMT=$(ls -d ../../prebuilts/rust/$OS-x86/*/bin/rustfmt | tail -1)
+if [ -z "$RUSTFMT" ] || [ ! -x "$RUSTFMT" ]; then
+    echo "Error: Could not find prebuilt rustfmt executable. Skipping formatting."
+else
+    find "$PROTO_SRC_DIR" -name '*.rs' -exec "$RUSTFMT" --files-with-diff {} \;
+fi
+
+if [ -f "rust/Cargo.lock" ]; then
+    rm rust/Cargo.lock
+    echo "Removed rust/Cargo.lock"
+fi
diff --git a/scripts/tasks/compile_install_task.py b/scripts/tasks/compile_install_task.py
index 84f7cdfa..6ede7d40 100644
--- a/scripts/tasks/compile_install_task.py
+++ b/scripts/tasks/compile_install_task.py
@@ -18,7 +18,7 @@ from pathlib import Path
 import platform
 
 from tasks.task import Task
-from utils import (CMAKE, run)
+from utils import (CMAKE, WINDOWS_TMP_OBJS_PATH, move_contents, run)
 
 
 class CompileInstallTask(Task):
@@ -35,9 +35,31 @@ class CompileInstallTask(Task):
       target += "/strip"
 
     # Build
-    run(
-        [CMAKE, "--build", self.out, "--target", target],
-        self.env,
-        "bld",
-    )
+    if platform.system() == "Windows":
+      try:
+        # Use mkdir() with parents=True and exist_ok=True
+        WINDOWS_TMP_OBJS_PATH.mkdir(parents=True, exist_ok=True)
+        print(
+            f"Directory '{WINDOWS_TMP_OBJS_PATH}' ensured (created or already"
+            " exists)."
+        )
+
+      except OSError as e:
+        # Catch potential OS errors (like permission issues)
+        print(f"Error creating directory '{WINDOWS_TMP_OBJS_PATH}': {e}")
+      run(
+          [CMAKE, "--build", WINDOWS_TMP_OBJS_PATH, "--target", target],
+          self.env,
+          "bld",
+      )
+      move_contents(
+          WINDOWS_TMP_OBJS_PATH,
+          self.out,
+      )
+    else:
+      run(
+          [CMAKE, "--build", self.out, "--target", target],
+          self.env,
+          "bld",
+      )
     return True
diff --git a/scripts/tasks/compile_task.py b/scripts/tasks/compile_task.py
index 0b56e5ba..8174a804 100644
--- a/scripts/tasks/compile_task.py
+++ b/scripts/tasks/compile_task.py
@@ -15,9 +15,11 @@
 # limitations under the License.
 
 from pathlib import Path
+import platform
+import shutil
 
 from tasks.task import Task
-from utils import (CMAKE, run)
+from utils import (CMAKE, WINDOWS_TMP_OBJS_PATH, move_contents, run)
 
 
 class CompileTask(Task):
@@ -29,9 +31,31 @@ class CompileTask(Task):
 
   def do_run(self):
     # Build
-    run(
-        [CMAKE, "--build", self.out],
-        self.env,
-        "bld",
-    )
+    if platform.system() == "Windows":
+      try:
+        # Use mkdir() with parents=True and exist_ok=True
+        WINDOWS_TMP_OBJS_PATH.mkdir(parents=True, exist_ok=True)
+        print(
+            f"Directory '{WINDOWS_TMP_OBJS_PATH}' ensured (created or already"
+            " exists)."
+        )
+
+      except OSError as e:
+        # Catch potential OS errors (like permission issues)
+        print(f"Error creating directory '{WINDOWS_TMP_OBJS_PATH}': {e}")
+      run(
+          [CMAKE, "--build", WINDOWS_TMP_OBJS_PATH],
+          self.env,
+          "bld",
+      )
+      move_contents(
+          WINDOWS_TMP_OBJS_PATH,
+          self.out,
+      )
+    else:
+      run(
+          [CMAKE, "--build", self.out],
+          self.env,
+          "bld",
+      )
     return True
diff --git a/scripts/tasks/configure_task.py b/scripts/tasks/configure_task.py
index 92eab413..efa5e60a 100644
--- a/scripts/tasks/configure_task.py
+++ b/scripts/tasks/configure_task.py
@@ -18,7 +18,7 @@ from pathlib import Path
 import platform
 import shutil
 from tasks.task import Task
-from utils import (AOSP_ROOT, cmake_toolchain, run)
+from utils import (AOSP_ROOT, WINDOWS_TMP_OBJS_PATH, cmake_toolchain, run)
 
 
 class ConfigureTask(Task):
@@ -51,14 +51,34 @@ class ConfigureTask(Task):
             / "bin"
         ),
     )
-    launcher = [
-        cmake,
-        f"-B{self.out}",
-        "-G Ninja",
-        self.build_config,
-        f"-DCMAKE_TOOLCHAIN_FILE={cmake_toolchain(self.target)}",
-        AOSP_ROOT / "tools" / "netsim",
-    ]
+    if platform.system() == "Windows":
+      try:
+        WINDOWS_TMP_OBJS_PATH.mkdir(parents=True, exist_ok=True)
+        print(
+            f"Directory '{WINDOWS_TMP_OBJS_PATH}' ensured (created or already"
+            " exists)."
+        )
 
-    run(launcher, self.env, "bld")
+      except OSError as e:
+        print(f"Error creating directory '{WINDOWS_TMP_OBJS_PATH}': {e}")
+
+      launcher = [
+          cmake,
+          f"-B{WINDOWS_TMP_OBJS_PATH}",
+          "-G Ninja",
+          self.build_config,
+          f"-DCMAKE_TOOLCHAIN_FILE={cmake_toolchain(self.target)}",
+          AOSP_ROOT / "tools" / "netsim",
+      ]
+      run(launcher, self.env, "bld")
+    else:
+      launcher = [
+          cmake,
+          f"-B{self.out}",
+          "-G Ninja",
+          self.build_config,
+          f"-DCMAKE_TOOLCHAIN_FILE={cmake_toolchain(self.target)}",
+          AOSP_ROOT / "tools" / "netsim",
+      ]
+      run(launcher, self.env, "bld")
     return True
diff --git a/scripts/tasks/install_emulator_task.py b/scripts/tasks/install_emulator_task.py
index 9c23aebe..54042753 100644
--- a/scripts/tasks/install_emulator_task.py
+++ b/scripts/tasks/install_emulator_task.py
@@ -44,7 +44,7 @@ class InstallEmulatorTask(Task):
     self.buildbot = args.buildbot
     self.out_dir = args.out_dir
     # Local fetching use only - default to emulator-linux_x64_gfxstream
-    self.target = args.emulator_target + "_gfxstream"
+    self.target = args.emulator_target
     # Local Emulator directory
     self.local_emulator_dir = args.local_emulator_dir
 
@@ -229,7 +229,7 @@ class InstallEmulatorManager:
                 "--target",
                 self.target,
                 "--branch",
-                "aosp-emu-master-dev",
+                "git_emu-main-dev",
                 "sdk-repo-linux-emulator-*.zip",
             ],
             get_default_environment(AOSP_ROOT),
diff --git a/scripts/utils.py b/scripts/utils.py
index 4a302be1..56281126 100644
--- a/scripts/utils.py
+++ b/scripts/utils.py
@@ -35,6 +35,7 @@ else:
 from threading import Thread, currentThread
 
 AOSP_ROOT = Path(__file__).absolute().parents[3]
+WINDOWS_TMP_OBJS_PATH = Path("C:\\netsim\\objs")
 TOOLS = Path(AOSP_ROOT, "tools")
 EMULATOR_ARTIFACT_PATH = Path(AOSP_ROOT, "tools", "netsim", "emulator_tmp")
 PYTHON_EXE = sys.executable or "python3"
@@ -161,6 +162,25 @@ def get_host_and_ip():
   return hostname, my_ip
 
 
+def move_contents(source, destination):
+  """Moves the contents of a source directory to a destination directory."""
+
+  if not os.path.exists(source):
+    print(f"Source directory '{source}' does not exist.")
+    return
+
+  if not os.path.exists(destination):
+    os.makedirs(destination)  # Create destination if it doesn't exist
+
+  for item in os.listdir(source):
+    s = os.path.join(source, item)
+    d = os.path.join(destination, item)
+    try:
+      shutil.move(s, d)
+    except Exception as e:
+      print(f"Error moving '{s}' to '{d}': {e}")
+
+
 class LogBelowLevel(logging.Filter):
 
   def __init__(self, exclusive_maximum, name=""):
diff --git a/src/hci/bluetooth_facade.cc b/src/hci/bluetooth_facade.cc
index 36fc4564..0856c8b7 100644
--- a/src/hci/bluetooth_facade.cc
+++ b/src/hci/bluetooth_facade.cc
@@ -48,7 +48,8 @@ void SetLogColorEnable(bool);
 
 namespace netsim::hci::facade {
 
-int8_t SimComputeRssi(int send_id, int recv_id, int8_t tx_power);
+int8_t SimComputeRssi(int send_id, int recv_id, rootcanal::Phy::Type phy_type,
+                      int8_t tx_power);
 void IncrTx(uint32_t send_id, rootcanal::Phy::Type phy_type);
 void IncrRx(uint32_t receive_id, rootcanal::Phy::Type phy_type);
 
@@ -68,7 +69,7 @@ class SimPhyLayer : public PhyLayer {
   int8_t ComputeRssi(PhyDevice::Identifier sender_id,
                      PhyDevice::Identifier receiver_id,
                      int8_t tx_power) override {
-    return SimComputeRssi(sender_id, receiver_id, tx_power);
+    return SimComputeRssi(sender_id, receiver_id, type, tx_power);
   }
 
   // Check if the device is present in the phy_devices
@@ -465,9 +466,8 @@ void IncrRx(uint32_t id, rootcanal::Phy::Type phy_type) {
   }
 }
 
-// TODO: Make SimComputeRssi invoke netsim::device::GetDistanceRust with dev
-// flag
-int8_t SimComputeRssi(int send_id, int recv_id, int8_t tx_power) {
+int8_t SimComputeRssi(int send_id, int recv_id, rootcanal::Phy::Type phy_type,
+                      int8_t tx_power) {
   if (id_to_chip_info_.find(send_id) == id_to_chip_info_.end() ||
       id_to_chip_info_.find(recv_id) == id_to_chip_info_.end()) {
 #ifdef NETSIM_ANDROID_EMULATOR
@@ -477,10 +477,18 @@ int8_t SimComputeRssi(int send_id, int recv_id, int8_t tx_power) {
 #endif
     return tx_power;
   }
-  auto a = id_to_chip_info_[send_id]->chip_id;
-  auto b = id_to_chip_info_[recv_id]->chip_id;
-  auto distance = netsim::device::GetDistanceCxx(a, b);
-  return netsim::DistanceToRssi(tx_power, distance);
+  auto sender = id_to_chip_info_[send_id]->chip_id;
+  auto receiver = id_to_chip_info_[recv_id]->chip_id;
+  // Map rootcanal Phy type to netsim PhyKind
+  model::PhyKind link_kind;
+  if (phy_type == rootcanal::Phy::Type::LOW_ENERGY) {
+    link_kind = model::PhyKind::BLUETOOTH_LOW_ENERGY;
+  } else if (phy_type == rootcanal::Phy::Type::BR_EDR) {
+    link_kind = model::PhyKind::BLUETOOTH_CLASSIC;
+  } else {
+    link_kind = model::PhyKind::NONE;  // Unknown
+  }
+  return netsim::GetRssi(sender, receiver, link_kind, tx_power);
 }
 
 rust::Vec<::std::uint8_t> GetCxx(uint32_t id) {
```

