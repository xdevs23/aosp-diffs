```diff
diff --git a/Android.bp b/Android.bp
index 2c5035a..2691829 100644
--- a/Android.bp
+++ b/Android.bp
@@ -91,6 +91,12 @@ cc_library {
         "libopen_dice_headers",
     ],
     shared_libs: ["libcrypto"],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 cc_library_static {
@@ -131,6 +137,12 @@ cc_library_static {
         "libopen_dice_headers",
     ],
     static_libs: ["libcrypto_baremetal"],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 filegroup {
@@ -150,6 +162,12 @@ cc_library {
         "libcrypto",
         "libopen_dice_cbor",
     ],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 cc_library_static {
@@ -160,6 +178,12 @@ cc_library_static {
         "libcrypto_baremetal",
         "libopen_dice_cbor_baremetal",
     ],
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 cc_library_static {
diff --git a/BUILD.gn b/BUILD.gn
index 655230c..eb43c80 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -59,6 +59,10 @@ config("boringssl_ed25519_ops_config") {
   include_dirs = [ "//include/dice/config/boringssl_ed25519" ]
 }
 
+config("boringssl_ecdsa_p256_ops_config") {
+  include_dirs = [ "//include/dice/config/boringssl_ecdsa_p256" ]
+}
+
 config("boringssl_ecdsa_p384_ops_config") {
   include_dirs = [ "//include/dice/config/boringssl_ecdsa_p384" ]
 }
@@ -80,6 +84,23 @@ pw_static_library("dice_with_boringssl_ed25519_ops") {
   all_dependent_configs = [ ":boringssl_ed25519_ops_config" ]
 }
 
+pw_static_library("dice_with_boringssl_p256_ops") {
+  public = [
+    "include/dice/dice.h",
+    "include/dice/utils.h",
+  ]
+  sources = [
+    "src/boringssl_cert_op.c",
+    "src/boringssl_hash_kdf_ops.c",
+    "src/boringssl_p256_ops.c",
+    "src/clear_memory.c",
+    "src/dice.c",
+    "src/utils.c",
+  ]
+  deps = [ "//third_party/boringssl:crypto" ]
+  all_dependent_configs = [ ":boringssl_ecdsa_p256_ops_config" ]
+}
+
 pw_static_library("dice_with_boringssl_p384_ops") {
   public = [
     "include/dice/dice.h",
@@ -148,6 +169,28 @@ pw_static_library("boringssl_ecdsa_utils") {
   deps = [ "//third_party/boringssl:crypto" ]
 }
 
+pw_static_library("dice_with_cbor_p256_cert") {
+  public = [
+    "include/dice/dice.h",
+    "include/dice/utils.h",
+  ]
+  sources = [
+    "src/boringssl_hash_kdf_ops.c",
+    "src/boringssl_p256_ops.c",
+    "src/cbor_cert_op.c",
+    "src/cbor_p256_cert_op.c",
+    "src/clear_memory.c",
+    "src/dice.c",
+    "src/utils.c",
+  ]
+  deps = [
+    ":boringssl_ecdsa_utils",
+    ":cbor_writer",
+    "//third_party/boringssl:crypto",
+  ]
+  all_dependent_configs = [ ":boringssl_ecdsa_p256_ops_config" ]
+}
+
 pw_static_library("dice_with_cbor_p384_cert") {
   public = [
     "include/dice/dice.h",
@@ -261,6 +304,13 @@ pw_executable("boringssl_ed25519_ops_fuzzer") {
   ]
 }
 
+pw_executable("boringssl_p256_ops_fuzzer") {
+  deps = [
+    ":dice_with_boringssl_p256_ops",
+    ":fuzzer",
+  ]
+}
+
 pw_executable("boringssl_p384_ops_fuzzer") {
   deps = [
     ":dice_with_boringssl_p384_ops",
@@ -303,6 +353,20 @@ pw_test("cbor_ed25519_cert_op_test") {
   ]
 }
 
+pw_test("cbor_p256_cert_op_test") {
+  sources = [
+    "src/cbor_p256_cert_op_test.cc",
+    "src/test_utils.cc",
+  ]
+  deps = [
+    ":boringssl_ecdsa_utils",
+    ":dice_with_cbor_p256_cert",
+    "$dir_pw_string:pw_string",
+    "//third_party/boringssl:crypto",
+    "//third_party/cose-c:cose-c_p256",
+  ]
+}
+
 pw_test("cbor_p384_cert_op_test") {
   sources = [
     "src/cbor_p384_cert_op_test.cc",
@@ -394,6 +458,7 @@ pw_test_group("tests") {
     ":android_test",
     ":boringssl_ed25519_ops_test",
     ":cbor_ed25519_cert_op_test",
+    ":cbor_p256_cert_op_test",
     ":cbor_p384_cert_op_test",
     ":cbor_reader_test",
     ":cbor_writer_test",
@@ -408,6 +473,7 @@ group("fuzzers") {
   deps = [
     ":android_fuzzer",
     ":boringssl_ed25519_ops_fuzzer",
+    ":boringssl_p256_ops_fuzzer",
     ":boringssl_p384_ops_fuzzer",
     ":cbor_ed25519_cert_op_fuzzer",
     ":cbor_reader_fuzzer",
@@ -532,6 +598,11 @@ pw_size_diff("library_size_report") {
       label = "CBOR Cert"
       base = ":dice_standalone"
     },
+    {
+      target = ":dice_with_cbor_p256_cert"
+      label = "CBOR P256 Cert"
+      base = ":dice_standalone"
+    },
     {
       target = ":dice_with_cbor_p384_cert"
       label = "CBOR P384 Cert"
@@ -556,6 +627,7 @@ group("optimized_libs") {
     ":dice_standalone",
     ":dice_with_boringssl_ed25519_ops",
     ":dice_with_cbor_ed25519_cert",
+    ":dice_with_cbor_p256_cert",
     ":dice_with_cbor_p384_cert",
     ":dice_with_cbor_template_ed25519_cert",
     ":dice_with_mbedtls_ops",
diff --git a/docs/android.md b/docs/android.md
index 8c40f27..980e63c 100644
--- a/docs/android.md
+++ b/docs/android.md
@@ -83,6 +83,7 @@ Component&nbsp;version | -70003 | int&nbsp;/&nbsp;tstr | Version of the componen
 Resettable             | -70004 | null                 | If present, key changes on factory reset
 Security&nbsp;version  | -70005 | uint                 | Machine-comparable, monotonically increasing version of the component where a greater value indicates a newer version. This value must increment for every update that changes the code hash, for example by using the timestamp of the version's release.
 [RKP&nbsp;VM][rkp-vm]&nbsp;marker | -70006 | null      | See the [Android HAL documentation][rkp-hal-readme] for precise semantics, as they vary by Android version.
+Component&nbsp;instance&nbsp;name | -70007 | tstr      | When component is meant as a type, class or category, one can further specify the particular instance of that component.
 
 [rkp-vm]: https://android.googlesource.com/platform/packages/modules/Virtualization/+/main/service_vm/README.md#rkp-vm-remote-key-provisioning-virtual-machine
 [rkp-hal-readme]: https://android.googlesource.com/platform/hardware/interfaces/+/main/security/rkp/README.md
diff --git a/dpe-rs/Cargo.toml b/dpe-rs/Cargo.toml
new file mode 100644
index 0000000..c491b03
--- /dev/null
+++ b/dpe-rs/Cargo.toml
@@ -0,0 +1,58 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License"); you may not
+# use this file except in compliance with the License. You may obtain a copy of
+# the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+# License for the specific language governing permissions and limitations under
+# the License.
+
+[package]
+name = "dpe-rs"
+version = "0.1.0"
+edition = "2021"
+
+# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
+
+[dependencies]
+aes-gcm = { version = "0.10.3", default-features = false, features = ["aes", "heapless", "zeroize"] }
+env_logger = "0.10.0"
+hash32 = "0.3.1"
+heapless = { version = "0.7.16", default-features = false }
+libc-print = "0.1.22"
+log = "0.4.20"
+minicbor = "0.19.1"
+noise-protocol = "0.2.0"
+rand_core = "0.6.4"
+zeroize = { version = "1.7.0", features = ["zeroize_derive"], default-features = false }
+
+[dev-dependencies]
+aes-gcm-siv = "0.11.1"
+ed25519-dalek = { version = "2.1.0", default-features = false, features = ["zeroize"] }
+hkdf = "0.12.3"
+hmac = "0.12.1"
+hpke = { version = "0.11.0", default-features = false, features = ["x25519"] }
+noise-rust-crypto = "0.6.2"
+sha2 = { version = "0.10.8", default-features = false }
+x25519-dalek = { version = "2.0.0", default-features = false, features = ["zeroize"] }
+rand_chacha = { version = "0.3.1", default-features = false }
+
+[workspace.lints.rust]
+unsafe_code = "deny"
+missing_docs = "deny"
+trivial_casts = "deny"
+trivial_numeric_casts = "deny"
+unused_extern_crates = "deny"
+unused_import_braces = "deny"
+unused_results = "deny"
+
+[workspace.lints.clippy]
+indexing_slicing = "deny"
+unwrap_used = "deny"
+panic = "deny"
+expect_used = "deny"
diff --git a/dpe-rs/src/args.rs b/dpe-rs/src/args.rs
new file mode 100644
index 0000000..f83d891
--- /dev/null
+++ b/dpe-rs/src/args.rs
@@ -0,0 +1,148 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Types related to command arguments.
+
+use crate::error::{DpeResult, ErrCode};
+use crate::memory::SizedMessage;
+use heapless::FnvIndexMap;
+use log::error;
+
+/// Represents the numeric identifier of a command or response argument.
+pub type ArgId = u32;
+
+/// Represents the type of a command or response argument.
+#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
+pub enum ArgTypeSelector {
+    /// Indicates an argument was not recognized, so its type is unknown.
+    #[default]
+    Unknown,
+    /// Indicates an argument is encoded as a CBOR byte string.
+    Bytes,
+    /// Indicates an argument is encoded as a CBOR unsigned integer.
+    Int,
+    /// Indicates an argument is encoded as a CBOR true or false simple value.
+    Bool,
+    /// Indicates an argument needs additional custom decoding.
+    Other,
+}
+
+/// Represents a command or response argument value.
+#[derive(Clone, Debug, Eq, PartialEq, Hash)]
+pub enum ArgValue<'a> {
+    /// This instantiation borrows a slice of a message buffer that was decoded
+    /// as a CBOR byte string. The slice needs to live at least as long as
+    /// this.
+    BytesArg(&'a [u8]),
+    /// This instantiation contains a decoded CBOR unsigned integer.
+    IntArg(u64),
+    /// This instantiation contains a decoded CBOR boolean value.
+    BoolArg(bool),
+}
+
+impl<'a> ArgValue<'a> {
+    /// Creates a new `BytesArg` from a slice, borrowing the slice.
+    pub fn from_slice(value: &'a [u8]) -> Self {
+        ArgValue::BytesArg(value)
+    }
+
+    /// Returns the borrowed slice if this is a BytesArg.
+    ///
+    /// # Errors
+    ///
+    /// Returns an InternalError error if this is not a BytesArg.
+    pub fn try_into_slice(&self) -> DpeResult<&'a [u8]> {
+        match self {
+            ArgValue::IntArg(_) | ArgValue::BoolArg(_) => {
+                error!("ArgValue::try_info_slice called on {:?}", self);
+                Err(ErrCode::InternalError)
+            }
+            ArgValue::BytesArg(value) => Ok(value),
+        }
+    }
+
+    /// Returns the value held by an IntArg as a u32.
+    ///
+    /// # Errors
+    ///
+    /// Returns an InternalError error if this is not an IntArg.
+    pub fn try_into_u32(&self) -> DpeResult<u32> {
+        match self {
+            ArgValue::IntArg(i) => Ok((*i).try_into()?),
+            _ => {
+                error!("ArgValue::try_into_u32 called on {:?}", self);
+                Err(ErrCode::InternalError)
+            }
+        }
+    }
+
+    /// Creates a new `IntArg` holding the given u32 `value`.
+    pub fn from_u32(value: u32) -> Self {
+        ArgValue::IntArg(value as u64)
+    }
+
+    /// Returns the value held by an IntArg as a u64.
+    ///
+    /// # Errors
+    ///
+    /// Returns an InternalError error if this is not an IntArg.
+    pub fn try_into_u64(&self) -> DpeResult<u64> {
+        match self {
+            ArgValue::IntArg(i) => Ok(*i),
+            _ => {
+                error!("ArgValue::try_into_u64 called on {:?}", self);
+                Err(ErrCode::InternalError)
+            }
+        }
+    }
+
+    /// Creates a new `IntArg` holding the given u64 `value`.
+    pub fn from_u64(value: u64) -> Self {
+        ArgValue::IntArg(value)
+    }
+
+    /// Returns the value held by a BoolArg.
+    ///
+    /// # Errors
+    ///
+    /// Returns an InternalError error if this is not a BoolArg.
+    pub fn try_into_bool(&self) -> DpeResult<bool> {
+        match self {
+            ArgValue::BoolArg(b) => Ok(*b),
+            _ => {
+                error!("ArgValue::try_into_bool called on {:?}", self);
+                Err(ErrCode::InternalError)
+            }
+        }
+    }
+
+    /// Creates a new `BoolArg` holding the given `value`.
+    pub fn from_bool(value: bool) -> Self {
+        ArgValue::BoolArg(value)
+    }
+}
+
+impl<'a, const S: usize> From<&'a SizedMessage<S>> for ArgValue<'a> {
+    fn from(message: &'a SizedMessage<S>) -> Self {
+        Self::BytesArg(message.as_slice())
+    }
+}
+
+/// Contains a set of command or response arguments in the form of a map from
+/// [`ArgId`] to [`ArgValue`].
+pub type ArgMap<'a> = FnvIndexMap<ArgId, ArgValue<'a>, 16>;
+
+/// Contains a set of argument types in the form of a map from ArgId to
+/// [`ArgTypeSelector`].
+pub type ArgTypeMap = FnvIndexMap<ArgId, ArgTypeSelector, 16>;
diff --git a/dpe-rs/src/cbor.rs b/dpe-rs/src/cbor.rs
new file mode 100644
index 0000000..373f4a1
--- /dev/null
+++ b/dpe-rs/src/cbor.rs
@@ -0,0 +1,154 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Utilities related to CBOR encode/decode.
+
+use crate::error::{DpeResult, ErrCode};
+use crate::memory::SizedMessage;
+use log::error;
+use minicbor::{Decoder, Encoder};
+
+// Required in order for minicbor to write into a SizedMessage.
+impl<const S: usize> minicbor::encode::Write for SizedMessage<S> {
+    type Error = ();
+    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
+        self.vec.extend_from_slice(buf)
+    }
+}
+
+/// Creates a CBOR [Encoder] which encodes into `output`.
+pub fn cbor_encoder_from_message<const S: usize>(
+    output: &mut SizedMessage<S>,
+) -> Encoder<&mut SizedMessage<S>> {
+    Encoder::new(output)
+}
+
+/// Creates a CBOR [Decoder] which decodes from `input`.
+pub fn cbor_decoder_from_message<const S: usize>(
+    input: &SizedMessage<S>,
+) -> Decoder {
+    Decoder::new(input.as_slice())
+}
+
+/// Extends minicbor::Decoder.
+pub trait DecoderExt {
+    /// Decodes a byte slice and returns only its position. This is useful when
+    /// the byte slice is the last CBOR item, might be large, and will be
+    /// processed in-place using up to the entire available message buffer.
+    /// This is intended to be used in conjunction with [`remove_prefix`].
+    ///
+    /// # Errors
+    ///
+    /// Returns an InvalidArgument error if a CBOR Bytes item cannot be decoded.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// use dpe_rs::cbor::{
+    ///     cbor_decoder_from_message,
+    ///     cbor_encoder_from_message,
+    ///     DecoderExt,
+    /// };
+    /// use dpe_rs::memory::Message;
+    ///
+    /// let mut message = Message::new();
+    /// cbor_encoder_from_message(&mut message).bytes(&[0; 1000]);
+    /// let mut decoder = cbor_decoder_from_message(&message);
+    /// let position = decoder.decode_bytes_prefix().unwrap();
+    /// assert_eq!(&message.as_slice()[position..], &[0; 1000]);
+    /// ```
+    /// [`remove_prefix`]: SizedMessage::remove_prefix
+    fn decode_bytes_prefix(&mut self) -> DpeResult<usize>;
+}
+impl DecoderExt for Decoder<'_> {
+    fn decode_bytes_prefix(&mut self) -> DpeResult<usize> {
+        let bytes_len = self.bytes()?.len();
+        Ok(self.position() - bytes_len)
+    }
+}
+
+/// Encodes a CBOR Bytes prefix for a given `bytes_len` and appends it to
+/// `buffer`. This must be appended by `bytes_len` bytes to form a valid CBOR
+/// encoding.
+///
+/// # Errors
+///
+/// Returns an InternalError error if `bytes_len` is too large for the remaining
+/// capacity of the `buffer`.
+///
+/// # Example
+///
+/// ```rust
+/// use dpe_rs::cbor::{
+///     cbor_decoder_from_message,
+///     cbor_encoder_from_message,
+///     encode_bytes_prefix,
+/// };
+/// use dpe_rs::memory::{
+///     Message,
+///     SizedMessage,
+/// };
+/// type Prefix = SizedMessage<10>;
+///
+/// let mut message = Message::from_slice(&[0; 100]).unwrap();
+/// let mut prefix = Prefix::new();
+/// encode_bytes_prefix(&mut prefix, message.len()).unwrap();
+/// message.insert_prefix(prefix.as_slice()).unwrap();
+/// let mut decoder = cbor_decoder_from_message(&message);
+/// assert_eq!(decoder.bytes().unwrap(), &[0; 100]);
+/// ```
+pub fn encode_bytes_prefix<const S: usize>(
+    buffer: &mut SizedMessage<S>,
+    bytes_len: usize,
+) -> DpeResult<()> {
+    // See RFC 8949 sections 3 and 3.1 for how this is encoded.
+    // `CBOR_BYTES_MAJOR_TYPE` is major type 2 in the high-order 3 bits.
+    const CBOR_BYTES_MAJOR_TYPE: u8 = 2 << 5;
+    const CBOR_VALUE_IN_ONE_BYTE: u8 = 24;
+    const CBOR_VALUE_IN_TWO_BYTES: u8 = 25;
+    let initial_byte_value;
+    let mut following_bytes: &[u8] = &[];
+    let mut big_endian_value: [u8; 2] = Default::default();
+    match bytes_len {
+        0..=23 => {
+            // Encode the length in the lower 5 bits of the initial byte.
+            initial_byte_value = bytes_len as u8;
+        }
+        24..=255 => {
+            // Encode the length in a single additional byte.
+            initial_byte_value = CBOR_VALUE_IN_ONE_BYTE;
+            big_endian_value[0] = bytes_len as u8;
+            following_bytes = &big_endian_value[..1];
+        }
+        256..=65535 => {
+            // Encode the length in two additional bytes, big endian.
+            initial_byte_value = CBOR_VALUE_IN_TWO_BYTES;
+            big_endian_value = (bytes_len as u16).to_be_bytes();
+            following_bytes = &big_endian_value;
+        }
+        _ => {
+            error!("Unsupported CBOR length");
+            return Err(ErrCode::InternalError);
+        }
+    }
+    buffer
+        .vec
+        .push(CBOR_BYTES_MAJOR_TYPE + initial_byte_value)
+        .map_err(|_| ErrCode::InternalError)?;
+    buffer
+        .vec
+        .extend_from_slice(following_bytes)
+        .map_err(|_| ErrCode::InternalError)?;
+    Ok(())
+}
diff --git a/dpe-rs/src/constants.rs b/dpe-rs/src/constants.rs
new file mode 100644
index 0000000..2310e67
--- /dev/null
+++ b/dpe-rs/src/constants.rs
@@ -0,0 +1,52 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Global constants
+
+/// The maximum size in bytes of a message buffer.
+pub const MAX_MESSAGE_SIZE: usize = 8192;
+
+/// The size in bytes of a cryptographic hash.
+pub const HASH_SIZE: usize = 64;
+
+/// The size in bytes of a private session key agreement key.
+pub const DH_PRIVATE_KEY_SIZE: usize = 32;
+
+/// The size in bytes of a public session key agreement key.
+pub const DH_PUBLIC_KEY_SIZE: usize = 32;
+
+/// The size in bytes of an encryption key, currently this is the same for
+/// session and sealing encryption.
+pub const ENCRYPTION_KEY_SIZE: usize = 32;
+
+/// The size in bytes of a serialized public key for signing.
+pub const SIGNING_PUBLIC_KEY_SIZE: usize = 32;
+
+/// The size in bytes of a serialized private key for signing.
+pub const SIGNING_PRIVATE_KEY_SIZE: usize = 32;
+
+/// The size in bytes of a serialized public key for sealing.
+pub const SEALING_PUBLIC_KEY_SIZE: usize = 32;
+
+/// The size in bytes of a serialized private key for sealing.
+pub const SEALING_PRIVATE_KEY_SIZE: usize = 32;
+
+/// The maximum size in bytes of a signature produced by the Sign command.
+pub const MAX_SIGNATURE_SIZE: usize = 64;
+
+/// The maximum size in bytes of a session handshake message.
+pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 64;
+
+/// The maximum size in bytes of a session handshake payload.
+pub const MAX_HANDSHAKE_PAYLOAD_SIZE: usize = 8;
diff --git a/dpe-rs/src/crypto.rs b/dpe-rs/src/crypto.rs
new file mode 100644
index 0000000..ef16210
--- /dev/null
+++ b/dpe-rs/src/crypto.rs
@@ -0,0 +1,321 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Defines the Crypto trait and related types.
+
+use crate::byte_array_wrapper;
+use crate::constants::*;
+use crate::error::DpeResult;
+use crate::memory::{Message, SizedMessage};
+use zeroize::ZeroizeOnDrop;
+
+byte_array_wrapper!(MacKey, HASH_SIZE, "MAC key");
+byte_array_wrapper!(EncryptionKey, ENCRYPTION_KEY_SIZE, "encryption key");
+byte_array_wrapper!(DhPublicKey, DH_PUBLIC_KEY_SIZE, "DH public key");
+byte_array_wrapper!(DhPrivateKey, DH_PRIVATE_KEY_SIZE, "DH private key");
+byte_array_wrapper!(Hash, HASH_SIZE, "hash");
+byte_array_wrapper!(
+    SigningPublicKey,
+    SIGNING_PUBLIC_KEY_SIZE,
+    "signing public key"
+);
+byte_array_wrapper!(
+    SigningPrivateKey,
+    SIGNING_PRIVATE_KEY_SIZE,
+    "signing private key"
+);
+byte_array_wrapper!(
+    SealingPublicKey,
+    SEALING_PUBLIC_KEY_SIZE,
+    "sealing public key"
+);
+byte_array_wrapper!(
+    SealingPrivateKey,
+    SEALING_PRIVATE_KEY_SIZE,
+    "sealing private key"
+);
+
+/// A session handshake message.
+pub type HandshakeMessage = SizedMessage<MAX_HANDSHAKE_MESSAGE_SIZE>;
+/// A session handshake payload.
+pub type HandshakePayload = SizedMessage<MAX_HANDSHAKE_PAYLOAD_SIZE>;
+/// A signature.
+pub type Signature = SizedMessage<MAX_SIGNATURE_SIZE>;
+
+/// A trait for committing previously staged changes.
+pub trait Commit {
+    /// Commits a previously staged changes. When used with session cipher
+    /// state, the staged changes are typically counter increments that result
+    /// from encrypt or decrypt operations.
+    fn commit(&mut self);
+}
+
+/// A trait for maintaining a counter.
+pub trait Counter {
+    /// Returns the current counter value.
+    fn n(&self) -> u64;
+    /// Sets the counter value to `n`.
+    fn set_n(&mut self, n: u64);
+}
+
+/// Provides cryptographic operations for encrypted sessions.
+pub trait SessionCrypto {
+    /// A type to represent session cipher states. These are owned by and opaque
+    /// to the caller in `new_session_handshake` and `derive_session_handshake`.
+    type SessionCipherState: Commit + Counter;
+
+    /// Performs a session responder handshake for a new session.
+    ///
+    /// # Parameters
+    ///
+    /// * `static_dh_key`: The DPE session identity, which the client is
+    /// expected to already know.
+    /// * `initiator_handshake`: The handshake message received from the client.
+    /// * `payload`: The payload to include in the `responder_handshake`.
+    /// * `responder_handshake`: Receives the handshake message to be sent back
+    /// to the client.
+    /// * `decrypt_cipher_state`: Receives cipher state for decrypting incoming
+    /// session messages. This is intended to be passed to
+    /// [`SessionCrypto::session_decrypt`].
+    /// * `encrypt_cipher_state`: Receives cipher state for encrypting outgoing
+    /// session messages. This is intended to be passed to
+    /// [`SessionCrypto::session_encrypt`].
+    /// * `psk_seed`: Receives a PSK seed that can be used to construct a PSK to
+    /// be used when deriving a session (see
+    /// [`SessionCrypto::derive_session_handshake`]).
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    #[allow(clippy::too_many_arguments)]
+    fn new_session_handshake(
+        static_dh_key: &DhPrivateKey,
+        initiator_handshake: &HandshakeMessage,
+        payload: &HandshakePayload,
+        responder_handshake: &mut HandshakeMessage,
+        decrypt_cipher_state: &mut Self::SessionCipherState,
+        encrypt_cipher_state: &mut Self::SessionCipherState,
+        psk_seed: &mut Hash,
+    ) -> DpeResult<()>;
+
+    /// Performs a session responder handshake for a derived session. In
+    /// contrast to a new session handshake, a derived session does not use a
+    /// static key, but a pre-shared key (PSK) derived from an existing session.
+    ///
+    /// # Parameters
+    ///
+    /// * `psk`: A PSK derived from an existing session.
+    /// * `initiator_handshake`: The handshake message received from the client.
+    /// * `payload`: The payload to include in the `responder_handshake`.
+    /// * `responder_handshake`: Receives the handshake message to be sent back
+    /// to the client.
+    /// * `decrypt_cipher_state`: Receives cipher state for decrypting incoming
+    /// session messages. This is intended to be passed to
+    /// [`SessionCrypto::session_decrypt`].
+    /// * `encrypt_cipher_state`: Receives cipher state for encrypting outgoing
+    /// session messages. This is intended to be passed to
+    /// [`SessionCrypto::session_encrypt`].
+    /// * `psk_seed`: Receives a PSK seed that can be used to construct a PSK to
+    /// be used when deriving another session.
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    #[allow(clippy::too_many_arguments)]
+    fn derive_session_handshake(
+        psk: &Hash,
+        initiator_handshake: &HandshakeMessage,
+        payload: &HandshakePayload,
+        responder_handshake: &mut HandshakeMessage,
+        decrypt_cipher_state: &mut Self::SessionCipherState,
+        encrypt_cipher_state: &mut Self::SessionCipherState,
+        psk_seed: &mut Hash,
+    ) -> DpeResult<()>;
+
+    /// Derives a PSK from session state: `psk_seed`, `decrypt_cipher_state`,
+    /// and `encrypt_cipher_state`. The returned PSK is appropriate as an
+    /// argument to [`derive_session_handshake`].
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    ///
+    /// [`derive_session_handshake`]: #method.derive_session_handshake
+    fn derive_psk_from_session(
+        psk_seed: &Hash,
+        decrypt_cipher_state: &Self::SessionCipherState,
+        encrypt_cipher_state: &Self::SessionCipherState,
+    ) -> DpeResult<Hash>;
+
+    /// Encrypts an outgoing session message with the given `cipher_state`. The
+    /// `in_place_buffer` both provides the plaintext message and receives the
+    /// corresponding ciphertext.
+    ///
+    /// # Errors
+    ///
+    /// This method fails with an OutOfMemory error if the encryption overhead
+    /// does not fit in the buffer.
+    fn session_encrypt(
+        cipher_state: &mut Self::SessionCipherState,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+
+    /// Decrypts an incoming session message with the given `cipher_state`. The
+    /// `in_place_buffer` both provides the ciphertext message and receives the
+    /// corresponding plaintext.
+    ///
+    /// # Errors
+    ///
+    /// This method fails with an InvalidArgument error if the ciphertext cannot
+    /// be decrypted (e.g. if tag authentication fails).
+    fn session_decrypt(
+        cipher_state: &mut Self::SessionCipherState,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+}
+
+/// Provides cryptographic operations. These operations are specifically for DPE
+/// concepts, defined by a DPE profile, and to be invoked by a DPE instance.
+pub trait Crypto {
+    /// An associated [`SessionCrypto`] type.
+    type S: SessionCrypto;
+
+    /// Returns a hash of `input`.
+    ///
+    /// # Errors
+    ///
+    /// This method is infallible.
+    fn hash(input: &[u8]) -> Hash;
+
+    /// Returns a hash over all items in `iter`, in order.
+    ///
+    /// # Errors
+    ///
+    /// This method is infallible.
+    fn hash_iter<'a>(iter: impl Iterator<Item = &'a [u8]>) -> Hash;
+
+    /// Runs a key derivation function (KDF) to derive a key the length of the
+    /// `derived_key` buffer. The inputs are interpreted as documented by the
+    /// [HKDF](<https://datatracker.ietf.org/doc/html/rfc5869>) scheme. The
+    /// implementation doesn't need to be HKDF specifically but needs to work
+    /// with HKDF-style inputs.
+    ///
+    /// # Parameters
+    ///
+    /// * `kdf_ikm`: input keying material
+    /// * `kdf_info`: HKDF-style info (optional)
+    /// * `kdf_salt`: HKDF-style salt (optional)
+    /// * `derived_key`: Receives the derived key
+    ///
+    /// # Errors
+    ///
+    /// Fails with an `InternalError` if `derived_key` is too large.
+    fn kdf(
+        kdf_ikm: &[u8],
+        kdf_info: &[u8],
+        kdf_salt: &[u8],
+        derived_key: &mut [u8],
+    ) -> DpeResult<()>;
+
+    /// Derives an asymmetric key pair for signing from a given `seed`.
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    fn signing_keypair_from_seed(
+        seed: &Hash,
+    ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)>;
+
+    /// Derives an asymmetric key pair for sealing from a given `seed`.
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    fn sealing_keypair_from_seed(
+        seed: &Hash,
+    ) -> DpeResult<(SealingPublicKey, SealingPrivateKey)>;
+
+    /// Computes a MAC over `data` using the given `key`.
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    fn mac(key: &MacKey, data: &[u8]) -> DpeResult<Hash>;
+
+    /// Generates a signature over `tbs` using the given `key`.
+    ///
+    /// # Errors
+    ///
+    /// This method allows implementers to return an error but it is expected to
+    /// be infallible.
+    fn sign(key: &SigningPrivateKey, tbs: &[u8]) -> DpeResult<Signature>;
+
+    /// Encrypts data using the given `key` in a way that it can be decrypted by
+    /// the `unseal` method with the same `key`. The `in_place_buffer` both
+    /// provides the plaintext input and receives the ciphertext output.
+    ///
+    /// # Errors
+    ///
+    /// Fails with OutOfMemory if the ciphertext, including overhead, does not
+    /// fit in the buffer.
+    fn seal(
+        key: &EncryptionKey,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+
+    /// Decrypts and authenticates data previously generated by the `seal`
+    /// method using the given 'key'. The `in_place_buffer` both provides the
+    /// ciphertext input and receives the plaintext output.
+    ///
+    /// # Errors
+    ///
+    /// Fails with InvalidArgument if authenticated decryption fails.
+    fn unseal(
+        key: &EncryptionKey,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+
+    /// Encrypts data using an asymmetric scheme and the given `public_key` in
+    /// a way that it can be decrypted by the `unseal_asymmetric` method given
+    /// the corresponding private key. While this method is useful for testing,
+    /// a DPE does not use this during normal operation. The `in_place_buffer`
+    /// both provides the plaintext input and receives the ciphertext output.
+    ///
+    /// # Errors
+    ///
+    /// Fails with OutOfMemory if the ciphertext, including overhead, does not
+    /// fit in the buffer.
+    fn seal_asymmetric(
+        public_key: &SealingPublicKey,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+
+    /// Decrypts data using an asymmetric scheme and the give `key`. The
+    /// `in_place_buffer` both provides the ciphertext input and receives the
+    /// plaintext output.
+    ///
+    /// # Errors
+    ///
+    /// Fails with InvalidArgument if the ciphertext cannot be decrypted.
+    fn unseal_asymmetric(
+        key: &SealingPrivateKey,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()>;
+}
diff --git a/dpe-rs/src/error.rs b/dpe-rs/src/error.rs
new file mode 100644
index 0000000..50293d7
--- /dev/null
+++ b/dpe-rs/src/error.rs
@@ -0,0 +1,83 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Defines the [ErrCode] and [DpeResult] types.
+
+use log::error;
+
+/// An enum of error codes as defined in the DPE specification. The
+/// discriminant values match the CBOR encoding values per the specification.
+#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
+pub enum ErrCode {
+    /// An unexpected error has occurred which is not actionable by the client.
+    InternalError = 1,
+    /// The command could not be decrypted, parsed, or is not supported.
+    InvalidCommand = 2,
+    /// A command argument is malformed, invalid with respect to the current
+    /// DPE state, in conflict with other arguments, not allowed, not
+    /// recognized, or otherwise not supported.
+    InvalidArgument = 3,
+    /// Keys for an encrypted session have been exhausted.
+    SessionExhausted = 4,
+    /// The command cannot be fulfilled because an internal seed component is
+    /// no longer available.
+    InitializationSeedLocked = 5,
+    /// A lack of internal resources prevented the DPE from fulfilling the
+    /// command.
+    OutOfMemory = 6,
+    /// The command was canceled.
+    Canceled = 7,
+}
+
+impl<E> From<minicbor::encode::Error<E>> for ErrCode {
+    fn from(_error: minicbor::encode::Error<E>) -> Self {
+        error!("Failed to encode CBOR message");
+        ErrCode::InternalError
+    }
+}
+
+impl From<minicbor::decode::Error> for ErrCode {
+    fn from(_error: minicbor::decode::Error) -> Self {
+        error!("Failed to decode CBOR message");
+        ErrCode::InvalidArgument
+    }
+}
+
+impl From<core::num::TryFromIntError> for ErrCode {
+    fn from(_: core::num::TryFromIntError) -> Self {
+        error!("Unexpected failure: core::num::TryFromIntError");
+        ErrCode::InternalError
+    }
+}
+
+impl From<u32> for ErrCode {
+    fn from(value: u32) -> Self {
+        match value {
+            1 => Self::InternalError,
+            2 => Self::InvalidCommand,
+            3 => Self::InvalidArgument,
+            4 => Self::SessionExhausted,
+            5 => Self::InitializationSeedLocked,
+            6 => Self::OutOfMemory,
+            7 => Self::Canceled,
+            _ => {
+                error!("Unknown error code");
+                Self::InternalError
+            }
+        }
+    }
+}
+
+/// A Result type using a DPE [`ErrCode`] error type.
+pub type DpeResult<T> = Result<T, ErrCode>;
diff --git a/dpe-rs/src/lib.rs b/dpe-rs/src/lib.rs
new file mode 100644
index 0000000..b995caf
--- /dev/null
+++ b/dpe-rs/src/lib.rs
@@ -0,0 +1,57 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#![no_std]
+#![deny(unsafe_code)]
+#![deny(missing_docs)]
+#![deny(trivial_casts)]
+#![deny(trivial_numeric_casts)]
+#![deny(unused_extern_crates)]
+#![deny(unused_import_braces)]
+#![deny(unused_results)]
+#![deny(clippy::indexing_slicing)]
+#![deny(clippy::unwrap_used)]
+#![deny(clippy::panic)]
+#![deny(clippy::expect_used)]
+
+//! # DICE Protection Environment
+//!
+//! `dpe_rs` implements a DICE Protection Environment (DPE) for a family of DPE
+//! profiles which align with the
+//! [Open Profile for DICE](<https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md>)
+//! specification.
+//!
+//! # no_std
+//!
+//! This crate uses `#![no_std]` for portability to embedded environments.
+//!
+//! # Panics
+//!
+//! Functions and methods in this crate, aside from tests, do not panic. A panic
+//! means there is a bug that should be fixed.
+//!
+//! # Safety
+//!
+//! This crate does not use unsafe code.
+//!
+//! # Notes
+//!
+//! This crate is in development and not ready for production use.
+pub mod args;
+pub mod cbor;
+pub mod constants;
+pub mod crypto;
+pub mod error;
+pub mod memory;
+pub mod noise;
diff --git a/dpe-rs/src/memory.rs b/dpe-rs/src/memory.rs
new file mode 100644
index 0000000..905b136
--- /dev/null
+++ b/dpe-rs/src/memory.rs
@@ -0,0 +1,291 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! Types and functions to help with memory buffer management.
+
+use crate::constants::*;
+use crate::error::{DpeResult, ErrCode};
+use heapless::Vec;
+use zeroize::ZeroizeOnDrop;
+
+/// Creates a byte array wrapper type for the sake of precise typing.
+#[macro_export]
+macro_rules! byte_array_wrapper {
+    ($type_name:ident, $len:ident, $desc:expr) => {
+        #[doc = "A byte array wrapper to represent a "]
+        #[doc = $desc]
+        #[doc = "."]
+        #[derive(Clone, Debug, Eq, PartialEq, Hash, ZeroizeOnDrop)]
+        pub struct $type_name([u8; $len]);
+        impl $type_name {
+            #[doc = "Returns the length of the array."]
+            pub fn len(&self) -> usize {
+                self.0.len()
+            }
+
+            #[doc = "Whether the array is empty."]
+            pub fn is_empty(&self) -> bool {
+                self.0.is_empty()
+            }
+
+            #[doc = "Borrows the array as a slice."]
+            pub fn as_slice(&self) -> &[u8] {
+                self.0.as_slice()
+            }
+
+            #[doc = "Mutably borrows the array as a slice."]
+            pub fn as_mut_slice(&mut self) -> &mut [u8] {
+                &mut self.0
+            }
+
+            #[doc = "Borrows the array."]
+            pub fn as_array(&self) -> &[u8; $len] {
+                &self.0
+            }
+
+            #[doc = "Creates a "]
+            #[doc = stringify!($type_name)]
+            #[doc = " from a slice. Fails if the slice length is not "]
+            #[doc = stringify!($len)]
+            #[doc = "."]
+            pub fn from_slice(s: &[u8]) -> DpeResult<Self> {
+                Self::try_from(s)
+            }
+
+            #[doc = "Creates a "]
+            #[doc = stringify!($type_name)]
+            #[doc = " from a slice infallibly. If the length of the slice is less than "]
+            #[doc = stringify!($len)]
+            #[doc = ", the remainder of the array is the default value. If the length "]
+            #[doc = "of the slice is more than "]
+            #[doc = stringify!($len)]
+            #[doc = ", only the first "]
+            #[doc = stringify!($len)]
+            #[doc = " bytes are used. This method is infallible."]
+            pub fn from_slice_infallible(value: &[u8]) -> Self {
+                #![allow(clippy::indexing_slicing)]
+                let mut tmp: Self = Default::default();
+                if value.len() < $len {
+                    tmp.0[..value.len()].copy_from_slice(value);
+                } else {
+                    tmp.0.copy_from_slice(&value[..$len]);
+                }
+                tmp
+            }
+
+            #[doc = "Creates a "]
+            #[doc = stringify!($type_name)]
+            #[doc = " from an array."]
+            pub fn from_array(value: &[u8; $len]) -> Self {
+                Self(*value)
+            }
+        }
+
+        impl Default for $type_name {
+            fn default() -> Self {
+                Self([0; $len])
+            }
+        }
+
+        impl TryFrom<&[u8]> for $type_name {
+            type Error = $crate::error::ErrCode;
+
+            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
+                value.try_into().map(Self).map_err(|_| {
+                    log::error!("Invalid length for fixed length value: {}", $desc);
+                    $crate::error::ErrCode::InvalidArgument
+                })
+            }
+        }
+
+        impl From<[u8; $len]> for $type_name {
+            fn from(value: [u8; $len]) -> Self {
+                Self(value)
+            }
+        }
+    };
+}
+
+/// Wraps a [heapless::Vec] of bytes and provides various convenience methods
+/// that are useful when processing DPE messages. The inner `vec` is also
+/// accessible directly.
+#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, ZeroizeOnDrop)]
+pub struct SizedMessage<const S: usize> {
+    /// The wrapped Vec.
+    pub vec: Vec<u8, S>,
+}
+
+impl<const S: usize> SizedMessage<S> {
+    /// Creates a new, empty instance.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// assert_eq!(MyMessage::new().len(), 0);
+    /// ```
+    pub fn new() -> Self {
+        Default::default()
+    }
+
+    /// Creates a new instance from a slice.
+    ///
+    /// # Errors
+    ///
+    /// If `value` exceeds the available capacity, returns an OutOfMemory error.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// assert_eq!(MyMessage::from_slice(&[0; 12]).unwrap().as_slice(), &[0; 12]);
+    /// ```
+    pub fn from_slice(value: &[u8]) -> DpeResult<Self> {
+        Ok(Self {
+            vec: Vec::from_slice(value).map_err(|_| ErrCode::OutOfMemory)?,
+        })
+    }
+
+    /// Clones `slice`, replacing any existing content.
+    ///
+    /// # Errors
+    ///
+    /// If `slice` exceeds the available capacity, returns an OutOfMemory error.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// let mut m = MyMessage::from_slice(&[0; 12]).unwrap();
+    /// m.clone_from_slice(&[1; 3]).unwrap();
+    /// assert_eq!(m.as_slice(), &[1; 3]);
+    /// ```
+    pub fn clone_from_slice(&mut self, slice: &[u8]) -> DpeResult<()> {
+        self.clear();
+        self.vec.extend_from_slice(slice).map_err(|_| ErrCode::OutOfMemory)
+    }
+
+    /// Borrows the inner byte array.
+    pub fn as_slice(&self) -> &[u8] {
+        self.vec.as_slice()
+    }
+
+    /// Mutably borrows the inner byte array after resizing. This is useful when
+    /// using the type as an output buffer.
+    ///
+    /// # Errors
+    ///
+    /// If `size` exceeds the available capacity, returns an OutOfMemory error.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// use rand_core::{RngCore, SeedableRng};
+    ///
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// let mut buffer = MyMessage::new();
+    /// <rand_chacha::ChaCha12Rng as SeedableRng>::seed_from_u64(0)
+    ///     .fill_bytes(buffer.as_mut_sized(100).unwrap());
+    /// assert_eq!(buffer.len(), 100);
+    /// ```
+    pub fn as_mut_sized(&mut self, size: usize) -> DpeResult<&mut [u8]> {
+        self.vec.resize_default(size).map_err(|_| ErrCode::OutOfMemory)?;
+        Ok(self.vec.as_mut())
+    }
+
+    /// Returns the length of the inner vec.
+    pub fn len(&self) -> usize {
+        self.vec.len()
+    }
+
+    /// Whether the inner vec is empty.
+    pub fn is_empty(&self) -> bool {
+        self.vec.is_empty()
+    }
+
+    /// Clears the inner vec.
+    pub fn clear(&mut self) {
+        self.vec.clear()
+    }
+
+    /// Removes the first `prefix_size` bytes from the message. This carries the
+    /// cost of moving the remaining bytes to the front of the buffer.
+    ///
+    /// # Errors
+    ///
+    /// If `prefix_size` is larger than the current length, returns an
+    /// InternalError error.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// let mut m = MyMessage::from_slice("prefixdata".as_bytes()).unwrap();
+    /// m.remove_prefix(6).unwrap();
+    /// assert_eq!(m.as_slice(), "data".as_bytes());
+    /// ```
+    pub fn remove_prefix(&mut self, prefix_size: usize) -> DpeResult<()> {
+        if prefix_size > self.len() {
+            return Err(ErrCode::InternalError);
+        }
+        if prefix_size == self.len() {
+            self.clear();
+        } else if prefix_size > 0 {
+            let slice: &mut [u8] = self.vec.as_mut();
+            slice.copy_within(prefix_size.., 0);
+            self.vec.truncate(self.len() - prefix_size);
+        }
+        Ok(())
+    }
+
+    /// Inserts `prefix` at the start of the message. This carries the cost of
+    /// moving the existing bytes to make room for the prefix.
+    ///
+    /// # Errors
+    ///
+    /// If inserting `prefix` overflows the available capacity, returns an
+    /// OutOfMemory error.
+    ///
+    /// # Example
+    ///
+    /// ```rust
+    /// type MyMessage = dpe_rs::memory::SizedMessage<200>;
+    ///
+    /// let mut m = MyMessage::from_slice("data".as_bytes()).unwrap();
+    /// m.insert_prefix("prefix".as_bytes()).unwrap();
+    /// assert_eq!(m.as_slice(), "prefixdata".as_bytes());
+    /// ```
+    pub fn insert_prefix(&mut self, prefix: &[u8]) -> DpeResult<()> {
+        let old_len = self.len();
+        self.vec
+            .resize_default(self.len() + prefix.len())
+            .map_err(|_| ErrCode::OutOfMemory)?;
+        let slice: &mut [u8] = self.vec.as_mut();
+        slice.copy_within(0..old_len, prefix.len());
+        slice
+            .get_mut(..prefix.len())
+            .ok_or(ErrCode::InternalError)?
+            .copy_from_slice(prefix);
+        Ok(())
+    }
+}
+
+/// Represents a DPE command/response message. This type is large and should not
+/// be instantiated unnecessarily.
+pub type Message = SizedMessage<MAX_MESSAGE_SIZE>;
diff --git a/dpe-rs/src/noise.rs b/dpe-rs/src/noise.rs
new file mode 100644
index 0000000..49fa517
--- /dev/null
+++ b/dpe-rs/src/noise.rs
@@ -0,0 +1,698 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+//! An encrypted session implementation which uses
+//! Noise_NK_X25519_AESGCM_SHA512 and Noise_NNpsk0_X25519_AESGCM_SHA512.
+
+use crate::crypto::{
+    Commit, Counter, DhPrivateKey, DhPublicKey, HandshakeMessage,
+    HandshakePayload, Hash, SessionCrypto,
+};
+use crate::error::{DpeResult, ErrCode};
+use crate::memory::Message;
+use core::marker::PhantomData;
+use log::{debug, error};
+use noise_protocol::{HandshakeStateBuilder, Hash as NoiseHash, U8Array};
+
+impl From<noise_protocol::Error> for ErrCode {
+    fn from(_err: noise_protocol::Error) -> Self {
+        ErrCode::InvalidArgument
+    }
+}
+
+impl<NoiseHash> From<&NoiseHash> for Hash
+where
+    NoiseHash: U8Array,
+{
+    fn from(value: &NoiseHash) -> Self {
+        // The Noise hash size may not match HASH_SIZE.
+        Hash::from_slice_infallible(value.as_slice())
+    }
+}
+
+/// A cipher state type that can be used as a
+/// [`SessionCipherState`](crate::crypto::SessionCrypto::SessionCipherState).
+pub struct NoiseCipherState<C: noise_protocol::Cipher> {
+    k: C::Key,
+    n: u64,
+    n_staged: u64,
+}
+
+impl<C: noise_protocol::Cipher> Clone for NoiseCipherState<C> {
+    fn clone(&self) -> Self {
+        Self { k: self.k.clone(), n: self.n, n_staged: self.n_staged }
+    }
+}
+
+impl<C: noise_protocol::Cipher> Default for NoiseCipherState<C> {
+    fn default() -> Self {
+        Self { k: C::Key::new(), n: 0, n_staged: 0 }
+    }
+}
+
+impl<C: noise_protocol::Cipher> core::fmt::Debug for NoiseCipherState<C> {
+    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
+        write!(f, "k: redacted, n: {}", self.n)?;
+        Ok(())
+    }
+}
+
+impl<C: noise_protocol::Cipher> core::hash::Hash for NoiseCipherState<C> {
+    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
+        self.k.as_slice().hash(state);
+        self.n.hash(state);
+        self.n_staged.hash(state);
+    }
+}
+
+#[cfg(test)]
+impl<C: noise_protocol::Cipher> PartialEq for NoiseCipherState<C> {
+    fn eq(&self, other: &Self) -> bool {
+        self.k.as_slice() == other.k.as_slice()
+            && self.n == other.n
+            && self.n_staged == other.n_staged
+    }
+}
+
+#[cfg(test)]
+impl<C: noise_protocol::Cipher> Eq for NoiseCipherState<C> {}
+
+impl<C: noise_protocol::Cipher> Counter for NoiseCipherState<C> {
+    fn n(&self) -> u64 {
+        self.n
+    }
+    fn set_n(&mut self, n: u64) {
+        self.n = n;
+    }
+}
+
+impl<C: noise_protocol::Cipher> Commit for NoiseCipherState<C> {
+    // Called when an encrypted message is finalized to commit the new cipher
+    // state.
+    fn commit(&mut self) {
+        self.n = self.n_staged;
+    }
+}
+
+impl<C: noise_protocol::Cipher> From<&noise_protocol::CipherState<C>>
+    for NoiseCipherState<C>
+{
+    fn from(cs: &noise_protocol::CipherState<C>) -> Self {
+        let (key, counter) = cs.clone().extract();
+        NoiseCipherState { k: key, n: counter, n_staged: counter }
+    }
+}
+
+/// Returns the public key corresponding to a given `dh_private_key`.
+pub fn get_dh_public_key<D: noise_protocol::DH>(
+    dh_private_key: &DhPrivateKey,
+) -> DpeResult<DhPublicKey> {
+    DhPublicKey::from_slice(
+        D::pubkey(&D::Key::from_slice(dh_private_key.as_slice())).as_slice(),
+    )
+}
+
+/// A trait representing [`NoiseSessionCrypto`] dependencies.
+pub trait NoiseCryptoDeps {
+    /// Cipher type
+    type Cipher: noise_protocol::Cipher;
+    /// DH type
+    type DH: noise_protocol::DH;
+    /// Hash type
+    type Hash: noise_protocol::Hash;
+}
+
+/// A Noise implementation of the [`SessionCrypto`] trait.
+pub struct NoiseSessionCrypto<D: NoiseCryptoDeps> {
+    #[allow(dead_code)]
+    phantom: PhantomData<D>,
+}
+
+impl<D> Clone for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn clone(&self) -> Self {
+        Self { phantom: Default::default() }
+    }
+}
+
+impl<D> Default for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn default() -> Self {
+        Self { phantom: Default::default() }
+    }
+}
+
+impl<D> core::fmt::Debug for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
+        Ok(())
+    }
+}
+
+impl<D> core::hash::Hash for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn hash<Hr: core::hash::Hasher>(&self, _: &mut Hr) {}
+}
+
+impl<D> PartialEq for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn eq(&self, _: &Self) -> bool {
+        true
+    }
+}
+
+impl<D> Eq for NoiseSessionCrypto<D> where D: NoiseCryptoDeps {}
+
+impl<D> SessionCrypto for NoiseSessionCrypto<D>
+where
+    D: NoiseCryptoDeps,
+{
+    type SessionCipherState = NoiseCipherState<D::Cipher>;
+
+    /// Implements the responder role of a Noise_NK handshake.
+    fn new_session_handshake(
+        static_dh_key: &DhPrivateKey,
+        initiator_handshake: &HandshakeMessage,
+        payload: &HandshakePayload,
+        responder_handshake: &mut HandshakeMessage,
+        decrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
+        encrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
+        psk_seed: &mut Hash,
+    ) -> DpeResult<()> {
+        #[allow(unused_results)]
+        let mut handshake: noise_protocol::HandshakeState<
+            D::DH,
+            D::Cipher,
+            D::Hash,
+        > = {
+            let mut builder = HandshakeStateBuilder::new();
+            builder.set_pattern(noise_protocol::patterns::noise_nk());
+            builder.set_is_initiator(false);
+            builder.set_prologue(&[]);
+            builder.set_s(<D::DH as noise_protocol::DH>::Key::from_slice(
+                static_dh_key.as_slice(),
+            ));
+            builder.build_handshake_state()
+        };
+        handshake.read_message(initiator_handshake.as_slice(), &mut [])?;
+        handshake.write_message(
+            payload.as_slice(),
+            responder_handshake.as_mut_sized(
+                handshake.get_next_message_overhead() + payload.len(),
+            )?,
+        )?;
+        assert!(handshake.completed());
+        let ciphers = handshake.get_ciphers();
+        *decrypt_cipher_state = (&ciphers.0).into();
+        *encrypt_cipher_state = (&ciphers.1).into();
+        debug!("get_hash");
+        *psk_seed = Hash::from_slice(handshake.get_hash())?;
+        Ok(())
+    }
+
+    /// Implements the responder role of a Noise_NNpsk0 handshake.
+    fn derive_session_handshake(
+        psk: &Hash,
+        initiator_handshake: &HandshakeMessage,
+        payload: &HandshakePayload,
+        responder_handshake: &mut HandshakeMessage,
+        decrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
+        encrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
+        psk_seed: &mut Hash,
+    ) -> DpeResult<()> {
+        #[allow(unused_results)]
+        let mut handshake: noise_protocol::HandshakeState<
+            D::DH,
+            D::Cipher,
+            D::Hash,
+        > = {
+            let mut builder = HandshakeStateBuilder::new();
+            builder.set_pattern(noise_protocol::patterns::noise_nn_psk0());
+            builder.set_is_initiator(false);
+            builder.set_prologue(&[]);
+            builder.build_handshake_state()
+        };
+        handshake
+            .push_psk(psk.as_slice().get(..32).ok_or(ErrCode::InternalError)?);
+        handshake.read_message(initiator_handshake.as_slice(), &mut [])?;
+        handshake.write_message(
+            payload.as_slice(),
+            responder_handshake.as_mut_sized(
+                handshake.get_next_message_overhead() + payload.len(),
+            )?,
+        )?;
+        let ciphers = handshake.get_ciphers();
+        *decrypt_cipher_state = (&ciphers.0).into();
+        *encrypt_cipher_state = (&ciphers.1).into();
+        *psk_seed = Hash::from_slice(handshake.get_hash())?;
+        Ok(())
+    }
+
+    /// Encrypts a Noise transport message in place.
+    fn session_encrypt(
+        cipher_state: &mut NoiseCipherState<D::Cipher>,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()> {
+        let mut cs = noise_protocol::CipherState::<D::Cipher>::new(
+            cipher_state.k.as_slice(),
+            cipher_state.n,
+        );
+        let plaintext_len = in_place_buffer.len();
+        let _ = cs.encrypt_in_place(
+            in_place_buffer.as_mut_sized(
+                plaintext_len
+                    + <D::Cipher as noise_protocol::Cipher>::tag_len(),
+            )?,
+            plaintext_len,
+        );
+        // Encrypting a message is usually not the final step in preparing
+        // the message for transport. If a subsequent step fails, it is
+        // better for 'n' to remain unchanged so we don't get out of sync.
+        (_, cipher_state.n_staged) = cs.extract();
+        Ok(())
+    }
+
+    /// Decrypts a Noise transport message in place.
+    fn session_decrypt(
+        cipher_state: &mut NoiseCipherState<D::Cipher>,
+        in_place_buffer: &mut Message,
+    ) -> DpeResult<()> {
+        let mut cs = noise_protocol::CipherState::<D::Cipher>::new(
+            cipher_state.k.as_slice(),
+            cipher_state.n,
+        );
+        let ciphertext_len = in_place_buffer.len();
+        let plaintext_len = match cs
+            .decrypt_in_place(in_place_buffer.vec.as_mut(), ciphertext_len)
+        {
+            Ok(length) => length,
+            _ => {
+                error!("Session decrypt failed");
+                return Err(ErrCode::InvalidCommand);
+            }
+        };
+        in_place_buffer.vec.truncate(plaintext_len);
+        (_, cipher_state.n) = cs.extract();
+        Ok(())
+    }
+
+    /// Derives a responder-side PSK.
+    fn derive_psk_from_session(
+        psk_seed: &Hash,
+        decrypt_cipher_state: &NoiseCipherState<D::Cipher>,
+        encrypt_cipher_state: &NoiseCipherState<D::Cipher>,
+    ) -> DpeResult<Hash> {
+        let mut hasher: D::Hash = Default::default();
+        hasher.input(psk_seed.as_slice());
+        // Use the decrypt state as it was before we decrypted the current
+        // command message. This allows clients to compute the PSK using
+        // the cipher states as they are before the client sends the
+        // command.
+        hasher.input(&(decrypt_cipher_state.n() - 1).to_le_bytes());
+        hasher.input(&encrypt_cipher_state.n().to_le_bytes());
+        Ok((&hasher.result()).into())
+    }
+}
+
+/// A SessionClient implements the initiator side of an encrypted session. A
+/// DPE does not use this itself, it is useful for clients and testing.
+pub struct SessionClient<D>
+where
+    D: NoiseCryptoDeps,
+{
+    handshake_state:
+        Option<noise_protocol::HandshakeState<D::DH, D::Cipher, D::Hash>>,
+    /// Cipher state for encrypting messages to a DPE.
+    pub encrypt_cipher_state: NoiseCipherState<D::Cipher>,
+    /// Cipher state for decrypting messages from a DPE.
+    pub decrypt_cipher_state: NoiseCipherState<D::Cipher>,
+    /// PSK seed for deriving sessions. See [`derive_psk`].
+    ///
+    /// [`derive_psk`]: #method.derive_psk
+    pub psk_seed: Hash,
+}
+
+impl<D> Clone for SessionClient<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn clone(&self) -> Self {
+        Self {
+            handshake_state: self.handshake_state.clone(),
+            encrypt_cipher_state: self.encrypt_cipher_state.clone(),
+            decrypt_cipher_state: self.decrypt_cipher_state.clone(),
+            psk_seed: self.psk_seed.clone(),
+        }
+    }
+}
+
+impl<D> Default for SessionClient<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn default() -> Self {
+        Self::new()
+    }
+}
+
+impl<D> core::fmt::Debug for SessionClient<D>
+where
+    D: NoiseCryptoDeps,
+{
+    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
+        Ok(())
+    }
+}
+
+impl<D> SessionClient<D>
+where
+    D: NoiseCryptoDeps,
+{
+    /// Creates a new SessionClient instance. Set up by starting and finishing a
+    /// handshake.
+    pub fn new() -> Self {
+        Self {
+            handshake_state: Default::default(),
+            encrypt_cipher_state: Default::default(),
+            decrypt_cipher_state: Default::default(),
+            psk_seed: Default::default(),
+        }
+    }
+
+    /// Starts a handshake using a known `public_key` and returns a message that
+    /// works with the DPE OpenSession command.
+    pub fn start_handshake_with_known_public_key(
+        &mut self,
+        public_key: &DhPublicKey,
+    ) -> DpeResult<HandshakeMessage> {
+        #[allow(unused_results)]
+        let mut handshake_state = {
+            let mut builder = HandshakeStateBuilder::new();
+            builder.set_pattern(noise_protocol::patterns::noise_nk());
+            builder.set_is_initiator(true);
+            builder.set_prologue(&[]);
+            builder.set_rs(<D::DH as noise_protocol::DH>::Pubkey::from_slice(
+                public_key.as_slice(),
+            ));
+            builder.build_handshake_state()
+        };
+        let mut message = HandshakeMessage::new();
+        handshake_state.write_message(
+            &[],
+            message
+                .as_mut_sized(handshake_state.get_next_message_overhead())?,
+        )?;
+        self.handshake_state = Some(handshake_state);
+        Ok(message)
+    }
+
+    /// Starts a handshake using a `psk` and returns a message that works with
+    /// the DPE DeriveContext command. Use [`derive_psk`] to obtain this value
+    /// from an existing session.
+    ///
+    /// [`derive_psk`]: #method.derive_psk
+    pub fn start_handshake_with_psk(
+        &mut self,
+        psk: &Hash,
+    ) -> DpeResult<HandshakeMessage> {
+        #[allow(unused_results)]
+        let mut handshake_state = {
+            let mut builder = HandshakeStateBuilder::new();
+            builder.set_pattern(noise_protocol::patterns::noise_nn_psk0());
+            builder.set_is_initiator(true);
+            builder.set_prologue(&[]);
+            builder.build_handshake_state()
+        };
+        handshake_state
+            .push_psk(psk.as_slice().get(..32).ok_or(ErrCode::InternalError)?);
+        let mut message = HandshakeMessage::new();
+        handshake_state.write_message(
+            &[],
+            message
+                .as_mut_sized(handshake_state.get_next_message_overhead())?,
+        )?;
+        self.handshake_state = Some(handshake_state);
+        Ok(message)
+    }
+
+    /// Finishes a handshake started using one of the start_handshake_* methods.
+    /// On success, returns the handshake payload from the responder and sets up
+    /// internal state for subsequent calls to encrypt and decrypt.
+    pub fn finish_handshake(
+        &mut self,
+        responder_handshake: &HandshakeMessage,
+    ) -> DpeResult<HandshakePayload> {
+        match self.handshake_state {
+            None => Err(ErrCode::InvalidArgument),
+            Some(ref mut handshake) => {
+                let mut payload = HandshakePayload::new();
+                handshake.read_message(
+                    responder_handshake.as_slice(),
+                    payload.as_mut_sized(
+                        responder_handshake.len()
+                            - handshake.get_next_message_overhead(),
+                    )?,
+                )?;
+                let ciphers = handshake.get_ciphers();
+                self.encrypt_cipher_state = (&ciphers.0).into();
+                self.decrypt_cipher_state = (&ciphers.1).into();
+                self.psk_seed = Hash::from_slice(handshake.get_hash())?;
+                Ok(payload)
+            }
+        }
+    }
+
+    /// Derives a PSK from the current session.
+    pub fn derive_psk(&self) -> Hash {
+        // Note this is from a client perspective so the counters are hashed
+        // encrypt first and unmodified from their current state. A DPE will
+        // reverse the order and decrement the first counter in order to derive
+        // the same value (see derive_psk_from_session).
+        let mut hasher: D::Hash = Default::default();
+        hasher.input(self.psk_seed.as_slice());
+        hasher.input(&self.encrypt_cipher_state.n().to_le_bytes());
+        hasher.input(&self.decrypt_cipher_state.n().to_le_bytes());
+        (&hasher.result()).into()
+    }
+
+    /// Encrypts a message to send to a DPE and commits cipher state changes.
+    pub fn encrypt(&mut self, in_place_buffer: &mut Message) -> DpeResult<()> {
+        NoiseSessionCrypto::<D>::session_encrypt(
+            &mut self.encrypt_cipher_state,
+            in_place_buffer,
+        )?;
+        self.encrypt_cipher_state.commit();
+        Ok(())
+    }
+
+    /// Decrypts a message from a DPE.
+    pub fn decrypt(&mut self, in_place_buffer: &mut Message) -> DpeResult<()> {
+        NoiseSessionCrypto::<D>::session_decrypt(
+            &mut self.decrypt_cipher_state,
+            in_place_buffer,
+        )
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    struct DepsForTesting {}
+    impl NoiseCryptoDeps for DepsForTesting {
+        type Cipher = noise_rust_crypto::Aes256Gcm;
+        type DH = noise_rust_crypto::X25519;
+        type Hash = noise_rust_crypto::Sha512;
+    }
+
+    type SessionCryptoForTesting = NoiseSessionCrypto<DepsForTesting>;
+
+    type SessionClientForTesting = SessionClient<DepsForTesting>;
+
+    type CipherStateForTesting = NoiseCipherState<noise_rust_crypto::Aes256Gcm>;
+
+    #[test]
+    fn end_to_end_session() {
+        let mut client = SessionClientForTesting::new();
+        let dh_key: DhPrivateKey = Default::default();
+        let dh_public_key = get_dh_public_key::<
+            <DepsForTesting as NoiseCryptoDeps>::DH,
+        >(&dh_key)
+        .unwrap();
+        let handshake1 = client
+            .start_handshake_with_known_public_key(&dh_public_key)
+            .unwrap();
+        let mut dpe_decrypt_cs: CipherStateForTesting = Default::default();
+        let mut dpe_encrypt_cs: CipherStateForTesting = Default::default();
+        let mut psk_seed = Default::default();
+        let mut handshake2 = Default::default();
+        let payload = HandshakePayload::from_slice("pay".as_bytes()).unwrap();
+        SessionCryptoForTesting::new_session_handshake(
+            &dh_key,
+            &handshake1,
+            &payload,
+            &mut handshake2,
+            &mut dpe_decrypt_cs,
+            &mut dpe_encrypt_cs,
+            &mut psk_seed,
+        )
+        .unwrap();
+        assert_eq!(payload, client.finish_handshake(&handshake2).unwrap());
+
+        // Check that the session works.
+        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
+        client.encrypt(&mut buffer).unwrap();
+        SessionCryptoForTesting::session_decrypt(
+            &mut dpe_decrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+        SessionCryptoForTesting::session_encrypt(
+            &mut dpe_encrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        dpe_encrypt_cs.commit();
+        client.decrypt(&mut buffer).unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+
+        // Do it again to check session state still works.
+        client.encrypt(&mut buffer).unwrap();
+        SessionCryptoForTesting::session_decrypt(
+            &mut dpe_decrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+        SessionCryptoForTesting::session_encrypt(
+            &mut dpe_encrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        dpe_encrypt_cs.commit();
+        client.decrypt(&mut buffer).unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+    }
+
+    #[test]
+    fn derived_session() {
+        // Set up a session from which to derive.
+        let mut client = SessionClientForTesting::new();
+        let dh_key: DhPrivateKey = Default::default();
+        let dh_public_key = get_dh_public_key::<
+            <DepsForTesting as NoiseCryptoDeps>::DH,
+        >(&dh_key)
+        .unwrap();
+        let handshake1 = client
+            .start_handshake_with_known_public_key(&dh_public_key)
+            .unwrap();
+        let mut dpe_decrypt_cs = Default::default();
+        let mut dpe_encrypt_cs = Default::default();
+        let mut psk_seed = Default::default();
+        let mut handshake2 = Default::default();
+        let payload = HandshakePayload::from_slice("pay".as_bytes()).unwrap();
+        SessionCryptoForTesting::new_session_handshake(
+            &dh_key,
+            &handshake1,
+            &payload,
+            &mut handshake2,
+            &mut dpe_decrypt_cs,
+            &mut dpe_encrypt_cs,
+            &mut psk_seed,
+        )
+        .unwrap();
+        assert_eq!(payload, client.finish_handshake(&handshake2).unwrap());
+
+        // Derive a second session.
+        let mut client2 = SessionClientForTesting::new();
+        let client_psk = client.derive_psk();
+        // Simulate the session state after command decryption on the DPE side
+        // as expected by the DPE PSK logic.
+        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
+        client.encrypt(&mut buffer).unwrap();
+        SessionCryptoForTesting::session_decrypt(
+            &mut dpe_decrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        let dpe_psk = SessionCryptoForTesting::derive_psk_from_session(
+            &psk_seed,
+            &dpe_decrypt_cs,
+            &dpe_encrypt_cs,
+        )
+        .unwrap();
+        let handshake1 = client2.start_handshake_with_psk(&client_psk).unwrap();
+        let mut dpe_decrypt_cs2 = Default::default();
+        let mut dpe_encrypt_cs2 = Default::default();
+        let mut psk_seed2 = Default::default();
+        SessionCryptoForTesting::derive_session_handshake(
+            &dpe_psk,
+            &handshake1,
+            &payload,
+            &mut handshake2,
+            &mut dpe_decrypt_cs2,
+            &mut dpe_encrypt_cs2,
+            &mut psk_seed2,
+        )
+        .unwrap();
+        assert_eq!(payload, client2.finish_handshake(&handshake2).unwrap());
+
+        // Check that the second session works.
+        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
+        client2.encrypt(&mut buffer).unwrap();
+        SessionCryptoForTesting::session_decrypt(
+            &mut dpe_decrypt_cs2,
+            &mut buffer,
+        )
+        .unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+        SessionCryptoForTesting::session_encrypt(
+            &mut dpe_encrypt_cs2,
+            &mut buffer,
+        )
+        .unwrap();
+        dpe_encrypt_cs2.commit();
+        client2.decrypt(&mut buffer).unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+
+        // Check that the first session also still works.
+        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
+        client.encrypt(&mut buffer).unwrap();
+        SessionCryptoForTesting::session_decrypt(
+            &mut dpe_decrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+        SessionCryptoForTesting::session_encrypt(
+            &mut dpe_encrypt_cs,
+            &mut buffer,
+        )
+        .unwrap();
+        dpe_encrypt_cs.commit();
+        client.decrypt(&mut buffer).unwrap();
+        assert_eq!("message".as_bytes(), buffer.as_slice());
+    }
+}
diff --git a/include/dice/boringssl_ecdsa_utils.h b/include/dice/boringssl_ecdsa_utils.h
index f044d37..bcc32aa 100644
--- a/include/dice/boringssl_ecdsa_utils.h
+++ b/include/dice/boringssl_ecdsa_utils.h
@@ -24,6 +24,32 @@
 extern "C" {
 #endif
 
+#define P256_PRIVATE_KEY_SIZE 32
+#define P256_PUBLIC_KEY_SIZE 64
+#define P256_SIGNATURE_SIZE 64
+
+// Deterministically generates a public and private key pair from |seed|.
+// Since this is deterministic, |seed| is as sensitive as a private key and can
+// be used directly as the private key. The |private_key| may use an
+// implementation defined format so may only be passed to the |sign| operation.
+int P256KeypairFromSeed(uint8_t public_key[P256_PUBLIC_KEY_SIZE],
+                        uint8_t private_key[P256_PRIVATE_KEY_SIZE],
+                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]);
+
+// Calculates a signature of |message_size| bytes from |message| using
+// |private_key|. |private_key| was generated by |keypair_from_seed| to allow
+// an implementation to use their own private key format. |signature| points to
+// the buffer where the calculated signature is written.
+int P256Sign(uint8_t signature[P256_SIGNATURE_SIZE], const uint8_t* message,
+             size_t message_size,
+             const uint8_t private_key[P256_PRIVATE_KEY_SIZE]);
+
+// Verifies, using |public_key|, that |signature| covers |message_size| bytes
+// from |message|.
+int P256Verify(const uint8_t* message, size_t message_size,
+               const uint8_t signature[P256_SIGNATURE_SIZE],
+               const uint8_t public_key[P256_PUBLIC_KEY_SIZE]);
+
 #define P384_PRIVATE_KEY_SIZE 48
 #define P384_PUBLIC_KEY_SIZE 96
 #define P384_SIGNATURE_SIZE 96
diff --git a/include/dice/config/boringssl_ecdsa_p256/dice/config.h b/include/dice/config/boringssl_ecdsa_p256/dice/config.h
new file mode 100644
index 0000000..98045f7
--- /dev/null
+++ b/include/dice/config/boringssl_ecdsa_p256/dice/config.h
@@ -0,0 +1,26 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#ifndef DICE_CONFIG_BORINGSSL_ECDSA_P256_DICE_CONFIG_H_
+#define DICE_CONFIG_BORINGSSL_ECDSA_P256_DICE_CONFIG_H_
+
+// ECDSA P256
+// From table 1 of RFC 9053
+#define DICE_COSE_KEY_ALG_VALUE (-7)
+#define DICE_PUBLIC_KEY_SIZE 64
+#define DICE_PRIVATE_KEY_SIZE 32
+#define DICE_SIGNATURE_SIZE 64
+#define DICE_PROFILE_NAME "opendice.example.p256"
+
+#endif  // DICE_CONFIG_BORINGSSL_ECDSA_P256_DICE_DICE_CONFIG_H_
diff --git a/include/dice/config/mbedtls_ecdsa_p256/dice/config.h b/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
index 107e4d5..c5e23e1 100644
--- a/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
+++ b/include/dice/config/mbedtls_ecdsa_p256/dice/config.h
@@ -19,6 +19,6 @@
 #define DICE_PUBLIC_KEY_SIZE 33
 #define DICE_PRIVATE_KEY_SIZE 32
 #define DICE_SIGNATURE_SIZE 64
-#define DICE_PROFILE_NAME "openssl.example.p256"
+#define DICE_PROFILE_NAME "openssl.example.p256_compressed"
 
 #endif  // DICE_CONFIG_MBEDTLS_ECDSA_P256_DICE_DICE_CONFIG_H_
diff --git a/include/dice/known_test_values.h b/include/dice/known_test_values.h
index a74ed1d..3bf61cb 100644
--- a/include/dice/known_test_values.h
+++ b/include/dice/known_test_values.h
@@ -179,7 +179,7 @@ constexpr uint8_t kExpectedX509Ed25519Cert_ZeroInput[638] = {
 //             X509v3 Basic Constraints: critical
 //                 CA:TRUE
 //             1.3.6.1.4.1.11129.2.1.24: critical
-//     0:d=0  hl=3 l= 233 cons: SEQUENCE
+//     0:d=0  hl=3 l= 244 cons: SEQUENCE
 //     3:d=1  hl=2 l=  66 cons:  cont [ 0 ]
 //     5:d=2  hl=2 l=  64 prim:   OCTET STRING
 //       0000 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
@@ -200,17 +200,17 @@ constexpr uint8_t kExpectedX509Ed25519Cert_ZeroInput[638] = {
 //       0030 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
 //   207:d=1  hl=2 l=   3 cons:  cont [ 6 ]
 //   209:d=2  hl=2 l=   1 prim:   ENUMERATED        :00
-//   212:d=1  hl=2 l=  22 cons:  cont [ 7 ]
-//   214:d=2  hl=2 l=  20 prim:   UTF8STRING        :openssl.example.p256
+//   212:d=1  hl=2 l=  33 cons:  cont [ 7 ]
+//   214:d=2  hl=2 l=  31 prim:   UTF8STRING :openssl.example.p256_compressed
 //
 //     Signature Algorithm: ecdsa-with-SHA512
 //     Signature Value:
-//         30:46:02:21:00:a8:d1:e1:d1:7b:89:bf:a3:f1:8c:fa:43:fa:
-//         77:bf:83:ef:28:cb:54:d1:f5:29:e4:f3:05:99:e2:7a:d0:33:
-//         13:02:21:00:d7:9c:82:91:6b:a0:ca:70:48:76:03:95:1c:a4:
-//         6d:f0:44:ed:ba:02:2d:9a:e4:bf:f2:92:f6:78:ce:08:01:26
-constexpr uint8_t kExpectedX509P256Cert_ZeroInput[731] = {
-    0x30, 0x82, 0x02, 0xd7, 0x30, 0x82, 0x02, 0x7a, 0xa0, 0x03, 0x02, 0x01,
+//         30:45:02:21:00:a9:e5:96:e1:5a:8e:83:18:34:fa:11:71:fa:
+//         9c:81:a4:ff:3f:4e:54:aa:d4:f9:9e:32:08:66:84:24:8c:80:
+//         fd:02:20:5c:0a:57:e8:04:0e:16:12:4c:5d:1e:ef:17:b7:53:
+//         93:c6:21:d9:4e:aa:77:ba:cb:5d:2d:5f:98:96:9a:ea:e4
+constexpr uint8_t kExpectedX509P256Cert_ZeroInput[742] = {
+    0x30, 0x82, 0x02, 0xe2, 0x30, 0x82, 0x02, 0x86, 0xa0, 0x03, 0x02, 0x01,
     0x02, 0x02, 0x14, 0x7c, 0x7d, 0xc0, 0xa3, 0xc1, 0xe7, 0x8d, 0x4e, 0x68,
     0xbc, 0xc1, 0xa2, 0x32, 0x9e, 0xf9, 0x1c, 0xa8, 0x12, 0x44, 0x91, 0x30,
     0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05,
@@ -233,7 +233,7 @@ constexpr uint8_t kExpectedX509P256Cert_ZeroInput[731] = {
     0x06, 0x02, 0xae, 0xc2, 0x69, 0x54, 0x1c, 0x6b, 0xe7, 0xeb, 0x40, 0x19,
     0xab, 0x55, 0xc6, 0x6b, 0xc8, 0x8b, 0xb8, 0xb4, 0x69, 0xad, 0x7e, 0xe8,
     0x58, 0x9e, 0x07, 0xd2, 0xf8, 0xbc, 0x88, 0x8e, 0xb3, 0x11, 0xc2, 0xdf,
-    0x97, 0x3b, 0x1b, 0x4a, 0xa3, 0x82, 0x01, 0x66, 0x30, 0x82, 0x01, 0x62,
+    0x97, 0x3b, 0x1b, 0x4a, 0xa3, 0x82, 0x01, 0x72, 0x30, 0x82, 0x01, 0x6e,
     0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
     0x14, 0x4c, 0x51, 0x4d, 0x88, 0xdb, 0x0f, 0x81, 0xd5, 0x7b, 0xeb, 0x96,
     0x17, 0x7e, 0x3d, 0x7e, 0xa4, 0xaa, 0x58, 0x1e, 0x66, 0x30, 0x1d, 0x06,
@@ -242,35 +242,36 @@ constexpr uint8_t kExpectedX509P256Cert_ZeroInput[731] = {
     0xa8, 0x12, 0x44, 0x91, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
     0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0f, 0x06, 0x03,
     0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
-    0xff, 0x30, 0x81, 0xfe, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6,
-    0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x81, 0xec, 0x30, 0x81,
-    0xe9, 0xa0, 0x42, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0xff, 0x30, 0x82, 0x01, 0x09, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
+    0xd6, 0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x81, 0xf7, 0x30,
+    0x81, 0xf4, 0xa0, 0x42, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
-    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x42, 0x04,
-    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x42,
+    0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
-    0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x42, 0x04, 0x40, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x42, 0x04, 0x40, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
-    0x00, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x16, 0x0c, 0x14, 0x6f, 0x70,
-    0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
-    0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
-    0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00, 0x03, 0x49, 0x00, 0x30,
-    0x46, 0x02, 0x21, 0x00, 0xa8, 0xd1, 0xe1, 0xd1, 0x7b, 0x89, 0xbf, 0xa3,
-    0xf1, 0x8c, 0xfa, 0x43, 0xfa, 0x77, 0xbf, 0x83, 0xef, 0x28, 0xcb, 0x54,
-    0xd1, 0xf5, 0x29, 0xe4, 0xf3, 0x05, 0x99, 0xe2, 0x7a, 0xd0, 0x33, 0x13,
-    0x02, 0x21, 0x00, 0xd7, 0x9c, 0x82, 0x91, 0x6b, 0xa0, 0xca, 0x70, 0x48,
-    0x76, 0x03, 0x95, 0x1c, 0xa4, 0x6d, 0xf0, 0x44, 0xed, 0xba, 0x02, 0x2d,
-    0x9a, 0xe4, 0xbf, 0xf2, 0x92, 0xf6, 0x78, 0xce, 0x08, 0x01, 0x26};
+    0x00, 0x00, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x21, 0x0c, 0x1f, 0x6f,
+    0x70, 0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
+    0x6c, 0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x5f, 0x63, 0x6f, 0x6d, 0x70,
+    0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
+    0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30,
+    0x45, 0x02, 0x21, 0x00, 0xa9, 0xe5, 0x96, 0xe1, 0x5a, 0x8e, 0x83, 0x18,
+    0x34, 0xfa, 0x11, 0x71, 0xfa, 0x9c, 0x81, 0xa4, 0xff, 0x3f, 0x4e, 0x54,
+    0xaa, 0xd4, 0xf9, 0x9e, 0x32, 0x08, 0x66, 0x84, 0x24, 0x8c, 0x80, 0xfd,
+    0x02, 0x20, 0x5c, 0x0a, 0x57, 0xe8, 0x04, 0x0e, 0x16, 0x12, 0x4c, 0x5d,
+    0x1e, 0xef, 0x17, 0xb7, 0x53, 0x93, 0xc6, 0x21, 0xd9, 0x4e, 0xaa, 0x77,
+    0xba, 0xcb, 0x5d, 0x2d, 0x5f, 0x98, 0x96, 0x9a, 0xea, 0xe4};
 
 constexpr uint8_t kExpectedX509P384Cert_ZeroInput[0] = {};
 
@@ -313,7 +314,49 @@ constexpr uint8_t kExpectedCborEd25519Cert_ZeroInput[441] = {
     0x21, 0xec, 0xa3, 0xd3, 0x89, 0x7a, 0x24, 0x4d, 0xcb, 0xe1, 0x1a, 0x0f,
     0x9a, 0xb7, 0x9f, 0x67, 0x09, 0x3f, 0xee, 0x56, 0x0f};
 
-constexpr uint8_t kExpectedCborP256Cert_ZeroInput[0] = {};
+constexpr uint8_t kExpectedCborP256Cert_ZeroInput[503] = {
+    0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0xac, 0xa9, 0x01, 0x78,
+    0x28, 0x36, 0x37, 0x32, 0x64, 0x30, 0x30, 0x35, 0x33, 0x61, 0x65, 0x34,
+    0x35, 0x31, 0x33, 0x66, 0x62, 0x62, 0x33, 0x62, 0x61, 0x63, 0x38, 0x32,
+    0x30, 0x39, 0x64, 0x61, 0x65, 0x62, 0x33, 0x65, 0x38, 0x38, 0x39, 0x37,
+    0x36, 0x38, 0x31, 0x63, 0x64, 0x02, 0x78, 0x28, 0x32, 0x65, 0x37, 0x35,
+    0x62, 0x36, 0x65, 0x37, 0x32, 0x33, 0x30, 0x63, 0x32, 0x30, 0x66, 0x32,
+    0x39, 0x36, 0x30, 0x62, 0x64, 0x65, 0x34, 0x61, 0x63, 0x66, 0x31, 0x32,
+    0x38, 0x38, 0x64, 0x34, 0x61, 0x62, 0x36, 0x36, 0x35, 0x62, 0x39, 0x62,
+    0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a,
+    0x00, 0x47, 0x44, 0x53, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00,
+    0x47, 0x44, 0x54, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x47,
+    0x44, 0x56, 0x41, 0x00, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x50, 0xa6,
+    0x01, 0x02, 0x03, 0x26, 0x04, 0x81, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20,
+    0x4f, 0x3b, 0x4e, 0x82, 0xc4, 0x5a, 0xda, 0x08, 0x45, 0x89, 0xc2, 0x19,
+    0x7b, 0xaf, 0x1f, 0x37, 0x6e, 0xac, 0x40, 0xe1, 0xfd, 0x49, 0xb0, 0x24,
+    0x06, 0x02, 0xae, 0xc2, 0x69, 0x54, 0x1c, 0x6b, 0x22, 0x58, 0x20, 0xe7,
+    0xeb, 0x40, 0x19, 0xab, 0x55, 0xc6, 0x6b, 0xc8, 0x8b, 0xb8, 0xb4, 0x69,
+    0xad, 0x7e, 0xe8, 0x58, 0x9e, 0x07, 0xd2, 0xf8, 0xbc, 0x88, 0x8e, 0xb3,
+    0x11, 0xc2, 0xdf, 0x97, 0x3b, 0x1b, 0x4a, 0x3a, 0x00, 0x47, 0x44, 0x58,
+    0x41, 0x20, 0x3a, 0x00, 0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e,
+    0x64, 0x69, 0x63, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
+    0x2e, 0x70, 0x32, 0x35, 0x36, 0x58, 0x40, 0x63, 0xb5, 0x32, 0x12, 0x4a,
+    0x18, 0xf5, 0xa8, 0xf0, 0x67, 0x3e, 0x76, 0x46, 0xa5, 0xb6, 0xb8, 0xbf,
+    0xfe, 0xa2, 0xeb, 0x6f, 0x4d, 0x5f, 0x18, 0x69, 0x03, 0xc6, 0x31, 0xce,
+    0xeb, 0xae, 0xcd, 0xca, 0x93, 0x31, 0x51, 0x51, 0xcf, 0x05, 0xb6, 0x7e,
+    0x87, 0x91, 0xd0, 0x5b, 0x88, 0xf5, 0xe3, 0x93, 0xf7, 0xba, 0xd5, 0xd7,
+    0x07, 0xe3, 0xe6, 0x3f, 0xcb, 0xf6, 0x24, 0xd2, 0xf6, 0xc1, 0x5c};
 
 constexpr uint8_t kExpectedCborP384Cert_ZeroInput[569] = {
     0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x01, 0xcd, 0xa9, 0x01,
@@ -355,15 +398,15 @@ constexpr uint8_t kExpectedCborP384Cert_ZeroInput[569] = {
     0x05, 0xb5, 0x29, 0xa0, 0xf1, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20,
     0x3a, 0x00, 0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e, 0x64, 0x69,
     0x63, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70,
-    0x33, 0x38, 0x34, 0x58, 0x60, 0x19, 0x40, 0xb7, 0x32, 0x81, 0xdd, 0x03,
-    0x7b, 0x0f, 0x35, 0xd2, 0x5a, 0x01, 0x85, 0x5b, 0xbc, 0xea, 0xb4, 0x0d,
-    0x83, 0xec, 0x6a, 0x33, 0x6d, 0x2d, 0xa0, 0x7d, 0xa6, 0x2e, 0xe8, 0x64,
-    0xdc, 0x51, 0x71, 0xa0, 0x76, 0x3e, 0x5b, 0x4e, 0xee, 0x4a, 0xa1, 0x1a,
-    0xd2, 0xd4, 0xaf, 0x38, 0x86, 0xa7, 0xd8, 0x62, 0xce, 0x55, 0xdc, 0x14,
-    0x8c, 0x08, 0xda, 0xcb, 0x0a, 0x82, 0x1f, 0x89, 0x6e, 0x75, 0x08, 0xa1,
-    0x14, 0xe8, 0x74, 0xdf, 0xf9, 0x01, 0x6b, 0x1b, 0x69, 0xb5, 0xba, 0x6e,
-    0xec, 0x4b, 0x27, 0x04, 0xcf, 0xff, 0x5f, 0x07, 0xbe, 0x60, 0xf2, 0x8d,
-    0x07, 0x4a, 0xe6, 0xa1, 0xa3};
+    0x33, 0x38, 0x34, 0x58, 0x60, 0x15, 0x22, 0x2f, 0x02, 0xdd, 0x28, 0x07,
+    0x9a, 0x90, 0xcf, 0xae, 0x29, 0x76, 0x81, 0x14, 0xc3, 0xf2, 0x06, 0x13,
+    0x01, 0xe1, 0x5f, 0x6e, 0xb1, 0x1d, 0x1f, 0x7a, 0xcd, 0x3f, 0xf5, 0xf9,
+    0x87, 0x4d, 0x78, 0x6e, 0xa5, 0xff, 0x86, 0xb2, 0x1e, 0x0c, 0x8b, 0xd2,
+    0x26, 0x20, 0x02, 0xe1, 0x65, 0x8b, 0x91, 0x8f, 0x29, 0x97, 0xdb, 0x4b,
+    0x05, 0xa7, 0xe3, 0xc7, 0x97, 0x8e, 0x42, 0xe5, 0xbe, 0x44, 0xdd, 0xff,
+    0xed, 0xf9, 0x70, 0xa3, 0xec, 0x64, 0xe4, 0xb9, 0x1d, 0x2b, 0xe0, 0xe9,
+    0x29, 0xa3, 0x1d, 0xf5, 0x79, 0xd0, 0x1c, 0x3a, 0x26, 0xbc, 0xb2, 0xf9,
+    0xd9, 0xcd, 0x59, 0xd9, 0xc1};
 
 constexpr uint8_t kExpectedCdiAttest_HashOnlyInput[32] = {
     0x08, 0x4e, 0xf4, 0x06, 0xc6, 0x9b, 0xa7, 0x4b, 0x1e, 0x24, 0xd0,
@@ -521,7 +564,7 @@ constexpr uint8_t kExpectedX509Ed25519Cert_HashOnlyInput[638] = {
 //             X509v3 Basic Constraints: critical
 //                 CA:TRUE
 //             1.3.6.1.4.1.11129.2.1.24: critical
-//     0:d=0  hl=3 l= 233 cons: SEQUENCE
+//     0:d=0  hl=3 l= 244 cons: SEQUENCE
 //     3:d=1  hl=2 l=  66 cons:  cont [ 0 ]
 //     5:d=2  hl=2 l=  64 prim:   OCTET STRING
 //       0000 - b7 d4 0c cb 22 5b a5 78-8f 98 ff 9e 86 93 75 f6 ...."[.x......u.
@@ -542,17 +585,17 @@ constexpr uint8_t kExpectedX509Ed25519Cert_HashOnlyInput[638] = {
 //       0030 - 94 4f be 1b 21 f9 cc 23-73 41 b6 b9 b6 98 d0 bc .O..!..#sA......
 //   207:d=1  hl=2 l=   3 cons:  cont [ 6 ]
 //   209:d=2  hl=2 l=   1 prim:   ENUMERATED        :00
-//   212:d=1  hl=2 l=  22 cons:  cont [ 7 ]
-//   214:d=2  hl=2 l=  20 prim:   UTF8STRING        :openssl.example.p256
+//   212:d=1  hl=2 l=  33 cons:  cont [ 7 ]
+//   214:d=2  hl=2 l=  31 prim:   UTF8STRING :openssl.example.p256_compressed
 //
 //     Signature Algorithm: ecdsa-with-SHA512
 //     Signature Value:
-//         30:44:02:20:2a:d1:3e:6f:ee:42:e2:d0:64:b8:1c:bd:de:fe:
-//         49:2f:2e:4f:80:3c:66:52:05:95:2a:d9:87:7a:6d:47:44:bf:
-//         02:20:6e:1c:5a:a0:62:00:17:61:f9:c3:93:17:72:1a:ce:28:
-//         3d:c7:7d:35:22:de:b3:d6:3d:b2:6e:75:c9:f0:c1:73
-constexpr uint8_t kExpectedX509P256Cert_HashOnlyInput[729] = {
-    0x30, 0x82, 0x02, 0xd5, 0x30, 0x82, 0x02, 0x7a, 0xa0, 0x03, 0x02, 0x01,
+//         30:44:02:20:4f:9c:d7:7d:76:9c:02:41:46:f4:8a:9c:38:0c:
+//         77:32:c5:08:cc:a9:53:70:99:f7:15:68:4c:3b:22:4f:df:d1:
+//         02:20:19:ad:a1:53:1f:7d:6e:4a:70:32:9f:7d:2e:3b:be:f4:
+//         c8:f0:9a:31:6d:4b:3e:32:eb:db:8e:fc:cd:28:8b:1f
+constexpr uint8_t kExpectedX509P256Cert_HashOnlyInput[741] = {
+    0x30, 0x82, 0x02, 0xe1, 0x30, 0x82, 0x02, 0x86, 0xa0, 0x03, 0x02, 0x01,
     0x02, 0x02, 0x14, 0x68, 0x49, 0x58, 0xd9, 0xae, 0xa7, 0x2e, 0xbf, 0x7c,
     0x06, 0xaf, 0x20, 0x03, 0xb6, 0x44, 0x47, 0x82, 0x4a, 0x62, 0x71, 0x30,
     0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05,
@@ -575,7 +618,7 @@ constexpr uint8_t kExpectedX509P256Cert_HashOnlyInput[729] = {
     0xfb, 0x6d, 0x57, 0x18, 0xfc, 0x8f, 0x6f, 0x0b, 0x09, 0x1a, 0x19, 0xea,
     0x10, 0x7e, 0xa9, 0x38, 0xf4, 0x45, 0x33, 0xc1, 0x66, 0x5b, 0xbc, 0xfc,
     0x0a, 0x6e, 0x98, 0x99, 0x72, 0x88, 0xc1, 0xad, 0x0e, 0x15, 0xc2, 0x85,
-    0x77, 0x75, 0x00, 0x0b, 0xa3, 0x82, 0x01, 0x66, 0x30, 0x82, 0x01, 0x62,
+    0x77, 0x75, 0x00, 0x0b, 0xa3, 0x82, 0x01, 0x72, 0x30, 0x82, 0x01, 0x6e,
     0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
     0x14, 0x1b, 0xe5, 0x68, 0x79, 0x33, 0xdb, 0x3d, 0x9c, 0xd5, 0xfc, 0xa7,
     0x29, 0xe8, 0x1d, 0x66, 0x85, 0x46, 0x5a, 0x7b, 0xf1, 0x30, 0x1d, 0x06,
@@ -584,35 +627,36 @@ constexpr uint8_t kExpectedX509P256Cert_HashOnlyInput[729] = {
     0x82, 0x4a, 0x62, 0x71, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
     0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0f, 0x06, 0x03,
     0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
-    0xff, 0x30, 0x81, 0xfe, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6,
-    0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x81, 0xec, 0x30, 0x81,
-    0xe9, 0xa0, 0x42, 0x04, 0x40, 0xb7, 0xd4, 0x0c, 0xcb, 0x22, 0x5b, 0xa5,
-    0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6, 0x90, 0xac, 0x50,
-    0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e, 0x52, 0x19, 0xe4,
-    0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40, 0x87, 0x7a, 0xdd,
-    0x17, 0x48, 0x05, 0x89, 0x7e, 0x2b, 0xcb, 0x54, 0x79, 0xcc, 0x66, 0xf1,
-    0xb3, 0x13, 0x29, 0x0c, 0x68, 0x96, 0xb2, 0xbb, 0x8f, 0xa3, 0x42, 0x04,
-    0x40, 0xcf, 0x99, 0x7b, 0xea, 0x2e, 0x2c, 0x86, 0xa0, 0x7b, 0x52, 0x09,
-    0xc8, 0xb5, 0x3c, 0x41, 0x12, 0x29, 0x28, 0x1a, 0x82, 0x0d, 0x49, 0x9c,
-    0x95, 0xcb, 0x0b, 0x1b, 0x31, 0x1a, 0x01, 0x9c, 0xf2, 0x66, 0x1a, 0xd9,
-    0xb5, 0xce, 0x52, 0x59, 0xcb, 0xf4, 0x81, 0x9b, 0x21, 0xaf, 0x32, 0x5d,
-    0x07, 0xa0, 0x1e, 0x91, 0x59, 0x6f, 0x06, 0x55, 0x10, 0x8e, 0x2e, 0x08,
-    0x88, 0x52, 0x28, 0x86, 0x7f, 0xa4, 0x42, 0x04, 0x40, 0x22, 0x52, 0x60,
-    0x17, 0xef, 0x2c, 0xa1, 0xf6, 0xcb, 0xed, 0x39, 0xd5, 0xe2, 0xaa, 0x65,
-    0x20, 0xfb, 0xad, 0x82, 0x93, 0xe5, 0x78, 0x23, 0x22, 0x97, 0xc1, 0x6e,
-    0x6a, 0x4e, 0x36, 0xd7, 0x6a, 0x61, 0x39, 0x08, 0x21, 0xd4, 0xfe, 0x92,
-    0x5f, 0x36, 0x2d, 0xeb, 0x5d, 0xbb, 0x32, 0x8b, 0xe3, 0x94, 0x4f, 0xbe,
-    0x1b, 0x21, 0xf9, 0xcc, 0x23, 0x73, 0x41, 0xb6, 0xb9, 0xb6, 0x98, 0xd0,
-    0xbc, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x16, 0x0c, 0x14, 0x6f, 0x70,
-    0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
-    0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
+    0xff, 0x30, 0x82, 0x01, 0x09, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
+    0xd6, 0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x81, 0xf7, 0x30,
+    0x81, 0xf4, 0xa0, 0x42, 0x04, 0x40, 0xb7, 0xd4, 0x0c, 0xcb, 0x22, 0x5b,
+    0xa5, 0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6, 0x90, 0xac,
+    0x50, 0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e, 0x52, 0x19,
+    0xe4, 0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40, 0x87, 0x7a,
+    0xdd, 0x17, 0x48, 0x05, 0x89, 0x7e, 0x2b, 0xcb, 0x54, 0x79, 0xcc, 0x66,
+    0xf1, 0xb3, 0x13, 0x29, 0x0c, 0x68, 0x96, 0xb2, 0xbb, 0x8f, 0xa3, 0x42,
+    0x04, 0x40, 0xcf, 0x99, 0x7b, 0xea, 0x2e, 0x2c, 0x86, 0xa0, 0x7b, 0x52,
+    0x09, 0xc8, 0xb5, 0x3c, 0x41, 0x12, 0x29, 0x28, 0x1a, 0x82, 0x0d, 0x49,
+    0x9c, 0x95, 0xcb, 0x0b, 0x1b, 0x31, 0x1a, 0x01, 0x9c, 0xf2, 0x66, 0x1a,
+    0xd9, 0xb5, 0xce, 0x52, 0x59, 0xcb, 0xf4, 0x81, 0x9b, 0x21, 0xaf, 0x32,
+    0x5d, 0x07, 0xa0, 0x1e, 0x91, 0x59, 0x6f, 0x06, 0x55, 0x10, 0x8e, 0x2e,
+    0x08, 0x88, 0x52, 0x28, 0x86, 0x7f, 0xa4, 0x42, 0x04, 0x40, 0x22, 0x52,
+    0x60, 0x17, 0xef, 0x2c, 0xa1, 0xf6, 0xcb, 0xed, 0x39, 0xd5, 0xe2, 0xaa,
+    0x65, 0x20, 0xfb, 0xad, 0x82, 0x93, 0xe5, 0x78, 0x23, 0x22, 0x97, 0xc1,
+    0x6e, 0x6a, 0x4e, 0x36, 0xd7, 0x6a, 0x61, 0x39, 0x08, 0x21, 0xd4, 0xfe,
+    0x92, 0x5f, 0x36, 0x2d, 0xeb, 0x5d, 0xbb, 0x32, 0x8b, 0xe3, 0x94, 0x4f,
+    0xbe, 0x1b, 0x21, 0xf9, 0xcc, 0x23, 0x73, 0x41, 0xb6, 0xb9, 0xb6, 0x98,
+    0xd0, 0xbc, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x21, 0x0c, 0x1f, 0x6f,
+    0x70, 0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
+    0x6c, 0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x5f, 0x63, 0x6f, 0x6d, 0x70,
+    0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
     0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00, 0x03, 0x47, 0x00, 0x30,
-    0x44, 0x02, 0x20, 0x2a, 0xd1, 0x3e, 0x6f, 0xee, 0x42, 0xe2, 0xd0, 0x64,
-    0xb8, 0x1c, 0xbd, 0xde, 0xfe, 0x49, 0x2f, 0x2e, 0x4f, 0x80, 0x3c, 0x66,
-    0x52, 0x05, 0x95, 0x2a, 0xd9, 0x87, 0x7a, 0x6d, 0x47, 0x44, 0xbf, 0x02,
-    0x20, 0x6e, 0x1c, 0x5a, 0xa0, 0x62, 0x00, 0x17, 0x61, 0xf9, 0xc3, 0x93,
-    0x17, 0x72, 0x1a, 0xce, 0x28, 0x3d, 0xc7, 0x7d, 0x35, 0x22, 0xde, 0xb3,
-    0xd6, 0x3d, 0xb2, 0x6e, 0x75, 0xc9, 0xf0, 0xc1, 0x73};
+    0x44, 0x02, 0x20, 0x4f, 0x9c, 0xd7, 0x7d, 0x76, 0x9c, 0x02, 0x41, 0x46,
+    0xf4, 0x8a, 0x9c, 0x38, 0x0c, 0x77, 0x32, 0xc5, 0x08, 0xcc, 0xa9, 0x53,
+    0x70, 0x99, 0xf7, 0x15, 0x68, 0x4c, 0x3b, 0x22, 0x4f, 0xdf, 0xd1, 0x02,
+    0x20, 0x19, 0xad, 0xa1, 0x53, 0x1f, 0x7d, 0x6e, 0x4a, 0x70, 0x32, 0x9f,
+    0x7d, 0x2e, 0x3b, 0xbe, 0xf4, 0xc8, 0xf0, 0x9a, 0x31, 0x6d, 0x4b, 0x3e,
+    0x32, 0xeb, 0xdb, 0x8e, 0xfc, 0xcd, 0x28, 0x8b, 0x1f};
 
 constexpr uint8_t kExpectedX509P384Cert_HashOnlyInput[0] = {};
 
@@ -655,7 +699,49 @@ constexpr uint8_t kExpectedCborEd25519Cert_HashOnlyInput[441] = {
     0xb6, 0x71, 0xc7, 0x76, 0x64, 0x25, 0xfb, 0x03, 0xcf, 0xd6, 0x6f, 0x2f,
     0x9a, 0x15, 0xc8, 0xad, 0x47, 0x9a, 0xf3, 0x16, 0x01};
 
-constexpr uint8_t kExpectedCborP256Cert_HashOnlyInput[0] = {};
+constexpr uint8_t kExpectedCborP256Cert_HashOnlyInput[503] = {
+    0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0xac, 0xa9, 0x01, 0x78,
+    0x28, 0x34, 0x38, 0x36, 0x30, 0x33, 0x63, 0x30, 0x30, 0x35, 0x32, 0x63,
+    0x31, 0x63, 0x61, 0x63, 0x37, 0x33, 0x63, 0x61, 0x65, 0x33, 0x36, 0x63,
+    0x33, 0x62, 0x64, 0x65, 0x63, 0x37, 0x63, 0x36, 0x31, 0x33, 0x39, 0x38,
+    0x38, 0x35, 0x63, 0x39, 0x64, 0x02, 0x78, 0x28, 0x37, 0x63, 0x32, 0x30,
+    0x30, 0x61, 0x35, 0x35, 0x65, 0x66, 0x65, 0x37, 0x31, 0x31, 0x32, 0x65,
+    0x63, 0x61, 0x34, 0x65, 0x30, 0x32, 0x36, 0x64, 0x37, 0x30, 0x32, 0x63,
+    0x36, 0x34, 0x65, 0x39, 0x65, 0x32, 0x39, 0x63, 0x64, 0x33, 0x65, 0x39,
+    0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0xb7, 0xd4, 0x0c, 0xcb, 0x22,
+    0x5b, 0xa5, 0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6, 0x90,
+    0xac, 0x50, 0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e, 0x52,
+    0x19, 0xe4, 0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40, 0x87,
+    0x7a, 0xdd, 0x17, 0x48, 0x05, 0x89, 0x7e, 0x2b, 0xcb, 0x54, 0x79, 0xcc,
+    0x66, 0xf1, 0xb3, 0x13, 0x29, 0x0c, 0x68, 0x96, 0xb2, 0xbb, 0x8f, 0x3a,
+    0x00, 0x47, 0x44, 0x53, 0x58, 0x40, 0xcf, 0x99, 0x7b, 0xea, 0x2e, 0x2c,
+    0x86, 0xa0, 0x7b, 0x52, 0x09, 0xc8, 0xb5, 0x3c, 0x41, 0x12, 0x29, 0x28,
+    0x1a, 0x82, 0x0d, 0x49, 0x9c, 0x95, 0xcb, 0x0b, 0x1b, 0x31, 0x1a, 0x01,
+    0x9c, 0xf2, 0x66, 0x1a, 0xd9, 0xb5, 0xce, 0x52, 0x59, 0xcb, 0xf4, 0x81,
+    0x9b, 0x21, 0xaf, 0x32, 0x5d, 0x07, 0xa0, 0x1e, 0x91, 0x59, 0x6f, 0x06,
+    0x55, 0x10, 0x8e, 0x2e, 0x08, 0x88, 0x52, 0x28, 0x86, 0x7f, 0x3a, 0x00,
+    0x47, 0x44, 0x54, 0x58, 0x40, 0x22, 0x52, 0x60, 0x17, 0xef, 0x2c, 0xa1,
+    0xf6, 0xcb, 0xed, 0x39, 0xd5, 0xe2, 0xaa, 0x65, 0x20, 0xfb, 0xad, 0x82,
+    0x93, 0xe5, 0x78, 0x23, 0x22, 0x97, 0xc1, 0x6e, 0x6a, 0x4e, 0x36, 0xd7,
+    0x6a, 0x61, 0x39, 0x08, 0x21, 0xd4, 0xfe, 0x92, 0x5f, 0x36, 0x2d, 0xeb,
+    0x5d, 0xbb, 0x32, 0x8b, 0xe3, 0x94, 0x4f, 0xbe, 0x1b, 0x21, 0xf9, 0xcc,
+    0x23, 0x73, 0x41, 0xb6, 0xb9, 0xb6, 0x98, 0xd0, 0xbc, 0x3a, 0x00, 0x47,
+    0x44, 0x56, 0x41, 0x00, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x50, 0xa6,
+    0x01, 0x02, 0x03, 0x26, 0x04, 0x81, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20,
+    0xfe, 0x9d, 0xb2, 0xf9, 0x28, 0x09, 0xc3, 0x04, 0x12, 0x85, 0xdc, 0xd3,
+    0x70, 0x6f, 0x22, 0x1c, 0x72, 0xb6, 0xc4, 0x4f, 0xde, 0x93, 0xee, 0xfd,
+    0xfb, 0x6d, 0x57, 0x18, 0xfc, 0x8f, 0x6f, 0x0b, 0x22, 0x58, 0x20, 0x09,
+    0x1a, 0x19, 0xea, 0x10, 0x7e, 0xa9, 0x38, 0xf4, 0x45, 0x33, 0xc1, 0x66,
+    0x5b, 0xbc, 0xfc, 0x0a, 0x6e, 0x98, 0x99, 0x72, 0x88, 0xc1, 0xad, 0x0e,
+    0x15, 0xc2, 0x85, 0x77, 0x75, 0x00, 0x0b, 0x3a, 0x00, 0x47, 0x44, 0x58,
+    0x41, 0x20, 0x3a, 0x00, 0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e,
+    0x64, 0x69, 0x63, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
+    0x2e, 0x70, 0x32, 0x35, 0x36, 0x58, 0x40, 0x9f, 0xc7, 0x0a, 0x63, 0x96,
+    0x61, 0xc1, 0x7a, 0x55, 0x52, 0x76, 0x30, 0xc7, 0xe1, 0xb9, 0x92, 0x21,
+    0x43, 0x7e, 0x46, 0xf1, 0x45, 0xba, 0xf3, 0xb5, 0x99, 0xe7, 0x8b, 0x64,
+    0x58, 0x1d, 0x5c, 0x49, 0xc7, 0x9e, 0x1d, 0xb2, 0x0c, 0xb1, 0xd3, 0x81,
+    0x43, 0x6a, 0x2d, 0x13, 0xcb, 0xf8, 0x45, 0x1d, 0xe7, 0x76, 0xed, 0xba,
+    0x1a, 0x09, 0x28, 0xe6, 0xd0, 0x23, 0x81, 0x9e, 0xd8, 0xb9, 0x8f};
 
 constexpr uint8_t kExpectedCborP384Cert_HashOnlyInput[569] = {
     0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x01, 0xcd, 0xa9, 0x01,
@@ -697,15 +783,15 @@ constexpr uint8_t kExpectedCborP384Cert_HashOnlyInput[569] = {
     0xc3, 0xb2, 0xe7, 0x34, 0xf5, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20,
     0x3a, 0x00, 0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e, 0x64, 0x69,
     0x63, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70,
-    0x33, 0x38, 0x34, 0x58, 0x60, 0x08, 0x82, 0x40, 0x67, 0xcb, 0x0b, 0x5d,
-    0x98, 0x3b, 0x7b, 0xf0, 0x9c, 0x5f, 0x32, 0x47, 0xb4, 0x5d, 0xb9, 0x7a,
-    0xce, 0x1c, 0x55, 0x35, 0xc2, 0x18, 0x2d, 0xcb, 0x4b, 0xc1, 0xa7, 0xd2,
-    0xfa, 0x1e, 0x17, 0xa9, 0x61, 0xd5, 0x2a, 0x9f, 0x8c, 0x8e, 0x72, 0xc7,
-    0x60, 0x2e, 0x11, 0x59, 0x3a, 0xe9, 0x7d, 0x90, 0x00, 0x03, 0x67, 0xb7,
-    0x17, 0xc1, 0x95, 0x07, 0x04, 0xec, 0x81, 0x11, 0x21, 0x19, 0x4b, 0x22,
-    0x35, 0xbe, 0x93, 0xc8, 0xb8, 0x78, 0xb5, 0x16, 0xb9, 0x6e, 0x7b, 0xf6,
-    0x50, 0xe8, 0xf4, 0x81, 0xc2, 0xf4, 0x1c, 0x4b, 0xe2, 0x8d, 0x9d, 0x80,
-    0xcb, 0x34, 0x15, 0xc5, 0x63};
+    0x33, 0x38, 0x34, 0x58, 0x60, 0x88, 0xa1, 0x0e, 0xbc, 0x51, 0xfb, 0x22,
+    0x0c, 0x05, 0x67, 0x56, 0x39, 0x8c, 0xdb, 0x8e, 0x3f, 0x1b, 0x2c, 0x8c,
+    0x67, 0x49, 0x85, 0xc3, 0x9b, 0x33, 0x0f, 0x2b, 0x5e, 0x99, 0x65, 0x0d,
+    0x7b, 0xa4, 0x8e, 0xcd, 0x4a, 0xd0, 0x3c, 0x81, 0x9d, 0x34, 0xc5, 0x0a,
+    0x4f, 0xab, 0xeb, 0xc8, 0xe6, 0xb9, 0x2e, 0x09, 0x64, 0xdc, 0xa1, 0xc5,
+    0x19, 0x1a, 0xf2, 0x1c, 0xc2, 0xc7, 0x02, 0xb3, 0x93, 0xac, 0x8c, 0x61,
+    0x7d, 0x4d, 0xcf, 0xc3, 0x1b, 0x06, 0x0e, 0x7f, 0x03, 0x71, 0x79, 0x21,
+    0x4c, 0x46, 0xd5, 0x77, 0xe9, 0xd2, 0x5e, 0xa8, 0xe4, 0x71, 0xfc, 0x6d,
+    0xa1, 0xf6, 0x12, 0xab, 0x40};
 
 constexpr uint8_t kExpectedCdiAttest_DescriptorInput[32] = {
     0x20, 0xd5, 0x0c, 0x68, 0x5a, 0xd9, 0xe2, 0xdf, 0x77, 0x60, 0x78,
@@ -902,7 +988,7 @@ constexpr uint8_t kExpectedX509Ed25519Cert_DescriptorInput[858] = {
 //             X509v3 Basic Constraints: critical
 //                 CA:TRUE
 //             1.3.6.1.4.1.11129.2.1.24: critical
-//     0:d=0  hl=4 l= 450 cons: SEQUENCE
+//     0:d=0  hl=4 l= 461 cons: SEQUENCE
 //     4:d=1  hl=2 l=  66 cons:  cont [ 0 ]
 //     6:d=2  hl=2 l=  64 prim:   OCTET STRING
 //       0000 - b7 d4 0c cb 22 5b a5 78-8f 98 ff 9e 86 93 75 f6 ...."[.x......u.
@@ -944,17 +1030,17 @@ constexpr uint8_t kExpectedX509Ed25519Cert_DescriptorInput[858] = {
 //       0040 - a2                                                .
 //   425:d=1  hl=2 l=   3 cons:  cont [ 6 ]
 //   427:d=2  hl=2 l=   1 prim:   ENUMERATED        :00
-//   430:d=1  hl=2 l=  22 cons:  cont [ 7 ]
-//   432:d=2  hl=2 l=  20 prim:   UTF8STRING        :openssl.example.p256
+//   430:d=1  hl=2 l=  33 cons:  cont [ 7 ]
+//   432:d=2  hl=2 l=  31 prim:   UTF8STRING :openssl.example.p256_compressed
 //
 //     Signature Algorithm: ecdsa-with-SHA512
 //     Signature Value:
-//         30:45:02:20:4f:55:9a:0c:2a:48:d5:51:fe:a1:b9:40:e7:95:
-//         97:d0:48:0a:de:71:bf:aa:19:5f:51:3d:d9:4c:df:a8:69:a8:
-//         02:21:00:d4:8c:28:58:8e:3c:4e:b6:98:76:24:2b:92:c5:8c:
-//         42:8c:88:a7:58:35:3d:b5:0e:18:a5:6f:2d:d3:0c:4c:33
-constexpr uint8_t kExpectedX509P256Cert_DescriptorInput[950] = {
-    0x30, 0x82, 0x03, 0xb2, 0x30, 0x82, 0x03, 0x56, 0xa0, 0x03, 0x02, 0x01,
+//         30:44:02:20:1e:7d:b6:7e:85:4a:20:fc:61:a8:b8:73:40:a0:
+//         c2:5f:a5:3f:06:07:0a:1c:26:82:a0:5c:d5:b9:58:f5:e5:b0:
+//         02:20:46:61:2d:29:ee:a7:b6:ad:c4:0d:c6:b2:76:f2:5a:88:
+//         c1:bd:8e:dd:5e:bd:c7:1d:b3:c3:2d:84:4b:f6:ce:7f
+constexpr uint8_t kExpectedX509P256Cert_DescriptorInput[960] = {
+    0x30, 0x82, 0x03, 0xbc, 0x30, 0x82, 0x03, 0x61, 0xa0, 0x03, 0x02, 0x01,
     0x02, 0x02, 0x14, 0x2c, 0x0d, 0xe9, 0x55, 0xc4, 0xfa, 0x08, 0x2c, 0x2c,
     0x3a, 0x0b, 0x40, 0x66, 0x59, 0xaf, 0xa1, 0xc1, 0xc0, 0x84, 0x6c, 0x30,
     0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05,
@@ -977,7 +1063,7 @@ constexpr uint8_t kExpectedX509P256Cert_DescriptorInput[950] = {
     0x9b, 0x27, 0xf3, 0x87, 0x97, 0xb3, 0xe7, 0x36, 0xe6, 0x42, 0x87, 0x8c,
     0x72, 0xde, 0xf7, 0xaf, 0x2d, 0xc6, 0x23, 0x00, 0xb1, 0x2b, 0x4e, 0x1c,
     0xf3, 0xaf, 0x67, 0xf0, 0x9b, 0x88, 0x40, 0x79, 0x3b, 0x09, 0x78, 0x30,
-    0x51, 0x65, 0x38, 0x61, 0xa3, 0x82, 0x02, 0x42, 0x30, 0x82, 0x02, 0x3e,
+    0x51, 0x65, 0x38, 0x61, 0xa3, 0x82, 0x02, 0x4d, 0x30, 0x82, 0x02, 0x49,
     0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
     0x14, 0x1b, 0xe5, 0x68, 0x79, 0x33, 0xdb, 0x3d, 0x9c, 0xd5, 0xfc, 0xa7,
     0x29, 0xe8, 0x1d, 0x66, 0x85, 0x46, 0x5a, 0x7b, 0xf1, 0x30, 0x1d, 0x06,
@@ -986,9 +1072,9 @@ constexpr uint8_t kExpectedX509P256Cert_DescriptorInput[950] = {
     0xc1, 0xc0, 0x84, 0x6c, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
     0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0f, 0x06, 0x03,
     0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
-    0xff, 0x30, 0x82, 0x01, 0xd9, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
-    0xd6, 0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x82, 0x01, 0xc6,
-    0x30, 0x82, 0x01, 0xc2, 0xa0, 0x42, 0x04, 0x40, 0xb7, 0xd4, 0x0c, 0xcb,
+    0xff, 0x30, 0x82, 0x01, 0xe4, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
+    0xd6, 0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04, 0x82, 0x01, 0xd1,
+    0x30, 0x82, 0x01, 0xcd, 0xa0, 0x42, 0x04, 0x40, 0xb7, 0xd4, 0x0c, 0xcb,
     0x22, 0x5b, 0xa5, 0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6,
     0x90, 0xac, 0x50, 0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e,
     0x52, 0x19, 0xe4, 0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40,
@@ -1023,17 +1109,17 @@ constexpr uint8_t kExpectedX509P256Cert_DescriptorInput[950] = {
     0x11, 0x2d, 0x08, 0x4d, 0x7c, 0x39, 0x76, 0xdc, 0x73, 0xe7, 0x1c, 0x16,
     0x62, 0xd5, 0x59, 0xd7, 0x49, 0x2b, 0x6a, 0xa2, 0x36, 0x67, 0x57, 0xd1,
     0xf2, 0xf9, 0xaf, 0x13, 0xd7, 0xa3, 0xe4, 0xd3, 0x39, 0x5b, 0x02, 0x78,
-    0xb1, 0xe0, 0x09, 0x70, 0xa2, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x16,
-    0x0c, 0x14, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78,
-    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x30, 0x0c,
-    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00,
-    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x4f, 0x55, 0x9a, 0x0c, 0x2a,
-    0x48, 0xd5, 0x51, 0xfe, 0xa1, 0xb9, 0x40, 0xe7, 0x95, 0x97, 0xd0, 0x48,
-    0x0a, 0xde, 0x71, 0xbf, 0xaa, 0x19, 0x5f, 0x51, 0x3d, 0xd9, 0x4c, 0xdf,
-    0xa8, 0x69, 0xa8, 0x02, 0x21, 0x00, 0xd4, 0x8c, 0x28, 0x58, 0x8e, 0x3c,
-    0x4e, 0xb6, 0x98, 0x76, 0x24, 0x2b, 0x92, 0xc5, 0x8c, 0x42, 0x8c, 0x88,
-    0xa7, 0x58, 0x35, 0x3d, 0xb5, 0x0e, 0x18, 0xa5, 0x6f, 0x2d, 0xd3, 0x0c,
-    0x4c, 0x33};
+    0xb1, 0xe0, 0x09, 0x70, 0xa2, 0xa6, 0x03, 0x0a, 0x01, 0x00, 0xa7, 0x21,
+    0x0c, 0x1f, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x6c, 0x2e, 0x65, 0x78,
+    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70, 0x32, 0x35, 0x36, 0x5f, 0x63,
+    0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x30, 0x0c, 0x06,
+    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x05, 0x00, 0x03,
+    0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x1e, 0x7d, 0xb6, 0x7e, 0x85, 0x4a,
+    0x20, 0xfc, 0x61, 0xa8, 0xb8, 0x73, 0x40, 0xa0, 0xc2, 0x5f, 0xa5, 0x3f,
+    0x06, 0x07, 0x0a, 0x1c, 0x26, 0x82, 0xa0, 0x5c, 0xd5, 0xb9, 0x58, 0xf5,
+    0xe5, 0xb0, 0x02, 0x20, 0x46, 0x61, 0x2d, 0x29, 0xee, 0xa7, 0xb6, 0xad,
+    0xc4, 0x0d, 0xc6, 0xb2, 0x76, 0xf2, 0x5a, 0x88, 0xc1, 0xbd, 0x8e, 0xdd,
+    0x5e, 0xbd, 0xc7, 0x1d, 0xb3, 0xc3, 0x2d, 0x84, 0x4b, 0xf6, 0xce, 0x7f};
 
 constexpr uint8_t kExpectedX509P384Cert_DescriptorInput[0] = {};
 
@@ -1095,7 +1181,68 @@ constexpr uint8_t kExpectedCborEd25519Cert_DescriptorInput[667] = {
     0x5a, 0xfa, 0xca, 0xcd, 0x5d, 0x44, 0x58, 0x45, 0xdf, 0xbb, 0x3d, 0x08,
     0x88, 0x9b, 0x0c, 0x3b, 0x06, 0x7c, 0x0e};
 
-constexpr uint8_t kExpectedCborP256Cert_DescriptorInput[0] = {};
+constexpr uint8_t kExpectedCborP256Cert_DescriptorInput[729] = {
+    0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x02, 0x8e, 0xac, 0x01, 0x78,
+    0x28, 0x34, 0x38, 0x36, 0x30, 0x33, 0x63, 0x30, 0x30, 0x35, 0x32, 0x63,
+    0x31, 0x63, 0x61, 0x63, 0x37, 0x33, 0x63, 0x61, 0x65, 0x33, 0x36, 0x63,
+    0x33, 0x62, 0x64, 0x65, 0x63, 0x37, 0x63, 0x36, 0x31, 0x33, 0x39, 0x38,
+    0x38, 0x35, 0x63, 0x39, 0x64, 0x02, 0x78, 0x28, 0x35, 0x61, 0x30, 0x34,
+    0x65, 0x39, 0x65, 0x63, 0x66, 0x31, 0x39, 0x61, 0x64, 0x33, 0x64, 0x35,
+    0x32, 0x36, 0x36, 0x38, 0x62, 0x38, 0x32, 0x61, 0x36, 0x30, 0x38, 0x31,
+    0x66, 0x30, 0x33, 0x66, 0x64, 0x62, 0x32, 0x39, 0x66, 0x38, 0x36, 0x34,
+    0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0xb7, 0xd4, 0x0c, 0xcb, 0x22,
+    0x5b, 0xa5, 0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6, 0x90,
+    0xac, 0x50, 0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e, 0x52,
+    0x19, 0xe4, 0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40, 0x87,
+    0x7a, 0xdd, 0x17, 0x48, 0x05, 0x89, 0x7e, 0x2b, 0xcb, 0x54, 0x79, 0xcc,
+    0x66, 0xf1, 0xb3, 0x13, 0x29, 0x0c, 0x68, 0x96, 0xb2, 0xbb, 0x8f, 0x3a,
+    0x00, 0x47, 0x44, 0x51, 0x58, 0x64, 0x6c, 0x46, 0x01, 0x33, 0x26, 0x73,
+    0x4b, 0x22, 0x65, 0xfd, 0xfa, 0x58, 0xd7, 0x57, 0x3e, 0x95, 0x59, 0xe0,
+    0x3a, 0xc3, 0xb9, 0xf7, 0xc8, 0x0e, 0x98, 0x80, 0x8c, 0xf5, 0xc4, 0xb8,
+    0xaf, 0xe3, 0x16, 0x84, 0x25, 0xa5, 0x35, 0x5d, 0x17, 0x72, 0x56, 0x8f,
+    0x8e, 0xec, 0x2f, 0x5a, 0x74, 0x60, 0x77, 0x2a, 0x6e, 0x90, 0xc0, 0x4e,
+    0x9f, 0x87, 0x6b, 0xf4, 0x8d, 0x9c, 0x66, 0xe3, 0x0b, 0xd2, 0x10, 0x35,
+    0x21, 0xa8, 0x1d, 0xa2, 0x31, 0x17, 0xe7, 0x0c, 0xdf, 0x18, 0xf7, 0x94,
+    0xe4, 0xd1, 0xca, 0x32, 0x7d, 0xf2, 0x63, 0x23, 0x1d, 0xbc, 0x84, 0x74,
+    0x61, 0xdb, 0x87, 0xf2, 0xab, 0x72, 0xad, 0xaf, 0x08, 0xf8, 0x3a, 0x00,
+    0x47, 0x44, 0x53, 0x58, 0x28, 0x1b, 0x40, 0xc1, 0xa9, 0x77, 0x60, 0xeb,
+    0xc3, 0x67, 0xf0, 0x5f, 0x6a, 0xe1, 0x5e, 0x20, 0xc2, 0x51, 0x68, 0x4d,
+    0x82, 0x48, 0x8b, 0x03, 0x32, 0x16, 0x79, 0x88, 0x14, 0x37, 0x78, 0x7f,
+    0x16, 0x9a, 0x06, 0xfd, 0xc0, 0x8a, 0x15, 0x80, 0x62, 0x3a, 0x00, 0x47,
+    0x44, 0x52, 0x58, 0x40, 0x45, 0x00, 0xe9, 0x5c, 0xbd, 0x00, 0x57, 0x04,
+    0x55, 0x87, 0x6c, 0xbd, 0x2f, 0xea, 0x41, 0x9c, 0x66, 0x42, 0x51, 0x41,
+    0xbb, 0x44, 0xed, 0x0e, 0xe9, 0x66, 0xcf, 0xd5, 0x10, 0x73, 0x0d, 0x4b,
+    0x48, 0xe4, 0x7a, 0x53, 0x35, 0x01, 0x0e, 0x6d, 0x15, 0x55, 0xc5, 0xb7,
+    0xd2, 0xd5, 0x36, 0xb6, 0xbc, 0x7e, 0xb0, 0xf3, 0x3d, 0xe6, 0x19, 0x78,
+    0x62, 0xeb, 0x02, 0x57, 0x39, 0x56, 0x73, 0x4f, 0x3a, 0x00, 0x47, 0x44,
+    0x54, 0x58, 0x40, 0x22, 0x52, 0x60, 0x17, 0xef, 0x2c, 0xa1, 0xf6, 0xcb,
+    0xed, 0x39, 0xd5, 0xe2, 0xaa, 0x65, 0x20, 0xfb, 0xad, 0x82, 0x93, 0xe5,
+    0x78, 0x23, 0x22, 0x97, 0xc1, 0x6e, 0x6a, 0x4e, 0x36, 0xd7, 0x6a, 0x61,
+    0x39, 0x08, 0x21, 0xd4, 0xfe, 0x92, 0x5f, 0x36, 0x2d, 0xeb, 0x5d, 0xbb,
+    0x32, 0x8b, 0xe3, 0x94, 0x4f, 0xbe, 0x1b, 0x21, 0xf9, 0xcc, 0x23, 0x73,
+    0x41, 0xb6, 0xb9, 0xb6, 0x98, 0xd0, 0xbc, 0x3a, 0x00, 0x47, 0x44, 0x55,
+    0x58, 0x41, 0x92, 0xd6, 0x97, 0xb3, 0x83, 0xdf, 0xe7, 0x8c, 0xc7, 0xbc,
+    0x4a, 0xfc, 0xea, 0x76, 0xc0, 0x53, 0x66, 0xbd, 0x2c, 0x1e, 0x10, 0x31,
+    0x90, 0x80, 0x11, 0x2d, 0x08, 0x4d, 0x7c, 0x39, 0x76, 0xdc, 0x73, 0xe7,
+    0x1c, 0x16, 0x62, 0xd5, 0x59, 0xd7, 0x49, 0x2b, 0x6a, 0xa2, 0x36, 0x67,
+    0x57, 0xd1, 0xf2, 0xf9, 0xaf, 0x13, 0xd7, 0xa3, 0xe4, 0xd3, 0x39, 0x5b,
+    0x02, 0x78, 0xb1, 0xe0, 0x09, 0x70, 0xa2, 0x3a, 0x00, 0x47, 0x44, 0x56,
+    0x41, 0x00, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x50, 0xa6, 0x01, 0x02,
+    0x03, 0x26, 0x04, 0x81, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x6d, 0x1e,
+    0xdd, 0x35, 0x38, 0x70, 0xc2, 0x8a, 0x01, 0xdf, 0x80, 0xb1, 0xa5, 0xae,
+    0x85, 0x4b, 0x7a, 0x12, 0xdd, 0x11, 0xf6, 0x97, 0x27, 0x44, 0x9b, 0x27,
+    0xf3, 0x87, 0x97, 0xb3, 0xe7, 0x36, 0x22, 0x58, 0x20, 0xe6, 0x42, 0x87,
+    0x8c, 0x72, 0xde, 0xf7, 0xaf, 0x2d, 0xc6, 0x23, 0x00, 0xb1, 0x2b, 0x4e,
+    0x1c, 0xf3, 0xaf, 0x67, 0xf0, 0x9b, 0x88, 0x40, 0x79, 0x3b, 0x09, 0x78,
+    0x30, 0x51, 0x65, 0x38, 0x61, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20,
+    0x3a, 0x00, 0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e, 0x64, 0x69,
+    0x63, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70,
+    0x32, 0x35, 0x36, 0x58, 0x40, 0x5e, 0x90, 0x5d, 0x5b, 0x1e, 0xfc, 0xda,
+    0xab, 0x8d, 0x52, 0xb0, 0xb4, 0xa3, 0xb9, 0xb1, 0x7e, 0x36, 0x20, 0x7f,
+    0x2e, 0x4b, 0x2c, 0x86, 0x77, 0x1f, 0xf2, 0x7d, 0x5a, 0x18, 0xfb, 0x15,
+    0x7b, 0x3a, 0x0a, 0xdc, 0x0a, 0x1e, 0xcb, 0xfa, 0x72, 0xac, 0x30, 0xb1,
+    0x1c, 0x4b, 0xd8, 0x28, 0x70, 0x43, 0x73, 0x91, 0xe5, 0x6b, 0xab, 0xd1,
+    0x55, 0xc7, 0x0c, 0xed, 0x32, 0x9b, 0xa0, 0x5e, 0x26};
 
 constexpr uint8_t kExpectedCborP384Cert_DescriptorInput[795] = {
     0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59, 0x02, 0xaf, 0xac, 0x01,
@@ -1156,15 +1303,15 @@ constexpr uint8_t kExpectedCborP384Cert_DescriptorInput[795] = {
     0x8d, 0x1d, 0x4b, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20, 0x3a, 0x00,
     0x47, 0x44, 0x59, 0x75, 0x6f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x63, 0x65,
     0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x70, 0x33, 0x38,
-    0x34, 0x58, 0x60, 0xe4, 0x8c, 0x6b, 0x6b, 0x24, 0xb2, 0xc6, 0x17, 0xcf,
-    0xfb, 0xb0, 0x8b, 0x28, 0x81, 0x8c, 0xb7, 0xc0, 0xed, 0x46, 0x9d, 0xb7,
-    0xb6, 0x7f, 0xfd, 0xc6, 0xdd, 0xb8, 0x61, 0xb9, 0x03, 0xbc, 0x66, 0x01,
-    0xb2, 0x7e, 0x9d, 0x4e, 0x62, 0x7b, 0xb0, 0x41, 0x39, 0x81, 0x7f, 0x30,
-    0x64, 0x4e, 0x5b, 0x33, 0x22, 0x1c, 0xa4, 0xac, 0x88, 0x33, 0x87, 0xe1,
-    0x7b, 0x0f, 0xa1, 0x55, 0xaa, 0x8a, 0x4e, 0xbd, 0x50, 0xec, 0xc0, 0x35,
-    0x28, 0xb4, 0xaa, 0xaa, 0x2a, 0x78, 0x42, 0x5f, 0xcb, 0x76, 0xa7, 0x84,
-    0xa1, 0xca, 0xf2, 0xda, 0xdb, 0x14, 0x6a, 0x87, 0x05, 0x11, 0xa8, 0xfa,
-    0x09, 0x30, 0x9c};
+    0x34, 0x58, 0x60, 0x5b, 0xe4, 0xf7, 0x39, 0x88, 0x09, 0x93, 0x73, 0x57,
+    0x5d, 0xb9, 0xb1, 0xb9, 0x39, 0xa8, 0x45, 0x8c, 0xba, 0x07, 0x11, 0x9d,
+    0xda, 0x23, 0x3c, 0x56, 0x82, 0x04, 0x81, 0xcb, 0x61, 0xb0, 0x1c, 0xe5,
+    0xbe, 0x3b, 0xa1, 0x77, 0x44, 0xa3, 0xe0, 0x18, 0x11, 0x78, 0x9e, 0xc4,
+    0x2c, 0x3f, 0xb6, 0x60, 0xa6, 0x3b, 0xe3, 0x74, 0x4d, 0xcc, 0x3a, 0x99,
+    0x22, 0x66, 0x1b, 0x09, 0xb8, 0x1c, 0x81, 0x32, 0x57, 0x66, 0xde, 0xa2,
+    0x76, 0x50, 0xa1, 0xee, 0xb3, 0x95, 0x60, 0x82, 0x40, 0x29, 0x30, 0x8b,
+    0x19, 0x33, 0x90, 0x54, 0x47, 0xd1, 0x38, 0x25, 0xb8, 0x28, 0xe9, 0xc5,
+    0x9d, 0x9a, 0x3e};
 
 }  // namespace test
 }  // namespace dice
diff --git a/include/dice/test_utils.h b/include/dice/test_utils.h
index 7e403b9..c5bea9e 100644
--- a/include/dice/test_utils.h
+++ b/include/dice/test_utils.h
@@ -33,6 +33,7 @@ enum CertificateType {
 enum KeyType {
   KeyType_Ed25519,
   KeyType_P256,
+  KeyType_P256_COMPRESSED,
   KeyType_P384,
 };
 
diff --git a/src/boringssl_ecdsa_utils.c b/src/boringssl_ecdsa_utils.c
index 876e87f..e42f679 100644
--- a/src/boringssl_ecdsa_utils.c
+++ b/src/boringssl_ecdsa_utils.c
@@ -12,8 +12,7 @@
 // License for the specific language governing permissions and limitations under
 // the License.
 
-// This is an implementation of the crypto operations that uses boringssl. The
-// algorithms used are SHA512, HKDF-SHA512, and ECDSA P384-SHA384.
+// This is an implementation of the ECDSA crypto operations that uses boringssl.
 
 #include "dice/boringssl_ecdsa_utils.h"
 
@@ -89,10 +88,8 @@ static BIGNUM *derivePrivateKey(const EC_GROUP *group, const uint8_t *seed,
   BIGNUM *candidate = NULL;
   uint8_t v[64];
   uint8_t k[64];
-  uint8_t temp[64];
   memset(v, 1, 64);
   memset(k, 0, 64);
-  memset(temp, 0, 64);
 
   if (private_key_len > 64) {
     goto err;
@@ -111,14 +108,14 @@ static BIGNUM *derivePrivateKey(const EC_GROUP *group, const uint8_t *seed,
     if (1 != hmac(k, v, v, sizeof(v))) {
       goto err;
     }
-    if (1 != hmac(k, v, temp, sizeof(temp))) {
+    if (1 != hmac(k, v, v, sizeof(v))) {
       goto err;
     }
-    if (1 != hmac3(k, v, 0x00, NULL, 0, k)) {
+    candidate = BN_bin2bn(v, private_key_len, candidate);
+    if (!candidate) {
       goto err;
     }
-    candidate = BN_bin2bn(temp, private_key_len, NULL);
-    if (!candidate) {
+    if (1 != hmac3(k, v, 0x00, NULL, 0, k)) {
       goto err;
     }
   } while (BN_cmp(candidate, EC_GROUP_get0_order(group)) >= 0 ||
@@ -132,16 +129,16 @@ out:
   return candidate;
 }
 
-int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
-                        uint8_t private_key[P384_PRIVATE_KEY_SIZE],
-                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
+static int KeypairFromSeed(int nid, uint8_t *public_key, size_t public_key_size,
+                           uint8_t *private_key, size_t private_key_size,
+                           const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
   int ret = 0;
   EC_POINT *publicKey = NULL;
   BIGNUM *pD = NULL;
   BIGNUM *x = NULL;
   BIGNUM *y = NULL;
 
-  EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
+  EC_KEY *key = EC_KEY_new_by_curve_name(nid);
   if (!key) {
     goto out;
   }
@@ -155,11 +152,11 @@ int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
   }
 
   pD = derivePrivateKey(group, seed, DICE_PRIVATE_KEY_SEED_SIZE,
-                        P384_PRIVATE_KEY_SIZE);
+                        private_key_size);
   if (!pD) {
     goto out;
   }
-  if (1 != BN_bn2bin_padded(private_key, P384_PRIVATE_KEY_SIZE, pD)) {
+  if (1 != BN_bn2bin_padded(private_key, private_key_size, pD)) {
     goto out;
   }
   if (1 != EC_KEY_set_private_key(key, pD)) {
@@ -179,11 +176,11 @@ int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
   if (1 != EC_POINT_get_affine_coordinates_GFp(group, publicKey, x, y, NULL)) {
     goto out;
   }
-  if (1 != BN_bn2bin_padded(&public_key[0], P384_PUBLIC_KEY_SIZE / 2, x)) {
+  size_t coord_size = public_key_size / 2;
+  if (1 != BN_bn2bin_padded(&public_key[0], coord_size, x)) {
     goto out;
   }
-  if (1 != BN_bn2bin_padded(&public_key[P384_PUBLIC_KEY_SIZE / 2],
-                            P384_PUBLIC_KEY_SIZE / 2, y)) {
+  if (1 != BN_bn2bin_padded(&public_key[coord_size], coord_size, y)) {
     goto out;
   }
   ret = 1;
@@ -198,36 +195,54 @@ out:
   return ret;
 }
 
-int P384Sign(uint8_t signature[P384_SIGNATURE_SIZE], const uint8_t *message,
-             size_t message_size,
-             const uint8_t private_key[P384_PRIVATE_KEY_SIZE]) {
+int P256KeypairFromSeed(uint8_t public_key[P256_PUBLIC_KEY_SIZE],
+                        uint8_t private_key[P256_PRIVATE_KEY_SIZE],
+                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
+  return KeypairFromSeed(NID_X9_62_prime256v1, public_key, P256_PUBLIC_KEY_SIZE,
+                         private_key, P256_PRIVATE_KEY_SIZE, seed);
+}
+
+int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
+                        uint8_t private_key[P384_PRIVATE_KEY_SIZE],
+                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
+  return KeypairFromSeed(NID_secp384r1, public_key, P384_PUBLIC_KEY_SIZE,
+                         private_key, P384_PRIVATE_KEY_SIZE, seed);
+}
+
+static int Sign(int nid, uint8_t *signature, size_t signature_size,
+                const EVP_MD *md_type, const uint8_t *message,
+                size_t message_size, const uint8_t *private_key,
+                size_t private_key_size) {
   int ret = 0;
   BIGNUM *pD = NULL;
   EC_KEY *key = NULL;
-  uint8_t output[48];
+  uint8_t output[EVP_MAX_MD_SIZE];
+  unsigned int md_size;
   ECDSA_SIG *sig = NULL;
 
-  pD = BN_bin2bn(private_key, P384_PRIVATE_KEY_SIZE, NULL);
+  pD = BN_bin2bn(private_key, private_key_size, NULL);
   if (!pD) {
     goto out;
   }
-  key = EC_KEY_new_by_curve_name(NID_secp384r1);
+  key = EC_KEY_new_by_curve_name(nid);
   if (!key) {
     goto out;
   }
   if (1 != EC_KEY_set_private_key(key, pD)) {
     goto out;
   }
-  SHA384(message, message_size, output);
-  sig = ECDSA_do_sign(output, 48, key);
+  if (1 != EVP_Digest(message, message_size, output, &md_size, md_type, NULL)) {
+    goto out;
+  }
+  sig = ECDSA_do_sign(output, md_size, key);
   if (!sig) {
     goto out;
   }
-  if (1 != BN_bn2bin_padded(&signature[0], P384_SIGNATURE_SIZE / 2, sig->r)) {
+  size_t coord_size = signature_size / 2;
+  if (1 != BN_bn2bin_padded(&signature[0], coord_size, sig->r)) {
     goto out;
   }
-  if (1 != BN_bn2bin_padded(&signature[P384_SIGNATURE_SIZE / 2],
-                            P384_SIGNATURE_SIZE / 2, sig->s)) {
+  if (1 != BN_bn2bin_padded(&signature[coord_size], coord_size, sig->s)) {
     goto out;
   }
   ret = 1;
@@ -239,19 +254,38 @@ out:
   return ret;
 }
 
-int P384Verify(const uint8_t *message, size_t message_size,
-               const uint8_t signature[P384_SIGNATURE_SIZE],
-               const uint8_t public_key[P384_PUBLIC_KEY_SIZE]) {
+int P256Sign(uint8_t signature[P256_SIGNATURE_SIZE], const uint8_t *message,
+             size_t message_size,
+             const uint8_t private_key[P256_PRIVATE_KEY_SIZE]) {
+  return Sign(NID_X9_62_prime256v1, signature, P256_SIGNATURE_SIZE,
+              EVP_sha256(), message, message_size, private_key,
+              P256_PRIVATE_KEY_SIZE);
+}
+
+int P384Sign(uint8_t signature[P384_SIGNATURE_SIZE], const uint8_t *message,
+             size_t message_size,
+             const uint8_t private_key[P384_PRIVATE_KEY_SIZE]) {
+  return Sign(NID_secp384r1, signature, P384_SIGNATURE_SIZE, EVP_sha384(),
+              message, message_size, private_key, P384_PRIVATE_KEY_SIZE);
+}
+
+static int Verify(int nid, const EVP_MD *md_type, const uint8_t *message,
+                  size_t message_size, const uint8_t *signature,
+                  size_t signature_size, const uint8_t *public_key,
+                  size_t public_key_size) {
   int ret = 0;
-  uint8_t output[48];
+  uint8_t output[EVP_MAX_MD_SIZE];
+  unsigned int md_size;
   EC_KEY *key = NULL;
   BIGNUM *bn_ret = NULL;
   BIGNUM *x = NULL;
   BIGNUM *y = NULL;
   ECDSA_SIG *sig = NULL;
 
-  SHA384(message, message_size, output);
-  key = EC_KEY_new_by_curve_name(NID_secp384r1);
+  if (1 != EVP_Digest(message, message_size, output, &md_size, md_type, NULL)) {
+    goto out;
+  }
+  key = EC_KEY_new_by_curve_name(nid);
   if (!key) {
     goto out;
   }
@@ -259,7 +293,8 @@ int P384Verify(const uint8_t *message, size_t message_size,
   if (!x) {
     goto out;
   }
-  bn_ret = BN_bin2bn(&public_key[0], P384_PUBLIC_KEY_SIZE / 2, x);
+  size_t coord_size = public_key_size / 2;
+  bn_ret = BN_bin2bn(&public_key[0], coord_size, x);
   if (!bn_ret) {
     goto out;
   }
@@ -267,8 +302,7 @@ int P384Verify(const uint8_t *message, size_t message_size,
   if (!y) {
     goto out;
   }
-  bn_ret = BN_bin2bn(&public_key[P384_PUBLIC_KEY_SIZE / 2],
-                     P384_PUBLIC_KEY_SIZE / 2, y);
+  bn_ret = BN_bin2bn(&public_key[coord_size], coord_size, y);
   if (!bn_ret) {
     goto out;
   }
@@ -280,16 +314,16 @@ int P384Verify(const uint8_t *message, size_t message_size,
   if (!sig) {
     goto out;
   }
-  bn_ret = BN_bin2bn(&signature[0], P384_SIGNATURE_SIZE / 2, sig->r);
+  coord_size = signature_size / 2;
+  bn_ret = BN_bin2bn(&signature[0], coord_size, sig->r);
   if (!bn_ret) {
     goto out;
   }
-  bn_ret = BN_bin2bn(&signature[P384_SIGNATURE_SIZE / 2],
-                     P384_SIGNATURE_SIZE / 2, sig->s);
+  bn_ret = BN_bin2bn(&signature[coord_size], coord_size, sig->s);
   if (!bn_ret) {
     goto out;
   }
-  ret = ECDSA_do_verify(output, 48, sig, key);
+  ret = ECDSA_do_verify(output, md_size, sig, key);
 
 out:
   BN_clear_free(y);
@@ -298,3 +332,18 @@ out:
   ECDSA_SIG_free(sig);
   return ret;
 }
+
+int P256Verify(const uint8_t *message, size_t message_size,
+               const uint8_t signature[P256_SIGNATURE_SIZE],
+               const uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
+  return Verify(NID_X9_62_prime256v1, EVP_sha256(), message, message_size,
+                signature, P256_SIGNATURE_SIZE, public_key,
+                P256_PUBLIC_KEY_SIZE);
+}
+
+int P384Verify(const uint8_t *message, size_t message_size,
+               const uint8_t signature[P384_SIGNATURE_SIZE],
+               const uint8_t public_key[P384_PUBLIC_KEY_SIZE]) {
+  return Verify(NID_secp384r1, EVP_sha384(), message, message_size, signature,
+                P384_SIGNATURE_SIZE, public_key, P384_PUBLIC_KEY_SIZE);
+}
diff --git a/src/boringssl_p256_ops.c b/src/boringssl_p256_ops.c
new file mode 100644
index 0000000..e6e030a
--- /dev/null
+++ b/src/boringssl_p256_ops.c
@@ -0,0 +1,68 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+// This is an implementation of P-256 signature operations using boringssl.
+
+#include <stdint.h>
+#include <stdio.h>
+
+#include "dice/boringssl_ecdsa_utils.h"
+#include "dice/dice.h"
+#include "dice/ops.h"
+
+#if DICE_PRIVATE_KEY_SEED_SIZE != 32
+#error "Private key seed is expected to be 32 bytes."
+#endif
+#if DICE_PUBLIC_KEY_SIZE != 64
+#error "This P-256 implementation needs 64 bytes to store the public key."
+#endif
+#if DICE_PRIVATE_KEY_SIZE != 32
+#error "P-256 needs 32 bytes for the private key."
+#endif
+#if DICE_SIGNATURE_SIZE != 64
+#error "P-256 needs 64 bytes to store the signature."
+#endif
+
+DiceResult DiceKeypairFromSeed(void* context_not_used,
+                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
+                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
+                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]) {
+  (void)context_not_used;
+  if (1 == P256KeypairFromSeed(public_key, private_key, seed)) {
+    return kDiceResultOk;
+  }
+  return kDiceResultPlatformError;
+}
+
+DiceResult DiceSign(void* context_not_used, const uint8_t* message,
+                    size_t message_size,
+                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
+                    uint8_t signature[DICE_SIGNATURE_SIZE]) {
+  (void)context_not_used;
+  if (1 == P256Sign(signature, message, message_size, private_key)) {
+    return kDiceResultOk;
+  }
+  return kDiceResultPlatformError;
+}
+
+DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
+                      size_t message_size,
+                      const uint8_t signature[DICE_SIGNATURE_SIZE],
+                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]) {
+  (void)context_not_used;
+  if (1 == P256Verify(message, message_size, signature, public_key)) {
+    return kDiceResultOk;
+  }
+  return kDiceResultPlatformError;
+}
diff --git a/src/cbor_p256_cert_op.c b/src/cbor_p256_cert_op.c
new file mode 100644
index 0000000..fdc7e11
--- /dev/null
+++ b/src/cbor_p256_cert_op.c
@@ -0,0 +1,80 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+// This is a DiceGenerateCertificate implementation that generates a CWT-style
+// CBOR certificate using the P-256 signature algorithm.
+
+#include <stddef.h>
+#include <stdint.h>
+#include <string.h>
+
+#include "dice/cbor_writer.h"
+#include "dice/dice.h"
+#include "dice/ops.h"
+#include "dice/ops/trait/cose.h"
+#include "dice/utils.h"
+
+#if DICE_PUBLIC_KEY_SIZE != 64
+#error "64 bytes needed to store the public key."
+#endif
+#if DICE_SIGNATURE_SIZE != 64
+#error "64 bytes needed to store the signature."
+#endif
+
+DiceResult DiceCoseEncodePublicKey(
+    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
+    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
+  (void)context_not_used;
+
+  // Constants per RFC 8152.
+  const int64_t kCoseKeyKtyLabel = 1;
+  const int64_t kCoseKeyAlgLabel = 3;
+  const int64_t kCoseKeyAlgValue = DICE_COSE_KEY_ALG_VALUE;
+  const int64_t kCoseKeyOpsLabel = 4;
+  const int64_t kCoseKeyOpsValue = 2;  // Verify
+  const int64_t kCoseKeyKtyValue = 2;  // EC2
+  const int64_t kCoseEc2CrvLabel = -1;
+  const int64_t kCoseEc2CrvValue = 1;  // P-256
+  const int64_t kCoseEc2XLabel = -2;
+  const int64_t kCoseEc2YLabel = -3;
+
+  struct CborOut out;
+  CborOutInit(buffer, buffer_size, &out);
+  CborWriteMap(/*num_pairs=*/6, &out);
+  // Add the key type.
+  CborWriteInt(kCoseKeyKtyLabel, &out);
+  CborWriteInt(kCoseKeyKtyValue, &out);
+  // Add the algorithm.
+  CborWriteInt(kCoseKeyAlgLabel, &out);
+  CborWriteInt(kCoseKeyAlgValue, &out);
+  // Add the KeyOps.
+  CborWriteInt(kCoseKeyOpsLabel, &out);
+  CborWriteArray(/*num_elements=*/1, &out);
+  CborWriteInt(kCoseKeyOpsValue, &out);
+  // Add the curve.
+  CborWriteInt(kCoseEc2CrvLabel, &out);
+  CborWriteInt(kCoseEc2CrvValue, &out);
+  // Add the subject public key x and y coordinates
+  CborWriteInt(kCoseEc2XLabel, &out);
+  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2, &public_key[0], &out);
+  CborWriteInt(kCoseEc2YLabel, &out);
+  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2,
+                &public_key[DICE_PUBLIC_KEY_SIZE / 2], &out);
+
+  *encoded_size = CborOutSize(&out);
+  if (CborOutOverflowed(&out)) {
+    return kDiceResultBufferTooSmall;
+  }
+  return kDiceResultOk;
+}
diff --git a/src/cbor_p256_cert_op_test.cc b/src/cbor_p256_cert_op_test.cc
new file mode 100644
index 0000000..32fc2e2
--- /dev/null
+++ b/src/cbor_p256_cert_op_test.cc
@@ -0,0 +1,254 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+
+#include <memory>
+
+#include "dice/config.h"
+#include "dice/dice.h"
+#include "dice/known_test_values.h"
+#include "dice/test_framework.h"
+#include "dice/test_utils.h"
+#include "dice/utils.h"
+#include "pw_string/format.h"
+
+namespace {
+
+using dice::test::CertificateType_Cbor;
+using dice::test::DeriveFakeInputValue;
+using dice::test::DiceStateForTest;
+using dice::test::KeyType_P256;
+
+TEST(DiceOpsTest, KnownAnswerZeroInput) {
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "zero_input", next_state);
+  // The CDI values should be deterministic.
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
+                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
+  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
+                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_ZeroInput),
+            next_state.certificate_size);
+  // Comparing everything except for the signature, since ECDSA signatures are
+  // not deterministic
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_ZeroInput,
+                      next_state.certificate,
+                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+}
+
+TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  input_values.config_type = kDiceConfigTypeInline;
+  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
+                       input_values.config_value);
+
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "hash_only_input", next_state);
+  ASSERT_EQ(sizeof(next_state.cdi_attest),
+            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(next_state.cdi_seal),
+            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
+                DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_HashOnlyInput),
+            next_state.certificate_size);
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_HashOnlyInput,
+                      next_state.certificate,
+                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+}
+
+TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
+  DiceStateForTest current_state = {};
+  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
+  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
+
+  DiceStateForTest next_state = {};
+
+  DiceInputValues input_values = {};
+  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
+  uint8_t code_descriptor[100];
+  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
+  input_values.code_descriptor = code_descriptor;
+  input_values.code_descriptor_size = sizeof(code_descriptor);
+
+  uint8_t config_descriptor[40];
+  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
+                       config_descriptor);
+  input_values.config_descriptor = config_descriptor;
+  input_values.config_descriptor_size = sizeof(config_descriptor);
+  input_values.config_type = kDiceConfigTypeDescriptor;
+
+  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
+                       input_values.authority_hash);
+  uint8_t authority_descriptor[65];
+  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
+                       authority_descriptor);
+  input_values.authority_descriptor = authority_descriptor;
+  input_values.authority_descriptor_size = sizeof(authority_descriptor);
+
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  DumpState(CertificateType_Cbor, KeyType_P256, "descriptor_input", next_state);
+  // Both CDI values and the certificate should be deterministic.
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_attest,
+                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
+  EXPECT_EQ(
+      0, memcmp(next_state.cdi_seal,
+                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
+  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_DescriptorInput),
+            next_state.certificate_size);
+  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_DescriptorInput,
+                      next_state.certificate,
+                      next_state.certificate_size - DICE_SIGNATURE_SIZE));
+}
+
+TEST(DiceOpsTest, NonZeroMode) {
+  constexpr size_t kModeOffsetInCert = 315;
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.mode = kDiceModeDebug;
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultOk, result);
+  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
+}
+
+TEST(DiceOpsTest, LargeInputs) {
+  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.code_descriptor = kBigBuffer;
+  input_values.code_descriptor_size = sizeof(kBigBuffer);
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultBufferTooSmall, result);
+}
+
+TEST(DiceOpsTest, InvalidConfigType) {
+  DiceStateForTest current_state = {};
+  DiceStateForTest next_state = {};
+  DiceInputValues input_values = {};
+  input_values.config_type = (DiceConfigType)55;
+  DiceResult result = DiceMainFlow(
+      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
+      sizeof(next_state.certificate), next_state.certificate,
+      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
+  EXPECT_EQ(kDiceResultInvalidInput, result);
+}
+
+TEST(DiceOpsTest, PartialCertChain) {
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(/*context=*/NULL, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "part_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
+  }
+  // Use the first derived CDI cert as the 'root' of partial chain.
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
+      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
+}
+
+TEST(DiceOpsTest, FullCertChain) {
+  constexpr size_t kNumLayers = 7;
+  DiceStateForTest states[kNumLayers + 1] = {};
+  DiceInputValues inputs[kNumLayers] = {};
+  for (size_t i = 0; i < kNumLayers; ++i) {
+    char seed[40];
+    pw::string::Format(seed, "code_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
+    pw::string::Format(seed, "authority_hash_%zu", i);
+    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
+    inputs[i].config_type = kDiceConfigTypeInline;
+    pw::string::Format(seed, "inline_config_%zu", i);
+    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
+    inputs[i].mode = kDiceModeNormal;
+    EXPECT_EQ(
+        kDiceResultOk,
+        DiceMainFlow(/*context=*/NULL, states[i].cdi_attest, states[i].cdi_seal,
+                     &inputs[i], sizeof(states[i + 1].certificate),
+                     states[i + 1].certificate, &states[i + 1].certificate_size,
+                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
+    char suffix[40];
+    pw::string::Format(suffix, "full_cert_chain_%zu", i);
+    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
+  }
+  // Use a fake self-signed UDS cert as the 'root'.
+  uint8_t root_certificate[dice::test::kTestCertSize];
+  size_t root_certificate_size = 0;
+  dice::test::CreateFakeUdsCertificate(
+      NULL, states[0].cdi_attest, CertificateType_Cbor, KeyType_P256,
+      root_certificate, &root_certificate_size);
+  EXPECT_TRUE(dice::test::VerifyCertificateChain(
+      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
+      kNumLayers, /*is_partial_chain=*/false));
+}
+
+}  // namespace
diff --git a/src/cbor_reader.c b/src/cbor_reader.c
index 035a0bc..1270206 100644
--- a/src/cbor_reader.c
+++ b/src/cbor_reader.c
@@ -29,10 +29,10 @@ static bool CborReadWouldOverflow(size_t size, struct CborIn* in) {
   return size > SIZE_MAX - in->cursor || in->cursor + size > in->buffer_size;
 }
 
-static enum CborReadResult CborPeekIntialValueAndArgument(struct CborIn* in,
-                                                          uint8_t* size,
-                                                          enum CborType* type,
-                                                          uint64_t* val) {
+static enum CborReadResult CborPeekInitialValueAndArgument(struct CborIn* in,
+                                                           uint8_t* size,
+                                                           enum CborType* type,
+                                                           uint64_t* val) {
   uint8_t initial_byte;
   uint8_t additional_information;
   uint64_t value;
@@ -54,13 +54,13 @@ static enum CborReadResult CborPeekIntialValueAndArgument(struct CborIn* in,
     if (bytes == 2) {
       value |= in->buffer[in->cursor + 1];
     } else if (bytes == 3) {
-      value |= (uint16_t)in->buffer[in->cursor + 1] << 8;
-      value |= (uint16_t)in->buffer[in->cursor + 2];
+      value |= (uint64_t)in->buffer[in->cursor + 1] << 8;
+      value |= (uint64_t)in->buffer[in->cursor + 2];
     } else if (bytes == 5) {
-      value |= (uint32_t)in->buffer[in->cursor + 1] << 24;
-      value |= (uint32_t)in->buffer[in->cursor + 2] << 16;
-      value |= (uint32_t)in->buffer[in->cursor + 3] << 8;
-      value |= (uint32_t)in->buffer[in->cursor + 4];
+      value |= (uint64_t)in->buffer[in->cursor + 1] << 24;
+      value |= (uint64_t)in->buffer[in->cursor + 2] << 16;
+      value |= (uint64_t)in->buffer[in->cursor + 3] << 8;
+      value |= (uint64_t)in->buffer[in->cursor + 4];
     } else if (bytes == 9) {
       value |= (uint64_t)in->buffer[in->cursor + 1] << 56;
       value |= (uint64_t)in->buffer[in->cursor + 2] << 48;
@@ -86,7 +86,7 @@ static enum CborReadResult CborReadSize(struct CborIn* in, enum CborType type,
   enum CborType in_type;
   uint64_t raw;
   enum CborReadResult res =
-      CborPeekIntialValueAndArgument(in, &bytes, &in_type, &raw);
+      CborPeekInitialValueAndArgument(in, &bytes, &in_type, &raw);
   if (res != CBOR_READ_RESULT_OK) {
     return res;
   }
@@ -96,7 +96,7 @@ static enum CborReadResult CborReadSize(struct CborIn* in, enum CborType type,
   if (raw > SIZE_MAX) {
     return CBOR_READ_RESULT_MALFORMED;
   }
-  *size = raw;
+  *size = (size_t)raw;
   in->cursor += bytes;
   return CBOR_READ_RESULT_OK;
 }
@@ -124,7 +124,7 @@ static enum CborReadResult CborReadSimple(struct CborIn* in, uint8_t val) {
   enum CborType type;
   uint64_t raw;
   enum CborReadResult res =
-      CborPeekIntialValueAndArgument(in, &bytes, &type, &raw);
+      CborPeekInitialValueAndArgument(in, &bytes, &type, &raw);
   if (res != CBOR_READ_RESULT_OK) {
     return res;
   }
@@ -140,7 +140,7 @@ enum CborReadResult CborReadInt(struct CborIn* in, int64_t* val) {
   enum CborType type;
   uint64_t raw;
   enum CborReadResult res =
-      CborPeekIntialValueAndArgument(in, &bytes, &type, &raw);
+      CborPeekInitialValueAndArgument(in, &bytes, &type, &raw);
   if (res != CBOR_READ_RESULT_OK) {
     return res;
   }
@@ -159,7 +159,7 @@ enum CborReadResult CborReadUint(struct CborIn* in, uint64_t* val) {
   uint8_t bytes;
   enum CborType type;
   enum CborReadResult res =
-      CborPeekIntialValueAndArgument(in, &bytes, &type, val);
+      CborPeekInitialValueAndArgument(in, &bytes, &type, val);
   if (res != CBOR_READ_RESULT_OK) {
     return res;
   }
@@ -192,7 +192,7 @@ enum CborReadResult CborReadTag(struct CborIn* in, uint64_t* tag) {
   uint8_t bytes;
   enum CborType type;
   enum CborReadResult res =
-      CborPeekIntialValueAndArgument(in, &bytes, &type, tag);
+      CborPeekInitialValueAndArgument(in, &bytes, &type, tag);
   if (res != CBOR_READ_RESULT_OK) {
     return res;
   }
@@ -229,7 +229,7 @@ enum CborReadResult CborReadSkip(struct CborIn* in) {
     uint64_t val;
     enum CborReadResult res;
 
-    res = CborPeekIntialValueAndArgument(&peeker, &bytes, &type, &val);
+    res = CborPeekInitialValueAndArgument(&peeker, &bytes, &type, &val);
     if (res != CBOR_READ_RESULT_OK) {
       return res;
     }
@@ -250,7 +250,7 @@ enum CborReadResult CborReadSkip(struct CborIn* in) {
         continue;
       case CBOR_TYPE_BSTR:
       case CBOR_TYPE_TSTR:
-        if (CborReadWouldOverflow(val, &peeker)) {
+        if (val > SIZE_MAX || CborReadWouldOverflow((size_t)val, &peeker)) {
           return CBOR_READ_RESULT_END;
         }
         peeker.cursor += val;
@@ -277,7 +277,10 @@ enum CborReadResult CborReadSkip(struct CborIn* in) {
     if (stack_size == CBOR_READ_SKIP_STACK_SIZE) {
       return CBOR_READ_RESULT_MALFORMED;
     }
-    size_stack[stack_size++] = val;
+    if (val > SIZE_MAX) {
+      return CBOR_READ_RESULT_END;
+    }
+    size_stack[stack_size++] = (size_t)val;
   }
 
   in->cursor = peeker.cursor;
diff --git a/src/cbor_writer.c b/src/cbor_writer.c
index e512931..6c70129 100644
--- a/src/cbor_writer.c
+++ b/src/cbor_writer.c
@@ -59,22 +59,22 @@ static void CborWriteType(enum CborType type, uint64_t val,
   }
   if (CborWriteFitsInBuffer(size, out)) {
     if (size == 1) {
-      out->buffer[out->cursor] = (type << 5) | val;
+      out->buffer[out->cursor] = (uint8_t)((type << 5) | val);
     } else if (size == 2) {
-      out->buffer[out->cursor] = (type << 5) | 24;
+      out->buffer[out->cursor] = (uint8_t)((type << 5) | 24);
       out->buffer[out->cursor + 1] = val & 0xff;
     } else if (size == 3) {
-      out->buffer[out->cursor] = (type << 5) | 25;
+      out->buffer[out->cursor] = (uint8_t)((type << 5) | 25);
       out->buffer[out->cursor + 1] = (val >> 8) & 0xff;
       out->buffer[out->cursor + 2] = val & 0xff;
     } else if (size == 5) {
-      out->buffer[out->cursor] = (type << 5) | 26;
+      out->buffer[out->cursor] = (uint8_t)((type << 5) | 26);
       out->buffer[out->cursor + 1] = (val >> 24) & 0xff;
       out->buffer[out->cursor + 2] = (val >> 16) & 0xff;
       out->buffer[out->cursor + 3] = (val >> 8) & 0xff;
       out->buffer[out->cursor + 4] = val & 0xff;
     } else if (size == 9) {
-      out->buffer[out->cursor] = (type << 5) | 27;
+      out->buffer[out->cursor] = (uint8_t)((type << 5) | 27);
       out->buffer[out->cursor + 1] = (val >> 56) & 0xff;
       out->buffer[out->cursor + 2] = (val >> 48) & 0xff;
       out->buffer[out->cursor + 3] = (val >> 40) & 0xff;
@@ -108,9 +108,9 @@ static void CborWriteStr(enum CborType type, size_t data_size, const void* data,
 
 void CborWriteInt(int64_t val, struct CborOut* out) {
   if (val < 0) {
-    CborWriteType(CBOR_TYPE_NINT, (-1 - val), out);
+    CborWriteType(CBOR_TYPE_NINT, (uint64_t)(-1 - val), out);
   } else {
-    CborWriteType(CBOR_TYPE_UINT, val, out);
+    CborWriteType(CBOR_TYPE_UINT, (uint64_t)val, out);
   }
 }
 
diff --git a/src/mbedtls_ops_test.cc b/src/mbedtls_ops_test.cc
index 7f97366..66db7c4 100644
--- a/src/mbedtls_ops_test.cc
+++ b/src/mbedtls_ops_test.cc
@@ -31,7 +31,7 @@ using dice::test::CertificateType_X509;
 using dice::test::DeriveFakeInputValue;
 using dice::test::DiceStateForTest;
 using dice::test::DumpState;
-using dice::test::KeyType_P256;
+using dice::test::KeyType_P256_COMPRESSED;
 
 TEST(DiceOpsTest, KnownAnswerZeroInput) {
   DiceStateForTest current_state = {};
@@ -42,7 +42,8 @@ TEST(DiceOpsTest, KnownAnswerZeroInput) {
       sizeof(next_state.certificate), next_state.certificate,
       &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
   EXPECT_EQ(kDiceResultOk, result);
-  DumpState(CertificateType_X509, KeyType_P256, "zero_input", next_state);
+  DumpState(CertificateType_X509, KeyType_P256_COMPRESSED, "zero_input",
+            next_state);
   // Both CDI values and the certificate should be deterministic.
   EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                       dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
@@ -72,7 +73,8 @@ TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
       sizeof(next_state.certificate), next_state.certificate,
       &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
   EXPECT_EQ(kDiceResultOk, result);
-  DumpState(CertificateType_X509, KeyType_P256, "hash_only_input", next_state);
+  DumpState(CertificateType_X509, KeyType_P256_COMPRESSED, "hash_only_input",
+            next_state);
   // Both CDI values and the certificate should be deterministic.
   EXPECT_EQ(
       0, memcmp(next_state.cdi_attest,
@@ -120,7 +122,8 @@ TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
       sizeof(next_state.certificate), next_state.certificate,
       &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
   EXPECT_EQ(kDiceResultOk, result);
-  DumpState(CertificateType_X509, KeyType_P256, "descriptor_input", next_state);
+  DumpState(CertificateType_X509, KeyType_P256_COMPRESSED, "descriptor_input",
+            next_state);
   // Both CDI values and the certificate should be deterministic.
   EXPECT_EQ(
       0, memcmp(next_state.cdi_attest,
@@ -135,7 +138,7 @@ TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
 }
 
 TEST(DiceOpsTest, NonZeroMode) {
-  constexpr size_t kModeOffsetInCert = 0x269;
+  constexpr size_t kModeOffsetInCert = 0x26a;
   DiceStateForTest current_state = {};
   DiceStateForTest next_state = {};
   DiceInputValues input_values = {};
@@ -196,7 +199,8 @@ TEST(DiceOpsTest, PartialCertChain) {
                      states[i + 1].cdi_attest, states[i + 1].cdi_seal));
     char suffix[40];
     pw::string::Format(suffix, "part_cert_chain_%zu", i);
-    DumpState(CertificateType_X509, KeyType_P256, suffix, states[i + 1]);
+    DumpState(CertificateType_X509, KeyType_P256_COMPRESSED, suffix,
+              states[i + 1]);
   }
   // Use the first derived CDI cert as the 'root' of partial chain.
   EXPECT_TRUE(dice::test::VerifyCertificateChain(
@@ -226,14 +230,16 @@ TEST(DiceOpsTest, FullCertChain) {
                      states[i + 1].cdi_attest, states[i + 1].cdi_seal));
     char suffix[40];
     pw::string::Format(suffix, "full_cert_chain_%zu", i);
-    DumpState(CertificateType_X509, KeyType_P256, suffix, states[i + 1]);
+    DumpState(CertificateType_X509, KeyType_P256_COMPRESSED, suffix,
+              states[i + 1]);
   }
   // Use a fake self-signed UDS cert as the 'root'.
   uint8_t root_certificate[dice::test::kTestCertSize];
   size_t root_certificate_size = 0;
   dice::test::CreateFakeUdsCertificate(
       NULL, states[0].cdi_attest, dice::test::CertificateType_X509,
-      dice::test::KeyType_P256, root_certificate, &root_certificate_size);
+      dice::test::KeyType_P256_COMPRESSED, root_certificate,
+      &root_certificate_size);
   EXPECT_TRUE(dice::test::VerifyCertificateChain(
       CertificateType_X509, root_certificate, root_certificate_size, &states[1],
       kNumLayers,
diff --git a/src/test_utils.cc b/src/test_utils.cc
index f8899e0..0592fc5 100644
--- a/src/test_utils.cc
+++ b/src/test_utils.cc
@@ -18,7 +18,10 @@
 #include <stdint.h>
 #include <string.h>
 
+#include <functional>
 #include <memory>
+#include <span>
+#include <vector>
 
 #include "cose/cose.h"
 #include "dice/boringssl_ecdsa_utils.h"
@@ -28,7 +31,6 @@
 #include "openssl/bn.h"
 #include "openssl/curve25519.h"
 #include "openssl/evp.h"
-#include "openssl/hmac.h"
 #include "openssl/is_boringssl.h"
 #include "openssl/mem.h"
 #include "openssl/sha.h"
@@ -63,6 +65,7 @@ const char* GetKeyTypeStr(dice::test::KeyType key_type) {
     case dice::test::KeyType_Ed25519:
       return "Ed25519";
     case dice::test::KeyType_P256:
+    case dice::test::KeyType_P256_COMPRESSED:
       return "P256";
     case dice::test::KeyType_P384:
       return "P384";
@@ -87,83 +90,21 @@ void DumpToFile(const char* filename, const uint8_t* data, size_t size) {
   }
 }
 
-// A simple hmac-drbg to help with deterministic ecdsa.
-class HmacSha512Drbg {
- public:
-  HmacSha512Drbg(const uint8_t seed[32]) {
-    Init();
-    Update(seed, 32);
-  }
-  ~HmacSha512Drbg() { HMAC_CTX_cleanup(&ctx_); }
-
-  // Populates |num_bytes| random bytes into |buffer|.
-  void GetBytes(size_t num_bytes, uint8_t* buffer) {
-    size_t bytes_written = 0;
-    while (bytes_written < num_bytes) {
-      size_t bytes_to_copy = num_bytes - bytes_written;
-      if (bytes_to_copy > 64) {
-        bytes_to_copy = 64;
-      }
-      Hmac(v_, v_);
-      memcpy(&buffer[bytes_written], v_, bytes_to_copy);
-      bytes_written += bytes_to_copy;
-    }
-    Update0();
-  }
-
- private:
-  void Init() {
-    memset(k_, 0, 64);
-    memset(v_, 1, 64);
-    HMAC_CTX_init(&ctx_);
-  }
-
-  void Hmac(uint8_t in[64], uint8_t out[64]) {
-    HmacStart();
-    HmacUpdate(in, 64);
-    HmacFinish(out);
-  }
-
-  void HmacStart() {
-    HMAC_Init_ex(&ctx_, k_, 64, EVP_sha512(), nullptr /* impl */);
-  }
-
-  void HmacUpdate(const uint8_t* data, size_t data_size) {
-    HMAC_Update(&ctx_, data, data_size);
-  }
-
-  void HmacUpdateByte(uint8_t byte) { HmacUpdate(&byte, 1); }
-
-  void HmacFinish(uint8_t out[64]) {
-    unsigned int out_len = 64;
-    HMAC_Final(&ctx_, out, &out_len);
-  }
-
-  void Update(const uint8_t* data, size_t data_size) {
-    HmacStart();
-    HmacUpdate(v_, 64);
-    HmacUpdateByte(0x00);
-    if (data_size > 0) {
-      HmacUpdate(data, data_size);
-    }
-    HmacFinish(k_);
-    Hmac(v_, v_);
-    if (data_size > 0) {
-      HmacStart();
-      HmacUpdate(v_, 64);
-      HmacUpdateByte(0x01);
-      HmacUpdate(data, data_size);
-      HmacFinish(k_);
-      Hmac(v_, v_);
-    }
-  }
-
-  void Update0() { Update(nullptr, 0); }
-
-  uint8_t k_[64];
-  uint8_t v_[64];
-  HMAC_CTX ctx_;
-};
+bssl::UniquePtr<EVP_PKEY> EcKeyFromCoords(
+    int nid, uint8_t raw_public_key[MAX_PUBLIC_KEY_SIZE],
+    size_t public_key_size) {
+  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
+  BIGNUM* x = BN_new();
+  BN_bin2bn(&raw_public_key[0], public_key_size / 2, x);
+  BIGNUM* y = BN_new();
+  BN_bin2bn(&raw_public_key[public_key_size / 2], public_key_size / 2, y);
+  EC_KEY_set_public_key_affine_coordinates(key.get(), x, y);
+  BN_clear_free(y);
+  BN_clear_free(x);
+  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
+  EVP_PKEY_set1_EC_KEY(pkey.get(), key.get());
+  return pkey;
+}
 
 bssl::UniquePtr<EVP_PKEY> KeyFromRawKey(
     const uint8_t raw_key[DICE_PRIVATE_KEY_SEED_SIZE],
@@ -176,32 +117,24 @@ bssl::UniquePtr<EVP_PKEY> KeyFromRawKey(
     *raw_public_key_size = 32;
     EVP_PKEY_get_raw_public_key(key.get(), raw_public_key, raw_public_key_size);
     return key;
-  } else if (key_type == dice::test::KeyType_P256) {
-    bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
-    const EC_GROUP* group = EC_KEY_get0_group(key.get());
-    bssl::UniquePtr<EC_POINT> pub(EC_POINT_new(group));
-    // Match the algorithm described in RFC6979 and seed with the raw key.
-    HmacSha512Drbg drbg(raw_key);
-    while (true) {
-      uint8_t tmp[32];
-      drbg.GetBytes(32, tmp);
-      bssl::UniquePtr<BIGNUM> candidate(BN_bin2bn(tmp, 32, /*ret=*/nullptr));
-      if (BN_cmp(candidate.get(), EC_GROUP_get0_order(group)) < 0 &&
-          !BN_is_zero(candidate.get())) {
-        // Candidate is suitable.
-        EC_POINT_mul(group, pub.get(), candidate.get(), /*q=*/nullptr,
-                     /*m=*/nullptr,
-                     /*ctx=*/nullptr);
-        EC_KEY_set_public_key(key.get(), pub.get());
-        EC_KEY_set_private_key(key.get(), candidate.get());
-        break;
-      }
+  } else if (key_type == dice::test::KeyType_P256 ||
+             key_type == dice::test::KeyType_P256_COMPRESSED) {
+    const size_t kPublicKeySize = 64;
+    const size_t kPrivateKeySize = 32;
+    uint8_t pk[kPrivateKeySize];
+    P256KeypairFromSeed(raw_public_key, pk, raw_key);
+    bssl::UniquePtr<EVP_PKEY> pkey =
+        EcKeyFromCoords(NID_X9_62_prime256v1, raw_public_key, kPublicKeySize);
+    if (key_type == dice::test::KeyType_P256_COMPRESSED) {
+      const EC_KEY* key = EVP_PKEY_get0_EC_KEY(pkey.get());
+      const EC_GROUP* group = EC_KEY_get0_group(key);
+      const EC_POINT* pub = EC_KEY_get0_public_key(key);
+      *raw_public_key_size = EC_POINT_point2oct(
+          group, pub, POINT_CONVERSION_COMPRESSED, raw_public_key,
+          MAX_PUBLIC_KEY_SIZE, /*ctx=*/nullptr);
+    } else {
+      *raw_public_key_size = kPublicKeySize;
     }
-    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
-    EVP_PKEY_set1_EC_KEY(pkey.get(), key.get());
-    *raw_public_key_size =
-        EC_POINT_point2oct(group, pub.get(), POINT_CONVERSION_COMPRESSED,
-                           raw_public_key, 33, /*ctx=*/nullptr);
     return pkey;
   } else if (key_type == dice::test::KeyType_P384) {
     const size_t kPublicKeySize = 96;
@@ -209,18 +142,7 @@ bssl::UniquePtr<EVP_PKEY> KeyFromRawKey(
     uint8_t pk[kPrivateKeySize];
     P384KeypairFromSeed(raw_public_key, pk, raw_key);
     *raw_public_key_size = kPublicKeySize;
-
-    bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_secp384r1));
-    BIGNUM* x = BN_new();
-    BN_bin2bn(&raw_public_key[0], kPublicKeySize / 2, x);
-    BIGNUM* y = BN_new();
-    BN_bin2bn(&raw_public_key[kPublicKeySize / 2], kPublicKeySize / 2, y);
-    EC_KEY_set_public_key_affine_coordinates(key.get(), x, y);
-    BN_clear_free(y);
-    BN_clear_free(x);
-    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
-    EVP_PKEY_set1_EC_KEY(pkey.get(), key.get());
-    return pkey;
+    return EcKeyFromCoords(NID_secp384r1, raw_public_key, kPublicKeySize);
   }
 
   printf("ERROR: Unsupported key type.\n");
@@ -408,42 +330,37 @@ void CreateEd25519CborUdsCertificate(
       certificate, 0, dice::test::kTestCertSize, sign1.get());
 }
 
-void CreateP384CborUdsCertificate(
-    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
-    const uint8_t id[DICE_ID_SIZE],
+void CreateEcdsaCborUdsCertificate(
+    std::span<uint8_t> public_key,
+    std::function<std::vector<uint8_t>(std::span<uint8_t>)> sign,
+    const uint8_t id[DICE_ID_SIZE], int8_t alg, uint8_t crv,
     uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
   const int64_t kCwtIssuerLabel = 1;
   const int64_t kCwtSubjectLabel = 2;
   const int64_t kUdsPublicKeyLabel = -4670552;
   const int64_t kUdsKeyUsageLabel = -4670553;
   const uint8_t kKeyUsageCertSign = 32;  // Bit 5.
-  const uint8_t kProtectedAttributesCbor[4] = {
-      0xa1 /* map(1) */, 0x01 /* alg(1) */, 0x38, 0x22 /* ES384(-34) */};
-  const size_t kPublicKeySize = 96;
-  const size_t kPrivateKeySize = 48;
-  const size_t kSignatureSize = 96;
+  const uint8_t kProtectedAttributesCbor[4] = {0xa1 /* map(1) */,
+                                               0x01 /* alg(1) */, 0x38,
+                                               static_cast<uint8_t>(-alg - 1)};
 
-  // Public key encoded as a COSE_Key.
-  uint8_t public_key[kPublicKeySize];
-  uint8_t private_key[kPrivateKeySize];
-  P384KeypairFromSeed(public_key, private_key, private_key_seed);
   cn_cbor_errback error;
   ScopedCbor public_key_cbor(cn_cbor_map_create(&error));
   // kty = ec2
   cn_cbor_mapput_int(public_key_cbor.get(), 1, cn_cbor_int_create(2, &error),
                      &error);
-  // crv = P-384
-  cn_cbor_mapput_int(public_key_cbor.get(), -1, cn_cbor_int_create(2, &error),
+  // crv
+  cn_cbor_mapput_int(public_key_cbor.get(), -1, cn_cbor_int_create(crv, &error),
                      &error);
   // x = public_key X
-  cn_cbor_mapput_int(
-      public_key_cbor.get(), -2,
-      cn_cbor_data_create(&public_key[0], kPublicKeySize / 2, &error), &error);
-  // y = public_key Y
-  cn_cbor_mapput_int(public_key_cbor.get(), -3,
-                     cn_cbor_data_create(&public_key[kPublicKeySize / 2],
-                                         kPublicKeySize / 2, &error),
+  size_t coord_size = public_key.size() / 2;
+  cn_cbor_mapput_int(public_key_cbor.get(), -2,
+                     cn_cbor_data_create(&public_key[0], coord_size, &error),
                      &error);
+  // y = public_key Y
+  cn_cbor_mapput_int(
+      public_key_cbor.get(), -3,
+      cn_cbor_data_create(&public_key[coord_size], coord_size, &error), &error);
   uint8_t encoded_public_key[200];
   size_t encoded_public_key_size =
       cn_cbor_encoder_write(encoded_public_key, 0, 200, public_key_cbor.get());
@@ -484,8 +401,7 @@ void CreateP384CborUdsCertificate(
   uint8_t tbs[dice::test::kTestCertSize];
   size_t tbs_size =
       cn_cbor_encoder_write(tbs, 0, dice::test::kTestCertSize, tbs_cbor.get());
-  uint8_t signature[kSignatureSize];
-  P384Sign(signature, tbs, tbs_size, private_key);
+  std::vector signature = sign({tbs, tbs_size});
 
   // COSE Sign1.
   ScopedCbor sign1(cn_cbor_array_create(&error));
@@ -495,13 +411,63 @@ void CreateP384CborUdsCertificate(
   cn_cbor_array_append(sign1.get(), cn_cbor_map_create(&error), &error);
   cn_cbor_array_append(
       sign1.get(), cn_cbor_data_create(payload, payload_size, &error), &error);
-  cn_cbor_array_append(sign1.get(),
-                       cn_cbor_data_create(signature, kSignatureSize, &error),
-                       &error);
+  cn_cbor_array_append(
+      sign1.get(),
+      cn_cbor_data_create(signature.data(), signature.size(), &error), &error);
   *certificate_size = cn_cbor_encoder_write(
       certificate, 0, dice::test::kTestCertSize, sign1.get());
 }
 
+void CreateP256CborUdsCertificate(
+    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    const uint8_t id[DICE_ID_SIZE],
+    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
+  const int8_t kAlgEs256 = -7;
+  const uint8_t kCrvP256 = 1;
+  const size_t kPublicKeySize = 64;
+  const size_t kPrivateKeySize = 32;
+  const size_t kSignatureSize = 64;
+
+  // Public key encoded as a COSE_Key.
+  uint8_t public_key[kPublicKeySize];
+  uint8_t private_key[kPrivateKeySize];
+  P256KeypairFromSeed(public_key, private_key, private_key_seed);
+
+  auto sign = [&](std::span<uint8_t> tbs) {
+    std::vector<uint8_t> signature(kSignatureSize);
+    P256Sign(signature.data(), tbs.data(), tbs.size(), private_key);
+    return signature;
+  };
+
+  CreateEcdsaCborUdsCertificate(public_key, sign, id, kAlgEs256, kCrvP256,
+                                certificate, certificate_size);
+}
+
+void CreateP384CborUdsCertificate(
+    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
+    const uint8_t id[DICE_ID_SIZE],
+    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
+  const int8_t kAlgEs384 = -35;
+  const uint8_t kCrvP384 = 2;
+  const size_t kPublicKeySize = 96;
+  const size_t kPrivateKeySize = 48;
+  const size_t kSignatureSize = 96;
+
+  // Public key encoded as a COSE_Key.
+  uint8_t public_key[kPublicKeySize];
+  uint8_t private_key[kPrivateKeySize];
+  P384KeypairFromSeed(public_key, private_key, private_key_seed);
+
+  auto sign = [&](std::span<uint8_t> tbs) {
+    std::vector<uint8_t> signature(kSignatureSize);
+    P384Sign(signature.data(), tbs.data(), tbs.size(), private_key);
+    return signature;
+  };
+
+  CreateEcdsaCborUdsCertificate(public_key, sign, id, kAlgEs384, kCrvP384,
+                                certificate, certificate_size);
+}
+
 void CreateCborUdsCertificate(
     const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
     dice::test::KeyType key_type, const uint8_t id[DICE_ID_SIZE],
@@ -512,10 +478,12 @@ void CreateCborUdsCertificate(
                                       certificate_size);
       break;
     case dice::test::KeyType_P256:
-      printf(
-          "Error: encountered unsupported KeyType P256 when creating CBOR UDS "
-          "certificate\n");
+      CreateP256CborUdsCertificate(private_key_seed, id, certificate,
+                                   certificate_size);
       break;
+    case dice::test::KeyType_P256_COMPRESSED:
+      fprintf(stderr, "ERROR: Unsupported key type.\n");
+      abort();
     case dice::test::KeyType_P384:
       CreateP384CborUdsCertificate(private_key_seed, id, certificate,
                                    certificate_size);
diff --git a/third_party/boringssl/BUILD.gn b/third_party/boringssl/BUILD.gn
index bde1a77..dc9ea25 100644
--- a/third_party/boringssl/BUILD.gn
+++ b/third_party/boringssl/BUILD.gn
@@ -38,9 +38,23 @@ config("internal_config") {
   ]
 }
 
+config("no_cast_function_type_warnings") {
+  cflags = [
+    # Disable "-Wcast-fuction-type-strict"
+    # and "-Wcast-function-type-mismatch"  which enforce an exact type match
+    # between a function pointer and the target function.
+    "-Wno-cast-function-type-strict",
+    "-Wno-cast-function-type-mismatch",
+    "-Wno-unknown-warning-option",
+  ]
+}
+
 pw_static_library("crypto") {
   sources = crypto_sources
   public = crypto_headers
   public_configs = [ ":external_config" ]
-  configs = [ ":internal_config" ]
+  configs = [
+    ":internal_config",
+    ":no_cast_function_type_warnings",
+  ]
 }
diff --git a/third_party/cose-c/BUILD.gn b/third_party/cose-c/BUILD.gn
index e5a46aa..6d26a92 100644
--- a/third_party/cose-c/BUILD.gn
+++ b/third_party/cose-c/BUILD.gn
@@ -22,6 +22,13 @@ config("external_config_ed25519") {
   ]
 }
 
+config("external_config_p256") {
+  include_dirs = [
+    "src/include",
+    "include/p256",
+  ]
+}
+
 config("external_config_p384") {
   include_dirs = [
     "src/include",
@@ -35,15 +42,17 @@ config("internal_config") {
   cflags = [ "-Wno-cast-qual" ]
 }
 
+cose_c_sources = [
+  "cose_deps.cc",
+  "src/src/Cose.cpp",
+  "src/src/CoseKey.cpp",
+  "src/src/Sign1.cpp",
+  "src/src/cbor.cpp",
+]
+
 pw_static_library("cose-c_ed25519") {
   public = [ "src/include/cose/cose.h" ]
-  sources = [
-    "cose_ed25519_deps.cc",
-    "src/src/Cose.cpp",
-    "src/src/CoseKey.cpp",
-    "src/src/Sign1.cpp",
-    "src/src/cbor.cpp",
-  ]
+  sources = cose_c_sources
   public_configs = [ ":external_config_ed25519" ]
   configs = [ ":internal_config" ]
   public_deps = [
@@ -52,15 +61,20 @@ pw_static_library("cose-c_ed25519") {
   ]
 }
 
-pw_static_library("cose-c_p384") {
+pw_static_library("cose-c_p256") {
   public = [ "src/include/cose/cose.h" ]
-  sources = [
-    "cose_p384_deps.cc",
-    "src/src/Cose.cpp",
-    "src/src/CoseKey.cpp",
-    "src/src/Sign1.cpp",
-    "src/src/cbor.cpp",
+  sources = cose_c_sources
+  public_configs = [ ":external_config_p256" ]
+  configs = [ ":internal_config" ]
+  public_deps = [
+    "//third_party/boringssl:crypto",
+    "//third_party/cn-cbor:cn-cbor",
   ]
+}
+
+pw_static_library("cose-c_p384") {
+  public = [ "src/include/cose/cose.h" ]
+  sources = cose_c_sources
   public_configs = [ ":external_config_p384" ]
   configs = [ ":internal_config" ]
   public_deps = [
diff --git a/third_party/cose-c/cose_deps.cc b/third_party/cose-c/cose_deps.cc
new file mode 100644
index 0000000..33c2d57
--- /dev/null
+++ b/third_party/cose-c/cose_deps.cc
@@ -0,0 +1,235 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License"); you may not
+// use this file except in compliance with the License. You may obtain a copy of
+// the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+// License for the specific language governing permissions and limitations under
+// the License.
+
+#include <stdint.h>
+#include <string.h>
+
+#include <optional>
+
+#include "cose/cose.h"
+#include "cose/cose_configure.h"
+#include "cose_int.h"
+#include "openssl/bn.h"
+#include "openssl/curve25519.h"
+#include "openssl/ec.h"
+#include "openssl/ec_key.h"
+#include "openssl/ecdsa.h"
+#include "openssl/evp.h"
+#include "openssl/is_boringssl.h"
+#include "openssl/sha.h"
+
+namespace {
+
+// Checks the type and ops have the expected values.
+bool CheckCoseKeyTypeAndOps(const cn_cbor *key, uint64_t expected_type) {
+  const int64_t kCoseKeyOpsLabel = 4;
+  const uint64_t kCoseKeyOpsVerify = 2;
+
+  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
+  if (!type) {
+    return false;
+  }
+  if (type->type != CN_CBOR_UINT || type->v.uint != expected_type) {
+    return false;
+  }
+
+  cn_cbor *ops = cn_cbor_mapget_int(key, kCoseKeyOpsLabel);
+  if (ops) {
+    if (ops->type != CN_CBOR_ARRAY || ops->length == 0) {
+      return false;
+    }
+    bool found_verify = false;
+    for (size_t i = 0; i < ops->length; ++i) {
+      cn_cbor *item = cn_cbor_index(ops, i);
+      if (!item || item->type != CN_CBOR_UINT) {
+        return false;
+      }
+      if (item->v.uint == kCoseKeyOpsVerify) {
+        found_verify = true;
+      }
+    }
+    if (!found_verify) {
+      return false;
+    }
+  }
+  return true;
+}
+
+// Checks that the optional algorithm field is the expected value.
+bool CheckCoseKeyAlg(const cn_cbor *key, int64_t expected_alg) {
+  const int64_t kCoseKeyAlgLabel = 3;
+
+  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
+  if (alg) {
+    if (alg->type != CN_CBOR_INT || alg->v.sint != expected_alg) {
+      return false;
+    }
+  }
+  return true;
+}
+
+// Gets the public key from a well-formed EC2 COSE_Key.
+std::optional<bssl::UniquePtr<EC_KEY>> GetEcKey(cn_cbor *key, int nid,
+                                                size_t coord_size) {
+  cn_cbor *raw_x = cn_cbor_mapget_int(key, COSE_Key_EC2_X);
+  if (!raw_x || raw_x->type != CN_CBOR_BYTES || raw_x->length != coord_size) {
+    return std::nullopt;
+  }
+
+  cn_cbor *raw_y = cn_cbor_mapget_int(key, COSE_Key_EC2_Y);
+  if (!raw_y || raw_y->type != CN_CBOR_BYTES || raw_y->length != coord_size) {
+    return std::nullopt;
+  }
+
+  bssl::UniquePtr<BIGNUM> x(BN_new());
+  bssl::UniquePtr<BIGNUM> y(BN_new());
+  bssl::UniquePtr<EC_KEY> eckey(EC_KEY_new_by_curve_name(nid));
+  if (!x || !y || !eckey) {
+    return std::nullopt;
+  }
+
+  BN_bin2bn(raw_x->v.bytes, coord_size, x.get());
+  BN_bin2bn(raw_y->v.bytes, coord_size, y.get());
+  if (0 ==
+      EC_KEY_set_public_key_affine_coordinates(eckey.get(), x.get(), y.get())) {
+    return std::nullopt;
+  }
+
+  return eckey;
+}
+
+}  // namespace
+
+// A simple implementation of 'EdDSA_Verify' using boringssl. This function is
+// required by 'COSE_Sign1_validate'.
+bool EdDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
+                  const byte *message, size_t message_size, cose_errback *) {
+  const int64_t kCoseAlgEdDSA = -8;
+
+  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
+  cn_cbor *key = cose_key->m_cborKey;
+  if (!signature || !key) {
+    return false;
+  }
+  if (signature->type != CN_CBOR_BYTES || signature->length != 64) {
+    return false;
+  }
+  if (!CheckCoseKeyTypeAndOps(key, COSE_Key_Type_OKP)) {
+    return false;
+  }
+  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
+  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_OPK_X);
+  if (!curve || !x) {
+    return false;
+  }
+  if (curve->type != CN_CBOR_UINT || curve->v.uint != COSE_Curve_Ed25519) {
+    return false;
+  }
+  if (x->type != CN_CBOR_BYTES || x->length != 32) {
+    return false;
+  }
+  if (!CheckCoseKeyAlg(key, kCoseAlgEdDSA)) {
+    return false;
+  }
+  if (1 !=
+      ED25519_verify(message, message_size, signature->v.bytes, x->v.bytes)) {
+    return false;
+  }
+  return true;
+}
+
+// A stub for 'EdDSA_Sign'. This is unused, but helps make linkers happy.
+bool EdDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
+                COSE_KEY * /*cose_key*/, const byte * /*message*/,
+                size_t /*message_size*/, cose_errback *) {
+  return false;
+}
+
+// A simple implementation of 'ECDSA_Verify' using boringssl. This function is
+// required by 'COSE_Sign1_validate'.
+bool ECDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
+                  int cbitsDigest, const byte *message, size_t message_size,
+                  cose_errback *) {
+  const int64_t kCoseAlgEs256 = -7;
+  const int64_t kCoseAlgEs384 = -35;
+
+  (void)cbitsDigest;
+  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
+  cn_cbor *key = cose_key->m_cborKey;
+  if (!signature || !key) {
+    return false;
+  }
+
+  if (!CheckCoseKeyTypeAndOps(key, COSE_Key_Type_EC2)) {
+    return false;
+  }
+
+  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
+  if (!curve || curve->type != CN_CBOR_UINT) {
+    return false;
+  }
+
+  size_t coord_size;
+  int nid;
+  const EVP_MD *md_type;
+  if (curve->v.uint == COSE_Curve_P256) {
+    if (!CheckCoseKeyAlg(key, kCoseAlgEs256)) {
+      return false;
+    }
+    coord_size = 32;
+    nid = NID_X9_62_prime256v1;
+    md_type = EVP_sha256();
+  } else if (curve->v.uint == COSE_Curve_P384) {
+    if (!CheckCoseKeyAlg(key, kCoseAlgEs384)) {
+      return false;
+    }
+    coord_size = 48;
+    nid = NID_secp384r1;
+    md_type = EVP_sha384();
+  } else {
+    return false;
+  }
+
+  uint8_t md[EVP_MAX_MD_SIZE];
+  unsigned int md_size;
+  if (1 != EVP_Digest(message, message_size, md, &md_size, md_type, nullptr)) {
+    return false;
+  }
+
+  std::optional<bssl::UniquePtr<EC_KEY>> eckey = GetEcKey(key, nid, coord_size);
+  if (!eckey) {
+    return false;
+  }
+
+  if (signature->type != CN_CBOR_BYTES ||
+      signature->length != (coord_size * 2)) {
+    return false;
+  }
+
+  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
+  BN_bin2bn(&signature->v.bytes[0], coord_size, sig->r);
+  BN_bin2bn(&signature->v.bytes[coord_size], coord_size, sig->s);
+  if (1 != ECDSA_do_verify(md, md_size, sig.get(), eckey->get())) {
+    return false;
+  }
+
+  return true;
+}
+
+// A stub for 'ECDSA_Sign'. This is unused, but helps make linkers happy.
+bool ECDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
+                COSE_KEY * /*cose_key*/, const byte * /*message*/,
+                size_t /*message_size*/, cose_errback *) {
+  return false;
+}
diff --git a/third_party/cose-c/cose_ed25519_deps.cc b/third_party/cose-c/cose_ed25519_deps.cc
deleted file mode 100644
index 3d78b60..0000000
--- a/third_party/cose-c/cose_ed25519_deps.cc
+++ /dev/null
@@ -1,105 +0,0 @@
-// Copyright 2020 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License"); you may not
-// use this file except in compliance with the License. You may obtain a copy of
-// the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-// License for the specific language governing permissions and limitations under
-// the License.
-
-#include <stdint.h>
-#include <string.h>
-
-#include "cose/cose.h"
-#include "cose/cose_configure.h"
-#include "cose_int.h"
-#include "openssl/curve25519.h"
-#include "openssl/is_boringssl.h"
-
-// Gets the public key from a well-formed Ed25519 COSE_Key. On success populates
-// |public_key| and returns true.
-static bool GetPublicKeyFromCbor(const cn_cbor *key,
-                                 uint8_t public_key[PUBLIC_KEY_SIZE]) {
-  const int64_t kCoseKeyAlgLabel = 3;
-  const int64_t kCoseKeyOpsLabel = 4;
-  const uint64_t kCoseKeyOpsVerify = 2;
-  const int64_t kCoseAlgEdDSA = -8;
-
-  // Mandatory attributes.
-  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
-  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
-  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_OPK_X);
-  if (!type || !curve || !x) {
-    return false;
-  }
-  if (type->type != CN_CBOR_UINT || type->v.uint != COSE_Key_Type_OKP) {
-    return false;
-  }
-  if (curve->type != CN_CBOR_UINT || curve->v.uint != COSE_Curve_Ed25519) {
-    return false;
-  }
-  if (x->type != CN_CBOR_BYTES || x->length != PUBLIC_KEY_SIZE) {
-    return false;
-  }
-  // Optional attributes.
-  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
-  if (alg) {
-    if (alg->type != CN_CBOR_INT || alg->v.sint != kCoseAlgEdDSA) {
-      return false;
-    }
-  }
-  cn_cbor *ops = cn_cbor_mapget_int(key, kCoseKeyOpsLabel);
-  if (ops) {
-    if (ops->type != CN_CBOR_ARRAY || ops->length == 0) {
-      return false;
-    }
-    bool found_verify = false;
-    for (size_t i = 0; i < ops->length; ++i) {
-      cn_cbor *item = cn_cbor_index(ops, i);
-      if (!item || item->type != CN_CBOR_UINT) {
-        return false;
-      }
-      if (item->v.uint == kCoseKeyOpsVerify) {
-        found_verify = true;
-      }
-    }
-    if (!found_verify) {
-      return false;
-    }
-  }
-
-  memcpy(public_key, x->v.bytes, PUBLIC_KEY_SIZE);
-  return true;
-}
-
-// A simple implementation of 'EdDSA_Verify' using boringssl. This function is
-// required by 'COSE_Sign1_validate'.
-bool EdDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
-                  const byte *message, size_t message_size, cose_errback *) {
-  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
-  cn_cbor *key = cose_key->m_cborKey;
-  if (!signature || !key) {
-    return false;
-  }
-  if (signature->type != CN_CBOR_BYTES || signature->length != 64) {
-    return false;
-  }
-  uint8_t public_key[PUBLIC_KEY_SIZE];
-  if (!GetPublicKeyFromCbor(key, public_key)) {
-    return false;
-  }
-  return (1 == ED25519_verify(message, message_size, signature->v.bytes,
-                              public_key));
-}
-
-// A stub for 'EdDSA_Sign'. This is unused, but helps make linkers happy.
-bool EdDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
-                COSE_KEY * /*cose_key*/, const byte * /*message*/,
-                size_t /*message_size*/, cose_errback *) {
-  return false;
-}
diff --git a/third_party/cose-c/cose_p384_deps.cc b/third_party/cose-c/cose_p384_deps.cc
deleted file mode 100644
index 3b9a9d9..0000000
--- a/third_party/cose-c/cose_p384_deps.cc
+++ /dev/null
@@ -1,149 +0,0 @@
-// Copyright 2023 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License"); you may not
-// use this file except in compliance with the License. You may obtain a copy of
-// the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-// License for the specific language governing permissions and limitations under
-// the License.
-
-#include <stdint.h>
-#include <string.h>
-
-#include "cose/cose.h"
-#include "cose/cose_configure.h"
-#include "cose_int.h"
-#include "openssl/bn.h"
-#include "openssl/ec.h"
-#include "openssl/ec_key.h"
-#include "openssl/ecdsa.h"
-#include "openssl/evp.h"
-#include "openssl/hkdf.h"
-#include "openssl/is_boringssl.h"
-#include "openssl/sha.h"
-
-// Gets the public key from a well-formed ECDSA P-384 COSE_Key. On
-// success populates |public_key| and returns true; public_key must hold 96
-// bytes (uncompressed format).
-static bool GetPublicKeyFromCbor(const cn_cbor *key, uint8_t *public_key) {
-  const int64_t kCoseKeyAlgLabel = 3;
-  const int64_t kCoseKeyOpsLabel = 4;
-  const uint64_t kCoseKeyOpsVerify = 2;
-  const int64_t kCoseAlgEs384 = -35;
-
-  // Mandatory attributes.
-  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
-  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
-  if (!type || !curve) {
-    return false;
-  }
-  if (type->type != CN_CBOR_UINT || curve->type != CN_CBOR_UINT) {
-    return false;
-  }
-
-  if (type->v.uint != COSE_Key_Type_EC2 || curve->v.uint != COSE_Curve_P384) {
-    return false;
-  }
-
-  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_EC2_X);
-  if (!x || x->type != CN_CBOR_BYTES || x->length != (PUBLIC_KEY_SIZE / 2)) {
-    return false;
-  }
-
-  cn_cbor *y = cn_cbor_mapget_int(key, COSE_Key_EC2_Y);
-  if (!y || y->type != CN_CBOR_BYTES || y->length != (PUBLIC_KEY_SIZE / 2)) {
-    return false;
-  }
-
-  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
-  if (alg) {
-    if (alg->type != CN_CBOR_INT || alg->v.sint != kCoseAlgEs384) {
-      return false;
-    }
-  }
-
-  cn_cbor *ops = cn_cbor_mapget_int(key, kCoseKeyOpsLabel);
-  if (ops) {
-    if (ops->type != CN_CBOR_ARRAY || ops->length == 0) {
-      return false;
-    }
-    bool found_verify = false;
-    for (size_t i = 0; i < ops->length; ++i) {
-      cn_cbor *item = cn_cbor_index(ops, i);
-      if (!item || item->type != CN_CBOR_UINT) {
-        return false;
-      }
-      if (item->v.uint == kCoseKeyOpsVerify) {
-        found_verify = true;
-      }
-    }
-    if (!found_verify) {
-      return false;
-    }
-  }
-
-  memcpy(&public_key[0], x->v.bytes, PUBLIC_KEY_SIZE / 2);
-  memcpy(&public_key[PUBLIC_KEY_SIZE / 2], y->v.bytes, PUBLIC_KEY_SIZE / 2);
-  return true;
-}
-
-bool ECDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
-                  int cbitsDigest, const byte *message, size_t message_size,
-                  cose_errback *) {
-  (void)cbitsDigest;
-  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
-  cn_cbor *key = cose_key->m_cborKey;
-  if (!signature || !key) {
-    return false;
-  }
-  if (signature->type != CN_CBOR_BYTES ||
-      signature->length != PUBLIC_KEY_SIZE) {
-    return false;
-  }
-  uint8_t public_key[PUBLIC_KEY_SIZE];
-  if (!GetPublicKeyFromCbor(key, public_key)) {
-    return false;
-  }
-
-  // Implementation of ECDSA verification starts here
-  uint8_t output[48];
-  SHA384(message, message_size, output);
-  EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
-  BIGNUM *x = BN_new();
-  BN_bin2bn(&public_key[0], 48, x);
-  BIGNUM *y = BN_new();
-  BN_bin2bn(&public_key[48], 48, y);
-  int result = EC_KEY_set_public_key_affine_coordinates(eckey, x, y);
-
-  BN_clear_free(y);
-  BN_clear_free(x);
-
-  if (result == 0) {
-    printf("Setting affine coordinates failed\n");
-    return false;
-  }
-
-  ECDSA_SIG *sig = ECDSA_SIG_new();
-  BN_bin2bn(&(signature->v.bytes[0]), 48, sig->r);
-  BN_bin2bn(&(signature->v.bytes[48]), 48, sig->s);
-  result = ECDSA_do_verify(output, 48, sig, eckey);
-
-  EC_KEY_free(eckey);
-  ECDSA_SIG_free(sig);
-  if (1 != result) {
-    return false;
-  }
-  return true;
-}
-
-// A stub for 'ECDSA_Sign'. This is unused, but helps make linkers happy.
-bool ECDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
-                COSE_KEY * /*cose_key*/, const byte * /*message*/,
-                size_t /*message_size*/, cose_errback *) {
-  return false;
-}
diff --git a/third_party/cose-c/include/ed25519/cose/cose_configure.h b/third_party/cose-c/include/ed25519/cose/cose_configure.h
index b487905..8cbccc8 100644
--- a/third_party/cose-c/include/ed25519/cose/cose_configure.h
+++ b/third_party/cose-c/include/ed25519/cose/cose_configure.h
@@ -2,7 +2,6 @@
 #define THIRD_PARTY_COSE_C_ED25519_COSE_COSE_CONFIGURE_H_
 
 #define USE_EDDSA
-#define PUBLIC_KEY_SIZE 32
 
 #define INCLUDE_ENCRYPT 0
 #define INCLUDE_ENCRYPT0 0
diff --git a/third_party/cose-c/include/p256/cose/cose_configure.h b/third_party/cose-c/include/p256/cose/cose_configure.h
new file mode 100644
index 0000000..64b5437
--- /dev/null
+++ b/third_party/cose-c/include/p256/cose/cose_configure.h
@@ -0,0 +1,15 @@
+#ifndef THIRD_PARTY_COSE_C_P256_COSE_COSE_CONFIGURE_H_
+#define THIRD_PARTY_COSE_C_P256_COSE_COSE_CONFIGURE_H_
+
+#define USE_ECDSA_SHA_256
+
+#define INCLUDE_ENCRYPT 0
+#define INCLUDE_ENCRYPT0 0
+#define INCLUDE_MAC 0
+#define INCLUDE_MAC0 0
+#define INCLUDE_SIGN 0
+#define INCLUDE_SIGN1 1
+#define INCLUDE_COUNTERSIGNATURE 0
+#define INCLUDE_COUNTERSIGNATURE1 0
+
+#endif  // THIRD_PARTY_COSE_C_P256_COSE_COSE_CONFIGURE_H_
diff --git a/third_party/cose-c/include/p384/cose/cose_configure.h b/third_party/cose-c/include/p384/cose/cose_configure.h
index 5ddf8d7..1559fc7 100644
--- a/third_party/cose-c/include/p384/cose/cose_configure.h
+++ b/third_party/cose-c/include/p384/cose/cose_configure.h
@@ -2,7 +2,6 @@
 #define THIRD_PARTY_COSE_C_P384_COSE_COSE_CONFIGURE_H_
 
 #define USE_ECDSA_SHA_384
-#define PUBLIC_KEY_SIZE 96
 
 #define INCLUDE_ENCRYPT 0
 #define INCLUDE_ENCRYPT0 0
```

