```diff
diff --git a/app/finger_guard/rules.mk b/app/finger_guard/rules.mk
index 47a6151..1c2b6c6 100644
--- a/app/finger_guard/rules.mk
+++ b/app/finger_guard/rules.mk
@@ -20,15 +20,18 @@ MODULE := $(LOCAL_DIR)
 MANIFEST := $(LOCAL_DIR)/manifest.json
 
 MODULE_SRCS += \
-	$(LOCAL_DIR)/lib.rs \
+	$(LOCAL_DIR)/src/lib.rs \
 
 MODULE_CRATE_NAME := finger_guard
 
 MODULE_LIBRARY_DEPS += \
 	$(call FIND_CRATE,log) \
 	$(call FIND_CRATE,zerocopy) \
+	$(call FIND_CRATE,thiserror) \
+	$(call FIND_CRATE,once_cell) \
 	trusty/user/base/lib/keymint-rust/boringssl \
 	trusty/user/base/lib/keymint-rust/common \
+	trusty/user/base/lib/keymint-rust/wire \
 	trusty/user/base/lib/openssl-rust \
 	trusty/user/base/lib/storage/rust \
 	trusty/user/base/lib/tipc/rust \
diff --git a/app/finger_guard/service.rs b/app/finger_guard/service.rs
deleted file mode 100644
index c58cf7e..0000000
--- a/app/finger_guard/service.rs
+++ /dev/null
@@ -1,99 +0,0 @@
-use crate::rng;
-use binder::Interface;
-use fingerguard_api::aidl::IFingerGuard::IFingerGuard;
-use kmr_common::crypto::Rng;
-use log::error;
-use storage::{OpenMode, Port, Session};
-use tipc::TipcError;
-use trusty_sys::Error;
-
-#[derive(Hash, Eq, PartialEq, Debug)]
-struct SensorStateIndex {
-    sensor_id: i32,
-    user_id: i32,
-}
-
-impl SensorStateIndex {
-    fn authenticator_id_file_name(&self) -> String {
-        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
-    }
-}
-
-fn deserialize_authenticator_id(buffer: &[u8]) -> Result<i64, TipcError> {
-    if let Ok(buffer) = buffer.try_into() {
-        return Ok(i64::from_ne_bytes(buffer));
-    }
-    error!("failed to deserialize the auth id from buffer: expected size 8, got {}", buffer.len());
-    Err(TipcError::SystemError(Error::BadState))
-}
-
-/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
-pub struct FingerGuardService {}
-
-impl FingerGuardService {
-    pub fn new() -> Self {
-        Self {}
-    }
-
-    fn read_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
-        let index = SensorStateIndex { sensor_id, user_id };
-        let file_name = index.authenticator_id_file_name();
-        let mut session = Session::new(Port::TamperDetect, false).map_err(|e| {
-            error!("failed to create storage session: {:?}", e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        let secure_file = session.open_file(&file_name, OpenMode::Create).map_err(|e| {
-            error!("failed to open file {}: {:?}", file_name, e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        let file_size = session.get_size(&secure_file).map_err(|e| {
-            error!("failed to get file size for {}: {:?}", file_name, e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        let mut buffer = vec![0; file_size];
-        let content = session.read_all(&secure_file, buffer.as_mut_slice()).map_err(|e| {
-            error!("failed to read file bytes for {}: {:?}", file_name, e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        // By the HAL definition, When no authenticator id was ever generated, return 0.
-        if content.len() == 0 {
-            return Ok(0_i64);
-        }
-        deserialize_authenticator_id(&content)
-    }
-
-    fn generate_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
-        let mut rng = rng::TrustyRng::default();
-        let mut buffer = [0u8; 8];
-        rng.fill_bytes(&mut buffer[..]);
-        let authenticator_id = deserialize_authenticator_id(&buffer)?;
-        let index = SensorStateIndex { sensor_id, user_id };
-        let file_name = index.authenticator_id_file_name();
-        let mut session = Session::new(Port::TamperDetect, true).map_err(|e| {
-            error!("failed to create storage session: {:?}", e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        let mut secure_file = session.open_file(&file_name, OpenMode::Create).map_err(|e| {
-            error!("failed to open file {}: {:?}", file_name, e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        session.write_all(&mut secure_file, &buffer).map_err(|e| {
-            error!("failed to write the serialized auth id to {}: {:?}", file_name, e);
-            TipcError::SystemError(Error::BadState)
-        })?;
-        Ok(authenticator_id)
-    }
-}
-
-impl Interface for FingerGuardService {}
-
-impl IFingerGuard for FingerGuardService {
-    fn getAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
-        FingerGuardService::read_authenticator_id(&self, sensor_id, user_id)
-            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
-    }
-    fn newAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
-        FingerGuardService::generate_authenticator_id(&self, sensor_id, user_id)
-            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
-    }
-}
diff --git a/app/finger_guard/src/clock.rs b/app/finger_guard/src/clock.rs
new file mode 100644
index 0000000..2413cf2
--- /dev/null
+++ b/app/finger_guard/src/clock.rs
@@ -0,0 +1,65 @@
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
+//! Trusty system clock util functions.
+use crate::error::{ServiceError, ServiceResult};
+use std::ops::Add;
+use std::time::Duration;
+
+/// Newtype for the time elaspsed in nanoseconds.
+#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
+pub struct Instant(i64);
+
+impl Instant {
+    pub fn to_nanos(&self) -> i64 {
+        self.0
+    }
+}
+
+impl Add<Duration> for Instant {
+    type Output = Instant;
+
+    /// # Panics
+    ///
+    /// This function may panic if the result exceeds i64::MAX or the duration's
+    /// nanos representation is greater than i64::MAX. In practice, it should
+    /// never happen as either the duration is greater than ~292 years or the
+    /// result instant is ~292 years since boot.
+    /// For the actual usage of fingerprint auth rate limiting and timeout, the
+    /// duration is at most several hours, so panic shall never be a problem.
+    fn add(self, other: Duration) -> Instant {
+        let other_nanos =
+            i64::try_from(other.as_nanos()).expect("overflow with duration conversion");
+        Self(self.0.checked_add(other_nanos).expect("overflow when adding duration to instant"))
+    }
+}
+
+pub fn elapsed_real_time_milli() -> ServiceResult<i64> {
+    let instant = now()?;
+    Ok(instant.to_nanos() / (1000 * 1000))
+}
+
+/// Returns nanoseconds since boot, including time spent in sleep.
+pub fn now() -> ServiceResult<Instant> {
+    let mut time_ns = 0;
+    //Safety: trivial, external syscall gets valid raw pointer to a `i64`.
+    let rc = unsafe { trusty_sys::gettime(0, 0, &mut time_ns) };
+    if rc < 0 {
+        Err(ServiceError::TrustySysRcError("gettime", rc))
+    } else {
+        Ok(Instant(time_ns))
+    }
+}
diff --git a/app/finger_guard/src/crypto.rs b/app/finger_guard/src/crypto.rs
new file mode 100644
index 0000000..7aedb6a
--- /dev/null
+++ b/app/finger_guard/src/crypto.rs
@@ -0,0 +1,239 @@
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
+//! Cryptographic operations used by the finger guard service.
+
+use crate::error::{ServiceError, ServiceResult};
+use crate::storage::{SensorSessionCounter, SensorStateIndex};
+use fingerguard_api::aidl::HardwareAuthToken::HardwareAuthToken;
+use openssl::bn::BigNumContext;
+use openssl::derive::Deriver;
+use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
+use openssl::hmac::HmacCtx;
+use openssl::md::Md;
+use openssl::nid::Nid;
+use openssl::pkey::{PKey, Private, Public};
+use openssl::symm::Cipher;
+
+/// Standard size for most chunks of entropy.
+pub const ENTROPY_SIZE: usize = 32;
+/// Standard fixed-size block of entropy, generally a key.
+pub type FixedSizeEntropy = [u8; ENTROPY_SIZE];
+
+/// The type of EC used by finger_guard.
+pub const NIST_P256_CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;
+
+/// Generate a new EC private key.
+pub fn ec_keygen() -> Result<EcKey<Private>, openssl::error::ErrorStack> {
+    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
+    let server_private_key = EcKey::generate(&group)?;
+    Ok(server_private_key)
+}
+
+/// Serialize a given EC private key into a blob of bytes.
+pub fn ec_public_key_serialization(
+    private_key: &EcKey<Private>,
+) -> Result<Vec<u8>, openssl::error::ErrorStack> {
+    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
+    let mut ctx = BigNumContext::new()?;
+    let server_public_key_bytes =
+        private_key.public_key().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;
+    Ok(server_public_key_bytes)
+}
+
+/// Perform a DH exchange using a private and public key, returning the new private key.
+pub fn perform_ecdh(
+    server_private_key: &PKey<Private>,
+    client_public_key_bytes: &[u8],
+) -> Result<Vec<u8>, openssl::error::ErrorStack> {
+    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
+    let mut ctx = BigNumContext::new()?;
+    let client_public_point = EcPoint::from_bytes(&group, &client_public_key_bytes, &mut ctx)?;
+    let client_public_key: PKey<Public> =
+        EcKey::from_public_key(&group, &client_public_point)?.try_into()?;
+    let mut pk_deriver = Deriver::new(&server_private_key)?;
+    pk_deriver.set_peer(&client_public_key)?;
+    let pk = pk_deriver.derive_to_vec()?;
+    Ok(pk)
+}
+
+/// Encrypt a message using AES256-GCM with the given Hmac as a key.
+pub fn encrypt_aes256_gcm(
+    key: &Hmac,
+    iv: Option<&[u8]>,
+    aad: &[u8],
+    data: &[u8],
+    tag: &mut [u8],
+) -> Result<Vec<u8>, openssl::error::ErrorStack> {
+    openssl::symm::encrypt_aead(Cipher::aes_256_gcm(), key.bytes.as_slice(), iv, aad, data, tag)
+}
+
+/// Decrypt a message using AES256-GCM with the given Hmac as a key.
+#[allow(dead_code)]
+pub fn decrypt_aes256_gcm(
+    key: &Hmac,
+    iv: Option<&[u8]>,
+    aad: &[u8],
+    data: &[u8],
+    tag: &[u8],
+) -> Result<Vec<u8>, openssl::error::ErrorStack> {
+    openssl::symm::decrypt_aead(Cipher::aes_256_gcm(), key.bytes.as_slice(), iv, aad, data, tag)
+}
+
+pub enum MessageSender {
+    FINGERGUARD,
+    FPMCU,
+}
+
+pub enum SensorSessionType {
+    ENROLL,
+    AUTH,
+}
+
+/// Size of an HMAC, in bytes.
+pub const HMAC_SIZE: usize = 32; // These are SHA-256 HMACs.
+
+/// Object representing an HMAC.
+///
+/// An HMAC is ultimately just a blob of bytes, but this type restricts the operations that can be
+/// performed on it to give us more control over how it is used.
+pub struct Hmac {
+    bytes: [u8; HMAC_SIZE],
+}
+
+/// Compare an HMAC to a given blob of bytes.
+///
+/// This is done with a constant-time comparison to avoid timing attacks.
+impl PartialEq<&[u8]> for Hmac {
+    fn eq(&self, other: &&[u8]) -> bool {
+        openssl::memcmp::eq(&self.bytes, other)
+    }
+}
+
+/// Allow Hmac to be converted to a Vec<u8> for external export.
+///
+/// This should not be used internally to extract the bytes of the HMAC and perform operations on
+/// them. Instead, any such computations should be added as methods on the Hmac struct.
+impl From<Hmac> for Vec<u8> {
+    fn from(value: Hmac) -> Self {
+        value.bytes.to_vec()
+    }
+}
+
+/// Generator which can consume bytes and produce an HMAC.
+///
+/// The HMACs used by finger guard are based on SHA-256 hashes.
+pub struct HmacGenerator {
+    context: HmacCtx,
+}
+
+impl HmacGenerator {
+    /// Construct a new HMAC generator that will use the given key.
+    pub fn new(key: &FixedSizeEntropy) -> ServiceResult<Self> {
+        Ok(Self {
+            context: HmacCtx::new(key, Md::sha256())
+                .map_err(|e| ServiceError::OpenSsl("unable to initialize hmac", e))?,
+        })
+    }
+
+    /// Construct a new HMAC generator that will use the given HMAC as the key.
+    pub fn with_hmac_key(key: &Hmac) -> ServiceResult<Self> {
+        Ok(Self {
+            context: HmacCtx::new(&key.bytes, Md::sha256())
+                .map_err(|e| ServiceError::OpenSsl("unable to initialize hmac", e))?,
+        })
+    }
+
+    /// Update the HMAC with the given chunk of bytes.
+    pub fn update(&mut self, buffer: &[u8]) -> ServiceResult<()> {
+        self.context.update(buffer).map_err(|e| ServiceError::OpenSsl("unable to update hmac", e))
+    }
+
+    /// Complete the generation of the HMAC, returning the final result.
+    pub fn complete(mut self) -> ServiceResult<Hmac> {
+        let mut hmac = Hmac { bytes: Default::default() };
+        self.context
+            .finalize(hmac.bytes.as_mut_slice())
+            .map_err(|e| ServiceError::OpenSsl("unable to finalize hmac", e))?;
+        Ok(hmac)
+    }
+
+    /// Compute an HMAC using the given key and buffer.
+    ///
+    /// This is a useful helper method that simplifies the very common case of
+    /// computing an HMAC using a single pre-existing buffer of bytes.
+    pub fn compute(key: &FixedSizeEntropy, buffer: &[u8]) -> ServiceResult<Hmac> {
+        let mut generator = Self::new(key)?;
+        generator.update(buffer)?;
+        Ok(generator.complete()?)
+    }
+}
+
+/// Helper to compute the HMAC for the enrollment/authentication
+/// session messages from this service or from the sensor.
+pub fn sensor_session_message_hmac(
+    key: &Hmac,
+    nonce: &FixedSizeEntropy,
+    sender: MessageSender,
+    session_type: SensorSessionType,
+    ssi: &SensorStateIndex,
+    session_counter: &SensorSessionCounter,
+) -> ServiceResult<Hmac> {
+    let sender_name: &[u8] = match sender {
+        MessageSender::FINGERGUARD => b"fingerguard",
+        MessageSender::FPMCU => b"fpmcu",
+    };
+    let session_name: &[u8] = match session_type {
+        SensorSessionType::ENROLL => b"enroll",
+        SensorSessionType::AUTH => b"auth",
+    };
+    //
+    // Compute mac as HMAC_SHA256(key, msg) where
+    // msg = nonce || user_id || sender_name || session_name || session_counter
+    //
+    let mut generator = HmacGenerator::with_hmac_key(key)?;
+    generator.update(nonce.as_slice())?;
+    generator.update(&ssi.user_id_be_bytes())?;
+    generator.update(sender_name)?;
+    generator.update(session_name)?;
+    generator.update(&session_counter.as_i64().to_be_bytes())?;
+    Ok(generator.complete()?)
+}
+
+/// Helper to compute the MAC for a given HardwareAuthToken.
+/// The MAC is a 32 bytes HMAC-SHA256 with the auth token signing key over the
+/// following string
+///         version || challenge || user_id || authenticator_id || authenticator_type || timestamp
+///
+/// where ``||'' represents concatenation, the leading version is a single
+/// byte, and all integers are represented as unsigned values, the full width
+/// of the type.  The challenge, userId and authenticatorId values are in
+/// machine order, but authenticatorType and timestamp are in network order
+/// (big-endian). This odd construction is compatible with the hw_auth_token_t
+/// structure.
+pub fn hardware_auth_token_mac(
+    key: &FixedSizeEntropy,
+    hat: &HardwareAuthToken,
+) -> ServiceResult<Hmac> {
+    let mut generator = HmacGenerator::new(key)?;
+    generator.update(&hat.version.to_ne_bytes())?;
+    generator.update(&hat.challenge.to_ne_bytes())?;
+    generator.update(&hat.userId.to_ne_bytes())?;
+    generator.update(&hat.authenticatorId.to_ne_bytes())?;
+    generator.update(&hat.authenticatorType.to_be_bytes())?;
+    generator.update(&hat.timestamp.to_be_bytes())?;
+    Ok(generator.complete()?)
+}
diff --git a/app/finger_guard/src/error.rs b/app/finger_guard/src/error.rs
new file mode 100644
index 0000000..664cc92
--- /dev/null
+++ b/app/finger_guard/src/error.rs
@@ -0,0 +1,64 @@
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
+//! Error types for the finger guard service.
+
+/// Common error type for errors within the service implementation.
+///
+/// The actual service layer returns binder::Result errors but that type is
+/// basically just a status code that lacks the ability to attach any kind of
+/// informative message or underlying source error.
+#[derive(thiserror::Error, Debug)]
+pub enum ServiceError {
+    // Wrapping errors or pseudo-errors that are returned by other libraries.
+    #[error("{0}: openssl error: {1:?}")]
+    OpenSsl(&'static str, #[source] openssl::error::ErrorStack),
+    #[error("{0}: trusty storage error: {1:?}")]
+    TrustyStorage(&'static str, storage::Error),
+    #[error("{0}: trusty storage file error at {1}: {2:?}")]
+    TrustyFile(&'static str, String, storage::Error),
+    #[error("{0}: zerocopy conversion error")]
+    ZcConvert(&'static str),
+    #[error("{0}: {1:?}")]
+    TipcError(&'static str, tipc::TipcError),
+    #[error("Trusty system api {0} returns an error code: {1}")]
+    TrustySysRcError(&'static str, i64),
+
+    // Errors from interacting with keymint.
+    #[error("Keymint {cmd} returned an error code: {code}")]
+    KeymintError { cmd: &'static str, code: u32 },
+    #[error("Keymint {cmd} returned an unparseable response")]
+    KeymintBadResponse { cmd: &'static str },
+
+    // Errors directly reported by the service implementation itself.
+    #[error("{name} buffer size mismatch, expected {expected}, got {actual}")]
+    BufferSizeMismatch { name: &'static str, expected: usize, actual: usize },
+    #[error("failed to acquire {name} {mode} lock")]
+    LockAcquire { name: &'static str, mode: &'static str },
+    #[error("invalid argument {0}")]
+    InvalidArg(&'static str),
+    #[error("internal state {0} already exists")]
+    StateAlreadyExists(&'static str),
+    #[error("internal state {0} was unavailable")]
+    StateUnavailable(&'static str),
+    #[error("incorrect mac for {0}")]
+    BadMac(&'static str),
+}
+
+/// Common Result type for service methods.
+///
+/// This is the standard Result type to use for internal service functions.
+pub type ServiceResult<T> = Result<T, ServiceError>;
diff --git a/app/finger_guard/src/keymint.rs b/app/finger_guard/src/keymint.rs
new file mode 100644
index 0000000..40e79fe
--- /dev/null
+++ b/app/finger_guard/src/keymint.rs
@@ -0,0 +1,103 @@
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
+use crate::error::{ServiceError, ServiceResult};
+use kmr_common::wire::legacy::{self, TrustyKeymasterSecureOperation};
+use std::ffi::CStr;
+use tipc::{Deserialize, Handle, Serialize, Serializer, TipcError};
+use trusty_std::alloc::TryAllocFrom;
+use zerocopy::FromBytes;
+
+// The port string for keymint.
+const KEYMINT_PORT: &CStr = c"com.android.trusty.keymaster.secure";
+
+// Create a byte buffer contains the serialized GetAuthTokenKeyRequest.
+fn get_auth_token_key_request() -> Vec<u8> {
+    ((TrustyKeymasterSecureOperation::GetAuthTokenKey as u32) << legacy::TRUSTY_CMD_SHIFT)
+        .to_ne_bytes()
+        .to_vec()
+}
+
+// Since we are only interested in sending/receiving the GetAuthTokenKey
+// request/response, which have simple layouts, the hardcoded request/response
+// encoding and parsing is much easier to produce and maintain. The full
+// service interface is a legacy Keymaster interface without an AIDL
+// specification. Having a generialized request and response serde impl for
+// the entire interface is not worth it.
+// KMMessage implements a naive serde for a byte buffer. This allows we send
+// and receive a byte buffer directly with a tipc::Handle object so that we can
+// plug in the hardcoded request encoder and response decoder.
+struct KMMessage(Vec<u8>);
+const MAX_MESSAGE_SIZE: usize = 1024;
+
+impl<'s> Serialize<'s> for KMMessage {
+    fn serialize<'a: 's, S: Serializer<'s>>(
+        &'a self,
+        serializer: &mut S,
+    ) -> Result<S::Ok, S::Error> {
+        serializer.serialize_bytes(self.0.as_slice())
+    }
+}
+
+impl Deserialize for KMMessage {
+    type Error = TipcError;
+    const MAX_SERIALIZED_SIZE: usize = MAX_MESSAGE_SIZE;
+
+    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
+        Ok(KMMessage(Vec::try_alloc_from(bytes)?))
+    }
+}
+
+fn raw_get_auth_token_key_response() -> tipc::Result<Vec<u8>> {
+    let session = Handle::connect(KEYMINT_PORT)?;
+    let req = KMMessage(get_auth_token_key_request());
+    session.send(&req)?;
+    let mut buf = [0u8; MAX_MESSAGE_SIZE];
+    let resp: KMMessage = session.recv(&mut buf)?;
+    Ok(resp.0)
+}
+
+#[derive(FromBytes)]
+#[repr(C)]
+struct AuthTokenKeyMessage {
+    _raw_cmd: u32,
+    auth_token_key: [u8; 32],
+}
+
+#[derive(FromBytes)]
+#[repr(C)]
+struct ErrorMessage {
+    _raw_cmd: u32,
+    error_code: u32,
+}
+
+// Parse the raw response of GetAuthTokenKey and returns the 32-byte auth token
+// key if any.
+pub fn get_auth_token_key() -> ServiceResult<[u8; 32]> {
+    let raw_response = raw_get_auth_token_key_response()
+        .map_err(|e| ServiceError::TipcError("Keymint connection failed", e))?;
+
+    // For GetAuthTokenKey, the client has to distinguish between OK and error
+    // responses by the size of the result byte array: 4+32 for OK, 4+4 for
+    // error. C.f. system/keymint/wire/src/legacy.rs
+    if let Ok(success_message) = AuthTokenKeyMessage::read_from_bytes(&raw_response) {
+        Ok(success_message.auth_token_key)
+    } else if let Ok(error_message) = ErrorMessage::read_from_bytes(&raw_response) {
+        Err(ServiceError::KeymintError { cmd: "GetAuthTokenKey", code: error_message.error_code })
+    } else {
+        Err(ServiceError::KeymintBadResponse { cmd: "GetAuthTokenKey" })
+    }
+}
diff --git a/app/finger_guard/lib.rs b/app/finger_guard/src/lib.rs
similarity index 70%
rename from app/finger_guard/lib.rs
rename to app/finger_guard/src/lib.rs
index d8c38f7..292f2ba 100644
--- a/app/finger_guard/lib.rs
+++ b/app/finger_guard/src/lib.rs
@@ -14,15 +14,20 @@
 * limitations under the License.
 */
 
+mod clock;
+mod crypto;
+mod error;
+mod keymint;
 mod rng;
 mod service;
+mod storage;
 
 use crate::service::FingerGuardService;
-use alloc::rc::Rc;
 use binder::BinderFeatures;
 use fingerguard_api::aidl::IFingerGuard::BnFingerGuard;
 use rpcbinder::RpcServer;
-use tipc::{Manager, PortCfg, TipcError};
+use std::rc::Rc;
+use tipc::{Manager, PortCfg};
 
 // The port on FingerGuard TA which the Fingerprint sensor HAL connects to.
 const APP_SERVICE_PORT: &str = "com.android.trusty.rust.FingerGuard.V1";
@@ -35,7 +40,7 @@ tipc::service_dispatcher! {
         RpcServer
     }
 }
-pub fn init_and_start_loop() -> Result<(), TipcError> {
+pub fn init_and_start_loop() -> tipc::Result<()> {
     trusty_log::init();
 
     let mut dispatcher =
@@ -63,33 +68,3 @@ pub fn init_and_start_loop() -> Result<(), TipcError> {
 
     Ok(())
 }
-
-#[cfg(test)]
-mod tests {
-    test::init!();
-
-    #[test]
-    fn connect_server() {
-        let _ = fingerguard_api::connect_finger_guard().unwrap();
-    }
-
-    #[test]
-    fn get_authenticator_id() {
-        let service = fingerguard_api::connect_finger_guard().unwrap();
-        assert_eq!(service.getAuthenticatorId(0, 0), Ok(0));
-    }
-
-    #[test]
-    fn new_authenticator_id() {
-        let service = fingerguard_api::connect_finger_guard().unwrap();
-        let new_id = service.newAuthenticatorId(1, 1).unwrap();
-        assert_ne!(new_id, 0_i64);
-    }
-    #[test]
-    fn new_and_get_authenticator_id() {
-        let service = fingerguard_api::connect_finger_guard().unwrap();
-        let new_id = service.newAuthenticatorId(1, 1).unwrap();
-        let got_id = service.getAuthenticatorId(1, 1).unwrap();
-        assert_eq!(new_id, got_id);
-    }
-}
diff --git a/app/finger_guard/src/rng.rs b/app/finger_guard/src/rng.rs
new file mode 100644
index 0000000..ebeed80
--- /dev/null
+++ b/app/finger_guard/src/rng.rs
@@ -0,0 +1,60 @@
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
+//! Trusty implementation of `kmr_common::crypto::Rng`.
+use kmr_common::crypto::Rng;
+
+/// [`crypto::Rng`] implementation for Trusty.
+#[derive(Default)]
+pub struct TrustyRng;
+
+impl Rng for TrustyRng {
+    fn add_entropy(&mut self, _data: &[u8]) {} // Safety: No op as intended, BoringSSL's RAND_bytes() doesn't utilize this function.
+    fn fill_bytes(&mut self, dest: &mut [u8]) {
+        openssl::rand::rand_bytes(dest).unwrap(); // safe: BoringSSL's RAND_bytes() never fails
+    }
+}
+
+// Generate a buffer of size N filled with random bytes.
+pub fn generate_random_buffer<const N: usize>() -> [u8; N] {
+    let mut rng = TrustyRng::default();
+    let mut bytes = [0; N];
+    rng.fill_bytes(&mut bytes);
+    bytes
+}
+
+// Generate a byte vector of size N filled with random bytes.
+pub fn generate_random_vec<const N: usize>() -> Vec<u8> {
+    let mut rng = TrustyRng::default();
+    let mut bytes = vec![0u8; N];
+    rng.fill_bytes(&mut bytes.as_mut_slice());
+    bytes
+}
+
+// Generate a random integer of the given type.
+//
+// This is implemented as a macro because there's no generic way to turn a blob of random bytes
+// into a specific type. In fact, even generating a random integer of a specific size is difficult
+// because size_of can't be used on generic types in current Rust.
+macro_rules! generate_random_int {
+    ($int_type:ty) => {{
+        const INT_SIZE: usize = std::mem::size_of::<$int_type>();
+        let bytes = $crate::rng::generate_random_buffer::<INT_SIZE>();
+        let var = <$int_type>::from_ne_bytes(bytes);
+        var
+    }};
+}
+pub(crate) use generate_random_int;
diff --git a/app/finger_guard/src/service.rs b/app/finger_guard/src/service.rs
new file mode 100644
index 0000000..4ec6611
--- /dev/null
+++ b/app/finger_guard/src/service.rs
@@ -0,0 +1,758 @@
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
+use crate::clock::{self, Instant};
+use crate::crypto::{self, FixedSizeEntropy, ENTROPY_SIZE};
+use crate::error::{ServiceError, ServiceResult};
+use crate::keymint;
+use crate::rng;
+use crate::storage::{
+    AuthenticatorId, PersistedState, SecureUserId, SensorSessionCounter, SensorStateIndex,
+    SingleFileState,
+};
+use binder::Interface;
+use fingerguard_api::aidl::{
+    AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
+    HandshakeResponse::HandshakeResponse, HardwareAuthToken::HardwareAuthToken,
+    IFingerGuard::IFingerGuard, PrepareAuthSessionResponse::PrepareAuthSessionResponse,
+    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SensorUserPair::SensorUserPair,
+    SessionResponse::SessionResponse,
+};
+use log::error;
+use once_cell::sync::OnceCell;
+use openssl::pkey::{PKey, Private};
+use std::collections::BTreeMap;
+use std::default::Default;
+use std::sync::Mutex;
+use std::time::Duration;
+use zerocopy::{FromBytes, Immutable, IntoBytes};
+
+#[derive(FromBytes, IntoBytes, Immutable)]
+#[repr(C)]
+/// Represents the required parameters after the service initializes
+/// through the init handshake.
+struct InitParams {
+    pk: FixedSizeEntropy,
+    tpm_seed: FixedSizeEntropy,
+}
+
+impl PersistedState for InitParams {}
+impl SingleFileState for InitParams {
+    const FILE_NAME: &str = "fingerguard_init_params";
+}
+
+#[derive(Clone, PartialOrd, Ord, Eq, PartialEq)]
+/// Encapsulates a challenge associated with a SensorStateIndex
+pub struct EnrollmentChallenge {
+    ssi: SensorStateIndex,
+    challenge: i64,
+}
+
+impl EnrollmentChallenge {
+    const EMPTY: i64 = 0;
+    /// Converts the challenge to an i64.
+    fn challenge(&self) -> i64 {
+        self.challenge
+    }
+}
+
+#[derive(Default, Eq, PartialEq)]
+/// Represents the global state of the ongoing sensor session.
+enum SensorSession {
+    #[default]
+    NONE,
+    ENROLL {
+        nonce: FixedSizeEntropy,
+    },
+    AUTH {
+        nonce: FixedSizeEntropy,
+        challenge: i64,
+    },
+}
+
+/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
+pub struct FingerGuardService {
+    init_params: Mutex<Option<InitParams>>,
+    sk: Mutex<Option<crypto::Hmac>>,
+    sensor_session: Mutex<SensorSession>,
+    auth_token_key: OnceCell<FixedSizeEntropy>,
+    enrollment_challenges: Mutex<BTreeMap<EnrollmentChallenge, Instant>>,
+}
+
+impl FingerGuardService {
+    pub fn new() -> Self {
+        Self {
+            init_params: Mutex::new(
+                InitParams::load()
+                    .inspect_err(|e| error!("failed to load init_params: {e:?}"))
+                    .ok(),
+            ),
+            sk: Mutex::new(None),
+            sensor_session: Mutex::new(SensorSession::default()),
+            auth_token_key: OnceCell::new(),
+            enrollment_challenges: Mutex::new(BTreeMap::new()),
+        }
+    }
+
+    fn get_auth_token_key(&self) -> ServiceResult<&FixedSizeEntropy> {
+        self.auth_token_key.get_or_try_init(|| keymint::get_auth_token_key())
+    }
+
+    fn init_handshake(&self, client_public_key_bytes: &[u8]) -> ServiceResult<HandshakeResponse> {
+        let mut init_params = self
+            .init_params
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "write" })?;
+        if let Some(_) = *init_params {
+            return Err(ServiceError::StateAlreadyExists("init_params"));
+        }
+        let server_private_key =
+            crypto::ec_keygen().map_err(|e| ServiceError::OpenSsl("failed to ec keygen", e))?;
+        let server_public_key_bytes = crypto::ec_public_key_serialization(&server_private_key)
+            .map_err(|e| ServiceError::OpenSsl("failed to serialize server public key", e))?;
+        let server_private_key: PKey<Private> = server_private_key
+            .try_into()
+            .map_err(|e| ServiceError::OpenSsl("failed to convert ec key to pkey", e))?;
+        let pk = crypto::perform_ecdh(&server_private_key, client_public_key_bytes)
+            .map_err(|e| ServiceError::OpenSsl("failed to derive pk", e))?;
+        let pk: FixedSizeEntropy = {
+            let len = pk.len();
+            pk.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
+                name: "pk",
+                expected: ENTROPY_SIZE,
+                actual: len,
+            })
+        }?;
+        // generate random tpm_seed.
+        let tpm_seed = rng::generate_random_buffer::<ENTROPY_SIZE>();
+        let mac = crypto::HmacGenerator::compute(&pk, b"tofu")?;
+        // save pk and tpm_seed to storage.
+        let new_init_params = InitParams { pk, tpm_seed };
+        new_init_params.save()?;
+        *init_params = Some(new_init_params);
+        Ok(HandshakeResponse { serverPublicKey: server_public_key_bytes, pkMac: mac.into() })
+    }
+
+    fn new_session(&self, client_nonce: &[u8]) -> ServiceResult<SessionResponse> {
+        if client_nonce.len() != 32 {
+            return Err(ServiceError::InvalidArg("client_nonce"));
+        }
+        let init_params = self
+            .init_params
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "read" })?;
+        let Some(ref init_params) = *init_params else {
+            return Err(ServiceError::StateUnavailable("init_params"));
+        };
+        let pk = init_params.pk;
+        let tpm_seed = init_params.tpm_seed;
+        let mut sk = self
+            .sk
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "write" })?;
+        if let Some(_) = *sk {
+            return Err(ServiceError::StateAlreadyExists("sk"));
+        }
+        let nonce = rng::generate_random_vec::<32>();
+        let mut hmac_generator = crypto::HmacGenerator::new(&pk)?;
+        hmac_generator.update(client_nonce)?;
+        hmac_generator.update(nonce.as_slice())?;
+        let new_sk = hmac_generator.complete()?;
+        let iv = rng::generate_random_vec::<12>();
+        let mut tag = vec![0u8; 16];
+        let wrapped_tpm_seed = crypto::encrypt_aes256_gcm(
+            &new_sk,
+            Some(iv.as_slice()),
+            b"tpm_seed", // aad = "tpm_seed"
+            tpm_seed.as_slice(),
+            tag.as_mut_slice(),
+        )
+        .map_err(|e| ServiceError::OpenSsl("failed to encrypt tpm_seed", e))?;
+        *sk = Some(new_sk);
+        Ok(SessionResponse { nonce, wrappedTpmSeed: wrapped_tpm_seed, iv, tag })
+    }
+
+    fn generate_challenge(&self, sensor_user_pair: &SensorUserPair) -> ServiceResult<i64> {
+        let mut enrollment_challenges = self.enrollment_challenges.try_lock().map_err(|_| {
+            ServiceError::LockAcquire { name: "enrollment_challenges", mode: "write" }
+        })?;
+        let ssi = SensorStateIndex::from(sensor_user_pair);
+        let challenge = rng::generate_random_int!(i64);
+        let valid_until = clock::now()? + Duration::from_secs(60);
+        let ec = EnrollmentChallenge { ssi, challenge };
+        enrollment_challenges.insert(ec, valid_until);
+        Ok(challenge)
+    }
+
+    fn revoke_challenge(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        challenge: i64,
+    ) -> ServiceResult<i64> {
+        let mut enrollment_challenges = self.enrollment_challenges.try_lock().map_err(|_| {
+            ServiceError::LockAcquire { name: "enrollment_challenges", mode: "write" }
+        })?;
+        let ssi = SensorStateIndex::from(sensor_user_pair);
+        let ec = EnrollmentChallenge { ssi, challenge };
+        let now = clock::now()?;
+        enrollment_challenges.remove(&ec).map_or(Ok(EnrollmentChallenge::EMPTY), |valid_until| {
+            if now < valid_until {
+                Ok(ec.challenge())
+            } else {
+                Ok(EnrollmentChallenge::EMPTY)
+            }
+        })
+    }
+
+    // TODO(b/401303592): Clear sensor lockout with the HAT verification.
+    fn prepare_enroll_session(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        hat: &HardwareAuthToken,
+    ) -> ServiceResult<PrepareEnrollSessionResponse> {
+        let sk = self
+            .sk
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
+        let Some(ref sk) = *sk else {
+            return Err(ServiceError::StateUnavailable("sk"));
+        };
+        let mut sensor_session = self
+            .sensor_session
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
+        if *sensor_session != SensorSession::NONE {
+            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
+        }
+
+        // revoke_challenge returns the given challenge when it is valid.
+        let challenge =
+            FingerGuardService::revoke_challenge(&self, sensor_user_pair, hat.challenge)?;
+        if challenge != EnrollmentChallenge::EMPTY || challenge != hat.challenge {
+            return Err(ServiceError::StateUnavailable("enrollment challenge"));
+        }
+        let auth_token_key = self.get_auth_token_key()?;
+        let mac = crypto::hardware_auth_token_mac(&auth_token_key, hat)?;
+        if mac != hat.mac.as_slice() {
+            return Err(ServiceError::BadMac("hardware auth token"));
+        }
+
+        // Start a new enroll session.
+        let stored_counter = SensorSessionCounter::load().unwrap_or_default();
+        let session_counter = stored_counter.increment();
+        session_counter.save()?;
+
+        let nonce = rng::generate_random_buffer::<32>();
+        *sensor_session = SensorSession::ENROLL { nonce };
+
+        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
+        // Save the secure user id from the HAT.
+        let sid_file = sensor_state_index.secure_user_id_file_name();
+        let secure_user_id = SecureUserId::from(hat.userId);
+        secure_user_id.save_to(&sid_file)?;
+        let hmac = crypto::sensor_session_message_hmac(
+            &sk,
+            &nonce,
+            crypto::MessageSender::FINGERGUARD,
+            crypto::SensorSessionType::ENROLL,
+            &sensor_state_index,
+            &session_counter,
+        )?;
+        Ok(PrepareEnrollSessionResponse {
+            sessionCounter: session_counter.as_i64(),
+            nonce,
+            mac: hmac.into(),
+        })
+    }
+
+    fn finish_enroll_session(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        result: &EnrollmentResult,
+    ) -> ServiceResult<()> {
+        let sk = self
+            .sk
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
+        let Some(ref sk) = *sk else {
+            return Err(ServiceError::StateUnavailable("sk"));
+        };
+        let mut sensor_session = self
+            .sensor_session
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
+        let SensorSession::ENROLL { nonce } = *sensor_session else {
+            return Err(ServiceError::StateUnavailable("ongoing enroll session"));
+        };
+        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
+        let session_counter = SensorSessionCounter::load().unwrap_or_default();
+        // Close the session.
+        *sensor_session = SensorSession::NONE;
+        // If enrollment succeeds, compute and compare the mac.
+        if result.enrolled {
+            let hmac = crypto::sensor_session_message_hmac(
+                &sk,
+                &nonce,
+                crypto::MessageSender::FPMCU,
+                crypto::SensorSessionType::ENROLL,
+                &sensor_state_index,
+                &session_counter,
+            )?;
+            // Use a constant-time comparison to avoid timing attacks against
+            // the session hmac. This would be difficult to exploit anyway
+            // because retries are not possible, but better safe than sorry.
+            if hmac != result.mac.as_slice() {
+                return Err(ServiceError::BadMac("enrollment result"));
+            }
+            // Generate and save a new AuthenticatorId.
+            let authenticator_id = AuthenticatorId::generate_random();
+            let file_name = sensor_state_index.authenticator_id_file_name();
+            authenticator_id.save_to(&file_name)?;
+        }
+        Ok(())
+    }
+
+    fn prepare_auth_session(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        challenge: i64,
+    ) -> ServiceResult<PrepareAuthSessionResponse> {
+        let sk = self
+            .sk
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
+        let Some(ref sk) = *sk else {
+            return Err(ServiceError::StateUnavailable("sk"));
+        };
+        let mut sensor_session = self
+            .sensor_session
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
+        if *sensor_session != SensorSession::NONE {
+            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
+        }
+        // Start a new auth session.
+        let stored_counter = SensorSessionCounter::load().unwrap_or_default();
+        let session_counter = stored_counter.increment();
+        session_counter.save()?;
+
+        let nonce = rng::generate_random_buffer::<32>();
+        *sensor_session = SensorSession::AUTH { nonce, challenge };
+
+        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
+        let hmac = crypto::sensor_session_message_hmac(
+            &sk,
+            &nonce,
+            crypto::MessageSender::FINGERGUARD,
+            crypto::SensorSessionType::AUTH,
+            &sensor_state_index,
+            &session_counter,
+        )?;
+        Ok(PrepareAuthSessionResponse {
+            sessionCounter: session_counter.as_i64(),
+            nonce,
+            mac: hmac.into(),
+        })
+    }
+
+    fn finish_auth_session(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        result: &AuthenticationResult,
+    ) -> ServiceResult<HardwareAuthToken> {
+        let sk = self
+            .sk
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
+        let Some(ref sk) = *sk else {
+            return Err(ServiceError::StateUnavailable("sk"));
+        };
+        let mut sensor_session = self
+            .sensor_session
+            .try_lock()
+            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
+        let SensorSession::AUTH { nonce, challenge } = *sensor_session else {
+            return Err(ServiceError::StateUnavailable("ongoing auth session"));
+        };
+        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
+        let session_counter = SensorSessionCounter::load().unwrap_or_default();
+        // Close the session.
+        *sensor_session = SensorSession::NONE;
+        // Build the outgoing HAT.
+        let aid_file_name = sensor_state_index.authenticator_id_file_name();
+        let sid_file_name = sensor_state_index.secure_user_id_file_name();
+        let authenticator_id = AuthenticatorId::load_from(&aid_file_name)?;
+        let secure_user_id = SecureUserId::load_from(&sid_file_name)?;
+        let hat = HardwareAuthToken {
+            version: 0,
+            challenge: challenge,
+            userId: secure_user_id.as_i64(),
+            authenticatorId: authenticator_id.as_i64(),
+            authenticatorType: 2, // Fingerprint
+            timestamp: clock::elapsed_real_time_milli()?,
+            mac: vec![],
+        };
+        // If enrollment succeeds, compute and compare the mac.
+        if result.authenticated {
+            let hmac = crypto::sensor_session_message_hmac(
+                &sk,
+                &nonce,
+                crypto::MessageSender::FPMCU,
+                crypto::SensorSessionType::AUTH,
+                &sensor_state_index,
+                &session_counter,
+            )?;
+            // Use a constant-time comparison to avoid timing attacks against
+            // the session hmac. This would be difficult to exploit anyway
+            // because retries are not possible, but better safe than sorry.
+            if hmac != result.mac.as_slice() {
+                return Err(ServiceError::BadMac("authentication result"));
+            }
+            // TODO(b/419332065): add a valid mac to HAT.
+            // TODO(b/401303592): Clear sensor lockout state.
+        }
+        Ok(hat)
+    }
+
+    fn read_authenticator_id(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+    ) -> ServiceResult<AuthenticatorId> {
+        let index = SensorStateIndex::from(sensor_user_pair);
+        let file_name = index.authenticator_id_file_name();
+        // Treat read failure as there is no authenticator id and use the default
+        // value of 0.
+        let authenticator_id = AuthenticatorId::load_from(&file_name)
+            .inspect_err(|e| error!("failed to read authenticator id: {e:?}"))
+            .unwrap_or_default();
+        Ok(authenticator_id)
+    }
+
+    fn generate_authenticator_id(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+    ) -> ServiceResult<AuthenticatorId> {
+        let authenticator_id = AuthenticatorId::generate_random();
+        let index = SensorStateIndex::from(sensor_user_pair);
+        let file_name = index.authenticator_id_file_name();
+        authenticator_id.save_to(&file_name)?;
+        Ok(authenticator_id)
+    }
+}
+
+impl Interface for FingerGuardService {}
+
+impl IFingerGuard for FingerGuardService {
+    fn initHandshake(&self, client_public_key: &[u8]) -> binder::Result<HandshakeResponse> {
+        FingerGuardService::init_handshake(&self, client_public_key)
+            .inspect_err(|e| error!("initHandshake failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn newSession(&self, client_nonce: &[u8]) -> binder::Result<SessionResponse> {
+        FingerGuardService::new_session(&self, client_nonce)
+            .inspect_err(|e| error!("newSession failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn generateChallenge(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
+        FingerGuardService::generate_challenge(&self, sensor_user_pair)
+            .inspect_err(|e| error!("generateChallenge failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn revokeChallenge(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        challenge: i64,
+    ) -> binder::Result<i64> {
+        FingerGuardService::revoke_challenge(&self, sensor_user_pair, challenge)
+            .inspect_err(|e| error!("revokeChallenge failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn prepareEnrollSession(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        hat: &HardwareAuthToken,
+    ) -> binder::Result<PrepareEnrollSessionResponse> {
+        FingerGuardService::prepare_enroll_session(&self, sensor_user_pair, hat)
+            .inspect_err(|e| error!("prepareEnrollSession failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn finishEnrollSession(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        result: &EnrollmentResult,
+    ) -> binder::Result<()> {
+        FingerGuardService::finish_enroll_session(&self, sensor_user_pair, result)
+            .inspect_err(|e| error!("finishEnrollSession failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn prepareAuthSession(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        challenge: i64,
+    ) -> binder::Result<PrepareAuthSessionResponse> {
+        FingerGuardService::prepare_auth_session(&self, sensor_user_pair, challenge)
+            .inspect_err(|e| error!("prepareAuthSession failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn finishAuthSession(
+        &self,
+        sensor_user_pair: &SensorUserPair,
+        result: &AuthenticationResult,
+    ) -> binder::Result<HardwareAuthToken> {
+        FingerGuardService::finish_auth_session(&self, sensor_user_pair, result)
+            .inspect_err(|e| error!("finishAuthSession failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn getAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
+        FingerGuardService::read_authenticator_id(&self, sensor_user_pair)
+            .map(|id| id.as_i64())
+            .inspect_err(|e| error!("getAuthenticatorId failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+    fn newAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
+        FingerGuardService::generate_authenticator_id(&self, sensor_user_pair)
+            .map(|id| id.as_i64())
+            .inspect_err(|e| error!("newAuthenticatorId failed: {e:?}"))
+            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use crate::crypto::{self, FixedSizeEntropy, NIST_P256_CURVE_NAME};
+    use crate::keymint;
+    use crate::rng;
+    use fingerguard_api::aidl::{
+        AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
+        HardwareAuthToken::HardwareAuthToken, SensorUserPair::SensorUserPair,
+    };
+    use openssl::bn::BigNumContext;
+    use openssl::derive::Deriver;
+    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
+    use openssl::pkey::{PKey, Private, Public};
+    test::init!();
+
+    #[test]
+    fn connect_server() {
+        let _ = fingerguard_api::connect_finger_guard().unwrap();
+    }
+
+    // Establish a shared PK with the fingerguard server.
+    fn init_service() -> FixedSizeEntropy {
+        // Prepare the client key pair.
+        let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME).unwrap();
+        let mut ctx = BigNumContext::new().unwrap();
+        let client_private_key: EcKey<Private> = EcKey::generate(&group).unwrap();
+        let client_public_key_bytes = client_private_key
+            .public_key()
+            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
+            .unwrap();
+
+        // ECDH with the server.
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let handshake_response = service.initHandshake(client_public_key_bytes.as_slice()).unwrap();
+        let server_public_key_bytes = handshake_response.serverPublicKey;
+
+        // Derive PK from the client side.
+        let server_public_point =
+            EcPoint::from_bytes(&group, &server_public_key_bytes, &mut ctx).unwrap();
+        let server_public_key: PKey<Public> =
+            EcKey::from_public_key(&group, &server_public_point).unwrap().try_into().unwrap();
+        let client_private_key: PKey<Private> = client_private_key.try_into().unwrap();
+        let mut pk_deriver = Deriver::new(&client_private_key).unwrap();
+        pk_deriver.set_peer(&server_public_key).unwrap();
+        let pk = pk_deriver.derive_to_vec().unwrap();
+        assert_eq!(pk.len(), 32);
+        let pk = pk.try_into().unwrap();
+
+        // Check the computed MAC matches the one in the response.
+        let hmac = crypto::HmacGenerator::compute(&pk, b"tofu").unwrap();
+        assert!(hmac == handshake_response.pkMac.as_slice());
+        pk
+    }
+
+    #[test]
+    fn everything_with_a_shared_session() {
+        let auth_token_key = keymint::get_auth_token_key().unwrap();
+        let pk = init_service();
+        let client_nonce = rng::generate_random_vec::<32>();
+
+        // Start a new session with the server.
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let session_response = service.newSession(client_nonce.as_slice()).unwrap();
+        let server_nonce = session_response.nonce;
+        let all_nonce = vec![client_nonce, server_nonce].concat();
+        let sk = crypto::HmacGenerator::compute(&pk, &all_nonce).unwrap();
+
+        // Decrypt the wrapped tpm seed.
+        let iv = session_response.iv;
+        let tag = session_response.tag;
+        let encrypted_tpm_seed = session_response.wrappedTpmSeed;
+        let aad = b"tpm_seed";
+        let tpm_seed = crypto::decrypt_aes256_gcm(
+            &sk,
+            Some(iv.as_slice()),
+            aad,
+            encrypted_tpm_seed.as_slice(),
+            tag.as_slice(),
+        )
+        .unwrap();
+        assert_eq!(tpm_seed.len(), 32);
+
+        // Bad AAD leads to a decryption error.
+        assert!(crypto::decrypt_aes256_gcm(
+            &sk,
+            Some(iv.as_slice()),
+            b"incorrect_aad",
+            encrypted_tpm_seed.as_slice(),
+            tag.as_slice(),
+        )
+        .is_err());
+
+        // Ensure newSession only allows one successful invocation per boot.
+        assert!(service.newSession(vec![0u8; 32].as_slice()).is_err());
+
+        let sensor_id = 1_i32;
+        let user_id = 1_i32;
+        let sup = SensorUserPair { sensorId: sensor_id, userId: user_id };
+
+        // ---- Start Enrollment Test ----
+
+        let challenge = service.generateChallenge(&sup).unwrap();
+        let secure_user_id = 0x1337BEEF as i64;
+        let mut hat = HardwareAuthToken {
+            version: 0,
+            challenge: challenge,
+            userId: secure_user_id,
+            authenticatorId: 0,
+            authenticatorType: 0,
+            timestamp: 0,
+            mac: vec![],
+        };
+        hat.mac = Vec::from(crypto::hardware_auth_token_mac(&auth_token_key, &hat).unwrap());
+        let session_resp = service.prepareEnrollSession(&sup, &hat).unwrap();
+        assert_eq!(session_resp.sessionCounter, 1);
+        let mut hmac_gen = crypto::HmacGenerator::with_hmac_key(&sk).unwrap();
+        hmac_gen.update(&session_resp.nonce).unwrap();
+        hmac_gen.update(&user_id.to_be_bytes()).unwrap();
+        hmac_gen.update(b"fingerguardenroll").unwrap();
+        hmac_gen.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
+        let hmac = hmac_gen.complete().unwrap();
+        assert!(hmac == session_resp.mac.as_slice());
+
+        let old_auth_id = service.getAuthenticatorId(&sup).unwrap();
+        let mut hmac_gen = crypto::HmacGenerator::with_hmac_key(&sk).unwrap();
+        hmac_gen.update(&session_resp.nonce).unwrap();
+        hmac_gen.update(&user_id.to_be_bytes()).unwrap();
+        hmac_gen.update(b"fpmcuenroll").unwrap();
+        hmac_gen.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
+        let hmac = hmac_gen.complete().unwrap();
+        let enrollment_result = EnrollmentResult { enrolled: true, mac: hmac.into() };
+        let _ = service.finishEnrollSession(&sup, &enrollment_result).unwrap();
+        // Ensure the authenticator id updates after enrollment.
+        let new_auth_id = service.getAuthenticatorId(&sup).unwrap();
+        assert_ne!(new_auth_id, old_auth_id);
+
+        // Test enrollment session cancellation.
+        hat.challenge = service.generateChallenge(&sup).unwrap();
+        hat.mac = Vec::from(crypto::hardware_auth_token_mac(&auth_token_key, &hat).unwrap());
+        let session_resp = service.prepareEnrollSession(&sup, &hat).unwrap();
+        assert_eq!(session_resp.sessionCounter, 2);
+        // Use a empty mac to signal the session cancellation.
+        let cancel_result = EnrollmentResult { enrolled: false, mac: vec![] };
+        let _ = service.finishEnrollSession(&sup, &cancel_result).unwrap();
+        // ---- End Enrollment Test ----
+
+        // ---- Start Authentication Test ----
+        let challenge = 0xc4a11e49e as i64;
+        let session_resp = service.prepareAuthSession(&sup, challenge).unwrap();
+        assert_eq!(session_resp.sessionCounter, 3);
+        let mut hmac_gen = crypto::HmacGenerator::with_hmac_key(&sk).unwrap();
+        hmac_gen.update(&session_resp.nonce).unwrap();
+        hmac_gen.update(&user_id.to_be_bytes()).unwrap();
+        hmac_gen.update(b"fingerguardauth").unwrap();
+        hmac_gen.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
+        let hmac = hmac_gen.complete().unwrap();
+        assert!(hmac == session_resp.mac.as_slice());
+
+        let mut hmac_gen = crypto::HmacGenerator::with_hmac_key(&sk).unwrap();
+        hmac_gen.update(&session_resp.nonce).unwrap();
+        hmac_gen.update(&user_id.to_be_bytes()).unwrap();
+        hmac_gen.update(b"fpmcuauth").unwrap();
+        hmac_gen.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
+        let hmac = hmac_gen.complete().unwrap();
+        let auth_result = AuthenticationResult { authenticated: true, mac: hmac.into() };
+        let valid_hat = service.finishAuthSession(&sup, &auth_result).unwrap();
+        assert_eq!(valid_hat.challenge, challenge);
+        assert_eq!(valid_hat.userId, secure_user_id);
+        assert_eq!(valid_hat.authenticatorId, new_auth_id);
+        assert_ne!(valid_hat.timestamp, 0);
+        // TODO(b/419332065): Check mac.
+
+        // ---- End Authentication Test ----
+    }
+
+    #[test]
+    fn get_authenticator_id() {
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let sup = SensorUserPair { sensorId: 0, userId: 0 };
+        assert_eq!(service.getAuthenticatorId(&sup), Ok(0));
+    }
+
+    #[test]
+    fn new_authenticator_id() {
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let sup = SensorUserPair { sensorId: 1, userId: 1 };
+        let new_id = service.newAuthenticatorId(&sup).unwrap();
+        assert_ne!(new_id, 0_i64);
+    }
+
+    #[test]
+    fn new_and_get_authenticator_id() {
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let sup = SensorUserPair { sensorId: 1, userId: 1 };
+        let new_id = service.newAuthenticatorId(&sup).unwrap();
+        let got_id = service.getAuthenticatorId(&sup).unwrap();
+        assert_eq!(new_id, got_id);
+    }
+
+    #[test]
+    fn generate_and_revoke_challenge() {
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let sup = SensorUserPair { sensorId: 1, userId: 1 };
+        // Generate multiple challenges and revoke them individually.
+        let c1 = service.generateChallenge(&sup).unwrap();
+        assert_ne!(c1, 0_i64);
+        let c2 = service.generateChallenge(&sup).unwrap();
+        assert_ne!(c2, 0_i64);
+        assert_ne!(c1, c2);
+        // Revoke once, return the same challenge.
+        let revoked_c1 = service.revokeChallenge(&sup, c1).unwrap();
+        assert_eq!(c1, revoked_c1);
+        let revoked_c2 = service.revokeChallenge(&sup, c2).unwrap();
+        assert_eq!(c2, revoked_c2);
+        // Revoke the 1st challenge twice, return zero.
+        assert_eq!(service.revokeChallenge(&sup, c1), Ok(0));
+    }
+
+    #[test]
+    fn revoke_invalid_challenge() {
+        let service = fingerguard_api::connect_finger_guard().unwrap();
+        let sup = SensorUserPair { sensorId: 2, userId: 2 };
+        let invalid_challenge = 1234_i64;
+        assert_eq!(service.revokeChallenge(&sup, invalid_challenge), Ok(0));
+    }
+}
diff --git a/app/finger_guard/src/storage.rs b/app/finger_guard/src/storage.rs
new file mode 100644
index 0000000..fe62960
--- /dev/null
+++ b/app/finger_guard/src/storage.rs
@@ -0,0 +1,188 @@
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
+//! Types and utilities for data which is stored persistently on the device.
+
+use crate::error::ServiceError;
+use crate::rng;
+use fingerguard_api::aidl::SensorUserPair::SensorUserPair;
+use storage::{OpenMode, Port, Session};
+use zerocopy::{FromBytes, Immutable, IntoBytes};
+
+/// A utility function to read the full content of a file.
+fn read_all_bytes(file_name: &str) -> Result<Vec<u8>, storage::Error> {
+    let mut session = Session::new(Port::TamperDetect, true)?;
+    let secure_file = session.open_file(&file_name, OpenMode::Open)?;
+    let file_size = session.get_size(&secure_file)?;
+    let mut buffer = vec![0u8; file_size];
+    let content = session.read_all(&secure_file, buffer.as_mut_slice())?;
+    Ok(content.to_vec())
+}
+
+/// Indicates that the type is persisted as a file in the Trusty Storage.
+///
+/// This trait is required for types that keeps service states across reboots.
+/// It provides a default save_to and load_from implementation, which should
+/// satisfy the needs of most types.
+///
+/// # Safety
+///
+/// This trait does not guarantee thread safety against read write races.
+pub trait PersistedState: FromBytes + IntoBytes + Immutable {
+    fn load_from(file_name: &str) -> Result<Self, ServiceError>
+    where
+        Self: Sized,
+    {
+        let all_bytes = read_all_bytes(&file_name)
+            .map_err(|e| ServiceError::TrustyFile("failed to read", file_name.to_owned(), e))?;
+        Self::read_from_bytes(&all_bytes)
+            .map_err(|_| ServiceError::ZcConvert("failed to deserialize file content"))
+    }
+
+    fn save_to(&self, file_name: &str) -> Result<(), ServiceError> {
+        let mut session = Session::new(Port::TamperDetect, true)
+            .map_err(|e| ServiceError::TrustyStorage("failed to create storage session", e))?;
+        let mut secure_file = session
+            .open_file(&file_name, OpenMode::Create)
+            .map_err(|e| ServiceError::TrustyFile("open failed", file_name.to_owned(), e))?;
+        let serialized_bytes = Self::as_bytes(&self);
+        session
+            .write_all(&mut secure_file, &serialized_bytes)
+            .map_err(|e| ServiceError::TrustyFile("write failed", file_name.to_owned(), e))?;
+        Ok(())
+    }
+}
+
+/// Indicates that the type is pesisted to one single file.
+///
+/// This trait suits those global singleton service states.
+/// This trait requires the type implement the PersistedState trait first.
+///
+/// # Safety
+///
+/// This trait does not guarantee thread safety against read write races.
+pub trait SingleFileState: PersistedState {
+    const FILE_NAME: &str;
+    fn load() -> Result<Self, ServiceError>
+    where
+        Self: Sized,
+    {
+        Self::load_from(Self::FILE_NAME)
+    }
+    fn save(&self) -> Result<(), ServiceError>
+    where
+        Self: PersistedState,
+    {
+        Self::save_to(&self, Self::FILE_NAME)
+    }
+}
+
+#[derive(Clone, PartialOrd, Ord, Eq, PartialEq, Debug)]
+/// Represents a key to index sensor state.
+/// It is equivalent to a SensorUserPair defined in the service interface.
+/// Within the service, this type should be used instead of the AIDL object.
+pub struct SensorStateIndex {
+    sensor_id: u32,
+    user_id: u32,
+}
+
+impl From<&SensorUserPair> for SensorStateIndex {
+    fn from(sensor_user_pair: &SensorUserPair) -> Self {
+        SensorStateIndex {
+            sensor_id: sensor_user_pair.sensorId as u32,
+            user_id: sensor_user_pair.userId as u32,
+        }
+    }
+}
+
+impl SensorStateIndex {
+    /// Big endian representation of user_id.
+    pub fn user_id_be_bytes(&self) -> [u8; 4] {
+        self.user_id.to_be_bytes()
+    }
+    /// The file name for the authenticator id with this index.
+    pub fn authenticator_id_file_name(&self) -> String {
+        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
+    }
+    /// The file name for the secure user id with this index.
+    pub fn secure_user_id_file_name(&self) -> String {
+        format!("s{}.u{}.secure_user_id", self.sensor_id, self.user_id)
+    }
+}
+
+#[derive(Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
+#[repr(C)]
+/// Newtype that encapsulates an authenticator id.
+pub struct AuthenticatorId(i64);
+
+impl AuthenticatorId {
+    /// Generate a new random authenticator id.
+    pub fn generate_random() -> Self {
+        Self(rng::generate_random_int!(i64))
+    }
+
+    /// Convert the id to an i64.
+    ///
+    /// This should only be used to return the id across an AIDL interface. For
+    /// storage the (de)serialization traits should be used.
+    pub fn as_i64(&self) -> i64 {
+        self.0
+    }
+}
+
+impl PersistedState for AuthenticatorId {}
+
+#[derive(Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
+#[repr(C)]
+/// Newtype that encapsulates a secure user id.
+pub struct SecureUserId(u64);
+
+impl From<i64> for SecureUserId {
+    fn from(value: i64) -> Self {
+        Self(value as u64)
+    }
+}
+
+impl SecureUserId {
+    /// Convert the id to an i64.
+    pub fn as_i64(&self) -> i64 {
+        self.0 as i64
+    }
+}
+
+impl PersistedState for SecureUserId {}
+
+#[derive(Default, FromBytes, IntoBytes, Immutable)]
+#[repr(C)]
+/// Newtype that encapsulates the sensor session counter.
+pub struct SensorSessionCounter(u64);
+impl SensorSessionCounter {
+    pub fn increment(&self) -> Self {
+        Self(self.0 + 1)
+    }
+    /// Convert the id to an i64.
+    ///
+    /// This should only be used to return the counter across an AIDL interface. For
+    /// storage the (de)serialization traits should be used.
+    pub fn as_i64(&self) -> i64 {
+        self.0 as i64
+    }
+}
+
+impl PersistedState for SensorSessionCounter {}
+impl SingleFileState for SensorSessionCounter {
+    const FILE_NAME: &str = "fingerguard_sensor_session_counter";
+}
diff --git a/app/gsc_svc/app/manifest.json b/app/gsc_svc/app/manifest.json
index 3d8ee26..6b6ac9c 100644
--- a/app/gsc_svc/app/manifest.json
+++ b/app/gsc_svc/app/manifest.json
@@ -1,6 +1,6 @@
 {
     "app_name": "gsc_svc_app",
     "uuid": "77026d06-be0f-4604-a6d5-f729388a445b",
-    "min_heap": 16384,
-    "min_stack": 16384
+    "min_heap": 32768,
+    "min_stack": 32768
 }
diff --git a/app/gsc_svc/boot_params_svc.rs b/app/gsc_svc/boot_params_svc.rs
index ec72f2c..7372dae 100644
--- a/app/gsc_svc/boot_params_svc.rs
+++ b/app/gsc_svc/boot_params_svc.rs
@@ -19,7 +19,8 @@ use android_desktop_security_boot_params::aidl::android::desktop::security::boot
 use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::BnBootParams;
 use binder::{BinderFeatures, Interface, Result as BinderResult, Strong};
 use boot_params::BootParams;
-use tipc::TipcError;
+#[cfg(not(feature = "builtin-bcc"))]
+use vmm_obj::get_vmm_obj;
 
 pub struct Server {
     params: BootParams,
@@ -31,18 +32,53 @@ impl IBootParams for Server {
     fn getEarlyEntropy(&self) -> BinderResult<Vec<u8>> {
         Ok(self.params.gsc_boot_params.early_entropy.to_vec())
     }
+    fn getCdiSeal(&self) -> BinderResult<Vec<u8>> {
+        Ok(self.params.dice.cdi_seal.to_vec())
+    }
+    fn getCdiAttest(&self) -> BinderResult<Vec<u8>> {
+        Ok(self.params.dice.cdi_attest.to_vec())
+    }
+    fn getAuthTokenKeySeed(&self) -> BinderResult<Vec<u8>> {
+        Ok(self.params.gsc_boot_params.auth_token_key_seed.to_vec())
+    }
+}
+
+#[cfg(feature = "builtin-bcc")]
+impl Default for Server {
+    /// Create a boot params struct from constant data.
+    fn default() -> Self {
+        Self { params: BootParams::default() }
+    }
 }
 
 impl Server {
-    fn new() -> Self {
-        Self { params: BootParams::new() }
+    #[cfg(not(feature = "builtin-bcc"))]
+    fn new(entropy: [u8; 64], session: [u8; 32], auth: [u8; 32], dice: &[u8]) -> Self {
+        Self {
+            params: BootParams::new_from_dt(entropy, session, auth, dice)
+                .expect("Unable to start server"),
+        }
     }
 }
 
-pub fn create_boot_params_service() -> Result<Strong<dyn IBootParams>, TipcError> {
-    let srv = Server::new();
+#[cfg(feature = "builtin-bcc")]
+pub(crate) fn create_boot_params_service() -> Strong<dyn IBootParams> {
+    BnBootParams::new_binder(Server::default(), BinderFeatures::default())
+}
 
-    let service = BnBootParams::new_binder(srv, BinderFeatures::default());
+#[cfg(not(feature = "builtin-bcc"))]
+pub(crate) fn create_boot_params_service() -> Strong<dyn IBootParams> {
+    let entropy = get_vmm_obj(c"google,early-entropy").expect("Could not get entropy");
+    let session = get_vmm_obj(c"google,session-key-seed").expect("Could not get session key seed");
+    let auth =
+        get_vmm_obj(c"google,auth-token-key-seed").expect("Could not get auth token key seed");
+    let dice = get_vmm_obj(c"google,open-dice").expect("Could not get DICE chain");
 
-    Ok(service)
+    let srv = Server::new(
+        entropy.try_into().unwrap(),
+        session.try_into().unwrap(),
+        auth.try_into().unwrap(),
+        &dice,
+    );
+    BnBootParams::new_binder(srv, BinderFeatures::default())
 }
diff --git a/app/gsc_svc/lib.rs b/app/gsc_svc/lib.rs
index 3c35998..2ae798e 100644
--- a/app/gsc_svc/lib.rs
+++ b/app/gsc_svc/lib.rs
@@ -26,16 +26,16 @@ use std::borrow::Cow;
 use std::rc::Rc;
 use std::sync::Arc;
 use std::sync::Mutex;
-use tipc::TipcError;
 use tipc::{
     service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
     Serialize, Serializer, UnbufferedService, Uuid,
 };
+use tipc::{wrap_service, TipcError};
 use trusty_sys::Error;
 
 const GSC_SERVICE_PORT: &str = "com.android.trusty.rust.GscAppService.V1";
 const TUNNEL_SERVICE_PORT: &str = "com.android.trusty.rust.GscTunnelService.V1";
-const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1";
+const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1.bnd";
 
 /// A GscProxy implements the IGsc binder interface and forwards requests from trusty apps to the
 /// GSC over a GscTunnel.
@@ -152,15 +152,19 @@ impl GscTunnel {
     }
 }
 
+wrap_service!(GscService(RpcServer: UnbufferedService));
+wrap_service!(BpService(RpcServer: UnbufferedService));
+
 service_dispatcher! {
     enum GscDispatcher {
-        RpcServer,
+        GscService,
         GscTunnel,
+        BpService,
     }
 }
 
 const PORT_COUNT: usize = 3;
-const CONNECTION_COUNT: usize = 4;
+const CONNECTION_COUNT: usize = 8;
 
 pub fn init_and_start_loop() -> Result<(), TipcError> {
     trusty_log::init();
@@ -176,7 +180,7 @@ pub fn init_and_start_loop() -> Result<(), TipcError> {
     let app_cfg =
         PortCfg::new(GSC_SERVICE_PORT).expect("Could not create port config").allow_ta_connect();
     dispatcher
-        .add_service(Rc::new(gsc_rpc_server), app_cfg)
+        .add_service(Rc::new(GscService(gsc_rpc_server)), app_cfg)
         .expect("Could not add GSC service to dispatcher");
 
     let tunnel_cfg =
@@ -187,10 +191,10 @@ pub fn init_and_start_loop() -> Result<(), TipcError> {
 
     let bp_cfg =
         PortCfg::new(BP_SERVICE_PORT).expect("Could not create port config").allow_ta_connect();
-    let bp = boot_params_svc::create_boot_params_service()?;
+    let bp = boot_params_svc::create_boot_params_service();
     let bp_rpc_server = RpcServer::new_per_session(move |_uuid| Some(bp.as_binder()));
     dispatcher
-        .add_service(Rc::new(bp_rpc_server), bp_cfg)
+        .add_service(Rc::new(BpService(bp_rpc_server)), bp_cfg)
         .expect("Could not add bp service to dispatcher");
 
     Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
@@ -200,3 +204,39 @@ pub fn init_and_start_loop() -> Result<(), TipcError> {
 
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+
+    use super::*;
+    use binder::Strong;
+    use rpcbinder::RpcSession;
+    use std::ffi::CStr;
+
+    test::init!();
+
+    const GSC_SERVICE_PORT: &CStr = c"com.android.trusty.rust.GscAppService.V1";
+    fn get_service(port: &CStr) -> Strong<dyn IGsc> {
+        let session = RpcSession::new();
+        log::error!("created session");
+        let ret = session.setup_trusty_client(port).expect("Failed to create GSC session");
+        log::error!("trusty setup");
+        ret
+    }
+
+    #[test]
+    fn get_random() {
+        log::error!("get port");
+        let service = get_service(GSC_SERVICE_PORT);
+        log::error!("got port");
+        let get_random =
+            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x10];
+        let out = service.transmit(&get_random).unwrap();
+        assert_eq!(out[..2], [0x80, 0x01], "Bad tag");
+        assert_eq!(out[2..6], 0x1Cu32.to_be_bytes(), "Bad message size");
+        assert_eq!(out[6..10], 0u32.to_be_bytes(), "Bad status");
+        assert_eq!(out[10..12], 0x10u16.to_be_bytes(), "Bad TPM2B size");
+        assert_eq!(out[12..].len(), 0x10, "Bad vec length");
+        assert!(out[12..].iter().any(|&x| x != 0), "All zeroes for random bytes");
+    }
+}
diff --git a/app/gsc_svc/rules.mk b/app/gsc_svc/rules.mk
index d28ce11..de3d95e 100644
--- a/app/gsc_svc/rules.mk
+++ b/app/gsc_svc/rules.mk
@@ -38,5 +38,10 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/keymint-rust/wire \
 
 MODULE_RUST_USE_CLIPPY := true
+MODULE_RUST_TESTS := true
+
+ifneq ($(BUILTIN_BCC),)
+MODULE_RUSTFLAGS += --cfg 'feature="builtin-bcc"'
+endif
 
 include make/library.mk
diff --git a/app/hwbcc/manifest.json b/app/hwbcc/manifest.json
new file mode 100644
index 0000000..c5a04c2
--- /dev/null
+++ b/app/hwbcc/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hwbcc",
+    "uuid": "f758d162-3481-4bb4-ab54-5ed41652f44e",
+    "min_heap": 8192,
+    "min_stack": 16384
+}
diff --git a/app/hwbcc/rules.mk b/app/hwbcc/rules.mk
new file mode 100644
index 0000000..53cf15d
--- /dev/null
+++ b/app/hwbcc/rules.mk
@@ -0,0 +1,36 @@
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
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := $(LOCAL_DIR)/src/main.rs
+
+MODULE_CRATE_NAME := hwbcc
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy-derive) \
+	trusty/user/base/lib/pvmdice \
+	trusty/user/base/lib/hwbcc/rust \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-std \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/base/lib/vmm_obj/rust \
+
+include make/trusted_app.mk
diff --git a/app/hwbcc/src/main.rs b/app/hwbcc/src/main.rs
new file mode 100644
index 0000000..7dd559b
--- /dev/null
+++ b/app/hwbcc/src/main.rs
@@ -0,0 +1,39 @@
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
+use hwbcc::srv::HwBccService;
+use pvmdice::PvmDice;
+use tipc::{Manager, PortCfg};
+use trusty_std::rc::Rc;
+use vmm_obj::get_vmm_obj;
+
+const HWBCC_PORT_NAME: &str = "com.android.trusty.hwbcc";
+
+fn main() {
+    trusty_log::init();
+    let dice = get_vmm_obj(c"google,open-dice").expect("Could not get DICE chain");
+
+    let pvmdice = Rc::new(PvmDice::try_new(&dice).expect("Could not initialize PvmDice"));
+
+    let service = HwBccService::new(pvmdice);
+
+    let cfg = PortCfg::new(HWBCC_PORT_NAME).expect("Could not create port config");
+    let buffer = [0u8; 4096];
+    Manager::<_, _, 1, 1>::new(service, cfg, buffer)
+        .expect("Could not create service manager")
+        .run_event_loop()
+        .expect("hwbcc event loop failed");
+}
diff --git a/app/hwkey/hwcrypto_consts.json b/app/hwkey/hwcrypto_consts.json
new file mode 100644
index 0000000..cd1f49b
--- /dev/null
+++ b/app/hwkey/hwcrypto_consts.json
@@ -0,0 +1,85 @@
+{
+    "header": "hwkey_consts.h",
+    "constants": [
+        {
+            "name": "HWCRYPTO_UNITTEST_APP_UUID",
+            "value": "ab742471-d6e6-4806-85f6-0555b024f4da",
+            "type": "uuid"
+        },
+        {
+            "name": "HWCRYPTO_UNITTEST_RUST_APP_UUID",
+            "value": "7e15bb1a-571b-4404-9337-eeef60ed96e9",
+            "type": "uuid"
+        },
+        {
+            "name": "SECURE_STORAGE_SERVER_APP_UUID",
+            "value": "cea8706d-6cb4-49f3-b994-29e0e478bd29",
+            "type": "uuid"
+        },
+        {
+            "name": "KM_APP_UUID",
+            "value": "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf",
+            "type": "uuid"
+        },
+        {
+            "name": "KM_RUST_APP_UUID",
+            "value": "2e5415f0-d4d5-4a18-838f-29647dfc01d7",
+            "type": "uuid"
+        },
+        {
+            "name": "KM_RUST_UNITTEST_UUID",
+            "value": "d322eec9-6d03-49fa-821c-1ccd2705719c",
+            "type": "uuid"
+        },
+        {
+            "name": "APPLOADER_APP_UUID",
+            "value": "081ba88f-f1ee-452e-b5e8-a7e9ef173a97",
+            "type": "uuid"
+        },
+        {
+            "name": "SAMPLE_HWAES_APP_UUID",
+            "value": "6f4a2303-f4f8-431d-82d1-3ec52aebbb89",
+            "type": "uuid"
+        },
+        {
+            "name": "HWAES_UNITTEST_APP_UUID",
+            "value": "ab8a6820-1cc2-44d5-bee0-22b51befa835",
+            "type": "uuid"
+        },
+        {
+            "name": "HWAES_BENCH_APP_UUID",
+            "value": "9b424d86-9b1e-4755-942c-dca639de4289",
+            "type": "uuid"
+        },
+        {
+            "name": "GATEKEEPER_APP_UUID",
+            "value": "38ba0cdc-df0e-11e4-9869-233fb6ae4795",
+            "type": "uuid"
+        },
+        {
+            "name": "SAMPLE_HWBCC_APP_UUID",
+            "value": "f758d162-3481-4bb4-ab54-5ed41652f44e",
+            "type": "uuid"
+        },
+        {
+            "name": "HWBCC_UNITTEST_APP_UUID",
+            "value": "0e109d31-8bbe-47d6-bb47-e1dd08910e16",
+            "type": "uuid"
+        },
+        {
+            "name": "HWBCC_UNITTEST_RUST_APP_UUID",
+            "value": "67925337-2c03-49ed-9240-d51b6fea3e30",
+            "type": "uuid"
+        },
+        {
+            "name": "HWCRYPTOHAL_UNITTEST_RUST_APP_UUID",
+            "value": "f41a7796-975a-4279-8cc4-b73f8820430d",
+            "type": "uuid"
+        },
+        {
+            "name": "HWCRYPTOHAL_RUST_APP_UUID",
+            "value": "f49e28c4-d8b0-41c2-8197-11f27402c0f8",
+            "type": "uuid"
+        }
+    ]
+}
diff --git a/app/hwkey/hwkey.c b/app/hwkey/hwkey.c
new file mode 100644
index 0000000..cc7da3d
--- /dev/null
+++ b/app/hwkey/hwkey.c
@@ -0,0 +1,66 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#define TLOG_TAG "hwcrypto_srv"
+
+#include <assert.h>
+#include <inttypes.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <uapi/err.h>
+
+#include <lib/tipc/tipc.h>
+#include <lk/err_ptr.h>
+#include <trusty_log.h>
+
+#include "hwkey_srv_priv.h"
+
+/*
+ *  Main application event loop
+ */
+int run_hwkey(uint8_t* encrypt, size_t encrypt_size, uint8_t* attest,
+        size_t attest_size, uint8_t* auth_token_key_seed,
+        size_t auth_token_key_seed_size, int32_t rollback_version,
+        int32_t running_version) {
+    int rc;
+    struct tipc_hset* hset;
+
+    TLOGD("Initializing\n");
+
+    hset = tipc_hset_create();
+    if (IS_ERR(hset)) {
+        rc = PTR_ERR(hset);
+        TLOGE("tipc_hset_create failed (%d)\n", rc);
+        goto out;
+    }
+
+    /* initialize service providers */
+    rc = hwkey_init_srv_provider(hset, encrypt, encrypt_size, attest,
+            attest_size, auth_token_key_seed, auth_token_key_seed_size,
+            rollback_version, running_version);
+    if (rc != NO_ERROR) {
+        TLOGE("Failed (%d) to initialize HwKey service\n", rc);
+        goto out;
+    }
+
+    TLOGD("enter main event loop\n");
+
+    /* enter main event loop */
+    rc = tipc_run_event_loop(hset);
+
+out:
+    return rc;
+}
diff --git a/app/hwkey/hwkey_srv.c b/app/hwkey/hwkey_srv.c
new file mode 100644
index 0000000..711a106
--- /dev/null
+++ b/app/hwkey/hwkey_srv.c
@@ -0,0 +1,725 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#define TLOG_TAG "hwkey_srv"
+
+#include <assert.h>
+#include <lk/list.h>
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <uapi/err.h>
+
+#include <interface/hwkey/hwkey.h>
+#include <lib/rng/trusty_rng.h>
+#include <lib/tipc/tipc.h>
+#include <openssl/evp.h>
+#include <openssl/mem.h>
+#include <trusty_log.h>
+
+#include <hwkey_consts.h>
+#include "hwkey_srv_priv.h"
+
+struct hwkey_chan_ctx {
+    struct tipc_event_handler evt_handler;
+    handle_t chan;
+    uuid_t uuid;
+};
+
+/**
+ * An opaque key access token.
+ *
+ * Clients can retrieve an opaque access token as a handle to a key they are
+ * allowed to use but not read directly. This handle can then be passed to other
+ * crypto services which can use the token to retrieve the actual key from
+ * hwkey.
+ */
+typedef char access_token_t[HWKEY_OPAQUE_HANDLE_SIZE];
+
+struct opaque_handle_node {
+    const struct hwkey_keyslot* key_slot;
+    struct hwkey_chan_ctx* owner;
+    access_token_t token;
+    struct list_node node;
+};
+
+/*
+ * Global list of currently valid opaque handles. Each client may only have a
+ * single entry in this list for a given key slot, and this entry will be
+ * cleaned up when the connection it was created for is closed.
+ */
+static struct list_node opaque_handles = LIST_INITIAL_VALUE(opaque_handles);
+
+static uint8_t req_data[HWKEY_MAX_MSG_SIZE + 1];
+static __attribute__((aligned(4))) uint8_t key_data[HWKEY_MAX_MSG_SIZE];
+
+static unsigned int key_slot_cnt;
+static const struct hwkey_keyslot* key_slots;
+
+static bool is_opaque_handle(const struct hwkey_keyslot* key_slot) {
+    assert(key_slot);
+    return key_slot->handler == get_key_handle;
+}
+
+static void delete_opaque_handle(struct opaque_handle_node* node) {
+    assert(node);
+
+    /* Zero out the access token just in case the memory is reused */
+    memset(node->token, 0, HWKEY_OPAQUE_HANDLE_SIZE);
+
+    list_delete(&node->node);
+    free(node);
+}
+
+/*
+ * Close specified hwkey context
+ */
+static void hwkey_ctx_close(struct hwkey_chan_ctx* ctx) {
+    struct opaque_handle_node* entry;
+    struct opaque_handle_node* temp;
+    list_for_every_entry_safe(&opaque_handles, entry, temp,
+                              struct opaque_handle_node, node) {
+        if (entry->owner == ctx) {
+            delete_opaque_handle(entry);
+        }
+    }
+    close(ctx->chan);
+    free(ctx);
+}
+
+/*
+ * Send response message
+ */
+static int hwkey_send_rsp(struct hwkey_chan_ctx* ctx,
+                          struct hwkey_msg* rsp_hdr,
+                          uint8_t* rsp_data,
+                          size_t rsp_data_len) {
+    rsp_hdr->header.cmd |= HWKEY_RESP_BIT;
+    return tipc_send2(ctx->chan, rsp_hdr, sizeof(*rsp_hdr), rsp_data,
+                      rsp_data_len);
+}
+
+static bool is_allowed_to_read_opaque_key(const uuid_t* uuid,
+                                          const struct hwkey_keyslot* slot) {
+    assert(slot);
+    const struct hwkey_opaque_handle_data* handle = slot->priv;
+    assert(handle);
+
+    for (size_t i = 0; i < handle->allowed_uuids_len; ++i) {
+        if (memcmp(handle->allowed_uuids[i], uuid, sizeof(uuid_t)) == 0) {
+            return true;
+        }
+    }
+    return false;
+}
+
+static struct opaque_handle_node* find_opaque_handle_for_slot(
+        const struct hwkey_keyslot* slot) {
+    struct opaque_handle_node* entry;
+    list_for_every_entry(&opaque_handles, entry, struct opaque_handle_node,
+                         node) {
+        if (entry->key_slot == slot) {
+            return entry;
+        }
+    }
+
+    return NULL;
+}
+
+/*
+ * If a handle doesn't exist yet for the given slot, create and insert a new one
+ * in the global list.
+ */
+static uint32_t insert_handle_node(struct hwkey_chan_ctx* ctx,
+                                   const struct hwkey_keyslot* slot) {
+    struct opaque_handle_node* entry = find_opaque_handle_for_slot(slot);
+
+    if (!entry) {
+        entry = calloc(1, sizeof(struct opaque_handle_node));
+        if (!entry) {
+            TLOGE("Could not allocate new opaque_handle_node\n");
+            return HWKEY_ERR_GENERIC;
+        }
+
+        entry->owner = ctx;
+        entry->key_slot = slot;
+        list_add_tail(&opaque_handles, &entry->node);
+    }
+
+    return HWKEY_NO_ERROR;
+}
+
+static uint32_t _handle_slots(struct hwkey_chan_ctx* ctx,
+                              const char* slot_id,
+                              const struct hwkey_keyslot* slots,
+                              unsigned int slot_cnt,
+                              uint8_t* kbuf,
+                              size_t kbuf_len,
+                              size_t* klen) {
+    if (!slots)
+        return HWKEY_ERR_NOT_FOUND;
+
+    for (unsigned int i = 0; i < slot_cnt; i++, slots++) {
+        /* check key id */
+        if (strcmp(slots->key_id, slot_id))
+            continue;
+
+        /* Check if the caller is allowed to get that key */
+        if (memcmp(&ctx->uuid, slots->uuid, sizeof(uuid_t)) == 0) {
+            if (slots->handler) {
+                if (is_opaque_handle(slots)) {
+                    uint32_t rc = insert_handle_node(ctx, slots);
+                    if (rc != HWKEY_NO_ERROR)
+                        return rc;
+                }
+                return slots->handler(slots, kbuf, kbuf_len, klen);
+            }
+        }
+    }
+
+    /*
+     * We couldn't match a key ID, so try to treat the id as an opaque access
+     * handle
+     */
+    return get_opaque_key(&ctx->uuid, slot_id, kbuf, kbuf_len, klen);
+}
+
+uint32_t hwkey_get_derived_key(const struct hwkey_derived_keyslot_data* data,
+                               uint8_t* kbuf,
+                               size_t kbuf_len,
+                               size_t* klen) {
+    assert(kbuf);
+    assert(klen);
+    assert(data);
+    assert(data->encrypted_key_size_ptr);
+
+    uint8_t key_buffer[HWKEY_DERIVED_KEY_MAX_SIZE] = {0};
+    size_t key_len;
+    uint32_t rc =
+            data->retriever(data, key_buffer, sizeof(key_buffer), &key_len);
+    if (rc != HWKEY_NO_ERROR) {
+        return rc;
+    }
+
+    const EVP_CIPHER* cipher;
+    switch (key_len) {
+    case 16:
+        cipher = EVP_aes_128_cbc();
+        break;
+    case 32:
+        cipher = EVP_aes_256_cbc();
+        break;
+    default:
+        TLOGE("invalid key length: (%zd)\n", key_len);
+        return HWKEY_ERR_GENERIC;
+    }
+
+    int evp_ret;
+    int out_len = 0;
+    uint8_t* iv = NULL;
+    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
+    if (!cipher_ctx) {
+        return HWKEY_ERR_GENERIC;
+    }
+
+    /* if we exit early */
+    rc = HWKEY_ERR_GENERIC;
+
+    evp_ret = EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL);
+    if (evp_ret != 1) {
+        TLOGE("Initializing decryption algorithm failed\n");
+        goto out;
+    }
+
+    unsigned int iv_length = EVP_CIPHER_CTX_iv_length(cipher_ctx);
+
+    /* encrypted key contains IV + ciphertext */
+    if (iv_length >= *data->encrypted_key_size_ptr) {
+        TLOGE("Encrypted key is too small\n");
+        goto out;
+    }
+
+    if (kbuf_len < *data->encrypted_key_size_ptr - iv_length) {
+        TLOGE("Not enough space in output buffer\n");
+        rc = HWKEY_ERR_BAD_LEN;
+        goto out;
+    }
+
+    evp_ret = EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key_buffer,
+                                 data->encrypted_key_data);
+    if (evp_ret != 1) {
+        TLOGE("Initializing decryption algorithm failed\n");
+        goto out;
+    }
+
+    evp_ret = EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
+    if (evp_ret != 1) {
+        TLOGE("EVP_CIPHER_CTX_set_padding failed\n");
+        goto out;
+    }
+
+    evp_ret = EVP_DecryptUpdate(cipher_ctx, kbuf, &out_len,
+                                data->encrypted_key_data + iv_length,
+                                *data->encrypted_key_size_ptr - iv_length);
+    if (evp_ret != 1) {
+        TLOGE("EVP_DecryptUpdate failed\n");
+        goto out;
+    }
+
+    /* We don't support padding so input length == output length */
+    assert(out_len >= 0 &&
+           (unsigned int)out_len == *data->encrypted_key_size_ptr - iv_length);
+
+    evp_ret = EVP_DecryptFinal_ex(cipher_ctx, NULL, &out_len);
+    if (evp_ret != 1) {
+        TLOGE("EVP_DecryptFinal failed\n");
+        goto out;
+    }
+
+    assert(out_len == 0);
+
+    *klen = *data->encrypted_key_size_ptr - iv_length;
+
+    /* Decryption was successful */
+    rc = HWKEY_NO_ERROR;
+
+out:
+    if (iv) {
+        free(iv);
+    }
+    EVP_CIPHER_CTX_free(cipher_ctx);
+    return rc;
+}
+
+/*
+ * Handle get key slot command
+ */
+static int hwkey_handle_get_keyslot_cmd(struct hwkey_chan_ctx* ctx,
+                                        struct hwkey_msg* hdr,
+                                        const char* slot_id) {
+    int rc;
+    size_t klen = 0;
+
+    hdr->header.status = _handle_slots(ctx, slot_id, key_slots, key_slot_cnt,
+                                       key_data, sizeof(key_data), &klen);
+
+    rc = hwkey_send_rsp(ctx, hdr, key_data, klen);
+    if (klen) {
+        /* sanitize key buffer */
+        memset(key_data, 0, klen);
+    }
+    return rc;
+}
+
+/* Shared implementation for the unversioned key derivation API */
+static uint32_t hwkey_handle_derive_key_impl(uint32_t* kdf_version,
+                                             const uuid_t* uuid,
+                                             const uint8_t* context,
+                                             size_t context_len,
+                                             uint8_t* key,
+                                             size_t key_len) {
+    /* check requested key derivation function */
+    if (*kdf_version == HWKEY_KDF_VERSION_BEST) {
+        *kdf_version = HWKEY_KDF_VERSION_1;
+    }
+
+    if (!context || !key || key_len == 0) {
+        return HWKEY_ERR_NOT_VALID;
+    }
+
+    switch (*kdf_version) {
+    case HWKEY_KDF_VERSION_1:
+        return derive_key_v1(uuid, context, context_len, key, key_len);
+
+    default:
+        TLOGE("%u is unsupported KDF function\n", *kdf_version);
+        return HWKEY_ERR_NOT_IMPLEMENTED;
+    }
+}
+
+/*
+ * Handle Derive key cmd
+ */
+static int hwkey_handle_derive_key_cmd(struct hwkey_chan_ctx* ctx,
+                                       struct hwkey_msg* hdr,
+                                       const uint8_t* ikm_data,
+                                       size_t ikm_len) {
+    int rc;
+    size_t key_len = ikm_len;
+    if (key_len > HWKEY_MAX_MSG_SIZE - sizeof(*hdr)) {
+        TLOGE("Key length exceeds message size: %zu\n", key_len);
+        key_len = 0;
+        hdr->header.status = HWKEY_ERR_BAD_LEN;
+        goto send_response;
+    }
+
+    hdr->header.status = hwkey_handle_derive_key_impl(
+            &hdr->arg1, &ctx->uuid, ikm_data, ikm_len, key_data, key_len);
+
+send_response:
+    rc = hwkey_send_rsp(ctx, hdr, key_data, key_len);
+    if (key_len) {
+        /* sanitize key buffer */
+        memset(key_data, 0, sizeof(key_data));
+    }
+    return rc;
+}
+
+/**
+ * hwkey_handle_derive_versioned_key_cmd() - Handle versioned key derivation
+ * @ctx: client context
+ * @msg: request/response message
+ * @context: key derivation info input
+ * @context_len: length in bytes of @context
+ *
+ * Derive a new key from an internal secret key, unique to the provided context,
+ * UUID of the client, and requested rollback version. Rollback versions greater
+ * than the current image or fused rollback version are not allowed. See &struct
+ * hwkey_derive_versioned_msg for more details.
+ *
+ * Because key versions newer than the current image rollback version are not
+ * available to clients, incrementing this version in the Trusty image results
+ * in a new set of keys being available that previous Trusty apps never had
+ * access to. This mechanism can be used to roll to new keys after patching a
+ * Trusty app vulnerability that may have exposed old keys. If the key
+ * derivation is implemented outside of Trusty entirely, then keys can be
+ * refreshed after a potential Trusty kernel compromise.
+ *
+ * Return: A negative return value indicates an error occurred sending the IPC
+ *         response back to the client.
+ */
+static int hwkey_handle_derive_versioned_key_cmd(
+        struct hwkey_chan_ctx* ctx,
+        struct hwkey_derive_versioned_msg* msg,
+        const uint8_t* context,
+        size_t context_len) {
+    int i;
+    int rc;
+    bool shared = msg->key_options & HWKEY_SHARED_KEY_TYPE;
+    uint32_t status;
+    size_t key_len;
+
+    key_len = msg->key_len;
+    if (key_len > HWKEY_MAX_MSG_SIZE - sizeof(*msg)) {
+        TLOGE("Key length (%zu) exceeds buffer length\n", key_len);
+        status = HWKEY_ERR_BAD_LEN;
+        goto send_response;
+    }
+
+    /*
+     * make sure to retrieve the current OS version before calling
+     * hwkey_derive_versioned_msg_compatible_with_unversioned() so that we
+     * derive the same key with CURRENT == 0 and 0 passed explicitly.
+     */
+
+    int os_rollback_version =
+            msg->rollback_versions[HWKEY_ROLLBACK_VERSION_OS_INDEX];
+    if (os_rollback_version == HWKEY_ROLLBACK_VERSION_CURRENT) {
+        os_rollback_version =
+                get_current_os_rollback_version(msg->rollback_version_source);
+        if (os_rollback_version < 0) {
+            status = HWKEY_ERR_GENERIC;
+            goto send_response;
+        }
+        msg->rollback_versions[HWKEY_ROLLBACK_VERSION_OS_INDEX] =
+                os_rollback_version;
+    }
+
+    for (i = HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT;
+         i < HWKEY_ROLLBACK_VERSION_INDEX_COUNT; ++i) {
+        if (msg->rollback_versions[i] != 0) {
+            TLOGE("Unsupported rollback version set: %d\n", i);
+            status = HWKEY_ERR_NOT_VALID;
+            goto send_response;
+        }
+    }
+
+    if (hwkey_derive_versioned_msg_compatible_with_unversioned(msg)) {
+        status = hwkey_handle_derive_key_impl(&msg->kdf_version, &ctx->uuid,
+                                              context, context_len, key_data,
+                                              key_len);
+        if (key_len == 0) {
+            /*
+             * derive_key_v1() doesn't support an empty key length, but we still
+             * want to allow querying key versions with NULL key and zero
+             * length. Reset the status to ok in this case.
+             */
+            status = HWKEY_NO_ERROR;
+        }
+        goto send_response;
+    }
+
+    /* check requested key derivation function */
+    if (msg->kdf_version == HWKEY_KDF_VERSION_BEST) {
+        msg->kdf_version = HWKEY_KDF_VERSION_1;
+    }
+
+    switch (msg->kdf_version) {
+    case HWKEY_KDF_VERSION_1:
+        status = derive_key_versioned_v1(&ctx->uuid, shared,
+                                         msg->rollback_version_source,
+                                         msg->rollback_versions, context,
+                                         context_len, key_data, key_len);
+        break;
+
+    default:
+        TLOGE("%u is unsupported KDF function\n", msg->kdf_version);
+        status = HWKEY_ERR_NOT_IMPLEMENTED;
+    }
+
+send_response:
+    if (status != HWKEY_NO_ERROR) {
+        msg->key_len = 0;
+    }
+
+    msg->header.status = status;
+    msg->header.cmd |= HWKEY_RESP_BIT;
+    rc = tipc_send2(ctx->chan, msg, sizeof(*msg), key_data, msg->key_len);
+    if (msg->key_len) {
+        /* sanitize key buffer */
+        memset(key_data, 0, sizeof(key_data));
+    }
+    return rc;
+}
+
+/*
+ *  Read and queue HWKEY request message
+ */
+int hwkey_chan_handle_msg(const struct tipc_port* port,
+                          handle_t chan,
+                          void* received_ctx) {
+    int rc;
+    size_t req_data_len;
+    struct hwkey_msg_header* hdr;
+
+    struct hwkey_chan_ctx* ctx = (struct hwkey_chan_ctx*)received_ctx;
+
+    rc = tipc_recv1(ctx->chan, sizeof(*hdr), req_data, sizeof(req_data) - 1);
+    if (rc < 0) {
+        TLOGE("failed (%d) to recv msg from chan %d\n", rc, ctx->chan);
+        return rc;
+    }
+
+    req_data_len = (size_t)rc;
+
+    if (req_data_len < sizeof(*hdr)) {
+        TLOGE("Received too little data (%zu) from chan %d\n", req_data_len,
+              ctx->chan);
+        return ERR_BAD_LEN;
+    }
+
+    hdr = (struct hwkey_msg_header*)req_data;
+
+    /* handle it */
+    switch (hdr->cmd) {
+    case HWKEY_GET_KEYSLOT:
+        req_data[req_data_len] = 0; /* force zero termination */
+        if (req_data_len < sizeof(struct hwkey_msg)) {
+            TLOGE("Received too little data (%zu) from chan %d\n", req_data_len,
+                  ctx->chan);
+            return ERR_BAD_LEN;
+        }
+        rc = hwkey_handle_get_keyslot_cmd(
+                ctx, (struct hwkey_msg*)req_data,
+                (const char*)(req_data + sizeof(struct hwkey_msg)));
+        break;
+
+    case HWKEY_DERIVE:
+        if (req_data_len < sizeof(struct hwkey_msg)) {
+            TLOGE("Received too little data (%zu) from chan %d\n", req_data_len,
+                  ctx->chan);
+            return ERR_BAD_LEN;
+        }
+        rc = hwkey_handle_derive_key_cmd(
+                ctx, (struct hwkey_msg*)req_data,
+                req_data + sizeof(struct hwkey_msg),
+                req_data_len - sizeof(struct hwkey_msg));
+        memset(req_data, 0, req_data_len); /* sanitize request buffer */
+        break;
+
+    case HWKEY_DERIVE_VERSIONED:
+        if (req_data_len < sizeof(struct hwkey_derive_versioned_msg)) {
+            TLOGE("Received too little data (%zu) from chan %d\n", req_data_len,
+                  ctx->chan);
+            return ERR_BAD_LEN;
+        }
+        rc = hwkey_handle_derive_versioned_key_cmd(
+                ctx, (struct hwkey_derive_versioned_msg*)req_data,
+                req_data + sizeof(struct hwkey_derive_versioned_msg),
+                req_data_len - sizeof(struct hwkey_derive_versioned_msg));
+        memset(req_data, 0, req_data_len); /* sanitize request buffer */
+        break;
+
+    default:
+        TLOGE("Unsupported request: %d\n", (int)hdr->cmd);
+        hdr->status = HWKEY_ERR_NOT_IMPLEMENTED;
+        hdr->cmd |= HWKEY_RESP_BIT;
+        rc = tipc_send1(ctx->chan, hdr, sizeof(*hdr));
+    }
+
+    return rc;
+}
+
+/*
+ *  Install Key slot provider
+ */
+void hwkey_install_keys(const struct hwkey_keyslot* keys, unsigned int kcnt) {
+    assert(key_slots == NULL);
+    assert(key_slot_cnt == 0);
+    assert(keys && kcnt);
+
+    key_slots = keys;
+    key_slot_cnt = kcnt;
+}
+
+static bool is_empty_token(const char* access_token) {
+    for (int i = 0; i < HWKEY_OPAQUE_HANDLE_SIZE; i++) {
+        if (access_token[i] != 0) {
+            assert(strnlen(access_token, HWKEY_OPAQUE_HANDLE_SIZE) ==
+                   HWKEY_OPAQUE_HANDLE_SIZE - 1);
+            return false;
+        }
+    }
+    return true;
+}
+
+uint32_t get_key_handle(const struct hwkey_keyslot* slot,
+                        uint8_t* kbuf,
+                        size_t kbuf_len,
+                        size_t* klen) {
+    assert(kbuf);
+    assert(klen);
+
+    const struct hwkey_opaque_handle_data* handle = slot->priv;
+    assert(handle);
+    assert(kbuf_len >= HWKEY_OPAQUE_HANDLE_SIZE);
+
+    struct opaque_handle_node* entry = find_opaque_handle_for_slot(slot);
+    /* _handle_slots should have already created an entry for this slot */
+    assert(entry);
+
+    if (!is_empty_token(entry->token)) {
+        /*
+         * We do not allow fetching a token again for the same slot again after
+         * the token is first created and returned
+         */
+        return HWKEY_ERR_ALREADY_EXISTS;
+    }
+
+    /*
+     * We want to generate a null-terminated opaque handle with no interior null
+     * bytes, so we generate extra randomness and only use the non-zero bytes.
+     */
+    uint8_t random_buf[HWKEY_OPAQUE_HANDLE_SIZE + 2];
+    while (1) {
+        int rc = trusty_rng_hw_rand(random_buf, sizeof(random_buf));
+        if (rc != NO_ERROR) {
+            /* Don't leave an empty entry if we couldn't generate a token */
+            delete_opaque_handle(entry);
+            return rc;
+        }
+
+        size_t token_offset = 0;
+        for (size_t i = 0; i < sizeof(random_buf) &&
+                           token_offset < HWKEY_OPAQUE_HANDLE_SIZE - 1;
+             ++i) {
+            if (random_buf[i] != 0) {
+                entry->token[token_offset] = random_buf[i];
+                token_offset++;
+            }
+        }
+        if (token_offset == HWKEY_OPAQUE_HANDLE_SIZE - 1) {
+            break;
+        }
+    }
+
+    /* ensure that token is properly null-terminated */
+    assert(entry->token[HWKEY_OPAQUE_HANDLE_SIZE - 1] == 0);
+
+    memcpy(kbuf, entry->token, HWKEY_OPAQUE_HANDLE_SIZE);
+    *klen = HWKEY_OPAQUE_HANDLE_SIZE;
+
+    return HWKEY_NO_ERROR;
+}
+
+uint32_t get_opaque_key(const uuid_t* uuid,
+                        const char* access_token,
+                        uint8_t* kbuf,
+                        size_t kbuf_len,
+                        size_t* klen) {
+    struct opaque_handle_node* entry;
+    list_for_every_entry(&opaque_handles, entry, struct opaque_handle_node,
+                         node) {
+        /* get_key_handle should never leave an empty token in the list */
+        assert(!is_empty_token(entry->token));
+
+        if (!is_allowed_to_read_opaque_key(uuid, entry->key_slot))
+            continue;
+
+        /*
+         * We are using a constant-time memcmp here to avoid side-channel
+         * leakage of the access token. Even if we trust the service that is
+         * allowed to retrieve this key, one of its clients may be trying to
+         * brute force the token, so this comparison must be constant-time.
+         */
+        if (CRYPTO_memcmp(entry->token, access_token,
+                          HWKEY_OPAQUE_HANDLE_SIZE) == 0) {
+            const struct hwkey_opaque_handle_data* handle =
+                    entry->key_slot->priv;
+            assert(handle);
+            return handle->retriever(handle, kbuf, kbuf_len, klen);
+        }
+    }
+
+    return HWKEY_ERR_NOT_FOUND;
+}
+
+/*
+ * Create hwkey channel context
+ */
+int hwkey_chan_ctx_create(const struct tipc_port* port,
+                          handle_t chan,
+                          const struct uuid* peer,
+                          void** ctx) {
+    struct hwkey_chan_ctx* chan_ctx = calloc(1, sizeof(*chan_ctx));
+
+    if (!chan_ctx) {
+        return ERR_NO_MEMORY;
+    }
+
+    chan_ctx->uuid = *peer;
+    chan_ctx->chan = chan;
+    *ctx = chan_ctx;
+
+    return NO_ERROR;
+}
+
+/*
+ * Close specified hwkey channel context
+ */
+void hwkey_chan_ctx_close(void* ctx) {
+    struct opaque_handle_node* entry;
+    struct opaque_handle_node* temp;
+    list_for_every_entry_safe(&opaque_handles, entry, temp,
+                              struct opaque_handle_node, node) {
+        if (entry->owner == ctx) {
+            delete_opaque_handle(entry);
+        }
+    }
+    free(ctx);
+}
diff --git a/app/hwkey/hwkey_srv_gsc_provider.c b/app/hwkey/hwkey_srv_gsc_provider.c
new file mode 100644
index 0000000..57da5c7
--- /dev/null
+++ b/app/hwkey/hwkey_srv_gsc_provider.c
@@ -0,0 +1,819 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#define TLOG_TAG "hwkey_gsc_srv"
+
+#include <assert.h>
+#include <lk/compiler.h>
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <uapi/err.h>
+
+#include <openssl/aes.h>
+#include <openssl/cipher.h>
+#include <openssl/digest.h>
+#include <openssl/err.h>
+#include <openssl/hkdf.h>
+
+#include <interface/hwaes/hwaes.h>
+#include <interface/hwkey/hwkey.h>
+#include <lib/system_state/system_state.h>
+#include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
+#include <trusty_log.h>
+
+#include <hwkey_consts.h>
+#include "hwkey_srv_priv.h"
+
+/* 0 means unlimited number of connections */
+#define HWKEY_MAX_NUM_CHANNELS 0
+
+static uint8_t encrypt_key[32];
+static uint8_t attest_key[32];
+static int32_t rollback_ver;
+static int32_t running_ver;
+
+/*
+ * Derive key V1 - HMAC SHA256 based Key derivation function
+ */
+uint32_t derive_key_v1(const uuid_t* uuid,
+                       const uint8_t* ikm_data,
+                       size_t ikm_len,
+                       uint8_t* key_buf,
+                       size_t key_len) {
+    if (!ikm_len) {
+        return HWKEY_ERR_BAD_LEN;
+    }
+
+    if (!HKDF(key_buf, key_len, EVP_sha256(), (const uint8_t*)encrypt_key,
+              sizeof(encrypt_key), (const uint8_t*)uuid, sizeof(uuid_t),
+              ikm_data, ikm_len)) {
+        TLOGE("HDKF failed 0x%x\n", ERR_get_error());
+        memset(key_buf, 0, key_len);
+        return HWKEY_ERR_GENERIC;
+    }
+
+    return HWKEY_NO_ERROR;
+}
+
+/*
+ * Context labels for key derivation contexts, see derive_key_versioned_v1() for
+ * details.
+ */
+#define HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL "DERIVE VERSIONED"
+#define ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL "TZOS"
+
+#define HWKEY_DERIVE_VERSIONED_SALT "hwkey derive versioned salt"
+
+static uint8_t context_buf[4096];
+
+/**
+ * fill_context_buf() - Add data to context_buf
+ * @src: Pointer to data to copy into the context buf. If null, @len zero bytes
+ *       will be added.
+ * @len: Number of bytes of data to add.
+ * @cur_position: Pointer to the next unwritten byte of context_buf. Updated
+ *                with the new current position when successful.
+ *
+ * Return: HWKEY_NO_ERROR on success, HWKEY_ERR_BAD_LEN if @len will cause the
+ * buffer to overflow.
+ */
+static uint32_t fill_context_buf(const void* src,
+                                 size_t len,
+                                 size_t* cur_position) {
+    size_t new_position;
+    if (len == 0) {
+        return HWKEY_NO_ERROR;
+    }
+    if (__builtin_add_overflow(*cur_position, len, &new_position) ||
+        new_position >= sizeof(context_buf)) {
+        return HWKEY_ERR_BAD_LEN;
+    }
+    if (src == NULL) {
+        memset(&context_buf[*cur_position], 0, len);
+    } else {
+        memcpy(&context_buf[*cur_position], src, len);
+    }
+    *cur_position = new_position;
+    return HWKEY_NO_ERROR;
+}
+
+/*
+ * In a real implementation this portion of the derivation should be done by a
+ * trusted source of the Trusty OS rollback version. Doing the key derivation
+ * here in the hwkey service protects against some app-level compromises, but
+ * does not protect against compromise of any Trusty code that can derive
+ * directly using the secret key derivation input - which in this sample
+ * implementation would be the kernel and the hwkey service.
+ *
+ * This function MUST mix @rollback_version_source, @os_rollback_version, and
+ * @hwkey_context into the derivation context in a way that the client cannot
+ * forge.
+ */
+static uint32_t root_of_trust_derive_key(bool shared,
+                                         uint32_t rollback_version_source,
+                                         int32_t os_rollback_version,
+                                         const uint8_t* hwkey_context,
+                                         size_t hwkey_context_len,
+                                         uint8_t* key_buf,
+                                         size_t key_len) {
+    size_t context_len = 0;
+    int rc;
+    const size_t root_of_trust_context_len =
+            sizeof(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL) +
+            sizeof(rollback_version_source) + sizeof(os_rollback_version);
+    const uint8_t* secret_key;
+    size_t secret_key_len;
+    size_t total_len;
+
+    /*
+     * We need to move the hwkey_context (currently at the beginning of
+     * context_buf) over to make room for the root-of-trust context injected
+     * before it. We avoid the need for a separate buffer by memmoving it first
+     * then adding the context into the space we made.
+     */
+    if (__builtin_add_overflow(hwkey_context_len, root_of_trust_context_len,
+                               &total_len) ||
+        total_len >= sizeof(context_buf)) {
+        return HWKEY_ERR_BAD_LEN;
+    }
+    memmove(&context_buf[root_of_trust_context_len], hwkey_context,
+            hwkey_context_len);
+
+    /*
+     * Add a fixed label to ensure that another user of the same key derivation
+     * primitive will not collide with this use, regardless of the provided
+     * hwkey_context (as long as other users also add a different fixed label).
+     */
+    rc = fill_context_buf(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL,
+                          sizeof(ROOT_OF_TRUST_DERIVE_CONTEXT_LABEL),
+                          &context_len);
+    if (rc) {
+        return rc;
+    }
+    /* Keys for different version limit sources must be different */
+    rc = fill_context_buf(&rollback_version_source,
+                          sizeof(rollback_version_source), &context_len);
+    if (rc) {
+        return rc;
+    }
+    /*
+     * Keys with different rollback versions must not be the same. This is part
+     * of the root-of-trust context to ensure that a compromised kernel cannot
+     * forge a version (if the root of trust is outside of Trusty)
+     */
+    rc = fill_context_buf(&os_rollback_version, sizeof(os_rollback_version),
+                          &context_len);
+    if (rc) {
+        return rc;
+    }
+
+    assert(root_of_trust_context_len == context_len);
+
+    /*
+     * We already moved the hwkey_context into place after the root of trust
+     * context.
+     */
+    context_len += hwkey_context_len;
+
+    if (shared) {
+        secret_key = attest_key;
+        secret_key_len = sizeof(attest_key);
+    } else {
+        secret_key = encrypt_key;
+        secret_key_len = sizeof(encrypt_key);
+    }
+
+    if (!HKDF(key_buf, key_len, EVP_sha256(), secret_key, secret_key_len,
+              (const uint8_t*)HWKEY_DERIVE_VERSIONED_SALT,
+              sizeof(HWKEY_DERIVE_VERSIONED_SALT), context_buf, context_len)) {
+        TLOGE("HDKF failed 0x%x\n", ERR_get_error());
+        memset(key_buf, 0, key_len);
+        return HWKEY_ERR_GENERIC;
+    }
+    return HWKEY_NO_ERROR;
+}
+
+int32_t get_current_os_rollback_version(uint32_t source) {
+    switch (source) {
+    case HWKEY_ROLLBACK_RUNNING_VERSION:
+        return running_ver;
+
+    case HWKEY_ROLLBACK_COMMITTED_VERSION:
+        return rollback_ver;
+
+    default:
+        TLOGE("Unknown rollback version source: %u\n", source);
+        return ERR_NOT_VALID;
+    }
+}
+
+/*
+ * Derive a versioned key - HMAC SHA256 based versioned key derivation function
+ */
+uint32_t derive_key_versioned_v1(
+        const uuid_t* uuid,
+        bool shared,
+        uint32_t rollback_version_source,
+        int32_t rollback_versions[HWKEY_ROLLBACK_VERSION_INDEX_COUNT],
+        const uint8_t* user_context,
+        size_t user_context_len,
+        uint8_t* key_buf,
+        size_t key_len) {
+    size_t context_len = 0;
+    int i;
+    uint32_t rc = HWKEY_NO_ERROR;
+    int32_t os_rollback_version =
+            rollback_versions[HWKEY_ROLLBACK_VERSION_OS_INDEX];
+    int32_t os_rollback_version_current =
+            get_current_os_rollback_version(rollback_version_source);
+
+    if (os_rollback_version_current < 0) {
+        rc = HWKEY_ERR_NOT_VALID;
+        goto err;
+    }
+
+    if (os_rollback_version > os_rollback_version_current) {
+        TLOGE("Requested rollback version too new: %u\n", os_rollback_version);
+        rc = HWKEY_ERR_NOT_FOUND;
+        goto err;
+    }
+
+    /* short-circuit derivation if we have nothing to derive */
+    if (key_len == 0) {
+        rc = HWKEY_NO_ERROR;
+        goto err;
+    }
+
+    /* for compatibility with unversioned derive, require a context */
+    if (!key_buf || !user_context || user_context_len == 0) {
+        rc = HWKEY_ERR_NOT_VALID;
+        goto err;
+    }
+
+    /*
+     * This portion of the context may always be added by the hwkey service, as
+     * it deals with the identity of the client requesting the key derivation.
+     */
+    /*
+     * Fixed label ensures that this derivation will not collide with a
+     * different user of root_of_trust_derive_key(), regardless of the provided
+     * user context (as long as other users also add a different fixed label).
+     */
+    rc = fill_context_buf(HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL,
+                          sizeof(HWKEY_DERIVE_VERSIONED_CONTEXT_LABEL),
+                          &context_len);
+    if (rc) {
+        goto err;
+    }
+    /* Keys for different apps must be different */
+    rc = fill_context_buf(uuid, sizeof(*uuid), &context_len);
+    if (rc) {
+        goto err;
+    }
+    for (i = 0; i < HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT; ++i) {
+        /*
+         * We skip the OS version because the root-of-trust should be inserting
+         * that, and we don't want to mask a buggy implementation there in
+         * testing. If the root-of-trust somehow did not insert the OS version,
+         * we want to notice.
+         */
+        if (i == HWKEY_ROLLBACK_VERSION_OS_INDEX) {
+            continue;
+        }
+        rc = fill_context_buf(&rollback_versions[i], sizeof(*rollback_versions),
+                              &context_len);
+        if (rc) {
+            goto err;
+        }
+    }
+    /* Reserve space for additional versions in the future */
+    if (HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT <
+        HWKEY_ROLLBACK_VERSION_INDEX_COUNT) {
+        rc = fill_context_buf(NULL,
+                              sizeof(*rollback_versions) *
+                                      (HWKEY_ROLLBACK_VERSION_INDEX_COUNT -
+                                       HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT),
+                              &context_len);
+        if (rc) {
+            goto err;
+        }
+    }
+    /*
+     * Clients need to be able to generate multiple different keys in the same
+     * app.
+     */
+    rc = fill_context_buf(user_context, user_context_len, &context_len);
+    if (rc) {
+        goto err;
+    }
+
+    rc = root_of_trust_derive_key(shared, rollback_version_source,
+                                  os_rollback_version, context_buf, context_len,
+                                  key_buf, key_len);
+    if (rc) {
+        goto err;
+    }
+
+err:
+    memset(context_buf, 0, sizeof(context_buf));
+    return rc;
+}
+
+/* UUID of HWCRYPTO_UNITTEST application */
+static const uuid_t hwcrypto_unittest_uuid = HWCRYPTO_UNITTEST_APP_UUID;
+static const uuid_t hwcrypto_unittest_rust_uuid =
+        HWCRYPTO_UNITTEST_RUST_APP_UUID;
+
+#if WITH_HWCRYPTO_UNITTEST
+/*
+ *  Support for hwcrypto unittest keys should be only enabled
+ *  to test hwcrypto related APIs
+ */
+
+static uint8_t _unittest_key32[32] = "unittestkeyslotunittestkeyslotun";
+static uint32_t get_unittest_key32(uint8_t* kbuf,
+                                   size_t kbuf_len,
+                                   size_t* klen) {
+    assert(kbuf);
+    assert(klen);
+    assert(kbuf_len >= sizeof(_unittest_key32));
+
+    /* just return predefined key */
+    memcpy(kbuf, _unittest_key32, sizeof(_unittest_key32));
+    *klen = sizeof(_unittest_key32);
+
+    return HWKEY_NO_ERROR;
+}
+
+static uint32_t get_unittest_key32_handler(const struct hwkey_keyslot* slot,
+                                           uint8_t* kbuf,
+                                           size_t kbuf_len,
+                                           size_t* klen) {
+    return get_unittest_key32(kbuf, kbuf_len, klen);
+}
+
+/*
+ * "unittestderivedkeyslotunittestde" encrypted with _unittest_key32 using an
+ * all 0 IV. IV is prepended to the ciphertext.
+ */
+static uint8_t _unittest_encrypted_key32[48] = {
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x3e, 0x2b, 0x02, 0x54, 0x54, 0x8c, 0xa7, 0xb8,
+        0xa3, 0xfa, 0xf5, 0xd0, 0xbc, 0x1d, 0x40, 0x11, 0xac, 0x68, 0xbb, 0xf0,
+        0x55, 0xa3, 0xc5, 0x49, 0x3e, 0x77, 0x4a, 0x8b, 0x3f, 0x33, 0x56, 0x07,
+};
+
+static unsigned int _unittest_encrypted_key32_size =
+        sizeof(_unittest_encrypted_key32);
+
+static uint32_t get_unittest_key32_derived(
+        const struct hwkey_derived_keyslot_data* data,
+        uint8_t* kbuf,
+        size_t kbuf_len,
+        size_t* klen) {
+    return get_unittest_key32(kbuf, kbuf_len, klen);
+}
+
+static const struct hwkey_derived_keyslot_data hwcrypto_unittest_derived_data =
+        {
+                .encrypted_key_data = _unittest_encrypted_key32,
+                .encrypted_key_size_ptr = &_unittest_encrypted_key32_size,
+                .retriever = get_unittest_key32_derived,
+};
+
+static uint32_t derived_keyslot_handler(const struct hwkey_keyslot* slot,
+                                        uint8_t* kbuf,
+                                        size_t kbuf_len,
+                                        size_t* klen) {
+    assert(slot);
+    return hwkey_get_derived_key(slot->priv, kbuf, kbuf_len, klen);
+}
+
+static const uuid_t* unittest_allowed_opaque_key_uuids[] = {
+        &hwcrypto_unittest_uuid,
+        &hwcrypto_unittest_rust_uuid,
+};
+
+static uint32_t get_unittest_key32_opaque(
+        const struct hwkey_opaque_handle_data* data,
+        uint8_t* kbuf,
+        size_t kbuf_len,
+        size_t* klen) {
+    return get_unittest_key32(kbuf, kbuf_len, klen);
+}
+
+static struct hwkey_opaque_handle_data unittest_opaque_handle_data = {
+        .allowed_uuids = unittest_allowed_opaque_key_uuids,
+        .allowed_uuids_len = countof(unittest_allowed_opaque_key_uuids),
+        .retriever = get_unittest_key32_opaque,
+};
+
+static struct hwkey_opaque_handle_data unittest_opaque_handle_data2 = {
+        .allowed_uuids = unittest_allowed_opaque_key_uuids,
+        .allowed_uuids_len = countof(unittest_allowed_opaque_key_uuids),
+        .retriever = get_unittest_key32_opaque,
+};
+
+static struct hwkey_opaque_handle_data unittest_opaque_handle_data_noaccess = {
+        .allowed_uuids = NULL,
+        .allowed_uuids_len = 0,
+        .retriever = get_unittest_key32_opaque,
+};
+
+/*
+ * Adapter to cast hwkey_opaque_handle_data.priv field to struct
+ * hwkey_derived_keyslot_data*
+ */
+static uint32_t get_derived_key_opaque(
+        const struct hwkey_opaque_handle_data* data,
+        uint8_t* kbuf,
+        size_t kbuf_len,
+        size_t* klen) {
+    assert(data);
+    return hwkey_get_derived_key(data->priv, kbuf, kbuf_len, klen);
+}
+
+static struct hwkey_opaque_handle_data unittest_opaque_derived_data = {
+        .allowed_uuids = unittest_allowed_opaque_key_uuids,
+        .allowed_uuids_len = countof(unittest_allowed_opaque_key_uuids),
+        .retriever = get_derived_key_opaque,
+        .priv = &hwcrypto_unittest_derived_data,
+};
+
+#endif /* WITH_HWCRYPTO_UNITTEST */
+
+/*
+ *  RPMB Key support
+ */
+#define RPMB_SS_AUTH_KEY_SIZE 32
+#define RPMB_SS_AUTH_KEY_ID "com.android.trusty.storage_auth.rpmb"
+
+/* Secure storage service app uuid */
+static const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;
+
+static uint8_t rpmb_salt[RPMB_SS_AUTH_KEY_SIZE] = {
+        0x42, 0x18, 0xa9, 0xf2, 0xf6, 0xb1, 0xf5, 0x35, 0x06, 0x37, 0x9f,
+        0xba, 0xcc, 0x1a, 0xc9, 0x36, 0xf4, 0x83, 0x04, 0xd4, 0xf1, 0x65,
+        0x91, 0x32, 0xa6, 0xae, 0xda, 0x27, 0x4d, 0x21, 0xdb, 0x40};
+
+/*
+ * Generate RPMB Secure Storage Authentication key
+ */
+static uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot* slot,
+                                     uint8_t* kbuf,
+                                     size_t kbuf_len,
+                                     size_t* klen) {
+    int rc;
+    int out_len;
+    EVP_CIPHER_CTX evp;
+
+    assert(kbuf);
+    assert(klen);
+
+    EVP_CIPHER_CTX_init(&evp);
+
+    rc = EVP_EncryptInit_ex(&evp, EVP_aes_256_cbc(), NULL, encrypt_key,
+                            NULL);
+    if (!rc)
+        goto evp_err;
+
+    rc = EVP_CIPHER_CTX_set_padding(&evp, 0);
+    if (!rc)
+        goto evp_err;
+
+    size_t min_kbuf_len =
+            RPMB_SS_AUTH_KEY_SIZE + EVP_CIPHER_CTX_key_length(&evp);
+    if (kbuf_len < min_kbuf_len) {
+        TLOGE("buffer too small: (%zd vs. %zd )\n", kbuf_len, min_kbuf_len);
+        goto other_err;
+    }
+
+    rc = EVP_EncryptUpdate(&evp, kbuf, &out_len, rpmb_salt, sizeof(rpmb_salt));
+    if (!rc)
+        goto evp_err;
+
+    if ((size_t)out_len != RPMB_SS_AUTH_KEY_SIZE) {
+        TLOGE("output length mismatch (%zd vs %zd)\n", (size_t)out_len,
+              sizeof(rpmb_salt));
+        goto other_err;
+    }
+
+    rc = EVP_EncryptFinal_ex(&evp, NULL, &out_len);
+    if (!rc)
+        goto evp_err;
+
+    *klen = RPMB_SS_AUTH_KEY_SIZE;
+
+    EVP_CIPHER_CTX_cleanup(&evp);
+    return HWKEY_NO_ERROR;
+
+evp_err:
+    TLOGE("EVP err 0x%x\n", ERR_get_error());
+other_err:
+    EVP_CIPHER_CTX_cleanup(&evp);
+    return HWKEY_ERR_GENERIC;
+}
+
+/*
+ * Keymint KAK support
+ */
+#define KM_KAK_SIZE 32
+/* TODO import this constant from KM TA when build support is ready */
+#define KM_KAK_ID "com.android.trusty.keymint.kak"
+
+/* KM app uuid */
+static const uuid_t km_uuid = KM_APP_UUID;
+
+/* KM rust app uuid */
+static const uuid_t km_rust_uuid = KM_RUST_APP_UUID;
+
+#if TEST_BUILD
+/* KM rust unit test uuid */
+static const uuid_t km_rust_unittest_uuid = KM_RUST_UNITTEST_UUID;
+
+/* HWCrypto HAL rust unit test uuid */
+static const uuid_t hwcryptohal_rust_unittest_uuid =
+        HWCRYPTOHAL_UNITTEST_RUST_APP_UUID;
+#endif
+
+/* HWCrypto HAL rust unit test uuid */
+static const uuid_t hwcryptohal_rust_uuid = HWCRYPTOHAL_RUST_APP_UUID;
+
+static uint8_t kak_salt[KM_KAK_SIZE];
+
+/*
+ * This should be replaced with a device-specific implementation such that
+ * any Strongbox on the device will have the same KAK.
+ */
+static uint32_t get_km_kak_key(const struct hwkey_keyslot* slot,
+                               uint8_t* kbuf,
+                               size_t kbuf_len,
+                               size_t* klen) {
+    assert(kbuf);
+    assert(klen);
+
+    if (kbuf_len < KM_KAK_SIZE) {
+        return HWKEY_ERR_BAD_LEN;
+    }
+    *klen = KM_KAK_SIZE;
+
+    return derive_key_v1(slot->uuid, kak_salt, KM_KAK_SIZE, kbuf, *klen);
+}
+
+static const uuid_t hwaes_uuid = SAMPLE_HWAES_APP_UUID;
+
+#if WITH_HWCRYPTO_UNITTEST
+static const uuid_t hwaes_unittest_uuid = HWAES_UNITTEST_APP_UUID;
+static const uuid_t hwaes_bench_uuid = HWAES_BENCH_APP_UUID;
+
+static const uuid_t* hwaes_unittest_allowed_opaque_key_uuids[] = {
+        &hwaes_uuid,
+};
+
+static struct hwkey_opaque_handle_data hwaes_unittest_opaque_handle_data = {
+        .allowed_uuids = hwaes_unittest_allowed_opaque_key_uuids,
+        .allowed_uuids_len = countof(hwaes_unittest_allowed_opaque_key_uuids),
+        .retriever = get_unittest_key32_opaque,
+};
+#endif
+
+
+static const uuid_t gatekeeper_uuid = GATEKEEPER_APP_UUID;
+static const uuid_t hwbcc_uuid = SAMPLE_HWBCC_APP_UUID;
+static const uuid_t hwbcc_unittest_uuid = HWBCC_UNITTEST_APP_UUID;
+
+/* Clients that are allowed to connect to this service */
+static const uuid_t* allowed_clients[] = {
+        /* Needs to derive keys and access keyslot RPMB_SS_AUTH_KEY_ID */
+        &ss_uuid,
+        /* Needs to derive keys and access keyslot KM_KAK_ID */
+        &km_uuid,
+        &km_rust_uuid,
+#if TEST_BUILD
+        &km_rust_unittest_uuid,
+        /*HWCrypto HAL needs to derive key and access keylots*/
+        &hwcryptohal_rust_unittest_uuid,
+#endif
+        &hwcryptohal_rust_uuid,
+        /* Needs access to opaque keys */
+        &hwaes_uuid,
+        /* Needs to derive keys */
+        &gatekeeper_uuid,
+
+        /* Needs to derive keys even if it doesn't have test keyslots */
+        &hwcrypto_unittest_uuid,
+        &hwcrypto_unittest_rust_uuid,
+
+#if WITH_HWCRYPTO_UNITTEST
+        &hwaes_unittest_uuid,
+        &hwaes_bench_uuid,
+#endif
+        /* Needs to derive keys */
+        &hwbcc_uuid,
+        /* Needs to derive keys */
+        &hwbcc_unittest_uuid,
+};
+
+/*
+ *  List of keys slots that hwkey service supports
+ */
+static const struct hwkey_keyslot _keys[] = {
+        {
+                .uuid = &ss_uuid,
+                .key_id = RPMB_SS_AUTH_KEY_ID,
+                .handler = get_rpmb_ss_auth_key,
+        },
+        {
+                .uuid = &km_uuid,
+                .key_id = KM_KAK_ID,
+                .handler = get_km_kak_key,
+        },
+        {
+                .uuid = &km_rust_uuid,
+                .key_id = KM_KAK_ID,
+                .handler = get_km_kak_key,
+        },
+#if TEST_BUILD
+        {
+                .uuid = &km_rust_unittest_uuid,
+                .key_id = KM_KAK_ID,
+                .handler = get_km_kak_key,
+        },
+#endif
+#if WITH_HWCRYPTO_UNITTEST
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.key32",
+                .handler = get_unittest_key32_handler,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.key32",
+                .handler = get_unittest_key32_handler,
+        },
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.derived_key32",
+                .priv = &hwcrypto_unittest_derived_data,
+                .handler = derived_keyslot_handler,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.derived_key32",
+                .priv = &hwcrypto_unittest_derived_data,
+                .handler = derived_keyslot_handler,
+        },
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_handle",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_handle",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data,
+        },
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_handle2",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data2,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_handle2",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data2,
+        },
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id =
+                        "com.android.trusty.hwcrypto.unittest.opaque_handle_noaccess",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data_noaccess,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id =
+                        "com.android.trusty.hwcrypto.unittest.opaque_handle_noaccess",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_handle_data_noaccess,
+        },
+        {
+                .uuid = &hwcrypto_unittest_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_derived",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_derived_data,
+        },
+        {
+                .uuid = &hwcrypto_unittest_rust_uuid,
+                .key_id = "com.android.trusty.hwcrypto.unittest.opaque_derived",
+                .handler = get_key_handle,
+                .priv = &unittest_opaque_derived_data,
+        },
+        {
+                .uuid = &hwaes_unittest_uuid,
+                .key_id = "com.android.trusty.hwaes.unittest.opaque_handle",
+                .handler = get_key_handle,
+                .priv = &hwaes_unittest_opaque_handle_data,
+        },
+        {
+                .uuid = &hwaes_bench_uuid,
+                .key_id = "com.android.trusty.hwaes.unittest.opaque_handle",
+                .handler = get_key_handle,
+                .priv = &hwaes_unittest_opaque_handle_data,
+        },
+#endif /* WITH_HWCRYPTO_UNITTEST */
+};
+
+/*
+ *  Initialize HWKEY service
+ */
+static int hwkey_start_service(struct tipc_hset* hset) {
+    TLOGD("Start HWKEY service\n");
+
+    static struct tipc_port_acl acl = {
+            .flags = IPC_PORT_ALLOW_TA_CONNECT,
+            .uuid_num = countof(allowed_clients),
+            .uuids = allowed_clients,
+    };
+
+    static struct tipc_port port = {
+            .name = HWKEY_PORT,
+            .msg_max_size = HWKEY_MAX_MSG_SIZE,
+            .msg_queue_len = 1,
+            .acl = &acl,
+    };
+
+    static struct tipc_srv_ops ops = {
+            .on_message = hwkey_chan_handle_msg,
+            .on_connect = hwkey_chan_ctx_create,
+            .on_channel_cleanup = hwkey_chan_ctx_close,
+    };
+
+    return tipc_add_service(hset, &port, 1, HWKEY_MAX_NUM_CHANNELS, &ops);
+}
+
+/*
+ *  Initialize Fake HWKEY service provider
+ */
+int hwkey_init_srv_provider(struct tipc_hset* hset, uint8_t* encrypt,
+        size_t encrypt_size, uint8_t* attest, size_t attest_size,
+        uint8_t* auth_token_key_seed, size_t auth_token_key_seed_size,
+        int32_t rollback_version, int32_t running_version) {
+    int rc;
+
+    rollback_ver = rollback_version;
+    running_ver = running_version;
+
+    if (encrypt_size != sizeof(encrypt_key)) {
+        TLOGE("bad encryption key size\n");
+        abort();
+    }
+    memcpy(encrypt_key, encrypt, sizeof(encrypt_key));
+    memset(encrypt, 0, encrypt_size);
+
+    if (attest_size != sizeof(attest_key)) {
+        TLOGE("bad attestion key size\n");
+        abort();
+    }
+    memcpy(attest_key, attest, sizeof(attest_key));
+    memset(attest, 0, attest_size);
+
+    if (auth_token_key_seed_size != sizeof(kak_salt)) {
+        TLOGE("bad auth token key seed size\n");
+        abort();
+    }
+    memcpy(kak_salt, auth_token_key_seed, sizeof(kak_salt));
+    memset(auth_token_key_seed, 0, auth_token_key_seed_size);
+
+    /* install key handlers */
+    hwkey_install_keys(_keys, countof(_keys));
+
+    /* start service */
+    rc = hwkey_start_service(hset);
+    if (rc != NO_ERROR) {
+        TLOGE("failed (%d) to start HWKEY service\n", rc);
+    }
+
+    return rc;
+}
diff --git a/app/hwkey/hwkey_srv_priv.h b/app/hwkey/hwkey_srv_priv.h
new file mode 100644
index 0000000..10dbff9
--- /dev/null
+++ b/app/hwkey/hwkey_srv_priv.h
@@ -0,0 +1,190 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#include <interface/hwkey/hwkey.h>
+#include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
+#include <lk/compiler.h>
+#include <stdbool.h>
+#include <sys/types.h>
+#include <uapi/trusty_uuid.h>
+
+struct hwkey_keyslot {
+    const char* key_id;
+    const uuid_t* uuid;
+    const void* priv;
+    uint32_t (*handler)(const struct hwkey_keyslot* slot,
+                        uint8_t* kbuf,
+                        size_t kbuf_len,
+                        size_t* klen);
+};
+
+/**
+ * struct hwkey_derived_keyslot_data - data for a keyslot which derives its key
+ * by decrypting a fixed key
+ *
+ * This slot data is used by hwkey_get_derived_key() which will decrypt the
+ * encrypted data using the key from retriever().
+ *
+ * @encrypted_key_data:
+ *     Block-sized IV followed by encrypted key data
+ */
+struct hwkey_derived_keyslot_data {
+    const uint8_t* encrypted_key_data;
+    const unsigned int* encrypted_key_size_ptr;
+    const void* priv;
+    uint32_t (*retriever)(const struct hwkey_derived_keyslot_data* data,
+                          uint8_t* kbuf,
+                          size_t kbuf_len,
+                          size_t* klen);
+};
+
+/*
+ * Max size (in bytes) of a key returned by &struct
+ * hwkey_derived_keyslot_data.retriever
+ */
+#define HWKEY_DERIVED_KEY_MAX_SIZE 32
+
+#define HWKEY_OPAQUE_HANDLE_SIZE 32
+STATIC_ASSERT(HWKEY_OPAQUE_HANDLE_SIZE <= HWKEY_OPAQUE_HANDLE_MAX_SIZE);
+
+/**
+ * struct hwkey_opaque_handle_data - Opaque handle data for keyslots that allow
+ * opaque usage in hwaes.
+ *
+ * Intended for use in the @hwkey_keyslot.priv field. The retriever function is
+ * equivalent to the generic &hwkey_keyslot->handler but is called only when a
+ * service allowed to unwrap opaque requests this handle.
+ *
+ * @token:             The access token used as an opaque handle to
+ *                     reference this keyslot
+ * @allowed_uuids:     Array of UUIDs that are allowed to retrieve the
+ *                     plaintext key corresponding to an opaque handle
+ *                     for this slot
+ * @allowed_uuids_len: Length of the @allowed_reader_uuids array
+ * @priv:              Opaque pointer to keyslot-specific data
+ * @retriever:         Keyslot-specific callback which retrieves the
+ *                     actual key corresponding to this opaque handle.
+ */
+struct hwkey_opaque_handle_data {
+    const uuid_t** allowed_uuids;
+    size_t allowed_uuids_len;
+    const void* priv;
+    uint32_t (*retriever)(const struct hwkey_opaque_handle_data* data,
+                          uint8_t* kbuf,
+                          size_t kbuf_len,
+                          size_t* klen);
+};
+
+__BEGIN_CDECLS
+
+/**
+ * hwkey_get_derived_key() - Return a slot-specific key using the key data from
+ * hwkey_derived_keyslot_data
+ *
+ * Some devices may store a shared encryption key in hardware. However, we do
+ * not want to allow multiple clients to directly use this key, as they would
+ * then be able to decrypt each other's data. To solve this, we want to be able
+ * to derive unique, client-specific keys from the shared encryption key.
+ *
+ * To use this handler for key derivation from a common shared key, the
+ * encrypting entity should generate a unique, random key for a particular
+ * client, then encrypt that unique key using the common shared key resulting in
+ * a wrapped, client-specific key. This wrapped key can then be safely embedded
+ * in the hwkey service in the &struct
+ * hwkey_derived_keyslot_data.encrypted_key_data field and will only be
+ * accessible using the shared key which is retrieved via the &struct
+ * hwkey_derived_keyslot_data.retriever callback.
+ */
+uint32_t hwkey_get_derived_key(const struct hwkey_derived_keyslot_data* data,
+                               uint8_t* kbuf,
+                               size_t kbuf_len,
+                               size_t* klen);
+
+/**
+ * get_key_handle() - Handler for opaque keys
+ *
+ * Create and return an access token for a key slot. This key slot must contain
+ * a pointer to a &struct hwkey_opaque_handle_data in the &hwkey_keyslot.priv
+ * field.
+ */
+uint32_t get_key_handle(const struct hwkey_keyslot* slot,
+                        uint8_t* kbuf,
+                        size_t kbuf_len,
+                        size_t* klen);
+
+/**
+ * get_opaque_key() - Get an opaque key given an access handle
+ *
+ * @access_token: pointer to an access_token_t
+ */
+uint32_t get_opaque_key(const uuid_t* uuid,
+                        const char* access_token,
+                        uint8_t* kbuf,
+                        size_t kbuf_len,
+                        size_t* klen);
+
+int hwkey_init_srv_provider(struct tipc_hset* hset, uint8_t* encrypt,
+        size_t enrypt_size, uint8_t* attest, size_t attest_size,
+        uint8_t* auth_token_key_seed, size_t auth_token_key_seed_size,
+        int32_t rollback_version,  int32_t running_version);
+
+void hwkey_install_keys(const struct hwkey_keyslot* keys, unsigned int kcnt);
+
+int hwkey_chan_handle_msg(const struct tipc_port* _port,
+                          handle_t _chan,
+                          void* _received_ctx);
+
+int hwkey_chan_ctx_create(const struct tipc_port* port,
+                          handle_t chan,
+                          const struct uuid* peer,
+                          void** ctx);
+
+void hwkey_chan_ctx_close(void* ctx);
+
+uint32_t derive_key_v1(const uuid_t* uuid,
+                       const uint8_t* ikm_data,
+                       size_t ikm_len,
+                       uint8_t* key_data,
+                       size_t key_len);
+
+/**
+ * get_current_os_rollback_versions() - Get the current OS rollback version
+ * @source: Source of the rollback version, one of &enum
+ *          hwkey_rollback_version_source.
+ *
+ * Return: Negative error code on failure, current rollback version otherwise
+ */
+int32_t get_current_os_rollback_version(uint32_t source);
+
+/*
+ * This sample service supports only the first version element in the
+ * rollback_versions array in struct hwkey_derive_versioned_msg.
+ */
+#define HWKEY_ROLLBACK_VERSION_SUPPORTED_COUNT 1
+
+uint32_t derive_key_versioned_v1(
+        const uuid_t* uuid,
+        bool shared,
+        uint32_t rollback_version_source,
+        int32_t rollback_versions[HWKEY_ROLLBACK_VERSION_INDEX_COUNT],
+        const uint8_t* context,
+        size_t context_len,
+        uint8_t* key_data,
+        size_t key_len);
+
+__END_CDECLS
diff --git a/app/hwkey/include/hwcrypto/hwrng_dev.h b/app/hwkey/include/hwcrypto/hwrng_dev.h
new file mode 100644
index 0000000..a5a2e61
--- /dev/null
+++ b/app/hwkey/include/hwcrypto/hwrng_dev.h
@@ -0,0 +1,49 @@
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
+#pragma once
+
+#include <lib/rng/trusty_rng.h>
+#include <lk/compiler.h>
+#include <stddef.h>
+#include <stdint.h>
+
+__BEGIN_CDECLS
+
+/*
+ * These function abstract device-specific details of HWRNG and must be defined
+ * per platform.
+ */
+
+/*
+ * hwrng_dev_init() - initialize HWRNG devices
+ *
+ * Return: NO_ERROR on success, a negative error code otherwise.
+ */
+int hwrng_dev_init(void);
+
+/*
+ * trusty_rng_hw_rand() - get hardware-generated random data. Function
+ * definition located in trusty_rng.h.
+ * @buf: buffer to be filled up
+ * @buf_len: requested amount of random data
+ *
+ * Return: NO_ERROR on success, a negative error code otherwise.
+ *
+ * int trusty_rng_hw_rand(uint8_t* data, size_t len);
+ */
+
+__END_CDECLS
diff --git a/app/hwkey/keybox/keybox.h b/app/hwkey/keybox/keybox.h
new file mode 100644
index 0000000..f629b21
--- /dev/null
+++ b/app/hwkey/keybox/keybox.h
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+#include <stddef.h>
+#include <stdint.h>
+
+#include <lk/macros.h>
+
+#include <interface/keybox/keybox.h>
+
+enum keybox_status keybox_unwrap(const uint8_t* keybox_ciphertext,
+                                 size_t keybox_ciphertext_len,
+                                 uint8_t* keybox_plaintext,
+                                 size_t keybox_plaintext_buf_len,
+                                 size_t* keybox_plaintext_len);
diff --git a/app/hwkey/keybox/keybox_fake_provider.c b/app/hwkey/keybox/keybox_fake_provider.c
new file mode 100644
index 0000000..122dfc4
--- /dev/null
+++ b/app/hwkey/keybox/keybox_fake_provider.c
@@ -0,0 +1,74 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+#define TLOG_TAG "keybox"
+
+#include <assert.h>
+#include <inttypes.h>
+#include <lk/list.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <uapi/err.h>
+
+#include <trusty_log.h>
+
+#include "keybox.h"
+
+/*
+ * THIS DOES NOT PROVIDE ANY SECURITY
+ *
+ * This is not a useful wrapping system. This is just intended as enough to mock
+ * that:
+ * 1. The wrapped data and unwrapped data are not the same.
+ * 2. The wrapped data will fail to unwrap if it is trivially tampered with.
+ */
+enum keybox_status keybox_unwrap(const uint8_t* wrapped_keybox,
+                                 size_t wrapped_keybox_len,
+                                 uint8_t* keybox_plaintext,
+                                 size_t keybox_plaintext_buf_len,
+                                 size_t* keybox_plaintext_len) {
+    if (wrapped_keybox_len < 1) {
+        TLOGE("Wrapped keybox too short: %zu\n", wrapped_keybox_len);
+        return KEYBOX_STATUS_INVALID_REQUEST;
+    }
+
+    if (keybox_plaintext_buf_len < wrapped_keybox_len - 1) {
+        TLOGE("Unwrapped keybox buffer too short: %zu\n",
+              keybox_plaintext_buf_len);
+        return KEYBOX_STATUS_INVALID_REQUEST;
+    }
+
+    /* Validate checksum */
+    uint8_t checksum = 0;
+    for (size_t i = 0; i < wrapped_keybox_len - 1; i++) {
+        checksum ^= wrapped_keybox[i];
+    }
+
+    if (checksum != wrapped_keybox[wrapped_keybox_len - 1]) {
+        TLOGE("Invalid checksum\n");
+        return KEYBOX_STATUS_UNWRAP_FAIL;
+    }
+
+    /* Flip bits with masking byte */
+    for (size_t i = 0; i < wrapped_keybox_len - 1; i++) {
+        keybox_plaintext[i] = wrapped_keybox[i] ^ 0x42;
+    }
+
+    *keybox_plaintext_len = wrapped_keybox_len - 1;
+
+    return KEYBOX_STATUS_SUCCESS;
+}
diff --git a/app/hwkey/keybox/rules.mk b/app/hwkey/keybox/rules.mk
new file mode 100644
index 0000000..be87656
--- /dev/null
+++ b/app/hwkey/keybox/rules.mk
@@ -0,0 +1,24 @@
+#
+# Copyright (C) 2021 The Android Open Source Project
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
+MODULE_SRCS += \
+	$(LOCAL_DIR)/keybox/srv.c \
+	$(LOCAL_DIR)/keybox/keybox_fake_provider.c \
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/base/lib/libc-trusty \
+	trusty/user/base/lib/tipc \
+	trusty/user/base/interface/keybox \
diff --git a/app/hwkey/keybox/srv.c b/app/hwkey/keybox/srv.c
new file mode 100644
index 0000000..d7a5ad3
--- /dev/null
+++ b/app/hwkey/keybox/srv.c
@@ -0,0 +1,154 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+#define TLOG_TAG "keybox"
+
+#include <assert.h>
+#include <inttypes.h>
+#include <lk/list.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <uapi/err.h>
+
+#include <interface/keybox/keybox.h>
+
+#include <lib/tipc/tipc.h>
+#include <trusty_log.h>
+
+#include "keybox.h"
+#include "srv.h"
+
+/* 0 means unlimited number of connections */
+#define KEYBOX_MAX_NUM_CHANNELS 0
+
+struct keybox_chan_ctx {
+    struct tipc_event_handler evt_handler;
+    handle_t chan;
+};
+
+struct full_keybox_unwrap_req {
+    struct keybox_unwrap_req unwrap_header;
+    uint8_t wrapped_keybox[KEYBOX_MAX_SIZE];
+};
+
+struct full_keybox_unwrap_resp {
+    struct keybox_resp header;
+    struct keybox_unwrap_resp unwrap_header;
+};
+
+static int keybox_handle_unwrap(handle_t chan,
+                                struct full_keybox_unwrap_req* req,
+                                size_t req_size) {
+    struct full_keybox_unwrap_resp rsp = {
+            .header.cmd = KEYBOX_CMD_UNWRAP | KEYBOX_CMD_RSP_BIT,
+    };
+
+    uint8_t output[KEYBOX_MAX_SIZE];
+    if (req_size < sizeof(req->unwrap_header)) {
+        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
+        goto out;
+    }
+
+    uint64_t computed_size;
+    if (__builtin_add_overflow(req->unwrap_header.wrapped_keybox_len,
+                               sizeof(req->unwrap_header), &computed_size)) {
+        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
+        goto out;
+    }
+    if (computed_size != req_size) {
+        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
+        goto out;
+    }
+
+    rsp.header.status = keybox_unwrap(
+            req->wrapped_keybox, req->unwrap_header.wrapped_keybox_len, output,
+            sizeof(output), (size_t*)&rsp.unwrap_header.unwrapped_keybox_len);
+    if (rsp.header.status != KEYBOX_STATUS_SUCCESS) {
+        goto out;
+    }
+
+    return tipc_send2(chan, &rsp, sizeof(rsp), output,
+                      rsp.unwrap_header.unwrapped_keybox_len);
+
+out:
+    return tipc_send1(chan, &rsp, sizeof(rsp.header));
+}
+
+struct full_keybox_req {
+    struct keybox_req header;
+    union {
+        struct full_keybox_unwrap_req unwrap;
+    } cmd_header;
+};
+
+static int keybox_chan_handle_msg(const struct tipc_port* port,
+                                  handle_t chan,
+                                  void* ctx) {
+    int rc;
+    struct full_keybox_req req;
+    enum keybox_status status = KEYBOX_STATUS_SUCCESS;
+    rc = tipc_recv1(chan, sizeof(req.header), &req, sizeof(req));
+    if (rc < 0) {
+        TLOGE("Failed (%d) to receive Keybox message\n", rc);
+        return KEYBOX_STATUS_INTERNAL_ERROR;
+    }
+
+    size_t cmd_specific_size = (size_t)rc - sizeof(req.header);
+    switch (req.header.cmd) {
+    case KEYBOX_CMD_UNWRAP:
+        rc = keybox_handle_unwrap(chan, &req.cmd_header.unwrap,
+                                  cmd_specific_size);
+        break;
+    default:
+        TLOGE("Invalid Keybox command: %d\n", req.header.cmd);
+        struct keybox_resp rsp;
+        rsp.cmd = req.header.cmd | KEYBOX_CMD_RSP_BIT;
+        rsp.status = KEYBOX_STATUS_INVALID_REQUEST;
+        rc = tipc_send1(chan, &rsp, sizeof(rsp));
+    }
+
+    if (rc < 0) {
+        status = KEYBOX_STATUS_INTERNAL_ERROR;
+    }
+
+    return status;
+}
+
+/*
+ *  Initialize Keybox service
+ */
+int keybox_start_service(struct tipc_hset* hset) {
+    TLOGD("Start Keybox service\n");
+
+    // TODO: check why we are not restricting connections by uuid
+    static struct tipc_port_acl acl = {
+            .flags = IPC_PORT_ALLOW_TA_CONNECT,
+            .uuid_num = 0,
+            .uuids = NULL,
+    };
+
+    static struct tipc_port port = {
+            .name = KEYBOX_PORT,
+            .msg_max_size = sizeof(struct full_keybox_req),
+            .msg_queue_len = 1,
+            .acl = &acl,
+    };
+    static struct tipc_srv_ops ops = {
+            .on_message = keybox_chan_handle_msg,
+    };
+    return tipc_add_service(hset, &port, 1, KEYBOX_MAX_NUM_CHANNELS, &ops);
+}
diff --git a/app/hwkey/keybox/srv.h b/app/hwkey/keybox/srv.h
new file mode 100644
index 0000000..2c65108
--- /dev/null
+++ b/app/hwkey/keybox/srv.h
@@ -0,0 +1,27 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+#include <lib/tipc/tipc.h>
+#include <lib/tipc/tipc_srv.h>
+#include <lk/compiler.h>
+
+__BEGIN_CDECLS
+
+int keybox_start_service(struct tipc_hset*);
+
+__END_CDECLS
diff --git a/app/hwkey/main.c b/app/hwkey/main.c
new file mode 100644
index 0000000..e98d096
--- /dev/null
+++ b/app/hwkey/main.c
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+#define TLOG_TAG "hwcrypto_srv"
+
+#include <assert.h>
+#include <inttypes.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <uapi/err.h>
+
+#include <hwcrypto/hwrng_dev.h>
+#include <lib/tipc/tipc.h>
+#include <lk/err_ptr.h>
+#include <trusty_log.h>
+
+#include "hwkey_srv_priv.h"
+#include "hwrng_srv_priv.h"
+
+#include "keybox/srv.h"
+
+/*
+ *  Main application event loop
+ */
+int main(void) {
+    int rc;
+    struct tipc_hset* hset;
+
+    TLOGD("Initializing\n");
+
+    hset = tipc_hset_create();
+    if (IS_ERR(hset)) {
+        rc = PTR_ERR(hset);
+        TLOGE("tipc_hset_create failed (%d)\n", rc);
+        goto out;
+    }
+
+    /* initialize service providers */
+#if WITH_HWCRYPTO_HWRNG
+    rc = hwrng_start_service(hset);
+    if (rc != NO_ERROR) {
+        TLOGE("Failed (%d) to initialize HWRNG service\n", rc);
+        goto out;
+    }
+#endif
+
+    /*rc = hwkey_init_srv_provider(hset);*/
+    /*if (rc != NO_ERROR) {*/
+        /*TLOGE("Failed (%d) to initialize HwKey service\n", rc);*/
+        /*goto out;*/
+    /*}*/
+
+#if defined(WITH_FAKE_KEYBOX)
+    rc = keybox_start_service(hset);
+    if (rc != NO_ERROR) {
+        TLOGE("Failed (%d) to initialize Keybox service\n", rc);
+        goto out;
+    }
+#endif
+
+    TLOGD("enter main event loop\n");
+
+    /* enter main event loop */
+    rc = tipc_run_event_loop(hset);
+
+out:
+    return rc;
+}
diff --git a/app/hwkey/manifest.json b/app/hwkey/manifest.json
new file mode 100644
index 0000000..47c2cc2
--- /dev/null
+++ b/app/hwkey/manifest.json
@@ -0,0 +1,5 @@
+{
+    "uuid": "GEN_HWCRYPTO_UUID",
+    "min_heap": 24576,
+    "min_stack": 8192
+}
diff --git a/app/hwkey/rules.mk b/app/hwkey/rules.mk
new file mode 100644
index 0000000..49178ee
--- /dev/null
+++ b/app/hwkey/rules.mk
@@ -0,0 +1,40 @@
+#
+# Copyright (C) 2016 The Android Open Source Project
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
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CONSTANTS := $(LOCAL_DIR)/hwcrypto_consts.json
+
+MODULE_INCLUDES := $(LOCAL_DIR)/include
+
+MODULE_SRCS := \
+	$(LOCAL_DIR)/hwkey.c \
+	$(LOCAL_DIR)/hwkey_srv.c \
+	$(LOCAL_DIR)/hwkey_srv_gsc_provider.c \
+
+
+MODULE_LIBRARY_DEPS := \
+	external/boringssl \
+	trusty/user/base/interface/hwaes \
+	trusty/user/base/interface/hwrng \
+	trusty/user/base/interface/hwkey \
+	trusty/user/base/lib/libc-trusty \
+	trusty/user/base/lib/system_state \
+	trusty/user/base/lib/tipc \
+
+include make/library.mk
diff --git a/app/hwkey/rust/manifest.json b/app/hwkey/rust/manifest.json
new file mode 100644
index 0000000..d557770
--- /dev/null
+++ b/app/hwkey/rust/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hwkey",
+    "uuid": "8725bc1c-b333-47f7-9dff-5730aa18f6bf",
+    "min_heap": 24576,
+    "min_stack": 8192
+}
diff --git a/app/hwkey/rust/rules.mk b/app/hwkey/rust/rules.mk
new file mode 100644
index 0000000..6fba2e4
--- /dev/null
+++ b/app/hwkey/rust/rules.mk
@@ -0,0 +1,37 @@
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
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := $(LOCAL_DIR)/src/main.rs
+
+MODULE_CRATE_NAME := hwkey
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy-derive) \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/lib/service_manager/client \
+	trusty/user/desktop/interface/boot_params/aidl \
+	trusty/user/base/lib/trusty-std \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/desktop/app/hwkey \
+
+include make/trusted_app.mk
diff --git a/app/hwkey/rust/src/main.rs b/app/hwkey/rust/src/main.rs
new file mode 100644
index 0000000..68d5f6e
--- /dev/null
+++ b/app/hwkey/rust/src/main.rs
@@ -0,0 +1,69 @@
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
+use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::IBootParams;
+use service_manager::wait_for_interface;
+
+const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1";
+
+// TODO(b/418065023) Support versioned keys.
+// Until version keys are implemented, reserve a special case for use CDI_SEAL.
+const VERSION_CDI_SEAL: i32 = 0;
+// Until version keys are implement, reserve a special case for use when we bave the base framwork
+// but cannot generate older versions.
+const _VERSION_UNVERSIONED: i32 = 1;
+
+extern "C" {
+    // Implementations of run_hwkey should not retain any referencs but may clear the contents of
+    // encrypt and sign.
+    fn run_hwkey(
+        encrypt: *mut u8,
+        encrypt_size: usize,
+        sign: *mut u8,
+        sign_size: usize,
+        auth_token_key_seed: *mut u8,
+        auth_token_key_seed_size: usize,
+        rollback_version: i32,
+        running_version: i32,
+    ) -> i32;
+}
+
+fn main() {
+    trusty_log::init();
+    log::info!("HwKey starting.");
+    let bp: binder::Strong<dyn IBootParams> =
+        wait_for_interface(BP_SERVICE_PORT).expect("Could not connect");
+
+    let mut seal = bp.getCdiSeal().expect("Could not get seal");
+    let mut sign = bp.getCdiAttest().expect("Could not get sign");
+    let mut auth_token_key_seed =
+        bp.getAuthTokenKeySeed().expect("Could not get auth token key seed");
+
+    log::info!("Launching hwkey service.");
+    // SAFETY: run_hwbcc copies the data from code and auth and does not retain references to them.
+    unsafe {
+        run_hwkey(
+            seal.as_mut_ptr(),
+            seal.len(),
+            sign.as_mut_ptr(),
+            sign.len(),
+            auth_token_key_seed.as_mut_ptr(),
+            auth_token_key_seed.len(),
+            VERSION_CDI_SEAL,
+            VERSION_CDI_SEAL,
+        );
+    }
+}
diff --git a/app/pinweaver/rules.mk b/app/pinweaver/rules.mk
index e12e103..33c6193 100644
--- a/app/pinweaver/rules.mk
+++ b/app/pinweaver/rules.mk
@@ -1,4 +1,4 @@
-# Copyright (C) 2024 The Android Open Source Project
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -34,5 +34,6 @@ MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
 
 MODULE_RUST_USE_CLIPPY := true
+MODULE_RUST_TESTS := true
 
 include make/library.mk
diff --git a/app/pinweaver/src/lib.rs b/app/pinweaver/src/lib.rs
index 90dd94d..4f855a2 100644
--- a/app/pinweaver/src/lib.rs
+++ b/app/pinweaver/src/lib.rs
@@ -27,17 +27,26 @@ use tipc::{Manager, PortCfg};
 mod dispatcher;
 mod service;
 mod storage;
+#[cfg(test)]
+mod tests;
 
 const PORT_COUNT: usize = 2;
 const CONNECTION_COUNT: usize = 4;
 
+struct ProdDeps;
+impl service::PinWeaverServiceDeps for ProdDeps {
+    type Storage = StorageClient;
+}
+
 pub fn init_and_start_loop() -> tipc::Result<()> {
     trusty_log::init();
     let storage = Arc::new(StorageClient::default());
     let storage_service = StorageClientService::new(storage.clone());
 
-    let service =
-        BnPinWeaver::new_binder(PinWeaverService::new(storage), BinderFeatures::default());
+    let service = BnPinWeaver::new_binder(
+        PinWeaverService::<ProdDeps>::new(storage),
+        BinderFeatures::default(),
+    );
     let rpc_server = RpcServer::new_per_session(move |_uuid| Some(service.as_binder()));
 
     let mut dispatcher =
@@ -50,7 +59,7 @@ pub fn init_and_start_loop() -> tipc::Result<()> {
         .add_service(Rc::new(rpc_server), service_cfg)
         .expect("RPC service should add to dispatcher");
 
-    let storage_cfg = PortCfg::new(pinweaver_storage::current::PORT)
+    let storage_cfg = PortCfg::new(pinweaver_storage_api::PORT)
         .expect("Storage port shouldn't contain nul")
         .allow_ns_connect();
     dispatcher
diff --git a/app/pinweaver/src/service.rs b/app/pinweaver/src/service.rs
index d044993..6d66cd3 100644
--- a/app/pinweaver/src/service.rs
+++ b/app/pinweaver/src/service.rs
@@ -1,25 +1,30 @@
 use binder::Interface;
 use pinweaver_api::{DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet, TryAuthResponse};
-use pinweaver_storage::current::StorageInterface;
+use pinweaver_storage_api::StorageInterface;
 use std::sync::Arc;
 use tipc::TipcError;
 
+// The `'static` is necessary for implicit `PinWeaverService<Deps>: 'static`.
+pub trait PinWeaverServiceDeps: 'static {
+    type Storage: StorageInterface<Error = TipcError> + Send + Sync + ?Sized + 'static;
+}
+
 #[allow(dead_code)]
 /// Implements the `IPinWeaver` AIDL interface for other Trusty apps to call.
-pub struct PinWeaverService {
-    storage: Arc<dyn StorageInterface<Error = TipcError>>,
-    // TODO: b/359374997 - add `gsc: Arc<dyn IGSc>`
+pub struct PinWeaverService<Deps: PinWeaverServiceDeps> {
+    storage: Arc<Deps::Storage>,
+    // TODO: b/359374997 - add `gsc: Arc<Deps::Gsc>`
 }
 
-impl PinWeaverService {
-    pub fn new(storage: Arc<dyn StorageInterface<Error = TipcError>>) -> Self {
+impl<Deps: PinWeaverServiceDeps> PinWeaverService<Deps> {
+    pub fn new(storage: Arc<Deps::Storage>) -> Self {
         Self { storage }
     }
 }
 
-impl Interface for PinWeaverService {}
+impl<Deps: PinWeaverServiceDeps> Interface for PinWeaverService<Deps> {}
 
-impl IPinWeaver for PinWeaverService {
+impl<Deps: PinWeaverServiceDeps> IPinWeaver for PinWeaverService<Deps> {
     fn insert(
         &self,
         _id: &LeafId,
diff --git a/app/pinweaver/src/storage.rs b/app/pinweaver/src/storage.rs
index 9d90248..12650b1 100644
--- a/app/pinweaver/src/storage.rs
+++ b/app/pinweaver/src/storage.rs
@@ -1,6 +1,6 @@
-use pinweaver_storage::{
-    current::{StorageInterface, StorageRequest, StorageResponse},
+use pinweaver_storage_api::{
     util::{DeserializeExact, ForwardTipcSerialize},
+    StorageInterface, StorageRequest, StorageResponse,
 };
 use std::sync::{Arc, Mutex, MutexGuard};
 use tipc::{Handle, TipcError, UnbufferedService};
diff --git a/app/finger_guard/rng.rs b/app/pinweaver/src/tests.rs
similarity index 56%
rename from app/finger_guard/rng.rs
rename to app/pinweaver/src/tests.rs
index c4eaf88..c9b43e7 100644
--- a/app/finger_guard/rng.rs
+++ b/app/pinweaver/src/tests.rs
@@ -13,16 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-//! Trusty implementation of `kmr_common::crypto::Rng`.
-use kmr_common::crypto;
+//! Unit tests.
 
-/// [`crypto::Rng`] implementation for Trusty.
-#[derive(Default)]
-pub struct TrustyRng;
+test::init!();
 
-impl crypto::Rng for TrustyRng {
-    fn add_entropy(&mut self, _data: &[u8]) {} // Safety: No op as intended, BoringSSL's RAND_bytes() doesn't utilize this function.
-    fn fill_bytes(&mut self, dest: &mut [u8]) {
-        openssl::rand::rand_bytes(dest).unwrap(); // safe: BoringSSL's RAND_bytes() never fails
-    }
+#[test]
+fn pinweaver_test() {
+    // This is a placeholder to make sure the test builds and runs successfully.
 }
diff --git a/interface/boot_params/aidl/android/desktop/security/boot_params/IBootParams.aidl b/interface/boot_params/aidl/android/desktop/security/boot_params/IBootParams.aidl
index 496ec80..e9b896d 100644
--- a/interface/boot_params/aidl/android/desktop/security/boot_params/IBootParams.aidl
+++ b/interface/boot_params/aidl/android/desktop/security/boot_params/IBootParams.aidl
@@ -27,4 +27,25 @@ interface IBootParams {
      *
      */
     byte[] getEarlyEntropy();
+    /**
+     * Requests the CDI sealing key.
+     *
+     * @return             The CDI sealing key.
+     *
+     */
+    byte[] getCdiSeal();
+    /**
+     * Requests the CDI attestation key.
+     *
+     * @return             The CDI attestation key.
+     *
+     */
+    byte[] getCdiAttest();
+    /**
+     * Requests the auth token key seed.
+     *
+     * @return             The auth token key seed.
+     *
+     */
+    byte[] getAuthTokenKeySeed();
 }
diff --git a/interface/fingerguard/aidl/Android.bp b/interface/fingerguard/aidl/Android.bp
index cb48aa8..811f32e 100644
--- a/interface/fingerguard/aidl/Android.bp
+++ b/interface/fingerguard/aidl/Android.bp
@@ -3,7 +3,15 @@ aidl_interface {
     owner: "google",
     unstable: true,
     srcs: [
+        "android/desktop/security/fingerguard/AuthenticationResult.aidl",
+        "android/desktop/security/fingerguard/EnrollmentResult.aidl",
+        "android/desktop/security/fingerguard/HandshakeResponse.aidl",
+        "android/desktop/security/fingerguard/HardwareAuthToken.aidl",
         "android/desktop/security/fingerguard/IFingerGuard.aidl",
+        "android/desktop/security/fingerguard/PrepareAuthSessionResponse.aidl",
+        "android/desktop/security/fingerguard/PrepareEnrollSessionResponse.aidl",
+        "android/desktop/security/fingerguard/SensorUserPair.aidl",
+        "android/desktop/security/fingerguard/SessionResponse.aidl",
     ],
     frozen: false,
     backend: {
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/AuthenticationResult.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/AuthenticationResult.aidl
new file mode 100644
index 0000000..163e031
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/AuthenticationResult.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+/**
+ * AuthenticationResult represents an attested authentication result.
+ */
+parcelable AuthenticationResult {
+    boolean authenticated;
+    /**
+     * The MAC attests the authentication result.
+     * If authenticated = true:
+     * The MAC is a 32 bytes HMAC-SHA256, signed with the session key
+     * over the following string:
+     *         nonce || user_id || sensor_name || "auth" || session_counter
+     * where ``||'' represents concatenation; nonce, user_id,
+     * and session_counter are obtained from a previous prepareAuthSession
+     * request and response; sensor_name is the name of the sensor stack,
+     * e.g. "fpmcu".
+     *
+     * If authenticated = false: the MAC is empty.
+     */
+    byte[] mac;
+}
+
+
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/EnrollmentResult.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/EnrollmentResult.aidl
new file mode 100644
index 0000000..40b331e
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/EnrollmentResult.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+/**
+ * EnrollmentResult represents an attested enrollment result.
+ */
+parcelable EnrollmentResult {
+    boolean enrolled;
+    /**
+     * The MAC attests the enrollment result.
+     * If enrolled = true:
+     * The MAC is a 32 bytes HMAC-SHA256, signed with the session key
+     * over the following string:
+     *         nonce || user_id || sensor_name || "enroll" || session_counter
+     * where ``||'' represents concatenation; nonce, user_id,
+     * and session_counter are obtained from a previous PrepareEnrollSession
+     * request and response; sensor_name is the name of the sensor stack,
+     * e.g. "fpmcu".
+     *
+     * If enrolled = false: the MAC is empty.
+     */
+    byte[] mac;
+}
+
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/HandshakeResponse.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/HandshakeResponse.aidl
new file mode 100644
index 0000000..2f8663a
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/HandshakeResponse.aidl
@@ -0,0 +1,23 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+parcelable HandshakeResponse {
+    byte[] serverPublicKey;
+    byte[] pkMac;
+}
+
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/HardwareAuthToken.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/HardwareAuthToken.aidl
new file mode 100644
index 0000000..971bd00
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/HardwareAuthToken.aidl
@@ -0,0 +1,52 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+/**
+ * HardwareAuthToken mirrors the struct of hw_auth_token_t in hw_auth_token.h.
+ */
+parcelable HardwareAuthToken {
+    // Current version is 0. No other values allowed.
+    byte version = 0;
+
+    long challenge;
+
+    long userId;
+
+    long authenticatorId;
+
+    int authenticatorType = 0;
+
+    long timestamp;
+
+    /**
+     * MACs are computed with a backward-compatible method, used by Keymaster 3.0, Gatekeeper 1.0
+     * and Fingerprint 1.0, as well as pre-treble HALs.
+     *
+     * The MAC is a 32 bytes HMAC-SHA256 with the auth token signing key over the following string
+     *         version || challenge || user_id || authenticator_id || authenticator_type || timestamp
+     *
+     * where ``||'' represents concatenation, the leading version is a single byte, and all integers
+     * are represented as unsigned values, the full width of the type.  The challenge, userId and
+     * authenticatorId values are in machine order, but authenticatorType and timestamp are in
+     * network order (big-endian).  This odd construction is compatible with the hw_auth_token_t
+     * structure.
+     *
+     * Note that mac can be empty indicates the auth token is not yet signed and not valid.
+     */
+    byte[] mac;
+}
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/IFingerGuard.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/IFingerGuard.aidl
index 8b0a496..0eb3860 100644
--- a/interface/fingerguard/aidl/android/desktop/security/fingerguard/IFingerGuard.aidl
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/IFingerGuard.aidl
@@ -16,13 +16,84 @@
 
 package android.desktop.security.fingerguard;
 
+import android.desktop.security.fingerguard.AuthenticationResult;
+import android.desktop.security.fingerguard.EnrollmentResult;
+import android.desktop.security.fingerguard.HandshakeResponse;
+import android.desktop.security.fingerguard.PrepareAuthSessionResponse;
+import android.desktop.security.fingerguard.PrepareEnrollSessionResponse;
+import android.desktop.security.fingerguard.SensorUserPair;
+import android.desktop.security.fingerguard.SessionResponse;
+import android.desktop.security.fingerguard.HardwareAuthToken;
+
 interface IFingerGuard {
-    /** Return the AuthenticatorId associated with
-     * the (user, sensor) pair.
+    /**
+     * Return the HandshakeResponse.
+     * The pairing key, PK, is derived from ECDH key agreement. The client
+     * would use HandshakeResponse to derive the same PK.
+     * Once the PK is established, it will be persisted and block further
+     * initHandshake calls until the device is powerwashed.
+     */
+    HandshakeResponse initHandshake(in byte[] clientPublicKey);
+    /**
+     * Return the nonce for a common shared session key and the session key
+     * encrypted TPM seed.
+     * The session key is derived from the pairing key, plus the client nonce
+     * and the returned nonce.
+     */
+    SessionResponse newSession(in byte[] clientNonce);
+    /**
+     * Return a newly generated challange associated with the
+     * (sensor, user) pair.
+     * The challange should be returned in the HAT when prepareEnrollSession
+     * is invoked. The challenge will expire after a minute.
+     * It allows multiple in-flight challenges. Invoking generateChallenge
+     * twice does not invalidate the first challenge. The challenge is invalidated only when:
+     *   1) It expires.
+     *   2) revokeChallenge is invoked.
+     */
+    long generateChallenge(in SensorUserPair sensorUserPair);
+    /**
+     * Revoke and return the challenge associated with the (sensor, user) pair.
+     * If there is no previously generated challange matched the requested one
+     * or the challenge has expired, return 0.
+     */
+    long revokeChallenge(in SensorUserPair sensorUserPair, long challenge);
+    /**
+     * Create an enroll session for a given pair of (sensor, user).
+     * A nonce and a session counter will be returned, along with the
+     * associated MAC. The details of the MAC computation is up to the
+     * agreement between FingerGuard and its client.
+     *
+     * The challenge in the provided HAT must match the recorded challenge for
+     * the same (senor, user) pair and must not exceeds the timeout.
+     */
+    PrepareEnrollSessionResponse prepareEnrollSession(in SensorUserPair sensorUserPair, in HardwareAuthToken hat);
+    /**
+     * Finish a created enroll session.
+     * The associated AuthenticatorID will be updated with a successful
+     * enrollment.
+     */
+    void finishEnrollSession(in SensorUserPair sensorUserPair, in EnrollmentResult result);
+    /**
+     * Create an auth session for a given pair of (sensor, user).
+     * A nonce and a session counter will be returned, along with the
+     * associated MAC. The details of the MAC computation is up to the
+     * agreement between FingerGuard and its client.
+     */
+    PrepareAuthSessionResponse prepareAuthSession(in SensorUserPair sensorUserPair, in long challenge);
+    /**
+     * Finish a created auth session.
+     * If the authentication succeeds, return a valid auth token contains
+     * the challenge in prepareAuthSession. Otherwise, return an empty token.
+     */
+    HardwareAuthToken finishAuthSession(in SensorUserPair sensorUserPair, in AuthenticationResult result);
+    /**
+     * Return the AuthenticatorId associated with the (sensor, user) pair.
      */
-    long getAuthenticatorId(in int sensorId, in int userId);
-     /** Return a newly generated AuthenticatorId associated with
-     * the (user, sensor) pair.
+    long getAuthenticatorId(in SensorUserPair sensorUserPair);
+    /**
+     * Return a newly generated AuthenticatorId associated with the
+     * (sensor, user) pair.
      */
-    long newAuthenticatorId(in int sensorId, in int userId);
+    long newAuthenticatorId(in SensorUserPair sensorUserPair);
 }
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareAuthSessionResponse.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareAuthSessionResponse.aidl
new file mode 100644
index 0000000..2921c6f
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareAuthSessionResponse.aidl
@@ -0,0 +1,36 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+parcelable PrepareAuthSessionResponse {
+    // The session counter monotonically increases.
+    long sessionCounter;
+    // Random nonce.
+    byte[32] nonce;
+    /**
+     * The MAC is a 32 bytes HMAC-SHA256 with the session key over the
+     * following string:
+     *         nonce || user_id || ta_name || "auth" || session_counter
+     *
+     * where ``||'' represents concatenation; user_id is an unsigned integer
+     * from the input of PrepareEnrollSession, ta_name is the public name
+     * identifying the FingerGuard TA, i.e. "fingerguard".
+     */
+    byte[] mac;
+}
+
+
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareEnrollSessionResponse.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareEnrollSessionResponse.aidl
new file mode 100644
index 0000000..6028137
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/PrepareEnrollSessionResponse.aidl
@@ -0,0 +1,36 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+parcelable PrepareEnrollSessionResponse {
+    // The session counter monotonically increases.
+    long sessionCounter;
+    // Random nonce.
+    byte[32] nonce;
+    /**
+     * The MAC is a 32 bytes HMAC-SHA256 with the session key over the
+     * following string:
+     *         nonce || user_id || ta_name || "enroll" || session_counter
+     *
+     * where ``||'' represents concatenation; user_id is an unsigned integer
+     * from the input of PrepareEnrollSession, ta_name is the public name
+     * identifying the FingerGuard TA, i.e. "fingerguard".
+     */
+    byte[] mac;
+}
+
+
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/SensorUserPair.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/SensorUserPair.aidl
new file mode 100644
index 0000000..634b058
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/SensorUserPair.aidl
@@ -0,0 +1,22 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+parcelable SensorUserPair {
+    int sensorId;
+    int userId;
+}
diff --git a/interface/fingerguard/aidl/android/desktop/security/fingerguard/SessionResponse.aidl b/interface/fingerguard/aidl/android/desktop/security/fingerguard/SessionResponse.aidl
new file mode 100644
index 0000000..7856085
--- /dev/null
+++ b/interface/fingerguard/aidl/android/desktop/security/fingerguard/SessionResponse.aidl
@@ -0,0 +1,24 @@
+/*
+ * Copyright (c) 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.desktop.security.fingerguard;
+
+parcelable SessionResponse {
+    byte[] nonce;
+    byte[] wrappedTpmSeed;
+    byte[] iv;
+    byte[] tag;
+}
diff --git a/interface/fingerguard/aidl/rules.mk b/interface/fingerguard/aidl/rules.mk
index 0ca4a70..2d260b6 100644
--- a/interface/fingerguard/aidl/rules.mk
+++ b/interface/fingerguard/aidl/rules.mk
@@ -20,7 +20,15 @@ MODULE_AIDL_PACKAGE := android/desktop/security/fingerguard
 MODULE_CRATE_NAME := android_desktop_security_fingerguard
 
 MODULE_AIDLS := \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/AuthenticationResult.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/EnrollmentResult.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/HandshakeResponse.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/HardwareAuthToken.aidl \
 	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/IFingerGuard.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/PrepareAuthSessionResponse.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/PrepareEnrollSessionResponse.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/SensorUserPair.aidl \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/SessionResponse.aidl \
 
 MODULE_AIDL_LANGUAGE := rust
 
diff --git a/interface/fingerguard/src/lib.rs b/interface/fingerguard/src/lib.rs
index b57f07c..9474246 100644
--- a/interface/fingerguard/src/lib.rs
+++ b/interface/fingerguard/src/lib.rs
@@ -5,7 +5,8 @@ use core::ffi::CStr;
 use rpcbinder::RpcSession;
 
 pub use android_desktop_security_fingerguard::aidl::android::desktop::security::fingerguard::{
-    self as aidl, IFingerGuard::IFingerGuard,
+    self as aidl, HandshakeResponse::HandshakeResponse, IFingerGuard::IFingerGuard,
+    SessionResponse::SessionResponse,
 };
 pub const PORT_CSTR: &CStr = c"com.android.trusty.rust.FingerGuard.V1";
 
diff --git a/interface/pinweaver/storage/Android.bp b/interface/pinweaver/storage/Android.bp
index 1b0895e..34a565b 100644
--- a/interface/pinweaver/storage/Android.bp
+++ b/interface/pinweaver/storage/Android.bp
@@ -1,4 +1,4 @@
-// Copyright 2024 The Android Open Source Project
+// Copyright 2025 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -13,10 +13,13 @@
 // limitations under the License.
 
 rust_library {
-    name: "libpinweaver_storage",
+    name: "libpinweaver_storage_api",
     srcs: ["src/lib.rs"],
-    crate_name: "pinweaver_storage",
+    crate_name: "pinweaver_storage_api",
+    features: ["serde"],
     rustlibs: [
+        "libhex",
+        "libserde",
         "libtrusty-rs",
         "libzerocopy",
     ],
diff --git a/interface/pinweaver/storage/rules.mk b/interface/pinweaver/storage/rules.mk
index d7c594a..99b086f 100644
--- a/interface/pinweaver/storage/rules.mk
+++ b/interface/pinweaver/storage/rules.mk
@@ -1,4 +1,4 @@
-# Copyright (C) 2024 The Android Open Source Project
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -18,11 +18,10 @@ MODULE := $(LOCAL_DIR)
 
 MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
 
-MODULE_CRATE_NAME := pinweaver_storage
+MODULE_CRATE_NAME := pinweaver_storage_api
 
-# TODO: b/372549215 - Use `$(call FIND_CRATE,zerocopy)` when the 0.7 rules.mk is removed.
 MODULE_LIBRARY_DEPS += \
-	external/rust/android-crates-io/crates/zerocopy \
+	$(call FIND_CRATE,zerocopy) \
 	trusty/user/base/lib/tipc/rust \
 
 include make/library.mk
diff --git a/interface/pinweaver/storage/src/lib.rs b/interface/pinweaver/storage/src/lib.rs
index 0b4b373..c560129 100644
--- a/interface/pinweaver/storage/src/lib.rs
+++ b/interface/pinweaver/storage/src/lib.rs
@@ -16,9 +16,214 @@
 
 //! Defines types used to communicate between the PinWeaver storage daemon and Trusty app.
 //!
-//! The interface is versioned to perform cross-host updates of the protocol without breakage.
+//! This protocol is not version-controlled: it must change in lockstep with `libpinweaver_storage`.
 
+use crate::util::{serde_fields, serde_zerocopy, SerdeVec};
+use std::fmt::Debug;
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
+
+pub mod request;
+pub mod response;
 pub mod util;
-pub mod v1;
 
-pub use v1 as current;
+/// The port on the PinWeaver Trusty app that the storage daemon connects to.
+pub const PORT: &str = "com.android.desktop.security.PinWeaverStorage.V1";
+
+// These are also the parameters used currently on ChromeOS devices.
+
+/// The default height for the hash tree.
+pub const MAX_TREE_HEIGHT: u8 = 7;
+
+/// The default number of bits used to index into the tree per level of the tree.
+pub const MAX_TREE_BITS_PER_LEVEL: u8 = 2;
+
+/// The number of auxiliary hashes that need to be updated per-request.
+pub const MAX_AUX_HASHES: u32 =
+    ((1 << MAX_TREE_BITS_PER_LEVEL as u32) - 1) * MAX_TREE_HEIGHT as u32;
+
+/// Kept in sync with the size of [`wrapped_leaf_data_t`]
+///
+/// [`wrapped_leaf_data_t`]: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/refs/heads/main/pinweaver.h#88
+pub const LEAF_SIZE: u32 = 389;
+
+/// The maximum supported high-entropy key size provided by the client.
+///
+/// Increasing this much further will require protocol restructuring
+/// as it can't be sent in a single datagram over vsock.
+pub const MAX_LARGE_SECRET_SIZE: u32 = 1024;
+
+/// The interface to communicate with the storage daemon.
+pub trait StorageInterface {
+    /// The error while executing a storage request.
+    type Error: Debug;
+
+    /// Execute a storage request.
+    fn request(&self, request: &StorageRequest) -> Result<StorageResponse, Self::Error>;
+}
+
+pub use request::StorageRequest;
+pub use response::StorageResponse;
+
+/// Unaligned little-endian `u32` - used for [`IntoBytes`] structs to prevent padding.
+#[derive(
+    Clone,
+    Copy,
+    Debug,
+    FromBytes,
+    KnownLayout,
+    Immutable,
+    IntoBytes,
+    PartialEq,
+    Eq,
+    PartialOrd,
+    Ord,
+    Hash,
+)]
+#[repr(transparent)]
+#[cfg_attr(
+    feature = "serde",
+    derive(serde::Deserialize, serde::Serialize),
+    serde(from = "u32", into = "u32")
+)]
+pub struct U32(zerocopy::byteorder::U32<zerocopy::byteorder::LE>);
+impl U32 {
+    /// Constructs an unaligned `u32`.
+    pub fn new(val: u32) -> Self {
+        Self(zerocopy::byteorder::U32::new(val))
+    }
+
+    /// Gets the underlying `u32` value.
+    pub fn get(&self) -> u32 {
+        self.0.get()
+    }
+}
+
+impl std::fmt::Display for U32 {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        <u32 as std::fmt::Display>::fmt(&self.get(), f)
+    }
+}
+
+impl From<U32> for u32 {
+    fn from(val: U32) -> Self {
+        val.get()
+    }
+}
+
+impl From<u32> for U32 {
+    fn from(val: u32) -> Self {
+        Self::new(val)
+    }
+}
+
+/// A leaf identifier, distinct from a [`Path`] and specific to the Android PinWeaver API.
+///
+/// Both the leaf set and inner ID are client-chosen.
+///
+/// This has a 1:1 mapping with some [`Path`] on this device,
+/// except when a leaf with some ID is currently being replaced.
+#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+pub struct LeafId {
+    /// The group this leaf ID belongs to.
+    pub leaf_set: LeafSet,
+
+    /// The semantic meaning of the `inner_id` is specific to the `leaf_set`.
+    pub inner_id: U32,
+}
+
+/// The group this leaf ID belongs to.
+///
+/// See `LeafSet.aidl`.
+#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(transparent)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
+pub struct LeafSet(pub U32);
+
+/// A PinWeaver leaf path, indicating where in the hash tree a leaf is located.
+#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(transparent)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
+pub struct Path(pub [u8; 8]);
+
+/// The encrypted contents of a PinWeaver leaf on-disk.
+pub type LeafContents = SerdeVec<u8, LEAF_SIZE>;
+
+/// Parameters for a PinWeaver hash tree.
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+pub struct TreeParams {
+    /// The height of the new tree.
+    pub height: u8,
+
+    /// The number of bits in the path used per tree level.
+    /// This is log2(fan-out factor).
+    pub bits_per_level: u8,
+}
+
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(transparent)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
+/// A SHA-256 digest.
+pub struct TreeHash(#[cfg_attr(feature = "serde", serde(with = "util::hex_serde"))] pub [u8; 32]);
+
+/// A set of auxiliary hashes for a tree.
+pub type TreeHashes = SerdeVec<TreeHash, MAX_AUX_HASHES>;
+
+/// When PinWeaver needs to store a high-entropy secret that is larger than
+/// 32 bytes, the leaf's secret is an AES key used with these parameters.
+#[derive(Debug)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+pub struct LargeSecretInfo {
+    /// The IV for the ciphertext/key. Must not be reused.
+    pub iv: LargeSecretIv,
+
+    /// The GCM authentication tag used to verify that the low-entropy secret
+    /// is associated with this ciphertext.
+    pub auth_tag: LargeSecretAuthTag,
+
+    /// The encrypted high-entropy secret, decrypted with the key stored on the PinWeaver leaf.
+    pub secret_ciphertext: SerdeVec<u8, MAX_LARGE_SECRET_SIZE>,
+}
+
+/// An AES-256 Initialization Vector.
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(transparent)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
+pub struct LargeSecretIv(
+    #[cfg_attr(feature = "serde", serde(with = "util::hex_serde"))] pub [u8; 12],
+);
+
+/// The GCM [authentication tag] ensuring integrity of large-secret data.
+///
+/// [authentication tag]: https://en.wikipedia.org/wiki/Authenticated_encryption
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(transparent)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
+pub struct LargeSecretAuthTag(pub U32);
+
+serde_fields! {
+    LargeSecretInfo { iv, auth_tag, secret_ciphertext },
+}
+serde_zerocopy!(LargeSecretAuthTag, LargeSecretIv, LeafId, LeafSet, Path, TreeHash, TreeParams);
+
+impl From<LeafId> for i64 {
+    fn from(id: LeafId) -> i64 {
+        zerocopy::transmute!(id)
+    }
+}
+
+impl From<i64> for LeafId {
+    fn from(id: i64) -> LeafId {
+        zerocopy::transmute!(id)
+    }
+}
+
+#[cfg(feature = "rusqlite")]
+impl rusqlite::ToSql for LeafId {
+    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
+        i64::from(*self).to_sql()
+    }
+}
diff --git a/interface/pinweaver/storage/src/request.rs b/interface/pinweaver/storage/src/request.rs
new file mode 100644
index 0000000..fb6de6d
--- /dev/null
+++ b/interface/pinweaver/storage/src/request.rs
@@ -0,0 +1,124 @@
+/*
+ * Copyright (c) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+//! v1 storage request
+
+use super::{LargeSecretInfo, LeafContents, LeafId, LeafSet, TreeParams};
+use crate::util::{serde_enums, serde_fields, serde_zerocopy, SerdeOption};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
+
+serde_enums! {
+    /// A request to the storage daemon.
+    pub enum StorageRequest {
+        /// Gets the status of on-disk PinWeaver data and tree info.
+        GetStatus = 0,
+
+        /// Initializes a new database for PinWeaver.
+        ResetTree(ResetTreeRequest) = 1,
+
+        /// Starts a mutating operation on the PinWeaver tree.
+        ///
+        /// This may commit to disk that the operation has begun.
+        StartOp(StartOpRequest) = 2,
+
+        /// Commits a mutating operation on the PinWeaver tree.
+        CommitOp(CommitOpRequest) = 3,
+    }
+
+    /// Start a PinWeaver transaction.
+    ///
+    /// Describes a multi-step operation which may be interrupted by
+    /// power loss, de-syncing disk and on-chip PinWeaver state.
+    ///
+    /// This responds with the necessary tree hashes to perform the
+    /// operation. If necessary, this also tracks that it's begun.
+    pub enum StartOpRequest {
+        /// Insert a leaf into PinWeaver.
+        Insert(InsertOpRequest) = 0,
+
+        /// Authenticate a leaf.
+        /// Disk state is always mutated for auth attempts.
+        TryAuth(LeafId) = 1,
+
+        /// Remove a specific leaf in PinWeaver.
+        Remove(LeafId) = 2,
+
+        /// Remove many leaves in PinWeaver.
+        RemoveBulk(LeafSet) = 3,
+    }
+
+    /// Whether to allow an insert with the same leaf ID as in the
+    /// [`InsertOpRequest`].
+    pub enum InsertMode {
+        /// Reject the insertion if a leaf with this ID exists.
+        NewOnly = 0,
+
+        /// Replace the leaf with new contents if this ID is already present.
+        ReplaceExisting = 1,
+    }
+}
+
+/// Clear any existing PinWeaver state and reinitialize.
+///
+/// An empty PinWeaver Merkle tree has tree hashes derivable
+/// from these parameters and no on-chip secrets.
+///
+/// The response root hash should equal the value returned by the GSC.
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+
+pub struct ResetTreeRequest {
+    /// The parameters for the newly constructed tree.
+    pub tree_params: TreeParams,
+}
+
+/// Request to insert a leaf into PinWeaver.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
+pub struct InsertOpRequest {
+    /// The leaf this operation targets.
+    pub leaf_id: LeafId,
+
+    /// Whether to allow an insert when a leaf with `leaf_id` exists.
+    pub mode: InsertMode,
+
+    /// The large key info associated with the new leaf.
+    pub large_key_info: SerdeOption<LargeSecretInfo>,
+}
+
+/// Commit a PinWeaver transaction to disk.
+///
+/// The new tree hashes are also calculated by the storage daemon
+/// and committed to disk.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
+pub struct CommitOpRequest {
+    /// The original start request.
+    ///
+    /// Large key info is not included.
+    pub start_request: StartOpRequest,
+
+    /// The new contents of the leaf returned by PinWeaver.
+    ///
+    /// Empty if being removed.
+    pub new_leaf_contents: LeafContents,
+}
+
+serde_fields!(
+    CommitOpRequest { start_request, new_leaf_contents },
+    InsertOpRequest { leaf_id, mode, large_key_info },
+);
+serde_zerocopy!(ResetTreeRequest);
diff --git a/interface/pinweaver/storage/src/v1/response.rs b/interface/pinweaver/storage/src/response.rs
similarity index 73%
rename from interface/pinweaver/storage/src/v1/response.rs
rename to interface/pinweaver/storage/src/response.rs
index b047a01..5ca3d74 100644
--- a/interface/pinweaver/storage/src/v1/response.rs
+++ b/interface/pinweaver/storage/src/response.rs
@@ -19,57 +19,33 @@ use super::{LargeSecretInfo, LeafContents, LeafId, Path, TreeHash, TreeHashes, T
 use crate::util::{serde_enums, serde_fields, serde_zerocopy, SerdeOption};
 use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
 
-/// The response from the storage daemon.
-pub struct StorageResponse {
-    /// Header info that is serialized contiguously.
-    pub header: StorageResponseHeader,
-
-    /// The operation-specific data for a storage response.
-    pub op_data: StorageResponseData,
-}
-
-/// The header for [`StorageResponse`].
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(C)]
-pub struct StorageResponseHeader {
-    /// The status of executing the request; check this first.
-    pub status: ResponseStatus,
-
-    /// The current root hash for the tree.
-    pub root_hash: TreeHash,
-}
-
 /// The response when getting the status of PinWeaver.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
 #[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
 pub struct GetStatusResponse {
     /// The parameters for the hash tree, as understood by the storage daemon.
     pub tree_params: TreeParams,
-}
-
-/// The status of a storage daemon operation.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(transparent)]
-pub struct ResponseStatus(u8);
 
-#[allow(non_upper_case_globals)]
-impl ResponseStatus {
-    /// Success.
-    pub const Ok: Self = Self(0);
-
-    /// An unknown internal error occurred.
-    pub const ErrUnknown: Self = Self(1);
+    /// The current root hash for the tree.
+    pub root_hash: TreeHash,
 }
 
-/// The response when initializing PinWeaver on disk.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
+/// The response when resetting the PinWeaver tree on disk.
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
 #[repr(C)]
-pub struct InitializeResponse {
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+pub struct ResetTreeResponse {
     /// The total number of leaves in this tree.
     pub num_hashes: U32,
+
+    /// The current root hash for the tree.
+    pub root_hash: TreeHash,
 }
 
 /// The response when starting an operation in PinWeaver.
+#[derive(Debug)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
 pub struct StartOpResponse {
     /// The path of the currently operating leaf.
     pub path: Path,
@@ -82,28 +58,52 @@ pub struct StartOpResponse {
 }
 
 /// The response when committing an operation in PinWeaver.
+#[derive(Debug)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
 pub struct CommitOpResponse {
     /// The path of the leaf that was just updated.
     pub path: Path,
 
+    /// The current root hash for the tree.
+    pub root_hash: TreeHash,
+
     /// The response data specific to this operation.
     pub op_data: CommitOpResponseData,
 }
 
 serde_enums! {
-    /// The operation-specific data for a storage response.
-    pub enum StorageResponseData {
+    /// The response from the storage daemon.
+    pub enum StorageResponse {
+        /// An error occurred.
+        Error(ResponseError) = 0,
+
         /// The response when getting the status of PinWeaver.
-        GetStatus(GetStatusResponse) = 0,
+        GetStatus(GetStatusResponse) = 1,
 
         /// The response when initializing PinWeaver.
-        Initialize(InitializeResponse) = 1,
+        ResetTree(ResetTreeResponse) = 2,
 
         /// The response when starting an operation in PinWeaver.
-        StartOp(StartOpResponse) = 2,
+        StartOp(StartOpResponse) = 3,
 
         /// The response when committing an operation in PinWeaver.
-        CommitOp(CommitOpResponse) = 3,
+        CommitOp(CommitOpResponse) = 4,
+    }
+
+    /// The status of a storage daemon operation.
+    pub enum ResponseError {
+        /// Unknown error.
+        Unknown = 0,
+
+        /// PinWeaver data was not found: the system should be initialized
+        /// by resetting the PinWeaver tree.
+        NotInitialized = 1,
+
+        /// Unexpected arithmetic overflow occurred.
+        Overflow = 2,
+
+        /// Database access returned an error.
+        Db = 3,
     }
 
     /// The suboperation-specific data for a start-operation response.
@@ -151,20 +151,25 @@ serde_enums! {
 }
 
 /// The response when starting insert of a new leaf.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
 pub struct StartInsertResponseData {
     /// The leaf path that is being replaced and will be deleted, if any.
     pub replacing_path: SerdeOption<Path>,
 }
 
 /// The response when starting removal of a leaf.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
 #[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
 pub struct StartRemoveResponseData {
     /// The HMAC of the leaf to remove.
     pub leaf_hmac: TreeHash,
 }
 
 /// The response when starting to authenticate the low-entropy secret in a leaf.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
 pub struct StartTryAuthResponseData {
     /// The size of the high-entropy secret stored by the client in bytes.
     pub secret_size: u32,
@@ -178,8 +183,9 @@ pub struct StartTryAuthResponseData {
 }
 
 /// Header for [`ContinueRemoveBulkResponse`].
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
+#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
 #[repr(C)]
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
 pub struct ContinueRemoveBulkResponseHeader {
     /// The next leaf to remove as part of this bulk removal.
     pub id: LeafId,
@@ -190,6 +196,8 @@ pub struct ContinueRemoveBulkResponseHeader {
 
 /// Response when committing the bulk removal of one leaf,
 /// and there are more leaves to remove.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
 pub struct ContinueRemoveBulkResponse {
     /// Header info that is serialized contiguously.
     pub header: ContinueRemoveBulkResponseHeader,
@@ -199,6 +207,8 @@ pub struct ContinueRemoveBulkResponse {
 }
 
 /// Response when a leaf should be removed after a commit operation.
+#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
+#[derive(Debug)]
 pub struct RemoveHashes {
     /// The HMAC for the leaf to remove removed.
     pub leaf_hmac: TreeHash,
@@ -208,9 +218,8 @@ pub struct RemoveHashes {
 }
 
 serde_fields! {
-    StorageResponse { header, op_data },
     StartOpResponse { path, tree_hashes, op_data },
-    CommitOpResponse { path, op_data },
+    CommitOpResponse { path, root_hash, op_data },
     StartInsertResponseData { replacing_path },
     StartTryAuthResponseData { secret_size, leaf_contents, large_key_info },
     ContinueRemoveBulkResponse { header, hashes },
@@ -218,9 +227,8 @@ serde_fields! {
 }
 
 serde_zerocopy!(
-    StorageResponseHeader,
+    ContinueRemoveBulkResponseHeader,
     GetStatusResponse,
-    InitializeResponse,
+    ResetTreeResponse,
     StartRemoveResponseData,
-    ContinueRemoveBulkResponseHeader,
 );
diff --git a/interface/pinweaver/storage/src/util.rs b/interface/pinweaver/storage/src/util.rs
index 0d07b40..e46d4dc 100644
--- a/interface/pinweaver/storage/src/util.rs
+++ b/interface/pinweaver/storage/src/util.rs
@@ -115,7 +115,47 @@ impl<T: Immutable + KnownLayout + IntoBytes + FromBytes + 'static, const MAX_LEN
     }
 }
 
+#[cfg(feature = "serde")]
+impl<const N: u32> serde::Serialize for SerdeVec<u8, N> {
+    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
+        hex_serde::serialize(&self.values, serializer)
+    }
+}
+
+#[cfg(feature = "serde")]
+impl<'de, const N: u32> serde::Deserialize<'de> for SerdeVec<u8, N> {
+    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
+    where
+        D: serde::Deserializer<'de>,
+    {
+        use serde::de::Error;
+        let s = String::deserialize(deserializer)?;
+        hex::decode(&s)
+            .map_err(|e| D::Error::custom(format!("Failed to decode hex string {s:?}: {e}")))
+            .map(|v| Self { len: v.len().try_into().unwrap(), values: v })
+    }
+}
+
+#[cfg(feature = "serde")]
+impl<const N: u32> serde::Serialize for SerdeVec<crate::TreeHash, N> {
+    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
+        serde::Serialize::serialize(&self.values[..], serializer)
+    }
+}
+
+#[cfg(feature = "serde")]
+impl<'de, const N: u32> serde::Deserialize<'de> for SerdeVec<crate::TreeHash, N> {
+    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
+    where
+        D: serde::Deserializer<'de>,
+    {
+        serde::Deserialize::deserialize(deserializer)
+            .map(|v: Vec<crate::TreeHash>| Self { len: v.len().try_into().unwrap(), values: v })
+    }
+}
+
 /// An `Option` alternative that is compatible with tipc serialization.
+#[derive(Debug)]
 #[repr(u8)]
 pub enum SerdeOption<T> {
     /// Equivalent to [`Option::None`].
@@ -178,6 +218,30 @@ impl<T: DeserializePrefix> DeserializePrefix for SerdeOption<T> {
     }
 }
 
+#[cfg(feature = "serde")]
+impl<T: serde::Serialize> serde::Serialize for SerdeOption<T> {
+    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
+        serde::Serialize::serialize(
+            &match self {
+                SerdeOption::None => None,
+                SerdeOption::Some(v) => Some(v),
+            },
+            serializer,
+        )
+    }
+}
+
+#[cfg(feature = "serde")]
+impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for SerdeOption<T> {
+    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
+    where
+        D: serde::Deserializer<'de>,
+    {
+        let val: Option<T> = serde::Deserialize::deserialize(deserializer)?;
+        Ok(val.into())
+    }
+}
+
 /// An error that occurred while deserializing.
 #[derive(Debug)]
 pub enum DeserializeError {
@@ -293,6 +357,40 @@ impl<T: DeserializePrefix> tipc::Deserialize for DeserializeExact<T> {
     }
 }
 
+/// A tipc-compatible serializer that coalesces all buffers into one contiguous one.
+// TODO: kupiakos - expose `write_vectored` in trusty-rs and avoid the copies.
+#[derive(Default)]
+pub struct CoalescingSerializer {
+    data: Vec<u8>,
+}
+
+impl CoalescingSerializer {
+    /// Clear the currently-serialized bytes.
+    ///
+    /// This preserves the allocation for efficiency.
+    pub fn clear(&mut self) {
+        self.data.clear()
+    }
+
+    /// Returns the bytes serialized into a contiguous slice.
+    pub fn bytes(&self) -> &[u8] {
+        &self.data
+    }
+}
+
+impl<'s> Serializer<'s> for CoalescingSerializer {
+    type Ok = ();
+    type Error = std::collections::TryReserveError;
+
+    fn serialize_bytes(&mut self, bytes: &'s [u8]) -> Result<Self::Ok, Self::Error> {
+        if let Some(additional) = bytes.len().checked_sub(self.data.capacity() - self.data.len()) {
+            self.data.try_reserve(additional)?;
+        }
+        self.data.extend(bytes);
+        Ok(())
+    }
+}
+
 pub(crate) const fn field_max_serialized_size<T, U: DeserializePrefix>(
     _accessor: &impl FnOnce(&T) -> &U,
 ) -> usize {
@@ -375,6 +473,8 @@ macro_rules! serde_enums {
         }
     )*) => {$(
         $(#[$attr])*
+        #[derive(Debug)]
+        #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
         #[repr(u8)]
         pub enum $name {$(
             $(#[$variant_attr])*
@@ -429,6 +529,27 @@ macro_rules! serde_enums {
     )*};
 }
 
+#[cfg(feature = "serde")]
+pub(crate) mod hex_serde {
+    use hex;
+    use serde::{de::Error, Deserialize, Deserializer, Serializer};
+
+    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
+        serializer.serialize_str(&hex::encode(bytes))
+    }
+
+    pub(crate) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
+    where
+        D: Deserializer<'de>,
+    {
+        let s = String::deserialize(deserializer)?;
+        let mut bytes = [0u8; N];
+        hex::decode_to_slice(&s, &mut bytes)
+            .map_err(|e| D::Error::custom(format!("Failed to decode hex string {s:?}: {e}")))?;
+        Ok(bytes)
+    }
+}
+
 /// Implements `Serialize`/`DeserializePrefix` for all of the fields in the given wire order.
 macro_rules! serde_fields {
     ($($name:ident {$($field:ident),* $(,)?}),* $(,)?) => {$(
diff --git a/interface/pinweaver/storage/src/v1.rs b/interface/pinweaver/storage/src/v1.rs
deleted file mode 100644
index 640fbf9..0000000
--- a/interface/pinweaver/storage/src/v1.rs
+++ /dev/null
@@ -1,141 +0,0 @@
-/*
- * Copyright (c) 2024, The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *     http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//! Version 1 of the PinWeaver storage daemon interface.
-
-use crate::util::{serde_fields, serde_zerocopy, SerdeVec};
-use std::fmt::Debug;
-use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
-
-pub mod request;
-pub mod response;
-
-/// The port on the PinWeaver Trusty app that the storage daemon connects to.
-pub const PORT: &str = "com.android.desktop.security.PinWeaverStorage.V1";
-
-// These are also the parameters used currently on ChromeOS devices.
-
-/// The default height for the hash tree.
-pub const MAX_TREE_HEIGHT: u8 = 7;
-
-/// The default number of bits used to index into the tree per level of the tree.
-pub const MAX_TREE_BITS_PER_LEVEL: u8 = 2;
-
-/// The number of auxiliary hashes that need to be updated per-request.
-pub const MAX_AUX_HASHES: u32 =
-    ((1 << MAX_TREE_BITS_PER_LEVEL as u32) - 1) * MAX_TREE_HEIGHT as u32;
-
-/// Kept in sync with the size of [`wrapped_leaf_data_t`]
-///
-/// [`wrapped_leaf_data_t`]: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/refs/heads/main/pinweaver.h#88
-pub const LEAF_SIZE: u32 = 389;
-
-/// The maximum supported high-entropy key size provided by the client.
-///
-/// Increasing this much further will require protocol restructuring
-/// as it can't be sent in a single datagram over vsock.
-pub const MAX_LARGE_SECRET_SIZE: u32 = 1024;
-
-/// The interface to communicate with the storage daemon.
-pub trait StorageInterface: 'static + Sync + Send {
-    /// The error while executing a storage request.
-    type Error: Debug;
-
-    /// Execute a storage request.
-    fn request(&self, request: &StorageRequest) -> Result<StorageResponse, Self::Error>;
-}
-
-pub use request::StorageRequest;
-pub use response::StorageResponse;
-
-/// Unaligned `u32` - used for [`IntoBytes`] structs to prevent padding.
-pub type U32 = zerocopy::byteorder::U32<zerocopy::byteorder::LE>;
-
-/// A leaf identifier, distinct from a [`Path`] and specific to the Android PinWeaver API.
-///
-/// Both the leaf set and inner ID are client-chosen.
-///
-/// This has a 1:1 mapping with some [`Path`] on this device,
-/// except when a leaf with some ID is currently being replaced.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(C)]
-pub struct LeafId {
-    /// The group this leaf ID belongs to. See `LeafSet.aidl`.
-    pub leaf_set: U32,
-
-    /// The semantic meaning of the `inner_id` is specific to the `leaf_set`.
-    pub inner_id: U32,
-}
-
-/// A PinWeaver leaf path, indicating where in the hash tree a leaf is located.
-#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(transparent)]
-pub struct Path(pub [u8; 8]);
-
-/// The encrypted contents of a PinWeaver leaf on-disk.
-pub type LeafContents = SerdeVec<u8, LEAF_SIZE>;
-
-/// Parameters for a PinWeaver hash tree.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(C)]
-pub struct TreeParams {
-    /// The height of the new tree.
-    pub height: u8,
-
-    /// The number of bits in the path used per tree level.
-    /// This is log2(fan-out factor).
-    pub bits_per_level: u8,
-}
-
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(transparent)]
-/// A SHA-256 digest.
-pub struct TreeHash(pub [u8; 32]);
-
-/// A set of auxiliary hashes for a tree.
-pub type TreeHashes = SerdeVec<TreeHash, MAX_AUX_HASHES>;
-
-/// When PinWeaver needs to store a high-entropy secret that is larger than
-/// 32 bytes, the leaf's secret is an AES key used with these parameters.
-#[repr(C)]
-pub struct LargeSecretInfo {
-    /// The IV for the ciphertext/key. Must not be reused.
-    pub iv: LargeSecretIv,
-
-    /// The GCM authentication tag used to verify that the low-entropy secret
-    /// is associated with this ciphertext.
-    pub auth_tag: LargeSecretAuthTag,
-
-    /// The encrypted high-entropy secret, decrypted with the key stored on the PinWeaver leaf.
-    pub secret_ciphertext: SerdeVec<u8, MAX_LARGE_SECRET_SIZE>,
-}
-
-/// An AES-256 Initialization Vector.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(transparent)]
-pub struct LargeSecretIv(pub [u8; 12]);
-
-/// The GCM [authentication tag] ensuring integrity of large-secret data.
-///
-/// [authentication tag]: https://en.wikipedia.org/wiki/Authenticated_encryption
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(transparent)]
-pub struct LargeSecretAuthTag(pub [u8; 4]);
-
-serde_fields! {
-    LargeSecretInfo { iv, auth_tag, secret_ciphertext },
-}
-serde_zerocopy!(TreeHash, LeafId, Path, LargeSecretAuthTag, LargeSecretIv);
diff --git a/interface/pinweaver/storage/src/v1/request.rs b/interface/pinweaver/storage/src/v1/request.rs
deleted file mode 100644
index b256451..0000000
--- a/interface/pinweaver/storage/src/v1/request.rs
+++ /dev/null
@@ -1,104 +0,0 @@
-/*
- * Copyright (c) 2024, The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *     http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-//! v1 storage request
-
-use super::{LeafContents, LeafId, TreeParams};
-use crate::util::{serde_enums, serde_fields, serde_zerocopy};
-use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
-
-serde_enums! {
-    /// A request to the storage daemon.
-    pub enum StorageRequest {
-        /// Gets the status of on-disk PinWeaver data and tree info.
-        GetStatus = 0,
-
-        /// Initializes a new database for PinWeaver.
-        Initialize(InitializeRequest) = 1,
-
-        /// Starts a mutating operation on the PinWeaver tree.
-        ///
-        /// This may commit to disk that the operation has begun.
-        StartOp(StartOpRequest) = 2,
-
-        /// Commits a mutating operation on the PinWeaver tree.
-        CommitOp(CommitOpRequest) = 3,
-    }
-}
-
-/// Clear any existing PinWeaver state and reinitialize.
-///
-/// An empty PinWeaver Merkle tree has tree hashes derivable
-/// from these parameters and no on-chip secrets.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(C)]
-pub struct InitializeRequest {
-    /// The parameters for the newly constructed tree.
-    pub tree_params: TreeParams,
-}
-
-/// The kind of operation that PinWeaver is performing and needs disk info for.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, PartialEq, Eq)]
-#[repr(transparent)]
-pub struct OperationKind(pub u8);
-
-#[allow(non_upper_case_globals)]
-impl OperationKind {
-    /// Inserting a new leaf. Reject existing leaves with the same ID.
-    pub const InsertNew: Self = Self(0);
-
-    /// Inserting a new leaf. Replace a leaf with the same ID.
-    pub const Insert: Self = Self(1);
-
-    /// Trying to authenticate a low-entropy secret with a leaf.
-    pub const TryAuth: Self = Self(2);
-
-    /// Removing a specific leaf.
-    pub const Remove: Self = Self(3);
-
-    /// Removing a set of leaves.
-    pub const RemoveBulk: Self = Self(4);
-}
-
-/// Start a PinWeaver transaction.
-///
-/// This returns the necessary tree hashes to perform the operation.
-/// If necessary, this also tracks that the operation has begun.
-#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
-#[repr(C)]
-pub struct StartOpRequest {
-    /// The leaf this operation targets.
-    pub leaf_id: LeafId,
-
-    /// The kind of operation being performed on this leaf.
-    pub op_kind: OperationKind,
-}
-
-/// Commit a PinWeaver transaction to disk.
-///
-/// The new tree hashes are also calculated by the storage daemon
-/// and committed to disk.
-pub struct CommitOpRequest {
-    /// The original start request.
-    pub request: StartOpRequest,
-
-    /// The new contents of the leaf returned by PinWeaver.
-    ///
-    /// Empty if being removed.
-    pub new_leaf_contents: LeafContents,
-}
-
-serde_fields!(CommitOpRequest { request, new_leaf_contents });
-serde_zerocopy!(InitializeRequest, StartOpRequest);
diff --git a/lib/boot_params/gsc.rs b/lib/boot_params/gsc.rs
index 908eba2..e162943 100644
--- a/lib/boot_params/gsc.rs
+++ b/lib/boot_params/gsc.rs
@@ -19,6 +19,16 @@ impl Default for GscBootParams {
     }
 }
 
+impl GscBootParams {
+    pub fn new(
+        early_entropy: [u8; 64],
+        session_key_seed: [u8; 32],
+        auth_token_key_seed: [u8; 32],
+    ) -> Self {
+        Self { early_entropy, session_key_seed, auth_token_key_seed }
+    }
+}
+
 impl coset::AsCborValue for GscBootParams {
     fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
         if let Some(vals) = value.as_map() {
diff --git a/lib/boot_params/lib.rs b/lib/boot_params/lib.rs
index b77b777..6bbabe3 100644
--- a/lib/boot_params/lib.rs
+++ b/lib/boot_params/lib.rs
@@ -1,10 +1,7 @@
 use ciborium::de::Error as CbError;
 use coset::cbor::value::Value;
-#[cfg(feature = "builtin-bcc")]
 use coset::AsCborValue;
 use coset::CoseError;
-#[cfg(feature = "builtin-bcc")]
-use kmr_wire::read_to_value;
 
 pub mod cdi;
 pub mod cwt;
@@ -18,9 +15,13 @@ use crate::dice::DiceHandover;
 use crate::gsc::GscBootParams;
 use crate::pub_key::SubjectPublicKey;
 
+#[cfg(feature = "builtin-bcc")]
+use kmr_wire::read_to_value;
+
 #[derive(Debug)]
 pub enum Error {
     NotAvailable,
+    CborError,
 }
 
 #[allow(dead_code)]
@@ -29,22 +30,10 @@ pub struct BootParams {
     pub gsc_boot_params: GscBootParams,
 }
 
-impl Default for BootParams {
-    fn default() -> Self {
-        Self::new()
-    }
-}
-
-#[cfg(feature = "builtin-bcc")]
-const BOOT_PARAM_KEY: i32 = 2;
 #[cfg(feature = "builtin-bcc")]
-const DICE_KEY: i32 = 3;
-
-#[allow(dead_code)]
-impl BootParams {
+impl Default for BootParams {
     /// Create a boot params struct from constant data.
-    #[cfg(feature = "builtin-bcc")]
-    pub fn new() -> Self {
+    fn default() -> Self {
         let data = desktop_test_data::boot::BOOT_PARAM;
         let data = read_to_value(data).unwrap();
         let data = data.as_map().unwrap();
@@ -58,10 +47,31 @@ impl BootParams {
 
         Self { dice, gsc_boot_params }
     }
+}
 
-    #[cfg(not(feature = "builtin-bcc"))]
-    pub fn new() -> Self {
-        Self { dice: DiceHandover::default(), gsc_boot_params: GscBootParams::default() }
+#[cfg(feature = "builtin-bcc")]
+const BOOT_PARAM_KEY: i32 = 2;
+#[cfg(feature = "builtin-bcc")]
+const DICE_KEY: i32 = 3;
+
+impl BootParams {
+    pub fn new_from_dt(
+        early_entropy: [u8; 64],
+        session_key_seed: [u8; 32],
+        auth_token_key_seed: [u8; 32],
+        dice: &[u8],
+    ) -> Result<Self, Error> {
+        let dice = ciborium::de::from_reader_with_recursion_limit(dice, 16)
+            .map_err(|_| Error::CborError)?;
+        let dice = DiceHandover::from_cbor_value(dice).map_err(|_| Error::CborError)?;
+        Ok(Self {
+            dice,
+            gsc_boot_params: GscBootParams::new(
+                early_entropy,
+                session_key_seed,
+                auth_token_key_seed,
+            ),
+        })
     }
 
     /// Returns the UDS public key for the device.
@@ -80,7 +90,7 @@ impl BootParams {
     }
 
     /// Returns the CDI keypair as a tuple (attest, seal).
-    fn get_cdi_keypair(&self) -> Result<(&[u8], &[u8]), Error> {
+    pub fn get_cdi_keypair(&self) -> Result<(&[u8], &[u8]), Error> {
         Ok((&self.dice.cdi_attest, &self.dice.cdi_seal))
     }
 }
diff --git a/lib/external_super_block_mac/rules.mk b/lib/external_super_block_mac/rules.mk
new file mode 100644
index 0000000..937dea5
--- /dev/null
+++ b/lib/external_super_block_mac/rules.mk
@@ -0,0 +1,32 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SDK_LIB_NAME := desktop_external_super_block_mac
+
+MODULE_SRCS := \
+    $(LOCAL_DIR)/super_block_mac_device.c \
+
+MODULE_LIBRARY_DEPS := \
+    frameworks/native/libs/binder/trusty \
+    frameworks/native/libs/binder/trusty/binder_rpc_unstable \
+    trusty/user/base/lib/libc-trusty \
+    trusty/user/app/storage/lib_internal \
+    trusty/user/base/lib/tipc \
+    trusty/user/desktop/lib/gsc_svc_client/gsc_svc_client_staticlib \
+
+include make/library.mk
diff --git a/lib/external_super_block_mac/super_block_mac_device.c b/lib/external_super_block_mac/super_block_mac_device.c
new file mode 100644
index 0000000..ee4fb60
--- /dev/null
+++ b/lib/external_super_block_mac/super_block_mac_device.c
@@ -0,0 +1,105 @@
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
+#include <stdint.h>
+
+#include <lib/gsc_svc/gsc_svc.h>
+#include <storage_internal/super_block_mac_device.h>
+
+static int super_block_mac_get(const uint8_t index,
+           uint8_t *flags,
+           struct mac* mac) {
+    int ret = gsc_svc_client_super_block_mac_read(index, flags, &mac->byte);
+    if (ret) {
+        return SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION;
+    }
+
+    /*
+     * Check the flags MSB to determine if the mac is initialized or not. If the
+     * bit is not set, notify the storage application by returning a specific
+     * error code.
+     */
+    if (!(*flags & 0x80)) {
+        return SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED;
+    }
+
+    return ret;
+}
+
+static int super_block_mac_set(const uint8_t index,
+           const uint8_t flags,
+           const struct mac* mac) {
+    int ret = gsc_svc_client_super_block_mac_write(index, flags, &mac->byte);
+    if (ret) {
+        return SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION;
+    }
+
+    return ret;
+}
+
+static int super_block_mac_delete(const uint8_t index) {
+    int ret = gsc_svc_client_super_block_mac_delete(index);
+    if (ret) {
+        return SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION;
+    }
+
+    return ret;
+}
+
+int super_block_mac_get_td(struct super_block_mac_device* super_block_mac_dev,
+           uint8_t* flags,
+           struct mac* mac) {
+    return super_block_mac_get(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD, flags, mac);
+}
+
+int super_block_mac_set_td(struct super_block_mac_device* super_block_mac_dev,
+           const uint8_t flags,
+           const struct mac* mac) {
+    return super_block_mac_set(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD, flags, mac);
+}
+
+int super_block_mac_delete_td(struct super_block_mac_device* super_block_mac_dev) {
+    return super_block_mac_delete(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD);
+}
+
+struct super_block_mac_device super_block_mac_dev_td = {
+    .get = super_block_mac_get_td,
+    .set = super_block_mac_set_td,
+    .delete_mac = super_block_mac_delete_td,
+};
+
+int super_block_mac_get_tdp(struct super_block_mac_device* super_block_mac_dev,
+           uint8_t* flags,
+           struct mac* mac) {
+    return super_block_mac_get(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP, flags, mac);
+}
+
+int super_block_mac_set_tdp(struct super_block_mac_device* super_block_mac_dev,
+           const uint8_t flags,
+           const struct mac* mac) {
+    return super_block_mac_set(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP, flags, mac);
+}
+
+int super_block_mac_delete_tdp(struct super_block_mac_device* super_block_mac_dev) {
+    return super_block_mac_delete(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP);
+}
+
+struct super_block_mac_device super_block_mac_dev_tdp = {
+    .get = super_block_mac_get_tdp,
+    .set = super_block_mac_set_tdp,
+    .delete_mac = super_block_mac_delete_tdp,
+};
+
diff --git a/lib/gsc_svc_client/gsc_svc_client_staticlib/cbindgen.toml b/lib/gsc_svc_client/gsc_svc_client_staticlib/cbindgen.toml
new file mode 100644
index 0000000..61267e1
--- /dev/null
+++ b/lib/gsc_svc_client/gsc_svc_client_staticlib/cbindgen.toml
@@ -0,0 +1,32 @@
+# cbindgen.toml file specifically for generating gsc_svc.h
+
+language = "C"
+
+header = """
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
+ */"""
+
+autogen_warning = "/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */"
+
+pragma_once = true
+
+# Don't generate typedefs
+style = "tag"
+
+[enum]
+rename_variants = "snake_case"
+prefix_with_name = true
+
diff --git a/lib/gsc_svc_client/gsc_svc_client_staticlib/include/lib/gsc_svc/gsc_svc.h b/lib/gsc_svc_client/gsc_svc_client_staticlib/include/lib/gsc_svc/gsc_svc.h
new file mode 100644
index 0000000..c1bf2a2
--- /dev/null
+++ b/lib/gsc_svc_client/gsc_svc_client_staticlib/include/lib/gsc_svc/gsc_svc.h
@@ -0,0 +1,58 @@
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
+/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */
+
+#include <stdarg.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdlib.h>
+
+/**
+ * Tamper detect persist file index
+ */
+#define GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP 1
+
+/**
+ * Tamper detect file index
+ */
+#define GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD 2
+
+/**
+ * Reads the super block mac `data` from the GSC for a specific `index`.
+ *
+ * Returns `0` on success and `-1` on failure.
+ */
+int gsc_svc_client_super_block_mac_read(uint8_t index, uint8_t *flags, uint8_t (*mac)[16]);
+
+/**
+ * Writes the super block mac `data` to the GSC for a specific `index`.
+ *
+ * Returns `0` on success and `-1` on failure.
+ */
+int gsc_svc_client_super_block_mac_write(uint8_t index, uint8_t flags, const uint8_t (*mac)[16]);
+
+/**
+ * Delete a super block `mac` from the GSC for a specific `index`.
+ *
+ * The seven least significant flags bits will be preserved through a delete
+ * call.
+ *
+ * Returns `0` on success and `-1` on failure.
+ */
+int gsc_svc_client_super_block_mac_delete(uint8_t index);
diff --git a/lib/gsc_svc_client/gsc_svc_client_staticlib/lib.rs b/lib/gsc_svc_client/gsc_svc_client_staticlib/lib.rs
new file mode 100644
index 0000000..bf0c2b1
--- /dev/null
+++ b/lib/gsc_svc_client/gsc_svc_client_staticlib/lib.rs
@@ -0,0 +1,126 @@
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
+//! GSC service client C interface implementation
+//!
+//! To generate a new header file from this interface:
+//!
+//! ```shell
+//! $ cbindgen lib.rs --output include/lib/gsc_svc/gsc_svc.h
+//! ```
+
+use libc::c_int;
+
+use gsc_svc_client::{
+    GscServiceClient, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
+    TrustyStorageMacFileIndex,
+};
+use static_assertions::const_assert_eq;
+use zerocopy::TryFromBytes;
+
+/// Tamper detect persist file index
+pub const GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP: u8 = 1;
+
+/// Tamper detect file index
+pub const GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD: u8 = 2;
+
+// Supported superblock MAC file constants should match
+// `TrustyStorageMacFileIndex` values. We don't directly reference the enum so
+// cbindgen can cleanly generate C defines without knowing about Rust
+// dependencies.
+const_assert_eq!(
+    TrustyStorageMacFileIndex::TamperDetectPersist as u8,
+    GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP
+);
+const_assert_eq!(
+    TrustyStorageMacFileIndex::TamperDetect as u8,
+    GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD
+);
+
+/// Reads the super block mac `data` from the GSC for a specific `index`.
+///
+/// Returns `0` on success and `-1` on failure.
+#[no_mangle]
+pub extern "C" fn gsc_svc_client_super_block_mac_read(
+    index: u8,
+    flags: &mut u8,
+    mac: &mut [u8; 16],
+) -> c_int {
+    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
+        return -1;
+    };
+
+    let Ok(client) = GscServiceClient::new() else {
+        return -1;
+    };
+
+    let Ok(data) = client.read_trusty_storage_superblock_mac(index) else {
+        return -1;
+    };
+    *mac = data.mac.0;
+    *flags = data.flags.0;
+
+    0
+}
+
+/// Writes the super block mac `data` to the GSC for a specific `index`.
+///
+/// Returns `0` on success and `-1` on failure.
+#[no_mangle]
+pub extern "C" fn gsc_svc_client_super_block_mac_write(
+    index: u8,
+    flags: u8,
+    mac: &[u8; 16],
+) -> c_int {
+    let mac = TrustyStorageMac(*mac);
+    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
+        return -1;
+    };
+
+    let Ok(client) = GscServiceClient::new() else {
+        return -1;
+    };
+
+    let data = TrustyStorageMacData { mac, flags: TrustyStorageFlags(flags) };
+    let Ok(_) = client.write_trusty_storage_superblock_mac(index, data) else {
+        return -1;
+    };
+
+    0
+}
+
+/// Delete a super block `mac` from the GSC for a specific `index`.
+///
+/// The seven least significant flags bits will be preserved through a delete
+/// call.
+///
+/// Returns `0` on success and `-1` on failure.
+#[no_mangle]
+pub extern "C" fn gsc_svc_client_super_block_mac_delete(index: u8) -> c_int {
+    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
+        return -1;
+    };
+
+    let Ok(client) = GscServiceClient::new() else {
+        return -1;
+    };
+
+    let Ok(_) = client.delete_trusty_storage_superblock_mac(index) else {
+        return -1;
+    };
+
+    0
+}
diff --git a/lib/gsc_svc_client/gsc_svc_client_staticlib/rules.mk b/lib/gsc_svc_client/gsc_svc_client_staticlib/rules.mk
new file mode 100644
index 0000000..a75f344
--- /dev/null
+++ b/lib/gsc_svc_client/gsc_svc_client_staticlib/rules.mk
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
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := gsc_svc_client_staticlib
+
+MODULE_RUST_CRATE_TYPES := staticlib
+
+MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include/
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,libc) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,static_assertions) \
+	$(call FIND_CRATE,zerocopy) \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/desktop/lib/gsc_svc_client \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/gsc_svc_client/lib.rs b/lib/gsc_svc_client/lib.rs
new file mode 100644
index 0000000..e166241
--- /dev/null
+++ b/lib/gsc_svc_client/lib.rs
@@ -0,0 +1,197 @@
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
+use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
+use binder::Strong;
+use rpcbinder::RpcSession;
+use std::ffi::CStr;
+use tpm_commands::{TpmResponseHeader, TpmvRequest};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
+
+pub use tpm_commands::trusty_storage_superblock_mac::{
+    TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData, TrustyStorageMacFileIndex,
+};
+
+const GSC_SERVICE_PORT: &CStr = c"com.android.trusty.rust.GscAppService.V1";
+
+/// Possible client errors.
+#[derive(Debug, Eq, PartialEq)]
+pub enum GscServiceClientError {
+    /// Error connecting to the GSC service.
+    ConnectError,
+    /// Error when transacting with the GSC service.
+    TransmitError,
+    /// Message processing error.
+    Deserialization,
+    /// Tpm error.
+    Tpm(u32),
+}
+
+fn get_service(port: &CStr) -> Result<Strong<dyn IGsc>, GscServiceClientError> {
+    RpcSession::new().setup_trusty_client(port).map_err(|_| GscServiceClientError::ConnectError)
+}
+
+/// Client connected to the GSC service.
+pub struct GscServiceClient(pub Strong<dyn IGsc>);
+
+impl Default for GscServiceClient {
+    fn default() -> Self {
+        Self(get_service(GSC_SERVICE_PORT).unwrap())
+    }
+}
+
+impl GscServiceClient {
+    /// Create a new GSC service client. This method will attempt to connect to
+    /// the service.
+    pub fn new() -> Result<Self, GscServiceClientError> {
+        Ok(Self(get_service(GSC_SERVICE_PORT)?))
+    }
+
+    /// Get the superblock `mac` value stored on the GSC for a given `index`.
+    pub fn read_trusty_storage_superblock_mac(
+        &self,
+        index: TrustyStorageMacFileIndex,
+    ) -> Result<TrustyStorageMacData, GscServiceClientError> {
+        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
+        let response: Response = self.transmit(Request::new_read(index))?;
+
+        Ok(response.data)
+    }
+
+    /// Set the superblock mac `data` value stored on the GSC for a given
+    /// `index`.
+    pub fn write_trusty_storage_superblock_mac(
+        &self,
+        index: TrustyStorageMacFileIndex,
+        data: TrustyStorageMacData,
+    ) -> Result<(), GscServiceClientError> {
+        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
+        let _: Response = self.transmit(Request::new_write(index, data))?;
+
+        Ok(())
+    }
+
+    /// Uninitialize the superblock mac `data` value stored on the GSC for a
+    /// given `index`. The seven lower `flags` bits will be preserved.
+    pub fn delete_trusty_storage_superblock_mac(
+        &self,
+        index: TrustyStorageMacFileIndex,
+    ) -> Result<(), GscServiceClientError> {
+        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
+        let _: Response = self.transmit(Request::new_delete(index))?;
+
+        Ok(())
+    }
+
+    /// Helper function to transmit a tpmv request and return a deserialized
+    /// response type.
+    fn transmit<Req: TpmvRequest, Rsp: FromBytes + KnownLayout + Immutable>(
+        &self,
+        request: Req,
+    ) -> Result<Rsp, GscServiceClientError> {
+        use tpm_commands::{TpmRequestMessage, TpmResponseMessage};
+        let request = TpmRequestMessage::<Req>::new(request);
+        let bytes = self
+            .0
+            .transmit(request.as_bytes())
+            .map_err(|_| GscServiceClientError::TransmitError)?;
+
+        // Check for TPM errors
+        let (header, _) = TpmResponseHeader::ref_from_prefix(&bytes)
+            .map_err(|_| GscServiceClientError::Deserialization)?;
+        if header.error_code != 0 {
+            return Err(GscServiceClientError::Tpm(header.error_code.into()));
+        }
+
+        let response = TpmResponseMessage::<Rsp>::read_from_bytes(&bytes)
+            .map_err(|_| GscServiceClientError::Deserialization)?;
+
+        Ok(response.response)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    test::init!();
+
+    #[test]
+    fn send_bad_tpmv_request() {
+        use zerocopy::*;
+        #[derive(Default, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        pub struct Request;
+
+        #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
+        #[repr(C)]
+        pub struct Response;
+
+        impl TpmvRequest for Request {
+            const TAG: U16<BE> = U16::new(0x8001);
+            const COMMAND_CODE: U16<BE> = U16::new(0x0004);
+            const ORDINAL: U32<BE> = U32::new(0x20000000);
+            type TpmvResponse = Response;
+        }
+
+        let client = GscServiceClient::new().unwrap();
+        let res: Result<Response, GscServiceClientError> = client.transmit(Request);
+        assert_eq!(Err(GscServiceClientError::Tpm(0x508)), res);
+    }
+
+    #[test]
+    fn read_trusty_storage_superblock_mac() {
+        let client = GscServiceClient::new().unwrap();
+        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
+        client.read_trusty_storage_superblock_mac(index).unwrap();
+    }
+
+    // This test is destructive so it is disabled by default.
+    // #[test]
+    #[allow(dead_code)]
+    fn write_trusty_storage_superblock_mac() {
+        let client = GscServiceClient::new().unwrap();
+        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
+
+        // Reset mac storage
+        let empty_data = TrustyStorageMacData::default();
+        let res = client.write_trusty_storage_superblock_mac(index, empty_data);
+        assert_eq!(Ok(()), res);
+        let res = client.delete_trusty_storage_superblock_mac(index);
+        assert_eq!(Ok(()), res);
+        let res = client.read_trusty_storage_superblock_mac(index);
+        assert_eq!(Ok(empty_data), res);
+
+        // Verify that 0x80 bit is set on write
+        let data = TrustyStorageMacData {
+            mac: TrustyStorageMac([0xabu8; 16]),
+            flags: TrustyStorageFlags(0x43),
+        };
+        let res = client.write_trusty_storage_superblock_mac(index, data);
+        assert_eq!(Ok(()), res);
+        let expected =
+            TrustyStorageMacData { mac: data.mac, flags: TrustyStorageFlags(0x80 | data.flags.0) };
+        let res = client.read_trusty_storage_superblock_mac(index);
+        assert_eq!(Ok(expected), res);
+
+        // Verify that flags 0x7f are preserved when delete is called
+        let res = client.delete_trusty_storage_superblock_mac(index);
+        assert_eq!(Ok(()), res);
+        let expected = TrustyStorageMacData { mac: TrustyStorageMac::default(), flags: data.flags };
+        let res = client.read_trusty_storage_superblock_mac(index);
+        assert_eq!(Ok(expected), res);
+    }
+}
diff --git a/lib/gsc_svc_client/manifest.json b/lib/gsc_svc_client/manifest.json
new file mode 100644
index 0000000..970955b
--- /dev/null
+++ b/lib/gsc_svc_client/manifest.json
@@ -0,0 +1,6 @@
+{
+        "app_name": "gsc_svc_client",
+        "uuid": "01b7938e-abdd-4e35-9395-c6b9b4dd8001",
+        "min_heap": 16384,
+        "min_stack": 16384
+}
diff --git a/lib/gsc_svc_client/rules.mk b/lib/gsc_svc_client/rules.mk
new file mode 100644
index 0000000..b8b8c73
--- /dev/null
+++ b/lib/gsc_svc_client/rules.mk
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
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := gsc_svc_client
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,libc) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy) \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/desktop/interface/gscd \
+	trusty/user/desktop/lib/tpm_commands \
+
+MODULE_RUST_TESTS := true
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/keymint_access_policy/lib.rs b/lib/keymint_access_policy/lib.rs
new file mode 100644
index 0000000..e1f0cb2
--- /dev/null
+++ b/lib/keymint_access_policy/lib.rs
@@ -0,0 +1,40 @@
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
+//! The library implementing the generic access policy for Keymint Rust.
+//! This originates from a replication of `trusty/user/app/keymint/generic_access_policy`.
+//! It contains desktop specific modifications.
+
+use tipc::Uuid;
+
+pub const KEYMINT_ACCESSIBLE_UUIDS: [Uuid; 6] = [
+    /* gatekeeper uuid */
+    Uuid::new(0x38ba0cdc, 0xdf0e, 0x11e4, [0x98, 0x69, 0x23, 0x3f, 0xb6, 0xae, 0x47, 0x95]),
+    /* confirmation UI uuid */
+    Uuid::new(0x7dee2364, 0xc036, 0x425b, [0xb0, 0x86, 0xdf, 0x0f, 0x6c, 0x23, 0x3c, 0x1b]),
+    /* keymaster unit test uuid */
+    Uuid::new(0xf3ba7629, 0xe8cc, 0x44a0, [0x88, 0x4d, 0xf9, 0x16, 0xf7, 0x03, 0xa2, 0x00]),
+    /* keymint unit test uuid */
+    Uuid::new(0xd322eec9, 0x6d03, 0x49fa, [0x82, 0x1c, 0x1c, 0xcd, 0x27, 0x05, 0x71, 0x9c]),
+    /* finger_guard trusty app uuid */
+    Uuid::new(0x0c997054, 0xf477, 0x4cab, [0x96, 0x46, 0x46, 0x29, 0xe3, 0x4c, 0xb2, 0xf9]),
+    /* finger_guard unit test uuid */
+    Uuid::new(0x868899c6, 0xe820, 0x4cc0, [0xa8, 0x19, 0x11, 0x56, 0x5f, 0xfa, 0x8a, 0x45]),
+];
+
+pub fn keymint_check_secure_target_access_policy_provisioning(_uuid: &Uuid) -> bool {
+    /* Not Supported */
+    return false;
+}
diff --git a/lib/keymint_access_policy/rules.mk b/lib/keymint_access_policy/rules.mk
new file mode 100644
index 0000000..964fb75
--- /dev/null
+++ b/lib/keymint_access_policy/rules.mk
@@ -0,0 +1,29 @@
+# Copyright (C) 2023 The Android Open Source Project
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
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := keymint_access_policy
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+
+include make/library.mk
diff --git a/lib/tpm_commands/Android.bp b/lib/tpm_commands/Android.bp
index a4d7775..26821ad 100644
--- a/lib/tpm_commands/Android.bp
+++ b/lib/tpm_commands/Android.bp
@@ -15,8 +15,11 @@
 rust_defaults {
     name: "libdesktop_hwsec_tpm_commands_defaults",
     rustlibs: [
+        "libopen_enum",
+        "libthiserror",
         "libzerocopy",
     ],
+    proc_macros: ["libpaste"],
 }
 
 rust_library {
@@ -33,4 +36,5 @@ rust_test {
     defaults: ["libdesktop_hwsec_tpm_commands_defaults"],
     test_suites: ["general-tests"],
     auto_gen_config: true,
+    host_supported: true,
 }
diff --git a/lib/tpm_commands/lib.rs b/lib/tpm_commands/lib.rs
index 5adc5a2..7717561 100644
--- a/lib/tpm_commands/lib.rs
+++ b/lib/tpm_commands/lib.rs
@@ -16,7 +16,10 @@
 
 //! Structs and items that define TPM communications with the GSC
 
-use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, BE, U16, U32};
+use zerocopy::{
+    ConvertError, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes,
+    TryReadError, Unaligned, BE, U16, U32,
+};
 
 /// Indicates that the request will run without a session. All TPM vendor
 /// commands use this tag
@@ -40,7 +43,7 @@ pub enum AlignedZeroU32 {
 }
 
 /// An unaligned wrapper around [`AlignedZeroU32`]
-/// TODO: https://github.com/google/zerocopy/issues/2273 - Replace with zerocopy implementation
+/// TODO: <https://github.com/google/zerocopy/issues/2273> - Replace with zerocopy implementation
 #[repr(C, packed)]
 #[derive(
     Clone,
@@ -62,7 +65,7 @@ pub struct ZeroU32(AlignedZeroU32);
     Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned,
 )]
 #[repr(C)]
-// TODO: https://github.com/kupiakos/open-enum/issues/27 - use open_enum when it supports U32<BE>
+// TODO: <https://github.com/kupiakos/open-enum/issues/27> - use open_enum when it supports U32<BE>
 pub struct UpdateStatus(pub U32<BE>);
 
 impl UpdateStatus {
@@ -84,9 +87,10 @@ impl UpdateStatus {
     pub const DevIdMismatch: Self = UpdateStatus(U32::new(14));
 }
 
-/// A trait used to define the constants required by each type of TPMV request
-/// All TPMV requests are required to implement this trait
-pub trait TpmvRequest: IntoBytes + Immutable + Unaligned + Sized {
+/// Defines the constants required by each type of TPM vendor request.
+///
+/// All TPMV requests are required to implement this trait.
+pub trait TpmvRequest: IntoBytes + Immutable + Unaligned {
     /// The first 4 bytes of every TPM request and response.
     /// Used to indicate if the request requires a session to be run
     const TAG: U16<BE>;
@@ -99,15 +103,39 @@ pub trait TpmvRequest: IntoBytes + Immutable + Unaligned + Sized {
     const ORDINAL: U32<BE>;
 
     /// Each request type has an associated response type used to deserialize
-    /// bytes received from the TPM after a request is processed
-    type TpmvResponse: FromBytes + ?Sized + Unaligned;
+    /// bytes received from the TPM after a request is processed.
+    type TpmvResponse: TryFromBytes + ?Sized + Unaligned;
+}
+
+/// Operations to build a dynamically-sized request type.
+///
+/// See [`TpmRequestMessage::new_in_vec`].
+pub trait TpmvRequestBuild: TpmvRequest + FromZeros + KnownLayout {
+    /// Parameters to build an self-consistent instance of this request from zeros.
+    ///
+    /// This does not need to fill every field of the request, only those that should
+    /// be static for every instance of this message.
+    type BuildParams;
+
+    /// Error in initialization or size calculation.
+    type Err;
+
+    /// The expected size for the request in bytes, excluding the TPM header.
+    ///
+    /// If `Self: Sized` this should be `size_of::<Self>()`.
+    fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err>;
+
+    /// Initializes a zeroed `self` to an internally consistent state.
+    ///
+    /// This is where data length fields should be initialized, for example.
+    fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err>;
 }
 
 /// Represents a complete TPM request. Contains both the request header and any
 /// additional fields required by the request type
-#[derive(Debug, Eq, IntoBytes, Immutable, PartialEq)]
+#[derive(Debug, Eq, TryFromBytes, IntoBytes, Immutable, PartialEq, KnownLayout, Unaligned)]
 #[repr(C)]
-pub struct TpmRequestMessage<T: TpmvRequest> {
+pub struct TpmRequestMessage<T: TpmvRequest + ?Sized> {
     /// The request header
     header: TpmRequestHeader,
 
@@ -116,28 +144,89 @@ pub struct TpmRequestMessage<T: TpmvRequest> {
 }
 
 impl<T: TpmvRequest> TpmRequestMessage<T> {
-    /// Generates a new `TpmvRequest` of the provided type T
+    /// Generates a new `TpmvRequest` for the provided type `T`.
     pub fn new(request: T) -> Self {
-        Self {
-            header: TpmRequestHeader {
-                tag: T::TAG,
-                length: U32::new(size_of::<Self>() as u32),
-                ordinal: T::ORDINAL,
-                command_code: T::COMMAND_CODE,
-            },
-            request,
+        Self { header: TpmRequestHeader::for_request::<T>(), request }
+    }
+}
+
+/// An error while building a TPM Request from a buffer.
+#[derive(thiserror::Error)]
+pub enum TpmRequestBuildError<Req: ?Sized + TpmvRequestBuild> {
+    /// Failed to allocate enough space for the request.
+    #[error("failed to allocate enough space for the request")]
+    Alloc,
+
+    /// The size returned by the request was invalid.
+    #[error("the request code gave an invalid size")]
+    Size,
+
+    /// `init` or `expected_size` in [`TpmvRequestBuild`] failed.
+    #[error("internal request build error: {0}")]
+    Internal(Req::Err),
+}
+
+impl<Req: ?Sized + TpmvRequestBuild> std::fmt::Debug for TpmRequestBuildError<Req>
+where
+    Req::Err: std::fmt::Debug,
+{
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            Self::Alloc => write!(f, "Alloc"),
+            Self::Size => write!(f, "Size"),
+            Self::Internal(arg0) => f.debug_tuple("Internal").field(arg0).finish(),
+        }
+    }
+}
+
+impl<Req: ?Sized + TpmvRequestBuild> From<std::collections::TryReserveError>
+    for TpmRequestBuildError<Req>
+{
+    fn from(_: std::collections::TryReserveError) -> Self {
+        Self::Alloc
+    }
+}
+
+impl<T: ?Sized + TpmvRequestBuild> TpmRequestMessage<T> {
+    /// Builds a request message using the given `Vec` as backing memory.
+    pub fn new_in_vec(
+        buf: &mut Vec<u8>,
+        params: <T as TpmvRequestBuild>::BuildParams,
+    ) -> Result<&mut Self, TpmRequestBuildError<T>> {
+        let data_size: usize = T::expected_size(&params)
+            .map_err(TpmRequestBuildError::Internal)?
+            .try_into()
+            .map_err(|_| TpmRequestBuildError::Size)?;
+        let total_size = data_size
+            .checked_add(size_of::<TpmRequestHeader>())
+            .ok_or(TpmRequestBuildError::Size)?;
+        let total_size_u32: u32 = total_size.try_into().map_err(|_| TpmRequestBuildError::Size)?;
+        if let Some(additional) = total_size.checked_sub(buf.len()) {
+            buf.try_reserve(additional)?;
         }
+        buf.clear();
+        buf.resize(total_size, 0);
+        let out = match Self::try_mut_from_bytes(&mut buf[..]).map_err(TryReadError::from) {
+            Ok(m) if size_of_val(m) == total_size => Ok(m),
+            Ok(_) | Err(ConvertError::Size(_)) => Err(TpmRequestBuildError::Size),
+            Err(ConvertError::Validity(_)) => unreachable!("T: FromZeros"),
+        }?;
+        out.header = TpmRequestHeader::for_request_with_total_size::<T>(total_size_u32);
+        out.request.init(params).map_err(TpmRequestBuildError::Internal)?;
+        Ok(out)
     }
 }
 
 /// Represents the initial bytes of every TPM request.
-#[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
+#[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, PartialEq, Unaligned)]
 #[repr(C)]
 pub struct TpmRequestHeader {
     /// The first 4 bytes of every TPM request
     pub tag: U16<BE>,
 
     /// The total number of bytes in the request
+    ///
+    /// Rust usually calls this term a "size" - `[u32; 3]` has a size of 12, but a length of 3.
     pub length: U32<BE>,
 
     /// The request's ordinal
@@ -148,6 +237,24 @@ pub struct TpmRequestHeader {
     pub command_code: U16<BE>,
 }
 
+impl TpmRequestHeader {
+    /// Constructs a `TpmRequestHeader` for the given request and total message size in bytes.
+    pub fn for_request_with_total_size<T: TpmvRequest + ?Sized>(size: u32) -> Self {
+        TpmRequestHeader {
+            tag: T::TAG,
+            length: U32::new(size),
+            ordinal: T::ORDINAL,
+            command_code: T::COMMAND_CODE,
+        }
+    }
+
+    /// Constructs a `TpmRequestHeader` for the given fixed-size request.
+    pub fn for_request<T: TpmvRequest>() -> Self {
+        const { assert!(size_of::<TpmRequestMessage<T>>() as u64 <= u32::MAX as u64) }
+        Self::for_request_with_total_size::<T>(size_of::<TpmRequestMessage<T>>() as u32)
+    }
+}
+
 /// Represents a complete TPM response. Contains both the response header and any
 /// additional fields required by the response type
 #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq)]
@@ -259,10 +366,147 @@ pub mod get_version_info {
     }
 }
 
+pub mod pinweaver;
+
+/// Contains the requests and responses used to access superblock mac
+/// storage on the GSC.
+pub mod trusty_storage_superblock_mac {
+    use super::*;
+
+    /// Trusty storage application mac.
+    #[derive(
+        Clone,
+        Copy,
+        Debug,
+        Default,
+        Eq,
+        FromBytes,
+        IntoBytes,
+        Immutable,
+        KnownLayout,
+        PartialEq,
+        Unaligned,
+    )]
+    #[repr(C)]
+    pub struct TrustyStorageMac(pub [u8; 16]);
+
+    /// Trusty storage application flags.
+    #[derive(
+        Clone,
+        Copy,
+        Debug,
+        Default,
+        Eq,
+        FromBytes,
+        IntoBytes,
+        Immutable,
+        KnownLayout,
+        PartialEq,
+        Unaligned,
+    )]
+    #[repr(C)]
+    pub struct TrustyStorageFlags(pub u8);
+
+    /// Supported storage mac commands.
+    #[derive(Clone, Copy, Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
+    #[repr(u8)]
+    pub enum TrustyStorageMacCommand {
+        /// Read operation.
+        Read = 0,
+        /// Write operation.
+        Write = 1,
+        /// Delete operation.
+        Delete = 2,
+    }
+
+    /// Used by the Trusty secure storage application to store the MAC of the
+    /// current valid superblock.
+    #[derive(Clone, Copy, Debug, Eq, IntoBytes, Immutable, PartialEq, TryFromBytes, Unaligned)]
+    #[repr(u8)]
+    pub enum TrustyStorageMacFileIndex {
+        /// Tamper detect persist filesystem mac index.
+        TamperDetectPersist = 1,
+        /// Tamper detect filesystem mac index.
+        TamperDetect = 2,
+    }
+
+    /// Trusty storage application data.
+    #[derive(
+        Clone,
+        Copy,
+        Debug,
+        Default,
+        Eq,
+        FromBytes,
+        IntoBytes,
+        Immutable,
+        KnownLayout,
+        PartialEq,
+        Unaligned,
+    )]
+    #[repr(C)]
+    pub struct TrustyStorageMacData {
+        /// MAC data currently stored.
+        pub mac: TrustyStorageMac,
+        /// Super block flags.
+        pub flags: TrustyStorageFlags,
+    }
+
+    /// Requests superblock mac reads/writes from the GSC.
+    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
+    #[repr(C)]
+    pub struct Request {
+        /// Operation to perform.
+        pub command: TrustyStorageMacCommand,
+        /// File identifier.
+        pub index: TrustyStorageMacFileIndex,
+        /// MAC data to write.
+        pub data: TrustyStorageMacData,
+    }
+
+    impl Request {
+        /// Create a new read request.
+        pub fn new_read(index: TrustyStorageMacFileIndex) -> Self {
+            Self {
+                command: TrustyStorageMacCommand::Read,
+                index,
+                data: TrustyStorageMacData::default(),
+            }
+        }
+
+        /// Create a new write request.
+        pub fn new_write(index: TrustyStorageMacFileIndex, data: TrustyStorageMacData) -> Self {
+            Self { command: TrustyStorageMacCommand::Write, index, data }
+        }
+
+        /// Create a new delete request.
+        pub fn new_delete(index: TrustyStorageMacFileIndex) -> Self {
+            Self {
+                command: TrustyStorageMacCommand::Delete,
+                index,
+                data: TrustyStorageMacData::default(),
+            }
+        }
+    }
+
+    impl TpmvRequest for Request {
+        const TAG: U16<BE> = NO_SESSION_TAG;
+        const COMMAND_CODE: U16<BE> = U16::new(0x004D);
+        const ORDINAL: U32<BE> = VENDOR_COMMAND_ORDINAL;
+        type TpmvResponse = Response;
+    }
+
+    /// Represents a response from a [`Request`]
+    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
+    #[repr(C)]
+    pub struct Response {
+        /// MAC data currently stored.
+        pub data: TrustyStorageMacData,
+    }
+}
+
 #[cfg(test)]
 mod tests {
-    use super::get_console_log;
-    use super::get_version_info;
     use super::*;
 
     #[test]
@@ -360,4 +604,212 @@ mod tests {
             TpmResponseMessage::<get_version_info::Response>::ref_from_bytes(&bytes).unwrap();
         assert_eq!(*tpm_response, expected_response);
     }
+
+    #[test]
+    fn test_trusty_storage_superblock_mac_serialize() {
+        use trusty_storage_superblock_mac::{
+            Request, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
+            TrustyStorageMacFileIndex,
+        };
+        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
+        let request = TpmRequestMessage::<Request>::new(Request::new_read(index));
+        let expected_bytes = vec![
+            0x80, 0x01, // header.tag
+            0x00, 0x00, 0x00, 0x1F, // header.length
+            0x20, 0x00, 0x00, 0x00, // header.ordinal
+            0x00, 0x4D, // header.subcmd
+            0x00, // request.command
+            0x01, // request.index
+            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0x00, // request.data.mac
+            0x00, // request.data.flags
+        ];
+
+        assert_eq!(expected_bytes, request.as_bytes());
+
+        let index = TrustyStorageMacFileIndex::TamperDetect;
+        let data = TrustyStorageMacData {
+            mac: TrustyStorageMac([
+                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+                0x00, 0xff,
+            ]),
+            flags: TrustyStorageFlags(0x81),
+        };
+        let request = TpmRequestMessage::<Request>::new(Request::new_write(index, data));
+        let expected_bytes = vec![
+            0x80, 0x01, // header.tag
+            0x00, 0x00, 0x00, 0x1F, // header.length
+            0x20, 0x00, 0x00, 0x00, // header.ordinal
+            0x00, 0x4D, // header.subcmd
+            0x01, // request.command
+            0x02, // request.index
+            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+            0x00, 0xff, // request.data.mac
+            0x81, // request.data.flags
+        ];
+
+        assert_eq!(expected_bytes, request.as_bytes());
+    }
+
+    #[test]
+    fn test_trusty_storage_superblock_mac_deserialize() {
+        use trusty_storage_superblock_mac::{
+            Response, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
+        };
+        let bytes = vec![
+            0x80, 0x01, // header.tag
+            0x00, 0x00, 0x00, 0x1D, // header.length
+            0xDE, 0xAD, 0xBE, 0xEF, // header.error_code
+            0x00, 0x4D, // header.subcmd
+            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
+            0x02, 0x02, // response.data.mac
+            0x81, // response.data.flags
+        ];
+
+        let expected_response = TpmResponseMessage {
+            header: TpmResponseHeader {
+                tag: U16::new(0x8001),
+                length: U32::new(0x0000001D),
+                error_code: U32::new(0xDEADBEEF),
+                command_code: U16::new(0x004D),
+            },
+
+            response: Response {
+                data: TrustyStorageMacData {
+                    mac: TrustyStorageMac([2u8; 16]),
+                    flags: TrustyStorageFlags(0x81),
+                },
+            },
+        };
+
+        let tpm_response = TpmResponseMessage::<Response>::ref_from_bytes(&bytes).unwrap();
+        assert_eq!(*tpm_response, expected_response);
+    }
+
+    #[test]
+    fn test_request_new_in_vec() {
+        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C, packed)]
+        struct FakeRequest {
+            rest_len: U32<BE>,
+            must_be_zero: [ZeroU32; 3],
+            rest: [u8],
+        }
+        impl TpmvRequest for FakeRequest {
+            const TAG: U16<BE> = NO_SESSION_TAG;
+            const ORDINAL: U32<BE> = U32::new(2);
+            const COMMAND_CODE: U16<BE> = U16::new(1);
+            type TpmvResponse = FakeResponse;
+        }
+        impl TpmvRequestBuild for FakeRequest {
+            type BuildParams = u32;
+            type Err = ();
+
+            fn init(&mut self, rest_len: u32) -> Result<(), ()> {
+                self.rest_len.set(rest_len);
+                Ok(())
+            }
+
+            fn expected_size(rest_len: &u32) -> Result<u32, ()> {
+                Ok((size_of::<U32<BE>>()
+                    + 3 * size_of::<ZeroU32>()
+                    + usize::try_from(*rest_len).unwrap()) as u32)
+            }
+        }
+        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        struct FakeResponse;
+        let mut buf = Vec::new();
+        let req = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, 10).unwrap();
+        assert_eq!(req.request.rest_len.get(), 10);
+        assert_eq!(req.request.rest, [0; 10]);
+        req.request.rest[0] = 10;
+        assert_eq!(
+            req.as_bytes(),
+            [
+                0x80, 1, 0, 0, 0, 38, 0, 0, 0, 2, 0, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+                0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0
+            ]
+        );
+        assert_eq!(buf.len(), 38);
+
+        let req = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, 5).unwrap();
+        assert_eq!(req.request.rest_len.get(), 5);
+        assert_eq!(req.request.rest, [0; 5], "buf should have been zeroed");
+        assert_eq!(buf.len(), 33, "buf should have been truncated");
+    }
+
+    #[test]
+    fn test_request_new_in_vec_overflow() {
+        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        struct FakeRequest;
+        impl TpmvRequest for FakeRequest {
+            const TAG: U16<BE> = NO_SESSION_TAG;
+            const ORDINAL: U32<BE> = U32::new(2);
+            const COMMAND_CODE: U16<BE> = U16::new(1);
+            type TpmvResponse = FakeResponse;
+        }
+        impl TpmvRequestBuild for FakeRequest {
+            type BuildParams = ();
+            type Err = ();
+
+            fn init(&mut self, _: ()) -> Result<(), ()> {
+                Ok(())
+            }
+
+            fn expected_size(_: &()) -> Result<u32, ()> {
+                Ok(u32::MAX)
+            }
+        }
+        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        struct FakeResponse;
+        let mut buf = vec![1, 2, 3];
+        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, ());
+        assert!(matches!(res, Err(TpmRequestBuildError::Size)));
+        assert_eq!(buf, [1, 2, 3], "expected size error should not affect buf")
+    }
+
+    #[test]
+    fn test_request_new_in_vec_internal_error() {
+        #[derive(Debug, FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        struct FakeRequest;
+        impl TpmvRequest for FakeRequest {
+            const TAG: U16<BE> = NO_SESSION_TAG;
+            const ORDINAL: U32<BE> = U32::new(2);
+            const COMMAND_CODE: U16<BE> = U16::new(1);
+            type TpmvResponse = FakeResponse;
+        }
+        impl TpmvRequestBuild for FakeRequest {
+            type BuildParams = bool;
+            type Err = &'static str;
+
+            fn init(&mut self, fail_init: bool) -> Result<(), Self::Err> {
+                if fail_init {
+                    Err("init")
+                } else {
+                    Ok(())
+                }
+            }
+
+            fn expected_size(&fail_init: &bool) -> Result<u32, Self::Err> {
+                if !fail_init {
+                    Err("expected_size")
+                } else {
+                    Ok(0)
+                }
+            }
+        }
+        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
+        #[repr(C)]
+        struct FakeResponse;
+        let mut buf = vec![1, 2, 3];
+        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, false);
+        assert!(matches!(res, Err(TpmRequestBuildError::Internal("expected_size"))));
+        assert_eq!(buf, [1, 2, 3], "expected_size error should not affect buf");
+        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, true);
+        assert!(matches!(res, Err(TpmRequestBuildError::Internal("init"))));
+    }
 }
diff --git a/lib/tpm_commands/pinweaver.rs b/lib/tpm_commands/pinweaver.rs
new file mode 100644
index 0000000..c8a1f83
--- /dev/null
+++ b/lib/tpm_commands/pinweaver.rs
@@ -0,0 +1,457 @@
+//! Contains the requests and responses used to access PinWeaver on the GSC.
+//!
+//! This is based on the Chromium PinWeaver [source][0], but was not mechanically derived.
+//!
+//! [0]: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/main/pinweaver_types.h
+
+#![allow(dead_code)] // Many private fields exist to be serialized and deserialized from bytes.
+
+use crate::{TpmRequestMessage, TpmResponseMessage};
+use paste::paste;
+use zerocopy::{
+    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, LE, U16, U32,
+    U64,
+};
+
+pub mod request;
+pub mod response;
+
+/// The protocol version recognized by this implementation.
+pub const PROTOCOL_VERSION: u8 = 2;
+
+macro_rules! export_request_response {
+    ($($name:ident),* $(,)?) => {
+        paste! {$(
+            #[doc = concat!("A full PinWeaver ", stringify!($name), " request.")]
+            pub type [<$name Request>] = TpmRequestMessage<request::Request<request::$name>>;
+            #[doc = concat!("A full PinWeaver ", stringify!($name), " response.")]
+            pub type [<$name Response>] = TpmResponseMessage<response::Response<response::$name>>;
+        )*}
+    };
+}
+export_request_response!(ResetTree, InsertLeaf, RemoveLeaf, TryAuth, SysInfo);
+
+/// Overflow error while performing size arithmetic or integer conversion.
+///
+/// Not expected in normal usage.
+#[derive(Debug, thiserror::Error)]
+#[error("unexpected arithmetic overflow")]
+pub struct Overflow;
+
+/// Parameters for a tree.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct TreeParams {
+    /// The number of bits to distinguish each level of the tree.
+    pub bits_per_level: u8,
+
+    /// The height of the tree, measured as edge count from root to leaf.
+    pub height: u8,
+}
+
+/// Requests and responses which include the contents of a leaf on disk.
+#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C, packed)]
+pub struct WithUnimportedLeafData<Head> {
+    /// Data before the leaf data.
+    pub head: Head,
+
+    /// The leaf data persisted off-GSC.
+    pub unimported_leaf_data: UnimportedLeafData,
+}
+
+impl<Head: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + std::fmt::Debug>
+    std::fmt::Debug for WithUnimportedLeafData<Head>
+{
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("WithUnimportedLeafData")
+            .field("header", self.head())
+            .field("unimported_leaf_data", &&self.unimported_leaf_data)
+            .finish()
+    }
+}
+
+impl<Head: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned>
+    WithUnimportedLeafData<Head>
+{
+    /// Gets a reference to the head of this message.
+    ///
+    /// Taking a reference to a generic field gives an error because Rust doesn't
+    /// know about `Unaligned` making `repr(packed)` alignment errors impossible.
+    pub fn head(&self) -> &Head {
+        Head::ref_from_prefix(self.as_bytes()).unwrap().0
+    }
+
+    /// Gets a mutable reference to the head of this message..
+    pub fn head_mut(&mut self) -> &mut Head {
+        Head::mut_from_prefix(self.as_mut_bytes()).unwrap().0
+    }
+}
+
+/// Version of leaf data.
+///
+/// This is largely ignored by Android - all that matters is consistency with GSC data.
+/// The below is adapted from the original doc:
+///
+/// `minor` comes first so this struct will be compatible with `u32`
+/// comparisons for little endian to make version comparisons easier.
+/// Changes to minor versions are allowed to add new fields, but not
+/// remove existing fields, and they are allowed to be interpreted by
+/// previous versions---any extra fields are truncated.
+/// Leafs will reject future major versions assuming they are
+/// incompatible, so fields in public data and ciphertext data in
+/// the [`UnimportedLeafData`] may be removed for new major versions.
+/// Upgrades across major versions will require explicit logic to
+/// map the old struct to the new struct or vice versa.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct LeafVersion {
+    /// Minor version - can interop with other versions with the same `major`.
+    minor: U16<LE>,
+
+    /// Major version - upgrading is incompatible.
+    major: U16<LE>,
+}
+
+impl LeafVersion {
+    /// Builds a new `LeafVersion`.
+    pub fn new(minor: u16, major: u16) -> Self {
+        Self { minor: minor.into(), major: major.into() }
+    }
+
+    /// Gets the minor version.
+    pub fn minor(&self) -> u16 {
+        self.minor.get()
+    }
+
+    /// Gets the major version.
+    pub fn major(&self) -> u16 {
+        self.major.get()
+    }
+}
+
+/// Identifies the version and layout of a leaf.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct LeafHeader {
+    /// The version of the leaf structure.
+    leaf_version: LeafVersion,
+
+    /// Length of the public data.
+    pub_len: U16<LE>,
+
+    /// Length of the ciphertext data.
+    sec_len: U16<LE>,
+}
+
+impl LeafHeader {
+    /// Gets the length of the public data in the `UnimportedLeafData` `data` field.
+    pub fn pub_len(&self) -> u16 {
+        self.pub_len.get()
+    }
+
+    /// Gets the length of the ciphertext data in the `UnimportedLeafData` `data` field.
+    pub fn sec_len(&self) -> u16 {
+        self.pub_len.get()
+    }
+
+    /// Gets the leaf version.
+    pub fn leaf_version(&self) -> &LeafVersion {
+        &self.leaf_version
+    }
+}
+
+/// Returns the number of auxiliary hashes to include in requests that require them.
+///
+/// Depends on the tree parameters.
+pub fn path_auxiliary_hash_count(bits_per_level: u8, height: u8) -> Result<usize, Overflow> {
+    ((1usize.checked_shl(bits_per_level.into()).ok_or(Overflow)?) - 1)
+        .checked_mul(height.into())
+        .ok_or(Overflow)
+}
+
+/// Leaf data persisted off-GSC.
+#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C, packed)] // The `packed` is required for DST IntoBytes at the moment.
+pub struct UnimportedLeafData {
+    header: LeafHeader,
+    /// HMAC for the leaf - covers head, iv, and payload, excluding the path hashes.
+    pub hmac: Hash,
+
+    /// IV used to calculate the HMAC.
+    pub iv: Iv,
+
+    /// Blob of remaining data. Has the following layout:
+    ///
+    /// ```
+    /// #[repr(C)]
+    /// struct Tail {
+    ///     pub_data: [u8; header.pub_len],
+    ///     cipher_text: [u8; header.sec_len],
+    ///     // For requests only (size expected external to this struct):
+    ///     path_hashes: [Hash; path_auxiliary_hash_count(bits_per_level, height)],
+    /// }
+    /// ```
+    pub data: [u8],
+}
+
+// Cannot `derive(Debug)` for `repr(packed)`
+impl std::fmt::Debug for UnimportedLeafData {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("UnimportedLeafData")
+            .field("head", &self.header)
+            .field("hmac", &self.hmac)
+            .field("iv", &self.iv)
+            .field("data", &&self.data)
+            .finish()
+    }
+}
+
+/// Error in the consistency of sizes in an [`UnimportedLeafData`].
+#[derive(Clone, Debug, thiserror::Error)]
+pub enum UnimportedLeafDataSizeError {
+    /// Bad leaf data size.
+    #[error("leaf data size invalid - got {pub_len} + {sec_len}, expected {total_received}")]
+    LeafDataSizes {
+        /// The length of public data reported in the invalid header.
+        pub_len: u16,
+
+        /// The length of ciphertext data reported in the invalid header.
+        sec_len: u16,
+
+        /// The total length of dynamic data in the invalid [`UnimportedLeafData`].
+        total_received: usize,
+    },
+
+    /// Trailing path hash sizes not divisible by the hash size.
+    #[error("remaining leaf data size not divisible by hash size: {size_for_hashes}")]
+    HashDataSizeNotDivisible {
+        /// The size in bytes remaining for hashes after subtracting public and secure lengths.
+        size_for_hashes: usize,
+    },
+
+    /// Trailing data for path hashes in the `UnimportedLeafData` wasn't the right size.
+    #[error(
+        "unexpected hash count in leaf data: got {num_hashes_got}, expected {num_hashes_expected}"
+    )]
+    HashDataLen {
+        /// The number of hashes present in the leaf data.
+        num_hashes_got: usize,
+
+        /// The number of expected hashes in the leaf based on the current tree parameters.
+        num_hashes_expected: usize,
+    },
+
+    /// Invalid tree parameters.
+    #[error("tried to check consistency with invalid tree params {0:?}")]
+    InvalidTreeParams(TreeParams),
+}
+
+impl UnimportedLeafData {
+    /// Gets the unimported leaf header.
+    pub fn header(&self) -> &LeafHeader {
+        &self.header
+    }
+
+    /// Gets the path hashes to fill in for a request.
+    ///
+    /// Returns `None` if the header does not have valid sizes.
+    /// Note that this will be `Some([])` for a self-consistent response message.
+    ///
+    /// If `check_consistency` returned `Ok` with `Some(TreeParams)`, then the length of the
+    /// returned slice will be the number of sibling hashes needed for a path in that tree.
+    pub fn path_hashes_mut(&mut self) -> Option<&mut [Hash]> {
+        let hashes_offset = usize::from(self.header.pub_len()) + usize::from(self.header.sec_len());
+        self.data
+            .get_mut(hashes_offset..)
+            .and_then(|hashes_bytes| <[Hash]>::mut_from_bytes(hashes_bytes).ok())
+    }
+
+    /// Checks the consistency of the unimported leaf data header against its dynamic size.
+    ///
+    /// `request_tree_params` should only be `Some` for request messages, which use path hashes.
+    pub fn check_consistency(
+        &self,
+        request_tree_params: Option<&TreeParams>,
+    ) -> Result<(), UnimportedLeafDataSizeError> {
+        use UnimportedLeafDataSizeError::*;
+        let total_received = self.data.len();
+        let pub_len = self.header.pub_len.get();
+        let sec_len = self.header.sec_len.get();
+        let num_expected_hashes = request_tree_params
+            .map(|&tree_params| {
+                path_auxiliary_hash_count(tree_params.bits_per_level, tree_params.height)
+                    .map_err(|Overflow| InvalidTreeParams(tree_params))
+            })
+            .transpose()?;
+
+        let dyn_leaf_data_size = usize::from(pub_len) + usize::from(sec_len);
+        match (total_received.checked_sub(dyn_leaf_data_size), num_expected_hashes) {
+            (Some(0), None) => Ok(()),
+            (Some(1..), None) | (None, _) => {
+                Err(LeafDataSizes { pub_len, sec_len, total_received })
+            }
+            (Some(size_for_hashes), Some(_)) if size_for_hashes % size_of::<Hash>() != 0 => {
+                Err(HashDataSizeNotDivisible { size_for_hashes })
+            }
+            (Some(size_for_hashes), Some(num_hashes_expected)) => {
+                let num_hashes_got = size_for_hashes / size_of::<Hash>();
+                if num_hashes_got == num_hashes_expected {
+                    Ok(())
+                } else {
+                    Err(HashDataLen { num_hashes_got, num_hashes_expected })
+                }
+            }
+        }
+    }
+}
+
+/// Unencrypted part of the leaf data.
+#[derive(Clone, Debug, IntoBytes, Immutable, KnownLayout, TryFromBytes, Unaligned)]
+#[repr(C)]
+pub struct LeafPublicData {
+    /// The label of the leaf.
+    pub label: Label,
+
+    /// The delay schedule for the new leaf.
+    pub delay_schedule: DelaySchedule,
+
+    /// The last access of the tree.
+    pub last_access: Timestamp,
+
+    /// The number of attempted auths against this leaf since the last successful auth.
+    ///
+    /// Capped at `u32::MAX`.
+    pub attempt_count: U32<LE>,
+
+    /// The PCR criteria used to validate a leaf.
+    pub valid_pcr_criteria: ValidPcrCriteria,
+
+    /// Timestamp when the leaf data expires and authentication is always rejected.
+    ///
+    /// All zeroes if expiration will not take place.
+    pub expiration: Timestamp,
+
+    /// The delay from creation of this leaf to when its expiration.
+    ///
+    /// 0 indicates no expiration will take place.
+    ///
+    /// Kept here to update `expiration` after resetting a leaf.
+    pub expiration_delay: TimeDiff,
+
+    /// The type of PinWeaver leaf.
+    pub leaf_type: LeafType,
+}
+
+/// A single entry in a delay schedule table.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct DelayScheduleEntry {
+    /// The number of attempts taken before this entry takes effect.
+    pub attempt_count: U32<LE>,
+
+    /// The time interval to wait after `attempt_count` attempts, in seconds.
+    /// Use `u32::MAX` to block all subsequent attempts.
+    pub time_diff: TimeDiff,
+}
+
+/// The number of delay schedule entries allowed for a PinWeaver leaf.
+pub const DELAY_SCHEDULE_ENTRIES: usize = 16;
+
+/// The delay schedule for a PinWeaver leaf upon unsuccessful auth.
+///
+/// `attempt_count` and `time_diff` must not be less than previous entries.
+pub type DelaySchedule = [DelayScheduleEntry; DELAY_SCHEDULE_ENTRIES];
+
+/// A label in the tree. Synonymous with "path" - used interchangeably.
+pub type Label = U64<LE>;
+
+/// Contents of a PinWeaver secret.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(transparent)]
+pub struct Secret(pub [u8; 32]);
+
+/// A hash in the PinWeaver tree. Unrelated to the size of `Secret`s.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(transparent)]
+pub struct Hash(pub [u8; 32]);
+
+/// The block size of encryption used for wrapped leaf data.
+const WRAP_BLOCK_SIZE: usize = 16;
+
+/// An IV for a PinWeaver leaf's HMAC calculation.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(transparent)]
+pub struct Iv(pub [u8; WRAP_BLOCK_SIZE]);
+
+/// Time difference in seconds.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(transparent)]
+pub struct TimeDiff(U32<LE>);
+
+impl TimeDiff {
+    /// Used to block all subsequent attempts in a [`DelayScheduleEntry`].
+    pub const BLOCK_ATTEMPTS: Self = Self::from_secs(u32::MAX);
+
+    /// Converts from seconds.
+    pub const fn from_secs(secs: u32) -> Self {
+        Self(U32::new(secs))
+    }
+
+    /// Converts to seconds.
+    pub const fn to_secs(self) -> u32 {
+        self.0.get()
+    }
+}
+
+impl From<TimeDiff> for std::time::Duration {
+    fn from(value: TimeDiff) -> Self {
+        std::time::Duration::from_secs(value.to_secs().into())
+    }
+}
+
+/// The maximum number of criteria for valid PCR values.
+pub const MAX_PCR_CRITERIA_COUNT: usize = 2;
+
+/// The set of PCR criteria used to validate a leaf.
+pub type ValidPcrCriteria = [ValidPcrValue; MAX_PCR_CRITERIA_COUNT];
+
+/// The type of PinWeaver leaf. As of writing, only `Normal` is supported by this version.
+#[derive(Clone, Copy, Debug, FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(u8)]
+pub enum LeafType {
+    /// A normal leaf.
+    Normal = 0,
+
+    /// A biometrics leaf.
+    Biometrics = 1,
+}
+
+/// Represents a set of PCR values hashed into a single digest.
+///
+/// This is a criterion that can be added to a leaf. A leaf is only valid if at least one
+/// of the `ValidPcrValue` criteria it contains is satisfied.
+#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct ValidPcrValue {
+    /// The set of PCR indexes that have to pass the validation.
+    pub bitmask: [u8; 2],
+
+    /// The hash digest of the PCR values contained in the bitmask.
+    pub digest: Hash,
+}
+
+/// Represents a notion of time for PinWeaver.
+///
+/// Note that this is not wall clock time.
+#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct Timestamp {
+    /// Number of boots.
+    ///
+    /// Used to track if the GSC has rebooted since `timer_value` was recorded.
+    pub boot_count: U32<LE>,
+
+    /// Seconds since boot.
+    pub timer_value: U64<LE>,
+}
diff --git a/lib/tpm_commands/pinweaver/request.rs b/lib/tpm_commands/pinweaver/request.rs
new file mode 100644
index 0000000..ac6439c
--- /dev/null
+++ b/lib/tpm_commands/pinweaver/request.rs
@@ -0,0 +1,352 @@
+//! PinWeaver request-only types.
+
+use super::{
+    path_auxiliary_hash_count, response, DelaySchedule, Hash, Iv, Label, LeafHeader, LeafVersion,
+    Overflow, Secret, TreeParams, ValidPcrCriteria, WithUnimportedLeafData, PROTOCOL_VERSION,
+};
+use crate::{TpmvRequest, TpmvRequestBuild, NO_SESSION_TAG, VENDOR_COMMAND_ORDINAL};
+use zerocopy::{
+    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, BE, LE, U16, U32,
+};
+
+/// A PinWeaver request, after the TPM header.
+#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct Request<R: ?Sized> {
+    // Private since there is no need to access these fields after `init`.
+    header: RequestHeader,
+
+    /// The data specific to the request type.
+    pub data: R,
+}
+
+/// Trailing data specific to a particular kind of request.
+pub trait RequestData: FromZeros + KnownLayout + Immutable + IntoBytes + Unaligned {
+    /// Parameters to build an instance of this request.
+    type BuildParams;
+
+    /// The response data associated with this request.
+    ///
+    /// The response doesn't indicate the message type.
+    /// The full response is a `pinweaver::response::Response<Self::ResponseData>`.
+    type ResponseData: ?Sized + response::ResponseData<RequestData = Self>;
+
+    /// The type of message that should always be filled in this request.
+    const MESSAGE_TYPE: MessageType;
+
+    /// Initialize a zeroed `self` to an internally consistent state.
+    fn init(&mut self, _params: Self::BuildParams) -> Result<(), Overflow> {
+        Ok(())
+    }
+
+    /// The expected size of this part of the request.
+    fn expected_size(params: &Self::BuildParams) -> Result<u32, Overflow>;
+}
+
+impl<R: ?Sized + RequestData> TpmvRequest for Request<R> {
+    const TAG: U16<BE> = NO_SESSION_TAG;
+    const COMMAND_CODE: U16<BE> = U16::new(0x0025);
+    const ORDINAL: U32<BE> = VENDOR_COMMAND_ORDINAL;
+    type TpmvResponse = response::Response<R::ResponseData>;
+}
+
+impl<R: ?Sized + RequestData> TpmvRequestBuild for Request<R> {
+    type BuildParams = R::BuildParams;
+    type Err = Overflow;
+
+    fn init(&mut self, params: Self::BuildParams) -> Result<(), Overflow> {
+        self.header = RequestHeader {
+            data_size: size_of_val(&self.data).try_into().map_err(|_| Overflow)?,
+            version: PROTOCOL_VERSION,
+            message_type: R::MESSAGE_TYPE,
+        };
+        self.data.init(params)?;
+        Ok(())
+    }
+
+    fn expected_size(params: &Self::BuildParams) -> Result<u32, Overflow> {
+        (u32::try_from(size_of::<RequestHeader>()).unwrap())
+            .checked_add(R::expected_size(params)?)
+            .ok_or(Overflow)
+    }
+}
+
+/// Requests that end in a set of hashes along the path for a leaf.
+#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C, packed)] // The `packed` is required for DST IntoBytes at the moment.
+pub struct WithPathHashes<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned> {
+    header: Header,
+
+    /// Sibling hashes along the path, left-to-right, bottom-to-top.
+    pub path_hashes: [Hash],
+}
+
+impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned> WithPathHashes<Header> {
+    /// Gets a reference to the header.
+    ///
+    /// Taking a reference to a generic field gives an error because Rust doesn't
+    /// know about `Unaligned` making `repr(packed)` alignment errors impossible.
+    pub fn header(&self) -> &Header {
+        Header::ref_from_prefix(self.as_bytes()).unwrap().0
+    }
+
+    /// Gets a mutable reference to the header.
+    pub fn header_mut(&mut self) -> &mut Header {
+        Header::mut_from_prefix(self.as_mut_bytes()).unwrap().0
+    }
+}
+
+// Debug can't be derived with `repr(packed)`, which is needed for the current version of zerocopy.
+impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + std::fmt::Debug>
+    std::fmt::Debug for WithPathHashes<Header>
+{
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("WithPathHashes")
+            .field("header", self.header())
+            .field("path_hashes", &&self.path_hashes)
+            .finish()
+    }
+}
+
+/// Identifies the correct message type and response type from part of a request.
+pub trait RequestPart {
+    /// The type of message that should always be filled in this request.
+    const MESSAGE_TYPE: MessageType;
+
+    /// Response data associated with this request. Does not correspond to `ResponsePart`.
+    ///
+    /// Putting a `ResponseData` bound here puts the type checker in a loop.
+    type ResponseData: ?Sized;
+}
+
+impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + RequestPart> RequestData
+    for WithPathHashes<Header>
+where
+    Header::ResponseData: response::ResponseData<RequestData = Self>,
+{
+    type BuildParams = TreeParams;
+    type ResponseData = Header::ResponseData;
+    const MESSAGE_TYPE: MessageType = Header::MESSAGE_TYPE;
+
+    fn init(&mut self, _: TreeParams) -> Result<(), Overflow> {
+        // No header requires init.
+        Ok(())
+    }
+
+    fn expected_size(params: &TreeParams) -> Result<u32, Overflow> {
+        let tail_size = path_auxiliary_hash_count(params.bits_per_level, params.height)?
+            .checked_mul(size_of::<Hash>())
+            .ok_or(Overflow)?;
+        size_of::<Header>().checked_add(tail_size).ok_or(Overflow)?.try_into().map_err(|_| Overflow)
+    }
+}
+
+/// Parameters to build a new `UnimportedLeafData`.
+pub struct UnimportedLeafDataBuildParams {
+    /// The version of the leaf contents.
+    ///
+    /// Used by the GSC to process the message.
+    pub leaf_version: LeafVersion,
+
+    /// Length of the public data.
+    pub pub_len: u16,
+
+    /// Length of the ciphertext data.
+    pub sec_len: u16,
+
+    /// Parameters for the tree.
+    ///
+    /// Only used in requests.
+    pub tree_params: TreeParams,
+}
+
+impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + RequestPart> RequestData
+    for WithUnimportedLeafData<Header>
+where
+    Header::ResponseData: response::ResponseData<RequestData = Self>,
+{
+    type BuildParams = UnimportedLeafDataBuildParams;
+    type ResponseData = Header::ResponseData;
+    const MESSAGE_TYPE: MessageType = Header::MESSAGE_TYPE;
+
+    fn expected_size(params: &UnimportedLeafDataBuildParams) -> Result<u32, Overflow> {
+        let TreeParams { bits_per_level, height } = params.tree_params;
+        let path_hashes = path_auxiliary_hash_count(bits_per_level, height)?;
+        let static_len = const {
+            size_of::<Header>() + size_of::<LeafHeader>() + size_of::<Hash>() + size_of::<Iv>()
+        };
+        let pub_sec_len = usize::from(params.pub_len) + usize::from(params.sec_len);
+        let path_hashes_size = path_hashes.checked_mul(size_of::<Hash>()).ok_or(Overflow)?;
+        let dyn_len = pub_sec_len.checked_add(path_hashes_size).ok_or(Overflow)?;
+        let total_len = static_len.checked_add(dyn_len).ok_or(Overflow)?;
+        total_len.try_into().map_err(|_| Overflow)
+    }
+
+    fn init(&mut self, params: UnimportedLeafDataBuildParams) -> Result<(), Overflow> {
+        self.unimported_leaf_data.header = LeafHeader {
+            leaf_version: params.leaf_version,
+            pub_len: params.pub_len.into(),
+            sec_len: params.sec_len.into(),
+        };
+        Ok(())
+    }
+}
+
+/// Header for all PinWeaver requests.
+#[derive(Clone, Copy, Debug, FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct RequestHeader {
+    /// The protocol version for the request.
+    version: u8,
+
+    /// The type of contained message.
+    message_type: MessageType,
+
+    /// The size of the request in bytes.
+    ///
+    /// Does *not* include the size of this header.
+    data_size: U16<LE>,
+}
+
+/// The type of PinWeaver request - identifies what the rest of the message should contain.
+#[repr(u8)]
+#[derive(Clone, Copy, Debug, FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
+pub enum MessageType {
+    /// Invalid message type
+    Invalid = 0,
+
+    /// Reset a PinWeaver tree
+    ResetTree = 1,
+
+    /// Insert a leaf into the tree.
+    InsertLeaf = 2,
+
+    /// Remove a leaf from the tree.
+    RemoveLeaf = 3,
+
+    /// Try to authenticate a leaf against the tree.
+    TryAuth = 4,
+
+    /// Reset the authentication attempts for a leaf.
+    ResetAuth = 5,
+
+    /// Gets the replay log for data loss.
+    GetLog = 6,
+
+    /// Replays a specific operation based on the log to recover the tree.
+    LogReplay = 7,
+
+    /// Get info about the system.
+    SysInfo = 8,
+
+    // The following are vendor-specific commands for biometrics features.
+    /// Generate bioauthentication private key.
+    GenerateBaPk = 9,
+
+    /// Start biometric authentication.
+    StartBioAuth = 10,
+
+    /// Block future `GenerateBaPk` requests until next reset.
+    BlockGenerateBaPk = 11,
+}
+
+/// Requests that the tree be reset.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct ResetTree {
+    tree_params: TreeParams,
+}
+
+impl RequestData for ResetTree {
+    type BuildParams = ();
+    type ResponseData = response::ResetTree;
+    const MESSAGE_TYPE: MessageType = MessageType::ResetTree;
+
+    fn expected_size(_: &()) -> Result<u32, Overflow> {
+        Ok(size_of::<Self>().try_into().unwrap())
+    }
+}
+
+/// Requests a new leaf be inserted into the tree.
+pub type InsertLeaf = WithPathHashes<InsertLeafHeader>;
+
+/// Header for insert leaf request data.
+#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct InsertLeafHeader {
+    /// The label of the leaf to insert.
+    pub label: Label,
+
+    /// The delay schedule for the new leaf.
+    pub delay_schedule: DelaySchedule,
+
+    /// The low entropy secret protecting the new leaf.
+    pub low_entropy_secret: Secret,
+
+    /// The high entropy secret stored in the new leaf.
+    pub high_entropy_secret: Secret,
+
+    /// The secret that can reset authentication for a leaf.
+    pub reset_secret: Secret,
+
+    /// The Platform Configuration Register criteria used to validate a leaf.
+    pub valid_pcr_criteria: ValidPcrCriteria,
+}
+
+impl RequestPart for InsertLeafHeader {
+    const MESSAGE_TYPE: MessageType = MessageType::InsertLeaf;
+    type ResponseData = response::InsertLeaf;
+}
+
+/// Remove leaf request data.
+pub type RemoveLeaf = WithPathHashes<RemoveLeafHeader>;
+
+/// Header for remove leaf request data.
+#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct RemoveLeafHeader {
+    /// The label/path of the target leaf to remove.
+    pub leaf_location: Label,
+
+    /// The HMAC of the target leaf.
+    pub leaf_hmac: Hash,
+}
+
+impl RequestPart for RemoveLeafHeader {
+    const MESSAGE_TYPE: MessageType = MessageType::RemoveLeaf;
+    type ResponseData = response::RemoveLeaf;
+}
+
+/// Try auth request data.
+pub type TryAuth = WithUnimportedLeafData<TryAuthHeader>;
+
+/// Header for try auth request data.
+#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct TryAuthHeader {
+    /// The low entropy secret for PinWeaver to check against the encrypted leaf contents.
+    pub low_entropy_secret: Secret,
+}
+
+impl RequestPart for TryAuthHeader {
+    const MESSAGE_TYPE: MessageType = MessageType::TryAuth;
+    type ResponseData = response::TryAuth;
+}
+
+/// Request system info from PinWeaver.
+///
+/// This type selects the correct message.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct SysInfo;
+
+impl RequestData for SysInfo {
+    type BuildParams = ();
+    type ResponseData = response::SysInfo;
+
+    const MESSAGE_TYPE: MessageType = MessageType::SysInfo;
+
+    fn expected_size(_: &()) -> Result<u32, Overflow> {
+        Ok(size_of::<Self>().try_into().unwrap())
+    }
+}
diff --git a/lib/tpm_commands/pinweaver/response.rs b/lib/tpm_commands/pinweaver/response.rs
new file mode 100644
index 0000000..ec3899f
--- /dev/null
+++ b/lib/tpm_commands/pinweaver/response.rs
@@ -0,0 +1,362 @@
+//! PinWeaver response-only types.
+
+use super::{
+    request, Hash, Secret, TimeDiff, Timestamp, TreeParams, UnimportedLeafDataSizeError,
+    WithUnimportedLeafData, PROTOCOL_VERSION,
+};
+use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, LE, U16, U32};
+
+/// A PinWeaver response, after the TPM header.
+#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct Response<R: ?Sized> {
+    /// The header for the response.
+    ///
+    /// This field is private because it's invalid in the general case
+    /// to overwrite one whole `ResponseHeader` with another.
+    header: ResponseHeader,
+
+    /// The response-specific data.
+    pub data: R,
+}
+
+/// Returned when the response failed its consistency check.
+#[derive(Clone, Debug, thiserror::Error)]
+pub enum Error {
+    /// Protocol version error.
+    #[error("protocol version (got {0}, expected {PROTOCOL_VERSION})")]
+    ProtocolVersion(u8),
+
+    /// Total size of the response invalid.
+    #[error("total size invalid (header says {in_header}, parsed {received}) ")]
+    TotalSize {
+        /// The size indicated in the header.
+        in_header: u16,
+
+        /// The size parsed and stored in the object.
+        received: usize,
+    },
+
+    /// Leaf contains an invalid size header for the parsed message.
+    #[error(transparent)]
+    LeafDataSize(#[from] UnimportedLeafDataSizeError),
+
+    /// PinWeaver on the GSC returned an error.
+    #[error("operation failed: {0}")]
+    ResultCode(#[source] ResultCode),
+}
+
+impl<R: ?Sized + ResponseData> Response<R> {
+    /// Gets the header for the response.
+    pub fn header(&self) -> &ResponseHeader {
+        &self.header
+    }
+
+    /// Checks the validity of the response data.
+    ///
+    /// This checks, in this order:
+    ///
+    /// - The response header protocol version must match `PROTOCOL_VERSION`.
+    /// - The response code must be `Success`.
+    /// - The data sizes in the message must match the size of received data.
+    ///
+    /// Note that this does *not* check that a path hash length
+    /// matches what is expected for the current tree parameters.
+    pub fn check_consistency(&self, tree_params: &TreeParams) -> Result<(), Error> {
+        if self.header.version != PROTOCOL_VERSION {
+            return Err(Error::ProtocolVersion(self.header.version));
+        }
+        if !matches!(
+            self.header.result_code,
+            ResultCode::Success | ResultCode::SuccessWithIncrement
+        ) {
+            return Err(Error::ResultCode(self.header.result_code));
+        }
+        let header_data_size = self.header.data_size.get();
+        let received_data_size = size_of_val(&self.data);
+        if usize::from(header_data_size) != received_data_size {
+            return Err(Error::TotalSize {
+                in_header: header_data_size,
+                received: received_data_size,
+            });
+        }
+        self.data.check_consistency(tree_params)
+    }
+}
+
+/// Trailing data specific to a particular kind of response.
+pub trait ResponseData: FromZeros + KnownLayout + Immutable + IntoBytes + Unaligned {
+    /// Request data associated with this response.
+    type RequestData: ?Sized + request::RequestData<ResponseData = Self>;
+
+    /// Checks the validity of the message-type-specific data.
+    fn check_consistency(&self, _tree_params: &TreeParams) -> Result<(), Error> {
+        Ok(())
+    }
+}
+
+/// Identifies the correct corresponding request type from part of a response.
+pub trait ResponsePart {
+    /// Request data associated with this response. Does not correspond to `RequestPart`.
+    ///
+    /// Putting a `RequestData` bound here puts the type checker in a loop.
+    type RequestData: ?Sized;
+}
+
+impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + ResponsePart>
+    ResponseData for WithUnimportedLeafData<Header>
+where
+    Header::RequestData: request::RequestData<ResponseData = Self>,
+{
+    type RequestData = Header::RequestData;
+
+    /// Checks the validity of the message-type-specific data.
+    fn check_consistency(&self, _tree_params: &TreeParams) -> Result<(), Error> {
+        // Responses do not contain path hashes - `TreeParams` aren't used.
+        self.unimported_leaf_data.check_consistency(None)?;
+        Ok(())
+    }
+}
+
+/// Header for all PinWeaver responses.
+#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct ResponseHeader {
+    /// The protocol version for the response.
+    version: u8,
+
+    /// The size of the response in bytes.
+    ///
+    /// Does *not* include the size of this header.
+    data_size: U16<LE>,
+
+    /// The result of the operation.
+    pub result_code: ResultCode,
+
+    /// The current root hash of the tree.
+    pub root: Hash,
+}
+
+/// The response data from resetting a tree.
+///
+/// No extra data comes with the response.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct ResetTree;
+impl ResponseData for ResetTree {
+    type RequestData = request::ResetTree;
+}
+
+/// Insert leaf response data.
+pub type InsertLeaf = WithUnimportedLeafData<InsertLeafHeader>;
+
+/// The portion of insert leaf response data before the unimported leaf.
+///
+/// In other words, nothing - this just distinguishes from other responses.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct InsertLeafHeader;
+impl ResponsePart for InsertLeafHeader {
+    type RequestData = request::InsertLeaf;
+}
+
+/// The response data from removing a leaf.
+///
+/// No extra data comes with the response.
+#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct RemoveLeaf;
+impl ResponseData for RemoveLeaf {
+    type RequestData = request::RemoveLeaf;
+}
+
+/// Try auth response data.
+pub type TryAuth = WithUnimportedLeafData<TryAuthHeader>;
+
+/// The portion of try auth response data before the unimported leaf.
+///
+/// The unimported leaf is used for the `LowentAuthfailed` and `Success` return codes.
+// TODO: b/359374997 - confirm that unimported leaf data validation still works for other errors.
+pub struct TryAuthHeader {
+    /// Used for the `RateLimitReached` return code only.
+    pub seconds_to_wait: TimeDiff,
+
+    /// Used for the `Success` return code only.
+    pub high_entropy_secret: Secret,
+
+    /// Used for the `Success` return code only.
+    pub reset_secret: Secret,
+}
+
+impl ResponsePart for TryAuthHeader {
+    type RequestData = request::TryAuth;
+}
+
+/// Info about the PinWeaver system.
+#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
+#[repr(C)]
+pub struct SysInfo {
+    /// The current timestamp as recognized by PinWeaver.
+    pub current_timestamp: Timestamp,
+}
+
+impl ResponseData for SysInfo {
+    type RequestData = request::SysInfo;
+}
+
+/// A PinWeaver result code.
+// TODO: https://github.com/kupiakos/open-enum/issues/27 - use open_enum when it supports U32<LE>
+#[derive(
+    Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq, Unaligned,
+)]
+#[repr(transparent)]
+pub struct ResultCode(pub U32<LE>);
+
+#[allow(non_upper_case_globals)]
+impl ResultCode {
+    /// Success. Also see `SuccessWithIncrement`.
+    pub const Success: Self = Self(U32::new(0));
+
+    /// Unknown error.
+    pub const Unknown: Self = Self(U32::new(1));
+
+    /// Functionality unimplemented.
+    pub const Unimplemented: Self = Self(U32::new(2));
+
+    /// Version mismatch in request.
+    pub const VersionMismatch: Self = Self(U32::new(0x10000));
+
+    /// Invalid parameters for tree.
+    pub const TreeInvalid: Self = Self(U32::new(0x10001));
+
+    /// Request length is invalid.
+    pub const LengthInvalid: Self = Self(U32::new(0x10002));
+
+    /// Request type is invalid.
+    pub const TypeInvalid: Self = Self(U32::new(0x10003));
+
+    /// Tree bits per level invalid.
+    ///
+    /// Note: the implementation returns `TreeInvalid` instead of bits/height invalid.
+    pub const BitsPerLevelInvalid: Self = Self(U32::new(0x10004));
+
+    /// Tree height invalid.
+    pub const HeightInvalid: Self = Self(U32::new(0x10005));
+
+    /// Leaf label invalid for the tree.
+    pub const LabelInvalid: Self = Self(U32::new(0x10006));
+
+    /// Delay schedule is invalid.
+    pub const DelayScheduleInvalid: Self = Self(U32::new(0x10007));
+
+    /// Path authentication failed.
+    pub const PathAuthFailed: Self = Self(U32::new(0x10008));
+
+    /// Version mismatch in leaf.
+    pub const LeafVersionMismatch: Self = Self(U32::new(0x10009));
+
+    /// HMAC authentication failed.
+    pub const HmacAuthFailed: Self = Self(U32::new(0x1000a));
+
+    /// Low-entropy secret failed authentication.
+    pub const LowentAuthFailed: Self = Self(U32::new(0x1000b));
+
+    /// Resetting authentication failed.
+    pub const ResetAuthFailed: Self = Self(U32::new(0x1000c));
+
+    /// Failure in GSC crypto engine.
+    pub const CryptoFailure: Self = Self(U32::new(0x1000d));
+
+    /// Rate limit reached for leaf.
+    pub const RateLimitReached: Self = Self(U32::new(0x1000e));
+
+    /// Root hash not present in replay log.
+    pub const RootNotFound: Self = Self(U32::new(0x1000f));
+
+    /// Internal non-volatile empty.
+    pub const NvEmpty: Self = Self(U32::new(0x10010));
+
+    /// Length mismatch in internal non-volatile.
+    pub const NvLengthMismatch: Self = Self(U32::new(0x10011));
+
+    /// Version mismatch in internal non-volatile.
+    pub const NvVersionMismatch: Self = Self(U32::new(0x10012));
+
+    /// Auth failed due to mismatch in PCR values.
+    pub const PcrNotMatch: Self = Self(U32::new(0x10013));
+
+    /// Unknown internal failure.
+    pub const InternalFailure: Self = Self(U32::new(0x10014));
+
+    /// The leaf has expired.
+    pub const Expired: Self = Self(U32::new(0x10015));
+
+    /// The bio auth channel is invalid.
+    pub const BioAuthChannelInvalid: Self = Self(U32::new(0x10016));
+
+    /// Mismatch in public key version for bio auth.
+    pub const BioAuthPublicKeyVersionMismatch: Self = Self(U32::new(0x10017));
+
+    /// Access denied for bio auth.
+    pub const BioAuthAccessDenied: Self = Self(U32::new(0x10018));
+
+    /// Bio auth public key not established.
+    pub const BioAuthPkNotEstablished: Self = Self(U32::new(0x10019));
+
+    /// Success, but the attempt counter should be incremented.
+    ///
+    /// Log replay depends on the return code to decide whether the attempt
+    /// counter should be increased, but try_auth on a biometrics leaf should
+    /// always increase the counter. Therefore, use this special error code
+    /// when logging a try_auth event like this.
+    pub const SuccessWithIncrement: Self = Self(U32::new(0x1001a));
+
+    /// Bio auth public key already established.
+    pub const BioAuthPkAlreadyEstablished: Self = Self(U32::new(0x1001b));
+}
+
+impl ResultCode {
+    fn description(self) -> &'static str {
+        match self {
+            Self::Success => "success",
+            Self::Unimplemented => "functionality unimplemented",
+            Self::VersionMismatch => "version mismatch in request",
+            Self::TreeInvalid => "invalid parameters for tree",
+            Self::LengthInvalid => "request length is invalid",
+            Self::TypeInvalid => "request type is invalid",
+            Self::BitsPerLevelInvalid => "tree bits per level invalid",
+            Self::HeightInvalid => "tree height invalid",
+            Self::LabelInvalid => "leaf label invalid for the tree",
+            Self::DelayScheduleInvalid => "delay schedule is invalid",
+            Self::PathAuthFailed => "path authentication failed",
+            Self::LeafVersionMismatch => "version mismatch in leaf",
+            Self::HmacAuthFailed => "HMAC authentication failed",
+            Self::LowentAuthFailed => "low-entropy secret failed authentication",
+            Self::ResetAuthFailed => "resetting authentication failed",
+            Self::CryptoFailure => "failure in GSC crypto engine",
+            Self::RateLimitReached => "rate limit reached for leaf",
+            Self::RootNotFound => "root hash not present in replay log",
+            Self::NvEmpty => "internal non-volatile empty",
+            Self::NvLengthMismatch => "length mismatch in internal non-volatile",
+            Self::NvVersionMismatch => "version mismatch in internal non-volatile",
+            Self::PcrNotMatch => "auth failed due to mismatch in PCR values",
+            Self::InternalFailure => "unknown internal failure",
+            Self::Expired => "the leaf has expired",
+            Self::BioAuthChannelInvalid => "the bio auth channel is invalid",
+            Self::BioAuthPublicKeyVersionMismatch => "mismatch in public key version for bio auth",
+            Self::BioAuthAccessDenied => "access denied for bio auth",
+            Self::BioAuthPkNotEstablished => "bio auth public key not established",
+            Self::SuccessWithIncrement => "success, but the attempt counter should be incremented",
+            Self::BioAuthPkAlreadyEstablished => "bio auth public key already established",
+            _ => "unknown error",
+        }
+    }
+}
+
+impl std::fmt::Display for ResultCode {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "{}", self.description())
+    }
+}
+
+impl std::error::Error for ResultCode {}
diff --git a/lib/tpm_commands/rules.mk b/lib/tpm_commands/rules.mk
index 804f0be..06984cf 100644
--- a/lib/tpm_commands/rules.mk
+++ b/lib/tpm_commands/rules.mk
@@ -25,6 +25,9 @@ MODULE_SRCS += \
 MODULE_CRATE_NAME := tpm_commands
 
 MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,open-enum) \
+	$(call FIND_CRATE,paste) \
+	$(call FIND_CRATE,thiserror) \
 	$(call FIND_CRATE,zerocopy) \
 	trusty/user/base/lib/trusty-std \
 
```

