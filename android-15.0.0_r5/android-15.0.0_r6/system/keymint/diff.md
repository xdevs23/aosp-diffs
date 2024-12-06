```diff
diff --git a/README.md b/README.md
index 5149887..013a503 100644
--- a/README.md
+++ b/README.md
@@ -144,6 +144,20 @@ and send a `kmr_wire::SetBootInfoRequest` message to do this.
 - [ ] Implementation of communication channel from bootloader to TA.
 - [ ] Trigger for and population of `kmr_wire::SetBootInfoRequest` message.
 
+### Authenticators
+
+KeyMint supports auth-bound keys that can only be used when an appropriate hardware authentication
+token (HAT) is presented. Secure authenticators such as Gatekeeper or Fingerprint produce these
+HATs, and validation of them requires that:
+
+- [ ] KeyMint and the authenticators share a common monotonic time source.
+- [ ] The authenticators have access to the (per-boot) HMAC signing key, via one of:
+   - [ ] The authenticator retrieves the HMAC key from KeyMint via a communication mechanism that is
+         completely internal to the secure environment, using `KeyMintTa::get_hmac_key`, or
+   - [ ] The authenticator also implements the `ISharedSecret` HAL, and joins in the HMAC key
+         derivation process.  This requires that the authenticator have access to the pre-shared key
+         that is used as the basis of the derivation process.
+
 ### Cryptographic Abstractions
 
 The KeyMint TA requires implementations for low-level cryptographic primitives to be provided, in
@@ -171,7 +185,7 @@ BoringSSL-based implementations are available for all of the above (except for s
 
 The KeyMint TA requires implementations of traits that involve interaction with device-specific
 features or provisioned information, in the form of implementations of the various Rust traits held
-in [`kmr_hal::device`](hal/src/device.rs).
+in [`kmr_ta::device`](ta/src/device.rs).
 
 **Checklist:**
 
@@ -179,7 +193,7 @@ in [`kmr_hal::device`](hal/src/device.rs).
 - [ ] Attestation key / chain retrieval implementation (optional).
 - [ ] Attestation device ID retrieval implementation.
 - [ ] Retrieval of BCC and DICE artefacts.
-- [ ] Secure storage implementation (optional).
+- [ ] Secure secret storage (for rollback-resistant keys) implementation (optional).
 - [ ] Bootloader status retrieval (optional)
 - [ ] Storage key wrapping integration (optional).
 - [ ] Trusted user presence indication (optional).
diff --git a/boringssl/src/aes.rs b/boringssl/src/aes.rs
index 94874cb..5aaf7d6 100644
--- a/boringssl/src/aes.rs
+++ b/boringssl/src/aes.rs
@@ -129,7 +129,7 @@ impl crypto::Aes for BoringAes {
     }
 }
 
-/// [`crypto::AesOperation`] implementation based on BoringSSL.
+/// AES operation based on BoringSSL.
 pub struct BoringAesOperation {
     crypter: openssl::symm::Crypter,
 }
@@ -153,7 +153,7 @@ impl crypto::EmittingOperation for BoringAesOperation {
     }
 }
 
-/// [`crypto::AesGcmEncryptOperation`] implementation based on BoringSSL.
+/// AES-GCM encrypt operation based on BoringSSL.
 pub struct BoringAesGcmEncryptOperation {
     mode: crypto::aes::GcmMode,
     inner: BoringAesOperation,
@@ -187,7 +187,7 @@ impl crypto::EmittingOperation for BoringAesGcmEncryptOperation {
     }
 }
 
-/// [`crypto::AesGcmDecryptOperation`] implementation based on BoringSSL.
+/// AES-GCM decrypt operation based on BoringSSL.
 pub struct BoringAesGcmDecryptOperation {
     crypter: openssl::symm::Crypter,
 
diff --git a/boringssl/src/aes_cmac.rs b/boringssl/src/aes_cmac.rs
index 7c87b70..1f5503a 100644
--- a/boringssl/src/aes_cmac.rs
+++ b/boringssl/src/aes_cmac.rs
@@ -67,7 +67,7 @@ impl crypto::AesCmac for BoringAesCmac {
     }
 }
 
-/// [`crypto::AesCmacOperation`] implementation based on BoringSSL.
+/// AES-CMAC implementation based on BoringSSL.
 ///
 /// This implementation uses the `unsafe` wrappers around `CMAC_*` functions directly, because
 /// BoringSSL does not support the `EVP_PKEY_CMAC` implementations that are used in the rust-openssl
diff --git a/boringssl/src/des.rs b/boringssl/src/des.rs
index d0c49ac..9fbfc39 100644
--- a/boringssl/src/des.rs
+++ b/boringssl/src/des.rs
@@ -65,7 +65,7 @@ impl crypto::Des for BoringDes {
     }
 }
 
-/// [`crypto::DesOperation`] implementation based on BoringSSL.
+/// DES operation based on BoringSSL.
 pub struct BoringDesOperation {
     crypter: openssl::symm::Crypter,
 }
diff --git a/boringssl/src/ec.rs b/boringssl/src/ec.rs
index caf0bf7..ddecdd1 100644
--- a/boringssl/src/ec.rs
+++ b/boringssl/src/ec.rs
@@ -185,7 +185,7 @@ impl crypto::Ec for BoringEc {
     }
 }
 
-/// [`crypto::EcAgreeOperation`] based on BoringSSL.
+/// ECDH operation based on BoringSSL.
 pub struct BoringEcAgreeOperation {
     key: Key,
     pending_input: Vec<u8>, // Limited to `max_size` below.
@@ -261,7 +261,7 @@ impl crypto::AccumulatingOperation for BoringEcAgreeOperation {
     }
 }
 
-/// [`crypto::EcSignOperation`] based on BoringSSL, when an external digest is used.
+/// ECDSA signing operation based on BoringSSL, when an external digest is used.
 pub struct BoringEcDigestSignOperation {
     // Safety: `pkey` internally holds a pointer to BoringSSL-allocated data (`EVP_PKEY`),
     // as do both of the raw pointers.  This means that this item stays valid under moves,
@@ -349,7 +349,7 @@ impl crypto::AccumulatingOperation for BoringEcDigestSignOperation {
     }
 }
 
-/// [`crypto::EcSignOperation`] based on BoringSSL, when data is undigested.
+/// ECDSA signing operation based on BoringSSL, when data is undigested.
 pub struct BoringEcUndigestSignOperation {
     ec_key: openssl::ec::EcKey<openssl::pkey::Private>,
     pending_input: Vec<u8>,
@@ -386,7 +386,7 @@ impl crypto::AccumulatingOperation for BoringEcUndigestSignOperation {
     }
 }
 
-/// [`crypto::EcSignOperation`] based on BoringSSL for Ed25519.
+/// EdDSA signing operation based on BoringSSL for Ed25519.
 pub struct BoringEd25519SignOperation {
     pkey: openssl::pkey::PKey<openssl::pkey::Private>,
     pending_input: Vec<u8>,
diff --git a/boringssl/src/hmac.rs b/boringssl/src/hmac.rs
index c935e84..dcce39b 100644
--- a/boringssl/src/hmac.rs
+++ b/boringssl/src/hmac.rs
@@ -67,7 +67,7 @@ impl crypto::Hmac for BoringHmac {
     }
 }
 
-/// [`crypto::HmacOperation`] implementation based on BoringSSL.
+/// HMAC operation based on BoringSSL.
 ///
 /// This implementation uses the `unsafe` wrappers around `HMAC_*` functions directly, because
 /// BoringSSL does not support the `EVP_PKEY_HMAC` implementations that are used in the rust-openssl
diff --git a/boringssl/src/rsa.rs b/boringssl/src/rsa.rs
index 411e8a0..ebbd6d9 100644
--- a/boringssl/src/rsa.rs
+++ b/boringssl/src/rsa.rs
@@ -119,7 +119,7 @@ impl crypto::Rsa for BoringRsa {
     }
 }
 
-/// [`crypto::RsaDecryptOperation`] based on BoringSSL.
+/// RSA decryption operation based on BoringSSL.
 pub struct BoringRsaDecryptOperation {
     key: crypto::rsa::Key,
     mode: DecryptionMode,
@@ -182,7 +182,7 @@ impl crypto::AccumulatingOperation for BoringRsaDecryptOperation {
     }
 }
 
-/// [`crypto::RsaSignOperation`] based on BoringSSL, for when an external digest is used.
+/// RSA signing operation based on BoringSSL, for when an external digest is used.
 /// Directly uses FFI functions because [`openssl::sign::Signer`] requires a lifetime.
 pub struct BoringRsaDigestSignOperation {
     // Safety: `pkey` internally holds a pointer to BoringSSL-allocated data (`EVP_PKEY`),
@@ -286,7 +286,7 @@ impl crypto::AccumulatingOperation for BoringRsaDigestSignOperation {
     }
 }
 
-/// [`crypto::RsaSignOperation`] based on BoringSSL, for undigested data.
+/// RSA signing operation based on BoringSSL, for undigested data.
 pub struct BoringRsaUndigestSignOperation {
     rsa_key: openssl::rsa::Rsa<openssl::pkey::Private>,
     left_pad: bool,
diff --git a/common/src/crypto/rsa.rs b/common/src/crypto/rsa.rs
index ab682dc..5cc3ffb 100644
--- a/common/src/crypto/rsa.rs
+++ b/common/src/crypto/rsa.rs
@@ -130,7 +130,8 @@ impl OpaqueOr<Key> {
         buf.try_extend_from_slice(&pub_key)?;
         Ok(SubjectPublicKeyInfo {
             algorithm: AlgorithmIdentifier { oid: X509_OID, parameters: Some(der::AnyRef::NULL) },
-            subject_public_key: BitStringRef::from_bytes(buf).unwrap(),
+            subject_public_key: BitStringRef::from_bytes(buf)
+                .map_err(|e| km_err!(UnknownError, "invalid bitstring: {e:?}"))?,
         })
     }
 }
diff --git a/common/src/crypto/traits.rs b/common/src/crypto/traits.rs
index cc7f0b9..bf20ac9 100644
--- a/common/src/crypto/traits.rs
+++ b/common/src/crypto/traits.rs
@@ -137,7 +137,7 @@ pub trait Aes: Send {
 
     /// Create an AES operation.  For block mode operations with no padding
     /// ([`aes::CipherMode::EcbNoPadding`] and [`aes::CipherMode::CbcNoPadding`]) the operation
-    /// implementation should reject (with [`ErrorCode::InvalidInputLength`]) input data that does
+    /// implementation should reject (with `ErrorCode::InvalidInputLength`) input data that does
     /// not end up being a multiple of the block size.
     fn begin(
         &self,
@@ -179,7 +179,7 @@ pub trait Des: Send {
 
     /// Create a DES operation.  For block mode operations with no padding
     /// ([`des::Mode::EcbNoPadding`] and [`des::Mode::CbcNoPadding`]) the operation implementation
-    /// should reject (with [`ErrorCode::InvalidInputLength`]) input data that does not end up being
+    /// should reject (with `ErrorCode::InvalidInputLength`) input data that does not end up being
     /// a multiple of the block size.
     fn begin(
         &self,
@@ -283,7 +283,7 @@ pub trait Rsa: Send {
     ) -> Result<Box<dyn AccumulatingOperation>, Error>;
 
     /// Create an RSA signing operation.  For [`rsa::SignMode::Pkcs1_1_5Padding(Digest::None)`] the
-    /// implementation should reject (with [`ErrorCode::InvalidInputLength`]) accumulated input that
+    /// implementation should reject (with `ErrorCode::InvalidInputLength`) accumulated input that
     /// is larger than the size of the RSA key less overhead
     /// ([`rsa::PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD`]).
     fn begin_sign(
@@ -396,7 +396,7 @@ pub trait Ec: Send {
     fn begin_agree(&self, key: OpaqueOr<ec::Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;
 
     /// Create an EC signing operation.  For Ed25519 signing operations, the implementation should
-    /// reject (with [`ErrorCode::InvalidInputLength`]) accumulated data that is larger than
+    /// reject (with `ErrorCode::InvalidInputLength`) accumulated data that is larger than
     /// [`ec::MAX_ED25519_MSG_SIZE`].
     fn begin_sign(
         &self,
@@ -582,7 +582,7 @@ impl Hmac for NoOpHmac {
     }
 }
 
-/// Stub implementation of [`Cmac`].
+/// Stub implementation of [`AesCmac`].
 pub struct NoOpAesCmac;
 impl AesCmac for NoOpAesCmac {
     fn begin(&self, _key: OpaqueOr<aes::Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
diff --git a/common/src/keyblob.rs b/common/src/keyblob.rs
index a0ce457..9375512 100644
--- a/common/src/keyblob.rs
+++ b/common/src/keyblob.rs
@@ -235,6 +235,7 @@ pub trait SecureDeletionSecretManager {
 /// RAII class to hold a secure deletion slot.  The slot is deleted when the holder is dropped.
 struct SlotHolder<'a> {
     mgr: &'a mut dyn SecureDeletionSecretManager,
+    // Invariant: `slot` is non-`None` except on destruction.
     slot: Option<SecureDeletionSlot>,
 }
 
@@ -261,7 +262,7 @@ impl<'a> SlotHolder<'a> {
 
     /// Acquire ownership of the secure deletion slot.
     fn consume(mut self) -> SecureDeletionSlot {
-        self.slot.take().unwrap()
+        self.slot.take().unwrap() // Safe: `is_some()` invariant
     }
 }
 
diff --git a/common/src/keyblob/sdd_mem.rs b/common/src/keyblob/sdd_mem.rs
index 3d6e2f8..0c3cbea 100644
--- a/common/src/keyblob/sdd_mem.rs
+++ b/common/src/keyblob/sdd_mem.rs
@@ -13,6 +13,8 @@
 // limitations under the License.
 
 //! In-memory secure deletion secret manager.
+//!
+//! Only suitable for development/testing (as secrets are lost on restart).
 
 use super::{SecureDeletionData, SecureDeletionSecretManager, SecureDeletionSlot, SlotPurpose};
 use crate::{crypto, km_err, Error};
@@ -99,16 +101,3 @@ impl<const N: usize> SecureDeletionSecretManager for InMemorySlotManager<N> {
         }
     }
 }
-
-#[derive(Default)]
-struct FakeRng(u8);
-
-impl crate::crypto::Rng for FakeRng {
-    fn add_entropy(&mut self, _data: &[u8]) {}
-    fn fill_bytes(&mut self, dest: &mut [u8]) {
-        for b in dest {
-            *b = self.0;
-            self.0 += 1;
-        }
-    }
-}
diff --git a/hal/src/keymint.rs b/hal/src/keymint.rs
index 461b1a1..34415c7 100644
--- a/hal/src/keymint.rs
+++ b/hal/src/keymint.rs
@@ -381,10 +381,9 @@ impl<T: SerializedChannel + 'static> keymint::IKeyMintOperation::IKeyMintOperati
             let batch_len = core::cmp::min(Self::MAX_DATA_SIZE, input.len());
             req.input = input[..batch_len].to_vec();
             input = &input[batch_len..];
-            let _rsp: UpdateAadResponse = self.execute(req).map_err(|e| {
+            let _rsp: UpdateAadResponse = self.execute(req).inspect_err(|_| {
                 // Any failure invalidates the operation
                 self.invalidate();
-                e
             })?;
         }
         Ok(())
@@ -410,9 +409,8 @@ impl<T: SerializedChannel + 'static> keymint::IKeyMintOperation::IKeyMintOperati
             let batch_len = core::cmp::min(Self::MAX_DATA_SIZE, input.len());
             req.input = input[..batch_len].to_vec();
             input = &input[batch_len..];
-            let rsp: UpdateResponse = self.execute(req).map_err(|e| {
+            let rsp: UpdateResponse = self.execute(req).inspect_err(|_| {
                 self.invalidate();
-                e
             })?;
             output.extend_from_slice(&rsp.ret);
         }
@@ -445,9 +443,8 @@ impl<T: SerializedChannel + 'static> keymint::IKeyMintOperation::IKeyMintOperati
                     timestamp_token: timestamp_token.clone(),
                 };
                 input = &input[MAX_DATA_SIZE..];
-                let rsp: UpdateResponse = self.execute(req).map_err(|e| {
+                let rsp: UpdateResponse = self.execute(req).inspect_err(|_| {
                     self.invalidate();
-                    e
                 })?;
                 output.extend_from_slice(&rsp.ret);
             }
diff --git a/ta/src/device.rs b/ta/src/device.rs
index 5c1c199..d25aa3d 100644
--- a/ta/src/device.rs
+++ b/ta/src/device.rs
@@ -72,7 +72,7 @@ pub trait RetrieveKeyMaterial {
     /// in any opaque context.
     fn root_kek(&self, context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error>;
 
-    /// Retrieve any opaque (but non-confidential) context needed for future calls to [`root_kek`].
+    /// Retrieve any opaque (but non-confidential) context needed for future calls to `root_kek`.
     /// Context should not include confidential data (it will be stored in the clear).
     fn kek_context(&self) -> Result<Vec<u8>, Error> {
         // Default implementation is to have an empty KEK retrieval context.
@@ -209,9 +209,9 @@ pub trait RetrieveRpcArtifacts {
     fn get_dice_info(&self, test_mode: rpc::TestMode) -> Result<DiceInfo, Error>;
 
     /// Sign the input data with the CDI leaf private key of the IRPC HAL implementation. In IRPC V2,
-    /// the `data` to be signed is the [`SignedMac_structure`] in ProtectedData.aidl, when signing
+    /// the `data` to be signed is the `SignedMac_structure` in ProtectedData.aidl, when signing
     /// the ephemeral MAC key used to authenticate the public keys. In IRPC V3, the `data` to be
-    /// signed is the [`SignedDataSigStruct`].
+    /// signed is the `SignedDataSigStruct`.
     /// If a particular implementation would like to return the signature in a COSE_Sign1 message,
     /// they can mark this unimplemented and override the default implementation in the
     /// `sign_data_in_cose_sign1` method below.
@@ -221,6 +221,7 @@ pub trait RetrieveRpcArtifacts {
     /// - NIST signatures are encoded as (r||s), with each value left-padded with zeroes to
     ///   the coordinate length.  Note that this is a *different* format than is emitted by
     ///   the `kmr_common::crypto::Ec` trait.
+    ///
     /// (The `kmr_common::crypto::ec::to_cose_signature()` function can help with this.)
     fn sign_data(
         &self,
@@ -287,12 +288,12 @@ pub enum CsrSigningAlgorithm {
 /// Public DICE artifacts.
 #[derive(Clone, Debug)]
 pub struct PubDiceArtifacts {
-    /// Certificates for the UDS Pub encoded in CBOR as per [`AdditionalDKSignatures`] structure in
-    /// ProtectedData.aidl for IRPC HAL version 2 and as per [`UdsCerts`] structure in IRPC HAL
+    /// Certificates for the UDS Pub encoded in CBOR as per `AdditionalDKSignatures` structure in
+    /// ProtectedData.aidl for IRPC HAL version 2 and as per `UdsCerts` structure in IRPC HAL
     /// version 3.
     pub uds_certs: Vec<u8>,
-    /// UDS Pub and the DICE certificates encoded in CBOR/COSE as per the [`Bcc`] structure
-    /// defined in ProtectedData.aidl for IRPC HAL version 2 and as per [`DiceCertChain`] structure
+    /// UDS Pub and the DICE certificates encoded in CBOR/COSE as per the `Bcc` structure
+    /// defined in ProtectedData.aidl for IRPC HAL version 2 and as per `DiceCertChain` structure
     /// in IRPC HAL version 3.
     pub dice_cert_chain: Vec<u8>,
 }
diff --git a/ta/src/lib.rs b/ta/src/lib.rs
index 44e144a..07e5db6 100644
--- a/ta/src/lib.rs
+++ b/ta/src/lib.rs
@@ -543,6 +543,10 @@ impl KeyMintTa {
     pub fn set_boot_info(&mut self, boot_info: keymint::BootInfo) -> Result<(), Error> {
         if !self.in_early_boot {
             error!("Rejecting attempt to set boot info {:?} after early boot", boot_info);
+            return Err(km_err!(
+                EarlyBootEnded,
+                "attempt to set boot info to {boot_info:?} after early boot"
+            ));
         }
         if let Some(existing_boot_info) = &self.boot_info {
             if *existing_boot_info == boot_info {
@@ -552,7 +556,7 @@ impl KeyMintTa {
                 );
             } else {
                 return Err(km_err!(
-                    InvalidArgument,
+                    RootOfTrustAlreadySet,
                     "attempt to set boot info to {:?} but already set to {:?}",
                     boot_info,
                     existing_boot_info
diff --git a/ta/src/rkp.rs b/ta/src/rkp.rs
index 9286e62..9f151a4 100644
--- a/ta/src/rkp.rs
+++ b/ta/src/rkp.rs
@@ -58,6 +58,15 @@ const RPC_P256_KEYGEN_PARAMS: [KeyParam; 8] = [
 const MAX_CHALLENGE_SIZE_V2: usize = 64;
 
 impl KeyMintTa {
+    /// Return the UDS certs for the device, encoded in CBOR as per `AdditionalDKSignatures`
+    /// structure in ProtectedData.aidl for IRPC HAL version 2 and as per `UdsCerts` structure in
+    /// IRPC HAL version 3.
+    pub fn uds_certs(&self) -> Result<Vec<u8>, Error> {
+        let dice_info =
+            self.get_dice_info().ok_or_else(|| rpc_err!(Failed, "DICE info not available."))?;
+        try_to_vec(&dice_info.pub_dice_artifacts.uds_certs)
+    }
+
     /// Return the CBOR-encoded `DeviceInfo`.
     pub fn rpc_device_info(&self) -> Result<Vec<u8>, Error> {
         let info = self.rpc_device_info_cbor()?;
diff --git a/wire/src/legacy.rs b/wire/src/legacy.rs
index 1e894ad..695ab2f 100644
--- a/wire/src/legacy.rs
+++ b/wire/src/legacy.rs
@@ -25,24 +25,24 @@
 //! sort of envelope that identifies the message type.
 //!
 //! 1) For Trusty, this envelope is the `keymaster_message` struct from
-//! `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`; this struct holds
-//! (and is serialized as):
+//!    `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`; this struct holds
+//!    (and is serialized as):
 //!
-//! - A u32 indicating which command is involved, together with two low bits to encode whether the
-//!   message is a response, and a stop bit.  The command code values are taken from
-//!   `keymaster_command` in
-//!   `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`.
-//! - The payload.
+//!    - A u32 indicating which command is involved, together with two low bits to encode whether the
+//!      message is a response, and a stop bit.  The command code values are taken from
+//!      `keymaster_command` in
+//!      `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`.
+//!    - The payload.
 //!
 //! 2) For Cuttlefish, this envelope is the `keymaster_message` struct from
-//! `device/google/cuttlefish/common/libs/security/keymaster_channel.h`; this struct holds (and is
-//! serialized as):
+//!    `device/google/cuttlefish/common/libs/security/keymaster_channel.h`; this struct holds (and is
+//!    serialized as):
 //!
-//! - A u32 indicating which command is involved, together with a bit indicating if the message is a
-//!   response.  The command code values are taken from `AndroidKeymasterCommand` in
-//!   `system/keymaster/include/keymaster/android_keymaster_messages.h`.
-//! - A u32 indicating the size of the payload
-//! - The payload.
+//!    - A u32 indicating which command is involved, together with a bit indicating if the message is a
+//!      response.  The command code values are taken from `AndroidKeymasterCommand` in
+//!      `system/keymaster/include/keymaster/android_keymaster_messages.h`.
+//!    - A u32 indicating the size of the payload
+//!    - The payload.
 //!
 //! In addition to the common messages defined in `android_keymaster_messages.h`, Trusty includes
 //! additional messages defined in `app/keymaster/trusty_keymaster_messages.h`.
@@ -178,6 +178,13 @@ impl<T: TrustySerialize> LegacyResult<T> {
     }
 }
 
+/// Serialize a Trusty response message in the form:
+/// - command code: 32-bit integer (native endian)
+/// - return code: 32-bit integer (native endian)
+/// - encoded response data (if return code is 0/Ok).
+///
+/// Note that some legacy response messages (e.g. [`GetDeviceInfoResponse`],
+/// [`GetAuthTokenKeyResponse`]) do not use this encoding format.
 fn serialize_trusty_response_message<T: TrustySerialize>(
     result: LegacyResult<T>,
 ) -> Result<Vec<u8>, Error> {
@@ -235,6 +242,9 @@ pub fn serialize_trusty_secure_rsp(rsp: TrustyPerformSecureOpRsp) -> Result<Vec<
             // and library are updated.
             serialize_trusty_raw_rsp(rsp.raw_code(), device_ids)
         }
+        TrustyPerformSecureOpRsp::GetUdsCerts(GetUdsCertsResponse { uds_certs: _ }) => {
+            serialize_trusty_response_message(LegacyResult::Ok(rsp))
+        }
         TrustyPerformSecureOpRsp::SetAttestationIds(_) => {
             serialize_trusty_response_message(LegacyResult::Ok(rsp))
         }
@@ -428,8 +438,8 @@ pub struct ConfigureVerifiedBootInfoResponse {}
 #[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
 pub struct SetAttestationIdsRequest {
     pub brand: Vec<u8>,
-    pub product: Vec<u8>,
     pub device: Vec<u8>,
+    pub product: Vec<u8>,
     pub serial: Vec<u8>,
     pub imei: Vec<u8>,
     pub meid: Vec<u8>,
@@ -492,6 +502,13 @@ impl InnerSerialize for GetDeviceInfoResponse {
     }
 }
 
+#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
+pub struct GetUdsCertsRequest {}
+#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
+pub struct GetUdsCertsResponse {
+    pub uds_certs: Vec<u8>,
+}
+
 #[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
 pub struct SetBootParamsRequest {
     pub os_version: u32,
@@ -537,6 +554,19 @@ pub struct SetWrappedAttestationKeyRequest {
 #[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
 pub struct SetWrappedAttestationKeyResponse {}
 
+#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
+pub struct AppendUdsCertificateRequest {
+    pub cert_data: Vec<u8>,
+}
+#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
+pub struct AppendUdsCertificateResponse {}
+
+#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
+pub struct ClearUdsCertificateRequest {}
+
+#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
+pub struct ClearUdsCertificateResponse {}
+
 macro_rules! declare_req_rsp_enums {
     {
         $cenum:ident => ($reqenum:ident, $rspenum:ident)
@@ -604,6 +634,9 @@ macro_rules! declare_req_rsp_enums {
 // - an enum value with an explicit numeric value
 // - a request enum which has an operation code associated to each variant
 // - a response enum which has the same operation code associated to each variant.
+//
+// Numerical values for discriminants match the values in
+// system/keymaster/include/keymaster/android_keymaster_messages.h
 declare_req_rsp_enums! { CuttlefishKeymasterOperation => (CuttlefishPerformOpReq, CuttlefishPerformOpRsp) {
     ConfigureBootPatchlevel = 33 =>                      (ConfigureBootPatchlevelRequest, ConfigureBootPatchlevelResponse),
     ConfigureVerifiedBootInfo = 34 =>                    (ConfigureVerifiedBootInfoRequest, ConfigureVerifiedBootInfoResponse),
@@ -611,6 +644,9 @@ declare_req_rsp_enums! { CuttlefishKeymasterOperation => (CuttlefishPerformOpReq
 } }
 
 // Possible legacy Trusty Keymaster operation requests for the non-secure port.
+//
+// Numerical values for discriminants match the values in
+// trusty/user/app/keymaster/ipc/keymaster_ipc.h.
 declare_req_rsp_enums! { TrustyKeymasterOperation => (TrustyPerformOpReq, TrustyPerformOpRsp) {
     GetVersion = 7 =>                                (GetVersionRequest, GetVersionResponse),
     GetVersion2 = 28 =>                              (GetVersion2Request, GetVersion2Response),
@@ -623,14 +659,19 @@ declare_req_rsp_enums! { TrustyKeymasterOperation => (TrustyPerformOpReq, Trusty
     SetWrappedAttestationKey = 0xb000 =>             (SetWrappedAttestationKeyRequest, SetWrappedAttestationKeyResponse),
     SetAttestationIds = 0xc000 =>                    (SetAttestationIdsRequest, SetAttestationIdsResponse),
     SetAttestationIdsKM3 = 0xc001 =>                 (SetAttestationIdsKM3Request, SetAttestationIdsKM3Response),
-
     ConfigureBootPatchlevel = 0xd0000 =>             (ConfigureBootPatchlevelRequest, ConfigureBootPatchlevelResponse),
+    AppendUdsCertificate = 0xe0000 =>                (AppendUdsCertificateRequest, AppendUdsCertificateResponse),
+    ClearUdsCertificate = 0xe0001 =>                 (ClearUdsCertificateRequest, ClearUdsCertificateResponse),
 } }
 
 // Possible legacy Trusty Keymaster operation requests for the secure port.
+//
+// Numerical values for discriminants match the values in
+// trusty/user/base/interface/keymaster/include/interface/keymaster/keymaster.h
 declare_req_rsp_enums! { TrustyKeymasterSecureOperation  => (TrustyPerformSecureOpReq, TrustyPerformSecureOpRsp) {
     GetAuthTokenKey = 0 =>                                  (GetAuthTokenKeyRequest, GetAuthTokenKeyResponse),
     GetDeviceInfo = 1 =>                                    (GetDeviceInfoRequest, GetDeviceInfoResponse),
+    GetUdsCerts = 2 =>                                      (GetUdsCertsRequest, GetUdsCertsResponse),
     SetAttestationIds = 0xc000 =>                           (SetAttestationIdsRequest, SetAttestationIdsResponse),
 } }
 
@@ -661,6 +702,8 @@ pub fn is_trusty_provisioning_code(code: u32) -> bool {
             | Some(TrustyKeymasterOperation::SetWrappedAttestationKey)
             | Some(TrustyKeymasterOperation::SetAttestationIds)
             | Some(TrustyKeymasterOperation::SetAttestationIdsKM3)
+            | Some(TrustyKeymasterOperation::AppendUdsCertificate)
+            | Some(TrustyKeymasterOperation::ClearUdsCertificate)
     )
 }
 
@@ -674,6 +717,8 @@ pub fn is_trusty_provisioning_req(req: &TrustyPerformOpReq) -> bool {
             | TrustyPerformOpReq::SetWrappedAttestationKey(_)
             | TrustyPerformOpReq::SetAttestationIds(_)
             | TrustyPerformOpReq::SetAttestationIdsKM3(_)
+            | TrustyPerformOpReq::AppendUdsCertificate(_)
+            | TrustyPerformOpReq::ClearUdsCertificate(_)
     )
 }
 
@@ -754,4 +799,21 @@ mod tests {
         let got_data = serialize_trusty_secure_rsp(msg).unwrap();
         assert_eq!(hex::encode(got_data), data);
     }
+    #[test]
+    fn test_get_uds_certs_rsp_serialize() {
+        let msg =
+            TrustyPerformSecureOpRsp::GetUdsCerts(GetUdsCertsResponse { uds_certs: vec![1, 2, 3] });
+        #[cfg(target_endian = "little")]
+        let data = concat!(
+            /* cmd */ "0b000000", /* rc */ "00000000", /* len */ "03000000",
+            /* data */ "010203"
+        );
+        #[cfg(target_endian = "big")]
+        let data = concat!(
+            /* cmd */ "0000000b", /* rc */ "00000000", /* len */ "00000003",
+            /* data */ "010203"
+        );
+        let got_data = serialize_trusty_secure_rsp(msg).unwrap();
+        assert_eq!(hex::encode(got_data), data);
+    }
 }
```

