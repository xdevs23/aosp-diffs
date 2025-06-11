```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 9b96f36..138fd39 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -4,7 +4,4 @@ rustfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
-rustfmt = --config-path=rustfmt.toml
-
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
+rustfmt = --config-path=rustfmt.toml
\ No newline at end of file
diff --git a/README.md b/README.md
index bcf35b9..faaf16a 100644
--- a/README.md
+++ b/README.md
@@ -201,6 +201,10 @@ features or provisioned information, in the form of implementations of the vario
 
 ## Supporting Older Versions of the KeyMint HAL
 
-The reference implementation has the ability to behave like an earlier version of the KeyMint
-HAL. To enable emulation of (say) KeyMint v1, link the HAL service against the `libkmr_hal_v1` and
-`libkmr_wire_hal_v1` targets rather than `libkmr_hal` / `libkmr_wire`.
+The reference implementation has the ability to behave like an earlier version of the KeyMint HAL
+for testing. To enable emulation of (say) KeyMint v1, link the HAL service against the
+`libkmr_hal_v1` and `libkmr_wire_hal_v1` targets rather than `libkmr_hal` / `libkmr_wire`, and
+ensure that the `downgrade` feature for the TA code is enabled.
+
+The `downgrade` feature for the TA code (`kmr-ta` crate) should not be enabled for a production
+device.
diff --git a/boringssl/src/err.rs b/boringssl/src/err.rs
index 55683ee..57c29a4 100644
--- a/boringssl/src/err.rs
+++ b/boringssl/src/err.rs
@@ -23,7 +23,7 @@ use log::error;
 pub(crate) fn map_openssl_err(err: &openssl::error::Error) -> ErrorCode {
     let code = err.code();
     // Safety: no pointers involved.
-    let reason = unsafe { ffi::ERR_GET_REASON_RUST(code) };
+    let reason = unsafe { ffi::ERR_GET_REASON(code) };
 
     // Global error reasons.
     match reason {
diff --git a/common/generated.cddl b/common/generated.cddl
index 69f7fa9..01e42db 100644
--- a/common/generated.cddl
+++ b/common/generated.cddl
@@ -120,6 +120,7 @@ ErrorCode = &(
     ErrorCode_InvalidIssuerSubject: -83,
     ErrorCode_BootLevelExceeded: -84,
     ErrorCode_HardwareNotYetAvailable: -85,
+    ErrorCode_ModuleHashAlreadySet: -86,
     ErrorCode_Unimplemented: -100,
     ErrorCode_VersionMismatch: -101,
     ErrorCode_UnknownError: -1000,
@@ -234,6 +235,7 @@ Tag = &(
     Tag_CertificateNotBefore: 1610613744,
     Tag_CertificateNotAfter: 1610613745,
     Tag_MaxBootLevel: 805307378,
+    Tag_ModuleHash: -1879047468,
 )
 TagType = &(
     TagType_Invalid: 0,
@@ -373,6 +375,7 @@ KeyParam = &(
     [1610613744, DateTime], ; Tag_CertificateNotBefore
     [1610613745, DateTime], ; Tag_CertificateNotAfter
     [805307378, int], ; Tag_MaxBootLevel
+    [-1879047468, bstr], ; Tag_ModuleHash
 )
 KeyMintOperation = &(
     DeviceGetHardwareInfo: 0x11,
@@ -406,6 +409,7 @@ KeyMintOperation = &(
     SetBootInfo: 0x82,
     SetAttestationIds: 0x83,
     SetHalVersion: 0x84,
+    SetAdditionalAttestationInfo: 0x91,
 )
 GetHardwareInfoRequest = []
 GetHardwareInfoResponse = [
@@ -592,6 +596,7 @@ PerformOpReq = &(
     [SetBootInfo, SetBootInfoRequest],
     [SetAttestationIds, SetAttestationIdsRequest],
     [SetHalVersion, SetHalVersionRequest],
+    [SetAdditionalAttestationInfo, SetAdditionalAttestationInfoRequest],
 )
 PerformOpRsp = &(
     [DeviceGetHardwareInfo, GetHardwareInfoResponse],
@@ -625,6 +630,7 @@ PerformOpRsp = &(
     [SetBootInfo, SetBootInfoResponse],
     [SetAttestationIds, SetAttestationIdsResponse],
     [SetHalVersion, SetHalVersionResponse],
+    [SetAdditionalAttestationInfo, SetAdditionalAttestationInfoResponse],
 )
 PerformOpResponse = [
     error_code: int,
diff --git a/common/src/crypto.rs b/common/src/crypto.rs
index 17868c0..db4fdf4 100644
--- a/common/src/crypto.rs
+++ b/common/src/crypto.rs
@@ -504,7 +504,7 @@ impl<T: Hmac> Hkdf for T {
         out_len: usize,
     ) -> Result<Vec<u8>, Error> {
         let prk = &explicit!(prk)?.0;
-        let n = (out_len + SHA256_DIGEST_LEN - 1) / SHA256_DIGEST_LEN;
+        let n = out_len.div_ceil(SHA256_DIGEST_LEN);
         if n > 256 {
             return Err(km_err!(InvalidArgument, "overflow in hkdf"));
         }
@@ -538,7 +538,7 @@ impl<T: AesCmac> Ckdf for T {
         // Note: the variables i and l correspond to i and L in the standard.  See page 12 of
         // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf.
 
-        let blocks: u32 = ((out_len + aes::BLOCK_SIZE - 1) / aes::BLOCK_SIZE) as u32;
+        let blocks: u32 = out_len.div_ceil(aes::BLOCK_SIZE) as u32;
         let l = (out_len * 8) as u32; // in bits
         let net_order_l = l.to_be_bytes();
         let zero_byte: [u8; 1] = [0];
diff --git a/common/src/crypto/aes.rs b/common/src/crypto/aes.rs
index c98d22a..c8e36b1 100644
--- a/common/src/crypto/aes.rs
+++ b/common/src/crypto/aes.rs
@@ -39,6 +39,17 @@ pub enum Variant {
     Aes256,
 }
 
+impl Variant {
+    /// Size in bytes of the corresponding AES key.
+    pub fn key_size(&self) -> usize {
+        match self {
+            Self::Aes128 => 16,
+            Self::Aes192 => 24,
+            Self::Aes256 => 32,
+        }
+    }
+}
+
 /// An AES-128, AES-192 or AES-256 key.
 #[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
 pub enum Key {
diff --git a/common/src/crypto/traits.rs b/common/src/crypto/traits.rs
index bf20ac9..9c06373 100644
--- a/common/src/crypto/traits.rs
+++ b/common/src/crypto/traits.rs
@@ -456,6 +456,35 @@ pub trait Hkdf: Send {
         info: &[u8],
         out_len: usize,
     ) -> Result<Vec<u8>, Error>;
+
+    /// Perform combined HKDF using the input key material in `ikm`, emitting output in the form of
+    /// an AES key.
+    fn hkdf_aes(
+        &self,
+        salt: &[u8],
+        ikm: &[u8],
+        info: &[u8],
+        variant: aes::Variant,
+    ) -> Result<OpaqueOr<aes::Key>, Error> {
+        // Default implementation generates explicit key material and converts to an [`aes::Key`].
+        let data = self.hkdf(salt, ikm, info, variant.key_size())?;
+        let explicit_key = aes::Key::new(data)?;
+        Ok(explicit_key.into())
+    }
+
+    /// Perform the HKDF-Expand step using the pseudo-random key in `prk`, emitting output in the
+    /// form of an AES key.
+    fn expand_aes(
+        &self,
+        prk: &OpaqueOr<hmac::Key>,
+        info: &[u8],
+        variant: aes::Variant,
+    ) -> Result<OpaqueOr<aes::Key>, Error> {
+        // Default implementation generates explicit key material and converts to an [`aes::Key`].
+        let data = self.expand(prk, info, variant.key_size())?;
+        let explicit_key = aes::Key::new(data)?;
+        Ok(explicit_key.into())
+    }
 }
 
 /// Abstraction of CKDF key derivation with AES-CMAC KDF from NIST SP 800-108 in counter mode (see
diff --git a/common/src/keyblob.rs b/common/src/keyblob.rs
index 9375512..2ee4ace 100644
--- a/common/src/keyblob.rs
+++ b/common/src/keyblob.rs
@@ -15,7 +15,8 @@
 //! Key blob manipulation functionality.
 
 use crate::{
-    contains_tag_value, crypto, km_err, tag, try_to_vec, vec_try, Error, FallibleAllocExt,
+    contains_tag_value, crypto, crypto::aes, km_err, tag, try_to_vec, vec_try, Error,
+    FallibleAllocExt,
 };
 use alloc::{
     format,
@@ -295,18 +296,20 @@ pub fn derive_kek(
     characteristics: Vec<KeyCharacteristics>,
     hidden: Vec<KeyParam>,
     sdd: Option<SecureDeletionData>,
-) -> Result<crypto::aes::Key, Error> {
+) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
     let mut info = try_to_vec(key_derivation_input)?;
     info.try_extend_from_slice(&characteristics.into_vec()?)?;
     info.try_extend_from_slice(&hidden.into_vec()?)?;
     if let Some(sdd) = sdd {
         info.try_extend_from_slice(&sdd.into_vec()?)?;
     }
-    let data = match root_key {
-        crypto::OpaqueOr::Explicit(key_material) => kdf.hkdf(&[], &key_material.0, &info, 32)?,
-        key @ crypto::OpaqueOr::Opaque(_) => kdf.expand(key, &info, 32)?,
-    };
-    Ok(crypto::aes::Key::Aes256(data.try_into().unwrap(/* safe: len checked */)))
+
+    match root_key {
+        crypto::OpaqueOr::Explicit(key_material) => {
+            kdf.hkdf_aes(&[], &key_material.0, &info, aes::Variant::Aes256)
+        }
+        key @ crypto::OpaqueOr::Opaque(_) => kdf.expand_aes(key, &info, aes::Variant::Aes256),
+    }
 }
 
 /// Plaintext key blob.
@@ -392,7 +395,7 @@ pub fn encrypt(
             &[],
             move |pt, aad| {
                 let mut op = aes.begin_aead(
-                    kek.into(),
+                    kek,
                     crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
                     crypto::SymmetricOperation::Encrypt,
                 )?;
@@ -455,7 +458,7 @@ pub fn decrypt(
     );
 
     let mut op = aes.begin_aead(
-        kek.into(),
+        kek,
         crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
         crypto::SymmetricOperation::Decrypt,
     )?;
diff --git a/common/src/keyblob/keyblob.cddl b/common/src/keyblob/keyblob.cddl
index 7ae5915..1e1ea6f 100644
--- a/common/src/keyblob/keyblob.cddl
+++ b/common/src/keyblob/keyblob.cddl
@@ -133,6 +133,7 @@ KeyParam = &(
     [1610613744, DateTime], ; Tag_CertificateNotBefore
     [1610613745, DateTime], ; Tag_CertificateNotAfter
     [805307378, int], ; Tag_MaxBootLevel
+    [-1879047468, bstr], ; Tag_ModuleHash
 )
 Tag = &(
     Tag_Invalid: 0,
@@ -201,6 +202,7 @@ Tag = &(
     Tag_CertificateNotBefore: 1610613744,
     Tag_CertificateNotAfter: 1610613745,
     Tag_MaxBootLevel: 805307378,
+    Tag_ModuleHash: -1879047468,
 )
 Algorithm = &(
     Algorithm_Rsa: 1,
diff --git a/ta/Cargo.toml b/ta/Cargo.toml
index 8b65a77..a05ccf9 100644
--- a/ta/Cargo.toml
+++ b/ta/Cargo.toml
@@ -8,6 +8,12 @@ authors = ["David Drysdale <drysdale@google.com>"]
 edition = "2021"
 license = "Apache-2.0"
 
+[features]
+default = []
+# The `downgrade` feature allows the HAL service to tell the TA what version of the KeyMint
+# HAL to implement.
+downgrade = []
+
 [dependencies]
 ciborium = { version = "^0.2.0", default-features = false }
 ciborium-io = "^0.2.0"
diff --git a/ta/src/cert.rs b/ta/src/cert.rs
index 9ce4a7c..97b15b3 100644
--- a/ta/src/cert.rs
+++ b/ta/src/cert.rs
@@ -275,7 +275,7 @@ pub struct AttestationExtension<'a> {
     hw_enforced: AuthorizationList<'a>,
 }
 
-impl<'a> AssociatedOid for AttestationExtension<'a> {
+impl AssociatedOid for AttestationExtension<'_> {
     const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
 }
 
@@ -1080,7 +1080,7 @@ fn asn1_len<T: Encode>(val: Option<ExplicitTaggedValue<T>>) -> der::Result<Lengt
 
 impl<'a> Sequence<'a> for AuthorizationList<'a> {}
 
-impl<'a> EncodeValue for AuthorizationList<'a> {
+impl EncodeValue for AuthorizationList<'_> {
     fn value_len(&self) -> der::Result<Length> {
         let mut length = asn1_len(asn1_set_of_integer!(self.auths, Purpose))?
             + asn1_len(asn1_integer!(self.auths, Algorithm))?
diff --git a/ta/src/lib.rs b/ta/src/lib.rs
index 95bdf09..a0efe49 100644
--- a/ta/src/lib.rs
+++ b/ta/src/lib.rs
@@ -14,6 +14,7 @@
 
 //! KeyMint trusted application (TA) implementation.
 
+#![allow(clippy::empty_line_after_doc_comments)]
 #![no_std]
 extern crate alloc;
 
@@ -42,7 +43,7 @@ use kmr_wire::{
     sharedsecret::SharedSecretParameters,
     *,
 };
-use log::{error, info, trace, warn};
+use log::{debug, error, info, trace, warn};
 
 mod cert;
 mod clock;
@@ -612,14 +613,25 @@ impl KeyMintTa {
 
     /// Configure the version of the HAL that this TA should act as.
     pub fn set_hal_version(&mut self, aidl_version: u32) -> Result<(), Error> {
-        self.aidl_version = match aidl_version {
+        let aidl_version = match aidl_version {
             100 => KeyMintHalVersion::V1,
             200 => KeyMintHalVersion::V2,
             300 => KeyMintHalVersion::V3,
             400 => KeyMintHalVersion::V4,
             _ => return Err(km_err!(InvalidArgument, "unsupported HAL version {}", aidl_version)),
         };
-        info!("Set aidl_version to {:?}", self.aidl_version);
+        if aidl_version == self.aidl_version {
+            debug!("Set aidl_version to existing version {aidl_version:?}");
+        } else if cfg!(feature = "downgrade") {
+            info!("Change aidl_version from {:?} to {:?}", self.aidl_version, aidl_version);
+            self.aidl_version = aidl_version;
+        } else {
+            // Only allow HAL-triggered downgrade if the "downgrade" feature is enabled.
+            warn!(
+                "Ignoring request to change aidl_version from {:?} to {:?}",
+                self.aidl_version, aidl_version
+            );
+        }
         Ok(())
     }
 
```

