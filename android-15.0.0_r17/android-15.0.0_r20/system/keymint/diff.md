```diff
diff --git a/Android.bp b/Android.bp
index a56493a..3c8134d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -28,3 +28,9 @@ license {
 }
 
 subdirs = ["*"]
+
+dirgroup {
+    name: "trusty_dirgroup_system_keymint",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/OWNERS b/OWNERS
index 85f036a..872c5b4 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,4 @@
+cvlasov@google.com
 drysdale@google.com
 hasinitg@google.com
+kwadhera@google.com
diff --git a/README.md b/README.md
index 013a503..bcf35b9 100644
--- a/README.md
+++ b/README.md
@@ -169,35 +169,35 @@ an external implementation is not required (but can be provided if desired).
 
 **Checklist:**
 
-- [ ] RNG implementation.
-- [ ] Constant time comparison implementation.
-- [ ] AES implementation.
-- [ ] 3-DES implementation.
-- [ ] HMAC implementation.
-- [ ] RSA implementation.
-- [ ] EC implementation (including curve 25519 support).
-- [ ] AES-CMAC or CKDF implementation.
-- [ ] Secure time implementation.
-
-BoringSSL-based implementations are available for all of the above (except for secure time).
+- [ ] RNG implementation: `Rng`.
+- [ ] Constant time comparison implementation: `ConstTimeEq`.
+- [ ] AES implementation: `Aes`.
+- [ ] 3-DES implementation: `Des`.
+- [ ] HMAC implementation: `Hmac`.
+- [ ] RSA implementation: `Rsa`.
+- [ ] EC implementation, including curve 25519 support: `Ec`.
+- [ ] AES-CMAC or CKDF implementation: `AesCmac`, `Ckdf`.
+
+BoringSSL-based implementations are available for all of the above.
 
 ### Device Abstractions
 
 The KeyMint TA requires implementations of traits that involve interaction with device-specific
 features or provisioned information, in the form of implementations of the various Rust traits held
-in [`kmr_ta::device`](ta/src/device.rs).
+(mostly) in [`kmr_ta::device`](ta/src/device.rs).
 
 **Checklist:**
 
-- [ ] Root key retrieval implementation.
-- [ ] Attestation key / chain retrieval implementation (optional).
-- [ ] Attestation device ID retrieval implementation.
-- [ ] Retrieval of BCC and DICE artefacts.
-- [ ] Secure secret storage (for rollback-resistant keys) implementation (optional).
-- [ ] Bootloader status retrieval (optional)
-- [ ] Storage key wrapping integration (optional).
-- [ ] Trusted user presence indication (optional).
-- [ ] Legacy keyblob format converter (optional).
+- [ ] Secure time implementation (monotonic, shared with authenticators): `kmr_common::crypto::MonotonicClock`.
+- [ ] Root key(s) retrieval implementation: `RetrieveKeyMaterial`.
+- [ ] Attestation key / chain retrieval implementation (optional): `RetrieveCertSigningInfo`.
+- [ ] Attestation device ID retrieval implementation: `RetrieveAttestationIds`.
+- [ ] Retrieval of BCC and DICE artefacts: `RetrieveRpcArtefacts`.
+- [ ] Secure secret storage (for rollback-resistant keys) implementation (optional): `SecureDeletionSecretManager`.
+- [ ] Bootloader status retrieval (optional): `BootloaderStatus`.
+- [ ] Storage key wrapping integration (optional): `StorageKeyWrapper`.
+- [ ] Trusted user presence indication (optional): `TrustedUserPresence`.
+- [ ] Legacy keyblob format converter (optional): `LegacyKeyHandler`.
 
 ## Supporting Older Versions of the KeyMint HAL
 
diff --git a/boringssl/Cargo.toml b/boringssl/Cargo.toml
index c56aba4..2598dfd 100644
--- a/boringssl/Cargo.toml
+++ b/boringssl/Cargo.toml
@@ -19,3 +19,6 @@ openssl = "^0.10.36"
 
 [dev-dependencies]
 kmr-tests = "*"
+
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(soong)'] }
\ No newline at end of file
diff --git a/boringssl/src/types.rs b/boringssl/src/types.rs
index 9250717..f07c0cf 100644
--- a/boringssl/src/types.rs
+++ b/boringssl/src/types.rs
@@ -13,10 +13,12 @@
 // limitations under the License.
 
 //! Rust types definitions for BoringSSL objects.
+#[cfg(soong)]
 use bssl_sys as ffi;
 
 /// New type for `*mut ffi::CMAC_CTX` to implement `Send` for it. This allow us to still check if a
 /// `!Send` item is added to `BoringAesCmacOperation`
+#[allow(dead_code)]
 pub(crate) struct CmacCtx(pub(crate) *mut ffi::CMAC_CTX);
 
 // Safety: Checked CMAC_CTX allocation, initialization and destruction code to insure that it is
diff --git a/common/src/tag/info.rs b/common/src/tag/info.rs
index 71d83d9..ad5405d 100644
--- a/common/src/tag/info.rs
+++ b/common/src/tag/info.rs
@@ -207,7 +207,7 @@ pub struct Info {
 /// Global "map" of tags to information about their behaviour.
 /// Encoded as an array to avoid allocation; lookup should only be slightly slower
 /// for this few entries.
-const INFO: [(Tag, Info); 60] = [
+const INFO: [(Tag, Info); 61] = [
     (
         Tag::Purpose,
         Info {
@@ -1130,6 +1130,24 @@ const INFO: [(Tag, Info); 60] = [
             bit_index: 59,
         },
     ),
+    (
+        Tag::ModuleHash,
+        Info {
+            name: "MODULE_HASH",
+            tt: TagType::Bytes,
+            ext_asn1_type: Some("OCTET STRING"),
+            user_can_specify: UserSpecifiable(false),
+            // The module hash is neither a key characteristic nor an operation parameter.
+            // The tag exists only to reserve a numeric value that can be used in the
+            // attestation extension record.
+            characteristic: Characteristic::NotKeyCharacteristic,
+            op_param: OperationParam::NotOperationParam,
+            keymint_auto_adds: AutoAddedCharacteristic(false),
+            lifetime: ValueLifetime::FixedAtStartup,
+            cert_gen: CertGenParam::NotRequired,
+            bit_index: 60,
+        },
+    ),
 ];
 
 /// Return behaviour information about the specified tag.
diff --git a/common/src/tag/legacy.rs b/common/src/tag/legacy.rs
index cda2919..62cff32 100644
--- a/common/src/tag/legacy.rs
+++ b/common/src/tag/legacy.rs
@@ -148,7 +148,8 @@ pub fn serialize(params: &[KeyParam]) -> Result<Vec<u8>, Error> {
             | KeyParam::Nonce(v)
             | KeyParam::RootOfTrust(v)
             | KeyParam::CertificateSerial(v)
-            | KeyParam::CertificateSubject(v) => {
+            | KeyParam::CertificateSubject(v)
+            | KeyParam::ModuleHash(v) => {
                 result.try_extend_from_slice(v)?;
                 blob_size += v.len() as u32;
             }
@@ -240,7 +241,8 @@ pub fn serialize(params: &[KeyParam]) -> Result<Vec<u8>, Error> {
             | KeyParam::Nonce(v)
             | KeyParam::RootOfTrust(v)
             | KeyParam::CertificateSerial(v)
-            | KeyParam::CertificateSubject(v) => {
+            | KeyParam::CertificateSubject(v)
+            | KeyParam::ModuleHash(v) => {
                 let blob_len = v.len() as u32;
                 result.try_extend_from_slice(&blob_len.to_ne_bytes())?;
                 result.try_extend_from_slice(&blob_offset.to_ne_bytes())?;
@@ -502,6 +504,9 @@ pub fn deserialize(data: &mut &[u8]) -> Result<Vec<KeyParam>, Error> {
             Tag::CertificateSubject => {
                 KeyParam::CertificateSubject(consume_blob(data, &mut next_blob_offset, blob_data)?)
             }
+            Tag::ModuleHash => {
+                KeyParam::ModuleHash(consume_blob(data, &mut next_blob_offset, blob_data)?)
+            }
             // Invalid variants.
             Tag::Invalid
             | Tag::HardwareType
@@ -589,6 +594,7 @@ pub fn param_compare(left: &KeyParam, right: &KeyParam) -> Ordering {
         (KeyParam::CertificateNotBefore(l), KeyParam::CertificateNotBefore(r)) => l.cmp(r),
         (KeyParam::CertificateNotAfter(l), KeyParam::CertificateNotAfter(r)) => l.cmp(r),
         (KeyParam::MaxBootLevel(l), KeyParam::MaxBootLevel(r)) => l.cmp(r),
+        (KeyParam::ModuleHash(l), KeyParam::ModuleHash(r)) => l.cmp(r),
 
         (left, right) => left.tag().cmp(&right.tag()),
     }
diff --git a/hal/Android.bp b/hal/Android.bp
index 8afa340..69145a6 100644
--- a/hal/Android.bp
+++ b/hal/Android.bp
@@ -46,6 +46,7 @@ rust_library {
     features: [
         "hal_v2",
         "hal_v3",
+        "hal_v4",
     ],
     defaults: [
         "keymint_use_latest_hal_aidl_rust",
@@ -56,6 +57,24 @@ rust_library {
     ],
 }
 
+rust_library {
+    name: "libkmr_hal_v3",
+    crate_name: "kmr_hal",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    features: [
+        "hal_v3",
+        "hal_v2",
+    ],
+    defaults: [
+        "kmr_hal_defaults",
+    ],
+    rustlibs: [
+        "android.hardware.security.keymint-V3-rust",
+        "libkmr_wire_hal_v3",
+    ],
+}
+
 rust_library {
     name: "libkmr_hal_v2",
     crate_name: "kmr_hal",
@@ -94,6 +113,7 @@ rust_test {
     features: [
         "hal_v2",
         "hal_v3",
+        "hal_v4",
     ],
     defaults: [
         "keymint_use_latest_hal_aidl_rust",
diff --git a/hal/src/hal.rs b/hal/src/hal.rs
index 3ddb5eb..e9f216d 100644
--- a/hal/src/hal.rs
+++ b/hal/src/hal.rs
@@ -400,6 +400,8 @@ impl Fromm<wire::keymint::KeyParam> for keymint::KeyParameter::KeyParameter {
             KeyParam::CertificateSubject(v) => {
                 (Tag::CERTIFICATE_SUBJECT, KeyParameterValue::Blob(v))
             }
+            #[cfg(feature = "hal_v4")]
+            KeyParam::ModuleHash(v) => (Tag::MODULE_HASH, KeyParameterValue::Blob(v)),
         };
         Self { tag, value }
     }
@@ -713,6 +715,8 @@ impl TryFromm<&keymint::KeyParameter::KeyParameter> for Option<KeyParam> {
             keymint::Tag::Tag::CERTIFICATE_SUBJECT => {
                 Some(KeyParam::CertificateSubject(clone_blob!(val)?))
             }
+            #[cfg(feature = "hal_v4")]
+            keymint::Tag::Tag::MODULE_HASH => Some(KeyParam::ModuleHash(clone_blob!(val)?)),
 
             // Unsupported variants
             keymint::Tag::Tag::UNIQUE_ID
diff --git a/hal/src/keymint.rs b/hal/src/keymint.rs
index 34415c7..7fe8518 100644
--- a/hal/src/keymint.rs
+++ b/hal/src/keymint.rs
@@ -281,6 +281,21 @@ impl<T: SerializedChannel> keymint::IKeyMintDevice::IKeyMintDevice for Device<T>
             self.execute(SendRootOfTrustRequest { root_of_trust: root_of_trust.to_vec() })?;
         Ok(())
     }
+    #[cfg(feature = "hal_v4")]
+    fn setAdditionalAttestationInfo(
+        &self,
+        info: &[keymint::KeyParameter::KeyParameter],
+    ) -> binder::Result<()> {
+        let _rsp: SetAdditionalAttestationInfoResponse =
+            self.execute(SetAdditionalAttestationInfoRequest {
+                info: info
+                    .iter()
+                    .filter_map(|p| p.try_innto().transpose())
+                    .collect::<Result<Vec<KeyParam>, _>>()
+                    .map_err(failed_conversion)?,
+            })?;
+        Ok(())
+    }
 }
 
 /// Representation of an in-progress KeyMint operation on a `SerializedChannel`.
diff --git a/hal/src/lib.rs b/hal/src/lib.rs
index 30b3fb1..ff777bd 100644
--- a/hal/src/lib.rs
+++ b/hal/src/lib.rs
@@ -269,7 +269,9 @@ pub fn send_hal_info<T: SerializedChannel>(channel: &mut T) -> binder::Result<()
     info!("HAL->TA: environment info is {:?}", req);
     let _rsp: kmr_wire::SetHalInfoResponse = channel_execute(channel, req)?;
 
-    let aidl_version = if cfg!(feature = "hal_v3") {
+    let aidl_version = if cfg!(feature = "hal_v4") {
+        400
+    } else if cfg!(feature = "hal_v3") {
         300
     } else if cfg!(feature = "hal_v2") {
         200
diff --git a/ta/src/cert.rs b/ta/src/cert.rs
index 2feba9f..9ce4a7c 100644
--- a/ta/src/cert.rs
+++ b/ta/src/cert.rs
@@ -52,7 +52,8 @@ use x509_cert::{
 pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
 
-/// Empty book key value to use in attestations.
+/// Empty value to use in the `RootOfTrust.verifiedBootKey` field in attestations
+/// if an empty value was passed to the bootloader.
 const EMPTY_BOOT_KEY: [u8; 32] = [0u8; 32];
 
 /// Build an ASN.1 DER-encodable `Certificate`.
@@ -250,14 +251,14 @@ pub(crate) fn basic_constraints_ext_value(ca_required: bool) -> BasicConstraints
 ///
 /// ```asn1
 /// KeyDescription ::= SEQUENCE {
-///     attestationVersion         INTEGER, # Value 300
-///     attestationSecurityLevel   SecurityLevel, # See below
-///     keyMintVersion             INTEGER, # Value 300
-///     keymintSecurityLevel       SecurityLevel, # See below
-///     attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
-///     uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
-///     softwareEnforced           AuthorizationList, # See below
-///     hardwareEnforced           AuthorizationList, # See below
+///     attestationVersion         INTEGER,
+///     attestationSecurityLevel   SecurityLevel,
+///     keyMintVersion             INTEGER,
+///     keymintSecurityLevel       SecurityLevel,
+///     attestationChallenge       OCTET_STRING,
+///     uniqueId                   OCTET_STRING,
+///     softwareEnforced           AuthorizationList,
+///     hardwareEnforced           AuthorizationList,
 /// }
 /// ```
 #[derive(Debug, Clone, Sequence, PartialEq)]
@@ -306,6 +307,7 @@ pub(crate) fn attestation_extension<'a>(
     chars: &'a [KeyCharacteristics],
     unique_id: &'a Vec<u8>,
     boot_info: &'a keymint::BootInfo,
+    additional_attestation_info: &'a [KeyParam],
 ) -> Result<AttestationExtension<'a>, Error> {
     let mut sw_chars: &[KeyParam] = &[];
     let mut hw_chars: &[KeyParam] = &[];
@@ -328,14 +330,21 @@ pub(crate) fn attestation_extension<'a>(
         keymint::SecurityLevel::Software => (params, &[]),
         _ => (&[], params),
     };
-    let sw_enforced =
-        AuthorizationList::new(sw_chars, sw_params, attestation_ids, None, Some(app_id))?;
+    let sw_enforced = AuthorizationList::new(
+        sw_chars,
+        sw_params,
+        attestation_ids,
+        None,
+        Some(app_id),
+        additional_attestation_info,
+    )?;
     let hw_enforced = AuthorizationList::new(
         hw_chars,
         hw_params,
         attestation_ids,
         Some(RootOfTrust::from(boot_info)),
         None,
+        &[],
     )?;
     let sec_level = SecurityLevel::try_from(security_level as u32)
         .map_err(|_| km_err!(InvalidArgument, "invalid security level {:?}", security_level))?;
@@ -352,18 +361,18 @@ pub(crate) fn attestation_extension<'a>(
     Ok(ext)
 }
 
-/// Struct for creating ASN.1 DER-serialized `AuthorizationList`. The fields in the ASN1
+/// Struct for creating ASN.1 DER-serialized `AuthorizationList`. The fields in the ASN.1
 /// sequence are categorized into four fields in the struct based on their usage.
 /// ```asn1
 /// AuthorizationList ::= SEQUENCE {
 ///     purpose                    [1] EXPLICIT SET OF INTEGER OPTIONAL,
 ///     algorithm                  [2] EXPLICIT INTEGER OPTIONAL,
 ///     keySize                    [3] EXPLICIT INTEGER OPTIONAL,
-///     blockMode                  [4] EXPLICIT SET OF INTEGER OPTIONAL, -- symmetric only
+///     blockMode                  [4] EXPLICIT SET OF INTEGER OPTIONAL,  -- Symmetric keys only
 ///     digest                     [5] EXPLICIT SET OF INTEGER OPTIONAL,
 ///     padding                    [6] EXPLICIT SET OF INTEGER OPTIONAL,
-///     callerNonce                [7] EXPLICIT NULL OPTIONAL, -- symmetric only
-///     minMacLength               [8] EXPLICIT INTEGER OPTIONAL, -- symmetric only
+///     callerNonce                [7] EXPLICIT NULL OPTIONAL,  -- Symmetric keys only
+///     minMacLength               [8] EXPLICIT INTEGER OPTIONAL,  -- Symmetric keys only
 ///     ecCurve                    [10] EXPLICIT INTEGER OPTIONAL,
 ///     rsaPublicExponent          [200] EXPLICIT INTEGER OPTIONAL,
 ///     mgfDigest                  [203] EXPLICIT SET OF INTEGER OPTIONAL,
@@ -373,7 +382,7 @@ pub(crate) fn attestation_extension<'a>(
 ///     originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
 ///     usageExpireDateTime        [402] EXPLICIT INTEGER OPTIONAL,
 ///     usageCountLimit            [405] EXPLICIT INTEGER OPTIONAL,
-///     userSecureId               [502] EXPLICIT INTEGER OPTIONAL, -- only used on import
+///     userSecureId               [502] EXPLICIT INTEGER OPTIONAL,  -- Only used on key import
 ///     noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
 ///     userAuthType               [504] EXPLICIT INTEGER OPTIONAL,
 ///     authTimeout                [505] EXPLICIT INTEGER OPTIONAL,
@@ -399,6 +408,8 @@ pub(crate) fn attestation_extension<'a>(
 ///     bootPatchLevel             [719] EXPLICIT INTEGER OPTIONAL,
 ///     deviceUniqueAttestation    [720] EXPLICIT NULL OPTIONAL,
 ///     attestationIdSecondImei    [723] EXPLICIT OCTET_STRING OPTIONAL,
+///     -- moduleHash contains a SHA-256 hash of DER-encoded `Modules`
+///     moduleHash                 [724] EXPLICIT OCTET_STRING OPTIONAL,
 /// }
 /// ```
 #[derive(Debug, Clone, PartialEq, Eq)]
@@ -407,6 +418,7 @@ pub struct AuthorizationList<'a> {
     pub keygen_params: Cow<'a, [KeyParam]>,
     pub rot_info: Option<KeyParam>,
     pub app_id: Option<KeyParam>,
+    pub additional_attestation_info: Cow<'a, [KeyParam]>,
 }
 
 /// Macro to check that a specified attestation ID matches the provisioned value.
@@ -439,6 +451,7 @@ impl<'a> AuthorizationList<'a> {
         attestation_ids: Option<&'a crate::AttestationIdInfo>,
         rot_info: Option<RootOfTrust<'a>>,
         app_id: Option<&'a [u8]>,
+        additional_attestation_info: &'a [KeyParam],
     ) -> Result<Self, Error> {
         check_attestation_id!(keygen_params, AttestationIdBrand, attestation_ids.map(|v| &v.brand));
         check_attestation_id!(
@@ -483,6 +496,7 @@ impl<'a> AuthorizationList<'a> {
                 Some(app_id) => Some(KeyParam::AttestationApplicationId(try_to_vec(app_id)?)),
                 None => None,
             },
+            additional_attestation_info: additional_attestation_info.into(),
         })
     }
 
@@ -499,6 +513,7 @@ impl<'a> AuthorizationList<'a> {
         let mut keygen_params = Vec::new();
         let mut rot: Option<KeyParam> = None;
         let mut attest_app_id: Option<KeyParam> = None;
+        let mut additional_attestation_info = Vec::new();
 
         // Divide key parameters into key characteristics and key generation parameters.
         for param in key_params {
@@ -516,6 +531,9 @@ impl<'a> AuthorizationList<'a> {
                 | KeyParam::AttestationIdModel(_) => {
                     keygen_params.try_push(param).map_err(der_alloc_err)?
                 }
+                KeyParam::ModuleHash(_) => {
+                    additional_attestation_info.try_push(param).map_err(der_alloc_err)?
+                }
                 _ => auths.try_push(param).map_err(der_alloc_err)?,
             }
         }
@@ -524,6 +542,7 @@ impl<'a> AuthorizationList<'a> {
             keygen_params: keygen_params.into(),
             rot_info: rot,
             app_id: attest_app_id,
+            additional_attestation_info: additional_attestation_info.into(),
         })
     }
 }
@@ -598,6 +617,7 @@ impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
                 keygen_params: Vec::new().into(),
                 rot_info: None,
                 app_id: None,
+                additional_attestation_info: Vec::new().into(),
             });
         }
         if decoder.remaining_len() < header.length {
@@ -656,7 +676,8 @@ impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
                 VendorPatchlevel,
                 BootPatchlevel,
                 DeviceUniqueAttestation,
-                AttestationIdSecondImei
+                AttestationIdSecondImei,
+                ModuleHash
             )
         );
 
@@ -875,6 +896,9 @@ fn decode_value_from_bytes(
         Tag::DeviceUniqueAttestation => {
             key_param_from_asn1_null!(DeviceUniqueAttestation, tlv_bytes, key_params);
         }
+        Tag::ModuleHash => {
+            key_param_from_asn1_octet_string!(ModuleHash, tlv_bytes, key_params);
+        }
         _ => {
             // Note: `der::Error` or `der::ErrorKind` is not expressive enough for decoding
             // tags in high tag form. Documentation of this error kind does not match this
@@ -1115,7 +1139,8 @@ impl<'a> EncodeValue for AuthorizationList<'a> {
             + asn1_len(asn1_integer!(self.auths, VendorPatchlevel))?
             + asn1_len(asn1_integer!(self.auths, BootPatchlevel))?
             + asn1_len(asn1_null!(self.auths, DeviceUniqueAttestation))?
-            + asn1_len(asn1_octet_string!(&self.keygen_params, AttestationIdSecondImei))?;
+            + asn1_len(asn1_octet_string!(&self.keygen_params, AttestationIdSecondImei))?
+            + asn1_len(asn1_octet_string!(&self.additional_attestation_info, ModuleHash))?;
         length
     }
 
@@ -1179,7 +1204,7 @@ impl<'a> EncodeValue for AuthorizationList<'a> {
         asn1_val(asn1_integer!(self.auths, BootPatchlevel), writer)?;
         asn1_val(asn1_null!(self.auths, DeviceUniqueAttestation), writer)?;
         asn1_val(asn1_octet_string!(&self.keygen_params, AttestationIdSecondImei), writer)?;
-
+        asn1_val(asn1_octet_string!(&self.additional_attestation_info, ModuleHash), writer)?;
         Ok(())
     }
 }
@@ -1243,9 +1268,6 @@ impl<T: Encode> Encode for ExplicitTaggedValue<T> {
 ///  *     verifiedBootKey            OCTET_STRING,
 ///  *     deviceLocked               BOOLEAN,
 ///  *     verifiedBootState          VerifiedBootState,
-///  *     # verifiedBootHash must contain 32-byte value that represents the state of all binaries
-///  *     # or other components validated by verified boot.  Updating any verified binary or
-///  *     # component must cause this value to change.
 ///  *     verifiedBootHash           OCTET_STRING,
 ///  * }
 /// ```
@@ -1310,6 +1332,7 @@ impl From<keymint::VerifiedBootState> for VerifiedBootState {
 mod tests {
     use super::*;
     use crate::KeyMintHalVersion;
+    use alloc::vec;
 
     #[test]
     fn test_attest_ext_encode_decode() {
@@ -1321,7 +1344,7 @@ mod tests {
             keymint_security_level: sec_level,
             attestation_challenge: b"abc",
             unique_id: b"xxx",
-            sw_enforced: AuthorizationList::new(&[], &[], None, None, None).unwrap(),
+            sw_enforced: AuthorizationList::new(&[], &[], None, None, None, &[]).unwrap(),
             hw_enforced: AuthorizationList::new(
                 &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
                 &[],
@@ -1333,6 +1356,7 @@ mod tests {
                     verified_boot_hash: &[0xee; 32],
                 }),
                 None,
+                &[],
             )
             .unwrap(),
         };
@@ -1392,6 +1416,7 @@ mod tests {
 
     #[test]
     fn test_authz_list_encode_decode() {
+        let additional_attestation_info = [KeyParam::ModuleHash(vec![0xaa; 32])];
         let authz_list = AuthorizationList::new(
             &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
             &[],
@@ -1403,11 +1428,12 @@ mod tests {
                 verified_boot_hash: &[0xee; 32],
             }),
             None,
+            &additional_attestation_info,
         )
         .unwrap();
         let got = authz_list.to_der().unwrap();
         let want: &str = concat!(
-            "3055", // SEQUENCE len 55
+            "307b", // SEQUENCE len 123
             "a203", // EXPLICIT [2]
             "0201", // INTEGER len 1
             "03",   // 3 (Algorithm::Ec)
@@ -1424,6 +1450,11 @@ mod tests {
             "0420", // OCTET STRING len 32
             "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
             "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
+            "bf8554",
+            "22",   // EXPLICIT [724] len 34
+            "0420", // OCTET STRING len 32
+            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
+            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         );
         // encode
         assert_eq!(hex::encode(&got), want);
@@ -1450,6 +1481,7 @@ mod tests {
                 verified_boot_hash: &[0xee; 32],
             }),
             None,
+            &[],
         )
         .unwrap();
         let got = authz_list.to_der().unwrap();
@@ -1517,6 +1549,7 @@ mod tests {
                 verified_boot_hash: &[0xee; 32],
             }),
             None,
+            &[],
         )
         .unwrap();
 
@@ -1541,6 +1574,7 @@ mod tests {
                 verified_boot_hash: &[0xee; 32],
             }),
             None,
+            &[],
         )
         .unwrap();
         let got = authz_list.to_der().unwrap();
@@ -1561,6 +1595,7 @@ mod tests {
                 verified_boot_hash: &[0xee; 32],
             }),
             None,
+            &[],
         )
         .unwrap();
         assert!(authz_list.to_der().is_err());
diff --git a/ta/src/keys.rs b/ta/src/keys.rs
index 8d6fab3..7323b01 100644
--- a/ta/src/keys.rs
+++ b/ta/src/keys.rs
@@ -182,6 +182,7 @@ impl crate::KeyMintTa {
                     chars,
                     &unique_id,
                     &boot_info,
+                    &self.additional_attestation_info,
                 )?;
                 Some(
                     cert::asn1_der_encode(&attest_ext)
diff --git a/ta/src/lib.rs b/ta/src/lib.rs
index 07e5db6..95bdf09 100644
--- a/ta/src/lib.rs
+++ b/ta/src/lib.rs
@@ -17,7 +17,9 @@
 #![no_std]
 extern crate alloc;
 
-use alloc::{boxed::Box, collections::BTreeMap, rc::Rc, string::ToString, vec::Vec};
+use alloc::{
+    boxed::Box, collections::BTreeMap, format, rc::Rc, string::String, string::ToString, vec::Vec,
+};
 use core::cmp::Ordering;
 use core::mem::size_of;
 use core::{cell::RefCell, convert::TryFrom};
@@ -32,7 +34,7 @@ use kmr_wire::{
     coset::TaggedCborSerializable,
     keymint::{
         Digest, ErrorCode, HardwareAuthToken, KeyCharacteristics, KeyMintHardwareInfo, KeyOrigin,
-        KeyParam, SecurityLevel, VerifiedBootState, NEXT_MESSAGE_SIGNAL_FALSE,
+        KeyParam, SecurityLevel, Tag, VerifiedBootState, NEXT_MESSAGE_SIGNAL_FALSE,
         NEXT_MESSAGE_SIGNAL_TRUE,
     },
     rpc,
@@ -60,6 +62,8 @@ mod tests;
 #[repr(i32)]
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub enum KeyMintHalVersion {
+    /// V4 adds support for attestation of module information.
+    V4 = 400,
     /// V3 adds support for attestation of second IMEI value.
     V3 = 300,
     /// V2 adds support for curve 25519 and root-of-trust transfer.
@@ -69,7 +73,7 @@ pub enum KeyMintHalVersion {
 }
 
 /// Version code for current KeyMint.
-pub const KEYMINT_CURRENT_VERSION: KeyMintHalVersion = KeyMintHalVersion::V3;
+pub const KEYMINT_CURRENT_VERSION: KeyMintHalVersion = KeyMintHalVersion::V4;
 
 /// Maximum number of parallel operations supported when running as TEE.
 const MAX_TEE_OPERATIONS: usize = 16;
@@ -80,6 +84,9 @@ const MAX_STRONGBOX_OPERATIONS: usize = 4;
 /// Maximum number of keys whose use count can be tracked.
 const MAX_USE_COUNTED_KEYS: usize = 32;
 
+/// Tags allowed in `KeyMintTa::additional_attestation_info`.
+const ALLOWED_ADDITIONAL_ATTESTATION_TAGS: &[Tag] = &[Tag::ModuleHash];
+
 /// Per-key ID use count.
 struct UseCount {
     key_id: KeyId,
@@ -131,6 +138,10 @@ pub struct KeyMintTa {
     /// Information provided by the HAL service once at start of day.
     hal_info: Option<HalInfo>,
 
+    /// Additional information to attest to, provided by Android. Refer to
+    /// `IKeyMintDevice::setAdditionalAttestationInfo()`.
+    additional_attestation_info: Vec<KeyParam>,
+
     /// Attestation chain information, retrieved on first use.
     attestation_chain_info: RefCell<BTreeMap<device::SigningKeyType, AttestationChainInfo>>,
 
@@ -324,6 +335,7 @@ impl KeyMintTa {
             attestation_chain_info: RefCell::new(BTreeMap::new()),
             attestation_id_info: RefCell::new(None),
             dice_info: RefCell::new(None),
+            additional_attestation_info: Vec::new(),
         }
     }
 
@@ -604,6 +616,7 @@ impl KeyMintTa {
             100 => KeyMintHalVersion::V1,
             200 => KeyMintHalVersion::V2,
             300 => KeyMintHalVersion::V3,
+            400 => KeyMintHalVersion::V4,
             _ => return Err(km_err!(InvalidArgument, "unsupported HAL version {}", aidl_version)),
         };
         info!("Set aidl_version to {:?}", self.aidl_version);
@@ -864,6 +877,14 @@ impl KeyMintTa {
                     Err(e) => op_error_rsp(SendRootOfTrustRequest::CODE, e),
                 }
             }
+            PerformOpReq::SetAdditionalAttestationInfo(req) => {
+                match self.set_additional_attestation_info(req.info) {
+                    Ok(_ret) => op_ok_rsp(PerformOpRsp::SetAdditionalAttestationInfo(
+                        SetAdditionalAttestationInfoResponse {},
+                    )),
+                    Err(e) => op_error_rsp(SetAdditionalAttestationInfoRequest::CODE, e),
+                }
+            }
 
             // IKeyMintOperation messages.
             PerformOpReq::OperationUpdateAad(req) => match self.op_update_aad(
@@ -1079,6 +1100,44 @@ impl KeyMintTa {
         Ok(())
     }
 
+    fn set_additional_attestation_info(&mut self, info: Vec<KeyParam>) -> Result<(), Error> {
+        for param in info {
+            let tag = param.tag();
+            if !ALLOWED_ADDITIONAL_ATTESTATION_TAGS.contains(&tag) {
+                warn!("ignoring non-allowlisted tag: {tag:?}");
+                continue;
+            }
+            match self.additional_attestation_info.iter().find(|&x| x.tag() == tag) {
+                Some(value) if value == &param => {
+                    warn!(
+                        concat!(
+                            "additional attestation info for: {:?} already set, ignoring repeated",
+                            " attempt to set same info"
+                        ),
+                        param
+                    );
+                    continue;
+                }
+                Some(value) => {
+                    return Err(set_additional_attestation_info_err(
+                        tag,
+                        format!(
+                            concat!(
+                            "attempt to set additional attestation info for: {:?}, but that tag",
+                            " already has a different value set: {:?}"
+                        ),
+                            param, value
+                        ),
+                    ));
+                }
+                None => {
+                    self.additional_attestation_info.push(param.clone());
+                }
+            }
+        }
+        Ok(())
+    }
+
     fn convert_storage_key_to_ephemeral(&self, keyblob: &[u8]) -> Result<Vec<u8>, Error> {
         if let Some(sk_wrapper) = &self.dev.sk_wrapper {
             // Parse and decrypt the keyblob. Note that there is no way to provide extra hidden
@@ -1218,6 +1277,15 @@ fn op_error_rsp(op: KeyMintOperation, err: Error) -> PerformOpResponse {
     }
 }
 
+/// Create an Error for [`KeyMintTa::set_additional_attestation_info`] failure that corresponds to
+/// the specified tag.
+fn set_additional_attestation_info_err(tag: Tag, err_msg: String) -> Error {
+    match tag {
+        Tag::ModuleHash => km_err!(ModuleHashAlreadySet, "{}", err_msg),
+        _ => km_err!(InvalidTag, "unexpected tag: {tag:?}"),
+    }
+}
+
 /// Hand-encoded [`PerformOpResponse`] data for [`ErrorCode::UNKNOWN_ERROR`].
 /// Does not perform CBOR serialization (and so is suitable for error reporting if/when
 /// CBOR serialization fails).
diff --git a/tests/Cargo.toml b/tests/Cargo.toml
index f252d75..7fc39fd 100644
--- a/tests/Cargo.toml
+++ b/tests/Cargo.toml
@@ -17,4 +17,7 @@ kmr-crypto-boring = "*"
 kmr-ta = "*"
 kmr-wire = "*"
 log = "^0.4"
-x509-cert = "0.1.0"
+x509-cert = "0.2.4"
+
+[lints.rust]
+unexpected_cfgs = { level = "warn", check-cfg = ['cfg(soong)'] }
diff --git a/wire/Android.bp b/wire/Android.bp
index 23e037d..93d197b 100644
--- a/wire/Android.bp
+++ b/wire/Android.bp
@@ -28,6 +28,33 @@ rust_library {
     features: [
         "hal_v2",
         "hal_v3",
+        "hal_v4",
+    ],
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+        "libcoset",
+        "liblog_rust",
+        "libzeroize",
+    ],
+    proc_macros: [
+        "libenumn",
+        "libkmr_derive",
+    ],
+}
+
+// Variant of the library that only includes support for the KeyMint v3 HAL types.
+rust_library {
+    name: "libkmr_wire_hal_v3",
+    crate_name: "kmr_wire",
+    srcs: ["src/lib.rs"],
+    host_supported: true,
+    vendor_available: true,
+    edition: "2021",
+    lints: "android",
+    features: [
+        "hal_v3",
+        "hal_v2",
     ],
     rustlibs: [
         "libciborium",
@@ -51,7 +78,6 @@ rust_library {
     vendor_available: true,
     edition: "2021",
     lints: "android",
-    // Default target includes support for all versions of the KeyMint HAL.
     features: [
         "hal_v2",
     ],
@@ -100,6 +126,7 @@ rust_library_rlib {
     features: [
         "hal_v2",
         "hal_v3",
+        "hal_v4",
     ],
     rustlibs: [
         "libciborium_nostd",
diff --git a/wire/Cargo.toml b/wire/Cargo.toml
index 8160b75..ce3d1e7 100644
--- a/wire/Cargo.toml
+++ b/wire/Cargo.toml
@@ -9,7 +9,9 @@ edition = "2021"
 license = "Apache-2.0"
 
 [features]
-default = ["hal_v2", "hal_v3"]
+default = ["hal_v2", "hal_v3", "hal_v4"]
+# Include support for types added in v4 of the KeyMint HAL.
+hal_v4 = ["hal_v3", "hal_v2"]
 # Include support for types added in v3 of the KeyMint HAL.
 hal_v3 = ["hal_v2"]
 # Include support for types added in v2 of the KeyMint HAL.
diff --git a/wire/src/keymint.rs b/wire/src/keymint.rs
index 9d73fda..b1da1f3 100644
--- a/wire/src/keymint.rs
+++ b/wire/src/keymint.rs
@@ -271,6 +271,7 @@ pub enum ErrorCode {
     InvalidIssuerSubject = -83,
     BootLevelExceeded = -84,
     HardwareNotYetAvailable = -85,
+    ModuleHashAlreadySet = -86,
     Unimplemented = -100,
     VersionMismatch = -101,
     UnknownError = -1000,
@@ -405,6 +406,8 @@ pub enum KeyParam {
     CertificateNotBefore(DateTime),
     CertificateNotAfter(DateTime),
     MaxBootLevel(u32),
+    #[cfg(feature = "hal_v4")]
+    ModuleHash(Vec<u8>),
 }
 
 impl KeyParam {
@@ -470,6 +473,8 @@ impl KeyParam {
             KeyParam::CertificateNotBefore(_) => Tag::CertificateNotBefore,
             KeyParam::CertificateNotAfter(_) => Tag::CertificateNotAfter,
             KeyParam::MaxBootLevel(_) => Tag::MaxBootLevel,
+            #[cfg(feature = "hal_v4")]
+            KeyParam::ModuleHash(_) => Tag::ModuleHash,
         }
     }
 }
@@ -620,6 +625,8 @@ impl crate::AsCborValue for KeyParam {
                 KeyParam::CertificateNotAfter(<DateTime>::from_cbor_value(raw)?)
             }
             Tag::MaxBootLevel => KeyParam::MaxBootLevel(<u32>::from_cbor_value(raw)?),
+            #[cfg(feature = "hal_v4")]
+            Tag::ModuleHash => KeyParam::ModuleHash(<Vec<u8>>::from_cbor_value(raw)?),
 
             _ => return Err(crate::CborError::UnexpectedItem("tag", "known tag")),
         })
@@ -702,6 +709,8 @@ impl crate::AsCborValue for KeyParam {
             KeyParam::CertificateNotBefore(v) => (Tag::CertificateNotBefore, v.to_cbor_value()?),
             KeyParam::CertificateNotAfter(v) => (Tag::CertificateNotAfter, v.to_cbor_value()?),
             KeyParam::MaxBootLevel(v) => (Tag::MaxBootLevel, v.to_cbor_value()?),
+            #[cfg(feature = "hal_v4")]
+            KeyParam::ModuleHash(v) => (Tag::ModuleHash, v.to_cbor_value()?),
         };
         Ok(cbor::value::Value::Array(vec_try![tag.to_cbor_value()?, val]?))
     }
@@ -1056,6 +1065,15 @@ impl crate::AsCborValue for KeyParam {
             u32::cddl_ref(),
             "Tag_MaxBootLevel",
         );
+        #[cfg(feature = "hal_v4")]
+        {
+            result += &format!(
+                "    [{}, {}], ; {}\n",
+                Tag::ModuleHash as i32,
+                Vec::<u8>::cddl_ref(),
+                "Tag_ModuleHash",
+            );
+        }
         result += ")";
         Some(result)
     }
@@ -1188,6 +1206,8 @@ pub enum Tag {
     CertificateNotBefore = 1610613744,
     CertificateNotAfter = 1610613745,
     MaxBootLevel = 805307378,
+    #[cfg(feature = "hal_v4")]
+    ModuleHash = -1879047468,
 }
 try_from_n!(Tag);
 
diff --git a/wire/src/types.rs b/wire/src/types.rs
index bb58ffb..77a51f7 100644
--- a/wire/src/types.rs
+++ b/wire/src/types.rs
@@ -233,6 +233,14 @@ pub struct SendRootOfTrustRequest {
 #[derive(Debug, AsCborValue)]
 pub struct SendRootOfTrustResponse {}
 
+#[derive(Debug, AsCborValue)]
+pub struct SetAdditionalAttestationInfoRequest {
+    pub info: Vec<KeyParam>,
+}
+
+#[derive(Debug, AsCborValue)]
+pub struct SetAdditionalAttestationInfoResponse {}
+
 // IKeyMintOperation methods.  These ...Request structures include an extra `op_handle` field whose
 // value was returned in the `InternalBeginResult` type and which identifies the operation in
 // progress.
@@ -651,6 +659,7 @@ declare_req_rsp_enums! { KeyMintOperation  =>    (PerformOpReq, PerformOpRsp) {
     SetBootInfo = 0x82 =>                              (SetBootInfoRequest, SetBootInfoResponse),
     SetAttestationIds = 0x83 =>                        (SetAttestationIdsRequest, SetAttestationIdsResponse),
     SetHalVersion = 0x84 =>                            (SetHalVersionRequest, SetHalVersionResponse),
+    SetAdditionalAttestationInfo = 0x91 =>             (SetAdditionalAttestationInfoRequest, SetAdditionalAttestationInfoResponse),
 } }
 
 /// Indicate whether an operation is part of the `IRemotelyProvisionedComponent` HAL.
```

