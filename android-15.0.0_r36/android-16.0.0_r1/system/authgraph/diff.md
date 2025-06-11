```diff
diff --git a/core/Android.bp b/core/Android.bp
index 4d8964c..4d0c70b 100644
--- a/core/Android.bp
+++ b/core/Android.bp
@@ -54,9 +54,12 @@ rust_library_rlib {
 rust_test {
     name: "libauthgraph_core_unit_test",
     crate_name: "authgraph_core_unit_test",
-    srcs: ["src/lib.rs"],
+    srcs: ["tests/lib.rs"],
     host_supported: true,
     rustlibs: [
+        "libauthgraph_boringssl",
+        "libauthgraph_core",
+        "libauthgraph_core_test",
         "libauthgraph_wire",
         "libcoset",
         "libhex",
diff --git a/core/src/key.rs b/core/src/key.rs
index 1034883..e04d3a1 100644
--- a/core/src/key.rs
+++ b/core/src/key.rs
@@ -22,6 +22,7 @@ use crate::FallibleAllocExt;
 use crate::{ag_err, ag_verr};
 use alloc::{
     string::{String, ToString},
+    vec,
     vec::Vec,
 };
 use authgraph_wire as wire;
@@ -53,24 +54,48 @@ pub const IDENTITY_VERSION: i32 = 1;
 pub const SHA_256_LEN: usize = 32;
 
 // Following constants represent the keys of the (key, value) pairs in a Dice certificate
-const ISS: i64 = 1;
-const SUB: i64 = 2;
-const PROFILE_NAME: i64 = -4670554;
-const SUBJECT_PUBLIC_KEY: i64 = -4670552;
-const KEY_USAGE: i64 = -4670553;
-const CODE_HASH: i64 = -4670545;
-const CODE_DESC: i64 = -4670546;
-const CONFIG_HASH: i64 = -4670547;
-const CONFIG_DESC: i64 = -4670548;
-const AUTHORITY_HASH: i64 = -4670549;
-const AUTHORITY_DESC: i64 = -4670550;
-const MODE: i64 = -4670551;
-
-const COMPONENT_NAME: i64 = -70002;
-const COMPONENT_VERSION: i64 = -70003;
-const RESETTABLE: i64 = -70004;
-const SECURITY_VERSION: i64 = -70005;
-const RKP_VM_MARKER: i64 = -70006;
+/// Issuer
+pub const ISSUER: i64 = 1;
+/// Subject
+pub const SUBJECT: i64 = 2;
+/// Profile Name
+pub const PROFILE_NAME: i64 = -4670554;
+/// Subject Public Key
+pub const SUBJECT_PUBLIC_KEY: i64 = -4670552;
+/// Key Usage
+pub const KEY_USAGE: i64 = -4670553;
+/// Code Hash
+pub const CODE_HASH: i64 = -4670545;
+/// Code Descriptor
+pub const CODE_DESC: i64 = -4670546;
+/// Configuration Hash
+pub const CONFIG_HASH: i64 = -4670547;
+/// Configuration Descriptor
+pub const CONFIG_DESC: i64 = -4670548;
+/// Authority Hash
+pub const AUTHORITY_HASH: i64 = -4670549;
+/// Authority Descriptor
+pub const AUTHORITY_DESC: i64 = -4670550;
+/// Mode
+pub const MODE: i64 = -4670551;
+
+/// Keys of the `ConfigurationDescriptor` map defined in hardware/interfaces/security/rkp/aidl/
+/// android/hardware/security/keymint/generateCertificateRequestV2.cddl
+/// Name of the component which is the owner of the certificate
+pub const COMPONENT_NAME: i64 = -70002;
+/// Version of the component
+pub const COMPONENT_VERSION: i64 = -70003;
+/// Is the component resettable
+pub const RESETTABLE: i64 = -70004;
+/// Security version of the component
+pub const SECURITY_VERSION: i64 = -70005;
+/// Is this component part of a RKP VM boot chain
+pub const RKP_VM_MARKER: i64 = -70006;
+/// Instance hash introduced in the "DICE specification for guest VM"
+/// in packages/modules/Virtualization/dice_for_avf_guest.cddl
+pub const INSTANCE_HASH: i64 = -71003;
+/// Name of the guest os component in a pVM DICE chain
+pub const GUEST_OS_COMPONENT_NAME: &str = "vm_entry";
 
 /// AES key of 256 bits
 #[derive(Clone, ZeroizeOnDrop)]
@@ -168,8 +193,19 @@ pub enum EcSignKey {
     P384(Vec<u8>),
 }
 
+impl EcSignKey {
+    /// Return the Cose signing algorithm corresponds to the given signing key.
+    pub fn get_cose_sign_algorithm(&self) -> iana::Algorithm {
+        match *self {
+            EcSignKey::Ed25519(_) => iana::Algorithm::EdDSA,
+            EcSignKey::P256(_) => iana::Algorithm::ES256,
+            EcSignKey::P384(_) => iana::Algorithm::ES384,
+        }
+    }
+}
+
 /// Variants of EC public key used to verify signature
-#[derive(Clone, PartialEq)]
+#[derive(Clone, Debug, PartialEq)]
 pub enum EcVerifyKey {
     /// On curve Ed25519
     Ed25519(CoseKey),
@@ -299,7 +335,7 @@ pub struct Identity {
 /// Certificate chain containing the public signing key. The CDDL is listed in
 /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/
 /// authgraph/ExplicitKeyDiceCertChain.cddl
-#[derive(Clone, PartialEq)]
+#[derive(Clone, Debug, Default, PartialEq)]
 pub struct CertChain {
     /// Version of the cddl
     pub version: i32,
@@ -311,7 +347,7 @@ pub struct CertChain {
 }
 
 /// An entry in the certificate chain (i.e. a certificate).
-#[derive(Clone, PartialEq)]
+#[derive(Clone, Debug, Default, PartialEq)]
 pub struct DiceChainEntry {
     /// A certificate is represented as CoseSign1. The `payload` field of CoseSign1 holds the CBOR
     /// encoded payload that was signed.
@@ -322,7 +358,7 @@ pub struct DiceChainEntry {
 }
 
 /// Partially decoded payload for each entry in the DICE chain
-#[derive(Default, Clone, PartialEq)]
+#[derive(Clone, Debug, Default, PartialEq)]
 pub struct DiceChainEntryPayloadPartiallyDecoded {
     /// Issuer of the DiceChainEntry. Required as per the CDDL.
     pub issuer: Option<String>,
@@ -336,7 +372,7 @@ pub struct DiceChainEntryPayloadPartiallyDecoded {
 }
 
 /// Payload for each entry in the DICE chain
-#[derive(Default, Clone, PartialEq)]
+#[derive(Clone, Debug, Default, PartialEq)]
 pub struct DiceChainEntryPayload {
     /// Issuer of the DiceChainEntry. Required as per the CDDL.
     pub issuer: Option<String>,
@@ -366,8 +402,11 @@ pub struct DiceChainEntryPayload {
     pub custom_fields: Vec<(i64, Value)>,
 }
 
+/// Type alias for an instance identifier found in a DICE certificate for a pVM instance
+pub type InstanceIdentifier = Vec<u8>;
+
 /// Configuration descriptor in `DiceChainEntryPayload`. All the fields are optional
-#[derive(Default, Clone, PartialEq)]
+#[derive(Clone, Debug, Default, PartialEq)]
 pub struct ConfigurationDescriptor {
     /// Component name
     pub component_name: Option<String>,
@@ -384,7 +423,7 @@ pub struct ConfigurationDescriptor {
 }
 
 /// Configuration descriptor that allows for non-spec compliant legacy values.
-#[derive(Clone, PartialEq)]
+#[derive(Clone, Debug, PartialEq)]
 pub enum ConfigurationDescriptorOrLegacy {
     /// Configuration descriptor complying with the CDDL schema.
     Descriptor(ConfigurationDescriptor),
@@ -393,7 +432,7 @@ pub enum ConfigurationDescriptorOrLegacy {
 }
 
 /// Component version can be either an integer or a string, as per the CDDL.
-#[derive(Clone, PartialEq)]
+#[derive(Clone, Debug, PartialEq)]
 pub enum ComponentVersion {
     /// Version represented as an integer
     IntVersion(u32),
@@ -404,7 +443,7 @@ pub enum ComponentVersion {
 /// Identity verification policy specifying how to validate the certificate chain. The CDDL is
 /// listed in hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/
 /// DicePolicy.cddl
-#[derive(Clone, Eq, PartialEq)]
+#[derive(Clone, Default, Debug, Eq, PartialEq)]
 pub struct Policy(pub Vec<u8>);
 
 /// The output of identity verification.
@@ -585,6 +624,114 @@ impl CertChain {
             }
         }
     }
+
+    /// Extract the instance identifier (a.k.a. instance hash) from a pVM DICE chain as per
+    /// packages/modules/Virtualization/dice_for_avf_guest.cddl. We are specifically looking for the
+    /// instance hash included in the DICE certificate that has the component name = "vm_entry",
+    /// which is set by the PVMFW. If not present, return None.
+    pub fn extract_instance_identifier_in_guest_os_entry(
+        &self,
+    ) -> Result<Option<InstanceIdentifier>, Error> {
+        // Access the configuration descriptor by decoding the `full_map` in a DiceChainEntry
+        // as `DiceChainEntryPayload` and check if instance identifier is present
+        if let Some(dice_cert_chain) = &self.dice_cert_chain {
+            for dice_cert in dice_cert_chain.iter().rev() {
+                if let Some(v) = &dice_cert.payload.full_map {
+                    let dice_chain_entry_payload =
+                        DiceChainEntryPayload::from_cbor_value(v.clone())?;
+                    if let Some(ConfigurationDescriptorOrLegacy::Descriptor(config_desc)) =
+                        dice_chain_entry_payload.configuration_descriptor
+                    {
+                        if config_desc
+                            .component_name
+                            .map_or(false, |comp_name| comp_name == GUEST_OS_COMPONENT_NAME)
+                        {
+                            let instance_hash_tuple =
+                                config_desc.custom_fields.iter().find(|v| v.0 == INSTANCE_HASH);
+                            if let Some((_, Value::Bytes(instance_hash))) =
+                                instance_hash_tuple.cloned()
+                            {
+                                return Ok(Some(instance_hash));
+                            }
+                        }
+                    }
+                }
+            }
+        }
+        Ok(None)
+    }
+
+    /// Convert a DICE chain to explicit key DICE chain format, if it is not already in this format.
+    /// This method is used to convert a DICE chain adhering to the CDDL defined in
+    /// hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/
+    /// generateCertificateRequestV2.cddl to a DICE chain adhering to the CDDL defined in
+    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/
+    /// ExplicitKeyDiceCertChain.cddl
+    pub fn from_non_explicit_key_cert_chain(dice_chain_bytes: &[u8]) -> Result<Self, Error> {
+        let value = Value::from_slice(dice_chain_bytes)?;
+        let dice_cert_chain_array = value
+            .into_array()
+            .map_err(|_| ag_err!(InvalidCertChain, "cert chain is not a cbor array"))?;
+        // Check if the dice_chain is already in explicit key format
+        if matches!(
+            &&dice_cert_chain_array[..],
+            [Value::Integer(_version), Value::Bytes(_public_key), ..]
+        ) {
+            return Ok(CertChain::from_slice(dice_chain_bytes)?);
+        }
+        let mut res: Vec<Value> = Vec::with_capacity(dice_cert_chain_array.len() + 1);
+        let mut it = dice_cert_chain_array.into_iter();
+        res.push(Value::from(EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION));
+        let root_key =
+            it.next().ok_or(ag_err!(InvalidCertChain, "cert chain is an empty array"))?;
+
+        // Canonicalize the root public key as per Core Deterministic Encoding Requirements
+        let mut root_key = CoseKey::from_cbor_value(root_key)?;
+        root_key.canonicalize(CborOrdering::Lexicographic);
+        // Converts to .bstr .cbor COSE_KEY
+        let root_key = root_key.to_vec()?;
+        res.push(Value::Bytes(root_key));
+        res.extend(it);
+        Ok(CertChain::from_cbor_value(Value::Array(res))?)
+    }
+
+    /// Get a copy of this DICE certificate chain extended with the given certificate.
+    pub fn extend_with(&self, cert: &DiceChainEntry, ecdsa: &dyn EcDsa) -> Result<Self, Error> {
+        let mut dice_chain_copy = self.clone();
+        let mut parent_pub_key: EcVerifyKey = dice_chain_copy.root_key.clone();
+        if let Some(cert_chain) = &dice_chain_copy.dice_cert_chain {
+            if let Some(current_leaf_cert) = cert_chain.last() {
+                parent_pub_key = current_leaf_cert
+                    .payload
+                    .subject_pub_key
+                    .as_ref()
+                    .cloned()
+                    .ok_or_else(|| ag_err!(InternalError, "subject public key is missing"))?;
+            }
+        };
+        parent_pub_key.validate_cose_key_params()?;
+        cert.signature
+            .verify_signature(&[], |sig, data| ecdsa.verify_signature(&parent_pub_key, data, sig))
+            .map_err(|_e| {
+                ag_err!(InvalidSignature, "failed to verify signature on the leaf cert")
+            })?;
+        if let Some(ref mut cert_chain) = dice_chain_copy.dice_cert_chain {
+            cert_chain.push(cert.clone());
+        } else {
+            dice_chain_copy.dice_cert_chain = Some(vec![cert.clone()]);
+        }
+        Ok(dice_chain_copy)
+    }
+
+    /// Match the leaf of the cert chain with the given certificate
+    pub fn is_current_leaf(&self, leaf: &DiceChainEntry) -> bool {
+        if let Some(cert_chain) = &self.dice_cert_chain {
+            if let Some(leaf_cert) = cert_chain.last() {
+                return leaf == leaf_cert;
+            }
+        }
+        false
+    }
 }
 
 impl AsCborValue for CertChain {
@@ -690,7 +837,7 @@ impl AsCborValue for DiceChainEntryPayloadPartiallyDecoded {
                 .try_into()
                 .map_err(|_| CoseError::UnexpectedItem("error", "an Integer convertible to i64"))?;
             match (key_int, val) {
-                (ISS, Value::Text(issuer)) => match dice_chain_entry_payload.issuer {
+                (ISSUER, Value::Text(issuer)) => match dice_chain_entry_payload.issuer {
                     None => dice_chain_entry_payload.issuer = Some(issuer.to_string()),
                     Some(_) => {
                         return Err(CoseError::UnexpectedItem(
@@ -699,7 +846,7 @@ impl AsCborValue for DiceChainEntryPayloadPartiallyDecoded {
                         ));
                     }
                 },
-                (SUB, Value::Text(subject)) => match dice_chain_entry_payload.subject {
+                (SUBJECT, Value::Text(subject)) => match dice_chain_entry_payload.subject {
                     None => dice_chain_entry_payload.subject = Some(subject.to_string()),
                     Some(_) => {
                         return Err(CoseError::UnexpectedItem(
@@ -756,7 +903,7 @@ impl AsCborValue for DiceChainEntryPayload {
                 .try_into()
                 .map_err(|_| CoseError::UnexpectedItem("error", "an Integer convertible to i64"))?;
             match (key_int, val) {
-                (ISS, Value::Text(issuer)) => match dice_chain_entry_payload.issuer {
+                (ISSUER, Value::Text(issuer)) => match dice_chain_entry_payload.issuer {
                     None => dice_chain_entry_payload.issuer = Some(issuer),
                     Some(_) => {
                         return Err(CoseError::UnexpectedItem(
@@ -765,7 +912,7 @@ impl AsCborValue for DiceChainEntryPayload {
                         ));
                     }
                 },
-                (SUB, Value::Text(subject)) => match dice_chain_entry_payload.subject {
+                (SUBJECT, Value::Text(subject)) => match dice_chain_entry_payload.subject {
                     None => dice_chain_entry_payload.subject = Some(subject),
                     Some(_) => {
                         return Err(CoseError::UnexpectedItem(
@@ -1045,58 +1192,3 @@ pub fn check_cose_key_params(
     }
     Ok(())
 }
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test_legacy_open_dice_payload() {
-        // Some legacy devices have an open-DICE format config descriptor (b/261647022) rather than
-        // the format used in the Android RKP HAL.  Ensure that they still parse.
-        let data = hex::decode(concat!(
-            "a8",   // 8-map
-            "01",   // Issuer:
-            "7828", // 40-tstr
-            "32336462613837333030633932323934663836333566323738316464346633366362313934383835",
-            "02",   // Subject:
-            "7828", // 40-tstr
-            "33376165616366396230333465643064376166383665306634653431656163356335383134343966",
-            "3a00474450", // Code Hash(-4670545):
-            "5840",       // 64-bstr
-            "3c9aa93a6766f16f5fbd3dfc7e5059b39cdc8aa0cf546cc878d588a69cfcd654",
-            "2fa509bd6cc14b7160a6bf34545ffdd840f0e91e35b274a7a952b5b0efcff1b0",
-            "3a00474453", // Configuration Descriptor (-4670548):
-            "5840",       // 64-bstr
-            // The RKP HAL expects the following data to match schema:
-            //
-            //     { ? -70002 : tstr, ? -70003 : int / tstr, ? -70004 : null,
-            //       ? -70005 : uint, ? -70006 : null, }
-            //
-            // However, the open-DICE spec had:
-            //     If the configuration input is a hash this field contains the original
-            //     configuration data that was hashed. If it is not a hash, this field contains the
-            //     exact 64-byte configuration input value used to compute CDI values."
-            "e2000000000001508609939b5a4f0f0800000000000000000101000000000000",
-            "0000000000000000000000000000000000000000000000000000000000000000",
-            "3a00474454", // Authority Hash (-4670549):
-            "5840",       // 64-bstr
-            "4d00da66eabbb2b684641a57e96c8e64d76df1e31ea203bbbb9f439372c1a8ec",
-            "aa550000aa550000aa550000aa550000aa550000aa550000aa550000aa550000",
-            "3a00474456", // Mode (-4670551):
-            "4101",       // 1-bstr value 0x01
-            "3a00474457", // Subject Public Key (-4670552):
-            "5871",       // 113-bstr
-            "a601020338220481022002215830694a8fa269c3375b770ef61d06dec5a78595",
-            "2ee96db3602b57c50d8fa67f97e874fbd3f5b42e66ac8ead3f3eb3b130f42258",
-            "301b5574256be9f4770c3325422e53981b1a969387068a51aea68fe98f779be5",
-            "75ecb077a60106852af654377e56d446a6",
-            "3a00474458", // Key Usage (-4670553):
-            "4120"        // 1-bstr value 0x20
-        ))
-        .unwrap();
-
-        assert!(DiceChainEntryPayloadPartiallyDecoded::from_slice(&data).is_ok());
-        assert!(DiceChainEntryPayload::from_slice(&data).is_ok());
-    }
-}
diff --git a/core/src/traits.rs b/core/src/traits.rs
index a597d20..3bf4c42 100644
--- a/core/src/traits.rs
+++ b/core/src/traits.rs
@@ -143,7 +143,7 @@ pub trait Sha256: Send {
 }
 
 /// Trait methods for generating cryptographically secure random numbers
-pub trait Rng {
+pub trait Rng: Send {
     /// Create a cryptographically secure random bytes
     fn fill_bytes(&self, nonce: &mut [u8]);
     /// Emit a copy of the trait implementation, as a boxed trait object.
diff --git a/core/testdata/bcc b/core/testdata/bcc
new file mode 100644
index 0000000..3386b72
Binary files /dev/null and b/core/testdata/bcc differ
diff --git a/core/tests/lib.rs b/core/tests/lib.rs
new file mode 100644
index 0000000..54bc2ff
--- /dev/null
+++ b/core/tests/lib.rs
@@ -0,0 +1,194 @@
+// Copyright 2025 Google LLC
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
+//
+////////////////////////////////////////////////////////////////////////////////
+
+//! The unit tests module
+#![no_std]
+extern crate alloc;
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use alloc::string::ToString;
+    use alloc::vec;
+    use authgraph_boringssl::BoringEcDsa;
+    use authgraph_core::key::{
+        CertChain, DiceChainEntry, DiceChainEntryPayload, DiceChainEntryPayloadPartiallyDecoded,
+        Identity,
+    };
+    use authgraph_core_test::{
+        create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
+    };
+    use coset::CborSerializable;
+
+    #[test]
+    fn test_legacy_open_dice_payload() {
+        // Some legacy devices have an open-DICE format config descriptor (b/261647022) rather than
+        // the format used in the Android RKP HAL.  Ensure that they still parse.
+        let data = hex::decode(concat!(
+            "a8",   // 8-map
+            "01",   // Issuer:
+            "7828", // 40-tstr
+            "32336462613837333030633932323934663836333566323738316464346633366362313934383835",
+            "02",   // Subject:
+            "7828", // 40-tstr
+            "33376165616366396230333465643064376166383665306634653431656163356335383134343966",
+            "3a00474450", // Code Hash(-4670545):
+            "5840",       // 64-bstr
+            "3c9aa93a6766f16f5fbd3dfc7e5059b39cdc8aa0cf546cc878d588a69cfcd654",
+            "2fa509bd6cc14b7160a6bf34545ffdd840f0e91e35b274a7a952b5b0efcff1b0",
+            "3a00474453", // Configuration Descriptor (-4670548):
+            "5840",       // 64-bstr
+            // The RKP HAL expects the following data to match schema:
+            //
+            //     { ? -70002 : tstr, ? -70003 : int / tstr, ? -70004 : null,
+            //       ? -70005 : uint, ? -70006 : null, }
+            //
+            // However, the open-DICE spec had:
+            //     If the configuration input is a hash this field contains the original
+            //     configuration data that was hashed. If it is not a hash, this field contains the
+            //     exact 64-byte configuration input value used to compute CDI values."
+            "e2000000000001508609939b5a4f0f0800000000000000000101000000000000",
+            "0000000000000000000000000000000000000000000000000000000000000000",
+            "3a00474454", // Authority Hash (-4670549):
+            "5840",       // 64-bstr
+            "4d00da66eabbb2b684641a57e96c8e64d76df1e31ea203bbbb9f439372c1a8ec",
+            "aa550000aa550000aa550000aa550000aa550000aa550000aa550000aa550000",
+            "3a00474456", // Mode (-4670551):
+            "4101",       // 1-bstr value 0x01
+            "3a00474457", // Subject Public Key (-4670552):
+            "5871",       // 113-bstr
+            "a601020338220481022002215830694a8fa269c3375b770ef61d06dec5a78595",
+            "2ee96db3602b57c50d8fa67f97e874fbd3f5b42e66ac8ead3f3eb3b130f42258",
+            "301b5574256be9f4770c3325422e53981b1a969387068a51aea68fe98f779be5",
+            "75ecb077a60106852af654377e56d446a6",
+            "3a00474458", // Key Usage (-4670553):
+            "4120"        // 1-bstr value 0x20
+        ))
+        .unwrap();
+
+        assert!(DiceChainEntryPayloadPartiallyDecoded::from_slice(&data).is_ok());
+        assert!(DiceChainEntryPayload::from_slice(&data).is_ok());
+    }
+
+    /// Test instance hash extraction API method with test data (from a device) that has
+    /// an instance hash
+    #[test]
+    fn test_instance_hash_extraction() {
+        // Read the DICE chain bytes from the file
+        let dice_chain_bytes: &[u8] = include_bytes!("../testdata/bcc");
+        // Create an explicit key DICE chain out of it
+        let explicit_key_dice_chain = CertChain::from_non_explicit_key_cert_chain(dice_chain_bytes)
+            .expect("error converting DICE chain to an explicit key DICE chain");
+        // Extract the instance hash
+        let instance_hash = explicit_key_dice_chain
+            .extract_instance_identifier_in_guest_os_entry()
+            .expect("error in extracting the instance id")
+            .expect("no instance id found");
+        let expected_instance_hash = vec![
+            68, 32, 41, 225, 228, 67, 229, 107, 207, 212, 74, 74, 191, 25, 211, 133, 57, 166, 35,
+            146, 86, 89, 182, 52, 183, 255, 215, 204, 5, 183, 254, 79, 129, 240, 197, 252, 238, 69,
+            124, 44, 164, 214, 205, 87, 194, 226, 124, 249, 158, 219, 188, 127, 55, 143, 232, 142,
+            119, 174, 202, 160, 234, 179, 205, 30,
+        ];
+        assert_eq!(instance_hash, expected_instance_hash);
+    }
+
+    /// Test instance hash extraction API method with test data (from a device) that does not
+    /// have an instance hash
+    #[test]
+    fn test_instance_hash_extraction_negative() {
+        let mut hex_data =
+            std::str::from_utf8(include_bytes!("../../tests/testdata/sample_identity.hex"))
+                .unwrap()
+                .to_string();
+        hex_data.retain(|c| !c.is_whitespace());
+        let data = hex::decode(hex_data).unwrap();
+        let identity = Identity::from_slice(&data).expect("identity data did not decode");
+        // Extract the instance hash
+        let instance_hash = identity
+            .cert_chain
+            .extract_instance_identifier_in_guest_os_entry()
+            .expect("error in extracting the instance id");
+        assert_eq!(instance_hash, None);
+    }
+
+    /// Test instance hash extraction with a programmatically created DICE cert chain that has
+    /// instance hash
+    #[test]
+    fn test_instance_hash_extraction_with_code_generated_dice_chain() {
+        let (_, _, dice_chain_bytes) =
+            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        let dice_cert_chain =
+            CertChain::from_slice(&dice_chain_bytes).expect("error decoding the DICE chain");
+        // Extract the instance hash
+        let instance_hash = dice_cert_chain
+            .extract_instance_identifier_in_guest_os_entry()
+            .expect("error in extracting the instance id")
+            .expect("no instance id found");
+        assert_eq!(instance_hash, SAMPLE_INSTANCE_HASH);
+    }
+
+    /// Test instance hash extraction with a programmatically created DICE cert chain that does not
+    /// has instance hash
+    #[test]
+    fn test_instance_hash_extraction_with_code_generated_dice_chain_negative() {
+        let (_, _, dice_chain_bytes) = create_dice_cert_chain_for_guest_os(None, 0);
+        let dice_cert_chain =
+            CertChain::from_slice(&dice_chain_bytes).expect("error decoding the DICE chain");
+        // Extract the instance id
+        let instance_hash = dice_cert_chain
+            .extract_instance_identifier_in_guest_os_entry()
+            .expect("error in extracting the instance id");
+        assert_eq!(instance_hash, None);
+    }
+
+    /// Test extending a DICE chain with a giveen DICE certificate
+    #[test]
+    fn test_dice_chain_extend() {
+        let ecdsa = BoringEcDsa;
+        // Create a DICE chain for a pvm instance and a leaf cert for keymint TA
+        let (_sign_key, cdi_values, cert_chain_bytes) =
+            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        let leaf_cert_bytes = create_dice_leaf_cert(cdi_values, "keymint", 1);
+        let dice_chain =
+            CertChain::from_slice(&cert_chain_bytes).expect("failed to decode dice chain");
+        let leaf_cert =
+            DiceChainEntry::from_slice(&leaf_cert_bytes).expect("failed to decode the leaf cert");
+        // Extend the pvm's DICE chain with the leaf cert
+        let extended_dice_chain =
+            dice_chain.extend_with(&leaf_cert, &ecdsa).expect("failed to extend the dice chain");
+        // Verify that the original DICE chain has extended as expected
+        assert_eq!(
+            dice_chain.dice_cert_chain.as_ref().unwrap().len() + 1,
+            extended_dice_chain.dice_cert_chain.as_ref().unwrap().len()
+        );
+        assert!(extended_dice_chain.is_current_leaf(&leaf_cert));
+        assert!(!dice_chain.is_current_leaf(&leaf_cert));
+
+        assert_eq!(
+            &leaf_cert,
+            extended_dice_chain.dice_cert_chain.as_ref().unwrap().last().unwrap()
+        );
+
+        // Create a secondary DICE chain, try to extend it with the previous leaf cert and expect
+        // error
+        let (_, _, cert_chain_bytes_2) =
+            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 2);
+        let dice_chain_2 =
+            CertChain::from_slice(&cert_chain_bytes_2).expect("failed to decode dice chain 2");
+        assert!(dice_chain_2.extend_with(&leaf_cert, &ecdsa).is_err());
+    }
+}
diff --git a/tests/src/lib.rs b/tests/src/lib.rs
index 4ef2b04..f9b9969 100644
--- a/tests/src/lib.rs
+++ b/tests/src/lib.rs
@@ -3,7 +3,9 @@
 extern crate alloc;
 use authgraph_core::key::{
     AesKey, EcSignKey, EcVerifyKey, EcdhSecret, HmacKey, Identity, Key, Nonce12, PseudoRandKey,
-    CURVE25519_PRIV_KEY_LEN, EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, IDENTITY_VERSION,
+    COMPONENT_NAME, COMPONENT_VERSION, CURVE25519_PRIV_KEY_LEN,
+    EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, GUEST_OS_COMPONENT_NAME, IDENTITY_VERSION, INSTANCE_HASH,
+    RESETTABLE, SECURITY_VERSION,
 };
 use authgraph_core::keyexchange;
 use authgraph_core::traits::{
@@ -17,8 +19,23 @@ use coset::{
     Algorithm, CborSerializable, CoseKey, CoseKeyBuilder, CoseSign1Builder, HeaderBuilder,
     KeyOperation, KeyType, Label,
 };
+pub use diced_open_dice::CdiValues;
 use std::ffi::CString;
 
+/// UDS used to create the DICE chains in this test-util library.
+pub const UDS: [u8; diced_open_dice::CDI_SIZE] = [
+    0x1d, 0xa5, 0xea, 0x90, 0x47, 0xfc, 0xb5, 0xf6, 0x47, 0x12, 0xd3, 0x65, 0x9c, 0xf2, 0x00, 0xe0,
+    0x06, 0xf7, 0xe8, 0x9e, 0x2f, 0xd0, 0x94, 0x7f, 0xc9, 0x9a, 0x9d, 0x40, 0xf7, 0xce, 0x13, 0x21,
+];
+
+/// Sample value for instance hash
+pub const SAMPLE_INSTANCE_HASH: [u8; 64] = [
+    0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a,
+    0x7d, 0x7e, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a, 0xe9, 0x90,
+    0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95,
+    0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a, 0x7d, 0x7e, 0xf5, 0x8e, 0xf5, 0x8e,
+];
+
 /// Test basic [`Rng`] functionality.
 pub fn test_rng<R: Rng>(rng: &mut R) {
     let mut nonce1 = [0; 16];
@@ -863,11 +880,6 @@ pub fn validate_identity<E: EcDsa>(ecdsa: &E) {
 /// certificate entries, using open-dice. The maximum length supported by this method is 5.
 /// Return the private signing key corresponding to the public signing key.
 pub fn create_identity(dice_chain_len: usize) -> Result<(EcSignKey, Vec<u8>), Error> {
-    const UDS: [u8; diced_open_dice::CDI_SIZE] = [
-        0x1d, 0xa5, 0xea, 0x90, 0x47, 0xfc, 0xb5, 0xf6, 0x47, 0x12, 0xd3, 0x65, 0x9c, 0xf2, 0x00,
-        0xe0, 0x06, 0xf7, 0xe8, 0x9e, 0x2f, 0xd0, 0x94, 0x7f, 0xc9, 0x9a, 0x9d, 0x40, 0xf7, 0xce,
-        0x13, 0x21,
-    ];
     let pvt_key_seed = diced_open_dice::derive_cdi_private_key_seed(&UDS).unwrap();
     let (root_pub_key, pvt_key) = diced_open_dice::keypair_from_seed(pvt_key_seed.as_array())
         .expect("failed to create key pair from seed.");
@@ -1243,3 +1255,325 @@ pub fn test_example_identity_validate<E: EcDsa>(ecdsa: &E) {
     let identity = Identity::from_slice(&data).expect("identity data did not decode");
     identity.validate(ecdsa).expect("identity did not validate");
 }
+
+/// This is a util method for writing tests related to the instance identifier in the vm entry of a
+/// pvm DICE chain. Returns the leaf private signing key, leaf CDI values and the sample DICE chain.
+pub fn create_dice_cert_chain_for_guest_os(
+    instance_hash_for_vm_entry: Option<[u8; 64]>,
+    security_version: u64,
+) -> (EcSignKey, CdiValues, Vec<u8>) {
+    let pvt_key_seed = diced_open_dice::derive_cdi_private_key_seed(&UDS).unwrap();
+    let (root_pub_key, _pvt_key) = diced_open_dice::keypair_from_seed(pvt_key_seed.as_array())
+        .expect("failed to create key pair from seed.");
+    let root_pub_cose_key = CoseKey {
+        kty: KeyType::Assigned(iana::KeyType::OKP),
+        alg: Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
+        key_ops: vec![KeyOperation::Assigned(iana::KeyOperation::Verify)].into_iter().collect(),
+        params: vec![
+            (
+                Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
+                iana::EllipticCurve::Ed25519.to_i64().into(),
+            ),
+            (Label::Int(iana::Ec2KeyParameter::X.to_i64()), Value::Bytes(root_pub_key.to_vec())),
+        ],
+        ..Default::default()
+    };
+    let root_pub_cose_key_bstr =
+        root_pub_cose_key.to_vec().expect("failed to serialize root pub key");
+
+    const CODE_HASH_TRUSTY: [u8; diced_open_dice::HASH_SIZE] = [
+        0x16, 0x48, 0xf2, 0x55, 0x53, 0x23, 0xdd, 0x15, 0x2e, 0x83, 0x38, 0xc3, 0x64, 0x38, 0x63,
+        0x26, 0x0f, 0xcf, 0x5b, 0xd1, 0x3a, 0xd3, 0x40, 0x3e, 0x23, 0xf8, 0x34, 0x4c, 0x6d, 0xa2,
+        0xbe, 0x25, 0x1c, 0xb0, 0x29, 0xe8, 0xc3, 0xfb, 0xb8, 0x80, 0xdc, 0xb1, 0xd2, 0xb3, 0x91,
+        0x4d, 0xd3, 0xfb, 0x01, 0x0f, 0xe4, 0xe9, 0x46, 0xa2, 0xc0, 0x26, 0x57, 0x5a, 0xba, 0x30,
+        0xf7, 0x15, 0x98, 0x14,
+    ];
+    const AUTHORITY_HASH_TRUSTY: [u8; diced_open_dice::HASH_SIZE] = [
+        0xf9, 0x00, 0x9d, 0xc2, 0x59, 0x09, 0xe0, 0xb6, 0x98, 0xbd, 0xe3, 0x97, 0x4a, 0xcb, 0x3c,
+        0xe7, 0x6b, 0x24, 0xc3, 0xe4, 0x98, 0xdd, 0xa9, 0x6a, 0x41, 0x59, 0x15, 0xb1, 0x23, 0xe6,
+        0xc8, 0xdf, 0xfb, 0x52, 0xb4, 0x52, 0xc1, 0xb9, 0x61, 0xdd, 0xbc, 0x5b, 0x37, 0x0e, 0x12,
+        0x12, 0xb2, 0xfd, 0xc1, 0x09, 0xb0, 0xcf, 0x33, 0x81, 0x4c, 0xc6, 0x29, 0x1b, 0x99, 0xea,
+        0xae, 0xfd, 0xaa, 0x0d,
+    ];
+    const HIDDEN_TRUSTY: [u8; diced_open_dice::HIDDEN_SIZE] = [
+        0xa2, 0x01, 0xd0, 0xc0, 0xaa, 0x75, 0x3c, 0x06, 0x43, 0x98, 0x6c, 0xc3, 0x5a, 0xb5, 0x5f,
+        0x1f, 0x0f, 0x92, 0x44, 0x3b, 0x0e, 0xd4, 0x29, 0x75, 0xe3, 0xdb, 0x36, 0xda, 0xc8, 0x07,
+        0x97, 0x4d, 0xff, 0xbc, 0x6a, 0xa4, 0x8a, 0xef, 0xc4, 0x7f, 0xf8, 0x61, 0x7d, 0x51, 0x4d,
+        0x2f, 0xdf, 0x7e, 0x8c, 0x3d, 0xa3, 0xfc, 0x63, 0xd4, 0xd4, 0x74, 0x8a, 0xc4, 0x14, 0x45,
+        0x83, 0x6b, 0x12, 0x7e,
+    ];
+    let comp_name_1 = CString::new("Trusty").expect("CString::new failed");
+    let config_values_1 = diced_open_dice::DiceConfigValues {
+        component_name: Some(&comp_name_1),
+        component_version: Some(1),
+        resettable: true,
+        security_version: Some(security_version),
+        ..Default::default()
+    };
+    let config_descriptor_1 = diced_open_dice::retry_bcc_format_config_descriptor(&config_values_1)
+        .expect("failed to format config descriptor");
+    let input_values_1 = diced_open_dice::InputValues::new(
+        CODE_HASH_TRUSTY,
+        diced_open_dice::Config::Descriptor(config_descriptor_1.as_slice()),
+        AUTHORITY_HASH_TRUSTY,
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        HIDDEN_TRUSTY,
+    );
+    let (cdi_values_1, cert_1) = diced_open_dice::retry_dice_main_flow(&UDS, &UDS, &input_values_1)
+        .expect("Failed to run first main flow");
+
+    const CODE_HASH_ABL: [u8; diced_open_dice::HASH_SIZE] = [
+        0xa4, 0x0c, 0xcb, 0xc1, 0xbf, 0xfa, 0xcc, 0xfd, 0xeb, 0xf4, 0xfc, 0x43, 0x83, 0x7f, 0x46,
+        0x8d, 0xd8, 0xd8, 0x14, 0xc1, 0x96, 0x14, 0x1f, 0x6e, 0xb3, 0xa0, 0xd9, 0x56, 0xb3, 0xbf,
+        0x2f, 0xfa, 0x88, 0x70, 0x11, 0x07, 0x39, 0xa4, 0xd2, 0xa9, 0x6b, 0x18, 0x28, 0xe8, 0x29,
+        0x20, 0x49, 0x0f, 0xbb, 0x8d, 0x08, 0x8c, 0xc6, 0x54, 0xe9, 0x71, 0xd2, 0x7e, 0xa4, 0xfe,
+        0x58, 0x7f, 0xd3, 0xc7,
+    ];
+    const AUTHORITY_HASH_ABL: [u8; diced_open_dice::HASH_SIZE] = [
+        0xb2, 0x69, 0x05, 0x48, 0x56, 0xb5, 0xfa, 0x55, 0x6f, 0xac, 0x56, 0xd9, 0x02, 0x35, 0x2b,
+        0xaa, 0x4c, 0xba, 0x28, 0xdd, 0x82, 0x3a, 0x86, 0xf5, 0xd4, 0xc2, 0xf1, 0xf9, 0x35, 0x7d,
+        0xe4, 0x43, 0x13, 0xbf, 0xfe, 0xd3, 0x36, 0xd8, 0x1c, 0x12, 0x78, 0x5c, 0x9c, 0x3e, 0xf6,
+        0x66, 0xef, 0xab, 0x3d, 0x0f, 0x89, 0xa4, 0x6f, 0xc9, 0x72, 0xee, 0x73, 0x43, 0x02, 0x8a,
+        0xef, 0xbc, 0x05, 0x98,
+    ];
+    const HIDDEN_ABL: [u8; diced_open_dice::HIDDEN_SIZE] = [
+        0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x5e, 0x64, 0xe5, 0x64, 0x3f, 0xfd, 0x21,
+        0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a, 0xe2, 0x97, 0xdd, 0xe2, 0x4f, 0xb0, 0x7d, 0x7e,
+        0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x54, 0x41, 0x3f, 0x8f, 0x78, 0x64, 0x1a, 0x51, 0x27,
+        0x9d, 0x55, 0x8a, 0xe9, 0x90, 0x35, 0xab, 0x39, 0x80, 0x4b, 0x94, 0x40, 0x84, 0xa2, 0xfd,
+        0x73, 0xeb, 0x35, 0x7a,
+    ];
+
+    let comp_name_2 = CString::new("ABL").expect("CString::new failed");
+    let config_values_2 = diced_open_dice::DiceConfigValues {
+        component_name: Some(&comp_name_2),
+        component_version: Some(12),
+        resettable: true,
+        ..Default::default()
+    };
+    let config_descriptor_2 = diced_open_dice::retry_bcc_format_config_descriptor(&config_values_2)
+        .expect("failed to format config descriptor");
+
+    let input_values_2 = diced_open_dice::InputValues::new(
+        CODE_HASH_ABL,
+        diced_open_dice::Config::Descriptor(config_descriptor_2.as_slice()),
+        AUTHORITY_HASH_ABL,
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        HIDDEN_ABL,
+    );
+
+    let (cdi_values_2, cert_2) = diced_open_dice::retry_dice_main_flow(
+        &cdi_values_1.cdi_attest,
+        &cdi_values_1.cdi_seal,
+        &input_values_2,
+    )
+    .expect("Failed to run second main flow");
+
+    const CODE_HASH_PVMFW: [u8; diced_open_dice::HASH_SIZE] = [
+        0x08, 0x78, 0xc2, 0x5b, 0xe7, 0xea, 0x3d, 0x62, 0x70, 0x22, 0xd9, 0x1c, 0x4f, 0x3c, 0x2e,
+        0x2f, 0x0f, 0x97, 0xa4, 0x6f, 0x6d, 0xd5, 0xe6, 0x4a, 0x6d, 0xbe, 0x34, 0x2e, 0x56, 0x04,
+        0xaf, 0xef, 0x74, 0x3f, 0xec, 0xb8, 0x44, 0x11, 0xf4, 0x2f, 0x05, 0xb2, 0x06, 0xa3, 0x0e,
+        0x75, 0xb7, 0x40, 0x9a, 0x4c, 0x58, 0xab, 0x96, 0xe7, 0x07, 0x97, 0x07, 0x86, 0x5c, 0xa1,
+        0x42, 0x12, 0xf0, 0x34,
+    ];
+    const AUTHORITY_HASH_PVMFW: [u8; diced_open_dice::HASH_SIZE] = [
+        0xc7, 0x97, 0x5b, 0xa9, 0x9e, 0xbf, 0x0b, 0xeb, 0xe7, 0x7f, 0x69, 0x8f, 0x8e, 0xcf, 0x04,
+        0x7d, 0x2c, 0x0f, 0x4d, 0xbe, 0xcb, 0xf5, 0xf1, 0x4c, 0x1d, 0x1c, 0xb7, 0x44, 0xdf, 0xf8,
+        0x40, 0x90, 0x09, 0x65, 0xab, 0x01, 0x34, 0x3e, 0xc2, 0xc4, 0xf7, 0xa2, 0x3a, 0x5c, 0x4e,
+        0x76, 0x4f, 0x42, 0xa8, 0x6c, 0xc9, 0xf1, 0x7b, 0x12, 0x80, 0xa4, 0xef, 0xa2, 0x4d, 0x72,
+        0xa1, 0x21, 0xe2, 0x47,
+    ];
+    const HIDDEN_PVMFW: [u8; diced_open_dice::HIDDEN_SIZE] = [
+        0xa2, 0x01, 0xd0, 0xc0, 0xaa, 0x75, 0x3c, 0x06, 0x43, 0x98, 0x6c, 0xc3, 0x5a, 0xb5, 0x5f,
+        0x1f, 0x0f, 0x92, 0x44, 0x3b, 0x0e, 0xd4, 0x29, 0x75, 0xe3, 0xdb, 0x36, 0xda, 0xc8, 0x07,
+        0x97, 0x4d, 0xff, 0xbc, 0x6a, 0xa4, 0x8a, 0xef, 0xc4, 0x7f, 0xf8, 0x61, 0x7d, 0x51, 0x4d,
+        0x2f, 0xdf, 0x7e, 0x8c, 0x3d, 0xa3, 0xfc, 0x63, 0xd4, 0xd4, 0x74, 0x8a, 0xc4, 0x14, 0x45,
+        0x83, 0x6b, 0x12, 0x7e,
+    ];
+    const INSTANCE_HASH_PVMFW: [u8; 64] = [
+        0x5c, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4,
+        0x2a, 0x7d, 0x7e, 0xa5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
+        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x7d, 0x5b, 0x3f, 0xc9,
+        0x5b, 0xe2, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2f, 0x7d, 0x7e,
+        0xf5, 0x8e, 0xf5, 0x6e,
+    ];
+
+    let config_descriptor_3: Vec<(Value, Value)> = vec![
+        (Value::Integer(COMPONENT_NAME.into()), Value::Text("Protected VM firmware".to_string())),
+        (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
+        (Value::Integer(RESETTABLE.into()), Value::Null),
+        (Value::Integer(SECURITY_VERSION.into()), Value::Integer(security_version.into())),
+        // Add an arbitrary instance hash element to the config descriptor of PVMFW
+        (Value::Integer(INSTANCE_HASH.into()), Value::Bytes(INSTANCE_HASH_PVMFW.to_vec())),
+    ];
+    let config_descriptor_3 = Value::Map(config_descriptor_3)
+        .to_vec()
+        .expect("error in encoding the config descriptor 3");
+    let input_values_3 = diced_open_dice::InputValues::new(
+        CODE_HASH_PVMFW,
+        diced_open_dice::Config::Descriptor(config_descriptor_3.as_slice()),
+        AUTHORITY_HASH_PVMFW,
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        HIDDEN_PVMFW,
+    );
+
+    let (cdi_values_3, cert_3) = diced_open_dice::retry_dice_main_flow(
+        &cdi_values_2.cdi_attest,
+        &cdi_values_2.cdi_seal,
+        &input_values_3,
+    )
+    .expect("Failed to run third main flow");
+
+    const CODE_HASH_VM: [u8; diced_open_dice::HASH_SIZE] = [
+        0x41, 0x92, 0x0d, 0xd0, 0xf5, 0x60, 0xe3, 0x69, 0x26, 0x7f, 0xb8, 0xbc, 0x12, 0x3a, 0xd1,
+        0x95, 0x1d, 0xb8, 0x9a, 0x9c, 0x3a, 0x3f, 0x01, 0xbf, 0xa8, 0xd9, 0x6d, 0xe9, 0x90, 0x30,
+        0x1d, 0x0b, 0xaf, 0xef, 0x74, 0x3f, 0xec, 0xb8, 0x44, 0x11, 0xf4, 0x2f, 0x05, 0xb2, 0x06,
+        0xa3, 0x0e, 0x75, 0xb7, 0x40, 0x9a, 0x4c, 0x58, 0xab, 0x96, 0xe7, 0x07, 0x97, 0x07, 0x86,
+        0x5c, 0xa1, 0x42, 0x12,
+    ];
+    const AUTHORITY_HASH_VM: [u8; diced_open_dice::HASH_SIZE] = [
+        0xe3, 0xd9, 0x1c, 0xf5, 0x6f, 0xee, 0x73, 0x40, 0x3d, 0x95, 0x59, 0x67, 0xea, 0x5d, 0x01,
+        0xfd, 0x25, 0x9d, 0x5c, 0x88, 0x94, 0x3a, 0xc6, 0xd7, 0xa9, 0xdc, 0x4c, 0x60, 0x81, 0xbe,
+        0x2b, 0x74, 0x40, 0x90, 0x09, 0x65, 0xab, 0x01, 0x34, 0x3e, 0xc2, 0xc4, 0xf7, 0xa2, 0x3a,
+        0x5c, 0x4e, 0x76, 0x4f, 0x42, 0xa8, 0x6c, 0xc9, 0xf1, 0x7b, 0x12, 0x80, 0xa4, 0xef, 0xa2,
+        0x4d, 0x72, 0xa1, 0x21,
+    ];
+    const HIDDEN_VM: [u8; diced_open_dice::HIDDEN_SIZE] = [
+        0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x5e, 0x64, 0xe5, 0x64, 0x3f, 0xfd, 0x21,
+        0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a, 0xe2, 0x97, 0xdd, 0xe2, 0x4f, 0xb0, 0x7d, 0x7e,
+        0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x54, 0x41, 0x3f, 0x8f, 0x78, 0x64, 0x1a, 0x51, 0x27,
+        0x9d, 0x55, 0x8a, 0xe9, 0x90, 0x35, 0xab, 0x39, 0x80, 0x4b, 0x94, 0x40, 0x84, 0xa2, 0xfd,
+        0x73, 0xeb, 0x35, 0x7a,
+    ];
+
+    let mut config_descriptor_4: Vec<(Value, Value)> = vec![
+        (Value::Integer(COMPONENT_NAME.into()), Value::Text(GUEST_OS_COMPONENT_NAME.to_string())),
+        (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
+        (Value::Integer(RESETTABLE.into()), Value::Null),
+        (Value::Integer(SECURITY_VERSION.into()), Value::Integer(security_version.into())),
+    ];
+    if let Some(instance_hash) = instance_hash_for_vm_entry {
+        config_descriptor_4
+            .push((Value::Integer(INSTANCE_HASH.into()), Value::Bytes(instance_hash.to_vec())));
+    };
+    let config_descriptor_4 = Value::Map(config_descriptor_4)
+        .to_vec()
+        .expect("error in encoding the config descriptor 4");
+
+    let input_values_4 = diced_open_dice::InputValues::new(
+        CODE_HASH_VM,
+        diced_open_dice::Config::Descriptor(config_descriptor_4.as_slice()),
+        AUTHORITY_HASH_VM,
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        HIDDEN_VM,
+    );
+
+    let (cdi_values_4, cert_4) = diced_open_dice::retry_dice_main_flow(
+        &cdi_values_3.cdi_attest,
+        &cdi_values_3.cdi_seal,
+        &input_values_4,
+    )
+    .expect("Failed to run fourth main flow");
+
+    const CODE_HASH_PAYLOAD: [u8; diced_open_dice::HASH_SIZE] = [
+        0x52, 0x93, 0x2b, 0xb0, 0x8d, 0xec, 0xdf, 0x54, 0x1f, 0x5c, 0x10, 0x9d, 0x17, 0xce, 0x7f,
+        0xac, 0xb0, 0x2b, 0xe2, 0x99, 0x05, 0x7d, 0xa3, 0x9b, 0xa6, 0x3e, 0xf9, 0x99, 0xa2, 0xea,
+        0xd4, 0xd9, 0x1d, 0x0b, 0xaf, 0xef, 0x74, 0x3f, 0xec, 0xb8, 0x44, 0x11, 0xf4, 0x2f, 0x05,
+        0xb2, 0x06, 0xa3, 0x0e, 0x75, 0xb7, 0x40, 0x9a, 0x4c, 0x58, 0xab, 0x96, 0xe7, 0x07, 0x97,
+        0x07, 0x86, 0x5c, 0xa1,
+    ];
+    const AUTHORITY_HASH_PAYLOAD: [u8; diced_open_dice::HASH_SIZE] = [
+        0xd1, 0xfc, 0x3d, 0x5f, 0xa0, 0x5f, 0x02, 0xd0, 0x83, 0x9b, 0x0e, 0x32, 0xc2, 0x27, 0x09,
+        0x12, 0xcc, 0xfc, 0x42, 0xf6, 0x0d, 0xf4, 0x7d, 0xc8, 0x80, 0x1a, 0x64, 0x25, 0xa7, 0xfa,
+        0x4a, 0x37, 0x2b, 0x74, 0x40, 0x90, 0x09, 0x65, 0xab, 0x01, 0x34, 0x3e, 0xc2, 0xc4, 0xf7,
+        0xa2, 0x3a, 0x5c, 0x4e, 0x76, 0x4f, 0x42, 0xa8, 0x6c, 0xc9, 0xf1, 0x7b, 0x12, 0x80, 0xa4,
+        0xef, 0xa2, 0x4d, 0x72,
+    ];
+    const INSTANCE_HASH_PAYLOAD: [u8; 64] = [
+        0x4c, 0x3f, 0xa9, 0x6b, 0xa3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4,
+        0x2a, 0x7d, 0x7e, 0xa5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
+        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x7d, 0x5b, 0x3f, 0xc9,
+        0x5b, 0xe2, 0x95, 0x52, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2f, 0x7d, 0x7e,
+        0xf5, 0x8e, 0xf5, 0x6f,
+    ];
+
+    let config_descriptor_5: Vec<(Value, Value)> = vec![
+        (Value::Integer(COMPONENT_NAME.into()), Value::Text("Payload".to_string())),
+        (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
+        (Value::Integer(RESETTABLE.into()), Value::Null),
+        // Add an arbitrary instance hash element to the config descriptor of Payload
+        (Value::Integer(INSTANCE_HASH.into()), Value::Bytes(INSTANCE_HASH_PAYLOAD.to_vec())),
+    ];
+    let config_descriptor_5 = Value::Map(config_descriptor_5)
+        .to_vec()
+        .expect("error in encoding the config descriptor 5");
+
+    let input_values_5 = diced_open_dice::InputValues::new(
+        CODE_HASH_PAYLOAD,
+        diced_open_dice::Config::Descriptor(config_descriptor_5.as_slice()),
+        AUTHORITY_HASH_PAYLOAD,
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        [0u8; diced_open_dice::HIDDEN_SIZE],
+    );
+
+    let (cdi_values_5, cert_5) = diced_open_dice::retry_dice_main_flow(
+        &cdi_values_4.cdi_attest,
+        &cdi_values_4.cdi_seal,
+        &input_values_5,
+    )
+    .expect("Failed to run fifth main flow");
+
+    let cert_chain = Value::Array(vec![
+        Value::Integer(EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION.into()),
+        Value::Bytes(root_pub_cose_key_bstr.clone()),
+        Value::from_slice(&cert_1).expect("failed to deserialize the certificate into CBOR"),
+        Value::from_slice(&cert_2).expect("failed to deserialize the certificate into CBOR"),
+        Value::from_slice(&cert_3).expect("failed to deserialize the certificate into CBOR"),
+        Value::from_slice(&cert_4).expect("failed to deserialize the certificate into CBOR"),
+        Value::from_slice(&cert_5).expect("failed to deserialize the certificate into CBOR"),
+    ]);
+    let pvt_key_seed =
+        diced_open_dice::derive_cdi_private_key_seed(&cdi_values_5.cdi_attest).unwrap();
+    let (_, pvt_key) = diced_open_dice::keypair_from_seed(pvt_key_seed.as_array())
+        .expect("failed to create key pair from seed.");
+    let pvt_key: [u8; CURVE25519_PRIV_KEY_LEN] = pvt_key.as_array()[0..CURVE25519_PRIV_KEY_LEN]
+        .try_into()
+        .expect("error in constructing the private signing key {:?}");
+    (
+        EcSignKey::Ed25519(pvt_key),
+        cdi_values_5,
+        cert_chain.to_vec().expect("error in encoding the cert chain to bytes"),
+    )
+}
+
+/// Helper function for testing which derives child DICE artifacts and creates a certificate
+pub fn create_dice_leaf_cert(
+    parent_cdi_values: CdiValues,
+    component_name: &str,
+    security_version: u64,
+) -> Vec<u8> {
+    let comp_name = CString::new(component_name).expect("CString::new failed");
+    let config_values = diced_open_dice::DiceConfigValues {
+        component_name: Some(&comp_name),
+        component_version: Some(1),
+        resettable: true,
+        security_version: Some(security_version),
+        ..Default::default()
+    };
+    let config_descriptor = diced_open_dice::retry_bcc_format_config_descriptor(&config_values)
+        .expect("failed to format config descriptor");
+    let input_values = diced_open_dice::InputValues::new(
+        [0u8; diced_open_dice::HASH_SIZE],
+        diced_open_dice::Config::Descriptor(config_descriptor.as_slice()),
+        [0u8; diced_open_dice::HASH_SIZE],
+        diced_open_dice::DiceMode::kDiceModeDebug,
+        [0u8; diced_open_dice::HASH_SIZE],
+    );
+    let (_, leaf_cert) = diced_open_dice::retry_dice_main_flow(
+        &parent_cdi_values.cdi_attest,
+        &parent_cdi_values.cdi_seal,
+        &input_values,
+    )
+    .expect("Failed to run first main flow");
+    leaf_cert
+}
diff --git a/wire/src/fragmentation.rs b/wire/src/fragmentation.rs
index 1d6e796..969ed28 100644
--- a/wire/src/fragmentation.rs
+++ b/wire/src/fragmentation.rs
@@ -39,7 +39,7 @@ impl<'a> Fragmenter<'a> {
     }
 }
 
-impl<'a> Iterator for Fragmenter<'a> {
+impl Iterator for Fragmenter<'_> {
     type Item = Vec<u8>;
     fn next(&mut self) -> Option<Self::Item> {
         if self.data.is_empty() {
```

