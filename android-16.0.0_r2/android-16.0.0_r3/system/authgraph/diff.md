```diff
diff --git a/core/src/error.rs b/core/src/error.rs
index 830296b..62fc017 100644
--- a/core/src/error.rs
+++ b/core/src/error.rs
@@ -21,7 +21,7 @@ use authgraph_wire::ErrorCode;
 use coset::CoseError;
 
 /// AuthGraph error type.
-#[derive(Debug)]
+#[derive(Debug, PartialEq)]
 pub struct Error(pub ErrorCode, pub String);
 
 impl core::convert::From<CoseError> for Error {
diff --git a/core/src/key.rs b/core/src/key.rs
index e04d3a1..596bc80 100644
--- a/core/src/key.rs
+++ b/core/src/key.rs
@@ -626,9 +626,8 @@ impl CertChain {
     }
 
     /// Extract the instance identifier (a.k.a. instance hash) from a pVM DICE chain as per
-    /// packages/modules/Virtualization/dice_for_avf_guest.cddl. We are specifically looking for the
-    /// instance hash included in the DICE certificate that has the component name = "vm_entry",
-    /// which is set by the PVMFW. If not present, return None.
+    /// packages/modules/Virtualization/dice_for_avf_guest.cddl. We search backwards from the leaf
+    /// and return the first instance hash we find. If not present, return None.
     pub fn extract_instance_identifier_in_guest_os_entry(
         &self,
     ) -> Result<Option<InstanceIdentifier>, Error> {
@@ -636,23 +635,15 @@ impl CertChain {
         // as `DiceChainEntryPayload` and check if instance identifier is present
         if let Some(dice_cert_chain) = &self.dice_cert_chain {
             for dice_cert in dice_cert_chain.iter().rev() {
-                if let Some(v) = &dice_cert.payload.full_map {
-                    let dice_chain_entry_payload =
-                        DiceChainEntryPayload::from_cbor_value(v.clone())?;
+                if let Some(dice_chain_entry_payload) = &dice_cert.payload.get_full_payload()? {
                     if let Some(ConfigurationDescriptorOrLegacy::Descriptor(config_desc)) =
-                        dice_chain_entry_payload.configuration_descriptor
+                        &dice_chain_entry_payload.configuration_descriptor
                     {
-                        if config_desc
-                            .component_name
-                            .map_or(false, |comp_name| comp_name == GUEST_OS_COMPONENT_NAME)
+                        let instance_hash_tuple =
+                            config_desc.custom_fields.iter().find(|v| v.0 == INSTANCE_HASH);
+                        if let Some((_, Value::Bytes(instance_hash))) = instance_hash_tuple.cloned()
                         {
-                            let instance_hash_tuple =
-                                config_desc.custom_fields.iter().find(|v| v.0 == INSTANCE_HASH);
-                            if let Some((_, Value::Bytes(instance_hash))) =
-                                instance_hash_tuple.cloned()
-                            {
-                                return Ok(Some(instance_hash));
-                            }
+                            return Ok(Some(instance_hash));
                         }
                     }
                 }
@@ -732,6 +723,46 @@ impl CertChain {
         }
         false
     }
+
+    /// Get the component name on the leaf cert of this CertChain.
+    /// On success this returns Ok(Some(String)), with the component name
+    /// of the leaf cert.
+    ///
+    /// If there is no leaf cert, or no component name on the leaf cert
+    /// this returns Ok(None).
+    ///
+    /// Otherwise, an Error is returned.
+    pub fn get_leaf_cert_component_name(&self) -> Result<Option<String>, Error> {
+        let chain = match &self.dice_cert_chain {
+            Some(x) => x,
+            // No cert chain
+            None => return Ok(None),
+        };
+
+        let last_cert = match chain.last() {
+            Some(x) => x,
+            // Empty cert chain
+            None => return Ok(None),
+        };
+
+        let full_payload = match last_cert.payload.get_full_payload()? {
+            Some(x) => x,
+            // No full map for this cert
+            None => return Ok(None),
+        };
+
+        match full_payload.configuration_descriptor {
+            Some(desc) => match desc {
+                ConfigurationDescriptorOrLegacy::Descriptor(desc) => Ok(desc.component_name),
+                ConfigurationDescriptorOrLegacy::Legacy(_) => Err(ag_err!(
+                    Unimplemented,
+                    "Cannot retrieve component name from legacy descriptor"
+                )),
+            },
+            // No config descriptor
+            None => Ok(None),
+        }
+    }
 }
 
 impl AsCborValue for CertChain {
@@ -819,6 +850,18 @@ impl AsCborValue for DiceChainEntry {
     }
 }
 
+impl DiceChainEntryPayloadPartiallyDecoded {
+    /// Get the complete DiceChainEntryPayload from the full map of this partially
+    /// decoded payload.
+    pub fn get_full_payload(&self) -> Result<Option<DiceChainEntryPayload>, Error> {
+        if let Some(v) = &self.full_map {
+            Ok(Some(DiceChainEntryPayload::from_cbor_value(v.clone())?))
+        } else {
+            Ok(None)
+        }
+    }
+}
+
 impl CborSerializable for DiceChainEntryPayloadPartiallyDecoded {}
 
 impl AsCborValue for DiceChainEntryPayloadPartiallyDecoded {
diff --git a/core/tests/lib.rs b/core/tests/lib.rs
index 54bc2ff..ed452f2 100644
--- a/core/tests/lib.rs
+++ b/core/tests/lib.rs
@@ -29,7 +29,8 @@ mod tests {
         Identity,
     };
     use authgraph_core_test::{
-        create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
+        create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, create_identity,
+        SAMPLE_INSTANCE_HASH, TEST_OS_COMPONENT_NAME,
     };
     use coset::CborSerializable;
 
@@ -191,4 +192,28 @@ mod tests {
             CertChain::from_slice(&cert_chain_bytes_2).expect("failed to decode dice chain 2");
         assert!(dice_chain_2.extend_with(&leaf_cert, &ecdsa).is_err());
     }
+
+    #[test]
+    fn test_leaf_cert_component_name_no_cert_chain() {
+        let (_, serialized_identity) =
+            create_identity(0 /*no cert chain */).expect("error in creating identity");
+        let identity =
+            Identity::from_slice(&serialized_identity).expect("error in decoding the identity");
+
+        assert_eq!(Ok(None), identity.cert_chain.get_leaf_cert_component_name());
+    }
+
+    #[test]
+    fn test_leaf_cert_component_name() {
+        let (_, _, serialized_chain) =
+            create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        let dice_chain_res = CertChain::from_slice(&serialized_chain);
+        assert!(dice_chain_res.is_ok());
+        let dice_chain = dice_chain_res.unwrap();
+
+        assert_eq!(
+            Ok(Some(TEST_OS_COMPONENT_NAME.to_string())),
+            dice_chain.get_leaf_cert_component_name()
+        );
+    }
 }
diff --git a/tests/src/lib.rs b/tests/src/lib.rs
index f9b9969..b7f6f7f 100644
--- a/tests/src/lib.rs
+++ b/tests/src/lib.rs
@@ -4,8 +4,8 @@ extern crate alloc;
 use authgraph_core::key::{
     AesKey, EcSignKey, EcVerifyKey, EcdhSecret, HmacKey, Identity, Key, Nonce12, PseudoRandKey,
     COMPONENT_NAME, COMPONENT_VERSION, CURVE25519_PRIV_KEY_LEN,
-    EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, GUEST_OS_COMPONENT_NAME, IDENTITY_VERSION, INSTANCE_HASH,
-    RESETTABLE, SECURITY_VERSION,
+    EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, IDENTITY_VERSION, INSTANCE_HASH, RESETTABLE,
+    SECURITY_VERSION,
 };
 use authgraph_core::keyexchange;
 use authgraph_core::traits::{
@@ -22,6 +22,10 @@ use coset::{
 pub use diced_open_dice::CdiValues;
 use std::ffi::CString;
 
+/// The OS name is placed into the config descriptor component name field
+/// as if it were provided in the avb footer android.virt.name.
+pub const TEST_OS_COMPONENT_NAME: &str = "test_vm_entry";
+
 /// UDS used to create the DICE chains in this test-util library.
 pub const UDS: [u8; diced_open_dice::CDI_SIZE] = [
     0x1d, 0xa5, 0xea, 0x90, 0x47, 0xfc, 0xb5, 0xf6, 0x47, 0x12, 0xd3, 0x65, 0x9c, 0xf2, 0x00, 0xe0,
@@ -1390,21 +1394,12 @@ pub fn create_dice_cert_chain_for_guest_os(
         0x2f, 0xdf, 0x7e, 0x8c, 0x3d, 0xa3, 0xfc, 0x63, 0xd4, 0xd4, 0x74, 0x8a, 0xc4, 0x14, 0x45,
         0x83, 0x6b, 0x12, 0x7e,
     ];
-    const INSTANCE_HASH_PVMFW: [u8; 64] = [
-        0x5c, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4,
-        0x2a, 0x7d, 0x7e, 0xa5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
-        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x7d, 0x5b, 0x3f, 0xc9,
-        0x5b, 0xe2, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2f, 0x7d, 0x7e,
-        0xf5, 0x8e, 0xf5, 0x6e,
-    ];
 
     let config_descriptor_3: Vec<(Value, Value)> = vec![
         (Value::Integer(COMPONENT_NAME.into()), Value::Text("Protected VM firmware".to_string())),
         (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
         (Value::Integer(RESETTABLE.into()), Value::Null),
         (Value::Integer(SECURITY_VERSION.into()), Value::Integer(security_version.into())),
-        // Add an arbitrary instance hash element to the config descriptor of PVMFW
-        (Value::Integer(INSTANCE_HASH.into()), Value::Bytes(INSTANCE_HASH_PVMFW.to_vec())),
     ];
     let config_descriptor_3 = Value::Map(config_descriptor_3)
         .to_vec()
@@ -1447,7 +1442,7 @@ pub fn create_dice_cert_chain_for_guest_os(
     ];
 
     let mut config_descriptor_4: Vec<(Value, Value)> = vec![
-        (Value::Integer(COMPONENT_NAME.into()), Value::Text(GUEST_OS_COMPONENT_NAME.to_string())),
+        (Value::Integer(COMPONENT_NAME.into()), Value::Text(TEST_OS_COMPONENT_NAME.to_string())),
         (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
         (Value::Integer(RESETTABLE.into()), Value::Null),
         (Value::Integer(SECURITY_VERSION.into()), Value::Integer(security_version.into())),
@@ -1475,54 +1470,6 @@ pub fn create_dice_cert_chain_for_guest_os(
     )
     .expect("Failed to run fourth main flow");
 
-    const CODE_HASH_PAYLOAD: [u8; diced_open_dice::HASH_SIZE] = [
-        0x52, 0x93, 0x2b, 0xb0, 0x8d, 0xec, 0xdf, 0x54, 0x1f, 0x5c, 0x10, 0x9d, 0x17, 0xce, 0x7f,
-        0xac, 0xb0, 0x2b, 0xe2, 0x99, 0x05, 0x7d, 0xa3, 0x9b, 0xa6, 0x3e, 0xf9, 0x99, 0xa2, 0xea,
-        0xd4, 0xd9, 0x1d, 0x0b, 0xaf, 0xef, 0x74, 0x3f, 0xec, 0xb8, 0x44, 0x11, 0xf4, 0x2f, 0x05,
-        0xb2, 0x06, 0xa3, 0x0e, 0x75, 0xb7, 0x40, 0x9a, 0x4c, 0x58, 0xab, 0x96, 0xe7, 0x07, 0x97,
-        0x07, 0x86, 0x5c, 0xa1,
-    ];
-    const AUTHORITY_HASH_PAYLOAD: [u8; diced_open_dice::HASH_SIZE] = [
-        0xd1, 0xfc, 0x3d, 0x5f, 0xa0, 0x5f, 0x02, 0xd0, 0x83, 0x9b, 0x0e, 0x32, 0xc2, 0x27, 0x09,
-        0x12, 0xcc, 0xfc, 0x42, 0xf6, 0x0d, 0xf4, 0x7d, 0xc8, 0x80, 0x1a, 0x64, 0x25, 0xa7, 0xfa,
-        0x4a, 0x37, 0x2b, 0x74, 0x40, 0x90, 0x09, 0x65, 0xab, 0x01, 0x34, 0x3e, 0xc2, 0xc4, 0xf7,
-        0xa2, 0x3a, 0x5c, 0x4e, 0x76, 0x4f, 0x42, 0xa8, 0x6c, 0xc9, 0xf1, 0x7b, 0x12, 0x80, 0xa4,
-        0xef, 0xa2, 0x4d, 0x72,
-    ];
-    const INSTANCE_HASH_PAYLOAD: [u8; 64] = [
-        0x4c, 0x3f, 0xa9, 0x6b, 0xa3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4,
-        0x2a, 0x7d, 0x7e, 0xa5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
-        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x7d, 0x5b, 0x3f, 0xc9,
-        0x5b, 0xe2, 0x95, 0x52, 0x40, 0x21, 0x09, 0x9d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2f, 0x7d, 0x7e,
-        0xf5, 0x8e, 0xf5, 0x6f,
-    ];
-
-    let config_descriptor_5: Vec<(Value, Value)> = vec![
-        (Value::Integer(COMPONENT_NAME.into()), Value::Text("Payload".to_string())),
-        (Value::Integer(COMPONENT_VERSION.into()), Value::Integer(12.into())),
-        (Value::Integer(RESETTABLE.into()), Value::Null),
-        // Add an arbitrary instance hash element to the config descriptor of Payload
-        (Value::Integer(INSTANCE_HASH.into()), Value::Bytes(INSTANCE_HASH_PAYLOAD.to_vec())),
-    ];
-    let config_descriptor_5 = Value::Map(config_descriptor_5)
-        .to_vec()
-        .expect("error in encoding the config descriptor 5");
-
-    let input_values_5 = diced_open_dice::InputValues::new(
-        CODE_HASH_PAYLOAD,
-        diced_open_dice::Config::Descriptor(config_descriptor_5.as_slice()),
-        AUTHORITY_HASH_PAYLOAD,
-        diced_open_dice::DiceMode::kDiceModeDebug,
-        [0u8; diced_open_dice::HIDDEN_SIZE],
-    );
-
-    let (cdi_values_5, cert_5) = diced_open_dice::retry_dice_main_flow(
-        &cdi_values_4.cdi_attest,
-        &cdi_values_4.cdi_seal,
-        &input_values_5,
-    )
-    .expect("Failed to run fifth main flow");
-
     let cert_chain = Value::Array(vec![
         Value::Integer(EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION.into()),
         Value::Bytes(root_pub_cose_key_bstr.clone()),
@@ -1530,10 +1477,9 @@ pub fn create_dice_cert_chain_for_guest_os(
         Value::from_slice(&cert_2).expect("failed to deserialize the certificate into CBOR"),
         Value::from_slice(&cert_3).expect("failed to deserialize the certificate into CBOR"),
         Value::from_slice(&cert_4).expect("failed to deserialize the certificate into CBOR"),
-        Value::from_slice(&cert_5).expect("failed to deserialize the certificate into CBOR"),
     ]);
     let pvt_key_seed =
-        diced_open_dice::derive_cdi_private_key_seed(&cdi_values_5.cdi_attest).unwrap();
+        diced_open_dice::derive_cdi_private_key_seed(&cdi_values_4.cdi_attest).unwrap();
     let (_, pvt_key) = diced_open_dice::keypair_from_seed(pvt_key_seed.as_array())
         .expect("failed to create key pair from seed.");
     let pvt_key: [u8; CURVE25519_PRIV_KEY_LEN] = pvt_key.as_array()[0..CURVE25519_PRIV_KEY_LEN]
@@ -1541,7 +1487,7 @@ pub fn create_dice_cert_chain_for_guest_os(
         .expect("error in constructing the private signing key {:?}");
     (
         EcSignKey::Ed25519(pvt_key),
-        cdi_values_5,
+        cdi_values_4,
         cert_chain.to_vec().expect("error in encoding the cert chain to bytes"),
     )
 }
```

