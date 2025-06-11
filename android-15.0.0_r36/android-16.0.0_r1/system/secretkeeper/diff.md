```diff
diff --git a/OWNERS b/OWNERS
index 524278a..8cf7c1f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
-alanstokes@google.com
 aliceywang@google.com
 drysdale@google.com
 paulcrowley@google.com
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 0a2f0cd..080dd06 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -13,7 +13,7 @@
       "name": "libdice_policy.test"
     },
     {
-      "name": "libsecretkeeper_client.test"
+      "name": "libexplicitkeydice.test"
     },
     {
       "name": "libsecretkeeper_comm.test"
diff --git a/client/Android.bp b/client/Android.bp
index 8397c0b..ecb5a77 100644
--- a/client/Android.bp
+++ b/client/Android.bp
@@ -32,10 +32,10 @@ rust_defaults {
         "libauthgraph_boringssl",
         "libauthgraph_wire",
         "libbinder_rs",
-        "libciborium",
         "libcoset",
-        "libhex",
         "libdiced_open_dice",
+        "libexplicitkeydice",
+        "libhex",
         // TODO(b/315464358): Use the std version
         "libsecretkeeper_comm_nostd",
         // TODO(b/291228655): This is required for 'cipher', refactor to cut this dependency.
@@ -49,14 +49,31 @@ rust_library {
     srcs: ["src/lib.rs"],
 }
 
+rust_library {
+    name: "libexplicitkeydice",
+    crate_name: "explicitkeydice",
+    edition: "2021",
+    lints: "android",
+    srcs: ["src/dice.rs"],
+    rustlibs: [
+        "libciborium",
+        "libcoset",
+        "libdiced_open_dice",
+    ],
+    vendor_available: true,
+    min_sdk_version: "35",
+}
+
 rust_test {
-    name: "libsecretkeeper_client.test",
+    name: "libexplicitkeydice.test",
     defaults: [
-        "libsecretkeeper_client.defaults",
         "rdroidtest.defaults",
     ],
-    srcs: ["src/lib.rs"],
+    srcs: ["src/dice.rs"],
     rustlibs: [
+        "libciborium",
+        "libcoset",
+        "libdiced_open_dice",
         "libhex",
     ],
     test_suites: ["general-tests"],
diff --git a/client/src/authgraph_dev.rs b/client/src/authgraph_dev.rs
index 3784048..2900d84 100644
--- a/client/src/authgraph_dev.rs
+++ b/client/src/authgraph_dev.rs
@@ -20,7 +20,6 @@
 
 extern crate alloc;
 
-use crate::dice::OwnedDiceArtifactsWithExplicitKey;
 use authgraph_boringssl::{BoringAes, BoringRng};
 use authgraph_core::ag_err;
 use authgraph_core::error::Error as AgError;
@@ -36,9 +35,11 @@ use authgraph_wire::{ErrorCode, SESSION_ID_LEN};
 use coset::CborSerializable;
 use coset::{iana, CoseKey};
 use diced_open_dice::derive_cdi_leaf_priv;
+use explicitkeydice::OwnedDiceArtifactsWithExplicitKey;
 
 /// Implementation of `authgraph_core::traits::Device` required for configuring the local
 /// `AuthGraphParticipant` for client.
+#[derive(Clone)]
 pub struct AgDevice {
     per_boot_key: AesKey,
     identity: (EcSignKey, Identity),
diff --git a/client/src/dice.rs b/client/src/dice.rs
index c45e49a..356a0d5 100644
--- a/client/src/dice.rs
+++ b/client/src/dice.rs
@@ -16,7 +16,6 @@
 
 //! Support for explicit key chain format & conversion from legacy DiceArtifacts.
 
-use crate::Error;
 use ciborium::Value;
 use coset::{AsCborValue, CborOrdering, CborSerializable, CoseKey};
 use diced_open_dice::{DiceArtifacts, OwnedDiceArtifacts, CDI_SIZE};
@@ -24,6 +23,34 @@ use std::fmt;
 
 const EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION: u64 = 1;
 
+/// Error type thrown in OwnedDiceArtifactsWithExplicitKey struct
+#[derive(Debug)]
+pub enum Error {
+    /// Errors originating in the coset library.
+    CoseError(coset::CoseError),
+    /// Unexpected item encountered (got, want).
+    UnexpectedItem(&'static str, &'static str),
+}
+
+impl std::error::Error for Error {}
+
+impl std::fmt::Display for Error {
+    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
+        match self {
+            Self::CoseError(e) => write!(f, "Errors originating in the coset library {e:?}"),
+            Self::UnexpectedItem(got, want) => {
+                write!(f, "Unexpected item - Got:{got}, Expected:{want}")
+            }
+        }
+    }
+}
+
+impl From<coset::CoseError> for Error {
+    fn from(e: coset::CoseError) -> Self {
+        Self::CoseError(e)
+    }
+}
+
 /// An OwnedDiceArtifactsWithExplicitKey is an OwnedDiceArtifacts that also exposes its
 /// DICE chain (BCC) in explicit key format.
 pub struct OwnedDiceArtifactsWithExplicitKey {
@@ -75,10 +102,10 @@ impl DiceArtifacts for OwnedDiceArtifactsWithExplicitKey {
     }
 }
 
-// Convert a DICE chain to explicit key format. Note that this method checks if the input is
-// already in the Explicit-key format & returns it if so. The check is lightweight though.
-// A twisted incorrect dice chain input may produce incorrect output.
-fn to_explicit_chain(dice_chain_bytes: &[u8]) -> Result<Vec<u8>, Error> {
+/// Convert a DICE chain to explicit key format. Note that this method checks if the input is
+/// already in the Explicit-key format & returns it if so. The check is lightweight though.
+/// A twisted incorrect dice chain input may produce incorrect output.
+pub fn to_explicit_chain(dice_chain_bytes: &[u8]) -> Result<Vec<u8>, Error> {
     let dice_chain = deserialize_cbor_array(dice_chain_bytes)?;
     // Check if the dice_chain is already in explicit key format
     if matches!(&&dice_chain[..], [Value::Integer(_version), Value::Bytes(_public_key), ..]) {
@@ -106,6 +133,9 @@ fn deserialize_cbor_array(cbor_array: &[u8]) -> Result<Vec<Value>, Error> {
     value.into_array().map_err(|_| Error::UnexpectedItem("-", "Array"))
 }
 
+#[cfg(test)]
+rdroidtest::test_main!();
+
 #[cfg(test)]
 mod tests {
     use super::*;
diff --git a/client/src/lib.rs b/client/src/lib.rs
index ee8a31b..1a1c4fd 100644
--- a/client/src/lib.rs
+++ b/client/src/lib.rs
@@ -18,10 +18,8 @@
 //! and the messages is encrypted/decrypted using the shared keys.
 
 mod authgraph_dev;
-pub mod dice;
 
 use crate::authgraph_dev::AgDevice;
-use crate::dice::OwnedDiceArtifactsWithExplicitKey;
 
 use authgraph_boringssl as boring;
 use authgraph_core::keyexchange as ke;
@@ -33,6 +31,7 @@ use android_hardware_security_authgraph::aidl::android::hardware::security::auth
     SessionIdSignature::SessionIdSignature, Identity::Identity,
 };
 use coset::{CoseKey, CborSerializable, CoseEncrypt0};
+use explicitkeydice::OwnedDiceArtifactsWithExplicitKey;
 use secretkeeper_core::cipher;
 use secretkeeper_comm::data_types::SeqNum;
 use secretkeeper_comm::wire::ApiError;
@@ -40,7 +39,7 @@ use std::cell::RefCell;
 use std::fmt;
 use std::rc::Rc;
 
-/// A Secretkeeper session that can be used by client, this encapsulates the Authgraph Key exchange
+/// A Secretkeeper session that can be used by client, this encapsulates the AuthGraph Key exchange
 /// session as well as the encryption/decryption of request/response to/from Secretkeeper.
 pub struct SkSession {
     sk: binder::Strong<dyn ISecretkeeper>,
@@ -52,10 +51,12 @@ pub struct SkSession {
     seq_num_outgoing: SeqNum,
     // Sequence number for decrypting the next incoming message.
     seq_num_incoming: SeqNum,
+    // The local AuthGraph Device impl - encapsulates the local identity etc.
+    authgraph_participant: AgDevice,
 }
 
 impl SkSession {
-    /// Create a new Secretkeeper session. This triggers an AuthgraphKeyExchange protocol with a
+    /// Create a new Secretkeeper session. This triggers an AuthGraphKeyExchange protocol with a
     /// local `source` and remote `sink`.
     ///
     /// # Arguments
@@ -70,9 +71,11 @@ impl SkSession {
         dice: &OwnedDiceArtifactsWithExplicitKey,
         expected_sk_key: Option<CoseKey>,
     ) -> Result<Self, Error> {
-        let ag_dev = Rc::new(RefCell::new(AgDevice::new(dice, expected_sk_key)?));
-        let ([encryption_key, decryption_key], session_id) =
-            authgraph_key_exchange(sk.clone(), ag_dev.clone())?;
+        let authgraph_participant = AgDevice::new(dice, expected_sk_key)?;
+        let ([encryption_key, decryption_key], session_id) = authgraph_key_exchange(
+            sk.clone(),
+            Rc::new(RefCell::new(authgraph_participant.clone())),
+        )?;
         Ok(Self {
             sk,
             encryption_key,
@@ -80,9 +83,25 @@ impl SkSession {
             session_id,
             seq_num_outgoing: SeqNum::new(),
             seq_num_incoming: SeqNum::new(),
+            authgraph_participant,
         })
     }
 
+    /// Refresh the existing Secretkeeper session. This reuses the client
+    /// identity & per_boot_key, does AuthGraphKeyExchange resetting the keys!
+    pub fn refresh(&mut self) -> Result<(), Error> {
+        let ([encryption_key, decryption_key], session_id) = authgraph_key_exchange(
+            self.sk.clone(),
+            Rc::new(RefCell::new(self.authgraph_participant.clone())),
+        )?;
+        self.encryption_key = encryption_key;
+        self.decryption_key = decryption_key;
+        self.session_id = session_id;
+        self.seq_num_outgoing = SeqNum::new();
+        self.seq_num_incoming = SeqNum::new();
+        Ok(())
+    }
+
     /// Wrapper around `ISecretkeeper::processSecretManagementRequest`. This additionally handles
     /// encryption and decryption.
     pub fn secret_management_request(&mut self, req_data: &[u8]) -> Result<Vec<u8>, Error> {
@@ -278,6 +297,3 @@ fn vec_to_identity(data: &[u8]) -> Identity {
 fn vec_to_signature(data: &[u8]) -> SessionIdSignature {
     SessionIdSignature { signature: data.to_vec() }
 }
-
-#[cfg(test)]
-rdroidtest::test_main!();
diff --git a/dice_policy/Android.bp b/dice_policy/Android.bp
index a96b0d1..9cdfcca 100644
--- a/dice_policy/Android.bp
+++ b/dice_policy/Android.bp
@@ -20,4 +20,6 @@ rust_library {
     name: "libdice_policy",
     defaults: ["libdice_policy.defaults"],
     srcs: ["src/lib.rs"],
+    host_supported: true,
+    min_sdk_version: "35",
 }
diff --git a/dice_policy/building/Android.bp b/dice_policy/building/Android.bp
index 143b872..c6fd19b 100644
--- a/dice_policy/building/Android.bp
+++ b/dice_policy/building/Android.bp
@@ -17,9 +17,11 @@ rust_defaults {
     ],
     proc_macros: ["libenumn"],
     vendor_available: true,
+    host_supported: true,
 }
 
 rust_library {
     name: "libdice_policy_builder",
     defaults: ["libdice_policy_builder.defaults"],
+    host_supported: true,
 }
diff --git a/dice_policy/building/src/lib.rs b/dice_policy/building/src/lib.rs
index a45b19c..20ec705 100644
--- a/dice_policy/building/src/lib.rs
+++ b/dice_policy/building/src/lib.rs
@@ -197,7 +197,7 @@ pub enum MissingAction {
 /// `dice_chain`: The serialized CBOR encoded Dice chain, adhering to Explicit-key
 /// DiceCertChain format. See definition at ExplicitKeyDiceCertChain.cddl
 ///
-/// `constraint_spec`: List of constraints to be applied on dice node.
+/// `ConstraintSpec`: List of constraints to be applied on dice node.
 /// Each constraint is a ConstraintSpec object.
 ///
 /// Note: Dice node is treated as a nested structure (map or array) (& so the lookup is done in
@@ -236,7 +236,7 @@ pub fn policy_for_dice_chain(
     for i in 0..chain_entries_len {
         let entry = payload_value_from_cose_sign(it.next().unwrap())
             .map_err(|e| format!("Unable to get Cose payload at pos {i} from end: {e:?}"))?;
-        constraints_list.push(constraints_on_dice_node(entry, &mut constraint_spec).map_err(
+        constraints_list.push(constraints_on_dice_node(&entry, &mut constraint_spec).map_err(
             |e| format!("Unable to get constraints for payload at {i} from end: {e:?}"),
         )?);
     }
@@ -262,29 +262,31 @@ pub fn policy_for_dice_chain(
     })
 }
 
-// Take the ['node_payload'] of a dice node & construct the [`NodeConstraints`] on it. If the value
-// corresponding to the a [`constraint_spec`] is not present in payload & iff it is marked
-// `MissingAction::Ignore`, the corresponding constraint will be missing from the NodeConstraints.
-// Not all constraint_spec applies to all DiceChainEntries, see `TargetEntry::ByName`.
-fn constraints_on_dice_node(
-    node_payload: Value,
+/// Take the ['node_payload'] of a dice node & construct the [`NodeConstraints`] on it. If the value
+/// corresponding to a [`ConstraintSpec`] is not present in payload & iff it is marked
+/// `MissingAction::Ignore`, the corresponding constraint will be missing from the NodeConstraints.
+/// Not all constraint_spec applies to all DiceChainEntries, see `TargetEntry::ByName`.
+pub fn constraints_on_dice_node(
+    node_payload: &Value,
     constraint_spec: &mut Vec<ConstraintSpec>,
 ) -> Result<NodeConstraints, Error> {
     let mut node_constraints: Vec<Constraint> = Vec::new();
     let constraint_spec_with_retention_marker =
-        constraint_spec.iter().map(|c| (c.clone(), is_target_node(&node_payload, c)));
+        constraint_spec.iter().map(|c| (c.clone(), is_target_node(node_payload, c)));
 
     for (constraint_item, is_target) in constraint_spec_with_retention_marker.clone() {
         if !is_target {
             continue;
         }
         // Some constraint spec may have wildcard entries, expand those!
-        for constraint_item_expanded in constraint_item.expand(&node_payload) {
+        for constraint_item_expanded in constraint_item.expand(node_payload) {
             let constraint_item_expanded = constraint_item_expanded?;
             if let Some(constraint) =
-                constraint_on_dice_node(&node_payload, &constraint_item_expanded)?
+                constraint_on_dice_node(node_payload, &constraint_item_expanded)?
             {
-                node_constraints.push(constraint);
+                if !node_constraints.contains(&constraint) {
+                    node_constraints.push(constraint);
+                }
             }
         }
     }
diff --git a/dice_policy/src/lib.rs b/dice_policy/src/lib.rs
index eeed30e..f1455f8 100644
--- a/dice_policy/src/lib.rs
+++ b/dice_policy/src/lib.rs
@@ -144,9 +144,6 @@ impl AsCborValue for NodeConstraints {
             .into_iter()
             .map(Constraint::from_cbor_value)
             .collect::<Result<_, _>>()?;
-        if res.is_empty() {
-            return Err(UnexpectedItem("Empty array", "Non empty array"));
-        }
         Ok(Self(res.into_boxed_slice()))
     }
 
@@ -232,7 +229,9 @@ impl DicePolicy {
     }
 }
 
-fn check_constraints_on_node(
+/// Matches a single DICE cert chain node against the corresponding node constraints of the DICE
+/// policy.
+pub fn check_constraints_on_node(
     node_constraints: &NodeConstraints,
     dice_node: &Value,
 ) -> Result<(), Error> {
diff --git a/dice_policy/tests/test.rs b/dice_policy/tests/test.rs
index 92a3cc4..f1e56e2 100644
--- a/dice_policy/tests/test.rs
+++ b/dice_policy/tests/test.rs
@@ -402,4 +402,15 @@ fn lookup_in_nested_container_test() {
     assert_eq!(lookup_in_nested_container(&nested_container, &path_missing2).unwrap(), None);
 }
 
+#[rdroidtest]
+fn empty_node_constraints_deserialize_succeed() {
+    let empty_node_constraints = NodeConstraints(vec![].into_boxed_slice());
+    let serialized_cbor = empty_node_constraints.to_cbor_value().unwrap();
+
+    let res = NodeConstraints::from_cbor_value(serialized_cbor);
+
+    assert!(res.is_ok());
+    assert_eq!(res.unwrap().0.len(), 0);
+}
+
 rdroidtest::test_main!();
```

