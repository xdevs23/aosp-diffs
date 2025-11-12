```diff
diff --git a/OWNERS b/OWNERS
index 8cf7c1f..52401b7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,5 @@
 aliceywang@google.com
+ascull@google.com
+cukie@google.com
 drysdale@google.com
-paulcrowley@google.com
 shikhapanwar@google.com
diff --git a/client/Android.bp b/client/Android.bp
index ecb5a77..09ba930 100644
--- a/client/Android.bp
+++ b/client/Android.bp
@@ -36,10 +36,9 @@ rust_defaults {
         "libdiced_open_dice",
         "libexplicitkeydice",
         "libhex",
-        // TODO(b/315464358): Use the std version
-        "libsecretkeeper_comm_nostd",
+        "libsecretkeeper_comm",
         // TODO(b/291228655): This is required for 'cipher', refactor to cut this dependency.
-        "libsecretkeeper_core_nostd",
+        "libsecretkeeper_core",
     ],
 }
 
diff --git a/comm/Android.bp b/comm/Android.bp
index f85fa23..e65c862 100644
--- a/comm/Android.bp
+++ b/comm/Android.bp
@@ -24,19 +24,35 @@ rust_defaults {
     defaults: ["avf_build_flags_rust"],
     edition: "2021",
     lints: "android",
-    rustlibs: [
-        "libciborium",
-        "libcoset",
-        "libzeroize",
-    ],
     proc_macros: ["libenumn"],
     vendor_available: true,
 }
 
-rust_library {
+rust_library_rlib {
     name: "libsecretkeeper_comm_nostd",
     defaults: ["libsecretkeeper_comm.defaults"],
     srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libciborium_nostd",
+        "libcoset_nostd",
+        "libzeroize_nostd",
+    ],
+    no_stdlibs: true,
+    prefer_rlib: true,
+    stdlibs: [
+        "liballoc.rust_sysroot",
+    ],
+}
+
+rust_library {
+    name: "libsecretkeeper_comm",
+    srcs: ["src/lib.rs"],
+    defaults: ["libsecretkeeper_comm.defaults"],
+    rustlibs: [
+        "libciborium",
+        "libcoset",
+        "libzeroize",
+    ],
 }
 
 rust_test {
@@ -48,6 +64,8 @@ rust_test {
     srcs: ["tests/tests.rs"],
     test_suites: ["general-tests"],
     rustlibs: [
-        "libsecretkeeper_comm_nostd",
+        "libciborium",
+        "libcoset",
+        "libsecretkeeper_comm",
     ],
 }
diff --git a/core/Android.bp b/core/Android.bp
index 92ed7ee..5fe95b8 100644
--- a/core/Android.bp
+++ b/core/Android.bp
@@ -24,26 +24,51 @@ rust_defaults {
         "authgraph_use_latest_hal_aidl_rust",
         "secretkeeper_use_latest_hal_aidl_rust",
     ],
+}
+
+rust_library_rlib {
+    name: "libsecretkeeper_core_nostd",
+    crate_name: "secretkeeper_core",
+    srcs: ["src/lib.rs"],
+    defaults: [
+        "libsecretkeeper_core_defaults",
+    ],
+    rustlibs: [
+        "libauthgraph_core_nostd",
+        "libauthgraph_wire_nostd",
+        "libciborium_nostd",
+        "libcoset_nostd",
+        "libdice_policy_nostd",
+        "liblog_rust_nostd",
+        "libsecretkeeper_comm_nostd",
+    ],
+    prefer_rlib: true,
+    no_stdlibs: true,
+}
+
+rust_defaults {
+    name: "libsecretkeeper_core_std_defaults",
+    defaults: [
+        "libsecretkeeper_core_defaults",
+    ],
     rustlibs: [
-        // TODO(b/315464358): Use no_std version of authgraph_core/authgraph_wire/coset
         "libauthgraph_core",
         "libauthgraph_wire",
         "libciborium",
         "libcoset",
         "libdice_policy",
         "liblog_rust",
-        "libsecretkeeper_comm_nostd",
+        "libsecretkeeper_comm",
     ],
 }
 
 rust_library {
-    name: "libsecretkeeper_core_nostd",
+    name: "libsecretkeeper_core",
     crate_name: "secretkeeper_core",
     srcs: ["src/lib.rs"],
     defaults: [
-        "libsecretkeeper_core_defaults",
+        "libsecretkeeper_core_std_defaults",
     ],
-    no_stdlibs: true,
 }
 
 rust_test {
@@ -51,7 +76,7 @@ rust_test {
     crate_name: "secretkeeper_core_test",
     srcs: ["src/lib.rs"],
     defaults: [
-        "libsecretkeeper_core_defaults",
+        "libsecretkeeper_core_std_defaults",
     ],
     rustlibs: [
         "libhex",
diff --git a/dice_policy/Android.bp b/dice_policy/Android.bp
index 9cdfcca..b54c9e7 100644
--- a/dice_policy/Android.bp
+++ b/dice_policy/Android.bp
@@ -8,12 +8,20 @@ rust_defaults {
     defaults: ["avf_build_flags_rust"],
     edition: "2021",
     lints: "android",
+    vendor_available: true,
+}
+
+rust_library_rlib {
+    name: "libdice_policy_nostd",
+    defaults: ["libdice_policy.defaults"],
+    srcs: ["src/lib.rs"],
     rustlibs: [
-        "libciborium",
-        "libcoset",
+        "libciborium_nostd",
+        "libcoset_nostd",
     ],
-    vendor_available: true,
-    host_supported: true,
+    prefer_rlib: true,
+    no_stdlibs: true,
+    min_sdk_version: "35",
 }
 
 rust_library {
@@ -22,4 +30,8 @@ rust_library {
     srcs: ["src/lib.rs"],
     host_supported: true,
     min_sdk_version: "35",
+    rustlibs: [
+        "libciborium",
+        "libcoset",
+    ],
 }
diff --git a/dice_policy/README.md b/dice_policy/README.md
index 4506fe2..feb9a0a 100644
--- a/dice_policy/README.md
+++ b/dice_policy/README.md
@@ -6,14 +6,14 @@ set out in the policy.
 
 ## Navigating this project
 
-This directory exports Rust crates for matching Dice Chains against Dice Policies as well building
-Dice Policies.
+This directory exports Rust crates for matching DICE Chains against DICE Policies as well building
+DICE Policies.
 
 1. [./building/](https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/dice_policy/building/src/lib.rs):
-   Supports constructing Dice Policies on a Dice chains, enabling various ways to specify the
+   Supports constructing DICE Policies on a DICE chains, enabling various ways to specify the
    constraints.
 1. [./src/](https://cs.android.com/android/platform/superproject/main/+/main:system/secretkeeper/dice_policy/src/lib.rs):
-   Supports matching Dice Chains against Dice Policies.
+   Supports matching DICE Chains against DICE Policies.
 
 ## DICE chain
 
diff --git a/dice_policy/building/src/lib.rs b/dice_policy/building/src/lib.rs
index 20ec705..592c463 100644
--- a/dice_policy/building/src/lib.rs
+++ b/dice_policy/building/src/lib.rs
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-//! This library supports constructing Dice Policies on a Dice chains, enabling various ways to
-//! specify the constraints. This adheres to the Dice Policy spec at DicePolicy.cddl & works with
+//! This library supports constructing DICE Policies on a DICE chains, enabling various ways to
+//! specify the constraints. This adheres to the DICE Policy spec at DicePolicy.cddl & works with
 //! the rust structs exported by libdice_policy.
 
 #![allow(missing_docs)] // Sadly needed due to use of enumn::N
@@ -43,7 +43,7 @@ const CONFIG_DESC: i64 = -4670548;
 const COMPONENT_NAME: i64 = -70002;
 const PATH_TO_COMPONENT_NAME: [i64; 2] = [CONFIG_DESC, COMPONENT_NAME];
 
-/// Constraint Types supported in Dice policy.
+/// Constraint Types supported in DICE policy.
 #[repr(u16)]
 #[non_exhaustive]
 #[derive(Clone, Copy, Debug, PartialEq, N)]
@@ -125,7 +125,7 @@ pub enum TargetEntry {
 fn try_extract_component_name(node_payload: &Value) -> Option<String> {
     let component_name = lookup_in_nested_container(node_payload, &PATH_TO_COMPONENT_NAME)
         .unwrap_or_else(|e| {
-            log::warn!("Lookup for component_name in the node failed {e:?}- ignoring!");
+            log::warn!("Lookup for component_name in the node failed {e}- ignoring!");
             None
         })?;
     component_name.into_text().ok()
@@ -194,13 +194,13 @@ pub enum MissingAction {
 /// ExactMatch of the whole node.
 ///
 /// # Arguments
-/// `dice_chain`: The serialized CBOR encoded Dice chain, adhering to Explicit-key
+/// `dice_chain`: The serialized CBOR encoded DICE chain, adhering to Explicit-key
 /// DiceCertChain format. See definition at ExplicitKeyDiceCertChain.cddl
 ///
 /// `ConstraintSpec`: List of constraints to be applied on dice node.
 /// Each constraint is a ConstraintSpec object.
 ///
-/// Note: Dice node is treated as a nested structure (map or array) (& so the lookup is done in
+/// Note: DICE node is treated as a nested structure (map or array) (& so the lookup is done in
 /// that fashion).
 ///
 /// Examples of constraint_spec:
@@ -235,10 +235,12 @@ pub fn policy_for_dice_chain(
     let mut it = dice_chain.into_iter().rev();
     for i in 0..chain_entries_len {
         let entry = payload_value_from_cose_sign(it.next().unwrap())
-            .map_err(|e| format!("Unable to get Cose payload at pos {i} from end: {e:?}"))?;
-        constraints_list.push(constraints_on_dice_node(&entry, &mut constraint_spec).map_err(
-            |e| format!("Unable to get constraints for payload at {i} from end: {e:?}"),
-        )?);
+            .map_err(|e| format!("Unable to get Cose payload at pos {i} from end: {e}"))?;
+        constraints_list.push(
+            constraints_on_dice_node(&entry, &mut constraint_spec).map_err(|e| {
+                format!("Unable to get constraints for payload at {i} from end: {e}")
+            })?,
+        );
     }
 
     // 1st & 2nd dice node of Explicit-key DiceCertChain format are
@@ -324,14 +326,11 @@ fn constraint_on_dice_node(
         }
         Err(e) => {
             if constraint_spec.if_path_missing == MissingAction::Ignore {
-                log::warn!(
-                    "Error ({e:?}) getting Value for {:?}, - skipping!",
-                    constraint_spec.path
-                );
+                log::warn!("Error ({e}) getting Value for {:?}, - skipping!", constraint_spec.path);
                 None
             } else {
                 return Err(format!(
-                    "Error ({e:?}) getting Value for {:?}, constraint\
+                    "Error ({e}) getting Value for {:?}, constraint\
                      spec is marked to fail on missing path",
                     constraint_spec.path
                 ));
diff --git a/dice_policy/src/lib.rs b/dice_policy/src/lib.rs
index f1455f8..ff60b3d 100644
--- a/dice_policy/src/lib.rs
+++ b/dice_policy/src/lib.rs
@@ -18,7 +18,7 @@
 //! verifier takes a policy and a DICE chain, and returns a boolean indicating whether the
 //! DICE chain meets the constraints set out on a policy.
 //!
-//! This forms the foundation of Dice Policy aware Authentication (DPA-Auth), where the server
+//! This forms the foundation of DICE Policy aware Authentication (DPA-Auth), where the server
 //! authenticates a client by comparing its dice chain against a set policy.
 //!
 //! Another use is "sealing", where clients can use an appropriately constructed dice policy to
@@ -36,7 +36,7 @@
 //! 2. Greater than or equal to: Useful for setting policies that seal
 //!    Anti-rollback protected entities (should be accessible to versions >= present).
 //!
-//! Dice Policy CDDL (keep in sync with DicePolicy.cddl):
+//! DICE Policy CDDL (keep in sync with DicePolicy.cddl):
 //!
 //! ```
 //! dicePolicy = [
@@ -59,14 +59,22 @@
 //! value = bool / int / tstr / bstr
 //! ```
 
+#![no_std]
+
+extern crate alloc;
+use alloc::borrow::Cow;
+use alloc::boxed::Box;
+use alloc::format;
+use alloc::string::String;
+use alloc::string::ToString;
+use alloc::vec;
+use alloc::vec::Vec;
 use ciborium::Value;
+use core::iter::zip;
 use coset::{AsCborValue, CborSerializable, CoseError, CoseError::UnexpectedItem, CoseSign1};
-use std::borrow::Cow;
-use std::iter::zip;
-
 type Error = String;
 
-/// Version of the Dice policy spec
+/// Version of the DICE policy spec
 pub const DICE_POLICY_VERSION: u64 = 1;
 /// Identifier for `exactMatchConstraint` as per spec
 pub const EXACT_MATCH_CONSTRAINT: u16 = 1;
@@ -77,9 +85,9 @@ pub const GREATER_OR_EQUAL_CONSTRAINT: u16 = 2;
 /// Ok(()) in case of successful match, otherwise returns error in case of failure.
 pub fn chain_matches_policy(dice_chain: &[u8], policy: &[u8]) -> Result<(), Error> {
     DicePolicy::from_slice(policy)
-        .map_err(|e| format!("DicePolicy decoding failed {e:?}"))?
+        .map_err(|e| format!("DicePolicy decoding failed {e}"))?
         .matches_dice_chain(dice_chain)
-        .map_err(|e| format!("DicePolicy matching failed {e:?}"))?;
+        .map_err(|e| format!("DicePolicy matching failed {e}"))?;
     Ok(())
 }
 
@@ -161,9 +169,9 @@ impl AsCborValue for NodeConstraints {
 /// This is Rust equivalent of `dicePolicy` in the CDDL above. Keep in sync!
 #[derive(Clone, Debug, PartialEq)]
 pub struct DicePolicy {
-    /// Dice policy version
+    /// DICE policy version
     pub version: u64,
-    /// List of `NodeConstraints`, one for each node of Dice chain.
+    /// List of `NodeConstraints`, one for each node of DICE chain.
     pub node_constraints_list: Box<[NodeConstraints]>,
 }
 
@@ -195,78 +203,81 @@ impl AsCborValue for DicePolicy {
 impl CborSerializable for DicePolicy {}
 
 impl DicePolicy {
-    /// Dice chain policy verifier - Compare the input dice chain against this Dice policy.
-    /// The method returns Ok() if the dice chain meets the constraints set in Dice policy,
-    /// otherwise returns error in case of mismatch.
+    /// Matches this DICE policy against a serialized ExplicitKeyDiceCertChain.
+    /// The method returns Ok() if the dice chain matches the constraints of this DICE policy,
+    /// otherwise returns an error.
+    ///
+    /// For ExplicitKeyDiceCertChain CDDL see
+    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ExplicitKeyDiceCertChain.cddl
+    ///
     /// TODO(b/291238565) Create a separate error module for DicePolicy mismatches.
-    pub fn matches_dice_chain(&self, dice_chain: &[u8]) -> Result<(), Error> {
-        let dice_chain = deserialize_cbor_array(dice_chain)?;
-        check_is_explicit_key_dice_chain(&dice_chain)?;
-        if dice_chain.len() != self.node_constraints_list.len() {
+    pub fn matches_dice_chain(&self, explicit_key_dice_chain: &[u8]) -> Result<(), Error> {
+        let explicit_key_dice_chain = deserialize_cbor_array(explicit_key_dice_chain)?;
+        check_is_explicit_key_dice_chain(&explicit_key_dice_chain)?;
+        if explicit_key_dice_chain.len() != self.node_constraints_list.len() {
             return Err(format!(
-                "Dice chain size({}) does not match policy({})",
-                dice_chain.len(),
+                "ExplicitKeyDiceCertChain size({}) does not match policy({})",
+                explicit_key_dice_chain.len(),
                 self.node_constraints_list.len()
             ));
         }
 
-        for (n, (dice_node, node_constraints)) in
-            zip(dice_chain, self.node_constraints_list.iter()).enumerate()
+        for (n, (node_constraints, node)) in
+            zip(self.node_constraints_list.iter(), explicit_key_dice_chain).enumerate()
         {
-            let dice_node_payload = if n <= 1 {
-                // 1st & 2nd dice node of Explicit-key DiceCertChain format are
-                // EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION & DiceCertChainInitialPayload. The rest are
-                // DiceChainEntry which is a CoseSign1.
-                dice_node
-            } else {
-                payload_value_from_cose_sign(dice_node)
-                    .map_err(|e| format!("Unable to get Cose payload at {n}: {e:?}"))?
+            let node = match n {
+                0..=1 => node,
+                n => payload_value_from_cose_sign(node)
+                    .map_err(|e| format!("Unable to parse DiceChainEntry[{i}]: {e}", i = n - 2))?,
             };
-            check_constraints_on_node(node_constraints, &dice_node_payload)
-                .map_err(|e| format!("Mismatch found at {n}: {e:?}"))?;
+            check_constraints_on_node(node_constraints, &node).map_err(|e| match n {
+                0 => format!("Mismatch at ExplicitKeyDiceCertChain version: {e}"),
+                1 => format!("Mismatch at DiceCertChainInitialPayload: {e}"),
+                n => format!("Mismatch at DiceChainEntry[{i}]: {e}", i = n - 2),
+            })?;
         }
         Ok(())
     }
 }
 
-/// Matches a single DICE cert chain node against the corresponding node constraints of the DICE
-/// policy.
+/// Matches a single node against the corresponding node constraints of the DICE policy.
 pub fn check_constraints_on_node(
     node_constraints: &NodeConstraints,
-    dice_node: &Value,
+    node: &Value,
 ) -> Result<(), Error> {
     for constraint in node_constraints.0.iter() {
-        check_constraint_on_node(constraint, dice_node)?;
+        check_constraint_on_node(constraint, node)?;
     }
     Ok(())
 }
 
-fn check_constraint_on_node(constraint: &Constraint, dice_node: &Value) -> Result<(), Error> {
+fn check_constraint_on_node(constraint: &Constraint, node: &Value) -> Result<(), Error> {
     let Constraint(cons_type, path, value_in_constraint) = constraint;
-    let value_in_node = lookup_in_nested_container(dice_node, path)?
-        .ok_or(format!("Value not found for constraint_path {path:?})"))?;
+    let value_in_node = lookup_in_nested_container(node, path)?
+        .ok_or(format!("Value not found for constraint {path:?}"))?;
     match *cons_type {
         EXACT_MATCH_CONSTRAINT => {
             if value_in_node != *value_in_constraint {
                 return Err(format!(
-                    "Policy mismatch. Expected {value_in_constraint:?}; found {value_in_node:?}"
+                    "Constraint {path:?}): \
+                    expected {value_in_constraint:?}; found {value_in_node:?}"
                 ));
             }
         }
         GREATER_OR_EQUAL_CONSTRAINT => {
-            let value_in_node = value_in_node
-                .as_integer()
-                .ok_or("Mismatch type: expected a CBOR integer".to_string())?;
             let value_min = value_in_constraint
                 .as_integer()
-                .ok_or("Mismatch type: expected a CBOR integer".to_string())?;
+                .ok_or(format!("Invalid constraint {path:?}: expected a CBOR integer"))?;
+            let value_in_node = value_in_node
+                .as_integer()
+                .ok_or(format!("Constraint {path:?}: expected a CBOR integer"))?;
             if value_in_node < value_min {
                 return Err(format!(
-                    "Policy mismatch. Expected >= {value_min:?}; found {value_in_node:?}"
+                    "Constraint {path:?}: expected >= {value_min:?}; found {value_in_node:?}"
                 ));
             }
         }
-        cons_type => return Err(format!("Unexpected constraint type {cons_type:?}")),
+        cons_type => return Err(format!("Invalid constraint {path:?}: unknown type {cons_type}")),
     };
     Ok(())
 }
@@ -291,7 +302,7 @@ fn get_container_from_value(container: &Value) -> Result<Container, Error> {
         // Value can be Map/Array/Encoded Map. Encoded Arrays are not yet supported (or required).
         // Note: Encoded Map is used for Configuration descriptor entry in DiceChainEntryPayload.
         Value::Bytes(b) => Value::from_slice(b)
-            .map_err(|e| format!("{e:?}"))?
+            .map_err(|e| format!("{e}"))?
             .into_map()
             .map(|m| Container::Map(Cow::Owned(m)))
             .map_err(|e| format!("Expected a CBOR map: {:?}", e)),
@@ -324,7 +335,7 @@ fn lookup_value_in_container<'a>(container: &'a Container<'a>, key: i64) -> Opti
     }
 }
 
-/// This library only works with Explicit-key DiceCertChain format. Further we require it to have
+/// This library only works with ExplicitKeyDiceCertChain format. Further we require it to have
 /// at least 1 DiceChainEntry. Note that this is a lightweight check so that we fail early for
 /// legacy chains.
 pub fn check_is_explicit_key_dice_chain(dice_chain: &[Value]) -> Result<(), Error> {
@@ -337,18 +348,18 @@ pub fn check_is_explicit_key_dice_chain(dice_chain: &[Value]) -> Result<(), Erro
 
 /// Extract the payload from the COSE Sign
 pub fn payload_value_from_cose_sign(cbor: Value) -> Result<Value, Error> {
-    let sign1 = CoseSign1::from_cbor_value(cbor)
-        .map_err(|e| format!("Error extracting CoseSign1: {e:?}"))?;
+    let sign1 =
+        CoseSign1::from_cbor_value(cbor).map_err(|e| format!("Error extracting CoseSign1: {e}"))?;
     match sign1.payload {
         None => Err("Missing payload".to_string()),
-        Some(payload) => Value::from_slice(&payload).map_err(|e| format!("{e:?}")),
+        Some(payload) => Value::from_slice(&payload).map_err(|e| format!("{e}")),
     }
 }
 
 /// Decode a CBOR array
 pub fn deserialize_cbor_array(cbor_array_bytes: &[u8]) -> Result<Vec<Value>, Error> {
     let cbor_array = Value::from_slice(cbor_array_bytes)
-        .map_err(|e| format!("Unable to decode top-level CBOR: {e:?}"))?;
+        .map_err(|e| format!("Unable to decode top-level CBOR: {e}"))?;
     let cbor_array =
         cbor_array.into_array().map_err(|e| format!("Expected an array found: {e:?}"))?;
     Ok(cbor_array)
diff --git a/dice_policy/tests/test.rs b/dice_policy/tests/test.rs
index f1e56e2..98ec6dc 100644
--- a/dice_policy/tests/test.rs
+++ b/dice_policy/tests/test.rs
@@ -280,14 +280,16 @@ fn policy_matches_updated_dice_chain() {
 #[rdroidtest]
 fn policy_mismatch_downgraded_dice_chain() {
     let example = TestArtifacts::get_example();
+    let res = policy_for_dice_chain(&example.updated_input_dice, example.constraint_spec)
+        .unwrap()
+        .matches_dice_chain(&example.input_dice);
     assert!(
-        policy_for_dice_chain(&example.updated_input_dice, example.constraint_spec)
-            .unwrap()
-            .matches_dice_chain(&example.input_dice)
-            .is_err(),
+        res.is_err(),
         "The (downgraded) dice chain matched the policy constructed out of the 'updated'\
             dice chain!!"
     );
+    // The DICE chains vary at path [3,100], check that the error string contain the path
+    assert!(res.clone().unwrap_err().contains("[3, 100]"), "Unexpected error message {res:?}");
 }
 
 #[rdroidtest]
diff --git a/hal/Android.bp b/hal/Android.bp
index 6782def..9c71d4f 100644
--- a/hal/Android.bp
+++ b/hal/Android.bp
@@ -29,7 +29,7 @@ rust_defaults {
         "libbinder_rs",
         "libcoset",
         "liblog_rust",
-        "libsecretkeeper_comm_nostd",
+        "libsecretkeeper_comm",
     ],
 }
 
```

