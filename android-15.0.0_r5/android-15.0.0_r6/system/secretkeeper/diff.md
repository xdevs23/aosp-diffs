```diff
diff --git a/core/src/store.rs b/core/src/store.rs
index d1f35f1..28c2438 100644
--- a/core/src/store.rs
+++ b/core/src/store.rs
@@ -33,14 +33,14 @@ use secretkeeper_comm::data_types::{Id, Secret};
 /// access to its stored entry.
 ///
 /// 1) Storage: `PolicyGatedStorage` allows storing a Secret (and sealing_policy) which is indexed
-/// by an [`Id`]. Under the hood, it uses a Key-Value based storage, which should be provided on
-/// initialization.  The security properties (Confidentiality/Integrity/Persistence) expected from
-/// the Storage are listed in ISecretkeeper.aidl
+///    by an [`Id`]. Under the hood, it uses a Key-Value based storage, which should be provided on
+///    initialization.  The security properties (Confidentiality/Integrity/Persistence) expected from
+///    the Storage are listed in ISecretkeeper.aidl
 ///
 /// 2) Access control: Secretkeeper uses DICE policy based access control. Each secret is
-/// associated with a sealing_policy, which is a DICE policy. This is a required input while
-/// storing a secret. Further access to this secret is restricted to clients whose DICE chain
-/// adheres to the sealing_policy.
+///    associated with a sealing_policy, which is a DICE policy. This is a required input while
+///    storing a secret. Further access to this secret is restricted to clients whose DICE chain
+///    adheres to the sealing_policy.
 pub struct PolicyGatedStorage {
     secure_store: Box<dyn KeyValueStore>,
 }
diff --git a/dice_policy/Android.bp b/dice_policy/Android.bp
index 9e6bc7b..a96b0d1 100644
--- a/dice_policy/Android.bp
+++ b/dice_policy/Android.bp
@@ -13,6 +13,7 @@ rust_defaults {
         "libcoset",
     ],
     vendor_available: true,
+    host_supported: true,
 }
 
 rust_library {
diff --git a/dice_policy/building/src/lib.rs b/dice_policy/building/src/lib.rs
index 1522b38..a45b19c 100644
--- a/dice_policy/building/src/lib.rs
+++ b/dice_policy/building/src/lib.rs
@@ -205,19 +205,23 @@ pub enum MissingAction {
 ///
 /// Examples of constraint_spec:
 ///  1. For exact_match on auth_hash & greater_or_equal on security_version
+///    ```
 ///    constraint_spec =[
 ///     (ConstraintType::ExactMatch, vec![AUTHORITY_HASH]),
 ///     (ConstraintType::GreaterOrEqual, vec![CONFIG_DESC, COMPONENT_NAME]),
 ///    ];
+///    ```
 ///
 /// 2. For hypothetical (and highly simplified) dice chain:
 ///
+///    ```
 ///    [1, ROT_KEY, [{1 : 'a', 2 : {200 : 5, 201 : 'b'}}]]
 ///    The following can be used
 ///    constraint_spec =[
 ///     ConstraintSpec(ConstraintType::ExactMatch, vec![1]),         // exact_matches value 'a'
 ///     ConstraintSpec(ConstraintType::GreaterOrEqual, vec![2, 200]),// matches any value >= 5
 ///    ];
+///    ```
 pub fn policy_for_dice_chain(
     explicit_key_dice_chain: &[u8],
     mut constraint_spec: Vec<ConstraintSpec>,
diff --git a/dice_policy/src/lib.rs b/dice_policy/src/lib.rs
index 592c24f..eeed30e 100644
--- a/dice_policy/src/lib.rs
+++ b/dice_policy/src/lib.rs
@@ -34,10 +34,11 @@
 //! These constraints used to express policy are (for now) limited to following 2 types:
 //! 1. Exact Match: useful for enforcing rules like authority hash should be exactly equal.
 //! 2. Greater than or equal to: Useful for setting policies that seal
-//! Anti-rollback protected entities (should be accessible to versions >= present).
+//!    Anti-rollback protected entities (should be accessible to versions >= present).
 //!
 //! Dice Policy CDDL (keep in sync with DicePolicy.cddl):
 //!
+//! ```
 //! dicePolicy = [
 //! 1, ; dice policy version
 //! + nodeConstraintList ; for each entry in dice chain
@@ -56,6 +57,7 @@
 //! keySpec = [value+]
 //!
 //! value = bool / int / tstr / bstr
+//! ```
 
 use ciborium::Value;
 use coset::{AsCborValue, CborSerializable, CoseError, CoseError::UnexpectedItem, CoseSign1};
```

