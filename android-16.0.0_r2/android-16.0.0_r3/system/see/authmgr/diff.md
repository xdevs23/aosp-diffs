```diff
diff --git a/Android.bp b/Android.bp
index 778aa71..20cf0bc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,6 +14,7 @@
 
 package {
     default_applicable_licenses: ["system_see_authmgr_license"],
+    default_team: "trendy_team_trusty",
 }
 
 license {
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 94d25e8..db5f7c1 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -9,5 +9,3 @@ rustfmt = --config-path=rustfmt.toml
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
 
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/authmgr-be-impl/src/lib.rs b/authmgr-be-impl/src/lib.rs
index 135e0d8..1215154 100644
--- a/authmgr-be-impl/src/lib.rs
+++ b/authmgr-be-impl/src/lib.rs
@@ -24,8 +24,10 @@ extern crate alloc;
 use authgraph_boringssl::{ec::BoringEcDsa, BoringRng};
 use authgraph_core::key::{CertChain, InstanceIdentifier, Policy};
 use authmgr_be::error::Error;
-use authmgr_be::traits::{CryptoTraitImpl, Device, RawConnection};
-use authmgr_common::{match_dice_chain_with_policy, signed_connection_request::TransportID};
+use authmgr_be::traits::{Device, RawConnection};
+use authmgr_common::{
+    match_dice_chain_with_policy, signed_connection_request::TransportID, CryptoTraitImpl,
+};
 use std::collections::HashMap;
 
 pub mod mock_storage;
@@ -77,7 +79,7 @@ impl Device for AuthMgrBeDevice {
     fn handover_client_connection(
         &self,
         _service_name: &str,
-        _client_seq_number: i32,
+        _client_seq_number: i64,
         _client_conn_handle: Box<dyn RawConnection>,
         _is_persistent: bool,
     ) -> Result<(), Error> {
diff --git a/authmgr-be-impl/src/mock_storage.rs b/authmgr-be-impl/src/mock_storage.rs
index b639c97..88ee11e 100644
--- a/authmgr-be-impl/src/mock_storage.rs
+++ b/authmgr-be-impl/src/mock_storage.rs
@@ -30,7 +30,7 @@ use std::collections::{hash_map::Entry, HashMap};
 
 /// Instance sequence number is part of the fully qualified path of a client's storage
 #[derive(Clone, Debug, Eq, Hash, PartialEq)]
-pub struct InstanceSeqNumber(i32);
+pub struct InstanceSeqNumber(i64);
 
 #[derive(Clone, Debug, Eq, Hash, PartialEq)]
 struct FullyQualifiedClientId(InstanceSeqNumber, Arc<ClientId>);
@@ -38,7 +38,7 @@ struct FullyQualifiedClientId(InstanceSeqNumber, Arc<ClientId>);
 /// In-memory implementation for AuthMgr persistent storage
 #[derive(Default)]
 pub struct MockPersistentStorage {
-    global_seq_num: i32,
+    global_seq_num: i64,
     instances: HashMap<Arc<InstanceIdentifier>, PersistentInstanceContext>,
     clients: HashMap<FullyQualifiedClientId, PersistentClientContext>,
 }
@@ -69,7 +69,7 @@ impl Storage for MockPersistentStorage {
 
     fn update_client_policy_in_storage(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         latest_dice_policy: &Arc<Policy>,
     ) -> Result<(), Error> {
@@ -106,7 +106,7 @@ impl Storage for MockPersistentStorage {
 
     fn read_client_context(
         &self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
     ) -> Result<Option<Self::ClientContext>, Error> {
         Ok(self
@@ -120,7 +120,7 @@ impl Storage for MockPersistentStorage {
 
     fn create_client_context(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         client_info: Self::ClientContext,
     ) -> Result<(), Error> {
@@ -137,11 +137,11 @@ impl Storage for MockPersistentStorage {
 }
 
 impl PersistentStorage for MockPersistentStorage {
-    fn get_or_create_global_sequence_number(&mut self) -> Result<i32, Error> {
+    fn get_or_create_global_sequence_number(&mut self) -> Result<i64, Error> {
         Ok(self.global_seq_num)
     }
 
-    fn increment_global_sequence_number(&mut self) -> Result<i32, Error> {
+    fn increment_global_sequence_number(&mut self) -> Result<i64, Error> {
         self.global_seq_num += 1;
         Ok(self.global_seq_num)
     }
diff --git a/authmgr-be-impl/src/tests.rs b/authmgr-be-impl/src/tests.rs
index a8c8bcc..9945520 100644
--- a/authmgr-be-impl/src/tests.rs
+++ b/authmgr-be-impl/src/tests.rs
@@ -20,6 +20,7 @@ use crate::AuthMgrBeDevice;
 use authgraph_core::key::{CertChain, DiceChainEntry, InstanceIdentifier, Policy};
 use authgraph_core_test::{
     create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, CdiValues, SAMPLE_INSTANCE_HASH,
+    TEST_OS_COMPONENT_NAME,
 };
 use authmgr_be::authorization::AuthMgrBE;
 use authmgr_be::data_structures::MemoryLimits;
@@ -46,7 +47,7 @@ fn test_auth_mgr_protocol_single_pvm() {
         .extract_instance_identifier_in_guest_os_entry()
         .expect("error in extracting instance id")
         .unwrap();
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
 
     let dice_policy = Policy(
         dice_policy_builder::policy_for_dice_chain(&dice_cert, constraint_spec)
diff --git a/authmgr-be/src/authorization.rs b/authmgr-be/src/authorization.rs
index 3925ae8..fb3ea15 100644
--- a/authmgr-be/src/authorization.rs
+++ b/authmgr-be/src/authorization.rs
@@ -27,7 +27,7 @@ use crate::{
         VERSION_PERSISTENT_INSTANCE_CONTEXT,
     },
     error::{Error, ErrorCode},
-    traits::{CryptoTraitImpl, Device, PersistentStorage, RawConnection, RpcConnection},
+    traits::{Device, PersistentStorage, RawConnection, RpcConnection},
     try_to_vec,
 };
 use alloc::boxed::Box;
@@ -36,7 +36,7 @@ use authgraph_core::key::{CertChain, DiceChainEntry, InstanceIdentifier, Policy}
 use authmgr_common::{
     extend_dice_policy_with, match_dice_cert_with_policy, match_dice_chain_with_policy,
     signed_connection_request::{Challenge, ConnectionRequest},
-    Token,
+    CryptoTraitImpl, Token,
 };
 use coset::CborSerializable;
 
@@ -57,13 +57,15 @@ pub struct AuthMgrBE {
 }
 
 /// Data structure encapsulating the global sequence number - which is used to assign a unique
-/// identifier to the instances and clients by the AuthMgr BE
-pub struct LatestGlobalSeqNum(i32);
+/// identifier to the instances and clients by the AuthMgr BE.
+/// Currently, AIDL types do not support u64. Therefore, we use i64 here, although client sequence
+/// number cannot be negative.
+pub struct LatestGlobalSeqNum(i64);
 
 impl LatestGlobalSeqNum {
     /// Constructs an instance of the in-memory global sequence number given the latest global
     /// sequence number which is read from the persistent storage
-    pub fn new(latest_global_seq_num: i32) -> Self {
+    pub fn new(latest_global_seq_num: i64) -> Self {
         Self(latest_global_seq_num)
     }
 
@@ -72,7 +74,7 @@ impl LatestGlobalSeqNum {
     pub fn fetch_and_increment(
         &mut self,
         persistent_storage: &mut dyn PersistentStorage,
-    ) -> Result<i32, Error> {
+    ) -> Result<i64, Error> {
         let current_global_seq_num = self.0;
         self.0 = persistent_storage.increment_global_sequence_number()?;
         Ok(current_global_seq_num)
@@ -425,7 +427,7 @@ impl AuthMgrBE {
         instance_id: &Arc<InstanceIdentifier>,
         given_policy: &Arc<Policy>,
         dice_chain: &CertChain,
-    ) -> Result<i32, Error> {
+    ) -> Result<i64, Error> {
         match self.persistent_storage.read_instance_context(instance_id)? {
             Some(instance_ctx) => {
                 self.enforce_rollback_protection_for_pvm(
@@ -506,7 +508,7 @@ impl AuthMgrBE {
     // A helper method to enforce rollback protection for a client already in the cache.
     fn enforce_rollback_protection_for_client_in_cache(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         is_persistent: bool,
         authorized_client: &mut AuthorizedClient,
         given_dice_cert: &DiceChainEntry,
@@ -529,11 +531,11 @@ impl AuthMgrBE {
 
     fn handle_client_in_persistent_storage(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         given_dice_cert: &DiceChainEntry,
         given_policy: &Arc<Policy>,
-    ) -> Result<i32, Error> {
+    ) -> Result<i64, Error> {
         match self.persistent_storage.read_client_context(instance_seq_number, client_id)? {
             Some(client_ctx) => {
                 self.enforce_rollback_protection_for_client(
@@ -572,7 +574,7 @@ impl AuthMgrBE {
 
     fn enforce_rollback_protection_for_client(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         given_dice_cert: &DiceChainEntry,
         given_policy: &Arc<Policy>,
@@ -617,7 +619,7 @@ impl AuthMgrBE {
     fn update_global_list_of_authorized_clients(
         &mut self,
         state: &AuthenticatedConnectionState,
-        client_seq_number: i32,
+        client_seq_number: i64,
         client_id: &Arc<ClientId>,
         dice_leaf: &DiceChainEntry,
         given_policy: &Arc<Policy>,
diff --git a/authmgr-be/src/data_structures.rs b/authmgr-be/src/data_structures.rs
index b032a0e..70a5f3b 100644
--- a/authmgr-be/src/data_structures.rs
+++ b/authmgr-be/src/data_structures.rs
@@ -57,7 +57,7 @@ pub struct AuthenticatedConnectionState {
     /// Transport id of the pvm
     pub transport_id: TransportID,
     /// Unique sequence number assigned to the instance by the AuthMgr BE
-    pub instance_seq_number: i32,
+    pub instance_seq_number: i64,
     /// DICE artifacts of the pvm
     pub dice_artifacts: DiceArtifacts,
     /// Public key of the signing key pair of the pvm
@@ -75,7 +75,7 @@ impl AuthenticatedConnectionState {
     pub fn new(
         instance_id: Arc<InstanceIdentifier>,
         transport_id: TransportID,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         dice_artifacts: DiceArtifacts,
         pub_signing_key: EcVerifyKey,
         is_persistent: bool,
@@ -145,7 +145,7 @@ pub struct AuthorizedClient {
     /// Client id
     pub client_id: Arc<ClientId>,
     /// Unique sequence number assigned to the client by the AuthMgr BE
-    pub sequence_number: i32,
+    pub sequence_number: i64,
     /// DICE policy of the client
     pub policy: Arc<Policy>,
 }
@@ -164,7 +164,7 @@ pub struct PersistentInstanceContext {
     /// Version of the data structure format
     pub version: i32,
     /// Unique sequence number of the persistent instance
-    pub sequence_number: i32,
+    pub sequence_number: i64,
     /// DICE policy
     pub dice_policy: Arc<Policy>,
 }
@@ -175,7 +175,7 @@ pub struct PersistentClientContext {
     /// Version of the data structure format
     pub version: i32,
     /// Unique sequence number of the persistent client
-    pub sequence_number: i32,
+    pub sequence_number: i64,
     /// DICE policy
     pub dice_policy: Arc<Policy>,
 }
@@ -475,7 +475,7 @@ impl PendingClientAuthorizations {
 /// "policy matching as a service" provided by AuthMgr BE.
 pub struct AuthorizedClientFullDiceArtifacts {
     /// Unique sequence number of the client
-    pub sequence_number: i32,
+    pub sequence_number: i64,
     /// Transport id of the pvm that the client belongs to (used to cleanup the cache upon
     /// connection close by the pvm)
     pub transport_id: TransportID,
@@ -504,7 +504,7 @@ impl AuthorizedClientsGlobalList {
     }
 
     /// Retrieve a mutable client given the client's unique sequence number
-    pub fn get_mut(&mut self, seq_number: i32) -> Option<&mut AuthorizedClientFullDiceArtifacts> {
+    pub fn get_mut(&mut self, seq_number: i64) -> Option<&mut AuthorizedClientFullDiceArtifacts> {
         self.authorized_clients_list
             .iter_mut()
             .find(|authorized_client| authorized_client.sequence_number == seq_number)
diff --git a/authmgr-be/src/traits.rs b/authmgr-be/src/traits.rs
index 04fc1e1..c1056c8 100644
--- a/authmgr-be/src/traits.rs
+++ b/authmgr-be/src/traits.rs
@@ -22,17 +22,8 @@ use crate::error::Error;
 use alloc::boxed::Box;
 use alloc::sync::Arc;
 use authgraph_core::key::{CertChain, InstanceIdentifier, Policy};
-use authgraph_core::traits::{EcDsa, Rng};
 use authmgr_common::signed_connection_request::TransportID;
 
-/// The cryptographic functionality that must be provided by an implementation of AuthMgr BE
-pub struct CryptoTraitImpl {
-    /// Implementation of ECDSA functionality
-    pub ecdsa: Box<dyn EcDsa>,
-    /// Implementation of secure random number generation
-    pub rng: Box<dyn Rng>,
-}
-
 /// Trait defining device specific functionality
 pub trait Device: Send {
     /// Return the transport ID of the AuthMgr BE
@@ -60,7 +51,7 @@ pub trait Device: Send {
     fn handover_client_connection(
         &self,
         service_name: &str,
-        client_seq_number: i32,
+        client_seq_number: i64,
         client_conn_handle: Box<dyn RawConnection>,
         is_persistent: bool,
     ) -> Result<(), Error>;
@@ -183,7 +174,7 @@ pub trait Storage: Send {
     /// Use this method to update the client's DICE policy.
     fn update_client_policy_in_storage(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         latest_dice_policy: &Arc<Policy>,
     ) -> Result<(), Error>;
@@ -210,7 +201,7 @@ pub trait Storage: Send {
     /// AuthMgr BE's secure storage, otherwise, return None.
     fn read_client_context(
         &self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
     ) -> Result<Option<Self::ClientContext>, Error>;
 
@@ -219,7 +210,7 @@ pub trait Storage: Send {
     /// instance.
     fn create_client_context(
         &mut self,
-        instance_seq_number: i32,
+        instance_seq_number: i64,
         client_id: &Arc<ClientId>,
         client_info: Self::ClientContext,
     ) -> Result<(), Error>;
@@ -232,10 +223,10 @@ pub trait PersistentStorage:
 {
     /// Retrieve the global sequence number stored in the factory-reset surviving secure storage of
     /// the AuthMgr BE. If it does not already exist, initialize it from 0.
-    fn get_or_create_global_sequence_number(&mut self) -> Result<i32, Error>;
+    fn get_or_create_global_sequence_number(&mut self) -> Result<i64, Error>;
 
     /// Increment the global sequence number stored in the factory-reset surviving secure storage of
     /// the AuthMgr BE. Return the latest global sequence number if successful andan error if it
     /// does not exist in the AuthMgr BE's secure storage.
-    fn increment_global_sequence_number(&mut self) -> Result<i32, Error>;
+    fn increment_global_sequence_number(&mut self) -> Result<i64, Error>;
 }
diff --git a/authmgr-common/src/lib.rs b/authmgr-common/src/lib.rs
index 477b745..dd739a4 100644
--- a/authmgr-common/src/lib.rs
+++ b/authmgr-common/src/lib.rs
@@ -19,8 +19,10 @@
 #![no_std]
 extern crate alloc;
 
+use alloc::boxed::Box;
 use alloc::string::String;
 use authgraph_core::key::{CertChain, DiceChainEntry, Policy};
+use authgraph_core::traits::{EcDsa, Rng};
 use coset::{CborSerializable, CoseError};
 use dice_policy::{DicePolicy, DICE_POLICY_VERSION};
 
@@ -60,6 +62,14 @@ pub enum ErrorCode {
     UnknownError,
 }
 
+/// The cryptographic functionality that must be provided by an implementation of AuthMgr BE
+pub struct CryptoTraitImpl {
+    /// Implementation of ECDSA functionality
+    pub ecdsa: Box<dyn EcDsa>,
+    /// Implementation of secure random number generation
+    pub rng: Box<dyn Rng>,
+}
+
 /// AuthMgr common result type
 pub type Result<T, E = Error> = core::result::Result<T, E>;
 
@@ -137,11 +147,10 @@ mod tests {
     use alloc::string::ToString;
     use alloc::{vec, vec::Vec};
     use authgraph_boringssl::ec::BoringEcDsa;
-    use authgraph_core::key::{
-        AUTHORITY_HASH, CONFIG_DESC, GUEST_OS_COMPONENT_NAME, INSTANCE_HASH, MODE, SECURITY_VERSION,
-    };
+    use authgraph_core::key::{AUTHORITY_HASH, CONFIG_DESC, INSTANCE_HASH, MODE, SECURITY_VERSION};
     use authgraph_core_test::{
         create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
+        TEST_OS_COMPONENT_NAME,
     };
     use authmgr_common_util::{
         get_constraint_spec_for_static_trusty_ta, get_constraints_spec_for_trusty_vm,
@@ -157,7 +166,7 @@ mod tests {
         let cert_chain_1 =
             CertChain::from_slice(&cert_chain_bytes_1).expect("failed to decode cert_chain 1");
         // Create constraints spec 1
-        let constraint_spec_1 = get_constraints_spec_for_trusty_vm();
+        let constraint_spec_1 = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
         // Create policy 1 given constraints spec 1 and DICE chain 1
         let policy_1 = Policy(
             dice_policy_builder::policy_for_dice_chain(
@@ -233,7 +242,7 @@ mod tests {
         let cert_chain_1 =
             CertChain::from_slice(&cert_chain_bytes_1).expect("failed to decode cert_chain 1");
         // Create constraints spec 1
-        let constraint_spec_1 = get_constraints_spec_for_trusty_vm();
+        let constraint_spec_1 = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
         // Create policy 1 given constraints spec 1 and DICE chain 1
         let policy_1 = Policy(
             dice_policy_builder::policy_for_dice_chain(
@@ -403,13 +412,13 @@ mod tests {
                 ConstraintType::ExactMatch,
                 vec![CONFIG_DESC, INSTANCE_HASH],
                 MissingAction::Fail,
-                TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
+                TargetEntry::ByName(TEST_OS_COMPONENT_NAME.to_string()),
             ),
             ConstraintSpec::new(
                 ConstraintType::GreaterOrEqual,
                 vec![CONFIG_DESC, SECURITY_VERSION],
                 MissingAction::Fail,
-                TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
+                TargetEntry::ByName(TEST_OS_COMPONENT_NAME.to_string()),
             ),
         ]
     }
diff --git a/authmgr-common/util/src/lib.rs b/authmgr-common/util/src/lib.rs
index ea3c327..eacb57e 100644
--- a/authmgr-common/util/src/lib.rs
+++ b/authmgr-common/util/src/lib.rs
@@ -20,8 +20,8 @@ extern crate alloc;
 
 use alloc::vec::Vec;
 use authgraph_core::key::{
-    DiceChainEntry, AUTHORITY_HASH, COMPONENT_NAME, CONFIG_DESC, GUEST_OS_COMPONENT_NAME,
-    INSTANCE_HASH, MODE, SECURITY_VERSION,
+    DiceChainEntry, AUTHORITY_HASH, COMPONENT_NAME, CONFIG_DESC, INSTANCE_HASH, MODE,
+    SECURITY_VERSION,
 };
 use authmgr_common::{amc_err, Error, ErrorCode, Result};
 use dice_policy::{DicePolicy, NodeConstraints, DICE_POLICY_VERSION};
@@ -57,7 +57,7 @@ pub fn policy_for_dice_node(
 /// Constraints spec to create a DICE policy for a DICE cert chain of a Trusty VM.
 /// Note that this is a helper method only. The implementors of AuthMgr-FE should build a constraint
 /// spec according to their environment and requirements.
-pub fn get_constraints_spec_for_trusty_vm() -> Vec<ConstraintSpec> {
+pub fn get_constraints_spec_for_trusty_vm(guest_os_component_name: &str) -> Vec<ConstraintSpec> {
     vec![
         ConstraintSpec::new(
             ConstraintType::ExactMatch,
@@ -81,13 +81,26 @@ pub fn get_constraints_spec_for_trusty_vm() -> Vec<ConstraintSpec> {
             ConstraintType::ExactMatch,
             vec![CONFIG_DESC, INSTANCE_HASH],
             MissingAction::Fail,
-            TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
+            TargetEntry::ByName(guest_os_component_name.to_string()),
         ),
         ConstraintSpec::new(
             ConstraintType::GreaterOrEqual,
             vec![CONFIG_DESC, SECURITY_VERSION],
             MissingAction::Fail,
-            TargetEntry::ByName(GUEST_OS_COMPONENT_NAME.to_string()),
+            TargetEntry::ByName(guest_os_component_name.to_string()),
+        ),
+        // Trusty system VMs are all signed with the same key. By default
+        // pvmfw gives all VMs the same component name in their DICE cert.
+        // This makes trusty VM policies potentially distinguishable only by the
+        // host-provided instance id. When we build trusty VMs we assign a
+        // unique name by setting the avb footer property com.android.virt.name.
+        // Constraining our DICE policies on this name ensures the cert chain
+        // of one system trusty VM cannot match the policy of another.
+        ConstraintSpec::new(
+            ConstraintType::ExactMatch,
+            vec![CONFIG_DESC, COMPONENT_NAME],
+            MissingAction::Fail,
+            TargetEntry::ByName(guest_os_component_name.to_string()),
         ),
     ]
 }
diff --git a/authmgr-fe/Android.bp b/authmgr-fe/Android.bp
new file mode 100644
index 0000000..ff2687a
--- /dev/null
+++ b/authmgr-fe/Android.bp
@@ -0,0 +1,46 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+package {
+    default_applicable_licenses: ["system_see_authmgr_license"],
+}
+
+rust_defaults {
+    name: "libauthmgr_fe_defaults",
+    defaults: [
+        "authmgr_use_latest_hal_aidl_rust",
+    ],
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    rustlibs: [
+        "libauthgraph_core",
+        "libauthmgr_common",
+        "libcoset",
+        "libciborium",
+        "liblog_rust",
+    ],
+    no_stdlibs: true,
+}
+
+rust_library {
+    name: "libauthmgr_fe",
+    crate_name: "authmgr_fe",
+    defaults: ["libauthmgr_fe_defaults"],
+}
+
+rust_test {
+    name: "libauthmgr_fe_unit_test",
+    crate_name: "authmgr_fe_unit_test",
+    defaults: ["libauthmgr_fe_defaults"],
+    test_suites: ["general-tests"],
+}
diff --git a/authmgr-fe/src/authorization.rs b/authmgr-fe/src/authorization.rs
new file mode 100644
index 0000000..ad27ed9
--- /dev/null
+++ b/authmgr-fe/src/authorization.rs
@@ -0,0 +1,205 @@
+// Copyright 2024 Google LLC
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
+//! Core logic for an AuthMgr Frontend (FE) as defined in
+//! hardware/interfaces/security/see/authmgr/IAuthMgrAuthorization.aidl
+
+use crate::error::Error;
+use crate::traits::{ConnectionToAuthorize, Device};
+use alloc::boxed::Box;
+use alloc::vec::Vec;
+use log::warn;
+
+use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::{
+    DiceChainEntry::DiceChainEntry, DiceLeafArtifacts::DiceLeafArtifacts, DicePolicy::DicePolicy,
+    Error::Error as IAuthMgrAuthorizationError, ExplicitKeyDiceCertChain::ExplicitKeyDiceCertChain,
+    IAuthMgrAuthorization::IAuthMgrAuthorization, SignedConnectionRequest::SignedConnectionRequest,
+};
+use android_hardware_security_see_authmgr::binder;
+use authgraph_core::key::{DiceChainEntry as AuthGraphDiceChainEntry, EcSignKey};
+use authmgr_common::signed_connection_request::{Challenge, ConnectionRequest, TransportIdInfo};
+use authmgr_common::{CryptoTraitImpl, Token, CMD_RAW, TOKEN_LENGTH};
+use coset::CborSerializable;
+
+/// The core logic for AuthMgr FE
+pub struct AuthMgrFe {
+    device: Box<dyn Device>,
+    crypto: CryptoTraitImpl,
+    authmgr: binder::Strong<dyn IAuthMgrAuthorization>,
+    is_pvm_authenticated: bool,
+}
+
+impl AuthMgrFe {
+    /// Create a new AuthMgrFE
+    pub fn new(
+        device: Box<dyn Device>,
+        crypto: CryptoTraitImpl,
+        authmgr: binder::Strong<dyn IAuthMgrAuthorization>,
+    ) -> Self {
+        AuthMgrFe { device, crypto, authmgr, is_pvm_authenticated: false }
+    }
+
+    /// Authenticate a protected virtual machine (pVM).
+    ///
+    /// In IAuthMgrAuthorization this is referred to as phase 1 of the AuthMgr protocol.
+    ///
+    /// `policy` is a CBOR-encoded DicePolicy as defined in
+    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ \
+    /// DicePolicy.cddl
+    ///
+    /// Callers should ensure that policies are specific to their pVMs and enforce rollback
+    /// protection. At a minimum, this means enforcing that authority hashes match for all nodes in
+    /// a chain and security versions are greater than or equal to the given policy. Callers may
+    /// also want to ensure that the leaf component name matches in the case where multiple VMs are
+    /// being signed with the same signing key. In this case, component names must be unique.
+    ///
+    /// It is strongly recommended to use the AOSP-provided `libdice_policy_builder` crate to create
+    /// policies for a given dice chain.
+    ///
+    /// An Ok(()) Result indicates that the pVM has been successfully authenticated
+    /// and can attempt to resolve authorized connections using phase 2 of the
+    /// AuthMgr protocol.
+    pub fn authenticate_pvm(
+        &mut self,
+        cert_chain: Vec<u8>,
+        signing_key: EcSignKey,
+        policy: Vec<u8>,
+    ) -> Result<(), Error> {
+        let dice_chain = ExplicitKeyDiceCertChain { diceCertChain: cert_chain };
+
+        // We need to convert from Option<[u8: 64]> to what
+        // initAuthentication expects, Option<&[u8]>
+        let owned_oob_ident = self.device.get_out_of_band_identifier();
+        let oob_ident = owned_oob_ident.as_ref().map(|i| i.as_slice());
+
+        let challenge = self.authmgr.initAuthentication(&dice_chain, oob_ident)?;
+
+        let signed_connection_request =
+            self.get_signed_connection_request(challenge, signing_key)?;
+        let dice_policy = DicePolicy { dicePolicy: policy };
+
+        self.authmgr.completeAuthentication(&signed_connection_request, &dice_policy)?;
+
+        // If we've reached this point, completeAuthentication returned Ok(()) and
+        // we can consider this pVM successfully authenticated.
+        self.is_pvm_authenticated = true;
+
+        Ok(())
+    }
+
+    /// Authorize a connection on behalf of a client.
+    ///
+    /// In IAuthMgrAuthorization this is referred to as phase 2 of the AuthMgr protocol.
+    ///
+    /// A successful Result from this function indicates that the caller can hand the given
+    /// connection back to the specified client and that client can expect that the requested
+    /// trusted service will be on the other end of the connection (i.e. AuthMgr-BE has also
+    /// handed its end of the connection off).
+    ///
+    /// `client_id` must be unique within this OS and should be enforced by an entity with greater
+    /// privilege than AuthMgr-FE if possible. As an example, the Trusty OS uses trusted applet
+    /// UUIDs, which are provided to AuthMgr-FE by the kernel during IPC.
+    ///
+    /// `leaf_policy` is a CBOR-encoded DicePolicy as defined in
+    /// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/ \
+    /// DicePolicy.cddl
+    ///
+    /// A `leaf_policy` should be specified in such a way as to uniquely identify a client and
+    /// prevent other clients within this pVM from impersonating that client. In the initial Trusty
+    /// pVMs, we use UUIDs as component names for DICE leaf certs, but environments with dynamic app
+    /// loading or multiple signing entities will need to consider limits on authorities, security
+    /// versions, and other OS-specific policies.
+    pub fn authorize_connection(
+        &self,
+        connection: &dyn ConnectionToAuthorize,
+        client_id: &[u8],
+        service_name: &str,
+        // TODO at the end of the day these values are just serialized directly.
+        // It does not make sense for callers to serde only for us to ser again.
+        dice_leaf: AuthGraphDiceChainEntry,
+        leaf_policy: Vec<u8>,
+    ) -> Result<(), Error> {
+        // The initial message on the out of band connection consists of
+        // a single byte control character (CMD_RAW) and a Token.
+        let msg_size = 1 + TOKEN_LENGTH;
+        let mut initial_msg = Vec::new();
+        initial_msg.try_reserve(msg_size)?;
+        initial_msg.push(CMD_RAW);
+        initial_msg.resize(msg_size, 0);
+        self.crypto.rng.fill_bytes(&mut initial_msg[1..]);
+        let token: &Token = initial_msg[1..].try_into().expect("token should be TOKEN_LENGTH size");
+
+        connection.send(&initial_msg)?;
+
+        let dice_leaf_artifacts = DiceLeafArtifacts {
+            diceLeaf: DiceChainEntry { diceChainEntry: dice_leaf.to_vec()? },
+            diceLeafPolicy: DicePolicy { dicePolicy: leaf_policy },
+        };
+
+        // We've established a connection to the AuthMgr-BE and sent a unique token over
+        // to it. Now ask the AuthMgr-BE to authorize it.
+        let auth_res = self.authmgr.authorizeAndConnectClientToTrustedService(
+            client_id,
+            service_name,
+            token,
+            &dice_leaf_artifacts,
+        );
+
+        // TODO: b/411457820 - remove this once we update the protocol to fix this issue
+        // There's no guarantee that the service will process the raw connection before we
+        // attempt to authorize. We currently have no way of knowing that the send on our
+        // raw connection was processed. In that case only, we retry. Retrying with the same token
+        // should be fine because the BE hasn't seen it yet.
+        match auth_res {
+            Ok(_) => Ok(()),
+            Err(b)
+                if b.service_specific_error()
+                    == IAuthMgrAuthorizationError::NO_CONNECTION_TO_AUTHORIZE.get() =>
+            {
+                warn!(
+                    "Retrying authorization for client {client_id:?} and service {service_name} \
+                because authmgr-be has not processed the raw connection yet"
+                );
+                Ok(self.authmgr.authorizeAndConnectClientToTrustedService(
+                    client_id,
+                    service_name,
+                    token,
+                    &dice_leaf_artifacts,
+                )?)
+            }
+            Err(e) => Err(e)?,
+        }
+    }
+
+    fn get_signed_connection_request(
+        &self,
+        challenge: Challenge,
+        signing_key: EcSignKey,
+    ) -> Result<SignedConnectionRequest, Error> {
+        let transport_info = self.device.get_transport_id_info()?;
+        let connection_request = match transport_info {
+            TransportIdInfo::FFATransportId { fe_id, be_id } => {
+                ConnectionRequest::new_for_ffa_transport(challenge, fe_id, be_id)
+            }
+        };
+        let algo = signing_key.get_cose_sign_algorithm();
+
+        let signed_buff =
+            connection_request.sign(&signing_key, self.crypto.ecdsa.as_ref(), algo)?;
+
+        Ok(SignedConnectionRequest { signedConnectionRequest: signed_buff })
+    }
+}
diff --git a/authmgr-fe/src/error.rs b/authmgr-fe/src/error.rs
new file mode 100644
index 0000000..c934888
--- /dev/null
+++ b/authmgr-fe/src/error.rs
@@ -0,0 +1,75 @@
+// Copyright 2024 Google LLC
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
+//! Error definitions for AuthMgr FE
+
+use alloc::collections::TryReserveError;
+use android_hardware_security_see_authmgr::binder;
+use authgraph_core::error::Error as AuthGraphError;
+use coset::CoseError;
+
+/// All errors thrown by AuthMgr FE
+#[derive(Debug)]
+pub enum Error {
+    /// Errors thrown by the IAuthMgrAuthorization service
+    BinderStatus(binder::Status),
+    /// Errors from the authmgr_common lib
+    AuthMgrCommonError(authmgr_common::Error),
+    /// Errors working with COSE objects
+    CoseError(coset::CoseError),
+    /// An error with a provided crypto operation
+    CryptoError(AuthGraphError),
+    /// A fallible allocation has failed
+    FailedAlloc,
+    /// Failed to connect to AuthMgr-BE
+    AuthMgrBeConnectionFailed,
+}
+
+impl From<binder::Status> for Error {
+    fn from(s: binder::Status) -> Self {
+        Self::BinderStatus(s)
+    }
+}
+
+impl From<binder::StatusCode> for Error {
+    fn from(s: binder::StatusCode) -> Self {
+        Self::BinderStatus(s.into())
+    }
+}
+
+impl From<coset::CoseError> for Error {
+    fn from(e: CoseError) -> Self {
+        Self::CoseError(e)
+    }
+}
+
+impl From<AuthGraphError> for Error {
+    fn from(e: AuthGraphError) -> Self {
+        Self::CryptoError(e)
+    }
+}
+
+impl From<authmgr_common::Error> for Error {
+    fn from(e: authmgr_common::Error) -> Self {
+        Self::AuthMgrCommonError(e)
+    }
+}
+
+impl From<TryReserveError> for Error {
+    fn from(_: TryReserveError) -> Self {
+        Self::FailedAlloc
+    }
+}
diff --git a/authmgr-fe/src/lib.rs b/authmgr-fe/src/lib.rs
new file mode 100644
index 0000000..4e05295
--- /dev/null
+++ b/authmgr-fe/src/lib.rs
@@ -0,0 +1,9 @@
+//! The AuthMgr frontend library
+
+#![no_std]
+
+extern crate alloc;
+
+pub mod authorization;
+pub mod error;
+pub mod traits;
diff --git a/authmgr-fe/src/traits.rs b/authmgr-fe/src/traits.rs
new file mode 100644
index 0000000..a75648c
--- /dev/null
+++ b/authmgr-fe/src/traits.rs
@@ -0,0 +1,45 @@
+// Copyright 2024 Google LLC
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
+//! Traits required by concrete implementations of an AuthMgr Frontend (FE)
+
+use crate::error::Error;
+use authmgr_common::signed_connection_request::TransportIdInfo;
+
+/// Device specific behavior that a concrete implementation needs to provide
+pub trait Device: Send {
+    /// This function can be implemented to provide a unique instance id for
+    /// a given AuthMgr FE.
+    ///
+    /// For AuthMgr FEs running in pVMs this should return None because the
+    /// DICE chain for the pVM should contain the instance identifier.
+    fn get_out_of_band_identifier(&self) -> Option<[u8; 64]> {
+        None
+    }
+
+    /// The transport info for the AuthMgr Frontend (this pVM) and the
+    /// AuthMgr Backend (i.e. where IAuthMgrAuthorization is running)
+    fn get_transport_id_info(&self) -> Result<TransportIdInfo, Error>;
+}
+
+/// Implementers of this trait are connections to the AuthMgr-BE requesting
+/// to be handed over to a trusted service.
+///
+/// See `AuthMgrFe::authorize_connection` for more detail.
+pub trait ConnectionToAuthorize {
+    /// Send data on this connection. Implementers must send the entire buffer.
+    fn send(&self, buff: &[u8]) -> Result<(), Error>;
+}
```

