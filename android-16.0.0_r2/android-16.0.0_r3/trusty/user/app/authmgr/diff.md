```diff
diff --git a/authmgr-be/app/main.rs b/authmgr-be/app/main.rs
index a1560a0..2a1709d 100644
--- a/authmgr-be/app/main.rs
+++ b/authmgr-be/app/main.rs
@@ -23,7 +23,7 @@ fn log_formatter(record: &log::Record) -> String {
     // line number should be present, so keeping it simple by just returning a 0.
     let line = record.line().unwrap_or(0);
     let file = record.file().unwrap_or("unknown file");
-    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
+    format!("{}: authmgr-be: {}:{} {}\n", record.level(), file, line, record.args())
 }
 
 fn main() {
diff --git a/authmgr-be/lib/rules.mk b/authmgr-be/lib/rules.mk
index 2aed10f..c82d9cd 100644
--- a/authmgr-be/lib/rules.mk
+++ b/authmgr-be/lib/rules.mk
@@ -40,6 +40,7 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/authmgr-common-util-rust \
 	trusty/user/base/lib/secretkeeper/dice_policy \
 	trusty/user/base/lib/secretkeeper/dice-policy-builder \
+	trusty/user/base/lib/service_manager/client \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
diff --git a/authmgr-be/lib/src/authorization_service.rs b/authmgr-be/lib/src/authorization_service.rs
index 70c1021..6c5dfa8 100644
--- a/authmgr-be/lib/src/authorization_service.rs
+++ b/authmgr-be/lib/src/authorization_service.rs
@@ -40,19 +40,15 @@ use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHand
 use binder::ParcelFileDescriptor;
 use binder::SpIBinder;
 use binder::Strong;
-use log::error;
+use log::{error, info};
 use rpcbinder::{FileDescriptorTransportMode, RpcSession};
-use std::ffi::CStr;
+use service_manager::{service_name_to_trusty_c_port, HANDOVER_SERVICE_PREFIX};
 use std::os::fd::FromRawFd;
 use std::os::fd::OwnedFd;
 use std::sync::Arc;
 use std::sync::Mutex;
 use tipc::Handle;
 
-// TODO: b/400118241. Construct the handover service's port from the given service name.
-// For now, hardcode the port for the handover service of the HelloWorld TA.
-const HANDOVER_SERVICE_PORT: &CStr = c"com.android.trusty.rust.handover.hello.service.V1";
-
 /// Represents a per-session RPC binder object which implements the `IAuthMgrAuthorization`
 /// interface. This encapsulates the connection information as well as the global state of the
 /// AuthMgr Authorization service.
@@ -148,6 +144,7 @@ impl IAuthMgrAuthorization for AuthMgrAuthorizationRPCService {
         token: &[u8; 32],
         client_dice_artifacts: &DiceLeafArtifacts,
     ) -> binder::Result<()> {
+        info!("Attempting to authorize and connect client {client_id:02x?} to {service_name}");
         let mut global_state = self.global_state.lock().unwrap();
         let mut connection_info = self.connection_information.lock().unwrap();
         global_state
@@ -160,6 +157,11 @@ impl IAuthMgrAuthorization for AuthMgrAuthorizationRPCService {
                 &client_dice_artifacts.diceLeaf.diceChainEntry,
                 &client_dice_artifacts.diceLeafPolicy.dicePolicy,
             )
+            .inspect(|_| {
+                info!(
+                    "Successfully authorized and connected client {client_id:02x?} to {service_name}"
+                );
+            })
             .map_err(|e| {
                 error!("Failed step 2 of phase 1: {:?}", e);
                 errcode_to_binder_err(e.0)
@@ -298,21 +300,26 @@ impl Device for DeviceInformation {
 
     fn handover_client_connection(
         &self,
-        _service_name: &str,
-        client_seq_number: i32,
+        service_name: &str,
+        client_seq_number: i64,
         client_conn_handle: Box<dyn RawConnection>,
         _is_persistent: bool,
     ) -> Result<(), Error> {
-        // TODO: b/400118241.
-        // Currently we have the port of the hand over service hardcoded to that of the example TA.
-        // Instead the AuthMgr should construct the appropriate hand over service port based on the
-        // input `service_name`.
         // TODO: We may be able to retrieve an already setup RPC session to a trusted service from
         // the cache
+        let handover_service_port_name_len = service_name.len() + HANDOVER_SERVICE_PREFIX.len();
+        let mut handover_service_port_name = String::new();
+        handover_service_port_name.try_reserve(handover_service_port_name_len)?;
+        handover_service_port_name.push_str(HANDOVER_SERVICE_PREFIX);
+        handover_service_port_name.push_str(service_name);
+        let updated_handover_service_port_name =
+            service_name_to_trusty_c_port(&handover_service_port_name).map_err(|_| {
+                am_err!(InternalError, "Failed to retrieve the handover port name.")
+            })?;
         let rpc_session = RpcSession::new();
         rpc_session.set_file_descriptor_transport_mode(FileDescriptorTransportMode::Trusty);
         let rpc_session: Strong<dyn ITrustedServicesHandover> =
-            rpc_session.setup_trusty_client(HANDOVER_SERVICE_PORT).map_err(|_e| {
+            rpc_session.setup_trusty_client(&updated_handover_service_port_name).map_err(|_e| {
                 am_err!(
                     ConnectionHandoverFailed,
                     "Failed to setup connection to the handover service."
diff --git a/authmgr-be/lib/src/handover_service.rs b/authmgr-be/lib/src/handover_service.rs
new file mode 100644
index 0000000..ef6b483
--- /dev/null
+++ b/authmgr-be/lib/src/handover_service.rs
@@ -0,0 +1,114 @@
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
+//! module to support creation of handover services by providing a generic implementation.
+use authmgr_be::error::ErrorCode;
+use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHandover::{
+    BnTrustedServicesHandover, ITrustedServicesHandover,
+};
+use binder::ParcelFileDescriptor;
+use log::error;
+use rpcbinder::RpcServer;
+use service_manager::service_name_to_trusty_c_port;
+use std::os::fd::AsRawFd;
+use std::sync::{Arc, Weak};
+use tipc::raw::{HandleSetWrapper, ToConnect, WorkToDo};
+use tipc::{ClientIdentifier, Handle, PortCfg, TipcError, Uuid};
+use trusty_std::TryClone;
+
+const ALLOWED_UUIDS: [Uuid; 1] =
+    [
+        /* authmgr_be uuid */
+        Uuid::new(0xf4768956, 0x62d9, 0x4904, [0x95, 0x12, 0x86, 0xdf, 0x36, 0x0d, 0x8d, 0x50]),
+    ];
+
+pub struct HandoverService {
+    handle_set: Weak<HandleSetWrapper<RpcServer>>,
+    trusted_service: Arc<RpcServer>,
+    service_port_config: PortCfg,
+}
+
+impl HandoverService {
+    pub fn new_handover_session(
+        _client_id: ClientIdentifier,
+        // Handleset is a weak reference to avoid potential cyclic references
+        handle_set: Weak<HandleSetWrapper<RpcServer>>,
+        trusted_service: Arc<RpcServer>,
+        service_port_config: PortCfg,
+    ) -> binder::Strong<dyn ITrustedServicesHandover> {
+        let handover_service = Self { handle_set, trusted_service, service_port_config };
+        BnTrustedServicesHandover::new_binder(handover_service, binder::BinderFeatures::default())
+    }
+}
+
+impl binder::Interface for HandoverService {}
+
+impl ITrustedServicesHandover for HandoverService {
+    fn handoverConnection(
+        &self,
+        fd: &ParcelFileDescriptor,
+        client_seq_num: i64,
+    ) -> binder::Result<()> {
+        let raw_fd = fd.as_raw_fd();
+        let handle = Handle::from_raw(raw_fd).map_err(|e| {
+            error!("Failed to create the handle from the raw fd: {:?}.", e);
+            binder::Status::new_exception_str(
+                binder::ExceptionCode::ILLEGAL_ARGUMENT,
+                Some("Could not create the handle from the raw fd."),
+            )
+        })?;
+        let dup_handle = handle.try_clone().map_err(|e| {
+            error!("Failed to clone the handle: {:?}", e);
+            binder::Status::new_service_specific_error(
+                ErrorCode::InternalError as i32,
+                Some(c"Failed to clone the handle."),
+            )
+        })?;
+        let port_config = self.service_port_config.try_clone().map_err(|e| {
+            error!("Failed to clone the port config: {:?}", e);
+            binder::Status::new_service_specific_error(
+                ErrorCode::MemoryAllocationFailed as i32,
+                Some(c"Failed to clone the port config."),
+            )
+        })?;
+        // Prevent the destructor of the handle from calling because it will be closed by the Parcel
+        // File Descriptor which owns it.
+        core::mem::forget(handle);
+        let to_connect = ToConnect::new(
+            dup_handle,
+            Arc::clone(&self.trusted_service),
+            port_config,
+            client_seq_num,
+        );
+        self.handle_set
+            .upgrade()
+            .ok_or(binder::Status::new_exception_str(
+                binder::ExceptionCode::ILLEGAL_ARGUMENT,
+                Some("Failed to get the handle set."),
+            ))?
+            .add_work(WorkToDo::Connect(to_connect));
+        Ok(())
+    }
+}
+
+pub fn default_handover_port_config(handover_service_name: &str) -> Result<PortCfg, TipcError> {
+    Ok(PortCfg::new_raw(service_name_to_trusty_c_port(handover_service_name).map_err(|e| {
+        error!("Failed to construct the handover port name: {:?}", e);
+        TipcError::UnknownError
+    })?)
+    .allow_ta_connect()
+    .allowed_uuids(&ALLOWED_UUIDS))
+}
diff --git a/authmgr-be/lib/src/lib.rs b/authmgr-be/lib/src/lib.rs
index 6125d87..658c463 100644
--- a/authmgr-be/lib/src/lib.rs
+++ b/authmgr-be/lib/src/lib.rs
@@ -17,6 +17,10 @@
 //! Entry point to the AuthMgr BE TA library
 
 mod authorization_service;
+mod handover_service;
 pub mod server;
 #[cfg(test)]
 mod tests;
+
+pub use handover_service::default_handover_port_config;
+pub use handover_service::HandoverService;
diff --git a/authmgr-be/lib/src/server.rs b/authmgr-be/lib/src/server.rs
index 6aa8879..bcb27e1 100644
--- a/authmgr-be/lib/src/server.rs
+++ b/authmgr-be/lib/src/server.rs
@@ -34,7 +34,7 @@ use tipc::{
 use trusty_std::alloc::TryAllocFrom;
 
 /// Port for the AuthMgr main service
-pub(crate) const AUTHMGR_SERVICE_PORT: &CStr = c"com.android.trusty.rust.authmgr.V1";
+pub(crate) const AUTHMGR_SERVICE_PORT: &CStr = c"ahss.authmgr.IAuthMgrAuthorization/default.bnd";
 
 /// Maximum message size.
 /// TODO: determine the size
@@ -101,7 +101,7 @@ impl UnbufferedService for AuthMgrService {
         handle: &Handle,
         peer: &Uuid,
     ) -> Result<ConnectResult<Self::Connection>, TipcError> {
-        debug!("Accepted AthMgr BE connection from uuid: {:?}, handle: {:?}", peer, handle);
+        debug!("Accepted AuthMgr BE connection from uuid: {:?}, handle: {:?}", peer, handle);
         Ok(ConnectResult::Accept(AuthMgrConnection {
             uuid: peer.clone(),
             pending_to_be_routed: Arc::new(Mutex::new(true)),
@@ -166,11 +166,12 @@ impl UnbufferedService for AuthMgrService {
                     let authmgr_service_port_cfg = PortCfg::new_raw(AUTHMGR_SERVICE_PORT.into())
                         .allow_ta_connect()
                         .allow_ns_connect();
-                    let rpc_connection = match self.rpc_service.on_connect(
-                        &authmgr_service_port_cfg,
-                        handle,
-                        &connection.uuid,
-                    )? {
+                    let rpc_connection = match self
+                        .rpc_service
+                        .on_connect(&authmgr_service_port_cfg, handle, &connection.uuid)
+                        .inspect_err(|e| {
+                            log::debug!("error on_connection {:?}", e);
+                        })? {
                         ConnectResult::Accept(conn) => conn,
                         ConnectResult::CloseConnection => {
                             return Ok(MessageResult::CloseConnection)
diff --git a/authmgr-be/lib/src/tests.rs b/authmgr-be/lib/src/tests.rs
index b598832..af16aae 100644
--- a/authmgr-be/lib/src/tests.rs
+++ b/authmgr-be/lib/src/tests.rs
@@ -26,7 +26,7 @@ use authgraph_boringssl::{BoringEcDsa, BoringRng};
 use authgraph_core::key::{CertChain, DiceChainEntry};
 use authgraph_core::traits::Rng;
 use authgraph_core_test::{
-    create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
+    create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, TEST_OS_COMPONENT_NAME,
 };
 use authmgr_common::{
     signed_connection_request::{
@@ -46,6 +46,11 @@ use test::assert_ok;
 use tipc::{Deserialize, Handle, Serialize, Serializer, TipcError};
 use trusty_std::alloc::TryAllocFrom;
 
+// Note: TODO: b/404865387 - until we have an internal API in AuthMgr to delete a pVM context
+// created by a test, we need to use a different instance hash (instance id) for each test vm
+// context "stored" in AuthMgrBE storage, in order to avoid multiple tests interfering with each
+// other.
+
 test::init!();
 
 #[test]
@@ -103,11 +108,10 @@ fn test_authmgr_init_auth_ok() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (_signing_key, _cdi_values, cert_chain) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
-    let _challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let _challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 }
 
 #[test]
@@ -131,11 +135,9 @@ fn test_authmgr_init_auth_with_invalid_dice_chain() {
 
     let result_init_auth = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: Vec::<u8>::new() }, None);
-    assert!(result_init_auth.is_err());
-    assert_eq!(
-        result_init_auth.err().unwrap().service_specific_error(),
-        Error::INVALID_DICE_CERT_CHAIN.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INVALID_DICE_CERT_CHAIN.0, None);
+    assert_eq!(result_init_auth.err(), Some(expected_err));
 }
 
 #[test]
@@ -161,11 +163,9 @@ fn test_authmgr_init_auth_no_instance_id() {
     let result_init_auth = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
     // Expect error because the instance hash is neither in the DICE chain nor provided externally
-    assert!(result_init_auth.is_err());
-    assert_eq!(
-        result_init_auth.err().unwrap().service_specific_error(),
-        Error::INVALID_INSTANCE_IDENTIFIER.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INVALID_INSTANCE_IDENTIFIER.0, None);
+    assert_eq!(result_init_auth.err(), Some(expected_err));
 }
 
 #[test]
@@ -188,19 +188,16 @@ fn test_authmgr_duplicate_init_auth_with_same_vm_id() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (_signing_key, _cdi_values, cert_chain) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain.clone() }, None);
-    let _challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let _challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let result_init_auth2 = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
-    assert!(result_init_auth2.is_err());
-    assert_eq!(
-        result_init_auth2.err().unwrap().service_specific_error(),
-        Error::AUTHENTICATION_ALREADY_STARTED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::AUTHENTICATION_ALREADY_STARTED.0, None);
+    assert_eq!(result_init_auth2.err(), Some(expected_err));
 }
 
 #[test]
@@ -224,11 +221,10 @@ fn test_authmgr_duplicate_init_auth_with_same_vm_id_after_cache_cleanup() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (_signing_key, _cdi_values, cert_chain) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain.clone() }, None);
-    let _challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let _challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
     // Drop the first connection to trigger cache cleanup
     core::mem::drop(conn_rpc);
 
@@ -250,7 +246,7 @@ fn test_authmgr_duplicate_init_auth_with_same_vm_id_after_cache_cleanup() {
 
     let result_init_auth2 = rpc_session_2
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
-    let _challenge: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth2);
+    let _challenge = assert_ok!(result_init_auth2);
 }
 
 #[test]
@@ -271,13 +267,12 @@ fn test_authmgr_complete_auth_ok() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -296,13 +291,13 @@ fn test_authmgr_complete_auth_ok() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -332,13 +327,12 @@ fn test_authmgr_duplicate_init_auth_on_authenticated_connection() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -357,13 +351,13 @@ fn test_authmgr_duplicate_init_auth_on_authenticated_connection() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -372,14 +366,12 @@ fn test_authmgr_duplicate_init_auth_on_authenticated_connection() {
     );
     assert_ok!(result_complete_auth);
 
-    // ******* Invoke step 1 of phase 1 of the protocol over the same connection ********
+    // Invoke step 1 of phase 1 of the protocol over the same connection**
     let result_init_auth2 = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes }, None);
-    assert!(result_init_auth2.is_err());
-    assert_eq!(
-        result_init_auth2.err().unwrap().service_specific_error(),
-        Error::INSTANCE_ALREADY_AUTHENTICATED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INSTANCE_ALREADY_AUTHENTICATED.0, None);
+    assert_eq!(result_init_auth2.err(), Some(expected_err));
 }
 
 #[test]
@@ -402,13 +394,12 @@ fn test_authmgr_duplicate_init_auth_with_same_instance_id_of_authenticatd_vm_on_
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -427,13 +418,13 @@ fn test_authmgr_duplicate_init_auth_with_same_instance_id_of_authenticatd_vm_on_
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -442,7 +433,7 @@ fn test_authmgr_duplicate_init_auth_with_same_instance_id_of_authenticatd_vm_on_
     );
     assert_ok!(result_complete_auth);
 
-    // ******* Invoke step 1 of phase 1 of the protocol over a different connection ********
+    // Invoke step 1 of phase 1 of the protocol over a different connection**
     let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
     assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
     let cb_authmgr_2 = || {
@@ -459,11 +450,9 @@ fn test_authmgr_duplicate_init_auth_with_same_instance_id_of_authenticatd_vm_on_
 
     let result_init_auth2 = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes }, None);
-    assert!(result_init_auth2.is_err());
-    assert_eq!(
-        result_init_auth2.err().unwrap().service_specific_error(),
-        Error::INSTANCE_ALREADY_AUTHENTICATED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INSTANCE_ALREADY_AUTHENTICATED.0, None);
+    assert_eq!(result_init_auth2.err(), Some(expected_err));
 }
 
 #[test]
@@ -488,13 +477,12 @@ fn test_authmgr_duplicate_init_auth_with_diff_instance_ids_same_vm_id_of_authent
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -513,13 +501,13 @@ fn test_authmgr_duplicate_init_auth_with_diff_instance_ids_same_vm_id_of_authent
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -529,17 +517,10 @@ fn test_authmgr_duplicate_init_auth_with_diff_instance_ids_same_vm_id_of_authent
     assert_ok!(result_complete_auth);
 
     // Create a DICE chain with a different instance hash
-    pub const DIFF_INSTANCE_HASH: [u8; 64] = [
-        0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9c, 0xf3, 0xcd, 0xc7, 0xa4,
-        0x2a, 0x7d, 0x7e, 0xf5, 0x8e, 0xd6, 0x4d, 0x82, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
-        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x5b, 0x3f, 0xc9,
-        0x6a, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x3d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a, 0x7d, 0x7e,
-        0xf5, 0x8e, 0xf5, 0x8e,
-    ];
     let (_signing_key_2, _cdi_values_2, cert_chain_bytes_2) =
-        create_dice_cert_chain_for_guest_os(Some(DIFF_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
 
-    // ******* Invoke step 1 of phase 1 of the protocol over a different connection ********
+    // Invoke step 1 of phase 1 of the protocol over a different connection
     let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
     assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
     let cb_authmgr_2 = || {
@@ -556,11 +537,9 @@ fn test_authmgr_duplicate_init_auth_with_diff_instance_ids_same_vm_id_of_authent
 
     let result_init_auth2 = rpc_session
         .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_2 }, None);
-    assert!(result_init_auth2.is_err());
-    assert_eq!(
-        result_init_auth2.err().unwrap().service_specific_error(),
-        Error::INSTANCE_ALREADY_AUTHENTICATED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INSTANCE_ALREADY_AUTHENTICATED.0, None);
+    assert_eq!(result_init_auth2.err(), Some(expected_err));
 }
 
 #[test]
@@ -630,17 +609,15 @@ fn test_authmgr_complete_auth_without_init_auth() {
         &SignedConnectionRequest { signedConnectionRequest: Vec::new() },
         &DicePolicy { dicePolicy: Vec::new() },
     );
-    assert!(result_complete_auth.is_err());
-    assert_eq!(
-        result_complete_auth.err().unwrap().service_specific_error(),
-        Error::AUTHENTICATION_NOT_STARTED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::AUTHENTICATION_NOT_STARTED.0, None);
+    assert_eq!(result_complete_auth.err(), Some(expected_err));
 }
 
 #[test]
 fn test_authmgr_duplicate_complete_auth_on_the_same_connection() {
     // Test IAuthMgrAuthorization AIDL interface - by invoking completeAuthentication on an alerady
-    // authenticated connection.
+    // authenticated connection, expect error.
     let conn_rpc =
         assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
     let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
@@ -656,13 +633,12 @@ fn test_authmgr_duplicate_complete_auth_on_the_same_connection() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -681,13 +657,13 @@ fn test_authmgr_duplicate_complete_auth_on_the_same_connection() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature.clone() },
         &DicePolicy {
@@ -702,11 +678,9 @@ fn test_authmgr_duplicate_complete_auth_on_the_same_connection() {
             dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
         },
     );
-    assert!(result_complete_auth2.is_err());
-    assert_eq!(
-        result_complete_auth2.err().unwrap().service_specific_error(),
-        Error::INSTANCE_ALREADY_AUTHENTICATED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INSTANCE_ALREADY_AUTHENTICATED.0, None);
+    assert_eq!(result_complete_auth2.err(), Some(expected_err));
 }
 
 #[test]
@@ -729,13 +703,12 @@ fn test_authmgr_duplicate_complete_auth_on_new_connection() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -754,13 +727,13 @@ fn test_authmgr_duplicate_complete_auth_on_new_connection() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature.clone() },
         &DicePolicy {
@@ -769,7 +742,7 @@ fn test_authmgr_duplicate_complete_auth_on_new_connection() {
     );
     assert_ok!(result_complete_auth);
 
-    // ******* Invoke step 2 of phase 1 of the protocol over a different connection ********
+    // Invoke step 2 of phase 1 of the protocol over a different connection
     let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
     assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
     let cb_authmgr_2 = || {
@@ -790,11 +763,9 @@ fn test_authmgr_duplicate_complete_auth_on_new_connection() {
             dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
         },
     );
-    assert!(result_complete_auth_2.is_err());
-    assert_eq!(
-        result_complete_auth_2.err().unwrap().service_specific_error(),
-        Error::INSTANCE_ALREADY_AUTHENTICATED.0
-    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INSTANCE_ALREADY_AUTHENTICATED.0, None);
+    assert_eq!(result_complete_auth_2.err(), Some(expected_err));
 }
 
 #[test]
@@ -818,13 +789,12 @@ fn test_authmgr_duplicate_complete_auth_after_cache_cleanup() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, _cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -843,13 +813,13 @@ fn test_authmgr_duplicate_complete_auth_after_cache_cleanup() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    // Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -901,6 +871,537 @@ fn test_authmgr_duplicate_complete_auth_after_cache_cleanup() {
     assert_ok!(result_complete_auth_2);
 }
 
+#[test]
+fn authmgr_complete_auth_with_dice_chain_signature_error() {
+    // Test the IAuthMgrAuthorization AIDL interface - invoking completeAuthentication where the
+    // DICE chain has invalid signatures (note that although the DICE chain is passed in the
+    // initAuthentication call, the signatures are verified only in completeAuthentication, because
+    // the signature on the challenge is passed in the second call), expect error.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain with an invalid signature in the leaf certificate
+    let (_signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
+    let (_signing_key_diff, cdi_values_diff, _cert_chain_bytes_diff) =
+        create_dice_cert_chain_for_guest_os(None, 1);
+    let leaf_cert_bytes = create_dice_leaf_cert(cdi_values_diff, "keymint", 1);
+    let mut dice_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode dice chain");
+    let leaf_cert =
+        assert_ok!(DiceChainEntry::from_slice(&leaf_cert_bytes), "Failed to decode the leaf cert");
+    if let Some(ref mut cert_chain) = dice_chain.dice_cert_chain {
+        cert_chain.push(leaf_cert);
+    } else {
+        dice_chain.dice_cert_chain = Some(vec![leaf_cert]);
+    };
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain {
+            diceCertChain: assert_ok!(dice_chain.to_vec(), "Failed to encode DICE cert chain."),
+        },
+        None,
+    );
+    let _challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: Vec::new() },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::INVALID_DICE_CERT_CHAIN.0, None);
+    assert_eq!(result_complete_auth.err(), Some(expected_err));
+}
+
+#[test]
+fn authmgr_complete_auth_with_invalid_signature() {
+    // Test the IAuthMgrAuthorization AIDL interface - invoking completeAuthentication with
+    // an invalid signature, expect error.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain
+    let (_signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
+    // Create another DICE chain and use the signing key for (invalid) signing
+    let (signing_key_diff, _cdi_values_diff, _cert_chain_bytes_diff) =
+        create_dice_cert_chain_for_guest_os(None, 1);
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key_diff, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::SIGNATURE_VERIFICATION_FAILED.0, None);
+    assert_eq!(result_complete_auth.err(), Some(expected_err));
+}
+
+#[test]
+fn authmgr_complete_auth_with_invalid_dice_policy() {
+    // Test the IAuthMgrAuthorization AIDL interface - invoking completeAuthentication with
+    // an invalid policy, expect error.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy { dicePolicy: Vec::new() },
+    );
+    // TODO: b/406264572 expect INVALID_DICE_POLICY error code after refactoring authmgr-common
+    // code to use DicePolicy struct from the dice_policy library
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::DICE_POLICY_MATCHING_FAILED.0, None);
+    assert_eq!(result_complete_auth.err(), Some(expected_err));
+}
+
+#[test]
+fn authmgr_complete_auth_with_non_matching_dice_chain_and_policy() {
+    // Test the IAuthMgrAuthorization AIDL interface by invoking completeAuthentication where the
+    // DICE chain doesn't match the policy
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create two test DICE chains with different inputs, and corresponding DICE policies
+    let (signing_key_1, _cdi_values_1, cert_chain_bytes_1) =
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let _policy_1 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_1, constraint_spec.clone()),
+        "Failed to building policy for pvm"
+    );
+
+    let (_signing_key_2, _cdi_values_2, cert_chain_bytes_2) =
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 3);
+    let policy_2 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_2, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_1.clone() },
+        None,
+    );
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes_1), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key_1, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy_2.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::DICE_POLICY_MATCHING_FAILED.0, None);
+    assert_eq!(result_complete_auth.err(), Some(expected_err));
+}
+
+#[test]
+fn authmgr_rollback_protection_with_version_upgrade_for_pvm() {
+    // Test the IAuthMgrAuthorization AIDL interface by invoking completeAuthentication twice, where
+    // the DICE chain security version has been upgraded in the second call, expect success.
+    // Then try to authenticate with original DICE chain and policy, and expect error
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a DICE chain with security version 1, and the DICE policy
+    let instance_hash = generate_random_instance_hash();
+    const INITIAL_SECURITY_VERSION: u64 = 1;
+    let (signing_key_1, _cdi_values_1, cert_chain_bytes_1) =
+        create_dice_cert_chain_for_guest_os(Some(instance_hash), INITIAL_SECURITY_VERSION);
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let policy_1 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_1, constraint_spec.clone()),
+        "Failed to building policy for pvm"
+    );
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_1.clone() },
+        None,
+    );
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes_1), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key_1, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(
+                policy_1.clone().to_vec(),
+                "Failed to encode DICE policy for pvm"
+            ),
+        },
+    );
+    assert_ok!(result_complete_auth);
+    // Drop the first connection to trigger cache cleanup
+    core::mem::drop(conn_rpc);
+
+    // Create a DICE chain with security version 3, and the DICE policy
+    let (signing_key_2, _cdi_values_2, cert_chain_bytes_2) =
+        create_dice_cert_chain_for_guest_os(Some(instance_hash), INITIAL_SECURITY_VERSION + 2);
+    let policy_2 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_2, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // Setup a new connection
+    let conn_rpc_2 =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session_2: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth_2 = rpc_session_2
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_2 }, None);
+    let challenge_2: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth_2);
+
+    // Build the connection request to be signed
+    let conn_req_2 = ConnectionRequest::new_for_ffa_transport(
+        challenge_2,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    let signature_2 = assert_ok!(
+        conn_req_2.sign(&signing_key_2, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    let result_complete_auth_2 = rpc_session_2.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature_2 },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy_2.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth_2);
+
+    // Drop the second connection to trigger cache cleanup
+    core::mem::drop(conn_rpc_2);
+
+    // Setup a new connection
+    let conn_rpc_3 =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    assert_ok!(
+        conn_rpc_3.send(&AuthMgrMessage(vec![CMD_RPC])),
+        "Failed to send the command requesting RPC service."
+    );
+    let cb_authmgr_3 = || {
+        let fd = conn_rpc_3.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_3 = RpcSession::new();
+    let rpc_session_3: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_3.setup_preconnected_client(cb_authmgr_3),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth_3 = rpc_session_3
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_1 }, None);
+    let challenge_3: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth_3);
+
+    // Build the connection request to be signed
+    let conn_req_3 = ConnectionRequest::new_for_ffa_transport(
+        challenge_3,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    let signature_3 = assert_ok!(
+        conn_req_3.sign(&signing_key_1, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    let result_complete_auth_3 = rpc_session_3.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature_3 },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy_1.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::DICE_POLICY_MATCHING_FAILED.0, None);
+    assert_eq!(result_complete_auth_3.err(), Some(expected_err));
+}
+
+#[test]
+fn authmgr_rollback_protection_with_version_downgrade_for_pvm() {
+    // Test the IAuthMgrAuthorization AIDL interface by invoking completeAuthentication twice, where
+    // the DICE chain security version has been downgraded in the second call, expect error.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create two test DICE chains with different inputs, and corresponding DICE policies
+    let instance_hash = generate_random_instance_hash();
+    const CURRENT_SECURITY_VERSION: u64 = 3;
+    let (signing_key_1, _cdi_values_1, cert_chain_bytes_1) =
+        create_dice_cert_chain_for_guest_os(Some(instance_hash), CURRENT_SECURITY_VERSION);
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let policy_1 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_1, constraint_spec.clone()),
+        "Failed to building policy for pvm"
+    );
+
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_1.clone() },
+        None,
+    );
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes_1), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key_1, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    // Invoke step 2 of phase 1 of the protocol
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy_1.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+    // Drop the first connection to trigger cache cleanup
+    core::mem::drop(conn_rpc);
+
+    let (signing_key_2, _cdi_values_2, cert_chain_bytes_2) =
+        create_dice_cert_chain_for_guest_os(Some(instance_hash), CURRENT_SECURITY_VERSION - 2);
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
+    let policy_2 = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes_2, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // Setup a new connection
+    let conn_rpc_2 =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    assert_ok!(
+        conn_rpc_2.send(&AuthMgrMessage(vec![CMD_RPC])),
+        "Failed to send the command requesting RPC service."
+    );
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session_2: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth_2 = rpc_session_2.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_2.clone() },
+        None,
+    );
+    let challenge_2: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth_2);
+
+    // Build the connection request to be signed
+    let conn_req_2 = ConnectionRequest::new_for_ffa_transport(
+        challenge_2,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes_2), "Failed to decode the cert chain");
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature_2 = assert_ok!(
+        conn_req_2.sign(&signing_key_2, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    let result_complete_auth_2 = rpc_session_2.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature_2 },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy_2.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    let expected_err =
+        binder::Status::new_service_specific_error(Error::DICE_POLICY_MATCHING_FAILED.0, None);
+    assert_eq!(result_complete_auth_2.err(), Some(expected_err));
+}
+
 #[test]
 fn authmgr_full_protocol_happy_path() {
     // Connect to the TA and send message indicating the intent to connect to the binder RPC service
@@ -919,13 +1420,12 @@ fn authmgr_full_protocol_happy_path() {
     );
     // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
     let (signing_key, cdi_values, cert_chain_bytes) =
-        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+        create_dice_cert_chain_for_guest_os(Some(generate_random_instance_hash()), 1);
     let result_init_auth = rpc_session.initAuthentication(
         &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
         None,
     );
-    let challenge: [u8; TOKEN_LENGTH] =
-        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    let challenge = assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
 
     let cert_chain =
         assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
@@ -944,13 +1444,13 @@ fn authmgr_full_protocol_happy_path() {
         "Failed to sign connection request"
     );
     // Create a DICE policy
-    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let constraint_spec = get_constraints_spec_for_trusty_vm(TEST_OS_COMPONENT_NAME);
     let policy = assert_ok!(
         dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
         "Failed to building policy for pvm"
     );
 
-    // ****** Invoke step 2 of phase 1 of the protocol ******
+    //  Invoke step 2 of phase 1 of the protocol
     let result_complete_auth = rpc_session.completeAuthentication(
         &SignedConnectionRequest { signedConnectionRequest: signature },
         &DicePolicy {
@@ -972,7 +1472,7 @@ fn authmgr_full_protocol_happy_path() {
     let cmd_raw = AuthMgrMessage(msg);
     assert_ok!(conn_raw.send(&cmd_raw));
 
-    // ****** Execute phase 2 of the AuthMgr protocol ******
+    // Execute phase 2 of the AuthMgr protocol
     // Create DICE certificate and a DICE policy for the client
     let leaf_cert_bytes = create_dice_leaf_cert(cdi_values, "keymint", 1);
     let client_constraint_spec_km = get_constraint_spec_for_static_trusty_ta();
@@ -984,7 +1484,7 @@ fn authmgr_full_protocol_happy_path() {
     );
     let result_client_authz = rpc_session.authorizeAndConnectClientToTrustedService(
         &[],
-        "HelloService",
+        "android.hardware.security.IHelloWorld/default",
         &token,
         &DiceLeafArtifacts {
             diceLeaf: AidlDiceChainEntry { diceChainEntry: leaf_cert_bytes },
@@ -1013,3 +1513,11 @@ fn authmgr_full_protocol_happy_path() {
     let result = assert_ok!(trusted_service_rpc_session.sayHello("Test."));
     assert_eq!("Hello Test.", result);
 }
+
+// A helper function to generate a random instance hash
+fn generate_random_instance_hash() -> [u8; 64] {
+    let mut instance_hash = [0u8; 64];
+    let boring_rng = BoringRng;
+    boring_rng.fill_bytes(&mut instance_hash);
+    instance_hash
+}
diff --git a/authmgr-fe/README.md b/authmgr-fe/README.md
new file mode 100644
index 0000000..1a99045
--- /dev/null
+++ b/authmgr-fe/README.md
@@ -0,0 +1,132 @@
+# Trusty AuthMgr-FE
+
+This directory contains the source for the AuthMgr-FE TA. This TA was built for situations in
+which trusty is a VM guest, most often running as a protected VM. The TA is designed to be the
+only user space entity in a trusty VM that has access to the [DICE handover from pvmfw], which is
+presented to the trusty kernel in a `reserved-memory` node by pvmfw. As the user space owner of the
+VM's DICE chain and associated CDIs, the TA serves two functions:
+
+1. AuthMgr-FE is the hwbcc server for protected VMs
+2. AuthMgr-FE facilitates authorized connections to trusted HALs via the authmgr protocol.
+
+[Dice handover from pvmfw]: https://source.corp.google.com/h/googleplex-android/platform/superproject/main/+/main:packages/modules/Virtualization/guest/pvmfw/README.md
+
+## Useful AuthMgr references
+
+- [The AuthMgr protocol documentation](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/see/authmgr/aidl/README.md)
+- [The core AuthMgr-FE and AuthMgr-BE library source](https://cs.android.com/android/platform/superproject/main/+/main:system/see/authmgr/)
+
+## hwbcc server
+
+In trusty, the [hwbcc interface] allows user space TAs like Keymint to obtain DICE cert chains
+describing the current pVM and perform signing operations using keys derived from CDIs associated
+with that cert chain.
+
+The implementation of the server is in the [pvmdice] library. Not all `hwbcc` operations are
+currently supported, since we didn't initially add support for operations that had no existing
+use cases. The currently supported operations are:
+
+1. `HWBCC_GET_BCC`
+2. `HWBCC_SIGN_DATA`
+
+The server is compatible with both the [C client lib][hwbcc-c-client] and [Rust client lib][hwbcc-rust-client].
+
+[hwbcc-c-client]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/lib/hwbcc/client/
+[hwbcc-rust-client]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/lib/hwbcc/rust/src/lib.rs
+[hwbcc interface]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/interface/hwbcc/
+[pvmdice]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/lib/pvmdice/
+
+## AuthMgr protocol implementation
+
+The AuthMgr-FE TA implementation of the AuthMgr protocol allows a pVM to
+authenticate to an AuthMgr-BE in a secure partition and retrieve authenticated and authorized
+connections to trusted hal services in the form of Binder objects. The core traits and
+phase 1 of the protocol are implemented in [src/authorization.rs](src/authorization.rs)
+and phase 2 of the protocol is implemented in [src/accessor.rs](src/accessor.rs) .
+
+### Authenticating the pVM - AuthMgr Phase 1
+
+On TA startup, the AuthMgr-FE will use the pVM's DICE handover to authenticate itself to the
+AuthMgr-BE. Failure to authenticate will result in the TA exiting. Successful authentication
+of the VM is crucial, since this step provides rollback protection of the OS image.
+
+Rollback protection is provided via the DICE policy that AuthMgr-FE constructs. That policy
+ensures that once a given version, `N`, of the VM is authenticated by the AuthMgr-BE, an older
+version `(<N)` of the VM cannot be successfully authenticated by the AuthMgr-BE.
+
+### The trusty service_manager lib
+
+All Binder interfaces in trusty can be retrieved via the trusty [service_manager] library.
+We don't aim to give comprehensive documentation of that library here, but give an overview
+to explain how AuthMgr-FE interacts with it.
+
+The `service_manager` library implements an API surface as close as possible to the upstream
+Binder `ServiceManager` interface, so it may be familiar if you've worked with Binder in
+Android. To retrieve a Binder object via BinderRpc, one calls `wait_for_interface` with a
+service name:
+
+```
+let my_binder = service_manager::wait_for_interface("foo.bar.MyInterface/default");
+```
+
+`wait_for_interface` connects to the port serving the requested service name and expects to find
+either:
+
+1. The requested Binder interface, in which case it returns to the caller.
+2. An `ITrustyAccessor` Binder.
+
+The [ITrustyAccessor] interface allows a client to delegate connection establishment for a Binder
+object via BinderRpc to a different process. We rely on this to execute the AuthMgr protocol to
+retrieve authorized connections to trusted HALs. The fact that this interface is identical
+to the upstream Binder `IAccessor` interface is an implementation detail that should never
+be relied upon.
+
+[service_manager]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/lib/service_manager/
+[ITrustyAccessor]: https://cs.android.com/android/platform/superproject/main/+/main:trusty/user/base/interface/binder_accessor/trusty/os/ITrustyAccessor.aidl
+
+### AuthMgr-FE ITrustyAccessor implementation
+
+The AuthMgr-FE exposes an `ITrustyAccessor` for every trusted HAL interface it supports.
+Practically, this means it creates a port for each Trusted HAL and starts a BinderRpc server
+handling requests on that port. When a client uses `service_manager` to request a Trusted HAL
+Binder, `AuthMgrFeAccessor::addConnection()` will attempt to execute phase 2 of the AuthMgr
+protocol and create an authorized connection to the requested Trusted HAL service. If
+successful, it returns a ParcelFileDescriptor (implemented as a Handle in trusty) to the client.
+`service_manager::wait_for_interface` takes care of setting up a BinderRpc session on that file
+descriptor before it returns.
+
+### Flow Diagram
+
+The following is a sequence diagram, which can be rendered with [js-sequence-diagrams](https://bramp.github.io/js-sequence-diagrams/).
+This is automatically supported when viewing in Android code search.
+
+NOTE: This diagram is intended to show a high-level flow of how the AuthMgr-FE interacts with client
+TAs and the AuthMgr-BE. It glosses over some specifics of the AuthMgr protocol and does not show
+any detail about the implementation of the AuthMgr-BE or how it hands authorized connection
+requests over to trusted HAL implementations.
+
+```sequence-diagram
+Note over Client TA: Client calls service_manager::wait_for_interface("foo.bar.MyTrustedHal/default")
+Client TA->AuthMgrFE TA: ITrustyAccessor::addConnection()
+AuthMgrFE TA->AuthMgrFE TA: Derive client DICE cert
+AuthMgrFE TA->AuthMgrFE TA: Derive client DICE policy
+AuthMgrFE TA-->AuthMgrBE: Create TrustyConnectionToAuthorize
+AuthMgrFE TA->AuthMgrBE: AuthMgrFe::authorize_connection(...)
+AuthMgrBE->AuthMgrFE TA: Ok(...)
+AuthMgrFE TA->Client TA: return fd from TrustyConnectionToAuthorize
+Note over Client TA: service_manager::wait_for_interface sets\nup Binder with setupPreconnectedClient\nand returns
+Note over Client TA: Client uses Binder, now served\n by BinderRpc to MyTrustedHal
+```
+
+
+## Insecure Configuration Options
+The following build-time configs can be useful for testing.
+
+### AUTHMGRFE_FAKE_DICE_CHAIN
+Setting this to `true` instructs the AuthMgr-FE TA to use a hard-coded fake DICE handover
+directly from user space. It will not attempt to use the DICE handover provided to the trusty
+kernel. This fake DICE handover will also be used to initialize `PvmDice`. This config is only
+allowed if `TEST_BUILD` is also set to `true`.
+
+
+
diff --git a/authmgr-fe/accessor.rs b/authmgr-fe/accessor.rs
deleted file mode 100644
index f171596..0000000
--- a/authmgr-fe/accessor.rs
+++ /dev/null
@@ -1,87 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-use binder::{BinderFeatures, Interface, ParcelFileDescriptor, Status, StatusCode};
-use std::ffi::CStr;
-use std::os::fd::{FromRawFd, OwnedFd};
-use tipc::Uuid;
-use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
-    BnTrustyAccessor, ITrustyAccessor, ERROR_FAILED_TO_CREATE_SOCKET,
-};
-
-pub enum SecurityConfig {
-    // The accessor will resolve connections using the AuthMgr protocol.
-    Secure,
-    // The accessor will not perform any authentication or authorization,
-    // but simply establish a connection to the target port.
-    Insecure { target_port: &'static CStr },
-}
-
-pub struct AuthMgrAccessor {
-    service_name: &'static str,
-    security_config: SecurityConfig,
-    _uuid: Uuid,
-}
-
-impl AuthMgrAccessor {
-    pub fn new_binder(
-        service_name: &'static str,
-        security_config: SecurityConfig,
-        _uuid: Uuid,
-    ) -> binder::Strong<dyn ITrustyAccessor> {
-        let accessor = AuthMgrAccessor { service_name, security_config, _uuid };
-        BnTrustyAccessor::new_binder(accessor, BinderFeatures::default())
-    }
-}
-
-impl ITrustyAccessor for AuthMgrAccessor {
-    fn addConnection(&self) -> Result<ParcelFileDescriptor, Status> {
-        match self.security_config {
-            SecurityConfig::Secure => unimplemented!(),
-            SecurityConfig::Insecure { target_port } => add_insecure_connection(target_port),
-        }
-    }
-
-    fn getInstanceName(&self) -> Result<String, Status> {
-        let mut out_name = String::new();
-        out_name.try_reserve_exact(self.service_name.len()).map_err(|_| StatusCode::NO_MEMORY)?;
-        out_name.push_str(self.service_name);
-
-        Ok(out_name)
-    }
-}
-
-impl Interface for AuthMgrAccessor {}
-
-fn add_insecure_connection(port: &CStr) -> Result<ParcelFileDescriptor, Status> {
-    let handle = tipc::Handle::connect(port).map_err(|_| {
-        binder::Status::new_service_specific_error(
-            ERROR_FAILED_TO_CREATE_SOCKET,
-            Some(c"AuthMgrAccessor failed to connect to port"),
-        )
-    })?;
-
-    // TODO: b/395847127 - clean this up once we have Handle::into_raw_fd
-    let fd = handle.as_raw_fd();
-    // Do not close this fd. We're passing ownership of it
-    // to ParcelFileDescriptor.
-    core::mem::forget(handle);
-    // SAFETY: The fd is open since it was obtained from a successful call to
-    // tipc::Handle::connect. The fd is suitable for transferring ownership because we've leaked
-    // the original handle to ensure it isn't dropped.
-    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
-    Ok(ParcelFileDescriptor::new(owned_fd))
-}
diff --git a/authmgr-fe/app/main.rs b/authmgr-fe/app/main.rs
index 8f7f0ca..c8e4949 100644
--- a/authmgr-fe/app/main.rs
+++ b/authmgr-fe/app/main.rs
@@ -14,11 +14,20 @@
  * limitations under the License.
  */
 
-use log::info;
+fn log_formatter(record: &log::Record) -> String {
+    let line = record.line().unwrap_or(0);
+    let file = record.file().unwrap_or("unknown file");
+    format!("{}: authmgr-fe: {}:{} {}\n", record.level(), file, line, record.args())
+}
 
 fn main() {
-    trusty_log::init();
-    info!("Hello from AuthMgr-FE!");
+    let config = trusty_log::TrustyLoggerConfig::default()
+        .with_min_level(log::Level::Info)
+        .format(&log_formatter);
+
+    trusty_log::init_with_config(config);
+
+    log::info!("Hello from authmgr-fe!");
 
-    authmgr_fe::init_and_start_loop().expect("AuthMgr-FE should not exit");
+    let _ = authmgr_fe::init_and_start_loop().expect("Loop should not exit");
 }
diff --git a/authmgr-fe/app/manifest.json b/authmgr-fe/app/manifest.json
index 569b9ba..106476a 100644
--- a/authmgr-fe/app/manifest.json
+++ b/authmgr-fe/app/manifest.json
@@ -1,6 +1,6 @@
 {
     "app_name": "authmgr_fe_app",
     "uuid": "9b3c1e9e-1808-4b98-8fa9-8592dff3a337",
-    "min_heap": 16384,
-    "min_stack": 8192
+    "min_heap": 32768,
+    "min_stack": 32768
 }
diff --git a/authmgr-fe/lib.rs b/authmgr-fe/lib.rs
deleted file mode 100644
index b4487fd..0000000
--- a/authmgr-fe/lib.rs
+++ /dev/null
@@ -1,109 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-mod accessor;
-
-use alloc::rc::Rc;
-use rpcbinder::RpcServer;
-use std::ffi::CStr;
-use tipc::{service_dispatcher, Manager, PortCfg};
-
-pub use accessor::{AuthMgrAccessor, SecurityConfig};
-
-const SECURE_STORAGE_SERVICE_NAME: &str =
-    "android.hardware.security.see.storage.ISecureStorage/default";
-const SECURE_STORAGE_TARGET_PORT: &CStr = c"com.android.hardware.security.see.storage";
-const HWKEY_SERVICE_NAME: &str = "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";
-const HWKEY_TARGET_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
-
-const PORT_COUNT: usize = 2;
-const CONNECTION_COUNT: usize = 6;
-
-type AuthMgrAccessorService = rpcbinder::RpcServer;
-
-service_dispatcher! {
-    pub enum AuthMgrFeDispatcher {
-        AuthMgrAccessorService,
-    }
-}
-
-fn add_server_to_authmgr_dispatcher(
-    dispatcher: &mut AuthMgrFeDispatcher<PORT_COUNT>,
-    service_name: &'static str,
-    target_port: &'static CStr,
-) {
-    let accessor_server = RpcServer::new_per_session(move |uuid| {
-        Some(
-            AuthMgrAccessor::new_binder(service_name, get_security_config(target_port), uuid)
-                .as_binder(),
-        )
-    });
-    let serving_port = service_manager::service_name_to_trusty_port(service_name)
-        .expect("Port name to be derivable from service name");
-    let service_cfg =
-        PortCfg::new(serving_port).expect("Service port should be valid").allow_ta_connect();
-
-    dispatcher
-        .add_service(Rc::new(accessor_server), service_cfg)
-        .expect("RPC service should add to dispatcher");
-}
-
-#[cfg(feature = "authmgrfe_mode_insecure")]
-fn get_security_config(target_port: &'static CStr) -> SecurityConfig {
-    log::warn!("Using authmgr-fe SecurityConfig::Insecure - no authentication or authorization for trusted services.");
-    SecurityConfig::Insecure { target_port }
-}
-
-#[cfg(not(feature = "authmgrfe_mode_insecure"))]
-fn get_security_config(_target_port: &'static CStr) -> SecurityConfig {
-    log::info!("Using authmgr-fe SecurityConfig::Secure.");
-    SecurityConfig::Secure
-}
-
-pub fn init_and_start_loop() -> tipc::Result<()> {
-    let mut dispatcher =
-        AuthMgrFeDispatcher::<PORT_COUNT>::new().expect("Dispatcher creation should not fail");
-
-    add_server_to_authmgr_dispatcher(
-        &mut dispatcher,
-        SECURE_STORAGE_SERVICE_NAME,
-        SECURE_STORAGE_TARGET_PORT,
-    );
-    add_server_to_authmgr_dispatcher(&mut dispatcher, HWKEY_SERVICE_NAME, HWKEY_TARGET_PORT);
-
-    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
-        .expect("Service manager should be created")
-        .run_event_loop()
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use binder::IBinder;
-    use test::*;
-    use service_manager::*;
-    use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::ISecureStorage::ISecureStorage;
-
-    test::init!();
-
-    #[test]
-    fn test_get_secure_storage_binder() {
-        let ss: Result<binder::Strong<dyn ISecureStorage>, binder::StatusCode> =
-            wait_for_interface(SECURE_STORAGE_SERVICE_NAME);
-
-        assert_ok!(ss.expect("secure storage interface to be resolved").as_binder().ping_binder());
-    }
-}
diff --git a/authmgr-fe/rules.mk b/authmgr-fe/rules.mk
index a7a7728..b017aa3 100644
--- a/authmgr-fe/rules.mk
+++ b/authmgr-fe/rules.mk
@@ -19,20 +19,33 @@ MODULE := $(LOCAL_DIR)
 
 
 MODULE_SRCS += \
-	$(LOCAL_DIR)/lib.rs \
+	$(LOCAL_DIR)/src/lib.rs \
 
 MODULE_CRATE_NAME := authmgr_fe
 
 MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,ciborium) \
+	$(call FIND_CRATE,coset) \
 	$(call FIND_CRATE,log) \
 	frameworks/native/libs/binder/trusty/rust \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	packages/modules/Virtualization/libs/dice/open_dice \
+	trusty/user/app/sample/hwcryptohal/aidl/rust  \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/aidl \
+	trusty/user/base/interface/authmgr/rust \
 	trusty/user/base/interface/binder_accessor \
-	trusty/user/base/interface/secure_storage/rust \
+	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/authgraph-rust/tests \
+	trusty/user/base/lib/authmgr-common-rust \
+	trusty/user/base/lib/authmgr-common-util-rust \
+	trusty/user/base/lib/authmgr-fe-core-rust \
+	trusty/user/base/lib/hwbcc/rust \
+	trusty/user/base/lib/pvmdice \
 	trusty/user/base/lib/service_manager/client \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
+	trusty/user/base/lib/vmm_obj/rust \
 
 
 ifeq (true,$(call TOBOOL,$(AUTHMGRFE_MODE_INSECURE)))
@@ -42,6 +55,14 @@ MODULE_RUSTFLAGS += \
 
 endif
 
+AUTHMGRFE_FAKE_DICE_CHAIN ?= 0
+
+ifeq (true,$(call TOBOOL,$(AUTHMGRFE_FAKE_DICE_CHAIN)))
+
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="authmgrfe_fake_dice_chain"' \
+
+endif
 
 MODULE_RUST_TESTS := true
 
diff --git a/authmgr-fe/src/accessor.rs b/authmgr-fe/src/accessor.rs
new file mode 100644
index 0000000..ce79e1c
--- /dev/null
+++ b/authmgr-fe/src/accessor.rs
@@ -0,0 +1,182 @@
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
+use crate::authorization::TrustyConnectionToAuthorize;
+use alloc::sync::Arc;
+use authgraph_core::key::DiceChainEntry;
+use authmgr_common_util::get_constraint_spec_for_static_trusty_ta;
+use authmgr_common_util::policy_for_dice_node;
+use authmgr_fe_core::authorization::AuthMgrFe;
+use binder::{BinderFeatures, Interface, ParcelFileDescriptor, Status, StatusCode};
+use coset::CborSerializable;
+use pvmdice::PvmDice;
+use std::ffi::CStr;
+use std::os::fd::IntoRawFd;
+use std::os::fd::{FromRawFd, OwnedFd};
+use std::sync::Mutex;
+use tipc::Uuid;
+use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
+    BnTrustyAccessor, ITrustyAccessor, ERROR_FAILED_TO_CONNECT_EACCES,
+    ERROR_FAILED_TO_CREATE_SOCKET,
+};
+
+/// A helper macro for the common task in this file of mapping a result
+/// to a binder::Status with a service-specific error of EACCESS.
+///
+/// E.g.
+/// ```
+/// let thing = ok_or_eaccess!(other.might_fail(), "Failed to do thing")?;
+/// ```
+macro_rules! ok_or_eaccess {
+    ($e:expr, $msg:literal) => {
+        $e.map_err(|e| {
+            log::error!("AuthMgrAccessor: {} {:?}", $msg, e);
+            binder::Status::new_service_specific_error_str(
+                ERROR_FAILED_TO_CONNECT_EACCES,
+                Some($msg),
+            )
+        })
+    };
+}
+
+#[derive(Clone)]
+pub enum SecurityConfig {
+    // The accessor will resolve connections using the AuthMgr protocol.
+    Secure { authmgr: Arc<Mutex<AuthMgrFe>>, pvmdice: Arc<Mutex<PvmDice>> },
+    // The accessor will not perform any authentication or authorization,
+    // but simply establish a connection to the target port.
+    Insecure { target_port: &'static CStr },
+}
+
+pub struct AuthMgrAccessor {
+    service_name: &'static str,
+    security_config: SecurityConfig,
+    uuid: Uuid,
+}
+
+impl AuthMgrAccessor {
+    pub fn new_binder(
+        service_name: &'static str,
+        security_config: SecurityConfig,
+        uuid: Uuid,
+    ) -> binder::Strong<dyn ITrustyAccessor> {
+        let accessor = AuthMgrAccessor { service_name, security_config, uuid };
+        BnTrustyAccessor::new_binder(accessor, BinderFeatures::default())
+    }
+
+    fn add_secure_connection(
+        &self,
+        authmgr: Arc<Mutex<AuthMgrFe>>,
+        pvmdice: Arc<Mutex<PvmDice>>,
+    ) -> Result<ParcelFileDescriptor, Status> {
+        let connection_to_authorize = TrustyConnectionToAuthorize::new().map_err(|_| {
+            binder::Status::new_service_specific_error_str(
+                ERROR_FAILED_TO_CREATE_SOCKET,
+                Some("AuthMgrAccessor failed to set up TrustyConnectionToAuthorize"),
+            )
+        })?;
+
+        let dice_cbor = ok_or_eaccess!(
+            pvmdice.lock().unwrap().derive_dice_cert_for_ta(self.uuid.clone()),
+            "Failed to dervice TA DICE cert"
+        )?;
+        let dice_leaf = ok_or_eaccess!(
+            DiceChainEntry::from_slice(&dice_cbor),
+            "Failed to deserialize TA DICE cert"
+        )?;
+        let constraint_spec = get_constraint_spec_for_static_trusty_ta();
+        let leaf_policy = ok_or_eaccess!(
+            policy_for_dice_node(&dice_leaf, constraint_spec),
+            "Failed to build DICE policy"
+        )?;
+        let leaf_policy_cbor =
+            ok_or_eaccess!(leaf_policy.to_vec(), "Failed to serialize DICE policy")?;
+
+        let client_id = self.uuid.to_string();
+        let client_id_bytes = client_id.as_bytes();
+
+        log::info!(
+            "Attempting to authorize connection for {} from caller {:02x?}",
+            self.service_name,
+            client_id_bytes,
+        );
+
+        ok_or_eaccess!(
+            authmgr.lock().unwrap().authorize_connection(
+                &connection_to_authorize,
+                client_id_bytes,
+                self.service_name,
+                dice_leaf,
+                leaf_policy_cbor,
+            ),
+            "Authorization failed"
+        )?;
+
+        log::info!("Successfully authorized connection to {} for {client_id:?}", self.service_name);
+
+        Ok(ParcelFileDescriptor::new(connection_to_authorize))
+    }
+}
+
+impl ITrustyAccessor for AuthMgrAccessor {
+    fn addConnection(&self) -> Result<ParcelFileDescriptor, Status> {
+        match &self.security_config {
+            SecurityConfig::Secure { authmgr, pvmdice } => {
+                log::debug!(
+                    "Attempting to add secure connection for {} from caller {:?}",
+                    self.service_name,
+                    &self.uuid
+                );
+                self.add_secure_connection(Arc::clone(authmgr), Arc::clone(pvmdice))
+            }
+            SecurityConfig::Insecure { target_port } => {
+                log::debug!(
+                    "Attempting to add insecure connection for {} from caller {:?}",
+                    self.service_name,
+                    &self.uuid
+                );
+                add_insecure_connection(target_port)
+            }
+        }
+    }
+
+    fn getInstanceName(&self) -> Result<String, Status> {
+        let mut out_name = String::new();
+        out_name.try_reserve_exact(self.service_name.len()).map_err(|_| StatusCode::NO_MEMORY)?;
+        out_name.push_str(self.service_name);
+
+        Ok(out_name)
+    }
+}
+
+impl Interface for AuthMgrAccessor {}
+
+fn add_insecure_connection(port: &CStr) -> Result<ParcelFileDescriptor, Status> {
+    let handle = tipc::Handle::connect(port).map_err(|_| {
+        binder::Status::new_service_specific_error(
+            ERROR_FAILED_TO_CREATE_SOCKET,
+            Some(c"AuthMgrAccessor failed to connect to port"),
+        )
+    })?;
+
+    let fd = handle.into_raw_fd();
+
+    // SAFETY: The fd is open since it was obtained from a successful call to
+    // tipc::Handle::connect. The fd is suitable for transferring ownership because
+    // it's been obtained by an implementation of IntoRawFd on Handle.
+    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
+    Ok(ParcelFileDescriptor::new(owned_fd))
+}
diff --git a/authmgr-fe/src/authorization.rs b/authmgr-fe/src/authorization.rs
new file mode 100644
index 0000000..9672c44
--- /dev/null
+++ b/authmgr-fe/src/authorization.rs
@@ -0,0 +1,143 @@
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
+//! Implementations of authmgr_fe_core::traits and a few helper functions
+//! for use in the authmgr-fe TA.
+
+use authgraph_boringssl::{ec::BoringEcDsa, BoringRng};
+use authgraph_core::key::{CertChain, EcSignKey};
+use authmgr_fe_core::traits::{Device, ConnectionToAuthorize};
+use authmgr_fe_core::error::Error;
+use authmgr_fe_core::authorization::AuthMgrFe;
+use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::IAuthMgrAuthorization::IAuthMgrAuthorization;
+use service_manager::{wait_for_interface, service_name_to_trusty_c_port};
+use alloc::boxed::Box;
+use authmgr_common::signed_connection_request::TransportIdInfo;
+use authmgr_common::signed_connection_request::{TEMP_AUTHMGR_FE_TRANSPORT_ID, TEMP_AUTHMGR_BE_TRANSPORT_ID};
+use authmgr_common::CryptoTraitImpl;
+use authmgr_common_util::get_constraints_spec_for_trusty_vm;
+use tipc::Handle;
+use std::os::fd::{FromRawFd, OwnedFd, IntoRawFd};
+use pvmdice::PvmDice;
+use dice_policy_builder::policy_for_dice_chain;
+use diced_open_dice::DiceArtifacts;
+use coset::CborSerializable;
+use crate::error::AuthMgrFeTrustyError;
+
+pub const AUTHMGR_BE_SERVICE_NAME: &str =
+    "android.hardware.security.see.authmgr.IAuthMgrAuthorization/default";
+
+pub struct AuthMgrFeDevice;
+
+impl Device for AuthMgrFeDevice {
+    fn get_transport_id_info(&self) -> Result<TransportIdInfo, authmgr_fe_core::error::Error> {
+        // TODO: b/392905377 - Retrieve real frontend and backend transport ids
+        Ok(TransportIdInfo::FFATransportId {
+            fe_id: TEMP_AUTHMGR_FE_TRANSPORT_ID,
+            be_id: TEMP_AUTHMGR_BE_TRANSPORT_ID,
+        })
+    }
+}
+
+pub struct TrustyConnectionToAuthorize {
+    handle: Handle,
+}
+
+impl TrustyConnectionToAuthorize {
+    pub fn new() -> Result<Self, authmgr_fe_core::error::Error> {
+        let port_name = service_name_to_trusty_c_port(AUTHMGR_BE_SERVICE_NAME)
+            .map_err(|_| authmgr_fe_core::error::Error::AuthMgrBeConnectionFailed)?;
+
+        Ok(TrustyConnectionToAuthorize {
+            handle: Handle::connect(port_name.as_c_str())
+                .map_err(|_| authmgr_fe_core::error::Error::AuthMgrBeConnectionFailed)?,
+        })
+    }
+}
+
+impl From<TrustyConnectionToAuthorize> for OwnedFd {
+    fn from(conn: TrustyConnectionToAuthorize) -> OwnedFd {
+        let fd = conn.handle.into_raw_fd();
+
+        // SAFETY: The fd is open since self can only be constructed with a successful call
+        // to Handle::connect() in Self::new(). The underlying fd cannot be subsequently
+        // accessed to be closed by any public methods of Self.
+        //
+        // The fd is suitable for transferring ownership because it was obtained using
+        // Handle::into_raw_fd() which transfers ownership.
+        unsafe { OwnedFd::from_raw_fd(fd) }
+    }
+}
+
+impl ConnectionToAuthorize for TrustyConnectionToAuthorize {
+    fn send(&self, buff: &[u8]) -> Result<(), authmgr_fe_core::error::Error> {
+        self.handle
+            .send(&buff)
+            .map_err(|_| authmgr_fe_core::error::Error::AuthMgrBeConnectionFailed)
+    }
+}
+
+/// Initialize and return a new AuthmgrFe instance that can be used to authenticate
+/// this pVM and authorize client services.
+pub fn get_authmgr_fe() -> Result<AuthMgrFe, Error> {
+    let device = Box::new(AuthMgrFeDevice);
+
+    let authmgr_be: binder::Strong<dyn IAuthMgrAuthorization> =
+        wait_for_interface(AUTHMGR_BE_SERVICE_NAME)?;
+
+    let crypto = CryptoTraitImpl { ecdsa: Box::new(BoringEcDsa), rng: Box::new(BoringRng) };
+
+    Ok(AuthMgrFe::new(device, crypto, authmgr_be))
+}
+
+/// Authenticate this pVM (phase 1 of the AuthMgr protocol)
+///
+/// This function will succeed if authenticated or panic otherwise.
+/// Panicking is acceptable because we're initializing state for the core object in the AuthMgr-FE
+/// TA. The TA will exit on failure anyways.
+pub fn authenticate_pvm(
+    authmgr: &mut AuthMgrFe,
+    pvmdice: &PvmDice,
+) -> Result<(), AuthMgrFeTrustyError> {
+    let dice_chain_cbor = pvmdice.bcc().ok_or(AuthMgrFeTrustyError::UnknownError(
+        "PvmDice does not have a cert chain. Initialization should have failed.",
+    ))?;
+    let explicit_dice_chain = CertChain::from_non_explicit_key_cert_chain(dice_chain_cbor)?;
+    let guest_os_name = explicit_dice_chain
+        .get_leaf_cert_component_name()?
+        .ok_or(AuthMgrFeTrustyError::UnknownError("No component_name on leaf cert"))?;
+    let explicit_dice_chain_ser = explicit_dice_chain.to_vec()?;
+
+    let policy = policy_for_dice_chain(
+        &explicit_dice_chain_ser,
+        get_constraints_spec_for_trusty_vm(&guest_os_name),
+    )
+    .map_err(|e| {
+        log::error!("Failed to get policy for pvm dice chain {e}");
+        AuthMgrFeTrustyError::UnknownError("failed to get policy for pvm dice chain")
+    })?;
+
+    // An authgraph EcSignKey::Ed25519 is actually constructed from just the private key seed, which
+    // ends up being the first 32 bytes of the eventual private key.
+    let signing_key_seed = diced_open_dice::derive_cdi_private_key_seed(pvmdice.cdi_attest())?;
+    let signing_key = EcSignKey::Ed25519(signing_key_seed.as_array().clone());
+
+    Ok(authmgr.authenticate_pvm(
+        explicit_dice_chain_ser,
+        signing_key,
+        policy.to_vec().expect("should be able to serialize DicePolicy"),
+    )?)
+}
diff --git a/authmgr-fe/src/dice_handover.rs b/authmgr-fe/src/dice_handover.rs
new file mode 100644
index 0000000..e0b751a
--- /dev/null
+++ b/authmgr-fe/src/dice_handover.rs
@@ -0,0 +1,21 @@
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
+use vmm_obj::get_vmm_obj;
+
+pub(crate) fn get_dice_handover() -> Vec<u8> {
+    get_vmm_obj(c"google,open-dice").expect("Should be able get kernel-mapped DICE handover")
+}
diff --git a/authmgr-fe/src/error.rs b/authmgr-fe/src/error.rs
new file mode 100644
index 0000000..f126057
--- /dev/null
+++ b/authmgr-fe/src/error.rs
@@ -0,0 +1,50 @@
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
+//! Error definitions for AuthMgr FE Trusty TA
+
+#[derive(Debug)]
+pub enum AuthMgrFeTrustyError {
+    AuthGraphError(authgraph_core::error::Error),
+    AuthMgrFeCoreError(authmgr_fe_core::error::Error),
+    BinderStatus(binder::StatusCode),
+    CoseError(coset::CoseError),
+    DiceError(diced_open_dice::DiceError),
+    PvmDiceError(pvmdice::PvmDiceError),
+    TipcError(tipc::TipcError),
+    UnknownError(&'static str),
+}
+
+// It would be nice to use something like thiserror or anyhow,
+// but to do so we'd need to go back and implement core::error::Error
+// on a bunch of our error types.
+macro_rules! impl_from {
+    ($from_err:ty, $variant:ident) => {
+        impl From<$from_err> for AuthMgrFeTrustyError {
+            fn from(e: $from_err) -> Self {
+                Self::$variant(e)
+            }
+        }
+    };
+}
+
+impl_from!(authgraph_core::error::Error, AuthGraphError);
+impl_from!(authmgr_fe_core::error::Error, AuthMgrFeCoreError);
+impl_from!(binder::StatusCode, BinderStatus);
+impl_from!(coset::CoseError, CoseError);
+impl_from!(diced_open_dice::DiceError, DiceError);
+impl_from!(tipc::TipcError, TipcError);
+impl_from!(pvmdice::PvmDiceError, PvmDiceError);
diff --git a/authmgr-fe/src/fake_dice_handover.rs b/authmgr-fe/src/fake_dice_handover.rs
new file mode 100644
index 0000000..d4ce3e1
--- /dev/null
+++ b/authmgr-fe/src/fake_dice_handover.rs
@@ -0,0 +1,83 @@
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
+use authgraph_core_test::create_dice_cert_chain_for_guest_os;
+use ciborium::Value;
+use coset::{AsCborValue, CborSerializable, CoseKey};
+
+// It would be nice to directly define these constants as
+// Value e.g.
+//
+// const HANDOVER_CDI_ATTEST_KEY: Value = Value::Integer(1.into());
+//
+// but this depends on the nightly feature `const_trait_impl` since
+// ciborium::value::Integer can't be constructed directly but only
+// from its From/TryFrom implementations.
+const HANDOVER_CDI_ATTEST_KEY: i32 = 1;
+const HANDOVER_CDI_SEAL_KEY: i32 = 2;
+const HANDOVER_DICE_CHAIN_KEY: i32 = 3;
+
+/// Get a fake dice handover. This will only succeed if TEST_BUILD is
+/// set. This method panics on failure - the rationale being that this
+/// handover is critical for the operation of an authmgr-fe. Without it,
+/// the app can't run.
+pub(crate) fn get_dice_handover() -> Vec<u8> {
+    if !cfg!(TEST_BUILD) {
+        panic!("Cannot provide a fake dice chain because this is not a TEST_BUILD");
+    }
+
+    log::warn!("Using a hardcoded fake dice chain handover.");
+
+    let fake_instance_hash = Some([9; 64]);
+    let fake_security_version = 1;
+    let (_signing_key, cdi_values, explicit_chain) =
+        create_dice_cert_chain_for_guest_os(fake_instance_hash, fake_security_version);
+
+    // The dice chain in the handover format is slightly different than the ExplicitKeyDiceChain
+    // that the helper implements above so we deserialize completely to mutate it.
+    let explicit_chain: Value = ciborium::from_reader(explicit_chain.as_slice()).unwrap();
+    let mut explicit_chain = explicit_chain.into_array().unwrap();
+    // The first and second entries in the explicit format are the version and key,
+    // respectively. Everything at index 2 and beyond is a cert.
+    let certs = explicit_chain.split_off(2);
+    // ExplicitKeyDiceChain includes the CoseKey as serialized bytes, but
+    // the handover format includes the CoseKey directly, which is a map.
+    let cose_key = match explicit_chain.remove(1) {
+        Value::Bytes(encoded_key) => CoseKey::from_slice(&encoded_key)
+            .expect("cose key to be deserialized")
+            .to_cbor_value()
+            .expect("cose key to be serialized"),
+        _ => panic!("expected cose key to be serialized bytes"),
+    };
+
+    let mut non_explicit_chain = vec![cose_key];
+    non_explicit_chain.extend(certs);
+
+    let dice_handover = Value::Map(vec![
+        (
+            Value::Integer(HANDOVER_CDI_ATTEST_KEY.into()),
+            Value::Bytes(cdi_values.cdi_attest.to_vec()),
+        ),
+        (Value::Integer(HANDOVER_CDI_SEAL_KEY.into()), Value::Bytes(cdi_values.cdi_seal.to_vec())),
+        (Value::Integer(HANDOVER_DICE_CHAIN_KEY.into()), Value::Array(non_explicit_chain)),
+    ]);
+
+    let mut dice_handover_cbor = Vec::new();
+    let _ = ciborium::into_writer(&dice_handover, &mut dice_handover_cbor)
+        .expect("serialize dice handover");
+
+    dice_handover_cbor
+}
diff --git a/authmgr-fe/src/lib.rs b/authmgr-fe/src/lib.rs
new file mode 100644
index 0000000..5386234
--- /dev/null
+++ b/authmgr-fe/src/lib.rs
@@ -0,0 +1,211 @@
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
+mod accessor;
+mod authorization;
+mod error;
+
+#[cfg(not(feature = "authmgrfe_fake_dice_chain"))]
+mod dice_handover;
+
+#[cfg(feature = "authmgrfe_fake_dice_chain")]
+mod fake_dice_handover;
+#[cfg(feature = "authmgrfe_fake_dice_chain")]
+use fake_dice_handover as dice_handover;
+
+use crate::authorization::{authenticate_pvm, get_authmgr_fe};
+use crate::error::AuthMgrFeTrustyError;
+use alloc::rc::Rc;
+use dice_handover::get_dice_handover;
+use hwbcc::srv::HwBccService;
+use pvmdice::{PvmDice, PvmDiceThreadSafe};
+use rpcbinder::RpcServer;
+use std::ffi::CStr;
+use std::sync::{Arc, Mutex};
+use tipc::{service_dispatcher, Manager, PortCfg};
+use tipc::{ClientIdentifier, Uuid};
+
+pub use accessor::{AuthMgrAccessor, SecurityConfig};
+
+const SECURE_STORAGE_SERVICE_NAME: &str =
+    "android.hardware.security.see.storage.ISecureStorage/default";
+const SECURE_STORAGE_TARGET_PORT: &CStr = c"com.android.hardware.security.see.storage";
+const HWKEY_SERVICE_NAME: &str = "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";
+const HWKEY_TARGET_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
+const HELLO_WORLD_SERVICE: &str = "android.hardware.security.IHelloWorld/default";
+
+const HWBCC_PORT: &str = "com.android.trusty.hwbcc";
+
+// The IHelloWorld service only exists in secure mode as its purpose is to test
+// the e2e AuthMgr protocol.
+#[cfg(not(feature = "authmgrfe_mode_insecure"))]
+const PORT_COUNT: usize = 4;
+#[cfg(feature = "authmgrfe_mode_insecure")]
+const PORT_COUNT: usize = 3;
+
+const CONNECTION_COUNT: usize = 6;
+
+const KEYMINT_UUID: Uuid =
+    Uuid::new(0x5f902ace, 0x5e5c, 0x4cd8, [0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf]);
+const WV_UUID: Uuid =
+    Uuid::new(0x19c7289c, 0x5004, 0x4a30, [0xb8, 0x5a, 0x2a, 0x22, 0xa7, 0x6e, 0x63, 0x27]);
+const HWBCC_TEST_UUID: Uuid =
+    Uuid::new(0x0e109d31, 0x8bbe, 0x47d6, [0xbb, 0x47, 0xe1, 0xdd, 0x08, 0x91, 0x0e, 0x16]);
+const HWBCC_RUST_TEST_UUID: Uuid =
+    Uuid::new(0x67925337, 0x2c03, 0x49ed, [0x92, 0x40, 0xd5, 0x1b, 0x6f, 0xea, 0x3e, 0x30]);
+
+const PVMDICE_TEST_BUILD_ALLOWED_UUIDS: [Uuid; 4] =
+    [KEYMINT_UUID, WV_UUID, HWBCC_TEST_UUID, HWBCC_RUST_TEST_UUID];
+
+const PVMDICE_ALLOWED_UUIDS: [Uuid; 2] = [KEYMINT_UUID, WV_UUID];
+
+fn get_pvmdice_allowed_uuids() -> &'static [Uuid] {
+    if cfg!(TEST_BUILD) {
+        &PVMDICE_TEST_BUILD_ALLOWED_UUIDS
+    } else {
+        &PVMDICE_ALLOWED_UUIDS
+    }
+}
+
+type AuthMgrAccessorService = rpcbinder::RpcServer;
+
+service_dispatcher! {
+    pub enum AuthMgrFeDispatcher {
+        AuthMgrAccessorService,
+        HwBccService,
+    }
+}
+
+fn add_accessor_to_authmgr_dispatcher(
+    dispatcher: &mut AuthMgrFeDispatcher<PORT_COUNT>,
+    service_name: &'static str,
+    security_config: SecurityConfig,
+) -> Result<(), AuthMgrFeTrustyError> {
+    let accessor_server = RpcServer::new_per_session(move |client_id| {
+        let uuid = match client_id {
+            ClientIdentifier::UUID(uuid) => uuid,
+            _ => {
+                log::error!("Expected a Uuid as client id, got: {:?}", client_id);
+                return None;
+            }
+        };
+        Some(AuthMgrAccessor::new_binder(service_name, security_config.clone(), uuid).as_binder())
+    });
+    let serving_port = service_manager::service_name_to_trusty_port(service_name)?;
+
+    log::info!("Adding {} to authmgr-fe dispatcher on port {}", service_name, &serving_port);
+
+    let service_cfg = PortCfg::new(serving_port)?.allow_ta_connect();
+
+    dispatcher.add_service(Rc::new(accessor_server), service_cfg)?;
+
+    Ok(())
+}
+
+pub fn init_and_start_loop() -> Result<(), AuthMgrFeTrustyError> {
+    let mut dispatcher = AuthMgrFeDispatcher::<PORT_COUNT>::new()?;
+
+    let handover = get_dice_handover();
+    log::info!(
+        "Initializing hwbcc server with PvmDice using handover of size: {} bytes.",
+        handover.len()
+    );
+
+    let pvmdice = Arc::new(Mutex::new(PvmDice::try_new(&handover)?));
+    let pvmdice_service = HwBccService::new(Rc::new(PvmDiceThreadSafe::new(Arc::clone(&pvmdice))));
+
+    let pvmdice_port_cfg =
+        PortCfg::new(HWBCC_PORT)?.allow_ta_connect().allowed_uuids(get_pvmdice_allowed_uuids());
+
+    dispatcher.add_service(Rc::new(pvmdice_service), pvmdice_port_cfg)?;
+
+    if cfg!(feature = "authmgrfe_mode_insecure") {
+        let _ = add_accessor_to_authmgr_dispatcher(
+            &mut dispatcher,
+            SECURE_STORAGE_SERVICE_NAME,
+            SecurityConfig::Insecure { target_port: SECURE_STORAGE_TARGET_PORT },
+        )?;
+
+        let _ = add_accessor_to_authmgr_dispatcher(
+            &mut dispatcher,
+            HWKEY_SERVICE_NAME,
+            SecurityConfig::Insecure { target_port: HWKEY_TARGET_PORT },
+        )?;
+    } else {
+        let authmgr = Arc::new(Mutex::new(get_authmgr_fe()?));
+        authenticate_pvm(&mut authmgr.lock().unwrap(), &pvmdice.lock().unwrap())?;
+        log::info!("Successfully authenticated pVM");
+
+        let _ = add_accessor_to_authmgr_dispatcher(
+            &mut dispatcher,
+            SECURE_STORAGE_SERVICE_NAME,
+            SecurityConfig::Secure { authmgr: Arc::clone(&authmgr), pvmdice: Arc::clone(&pvmdice) },
+        )?;
+
+        let _ = add_accessor_to_authmgr_dispatcher(
+            &mut dispatcher,
+            HWKEY_SERVICE_NAME,
+            SecurityConfig::Secure { authmgr: Arc::clone(&authmgr), pvmdice: Arc::clone(&pvmdice) },
+        )?;
+
+        let _ = add_accessor_to_authmgr_dispatcher(
+            &mut dispatcher,
+            HELLO_WORLD_SERVICE,
+            SecurityConfig::Secure { authmgr: Arc::clone(&authmgr), pvmdice: Arc::clone(&pvmdice) },
+        )?;
+    }
+
+    log::info!("Starting authmgr-fe event loop");
+
+    // We provide a buffer because this Manager is handling buffered and unbuffered services.
+    // On construction, the Manager will check if the buffer is sufficient for the configured
+    // services.
+    Ok(Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [0u8; 4096])?
+        .run_event_loop()?)
+}
+
+// Since tests are compiled conditionally, it's expected that
+// some imports are unused for certain builds.
+#[allow(unused_imports)]
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use binder::IBinder;
+    use service_manager::*;
+    use test::*;
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
+    use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::IHelloWorld::IHelloWorld;
+
+    test::init!();
+
+    #[cfg(feature = "authmgrfe_mode_insecure")]
+    #[test]
+    fn test_get_hwcrypto_binder_insecure_mode() {
+        let hwcrypto: binder::Strong<dyn IHwCryptoKey> =
+            assert_ok!(wait_for_interface(HWKEY_SERVICE_NAME));
+
+        assert_ok!(hwcrypto.as_binder().ping_binder());
+    }
+
+    #[cfg(not(feature = "authmgrfe_mode_insecure"))]
+    #[test]
+    fn test_get_hello_world() {
+        let hello: binder::Strong<dyn IHelloWorld> =
+            assert_ok!(wait_for_interface(HELLO_WORLD_SERVICE));
+
+        assert_ok!(hello.as_binder().ping_binder());
+    }
+}
```

