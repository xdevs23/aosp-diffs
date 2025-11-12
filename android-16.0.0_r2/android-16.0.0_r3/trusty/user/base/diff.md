```diff
diff --git a/include/user/trusty_ipc.h b/include/user/trusty_ipc.h
index eaf59f7..cdb68d8 100644
--- a/include/user/trusty_ipc.h
+++ b/include/user/trusty_ipc.h
@@ -48,6 +48,17 @@ typedef int32_t handle_t;
  */
 #define INFINITE_TIME UINT32_MAX
 
+/*
+ * The Trusty driver uses a 4096-byte shared buffer to transfer messages.
+ * However, the virtio/TIPC bridge overestimates the portion of the buffer
+ * available to it. Specifically, it does not account for the TIPC headers
+ * and the FDs being transferred. We reserve some of the buffer here to
+ * account for this. The reserved size is chosen to allow room for the
+ * TIPC header (16 bytes), 8x FD (24 bytes), plus some margin.
+ */
+#define TIPC_HDR_AND_FDS_MAX_SIZE 256
+#define VIRTIO_VSOCK_MSG_SIZE_LIMIT (4096 - TIPC_HDR_AND_FDS_MAX_SIZE)
+
 /*
  * Combination of these flags sets additional options
  * for port_create syscall.
@@ -107,6 +118,10 @@ enum {
     HSET_MOD = 0x2, /* modifies handle attributes in handle set */
     HSET_DEL_GET_COOKIE =
             0x3, /* deletes a handle from handle set and returns its cookie */
+    HSET_DEL_WITH_COOKIE = 0x4, /* like `HSET_DEL`, but requires the passed in
+                                   cookie to match the stored one */
+    HSET_MOD_WITH_COOKIE = 0x5, /* like `HSET_MOD`, but requires the passed in
+                                   cookie to match the stored one */
 };
 
 /*
diff --git a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
index b762c98..a88991f 100644
--- a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
+++ b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
@@ -387,6 +387,15 @@ struct ffa_part_info_desc {
 };
 STATIC_ASSERT(sizeof(struct ffa_part_info_desc) == 24);
 
+/**
+ * typedef ffa_msg_wait_flag32_t - FFA_MSG_WAIT flags
+ *
+ * * @FFA_MSG_WAIT_FLAG_RETAIN_RX
+ *     Retain RX Buffer Ownership flag.
+ */
+typedef uint32_t ffa_msg_wait_flag32_t;
+#define FFA_MSG_WAIT_FLAG_RETAIN_RX (1U << 0)
+
 /**
  * enum ffa_error - FF-A error code
  * @FFA_ERROR_NOT_SUPPORTED:
diff --git a/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl b/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl
index 0523261..f6dff36 100644
--- a/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl
+++ b/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl
@@ -37,5 +37,5 @@ interface ITrustedServicesHandover {
      *                           the AuthMgr authorization protocol
      * @param clientSeqNumber - the unique sequence number assigned to the client
      */
-    void handoverConnection(in ParcelFileDescriptor connectionHandle, in int clientSeqNumber);
+    void handoverConnection(in ParcelFileDescriptor connectionHandle, in long clientSeqNumber);
 }
diff --git a/interface/authmgr-handover/cpp/rules.mk b/interface/authmgr-handover/cpp/rules.mk
new file mode 100644
index 0000000..26fd1b0
--- /dev/null
+++ b/interface/authmgr-handover/cpp/rules.mk
@@ -0,0 +1,28 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+AIDL_DIR := $(LOCAL_DIR)/../aidl
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_AIDL_LANGUAGE := cpp
+
+MODULE_AIDL_PACKAGE := android/trusty/handover
+
+MODULE_AIDLS := \
+    $(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ITrustedServicesHandover.aidl \
+
+include make/aidl.mk
diff --git a/interface/authmgr/rust/rules.mk b/interface/authmgr/rust/rules.mk
index 7d3b68d..1380ec7 100644
--- a/interface/authmgr/rust/rules.mk
+++ b/interface/authmgr/rust/rules.mk
@@ -14,7 +14,11 @@
 #
 LOCAL_DIR := $(GET_LOCAL_DIR)
 
-AUTHMGR_BE_AIDL_DIR = hardware/interfaces/security/see/authmgr/aidl
+ROOT_AUTHMGR_BE_AIDL_DIR = hardware/interfaces/security/see/authmgr/aidl
+AUTHMGR_BE_AIDL_API_DIR = $(ROOT_AUTHMGR_BE_AIDL_DIR)/aidl_api/android.hardware.security.see.authmgr
+
+MODULE_AIDL_VERSION := 1
+AUTHMGR_BE_AIDL_DIR = $(AUTHMGR_BE_AIDL_API_DIR)/$(MODULE_AIDL_VERSION)
 
 MODULE := $(LOCAL_DIR)
 
@@ -27,8 +31,12 @@ MODULE_AIDL_PACKAGE := android/hardware/security/see/authmgr
 MODULE_AIDL_INCLUDES := \
 	-I $(AUTHMGR_BE_AIDL_DIR) \
 
+MODULE_AIDL_HASH := $(shell cat $(AUTHMGR_BE_AIDL_DIR)/.hash)
+
 MODULE_AIDL_FLAGS := \
     --stability=vintf \
+    --version=$(MODULE_AIDL_VERSION) \
+    --hash=$(MODULE_AIDL_HASH) \
 
 MODULE_AIDLS := \
     $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DiceChainEntry.aidl \
diff --git a/interface/secure_storage/cpp/include/interface/storage/storage_aidl/ports.h b/interface/secure_storage/cpp/include/interface/storage/storage_aidl/ports.h
index 061be7e..87edea9 100644
--- a/interface/secure_storage/cpp/include/interface/storage/storage_aidl/ports.h
+++ b/interface/secure_storage/cpp/include/interface/storage/storage_aidl/ports.h
@@ -16,3 +16,5 @@
 #pragma once
 
 #define STORAGE_ISECURE_STORAGE_PORT "com.android.hardware.security.see.storage"
+#define STORAGE_ISECURE_STORAGE_HANDOVER_PORT \
+    "ahss.storage.ISecureStorage/default.hnd"
diff --git a/lib/apploader_package/include/apploader/cbor.h b/lib/apploader_package/include/apploader/cbor.h
index 76f21de..e590491 100644
--- a/lib/apploader_package/include/apploader/cbor.h
+++ b/lib/apploader_package/include/apploader/cbor.h
@@ -221,7 +221,8 @@ static inline uint8_t* encodeBstrHeader(uint64_t bstrSize,
                                         uint8_t* outBuf) {
     struct CborOut fakeOut;
     const size_t bstrHeaderSize = cbor::encodedSizeOf(bstrSize);
-    assert(0 < bstrHeaderSize <= outBufSize);
+    assert(0 < bstrHeaderSize);
+    assert(bstrHeaderSize <= outBufSize);
     size_t fakeBufferSize;
     if (__builtin_add_overflow(bstrHeaderSize, bstrSize, &fakeBufferSize)) {
         return nullptr;
diff --git a/lib/authmgr-fe-core-rust/rules.mk b/lib/authmgr-fe-core-rust/rules.mk
new file mode 100644
index 0000000..5f07095
--- /dev/null
+++ b/lib/authmgr-fe-core-rust/rules.mk
@@ -0,0 +1,32 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := system/see/authmgr/authmgr-fe/src/lib.rs
+
+MODULE_CRATE_NAME := authmgr_fe_core
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	packages/modules/Virtualization/libs/dice/open_dice \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authmgr-common-rust \
+	trusty/user/base/interface/authmgr/rust \
+	$(call FIND_CRATE,coset) \
+	$(call FIND_CRATE,log) \
+
+include make/library.mk
\ No newline at end of file
diff --git a/lib/bssl-sys-rust/rules.mk b/lib/bssl-sys-rust/rules.mk
index c581390..8ed62f6 100644
--- a/lib/bssl-sys-rust/rules.mk
+++ b/lib/bssl-sys-rust/rules.mk
@@ -37,8 +37,6 @@ MODULE_BINDGEN_FLAGS += \
 	--default-macro-constant-type="signed" \
 	--rustified-enum="point_conversion_form_t" \
 
-MODULE_RUSTFLAGS += --cfg 'unsupported_inline_wrappers'
-
 # These regexes use [[:punct:]] instead of / to handle Windows file paths.
 # Ideally we would write [/\\], but escaping rules are complex, and often
 # ill-defined, in some build systems, so align on [[:punct:]].
@@ -63,6 +61,8 @@ MODULE_BINDGEN_OUTPUT_ENV_VAR := BINDGEN_RS_FILE
 
 MODULE_BINDGEN_OUTPUT_FILE_NAME := bindgen
 
+MODULE_BINDGEN_WRAP_STATIC_FNS := true
+
 MODULE_INCLUDES += \
 	$(BSSL_SRC_DIR)/include \
 
diff --git a/lib/hwbcc/rust/rules.mk b/lib/hwbcc/rust/rules.mk
index a5178e2..3874ac5 100644
--- a/lib/hwbcc/rust/rules.mk
+++ b/lib/hwbcc/rust/rules.mk
@@ -60,10 +60,22 @@ MODULE_BINDGEN_FLAGS := \
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
 # Enable tests specific to the generic emulator build,
-# which depend on the device-specific BCC key
+# which depend on the device-specific BCC key.
+# Exclude trusty as a VM guest since on arm those builds run
+# as part of the generic-arm64 platform but do not use the
+# same hardcoded key.
 ifeq (generic-arm64, $(PLATFORM))
+ifeq (false,$(call TOBOOL,$(TRUSTY_VM_GUEST)))
 MODULE_RUSTFLAGS += --cfg 'feature="generic-arm-unittest"'
 endif
+endif
+
+# Some functionality of hwbcc does not exist in VMs
+# like TEST_MODE and ns_deprivilege.
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_GUEST)))
+MODULE_RUSTFLAGS += --cfg 'feature="trusty_vm_guest"'
+endif
+
 
 MODULE_RUST_TESTS := true
 
diff --git a/lib/hwbcc/rust/src/test.rs b/lib/hwbcc/rust/src/test.rs
index 80bdb25..7386598 100644
--- a/lib/hwbcc/rust/src/test.rs
+++ b/lib/hwbcc/rust/src/test.rs
@@ -15,10 +15,10 @@
  */
 
 use super::*;
-use ::test::{assert, assert_ne};
+use ::test::assert;
 
 #[cfg(feature = "generic-arm-unittest")]
-use ::test::assert_eq;
+use ::test::{assert_eq, assert_ne};
 
 #[cfg(feature = "generic-arm-unittest")]
 use system_state::{SystemState, SystemStateFlag};
@@ -94,6 +94,7 @@ fn test_get_dice_artifacts() {
     }
 }
 
+#[cfg(not(feature = "trusty_vm_guest"))]
 #[test]
 fn test_ns_deprivilege() {
     ns_deprivilege().expect("could not execute ns deprivilege");
@@ -103,6 +104,7 @@ fn test_ns_deprivilege() {
     assert!(get_dice_artifacts(0, dice_artifacts_buf).is_ok());
 }
 
+#[cfg(not(feature = "trusty_vm_guest"))]
 #[test]
 fn test_get_bcc_test_mode() {
     let mut bcc_buf = [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
@@ -191,6 +193,7 @@ fn test_get_bcc() {
     assert_eq!(dk_pub_key, km_pub_key);
 }
 
+#[cfg(not(feature = "trusty_vm_guest"))]
 #[test]
 fn test_sign_data_test_mode() {
     let mut cose_sign1_buf = [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
@@ -207,7 +210,6 @@ fn test_sign_data_test_mode() {
     assert!(cose_sign1.len() > 0);
 }
 
-#[cfg(feature = "generic-arm-unittest")]
 #[test]
 fn test_sign_data() {
     let mut cose_sign1_buf = [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
diff --git a/lib/pvmdice/src/lib.rs b/lib/pvmdice/src/lib.rs
index 5fdc78a..8adabaf 100644
--- a/lib/pvmdice/src/lib.rs
+++ b/lib/pvmdice/src/lib.rs
@@ -1,9 +1,26 @@
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
 use alloc::collections::TryReserveError;
 use alloc::ffi::CString;
 use diced_open_dice::{
     bcc_handover_parse, retry_bcc_format_config_descriptor, retry_bcc_main_flow,
-    retry_sign_cose_sign1_with_cdi_leaf_priv, Config, DiceArtifacts, DiceConfigValues, DiceMode,
-    Hash, Hidden, InputValues, OwnedDiceArtifacts, CDI_SIZE, HASH_SIZE, HIDDEN_SIZE,
+    retry_dice_main_flow, retry_sign_cose_sign1_with_cdi_leaf_priv, Config, DiceArtifacts,
+    DiceConfigValues, DiceMode, Hash, Hidden, InputValues, OwnedDiceArtifacts, CDI_SIZE, HASH_SIZE,
+    HIDDEN_SIZE,
 };
 use hwbcc::srv::{HwBccOps, RequestContext};
 use hwbcc::{HwBccError, HwBccMode};
@@ -15,6 +32,9 @@ mod sys {
     include!(env!("BINDGEN_INC_FILE"));
 }
 
+mod thread_safe;
+pub use thread_safe::PvmDiceThreadSafe;
+
 // Currently we do not support dynamically loading apps into trusty pVMs.
 // As such, all user space apps are packaged and signed together with
 // the trusty kernel. This allows us to use empty authority and code
@@ -30,10 +50,12 @@ const TRUSTY_NON_LOADABLE_CODE_HASH: Hash = [0; HASH_SIZE];
 
 const EMPTY_HIDDEN_INPUTS: Hidden = [0; HIDDEN_SIZE];
 
+// 5f902ace-5e5c-4cd8-ae54-87b88c22ddaf
 const KEYMINT_UUID: Uuid =
     Uuid::new(0x5f902ace, 0x5e5c, 0x4cd8, [0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf]);
+// 19c7289c-5004-4a30-b85a-2a22a76e6327
 const WIDEVINE_UUID: Uuid =
-    Uuid::new(0x08d3ed40, 0xbde2, 0x448c, [0xa9, 0x1d, 0x75, 0xf1, 0x98, 0x9c, 0x57, 0xef]);
+    Uuid::new(0x19c7289c, 0x5004, 0x4a30, [0xb8, 0x5a, 0x2a, 0x22, 0xa7, 0x6e, 0x63, 0x27]);
 
 struct ComponentSpecificConfigValues {
     component_name: CString,
@@ -52,6 +74,14 @@ pub enum PvmDiceError {
     /// Returned on construction of PvmDice if we can't ensure that
     /// the apploader user space service is not and cannot run.
     ApploaderInvariantViolated,
+    /// An error serializing to COSE
+    CoseSerialization(coset::CoseError),
+}
+
+impl From<coset::CoseError> for PvmDiceError {
+    fn from(e: coset::CoseError) -> Self {
+        PvmDiceError::CoseSerialization(e)
+    }
 }
 
 impl From<diced_open_dice::DiceError> for PvmDiceError {
@@ -68,6 +98,7 @@ impl From<TryReserveError> for PvmDiceError {
 
 /// An implementation of the hwbcc interface for trusty guests running in
 /// protected virtual machines (pVMs).
+#[derive(Clone)]
 pub struct PvmDice {
     bcc: Vec<u8>,
     cdi_attest: [u8; CDI_SIZE],
@@ -107,23 +138,43 @@ impl PvmDice {
         }
     }
 
+    /// Derive the leaf cert as CBOR for a given trusty TA identified by its Uuid.
+    ///
+    /// The resulting `Vec<u8>` is an encoded CoseSign1 object as per the DICE specification
+    /// for DICE certs.
+    pub fn derive_dice_cert_for_ta(&self, uuid: Uuid) -> Result<Vec<u8>, PvmDiceError> {
+        let request_ctx = RequestContext { peer: uuid };
+        let config_descriptor = config_descriptor_for_trusty_user_app(&request_ctx)?;
+        let input_values = dice_input_values_for_trusty_user_app(config_descriptor.as_slice());
+
+        let (_, ta_cert) = retry_dice_main_flow(&self.cdi_attest, &self.cdi_seal, &input_values)?;
+
+        Ok(ta_cert)
+    }
+
     fn derive_next_dice_artifacts(
         &self,
         request_ctx: &RequestContext,
     ) -> Result<OwnedDiceArtifacts, HwBccError> {
         let config_descriptor = config_descriptor_for_trusty_user_app(request_ctx)?;
-        let input_values = InputValues::new(
-            TRUSTY_NON_LOADABLE_CODE_HASH,
-            Config::Descriptor(config_descriptor.as_slice()),
-            TRUSTY_NON_LOADABLE_AUTHORITY_HASH,
-            dice_mode_for_trusty_user_space_certs(),
-            EMPTY_HIDDEN_INPUTS,
-        );
+        let input_values = dice_input_values_for_trusty_user_app(config_descriptor.as_slice());
 
         Ok(retry_bcc_main_flow(&self.cdi_attest, &self.cdi_seal, &self.bcc, &input_values)?)
     }
 }
 
+impl DiceArtifacts for PvmDice {
+    fn cdi_attest(&self) -> &[u8; CDI_SIZE] {
+        &self.cdi_attest
+    }
+    fn cdi_seal(&self) -> &[u8; CDI_SIZE] {
+        &self.cdi_seal
+    }
+    fn bcc(&self) -> Option<&[u8]> {
+        Some(&self.bcc)
+    }
+}
+
 impl HwBccOps for PvmDice {
     fn init(&self, _: &RequestContext) -> Result<(), HwBccError> {
         Ok(())
@@ -194,7 +245,7 @@ fn dice_mode_for_trusty_user_space_certs() -> DiceMode {
 /// Generate config descriptor for a dice derivation based on the calling app.
 fn config_descriptor_for_trusty_user_app(
     request_ctx: &RequestContext,
-) -> Result<Vec<u8>, HwBccError> {
+) -> Result<Vec<u8>, diced_open_dice::DiceError> {
     let component_config = dice_component_specific_config_values(request_ctx);
 
     let config_values = DiceConfigValues {
@@ -210,6 +261,16 @@ fn config_descriptor_for_trusty_user_app(
     Ok(retry_bcc_format_config_descriptor(&config_values)?)
 }
 
+fn dice_input_values_for_trusty_user_app(config_descriptor: &[u8]) -> InputValues {
+    InputValues::new(
+        TRUSTY_NON_LOADABLE_CODE_HASH,
+        Config::Descriptor(config_descriptor),
+        TRUSTY_NON_LOADABLE_AUTHORITY_HASH,
+        dice_mode_for_trusty_user_space_certs(),
+        EMPTY_HIDDEN_INPUTS,
+    )
+}
+
 /// Derive a component name from an incoming request.
 /// There are certain UUIDs that have special treatment so that they
 /// can be recognized by the RKP server. For all other UUIDs, we use
@@ -238,6 +299,11 @@ fn dice_component_specific_config_values(
 /// of the dice chain should recognize the app as different from the production
 /// variant.
 fn enforce_no_apploader_invariant() -> Result<handle_t, PvmDiceError> {
+    if cfg!(TEST_BUILD) {
+        log::warn!("Not attempting to claim apploader port because TEST_BUILD is set");
+        return Ok(-1);
+    }
+
     let port = CStr::from_bytes_with_nul(sys::APPLOADER_PORT)
         .map_err(|_| PvmDiceError::ApploaderInvariantViolated)?;
 
@@ -253,11 +319,6 @@ fn enforce_no_apploader_invariant() -> Result<handle_t, PvmDiceError> {
     };
 
     if rc < 0 {
-        if cfg!(TEST_BUILD) {
-            log::warn!("Failed to claim apploader port. Ignoring because TEST_BUILD is set.");
-            return Ok(-1);
-        }
-
         log::error!("Failed to claim apploader port. PvmDice invariant check failed: {}", rc);
 
         return Err(PvmDiceError::ApploaderInvariantViolated);
@@ -274,20 +335,23 @@ fn enforce_no_apploader_invariant() -> Result<handle_t, PvmDiceError> {
 mod test {
     use crate::PvmDice;
     use authgraph_boringssl::BoringEcDsa;
-    use authgraph_core::key::DiceChainEntry;
+    use authgraph_core::key::{CertChain, DiceChainEntry};
     use authgraph_core::traits::EcDsa;
     use ciborium::value::Value;
-    use coset::{AsCborValue, CborSerializable};
+    use coset::{AsCborValue, CborSerializable, CoseSign1};
     use diced_open_dice::DiceArtifacts;
     use diced_sample_inputs::make_sample_bcc_and_cdis;
     use hwbcc::srv::{HwBccOps, RequestContext};
     use hwbcc::HwBccMode;
-    use test::expect;
+    use std::cell::LazyCell;
+    use test::{expect, expect_eq};
     use tipc::Uuid;
     ::test::init!();
 
     const TEST_MESSAGE: &[u8] = "pvmdice test message".as_bytes();
     const TEST_AAD: &[u8] = "pvmdice test aad".as_bytes();
+    const TEST_UUID: LazyCell<Uuid> =
+        LazyCell::new(|| Uuid::new_from_string("c07129be-cabb-4d4d-837f-ea8fd204dcf1").unwrap());
 
     #[test]
     fn test_init_empty_handover() {
@@ -351,6 +415,57 @@ mod test {
             .is_ok());
     }
 
+    #[test]
+    fn test_pvmdice_as_dice_artifacts() {
+        let dice_artifacts = make_sample_bcc_and_cdis().unwrap();
+        let handover = to_bcc_handover(&dice_artifacts);
+        let pvmdice = PvmDice::try_new(&handover).unwrap();
+
+        expect_eq!(dice_artifacts.bcc(), pvmdice.bcc());
+        expect_eq!(dice_artifacts.cdi_attest(), pvmdice.cdi_attest());
+        expect_eq!(dice_artifacts.cdi_seal(), pvmdice.cdi_seal());
+    }
+
+    #[test]
+    fn test_derive_dice_cert_for_ta() {
+        let dice_artifacts = make_sample_bcc_and_cdis().unwrap();
+        let handover = to_bcc_handover(&dice_artifacts);
+        let pvmdice = PvmDice::try_new(&handover).unwrap();
+
+        let ta_cert_res = pvmdice.derive_dice_cert_for_ta(TEST_UUID.clone());
+        expect!(ta_cert_res.is_ok());
+    }
+
+    /// TA certificate generation is an optimization.
+    /// Certain users of pvmdice, like Keymint, may end up
+    /// deriving a dice chain with `get_bcc()` and also having
+    /// a leaf cert generated for them when they access a trusted
+    /// service from a pVM. This test asserts that certs representing
+    /// a TA remain the same no matter how they are derived.
+    #[test]
+    fn test_ta_cert_and_bcc_leaf_cert_match() {
+        let dice_artifacts = make_sample_bcc_and_cdis().unwrap();
+        let handover = to_bcc_handover(&dice_artifacts);
+        let pvmdice = PvmDice::try_new(&handover).unwrap();
+
+        let rq = RequestContext { peer: TEST_UUID.clone() };
+
+        let bcc_cbor_res = pvmdice.get_bcc(&rq, HwBccMode::Release);
+        expect!(bcc_cbor_res.is_ok());
+        let bcc_cbor = bcc_cbor_res.unwrap();
+        let dice_chain_res = CertChain::from_non_explicit_key_cert_chain(bcc_cbor.as_slice());
+        let dice_chain = dice_chain_res.unwrap();
+        let leaf_cert = dice_chain.dice_cert_chain.unwrap().pop().unwrap();
+
+        let ta_cert_res = pvmdice.derive_dice_cert_for_ta(TEST_UUID.clone());
+        expect!(ta_cert_res.is_ok());
+        let ta_cert = ta_cert_res.unwrap();
+        let ta_cert_cose = CoseSign1::from_slice(ta_cert.as_slice());
+        expect!(ta_cert_cose.is_ok());
+
+        expect_eq!(ta_cert_cose.unwrap(), leaf_cert.signature);
+    }
+
     fn leaf_cert_from_non_explicit_chain(dice_chain: &Vec<u8>) -> DiceChainEntry {
         let mut chain_value = Value::from_slice(dice_chain.as_slice()).expect("invalid cbor");
         let chain_arr: &mut Vec<Value> =
diff --git a/lib/pvmdice/src/thread_safe.rs b/lib/pvmdice/src/thread_safe.rs
new file mode 100644
index 0000000..24d7e1c
--- /dev/null
+++ b/lib/pvmdice/src/thread_safe.rs
@@ -0,0 +1,69 @@
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
+//! This module provides PvmDiceThreadSafe.
+//!
+//! This wrapper was originally written to support a single PvmDice object being
+//! shared between an hwbcc server and an rpcbinder server running in the same
+//! TA and event loop. rpcbinder services are thread safe and so we need a version
+//! of PvmDice that is Send + Sync if we want to use it within the request path
+//! of one of those services.
+//!
+//! Trusty user space does not support multi-threading so we assume a Mutex will
+//! never be poisoned and call unwrap throughout.
+
+use crate::PvmDice;
+use hwbcc::srv::{HwBccOps, RequestContext};
+use hwbcc::{HwBccError, HwBccMode};
+use std::sync::{Arc, Mutex};
+
+pub struct PvmDiceThreadSafe {
+    pvmdice: Arc<Mutex<PvmDice>>,
+}
+
+impl PvmDiceThreadSafe {
+    pub fn new(pvmdice: Arc<Mutex<PvmDice>>) -> Self {
+        PvmDiceThreadSafe { pvmdice }
+    }
+}
+
+impl HwBccOps for PvmDiceThreadSafe {
+    fn init(&self, context: &RequestContext) -> Result<(), HwBccError> {
+        self.pvmdice.lock().unwrap().init(context)
+    }
+
+    fn close(&self, context: &RequestContext) {
+        self.pvmdice.lock().unwrap().close(context)
+    }
+
+    fn get_bcc(
+        &self,
+        request_ctx: &RequestContext,
+        mode: HwBccMode,
+    ) -> Result<Vec<u8>, HwBccError> {
+        self.pvmdice.lock().unwrap().get_bcc(request_ctx, mode)
+    }
+
+    fn sign_data<'a>(
+        &self,
+        request_ctx: &RequestContext,
+        data: &'a [u8],
+        aad: &'a [u8],
+        mode: HwBccMode,
+    ) -> Result<Vec<u8>, HwBccError> {
+        self.pvmdice.lock().unwrap().sign_data(request_ctx, data, aad, mode)
+    }
+}
diff --git a/lib/service_manager/client/rules.mk b/lib/service_manager/client/rules.mk
index 829370f..66b3861 100644
--- a/lib/service_manager/client/rules.mk
+++ b/lib/service_manager/client/rules.mk
@@ -26,7 +26,11 @@ MODULE_SDK_LIB_NAME := service_manager-rust
 MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/sample/hwcryptohal/aidl/rust  \
+	trusty/user/base/interface/authmgr/rust \
 	trusty/user/base/interface/binder_accessor \
+	trusty/user/base/interface/secure_storage/rust \
+	trusty/user/base/lib/authmgr-common-rust \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-std \
 
diff --git a/lib/service_manager/client/src/lib.rs b/lib/service_manager/client/src/lib.rs
index 88306a6..eb1cd4a 100644
--- a/lib/service_manager/client/src/lib.rs
+++ b/lib/service_manager/client/src/lib.rs
@@ -14,7 +14,12 @@
 * limitations under the License.
 */
 
+mod vintf_services;
+
+pub use vintf_services::{get_supported_vintf_services, VintfService};
+
 use alloc::ffi::CString;
+use authmgr_common::CMD_RPC;
 use binder::{ExceptionCode, FromIBinder, ParcelFileDescriptor, StatusCode, Strong};
 use rpcbinder::{FileDescriptorTransportMode, RpcSession};
 use std::ffi::CStr;
@@ -29,6 +34,11 @@ const MAX_TIPC_PORT_NAME_LEN: usize = 64;
 const TRUSTY_BINDER_RPC_PORT_SUFFIX: &str = ".bnd";
 const TRUSTED_HAL_COMMON_PREFIX: &str = "android.hardware.security.see";
 const TRUSTED_HAL_REPLACEMENT_PREFIX: &str = "ahss";
+pub const HANDOVER_SERVICE_PREFIX: &str = "IHandover/";
+const HANDOVER_SERVICE_SUFFIX: &str = ".hnd";
+// The trailing slash ensures some future interface IAuthMgrAuthorizationMORE doesn't also match
+// this criteria.
+const AUTHMGR_NAME_PREFIX: &str = "android.hardware.security.see.authmgr.IAuthMgrAuthorization/";
 
 #[derive(Debug, PartialEq)]
 enum Error {
@@ -58,13 +68,20 @@ pub fn wait_for_interface<T: FromIBinder + ?Sized>(name: &str) -> Result<Strong<
     let c_port_name = service_name_to_trusty_c_port(name)?;
     let port_name = c_port_name.as_c_str().to_str().map_err(|_| StatusCode::BAD_VALUE)?;
 
+    // IAuthMgrAuthorization is a special case. As per the protocol spec,
+    // it multiplexes to two different services on the same port depending
+    // on an initial control byte. The service_manager lib only deals with
+    // AIDL services so we always send the RPC command.
+    let control_byte = if name.starts_with(AUTHMGR_NAME_PREFIX) { Some(CMD_RPC) } else { None };
+
     // First try and see if our service is gated by an ITrustyAccessor implementation.
     // This is a binder service exposed on the port we've connected to that acts as
     // an intermediary for resolving connections to the requested service. It was originally
     // introduced to allow for authentication and authorization of the caller before handing
     // back a handle to the requested service.
+    log::trace!("Attempting to get ITrustyAccessor at port {:?}", port_name);
     let mut session = get_new_rpc_session();
-    match setup_trusty_client(&session, &c_port_name) {
+    match setup_trusty_client(&session, &c_port_name, control_byte) {
         Ok(accessor) => {
             let service_fd = fd_from_accessor(&accessor, name)?;
 
@@ -92,8 +109,9 @@ pub fn wait_for_interface<T: FromIBinder + ?Sized>(name: &str) -> Result<Strong<
     }
 
     // The binder on the other end was likely not an accessor, try a direct connection.
+    log::trace!("Attempting to get direct interface at port {:?}", port_name);
     session = get_new_rpc_session();
-    setup_trusty_client(&session, &c_port_name).map_err(|e| {
+    setup_trusty_client(&session, &c_port_name, control_byte).map_err(|e| {
         log::error!("failed to setup binder on {:?} {:?}", &port_name, e);
         match e {
             // This is an unexpected case. We've already successfully connected to this port once.
@@ -156,17 +174,29 @@ fn rpcbinder_from_parcel_fd<T: FromIBinder + ?Sized>(
     session.setup_preconnected_client(move || Some(raw_fd))
 }
 
-/// Pretty much a re-implementation of RpcSession::setup_trusty_client but does not panic
-/// when a connection fails. As a bonus, we can differentiate between a failed raw connection
-/// and other binder-specific errors.
+/// Sets up a new RpcSession with a new tipc connection.
+/// A re-implementation of RpcSession::setup_trusty_client but does not panic.
+///
+/// If control_byte is set, this byte will be sent on the opened handle before
+/// setting up the session.
 fn setup_trusty_client<T: FromIBinder + ?Sized>(
     session: &RpcSession,
     port: &CStr,
+    control_byte: Option<u8>,
 ) -> Result<Strong<T>, Error> {
     let h = tipc::Handle::connect(port).map_err(|e| {
         log::error!("Failed to connect to port {:?} {:?}", port, e);
         Error::ConnectionFailed
     })?;
+
+    if let Some(c) = control_byte {
+        log::trace!("sending control byte on port {port:?}");
+        h.send(&c).map_err(|e| {
+            log::error!("Failed to send control byte on port {:?} {:?}", port, e);
+            Error::ConnectionFailed
+        })?;
+    }
+
     // Do not close the handle at the end of the scope
     let fd = h.as_raw_fd();
     core::mem::forget(h);
@@ -191,6 +221,11 @@ fn get_new_rpc_session() -> RpcSession {
 //
 // So for example, "android.hardware.security.see.authmgr.IAuthMgrAuthorization/default"
 // will result in a port name of ahss.authmgr.IAuthMgrAuhtorization/default .
+//
+// This function also constructs (shortened) port names for the handover services associated with
+// the trusted services. An example handover service's name given as:
+// "IHandover/android.hardware.security.see.secure.storage.ISecureStorage/default" will result in a
+// port name of: "ahss.secure.storage.ISecureStorage/default.hnd".
 fn try_long_service_name_to_port(service_name: &str) -> Result<String, StatusCode> {
     let mut port_name = String::new();
 
@@ -198,33 +233,43 @@ fn try_long_service_name_to_port(service_name: &str) -> Result<String, StatusCod
         // Since we're in this function, we already know the given service_name is too long
         // and a None here means we won't shorten it since our prefix wasn't found.
         None => Err(port_size_err(service_name)),
-        // In this case our pattern was found, but not at the front of the str, which
-        // is not a valid case for our name shortening. Since we're in this function
-        // we now know we have a name that's too long and we can't shorten.
+        // In this case our pattern was found, but not at the front of the str. We first check
+        // whether the front of the str matches the prefix for the handover service and handle it
+        // accordingly.
+        Some((pre, post)) if pre == HANDOVER_SERVICE_PREFIX => {
+            build_shortened_port_name(&mut port_name, post, HANDOVER_SERVICE_SUFFIX)
+        }
+        // The front of the str doesn't match any known prefix. Therefore, it is not a valid case
+        // for our name shortening. Since we're in this function we now know we have a name that's
+        // too long and we can't shorten.
         Some((pre, _)) if !pre.is_empty() => Err(port_size_err(service_name)),
         Some((_, post)) => {
-            port_name
-                .try_reserve(
-                    TRUSTED_HAL_REPLACEMENT_PREFIX.len()
-                        + post.len()
-                        + TRUSTY_BINDER_RPC_PORT_SUFFIX.len(),
-                )
-                .map_err(|_| StatusCode::NO_MEMORY)?;
-
-            port_name.push_str(TRUSTED_HAL_REPLACEMENT_PREFIX);
-            port_name.push_str(post);
-            port_name.push_str(TRUSTY_BINDER_RPC_PORT_SUFFIX);
-
-            // Check size again. It's possible we weren't able to shorten the name enough.
-            if !is_valid_port_len(port_name.len()) {
-                return Err(port_size_err(&port_name));
-            }
-
-            Ok(port_name)
+            build_shortened_port_name(&mut port_name, post, TRUSTY_BINDER_RPC_PORT_SUFFIX)
         }
     }
 }
 
+fn build_shortened_port_name(
+    port_name: &mut String,
+    service_name: &str,
+    suffix: &str,
+) -> Result<String, StatusCode> {
+    port_name
+        .try_reserve(TRUSTED_HAL_REPLACEMENT_PREFIX.len() + service_name.len() + suffix.len())
+        .map_err(|_| StatusCode::NO_MEMORY)?;
+
+    port_name.push_str(TRUSTED_HAL_REPLACEMENT_PREFIX);
+    port_name.push_str(service_name);
+    port_name.push_str(suffix);
+
+    // Check size again. It's possible we weren't able to shorten the name enough.
+    if !is_valid_port_len(port_name.len()) {
+        return Err(port_size_err(port_name));
+    }
+
+    Ok(port_name.clone())
+}
+
 fn is_valid_port_len(port_len: usize) -> bool {
     // Note that if the name is equal to the max, we fail because
     // these ports will eventually be represented as CStrings and passed
@@ -244,13 +289,22 @@ fn port_size_err(service_name: &str) -> StatusCode {
 }
 
 /// A helper to transform a binder service name to a trusty port name.
-/// A suffix is added to the service name to identify it as a port that is serving
+/// A suffix (".bnd") is added to the service name to identify it as a port that is serving
 /// binders.
 ///
 /// Some known trusted hal services, those that start with android.hardware.security.see
 /// are transformed to fit within trusty's port length limits.
+///
+/// Similarly, this function also transforms the handover services' names to a trusty port name.
+/// A handover service name is detected by the prefix: "IHandover/", which is removed in the
+/// returned port name. A different suffix of ".hnd" is added to the returned port name.
 pub fn service_name_to_trusty_port(service_name: &str) -> Result<String, StatusCode> {
-    let service_name_len = service_name.len() + TRUSTY_BINDER_RPC_PORT_SUFFIX.len();
+    let is_handover_service_name = service_name.starts_with(HANDOVER_SERVICE_PREFIX);
+    let service_name_len = if is_handover_service_name {
+        service_name.len() - HANDOVER_SERVICE_PREFIX.len() + HANDOVER_SERVICE_SUFFIX.len()
+    } else {
+        service_name.len() + TRUSTY_BINDER_RPC_PORT_SUFFIX.len()
+    };
 
     // TODO: b/403531416 - remove this once longer port names are supported in trusty
     if !is_valid_port_len(service_name_len) {
@@ -258,11 +312,15 @@ pub fn service_name_to_trusty_port(service_name: &str) -> Result<String, StatusC
     }
 
     let mut port_name = String::new();
-
     port_name.try_reserve(service_name_len).map_err(|_| StatusCode::NO_MEMORY)?;
 
-    port_name.push_str(service_name);
-    port_name.push_str(TRUSTY_BINDER_RPC_PORT_SUFFIX);
+    if is_handover_service_name {
+        port_name.push_str(extract_handover_service_name(service_name)?);
+        port_name.push_str(HANDOVER_SERVICE_SUFFIX);
+    } else {
+        port_name.push_str(service_name);
+        port_name.push_str(TRUSTY_BINDER_RPC_PORT_SUFFIX);
+    }
 
     Ok(port_name)
 }
@@ -276,3 +334,16 @@ pub fn service_name_to_trusty_c_port(service_name: &str) -> Result<CString, Stat
 
     CString::new(port_name).map_err(|_| StatusCode::BAD_VALUE)
 }
+
+// A helper function to extract the handover service name by removing the prefix: "IHandover".
+fn extract_handover_service_name(prefixed_handover_service_name: &str) -> Result<&str, StatusCode> {
+    match prefixed_handover_service_name.split_once(HANDOVER_SERVICE_PREFIX) {
+        // In this case our pattern was found, but not at the front of the str, which
+        // is not a valid case.
+        Some((pre, _)) if !pre.is_empty() => Err(StatusCode::BAD_VALUE),
+        Some((_, post)) => Ok(post),
+        // Since we're in this function, we already know the given service_name should contain the
+        // prefix. So this match arm cannot be hit.
+        None => Err(StatusCode::BAD_VALUE),
+    }
+}
diff --git a/lib/service_manager/client/src/vintf_services.rs b/lib/service_manager/client/src/vintf_services.rs
new file mode 100644
index 0000000..2fa9fc8
--- /dev/null
+++ b/lib/service_manager/client/src/vintf_services.rs
@@ -0,0 +1,87 @@
+/*
+* Copyright (C) 2025 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+//! This module contains helpers for trusty TAs that need to provide or test against
+//! VINTF stable services in trusty. It's pretty unlikely that you should be using
+//! these helpers unless you're implementing a TA that facilitates access to services
+//! like authmgr-fe or the VINTF testing TA.
+//!
+//! To get an SpIBinder for each supported VINTF services, you can do the following:
+//!
+//! ```
+//! use service_manager::vintf_services::{VintfServiceImpl, get_supported_vintf_services};
+//!
+//! for service in get_supported_vintf_services() {
+//!     binder = service.get_binder();
+//!     // use `binder` here
+//! }
+//! ```
+
+use binder::{SpIBinder, FromIBinder};
+use crate::wait_for_interface;
+use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::IAuthMgrAuthorization::IAuthMgrAuthorization;
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
+use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::ISecureStorage::ISecureStorage;
+use std::marker::PhantomData;
+
+pub trait VintfService {
+    /// Get the root SpIBinder for this VINTF service.
+    /// NOTE: the only implementation of this trait will block
+    /// forever if no service is published at the expected port.
+    fn get_binder(&self) -> binder::Result<SpIBinder>;
+
+    /// The name for this service. This name is used to
+    /// publish the service locally. Callers should not depend
+    /// on it to derive class and instance names, but should
+    /// get this information from the binder object itself.
+    fn name(&self) -> &'static str;
+}
+
+pub struct VintfServiceImpl<T: FromIBinder + ?Sized> {
+    name: &'static str,
+    phantom: PhantomData<T>,
+}
+
+impl<T: FromIBinder + ?Sized> VintfServiceImpl<T> {
+    fn new(name: &'static str) -> Self {
+        Self { name, phantom: PhantomData }
+    }
+}
+
+impl<T: FromIBinder + ?Sized> VintfService for VintfServiceImpl<T> {
+    fn get_binder(&self) -> binder::Result<SpIBinder> {
+        Ok(wait_for_interface::<T>(self.name)?.as_binder())
+    }
+
+    fn name(&self) -> &'static str {
+        self.name
+    }
+}
+
+/// Get all supported VINTF services.
+pub fn get_supported_vintf_services() -> Vec<Box<dyn VintfService>> {
+    vec![
+        Box::new(VintfServiceImpl::<dyn ISecureStorage>::new(
+            "android.hardware.security.see.storage.ISecureStorage/default",
+        )),
+        Box::new(VintfServiceImpl::<dyn IHwCryptoKey>::new(
+            "android.hardware.security.see.hwcrypto.IHwCryptoKey/default",
+        )),
+        Box::new(VintfServiceImpl::<dyn IAuthMgrAuthorization>::new(
+            "android.hardware.security.see.authmgr.IAuthMgrAuthorization/default",
+        )),
+    ]
+}
diff --git a/lib/service_manager/tests/fake_accessor/src/main.rs b/lib/service_manager/tests/fake_accessor/src/main.rs
index daf3c17..9b5ef5b 100644
--- a/lib/service_manager/tests/fake_accessor/src/main.rs
+++ b/lib/service_manager/tests/fake_accessor/src/main.rs
@@ -3,7 +3,7 @@ use binder::{BinderFeatures, Interface, ParcelFileDescriptor, Status};
 use rpcbinder::RpcServer;
 use service_manager::{service_name_to_trusty_c_port, service_name_to_trusty_port};
 use std::os::fd::{FromRawFd, OwnedFd};
-use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, Uuid};
+use tipc::{service_dispatcher, wrap_service, Manager, PortCfg};
 use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
     BnTrustyAccessor, ITrustyAccessor, ERROR_FAILED_TO_CREATE_SOCKET,
 };
@@ -17,7 +17,7 @@ const ACCESSOR_MISMATCH_TEST_NAME: &str = "com.android.trusty.test_service.ISMTe
 // This port is locked down to not allow access to any existing TAs. It allows the client tests
 // to exercise connection failure paths.
 const ACCESSOR_NO_PERMISSIONS: &str = "com.android.trusty.test_service.ISMTestService/eperm";
-const EMPTY_ALLOWED_UUIDS: &[Uuid] = &[];
+
 struct FakeAccessor;
 impl Interface for FakeAccessor {}
 impl ITrustyAccessor for FakeAccessor {
@@ -76,12 +76,17 @@ fn main() {
     dispatcher
         .add_service(test_service.clone(), cfg)
         .expect("failed to add mismatch test port to dispatcher");
+
+    // Purposefully do not set the ta or ns allow flags.
+    // If we reject by UUID allow list instead, there is a race condition
+    // between the connection being accepted and then subsequently dropped
+    // when the permission check happens in user space on the server.
+    // This is typically fine, but leads to non-deterministic behavior in
+    // tests that are trying to test rejected connections.
     let cfg = PortCfg::new(
         service_name_to_trusty_port(ACCESSOR_NO_PERMISSIONS).expect("no perm port to be resolved"),
     )
-    .expect("could not create port config")
-    .allow_ta_connect()
-    .allowed_uuids(EMPTY_ALLOWED_UUIDS);
+    .expect("could not create port config");
     dispatcher.add_service(test_service, cfg).expect("failed to add eperm test port to dispatcher");
     Manager::<_, _, 3, 1>::new_with_dispatcher(dispatcher, [])
         .expect("Service manager could not be created")
diff --git a/lib/service_manager/tests/tests.rs b/lib/service_manager/tests/tests.rs
index 2e0038f..aa3c560 100644
--- a/lib/service_manager/tests/tests.rs
+++ b/lib/service_manager/tests/tests.rs
@@ -121,4 +121,59 @@ mod tests {
             Err(binder::StatusCode::BAD_VALUE),
         )
     }
+
+    #[test]
+    fn test_handover_service_name_to_trusty_port_under_max_without_trustedhal_prefix() {
+        expect_eq!(
+            service_name_to_trusty_port("IHandover/android.hardware.security.IHelloWorld/default"),
+            Ok("android.hardware.security.IHelloWorld/default.hnd".to_owned()),
+        );
+    }
+
+    #[test]
+    fn test_handover_service_name_to_trusty_port_under_max_with_trustedhal_prefix() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "IHandover/android.hardware.security.see.hwcrypto.IHwCryptoKey/default"
+            ),
+            Ok("android.hardware.security.see.hwcrypto.IHwCryptoKey/default.hnd".to_owned()),
+        )
+    }
+
+    #[test]
+    fn test_handover_service_name_to_trusty_port_too_long_without_trustedhal_prefix() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "IHandover/android.hardware.some.too.long.path.secure.ISecureStorage/default"
+            ),
+            Err(binder::StatusCode::BAD_VALUE),
+        )
+    }
+
+    #[test]
+    fn test_handover_service_name_to_trusty_port_too_long_with_trustedhal_prefix() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "IHandover/android.hardware.security.see.secure.storage.ISecureStorage/default"
+            ),
+            Ok("ahss.secure.storage.ISecureStorage/default.hnd".to_owned()),
+        )
+    }
+
+    #[test]
+    fn test_handover_service_name_to_trusty_port_too_long_with_wrong_pattern() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "wrong.IHandover/hardware.security.secure.storage.ISecureStorage/default"
+            ),
+            Err(binder::StatusCode::BAD_VALUE),
+        );
+
+        expect_eq!(
+            service_name_to_trusty_port(
+                "android.hardware.some.too.long.path.ISecureStorage/default/IHandover/"
+            ),
+            Err(binder::StatusCode::BAD_VALUE),
+        )
+    }
 }
diff --git a/lib/tipc/rust/rules.mk b/lib/tipc/rust/rules.mk
index 54873e0..737708c 100644
--- a/lib/tipc/rust/rules.mk
+++ b/lib/tipc/rust/rules.mk
@@ -28,6 +28,7 @@ MODULE_INCLUDES += \
 
 MODULE_LIBRARY_DEPS += \
 	$(call FIND_CRATE,zerocopy) \
+	$(call FIND_CRATE,zerocopy-derive) \
 
 MODULE_LIBRARY_EXPORTED_DEPS += \
 	$(call FIND_CRATE,arrayvec) \
diff --git a/lib/tipc/rust/src/handle.rs b/lib/tipc/rust/src/handle.rs
index 6f6bb66..fe33b1e 100644
--- a/lib/tipc/rust/src/handle.rs
+++ b/lib/tipc/rust/src/handle.rs
@@ -19,8 +19,9 @@ use crate::sys::*;
 use crate::{Deserialize, Serialize, TipcError};
 use core::convert::TryInto;
 use core::ffi::CStr;
-use core::mem::MaybeUninit;
+use core::mem::{ManuallyDrop, MaybeUninit};
 use log::{error, warn};
+use std::os::fd::{IntoRawFd, RawFd};
 use trusty_sys::{c_int, c_long};
 
 /// An open IPC connection or shared memory reference.
@@ -372,6 +373,14 @@ impl Drop for Handle {
     }
 }
 
+impl IntoRawFd for Handle {
+    fn into_raw_fd(self) -> RawFd {
+        let h = ManuallyDrop::new(self);
+
+        h.as_raw_fd()
+    }
+}
+
 /// A serializer that borrows its input bytes and does not allocate.
 #[derive(Default)]
 struct BorrowingSerializer<'a> {
@@ -468,8 +477,9 @@ pub(crate) mod test {
     use super::Handle;
     use crate::sys;
     use crate::TipcError;
+    use std::os::fd::IntoRawFd;
     use std::sync::Once;
-    use test::expect_eq;
+    use test::{expect, expect_eq};
     use trusty_sys::Error;
 
     // Expected limits: should be in sync with kernel settings
@@ -553,4 +563,24 @@ pub(crate) mod test {
             );
         }
     }
+
+    #[test]
+    fn into_raw_fd() {
+        // Handle ignores errors from the close syscall on drop so scoping
+        // the handle ensures drop is called and we can test to ensure we
+        // still have a valid RawFd.
+        let raw_fd = {
+            let handle = Handle::connect(c"com.android.ipc-unittest.srv.ta_only");
+            expect!(handle.is_ok());
+
+            handle.unwrap().into_raw_fd()
+        };
+
+        // SAFETY: Calling the close syscall with the expected type. It is safe to
+        // call close with an invalid handle as it will just return an error.
+        let rc = unsafe { trusty_sys::close(raw_fd) };
+
+        // No error on close means we had a valid handle.
+        expect!(!Error::is_err(rc));
+    }
 }
diff --git a/lib/tipc/rust/src/lib.rs b/lib/tipc/rust/src/lib.rs
index 601182d..355a2a0 100644
--- a/lib/tipc/rust/src/lib.rs
+++ b/lib/tipc/rust/src/lib.rs
@@ -42,7 +42,9 @@ mod service;
 pub use err::{ConnectResult, MessageResult, Result, TipcError};
 pub use handle::{Handle, MMapFlags, UnsafeSharedBuf, MAX_MSG_HANDLES};
 pub use serialization::{Deserialize, Serialize, Serializer};
-pub use service::{Dispatcher, Manager, PortCfg, Service, UnbufferedService, Uuid};
+pub use service::{
+    ClientIdentifier, Dispatcher, Manager, PortCfg, Service, UnbufferedService, Uuid,
+};
 
 #[cfg(test)]
 mod test {
diff --git a/lib/tipc/rust/src/raw/handle_set_wrapper.rs b/lib/tipc/rust/src/raw/handle_set_wrapper.rs
index c79b5b5..4b019f0 100644
--- a/lib/tipc/rust/src/raw/handle_set_wrapper.rs
+++ b/lib/tipc/rust/src/raw/handle_set_wrapper.rs
@@ -18,7 +18,8 @@
 //! raw handle set. The wrapper also enforces the limits on ports and connections per TA.
 use crate::raw::{service_handle::PortWrapper, HandleType, RawHandleSet, ServiceHandle};
 use crate::{
-    ConnectResult, Handle, MessageResult, PortCfg, Result, TipcError, UnbufferedService, Uuid,
+    ClientIdentifier, ConnectResult, Handle, MessageResult, PortCfg, Result, TipcError,
+    UnbufferedService, Uuid,
 };
 use alloc::sync::Arc;
 use log::error;
@@ -26,24 +27,29 @@ use std::collections::vec_deque::VecDeque;
 use std::sync::Mutex;
 use trusty_std::TryClone;
 
-/// Encapsulate a work item to call on_connect on a given service
+/// Encapsulate a work item to handover connection to a given service from a given client
+/// Note that the client sequence number cannot take negative values. It is defined as i64 because
+/// AIDL types currently do not support u64.
 pub struct ToConnect<S: UnbufferedService> {
     handle: Handle,
     service: Arc<S>,
     port: PortCfg,
-    // TODO: This should be removed in the long term
-    uuid: Uuid,
+    client_seq_num: i64,
 }
 
 impl<S: UnbufferedService> ToConnect<S> {
     /// Constructor
-    pub fn new(handle: Handle, service: Arc<S>, port: PortCfg, uuid: Uuid) -> Self {
-        Self { handle, service, port, uuid }
+    pub fn new(handle: Handle, service: Arc<S>, port: PortCfg, client_seq_num: i64) -> Self {
+        Self { handle, service, port, client_seq_num }
     }
 
-    /// Handle on_connect work item
-    pub fn do_on_connect(&self) -> Result<ConnectResult<S::Connection>> {
-        self.service.on_connect(&self.port, &self.handle, &self.uuid)
+    /// Handover connection
+    pub fn do_connect(&self) -> Result<ConnectResult<S::Connection>> {
+        self.service.on_new_connection(
+            &self.port,
+            &self.handle,
+            &ClientIdentifier::ClientSeqNumber(self.client_seq_num),
+        )
     }
 }
 
@@ -71,7 +77,7 @@ impl<S: UnbufferedService> HandleSetWrapper<S> {
         let mut wq = self.work_queue.lock().unwrap();
         while let Some(work_item) = wq.pop_front() {
             let WorkToDo::Connect(to_connect) = work_item;
-            match to_connect.do_on_connect()? {
+            match to_connect.do_connect()? {
                 ConnectResult::Accept(conn) => {
                     return self
                         .add_connection(conn, to_connect.handle, to_connect.service)
@@ -183,20 +189,19 @@ impl<S: UnbufferedService> HandleSetWrapper<S> {
             error!("A connection type handle is expected. Received: {:?}", &service_handle.ty);
             return Err(TipcError::InvalidData);
         }
-        self.remove(service_handle)?;
-        Ok(())
+        self.remove(service_handle)
     }
 
-    /// Remove a handle from the handle set
-    pub fn remove(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<()> {
+    /// Set a port's event mask.
+    pub fn set_event_mask(&self, port_wrapper: &PortWrapper<S>, enabled_events: u32) -> Result<()> {
         let hs = self.handle_set.lock().unwrap();
-        hs.remove(service_handle)
+        hs.set_event_mask(&port_wrapper.service_handle, enabled_events)
     }
 
-    /// Remove a handle from the handle set
-    pub fn remove_raw(&self, handle: i32) -> Result<Arc<ServiceHandle<S>>> {
+    /// Remove a service handle from the handle set.
+    pub fn remove(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<()> {
         let hs = self.handle_set.lock().unwrap();
-        hs.remove_raw(handle)
+        hs.remove(service_handle)
     }
 
     /// Add a work item
@@ -209,7 +214,7 @@ impl<S: UnbufferedService> HandleSetWrapper<S> {
 #[cfg(test)]
 mod test {
     use crate::handle::test::{first_free_handle_index, MAX_USER_HANDLES};
-    use crate::raw::{raw_handle_set::Handler, HandleSetWrapper};
+    use crate::raw::{service_handle::PortWrapper, HandleSetWrapper, HandleType, ServiceHandle};
     use crate::{
         ConnectResult, Handle, MessageResult, PortCfg, Result, Service, TipcError,
         UnbufferedService, Uuid,
@@ -336,43 +341,77 @@ mod test {
     }
 
     #[test]
-    fn add_port_drop_wrapper() {
+    fn add_port_mask_wrapper() {
         let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
         let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
         let cfg = PortCfg::new(path).unwrap();
         let service = Arc::new(());
         {
-            // This line ignores the returned wrapper, which immediately drops it.
-            handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
-            expect_eq!(Arc::strong_count(&service), 1);
+            let port_wrapper = handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&service), 2);
+            handle_set_wrapper
+                .set_event_mask(&port_wrapper, trusty_sys::uevent::NO_EVENTS)
+                .unwrap();
+            handle_set_wrapper
+                .set_event_mask(&port_wrapper, trusty_sys::uevent::ALL_EVENTS)
+                .unwrap();
         }
         expect_eq!(Arc::strong_count(&service), 1);
     }
 
     #[test]
-    fn add_connection() {
+    fn add_port_mask_corrupted_wrapper() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path_1 = format!("{}.port.{}", SRV_PATH_BASE, "test_1");
+        let path_2 = format!("{}.port.{}", SRV_PATH_BASE, "test_2");
+        let cfg_1 = PortCfg::new(path_1).unwrap();
+        let cfg_2 = PortCfg::new(path_2).unwrap();
+        let service = Arc::new(());
+        {
+            let port_wrapper_1 = handle_set_wrapper.add_port(&cfg_1, service.clone()).unwrap();
+            let port_wrapper_2 = handle_set_wrapper.add_port(&cfg_2, service.clone()).unwrap();
+            let corrupted_port_wrapper = PortWrapper {
+                handle_set_wrapper: port_wrapper_1.handle_set_wrapper,
+                service_handle: Arc::new(ServiceHandle {
+                    handle: Handle::from_raw(port_wrapper_2.service_handle.handle.as_raw_fd())
+                        .unwrap(),
+                    service: service.clone(),
+                    ty: HandleType::Port(cfg_2),
+                }),
+            };
+            expect_eq!(Arc::strong_count(&service), 4);
+            expect_eq!(
+                Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
+                handle_set_wrapper
+                    .set_event_mask(&corrupted_port_wrapper, trusty_sys::uevent::NO_EVENTS),
+                "the cookie doesn't match the handle"
+            );
+            handle_set_wrapper
+                .set_event_mask(&port_wrapper_2, trusty_sys::uevent::NO_EVENTS)
+                .unwrap();
+
+            // Manually destroy the corrupted wrapper before its `drop` causes problems.
+            // If its `Handle` is dropped, then the drop of `port_wrapper_2` will leak resources.
+            std::mem::forget(corrupted_port_wrapper);
+            // SAFETY: We are doing manual cleanup to destroy a deliberately corrupted object.
+            unsafe {
+                Arc::decrement_strong_count(Arc::as_ptr(&service));
+            }
+        }
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn add_port_drop_wrapper() {
         let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
         let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
         let cfg = PortCfg::new(path).unwrap();
         let service = Arc::new(());
-
-        // SAFETY: syscall, `cfg` is a local and outlives the call.
-        // The return value is either a negative error code or a valid handle.
-        let rc = unsafe {
-            trusty_sys::port_create(
-                cfg.get_path().as_ptr(),
-                cfg.get_msg_queue_len(),
-                cfg.get_msg_max_size(),
-                cfg.get_flags(),
-            )
-        };
-        expect!(rc >= 0, "created the connection handle");
-
-        let handle_fd = rc as i32;
-        let handle = Handle::from_raw(handle_fd).unwrap();
-        handle_set_wrapper.add_connection((), handle, service.clone()).unwrap();
-        expect_eq!(Arc::strong_count(&service), 2);
-        expect!(handle_set_wrapper.remove_raw(handle_fd).is_ok(), "removed the connection handle");
+        {
+            // This line ignores the returned wrapper, which immediately drops it.
+            handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&service), 1);
+        }
         expect_eq!(Arc::strong_count(&service), 1);
     }
 
@@ -401,39 +440,8 @@ mod test {
             expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 2);
             expect_eq!(Arc::strong_count(&service), 2);
             expect!(handle_set_wrapper.remove(port_wrapper.service_handle.clone()).is_ok());
-            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 1);
-            expect_eq!(
-                Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
-                handle_set_wrapper.remove(port_wrapper.service_handle.clone()),
-                "handle already removed"
-            );
-        }
-        // `port_wrapper.service_handle` gets removed one more time here
-        // when port_wrapper is dropped. This emits an error message.
-        expect_eq!(Arc::strong_count(&service), 1);
-    }
-
-    #[test]
-    fn remove_raw() {
-        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
-        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
-        let cfg = PortCfg::new(path).unwrap();
-        let service = Arc::new(());
-        {
-            let port_wrapper = handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
-            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 2);
             expect_eq!(Arc::strong_count(&service), 2);
-            expect!(handle_set_wrapper
-                .remove_raw(port_wrapper.service_handle.get_raw_fd_id())
-                .is_ok());
-            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 1);
-            expect_eq!(
-                Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
-                handle_set_wrapper.remove(port_wrapper.service_handle.clone())
-            );
         }
-        // `port_wrapper.service_handle` gets removed one more time here
-        // when port_wrapper is dropped. This emits an error message.
         expect_eq!(Arc::strong_count(&service), 1);
     }
 
diff --git a/lib/tipc/rust/src/raw/raw_handle_set.rs b/lib/tipc/rust/src/raw/raw_handle_set.rs
index 19e48bd..bbf1891 100644
--- a/lib/tipc/rust/src/raw/raw_handle_set.rs
+++ b/lib/tipc/rust/src/raw/raw_handle_set.rs
@@ -78,33 +78,26 @@ impl<H: Handler> RawHandleSet<H> {
         ret
     }
 
-    /// Remove a previously registered handle object.
-    pub fn remove(&self, event_cookie_obj: Arc<H>) -> Result<()> {
-        self.remove_raw(event_cookie_obj.get_raw_fd_id()).map(|_| ())
+    /// Set the event mask for a previously registered service handle.
+    pub fn set_event_mask(&self, event_cookie_obj: &Arc<H>, enabled_events: u32) -> Result<()> {
+        self.do_set_ctrl(sys::HSET_MOD_WITH_COOKIE as u32, enabled_events, &event_cookie_obj)
     }
 
-    /// Remove a previously registered handle object and return an arc to it.
-    pub fn remove_raw(&self, handle: i32) -> Result<Arc<H>> {
-        let mut uevt = trusty_sys::uevent { handle, event: 0, cookie: std::ptr::null_mut() };
-        // SAFETY: syscall. The uevent pointer points to a correctly initialized
-        // structure that is valid across the call. The handle for the handle set is valid for
-        // the same lifetime as self, so will remain valid at least as long as the handle object
-        // being added/modified.
-        let rc = unsafe {
-            trusty_sys::handle_set_ctrl(
-                self.handle.as_raw_fd(),
-                sys::HSET_DEL_GET_COOKIE,
-                &mut uevt,
-            )
-        };
-
-        if rc < 0 {
-            Err(TipcError::from_uapi(rc))
-        } else {
-            // SAFETY: the `cookie` is the `Arc` that we registered in `register`. Here, we
-            // successfully deleted the handle from the handle set and are returning its cookie.
-            unsafe { Ok(Arc::from_raw(uevt.cookie.cast::<H>())) }
+    /// Remove a previously registered service handle.
+    pub fn remove(&self, event_cookie_obj: Arc<H>) -> Result<()> {
+        let ret = self.do_set_ctrl(
+            sys::HSET_DEL_WITH_COOKIE as u32,
+            trusty_sys::uevent::NO_EVENTS,
+            &event_cookie_obj,
+        );
+        if ret.is_ok() {
+            // SAFETY: The ref count is at least 2 (local arg + kernel).
+            // Here, we decrement it to represent the successful removal from the kernel.
+            unsafe {
+                Arc::decrement_strong_count(Arc::as_ptr(&event_cookie_obj));
+            }
         }
+        ret
     }
 
     // Add, update or remove the handle object (event cookie object) from the kernel handle set.
@@ -112,6 +105,16 @@ impl<H: Handler> RawHandleSet<H> {
     // When this is called in the delete path, an arc to the deleted handle object is returned to
     // caller, without dropping it, because the caller may need it for further processing.
     fn do_set_ctrl(&self, cmd: u32, event: u32, event_cookie_obj: &Arc<H>) -> Result<()> {
+        if ![
+            sys::HSET_ADD as u32,
+            sys::HSET_MOD_WITH_COOKIE as u32,
+            sys::HSET_DEL_WITH_COOKIE as u32,
+        ]
+        .contains(&cmd)
+        {
+            // other commands can break our memory safety guarantees
+            return Err(TipcError::SystemError(trusty_sys::Error::InvalidArgs));
+        }
         let raw_handle_fd: i32 = event_cookie_obj.get_raw_fd_id();
         let cookie = Arc::as_ptr(event_cookie_obj);
         let mut uevt =
diff --git a/lib/tipc/rust/src/service.rs b/lib/tipc/rust/src/service.rs
index ffea901..fb4d0e9 100644
--- a/lib/tipc/rust/src/service.rs
+++ b/lib/tipc/rust/src/service.rs
@@ -28,7 +28,7 @@ use crate::handle::MAX_MSG_HANDLES;
 use crate::sys;
 use crate::{ConnectResult, Deserialize, Handle, MessageResult, Result, TipcError};
 use handle_set::HandleSet;
-
+use zerocopy::{FromBytes, Immutable, IntoBytes};
 mod handle_set;
 
 /// A description of a server-side IPC port.
@@ -262,7 +262,7 @@ impl<D: Dispatcher> Channel<D> {
 }
 
 /// Trusty APP UUID
-#[derive(Clone, Eq, PartialEq)]
+#[derive(Clone, Eq, IntoBytes, Immutable, PartialEq)]
 pub struct Uuid(trusty_sys::uuid);
 
 impl Uuid {
@@ -406,6 +406,89 @@ impl alloc::string::ToString for Uuid {
     }
 }
 
+/// Enum representing the three types of identifiers that a client can be identified with.
+#[derive(Debug, PartialEq)]
+pub enum ClientIdentifier {
+    /// The identifier of a local client TA that connects to the service
+    UUID(Uuid),
+
+    /// The identifier of a remote client TA that connects to the service by AuthMgr-BE
+    /// This introduction happens via an AIDL interface. Currently, AIDL types do not support u64.
+    /// Therefore, we use i64 here, although client sequence number cannot be negative.
+    ClientSeqNumber(i64),
+
+    /// The identifier of a remote pVM that connects to the AuthMgr-BE TA. This identifier type is
+    /// primarily used during the AuthMgr protocol. In the legitimate settings, only the AuthMgr-FE
+    /// TA in the remote pVM connects to the AuthMgr-BE TA.
+    VMID(u16),
+}
+
+impl ClientIdentifier {
+    // Type of the tag is u64 instead of u8 because arm64 normally requires 64 bit values to be
+    // 64 bit aligned, and we want to optimize for the 64 bit or multiple of 64 bit values (i.e.
+    // client_seq_num and uuid respectively) that come after the tag.
+    const UUID_TAG: u64 = 0;
+    const CLIENT_SEQ_NUM_TAG: u64 = 1;
+    const VMID_TAG: u64 = 2;
+
+    const TAG_LEN: usize = std::mem::size_of::<u64>();
+
+    const I64_LEN: usize = std::mem::size_of::<i64>();
+    const U16_LEN: usize = std::mem::size_of::<u16>();
+
+    fn get_data_as_bytes(&self) -> &[u8] {
+        match self {
+            ClientIdentifier::UUID(uuid) => uuid.as_bytes(),
+            ClientIdentifier::ClientSeqNumber(seq_num) => seq_num.as_bytes(),
+            ClientIdentifier::VMID(vm_id) => vm_id.as_bytes(),
+        }
+    }
+
+    fn with_tag_byte(tag: u64, data: &[u8]) -> Box<[u8]> {
+        let mut buf = Vec::<u8>::with_capacity(Self::TAG_LEN + data.len());
+        buf.extend_from_slice(tag.to_ne_bytes().as_slice());
+        buf.extend_from_slice(data);
+        buf.into_boxed_slice()
+    }
+
+    /// Get a pointer to the data contained in the enum variant with a tag identifying the enum
+    /// variant prepended, and the size of the data
+    pub fn as_tagged_bytes(&self) -> Box<[u8]> {
+        let data = self.get_data_as_bytes();
+        match self {
+            ClientIdentifier::UUID(_) => Self::with_tag_byte(Self::UUID_TAG, data),
+            ClientIdentifier::ClientSeqNumber(_) => {
+                Self::with_tag_byte(Self::CLIENT_SEQ_NUM_TAG, data)
+            }
+            ClientIdentifier::VMID(_) => Self::with_tag_byte(Self::VMID_TAG, data),
+        }
+    }
+
+    /// Re-construct the enum from bytes
+    pub fn from_tagged_bytes(tagged_data: &[u8]) -> Result<Self> {
+        // The length of the pointed data should be at least as long as the tag +
+        // the size of the smallest variant
+        let (tag_bytes, data) =
+            tagged_data.split_at_checked(Self::TAG_LEN).ok_or(TipcError::InvalidData)?;
+        let tag = u64::from_ne_bytes(tag_bytes.try_into().map_err(|_e| TipcError::InvalidData)?);
+        match (tag, data.len()) {
+            (Self::UUID_TAG, Uuid::UUID_BYTE_LEN) => {
+                Ok(ClientIdentifier::UUID(Uuid::try_from_bytes(data)?))
+            }
+            (Self::CLIENT_SEQ_NUM_TAG, Self::I64_LEN) => {
+                let client_seq_num =
+                    i64::read_from_bytes(data).map_err(|_e| TipcError::InvalidData)?;
+                Ok(ClientIdentifier::ClientSeqNumber(client_seq_num))
+            }
+            (Self::VMID_TAG, Self::U16_LEN) => {
+                let vm_id = u16::read_from_bytes(data).map_err(|_e| TipcError::InvalidData)?;
+                Ok(ClientIdentifier::VMID(vm_id))
+            }
+            (_, _) => Err(TipcError::InvalidData),
+        }
+    }
+}
+
 /// A service which handles IPC messages for a collection of ports.
 ///
 /// A service which implements this interface can register itself, along with a
@@ -488,6 +571,25 @@ pub trait UnbufferedService {
     fn max_message_length(&self) -> usize {
         0
     }
+
+    /// Called when a client connects, where the client can be identified by either of the
+    /// identifiers defined in the three variations of the `ClientIdentifier` enum.
+    ///
+    /// A default implementation is provided for backward compatibility. Any new service should
+    /// override this method and handle the three client variations.
+    fn on_new_connection(
+        &self,
+        port: &PortCfg,
+        handle: &Handle,
+        client_identifier: &ClientIdentifier,
+    ) -> Result<ConnectResult<Self::Connection>> {
+        match client_identifier {
+            ClientIdentifier::UUID(peer) => self.on_connect(port, handle, &peer),
+            _ => {
+                unimplemented!();
+            }
+        }
+    }
 }
 
 impl<T, U: Deserialize, V: Service<Connection = T, Message = U>> UnbufferedService for V {
@@ -1682,3 +1784,75 @@ mod uuid_tests {
         expect!(bad_uuid_from_str.is_err(), "shouldn't be able to parse string");
     }
 }
+
+#[cfg(test)]
+mod client_id_tests {
+    use super::{ClientIdentifier, Uuid};
+    use alloc::slice;
+    use std::ffi::c_void;
+    use test::assert_eq;
+
+    #[test]
+    fn client_id_len() {
+        let uuid_string = "4b4127e1-ca5c-4367-bdb5-05164005b7c4".to_string();
+        let uuid = Uuid::new_from_string(&uuid_string).unwrap();
+        let uuid_client_id = ClientIdentifier::UUID(uuid);
+        let client_seq_num_client_id = ClientIdentifier::ClientSeqNumber(2);
+        let vm_id_client_id = ClientIdentifier::VMID(5);
+        assert_eq!(Uuid::UUID_BYTE_LEN, std::mem::size_of::<Uuid>());
+        assert_eq!(
+            Uuid::UUID_BYTE_LEN,
+            uuid_client_id.as_tagged_bytes().len() - ClientIdentifier::TAG_LEN
+        );
+        assert_eq!(
+            ClientIdentifier::I64_LEN,
+            client_seq_num_client_id.as_tagged_bytes().len() - ClientIdentifier::TAG_LEN
+        );
+        assert_eq!(
+            ClientIdentifier::U16_LEN,
+            vm_id_client_id.as_tagged_bytes().len() - ClientIdentifier::TAG_LEN
+        );
+    }
+
+    #[test]
+    fn client_id_to_from_ptr() {
+        let uuid_string = "4b4127e1-ca5c-4367-bdb5-05164005b7c4".to_string();
+        let uuid = Uuid::new_from_string(&uuid_string).unwrap();
+        let uuid_client_id = ClientIdentifier::UUID(uuid.clone());
+        let client_seq_num_client_id = ClientIdentifier::ClientSeqNumber(2);
+        let vm_id_client_id = ClientIdentifier::VMID(5);
+
+        // Simulate the steps taken place when ClientIdentifier is used with
+        // rpc-binder C++ interface
+        let tagged_uuid = uuid_client_id.as_tagged_bytes();
+        let len = tagged_uuid.len();
+        let tagged_uuid_ptr = Box::into_raw(tagged_uuid);
+        let tagged_uuid_void_ptr: *const c_void = tagged_uuid_ptr.cast();
+        let tagged_uuid_ptr_back: *const u8 = tagged_uuid_void_ptr.cast();
+        let tagged_uuid_data = unsafe { slice::from_raw_parts(tagged_uuid_ptr_back, len) };
+        let uuid_client_id_expected =
+            ClientIdentifier::from_tagged_bytes(tagged_uuid_data).unwrap();
+        assert_eq!(uuid_client_id, uuid_client_id_expected);
+        let _ = unsafe { Box::from_raw(tagged_uuid_ptr) };
+
+        let tagged_csn = client_seq_num_client_id.as_tagged_bytes();
+        let len = tagged_csn.len();
+        let tagged_csn_ptr = Box::into_raw(tagged_csn);
+        let tagged_csn_void_ptr: *const c_void = tagged_csn_ptr.cast();
+        let tagged_csn_ptr_back: *const u8 = tagged_csn_void_ptr.cast();
+        let tagged_csn_data = unsafe { slice::from_raw_parts(tagged_csn_ptr_back, len) };
+        let csn_expected = ClientIdentifier::from_tagged_bytes(tagged_csn_data).unwrap();
+        assert_eq!(client_seq_num_client_id, csn_expected);
+        let _ = unsafe { Box::from_raw(tagged_csn_ptr) };
+
+        let tagged_vm_id = vm_id_client_id.as_tagged_bytes();
+        let len = tagged_vm_id.len();
+        let tagged_vm_id_ptr = Box::into_raw(tagged_vm_id);
+        let tagged_vm_id_void_ptr: *const c_void = tagged_vm_id_ptr.cast();
+        let tagged_vm_id_ptr_back: *const u8 = tagged_vm_id_void_ptr.cast();
+        let tagged_vm_id_data = unsafe { slice::from_raw_parts(tagged_vm_id_ptr_back, len) };
+        let vm_id_expected = ClientIdentifier::from_tagged_bytes(tagged_vm_id_data).unwrap();
+        assert_eq!(vm_id_client_id, vm_id_expected);
+        let _ = unsafe { Box::from_raw(tagged_vm_id_ptr) };
+    }
+}
diff --git a/lib/trusty-sys/rules.mk b/lib/trusty-sys/rules.mk
index d3c1208..1a9f1bd 100644
--- a/lib/trusty-sys/rules.mk
+++ b/lib/trusty-sys/rules.mk
@@ -25,6 +25,7 @@ MODULE_LIBRARY_EXPORTED_DEPS += \
 	trusty/user/base/lib/libcompiler_builtins-rust \
 	trusty/user/base/lib/libcore-rust \
 	trusty/user/base/lib/syscall-stubs \
+	$(call FIND_CRATE,zerocopy) \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
@@ -56,6 +57,9 @@ MODULE_BINDGEN_ALLOW_VARS := \
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
 # Derive eq and hash for uuid
-MODULE_BINDGEN_FLAGS += --with-derive-eq --with-derive-hash
+MODULE_BINDGEN_FLAGS := \
+	--with-derive-eq \
+	--with-derive-hash \
+	--with-derive-custom="uuid=zerocopy::IntoBytes, zerocopy::Immutable" \
 
 include make/library.mk
diff --git a/lib/trusty-sys/src/lib.rs b/lib/trusty-sys/src/lib.rs
index 1b352f5..e3bd93d 100644
--- a/lib/trusty-sys/src/lib.rs
+++ b/lib/trusty-sys/src/lib.rs
@@ -33,6 +33,7 @@ mod sys {
 
     impl uevent {
         pub const ALL_EVENTS: u32 = u32::MAX;
+        pub const NO_EVENTS: u32 = 0;
     }
 }
 
diff --git a/make/aidl.mk b/make/aidl.mk
index b88f023..679afe8 100644
--- a/make/aidl.mk
+++ b/make/aidl.mk
@@ -54,11 +54,15 @@ endif
 # of MODULE_AIDL_PACKAGE; support multiple packages
 GET_AIDL_PACKAGE_ROOT = $(if $(MODULE_AIDL_PACKAGE),$(firstword $(subst $(MODULE_AIDL_PACKAGE), ,$1)),$(dir $1))
 
-ifneq (,$(wildcard out/host/linux-x86/bin/aidl))
+ifneq (,$(ANDROID_BUILD_TOP))
 # Use the aidl tool from the build output if it exists
-AIDL_TOOL := out/host/linux-x86/bin/aidl
+AIDL_TOOL ?= $(wildcard $(ANDROID_BUILD_TOP)/out/host/linux-x86/bin/aidl)
 else
-AIDL_TOOL := prebuilts/build-tools/linux-x86/bin/aidl
+AIDL_TOOL ?= $(wildcard prebuilts/build-tools/linux-x86/bin/aidl)
+endif
+
+ifeq ($(AIDL_TOOL),)
+$(error No AIDL_TOOL. Please build the AIDL compiler or checkout the main-trusty branch)
 endif
 
 MODULE_AIDL_INCLUDES ?=
@@ -116,10 +120,11 @@ endif
 
 # Generate the top-level aidl_lib.rs for this module
 $(AIDL_ROOT_RS): AIDL_RUST_GLUE_TOOL := $(AIDL_RUST_GLUE_TOOL)
+$(AIDL_ROOT_RS): AIDL_SRCS := $(AIDL_SRCS)
 $(AIDL_ROOT_RS): MODULE_AIDL_RUST_DEPS := $(foreach crate,$(MODULE_AIDL_RUST_DEPS),-I $(crate))
-$(AIDL_ROOT_RS): $(AIDL_SRCS)
+$(AIDL_ROOT_RS): $(AIDL_SRCS) $(AIDL_RUST_GLUE_TOOL)
 	@echo generating $@ from AIDL Rust glue
-	$(NOECHO)$(AIDL_RUST_GLUE_TOOL) $(MODULE_AIDL_RUST_DEPS) $@ $(dir $@) $^
+	$(NOECHO)$(AIDL_RUST_GLUE_TOOL) $(MODULE_AIDL_RUST_DEPS) $@ $(dir $@) $(AIDL_SRCS)
 
 MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
@@ -145,5 +150,4 @@ MODULE_AIDL_RUST_DEPS :=
 AIDL_EXT :=
 AIDL_HEADER_DIR :=
 AIDL_SRCS :=
-AIDL_TOOL :=
 AIDL_ROOT_RS :=
diff --git a/make/bindgen.mk b/make/bindgen.mk
index cbc255b..d42254c 100644
--- a/make/bindgen.mk
+++ b/make/bindgen.mk
@@ -30,6 +30,7 @@
 # MODULE_BINDGEN_OUTPUT_ENV_VAR
 # MODULE_BINDGEN_SRC_HEADER
 # MODULE_BINDGEN_OUTPUT_FILE_NAME
+# MODULE_BINDGEN_WRAP_STATIC_FNS
 
 ifeq ($(strip $(MODULE_BINDGEN_SRC_HEADER)),)
 $(error $(MODULE): MODULE_BINDGEN_SRC_HEADER is required to use bindgen.mk)
@@ -54,6 +55,63 @@ ifneq ($(strip $(MODULE_BINDGEN_CTYPES_PREFIX)),)
 MODULE_BINDGEN_FLAGS += --ctypes-prefix $(MODULE_BINDGEN_CTYPES_PREFIX)
 endif
 
+ifeq ($(call TOBOOL,$(MODULE_BINDGEN_WRAP_STATIC_FNS)),true)
+BINDGEN_STATIC_FNS_SRC := $(addsuffix .static_fns.c,$(MODULE_BINDGEN_OUTPUT_FILE))
+BINDGEN_STATIC_FNS_OBJ := $(addsuffix .o,$(BINDGEN_STATIC_FNS_SRC))
+BINDGEN_STATIC_FNS_DEP := $(addsuffix .d,$(BINDGEN_STATIC_FNS_SRC))
+
+MODULE_BINDGEN_FLAGS += \
+	--experimental \
+	--wrap-static-fns \
+	--wrap-static-fns-path=$(BINDGEN_STATIC_FNS_SRC) \
+
+# The re-exported wrappers trigger dead code errors
+MODULE_RUSTFLAGS += -A dead-code
+
+ifeq ($(call TOBOOL,$(TRUSTY_USERSPACE)),true)
+$(BINDGEN_STATIC_FNS_OBJ): GLOBAL_OPTFLAGS := $(GLOBAL_SHARED_OPTFLAGS) $(GLOBAL_USER_OPTFLAGS) $(GLOBAL_USER_IN_TREE_OPTFLAGS) $(ARCH_OPTFLAGS)
+$(BINDGEN_STATIC_FNS_OBJ): GLOBAL_COMPILEFLAGS := $(GLOBAL_SHARED_COMPILEFLAGS) $(GLOBAL_USER_COMPILEFLAGS) $(GLOBAL_USER_IN_TREE_COMPILEFLAGS)
+$(BINDGEN_STATIC_FNS_OBJ): GLOBAL_CFLAGS := $(GLOBAL_SHARED_CFLAGS) $(GLOBAL_USER_CFLAGS) $(GLOBAL_USER_IN_TREE_CFLAGS)
+$(BINDGEN_STATIC_FNS_OBJ): GLOBAL_INCLUDES := $(addprefix -I,$(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES))
+
+# Add some extra user space definitions that are needed for the musl headers
+$(BINDGEN_STATIC_FNS_OBJ): GLOBAL_COMPILEFLAGS += -DTRUSTY_USERSPACE=1 -U_ALL_SOURCE -D_XOPEN_SOURCE=700
+endif
+
+-include $(BINDGEN_STATIC_FNS_DEP)
+
+# Save the variables read or written by compile.mk
+BINDGEN_SAVED_MODULE_INCLUDES := $(MODULE_INCLUDES)
+BINDGEN_SAVED_MODULE_OBJS := $(MODULE_OBJS)
+BINDGEN_SAVED_MODULE_SRCS := $(MODULE_SRCS)
+BINDGEN_SAVED_MODULE_SRCS_FIRST := $(MODULE_SRCS_FIRST)
+MODULE_SRCS := $(BINDGEN_STATIC_FNS_SRC)
+MODULE_SRCS_FIRST :=
+
+# Explicitly prepend the -I prefix to MODULE_INCLUDES just like make/module.mk
+MODULE_INCLUDES := $(addprefix -I,$(MODULE_INCLUDES))
+# We add $TRUSTY_TOP to the include directories because the .static_fns.c file
+# includes $MODULE_BINDGEN_SRC_HEADER as is (which could be a relative path)
+MODULE_INCLUDES += -I$(TRUSTY_TOP)
+
+include make/compile.mk
+ifneq ($(realpath $(MODULE_OBJS)),$(realpath $(BINDGEN_STATIC_FNS_OBJ)))
+$(error Internal bindgen build error: mismatch between MODULE_OBJS="$(MODULE_OBJS)" and "$(BINDGEN_STATIC_FNS_OBJ)")
+endif
+
+MODULE_INCLUDES := $(BINDGEN_SAVED_MODULE_INCLUDES)
+MODULE_OBJS := $(BINDGEN_SAVED_MODULE_OBJS)
+MODULE_SRCS := $(BINDGEN_SAVED_MODULE_SRCS)
+MODULE_SRCS_FIRST := $(BINDGEN_SAVED_MODULE_SRCS_FIRST)
+
+GENERATED += \
+	$(BINDGEN_STATIC_FNS_SRC) \
+	$(BINDGEN_STATIC_FNS_OBJ) \
+	$(BINDGEN_STATIC_FNS_DEP) \
+
+MODULE_EXPORT_EXTRA_OBJECTS += $(BINDGEN_STATIC_FNS_OBJ)
+endif
+
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-var ,$(MODULE_BINDGEN_ALLOW_VARS))
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-type ,$(MODULE_BINDGEN_ALLOW_TYPES))
 MODULE_BINDGEN_FLAGS += $(addprefix --blocklist-type ,$(MODULE_BINDGEN_BLOCK_TYPES))
@@ -84,21 +142,27 @@ $(MODULE_BINDGEN_CONFIG): configheader
 	@$(call INFO_DONE,$(MODULE),generating bindgen config header, $@)
 	@$(call MAKECONFIGHEADER,$@,MODULE_BINDGEN_DEFINES)
 
-$(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN := $(BINDGEN)
-$(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN_MODULE_COMPILEFLAGS := $(BINDGEN_MODULE_COMPILEFLAGS)
-$(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN_MODULE_INCLUDES := $(addprefix -I,$(MODULE_INCLUDES))
-$(MODULE_BINDGEN_OUTPUT_FILE): ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
-$(MODULE_BINDGEN_OUTPUT_FILE): DEFINES := $(addprefix -D,$(MODULE_DEFINES))
-$(MODULE_BINDGEN_OUTPUT_FILE): MODULE_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
-$(MODULE_BINDGEN_OUTPUT_FILE): RUSTFMT_PATH := $(RUST_BINDIR)/rustfmt
-$(MODULE_BINDGEN_OUTPUT_FILE): $(MODULE_BINDGEN_SRC_HEADER) $(BINDGEN) $(MODULE_SRCDEPS) $(CONFIGHEADER) $(MODULE_BINDGEN_CONFIG)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): BINDGEN := $(BINDGEN)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): BINDGEN_MODULE_COMPILEFLAGS := $(BINDGEN_MODULE_COMPILEFLAGS)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): BINDGEN_MODULE_INCLUDES := $(addprefix -I,$(MODULE_INCLUDES))
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): DEFINES := $(addprefix -D,$(MODULE_DEFINES))
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): MODULE_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): RUSTFMT_PATH := $(RUST_BINDIR)/rustfmt
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC): MODULE_BINDGEN_OUTPUT_FILE := $(MODULE_BINDGEN_OUTPUT_FILE)
+$(MODULE_BINDGEN_OUTPUT_FILE) $(BINDGEN_STATIC_FNS_SRC) &: $(MODULE_BINDGEN_SRC_HEADER) $(BINDGEN) $(MODULE_SRCDEPS) $(CONFIGHEADER) $(MODULE_BINDGEN_CONFIG)
 	@$(MKDIR)
 	$(NOECHO)
 	CLANG_PATH=$(BINDGEN_CLANG_PATH) \
 	LIBCLANG_PATH=$(BINDGEN_LIBCLANG_PATH) \
 	RUSTFMT=$(RUSTFMT_PATH) \
-	$(BINDGEN) $< -o $@.tmp $(MODULE_BINDGEN_FLAGS) --depfile $@.d -- $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(BINDGEN_MODULE_COMPILEFLAGS) $(BINDGEN_MODULE_INCLUDES) $(GLOBAL_INCLUDES) $(DEFINES)
-	@$(call TESTANDREPLACEFILE,$@.tmp,$@)
+	$(BINDGEN) $< -o $(MODULE_BINDGEN_OUTPUT_FILE) $(MODULE_BINDGEN_FLAGS) --depfile $(MODULE_BINDGEN_OUTPUT_FILE).d -- $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(BINDGEN_MODULE_COMPILEFLAGS) $(BINDGEN_MODULE_INCLUDES) $(GLOBAL_INCLUDES) $(DEFINES) \
+	|| ( \
+	    err=$$?; \
+	    echo "Bindgen failed with exit code $$err" >&2; \
+	    rm -f $@; \
+	    exit $$err \
+	   )
 
 MODULE_SRCDEPS += $(MODULE_BINDGEN_OUTPUT_FILE)
 
@@ -125,8 +189,16 @@ MODULE_BINDGEN_DEFINES :=
 MODULE_BINDGEN_OUTPUT_ENV_VAR :=
 MODULE_BINDGEN_OUTPUT_FILE_NAME :=
 MODULE_BINDGEN_SRC_HEADER :=
+MODULE_BINDGEN_WRAP_STATIC_FNS :=
 
 BINDGEN :=
 MODULE_BINDGEN_FLAGS :=
 BINDGEN_MODULE_COMPILEFLAGS :=
 MODULE_BINDGEN_OUTPUT_FILE :=
+BINDGEN_SAVED_MODULE_INCLUDES :=
+BINDGEN_SAVED_MODULE_OBJS :=
+BINDGEN_SAVED_MODULE_SRCS :=
+BINDGEN_SAVED_MODULE_SRCS_FIRST :=
+BINDGEN_STATIC_FNS_DEP :=
+BINDGEN_STATIC_FNS_OBJ :=
+BINDGEN_STATIC_FNS_SRC :=
diff --git a/make/protoc_plugin.mk b/make/protoc_plugin.mk
index 98bda65..4d1b74f 100644
--- a/make/protoc_plugin.mk
+++ b/make/protoc_plugin.mk
@@ -48,7 +48,7 @@ $(MODULE_SRCS): MODULE_PROTOC_PLUGIN := $(MODULE_PROTOC_PLUGIN)
 $(MODULE_SRCS): MODULE_PROTOC_PLUGIN_FLAGS := $(MODULE_PROTOC_PLUGIN_FLAGS)
 $(MODULE_SRCS): MODULE_PROTO_PACKAGE := $(MODULE_PROTO_PACKAGE)
 $(MODULE_SRCS): MODULE_PROTO_OUT_DIR := $(MODULE_PROTO_OUT_DIR)
-$(MODULE_SRCS): $(BUILDDIR)/%.c: %.proto $(MODULE_PROTOC_PLUGIN)
+$(MODULE_SRCS): $(BUILDDIR)/%.c: %.proto $(MODULE_PROTOC_PLUGIN) $(PROTOC_TOOL)
 	@$(MKDIR)
 	@echo generating $@ from PROTO
 	$(NOECHO)$(PROTOC_TOOL) \
diff --git a/make/userspace_recurse.mk b/make/userspace_recurse.mk
index f7f9574..33fec16 100644
--- a/make/userspace_recurse.mk
+++ b/make/userspace_recurse.mk
@@ -152,7 +152,6 @@ SAVED_$(MODULE)_MODULE_AIDL_RUST_DEPS := $(MODULE_AIDL_RUST_DEPS)
 SAVED_$(MODULE)_AIDL_EXT := $(AIDL_EXT)
 SAVED_$(MODULE)_AIDL_HEADER_DIR := $(AIDL_HEADER_DIR)
 SAVED_$(MODULE)_AIDL_SRCS := $(AIDL_SRCS)
-SAVED_$(MODULE)_AIDL_TOOL := $(AIDL_TOOL)
 SAVED_$(MODULE)_AIDL_ROOT_RS := $(AIDL_ROOT_RS)
 
 SAVED_$(MODULE)_DEPENDENCY_MODULE := $(DEPENDENCY_MODULE)
@@ -254,7 +253,6 @@ MODULE_AIDL_RUST_DEPS :=
 AIDL_EXT :=
 AIDL_HEADER_DIR :=
 AIDL_SRCS :=
-AIDL_TOOL :=
 AIDL_ROOT_RS :=
 
 ALLMODULES :=
@@ -364,7 +362,6 @@ MODULE_AIDL_RUST_DEPS := $(SAVED_$(MODULE)_MODULE_AIDL_RUST_DEPS)
 AIDL_EXT := $(SAVED_$(MODULE)_AIDL_EXT)
 AIDL_HEADER_DIR := $(SAVED_$(MODULE)_AIDL_HEADER_DIR)
 AIDL_SRCS := $(SAVED_$(MODULE)_AIDL_SRCS)
-AIDL_TOOL := $(SAVED_$(MODULE)_AIDL_TOOL)
 AIDL_ROOT_RS := $(SAVED_$(MODULE)_AIDL_ROOT_RS)
 
 DEPENDENCY_MODULE := $(SAVED_$(MODULE)_DEPENDENCY_MODULE)
```

