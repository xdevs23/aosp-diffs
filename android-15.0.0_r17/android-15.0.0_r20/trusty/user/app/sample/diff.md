```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..537a395
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_sample",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/hwcryptohal/aidl/rust/rules.mk b/hwcryptohal/aidl/rust/rules.mk
index e164bd1..a6f9ab7 100644
--- a/hwcryptohal/aidl/rust/rules.mk
+++ b/hwcryptohal/aidl/rust/rules.mk
@@ -17,9 +17,9 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-HWCRYPTO_AIDL_DIR = hardware/interfaces/staging/security/see/hwcrypto/aidl
+HWCRYPTO_AIDL_DIR = hardware/interfaces/security/see/hwcrypto/aidl
 
-MODULE_CRATE_NAME := android_hardware_security_see
+MODULE_CRATE_NAME := android_hardware_security_see_hwcrypto
 
 MODULE_AIDL_LANGUAGE := rust
 
@@ -28,6 +28,11 @@ MODULE_AIDL_PACKAGE := android/hardware/security/see/hwcrypto
 MODULE_AIDL_INCLUDES := \
 	-I $(HWCRYPTO_AIDL_DIR) \
 
+MODULE_AIDL_FLAGS := \
+	--stability=vintf \
+
+MODULE_AIDL_FLAGS += --version=1
+
 MODULE_AIDLS := \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperation.aidl                        \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperationErrorAdditionalInfo.aidl     \
@@ -47,13 +52,17 @@ MODULE_AIDLS := \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/CipherModeParameters.aidl             \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/ExplicitKeyMaterial.aidl              \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HalErrorCode.aidl                     \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HmacOperationParameters.aidl          \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HmacKey.aidl          \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyLifetime.aidl                      \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyPermissions.aidl                   \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyType.aidl                          \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyUse.aidl                           \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/MemoryBufferReference.aidl            \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OpaqueKeyToken.aidl                   \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OperationData.aidl                    \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OperationType.aidl                    \
+    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/ProtectionId.aidl                     \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricAuthCryptoParameters.aidl    \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricAuthOperationParameters.aidl \
     $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricCryptoParameters.aidl        \
diff --git a/hwcryptohal/common/cose.rs b/hwcryptohal/common/cose.rs
index 3dc51d9..ef49331 100644
--- a/hwcryptohal/common/cose.rs
+++ b/hwcryptohal/common/cose.rs
@@ -40,9 +40,13 @@ macro_rules! aidl_enum_wrapper {
             }
         }
 
-        impl From<$aidl_name> for $wrapper_name {
-            fn from(value: $aidl_name) -> Self {
-                $wrapper_name(value)
+        impl TryFrom<$aidl_name> for $wrapper_name {
+            type Error = $crate::err::HwCryptoError;
+
+            fn try_from(value: $aidl_name) -> Result<Self, Self::Error> {
+                let val = $wrapper_name(value);
+                val.check_value()?;
+                Ok(val)
             }
         }
 
@@ -72,6 +76,15 @@ macro_rules! aidl_enum_wrapper {
                 (value.0.0 as u64).into()
             }
         }
+
+        impl $wrapper_name {
+            fn check_value(&self) -> Result<(), $crate::err::HwCryptoError>  {
+                // `TryInto` from a u64 will return an error if the enum value
+                // is not one of the declared ones in `fields`
+                let _: $wrapper_name =  (self.0.0 as u64).try_into()?;
+                Ok(())
+            }
+        }
     }
 }
 
diff --git a/hwcryptohal/common/err.rs b/hwcryptohal/common/err.rs
index 5e022f2..279490a 100644
--- a/hwcryptohal/common/err.rs
+++ b/hwcryptohal/common/err.rs
@@ -17,10 +17,11 @@
 //! HwCrypto error handling code and related structures
 
 use alloc::{collections::TryReserveError, ffi::CString};
-pub use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode;
-use android_hardware_security_see::binder;
+pub use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode;
+use android_hardware_security_see_hwcrypto::binder;
 use core::array::TryFromSliceError;
 use coset::CoseError;
+use std::sync::PoisonError;
 use tipc::TipcError;
 use vm_memory::VolatileMemoryError;
 
@@ -122,3 +123,12 @@ impl From<HwCryptoError> for binder::Status {
         }
     }
 }
+
+impl<T> From<PoisonError<T>> for HwCryptoError {
+    fn from(_: PoisonError<T>) -> Self {
+        hwcrypto_err!(
+            GENERIC_ERROR,
+            "found PoisonError which shouldn't happen, we are single threaded"
+        )
+    }
+}
diff --git a/hwcryptohal/common/policy.rs b/hwcryptohal/common/policy.rs
index b49e538..8692972 100644
--- a/hwcryptohal/common/policy.rs
+++ b/hwcryptohal/common/policy.rs
@@ -17,10 +17,10 @@
 //! KeyPolicy serialization facilities
 
 use alloc::collections::btree_set::BTreeSet;
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
     KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
 };
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
 use ciborium::Value;
 use coset::{AsCborValue, CborSerializable, CoseError};
 
diff --git a/hwcryptohal/server/cmd_processing.rs b/hwcryptohal/server/cmd_processing.rs
index 584c579..93c73e1 100644
--- a/hwcryptohal/server/cmd_processing.rs
+++ b/hwcryptohal/server/cmd_processing.rs
@@ -16,15 +16,16 @@
 
 //! Module providing an implementation of a cryptographic command processor.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
     MemoryBufferReference::MemoryBufferReference, OperationData::OperationData,
 };
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
     CryptoOperation::CryptoOperation,
     MemoryBufferParameter::{
         MemoryBuffer::MemoryBuffer as MemoryBufferAidl, MemoryBufferParameter,
     },
     OperationParameters::OperationParameters,
+    PatternParameters::PatternParameters,
 };
 use core::ffi::c_void;
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
@@ -99,22 +100,102 @@ enum CmdProcessorState {
     Destroyed,
 }
 
-// `DataToProcess`is used to abstract away if the cryptographic operations are working on memory
-// buffers or vectors.
-pub(crate) enum DataToProcess<'a> {
+pub(crate) enum DataToProcessBuffer<'a> {
     VolatileSlice(VolatileSlice<'a>),
     Slice(&'a mut [u8]),
 }
 
+// `DataToProcess`is used to abstract away if the cryptographic operations are working on memory
+// buffers or vectors.
+pub(crate) struct DataToProcess<'a> {
+    start_index: usize,
+    buffer: DataToProcessBuffer<'a>,
+}
+
 impl<'a> DataToProcess<'a> {
+    pub(crate) fn new_from_volatile_slice(buffer: VolatileSlice<'a>) -> Self {
+        Self { buffer: DataToProcessBuffer::VolatileSlice(buffer), start_index: 0 }
+    }
+
+    pub(crate) fn new_from_slice(buffer: &'a mut [u8]) -> Self {
+        Self { buffer: DataToProcessBuffer::Slice(buffer), start_index: 0 }
+    }
+
     pub(crate) fn len(&self) -> usize {
-        match self {
-            Self::VolatileSlice(vs) => vs.len(),
-            Self::Slice(s) => s.len(),
+        match &self.buffer {
+            DataToProcessBuffer::VolatileSlice(vs) => vs.len() - self.start_index,
+            DataToProcessBuffer::Slice(s) => s.len() - self.start_index,
+        }
+    }
+
+    pub(crate) fn is_non_volatile_slice_backed(&self) -> bool {
+        match &self.buffer {
+            DataToProcessBuffer::VolatileSlice(_) => true,
+            DataToProcessBuffer::Slice(_) => false,
+        }
+    }
+
+    /// If self is backed by a non-volatile buffer, returns a slice of the specified
+    /// length, incrementing the current position. Return an error if self is volatile (use
+    /// `read_into_slice()` instead to make a copy of the data) or if the requested length exceeds
+    /// the slice capacity.
+    pub(crate) fn try_slice(&mut self, len: usize) -> Result<&[u8], HwCryptoError> {
+        if len > self.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "end {} out of slice bounds for slice size {}",
+                len,
+                self.len()
+            ));
+        }
+
+        if let DataToProcess { buffer: DataToProcessBuffer::Slice(slice), start_index } = self {
+            let slice_start = *start_index;
+            *start_index += len;
+            Ok(&slice[slice_start..slice_start + len])
+        } else {
+            Err(hwcrypto_err!(BAD_PARAMETER, "DataToProcess is backed by a VolatileSlice",))
         }
     }
 
-    pub(crate) fn copy_slice(&mut self, from: &[u8]) -> Result<(), HwCryptoError> {
+    pub(crate) fn read_into_slice(
+        &mut self,
+        to: &mut [u8],
+        len: Option<usize>,
+    ) -> Result<(), HwCryptoError> {
+        let len = len.unwrap_or(to.len());
+
+        if len > to.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "end {} out of slice bounds for slice size {}",
+                len,
+                to.len()
+            ));
+        }
+
+        if len > self.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "end {} out of slice bounds for slice size {}",
+                len,
+                self.len()
+            ));
+        }
+
+        match &self.buffer {
+            DataToProcessBuffer::Slice(from) => {
+                to[..len].copy_from_slice(&from[self.start_index..self.start_index + len])
+            }
+            DataToProcessBuffer::VolatileSlice(from) => {
+                from.read_slice(&mut to[..len], self.start_index)?
+            }
+        };
+        self.start_index += len;
+        Ok(())
+    }
+
+    pub(crate) fn append_slice(&mut self, from: &[u8]) -> Result<(), HwCryptoError> {
         if self.len() < from.len() {
             return Err(hwcrypto_err!(
                 BAD_PARAMETER,
@@ -123,34 +204,62 @@ impl<'a> DataToProcess<'a> {
                 from.len()
             ));
         }
-        match self {
-            Self::VolatileSlice(to) => to.write_slice(from, 0)?,
-            Self::Slice(to) => to[..from.len()].copy_from_slice(from),
+        match &mut self.buffer {
+            DataToProcessBuffer::VolatileSlice(to) => to.write_slice(from, self.start_index)?,
+            DataToProcessBuffer::Slice(to) => {
+                to[self.start_index..(self.start_index + from.len())].copy_from_slice(from)
+            }
         }
+        self.start_index += from.len();
         Ok(())
     }
 
-    pub(crate) fn copy_from_slice(
+    pub(crate) fn read_from_slice(
         &mut self,
-        slice: &DataToProcess<'a>,
+        slice: &mut DataToProcess<'a>,
+        len: Option<usize>,
     ) -> Result<(), HwCryptoError> {
-        if self.len() < slice.len() {
+        let read_len = len.unwrap_or(slice.len());
+
+        if read_len > slice.len() {
             return Err(hwcrypto_err!(
                 BAD_PARAMETER,
-                "slice size: {} is less than the slice provided {}",
-                self.len(),
+                "len {} was greater than slice len {}",
+                read_len,
                 slice.len()
             ));
         }
 
-        match (slice, self) {
-            (Self::Slice(from), Self::VolatileSlice(to)) => to.write_slice(from, 0)?,
-            (Self::VolatileSlice(from), Self::VolatileSlice(to)) => {
-                from.copy_to_volatile_slice(to.get_slice(0, to.len())?)
+        if self.len() < read_len {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "slice size: {} is less than the slice provided size {}",
+                self.len(),
+                read_len
+            ));
+        }
+
+        let from_start_index = slice.start_index;
+        let to_start_index = self.start_index;
+
+        match (&slice.buffer, &mut self.buffer) {
+            (DataToProcessBuffer::Slice(from), DataToProcessBuffer::VolatileSlice(to)) => to
+                .write_slice(
+                    &from[from_start_index..from_start_index + read_len],
+                    to_start_index,
+                )?,
+            (DataToProcessBuffer::VolatileSlice(from), DataToProcessBuffer::VolatileSlice(to)) => {
+                from.get_slice(from_start_index, read_len)?
+                    .copy_to_volatile_slice(to.get_slice(to_start_index, read_len)?)
             }
-            (Self::Slice(from), Self::Slice(to)) => to[..from.len()].copy_from_slice(from),
-            (Self::VolatileSlice(from), Self::Slice(to)) => from.read_slice(to, 0)?,
+            (DataToProcessBuffer::Slice(from), DataToProcessBuffer::Slice(to)) => to
+                [to_start_index..to_start_index + read_len]
+                .copy_from_slice(&from[from_start_index..from_start_index + read_len]),
+            (DataToProcessBuffer::VolatileSlice(from), DataToProcessBuffer::Slice(to)) => from
+                .read_slice(&mut to[to_start_index..to_start_index + read_len], from_start_index)?,
         }
+        self.start_index += read_len;
+        slice.start_index += read_len;
         Ok(())
     }
 
@@ -165,7 +274,10 @@ impl<'a> DataToProcess<'a> {
         // Addition should be safe because try_reserve didn't fail
         let new_len = original_len + buffer_size;
         vector.resize_with(new_len, Default::default);
-        Ok(Self::Slice(&mut vector[original_len..new_len]))
+        Ok(DataToProcess {
+            buffer: DataToProcessBuffer::Slice(&mut vector[original_len..new_len]),
+            start_index: 0,
+        })
     }
 }
 
@@ -310,7 +422,7 @@ impl MemoryBuffer {
         size: usize,
     ) -> Result<DataToProcess<'a>, HwCryptoError> {
         let mem_buffer = self.get_memory_slice()?;
-        Ok(DataToProcess::VolatileSlice(mem_buffer.subslice(start, size)?))
+        Ok(DataToProcess::new_from_volatile_slice(mem_buffer.subslice(start, size)?))
     }
 }
 
@@ -466,6 +578,14 @@ impl CmdProcessorContext {
         self.operation_step(Some(input_parameters), current_output_ref, false, None)
     }
 
+    fn set_pattern(&mut self, step_parameter: &mut PatternParameters) -> Result<(), HwCryptoError> {
+        let crypto_operation = self
+            .current_crypto_operation
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "crypto operation has not been set yet"))?;
+        crypto_operation.set_operation_pattern(step_parameter)
+    }
+
     fn operation_step(
         &mut self,
         input_parameters: Option<&mut OperationData>,
@@ -482,7 +602,7 @@ impl CmdProcessorContext {
             ))?;
         }
         // Creating a `DataToProcess` variable to abstract away where the input is located
-        let input = match input_parameters {
+        let mut input = match input_parameters {
             Some(OperationData::MemoryBufferReference(buffer_reference)) => Some({
                 let buffer_reference =
                     MemoryBufferReferenceWithType::Input((*buffer_reference).into());
@@ -493,7 +613,9 @@ impl CmdProcessorContext {
                     .ok_or(hwcrypto_err!(BAD_PARAMETER, "input buffer not set yet"))?
                     .get_subslice_as_data_to_process(input_start, input_size)?
             }),
-            Some(OperationData::DataBuffer(input)) => Some(DataToProcess::Slice(&mut input[..])),
+            Some(OperationData::DataBuffer(input)) => {
+                Some(DataToProcess::new_from_slice(&mut input[..]))
+            }
             None => None,
         };
         if let Some(ref input) = input {
@@ -523,9 +645,10 @@ impl CmdProcessorContext {
                 // We are saving data into a vector, as long as we can resize the vector we can fit
                 // the result
                 let original_size = output_vec.len();
-                let output_buff =
+                let mut output_buff =
                     DataToProcess::allocate_buffer_end_vector(*output_vec, req_output_size)?;
-                let added_bytes = crypto_operation.operation(input, output_buff, is_finish)?;
+                let added_bytes =
+                    crypto_operation.operation(input.as_mut(), &mut output_buff, is_finish)?;
                 output_vec.truncate(original_size + added_bytes);
             }
             OutputData::MemoryReference(output_buff_ref, remaining_size) => {
@@ -544,12 +667,13 @@ impl CmdProcessorContext {
                 // _output_start                output_start_offset                    output_stop
                 //
                 let output_start_offset = output_stop - *remaining_size;
-                let output_slice = self
+                let mut output_slice = self
                     .current_output_memory_buffer
                     .as_mut()
                     .ok_or(hwcrypto_err!(BAD_PARAMETER, "output buffer not set yet"))?
                     .get_subslice_as_data_to_process(output_start_offset, req_output_size)?;
-                let req_output_size = crypto_operation.operation(input, output_slice, is_finish)?;
+                let req_output_size =
+                    crypto_operation.operation(input.as_mut(), &mut output_slice, is_finish)?;
                 *remaining_size = *remaining_size - req_output_size;
             }
         }
@@ -657,8 +781,8 @@ impl CmdProcessorContext {
                         self.current_state = CmdProcessorState::InitialState;
                         self.finish_step(&mut curr_output)?;
                     }
-                    CryptoOperation::SetPattern(_) => {
-                        unimplemented!("SetPattern not implemented yet")
+                    CryptoOperation::SetPattern(step_data) => {
+                        self.set_pattern(step_data)?;
                     }
                     CryptoOperation::DataInput(step_data) => {
                         self.input_step(step_data, &mut curr_output)?;
@@ -690,7 +814,7 @@ impl CmdProcessorContext {
 mod tests {
     use super::*;
     use crate::opaque_key::OpaqueKey;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters, HalErrorCode,
             KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
@@ -707,7 +831,12 @@ mod tests {
     use std::alloc::{alloc_zeroed, dealloc, Layout};
     use std::os::fd::{FromRawFd, OwnedFd};
     use test::{expect, expect_eq};
+    use tipc::Uuid;
 
+    fn connection_info() -> Uuid {
+        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
+        Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap()
+    }
     /// Structure only intended to use on unit tests. It will allocate a single memory page and
     /// create a memref to it.
     struct TestPageAllocator {
@@ -1047,7 +1176,7 @@ mod tests {
             keyType: KeyType::AES_128_CBC_NO_PADDING,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy);
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info());
         expect!(key.is_ok(), "couldn't generate key");
         let key = key.unwrap();
         let mode = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -1289,7 +1418,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
             nonce: nonce.into(),
@@ -1340,4 +1470,536 @@ mod tests {
             String::from_utf8(decrypted_data).expect("couldn't decode received message");
         expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
     }
+
+    #[test]
+    fn data_to_process_slice_based() {
+        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
+
+        let mut slice = DataToProcess::new_from_slice(data.as_mut());
+
+        let mut read_data = [0u8; 2];
+        slice.read_into_slice(&mut read_data, None).expect("couldn't read data");
+
+        expect_eq!(read_data.len(), 2, "advanced data has wrong size");
+        expect_eq!(slice.len(), 8, "advanced data has wrong size");
+        expect_eq!(read_data, [0, 1], "read data had wrong values");
+
+        slice.append_slice(&read_data).expect("couldn't copy data");
+        slice.start_index = 0;
+
+        let mut read_data = [0u8; 10];
+        slice.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [0, 1, 0, 1, 4, 5, 6, 7, 8, 9], "read data had wrong values");
+    }
+
+    #[test]
+    fn copy_slice() {
+        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
+        let mut output_page_2 = TestPageAllocator::new().expect("couldn't allocate test page");
+        output_page_2.copy_values(0, &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29]).unwrap();
+
+        let total_buffer_size = TestPageAllocator::get_allocation_size();
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+        let mut memory_buffer =
+            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");
+
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page_2.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+        let mut memory_buffer_2 =
+            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");
+
+        let mut data_to_process = DataToProcess::new_from_volatile_slice(
+            memory_buffer.get_memory_slice().expect("couldn't get memory slice"),
+        );
+
+        let mut data_to_process_2 = DataToProcess::new_from_volatile_slice(
+            memory_buffer_2.get_memory_slice().expect("couldn't get memory slice"),
+        );
+
+        expect_eq!(
+            data_to_process.len(),
+            data_to_process_2.len(),
+            "data to process len should match at this point"
+        );
+        let original_size = data_to_process.len();
+
+        expect_eq!(
+            data_to_process.start_index,
+            data_to_process_2.start_index,
+            "start index of data to process should match"
+        );
+        expect_eq!(data_to_process.start_index, 0, "start index of data to process should be 0");
+
+        data_to_process.read_from_slice(&mut data_to_process_2, Some(3)).expect("couldn't copy");
+        expect_eq!(
+            data_to_process.len(),
+            original_size - 3,
+            "data to process len should have decreased by 3"
+        );
+        expect_eq!(
+            data_to_process_2.len(),
+            original_size - 3,
+            "data to process len should have decreased by 3"
+        );
+        expect_eq!(data_to_process.start_index, 3, "start index of data to process should be 3");
+        expect_eq!(data_to_process_2.start_index, 3, "start index of data to process should be 3");
+
+        let mut read_data = [0u8; 3];
+        data_to_process.start_index = 0;
+        data_to_process.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [20, 21, 22], "wrong data copied");
+
+        data_to_process.read_from_slice(&mut data_to_process_2, Some(0)).expect("couldn't copy");
+        expect_eq!(
+            data_to_process.len(),
+            original_size - 3,
+            "data to process len should have decreased by 3"
+        );
+        expect_eq!(
+            data_to_process_2.len(),
+            original_size - 3,
+            "data to process len should have decreased by 3"
+        );
+        expect_eq!(data_to_process.start_index, 3, "start index of data to process should be 3");
+        expect_eq!(data_to_process_2.start_index, 3, "start index of data to process should be 3");
+
+        let mut read_data = [0u8; 3];
+        data_to_process.start_index = 0;
+        data_to_process.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [20, 21, 22], "wrong data copied");
+
+        data_to_process.read_from_slice(&mut data_to_process_2, Some(4)).expect("couldn't copy");
+        expect_eq!(
+            data_to_process.len(),
+            original_size - 7,
+            "data to process len should have decreased by 4"
+        );
+        expect_eq!(
+            data_to_process_2.len(),
+            original_size - 7,
+            "data to process len should have decreased by 4"
+        );
+        expect_eq!(data_to_process.start_index, 7, "start index of data to process should be 7");
+        expect_eq!(data_to_process_2.start_index, 7, "start index of data to process should be 7");
+
+        let mut read_data = [0u8; 7];
+        data_to_process.start_index = 0;
+        data_to_process.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [20, 21, 22, 23, 24, 25, 26], "wrong data copied");
+
+        let mut data_process_vec = vec![0u8; 2];
+        let mut data_process_slice = DataToProcess::new_from_slice(data_process_vec.as_mut_slice());
+
+        expect_eq!(data_process_slice.len(), 2, "data to process len should be 2");
+        expect_eq!(data_process_slice.start_index, 0, "start index of data to process should be 0");
+
+        data_process_slice.read_from_slice(&mut data_to_process_2, Some(2)).expect("couldn't copy");
+
+        expect_eq!(data_process_slice.len(), 0, "data to process len ahould be 0");
+        expect_eq!(data_process_slice.start_index, 2, "start index of data to process should be 2");
+        expect_eq!(
+            data_to_process_2.len(),
+            original_size - 9,
+            "data to process len should have decreased by 2"
+        );
+        expect_eq!(data_to_process_2.start_index, 9, "start index of data to process should be 9");
+
+        let mut read_data = [0u8; 2];
+        data_process_slice.start_index = 0;
+        data_process_slice.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [27, 28], "wrong data copied");
+        data_process_slice.start_index = 0;
+
+        data_to_process.read_from_slice(&mut data_process_slice, None).expect("couldn't copy");
+        expect_eq!(
+            data_to_process.len(),
+            original_size - 9,
+            "data to process len should have decreased by 2"
+        );
+        expect_eq!(data_to_process.start_index, 9, "start index of data to process should be 9");
+
+        let mut read_data = [0u8; 9];
+        data_to_process.start_index = 0;
+        data_to_process.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [20, 21, 22, 23, 24, 25, 26, 27, 28], "wrong data copied");
+
+        let mut data_process_vec_2 = vec![0u8; 9];
+        let mut data_process_slice_2 =
+            DataToProcess::new_from_slice(data_process_vec_2.as_mut_slice());
+
+        data_process_slice.start_index = 0;
+
+        data_process_slice_2.read_from_slice(&mut data_process_slice, None).expect("couldn't copy");
+
+        let mut read_data = [0u8; 9];
+        data_process_slice_2.start_index = 0;
+        data_process_slice_2.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [27, 28, 0, 0, 0, 0, 0, 0, 0], "wrong data copied");
+    }
+
+    #[test]
+    fn data_to_process_memory_reference_copies() {
+        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
+        let mut output_page_2 = TestPageAllocator::new().expect("couldn't allocate test page");
+        output_page_2.copy_values(0, &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29]).unwrap();
+
+        let total_buffer_size = TestPageAllocator::get_allocation_size();
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+        let mut memory_buffer =
+            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");
+
+        let mem_buffer_parameters = MemoryBufferParameter {
+            bufferHandle: MemoryBufferAidl::Output(Some(
+                output_page_2.get_parcel_file_descriptor().expect("couldn't create fd"),
+            )),
+            sizeBytes: total_buffer_size as i32,
+        };
+        let mut memory_buffer_2 =
+            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");
+
+        let mut data_to_process = DataToProcess::new_from_volatile_slice(
+            memory_buffer.get_memory_slice().expect("couldn't get memory slice"),
+        );
+
+        expect_eq!(data_to_process.len(), total_buffer_size, "data to process had the wrong size");
+
+        let res = data_to_process.append_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
+        expect!(res.is_ok(), "Couldn't write slice");
+        data_to_process.start_index = 0;
+
+        let mut read_data = [0u8; 2];
+        data_to_process.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [0, 1], "wrong data read");
+        expect_eq!(
+            data_to_process.len(),
+            total_buffer_size - 2,
+            "data to process had the wrong size"
+        );
+
+        expect_eq!(data_to_process.start_index, 2, "start index should be 2");
+
+        let res = data_to_process.append_slice(&[10, 11]);
+        expect!(res.is_ok(), "Couldn't write slice");
+
+        expect_eq!(data_to_process.start_index, 4, "start index should be 4");
+
+        let mut data_to_process_2 = DataToProcess::new_from_volatile_slice(
+            memory_buffer_2.get_memory_slice().expect("couldn't get memory slice"),
+        );
+
+        let mut read_data = [0u8; 7];
+        data_to_process_2.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [20, 21, 22, 23, 24, 25, 26], "wrong data read");
+        expect_eq!(
+            data_to_process_2.len(),
+            total_buffer_size - 7,
+            "data to process had the wrong size"
+        );
+
+        expect_eq!(data_to_process_2.start_index, 7, "start index should be 7");
+
+        let mut read_data = [0u8; 2];
+        data_to_process_2.read_into_slice(&mut read_data, None).expect("couldn't read data");
+        expect_eq!(read_data, [27, 28], "wrong data read");
+        expect_eq!(
+            data_to_process_2.len(),
+            total_buffer_size - 9,
+            "data to process had the wrong size"
+        );
+
+        let mut data_process_slice = DataToProcess::new_from_slice(&mut read_data);
+        let res = data_to_process.read_from_slice(&mut data_process_slice, None);
+        expect!(res.is_ok(), "Couldn't data to process");
+
+        let mut slice = vec![0; 10];
+        read_slice(&memory_buffer, &mut slice, 0).expect("couldn't get slice");
+        expect_eq!(
+            slice,
+            [0, 1, 10, 11, 27, 28, 6, 7, 8, 9],
+            "wrong value retrieved through slice"
+        );
+    }
+
+    #[test]
+    fn aes_simple_cbcs_test() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_NO_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 9,
+        }));
+        let input_data =
+            OperationData::DataBuffer("encryption data.0123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data = OperationData::DataBuffer(
+            "fedcba98765432100123456789abcdefProtectedSection".as_bytes().to_vec(),
+        );
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let clear_encrypted_msg =
+            String::from_utf8(encrypted_data[16..encrypted_data.len() - 16].to_vec())
+                .expect("couldn't decode received message");
+        expect_eq!(
+            clear_encrypted_msg,
+            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210\
+            0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdef",
+            "couldn't retrieve clear portion"
+        );
+
+        // Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 9,
+        }));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(
+            decrypted_msg,
+            "encryption data.0123456789abcdeffedcba9876543210\
+            0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210\
+            0123456789abcdeffedcba98765432100123456789abcdefProtectedSection",
+            "couldn't retrieve original message"
+        );
+    }
+
+    #[test]
+    fn check_cbcs_wrong_key_types() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_128_CBC_PKCS7_PADDING,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 9,
+        }));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Should not be able to use cbcs mode with this key type");
+
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::AES_256_CBC_NO_PADDING,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 9,
+        }));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_err(), "Should not be able to use cbcs mode with this key type");
+    }
+
+    #[test]
+    fn aes_simple_all_encrypted_cbcs_test() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_NO_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::EPHEMERAL,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 1,
+            numberBlocksCopy: 0,
+        }));
+        let input_data =
+            OperationData::DataBuffer("encryption data.0123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        // Checking that encrypting with patter 0,0 is equivalent to pattern 1,0
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::SetPattern(PatternParameters {
+            numberBlocksProcess: 0,
+            numberBlocksCopy: 0,
+        }));
+        let input_data =
+            OperationData::DataBuffer("encryption data.0123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        let input_data =
+            OperationData::DataBuffer("fedcba98765432100123456789abcdef".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data1)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        assert_eq!(encrypted_data, encrypted_data1, "encrypted data should match");
+
+        // Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params =
+            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let mut cmd_processor = CmdProcessorContext::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
+        expect!(process_result.is_ok(), "Couldn't process command");
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            cmd_list.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(
+            decrypted_msg,
+            "encryption data.0123456789abcdeffedcba9876543210\
+            0123456789abcdef",
+            "couldn't retrieve original message"
+        );
+    }
 }
diff --git a/hwcryptohal/server/crypto_operation.rs b/hwcryptohal/server/crypto_operation.rs
index 2346af9..8e2a61d 100644
--- a/hwcryptohal/server/crypto_operation.rs
+++ b/hwcryptohal/server/crypto_operation.rs
@@ -16,22 +16,63 @@
 
 //! Module providing a shim for the different crypto operations.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
-    OperationParameters::OperationParameters,
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
+    HmacOperationParameters::HmacOperationParameters, KeyUse::KeyUse,
+    SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
 };
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
-    SymmetricCryptoParameters::SymmetricCryptoParameters,
-    SymmetricOperation::SymmetricOperation,
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
+    OperationParameters::OperationParameters, PatternParameters::PatternParameters,
 };
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
-use kmr_common::crypto::{self, Aes, KeyMaterial, SymmetricOperation as CryptoSymmetricOperation};
-use vm_memory::Bytes;
+use kmr_common::crypto::{
+    self, Aes, Hmac, KeyMaterial, SymmetricOperation as CryptoSymmetricOperation,
+};
 
 use crate::cmd_processing::DataToProcess;
 use crate::crypto_provider;
 use crate::helpers;
 use crate::opaque_key::OpaqueKey;
 
+// Pattern for cbcs operations. cbcs is based on partially encryption using AES-CBC as defined in
+// IEC 23001-7:2016
+enum CbcsPattern {
+    Protected(usize),
+    Clear(usize),
+}
+
+struct CbcsPatternParams {
+    num_encrypted_bytes: usize,
+    num_clear_bytes: usize,
+    current_pattern: CbcsPattern,
+}
+
+impl CbcsPatternParams {
+    fn new(pattern_parameters: &PatternParameters) -> Result<Self, HwCryptoError> {
+        let mut num_encrypted_blocks: usize =
+            pattern_parameters.numberBlocksProcess.try_into().map_err(|e| {
+                hwcrypto_err!(BAD_PARAMETER, "number encrypted blocks cannot be negative: {:?}", e)
+            })?;
+        let num_clear_blocks: usize =
+            pattern_parameters.numberBlocksCopy.try_into().map_err(|e| {
+                hwcrypto_err!(BAD_PARAMETER, "number clear blocks cannot be negative: {:?}", e)
+            })?;
+        // Special case. Some encoders pass a 0,0 to represent full sample encryption. Treating it
+        // the same as 1, 0.
+        if (num_encrypted_blocks == 0) && (num_clear_blocks == 0) {
+            num_encrypted_blocks = 1;
+        }
+        let num_encrypted_bytes = num_encrypted_blocks
+            .checked_mul(crypto::aes::BLOCK_SIZE)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "number encrypted blocks was too high"))?;
+        let num_clear_bytes = num_clear_blocks
+            .checked_mul(crypto::aes::BLOCK_SIZE)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "number clear blocks was too high"))?;
+        // Patterns starts with a number of protected blocks
+        let current_pattern = CbcsPattern::Protected(num_encrypted_bytes);
+        Ok(Self { num_encrypted_bytes, num_clear_bytes, current_pattern })
+    }
+}
+
 pub(crate) trait ICryptographicOperation: Send {
     // Returns the required minimum size in bytes the output buffer needs to have for the given
     // `input`
@@ -43,8 +84,8 @@ pub(crate) trait ICryptographicOperation: Send {
 
     fn operation<'a>(
         &mut self,
-        input: Option<DataToProcess<'a>>,
-        output: DataToProcess<'a>,
+        input: Option<&mut DataToProcess<'a>>,
+        output: &mut DataToProcess<'a>,
         is_finish: bool,
     ) -> Result<usize, HwCryptoError>;
 
@@ -57,13 +98,20 @@ pub(crate) trait ICryptographicOperation: Send {
             "update aad only valid for authenticated symmetric operations"
         ))
     }
+
+    fn set_operation_pattern(
+        &mut self,
+        _patter_parameter: &PatternParameters,
+    ) -> Result<(), HwCryptoError> {
+        Err(hwcrypto_err!(BAD_PARAMETER, "set_operation_pattern only supported for AES CBC"))
+    }
 }
 
 trait IBaseCryptoOperation: Send {
-    fn update(
+    fn update<'a>(
         &mut self,
-        input: &DataToProcess,
-        output: &mut DataToProcess,
+        input: &mut DataToProcess<'a>,
+        output: &mut DataToProcess<'a>,
     ) -> Result<usize, HwCryptoError>;
 
     fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError>;
@@ -80,6 +128,11 @@ trait IBaseCryptoOperation: Send {
             "update aad only valid for authenticated symmetric operations"
         ))
     }
+
+    fn set_operation_pattern(
+        &mut self,
+        patter_parameter: &PatternParameters,
+    ) -> Result<(), HwCryptoError>;
 }
 
 impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
@@ -97,18 +150,18 @@ impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
         }
     }
 
-    fn operation(
+    fn operation<'a>(
         &mut self,
-        input: Option<DataToProcess>,
-        mut output: DataToProcess,
+        mut input: Option<&mut DataToProcess<'a>>,
+        output: &mut DataToProcess<'a>,
         is_finish: bool,
     ) -> Result<usize, HwCryptoError> {
         if is_finish {
-            self.finish(&mut output)
+            self.finish(output)
         } else {
             let input =
-                input.as_ref().ok_or(hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
-            self.update(&input, &mut output)
+                input.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+            self.update(input, output)
         }
     }
 
@@ -119,6 +172,13 @@ impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
     fn update_aad(&mut self, input: &DataToProcess) -> Result<(), HwCryptoError> {
         self.update_aad(input)
     }
+
+    fn set_operation_pattern(
+        &mut self,
+        patter_parameter: &PatternParameters,
+    ) -> Result<(), HwCryptoError> {
+        self.set_operation_pattern(patter_parameter)
+    }
 }
 
 // Newtype used because the traits we currently use for cryptographic operations cannot directly
@@ -131,32 +191,132 @@ impl TempBuffer {
         TempBuffer(Vec::new())
     }
 
-    fn get_buffer_reference<'a>(
+    fn read_into_buffer_reference<'a>(
         &'a mut self,
-        input: &'a DataToProcess,
+        input: &'a mut DataToProcess,
+        len: Option<usize>,
     ) -> Result<&'a [u8], HwCryptoError> {
-        match input {
-            DataToProcess::Slice(slice) => Ok(slice),
-            DataToProcess::VolatileSlice(slice) => {
-                self.0.clear();
-                let slice_len = slice.len();
-                self.0.try_reserve(slice_len)?;
-                // Addition should be safe because try_reserve didn't fail
-                self.0.resize_with(slice_len, Default::default);
-                slice.read_slice(&mut self.0, 0)?;
-                Ok(&self.0[..])
-            }
+        let len = len.unwrap_or(input.len());
+        if len > input.len() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "end {} out of slice bounds for slice size {}",
+                len,
+                input.len()
+            ));
+        }
+
+        if !input.is_non_volatile_slice_backed() {
+            let slice = input.try_slice(len)?;
+            Ok(slice)
+        } else {
+            self.0.clear();
+            self.0.try_reserve(len)?;
+            // Addition should be safe because try_reserve didn't fail
+            self.0.resize_with(len, Default::default);
+            input.read_into_slice(self.0.as_mut_slice(), Some(len))?;
+            Ok(&self.0[..])
+        }
+    }
+}
+
+pub(crate) struct HmacOperation {
+    accumulating_op: Option<Box<dyn crypto::AccumulatingOperation>>,
+}
+
+impl HmacOperation {
+    fn new(parameters: &HmacOperationParameters) -> Result<Self, HwCryptoError> {
+        let opaque_key: OpaqueKey = parameters
+            .key
+            .as_ref()
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "hmac key not provided"))?
+            .try_into()?;
+        Self::check_parameters(&opaque_key, parameters)?;
+        let digest = helpers::aidl_to_rust_digest(&opaque_key.get_key_type())?;
+        let hmac = crypto_provider::HmacImpl;
+        let accumulating_op = match opaque_key.key_material {
+            KeyMaterial::Hmac(key) => hmac.begin(key.clone(), digest).map_err(|e| {
+                hwcrypto_err!(GENERIC_ERROR, "couldn't begin hmac operation: {:?}", e)
+            }),
+            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
+        }?;
+        Ok(HmacOperation { accumulating_op: Some(accumulating_op) })
+    }
+
+    fn check_parameters(
+        opaque_key: &OpaqueKey,
+        _parameters: &HmacOperationParameters,
+    ) -> Result<(), HwCryptoError> {
+        if !opaque_key.key_usage_supported(KeyUse::SIGN) {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "Provided key cannot be used for signing"));
+        }
+        match &opaque_key.key_material {
+            KeyMaterial::Hmac(_) => Ok(()),
+            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
         }
     }
 }
 
-#[allow(dead_code)]
+impl IBaseCryptoOperation for HmacOperation {
+    fn get_req_size_update(&self, _input: &DataToProcess) -> Result<usize, HwCryptoError> {
+        Ok(0)
+    }
+
+    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
+        Ok(crypto_provider::HMAC_MAX_SIZE)
+    }
+
+    fn update(
+        &mut self,
+        input: &mut DataToProcess,
+        _output: &mut DataToProcess,
+    ) -> Result<usize, HwCryptoError> {
+        let op = self
+            .accumulating_op
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
+        // TODO: refactor traits to not require copying the input for VolatileSlices
+        let mut input_buffer = TempBuffer::new();
+        let input_data = input_buffer.read_into_buffer_reference(input, None)?;
+        op.update(input_data)?;
+        Ok(0)
+    }
+
+    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError> {
+        let op = self
+            .accumulating_op
+            .take()
+            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
+        let req_size = self.get_req_size_finish()?;
+        if output.len() != req_size {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
+        }
+        let output_data = op.finish()?;
+        let output_len = output_data.len();
+        output.append_slice(output_data.as_slice())?;
+        Ok(output_len)
+    }
+
+    fn is_active(&self) -> bool {
+        self.accumulating_op.is_some()
+    }
+
+    fn set_operation_pattern(
+        &mut self,
+        _patter_parameter: &PatternParameters,
+    ) -> Result<(), HwCryptoError> {
+        Err(hwcrypto_err!(BAD_PARAMETER, "set_operation_pattern only supported for AES CBC"))
+    }
+}
+
 pub(crate) struct AesOperation {
     opaque_key: OpaqueKey,
     emitting_op: Option<Box<dyn crypto::EmittingOperation>>,
     dir: CryptoSymmetricOperation,
     remaining_unaligned_data_size: usize,
     block_based_encryption: bool,
+    cbcs_pattern: Option<CbcsPatternParams>,
+    operation_started: bool,
 }
 
 impl AesOperation {
@@ -185,6 +345,8 @@ impl AesOperation {
             dir,
             remaining_unaligned_data_size: 0,
             block_based_encryption,
+            cbcs_pattern: None,
+            operation_started: false,
         };
         Ok(aes_operation)
     }
@@ -228,15 +390,105 @@ impl AesOperation {
     fn round_to_block_size(size: usize) -> usize {
         ((size + crypto::aes::BLOCK_SIZE - 1) / crypto::aes::BLOCK_SIZE) * crypto::aes::BLOCK_SIZE
     }
+
+    fn cbcs_update<'a>(
+        &mut self,
+        input: &mut DataToProcess<'a>,
+        output: &mut DataToProcess<'a>,
+    ) -> Result<usize, HwCryptoError> {
+        let total_size = input.len();
+        if (total_size % crypto::aes::BLOCK_SIZE) != 0 {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "input size was not multiple of {}: {}",
+                crypto::aes::BLOCK_SIZE,
+                input.len()
+            ));
+        }
+        if output.len() != input.len() {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "output size was not {}", input.len()));
+        }
+        let cbcs_pattern = self
+            .cbcs_pattern
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "not a cbcs operation"))?;
+        // TODO: refactor to remove need of input copy for memory slices
+        let mut input_buff = TempBuffer::new();
+        let mut remaining_len = total_size;
+        let aes_op = self
+            .emitting_op
+            .as_mut()
+            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
+        while remaining_len > 0 {
+            match cbcs_pattern.current_pattern {
+                CbcsPattern::Protected(num_encrypted_bytes) => {
+                    let encrypted_bytes = std::cmp::min(remaining_len, num_encrypted_bytes);
+                    let input_data =
+                        input_buff.read_into_buffer_reference(input, Some(encrypted_bytes))?;
+                    let output_data = aes_op.update(input_data)?;
+                    output.append_slice(output_data.as_slice())?;
+                    if remaining_len > num_encrypted_bytes {
+                        // There is still data to process, advance index and change pattern to clear
+                        // In this case encrypted_bytes == num_encrypted_bytes
+                        cbcs_pattern.current_pattern =
+                            CbcsPattern::Clear(cbcs_pattern.num_clear_bytes);
+                    } else {
+                        // We processed all available data, check if we should change pattern or
+                        // keep the same
+                        if num_encrypted_bytes > remaining_len {
+                            // We are still on the protected pattern area
+                            cbcs_pattern.current_pattern =
+                                CbcsPattern::Protected(num_encrypted_bytes - remaining_len);
+                        } else {
+                            // We need to switch to a clear area
+                            cbcs_pattern.current_pattern =
+                                CbcsPattern::Clear(cbcs_pattern.num_clear_bytes);
+                        }
+                        break;
+                    }
+                    remaining_len -= num_encrypted_bytes;
+                }
+                CbcsPattern::Clear(num_clear_bytes) => {
+                    let clear_bytes = std::cmp::min(remaining_len, num_clear_bytes);
+                    output.read_from_slice(input, Some(clear_bytes))?;
+                    if remaining_len > num_clear_bytes {
+                        // There is still data to process, advance index and change pattern to
+                        // protected. In this case clear_bytes == num_clear_bytes
+                        cbcs_pattern.current_pattern =
+                            CbcsPattern::Protected(cbcs_pattern.num_encrypted_bytes);
+                    } else {
+                        // We processed all available data, check if we should change pattern or
+                        // keep the same
+                        if num_clear_bytes > remaining_len {
+                            // We are still on the clear pattern area
+                            cbcs_pattern.current_pattern =
+                                CbcsPattern::Clear(num_clear_bytes - remaining_len);
+                        } else {
+                            // We need to switch to a protected area
+                            cbcs_pattern.current_pattern =
+                                CbcsPattern::Protected(cbcs_pattern.num_encrypted_bytes);
+                        }
+                        break;
+                    }
+                    remaining_len -= num_clear_bytes;
+                }
+            }
+        }
+        Ok(total_size)
+    }
 }
 
 impl IBaseCryptoOperation for AesOperation {
-    fn update(
+    fn update<'a>(
         &mut self,
-        input: &DataToProcess,
-        output: &mut DataToProcess,
+        input: &mut DataToProcess<'a>,
+        output: &mut DataToProcess<'a>,
     ) -> Result<usize, HwCryptoError> {
-        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(input)?;
+        self.operation_started = true;
+        if self.cbcs_pattern.is_some() {
+            return self.cbcs_update(input, output);
+        }
+        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(&input)?;
         if output.len() != req_size {
             return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
         }
@@ -246,10 +498,10 @@ impl IBaseCryptoOperation for AesOperation {
             .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
         // TODO: refactor traits to not require copying the input for VolatileSlices
         let mut input_buffer = TempBuffer::new();
-        let input_data = input_buffer.get_buffer_reference(input)?;
+        let input_data = input_buffer.read_into_buffer_reference(input, None)?;
         let output_data = op.update(input_data)?;
         let output_len = output_data.len();
-        output.copy_slice(output_data.as_slice())?;
+        output.append_slice(output_data.as_slice())?;
         self.remaining_unaligned_data_size = unaligned_size;
         Ok(output_len)
     }
@@ -265,8 +517,9 @@ impl IBaseCryptoOperation for AesOperation {
         }
         let output_data = op.finish()?;
         let output_len = output_data.len();
-        output.copy_slice(output_data.as_slice())?;
+        output.append_slice(output_data.as_slice())?;
         self.remaining_unaligned_data_size = 0;
+        self.operation_started = false;
         Ok(output_len)
     }
 
@@ -275,21 +528,60 @@ impl IBaseCryptoOperation for AesOperation {
     }
 
     fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
-        let (req_size_to_process, _) = self.get_req_size_from_len(0)?;
-        match self.dir {
-            CryptoSymmetricOperation::Encrypt => Ok(req_size_to_process + crypto::aes::BLOCK_SIZE),
-            CryptoSymmetricOperation::Decrypt => Ok(crypto::aes::BLOCK_SIZE),
+        if self.cbcs_pattern.is_some() {
+            // On CBCS patterns we do not have more data to write on finish, because there is no
+            // padding needed and all operations were done using block boundaries.
+            Ok(0)
+        } else {
+            let (req_size_to_process, _) = self.get_req_size_from_len(0)?;
+            match self.dir {
+                CryptoSymmetricOperation::Encrypt => {
+                    Ok(req_size_to_process + crypto::aes::BLOCK_SIZE)
+                }
+                CryptoSymmetricOperation::Decrypt => Ok(crypto::aes::BLOCK_SIZE),
+            }
         }
     }
 
     fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError> {
-        let (req_size, _) = self.get_update_req_size_with_remainder(input)?;
-        Ok(req_size)
+        if self.cbcs_pattern.is_some() {
+            // On CBCS patterns we are currently processing a number of bytes multiple of block
+            // sizes, so the space needed is always the size of the input.
+            if (input.len() % crypto::aes::BLOCK_SIZE) != 0 {
+                return Err(hwcrypto_err!(
+                    BAD_PARAMETER,
+                    "input size was not multiple of {}: {}",
+                    crypto::aes::BLOCK_SIZE,
+                    input.len()
+                ));
+            }
+            Ok(input.len())
+        } else {
+            let (req_size, _) = self.get_update_req_size_with_remainder(input)?;
+            Ok(req_size)
+        }
     }
 
     fn is_active(&self) -> bool {
         self.emitting_op.is_some()
     }
+
+    fn set_operation_pattern(
+        &mut self,
+        pattern_parameters: &PatternParameters,
+    ) -> Result<(), HwCryptoError> {
+        self.opaque_key.supports_pattern_encryption()?;
+        // We only support setting a pattern if we have not started encrypting/decrypting
+        if self.operation_started {
+            return Err(hwcrypto_err!(BAD_STATE, "pattern cannot be set if operation has started"));
+        }
+        // We do not support changing an already set up pattern
+        if self.cbcs_pattern.is_some() {
+            return Err(hwcrypto_err!(BAD_STATE, "pattern has already been set"));
+        }
+        self.cbcs_pattern = Some(CbcsPatternParams::new(pattern_parameters)?);
+        Ok(())
+    }
 }
 
 pub(crate) struct CopyOperation;
@@ -306,13 +598,14 @@ impl ICryptographicOperation for CopyOperation {
 
     fn operation<'a>(
         &mut self,
-        input: Option<DataToProcess<'a>>,
-        mut output: DataToProcess<'a>,
+        input: Option<&mut DataToProcess<'a>>,
+        output: &mut DataToProcess<'a>,
         _is_finish: bool,
     ) -> Result<usize, HwCryptoError> {
-        let num_bytes_copy = self.get_operation_req_size(input.as_ref(), false)?;
-        let input = input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
-        output.copy_from_slice(&input)?;
+        let num_bytes_copy = self.get_operation_req_size(input.as_deref(), false)?;
+        let mut input =
+            input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+        output.read_from_slice(&mut input, None)?;
         Ok(num_bytes_copy)
     }
 
@@ -340,6 +633,10 @@ impl CryptographicOperation {
                     Err(hwcrypto_err!(BAD_PARAMETER, "key was null"))
                 }
             }
+            OperationParameters::Hmac(params) => {
+                let hmac_op = HmacOperation::new(params)?;
+                Ok(Box::new(hmac_op))
+            }
             _ => unimplemented!("operation not implemented yet"),
         }
     }
@@ -358,8 +655,8 @@ impl ICryptographicOperation for () {
 
     fn operation(
         &mut self,
-        _input: Option<DataToProcess>,
-        mut _output: DataToProcess,
+        _input: Option<&mut DataToProcess>,
+        _output: &mut DataToProcess,
         _is_finish: bool,
     ) -> Result<usize, HwCryptoError> {
         Err(hwcrypto_err!(UNSUPPORTED, "nothing to execute on null operation"))
@@ -373,7 +670,7 @@ impl ICryptographicOperation for () {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
         AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
         KeyLifetime::KeyLifetime,
         KeyType::KeyType, KeyUse::KeyUse,
@@ -381,10 +678,16 @@ mod tests {
         SymmetricOperation::SymmetricOperation,
         SymmetricOperationParameters::SymmetricOperationParameters,
     };
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         KeyPolicy::KeyPolicy,
     };
     use test::{expect, expect_eq};
+    use tipc::Uuid;
+
+    fn connection_info() -> Uuid {
+        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
+        Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap()
+    }
 
     #[test]
     fn use_aes_key() {
@@ -397,7 +700,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let handle = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
+        let handle = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
             nonce: nonce.into(),
@@ -408,7 +712,7 @@ mod tests {
         let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
         let input_to_encrypt = "hello world1234";
         let mut input_data = input_to_encrypt.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let mut op =
             CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
         let req_size = op
@@ -416,9 +720,10 @@ mod tests {
             .expect("couldn't get required_size");
         expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
         let mut output_data = vec![];
-        let output_slice = DataToProcess::Slice(&mut output_data[..]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         expect_eq!(written_bytes, 0, "Written bytes for encryptiong less than a block should be 0");
         let req_size_finish =
             op.get_operation_req_size(None, true).expect("couldn't get required_size");
@@ -428,14 +733,14 @@ mod tests {
             "Required size for encryptiong less than a block should be a block"
         );
         output_data.append(&mut vec![0u8; 16]);
-        let output_slice = DataToProcess::Slice(&mut output_data[..]);
-        op.operation(None, output_slice, true).expect("couldn't finish");
-        let output_slice = DataToProcess::Slice(&mut output_data[0..0]);
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
-        let update_op = op.operation(Some(input_slice), output_slice, false);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
+        op.operation(None, &mut output_slice, true).expect("couldn't finish");
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[0..0]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
+        let update_op = op.operation(Some(&mut input_slice), &mut output_slice, false);
         expect!(update_op.is_err(), "shouldn't be able to run operations anymore");
-        let output_slice = DataToProcess::Slice(&mut output_data[0..0]);
-        let finish_op = op.operation(None, output_slice, true);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[0..0]);
+        let finish_op = op.operation(None, &mut output_slice, true);
         expect!(finish_op.is_err(), "shouldn't be able to run operations anymore");
         let direction = SymmetricOperation::DECRYPT;
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -446,21 +751,24 @@ mod tests {
         let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
         let mut op =
             CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
-        let output_slice = DataToProcess::Slice(&mut output_data[..]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&output_slice), false)
             .expect("couldn't get required_size");
         let mut decrypted_data = vec![0; req_size];
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..]);
-        let mut decrypted_data_size =
-            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..]);
+        let mut decrypted_data_size = op
+            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
+            .expect("couldn't update");
         let decrypted_data_start = decrypted_data_size;
         let req_size_finish =
             op.get_operation_req_size(None, true).expect("couldn't get required_size");
         let decrypted_data_end = decrypted_data_size + req_size_finish;
-        let decrypted_slice =
-            DataToProcess::Slice(&mut decrypted_data[decrypted_data_start..decrypted_data_end]);
-        let total_finish_size = op.operation(None, decrypted_slice, true).expect("couldn't finish");
+        let mut decrypted_slice = DataToProcess::new_from_slice(
+            &mut decrypted_data[decrypted_data_start..decrypted_data_end],
+        );
+        let total_finish_size =
+            op.operation(None, &mut decrypted_slice, true).expect("couldn't finish");
         decrypted_data_size += total_finish_size;
         decrypted_data.truncate(decrypted_data_size);
         expect_eq!(input_to_encrypt.len(), decrypted_data_size, "bad length for decrypted data");
@@ -479,7 +787,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let handle = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
+        let handle = OpaqueKey::generate_opaque_key(&policy, connection_info())
+            .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
             nonce: nonce.into(),
@@ -492,80 +801,91 @@ mod tests {
             CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
         let input_to_encrypt = "test encryption string";
         let mut input_data = input_to_encrypt.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
         let mut output_data = vec![0; 200];
-        let output_slice = DataToProcess::Slice(&mut output_data[..req_size]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..req_size]);
         let mut total_encryption_size = 0;
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         total_encryption_size += written_bytes;
         expect_eq!(written_bytes, 16, "A block should have been encrypted");
         let input_to_encrypt_2 = " for this ";
         let mut input_data = input_to_encrypt_2.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         let output_start = written_bytes;
         let output_stop = written_bytes + req_size;
         expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         expect_eq!(written_bytes, 16, "A block should have been encrypted");
         total_encryption_size += written_bytes;
         let output_start = output_start + written_bytes;
         let input_to_encrypt_3 = "test";
         let mut input_data = input_to_encrypt_3.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         total_encryption_size += written_bytes;
         expect_eq!(written_bytes, 0, "No bytes should have been written");
         let input_to_encrypt_4 = " is";
         let mut input_data = input_to_encrypt_4.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         expect_eq!(written_bytes, 0, "No bytes should have been written");
         total_encryption_size += written_bytes;
         let input_to_encrypt_5 = " a ";
         let mut input_data = input_to_encrypt_5.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_start]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         expect_eq!(written_bytes, 0, "No bytes should have been written");
         total_encryption_size += written_bytes;
         let input_to_encrypt_6 = "random one.";
         let mut input_data = input_to_encrypt_6.as_bytes().to_vec();
-        let input_slice = DataToProcess::Slice(&mut input_data[..]);
+        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
         let req_size = op
             .get_operation_req_size(Some(&input_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
         let output_stop = output_start + req_size;
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
-        let written_bytes =
-            op.operation(Some(input_slice), output_slice, false).expect("couldn't update");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
+        let written_bytes = op
+            .operation(Some(&mut input_slice), &mut output_slice, false)
+            .expect("couldn't update");
         total_encryption_size += written_bytes;
         expect_eq!(written_bytes, 16, "A block should have been encrypted");
         let output_start = output_start + written_bytes;
@@ -577,8 +897,10 @@ mod tests {
             "Required size for encryptiong less than a block should be a block"
         );
         let output_stop = output_start + req_size_finish;
-        let output_slice = DataToProcess::Slice(&mut output_data[output_start..output_stop]);
-        let finish_written_bytes = op.operation(None, output_slice, true).expect("couldn't finish");
+        let mut output_slice =
+            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
+        let finish_written_bytes =
+            op.operation(None, &mut output_slice, true).expect("couldn't finish");
         expect_eq!(finish_written_bytes, 16, "With padding we should have written a block");
         total_encryption_size += finish_written_bytes;
         output_data.truncate(total_encryption_size);
@@ -594,51 +916,56 @@ mod tests {
         let mut op =
             CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
         let mut decrypted_data = vec![0; total_encryption_size];
-        let output_slice = DataToProcess::Slice(&mut output_data[..4]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..4]);
         let req_size = op
             .get_operation_req_size(Some(&output_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 16, "worse case space for this size of input is a block");
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..16]);
-        let written_bytes =
-            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..16]);
+        let written_bytes = op
+            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
+            .expect("couldn't update");
         decrypted_data_size += written_bytes;
         expect_eq!(written_bytes, 0, "No bytes should have been written");
-        let output_slice = DataToProcess::Slice(&mut output_data[4..32]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[4..32]);
         let req_size = op
             .get_operation_req_size(Some(&output_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[..32]);
-        let written_bytes =
-            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..32]);
+        let written_bytes = op
+            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
+            .expect("couldn't update");
         decrypted_data_size += written_bytes;
         expect_eq!(written_bytes, 16, "One block should have been written");
-        let output_slice = DataToProcess::Slice(&mut output_data[32..50]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[32..50]);
         let req_size = op
             .get_operation_req_size(Some(&output_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[16..48]);
-        let written_bytes =
-            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[16..48]);
+        let written_bytes = op
+            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
+            .expect("couldn't update");
         decrypted_data_size += written_bytes;
         expect_eq!(written_bytes, 32, "Two block should have been written");
-        let output_slice = DataToProcess::Slice(&mut output_data[50..64]);
+        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[50..64]);
         let req_size = op
             .get_operation_req_size(Some(&output_slice), false)
             .expect("couldn't get required_size");
         expect_eq!(req_size, 16, "worse case space for this size of input is 1 block");
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[48..64]);
-        let written_bytes =
-            op.operation(Some(output_slice), decrypted_slice, false).expect("couldn't update");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[48..64]);
+        let written_bytes = op
+            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
+            .expect("couldn't update");
         decrypted_data_size += written_bytes;
         expect_eq!(written_bytes, 0, "No blocks should have been written");
         let req_size_finish =
             op.get_operation_req_size(None, true).expect("couldn't get required_size");
         expect_eq!(req_size_finish, 16, "Max size required to finish should be 1 block");
-        let decrypted_slice = DataToProcess::Slice(&mut decrypted_data[48..64]);
-        let total_finish_size = op.operation(None, decrypted_slice, true).expect("couldn't finish");
+        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[48..64]);
+        let total_finish_size =
+            op.operation(None, &mut decrypted_slice, true).expect("couldn't finish");
         decrypted_data_size += total_finish_size;
         decrypted_data.truncate(decrypted_data_size);
         let decrypted_msg =
diff --git a/hwcryptohal/server/crypto_operation_context.rs b/hwcryptohal/server/crypto_operation_context.rs
index 02765c2..b7c89e6 100644
--- a/hwcryptohal/server/crypto_operation_context.rs
+++ b/hwcryptohal/server/crypto_operation_context.rs
@@ -17,7 +17,7 @@
 //! Implementation of the `ICryptoOperationContext` AIDL interface. It can be used to execute more
 //! commands over the same context.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
     CryptoOperation::CryptoOperation, ICryptoOperationContext::BnCryptoOperationContext,
     ICryptoOperationContext::ICryptoOperationContext,
 };
diff --git a/hwcryptohal/server/crypto_provider.rs b/hwcryptohal/server/crypto_provider.rs
index 3f6c593..77e00f9 100644
--- a/hwcryptohal/server/crypto_provider.rs
+++ b/hwcryptohal/server/crypto_provider.rs
@@ -19,3 +19,4 @@
 pub(crate) use crate::platform_functions::PlatformRng as RngImpl;
 pub(crate) use kmr_crypto_boring::aes::BoringAes as AesImpl;
 pub(crate) use kmr_crypto_boring::hmac::BoringHmac as HmacImpl;
+pub(crate) const HMAC_MAX_SIZE: usize = bssl_sys::EVP_MAX_MD_SIZE as usize;
diff --git a/hwcryptohal/server/helpers.rs b/hwcryptohal/server/helpers.rs
index b1972a6..b779e4a 100644
--- a/hwcryptohal/server/helpers.rs
+++ b/hwcryptohal/server/helpers.rs
@@ -16,18 +16,28 @@
 
 //! Helper functions that includes data transformation for AIDL types.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
     AesCipherMode::AesCipherMode, AesKey::AesKey, CipherModeParameters::CipherModeParameters,
-    ExplicitKeyMaterial::ExplicitKeyMaterial, KeyType::KeyType, KeyUse::KeyUse,
+    ExplicitKeyMaterial::ExplicitKeyMaterial, HmacKey::HmacKey, KeyType::KeyType, KeyUse::KeyUse,
     SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
 };
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use kmr_common::crypto::{
-    self, aes, KeyMaterial, OpaqueOr, SymmetricOperation as KmSymmetricOperation,
+    self, aes, hmac, KeyMaterial, OpaqueOr, SymmetricOperation as KmSymmetricOperation,
 };
+use kmr_wire::keymint;
 
 use crate::opaque_key::OpaqueKey;
 
+fn aidl_hmac_explicit_key_to_rust_key_material(
+    hmac_key_material: &[u8],
+) -> Result<KeyMaterial, HwCryptoError> {
+    let mut ekm = Vec::new();
+    ekm.try_reserve(hmac_key_material.len())?;
+    ekm.extend_from_slice(hmac_key_material);
+    Ok(KeyMaterial::Hmac(OpaqueOr::Explicit(hmac::Key(ekm))))
+}
+
 pub(crate) fn aidl_explicit_key_to_rust_key_material(
     key_material: &ExplicitKeyMaterial,
 ) -> Result<KeyMaterial, HwCryptoError> {
@@ -38,6 +48,12 @@ pub(crate) fn aidl_explicit_key_to_rust_key_material(
         ExplicitKeyMaterial::Aes(AesKey::Aes256(km)) => {
             Ok(KeyMaterial::Aes(OpaqueOr::Explicit(aes::Key::Aes256(*km))))
         }
+        ExplicitKeyMaterial::Hmac(HmacKey::Sha256(km)) => {
+            aidl_hmac_explicit_key_to_rust_key_material(km)
+        }
+        ExplicitKeyMaterial::Hmac(HmacKey::Sha512(km)) => {
+            aidl_hmac_explicit_key_to_rust_key_material(km)
+        }
     }
 }
 
@@ -52,6 +68,14 @@ pub(crate) fn symmetric_encryption_block_based(
     }
 }
 
+pub(crate) fn aidl_to_rust_digest(key_type: &KeyType) -> Result<keymint::Digest, HwCryptoError> {
+    match *key_type {
+        KeyType::HMAC_SHA256 => Ok(keymint::Digest::Sha256),
+        KeyType::HMAC_SHA512 => Ok(keymint::Digest::Sha512),
+        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported key type to get digest: {:?}", key_type)),
+    }
+}
+
 pub(crate) fn aidl_to_rust_aes_cipher_params(
     params: &SymmetricCryptoParameters,
     opaque_key: &OpaqueKey,
diff --git a/hwcryptohal/server/hwcrypto_device_key.rs b/hwcryptohal/server/hwcrypto_device_key.rs
index aa08a65..cd3ed21 100644
--- a/hwcryptohal/server/hwcrypto_device_key.rs
+++ b/hwcryptohal/server/hwcrypto_device_key.rs
@@ -17,22 +17,22 @@
 //! Implementation of the `IHwCryptoKey` AIDL interface. It can be use to generate and
 //! retrieve device specific keys.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
     types::{
         ExplicitKeyMaterial::ExplicitKeyMaterial, KeyLifetime::KeyLifetime, KeyType::KeyType,
-        KeyUse::KeyUse,
+        KeyUse::KeyUse, OpaqueKeyToken::OpaqueKeyToken,
     },
     IHwCryptoKey::{
         BnHwCryptoKey, DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
         DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
         DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
-        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
+        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey, KeySlot::KeySlot,
     },
     IHwCryptoOperations::IHwCryptoOperations,
     IOpaqueKey::IOpaqueKey,
     KeyPolicy::KeyPolicy,
 };
-use android_hardware_security_see::binder;
+use android_hardware_security_see_hwcrypto::binder;
 use ciborium::{cbor, Value};
 use coset::{AsCborValue, CborSerializable, CoseError};
 use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
@@ -43,7 +43,9 @@ use crate::hwcrypto_operations::HwCryptoOperations;
 
 use crate::helpers;
 use crate::opaque_key::{self, DerivationContext, HkdfOperationType, OpaqueKey};
-use crate::service_encryption_key::{self, EncryptionHeader};
+use crate::service_encryption_key::{
+    self, EncryptedContent, EncryptionHeader, EncryptionHeaderKey,
+};
 
 const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";
 
@@ -76,7 +78,7 @@ impl VersionContext {
     }
 
     fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
-        let header = Some(EncryptionHeader::generate()?);
+        let header = Some(EncryptionHeader::generate(EncryptedContent::DicePolicy)?);
         let version = Self::get_current_version()?;
         Ok(VersionContext { uuid, version, header })
     }
@@ -119,7 +121,8 @@ impl VersionContext {
         let (version_ctx_header, decrypted_data) =
             EncryptionHeader::decrypt_content_service_encryption_key(
                 encrypted_context,
-                DEVICE_KEY_CTX,
+                EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
+                EncryptedContent::DicePolicy,
             )?;
 
         let mut version_context =
@@ -130,7 +133,10 @@ impl VersionContext {
 
     fn encrypt_context(mut self) -> Result<Vec<u8>, HwCryptoError> {
         let header = self.header.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "no header found"))?;
-        header.encrypt_content_service_encryption_key(DEVICE_KEY_CTX, self)
+        header.encrypt_content_service_encryption_key(
+            EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
+            self,
+        )
     }
 
     fn get_stable_context(encrypted_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
@@ -186,8 +192,7 @@ impl AsCborValue for VersionContext {
 /// The `IHwCryptoKey` implementation.
 #[derive(Debug)]
 pub struct HwCryptoKey {
-    #[allow(dead_code)]
-    uuid: Uuid,
+    pub(crate) uuid: Uuid,
 }
 
 impl binder::Interface for HwCryptoKey {}
@@ -198,14 +203,19 @@ impl HwCryptoKey {
         BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
     }
 
-    fn derive_dice_policy_bound_key(
+    // check_dice_policy_owner shall only be false for creating internal keys that can be used
+    // to seal content bounded to another party DICE policy
+    pub(crate) fn derive_dice_policy_bound_key(
         &self,
         derivation_key: &DiceBoundDerivationKey,
         dice_policy_for_key_version: &[u8],
+        check_dice_policy_owner: bool,
     ) -> Result<DiceBoundKeyResult, HwCryptoError> {
         // Verifying provided DICE policy
         let connection_info = ConnectionInformation { uuid: self.uuid.clone() };
-        VersionContext::check_encrypted_context(dice_policy_for_key_version, connection_info)?;
+        if check_dice_policy_owner {
+            VersionContext::check_encrypted_context(dice_policy_for_key_version, connection_info)?;
+        }
         // Getting back a stable DICE policy for context, so keys derived with the same version will
         // match
         let dice_context = VersionContext::get_stable_context(dice_policy_for_key_version)?;
@@ -230,7 +240,6 @@ impl HwCryptoKey {
                     DeviceKeyId::DEVICE_BOUND_KEY => {
                         Ok(hwkey_session.derive_key_req().unique_key())
                     }
-                    DeviceKeyId::BATCH_KEY => Ok(hwkey_session.derive_key_req().shared_key()),
                     _ => Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id)),
                 }?;
 
@@ -248,7 +257,7 @@ impl HwCryptoKey {
                 };
                 // Create a new opaque key from the generated key material
                 let km = opaque_key::generate_key_material(&policy.keyType, Some(derived_key))?;
-                let key = opaque_key::OpaqueKey::new_binder(&policy, km)
+                let key = opaque_key::OpaqueKey::new_binder(&policy, km, self.uuid.clone())
                     .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to create key {:?}", e))?;
                 let dice_policy_current =
                     VersionContext::is_context_current(dice_policy_for_key_version)?;
@@ -263,6 +272,15 @@ impl HwCryptoKey {
             )),
         }
     }
+
+    fn check_caller_can_access_keyslot(&self, _keyslot: KeySlot) -> Result<(), HwCryptoError> {
+        // Simple uuid check for host uuid until we have DICE
+        if self.uuid.to_string() == "00000000-0000-0000-0000-000000000000" {
+            Err(hwcrypto_err!(UNAUTHORIZED, "caller do not have permission to access this key"))
+        } else {
+            Ok(())
+        }
+    }
 }
 
 impl IHwCryptoKey for HwCryptoKey {
@@ -271,7 +289,8 @@ impl IHwCryptoKey for HwCryptoKey {
         derivation_key: &DiceBoundDerivationKey,
     ) -> binder::Result<DiceCurrentBoundKeyResult> {
         let dice_policy = VersionContext::new_current_encrypted(self.uuid.clone())?;
-        let derived_key_result = self.derive_dice_policy_bound_key(derivation_key, &dice_policy)?;
+        let derived_key_result =
+            self.derive_dice_policy_bound_key(derivation_key, &dice_policy, true)?;
         let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: policy_current } =
             derived_key_result;
         if !policy_current {
@@ -288,7 +307,42 @@ impl IHwCryptoKey for HwCryptoKey {
         derivation_key: &DiceBoundDerivationKey,
         dice_policy_for_key_version: &[u8],
     ) -> binder::Result<DiceBoundKeyResult> {
-        Ok(self.derive_dice_policy_bound_key(derivation_key, dice_policy_for_key_version)?)
+        Ok(self.derive_dice_policy_bound_key(derivation_key, dice_policy_for_key_version, true)?)
+    }
+
+    fn getCurrentDicePolicy(&self) -> binder::Result<Vec<u8>> {
+        Ok(VersionContext::new_current_encrypted(self.uuid.clone())?)
+    }
+
+    fn keyTokenImport(
+        &self,
+        key_token: &OpaqueKeyToken,
+        sealing_dice_policy: &[u8],
+    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        // We derive a normal DICE bound key. This will check that the policy matches
+        // our DICE chain.
+        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: _ } = self
+            .deriveDicePolicyBoundKey(
+                &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
+                sealing_dice_policy,
+            )?;
+        let key = key.ok_or(binder::Status::new_exception_str(
+            binder::ExceptionCode::UNSUPPORTED_OPERATION,
+            Some("shouldn't happen, previous operation succeeded"),
+        ))?;
+        let sealing_key: OpaqueKey = (&key).try_into().map_err(|_| {
+            binder::Status::new_exception_str(
+                binder::ExceptionCode::UNSUPPORTED_OPERATION,
+                Some("shouldn't happen, opaque key was local"),
+            )
+        })?;
+
+        Ok(opaque_key::OpaqueKey::import_token(
+            key_token.keyToken.as_slice(),
+            sealing_key,
+            self.uuid.clone(),
+        )?
+        .into())
     }
 
     fn deriveKey(&self, parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
@@ -326,8 +380,11 @@ impl IHwCryptoKey for HwCryptoKey {
                 Ok(DerivedKey::ExplicitKey(derived_key))
             }
             DerivedKeyPolicy::OpaqueKey(key_policy) => {
-                let derived_key =
-                    derivation_key.derive_opaque_key(key_policy, parameters.context.as_slice())?;
+                let derived_key = derivation_key.derive_opaque_key(
+                    key_policy,
+                    parameters.context.as_slice(),
+                    self.uuid.clone(),
+                )?;
                 Ok(DerivedKey::Opaque(Some(derived_key)))
             }
         }
@@ -343,7 +400,32 @@ impl IHwCryptoKey for HwCryptoKey {
         new_key_policy: &KeyPolicy,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = helpers::aidl_explicit_key_to_rust_key_material(key_to_be_imported)?;
-        Ok(OpaqueKey::import_key_material(new_key_policy, key_material)?)
+        Ok(OpaqueKey::import_key_material(new_key_policy, key_material, self.uuid.clone())?)
+    }
+
+    fn getKeyslotData(&self, keyslot: KeySlot) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
+        self.check_caller_can_access_keyslot(keyslot)?;
+        match keyslot {
+            KeySlot::KEYMINT_SHARED_HMAC_KEY => {
+                let key_generator =
+                    EncryptionHeader::generate_with_version(0, EncryptedContent::KeyMaterial);
+                let mock_hmac_key = key_generator.derive_raw_service_encryption_key(
+                    EncryptionHeaderKey::KeyGenerationContext(b"hmac_key_ctx"),
+                )?;
+                let policy = KeyPolicy {
+                    usage: KeyUse::SIGN,
+                    keyLifetime: KeyLifetime::HARDWARE,
+                    keyPermissions: Vec::new(),
+                    keyType: KeyType::HMAC_SHA256,
+                    keyManagementKey: false,
+                };
+                OpaqueKey::new_opaque_key_from_raw_bytes(&policy, mock_hmac_key, self.uuid.clone())
+            }
+            _ => Err(binder::Status::new_exception_str(
+                binder::ExceptionCode::UNSUPPORTED_OPERATION,
+                Some("Unknown key slot requested"),
+            )),
+        }
     }
 }
 
@@ -351,10 +433,11 @@ impl IHwCryptoKey for HwCryptoKey {
 mod tests {
     use super::*;
     use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, AesKey::AesKey,
-            CipherModeParameters::CipherModeParameters, OperationData::OperationData,
+            CipherModeParameters::CipherModeParameters, HmacKey::HmacKey,
+            HmacOperationParameters::HmacOperationParameters, OperationData::OperationData,
             SymmetricCryptoParameters::SymmetricCryptoParameters,
             SymmetricOperation::SymmetricOperation,
             SymmetricOperationParameters::SymmetricOperationParameters,
@@ -383,9 +466,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let aes_key_material: ExplicitKeyMaterial = ExplicitKeyMaterial::Aes(AesKey::Aes128([
-            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        ]));
+        let aes_key_material: ExplicitKeyMaterial =
+            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
         let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -447,6 +529,56 @@ mod tests {
         expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
     }
 
+    #[test]
+    fn import_clear_hmac_key() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+        let usage = KeyUse::SIGN;
+        let key_type = KeyType::HMAC_SHA256;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let aes_key_material: ExplicitKeyMaterial = ExplicitKeyMaterial::Hmac(HmacKey::Sha256([
+            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
+            10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
+        ]));
+        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
+        let hmac_parameters = HmacOperationParameters { key: Some(key) };
+        let op_parameters = OperationParameters::Hmac(hmac_parameters);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
+        let input_data = OperationData::DataBuffer(b"test data".to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let expected_response = [
+            0x1d, 0x07, 0xd7, 0x52, 0xc2, 0x1a, 0x46, 0x73, 0xd8, 0x0b, 0xc4, 0x9b, 0xc8, 0x27,
+            0xbb, 0x9d, 0x9b, 0x36, 0xe8, 0xfc, 0xec, 0xc1, 0x97, 0x21, 0xb2, 0x83, 0x57, 0x4a,
+            0x18, 0x95, 0x5d, 0xfc,
+        ];
+        expect_eq!(mac, expected_response, "Didn't get back expected mac");
+    }
+
     #[test]
     fn derived_dice_bound_keys() {
         let hw_device_key = HwCryptoKey::new_binder(
@@ -467,7 +599,7 @@ mod tests {
         expect!(key.is_some(), "should have received a key");
         expect!(current_policy, "policy should have been current");
 
-        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::BATCH_KEY);
+        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
         let key_and_policy =
             assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
         let DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: policy } =
@@ -535,4 +667,148 @@ mod tests {
         };
         expect!(!openssl::memcmp::eq(&key1, &key3), "keys shouldn't have matched");
     }
+
+    #[test]
+    fn create_key_tokens() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let aes_key_material: ExplicitKeyMaterial =
+            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
+        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
+
+        let sealing_dice_policy =
+            hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
+
+        let token = key.getShareableToken(&sealing_dice_policy);
+        expect!(token.is_ok(), "couldn't get shareadble token");
+        let token = token.unwrap();
+
+        let nonce = [0u8; 16];
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::ENCRYPT;
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
+        let key = hw_key.keyTokenImport(&token, &sealing_dice_policy);
+        expect!(key.is_ok(), "couldn't import shareable token");
+        let key = key.unwrap();
+
+        //// Decrypting
+        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
+            nonce: nonce.into(),
+        }));
+        let direction = SymmetricOperation::DECRYPT;
+        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
+        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
+        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        let decrypted_msg =
+            String::from_utf8(decrypted_data).expect("couldn't decode received message");
+        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
+    }
+
+    #[test]
+    fn key_token_import_wrong_policy() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+
+        let aes_key_material: ExplicitKeyMaterial =
+            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
+
+        let sealing_dice_policy =
+            hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
+
+        let token = key.getShareableToken(&sealing_dice_policy);
+        expect!(token.is_ok(), "couldn't get shareadble token");
+        let token = token.unwrap();
+
+        let bad_dice_policy = VersionContext::new_current_encrypted(
+            Uuid::new_from_string("f41a7796-975a-427a-8cc4-a73f8820430d").unwrap(),
+        )
+        .expect("couldn't create DICE policy");
+
+        let key = hw_key.keyTokenImport(&token, &bad_dice_policy);
+        expect!(key.is_err(), "shouldn't be able to import key using the wrong DICE policy");
+    }
+
+    #[test]
+    fn get_keyslot() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+
+        let key = hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY);
+        expect!(key.is_ok(), "couldn't get key");
+    }
+
+    #[test]
+    fn get_keyslot_form_unautorized_caller() {
+        let hw_key = HwCryptoKey::new_binder(
+            Uuid::new_from_string("00000000-0000-0000-0000-000000000000")
+                .expect("couldn't create uuid"),
+        );
+        let key = hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY);
+        expect!(key.is_err(), "shouldn't be able to get key");
+    }
 }
diff --git a/hwcryptohal/server/hwcrypto_ipc_server.rs b/hwcryptohal/server/hwcrypto_ipc_server.rs
index a69b2c3..a4f0a2f 100644
--- a/hwcryptohal/server/hwcrypto_ipc_server.rs
+++ b/hwcryptohal/server/hwcrypto_ipc_server.rs
@@ -95,8 +95,8 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
 
 #[cfg(test)]
 mod tests {
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoOperations::IHwCryptoOperations;
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoOperations::IHwCryptoOperations;
     use rpcbinder::RpcSession;
     use binder::{IBinder, Strong};
     use test::expect_eq;
diff --git a/hwcryptohal/server/hwcrypto_operations.rs b/hwcryptohal/server/hwcrypto_operations.rs
index e0a0e53..6b9769d 100644
--- a/hwcryptohal/server/hwcrypto_operations.rs
+++ b/hwcryptohal/server/hwcrypto_operations.rs
@@ -17,12 +17,12 @@
 //! Implementation of the `IHwCryptoOperations` AIDL interface. It can be use to retrieve the
 //! key generation interface and to process cryptographic operations.
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
     CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
     CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
     IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
 };
-use android_hardware_security_see::binder;
+use android_hardware_security_see_hwcrypto::binder;
 use hwcryptohal_common::hwcrypto_err;
 
 use crate::cmd_processing::CmdProcessorContext;
@@ -78,11 +78,12 @@ impl IHwCryptoOperations for HwCryptoOperations {
 mod tests {
     use super::*;
     use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
-            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
-            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
+            HmacOperationParameters::HmacOperationParameters, KeyLifetime::KeyLifetime,
+            KeyType::KeyType, KeyUse::KeyUse, OperationData::OperationData,
+            SymmetricCryptoParameters::SymmetricCryptoParameters,
             SymmetricOperation::SymmetricOperation,
             SymmetricOperationParameters::SymmetricOperationParameters,
         },
@@ -91,7 +92,7 @@ mod tests {
             DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
             DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
             DiceBoundDerivationKey::DiceBoundDerivationKey,
-            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
+            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey, KeySlot::KeySlot,
         },
         KeyPolicy::KeyPolicy,
         OperationParameters::OperationParameters,
@@ -212,4 +213,65 @@ mod tests {
             String::from_utf8(decrypted_data).expect("couldn't decode received message");
         expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
     }
+
+    #[test]
+    fn hmac_simple_test_from_binder() {
+        let hw_key: Strong<dyn IHwCryptoKey> =
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
+
+        let key =
+            hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY).expect("couldn't get key");
+
+        let hw_crypto = hw_key.getHwCryptoOperations().expect("Failed to get crypto ops.");
+
+        let hmac_parameters = HmacOperationParameters { key: Some(key.clone()) };
+        let op_parameters = OperationParameters::Hmac(hmac_parameters);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
+        let input_data = OperationData::DataBuffer("text to be mac'ed".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        //Getting a second mac to compare
+        let hmac_parameters = HmacOperationParameters { key: Some(key) };
+        let op_parameters = OperationParameters::Hmac(hmac_parameters);
+        let mut cmd_list = Vec::<CryptoOperation>::new();
+        let data_output = OperationData::DataBuffer(Vec::new());
+        cmd_list.push(CryptoOperation::DataOutput(data_output));
+        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
+        let input_data = OperationData::DataBuffer("text to be mac'ed".as_bytes().to_vec());
+        cmd_list.push(CryptoOperation::DataInput(input_data));
+        cmd_list.push(CryptoOperation::Finish(None));
+        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
+        let mut crypto_sets = Vec::new();
+        crypto_sets.push(crypto_op_set);
+        let mut additional_error_info =
+            CryptoOperationErrorAdditionalInfo { failingCommandIndex: 0 };
+        hw_crypto
+            .processCommandList(&mut crypto_sets, &mut additional_error_info)
+            .expect("couldn't process commands");
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac2)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        expect_eq!(mac, mac2, "got a different mac");
+    }
 }
diff --git a/hwcryptohal/server/opaque_key.rs b/hwcryptohal/server/opaque_key.rs
index 43ff75f..8bb8564 100644
--- a/hwcryptohal/server/opaque_key.rs
+++ b/hwcryptohal/server/opaque_key.rs
@@ -16,38 +16,55 @@
 
 //! Implementation of the `IOpaqueKey` AIDL interface. It is used as a handle to key material
 
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
+use alloc::collections::btree_map::BTreeMap;
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
     AesCipherMode::AesCipherMode, KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions,
-    KeyType::KeyType, KeyUse::KeyUse, SymmetricCryptoParameters::SymmetricCryptoParameters,
+    KeyType::KeyType, KeyUse::KeyUse, OpaqueKeyToken::OpaqueKeyToken, OperationType::OperationType,
+    ProtectionId::ProtectionId, SymmetricCryptoParameters::SymmetricCryptoParameters,
     SymmetricOperation::SymmetricOperation,
 };
-use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
+    IHwCryptoKey::{
+        DeviceKeyId::DeviceKeyId, DiceBoundDerivationKey::DiceBoundDerivationKey,
+        DiceBoundKeyResult::DiceBoundKeyResult,
+    },
     IOpaqueKey::{BnOpaqueKey, IOpaqueKey},
     KeyPolicy::KeyPolicy,
 };
-use android_hardware_security_see::binder;
+use android_hardware_security_see_hwcrypto::binder;
 use binder::binder_impl::Binder;
 use ciborium::Value;
 use core::fmt;
-use coset::CborSerializable;
+use coset::{AsCborValue, CborSerializable, CoseError};
 use hwcryptohal_common::{
+    aidl_enum_wrapper, cose_enum_gen,
     err::HwCryptoError,
     hwcrypto_err,
-    policy::{self, KeyLifetimeSerializable, KeyTypeSerializable, KeyUseSerializable},
+    policy::{
+        self, cbor_policy_to_aidl, cbor_serialize_key_policy, KeyLifetimeSerializable,
+        KeyTypeSerializable, KeyUseSerializable,
+    },
 };
 use kmr_common::{
     crypto::{self, Aes, CurveType, Hkdf, Hmac, KeyMaterial, OpaqueOr, Rng},
     explicit, FallibleAllocExt,
 };
-use kmr_wire::keymint::EcCurve;
-use std::sync::OnceLock;
+use kmr_wire::{keymint::EcCurve, AsCborValue as _};
+use std::sync::{Mutex, OnceLock};
+use tipc::Uuid;
 
 use crate::crypto_provider;
 use crate::helpers;
+use crate::hwcrypto_device_key::HwCryptoKey;
+use crate::service_encryption_key::{EncryptedContent, EncryptionHeader, EncryptionHeaderKey};
 
 /// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
 const UNIQUE_VALUE_SIZEOF: usize = 32;
 
+const SEALING_KEY_DERIVATION_HMAC_256_CTX: &[u8] = b"SEALING_KEY_DERIVATION_HMAC_256_CTX";
+
+const HW_CRYPTO_WRAP_KEY_HMAC_256_CTX: &[u8] = b"HW_CRYPTO_WRAP_KEY_HMAC_256_CTX";
+
 /// Struct to wrap boot unique counter. It is used to tag objects to the current boot.
 #[derive(Clone)]
 struct BootUniqueValue([u8; UNIQUE_VALUE_SIZEOF]);
@@ -95,6 +112,7 @@ pub(crate) enum HkdfOperationType {
     DiceBoundDerivation = 1,
     ClearKeyDerivation = 3,
     OpaqueKeyDerivation = 4,
+    InternalSealingKeyDerivation = 5,
 }
 
 pub(crate) struct DerivationContext {
@@ -139,12 +157,8 @@ impl DerivationContext {
     }
 }
 
-/// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
-/// the key.
 #[derive(Debug)]
-pub(crate) struct KeyHeader {
-    boot_unique_value: BootUniqueValue,
-    expiration_time: Option<u64>,
+struct KeyHeaderPolicy {
     key_lifetime: KeyLifetimeSerializable,
     key_permissions: Vec<KeyPermissions>,
     key_usage: KeyUseSerializable,
@@ -152,21 +166,11 @@ pub(crate) struct KeyHeader {
     management_key: bool,
 }
 
-impl KeyHeader {
+impl KeyHeaderPolicy {
     fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
-        let boot_unique_value = BootUniqueValue::new()?;
-        Self::new_with_boot_value(policy, boot_unique_value)
-    }
-
-    fn new_with_boot_value(
-        policy: &KeyPolicy,
-        boot_unique_value: BootUniqueValue,
-    ) -> Result<Self, HwCryptoError> {
         let mut key_permissions = Vec::new();
         key_permissions.try_extend_from_slice(&policy.keyPermissions[..])?;
         Ok(Self {
-            boot_unique_value,
-            expiration_time: None,
             key_lifetime: KeyLifetimeSerializable(policy.keyLifetime),
             key_permissions,
             key_usage: KeyUseSerializable(policy.usage),
@@ -191,8 +195,6 @@ impl KeyHeader {
         let mut key_permissions = Vec::new();
         key_permissions.try_extend_from_slice(&self.key_permissions[..])?;
         Ok(Self {
-            boot_unique_value: self.boot_unique_value.clone(),
-            expiration_time: self.expiration_time,
             key_lifetime: self.key_lifetime,
             key_permissions,
             key_usage: self.key_usage,
@@ -202,10 +204,336 @@ impl KeyHeader {
     }
 }
 
+fn check_protection_id_settings(
+    protection_id: &ProtectionIdSerializable,
+    settings: &ProtectionSetting,
+) -> Result<bool, HwCryptoError> {
+    match protection_id.0 {
+        ProtectionId::WIDEVINE_OUTPUT_BUFFER => {
+            // For Widevine buffers we cannot create a key that can read into this area
+            Ok(!settings.read_protection)
+        }
+        _ => Err(hwcrypto_err!(BAD_PARAMETER, "unsupported protection_id {:?}", protection_id,)),
+    }
+}
+
+#[derive(Debug)]
+struct KeyHeaderMetadata {
+    expiration_time: Option<u64>,
+    protection_id_settings: BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
+}
+
+impl KeyHeaderMetadata {
+    fn new() -> Self {
+        Self { expiration_time: None, protection_id_settings: BTreeMap::new() }
+    }
+
+    // While the current metadata definition wouldn't fail on this operation, we are doing this
+    // division to add an element to metadata that could fail while ying to clone
+    fn try_clone(&self) -> Result<Self, HwCryptoError> {
+        let mut protection_id_settings = BTreeMap::new();
+        protection_id_settings.extend(self.protection_id_settings.iter());
+        Ok(Self { expiration_time: None, protection_id_settings })
+    }
+
+    fn add_protection_id(
+        &mut self,
+        protection_id: ProtectionId,
+        allowed_operations: &[OperationType],
+    ) -> Result<(), HwCryptoError> {
+        if allowed_operations.is_empty() {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "didn't receive any allowed operations for add_protection_id",
+            ));
+        }
+        let protection_id = ProtectionIdSerializable::try_from(protection_id)?;
+        if !self.protection_id_settings.contains_key(&protection_id) {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "settings for protection id {:?} have already been set",
+                protection_id
+            ));
+        }
+        let mut protection_setting =
+            ProtectionSetting { write_protection: false, read_protection: false };
+        for operation in allowed_operations {
+            match *operation {
+                OperationType::READ => protection_setting.read_protection = true,
+                OperationType::WRITE => protection_setting.write_protection = true,
+                _ => {
+                    return Err(hwcrypto_err!(
+                        BAD_PARAMETER,
+                        "received unsupported OperationType {:?}",
+                        operation
+                    ))
+                }
+            }
+        }
+        if !check_protection_id_settings(&protection_id, &protection_setting)? {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "unsupported setting for permissions {:?}: {:?}",
+                protection_id,
+                protection_setting
+            ));
+        }
+        self.protection_id_settings.insert(protection_id, protection_setting);
+        Ok(())
+    }
+
+    fn get_metadata_as_cbor(&self) -> Result<Value, HwCryptoError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(2)?;
+
+        // Adding expiration time
+        let expiration_time_value = if let Some(expiration_time) = self.expiration_time {
+            Value::Integer(expiration_time.into())
+        } else {
+            Value::Null
+        };
+        let key = Value::Integer((KeyMetadataCoseLabels::KeyExpirationPeriod as i64).into());
+        cbor_map.push((key, expiration_time_value));
+
+        // Adding protection IDs
+        let mut protection_id_cbor_map = Vec::<(Value, Value)>::new();
+        protection_id_cbor_map.try_reserve(self.protection_id_settings.len())?;
+        for (protection_id, protection_id_setting) in &self.protection_id_settings {
+            let protection_id_key = ciborium::Value::Integer((*protection_id).into());
+            protection_id_cbor_map.push((
+                protection_id_key,
+                protection_id_setting.to_cbor_value().map_err(|_| {
+                    hwcrypto_err!(
+                        BAD_PARAMETER,
+                        "couldn't get cbor representation of protection id setting"
+                    )
+                })?,
+            ))
+        }
+        let key = Value::Integer((KeyMetadataCoseLabels::ProtectionIdSettings as i64).into());
+        cbor_map.push((key, ciborium::Value::Map(protection_id_cbor_map)));
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn set_metadata_from_cbor(&mut self, metadata_as_cbor: Value) -> Result<(), HwCryptoError> {
+        let metadata = metadata_as_cbor
+            .into_map()
+            .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received cbor wasn't a map"))?;
+
+        let mut protection_id_settings: Option<
+            BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
+        > = None;
+        let mut expiration_time: Option<Option<u64>> = None;
+
+        for (map_key, map_val) in metadata {
+            let key = map_key
+                .into_integer()
+                .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received map key wasn't an integer"))?;
+            match key.try_into()? {
+                KeyMetadataCoseLabels::KeyExpirationPeriod => {
+                    expiration_time = if map_val.is_null() {
+                        Some(None)
+                    } else {
+                        let value = map_val
+                            .into_integer()
+                            .map_err(|_| {
+                                hwcrypto_err!(BAD_PARAMETER, "protection id key wasn't an integer")
+                            })?
+                            .try_into()
+                            .map_err(|_| {
+                                hwcrypto_err!(BAD_PARAMETER, "couldn't decode expiration time")
+                            })?;
+                        Some(Some(value))
+                    }
+                }
+                KeyMetadataCoseLabels::ProtectionIdSettings => {
+                    let mut settings = BTreeMap::new();
+                    for (protection_id, protection_setting) in map_val
+                        .into_map()
+                        .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received cbor wasn't a map"))?
+                    {
+                        //settings.try_reserve(1).map_err(|_| CoseError::EncodeFailed)?;
+                        let protection_id: ProtectionIdSerializable = protection_id
+                            .into_integer()
+                            .map_err(|_| {
+                                hwcrypto_err!(BAD_PARAMETER, "protection id key wasn't an integer")
+                            })?
+                            .try_into()
+                            .map_err(|_| {
+                                hwcrypto_err!(BAD_PARAMETER, "couldn't decode protection ID")
+                            })?;
+                        let protection_setting =
+                            ProtectionSetting::from_cbor_value(protection_setting)?;
+                        if settings.contains_key(&protection_id) {
+                            return Err(hwcrypto_err!(
+                                BAD_PARAMETER,
+                                "received duplicated protection ID entry"
+                            ));
+                        }
+                        settings.insert(protection_id, protection_setting);
+                    }
+                    protection_id_settings = Some(settings);
+                }
+            }
+        }
+        self.expiration_time = expiration_time
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "didn't find expiration time on metadata"))?;
+        self.protection_id_settings = protection_id_settings.ok_or(hwcrypto_err!(
+            BAD_PARAMETER,
+            "didn't find protection_ id settings on metadata"
+        ))?;
+        Ok(())
+    }
+}
+
+/// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
+/// the key.
+#[derive(Debug)]
+pub(crate) struct KeyHeader {
+    boot_unique_value: BootUniqueValue,
+    key_policy: KeyHeaderPolicy,
+    key_metadata: Mutex<KeyHeaderMetadata>,
+}
+
+impl KeyHeader {
+    fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
+        let boot_unique_value = BootUniqueValue::new()?;
+        Self::new_with_boot_value(policy, boot_unique_value)
+    }
+
+    fn new_with_boot_value(
+        policy: &KeyPolicy,
+        boot_unique_value: BootUniqueValue,
+    ) -> Result<Self, HwCryptoError> {
+        let key_policy = KeyHeaderPolicy::new(policy)?;
+        let key_metadata = Mutex::new(KeyHeaderMetadata::new());
+        Ok(Self { boot_unique_value, key_policy, key_metadata })
+    }
+
+    fn get_policy(&self) -> Result<KeyPolicy, HwCryptoError> {
+        self.key_policy.get_policy()
+    }
+
+    fn try_clone(&self) -> Result<Self, HwCryptoError> {
+        let key_policy = self.key_policy.try_clone()?;
+        let key_metadata = self.key_metadata.lock()?.try_clone()?;
+        Ok(Self {
+            boot_unique_value: self.boot_unique_value.clone(),
+            key_policy,
+            key_metadata: Mutex::new(key_metadata),
+        })
+    }
+
+    fn get_metadata_as_cbor(&self) -> Result<Value, HwCryptoError> {
+        self.key_metadata.lock()?.get_metadata_as_cbor()
+    }
+
+    fn set_metadata_from_cbor(&mut self, metadata_as_cbor: Value) -> Result<(), HwCryptoError> {
+        self.key_metadata.lock()?.set_metadata_from_cbor(metadata_as_cbor)
+    }
+}
+
+cose_enum_gen! {
+    enum OpaqueKeyCoseLabels {
+        KeyMaterial = -66000,
+        KeyPolicy = -66001,
+        BootValue = -66002,
+        KeyMetadata = -66003,
+    }
+}
+
+cose_enum_gen! {
+    enum ProtectionSettingsCoseLabels {
+        WriteProtection = -67000,
+        ReadProtection = -67001,
+    }
+}
+
+cose_enum_gen! {
+    enum KeyMetadataCoseLabels {
+        KeyExpirationPeriod = -68000,
+        ProtectionIdSettings = -68001,
+    }
+}
+
+aidl_enum_wrapper! {
+    aidl_name: ProtectionId,
+    wrapper_name: ProtectionIdSerializable,
+    fields: [WIDEVINE_OUTPUT_BUFFER]
+}
+
+#[derive(Debug, Copy, Clone)]
+struct ProtectionSetting {
+    write_protection: bool,
+    read_protection: bool,
+}
+
+impl AsCborValue for ProtectionSetting {
+    fn to_cbor_value(self) -> Result<Value, CoseError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
+
+        let key = Value::Integer((ProtectionSettingsCoseLabels::WriteProtection as i64).into());
+        let value = Value::Bool(self.write_protection.into());
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((ProtectionSettingsCoseLabels::ReadProtection as i64).into());
+        let value = Value::Bool(self.read_protection.into());
+        cbor_map.push((key, value));
+
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
+        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+        if opaque_key_map.len() != 2 {
+            return Err(CoseError::ExtraneousData);
+        }
+
+        let mut write_protection: Option<bool> = None;
+        let mut read_protection: Option<bool> = None;
+        for (map_key, map_val) in opaque_key_map {
+            match map_key {
+                Value::Integer(key) => match key.try_into()? {
+                    ProtectionSettingsCoseLabels::WriteProtection => {
+                        write_protection = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
+                    }
+                    ProtectionSettingsCoseLabels::ReadProtection => {
+                        read_protection = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
+                    }
+                },
+                _ => return Err(CoseError::ExtraneousData),
+            }
+        }
+
+        let write_protection = write_protection.ok_or(CoseError::EncodeFailed)?;
+        let read_protection = read_protection.ok_or(CoseError::EncodeFailed)?;
+
+        Ok(Self { write_protection, read_protection })
+    }
+}
+
+fn get_dice_sealing_key_derivation_context() -> Result<Vec<u8>, HwCryptoError> {
+    let mut context = Vec::<u8>::new();
+
+    context.try_reserve(SEALING_KEY_DERIVATION_HMAC_256_CTX.len() + UNIQUE_VALUE_SIZEOF)?;
+    context.extend_from_slice(SEALING_KEY_DERIVATION_HMAC_256_CTX);
+    context.extend_from_slice(&get_boot_unique_value()?.0);
+
+    Ok(context)
+}
+
 /// `IOpaqueKey` implementation.
 pub struct OpaqueKey {
     pub(crate) key_header: KeyHeader,
     pub(crate) key_material: KeyMaterial,
+    pub(crate) key_in_owner_control: bool,
+}
+
+impl From<OpaqueKey> for binder::Strong<dyn IOpaqueKey> {
+    fn from(value: OpaqueKey) -> binder::Strong<dyn IOpaqueKey> {
+        BnOpaqueKey::new_binder(value, binder::BinderFeatures::default())
+    }
 }
 
 impl TryFrom<&binder::Strong<dyn IOpaqueKey>> for OpaqueKey {
@@ -227,14 +555,95 @@ impl TryFrom<&binder::Strong<dyn IOpaqueKey>> for OpaqueKey {
     }
 }
 
+impl AsCborValue for OpaqueKey {
+    fn to_cbor_value(self) -> Result<Value, CoseError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(4).map_err(|_| CoseError::EncodeFailed)?;
+        let key = Value::Integer((OpaqueKeyCoseLabels::KeyPolicy as i64).into());
+        let key_policy = self.getKeyPolicy().map_err(|_| CoseError::EncodeFailed)?;
+        let cbor_key_policy =
+            cbor_serialize_key_policy(&key_policy).map_err(|_| CoseError::EncodeFailed)?;
+        cbor_map.push((key, Value::Bytes(cbor_key_policy)));
+
+        let key = Value::Integer((OpaqueKeyCoseLabels::KeyMaterial as i64).into());
+        cbor_map
+            .push((key, self.key_material.to_cbor_value().map_err(|_| CoseError::EncodeFailed)?));
+
+        let key = Value::Integer((OpaqueKeyCoseLabels::BootValue as i64).into());
+        let mut boot_value = Vec::new();
+        boot_value
+            .try_reserve(self.key_header.boot_unique_value.0.len())
+            .map_err(|_| CoseError::EncodeFailed)?;
+        boot_value.extend_from_slice(&self.key_header.boot_unique_value.0);
+        cbor_map.push((key, Value::Bytes(boot_value)));
+
+        let key = Value::Integer((OpaqueKeyCoseLabels::KeyMetadata as i64).into());
+        cbor_map.push((
+            key,
+            self.key_header.get_metadata_as_cbor().map_err(|_| CoseError::EncodeFailed)?,
+        ));
+
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
+        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+        if opaque_key_map.len() != 4 {
+            return Err(CoseError::ExtraneousData);
+        }
+        let mut key_material: Option<KeyMaterial> = None;
+        let mut key_policy: Option<KeyPolicy> = None;
+        let mut boot_value: Option<BootUniqueValue> = None;
+        let mut key_metadata: Option<Value> = None;
+        for (map_key, map_val) in opaque_key_map {
+            match map_key {
+                Value::Integer(key) => match key.try_into()? {
+                    OpaqueKeyCoseLabels::KeyMaterial => {
+                        key_material = Some(
+                            KeyMaterial::from_cbor_value(map_val)
+                                .map_err(|_| CoseError::EncodeFailed)?,
+                        )
+                    }
+                    OpaqueKeyCoseLabels::KeyPolicy => {
+                        let policy_bytes = map_val.as_bytes().ok_or(CoseError::EncodeFailed)?;
+                        key_policy = Some(
+                            cbor_policy_to_aidl(policy_bytes.as_slice())
+                                .map_err(|_| CoseError::EncodeFailed)?,
+                        )
+                    }
+                    OpaqueKeyCoseLabels::BootValue => {
+                        let boot_value_bytes = map_val.as_bytes().ok_or(CoseError::EncodeFailed)?;
+                        boot_value = Some(BootUniqueValue(
+                            (boot_value_bytes.clone())
+                                .try_into()
+                                .map_err(|_| CoseError::EncodeFailed)?,
+                        ))
+                    }
+                    OpaqueKeyCoseLabels::KeyMetadata => key_metadata = Some(map_val),
+                },
+                _ => return Err(CoseError::ExtraneousData),
+            }
+        }
+        let key_material = key_material.ok_or(CoseError::EncodeFailed)?;
+        let key_policy = key_policy.ok_or(CoseError::EncodeFailed)?;
+        let boot_value = boot_value.ok_or(CoseError::EncodeFailed)?;
+        let mut key_header = KeyHeader::new_with_boot_value(&key_policy, boot_value)
+            .map_err(|_| CoseError::EncodeFailed)?;
+        let key_metadata = key_metadata.ok_or(CoseError::EncodeFailed)?;
+        key_header.set_metadata_from_cbor(key_metadata).map_err(|_| CoseError::EncodeFailed)?;
+        Ok(OpaqueKey { key_material, key_header, key_in_owner_control: false })
+    }
+}
+
 impl OpaqueKey {
     pub(crate) fn new_binder(
         policy: &KeyPolicy,
         key_material: KeyMaterial,
+        _connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_header = KeyHeader::new(policy)?;
         check_key_material_with_policy(&key_material, policy)?;
-        let opaque_key = OpaqueKey { key_header, key_material };
+        let opaque_key = OpaqueKey { key_header, key_material, key_in_owner_control: true };
         let opaque_keybinder =
             BnOpaqueKey::new_binder(opaque_key, binder::BinderFeatures::default());
         Ok(opaque_keybinder)
@@ -253,31 +662,121 @@ impl OpaqueKey {
     pub(crate) fn import_key_material(
         policy: &KeyPolicy,
         key_material: KeyMaterial,
+        connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         check_key_material_with_policy(&key_material, policy)?;
         Self::check_clear_import_policy(policy)?;
-        Self::new_binder(policy, key_material)
+        Self::new_binder(policy, key_material, connection_info)
+    }
+
+    fn check_ownership(&self) -> bool {
+        self.key_in_owner_control
+    }
+
+    // Create a key token sealed using the receiver DICE policy. This means that only the
+    // intended token receiver can import this token. The token has 2 levels of encryption,
+    // the outer layer is provided by a device key bounded to the HwCrypto service and the
+    // outer layer is generated using the receiver DICE policy.
+    fn create_token(&self, sealing_dice_policy: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
+        if !self.check_ownership() {
+            // We haven't created this key, so we cannot export it
+            // TODO: Change the error type to UNAUTORIZED
+            return Err(hwcrypto_err!(GENERIC_ERROR, "only the owner of a key can export it"));
+        }
+        let key: OpaqueKey = self.try_clone()?;
+        let token_creator = EncryptionHeader::generate(EncryptedContent::KeyMaterial)?;
+
+        // This is a temporary workaround to create a DICE bound key because we will move to
+        // using DICE policies and the AuthMgr instead of UUIDs.
+        let hw_device_key = HwCryptoKey {
+            uuid: Uuid::new_from_string("ffffffff-ffff-ffff-ffff-ffffffffffff")
+                .expect("shouldn't happen, string can be parsed to uuid"),
+        };
+
+        // Create a DICE key bound to the receiver policy.
+        let DiceBoundKeyResult { diceBoundKey: sealing_dice_key, dicePolicyWasCurrent: _ } =
+            hw_device_key.derive_dice_policy_bound_key(
+                &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
+                sealing_dice_policy,
+                false,
+            )?;
+        let sealing_dice_key: OpaqueKey = sealing_dice_key
+            .as_ref()
+            .ok_or(hwcrypto_err!(GENERIC_ERROR, "shouldn't happen, sealing key is local"))?
+            .try_into()?;
+        let context = get_dice_sealing_key_derivation_context()?;
+        let sealing_key = sealing_dice_key
+            .derive_internal_sealing_key(&context, get_key_size_in_bytes(&KeyType::HMAC_SHA256)?)?;
+        // Inner encryption using the DICE policy bound key
+        let inner_content = token_creator.encrypt_content_service_encryption_key(
+            EncryptionHeaderKey::ProvidedHkdfKey(sealing_key),
+            key,
+        )?;
+
+        // External encryption using the HwCrypto service key
+        let token_creator = EncryptionHeader::generate(EncryptedContent::WrappedKeyMaterial)?;
+        let content = token_creator.encrypt_content_service_encryption_key(
+            EncryptionHeaderKey::KeyGenerationContext(HW_CRYPTO_WRAP_KEY_HMAC_256_CTX),
+            Value::Bytes(inner_content),
+        )?;
+        Ok(content)
+    }
+
+    pub(crate) fn import_token(
+        key_token: &[u8],
+        sealing_dice_key: OpaqueKey,
+        _connection_information: Uuid,
+    ) -> Result<Self, HwCryptoError> {
+        // External encryption layer used a HwCrypto service device key
+        let (_, content) = EncryptionHeader::decrypt_content_service_encryption_key(
+            key_token,
+            EncryptionHeaderKey::KeyGenerationContext(HW_CRYPTO_WRAP_KEY_HMAC_256_CTX),
+            EncryptedContent::WrappedKeyMaterial,
+        )?;
+
+        let context = get_dice_sealing_key_derivation_context()?;
+        // Preparing internal encryption DICE policy bound key
+        let sealing_key = sealing_dice_key
+            .derive_internal_sealing_key(&context, get_key_size_in_bytes(&KeyType::HMAC_SHA256)?)?;
+
+        let cbor_bytes = Value::from_slice(content.as_slice())?;
+        let inner_content = cbor_bytes.as_bytes().ok_or(hwcrypto_err!(
+            GENERIC_ERROR,
+            "shouldn't happen, inner content was encrypted by us"
+        ))?;
+
+        let (_, inner_key) = EncryptionHeader::decrypt_content_service_encryption_key(
+            &inner_content,
+            EncryptionHeaderKey::ProvidedHkdfKey(sealing_key),
+            EncryptedContent::KeyMaterial,
+        )?;
+
+        let opaque_key = Self::from_cbor_value(Value::from_slice(inner_key.as_slice())?)?;
+        Ok(opaque_key)
     }
 
     #[allow(unused)]
     pub(crate) fn generate_opaque_key(
         policy: &KeyPolicy,
+        connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = generate_key_material(&policy.keyType, None)?;
-        OpaqueKey::new_binder(policy, key_material)
+        OpaqueKey::new_binder(policy, key_material, connection_info)
     }
+
     fn try_clone(&self) -> Result<Self, HwCryptoError> {
         let key_header = self.key_header.try_clone()?;
         let key_material = self.key_material.clone();
-        Ok(OpaqueKey { key_header, key_material })
+        Ok(OpaqueKey { key_header, key_material, key_in_owner_control: self.key_in_owner_control })
     }
 
-    fn new_opaque_key_from_raw_bytes(
+    pub(crate) fn new_opaque_key_from_raw_bytes(
         policy: &KeyPolicy,
         key_material: Vec<u8>,
+        connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = generate_key_material(&policy.keyType, Some(key_material))?;
-        OpaqueKey::new_binder(policy, key_material)
+        OpaqueKey::new_binder(policy, key_material, connection_info)
     }
 
     pub(crate) fn check_key_derivation_parameters(
@@ -323,21 +822,40 @@ impl OpaqueKey {
         }
     }
 
-    pub(crate) fn derive_clear_key_material(
+    fn derive_clear_key_from_derivation_context(
         &self,
+        mut op_context: DerivationContext,
         context: &[u8],
         derived_key_size: usize,
     ) -> Result<Vec<u8>, HwCryptoError> {
-        let mut op_context = DerivationContext::new(HkdfOperationType::ClearKeyDerivation)?;
         op_context.add_unsigned_integer(derived_key_size as u64)?;
         op_context.add_binary_string(context)?;
         self.derive_raw_key_material(op_context, derived_key_size)
     }
 
+    pub(crate) fn derive_internal_sealing_key(
+        &self,
+        context: &[u8],
+        derived_key_size: usize,
+    ) -> Result<Vec<u8>, HwCryptoError> {
+        let op_context = DerivationContext::new(HkdfOperationType::InternalSealingKeyDerivation)?;
+        self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
+    }
+
+    pub(crate) fn derive_clear_key_material(
+        &self,
+        context: &[u8],
+        derived_key_size: usize,
+    ) -> Result<Vec<u8>, HwCryptoError> {
+        let op_context = DerivationContext::new(HkdfOperationType::ClearKeyDerivation)?;
+        self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
+    }
+
     pub(crate) fn derive_opaque_key(
         &self,
         policy: &[u8],
         context: &[u8],
+        connection_info: Uuid,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let aidl_policy = policy::cbor_policy_to_aidl(policy)?;
         self.check_key_derivation_parameters(&aidl_policy)?;
@@ -346,16 +864,16 @@ impl OpaqueKey {
         op_context.add_binary_string(policy)?;
         op_context.add_binary_string(context)?;
         let raw_key_material = self.derive_raw_key_material(op_context, derived_key_size)?;
-        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material)
+        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material, connection_info)
     }
 
     fn derivation_allowed_lifetime(
         &self,
         derived_key_lifetime: KeyLifetime,
     ) -> Result<bool, HwCryptoError> {
-        validate_lifetime(self.key_header.key_lifetime.0)?;
+        validate_lifetime(self.key_header.key_policy.key_lifetime.0)?;
         validate_lifetime(derived_key_lifetime)?;
-        match self.key_header.key_lifetime.0 {
+        match self.key_header.key_policy.key_lifetime.0 {
             //ephemeral keys can be used to derive/wrap any other key
             KeyLifetime::EPHEMERAL => Ok(true),
             KeyLifetime::HARDWARE => {
@@ -377,7 +895,7 @@ impl OpaqueKey {
             _ => Err(hwcrypto_err!(
                 UNSUPPORTED,
                 "unsupported Key lifetime {:?}",
-                self.key_header.key_lifetime
+                self.key_header.key_policy.key_lifetime
             )),
         }
     }
@@ -387,18 +905,25 @@ impl OpaqueKey {
             KeyMaterial::Hmac(_) => Ok(()),
             _ => Err(hwcrypto_err!(UNSUPPORTED, "Only HMAC keys can be used for key derivation")),
         }?;
-        if self.key_header.key_usage.0 != KeyUse::DERIVE {
+        if self.key_header.key_policy.key_usage.0 != KeyUse::DERIVE {
             return Err(hwcrypto_err!(BAD_PARAMETER, "key was not exclusively a derive key"));
         }
         Ok(())
     }
 
     pub(crate) fn key_usage_supported(&self, usage: KeyUse) -> bool {
-        (usage.0 & self.key_header.key_usage.0 .0) == usage.0
+        (usage.0 & self.key_header.key_policy.key_usage.0 .0) == usage.0
     }
 
     pub fn get_key_type(&self) -> KeyType {
-        self.key_header.key_type.0
+        self.key_header.key_policy.key_type.0
+    }
+
+    pub fn supports_pattern_encryption(&self) -> Result<(), HwCryptoError> {
+        match self.key_header.key_policy.key_type.0 {
+            KeyType::AES_128_CBC_NO_PADDING => Ok(()),
+            _ => Err(hwcrypto_err!(BAD_PARAMETER, "only AES CBC supports pattern encryption")),
+        }
     }
 
     /// Checks if the requested operation (encrypt/decrypt) can be done with this key
@@ -435,6 +960,22 @@ impl OpaqueKey {
             },
         }
     }
+
+    fn add_protection_id(
+        &self,
+        protection_id: ProtectionId,
+        allowed_operations: &[OperationType],
+    ) -> Result<(), HwCryptoError> {
+        if !self.check_ownership() {
+            // We haven't created this key, so we cannot export it
+            // TODO: Change the error type to UNAUTORIZED
+            return Err(hwcrypto_err!(
+                GENERIC_ERROR,
+                "only the owner of a key can modify protection IDs"
+            ));
+        }
+        self.key_header.key_metadata.lock()?.add_protection_id(protection_id, allowed_operations)
+    }
 }
 
 impl binder::Interface for OpaqueKey {}
@@ -460,6 +1001,18 @@ impl IOpaqueKey for OpaqueKey {
             Some("get_public_key has not been implemented yet"),
         ))
     }
+
+    fn getShareableToken(&self, sealing_dice_policy: &[u8]) -> binder::Result<OpaqueKeyToken> {
+        Ok(OpaqueKeyToken { keyToken: self.create_token(sealing_dice_policy)? })
+    }
+
+    fn setProtectionId(
+        &self,
+        protection_id: ProtectionId,
+        allowed_operations: &[OperationType],
+    ) -> Result<(), binder::Status> {
+        Ok(self.add_protection_id(protection_id, allowed_operations)?)
+    }
 }
 
 pub(crate) fn check_key_material_with_policy(
@@ -509,9 +1062,29 @@ pub(crate) fn check_key_material_with_policy(
         }
         KeyMaterial::Hmac(hmac_key) => match hmac_key {
             OpaqueOr::Opaque(_) => Err(hwcrypto_err!(BAD_PARAMETER, "opaque HMAC key provided")),
-            OpaqueOr::Explicit(_) => match *key_type {
-                KeyType::HMAC_SHA256 => Ok(()),
-                KeyType::HMAC_SHA512 => Ok(()),
+            OpaqueOr::Explicit(km) => match *key_type {
+                KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
+                    let expected_size = get_key_size_in_bytes(key_type)?;
+                    let km_size = km.0.len();
+                    match policy.usage {
+                        KeyUse::SIGN | KeyUse::DERIVE => Ok(()),
+                        _ => Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "wrong key use for hmac key, received {:?}",
+                            policy.usage
+                        )),
+                    }?;
+                    if km_size == expected_size {
+                        Ok(())
+                    } else {
+                        Err(hwcrypto_err!(
+                            BAD_PARAMETER,
+                            "bad len for hmac key received {} bytes, expected {} bytes",
+                            km_size,
+                            expected_size
+                        ))
+                    }
+                }
                 _ => Err(hwcrypto_err!(
                     BAD_PARAMETER,
                     "type mismatch for HMAC key key type: {:?}",
diff --git a/hwcryptohal/server/service_encryption_key.rs b/hwcryptohal/server/service_encryption_key.rs
index 8bb1e66..62f31c9 100644
--- a/hwcryptohal/server/service_encryption_key.rs
+++ b/hwcryptohal/server/service_encryption_key.rs
@@ -40,43 +40,136 @@ const ZERO_NONCE: [u8; 12] = [0u8; 12];
 
 const KEY_DERIVATION_CTX_COSE_LABEL: i64 = -65539;
 const KEY_DERIVATION_VERSION_COSE_LABEL: i64 = -65540;
+const WRAPPED_CONTENT_TYPE_COSE_LABEL: i64 = -65541;
+
+// `EncryptionHeaderKey` defines if we derive a device key bound to HwCrypto service or if we use a
+// provided key for that. This key will then be used to encrypt some content.
+pub(crate) enum EncryptionHeaderKey<'a> {
+    // `KeyGenerationContext` will be used to derive a key from a key bounded to HwCrypto service
+    KeyGenerationContext(&'a [u8]),
+    // `ProvidedHkdfKey` will be directly fed to the hkdf algorithm.
+    ProvidedHkdfKey(Vec<u8>),
+}
+
+#[derive(Copy, Clone, Debug, PartialEq)]
+pub(crate) enum EncryptedContent {
+    DicePolicy = 1,
+    WrappedKeyMaterial = 2,
+    KeyMaterial = 3,
+}
+
+impl TryFrom<u64> for EncryptedContent {
+    type Error = HwCryptoError;
+
+    fn try_from(value: u64) -> Result<Self, Self::Error> {
+        match value {
+            x if x == EncryptedContent::DicePolicy as u64 => Ok(EncryptedContent::DicePolicy),
+            x if x == EncryptedContent::WrappedKeyMaterial as u64 => {
+                Ok(EncryptedContent::WrappedKeyMaterial)
+            }
+            x if x == EncryptedContent::KeyMaterial as u64 => Ok(EncryptedContent::KeyMaterial),
+            _ => Err(hwcrypto_err!(
+                SERIALIZATION_ERROR,
+                "invalid value for EncryptedContent: {}",
+                value
+            )),
+        }
+    }
+}
+
+impl TryFrom<ciborium::value::Integer> for EncryptedContent {
+    type Error = HwCryptoError;
+
+    fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
+        let value: u64 = value.try_into().map_err(|_| {
+            hwcrypto_err!(SERIALIZATION_ERROR, "couldn't convert CBOR integer into u64")
+        })?;
+        Ok(value.try_into().map_err(|_| {
+            hwcrypto_err!(
+                SERIALIZATION_ERROR,
+                "Error converting encrypted content type from ciborium value"
+            )
+        })?)
+    }
+}
+
+impl From<EncryptedContent> for ciborium::value::Integer {
+    fn from(value: EncryptedContent) -> Self {
+        (value as u64).into()
+    }
+}
 
 // Header used to derive a different key per each encrypted context. Encryption of the context is
 // similar to what KeyMint does to wrap keys.
 pub(crate) struct EncryptionHeader {
     key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
     header_version: u32,
+    wrapped_content_type: EncryptedContent,
 }
 
 impl EncryptionHeader {
-    fn new(key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH], header_version: u32) -> Self {
-        Self { key_derivation_context, header_version }
+    fn new(
+        key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
+        header_version: u32,
+        wrapped_content_type: EncryptedContent,
+    ) -> Self {
+        Self { key_derivation_context, header_version, wrapped_content_type }
     }
 
-    pub(crate) fn generate() -> Result<Self, HwCryptoError> {
+    pub(crate) fn generate(wrapped_content_type: EncryptedContent) -> Result<Self, HwCryptoError> {
         let header_version = get_service_current_version()?;
-        Ok(Self::generate_with_version(header_version))
+        Ok(Self::generate_with_version(header_version, wrapped_content_type))
     }
 
-    pub(crate) fn generate_with_version(header_version: u32) -> Self {
+    pub(crate) fn generate_with_version(
+        header_version: u32,
+        wrapped_content_type: EncryptedContent,
+    ) -> Self {
         let key_derivation_context = get_new_key_derivation_context();
-        Self::new(key_derivation_context, header_version)
+        Self::new(key_derivation_context, header_version, wrapped_content_type)
     }
 
     // Function used to generate different device bound encryption keys tied to the HWCrypto service
     // to be used for different purposes, which include VersionContext encryption and key wrapping.
-    fn derive_service_encryption_key(
+    pub(crate) fn derive_raw_service_encryption_key(
         &self,
-        key_context: &[u8],
-    ) -> Result<crypto::aes::Key, HwCryptoError> {
-        let encryption_key = get_encryption_key(self.header_version, key_context)?;
+        encryption_key: EncryptionHeaderKey,
+    ) -> Result<Vec<u8>, HwCryptoError> {
+        let encryption_key = match encryption_key {
+            EncryptionHeaderKey::KeyGenerationContext(key_context) => {
+                get_encryption_key(self.header_version, key_context)?
+            }
+            EncryptionHeaderKey::ProvidedHkdfKey(key) => {
+                if key.len() != SERVICE_KEK_LENGTH {
+                    return Err(hwcrypto_err!(
+                        INVALID_KEY,
+                        "We only support hkdf keys of length {}",
+                        SERVICE_KEK_LENGTH
+                    ));
+                }
+                key
+            }
+        };
         derive_key_hkdf(&encryption_key, &self.key_derivation_context[..])
     }
 
+    pub(crate) fn derive_service_encryption_key(
+        &self,
+        encryption_key: EncryptionHeaderKey,
+    ) -> Result<crypto::aes::Key, HwCryptoError> {
+        let raw_key = self.derive_raw_service_encryption_key(encryption_key)?;
+        let key_material = crypto::aes::Key::Aes256(
+            raw_key
+                .try_into()
+                .expect("should not fail, call with SERVICE_KEK_LENGTH returns 32 bytes"),
+        );
+        Ok(key_material)
+    }
+
     /// Encrypt CBOR serializable data using a device key derived using `key_context`
     pub(crate) fn encrypt_content_service_encryption_key<T: AsCborValue>(
         &self,
-        key_context: &[u8],
+        key_context: EncryptionHeaderKey,
         content: T,
     ) -> Result<Vec<u8>, HwCryptoError> {
         let kek = self.derive_service_encryption_key(key_context)?;
@@ -106,12 +199,21 @@ impl EncryptionHeader {
     /// include an `EncryptionHeader` on the COSE protected header.
     pub(crate) fn decrypt_content_service_encryption_key(
         encrypted_context: &[u8],
-        key_context: &[u8],
+        key_context: EncryptionHeaderKey,
+        wrapped_content_type: EncryptedContent,
     ) -> Result<(Self, Vec<u8>), HwCryptoError> {
         let context: coset::CoseEncrypt0 = coset::CborSerializable::from_slice(encrypted_context)?;
         let encryption_header: EncryptionHeader = (&context.protected).try_into()?;
         let kek = encryption_header.derive_service_encryption_key(key_context)?;
 
+        if encryption_header.wrapped_content_type != wrapped_content_type {
+            return Err(hwcrypto_err!(
+                BAD_PARAMETER,
+                "provided content has wrong content. Expected {:?}",
+                wrapped_content_type
+            ));
+        }
+
         let aes = crypto_provider::AesImpl;
         let mut op = aes.begin_aead(
             kek.into(),
@@ -139,15 +241,16 @@ impl TryFrom<&ProtectedHeader> for EncryptionHeader {
 
     fn try_from(value: &ProtectedHeader) -> Result<EncryptionHeader, Self::Error> {
         let cose_header_rest = &value.header.rest;
-        if cose_header_rest.len() != 2 {
+        if cose_header_rest.len() != 3 {
             return Err(hwcrypto_err!(
                 BAD_PARAMETER,
-                "header length was {} instead of 2",
+                "header length was {} instead of 3",
                 cose_header_rest.len()
             ));
         }
         let mut key_derivation_context = None;
         let mut header_version = None;
+        let mut wrapped_content_type: Option<EncryptedContent> = None;
         for element in cose_header_rest {
             let label: i64 = element
                 .0
@@ -177,6 +280,18 @@ impl TryFrom<&ProtectedHeader> for EncryptionHeader {
                 KEY_DERIVATION_VERSION_COSE_LABEL => {
                     header_version = Some(parse_cborium_u32(&element.1, "header version")?);
                 }
+                WRAPPED_CONTENT_TYPE_COSE_LABEL => {
+                    wrapped_content_type = Some(
+                        element
+                            .1
+                            .as_integer()
+                            .ok_or(hwcrypto_err!(
+                                BAD_PARAMETER,
+                                "wrapped_content_type was not an integer"
+                            ))?
+                            .try_into()?,
+                    );
+                }
                 _ => return Err(hwcrypto_err!(BAD_PARAMETER, "unknown label {}", label)),
             }
         }
@@ -184,7 +299,9 @@ impl TryFrom<&ProtectedHeader> for EncryptionHeader {
             .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse key context"))?;
         let header_version = header_version
             .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse header version"))?;
-        Ok(Self::new(key_derivation_context, header_version))
+        let wrapped_content_type = wrapped_content_type
+            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse content type"))?;
+        Ok(Self::new(key_derivation_context, header_version, wrapped_content_type))
     }
 }
 
@@ -198,6 +315,10 @@ impl TryFrom<&EncryptionHeader> for Header {
             .algorithm(coset::iana::Algorithm::A256GCM)
             .value(KEY_DERIVATION_CTX_COSE_LABEL, Value::Bytes(key_derivation_context))
             .value(KEY_DERIVATION_VERSION_COSE_LABEL, Value::Integer(value.header_version.into()))
+            .value(
+                WRAPPED_CONTENT_TYPE_COSE_LABEL,
+                Value::Integer(value.wrapped_content_type.into()),
+            )
             .build();
         Ok(cose_header)
     }
@@ -225,13 +346,9 @@ fn get_encryption_key(header_version: u32, key_context: &[u8]) -> Result<Vec<u8>
 fn derive_key_hkdf(
     derivation_key: &[u8],
     derivation_context: &[u8],
-) -> Result<crypto::aes::Key, HwCryptoError> {
+) -> Result<Vec<u8>, HwCryptoError> {
     let kdf = crypto_provider::HmacImpl;
-    let raw_key = kdf.hkdf(&[], &derivation_key, &derivation_context, SERVICE_KEK_LENGTH)?;
-    let key_material = crypto::aes::Key::Aes256(
-        raw_key.try_into().expect("should not fail, call with SERVICE_KEK_LENGTH returns 32 bytes"),
-    );
-    Ok(key_material)
+    Ok(kdf.hkdf(&[], &derivation_key, &derivation_context, SERVICE_KEK_LENGTH)?)
 }
 
 fn get_new_key_derivation_context() -> [u8; KEY_DERIVATION_CTX_LENGTH] {
@@ -292,18 +409,19 @@ mod tests {
 
     #[test]
     fn header_encryption_decryption() {
-        let header = EncryptionHeader::generate();
+        let header = EncryptionHeader::generate(EncryptedContent::DicePolicy);
         expect!(header.is_ok(), "couldn't generate header");
         let header = header.unwrap();
         let encrypted_content = header.encrypt_content_service_encryption_key(
-            b"fake_context",
+            EncryptionHeaderKey::KeyGenerationContext(b"fake_context"),
             Value::Bytes(b"test_data".to_vec()),
         );
         expect!(encrypted_content.is_ok(), "couldn't generate header");
         let encrypted_content = encrypted_content.unwrap();
         let decrypted_data = EncryptionHeader::decrypt_content_service_encryption_key(
             &encrypted_content[..],
-            b"fake_context",
+            EncryptionHeaderKey::KeyGenerationContext(b"fake_context"),
+            EncryptedContent::DicePolicy,
         );
         expect!(decrypted_data.is_ok(), "couldn't generate header");
         let (decrypted_header, decrypted_content) = decrypted_data.unwrap();
diff --git a/hwcryptokey-test/aes_vectors.rs b/hwcryptokey-test/aes_vectors.rs
index 4bca737..4c5c5a9 100644
--- a/hwcryptokey-test/aes_vectors.rs
+++ b/hwcryptokey-test/aes_vectors.rs
@@ -17,7 +17,7 @@
 mod tests {
     pub(crate) const RUST_HWCRYPTO_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
 
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, AesKey::AesKey,
             CipherModeParameters::CipherModeParameters, ExplicitKeyMaterial::ExplicitKeyMaterial,
diff --git a/hwcryptokey-test/rules.mk b/hwcryptokey-test/rules.mk
index af080dd..ee3de2e 100644
--- a/hwcryptokey-test/rules.mk
+++ b/hwcryptokey-test/rules.mk
@@ -30,7 +30,7 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/app/sample/hwcryptohal/aidl/rust  \
 	trusty/user/app/sample/hwcryptohal/common \
 	trusty/user/base/lib/trusty-std \
-	external/rust/crates/log \
+	$(call FIND_CRATE,log) \
 
 MODULE_RUST_TESTS := true
 
diff --git a/hwcryptokey-test/versioned_keys_explicit.rs b/hwcryptokey-test/versioned_keys_explicit.rs
index 0c5ac1a..5690ffb 100644
--- a/hwcryptokey-test/versioned_keys_explicit.rs
+++ b/hwcryptokey-test/versioned_keys_explicit.rs
@@ -15,7 +15,7 @@
  */
 #[cfg(test)]
 mod tests {
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         IHwCryptoKey::{
             DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
             DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
@@ -31,15 +31,16 @@ mod tests {
 
     pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
 
-    pub(crate) const VERSION_0_DICE_POLICY: [u8; 120] = [
-        0x83, 0x58, 0x30, 0xa3, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x7a, 0x87,
-        0x07, 0x18, 0x72, 0x14, 0xb4, 0x1e, 0x69, 0x60, 0xc8, 0x6e, 0xfd, 0x8d, 0xdf, 0x6e, 0x48,
-        0xbd, 0x33, 0xa2, 0xdf, 0x6c, 0x76, 0x59, 0xdf, 0x82, 0x93, 0x3e, 0xf3, 0xa9, 0x6a, 0x23,
-        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0xa0, 0x58, 0x42, 0xea, 0xf7, 0x26, 0xfd, 0x2a, 0x06,
-        0x0a, 0x4b, 0x9e, 0x8c, 0xba, 0xf3, 0x41, 0x91, 0xac, 0x88, 0xfd, 0xc6, 0x23, 0xc3, 0x3f,
-        0x33, 0x64, 0x6d, 0x20, 0xb4, 0x18, 0x7a, 0x55, 0x7c, 0x4c, 0xdd, 0x64, 0x84, 0x54, 0x22,
-        0xec, 0xd9, 0x1d, 0x89, 0x49, 0xf3, 0xcb, 0x37, 0xfb, 0x1c, 0x49, 0x5a, 0xd5, 0xbc, 0xf6,
-        0x82, 0xd7, 0x82, 0xcc, 0x51, 0x00, 0x3b, 0x71, 0x0f, 0xde, 0xdb, 0x8a, 0xcf, 0x23, 0xf9,
+    pub(crate) const VERSION_0_DICE_POLICY: [u8; 126] = [
+        0x83, 0x58, 0x36, 0xa4, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x55, 0x51,
+        0xba, 0x39, 0x55, 0xfa, 0x6f, 0x92, 0xbb, 0xf9, 0xed, 0xe1, 0xc0, 0x91, 0x3f, 0x2b, 0xbf,
+        0xb5, 0xb3, 0x93, 0x8a, 0x08, 0x5f, 0x78, 0xa8, 0x00, 0xa2, 0xce, 0x09, 0x99, 0xa9, 0x5e,
+        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x04, 0x01, 0xa0, 0x58, 0x42,
+        0xda, 0x4f, 0xef, 0x97, 0xf4, 0x19, 0x90, 0xf3, 0x06, 0x1f, 0x06, 0xfe, 0x4d, 0xcb, 0x89,
+        0xcf, 0x6a, 0xa1, 0xd1, 0xf5, 0x34, 0x68, 0x47, 0x17, 0x2d, 0xa2, 0x0e, 0xec, 0xc1, 0xcb,
+        0xac, 0xa4, 0xe1, 0x36, 0x51, 0x88, 0xdb, 0x2e, 0x1c, 0x06, 0xeb, 0xe8, 0x0c, 0xde, 0x56,
+        0xc7, 0xed, 0x17, 0x03, 0x2a, 0x9c, 0x4e, 0x52, 0x65, 0xd6, 0x4e, 0xfb, 0xea, 0xf0, 0x9d,
+        0x49, 0x70, 0x3f, 0x37, 0xf3, 0x33,
     ];
 
     pub(crate) const VERSION_0_CLEAR_KEY: [u8; 256] = [
diff --git a/hwcryptokey-test/versioned_keys_opaque.rs b/hwcryptokey-test/versioned_keys_opaque.rs
index c0975dd..9a40d5b 100644
--- a/hwcryptokey-test/versioned_keys_opaque.rs
+++ b/hwcryptokey-test/versioned_keys_opaque.rs
@@ -16,7 +16,7 @@
 
 #[cfg(test)]
 mod tests {
-    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
+    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
             KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
@@ -45,15 +45,16 @@ mod tests {
 
     pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
 
-    pub(crate) const VERSION_0_DICE_POLICY: [u8; 120] = [
-        0x83, 0x58, 0x30, 0xa3, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x7a, 0x87,
-        0x07, 0x18, 0x72, 0x14, 0xb4, 0x1e, 0x69, 0x60, 0xc8, 0x6e, 0xfd, 0x8d, 0xdf, 0x6e, 0x48,
-        0xbd, 0x33, 0xa2, 0xdf, 0x6c, 0x76, 0x59, 0xdf, 0x82, 0x93, 0x3e, 0xf3, 0xa9, 0x6a, 0x23,
-        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0xa0, 0x58, 0x42, 0xea, 0xf7, 0x26, 0xfd, 0x2a, 0x06,
-        0x0a, 0x4b, 0x9e, 0x8c, 0xba, 0xf3, 0x41, 0x91, 0xac, 0x88, 0xfd, 0xc6, 0x23, 0xc3, 0x3f,
-        0x33, 0x64, 0x6d, 0x20, 0xb4, 0x18, 0x7a, 0x55, 0x7c, 0x4c, 0xdd, 0x64, 0x84, 0x54, 0x22,
-        0xec, 0xd9, 0x1d, 0x89, 0x49, 0xf3, 0xcb, 0x37, 0xfb, 0x1c, 0x49, 0x5a, 0xd5, 0xbc, 0xf6,
-        0x82, 0xd7, 0x82, 0xcc, 0x51, 0x00, 0x3b, 0x71, 0x0f, 0xde, 0xdb, 0x8a, 0xcf, 0x23, 0xf9,
+    pub(crate) const VERSION_0_DICE_POLICY: [u8; 126] = [
+        0x83, 0x58, 0x36, 0xa4, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x55, 0x51,
+        0xba, 0x39, 0x55, 0xfa, 0x6f, 0x92, 0xbb, 0xf9, 0xed, 0xe1, 0xc0, 0x91, 0x3f, 0x2b, 0xbf,
+        0xb5, 0xb3, 0x93, 0x8a, 0x08, 0x5f, 0x78, 0xa8, 0x00, 0xa2, 0xce, 0x09, 0x99, 0xa9, 0x5e,
+        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x04, 0x01, 0xa0, 0x58, 0x42,
+        0xda, 0x4f, 0xef, 0x97, 0xf4, 0x19, 0x90, 0xf3, 0x06, 0x1f, 0x06, 0xfe, 0x4d, 0xcb, 0x89,
+        0xcf, 0x6a, 0xa1, 0xd1, 0xf5, 0x34, 0x68, 0x47, 0x17, 0x2d, 0xa2, 0x0e, 0xec, 0xc1, 0xcb,
+        0xac, 0xa4, 0xe1, 0x36, 0x51, 0x88, 0xdb, 0x2e, 0x1c, 0x06, 0xeb, 0xe8, 0x0c, 0xde, 0x56,
+        0xc7, 0xed, 0x17, 0x03, 0x2a, 0x9c, 0x4e, 0x52, 0x65, 0xd6, 0x4e, 0xfb, 0xea, 0xf0, 0x9d,
+        0x49, 0x70, 0x3f, 0x37, 0xf3, 0x33,
     ];
 
     pub(crate) const ENCRYPTION_PAYLOAD: &str = "string to be encrypted";
diff --git a/hwrng-unittest/main.c b/hwrng-unittest/main.c
index 6845ff5..62bd61f 100644
--- a/hwrng-unittest/main.c
+++ b/hwrng-unittest/main.c
@@ -80,6 +80,7 @@ TEST(hwrng, var_rng_req_test) {
     }
 }
 
+#if !WITHOUT_HWRNG_FORWARD_TEST
 /*
  * This Test is NOT intended as a replacement for a proper NIST SP 800-22
  * certification suites. It only attempts to detect detect gross misbehaviors of
@@ -168,6 +169,8 @@ TEST(hwrng, cumulative_sums_forward_test) {
             "NIST 800-22 - Section 2.13.5 criteria not met after 3 attempts.");
 }
 
+#endif
+
 TEST(hwrng, stats_test) {
     int rc;
     unsigned int i;
diff --git a/memref-test/include/lender.h b/memref-test/include/lender.h
index cd472e7..0ea8da2 100644
--- a/memref-test/include/lender.h
+++ b/memref-test/include/lender.h
@@ -28,11 +28,16 @@ enum lender_command {
 };
 
 struct lender_region {
-    size_t offset;
-    size_t size;
+    uint64_t offset;
+    uint64_t size;
 };
 
+/**
+ * struct lender_msg - lend command
+ * @cmd:     command identifier, one of &enum lender_command
+ * @region:  region to operate on
+ */
 struct lender_msg {
-    enum lender_command cmd;
+    uint64_t cmd;
     struct lender_region region;
 };
diff --git a/memref-test/lender/lender.c b/memref-test/lender/lender.c
index c4a4107..da9c30c 100644
--- a/memref-test/lender/lender.c
+++ b/memref-test/lender/lender.c
@@ -195,7 +195,7 @@ static int lender_on_message(const struct tipc_port* port,
         }
         break;
     default:
-        TLOGE("Bad command: %d\n", msg.cmd);
+        TLOGE("Bad command: %" PRIu64 "\n", msg.cmd);
         return -1;
     }
 
diff --git a/memref-test/rust/memref_test.rs b/memref-test/rust/memref_test.rs
index afe0560..96b07de 100644
--- a/memref-test/rust/memref_test.rs
+++ b/memref-test/rust/memref_test.rs
@@ -62,7 +62,10 @@ fn request_remote_buf(lender: &Handle) -> Handle {
     // Send a command to the lender service telling it we want to receive a shared
     // memory buffer.
     lender
-        .send(&lender_msg { cmd: sys::lender_command_LENDER_LEND_BSS, region: Default::default() })
+        .send(&lender_msg {
+            cmd: sys::lender_command_LENDER_LEND_BSS as u64,
+            region: Default::default(),
+        })
         .unwrap();
 
     // Receive the memref from the lender service.
@@ -88,7 +91,7 @@ fn test_read_write(lender: &Handle, remote_buf: UnsafeSharedBuf) {
 
     lender
         .send(&lender_msg {
-            cmd: sys::lender_command_LENDER_READ_BSS,
+            cmd: sys::lender_command_LENDER_READ_BSS as u64,
             region: lender_region { offset: 0, size: 1 },
         })
         .unwrap();
@@ -105,7 +108,7 @@ fn test_read_write(lender: &Handle, remote_buf: UnsafeSharedBuf) {
     lender
         .send(&WriteRequest {
             msg: lender_msg {
-                cmd: sys::lender_command_LENDER_WRITE_BSS,
+                cmd: sys::lender_command_LENDER_WRITE_BSS as u64,
                 region: lender_region { offset: 1, size: 1 },
             },
             value: 123,
diff --git a/skel2/rust/rules.mk b/skel2/rust/rules.mk
index 89711bf..21ece2b 100644
--- a/skel2/rust/rules.mk
+++ b/skel2/rust/rules.mk
@@ -24,6 +24,6 @@ MODULE_CRATE_NAME := staticlib_test
 MODULE_RUST_CRATE_TYPES := staticlib
 
 MODULE_LIBRARY_DEPS += \
-	external/rust/crates/zerocopy-derive
+	$(call FIND_CRATE,zerocopy-derive)
 
 include make/library.mk
```

