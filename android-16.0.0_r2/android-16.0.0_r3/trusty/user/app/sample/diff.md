```diff
diff --git a/hwcryptohal/common/android.rs b/hwcryptohal/common/android.rs
index 4f44b75..648a956 100644
--- a/hwcryptohal/common/android.rs
+++ b/hwcryptohal/common/android.rs
@@ -370,7 +370,7 @@ impl AsCborValue for SerializableKeyPolicy {
 /// Mask used for valid AES key uses
 pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
 /// Mask used for valid HMAC key uses
-pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;
+pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0 | KeyUse::SIGN.0;
 
 /// checks if the values contained on `key_policy` are valid
 pub fn check_key_policy_values(key_policy: &KeyPolicy) -> Result<(), binder::Status> {
diff --git a/hwcryptohal/server/app/manifest.json b/hwcryptohal/server/app/manifest.json
index 53bfebd..45580f3 100644
--- a/hwcryptohal/server/app/manifest.json
+++ b/hwcryptohal/server/app/manifest.json
@@ -1,6 +1,6 @@
 {
     "app_name": "hwcryptohalserver_app",
     "uuid": "f49e28c4-d8b0-41c2-8197-11f27402c0f8",
-    "min_heap": 114688,
+    "min_heap": 458752,
     "min_stack": 32768
 }
diff --git a/hwcryptohal/server/cmd_processing.rs b/hwcryptohal/server/cmd_processing.rs
index 8ed3e1f..2df0dbf 100644
--- a/hwcryptohal/server/cmd_processing.rs
+++ b/hwcryptohal/server/cmd_processing.rs
@@ -27,17 +27,13 @@ use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::s
     OperationParameters::OperationParameters,
     PatternParameters::PatternParameters,
 };
-use core::ffi::c_void;
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
-use std::{os::fd::AsRawFd, ptr::NonNull};
+use hwcryptohalinterfaces::MemoryMappedObject;
+use hwcryptohalplatform::MemoryMappedObjectImpl;
 use vm_memory::{volatile_memory::VolatileSlice, Bytes, VolatileMemory};
 
 use crate::crypto_operation::{CopyOperation, CryptographicOperation, ICryptographicOperation};
 
-const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
-    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
-const INPUT_MEMORY_BUFFER_FLAGS: u32 = trusty_sys::MMAP_FLAG_PROT_READ;
-
 /// `CmdProcessorState` is a state machine with 3 states:
 ///
 /// * `InitialState`: State machine operation starts here. No cryptographic operations can be
@@ -287,13 +283,6 @@ enum OutputData<'a> {
     MemoryReference(MemoryBufferReference, usize),
 }
 
-fn get_mmap_prot_flags(memory_buffer: &MemoryBufferAidl) -> u32 {
-    match memory_buffer {
-        MemoryBufferAidl::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
-        MemoryBufferAidl::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
-    }
-}
-
 // `MemoryBufferReference` types do not contain the necessary information to
 // know if it should operate on an Input or Output buffer. That information is provided by the
 // Operation which contains the `MemoryBufferReference`. This wrapper preserves that information to
@@ -349,93 +338,28 @@ fn get_limits(
     }
 }
 
-// Wrapper over pointer used to map memory buffer.
-struct MappedBuffer(NonNull<u8>);
-
-// SAFETY: `MappedBuffer` is only used to free object on drop or to create a `VolatileSlice` when
-//         we need to access the underlying memory buffer; never directly. It is safe to access and
-//         drop on a different thread. All accesses to the mmaped memory are done through the
-//         `VolatileSlice` which already has the assumption that the underlying memory is shared
-//         between different entities, so it only uses `std::ptr::{copy, read_volatile,
-//         write_volatile}` to access memory.
-unsafe impl Send for MappedBuffer {}
-
-struct MemoryBuffer {
-    buffer_ptr: MappedBuffer,
-    total_size: usize,
-}
+struct MemoryBuffer(MemoryMappedObjectImpl);
 
 impl MemoryBuffer {
     fn new(memory_buffer_parameters: &MemoryBufferParameter) -> Result<Self, HwCryptoError> {
-        if memory_buffer_parameters.sizeBytes <= 0 {
-            return Err(hwcrypto_err!(BAD_PARAMETER, "Buffer size was not greater than 0"));
-        }
-        // memory_buffer_parameters.size is positive and because it is an i32, conversion is correct
-        let buffer_size = memory_buffer_parameters.sizeBytes as u32;
-        let protection_flags = get_mmap_prot_flags(&memory_buffer_parameters.bufferHandle);
-        let buffer_handle = match &memory_buffer_parameters.bufferHandle {
-            MemoryBufferAidl::Input(handle) | MemoryBufferAidl::Output(handle) => handle,
-        };
-        let buffer_handle = buffer_handle
-            .as_ref()
-            .ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "received a null buffer handle"))?;
-        // SAFETY: mmap is left to choose the address for the allocation. It will check that the
-        //         protection flags, size and fd are correct and return a negative value if
-        //         not.
-        let buffer_ptr = unsafe {
-            trusty_sys::mmap(
-                std::ptr::null_mut(),
-                buffer_size,
-                protection_flags,
-                buffer_handle.as_ref().as_raw_fd(),
-            )
-        };
-        if trusty_sys::Error::is_ptr_err(buffer_ptr as *const c_void) {
-            return Err(hwcrypto_err!(
-                BAD_PARAMETER,
-                "mapping buffer handle failed: {}",
-                buffer_ptr
-            ));
-        }
-        // cast is correct because buffer_ptr is positive and a pointer
-        let buffer_ptr = NonNull::new(buffer_ptr as *mut u8)
-            .ok_or(hwcrypto_err!(BAD_PARAMETER, "buffer_ptr was NULL"))?;
-        // cast is correct because buffer_size is an u32
-        let total_size = buffer_size as usize;
-
-        Ok(Self { buffer_ptr: MappedBuffer(buffer_ptr), total_size })
+        let mapped_buffer = MemoryMappedObjectImpl::mmap(memory_buffer_parameters)?;
+        Ok(Self(mapped_buffer))
     }
 
-    fn get_memory_slice<'a>(&'a mut self) -> Result<VolatileSlice<'a>, HwCryptoError> {
-        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
-        //         operation would have failed. All accesses to this memory on this service are
-        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory is
-        //         only unmapped on drop, so it will available for the lifetime of the
-        //         `VolatileSlice`.
-        let mem_buffer = unsafe { VolatileSlice::new(self.buffer_ptr.0.as_ptr(), self.total_size) };
-        Ok(mem_buffer)
+    fn get_memory_slice(&mut self) -> Result<VolatileSlice, HwCryptoError> {
+        self.0.get_memory_slice()
     }
 
-    fn get_subslice_as_data_to_process<'a>(
-        &'a mut self,
+    fn get_subslice_as_data_to_process(
+        &mut self,
         start: usize,
         size: usize,
-    ) -> Result<DataToProcess<'a>, HwCryptoError> {
+    ) -> Result<DataToProcess, HwCryptoError> {
         let mem_buffer = self.get_memory_slice()?;
         Ok(DataToProcess::new_from_volatile_slice(mem_buffer.subslice(start, size)?))
     }
 }
 
-impl Drop for MemoryBuffer {
-    fn drop(&mut self) {
-        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
-        //         of the object. `buffer_ptr` is still mapped at this point
-        unsafe {
-            trusty_sys::munmap(self.buffer_ptr.0.as_ptr().cast::<c_void>(), self.total_size as u32)
-        };
-    }
-}
-
 // `CmdProcessorContext` is the type in charge of executing a set of commands.
 pub(crate) struct CmdProcessorContext {
     current_input_memory_buffer: Option<MemoryBuffer>,
@@ -482,14 +406,14 @@ impl CmdProcessorContext {
             return Err(hwcrypto_err!(BAD_PARAMETER, "cannot create buffer references of size 0"));
         }
         if let Some(current_memory_buffer) = current_memory_buffer {
-            if buffer_start >= current_memory_buffer.total_size {
+            if buffer_start >= current_memory_buffer.0.buffer_size() {
                 return Err(hwcrypto_err!(BAD_PARAMETER, "buffer start falls outside of buffer"));
             }
             // Because both values are positive and signed, then the addition should not
             // overflow. Using a checked add in case we can change these values to unsigned
             // in the future
             if let Some(buffer_end) = buffer_size.checked_add(buffer_start) {
-                if buffer_end > current_memory_buffer.total_size {
+                if buffer_end > current_memory_buffer.0.buffer_size() {
                     Err(hwcrypto_err!(BAD_PARAMETER, "buffer reference falls outside of buffer"))
                 } else {
                     Ok(())
@@ -524,23 +448,21 @@ impl CmdProcessorContext {
         };
         if current_memory_buffer.is_some() {
             Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer already set"))
+        } else if parameters.sizeBytes < 0 {
+            Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer size is negative"))
         } else {
-            if parameters.sizeBytes < 0 {
-                Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer size is negative"))
-            } else {
-                // With the current behaviour, next check should not be needed, because we can only
-                // set up the current_memory_buffer once and we can only set the current_output_ref
-                // after setting a current output memory buffer. Leaving the check here in case the
-                // behavior changes in the future
-                if buffer_is_output {
-                    if let Some(OutputData::MemoryReference(_, _)) = current_output_ref {
-                        // If the current output is a buffer reference, we need to invalidate it
-                        return Err(hwcrypto_err!(BAD_PARAMETER, "This should not be possible with current flow, we need to invalidate the current output reference now."));
-                    }
+            // With the current behaviour, next check should not be needed, because we can only
+            // set up the current_memory_buffer once and we can only set the current_output_ref
+            // after setting a current output memory buffer. Leaving the check here in case the
+            // behavior changes in the future
+            if buffer_is_output {
+                if let Some(OutputData::MemoryReference(_, _)) = current_output_ref {
+                    // If the current output is a buffer reference, we need to invalidate it
+                    return Err(hwcrypto_err!(BAD_PARAMETER, "This should not be possible with current flow, we need to invalidate the current output reference now."));
                 }
-                *current_memory_buffer = Some(MemoryBuffer::new(parameters)?);
-                Ok(())
             }
+            *current_memory_buffer = Some(MemoryBuffer::new(parameters)?);
+            Ok(())
         }
     }
 
@@ -554,7 +476,7 @@ impl CmdProcessorContext {
                 Ok(OutputData::MemoryReference(
                     *buffer_reference,
                     self.get_data_buffer_size(&MemoryBufferReferenceWithType::Output(
-                        (*buffer_reference).into(),
+                        *buffer_reference,
                     ))?,
                 ))
             }
@@ -598,14 +520,13 @@ impl CmdProcessorContext {
         // available method could potentially be use to modify the underlying memory buffer.
         if let Some(OutputData::MemoryReference(buff_ref, _)) = current_output_ref.as_ref() {
             self.check_memory_reference_in_range(&MemoryBufferReferenceWithType::Output(
-                (*buff_ref).into(),
+                *buff_ref,
             ))?;
         }
         // Creating a `DataToProcess` variable to abstract away where the input is located
         let mut input = match input_parameters {
             Some(OperationData::MemoryBufferReference(buffer_reference)) => Some({
-                let buffer_reference =
-                    MemoryBufferReferenceWithType::Input((*buffer_reference).into());
+                let buffer_reference = MemoryBufferReferenceWithType::Input(*buffer_reference);
                 self.check_memory_reference_in_range(&buffer_reference)?;
                 let (input_start, _input_stop, input_size) = get_limits(&buffer_reference)?;
                 self.current_input_memory_buffer
@@ -649,7 +570,7 @@ impl CmdProcessorContext {
                 // the result
                 let original_size = output_vec.len();
                 let mut output_buff =
-                    DataToProcess::allocate_buffer_end_vector(*output_vec, req_output_size)?;
+                    DataToProcess::allocate_buffer_end_vector(output_vec, req_output_size)?;
                 let added_bytes =
                     crypto_operation.operation(input.as_mut(), &mut output_buff, is_finish)?;
                 output_vec.truncate(original_size + added_bytes);
@@ -659,7 +580,7 @@ impl CmdProcessorContext {
                     return Err(hwcrypto_err!(ALLOCATION_ERROR, "run out of space output buffer"));
                 }
                 let (_output_start, output_stop, _output_size) =
-                    get_limits(&MemoryBufferReferenceWithType::Output((*output_buff_ref).into()))?;
+                    get_limits(&MemoryBufferReferenceWithType::Output(*output_buff_ref))?;
                 // We are automatically filling up the output buffer with the received input, so
                 // the first available position will be equal to the end of the buffer minus the
                 // remaining space:
@@ -677,7 +598,7 @@ impl CmdProcessorContext {
                     .get_subslice_as_data_to_process(output_start_offset, req_output_size)?;
                 let req_output_size =
                     crypto_operation.operation(input.as_mut(), &mut output_slice, is_finish)?;
-                *remaining_size = *remaining_size - req_output_size;
+                *remaining_size -= req_output_size;
             }
         }
         Ok(())
@@ -741,7 +662,7 @@ impl CmdProcessorContext {
                     }
                     CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
                     CryptoOperation::SetMemoryBuffer(step_data) => {
-                        let op_result = self.set_memory_buffer_step(&step_data, &mut curr_output);
+                        let op_result = self.set_memory_buffer_step(step_data, &mut curr_output);
                         // Workaround, currently trying to return with a operation step that includes
                         // file descriptors fails on the trusty binder sw stack. We are changing
                         // changing the operation type instead of deleting it so the client do not
@@ -752,7 +673,7 @@ impl CmdProcessorContext {
                     }
                     CryptoOperation::SetOperationParameters(step_data) => {
                         self.current_state = CmdProcessorState::RunningOperation;
-                        self.set_operation_parameters_step(&step_data, &mut curr_output)?;
+                        self.set_operation_parameters_step(step_data, &mut curr_output)?;
                     }
                     CryptoOperation::SetPattern(_) => {
                         return Err(hwcrypto_err!(
@@ -841,12 +762,12 @@ mod tests {
     use std::alloc::{alloc_zeroed, dealloc, Layout};
     use std::os::fd::{FromRawFd, OwnedFd};
     use test::{expect, expect_eq};
-    use tipc::Uuid;
 
-    fn connection_info() -> Uuid {
-        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
-        Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap()
-    }
+    use crate::tests::connection_info;
+
+    const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
+        trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
+
     /// Structure only intended to use on unit tests. It will allocate a single memory page and
     /// create a memref to it.
     struct TestPageAllocator {
@@ -948,18 +869,11 @@ mod tests {
     }
 
     fn read_slice(
-        memory_buffer: &MemoryBuffer,
+        memory_buffer: &mut MemoryBuffer,
         buf: &mut [u8],
         start: usize,
     ) -> Result<(), HwCryptoError> {
-        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
-        //         operation would have failed. All accesses to this memory on this service are
-        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory
-        //         is only unmapped on drop, so it will available for the lifetime of the
-        //         `VolatileSlice`.
-        let mem_buffer = unsafe {
-            VolatileSlice::new(memory_buffer.buffer_ptr.0.as_ptr(), memory_buffer.total_size)
-        };
+        let mem_buffer = memory_buffer.get_memory_slice()?;
         mem_buffer.read_slice(buf, start).map_err(HwCryptoError::from)
     }
 
@@ -989,29 +903,29 @@ mod tests {
 
         let mut slice = vec![0; 5];
 
-        read_slice(&memory_buffer, &mut slice[0..2], 1).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..2], 1).expect("couldn't get slice");
         expect_eq!(&slice[0..2], &[2, 3], "wrong value retrieved through slice");
 
-        read_slice(&memory_buffer, &mut slice[0..1], 8).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..1], 8).expect("couldn't get slice");
         expect_eq!(&slice[0..1], &[9], "wrong value retrieved through slice");
 
-        let result = read_slice(&memory_buffer, &mut slice[0..2], total_buffer_size - 1);
+        let result = read_slice(&mut memory_buffer, &mut slice[0..2], total_buffer_size - 1);
         expect!(result.is_err(), "Shouldn't be able to get slice with end out of range");
 
-        let result = read_slice(&memory_buffer, &mut slice[0..1], total_buffer_size);
+        let result = read_slice(&mut memory_buffer, &mut slice[0..1], total_buffer_size);
         expect!(result.is_err(), "Shouldn't be able to get slice with start out of range");
 
-        read_slice(&memory_buffer, &mut slice[0..1], 0).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..1], 0).expect("couldn't get slice");
         expect_eq!(&slice[0..1], &[1], "wrong value retrieved through slice");
 
-        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
         expect_eq!(&slice[0..3], &[5, 6, 7], "wrong value retrieved through slice");
 
         write_slice(&mut memory_buffer, &[55], 5).expect("couldn't write slice");
-        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
         expect_eq!(&slice[0..3], &[5, 55, 7], "wrong value retrieved through slice");
 
-        read_slice(&memory_buffer, &mut slice[0..5], 3).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice[0..5], 3).expect("couldn't get slice");
         expect_eq!(&slice[0..5], &[4, 5, 55, 7, 8], "wrong value retrieved through slice");
     }
 
@@ -1181,7 +1095,7 @@ mod tests {
             keyType: KeyType::AES_128_CBC_NO_PADDING,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info());
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info());
         expect!(key.is_ok(), "couldn't generate key");
         let key = key.unwrap();
         let mode = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -1224,9 +1138,9 @@ mod tests {
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         let mut read_slice_val = vec![55; 9];
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
         cmd_list.remove(0);
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(
             &read_slice_val[..],
             &[1, 2, 3, 0, 0, 0, 0, 0, 0],
@@ -1239,8 +1153,8 @@ mod tests {
             process_result.is_err(),
             "Command should have failed because we run out of output buffer"
         );
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(
             &read_slice_val[..],
             &[1, 2, 3, 0, 0, 0, 0, 0, 0],
@@ -1321,8 +1235,8 @@ mod tests {
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         let mut read_slice_val = vec![55; 9];
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0], "initial values where not 0");
         cmd_list.remove(1);
         cmd_list.remove(0);
@@ -1334,14 +1248,14 @@ mod tests {
         cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[1, 2, 3, 0, 0, 0, 0, 0, 0], "initial values where not 0");
         cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 0, 0, 0], "initial values where not 0");
         let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
         cmd_list
@@ -1349,8 +1263,8 @@ mod tests {
         let process_result = cmd_processor.process_all_steps(&mut cmd_list);
         expect!(process_result.is_ok(), "Couldn't process command");
         cmd_list.clear();
-        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
-        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
+        let mut mem_buffer = cmd_processor.current_output_memory_buffer.as_mut().unwrap();
+        read_slice(&mut mem_buffer, &mut read_slice_val[..], 0).unwrap();
         expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9], "initial values where not 0");
     }
 
@@ -1420,7 +1334,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -1728,7 +1642,7 @@ mod tests {
         expect!(res.is_ok(), "Couldn't data to process");
 
         let mut slice = vec![0; 10];
-        read_slice(&memory_buffer, &mut slice, 0).expect("couldn't get slice");
+        read_slice(&mut memory_buffer, &mut slice, 0).expect("couldn't get slice");
         expect_eq!(
             slice,
             [0, 1, 10, 11, 27, 28, 6, 7, 8, 9],
@@ -1747,7 +1661,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -1847,7 +1761,7 @@ mod tests {
             keyType: KeyType::AES_128_CBC_PKCS7_PADDING,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -1875,7 +1789,7 @@ mod tests {
             keyType: KeyType::AES_256_CBC_NO_PADDING,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
             nonce: nonce.into(),
@@ -1906,7 +1820,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -2016,7 +1930,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let key = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let key = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
diff --git a/hwcryptohal/server/crypto_operation.rs b/hwcryptohal/server/crypto_operation.rs
index e6ca562..ad66bdc 100644
--- a/hwcryptohal/server/crypto_operation.rs
+++ b/hwcryptohal/server/crypto_operation.rs
@@ -24,15 +24,18 @@ use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::s
     OperationParameters::OperationParameters, PatternParameters::PatternParameters,
 };
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use hwcryptohalplatform::{AesImpl, HmacImpl};
 use kmr_common::crypto::{
     self, Aes, Hmac, KeyMaterial, SymmetricOperation as CryptoSymmetricOperation,
 };
 
 use crate::cmd_processing::DataToProcess;
-use crate::crypto_provider;
 use crate::helpers;
 use crate::opaque_key::OpaqueKey;
 
+// We only support SHA256 and SHA512
+const HMAC_MAX_SIZE: usize = 64;
+
 // Pattern for cbcs operations. cbcs is based on partially encryption using AES-CBC as defined in
 // IEC 23001-7:2016
 enum CbcsPattern {
@@ -242,9 +245,8 @@ impl HmacOperation {
             .try_into()?;
         Self::check_parameters(&opaque_key, parameters)?;
         let digest = helpers::aidl_to_rust_digest(&opaque_key.get_key_type())?;
-        let hmac = crypto_provider::HmacImpl;
         let accumulating_op = match opaque_key.key_material {
-            KeyMaterial::Hmac(ref key) => hmac.begin(key.clone(), digest).map_err(|e| {
+            KeyMaterial::Hmac(ref key) => HmacImpl.begin(key.clone(), digest).map_err(|e| {
                 hwcrypto_err!(GENERIC_ERROR, "couldn't begin hmac operation: {:?}", e)
             }),
             _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
@@ -273,7 +275,7 @@ impl IBaseCryptoOperation for HmacOperation {
     }
 
     fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
-        Ok(crypto_provider::HMAC_MAX_SIZE)
+        Ok(HMAC_MAX_SIZE)
     }
 
     fn update(
@@ -344,9 +346,8 @@ impl AesOperation {
         let dir = helpers::aidl_to_rust_symmetric_direction(dir)?;
         let emitting_op = match key_material {
             KeyMaterial::Aes(key) => {
-                let aes = crypto_provider::AesImpl;
                 let mode = helpers::aidl_to_rust_aes_cipher_params(parameters, &opaque_key)?;
-                aes.begin(key.clone(), mode, dir).map_err(|e| {
+                AesImpl.begin(key.clone(), mode, dir).map_err(|e| {
                     hwcrypto_err!(GENERIC_ERROR, "couldn't begin aes operation: {:?}", e)
                 })
             }
@@ -403,7 +404,7 @@ impl AesOperation {
     }
 
     fn round_to_block_size(size: usize) -> usize {
-        ((size + crypto::aes::BLOCK_SIZE - 1) / crypto::aes::BLOCK_SIZE) * crypto::aes::BLOCK_SIZE
+        size.div_ceil(crypto::aes::BLOCK_SIZE) * crypto::aes::BLOCK_SIZE
     }
 
     fn cbcs_update<'a>(
@@ -504,7 +505,7 @@ impl IBaseCryptoOperation for AesOperation {
         if self.cbcs_pattern.is_some() {
             return self.cbcs_update(input, output);
         }
-        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(&input)?;
+        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(input)?;
         if output.len() != req_size {
             return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
         }
@@ -616,9 +617,8 @@ impl ICryptographicOperation for CopyOperation {
         _is_finish: bool,
     ) -> Result<usize, HwCryptoError> {
         let num_bytes_copy = self.get_operation_req_size(input.as_deref(), false)?;
-        let mut input =
-            input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
-        output.read_from_slice(&mut input, None)?;
+        let input = input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
+        output.read_from_slice(input, None)?;
         Ok(num_bytes_copy)
     }
 
@@ -703,12 +703,8 @@ mod tests {
         KeyPolicy::KeyPolicy,
     };
     use test::{expect, expect_eq};
-    use tipc::Uuid;
 
-    fn connection_info() -> Uuid {
-        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
-        Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap()
-    }
+    use crate::tests::connection_info;
 
     #[test]
     fn use_aes_key() {
@@ -721,7 +717,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let handle = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let handle = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
@@ -808,7 +804,7 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let handle = OpaqueKey::generate_opaque_key(&policy, connection_info())
+        let handle = OpaqueKey::generate_opaque_key(&policy, &connection_info())
             .expect("couldn't generate key");
         let nonce = [0u8; 16];
         let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
diff --git a/hwcryptohal/server/helpers.rs b/hwcryptohal/server/helpers.rs
index b779e4a..2a97d6d 100644
--- a/hwcryptohal/server/helpers.rs
+++ b/hwcryptohal/server/helpers.rs
@@ -83,23 +83,13 @@ pub(crate) fn aidl_to_rust_aes_cipher_params(
     let SymmetricCryptoParameters::Aes(aes_params) = params;
     match aes_params {
         AesCipherMode::Cbc(CipherModeParameters { nonce }) => {
-            // TODO: change clone() into something like a try_clone()
-            let nonce = nonce.clone();
-            let nonce_len = nonce.len();
+            let nonce = *nonce;
             match opaque_key.get_key_type() {
                 KeyType::AES_128_CBC_NO_PADDING | KeyType::AES_256_CBC_NO_PADDING => {
-                    Ok(crypto::aes::CipherMode::CbcNoPadding {
-                        nonce: nonce.try_into().map_err(|_| {
-                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
-                        })?,
-                    })
+                    Ok(crypto::aes::CipherMode::CbcNoPadding { nonce })
                 }
                 KeyType::AES_128_CBC_PKCS7_PADDING | KeyType::AES_256_CBC_PKCS7_PADDING => {
-                    Ok(crypto::aes::CipherMode::CbcPkcs7Padding {
-                        nonce: nonce.try_into().map_err(|_| {
-                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
-                        })?,
-                    })
+                    Ok(crypto::aes::CipherMode::CbcPkcs7Padding { nonce })
                 }
                 _ => Err(hwcrypto_err!(
                     BAD_PARAMETER,
@@ -109,14 +99,7 @@ pub(crate) fn aidl_to_rust_aes_cipher_params(
             }
         }
         AesCipherMode::Ctr(CipherModeParameters { nonce }) => {
-            let nonce_len = nonce.len();
-            // TODO: change clone() into something like a try_clone()
-            Ok(crypto::aes::CipherMode::Ctr {
-                nonce: nonce
-                    .clone()
-                    .try_into()
-                    .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len))?,
-            })
+            Ok(crypto::aes::CipherMode::Ctr { nonce: *nonce })
         }
     }
 }
diff --git a/hwcryptohal/server/hwcrypto_device_key.rs b/hwcryptohal/server/hwcrypto_device_key.rs
index b765022..5f4a7a0 100644
--- a/hwcryptohal/server/hwcrypto_device_key.rs
+++ b/hwcryptohal/server/hwcrypto_device_key.rs
@@ -33,105 +33,79 @@ use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::s
     KeyPolicy::KeyPolicy,
 };
 use android_hardware_security_see_hwcrypto::binder;
-use ciborium::{cbor, Value};
+use ciborium::Value;
 use coset::{AsCborValue, CborSerializable, CoseError};
 use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
-use hwkey::{Hwkey, KdfVersion};
-use tipc::Uuid;
-
-use crate::hwcrypto_operations::HwCryptoOperations;
+use hwcryptohalinterfaces::{ClientIdentification, ClientPolicyCheck, DeviceKeys};
+use hwcryptohalplatform::DeviceKeysImpl;
 
 use crate::helpers;
+use crate::hwcrypto_operations::HwCryptoOperations;
 use crate::opaque_key::{self, DerivationContext, HkdfOperationType, OpaqueKey};
 use crate::service_encryption_key::{
     self, EncryptedContent, EncryptionHeader, EncryptionHeaderKey,
 };
+use hwcryptohalplatform::ClientIdentificationImpl;
 
 const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";
 
-// enum used for serializing the `VersionContext`
+// enum used for serializing the `ClientPolicyWrapper`
+// ClientPolicyWrapper = {
+//     -65680 : bstr                        ; ClientPolicy
+//     -65681 : bstr                        ; DeviceKeyPolicy
+// }
 cose_enum_gen! {
-    enum VersionContextCoseLabels {
-        Uuid = -65537,
-        Version = -65538,
+    enum ClientPolicyWrapperCoseLabels {
+        ClientPolicy = -65680,
+        DeviceKeyPolicy = -65681,
     }
 }
 
-// TODO: `ConnectionInformation` will be opaque to the HwCrypto service once we have a connection
-//        manager.
-struct ConnectionInformation {
-    uuid: Uuid,
-}
-
-// Mock version object to be used until we have more DICE support. It is based on the trusty version
-// retrievable from HwKey and the uuid of the caller. `VersionContext`` encryption is similar to
-// what KeyMint uses to wrap keys.
-struct VersionContext {
-    uuid: Uuid,
-    version: u32,
+// Object containing the Client policy and device key version. It will encrypt and decrypt them when
+// interacting with the client. The current policy is based on the trusty version retrievable from
+// HwKey and the uuid of the caller. Dice will be added once we have support for it. The device key
+// version is used to retrieve a unique versioned key tied to the HwCrypto server.
+// `ClientPolicyWrapper` encryption is similar to what KeyMint uses to wrap
+// keys. While the stable policy returned by the `ClientPolicyWrapper` only includes the client
+// policy, the generation of the derivation key consumes both this stable policy and the device key
+// version.
+struct ClientPolicyWrapper {
+    client_policy: Vec<u8>,
+    device_key_policy: Vec<u8>,
     header: Option<EncryptionHeader>,
 }
 
-impl VersionContext {
-    fn get_current_version() -> Result<u32, HwCryptoError> {
-        service_encryption_key::get_service_current_version()
-    }
-
-    fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
-        let header = Some(EncryptionHeader::generate(EncryptedContent::DicePolicy)?);
-        let version = Self::get_current_version()?;
-        Ok(VersionContext { uuid, version, header })
-    }
-
-    fn new_current_encrypted(uuid: Uuid) -> Result<Vec<u8>, HwCryptoError> {
-        let ctx = Self::new_current(uuid)?;
-        Ok(ctx.encrypt_context()?)
-    }
-
-    fn check_version(&self) -> Result<(), HwCryptoError> {
-        let current_version = Self::get_current_version()?;
-        if self.version > current_version {
-            return Err(hwcrypto_err!(BAD_PARAMETER, "version is not valid"));
-        }
-        Ok(())
-    }
-
-    fn check_context(&self, connection: ConnectionInformation) -> Result<(), HwCryptoError> {
-        if connection.uuid != self.uuid {
-            return Err(hwcrypto_err!(BAD_PARAMETER, "uuid mismatch"));
-        }
-        self.check_version()
-    }
+impl ClientPolicyWrapper {
+    // decrypts and returns a new `ClientPolicyWrapper`
+    fn from_encrypted_slice(encrypted_wrapped_policy: &[u8]) -> Result<Self, HwCryptoError> {
+        let (wrapped_policy_header, decrypted_data) =
+            EncryptionHeader::decrypt_content_service_encryption_key(
+                encrypted_wrapped_policy,
+                EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
+                EncryptedContent::ClientPolicy,
+            )?;
 
-    fn check_encrypted_context(
-        encrypted_ctx: &[u8],
-        connection: ConnectionInformation,
-    ) -> Result<(), HwCryptoError> {
-        let context = Self::decrypt_context(encrypted_ctx)?;
-        context.check_context(connection)
+        let mut wrapped_policy =
+            ClientPolicyWrapper::from_cbor_value(Value::from_slice(&decrypted_data[..])?)?;
+        wrapped_policy.header = Some(wrapped_policy_header);
+        Ok(wrapped_policy)
     }
 
-    fn is_context_current(encrypted_ctx: &[u8]) -> Result<bool, HwCryptoError> {
-        let context = Self::decrypt_context(encrypted_ctx)?;
-        let current_version = Self::get_current_version()?;
-        Ok(context.version >= current_version)
+    // returns the current version of the platform device key service
+    fn get_device_key_service_current_version() -> Result<Vec<u8>, HwCryptoError> {
+        service_encryption_key::get_service_current_version()
     }
 
-    fn decrypt_context(encrypted_context: &[u8]) -> Result<Self, HwCryptoError> {
-        let (version_ctx_header, decrypted_data) =
-            EncryptionHeader::decrypt_content_service_encryption_key(
-                encrypted_context,
-                EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
-                EncryptedContent::DicePolicy,
-            )?;
-
-        let mut version_context =
-            VersionContext::from_cbor_value(Value::from_slice(&decrypted_data[..])?)?;
-        version_context.header = Some(version_ctx_header);
-        Ok(version_context)
+    // returns a new `ClientPolicyWrapper` with the version set to the current client version
+    fn new_current(client_id: &[u8]) -> Result<Self, HwCryptoError> {
+        let header = Some(EncryptionHeader::generate(EncryptedContent::ClientPolicy)?);
+        let device_key_policy = Self::get_device_key_service_current_version()?;
+        let client_policy = ClientIdentificationImpl::get_client_current_policy(client_id)?;
+        Ok(ClientPolicyWrapper { client_policy, device_key_policy, header })
     }
 
-    fn encrypt_context(mut self) -> Result<Vec<u8>, HwCryptoError> {
+    // consumes a `ClientPolicyWrapper` and returns it encrypted
+    fn encrypt(mut self) -> Result<Vec<u8>, HwCryptoError> {
         let header = self.header.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "no header found"))?;
         header.encrypt_content_service_encryption_key(
             EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
@@ -139,115 +113,120 @@ impl VersionContext {
         )
     }
 
-    fn get_stable_context(encrypted_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
-        let decrypted_context = Self::decrypt_context(encrypted_context)?;
-        Ok(decrypted_context.to_cbor_value()?.to_vec()?)
+    // returns both the client policy and the device key version contained by the
+    // `ClientPolicyWrapper`
+    fn into_client_and_device_key_policies(self) -> Result<(Vec<u8>, Vec<u8>), HwCryptoError> {
+        Ok((self.client_policy, self.device_key_policy))
     }
 }
 
-impl AsCborValue for VersionContext {
+impl AsCborValue for ClientPolicyWrapper {
     fn to_cbor_value(self) -> Result<Value, CoseError> {
-        cbor!({
-            (VersionContextCoseLabels::Uuid as i64) => self.uuid.to_string(),
-            (VersionContextCoseLabels::Version as i64) => self.version,
-        })
-        .map_err(|_| CoseError::ExtraneousData)
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
+
+        let key = Value::Integer((ClientPolicyWrapperCoseLabels::ClientPolicy as i64).into());
+        let value = Value::Bytes(self.client_policy);
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((ClientPolicyWrapperCoseLabels::DeviceKeyPolicy as i64).into());
+        let value = Value::Bytes(self.device_key_policy);
+        cbor_map.push((key, value));
+
+        Ok(Value::Map(cbor_map))
     }
 
     fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
-        let version_context = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
-        let mut uuid: Option<Uuid> = None;
-        let mut version: Option<u32> = None;
-        for (map_key, map_val) in version_context {
+        let wrapped_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+        let mut client_policy: Option<Vec<u8>> = None;
+        let mut device_key_policy: Option<Vec<u8>> = None;
+        for (map_key, map_val) in wrapped_policy {
             match map_key {
                 Value::Integer(key) => {
-                    match key.try_into().map_err(|_| CoseError::EncodeFailed)? {
-                        VersionContextCoseLabels::Uuid => {
-                            let uuid_str =
-                                map_val.into_text().map_err(|_| CoseError::EncodeFailed)?;
-                            let parsed_uuid = Uuid::new_from_string(&uuid_str)
-                                .map_err(|_| CoseError::EncodeFailed)?;
-                            uuid = Some(parsed_uuid);
+                    match key.try_into().map_err(|_| {
+                        CoseError::UnexpectedItem(
+                            "value not matching enum",
+                            "ClientPolicyWrapperCoseLabels",
+                        )
+                    })? {
+                        ClientPolicyWrapperCoseLabels::ClientPolicy => {
+                            client_policy =
+                                Some(map_val.into_bytes().map_err(|_| {
+                                    CoseError::UnexpectedItem("other type", "Bytes")
+                                })?);
                         }
-                        VersionContextCoseLabels::Version => {
+                        ClientPolicyWrapperCoseLabels::DeviceKeyPolicy => {
                             let parsed_version = map_val
-                                .into_integer()
-                                .map_err(|_| CoseError::EncodeFailed)?
-                                .try_into()
-                                .map_err(|_| CoseError::ExtraneousData)?;
-                            version = Some(parsed_version);
+                                .into_bytes()
+                                .map_err(|_| CoseError::UnexpectedItem("other type", "Bytes"))?;
+                            device_key_policy = Some(parsed_version);
                         }
                     }
                 }
                 _ => return Err(CoseError::ExtraneousData),
             }
         }
-        let uuid = uuid.ok_or(CoseError::EncodeFailed)?;
-        let version = version.ok_or(CoseError::EncodeFailed)?;
+        let client_policy = client_policy.ok_or(CoseError::EncodeFailed)?;
+        let device_key_policy = device_key_policy.ok_or(CoseError::EncodeFailed)?;
         // Header travels in the clear, the decoded section only contains the encrypted fields
-        Ok(VersionContext { uuid, version, header: None })
+        Ok(ClientPolicyWrapper { client_policy, device_key_policy, header: None })
     }
 }
 
 /// The `IHwCryptoKey` implementation.
 #[derive(Debug)]
 pub struct HwCryptoKey {
-    pub(crate) uuid: Uuid,
+    pub(crate) client_id: Vec<u8>,
 }
 
 impl binder::Interface for HwCryptoKey {}
 
 impl HwCryptoKey {
-    pub(crate) fn new_binder(uuid: Uuid) -> binder::Strong<dyn IHwCryptoKey> {
-        let hwcrypto_device_key = HwCryptoKey { uuid };
+    pub fn new_binder(client_id: Vec<u8>) -> binder::Strong<dyn IHwCryptoKey> {
+        let hwcrypto_device_key = HwCryptoKey { client_id };
         BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
     }
 
-    // check_dice_policy_owner shall only be false for creating internal keys that can be used
+    // check_client_policy_owner shall only be false for creating internal keys that can be used
     // to seal content bounded to another party DICE policy
     pub(crate) fn derive_dice_policy_bound_key(
         &self,
         derivation_key: &DiceBoundDerivationKey,
-        dice_policy_for_key_version: &[u8],
-        check_dice_policy_owner: bool,
+        client_policy_for_versioned_key: &[u8],
+        check_client_policy_owner: bool,
     ) -> Result<DiceBoundKeyResult, HwCryptoError> {
         // Verifying provided DICE policy
-        let connection_info: ConnectionInformation =
-            ConnectionInformation { uuid: self.uuid.clone() };
-        if check_dice_policy_owner {
-            VersionContext::check_encrypted_context(dice_policy_for_key_version, connection_info)?;
+        let (caller_client_policy, device_key_policy) =
+            ClientPolicyWrapper::from_encrypted_slice(client_policy_for_versioned_key)?
+                .into_client_and_device_key_policies()?;
+        let ClientPolicyCheck { policy_matches, policy_is_current } =
+            ClientIdentificationImpl::check_client_policy(
+                self.client_id.as_slice(),
+                caller_client_policy.as_slice(),
+            )?;
+        if check_client_policy_owner && !policy_matches {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "client identity mismatch"));
         }
-        // Getting back a stable DICE policy for context, so keys derived with the same version will
-        // match
-        let dice_context = VersionContext::get_stable_context(dice_policy_for_key_version)?;
         let mut op_context = DerivationContext::new(HkdfOperationType::DiceBoundDerivation)?;
-        op_context.add_owned_binary_string(dice_context)?;
+        // Using the decrypted (stable) DICE policy for context, so keys derived with the same
+        // version will match
+        op_context.add_owned_binary_string(caller_client_policy)?;
         let concat_context = op_context.create_key_derivation_context()?;
 
         // The returned key will only be used for derivation, so fixing tis type to HMAC_SHA256
         let key_type = KeyType::HMAC_SHA256;
         let key_size = opaque_key::get_key_size_in_bytes(&key_type)?;
-        // Create an array big enough to hold the bytes of the derived key material
-        let mut derived_key = Vec::<u8>::new();
-        derived_key.try_reserve(key_size)?;
-        derived_key.resize(key_size, 0);
 
         match derivation_key {
             DiceBoundDerivationKey::KeyId(key_id) => {
-                let hwkey_session = Hwkey::open().map_err(|e| {
-                    hwcrypto_err!(GENERIC_ERROR, "could not connect to hwkey service {:?}", e)
-                })?;
-                let session_req = match *key_id {
-                    DeviceKeyId::DEVICE_BOUND_KEY => {
-                        Ok(hwkey_session.derive_key_req().unique_key())
-                    }
-                    _ => Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id)),
-                }?;
-
-                session_req
-                    .kdf(KdfVersion::Best)
-                    .derive(concat_context.as_slice(), &mut derived_key[..])
-                    .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to derive key {:?}", e))?;
+                if DeviceKeyId::DEVICE_BOUND_KEY != *key_id {
+                    return Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id));
+                }
+                let derived_key = DeviceKeysImpl.derive_caller_unique_key(
+                    concat_context.as_slice(),
+                    device_key_policy.as_slice(),
+                    key_size,
+                )?;
 
                 let policy = KeyPolicy {
                     usage: KeyUse::DERIVE,
@@ -258,13 +237,11 @@ impl HwCryptoKey {
                 };
                 // Create a new opaque key from the generated key material
                 let km = opaque_key::generate_key_material(&policy.keyType, Some(derived_key))?;
-                let key = opaque_key::OpaqueKey::new_binder(&policy, km, self.uuid.clone())
+                let key = opaque_key::OpaqueKey::new_binder(&policy, km, self.client_id.as_slice())
                     .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to create key {:?}", e))?;
-                let dice_policy_current =
-                    VersionContext::is_context_current(dice_policy_for_key_version)?;
                 Ok(DiceBoundKeyResult {
                     diceBoundKey: Some(key),
-                    dicePolicyWasCurrent: dice_policy_current,
+                    dicePolicyWasCurrent: policy_is_current,
                 })
             }
             DiceBoundDerivationKey::OpaqueKey(_opaque_key) => Err(hwcrypto_err!(
@@ -274,12 +251,12 @@ impl HwCryptoKey {
         }
     }
 
-    fn check_caller_can_access_keyslot(&self, _keyslot: KeySlot) -> Result<(), HwCryptoError> {
-        // Simple uuid check for host uuid until we have DICE
-        if self.uuid.to_string() == "00000000-0000-0000-0000-000000000000" {
-            Err(hwcrypto_err!(UNAUTHORIZED, "caller do not have permission to access this key"))
-        } else {
+    fn check_caller_can_access_keyslot(&self, keyslot: KeySlot) -> Result<(), HwCryptoError> {
+        if ClientIdentificationImpl::client_can_access_keyslot(self.client_id.as_slice(), keyslot)?
+        {
             Ok(())
+        } else {
+            Err(hwcrypto_err!(UNAUTHORIZED, "caller do not have permission to access this key"))
         }
     }
 }
@@ -289,9 +266,10 @@ impl IHwCryptoKey for HwCryptoKey {
         &self,
         derivation_key: &DiceBoundDerivationKey,
     ) -> binder::Result<DiceCurrentBoundKeyResult> {
-        let dice_policy = VersionContext::new_current_encrypted(self.uuid.clone())?;
+        let client_policy =
+            ClientPolicyWrapper::new_current(self.client_id.as_slice())?.encrypt()?;
         let derived_key_result =
-            self.derive_dice_policy_bound_key(derivation_key, &dice_policy, true)?;
+            self.derive_dice_policy_bound_key(derivation_key, &client_policy, true)?;
         let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: policy_current } =
             derived_key_result;
         if !policy_current {
@@ -300,32 +278,36 @@ impl IHwCryptoKey for HwCryptoKey {
                 Some("generated a policy that was not the latest"),
             ));
         }
-        Ok(DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: dice_policy })
+        Ok(DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: client_policy })
     }
 
     fn deriveDicePolicyBoundKey(
         &self,
         derivation_key: &DiceBoundDerivationKey,
-        dice_policy_for_key_version: &[u8],
+        client_policy_for_versioned_key: &[u8],
     ) -> binder::Result<DiceBoundKeyResult> {
-        Ok(self.derive_dice_policy_bound_key(derivation_key, dice_policy_for_key_version, true)?)
+        Ok(self.derive_dice_policy_bound_key(
+            derivation_key,
+            client_policy_for_versioned_key,
+            true,
+        )?)
     }
 
     fn getCurrentDicePolicy(&self) -> binder::Result<Vec<u8>> {
-        Ok(VersionContext::new_current_encrypted(self.uuid.clone())?)
+        Ok(ClientPolicyWrapper::new_current(self.client_id.as_slice())?.encrypt()?)
     }
 
     fn keyTokenImport(
         &self,
         key_token: &OpaqueKeyToken,
-        sealing_dice_policy: &[u8],
+        sealing_client_policy: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         // We derive a normal DICE bound key. This will check that the policy matches
         // our DICE chain.
         let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: _ } = self
             .deriveDicePolicyBoundKey(
                 &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
-                sealing_dice_policy,
+                sealing_client_policy,
             )?;
         let key = key.ok_or(binder::Status::new_exception_str(
             binder::ExceptionCode::UNSUPPORTED_OPERATION,
@@ -341,7 +323,7 @@ impl IHwCryptoKey for HwCryptoKey {
         Ok(opaque_key::OpaqueKey::import_token(
             key_token.keyToken.as_slice(),
             sealing_key,
-            self.uuid.clone(),
+            self.client_id.as_slice(),
         )?
         .into())
     }
@@ -384,7 +366,7 @@ impl IHwCryptoKey for HwCryptoKey {
                 let derived_key = derivation_key.derive_opaque_key(
                     key_policy,
                     parameters.context.as_slice(),
-                    self.uuid.clone(),
+                    self.client_id.as_slice(),
                 )?;
                 Ok(DerivedKey::Opaque(Some(derived_key)))
             }
@@ -401,18 +383,19 @@ impl IHwCryptoKey for HwCryptoKey {
         new_key_policy: &KeyPolicy,
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = helpers::aidl_explicit_key_to_rust_key_material(key_to_be_imported)?;
-        Ok(OpaqueKey::import_key_material(new_key_policy, key_material, self.uuid.clone())?)
+        OpaqueKey::import_key_material(new_key_policy, key_material, self.client_id.as_slice())
     }
 
     fn getKeyslotData(&self, keyslot: KeySlot) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         self.check_caller_can_access_keyslot(keyslot)?;
         match keyslot {
             KeySlot::KEYMINT_SHARED_HMAC_KEY => {
-                let key_generator =
-                    EncryptionHeader::generate_with_version(0, EncryptedContent::KeyMaterial);
-                let mock_hmac_key = key_generator.derive_raw_service_encryption_key(
-                    EncryptionHeaderKey::KeyGenerationContext(b"hmac_key_ctx"),
-                )?;
+                let hmac_key = DeviceKeysImpl.get_keymint_shared_hmac_key()?.0;
+                let mut hmac_key_vec = Vec::new();
+                hmac_key_vec.try_reserve(hmac_key.len()).map_err(|e| {
+                    hwcrypto_err!(ALLOCATION_ERROR, "failed to space for key key {:?}", e)
+                })?;
+                hmac_key_vec.extend_from_slice(&hmac_key);
                 let policy = KeyPolicy {
                     usage: KeyUse::SIGN,
                     keyLifetime: KeyLifetime::HARDWARE,
@@ -420,7 +403,11 @@ impl IHwCryptoKey for HwCryptoKey {
                     keyType: KeyType::HMAC_SHA256,
                     keyManagementKey: false,
                 };
-                OpaqueKey::new_opaque_key_from_raw_bytes(&policy, mock_hmac_key, self.uuid.clone())
+                OpaqueKey::new_opaque_key_from_raw_bytes(
+                    &policy,
+                    hmac_key_vec,
+                    self.client_id.as_slice(),
+                )
             }
             _ => Err(binder::Status::new_exception_str(
                 binder::ExceptionCode::UNSUPPORTED_OPERATION,
@@ -452,6 +439,8 @@ mod tests {
     use rpcbinder::RpcSession;
     use test::{assert_ok, expect, expect_eq};
 
+    use crate::tests::{connection_info, unauthorized_connection_info};
+
     #[test]
     fn import_clear_aes_key() {
         let hw_key: Strong<dyn IHwCryptoKey> =
@@ -571,9 +560,7 @@ mod tests {
 
     #[test]
     fn derived_dice_bound_keys() {
-        let hw_device_key = HwCryptoKey::new_binder(
-            Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap(),
-        );
+        let hw_device_key = HwCryptoKey::new_binder(connection_info());
 
         let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
         let key_and_policy =
@@ -606,9 +593,7 @@ mod tests {
 
     #[test]
     fn derived_clear_key() {
-        let hw_device_key = HwCryptoKey::new_binder(
-            Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap(),
-        );
+        let hw_device_key = HwCryptoKey::new_binder(connection_info());
 
         let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
         let key_and_policy =
@@ -659,6 +644,95 @@ mod tests {
         expect!(!openssl::memcmp::eq(&key1, &key3), "keys shouldn't have matched");
     }
 
+    #[test]
+    fn hwcrypto_token_export_import_hmac_use() {
+        // This test is not representative of the complete flow because here the exporter and importer
+        // are the same client, which is not something we would usually do
+        let hw_crypto_key: Strong<dyn IHwCryptoKey> = assert_ok!(
+            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT),
+            "Failed to connect"
+        );
+        let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; 32]));
+        let policy = KeyPolicy {
+            usage: KeyUse::SIGN,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyManagementKey: false,
+            keyType: KeyType::HMAC_SHA256,
+        };
+        let key = assert_ok!(
+            hw_crypto_key.importClearKey(&clear_key, &policy),
+            "couldn't import clear key"
+        );
+        let client_policy =
+            assert_ok!(hw_crypto_key.getCurrentDicePolicy(), "Couldn't get dice policy back");
+        let token = assert_ok!(
+            key.getShareableToken(client_policy.as_slice()),
+            "Couldn't get shareable token"
+        );
+        let imported_key = assert_ok!(
+            hw_crypto_key.keyTokenImport(&token, client_policy.as_slice()),
+            "Couldn't import shareable token"
+        );
+
+        let policy = imported_key.getKeyPolicy();
+        assert!(policy.is_ok(), "Couldn't get token key policy");
+
+        let hw_crypto_operations = assert_ok!(
+            hw_crypto_key.getHwCryptoOperations(),
+            "Couldn't get back a hwcryptokey operations binder object"
+        );
+
+        // Using operations to verify that the keys match
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
+        assert_ok!(
+            hw_crypto_operations.processCommandList(&mut crypto_sets),
+            "couldn't process commands"
+        );
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+
+        // creating a key with the imported key to compare
+        let hmac_parameters = HmacOperationParameters { key: Some(imported_key) };
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
+        assert_ok!(
+            hw_crypto_operations.processCommandList(&mut crypto_sets),
+            "couldn't process commands"
+        );
+        // Extracting the vector from the command list because of ownership
+        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac2)) =
+            crypto_sets.remove(0).operations.remove(0)
+        else {
+            panic!("not reachable, we created this object above on the test");
+        };
+        assert_eq!(mac, mac2, "got a different mac");
+    }
+
     #[test]
     fn create_key_tokens() {
         let hw_key: Strong<dyn IHwCryptoKey> =
@@ -677,10 +751,10 @@ mod tests {
             ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
         let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
 
-        let sealing_dice_policy =
+        let sealing_client_policy =
             hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
 
-        let token = key.getShareableToken(&sealing_dice_policy);
+        let token = key.getShareableToken(&sealing_client_policy);
         expect!(token.is_ok(), "couldn't get shareadble token");
         let token = token.unwrap();
 
@@ -712,7 +786,7 @@ mod tests {
         let hw_key: Strong<dyn IHwCryptoKey> =
             RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
         let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
-        let key = hw_key.keyTokenImport(&token, &sealing_dice_policy);
+        let key = hw_key.keyTokenImport(&token, &sealing_client_policy);
         expect!(key.is_ok(), "couldn't import shareable token");
         let key = key.unwrap();
 
@@ -762,37 +836,26 @@ mod tests {
         };
         let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
 
-        let sealing_dice_policy =
+        let sealing_client_policy =
             hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
 
-        let token = key.getShareableToken(&sealing_dice_policy);
+        let token = key.getShareableToken(&sealing_client_policy);
         expect!(token.is_ok(), "couldn't get shareadble token");
         let token = token.unwrap();
 
-        let bad_dice_policy = VersionContext::new_current_encrypted(
-            Uuid::new_from_string("f41a7796-975a-427a-8cc4-a73f8820430d").unwrap(),
-        )
-        .expect("couldn't create DICE policy");
+        let bad_client_policy = assert_ok!(
+            ClientPolicyWrapper::new_current(&connection_info()),
+            "couldn't create DICE policy"
+        );
+        let bad_client_policy = assert_ok!(bad_client_policy.encrypt(), "couldn't encrypt policy");
 
-        let key = hw_key.keyTokenImport(&token, &bad_dice_policy);
+        let key = hw_key.keyTokenImport(&token, &bad_client_policy);
         expect!(key.is_err(), "shouldn't be able to import key using the wrong DICE policy");
     }
 
-    #[test]
-    fn get_keyslot() {
-        let hw_key: Strong<dyn IHwCryptoKey> =
-            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
-
-        let key = hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY);
-        expect!(key.is_ok(), "couldn't get key");
-    }
-
     #[test]
     fn get_keyslot_form_unautorized_caller() {
-        let hw_key = HwCryptoKey::new_binder(
-            Uuid::new_from_string("00000000-0000-0000-0000-000000000000")
-                .expect("couldn't create uuid"),
-        );
+        let hw_key = HwCryptoKey::new_binder(unauthorized_connection_info());
         let key = hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY);
         expect!(key.is_err(), "shouldn't be able to get key");
     }
diff --git a/hwcryptohal/server/hwcrypto_ipc_server.rs b/hwcryptohal/server/hwcrypto_ipc_server.rs
index 0463c42..bf0a538 100644
--- a/hwcryptohal/server/hwcrypto_ipc_server.rs
+++ b/hwcryptohal/server/hwcrypto_ipc_server.rs
@@ -16,23 +16,38 @@
 
 //! AIDL IPC Server code.
 use crate::hwcrypto_device_key;
+use authmgr_be_lib::{default_handover_port_config, HandoverService};
 use binder::SpIBinder;
 use core::ffi::CStr;
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use rpcbinder::RpcServer;
-use tipc::{self, Manager, PortCfg, Uuid};
+use std::sync::Arc;
+use tipc::raw::{EventLoop, HandleSetWrapper};
+use tipc::{self, ClientIdentifier, PortCfg};
 
 pub(crate) const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
+pub(crate) const HANDOVER_SERVICE_PORT: &str =
+    "android.hardware.security.see.hwcrypto.IHwCryptoKey/default.hnd";
 pub(crate) const NUM_IPC_QUEUES: u32 = 4;
 
-fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
-    Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
+fn create_device_key_service(client_identifier: ClientIdentifier) -> Option<SpIBinder> {
+    let uuid = match client_identifier {
+        ClientIdentifier::UUID(uuid) => uuid,
+        _ => {
+            log::error!("Expected a Uuid as client id, got: {:?}", client_identifier);
+            return None;
+        }
+    };
+    let mut client_id = Vec::new();
+    let uuid_string = uuid.to_string();
+    let uuid_bytes = uuid_string.as_bytes();
+    client_id.try_reserve(uuid_bytes.len()).ok()?;
+    client_id.extend_from_slice(uuid_bytes);
+    Some(hwcrypto_device_key::HwCryptoKey::new_binder(client_id).as_binder())
 }
 
-pub fn main_loop() -> Result<(), HwCryptoError> {
-    let hwdk_rpc_server = RpcServer::new_per_session(create_device_key_service);
-
-    let cfg = PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
+fn hwcryptohal_port_cfg() -> Result<PortCfg, HwCryptoError> {
+    Ok(PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
         .map_err(|e| {
             hwcrypto_err!(
                 GENERIC_ERROR,
@@ -43,14 +58,51 @@ pub fn main_loop() -> Result<(), HwCryptoError> {
         })?
         .msg_queue_len(NUM_IPC_QUEUES)
         .allow_ta_connect()
-        .allow_ns_connect();
+        .allow_ns_connect())
+}
+
+pub fn main_loop() -> Result<(), HwCryptoError> {
+    let hwdk_rpc_server = Arc::new(RpcServer::new_per_session(create_device_key_service));
+    let hwdk_cfg = hwcryptohal_port_cfg()?;
+
+    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);
+    // keeping a reference to `_port_wrapper_hw_crypto` is necessary for the service not to be
+    // removed from the set
+    let _port_wrapper_hw_crypto =
+        handle_set_wrapper.add_port(&hwdk_cfg, hwdk_rpc_server.clone())?;
 
-    let manager = Manager::<_, _, 1, 4>::new_unbuffered(hwdk_rpc_server, cfg)
-        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not create service manager: {:?}", e))?;
+    let handle_set_wrapper_for_cb = Arc::clone(&handle_set_wrapper);
+
+    let handover_cb_per_session = move |client_id| {
+        Some(
+            HandoverService::new_handover_session(
+                client_id,
+                Arc::downgrade(&handle_set_wrapper_for_cb),
+                Arc::clone(&hwdk_rpc_server),
+                hwcryptohal_port_cfg().ok()?,
+            )
+            .as_binder(),
+        )
+    };
+
+    let handover_rpc_service = Arc::new(RpcServer::new_per_session(handover_cb_per_session));
+
+    let handover_service_port_cfg =
+        default_handover_port_config(HANDOVER_SERVICE_PORT).map_err(|e| {
+            hwcrypto_err!(
+                GENERIC_ERROR,
+                "could not create port config for {:?}: {:?}",
+                HANDOVER_SERVICE_PORT,
+                e
+            )
+        })?;
+    // keeping a reference to `_port_wrapper_handover` is necessary for the service not to be
+    // removed from the set
+    let _port_wrapper_handover =
+        handle_set_wrapper.add_port(&handover_service_port_cfg, handover_rpc_service)?;
 
-    manager
-        .run_event_loop()
-        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "service manager received error: {:?}", e))
+    let event_loop = EventLoop::new(handle_set_wrapper.clone());
+    Ok(event_loop.run()?)
 }
 
 #[cfg(test)]
diff --git a/hwcryptohal/server/hwcrypto_operations.rs b/hwcryptohal/server/hwcrypto_operations.rs
index fe109aa..85dd517 100644
--- a/hwcryptohal/server/hwcrypto_operations.rs
+++ b/hwcryptohal/server/hwcrypto_operations.rs
@@ -18,6 +18,7 @@
 //! key generation interface and to process cryptographic operations.
 
 use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
+    types::OperationData::OperationData, CryptoOperation::CryptoOperation,
     CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
     IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
 };
@@ -56,10 +57,10 @@ impl IHwCryptoOperations for HwCryptoOperations {
                     cmd_processor.process_all_steps(&mut command_list.operations)?;
                     if !cmd_processor.is_destroyed() {
                         let operation_context = CryptoOperationContext::new_binder(cmd_processor);
-                        (*results
+                        results
                             .last_mut()
-                            .expect("shouldn't happen, we pushed an element before match"))
-                        .context = Some(operation_context);
+                            .expect("shouldn't happen, we pushed an element before match")
+                            .context = Some(operation_context);
                     }
                 }
                 Some(operation_context) => {
@@ -67,6 +68,12 @@ impl IHwCryptoOperations for HwCryptoOperations {
                         .process_all_steps(&mut command_list.operations)?;
                 }
             }
+            // Just keep the command list elements that contain an output that needs to be return to
+            // the caller. At this point CryptoOperation::DataOutput is the only operation returning
+            // data using vectors but only when it contains an OperationData::DataBuffer.
+            command_list
+                .operations
+                .retain(|x| matches!(x, CryptoOperation::DataOutput(OperationData::DataBuffer(_))));
         }
         Ok(results)
     }
@@ -79,9 +86,10 @@ mod tests {
     use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
-            HmacOperationParameters::HmacOperationParameters, KeyLifetime::KeyLifetime,
-            KeyType::KeyType, KeyUse::KeyUse, OperationData::OperationData,
-            SymmetricCryptoParameters::SymmetricCryptoParameters,
+            ExplicitKeyMaterial::ExplicitKeyMaterial,
+            HmacOperationParameters::HmacOperationParameters, HmacKey::HmacKey,
+            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
+            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
             SymmetricOperation::SymmetricOperation,
             SymmetricOperationParameters::SymmetricOperationParameters,
         },
@@ -90,7 +98,7 @@ mod tests {
             DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
             DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
             DiceBoundDerivationKey::DiceBoundDerivationKey,
-            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey, KeySlot::KeySlot,
+            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
         },
         KeyPolicy::KeyPolicy,
         OperationParameters::OperationParameters,
@@ -210,8 +218,16 @@ mod tests {
         let hw_key: Strong<dyn IHwCryptoKey> =
             RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
 
-        let key =
-            hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY).expect("couldn't get key");
+        let policy = KeyPolicy {
+            usage: KeyUse::SIGN,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: KeyType::HMAC_SHA256,
+            keyManagementKey: false,
+        };
+        let hmac_key_material: ExplicitKeyMaterial =
+            ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; 32]));
+        let key = hw_key.importClearKey(&hmac_key_material, &policy).expect("couldn't import key");
 
         let hw_crypto = hw_key.getHwCryptoOperations().expect("Failed to get crypto ops.");
 
diff --git a/hwcryptohal/server/interfaces/client_identification.rs b/hwcryptohal/server/interfaces/client_identification.rs
new file mode 100644
index 0000000..f780863
--- /dev/null
+++ b/hwcryptohal/server/interfaces/client_identification.rs
@@ -0,0 +1,43 @@
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
+//! Module providing trait definition to access and check clients policies against their identities.
+
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::KeySlot::KeySlot;
+use hwcryptohal_common::err::HwCryptoError;
+
+pub struct ClientPolicyCheck {
+    pub policy_matches: bool,
+    pub policy_is_current: bool,
+}
+
+/// Abstraction of client identification and authorization
+pub trait ClientIdentification {
+    /// checks that the provided client policy matches the client
+    fn check_client_policy(
+        client_id: &[u8],
+        client_policy: &[u8],
+    ) -> Result<ClientPolicyCheck, HwCryptoError>;
+
+    /// retrieves the client current client policy
+    fn get_client_current_policy(client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError>;
+
+    /// checks if the caller can access the requested keyslot
+    fn client_can_access_keyslot(
+        client_id: &[u8],
+        key_slot: KeySlot,
+    ) -> Result<bool, HwCryptoError>;
+}
diff --git a/hwcryptohal/server/interfaces/device_keys.rs b/hwcryptohal/server/interfaces/device_keys.rs
new file mode 100644
index 0000000..1cf97f3
--- /dev/null
+++ b/hwcryptohal/server/interfaces/device_keys.rs
@@ -0,0 +1,44 @@
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
+//! Module providing trait definition to access device specific keys.
+
+use hwcryptohal_common::err::HwCryptoError;
+
+/// Definition for the Keymint shared HMAC key
+pub struct KeymintHmacKey(pub [u8; 32]);
+
+/// Abstraction of device specific keys
+pub trait DeviceKeys {
+    /// Returns the Keymint shared HMAC key. The size of the key matches what Android expects.
+    fn get_keymint_shared_hmac_key(&self) -> Result<KeymintHmacKey, HwCryptoError>;
+
+    /// Returns a unique versioned key cryptographically bound to the caller, context and security
+    /// version. If the caller current version is greater or equal than the provided version,
+    /// the function should succeed. Calling this function with the same caller, version and context
+    /// should generate the same key, if the version check passes. Notice that the security version
+    /// could be a DICE policy.
+    fn derive_caller_unique_key(
+        &self,
+        key_context: &[u8],
+        key_sec_version: &[u8],
+        key_size: usize,
+    ) -> Result<Vec<u8>, HwCryptoError>;
+
+    /// Returns the caller current security version. Notice that this version could be a DICE
+    /// policy.
+    fn get_caller_current_security_version(&self) -> Result<Vec<u8>, HwCryptoError>;
+}
diff --git a/hwcryptohal/server/crypto_provider.rs b/hwcryptohal/server/interfaces/lib.rs
similarity index 58%
rename from hwcryptohal/server/crypto_provider.rs
rename to hwcryptohal/server/interfaces/lib.rs
index 77e00f9..6397857 100644
--- a/hwcryptohal/server/crypto_provider.rs
+++ b/hwcryptohal/server/interfaces/lib.rs
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,9 +14,14 @@
  * limitations under the License.
  */
 
-//! Module providing access to the cryptographic implementations used by the library.
+//! Module providing trait definitions
+mod client_identification;
+mod device_keys;
+mod memory_access;
+mod time;
 
-pub(crate) use crate::platform_functions::PlatformRng as RngImpl;
-pub(crate) use kmr_crypto_boring::aes::BoringAes as AesImpl;
-pub(crate) use kmr_crypto_boring::hmac::BoringHmac as HmacImpl;
-pub(crate) const HMAC_MAX_SIZE: usize = bssl_sys::EVP_MAX_MD_SIZE as usize;
+pub use client_identification::ClientIdentification;
+pub use client_identification::ClientPolicyCheck;
+pub use device_keys::{DeviceKeys, KeymintHmacKey};
+pub use memory_access::MemoryMappedObject;
+pub use time::DeviceTime;
diff --git a/hwcryptohal/server/interfaces/memory_access.rs b/hwcryptohal/server/interfaces/memory_access.rs
new file mode 100644
index 0000000..7cd292d
--- /dev/null
+++ b/hwcryptohal/server/interfaces/memory_access.rs
@@ -0,0 +1,36 @@
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
+//! Module providing trait definition to map objects to memory.
+
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::MemoryBufferParameter::MemoryBufferParameter;
+use hwcryptohal_common::err::HwCryptoError;
+use vm_memory::VolatileSlice;
+
+/// Abstraction of memory mapped objects. Notice that the trait do not contain an unmap function, so
+/// any cleanup needed by the implementation must be done by implementing `Drop`.
+pub trait MemoryMappedObject: Send {
+    /// Maps a `MemoryBufferParameter` into a `MemoryMappedObject`
+    fn mmap(memory_buffer: &MemoryBufferParameter) -> Result<Self, HwCryptoError>
+    where
+        Self: std::marker::Sized;
+
+    /// Gets a memory slice that can be used to read or write on the memory mapped object
+    fn get_memory_slice(&mut self) -> Result<VolatileSlice, HwCryptoError>;
+
+    /// Returns the mapped memory buffer size
+    fn buffer_size(&self) -> usize;
+}
diff --git a/hwcryptohal/server/interfaces/rules.mk b/hwcryptohal/server/interfaces/rules.mk
new file mode 100644
index 0000000..31970b8
--- /dev/null
+++ b/hwcryptohal/server/interfaces/rules.mk
@@ -0,0 +1,34 @@
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
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := hwcryptohalinterfaces
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/app/sample/hwcryptohal/aidl/rust  \
+	trusty/user/app/sample/hwcryptohal/common  \
+	$(call FIND_CRATE,vm-memory) \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/hwcryptohal/server/interfaces/time.rs b/hwcryptohal/server/interfaces/time.rs
new file mode 100644
index 0000000..caf3177
--- /dev/null
+++ b/hwcryptohal/server/interfaces/time.rs
@@ -0,0 +1,26 @@
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
+//! Module providing trait definition to access device time functionality.
+
+use hwcryptohal_common::err::HwCryptoError;
+
+/// Abstraction of device specific time functionality
+pub trait DeviceTime {
+    /// Returns time in ms from a platform defined epoch. The time must not go back in time for a
+    /// given boot.
+    fn current_epoch_time_ms() -> Result<u64, HwCryptoError>;
+}
diff --git a/hwcryptohal/server/lib.rs b/hwcryptohal/server/lib.rs
index f824779..3f85e87 100644
--- a/hwcryptohal/server/lib.rs
+++ b/hwcryptohal/server/lib.rs
@@ -25,16 +25,40 @@ pub mod hwcrypto_ipc_server;
 mod cmd_processing;
 mod crypto_operation;
 mod crypto_operation_context;
-mod crypto_provider;
-mod ffi_bindings;
 mod helpers;
 mod hwcrypto_device_key;
 mod hwcrypto_operations;
 mod opaque_key;
-mod platform_functions;
 mod service_encryption_key;
 
+use hwcryptohalinterfaces::{ClientIdentification, DeviceKeys, DeviceTime, MemoryMappedObject};
+use hwcryptohalplatform::{
+    AesImpl, ClientIdentificationImpl, DeviceKeysImpl, DeviceTimeImpl, HmacImpl,
+    MemoryMappedObjectImpl, RngImpl,
+};
+use kmr_common::crypto::{Aes, Hkdf, Hmac, Rng};
+use static_assertions::assert_impl_all;
+
+assert_impl_all!(ClientIdentificationImpl: ClientIdentification);
+assert_impl_all!(DeviceKeysImpl: DeviceKeys);
+assert_impl_all!(DeviceTimeImpl: DeviceTime);
+assert_impl_all!(MemoryMappedObjectImpl: MemoryMappedObject);
+
+assert_impl_all!(AesImpl: Aes);
+assert_impl_all!(HmacImpl: Hkdf, Hmac);
+assert_impl_all!(RngImpl: Rng);
+
 #[cfg(test)]
 mod tests {
     test::init!();
+
+    pub(crate) fn connection_info() -> Vec<u8> {
+        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
+        "f41a7796-975a-4279-8cc4-b73f8820430d".as_bytes().to_vec()
+    }
+
+    pub(crate) fn unauthorized_connection_info() -> Vec<u8> {
+        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
+        "00000000-0000-0000-0000-000000000000".as_bytes().to_vec()
+    }
 }
diff --git a/hwcryptohal/server/opaque_key.rs b/hwcryptohal/server/opaque_key.rs
index 5d1a152..38493b2 100644
--- a/hwcryptohal/server/opaque_key.rs
+++ b/hwcryptohal/server/opaque_key.rs
@@ -36,6 +36,8 @@ use binder::binder_impl::Binder;
 use ciborium::Value;
 use core::fmt;
 use coset::{AsCborValue, CborSerializable, CoseError};
+use hwcryptohalinterfaces::DeviceTime;
+use hwcryptohalplatform::{AesImpl, DeviceTimeImpl, HmacImpl, RngImpl};
 use hwcryptohal_common::{
     aidl_enum_wrapper, cose_enum_gen,
     err::HwCryptoError,
@@ -51,12 +53,10 @@ use kmr_common::{
 };
 use kmr_wire::{keymint::EcCurve, AsCborValue as _};
 use std::sync::{Mutex, OnceLock};
-use tipc::Uuid;
 
 use crate::helpers;
 use crate::hwcrypto_device_key::HwCryptoKey;
 use crate::service_encryption_key::{EncryptedContent, EncryptionHeader, EncryptionHeaderKey};
-use crate::{crypto_provider, platform_functions};
 
 /// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
 const UNIQUE_VALUE_SIZEOF: usize = 32;
@@ -101,14 +101,14 @@ fn get_boot_unique_value() -> Result<BootUniqueValue, HwCryptoError> {
     // current implementation with one that can fail when trying to retrieve a random number.
     // If the RNG changes to a fallible one we could use `get_or_try_init`.
     let boot_unique_value = BOOT_UNIQUE_VALUE.get_or_init(|| {
-        let mut rng = crypto_provider::RngImpl::default();
         let mut new_boot_unique_value = BootUniqueValue([0u8; UNIQUE_VALUE_SIZEOF]);
-        rng.fill_bytes(&mut new_boot_unique_value.0[..]);
+        RngImpl.fill_bytes(&mut new_boot_unique_value.0[..]);
         new_boot_unique_value
     });
     Ok(boot_unique_value.clone())
 }
 
+#[allow(clippy::enum_variant_names)]
 #[derive(Copy, Clone)]
 pub(crate) enum HkdfOperationType {
     DiceBoundDerivation = 1,
@@ -227,7 +227,7 @@ pub(crate) struct ExpirationTime {
 
 impl ExpirationTime {
     fn new(expiration_time_sec: u64) -> Result<Self, HwCryptoError> {
-        let set_time_ms = platform_functions::current_epoch_time_ms()?;
+        let set_time_ms = DeviceTimeImpl::current_epoch_time_ms()?;
         let valid_period_ms = expiration_time_sec
             .checked_mul(1000)
             .ok_or(hwcrypto_err!(BAD_PARAMETER, "validity period is too big",))?;
@@ -235,7 +235,7 @@ impl ExpirationTime {
     }
 
     pub(crate) fn check_validity(&self) -> Result<bool, HwCryptoError> {
-        let current_time_ms = platform_functions::current_epoch_time_ms()?;
+        let current_time_ms = DeviceTimeImpl::current_epoch_time_ms()?;
         if current_time_ms < self.set_time_ms {
             return Err(hwcrypto_err!(INVALID_KEY, "current time is before expiry set time",));
         }
@@ -264,7 +264,6 @@ impl AsCborValue for ExpirationTime {
     }
 
     fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
-        //unimplemented!("sdsdsdsd")
         let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
         if opaque_key_map.len() != 2 {
             return Err(CoseError::ExtraneousData);
@@ -342,7 +341,7 @@ impl KeyHeaderMetadata {
         let protection_id = ProtectionIdSerializable::try_from(protection_id).map_err(|e| {
             hwcrypto_err!(GENERIC_ERROR, "couldn't convert from protection id {:?}", e,)
         })?;
-        if !self.protection_id_settings.contains_key(&protection_id) {
+        if self.protection_id_settings.contains_key(&protection_id) {
             return Err(hwcrypto_err!(
                 BAD_PARAMETER,
                 "settings for protection id {:?} have already been set",
@@ -604,11 +603,11 @@ impl AsCborValue for ProtectionSetting {
         cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
 
         let key = Value::Integer((ProtectionSettingsCoseLabels::WriteProtection as i64).into());
-        let value = Value::Bool(self.write_protection.into());
+        let value = Value::Bool(self.write_protection);
         cbor_map.push((key, value));
 
         let key = Value::Integer((ProtectionSettingsCoseLabels::ReadProtection as i64).into());
-        let value = Value::Bool(self.read_protection.into());
+        let value = Value::Bool(self.read_protection);
         cbor_map.push((key, value));
 
         Ok(Value::Map(cbor_map))
@@ -658,6 +657,7 @@ pub struct OpaqueKey {
     pub(crate) key_header: KeyHeader,
     pub(crate) key_material: KeyMaterial,
     pub(crate) key_in_owner_control: bool,
+    client_id: Option<Vec<u8>>,
 }
 
 impl From<OpaqueKey> for binder::Strong<dyn IOpaqueKey> {
@@ -761,7 +761,7 @@ impl AsCborValue for OpaqueKey {
             .map_err(|_| CoseError::EncodeFailed)?;
         let key_metadata = key_metadata.ok_or(CoseError::EncodeFailed)?;
         key_header.set_metadata_from_cbor(key_metadata).map_err(|_| CoseError::EncodeFailed)?;
-        Ok(OpaqueKey { key_material, key_header, key_in_owner_control: false })
+        Ok(OpaqueKey { key_material, key_header, key_in_owner_control: false, client_id: None })
     }
 }
 
@@ -769,11 +769,21 @@ impl OpaqueKey {
     pub(crate) fn new_binder(
         policy: &KeyPolicy,
         key_material: KeyMaterial,
-        _connection_info: Uuid,
+        client_conn_id: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_header = KeyHeader::new(policy)?;
         check_key_material_with_policy(&key_material, policy)?;
-        let opaque_key = OpaqueKey { key_header, key_material, key_in_owner_control: true };
+        let mut client_id = Vec::new();
+        client_id
+            .try_reserve(client_conn_id.len())
+            .map_err(|_| hwcrypto_err!(ALLOCATION_ERROR, "couldn't allcoate client id"))?;
+        client_id.extend_from_slice(client_conn_id);
+        let opaque_key = OpaqueKey {
+            key_header,
+            key_material,
+            key_in_owner_control: true,
+            client_id: Some(client_id),
+        };
         let opaque_keybinder =
             BnOpaqueKey::new_binder(opaque_key, binder::BinderFeatures::default());
         Ok(opaque_keybinder)
@@ -792,11 +802,11 @@ impl OpaqueKey {
     pub(crate) fn import_key_material(
         policy: &KeyPolicy,
         key_material: KeyMaterial,
-        connection_info: Uuid,
+        client_conn_id: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         check_key_material_with_policy(&key_material, policy)?;
         Self::check_clear_import_policy(policy)?;
-        Self::new_binder(policy, key_material, connection_info)
+        Self::new_binder(policy, key_material, client_conn_id)
     }
 
     fn check_ownership(&self) -> bool {
@@ -817,12 +827,12 @@ impl OpaqueKey {
         key.set_expiration_time(TOKEN_EXPORT_EXPIRATION_TIME_10S)?;
         let token_creator = EncryptionHeader::generate(EncryptedContent::KeyMaterial)?;
 
-        // This is a temporary workaround to create a DICE bound key because we will move to
-        // using DICE policies and the AuthMgr instead of UUIDs.
-        let hw_device_key = HwCryptoKey {
-            uuid: Uuid::new_from_string("ffffffff-ffff-ffff-ffff-ffffffffffff")
-                .expect("shouldn't happen, string can be parsed to uuid"),
-        };
+        let mut client_id = Vec::new();
+        let client_conn_id =
+            self.client_id.as_ref().ok_or(hwcrypto_err!(GENERIC_ERROR, "key has no client id"))?;
+        client_id.try_reserve(client_conn_id.len())?;
+        client_id.extend_from_slice(client_conn_id.as_slice());
+        let hw_device_key = HwCryptoKey { client_id };
 
         // Create a DICE key bound to the receiver policy.
         let DiceBoundKeyResult { diceBoundKey: sealing_dice_key, dicePolicyWasCurrent: _ } =
@@ -856,7 +866,7 @@ impl OpaqueKey {
     pub(crate) fn import_token(
         key_token: &[u8],
         sealing_dice_key: OpaqueKey,
-        _connection_information: Uuid,
+        _client_conn_id: &[u8],
     ) -> Result<Self, HwCryptoError> {
         // External encryption layer used a HwCrypto service device key
         let (_, content) = EncryptionHeader::decrypt_content_service_encryption_key(
@@ -879,11 +889,14 @@ impl OpaqueKey {
         ))?;
 
         let (_, inner_key) = EncryptionHeader::decrypt_content_service_encryption_key(
-            &inner_content,
+            inner_content,
             EncryptionHeaderKey::ProvidedHkdfKey(sealing_key),
             EncryptedContent::KeyMaterial,
         )?;
 
+        // We are not propagating _client_conn_id into the imported key. Currently connection
+        // information is only used to export keys and keys imported by the client should not be
+        // re-exported.
         let opaque_key = Self::from_cbor_value(Value::from_slice(inner_key.as_slice())?)?;
         if !opaque_key.expiration_time_set()? {
             return Err(hwcrypto_err!(
@@ -898,25 +911,39 @@ impl OpaqueKey {
     #[allow(unused)]
     pub(crate) fn generate_opaque_key(
         policy: &KeyPolicy,
-        connection_info: Uuid,
+        client_conn_id: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = generate_key_material(&policy.keyType, None)?;
-        OpaqueKey::new_binder(policy, key_material, connection_info)
+        OpaqueKey::new_binder(policy, key_material, client_conn_id)
     }
 
     fn try_clone(&self) -> Result<Self, HwCryptoError> {
         let key_header = self.key_header.try_clone()?;
         let key_material = self.key_material.clone();
-        Ok(OpaqueKey { key_header, key_material, key_in_owner_control: self.key_in_owner_control })
+        let client_id = if self.client_id.is_some() {
+            let mut client_id = Vec::new();
+            let client_conn_id = self.client_id.as_ref().unwrap();
+            client_id.try_reserve(client_conn_id.len())?;
+            client_id.extend_from_slice(client_conn_id.as_slice());
+            Some(client_id)
+        } else {
+            None
+        };
+        Ok(OpaqueKey {
+            key_header,
+            key_material,
+            key_in_owner_control: self.key_in_owner_control,
+            client_id,
+        })
     }
 
     pub(crate) fn new_opaque_key_from_raw_bytes(
         policy: &KeyPolicy,
         key_material: Vec<u8>,
-        connection_info: Uuid,
+        client_conn_id: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         let key_material = generate_key_material(&policy.keyType, Some(key_material))?;
-        OpaqueKey::new_binder(policy, key_material, connection_info)
+        OpaqueKey::new_binder(policy, key_material, client_conn_id)
     }
 
     pub(crate) fn check_key_derivation_parameters(
@@ -951,11 +978,10 @@ impl OpaqueKey {
         let context_with_op_type = context.create_key_derivation_context()?;
         match &self.key_material {
             KeyMaterial::Hmac(key) => {
-                let hkdf = crypto_provider::HmacImpl;
                 let explicit_key = explicit!(key).map_err(|_| {
                     hwcrypto_err!(BAD_PARAMETER, "only explicit HMAC keys supported")
                 })?;
-                let raw_key = hkdf
+                let raw_key = HmacImpl
                     .hkdf(&[], &explicit_key.0, context_with_op_type.as_slice(), derived_key_size)
                     .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "couldn't derive key {:?}", e))?;
                 Ok(raw_key)
@@ -999,7 +1025,7 @@ impl OpaqueKey {
         &self,
         policy: &[u8],
         context: &[u8],
-        connection_info: Uuid,
+        client_conn_id: &[u8],
     ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
         self.expiration_time_valid()?;
         let aidl_policy = policy::cbor_policy_to_aidl(policy)?;
@@ -1009,7 +1035,7 @@ impl OpaqueKey {
         op_context.add_binary_string(policy)?;
         op_context.add_binary_string(context)?;
         let raw_key_material = self.derive_raw_key_material(op_context, derived_key_size)?;
-        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material, connection_info)
+        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material, client_conn_id)
     }
 
     fn derivation_allowed_lifetime(
@@ -1385,9 +1411,6 @@ pub(crate) fn generate_key_material(
     key_type: &KeyType,
     key_random_bytes: Option<Vec<u8>>,
 ) -> Result<KeyMaterial, HwCryptoError> {
-    let aes = crypto_provider::AesImpl;
-    let hmac = crypto_provider::HmacImpl;
-    let mut rng = crypto_provider::RngImpl::default();
     match *key_type {
         KeyType::AES_128_CBC_NO_PADDING
         | KeyType::AES_128_CBC_PKCS7_PADDING
@@ -1422,7 +1445,7 @@ pub(crate) fn generate_key_material(
                     )),
                 }
             } else {
-                Ok(aes.generate_key(&mut rng, variant, &[])?)
+                Ok(AesImpl.generate_key(&mut RngImpl, variant, &[])?)
             }
         }
         KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
@@ -1439,8 +1462,8 @@ pub(crate) fn generate_key_material(
                     Ok(KeyMaterial::Hmac(crypto::hmac::Key::new(key_bytes).into()))
                 }
             } else {
-                Ok(hmac.generate_key(
-                    &mut rng,
+                Ok(HmacImpl.generate_key(
+                    &mut RngImpl,
                     kmr_wire::KeySizeInBits((key_size_bytes * 8).try_into().map_err(|_| {
                         hwcrypto_err!(
                             GENERIC_ERROR,
@@ -1458,7 +1481,7 @@ pub(crate) fn generate_key_material(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use test::{expect, expect_eq};
+    use test::{assert_ok, expect, expect_eq};
     use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
         types::{
             AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
@@ -1471,7 +1494,9 @@ mod tests {
         KeyPolicy::KeyPolicy,
         OperationParameters::OperationParameters,
     };
+
     use crate::cmd_processing::CmdProcessorContext;
+    use crate::tests::connection_info;
 
     #[test]
     fn boot_unique_values_match() {
@@ -1563,9 +1588,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let uuid = Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap();
-        let key =
-            OpaqueKey::generate_opaque_key(&policy, uuid.clone()).expect("couldn't generate key");
+        let uuid = connection_info();
+        let key = OpaqueKey::generate_opaque_key(&policy, &uuid).expect("couldn't generate key");
         let hw_device_key = HwCryptoKey::new_binder(uuid);
         let sealing_dice_policy =
             hw_device_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
@@ -1594,9 +1618,8 @@ mod tests {
             keyType: key_type,
             keyManagementKey: false,
         };
-        let uuid = Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap();
-        let key =
-            OpaqueKey::generate_opaque_key(&policy, uuid.clone()).expect("couldn't generate key");
+        let uuid = connection_info();
+        let key = OpaqueKey::generate_opaque_key(&policy, &uuid).expect("couldn't generate key");
         let key: OpaqueKey = (&key).try_into().expect("couldn't cast back key");
         key.set_expiration_time(0).expect("couldn't set up expiration time");
         let binder_key = BnOpaqueKey::new_binder(key, binder::BinderFeatures::default());
@@ -1622,4 +1645,24 @@ mod tests {
             "shouldn't be able to run an operation with an expired key"
         )
     }
+
+    #[test]
+    fn protection_id_can_be_set() {
+        let usage = KeyUse::ENCRYPT_DECRYPT;
+        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
+        let policy = KeyPolicy {
+            usage,
+            keyLifetime: KeyLifetime::PORTABLE,
+            keyPermissions: Vec::new(),
+            keyType: key_type,
+            keyManagementKey: false,
+        };
+        let uuid = connection_info();
+        let key =
+            assert_ok!(OpaqueKey::generate_opaque_key(&policy, &uuid), "couldn't generate key");
+        assert_ok!(
+            key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &[OperationType::WRITE]),
+            "couldn't set protectionID"
+        )
+    }
 }
diff --git a/hwcryptohal/server/bindings.h b/hwcryptohal/server/platform/bindings.h
similarity index 100%
rename from hwcryptohal/server/bindings.h
rename to hwcryptohal/server/platform/bindings.h
diff --git a/hwcryptohal/server/platform/client_identification.rs b/hwcryptohal/server/platform/client_identification.rs
new file mode 100644
index 0000000..9815d54
--- /dev/null
+++ b/hwcryptohal/server/platform/client_identification.rs
@@ -0,0 +1,158 @@
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
+//! Module providing client identification functions.
+
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::KeySlot::KeySlot;
+use ciborium::Value;
+use coset::{AsCborValue, CborSerializable, CoseError};
+use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
+use hwcryptohalinterfaces::{ClientIdentification, ClientPolicyCheck, DeviceKeys};
+use tipc::Uuid;
+
+use crate::device_keys::bytes_to_version;
+
+// enum used for serializing the `ClientPolicyUuidBased`
+cose_enum_gen! {
+    enum UuidPolicyCoseLabels {
+        Uuid = -65537,
+        Version = -65538,
+    }
+}
+
+// Policy based on uuids for internal Trusty Connections. It is based on the Trusty security version
+// retrievable from HwKey and the uuid of the caller. `ClientPolicyUuidBased` encryption is similar
+// to what KeyMint uses to wrap keys.
+struct ClientPolicyUuidBased {
+    uuid: Uuid,
+    version: u32,
+}
+
+impl ClientPolicyUuidBased {
+    fn get_current_version() -> Result<u32, HwCryptoError> {
+        bytes_to_version(crate::DeviceKeysImpl.get_caller_current_security_version()?.as_slice())
+    }
+
+    fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
+        let version = Self::get_current_version()?;
+        Ok(ClientPolicyUuidBased { uuid, version })
+    }
+
+    fn check_identity(&self, uuid: &Uuid) -> Result<bool, HwCryptoError> {
+        Ok(*uuid == self.uuid)
+    }
+
+    fn is_policy_current(&self) -> Result<bool, HwCryptoError> {
+        let current_version = Self::get_current_version()?;
+        Ok(self.version >= current_version)
+    }
+}
+
+impl AsCborValue for ClientPolicyUuidBased {
+    fn to_cbor_value(self) -> Result<Value, CoseError> {
+        let mut cbor_map = Vec::<(Value, Value)>::new();
+        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
+
+        let key = Value::Integer((UuidPolicyCoseLabels::Uuid as i64).into());
+        let value = Value::Text(self.uuid.to_string());
+        cbor_map.push((key, value));
+
+        let key = Value::Integer((UuidPolicyCoseLabels::Version as i64).into());
+        let value = Value::Integer(self.version.into());
+        cbor_map.push((key, value));
+
+        Ok(Value::Map(cbor_map))
+    }
+
+    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
+        let client_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
+        let mut uuid: Option<Uuid> = None;
+        let mut version: Option<u32> = None;
+        if client_policy.len() != 2 {
+            return Err(CoseError::ExtraneousData);
+        }
+        for (map_key, map_val) in client_policy {
+            match map_key {
+                Value::Integer(key) => {
+                    match key.try_into().map_err(|_| {
+                        CoseError::UnexpectedItem("value not matching enum", "UuidPolicyCoseLabels")
+                    })? {
+                        UuidPolicyCoseLabels::Uuid => {
+                            let uuid_str = map_val
+                                .into_text()
+                                .map_err(|_| CoseError::UnexpectedItem("other type", "string"))?;
+                            let parsed_uuid = Uuid::new_from_string(&uuid_str)
+                                .map_err(|_| CoseError::EncodeFailed)?;
+                            uuid = Some(parsed_uuid);
+                        }
+                        UuidPolicyCoseLabels::Version => {
+                            version = Some(
+                                map_val
+                                    .into_integer()
+                                    .map_err(|_| {
+                                        CoseError::UnexpectedItem("not an integer", "integer")
+                                    })?
+                                    .try_into()
+                                    .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
+                            );
+                        }
+                    }
+                }
+                _ => return Err(CoseError::ExtraneousData),
+            }
+        }
+        let uuid = uuid.ok_or(CoseError::EncodeFailed)?;
+        let version = version.ok_or(CoseError::EncodeFailed)?;
+        Ok(ClientPolicyUuidBased { uuid, version })
+    }
+}
+
+fn get_uuid(uuid_bytes: &[u8]) -> Result<Uuid, HwCryptoError> {
+    let uuid_str = std::str::from_utf8(uuid_bytes)
+        .map_err(|e| hwcrypto_err!(BAD_PARAMETER, "couldn't parse uuid {:?}", e))?;
+    Ok(Uuid::new_from_string(uuid_str)?)
+}
+
+pub struct TrustyClientIdentification;
+
+impl ClientIdentification for TrustyClientIdentification {
+    fn check_client_policy(
+        client_id: &[u8],
+        client_policy: &[u8],
+    ) -> Result<ClientPolicyCheck, HwCryptoError> {
+        let client_id = get_uuid(client_id)?;
+        let client_policy =
+            ClientPolicyUuidBased::from_cbor_value(Value::from_slice(client_policy)?)?;
+        let policy_matches = client_policy.check_identity(&client_id)?;
+        // there is no reason to check versions if the client is different
+        let policy_is_current = policy_matches && client_policy.is_policy_current()?;
+        Ok(ClientPolicyCheck { policy_matches, policy_is_current })
+    }
+
+    fn get_client_current_policy(client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
+        let client_id = get_uuid(client_id)?;
+        Ok(ClientPolicyUuidBased::new_current(client_id)?.to_cbor_value()?.to_vec()?)
+    }
+
+    fn client_can_access_keyslot(
+        client_id: &[u8],
+        _key_slot: KeySlot,
+    ) -> Result<bool, HwCryptoError> {
+        let client_id = get_uuid(client_id)?;
+        // Simple uuid check for host uuid until we have DICE
+        Ok(client_id.to_string() != "00000000-0000-0000-0000-000000000000")
+    }
+}
diff --git a/hwcryptohal/server/platform/device_keys.rs b/hwcryptohal/server/platform/device_keys.rs
new file mode 100644
index 0000000..9e676e5
--- /dev/null
+++ b/hwcryptohal/server/platform/device_keys.rs
@@ -0,0 +1,71 @@
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
+//! Module implementing the `DeviceKeys` for trusty.
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use hwcryptohalinterfaces::{DeviceKeys, KeymintHmacKey};
+use hwkey::{Hwkey, KdfVersion, OsRollbackVersion, RollbackVersionSource};
+
+#[derive(Default)]
+pub struct TrustyDeviceKeys;
+
+impl DeviceKeys for TrustyDeviceKeys {
+    fn get_keymint_shared_hmac_key(&self) -> Result<KeymintHmacKey, HwCryptoError> {
+        // TODO: Bug 416737037 implement shared HMAC key generation
+        Err(hwcrypto_err!(UNSUPPORTED, "error communicating with HwKey service"))
+    }
+
+    fn derive_caller_unique_key(
+        &self,
+        key_context: &[u8],
+        key_sec_version: &[u8],
+        key_size: usize,
+    ) -> Result<Vec<u8>, HwCryptoError> {
+        let mut derived_key = Vec::<u8>::new();
+        derived_key.try_reserve(key_size)?;
+        derived_key.resize(key_size, 0);
+
+        let version_bytes: [u8; 4] = key_sec_version.try_into()?;
+        let version = u32::from_le_bytes(version_bytes);
+
+        let hwkey_session = Hwkey::open()?;
+        let session = hwkey_session.derive_key_req().unique_key();
+
+        session
+            .kdf(KdfVersion::Best)
+            .os_rollback_version(OsRollbackVersion::Version(version))
+            .rollback_version_source(RollbackVersionSource::CommittedVersion)
+            .derive(key_context, &mut derived_key[..])
+            .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to derive key {:?}", e))?;
+
+        Ok(derived_key)
+    }
+
+    fn get_caller_current_security_version(&self) -> Result<Vec<u8>, HwCryptoError> {
+        let hwkey_session = Hwkey::open()?;
+
+        let version =
+            match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
+                Ok(OsRollbackVersion::Version(n)) => Ok(n),
+                _ => Err(hwcrypto_err!(GENERIC_ERROR, "error communicating with HwKey service")),
+            }?;
+        Ok(version.to_le_bytes().to_vec())
+    }
+}
+
+pub(crate) fn bytes_to_version(version: &[u8]) -> Result<u32, HwCryptoError> {
+    Ok(u32::from_le_bytes(version.try_into()?))
+}
diff --git a/hwcryptohal/server/ffi_bindings.rs b/hwcryptohal/server/platform/ffi_bindings.rs
similarity index 100%
rename from hwcryptohal/server/ffi_bindings.rs
rename to hwcryptohal/server/platform/ffi_bindings.rs
diff --git a/hwcryptohal/server/platform/lib.rs b/hwcryptohal/server/platform/lib.rs
new file mode 100644
index 0000000..85bf17a
--- /dev/null
+++ b/hwcryptohal/server/platform/lib.rs
@@ -0,0 +1,32 @@
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
+//! library implementing platform specific functions.
+
+mod client_identification;
+mod device_keys;
+mod ffi_bindings;
+mod memory;
+mod rng;
+mod time;
+
+pub use client_identification::TrustyClientIdentification as ClientIdentificationImpl;
+pub use device_keys::TrustyDeviceKeys as DeviceKeysImpl;
+pub use kmr_crypto_boring::aes::BoringAes as AesImpl;
+pub use kmr_crypto_boring::hmac::BoringHmac as HmacImpl;
+pub use memory::TrustyMappedObject as MemoryMappedObjectImpl;
+pub use rng::PlatformRng as RngImpl;
+pub use time::TrustyDeviceTime as DeviceTimeImpl;
diff --git a/hwcryptohal/server/platform/manifest.json b/hwcryptohal/server/platform/manifest.json
new file mode 100644
index 0000000..d0bdc23
--- /dev/null
+++ b/hwcryptohal/server/platform/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "hwcryptohalplatform_lib",
+    "uuid": "fbbb8273-cbbb-4a48-82ad-dbc85cb7363d",
+    "min_heap": 118784,
+    "min_stack": 32768
+}
diff --git a/hwcryptohal/server/platform/memory.rs b/hwcryptohal/server/platform/memory.rs
new file mode 100644
index 0000000..573746b
--- /dev/null
+++ b/hwcryptohal/server/platform/memory.rs
@@ -0,0 +1,125 @@
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
+//! Module providing an implementation for the `MemoryMappedObject` trait.
+use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::MemoryBufferParameter::{
+    MemoryBuffer::MemoryBuffer, MemoryBufferParameter,
+};
+use binder::ParcelFileDescriptor;
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use hwcryptohalinterfaces::MemoryMappedObject;
+use std::ffi::c_void;
+use std::os::fd::AsRawFd;
+use std::ptr::NonNull;
+use vm_memory::VolatileSlice;
+
+const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
+    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
+const INPUT_MEMORY_BUFFER_FLAGS: u32 = trusty_sys::MMAP_FLAG_PROT_READ;
+
+fn mmap(
+    buffer_size: usize,
+    protection_flags: u32,
+    buffer_handle: &ParcelFileDescriptor,
+) -> Result<*mut c_void, HwCryptoError> {
+    let buffer_size = u32::try_from(buffer_size)
+        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "error converting buffer size {:?}", e))?;
+    // SAFETY: mmap is left to choose the address for the allocation. It will check that the
+    //         protection flags, size and fd are correct and return a negative value if
+    //         not.
+    let buffer_ptr = unsafe {
+        trusty_sys::mmap(
+            std::ptr::null_mut(),
+            buffer_size,
+            protection_flags,
+            buffer_handle.as_ref().as_raw_fd(),
+        )
+    };
+    if trusty_sys::Error::is_ptr_err(buffer_ptr as *const c_void) {
+        return Err(hwcrypto_err!(BAD_PARAMETER, "mapping buffer handle failed: {}", buffer_ptr));
+    }
+    Ok(buffer_ptr as *mut c_void)
+}
+
+fn get_mmap_prot_flags(memory_buffer: &MemoryBuffer) -> u32 {
+    match memory_buffer {
+        MemoryBuffer::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
+        MemoryBuffer::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
+    }
+}
+
+// Wrapper over pointer used to map memory buffer.
+pub struct MappedBuffer(NonNull<u8>);
+
+// SAFETY: `MappedBuffer` is only used to free object on drop or to create a `VolatileSlice` when
+//         we need to access the underlying memory buffer; never directly. It is safe to access and
+//         drop on a different thread. All accesses to the mmaped memory are done through the
+//         `VolatileSlice` which already has the assumption that the underlying memory is shared
+//         between different entities, so it only uses `std::ptr::{copy, read_volatile,
+//         write_volatile}` to access memory.
+unsafe impl Send for MappedBuffer {}
+
+pub struct TrustyMappedObject {
+    buffer_ptr: MappedBuffer,
+    buffer_size: usize,
+}
+
+impl MemoryMappedObject for TrustyMappedObject {
+    fn mmap(memory_buffer: &MemoryBufferParameter) -> Result<Self, HwCryptoError> {
+        if memory_buffer.sizeBytes <= 0 {
+            return Err(hwcrypto_err!(BAD_PARAMETER, "Buffer size was not greater than 0"));
+        }
+        // memory_buffer_parameters.size is positive and because it is an i32, conversion is correct
+        let buffer_size = memory_buffer.sizeBytes as usize;
+        let protection_flags = get_mmap_prot_flags(&memory_buffer.bufferHandle);
+        let buffer_handle = match &memory_buffer.bufferHandle {
+            MemoryBuffer::Input(handle) | MemoryBuffer::Output(handle) => handle,
+        };
+        let buffer_handle = buffer_handle
+            .as_ref()
+            .ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "received a null buffer handle"))?;
+        let buffer_ptr = mmap(buffer_size, protection_flags, buffer_handle)?;
+        let buffer_ptr = NonNull::new(buffer_ptr as *mut u8)
+            .ok_or(hwcrypto_err!(BAD_PARAMETER, "buffer_ptr was NULL"))?;
+
+        Ok(Self { buffer_ptr: MappedBuffer(buffer_ptr), buffer_size })
+    }
+
+    fn get_memory_slice(&mut self) -> Result<VolatileSlice<'_>, HwCryptoError> {
+        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
+        //         operation would have failed. All accesses to this memory on this service are
+        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory is
+        //         only unmapped on drop, so it will available for the lifetime of the
+        //         `VolatileSlice`.
+        let mem_buffer =
+            unsafe { VolatileSlice::new(self.buffer_ptr.0.as_ptr(), self.buffer_size) };
+        Ok(mem_buffer)
+    }
+
+    fn buffer_size(&self) -> usize {
+        self.buffer_size
+    }
+}
+
+impl Drop for TrustyMappedObject {
+    fn drop(&mut self) {
+        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
+        //         of the object. `buffer_ptr` is still mapped at this point
+        unsafe {
+            trusty_sys::munmap(self.buffer_ptr.0.as_ptr().cast::<c_void>(), self.buffer_size as u32)
+        };
+    }
+}
diff --git a/hwcryptohal/server/platform_functions.rs b/hwcryptohal/server/platform/rng.rs
similarity index 54%
rename from hwcryptohal/server/platform_functions.rs
rename to hwcryptohal/server/platform/rng.rs
index 8741b57..61db7c3 100644
--- a/hwcryptohal/server/platform_functions.rs
+++ b/hwcryptohal/server/platform/rng.rs
@@ -15,24 +15,12 @@
  */
 
 //! Module providing access to platform specific functions used by the library.
-use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
 use kmr_common::crypto;
-use log::error;
 
 use crate::ffi_bindings;
 
-const NANOSECONDS_IN_1_MS: u64 = 1000000;
-
-// Placeholder for function to compare VM identities. Identities will probably be based on DICE,
-// a simple comparison could be done if the DICE chains are unencrypted and the order of fields is
-// always the same.
-#[allow(dead_code)]
-pub(crate) fn compare_vm_identities(vm1_identity: &[u8], vm2_identity: &[u8]) -> bool {
-    (vm1_identity.len() == vm2_identity.len()) && openssl::memcmp::eq(vm1_identity, vm2_identity)
-}
-
 #[derive(Default)]
-pub(crate) struct PlatformRng;
+pub struct PlatformRng;
 
 impl crypto::Rng for PlatformRng {
     fn add_entropy(&mut self, data: &[u8]) {
@@ -52,17 +40,3 @@ pub fn trusty_rng_add_entropy(data: &[u8]) {
         panic!("trusty_rng_add_entropy() failed, {}", rc)
     }
 }
-
-pub fn current_epoch_time_ms() -> Result<u64, HwCryptoError> {
-    let mut secure_time_ns = 0;
-    // Safety: external syscall gets valid raw pointer to a `u64`.
-    let rc = unsafe { trusty_sys::gettime(0, 0, &mut secure_time_ns) };
-    if rc < 0 {
-        // Couldn't get time
-        error!("Error calling trusty_gettime: {:#x}", rc);
-        Err(hwcrypto_err!(GENERIC_ERROR, "error calling trusty_gettime: {:#x}", rc))
-    } else {
-        // secure_time_ns is positive, so casting is correct
-        Ok((secure_time_ns as u64) / NANOSECONDS_IN_1_MS)
-    }
-}
diff --git a/hwcryptohal/server/platform/rules.mk b/hwcryptohal/server/platform/rules.mk
new file mode 100644
index 0000000..09a287d
--- /dev/null
+++ b/hwcryptohal/server/platform/rules.mk
@@ -0,0 +1,50 @@
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
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := hwcryptohalplatform
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	trusty/user/app/sample/hwcryptohal/aidl/rust  \
+	trusty/user/app/sample/hwcryptohal/common  \
+	trusty/user/app/sample/hwcryptohal/server/interfaces \
+	trusty/user/base/lib/hwkey/rust \
+	trusty/user/base/lib/keymint-rust/boringssl \
+	trusty/user/base/lib/keymint-rust/common \
+	trusty/user/base/lib/openssl-rust \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+	$(call FIND_CRATE,log) \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,vm-memory) \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	trusty_rng_.* \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/hwcryptohal/server/platform/time.rs b/hwcryptohal/server/platform/time.rs
new file mode 100644
index 0000000..206b9e5
--- /dev/null
+++ b/hwcryptohal/server/platform/time.rs
@@ -0,0 +1,40 @@
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
+//! Module providing time related functions.
+use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
+use hwcryptohalinterfaces::DeviceTime;
+use log::error;
+
+const NANOSECONDS_IN_1_MS: u64 = 1000000;
+
+pub struct TrustyDeviceTime;
+
+impl DeviceTime for TrustyDeviceTime {
+    fn current_epoch_time_ms() -> Result<u64, HwCryptoError> {
+        let mut secure_time_ns = 0;
+        // Safety: external syscall gets valid raw pointer to a `u64`.
+        let rc = unsafe { trusty_sys::gettime(0, 0, &mut secure_time_ns) };
+        if rc < 0 {
+            // Couldn't get time
+            error!("Error calling trusty_gettime: {:#x}", rc);
+            Err(hwcrypto_err!(GENERIC_ERROR, "error calling trusty_gettime: {:#x}", rc))
+        } else {
+            // secure_time_ns is positive, so casting is correct
+            Ok((secure_time_ns as u64) / NANOSECONDS_IN_1_MS)
+        }
+    }
+}
diff --git a/hwcryptohal/server/rules.mk b/hwcryptohal/server/rules.mk
index 36b9096..a47c52b 100644
--- a/hwcryptohal/server/rules.mk
+++ b/hwcryptohal/server/rules.mk
@@ -28,24 +28,25 @@ MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
 	frameworks/native/libs/binder/trusty/rust/binder_rpc_server \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/authmgr/authmgr-be/lib \
 	trusty/user/app/sample/hwcryptohal/aidl/rust  \
 	trusty/user/app/sample/hwcryptohal/common  \
-	trusty/user/base/lib/hwkey/rust \
+	trusty/user/base/interface/authmgr-handover/aidl \
+	trusty/user/app/sample/hwcryptohal/server/interfaces \
+	trusty/user/app/sample/hwcryptohal/server/platform \
 	trusty/user/base/lib/keymint-rust/boringssl \
 	trusty/user/base/lib/keymint-rust/common \
 	trusty/user/base/lib/openssl-rust \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-sys \
 	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,static_assertions) \
 	trusty/user/base/lib/trusty-log \
 	trusty/user/base/lib/trusty-std \
 	$(call FIND_CRATE,vm-memory) \
 
-MODULE_BINDGEN_ALLOW_FUNCTIONS := \
-	trusty_rng_.* \
-
-MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
-
 MODULE_RUST_TESTS := true
 
+MODULE_RUST_USE_CLIPPY := true
+
 include make/library.mk
diff --git a/hwcryptohal/server/service_encryption_key.rs b/hwcryptohal/server/service_encryption_key.rs
index 62f31c9..223d654 100644
--- a/hwcryptohal/server/service_encryption_key.rs
+++ b/hwcryptohal/server/service_encryption_key.rs
@@ -20,14 +20,13 @@
 use ciborium::Value;
 use coset::{AsCborValue, CborSerializable, Header, ProtectedHeader};
 use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
-use hwkey::{Hwkey, OsRollbackVersion, RollbackVersionSource};
+use hwcryptohalinterfaces::DeviceKeys;
+use hwcryptohalplatform::{AesImpl, DeviceKeysImpl, HmacImpl, RngImpl};
 use kmr_common::{
     crypto::{self, Aes, Hkdf, Rng},
     FallibleAllocExt,
 };
 
-use crate::crypto_provider;
-
 /// Size of the base encryption key used by the service to derive other versioned context encryption
 /// keys
 const SERVICE_KEK_LENGTH: usize = 32;
@@ -53,7 +52,7 @@ pub(crate) enum EncryptionHeaderKey<'a> {
 
 #[derive(Copy, Clone, Debug, PartialEq)]
 pub(crate) enum EncryptedContent {
-    DicePolicy = 1,
+    ClientPolicy = 1,
     WrappedKeyMaterial = 2,
     KeyMaterial = 3,
 }
@@ -63,7 +62,7 @@ impl TryFrom<u64> for EncryptedContent {
 
     fn try_from(value: u64) -> Result<Self, Self::Error> {
         match value {
-            x if x == EncryptedContent::DicePolicy as u64 => Ok(EncryptedContent::DicePolicy),
+            x if x == EncryptedContent::ClientPolicy as u64 => Ok(EncryptedContent::ClientPolicy),
             x if x == EncryptedContent::WrappedKeyMaterial as u64 => {
                 Ok(EncryptedContent::WrappedKeyMaterial)
             }
@@ -84,12 +83,12 @@ impl TryFrom<ciborium::value::Integer> for EncryptedContent {
         let value: u64 = value.try_into().map_err(|_| {
             hwcrypto_err!(SERIALIZATION_ERROR, "couldn't convert CBOR integer into u64")
         })?;
-        Ok(value.try_into().map_err(|_| {
+        value.try_into().map_err(|_| {
             hwcrypto_err!(
                 SERIALIZATION_ERROR,
                 "Error converting encrypted content type from ciborium value"
             )
-        })?)
+        })
     }
 }
 
@@ -103,14 +102,14 @@ impl From<EncryptedContent> for ciborium::value::Integer {
 // similar to what KeyMint does to wrap keys.
 pub(crate) struct EncryptionHeader {
     key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
-    header_version: u32,
+    header_version: Vec<u8>,
     wrapped_content_type: EncryptedContent,
 }
 
 impl EncryptionHeader {
     fn new(
         key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
-        header_version: u32,
+        header_version: Vec<u8>,
         wrapped_content_type: EncryptedContent,
     ) -> Self {
         Self { key_derivation_context, header_version, wrapped_content_type }
@@ -122,7 +121,7 @@ impl EncryptionHeader {
     }
 
     pub(crate) fn generate_with_version(
-        header_version: u32,
+        header_version: Vec<u8>,
         wrapped_content_type: EncryptedContent,
     ) -> Self {
         let key_derivation_context = get_new_key_derivation_context();
@@ -137,7 +136,7 @@ impl EncryptionHeader {
     ) -> Result<Vec<u8>, HwCryptoError> {
         let encryption_key = match encryption_key {
             EncryptionHeaderKey::KeyGenerationContext(key_context) => {
-                get_encryption_key(self.header_version, key_context)?
+                get_encryption_key(self.header_version.as_slice(), key_context)?
             }
             EncryptionHeaderKey::ProvidedHkdfKey(key) => {
                 if key.len() != SERVICE_KEK_LENGTH {
@@ -173,14 +172,13 @@ impl EncryptionHeader {
         content: T,
     ) -> Result<Vec<u8>, HwCryptoError> {
         let kek = self.derive_service_encryption_key(key_context)?;
-        let aes = crypto_provider::AesImpl;
         let cose_encrypt = coset::CoseEncrypt0Builder::new()
             .protected(self.try_into()?)
             .try_create_ciphertext::<_, HwCryptoError>(
                 &content.to_cbor_value()?.to_vec()?,
                 &[],
                 move |pt, aad| {
-                    let mut op = aes.begin_aead(
+                    let mut op = AesImpl.begin_aead(
                         kek.into(),
                         crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
                         crypto::SymmetricOperation::Encrypt,
@@ -214,8 +212,7 @@ impl EncryptionHeader {
             ));
         }
 
-        let aes = crypto_provider::AesImpl;
-        let mut op = aes.begin_aead(
+        let mut op = AesImpl.begin_aead(
             kek.into(),
             crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
             crypto::SymmetricOperation::Decrypt,
@@ -278,7 +275,11 @@ impl TryFrom<&ProtectedHeader> for EncryptionHeader {
                         Some(parse_cborium_bytes_to_fixed_array(&element.1, "KEK context")?);
                 }
                 KEY_DERIVATION_VERSION_COSE_LABEL => {
-                    header_version = Some(parse_cborium_u32(&element.1, "header version")?);
+                    let value_bytes = element.1.as_bytes().ok_or(hwcrypto_err!(
+                        SERIALIZATION_ERROR,
+                        "wrong type when trying to parse bytes for header version"
+                    ))?;
+                    header_version = Some(value_bytes);
                 }
                 WRAPPED_CONTENT_TYPE_COSE_LABEL => {
                     wrapped_content_type = Some(
@@ -297,10 +298,12 @@ impl TryFrom<&ProtectedHeader> for EncryptionHeader {
         }
         let key_derivation_context = key_derivation_context
             .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse key context"))?;
-        let header_version = header_version
+        let header_version_ref = header_version
             .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse header version"))?;
         let wrapped_content_type = wrapped_content_type
             .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse content type"))?;
+        let mut header_version = Vec::<u8>::new();
+        header_version.try_extend_from_slice(header_version_ref.as_slice())?;
         Ok(Self::new(key_derivation_context, header_version, wrapped_content_type))
     }
 }
@@ -311,10 +314,12 @@ impl TryFrom<&EncryptionHeader> for Header {
     fn try_from(value: &EncryptionHeader) -> Result<Header, Self::Error> {
         let mut key_derivation_context = Vec::<u8>::new();
         key_derivation_context.try_extend_from_slice(&value.key_derivation_context[..])?;
+        let mut header_version = Vec::<u8>::new();
+        header_version.try_extend_from_slice(value.header_version.as_slice())?;
         let cose_header = coset::HeaderBuilder::new()
             .algorithm(coset::iana::Algorithm::A256GCM)
             .value(KEY_DERIVATION_CTX_COSE_LABEL, Value::Bytes(key_derivation_context))
-            .value(KEY_DERIVATION_VERSION_COSE_LABEL, Value::Integer(value.header_version.into()))
+            .value(KEY_DERIVATION_VERSION_COSE_LABEL, Value::Bytes(header_version))
             .value(
                 WRAPPED_CONTENT_TYPE_COSE_LABEL,
                 Value::Integer(value.wrapped_content_type.into()),
@@ -326,20 +331,8 @@ impl TryFrom<&EncryptionHeader> for Header {
 
 /// Get the base versioned encryption key used by the service to derive other versioned context
 /// encryption keys
-fn get_encryption_key(header_version: u32, key_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
-    let mut key = Vec::<u8>::new();
-    key.try_reserve(SERVICE_KEK_LENGTH)?;
-    key.resize(SERVICE_KEK_LENGTH, 0);
-    let hwkey_session = Hwkey::open()
-        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not connect to hwkey service {:?}", e))?;
-    hwkey_session
-        .derive_key_req()
-        .unique_key()
-        .rollback_version_source(RollbackVersionSource::CommittedVersion)
-        .os_rollback_version(OsRollbackVersion::Version(header_version))
-        .derive(key_context, &mut key[..])
-        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could derive key {:?}", e))?;
-    Ok(key)
+fn get_encryption_key(header_version: &[u8], key_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
+    DeviceKeysImpl.derive_caller_unique_key(key_context, header_version, SERVICE_KEK_LENGTH)
 }
 
 // Create an AES key compatible with the current crypto backend used
@@ -347,14 +340,12 @@ fn derive_key_hkdf(
     derivation_key: &[u8],
     derivation_context: &[u8],
 ) -> Result<Vec<u8>, HwCryptoError> {
-    let kdf = crypto_provider::HmacImpl;
-    Ok(kdf.hkdf(&[], &derivation_key, &derivation_context, SERVICE_KEK_LENGTH)?)
+    Ok(HmacImpl.hkdf(&[], derivation_key, derivation_context, SERVICE_KEK_LENGTH)?)
 }
 
 fn get_new_key_derivation_context() -> [u8; KEY_DERIVATION_CTX_LENGTH] {
-    let mut rng = crypto_provider::RngImpl::default();
     let mut key_ctx = [0u8; KEY_DERIVATION_CTX_LENGTH];
-    rng.fill_bytes(&mut key_ctx[..]);
+    RngImpl.fill_bytes(&mut key_ctx[..]);
     key_ctx
 }
 
@@ -379,27 +370,8 @@ pub(crate) fn parse_cborium_bytes_to_fixed_array(
     Ok(value_bytes.as_slice().try_into().expect("Shouldn't fail, we checked size already"))
 }
 
-fn parse_cborium_u32(
-    value: &ciborium::value::Value,
-    value_name: &str,
-) -> Result<u32, HwCryptoError> {
-    let integer_value = value.as_integer().ok_or(hwcrypto_err!(
-        SERIALIZATION_ERROR,
-        "wrong type when trying to parse a u32 from {}",
-        value_name
-    ))?;
-    integer_value.try_into().map_err(|e| {
-        hwcrypto_err!(SERIALIZATION_ERROR, "Error converting {} to u32: {}", value_name, e)
-    })
-}
-
-pub(crate) fn get_service_current_version() -> Result<u32, HwCryptoError> {
-    let hwkey_session = Hwkey::open()?;
-
-    match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
-        Ok(OsRollbackVersion::Version(n)) => Ok(n),
-        _ => Err(hwcrypto_err!(GENERIC_ERROR, "error communicating with HwKey service")),
-    }
+pub(crate) fn get_service_current_version() -> Result<Vec<u8>, HwCryptoError> {
+    DeviceKeysImpl.get_caller_current_security_version()
 }
 
 #[cfg(test)]
@@ -409,7 +381,7 @@ mod tests {
 
     #[test]
     fn header_encryption_decryption() {
-        let header = EncryptionHeader::generate(EncryptedContent::DicePolicy);
+        let header = EncryptionHeader::generate(EncryptedContent::ClientPolicy);
         expect!(header.is_ok(), "couldn't generate header");
         let header = header.unwrap();
         let encrypted_content = header.encrypt_content_service_encryption_key(
@@ -421,7 +393,7 @@ mod tests {
         let decrypted_data = EncryptionHeader::decrypt_content_service_encryption_key(
             &encrypted_content[..],
             EncryptionHeaderKey::KeyGenerationContext(b"fake_context"),
-            EncryptedContent::DicePolicy,
+            EncryptedContent::ClientPolicy,
         );
         expect!(decrypted_data.is_ok(), "couldn't generate header");
         let (decrypted_header, decrypted_content) = decrypted_data.unwrap();
diff --git a/hwcryptokey-test/main.rs b/hwcryptokey-test/main.rs
index 1729407..4d8d845 100644
--- a/hwcryptokey-test/main.rs
+++ b/hwcryptokey-test/main.rs
@@ -15,8 +15,6 @@
  */
 
 mod aes_vectors;
-mod versioned_keys_explicit;
-mod versioned_keys_opaque;
 
 #[cfg(test)]
 mod tests {
diff --git a/hwcryptokey-test/versioned_keys_explicit.rs b/hwcryptokey-test/versioned_keys_explicit.rs
deleted file mode 100644
index e7fa525..0000000
--- a/hwcryptokey-test/versioned_keys_explicit.rs
+++ /dev/null
@@ -1,469 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#[cfg(test)]
-mod tests {
-    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
-        IHwCryptoKey::{
-            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
-            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
-            DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
-            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
-            ClearKeyPolicy::ClearKeyPolicy,
-        },
-    };
-    use binder::{StatusCode, Strong};
-    use rpcbinder::RpcSession;
-    use test::{expect, assert_ok};
-    use trusty_std::ffi::{CString, FallibleCString};
-
-    pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
-
-    pub(crate) const VERSION_0_DICE_POLICY: [u8; 126] = [
-        0x83, 0x58, 0x36, 0xa4, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x55, 0x51,
-        0xba, 0x39, 0x55, 0xfa, 0x6f, 0x92, 0xbb, 0xf9, 0xed, 0xe1, 0xc0, 0x91, 0x3f, 0x2b, 0xbf,
-        0xb5, 0xb3, 0x93, 0x8a, 0x08, 0x5f, 0x78, 0xa8, 0x00, 0xa2, 0xce, 0x09, 0x99, 0xa9, 0x5e,
-        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x04, 0x01, 0xa0, 0x58, 0x42,
-        0xda, 0x4f, 0xef, 0x97, 0xf4, 0x19, 0x90, 0xf3, 0x06, 0x1f, 0x06, 0xfe, 0x4d, 0xcb, 0x89,
-        0xcf, 0x6a, 0xa1, 0xd1, 0xf5, 0x34, 0x68, 0x47, 0x17, 0x2d, 0xa2, 0x0e, 0xec, 0xc1, 0xcb,
-        0xac, 0xa4, 0xe1, 0x36, 0x51, 0x88, 0xdb, 0x2e, 0x1c, 0x06, 0xeb, 0xe8, 0x0c, 0xde, 0x56,
-        0xc7, 0xed, 0x17, 0x03, 0x2a, 0x9c, 0x4e, 0x52, 0x65, 0xd6, 0x4e, 0xfb, 0xea, 0xf0, 0x9d,
-        0x49, 0x70, 0x3f, 0x37, 0xf3, 0x33,
-    ];
-
-    pub(crate) const VERSION_0_CLEAR_KEY: [u8; 256] = [
-        0xbb, 0x3c, 0xca, 0xca, 0x52, 0x68, 0x05, 0xae, 0xbe, 0xd9, 0x27, 0x98, 0xc8, 0x0e, 0xf0,
-        0xbd, 0xfb, 0x03, 0x77, 0x47, 0xe1, 0x68, 0x5b, 0x54, 0xad, 0x42, 0x80, 0x06, 0x83, 0x65,
-        0xeb, 0x69, 0x25, 0x22, 0x00, 0x5f, 0x7e, 0xa7, 0x56, 0xe8, 0xce, 0x44, 0x0b, 0xd0, 0x25,
-        0xcb, 0x29, 0x50, 0xf2, 0x4e, 0xda, 0x6a, 0xa3, 0x99, 0x47, 0x35, 0x14, 0x08, 0x3b, 0x57,
-        0x86, 0xb0, 0xfe, 0x58, 0xb8, 0x23, 0xe8, 0x7c, 0xee, 0x97, 0x84, 0x09, 0x57, 0xa9, 0xc2,
-        0xbe, 0xe1, 0xa2, 0xbb, 0xfe, 0xcb, 0x5d, 0xea, 0x01, 0xee, 0x93, 0x66, 0x71, 0xef, 0x5a,
-        0x02, 0x34, 0x9e, 0xb8, 0x38, 0xc1, 0x2d, 0xeb, 0x1b, 0xbe, 0x8e, 0x69, 0x6e, 0xbf, 0x82,
-        0x72, 0x4e, 0x28, 0x89, 0xda, 0x4a, 0x0c, 0xc4, 0xee, 0x6d, 0xd7, 0x3a, 0x1f, 0xb0, 0x3d,
-        0xcc, 0xff, 0x4a, 0x3b, 0x27, 0x49, 0xf3, 0x85, 0xd8, 0x67, 0xcb, 0x4b, 0x92, 0x5f, 0xce,
-        0xbb, 0xcb, 0xe1, 0xfe, 0x8a, 0xab, 0xc3, 0x54, 0xce, 0x44, 0xff, 0x36, 0xe1, 0x46, 0xce,
-        0x86, 0x25, 0xc0, 0x35, 0xe6, 0x7d, 0xdb, 0xab, 0x2d, 0xfc, 0x7e, 0xeb, 0xb0, 0x93, 0x79,
-        0x3d, 0x1b, 0x78, 0x64, 0x0d, 0x6f, 0x35, 0x40, 0xc1, 0xd2, 0x00, 0xfc, 0x2a, 0x14, 0xc3,
-        0xc2, 0x0f, 0x10, 0x56, 0x5b, 0x5c, 0xcb, 0xbe, 0x80, 0xdf, 0x08, 0x0d, 0x26, 0x18, 0x8f,
-        0xf6, 0x94, 0xf0, 0x8d, 0xb2, 0x29, 0x2e, 0xb9, 0x2d, 0xd0, 0x67, 0x57, 0xea, 0xed, 0x2f,
-        0xb0, 0x21, 0xfa, 0x67, 0x42, 0x4a, 0x6a, 0xae, 0xdd, 0x98, 0xc5, 0x1a, 0x6e, 0xf8, 0xfa,
-        0xf6, 0x44, 0x7f, 0x2f, 0x88, 0x6f, 0xe1, 0x60, 0x70, 0xa6, 0x08, 0xdf, 0xdf, 0xc1, 0x3f,
-        0x8c, 0xed, 0x42, 0x99, 0x15, 0x3b, 0xc7, 0x97, 0x61, 0xcd, 0xf6, 0x65, 0x77, 0xc6, 0x8e,
-        0x8d,
-    ];
-
-    fn connect() -> Result<Strong<dyn IHwCryptoKey>, StatusCode> {
-        let port =
-            CString::try_new(RUST_DEVICE_KEY_SERVICE_PORT).expect("Failed to allocate port name");
-        RpcSession::new().setup_trusty_client(port.as_c_str())
-    }
-
-    fn keys_are_sufficiently_distinct(key1: Vec<u8>, key2: Vec<u8>) -> bool {
-        let differing_bytes = key1.iter().zip(key2.iter()).filter(|(&x1, &x2)| x1 != x2).count();
-
-        std::cmp::min(key1.len(), key2.len()) - differing_bytes <= 4
-    }
-
-    #[test]
-    fn generate_new_policy_and_clear_key() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key1,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key1.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        // Derive a clear key from returned current policy and derivation key
-        let mut params = DerivedKeyParameters {
-            derivationKey: derivation_key1,
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key1.len() as i32, 256, "wrong key length");
-
-        // Use dice policy to request same key
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy));
-        let DiceBoundKeyResult {
-            diceBoundKey: derivation_key2,
-            dicePolicyWasCurrent: dice_policy_current,
-        } = key_and_policy;
-
-        expect!(derivation_key2.is_some(), "should have received a key");
-        expect!(dice_policy_current, "policy should have been current");
-
-        // generate derived key 2 and compare to key 1
-        params.derivationKey = derivation_key2;
-
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key2.len() as i32, 256, "wrong key length");
-
-        // Make sure both derived keys match
-        assert_eq!(derived_key2, derived_key1, "key mismatch");
-
-        // If we request current dice policy again, we expect the same key, but different
-        // encryption of the returned policy. Note underlying policy is the same (latest),
-        // but encrypted byte array returned will be different
-
-        // Generate the current derivation key and policy again
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key3,
-            dicePolicyForKeyVersion: dice_policy3,
-        } = key_and_policy;
-
-        // We expect the dice policy to appear different due to encruption
-        assert_ne!(
-            dice_policy, dice_policy3,
-            "expected dice policies to appear different due to encryption"
-        );
-
-        // Ensure derived key from this policy matches previously generated derived key
-        params.derivationKey = derivation_key3;
-
-        let derived_key3 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key3 = match derived_key3 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key3.len() as i32, 256, "wrong key length");
-
-        // Make sure both derived keys match
-        assert_eq!(derived_key3, derived_key1, "key mismatch");
-    }
-
-    #[test]
-    fn old_dice_generates_old_clear_key_and_new_policy() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate a derived key from version 0 dice policy
-        let key_and_policy = assert_ok!(
-            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
-        );
-        let DiceBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyWasCurrent: dice_policy_current,
-        } = key_and_policy;
-
-        // We expect version 0 should not be current
-        expect!(!dice_policy_current, "policy not expected to be current");
-
-        // Derive clear key from derivation key
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key,
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key = match derived_key {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key.len() as i32, 256, "wrong key length");
-
-        // Check we got the old key and a new policy
-        assert_eq!(derived_key, VERSION_0_CLEAR_KEY.to_vec(), "Retrieved version 0 key mismatch");
-    }
-
-    #[test]
-    fn dice_updates_are_unique() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate a derived key from version 0 dice policy
-        let key_and_policy = assert_ok!(
-            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
-        );
-        let DiceBoundKeyResult {
-            diceBoundKey: _derivation_key,
-            dicePolicyWasCurrent: dice_policy_current,
-        } = key_and_policy;
-
-        // We expect version 0 should not be current
-        expect!(!dice_policy_current, "policy not expected to be current");
-
-        // Get current dice policy multiple times
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key1,
-            dicePolicyForKeyVersion: dice_policy1,
-        } = key_and_policy;
-
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key2,
-            dicePolicyForKeyVersion: dice_policy2,
-        } = key_and_policy;
-
-        // policies should appear different due to encryption and not be zero length
-        expect!(dice_policy1.len() > 0, "should have received a DICE policy");
-        expect!(dice_policy2.len() > 0, "should have received a DICE policy");
-        assert_ne!(dice_policy1, dice_policy2, "expected policies to be different");
-
-        expect!(derivation_key1.is_some(), "should have received a key");
-        expect!(derivation_key2.is_some(), "should have received a key");
-
-        // Generate derived clear keys from returned derivation keys
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key1,
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key2,
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check derived keys
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        // Check that generated keys match
-        assert_eq!(derived_key1, derived_key2, "key mismatch");
-
-        // Check that both dice policies are considered current
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy1));
-        let DiceBoundKeyResult { diceBoundKey: _, dicePolicyWasCurrent: dice_policy1_current } =
-            key_and_policy;
-
-        expect!(dice_policy1_current, "policy expected to be current");
-
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy2));
-        let DiceBoundKeyResult { diceBoundKey: _, dicePolicyWasCurrent: dice_policy2_current } =
-            key_and_policy;
-
-        expect!(dice_policy2_current, "policy expected to be current");
-    }
-
-    #[test]
-    fn explicit_keys_unique_by_context() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        // Define two different contexts and get clear derived keys for each
-        let context1 = "context1";
-        let context2 = "context2";
-
-        let params1 = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: context1.as_bytes().to_vec(),
-        };
-
-        let params2 = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: context2.as_bytes().to_vec(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params1));
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params2));
-
-        // Check key2 type and length
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key1.len() as i32, 256, "wrong key length");
-        assert_eq!(derived_key2.len() as i32, 256, "wrong key length");
-
-        // Ensure keys are different
-        assert_ne!(derived_key2, derived_key1, "returned keys are same");
-        assert!(
-            keys_are_sufficiently_distinct(derived_key2, derived_key1),
-            "derived keys share too many bytes"
-        );
-    }
-
-    #[test]
-    fn invalid_key_sizes() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        // Request a zero length key
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 0 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key = hw_device_key.deriveKey(&params);
-        expect!(derived_key.is_err(), "expected error on bad key size");
-
-        // Request a negative length key
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: -256 }),
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key = hw_device_key.deriveKey(&params);
-        expect!(derived_key.is_err(), "expected error on bad key size");
-    }
-
-    #[test]
-    fn large_context() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        // Pick a reasonable large context size
-        const PAYLOAD_LEN: usize = 512;
-
-        let mut context = vec![42; PAYLOAD_LEN];
-
-        // Get a derived key based on large context
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: context.clone(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key1.len() as i32, 256, "wrong key length");
-
-        // Make a minor change to last byte of context and request another key
-        context[PAYLOAD_LEN - 1] = 43;
-
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
-            context: context.clone(),
-        };
-
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type and length
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
-            DerivedKey::ExplicitKey(k) => k,
-        };
-
-        assert_eq!(derived_key2.len() as i32, 256, "wrong key length");
-
-        //Ensure keys are different
-        assert_ne!(derived_key1, derived_key2, "keys expected to differ");
-        assert!(
-            keys_are_sufficiently_distinct(derived_key1, derived_key2),
-            "derived keys share too many bytes"
-        );
-    }
-}
diff --git a/hwcryptokey-test/versioned_keys_opaque.rs b/hwcryptokey-test/versioned_keys_opaque.rs
deleted file mode 100644
index 0e8dc02..0000000
--- a/hwcryptokey-test/versioned_keys_opaque.rs
+++ /dev/null
@@ -1,419 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#[cfg(test)]
-mod tests {
-    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
-        types::{
-            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
-            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
-            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
-            SymmetricOperation::SymmetricOperation,
-            SymmetricOperationParameters::SymmetricOperationParameters,
-        },
-        CryptoOperation::CryptoOperation,
-        CryptoOperationSet::CryptoOperationSet,
-        IHwCryptoKey::{
-            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
-            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
-            DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
-            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
-        },
-        IHwCryptoOperations::IHwCryptoOperations,
-        IOpaqueKey::IOpaqueKey,
-        KeyPolicy::KeyPolicy,
-        OperationParameters::OperationParameters,
-    };
-    use binder::{Status, StatusCode, Strong};
-    use rpcbinder::RpcSession;
-    use test::{assert_ok, expect};
-    use trusty_std::ffi::{CString, FallibleCString};
-
-    pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
-
-    pub(crate) const VERSION_0_DICE_POLICY: [u8; 126] = [
-        0x83, 0x58, 0x36, 0xa4, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x55, 0x51,
-        0xba, 0x39, 0x55, 0xfa, 0x6f, 0x92, 0xbb, 0xf9, 0xed, 0xe1, 0xc0, 0x91, 0x3f, 0x2b, 0xbf,
-        0xb5, 0xb3, 0x93, 0x8a, 0x08, 0x5f, 0x78, 0xa8, 0x00, 0xa2, 0xce, 0x09, 0x99, 0xa9, 0x5e,
-        0x3a, 0x00, 0x01, 0x00, 0x03, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x04, 0x01, 0xa0, 0x58, 0x42,
-        0xda, 0x4f, 0xef, 0x97, 0xf4, 0x19, 0x90, 0xf3, 0x06, 0x1f, 0x06, 0xfe, 0x4d, 0xcb, 0x89,
-        0xcf, 0x6a, 0xa1, 0xd1, 0xf5, 0x34, 0x68, 0x47, 0x17, 0x2d, 0xa2, 0x0e, 0xec, 0xc1, 0xcb,
-        0xac, 0xa4, 0xe1, 0x36, 0x51, 0x88, 0xdb, 0x2e, 0x1c, 0x06, 0xeb, 0xe8, 0x0c, 0xde, 0x56,
-        0xc7, 0xed, 0x17, 0x03, 0x2a, 0x9c, 0x4e, 0x52, 0x65, 0xd6, 0x4e, 0xfb, 0xea, 0xf0, 0x9d,
-        0x49, 0x70, 0x3f, 0x37, 0xf3, 0x33,
-    ];
-
-    pub(crate) const ENCRYPTION_PAYLOAD: &str = "string to be encrypted";
-
-    pub(crate) const VERSION_0_ENCRYPTION_KNOWN_VALUE: [u8; 32] = [
-        0x68, 0xb6, 0xf7, 0xd8, 0x05, 0x91, 0x59, 0x42, 0x2c, 0xd1, 0x07, 0xd7, 0x81, 0xbf, 0xd0,
-        0x31, 0xeb, 0x39, 0x11, 0x68, 0xfc, 0xfb, 0x90, 0xd7, 0x82, 0x04, 0xeb, 0x98, 0x44, 0x4d,
-        0xcf, 0x0a,
-    ];
-
-    fn connect() -> Result<Strong<dyn IHwCryptoKey>, StatusCode> {
-        let port =
-            CString::try_new(RUST_DEVICE_KEY_SERVICE_PORT).expect("Failed to allocate port name");
-        RpcSession::new().setup_trusty_client(port.as_c_str())
-    }
-
-    fn do_cipher(
-        hw_crypto: &dyn IHwCryptoOperations,
-        key: Strong<dyn IOpaqueKey>,
-        direction: SymmetricOperation,
-        payload: Vec<u8>,
-    ) -> Result<Vec<u8>, Status> {
-        let nonce = [0u8; 16];
-        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
-            nonce: nonce.into(),
-        }));
-
-        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
-        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
-
-        let mut cmd_list = Vec::<CryptoOperation>::new();
-        let data_output = OperationData::DataBuffer(Vec::new());
-        cmd_list.push(CryptoOperation::DataOutput(data_output));
-        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
-        let input_data = OperationData::DataBuffer(payload);
-        cmd_list.push(CryptoOperation::DataInput(input_data));
-        cmd_list.push(CryptoOperation::Finish(None));
-
-        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
-        let mut crypto_sets = Vec::new();
-        crypto_sets.push(crypto_op_set);
-
-        let result = hw_crypto.processCommandList(&mut crypto_sets);
-        match result {
-            Ok(..) => {}
-            Err(e) => return Err(e),
-        }
-
-        let CryptoOperation::DataOutput(OperationData::DataBuffer(result)) =
-            crypto_sets.remove(0).operations.remove(0)
-        else {
-            panic!("not reachable, we created this object above on the test");
-        };
-
-        Ok(result)
-    }
-
-    fn encrypt(
-        hw_crypto: &dyn IHwCryptoOperations,
-        key: Strong<dyn IOpaqueKey>,
-        payload: Vec<u8>,
-    ) -> Result<Vec<u8>, Status> {
-        do_cipher(hw_crypto, key, SymmetricOperation::ENCRYPT, payload)
-    }
-
-    fn decrypt(
-        hw_crypto: &dyn IHwCryptoOperations,
-        key: Strong<dyn IOpaqueKey>,
-        payload: Vec<u8>,
-    ) -> Result<Vec<u8>, Status> {
-        do_cipher(hw_crypto, key, SymmetricOperation::DECRYPT, payload)
-    }
-
-    #[test]
-    fn generate_new_policy_and_opaque_key() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-        let hw_crypto =
-            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key1,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key1.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        // Derive an opaque key from returned current policy and derivation key
-        let policy = KeyPolicy {
-            usage: KeyUse::ENCRYPT_DECRYPT,
-            keyLifetime: KeyLifetime::HARDWARE,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
-            keyManagementKey: false,
-        };
-
-        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
-            .expect("couldn't serialize policy");
-        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
-
-        let mut params = DerivedKeyParameters {
-            derivationKey: derivation_key1,
-            keyPolicy: key_policy,
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key1 = derived_key1.expect("key is missing");
-
-        // Baseline encryption operations
-        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
-
-        let encrypted_data =
-            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
-                .expect("encryption failure");
-        let clear_data = decrypt(hw_crypto.as_ref(), derived_key1.clone(), encrypted_data.clone())
-            .expect("decryption failure");
-
-        assert_eq!(clear_payload, clear_data, "decrypted data mismatch");
-
-        // Use dice policy to request same derivation key
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy));
-        let DiceBoundKeyResult {
-            diceBoundKey: derivation_key2,
-            dicePolicyWasCurrent: dice_policy_current,
-        } = key_and_policy;
-
-        expect!(derivation_key2.is_some(), "should have received a key");
-        expect!(dice_policy_current, "policy should have been current");
-
-        // Generate derived key 2
-        params.derivationKey = derivation_key2;
-
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key2 = derived_key2.expect("key is missing");
-
-        let clear_data2 = decrypt(hw_crypto.as_ref(), derived_key2.clone(), encrypted_data.clone())
-            .expect("decryption failure");
-        assert_eq!(clear_payload, clear_data2, "decrypted data mismatch");
-
-        // If we request current dice policy again, we expect the same key, but different
-        // encryption of the returned policy. Note underlying policy is the same (latest),
-        // but encrypted byte array returned will be different
-
-        // Generate the current derivation key and policy again
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key3,
-            dicePolicyForKeyVersion: dice_policy3,
-        } = key_and_policy;
-
-        // We expect the dice policy to appear different due to encruption
-        assert_ne!(
-            dice_policy, dice_policy3,
-            "expected dice policies to appear different due to encryption"
-        );
-
-        // Ensure derived key from this policy matches previously generated derived key
-        params.derivationKey = derivation_key3;
-
-        let derived_key3 = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type
-        let derived_key3 = match derived_key3 {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key3 = derived_key3.expect("key is missing");
-
-        // Try encrypting same clear_payload and verify encrypted result is same
-        let encrypted_data3 =
-            encrypt(hw_crypto.as_ref(), derived_key3.clone(), clear_payload.clone())
-                .expect("encryption failure");
-        assert_eq!(encrypted_data3, encrypted_data, "unexpected encrypted data mismatch");
-
-        // try using key to decrypt earlier encryption result
-        let clear_data3 = decrypt(hw_crypto.as_ref(), derived_key3.clone(), encrypted_data.clone())
-            .expect("decryption failure");
-        assert_eq!(clear_data3, clear_payload, "unexpected data mismatch");
-    }
-
-    #[test]
-    fn old_dice_policy_generates_old_opaque_key_and_new_policy() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-        let hw_crypto =
-            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate a derived key from version 0 dice policy
-        let key_and_policy = assert_ok!(
-            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
-        );
-        let DiceBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyWasCurrent: dice_policy_current,
-        } = key_and_policy;
-
-        // We expect version 0 should not be current
-        expect!(!dice_policy_current, "policy not expected to be current");
-
-        // Generate a key using version 0 dice policy
-        let policy = KeyPolicy {
-            usage: KeyUse::ENCRYPT_DECRYPT,
-            keyLifetime: KeyLifetime::HARDWARE,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
-            keyManagementKey: false,
-        };
-
-        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
-            .expect("couldn't serialize policy");
-        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
-
-        let params = DerivedKeyParameters {
-            derivationKey: derivation_key,
-            keyPolicy: key_policy,
-            context: "context".as_bytes().to_vec(),
-        };
-
-        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
-
-        // Check key type
-        let derived_key = match derived_key {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key = derived_key.expect("key is missing");
-
-        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
-        let encrypted_data =
-            encrypt(hw_crypto.as_ref(), derived_key.clone(), clear_payload.clone())
-                .expect("encryption failure");
-
-        // Check we got the old key and encryption results match expected for version 0 dice policy
-        assert_eq!(
-            encrypted_data,
-            VERSION_0_ENCRYPTION_KNOWN_VALUE.to_vec(),
-            "Unexpected encryption result"
-        );
-    }
-
-    #[test]
-    fn opaque_keys_unique_by_context() {
-        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");
-        let hw_crypto =
-            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
-
-        // Get the device bound key
-        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
-
-        // Generate the current derivation key and policy
-        let key_and_policy =
-            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
-        let DiceCurrentBoundKeyResult {
-            diceBoundKey: derivation_key,
-            dicePolicyForKeyVersion: dice_policy,
-        } = key_and_policy;
-
-        expect!(derivation_key.is_some(), "should have received a key");
-        expect!(dice_policy.len() > 0, "should have received a DICE policy");
-
-        let context1 = "context1";
-        let context2 = "context2";
-
-        // Get derived key for context1
-        let policy1 = KeyPolicy {
-            usage: KeyUse::ENCRYPT_DECRYPT,
-            keyLifetime: KeyLifetime::HARDWARE,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
-            keyManagementKey: false,
-        };
-
-        let cbor_policy1 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy1)
-            .expect("couldn't serialize policy");
-        let key_policy1 = DerivedKeyPolicy::OpaqueKey(cbor_policy1);
-
-        let params1 = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: key_policy1,
-            context: context1.as_bytes().to_vec(),
-        };
-
-        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params1));
-
-        // Check key type
-        let derived_key1 = match derived_key1 {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key1 = derived_key1.expect("key is missing");
-
-        // Context1 encryption
-        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
-        let encrypted_data1 =
-            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
-                .expect("encryption failure");
-
-        // Request key for context2 and verify key is different
-        let policy2 = KeyPolicy {
-            usage: KeyUse::ENCRYPT_DECRYPT,
-            keyLifetime: KeyLifetime::HARDWARE,
-            keyPermissions: Vec::new(),
-            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
-            keyManagementKey: false,
-        };
-
-        let cbor_policy2 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy2)
-            .expect("couldn't serialize policy");
-        let key_policy2 = DerivedKeyPolicy::OpaqueKey(cbor_policy2);
-
-        let params2 = DerivedKeyParameters {
-            derivationKey: derivation_key.clone(),
-            keyPolicy: key_policy2,
-            context: context2.as_bytes().to_vec(),
-        };
-
-        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params2));
-
-        // Check key type
-        let derived_key2 = match derived_key2 {
-            DerivedKey::Opaque(k) => k,
-            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
-        };
-
-        let derived_key2 = derived_key2.expect("key is missing");
-
-        // Context2 encryption
-        let encrypted_data2 =
-            encrypt(hw_crypto.as_ref(), derived_key2.clone(), clear_payload.clone())
-                .expect("encryption failure");
-
-        // Verify encryption results are different
-        assert_ne!(encrypted_data2, encrypted_data1, "encrypted results should not match");
-    }
-}
diff --git a/rust-hello-world-trusted-hal/lib/rules.mk b/rust-hello-world-trusted-hal/lib/rules.mk
index 3036dce..77b0b55 100644
--- a/rust-hello-world-trusted-hal/lib/rules.mk
+++ b/rust-hello-world-trusted-hal/lib/rules.mk
@@ -28,9 +28,11 @@ MODULE_LIBRARY_DEPS += \
 	frameworks/native/libs/binder/trusty/rust \
 	frameworks/native/libs/binder/trusty/rust/binder_rpc_server \
 	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/authmgr/authmgr-be/lib \
 	trusty/user/app/sample/rust-hello-world-trusted-hal/aidl \
 	trusty/user/base/interface/authmgr-handover/aidl \
 	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/service_manager/client \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/trusty-sys \
 	trusty/user/base/lib/trusty-log \
diff --git a/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs b/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs
deleted file mode 100644
index ce313be..0000000
--- a/rust-hello-world-trusted-hal/lib/src/hand_over_service.rs
+++ /dev/null
@@ -1,105 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#![allow(dead_code)]
-//! Implementation of ITrustedServicesCommonsConnect.aidl
-use crate::server::HELLO_WORLD_TRUSTED_SERVICE_PORT;
-use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHandover::{
-    BnTrustedServicesHandover, ITrustedServicesHandover,
-};
-use authmgr_handover_aidl::binder;
-use binder::{ParcelFileDescriptor, SpIBinder};
-use log::error;
-use rpcbinder::RpcServer;
-use std::os::fd::AsRawFd;
-use std::sync::{Arc, Weak};
-use tipc::raw::{HandleSetWrapper, ToConnect, WorkToDo};
-use tipc::{Handle, PortCfg, Uuid};
-use trusty_std::ffi::CString;
-
-pub struct HandoverService {
-    handle_set: Weak<HandleSetWrapper<RpcServer>>,
-    trusted_service: Arc<RpcServer>,
-    // TODO b/401776482. This is temporary, until the bug is fixed.
-    uuid: Uuid,
-}
-
-impl binder::Interface for HandoverService {}
-
-impl HandoverService {
-    pub fn new_handover_session(
-        uuid: Uuid,
-        // Handleset is a weak reference to avoid potential cyclic references
-        handle_set: Weak<HandleSetWrapper<RpcServer>>,
-        trusted_service: Arc<RpcServer>,
-    ) -> Option<SpIBinder> {
-        let handover_service = HandoverService { handle_set, trusted_service, uuid };
-        Some(
-            BnTrustedServicesHandover::new_binder(
-                handover_service,
-                binder::BinderFeatures::default(),
-            )
-            .as_binder(),
-        )
-    }
-}
-
-impl ITrustedServicesHandover for HandoverService {
-    fn handoverConnection(
-        &self,
-        fd: &ParcelFileDescriptor,
-        _client_seq_num: i32,
-    ) -> binder::Result<()> {
-        let raw_fd = fd.as_raw_fd();
-        let handle = Handle::from_raw(raw_fd).map_err(|e| {
-            error!("Failed to create the handle from the raw fd: {:?}.", e);
-            binder::Status::new_exception(
-                binder::ExceptionCode::SERVICE_SPECIFIC,
-                Some(
-                    &CString::new("Could not create the handle from the raw fd.".to_string())
-                        .unwrap(),
-                ),
-            )
-        })?;
-        let dup_handle = handle.try_clone().map_err(|e| {
-            error!("Failed to clone the handle: {:?}", e);
-            binder::Status::new_exception(
-                binder::ExceptionCode::SERVICE_SPECIFIC,
-                Some(&CString::new("Failed to clone the handle.".to_string()).unwrap()),
-            )
-        })?;
-        // Prevent the destructor of the handle from calling because it will be closed by the Parcel
-        // File Descriptor which owns it.
-        core::mem::forget(handle);
-        let hello_service_port_cfg = PortCfg::new_raw(HELLO_WORLD_TRUSTED_SERVICE_PORT.into())
-            .allow_ta_connect()
-            .allow_ns_connect();
-        let to_connect = ToConnect::new(
-            dup_handle,
-            Arc::clone(&self.trusted_service),
-            hello_service_port_cfg,
-            // TODO b/401776482. We need to pass in `client_seq_num` once the bug is fixed.
-            self.uuid.clone(),
-        );
-        self.handle_set
-            .upgrade()
-            .ok_or(binder::Status::new_exception(
-                binder::ExceptionCode::SERVICE_SPECIFIC,
-                Some(&CString::new("Failed to get the handle set.".to_string()).unwrap()),
-            ))?
-            .add_work(WorkToDo::Connect(to_connect));
-        Ok(())
-    }
-}
diff --git a/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs b/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs
index 5a7ecb7..232416d 100644
--- a/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs
+++ b/rust-hello-world-trusted-hal/lib/src/hello_world_trusted_service.rs
@@ -15,27 +15,31 @@
  */
 
 //! Implementation of IHelloWorld.aidl
-
+use binder::SpIBinder;
 use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::IHelloWorld::{
     BnHelloWorld, IHelloWorld,
 };
 use hello_world_trusted_aidl::binder;
 use log::info;
+use tipc::ClientIdentifier;
 
-pub struct HelloWorldService;
+pub struct HelloWorldService {
+    client_id: ClientIdentifier,
+}
 
 impl binder::Interface for HelloWorldService {}
 
 impl HelloWorldService {
-    /// Creates a binder object
-    pub fn new_binder() -> binder::Strong<dyn IHelloWorld> {
-        BnHelloWorld::new_binder(HelloWorldService, binder::BinderFeatures::default())
+    /// Creates a per-session binder object with client id
+    pub fn new_per_session(client_id: ClientIdentifier) -> Option<SpIBinder> {
+        let hello_service = HelloWorldService { client_id };
+        Some(BnHelloWorld::new_binder(hello_service, binder::BinderFeatures::default()).as_binder())
     }
 }
 
 impl IHelloWorld for HelloWorldService {
     fn sayHello(&self, name: &str) -> binder::Result<String> {
-        info!("In IHelloWorld trusted service...");
+        info!("In IHelloWorld trusted service... Client id: {:?}", self.client_id);
         let mut hello_string = String::from("Hello ");
         hello_string.push_str(name);
         Ok(hello_string)
diff --git a/rust-hello-world-trusted-hal/lib/src/lib.rs b/rust-hello-world-trusted-hal/lib/src/lib.rs
index c1240f7..4fe20a0 100644
--- a/rust-hello-world-trusted-hal/lib/src/lib.rs
+++ b/rust-hello-world-trusted-hal/lib/src/lib.rs
@@ -16,6 +16,5 @@
 
 //! Entrypoint to the HelloWorld Trusted HAL TA library
 
-mod hand_over_service;
 mod hello_world_trusted_service;
 pub mod server;
diff --git a/rust-hello-world-trusted-hal/lib/src/server.rs b/rust-hello-world-trusted-hal/lib/src/server.rs
index 222280d..df1d149 100644
--- a/rust-hello-world-trusted-hal/lib/src/server.rs
+++ b/rust-hello-world-trusted-hal/lib/src/server.rs
@@ -15,35 +15,58 @@
  */
 
 //! Setting up the server for the Hello World Trusted HAL service.
-use crate::hand_over_service::HandoverService;
 use crate::hello_world_trusted_service::HelloWorldService;
+use authmgr_be_lib::{default_handover_port_config, HandoverService};
+use log::error;
 use rpcbinder::RpcServer;
-use std::ffi::CStr;
+use service_manager::service_name_to_trusty_c_port;
 use std::sync::Arc;
 use tipc::raw::{EventLoop, HandleSetWrapper};
 use tipc::{PortCfg, TipcError};
 
 // Port for the handover service for the HelloWorld trusted service
-pub const HANDOVER_SERVICE_PORT: &CStr = c"com.android.trusty.rust.handover.hello.service.V1";
+pub const HANDOVER_SERVICE_PORT: &str = "IHandover/android.hardware.security.IHelloWorld/default";
 
 // Port for the HelloWorld trusted service
-pub const HELLO_WORLD_TRUSTED_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hello.service.V1";
+// Note: The TAs that host trusted services do not usually register a port handle for a trusted
+// service in their event loop. They register a port handle only for the corresponding hand over
+// service. We define the port name for the trusted service here because it is needed as an input
+// for `on_connect` method that is invoked in the call path of connection handover.
+pub const HELLO_WORLD_TRUSTED_SERVICE_PORT: &str = "android.hardware.security.IHelloWorld/default";
+
+fn hello_service_port_cfg() -> Result<PortCfg, TipcError> {
+    let hello_service_port_cfg = PortCfg::new_raw(
+        service_name_to_trusty_c_port(HELLO_WORLD_TRUSTED_SERVICE_PORT).map_err(|e| {
+            error!("Failed to construct the hello service port name: {:?}", e);
+            TipcError::UnknownError
+        })?,
+    )
+    .allow_ta_connect()
+    .allow_ns_connect();
+    Ok(hello_service_port_cfg)
+}
 
 pub fn main_loop() -> Result<(), TipcError> {
     let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);
     let handle_set_wrapper_clone = Arc::clone(&handle_set_wrapper);
-    let helloworld_binder = HelloWorldService::new_binder();
-    let helloworld_rpc_service = Arc::new(RpcServer::new(helloworld_binder.as_binder()));
+
+    let cb_per_session_with_client_id =
+        move |client_id| HelloWorldService::new_per_session(client_id);
+    let helloworld_rpc_service =
+        Arc::new(RpcServer::new_per_session(cb_per_session_with_client_id));
 
     // Only the AuthMgr BE TA is allowed to connect
-    let handover_service_port_cfg =
-        PortCfg::new_raw(HANDOVER_SERVICE_PORT.into()).allow_ta_connect();
+    let handover_service_port_cfg = default_handover_port_config(HANDOVER_SERVICE_PORT)?;
 
     let cb_per_session = move |uuid| {
-        HandoverService::new_handover_session(
-            uuid,
-            Arc::downgrade(&handle_set_wrapper),
-            Arc::clone(&helloworld_rpc_service),
+        Some(
+            HandoverService::new_handover_session(
+                uuid,
+                Arc::downgrade(&handle_set_wrapper),
+                Arc::clone(&helloworld_rpc_service),
+                hello_service_port_cfg().ok()?,
+            )
+            .as_binder(),
         )
     };
 
diff --git a/vintf/aidl/rust/rules.mk b/vintf/aidl/rust/rules.mk
new file mode 100644
index 0000000..d10c287
--- /dev/null
+++ b/vintf/aidl/rust/rules.mk
@@ -0,0 +1,31 @@
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
+MODULE := $(LOCAL_DIR)
+
+VINTF_TA_AIDL_DIR := test/vts-testcase/hal/treble/vintf/aidl
+
+MODULE_CRATE_NAME := vintf_service_info_aidl
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_AIDL_PACKAGE := android/vintf
+
+MODULE_AIDLS := \
+	$(VINTF_TA_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ServiceInfo.aidl \
+	$(VINTF_TA_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IServiceInfoFetcher.aidl \
+
+include make/aidl.mk
diff --git a/vintf/app/manifest.json b/vintf/app/manifest.json
new file mode 100644
index 0000000..ef1b5b8
--- /dev/null
+++ b/vintf/app/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "vintf_trusted_app",
+    "uuid": "d2d10228-107c-4f7b-9c52-86dce8007049",
+    "min_heap": 118784,
+    "min_stack": 65536
+}
diff --git a/vintf/app/rules.mk b/vintf/app/rules.mk
new file mode 100644
index 0000000..79976a4
--- /dev/null
+++ b/vintf/app/rules.mk
@@ -0,0 +1,31 @@
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
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/main.rs \
+
+MODULE_CRATE_NAME := vintf_trusted_app
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	trusty/user/app/sample/vintf/lib  \
+	trusty/user/base/lib/trusty-log \
+
+include make/trusted_app.mk
diff --git a/vintf/app/src/main.rs b/vintf/app/src/main.rs
new file mode 100644
index 0000000..fa0d1cd
--- /dev/null
+++ b/vintf/app/src/main.rs
@@ -0,0 +1,25 @@
+// Copyright 2025, The Android Open Source Project
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
+
+//! Trusty VINTF TA
+
+use log::info;
+use vintf_ta_server::server::main_loop;
+
+fn main() {
+    let config = trusty_log::TrustyLoggerConfig::default();
+    trusty_log::init_with_config(config);
+    info!("starting Vintf TA...");
+    main_loop().expect("Vintf TA quits unexpectedly.");
+}
diff --git a/vintf/lib/rules.mk b/vintf/lib/rules.mk
new file mode 100644
index 0000000..5f6d928
--- /dev/null
+++ b/vintf/lib/rules.mk
@@ -0,0 +1,31 @@
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
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_CRATE_NAME := vintf_ta_server
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/sample/vintf/aidl/rust  \
+	trusty/user/base/lib/service_manager/client \
+	trusty/user/base/lib/tipc/rust \
+
+include make/library.mk
diff --git a/vintf/lib/src/lib.rs b/vintf/lib/src/lib.rs
new file mode 100644
index 0000000..78f9e09
--- /dev/null
+++ b/vintf/lib/src/lib.rs
@@ -0,0 +1,18 @@
+// Copyright 2025, The Android Open Source Project
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
+
+//! Entrypoint to the VINTF TA library
+
+pub mod server;
+mod service_info_fetcher;
diff --git a/vintf/lib/src/server.rs b/vintf/lib/src/server.rs
new file mode 100644
index 0000000..a87ab06
--- /dev/null
+++ b/vintf/lib/src/server.rs
@@ -0,0 +1,52 @@
+// Copyright 2025, The Android Open Source Project
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
+
+//! Trusty VINTF TA
+
+use crate::service_info_fetcher::ServiceInfoFetcher;
+
+use alloc::rc::Rc;
+use log::info;
+use rpcbinder::RpcServer;
+use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};
+
+const SERVICE_INFO_FETCHER_PORT_NAME: &str = "com.android.trusty.vintf";
+
+wrap_service!(DirectTestService(RpcServer: UnbufferedService));
+
+service_dispatcher! {
+    enum VintfServices {
+        DirectTestService,
+    }
+}
+
+pub fn main_loop() -> Result<(), TipcError> {
+    info!("Hello from Vintf TA!");
+    let service = ServiceInfoFetcher::new_binder();
+    let direct_rpc_server = RpcServer::new_per_session(move |_uuid| Some(service.as_binder()));
+    let direct = DirectTestService(direct_rpc_server);
+
+    let cfg = PortCfg::new(SERVICE_INFO_FETCHER_PORT_NAME)
+        .expect("failed to create port config")
+        .allow_ta_connect()
+        .allow_ns_connect();
+
+    let mut dispatcher = VintfServices::<1>::new().expect("dispatcher creation failed");
+    dispatcher
+        .add_service(Rc::new(direct), cfg)
+        .expect("failed to add direct ServiceInfoFetcher to dispatcher");
+    Manager::<_, _, 1, 1>::new_with_dispatcher(dispatcher, [])
+        .expect("Manager could not be created")
+        .run_event_loop()
+}
diff --git a/vintf/lib/src/service_info_fetcher.rs b/vintf/lib/src/service_info_fetcher.rs
new file mode 100644
index 0000000..9cd02a2
--- /dev/null
+++ b/vintf/lib/src/service_info_fetcher.rs
@@ -0,0 +1,105 @@
+// Copyright 2025, The Android Open Source Project
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
+
+//! Implementation of IServiceInfoFetcher.aidl
+
+use log::{error, trace};
+use service_manager::get_supported_vintf_services;
+use vintf_service_info_aidl::aidl::android::vintf::{
+    IServiceInfoFetcher::{BnServiceInfoFetcher, IServiceInfoFetcher},
+    ServiceInfo::ServiceInfo,
+};
+use vintf_service_info_aidl::binder::{
+    self,
+    binder_impl::{Deserialize, IBinderInternal, TransactionCode, LAST_CALL_TRANSACTION},
+    SpIBinder,
+};
+
+const INTERFACE_HASH_TRANSACTION: TransactionCode = LAST_CALL_TRANSACTION - 1;
+const INTERFACE_VERSION_TRANSACTION: TransactionCode = LAST_CALL_TRANSACTION;
+
+pub struct ServiceInfoFetcher;
+
+impl binder::Interface for ServiceInfoFetcher {}
+
+impl ServiceInfoFetcher {
+    /// Creates a binder object
+    pub fn new_binder() -> binder::Strong<dyn IServiceInfoFetcher> {
+        BnServiceInfoFetcher::new_binder(ServiceInfoFetcher, binder::BinderFeatures::default())
+    }
+}
+
+impl IServiceInfoFetcher for ServiceInfoFetcher {
+    fn listAllServices(&self) -> binder::Result<Vec<String>> {
+        trace!("In IServiceInfoFetcher list service...");
+        let services = get_supported_vintf_services();
+        Ok(services.into_iter().map(|s| s.name().to_string()).collect())
+    }
+
+    fn getServiceInfo(&self, service_name: &str) -> binder::Result<ServiceInfo> {
+        trace!("In IServiceInfoFetcher get service info... {} ", service_name);
+        let service = get_supported_vintf_services()
+            .into_iter()
+            .find(|s| s.name() == service_name)
+            .ok_or_else(|| {
+                binder::Status::new_service_specific_error_str(
+                    -1,
+                    Some("failed to get vintf service"),
+                )
+            })?;
+        let mut service_binder = service.get_binder()?;
+        let interface = service_binder.get_class().ok_or_else(|| {
+            binder::Status::new_service_specific_error_str(-1, Some("failed to get interface"))
+        })?;
+        let descriptor = interface.get_descriptor();
+        let name: Vec<&str> = service_name.split('/').collect();
+        if name.len() != 2 {
+            return Err(binder::Status::new_service_specific_error_str(
+                -1,
+                Some("invalid service name"),
+            ));
+        }
+        if name[0] != descriptor {
+            return Err(binder::Status::new_service_specific_error_str(
+                -1,
+                Some("service name does not match descriptor"),
+            ));
+        }
+        let hash = transact(&service_binder, INTERFACE_HASH_TRANSACTION)?;
+        let version = transact(&service_binder, INTERFACE_VERSION_TRANSACTION)?;
+        let service_info = ServiceInfo {
+            r#type: descriptor,
+            instance: name[1].to_string(),
+            version,
+            requireVintfDeclaration: true,
+            hash,
+            exe: "".to_string(),
+            extensions: vec![],
+        };
+        Ok(service_info)
+    }
+}
+
+fn transact<D: Deserialize>(b: &SpIBinder, transaction_code: TransactionCode) -> binder::Result<D> {
+    let data = b.prepare_transact()?;
+    let parcel = b.submit_transact(transaction_code, data, 0)?;
+    let status: binder::Status =
+        parcel.read().inspect_err(|e| error!("failed to read binder status: {e:?}"))?;
+    if status.is_ok() {
+        Ok(parcel.read().inspect_err(|e| error!("failed to read parcel: {e:?}"))?)
+    } else {
+        error!("failed to get parcel: {status:?}");
+        Err(status)
+    }
+}
```

