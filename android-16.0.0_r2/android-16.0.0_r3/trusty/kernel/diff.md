```diff
diff --git a/lib/arm_ffa/arm_ffa.c b/lib/arm_ffa/arm_ffa.c
index 704ea79..b8888fc 100644
--- a/lib/arm_ffa/arm_ffa.c
+++ b/lib/arm_ffa/arm_ffa.c
@@ -577,7 +577,18 @@ struct smc_ret18 arm_ffa_call_error(enum ffa_error err) {
 }
 
 struct smc_ret18 arm_ffa_call_msg_wait(void) {
-    return smc8_ret18(SMC_FC_FFA_MSG_WAIT, 0, 0, 0, 0, 0, 0, 0);
+    ffa_msg_wait_flag32_t flags = 0;
+
+    if (ffa_version >= FFA_VERSION(1, 2)) {
+        /*
+         * For now, we always want to retain the RX buffer
+         * because we should have explicit release calls
+         * on all code paths
+         */
+        flags |= FFA_MSG_WAIT_FLAG_RETAIN_RX;
+    }
+
+    return smc8_ret18(SMC_FC_FFA_MSG_WAIT, 0, flags, 0, 0, 0, 0, 0);
 }
 
 struct smc_ret18 arm_ffa_msg_send_direct_resp(
@@ -641,7 +652,7 @@ struct smc_ret18 arm_ffa_msg_send_direct_resp2(
 status_t arm_ffa_msg_send_direct_req2(
         uuid_t uuid,
         uint16_t receiver_id,
-        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+        const uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
         struct smc_ret18* resp) {
     struct smc_ret18 smc_ret;
     uint64_t uuid_lo_hi[2];
@@ -1501,6 +1512,150 @@ err_alloc_tx:
     return res;
 }
 
+#if TRUSTY_VM_GUEST
+/*
+ * If num_desc is zero, return number of descriptors in count_out.
+ * If num_desc is non-zero, retrieve descriptors in ffa_rx and return the number
+ * of descriptors in count_out.
+ *
+ * If FF-A version is 1.0, the function must be called with
+ * ffa_rxtx_buffer_lock held. For later FF-A versions, the ffa_rxtx_buffer_lock
+ * must be held when num_desc is non-zero.
+ *
+ * If the function returns NO_ERROR, the caller must release the ffa_rx buffer
+ * unless num_desc was non-zero and FF-A version is later than 1.0.
+ * If an error is returned, the caller must release the ffa_rxtx_buffer_lock if
+ * it was acquired prior to the call.
+ */
+static status_t arm_ffa_call_partition_info_get(uuid_t uuid_obj,
+                                                size_t num_desc,
+                                                uint32_t flags,
+                                                size_t* count_out) {
+    int32_t error;
+    struct smc_ret18 smc_ret;
+    uint64_t uuid[2];
+
+    DEBUG_ASSERT(count_out);
+    /* FF-A adds a flag to request count only so the rx buffer isn't acquired */
+    DEBUG_ASSERT((flags & FFA_PARTITION_INFO_GET_FLAG_RETURN_COUNT_ONLY) ||
+                 is_mutex_held(&ffa_rxtx_buffer_lock));
+
+    uuid_to_le64_pair(uuid_obj, uuid);
+
+    smc_ret = smc18(SMC_FC_FFA_PARTITION_INFO_GET, uuid[0] & 0xFFFFFFFFU,
+                    uuid[0] >> 32, uuid[1] & 0xFFFFFFFFU, uuid[1] >> 32, flags,
+                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_SUCCESS:
+        /* FF-A 1.0 does not include descriptor size in the response */
+        if (num_desc > 0 && ffa_version > FFA_VERSION(1, 0)) {
+            /* If Bit[0] in flags is 0, r3 holds the size of each descriptor */
+            if ((uint32_t)smc_ret.r3 != sizeof(struct ffa_part_info_desc)) {
+                panic("Expected descriptor size (%zu) != size in response (%u)\n",
+                      sizeof(struct ffa_part_info_desc), (uint32_t)smc_ret.r3);
+            }
+        }
+        *count_out = (uint32_t)smc_ret.r2;
+        return NO_ERROR;
+    case SMC_FC_FFA_ERROR:
+        error = (int32_t)smc_ret.r2;
+        switch (error) {
+        case FFA_ERROR_BUSY:
+            return ERR_BUSY;
+        case FFA_ERROR_INVALID_PARAMETERS:
+            return ERR_INVALID_ARGS;
+        case FFA_ERROR_NO_MEMORY:
+            return ERR_NO_MEMORY;
+        case FFA_ERROR_DENIED:
+            return ERR_BAD_STATE;
+        case FFA_ERROR_NOT_SUPPORTED:
+            return ERR_NOT_SUPPORTED;
+        case FFA_ERROR_NOT_READY:
+            return ERR_NOT_READY;
+        default:
+            TRACEF("Unexpected FFA_ERROR: %x\n", error);
+            return ERR_NOT_VALID;
+        }
+    default:
+        return ERR_NOT_VALID;
+    }
+}
+
+status_t arm_ffa_partition_info_get_count(uuid_t uuid_obj, size_t* count_out) {
+    status_t res;
+    size_t num_desc = 0;
+    uint32_t flags = 0;
+    if (ffa_version == FFA_VERSION(1, 0)) {
+        /* FF-A version 1.0 acquires the rx buffer */
+        mutex_acquire(&ffa_rxtx_buffer_lock);
+    } else {
+        /* FF-A version 1.1 and later does not need rx buffer to get count */
+        flags |= FFA_PARTITION_INFO_GET_FLAG_RETURN_COUNT_ONLY;
+    }
+
+    res = arm_ffa_call_partition_info_get(uuid_obj, num_desc, flags, count_out);
+    if (res != NO_ERROR) {
+        TRACEF("Call to PARTITION_INFO_GET failed, err = %d\n", res);
+    }
+
+
+    if (ffa_version == FFA_VERSION(1, 0)) {
+        if (res != NO_ERROR) {
+            mutex_release(&ffa_rxtx_buffer_lock);
+            return res;
+        }
+        /* This also releases the rxtx buffer lock */
+        arm_ffa_rx_release();
+    }
+
+    return res;
+}
+
+status_t arm_ffa_partition_info_get_desc(uuid_t uuid_obj,
+                                         size_t num_desc,
+                                         struct ffa_part_info_desc* desc,
+                                         size_t* count_out) {
+    status_t res = NO_ERROR;
+    size_t count;
+    uint32_t flags = 0;
+
+    if (num_desc * sizeof(struct ffa_part_info_desc) > ffa_buf_size) {
+        return ERR_TOO_BIG;
+    }
+
+    if (!count_out || !desc) {
+        return ERR_INVALID_ARGS;
+    }
+
+    mutex_acquire(&ffa_rxtx_buffer_lock);
+
+    /* Clear the entire rx buffer */
+    memset(ffa_rx, 0, ffa_buf_size);
+
+    res = arm_ffa_call_partition_info_get(uuid_obj, num_desc, flags, &count);
+    /* On failure, only release rxtx lock; release buffer and lock otherwise */
+    if (res != NO_ERROR) {
+        TRACEF("Call to PARTITION_INFO_GET failed, err = %d\n", res);
+        mutex_release(&ffa_rxtx_buffer_lock);
+        return res;
+    }
+
+    /* Do we have enough space to store all descriptors returned by FFA? */
+    if (count > num_desc) {
+        res = ERR_NOT_ENOUGH_BUFFER;
+        goto err_not_enough_buffer;
+    }
+
+    *count_out = count; /* count is <= num_desc */
+    memcpy(desc, ffa_rx, count * sizeof(struct ffa_part_info_desc));
+
+err_not_enough_buffer:
+    /* This also releases the rxtx buffer lock */
+    arm_ffa_rx_release();
+    return res;
+}
+#endif
+
 static void arm_ffa_init(uint level) {
     status_t res;
 
diff --git a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
index e647b1b..afc9c5e 100644
--- a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
+++ b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
@@ -226,7 +226,7 @@ struct smc_ret18 arm_ffa_msg_send_direct_resp(
 status_t arm_ffa_msg_send_direct_req2(
         uuid_t uuid,
         uint16_t receiver_id,
-        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+        const uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
         struct smc_ret18* resp);
 
 /**
@@ -285,4 +285,45 @@ status_t arm_ffa_handle_direct_req2(struct smc_ret18* regs);
 status_t arm_ffa_register_direct_req2_handler(
         uuid_t uuid,
         arm_ffa_direct_req2_handler_t handler);
+
+/**
+ * arm_ffa_partition_info_get_count() - Get number of partitions for UUID.
+ *
+ * It is necessary to know how many partitions to allocate buffer for before
+ * calling arm_ffa_partition_info_get_desc(). This function helps with that.
+ *
+ * @uuid_obj: The UUID specifying the partition.
+ * @count: [out] A pointer to return the number of partition info descriptors.
+ *         Must not be %NULL.
+ *
+ * Return: 0 on success, a negative LK error code on failure.
+ */
+status_t arm_ffa_partition_info_get_count(uuid_t uuid_obj, size_t* count_out);
+
+/**
+ * arm_ffa_partition_info_get_desc() - Get partition descriptors for UUID.
+ *
+ * @uuid_obj: The UUID specifying the partition.
+ * @num_desc: The maximal number of descriptors that @desc can hold.
+ * @desc: [out] A pointer to a buffer large enough to hold *@num_desc
+ *        partition info descriptors. Must not be %NULL.
+ * @count_out: [out] A pointer to return the number of partition info
+ *             descriptors copied into @desc. Must not be %NULL. Upon
+ *             success, *@count_out will be between zero and @num_desc.
+ *
+ * Callers should first call arm_ffa_partition_info_get_count() to obtain the
+ * number of descriptors to allocate space for in @desc. The descriptor capacity
+ * should then be passed in @num_desc.
+ *
+ * Return:
+ * * %0                       - on success, a negative LK error code on failure.
+ * * %ERR_NOT_ENOUGH_BUFFER   - if @num_desc is too small to store the response
+ * * %ERR_INVALID_ARGS        - if @desc or @count_out are %NULL
+ * * a negative LK error code - on any other failure.
+ */
+status_t arm_ffa_partition_info_get_desc(uuid_t uuid_obj,
+                                         size_t num_desc,
+                                         struct ffa_part_info_desc* desc,
+                                         size_t* count_out);
+
 #endif
diff --git a/lib/arm_ffa/rust/bindings.h b/lib/arm_ffa/rust/bindings.h
new file mode 100644
index 0000000..328cfe4
--- /dev/null
+++ b/lib/arm_ffa/rust/bindings.h
@@ -0,0 +1,26 @@
+/*
+ * Copyright (c) 2025 Google Inc. All rights reserved
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#pragma once
+
+#include <lib/arm_ffa/arm_ffa.h>
diff --git a/lib/arm_ffa/rust/lib.rs b/lib/arm_ffa/rust/lib.rs
new file mode 100644
index 0000000..75deb82
--- /dev/null
+++ b/lib/arm_ffa/rust/lib.rs
@@ -0,0 +1,164 @@
+/*
+ * Copyright (c) 2025 Google Inc. All rights reserved
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#![no_std]
+
+use crate::sys::arm_ffa_mem_reclaim;
+use crate::sys::arm_ffa_mem_share_kernel_buffer;
+use crate::sys::arm_ffa_msg_send_direct_req2;
+use crate::sys::arm_ffa_register_direct_req2_handler;
+use crate::sys::smc_ret18;
+
+use log::error;
+use rust_support::paddr_t;
+use rust_support::status_t;
+use rust_support::uuid::Uuid;
+use rust_support::Error as LkError;
+use zerocopy::FromZeros;
+
+pub use crate::sys::arm_ffa_partition_info_get_count;
+pub use crate::sys::arm_ffa_partition_info_get_desc;
+pub use crate::sys::ffa_part_info_desc as FFAPartInfoDesc;
+
+// bindgen'ed as u32; exposing this as a usize avoids casts in many places
+pub const ARM_FFA_MSG_EXTENDED_ARGS_COUNT: usize =
+    crate::sys::ARM_FFA_MSG_EXTENDED_ARGS_COUNT as usize;
+
+pub use crate::sys::FFA_PAGE_SIZE;
+
+mod sys {
+    #![allow(unused)]
+    #![allow(non_camel_case_types)]
+    use rust_support::uuid_t;
+    include!(env!("BINDGEN_INC_FILE"));
+}
+
+pub type EndpointID = u16;
+
+/// An FFA memory handle that has been shared with an endpoint.
+///
+/// The caller must call `mem_reclaim` on memory handles to avoid leaking memory to other FFA
+/// endpoints.
+#[derive(Debug)]
+pub struct MemoryHandle(u64);
+
+impl MemoryHandle {
+    /// Get the value of the FFA memory handle.
+    pub fn get(&self) -> u64 {
+        // This can be safe because mem_reclaim accepts `Self` instead of `u64` and freeing through
+        // C's arm_ffa_mem_reclaim will require unsafe anyway.
+        self.0
+    }
+}
+
+pub struct DirectResp2 {
+    pub sender_id: EndpointID,
+    pub params: [u64; ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+}
+
+/// Register a callback for a given FFA endpoint service.
+///
+/// The handler is called every time an FFA_MSG_SEND_DIRECT_REQ2 with the given UUID is received.
+/// The handler takes the sender VM ID and the DIRECT_REQ2 params as arguments. The pointee is then
+/// returned to the FFA endpoint as the response parameters in FFA_MSG_SEND_DIRECT_RESP2.
+///
+/// # Safety
+///
+/// The callback passed to this function is allowed to treat its params pointer argument as a
+/// mutable reference to a 14-element u64 array, but must not have any other safety requirements.
+pub unsafe fn register_direct_req2_handler(
+    endpoint_service: Uuid,
+    handler: unsafe extern "C" fn(u16, *mut u64) -> status_t,
+) -> Result<(), LkError> {
+    // SAFETY: This schedules calling the unsafe handler function at a later point. Registering
+    // the handler itself is thread-safe since arm_ffa_register_direct_req2_handler grabs a spinlock
+    // before modifying any internal static variables. The safety requirements of calling the
+    // callback are delegated to the safety requirements of this function.
+    let rc = unsafe { arm_ffa_register_direct_req2_handler(endpoint_service.0, Some(handler)) };
+    LkError::from_lk(rc)?;
+    Ok(())
+}
+
+/// Send an FFA_MSG_SEND_DIRECT_REQ2 request with a given UUID to an FFA endpoint with a given ID.
+pub fn msg_send_direct_req2(
+    endpoint_uuid: Uuid,
+    endpoint_id: EndpointID,
+    msg: &[u64; ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+) -> Result<DirectResp2, LkError> {
+    let mut resp = smc_ret18::new_zeroed();
+    let msg_ptr = msg.as_ptr();
+    // SAFETY: Resp points to a mutable smc_ret18. This function blocks and resp is
+    // on the stack so it remains valid for the duration of the function call.
+    let rc = unsafe {
+        arm_ffa_msg_send_direct_req2(endpoint_uuid.0, endpoint_id, msg_ptr, &raw mut resp)
+    };
+    LkError::from_lk(rc)?;
+    // FFA_MSG_SEND_DIRECT_RESP2 puts the endpoint ID for the source (of the response) in the top 16
+    // bits of r1. It should match the endpoint_id of the request.
+    let sender_id = (resp.r1 >> 16) as u16;
+    if endpoint_id != sender_id {
+        error!(
+            "endpoint IDs mismatch between request ({:?}) and response ({:?})",
+            endpoint_id, sender_id
+        );
+        return Err(LkError::ERR_NOT_VALID);
+    }
+
+    // SAFETY: It's valid to access the union in resp as req2_params to create a copy since it was
+    // just populated by the call to arm_ffa_msg_send_direct_req2.
+    Ok(DirectResp2 { sender_id, params: unsafe { resp.__bindgen_anon_1.req2_params } })
+}
+
+/// Share memory with an FFA endpoint specified by receiver id and returns an FFA memory handle.
+///
+/// # Safety
+///
+/// The callee must ensure the buffer described by paddr and num_ffa_pages may be shared with other
+/// FFA endpoints. Any accesses to that memory after it is shared must be synchronized using some
+/// well-defined protocol. The caller must also ensure that flags matches the arch_mmu_flags passed
+/// to vmm_alloc_obj when the shared memory was allocated.
+pub unsafe fn mem_share_kernel_buffer(
+    receiver_id: u16,
+    paddr: paddr_t,
+    num_ffa_pages: usize,
+    flags: u32,
+) -> Result<MemoryHandle, LkError> {
+    let mut handle = 0;
+    // SAFETY: Safety delegated to the caller. See function documentation for details.
+    let rc = unsafe {
+        arm_ffa_mem_share_kernel_buffer(receiver_id, paddr, num_ffa_pages, flags, &raw mut handle)
+    };
+    LkError::from_lk(rc)?;
+    Ok(MemoryHandle(handle))
+}
+
+/// Reclaim memory shared with another FFA endpoint using the FFA memory handle.
+///
+/// The other FFA endpoints must have relinquished the memory for this to succeed. If this fails it
+/// returns the memory handle to allow retrying the reclaim.
+pub fn mem_reclaim(handle: MemoryHandle) -> Result<(), (MemoryHandle, LkError)> {
+    // SAFETY: Safety delegated to the caller. See function documentation for details.
+    let rc = unsafe { arm_ffa_mem_reclaim(handle.get()) };
+    LkError::from_lk(rc).map_err(|e| (handle, e))?;
+    Ok(())
+}
diff --git a/lib/arm_ffa/rust/rules.mk b/lib/arm_ffa/rust/rules.mk
new file mode 100644
index 0000000..2b5c298
--- /dev/null
+++ b/lib/arm_ffa/rust/rules.mk
@@ -0,0 +1,76 @@
+# Copyright (c) 2025, Google Inc. All rights reserved
+#
+# Permission is hereby granted, free of charge, to any person obtaining
+# a copy of this software and associated documentation files
+# (the "Software"), to deal in the Software without restriction,
+# including without limitation the rights to use, copy, modify, merge,
+# publish, distribute, sublicense, and/or sell copies of the Software,
+# and to permit persons to whom the Software is furnished to do so,
+# subject to the following conditions:
+#
+# The above copyright notice and this permission notice shall be
+# included in all copies or substantial portions of the Software.
+#
+# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := arm_ffa
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_ADD_IMPLICIT_DEPS := false
+
+MODULE_DEPS := \
+	$(LKROOT)/lib/rust_support \
+	trusty/kernel/lib/arm_ffa \
+	trusty/kernel/lib/smc \
+	trusty/user/base/lib/liballoc-rust \
+	trusty/user/base/lib/libcompiler_builtins-rust \
+	trusty/user/base/lib/libcore-rust \
+	$(call FIND_CRATE,lazy_static) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy) \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	arm_ffa_mem_reclaim \
+	arm_ffa_mem_share_kernel_buffer \
+	arm_ffa_msg_send_direct_req2 \
+	arm_ffa_partition_info_get_count \
+	arm_ffa_partition_info_get_desc \
+	arm_ffa_register_direct_req2_handler \
+
+MODULE_BINDGEN_ALLOW_TYPES := \
+	ffa_part_info_desc \
+
+MODULE_BINDGEN_ALLOW_VARS := \
+	ARM_FFA_MSG_EXTENDED_ARGS_COUNT \
+	FFA_PAGE_SIZE \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+ZEROCOPY_DERIVES := \
+	zerocopy::FromBytes,zerocopy::Immutable,zerocopy::KnownLayout \
+
+MODULE_BINDGEN_FLAGS += \
+	--with-derive-custom="ffa_part_info_desc=$(ZEROCOPY_DERIVES)" \
+	--with-derive-custom="ffa_part_info_desc__bindgen_ty_1=$(ZEROCOPY_DERIVES)" \
+	--with-derive-custom="smc_ret18=$(ZEROCOPY_DERIVES)" \
+	--with-derive-custom="smc_ret18__bindgen_ty_1=$(ZEROCOPY_DERIVES)" \
+	--with-derive-custom="smc_ret18__bindgen_ty_1__bindgen_ty_1=$(ZEROCOPY_DERIVES)" \
+
+MODULE_BINDGEN_BLOCK_TYPES := \
+	uuid_t \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/module.mk
diff --git a/lib/arm_trng/arm_trng.h b/lib/arm_trng/arm_trng.h
index f80eeb6..4d4f235 100644
--- a/lib/arm_trng/arm_trng.h
+++ b/lib/arm_trng/arm_trng.h
@@ -28,7 +28,7 @@
  * (https://developer.arm.com/documentation/den0098/latest).
  */
 
-#include <lib/sm/smcall.h>
+#include <interface/smc/smc_def.h>
 
 #define SMC_TRNG_CURRENT_MAJOR_VERSION 1
 
diff --git a/lib/arm_trng/rules.mk b/lib/arm_trng/rules.mk
index d62aa45..ca0c38d 100644
--- a/lib/arm_trng/rules.mk
+++ b/lib/arm_trng/rules.mk
@@ -30,6 +30,7 @@ MODULE_SRCS += \
 
 MODULE_DEPS += \
 	trusty/kernel/lib/smc \
+	trusty/user/base/interface/smc \
 
 # Timeouts in milliseconds for the long wait warning and the printing
 ARM_TRNG_LONG_WAIT_MS ?= 1000
diff --git a/lib/dtb_service/rust/rules.mk b/lib/dtb_service/rust/rules.mk
index 5dfefa0..729f053 100644
--- a/lib/dtb_service/rust/rules.mk
+++ b/lib/dtb_service/rust/rules.mk
@@ -24,6 +24,10 @@ MODULE_CRATE_NAME := dtb_service
 MODULE_SDK_LIB_NAME := dtb_service-rust
 
 MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,thiserror) \
+	packages/modules/Virtualization/libs/libfdt \
+	trusty/kernel/lib/vmm_obj_service/rust \
 
 MODULE_BINDGEN_ALLOW_TYPES :=
 
diff --git a/lib/dtb_service/rust/src/lib.rs b/lib/dtb_service/rust/src/lib.rs
index 62633b9..2608933 100644
--- a/lib/dtb_service/rust/src/lib.rs
+++ b/lib/dtb_service/rust/src/lib.rs
@@ -18,9 +18,97 @@
 
 #![no_std]
 
+use core::ffi::CStr;
+use core::slice::from_raw_parts;
+use libfdt::{Fdt, FdtError, FdtNode};
+use rust_support::ktipc::ktipc_port_acl;
+use thiserror::Error;
+
 #[allow(non_upper_case_globals)]
 #[allow(non_camel_case_types)]
 #[allow(unused)]
 pub mod sys {
     include!(env!("BINDGEN_INC_FILE"));
 }
+
+#[derive(Error, Debug)]
+pub enum DtbServiceError {
+    #[error("failed to construct Fdt {0}")]
+    FailedFdtConstruction(FdtError),
+    #[error("failed to retrieve global device tree {0}")]
+    NoGlobalDeviceTree(rust_support::Error),
+    #[error("failed to access device tree property {property_name}. {fdt_err}")]
+    PropertyNotFound { property_name: &'static str, fdt_err: FdtError },
+    #[error("failed to share memory with vmm_obj_service {0}")]
+    FailedVmmObjServiceShare(rust_support::Error),
+}
+
+/// Get a static reference to the device tree, if it has been set and
+/// is successfully validated.
+pub fn get_dtb() -> Result<&'static Fdt, DtbServiceError> {
+    let mut fdt_ptr: *const u8 = core::ptr::null_mut();
+    let mut fdt_size = 0usize;
+    // SAFETY: Neither pointer is retained by dtb_get. dbt_get does not read from *fdt_ptr.
+    let rc = unsafe { sys::dtb_get(&mut fdt_ptr as *mut *const u8, &mut fdt_size) };
+    if rc != sys::NO_ERROR as i32 || fdt_ptr.is_null() {
+        return Err(DtbServiceError::NoGlobalDeviceTree(
+            // We know rc != NO_ERROR so unwrap_err on from_lk should be a safe assumption
+            rust_support::Error::from_lk(rc).unwrap_err(),
+        ));
+    }
+    // SAFETY: Outputs from dtb_get are defined to be static, read only, and span the size returned.
+    // fdt_ptr has already been checked for null.
+    let fdt = unsafe { from_raw_parts(fdt_ptr, fdt_size) };
+
+    libfdt::Fdt::from_slice(fdt).map_err(|e| DtbServiceError::FailedFdtConstruction(e))
+}
+
+/// Expose the region described by a reserved-memory node as a
+/// vmm_obj_service. If the given name is found as a compatible
+/// string on the reserved_mem node, the vmm_obj_service is exposed
+/// on a port with the provided name and ACL, and Ok(()) is returned.
+///
+/// Otherwise, Err(DtbServiceError) is returned.
+///
+/// Note that this implementation only handles the first memory range
+/// on a reserved-memory node. If more ranges are specified via
+/// additional reg entries, they are ignored with a logged warning.
+pub fn map_reserved_memory(
+    reserved_mem: &FdtNode,
+    name: &'static CStr,
+    acl: &'static ktipc_port_acl,
+) -> Result<(), DtbServiceError> {
+    let node = reserved_mem
+        .next_compatible(name)
+        .map_err(|e| DtbServiceError::PropertyNotFound { property_name: "compatible", fdt_err: e })?
+        .ok_or_else(|| DtbServiceError::PropertyNotFound {
+            property_name: "compatible",
+            fdt_err: FdtError::NotFound,
+        })?;
+    let mut reg_itr = node
+        .reg()
+        .map_err(|e| DtbServiceError::PropertyNotFound { property_name: "reg", fdt_err: e })?
+        .ok_or_else(|| DtbServiceError::PropertyNotFound {
+            property_name: "reg",
+            fdt_err: FdtError::NotFound,
+        })?;
+    let reg = reg_itr.next().ok_or_else(|| DtbServiceError::PropertyNotFound {
+        property_name: "reg",
+        fdt_err: FdtError::NotFound,
+    })?;
+
+    vmm_obj_service_rust::share_sized_buffer(
+        reg.addr as *const u8,
+        reg.size.unwrap_or(0) as usize,
+        0,
+        name,
+        acl,
+    )
+    .map_err(|e| DtbServiceError::FailedVmmObjServiceShare(e))?;
+
+    if reg_itr.next().is_some() {
+        log::warn!("Found unexpected address in reg node. Ignoring.");
+    }
+
+    Ok(())
+}
diff --git a/lib/extmem/rust/rules.mk b/lib/extmem/rust/rules.mk
index d9b2842..c02cd3c 100644
--- a/lib/extmem/rust/rules.mk
+++ b/lib/extmem/rust/rules.mk
@@ -31,7 +31,7 @@ MODULE_SRCS += \
 MODULE_ADD_IMPLICIT_DEPS := false
 
 MODULE_DEPS := \
-	external/lk/lib/rust_support \
+	$(LKROOT)/lib/rust_support \
 	trusty/kernel/lib/extmem \
 	trusty/kernel/lib/sm \
 	trusty/user/base/lib/liballoc-rust \
diff --git a/lib/libc-trusty/rules.mk b/lib/libc-trusty/rules.mk
index a816c36..58d2e9c 100644
--- a/lib/libc-trusty/rules.mk
+++ b/lib/libc-trusty/rules.mk
@@ -106,6 +106,7 @@ MODULE_SRCS := \
 	$(LK_DIR)/lib/libc/eabi_unwind_stubs.c \
 	$(LK_DIR)/lib/libc/io_handle.c \
 	$(LK_DIR)/lib/libc/printf.c \
+	$(LK_DIR)/lib/libc/rand.c \
 	$(LK_DIR)/lib/libc/stdio.c \
 	$(LK_DIR)/lib/libc/strtol.c \
 	$(LK_DIR)/lib/libc/strtoll.c \
@@ -116,9 +117,6 @@ MODULE_SRCS += \
 	$(LK_DIR)/lib/libc/atexit.c \
 	$(LK_DIR)/lib/libc/pure_virtual.cpp
 
-MODULE_DEPS += \
-	$(LK_DIR)/lib/libc/rand
-
 # These stubs are only needed because binder uses libutils which uses pthreads mutex directly
 MODULE_SRCS += \
 	$(LIBC_TRUSTY_DIR)/pthreads.c
diff --git a/lib/trusty/include/lib/trusty/handle_set.h b/lib/trusty/include/lib/trusty/handle_set.h
index 9836a9b..d8674da 100644
--- a/lib/trusty/include/lib/trusty/handle_set.h
+++ b/lib/trusty/include/lib/trusty/handle_set.h
@@ -30,6 +30,8 @@
 #define HSET_DEL 1
 #define HSET_MOD 2
 #define HSET_DEL_GET_COOKIE 3
+#define HSET_DEL_WITH_COOKIE 4
+#define HSET_MOD_WITH_COOKIE 5
 
 __BEGIN_CDECLS
 
diff --git a/lib/trusty/uctx.c b/lib/trusty/uctx.c
index abd6ed1..0789975 100644
--- a/lib/trusty/uctx.c
+++ b/lib/trusty/uctx.c
@@ -713,7 +713,8 @@ static int _hset_add_item(struct handle* hset,
 
 static int _hset_del_item(struct handle* hset,
                           struct htbl_entry* item,
-                          struct uevent* uevent) {
+                          struct uevent* uevent,
+                          bool check_cookie) {
     uint del_cnt = 0;
     struct handle_ref* ref;
     struct handle_ref* tmp;
@@ -724,7 +725,17 @@ static int _hset_del_item(struct handle* hset,
             del_cnt++;
             LTRACEF("%p: %p\n", ref->parent, ref->handle);
             if (uevent) {
-                uevent->cookie = (user_addr_t)(uintptr_t)ref->cookie;
+                // If `check_cookie` is set, verify that it matches
+                // the stored cookie.
+                if (check_cookie &&
+                    (user_addr_t)(uintptr_t)ref->cookie != uevent->cookie) {
+                    return ERR_NOT_FOUND;
+                }
+                // Check if we're in `HSET_DEL_GET_COOKIE`.
+                if (!check_cookie) {
+                    // Write the stored cookie back to userspace.
+                    uevent->cookie = (user_addr_t)(uintptr_t)ref->cookie;
+                }
             }
             list_delete(&ref->uctx_node);
             handle_set_detach_ref(ref);
@@ -739,7 +750,8 @@ static int _hset_del_item(struct handle* hset,
 static int _hset_mod_item(struct handle* hset,
                           struct htbl_entry* item,
                           uint32_t emask,
-                          void* cookie) {
+                          void* cookie,
+                          bool check_cookie) {
     uint mod_cnt = 0;
     struct handle_ref* ref;
     struct handle_ref* tmp;
@@ -749,6 +761,11 @@ static int _hset_mod_item(struct handle* hset,
         if (ref->parent == hset) {
             mod_cnt++;
             LTRACEF("%p: %p\n", ref->parent, ref->handle);
+
+            // If `check_cookie` is not set, replace the cookie.
+            // If it is set, verify that it matches the stored cookie.
+            if (check_cookie && ref->cookie != cookie)
+                return ERR_NOT_FOUND;
             handle_set_update_ref(ref, emask, cookie);
         }
     }
@@ -782,17 +799,29 @@ static int _hset_ctrl_locked(handle_id_t hset_id,
 
     case HSET_DEL:
         ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
-                             NULL);
+                             NULL, /* check_cookie */ false);
         break;
 
     case HSET_DEL_GET_COOKIE:
         ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
-                             uevent);
+                             uevent, /* check_cookie */ false);
+        break;
+
+    case HSET_DEL_WITH_COOKIE:
+        ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
+                             uevent, /* check_cookie */ true);
         break;
 
     case HSET_MOD:
         ret = _hset_mod_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
-                             uevent->event, (void*)(uintptr_t)uevent->cookie);
+                             uevent->event, (void*)(uintptr_t)uevent->cookie,
+                             /* check_cookie */ false);
+        break;
+
+    case HSET_MOD_WITH_COOKIE:
+        ret = _hset_mod_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
+                             uevent->event, (void*)(uintptr_t)uevent->cookie,
+                             /* check_cookie */ true);
         break;
 
     default:
diff --git a/lib/version/rules.mk b/lib/version/rules.mk
index 22c0743..3b7a638 100644
--- a/lib/version/rules.mk
+++ b/lib/version/rules.mk
@@ -46,6 +46,11 @@ MODULE_CFLAGS += \
 	-DBUILDID=$(BUILDID)
 endif
 
+ifneq ($(BUILDDATE),)
+MODULE_CFLAGS += \
+	-DBUILDDATE="$(BUILDDATE)"
+endif
+
 MODULE_CFLAGS += \
 	-DVERSION_PROJECT=\"$(PROJECT)\"
 
diff --git a/lib/version/version.c b/lib/version/version.c
index feb09cb..335ea8b 100644
--- a/lib/version/version.c
+++ b/lib/version/version.c
@@ -44,5 +44,11 @@
 #define BUILDID_STR ""
 #endif
 
+#ifdef BUILDDATE
+#define BUILDDATE_STR TOSTRING(BUILDDATE)
+#else
+#define BUILDDATE_STR __TIME__ " " __DATE__
+#endif
+
 char lk_version[] = "Project: " VERSION_PROJECT ", " VERSION_STR BUILDID_STR
-                    "Built: " __TIME__ " " __DATE__;
+                    "Built: " BUILDDATE_STR;
diff --git a/make/host_tool.mk b/make/host_tool.mk
index d13b97d..0921464 100644
--- a/make/host_tool.mk
+++ b/make/host_tool.mk
@@ -100,7 +100,7 @@ GENERIC_CC := $(HOST_CC)
 GENERIC_SRCS := $(HOST_SRCS)
 GENERIC_OBJ_DIR := $(BUILDDIR)/host_tools/obj/$(HOST_TOOL_NAME)
 GENERIC_FLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror -Wno-missing-field-initializers $(HOST_SANITIZER_FLAGS) $(HOST_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
-GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809
+GENERIC_CFLAGS := -std=gnu11 -D_POSIX_C_SOURCE=200809
 GENERIC_CPPFLAGS := -std=c++20 $(HOST_LIBCXX_CPPFLAGS)
 GENERIC_SRCDEPS := $(HOST_SRCDEPS)
 GENERIC_LOG_NAME := $(HOST_TOOL_NAME)
diff --git a/platform/desktop/arm64/rust/rules.mk b/platform/desktop/arm64/rust/rules.mk
index 40e7043..ce0eb3c 100644
--- a/platform/desktop/arm64/rust/rules.mk
+++ b/platform/desktop/arm64/rust/rules.mk
@@ -33,9 +33,9 @@ MODULE_SRCS += \
 MODULE_LIBRARY_DEPS += \
 	$(call FIND_CRATE,log) \
 	packages/modules/Virtualization/libs/libfdt \
-	trusty/user/base/lib/trusty-std \
-	trusty/user/desktop/test/data \
+	trusty/kernel/lib/dtb_service \
 	trusty/kernel/lib/dtb_service/rust \
-	trusty/kernel/lib/vmm_obj_service/rust \
+	trusty/kernel/platform/desktop/common/rust \
+	trusty/user/base/lib/trusty-std \
 
 include make/library.mk
diff --git a/platform/desktop/arm64/rust/src/lib.rs b/platform/desktop/arm64/rust/src/lib.rs
index 4fbd6d9..1a4b03d 100644
--- a/platform/desktop/arm64/rust/src/lib.rs
+++ b/platform/desktop/arm64/rust/src/lib.rs
@@ -26,82 +26,14 @@
 
 #![no_std]
 
-use core::ffi::{c_uint, CStr};
-use core::slice::from_raw_parts;
-use dtb_service::sys::{dtb_get, NO_ERROR};
-use libfdt::FdtNode;
-use rust_support::{
-    init::lk_init_level,
-    ipc::IPC_PORT_ALLOW_TA_CONNECT,
-    ktipc::{ktipc_port_acl, uuid},
-    LK_INIT_HOOK,
-};
-
-/// UUID of the gsc_svc app.
-const GSC_SVC_UUID: uuid = uuid {
-    time_low: 0x77026d06,
-    time_mid: 0xbe0f,
-    time_hi_and_version: 0x4604,
-    clock_seq_and_node: [0xa6, 0xd5, 0xf7, 0x29, 0x38, 0x8a, 0x44, 0x5b],
-};
-const UUIDS: [*const uuid; 1] = [&GSC_SVC_UUID as *const uuid];
-const KTIPC_PORT_ACL: ktipc_port_acl = ktipc_port_acl {
-    flags: IPC_PORT_ALLOW_TA_CONNECT,
-    uuid_num: UUIDS.len() as u32,
-    uuids: (&UUIDS).as_ptr(),
-    extra_data: core::ptr::null(),
-};
-
-fn share_reserved_memory(reserved_mem: &FdtNode, name: &'static CStr) {
-    let node = reserved_mem
-        .next_compatible(name)
-        .expect("Could not get boot param node")
-        .expect("Could not get boot param node");
-    let mut reg_itr =
-        node.reg().expect("Could not get reg address").expect("Could not get reg address");
-    let reg = reg_itr.next().expect("Could not get reg address");
-    vmm_obj_service_rust::share_sized_buffer(
-        reg.addr as *const u8,
-        reg.size.unwrap_or(0) as usize,
-        0,
-        name,
-        &KTIPC_PORT_ACL,
-    )
-    .expect("Could not share boot params");
-    if reg_itr.next().is_some() {
-        log::warn!("Found unexpected address is reg node. Ignoring.");
-    }
-}
+use core::ffi::c_uint;
+use dtb_service::get_dtb;
+use platform_desktop_common::share_reserved_memory_if_available;
+use rust_support::{init::lk_init_level, LK_INIT_HOOK};
 
 extern "C" fn platform_dtb_init_func(_level: c_uint) {
-    let mut fdt_ptr: *const u8 = core::ptr::null_mut();
-    let mut fdt_size = 0usize;
-    // SAFETY: Neither pointer is retained by dtb_get. dbt_get does not read from *fdt_ptr.
-    let rc = unsafe { dtb_get(&mut fdt_ptr as *mut *const u8, &mut fdt_size) };
-    if rc != NO_ERROR as i32 || fdt_ptr.is_null() {
-        log::error!("Failed to get device tree (rc: {rc}, ptr: {fdt_ptr:p}, size: {fdt_size}).");
-        return;
-    }
-    // SAFETY: Outputs from dtb_get are defined to be static, read only, and span the size returned.
-    // fdt_ptr has already been checked for null.
-    let fdt = unsafe { from_raw_parts(fdt_ptr, fdt_size) };
-
-    let fdt = libfdt::Fdt::from_slice(fdt).expect("Device tree should be valid");
-    let reserved_mem = fdt
-        .node(c"/reserved-memory")
-        .expect("Could not get reserved memory node")
-        .expect("Could not get reserved memory node");
-
-    let boot_params = [
-        c"google,open-dice",
-        c"google,session-key-seed",
-        c"google,early-entropy",
-        c"google,auth-token-key-seed",
-    ];
-
-    for param in boot_params {
-        share_reserved_memory(&reserved_mem, param);
-    }
+    let fdt = get_dtb().expect("Device tree should be set and valid");
+    share_reserved_memory_if_available(&fdt);
 }
 
 LK_INIT_HOOK!(platform_dtb_init, platform_dtb_init_func, lk_init_level::LK_INIT_LEVEL_THREADING);
diff --git a/platform/desktop/common/rust/rules.mk b/platform/desktop/common/rust/rules.mk
new file mode 100644
index 0000000..3421c44
--- /dev/null
+++ b/platform/desktop/common/rust/rules.mk
@@ -0,0 +1,41 @@
+#
+# Copyright (c) 2025, Google, Inc. All rights reserved
+#
+# Permission is hereby granted, free of charge, to any person obtaining
+# a copy of this software and associated documentation files
+# (the "Software"), to deal in the Software without restriction,
+# including without limitation the rights to use, copy, modify, merge,
+# publish, distribute, sublicense, and/or sell copies of the Software,
+# and to permit persons to whom the Software is furnished to do so,
+# subject to the following conditions:
+#
+# The above copyright notice and this permission notice shall be
+# included in all copies or substantial portions of the Software.
+#
+# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := platform_desktop_common
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	packages/modules/Virtualization/libs/libfdt \
+	trusty/user/base/lib/trusty-std \
+	trusty/user/desktop/test/data \
+	trusty/kernel/lib/dtb_service/rust \
+	trusty/kernel/lib/vmm_obj_service/rust \
+
+include make/library.mk
diff --git a/platform/desktop/common/rust/src/lib.rs b/platform/desktop/common/rust/src/lib.rs
new file mode 100644
index 0000000..2b36afc
--- /dev/null
+++ b/platform/desktop/common/rust/src/lib.rs
@@ -0,0 +1,77 @@
+/*
+ * Copyright (c) 2025 Google Inc. All rights reserved
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+//! This library provides and registers a little kernel pre threading init function to map desktop
+//! specific reserved memory nodes from the device tree into the gsc_svc trusted app.
+
+#![no_std]
+
+use dtb_service::map_reserved_memory;
+use libfdt::Fdt;
+use rust_support::{
+    ipc::IPC_PORT_ALLOW_TA_CONNECT,
+    ktipc::{ktipc_port_acl, uuid},
+};
+
+/// UUID of the gsc_svc app.
+const GSC_SVC_UUID: uuid = uuid {
+    time_low: 0x77026d06,
+    time_mid: 0xbe0f,
+    time_hi_and_version: 0x4604,
+    clock_seq_and_node: [0xa6, 0xd5, 0xf7, 0x29, 0x38, 0x8a, 0x44, 0x5b],
+};
+const UUIDS: [*const uuid; 1] = [&GSC_SVC_UUID as *const uuid];
+const KTIPC_PORT_ACL_GSC_ONLY: &ktipc_port_acl = &ktipc_port_acl {
+    flags: IPC_PORT_ALLOW_TA_CONNECT,
+    uuid_num: UUIDS.len() as u32,
+    uuids: (&UUIDS).as_ptr(),
+    extra_data: core::ptr::null(),
+};
+const KTIPC_PORT_ACL_ANY: &ktipc_port_acl = &ktipc_port_acl {
+    flags: IPC_PORT_ALLOW_TA_CONNECT,
+    uuid_num: 0,
+    uuids: core::ptr::null(),
+    extra_data: core::ptr::null(),
+};
+
+// TODO(b/413491839): Panic if these aren't available one protected mode is fully supported.
+pub fn share_reserved_memory_if_available(fdt: &Fdt) {
+    let reserved_mem = match fdt.node(c"/reserved-memory") {
+        Ok(Some(x)) => x,
+        Ok(None) => return log::error!("Reserved memory node not found"),
+        Err(e) => return log::error!("Error getting reserved memory node: {e}"),
+    };
+
+    let boot_params = [
+        (c"google,open-dice", KTIPC_PORT_ACL_ANY),
+        (c"google,session-key-seed", KTIPC_PORT_ACL_GSC_ONLY),
+        (c"google,early-entropy", KTIPC_PORT_ACL_GSC_ONLY),
+        (c"google,auth-token-key-seed", KTIPC_PORT_ACL_GSC_ONLY),
+    ];
+
+    for (name, acl) in boot_params {
+        if map_reserved_memory(&reserved_mem, name, acl).is_err() {
+            log::error!("Failed to map {:?}.", name);
+        }
+    }
+}
diff --git a/platform/desktop/x86_64/rust/rules.mk b/platform/desktop/x86_64/rust/rules.mk
new file mode 100644
index 0000000..2214791
--- /dev/null
+++ b/platform/desktop/x86_64/rust/rules.mk
@@ -0,0 +1,40 @@
+#
+# Copyright (c) 2025, Google, Inc. All rights reserved
+#
+# Permission is hereby granted, free of charge, to any person obtaining
+# a copy of this software and associated documentation files
+# (the "Software"), to deal in the Software without restriction,
+# including without limitation the rights to use, copy, modify, merge,
+# publish, distribute, sublicense, and/or sell copies of the Software,
+# and to permit persons to whom the Software is furnished to do so,
+# subject to the following conditions:
+#
+# The above copyright notice and this permission notice shall be
+# included in all copies or substantial portions of the Software.
+#
+# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := platform_desktop_x86_64
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	packages/modules/Virtualization/libs/libfdt \
+	trusty/user/base/lib/trusty-std \
+	trusty/kernel/lib/dtb_boot_params \
+	trusty/kernel/platform/desktop/common/rust \
+
+include make/library.mk
diff --git a/platform/desktop/x86_64/rust/src/lib.rs b/platform/desktop/x86_64/rust/src/lib.rs
new file mode 100644
index 0000000..deb5af5
--- /dev/null
+++ b/platform/desktop/x86_64/rust/src/lib.rs
@@ -0,0 +1,45 @@
+/*
+ * Copyright (c) 2025 Google Inc. All rights reserved
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+//! This library provides and registers a little kernel pre threading init function to map desktop
+//! specific reserved memory nodes from the device tree into the gsc_svc trusted app.
+
+#![no_std]
+
+use dtb_boot_params::find_dtbs;
+
+use core::ffi::c_uint;
+use platform_desktop_common::share_reserved_memory_if_available;
+use rust_support::{init::lk_init_level, LK_INIT_HOOK};
+
+extern "C" fn platform_dtb_init_func(_level: c_uint) {
+    let fdt = find_dtbs()
+        .expect("Device tree should be passed to VM")
+        .next()
+        .expect("Device tree should be passed to VM")
+        .expect("Device tree should be passed to VM");
+    let fdt = libfdt::Fdt::from_slice(fdt.as_ref()).expect("Device tree should be valid");
+    share_reserved_memory_if_available(&fdt);
+}
+
+LK_INIT_HOOK!(platform_dtb_init, platform_dtb_init_func, lk_init_level::LK_INIT_LEVEL_THREADING);
diff --git a/platform/generic-arm64/map_reserved_mem/rules.mk b/platform/generic-arm64/map_reserved_mem/rules.mk
new file mode 100644
index 0000000..63d055e
--- /dev/null
+++ b/platform/generic-arm64/map_reserved_mem/rules.mk
@@ -0,0 +1,39 @@
+#
+# Copyright (c) 2025, Google, Inc. All rights reserved
+#
+# Permission is hereby granted, free of charge, to any person obtaining
+# a copy of this software and associated documentation files
+# (the "Software"), to deal in the Software without restriction,
+# including without limitation the rights to use, copy, modify, merge,
+# publish, distribute, sublicense, and/or sell copies of the Software,
+# and to permit persons to whom the Software is furnished to do so,
+# subject to the following conditions:
+#
+# The above copyright notice and this permission notice shall be
+# included in all copies or substantial portions of the Software.
+#
+# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := platform_generic_arm64_map_reserved_mem
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	packages/modules/Virtualization/libs/libfdt \
+	trusty/kernel/lib/dtb_service/rust \
+	trusty/kernel/lib/vmm_obj_service/rust \
+
+include make/library.mk
diff --git a/platform/generic-arm64/map_reserved_mem/src/lib.rs b/platform/generic-arm64/map_reserved_mem/src/lib.rs
new file mode 100644
index 0000000..8b1974b
--- /dev/null
+++ b/platform/generic-arm64/map_reserved_mem/src/lib.rs
@@ -0,0 +1,84 @@
+/*
+ * Copyright (c) 2025 Google Inc. All rights reserved
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining
+ * a copy of this software and associated documentation files
+ * (the "Software"), to deal in the Software without restriction,
+ * including without limitation the rights to use, copy, modify, merge,
+ * publish, distribute, sublicense, and/or sell copies of the Software,
+ * and to permit persons to whom the Software is furnished to do so,
+ * subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be
+ * included in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
+ * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
+ * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
+ * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+//! This library registers a little kernel init hook to
+//! map a DICE handover from a device tree if it is present.
+
+#![no_std]
+
+use core::ffi::c_uint;
+use dtb_service::{get_dtb, map_reserved_memory};
+use rust_support::{init::lk_init_level, LK_INIT_HOOK};
+use rust_support::{
+    ipc::IPC_PORT_ALLOW_TA_CONNECT,
+    ktipc::{ktipc_port_acl, uuid},
+};
+
+// 9b3c1e9e-1808-4b98-8fa9-8592dff3a337
+const AUTHMGR_FE_UUID: uuid = uuid {
+    time_low: 0x9b3c1e9e,
+    time_mid: 0x1808,
+    time_hi_and_version: 0x4b98,
+    clock_seq_and_node: [0x8f, 0xa9, 0x85, 0x92, 0xdf, 0xf3, 0xa3, 0x37],
+};
+const UUIDS: [*const uuid; 1] = [&AUTHMGR_FE_UUID as *const uuid];
+const KTIPC_PORT_ACL_AUTHMGR_FE_ONLY: &ktipc_port_acl = &ktipc_port_acl {
+    flags: IPC_PORT_ALLOW_TA_CONNECT,
+    uuid_num: UUIDS.len() as u32,
+    uuids: (&UUIDS).as_ptr(),
+    extra_data: core::ptr::null(),
+};
+
+/// An init hook to share the DICE handover to user space.
+///
+/// This hook does not panic and returns early on any errors encountered
+/// during the process of retrieving the dtb, finding the reserved-memory
+/// region for the DICE handover, or mapping that memory region. User
+/// space code that depends on this memory can choose how to fail. This
+/// gives flexibility for running the same kernel in environments where
+/// certain reserved-memory nodes may not be populated. For example, an
+/// unprotected VM or a protected VM launched without pvmfw.
+extern "C" fn share_dice_handover_hook(_level: c_uint) {
+    let fdt = match get_dtb() {
+        Ok(x) => x,
+        Err(e) => return log::error!("Could not retrieve global dtb: {e}"),
+    };
+
+    let reserved_mem = match fdt.node(c"/reserved-memory") {
+        Ok(Some(x)) => x,
+        Ok(None) => return log::error!("Reserved memory node not found"),
+        Err(e) => return log::error!("Error getting reserved memory node: {e}"),
+    };
+
+    let _ = map_reserved_memory(&reserved_mem, c"google,open-dice", KTIPC_PORT_ACL_AUTHMGR_FE_ONLY)
+        .inspect_err(|e| {
+            log::error!("Failed to map reserved memory node google,open-dice {}", e);
+        });
+}
+
+LK_INIT_HOOK!(
+    share_dice_handover,
+    share_dice_handover_hook,
+    // Apps are started at LK_INIT_LEVEL_APPS + 1
+    lk_init_level::LK_INIT_LEVEL_APPS
+);
diff --git a/platform/generic-arm64/rules.mk b/platform/generic-arm64/rules.mk
index a5e05c7..ce57d8b 100644
--- a/platform/generic-arm64/rules.mk
+++ b/platform/generic-arm64/rules.mk
@@ -76,6 +76,13 @@ MODULE_DEPS += \
 MODULE_DEPS += \
 	dev/virtio/vsock-rust \
 
+# We include the ARM TRNG library here instead of trusty/device
+# because it should be available on all generic ARMv8 devices.
+# TODO: b/379677575 - remove conditional once arm_trng supports HVCs
+ifeq (false,$(call TOBOOL,$(TRUSTY_VM_GUEST)))
+MODULE_DEPS += trusty/kernel/lib/arm_trng
+endif
+
 GLOBAL_DEFINES += \
 	MEMBASE=$(MEMBASE) \
 	MEMSIZE=$(MEMSIZE) \
@@ -112,4 +119,11 @@ MODULE_DEPS += \
 MODULE_DEFINES += MMIO_GUARD_ENABLED=1
 endif
 
+MAP_RESERVED_MEM_FROM_DT ?= false
+ifeq (true,$(call TOBOOL,$(MAP_RESERVED_MEM_FROM_DT)))
+MODULE_DEPS += \
+	trusty/kernel/platform/generic-arm64/map_reserved_mem \
+
+endif
+
 include make/module.mk
diff --git a/platform/generic-x86_64/rules.mk b/platform/generic-x86_64/rules.mk
index ca9811a..9efd098 100644
--- a/platform/generic-x86_64/rules.mk
+++ b/platform/generic-x86_64/rules.mk
@@ -30,5 +30,6 @@ MODULE_DEPS += \
 	$(LOCAL_DIR)/rust \
 	dev/interrupt/x86_lapic \
 	dev/timer/x86_generic \
+	trusty/kernel/lib/dtb_service \
 
 include make/module.mk
```

