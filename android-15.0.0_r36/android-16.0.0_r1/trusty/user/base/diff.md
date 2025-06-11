```diff
diff --git a/build-config-usertests b/build-config-usertests
index 42e5a79..ad6bb95 100644
--- a/build-config-usertests
+++ b/build-config-usertests
@@ -38,7 +38,10 @@
     porttest("com.android.trusty.rust.hwkey.test"),
     porttest("com.android.trusty.rust.hwbcc.test"),
     porttest("com.android.trusty.rust.hwwsk.test"),
+    porttest("com.android.trusty.rust.service_manager_tests.test"),
     porttest("com.android.trusty.rust.storage.test"),
+    porttest("com.android.trusty.rust.diced_open_dice_tests.test"),
+    porttest("com.android.trusty.rust.pvmdice.test"),
     compositetest(
         name="com.android.trusty.secure_fb.test-then-reboot",
         sequence=[
diff --git a/include/user/trusty_ipc.h b/include/user/trusty_ipc.h
index c52527e..eaf59f7 100644
--- a/include/user/trusty_ipc.h
+++ b/include/user/trusty_ipc.h
@@ -98,12 +98,15 @@ enum {
 };
 
 /*
- *  Values for cmd parameter of handle_set_ctrl call
+ *  Values for cmd parameter of handle_set_ctrl call.
+ *  These should be kept in sync with #defines in handle_set.h
  */
 enum {
     HSET_ADD = 0x0, /* adds new handle to handle set */
     HSET_DEL = 0x1, /* deletes handle from handle set */
     HSET_MOD = 0x2, /* modifies handle attributes in handle set */
+    HSET_DEL_GET_COOKIE =
+            0x3, /* deletes a handle from handle set and returns its cookie */
 };
 
 /*
diff --git a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
index 05c86f3..b762c98 100644
--- a/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
+++ b/interface/arm_ffa/include/interface/arm_ffa/arm_ffa.h
@@ -29,7 +29,7 @@
 #endif
 
 #define FFA_CURRENT_VERSION_MAJOR (1U)
-#define FFA_CURRENT_VERSION_MINOR (0U)
+#define FFA_CURRENT_VERSION_MINOR (2U)
 
 #define FFA_VERSION_TO_MAJOR(version) ((version) >> 16)
 #define FFA_VERSION_TO_MINOR(version) ((version) & (0xffff))
@@ -229,7 +229,7 @@ STATIC_ASSERT(sizeof(struct ffa_mapd) == 4);
  * struct ffa_emad - Endpoint memory access descriptor.
  * @mapd:  &struct ffa_mapd.
  * @comp_mrd_offset:
- *         Offset of &struct ffa_comp_mrd form start of &struct ffa_mtd.
+ *         Offset of &struct ffa_comp_mrd form start of &struct ffa_mtd_common.
  * @reserved_8_15:
  *         Reserved bytes 8-15. Must be 0.
  */
@@ -241,7 +241,7 @@ struct ffa_emad {
 STATIC_ASSERT(sizeof(struct ffa_emad) == 16);
 
 /**
- * struct ffa_mtd - Memory transaction descriptor.
+ * struct ffa_mtd_common - Memory transaction descriptor.
  * @sender_id:
  *         Sender endpoint id.
  * @memory_region_attributes:
@@ -253,6 +253,21 @@ STATIC_ASSERT(sizeof(struct ffa_emad) == 16);
  * @handle:
  *         Id of shared memory object. Most be 0 for MEM_SHARE.
  * @tag:   Client allocated tag. Must match original value.
+ */
+struct ffa_mtd_common {
+    ffa_endpoint_id16_t sender_id;
+    ffa_mem_attr8_t memory_region_attributes;
+    uint8_t reserved_3;
+    ffa_mtd_flag32_t flags;
+    uint64_t handle;
+    uint64_t tag;
+};
+STATIC_ASSERT(sizeof(struct ffa_mtd_common) == 24);
+
+/**
+ * struct ffa_mtd_v1_0 - Memory transaction descriptor for v1.0.
+ * @common:
+ *         The common part of the descriptor (shared with v1.1).
  * @reserved_24_27:
  *         Reserved bytes 24-27. Must be 0.
  * @emad_count:
@@ -261,18 +276,39 @@ STATIC_ASSERT(sizeof(struct ffa_emad) == 16);
  * @emad:
  *         Endpoint memory access descriptor array (see @struct ffa_emad).
  */
-struct ffa_mtd {
-    ffa_endpoint_id16_t sender_id;
-    ffa_mem_attr8_t memory_region_attributes;
-    uint8_t reserved_3;
-    ffa_mtd_flag32_t flags;
-    uint64_t handle;
-    uint64_t tag;
+struct ffa_mtd_v1_0 {
+    struct ffa_mtd_common common;
     uint32_t reserved_24_27;
     uint32_t emad_count;
     struct ffa_emad emad[];
 };
-STATIC_ASSERT(sizeof(struct ffa_mtd) == 32);
+STATIC_ASSERT(sizeof(struct ffa_mtd_v1_0) == 32);
+
+/**
+ * struct ffa_mtd_v1_1 - Memory transaction descriptor for v1.1 and higher.
+ * @common:
+ *         The common part of the descriptor (shared with v1.0).
+ * @emad_size:
+ *         Size of each endpoint memory access descriptor.
+ * @emad_count:
+ *         Number of entries at @emad_offset.
+ *         Must be 1 in current implementation.
+ *         FFA spec allows more entries.
+ * @emad_offset:
+ *         Offset from the base address of this descriptor to the
+ *         endpoint memory access descriptor array (see @struct ffa_emad).
+ * @reserved_36: Reserved bytes at offset 36. Must be 0.
+ * @reserved_40: Reserved bytes at offset 40. Must be 0.
+ */
+struct ffa_mtd_v1_1 {
+    struct ffa_mtd_common common;
+    uint32_t emad_size;
+    uint32_t emad_count;
+    uint32_t emad_offset;
+    uint32_t reserved_36;
+    uint64_t reserved_40;
+};
+STATIC_ASSERT(sizeof(struct ffa_mtd_v1_1) == 48);
 
 /**
  * struct ffa_mem_relinquish_descriptor - Relinquish request descriptor.
@@ -333,6 +369,24 @@ typedef uint32_t ffa_features2_t;
 typedef uint32_t ffa_features3_t;
 #define FFA_FEATURES3_MEM_RETRIEVE_REQ_REFCOUNT_MASK 0xffU
 
+/**
+ * Flags passed to FFA_PARTITION_INFO_GET
+ *
+ * * @FFA_PARTITION_INFO_GET_FLAG_RETURN_COUNT_ONLY
+ *     Return only the count of partitions corresponding to the given UUID.
+ */
+typedef uint32_t ffa_partition_info_get_flag32_t;
+#define FFA_PARTITION_INFO_GET_FLAG_RETURN_COUNT_ONLY (1U << 0)
+
+struct ffa_part_info_desc {
+    uint16_t partition_id;
+    uint16_t exec_ctx_or_proxy_id;
+    uint32_t properties;
+    uint64_t uuid_lo;
+    uint64_t uuid_hi;
+};
+STATIC_ASSERT(sizeof(struct ffa_part_info_desc) == 24);
+
 /**
  * enum ffa_error - FF-A error code
  * @FFA_ERROR_NOT_SUPPORTED:
@@ -353,6 +407,8 @@ typedef uint32_t ffa_features3_t;
  *         Operation aborted. Reason for abort is implementation specific.
  * @FFA_ERROR_NO_DATA:
  *         Requested information not available.
+ * @FFA_ERROR_NOT_READY:
+ *         Callee is not ready to handle the request.
  *
  */
 enum ffa_error {
@@ -365,6 +421,7 @@ enum ffa_error {
     FFA_ERROR_RETRY = -7,
     FFA_ERROR_ABORTED = -8,
     FFA_ERROR_NO_DATA = -9,
+    FFA_ERROR_NOT_READY = -10,
 };
 
 /**
@@ -522,6 +579,23 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_RXTX_UNMAP SMC_FASTCALL_NR_SHARED_MEMORY(0x67)
 
+/**
+ * SMC_FC_FFA_PARTITION_INFO_GET - SMC opcode to get info about FF-A components
+ *
+ * Register arguments:
+ *
+ * w1:      Bytes[0..3] of UUID in little-endian.
+ * w2:      Bytes[4..7] of UUID in little-endian.
+ * w3:      Bytes[8..11] of UUID in little-endian.
+ * w4:      Bytes[12..15] of UUID in little-endian.
+ * w5:      bit[0]    : Information type flag. 1 for just the partition count
+ *                      with the UUID and 0 for the partition info descriptors.
+ *          bit[31:1] : SBZ
+ * w6-w7:   Reserved (SBZ).
+ *
+ */
+#define SMC_FC_FFA_PARTITION_INFO_GET SMC_FASTCALL_NR_SHARED_MEMORY(0x68)
+
 /**
  * SMC_FC_FFA_ID_GET - SMC opcode to get endpoint id of caller
  *
@@ -536,6 +610,20 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_MSG_WAIT SMC_FASTCALL_NR_SHARED_MEMORY(0x6B)
 
+/**
+ * SMC_FC_FFA_YIELD - SMC opcode to yield execution back to the component that
+ *                    scheduled it.
+ *
+ * Register arguments:
+ *
+ * * w1:     Endpoint ID in [31:16], vCPU in [15:0].
+ * * w2:     Lower 32-bits of timeout interval in nanoseconds after which vCPU
+ *           in w1 must run.
+ * * w3:     Upper 32-bits of timeout interval in nanoseconds after which vCPU
+ *           in w1 must run.
+ */
+#define SMC_FC_FFA_YIELD SMC_FASTCALL_NR_SHARED_MEMORY(0x6C)
+
 /**
  * SMC_FC_FFA_MSG_RUN - SMC opcode to allocate cycles to an endpoint
  *
@@ -609,6 +697,32 @@ enum ffa_error {
  */
 #define SMC_FC64_FFA_MSG_SEND_DIRECT_RESP SMC_FASTCALL64_NR_SHARED_MEMORY(0x70)
 
+/**
+ * SMC_FC64_FFA_MSG_SEND_DIRECT_REQ2 - 64 bit SMC opcode to send direct message
+ *                                     as a request
+ *
+ * Register arguments:
+ *
+ * * w1:     Sender ID in bit[31:16], receiver ID in [15:0]
+ * * x2:     Bytes[0..7] of UUID.
+ * * x3:     Bytes[8..15] of UUID.
+ * * x4-x17:  Implementation defined.
+ */
+#define SMC_FC64_FFA_MSG_SEND_DIRECT_REQ2 SMC_FASTCALL64_NR_SHARED_MEMORY(0x8D)
+
+/**
+ * SMC_FC64_FFA_MSG_SEND_DIRECT_RESP2 - 64 bit SMC opcode to send direct message
+ *                                     as a response
+ *
+ * Register arguments:
+ *
+ * * w1:     Sender ID in bit[31:16], receiver ID in [15:0]
+ * * w2:     Should be zero.
+ * * w3:     Should be zero.
+ * * x4-x17:  Implementation defined.
+ */
+#define SMC_FC64_FFA_MSG_SEND_DIRECT_RESP2 SMC_FASTCALL64_NR_SHARED_MEMORY(0x8E)
+
 /**
  * SMC_FC_FFA_MEM_DONATE - 32 bit SMC opcode to donate memory
  *
@@ -809,3 +923,95 @@ enum ffa_error {
  *           %FFA_ERROR_INVALID_PARAMETERS Invalid entry point specified
  */
 #define SMC_FC64_FFA_SECONDARY_EP_REGISTER SMC_FASTCALL64_NR_SHARED_MEMORY(0x87)
+
+/* Framework messages */
+/**
+ * FFA_FRAMEWORK_MSG_FLAG - Direct message flag for framework messages.
+ *
+ * Framework messages have &FFA_FRAMEWORK_MSG_FLAG set in w2.
+ */
+#define FFA_FRAMEWORK_MSG_FLAG (1U << 31)
+
+/**
+ * FFA_FRAMEWORK_MSG_MASK - Mask for the framework message type.
+ *
+ * Mask the value in w2 against &FFA_FRAMEWORK_MSG_MASK
+ * to get the framework message type.
+ */
+#define FFA_FRAMEWORK_MSG_MASK (0xffU)
+
+/**
+ * FFA_FRAMEWORK_MSG_VM_CREATED_REQ - VM creation request.
+ *
+ * Register arguments:
+ *
+ * * w0:     &SMC_FC_FFA_MSG_SEND_DIRECT_REQ
+ * * w1:     Hypervisor ID in bit[31:16], SP ID in [15:0]
+ * * w2:     Message Flags.
+ *           bit[31]   : 1 for framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : &FFA_FRAMEWORK_MSG_VM_CREATED_REQ
+ * * w3/w4:  Handle to identify a memory region.
+ * * w5:     ID of VM in [15:0], remaining SBZ.
+ * * w6-7:   Should be zero.
+ */
+#define FFA_FRAMEWORK_MSG_VM_CREATED_REQ 4
+
+/**
+ * FFA_FRAMEWORK_MSG_VM_CREATED_RESP - VM creation response.
+ *
+ * Register arguments:
+ *
+ * * w0:     &SMC_FC_FFA_MSG_SEND_DIRECT_RESP
+ * * w1:     SP ID in bit[31:16], hypervisor ID in [15:0]
+ * * w2:     Message Flags.
+ *           bit[31]   : 1 for framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : &FFA_FRAMEWORK_MSG_VM_CREATED_RESP
+ * * w3:     SP return status code:
+ *           %0 in case of success
+ *           %FFA_ERROR_INVALID_PARAMETERS
+ *           %FFA_ERROR_INTERRUPTED
+ *           %FFA_ERROR_DENIED
+ *           %FFA_ERROR_RETRY
+ * * w4-7:   Should be zero.
+ */
+#define FFA_FRAMEWORK_MSG_VM_CREATED_RESP 5
+
+/**
+ * FFA_FRAMEWORK_MSG_VM_DESTROYED_REQ - VM destruction request.
+ *
+ * Register arguments:
+ *
+ * * w0:     &SMC_FC_FFA_MSG_SEND_DIRECT_REQ
+ * * w1:     Hypervisor ID in bit[31:16], SP ID in [15:0]
+ * * w2:     Message Flags.
+ *           bit[31]   : 1 for framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : &FFA_FRAMEWORK_MSG_VM_DESTROYED_REQ
+ * * w3/w4:  Handle to identify a memory region.
+ * * w5:     ID of VM in [15:0], remaining SBZ.
+ * * w6-7:   Should be zero.
+ */
+#define FFA_FRAMEWORK_MSG_VM_DESTROYED_REQ 6
+
+/**
+ * FFA_FRAMEWORK_MSG_VM_DESTROYED_RESP - VM destruction response.
+ *
+ * Register arguments:
+ *
+ * * w0:     &SMC_FC_FFA_MSG_SEND_DIRECT_RESP
+ * * w1:     SP ID in bit[31:16], hypervisor ID in [15:0]
+ * * w2:     Message Flags.
+ *           bit[31]   : 1 for framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : &FFA_FRAMEWORK_MSG_VM_DESTROYED_RESP
+ * * w3:     SP return status code:
+ *           %0 in case of success
+ *           %FFA_ERROR_INVALID_PARAMETERS
+ *           %FFA_ERROR_INTERRUPTED
+ *           %FFA_ERROR_DENIED
+ *           %FFA_ERROR_RETRY
+ * * w4-7:   Should be zero.
+ */
+#define FFA_FRAMEWORK_MSG_VM_DESTROYED_RESP 7
diff --git a/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl b/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl
new file mode 100644
index 0000000..0523261
--- /dev/null
+++ b/interface/authmgr-handover/aidl/android/trusty/handover/ITrustedServicesHandover.aidl
@@ -0,0 +1,41 @@
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
+package android.trusty.handover;
+
+/**
+ * This interface should be implemented by all the trusted services that are available to be
+ * accessed by the remote clients.
+ * The AuthMgr BE accesses this interface to establish a connection between a remote client and the
+ * trusted service, so that the remote client and the trusted service can communicate independently
+ * from the AuthMgr, once the AuthMgr authorization protocol is successfully completed.
+ */
+interface ITrustedServicesHandover {
+    /**
+     * The AuthMgr BE invokes this method to handover an authorized connection to
+     * the trusted service. The AuthMgr authorization protocol defined in `IAuthMgrAuthorization`
+     * makes sure that the other end of the connection is handed over to the authorized remote
+     * client.
+     * In addition to the connection handle, the AuthMgr BE also conveys to the trusted service
+     * a unique client identifier.
+     *
+     * @param connectionHandle - a handle to the new connection that was setup out-of-band between
+     *                           the AuthMgr BE and the AuthMgr FE and authorized during phase 2 of
+     *                           the AuthMgr authorization protocol
+     * @param clientSeqNumber - the unique sequence number assigned to the client
+     */
+    void handoverConnection(in ParcelFileDescriptor connectionHandle, in int clientSeqNumber);
+}
diff --git a/interface/authmgr-handover/aidl/rules.mk b/interface/authmgr-handover/aidl/rules.mk
new file mode 100644
index 0000000..2d44923
--- /dev/null
+++ b/interface/authmgr-handover/aidl/rules.mk
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
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := authmgr_handover_aidl
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_AIDL_PACKAGE := android/trusty/handover
+
+MODULE_AIDLS := \
+    $(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/ITrustedServicesHandover.aidl \
+
+include make/aidl.mk
diff --git a/interface/authmgr/rust/rules.mk b/interface/authmgr/rust/rules.mk
new file mode 100644
index 0000000..7d3b68d
--- /dev/null
+++ b/interface/authmgr/rust/rules.mk
@@ -0,0 +1,42 @@
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
+AUTHMGR_BE_AIDL_DIR = hardware/interfaces/security/see/authmgr/aidl
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := android_hardware_security_see_authmgr
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_AIDL_PACKAGE := android/hardware/security/see/authmgr
+
+MODULE_AIDL_INCLUDES := \
+	-I $(AUTHMGR_BE_AIDL_DIR) \
+
+MODULE_AIDL_FLAGS := \
+    --stability=vintf \
+
+MODULE_AIDLS := \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DiceChainEntry.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DiceLeafArtifacts.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/DicePolicy.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/Error.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ExplicitKeyDiceCertChain.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IAuthMgrAuthorization.aidl \
+    $(AUTHMGR_BE_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/SignedConnectionRequest.aidl \
+
+include make/aidl.mk
\ No newline at end of file
diff --git a/interface/binder_accessor/rules.mk b/interface/binder_accessor/rules.mk
new file mode 100644
index 0000000..f6d0a44
--- /dev/null
+++ b/interface/binder_accessor/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+AIDL_DIR := $(LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_CRATE_NAME := trusty_binder_accessor
+
+MODULE_AIDL_PACKAGE := trusty/os
+
+MODULE_AIDLS := \
+	$(AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ITrustyAccessor.aidl \
+
+include make/aidl.mk
diff --git a/interface/binder_accessor/trusty/os/ITrustyAccessor.aidl b/interface/binder_accessor/trusty/os/ITrustyAccessor.aidl
new file mode 100644
index 0000000..f47e05f
--- /dev/null
+++ b/interface/binder_accessor/trusty/os/ITrustyAccessor.aidl
@@ -0,0 +1,84 @@
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
+package trusty.os;
+
+import android.os.ParcelFileDescriptor;
+
+/**
+ * Interface for accessing the RPC server of a service.
+ * This interface was originally copied from frameworks/native/libs/binder/aidl/android/os/IAccessor.aidl
+ * because it serves a similar function, but this interface is for use within trusty only
+ * and its use should never assume that the internal binder IAccessor interface is stable or compatible
+ * with this one.
+ *
+ * @hide
+ */
+interface ITrustyAccessor {
+    /**
+     * The connection info was not available for this service.
+     * This happens when the user-supplied callback fails to produce
+     * valid connection info.
+     * Depending on the implementation of the callback, it might be helpful
+     * to retry.
+     */
+    const int ERROR_CONNECTION_INFO_NOT_FOUND = 0;
+    /**
+     * Failed to create the socket. Often happens when the process trying to create
+     * the socket lacks the permissions to do so.
+     * This may be a temporary issue, so retrying the operation is OK.
+     */
+    const int ERROR_FAILED_TO_CREATE_SOCKET = 1;
+    /**
+     * Failed to connect to the socket. This can happen for many reasons, so be sure
+     * log the error message and check it.
+     * This may be a temporary issue, so retrying the operation is OK.
+     */
+    const int ERROR_FAILED_TO_CONNECT_TO_SOCKET = 2;
+    /**
+     * Failed to connect to the socket with EACCES because this process does not
+     * have perimssions to connect.
+     * There is no need to retry the connection as this access will not be granted
+     * upon retry.
+     */
+    const int ERROR_FAILED_TO_CONNECT_EACCES = 3;
+    /**
+     * Unsupported socket family type returned.
+     * There is no need to retry the connection as this socket family is not
+     * supported.
+     */
+    const int ERROR_UNSUPPORTED_SOCKET_FAMILY = 4;
+
+    /**
+     * Adds a connection to the RPC server of the service managed by the ITrustyAccessor.
+     *
+     * This method can be called multiple times to establish multiple distinct
+     * connections to the same RPC server.
+     *
+     * @throws ServiceSpecificError with message and one of the ITrustyAccessor::ERROR_ values.
+     *
+     * @return A file descriptor connected to the RPC session of the service managed
+     *         by ITrustyAccessor.
+     */
+    ParcelFileDescriptor addConnection();
+
+    /**
+     * Get the instance name for the service this accessor is responsible for.
+     *
+     * This is used to verify the proxy binder is associated with the expected instance name.
+     */
+    String getInstanceName();
+}
diff --git a/interface/storage/Android.bp b/interface/storage/Android.bp
new file mode 100644
index 0000000..14a3cd2
--- /dev/null
+++ b/interface/storage/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2025 The Android Open-Source Project
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_static {
+    name: "libtrustystorageinterface",
+    vendor_available: true,
+    system_ext_specific: true,
+    export_include_dirs: ["include"],
+}
diff --git a/interface/storage/include/interface/storage/storage.h b/interface/storage/include/interface/storage/storage.h
index 52c620f..2e86681 100644
--- a/interface/storage/include/interface/storage/storage.h
+++ b/interface/storage/include/interface/storage/storage.h
@@ -194,23 +194,25 @@ enum storage_file_list_flag {
 /**
  * enum storage_msg_flag - protocol-level flags in struct storage_msg
  * @STORAGE_MSG_FLAG_BATCH:                 if set, command belongs to a batch
- *                                          transaction. No response will be sent by
- *                                          the server until it receives a command
- *                                          with this flag unset, at which point a
- *                                          cumulative result for all messages sent
- *                                          with STORAGE_MSG_FLAG_BATCH will be
- *                                          sent. This is only supported by the
+ *                                          transaction. No response will be
+ *                                          sent by the server until it receives
+ *                                          a command with this flag unset, at
+ *                                          which point a cumulative result for
+ *                                          all messages sent with
+ *                                          STORAGE_MSG_FLAG_BATCH will be sent.
+ *                                          This is only supported by the
  *                                          non-secure disk proxy server.
- * @STORAGE_MSG_FLAG_PRE_COMMIT:            if set, indicates that server need to
- *                                          commit pending changes before processing
- *                                          this message.
- * @STORAGE_MSG_FLAG_POST_COMMIT:           if set, indicates that server need to
- *                                          commit pending changes after processing
- *                                          this message.
- * @STORAGE_MSG_FLAG_TRANSACT_COMPLETE:     if set, indicates that server need to
- *                                          commit current transaction after
- *                                          processing this message. It is an alias
- *                                          for STORAGE_MSG_FLAG_POST_COMMIT.
+ * @STORAGE_MSG_FLAG_PRE_COMMIT:            if set, indicates that server need
+ *                                          to commit pending changes before
+ *                                          processing this message.
+ * @STORAGE_MSG_FLAG_POST_COMMIT:           if set, indicates that server need
+ *                                          to commit pending changes after
+ *                                          processing this message.
+ * @STORAGE_MSG_FLAG_TRANSACT_COMPLETE:     if set, indicates that server need
+ *                                          to commit current transaction after
+ *                                          processing this message. It is an
+ *                                          alias for
+ *                                          STORAGE_MSG_FLAG_POST_COMMIT.
  * @STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT: if set, indicates that server needs
  *                                          to ensure that there is not a
  *                                          pending checkpoint for the
diff --git a/lib/authgraph-rust/tests/rules.mk b/lib/authgraph-rust/tests/rules.mk
new file mode 100644
index 0000000..3f91cb6
--- /dev/null
+++ b/lib/authgraph-rust/tests/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := system/authgraph/tests/src/lib.rs
+
+MODULE_CRATE_NAME := authgraph_core_test
+
+MODULE_LIBRARY_DEPS += \
+	packages/modules/Virtualization/libs/dice/open_dice \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authgraph-rust/wire \
+	$(call FIND_CRATE,hex) \
+	$(call FIND_CRATE,coset) \
+
+include make/library.mk
\ No newline at end of file
diff --git a/lib/authmgr-be-impl-rust/rules.mk b/lib/authmgr-be-impl-rust/rules.mk
new file mode 100644
index 0000000..a02ca48
--- /dev/null
+++ b/lib/authmgr-be-impl-rust/rules.mk
@@ -0,0 +1,30 @@
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
+MODULE_SRCS := system/see/authmgr/authmgr-be-impl/src/lib.rs
+
+MODULE_CRATE_NAME := authmgr_be_impl
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authmgr-be-rust \
+	$(call FIND_CRATE,log) \
+
+include make/library.mk
diff --git a/lib/authmgr-be-rust/rules.mk b/lib/authmgr-be-rust/rules.mk
new file mode 100644
index 0000000..67235c1
--- /dev/null
+++ b/lib/authmgr-be-rust/rules.mk
@@ -0,0 +1,30 @@
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
+MODULE_SRCS := system/see/authmgr/authmgr-be/src/lib.rs
+
+MODULE_CRATE_NAME := authmgr_be
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authmgr-common-rust \
+	$(call FIND_CRATE,coset) \
+	$(call FIND_CRATE,log) \
+
+include make/library.mk
diff --git a/lib/authmgr-common-rust/rules.mk b/lib/authmgr-common-rust/rules.mk
new file mode 100644
index 0000000..11c7593
--- /dev/null
+++ b/lib/authmgr-common-rust/rules.mk
@@ -0,0 +1,33 @@
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
+MODULE_SRCS := system/see/authmgr/authmgr-common/src/lib.rs
+
+MODULE_CRATE_NAME := authmgr_common
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/secretkeeper/dice_policy \
+	trusty/user/base/lib/secretkeeper/dice-policy-builder \
+	$(call FIND_CRATE,coset) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,num-derive) \
+	$(call FIND_CRATE,num-traits) \
+
+include make/library.mk
diff --git a/lib/authmgr-common-util-rust/rules.mk b/lib/authmgr-common-util-rust/rules.mk
new file mode 100644
index 0000000..01e4823
--- /dev/null
+++ b/lib/authmgr-common-util-rust/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := system/see/authmgr/authmgr-common/util/src/lib.rs
+
+MODULE_CRATE_NAME := authmgr_common_util
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authmgr-common-rust \
+	trusty/user/base/lib/secretkeeper/dice_policy \
+	trusty/user/base/lib/secretkeeper/dice-policy-builder \
+	$(call FIND_CRATE,log) \
+
+include make/library.mk
diff --git a/lib/hwbcc/common/swbcc.c b/lib/hwbcc/common/swbcc.c
index e7af267..579e611 100644
--- a/lib/hwbcc/common/swbcc.c
+++ b/lib/hwbcc/common/swbcc.c
@@ -232,16 +232,16 @@ int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
      * the DICE artifacts to the clients.
      */
     if (is_zero_uuid(session->client_uuid)) {
-        *s = (swbcc_session_t)session;
-
         /**
          * Stop serving calls from non-secure world after receiving
          * `ns_deprivilege` call.
          */
         if (srv_state.ns_deprivileged) {
+            free(session);
             return ERR_NOT_ALLOWED;
         }
 
+        *s = (swbcc_session_t)session;
         return NO_ERROR;
     }
 
@@ -263,7 +263,7 @@ int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
         TLOGE("Failed to generate keypair: %d\n", rc);
-        return rc;
+        goto err;
     }
 
     /* Init test keys */
@@ -279,7 +279,7 @@ int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
     rc = dice_result_to_err(result);
     if (rc != NO_ERROR) {
         TLOGE("Failed to generate test keypair: %d\n", rc);
-        return rc;
+        goto err;
     }
 
     *s = (swbcc_session_t)session;
diff --git a/lib/hwbcc/rust/rules.mk b/lib/hwbcc/rust/rules.mk
index 6639746..a5178e2 100644
--- a/lib/hwbcc/rust/rules.mk
+++ b/lib/hwbcc/rust/rules.mk
@@ -28,9 +28,14 @@ MODULE_LIBRARY_DEPS += \
 	external/boringssl \
 	$(LIBCPPBOR_DIR) \
 	external/open-dice \
+	packages/modules/Virtualization/libs/dice/open_dice \
 	trusty/user/base/interface/hwbcc \
 	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,coset) \
 	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy) \
+	$(call FIND_CRATE,num-derive) \
+	$(call FIND_CRATE,num-traits) \
 	trusty/user/base/lib/tipc/rust \
 	trusty/user/base/lib/system_state/rust \
 	trusty/user/base/lib/hwbcc/common \
@@ -38,6 +43,8 @@ MODULE_LIBRARY_DEPS += \
 MODULE_BINDGEN_ALLOW_TYPES := \
 	hwbcc.* \
 
+
+
 MODULE_BINDGEN_ALLOW_VARS := \
 	HWBCC.* \
 	DICE.* \
@@ -48,6 +55,7 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 
 MODULE_BINDGEN_FLAGS := \
 	--use-array-pointers-in-arguments \
+	--with-derive-custom-struct=hwbcc.*=zerocopy::IntoBytes,zerocopy::FromBytes \
 
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
diff --git a/lib/hwbcc/rust/src/err.rs b/lib/hwbcc/rust/src/err.rs
index 18700bb..0102421 100644
--- a/lib/hwbcc/rust/src/err.rs
+++ b/lib/hwbcc/rust/src/err.rs
@@ -14,12 +14,14 @@
  * limitations under the License.
  */
 
+use alloc::collections::TryReserveError;
 use core::num::TryFromIntError;
+use diced_open_dice::DiceError;
 use tipc::TipcError;
 use trusty_std::alloc::AllocError;
 use trusty_sys::Error;
 
-#[derive(Debug)]
+#[derive(Debug, PartialEq)]
 pub enum HwBccError {
     NotAllowed,
     BadLen,
@@ -54,3 +56,24 @@ impl From<AllocError> for HwBccError {
         HwBccError::AllocError
     }
 }
+
+impl From<TryReserveError> for HwBccError {
+    fn from(_err: TryReserveError) -> Self {
+        HwBccError::AllocError
+    }
+}
+
+impl From<DiceError> for HwBccError {
+    fn from(dice_error: DiceError) -> Self {
+        match dice_error {
+            DiceError::InvalidInput => HwBccError::System(trusty_sys::Error::InvalidArgs),
+            DiceError::BufferTooSmall(_) => HwBccError::System(trusty_sys::Error::NotEnoughBuffer),
+            DiceError::PlatformError => HwBccError::System(trusty_sys::Error::Generic),
+            DiceError::UnsupportedKeyAlgorithm(_) => {
+                HwBccError::System(trusty_sys::Error::NotSupported)
+            }
+            DiceError::MemoryAllocationError => HwBccError::System(trusty_sys::Error::NoMemory),
+            DiceError::DiceChainNotFound => HwBccError::System(trusty_sys::Error::InvalidArgs),
+        }
+    }
+}
diff --git a/lib/hwbcc/rust/src/lib.rs b/lib/hwbcc/rust/src/lib.rs
index 88f4778..b69aebf 100644
--- a/lib/hwbcc/rust/src/lib.rs
+++ b/lib/hwbcc/rust/src/lib.rs
@@ -26,8 +26,11 @@
 
 #[cfg(test)]
 mod test;
+#[cfg(test)]
+mod test_serializer;
 
 mod err;
+pub mod srv;
 
 #[allow(non_upper_case_globals)]
 #[allow(non_camel_case_types)]
@@ -42,16 +45,19 @@ pub use err::HwBccError;
 
 use core::ffi::CStr;
 use core::mem;
+use coset::iana;
+use num_derive::FromPrimitive;
 use sys::*;
 use tipc::Serializer;
 use tipc::{Deserialize, Handle, Serialize};
 use trusty_std::alloc::{TryAllocFrom, Vec};
 use trusty_sys::{c_long, Error};
+use zerocopy::IntoBytes;
 
 // Constant defined in trusty/user/base/interface/hwbcc/include/interface/hwbcc
 pub const HWBCC_MAX_RESP_PAYLOAD_LENGTH: usize = HWBCC_MAX_RESP_PAYLOAD_SIZE as usize;
 
-#[derive(Copy, Clone)]
+#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
 #[repr(u32)]
 enum BccCmd {
     RespBit = hwbcc_cmd_HWBCC_CMD_RESP_BIT,
@@ -72,12 +78,46 @@ impl BccCmd {
     }
 }
 /// Generic header for all hwbcc requests.
+#[derive(Debug, PartialEq)]
 struct BccMsgHeader {
     cmd: BccCmd,
     test_mode: HwBccMode,
     context: u64,
 }
 
+/// The request message for the hwbcc service.
+/// Note that the Serialize trait implementation ensures compatibility with
+/// C clients and servers. We do not depend on the representation of this
+/// struct for that compatibility.
+#[derive(Debug, PartialEq)]
+struct BccMsg<'a> {
+    header: BccMsgHeader,
+    sign_req: Option<SignDataMsg<'a>>,
+}
+
+impl<'a> BccMsg<'a> {
+    fn new(cmd: BccCmd, test_mode: HwBccMode, context: u64) -> Self {
+        Self { header: BccMsgHeader { cmd, test_mode, context }, sign_req: None }
+    }
+
+    fn add_signing_req(&mut self, algorithm: SigningAlgorithm, data: &'a [u8], aad: &'a [u8]) {
+        self.sign_req = Some(SignDataMsg::new(algorithm, data, aad));
+    }
+}
+
+impl<'s> Serialize<'s> for BccMsg<'s> {
+    fn serialize<'a: 's, S: Serializer<'s>>(
+        &'a self,
+        serializer: &mut S,
+    ) -> Result<S::Ok, S::Error> {
+        let ok = self.header.serialize(serializer)?;
+        if let Some(sign_req) = &self.sign_req {
+            return sign_req.serialize(serializer);
+        }
+        Ok(ok)
+    }
+}
+
 impl<'s> Serialize<'s> for BccMsgHeader {
     fn serialize<'a: 's, S: Serializer<'s>>(
         &'a self,
@@ -95,8 +135,8 @@ impl<'s> Serialize<'s> for BccMsgHeader {
 }
 
 /// Request to sign data.
+#[derive(Debug, PartialEq)]
 struct SignDataMsg<'a> {
-    header: BccMsgHeader,
     /// Contains signing algorithm, data size, aad size
     algorithm: SigningAlgorithm,
     data: &'a [u8],
@@ -108,20 +148,8 @@ struct SignDataMsg<'a> {
 }
 
 impl<'a> SignDataMsg<'a> {
-    fn new(
-        header: BccMsgHeader,
-        algorithm: SigningAlgorithm,
-        data: &'a [u8],
-        aad: &'a [u8],
-    ) -> Self {
-        Self {
-            header,
-            algorithm,
-            data,
-            data_size: data.len() as u16,
-            aad,
-            aad_size: aad.len() as u32,
-        }
+    fn new(algorithm: SigningAlgorithm, data: &'a [u8], aad: &'a [u8]) -> Self {
+        Self { algorithm, data, data_size: data.len() as u16, aad, aad_size: aad.len() as u32 }
     }
 }
 
@@ -130,7 +158,6 @@ impl<'s> Serialize<'s> for SignDataMsg<'s> {
         &'a self,
         serializer: &mut S,
     ) -> Result<S::Ok, S::Error> {
-        self.header.serialize(serializer)?;
         // SAFETY:
         //  All serialized attributes are trivial types with
         //  corresponding C representations
@@ -145,15 +172,66 @@ impl<'s> Serialize<'s> for SignDataMsg<'s> {
 }
 
 /// Response type for all hwbcc services.
+#[derive(Debug, PartialEq)]
 struct HwBccResponse {
     /// Status of command result.
     status: i32,
     /// Sent command, acknowledged by service if successful.
     cmd: u32,
+    /// The payload size in bytes. We store this separately because
+    /// to serialize a response we need a size guaranteed to live as
+    /// long as the input serializer and calling payload.len() won't
+    /// satisfy that constraint. There are no current use cases where
+    /// payload is mutable. If they arise, this field needs to be kept
+    /// in sync with the length of the payload.
+    payload_size: u32,
     /// Response data.
     payload: Vec<u8>,
 }
 
+impl HwBccResponse {
+    fn try_new_with_payload(
+        status: Error,
+        cmd: BccCmd,
+        payload: Vec<u8>,
+    ) -> Result<Self, HwBccError> {
+        if payload.len() > HWBCC_MAX_RESP_PAYLOAD_LENGTH {
+            return Err(HwBccError::BadLen);
+        }
+
+        Ok(HwBccResponse {
+            status: status as i32,
+            cmd: hwbcc_cmd_HWBCC_CMD_RESP_BIT | cmd as u32,
+            payload_size: payload.len().try_into()?,
+            payload: payload,
+        })
+    }
+
+    fn new_without_payload(status: Error, cmd: BccCmd) -> HwBccResponse {
+        HwBccResponse {
+            status: status as i32,
+            cmd: hwbcc_cmd_HWBCC_CMD_RESP_BIT | cmd as u32,
+            payload_size: 0,
+            payload: Vec::new(),
+        }
+    }
+}
+
+impl<'s> Serialize<'s> for HwBccResponse {
+    /// We serialize for compatibility
+    /// with hwbcc_resp_hdr as defined in hwbcc.h
+    fn serialize<'a: 's, S: Serializer<'s>>(
+        &'a self,
+        serializer: &mut S,
+    ) -> Result<S::Ok, S::Error> {
+        serializer.serialize_bytes(self.cmd.as_bytes())?;
+        serializer.serialize_bytes(self.status.as_bytes())?;
+        serializer.serialize_bytes(self.payload_size.as_bytes())?;
+
+        serializer.serialize_bytes(&self.payload)
+    }
+}
+
 impl Deserialize for HwBccResponse {
     type Error = HwBccError;
     const MAX_SERIALIZED_SIZE: usize = HWBCC_MAX_RESP_PAYLOAD_LENGTH;
@@ -189,7 +267,12 @@ impl Deserialize for HwBccResponse {
             return Err(HwBccError::BadLen);
         }
 
-        Ok(Self { status: msg.status, cmd: msg.cmd, payload: response_payload })
+        Ok(Self {
+            status: msg.status,
+            cmd: msg.cmd,
+            payload_size: msg.payload_size,
+            payload: response_payload,
+        })
     }
 }
 
@@ -199,7 +282,7 @@ impl Deserialize for HwBccResponse {
 /// and should differ with each invocation, intra-test.
 /// `Release` mode relies on the hwkey service to derive
 /// its key seed.
-#[derive(Copy, Clone, Debug)]
+#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
 #[repr(u32)]
 pub enum HwBccMode {
     Release = 0,
@@ -210,12 +293,20 @@ pub enum HwBccMode {
 ///
 /// Project uses CBOR Object Signing and Encryption (COSE) encodings.
 #[non_exhaustive]
-#[derive(Copy, Clone, Debug)]
+#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
 #[repr(i16)]
 pub enum SigningAlgorithm {
     ED25519 = hwbcc_algorithm_HWBCC_ALGORITHM_ED25519 as i16,
 }
 
+impl From<SigningAlgorithm> for iana::Algorithm {
+    fn from(alg: SigningAlgorithm) -> Self {
+        match alg {
+            SigningAlgorithm::ED25519 => iana::Algorithm::EdDSA,
+        }
+    }
+}
+
 fn recv_resp(session: &Handle, cmd: BccCmd, buf: &mut [u8]) -> Result<HwBccResponse, HwBccError> {
     let response: HwBccResponse = session.recv(buf)?;
 
@@ -278,7 +369,7 @@ pub fn get_dice_artifacts<'a>(
     let session = Handle::connect(port)?;
 
     let cmd = BccCmd::GetDiceArtifacts;
-    session.send(&BccMsgHeader { cmd, test_mode: HwBccMode::Release, context })?;
+    session.send(&BccMsg::new(cmd, HwBccMode::Release, context))?;
 
     let res_buf = &mut [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
     let response = recv_resp(&session, cmd, res_buf)?;
@@ -309,7 +400,7 @@ pub fn ns_deprivilege() -> Result<(), HwBccError> {
     let session = Handle::connect(port)?;
 
     let cmd = BccCmd::NsDeprivilege;
-    session.send(&BccMsgHeader { cmd, test_mode: HwBccMode::Release, context: 0 })?;
+    session.send(&BccMsg::new(cmd, HwBccMode::Release, 0))?;
 
     let res_buf = &mut [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
     recv_resp(&session, cmd, res_buf)?;
@@ -341,7 +432,7 @@ pub fn get_bcc<'a>(test_mode: HwBccMode, bcc: &'a mut [u8]) -> Result<&'a [u8],
     let session = Handle::connect(port)?;
 
     let cmd = BccCmd::GetBcc;
-    session.send(&BccMsgHeader { cmd, test_mode, context: 0 })?;
+    session.send(&BccMsg::new(cmd, test_mode, 0))?;
 
     let res_buf = &mut [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
     let response = recv_resp(&session, cmd, res_buf)?;
@@ -388,8 +479,9 @@ pub fn sign_data<'a>(
     let session = Handle::connect(port)?;
 
     let cmd = BccCmd::SignData;
-    let req =
-        SignDataMsg::new(BccMsgHeader { cmd, test_mode, context: 0 }, cose_algorithm, data, aad);
+    let mut req = BccMsg::new(cmd, test_mode, 0);
+    req.add_signing_req(cose_algorithm, data, aad);
+
     session.send(&req)?;
 
     let res_buf = &mut [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
@@ -398,3 +490,29 @@ pub fn sign_data<'a>(
 
     Ok(cose_sign1)
 }
+
+#[cfg(test)]
+mod tests {
+    use crate::test_serializer::TestSerializer;
+    use crate::{BccCmd, HwBccResponse};
+    use test::expect_eq;
+    use tipc::{Deserialize, Serialize};
+
+    #[test]
+    fn test_hwbcc_resp_serde() {
+        let test_payload = "i am an expected response payload".as_bytes();
+
+        let mut serializer = TestSerializer::default();
+        let hwbcc_resp =
+            HwBccResponse::try_new_with_payload(0.into(), BccCmd::GetBcc, test_payload.to_vec())
+                .expect("Failed to create HwBccResponse for test");
+        let _ =
+            hwbcc_resp.serialize(&mut serializer).expect("serialization of HwBccResponse failed");
+
+        let deserialized =
+            HwBccResponse::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized, hwbcc_resp);
+    }
+}
diff --git a/lib/hwbcc/rust/src/srv.rs b/lib/hwbcc/rust/src/srv.rs
new file mode 100644
index 0000000..70c80b0
--- /dev/null
+++ b/lib/hwbcc/rust/src/srv.rs
@@ -0,0 +1,336 @@
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
+//! Service library for implementing hwbcc servers in Rust
+
+use crate::{
+    hwbcc_req_hdr, hwbcc_req_sign_data, BccCmd, BccMsg, HwBccError, HwBccMode, HwBccResponse,
+    SigningAlgorithm, HWBCC_MAX_AAD_SIZE, HWBCC_MAX_DATA_TO_SIGN_SIZE,
+};
+use alloc::rc::Rc;
+use core::mem::size_of;
+use num_traits::FromPrimitive;
+use tipc::{ConnectResult, Deserialize, Handle, MessageResult, PortCfg, Service, TipcError, Uuid};
+use trusty_std::alloc::TryAllocFrom;
+use trusty_sys::Error;
+use zerocopy::FromBytes;
+
+const HWBCC_MAX_MESSAGE_SIZE: usize = size_of::<hwbcc_req_hdr>()
+    + size_of::<hwbcc_req_sign_data>()
+    + HWBCC_MAX_AAD_SIZE as usize
+    + HWBCC_MAX_DATA_TO_SIGN_SIZE as usize;
+
+pub struct RequestContext {
+    pub peer: Uuid,
+}
+
+/// A raw buffer that holds a serialized `BccMsg` and allows
+/// for extraction of a `BccMsg` after deserialization.
+///
+/// Deserialization itself performs no validation and only
+/// copies the input buffer into the `RawBccMsgBuffer`. All
+/// validation occurs when calling `to_req_msg`.
+///
+/// This approach is needed because `BccMsg` is implemented
+/// to support serializing from borrowed data in the client.
+/// As such, it specifies an explicit lifetime, which is not
+/// supported by the `Message` type of the `Service` trait.
+pub struct RawBccMsgBuffer(Vec<u8>);
+
+impl RawBccMsgBuffer {
+    #[allow(dead_code)]
+    fn to_req_msg(&self) -> Result<BccMsg<'_>, HwBccError> {
+        let msg_buffer = &self.0;
+
+        match hwbcc_req_hdr::read_from_prefix(msg_buffer) {
+            Ok((header, sign_data_msg)) => {
+                let mut req_msg = BccMsg::new(
+                    BccCmd::from_u32(header.cmd).ok_or_else(|| HwBccError::TryFromIntError)?,
+                    HwBccMode::from_u32(header.test_mode)
+                        .ok_or_else(|| HwBccError::TryFromIntError)?,
+                    header.context,
+                );
+
+                if sign_data_msg.len() > 0 {
+                    let _ = deserialize_signing_msg(&sign_data_msg, &mut req_msg)?;
+                }
+
+                Ok(req_msg)
+            }
+            Err(_) => {
+                log::error!("hwbcc request too small. Smaller than required header.");
+                return Err(HwBccError::BadLen);
+            }
+        }
+    }
+}
+
+impl Deserialize for RawBccMsgBuffer {
+    type Error = TipcError;
+    const MAX_SERIALIZED_SIZE: usize = HWBCC_MAX_MESSAGE_SIZE;
+
+    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
+        Ok(RawBccMsgBuffer(Vec::try_alloc_from(bytes)?))
+    }
+}
+
+fn deserialize_signing_msg<'a>(
+    sign_data_bytes: &'a [u8],
+    msg: &mut BccMsg<'a>,
+) -> Result<(), HwBccError> {
+    match hwbcc_req_sign_data::read_from_prefix(sign_data_bytes) {
+        Ok((sign_header, rest)) => {
+            let algorithm = SigningAlgorithm::from_i16(sign_header.algorithm)
+                .ok_or_else(|| HwBccError::TryFromIntError)?;
+
+            if sign_header.aad_size > HWBCC_MAX_AAD_SIZE {
+                log::error!(
+                    "Failed to deserialize. aad size {} is greater than max of {}",
+                    sign_header.aad_size,
+                    HWBCC_MAX_AAD_SIZE
+                );
+                return Err(HwBccError::BadLen);
+            }
+
+            if sign_header.data_size as u32 > HWBCC_MAX_DATA_TO_SIGN_SIZE {
+                log::error!(
+                    "Failed to deserialize. data size {} is greater than max of {}",
+                    sign_header.aad_size,
+                    HWBCC_MAX_AAD_SIZE
+                );
+                return Err(HwBccError::BadLen);
+            }
+
+            // hwbcc defines sizes with different data types, and at the end of the
+            // day we need these as usize so we can use them to index into the remaining
+            // data. `data_size` is u16 so it infallibly converts. `aad_size` is unfortunately
+            // u32, but hwbcc defines `MAX_AAD_SIZE` as 512 bytes, which should always fit in
+            // rust's usize.
+            let data_size: usize = sign_header.data_size.into();
+            let aad_size: usize = sign_header.aad_size.try_into()?;
+
+            let required_rest_len = data_size + aad_size;
+
+            if rest.len() < required_rest_len {
+                log::error!("hwbcc_req_sign_data header sizes are larger than the provided buffer");
+                return Err(HwBccError::BadLen);
+            }
+
+            // We've checked above to ensure that these indices are not out of range.
+            // In the event that a larger buffer was sent than the configured sizes, this
+            // truncates to the sizes provided in the header.
+            let _ = msg.add_signing_req(
+                algorithm,
+                &rest[..data_size],
+                &rest[data_size..required_rest_len],
+            );
+
+            Ok(())
+        }
+        Err(_) => {
+            log::error!("hwbcc_req_sign_data request too small.");
+            Err(HwBccError::BadLen)
+        }
+    }
+}
+
+pub struct HwBccService {
+    ops: Rc<dyn HwBccOps>,
+}
+
+impl HwBccService {
+    pub fn new(ops: Rc<dyn HwBccOps>) -> Self {
+        Self { ops }
+    }
+}
+
+pub trait HwBccOps {
+    fn init(&self, session: &RequestContext) -> Result<(), HwBccError>;
+    fn close(&self, session: &RequestContext);
+    fn get_bcc(&self, session: &RequestContext, mode: HwBccMode) -> Result<Vec<u8>, HwBccError>;
+    fn sign_data<'a>(
+        &self,
+        session: &RequestContext,
+        data: &'a [u8],
+        aad: &'a [u8],
+        mode: HwBccMode,
+    ) -> Result<Vec<u8>, HwBccError>;
+}
+
+impl Service for HwBccService {
+    type Connection = RequestContext;
+    type Message = RawBccMsgBuffer;
+    fn on_connect(
+        &self,
+        _: &PortCfg,
+        _: &Handle,
+        peer: &Uuid,
+    ) -> Result<ConnectResult<<Self as Service>::Connection>, TipcError> {
+        log::debug!("Accepted connection from uuid {:?}.", peer);
+        let session = RequestContext { peer: peer.clone() };
+        match self.ops.init(&session) {
+            Ok(_) => Ok(ConnectResult::Accept(session)),
+            Err(e) => {
+                log::error!("Failed HwBccOps.init: {:?}", e);
+                Err(TipcError::UnknownError)
+            }
+        }
+    }
+
+    fn on_message(
+        &self,
+        connection: &<Self as Service>::Connection,
+        handle: &Handle,
+        message: RawBccMsgBuffer,
+    ) -> Result<MessageResult, TipcError> {
+        let bcc_msg = match message.to_req_msg() {
+            Ok(m) => m,
+            Err(_) => {
+                log::error!("Failed to deserialize request");
+                return Err(TipcError::InvalidData);
+            }
+        };
+
+        let header = &bcc_msg.header;
+
+        let response = match header.cmd {
+            BccCmd::GetBcc => {
+                payload_to_response(BccCmd::GetBcc, self.ops.get_bcc(connection, header.test_mode))?
+            }
+            BccCmd::SignData => {
+                if let Some(sign_req) = bcc_msg.sign_req {
+                    // Note that we ignore sign_req.algorithm because we always sign
+                    // with an algorithm derived from the leaf dice cert subject public key.
+                    // This makes external configuration impossible.
+                    payload_to_response(
+                        BccCmd::SignData,
+                        self.ops.sign_data(
+                            connection,
+                            sign_req.data,
+                            sign_req.aad,
+                            header.test_mode,
+                        ),
+                    )?
+                } else {
+                    HwBccResponse::new_without_payload(Error::InvalidArgs, BccCmd::SignData)
+                }
+            }
+            _ => HwBccResponse::new_without_payload(Error::NotSupported, header.cmd),
+        };
+
+        handle.send(&response)?;
+
+        Ok(MessageResult::MaintainConnection)
+    }
+
+    fn on_disconnect(&self, connection: &Self::Connection) {
+        self.ops.close(connection);
+    }
+}
+
+fn payload_to_response(
+    cmd: BccCmd,
+    payload: Result<Vec<u8>, HwBccError>,
+) -> Result<HwBccResponse, TipcError> {
+    match payload {
+        Ok(p) => HwBccResponse::try_new_with_payload(Error::NoError, cmd, p).map_err(|e| {
+            log::error!("Failed to create HwBccResponse from payload. Error: {:?}", e);
+            TipcError::InvalidData
+        }),
+        Err(_) => Ok(HwBccResponse::new_without_payload(Error::Generic, cmd)),
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::test_serializer::TestSerializer;
+    use test::expect_eq;
+    use tipc::Serialize;
+
+    #[test]
+    fn deserialize_header_only() {
+        let mut serializer = TestSerializer::default();
+        let msg = BccMsg::new(BccCmd::GetBcc, HwBccMode::Test, 5);
+        let _ = msg.serialize(&mut serializer).expect("serialization of BccMsg failed");
+
+        let deserialized =
+            &RawBccMsgBuffer::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized.to_req_msg().expect("failed to get deserialized BccMsg"), msg);
+    }
+
+    #[test]
+    fn deserialize_with_sign_data() {
+        let mut serializer = TestSerializer::default();
+        let mut msg = BccMsg::new(BccCmd::GetBcc, HwBccMode::Test, 5);
+        let data = vec![0xBB, 0xBB, 0xBB];
+        let aad = vec![0xCC, 0xCC, 0xCC];
+        msg.add_signing_req(SigningAlgorithm::ED25519, &data, &aad);
+        let _ = msg.serialize(&mut serializer).expect("serialization of BccMsg failed");
+
+        let deserialized =
+            &RawBccMsgBuffer::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized.to_req_msg().expect("failed to get deserialized BccMsg"), msg);
+    }
+
+    #[test]
+    fn deserialize_fail_if_main_header_too_small() {
+        let mut serializer = TestSerializer::default();
+        serializer.buffers.resize(size_of::<hwbcc_req_hdr>() - 1, 0xAA);
+        let deserialized =
+            &RawBccMsgBuffer::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized.to_req_msg().err(), Some(HwBccError::BadLen));
+    }
+
+    #[test]
+    fn deserialize_fail_if_sign_header_too_small() {
+        let mut serializer = TestSerializer::default();
+        let msg = BccMsg::new(BccCmd::GetBcc, HwBccMode::Test, 5);
+        let _ = msg.serialize(&mut serializer).expect("serialization of BccMsg failed");
+
+        // The signing header is encoded directly after the main header so this results in
+        // a signing header of length 1.
+        serializer.buffers.push(0xAA);
+        let deserialized =
+            &RawBccMsgBuffer::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized.to_req_msg().err(), Some(HwBccError::BadLen));
+    }
+
+    #[test]
+    fn deserialize_with_sign_req_should_truncate_buffer() {
+        let mut serializer = TestSerializer::default();
+        let mut msg = BccMsg::new(BccCmd::GetBcc, HwBccMode::Test, 5);
+        msg.add_signing_req(SigningAlgorithm::ED25519, b"signing data", b"aad data");
+        let _ = msg.serialize(&mut serializer).expect("serialization of BccMsg failed");
+
+        // The end of a message is the AAD data. We're adding erroneous data on the end here
+        // and ensuring that when deserializing, it's ignored.
+        serializer.buffers.push(0xAA);
+        let deserialized =
+            &RawBccMsgBuffer::deserialize(&mut serializer.buffers, &mut serializer.handles)
+                .expect("deserialization failed");
+
+        expect_eq!(deserialized.to_req_msg().expect("failed to get deserialized BccMsg"), msg);
+    }
+}
diff --git a/lib/hwbcc/rust/src/test_serializer.rs b/lib/hwbcc/rust/src/test_serializer.rs
new file mode 100644
index 0000000..23c5abb
--- /dev/null
+++ b/lib/hwbcc/rust/src/test_serializer.rs
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
+use tipc::{Handle, Serializer};
+
+#[derive(Debug)]
+pub struct TestSerializationError;
+
+/// A simple serializer that copies input data and allocates.
+/// Not suitable for production.
+#[derive(Default)]
+pub struct TestSerializer {
+    pub buffers: Vec<u8>,
+    pub handles: Vec<Option<Handle>>,
+}
+
+impl<'a> Serializer<'a> for TestSerializer {
+    type Ok = ();
+    type Error = TestSerializationError;
+
+    fn serialize_bytes(&mut self, bytes: &'a [u8]) -> Result<(), TestSerializationError> {
+        self.buffers.extend_from_slice(bytes);
+        Ok(())
+    }
+
+    fn serialize_handle(&mut self, handle: &'a Handle) -> Result<(), TestSerializationError> {
+        let h = handle.try_clone().or(Err(TestSerializationError))?;
+        self.handles.push(Some(h));
+        Ok(())
+    }
+}
diff --git a/lib/hwbcc/srv/srv.c b/lib/hwbcc/srv/srv.c
index b913067..0aa79e4 100644
--- a/lib/hwbcc/srv/srv.c
+++ b/lib/hwbcc/srv/srv.c
@@ -75,12 +75,20 @@ static const struct uuid widevine_uuid = {
         {0xa9, 0x1d, 0x75, 0xf1, 0x98, 0x9c, 0x57, 0xef},
 };
 
+/* UUID: {19c7289c-5004-4a30-b85a-2a22a76e6327} */
+static const struct uuid widevine_vm_uuid = {
+        0x19c7289c,
+        0x5004,
+        0x4a30,
+        {0xb8, 0x5a, 0x2a, 0x22, 0xa7, 0x6e, 0x63, 0x27},
+};
+
 /* ZERO UUID to allow connections from non-secure world */
 static const struct uuid zero_uuid = UUID_INITIAL_VALUE(zero_uuid);
 
 static const struct uuid* allowed_uuids[] = {
-        &km_uuid,       &hwbcc_test_uuid, &hwbcc_rust_test_uuid,
-        &widevine_uuid, &zero_uuid,
+        &km_uuid,       &hwbcc_test_uuid,  &hwbcc_rust_test_uuid,
+        &widevine_uuid, &widevine_vm_uuid, &zero_uuid,
 };
 
 static struct tipc_port_acl acl = {
diff --git a/lib/liballoc-rust/rules.mk b/lib/liballoc-rust/rules.mk
index 14f1b73..67cc4a0 100644
--- a/lib/liballoc-rust/rules.mk
+++ b/lib/liballoc-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-LIBALLOC_DIR = $(RUST_BINDIR)/../src/stdlibs/library/alloc
+LIBALLOC_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/library/alloc
 
 MODULE_SRCS := $(LIBALLOC_DIR)/src/lib.rs
 
@@ -36,4 +36,8 @@ MODULE_LIBRARY_EXPORTED_DEPS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work fine.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/libcompiler_builtins-rust/rules.mk b/lib/libcompiler_builtins-rust/rules.mk
index 86472c1..ab803a6 100644
--- a/lib/libcompiler_builtins-rust/rules.mk
+++ b/lib/libcompiler_builtins-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-COMPILER_BUILTINS_DIR = $(RUST_BINDIR)/../src/stdlibs/vendor/compiler_builtins
+COMPILER_BUILTINS_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/vendor/compiler_builtins
 
 MODULE_SRCS := $(COMPILER_BUILTINS_DIR)/src/lib.rs
 
@@ -26,7 +26,7 @@ MODULE_CRATE_NAME := compiler_builtins
 MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/libcore-rust \
 
-MODULE_RUST_EDITION := 2015
+MODULE_RUST_EDITION := 2018
 
 MODULE_RUSTFLAGS += \
 	--cfg 'feature="weak-intrinsics"' \
diff --git a/lib/libcore-rust/rules.mk b/lib/libcore-rust/rules.mk
index b6632e7..abb2e9d 100644
--- a/lib/libcore-rust/rules.mk
+++ b/lib/libcore-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-LIBCORE_DIR = $(RUST_BINDIR)/../src/stdlibs/library/core
+LIBCORE_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/library/core
 
 MODULE_SRCS := $(LIBCORE_DIR)/src/lib.rs
 
@@ -38,4 +38,8 @@ endif
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work fine.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/libhashbrown-rust/rules.mk b/lib/libhashbrown-rust/rules.mk
index a796560..43be260 100644
--- a/lib/libhashbrown-rust/rules.mk
+++ b/lib/libhashbrown-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-HASHBROWN_DIR = $(RUST_BINDIR)/../src/stdlibs/vendor/hashbrown
+HASHBROWN_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/vendor/hashbrown
 
 MODULE_SRCS := $(HASHBROWN_DIR)/src/lib.rs
 
@@ -31,6 +31,7 @@ MODULE_RUSTFLAGS += \
 	--cfg 'feature="rustc-dep-of-std"' \
 	--cfg 'feature="nightly"' \
 	--cfg 'feature="rustc-internal-api"' \
+	--cfg 'feature="raw-entry"' \
 
 # Suppress warnings since the crate generates warnings when being built as a
 # dependency of std. We use `--cap-lints=allow` because that's done when
@@ -43,4 +44,8 @@ MODULE_LIBRARY_DEPS += \
 	trusty/user/base/lib/liballoc-rust \
 	trusty/user/base/lib/libcompiler_builtins-rust \
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/libpanic_abort-rust/rules.mk b/lib/libpanic_abort-rust/rules.mk
index 683525e..d6c5f73 100644
--- a/lib/libpanic_abort-rust/rules.mk
+++ b/lib/libpanic_abort-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-SRC_DIR := $(RUST_BINDIR)/../src/stdlibs/library/panic_abort
+SRC_DIR := $(RUST_BINDIR)/../lib/rustlib/src/rust/library/panic_abort
 
 MODULE_SRCS := $(SRC_DIR)/src/lib.rs
 
@@ -32,4 +32,8 @@ MODULE_LIBRARY_DEPS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/librustc-demangle-rust/rules.mk b/lib/librustc-demangle-rust/rules.mk
index 4ae1311..0e61360 100644
--- a/lib/librustc-demangle-rust/rules.mk
+++ b/lib/librustc-demangle-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-RUSTC_DEMANGLE_DIR = $(RUST_BINDIR)/../src/stdlibs/vendor/rustc-demangle
+RUSTC_DEMANGLE_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/vendor/rustc-demangle
 
 MODULE_SRCS := $(RUSTC_DEMANGLE_DIR)/src/lib.rs
 
@@ -34,4 +34,8 @@ MODULE_LIBRARY_DEPS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/libstd-rust/rules.mk b/lib/libstd-rust/rules.mk
index dd2ccc7..e0786c6 100644
--- a/lib/libstd-rust/rules.mk
+++ b/lib/libstd-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-LIBSTD_DIR = $(RUST_BINDIR)/../src/stdlibs/library/std
+LIBSTD_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/library/std
 
 MODULE_SRCS := $(LIBSTD_DIR)/src/lib.rs
 
diff --git a/lib/libstd_detect-rust/rules.mk b/lib/libstd_detect-rust/rules.mk
index 5e667f8..d812c4d 100644
--- a/lib/libstd_detect-rust/rules.mk
+++ b/lib/libstd_detect-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-SRC_DIR = $(RUST_BINDIR)/../src/stdlibs/library/stdarch/crates/std_detect
+SRC_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/library/stdarch/crates/std_detect
 
 MODULE_SRCS := $(SRC_DIR)/src/lib.rs
 
@@ -37,4 +37,8 @@ MODULE_LIBRARY_DEPS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/libunwind-rust/rules.mk b/lib/libunwind-rust/rules.mk
index 1193069..f646e95 100644
--- a/lib/libunwind-rust/rules.mk
+++ b/lib/libunwind-rust/rules.mk
@@ -17,7 +17,7 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 
 MODULE := $(LOCAL_DIR)
 
-LIBUNWIND_DIR = $(RUST_BINDIR)/../src/stdlibs/library/unwind
+LIBUNWIND_DIR = $(RUST_BINDIR)/../lib/rustlib/src/rust/library/unwind
 
 MODULE_SRCS := $(LIBUNWIND_DIR)/src/lib.rs
 
@@ -33,4 +33,8 @@ MODULE_LIBRARY_DEPS += \
 
 MODULE_ADD_IMPLICIT_DEPS := false
 
+# TODO: figure out why as of Rust 1.82, rustdoc fails nsjailed Soong builds
+# whereas regular (build.py) builds still work.
+MODULE_SKIP_DOCS := true
+
 include make/library.mk
diff --git a/lib/pvmdice/bindings.h b/lib/pvmdice/bindings.h
new file mode 100644
index 0000000..3bba412
--- /dev/null
+++ b/lib/pvmdice/bindings.h
@@ -0,0 +1,17 @@
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
+#include <interface/apploader/apploader.h>
\ No newline at end of file
diff --git a/lib/pvmdice/manifest.json b/lib/pvmdice/manifest.json
new file mode 100644
index 0000000..a66dc39
--- /dev/null
+++ b/lib/pvmdice/manifest.json
@@ -0,0 +1,8 @@
+{
+    "uuid": "2d8fa4e9-41ae-4a31-a530-bfda434b689f",
+    "min_heap": 65536,
+    "min_stack": 32768,
+    "mgmt_flags": {
+        "non_critical_app": true
+    }
+}
diff --git a/lib/pvmdice/rules.mk b/lib/pvmdice/rules.mk
new file mode 100644
index 0000000..faf15a6
--- /dev/null
+++ b/lib/pvmdice/rules.mk
@@ -0,0 +1,51 @@
+# Copyright (C) 2024 The Android Open Source Project
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
+MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
+
+MODULE_CRATE_NAME := pvmdice
+
+MODULE_SDK_LIB_NAME := pvmdice-rust
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,coset) \
+	$(call FIND_CRATE,ciborium) \
+	trusty/user/base/interface/apploader \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/hwbcc/rust \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-std \
+	packages/modules/Virtualization/libs/dice/open_dice \
+	packages/modules/Virtualization/libs/dice/sample_inputs \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS :=
+MODULE_BINDGEN_ALLOW_TYPES :=
+MODULE_BINDGEN_ALLOW_VARS := \
+	APPLOADER_PORT \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+MODULE_RUST_TESTS := true
+
+# For test service
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+include make/library.mk
diff --git a/lib/pvmdice/src/lib.rs b/lib/pvmdice/src/lib.rs
new file mode 100644
index 0000000..5fdc78a
--- /dev/null
+++ b/lib/pvmdice/src/lib.rs
@@ -0,0 +1,375 @@
+use alloc::collections::TryReserveError;
+use alloc::ffi::CString;
+use diced_open_dice::{
+    bcc_handover_parse, retry_bcc_format_config_descriptor, retry_bcc_main_flow,
+    retry_sign_cose_sign1_with_cdi_leaf_priv, Config, DiceArtifacts, DiceConfigValues, DiceMode,
+    Hash, Hidden, InputValues, OwnedDiceArtifacts, CDI_SIZE, HASH_SIZE, HIDDEN_SIZE,
+};
+use hwbcc::srv::{HwBccOps, RequestContext};
+use hwbcc::{HwBccError, HwBccMode};
+use std::ffi::CStr;
+use tipc::Uuid;
+use trusty_sys::handle_t;
+
+mod sys {
+    include!(env!("BINDGEN_INC_FILE"));
+}
+
+// Currently we do not support dynamically loading apps into trusty pVMs.
+// As such, all user space apps are packaged and signed together with
+// the trusty kernel. This allows us to use empty authority and code
+// hashes when deriving leaf certs, since all measurements were
+// completed in 'pvmfw' before starting trusty and included in the leaf
+// node of the bcc handover.
+//
+// These hashes must only be used for dice certs that measure non-loadable
+// apps. If an app was dynamically loaded, it needs real code and authority
+// measurements, which should likely be provided by the trusty apploader.
+const TRUSTY_NON_LOADABLE_AUTHORITY_HASH: Hash = [0; HASH_SIZE];
+const TRUSTY_NON_LOADABLE_CODE_HASH: Hash = [0; HASH_SIZE];
+
+const EMPTY_HIDDEN_INPUTS: Hidden = [0; HIDDEN_SIZE];
+
+const KEYMINT_UUID: Uuid =
+    Uuid::new(0x5f902ace, 0x5e5c, 0x4cd8, [0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf]);
+const WIDEVINE_UUID: Uuid =
+    Uuid::new(0x08d3ed40, 0xbde2, 0x448c, [0xa9, 0x1d, 0x75, 0xf1, 0x98, 0x9c, 0x57, 0xef]);
+
+struct ComponentSpecificConfigValues {
+    component_name: CString,
+    rkp_vm_marker: bool,
+}
+
+#[derive(Debug)]
+pub enum PvmDiceError {
+    /// Errors returned from the diced_open_dice lib
+    DiceError(diced_open_dice::DiceError),
+    /// Used when trying to initialize PvmDice with a handover that
+    /// does not include a cert chain.
+    NoCertChainInHandover,
+    /// Used if an allocation fails
+    NoMemory,
+    /// Returned on construction of PvmDice if we can't ensure that
+    /// the apploader user space service is not and cannot run.
+    ApploaderInvariantViolated,
+}
+
+impl From<diced_open_dice::DiceError> for PvmDiceError {
+    fn from(e: diced_open_dice::DiceError) -> Self {
+        PvmDiceError::DiceError(e)
+    }
+}
+
+impl From<TryReserveError> for PvmDiceError {
+    fn from(_: TryReserveError) -> Self {
+        PvmDiceError::NoMemory
+    }
+}
+
+/// An implementation of the hwbcc interface for trusty guests running in
+/// protected virtual machines (pVMs).
+pub struct PvmDice {
+    bcc: Vec<u8>,
+    cdi_attest: [u8; CDI_SIZE],
+    cdi_seal: [u8; CDI_SIZE],
+    // We keep this port open to maintain our invariant that
+    // dynamic apps can't be loaded. See `enforce_no_apploader_invariant`.
+    apploader_port_handle: handle_t,
+}
+
+impl Drop for PvmDice {
+    fn drop(&mut self) {
+        // SAFETY we invoke the close syscall with the expected type. The handle will
+        // either be valid and closed, or close will safely return an error code.
+        let rc = unsafe { trusty_sys::close(self.apploader_port_handle) };
+
+        if rc != 0 {
+            log::warn!("Failed to close apploader port handle when dropping PvmDice: {}", rc);
+        }
+    }
+}
+
+impl PvmDice {
+    pub fn try_new(handover_buff: &[u8]) -> Result<Self, PvmDiceError> {
+        let bcc_handover = bcc_handover_parse(handover_buff)?;
+
+        if let Some(bcc) = bcc_handover.bcc() {
+            Ok(PvmDice {
+                bcc: bcc.to_vec(),
+                cdi_attest: *bcc_handover.cdi_attest(),
+                cdi_seal: *bcc_handover.cdi_seal(),
+                apploader_port_handle: enforce_no_apploader_invariant()?,
+            })
+        } else {
+            log::error!("attempting to initialize PvmDice without cert chain in handover");
+
+            Err(PvmDiceError::DiceError(diced_open_dice::DiceError::DiceChainNotFound))
+        }
+    }
+
+    fn derive_next_dice_artifacts(
+        &self,
+        request_ctx: &RequestContext,
+    ) -> Result<OwnedDiceArtifacts, HwBccError> {
+        let config_descriptor = config_descriptor_for_trusty_user_app(request_ctx)?;
+        let input_values = InputValues::new(
+            TRUSTY_NON_LOADABLE_CODE_HASH,
+            Config::Descriptor(config_descriptor.as_slice()),
+            TRUSTY_NON_LOADABLE_AUTHORITY_HASH,
+            dice_mode_for_trusty_user_space_certs(),
+            EMPTY_HIDDEN_INPUTS,
+        );
+
+        Ok(retry_bcc_main_flow(&self.cdi_attest, &self.cdi_seal, &self.bcc, &input_values)?)
+    }
+}
+
+impl HwBccOps for PvmDice {
+    fn init(&self, _: &RequestContext) -> Result<(), HwBccError> {
+        Ok(())
+    }
+
+    fn close(&self, _: &RequestContext) {}
+
+    fn get_bcc(
+        &self,
+        request_ctx: &RequestContext,
+        mode: HwBccMode,
+    ) -> Result<Vec<u8>, HwBccError> {
+        let _ = check_not_test_mode(mode)?;
+
+        let next_dice_artifacts = self.derive_next_dice_artifacts(request_ctx)?;
+
+        let mut bcc = Vec::new();
+
+        // We should always have `bcc` if retry_bcc_main_flow succeeds, but best to try and fail
+        // gracefully.
+        let next_bcc = next_dice_artifacts.bcc().ok_or(trusty_sys::Error::NotValid)?;
+        bcc.try_reserve(next_bcc.len())?;
+        bcc.extend_from_slice(&next_bcc);
+
+        Ok(bcc)
+    }
+
+    fn sign_data<'a>(
+        &self,
+        request_ctx: &RequestContext,
+        data: &'a [u8],
+        aad: &'a [u8],
+        mode: HwBccMode,
+    ) -> Result<Vec<u8>, HwBccError> {
+        let _ = check_not_test_mode(mode)?;
+
+        // TODO: b/404559104 - Keep per-session state around, to avoid re-deriving artifacts
+        // for the common case of calling `get_bcc` and then `sign_data`. Doing so now would
+        // have no impact because the rust hwbcc client opens a new connection for each operation.
+        let dice_artifacts = self.derive_next_dice_artifacts(request_ctx)?;
+
+        Ok(retry_sign_cose_sign1_with_cdi_leaf_priv(data, aad, &dice_artifacts)?)
+    }
+}
+
+/// A helper to check for HwBcc::TestMode and return an error if it's used.
+/// This mode was specific to V1 of the Keymint HAL and is not relevant
+/// for VM use cases where we expect callers are using later versions of
+/// the RKP protocol.
+fn check_not_test_mode(mode: HwBccMode) -> Result<(), HwBccError> {
+    if mode == HwBccMode::Test {
+        log::error!("pvmdice does not support HwBccMode::TestMode");
+        return Err(HwBccError::NotAllowed);
+    }
+
+    Ok(())
+}
+
+/// Get the DICE mode to be used for trusty user space leaf certs
+fn dice_mode_for_trusty_user_space_certs() -> DiceMode {
+    if cfg!(TEST_BUILD) {
+        return DiceMode::kDiceModeDebug;
+    }
+
+    DiceMode::kDiceModeNormal
+}
+
+/// Generate config descriptor for a dice derivation based on the calling app.
+fn config_descriptor_for_trusty_user_app(
+    request_ctx: &RequestContext,
+) -> Result<Vec<u8>, HwBccError> {
+    let component_config = dice_component_specific_config_values(request_ctx);
+
+    let config_values = DiceConfigValues {
+        component_name: Some(&component_config.component_name),
+        component_version: Some(1),
+        resettable: false,
+        rkp_vm_marker: component_config.rkp_vm_marker,
+        // We expect to rely on the security_version of the dice node representing the
+        // entire OS (our parent node) for non-loadable apps.
+        security_version: Some(1),
+    };
+
+    Ok(retry_bcc_format_config_descriptor(&config_values)?)
+}
+
+/// Derive a component name from an incoming request.
+/// There are certain UUIDs that have special treatment so that they
+/// can be recognized by the RKP server. For all other UUIDs, we use
+/// a stringified app UUID.
+fn dice_component_specific_config_values(
+    request_ctx: &RequestContext,
+) -> ComponentSpecificConfigValues {
+    match request_ctx.peer {
+        KEYMINT_UUID => {
+            ComponentSpecificConfigValues { component_name: c"keymint".into(), rkp_vm_marker: true }
+        }
+        WIDEVINE_UUID => ComponentSpecificConfigValues {
+            component_name: c"widevine".into(),
+            rkp_vm_marker: true,
+        },
+        _ => ComponentSpecificConfigValues {
+            component_name: CString::new(request_ctx.peer.to_string()).unwrap(),
+            rkp_vm_marker: false,
+        },
+    }
+}
+
+/// A helper that ensures that the trusty user space apploader does not run
+/// in the same OS as pvmdice. We only emit a warning when TEST_BUILD is set and apploader
+/// exists because in that case, the dice node will be marked as Debug, so verifiers
+/// of the dice chain should recognize the app as different from the production
+/// variant.
+fn enforce_no_apploader_invariant() -> Result<handle_t, PvmDiceError> {
+    let port = CStr::from_bytes_with_nul(sys::APPLOADER_PORT)
+        .map_err(|_| PvmDiceError::ApploaderInvariantViolated)?;
+
+    // SAFETY: This is a syscall. `port` is a valid CStr (checked above) and is only
+    // read by port_create.
+    let rc = unsafe {
+        trusty_sys::port_create(
+            port.as_ptr(),
+            1, /*num_recv_bufs */
+            1, /*recv_buf_size */
+            0, /*flags */
+        )
+    };
+
+    if rc < 0 {
+        if cfg!(TEST_BUILD) {
+            log::warn!("Failed to claim apploader port. Ignoring because TEST_BUILD is set.");
+            return Ok(-1);
+        }
+
+        log::error!("Failed to claim apploader port. PvmDice invariant check failed: {}", rc);
+
+        return Err(PvmDiceError::ApploaderInvariantViolated);
+    }
+
+    Ok(rc.try_into().map_err(|_| {
+        log::error!("Invalid handle for apploader port {}. PvmDice invariant check failed.", rc);
+
+        PvmDiceError::ApploaderInvariantViolated
+    })?)
+}
+
+#[cfg(test)]
+mod test {
+    use crate::PvmDice;
+    use authgraph_boringssl::BoringEcDsa;
+    use authgraph_core::key::DiceChainEntry;
+    use authgraph_core::traits::EcDsa;
+    use ciborium::value::Value;
+    use coset::{AsCborValue, CborSerializable};
+    use diced_open_dice::DiceArtifacts;
+    use diced_sample_inputs::make_sample_bcc_and_cdis;
+    use hwbcc::srv::{HwBccOps, RequestContext};
+    use hwbcc::HwBccMode;
+    use test::expect;
+    use tipc::Uuid;
+    ::test::init!();
+
+    const TEST_MESSAGE: &[u8] = "pvmdice test message".as_bytes();
+    const TEST_AAD: &[u8] = "pvmdice test aad".as_bytes();
+
+    #[test]
+    fn test_init_empty_handover() {
+        let handover: &[u8] = &[];
+        let pvmdice = PvmDice::try_new(handover);
+        expect!(pvmdice.is_err())
+    }
+
+    #[test]
+    fn test_init_bad_handover() {
+        let handover: &[u8] = &[0x12, 0x34, 0x56, 0x78];
+        let pvmdice = PvmDice::try_new(handover);
+        expect!(pvmdice.is_err())
+    }
+
+    #[test]
+    fn test_get_bcc() {
+        let dice_artifacts = make_sample_bcc_and_cdis().unwrap();
+        let handover = to_bcc_handover(&dice_artifacts);
+        let pvmdice = PvmDice::try_new(&handover).unwrap();
+
+        let rq = RequestContext {
+            peer: Uuid::new_from_string("c07129be-cabb-4d4d-837f-ea8fd204dcf1").unwrap(),
+        };
+
+        // TODO: b/393356669 - validate the cert chain.
+        let _ = pvmdice.get_bcc(&rq, HwBccMode::Release).unwrap();
+    }
+
+    #[test]
+    fn verify_sign_data_with_leaf_pub_key() {
+        let dice_artifacts = make_sample_bcc_and_cdis().unwrap();
+        let handover = to_bcc_handover(&dice_artifacts);
+        let pvmdice = PvmDice::try_new(&handover).unwrap();
+
+        let rq = RequestContext {
+            peer: Uuid::new_from_string("c07129be-cabb-4d4d-837f-ea8fd204dcf1").unwrap(),
+        };
+
+        let signed_payload_res =
+            pvmdice.sign_data(&rq, &TEST_MESSAGE, &TEST_AAD, HwBccMode::Release);
+        expect!(signed_payload_res.is_ok());
+        let signed_payload = signed_payload_res.unwrap();
+        let signed_payload_cose = coset::CoseSign1::from_slice(&signed_payload).unwrap();
+
+        // Now verify with the signature in the leaf cert from a chain
+        // retrieved from get_bcc.
+        let ecdsa = BoringEcDsa;
+        let non_explicit_chain_res = pvmdice.get_bcc(&rq, HwBccMode::Release);
+        expect!(non_explicit_chain_res.is_ok());
+        let non_explicit_chain = non_explicit_chain_res.unwrap();
+        let leaf_cert = leaf_cert_from_non_explicit_chain(&non_explicit_chain);
+        let leaf_cert_pub_key = leaf_cert.payload.subject_pub_key.unwrap();
+
+        expect!(signed_payload_cose
+            .verify_signature(&TEST_AAD, |sign, data| ecdsa.verify_signature(
+                &leaf_cert_pub_key,
+                data,
+                sign
+            ))
+            .is_ok());
+    }
+
+    fn leaf_cert_from_non_explicit_chain(dice_chain: &Vec<u8>) -> DiceChainEntry {
+        let mut chain_value = Value::from_slice(dice_chain.as_slice()).expect("invalid cbor");
+        let chain_arr: &mut Vec<Value> =
+            chain_value.as_array_mut().expect("get_bcc should return a CBOR array");
+        let last_cert_cbor = chain_arr.remove(chain_arr.len() - 1);
+
+        DiceChainEntry::from_cbor_value(last_cert_cbor).expect("Invalid leaf cert")
+    }
+
+    fn to_bcc_handover(dice_artifacts: &dyn DiceArtifacts) -> Vec<u8> {
+        let dice_chain: Value = ciborium::from_reader(&mut dice_artifacts.bcc().unwrap()).unwrap();
+        let bcc_handover = Value::Map(vec![
+            (Value::Integer(1.into()), Value::Bytes(dice_artifacts.cdi_attest().to_vec())),
+            (Value::Integer(2.into()), Value::Bytes(dice_artifacts.cdi_seal().to_vec())),
+            (Value::Integer(3.into()), dice_chain),
+        ]);
+        let mut data = Vec::new();
+        ciborium::into_writer(&bcc_handover, &mut data)
+            .expect("serialization of bcc_handover failed");
+        data
+    }
+}
diff --git a/lib/secretkeeper/dice-policy-builder/rules.mk b/lib/secretkeeper/dice-policy-builder/rules.mk
new file mode 100644
index 0000000..dd63748
--- /dev/null
+++ b/lib/secretkeeper/dice-policy-builder/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_SRCS := system/secretkeeper/dice_policy/building/src/lib.rs
+
+MODULE_CRATE_NAME := dice_policy_builder
+
+MODULE_LIBRARY_EXPORTED_DEPS += \
+	trusty/user/base/lib/secretkeeper/dice_policy \
+	$(call FIND_CRATE,enumn) \
+	$(call FIND_CRATE,ciborium) \
+	$(call FIND_CRATE,itertools) \
+	$(call FIND_CRATE,log) \
+
+include make/library.mk
diff --git a/lib/service_manager/client/rules.mk b/lib/service_manager/client/rules.mk
new file mode 100644
index 0000000..829370f
--- /dev/null
+++ b/lib/service_manager/client/rules.mk
@@ -0,0 +1,37 @@
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
+MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
+
+MODULE_CRATE_NAME := service_manager
+
+MODULE_SDK_LIB_NAME := service_manager-rust
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/interface/binder_accessor \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-std \
+
+MODULE_RUST_TESTS := false
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/service_manager/client/src/lib.rs b/lib/service_manager/client/src/lib.rs
new file mode 100644
index 0000000..88306a6
--- /dev/null
+++ b/lib/service_manager/client/src/lib.rs
@@ -0,0 +1,278 @@
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
+use alloc::ffi::CString;
+use binder::{ExceptionCode, FromIBinder, ParcelFileDescriptor, StatusCode, Strong};
+use rpcbinder::{FileDescriptorTransportMode, RpcSession};
+use std::ffi::CStr;
+use std::os::fd::IntoRawFd;
+use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
+    ITrustyAccessor, ERROR_CONNECTION_INFO_NOT_FOUND, ERROR_FAILED_TO_CONNECT_EACCES,
+};
+
+// At the time of writing, this max is enforced by the trusty kernel
+// which defines MAX_PORT_PATH_LEN
+const MAX_TIPC_PORT_NAME_LEN: usize = 64;
+const TRUSTY_BINDER_RPC_PORT_SUFFIX: &str = ".bnd";
+const TRUSTED_HAL_COMMON_PREFIX: &str = "android.hardware.security.see";
+const TRUSTED_HAL_REPLACEMENT_PREFIX: &str = "ahss";
+
+#[derive(Debug, PartialEq)]
+enum Error {
+    /// A connection to the given port could not be established.
+    ConnectionFailed,
+    /// A connection was established to the given port, but setting up a binder client
+    /// failed.
+    BinderSetupFailed(StatusCode),
+}
+
+/// Retrieve a service by name. This function will block until a service is available and
+/// may wait indefinitely if it never becomes available.
+///
+/// In trusty, services are exposed to other apps by their port names.
+/// The convention in Android Binder is to use {binder_descriptor}/{service_instance}
+/// as the pattern for service names. When possible, trusty services that are defined in AIDL
+/// should adhere to this convention.
+/// E.g. "android.hardware.security.see.storage.ISecureStorage/tee"
+///
+/// Note that trusty port names cannot be more than 64 characters, so `name` must be
+/// adhere to that constraint. To prevent collisions between non-binder trusty services,
+/// we add a suffix of `.bnd` to all service names in this function.
+///
+/// TODO: b/395096422 - Make this more performant once we have a CPP lib or a rust API
+/// that can access SpIBinder directly.
+pub fn wait_for_interface<T: FromIBinder + ?Sized>(name: &str) -> Result<Strong<T>, StatusCode> {
+    let c_port_name = service_name_to_trusty_c_port(name)?;
+    let port_name = c_port_name.as_c_str().to_str().map_err(|_| StatusCode::BAD_VALUE)?;
+
+    // First try and see if our service is gated by an ITrustyAccessor implementation.
+    // This is a binder service exposed on the port we've connected to that acts as
+    // an intermediary for resolving connections to the requested service. It was originally
+    // introduced to allow for authentication and authorization of the caller before handing
+    // back a handle to the requested service.
+    let mut session = get_new_rpc_session();
+    match setup_trusty_client(&session, &c_port_name) {
+        Ok(accessor) => {
+            let service_fd = fd_from_accessor(&accessor, name)?;
+
+            return rpcbinder_from_parcel_fd(service_fd).inspect_err(|&status_code| {
+                log::error!(
+                    "Failed to setup binder on fd returned from ITrustyAccessor for {:?} {}",
+                    &port_name,
+                    status_code
+                );
+            });
+        }
+        Err(Error::ConnectionFailed) => {
+            // If the port we requested didn't exist this would have blocked forever. So we assume
+            // that the service listening on this port rejected our connection.
+            return Err(StatusCode::PERMISSION_DENIED);
+        }
+        Err(Error::BinderSetupFailed(s)) => {
+            log::debug!(
+                "failed to setup client to ITrustyAccessor for {:?} {:?}. Will try a direct \
+            connection.",
+                &port_name,
+                s
+            );
+        }
+    }
+
+    // The binder on the other end was likely not an accessor, try a direct connection.
+    session = get_new_rpc_session();
+    setup_trusty_client(&session, &c_port_name).map_err(|e| {
+        log::error!("failed to setup binder on {:?} {:?}", &port_name, e);
+        match e {
+            // This is an unexpected case. We've already successfully connected to this port once.
+            Error::ConnectionFailed => StatusCode::PERMISSION_DENIED,
+            Error::BinderSetupFailed(s) => s,
+        }
+    })
+}
+
+fn fd_from_accessor(
+    accessor: &Strong<dyn ITrustyAccessor>,
+    name: &str,
+) -> Result<ParcelFileDescriptor, StatusCode> {
+    // Before we attempt to add a connection, ensure that we've obtained an Accessor
+    // for the correct service name.
+    let accessor_instance_name = accessor.getInstanceName().map_err(|status_code| {
+        log::error!(
+            "Failed to resolve ITrustyAccessor instance name at {:?} {}",
+            name,
+            status_code
+        );
+
+        StatusCode::NAME_NOT_FOUND
+    })?;
+
+    if accessor_instance_name != name {
+        log::error!(
+            "Provided service name {:?} does not match the instance name resolved from \
+        ITrustyAccessor {}",
+            name,
+            accessor_instance_name
+        );
+
+        return Err(StatusCode::NAME_NOT_FOUND);
+    }
+
+    let service_fd = accessor.addConnection().map_err(|status| {
+        log::error!("Failed to retrieve FD from accessor for {:?} {}", name, status);
+
+        match status.exception_code() {
+            ExceptionCode::SERVICE_SPECIFIC => match status.service_specific_error() {
+                ERROR_FAILED_TO_CONNECT_EACCES => StatusCode::PERMISSION_DENIED,
+                ERROR_CONNECTION_INFO_NOT_FOUND => StatusCode::NAME_NOT_FOUND,
+                _ => StatusCode::UNKNOWN_ERROR,
+            },
+            ExceptionCode::TRANSACTION_FAILED => status.transaction_error(),
+            _ => StatusCode::NAME_NOT_FOUND,
+        }
+    })?;
+
+    Ok(service_fd)
+}
+
+fn rpcbinder_from_parcel_fd<T: FromIBinder + ?Sized>(
+    parceled_fd: ParcelFileDescriptor,
+) -> Result<Strong<T>, StatusCode> {
+    let session = get_new_rpc_session();
+    let raw_fd = parceled_fd.into_raw_fd();
+
+    session.setup_preconnected_client(move || Some(raw_fd))
+}
+
+/// Pretty much a re-implementation of RpcSession::setup_trusty_client but does not panic
+/// when a connection fails. As a bonus, we can differentiate between a failed raw connection
+/// and other binder-specific errors.
+fn setup_trusty_client<T: FromIBinder + ?Sized>(
+    session: &RpcSession,
+    port: &CStr,
+) -> Result<Strong<T>, Error> {
+    let h = tipc::Handle::connect(port).map_err(|e| {
+        log::error!("Failed to connect to port {:?} {:?}", port, e);
+        Error::ConnectionFailed
+    })?;
+    // Do not close the handle at the end of the scope
+    let fd = h.as_raw_fd();
+    core::mem::forget(h);
+    session.setup_preconnected_client(|| Some(fd)).map_err(|status_code| {
+        log::debug!("failed to setup preconnected client on port {:?} {}", port, status_code);
+
+        Error::BinderSetupFailed(status_code)
+    })
+}
+
+fn get_new_rpc_session() -> RpcSession {
+    let session = RpcSession::new();
+    session.set_file_descriptor_transport_mode(FileDescriptorTransportMode::Trusty);
+
+    session
+}
+
+// Many trusted hal interfaces (VINTF stable interfaces to the TEE) are too long
+// for the current max port name (64 characters including a null byte). We work
+// around this temporarily by taking advantage of a common prefix they all have
+// and map "android.hardware.security.see" to "ahss".
+//
+// So for example, "android.hardware.security.see.authmgr.IAuthMgrAuthorization/default"
+// will result in a port name of ahss.authmgr.IAuthMgrAuhtorization/default .
+fn try_long_service_name_to_port(service_name: &str) -> Result<String, StatusCode> {
+    let mut port_name = String::new();
+
+    match service_name.split_once(TRUSTED_HAL_COMMON_PREFIX) {
+        // Since we're in this function, we already know the given service_name is too long
+        // and a None here means we won't shorten it since our prefix wasn't found.
+        None => Err(port_size_err(service_name)),
+        // In this case our pattern was found, but not at the front of the str, which
+        // is not a valid case for our name shortening. Since we're in this function
+        // we now know we have a name that's too long and we can't shorten.
+        Some((pre, _)) if !pre.is_empty() => Err(port_size_err(service_name)),
+        Some((_, post)) => {
+            port_name
+                .try_reserve(
+                    TRUSTED_HAL_REPLACEMENT_PREFIX.len()
+                        + post.len()
+                        + TRUSTY_BINDER_RPC_PORT_SUFFIX.len(),
+                )
+                .map_err(|_| StatusCode::NO_MEMORY)?;
+
+            port_name.push_str(TRUSTED_HAL_REPLACEMENT_PREFIX);
+            port_name.push_str(post);
+            port_name.push_str(TRUSTY_BINDER_RPC_PORT_SUFFIX);
+
+            // Check size again. It's possible we weren't able to shorten the name enough.
+            if !is_valid_port_len(port_name.len()) {
+                return Err(port_size_err(&port_name));
+            }
+
+            Ok(port_name)
+        }
+    }
+}
+
+fn is_valid_port_len(port_len: usize) -> bool {
+    // Note that if the name is equal to the max, we fail because
+    // these ports will eventually be represented as CStrings and passed
+    // to the trusty kernel to check their sizes so we need room for the
+    // nul byte.
+    port_len < MAX_TIPC_PORT_NAME_LEN
+}
+
+fn port_size_err(service_name: &str) -> StatusCode {
+    log::error!(
+        "Cannot create port name from {:?} within trusty port length limit of {}",
+        service_name,
+        MAX_TIPC_PORT_NAME_LEN
+    );
+
+    StatusCode::BAD_VALUE
+}
+
+/// A helper to transform a binder service name to a trusty port name.
+/// A suffix is added to the service name to identify it as a port that is serving
+/// binders.
+///
+/// Some known trusted hal services, those that start with android.hardware.security.see
+/// are transformed to fit within trusty's port length limits.
+pub fn service_name_to_trusty_port(service_name: &str) -> Result<String, StatusCode> {
+    let service_name_len = service_name.len() + TRUSTY_BINDER_RPC_PORT_SUFFIX.len();
+
+    // TODO: b/403531416 - remove this once longer port names are supported in trusty
+    if !is_valid_port_len(service_name_len) {
+        return try_long_service_name_to_port(service_name);
+    }
+
+    let mut port_name = String::new();
+
+    port_name.try_reserve(service_name_len).map_err(|_| StatusCode::NO_MEMORY)?;
+
+    port_name.push_str(service_name);
+    port_name.push_str(TRUSTY_BINDER_RPC_PORT_SUFFIX);
+
+    Ok(port_name)
+}
+
+/// Get a CString port name from a service_name.
+/// See `service_name_to_trusty_port` for details.
+pub fn service_name_to_trusty_c_port(service_name: &str) -> Result<CString, StatusCode> {
+    let mut port_name = service_name_to_trusty_port(service_name)?;
+    // Ensure we have room for the null byte that CString construction will add.
+    port_name.try_reserve_exact(1).map_err(|_| StatusCode::NO_MEMORY)?;
+
+    CString::new(port_name).map_err(|_| StatusCode::BAD_VALUE)
+}
diff --git a/lib/service_manager/tests/aidl/com/android/trusty/test_service/ISMTestService.aidl b/lib/service_manager/tests/aidl/com/android/trusty/test_service/ISMTestService.aidl
new file mode 100644
index 0000000..258ac43
--- /dev/null
+++ b/lib/service_manager/tests/aidl/com/android/trusty/test_service/ISMTestService.aidl
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
+package com.android.trusty.test_service;
+
+interface ISMTestService {
+       String hello();
+}
\ No newline at end of file
diff --git a/lib/service_manager/tests/aidl/rules.mk b/lib/service_manager/tests/aidl/rules.mk
new file mode 100644
index 0000000..7d69ef4
--- /dev/null
+++ b/lib/service_manager/tests/aidl/rules.mk
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
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_AIDL_PACKAGE := com/android/trusty/test_service
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_CRATE_NAME := service_manager_test_service
+
+MODULE_AIDLS := \
+	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/ISMTestService.aidl \
+
+include make/aidl.mk
\ No newline at end of file
diff --git a/lib/service_manager/tests/fake_accessor/manifest.json b/lib/service_manager/tests/fake_accessor/manifest.json
new file mode 100644
index 0000000..1ee0fc1
--- /dev/null
+++ b/lib/service_manager/tests/fake_accessor/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "fake_accessor",
+    "uuid": "18121b24-48a5-4f86-9058-066dbb20ed1f",
+    "min_heap": 8192,
+    "min_stack": 8192
+}
\ No newline at end of file
diff --git a/lib/service_manager/tests/fake_accessor/rules.mk b/lib/service_manager/tests/fake_accessor/rules.mk
new file mode 100644
index 0000000..a90d4bc
--- /dev/null
+++ b/lib/service_manager/tests/fake_accessor/rules.mk
@@ -0,0 +1,36 @@
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
+MODULE_SRCS := $(LOCAL_DIR)/src/main.rs
+
+MODULE_CRATE_NAME := fake_accessor
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/interface/binder_accessor \
+	trusty/user/base/lib/service_manager/client \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-std \
+
+MODULE_RUST_USE_CLIPPY := true
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+include make/trusted_app.mk
diff --git a/lib/service_manager/tests/fake_accessor/src/main.rs b/lib/service_manager/tests/fake_accessor/src/main.rs
new file mode 100644
index 0000000..daf3c17
--- /dev/null
+++ b/lib/service_manager/tests/fake_accessor/src/main.rs
@@ -0,0 +1,90 @@
+use alloc::rc::Rc;
+use binder::{BinderFeatures, Interface, ParcelFileDescriptor, Status};
+use rpcbinder::RpcServer;
+use service_manager::{service_name_to_trusty_c_port, service_name_to_trusty_port};
+use std::os::fd::{FromRawFd, OwnedFd};
+use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, Uuid};
+use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
+    BnTrustyAccessor, ITrustyAccessor, ERROR_FAILED_TO_CREATE_SOCKET,
+};
+const TEST_SERVICE_DIRECT_NAME: &str = "com.android.trusty.test_service.ISMTestService/direct";
+// This is the port that the accessor is exposing to the rest of the user space TAs
+const TEST_SERVICE_PUBLIC_NAME: &str = "com.android.trusty.test_service.ISMTestService/accessor";
+// This port exists to allow tests to exercise a check for the correct instance name from an accessor.
+// When connecting to this port, clients will find an ITrustyAccessor whose instance name does not match the
+// port name.
+const ACCESSOR_MISMATCH_TEST_NAME: &str = "com.android.trusty.test_service.ISMTestService/mismatch";
+// This port is locked down to not allow access to any existing TAs. It allows the client tests
+// to exercise connection failure paths.
+const ACCESSOR_NO_PERMISSIONS: &str = "com.android.trusty.test_service.ISMTestService/eperm";
+const EMPTY_ALLOWED_UUIDS: &[Uuid] = &[];
+struct FakeAccessor;
+impl Interface for FakeAccessor {}
+impl ITrustyAccessor for FakeAccessor {
+    fn addConnection(&self) -> Result<ParcelFileDescriptor, Status> {
+        let port = service_name_to_trusty_c_port(TEST_SERVICE_DIRECT_NAME)?;
+        let handle = tipc::Handle::connect(port.as_c_str()).map_err(|_| {
+            binder::Status::new_service_specific_error(
+                ERROR_FAILED_TO_CREATE_SOCKET,
+                Some(c"Failed to connect to com.android.trusty.test_service.ISMTestService/direct.bnd"),
+            )
+        })?;
+        let fd = handle.as_raw_fd();
+        // Do not close this fd. We're passing ownership of it
+        // to ParcelFileDescriptor.
+        core::mem::forget(handle);
+        // SAFETY: The fd is open since it was obtained from a successful call to
+        // tipc::Handle::connect. The fd is suitable for transferring ownership because we've leaked
+        // the original handle to ensure it isn't dropped.
+        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
+        Ok(ParcelFileDescriptor::new(owned_fd))
+    }
+    fn getInstanceName(&self) -> Result<String, Status> {
+        Ok(TEST_SERVICE_PUBLIC_NAME.to_owned())
+    }
+}
+fn new_fake_accessor_server() -> RpcServer {
+    let binder = BnTrustyAccessor::new_binder(FakeAccessor, BinderFeatures::default());
+    RpcServer::new_per_session(move |_uuid| Some(binder.as_binder()))
+}
+wrap_service!(AccessorExposingTestService(RpcServer: UnbufferedService));
+service_dispatcher! {
+    enum AccessorServices {
+        AccessorExposingTestService,
+    }
+}
+fn main() {
+    log::info!("Starting fake accessor...");
+    let test_service_server = new_fake_accessor_server();
+    let test_service = Rc::new(AccessorExposingTestService(test_service_server));
+    let mut dispatcher = AccessorServices::<3>::new().expect("Failed to create dispatcher");
+    let cfg = PortCfg::new(
+        service_name_to_trusty_port(TEST_SERVICE_PUBLIC_NAME)
+            .expect("test service port to be resolved"),
+    )
+    .expect("could not create port config")
+    .allow_ta_connect();
+    dispatcher
+        .add_service(test_service.clone(), cfg)
+        .expect("failed to add accessor test service to dispatcher");
+    let cfg = PortCfg::new(
+        service_name_to_trusty_port(ACCESSOR_MISMATCH_TEST_NAME)
+            .expect("accessor mismatch port to be resolved"),
+    )
+    .expect("could not create port config")
+    .allow_ta_connect();
+    dispatcher
+        .add_service(test_service.clone(), cfg)
+        .expect("failed to add mismatch test port to dispatcher");
+    let cfg = PortCfg::new(
+        service_name_to_trusty_port(ACCESSOR_NO_PERMISSIONS).expect("no perm port to be resolved"),
+    )
+    .expect("could not create port config")
+    .allow_ta_connect()
+    .allowed_uuids(EMPTY_ALLOWED_UUIDS);
+    dispatcher.add_service(test_service, cfg).expect("failed to add eperm test port to dispatcher");
+    Manager::<_, _, 3, 1>::new_with_dispatcher(dispatcher, [])
+        .expect("Service manager could not be created")
+        .run_event_loop()
+        .expect("Main event loop exited");
+}
diff --git a/lib/service_manager/tests/manifest.json b/lib/service_manager/tests/manifest.json
new file mode 100644
index 0000000..00dbc88
--- /dev/null
+++ b/lib/service_manager/tests/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "service_manager_integration_tests",
+    "uuid": "1a55040b-e35a-4326-88f5-b95601c2d4a0",
+    "min_heap": 16384,
+    "min_stack": 16384
+}
\ No newline at end of file
diff --git a/lib/service_manager/tests/rules.mk b/lib/service_manager/tests/rules.mk
new file mode 100644
index 0000000..e5d1dd6
--- /dev/null
+++ b/lib/service_manager/tests/rules.mk
@@ -0,0 +1,38 @@
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
+MODULE_SRCS := $(LOCAL_DIR)/tests.rs
+
+MODULE_CRATE_NAME := service_manager_tests
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	trusty/user/base/interface/secure_storage/rust \
+	trusty/user/base/lib/service_manager/client \
+	trusty/user/base/lib/service_manager/tests/aidl \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+
+MODULE_RUST_TESTS := true
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/service_manager/tests/test_service/manifest.json b/lib/service_manager/tests/test_service/manifest.json
new file mode 100644
index 0000000..e6b5dde
--- /dev/null
+++ b/lib/service_manager/tests/test_service/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "service_manager_test_service",
+    "uuid": "16ba623e-be98-43c5-955a-c24166198289",
+    "min_heap": 8192,
+    "min_stack": 8192
+}
\ No newline at end of file
diff --git a/lib/service_manager/tests/test_service/rules.mk b/lib/service_manager/tests/test_service/rules.mk
new file mode 100644
index 0000000..b8ead36
--- /dev/null
+++ b/lib/service_manager/tests/test_service/rules.mk
@@ -0,0 +1,35 @@
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
+MODULE_SRCS := $(LOCAL_DIR)/src/main.rs
+
+MODULE_CRATE_NAME := service_manager_test_service
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/lib/service_manager/tests/aidl \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-log \
+
+MODULE_RUST_USE_CLIPPY := true
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+include make/trusted_app.mk
diff --git a/lib/service_manager/tests/test_service/src/main.rs b/lib/service_manager/tests/test_service/src/main.rs
new file mode 100644
index 0000000..acb46c5
--- /dev/null
+++ b/lib/service_manager/tests/test_service/src/main.rs
@@ -0,0 +1,49 @@
+use alloc::rc::Rc;
+use binder::{BinderFeatures, Status};
+use rpcbinder::RpcServer;
+use service_manager_test_service::aidl::com::android::trusty::test_service::ISMTestService::{
+    BnSMTestService, ISMTestService,
+};
+use tipc::{service_dispatcher, wrap_service, Manager, PortCfg};
+
+const DIRECT_TEST_SERVICE_PORT: &str = "com.android.trusty.test_service.ISMTestService/direct.bnd";
+
+struct TestService;
+
+impl binder::Interface for TestService {}
+impl ISMTestService for TestService {
+    fn hello(&self) -> Result<String, Status> {
+        Ok("Hello from the service manager test service!".to_owned())
+    }
+}
+
+wrap_service!(DirectTestService(RpcServer: UnbufferedService));
+
+service_dispatcher! {
+    enum TestServices {
+        DirectTestService,
+    }
+}
+
+fn main() {
+    trusty_log::init();
+    let direct_service = BnSMTestService::new_binder(TestService, BinderFeatures::default());
+    let direct_rpc_server =
+        RpcServer::new_per_session(move |_uuid| Some(direct_service.as_binder()));
+    let direct = DirectTestService(direct_rpc_server);
+
+    let mut dispatcher = TestServices::<1>::new().expect("Failed to create dispatcher");
+
+    let cfg = PortCfg::new(DIRECT_TEST_SERVICE_PORT)
+        .expect("could not create port config")
+        .allow_ta_connect();
+
+    dispatcher
+        .add_service(Rc::new(direct), cfg)
+        .expect("failed to add direct test service to dispatcher");
+
+    Manager::<_, _, 1, 1>::new_with_dispatcher(dispatcher, [])
+        .expect("Service manager could not be created")
+        .run_event_loop()
+        .expect("Service manager test service failed");
+}
diff --git a/lib/service_manager/tests/tests.rs b/lib/service_manager/tests/tests.rs
new file mode 100644
index 0000000..2e0038f
--- /dev/null
+++ b/lib/service_manager/tests/tests.rs
@@ -0,0 +1,124 @@
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
+//! # Integration tests for the trusty service_manager lib.
+//!
+//!
+//! ## Test components
+//!
+//! ### ISMTestService
+//! The AIDL definition for the test service we use in this test suite.
+//!
+//! ### service_manager_test_service
+//! This is a trusty user space app that implements ISMTestService.
+//! It exposes "com.android.trusty.test_service.ISMTestService/direct" which, allows direct
+//! access to the test service.
+//!
+//! ### fake_accessor
+//! This is a trusty user space app that implements a binder ITrustyAccessor interface that returns
+//! a pre-connected fd to the service_manager_test_service. It exposes this accessor implementation
+//! on "com.android.trusty.test_service.ISMTestService/through_accessor".
+//!
+//! fake_accessor also exposes "com.android.trusty.test_service.ISMTestService/expect_mismatch" that
+//! intentionally has a different instance name than the port on which it is served. This allows us
+//! to cover this error condition in our integration tests.
+//!
+
+#[cfg(test)]
+mod tests {
+    use service_manager::*;
+    use service_manager_test_service::binder;
+    use service_manager_test_service::aidl::com::android::trusty::test_service::ISMTestService::ISMTestService;
+    use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::ISecureStorage::ISecureStorage;
+    use test::{expect, expect_eq};
+
+    test::init!();
+
+    #[test]
+    fn test_wait_for_interface_direct() {
+        let test_service: Result<binder::Strong<dyn ISMTestService>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/direct");
+        expect!(test_service.is_ok());
+        expect!(test_service.unwrap().hello().is_ok());
+    }
+
+    #[test]
+    fn test_wait_for_interface_through_accessor() {
+        let test_service: Result<binder::Strong<dyn ISMTestService>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/accessor");
+        expect!(test_service.is_ok());
+        expect!(test_service.unwrap().hello().is_ok());
+    }
+
+    #[test]
+    fn test_accessor_mismatch() {
+        let test_service: Result<binder::Strong<dyn ISMTestService>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/mismatch");
+        expect_eq!(test_service, Err(binder::StatusCode::NAME_NOT_FOUND));
+    }
+
+    #[test]
+    fn test_connection_failure() {
+        // tipc::Handle::connect will block forever on a non-existent port so a good way to
+        // get a connection failure is to connect to a real port that we don't have permissions for.
+        let test_service: Result<binder::Strong<dyn ISMTestService>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/eperm");
+
+        expect_eq!(test_service, Err(binder::StatusCode::PERMISSION_DENIED));
+    }
+
+    #[test]
+    fn test_wrong_direct_interface_requested() {
+        let test_service: Result<binder::Strong<dyn ISecureStorage>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/direct");
+        expect_eq!(test_service, Err(binder::StatusCode::BAD_TYPE));
+    }
+
+    #[test]
+    fn test_wrong_interface_requested_through_accessor() {
+        let test_service: Result<binder::Strong<dyn ISecureStorage>, binder::StatusCode> =
+            wait_for_interface("com.android.trusty.test_service.ISMTestService/accessor");
+        expect_eq!(test_service, Err(binder::StatusCode::BAD_TYPE));
+    }
+
+    #[test]
+    fn test_service_name_to_trusty_port_under_max() {
+        expect_eq!(
+            service_name_to_trusty_port("foo.bar.ok.IShortService/default"),
+            Ok("foo.bar.ok.IShortService/default.bnd".to_owned())
+        )
+    }
+
+    #[test]
+    fn test_service_name_to_trusty_port_too_long_known_prefix() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "android.hardware.security.see.authmgr.IAuthMgrAuthorization/default"
+            ),
+            Ok("ahss.authmgr.IAuthMgrAuthorization/default.bnd".to_owned()),
+        )
+    }
+
+    #[test]
+    fn test_service_name_to_trusty_port_too_long_invalid() {
+        expect_eq!(
+            service_name_to_trusty_port(
+                "unknown.prefix.so.we.dont.handle.it.for.now.ILongServiceName/default"
+            ),
+            Err(binder::StatusCode::BAD_VALUE),
+        )
+    }
+}
diff --git a/lib/syscall-stubs/rules.mk b/lib/syscall-stubs/rules.mk
index 7a8f865..d47fbea 100644
--- a/lib/syscall-stubs/rules.mk
+++ b/lib/syscall-stubs/rules.mk
@@ -30,7 +30,7 @@ $(SYSCALL_S): ARCH:=$(ARCH)
 $(SYSCALL_S): SYSCALL_H:=$(SYSCALL_H)
 $(SYSCALL_S): SYSCALL_S:=$(SYSCALL_S)
 $(SYSCALL_S): SYSCALL_RS:=$(SYSCALL_RS)
-$(SYSCALL_S): $(SYSCALL_TABLE) $(SYSCALL_STUBGEN_TOOL)
+$(SYSCALL_S): $(SYSCALL_TABLE) $(SYSCALL_STUBGEN_TOOL) $(CONFIGHEADER)
 	@$(MKDIR)
 	@echo generating syscalls stubs $@
 	$(NOECHO)$(SYSCALL_STUBGEN_TOOL) --arch $(ARCH) -d $(SYSCALL_H) -s $(SYSCALL_S) -r $(SYSCALL_RS) $<
diff --git a/lib/tipc/rust/src/lib.rs b/lib/tipc/rust/src/lib.rs
index 3eaaae1..601182d 100644
--- a/lib/tipc/rust/src/lib.rs
+++ b/lib/tipc/rust/src/lib.rs
@@ -35,6 +35,7 @@ mod sys {
 
 mod err;
 mod handle;
+pub mod raw;
 mod serialization;
 mod service;
 
diff --git a/lib/tipc/rust/src/raw/event_loop.rs b/lib/tipc/rust/src/raw/event_loop.rs
new file mode 100644
index 0000000..7c5a6b0
--- /dev/null
+++ b/lib/tipc/rust/src/raw/event_loop.rs
@@ -0,0 +1,137 @@
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
+//! Defines the event loop runner for the TAs. Compared to the legacy event loop included in the
+//! `Manager`, this does not use `Dispatcher`.
+use crate::raw::{HandleSetWrapper, HandleType};
+use crate::sys;
+use crate::{MessageResult, Result, TipcError, UnbufferedService};
+use alloc::sync::Arc;
+use log::{debug, error, warn};
+
+/// The event loop runner that waits for and dispatches the events.
+pub struct EventLoop<S: UnbufferedService> {
+    handle_set_wrapper: Arc<HandleSetWrapper<S>>,
+}
+
+impl<S: UnbufferedService> EventLoop<S> {
+    pub fn new(handle_set_wrapper: Arc<HandleSetWrapper<S>>) -> Self {
+        Self { handle_set_wrapper }
+    }
+
+    /// Runs the event loop.
+    pub fn run(&self) -> Result<()> {
+        loop {
+            let err_result = match self.wait_and_handle_event() {
+                Ok(()) => continue,
+                Err(e) => e,
+            };
+            // TODO(b/382291660): refactor
+            // The following code is equivalent to the error handling in:
+            // trusty/user/lib/tipc/rust/src/service.rs->run_event_loop()
+            // Check if the error is recoverable or not. If the error is not one of a
+            // limited set of recoverable errors, we break from the event loop.
+            use trusty_sys::Error;
+            match err_result {
+                // Recoverable errors that are always ignored.
+                | TipcError::SystemError(Error::TimedOut)
+                | TipcError::SystemError(Error::ChannelClosed)
+
+                // returned when peer UUID connection is not allowed.
+                | TipcError::SystemError(Error::NotAllowed)
+
+                // These are always caused by the client and so shouldn't be treated as an
+                // internal error or cause the event loop to exit.
+                | TipcError::ChannelClosed
+                => {
+                    debug!("Recoverable error ignored: {:?}", err_result)
+                }
+
+                // These are legitimate errors and we should be handling them, but they would be
+                // better handled lower in the event loop closer to where they originate. If
+                // they get propagated up here then we can't meaningfully handle them anymore,
+                // so just log them and continue the loop.
+                | TipcError::IncompleteWrite { .. }
+                | TipcError::NotEnoughBuffer
+                | TipcError::Busy
+                => {
+                    warn!(
+                        "Received error {:?} in main event loop. This should have been handled closer to where it originated",
+                        err_result,
+                    )
+                }
+
+                _ => {
+                    error!("Error occurred while handling incoming event: {:?}", err_result);
+                    return Err(err_result);
+                }
+            }
+        }
+    }
+
+    fn wait_and_handle_event(&self) -> Result<()> {
+        let (service_handle, event) = self.handle_set_wrapper.wait(None)?;
+        // TODO(b/382291660): refactor, the code should handle all events, not just one
+        // TODO(b/382291660): Abort on port errors?
+        // The following code is equivalent to: trusty/user/lib/tipc/rust/src/service.rs->handler()
+        match &service_handle.ty {
+            HandleType::Port(_) if event & (sys::IPC_HANDLE_POLL_READY as u32) != 0 => {
+                self.handle_set_wrapper.handle_connect(service_handle)
+            }
+            HandleType::Connection(_) if event & (sys::IPC_HANDLE_POLL_MSG as u32) != 0 => {
+                match self.handle_set_wrapper.handle_message(Arc::clone(&service_handle)) {
+                    Ok(MessageResult::MaintainConnection) => Ok(()),
+                    Ok(MessageResult::CloseConnection) => {
+                        self.handle_set_wrapper.remove(service_handle)?;
+                        Ok(())
+                    }
+                    Err(e) => {
+                        error!("Could not handle message, closing connection: {:?}", e);
+                        self.handle_set_wrapper.remove(service_handle)?;
+                        Ok(())
+                    }
+                }
+            }
+            HandleType::Connection(_) if event & (sys::IPC_HANDLE_POLL_HUP as u32) != 0 => {
+                self.handle_set_wrapper.handle_disconnect(service_handle)
+            }
+
+            //TODO(b/382291660): update this comment
+            // `SEND_UNBLOCKED` means that some previous attempt to send a message was
+            // blocked and has now become unblocked. This should normally be handled by
+            // the code trying to send the message, but if the sending code doesn't do so
+            // then we can end up getting it here.
+            _ if event & (sys::IPC_HANDLE_POLL_SEND_UNBLOCKED as u32) != 0 => {
+                warn!(
+                    "Received `SEND_UNBLOCKED` event received in main event loop. \
+                     This likely means that a sent message was lost somewhere"
+                );
+                //TODO(b/382291660): it is not safe to ignore this error
+                Ok(())
+            }
+
+            // `NONE` is not an event we should get in practice, but if it does then it
+            // shouldn't trigger an error.
+            _ if event == (sys::IPC_HANDLE_POLL_NONE as u32) => Ok(()),
+
+            // Treat any unrecognized events as errors by default.
+            _ => {
+                error!("Could not handle event {}", event);
+                Err(TipcError::UnknownError)
+            }
+        }
+    }
+}
diff --git a/lib/tipc/rust/src/raw/handle_set_wrapper.rs b/lib/tipc/rust/src/raw/handle_set_wrapper.rs
new file mode 100644
index 0000000..c79b5b5
--- /dev/null
+++ b/lib/tipc/rust/src/raw/handle_set_wrapper.rs
@@ -0,0 +1,605 @@
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
+//! A wrapper around the `RawHandleSet`, that is aware of the handle wrapper type stored in the
+//! raw handle set. The wrapper also enforces the limits on ports and connections per TA.
+use crate::raw::{service_handle::PortWrapper, HandleType, RawHandleSet, ServiceHandle};
+use crate::{
+    ConnectResult, Handle, MessageResult, PortCfg, Result, TipcError, UnbufferedService, Uuid,
+};
+use alloc::sync::Arc;
+use log::error;
+use std::collections::vec_deque::VecDeque;
+use std::sync::Mutex;
+use trusty_std::TryClone;
+
+/// Encapsulate a work item to call on_connect on a given service
+pub struct ToConnect<S: UnbufferedService> {
+    handle: Handle,
+    service: Arc<S>,
+    port: PortCfg,
+    // TODO: This should be removed in the long term
+    uuid: Uuid,
+}
+
+impl<S: UnbufferedService> ToConnect<S> {
+    /// Constructor
+    pub fn new(handle: Handle, service: Arc<S>, port: PortCfg, uuid: Uuid) -> Self {
+        Self { handle, service, port, uuid }
+    }
+
+    /// Handle on_connect work item
+    pub fn do_on_connect(&self) -> Result<ConnectResult<S::Connection>> {
+        self.service.on_connect(&self.port, &self.handle, &self.uuid)
+    }
+}
+
+/// Instructions about the work to do
+pub enum WorkToDo<S: UnbufferedService> {
+    Connect(ToConnect<S>),
+}
+
+/// A wrapper around the `RawHandleSet` exposed to the TAs and the event loop runner.
+pub struct HandleSetWrapper<S: UnbufferedService> {
+    // work queue should be emptied before waiting on the handle set
+    work_queue: Mutex<VecDeque<WorkToDo<S>>>,
+    handle_set: Mutex<RawHandleSet<ServiceHandle<S>>>,
+}
+
+impl<S: UnbufferedService> HandleSetWrapper<S> {
+    pub fn new() -> Result<Self> {
+        Ok(Self {
+            work_queue: Mutex::new(VecDeque::<WorkToDo<S>>::new()),
+            handle_set: Mutex::new(RawHandleSet::<ServiceHandle<S>>::new()?),
+        })
+    }
+
+    fn handle_work_queue(&self) -> Result<()> {
+        let mut wq = self.work_queue.lock().unwrap();
+        while let Some(work_item) = wq.pop_front() {
+            let WorkToDo::Connect(to_connect) = work_item;
+            match to_connect.do_on_connect()? {
+                ConnectResult::Accept(conn) => {
+                    return self
+                        .add_connection(conn, to_connect.handle, to_connect.service)
+                        .map(|_| ());
+                }
+                ConnectResult::CloseConnection => {
+                    error!("Connection closed by the service in on_connect.");
+                    return Err(TipcError::ChannelClosed);
+                }
+            }
+        }
+        Ok(())
+    }
+
+    /// Waits on the raw handle set and returns the event cookie object and the event.
+    pub fn wait(&self, timeout: Option<u32>) -> Result<(Arc<ServiceHandle<S>>, u32)> {
+        self.handle_work_queue()?;
+        let hs = self.handle_set.lock().unwrap();
+        hs.wait(timeout)
+    }
+
+    /// Add a port type connection to the handle set wrapper
+    pub fn add_port(&self, cfg: &PortCfg, service: Arc<S>) -> Result<PortWrapper<S>> {
+        // SAFETY: syscall, config path is borrowed and outlives the call.
+        // Return value is either a negative error code or a valid handle.
+        let rc = unsafe {
+            trusty_sys::port_create(
+                cfg.get_path().as_ptr(),
+                cfg.get_msg_queue_len(),
+                cfg.get_msg_max_size(),
+                cfg.get_flags(),
+            )
+        };
+        if rc < 0 {
+            Err(TipcError::from_uapi(rc))
+        } else {
+            let raw_handle_fd = rc as i32;
+            let handle = Handle::from_raw(raw_handle_fd)?;
+            let service_handle =
+                Arc::new(ServiceHandle::<S>::new_port_wrapper(cfg.try_clone()?, handle, service));
+            let hs = self.handle_set.lock().unwrap();
+            hs.register(service_handle.clone())?;
+            Ok(PortWrapper::new(self, service_handle))
+        }
+    }
+
+    /// Dispatch an event on a port handle
+    pub fn handle_connect(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<()> {
+        if let HandleType::Port(cfg) = &service_handle.ty {
+            let mut peer = Uuid::from_bytes(&[0; Uuid::UUID_BYTE_LEN]);
+            // SAFETY: syscall. The port owns its handle, so it is still valid as
+            // a raw fd. The peer structure outlives this call and is mutably
+            // borrowed by the call to initialize the structure's data.
+            let rc = unsafe {
+                trusty_sys::accept(service_handle.handle.as_raw_fd(), peer.as_mut_ptr()) as i32
+            };
+            let connection_handle = Handle::from_raw(rc)?;
+
+            // Check against access control list if we were given one
+            if let Some(uuids) = cfg.get_uuid_allow_list() {
+                if !uuids.contains(&peer) {
+                    error!("UUID {peer:?} isn't supported.\n");
+                    return Err(TipcError::SystemError(trusty_sys::Error::NotAllowed));
+                }
+            }
+            let connect_result =
+                service_handle.service.on_connect(&cfg, &connection_handle, &peer)?;
+            if let ConnectResult::Accept(conn) = connect_result {
+                self.add_connection(conn, connection_handle, Arc::clone(&service_handle.service))
+                    .map(|_| ())
+            } else {
+                error!("Connection closed");
+                return Err(TipcError::ChannelClosed);
+            }
+        } else {
+            error!("A port type handle is expected. Received: {:?}", &service_handle.ty);
+            return Err(TipcError::InvalidData);
+        }
+    }
+
+    /// Register a connection handle in the handle set
+    pub fn add_connection(
+        &self,
+        connection: S::Connection,
+        handle: Handle,
+        service: Arc<S>,
+    ) -> Result<()> {
+        let service_handle =
+            ServiceHandle::<S>::new_connection_wrapper(handle, service, connection);
+        let hs = self.handle_set.lock().unwrap();
+        hs.register(Arc::new(service_handle))
+    }
+
+    /// Dispatch an event on a port handle
+    pub fn handle_message(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<MessageResult> {
+        if let HandleType::Connection(conn) = &service_handle.ty {
+            service_handle.service.on_message(conn, &service_handle.handle, &mut [])
+        } else {
+            error!("A connection type handle is expected. Received: {:?}", &service_handle.ty);
+            return Err(TipcError::InvalidData);
+        }
+    }
+
+    /// Dispatch a connection close event
+    pub fn handle_disconnect(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<()> {
+        if let HandleType::Connection(conn) = &service_handle.ty {
+            service_handle.service.on_disconnect(conn)
+        } else {
+            error!("A connection type handle is expected. Received: {:?}", &service_handle.ty);
+            return Err(TipcError::InvalidData);
+        }
+        self.remove(service_handle)?;
+        Ok(())
+    }
+
+    /// Remove a handle from the handle set
+    pub fn remove(&self, service_handle: Arc<ServiceHandle<S>>) -> Result<()> {
+        let hs = self.handle_set.lock().unwrap();
+        hs.remove(service_handle)
+    }
+
+    /// Remove a handle from the handle set
+    pub fn remove_raw(&self, handle: i32) -> Result<Arc<ServiceHandle<S>>> {
+        let hs = self.handle_set.lock().unwrap();
+        hs.remove_raw(handle)
+    }
+
+    /// Add a work item
+    pub fn add_work(&self, todo: WorkToDo<S>) {
+        let mut wq = self.work_queue.lock().unwrap();
+        wq.push_back(todo);
+    }
+}
+
+#[cfg(test)]
+mod test {
+    use crate::handle::test::{first_free_handle_index, MAX_USER_HANDLES};
+    use crate::raw::{raw_handle_set::Handler, HandleSetWrapper};
+    use crate::{
+        ConnectResult, Handle, MessageResult, PortCfg, Result, Service, TipcError,
+        UnbufferedService, Uuid,
+    };
+    use alloc::sync::Arc;
+    use test::{expect, expect_eq};
+    use trusty_std::ffi::{CString, FallibleCString as _};
+    use trusty_sys::Error;
+
+    const SRV_PATH_BASE: &str = "com.android.ipc-raw-unittest";
+    /// Maximum length of port path name
+    const MAX_PORT_PATH_LEN: usize = 64;
+    /// Maximum number of buffers per port
+    const MAX_PORT_BUF_NUM: u32 = 64;
+
+    /// Maximum size of port buffer
+    const MAX_PORT_BUF_SIZE: u32 = 4096;
+
+    #[test]
+    fn port_create_negative() {
+        let path = [0u8; 0];
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let service = Arc::new(());
+        let cfg = PortCfg::new_raw(CString::try_new(&path[..]).unwrap());
+        let err = handle_set_wrapper.add_port(&cfg, service.clone()).err();
+        expect_eq!(err, Some(TipcError::SystemError(Error::InvalidArgs)), "empty server path");
+
+        let mut path = format!("{}.port", SRV_PATH_BASE);
+
+        let cfg = PortCfg::new(&path).unwrap().msg_queue_len(0);
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::InvalidArgs)),
+            "no buffers",
+        );
+
+        let cfg = PortCfg::new(&path).unwrap().msg_max_size(0);
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::InvalidArgs)),
+            "zero buffer size",
+        );
+
+        let cfg = PortCfg::new(&path).unwrap().msg_queue_len(MAX_PORT_BUF_NUM * 100);
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::InvalidArgs)),
+            "large number of buffers",
+        );
+
+        let cfg = PortCfg::new(&path).unwrap().msg_max_size(MAX_PORT_BUF_SIZE * 100);
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::InvalidArgs)),
+            "large buffers size",
+        );
+
+        while path.len() < MAX_PORT_PATH_LEN + 16 {
+            path.push('a');
+        }
+
+        let cfg = PortCfg::new(&path).unwrap();
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::InvalidArgs)),
+            "path is too long",
+        );
+    }
+
+    #[test]
+    fn port_create() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let mut ports = Vec::new();
+        let service = Arc::new(());
+
+        for i in first_free_handle_index()..MAX_USER_HANDLES - 2 {
+            let path = format!("{}.port.{}{}", SRV_PATH_BASE, "test", i);
+            let cfg = PortCfg::new(path).unwrap();
+            let result = handle_set_wrapper.add_port(&cfg, service.clone());
+            ports.push(result.unwrap());
+
+            expect_eq!(
+                handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+                Some(TipcError::SystemError(Error::AlreadyExists)),
+                "collide with existing port"
+            );
+        }
+        // Creating one more port should succeed
+        let path = format!("{}.port.{}{}", SRV_PATH_BASE, "test", MAX_USER_HANDLES - 1);
+        let cfg = PortCfg::new(path).unwrap();
+        let result = handle_set_wrapper.add_port(&cfg, service.clone());
+        expect!(result.is_ok(), "create one more port");
+
+        // but creating colliding port should fail with different error code
+        // because we actually exceeded max number of handles instead of
+        // colliding with an existing path
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::NoResources)),
+            "collide with existing port",
+        );
+
+        let path = format!("{}.port.{}{}", SRV_PATH_BASE, "test", MAX_USER_HANDLES);
+        let cfg = PortCfg::new(path).unwrap();
+        expect_eq!(
+            handle_set_wrapper.add_port(&cfg, service.clone()).err(),
+            Some(TipcError::SystemError(Error::NoResources)),
+            "max number of ports reached",
+        );
+    }
+
+    #[test]
+    fn add_port() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
+        let cfg = PortCfg::new(path).unwrap();
+        let service = Arc::new(());
+        {
+            let port_wrapper = handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 2);
+            expect_eq!(Arc::strong_count(&service), 2);
+        }
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn add_port_drop_wrapper() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
+        let cfg = PortCfg::new(path).unwrap();
+        let service = Arc::new(());
+        {
+            // This line ignores the returned wrapper, which immediately drops it.
+            handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&service), 1);
+        }
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn add_connection() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
+        let cfg = PortCfg::new(path).unwrap();
+        let service = Arc::new(());
+
+        // SAFETY: syscall, `cfg` is a local and outlives the call.
+        // The return value is either a negative error code or a valid handle.
+        let rc = unsafe {
+            trusty_sys::port_create(
+                cfg.get_path().as_ptr(),
+                cfg.get_msg_queue_len(),
+                cfg.get_msg_max_size(),
+                cfg.get_flags(),
+            )
+        };
+        expect!(rc >= 0, "created the connection handle");
+
+        let handle_fd = rc as i32;
+        let handle = Handle::from_raw(handle_fd).unwrap();
+        handle_set_wrapper.add_connection((), handle, service.clone()).unwrap();
+        expect_eq!(Arc::strong_count(&service), 2);
+        expect!(handle_set_wrapper.remove_raw(handle_fd).is_ok(), "removed the connection handle");
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn add_connection_invalid_handle() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let handle = Handle::from_raw(1063).unwrap();
+        let service = Arc::new(());
+
+        expect_eq!(
+            Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
+            handle_set_wrapper.add_connection((), handle, service.clone()),
+            "invalid handle"
+        );
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn remove() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
+        let cfg = PortCfg::new(path).unwrap();
+        let service = Arc::new(());
+        {
+            let port_wrapper = handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 2);
+            expect_eq!(Arc::strong_count(&service), 2);
+            expect!(handle_set_wrapper.remove(port_wrapper.service_handle.clone()).is_ok());
+            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 1);
+            expect_eq!(
+                Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
+                handle_set_wrapper.remove(port_wrapper.service_handle.clone()),
+                "handle already removed"
+            );
+        }
+        // `port_wrapper.service_handle` gets removed one more time here
+        // when port_wrapper is dropped. This emits an error message.
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn remove_raw() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let path = format!("{}.port.{}", SRV_PATH_BASE, "test");
+        let cfg = PortCfg::new(path).unwrap();
+        let service = Arc::new(());
+        {
+            let port_wrapper = handle_set_wrapper.add_port(&cfg, service.clone()).unwrap();
+            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 2);
+            expect_eq!(Arc::strong_count(&service), 2);
+            expect!(handle_set_wrapper
+                .remove_raw(port_wrapper.service_handle.get_raw_fd_id())
+                .is_ok());
+            expect_eq!(Arc::strong_count(&port_wrapper.service_handle), 1);
+            expect_eq!(
+                Err(TipcError::SystemError(trusty_sys::Error::NotFound)),
+                handle_set_wrapper.remove(port_wrapper.service_handle.clone())
+            );
+        }
+        // `port_wrapper.service_handle` gets removed one more time here
+        // when port_wrapper is dropped. This emits an error message.
+        expect_eq!(Arc::strong_count(&service), 1);
+    }
+
+    #[test]
+    fn wait_on_port() {
+        let handle_set_wrapper = HandleSetWrapper::<()>::new().unwrap();
+        let mut ports = Vec::new();
+        let service = Arc::new(());
+
+        for i in first_free_handle_index()..MAX_USER_HANDLES - 1 {
+            let path = format!("{}.port.{}{}", SRV_PATH_BASE, "test", i);
+            let cfg = PortCfg::new(path).unwrap();
+            let result = handle_set_wrapper.add_port(&cfg, service.clone());
+            ports.push(result.unwrap());
+        }
+
+        expect_eq!(
+            handle_set_wrapper.wait(Some(0)).err(),
+            Some(TipcError::SystemError(Error::TimedOut)),
+            "zero timeout"
+        );
+        expect_eq!(
+            handle_set_wrapper.wait(Some(100)).err(),
+            Some(TipcError::SystemError(Error::TimedOut)),
+            "non zero timeout"
+        );
+    }
+
+    struct Service1;
+
+    impl Service for Service1 {
+        type Connection = ();
+        type Message = ();
+
+        fn on_connect(
+            &self,
+            _port: &PortCfg,
+            _handle: &Handle,
+            _peer: &Uuid,
+        ) -> Result<ConnectResult<Self::Connection>> {
+            Ok(ConnectResult::Accept(()))
+        }
+
+        fn on_message(
+            &self,
+            _connection: &Self::Connection,
+            handle: &Handle,
+            _msg: Self::Message,
+        ) -> Result<MessageResult> {
+            handle.send(&1i32)?;
+            Ok(MessageResult::MaintainConnection)
+        }
+    }
+
+    struct Service2;
+
+    impl Service for Service2 {
+        type Connection = ();
+        type Message = ();
+
+        fn on_connect(
+            &self,
+            _port: &PortCfg,
+            _handle: &Handle,
+            _peer: &Uuid,
+        ) -> Result<ConnectResult<Self::Connection>> {
+            Ok(ConnectResult::Accept(()))
+        }
+
+        fn on_message(
+            &self,
+            _connection: &Self::Connection,
+            handle: &Handle,
+            _msg: Self::Message,
+        ) -> Result<MessageResult> {
+            handle.send(&2i32)?;
+            Ok(MessageResult::MaintainConnection)
+        }
+    }
+
+    enum WrapperService {
+        Service1(Service1),
+        Service2(Service2),
+    }
+
+    impl UnbufferedService for WrapperService {
+        type Connection = ();
+
+        fn on_connect(
+            &self,
+            port: &PortCfg,
+            handle: &Handle,
+            peer: &Uuid,
+        ) -> Result<ConnectResult<Self::Connection>> {
+            match self {
+                Self::Service1(service_1) => {
+                    match UnbufferedService::on_connect(service_1, port, handle, peer) {
+                        Ok(conn_result) => match conn_result {
+                            ConnectResult::Accept(conn) => Ok(ConnectResult::Accept(conn.into())),
+                            ConnectResult::CloseConnection => Ok(ConnectResult::CloseConnection),
+                        },
+                        Err(e) => Err(e),
+                    }
+                }
+
+                Self::Service2(service_2) => {
+                    match UnbufferedService::on_connect(service_2, port, handle, peer) {
+                        Ok(conn_result) => match conn_result {
+                            ConnectResult::Accept(conn) => Ok(ConnectResult::Accept(conn.into())),
+                            ConnectResult::CloseConnection => Ok(ConnectResult::CloseConnection),
+                        },
+                        Err(e) => Err(e),
+                    }
+                }
+            }
+        }
+
+        fn on_message(
+            &self,
+            connection: &Self::Connection,
+            handle: &Handle,
+            buffer: &mut [u8],
+        ) -> Result<MessageResult> {
+            match self {
+                Self::Service1(service_1) => UnbufferedService::on_message(
+                    service_1,
+                    connection.try_into().map_err(|_| TipcError::InvalidData)?,
+                    handle,
+                    buffer,
+                ),
+                Self::Service2(service_2) => UnbufferedService::on_message(
+                    service_2,
+                    connection.try_into().map_err(|_| TipcError::InvalidData)?,
+                    handle,
+                    buffer,
+                ),
+            }
+        }
+    }
+
+    #[test]
+    fn multiple_services() {
+        let handle_set_wrapper = Arc::new(HandleSetWrapper::new().unwrap());
+
+        let path_1 = format!("{}.port.{}", SRV_PATH_BASE, "testService1");
+        let cfg_1 = PortCfg::new(&path_1).unwrap();
+        let service_1 = Arc::new(WrapperService::Service1(Service1));
+
+        let path_2 = format!("{}.port.{}", SRV_PATH_BASE, "testService2");
+        let cfg_2 = PortCfg::new(&path_2).unwrap();
+        let service_2 = Arc::new(WrapperService::Service2(Service2));
+
+        {
+            let port_wrapper_1 =
+                handle_set_wrapper.add_port(&cfg_1, Arc::clone(&service_1)).unwrap();
+            let port_wrapper_2 =
+                handle_set_wrapper.add_port(&cfg_2, Arc::clone(&service_2)).unwrap();
+
+            expect_eq!(Arc::strong_count(&port_wrapper_1.service_handle), 2);
+            expect_eq!(Arc::strong_count(&service_1), 2);
+
+            expect_eq!(Arc::strong_count(&port_wrapper_2.service_handle), 2);
+            expect_eq!(Arc::strong_count(&service_2), 2);
+        }
+
+        expect_eq!(Arc::strong_count(&service_1), 1);
+        expect_eq!(Arc::strong_count(&service_2), 1);
+    }
+}
diff --git a/lib/tipc/rust/src/raw/mod.rs b/lib/tipc/rust/src/raw/mod.rs
new file mode 100644
index 0000000..cee03e3
--- /dev/null
+++ b/lib/tipc/rust/src/raw/mod.rs
@@ -0,0 +1,46 @@
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
+///! Entry point to a new tipc user space API. The goal of this module are three folds:
+///  1. the ability to share the handleset with the event loop as well as a
+///     service
+///  2. removing the dispatcher(present in the legacy Rust tipc library) from the event pipeline
+///  3. make the user space constructs thread safe, so that they can be shared with RPC binder
+///     services which has the thread safety requirement
+///
+///  A TA initialization code may use this API in the following manner to get the advantage of
+///  the aforementioned features.
+///  1. Create a `HandleSetWrapper` that manages a particular type of handle objects in an instance
+///     of a `RawHandleSet`.
+///  2. Create a tipc service that implements a given `*Service` trait
+///  3. Create a port type handle object containing a reference to the service and register it in
+///     the `HandleSetWrapper`.
+///  4. Give a reference of the `HandleSetWrapper` to the service, if the service needs to
+///     manipulate the `HandleSetWrapper`.
+///  5. Create the `EventLoop` with a reference to the HandleSetWrapper and run the `EventLoop`.
+///
+///  Note: This crate currently accommodates the services that implement the`UnbufferredService`
+///  trait only. It is a future work to implement a common `HandleSetWrapper` that can accommodate
+///  the services that implement the `Service` trait.
+mod event_loop;
+mod handle_set_wrapper;
+mod raw_handle_set;
+mod service_handle;
+
+pub use event_loop::EventLoop;
+pub use handle_set_wrapper::{HandleSetWrapper, ToConnect, WorkToDo};
+pub use raw_handle_set::{Handler, RawHandleSet};
+pub use service_handle::{HandleType, ServiceHandle};
diff --git a/lib/tipc/rust/src/raw/raw_handle_set.rs b/lib/tipc/rust/src/raw/raw_handle_set.rs
new file mode 100644
index 0000000..19e48bd
--- /dev/null
+++ b/lib/tipc/rust/src/raw/raw_handle_set.rs
@@ -0,0 +1,132 @@
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
+//! Define the raw handle set which registers in and removes from the handle set a given type of a
+//! handle. It waits on all the registered handles and returns the handle object along with the
+//! event when an event takes place in any of the handles.
+use crate::sys;
+use crate::{Handle, Result, TipcError};
+use alloc::sync::Arc;
+use core::ffi::c_void;
+use core::marker::PhantomData;
+
+/// Trait that should be implemented by a handle object that is passed into the `RawHandleSet`.
+pub trait Handler {
+    // Get the raw file descriptor corresponding to the handle object.
+    fn get_raw_fd_id(&self) -> i32;
+}
+
+/// Raw handle set parameterized by the type of the handle stored in the event cookie.
+pub struct RawHandleSet<H: Handler> {
+    // The handle that represents the handleset
+    handle: Handle,
+    data: PhantomData<H>,
+}
+
+impl<H: Handler> RawHandleSet<H> {
+    /// Constructor
+    pub fn new() -> Result<Self> {
+        // SAFETY: syscall, return value is either a negative error code or a
+        // valid handle.
+        let rc = unsafe { trusty_sys::handle_set_create() };
+        if rc < 0 {
+            Err(TipcError::from_uapi(rc))
+        } else {
+            let handle = Handle::from_raw(rc as i32)?;
+            Ok(RawHandleSet::<H> { handle, data: PhantomData })
+        }
+    }
+
+    /// Waits on the handles for events and returns the handle object that was registered in the
+    /// event cookie and the event flags.
+    pub fn wait(&self, timeout: Option<u32>) -> Result<(Arc<H>, u32)> {
+        let event = self.handle.wait(timeout)?;
+        let ptr = event.cookie;
+        let handle_obj =
+            // SAFETY: the `ptr` is the `Arc` that we registered in `register`. If we receive
+            // an event on a handle with this cookie, we return an `Arc` with a bumped ref count.
+            unsafe {
+                Arc::increment_strong_count(ptr);
+                Arc::from_raw(ptr.cast::<H>())
+            };
+        Ok((handle_obj, event.event))
+    }
+
+    /// Register a handle object as the event cookie along with the corresponding Handle.
+    pub fn register(&self, event_cookie_obj: Arc<H>) -> Result<()> {
+        let ret = self.do_set_ctrl(
+            sys::HSET_ADD as u32,
+            trusty_sys::uevent::ALL_EVENTS,
+            &event_cookie_obj,
+        );
+        if ret.is_ok() {
+            std::mem::forget(event_cookie_obj);
+        }
+        ret
+    }
+
+    /// Remove a previously registered handle object.
+    pub fn remove(&self, event_cookie_obj: Arc<H>) -> Result<()> {
+        self.remove_raw(event_cookie_obj.get_raw_fd_id()).map(|_| ())
+    }
+
+    /// Remove a previously registered handle object and return an arc to it.
+    pub fn remove_raw(&self, handle: i32) -> Result<Arc<H>> {
+        let mut uevt = trusty_sys::uevent { handle, event: 0, cookie: std::ptr::null_mut() };
+        // SAFETY: syscall. The uevent pointer points to a correctly initialized
+        // structure that is valid across the call. The handle for the handle set is valid for
+        // the same lifetime as self, so will remain valid at least as long as the handle object
+        // being added/modified.
+        let rc = unsafe {
+            trusty_sys::handle_set_ctrl(
+                self.handle.as_raw_fd(),
+                sys::HSET_DEL_GET_COOKIE,
+                &mut uevt,
+            )
+        };
+
+        if rc < 0 {
+            Err(TipcError::from_uapi(rc))
+        } else {
+            // SAFETY: the `cookie` is the `Arc` that we registered in `register`. Here, we
+            // successfully deleted the handle from the handle set and are returning its cookie.
+            unsafe { Ok(Arc::from_raw(uevt.cookie.cast::<H>())) }
+        }
+    }
+
+    // Add, update or remove the handle object (event cookie object) from the kernel handle set.
+    // This function should never be public.
+    // When this is called in the delete path, an arc to the deleted handle object is returned to
+    // caller, without dropping it, because the caller may need it for further processing.
+    fn do_set_ctrl(&self, cmd: u32, event: u32, event_cookie_obj: &Arc<H>) -> Result<()> {
+        let raw_handle_fd: i32 = event_cookie_obj.get_raw_fd_id();
+        let cookie = Arc::as_ptr(event_cookie_obj);
+        let mut uevt =
+            trusty_sys::uevent { handle: raw_handle_fd, event, cookie: cookie as *mut c_void };
+
+        // SAFETY: syscall. The uevent pointer points to a correctly initialized
+        // structure that is valid across the call. The handle for the handle set is valid for
+        // the same lifetime as self, so will remain valid at least as long as the handle object
+        // being added/modified.
+        let rc = unsafe { trusty_sys::handle_set_ctrl(self.handle.as_raw_fd(), cmd, &mut uevt) };
+
+        if rc < 0 {
+            Err(TipcError::from_uapi(rc))
+        } else {
+            Ok(())
+        }
+    }
+}
diff --git a/lib/tipc/rust/src/raw/service_handle.rs b/lib/tipc/rust/src/raw/service_handle.rs
new file mode 100644
index 0000000..af5ca4c
--- /dev/null
+++ b/lib/tipc/rust/src/raw/service_handle.rs
@@ -0,0 +1,94 @@
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
+///! A handle object type (i.e. a wrapper type for the `Handle`) that can be stored in the
+///! `RawHandleSet`. This is similar to `Channel`, except that this has a field to hold a reference
+///! to the service that corresponds to the `Handle`.
+use crate::{raw::HandleSetWrapper, raw::Handler, Handle, PortCfg, UnbufferedService};
+use alloc::sync::Arc;
+use core::fmt;
+use log::warn;
+
+/// A type of a handle object that can be stored in the `RawHandleSet`.
+pub struct ServiceHandle<S: UnbufferedService> {
+    pub(crate) handle: Handle,
+    pub(crate) service: Arc<S>,
+    pub(crate) ty: HandleType<S::Connection>,
+}
+
+pub struct PortWrapper<'a, S: UnbufferedService> {
+    pub(crate) handle_set_wrapper: &'a HandleSetWrapper<S>,
+    pub(crate) service_handle: Arc<ServiceHandle<S>>,
+}
+
+impl<'a, S: UnbufferedService> PortWrapper<'a, S> {
+    pub fn new(
+        handle_set_wrapper: &'a HandleSetWrapper<S>,
+        service_handle: Arc<ServiceHandle<S>>,
+    ) -> PortWrapper<'a, S> {
+        Self { handle_set_wrapper, service_handle }
+    }
+}
+
+impl<S: UnbufferedService> Drop for PortWrapper<'_, S> {
+    fn drop(&mut self) {
+        if let Err(error) = self.handle_set_wrapper.remove(self.service_handle.clone()) {
+            warn!("Failed to remove handle from the handle set: {error:?}");
+        };
+        let ref_count = Arc::strong_count(&self.service_handle);
+        if ref_count > 1 {
+            warn!("PortWrapper leaking handle {}", self.service_handle.get_raw_fd_id());
+        }
+    }
+}
+
+impl<S: UnbufferedService> ServiceHandle<S> {
+    /// Create a port type handle object
+    pub fn new_port_wrapper(cfg: PortCfg, handle: Handle, service: Arc<S>) -> Self {
+        Self { handle, service, ty: HandleType::Port(cfg) }
+    }
+    /// Create a connection type handle object
+    pub fn new_connection_wrapper(
+        handle: Handle,
+        service: Arc<S>,
+        connection: S::Connection,
+    ) -> Self {
+        Self { handle, service, ty: HandleType::Connection(connection) }
+    }
+}
+
+impl<S: UnbufferedService> Handler for ServiceHandle<S> {
+    fn get_raw_fd_id(&self) -> i32 {
+        self.handle.as_raw_fd()
+    }
+}
+
+/// Enum representing the type of the handle in the `ServiceHandle`.
+pub enum HandleType<C> {
+    /// Service port with a configuration describing the port
+    Port(PortCfg),
+
+    /// Client connection
+    Connection(C),
+}
+
+impl<C> fmt::Debug for HandleType<C> {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        match self {
+            HandleType::Port(cfg) => write!(f, "HandleType::Port({:?})", cfg),
+            HandleType::Connection(_) => write!(f, "HandleType::Connection"),
+        }
+    }
+}
diff --git a/lib/tipc/rust/src/serialization.rs b/lib/tipc/rust/src/serialization.rs
index f36dec4..13ce926 100644
--- a/lib/tipc/rust/src/serialization.rs
+++ b/lib/tipc/rust/src/serialization.rs
@@ -1,7 +1,7 @@
 use crate::{Handle, TipcError};
 use core::fmt::Debug;
 use core::{mem, slice};
-use zerocopy::AsBytes;
+use zerocopy::IntoBytes;
 
 /// A helper provided by the transport handle for the message type to serialize
 /// into.
diff --git a/lib/tipc/rust/src/service.rs b/lib/tipc/rust/src/service.rs
index 41d51f9..ffea901 100644
--- a/lib/tipc/rust/src/service.rs
+++ b/lib/tipc/rust/src/service.rs
@@ -126,6 +126,31 @@ impl PortCfg {
     pub fn allowed_uuids(self, uuids: &'static [Uuid]) -> Self {
         Self { uuid_allow_list: Some(uuids), ..self }
     }
+
+    /// Get path
+    pub fn get_path(&self) -> &CString {
+        &self.path
+    }
+
+    /// Get message max size
+    pub fn get_msg_max_size(&self) -> u32 {
+        self.msg_max_size
+    }
+
+    /// Get message queue length
+    pub fn get_msg_queue_len(&self) -> u32 {
+        self.msg_queue_len
+    }
+
+    /// Get flags
+    pub fn get_flags(&self) -> u32 {
+        self.flags
+    }
+
+    /// Get allowed UUIDs
+    pub fn get_uuid_allow_list(&self) -> Option<&'static [Uuid]> {
+        self.uuid_allow_list
+    }
 }
 
 impl TryClone for PortCfg {
@@ -241,7 +266,7 @@ impl<D: Dispatcher> Channel<D> {
 pub struct Uuid(trusty_sys::uuid);
 
 impl Uuid {
-    const UUID_BYTE_LEN: usize = std::mem::size_of::<trusty_sys::uuid>();
+    pub const UUID_BYTE_LEN: usize = std::mem::size_of::<trusty_sys::uuid>();
     // UUID_STR_SIZE is a u32, conversion to usize is correct on our targeted architectures
     // Subtracting 1 from UUID_STR_SIZE because we don't need the null terminator on the RUST
     // implementation.
@@ -274,6 +299,10 @@ impl Uuid {
         &self.0
     }
 
+    pub unsafe fn as_mut_ptr(&mut self) -> *mut trusty_sys::uuid {
+        &mut self.0
+    }
+
     pub fn new_from_string(uuid_str: &str) -> Result<Self> {
         // Helper function that first tries to convert the `uuid_element` bytes into a string and
         // then uses the provided `conversion_fn` to try to convert it into an integer, interpreting
@@ -365,6 +394,12 @@ impl fmt::Debug for Uuid {
     }
 }
 
+impl From<trusty_sys::uuid> for Uuid {
+    fn from(uuid: trusty_sys::uuid) -> Self {
+        Self(uuid)
+    }
+}
+
 impl alloc::string::ToString for Uuid {
     fn to_string(&self) -> String {
         format!("{:?}", self)
diff --git a/lib/trusty-log/src/lib.rs b/lib/trusty-log/src/lib.rs
index 1504c47..77736da 100644
--- a/lib/trusty-log/src/lib.rs
+++ b/lib/trusty-log/src/lib.rs
@@ -20,7 +20,7 @@
 
 use log::{Level, Log, Metadata, Record};
 use std::io::{stderr, Write};
-use std::sync::Once;
+use std::sync::OnceLock;
 
 /// Closure type that can be used by external callers to write a custom log formatter
 ///
@@ -118,8 +118,7 @@ fn default_log_function(record: &Record) -> String {
     format!("{} - {}\n", record.level(), record.args())
 }
 
-static mut LOGGER: Option<TrustyLogger> = None;
-static LOGGER_INIT: Once = Once::new();
+static LOGGER: OnceLock<TrustyLogger> = OnceLock::new();
 
 pub fn init() {
     init_with_config(TrustyLoggerConfig::default());
@@ -127,15 +126,7 @@ pub fn init() {
 
 pub fn init_with_config(config: TrustyLoggerConfig) {
     let log_level_filter = config.log_level.to_level_filter();
-    // SAFETY: We are using Once, so the mut global will only be written once even with multiple
-    // calls
-    let global_logger = unsafe {
-        LOGGER_INIT.call_once(|| {
-            LOGGER = Some(TrustyLogger::new(config));
-        });
-        // Logger is always Some(_) at this point, so we just unwrap it
-        LOGGER.as_ref().unwrap()
-    };
+    let global_logger = LOGGER.get_or_init(|| TrustyLogger::new(config));
     log::set_logger(global_logger).expect("Could not set global logger");
     log::set_max_level(log_level_filter);
 }
diff --git a/lib/trusty-std/rules.mk b/lib/trusty-std/rules.mk
index 3a6ed5c..baebe03 100644
--- a/lib/trusty-std/rules.mk
+++ b/lib/trusty-std/rules.mk
@@ -33,8 +33,8 @@ MODULE_LIBRARY_EXPORTED_DEPS += \
 else
 
 MODULE_DEPS += \
-	trusty/user/base/lib/libcore-rust/ \
-	trusty/user/base/lib/libcompiler_builtins-rust/ \
+	trusty/user/base/lib/libcore-rust \
+	trusty/user/base/lib/libcompiler_builtins-rust \
 
 endif
 
diff --git a/lib/trusty-std/src/lib.rs b/lib/trusty-std/src/lib.rs
index 5406172..383c1a6 100644
--- a/lib/trusty-std/src/lib.rs
+++ b/lib/trusty-std/src/lib.rs
@@ -37,7 +37,7 @@
 // min_specialization is only used to optimize CString::try_new(), so we can
 // remove it if needed
 #![feature(min_specialization)]
-#![feature(new_uninit)]
+#![cfg_attr(not(version("1.82")), feature(new_uninit))]
 #![cfg_attr(not(version("1.81")), feature(panic_info_message))]
 #![feature(slice_internals)]
 #![feature(slice_ptr_get)]
diff --git a/lib/unittest-rust/src/asserts.rs b/lib/unittest-rust/src/asserts.rs
index 9f9fb84..b4607f1 100644
--- a/lib/unittest-rust/src/asserts.rs
+++ b/lib/unittest-rust/src/asserts.rs
@@ -34,7 +34,6 @@ use std::fmt;
 use std::panic::Location;
 
 #[derive(Debug)]
-#[doc(hidden)]
 pub enum AssertKind {
     Eq,
     Ne,
@@ -43,7 +42,6 @@ pub enum AssertKind {
 
 #[cold]
 #[track_caller]
-#[doc(hidden)]
 pub fn assert_failed<T, U>(kind: AssertKind, left: &T, right: &U, args: Option<fmt::Arguments<'_>>)
 where
     T: fmt::Debug + ?Sized,
@@ -53,7 +51,7 @@ where
 }
 
 #[track_caller]
-pub fn assert_failed_inner(
+fn assert_failed_inner(
     kind: AssertKind,
     left: &dyn fmt::Debug,
     right: &dyn fmt::Debug,
@@ -90,19 +88,18 @@ pub fn assert_failed_inner(
     CONTEXT.fail(false);
 }
 
+#[cold]
 #[track_caller]
-#[doc(hidden)]
-pub fn assert_err<E: fmt::Display>(
+pub fn assert_ok_failed<E: fmt::Display>(
     result: &'static str,
-    err: &E,
+    err: E,
     args: Option<fmt::Arguments<'_>>,
 ) {
-    assert_err_inner(result, &*err, args);
+    assert_ok_failed_inner(result, &err, args);
 }
 
 #[track_caller]
-#[doc(hidden)]
-pub fn assert_err_inner(
+fn assert_ok_failed_inner(
     result: &'static str,
     err: &dyn fmt::Display,
     args: Option<fmt::Arguments<'_>>,
diff --git a/lib/unittest-rust/src/display.rs b/lib/unittest-rust/src/display.rs
new file mode 100644
index 0000000..0e64ab9
--- /dev/null
+++ b/lib/unittest-rust/src/display.rs
@@ -0,0 +1,168 @@
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
+use std::{
+    any::type_name,
+    fmt::{self, Debug, Display, Formatter},
+};
+
+/// Provides access to a best-effort implementation of [Display].
+///
+/// [BestEffortDisplay] creates a wrapper that implements [Display] for the
+/// provided type.
+///   * If `T` implements [Display], the wrapper will forward to `T`'s [Display]
+///     implementation.
+///   * If `T` does not implement [Display], but does implement [Debug], the
+///     wrapper will use to `T`'s [Debug] implementation.
+///   * If `T` implements neither [Display] nor [Debug], the wrapper will
+///     display `T`'s [type_name].
+///
+/// The wrapper should be created with the following expression. The
+/// [DisplayKind], [DebugKind], and [TypenameKind] traits need to be in scope.
+/// (` as _` is fine; the traits just need to be in scope for method resolution;
+/// the actual trait names don't need to be accessible.)
+///
+/// ```
+/// # fn example() -> impl std::fmt::Display {
+/// # let x: usize = 5;
+/// # use test::__internal_macro_utils::{
+/// #     BestEffortDisplay,
+/// #     DisplayKind as _,
+/// #     DebugKind as _,
+/// #     TypenameKind as _,
+/// # };
+/// (&&&BestEffortDisplay(&x)).display_kind().wrap(x)
+/// # }
+/// ```
+///
+/// # Examples
+///
+/// ```
+/// use test::__internal_macro_utils::BestEffortDisplay;
+///
+/// struct NeitherDisplayOrDebug;
+/// #[derive(Debug)]
+/// struct DebugOnlyType;
+/// struct DisplayType;
+///
+/// impl std::fmt::Display for DisplayType {
+///     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
+///         write!(f, "Fancy Description")
+///     }
+/// }
+///
+/// let a = DisplayType;
+/// let b = DebugOnlyType;
+/// let c = NeitherDisplayOrDebug;
+///
+/// use test::__internal_macro_utils::{DisplayKind as _, DebugKind as _, TypenameKind as _};
+/// let a = (&&&BestEffortDisplay(&a)).display_kind().wrap(a);
+/// let b = (&&&BestEffortDisplay(&b)).display_kind().wrap(b);
+/// let c = (&&&BestEffortDisplay(&c)).display_kind().wrap(c);
+///
+/// assert_eq!(a.to_string(), "Fancy Description");
+/// assert_eq!(b.to_string(), "DebugOnlyType");
+/// assert_eq!(c.to_string(),
+///            format!("value of type {}",
+///                    std::any::type_name::<NeitherDisplayOrDebug>()));
+/// ```
+///
+/// [BestEffortDisplay] is implemented with [autoref specialization], which has
+/// some limitations, namely that we have to know that `T` implements [Display]
+/// at `get`'s callsite. As a result, it's mostly only useful inside macros.
+/// Because the specialization has [more than two levels], we're acutually using
+/// auto*de*ref, which is why the usage requires calling `display_kind` on
+/// `&&&Self` (one more `&` than the highest priority `*Kind` impl).
+///
+/// Once stable Rust supports [min_specialization], this should be replaced to
+/// use that instead.
+///
+/// [autoref specialization]: https://github.com/dtolnay/case-studies/blob/master/autoref-specialization/README.md
+/// [more than two levels]: https://lukaskalbertodt.github.io/2019/12/05/generalized-autoref-based-specialization.html#using-autoderef-for--two-specialization-levels
+/// [min_specialization]: https://doc.rust-lang.org/nightly/unstable-book/language-features/min-specialization.html#min_specialization
+pub struct BestEffortDisplay<T>(pub T);
+
+// When calling `(&&&BestEffortDisplay(&x)).display_kind()`, autoderef
+// prioritizes the `DisplayKind` impl if it applies, then the `DebugKind` impl
+// if it applies, then `TypenameKind`, which always applies.
+impl<T: Display> DisplayKind for &&BestEffortDisplay<&T> {}
+impl<T: Debug> DebugKind for &BestEffortDisplay<&T> {}
+impl<T> TypenameKind for BestEffortDisplay<&T> {}
+
+/// Constructs [Display] wrappers for types that implement [Display].
+pub struct DisplayTag;
+/// Constructs [Display] wrappers for types that implement [Debug].
+pub struct DebugTag;
+/// Constructs [Display] wrappers for any type.
+pub struct TypenameTag;
+
+/// Implements [Display] by delegating to `T`'s [Display] implementation.
+pub struct DisplayDisplayer<T>(T);
+/// Implements [Display] by delegating to `T`'s [Debug] implementation.
+pub struct DebugDisplayer<T>(T);
+/// Implements [Display] by printing `T`'s [type_name].
+pub struct TypenameDisplayer<T>(T);
+
+pub trait DisplayKind {
+    #[inline]
+    fn display_kind(&self) -> DisplayTag {
+        DisplayTag
+    }
+}
+pub trait DebugKind {
+    #[inline]
+    fn display_kind(&self) -> DebugTag {
+        DebugTag
+    }
+}
+pub trait TypenameKind {
+    #[inline]
+    fn display_kind(&self) -> TypenameTag {
+        TypenameTag
+    }
+}
+
+impl DisplayTag {
+    pub fn wrap<T: Display>(self, t: T) -> DisplayDisplayer<T> {
+        DisplayDisplayer(t)
+    }
+}
+impl DebugTag {
+    pub fn wrap<T: Debug>(self, t: T) -> DebugDisplayer<T> {
+        DebugDisplayer(t)
+    }
+}
+impl TypenameTag {
+    pub fn wrap<T>(self, t: T) -> TypenameDisplayer<T> {
+        TypenameDisplayer(t)
+    }
+}
+
+impl<T: Display> Display for DisplayDisplayer<T> {
+    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
+        write!(f, "{}", self.0)
+    }
+}
+impl<T: Debug> Display for DebugDisplayer<T> {
+    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
+        write!(f, "{:?}", self.0)
+    }
+}
+impl<T> Display for TypenameDisplayer<T> {
+    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
+        write!(f, "value of type {}", type_name::<T>())
+    }
+}
diff --git a/lib/unittest-rust/src/lib.rs b/lib/unittest-rust/src/lib.rs
index 116c863..bd26845 100644
--- a/lib/unittest-rust/src/lib.rs
+++ b/lib/unittest-rust/src/lib.rs
@@ -46,9 +46,15 @@ pub use self::options::{ColorConfig, Options, OutputFormat, RunIgnored, ShouldPa
 pub use self::types::TestName::*;
 pub use self::types::*;
 
-pub mod asserts;
+#[doc(hidden)]
+pub mod __internal_macro_utils {
+    pub use crate::{asserts::*, display::*};
+}
+
+mod asserts;
 mod bench;
 mod context;
+mod display;
 mod macros;
 mod options;
 mod stats;
diff --git a/lib/unittest-rust/src/macros.rs b/lib/unittest-rust/src/macros.rs
index 565804c..a996f20 100644
--- a/lib/unittest-rust/src/macros.rs
+++ b/lib/unittest-rust/src/macros.rs
@@ -29,7 +29,8 @@
  * limitations under the License.
  */
 
-/// Expects two expressions are equal to each other (using [`PartialEq`]).
+/// Expects two expressions are equal to each other (using
+/// [std::cmp::PartialEq]).
 ///
 /// On failure, this macro will print the values of the expressions with their
 /// debug representations and signal the failure to the test framework. The test
@@ -53,11 +54,16 @@ macro_rules! expect_eq {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if !(*left_val == *right_val) {
-                    let kind = $crate::asserts::AssertKind::Eq;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::None);
+                    let kind = $crate::__internal_macro_utils::AssertKind::Eq;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::None
+                    );
                 }
             }
         }
@@ -66,18 +72,24 @@ macro_rules! expect_eq {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if !(*left_val == *right_val) {
-                    let kind = $crate::asserts::AssertKind::Eq;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::Some(core::format_args!($($arg)+)));
+                    let kind = $crate::__internal_macro_utils::AssertKind::Eq;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                 }
             }
         }
     });
 }
 
-/// Asserts that two expressions are equal to each other (using [`PartialEq`]).
+/// Asserts that two expressions are equal to each other (using
+/// [std::cmp::PartialEq]).
 ///
 /// Unlike [`core::assert_eq!`], this macro will not panic, but instead returns
 /// early from a test function.
@@ -100,11 +112,16 @@ macro_rules! assert_eq {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if !(*left_val == *right_val) {
-                    let kind = $crate::asserts::AssertKind::Eq;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::None);
+                    let kind = $crate::__internal_macro_utils::AssertKind::Eq;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::None
+                    );
                     return;
                 }
             }
@@ -114,11 +131,16 @@ macro_rules! assert_eq {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if !(*left_val == *right_val) {
-                    let kind = $crate::asserts::AssertKind::Eq;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::Some(core::format_args!($($arg)+)));
+                    let kind = $crate::__internal_macro_utils::AssertKind::Eq;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                     return;
                 }
             }
@@ -126,7 +148,8 @@ macro_rules! assert_eq {
     });
 }
 
-/// Expects that two expressions are not equal to each other (using [`PartialEq`]).
+/// Expects that two expressions are not equal to each other (using
+/// [std::cmp::PartialEq]).
 ///
 /// On failure, this macro will print the values of the expressions with their
 /// debug representations and signal the failure to the test framework. The test
@@ -150,11 +173,16 @@ macro_rules! expect_ne {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if *left_val == *right_val {
-                    let kind = $crate::asserts::AssertKind::Ne;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::None);
+                    let kind = $crate::__internal_macro_utils::AssertKind::Ne;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::None
+                    );
                 }
             }
         }
@@ -163,18 +191,24 @@ macro_rules! expect_ne {
         match (&($left), &($right)) {
             (left_val, right_val) => {
                 if *left_val == *right_val {
-                    let kind = $crate::asserts::AssertKind::Ne;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::Some(core::format_args!($($arg)+)));
+                    let kind = $crate::__internal_macro_utils::AssertKind::Ne;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                 }
             }
         }
     });
 }
 
-/// Asserts that two expressions are not equal to each other (using [`PartialEq`]).
+/// Asserts that two expressions are not equal to each other (using
+/// [std::cmp::PartialEq]).
 ///
 /// Unlike [`core::assert_ne!`], this macro will not panic, but instead returns
 /// early from a test function.
@@ -197,11 +231,16 @@ macro_rules! assert_ne {
         match (&$left, &$right) {
             (left_val, right_val) => {
                 if *left_val == *right_val {
-                    let kind = $crate::asserts::AssertKind::Ne;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::None);
+                    let kind = $crate::__internal_macro_utils::AssertKind::Ne;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::None
+                    );
                     return;
                 }
             }
@@ -211,11 +250,16 @@ macro_rules! assert_ne {
         match (&($left), &($right)) {
             (left_val, right_val) => {
                 if *left_val == *right_val {
-                    let kind = $crate::asserts::AssertKind::Ne;
-                    // The reborrows below are intentional. Without them, the stack slot for the
-                    // borrow is initialized even before the values are compared, leading to a
-                    // noticeable slow down.
-                    $crate::asserts::assert_failed(kind, &*left_val, &*right_val, core::option::Option::Some(core::format_args!($($arg)+)));
+                    let kind = $crate::__internal_macro_utils::AssertKind::Ne;
+                    // The reborrows below are intentional. Without them, the
+                    // stack slot for the borrow is initialized even before the
+                    // values are compared, leading to a noticeable slow down.
+                    $crate::__internal_macro_utils::assert_failed(
+                        kind,
+                        &*left_val,
+                        &*right_val,
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                     return;
                 }
             }
@@ -226,15 +270,24 @@ macro_rules! assert_ne {
 /// Asserts that a `Result` expression is `Ok`
 ///
 /// On failure, this macro will print an error message containing the `Err`
-/// (The `Err` value must implement [`std::fmt::Display`].) value and signal
-/// the failure to the test framework. On success, the macro expression will
-/// evaluate to the unwrapped `Ok` value.
+/// value and signal the failure to the test framework. On success, the macro
+/// expression will evaluate to the unwrapped `Ok` value.
 ///
 /// Like [`assert!`], this macro has a second form, where a custom error
 /// message can be provided with or without arguments for formatting. See
 /// [`core::fmt`] for syntax for this form. Expressions used as format arguments
 /// will only be evaluated if the assertion fails.
 ///
+/// Failures will include a best-effort representation of the error value in the
+/// error message. It will use the [std::fmt::Display], [std::fmt::Debug], or
+/// [std::any::type_name] in that order of priority, depending on which ones are
+/// implemented for the error type. (This is implemented with
+/// [autoderef specialization], so it will work for concrete types, but using it
+/// for unconstrained generic `T` will always use the [std::any::type_name]
+/// impl, regardless of what traits the type actually implements. Similarly, if
+/// the type is declared as `T: Debug`, the [std::fmt::Debug] impl will be
+/// invoked, even if the concrete type implements [std::fmt::Display] as well.)
+///
 /// # Examples
 ///
 /// ```
@@ -244,13 +297,26 @@ macro_rules! assert_ne {
 /// let y: Result<usize, String> = Ok(x);
 /// assert_ok!(y, "something went wrong; x was {}", x);
 /// ```
+///
+/// [autoderef specialization]: https://lukaskalbertodt.github.io/2019/12/05/generalized-autoref-based-specialization.html
 #[macro_export]
 macro_rules! assert_ok {
     ($result:expr $(,)?) => ({
         match ($result) {
             Ok(t) => t,
             Err(e) => {
-                $crate::asserts::assert_err(core::stringify!($result), &e, core::option::Option::None);
+                use $crate::__internal_macro_utils::{
+                    DisplayKind as _,
+                    DebugKind as _,
+                    TypenameKind as _,
+                };
+                $crate::__internal_macro_utils::assert_ok_failed(
+                    core::stringify!($result),
+                    (&&&$crate::__internal_macro_utils::BestEffortDisplay(&e))
+                        .display_kind()
+                        .wrap(e),
+                    core::option::Option::None
+                );
                 return;
             }
         }
@@ -259,7 +325,18 @@ macro_rules! assert_ok {
         match ($result) {
             Ok(t) => t,
             Err(e) => {
-                $crate::asserts::assert_err(core::stringify!($result), &e, core::option::Option::Some(core::format_args!($($arg)+)));
+                use $crate::__internal_macro_utils::{
+                    DisplayKind as _,
+                    DebugKind as _,
+                    TypenameKind as _,
+                };
+                $crate::__internal_macro_utils::assert_ok_failed(
+                    core::stringify!($result),
+                    (&&&$crate::__internal_macro_utils::BestEffortDisplay(&e))
+                        .display_kind()
+                        .wrap(e),
+                    core::option::Option::Some(core::format_args!($($arg)+))
+                );
                 return;
             }
         }
@@ -283,7 +360,10 @@ macro_rules! expect {
         match (&($cond)) {
             (cond) => {
                 if (!*cond) {
-                    $crate::asserts::simple_assert_failed(core::stringify!($cond), core::option::Option::None);
+                    $crate::__internal_macro_utils::simple_assert_failed(
+                        core::stringify!($cond),
+                        core::option::Option::None
+                    );
                 }
             }
         }
@@ -292,7 +372,10 @@ macro_rules! expect {
         match (&($cond)) {
             (cond) => {
                 if (!*cond) {
-                    $crate::asserts::simple_assert_failed(core::stringify!($cond), core::option::Option::Some(core::format_args!($($arg)+)));
+                    $crate::__internal_macro_utils::simple_assert_failed(
+                        core::stringify!($cond),
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                 }
             }
         }
@@ -316,7 +399,10 @@ macro_rules! assert {
         match (&($cond)) {
             (cond) => {
                 if (!*cond) {
-                    $crate::asserts::simple_assert_failed(core::stringify!($cond), core::option::Option::None);
+                    $crate::__internal_macro_utils::simple_assert_failed(
+                        core::stringify!($cond),
+                        core::option::Option::None
+                    );
                     return;
                 }
             }
@@ -326,7 +412,10 @@ macro_rules! assert {
         match (&($cond)) {
             (cond) => {
                 if (!*cond) {
-                    $crate::asserts::simple_assert_failed(core::stringify!($cond), core::option::Option::Some(core::format_args!($($arg)+)));
+                    $crate::__internal_macro_utils::simple_assert_failed(
+                        core::stringify!($cond),
+                        core::option::Option::Some(core::format_args!($($arg)+))
+                    );
                     return;
                 }
             }
@@ -344,11 +433,17 @@ macro_rules! assert {
 #[macro_export]
 macro_rules! fail {
     () => ({
-        $crate::asserts::simple_assert_failed("encountered test failure", core::option::Option::None);
+        $crate::__internal_macro_utils::simple_assert_failed(
+            "encountered test failure",
+            core::option::Option::None
+        );
         return;
     });
     ($($arg:tt)+) => ({
-        $crate::asserts::simple_assert_failed("encountered test failure", core::option::Option::Some(core::format_args!($($arg)+)));
+        $crate::__internal_macro_utils::simple_assert_failed(
+            "encountered test failure",
+            core::option::Option::Some(core::format_args!($($arg)+))
+        );
         return;
     });
 }
@@ -364,7 +459,11 @@ macro_rules! skip {
         return;
     });
     ($($arg:tt)+) => ({
-        std::eprintln!("test skipped: {}, {}", core::format_args!($($arg)+), std::panic::Location::caller());
+        std::eprintln!(
+            "test skipped: {}, {}",
+            core::format_args!($($arg)+),
+            std::panic::Location::caller()
+        );
         $crate::skip();
         return;
     });
diff --git a/lib/vmm_obj/rust/bindings.h b/lib/vmm_obj/rust/bindings.h
new file mode 100644
index 0000000..c2aa1ea
--- /dev/null
+++ b/lib/vmm_obj/rust/bindings.h
@@ -0,0 +1,17 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <lib/vmm_obj/vmm_obj.h>
diff --git a/lib/vmm_obj/rust/rules.mk b/lib/vmm_obj/rust/rules.mk
new file mode 100644
index 0000000..e8aeb33
--- /dev/null
+++ b/lib/vmm_obj/rust/rules.mk
@@ -0,0 +1,38 @@
+# Copyright (C) 2024 The Android Open Source Project
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
+MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
+
+MODULE_CRATE_NAME := vmm_obj
+
+MODULE_SDK_LIB_NAME := vmm_obj-rust
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/base/interface/system_state \
+	$(call FIND_CRATE,log) \
+	trusty/user/base/lib/trusty-std \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/vmm_obj \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	vmm_obj_.* \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+include make/library.mk
diff --git a/lib/vmm_obj/rust/src/lib.rs b/lib/vmm_obj/rust/src/lib.rs
new file mode 100644
index 0000000..240440e
--- /dev/null
+++ b/lib/vmm_obj/rust/src/lib.rs
@@ -0,0 +1,94 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+//! # Interface library for communicating with the vmm obj service.
+
+#![no_std]
+
+use core::ffi::CStr;
+use trusty_std::vec::Vec;
+use trusty_sys::c_void;
+
+#[allow(non_upper_case_globals)]
+#[allow(non_camel_case_types)]
+#[allow(unused)]
+pub mod sys {
+    include!(env!("BINDGEN_INC_FILE"));
+}
+
+#[derive(Debug)]
+pub enum GetVmmObjFailure {
+    NotFound,
+    BadSize,
+    BadStart,
+}
+
+/// A simple wrapper struct to call munmap on `Drop`.
+struct Mapped<'a>(&'a [u8]);
+
+impl<'a> Mapped<'_> {
+    /// # Safety
+    /// - `ptr` must be memory mmap-ed in this process and be readable for `sz` bytes while this struct is live.
+    /// - It must be sound to unmap this memory when this struct is dropped.
+    unsafe fn new(ptr: *const c_void, sz: usize) -> Self {
+        Self(unsafe { core::slice::from_raw_parts(ptr.cast(), sz) })
+    }
+}
+
+impl Drop for Mapped<'_> {
+    fn drop(&mut self) {
+        // SAFETY: This struct exists specifically to call munmap on mmap-ed memory. new is marked
+        // unsafe to discourage improper construction of this struct and details that ptr must be
+        // mapped in this process with the corresponding size.
+        let res = unsafe { libc::munmap(self.0.as_ptr() as *mut _, self.0.len()) };
+        if res != 0 {
+            log::error!("munmap failed!");
+        }
+    }
+}
+
+pub fn get_vmm_obj(name: &CStr) -> Result<Vec<u8>, GetVmmObjFailure> {
+    let mut ptr: *const c_void = std::ptr::null();
+    let mut sz: usize = 0;
+    // SAFETY:
+    // - `name.as_ptr()` points to as a valid, readable nul-terminated string as promised by CStr
+    // - ptr and sz have been initialized to valid values
+    // - references to name, ptr, and sz are not retained.
+    let rc = unsafe { crate::sys::vmm_obj_map_ro(name.as_ptr().cast(), &mut ptr, &mut sz) };
+    if rc < 0 || ptr.is_null() {
+        return Err(GetVmmObjFailure::NotFound);
+    }
+    // SAFETY: On success, vmm_obj_map_ro sets ptr to point to static immutable memory readable for
+    // sz bytes.
+    let buffer = unsafe { Mapped::new(ptr, sz) };
+    let start = u32::from_ne_bytes(
+        buffer
+            .0
+            .get(..4)
+            .ok_or(GetVmmObjFailure::BadStart)?
+            .try_into()
+            .map_err(|_| GetVmmObjFailure::BadStart)?,
+    ) as usize;
+    let sz = u32::from_ne_bytes(
+        buffer
+            .0
+            .get(4..8)
+            .ok_or(GetVmmObjFailure::BadSize)?
+            .try_into()
+            .map_err(|_| GetVmmObjFailure::BadSize)?,
+    ) as usize;
+    Ok(buffer.0.get(start..start + sz).ok_or(GetVmmObjFailure::BadSize)?.to_vec())
+}
diff --git a/make/aidl.mk b/make/aidl.mk
index e2e082b..b88f023 100644
--- a/make/aidl.mk
+++ b/make/aidl.mk
@@ -80,7 +80,7 @@ $(AIDL_SRCS): MODULE_AIDL_FLAGS := $(MODULE_AIDL_FLAGS)
 $(AIDL_SRCS): MODULE_AIDL_LANGUAGE := $(MODULE_AIDL_LANGUAGE)
 $(AIDL_SRCS): MODULE_AIDL_PACKAGE := $(MODULE_AIDL_PACKAGE)
 $(AIDL_SRCS): MODULE := $(MODULE)
-$(AIDL_SRCS): $(BUILDDIR)/%.$(AIDL_EXT): %.aidl
+$(AIDL_SRCS): $(BUILDDIR)/%.$(AIDL_EXT): %.aidl $(AIDL_TOOL)
 	@$(MKDIR)
 	@if [ -n "$(AIDL_HEADER_DIR)" ]; then mkdir -p $(AIDL_HEADER_DIR); fi
 	@$(call ECHO,$(MODULE),generating from AIDL,$@)
@@ -126,8 +126,8 @@ MODULE_LIBRARY_DEPS += \
 	$(call FIND_CRATE,async-trait) \
 	$(call FIND_CRATE,lazy_static) \
 
-# The AIDL compiler marks an aidl_data variable as mutable and rustc complains
-MODULE_RUSTFLAGS += -Aunused-mut -Aunused-variables
+# Disable all lints for auto-generated Rust sources
+MODULE_RUSTFLAGS += --cap-lints allow
 
 MODULE_SRCS += $(AIDL_ROOT_RS)
 MODULE_EXPORT_SRCDEPS += $(AIDL_ROOT_RS)
diff --git a/make/bindgen.mk b/make/bindgen.mk
index 596d8de..cbc255b 100644
--- a/make/bindgen.mk
+++ b/make/bindgen.mk
@@ -24,6 +24,7 @@
 # MODULE_BINDGEN_ALLOW_FUNCTIONS
 # MODULE_BINDGEN_ALLOW_TYPES
 # MODULE_BINDGEN_ALLOW_VARS
+# MODULE_BINDGEN_BLOCK_TYPES
 # MODULE_BINDGEN_CTYPES_PREFIX
 # MODULE_BINDGEN_FLAGS
 # MODULE_BINDGEN_OUTPUT_ENV_VAR
@@ -55,6 +56,7 @@ endif
 
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-var ,$(MODULE_BINDGEN_ALLOW_VARS))
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-type ,$(MODULE_BINDGEN_ALLOW_TYPES))
+MODULE_BINDGEN_FLAGS += $(addprefix --blocklist-type ,$(MODULE_BINDGEN_BLOCK_TYPES))
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-function ,$(MODULE_BINDGEN_ALLOW_FUNCTIONS))
 MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-file ,$(MODULE_BINDGEN_ALLOW_FILES))
 # other sanitizer flags if present will cause bindgen to fail unless we pass
@@ -116,6 +118,7 @@ MODULE_BINDGEN_ALLOW_FILES :=
 MODULE_BINDGEN_ALLOW_FUNCTIONS :=
 MODULE_BINDGEN_ALLOW_TYPES :=
 MODULE_BINDGEN_ALLOW_VARS :=
+MODULE_BINDGEN_BLOCK_TYPES :=
 MODULE_BINDGEN_CONFIG :=
 MODULE_BINDGEN_CTYPES_PREFIX :=
 MODULE_BINDGEN_DEFINES :=
diff --git a/make/library.mk b/make/library.mk
index 98e2732..c4aad50 100644
--- a/make/library.mk
+++ b/make/library.mk
@@ -300,6 +300,10 @@ define copy-headers-rule
 HEADERS := $$(shell cd "$(1)" 2>/dev/null && find -L . -type f)
 OUTPUT_HEADERS := $$(filter-out $$(MODULE_EXPORT_SDK_HEADERS),$$(addprefix $(TRUSTY_SDK_INCLUDE_DIR)/$(MODULE_SDK_HEADER_INSTALL_DIR)/,$$(HEADERS)))
 MODULE_EXPORT_SDK_HEADERS += $$(OUTPUT_HEADERS)
+# Create a fake dependency on configheader to trigger coping the file again
+# in case the copy source file path changes due to configuration change.
+# E.g. for headers copied from prebuilts/build-tools/sysroots/*
+$$(OUTPUT_HEADERS): $(CONFIGHEADER)
 $$(OUTPUT_HEADERS): $(TRUSTY_SDK_INCLUDE_DIR)/$(MODULE_SDK_HEADER_INSTALL_DIR)/% : $(1)/% $(MODULE_SRCDEPS)
 	@$$(MKDIR)
 	$$(NOECHO)cp -L $$< $$@
diff --git a/make/userspace_recurse.mk b/make/userspace_recurse.mk
index f8a310b..f7f9574 100644
--- a/make/userspace_recurse.mk
+++ b/make/userspace_recurse.mk
@@ -97,6 +97,7 @@ SAVED_$(MODULE)_RUST_EDITION := $(MODULE_RUST_EDITION)
 SAVED_$(MODULE)_RUST_TESTS := $(MODULE_RUST_TESTS)
 SAVED_$(MODULE)_BINDGEN_ALLOW_VARS := $(MODULE_BINDGEN_ALLOW_VARS)
 SAVED_$(MODULE)_BINDGEN_ALLOW_TYPES := $(MODULE_BINDGEN_ALLOW_TYPES)
+SAVED_$(MODULE)_BINDGEN_BLOCK_TYPES := $(MODULE_BINDGEN_BLOCK_TYPES)
 SAVED_$(MODULE)_BINDGEN_ALLOW_FUNCTIONS := $(MODULE_BINDGEN_ALLOW_FUNCTIONS)
 SAVED_$(MODULE)_BINDGEN_CTYPES_PREFIX := $(MODULE_BINDGEN_CTYPES_PREFIX)
 SAVED_$(MODULE)_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
@@ -205,6 +206,7 @@ MODULE_RUST_EDITION :=
 MODULE_RUST_TESTS :=
 MODULE_BINDGEN_ALLOW_VARS :=
 MODULE_BINDGEN_ALLOW_TYPES :=
+MODULE_BINDGEN_BLOCK_TYPES :=
 MODULE_BINDGEN_ALLOW_FUNCTIONS :=
 MODULE_BINDGEN_CTYPES_PREFIX :=
 MODULE_BINDGEN_FLAGS :=
@@ -307,6 +309,7 @@ MODULE_RUST_EDITION := $(SAVED_$(MODULE)_RUST_EDITION)
 MODULE_RUST_TESTS := $(SAVED_$(MODULE)_RUST_TESTS)
 MODULE_BINDGEN_ALLOW_VARS := $(SAVED_$(MODULE)_BINDGEN_ALLOW_VARS)
 MODULE_BINDGEN_ALLOW_TYPES := $(SAVED_$(MODULE)_BINDGEN_ALLOW_TYPES)
+MODULE_BINDGEN_BLOCK_TYPES := $(SAVED_$(MODULE)_BINDGEN_BLOCK_TYPES)
 MODULE_BINDGEN_ALLOW_FUNCTIONS := $(SAVED_$(MODULE)_BINDGEN_ALLOW_FUNCTIONS)
 MODULE_BINDGEN_CTYPES_PREFIX := $(SAVED_$(MODULE)_BINDGEN_CTYPES_PREFIX)
 MODULE_BINDGEN_FLAGS := $(SAVED_$(MODULE)_BINDGEN_FLAGS)
diff --git a/usertests-rust-inc.mk b/usertests-rust-inc.mk
index 9ede37c..d97deb4 100644
--- a/usertests-rust-inc.mk
+++ b/usertests-rust-inc.mk
@@ -13,9 +13,19 @@
 # limitations under the License.
 #
 
+TRUSTY_BUILTIN_USER_TASKS += \
+	trusty/user/base/lib/service_manager/tests/fake_accessor \
+	trusty/user/base/lib/service_manager/tests/test_service \
+
+# TRUSTY_BUILTIN_USER_TASKS += \
+#  	trusty/user/base/lib/service_manager/tests/test_service \
+
 TRUSTY_RUST_USER_TESTS += \
-	trusty/user/base/lib/tipc/rust \
+	packages/modules/Virtualization/libs/dice/open_dice/tests \
 	trusty/user/base/lib/hwkey/rust \
 	trusty/user/base/lib/hwbcc/rust \
 	trusty/user/base/lib/hwwsk/rust \
+	trusty/user/base/lib/pvmdice \
 	trusty/user/base/lib/storage/rust \
+	trusty/user/base/lib/service_manager/tests \
+	trusty/user/base/lib/tipc/rust \
```

