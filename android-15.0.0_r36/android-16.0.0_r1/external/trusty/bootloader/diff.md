```diff
diff --git a/ql-tipc/include/trusty/arm_ffa.h b/ql-tipc/include/trusty/arm_ffa.h
index ee7bda8..1e0ffc4 100644
--- a/ql-tipc/include/trusty/arm_ffa.h
+++ b/ql-tipc/include/trusty/arm_ffa.h
@@ -55,6 +55,11 @@
 
 #define FFA_PAGE_SIZE (4096)
 
+#define FFA_PACK_SRC_DST(src_id, dst_id) (((uint32_t)src_id << 16) | dst_id)
+#define FFA_PACK_DST_CPU(dst_id, cpu_id) (((uint32_t)dst_id << 16) | cpu_id)
+
+#define FFA_PACK_RXTX_UNMAP_ID(vm_id) (((uint32_t)vm_id << 16) | 0)
+
 /**
  * typedef ffa_endpoint_id16_t - Endpoint ID
  *
@@ -281,6 +286,25 @@ struct ffa_mem_relinquish_descriptor {
 };
 STATIC_ASSERT(sizeof(struct ffa_mem_relinquish_descriptor) == 16);
 
+/**
+ * struct ffa_partition_info - FFA partition info descriptor.
+ * @id:
+ *         16-bit ID of the partition
+ * @execution_ctx_count:
+ *         Number of execution contexts implemented by this partition
+ * @properties:
+ *         Flags to determine partition properties. Like direct/indirect
+ *         messages send/receive capabilities.
+ */
+struct ffa_partition_info {
+    uint16_t id;
+    uint16_t execution_ctx_count;
+    uint32_t properties;
+};
+
+/* partition property: Supports receipt of direct requests */
+#define FFA_PARTITION_DIRECT_REQ_RECV (1U << 0)
+
 /**
  * typedef ffa_features2_t - FFA_FEATURES values returned in w2
  *
@@ -389,6 +413,16 @@ enum ffa_error {
  */
 #define SMC_FC64_FFA_SUCCESS SMC_FASTCALL64_NR_SHARED_MEMORY(0x61)
 
+/**
+ * SMC_FC_FFA_INTERRUPT - 32 bit SMC for FFA interrupt opcode
+ *
+ * Register arguments:
+ *
+ * * w1:     VMID in [31:16], vCPU in [15:0]
+ * * w2:     Interrupt ID
+ */
+#define SMC_FC_FFA_INTERRUPT SMC_FASTCALL_NR_SHARED_MEMORY(0x62)
+
 /**
  * SMC_FC_FFA_VERSION - SMC opcode to return supported FF-A version
  *
@@ -430,6 +464,20 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_FEATURES SMC_FASTCALL_NR_SHARED_MEMORY(0x64)
 
+/**
+ * SMC_FC_FFA_RX_RELEASE - SMC opcode to Relinquish ownership of a RX buffer
+ *
+ * Return:
+ * * w0:     &SMC_FC_FFA_SUCCESS
+ *
+ * or
+ *
+ * * w0:     &SMC_FC_FFA_ERROR
+ * * w2:     %FFA_ERROR_DENIED Caller did not have ownership of the RX buffer.
+ *           %FFA_ERROR_NOT_SUPPORTED if operation not supported
+ */
+#define SMC_FC_FFA_RX_RELEASE SMC_FASTCALL_NR_SHARED_MEMORY(0x65)
+
 /**
  * SMC_FC_FFA_RXTX_MAP - 32 bit SMC opcode to map message buffers
  *
@@ -470,6 +518,18 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_RXTX_UNMAP SMC_FASTCALL_NR_SHARED_MEMORY(0x67)
 
+/**
+ * SMC_FC_FFA_PARTITION_INFO_GET - SMC opcode to get partition details
+ *
+ * Register arguments:
+ * * w1-w4:  Partition's UUID
+ *
+ * Return:
+ * * w0:     &SMC_FC_FFA_SUCCESS
+ * * w2:     ID in bit[15:0], bit[31:16] must be 0.
+ */
+#define SMC_FC_FFA_PARTITION_INFO_GET SMC_FASTCALL_NR_SHARED_MEMORY(0x68)
+
 /**
  * SMC_FC_FFA_ID_GET - SMC opcode to get endpoint id of caller
  *
@@ -479,6 +539,62 @@ enum ffa_error {
  */
 #define SMC_FC_FFA_ID_GET SMC_FASTCALL_NR_SHARED_MEMORY(0x69)
 
+/**
+ * SMC_FC_FFA_MSG_WAIT - 32 bit SMC opcode to used by the Receiver when
+ * it transfers execution back to the Sender.
+ *
+ * Register arguments:
+ * * w2:     Flags
+ */
+#define SMC_FC_FFA_MSG_WAIT SMC_FASTCALL_NR_SHARED_MEMORY(0x6B)
+
+/**
+ * SMC_FC_FFA_RUN - 32 bit SMC opcode to used by the Sender to resume a
+ * preempted Receiver.
+ *
+ * Register arguments:
+ * * w1:     Information to identify target SP/VM.
+ *
+ * Return:
+ * * w0:     &SMC_FC_FFA_SUCCESS, &SMC_FC_FFA_MSG_WAIT, or &SMC_FC_FFA_ERROR
+ */
+#define SMC_FC_FFA_RUN SMC_FASTCALL_NR_SHARED_MEMORY(0x6D)
+
+/**
+ * SMC_FC_FFA_MSG_SEND_DIRECT_REQ - 32 bit SMC opcode to send message as a
+ * request to a receiver endpoint.
+ *
+ * Register arguments
+ * * w1:     Sender and Receiver endpoint IDs.
+ * * w2:     Message flags.
+ *           bit[31]   : Message type. 0 for partition message and 1 for
+ *                       framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : Framework message type. Must be 0 if partition message.
+ * * w3-w7:  Implementation defined.
+ *
+ * Return:
+ * * w0:     &SMC_FC_FFA_MSG_SEND_DIRECT_RESP or &SMC_FC_FFA_INTERRUPT or
+ *           &SMC_FC_FFA_SUCCESS
+ */
+#define SMC_FC_FFA_MSG_SEND_DIRECT_REQ SMC_FASTCALL_NR_SHARED_MEMORY(0x6F)
+
+/**
+ * SMC_FC_FFA_MSG_SEND_DIRECT_RESP - 32 SMC opcode to send message as a response
+ * to a target endpoint.
+ *
+ * Register arguments:
+ *
+ * * w1:     Sender ID in bit[31:16], receiver ID in [15:0]
+ * * w2:     Message Flags.
+ *           bit[31]   : Message type. 0 for partition message and 1 for
+ *                       framework message.
+ *           bit[30:8] : Reserved. Must be 0.
+ *           bit[7:0]  : Framework message type. Must be 0 if partition message.
+ * * w3-w7:  Implementation defined.
+ */
+#define SMC_FC_FFA_MSG_SEND_DIRECT_RESP SMC_FASTCALL_NR_SHARED_MEMORY(0x70)
+
 /**
  * SMC_FC_FFA_MEM_DONATE - 32 bit SMC opcode to donate memory
  *
diff --git a/ql-tipc/include/trusty/smcall.h b/ql-tipc/include/trusty/smcall.h
index c480be3..21579fb 100644
--- a/ql-tipc/include/trusty/smcall.h
+++ b/ql-tipc/include/trusty/smcall.h
@@ -159,4 +159,83 @@
     SMC_STDCALL_NR(SMC_ENTITY_TRUSTED_OS, 32)
 #define SMC_FC_HANDLE_QL_TIPC_DEV_CMD SMC_FASTCALL_NR(SMC_ENTITY_TRUSTED_OS, 32)
 
+/**
+ * TRUSTY_FFA_MSG_RUN_FASTCALL - Run a Trusty fastcall synchronously.
+ *
+ * @r3: The value of %TRUSTY_FFA_MSG_RUN_FASTCALL.
+ * @r4: The fid of the Trusty fastcall.
+ * @r5: The 1st argument of the fastcall.
+ * @r6: The 2nd argument of the fastcall.
+ * @r7: The 3rd argument of the fastcall.
+ *
+ * Execute a Trusty fastcall synchronously with interrupts disabled,
+ * blocking until it completes and returning its result directly
+ * as a direct message response.
+ */
+#define TRUSTY_FFA_MSG_RUN_FASTCALL (0)
+
+/**
+ * TRUSTY_FFA_MSG_QUEUE_STDCALL - Asynchronously queue a Trusty stdcall.
+ *
+ * @r3: The value of %TRUSTY_FFA_MSG_QUEUE_STDCALL.
+ * @r4: The fid of the Trusty stdcall.
+ * @r5: The 1st argument of the stdcall.
+ * @r6: The 2nd argument of the stdcall.
+ * @r7: The 3rd argument of the stdcall.
+ *
+ * Queue a Trusty stdcall asynchronously for execution in the stdcall thread.
+ * The non-secure world should assign cycles to Trusty separately and
+ * call %TRUSTY_FFA_MSG_GET_STDCALL_RET to check if the call completed.
+ *
+ * Returns 0 on success, or %SM_ERR_BUSY if Trusty has another queued stdcall.
+ */
+#define TRUSTY_FFA_MSG_QUEUE_STDCALL (1)
+
+/**
+ * TRUSTY_FFA_MSG_GET_STDCALL_RET - Get the result of a Trusty stdcall.
+ *
+ * @r3: [out] The result of the call.
+ *
+ * The non-secure world should call this interface to
+ * retrieve the result of a previously queued stdcall.
+ * The request will return %SM_ERR_CPU_IDLE if the stdcall is still running.
+ */
+#define TRUSTY_FFA_MSG_GET_STDCALL_RET (2)
+
+/**
+ * TRUSTY_FFA_MSG_RUN_NOPCALL - Run the Trusty handler for a nopcall.
+ *
+ * @r3: The value of %TRUSTY_FFA_MSG_RUN_NOPCALL.
+ * @r4: The 1st argument of the nopcall.
+ * @r5: The 2nd argument of the nopcall.
+ * @r6: The 3rd argument of the nopcall.
+ *
+ * Returns 0 in @r3 on success, or one of the libsm error codes
+ * in case of failure.
+ *
+ * Execute a Trusty nopcall handler synchronously with interrupts disabled,
+ * blocking until it completes and returning its result directly
+ * as a direct message response. If Trusty should get more cycles to run
+ * the second half of the nopcall (triggered by the handler), it should
+ * signal the primary scheduler to enqueue a Trusty NOP.
+ */
+#define TRUSTY_FFA_MSG_RUN_NOPCALL (3)
+
+/**
+ * TRUSTY_FFA_MSG_IS_IDLE - Check if Trusty is idle on the current CPU.
+ *
+ * Return:
+ * * 1 in @r3 if the current CPU is idle
+ * * 0 if Trusty is busy (e.g. was interrupted)
+ * * One of the libsm error codes in case of error
+ *
+ * The non-secure scheduler needs to know if Trusty is idle to determine
+ * whether to give it more CPU cycles when it gets preempted. On Linux,
+ * we use the shadow priority but that requires sharing the sched-share state
+ * between NS and Trusty. %TRUSTY_FFA_MSG_IS_IDLE is a backup direct message
+ * that returns the same information to environments where this structure
+ * is not already shared, e.g., in bootloaders.
+ */
+#define TRUSTY_FFA_MSG_IS_IDLE (4)
+
 #endif /* QL_TIPC_SMCALL_H_ */
diff --git a/ql-tipc/include/trusty/sysdeps.h b/ql-tipc/include/trusty/sysdeps.h
index bd44b2d..5355d68 100644
--- a/ql-tipc/include/trusty/sysdeps.h
+++ b/ql-tipc/include/trusty/sysdeps.h
@@ -66,6 +66,8 @@ struct trusty_dev;
  */
 void trusty_lock(struct trusty_dev* dev);
 void trusty_unlock(struct trusty_dev* dev);
+/* Get the current CPU id */
+unsigned long trusty_get_cpu_num(void);
 /*
  * Disable/enable IRQ interrupts and save/restore @state
  */
diff --git a/ql-tipc/include/trusty/trusty_dev.h b/ql-tipc/include/trusty/trusty_dev.h
index 5e91170..ff85403 100644
--- a/ql-tipc/include/trusty/trusty_dev.h
+++ b/ql-tipc/include/trusty/trusty_dev.h
@@ -42,6 +42,7 @@ struct trusty_dev {
     uint16_t ffa_remote_id;
     void* ffa_tx;
     void* ffa_rx;
+    bool ffa_supports_direct_recv;
 };
 
 /*
@@ -60,10 +61,22 @@ int trusty_dev_shutdown(struct trusty_dev* dev);
  */
 int trusty_dev_nop(struct trusty_dev* dev);
 
-/*
- * Initialize the interrupt controller
+/**
+ * trusty_fast_call32() - Do a fastcall into Trusty.
+ *
+ * @dev:   trusty device, initialized with trusty_dev_init
+ * @smcnr: SMC fid number
+ * @a0:    1st argument
+ * @a1:    2nd argument
+ * @a2:    3rd argument
+ *
+ * Return: libsm error code.
  */
-int arch_gic_init(int cpu);
+int32_t trusty_fast_call32(struct trusty_dev* dev,
+                           uint32_t smcnr,
+                           uint32_t a0,
+                           uint32_t a1,
+                           uint32_t a2);
 
 /*
  * Invokes creation of queueless Trusty IPC device on the secure side.
diff --git a/ql-tipc/trusty_dev_common.c b/ql-tipc/trusty_dev_common.c
index 92901e2..01a53fb 100644
--- a/ql-tipc/trusty_dev_common.c
+++ b/ql-tipc/trusty_dev_common.c
@@ -34,6 +34,8 @@ struct trusty_dev;
 
 #define LOCAL_LOG 0
 
+#define TRUSTY_FFA_RXTX_PAGE_COUNT 1
+
 /*
  * Select RXTX map smc variant based on register size. Note that the FF-A spec
  * does not support passing a 64 bit paddr from a 32 bit client, so the
@@ -42,15 +44,172 @@ struct trusty_dev;
 #define SMC_FCZ_FFA_RXTX_MAP \
     ((sizeof(unsigned long) <= 4) ? SMC_FC_FFA_RXTX_MAP : SMC_FC64_FFA_RXTX_MAP)
 
-static int32_t trusty_fast_call32(struct trusty_dev* dev,
-                                  uint32_t smcnr,
-                                  uint32_t a0,
-                                  uint32_t a1,
-                                  uint32_t a2) {
+__attribute__((weak)) unsigned long trusty_get_cpu_num(void) {
+    trusty_fatal(
+            "%s: weak default called, "
+            "might return the wrong CPU number\n",
+            __func__);
+}
+
+static int trusty_ffa_send_direct_msg(struct trusty_dev* dev,
+                                      unsigned long msg,
+                                      unsigned long a0,
+                                      unsigned long a1,
+                                      unsigned long a2,
+                                      unsigned long a3) {
+    struct smc_ret8 smc_ret;
+    uint32_t src_dst;
+
+    src_dst = FFA_PACK_SRC_DST(dev->ffa_local_id, dev->ffa_remote_id);
+
+    /* 32bit FFA call for direct message request/response */
+    smc_ret = smc8(SMC_FC_FFA_MSG_SEND_DIRECT_REQ, src_dst, 0, msg, a0, a1, a2,
+                   a3);
+
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_INTERRUPT:
+        /*
+         * Trusty supports managed exit so it should return from an interrupt
+         * cleanly. We should never see an FFA_INTERRUPT here.
+         */
+        trusty_error("unexpected FFA_INTERRUPT(0x%x, 0x%x)\n",
+                     (uint32_t)smc_ret.r1, (uint32_t)smc_ret.r2);
+        return SM_ERR_INTERNAL_FAILURE;
+
+    case SMC_FC_FFA_ERROR:
+        trusty_error("unexpected FFA_ERROR(0x%x, 0x%x)\n", (uint32_t)smc_ret.r1,
+                     (uint32_t)smc_ret.r2);
+        return SM_ERR_INTERNAL_FAILURE;
+
+    case SMC_FC_FFA_MSG_SEND_DIRECT_RESP:
+        return smc_ret.r3;
+
+    default:
+        trusty_error("unknown FF-A result: 0x%x\n", (uint32_t)smc_ret.r0);
+        return SM_ERR_INTERNAL_FAILURE;
+    }
+}
+
+static int trusty_ffa_run(struct trusty_dev* dev) {
+    struct smc_ret8 smc_ret;
+    uint32_t dst_cpu;
+
+    dst_cpu = FFA_PACK_DST_CPU(dev->ffa_remote_id,
+                               (uint16_t)trusty_get_cpu_num());
+
+    smc_ret = smc8(SMC_FC_FFA_RUN, dst_cpu, 0, 0, 0, 0, 0, 0);
+
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_INTERRUPT:
+        /*
+         * Trusty supports managed exit so it should return from an interrupt
+         * cleanly. We should never see an FFA_INTERRUPT here.
+         */
+        trusty_error("unexpected FFA_INTERRUPT(0x%x, 0x%x)\n",
+                     (uint32_t)smc_ret.r1, (uint32_t)smc_ret.r2);
+        return SM_ERR_INTERNAL_FAILURE;
+
+    case SMC_FC_FFA_ERROR:
+        trusty_error("unexpected FFA_ERROR(0x%x, 0x%x)\n", (uint32_t)smc_ret.r1,
+                     (uint32_t)smc_ret.r2);
+        return SM_ERR_INTERNAL_FAILURE;
+
+    case SMC_FC_FFA_SUCCESS:
+    case SMC_FC_FFA_MSG_WAIT:
+        return trusty_ffa_send_direct_msg(dev, TRUSTY_FFA_MSG_IS_IDLE, 0, 0, 0,
+                                          0);
+
+    default:
+        trusty_error("unknown FF-A result: 0x%x\n", (uint32_t)smc_ret.r0);
+        return SM_ERR_INTERNAL_FAILURE;
+    }
+}
+
+static uint32_t trusty_ffa_call(struct trusty_dev* dev,
+                                unsigned long fid,
+                                unsigned long a0,
+                                unsigned long a1,
+                                unsigned long a2) {
+    int ret;
+
+    if (SMC_IS_FASTCALL(fid)) {
+        return trusty_ffa_send_direct_msg(dev, TRUSTY_FFA_MSG_RUN_FASTCALL, fid,
+                                          a0, a1, a2);
+    }
+
+    if (fid == SMC_SC_NOP) {
+        if (a0) {
+            ret = trusty_ffa_send_direct_msg(dev, TRUSTY_FFA_MSG_RUN_NOPCALL,
+                                             a0, a1, a2, 0);
+            if (ret) {
+                return ret;
+            }
+        }
+
+        ret = trusty_ffa_run(dev);
+        switch (ret) {
+        case 1:
+            /* Trusty is idle, we are done */
+            return SM_ERR_NOP_DONE;
+        case 0:
+            /* Trusty has more work to do, keep running it */
+            return SM_ERR_NOP_INTERRUPTED;
+        default:
+            return ret;
+        }
+    }
+
+    if (fid != SMC_SC_RESTART_LAST) {
+        ret = trusty_ffa_send_direct_msg(dev, TRUSTY_FFA_MSG_QUEUE_STDCALL, fid,
+                                         a0, a1, a2);
+        if (ret) {
+            return ret;
+        }
+
+        /*
+         * Trusty sends us the IPI after queuing a new stdcall.
+         * Unlike Linux which has a handler and enqueues a NOP in that case,
+         * we do not handle that interrupt so we need to call FFA_RUN manually.
+         */
+    }
+
+    ret = trusty_ffa_run(dev);
+    switch (ret) {
+    case 1:
+        /* Trusty is actually idle now, get the stdcall return value */
+        return trusty_ffa_send_direct_msg(dev, TRUSTY_FFA_MSG_GET_STDCALL_RET,
+                                          0, 0, 0, 0);
+    case 0:
+        /* Keep running Trusty without executing WFI until it becomes idle */
+        return SM_ERR_INTERRUPTED;
+    default:
+        return ret;
+    }
+}
+
+static int32_t trusty_call32(struct trusty_dev* dev,
+                             uint32_t smcnr,
+                             uint32_t a0,
+                             uint32_t a1,
+                             uint32_t a2) {
+    trusty_assert(dev);
+
+    if (dev->ffa_supports_direct_recv) {
+        return trusty_ffa_call(dev, smcnr, a0, a1, a2);
+    } else {
+        return smc(smcnr, a0, a1, a2);
+    }
+}
+
+int32_t trusty_fast_call32(struct trusty_dev* dev,
+                           uint32_t smcnr,
+                           uint32_t a0,
+                           uint32_t a1,
+                           uint32_t a2) {
     trusty_assert(dev);
     trusty_assert(SMC_IS_FASTCALL(smcnr));
 
-    return smc(smcnr, a0, a1, a2);
+    return trusty_call32(dev, smcnr, a0, a1, a2);
 }
 
 static unsigned long trusty_std_call_inner(struct trusty_dev* dev,
@@ -64,9 +223,9 @@ static unsigned long trusty_std_call_inner(struct trusty_dev* dev,
     trusty_debug("%s(0x%lx 0x%lx 0x%lx 0x%lx)\n", __func__, smcnr, a0, a1, a2);
 
     while (true) {
-        ret = smc(smcnr, a0, a1, a2);
+        ret = trusty_call32(dev, smcnr, a0, a1, a2);
         while ((int32_t)ret == SM_ERR_FIQ_INTERRUPTED)
-            ret = smc(SMC_SC_RESTART_FIQ, 0, 0, 0);
+            ret = trusty_call32(dev, SMC_SC_RESTART_FIQ, 0, 0, 0);
         if ((int)ret != SM_ERR_BUSY || !retry)
             break;
 
@@ -203,23 +362,23 @@ static int trusty_init_api_version(struct trusty_dev* dev) {
     return 0;
 }
 
-int trusty_dev_init(struct trusty_dev* dev, void* priv_data) {
+/*
+ * Trusty UUID: RFC-4122 compliant UUID version 4
+ * 40ee25f0-a2bc-304c-8c4ca173c57d8af1
+ * Trusty UUID used for partition info get call
+ */
+static const uint32_t trusty_uuid0_4[4] = {0xf025ee40, 0x4c30bca2, 0x73a14c8c,
+                                           0xf18a7dc5};
+
+static bool trusty_dev_ffa_init(struct trusty_dev* dev) {
     int ret;
     struct smc_ret8 smc_ret;
     struct ns_mem_page_info tx_pinfo;
     struct ns_mem_page_info rx_pinfo;
-    const size_t rxtx_page_count = 1;
     trusty_assert(dev);
 
-    dev->priv_data = priv_data;
     dev->ffa_tx = NULL;
-    ret = trusty_init_api_version(dev);
-    if (ret) {
-        return ret;
-    }
-    if (dev->api_version < TRUSTY_API_VERSION_MEM_OBJ) {
-        return 0;
-    }
+    dev->ffa_supports_direct_recv = false;
 
     /* Get supported FF-A version and check if it is compatible */
     smc_ret = smc8(SMC_FC_FFA_VERSION, FFA_CURRENT_VERSION, 0, 0, 0, 0, 0, 0);
@@ -241,9 +400,6 @@ int trusty_dev_init(struct trusty_dev* dev, void* priv_data) {
 
     /*
      * Set FF-A endpoint IDs.
-     *
-     * Hardcode 0x8000 for the secure os.
-     * TODO: Use FFA call or device tree to configure this dynamically
      */
     smc_ret = smc8(SMC_FC_FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0);
     if (smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
@@ -252,22 +408,25 @@ int trusty_dev_init(struct trusty_dev* dev, void* priv_data) {
         goto err_id_get;
     }
     dev->ffa_local_id = smc_ret.r2;
-    dev->ffa_remote_id = 0x8000;
 
-    dev->ffa_tx = trusty_alloc_pages(rxtx_page_count);
+    dev->ffa_tx = trusty_alloc_pages(TRUSTY_FFA_RXTX_PAGE_COUNT);
     if (!dev->ffa_tx) {
         goto err_alloc_ffa_tx;
     }
-    dev->ffa_rx = trusty_alloc_pages(rxtx_page_count);
+    dev->ffa_rx = trusty_alloc_pages(TRUSTY_FFA_RXTX_PAGE_COUNT);
     if (!dev->ffa_rx) {
         goto err_alloc_ffa_rx;
     }
     ret = trusty_encode_page_info(&tx_pinfo, dev->ffa_tx);
     if (ret) {
+        trusty_error("%s: trusty_encode_page_info failed (%d)\n", __func__,
+                     ret);
         goto err_encode_page_info;
     }
     ret = trusty_encode_page_info(&rx_pinfo, dev->ffa_rx);
     if (ret) {
+        trusty_error("%s: trusty_encode_page_info failed (%d)\n", __func__,
+                     ret);
         goto err_encode_page_info;
     }
 
@@ -277,34 +436,126 @@ int trusty_dev_init(struct trusty_dev* dev, void* priv_data) {
      */
 
     smc_ret = smc8(SMC_FCZ_FFA_RXTX_MAP, tx_pinfo.paddr, rx_pinfo.paddr,
-                   rxtx_page_count, 0, 0, 0, 0);
+                   TRUSTY_FFA_RXTX_PAGE_COUNT, 0, 0, 0, 0);
     if (smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
         trusty_error("%s: FFA_RXTX_MAP failed 0x%lx 0x%lx 0x%lx\n", __func__,
                      smc_ret.r0, smc_ret.r1, smc_ret.r2);
         goto err_rxtx_map;
     }
 
-    if (ret) {
-        goto err_setup_msg_buf;
+    /*
+     * Set remote FF-A endpoint IDs.
+     *
+     * This queries Trusty SP based on its UUID
+     */
+    smc_ret = smc8(SMC_FC_FFA_PARTITION_INFO_GET, trusty_uuid0_4[0],
+                   trusty_uuid0_4[1], trusty_uuid0_4[2], trusty_uuid0_4[3], 0,
+                   0, 0);
+    if ((uint32_t)smc_ret.r0 == SMC_FC_FFA_ERROR &&
+        (int32_t)smc_ret.r2 == FFA_ERROR_NOT_SUPPORTED) {
+        /*
+         * This interface is not supported,
+         * use hard-coded values for backward compatibility
+         */
+        dev->ffa_remote_id = 0x8000;
+        dev->ffa_supports_direct_recv = false;
+    } else if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS || smc_ret.r2 != 1) {
+        trusty_error(
+                "%s: SMC_FC_FFA_PARTITION_INFO_GET failed 0x%lx 0x%lx 0x%lx\n",
+                __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
+        goto err_part_info_get;
+    } else {
+        struct ffa_partition_info* part_info = dev->ffa_rx;
+
+        dev->ffa_remote_id = part_info->id;
+        dev->ffa_supports_direct_recv =
+                !!(part_info->id & FFA_PARTITION_DIRECT_REQ_RECV);
+
+        /* release ownership of the receive buffer */
+        smc_ret = smc8(SMC_FC_FFA_RX_RELEASE, 0, 0, 0, 0, 0, 0, 0);
+        if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
+            trusty_error("%s: SMC_FC_FFA_RX_RELEASE failed 0x%lx 0x%lx 0x%lx\n",
+                         __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
+            goto err_rx_release;
+        }
+    }
+
+    if (dev->ffa_supports_direct_recv) {
+        /* Check that direct message support is implemented */
+        smc_ret = smc8(SMC_FC_FFA_FEATURES, SMC_FC_FFA_MSG_SEND_DIRECT_REQ, 0,
+                       0, 0, 0, 0, 0);
+        if ((uint32_t)smc_ret.r0 == SMC_FC_FFA_ERROR &&
+            (int32_t)smc_ret.r2 == FFA_ERROR_NOT_SUPPORTED) {
+            /*
+             * The partition info said Trusty supports direct messages,
+             * but EL3 does not (e.g. it's running the SPD) so disable them.
+             */
+            dev->ffa_supports_direct_recv = false;
+        } else if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
+            trusty_error(
+                    "%s: SMC_FC_FFA_FEATURES(SMC_FC_FFA_MSG_SEND_DIRECT_REQ) "
+                    "failed 0x%lx 0x%lx 0x%lx\n",
+                    __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
+            goto err_features_direct_req;
+        }
     }
-    return 0;
 
-err_setup_msg_buf:
+    return true;
+
+err_features_direct_req:
+err_rx_release:
+    dev->ffa_supports_direct_recv = false;
+    dev->ffa_remote_id = 0;
+err_part_info_get:
+    smc(SMC_FC_FFA_RXTX_UNMAP, FFA_PACK_RXTX_UNMAP_ID(dev->ffa_local_id), 0, 0);
 err_rxtx_map:
 err_encode_page_info:
+    trusty_free_pages(dev->ffa_rx, TRUSTY_FFA_RXTX_PAGE_COUNT);
+    dev->ffa_rx = NULL;
 err_alloc_ffa_rx:
+    trusty_free_pages(dev->ffa_tx, TRUSTY_FFA_RXTX_PAGE_COUNT);
+    dev->ffa_tx = NULL;
 err_alloc_ffa_tx:
+    dev->ffa_local_id = 0;
 err_id_get:
 err_features:
 err_version:
-    trusty_fatal("%s: init failed\n", __func__, ret);
+    return false;
+}
+
+int trusty_dev_init(struct trusty_dev* dev, void* priv_data) {
+    bool found_ffa;
+    int ret;
+    trusty_assert(dev);
+
+    dev->priv_data = priv_data;
+    found_ffa = trusty_dev_ffa_init(dev);
+
+    ret = trusty_init_api_version(dev);
+    if (ret) {
+        return ret;
+    }
+    if (dev->api_version >= TRUSTY_API_VERSION_MEM_OBJ && !found_ffa) {
+        trusty_fatal("%s: FF-A required but not found\n", __func__);
+    }
+
+    return 0;
 }
 
 int trusty_dev_shutdown(struct trusty_dev* dev) {
     trusty_assert(dev);
 
     if (dev->ffa_tx) {
-        smc(SMC_FC_FFA_RXTX_UNMAP, 0, 0, 0);
+        smc(SMC_FC_FFA_RXTX_UNMAP, FFA_PACK_RXTX_UNMAP_ID(dev->ffa_local_id), 0,
+            0);
+
+        trusty_free_pages(dev->ffa_rx, TRUSTY_FFA_RXTX_PAGE_COUNT);
+        dev->ffa_rx = NULL;
+        trusty_free_pages(dev->ffa_tx, TRUSTY_FFA_RXTX_PAGE_COUNT);
+        dev->ffa_tx = NULL;
+        dev->ffa_local_id = 0;
+        dev->ffa_remote_id = 0;
+        dev->ffa_supports_direct_recv = false;
     }
     dev->priv_data = NULL;
     return 0;
diff --git a/test-runner/arm64/arch.c b/test-runner/arm64/arch.c
index 41b4278..1b2ac52 100644
--- a/test-runner/arm64/arch.c
+++ b/test-runner/arm64/arch.c
@@ -30,6 +30,7 @@
 #include <stdint.h>
 #include <trusty/smc.h>
 #include <trusty/smcall.h>
+#include <trusty/trusty_dev.h>
 
 #if GIC_VERSION > 2
 #define GICD_BASE (0x08000000)
@@ -51,11 +52,12 @@
 static uint32_t doorbell_irq;
 #endif
 
-int arch_gic_init(int cpu) {
+int arch_gic_init(struct trusty_dev* trusty_dev, int cpu) {
 #if GIC_VERSION > 2
     if (!cpu) {
         GICDREG_WRITE(GICD_CTLR, 2); /* Enable Non-secure group 1 interrupt */
-        doorbell_irq = smc(SMC_FC_GET_NEXT_IRQ, 0, TRUSTY_IRQ_TYPE_DOORBELL, 0);
+        doorbell_irq = trusty_fast_call32(trusty_dev, SMC_FC_GET_NEXT_IRQ, 0,
+                                          TRUSTY_IRQ_TYPE_DOORBELL, 0);
     }
     if (doorbell_irq >= 32) {
         /*
diff --git a/test-runner/arm64/asm.S b/test-runner/arm64/asm.S
index ce85cf9..4e0be0c 100644
--- a/test-runner/arm64/asm.S
+++ b/test-runner/arm64/asm.S
@@ -150,6 +150,11 @@ wfi:
 no_wfi:
     ret
 
+.global trusty_get_cpu_num
+trusty_get_cpu_num:
+    get_cpu_num x0
+    ret
+
 #if GIC_VERSION > 2
 .globl trusty_local_irq_disable
 trusty_local_irq_disable:
diff --git a/test-runner/include/test-runner-arch.h b/test-runner/include/test-runner-arch.h
index 467653d..192c500 100644
--- a/test-runner/include/test-runner-arch.h
+++ b/test-runner/include/test-runner-arch.h
@@ -66,3 +66,10 @@ void boot(int cpu);
  * Boot next operating system.
  */
 void boot_next(void);
+
+struct trusty_dev;
+
+/*
+ * Initialize the interrupt controller
+ */
+int arch_gic_init(struct trusty_dev* trusty_dev, int cpu);
diff --git a/test-runner/test-runner.c b/test-runner/test-runner.c
index 48063b0..a36cbef 100644
--- a/test-runner/test-runner.c
+++ b/test-runner/test-runner.c
@@ -81,7 +81,7 @@ void boot(int cpu) {
     struct virtio_console* console;
 
     if (cpu) {
-        ret = arch_gic_init(cpu);
+        ret = arch_gic_init(&trusty_dev, cpu);
         if (ret != 0) {
             return;
         }
@@ -128,7 +128,7 @@ void boot(int cpu) {
         return;
     }
 
-    ret = arch_gic_init(cpu);
+    ret = arch_gic_init(&trusty_dev, cpu);
     if (ret != 0) {
         return;
     }
```

