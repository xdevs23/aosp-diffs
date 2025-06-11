```diff
diff --git a/app/smptest/rules.mk b/app/smptest/rules.mk
index 166630b..36aadac 100644
--- a/app/smptest/rules.mk
+++ b/app/smptest/rules.mk
@@ -10,6 +10,11 @@ MODULE_DEPS += \
 MODULE_SRCS += \
 	$(LOCAL_DIR)/smptest.c \
 
+SMPTEST_MIN_CPU_COUNT ?= 4
+
+MODULE_DEFINES += \
+	SMPTEST_MIN_CPU_COUNT=$(SMPTEST_MIN_CPU_COUNT) \
+
 include make/module.mk
 
 endif
diff --git a/app/smptest/smptest.c b/app/smptest/smptest.c
index 7ea3fee..9b44f07 100644
--- a/app/smptest/smptest.c
+++ b/app/smptest/smptest.c
@@ -114,6 +114,16 @@ static int smptest_thread_func(void* arg) {
     return 0;
 }
 
+TEST(smptest, check_cpu_active) {
+    uint active_cpu_count = 0;
+    for (uint i = 0; i < SMP_MAX_CPUS; i++) {
+        if (mp_is_cpu_active(i)) {
+            active_cpu_count++;
+        }
+    }
+    EXPECT_GE(active_cpu_count, SMPTEST_MIN_CPU_COUNT);
+}
+
 TEST(smptest, run) {
     bool wait_for_cpus = false;
 
@@ -178,7 +188,8 @@ TEST(smptest, run) {
              * (up to 1 sec, then think they got stuck).
              */
             for (int i = 0; i < 10; i++) {
-                if (smpt->unblock_count != j || smpt->done_count != j) {
+                if (smpt->started &&
+                    (smpt->unblock_count != j || smpt->done_count != j)) {
                     thread_sleep(100);
                 }
             }
diff --git a/app/stdcalltest/stdcalltest.c b/app/stdcalltest/stdcalltest.c
index e6cb6d3..5616a90 100644
--- a/app/stdcalltest/stdcalltest.c
+++ b/app/stdcalltest/stdcalltest.c
@@ -27,11 +27,14 @@
  */
 #if WITH_LIB_SM
 
+#define LOCAL_TRACE 0
+
 #include <arch/arch_ops.h>
 #include <arch/ops.h>
 #include <err.h>
 #include <inttypes.h>
 #include <kernel/thread.h>
+#include <kernel/timer.h>
 #include <kernel/vm.h>
 #include <lib/sm.h>
 #include <lib/sm/sm_err.h>
@@ -299,6 +302,43 @@ err:
 }
 #endif
 
+/* 1ms x5000=5s should be long enough for the test to finish */
+#define FPSIMD_TIMER_PERIOD_NS (1000000)
+#define FPSIMD_TIMER_TICKS (5000)
+
+static struct timer fpsimd_timers[SMP_MAX_CPUS];
+static uint fpsimd_timer_ticks[SMP_MAX_CPUS];
+
+static enum handler_return fpsimd_timer_cb(struct timer* timer,
+                                           lk_time_ns_t now,
+                                           void* arg) {
+    uint cpu = arch_curr_cpu_num();
+
+    fpsimd_timer_ticks[cpu]--;
+    if (!fpsimd_timer_ticks[cpu]) {
+        LTRACEF("Disabling FP test timer on cpu %u\n", cpu);
+        timer_cancel(&fpsimd_timers[cpu]);
+    }
+
+    return INT_NO_RESCHEDULE;
+}
+
+static long stdcalltest_clobber_fpsimd_timer(struct smc32_args* args) {
+    uint cpu = arch_curr_cpu_num();
+    bool start_timer = !fpsimd_timer_ticks[cpu];
+
+    DEBUG_ASSERT(arch_ints_disabled());
+
+    LTRACEF("Enabling FP test timer on cpu %u\n", cpu);
+    fpsimd_timer_ticks[cpu] = FPSIMD_TIMER_TICKS;
+    if (start_timer) {
+        timer_set_periodic_ns(&fpsimd_timers[cpu], FPSIMD_TIMER_PERIOD_NS,
+                              fpsimd_timer_cb, NULL);
+    }
+
+    return 1;
+}
+
 static long stdcalltest_stdcall(struct smc32_args* args) {
     switch (args->smc_nr) {
     case SMC_SC_TEST_VERSION:
@@ -334,14 +374,28 @@ static long stdcalltest_fastcall(struct smc32_args* args) {
     }
 }
 
+static long stdcalltest_nopcall(struct smc32_args* args) {
+    switch (args->params[0]) {
+    case SMC_NC_TEST_CLOBBER_FPSIMD_TIMER:
+        return stdcalltest_clobber_fpsimd_timer(args);
+    default:
+        return SM_ERR_UNDEFINED_SMC;
+    }
+}
+
 static struct smc32_entity stdcalltest_sm_entity = {
         .stdcall_handler = stdcalltest_stdcall,
         .fastcall_handler = stdcalltest_fastcall,
+        .nopcall_handler = stdcalltest_nopcall,
 };
 
 static void stdcalltest_init(uint level) {
     int err;
 
+    for (size_t i = 0; i < SMP_MAX_CPUS; i++) {
+        timer_initialize(&fpsimd_timers[i]);
+    }
+
     err = sm_register_entity(SMC_ENTITY_TEST, &stdcalltest_sm_entity);
     if (err) {
         printf("trusty error register entity: %d\n", err);
diff --git a/app/stdcalltest/stdcalltest.h b/app/stdcalltest/stdcalltest.h
index b30d72f..de37e08 100644
--- a/app/stdcalltest/stdcalltest.h
+++ b/app/stdcalltest/stdcalltest.h
@@ -95,4 +95,17 @@
  */
 #define SMC_FC_TEST_CLOBBER_FPSIMD_CHECK SMC_FASTCALL_NR(SMC_ENTITY_TEST, 1)
 
+/**
+ * SMC_NC_TEST_CLOBBER_FPSIMD_TIMER - Trigger the FP/SIMD test timer.
+ *
+ * Return: 1 on success, or one of the libsm errors otherwise.
+ *
+ * Trigger a secure timer that runs periodically a fixed number of
+ * times, then automatically disables itself.
+ *
+ * The timer is not strictly required for the test, so failing to
+ * start or stop the timer is not an error per se.
+ */
+#define SMC_NC_TEST_CLOBBER_FPSIMD_TIMER SMC_STDCALL_NR(SMC_ENTITY_TEST, 0)
+
 #define TRUSTY_STDCALLTEST_API_VERSION 1
diff --git a/app/trusty/user-tasks.mk b/app/trusty/user-tasks.mk
index 535cf64..27efdab 100644
--- a/app/trusty/user-tasks.mk
+++ b/app/trusty/user-tasks.mk
@@ -407,14 +407,14 @@ BUILTIN_TASK_MANIFESTS_BINARY := $(foreach t, $(TRUSTY_BUILTIN_USER_TASKS),\
 BUILTIN_TASK_ELFS := $(foreach t, $(TRUSTY_BUILTIN_USER_TASKS),\
    $(_MODULES_$(t)_TRUSTY_APP_ELF))
 
-BUILTIN_TASK_OBJS := $(patsubst %.elf,%.o,$(BUILTIN_TASK_ELFS))
+BUILTIN_TASK_OBJS := $(patsubst %.elf,%.elf.o,$(BUILTIN_TASK_ELFS))
 
 $(BUILTIN_TASK_OBJS): CC := $(CC)
 $(BUILTIN_TASK_OBJS): GLOBAL_COMPILEFLAGS := $(GLOBAL_COMPILEFLAGS)
 $(BUILTIN_TASK_OBJS): ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
 $(BUILTIN_TASK_OBJS): USER_TASK_OBJ_ASM:=$(TRUSTY_APP_DIR)/appobj.S
 $(BUILTIN_TASK_OBJS): LOG_NAME:=$(TRUSTY_APP_DIR)
-$(BUILTIN_TASK_OBJS): %.o: %.elf %.manifest $(USER_TASK_OBJ_ASM)
+$(BUILTIN_TASK_OBJS): %.elf.o: %.elf %.manifest $(USER_TASK_OBJ_ASM)
 	@$(MKDIR)
 	@$(call ECHO,$(LOG_NAME),converting,$< to $@)
 	$(NOECHO)$(CC) -DUSER_TASK_ELF=\"$<\" -DMANIFEST_DATA=\"$(word 2,$^)\" $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) -c $(USER_TASK_OBJ_ASM) -o $@
diff --git a/build-config-kerneltests b/build-config-kerneltests
index 832fdd6..4120ba2 100644
--- a/build-config-kerneltests
+++ b/build-config-kerneltests
@@ -24,7 +24,9 @@
     porttest("com.android.kernel.iovectest"),
     porttest("com.android.kernel.ktipc.test"),
     porttest("com.android.kernel.libctest"),
-    porttest("com.android.kernel.libcxxtest"),
+    # disabled because libcxx/libcxxabi needs floating point instructions
+    # which are not available in the kernel; clang 19 or later errors out.
+    # porttest("com.android.kernel.libcxxtest"),
     porttest("com.android.kernel.memorylatency.bench").type(BENCHMARK),
     porttest("com.android.kernel.memorytest"),
     porttest("com.android.kernel.mmutest"),
diff --git a/include/shared/lk/trusty_unittest.h b/include/shared/lk/trusty_unittest.h
index 8cc6cab..f650d3a 100644
--- a/include/shared/lk/trusty_unittest.h
+++ b/include/shared/lk/trusty_unittest.h
@@ -904,6 +904,10 @@ static inline bool HasFailure(void) {
     return !_test_context.all_ok;
 }
 
+static inline bool HasFatalFailure(void) {
+    return _test_context.hard_fail;
+}
+
 /**
  * INSTANTIATE_TEST_SUITE_P - Instantiate parameters for a test suite
  * @inst_name:          Name for instantiation of parameters. Should not contain
diff --git a/kerneltests-inc.mk b/kerneltests-inc.mk
index 51b3e19..9d1e421 100644
--- a/kerneltests-inc.mk
+++ b/kerneltests-inc.mk
@@ -43,7 +43,11 @@ MODULES += \
 ifeq ($(LK_LIBC_IMPLEMENTATION),musl)
 MODULES += \
 	trusty/kernel/lib/libc-trusty/test \
-	trusty/kernel/lib/libcxx-trusty/test \
+
+# Disabled because libcxx/libcxxabi needs floating point
+# support which we don't have in the kernel so it makes
+# builds with clang 19 and later fail.
+# trusty/kernel/lib/libcxx-trusty/test \
 
 endif
 
diff --git a/lib/arm_ffa/arm_ffa.c b/lib/arm_ffa/arm_ffa.c
index b838423..704ea79 100644
--- a/lib/arm_ffa/arm_ffa.c
+++ b/lib/arm_ffa/arm_ffa.c
@@ -25,6 +25,7 @@
 #define LOCAL_TRACE 0
 
 #include <assert.h>
+#include <endian.h>
 #include <err.h>
 #include <interface/arm_ffa/arm_ffa.h>
 #include <inttypes.h>
@@ -32,13 +33,15 @@
 #include <kernel/vm.h>
 #include <lib/arm_ffa/arm_ffa.h>
 #include <lib/smc/smc.h>
+#include <lib/trusty/uuid.h>
 #include <lk/init.h>
 #include <lk/macros.h>
 #include <string.h>
 #include <sys/types.h>
 #include <trace.h>
 
-static bool arm_ffa_init_is_success = false;
+static enum arm_ffa_init_state ffa_init_state = ARM_FFA_INIT_UNINIT;
+static uint32_t ffa_version;
 static uint16_t ffa_local_id;
 static size_t ffa_buf_size;
 static void* ffa_tx;
@@ -46,11 +49,115 @@ static void* ffa_rx;
 static bool supports_ns_bit = false;
 static bool supports_rx_release = false;
 static bool console_log_is_unsupported;
-
 static mutex_t ffa_rxtx_buffer_lock = MUTEX_INITIAL_VALUE(ffa_rxtx_buffer_lock);
+#if ARCH_ARM64
+static bool send_direct_req2_is_unsupported;
+
+static struct bst_root arm_ffa_direct_req2_handler_tree =
+        BST_ROOT_INITIAL_VALUE;
+static spin_lock_t arm_ffa_direct_req2_tree_lock = SPIN_LOCK_INITIAL_VALUE;
+
+/**
+ * struct arm_ffa_direct_req2_bst_obj - Binary search tree object for
+ * ffa_direct_req2 handler
+ * @bst_node: BST node
+ * @uuid_lo_hi: Array that holds UUID as two 64 bit words
+ *              uuid_lo_hi[0] is what the FFA spec labels "Lo" - bytes [0-7]
+ *              uuid_lo_hi[1] is what the FFA spec labels "Hi" - bytes [8-15]
+ * @handler: Pointer to FFA_DIRECT_REQ2 handler function
+ */
+struct arm_ffa_direct_req2_bst_obj {
+    struct bst_node bst_node;
+    uint64_t uuid_lo_hi[2];
+    arm_ffa_direct_req2_handler_t handler;
+};
+static int arm_ffa_direct_req2_handler_compare(struct bst_node* a,
+                                               struct bst_node* b);
+#endif
+
+/**
+ * uuid_to_le64_pair() - convert uuid_t to (lo, hi)-pair per FFA spec.
+ *
+ * @uuid_lo_hi: Must be an array large enough to store a pair of 64-bit values.
+ *      These output elements are little-endian encoded. Upon function return,
+ *      uuid_lo_hi[0] contains what the FFA spec labels "Lo" - bytes [0-7], and
+ *      uuid_lo_hi[1] contains what the FFA spec labels "Hi" - bytes [8-15].
+ */
+static inline void uuid_to_le64_pair(uuid_t uuid_obj,
+                                     uint64_t uuid_lo_hi[static 2]) {
+    uuid_lo_hi[0] = (((uint64_t)__bswap16(uuid_obj.time_hi_and_version) << 48) |
+                     ((uint64_t)__bswap16(uuid_obj.time_mid) << 32) |
+                     ((uint64_t)__bswap32(uuid_obj.time_low)));
+
+    for (int i = 0; i < 8; i++) {
+        uuid_lo_hi[1] |= ((uint64_t)uuid_obj.clock_seq_and_node[i]) << (i * 8);
+    }
+}
+
+#if ARCH_ARM64
+status_t arm_ffa_register_direct_req2_handler(
+        uuid_t uuid,
+        arm_ffa_direct_req2_handler_t handler) {
+    struct arm_ffa_direct_req2_bst_obj* obj;
+
+    obj = calloc(1, sizeof(*obj));
+    if (!obj) {
+        LTRACEF("ERROR: not enough memory for direct_req2 handler\n");
+        return ERR_NO_MEMORY;
+    }
+
+    uuid_to_le64_pair(uuid, obj->uuid_lo_hi);
+    obj->handler = handler;
+
+    spin_lock(&arm_ffa_direct_req2_tree_lock);
+    if (!bst_insert(&arm_ffa_direct_req2_handler_tree, &obj->bst_node,
+                    arm_ffa_direct_req2_handler_compare)) {
+        spin_unlock(&arm_ffa_direct_req2_tree_lock);
+        free(obj);
+        LTRACEF("ERROR: couldn't insert direct_req2 hander into BST\n");
+        return ERR_ALREADY_EXISTS;
+    } else {
+        spin_unlock(&arm_ffa_direct_req2_tree_lock);
+        return 0;
+    }
+}
+
+static int arm_ffa_direct_req2_handler_compare(struct bst_node* a,
+                                               struct bst_node* b) {
+    struct arm_ffa_direct_req2_bst_obj* obj_a =
+            containerof(a, struct arm_ffa_direct_req2_bst_obj, bst_node);
+    struct arm_ffa_direct_req2_bst_obj* obj_b =
+            containerof(b, struct arm_ffa_direct_req2_bst_obj, bst_node);
+
+    return memcmp(obj_a->uuid_lo_hi, obj_b->uuid_lo_hi,
+                  sizeof(obj_a->uuid_lo_hi));
+}
 
-bool arm_ffa_is_init(void) {
-    return arm_ffa_init_is_success;
+status_t arm_ffa_handle_direct_req2(struct smc_ret18* regs) {
+    struct arm_ffa_direct_req2_bst_obj search_obj;
+    struct arm_ffa_direct_req2_bst_obj* found_obj;
+    uint16_t sender_id = (regs->r1 >> 16) & 0xffff;
+    search_obj.uuid_lo_hi[0] = regs->r2;
+    search_obj.uuid_lo_hi[1] = regs->r3;
+
+    spin_lock(&arm_ffa_direct_req2_tree_lock);
+    found_obj = bst_search_type(&arm_ffa_direct_req2_handler_tree, &search_obj,
+                                arm_ffa_direct_req2_handler_compare,
+                                struct arm_ffa_direct_req2_bst_obj, bst_node);
+    spin_unlock(&arm_ffa_direct_req2_tree_lock);
+
+    if (found_obj) {
+        return found_obj->handler(sender_id, &regs->r4);
+    } else {
+        LTRACEF("Error: No handler for UUID 0x%016lx 0x%016lx for sender %d\n",
+                regs->r2, regs->r3, sender_id);
+        return ERR_NOT_FOUND;
+    }
+}
+#endif
+
+enum arm_ffa_init_state arm_ffa_init_state(void) {
+    return ffa_init_state;
 }
 
 static status_t arm_ffa_call_id_get(uint16_t* id) {
@@ -58,7 +165,7 @@ static status_t arm_ffa_call_id_get(uint16_t* id) {
 
     smc_ret = smc8(SMC_FC_FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0);
 
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_SUCCESS:
     case SMC_FC64_FFA_SUCCESS:
         if (smc_ret.r2 & ~0xFFFFUL) {
@@ -69,7 +176,7 @@ static status_t arm_ffa_call_id_get(uint16_t* id) {
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        if (smc_ret.r2 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
+        if ((int32_t)smc_ret.r2 == FFA_ERROR_NOT_SUPPORTED) {
             return ERR_NOT_SUPPORTED;
         } else {
             TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
@@ -92,7 +199,7 @@ static status_t arm_ffa_call_version(uint16_t major,
     /* Bit 31 must be cleared. */
     ASSERT(!(version >> 31));
     smc_ret = smc8(SMC_FC_FFA_VERSION, version, 0, 0, 0, 0, 0, 0);
-    if (smc_ret.r0 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
+    if ((int32_t)smc_ret.r0 == FFA_ERROR_NOT_SUPPORTED) {
         return ERR_NOT_SUPPORTED;
     }
     *major_ret = FFA_VERSION_TO_MAJOR(smc_ret.r0);
@@ -122,7 +229,7 @@ static status_t arm_ffa_call_features(ulong id,
                    request_ns_bit ? FFA_FEATURES2_MEM_RETRIEVE_REQ_NS_BIT : 0,
                    0, 0, 0, 0, 0);
 
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_SUCCESS:
     case SMC_FC64_FFA_SUCCESS:
         *is_implemented = true;
@@ -135,7 +242,7 @@ static status_t arm_ffa_call_features(ulong id,
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        if (smc_ret.r2 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
+        if ((int32_t)smc_ret.r2 == FFA_ERROR_NOT_SUPPORTED) {
             *is_implemented = false;
             return NO_ERROR;
         } else {
@@ -151,23 +258,29 @@ static status_t arm_ffa_call_features(ulong id,
 
 /*
  * Call with ffa_rxtx_buffer_lock acquired and the ffa_tx buffer already
- * populated with struct ffa_mtd. Transmit in a single fragment.
+ * populated with struct ffa_mtd_common. Transmit in a single fragment.
  */
 static status_t arm_ffa_call_mem_retrieve_req(uint32_t* total_len,
                                               uint32_t* fragment_len) {
     struct smc_ret8 smc_ret;
-    struct ffa_mtd* req = ffa_tx;
+    struct ffa_mtd_v1_0* req_v1_0 = ffa_tx;
+    struct ffa_mtd_v1_1* req_v1_1 = ffa_tx;
     size_t len;
 
     DEBUG_ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
 
-    len = offsetof(struct ffa_mtd, emad[0]) +
-          req->emad_count * sizeof(struct ffa_emad);
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        len = offsetof(struct ffa_mtd_v1_0, emad[0]) +
+              req_v1_0->emad_count * sizeof(struct ffa_emad);
+    } else {
+        len = req_v1_1->emad_offset +
+              req_v1_1->emad_count * req_v1_1->emad_size;
+    }
 
     smc_ret = smc8(SMC_FC_FFA_MEM_RETRIEVE_REQ, len, len, 0, 0, 0, 0, 0);
 
-    long error;
-    switch (smc_ret.r0) {
+    int32_t error;
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_MEM_RETRIEVE_RESP:
         if (total_len) {
             *total_len = (uint32_t)smc_ret.r1;
@@ -177,7 +290,7 @@ static status_t arm_ffa_call_mem_retrieve_req(uint32_t* total_len,
         }
         return NO_ERROR;
     case SMC_FC_FFA_ERROR:
-        error = (long)smc_ret.r2;
+        error = (int32_t)smc_ret.r2;
         switch (error) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
@@ -190,7 +303,7 @@ static status_t arm_ffa_call_mem_retrieve_req(uint32_t* total_len,
         case FFA_ERROR_ABORTED:
             return ERR_CANCELLED;
         default:
-            TRACEF("Unknown error: 0x%lx\n", error);
+            TRACEF("Unknown error: 0x%x\n", error);
             return ERR_NOT_VALID;
         }
     default:
@@ -209,9 +322,10 @@ static status_t arm_ffa_call_mem_frag_rx(uint64_t handle,
                    offset, 0, 0, 0, 0);
 
     /* FRAG_RX is followed by FRAG_TX on successful completion. */
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_MEM_FRAG_TX: {
-        uint64_t handle_out = smc_ret.r1 + ((uint64_t)smc_ret.r2 << 32);
+        uint64_t handle_out =
+                (uint32_t)smc_ret.r1 | ((uint64_t)(uint32_t)smc_ret.r2 << 32);
         if (handle != handle_out) {
             TRACEF("Handle for response doesn't match the request, %" PRId64
                    " != %" PRId64,
@@ -222,7 +336,7 @@ static status_t arm_ffa_call_mem_frag_rx(uint64_t handle,
         return NO_ERROR;
     }
     case SMC_FC_FFA_ERROR:
-        switch ((int)smc_ret.r2) {
+        switch ((int32_t)smc_ret.r2) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
         case FFA_ERROR_INVALID_PARAMETERS:
@@ -230,7 +344,7 @@ static status_t arm_ffa_call_mem_frag_rx(uint64_t handle,
         case FFA_ERROR_ABORTED:
             return ERR_CANCELLED;
         default:
-            TRACEF("Unexpected error %d\n", (int)smc_ret.r2);
+            TRACEF("Unexpected error %d\n", (int32_t)smc_ret.r2);
             return ERR_NOT_VALID;
         }
     default:
@@ -239,6 +353,68 @@ static status_t arm_ffa_call_mem_frag_rx(uint64_t handle,
     }
 }
 
+static status_t arm_ffa_call_mem_share(size_t num_comp_mrd,
+                                       size_t num_cons_mrd,
+                                       uint32_t* total_len,
+                                       uint32_t* fragment_len,
+                                       uint64_t* handle) {
+    struct smc_ret8 smc_ret;
+    struct ffa_mtd_v1_0* req_v1_0 = ffa_tx;
+    struct ffa_mtd_v1_1* req_v1_1 = ffa_tx;
+    size_t len;
+    int32_t error;
+
+    DEBUG_ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
+
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        len = offsetof(struct ffa_mtd_v1_0, emad[0]) +
+              (req_v1_0->emad_count * sizeof(struct ffa_emad)) +
+              (num_comp_mrd * sizeof(struct ffa_comp_mrd)) +
+              (num_cons_mrd * sizeof(struct ffa_cons_mrd));
+    } else {
+        len = req_v1_1->emad_offset +
+              (req_v1_1->emad_count * req_v1_1->emad_size) +
+              (num_comp_mrd * sizeof(struct ffa_comp_mrd)) +
+              (num_cons_mrd * sizeof(struct ffa_cons_mrd));
+    }
+
+    /* w3 and w4 MBZ since tx buffer is used, the rest SBZ */
+    smc_ret = smc8(SMC_FC64_FFA_MEM_SHARE, len, len, 0, 0, 0, 0, 0);
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_SUCCESS:
+        if (total_len) {
+            *total_len = (uint32_t)smc_ret.r1;
+        }
+        if (fragment_len) {
+            *fragment_len = (uint32_t)smc_ret.r2;
+        }
+        if (handle) {
+            *handle = (uint32_t)smc_ret.r2;
+            *handle |= ((uint64_t)smc_ret.r3) << 32;
+        }
+        return NO_ERROR;
+    case SMC_FC_FFA_ERROR:
+        error = (int32_t)smc_ret.r2;
+        switch (error) {
+        case FFA_ERROR_INVALID_PARAMETERS:
+            return ERR_NOT_SUPPORTED;
+        case FFA_ERROR_DENIED:
+            return ERR_BAD_STATE;
+        case FFA_ERROR_NO_MEMORY:
+            return ERR_NO_MEMORY;
+        case FFA_ERROR_BUSY:
+            return ERR_BUSY;
+        case FFA_ERROR_ABORTED:
+            return ERR_CANCELLED;
+        default:
+            TRACEF("Unexpected error: 0x%x\n", error);
+            return ERR_NOT_VALID;
+        }
+    default:
+        return ERR_NOT_VALID;
+    }
+}
+
 static status_t arm_ffa_call_mem_relinquish(
         uint64_t handle,
         uint32_t flags,
@@ -268,13 +444,13 @@ static status_t arm_ffa_call_mem_relinquish(
 
     mutex_release(&ffa_rxtx_buffer_lock);
 
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_SUCCESS:
     case SMC_FC64_FFA_SUCCESS:
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        switch ((int)smc_ret.r2) {
+        switch ((int32_t)smc_ret.r2) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
         case FFA_ERROR_INVALID_PARAMETERS:
@@ -311,13 +487,13 @@ static status_t arm_ffa_call_rxtx_map(paddr_t tx_paddr,
     smc_ret = smc8(SMC_FC_FFA_RXTX_MAP, tx_paddr, rx_paddr, page_count, 0, 0, 0,
                    0);
 #endif
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_SUCCESS:
     case SMC_FC64_FFA_SUCCESS:
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        switch ((int)smc_ret.r2) {
+        switch ((int32_t)smc_ret.r2) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
         case FFA_ERROR_INVALID_PARAMETERS:
@@ -342,13 +518,13 @@ static status_t arm_ffa_call_rx_release(void) {
     DEBUG_ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
 
     smc_ret = smc8(SMC_FC_FFA_RX_RELEASE, 0, 0, 0, 0, 0, 0, 0);
-    switch (smc_ret.r0) {
+    switch ((uint32_t)smc_ret.r0) {
     case SMC_FC_FFA_SUCCESS:
     case SMC_FC64_FFA_SUCCESS:
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        switch ((int)smc_ret.r2) {
+        switch ((int32_t)smc_ret.r2) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
         case FFA_ERROR_DENIED:
@@ -377,7 +553,7 @@ static status_t ffa_call_secondary_ep_register(void) {
         return NO_ERROR;
 
     case SMC_FC_FFA_ERROR:
-        switch ((int)smc_ret.r2) {
+        switch ((int32_t)smc_ret.r2) {
         case FFA_ERROR_NOT_SUPPORTED:
             return ERR_NOT_SUPPORTED;
         case FFA_ERROR_INVALID_PARAMETERS:
@@ -395,49 +571,138 @@ static status_t ffa_call_secondary_ep_register(void) {
 }
 #endif /* WITH_SMP */
 
-struct smc_ret8 arm_ffa_call_error(enum ffa_error err) {
+struct smc_ret18 arm_ffa_call_error(enum ffa_error err) {
     long target = 0; /* Target must be zero (MBZ) at secure FF-A instances */
-    return smc8(SMC_FC_FFA_ERROR, target, (ulong)err, 0, 0, 0, 0, 0);
+    return smc8_ret18(SMC_FC_FFA_ERROR, target, (ulong)err, 0, 0, 0, 0, 0);
 }
 
-struct smc_ret8 arm_ffa_call_msg_wait(void) {
-    return smc8(SMC_FC_FFA_MSG_WAIT, 0, 0, 0, 0, 0, 0, 0);
+struct smc_ret18 arm_ffa_call_msg_wait(void) {
+    return smc8_ret18(SMC_FC_FFA_MSG_WAIT, 0, 0, 0, 0, 0, 0, 0);
 }
 
-struct smc_ret8 arm_ffa_msg_send_direct_resp(
-        const struct smc_ret8* direct_req_regs,
+struct smc_ret18 arm_ffa_msg_send_direct_resp(
+        const struct smc_ret18* direct_req_regs,
         ulong a0,
         ulong a1,
         ulong a2,
         ulong a3,
         ulong a4) {
-    ulong fid;
     uint32_t sender_receiver_id;
     uint32_t flags;
 
     DEBUG_ASSERT(direct_req_regs);
-    switch (direct_req_regs->r0) {
+
+    /* Copy and flip the sender from the direct message request */
+    sender_receiver_id = ((uint32_t)direct_req_regs->r1 >> 16) |
+                         ((uint32_t)ffa_local_id << 16);
+    /* Copy the flags as well */
+    flags = direct_req_regs->r2;
+
+    switch ((uint32_t)direct_req_regs->r0) {
     case SMC_FC_FFA_MSG_SEND_DIRECT_REQ:
-        fid = SMC_FC_FFA_MSG_SEND_DIRECT_RESP;
-        break;
+        return smc8_ret18(SMC_FC_FFA_MSG_SEND_DIRECT_RESP, sender_receiver_id,
+                          flags, a0, a1, a2, a3, a4);
     case SMC_FC64_FFA_MSG_SEND_DIRECT_REQ:
-        fid = SMC_FC64_FFA_MSG_SEND_DIRECT_RESP;
-        break;
+        return smc8_ret18(SMC_FC64_FFA_MSG_SEND_DIRECT_RESP, sender_receiver_id,
+                          flags, a0, a1, a2, a3, a4);
     default:
         dprintf(CRITICAL, "Invalid direct request function id %lx\n",
                 direct_req_regs->r0);
         return arm_ffa_call_error(FFA_ERROR_INVALID_PARAMETERS);
     }
 
+    __UNREACHABLE;
+}
+
+struct smc_ret18 arm_ffa_msg_send_direct_resp2(
+        const struct smc_ret18* direct_req_regs,
+        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT]) {
+    uint32_t sender_receiver_id;
+
+    DEBUG_ASSERT(direct_req_regs);
+    DEBUG_ASSERT(args);
+    if ((uint32_t)direct_req_regs->r0 != SMC_FC64_FFA_MSG_SEND_DIRECT_REQ2) {
+        dprintf(CRITICAL, "Invalid direct request function id %x\n",
+                (uint32_t)direct_req_regs->r0);
+        return arm_ffa_call_error(FFA_ERROR_INVALID_PARAMETERS);
+    }
+
     /* Copy and flip the sender from the direct message request */
     sender_receiver_id =
             (direct_req_regs->r1 >> 16) | ((uint32_t)ffa_local_id << 16);
-    /* Copy the flags as well */
-    flags = direct_req_regs->r2;
 
-    return smc8(fid, sender_receiver_id, flags, a0, a1, a2, a3, a4);
+    return smc18(SMC_FC64_FFA_MSG_SEND_DIRECT_RESP2, sender_receiver_id, 0, 0,
+                 args[0], args[1], args[2], args[3], args[4], args[5], args[6],
+                 args[7], args[8], args[9], args[10], args[11], args[12],
+                 args[13]);
 }
 
+#if ARCH_ARM64
+status_t arm_ffa_msg_send_direct_req2(
+        uuid_t uuid,
+        uint16_t receiver_id,
+        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+        struct smc_ret18* resp) {
+    struct smc_ret18 smc_ret;
+    uint64_t uuid_lo_hi[2];
+    uint32_t fid = SMC_FC64_FFA_MSG_SEND_DIRECT_REQ2;
+    uint32_t sender_receiver_id = ((uint32_t)ffa_local_id << 16) | receiver_id;
+
+    if (send_direct_req2_is_unsupported) {
+        return FFA_ERROR_NOT_SUPPORTED;
+    }
+
+    if (!args || !resp) {
+        return ERR_INVALID_ARGS;
+    }
+
+    uuid_to_le64_pair(uuid, uuid_lo_hi);
+
+    smc_ret = smc18(fid, sender_receiver_id, uuid_lo_hi[0], uuid_lo_hi[1],
+                    args[0], args[1], args[2], args[3], args[4], args[5],
+                    args[6], args[7], args[8], args[9], args[10], args[11],
+                    args[12], args[13]);
+
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC64_FFA_MSG_SEND_DIRECT_RESP2:
+        *resp = smc_ret;
+        return NO_ERROR;
+
+    case SMC_FC_FFA_ERROR:
+        switch ((int32_t)smc_ret.r2) {
+        case FFA_ERROR_NOT_SUPPORTED:
+            send_direct_req2_is_unsupported = true;
+            return ERR_NOT_SUPPORTED;
+        case FFA_ERROR_INVALID_PARAMETERS:
+            dprintf(CRITICAL, "Invalid parameters for direct request2\n");
+            return ERR_INVALID_ARGS;
+        default:
+            return ERR_NOT_VALID;
+        }
+
+    case SMC_UNKNOWN:
+        send_direct_req2_is_unsupported = true;
+        return ERR_NOT_SUPPORTED;
+
+    case SMC_FC_FFA_INTERRUPT:
+        /*
+         * SMC_FC_FFA_INTERRUPT or SMC_FC_FFA_YIELD can be returned per the FF-A
+         * spec but it shouldn't happen when Trusty is the receiver of requests.
+         */
+        panic("Received SMC_FC_FFA_INTERRUPT in response to direct request2");
+
+    case SMC_FC_FFA_YIELD:
+        /* See previous case */
+        panic("Received SMC_FC_FFA_YIELD in response to direct request2");
+
+    default:
+        dprintf(CRITICAL, "Unexpected response (%x) to direct request2\n",
+                (uint32_t)smc_ret.r0);
+        return ERR_NOT_VALID;
+    }
+}
+#endif
+
 ssize_t arm_ffa_console_log(const char* buf, size_t len) {
     struct smc_ret8 smc_ret;
 
@@ -583,23 +848,121 @@ static status_t arm_ffa_mem_retrieve_req_is_implemented(
 static void arm_ffa_populate_receive_req_tx_buffer(uint16_t sender_id,
                                                    uint64_t handle,
                                                    uint64_t tag) {
-    struct ffa_mtd* req = ffa_tx;
+    struct ffa_mtd_v1_0* req_v1_0 = ffa_tx;
+    struct ffa_mtd_v1_1* req_v1_1 = ffa_tx;
+    struct ffa_mtd_common* req = ffa_tx;
+    struct ffa_emad* emad;
     DEBUG_ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
 
-    memset(req, 0, sizeof(struct ffa_mtd));
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        memset(req_v1_0, 0, sizeof(struct ffa_mtd_v1_0));
+    } else {
+        memset(req_v1_1, 0, sizeof(struct ffa_mtd_v1_1));
+    }
 
     req->sender_id = sender_id;
     req->handle = handle;
     /* We must use the same tag as the one used by the sender to retrieve. */
     req->tag = tag;
 
-    /*
-     * We only support retrieving memory for ourselves for now.
-     * TODO: Also support stream endpoints. Possibly more than one.
-     */
-    req->emad_count = 1;
-    memset(req->emad, 0, sizeof(struct ffa_emad));
-    req->emad[0].mapd.endpoint_id = ffa_local_id;
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        /*
+         * We only support retrieving memory for ourselves for now.
+         * TODO: Also support stream endpoints. Possibly more than one.
+         */
+        req_v1_0->emad_count = 1;
+        emad = req_v1_0->emad;
+    } else {
+        req_v1_1->emad_count = 1;
+        req_v1_1->emad_size = sizeof(struct ffa_emad);
+        req_v1_1->emad_offset = sizeof(struct ffa_mtd_v1_1);
+        emad = (struct ffa_emad*)((uint8_t*)req_v1_1 + req_v1_1->emad_offset);
+    }
+
+    memset(emad, 0, sizeof(struct ffa_emad));
+    emad[0].mapd.endpoint_id = ffa_local_id;
+}
+
+static void arm_ffa_populate_share_tx_buffer(uint16_t receiver_id,
+                                             paddr_t buffer,
+                                             size_t num_ffa_pages,
+                                             uint arch_mmu_flags,
+                                             uint64_t tag) {
+    struct ffa_mtd_v1_0* req_v1_0 = ffa_tx;
+    struct ffa_mtd_v1_1* req_v1_1 = ffa_tx;
+    struct ffa_mtd_common* req = ffa_tx;
+    struct ffa_emad* emad;
+    ffa_mem_attr8_t attributes = 0;
+    ffa_mem_perm8_t permissions = 0;
+    uint32_t comp_mrd_offset = 0;
+    struct ffa_comp_mrd* comp_mrd;
+
+    DEBUG_ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
+
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        memset(req_v1_0, 0, sizeof(struct ffa_mtd_v1_0));
+    } else {
+        memset(req_v1_1, 0, sizeof(struct ffa_mtd_v1_1));
+    }
+
+    req->sender_id = ffa_local_id;
+
+    switch (arch_mmu_flags & ARCH_MMU_FLAG_CACHE_MASK) {
+    case ARCH_MMU_FLAG_UNCACHED_DEVICE:
+        attributes |= FFA_MEM_ATTR_DEVICE_NGNRE;
+        break;
+    case ARCH_MMU_FLAG_UNCACHED:
+        attributes |= FFA_MEM_ATTR_NORMAL_MEMORY_UNCACHED;
+        break;
+    case ARCH_MMU_FLAG_CACHED:
+        attributes |= FFA_MEM_ATTR_NORMAL_MEMORY_CACHED_WB |
+                      FFA_MEM_ATTR_INNER_SHAREABLE;
+        break;
+    }
+
+    req->memory_region_attributes = attributes;
+    req->flags = FFA_MTD_FLAG_TYPE_SHARE_MEMORY;
+    /* We must use the same tag as the one used by the receiver to share . */
+    req->tag = tag;
+    /* MBZ for MEM_SHARE */
+    req->handle = 0;
+
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        /*
+         * We only support retrieving memory for ourselves for now.
+         * TODO: Also support stream endpoints. Possibly more than one.
+         */
+        req_v1_0->emad_count = 1;
+        emad = req_v1_0->emad;
+    } else {
+        req_v1_1->emad_count = 1;
+        req_v1_1->emad_size = sizeof(struct ffa_emad);
+        req_v1_1->emad_offset = sizeof(struct ffa_mtd_v1_1);
+        emad = (struct ffa_emad*)((uint8_t*)req_v1_1 + req_v1_1->emad_offset);
+    }
+
+    memset(emad, 0, sizeof(struct ffa_emad));
+    emad[0].mapd.endpoint_id = receiver_id;
+    permissions = FFA_MEM_PERM_NX;
+    if (arch_mmu_flags & ARCH_MMU_FLAG_PERM_RO) {
+        permissions |= FFA_MEM_PERM_RO;
+    } else {
+        permissions |= FFA_MEM_PERM_RW;
+    }
+    emad[0].mapd.memory_access_permissions = permissions;
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        /* We only support one emad */
+        comp_mrd_offset = sizeof(struct ffa_mtd_v1_0) + sizeof(struct ffa_emad);
+    } else {
+        comp_mrd_offset = sizeof(struct ffa_mtd_v1_1) + sizeof(struct ffa_emad);
+    }
+    emad[0].comp_mrd_offset = comp_mrd_offset;
+
+    comp_mrd = (struct ffa_comp_mrd*)((uint8_t*)emad + sizeof(struct ffa_emad));
+    comp_mrd->total_page_count = num_ffa_pages;
+    comp_mrd->address_range_count = 1;
+    comp_mrd->address_range_array[0].address = buffer;
+    comp_mrd->address_range_array[0].page_count = num_ffa_pages;
 }
 
 /* *desc_buffer is malloc'd and on success passes responsibility to free to
@@ -685,7 +1048,9 @@ status_t arm_ffa_mem_retrieve_start(uint16_t sender_id,
                                     uint* arch_mmu_flags,
                                     struct arm_ffa_mem_frag_info* frag_info) {
     status_t res;
-    struct ffa_mtd* mtd;
+    struct ffa_mtd_v1_0* mtd_v1_0;
+    struct ffa_mtd_v1_1* mtd_v1_1;
+    struct ffa_mtd_common* mtd;
     struct ffa_emad* emad;
     struct ffa_comp_mrd* comp_mrd;
     uint32_t computed_len;
@@ -705,22 +1070,63 @@ status_t arm_ffa_mem_retrieve_start(uint16_t sender_id,
         return res;
     }
 
-    if (fragment_len <
-        offsetof(struct ffa_mtd, emad) + sizeof(struct ffa_emad)) {
-        TRACEF("Fragment too short for memory transaction descriptor\n");
-        return ERR_IO;
-    }
-
     mtd = ffa_rx;
-    emad = mtd->emad;
+    if (ffa_version < FFA_VERSION(1, 1)) {
+        if (fragment_len < sizeof(struct ffa_mtd_v1_0)) {
+            TRACEF("Fragment too short for memory transaction descriptor\n");
+            return ERR_IO;
+        }
 
-    /*
-     * We don't retrieve the memory on behalf of anyone else, so we only
-     * expect one receiver address range descriptor.
-     */
-    if (mtd->emad_count != 1) {
-        TRACEF("unexpected response count %d != 1\n", mtd->emad_count);
-        return ERR_IO;
+        mtd_v1_0 = ffa_rx;
+        if (fragment_len <
+            offsetof(struct ffa_mtd_v1_0, emad) + sizeof(struct ffa_emad)) {
+            TRACEF("Fragment too short for endpoint memory access descriptor\n");
+            return ERR_IO;
+        }
+        emad = mtd_v1_0->emad;
+
+        /*
+         * We don't retrieve the memory on behalf of anyone else, so we only
+         * expect one receiver address range descriptor.
+         */
+        if (mtd_v1_0->emad_count != 1) {
+            TRACEF("unexpected response count %d != 1\n", mtd_v1_0->emad_count);
+            return ERR_IO;
+        }
+    } else {
+        if (fragment_len < sizeof(struct ffa_mtd_v1_1)) {
+            TRACEF("Fragment too short for memory transaction descriptor\n");
+            return ERR_IO;
+        }
+
+        mtd_v1_1 = ffa_rx;
+        /*
+         * We know from the check above that
+         *   fragment_len >= sizeof(ffa_mtd_v1) >= sizeof(ffa_emad)
+         * so we can rewrite the following
+         *   fragment_len < emad_offset + sizeof(ffa_emad)
+         * into
+         *   fragment_len - sizeof(ffa_emad) < emad_offset
+         * to avoid a potential overflow.
+         */
+        if (fragment_len - sizeof(struct ffa_emad) < mtd_v1_1->emad_offset) {
+            TRACEF("Fragment too short for endpoint memory access descriptor\n");
+            return ERR_IO;
+        }
+        if (mtd_v1_1->emad_offset < sizeof(struct ffa_mtd_v1_1)) {
+            TRACEF("Endpoint memory access descriptor offset too short\n");
+            return ERR_IO;
+        }
+        if (!IS_ALIGNED(mtd_v1_1->emad_offset, 16)) {
+            TRACEF("Endpoint memory access descriptor not aligned to 16 bytes\n");
+            return ERR_IO;
+        }
+        emad = (struct ffa_emad*)((uint8_t*)mtd_v1_1 + mtd_v1_1->emad_offset);
+
+        if (mtd_v1_1->emad_count != 1) {
+            TRACEF("unexpected response count %d != 1\n", mtd_v1_1->emad_count);
+            return ERR_IO;
+        }
     }
 
     LTRACEF("comp_mrd_offset: %u\n", emad->comp_mrd_offset);
@@ -861,6 +1267,73 @@ status_t arm_ffa_mem_retrieve_next_frag(
     return NO_ERROR;
 }
 
+status_t arm_ffa_mem_share_kernel_buffer(uint16_t receiver_id,
+                                         paddr_t buffer,
+                                         size_t num_ffa_pages,
+                                         uint arch_mmu_flags,
+                                         uint64_t* handle) {
+    status_t res;
+    uint32_t len_out, fragment_len_out;
+
+    DEBUG_ASSERT(handle);
+
+    if (buffer % FFA_PAGE_SIZE) {
+        LTRACEF("Buffer address must be page-aligned\n");
+        return ERR_INVALID_ARGS;
+    }
+    if (!(arch_mmu_flags & ARCH_MMU_FLAG_PERM_NO_EXECUTE)) {
+        LTRACEF("Only non-executable buffers may be shared over FFA\n");
+        return ERR_INVALID_ARGS;
+    }
+
+    mutex_acquire(&ffa_rxtx_buffer_lock);
+
+    /* Populate the tx buffer with 1 composite mrd and 1 constituent mrd */
+    arm_ffa_populate_share_tx_buffer(receiver_id, buffer, num_ffa_pages,
+                                     arch_mmu_flags, 0);
+    res = arm_ffa_call_mem_share(1, 1, &len_out, &fragment_len_out, handle);
+    LTRACEF("total_len: %u, fragment_len: %u, handle: %" PRIx64 "\n", len_out,
+            fragment_len_out, *handle);
+    if (res != NO_ERROR) {
+        TRACEF("FF-A memory share failed, err= %d\n", res);
+    }
+
+    mutex_release(&ffa_rxtx_buffer_lock);
+    return res;
+}
+
+status_t arm_ffa_mem_reclaim(uint64_t handle) {
+    struct smc_ret8 smc_ret;
+    uint32_t handle_lo = (uint32_t)handle;
+    uint32_t handle_hi = (uint32_t)(handle >> 32);
+    uint32_t flags = 0;
+
+    smc_ret = smc8(SMC_FC_FFA_MEM_RECLAIM, handle_lo, handle_hi, flags, 0, 0, 0,
+                   0);
+
+    switch ((uint32_t)smc_ret.r0) {
+    case SMC_FC_FFA_SUCCESS:
+        return NO_ERROR;
+    case SMC_FC_FFA_ERROR:
+        switch ((int32_t)smc_ret.r2) {
+        case FFA_ERROR_INVALID_PARAMETERS:
+            return ERR_INVALID_ARGS;
+        case FFA_ERROR_NO_MEMORY:
+            return ERR_NO_MEMORY;
+        case FFA_ERROR_DENIED:
+            return ERR_BAD_STATE;
+        case FFA_ERROR_ABORTED:
+            return ERR_CANCELLED;
+        default:
+            TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
+            return ERR_NOT_VALID;
+        }
+    default:
+        TRACEF("Unexpected FFA SMC: %lx\n", smc_ret.r0);
+        return ERR_NOT_VALID;
+    }
+}
+
 status_t arm_ffa_rx_release(void) {
     status_t res;
     ASSERT(is_mutex_held(&ffa_rxtx_buffer_lock));
@@ -916,14 +1389,22 @@ static status_t arm_ffa_setup(void) {
     if (res != NO_ERROR) {
         TRACEF("No compatible FF-A version found\n");
         return res;
-    } else if (FFA_CURRENT_VERSION_MAJOR != ver_major_ret ||
-               FFA_CURRENT_VERSION_MINOR > ver_minor_ret) {
-        /* When trusty supports more FF-A versions downgrade may be possible */
+    } else if (FFA_CURRENT_VERSION_MAJOR != ver_major_ret) {
+        /* Allow downgrade within the same major version */
         TRACEF("Incompatible FF-A interface version, %" PRIu16 ".%" PRIu16 "\n",
                ver_major_ret, ver_minor_ret);
         return ERR_NOT_SUPPORTED;
     }
 
+    ffa_version = FFA_VERSION(ver_major_ret, ver_minor_ret);
+    if (ffa_version > FFA_CURRENT_VERSION) {
+        /* The SPMC supports a newer version, downgrade us */
+        ffa_version = FFA_CURRENT_VERSION;
+    }
+    LTRACEF("Negotiated FF-A version %" PRIu16 ".%" PRIu16 "\n",
+            FFA_VERSION_TO_MAJOR(ffa_version),
+            FFA_VERSION_TO_MINOR(ffa_version));
+
     res = arm_ffa_call_id_get(&ffa_local_id);
     if (res != NO_ERROR) {
         TRACEF("Failed to get FF-A partition id (err=%d)\n", res);
@@ -961,10 +1442,7 @@ static status_t arm_ffa_setup(void) {
     }
     if (!is_implemented) {
         TRACEF("FFA_MEM_RETRIEVE_REQ is not implemented\n");
-        return ERR_NOT_SUPPORTED;
-    }
-
-    if (ref_count_num_bits < 64) {
+    } else if (ref_count_num_bits < 64) {
         /*
          * Expect 64 bit reference count. If we don't have it, future calls to
          * SMC_FC_FFA_MEM_RETRIEVE_REQ can fail if we receive the same handle
@@ -1029,7 +1507,7 @@ static void arm_ffa_init(uint level) {
     res = arm_ffa_setup();
 
     if (res == NO_ERROR) {
-        arm_ffa_init_is_success = true;
+        ffa_init_state = ARM_FFA_INIT_SUCCESS;
 
 #if WITH_SMP
         res = ffa_call_secondary_ep_register();
@@ -1042,6 +1520,7 @@ static void arm_ffa_init(uint level) {
 #endif
     } else {
         TRACEF("Failed to initialize FF-A (err=%d)\n", res);
+        ffa_init_state = ARM_FFA_INIT_FAILED;
     }
 }
 
diff --git a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
index 273d4ba..e647b1b 100644
--- a/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
+++ b/lib/arm_ffa/include/lib/arm_ffa/arm_ffa.h
@@ -26,8 +26,28 @@
 #include <arch/ops.h>
 #include <interface/arm_ffa/arm_ffa.h>
 #include <lib/smc/smc.h>
+#include <lib/trusty/uuid.h>
 #include <stdbool.h>
 
+/**
+ * enum arm_ffa_init_state - The current state of FF-A initialization.
+ * @ARM_FFA_INIT_UNINIT: FF-A has not been initialized yet.
+ * @ARM_FFA_INIT_SUCCESS: FF-A has been successfully initialized.
+ * @ARM_FFA_INIT_FAILED: Failed to initialize FF-A.
+ */
+enum arm_ffa_init_state {
+    ARM_FFA_INIT_UNINIT,
+    ARM_FFA_INIT_SUCCESS,
+    ARM_FFA_INIT_FAILED,
+};
+
+/**
+ * arm_ffa_init_state() - Return the current state of FF-A initialization.
+ *
+ * Return: one of the &enum arm_ffa_init_state values.
+ */
+enum arm_ffa_init_state arm_ffa_init_state(void);
+
 /**
  * arm_ffa_is_init() - Check whether this module initialized successfully.
  *
@@ -36,7 +56,9 @@
  *
  * Return: %true in case of success, %false otherwise.
  */
-bool arm_ffa_is_init(void);
+static inline bool arm_ffa_is_init(void) {
+    return arm_ffa_init_state() == ARM_FFA_INIT_SUCCESS;
+}
 
 /**
  * arm_ffa_mem_relinquish() - Relinquish Trusty's access to a memory region.
@@ -111,6 +133,41 @@ status_t arm_ffa_mem_retrieve_start(uint16_t sender_id,
 status_t arm_ffa_mem_retrieve_next_frag(
         uint64_t handle,
         struct arm_ffa_mem_frag_info* frag_info);
+
+/**
+ * arm_ffa_mem_share_kernel_buffer() - Share kernel buffer over FFA.
+ *
+ * @receiver_id:    Id of the memory receiver.
+ * @buffer:         The start of the buffer. The address must be aligned to
+ *                  FFA_PAGE_SIZE.
+ * @num_ffa_pages:  Number of pages in the buffer. This uses FFA_PAGE_SIZE which
+ *                  may differ from Trusty's page size.
+ * @arch_mmu_flags: MMU flags used when allocating the buffer. Buffers must have
+ *                  the NO_EXECUTE bit.
+ * @handle:         [out] The handle identifying the memory region in the
+ *                  transaction.
+ *
+ * Grabs and releases the RXTX buffer lock.
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+status_t arm_ffa_mem_share_kernel_buffer(uint16_t receiver_id,
+                                         paddr_t buffer,
+                                         size_t num_ffa_pages,
+                                         uint arch_mmu_flags,
+                                         uint64_t* handle);
+
+/**
+ * arm_ffa_mem_reclaim() - Reclaim memory shared over FFA.
+ *
+ * @handle: The handle identifying the previously shared memory region. This
+ *          must have been the result of a call to
+ *          arm_ffa_mem_share_kernel_buffer().
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+status_t arm_ffa_mem_reclaim(uint64_t handle);
+
 /**
  * arm_ffa_rx_release() - Relinquish ownership of the RX buffer.
  *
@@ -125,14 +182,14 @@ status_t arm_ffa_rx_release(void);
  *
  * Return: the values of the CPU registers on return to Trusty.
  */
-struct smc_ret8 arm_ffa_call_error(enum ffa_error err);
+struct smc_ret18 arm_ffa_call_error(enum ffa_error err);
 
 /**
  * arm_ffa_call_msg_wait() - Invoke FFA_MSG_WAIT.
  *
  * Return: the values of the CPU registers on return to Trusty.
  */
-struct smc_ret8 arm_ffa_call_msg_wait(void);
+struct smc_ret18 arm_ffa_call_msg_wait(void);
 
 /**
  * arm_ffa_msg_send_direct_resp() - Send a direct message response.
@@ -147,14 +204,44 @@ struct smc_ret8 arm_ffa_call_msg_wait(void);
  *
  * Return: the values of the CPU registers on return to Trusty.
  */
-struct smc_ret8 arm_ffa_msg_send_direct_resp(
-        const struct smc_ret8* direct_req_regs,
+struct smc_ret18 arm_ffa_msg_send_direct_resp(
+        const struct smc_ret18* direct_req_regs,
         ulong a0,
         ulong a1,
         ulong a2,
         ulong a3,
         ulong a4);
 
+/**
+ * arm_ffa_msg_send_direct_req2() - Send a direct message request.
+ *
+ * @uuid: Handler UUID.
+ * @receiver_id: Receiver ID.
+ * @args: Contents of message request - x4-x17. Must not be %NULL.
+ * @resp: The registers passed back in response to the direct message iff
+ *        the request was successful. Must not be %NULL.
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+status_t arm_ffa_msg_send_direct_req2(
+        uuid_t uuid,
+        uint16_t receiver_id,
+        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT],
+        struct smc_ret18* resp);
+
+/**
+ * arm_ffa_msg_send_direct_resp2() - Send a direct message response.
+ *
+ * @direct_req_regs: The registers passed back in response to the direct message
+ *        iff the request was successful. Must not be %NULL.
+ * @args: Contents of message response - x4-x17. Must not be %NULL.
+ *
+ * Return: the values of the CPU registers on return to Trusty.
+ */
+struct smc_ret18 arm_ffa_msg_send_direct_resp2(
+        const struct smc_ret18* direct_req_regs,
+        uint64_t args[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT]);
+
 /**
  * arm_ffa_console_log() - Output a buffer using %FFA_CONSOLE_LOG.
  *
@@ -164,3 +251,38 @@ struct smc_ret8 arm_ffa_msg_send_direct_resp(
  * Return: the number of characters successfully printed, or an error code.
  */
 ssize_t arm_ffa_console_log(const char* buf, size_t len);
+
+#if ARCH_ARM64
+/**
+ * arm_ffa_direct_req2_handler_t - Handler function for DIRECT_REQ2 calls
+ *
+ * @sender_id: Sender's endpoint ID
+ * @regs: Contents of message - x4-x17
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+typedef status_t (*arm_ffa_direct_req2_handler_t)(
+        uint16_t sender_id,
+        uint64_t regs[static ARM_FFA_MSG_EXTENDED_ARGS_COUNT]);
+
+/**
+ * arm_ffa_handle_direct_req2() - Handle DIRECT_REQ2 call
+ *
+ * @regs: CPU registers for FFA call
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+status_t arm_ffa_handle_direct_req2(struct smc_ret18* regs);
+
+/**
+ * arm_ffa_register_direct_req2_handler() - Register DIRECT_REQ2 call handler
+ *
+ * @uuid: UUID of handler to register
+ * @handler: pointer to handler function
+ *
+ * Return: 0 on success, LK error code on failure.
+ */
+status_t arm_ffa_register_direct_req2_handler(
+        uuid_t uuid,
+        arm_ffa_direct_req2_handler_t handler);
+#endif
diff --git a/lib/dtb_boot_params/rules.mk b/lib/dtb_boot_params/rules.mk
new file mode 100644
index 0000000..343c5eb
--- /dev/null
+++ b/lib/dtb_boot_params/rules.mk
@@ -0,0 +1,18 @@
+ifeq ($(SUBARCH),x86-64)
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+MODULE := $(LOCAL_DIR)
+MODULE_CRATE_NAME := dtb_boot_params
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy) \
+	$(call FIND_CRATE,thiserror) \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
+
+endif
diff --git a/lib/dtb_boot_params/src/lib.rs b/lib/dtb_boot_params/src/lib.rs
new file mode 100644
index 0000000..3e9cb4b
--- /dev/null
+++ b/lib/dtb_boot_params/src/lib.rs
@@ -0,0 +1,326 @@
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
+use core::ffi::{c_ulong, c_void};
+use rust_support::{
+    mmu::{ARCH_MMU_FLAG_CACHED, ARCH_MMU_FLAG_PERM_NO_EXECUTE, ARCH_MMU_FLAG_PERM_RO, PAGE_SIZE},
+    status_t,
+    vmm::{vmm_alloc_physical, vmm_free_region, vmm_get_kernel_aspace},
+};
+use thiserror::Error;
+use zerocopy::{FromBytes, Immutable, KnownLayout};
+
+const PAGE_MASK: usize = PAGE_SIZE as usize - 1;
+
+extern "C" {
+    static lk_boot_args: [c_ulong; 4];
+}
+
+#[derive(Error, Debug)]
+pub enum MappingError {
+    #[error("failed to convert address: {0}")]
+    ConversionError(#[from] core::num::TryFromIntError),
+
+    #[error("mapping error {0}")]
+    MappingError(status_t),
+}
+
+struct Mapped<T: ?Sized + FromBytes> {
+    size: usize,
+    ptr: *mut c_void,
+    aligned_ptr: *mut c_void,
+
+    _phantom: core::marker::PhantomData<T>,
+}
+
+impl<T: ?Sized + FromBytes> Mapped<T> {
+    /// Maps [`size`] bytes at at the [`paddr`] physical address into virtual memory.
+    /// If the [`paddr`] is not page aligned, the function will also map the preceding space
+    /// to a closest page aligned address. Similarly the function will align up the size of
+    /// the mapped region to page alignment.
+    ///
+    /// # Safety
+    /// - The caller must be sure that [`paddr`] is mappable of at least [`size`] bytes
+    ///   and readable
+    /// - The caller must be sure that [`paddr`] is properly aligned for T
+    /// - The caller must be sure that [`paddr`]..[`paddr`] + [`size`] contains the correct data
+    ///   for T
+    unsafe fn map_nbytes(paddr: u64, size: usize) -> Result<Self, MappingError> {
+        let paddr = usize::try_from(paddr).map_err(MappingError::ConversionError)?;
+
+        // Page align address and size
+        let aligned_paddr = paddr & !PAGE_MASK;
+        let aligned_size = (size + PAGE_MASK) & !PAGE_MASK;
+        let offset = paddr - aligned_paddr;
+
+        assert!(offset < aligned_size);
+        assert_ne!(size, 0);
+
+        let mut aligned_ptr: *mut c_void = core::ptr::null_mut();
+
+        // Map the physical address to virtual memory
+        // SAFETY:Delegated to caller
+        let ret = unsafe {
+            // vmm_alloc_physical function accepts a constant reference for outputting a pointer to
+            // mapped region. Pass mutable reference and silence the clippy warning.
+            #[allow(clippy::unnecessary_mut_passed)]
+            vmm_alloc_physical(
+                vmm_get_kernel_aspace(),
+                c"rust-setup_data".as_ptr() as _,
+                aligned_size,
+                &mut aligned_ptr,
+                0,
+                aligned_paddr,
+                0,
+                ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO | ARCH_MMU_FLAG_PERM_NO_EXECUTE,
+            )
+        };
+
+        // Make sure that the region was mapped correctly
+        if ret != 0 || aligned_ptr.is_null() {
+            return Err(MappingError::MappingError(ret));
+        }
+
+        // Adjust the pointer to virtual memory back from aligned address to desired offset
+        // SAFETY: The pointer is within mapped range
+        let ptr = unsafe { aligned_ptr.add(paddr - aligned_paddr) };
+
+        Ok(Self { size, ptr, aligned_ptr, _phantom: Default::default() })
+    }
+}
+
+impl<T: FromBytes> Mapped<T> {
+    /// Maps T at at the [`paddr`] physical address into virtual memory. If the [`paddr`] is not
+    /// page aligned, the function will also map the preceding space to a closest page aligned
+    /// address. Similarly the function will align up the size of [`T`]  to page alignment.
+    ///
+    /// # Safety
+    ///
+    /// - The caller must be sure that [`paddr`] is mappable of at least sizeof(T) bytes
+    ///   and readable.
+    /// - The caller must be sure that [`paddr`] is properly aligned for T
+    /// - The caller must be sure that [`paddr`]..[`paddr`] + sizeof(T) contains the correct
+    ///   data for T
+    pub unsafe fn map(paddr: u64) -> Result<Self, MappingError> {
+        // SAFETY:Delegated to caller
+        Self::map_nbytes(paddr, core::mem::size_of::<T>())
+    }
+}
+
+impl<T: FromBytes> AsRef<T> for Mapped<T> {
+    fn as_ref(&self) -> &T {
+        debug_assert!(self.size == core::mem::size_of::<T>());
+
+        // SAFETY:[`Self`] created with [`Self::map`] is at least the T size and the alignment
+        // for T is asserted during the construction of [`Self`]. The bit pattern property is
+        // asserted by requiring T to be [`FromBytes`].
+        unsafe { self.ptr.cast::<T>().as_ref().unwrap() }
+    }
+}
+
+impl<T: FromBytes> Mapped<[T]> {
+    /// Maps `[T; size]` as a slice at at the [`paddr`] physical address into virtual memory
+    /// If the [`paddr`] is not page aligned, the function will also map the preceding space
+    /// to a closest page aligned address. Similarly the function will align up the size of
+    /// `[T; size]` to page alignment.
+    ///
+    /// # Safety
+    /// - The caller must be sure that [`paddr`] is mappable of at least [`size`] * sizeof(T)
+    ///   bytes and readable.
+    /// - The caller must be sure that [`paddr`] is properly aligned for T
+    /// - The caller must be sure that [`paddr`]..[`paddr`] + [`size`] * sizeof(T) contains
+    ///   the correct data for [T; size]
+    /// - The [`size`] must not be zero.
+    pub unsafe fn map_slice(paddr: u64, size: usize) -> Result<Self, MappingError> {
+        // SAFETY:Delegated to caller
+        Self::map_nbytes(paddr, size * core::mem::size_of::<T>())
+    }
+}
+
+impl<T: ?Sized + FromBytes> Drop for Mapped<T> {
+    fn drop(&mut self) {
+        // Unmap the no longer needed memory region from virtual memory
+        // SAFETY:: ptr came from vmm_alloc_physical
+        unsafe { vmm_free_region(vmm_get_kernel_aspace(), self.aligned_ptr as _) };
+    }
+}
+
+impl<T: FromBytes> AsRef<[T]> for Mapped<[T]> {
+    fn as_ref(&self) -> &[T] {
+        let n = self.size / core::mem::size_of::<T>();
+
+        assert_ne!(n, 0);
+
+        // SAFETY: The pointer compes from a successful vmm_alloc_physical call, so it's not null
+        // and valid. It is mapped as RO making it immutable. The caller of constructor is
+        // required to be sure that the data under the pointer is correct for [T; n] and properly
+        // aligned.
+        unsafe { core::slice::from_raw_parts::<'_, T>(self.ptr.cast::<T>(), n) }
+    }
+}
+
+const BOOT_PARAMS_BOOT_FLAG_OFFSET: usize = 0x1fe;
+const BOOT_PARAMS_BOOT_FLAG_MAGIC: u16 = 0xaa55;
+
+const BOOT_PARAMS_HEADER_OFFSET: usize = 0x202;
+const BOOT_PARAMS_HEADER_MAGIC: u32 = 0x53726448;
+
+const BOOT_PARAMS_SETUP_DATA_OFFSET: usize = 0x250;
+
+/// Based on crosvm's SETUP_DTB (x86_64/src/lib.rs)
+pub const SETUP_DTB: u32 = 2;
+
+/// Based on crosvm's setup_data_hdr (x86_64/src/lib.rs) which is
+/// based on https://www.kernel.org/doc/html/latest/arch/x86/boot.html
+#[repr(C)]
+#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
+struct setup_data_hdr {
+    next: u64,
+    type_: u32,
+    len: u32,
+}
+
+/// Error type returned by [`SetupDataIter`] functions
+#[derive(Error, Debug)]
+pub enum FindSetupDataError {
+    #[error("failed to map a memory region: {0}")]
+    MappingError(#[from] MappingError),
+    #[error("invalid magic in boot params structure")]
+    InvalidMagic,
+    #[error("failed to convert a value: {0}")]
+    ConversionError(#[from] core::num::TryFromIntError),
+}
+
+/// Unpacked type and data from [`setup_data_hdr`]
+pub struct SetupData {
+    type_: u32,
+    data: Mapped<[u8]>,
+}
+
+/// Iterator over `setup_data` chain rooted in `boot_params` structure
+pub struct SetupDataIter {
+    next: u64,
+}
+
+impl SetupDataIter {
+    /// Searches for boot_params using second boot argument and then creates a iterator over
+    /// setup_data chain.
+    pub fn find() -> Result<Self, FindSetupDataError> {
+        // SAFETY: lk_boot_args are set in early init and not modified afterwards
+        let boot_params_addr = unsafe { lk_boot_args[1] };
+
+        // Map the boot_params structure
+        // SAFETY: boot_params struct should be passed by boot loader in second register
+        let mapped_boot_params = unsafe {
+            Mapped::<[u8]>::map_slice(
+                boot_params_addr,
+                BOOT_PARAMS_SETUP_DATA_OFFSET + core::mem::size_of::<u64>(),
+            )?
+        };
+
+        let boot_params: &[u8] = mapped_boot_params.as_ref();
+
+        // Verify that constant value of boot_flag in boot_params matches
+        let boot_flag = u16::from_le_bytes(
+            boot_params[BOOT_PARAMS_BOOT_FLAG_OFFSET..][..2].try_into().unwrap(),
+        );
+
+        if boot_flag != BOOT_PARAMS_BOOT_FLAG_MAGIC {
+            return Err(FindSetupDataError::InvalidMagic);
+        }
+
+        // Verify that constant value of header in boot_params matches
+        let header =
+            u32::from_le_bytes(boot_params[BOOT_PARAMS_HEADER_OFFSET..][..4].try_into().unwrap());
+
+        if header != BOOT_PARAMS_HEADER_MAGIC {
+            return Err(FindSetupDataError::InvalidMagic);
+        }
+
+        // Get the first setup_data_hdr node address in the chain
+        let next = u64::from_le_bytes(
+            boot_params[BOOT_PARAMS_SETUP_DATA_OFFSET..][..8].try_into().unwrap(),
+        );
+
+        Ok(Self { next })
+    }
+
+    fn find_next(&mut self) -> Result<Option<SetupData>, FindSetupDataError> {
+        // Check if the end of chain has been reached
+        if self.next == 0u64 {
+            return Ok(None);
+        }
+
+        // Briefly map setup_data_hdr into memory and copy into variable.
+        // SAFETY:Each setup_data/next address passed using boot_params struct from bootloader
+        // is expected to be valid.
+        let mapped_hdr = unsafe { Mapped::<setup_data_hdr>::map(self.next)? };
+        let hdr: setup_data_hdr = *mapped_hdr.as_ref();
+        drop(mapped_hdr);
+
+        // Calculate data start address
+        let payload = self.next + u64::try_from(core::mem::size_of::<setup_data_hdr>())?;
+
+        // Set the next setup_data_hdr address in the chain
+        self.next = hdr.next;
+
+        // Map the data into virtual memory and return it
+        // SAFETY: The setup_data pointee is expected to be a valid mappable address and
+        // size.
+        let data = unsafe { Mapped::<[u8]>::map_slice(payload, usize::try_from(hdr.len)?)? };
+
+        Ok(Some(SetupData { type_: hdr.type_, data }))
+    }
+}
+
+impl Iterator for SetupDataIter {
+    type Item = Result<SetupData, FindSetupDataError>;
+
+    fn next(&mut self) -> Option<Self::Item> {
+        // Repack the Option and Result
+        match self.find_next() {
+            Ok(Some(next)) => Some(Ok(next)),
+            Ok(None) => None,
+            Err(err) => {
+                // Prevent next iterations to avoid dead lock
+                self.next = 0u64;
+
+                Some(Err(err))
+            }
+        }
+    }
+}
+
+/// Searches for boot_params structure and returns iterator that yields setup_datas with DTBs
+pub fn find_dtbs(
+) -> Result<impl Iterator<Item = Result<impl AsRef<[u8]>, FindSetupDataError>>, FindSetupDataError>
+{
+    Ok(SetupDataIter::find()?.filter_map(|setup| match setup {
+        // Filter out setup_data_hdr that are not DTBs
+        Ok(setup) if setup.type_ == SETUP_DTB => Some(Ok(setup.data)),
+        Ok(_) => None,
+        Err(err) => Some(Err(err)),
+    }))
+}
diff --git a/lib/dtb_service/dtb_service.cpp b/lib/dtb_service/dtb_service.cpp
index 0e184b8..9cf477f 100644
--- a/lib/dtb_service/dtb_service.cpp
+++ b/lib/dtb_service/dtb_service.cpp
@@ -174,3 +174,29 @@ int dtb_service_add(const void* dtb,
 
     return NO_ERROR;
 }
+
+static const uint8_t* s_dtb;
+
+int dtb_set(const uint8_t* dtb, size_t size) {
+    assert(s_dtb == NULL);
+    if (fdt_check_full(dtb, size)) {
+        return ERR_NOT_VALID;
+    }
+    s_dtb = dtb;
+    return NO_ERROR;
+}
+
+int dtb_get(const uint8_t** ptr, size_t* size) {
+    if (!ptr || !size) {
+        return ERR_INVALID_ARGS;
+    }
+    if (s_dtb) {
+        *ptr = s_dtb;
+        *size = fdt_totalsize(s_dtb);
+        return NO_ERROR;
+    } else {
+        *ptr = NULL;
+        *size = 0;
+        return ERR_NOT_READY;
+    }
+}
diff --git a/lib/dtb_service/include/lib/dtb_service/dtb_service.h b/lib/dtb_service/include/lib/dtb_service/dtb_service.h
index 953540b..afb6df3 100644
--- a/lib/dtb_service/include/lib/dtb_service/dtb_service.h
+++ b/lib/dtb_service/include/lib/dtb_service/dtb_service.h
@@ -45,4 +45,25 @@ int dtb_service_add(const void* dtb,
                     const char* dtb_port,
                     struct ktipc_server* server);
 
+/**
+ * dtb_set() - Set the dtb singleton to be provided by dtb_get().
+ * @dtb: Pointer to the base of the dtb in memory.
+ * @size: Size of the buffer pointer to by dtb.
+ *
+ * Return: %NO_ERROR if dtb is a valid device tree. %ERR_NOT_VALID otherwise.
+ */
+int dtb_set(const uint8_t* dtb, size_t size);
+
+/**
+ * dtb_get() - Set the dtb singleton.
+ * @ptr: Output pointer for the dtb.
+ * @size: Output size of the dtb.
+ *
+ * Return: %NO_ERROR in case of success, ptr and size are updated with the
+ * location and size of the dtb.
+ * %ERR_INVALID_ARGS if ptr or size is null
+ * %ERR_NOT_READY if the dtb has not been set. ptr and size are set to zero
+ */
+int dtb_get(const uint8_t** ptr, size_t* size);
+
 __END_CDECLS
diff --git a/lib/dtb_service/rust/bindings.h b/lib/dtb_service/rust/bindings.h
new file mode 100644
index 0000000..354da1d
--- /dev/null
+++ b/lib/dtb_service/rust/bindings.h
@@ -0,0 +1,18 @@
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
+#include <lib/dtb_service/dtb_service.h>
+#include <uapi/err.h>
diff --git a/lib/dtb_service/rust/rules.mk b/lib/dtb_service/rust/rules.mk
new file mode 100644
index 0000000..5dfefa0
--- /dev/null
+++ b/lib/dtb_service/rust/rules.mk
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
+MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs
+
+MODULE_CRATE_NAME := dtb_service
+
+MODULE_SDK_LIB_NAME := dtb_service-rust
+
+MODULE_LIBRARY_DEPS += \
+
+MODULE_BINDGEN_ALLOW_TYPES :=
+
+MODULE_BINDGEN_ALLOW_VARS := \
+	NO_ERROR \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	dtb_get \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+include make/library.mk
diff --git a/lib/dtb_service/rust/src/lib.rs b/lib/dtb_service/rust/src/lib.rs
new file mode 100644
index 0000000..62633b9
--- /dev/null
+++ b/lib/dtb_service/rust/src/lib.rs
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
+//! # Interface library for communicating with the system state service.
+
+#![no_std]
+
+#[allow(non_upper_case_globals)]
+#[allow(non_camel_case_types)]
+#[allow(unused)]
+pub mod sys {
+    include!(env!("BINDGEN_INC_FILE"));
+}
diff --git a/lib/extmem/external_memory.c b/lib/extmem/external_memory.c
index d9894a2..451ebe2 100644
--- a/lib/extmem/external_memory.c
+++ b/lib/extmem/external_memory.c
@@ -31,6 +31,7 @@
 #define LOCAL_TRACE 0
 
 static struct ext_mem_obj* ext_mem_obj_from_vmm_obj(struct vmm_obj* vmm_obj) {
+    DEBUG_ASSERT(vmm_obj->ops->get_page == ext_mem_obj_get_page);
     return containerof(vmm_obj, struct ext_mem_obj, vmm_obj);
 }
 
@@ -197,3 +198,18 @@ status_t ext_mem_map_obj_id(vmm_aspace_t* aspace,
             *ptr);
     return err;
 }
+
+size_t ext_mem_get_obj_size(struct vmm_obj* vmm_obj) {
+    struct ext_mem_obj* ext_obj = NULL;
+    size_t size = 0;
+    size_t index;
+
+    DEBUG_ASSERT(vmm_obj);
+
+    ext_obj = ext_mem_obj_from_vmm_obj(vmm_obj);
+    for (index = 0; index < ext_obj->page_run_count; index++) {
+        size += ext_obj->page_runs[index].size;
+    }
+
+    return size;
+}
diff --git a/lib/extmem/include/lib/extmem/extmem.h b/lib/extmem/include/lib/extmem/extmem.h
index 5f652c0..3aa5362 100644
--- a/lib/extmem/include/lib/extmem/extmem.h
+++ b/lib/extmem/include/lib/extmem/extmem.h
@@ -30,6 +30,7 @@
 
 struct vmm_obj;
 struct obj_ref;
+struct sm_vm;
 struct vmm_aspace;
 
 /**
@@ -106,7 +107,7 @@ static inline size_t ext_mem_obj_page_runs_size(size_t page_run_count) {
  * @id:             Unique id used by ext_mem_insert and ext_mem_lookup.
  * @tag:            Extra metadata used by some systems. Set to 0 if unused.
  * @ops:            Pointer to &struct vmm_obj_ops. @ops->check_flags can point
- *                  directly to ext_mem_obj_check_flags. @ops->get_page can
+ *                  directly to ext_mem_obj_check_flags. @ops->get_page must
  *                  point directly to ext_mem_obj_get_page. @ops->destroy must
  *                  point to a function supplied by the caller.
  * @arch_mmu_flags: Memory type and required permission flags.
@@ -227,6 +228,27 @@ status_t ext_mem_map_obj_id(struct vmm_aspace* aspace,
                             uint vmm_flags,
                             uint arch_mmu_flags);
 
+/**
+ * ext_mem_get_vm_vmm_obj - Lookup shared memory object for a specific VM.
+ * @vm:             VM where the memory originated.
+ * @mem_obj_id:     Id of shared memory object to lookup and return.
+ * @tag:            Tag of the memory. If a non-FF-A object, use 0.
+ * @size:           Size hint for object. Caller expects an object at least this
+ *                  big.
+ * @objp:           Pointer to return object in.
+ * @obj_ref:        Reference to *@objp.
+ *
+ * Not provided by ext_mem.
+ *
+ * Return: 0 on success. ERR_NOT_FOUND if @id does not exist.
+ */
+status_t ext_mem_get_vm_vmm_obj(struct sm_vm* vm,
+                                ext_mem_obj_id_t mem_obj_id,
+                                uint64_t tag,
+                                size_t size,
+                                struct vmm_obj** objp,
+                                struct obj_ref* obj_ref);
+
 /**
  * ext_mem_get_vmm_obj - Lookup shared memory object.
  * @client_id:      Id of external entity where the memory originated.
@@ -247,3 +269,12 @@ status_t ext_mem_get_vmm_obj(ext_mem_client_id_t client_id,
                              size_t size,
                              struct vmm_obj** objp,
                              struct obj_ref* obj_ref);
+
+/**
+ * ext_mem_get_obj_size - Get a shared memory object's size.
+ * @vmm_obj:        Pointer to the external memory object. This must be part of
+ *                  an ext_mem_obj, not an arbitrary vmm_obj.
+ *
+ * Return: The size of the external memory object.
+ */
+size_t ext_mem_get_obj_size(struct vmm_obj* vmm_obj);
diff --git a/lib/extmem/rust/bindings.h b/lib/extmem/rust/bindings.h
new file mode 100644
index 0000000..7bf6e12
--- /dev/null
+++ b/lib/extmem/rust/bindings.h
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
+#include <lib/extmem/extmem.h>
diff --git a/lib/extmem/rust/lib.rs b/lib/extmem/rust/lib.rs
new file mode 100644
index 0000000..3bf48f1
--- /dev/null
+++ b/lib/extmem/rust/lib.rs
@@ -0,0 +1,229 @@
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
+use crate::sys::ext_mem_client_id_t;
+use crate::sys::ext_mem_get_obj_size;
+use crate::sys::ext_mem_get_vmm_obj;
+use crate::sys::ext_mem_obj_id_t;
+use crate::sys::ext_mem_obj_set_match_tag;
+
+use rust_support::lk_obj_ref_init;
+use rust_support::mmu::PAGE_SIZE;
+use rust_support::obj_ref;
+use rust_support::status_t;
+use rust_support::vmm::vmm_alloc_obj;
+use rust_support::vmm::vmm_free_region;
+use rust_support::vmm::vmm_get_kernel_aspace;
+use rust_support::vmm::vmm_obj;
+use rust_support::vmm::vmm_obj_del_ref;
+use rust_support::Error;
+
+use core::ffi::c_void;
+use core::ffi::CStr;
+use core::mem::zeroed;
+use core::mem::ManuallyDrop;
+use core::ptr::null_mut;
+use core::ptr::NonNull;
+
+mod sys {
+    #![allow(non_camel_case_types)]
+    #![allow(unused)]
+    use rust_support::obj_ref;
+    use rust_support::vmm::vmm_obj;
+    include!(env!("BINDGEN_INC_FILE"));
+}
+/// An external memory object with ownership of its mapped memory.
+///
+/// Creating an ExtMemObj maps the object into the kernel address space and
+/// dropping (either implicitly or with unmap_obj) unmaps the memory.
+#[derive(Debug)]
+pub struct ExtMemObj {
+    vaddr: NonNull<c_void>,
+    map_size: usize,
+}
+
+// SAFETY: Once created the only modifications to the underlying vmm_obj allowed
+// is unmapping it which requires exclusive access to the ExtMemObj. Ensuring
+// accesses to the mapped memory are synchronized is delegated to the safety
+// requirements on the get_vaddr method.
+unsafe impl Sync for ExtMemObj {}
+
+// SAFETY: ExtMemObj may be sent between threads since any thread is allowed to
+// unmap it, not just the thread that mapped it in. See safety comment on Sync
+// impl for justification about calling get_vaddr from different threads.
+unsafe impl Send for ExtMemObj {}
+
+impl ExtMemObj {
+    /// Maps an external memory object specified by `mem_obj_id` and `client_id`
+    /// into the kernel address space..
+    ///
+    /// `size` can be specified to map a subset of the memory object starting at
+    /// `offset`. If `size` is `None` the entire object is mapped in. It must be
+    /// always be a multiple of the page size.
+    #[allow(clippy::too_many_arguments)]
+    pub fn map_obj_kernel(
+        name: &'static CStr,
+        client_id: ext_mem_client_id_t,
+        mem_obj_id: ext_mem_obj_id_t,
+        tag: u64,
+        offset: usize,
+        size: Option<usize>,
+        align_log2: u8,
+        vmm_flags: u32,
+        arch_mmu_flags: u32,
+    ) -> Result<Self, Error> {
+        if let Some(sz) = size {
+            assert!(sz % PAGE_SIZE as usize == 0);
+        }
+
+        let mut objp: *mut vmm_obj = null_mut();
+        // SAFETY: obj_ref is a C type with two pointers which can be zeroed.
+        // The obj_ref is initialized by lk_obj_ref_init before being used in
+        // ext_mem_get_vmm_obj and does not move out of this function so it's
+        // pointers to itself do not get invalidated.
+        let mut tmp_obj_ref: obj_ref = unsafe { zeroed() };
+        let tmp_obj_ref_ptr: *mut obj_ref = &raw mut tmp_obj_ref;
+        // SAFETY: This takes a pointer to an obj_ref that will not move for its
+        // entire lifetime.
+        unsafe {
+            lk_obj_ref_init(tmp_obj_ref_ptr);
+        }
+
+        // SAFETY: This takes a vmm_obj and vmm_obj_ref pointers that are
+        // initialized to valid values and the error code is checked before
+        // using the resulting vmm_obj. The function is thread-safe so there can
+        // be no data race.
+        let rc = unsafe {
+            ext_mem_get_vmm_obj(
+                client_id,
+                mem_obj_id,
+                tag,
+                0, /* size hint */
+                &raw mut objp,
+                tmp_obj_ref_ptr,
+            )
+        };
+        if rc < 0 {
+            Error::from_lk(rc)?;
+        }
+
+        // SAFETY: objp points to a valid vmm_obj since ext_mem_get_vmm_obj didn't return an error.
+        unsafe {
+            // match_tag must be set before mapping the object
+            ext_mem_obj_set_match_tag(objp, tag);
+        }
+
+        let aspace = vmm_get_kernel_aspace();
+        let name = name.as_ptr();
+        let map_size = match size {
+            Some(sz) => sz,
+            None => {
+                // SAFETY: This function requires a pointer to a vmm_obj within
+                // a ext_mem_obj which is ensured by ext_mem_get_vmm_obj
+                unsafe { ext_mem_get_obj_size(objp) }
+            }
+        };
+        let mut vaddr: *mut c_void = null_mut();
+        // SAFETY: name is static and will outlive the allocation and objp
+        // points to a valid vmm_obj because it was initialized in
+        // ext_mem_get_vmm_obj. The return code is checked before the resulting
+        // vaddr is used.
+        let rc = unsafe {
+            vmm_alloc_obj(
+                aspace,
+                name,
+                objp,
+                offset,
+                map_size,
+                &raw mut vaddr,
+                align_log2,
+                vmm_flags,
+                arch_mmu_flags,
+            )
+        };
+        // SAFETY: vmm_alloc_obj took a reference to the vmm_obj so dropping the
+        // temporary reference create in this function will not drop the
+        // vmm_obj. Arguments are valid because they were initialized in
+        // ext_mem_get_vmm_obj and lk_obj_ref_init
+        unsafe { vmm_obj_del_ref(objp, tmp_obj_ref_ptr) }
+        if rc < 0 {
+            Error::from_lk(rc)?;
+        }
+        let vaddr = NonNull::new(vaddr).expect("vmm_alloc_obj returned a non-null pointer");
+        Ok(Self { vaddr, map_size })
+    }
+
+    /// Get a pointer to the memory mapped into the kernel address space for the
+    /// memory object.
+    ///
+    /// # Safety
+    ///
+    /// Since the mapping is shared memory it may also be accessed from outside
+    /// Trusty (e.g. VMs) so the caller must ensure that accesses are
+    /// synchronized. Furthermore since ExtMemObj implements Sync these pointers
+    /// may be obtained from any thread in Trusty so the caller must also ensure
+    /// that accesses from different threads are synchronized. Finally the caller
+    /// must ensure that pointers are not accessed after the ExtMemObj is
+    /// dropped since that unmaps the memory from the kernel address space.
+    pub unsafe fn get_vaddr(&self) -> NonNull<c_void> {
+        self.vaddr
+    }
+
+    /// Get the size mapped for the external memory object.
+    pub fn get_size(&self) -> usize {
+        self.map_size
+    }
+
+    /// Unmaps the external memory object and returns whether the operation was
+    /// successful  or not.
+    ///
+    /// On failure this returns a tuple with an ExtMemObj for the same mapping
+    /// and a non-zero status_t returned by vmm_free_region.
+    pub fn unmap_obj(self) -> Result<(), (Self, Error)> {
+        let aspace = vmm_get_kernel_aspace();
+        // Skip dropping self to avoid calling vmm_free_region multiple times
+        let extmem = ManuallyDrop::new(self);
+        // SAFETY: This deletes the obj_ref created by vmm_alloc_obj unmapping
+        // the external memory object from the kernel address space.
+        let rc = unsafe { vmm_free_region(aspace, extmem.vaddr.as_ptr() as usize) };
+        if rc != 0 {
+            return Error::from_lk(rc).map_err(|e| (ManuallyDrop::into_inner(extmem), e));
+        }
+        Ok(())
+    }
+}
+
+impl Drop for ExtMemObj {
+    /// Unmaps the external memory object.
+    ///
+    /// On failure this leaks the mapping without giving the caller a chance to
+    /// retry.
+    fn drop(&mut self) {
+        let aspace = vmm_get_kernel_aspace();
+        // SAFETY: This deletes the obj_ref created by vmm_alloc_obj unmapping
+        // the external memory object from the kernel address space.
+        let _rc: status_t = unsafe { vmm_free_region(aspace, self.vaddr.as_ptr() as usize) };
+    }
+}
diff --git a/lib/extmem/rust/rules.mk b/lib/extmem/rust/rules.mk
new file mode 100644
index 0000000..d9b2842
--- /dev/null
+++ b/lib/extmem/rust/rules.mk
@@ -0,0 +1,62 @@
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
+MODULE_CRATE_NAME := extmem
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_ADD_IMPLICIT_DEPS := false
+
+MODULE_DEPS := \
+	external/lk/lib/rust_support \
+	trusty/kernel/lib/extmem \
+	trusty/kernel/lib/sm \
+	trusty/user/base/lib/liballoc-rust \
+	trusty/user/base/lib/libcompiler_builtins-rust \
+	trusty/user/base/lib/libcore-rust \
+	trusty/user/base/lib/trusty-std \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	ext_mem_get_obj_size \
+	ext_mem_get_vmm_obj \
+	ext_mem_obj_set_match_tag \
+
+MODULE_BINDGEN_ALLOW_TYPES := \
+	ext_mem_client_id_t \
+	ext_mem_obj_id_t \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+MODULE_RUST_USE_CLIPPY := true
+
+# When bindgen runs on this module it will attempt to create bindings for these types. rust_support
+# provides these types so we blocklist them in this call to bindgen and use those instead so they
+# can be used interchangeably with any other modules that use these types
+MODULE_BINDGEN_BLOCK_TYPES := \
+	obj_ref \
+	vmm_obj \
+
+include make/library.mk
diff --git a/lib/ktipc/include/lib/ktipc/ktipc.h b/lib/ktipc/include/lib/ktipc/ktipc.h
index 450595b..eb10c91 100644
--- a/lib/ktipc/include/lib/ktipc/ktipc.h
+++ b/lib/ktipc/include/lib/ktipc/ktipc.h
@@ -60,13 +60,7 @@ struct ktipc_server {
  *
  * Return: none
  */
-static inline void ktipc_server_init(struct ktipc_server* ksrv,
-                                     const char* name) {
-    ksrv->name = name;
-    ksrv->hset = NULL;
-    ksrv->thread = NULL;
-    event_init(&ksrv->have_handles_evt, false, 0);
-}
+void ktipc_server_init(struct ktipc_server* ksrv, const char* name);
 
 /**
  *  ktipc_server_start() - start specified ktipc server
@@ -97,7 +91,7 @@ int ktipc_server_start(struct ktipc_server* server);
 struct ktipc_port_acl {
     uint32_t flags;
     uint32_t uuid_num;
-    const struct uuid** uuids;
+    const struct uuid* const* uuids;
     const void* extra_data;
 };
 
diff --git a/lib/ktipc/ktipc.c b/lib/ktipc/ktipc.c
index 694ae05..027bd08 100644
--- a/lib/ktipc/ktipc.c
+++ b/lib/ktipc/ktipc.c
@@ -427,3 +427,10 @@ int ktipc_recv_iov(struct handle* chan,
     ipc_put_msg(chan, msg_inf.id);
     return rc;
 }
+
+void ktipc_server_init(struct ktipc_server* ksrv, const char* name) {
+    ksrv->name = name;
+    ksrv->hset = NULL;
+    ksrv->thread = NULL;
+    event_init(&ksrv->have_handles_evt, false, 0);
+}
diff --git a/lib/metrics/rules.mk b/lib/metrics/rules.mk
index c3eaad3..e35f259 100644
--- a/lib/metrics/rules.mk
+++ b/lib/metrics/rules.mk
@@ -29,6 +29,6 @@ MODULE_SRCS += \
 MODULE_DEPS += \
 	$(LKROOT)/lib/dpc \
 	trusty/kernel/lib/trusty \
-	trusty/user/base/interface/metrics/ \
+	trusty/user/base/interface/metrics \
 
 include make/module.mk
diff --git a/lib/rand/rust/bindings.h b/lib/rand/rust/bindings.h
new file mode 100644
index 0000000..515478c
--- /dev/null
+++ b/lib/rand/rust/bindings.h
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
+#include <lib/rand/rand.h>
diff --git a/lib/rand/rust/lib.rs b/lib/rand/rust/lib.rs
new file mode 100644
index 0000000..4151fe0
--- /dev/null
+++ b/lib/rand/rust/lib.rs
@@ -0,0 +1,44 @@
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
+mod sys {
+    #![allow(dead_code)]
+    #![allow(non_camel_case_types)]
+    include!(env!("BINDGEN_INC_FILE"));
+}
+
+pub fn rand_get_size(max: usize) -> usize {
+    // Safety: input and output are primitive values
+    unsafe { sys::rand_get_size(max) }
+}
+
+pub fn rand_get_bytes(slice: &mut [u8]) {
+    // Safety: we pass in the slice as a pointer/size pair
+    unsafe {
+        sys::rand_get_bytes(slice.as_mut_ptr(), slice.len());
+    }
+}
+
+// TODO: implement core::random::RandomSource when it lands
diff --git a/lib/rand/rust/rules.mk b/lib/rand/rust/rules.mk
new file mode 100644
index 0000000..a686c71
--- /dev/null
+++ b/lib/rand/rust/rules.mk
@@ -0,0 +1,42 @@
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
+MODULE_CRATE_NAME := rand
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_DEPS := \
+	trusty/kernel/lib/rand \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	rand_get_size \
+	rand_get_bytes \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/sm/include/lib/sm.h b/lib/sm/include/lib/sm.h
index ce4be93..bc88bfa 100644
--- a/lib/sm/include/lib/sm.h
+++ b/lib/sm/include/lib/sm.h
@@ -25,9 +25,12 @@
 
 #include <lib/extmem/extmem.h>
 #include <lib/sm/smcall.h>
+#include <lk/list.h>
+#include <lk/reflist.h>
 #include <stdbool.h>
 #include <stddef.h>
 #include <sys/types.h>
+#include <uapi/err.h>
 
 #define PRIxNS_ADDR PRIx64
 
@@ -92,6 +95,12 @@ long smc_intc_get_next_irq(struct smc32_args* args);
 status_t sm_intc_fiq_enter(void);
 enum handler_return sm_intc_enable_interrupts(void);
 
+/*
+ * Ring the doorbell or equivalent interrupt on the primary scheduler
+ * so that it enqueues a NOP for Trusty.
+ */
+void sm_intc_raise_doorbell_irq(void);
+
 /* Get the argument block passed in by the bootloader */
 status_t sm_get_boot_args(void** boot_argsp, size_t* args_sizep);
 
@@ -105,4 +114,123 @@ status_t sm_decode_ns_memory_attr(struct ns_page_info* pinf,
                                   ns_addr_t* ppa,
                                   uint* pmmu);
 
+/**
+ * struct sm_vm_notifier - VM notifier to call on VM events.
+ * @node:           List node in notifiers list.
+ * @client_id:      VM identifier.
+ * @destroy:        Destruction event callback.
+ *
+ * The &struct sm_vm_notifier object must exist at least until both the
+ * @destroy callback is called or sm_vm_notifier_unregister() has returned.
+ * If sm_vm_notifier_unregister() has returned, the callback will not be called
+ * and it is safe to free the object.
+ *
+ * If the client intends to call sm_vm_notifier_unregister() at any point
+ * after the callback returns, it should keep the notifier object alive
+ * until after the last call to sm_vm_notifier_unregister().
+ * Note that all such invocations will just return %ERR_NOT_FOUND.
+ */
+struct sm_vm_notifier {
+    struct list_node node;
+    ext_mem_obj_id_t client_id;
+    status_t (*destroy)(struct sm_vm_notifier*);
+};
+
+/**
+ * sm_vm_notifier_init() - Initialize a notifier.
+ * @notif: Pointer to notifier
+ * @client_id: VM identifier to set in notifier.
+ * @destroy: Destruction callback.
+ */
+static inline status_t sm_vm_notifier_init(
+        struct sm_vm_notifier* notif,
+        ext_mem_obj_id_t client_id,
+        status_t (*destroy)(struct sm_vm_notifier*)) {
+    if (!notif) {
+        return ERR_INVALID_ARGS;
+    }
+    if (!destroy) {
+        return ERR_INVALID_ARGS;
+    }
+
+    list_clear_node(&notif->node);
+    notif->client_id = client_id;
+    notif->destroy = destroy;
+
+    return NO_ERROR;
+}
+
+/**
+ * sm_vm_notifier_register() - Register a notifier for VM events.
+ * @notif: Pointer to notifier.
+ *
+ * Return:
+ * * %0 in case of success
+ * * %ERR_INVALID_ARGS if @notif is invalid
+ * * %ERR_NOT_FOUND if the VM has not been created
+ * * %ERR_BAD_STATE if the VM is already present and in an invalid state
+ *
+ * The contents of @notif should be initialized using
+ * sm_vm_notifier_init().
+ *
+ * The function does not take ownership of @notif.
+ */
+status_t sm_vm_notifier_register(struct sm_vm_notifier* notif);
+
+/**
+ * sm_vm_notifier_unregister() - Unregister a notifier for VM events.
+ * @notif: Pointer to notifier.
+ *
+ * Return:
+ * * %0 in case of success
+ * * %ERR_INVALID_ARGS if @notif is invalid
+ * * %ERR_NOT_FOUND if the notifier has not been previously registered
+ *
+ * The function will block until the destruction callback finishes
+ * if it is already running on another thread. If the destruction callback
+ * is not already running, it will not be called.
+ */
+status_t sm_vm_notifier_unregister(struct sm_vm_notifier* notif);
+
+struct sm_vm;
+
+/**
+ * sm_vm_get() - Get a &struct sm_vm for a given client id.
+ * @client_id: Id of the referenced VM.
+ * @ref:       Pointer to uninitialized &struct obj_ref object.
+ *             Must not be %NULL.
+ * @out_vm:    Output pointer to receive a pointer to the VM object.
+ *
+ * Return:
+ * * %0 in case of success
+ * * %ERR_INVALID_ARGS if @ref or @out_vm are invalid.
+ * * %ERR_NOT_FOUND if the VM does not exist
+ */
+status_t sm_vm_get(ext_mem_obj_id_t client_id,
+                   struct obj_ref* ref,
+                   struct sm_vm** out_vm);
+
+/**
+ * sm_vm_add_ref() - Add a reference to a VM.
+ * @vm:  Pointer to referenced VM object. Must not be %NULL.
+ * @ref: Pointer to uninitialized &struct obj_ref object.
+ *       Must not be %NULL.
+ */
+void sm_vm_add_ref(struct sm_vm* vm, struct obj_ref* ref);
+
+/**
+ * sm_vm_del_ref() - Delete a reference to a VM.
+ * @vm:  Pointer to referenced VM object. Must not be %NULL.
+ * @ref: Pointer to valid &struct obj_ref object. Must not be %NULL.
+ */
+void sm_vm_del_ref(struct sm_vm* vm, struct obj_ref* ref);
+
+/**
+ * sm_vm_get_id() - Get the client ID of a VM.
+ * @vm: Pointer to VM object. Must not be %NULL.
+ *
+ * Return: the VM ID.
+ */
+ext_mem_client_id_t sm_vm_get_id(struct sm_vm* vm);
+
 #endif /* __SM_H */
diff --git a/lib/sm/include/lib/sm/smcall.h b/lib/sm/include/lib/sm/smcall.h
index 0b1c539..68aa45d 100644
--- a/lib/sm/include/lib/sm/smcall.h
+++ b/lib/sm/include/lib/sm/smcall.h
@@ -162,4 +162,83 @@
 #define SMC_SC_HANDLE_QL_TIPC_DEV_CMD SMC_STDCALL_NR(SMC_ENTITY_TRUSTED_OS, 32)
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
 #endif /* __LIB_SM_SMCALL_H */
diff --git a/lib/sm/include/lib/sm/trusty_sched_share.h b/lib/sm/include/lib/sm/trusty_sched_share.h
index 4764871..443792b 100644
--- a/lib/sm/include/lib/sm/trusty_sched_share.h
+++ b/lib/sm/include/lib/sm/trusty_sched_share.h
@@ -37,6 +37,7 @@
 /*
  * trusty-shadow-priority valid values
  */
+#define TRUSTY_SHADOW_PRIORITY_IDLE 0
 #define TRUSTY_SHADOW_PRIORITY_LOW 1
 #define TRUSTY_SHADOW_PRIORITY_NORMAL 2
 #define TRUSTY_SHADOW_PRIORITY_HIGH 3
diff --git a/lib/sm/rules.mk b/lib/sm/rules.mk
index c1b1bb8..ba64870 100644
--- a/lib/sm/rules.mk
+++ b/lib/sm/rules.mk
@@ -28,6 +28,10 @@ MODULE := $(LOCAL_DIR)
 GLOBAL_DEFINES += \
 	WITH_LIB_SM=1 \
 
+ifeq (true,$(call TOBOOL,$(LIB_SM_WITH_FFA_LOOP)))
+MODULE_DEFINES += LIB_SM_WITH_FFA_LOOP=1
+endif
+
 GLOBAL_INCLUDES += \
 	$(LOCAL_DIR)/include
 
diff --git a/lib/sm/rust/bindings.h b/lib/sm/rust/bindings.h
new file mode 100644
index 0000000..847238a
--- /dev/null
+++ b/lib/sm/rust/bindings.h
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
+#include <lib/sm.h>
diff --git a/lib/sm/rust/lib.rs b/lib/sm/rust/lib.rs
new file mode 100644
index 0000000..3caf618
--- /dev/null
+++ b/lib/sm/rust/lib.rs
@@ -0,0 +1,37 @@
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
+mod sys {
+    #![allow(unused)]
+    #![allow(non_camel_case_types)]
+    include!(env!("BINDGEN_INC_FILE"));
+}
+
+pub fn intc_raise_doorbell_irq() {
+    // SAFETY: This function has no safety requirements and may be called from any context.
+    unsafe {
+        sys::sm_intc_raise_doorbell_irq();
+    }
+}
diff --git a/lib/sm/rust/rules.mk b/lib/sm/rust/rules.mk
new file mode 100644
index 0000000..4e24efc
--- /dev/null
+++ b/lib/sm/rust/rules.mk
@@ -0,0 +1,46 @@
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
+MODULE_CRATE_NAME := sm
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_ADD_IMPLICIT_DEPS := false
+
+MODULE_DEPS := \
+	trusty/kernel/lib/sm \
+	trusty/user/base/lib/liballoc-rust \
+	trusty/user/base/lib/libcompiler_builtins-rust \
+	trusty/user/base/lib/libcore-rust \
+
+MODULE_BINDGEN_ALLOW_FUNCTIONS := \
+	sm_intc_raise_doorbell_irq \
+
+MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/lib/sm/shared_mem.c b/lib/sm/shared_mem.c
index 6abc437..873d83b 100644
--- a/lib/sm/shared_mem.c
+++ b/lib/sm/shared_mem.c
@@ -41,7 +41,8 @@
 #define LOCAL_TRACE 0
 
 struct sm_mem_obj {
-    uint16_t sender_id;
+    struct sm_vm* vm;
+    struct obj_ref vm_ref;
     struct ext_mem_obj ext_mem_obj;
 };
 
@@ -124,12 +125,15 @@ static void sm_mem_obj_destroy(struct vmm_obj* vmm_obj) {
             containerof(vmm_obj, struct sm_mem_obj, ext_mem_obj.vmm_obj);
 
     DEBUG_ASSERT(obj);
+    DEBUG_ASSERT(obj->vm);
 
     ret = arm_ffa_mem_relinquish(obj->ext_mem_obj.id);
     if (ret != NO_ERROR) {
         TRACEF("Failed to relinquish the shared memory (%d)\n", ret);
     }
 
+    /* Release the VM reference */
+    sm_vm_del_ref(obj->vm, &obj->vm_ref);
     free(obj);
 }
 
@@ -141,7 +145,7 @@ static struct vmm_obj_ops sm_mem_obj_ops = {
 
 /**
  * sm_mem_alloc_obj - Allocate and initialize memory object.
- * @sender_id:      FF-A vm id of sender.
+ * @vm:             Pointer to VM object of sender.
  * @mem_id:         Id of object.
  * @tag:            Tag of the object
  * @page_run_count: Number of page runs to allocate for object.
@@ -150,7 +154,7 @@ static struct vmm_obj_ops sm_mem_obj_ops = {
  *
  * Return: Pointer to &struct sm_mem_obj, or %NULL if allocation fails.
  */
-static struct sm_mem_obj* sm_mem_alloc_obj(uint16_t sender_id,
+static struct sm_mem_obj* sm_mem_alloc_obj(struct sm_vm* vm,
                                            ext_mem_obj_id_t mem_id,
                                            uint64_t tag,
                                            size_t page_run_count,
@@ -163,13 +167,16 @@ static struct sm_mem_obj* sm_mem_alloc_obj(uint16_t sender_id,
     }
     ext_mem_obj_initialize(&obj->ext_mem_obj, obj_ref, mem_id, tag,
                            &sm_mem_obj_ops, arch_mmu_flags, page_run_count);
-    obj->sender_id = sender_id;
+
+    obj->vm = vm;
+    obj_ref_init(&obj->vm_ref);
+    sm_vm_add_ref(vm, &obj->vm_ref);
 
     return obj;
 }
 
 /* sm_mem_get_vmm_obj - Looks up a shared memory object using FF-A.
- * @client_id:      Id of external entity where the memory originated.
+ * @vm:             Pointer to VM object of sender.
  * @mem_obj_id:     Id of shared memory object to lookup and return.
  * @tag:            Tag of the memory.
  * @size:           Size hint for object. Caller expects an object at least this
@@ -179,22 +186,25 @@ static struct sm_mem_obj* sm_mem_alloc_obj(uint16_t sender_id,
  *
  * Return: 0 on success. ERR_NOT_FOUND if @id does not exist.
  */
-static status_t sm_mem_get_vmm_obj(ext_mem_client_id_t client_id,
+static status_t sm_mem_get_vmm_obj(struct sm_vm* vm,
                                    ext_mem_obj_id_t mem_obj_id,
                                    uint64_t tag,
                                    size_t size,
                                    struct vmm_obj** objp,
                                    struct obj_ref* obj_ref) {
     int ret;
+    ext_mem_client_id_t client_id;
     struct arm_ffa_mem_frag_info frag_info;
     uint32_t address_range_count;
     uint arch_mmu_flags;
     struct sm_mem_obj* obj;
     struct obj_ref tmp_obj_ref = OBJ_REF_INITIAL_VALUE(tmp_obj_ref);
 
+    DEBUG_ASSERT(vm);
     DEBUG_ASSERT(objp);
     DEBUG_ASSERT(obj_ref);
 
+    client_id = sm_vm_get_id(vm);
     if ((client_id & 0xffff) != client_id) {
         TRACEF("Invalid client ID\n");
         return ERR_INVALID_ARGS;
@@ -208,7 +218,7 @@ static status_t sm_mem_get_vmm_obj(ext_mem_client_id_t client_id,
         TRACEF("Failed to get FF-A memory buffer, err=%d\n", ret);
         goto err_mem_get_access;
     }
-    obj = sm_mem_alloc_obj(client_id, mem_obj_id, tag, address_range_count,
+    obj = sm_mem_alloc_obj(vm, mem_obj_id, tag, address_range_count,
                            arch_mmu_flags, &tmp_obj_ref);
     if (!obj) {
         TRACEF("Failed to allocate a shared memory object\n");
@@ -253,6 +263,38 @@ err_mem_get_access:
     return ret;
 }
 
+/**
+ * ext_mem_get_vm_vmm_obj - Lookup or create shared memory object for a VM.
+ * @vm:         VM where the memory originated.
+ * @mem_obj_id: Id of shared memory object to lookup and return.
+ * @tag:        Value to identify the transaction.
+ * @size:       Size hint for object.
+ * @objp:       Pointer to return object in.
+ * @obj_ref:    Reference to *@objp.
+ *
+ * Call SPM/Hypervisor to retrieve memory region or extract address and
+ * attributes from id for old clients.
+ */
+status_t ext_mem_get_vm_vmm_obj(struct sm_vm* vm,
+                                ext_mem_obj_id_t mem_obj_id,
+                                uint64_t tag,
+                                size_t size,
+                                struct vmm_obj** objp,
+                                struct obj_ref* obj_ref) {
+    ext_mem_client_id_t client_id = sm_vm_get_id(vm);
+
+    if (sm_get_api_version() >= TRUSTY_API_VERSION_MEM_OBJ) {
+        return sm_mem_get_vmm_obj(vm, mem_obj_id, tag, size, objp, obj_ref);
+    } else if (!client_id && !tag) {
+        /* If client is not running under a hypervisor allow using
+           old api. */
+        return sm_mem_compat_get_vmm_obj(client_id, mem_obj_id, size, objp,
+                                         obj_ref);
+    } else {
+        return ERR_NOT_SUPPORTED;
+    }
+}
+
 /*
  * ext_mem_get_vmm_obj - Lookup or create shared memory object.
  * @client_id:  Id of external entity where the memory originated.
@@ -271,17 +313,24 @@ status_t ext_mem_get_vmm_obj(ext_mem_client_id_t client_id,
                              size_t size,
                              struct vmm_obj** objp,
                              struct obj_ref* obj_ref) {
-    if (sm_get_api_version() >= TRUSTY_API_VERSION_MEM_OBJ) {
-        return sm_mem_get_vmm_obj(client_id, mem_obj_id, tag, size, objp,
-                                  obj_ref);
-    } else if (!client_id && !tag) {
-        /* If client is not running under a hypervisor allow using
-           old api. */
-        return sm_mem_compat_get_vmm_obj(client_id, mem_obj_id, size, objp,
-                                         obj_ref);
-    } else {
-        return ERR_NOT_SUPPORTED;
+    struct sm_vm* vm = NULL;
+    struct obj_ref vm_ref = OBJ_REF_INITIAL_VALUE(vm_ref);
+    status_t ret;
+
+    /*
+     * Get the VM for the given client ID.
+     * This should work even for the compatibility path because
+     * we have a default compatibility VM that the callee should return here.
+     */
+    ret = sm_vm_get(client_id, &vm_ref, &vm);
+    if (ret != NO_ERROR) {
+        TRACEF("Failed to get VM %" PRIu64 " reference (%d)\n", client_id, ret);
+        return ret;
     }
+
+    ret = ext_mem_get_vm_vmm_obj(vm, mem_obj_id, tag, size, objp, obj_ref);
+    sm_vm_del_ref(vm, &vm_ref);
+    return ret;
 }
 
 /**
diff --git a/lib/sm/sm.c b/lib/sm/sm.c
index cec2df6..db61cbb 100644
--- a/lib/sm/sm.c
+++ b/lib/sm/sm.c
@@ -21,11 +21,15 @@
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
 
+#include <arch/mp.h>
 #include <err.h>
+#include <interface/arm_ffa/arm_ffa.h>
 #include <kernel/event.h>
 #include <kernel/mutex.h>
 #include <kernel/thread.h>
 #include <kernel/vm.h>
+#include <lib/arm_ffa/arm_ffa.h>
+#include <lib/binary_search_tree.h>
 #include <lib/heap.h>
 #include <lib/sm.h>
 #include <lib/sm/sm_err.h>
@@ -64,6 +68,62 @@ static atomic_uint_fast32_t sm_api_version_max = TRUSTY_API_VERSION_CURRENT;
 static spin_lock_t sm_api_version_lock;
 static atomic_bool platform_halted;
 
+#if LIB_SM_WITH_FFA_LOOP
+static bool sm_use_ffa = true;
+static atomic_bool sm_ffa_valid_call;
+#else
+static bool sm_use_ffa = false;
+#endif
+
+enum sm_vm_state {
+    SM_VM_STATE_FRESH,
+    SM_VM_STATE_AVAILABLE,
+    SM_VM_STATE_DESTROY_NOTIFYING,
+    SM_VM_STATE_DESTROY_NOTIFIED,
+    SM_VM_STATE_READY_TO_FREE
+};
+
+struct sm_vm {
+    struct bst_node node;
+    enum sm_vm_state state;
+    ext_mem_obj_id_t client_id;
+    struct list_node notifiers;
+    struct obj refobj;
+    struct obj_ref self_ref;
+};
+
+/*
+ * VM ID to create; can be one of two values:
+ * * Non-negative 16-bit VM ID, or
+ * * -1 when no VM needs to be created
+ */
+static int32_t sm_vm_to_create = -1;
+static struct bst_root sm_vm_tree = BST_ROOT_INITIAL_VALUE;
+static struct bst_root sm_vm_free_tree = BST_ROOT_INITIAL_VALUE;
+static spin_lock_t sm_vm_lock;
+static event_t sm_vm_event =
+        EVENT_INITIAL_VALUE(sm_vm_event, 0, EVENT_FLAG_AUTOUNSIGNAL);
+static thread_t* sm_vm_notifier_thread;
+static atomic_uintptr_t sm_vm_active_notifier;
+static event_t sm_vm_notifier_done_event =
+        EVENT_INITIAL_VALUE(sm_vm_notifier_done_event,
+                            0,
+                            EVENT_FLAG_AUTOUNSIGNAL);
+
+/*
+ * Placeholder compatibility VM for environments without hypervisors
+ * and for the bootloader that may call Trusty before the hypervisor has
+ * initialized. This pseudo-VM does not get creation or destruction messages
+ * so we add and remove it from the tree manually.
+ */
+static struct sm_vm sm_vm_compat_vm = {
+        .node = BST_NODE_INITIAL_VALUE,
+        .state = SM_VM_STATE_FRESH,
+        .client_id = 0,
+        .notifiers = LIST_INITIAL_VALUE(sm_vm_compat_vm.notifiers),
+        .self_ref = OBJ_REF_INITIAL_VALUE(sm_vm_compat_vm.self_ref),
+};
+
 static event_t nsirqevent[SMP_MAX_CPUS];
 static thread_t* nsirqthreads[SMP_MAX_CPUS];
 static thread_t* nsidlethreads[SMP_MAX_CPUS];
@@ -80,6 +140,8 @@ extern smc32_handler_t sm_stdcall_table[];
 extern smc32_handler_t sm_nopcall_table[];
 extern smc32_handler_t sm_fastcall_table[];
 
+static long sm_get_stdcall_ret(ext_mem_obj_id_t);
+
 long smc_sm_api_version(struct smc32_args* args) {
     uint32_t api_version = args->params[0];
 
@@ -213,7 +275,13 @@ static long sm_queue_stdcall(struct smc32_args* args) {
     event_signal(&stdcallstate.event, false);
 
 restart_stdcall:
-    stdcallstate.active_cpu = cpu;
+    if (!sm_use_ffa) {
+        /*
+         * On FF-A, we do not keep track of the active CPU since
+         * get_stdcall_ret is called by a separate direct message.
+         */
+        stdcallstate.active_cpu = cpu;
+    }
     ret = 0;
 
 err:
@@ -222,7 +290,679 @@ err:
     return ret;
 }
 
+#if LIB_SM_WITH_FFA_LOOP
+static long sm_ffa_handle_direct_req(long ret, struct smc_ret18* regs) {
+    struct smc32_args args;
+    uint16_t client_id = (regs->r1 >> 16) & 0xFFFFU;
+    uint cpu = arch_curr_cpu_num();
+
+    switch (regs->r3) {
+    case TRUSTY_FFA_MSG_RUN_FASTCALL:
+        if (SMC_IS_SMC64(regs->r4)) {
+            return SM_ERR_NOT_SUPPORTED;
+        }
+        if (!SMC_IS_FASTCALL(regs->r4)) {
+            dprintf(CRITICAL, "Synchronous message is not a fastcall: %lx\n",
+                    regs->r4);
+            return SM_ERR_INVALID_PARAMETERS;
+        }
+
+        args.smc_nr = regs->r4;
+        args.params[0] = regs->r5;
+        args.params[1] = regs->r6;
+        args.params[2] = regs->r7;
+        args.client_id = client_id;
+        return sm_fastcall_table[SMC_ENTITY(args.smc_nr)](&args);
+
+    case TRUSTY_FFA_MSG_QUEUE_STDCALL:
+        if (SMC_IS_SMC64(regs->r4)) {
+            return SM_ERR_NOT_SUPPORTED;
+        }
+        if (SMC_IS_FASTCALL(regs->r4)) {
+            dprintf(CRITICAL, "Asynchronous message is a fastcall: %lx\n",
+                    regs->r4);
+            return SM_ERR_INVALID_PARAMETERS;
+        }
+
+        args.smc_nr = regs->r4;
+        args.params[0] = regs->r5;
+        args.params[1] = regs->r6;
+        args.params[2] = regs->r7;
+        args.client_id = client_id;
+
+        ret = sm_queue_stdcall(&args);
+        if (!ret) {
+            /* Ring the doorbell on the host so it queues a Trusty NOP */
+            sm_intc_raise_doorbell_irq();
+        }
+        return ret;
+
+    case TRUSTY_FFA_MSG_GET_STDCALL_RET:
+        return sm_get_stdcall_ret((ext_mem_obj_id_t)client_id);
+
+    case TRUSTY_FFA_MSG_RUN_NOPCALL:
+        args.smc_nr = SMC_SC_NOP;
+        args.params[0] = regs->r4;
+        args.params[1] = regs->r5;
+        args.params[2] = regs->r6;
+        args.client_id = client_id;
+
+#if !ARM_MERGE_FIQ_IRQ
+#error "FF-A libsm requires ARM_MERGE_FIQ_IRQ"
+#endif
+        ret = sm_nopcall_table[SMC_ENTITY(args.params[0])](&args);
+        if (!ret) {
+            /* Ring the doorbell on the host so it queues a Trusty NOP */
+            sm_intc_raise_doorbell_irq();
+        }
+        return ret;
+
+    case TRUSTY_FFA_MSG_IS_IDLE:
+        return get_current_thread() == nsidlethreads[cpu];
+
+    default:
+        dprintf(CRITICAL,
+                "Unsupported FF-A message from client %" PRIu16 ": %lx\n",
+                client_id, regs->r3);
+        return SM_ERR_NOT_SUPPORTED;
+    }
+}
+#endif
+
+static int sm_vm_compare_key(const struct bst_node* a, const void* b) {
+    const struct sm_vm* vm = containerof(a, struct sm_vm, node);
+    ext_mem_obj_id_t key = *(ext_mem_obj_id_t*)b;
+
+    if (key > vm->client_id) {
+        return 1;
+    } else if (key < vm->client_id) {
+        return -1;
+    } else {
+        return 0;
+    }
+}
+
+static int sm_vm_compare(struct bst_node* a, struct bst_node* b) {
+    const struct sm_vm* vm_b = containerof(b, struct sm_vm, node);
+
+    return sm_vm_compare_key(a, &vm_b->client_id);
+}
+
+static void sm_vm_add_compat_vm_locked(ext_mem_client_id_t client_id) {
+    DEBUG_ASSERT(spin_lock_held(&sm_vm_lock));
+
+    if (!bst_is_empty(&sm_vm_tree)) {
+        /*
+         * There is already a VM in the tree, so we don't need
+         * to add the compatibility VM explicitly.
+         */
+        return;
+    }
+    if (sm_vm_to_create != -1) {
+        /* The tree is empty but we have a pending VM queued up for creation */
+        return;
+    }
+
+    DEBUG_ASSERT(sm_vm_compat_vm.state == SM_VM_STATE_FRESH ||
+                 sm_vm_compat_vm.state == SM_VM_STATE_READY_TO_FREE);
+
+    sm_vm_compat_vm.client_id = client_id;
+    obj_init(&sm_vm_compat_vm.refobj, &sm_vm_compat_vm.self_ref);
+    if (!bst_insert(&sm_vm_tree, &sm_vm_compat_vm.node, sm_vm_compare)) {
+        panic("failed to insert compatibility VM\n");
+    }
+    sm_vm_compat_vm.state = SM_VM_STATE_AVAILABLE;
+}
+
+status_t sm_vm_notifier_register(struct sm_vm_notifier* notif) {
+    spin_lock_saved_state_t state;
+    struct sm_vm* vm;
+    status_t ret;
+
+    if (!notif) {
+        return ERR_INVALID_ARGS;
+    }
+    if (!notif->destroy) {
+        return ERR_INVALID_ARGS;
+    }
+
+    spin_lock_irqsave(&sm_vm_lock, state);
+    sm_vm_add_compat_vm_locked(notif->client_id);
+
+    vm = bst_search_key_type(&sm_vm_tree, &notif->client_id, sm_vm_compare_key,
+                             struct sm_vm, node);
+    if (!vm) {
+        ret = ERR_NOT_FOUND;
+    } else if (vm->state == SM_VM_STATE_AVAILABLE) {
+        list_add_tail(&vm->notifiers, &notif->node);
+        ret = NO_ERROR;
+    } else {
+        ret = ERR_BAD_STATE;
+    }
+    spin_unlock_irqrestore(&sm_vm_lock, state);
+
+    return ret;
+}
+
+status_t sm_vm_notifier_unregister(struct sm_vm_notifier* notif) {
+    spin_lock_saved_state_t state;
+    status_t ret = NO_ERROR;
+    struct sm_vm* vm;
+
+    if (!notif) {
+        return ERR_INVALID_ARGS;
+    }
+
+    spin_lock_irqsave(&sm_vm_lock, state);
+    /*
+     * Check the node with the lock held to avoid
+     * it getting removed during the check
+     */
+    if (!list_in_list(&notif->node)) {
+        ret = ERR_NOT_FOUND;
+        goto err_notif_not_in_list;
+    }
+    if ((uintptr_t)notif == atomic_load(&sm_vm_active_notifier)) {
+        spin_unlock_irqrestore(&sm_vm_lock, state);
+
+        /* The callback is currently running, wait for it to finish */
+        do {
+            /*
+             * If sm_vm_active_notifier is notif, that means that our
+             * notifier is currently running; retry the event_wait
+             * until the notifier actually completes in order to avoid
+             * leftover wakeups. We use a global variable because the
+             * notifier might have been destroyed by the handler by
+             * the time it returns.
+             */
+            event_wait(&sm_vm_notifier_done_event);
+        } while ((uintptr_t)notif == atomic_load(&sm_vm_active_notifier));
+
+        /* Nothing else to do here, the notifier is already out of the list */
+        return NO_ERROR;
+    }
+
+    vm = bst_search_key_type(&sm_vm_tree, &notif->client_id, sm_vm_compare_key,
+                             struct sm_vm, node);
+    if (!vm) {
+        ret = ERR_NOT_FOUND;
+        goto err_no_vm;
+    }
+
+    list_delete(&notif->node);
+
+err_notif_not_in_list:
+err_no_vm:
+    spin_unlock_irqrestore(&sm_vm_lock, state);
+    return ret;
+}
+
+status_t sm_vm_get(ext_mem_obj_id_t client_id,
+                   struct obj_ref* ref,
+                   struct sm_vm** out_vm) {
+    spin_lock_saved_state_t state;
+    struct sm_vm* vm;
+
+    if (!ref) {
+        return ERR_INVALID_ARGS;
+    }
+    if (obj_ref_active(ref)) {
+        return ERR_INVALID_ARGS;
+    }
+    if (!out_vm) {
+        return ERR_INVALID_ARGS;
+    }
+
+    spin_lock_irqsave(&sm_vm_lock, state);
+    sm_vm_add_compat_vm_locked(client_id);
+
+    vm = bst_search_key_type(&sm_vm_tree, &client_id, sm_vm_compare_key,
+                             struct sm_vm, node);
+    if (!vm) {
+        spin_unlock_irqrestore(&sm_vm_lock, state);
+        return ERR_NOT_FOUND;
+    }
+
+    obj_add_ref(&vm->refobj, ref);
+    *out_vm = vm;
+    spin_unlock_irqrestore(&sm_vm_lock, state);
+
+    return NO_ERROR;
+}
+
+void sm_vm_add_ref(struct sm_vm* vm, struct obj_ref* ref) {
+    spin_lock_saved_state_t state;
+
+    DEBUG_ASSERT(vm);
+    DEBUG_ASSERT(ref);
+    DEBUG_ASSERT(!obj_ref_active(ref));
+
+    spin_lock_irqsave(&sm_vm_lock, state);
+    obj_add_ref(&vm->refobj, ref);
+    spin_unlock_irqrestore(&sm_vm_lock, state);
+}
+
+void sm_vm_del_ref(struct sm_vm* vm, struct obj_ref* ref) {
+    spin_lock_saved_state_t state;
+
+    DEBUG_ASSERT(vm);
+    DEBUG_ASSERT(ref);
+    DEBUG_ASSERT(obj_ref_active(ref));
+
+    spin_lock_irqsave(&sm_vm_lock, state);
+    obj_del_ref(&vm->refobj, ref, NULL);
+
+    if (obj_has_only_ref(&vm->refobj, &vm->self_ref) &&
+        vm->state == SM_VM_STATE_DESTROY_NOTIFYING) {
+        /*
+         * This is the last reference to the VM and it is getting destroyed,
+         * so wake up the notifier thread so it updates the state
+         */
+        event_signal(&sm_vm_event, false);
+    }
+    spin_unlock_irqrestore(&sm_vm_lock, state);
+}
+
+ext_mem_client_id_t sm_vm_get_id(struct sm_vm* vm) {
+    DEBUG_ASSERT(vm);
+
+    return vm->client_id;
+}
+
+#if LIB_SM_WITH_FFA_LOOP
+static long sm_ffa_handle_framework_msg(struct smc_ret18* regs) {
+    uint32_t msg = regs->r2 & FFA_FRAMEWORK_MSG_MASK;
+    ext_mem_obj_id_t client_id = regs->r5 & 0xffffU;
+    struct sm_vm* vm;
+    long ret;
+    bool inserted;
+
+    /* TODO: validate receiver */
+
+    switch (msg) {
+    case FFA_FRAMEWORK_MSG_VM_CREATED_REQ:
+        LTRACEF_LEVEL(1, "Got VM creation message for %" PRIu64 "\n",
+                      client_id);
+
+        spin_lock(&sm_vm_lock);
+        vm = bst_search_key_type(&sm_vm_tree, &client_id, sm_vm_compare_key,
+                                 struct sm_vm, node);
+        if (!vm) {
+            if (sm_vm_to_create == -1) {
+                sm_vm_to_create = client_id;
+                event_signal(&sm_vm_event, false);
+                sm_intc_raise_doorbell_irq();
+            }
+            ret = FFA_ERROR_RETRY;
+        } else if (vm->state == SM_VM_STATE_FRESH) {
+            vm->state = SM_VM_STATE_AVAILABLE;
+            ret = 0;
+        } else {
+            dprintf(CRITICAL, "Duplicate VM creation for %" PRIu64 "\n",
+                    client_id);
+            ret = FFA_ERROR_INVALID_PARAMETERS;
+        }
+        spin_unlock(&sm_vm_lock);
+
+        LTRACEF_LEVEL(2, "VM creation returning %ld\n", ret);
+        regs->r2 = FFA_FRAMEWORK_MSG_VM_CREATED_RESP | FFA_FRAMEWORK_MSG_FLAG;
+        return ret;
+
+    case FFA_FRAMEWORK_MSG_VM_DESTROYED_REQ:
+        LTRACEF_LEVEL(1, "Got VM destruction message for %" PRIu64 "\n",
+                      client_id);
+
+        spin_lock(&sm_vm_lock);
+        vm = bst_search_key_type(&sm_vm_tree, &client_id, sm_vm_compare_key,
+                                 struct sm_vm, node);
+        if (!vm) {
+            ret = FFA_ERROR_INVALID_PARAMETERS;
+        } else {
+            DEBUG_ASSERT(vm->state != SM_VM_STATE_READY_TO_FREE);
+
+            switch (vm->state) {
+            case SM_VM_STATE_FRESH:
+                /*
+                 * We got a creation request for this VM that we
+                 * returned RETRY on, but the hypervisor never retried
+                 * the request until we could report a success and now
+                 * it's sending us a destruction request for that VM.
+                 *
+                 * We could start destroying the VM instead, but this
+                 * is not correct hypervisor behavior so we are probably
+                 * better off returning an error.
+                 */
+                dprintf(CRITICAL, "Got early VM destroy for %" PRIu64 "\n",
+                        client_id);
+                ret = FFA_ERROR_INVALID_PARAMETERS;
+                break;
+
+            case SM_VM_STATE_AVAILABLE:
+                vm->state = SM_VM_STATE_DESTROY_NOTIFYING;
+                /*
+                 * Signal the thread so it destroys the VM and ring
+                 * the doorbell on the host so it queues a Trusty NOP
+                 */
+                event_signal(&sm_vm_event, false);
+                sm_intc_raise_doorbell_irq();
+                __FALLTHROUGH;
+
+            case SM_VM_STATE_DESTROY_NOTIFYING:
+                ret = FFA_ERROR_RETRY;
+                break;
+
+            case SM_VM_STATE_DESTROY_NOTIFIED:
+                /* Mark the VM for freeing since we're done with it */
+                vm->state = SM_VM_STATE_READY_TO_FREE;
+                bst_delete(&sm_vm_tree, &vm->node);
+                inserted =
+                        bst_insert(&sm_vm_free_tree, &vm->node, sm_vm_compare);
+                DEBUG_ASSERT(inserted);
+                ret = 0;
+                /*
+                 * Signal the event so the VM is freed later; we do not
+                 * need to ring the doorbell because this is not urgent,
+                 * so the freeing can happen whenever Trusty gets cycles next.
+                 */
+                event_signal(&sm_vm_event, false);
+                break;
+
+            default:
+                panic("Invalid VM state: %d\n", vm->state);
+            }
+        }
+        spin_unlock(&sm_vm_lock);
+
+        LTRACEF_LEVEL(2, "VM destruction returning %ld\n", ret);
+        regs->r2 = FFA_FRAMEWORK_MSG_VM_DESTROYED_RESP | FFA_FRAMEWORK_MSG_FLAG;
+        return ret;
+
+    default:
+        dprintf(CRITICAL, "Unhandled FF-A framework message: %x\n", msg);
+        return FFA_ERROR_NOT_SUPPORTED;
+    }
+}
+#endif
+
+static int __NO_RETURN sm_vm_notifier_loop(void* arg) {
+    spin_lock_saved_state_t state;
+    struct sm_vm* vm;
+    struct sm_vm_notifier* notif;
+    status_t ret;
+
+    while (true) {
+        event_wait(&sm_vm_event);
+
+        /* Create the new VM if a message came in */
+        while (true) {
+            int32_t vm_id;
+            struct sm_vm* vm;
+            bool inserted;
+
+            spin_lock_irqsave(&sm_vm_lock, state);
+            if (sm_vm_to_create != -1 &&
+                sm_vm_compat_vm.state == SM_VM_STATE_AVAILABLE) {
+                /* We got an actual VM, tear down the compatibility one */
+                sm_vm_compat_vm.state = SM_VM_STATE_DESTROY_NOTIFYING;
+                /*
+                 * Signal the event so we continue the outer loop because
+                 * the remainder of the current iteration will handle the
+                 * new NOTIFYING state for the compatibility VM. The event
+                 * will be used at the start of the next iteration to get
+                 * back here and create the new VM.
+                 */
+                event_signal(&sm_vm_event, false);
+                /* Defer creation of the new VM until compat_vm is gone */
+                vm_id = -1;
+            } else {
+                vm_id = sm_vm_to_create;
+            }
+            spin_unlock_irqrestore(&sm_vm_lock, state);
+
+            LTRACEF_LEVEL(2, "Creating fresh VM %d\n", vm_id);
+            if (vm_id == -1) {
+                break;
+            }
+
+            vm = calloc(1, sizeof(struct sm_vm));
+            if (!vm) {
+                dprintf(CRITICAL, "Out of memory for VMs\n");
+                continue;
+            }
+
+            vm->state = SM_VM_STATE_FRESH;
+            vm->client_id = vm_id;
+            list_initialize(&vm->notifiers);
+            obj_init(&vm->refobj, &vm->self_ref);
+
+            spin_lock_irqsave(&sm_vm_lock, state);
+            sm_vm_to_create = -1;
+            inserted = bst_insert(&sm_vm_tree, &vm->node, sm_vm_compare);
+            spin_unlock_irqrestore(&sm_vm_lock, state);
+            DEBUG_ASSERT(inserted);
+        }
+
+        /* Destroy all VMs on the free list */
+        while (true) {
+            spin_lock_irqsave(&sm_vm_lock, state);
+            vm = bst_next_type(&sm_vm_free_tree, NULL, struct sm_vm, node);
+            if (vm) {
+                bst_delete(&sm_vm_free_tree, &vm->node);
+            }
+            spin_unlock_irqrestore(&sm_vm_lock, state);
+
+            if (!vm) {
+                break;
+            }
+
+            LTRACEF_LEVEL(2, "Freeing VM %" PRIu64 "\n", vm->client_id);
+            DEBUG_ASSERT(vm->state == SM_VM_STATE_READY_TO_FREE);
+            obj_del_ref(&vm->refobj, &vm->self_ref, NULL);
+            free(vm);
+        }
+
+        /* Call the next notifier */
+        while (true) {
+            spin_lock_irqsave(&sm_vm_lock, state);
+            notif = NULL;
+            bst_for_every_entry(&sm_vm_tree, vm, struct sm_vm, node) {
+                if (vm->state == SM_VM_STATE_DESTROY_NOTIFYING) {
+                    if (!list_is_empty(&vm->notifiers)) {
+                        notif = list_remove_head_type(
+                                &vm->notifiers, struct sm_vm_notifier, node);
+                        atomic_store(&sm_vm_active_notifier, (uintptr_t)notif);
+                        break;
+                    }
+
+                    if (!obj_has_only_ref(&vm->refobj, &vm->self_ref)) {
+                        /* There are active references to this VM */
+                        continue;
+                    }
+
+                    /*
+                     * No more notifiers or references, we can mark the VM
+                     * as "destroy-notified" and move on to the next one.
+                     *
+                     * This is thread-safe because only the current thread
+                     * runs the notifiers, and no new nodes can be added
+                     * while in the SM_VM_STATE_DESTROY_NOTIFYING.
+                     */
+                    vm->state = SM_VM_STATE_DESTROY_NOTIFIED;
+
+                    if (vm == &sm_vm_compat_vm) {
+                        /*
+                         * We are done with the compatibility VM,
+                         * remove it from the tree permanently.
+                         */
+                        vm->state = SM_VM_STATE_READY_TO_FREE;
+                        bst_delete(&sm_vm_tree, &vm->node);
+                        DEBUG_ASSERT(sm_vm_event.signaled);
+                    }
+                }
+            }
+            spin_unlock_irqrestore(&sm_vm_lock, state);
+
+            if (!notif) {
+                break;
+            }
+
+            LTRACEF_LEVEL(2, "Calling VM destroy handler for %" PRIu64 "\n",
+                          notif->client_id);
+            DEBUG_ASSERT(notif->destroy);
+            ret = notif->destroy(notif);
+            if (ret) {
+                TRACEF("VM destroy handler returned error (%d)\n", ret);
+            }
+            atomic_store(&sm_vm_active_notifier, 0);
+            event_signal(&sm_vm_notifier_done_event, true);
+        }
+    }
+}
+
+#if LIB_SM_WITH_FFA_LOOP
+static void sm_ffa_loop(long ret, struct smc32_args* args) {
+    struct smc_ret18 regs = {0};
+    uint64_t extended_args[ARM_FFA_MSG_EXTENDED_ARGS_COUNT];
+    STATIC_ASSERT(sizeof extended_args == sizeof regs.req2_params);
+    enum arm_ffa_init_state ffa_init_state = arm_ffa_init_state();
+
+    if (atomic_load(&platform_halted)) {
+        regs = arm_ffa_call_error(FFA_ERROR_ABORTED);
+    } else if (ffa_init_state == ARM_FFA_INIT_UNINIT) {
+        panic("FF-A not initialized before main loop\n");
+    } else if (ffa_init_state == ARM_FFA_INIT_FAILED) {
+        TRACEF("FF-A failed to initialize, "
+               "falling back to legacy SPD SMCs\n");
+        sm_use_ffa = false;
+        return;
+    } else {
+        /*
+         * Linux will check the shadow priority next and
+         * give us more cycles if it's anything other than IDLE
+         */
+        LTRACEF_LEVEL(5, "Calling FFA_MSG_WAIT (%ld)\n", ret);
+        regs = arm_ffa_call_msg_wait();
+    }
+
+    while (true) {
+        LTRACEF_LEVEL(5, "Incoming FF-A SMC (%lx)\n", regs.r0);
+        switch ((uint32_t)regs.r0) {
+        case SMC_FC_FFA_MSG_SEND_DIRECT_REQ:
+        case SMC_FC64_FFA_MSG_SEND_DIRECT_REQ:
+            if (atomic_load(&platform_halted)) {
+                /* Return to NS since we have nothing to do */
+                regs = arm_ffa_call_error(FFA_ERROR_ABORTED);
+                break;
+            }
+            atomic_store(&sm_ffa_valid_call, true);
+
+            if (regs.r2 & FFA_FRAMEWORK_MSG_FLAG) {
+                ret = sm_ffa_handle_framework_msg(&regs);
+            } else {
+                ret = sm_ffa_handle_direct_req(ret, &regs);
+            }
+
+            LTRACEF_LEVEL(5, "Calling FFA_MSG_SEND_DIRECT_RESP (%ld)\n", ret);
+            regs = arm_ffa_msg_send_direct_resp(&regs, (ulong)ret, 0, 0, 0, 0);
+            break;
+
+        case SMC_FC64_FFA_MSG_SEND_DIRECT_REQ2:
+            if (atomic_load(&platform_halted)) {
+                regs = arm_ffa_call_error(FFA_ERROR_ABORTED);
+                break;
+            }
+
+            ret = arm_ffa_handle_direct_req2(&regs);
+            /*
+             * Whereas sm_ffa_handle_direct_req returns secure monitor error
+             * codes, arm_ffa_handle_direct_req2 can fail with Trusty error
+             * codes not understood by the caller, e.g., if no handler is found.
+             */
+            if (ret) {
+                dprintf(CRITICAL,
+                        "Failed to handle FFA_MSG_SEND_DIRECT_REQ2: %lx\n",
+                        ret);
+                regs = arm_ffa_call_error(FFA_ERROR_ABORTED);
+                break;
+            }
+
+            LTRACEF_LEVEL(5, "Calling FFA_MSG_SEND_DIRECT_RESP2 (%ld)\n", ret);
+            /*
+             * copy req2_params into a fresh buffer `args` since the former can
+             * be overwritten at any time by the callee.
+             */
+            memcpy(extended_args, regs.req2_params, sizeof extended_args);
+            regs = arm_ffa_msg_send_direct_resp2(&regs, extended_args);
+            break;
+
+        case SMC_FC_FFA_RUN:
+            if (atomic_load(&platform_halted)) {
+                /* Return to NS since we have nothing to do */
+                regs = arm_ffa_call_error(FFA_ERROR_ABORTED);
+                break;
+            }
+            atomic_store(&sm_ffa_valid_call, true);
+
+            args->smc_nr = SMC_SC_NOP;
+            args->params[0] = args->params[1] = args->params[2] = 0;
+            return;
+
+        case SMC_FC_FFA_INTERRUPT:
+            atomic_store(&sm_ffa_valid_call, true);
+            sm_intc_fiq_enter();
+            /*
+             * sm_intc_fiq_enter rings the doorbell,
+             * so we do not need to do it again here.
+             */
+            regs = arm_ffa_call_msg_wait();
+            break;
+
+        case SMC_FC_FFA_ERROR:
+            if (atomic_load(&platform_halted)) {
+                /*
+                 * Loop forever if we halted and
+                 * got back here from FFA_ERROR_ABORTED,
+                 * there is not much else we can do
+                 */
+                break;
+            }
+            if ((int32_t)regs.r2 == FFA_ERROR_NOT_SUPPORTED &&
+                !atomic_load(&sm_ffa_valid_call)) {
+                TRACEF("Using legacy SPD SMCs\n");
+                sm_use_ffa = false;
+                return;
+            }
+            panic("Received FFA_ERROR from SPMC: (%lx, %lx)\n", regs.r1,
+                  regs.r2);
+
+        case SMC_UNKNOWN:
+            if (atomic_load(&sm_ffa_valid_call)) {
+                /* We already got a valid FF-A call earlier */
+                panic("Received SMC_UNKNOWN from SPMC\n");
+            }
+            TRACEF("Using legacy SPD SMCs\n");
+            sm_use_ffa = false;
+            return;
+
+        default:
+            dprintf(CRITICAL, "Unhandled FF-A SMC: %lx\n", regs.r0);
+            regs = arm_ffa_call_error(FFA_ERROR_NOT_SUPPORTED);
+        }
+    }
+}
+#endif
+
 static void sm_sched_nonsecure_fiq_loop(long ret, struct smc32_args* args) {
+#if LIB_SM_WITH_FFA_LOOP
+    if (sm_use_ffa) {
+        sm_ffa_loop(ret, args);
+        /* Check again in case we switched to the legacy SPD SMCs */
+        if (sm_use_ffa) {
+            return;
+        }
+    }
+#endif
+
     while (true) {
         if (atomic_load(&platform_halted)) {
             ret = SM_ERR_PANIC;
@@ -261,6 +1001,7 @@ static enum handler_return sm_return_and_wait_for_next_stdcall(long ret,
             LTRACEF_LEVEL(3, "cpu %d, got nop\n", cpu);
             ret = sm_nopcall_table[SMC_ENTITY(args.params[0])](&args);
         } else {
+            DEBUG_ASSERT(!sm_use_ffa);
             ret = sm_queue_stdcall(&args);
         }
     } while (ret);
@@ -311,20 +1052,26 @@ static int __NO_RETURN sm_irq_loop(void* arg) {
 }
 
 /* must be called with irqs disabled */
-static long sm_get_stdcall_ret(void) {
+static long sm_get_stdcall_ret(ext_mem_obj_id_t client_id) {
     long ret;
     uint cpu = arch_curr_cpu_num();
 
     spin_lock(&stdcallstate.lock);
 
-    if (stdcallstate.active_cpu != (int)cpu) {
+    if (!sm_use_ffa && stdcallstate.active_cpu != (int)cpu) {
         dprintf(CRITICAL, "%s: stdcallcpu, a%d != curr-cpu %d, l%d, i%d\n",
                 __func__, stdcallstate.active_cpu, cpu, stdcallstate.last_cpu,
                 stdcallstate.initial_cpu);
         ret = SM_ERR_INTERNAL_FAILURE;
         goto err;
     }
-    stdcallstate.last_cpu = stdcallstate.active_cpu;
+    if (stdcallstate.args.client_id != client_id) {
+        dprintf(CRITICAL, "%s: stdcallcpu, client %" PRIx64 " != %" PRIx64 "\n",
+                __func__, stdcallstate.args.client_id, client_id);
+        ret = SM_ERR_NOT_ALLOWED;
+        goto err;
+    }
+    stdcallstate.last_cpu = (int)cpu;
     stdcallstate.active_cpu = -1;
 
     if (stdcallstate.done) {
@@ -383,7 +1130,7 @@ static int sm_wait_for_smcall(void* arg) {
         cpu = enter_smcall_critical_section();
 
         if (cpu == stdcallstate.active_cpu)
-            ret = sm_get_stdcall_ret();
+            ret = sm_get_stdcall_ret(stdcallstate.args.client_id);
         else
             ret = SM_ERR_NOP_DONE;
 
@@ -475,6 +1222,14 @@ static void sm_init(uint level) {
     }
     thread_set_real_time(stdcallthread);
     thread_resume(stdcallthread);
+
+    sm_vm_notifier_thread =
+            thread_create("sm-vm-notifier", sm_vm_notifier_loop, NULL,
+                          HIGH_PRIORITY, DEFAULT_STACK_SIZE);
+    if (!sm_vm_notifier_thread) {
+        panic("failed to create sm-vm-notifier thread!\n");
+    }
+    thread_resume(sm_vm_notifier_thread);
 }
 
 LK_INIT_HOOK(libsm, sm_init, LK_INIT_LEVEL_PLATFORM - 1);
@@ -494,6 +1249,7 @@ enum handler_return sm_handle_irq(void) {
 void sm_handle_fiq(void) {
     uint32_t expected_return;
     struct smc32_args args = SMC32_ARGS_INITIAL_VALUE(args);
+    DEBUG_ASSERT(!sm_use_ffa);
     if (sm_check_and_lock_api_version(TRUSTY_API_VERSION_RESTART_FIQ)) {
         sm_sched_nonsecure_fiq_loop(SM_ERR_FIQ_INTERRUPTED, &args);
         expected_return = SMC_SC_RESTART_FIQ;
diff --git a/lib/sm/trusty_sched_share.c b/lib/sm/trusty_sched_share.c
index 8477772..6f43b87 100644
--- a/lib/sm/trusty_sched_share.c
+++ b/lib/sm/trusty_sched_share.c
@@ -231,32 +231,45 @@ static struct trusty_percpu_shared_data* get_percpu_share_ptr(uint32_t cpu_nr) {
     return percpu_data_ptr;
 }
 
-/*
- * Following function is called from trusty kernel thread.c
- */
-void platform_cpu_priority_set(uint32_t cpu_nr, uint32_t priority) {
-    spin_lock_saved_state_t state;
-    struct trusty_percpu_shared_data* percpu_data_ptr;
-    uint32_t requested_priority;
-
+static uint32_t cpu_priority_to_shadow(uint32_t current_priority,
+                                       uint32_t priority) {
     /* Ignore the set request by irq-ns-switch-* threads, which exclusively
      * run at the HIGHEST_PRIORITY. The problem is that the irq-ns-switch-*
      * threads run on behalf of linux (or any other normal world client os)
      * and are always the threads that return to linux (client os) while
      * trusty is busy,  but those are not the threads whose priority, the
      * linux side wants to know.
+     *
+     * The only exception is TRUSTY_SHADOW_PRIORITY_IDLE.
+     * We use that to signal to linux that we're done, but we want
+     * the opposite if we got here from the irq threads.
+     * It means an idle thread got interrupted; we would like to actually
+     * return the priority of the next ready thread, but we do not have
+     * that so we return HIGH just in case the next thread could
+     * want that priority.
      */
-    if (priority >= HIGHEST_PRIORITY) {
-        return;
+    if (priority >= HIGHEST_PRIORITY &&
+        current_priority != TRUSTY_SHADOW_PRIORITY_IDLE) {
+        return current_priority;
     }
 
     if (priority >= HIGH_PRIORITY) {
-        requested_priority = TRUSTY_SHADOW_PRIORITY_HIGH;
+        return TRUSTY_SHADOW_PRIORITY_HIGH;
+    } else if (priority <= LOWEST_PRIORITY + 1) {
+        return TRUSTY_SHADOW_PRIORITY_IDLE;
     } else if (priority <= LOW_PRIORITY) {
-        requested_priority = TRUSTY_SHADOW_PRIORITY_LOW;
+        return TRUSTY_SHADOW_PRIORITY_LOW;
     } else {
-        requested_priority = TRUSTY_SHADOW_PRIORITY_NORMAL;
+        return TRUSTY_SHADOW_PRIORITY_NORMAL;
     }
+}
+
+/*
+ * Following function is called from trusty kernel thread.c
+ */
+void platform_cpu_priority_set(uint32_t cpu_nr, uint32_t priority) {
+    spin_lock_saved_state_t state;
+    struct trusty_percpu_shared_data* percpu_data_ptr;
 
     /*
      * if the shared-memory is established and the reuesting
@@ -266,7 +279,8 @@ void platform_cpu_priority_set(uint32_t cpu_nr, uint32_t priority) {
     spin_lock_irqsave(&sched_shared_datalock, state);
     if ((sched_shared_mem) && (cpu_nr < shareinfo.cpu_count)) {
         percpu_data_ptr = get_percpu_share_ptr(cpu_nr);
-        percpu_data_ptr->ask_shadow_priority = requested_priority;
+        percpu_data_ptr->ask_shadow_priority = cpu_priority_to_shadow(
+                percpu_data_ptr->ask_shadow_priority, priority);
     }
     spin_unlock_irqrestore(&sched_shared_datalock, state);
 }
diff --git a/lib/smc/arch/arm64/smc.S b/lib/smc/arch/arm64/smc.S
index 76c0cc7..40988eb 100644
--- a/lib/smc/arch/arm64/smc.S
+++ b/lib/smc/arch/arm64/smc.S
@@ -48,3 +48,80 @@ FUNCTION(smc8)
 
 FUNCTION(hvc8)
     smc8_hvc8 hvc
+
+.macro smc8_hvc8_ret18, instr
+    /*
+     * Save x19 and lr. The SMC calling convention says el3 does not need to
+     * preserve x8 (return value ptr). The aarch64 calling convention (AAPCS64)
+     * says x8 is caller-saved even when used as the return value pointer.
+     */
+    push    x19, lr
+    mov     x19, x8 /* preserve return value pointer in x19  */
+
+    mov     x8,  xzr
+    mov     x9,  xzr
+    mov     x10, xzr
+    mov     x11, xzr
+    mov     x12, xzr
+    mov     x13, xzr
+    mov     x14, xzr
+    mov     x15, xzr
+    mov     x16, xzr
+    mov     x17, xzr
+
+    \instr  #0
+
+    /* Copy 8-register smc return value plus x8-x17 into struct smc_ret18 */
+    stp     x0,  x1,  [x19], #16
+    stp     x2,  x3,  [x19], #16
+    stp     x4,  x5,  [x19], #16
+    stp     x6,  x7,  [x19], #16
+    stp     x8,  x9,  [x19], #16
+    stp     x10, x11, [x19], #16
+    stp     x12, x13, [x19], #16
+    stp     x14, x15, [x19], #16
+    stp     x16, x17, [x19], #16
+
+    pop     x19, lr
+
+    ret
+.endm
+
+FUNCTION(smc8_ret18)
+    smc8_hvc8_ret18 smc
+
+FUNCTION(hvc8_ret18)
+    smc8_hvc8_ret18 hvc
+
+.macro smc18_hvc18, instr
+    push x19, lr
+    mov  x19, x8
+
+    ldp x8,  x9,  [sp, #16]
+    ldp x10, x11, [sp, #32]
+    ldp x12, x13, [sp, #48]
+    ldp x14, x15, [sp, #64]
+    ldp x16, x17, [sp, #80]
+
+    \instr  #0
+
+    stp     x0,  x1,  [x19], #16
+    stp     x2,  x3,  [x19], #16
+    stp     x4,  x5,  [x19], #16
+    stp     x6,  x7,  [x19], #16
+    stp     x8,  x9,  [x19], #16
+    stp     x10, x11, [x19], #16
+    stp     x12, x13, [x19], #16
+    stp     x14, x15, [x19], #16
+    stp     x16, x17, [x19], #16
+
+    pop     x19, lr
+
+    ret
+.endm
+
+FUNCTION(smc18)
+    smc18_hvc18 smc
+
+FUNCTION(hvc18)
+    smc18_hvc18 hvc
diff --git a/lib/smc/include/lib/smc/smc.h b/lib/smc/include/lib/smc/smc.h
index 44999e6..bfeaa12 100644
--- a/lib/smc/include/lib/smc/smc.h
+++ b/lib/smc/include/lib/smc/smc.h
@@ -23,6 +23,7 @@
 
 #pragma once
 
+#include <shared/lk/compiler.h>
 #include <sys/types.h>
 
 /* Unknown SMC (defined by ARM DEN 0028A(0.9.0) */
@@ -39,6 +40,36 @@ struct smc_ret8 {
     ulong r7;
 };
 
+#define ARM_FFA_MSG_EXTENDED_ARGS_COUNT 14
+
+struct smc_ret18 {
+    ulong r0;
+    ulong r1;
+    ulong r2;
+    ulong r3;
+    union {
+        struct {
+            ulong r4;
+            ulong r5;
+            ulong r6;
+            ulong r7;
+            ulong r8;
+            ulong r9;
+            ulong r10;
+            ulong r11;
+            ulong r12;
+            ulong r13;
+            ulong r14;
+            ulong r15;
+            ulong r16;
+            ulong r17;
+        };
+        ulong req2_params[ARM_FFA_MSG_EXTENDED_ARGS_COUNT];
+    };
+};
+
+STATIC_ASSERT(sizeof(struct smc_ret18) == sizeof(ulong) * 18);
+
 struct smc_ret8 smc8(ulong r0,
                      ulong r1,
                      ulong r2,
@@ -56,3 +87,65 @@ struct smc_ret8 hvc8(ulong r0,
                      ulong r5,
                      ulong r6,
                      ulong r7);
+
+/*
+ * same as smc8 but returns 18 registers with x8 and above set to zero on entry
+ */
+struct smc_ret18 smc8_ret18(ulong r0,
+                            ulong r1,
+                            ulong r2,
+                            ulong r3,
+                            ulong r4,
+                            ulong r5,
+                            ulong r6,
+                            ulong r7);
+
+/*
+ * same as hvc8 but returns 18 registers with x8 and above set to zero on entry
+ */
+struct smc_ret18 hvc8_ret18(ulong r0,
+                            ulong r1,
+                            ulong r2,
+                            ulong r3,
+                            ulong r4,
+                            ulong r5,
+                            ulong r6,
+                            ulong r7);
+
+struct smc_ret18 smc18(ulong r0,
+                       ulong r1,
+                       ulong r2,
+                       ulong r3,
+                       ulong r4,
+                       ulong r5,
+                       ulong r6,
+                       ulong r7,
+                       ulong r8,
+                       ulong r9,
+                       ulong r10,
+                       ulong r11,
+                       ulong r12,
+                       ulong r13,
+                       ulong r14,
+                       ulong r15,
+                       ulong r16,
+                       ulong r17);
+
+struct smc_ret18 hvc18(ulong r0,
+                       ulong r1,
+                       ulong r2,
+                       ulong r3,
+                       ulong r4,
+                       ulong r5,
+                       ulong r6,
+                       ulong r7,
+                       ulong r8,
+                       ulong r9,
+                       ulong r10,
+                       ulong r11,
+                       ulong r12,
+                       ulong r13,
+                       ulong r14,
+                       ulong r15,
+                       ulong r16,
+                       ulong r17);
diff --git a/lib/trusty/handle.c b/lib/trusty/handle.c
index c63290e..9ce9ad6 100644
--- a/lib/trusty/handle.c
+++ b/lib/trusty/handle.c
@@ -185,6 +185,10 @@ void handle_notify(struct handle* handle) {
     spin_unlock_restore(&handle->slock, state, SPIN_LOCK_FLAG_INTERRUPTS);
 }
 
+bool handle_ref_is_attached(const struct handle_ref* const ref) {
+    return list_in_list(&ref->set_node);
+}
+
 void handle_list_init(struct handle_list* hlist) {
     DEBUG_ASSERT(hlist);
 
diff --git a/lib/trusty/include/lib/trusty/handle.h b/lib/trusty/include/lib/trusty/handle.h
index 7bf61ff..5b48284 100644
--- a/lib/trusty/include/lib/trusty/handle.h
+++ b/lib/trusty/include/lib/trusty/handle.h
@@ -180,6 +180,11 @@ static inline void* handle_get_cookie(struct handle* handle) {
     return handle->cookie;
 }
 
+/**
+ * Safe to call no matter the state `ref` is in, as long as it was initialized.
+ */
+bool handle_ref_is_attached(const struct handle_ref* ref);
+
 void handle_list_init(struct handle_list* hlist);
 void handle_list_add(struct handle_list* hlist, struct handle* handle);
 void handle_list_del(struct handle_list* hlist, struct handle* handle);
diff --git a/lib/trusty/include/lib/trusty/handle_set.h b/lib/trusty/include/lib/trusty/handle_set.h
index c192170..9836a9b 100644
--- a/lib/trusty/include/lib/trusty/handle_set.h
+++ b/lib/trusty/include/lib/trusty/handle_set.h
@@ -29,6 +29,7 @@
 #define HSET_ADD 0
 #define HSET_DEL 1
 #define HSET_MOD 2
+#define HSET_DEL_GET_COOKIE 3
 
 __BEGIN_CDECLS
 
diff --git a/lib/trusty/smcall.c b/lib/trusty/smcall.c
index db8eff6..4a6d09f 100644
--- a/lib/trusty/smcall.c
+++ b/lib/trusty/smcall.c
@@ -132,7 +132,8 @@ static long trusty_sm_stdcall(struct smc32_args* args) {
     case SMC_SC_VIRTIO_STOP:
         res = get_ns_mem_buf(args, &ns_buf_id, &ns_sz);
         if (res == NO_ERROR)
-            res = virtio_stop(args->client_id, ns_buf_id, ns_sz, ns_mmu_flags);
+            res = virtio_stop(args->client_id, ns_buf_id, ns_sz, ns_mmu_flags,
+                              true);
         break;
 
     case SMC_SC_VDEV_RESET:
diff --git a/lib/trusty/tipc_dev_ql.c b/lib/trusty/tipc_dev_ql.c
index ecc58b7..31d4299 100644
--- a/lib/trusty/tipc_dev_ql.c
+++ b/lib/trusty/tipc_dev_ql.c
@@ -485,8 +485,15 @@ static long dev_has_event(struct ql_tipc_dev* dev,
                           uint32_t target) {
     const int opcode = QL_TIPC_DEV_FC_HAS_EVENT;
 
-    if (ns_sz < (sizeof(struct tipc_cmd_hdr) + sizeof(bool)) ||
-        ns_sz > dev->ns_sz) {
+    /*
+     * Ignore ns_sz. The client sets payload_len to 0 since the payload is
+     * only used to return data, no data is passed in.
+     *
+     * Check that buffer is large enough for the response, even though this
+     * check can't fail with the current struct size, since dev->ns_sz has
+     * already been checked to be page aligned and non-0.
+     */
+    if ((sizeof(struct tipc_cmd_hdr) + sizeof(bool)) > dev->ns_sz) {
         return set_status(dev, opcode, ERR_INVALID_ARGS, 0);
     }
 
diff --git a/lib/trusty/tipc_virtio_dev.c b/lib/trusty/tipc_virtio_dev.c
index fe29117..14f27d4 100644
--- a/lib/trusty/tipc_virtio_dev.c
+++ b/lib/trusty/tipc_virtio_dev.c
@@ -1096,6 +1096,10 @@ static status_t tipc_dev_reset(struct tipc_dev* dev) {
     vqueue_destroy(&dev->vqs[TIPC_VQ_RX]);
     vqueue_destroy(&dev->vqs[TIPC_VQ_TX]);
 
+    /* destroy iovs left over from reuse_mapping */
+    vqueue_unmap_list(&dev->receive_mapped);
+    vqueue_unmap_list(&dev->send_mapped);
+
     /* enter reset state */
     dev->vd.state = VDEV_STATE_RESET;
 
diff --git a/lib/trusty/trusty_virtio.c b/lib/trusty/trusty_virtio.c
index 7f8616d..cba5079 100644
--- a/lib/trusty/trusty_virtio.c
+++ b/lib/trusty/trusty_virtio.c
@@ -36,6 +36,7 @@
 #include <kernel/spinlock.h>
 #include <kernel/vm.h>
 #include <lib/binary_search_tree.h>
+#include <lib/sm.h>
 #include <lk/init.h>
 #include <lk/reflist.h>
 
@@ -80,6 +81,7 @@ struct trusty_virtio_bus {
      * bus may be freed.
      */
     event_t free_bus_event;
+    struct sm_vm_notifier vm_notifier;
 };
 
 static spin_lock_t virtio_buses_tree_lock = SPIN_LOCK_INITIAL_VALUE;
@@ -225,7 +227,8 @@ static struct trusty_virtio_bus* get_client_bus(ext_mem_client_id_t client_id,
  * the bus held by the caller.
  */
 static void remove_client_bus(struct trusty_virtio_bus* vb,
-                              struct obj_ref* ref) {
+                              struct obj_ref* ref,
+                              bool unregister_vm_notifier) {
     DEBUG_ASSERT(vb);
     DEBUG_ASSERT(ref);
 
@@ -255,6 +258,14 @@ static void remove_client_bus(struct trusty_virtio_bus* vb,
     if (bus_in_tree) {
         /* Blocks until the last reference to the bus is dropped */
         event_wait(&vb->free_bus_event);
+        if (unregister_vm_notifier) {
+            /*
+             * We have to unregister the VM notifier if called from
+             * anywhere other than the destruction callback,
+             * but only if it has been registered successfully.
+             */
+            sm_vm_notifier_unregister(&vb->vm_notifier);
+        }
         /*
          * Only the first call to remove_client_bus will find the bus in the
          * tree and end up freeing the bus
@@ -377,6 +388,10 @@ static void finalize_vdev_registry(struct trusty_virtio_bus* vb) {
     }
 }
 
+static status_t virtio_vm_destroy(struct sm_vm_notifier* notif) {
+    return virtio_stop(notif->client_id, 0, 0, 0, false);
+}
+
 /*
  * Retrieve device description to be shared with NS side
  */
@@ -402,6 +417,17 @@ ssize_t virtio_get_description(ext_mem_client_id_t client_id,
         return ret;
     }
 
+    ret = sm_vm_notifier_init(&vb->vm_notifier, client_id, virtio_vm_destroy);
+    if (!ret) {
+        ret = sm_vm_notifier_register(&vb->vm_notifier);
+    }
+    if (ret) {
+        LTRACEF("Could not register VM event notifier for client %" PRId64 "\n",
+                client_id);
+        remove_client_bus(vb, &tmp_ref, false);
+        return ret;
+    }
+
     /* on_create notifiers must only be called if virtio bus is uninitialized */
     if (vb->state == VIRTIO_BUS_STATE_UNINITIALIZED) {
         ret = on_create_virtio_bus(vb);
@@ -460,7 +486,7 @@ ssize_t virtio_get_description(ext_mem_client_id_t client_id,
 err_failed_map:
 err_buffer:
 err_failed_on_create:
-    remove_client_bus(vb, &tmp_ref);
+    remove_client_bus(vb, &tmp_ref, true);
     return ret;
 }
 
@@ -556,7 +582,8 @@ err_invalid_args:
 status_t virtio_stop(ext_mem_client_id_t client_id,
                      ext_mem_obj_id_t descr_id,
                      ns_size_t descr_sz,
-                     uint descr_mmu_flags) {
+                     uint descr_mmu_flags,
+                     bool unregister_vm_notifier) {
     status_t ret;
     int oldstate;
     struct vdev* vd;
@@ -592,13 +619,13 @@ status_t virtio_stop(ext_mem_client_id_t client_id,
     }
 
     vb->state = VIRTIO_BUS_STATE_IDLE;
-    remove_client_bus(vb, &tmp_ref);
+    remove_client_bus(vb, &tmp_ref, unregister_vm_notifier);
 
     return NO_ERROR;
 
 err_bad_state:
     /* Remove the bus even if it was not in the active state */
-    remove_client_bus(vb, &tmp_ref);
+    remove_client_bus(vb, &tmp_ref, unregister_vm_notifier);
     return ret;
 
 err_invalid_args:
diff --git a/lib/trusty/trusty_virtio.h b/lib/trusty/trusty_virtio.h
index 6de968b..86e263c 100644
--- a/lib/trusty/trusty_virtio.h
+++ b/lib/trusty/trusty_virtio.h
@@ -85,7 +85,8 @@ status_t virtio_start(ext_mem_client_id_t client_id,
 status_t virtio_stop(ext_mem_client_id_t client_id,
                      ext_mem_obj_id_t descr_id,
                      ns_size_t sz,
-                     uint mmu_flags);
+                     uint mmu_flags,
+                     bool unregister_vm_notifier);
 
 /*
  *  Reset virtio device with specified device id
diff --git a/lib/trusty/uctx.c b/lib/trusty/uctx.c
index d9c6716..abd6ed1 100644
--- a/lib/trusty/uctx.c
+++ b/lib/trusty/uctx.c
@@ -711,7 +711,9 @@ static int _hset_add_item(struct handle* hset,
                             item->ref_list.prev);
 }
 
-static int _hset_del_item(struct handle* hset, struct htbl_entry* item) {
+static int _hset_del_item(struct handle* hset,
+                          struct htbl_entry* item,
+                          struct uevent* uevent) {
     uint del_cnt = 0;
     struct handle_ref* ref;
     struct handle_ref* tmp;
@@ -721,12 +723,16 @@ static int _hset_del_item(struct handle* hset, struct htbl_entry* item) {
         if (ref->parent == hset) {
             del_cnt++;
             LTRACEF("%p: %p\n", ref->parent, ref->handle);
+            if (uevent) {
+                uevent->cookie = (user_addr_t)(uintptr_t)ref->cookie;
+            }
             list_delete(&ref->uctx_node);
             handle_set_detach_ref(ref);
             handle_decref(ref->handle);
             free(ref);
         }
     }
+    ASSERT(del_cnt <= 1);
     return del_cnt ? NO_ERROR : ERR_NOT_FOUND;
 }
 
@@ -746,41 +752,47 @@ static int _hset_mod_item(struct handle* hset,
             handle_set_update_ref(ref, emask, cookie);
         }
     }
+    ASSERT(mod_cnt <= 1);
     return mod_cnt ? NO_ERROR : ERR_NOT_FOUND;
 }
 
 static int _hset_ctrl_locked(handle_id_t hset_id,
-                             handle_id_t h_id,
                              uint32_t cmd,
-                             uint32_t event,
-                             void* cookie) {
+                             struct uevent* uevent) {
     int ret;
     int h_idx, hset_idx;
     struct uctx* ctx = current_uctx();
 
-    LTRACEF("%d: %d: cmd=%d\n", hset_id, h_id, cmd);
+    LTRACEF("%d: %d: cmd=%d\n", hset_id, uevent->handle, cmd);
 
     hset_idx = _check_handle_id(ctx, hset_id);
     if (hset_idx < 0)
         return hset_idx;
 
-    h_idx = _check_handle_id(ctx, h_id);
+    h_idx = _check_handle_id(ctx, uevent->handle);
     if (h_idx < 0)
         return h_idx;
 
     switch (cmd) {
     case HSET_ADD:
         ret = _hset_add_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
-                             h_id, event, cookie);
+                             uevent->handle, uevent->event,
+                             (void*)(uintptr_t)uevent->cookie);
         break;
 
     case HSET_DEL:
-        ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx]);
+        ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
+                             NULL);
+        break;
+
+    case HSET_DEL_GET_COOKIE:
+        ret = _hset_del_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
+                             uevent);
         break;
 
     case HSET_MOD:
         ret = _hset_mod_item(ctx->htbl[hset_idx].handle, &ctx->htbl[h_idx],
-                             event, cookie);
+                             uevent->event, (void*)(uintptr_t)uevent->cookie);
         break;
 
     default:
@@ -803,9 +815,12 @@ long __SYSCALL sys_handle_set_ctrl(handle_id_t hset_id,
         return ret;
 
     mutex_acquire(&ctx->mlock);
-    ret = _hset_ctrl_locked(hset_id, uevent.handle, cmd, uevent.event,
-                            (void*)(uintptr_t)uevent.cookie);
+    ret = _hset_ctrl_locked(hset_id, cmd, &uevent);
     mutex_release(&ctx->mlock);
+    if (ret < 0)
+        return ret;
+    if (cmd == HSET_DEL_GET_COOKIE)
+        ret = copy_to_user(user_event, &uevent, sizeof(uevent));
     return ret;
 }
 
diff --git a/lib/trusty/vqueue.c b/lib/trusty/vqueue.c
index 5a59ac5..9192e94 100644
--- a/lib/trusty/vqueue.c
+++ b/lib/trusty/vqueue.c
@@ -434,6 +434,18 @@ int vqueue_unmap_memid(ext_mem_obj_id_t id,
     return ERR_NOT_FOUND;
 }
 
+void vqueue_unmap_list(struct vqueue_mapped_list* mapped_list) {
+    struct vqueue_mem_obj* obj;
+
+    mutex_acquire(&mapped_list->lock);
+    bst_for_every_entry_delete(&mapped_list->list, obj, struct vqueue_mem_obj,
+                               node) {
+        vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)obj->iov_base);
+        free(obj);
+    }
+    mutex_release(&mapped_list->lock);
+}
+
 static int _vqueue_add_buf_locked(struct vqueue* vq,
                                   struct vqueue_buf* buf,
                                   uint32_t len) {
diff --git a/lib/trusty/vqueue.h b/lib/trusty/vqueue.h
index 05c095f..af9c411 100644
--- a/lib/trusty/vqueue.h
+++ b/lib/trusty/vqueue.h
@@ -106,6 +106,8 @@ int vqueue_unmap_memid(ext_mem_obj_id_t id,
                        struct vqueue_mapped_list* mapped_list[],
                        int list_cnt);
 
+void vqueue_unmap_list(struct vqueue_mapped_list* mapped_list);
+
 int vqueue_add_buf(struct vqueue* vq, struct vqueue_buf* buf, uint32_t len);
 
 void vqueue_signal_avail(struct vqueue* vq);
diff --git a/lib/vmm_obj_service/rust/rules.mk b/lib/vmm_obj_service/rust/rules.mk
new file mode 100644
index 0000000..1f28729
--- /dev/null
+++ b/lib/vmm_obj_service/rust/rules.mk
@@ -0,0 +1,16 @@
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MODULE_CRATE_NAME := vmm_obj_service_rust
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,zerocopy) \
+	packages/modules/Virtualization/libs/libfdt \
+	trusty/user/base/lib/trusty-std \
+
+include make/library.mk
diff --git a/lib/vmm_obj_service/rust/src/lib.rs b/lib/vmm_obj_service/rust/src/lib.rs
new file mode 100644
index 0000000..8c0968f
--- /dev/null
+++ b/lib/vmm_obj_service/rust/src/lib.rs
@@ -0,0 +1,169 @@
+/*
+ * Copyright (c) 2024 Google Inc. All rights reserved
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
+use core::ffi::CStr;
+use core::marker::PhantomPinned;
+use core::pin::Pin;
+use rust_support::{
+    ktipc::{ktipc_port_acl, ktipc_server, ktipc_server_new, ktipc_server_start},
+    mmu::PAGE_SIZE,
+    vmm::{
+        vmm_get_kernel_aspace, vmm_get_obj, vmm_obj_service, vmm_obj_service_add,
+        vmm_obj_service_create_ro, vmm_obj_service_destroy, vmm_obj_slice, vmm_obj_slice_init,
+        vmm_obj_slice_release, VmmPageArray,
+    },
+    Error,
+};
+use trusty_std::boxed::Box;
+use zerocopy::{Immutable, IntoBytes};
+
+#[derive(Immutable, IntoBytes)]
+#[repr(C)]
+pub struct VmmObjServiceHeader {
+    data_start: u32,
+    size: u32,
+}
+const HDR_SIZE: usize = core::mem::size_of::<VmmObjServiceHeader>();
+
+fn create_obj_service_ro(
+    port: &'static CStr,
+    acl: &'static ktipc_port_acl,
+    slice: &vmm_obj_slice,
+    size: usize,
+) -> Result<*mut vmm_obj_service, Error> {
+    let mut svc: *mut vmm_obj_service = core::ptr::null_mut();
+    // SAFETY: port and acl are static and therefore valid for the lifetime of vmm_obj_service.
+    let rc = unsafe { vmm_obj_service_create_ro(port.as_ptr(), acl, slice.obj, 0, size, &mut svc) };
+    if rc < 0 {
+        log::error!("Failed to create service {:X}", rc);
+        Error::from_lk(rc)?;
+    }
+    Ok(svc)
+}
+
+struct VmmObj {
+    page_array: VmmPageArray,
+    slice: vmm_obj_slice,
+    _marker: PhantomPinned,
+}
+impl VmmObj {
+    fn new(page_array: VmmPageArray) -> Result<Pin<Box<Self>>, Error> {
+        let aspace = vmm_get_kernel_aspace();
+        let ptr = page_array.ptr();
+        let size = page_array.size();
+        let mut slice = Box::<Self>::new_uninit();
+        // SAFETY: Initializes a vmm_obj_slice to a default state. Slice is allocated above.
+        unsafe { vmm_obj_slice_init(&raw mut (*slice.as_mut_ptr()).slice) };
+        // SAFETY: Move page_array since we're aliasing it's pointer and want to prevent anyone
+        // else from accessing it. This also ensures that underlying memory remains allocated for
+        // the lifetime of VmmObj.
+        unsafe { (*slice.as_mut_ptr()).page_array = page_array };
+        // SAFETY: The object has been initialized by the two operations above.
+        let mut slice = unsafe { slice.assume_init() };
+        // SAFETY: ptr allocated by the vmm service. slice has been default initialized above and
+        // is populated by this call with the object backing aligned buffer.
+        let rc = unsafe { vmm_get_obj(aspace, ptr as usize, size, &mut slice.as_mut().slice) };
+        if rc < 0 {
+            Error::from_lk(rc)?;
+        }
+        // obj_ref in vmm_obj_slice cannot be moved, to convert this into Pin.
+        let slice = Box::<VmmObj>::into_pin(slice);
+        Ok(slice)
+    }
+}
+
+impl Drop for VmmObj {
+    fn drop(&mut self) {
+        // SAFETY: Deallocating resources on failure. vmm_obj_slice_release is safe to call on an
+        // object in the default state.
+        unsafe { vmm_obj_slice_release(&mut self.slice) };
+    }
+}
+
+/// Shares a buffer with the TAs specified in acl. The buffer is copied to new pages and prefixed
+/// with size of the passed in data as a usize. This size will differ from that provided by
+/// vmm_obj_service_create_ro and vmm_obj_map_ro as those function operate in increments of
+/// PAGE_SIZE.
+///
+/// # Arguments
+///
+/// * `buffer` - a buffer to share with TAs.
+/// * `size` - size of buffer.
+/// * `align_log2` - alignment to use for the start of the destination data.
+/// * `port` - a tipc port name for TAs to request the mapped buffer.
+/// * `acl` - a ktipc_port_acl specifying which trust zones may connect and which apps may connect.
+///     If uuids is empty, any app may connect.
+///
+pub fn share_sized_buffer(
+    buffer: *const u8,
+    size: usize,
+    align_log2: u8,
+    port: &'static CStr,
+    acl: &'static ktipc_port_acl,
+) -> Result<(), Error> {
+    let aligned_ptr: usize = buffer as usize & !(PAGE_SIZE as usize - 1);
+    let offset = buffer as usize - aligned_ptr;
+    let aligned_size = (size + offset).next_multiple_of(PAGE_SIZE as usize);
+
+    let mut phys_page_array = VmmPageArray::new_physical(port, aligned_ptr, aligned_size, 0, 0)?;
+
+    let align = 1usize << align_log2;
+    let dst_data_start = HDR_SIZE.next_multiple_of(align);
+    let dst_size = (size + dst_data_start).next_multiple_of(PAGE_SIZE as usize);
+
+    let mut page_array = VmmPageArray::new(port, dst_size, 0, 0)?;
+    let header = VmmObjServiceHeader { data_start: dst_data_start as u32, size: size as u32 };
+    page_array.as_mut_slice()[..HDR_SIZE].copy_from_slice(header.as_bytes());
+    page_array.as_mut_slice()[dst_data_start..size + dst_data_start]
+        .copy_from_slice(&phys_page_array.as_mut_slice()[offset..offset + size]);
+
+    let slice = VmmObj::new(page_array)?;
+
+    let srv = ktipc_server_new(port);
+    // srv becomes owned by a new thread in ktipc_server_start, so leak the box to ensure Rust
+    // doesn't deallocate it.
+    let srv: *mut ktipc_server = Box::<ktipc_server>::leak(srv);
+    // SAFETY: srv has been intentionally leaked and ownership is transferred to a thread create by
+    // ktipc_server_start.
+    let rc = unsafe { ktipc_server_start(srv) };
+    if rc < 0 {
+        log::error!("Failed to create thread: {:X}", rc);
+        Error::from_lk(rc)?;
+    }
+
+    let mut svc = create_obj_service_ro(port, acl, &slice.slice, dst_size)?;
+
+    // SAFETY: vmm_obj_service_add add a new service (svc) to the ktipc server (srv). srv has
+    // already been moved to its own thread and svc now becomes owned by srv.
+    let rc = unsafe { vmm_obj_service_add(svc, srv) };
+    if rc < 0 {
+        log::error!("Failed to add service: {:X}", rc);
+        // SAFETY: Deallocating resources on failure.
+        unsafe { vmm_obj_service_destroy(&mut svc) };
+        Error::from_lk(rc)?;
+    }
+
+    Ok(())
+}
diff --git a/make/generic_compile.mk b/make/generic_compile.mk
index 28ac211..bef406b 100644
--- a/make/generic_compile.mk
+++ b/make/generic_compile.mk
@@ -47,19 +47,21 @@ GENERIC_FLAGS += --sysroot $(CLANG_HOST_SYSROOT)
 
 # Group the source files so we can differ the flags between C, C++, and assembly.
 GENERIC_C_SRCS := $(filter %.c,$(GENERIC_SRCS))
-GENERIC_C_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.c,%.o,$(GENERIC_C_SRCS)))
+GENERIC_C_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.c,%.c.o,$(GENERIC_C_SRCS)))
 
 GENERIC_CC_SRCS := $(filter %.cc,$(GENERIC_SRCS))
-GENERIC_CC_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.cc,%.o,$(GENERIC_CC_SRCS)))
+GENERIC_CC_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.cc,%.cc.o,$(GENERIC_CC_SRCS)))
 
 GENERIC_CPP_SRCS := $(filter %.cpp,$(GENERIC_SRCS))
-GENERIC_CPP_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.cpp,%.o,$(GENERIC_CPP_SRCS)))
+GENERIC_CPP_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.cpp,%.cpp.o,$(GENERIC_CPP_SRCS)))
 
 GENERIC_ASM_SRCS := $(filter %.S,$(GENERIC_SRCS))
-GENERIC_ASM_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.S,%.o,$(GENERIC_ASM_SRCS)))
+GENERIC_ASM_OBJS := $(addprefix $(GENERIC_OBJ_DIR)/,$(patsubst %.S,%.S.o,$(GENERIC_ASM_SRCS)))
 
 GENERIC_OBJS := $(strip $(GENERIC_C_OBJS) $(GENERIC_CC_OBJS) $(GENERIC_CPP_OBJS) $(GENERIC_ASM_OBJS))
 
+ALLOBJS += $(GENERIC_OBJS)
+
 # Bind inputs.
 $(GENERIC_OBJS): CC := $(GENERIC_CC)
 $(GENERIC_OBJS): FLAGS := $(GENERIC_FLAGS)
@@ -68,28 +70,28 @@ $(GENERIC_OBJS): CPPFLAGS := $(GENERIC_CPPFLAGS)
 $(GENERIC_OBJS): ASMFLAGS := $(GENERIC_ASMFLAGS)
 $(GENERIC_OBJS): LOG_NAME := $(GENERIC_LOG_NAME)
 
-$(GENERIC_C_OBJS): $(GENERIC_OBJ_DIR)/%.o: %.c $(GENERIC_SRCDEPS)
+$(GENERIC_C_OBJS): $(GENERIC_OBJ_DIR)/%.c.o: %.c $(GENERIC_SRCDEPS)
 	@$(call ECHO,$(LOG_NAME),building,$@)
 	@$(MKDIR)
-	$(NOECHO)$(CC) $(FLAGS) $(CFLAGS) -c $< -MMD -o $@
+	$(NOECHO)$(CC) $(FLAGS) $(CFLAGS) -c $< -MMD -MP -o $@
 	@$(call ECHO_DONE_SILENT,$(LOG_NAME),building,$@)
 
-$(GENERIC_CC_OBJS): $(GENERIC_OBJ_DIR)/%.o: %.cc $(GENERIC_SRCDEPS)
+$(GENERIC_CC_OBJS): $(GENERIC_OBJ_DIR)/%.cc.o: %.cc $(GENERIC_SRCDEPS)
 	@$(call ECHO,$(LOG_NAME),building,$@)
 	@$(MKDIR)
-	$(NOECHO)$(CC) $(FLAGS) $(CPPFLAGS) -c $< -MMD -o $@
+	$(NOECHO)$(CC) $(FLAGS) $(CPPFLAGS) -c $< -MMD -MP -o $@
 	@$(call ECHO_DONE_SILENT,$(LOG_NAME),building,$@)
 
-$(GENERIC_CPP_OBJS): $(GENERIC_OBJ_DIR)/%.o: %.cpp $(GENERIC_SRCDEPS)
+$(GENERIC_CPP_OBJS): $(GENERIC_OBJ_DIR)/%.cpp.o: %.cpp $(GENERIC_SRCDEPS)
 	@$(call ECHO,$(LOG_NAME),building,$@)
 	@$(MKDIR)
-	$(NOECHO)$(CC) $(FLAGS) $(CPPFLAGS) -c $< -MMD -o $@
+	$(NOECHO)$(CC) $(FLAGS) $(CPPFLAGS) -c $< -MMD -MP -o $@
 	@$(call ECHO_DONE_SILENT,$(LOG_NAME),building,$@)
 
-$(GENERIC_ASM_OBJS): $(GENERIC_OBJ_DIR)/%.o: %.S $(GENERIC_SRCDEPS)
+$(GENERIC_ASM_OBJS): $(GENERIC_OBJ_DIR)/%.S.o: %.S $(GENERIC_SRCDEPS)
 	@$(call ECHO,$(LOG_NAME),building,$@)
 	@$(MKDIR)
-	$(NOECHO)$(CC) $(FLAGS) $(ASMFLAGS) -c $< -MMD -o $@
+	$(NOECHO)$(CC) $(FLAGS) $(ASMFLAGS) -c $< -MMD -MP -o $@
 	@$(call ECHO_DONE_SILENT,$(LOG_NAME),building,$@)
 
 # Cleanup inputs
diff --git a/make/host_lib.mk b/make/host_lib.mk
index b367e42..1a65756 100644
--- a/make/host_lib.mk
+++ b/make/host_lib.mk
@@ -72,6 +72,7 @@ $(HOST_LIB_ARCHIVE): HOST_LIB_NAME := $(HOST_LIB_NAME)
 $(HOST_LIB_ARCHIVE): $(GENERIC_OBJS)
 	@$(call ECHO,$(HOST_LIB_NAME),aring,$@)
 	@$(MKDIR)
+	$(NOECHO)rm -f $@
 	$(NOECHO)$(AR) crs $@ $^
 	@$(call ECHO_DONE_SILENT,$(HOST_LIB_NAME),aring,$@)
 
diff --git a/platform/desktop/arm64/rust/rules.mk b/platform/desktop/arm64/rust/rules.mk
new file mode 100644
index 0000000..40e7043
--- /dev/null
+++ b/platform/desktop/arm64/rust/rules.mk
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
+MODULE_CRATE_NAME := platform_desktop_arm64
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
diff --git a/platform/desktop/arm64/rust/src/lib.rs b/platform/desktop/arm64/rust/src/lib.rs
new file mode 100644
index 0000000..4fbd6d9
--- /dev/null
+++ b/platform/desktop/arm64/rust/src/lib.rs
@@ -0,0 +1,107 @@
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
+use core::ffi::{c_uint, CStr};
+use core::slice::from_raw_parts;
+use dtb_service::sys::{dtb_get, NO_ERROR};
+use libfdt::FdtNode;
+use rust_support::{
+    init::lk_init_level,
+    ipc::IPC_PORT_ALLOW_TA_CONNECT,
+    ktipc::{ktipc_port_acl, uuid},
+    LK_INIT_HOOK,
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
+const KTIPC_PORT_ACL: ktipc_port_acl = ktipc_port_acl {
+    flags: IPC_PORT_ALLOW_TA_CONNECT,
+    uuid_num: UUIDS.len() as u32,
+    uuids: (&UUIDS).as_ptr(),
+    extra_data: core::ptr::null(),
+};
+
+fn share_reserved_memory(reserved_mem: &FdtNode, name: &'static CStr) {
+    let node = reserved_mem
+        .next_compatible(name)
+        .expect("Could not get boot param node")
+        .expect("Could not get boot param node");
+    let mut reg_itr =
+        node.reg().expect("Could not get reg address").expect("Could not get reg address");
+    let reg = reg_itr.next().expect("Could not get reg address");
+    vmm_obj_service_rust::share_sized_buffer(
+        reg.addr as *const u8,
+        reg.size.unwrap_or(0) as usize,
+        0,
+        name,
+        &KTIPC_PORT_ACL,
+    )
+    .expect("Could not share boot params");
+    if reg_itr.next().is_some() {
+        log::warn!("Found unexpected address is reg node. Ignoring.");
+    }
+}
+
+extern "C" fn platform_dtb_init_func(_level: c_uint) {
+    let mut fdt_ptr: *const u8 = core::ptr::null_mut();
+    let mut fdt_size = 0usize;
+    // SAFETY: Neither pointer is retained by dtb_get. dbt_get does not read from *fdt_ptr.
+    let rc = unsafe { dtb_get(&mut fdt_ptr as *mut *const u8, &mut fdt_size) };
+    if rc != NO_ERROR as i32 || fdt_ptr.is_null() {
+        log::error!("Failed to get device tree (rc: {rc}, ptr: {fdt_ptr:p}, size: {fdt_size}).");
+        return;
+    }
+    // SAFETY: Outputs from dtb_get are defined to be static, read only, and span the size returned.
+    // fdt_ptr has already been checked for null.
+    let fdt = unsafe { from_raw_parts(fdt_ptr, fdt_size) };
+
+    let fdt = libfdt::Fdt::from_slice(fdt).expect("Device tree should be valid");
+    let reserved_mem = fdt
+        .node(c"/reserved-memory")
+        .expect("Could not get reserved memory node")
+        .expect("Could not get reserved memory node");
+
+    let boot_params = [
+        c"google,open-dice",
+        c"google,session-key-seed",
+        c"google,early-entropy",
+        c"google,auth-token-key-seed",
+    ];
+
+    for param in boot_params {
+        share_reserved_memory(&reserved_mem, param);
+    }
+}
+
+LK_INIT_HOOK!(platform_dtb_init, platform_dtb_init_func, lk_init_level::LK_INIT_LEVEL_THREADING);
diff --git a/platform/generic-arm64/debug.c b/platform/generic-arm64/debug.c
index 514791b..1d18293 100644
--- a/platform/generic-arm64/debug.c
+++ b/platform/generic-arm64/debug.c
@@ -27,6 +27,10 @@
 #include <lk/reg.h>
 #include <lk/types.h>
 #include <platform/debug.h>
+#if MMIO_GUARD_ENABLED
+#include <err.h>
+#include <lib/libhypervisor/libhypervisor.h>
+#endif
 
 #include "debug.h"
 
@@ -62,11 +66,28 @@ static void map_uart(paddr_t reg_paddr, enum uart_type new_uart_type) {
     if (ret) {
         return;
     }
+
+#if MMIO_GUARD_ENABLED
+    /*
+     * MMIO Guard map UART registers. Ignore not supported which implies that
+     * guard is not used.
+     *
+     * TODO: Figure out why we sometimes get ERR_INVALID_ARGS when MMIO Guard is
+     * not supported. It happens on qemu-generic-arm64-gicv3-test-debug builds.
+     */
+    ret = hypervisor_mmio_map_region(reg_pbase, PAGE_SIZE);
+    if (ret != NO_ERROR && ret != ERR_NOT_SUPPORTED &&
+        ret != ERR_INVALID_ARGS) {
+        dprintf(CRITICAL, "failed to mmio guard map uart. error=%d\n", ret);
+        return;
+    }
+#endif
+
     uart_type = new_uart_type;
     uart_base = (uint8_t*)page_vaddr + (reg_paddr - reg_pbase);
 }
 
-void generic_arm64_setup_uart(void* fdt) {
+void generic_arm64_setup_uart(const void* fdt) {
     enum uart_type uart_type;
     int fdt_chosen_offset = fdt_path_offset(fdt, "/chosen");
     int fdt_stdout_path_len;
diff --git a/platform/generic-arm64/debug.h b/platform/generic-arm64/debug.h
index b197949..ca8990d 100644
--- a/platform/generic-arm64/debug.h
+++ b/platform/generic-arm64/debug.h
@@ -24,7 +24,7 @@
 #pragma once
 
 #if GENERIC_ARM64_DEBUG_UART
-void generic_arm64_setup_uart(void* fdt);
+void generic_arm64_setup_uart(const void* fdt);
 #else
-static inline void generic_arm64_setup_uart(void* fdt) {}
+static inline void generic_arm64_setup_uart(const void* fdt) {}
 #endif
diff --git a/platform/generic-arm64/platform.c b/platform/generic-arm64/platform.c
index bff837a..6b77366 100644
--- a/platform/generic-arm64/platform.c
+++ b/platform/generic-arm64/platform.c
@@ -27,11 +27,17 @@
 #include <inttypes.h>
 #include <kernel/vm.h>
 #include <lib/device_tree/libfdt_helpers.h>
+#include <lib/dtb_service/dtb_service.h>
 #include <lk/init.h>
 #include <platform/gic.h>
 #include <string.h>
 #include <sys/types.h>
+#if ARM64_BOOT_PROTOCOL_X0_DTB
 #include <vsock/vsock.h>
+#if MMIO_GUARD_ENABLED
+#include <lib/libhypervisor/libhypervisor.h>
+#endif
+#endif
 
 #include "debug.h"
 
@@ -156,6 +162,7 @@ static paddr_t generic_arm64_get_reg_base(int reg) {
 
 #endif
 
+#if ARM64_BOOT_PROTOCOL_X0_DTB
 int static pci_init_fdt(const void* fdt) {
     int fdt_pci_offset =
             fdt_node_offset_by_compatible(fdt, 0, "pci-host-cam-generic");
@@ -174,6 +181,7 @@ int static pci_init_fdt(const void* fdt) {
 
     return pci_init_mmio(pci_paddr, pci_size, 1 << 11);
 }
+#endif /* ARM64_BOOT_PROTOCOL_X0_DTB */
 
 static void platform_after_vm_init(uint level) {
 #ifdef GIC_VERSION
@@ -183,32 +191,39 @@ static void platform_after_vm_init(uint level) {
     paddr_t gicr = generic_arm64_get_reg_base(SMC_GET_GIC_BASE_GICR);
 #elif ARM64_BOOT_PROTOCOL_X0_DTB
     int ret;
-    void* fdt;
+    void* fdt_temp;
     size_t fdt_size;
     paddr_t fdt_paddr = lk_boot_args[0];
-    ret = vmm_alloc_physical(
-            vmm_get_kernel_aspace(), "device_tree_probe", PAGE_SIZE, &fdt, 0,
-            fdt_paddr, 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_CACHED);
+    ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "device_tree_probe",
+                             PAGE_SIZE, &fdt_temp, 0, fdt_paddr, 0,
+                             ARCH_MMU_FLAG_PERM_NO_EXECUTE |
+                                     ARCH_MMU_FLAG_CACHED |
+                                     ARCH_MMU_FLAG_PERM_RO);
     if (ret) {
         dprintf(CRITICAL,
                 "failed to map device tree page at 0x%" PRIxPADDR ": %d\n",
                 fdt_paddr, ret);
         return;
     }
+    const void* fdt = fdt_temp;
+
     if (fdt_check_header(fdt)) {
         dprintf(CRITICAL, "invalid device tree at 0x%" PRIxPADDR ": %d\n",
                 fdt_paddr, ret);
         return;
     }
+
     fdt_size = fdt_totalsize(fdt);
     if (fdt_size > PAGE_SIZE) {
         fdt_size = page_align(fdt_size);
         dprintf(INFO, "remapping device tree with size 0x%zx\n", fdt_size);
         vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)fdt);
-        ret = vmm_alloc_physical(
-                vmm_get_kernel_aspace(), "device_tree_full", fdt_size, &fdt, 0,
-                fdt_paddr, 0,
-                ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_CACHED);
+        ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "device_tree_full",
+                                 fdt_size, &fdt_temp, 0, fdt_paddr, 0,
+                                 ARCH_MMU_FLAG_PERM_NO_EXECUTE |
+                                         ARCH_MMU_FLAG_CACHED |
+                                         ARCH_MMU_FLAG_PERM_RO);
+        fdt = fdt_temp;
         if (ret) {
             dprintf(CRITICAL,
                     "failed to map device tree at 0x%" PRIxPADDR
@@ -242,6 +257,25 @@ static void platform_after_vm_init(uint level) {
                 GICR_SIZE);
         return;
     }
+
+#if MMIO_GUARD_ENABLED
+    /*
+     * MMIO Guard map GIC addresses. Ignore not supported which implies that
+     * guard is not used.
+     */
+    ret = hypervisor_mmio_map_region(gicc, GICC_SIZE);
+    if (ret != NO_ERROR && ret != ERR_NOT_SUPPORTED) {
+        dprintf(CRITICAL, "failed to mmio guard map gicc. error=%d\n", ret);
+    }
+    ret = hypervisor_mmio_map_region(gicd, GICD_SIZE);
+    if (ret != NO_ERROR && ret != ERR_NOT_SUPPORTED) {
+        dprintf(CRITICAL, "failed to mmio guard map gicd. error=%d\n", ret);
+    }
+    ret = hypervisor_mmio_map_region(gicr, GICR_SIZE);
+    if (ret != NO_ERROR && ret != ERR_NOT_SUPPORTED) {
+        dprintf(CRITICAL, "failed to mmio guard map gicr. error=%d\n", ret);
+    }
+#endif
 #else
 #error "Unknown ARM64_BOOT_PROTOCOL"
 #endif
@@ -266,6 +300,9 @@ static void platform_after_vm_init(uint level) {
     arm_generic_timer_init(ARM_GENERIC_TIMER_INT, 0);
 
 #if ARM64_BOOT_PROTOCOL_X0_DTB
+    if (dtb_set(fdt, fdt_size) != NO_ERROR) {
+        dprintf(CRITICAL, "failed to set device tree\n");
+    }
     pci_init_fdt(fdt); /* ignore pci init errors */
 #endif
 }
diff --git a/platform/generic-arm64/rules.mk b/platform/generic-arm64/rules.mk
index 6c25bd8..a5e05c7 100644
--- a/platform/generic-arm64/rules.mk
+++ b/platform/generic-arm64/rules.mk
@@ -48,6 +48,9 @@ GLOBAL_INCLUDES += \
 ifeq (true,$(call TOBOOL,$(HAFNIUM)))
 MODULE_DEFINES += HAFNIUM=1
 MODULE_DEPS += dev/interrupt/hafnium
+MODULE_INCLUDES += \
+	external/hafnium/inc/vmapi \
+	external/hafnium/src/arch/aarch64/inc
 else
 MODULE_DEFINES += GIC_VERSION=$(GIC_VERSION)
 MODULE_DEPS += dev/interrupt/arm_gic
@@ -68,6 +71,9 @@ MODULE_INCLUDES += \
 
 MODULE_DEPS += \
 	dev/timer/arm_generic \
+
+# vsock-rust only supports aarch64 (and x86_64)
+MODULE_DEPS += \
 	dev/virtio/vsock-rust \
 
 GLOBAL_DEFINES += \
@@ -97,4 +103,13 @@ ifeq ($(GENERIC_ARM64_DEBUG),FFA)
 MODULE_DEPS += trusty/kernel/lib/arm_ffa
 endif
 
+# MMIO Guard support
+MMIO_GUARD_ENABLED ?= false
+ifeq (true,$(call TOBOOL,$(MMIO_GUARD_ENABLED)))
+MODULE_DEPS += \
+	$(LKROOT)/lib/libhypervisor
+
+MODULE_DEFINES += MMIO_GUARD_ENABLED=1
+endif
+
 include make/module.mk
```

