```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 00000000..7f3334d3
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_external_trusty_lk",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/arch/arm/arm/faults.c b/arch/arm/arm/faults.c
index a80d7af1..e3c16fe5 100644
--- a/arch/arm/arm/faults.c
+++ b/arch/arm/arm/faults.c
@@ -149,7 +149,7 @@ static void halt_thread(uint32_t spsr, uint32_t crash_reason)
     if ((spsr & CPSR_MODE_MASK) == CPSR_MODE_USR) {
         arch_enable_fiqs();
         arch_enable_ints();
-        trusty_app_crash(crash_reason);
+        trusty_app_crash(crash_reason, 0, 0);
     }
 
     panic("fault\n");
diff --git a/arch/arm/arm/fpu.c b/arch/arm/arm/fpu.c
index bf6ca27a..9803d276 100644
--- a/arch/arm/arm/fpu.c
+++ b/arch/arm/arm/fpu.c
@@ -61,6 +61,12 @@ void arm_fpu_undefined_instruction(struct arm_iframe *frame)
     thread_t *t = get_current_thread();
 
     if (unlikely(arch_in_int_handler())) {
+#if WITH_SMP
+        /*
+         * arch_in_int_handler is currently not SMP safe and can give both
+         * false positive and false negative results. Retry to work around
+         * the most likely false positive result.
+         */
         int i;
         dprintf(CRITICAL, "floating point code while some cpu is in irq context. pc 0x%x\n", frame->pc);
         for (i = 0; i < 1000; i++) {
@@ -68,7 +74,10 @@ void arm_fpu_undefined_instruction(struct arm_iframe *frame)
                 dprintf(CRITICAL, "arch_in_int_handler status cleared after %d reads\n", i);
                 goto false_alarm;
             }
+            /* spin 10us to allow time for the interrupt handler to finish */
+            spin(10);
         }
+#endif
         panic("floating point code in irq context. pc 0x%x\n", frame->pc);
     }
 false_alarm:
diff --git a/arch/arm/armv7-unknown-trusty-kernel.json b/arch/arm/armv7-unknown-trusty-kernel.json
index eac4e472..44d19099 100644
--- a/arch/arm/armv7-unknown-trusty-kernel.json
+++ b/arch/arm/armv7-unknown-trusty-kernel.json
@@ -16,7 +16,7 @@
     "plt-by-default": false,
     "relro-level": "full",
     "static-position-independent-executables": true,
-    "supported-sanitizers": [],
+    "supported-sanitizers": ["cfi"],
     "target-mcount": "\u0001mcount",
     "target-pointer-width": "32"
 }
diff --git a/arch/arm/include/arch/arch_ops.h b/arch/arm/include/arch/arch_ops.h
index bb8881d0..7fef096c 100644
--- a/arch/arm/include/arch/arch_ops.h
+++ b/arch/arm/include/arch/arch_ops.h
@@ -121,7 +121,8 @@ static inline bool arch_in_int_handler(void)
     return (ipsr & IPSR_ISR_Msk);
 #else
     /* set by the interrupt glue to track that the cpu is inside a handler */
-    extern bool __arm_in_handler;
+    /* Note that this in not SMP safe */
+    extern volatile bool __arm_in_handler;
 
     return __arm_in_handler;
 #endif
diff --git a/arch/arm/toolchain.mk b/arch/arm/toolchain.mk
index 398ba9b8..2a7bf761 100644
--- a/arch/arm/toolchain.mk
+++ b/arch/arm/toolchain.mk
@@ -53,4 +53,5 @@ ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))
 ARCH_arm_RUSTFLAGS := --target=armv7-unknown-trusty
 else
 ARCH_arm_RUSTFLAGS := --target=$(LOCAL_DIR)/armv7-unknown-trusty-kernel.json
+ARCH_arm_SUPPORTS_RUST_CFI := true
 endif
diff --git a/arch/arm64/aarch64-unknown-trusty-kernel.json b/arch/arm64/aarch64-unknown-trusty-kernel.json
index e0f01b94..3d56fde5 100644
--- a/arch/arm64/aarch64-unknown-trusty-kernel.json
+++ b/arch/arm64/aarch64-unknown-trusty-kernel.json
@@ -15,7 +15,7 @@
     "plt-by-default": false,
     "relro-level": "full",
     "static-position-independent-executables": true,
-    "supported-sanitizers": [],
+    "supported-sanitizers": ["cfi"],
     "target-mcount": "\u0001_mcount",
     "target-pointer-width": "64"
 }
diff --git a/arch/arm64/exceptions_c.c b/arch/arm64/exceptions_c.c
index 4bd584b3..da4e9da7 100644
--- a/arch/arm64/exceptions_c.c
+++ b/arch/arm64/exceptions_c.c
@@ -566,7 +566,8 @@ void arm64_sync_exception(struct arm64_iframe_long *iframe, bool from_lower)
     if (from_lower) {
         arch_enable_fiqs();
         arch_enable_ints();
-        trusty_app_crash(esr);
+        /* TODO(snehalreddy): Remove ASLR */
+        trusty_app_crash(esr, far, display_pc);
     }
     panic("die\n");
 }
diff --git a/arch/arm64/fpu.c b/arch/arm64/fpu.c
index 9366c506..5af03cad 100644
--- a/arch/arm64/fpu.c
+++ b/arch/arm64/fpu.c
@@ -34,12 +34,22 @@ static void arm64_fpu_load_state(struct thread *t)
     uint cpu = arch_curr_cpu_num();
     struct fpstate *fpstate = &t->arch.fpstate;
 
-    if (fpstate == current_fpstate[cpu] && fpstate->current_cpu == cpu) {
+    if (!arm64_fpu_load_fpstate(fpstate, false)) {
         LTRACEF("cpu %d, thread %s, fpstate already valid\n", cpu, t->name);
         return;
     }
     LTRACEF("cpu %d, thread %s, load fpstate %p, last cpu %d, last fpstate %p\n",
             cpu, t->name, fpstate, fpstate->current_cpu, current_fpstate[cpu]);
+}
+
+bool arm64_fpu_load_fpstate(struct fpstate *fpstate, bool force)
+{
+    uint cpu = arch_curr_cpu_num();
+
+    if (!force && fpstate == current_fpstate[cpu] &&
+        fpstate->current_cpu == cpu) {
+        return false;
+    }
     fpstate->current_cpu = cpu;
     current_fpstate[cpu] = fpstate;
 
@@ -66,12 +76,22 @@ static void arm64_fpu_load_state(struct thread *t)
                      :: "r"(fpstate),
                      "r"((uint64_t)fpstate->fpcr),
                      "r"((uint64_t)fpstate->fpsr));
+
+    return true;
 }
 
 void arm64_fpu_save_state(struct thread *t)
 {
-    uint64_t fpcr, fpsr;
     struct fpstate *fpstate = &t->arch.fpstate;
+    arm64_fpu_save_fpstate(fpstate);
+
+    LTRACEF("thread %s, fpcr %x, fpsr %x\n", t->name, fpstate->fpcr, fpstate->fpsr);
+}
+
+void arm64_fpu_save_fpstate(struct fpstate *fpstate)
+{
+    uint64_t fpcr, fpsr;
+
     __asm__ volatile("stp     q0, q1, [%2, #(0 * 32)]\n"
                      "stp     q2, q3, [%2, #(1 * 32)]\n"
                      "stp     q4, q5, [%2, #(2 * 32)]\n"
@@ -95,8 +115,6 @@ void arm64_fpu_save_state(struct thread *t)
 
     fpstate->fpcr = fpcr;
     fpstate->fpsr = fpsr;
-
-    LTRACEF("thread %s, fpcr %x, fpsr %x\n", t->name, fpstate->fpcr, fpstate->fpsr);
 }
 
 void arm64_fpu_exception(struct arm64_iframe_long *iframe)
diff --git a/arch/arm64/include/arch/arm64.h b/arch/arm64/include/arch/arm64.h
index fbf245bc..7fe7e912 100644
--- a/arch/arm64/include/arch/arm64.h
+++ b/arch/arm64/include/arch/arm64.h
@@ -74,6 +74,7 @@ struct arm64_iframe_short {
 };
 
 struct thread;
+struct fpstate;
 
 /*
  * This declaration is made to avoid issues with CFI while setting
@@ -87,6 +88,29 @@ void arm64_el3_to_el1(void);
 void arm64_fpu_exception(struct arm64_iframe_long *iframe);
 void arm64_fpu_save_state(struct thread *thread);
 
+/**
+ * arm64_fpu_load_fpstate() - Load the FP state from memory.
+ * @fpstate: Pointer to a &struct fpstate containing the new
+ *           values of the FP registers.
+ * @force: Force the load operation even if the @fpstate pointer
+ *         is the same as the previous operation.
+ *
+ * Return:
+ * * %true if the load is performed successfully
+ * * %false if the register values are already present in the registers
+ *
+ * This function will copy the pointer from @fpstate into some internal
+ * storage. For this reason, the pointer should not point
+ * into the stack.
+ */
+bool arm64_fpu_load_fpstate(struct fpstate *fpstate, bool force);
+
+/**
+ * arm64_fpu_save_fpstate() - Save the current values of the FP registers.
+ * @fpstate: Pointer to a &struct fpstate to store the registers into.
+ */
+void arm64_fpu_save_fpstate(struct fpstate *fpstate);
+
 static inline void arm64_fpu_pre_context_switch(struct thread *thread)
 {
     uint64_t cpacr = ARM64_READ_SYSREG(cpacr_el1);
diff --git a/arch/arm64/system-onesegment.ld b/arch/arm64/system-onesegment.ld
index 716e5e96..91505eff 100644
--- a/arch/arm64/system-onesegment.ld
+++ b/arch/arm64/system-onesegment.ld
@@ -20,6 +20,12 @@ SECTIONS
             .text.init_have_lse_atomics
             .init_array*
         )
+
+        *libclang_rt.builtins-aarch64-android.a:aarch64.c.o(
+            .text.__init_cpu_features
+            .text.init_have_lse_atomics
+            .init_array*
+        )
     }
 
     /* text/read-only data */
diff --git a/arch/arm64/toolchain.mk b/arch/arm64/toolchain.mk
index bf251be3..86821534 100644
--- a/arch/arm64/toolchain.mk
+++ b/arch/arm64/toolchain.mk
@@ -34,4 +34,5 @@ ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))
 ARCH_arm64_RUSTFLAGS := --target=aarch64-unknown-trusty
 else
 ARCH_arm64_RUSTFLAGS := --target=$(LOCAL_DIR)/aarch64-unknown-trusty-kernel.json
+ARCH_arm64_SUPPORTS_RUST_CFI := true
 endif
diff --git a/arch/x86/64/kernel.ld b/arch/x86/64/kernel.ld
index b9da39e2..302c0ff9 100644
--- a/arch/x86/64/kernel.ld
+++ b/arch/x86/64/kernel.ld
@@ -59,6 +59,13 @@ SECTIONS
         __dtor_end = .;
     }
 
+    /*
+     * .got and .dynamic need to follow .ctors and .dtors because the linker
+     * puts them all in the RELRO segment and wants them contiguous
+     */
+    .dynamic : { *(.dynamic) }
+    .got : { *(.got.plt) *(.got) }
+
     /*
      * extra linker scripts tend to insert sections just after .rodata,
      * so we want to make sure this symbol comes after anything inserted above,
diff --git a/arch/x86/64/start.S b/arch/x86/64/start.S
index ea181ca5..55725bbd 100644
--- a/arch/x86/64/start.S
+++ b/arch/x86/64/start.S
@@ -26,19 +26,6 @@
 #include <arch/x86/descriptor.h>
 #include <arch/x86/mmu.h>
 
-/* The magic number for the Multiboot header. */
-#define MULTIBOOT_HEADER_MAGIC 0x1BADB002
-
-/* The flags for the Multiboot header. */
-#if defined(__ELF__) && 0
-#define MULTIBOOT_HEADER_FLAGS 0x00000002
-#else
-#define MULTIBOOT_HEADER_FLAGS 0x00010002
-#endif
-
-/* The magic number passed by a Multiboot-compliant boot loader. */
-#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002
-
 #define MSR_EFER    0xc0000080
 #define EFER_NXE    0x00000800
 #define EFER_SCE    0x00000001
@@ -346,84 +333,6 @@
 
 .global _start
 _start:
-    jmp real_start
-
-.align 8
-
-.type multiboot_header,STT_OBJECT
-multiboot_header:
-    /* magic */
-    .int MULTIBOOT_HEADER_MAGIC
-    /* flags */
-    .int MULTIBOOT_HEADER_FLAGS
-    /* checksum */
-    .int -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
-
-#if !defined(__ELF__) || 1
-    /* header_addr */
-    .int PHYS(multiboot_header)
-    /* load_addr */
-    .int PHYS(_start)
-    /* load_end_addr */
-    .int PHYS(__data_end)
-    /* bss_end_addr */
-    .int PHYS(__bss_end)
-    /* entry_addr */
-    .int PHYS(real_start)
-#endif
-
-real_start:
-    cmpq $MULTIBOOT_BOOTLOADER_MAGIC, %rax
-
-    jne .Lno_multiboot_info
-    movq %rbx, PHYS(_multiboot_info)
-
-    /* RSI stores multiboot info address */
-    leaq (%rbx), %rsi
-
-    /*
-     * first member in multiboot info structure is flag. If bit 0 in the flag
-     * word is set, then mem_lower and mem_high indicate the amount of lower
-     * and upper memory in kilobytes. Currently, we support this mode only.
-     */
-    movq 0(%rsi), %rcx
-    andq $0x1, %rcx
-    jz  .Lno_multiboot_info
-
-    /* ECX stores high memory (KB) provided by multiboot info */
-    movl 0x8(%rsi), %ecx
-
-    /* halt machine if memory size to small */
-    movq $__bss_end, %rdx
-    movq $__code_start, %rax
-    subq %rax, %rdx
-    addq $MEMBASE, %rdx
-    shrq $10, %rdx
-    cmpq %rdx, %rcx
-    jc .Lhalt
-
-    movq %rcx, %rdx
-    /* RDX indicates high memory in bytes */
-    shlq $10, %rdx
-    movq $MEMBASE, %rax
-
-    /* RDX indicates memory size in bytes */
-    subq %rax, %rdx
-
-    /* halt machine if memory size to large */
-    cmpq $MAX_MEM_SIZE, %rdx
-    jnc .Lhalt
-
-    leaq PHYS(mmu_initial_mappings), %rsi
-    /*
-     * RDI points to size of first entry in mmu_initial_mappings.
-     * Contents of this entry will be used to init pmm arena,
-     * mmu_initial_mappings is defined in platform.c.
-     */
-    leaq 0x10(%rsi), %rdi
-    movq %rdx, (%rdi)
-
-.Lno_multiboot_info:
 
     /* zero the bss section */
 bss_setup:
diff --git a/arch/x86/faults.c b/arch/x86/faults.c
index 8b783970..90259daf 100644
--- a/arch/x86/faults.c
+++ b/arch/x86/faults.c
@@ -191,7 +191,7 @@ void x86_pfe_handler(x86_iframe_t *frame)
             case 7:
             default:
                 arch_enable_ints();
-                trusty_app_crash(error_code);
+                trusty_app_crash(error_code, 0, 0);
                 break;
         }
     } else {
diff --git a/arch/x86/toolchain.mk b/arch/x86/toolchain.mk
index d6628991..97b53356 100644
--- a/arch/x86/toolchain.mk
+++ b/arch/x86/toolchain.mk
@@ -33,6 +33,7 @@ ARCH_x86_RUSTFLAGS := --target=x86_64-unknown-trusty
 else
 # Use custom toolchain file that disables hardware floating point
 ARCH_x86_RUSTFLAGS := --target=$(LOCAL_DIR)/x86_64-unknown-trusty-kernel.json
+ARCH_x86_SUPPORTS_RUST_CFI := true
 endif
 
 endif
diff --git a/arch/x86/x86_64-unknown-trusty-kernel.json b/arch/x86/x86_64-unknown-trusty-kernel.json
index 51c8fa25..49ab2f72 100644
--- a/arch/x86/x86_64-unknown-trusty-kernel.json
+++ b/arch/x86/x86_64-unknown-trusty-kernel.json
@@ -1,5 +1,6 @@
 {
     "arch": "x86_64",
+    "code-model": "kernel",
     "cpu": "x86-64",
     "crt-objects-fallback": "musl",
     "crt-static-default": false,
@@ -23,7 +24,7 @@
         ]
     },
     "static-position-independent-executables": true,
-    "supported-sanitizers": ["kcfi"],
+    "supported-sanitizers": ["cfi"],
     "target-pointer-width": "64",
     "features": "-3dnow,-3dnowa,-mmx,-sse,-sse2,+soft-float"
 }
diff --git a/dev/interrupt/arm_gic/arm_gic.c b/dev/interrupt/arm_gic/arm_gic.c
index 7101a65c..d9199a0d 100644
--- a/dev/interrupt/arm_gic/arm_gic.c
+++ b/dev/interrupt/arm_gic/arm_gic.c
@@ -36,6 +36,7 @@
 #include <platform/interrupts.h>
 #include <arch/ops.h>
 #include <platform/gic.h>
+#include <string.h>
 #include <trace.h>
 #include <inttypes.h>
 #if WITH_LIB_SM
@@ -75,6 +76,9 @@ static spin_lock_t gicd_lock;
 #define GIC_MAX_SGI_INT 16
 
 #if ARM_GIC_USE_DOORBELL_NS_IRQ
+#ifndef GIC_MAX_DEFERRED_ACTIVE_IRQS
+#define GIC_MAX_DEFERRED_ACTIVE_IRQS 32
+#endif
 static bool doorbell_enabled;
 #endif
 
@@ -113,6 +117,8 @@ struct int_handler_struct {
     void *arg;
 };
 
+#ifndef WITH_GIC_COMPACT_TABLE
+/* Handler and argument storage, per interrupt. */
 static struct int_handler_struct int_handler_table_per_cpu[GIC_MAX_PER_CPU_INT][SMP_MAX_CPUS];
 static struct int_handler_struct int_handler_table_shared[MAX_INT-GIC_MAX_PER_CPU_INT];
 
@@ -120,12 +126,202 @@ static struct int_handler_struct *get_int_handler(unsigned int vector, uint cpu)
 {
     if (vector < GIC_MAX_PER_CPU_INT)
         return &int_handler_table_per_cpu[vector][cpu];
-    else
+    else if(vector < MAX_INT)
         return &int_handler_table_shared[vector - GIC_MAX_PER_CPU_INT];
+    else
+        return NULL;
+}
+
+static struct int_handler_struct *alloc_int_handler(unsigned int vector, uint cpu) {
+    return get_int_handler(vector, cpu);
+}
+
+#else /* WITH_GIC_COMPACT_TABLE */
+
+#ifdef WITH_SMP
+#error WITH_GIC_COMPACT_TABLE does not support SMP
+#endif
+
+/* Maximum count of vector entries that can be registered / handled. */
+#ifndef GIC_COMPACT_MAX_HANDLERS
+#define GIC_COMPACT_MAX_HANDLERS 16
+#endif
+
+/* Array giving a mapping from a vector number to a handler entry index.
+ * This structure is kept small so it can be searched reasonably
+ * efficiently.  The position in int_handler_vecnum[] gives the index into
+ * int_handler_table[].
+ */
+__attribute__((aligned(CACHE_LINE)))
+static uint16_t int_handler_vecnum[GIC_COMPACT_MAX_HANDLERS];
+static uint16_t int_handler_count = 0;
+
+/* Handler entries themselves. */
+static struct int_handler_struct int_handler_table[GIC_COMPACT_MAX_HANDLERS];
+
+static struct int_handler_struct *bsearch_handler(const uint16_t num, const uint16_t *base, uint_fast16_t count) {
+    const uint16_t *bottom = base;
+
+    while (count > 0) {
+        const uint16_t *mid = &bottom[count / 2];
+
+        if (num < *mid) {
+            count /= 2;
+        } else if (num > *mid) {
+            bottom = mid + 1;
+            count -= count / 2 + 1;
+        } else {
+            return &int_handler_table[mid - base];
+        }
+    }
+
+    return NULL;
+}
+
+static struct int_handler_struct *get_int_handler(unsigned int vector, uint cpu)
+{
+    return bsearch_handler(vector, int_handler_vecnum, int_handler_count);
+}
+
+static struct int_handler_struct *alloc_int_handler(unsigned int vector, uint cpu)
+{
+    struct int_handler_struct *handler = get_int_handler(vector, cpu);
+
+    /* Return existing allocation if there is one */
+    if (handler) {
+        return handler;
+    }
+
+    /* Check an allocation is possible */
+    assert(int_handler_count < GIC_COMPACT_MAX_HANDLERS);
+    assert(spin_lock_held(&gicd_lock));
+
+    /* Find insertion point */
+    int i = 0;
+    while (i < int_handler_count && vector > int_handler_vecnum[i]) {
+        i++;
+    }
+
+    /* Move any remainder down */
+    const int remainder = int_handler_count - i;
+    memmove(&int_handler_vecnum[i + 1], &int_handler_vecnum[i],
+            sizeof(int_handler_vecnum[0]) * remainder);
+    memmove(&int_handler_table[i + 1], &int_handler_table[i],
+            sizeof(int_handler_table[0]) * remainder);
+
+    int_handler_count++;
+
+    /* Initialise the new entry */
+    int_handler_vecnum[i] = vector;
+    int_handler_table[i].handler = NULL;
+    int_handler_table[i].arg = NULL;
+
+    /* Return the allocated handler */
+    return &int_handler_table[i];
+}
+#endif /* WITH_GIC_COMPACT_TABLE */
+
+static bool has_int_handler(unsigned int vector, uint cpu) {
+    const struct int_handler_struct *h = get_int_handler(vector, cpu);
+
+    return likely(h && h->handler);
 }
 
 #if ARM_GIC_USE_DOORBELL_NS_IRQ
 static status_t arm_gic_set_priority_locked(u_int irq, uint8_t priority);
+static u_int deferred_active_irqs[SMP_MAX_CPUS][GIC_MAX_DEFERRED_ACTIVE_IRQS];
+
+static status_t reserve_deferred_active_irq_slot(void)
+{
+    static unsigned int num_handlers = 0;
+
+    if (num_handlers == GIC_MAX_DEFERRED_ACTIVE_IRQS)
+        return ERR_NO_MEMORY;
+
+    num_handlers++;
+    return NO_ERROR;
+}
+
+static status_t defer_active_irq(unsigned int vector, uint cpu)
+{
+    uint idx;
+
+    for (idx = 0; idx < GIC_MAX_DEFERRED_ACTIVE_IRQS; idx++) {
+        u_int irq = deferred_active_irqs[cpu][idx];
+
+        if (!irq)
+            break;
+
+        if (irq == vector) {
+            TRACEF("irq %d already deferred on cpu %u!\n", irq, cpu);
+            return ERR_ALREADY_EXISTS;
+        }
+    }
+
+    if (idx == GIC_MAX_DEFERRED_ACTIVE_IRQS)
+        panic("deferred active irq list is full on cpu %u\n", cpu);
+
+    deferred_active_irqs[cpu][idx] = vector;
+    GICCREG_WRITE(0, icc_eoir1_el1, vector);
+    LTRACEF_LEVEL(2, "deferred irq %u on cpu %u\n", vector, cpu);
+    return NO_ERROR;
+}
+
+static void raise_ns_doorbell_irq(uint cpu)
+{
+    uint64_t reg = arm_gicv3_sgir_val(ARM_GIC_DOORBELL_IRQ, cpu);
+
+    if (doorbell_enabled) {
+        LTRACEF("GICD_SGIR: %" PRIx64 "\n", reg);
+        GICCREG_WRITE(0, icc_asgi1r_el1, reg);
+    }
+}
+
+static status_t fiq_enter_defer_irqs(uint cpu)
+{
+    bool inject = false;
+
+    do {
+        u_int irq = GICCREG_READ(0, icc_iar1_el1) & 0x3ff;
+
+        if (irq >= 1020)
+            break;
+
+        if (defer_active_irq(irq, cpu) != NO_ERROR)
+            break;
+
+        inject = true;
+    } while (true);
+
+    if (inject)
+        raise_ns_doorbell_irq(cpu);
+
+    return ERR_NO_MSG;
+}
+
+static enum handler_return handle_deferred_irqs(void)
+{
+    enum handler_return ret = INT_NO_RESCHEDULE;
+    uint cpu = arch_curr_cpu_num();
+
+    for (uint idx = 0; idx < GIC_MAX_DEFERRED_ACTIVE_IRQS; idx++) {
+        struct int_handler_struct *h;
+        u_int irq = deferred_active_irqs[cpu][idx];
+
+        if (!irq)
+            break;
+
+        h = get_int_handler(irq, cpu);
+        if (h->handler && h->handler(h->arg) == INT_RESCHEDULE)
+            ret = INT_RESCHEDULE;
+
+        deferred_active_irqs[cpu][idx] = 0;
+        GICCREG_WRITE(0, icc_dir_el1, irq);
+        LTRACEF_LEVEL(2, "handled deferred irq %u on cpu %u\n", irq, cpu);
+    }
+
+    return ret;
+}
 #endif
 
 void register_int_handler(unsigned int vector, int_handler handler, void *arg)
@@ -141,18 +337,20 @@ void register_int_handler(unsigned int vector, int_handler handler, void *arg)
     spin_lock_save(&gicd_lock, &state, GICD_LOCK_FLAGS);
 
     if (arm_gic_interrupt_change_allowed(vector)) {
+#if ARM_GIC_USE_DOORBELL_NS_IRQ
+        if (reserve_deferred_active_irq_slot() != NO_ERROR) {
+            panic("register_int_handler: exceeded %d deferred active irq slots\n",
+                  GIC_MAX_DEFERRED_ACTIVE_IRQS);
+        }
+#endif
 #if GIC_VERSION > 2
         arm_gicv3_configure_irq_locked(cpu, vector);
 #endif
-        h = get_int_handler(vector, cpu);
+        h = alloc_int_handler(vector, cpu);
         h->handler = handler;
         h->arg = arg;
 #if ARM_GIC_USE_DOORBELL_NS_IRQ
-        /*
-         * Use lowest priority Linux does not mask to allow masking the entire
-         * group while still allowing other interrupts to be delivered.
-         */
-        arm_gic_set_priority_locked(vector, 0xf7);
+        arm_gic_set_priority_locked(vector, 0x7f);
 #endif
 
         /*
@@ -266,8 +464,7 @@ static void arm_gic_resume_cpu(uint level)
         uint max_irq = resume_gicd ? MAX_INT : GIC_MAX_PER_CPU_INT;
 
         for (uint v = 0; v < max_irq; v++) {
-            struct int_handler_struct *h = get_int_handler(v, cpu);
-            if (h->handler) {
+            if (has_int_handler(v, cpu)) {
                 arm_gicv3_configure_irq_locked(cpu, v);
             }
         }
@@ -557,10 +754,13 @@ enum handler_return __platform_irq(struct iframe *frame)
 
     ret = INT_NO_RESCHEDULE;
     struct int_handler_struct *handler = get_int_handler(vector, cpu);
-    if (handler->handler)
+    if (handler && handler->handler)
         ret = handler->handler(handler->arg);
 
     GICCREG_WRITE(0, GICC_PRIMARY_EOIR, iar);
+#if ARM_GIC_USE_DOORBELL_NS_IRQ
+    GICCREG_WRITE(0, icc_dir_el1, iar);
+#endif
 
     LTRACEF_LEVEL(2, "cpu %u exit %d\n", cpu, ret);
 
@@ -589,7 +789,7 @@ enum handler_return platform_irq(struct iframe *frame)
 #endif
 
     LTRACEF("ahppir %d\n", ahppir);
-    if (pending_irq < MAX_INT && get_int_handler(pending_irq, cpu)->handler) {
+    if (pending_irq < MAX_INT && has_int_handler(pending_irq, cpu)) {
         enum handler_return ret = 0;
         uint32_t irq;
         uint8_t old_priority;
@@ -610,7 +810,8 @@ enum handler_return platform_irq(struct iframe *frame)
         spin_unlock_restore(&gicd_lock, state, GICD_LOCK_FLAGS);
 
         LTRACEF("irq %d\n", irq);
-        if (irq < MAX_INT && (h = get_int_handler(pending_irq, cpu))->handler)
+        h = get_int_handler(pending_irq, cpu);
+        if (likely(h && h->handler))
             ret = h->handler(h->arg);
         else
             TRACEF("unexpected irq %d != %d may get lost\n", irq, pending_irq);
@@ -650,7 +851,7 @@ static status_t arm_gic_get_next_irq_locked(u_int min_irq, uint type)
         min_irq = GIC_MAX_PER_CPU_INT;
 
     for (irq = min_irq; irq < max_irq; irq++)
-        if (get_int_handler(irq, cpu)->handler)
+        if (has_int_handler(irq, cpu))
             return irq;
 #endif
 
@@ -676,17 +877,17 @@ long smc_intc_get_next_irq(struct smc32_args *args)
     return ret;
 }
 
-void sm_intc_enable_interrupts(void)
+enum handler_return sm_intc_enable_interrupts(void)
 {
 #if ARM_GIC_USE_DOORBELL_NS_IRQ
-    GICCREG_WRITE(0, icc_igrpen1_el1, 1); /* Enable secure Group 1 */
-    DSB;
+    return handle_deferred_irqs();
+#else
+    return INT_NO_RESCHEDULE;
 #endif
 }
 
-status_t sm_intc_fiq_enter(void)
+static status_t fiq_enter_unexpected_irq(u_int cpu)
 {
-    u_int cpu = arch_curr_cpu_num();
 #if GIC_VERSION > 2
     u_int irq = GICCREG_READ(0, icc_iar0_el1) & 0x3ff;
 #else
@@ -696,19 +897,7 @@ status_t sm_intc_fiq_enter(void)
     LTRACEF("cpu %d, irq %i\n", cpu, irq);
 
     if (irq >= 1020) {
-#if ARM_GIC_USE_DOORBELL_NS_IRQ
-        uint64_t val = arm_gicv3_sgir_val(ARM_GIC_DOORBELL_IRQ, cpu);
-
-        GICCREG_WRITE(0, icc_igrpen1_el1, 0); /* Disable secure Group 1 */
-        DSB;
-
-        if (doorbell_enabled) {
-            LTRACEF("GICD_SGIR: %" PRIx64 "\n", val);
-            GICCREG_WRITE(0, icc_asgi1r_el1, val);
-        }
-#else
         LTRACEF("spurious fiq: cpu %d, new %d\n", cpu, irq);
-#endif
         return ERR_NO_MSG;
     }
 
@@ -721,4 +910,14 @@ status_t sm_intc_fiq_enter(void)
     dprintf(INFO, "got disabled fiq: cpu %d, new %d\n", cpu, irq);
     return ERR_NOT_READY;
 }
+
+status_t sm_intc_fiq_enter(void)
+{
+    u_int cpu = arch_curr_cpu_num();
+#if ARM_GIC_USE_DOORBELL_NS_IRQ
+    return fiq_enter_defer_irqs(cpu);
+#else
+    return fiq_enter_unexpected_irq(cpu);
+#endif
+}
 #endif
diff --git a/dev/interrupt/arm_gic/gic_v3.c b/dev/interrupt/arm_gic/gic_v3.c
index d207a252..6ee06946 100644
--- a/dev/interrupt/arm_gic/gic_v3.c
+++ b/dev/interrupt/arm_gic/gic_v3.c
@@ -221,6 +221,9 @@ void arm_gicv3_init_percpu(void) {
     /* Initialized by ATF */
 #if ARM_GIC_USE_DOORBELL_NS_IRQ
     gicv3_gicr_setup_irq_group(ARM_GIC_DOORBELL_IRQ, GICV3_IRQ_GROUP_GRP1NS);
+
+    /* Enable EOIMode=1 */
+    GICCREG_WRITE(0, icc_ctlr_el1, (GICCREG_READ(0, icc_ctlr_el1) | 0x2));
 #endif
 #else
     /* non-TZ */
diff --git a/dev/interrupt/x86_lapic/interrupts.c b/dev/interrupt/x86_lapic/interrupts.c
index bd9923ab..e2c0c175 100644
--- a/dev/interrupt/x86_lapic/interrupts.c
+++ b/dev/interrupt/x86_lapic/interrupts.c
@@ -232,5 +232,7 @@ status_t sm_intc_fiq_enter(void) {
     return NO_ERROR;
 }
 
-void sm_intc_enable_interrupts(void) {}
+enum handler_return sm_intc_enable_interrupts(void) {
+    return INT_NO_RESCHEDULE;
+}
 #endif
diff --git a/dev/virtio/vsock-rust/include/vsock/vsock.h b/dev/virtio/vsock-rust/include/vsock/vsock.h
new file mode 100644
index 00000000..3242a4d8
--- /dev/null
+++ b/dev/virtio/vsock-rust/include/vsock/vsock.h
@@ -0,0 +1,27 @@
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
+/*
+ * TODO(b/370957658): generate header automatically via cbindgen.
+ */
+int pci_init_mmio(paddr_t cfg_base, size_t size, size_t cfg_size);
\ No newline at end of file
diff --git a/dev/virtio/vsock-rust/rules.mk b/dev/virtio/vsock-rust/rules.mk
index 329674ba..f49e49a2 100644
--- a/dev/virtio/vsock-rust/rules.mk
+++ b/dev/virtio/vsock-rust/rules.mk
@@ -4,14 +4,38 @@ MODULE_CRATE_NAME := vsock
 MODULE_SRCS := \
 	$(LOCAL_DIR)/src/lib.rs \
 
+MODULE_EXPORT_INCLUDES += \
+	$(LOCAL_DIR)/include
+
 MODULE_LIBRARY_DEPS := \
 	trusty/user/base/lib/liballoc-rust \
 	trusty/user/base/lib/trusty-std \
-	external/rust/crates/lazy_static \
-	external/rust/crates/log \
-	external/rust/crates/static_assertions \
-	external/rust/crates/virtio-drivers \
+	$(call FIND_CRATE,cfg-if) \
+	$(call FIND_CRATE,lazy_static) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,num-integer) \
+	$(call FIND_CRATE,spin) \
+	$(call FIND_CRATE,static_assertions) \
+	$(call FIND_CRATE,virtio-drivers) \
 
 # `trusty-std` is for its `#[global_allocator]`.
 
+# hypervisor_backends is arm64-only for now
+ifeq ($(ARCH),arm64)
+MODULE_LIBRARY_DEPS += \
+	packages/modules/Virtualization/libs/libhypervisor_backends \
+
+endif
+
+MODULE_RUSTFLAGS += \
+	-A clippy::disallowed_names \
+	-A clippy::type-complexity \
+	-A clippy::unnecessary_fallible_conversions \
+	-A clippy::unnecessary-wraps \
+	-A clippy::unusual-byte-groupings \
+	-A clippy::upper-case-acronyms \
+	-D clippy::undocumented_unsafe_blocks \
+
+MODULE_RUST_USE_CLIPPY := true
+
 include make/library.mk
diff --git a/dev/virtio/vsock-rust/src/err.rs b/dev/virtio/vsock-rust/src/err.rs
index 39ff21bb..0af72653 100644
--- a/dev/virtio/vsock-rust/src/err.rs
+++ b/dev/virtio/vsock-rust/src/err.rs
@@ -23,6 +23,8 @@
 
 use virtio_drivers::transport::pci::VirtioPciError;
 
+#[cfg(target_arch = "aarch64")]
+use hypervisor_backends::KvmError;
 use rust_support::Error as LkError;
 use virtio_drivers::Error as VirtioError;
 
@@ -33,6 +35,8 @@ pub enum Error {
     #[allow(dead_code)]
     Virtio(VirtioError),
     Lk(LkError),
+    #[cfg(target_arch = "aarch64")]
+    KvmError(KvmError),
 }
 
 impl From<VirtioPciError> for Error {
@@ -53,11 +57,20 @@ impl From<LkError> for Error {
     }
 }
 
+#[cfg(target_arch = "aarch64")]
+impl From<KvmError> for Error {
+    fn from(e: KvmError) -> Self {
+        Self::KvmError(e)
+    }
+}
+
 impl Error {
     pub fn into_c(self) -> i32 {
         match self {
             Self::Pci(_) => rust_support::Error::ERR_GENERIC,
             Self::Virtio(_) => rust_support::Error::ERR_GENERIC,
+            #[cfg(target_arch = "aarch64")]
+            Self::KvmError(_) => rust_support::Error::ERR_GENERIC,
             Self::Lk(e) => e,
         }
         .into()
diff --git a/dev/virtio/vsock-rust/src/kvm.rs b/dev/virtio/vsock-rust/src/kvm.rs
new file mode 100644
index 00000000..0d359908
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/kvm.rs
@@ -0,0 +1,128 @@
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
+use log::error;
+
+use num_integer::Integer;
+
+use hypervisor_backends::get_mem_sharer;
+use hypervisor_backends::Error;
+use hypervisor_backends::KvmError;
+
+use spin::Once;
+
+/// Result type with kvm error.
+pub type KvmResult<T> = Result<T, KvmError>;
+
+/// The granule size used by the hypervisor
+static GRANULE: Once<KvmResult<usize>> = Once::new();
+
+fn get_granule() -> KvmResult<usize> {
+    *GRANULE.call_once(|| {
+        let hypervisor = get_mem_sharer()
+            .ok_or(KvmError::NotSupported)
+            .inspect_err(|_| error!("failed to get hypervisor"))?;
+        let granule = hypervisor
+            .granule()
+            .inspect_err(|e| error!("failed to get granule: {e:?}"))
+            .map_err(|_| KvmError::NotSupported)?;
+        if !granule.is_power_of_two() {
+            error!("invalid memory protection granule");
+            return Err(KvmError::InvalidParameter);
+        }
+        Ok(granule)
+    })
+}
+
+pub(crate) fn share_pages(paddr: usize, size: usize) -> KvmResult<()> {
+    let hypervisor = get_mem_sharer()
+        .ok_or(KvmError::NotSupported)
+        .inspect_err(|_| error!("failed to get hypervisor"))?;
+    let hypervisor_page_size = get_granule()?;
+
+    if !paddr.is_multiple_of(&hypervisor_page_size) {
+        error!("paddr not aligned");
+        return Err(KvmError::InvalidParameter);
+    }
+
+    if !size.is_multiple_of(&hypervisor_page_size) {
+        error!("size ({size}) not aligned to page size ({hypervisor_page_size})");
+        return Err(KvmError::InvalidParameter);
+    }
+
+    for page in (paddr..paddr + size).step_by(hypervisor_page_size) {
+        hypervisor.share(page as u64).map_err(|err| {
+            error!("failed to share page 0x{page:x}: {err}");
+
+            // unmap any previously shared pages on error
+            // if sharing fail on the first page, the half-open range below is empty
+            for prev in (paddr..page).step_by(hypervisor_page_size) {
+                // keep going even if we fail
+                let _ = hypervisor.unshare(prev as u64);
+            }
+
+            match err {
+                Error::KvmError(e, _) => e,
+                _ => panic!("unexpected share error: {err:?}"),
+            }
+        })?;
+    }
+
+    Ok(())
+}
+
+pub(crate) fn unshare_pages(paddr: usize, size: usize) -> KvmResult<()> {
+    let hypervisor = get_mem_sharer()
+        .ok_or(KvmError::NotSupported)
+        .inspect_err(|_| error!("failed to get hypervisor"))?;
+
+    let hypervisor_page_size = get_granule()?;
+
+    if !hypervisor_page_size.is_power_of_two() {
+        error!("invalid memory protection granule");
+        return Err(KvmError::InvalidParameter);
+    }
+
+    if !paddr.is_multiple_of(&hypervisor_page_size) {
+        error!("paddr not aligned");
+        return Err(KvmError::InvalidParameter);
+    }
+
+    if !size.is_multiple_of(&hypervisor_page_size) {
+        error!("size ({size}) not aligned to page size ({hypervisor_page_size})");
+        return Err(KvmError::InvalidParameter);
+    }
+
+    for page in (paddr..paddr + size).step_by(hypervisor_page_size) {
+        hypervisor.unshare(page as u64).map_err(|err| {
+            error!("failed to unshare page 0x{page:x}: {err:?}");
+
+            match err {
+                Error::KvmError(e, _) => e,
+                _ => panic!("unexpected unshare error: {err:?}"),
+            }
+        })?;
+    }
+
+    Ok(())
+}
diff --git a/dev/virtio/vsock-rust/src/lib.rs b/dev/virtio/vsock-rust/src/lib.rs
index 0796e052..5ee0136b 100644
--- a/dev/virtio/vsock-rust/src/lib.rs
+++ b/dev/virtio/vsock-rust/src/lib.rs
@@ -1,12 +1,16 @@
 #![no_std]
 #![allow(non_camel_case_types)]
 #![feature(cfg_version)]
+// C string byte counts were stabilized in Rust 1.79
+#![cfg_attr(not(version("1.79")), feature(cstr_count_bytes))]
 // C string literals were stabilized in Rust 1.77
 #![cfg_attr(not(version("1.77")), feature(c_str_literals))]
 
 mod err;
-mod hal;
+#[cfg(target_arch = "aarch64")]
+mod kvm;
 mod pci;
 mod vsock;
 
+pub use err::Error;
 pub use pci::pci_init_mmio;
diff --git a/dev/virtio/vsock-rust/src/pci.rs b/dev/virtio/vsock-rust/src/pci.rs
index 07771e7d..a64946d0 100644
--- a/dev/virtio/vsock-rust/src/pci.rs
+++ b/dev/virtio/vsock-rust/src/pci.rs
@@ -27,7 +27,7 @@ use core::ptr;
 
 use alloc::sync::Arc;
 
-use log::debug;
+use log::{debug, error};
 
 use virtio_drivers::device::socket::VirtIOSocket;
 use virtio_drivers::device::socket::VsockConnectionManager;
@@ -49,8 +49,11 @@ use rust_support::vmm::vmm_get_kernel_aspace;
 use rust_support::Error as LkError;
 
 use crate::err::Error;
-use crate::hal::TrustyHal;
 use crate::vsock::VsockDevice;
+use hal::TrustyHal;
+
+mod arch;
+mod hal;
 
 impl TrustyHal {
     fn init_vsock(pci_root: &mut PciRoot, device_function: DeviceFunction) -> Result<(), Error> {
@@ -65,10 +68,9 @@ impl TrustyHal {
             .name(c"virtio_vsock_rx")
             .priority(Priority::HIGH)
             .spawn(move || {
-                crate::vsock::vsock_rx_loop(device_for_rx)
-                    .err()
-                    .unwrap_or(LkError::NO_ERROR.into())
-                    .into_c()
+                let ret = crate::vsock::vsock_rx_loop(device_for_rx);
+                error!("vsock_rx_loop returned {:?}", ret);
+                ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
             })
             .map_err(|e| LkError::from_lk(e).unwrap_err())?;
 
@@ -76,10 +78,9 @@ impl TrustyHal {
             .name(c"virtio_vsock_tx")
             .priority(Priority::HIGH)
             .spawn(move || {
-                crate::vsock::vsock_tx_loop(device_for_tx)
-                    .err()
-                    .unwrap_or(LkError::NO_ERROR.into())
-                    .into_c()
+                let ret = crate::vsock::vsock_tx_loop(device_for_tx);
+                error!("vsock_tx_loop returned {:?}", ret);
+                ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
             })
             .map_err(|e| LkError::from_lk(e).unwrap_err())?;
 
@@ -122,22 +123,27 @@ impl TrustyHal {
 unsafe fn map_pci_root(
     pci_paddr: paddr_t,
     pci_size: usize,
-    _cfg_size: usize,
+    cfg_size: usize,
 ) -> Result<PciRoot, Error> {
     // The ECAM is defined in Section 7.2.2 of the PCI Express Base Specification, Revision 2.0.
     // The ECAM size must be a power of two with the exponent between 1 and 8.
-    let cam = Cam::Ecam;
+    let cam = match cfg_size / /* device functions */ 8 {
+        256 => Cam::MmioCam,
+        4096 => Cam::Ecam,
+        _ => return Err(LkError::ERR_BAD_LEN.into()),
+    };
+
     if !pci_size.is_power_of_two() || pci_size > cam.size() as usize {
         return Err(LkError::ERR_BAD_LEN.into());
     }
     // The ECAM base must be 2^(n + 20)-bit aligned.
-    if pci_paddr & (pci_size - 1) != 0 {
+    if cam == Cam::Ecam && pci_paddr & (pci_size - 1) != 0 {
         return Err(LkError::ERR_INVALID_ARGS.into());
     }
 
     // Map the PCI configuration space.
     let pci_vaddr = ptr::null_mut();
-    // # Safety
+    // Safety:
     // `aspace` is `vmm_get_kernel_aspace()`.
     // `name` is a `&'static CStr`.
     // `pci_paddr` and `pci_size` are safe by this function's safety requirements.
@@ -155,7 +161,7 @@ unsafe fn map_pci_root(
     };
     LkError::from_lk(e)?;
 
-    // # Safety:
+    // Safety:
     // `pci_paddr` is a valid physical address to the base of the MMIO region.
     // `pci_vaddr` is the mapped virtual address of that.
     // `pci_paddr` has `'static` lifetime, and `pci_vaddr` is never unmapped,
diff --git a/dev/virtio/vsock-rust/src/pci/arch.rs b/dev/virtio/vsock-rust/src/pci/arch.rs
new file mode 100644
index 00000000..4ebb89e8
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/pci/arch.rs
@@ -0,0 +1,56 @@
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
+use cfg_if::cfg_if;
+
+cfg_if! {
+    if #[cfg(target_arch = "aarch64")] {
+        mod aarch64;
+        pub(crate) use aarch64::*;
+    } else if #[cfg(target_arch = "x86_64")] {
+        mod x86_64;
+        pub(crate) use x86_64::*;
+    } else {
+        use core::ptr::NonNull;
+        use virtio_drivers::BufferDirection;
+        use virtio_drivers::PhysAddr;
+
+        pub(crate) fn dma_alloc_share(_paddr: usize, _size: usize) {
+            unimplemented!();
+        }
+
+        pub(crate) fn dma_dealloc_unshare(_paddr: PhysAddr, _size: usize) {
+            unimplemented!();
+        }
+
+        // Safety: unimplemented
+        pub(crate) unsafe fn share(_buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
+            unimplemented!();
+        }
+
+        // Safety: unimplemented
+        pub(crate) unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
+            unimplemented!();
+        }
+    }
+}
diff --git a/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs b/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs
new file mode 100644
index 00000000..656cbaa5
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs
@@ -0,0 +1,115 @@
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
+use alloc::collections::btree_map::BTreeMap;
+
+use lazy_static::lazy_static;
+
+use core::ffi::c_void;
+use core::ops::DerefMut;
+use core::ptr::copy_nonoverlapping;
+use core::ptr::NonNull;
+
+use crate::kvm::share_pages;
+use crate::kvm::unshare_pages;
+
+use crate::pci::hal::TrustyHal;
+
+use rust_support::paddr_t;
+use rust_support::sync::Mutex;
+use rust_support::vaddr_t;
+
+use virtio_drivers::BufferDirection;
+use virtio_drivers::Hal;
+use virtio_drivers::PhysAddr;
+use virtio_drivers::PAGE_SIZE;
+
+lazy_static! {
+    /// Stores the paddr to vaddr mapping in `share` for use in `unshare`
+    static ref VADDRS: Mutex<BTreeMap<paddr_t, vaddr_t>> = Mutex::new(BTreeMap::new());
+}
+
+/// Perform architecture-specific DMA allocation
+pub(crate) fn dma_alloc_share(paddr: usize, size: usize) {
+    share_pages(paddr, size).expect("failed to share pages");
+}
+
+/// Perform architecture-specific DMA deallocation
+pub(crate) fn dma_dealloc_unshare(paddr: PhysAddr, size: usize) {
+    unshare_pages(paddr, size).expect("failed to unshare pages");
+}
+
+// Safety: buffer must be a valid kernel virtual address that is not already mapped for DMA.
+pub(crate) unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
+    let size = buffer.len();
+    let pages = to_pages(size);
+
+    let (paddr, vaddr) = TrustyHal::dma_alloc(pages, direction);
+    if let Some(old_vaddr) = VADDRS.lock().deref_mut().insert(paddr, vaddr.as_ptr() as usize) {
+        panic!("paddr ({:#x}) was already mapped to vaddr ({:#x})", paddr, old_vaddr);
+    }
+
+    let dst_ptr = vaddr.as_ptr() as *mut c_void;
+
+    if direction != BufferDirection::DeviceToDriver {
+        let src_ptr = buffer.as_ptr() as *const u8 as *const c_void;
+        // Safety: Both regions are valid, properly aligned, and don't overlap.
+        // - Because `vaddr` is a virtual address returned by `dma_alloc`, it is
+        // properly aligned and does not overlap with `buffer`.
+        // - There are no particular alignment requirements on `buffer`.
+        unsafe { copy_nonoverlapping(src_ptr, dst_ptr, size) };
+    }
+
+    paddr
+}
+
+// Safety:
+// - paddr is a valid physical address returned by call to `share`
+// - buffer must be a valid kernel virtual address previously passed to `share` that
+//   has not already been `unshare`d by this function.
+pub(crate) unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
+    let size = buffer.len();
+    let vaddr = VADDRS.lock().deref_mut().remove(&paddr).expect("paddr was inserted by share")
+        as *const c_void;
+
+    if direction != BufferDirection::DriverToDevice {
+        let dest = buffer.as_ptr() as *mut u8 as *mut c_void;
+        // Safety: Both regions are valid, properly aligned, and don't overlap.
+        // - Because `vaddr` was retrieved from `VADDRS`, it must have been returned
+        //   from the call to `dma_alloc` in `share`.
+        // - Because `vaddr` is a virtual address returned by `dma_alloc`, it is
+        //   properly aligned and does not overlap with `buffer`.
+        // - There are no particular alignment requirements on `buffer`.
+        unsafe { copy_nonoverlapping(vaddr, dest, size) };
+    }
+
+    let vaddr = NonNull::<u8>::new(vaddr as *mut u8).unwrap();
+    // Safety: memory was allocated by `share` and not previously `unshare`d.
+    unsafe {
+        TrustyHal::dma_dealloc(paddr, vaddr, to_pages(size));
+    }
+}
+
+fn to_pages(size: usize) -> usize {
+    size.div_ceil(PAGE_SIZE)
+}
diff --git a/dev/virtio/vsock-rust/src/pci/arch/x86_64.rs b/dev/virtio/vsock-rust/src/pci/arch/x86_64.rs
new file mode 100644
index 00000000..1bf5f43d
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/pci/arch/x86_64.rs
@@ -0,0 +1,47 @@
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
+use core::ptr::NonNull;
+
+use virtio_drivers::BufferDirection;
+use virtio_drivers::PhysAddr;
+
+use rust_support::vmm::vaddr_to_paddr;
+
+pub(crate) fn dma_alloc_share(_paddr: usize, _size: usize) {}
+pub(crate) fn dma_dealloc_unshare(_paddr: PhysAddr, _size: usize) {}
+
+// Safety: buffer must be a valid kernel virtual address for the duration of the call.
+pub(crate) unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
+    // no-op on x86_64
+    // Safety: buffer is a valid kernel virtual address
+    unsafe { vaddr_to_paddr(buffer.as_ptr().cast()) }
+}
+
+// Safety: not actually unsafe.
+pub(crate) unsafe fn unshare(
+    _paddr: PhysAddr,
+    _buffer: NonNull<[u8]>,
+    _direction: BufferDirection,
+) {
+}
diff --git a/dev/virtio/vsock-rust/src/hal.rs b/dev/virtio/vsock-rust/src/pci/hal.rs
similarity index 80%
rename from dev/virtio/vsock-rust/src/hal.rs
rename to dev/virtio/vsock-rust/src/pci/hal.rs
index 42574f5b..737513f0 100644
--- a/dev/virtio/vsock-rust/src/hal.rs
+++ b/dev/virtio/vsock-rust/src/pci/hal.rs
@@ -46,6 +46,7 @@ use virtio_drivers::transport::pci::bus::PciRoot;
 use virtio_drivers::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};
 
 use crate::err::Error;
+use crate::pci::arch;
 
 #[derive(Copy, Clone)]
 struct BarInfo {
@@ -75,7 +76,7 @@ impl TrustyHal {
                 let bar_vaddr = core::ptr::null_mut();
                 let bar_size_aligned = (bar_size as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
 
-                // # Safety
+                // Safety:
                 // `aspace` is `vmm_get_kernel_aspace()`.
                 // `name` is a `&'static CStr`.
                 // `bar_paddr` and `bar_size_aligned` are safe by this function's safety requirements.
@@ -107,6 +108,7 @@ impl TrustyHal {
 // Safety: TrustyHal is stateless and thus trivially safe to send to another thread
 unsafe impl Send for TrustyHal {}
 
+// Safety: See function specific comments
 unsafe impl Hal for TrustyHal {
     // Safety:
     // Function either returns a non-null, properly aligned pointer or panics the kernel.
@@ -114,18 +116,18 @@ unsafe impl Hal for TrustyHal {
     fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
         let name = c"vsock-rust";
         // dma_alloc requests num pages but vmm_alloc_contiguous expects bytes.
-        let size = pages * PAGE_SIZE as usize;
+        let size = pages * PAGE_SIZE;
         let mut vaddr = core::ptr::null_mut(); // stores pointer to virtual memory
         let align_pow2 = PAGE_SIZE_SHIFT as u8;
         let vmm_flags = 0;
-        let arch_mmu_flags = 0;
+        let arch_mmu_flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE;
         let aspace = vmm_get_kernel_aspace();
 
         // NOTE: the allocated memory will be zeroed since vmm_alloc_contiguous
         // calls vmm_alloc_pmm which does not set the PMM_ALLOC_FLAG_NO_CLEAR
         // flag.
         //
-        // # Safety
+        // Safety:
         // `aspace` is `vmm_get_kernel_aspace()`.
         // `name` is a `&'static CStr`.
         // `size` is validated by the callee
@@ -150,13 +152,23 @@ unsafe impl Hal for TrustyHal {
         // Safety: `vaddr` is valid because the call to `vmm_alloc_continuous` succeeded
         let paddr = unsafe { vaddr_to_paddr(vaddr) };
 
+        arch::dma_alloc_share(paddr, size);
+
         (paddr, NonNull::<u8>::new(vaddr as *mut u8).unwrap())
     }
 
-    unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, _pages: usize) -> i32 {
-        // TODO: store pointers allocated with dma_alloc to validate the args
+    // Safety: `vaddr` was returned by `dma_alloc` and hasn't been deallocated.
+    unsafe fn dma_dealloc(paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
+        let size = pages * PAGE_SIZE;
+        arch::dma_dealloc_unshare(paddr, size);
+
         let aspace = vmm_get_kernel_aspace();
-        vmm_free_region(aspace, vaddr.as_ptr() as _)
+        let vaddr = vaddr.as_ptr();
+        // Safety:
+        // - function-level requirements
+        // - `aspace` points to the kernel address space object
+        // - `vaddr` is a region in `aspace`
+        unsafe { vmm_free_region(aspace, vaddr as usize) }
     }
 
     // Only used for MMIO addresses within BARs read from the device,
@@ -173,28 +185,32 @@ unsafe impl Hal for TrustyHal {
                 if paddr + size > bar_paddr_end {
                     panic!("invalid arguments passed to mmio_phys_to_virt");
                 }
-                let offset: isize = (paddr - bar.paddr).try_into().unwrap();
+                let offset = paddr - bar.paddr;
 
                 let bar_vaddr_ptr: *mut u8 = bar.vaddr as _;
-                return NonNull::<u8>::new(bar_vaddr_ptr.offset(offset)).unwrap();
+                // Safety:
+                // - `BARS` correctly maps from physical to virtual pages
+                // - `offset` is less than or equal to bar.size because
+                //   `bar.paddr` <= `paddr`` < `bar_paddr_end`
+                let vaddr = unsafe { bar_vaddr_ptr.add(offset) };
+                return NonNull::<u8>::new(vaddr).unwrap();
             }
         }
 
         panic!("error mapping physical memory to virtual for mmio");
     }
 
-    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
-        // no-op on x86_64, not implemented on other architectures
-        #[cfg(not(target_arch = "x86_64"))]
-        unimplemented!();
-
-        vaddr_to_paddr(buffer.as_ptr().cast())
+    // Safety: delegated to callee
+    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
+        // Safety: delegated to arch::share
+        unsafe { arch::share(buffer, direction) }
     }
 
-    // Safety: no-op on x86-64, panic elsewhere.
-    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
-        // no-op on x86_64, not implemented on other architectures
-        #[cfg(not(target_arch = "x86_64"))]
-        unimplemented!();
+    // Safety: delegated to callee
+    unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
+        // Safety: delegated to arch::unshare
+        unsafe {
+            arch::unshare(paddr, buffer, direction);
+        }
     }
 }
diff --git a/dev/virtio/vsock-rust/src/vsock.rs b/dev/virtio/vsock-rust/src/vsock.rs
index e21d704a..0b00b9ae 100644
--- a/dev/virtio/vsock-rust/src/vsock.rs
+++ b/dev/virtio/vsock-rust/src/vsock.rs
@@ -31,7 +31,6 @@ use core::time::Duration;
 
 use alloc::boxed::Box;
 use alloc::ffi::CString;
-use alloc::format;
 use alloc::sync::Arc;
 use alloc::vec;
 use alloc::vec::Vec;
@@ -44,6 +43,7 @@ use log::warn;
 use rust_support::handle::IPC_HANDLE_POLL_HUP;
 use rust_support::handle::IPC_HANDLE_POLL_MSG;
 use rust_support::handle::IPC_HANDLE_POLL_READY;
+use rust_support::handle::IPC_HANDLE_POLL_SEND_UNBLOCKED;
 use rust_support::ipc::iovec_kern;
 use rust_support::ipc::ipc_get_msg;
 use rust_support::ipc::ipc_msg_info;
@@ -58,11 +58,13 @@ use rust_support::ipc::IPC_PORT_PATH_MAX;
 use rust_support::sync::Mutex;
 use rust_support::thread;
 use rust_support::thread::sleep;
+use virtio_drivers::device::socket::SocketError;
 use virtio_drivers::device::socket::VsockAddr;
 use virtio_drivers::device::socket::VsockConnectionManager;
 use virtio_drivers::device::socket::VsockEvent;
 use virtio_drivers::device::socket::VsockEventType;
 use virtio_drivers::transport::Transport;
+use virtio_drivers::Error as VirtioError;
 use virtio_drivers::Hal;
 use virtio_drivers::PAGE_SIZE;
 
@@ -83,6 +85,7 @@ enum VsockConnectionState {
     VsockOnly,
     TipcOnly,
     TipcConnecting,
+    TipcSendBlocked,
     Active,
     TipcClosed,
     Closed,
@@ -99,15 +102,25 @@ struct VsockConnection {
     tx_since_rx: u64,
     rx_count: u64,
     rx_since_tx: u64,
+    rx_buffer: Box<[u8]>, // buffers data if the tipc connection blocks
+    rx_pending: usize,    // how many bytes to send when tipc unblocks
 }
 
 impl VsockConnection {
     fn new(peer: VsockAddr, local_port: u32) -> Self {
+        // Make rx_buffer twice as large as the vsock connection rx buffer such
+        // that we can buffer pending messages if TIPC blocks.
+        //
+        // TODO: the ideal rx_buffer size depends on the connection so it might
+        // be worthwhile to dynamically re-size the buffer in response to tipc
+        // blocking or unblocking.
+        let rx_buffer_len = 2 * PAGE_SIZE;
         Self {
             peer,
             local_port,
             state: VsockConnectionState::VsockOnly,
             tipc_port_name: None,
+            rx_buffer: vec![0u8; rx_buffer_len].into_boxed_slice(),
             ..Default::default()
         }
     }
@@ -115,9 +128,8 @@ impl VsockConnection {
     fn tipc_port_name(&self) -> &str {
         self.tipc_port_name
             .as_ref()
-            .expect("port name not set")
-            .to_str()
-            .expect("invalid port name")
+            .map(|s| s.to_str().expect("invalid port name"))
+            .unwrap_or("(no port name)")
     }
 
     fn print_stats(&self) {
@@ -132,16 +144,119 @@ impl VsockConnection {
             self.state
         );
     }
+
+    fn tipc_try_send(&mut self) -> Result<(), Error> {
+        debug_assert!(self.rx_pending > 0 && self.rx_pending < PAGE_SIZE);
+        debug_assert!(
+            self.state == VsockConnectionState::Active
+                || self.state == VsockConnectionState::TipcSendBlocked
+        );
+
+        let length = self.rx_pending;
+        let mut iov = iovec_kern { iov_base: self.rx_buffer.as_mut_ptr() as _, iov_len: length };
+        let mut msg = ipc_msg_kern::new(&mut iov);
+
+        // Safety:
+        // `c.href.handle` is a handle attached to a tipc channel.
+        // `msg` contains an `iov` which points to a buffer from which
+        // the kernel can read `iov_len` bytes.
+        let ret = unsafe { ipc_send_msg(self.href.handle(), &mut msg) };
+        if ret == LkError::ERR_NOT_ENOUGH_BUFFER.into() {
+            self.state = VsockConnectionState::TipcSendBlocked;
+            return Ok(());
+        } else if ret < 0 {
+            error!("failed to send {length} bytes to {}: {ret} ", self.tipc_port_name());
+            LkError::from_lk(ret)?;
+        } else if ret as usize != length {
+            // TODO: in streaming mode, this should not be an error. Instead, consume
+            // the data that was sent and try sending the rest in the next message.
+            error!("sent {ret} bytes but expected to send {length} bytes");
+            return Err(LkError::ERR_BAD_LEN.into());
+        }
+
+        self.state = VsockConnectionState::Active;
+        self.tx_since_rx = 0;
+        self.rx_pending = 0;
+
+        debug!("sent {length} bytes to {}", self.tipc_port_name());
+
+        Ok(())
+    }
+}
+
+/// The action to take after running the `f` closure in [`vsock_connection_lookup`].
+#[derive(PartialEq, Eq)]
+enum ConnectionStateAction {
+    /// No action needs to be taken, so the connection stays open.
+    None,
+
+    /// TIPC has requested that the connection be closed.
+    /// This closes the connection and waits for the peer to acknowledge before removing it.
+    Close,
+
+    /// We want to close the connection and remove it
+    /// without waiting for the peer to acknowledge it,
+    /// such as when there is an error (but also potentially other reasons).
+    Remove,
 }
 
 fn vsock_connection_lookup(
     connections: &mut Vec<VsockConnection>,
     remote_port: u32,
-) -> Option<(usize, &mut VsockConnection)> {
-    connections
+    f: impl FnOnce(&mut VsockConnection) -> ConnectionStateAction,
+) -> Result<(), ()> {
+    let (index, connection) = connections
         .iter_mut()
         .enumerate()
         .find(|(_idx, connection)| connection.peer.port == remote_port)
+        .ok_or(())?;
+    let action = f(connection);
+    if action == ConnectionStateAction::None {
+        return Ok(());
+    }
+
+    if vsock_connection_close(connection, action) {
+        connections.swap_remove(index);
+    }
+
+    Ok(())
+}
+
+fn vsock_connection_close(c: &mut VsockConnection, action: ConnectionStateAction) -> bool {
+    info!(
+        "remote_port {}, tipc_port_name {}, state {:?}",
+        c.peer.port,
+        c.tipc_port_name(),
+        c.state
+    );
+
+    if c.state == VsockConnectionState::VsockOnly {
+        info!("tipc vsock only connection closed");
+        c.state = VsockConnectionState::TipcClosed;
+    }
+
+    if c.state == VsockConnectionState::Active
+        || c.state == VsockConnectionState::TipcConnecting
+        || c.state == VsockConnectionState::TipcSendBlocked
+    {
+        // The handle set owns the only reference we have to the handle and
+        // handle_set_wait might have already returned a pointer to c
+        c.href.detach();
+        c.href.handle_close();
+        c.href.set_cookie(null_mut());
+        info!("tipc handle closed");
+        c.state = VsockConnectionState::TipcClosed;
+    }
+    if action == ConnectionStateAction::Remove && c.state == VsockConnectionState::TipcClosed {
+        info!("vsock closed");
+        c.state = VsockConnectionState::Closed;
+    }
+    if c.state == VsockConnectionState::Closed && c.href.cookie().is_null() {
+        info!("remove connection");
+        c.print_stats();
+        return true; // remove connection
+    }
+    false // keep connection
 }
 
 pub struct VsockDevice<H, T>
@@ -172,10 +287,10 @@ where
 
         // do we already have a connection?
         let mut guard = self.connections.lock();
-        if let Some(_) = guard
+        if guard
             .deref()
             .iter()
-            .find(|connection| connection.peer == peer && connection.local_port == local.port)
+            .any(|connection| connection.peer == peer && connection.local_port == local.port)
         {
             panic!("connection already exists");
         };
@@ -200,7 +315,7 @@ where
             .unwrap();
         assert!(data_len == length);
         // allow manual connect from nc in line mode
-        if buffer[data_len - 1] == '\n' as _ {
+        if buffer[data_len - 1] == b'\n' as _ {
             data_len -= 1;
         }
         let port_name = &buffer[0..data_len];
@@ -233,7 +348,7 @@ where
             )
         }
 
-        info!("wait for connection to {}, remote {}", c.tipc_port_name(), c.peer.port);
+        debug!("wait for connection to {}, remote {}", c.tipc_port_name(), c.peer.port);
 
         c.state = VsockConnectionState::TipcConnecting;
 
@@ -270,81 +385,32 @@ where
         length: usize,
         source: VsockAddr,
         destination: VsockAddr,
-        rx_buffer: &mut Box<[u8]>,
     ) -> Result<(), Error> {
-        assert!(length <= rx_buffer.len());
-        let data_len = self
+        assert_eq!(c.state, VsockConnectionState::Active);
+
+        // multiple messages may be available when we call recv but we want to forward
+        // them on the tipc connection one by one. Pass a slice of the rx_buffer so
+        // we only drain the number of bytes that correspond to a single vsock event.
+        c.rx_pending = self
             .connection_manager
             .lock()
             .deref_mut()
-            .recv(source, destination.port, rx_buffer)
+            .recv(source, destination.port, &mut c.rx_buffer[..length])
             .unwrap();
 
         // TODO: handle large messages properly
-        assert!(data_len == length);
-
-        let mut iov = iovec_kern { iov_base: rx_buffer.as_mut_ptr() as _, iov_len: data_len };
-        let mut msg = ipc_msg_kern::new(&mut iov);
+        assert_eq!(c.rx_pending, length);
 
         c.rx_count += 1;
         c.rx_since_tx += 1;
-        c.tx_since_rx = 0;
-        // Safety:
-        // `c.href.handle` is a handle attached to a tipc channel.
-        // `msg` contains an `iov` which points to a buffer from which
-        // the kernel can read `iov_len` bytes.
-        let ret = unsafe { ipc_send_msg(c.href.handle(), &mut msg) };
-        if ret < 0 {
-            error!("failed to send {length} bytes to {}: {ret} ", c.tipc_port_name());
-            LkError::from_lk(ret)?;
-        }
-        if ret as usize != length {
-            error!("sent {ret} bytes but expected to send {length} bytes");
-            Err(LkError::ERR_IO)?;
-        }
 
-        debug!("sent {length} bytes to {}", c.tipc_port_name());
+        c.tipc_try_send()?;
+
         self.connection_manager.lock().deref_mut().update_credit(c.peer, c.local_port).unwrap();
 
         Ok(())
     }
 
-    fn vsock_connection_close(&self, c: &mut VsockConnection, vsock_done: bool) -> bool {
-        info!(
-            "remote_port {}, tipc_port_name {}, state {:?}",
-            c.peer.port,
-            c.tipc_port_name(),
-            c.state
-        );
-
-        if c.state == VsockConnectionState::VsockOnly {
-            info!("tipc vsock only connection closed");
-            c.state = VsockConnectionState::TipcClosed;
-        }
-
-        if c.state == VsockConnectionState::Active
-            || c.state == VsockConnectionState::TipcConnecting
-        {
-            // The handle set owns the only reference we have to the handle and
-            // handle_set_wait might have already returned a pointer to c
-            c.href.detach();
-            c.href.handle_close();
-            c.href.set_cookie(null_mut());
-            info!("tipc handle closed");
-            c.state = VsockConnectionState::TipcClosed;
-        }
-        if vsock_done && c.state == VsockConnectionState::TipcClosed {
-            info!("vsock closed");
-            c.state = VsockConnectionState::Closed;
-        }
-        if c.state == VsockConnectionState::Closed && c.href.cookie().is_null() {
-            info!("remove connection");
-            c.print_stats();
-            return true; // remove connection
-        }
-        return false; // keep connection
-    }
-
     fn print_stats(&self) {
         let guard = self.connections.lock();
         let connections = guard.deref();
@@ -379,94 +445,100 @@ where
 {
     let local_port = 1;
     let ten_ms = Duration::from_millis(10);
-    let mut rx_buffer = vec![0u8; PAGE_SIZE].into_boxed_slice();
+    let mut pending: Vec<VsockEvent> = vec![];
 
     debug!("starting vsock_rx_loop");
     device.connection_manager.lock().deref_mut().listen(local_port);
 
     loop {
         // TODO: use interrupts instead of polling
-        let event = device.connection_manager.lock().deref_mut().poll()?;
-        if let Some(VsockEvent { source, destination, event_type, .. }) = event {
-            match event_type {
-                VsockEventType::ConnectionRequest => {
-                    device.vsock_rx_op_request(source, destination);
-                }
-                VsockEventType::Connected => {
-                    panic!("outbound connections not supported");
-                }
-                VsockEventType::Received { length } => {
-                    debug!("recv destination: {destination:?}");
-
-                    let mut guard = device.connections.lock();
-                    if let Some((conn_idx, mut connection)) =
-                        vsock_connection_lookup(guard.deref_mut(), source.port)
-                    {
-                        if let Err(e) = match connection {
-                            ref mut c @ VsockConnection {
-                                state: VsockConnectionState::VsockOnly,
-                                ..
-                            } => device.vsock_connect_tipc(c, length, source, destination),
-                            ref mut c @ VsockConnection {
-                                state: VsockConnectionState::Active,
-                                ..
-                            } => device.vsock_rx_channel(
-                                *c,
-                                length,
+        // TODO: handle case where poll returns SocketError::OutputBufferTooShort
+        let event = pending
+            .pop()
+            .or_else(|| device.connection_manager.lock().deref_mut().poll().expect("poll failed"));
+
+        if event.is_none() {
+            sleep(ten_ms);
+            continue;
+        }
+
+        let VsockEvent { source, destination, event_type, buffer_status } = event.unwrap();
+
+        match event_type {
+            VsockEventType::ConnectionRequest => {
+                device.vsock_rx_op_request(source, destination);
+            }
+            VsockEventType::Connected => {
+                panic!("outbound connections not supported");
+            }
+            VsockEventType::Received { length } => {
+                debug!("recv destination: {destination:?}");
+
+                let connections = &mut *device.connections.lock();
+                let _ = vsock_connection_lookup(connections, source.port, |mut connection| {
+                    if let Err(e) = match connection {
+                        ref mut c @ VsockConnection {
+                            state: VsockConnectionState::VsockOnly, ..
+                        } => device.vsock_connect_tipc(c, length, source, destination),
+                        ref mut c @ VsockConnection {
+                            state: VsockConnectionState::Active, ..
+                        } => device.vsock_rx_channel(c, length, source, destination),
+                        VsockConnection {
+                            state: VsockConnectionState::TipcSendBlocked, ..
+                        } => {
+                            // requeue pending event.
+                            pending.push(VsockEvent {
                                 source,
                                 destination,
-                                &mut rx_buffer,
-                            ),
-                            VsockConnection {
-                                state: VsockConnectionState::TipcConnecting, ..
-                            } => {
-                                warn!("got data while still waiting for tipc connection");
-                                Err(LkError::ERR_BAD_STATE.into())
-                            }
-                            VsockConnection { state: s, .. } => {
-                                error!("got data for connection in state {s:?}");
-                                Err(LkError::ERR_BAD_STATE.into())
-                            }
-                        } {
-                            error!("failed to receive data from vsock connection:  {e:?}");
-                            // TODO: add reset function to device or connection?
-                            let _ = device
-                                .connection_manager
-                                .lock()
-                                .deref_mut()
-                                .force_close(connection.peer, connection.local_port);
-
-                            if device.vsock_connection_close(connection, true) {
-                                // TODO: find a proper way to satisfy the borrow checker
-                                guard.deref_mut().swap_remove(conn_idx);
-                            }
+                                event_type,
+                                buffer_status,
+                            });
+                            // TODO: on one hand, we want to wait for the tipc connection to unblock
+                            // on the other, we want to pick up incoming events as soon as we can...
+                            // NOTE: Adding support for interrupts means we no longer have to sleep.
+                            sleep(ten_ms);
+                            Ok(())
                         }
-                    } else {
-                        warn!("got packet for unknown connection");
-                    }
-                }
-                VsockEventType::Disconnected { reason } => {
-                    debug!("disconnected from peer. reason: {reason:?}");
-                    let mut guard = device.connections.lock();
-                    let connections = guard.deref_mut();
-                    if let Some((c_idx, c)) = vsock_connection_lookup(connections, source.port) {
-                        let vsock_done = true;
-                        if device.vsock_connection_close(c, vsock_done) {
-                            // TODO: find a proper way to satisfy the borrow checker
-                            connections.swap_remove(c_idx);
+                        VsockConnection { state: VsockConnectionState::TipcConnecting, .. } => {
+                            warn!("got data while still waiting for tipc connection");
+                            Err(LkError::ERR_BAD_STATE.into())
                         }
-                    } else {
-                        warn!("got disconnect ({reason:?}) for unknown connection");
+                        VsockConnection { state: s, .. } => {
+                            error!("got data for connection in state {s:?}");
+                            Err(LkError::ERR_BAD_STATE.into())
+                        }
+                    } {
+                        error!("failed to receive data from vsock connection:  {e:?}");
+                        // TODO: add reset function to device or connection?
+                        let _ = device
+                            .connection_manager
+                            .lock()
+                            .deref_mut()
+                            .force_close(connection.peer, connection.local_port);
+
+                        return ConnectionStateAction::Remove;
                     }
-                }
-                VsockEventType::CreditUpdate => { /* nothing to do */ }
-                VsockEventType::CreditRequest => {
-                    // Polling the VsockConnectionManager won't return this event type
-                    panic!("don't know how to handle credit requests");
-                }
+                    ConnectionStateAction::None
+                })
+                .inspect_err(|_| {
+                    warn!("got packet for unknown connection");
+                });
+            }
+            VsockEventType::Disconnected { reason } => {
+                debug!("disconnected from peer. reason: {reason:?}");
+                let connections = &mut *device.connections.lock();
+                let _ = vsock_connection_lookup(connections, source.port, |_connection| {
+                    ConnectionStateAction::Remove
+                })
+                .inspect_err(|_| {
+                    warn!("got disconnect ({reason:?}) for unknown connection");
+                });
+            }
+            VsockEventType::CreditUpdate => { /* nothing to do */ }
+            VsockEventType::CreditRequest => {
+                // Polling the VsockConnectionManager won't return this event type
+                panic!("don't know how to handle credit requests");
             }
-        } else {
-            sleep(ten_ms);
         }
     }
 }
@@ -487,9 +559,8 @@ where
             // but we can wait for it to become non-empty using handle_wait.
             // Once that that returns we have to call handle_set_wait again to
             // get the event we care about.
-            info!("handle_set_wait failed: {}", ret.unwrap_err());
             ret = device.handle_set.handle_wait(&mut href.emask(), timeout);
-            if ret != Err(LkError::ERR_TIMED_OUT.into()) {
+            if ret != Err(LkError::ERR_TIMED_OUT) {
                 info!("handle_wait on handle set returned: {ret:?}");
                 continue;
             }
@@ -507,9 +578,7 @@ where
             continue;
         }
 
-        let mut guard = device.connections.lock();
-        let connections = guard.deref_mut();
-        if let Some((_, c)) = vsock_connection_lookup(connections, href.id()) {
+        let _ = vsock_connection_lookup(&mut device.connections.lock(), href.id(), |c| {
             if !eq(c.href.as_mut_ptr() as *mut c_void, href.cookie()) {
                 panic!(
                     "unexpected cookie {:?} != {:?} for connection {}",
@@ -550,17 +619,48 @@ where
                         c.tx_count += 1;
                         c.tx_since_rx += 1;
                         c.rx_since_tx = 0;
-                        device
-                            .connection_manager
-                            .lock()
-                            .send(c.peer, c.local_port, &tx_buffer[..msg_info.len])
-                            .expect(&format!("failed to send message from {}", c.tipc_port_name()));
-                        debug!("sent {} bytes from {}", msg_info.len, c.tipc_port_name());
+                        match device.connection_manager.lock().send(
+                            c.peer,
+                            c.local_port,
+                            &tx_buffer[..msg_info.len],
+                        ) {
+                            Err(err) => {
+                                if err == VirtioError::SocketDeviceError(SocketError::NotConnected)
+                                {
+                                    debug!(
+                                        "failed to send {} bytes from {}. Connection closed",
+                                        msg_info.len,
+                                        c.tipc_port_name()
+                                    );
+                                } else {
+                                    // TODO: close connection instead
+                                    panic!(
+                                        "failed to send {} bytes from {}: {:?}",
+                                        msg_info.len,
+                                        c.tipc_port_name(),
+                                        err
+                                    );
+                                }
+                            }
+                            Ok(_) => {
+                                debug!("sent {} bytes from {}", msg_info.len, c.tipc_port_name());
+                            }
+                        }
                     } else {
                         error!("ipc_read_msg failed: {ret}");
                     }
                 }
             }
+            if href.emask() & IPC_HANDLE_POLL_SEND_UNBLOCKED != 0 {
+                assert_eq!(c.state, VsockConnectionState::TipcSendBlocked);
+                assert_ne!(c.rx_pending, 0);
+
+                debug!("tipc connection unblocked {}", c.tipc_port_name());
+
+                if let Err(e) = c.tipc_try_send() {
+                    error!("failed to send pending message to {}: {e:?}", c.tipc_port_name());
+                }
+            }
             if href.emask() & IPC_HANDLE_POLL_HUP != 0 {
                 // Print stats if we don't send any more packets for a while
                 timeout = ACTIVE_TIMEOUT;
@@ -571,11 +671,21 @@ where
                     c.peer,
                     c.local_port
                 );
-                device.connection_manager.lock().shutdown(c.peer, c.local_port)?;
-                device.vsock_connection_close(c, /* vsock_done */ false);
+                let res = device.connection_manager.lock().shutdown(c.peer, c.local_port);
+                if res.is_ok() {
+                    return ConnectionStateAction::Close;
+                } else {
+                    warn!(
+                        "failed to send shutdown command, connection removed? {}",
+                        res.unwrap_err()
+                    );
+                }
             }
-        }
-        drop(guard);
+            ConnectionStateAction::None
+        })
+        .inspect_err(|_| {
+            warn!("got event for non-existent remote {}, was it closed?", href.id());
+        });
         href.handle_decref();
     }
 }
diff --git a/engine.mk b/engine.mk
index 4cda6a24..a04c5f16 100644
--- a/engine.mk
+++ b/engine.mk
@@ -55,6 +55,15 @@ DEBUG ?= 2
 # when LOG_LEVEL_KERNEL = 2, dprintf SPEW level is enabled
 LOG_LEVEL_KERNEL ?= $(DEBUG)
 
+# LOG_LEVEL_KERNEL_RUST controls LK_LOGLEVEL_RUST
+# when LOG_LEVEL_KERNEL_RUST = 0, Rust max log level is LevelFilter::Off
+# when LOG_LEVEL_KERNEL_RUST = 1, Rust max log level is LevelFilter::Error
+# when LOG_LEVEL_KERNEL_RUST = 2, Rust max log level is LogLevel::Warning
+# when LOG_LEVEL_KERNEL_RUST = 3, Rust max log level is LogLevel::Info
+# when LOG_LEVEL_KERNEL_RUST = 4, Rust max log level is LogLevel::Debug
+# when LOG_LEVEL_KERNEL_RUST = 5 or greater, the max log level is LogLevel::Trace
+LOG_LEVEL_KERNEL_RUST ?= $(LOG_LEVEL_KERNEL)
+
 # LOG_LEVEL_USER controls TLOG_LVL_DEFAULT
 # when LOG_LEVEL_USER = 2 TLOG_LVL_DEFAULT = 4 (info)
 # when LOG_LEVEL_USER = 3 TLOG_LVL_DEFAULT = 5 (debug)
@@ -116,8 +125,6 @@ GLOBAL_SHARED_RUSTFLAGS += -C symbol-mangling-version=v0
 GLOBAL_SHARED_RUSTFLAGS += -C panic=abort -Z link-native-libraries=no
 GLOBAL_SHARED_RUSTFLAGS += -Z panic_abort_tests
 GLOBAL_SHARED_RUSTFLAGS += --deny warnings
-# Enable LTO for all Rust modules.
-GLOBAL_SHARED_RUSTFLAGS += -C lto=thin
 
 # Architecture specific compile flags
 ARCH_COMPILEFLAGS :=
@@ -223,6 +230,36 @@ GLOBAL_KERNEL_LDFLAGS += --whole-archive
 # TODO(b/224064243): remove this when we have a proper triple
 GLOBAL_SHARED_COMPILEFLAGS += -U__linux__
 
+# Enable LTO for all Rust modules.
+#
+# If the kernel has CFI enabled it needs to use linker LTO instead of the one
+# built into rustc. We need split LTO enabled for both languages
+# to avoid linking issues from mismatches between object files.
+# clang selects this by default, but rustc currently needs it to be selected
+# manually.
+ifeq (true,$(call TOBOOL,$(KERNEL_CFI_ENABLED)))
+GLOBAL_USER_RUSTFLAGS += -C lto=thin
+GLOBAL_KERNEL_RUSTFLAGS += -C linker-plugin-lto -Zsplit-lto-unit
+else
+GLOBAL_SHARED_RUSTFLAGS += -C lto=thin
+endif
+
+# Decide on the branch protection scheme.
+# Must mirror the MODULE_COMPILEFLAGS set in make/module.mk. We don't set
+# MODULE_RUSTFLAGS there since the lk-crates.a wrapper obj, which does not
+# use module.mk, needs the same flags.
+ifeq (true,$(call TOBOOL,$(KERNEL_BTI_ENABLED)))
+ifeq (true,$(call TOBOOL,$(KERNEL_PAC_ENABLED)))
+GLOBAL_KERNEL_RUSTFLAGS += -Z branch-protection=bti,pac-ret
+else
+GLOBAL_KERNEL_RUSTFLAGS += -Z branch-protection=bti
+endif
+else # !KERNEL_BTI_ENABLED
+ifeq (true,$(call TOBOOL,$(KERNEL_PAC_ENABLED)))
+GLOBAL_KERNEL_RUSTFLAGS += -Z branch-protection=pac-ret
+endif
+endif
+
 ifneq ($(GLOBAL_COMPILEFLAGS),)
 $(error Setting GLOBAL_COMPILEFLAGS directly from project or platform makefiles is no longer supported. Please use either GLOBAL_SHARED_COMPILEFLAGS or GLOBAL_KERNEL_COMPILEFLAGS.)
 endif
@@ -280,6 +317,7 @@ GLOBAL_DEFINES += \
 GLOBAL_DEFINES += \
 	LK_DEBUGLEVEL=$(DEBUG) \
 	LK_LOGLEVEL=$(LOG_LEVEL_KERNEL) \
+	LK_LOGLEVEL_RUST=$(LOG_LEVEL_KERNEL_RUST) \
 	TLOG_LVL_DEFAULT=$$(($(LOG_LEVEL_USER)+2)) \
 
 # add some automatic rust configuration flags
diff --git a/lib/rust_support/bindings.h b/lib/rust_support/bindings.h
index 98b51bcd..a6be22ff 100644
--- a/lib/rust_support/bindings.h
+++ b/lib/rust_support/bindings.h
@@ -12,3 +12,4 @@
 #include <streams.h> /* stubs for stdin, stdout, stderr */
 
 #include "error.h"
+#include "config.h" /* for LK_LOGLEVEL_RUST */
diff --git a/lib/rust_support/err.rs b/lib/rust_support/err.rs
index 40d8378a..a99a4e0e 100644
--- a/lib/rust_support/err.rs
+++ b/lib/rust_support/err.rs
@@ -66,52 +66,52 @@ impl From<Error> for i32 {
 impl fmt::Display for Error {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         let code = self.0;
-        let msg = match self {
-            &Self::NO_ERROR => "no error",
-            &Self::ERR_GENERIC => "generic error",
-            &Self::ERR_NOT_FOUND => "not ready",
-            &Self::ERR_NO_MSG => "no message",
-            &Self::ERR_NO_MEMORY => "no memory",
-            &Self::ERR_ALREADY_STARTED => "already started",
-            &Self::ERR_NOT_VALID => "not valid",
-            &Self::ERR_INVALID_ARGS => "invalid arguments",
-            &Self::ERR_NOT_ENOUGH_BUFFER => "not enough buffer",
-            &Self::ERR_NOT_SUSPENDED => "not suspended",
-            &Self::ERR_OBJECT_DESTROYED => "object destroyed",
-            &Self::ERR_NOT_BLOCKED => "not blocked",
-            &Self::ERR_TIMED_OUT => "timed out",
-            &Self::ERR_ALREADY_EXISTS => "already exists",
-            &Self::ERR_CHANNEL_CLOSED => "channel closed",
-            &Self::ERR_OFFLINE => "offline",
-            &Self::ERR_NOT_ALLOWED => "not allowed",
-            &Self::ERR_BAD_PATH => "bad path",
-            &Self::ERR_ALREADY_MOUNTED => "already mounted",
-            &Self::ERR_IO => "input/output error",
-            &Self::ERR_NOT_DIR => "not a directory",
-            &Self::ERR_NOT_FILE => "not a file",
-            &Self::ERR_RECURSE_TOO_DEEP => "recursion too deep",
-            &Self::ERR_NOT_SUPPORTED => "not supported",
-            &Self::ERR_TOO_BIG => "too big",
-            &Self::ERR_CANCELLED => "cancelled",
-            &Self::ERR_NOT_IMPLEMENTED => "not implemented",
-            &Self::ERR_CHECKSUM_FAIL => "checksum failure",
-            &Self::ERR_CRC_FAIL => "CRC failure",
-            &Self::ERR_CMD_UNKNOWN => "command unknown",
-            &Self::ERR_BAD_STATE => "bad state",
-            &Self::ERR_BAD_LEN => "bad length",
-            &Self::ERR_BUSY => "busy",
-            &Self::ERR_THREAD_DETACHED => "thread detached",
-            &Self::ERR_I2C_NACK => "I2C negative acknowledgement",
-            &Self::ERR_ALREADY_EXPIRED => "already expired",
-            &Self::ERR_OUT_OF_RANGE => "out of range",
-            &Self::ERR_NOT_CONFIGURED => "not configured",
-            &Self::ERR_NOT_MOUNTED => "not mounted",
-            &Self::ERR_FAULT => "fault",
-            &Self::ERR_NO_RESOURCES => "no resources",
-            &Self::ERR_BAD_HANDLE => "bad handle",
-            &Self::ERR_ACCESS_DENIED => "access denied",
-            &Self::ERR_PARTIAL_WRITE => "partial write",
-            &Self::ERR_USER_BASE => panic!("attempt to display invalid error code"),
+        let msg = match *self {
+            Self::NO_ERROR => "no error",
+            Self::ERR_GENERIC => "generic error",
+            Self::ERR_NOT_FOUND => "not ready",
+            Self::ERR_NO_MSG => "no message",
+            Self::ERR_NO_MEMORY => "no memory",
+            Self::ERR_ALREADY_STARTED => "already started",
+            Self::ERR_NOT_VALID => "not valid",
+            Self::ERR_INVALID_ARGS => "invalid arguments",
+            Self::ERR_NOT_ENOUGH_BUFFER => "not enough buffer",
+            Self::ERR_NOT_SUSPENDED => "not suspended",
+            Self::ERR_OBJECT_DESTROYED => "object destroyed",
+            Self::ERR_NOT_BLOCKED => "not blocked",
+            Self::ERR_TIMED_OUT => "timed out",
+            Self::ERR_ALREADY_EXISTS => "already exists",
+            Self::ERR_CHANNEL_CLOSED => "channel closed",
+            Self::ERR_OFFLINE => "offline",
+            Self::ERR_NOT_ALLOWED => "not allowed",
+            Self::ERR_BAD_PATH => "bad path",
+            Self::ERR_ALREADY_MOUNTED => "already mounted",
+            Self::ERR_IO => "input/output error",
+            Self::ERR_NOT_DIR => "not a directory",
+            Self::ERR_NOT_FILE => "not a file",
+            Self::ERR_RECURSE_TOO_DEEP => "recursion too deep",
+            Self::ERR_NOT_SUPPORTED => "not supported",
+            Self::ERR_TOO_BIG => "too big",
+            Self::ERR_CANCELLED => "cancelled",
+            Self::ERR_NOT_IMPLEMENTED => "not implemented",
+            Self::ERR_CHECKSUM_FAIL => "checksum failure",
+            Self::ERR_CRC_FAIL => "CRC failure",
+            Self::ERR_CMD_UNKNOWN => "command unknown",
+            Self::ERR_BAD_STATE => "bad state",
+            Self::ERR_BAD_LEN => "bad length",
+            Self::ERR_BUSY => "busy",
+            Self::ERR_THREAD_DETACHED => "thread detached",
+            Self::ERR_I2C_NACK => "I2C negative acknowledgement",
+            Self::ERR_ALREADY_EXPIRED => "already expired",
+            Self::ERR_OUT_OF_RANGE => "out of range",
+            Self::ERR_NOT_CONFIGURED => "not configured",
+            Self::ERR_NOT_MOUNTED => "not mounted",
+            Self::ERR_FAULT => "fault",
+            Self::ERR_NO_RESOURCES => "no resources",
+            Self::ERR_BAD_HANDLE => "bad handle",
+            Self::ERR_ACCESS_DENIED => "access denied",
+            Self::ERR_PARTIAL_WRITE => "partial write",
+            Self::ERR_USER_BASE => panic!("attempt to display invalid error code"),
             _ => unimplemented!("don't know how to display {self:?}"),
         };
         write!(f, "{msg} ({code})")
diff --git a/lib/rust_support/handle_set.rs b/lib/rust_support/handle_set.rs
index 3166616a..e7b900d1 100644
--- a/lib/rust_support/handle_set.rs
+++ b/lib/rust_support/handle_set.rs
@@ -46,6 +46,7 @@ fn duration_as_ms(dur: Duration) -> Result<u32, Error> {
     }
 }
 
+#[allow(clippy::new_without_default)]
 impl HandleSet {
     pub fn new() -> Self {
         // Safety: `handle_set_create` places no preconditions on callers.
diff --git a/lib/rust_support/init.rs b/lib/rust_support/init.rs
index 809ea401..8ad104e9 100644
--- a/lib/rust_support/init.rs
+++ b/lib/rust_support/init.rs
@@ -53,7 +53,7 @@ impl lk_init_struct {
         hook: unsafe extern "C" fn(uint),
         name: *const c_char,
     ) -> Self {
-        lk_init_struct { level: level.0, flags: flags.0, hook: Option::Some(hook), name: name }
+        lk_init_struct { level: level.0, flags: flags.0, hook: Option::Some(hook), name }
     }
 }
 
diff --git a/lib/rust_support/ipc.rs b/lib/rust_support/ipc.rs
index d18f1ae8..9e74e15e 100644
--- a/lib/rust_support/ipc.rs
+++ b/lib/rust_support/ipc.rs
@@ -37,12 +37,6 @@ pub use crate::sys::zero_uuid;
 pub use crate::sys::IPC_CONNECT_WAIT_FOR_PORT;
 pub use crate::sys::IPC_PORT_PATH_MAX;
 
-impl Default for ipc_msg_info {
-    fn default() -> Self {
-        Self { id: 0, len: 0, num_handles: 0 }
-    }
-}
-
 impl Default for ipc_msg_kern {
     fn default() -> Self {
         Self { iov: null_mut(), num_iov: 0, handles: null_mut(), num_handles: 0 }
diff --git a/lib/rust_support/lib.rs b/lib/rust_support/lib.rs
index ffa70b5d..d4d580d8 100644
--- a/lib/rust_support/lib.rs
+++ b/lib/rust_support/lib.rs
@@ -34,6 +34,7 @@ use core::ffi::CStr;
 use core::panic::PanicInfo;
 
 mod sys {
+    #![allow(clippy::upper_case_acronyms)]
     #![allow(unused)]
     #![allow(non_camel_case_types)]
     #![allow(non_upper_case_globals)]
@@ -47,6 +48,7 @@ pub mod handle_set;
 pub mod init;
 pub mod ipc;
 pub mod log;
+pub mod macros;
 pub mod mmu;
 pub mod sync;
 pub mod thread;
diff --git a/lib/rust_support/log.rs b/lib/rust_support/log.rs
index 264d45bf..74d21ea7 100644
--- a/lib/rust_support/log.rs
+++ b/lib/rust_support/log.rs
@@ -34,6 +34,7 @@ use crate::LK_INIT_HOOK;
 use crate::sys::fflush;
 use crate::sys::fputs;
 use crate::sys::lk_stderr;
+use crate::sys::LK_LOGLEVEL_RUST;
 
 static TRUSTY_LOGGER: TrustyKernelLogger = TrustyKernelLogger;
 
@@ -62,10 +63,32 @@ impl Log for TrustyKernelLogger {
     }
 }
 
+/// Initialize logging for Rust in the kernel
+///
+/// By default, only warnings and errors are logged (even in debug builds).
+///
+/// The log level (`LK_LOGLEVEL_RUST`) is controlled by these make variables:
+/// - `LOG_LEVEL_KERNEL_RUST` if set,
+/// - `LOG_LEVEL_KERNEL` if set, and
+/// - `DEBUG` otherwise.
+///
+/// Values below (above) expected values sets the log level to off (trace).
 extern "C" fn kernel_log_init_func(_level: c_uint) {
     log::set_logger(&TRUSTY_LOGGER).unwrap();
-    // TODO: should be set based on LK_DEBUGLEVEL
-    log::set_max_level(LevelFilter::Trace);
+    // Level or LevelFilter cannot be created directly from integers
+    // https://github.com/rust-lang/log/issues/460
+    //
+    // bindgen emits `LK_LOGLEVEL_RUST` as `u32` when the value is
+    // a positive integer and omits it otherwise thus causing the
+    // build to fail.
+    log::set_max_level(match LK_LOGLEVEL_RUST {
+        0 => LevelFilter::Off,
+        1 => LevelFilter::Error,
+        2 => LevelFilter::Warn, // the default for Trusty
+        3 => LevelFilter::Info,
+        4 => LevelFilter::Debug,
+        _ => LevelFilter::Trace, // enable trace! at 5+
+    });
 }
 
 LK_INIT_HOOK!(kernel_log_init, kernel_log_init_func, lk_init_level::LK_INIT_LEVEL_HEAP);
diff --git a/lib/rust_support/macros.rs b/lib/rust_support/macros.rs
new file mode 100644
index 00000000..e043b587
--- /dev/null
+++ b/lib/rust_support/macros.rs
@@ -0,0 +1,77 @@
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
+/// Helper macro for container_of and container_of_mut. Exported so it can be
+/// used by those macros and not meant to be used directly.
+#[macro_export]
+macro_rules! container_of_const_or_mut {
+    ($ptr:ident, $T:ty, $m:ident, $const_or_mut:ident) => {{
+        // SAFETY: The caller must ensure that $ptr is a pointer to the $m
+        // field in an object of type $T. This means that $ptr came from
+        // addr_of!((*original_ptr).$m) so subtracting the offset of $m from
+        // $ptr will restore the original pointer.
+        let original_ptr = (($ptr).byte_sub(core::mem::offset_of!($T, $m)) as *$const_or_mut $T);
+
+        // Check that type of $ptr matches type of $T.$m. This detects a
+        // subclass of bugs at compile time where the wrong field or pointer
+        // is passed and two types does not match.
+        //
+        // SAFETY: This should not generate any code.
+        let _always_true = core::ptr::addr_of!((*original_ptr).$m) == $ptr;
+
+        original_ptr
+    }};
+}
+
+/// Get the pointer to a struct from a pointer to an embedded field.
+/// Matches the C containerof define in include/shared/lk/macros.h.
+/// Const version.
+#[macro_export]
+macro_rules! container_of {
+    ($ptr:ident, $T:ty, $m:ident) => {
+        $crate::container_of_const_or_mut!($ptr, $T, $m, const)
+    };
+}
+
+/// Get the pointer to a struct from a pointer to an embedded field.
+/// Matches the C containerof define in include/shared/lk/macros.h.
+/// Mutable version.
+///
+/// To convert a pointer received by C code to a reference to a wrapping
+/// rust struct a helper function could be used like so:
+/// struct A {}
+/// struct B {
+///     a: A,
+/// }
+/// /// # SAFETY
+/// ///
+/// /// ptr_a must point to the a field in a B struct
+/// unsafe fn ptr_a_to_ref_b<'a>(ptr_a: *mut A) -> &'a mut B {
+///     unsafe { &mut *container_of_mut!(ptr_a, B, a) }
+/// }
+#[macro_export]
+macro_rules! container_of_mut {
+    ($ptr:ident, $T:ty, $m:ident) => {
+        $crate::container_of_const_or_mut!($ptr, $T, $m, mut)
+    };
+}
diff --git a/lib/rust_support/rules.mk b/lib/rust_support/rules.mk
index 49d97737..56ad372b 100644
--- a/lib/rust_support/rules.mk
+++ b/lib/rust_support/rules.mk
@@ -34,9 +34,9 @@ MODULE_SRCS := \
 MODULE_ADD_IMPLICIT_DEPS := false
 
 MODULE_DEPS := \
-	external/rust/crates/num-derive \
-	external/rust/crates/num-traits \
-	external/rust/crates/log \
+	$(call FIND_CRATE,num-derive) \
+	$(call FIND_CRATE,num-traits) \
+	$(call FIND_CRATE,log) \
 	trusty/user/base/lib/liballoc-rust \
 	trusty/user/base/lib/libcompiler_builtins-rust \
 	trusty/user/base/lib/libcore-rust \
@@ -93,6 +93,7 @@ MODULE_BINDGEN_ALLOW_VARS := \
 	IPC_CONNECT_WAIT_FOR_PORT \
 	IPC_HANDLE_POLL_.* \
 	IPC_PORT_PATH_MAX \
+	LK_LOGLEVEL_RUST \
 	NUM_PRIORITIES \
 	PAGE_SIZE \
 	PAGE_SIZE_SHIFT \
@@ -105,7 +106,19 @@ MODULE_BINDGEN_FLAGS := \
 	--no-prepend-enum-name \
 	--with-derive-custom Error=FromPrimitive \
 	--with-derive-custom handle_waiter=Default \
+	--with-derive-custom ipc_msg_info=Default \
 
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
+MODULE_RUSTFLAGS += \
+	-A clippy::disallowed_names \
+	-A clippy::type-complexity \
+	-A clippy::unnecessary_fallible_conversions \
+	-A clippy::unnecessary-wraps \
+	-A clippy::unusual-byte-groupings \
+	-A clippy::upper-case-acronyms \
+	-D clippy::undocumented_unsafe_blocks \
+
+MODULE_RUST_USE_CLIPPY := true
+
 include make/module.mk
diff --git a/lib/rust_support/sync.rs b/lib/rust_support/sync.rs
index 06fc2796..0db5d515 100644
--- a/lib/rust_support/sync.rs
+++ b/lib/rust_support/sync.rs
@@ -136,7 +136,7 @@ impl<T: ?Sized> Mutex<T> {
         // SAFETY: `mutex_acquire` is thread safe and it was `mutex_init`ialized.
         let status = unsafe { mutex_acquire(self.mutex.get_raw()) };
         assert_eq!(Error::from_lk(status), Ok(()));
-        MutexGuard { lock: &self }
+        MutexGuard { lock: self }
     }
 }
 
diff --git a/lib/rust_support/vmm.rs b/lib/rust_support/vmm.rs
index 68d924df..56147572 100644
--- a/lib/rust_support/vmm.rs
+++ b/lib/rust_support/vmm.rs
@@ -46,6 +46,7 @@ pub fn vmm_get_kernel_aspace() -> *mut vmm_aspace_t {
 /// # Safety
 ///
 /// Same as [`vmm_alloc_physical_etc`].
+#[allow(clippy::too_many_arguments)]
 #[inline]
 pub unsafe fn vmm_alloc_physical(
     aspace: *mut vmm_aspace_t,
diff --git a/make/macros.mk b/make/macros.mk
index 83fbdbe6..3d03da96 100644
--- a/make/macros.mk
+++ b/make/macros.mk
@@ -16,7 +16,7 @@ FIND_EXTERNAL = $(if $(wildcard external/trusty/$1),external/trusty/$1,external/
 
 # try to find a Rust crate at external/rust/crates/$CRATE and fall back to
 # trusty/user/base/host/$CRATE and then trusty/user/base/lib/$CRATE-rust
-FIND_CRATE = $(dir $(firstword $(wildcard external/rust/android-crates-io/crates/$1/rules.mk external/rust/crates/$1/rules.mk trusty/user/base/host/$1/rules.mk trusty/user/base/host/$1-rust/rules.mk)))
+FIND_CRATE = $(patsubst %/,%,$(dir $(firstword $(wildcard external/rust/android-crates-io/extra_versions/crates/$1/rules.mk external/rust/android-crates-io/crates/$1/rules.mk external/rust/crates/$1/rules.mk trusty/user/base/host/$1/rules.mk trusty/user/base/host/$1-rust/rules.mk))))
 
 # checks if module with a given path exists
 FIND_MODULE = $(wildcard $1/rules.mk)$(wildcard $(addsuffix /$1/rules.mk,$(.INCLUDE_DIRS)))
diff --git a/make/module.mk b/make/module.mk
index 20157372..80d4b21a 100644
--- a/make/module.mk
+++ b/make/module.mk
@@ -116,8 +116,14 @@ ifeq (true,$(call TOBOOL,$(MODULE_CFI_ENABLED)))
 MODULE_COMPILEFLAGS += \
 	-fsanitize-blacklist=trusty/kernel/lib/ubsan/exemptlist \
 	-fsanitize=cfi \
+	-fsanitize-cfi-icall-experimental-normalize-integers \
 	-DCFI_ENABLED
 
+ifeq (true,$(call TOBOOL,$(ARCH_$(ARCH)_SUPPORTS_RUST_CFI)))
+# CFI rust <-> C cfi
+MODULE_RUSTFLAGS += -Zsanitizer=cfi -Zsanitizer-cfi-normalize-integers
+endif
+
 MODULES += trusty/kernel/lib/ubsan
 
 ifeq (true,$(call TOBOOL,$(CFI_DIAGNOSTICS)))
@@ -252,10 +258,14 @@ MODULE_ALL_DEPS += \
 
 # rust_support depends on some external crates. We cannot
 # add it as an implicit dependency to any of them because
-# that would create a circular dependency.
+# that would create a circular dependency. External crates
+# are either under external/rust/crates or in the monorepo
+# external/rust/android-crates-io/crates.
 ifeq ($(filter external/rust/crates/%,$(MODULE)),)
+ifeq ($(filter external/rust/android-crates-io/crates/%,$(MODULE)),)
 MODULE_ALL_DEPS += $(LKROOT)/lib/rust_support
 endif
+endif
 
 endif
 
@@ -358,13 +368,13 @@ $(MODULE_RSOBJS): $(MODULE_RSSRC) $(MODULE_SRCDEPS) $(MODULE_EXTRA_OBJECTS) $(MO
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling rust module,$<)
 ifeq ($(call TOBOOL,$(MODULE_RUST_USE_CLIPPY)),true)
-	$(NOECHO) set -e ; \
+	+$(NOECHO) set -e ; \
 		TEMP_CLIPPY_DIR=$$(mktemp -d) ;\
 		mkdir -p $(dir $$TEMP_CLIPPY_DIR/$@) ;\
 		$(MODULE_RUST_ENV) $(CLIPPY_DRIVER) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< -o $$TEMP_CLIPPY_DIR/$@ ;\
 		rm -rf $$TEMP_CLIPPY_DIR
 endif
-	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< --emit "dep-info=$@.d" -o $@
+	+$(NOECHO)$(MODULE_RUST_ENV) $(RUSTC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< --emit "dep-info=$@.d" -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling rust module,$<)
 
 ifneq ($(call TOBOOL,$(MODULE_SKIP_DOCS)),true)
@@ -376,7 +386,7 @@ ifneq ($(call TOBOOL,$(MODULE_SKIP_DOCS)),true)
 $(MODULE_RUSTDOC_OBJECT): $(MODULE_RSSRC) | $(MODULE_RSOBJS)
 	@$(MKDIR)
 	@$(call ECHO,rustdoc,generating documentation,for $(MODULE_CRATE_NAME))
-	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTDOC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS_PRELINK) $(MODULE_RUSTDOCFLAGS) -L $(TRUSTY_LIBRARY_BUILDDIR) --out-dir $(MODULE_RUSTDOC_OUT_DIR) $<
+	+$(NOECHO)$(MODULE_RUST_ENV) $(RUSTDOC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS_PRELINK) $(MODULE_RUSTDOCFLAGS) -L $(TRUSTY_LIBRARY_BUILDDIR) --out-dir $(MODULE_RUSTDOC_OUT_DIR) $<
 	@touch $@
 	@$(call ECHO_DONE_SILENT,rustdoc,generating documentation,for $(MODULE_CRATE_NAME))
 
diff --git a/make/rust-toplevel.mk b/make/rust-toplevel.mk
index f231bad1..5fb68d56 100644
--- a/make/rust-toplevel.mk
+++ b/make/rust-toplevel.mk
@@ -55,7 +55,7 @@ $(RUST_WRAPPER_OBJ): WRAPPER_RUSTFLAGS := $(WRAPPER_RUSTFLAGS)
 $(RUST_WRAPPER_OBJ): ARCH_RUSTFLAGS := $(ARCH_$(ARCH)_RUSTFLAGS)
 
 $(RUST_WRAPPER_OBJ): $(ALLMODULE_RLIBS) $(RUST_WRAPPER)
-	$(RUSTC) $(GLOBAL_KERNEL_RUSTFLAGS) $(GLOBAL_SHARED_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(WRAPPER_RUSTFLAGS) -o $@ $(RUST_WRAPPER)
+	+$(NOECHO)$(RUSTC) $(GLOBAL_KERNEL_RUSTFLAGS) $(GLOBAL_SHARED_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(WRAPPER_RUSTFLAGS) -o $@ $(RUST_WRAPPER)
 
 # if there were no rust crates, don't build the .a
 ifneq ($(ALLMODULE_CRATE_STEMS),)
```

