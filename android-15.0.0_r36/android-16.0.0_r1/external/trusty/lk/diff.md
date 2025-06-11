```diff
diff --git a/arch/arm/toolchain.mk b/arch/arm/toolchain.mk
index 2a7bf761..25aa5c95 100644
--- a/arch/arm/toolchain.mk
+++ b/arch/arm/toolchain.mk
@@ -52,6 +52,8 @@ ARCH_arm_SUPPORTS_RUST := true
 ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))
 ARCH_arm_RUSTFLAGS := --target=armv7-unknown-trusty
 else
-ARCH_arm_RUSTFLAGS := --target=$(LOCAL_DIR)/armv7-unknown-trusty-kernel.json
+# Save the path to custom toolchain so Rust targets targets can depend on it
+ARCH_arm_RUST_TARGET := $(LOCAL_DIR)/armv7-unknown-trusty-kernel.json
+ARCH_arm_RUSTFLAGS := --target=$(ARCH_arm_RUST_TARGET)
 ARCH_arm_SUPPORTS_RUST_CFI := true
 endif
diff --git a/arch/arm64/aarch64-unknown-trusty-kernel.json b/arch/arm64/aarch64-unknown-trusty-kernel.json
index 3d56fde5..9fa10799 100644
--- a/arch/arm64/aarch64-unknown-trusty-kernel.json
+++ b/arch/arm64/aarch64-unknown-trusty-kernel.json
@@ -2,7 +2,7 @@
     "arch": "aarch64",
     "crt-objects-fallback": "musl",
     "crt-static-default": false,
-    "data-layout": "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128",
+    "data-layout": "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32",
     "dynamic-linking": false,
     "env": "musl",
     "features": "-neon,-fp-armv8,+reserve-x18",
diff --git a/arch/arm64/fpu.c b/arch/arm64/fpu.c
index 5af03cad..1e436449 100644
--- a/arch/arm64/fpu.c
+++ b/arch/arm64/fpu.c
@@ -55,7 +55,8 @@ bool arm64_fpu_load_fpstate(struct fpstate *fpstate, bool force)
 
 
     STATIC_ASSERT(sizeof(fpstate->regs) == 16 * 32);
-    __asm__ volatile("ldp     q0, q1, [%0, #(0 * 32)]\n"
+    __asm__ volatile(".arch_extension fp\n"
+                     "ldp     q0, q1, [%0, #(0 * 32)]\n"
                      "ldp     q2, q3, [%0, #(1 * 32)]\n"
                      "ldp     q4, q5, [%0, #(2 * 32)]\n"
                      "ldp     q6, q7, [%0, #(3 * 32)]\n"
@@ -73,6 +74,7 @@ bool arm64_fpu_load_fpstate(struct fpstate *fpstate, bool force)
                      "ldp     q30, q31, [%0, #(15 * 32)]\n"
                      "msr     fpcr, %1\n"
                      "msr     fpsr, %2\n"
+                     ".arch_extension nofp\n"
                      :: "r"(fpstate),
                      "r"((uint64_t)fpstate->fpcr),
                      "r"((uint64_t)fpstate->fpsr));
@@ -92,7 +94,8 @@ void arm64_fpu_save_fpstate(struct fpstate *fpstate)
 {
     uint64_t fpcr, fpsr;
 
-    __asm__ volatile("stp     q0, q1, [%2, #(0 * 32)]\n"
+    __asm__ volatile(".arch_extension fp\n"
+                     "stp     q0, q1, [%2, #(0 * 32)]\n"
                      "stp     q2, q3, [%2, #(1 * 32)]\n"
                      "stp     q4, q5, [%2, #(2 * 32)]\n"
                      "stp     q6, q7, [%2, #(3 * 32)]\n"
@@ -110,6 +113,7 @@ void arm64_fpu_save_fpstate(struct fpstate *fpstate)
                      "stp     q30, q31, [%2, #(15 * 32)]\n"
                      "mrs %0, fpcr\n"
                      "mrs %1, fpsr\n"
+                     ".arch_extension nofp\n"
                      : "=r"(fpcr), "=r"(fpsr)
                      : "r"(fpstate));
 
diff --git a/arch/arm64/include/arch/arch_ops.h b/arch/arm64/include/arch/arch_ops.h
index 5048d6df..2a4c18d9 100644
--- a/arch/arm64/include/arch/arch_ops.h
+++ b/arch/arm64/include/arch/arch_ops.h
@@ -296,7 +296,7 @@ static inline uint arch_curr_cpu_num(void)
  */
 static inline uintptr_t arch_extract_return_addr(uintptr_t lr) {
     if (arch_pac_address_supported()) {
-        __asm__(".arch_extension pauth\n"
+        __asm__ volatile(".arch_extension pauth\n"
                 "\txpaci %0" : "+r" (lr));
     }
     return lr;
diff --git a/arch/arm64/mp.c b/arch/arm64/mp.c
index e3584c85..28a3ec45 100644
--- a/arch/arm64/mp.c
+++ b/arch/arm64/mp.c
@@ -33,6 +33,8 @@
 #elif PLATFORM_BCM28XX
 /* bcm28xx has a weird custom interrupt controller for MP */
 extern void bcm28xx_send_ipi(uint irq, uint cpu_mask);
+#elif WITH_DEV_INTERRUPT_HAFNIUM
+#include <dev/interrupt/hafnium.h>
 #else
 #error need other implementation of interrupt controller that can ipi
 #endif
diff --git a/arch/arm64/start.S b/arch/arm64/start.S
index f7dec259..ddc86613 100644
--- a/arch/arm64/start.S
+++ b/arch/arm64/start.S
@@ -57,6 +57,9 @@ _start:
     bic     tmp, tmp, #(1<<1)  /* Disable Alignment Checking for EL1 EL0 */
     msr     sctlr_el1, tmp
 
+    /* Make sure SP1 is being used */
+    msr     spsel, #1
+
     /* set up the mmu according to mmu_initial_mappings */
 
     /* load the base of the translation table and clear the table */
@@ -373,7 +376,6 @@ _start:
     cbnz    cpuid, .Lsecondary_boot
 #endif
 #endif /* WITH_KERNEL_VM */
-
     adrl    tmp, sp_el1_bufs
     mov     sp, tmp
 
diff --git a/arch/arm64/system-onesegment.ld b/arch/arm64/system-onesegment.ld
index 91505eff..1baa1f6f 100644
--- a/arch/arm64/system-onesegment.ld
+++ b/arch/arm64/system-onesegment.ld
@@ -13,6 +13,8 @@ SECTIONS
      * compiler-rt that we don't want and that breaks our build. Until we compile
      * our own compiler-rt and either provide getauxval and enable CFI, or remove
      * this function, we can remove it during linking here
+     *
+     * LLVM 19 added init_aarch64_has_sme
      */
     /DISCARD/ : {
         *libclang_rt.builtins-aarch64-android.a:cpu_model.c.o(
@@ -26,6 +28,11 @@ SECTIONS
             .text.init_have_lse_atomics
             .init_array*
         )
+
+        *libclang_rt.builtins-aarch64-android.a:sme-abi-init.c.o(
+            .text.init_aarch64_has_sme
+            .init_array*
+        )
     }
 
     /* text/read-only data */
diff --git a/arch/arm64/toolchain.mk b/arch/arm64/toolchain.mk
index 86821534..893b816b 100644
--- a/arch/arm64/toolchain.mk
+++ b/arch/arm64/toolchain.mk
@@ -33,6 +33,8 @@ ARCH_arm64_SUPPORTS_RUST := true
 ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))
 ARCH_arm64_RUSTFLAGS := --target=aarch64-unknown-trusty
 else
-ARCH_arm64_RUSTFLAGS := --target=$(LOCAL_DIR)/aarch64-unknown-trusty-kernel.json
+# Save the path to custom toolchain so Rust targets targets can depend on it
+ARCH_arm64_RUST_TARGET := $(LOCAL_DIR)/aarch64-unknown-trusty-kernel.json
+ARCH_arm64_RUSTFLAGS := --target=$(ARCH_arm64_RUST_TARGET)
 ARCH_arm64_SUPPORTS_RUST_CFI := true
 endif
diff --git a/arch/x86/64/kernel.ld b/arch/x86/64/kernel.ld
index 302c0ff9..2188c45f 100644
--- a/arch/x86/64/kernel.ld
+++ b/arch/x86/64/kernel.ld
@@ -29,6 +29,18 @@ SECTIONS
 {
     . = %KERNEL_BASE% + %KERNEL_LOAD_OFFSET%;
 
+    /*
+     * Discard __cpu_indicator_init since we don't need it, and it touches
+     * xmm registers in clang-r530567 which we don't allow in the kernel
+     */
+    /DISCARD/ : {
+        *libclang_rt.builtins-x86_64-android.a:x86.c.o(
+            .text.__cpu_indicator_init
+            .rodata.__cpu_indicator_init
+            .init_array*
+        )
+    }
+
     .text : AT(%MEMBASE% + %KERNEL_LOAD_OFFSET%) {
         __code_start = .;
         KEEP(*(.text.boot))
diff --git a/arch/x86/64/start.S b/arch/x86/64/start.S
index 55725bbd..46fe7ee9 100644
--- a/arch/x86/64/start.S
+++ b/arch/x86/64/start.S
@@ -333,6 +333,11 @@
 
 .global _start
 _start:
+    /* save boot args first, in unused registers */
+    movq %rdi, %r12
+    movq %rsi, %r13
+    movq %rdx, %r14
+    movq %rcx, %r15
 
     /* zero the bss section */
 bss_setup:
@@ -460,6 +465,12 @@ paging_setup:
     /* set up the idt */
     call setup_idt
 
+    /* restore boot args to lk_main arguments */
+    movq %r12, %rdi
+    movq %r13, %rsi
+    movq %r14, %rdx
+    movq %r15, %rcx
+
     /* call the main module */
     call lk_main
 
diff --git a/arch/x86/toolchain.mk b/arch/x86/toolchain.mk
index 97b53356..a4974f92 100644
--- a/arch/x86/toolchain.mk
+++ b/arch/x86/toolchain.mk
@@ -31,8 +31,10 @@ ARCH_x86_SUPPORTS_RUST := true
 ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))
 ARCH_x86_RUSTFLAGS := --target=x86_64-unknown-trusty
 else
+# Save the path to custom toolchain so Rust targets targets can depend on it
+ARCH_x86_RUST_TARGET := $(LOCAL_DIR)/x86_64-unknown-trusty-kernel.json
 # Use custom toolchain file that disables hardware floating point
-ARCH_x86_RUSTFLAGS := --target=$(LOCAL_DIR)/x86_64-unknown-trusty-kernel.json
+ARCH_x86_RUSTFLAGS := --target=$(ARCH_x86_RUST_TARGET)
 ARCH_x86_SUPPORTS_RUST_CFI := true
 endif
 
diff --git a/dev/interrupt/arm_gic/arm_gic.c b/dev/interrupt/arm_gic/arm_gic.c
index d9199a0d..7a4ca09e 100644
--- a/dev/interrupt/arm_gic/arm_gic.c
+++ b/dev/interrupt/arm_gic/arm_gic.c
@@ -20,6 +20,7 @@
  * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
+#include <arch/mp.h>
 #include <assert.h>
 #include <bits.h>
 #include <err.h>
@@ -30,6 +31,7 @@
 #include <reg.h>
 #include <kernel/thread.h>
 #include <kernel/debug.h>
+#include <kernel/mp.h>
 #include <kernel/vm.h>
 #include <lk/init.h>
 #include <lk/macros.h>
@@ -920,4 +922,14 @@ status_t sm_intc_fiq_enter(void)
     return fiq_enter_unexpected_irq(cpu);
 #endif
 }
+
+void sm_intc_raise_doorbell_irq(void)
+{
+    u_int cpu = arch_curr_cpu_num();
+#if ARM_GIC_USE_DOORBELL_NS_IRQ
+    raise_ns_doorbell_irq(cpu);
+#else
+    arch_mp_send_ipi(1U << cpu, MP_IPI_GENERIC);
+#endif
+}
 #endif
diff --git a/dev/interrupt/hafnium/include/dev/interrupt/hafnium.h b/dev/interrupt/hafnium/include/dev/interrupt/hafnium.h
new file mode 100644
index 00000000..52bb6eec
--- /dev/null
+++ b/dev/interrupt/hafnium/include/dev/interrupt/hafnium.h
@@ -0,0 +1,24 @@
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
+*/
+
+#pragma once
diff --git a/dev/interrupt/hafnium/interrupts.c b/dev/interrupt/hafnium/interrupts.c
new file mode 100644
index 00000000..afab46fb
--- /dev/null
+++ b/dev/interrupt/hafnium/interrupts.c
@@ -0,0 +1,95 @@
+/*
+ * Copyright (c) 2024 LK Trusty Authors. All Rights Reserved.
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
+#define LOCAL_TRACE 0
+
+#include <arch/ops.h>
+#include <err.h>
+#include <lib/sm.h>
+#include <lib/sm/sm_err.h>
+#include <lib/smc/smc.h>
+#include <lk/init.h>
+#include <lk/trace.h>
+#include <platform/interrupts.h>
+
+#if ARCH_ARM
+#define iframe arm_iframe
+#define IFRAME_PC(frame) ((frame)->pc)
+#elif ARCH_ARM64
+#define iframe arm64_iframe_short
+#define IFRAME_PC(frame) ((frame)->elr)
+#else
+#error "Unknown Trusty architecture for Hafnium"
+#endif
+
+enum handler_return platform_irq(struct iframe* frame)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+void platform_fiq(struct iframe* frame) {
+    panic("Got FIQ on Hafnium\n");
+}
+
+void register_int_handler(unsigned int vector, int_handler handler, void* arg)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+status_t mask_interrupt(unsigned int vector)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+status_t unmask_interrupt(unsigned int vector)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+long smc_intc_get_next_irq(struct smc32_args *args)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+status_t sm_intc_fiq_enter(void)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+enum handler_return sm_intc_enable_interrupts(void)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+void sm_intc_raise_doorbell_irq(void)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+static void hafnium_interrupts_init(uint level)
+{
+    PANIC_UNIMPLEMENTED;
+}
+
+LK_INIT_HOOK_FLAGS(hafnium_interrupts_init, hafnium_interrupts_init,
+                   LK_INIT_LEVEL_PLATFORM_EARLY, LK_INIT_FLAG_ALL_CPUS);
diff --git a/dev/interrupt/hafnium/rules.mk b/dev/interrupt/hafnium/rules.mk
new file mode 100644
index 00000000..28b822dc
--- /dev/null
+++ b/dev/interrupt/hafnium/rules.mk
@@ -0,0 +1,39 @@
+#
+# Copyright (c) 2024 LK Trusty Authors. All Rights Reserved.
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
+MODULE_SRCS += \
+	$(LOCAL_DIR)/interrupts.c \
+
+MODULE_INCLUDES += \
+	external/hafnium/inc/vmapi \
+	external/hafnium/src/arch/aarch64/inc \
+
+MODULE_DEPS += \
+	trusty/kernel/lib/sm \
+	trusty/kernel/lib/smc \
+
+include make/module.mk
diff --git a/dev/virtio/vsock-rust/rules.mk b/dev/virtio/vsock-rust/rules.mk
index f49e49a2..a60b1ac8 100644
--- a/dev/virtio/vsock-rust/rules.mk
+++ b/dev/virtio/vsock-rust/rules.mk
@@ -16,11 +16,19 @@ MODULE_LIBRARY_DEPS := \
 	$(call FIND_CRATE,num-integer) \
 	$(call FIND_CRATE,spin) \
 	$(call FIND_CRATE,static_assertions) \
-	$(call FIND_CRATE,virtio-drivers) \
+	$(call FIND_CRATE,virtio-drivers-and-devices) \
+	$(call FIND_CRATE,zerocopy) \
+	lib/libhypervisor \
 
 # `trusty-std` is for its `#[global_allocator]`.
 
-# hypervisor_backends is arm64-only for now
+
+# hypervisor_backends supports arm64 and x86-64 only for now
+ifeq ($(SUBARCH),x86-64)
+MODULE_LIBRARY_DEPS += \
+	packages/modules/Virtualization/libs/libhypervisor_backends \
+
+endif
 ifeq ($(ARCH),arm64)
 MODULE_LIBRARY_DEPS += \
 	packages/modules/Virtualization/libs/libhypervisor_backends \
@@ -36,6 +44,38 @@ MODULE_RUSTFLAGS += \
 	-A clippy::upper-case-acronyms \
 	-D clippy::undocumented_unsafe_blocks \
 
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_HW_CRYPTO_HAL)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="hwcrypto_hal"' \
+
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_USE_WIDEVINE_AIDL_COMM)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="widevine_aidl_comm"' \
+
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_GATEKEEPER)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="gatekeeper"' \
+
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_KEYMINT)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="keymint"' \
+
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="securestorage_hal"' \
+
+endif
+ifeq (true,$(call TOBOOL,$(TRUSTY_VM_INCLUDE_AUTHMGR)))
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="authmgr"' \
+
+endif
+
+
 MODULE_RUST_USE_CLIPPY := true
 
 include make/library.mk
diff --git a/dev/virtio/vsock-rust/src/bindings.rs b/dev/virtio/vsock-rust/src/bindings.rs
new file mode 100644
index 00000000..7587ed1c
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/bindings.rs
@@ -0,0 +1,1737 @@
+/*
+ * rustfmt::skip is an unstable attribute being phased out in the future. This
+ * is fine for now because we should soon switch to generating bindings from C
+ * headers instead of checking in the bindgen output.
+ *
+ * Wrapping rustfmt::skip in cfg_attr silences the deprecation warning
+ */
+#![cfg_attr(any(), rustfmt::skip)]
+/* automatically generated by rust-bindgen 0.69.5 */
+pub const VIRTIO_CONFIG_S_ACKNOWLEDGE: u32 = 1;
+pub const VIRTIO_CONFIG_S_DRIVER: u32 = 2;
+pub const VIRTIO_CONFIG_S_DRIVER_OK: u32 = 4;
+pub const VIRTIO_CONFIG_S_FEATURES_OK: u32 = 8;
+pub const VIRTIO_CONFIG_S_NEEDS_RESET: u32 = 64;
+pub const VIRTIO_CONFIG_S_FAILED: u32 = 128;
+pub const VIRTIO_TRANSPORT_F_START: u32 = 28;
+pub const VIRTIO_TRANSPORT_F_END: u32 = 42;
+pub const VIRTIO_F_NOTIFY_ON_EMPTY: u32 = 24;
+pub const VIRTIO_F_ANY_LAYOUT: u32 = 27;
+pub const VIRTIO_F_VERSION_1: u32 = 32;
+pub const VIRTIO_F_ACCESS_PLATFORM: u32 = 33;
+pub const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
+pub const VIRTIO_F_RING_PACKED: u32 = 34;
+pub const VIRTIO_F_IN_ORDER: u32 = 35;
+pub const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
+pub const VIRTIO_F_SR_IOV: u32 = 37;
+pub const VIRTIO_F_NOTIFICATION_DATA: u32 = 38;
+pub const VIRTIO_F_NOTIF_CONFIG_DATA: u32 = 39;
+pub const VIRTIO_F_RING_RESET: u32 = 40;
+pub const VIRTIO_F_ADMIN_VQ: u32 = 41;
+pub const VIRTIO_MSG_CONNECT: u32 = 1;
+pub const VIRTIO_MSG_DISCONNECT: u32 = 2;
+pub const VIRTIO_MSG_DEVICE_INFO: u32 = 3;
+pub const VIRTIO_MSG_GET_FEATURES: u32 = 4;
+pub const VIRTIO_MSG_SET_FEATURES: u32 = 5;
+pub const VIRTIO_MSG_GET_CONFIG: u32 = 6;
+pub const VIRTIO_MSG_SET_CONFIG: u32 = 7;
+pub const VIRTIO_MSG_GET_CONFIG_GEN: u32 = 8;
+pub const VIRTIO_MSG_GET_DEVICE_STATUS: u32 = 9;
+pub const VIRTIO_MSG_SET_DEVICE_STATUS: u32 = 10;
+pub const VIRTIO_MSG_GET_VQUEUE: u32 = 11;
+pub const VIRTIO_MSG_SET_VQUEUE: u32 = 12;
+pub const VIRTIO_MSG_RESET_VQUEUE: u32 = 13;
+pub const VIRTIO_MSG_EVENT_CONFIG: u32 = 16;
+pub const VIRTIO_MSG_EVENT_AVAIL: u32 = 17;
+pub const VIRTIO_MSG_EVENT_USED: u32 = 18;
+pub const VIRTIO_MSG_MAX: u32 = 18;
+pub const VIRTIO_MSG_MAX_SIZE: u32 = 40;
+pub const VIRTIO_MSG_TYPE_RESPONSE: u32 = 1;
+pub const VIRTIO_MSG_TYPE_VIRTIO: u32 = 0;
+pub const VIRTIO_MSG_TYPE_BUS: u32 = 2;
+pub const VIRTIO_MSG_FFA_ERROR: u32 = 0;
+pub const VIRTIO_MSG_FFA_ACTIVATE: u32 = 1;
+pub const VIRTIO_MSG_FFA_DEACTIVATE: u32 = 2;
+pub const VIRTIO_MSG_FFA_CONFIGURE: u32 = 3;
+pub const VIRTIO_MSG_FFA_AREA_SHARE: u32 = 4;
+pub const VIRTIO_MSG_FFA_AREA_UNSHARE: u32 = 5;
+pub const VIRTIO_MSG_FFA_VERSION_1_0: u32 = 1;
+pub const VIRTIO_MSG_FFA_FEATURE_INDIRECT_MSG_SUPP: u32 = 1;
+pub const VIRTIO_MSG_FFA_FEATURE_DIRECT_MSG_SUPP: u32 = 2;
+pub const VIRTIO_MSG_FFA_FEATURE_NUM_SHM: u32 = 65280;
+pub const VIRTIO_MSG_FFA_AREA_ID_OFFSET: u32 = 56;
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_device_info_resp {
+    pub device_version: u32,
+    pub device_id: u32,
+    pub vendor_id: u32,
+}
+#[test]
+fn bindgen_test_layout_get_device_info_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_device_info_resp> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_device_info_resp>(),
+        12usize,
+        concat!("Size of: ", stringify!(get_device_info_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_device_info_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_device_info_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_version) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_device_info_resp),
+            "::",
+            stringify!(device_version)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_id) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_device_info_resp),
+            "::",
+            stringify!(device_id)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).vendor_id) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_device_info_resp),
+            "::",
+            stringify!(vendor_id)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_features {
+    pub index: u32,
+}
+#[test]
+fn bindgen_test_layout_get_features() {
+    const UNINIT: ::core::mem::MaybeUninit<get_features> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_features>(),
+        4usize,
+        concat!("Size of: ", stringify!(get_features))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_features>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_features))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_features),
+            "::",
+            stringify!(index)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_features_resp {
+    pub index: u32,
+    pub features: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_get_features_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_features_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_features_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(get_features_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_features_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_features_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_features_resp),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_features_resp),
+            "::",
+            stringify!(features)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_features {
+    pub index: u32,
+    pub features: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_set_features() {
+    const UNINIT: ::core::mem::MaybeUninit<set_features> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_features>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_features))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_features>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_features))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_features),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_features),
+            "::",
+            stringify!(features)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_features_resp {
+    pub index: u32,
+    pub features: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_set_features_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<set_features_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_features_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_features_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_features_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_features_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_features_resp),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_features_resp),
+            "::",
+            stringify!(features)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_config {
+    pub offset: [u8; 3usize],
+    pub size: u8,
+}
+#[test]
+fn bindgen_test_layout_get_config() {
+    const UNINIT: ::core::mem::MaybeUninit<get_config> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_config>(),
+        4usize,
+        concat!("Size of: ", stringify!(get_config))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_config>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_config))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config),
+            "::",
+            stringify!(offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        3usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config),
+            "::",
+            stringify!(size)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_config_resp {
+    pub offset: [u8; 3usize],
+    pub size: u8,
+    pub data: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_get_config_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_config_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_config_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(get_config_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_config_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_config_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config_resp),
+            "::",
+            stringify!(offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        3usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config_resp),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).data) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config_resp),
+            "::",
+            stringify!(data)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_config {
+    pub offset: [u8; 3usize],
+    pub size: u8,
+    pub data: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_set_config() {
+    const UNINIT: ::core::mem::MaybeUninit<set_config> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_config>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_config))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_config>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_config))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config),
+            "::",
+            stringify!(offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        3usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).data) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config),
+            "::",
+            stringify!(data)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_config_resp {
+    pub offset: [u8; 3usize],
+    pub size: u8,
+    pub data: [u64; 4usize],
+}
+#[test]
+fn bindgen_test_layout_set_config_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<set_config_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_config_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_config_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_config_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_config_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config_resp),
+            "::",
+            stringify!(offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        3usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config_resp),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).data) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_config_resp),
+            "::",
+            stringify!(data)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_config_gen_resp {
+    pub generation: u32,
+}
+#[test]
+fn bindgen_test_layout_get_config_gen_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_config_gen_resp> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_config_gen_resp>(),
+        4usize,
+        concat!("Size of: ", stringify!(get_config_gen_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_config_gen_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_config_gen_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).generation) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_config_gen_resp),
+            "::",
+            stringify!(generation)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_device_status_resp {
+    pub status: u32,
+}
+#[test]
+fn bindgen_test_layout_get_device_status_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_device_status_resp> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_device_status_resp>(),
+        4usize,
+        concat!("Size of: ", stringify!(get_device_status_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_device_status_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_device_status_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).status) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_device_status_resp),
+            "::",
+            stringify!(status)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_device_status {
+    pub status: u32,
+}
+#[test]
+fn bindgen_test_layout_set_device_status() {
+    const UNINIT: ::core::mem::MaybeUninit<set_device_status> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_device_status>(),
+        4usize,
+        concat!("Size of: ", stringify!(set_device_status))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_device_status>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_device_status))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).status) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_device_status),
+            "::",
+            stringify!(status)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_vqueue {
+    pub index: u32,
+}
+#[test]
+fn bindgen_test_layout_get_vqueue() {
+    const UNINIT: ::core::mem::MaybeUninit<get_vqueue> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_vqueue>(),
+        4usize,
+        concat!("Size of: ", stringify!(get_vqueue))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_vqueue>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_vqueue))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue),
+            "::",
+            stringify!(index)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct get_vqueue_resp {
+    pub index: u32,
+    pub max_size: u32,
+    pub size: u32,
+    pub descriptor_addr: u64,
+    pub driver_addr: u64,
+    pub device_addr: u64,
+}
+#[test]
+fn bindgen_test_layout_get_vqueue_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<get_vqueue_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<get_vqueue_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(get_vqueue_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<get_vqueue_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(get_vqueue_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).max_size) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(max_size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).descriptor_addr) as usize - ptr as usize },
+        12usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(descriptor_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).driver_addr) as usize - ptr as usize },
+        20usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(driver_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_addr) as usize - ptr as usize },
+        28usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(get_vqueue_resp),
+            "::",
+            stringify!(device_addr)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_vqueue {
+    pub index: u32,
+    pub unused: u32,
+    pub size: u32,
+    pub descriptor_addr: u64,
+    pub driver_addr: u64,
+    pub device_addr: u64,
+}
+#[test]
+fn bindgen_test_layout_set_vqueue() {
+    const UNINIT: ::core::mem::MaybeUninit<set_vqueue> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_vqueue>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_vqueue))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_vqueue>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_vqueue))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).unused) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(unused)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).descriptor_addr) as usize - ptr as usize },
+        12usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(descriptor_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).driver_addr) as usize - ptr as usize },
+        20usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(driver_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_addr) as usize - ptr as usize },
+        28usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue),
+            "::",
+            stringify!(device_addr)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct set_vqueue_resp {
+    pub index: u32,
+    pub unused: u32,
+    pub size: u32,
+    pub descriptor_addr: u64,
+    pub driver_addr: u64,
+    pub device_addr: u64,
+}
+#[test]
+fn bindgen_test_layout_set_vqueue_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<set_vqueue_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<set_vqueue_resp>(),
+        36usize,
+        concat!("Size of: ", stringify!(set_vqueue_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<set_vqueue_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(set_vqueue_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).unused) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(unused)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).descriptor_addr) as usize - ptr as usize },
+        12usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(descriptor_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).driver_addr) as usize - ptr as usize },
+        20usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(driver_addr)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_addr) as usize - ptr as usize },
+        28usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(set_vqueue_resp),
+            "::",
+            stringify!(device_addr)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct reset_vqueue {
+    pub index: u32,
+}
+#[test]
+fn bindgen_test_layout_reset_vqueue() {
+    const UNINIT: ::core::mem::MaybeUninit<reset_vqueue> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<reset_vqueue>(),
+        4usize,
+        concat!("Size of: ", stringify!(reset_vqueue))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<reset_vqueue>(),
+        1usize,
+        concat!("Alignment of ", stringify!(reset_vqueue))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(reset_vqueue),
+            "::",
+            stringify!(index)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct event_config {
+    pub status: u32,
+    pub offset: [u8; 3usize],
+    pub size: u8,
+    pub value: [u32; 4usize],
+}
+#[test]
+fn bindgen_test_layout_event_config() {
+    const UNINIT: ::core::mem::MaybeUninit<event_config> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<event_config>(),
+        24usize,
+        concat!("Size of: ", stringify!(event_config))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<event_config>(),
+        1usize,
+        concat!("Alignment of ", stringify!(event_config))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).status) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_config),
+            "::",
+            stringify!(status)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_config),
+            "::",
+            stringify!(offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
+        7usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_config),
+            "::",
+            stringify!(size)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).value) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_config),
+            "::",
+            stringify!(value)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct event_avail {
+    pub index: u32,
+    pub next_offset: u32,
+    pub next_wrap: u32,
+}
+#[test]
+fn bindgen_test_layout_event_avail() {
+    const UNINIT: ::core::mem::MaybeUninit<event_avail> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<event_avail>(),
+        12usize,
+        concat!("Size of: ", stringify!(event_avail))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<event_avail>(),
+        1usize,
+        concat!("Alignment of ", stringify!(event_avail))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_avail),
+            "::",
+            stringify!(index)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).next_offset) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_avail),
+            "::",
+            stringify!(next_offset)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).next_wrap) as usize - ptr as usize },
+        8usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_avail),
+            "::",
+            stringify!(next_wrap)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct event_used {
+    pub index: u32,
+}
+#[test]
+fn bindgen_test_layout_event_used() {
+    const UNINIT: ::core::mem::MaybeUninit<event_used> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<event_used>(),
+        4usize,
+        concat!("Size of: ", stringify!(event_used))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<event_used>(),
+        1usize,
+        concat!("Alignment of ", stringify!(event_used))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).index) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(event_used),
+            "::",
+            stringify!(index)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct virtio_msg {
+    pub type_: u8,
+    pub id: u8,
+    pub dev_id: u16,
+    pub __bindgen_anon_1: virtio_msg__bindgen_ty_1,
+}
+#[repr(C)]
+#[derive(Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub union virtio_msg__bindgen_ty_1 {
+    pub payload_u8: [u8; 36usize],
+    pub get_device_info_resp: get_device_info_resp,
+    pub get_features: get_features,
+    pub get_features_resp: get_features_resp,
+    pub set_features: set_features,
+    pub set_features_resp: set_features_resp,
+    pub get_config: get_config,
+    pub get_config_resp: get_config_resp,
+    pub set_config: set_config,
+    pub set_config_resp: set_config_resp,
+    pub get_config_gen_resp: get_config_gen_resp,
+    pub get_device_status_resp: get_device_status_resp,
+    pub set_device_status: set_device_status,
+    pub get_vqueue: get_vqueue,
+    pub get_vqueue_resp: get_vqueue_resp,
+    pub set_vqueue: set_vqueue,
+    pub set_vqueue_resp: set_vqueue_resp,
+    pub reset_vqueue: reset_vqueue,
+    pub event_config: event_config,
+    pub event_avail: event_avail,
+    pub event_used: event_used,
+}
+#[test]
+fn bindgen_test_layout_virtio_msg__bindgen_ty_1() {
+    const UNINIT: ::core::mem::MaybeUninit<virtio_msg__bindgen_ty_1> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<virtio_msg__bindgen_ty_1>(),
+        36usize,
+        concat!("Size of: ", stringify!(virtio_msg__bindgen_ty_1))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<virtio_msg__bindgen_ty_1>(),
+        1usize,
+        concat!("Alignment of ", stringify!(virtio_msg__bindgen_ty_1))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).payload_u8) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(payload_u8)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_device_info_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_device_info_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_features) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_features)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_features_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_features_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_features) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_features)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_features_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_features_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_config) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_config)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_config_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_config_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_config) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_config)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_config_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_config_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_config_gen_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_config_gen_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_device_status_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_device_status_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_device_status) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_device_status)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_vqueue) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_vqueue)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).get_vqueue_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(get_vqueue_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_vqueue) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_vqueue)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).set_vqueue_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(set_vqueue_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).reset_vqueue) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(reset_vqueue)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).event_config) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(event_config)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).event_avail) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(event_avail)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).event_used) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg__bindgen_ty_1),
+            "::",
+            stringify!(event_used)
+        )
+    );
+}
+#[test]
+fn bindgen_test_layout_virtio_msg() {
+    const UNINIT: ::core::mem::MaybeUninit<virtio_msg> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<virtio_msg>(),
+        40usize,
+        concat!("Size of: ", stringify!(virtio_msg))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<virtio_msg>(),
+        1usize,
+        concat!("Alignment of ", stringify!(virtio_msg))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).type_) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg),
+            "::",
+            stringify!(type_)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).id) as usize - ptr as usize },
+        1usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg),
+            "::",
+            stringify!(id)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).dev_id) as usize - ptr as usize },
+        2usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg),
+            "::",
+            stringify!(dev_id)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_activate {
+    pub driver_version: u32,
+}
+#[test]
+fn bindgen_test_layout_bus_activate() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_activate> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_activate>(),
+        4usize,
+        concat!("Size of: ", stringify!(bus_activate))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_activate>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_activate))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).driver_version) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_activate),
+            "::",
+            stringify!(driver_version)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_activate_resp {
+    pub device_version: u32,
+    pub features: u64,
+    pub num: u64,
+}
+#[test]
+fn bindgen_test_layout_bus_activate_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_activate_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_activate_resp>(),
+        20usize,
+        concat!("Size of: ", stringify!(bus_activate_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_activate_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_activate_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).device_version) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_activate_resp),
+            "::",
+            stringify!(device_version)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_activate_resp),
+            "::",
+            stringify!(features)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).num) as usize - ptr as usize },
+        12usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_activate_resp),
+            "::",
+            stringify!(num)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_configure {
+    pub features: u64,
+}
+#[test]
+fn bindgen_test_layout_bus_configure() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_configure> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_configure>(),
+        8usize,
+        concat!("Size of: ", stringify!(bus_configure))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_configure>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_configure))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_configure),
+            "::",
+            stringify!(features)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_configure_resp {
+    pub features: u64,
+}
+#[test]
+fn bindgen_test_layout_bus_configure_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_configure_resp> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_configure_resp>(),
+        8usize,
+        concat!("Size of: ", stringify!(bus_configure_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_configure_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_configure_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).features) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_configure_resp),
+            "::",
+            stringify!(features)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_area_share {
+    pub area_id: u32,
+    pub mem_handle: u64,
+}
+#[test]
+fn bindgen_test_layout_bus_area_share() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_area_share> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_area_share>(),
+        12usize,
+        concat!("Size of: ", stringify!(bus_area_share))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_area_share>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_area_share))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).area_id) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_area_share),
+            "::",
+            stringify!(area_id)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).mem_handle) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_area_share),
+            "::",
+            stringify!(mem_handle)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_area_share_resp {
+    pub area_id: u32,
+}
+#[test]
+fn bindgen_test_layout_bus_area_share_resp() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_area_share_resp> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_area_share_resp>(),
+        4usize,
+        concat!("Size of: ", stringify!(bus_area_share_resp))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_area_share_resp>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_area_share_resp))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).area_id) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_area_share_resp),
+            "::",
+            stringify!(area_id)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Debug, Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct bus_area_unshare {
+    pub area_id: u32,
+    pub mem_handle: u64,
+}
+#[test]
+fn bindgen_test_layout_bus_area_unshare() {
+    const UNINIT: ::core::mem::MaybeUninit<bus_area_unshare> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<bus_area_unshare>(),
+        12usize,
+        concat!("Size of: ", stringify!(bus_area_unshare))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<bus_area_unshare>(),
+        1usize,
+        concat!("Alignment of ", stringify!(bus_area_unshare))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).area_id) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_area_unshare),
+            "::",
+            stringify!(area_id)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).mem_handle) as usize - ptr as usize },
+        4usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(bus_area_unshare),
+            "::",
+            stringify!(mem_handle)
+        )
+    );
+}
+#[repr(C, packed)]
+#[derive(Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub struct virtio_msg_ffa {
+    pub type_: u8,
+    pub id: u8,
+    pub unused: u16,
+    pub __bindgen_anon_1: virtio_msg_ffa__bindgen_ty_1,
+}
+#[repr(C)]
+#[derive(Copy, Clone, zerocopy :: FromBytes, zerocopy :: Immutable)]
+pub union virtio_msg_ffa__bindgen_ty_1 {
+    pub payload_u8: [u8; 36usize],
+    pub bus_activate: bus_activate,
+    pub bus_activate_resp: bus_activate_resp,
+    pub bus_configure: bus_configure,
+    pub bus_configure_resp: bus_configure_resp,
+    pub bus_area_share: bus_area_share,
+    pub bus_area_share_resp: bus_area_share_resp,
+    pub bus_area_unshare: bus_area_unshare,
+}
+#[test]
+fn bindgen_test_layout_virtio_msg_ffa__bindgen_ty_1() {
+    const UNINIT: ::core::mem::MaybeUninit<virtio_msg_ffa__bindgen_ty_1> =
+        ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<virtio_msg_ffa__bindgen_ty_1>(),
+        36usize,
+        concat!("Size of: ", stringify!(virtio_msg_ffa__bindgen_ty_1))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<virtio_msg_ffa__bindgen_ty_1>(),
+        1usize,
+        concat!("Alignment of ", stringify!(virtio_msg_ffa__bindgen_ty_1))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).payload_u8) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(payload_u8)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_activate) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_activate)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_activate_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_activate_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_configure) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_configure)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_configure_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_configure_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_area_share) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_area_share)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_area_share_resp) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_area_share_resp)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).bus_area_unshare) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa__bindgen_ty_1),
+            "::",
+            stringify!(bus_area_unshare)
+        )
+    );
+}
+#[test]
+fn bindgen_test_layout_virtio_msg_ffa() {
+    const UNINIT: ::core::mem::MaybeUninit<virtio_msg_ffa> = ::core::mem::MaybeUninit::uninit();
+    let ptr = UNINIT.as_ptr();
+    assert_eq!(
+        ::core::mem::size_of::<virtio_msg_ffa>(),
+        40usize,
+        concat!("Size of: ", stringify!(virtio_msg_ffa))
+    );
+    assert_eq!(
+        ::core::mem::align_of::<virtio_msg_ffa>(),
+        1usize,
+        concat!("Alignment of ", stringify!(virtio_msg_ffa))
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).type_) as usize - ptr as usize },
+        0usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa),
+            "::",
+            stringify!(type_)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).id) as usize - ptr as usize },
+        1usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa),
+            "::",
+            stringify!(id)
+        )
+    );
+    assert_eq!(
+        unsafe { ::core::ptr::addr_of!((*ptr).unused) as usize - ptr as usize },
+        2usize,
+        concat!(
+            "Offset of field: ",
+            stringify!(virtio_msg_ffa),
+            "::",
+            stringify!(unused)
+        )
+    );
+}
diff --git a/dev/virtio/vsock-rust/src/err.rs b/dev/virtio/vsock-rust/src/err.rs
index 0af72653..995fae22 100644
--- a/dev/virtio/vsock-rust/src/err.rs
+++ b/dev/virtio/vsock-rust/src/err.rs
@@ -21,12 +21,12 @@
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
 
-use virtio_drivers::transport::pci::VirtioPciError;
+use virtio_drivers_and_devices::transport::pci::VirtioPciError;
 
 #[cfg(target_arch = "aarch64")]
 use hypervisor_backends::KvmError;
 use rust_support::Error as LkError;
-use virtio_drivers::Error as VirtioError;
+use virtio_drivers_and_devices::Error as VirtioError;
 
 #[derive(Debug)]
 pub enum Error {
diff --git a/dev/virtio/vsock-rust/src/hal.rs b/dev/virtio/vsock-rust/src/hal.rs
new file mode 100644
index 00000000..a91b3096
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/hal.rs
@@ -0,0 +1,87 @@
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
+use core::ffi::CStr;
+use core::ptr::NonNull;
+use rust_support::mmu::ARCH_MMU_FLAG_PERM_NO_EXECUTE;
+use rust_support::mmu::PAGE_SIZE_SHIFT;
+use rust_support::vmm::vaddr_to_paddr;
+use rust_support::vmm::vmm_alloc_contiguous;
+use rust_support::vmm::vmm_free_region;
+use rust_support::vmm::vmm_get_kernel_aspace;
+use virtio_drivers_and_devices::BufferDirection;
+use virtio_drivers_and_devices::PhysAddr;
+use virtio_drivers_and_devices::PAGE_SIZE;
+
+pub(crate) fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
+    const NAME: &CStr = c"vsock-rust";
+    // dma_alloc requests num pages but vmm_alloc_contiguous expects bytes.
+    let size = pages * PAGE_SIZE;
+    let mut vaddr = core::ptr::null_mut(); // stores pointer to virtual memory
+    let align_pow2 = PAGE_SIZE_SHIFT as u8;
+    let vmm_flags = 0;
+    let arch_mmu_flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE;
+    let aspace = vmm_get_kernel_aspace();
+
+    // NOTE: the allocated memory will be zeroed since vmm_alloc_contiguous
+    // calls vmm_alloc_pmm which does not set the PMM_ALLOC_FLAG_NO_CLEAR
+    // flag.
+    //
+    // Safety:
+    // `aspace` is `vmm_get_kernel_aspace()`.
+    // `name` is a `&'static CStr`.
+    // `size` is validated by the callee
+    let rc = unsafe {
+        vmm_alloc_contiguous(
+            aspace,
+            NAME.as_ptr(),
+            size,
+            &mut vaddr,
+            align_pow2,
+            vmm_flags,
+            arch_mmu_flags,
+        )
+    };
+    if rc != 0 {
+        panic!("error {} allocating physical memory", rc);
+    }
+    if vaddr as usize & (PAGE_SIZE - 1usize) != 0 {
+        panic!("error page-aligning allocation {:#x}", vaddr as usize);
+    }
+
+    // Safety: `vaddr` is valid because the call to `vmm_alloc_continuous` succeeded
+    let paddr = unsafe { vaddr_to_paddr(vaddr) };
+
+    (paddr, NonNull::<u8>::new(vaddr as *mut u8).unwrap())
+}
+
+// Safety: `vaddr` was returned by `dma_alloc` and hasn't been deallocated.
+pub(crate) unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, _pages: usize) -> i32 {
+    let aspace = vmm_get_kernel_aspace();
+    let vaddr = vaddr.as_ptr();
+    // Safety:
+    // - function-level requirements
+    // - `aspace` points to the kernel address space object
+    // - `vaddr` is a region in `aspace`
+    unsafe { vmm_free_region(aspace, vaddr as usize) }
+}
diff --git a/dev/virtio/vsock-rust/src/lib.rs b/dev/virtio/vsock-rust/src/lib.rs
index 5ee0136b..785a51b4 100644
--- a/dev/virtio/vsock-rust/src/lib.rs
+++ b/dev/virtio/vsock-rust/src/lib.rs
@@ -5,12 +5,25 @@
 #![cfg_attr(not(version("1.79")), feature(cstr_count_bytes))]
 // C string literals were stabilized in Rust 1.77
 #![cfg_attr(not(version("1.77")), feature(c_str_literals))]
+// unsigned_is_multiple_of feature was added in Rust 1.82
+#![cfg_attr(version("1.82"), feature(unsigned_is_multiple_of))]
 
 mod err;
-#[cfg(target_arch = "aarch64")]
-mod kvm;
+mod hal;
 mod pci;
 mod vsock;
 
+// TODO: Follow the normal bindgen pattern once we find a suitable location for
+// the header files that the virtio-msg bindings were generated from. Current
+// bindings were generated by building generic-arm64-virt-test-debug with
+// aosp/3390803/25 applied and used prebuilt bindgen 0.69.5.
+#[allow(clippy::upper_case_acronyms)]
+#[allow(unused)]
+#[allow(non_camel_case_types)]
+#[allow(non_upper_case_globals)]
+#[rustfmt::skip]
+#[path = "bindings.rs"]
+mod sys;
+
 pub use err::Error;
 pub use pci::pci_init_mmio;
diff --git a/dev/virtio/vsock-rust/src/pci.rs b/dev/virtio/vsock-rust/src/pci.rs
index a64946d0..70e4c640 100644
--- a/dev/virtio/vsock-rust/src/pci.rs
+++ b/dev/virtio/vsock-rust/src/pci.rs
@@ -25,69 +25,51 @@
 use core::ffi::c_int;
 use core::ptr;
 
-use alloc::sync::Arc;
-
-use log::{debug, error};
-
-use virtio_drivers::device::socket::VirtIOSocket;
-use virtio_drivers::device::socket::VsockConnectionManager;
-use virtio_drivers::transport::pci::bus::Cam;
-use virtio_drivers::transport::pci::bus::Command;
-use virtio_drivers::transport::pci::bus::DeviceFunction;
-use virtio_drivers::transport::pci::bus::PciRoot;
-use virtio_drivers::transport::pci::virtio_device_type;
-use virtio_drivers::transport::pci::PciTransport;
-use virtio_drivers::transport::DeviceType;
+use log::debug;
+
+use virtio_drivers_and_devices::device::socket::VirtIOSocket;
+use virtio_drivers_and_devices::transport::pci::bus::Cam;
+use virtio_drivers_and_devices::transport::pci::bus::Command;
+use virtio_drivers_and_devices::transport::pci::bus::ConfigurationAccess;
+use virtio_drivers_and_devices::transport::pci::bus::MmioCam;
+use virtio_drivers_and_devices::transport::pci::bus::PciRoot;
+use virtio_drivers_and_devices::transport::pci::virtio_device_type;
+use virtio_drivers_and_devices::transport::pci::PciTransport;
+use virtio_drivers_and_devices::transport::SomeTransport;
+#[cfg(target_arch = "x86_64")]
+use {
+    hypervisor_backends::get_mem_sharer,
+    virtio_drivers_and_devices::transport::x86_64::{HypCam, HypPciTransport},
+};
+
+use virtio_drivers_and_devices::transport::DeviceType;
+
+use hypervisor::mmio_map_region;
 
 use rust_support::mmu::ARCH_MMU_FLAG_PERM_NO_EXECUTE;
 use rust_support::mmu::ARCH_MMU_FLAG_UNCACHED_DEVICE;
 use rust_support::paddr_t;
-use rust_support::thread::Builder;
-use rust_support::thread::Priority;
 use rust_support::vmm::vmm_alloc_physical;
 use rust_support::vmm::vmm_get_kernel_aspace;
 use rust_support::Error as LkError;
 
 use crate::err::Error;
-use crate::vsock::VsockDevice;
+use crate::vsock::vsock_init;
 use hal::TrustyHal;
 
+#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
+mod arch;
+#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
+#[path = "pci/unimplemented.rs"]
 mod arch;
 mod hal;
 
 impl TrustyHal {
-    fn init_vsock(pci_root: &mut PciRoot, device_function: DeviceFunction) -> Result<(), Error> {
-        let transport = PciTransport::new::<Self>(pci_root, device_function)?;
-        let driver: VirtIOSocket<TrustyHal, PciTransport, 4096> = VirtIOSocket::new(transport)?;
-        let manager = VsockConnectionManager::new_with_capacity(driver, 4096);
-
-        let device_for_rx = Arc::new(VsockDevice::new(manager));
-        let device_for_tx = device_for_rx.clone();
-
-        Builder::new()
-            .name(c"virtio_vsock_rx")
-            .priority(Priority::HIGH)
-            .spawn(move || {
-                let ret = crate::vsock::vsock_rx_loop(device_for_rx);
-                error!("vsock_rx_loop returned {:?}", ret);
-                ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
-            })
-            .map_err(|e| LkError::from_lk(e).unwrap_err())?;
-
-        Builder::new()
-            .name(c"virtio_vsock_tx")
-            .priority(Priority::HIGH)
-            .spawn(move || {
-                let ret = crate::vsock::vsock_tx_loop(device_for_tx);
-                error!("vsock_tx_loop returned {:?}", ret);
-                ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
-            })
-            .map_err(|e| LkError::from_lk(e).unwrap_err())?;
-
-        Ok(())
-    }
-
-    fn init_all_vsocks(mut pci_root: PciRoot, pci_size: usize) -> Result<(), Error> {
+    fn init_all_vsocks(
+        mut pci_root: PciRoot<impl ConfigurationAccess>,
+        pci_size: usize,
+        use_hyp_transport: bool,
+    ) -> Result<(), Error> {
         for bus in u8::MIN..=u8::MAX {
             // each bus can use up to one megabyte of address space, make sure we stay in range
             if bus as usize * 0x100000 >= pci_size {
@@ -99,7 +81,7 @@ impl TrustyHal {
                 };
 
                 // Map the BARs of the device into virtual memory. Since the mappings must
-                // outlive the `PciTransport` constructed in `init_vsock` we no make no
+                // outlive the `PciTransport` constructed in `vsock_init` we no make no
                 // attempt to deallocate them.
                 Self::mmio_alloc(&mut pci_root, device_function)?;
 
@@ -109,7 +91,37 @@ impl TrustyHal {
                     Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
                 );
 
-                Self::init_vsock(&mut pci_root, device_function)?;
+                // In contrast to arm64, when Trusty runs as a protected VM on x86_64, emulated
+                // MMIO accesses require special handling. On x86_64, the host needs to read and
+                // decode guest instructions that caused the MMIO access trap to determine the
+                // address and access type. However, due to pKVM nature, the host cannot read
+                // protected VM memory. To address this, pKVM supports hypercalls for IOREAD and
+                // IOWRITE, which the guest can use.
+                //
+                // The virtio-drivers' HypPciTransport is based on mentioned hypercalls and
+                // therefore is used for x86 protected Trusty, while PciTransport is used
+                // otherwise.
+                let transport = if use_hyp_transport {
+                    #[cfg(target_arch = "x86_64")]
+                    {
+                        SomeTransport::HypPci(HypPciTransport::new::<_>(
+                            &mut pci_root,
+                            device_function,
+                        )?)
+                    }
+
+                    #[cfg(not(target_arch = "x86_64"))]
+                    panic!("HypPciTransport is x86_64 specific");
+                } else {
+                    SomeTransport::Pci(PciTransport::new::<Self, _>(
+                        &mut pci_root,
+                        device_function,
+                    )?)
+                };
+
+                let driver: VirtIOSocket<TrustyHal, SomeTransport, 4096> =
+                    VirtIOSocket::new(transport)?;
+                vsock_init(driver)?;
             }
         }
         Ok(())
@@ -120,11 +132,11 @@ impl TrustyHal {
 ///
 /// `pci_paddr` must be a valid physical address with `'static` lifetime to the base of the MMIO region,
 /// which must have a size of `pci_size`.
-unsafe fn map_pci_root(
+unsafe fn map_pci_root_and_init_vsock(
     pci_paddr: paddr_t,
     pci_size: usize,
     cfg_size: usize,
-) -> Result<PciRoot, Error> {
+) -> Result<(), Error> {
     // The ECAM is defined in Section 7.2.2 of the PCI Express Base Specification, Revision 2.0.
     // The ECAM size must be a power of two with the exponent between 1 and 8.
     let cam = match cfg_size / /* device functions */ 8 {
@@ -162,19 +174,45 @@ unsafe fn map_pci_root(
     LkError::from_lk(e)?;
 
     // Safety:
-    // `pci_paddr` is a valid physical address to the base of the MMIO region.
-    // `pci_vaddr` is the mapped virtual address of that.
-    // `pci_paddr` has `'static` lifetime, and `pci_vaddr` is never unmapped,
-    // so it, too, has `'static` lifetime.
-    // We also check that the `cam` size is valid.
-    let pci_root = unsafe { PciRoot::new(pci_vaddr.cast(), cam) };
-
-    Ok(pci_root)
+    // `pci_paddr` and `pci_size` are safe by this function's safety requirements.
+    match unsafe { mmio_map_region(pci_paddr, pci_size) } {
+        // Ignore not supported which implies that guard is not used.
+        Ok(()) | Err(LkError::ERR_NOT_SUPPORTED) | Err(LkError::ERR_INVALID_ARGS) => {}
+        Err(err) => {
+            log::error!("mmio_map_region returned unexpected error: {:?}", err);
+            return Err(Error::Lk(err));
+        }
+    }
+
+    #[cfg(not(target_arch = "x86_64"))]
+    let use_hyp_transport = false;
+
+    // x86 when running in protected mode requires hyp transport
+    #[cfg(target_arch = "x86_64")]
+    let use_hyp_transport = get_mem_sharer().is_some();
+
+    if use_hyp_transport {
+        #[cfg(target_arch = "x86_64")]
+        {
+            let pci_root = PciRoot::new(HypCam::new(pci_paddr, cam));
+            TrustyHal::init_all_vsocks(pci_root, pci_size, use_hyp_transport)?;
+        }
+    } else {
+        // Safety:
+        // `pci_paddr` is a valid physical address to the base of the MMIO region.
+        // `pci_vaddr` is the mapped virtual address of that.
+        // `pci_paddr` has `'static` lifetime, and `pci_vaddr` is never unmapped,
+        // so it, too, has `'static` lifetime.
+        // We also check that the `cam` size is valid.
+        let pci_root = PciRoot::new(unsafe { MmioCam::new(pci_vaddr.cast(), cam) });
+        TrustyHal::init_all_vsocks(pci_root, pci_size, use_hyp_transport)?;
+    }
+    Ok(())
 }
 
 /// # Safety
 ///
-/// See [`map_pci_root`].
+/// See [`map_pci_root_and_init_vsock`].
 #[no_mangle]
 pub unsafe extern "C" fn pci_init_mmio(
     pci_paddr: paddr_t,
@@ -183,9 +221,8 @@ pub unsafe extern "C" fn pci_init_mmio(
 ) -> c_int {
     debug!("initializing vsock: pci_paddr 0x{pci_paddr:x}, pci_size 0x{pci_size:x}");
     || -> Result<(), Error> {
-        // Safety: Delegated to `map_pci_root`.
-        let pci_root = unsafe { map_pci_root(pci_paddr, pci_size, cfg_size) }?;
-        TrustyHal::init_all_vsocks(pci_root, pci_size)?;
+        // Safety: Delegated to `map_pci_root_and_init_vsock`.
+        unsafe { map_pci_root_and_init_vsock(pci_paddr, pci_size, cfg_size) }?;
         Ok(())
     }()
     .err()
diff --git a/dev/virtio/vsock-rust/src/pci/arch.rs b/dev/virtio/vsock-rust/src/pci/arch.rs
index 4ebb89e8..0cfa794c 100644
--- a/dev/virtio/vsock-rust/src/pci/arch.rs
+++ b/dev/virtio/vsock-rust/src/pci/arch.rs
@@ -21,36 +21,100 @@
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
 
-use cfg_if::cfg_if;
-
-cfg_if! {
-    if #[cfg(target_arch = "aarch64")] {
-        mod aarch64;
-        pub(crate) use aarch64::*;
-    } else if #[cfg(target_arch = "x86_64")] {
-        mod x86_64;
-        pub(crate) use x86_64::*;
-    } else {
-        use core::ptr::NonNull;
-        use virtio_drivers::BufferDirection;
-        use virtio_drivers::PhysAddr;
-
-        pub(crate) fn dma_alloc_share(_paddr: usize, _size: usize) {
-            unimplemented!();
-        }
-
-        pub(crate) fn dma_dealloc_unshare(_paddr: PhysAddr, _size: usize) {
-            unimplemented!();
-        }
-
-        // Safety: unimplemented
-        pub(crate) unsafe fn share(_buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
-            unimplemented!();
-        }
-
-        // Safety: unimplemented
-        pub(crate) unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
-            unimplemented!();
-        }
+use alloc::collections::btree_map::BTreeMap;
+
+use lazy_static::lazy_static;
+
+use core::ffi::c_void;
+use core::ops::DerefMut;
+use core::ptr::copy_nonoverlapping;
+use core::ptr::NonNull;
+
+use hypervisor::share_pages;
+use hypervisor::unshare_pages;
+
+use crate::pci::hal::TrustyHal;
+
+use rust_support::paddr_t;
+use rust_support::sync::Mutex;
+use rust_support::vaddr_t;
+
+use static_assertions::assert_cfg;
+
+use virtio_drivers_and_devices::BufferDirection;
+use virtio_drivers_and_devices::Hal;
+use virtio_drivers_and_devices::PhysAddr;
+use virtio_drivers_and_devices::PAGE_SIZE;
+
+// This code will only work on x86_64 or aarch64
+assert_cfg!(any(target_arch = "x86_64", target_arch = "aarch64"), "Must target x86_64 or aarch64");
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
     }
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
 }
diff --git a/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs b/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs
deleted file mode 100644
index 656cbaa5..00000000
--- a/dev/virtio/vsock-rust/src/pci/arch/aarch64.rs
+++ /dev/null
@@ -1,115 +0,0 @@
-/*
- * Copyright (c) 2024 Google Inc. All rights reserved
- *
- * Permission is hereby granted, free of charge, to any person obtaining
- * a copy of this software and associated documentation files
- * (the "Software"), to deal in the Software without restriction,
- * including without limitation the rights to use, copy, modify, merge,
- * publish, distribute, sublicense, and/or sell copies of the Software,
- * and to permit persons to whom the Software is furnished to do so,
- * subject to the following conditions:
- *
- * The above copyright notice and this permission notice shall be
- * included in all copies or substantial portions of the Software.
- *
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
- * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
- * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
- * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
- * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
- * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
- * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
- */
-
-use alloc::collections::btree_map::BTreeMap;
-
-use lazy_static::lazy_static;
-
-use core::ffi::c_void;
-use core::ops::DerefMut;
-use core::ptr::copy_nonoverlapping;
-use core::ptr::NonNull;
-
-use crate::kvm::share_pages;
-use crate::kvm::unshare_pages;
-
-use crate::pci::hal::TrustyHal;
-
-use rust_support::paddr_t;
-use rust_support::sync::Mutex;
-use rust_support::vaddr_t;
-
-use virtio_drivers::BufferDirection;
-use virtio_drivers::Hal;
-use virtio_drivers::PhysAddr;
-use virtio_drivers::PAGE_SIZE;
-
-lazy_static! {
-    /// Stores the paddr to vaddr mapping in `share` for use in `unshare`
-    static ref VADDRS: Mutex<BTreeMap<paddr_t, vaddr_t>> = Mutex::new(BTreeMap::new());
-}
-
-/// Perform architecture-specific DMA allocation
-pub(crate) fn dma_alloc_share(paddr: usize, size: usize) {
-    share_pages(paddr, size).expect("failed to share pages");
-}
-
-/// Perform architecture-specific DMA deallocation
-pub(crate) fn dma_dealloc_unshare(paddr: PhysAddr, size: usize) {
-    unshare_pages(paddr, size).expect("failed to unshare pages");
-}
-
-// Safety: buffer must be a valid kernel virtual address that is not already mapped for DMA.
-pub(crate) unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
-    let size = buffer.len();
-    let pages = to_pages(size);
-
-    let (paddr, vaddr) = TrustyHal::dma_alloc(pages, direction);
-    if let Some(old_vaddr) = VADDRS.lock().deref_mut().insert(paddr, vaddr.as_ptr() as usize) {
-        panic!("paddr ({:#x}) was already mapped to vaddr ({:#x})", paddr, old_vaddr);
-    }
-
-    let dst_ptr = vaddr.as_ptr() as *mut c_void;
-
-    if direction != BufferDirection::DeviceToDriver {
-        let src_ptr = buffer.as_ptr() as *const u8 as *const c_void;
-        // Safety: Both regions are valid, properly aligned, and don't overlap.
-        // - Because `vaddr` is a virtual address returned by `dma_alloc`, it is
-        // properly aligned and does not overlap with `buffer`.
-        // - There are no particular alignment requirements on `buffer`.
-        unsafe { copy_nonoverlapping(src_ptr, dst_ptr, size) };
-    }
-
-    paddr
-}
-
-// Safety:
-// - paddr is a valid physical address returned by call to `share`
-// - buffer must be a valid kernel virtual address previously passed to `share` that
-//   has not already been `unshare`d by this function.
-pub(crate) unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
-    let size = buffer.len();
-    let vaddr = VADDRS.lock().deref_mut().remove(&paddr).expect("paddr was inserted by share")
-        as *const c_void;
-
-    if direction != BufferDirection::DriverToDevice {
-        let dest = buffer.as_ptr() as *mut u8 as *mut c_void;
-        // Safety: Both regions are valid, properly aligned, and don't overlap.
-        // - Because `vaddr` was retrieved from `VADDRS`, it must have been returned
-        //   from the call to `dma_alloc` in `share`.
-        // - Because `vaddr` is a virtual address returned by `dma_alloc`, it is
-        //   properly aligned and does not overlap with `buffer`.
-        // - There are no particular alignment requirements on `buffer`.
-        unsafe { copy_nonoverlapping(vaddr, dest, size) };
-    }
-
-    let vaddr = NonNull::<u8>::new(vaddr as *mut u8).unwrap();
-    // Safety: memory was allocated by `share` and not previously `unshare`d.
-    unsafe {
-        TrustyHal::dma_dealloc(paddr, vaddr, to_pages(size));
-    }
-}
-
-fn to_pages(size: usize) -> usize {
-    size.div_ceil(PAGE_SIZE)
-}
diff --git a/dev/virtio/vsock-rust/src/pci/hal.rs b/dev/virtio/vsock-rust/src/pci/hal.rs
index 737513f0..b6054a7a 100644
--- a/dev/virtio/vsock-rust/src/pci/hal.rs
+++ b/dev/virtio/vsock-rust/src/pci/hal.rs
@@ -27,23 +27,23 @@ use core::ptr::NonNull;
 
 use lazy_static::lazy_static;
 
+use hypervisor::mmio_map_region;
+
 use rust_support::mmu::ARCH_MMU_FLAG_PERM_NO_EXECUTE;
 use rust_support::mmu::ARCH_MMU_FLAG_UNCACHED_DEVICE;
-use rust_support::mmu::PAGE_SIZE_SHIFT;
 use rust_support::paddr_t;
 use rust_support::sync::Mutex;
 use rust_support::vaddr_t;
-use rust_support::vmm::vaddr_to_paddr;
-use rust_support::vmm::vmm_alloc_contiguous;
 use rust_support::vmm::vmm_alloc_physical;
-use rust_support::vmm::vmm_free_region;
 use rust_support::vmm::vmm_get_kernel_aspace;
+use rust_support::Error as LkError;
 
 use static_assertions::const_assert_eq;
 
-use virtio_drivers::transport::pci::bus::DeviceFunction;
-use virtio_drivers::transport::pci::bus::PciRoot;
-use virtio_drivers::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};
+use virtio_drivers_and_devices::transport::pci::bus::ConfigurationAccess;
+use virtio_drivers_and_devices::transport::pci::bus::DeviceFunction;
+use virtio_drivers_and_devices::transport::pci::bus::PciRoot;
+use virtio_drivers_and_devices::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};
 
 use crate::err::Error;
 use crate::pci::arch;
@@ -67,7 +67,7 @@ pub struct TrustyHal;
 
 impl TrustyHal {
     pub fn mmio_alloc(
-        pci_root: &mut PciRoot,
+        pci_root: &mut PciRoot<impl ConfigurationAccess>,
         device_function: DeviceFunction,
     ) -> Result<(), Error> {
         for bar in 0..NUM_BARS {
@@ -92,7 +92,18 @@ impl TrustyHal {
                         ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_UNCACHED_DEVICE,
                     )
                 };
-                rust_support::Error::from_lk(ret)?;
+                LkError::from_lk(ret)?;
+
+                // Safety:
+                // `bar_paddr` and `bar_size_aligned` are safe by this function's safety requirements.
+                match unsafe { mmio_map_region(bar_paddr as usize, bar_size_aligned) } {
+                    // Ignore not supported which implies that guard is not used.
+                    Ok(()) | Err(LkError::ERR_NOT_SUPPORTED) | Err(LkError::ERR_INVALID_ARGS) => {}
+                    Err(err) => {
+                        log::error!("mmio_map_region returned unexpected error: {:?}", err);
+                        return Err(Error::Lk(err));
+                    }
+                }
 
                 BARS.lock().deref_mut()[bar] = Some(BarInfo {
                     paddr: bar_paddr as usize,
@@ -113,48 +124,11 @@ unsafe impl Hal for TrustyHal {
     // Safety:
     // Function either returns a non-null, properly aligned pointer or panics the kernel.
     // The call to `vmm_alloc_contiguous` ensures that the pointed to memory is zeroed.
-    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
-        let name = c"vsock-rust";
-        // dma_alloc requests num pages but vmm_alloc_contiguous expects bytes.
+    fn dma_alloc(pages: usize, direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
         let size = pages * PAGE_SIZE;
-        let mut vaddr = core::ptr::null_mut(); // stores pointer to virtual memory
-        let align_pow2 = PAGE_SIZE_SHIFT as u8;
-        let vmm_flags = 0;
-        let arch_mmu_flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE;
-        let aspace = vmm_get_kernel_aspace();
-
-        // NOTE: the allocated memory will be zeroed since vmm_alloc_contiguous
-        // calls vmm_alloc_pmm which does not set the PMM_ALLOC_FLAG_NO_CLEAR
-        // flag.
-        //
-        // Safety:
-        // `aspace` is `vmm_get_kernel_aspace()`.
-        // `name` is a `&'static CStr`.
-        // `size` is validated by the callee
-        let rc = unsafe {
-            vmm_alloc_contiguous(
-                aspace,
-                name.as_ptr(),
-                size,
-                &mut vaddr,
-                align_pow2,
-                vmm_flags,
-                arch_mmu_flags,
-            )
-        };
-        if rc != 0 {
-            panic!("error {} allocating physical memory", rc);
-        }
-        if vaddr as usize & (PAGE_SIZE - 1usize) != 0 {
-            panic!("error page-aligning allocation {:#x}", vaddr as usize);
-        }
-
-        // Safety: `vaddr` is valid because the call to `vmm_alloc_continuous` succeeded
-        let paddr = unsafe { vaddr_to_paddr(vaddr) };
-
+        let (paddr, vaddr) = crate::hal::dma_alloc(pages, direction);
         arch::dma_alloc_share(paddr, size);
-
-        (paddr, NonNull::<u8>::new(vaddr as *mut u8).unwrap())
+        (paddr, vaddr)
     }
 
     // Safety: `vaddr` was returned by `dma_alloc` and hasn't been deallocated.
@@ -162,13 +136,9 @@ unsafe impl Hal for TrustyHal {
         let size = pages * PAGE_SIZE;
         arch::dma_dealloc_unshare(paddr, size);
 
-        let aspace = vmm_get_kernel_aspace();
-        let vaddr = vaddr.as_ptr();
         // Safety:
-        // - function-level requirements
-        // - `aspace` points to the kernel address space object
-        // - `vaddr` is a region in `aspace`
-        unsafe { vmm_free_region(aspace, vaddr as usize) }
+        // `vaddr` was returned by `dma_alloc` and hasn't been deallocated.
+        unsafe { crate::hal::dma_dealloc(paddr, vaddr, pages) }
     }
 
     // Only used for MMIO addresses within BARs read from the device,
diff --git a/dev/virtio/vsock-rust/src/pci/unimplemented.rs b/dev/virtio/vsock-rust/src/pci/unimplemented.rs
new file mode 100644
index 00000000..47032735
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/pci/unimplemented.rs
@@ -0,0 +1,25 @@
+use core::ptr::NonNull;
+use virtio_drivers_and_devices::BufferDirection;
+use virtio_drivers_and_devices::PhysAddr;
+
+pub(crate) fn dma_alloc_share(_paddr: usize, _size: usize) {
+    unimplemented!();
+}
+
+pub(crate) fn dma_dealloc_unshare(_paddr: PhysAddr, _size: usize) {
+    unimplemented!();
+}
+
+// Safety: unimplemented
+pub(crate) unsafe fn share(_buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
+    unimplemented!();
+}
+
+// Safety: unimplemented
+pub(crate) unsafe fn unshare(
+    _paddr: PhysAddr,
+    _buffer: NonNull<[u8]>,
+    _direction: BufferDirection,
+) {
+    unimplemented!();
+}
diff --git a/dev/virtio/vsock-rust/src/vsock.rs b/dev/virtio/vsock-rust/src/vsock.rs
index 0b00b9ae..71b1061c 100644
--- a/dev/virtio/vsock-rust/src/vsock.rs
+++ b/dev/virtio/vsock-rust/src/vsock.rs
@@ -23,12 +23,14 @@
 
 #![deny(unsafe_op_in_unsafe_fn)]
 use core::ffi::c_void;
+use core::ffi::CStr;
 use core::ops::Deref;
 use core::ops::DerefMut;
 use core::ptr::eq;
 use core::ptr::null_mut;
 use core::time::Duration;
 
+use alloc::borrow::ToOwned;
 use alloc::boxed::Box;
 use alloc::ffi::CString;
 use alloc::sync::Arc;
@@ -58,15 +60,19 @@ use rust_support::ipc::IPC_PORT_PATH_MAX;
 use rust_support::sync::Mutex;
 use rust_support::thread;
 use rust_support::thread::sleep;
-use virtio_drivers::device::socket::SocketError;
-use virtio_drivers::device::socket::VsockAddr;
-use virtio_drivers::device::socket::VsockConnectionManager;
-use virtio_drivers::device::socket::VsockEvent;
-use virtio_drivers::device::socket::VsockEventType;
-use virtio_drivers::transport::Transport;
-use virtio_drivers::Error as VirtioError;
-use virtio_drivers::Hal;
-use virtio_drivers::PAGE_SIZE;
+use rust_support::thread::Builder;
+use rust_support::thread::Priority;
+use virtio_drivers_and_devices::device::socket::SocketError;
+use virtio_drivers_and_devices::device::socket::VirtIOSocket;
+use virtio_drivers_and_devices::device::socket::VsockAddr;
+use virtio_drivers_and_devices::device::socket::VsockConnectionManager;
+use virtio_drivers_and_devices::device::socket::VsockEvent;
+use virtio_drivers_and_devices::device::socket::VsockEventType;
+use virtio_drivers_and_devices::device::socket::VsockManager;
+use virtio_drivers_and_devices::transport::Transport;
+use virtio_drivers_and_devices::Error as VirtioError;
+use virtio_drivers_and_devices::Hal;
+use virtio_drivers_and_devices::PAGE_SIZE;
 
 use rust_support::handle::HandleRef;
 use rust_support::handle_set::HandleSet;
@@ -77,6 +83,46 @@ use crate::err::Error;
 
 const ACTIVE_TIMEOUT: Duration = Duration::from_secs(5);
 
+struct TipcPortAcl {
+    name: &'static CStr,
+    enabled: bool,
+}
+
+// macro will generate the variable containing the ACL for all tipc ports. If the feature name is
+// defined, the corresponding port will be enabled; the port will be disabled otherwise. The macro
+// will generate 2 extra ports for connections that send the port name in the first package for port
+// 0 and 1.
+macro_rules! comm_port_feature_enable {
+    ($var_name:ident[$number_ports: literal]={$({port_name: $port_name:literal, feature_name: $feature_name:literal}),+ $(,)*}) => {
+    const $var_name: [TipcPortAcl; $number_ports + 2] = [
+        TipcPortAcl { name: c"", enabled: true }, // connections on port zero must send port name in first packet
+        TipcPortAcl { name: c"", enabled: true }, // temporary workaround to not change the port 1 to port 0
+        $(
+            #[cfg(feature = $feature_name)]
+            TipcPortAcl { name: $port_name, enabled: true },
+            #[cfg(not(feature = $feature_name))]
+            TipcPortAcl { name: $port_name, enabled: false },
+        )+
+    ];
+    }
+}
+
+// Mapping of vsock port numbers to tipc port names.
+//
+// Each tipc port name must be shorter than IPC_PORT_PATH_MAX.
+comm_port_feature_enable! {
+    PORT_MAP[8] = {
+        {port_name: c"com.android.trusty.authmgr", feature_name: "authmgr"},
+        {port_name: c"com.android.trusty.hwcryptooperations", feature_name: "hwcrypto_hal"},
+        {port_name: c"com.android.trusty.rust.hwcryptohal.V1", feature_name: "hwcrypto_hal"},
+        {port_name: c"com.android.trusty.securestorage", feature_name: "securestorage_hal"},
+        {port_name: c"com.android.trusty.widevine.transact", feature_name: "widevine_aidl_comm"},
+        {port_name: c"com.android.trusty.storage.proxy", feature_name: "securestorage_hal"},
+        {port_name: c"com.android.trusty.gatekeeper", feature_name: "gatekeeper"},
+        {port_name: c"com.android.trusty.keymint", feature_name: "keymint"},
+    }
+}
+
 #[allow(dead_code)]
 #[derive(Clone, Copy, Debug, Default, PartialEq)]
 enum VsockConnectionState {
@@ -200,28 +246,49 @@ enum ConnectionStateAction {
     Remove,
 }
 
-fn vsock_connection_lookup(
+fn vsock_connection_lookup_by(
     connections: &mut Vec<VsockConnection>,
-    remote_port: u32,
+    predicate: impl Fn(&VsockConnection) -> bool,
     f: impl FnOnce(&mut VsockConnection) -> ConnectionStateAction,
 ) -> Result<(), ()> {
-    let (index, connection) = connections
-        .iter_mut()
-        .enumerate()
-        .find(|(_idx, connection)| connection.peer.port == remote_port)
-        .ok_or(())?;
-    let action = f(connection);
+    let index = connections.iter().position(predicate).ok_or(())?;
+    let action = f(&mut connections[index]);
     if action == ConnectionStateAction::None {
         return Ok(());
     }
 
-    if vsock_connection_close(connection, action) {
+    if vsock_connection_close(&mut connections[index], action) {
         connections.swap_remove(index);
     }
 
     Ok(())
 }
 
+fn vsock_connection_lookup_peer(
+    connections: &mut Vec<VsockConnection>,
+    peer: VsockAddr,
+    local_port: u32,
+    f: impl FnOnce(&mut VsockConnection) -> ConnectionStateAction,
+) -> Result<(), ()> {
+    vsock_connection_lookup_by(
+        connections,
+        |c: &VsockConnection| c.peer == peer && c.local_port == local_port,
+        f,
+    )
+}
+
+fn vsock_connection_lookup_cookie(
+    connections: &mut Vec<VsockConnection>,
+    cookie: *mut c_void,
+    f: impl FnOnce(&mut VsockConnection) -> ConnectionStateAction,
+) -> Result<(), ()> {
+    vsock_connection_lookup_by(
+        connections,
+        |c: &VsockConnection| eq(c.href.as_ptr().cast::<c_void>(), cookie),
+        f,
+    )
+}
+
 fn vsock_connection_close(c: &mut VsockConnection, action: ConnectionStateAction) -> bool {
     info!(
         "remote_port {}, tipc_port_name {}, state {:?}",
@@ -259,22 +326,20 @@ fn vsock_connection_close(c: &mut VsockConnection, action: ConnectionStateAction
     false // keep connection
 }
 
-pub struct VsockDevice<H, T>
+pub struct VsockDevice<M>
 where
-    H: Hal,
-    T: Transport,
+    M: VsockManager,
 {
     connections: Mutex<Vec<VsockConnection>>,
     handle_set: HandleSet,
-    connection_manager: Mutex<VsockConnectionManager<H, T, 4096>>,
+    connection_manager: Mutex<M>,
 }
 
-impl<H, T> VsockDevice<H, T>
+impl<M> VsockDevice<M>
 where
-    H: Hal,
-    T: Transport,
+    M: VsockManager,
 {
-    pub(crate) fn new(manager: VsockConnectionManager<H, T, 4096>) -> Self {
+    pub(crate) fn new(manager: M) -> Self {
         Self {
             connections: Mutex::new(Vec::new()),
             handle_set: HandleSet::new(),
@@ -282,7 +347,7 @@ where
         }
     }
 
-    fn vsock_rx_op_request(&self, peer: VsockAddr, local: VsockAddr) {
+    fn vsock_rx_op_request(&self, peer: VsockAddr, local: VsockAddr) -> Result<(), Error> {
         debug!("dst_port {}, src_port {}", local.port, peer.port);
 
         // do we already have a connection?
@@ -292,19 +357,41 @@ where
             .iter()
             .any(|connection| connection.peer == peer && connection.local_port == local.port)
         {
-            panic!("connection already exists");
+            return Err(LkError::ERR_ALREADY_EXISTS.into());
         };
 
-        guard.deref_mut().push(VsockConnection::new(peer, local.port));
+        let mut c = VsockConnection::new(peer, local.port);
+
+        // ports greater than 1 use port map to determine what tipc port to connect to
+        if [0, 1].contains(&local.port) {
+            // wait on peer to send tipc port name
+        } else if (local.port as usize) < PORT_MAP.len() {
+            if PORT_MAP[local.port as usize].enabled {
+                c.tipc_port_name = Some(PORT_MAP[local.port as usize].name.to_owned());
+                self.vsock_connect_tipc(&mut c)?;
+            } else {
+                return Err(LkError::ERR_NOT_VALID.into());
+            }
+        } else {
+            return Err(LkError::ERR_OUT_OF_RANGE.into());
+        }
+
+        guard.deref_mut().push(c);
+
+        Ok(())
     }
 
-    fn vsock_connect_tipc(
+    fn vsock_connect_on_rx(
         &self,
         c: &mut VsockConnection,
         length: usize,
         source: VsockAddr,
         destination: VsockAddr,
     ) -> Result<(), Error> {
+        // destination port should be zero or one, otherwise, connection should not
+        // be in VsockOnly state (not already connected/connecting to tipc).
+        assert!([0, 1].contains(&destination.port));
+
         let mut buffer = [0; IPC_PORT_PATH_MAX as usize];
         assert!(length < buffer.len());
         let mut data_len = self
@@ -319,8 +406,19 @@ where
             data_len -= 1;
         }
         let port_name = &buffer[0..data_len];
+        info!("port_name is {:?}", port_name);
+
         // should not contain any null bytes
         c.tipc_port_name = CString::new(port_name).ok();
+        info!("tipc port name set to {}", c.tipc_port_name());
+
+        self.vsock_connect_tipc(c)
+    }
+
+    fn vsock_connect_tipc(&self, c: &mut VsockConnection) -> Result<(), Error> {
+        let port_name = c.tipc_port_name.as_ref().expect("tipc port name has been set");
+        // invariant: port_name.count_bytes() + 1 <= IPC_PORT_PATH_MAX
+        debug_assert!(port_name.count_bytes() < IPC_PORT_PATH_MAX as usize);
 
         // Safety:
         // - `cid`` is a valid uuid because we use a bindgen'd constant
@@ -334,8 +432,8 @@ where
         let ret = unsafe {
             ipc_port_connect_async(
                 &zero_uuid,
-                c.tipc_port_name.as_ref().unwrap().as_ptr(),
-                data_len + /* null byte added by CString::new */ 1,
+                port_name.as_ptr(),
+                port_name.count_bytes() + 1, /* count_bytes excludes null-byte */
                 IPC_CONNECT_WAIT_FOR_PORT,
                 &mut (*c.href.as_mut_ptr()).handle,
             )
@@ -411,6 +509,10 @@ where
         Ok(())
     }
 
+    fn vsock_send_reset(&self, peer: VsockAddr, local_port: u32) {
+        let _ = self.connection_manager.lock().deref_mut().force_close(peer, local_port);
+    }
+
     fn print_stats(&self) {
         let guard = self.connections.lock();
         let connections = guard.deref();
@@ -420,35 +522,24 @@ where
     }
 }
 
-// Safety: each field of a `VsockDevice` is safe to transfer across thread boundaries
-// TODO: remove this once https://github.com/rcore-os/virtio-drivers/pull/146 lands
-unsafe impl<H, T> Send for VsockDevice<H, T>
-where
-    H: Hal,
-    T: Transport,
-{
-}
-
-// Safety: each field of a `VsockDevice` is safe to share between threads
-// TODO: remove this once https://github.com/rcore-os/virtio-drivers/pull/146 lands
-unsafe impl<H, T> Sync for VsockDevice<H, T>
-where
-    H: Hal,
-    T: Transport,
-{
-}
-
-pub(crate) fn vsock_rx_loop<H, T>(device: Arc<VsockDevice<H, T>>) -> Result<(), Error>
+pub(crate) fn vsock_rx_loop<M>(device: Arc<VsockDevice<M>>) -> Result<(), Error>
 where
-    H: Hal,
-    T: Transport,
+    M: VsockManager,
 {
-    let local_port = 1;
     let ten_ms = Duration::from_millis(10);
     let mut pending: Vec<VsockEvent> = vec![];
 
     debug!("starting vsock_rx_loop");
-    device.connection_manager.lock().deref_mut().listen(local_port);
+
+    // Accept connections on port zero and each name port in the port map
+    {
+        let mut connection_manager_guard = device.connection_manager.lock();
+        let connection_manager = connection_manager_guard.deref_mut();
+
+        for port in 0..PORT_MAP.len() as u32 {
+            connection_manager.listen(port);
+        }
+    }
 
     loop {
         // TODO: use interrupts instead of polling
@@ -466,7 +557,10 @@ where
 
         match event_type {
             VsockEventType::ConnectionRequest => {
-                device.vsock_rx_op_request(source, destination);
+                if let Err(e) = device.vsock_rx_op_request(source, destination) {
+                    error!("error during vsock connection request: {e:?}");
+                    device.vsock_send_reset(source, destination.port);
+                }
             }
             VsockEventType::Connected => {
                 panic!("outbound connections not supported");
@@ -475,11 +569,12 @@ where
                 debug!("recv destination: {destination:?}");
 
                 let connections = &mut *device.connections.lock();
-                let _ = vsock_connection_lookup(connections, source.port, |mut connection| {
+                let lp = destination.port;
+                let _ = vsock_connection_lookup_peer(connections, source, lp, |mut connection| {
                     if let Err(e) = match connection {
                         ref mut c @ VsockConnection {
                             state: VsockConnectionState::VsockOnly, ..
-                        } => device.vsock_connect_tipc(c, length, source, destination),
+                        } => device.vsock_connect_on_rx(c, length, source, destination),
                         ref mut c @ VsockConnection {
                             state: VsockConnectionState::Active, ..
                         } => device.vsock_rx_channel(c, length, source, destination),
@@ -509,12 +604,7 @@ where
                         }
                     } {
                         error!("failed to receive data from vsock connection:  {e:?}");
-                        // TODO: add reset function to device or connection?
-                        let _ = device
-                            .connection_manager
-                            .lock()
-                            .deref_mut()
-                            .force_close(connection.peer, connection.local_port);
+                        device.vsock_send_reset(connection.peer, connection.local_port);
 
                         return ConnectionStateAction::Remove;
                     }
@@ -527,7 +617,8 @@ where
             VsockEventType::Disconnected { reason } => {
                 debug!("disconnected from peer. reason: {reason:?}");
                 let connections = &mut *device.connections.lock();
-                let _ = vsock_connection_lookup(connections, source.port, |_connection| {
+                let lp = destination.port;
+                let _ = vsock_connection_lookup_peer(connections, source, lp, |_connection| {
                     ConnectionStateAction::Remove
                 })
                 .inspect_err(|_| {
@@ -543,10 +634,9 @@ where
     }
 }
 
-pub(crate) fn vsock_tx_loop<H, T>(device: Arc<VsockDevice<H, T>>) -> Result<(), Error>
+pub(crate) fn vsock_tx_loop<M>(device: Arc<VsockDevice<M>>) -> Result<(), Error>
 where
-    H: Hal,
-    T: Transport,
+    M: VsockManager,
 {
     let mut timeout = Duration::MAX;
     let ten_secs = Duration::from_secs(10);
@@ -578,12 +668,13 @@ where
             continue;
         }
 
-        let _ = vsock_connection_lookup(&mut device.connections.lock(), href.id(), |c| {
-            if !eq(c.href.as_mut_ptr() as *mut c_void, href.cookie()) {
+        let cookie = href.cookie();
+        let _ = vsock_connection_lookup_cookie(&mut device.connections.lock(), cookie, |c| {
+            if href.id() != c.href.id() {
                 panic!(
-                    "unexpected cookie {:?} != {:?} for connection {}",
-                    href.cookie(),
-                    c.href.as_mut_ptr(),
+                    "unexpected id {:?} != {:?} for connection {}",
+                    href.id(),
+                    c.href.id(),
                     c.tipc_port_name()
                 );
             }
@@ -689,3 +780,37 @@ where
         href.handle_decref();
     }
 }
+
+pub(crate) fn vsock_init<T: Transport + 'static + Send, H: Hal + 'static>(
+    driver: VirtIOSocket<H, T, 4096>,
+) -> Result<(), Error> {
+    let manager = VsockConnectionManager::new_with_capacity(driver, 4096);
+    let device_for_rx = Arc::new(VsockDevice::new(manager));
+    let device_for_tx = device_for_rx.clone();
+
+    // In some builds, stack overflows can occur on both threads when using 4k stacks
+    let stack_size = 8192usize;
+    Builder::new()
+        .name(c"virtio_vsock_rx")
+        .priority(Priority::HIGH)
+        .stack_size(stack_size)
+        .spawn(move || {
+            let ret = vsock_rx_loop(device_for_rx);
+            error!("vsock_rx_loop returned {:?}", ret);
+            ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
+        })
+        .map_err(|e| LkError::from_lk(e).unwrap_err())?;
+
+    Builder::new()
+        .name(c"virtio_vsock_tx")
+        .priority(Priority::HIGH)
+        .stack_size(stack_size)
+        .spawn(move || {
+            let ret = vsock_tx_loop(device_for_tx);
+            error!("vsock_tx_loop returned {:?}", ret);
+            ret.err().unwrap_or(LkError::NO_ERROR.into()).into_c()
+        })
+        .map_err(|e| LkError::from_lk(e).unwrap_err())?;
+
+    Ok(())
+}
diff --git a/include/kernel/mp.h b/include/kernel/mp.h
index bdad0264..5db9ed60 100644
--- a/include/kernel/mp.h
+++ b/include/kernel/mp.h
@@ -66,23 +66,23 @@ extern struct mp_state mp;
 
 static inline int mp_is_cpu_active(uint cpu)
 {
-    return mp.active_cpus & (1 << cpu);
+    return mp.active_cpus & (1U << cpu);
 }
 
 static inline int mp_is_cpu_idle(uint cpu)
 {
-    return mp.idle_cpus & (1 << cpu);
+    return mp.idle_cpus & (1U << cpu);
 }
 
 /* must be called with the thread lock held */
 static inline void mp_set_cpu_idle(uint cpu)
 {
-    mp.idle_cpus |= 1UL << cpu;
+    mp.idle_cpus |= 1U << cpu;
 }
 
 static inline void mp_set_cpu_busy(uint cpu)
 {
-    mp.idle_cpus &= ~(1UL << cpu);
+    mp.idle_cpus &= ~(1U << cpu);
 }
 
 static inline mp_cpu_mask_t mp_get_idle_mask(void)
@@ -92,12 +92,12 @@ static inline mp_cpu_mask_t mp_get_idle_mask(void)
 
 static inline void mp_set_cpu_realtime(uint cpu)
 {
-    mp.realtime_cpus |= 1UL << cpu;
+    mp.realtime_cpus |= 1U << cpu;
 }
 
 static inline void mp_set_cpu_non_realtime(uint cpu)
 {
-    mp.realtime_cpus &= ~(1UL << cpu);
+    mp.realtime_cpus &= ~(1U << cpu);
 }
 
 static inline mp_cpu_mask_t mp_get_realtime_mask(void)
diff --git a/include/kernel/mutex.h b/include/kernel/mutex.h
index 97b59787..1adfa47a 100644
--- a/include/kernel/mutex.h
+++ b/include/kernel/mutex.h
@@ -69,8 +69,6 @@ static bool is_mutex_held(mutex_t *m)
     return m->holder == get_current_thread();
 }
 
-bool extern_is_mutex_held(mutex_t *m);
-
 __END_CDECLS;
 #endif
 
diff --git a/include/shared/lk/list.h b/include/shared/lk/list.h
index 36f0ca3e..0019766c 100644
--- a/include/shared/lk/list.h
+++ b/include/shared/lk/list.h
@@ -49,7 +49,7 @@ static inline void list_clear_node(struct list_node *item)
     item->prev = item->next = 0;
 }
 
-static inline bool list_in_list(struct list_node *item)
+static inline bool list_in_list(const struct list_node *item)
 {
     if (item->prev == 0 && item->next == 0)
         return false;
diff --git a/kernel/mutex.c b/kernel/mutex.c
index 505140fb..0a409e85 100644
--- a/kernel/mutex.c
+++ b/kernel/mutex.c
@@ -142,7 +142,3 @@ status_t mutex_release(mutex_t *m)
     THREAD_UNLOCK(state);
     return NO_ERROR;
 }
-
-bool extern_is_mutex_held(mutex_t *m) {
-    return is_mutex_held(m);
-}
diff --git a/lib/binary_search_tree/include/lib/binary_search_tree.h b/lib/binary_search_tree/include/lib/binary_search_tree.h
index e9cd1a01..4a44c45c 100644
--- a/lib/binary_search_tree/include/lib/binary_search_tree.h
+++ b/lib/binary_search_tree/include/lib/binary_search_tree.h
@@ -68,6 +68,16 @@ static inline void bst_root_initialize(struct bst_root *root) {
     root->root = NULL;
 }
 
+/**
+ * bst_is_empty - Check if the binary search tree is empty.
+ * @root:       Tree to check
+ *
+ * Return: %true if there are no nodes in the tree, %false otherwise.
+ */
+static inline bool bst_is_empty(struct bst_root *root) {
+    return !root->root;
+}
+
 /**
  * bst_compare_t - Compare function provided by caller
  * @a: First node to compare
diff --git a/lib/libhypervisor/include/lib/libhypervisor/libhypervisor.h b/lib/libhypervisor/include/lib/libhypervisor/libhypervisor.h
new file mode 100644
index 00000000..50c2eebb
--- /dev/null
+++ b/lib/libhypervisor/include/lib/libhypervisor/libhypervisor.h
@@ -0,0 +1,24 @@
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
+int hypervisor_mmio_map_region(paddr_t paddr, size_t size);
diff --git a/lib/libhypervisor/rules.mk b/lib/libhypervisor/rules.mk
new file mode 100644
index 00000000..efa28cd0
--- /dev/null
+++ b/lib/libhypervisor/rules.mk
@@ -0,0 +1,28 @@
+LOCAL_DIR := $(GET_LOCAL_DIR)
+MODULE := $(LOCAL_DIR)
+MODULE_CRATE_NAME := hypervisor
+MODULE_SRCS := \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_EXPORT_INCLUDES += \
+	$(LOCAL_DIR)/include
+
+MODULE_LIBRARY_DEPS := \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,spin) \
+
+# hypervisor_backends supports arm64 and x86-64 only for now
+ifeq ($(SUBARCH),x86-64)
+MODULE_LIBRARY_DEPS += \
+	packages/modules/Virtualization/libs/libhypervisor_backends \
+
+endif
+ifeq ($(ARCH),arm64)
+MODULE_LIBRARY_DEPS += \
+	packages/modules/Virtualization/libs/libhypervisor_backends \
+
+endif
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
diff --git a/dev/virtio/vsock-rust/src/kvm.rs b/lib/libhypervisor/src/hyp.rs
similarity index 50%
rename from dev/virtio/vsock-rust/src/kvm.rs
rename to lib/libhypervisor/src/hyp.rs
index 0d359908..f3234727 100644
--- a/dev/virtio/vsock-rust/src/kvm.rs
+++ b/lib/libhypervisor/src/hyp.rs
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2024 Google Inc. All rights reserved
+ * Copyright (c) 2025 Google Inc. All rights reserved
  *
  * Permission is hereby granted, free of charge, to any person obtaining
  * a copy of this software and associated documentation files
@@ -22,18 +22,91 @@
  */
 
 use log::error;
-
-use num_integer::Integer;
+use spin::Once;
 
 use hypervisor_backends::get_mem_sharer;
-use hypervisor_backends::Error;
+use hypervisor_backends::Error as HypError;
 use hypervisor_backends::KvmError;
 
-use spin::Once;
+#[cfg(target_arch = "aarch64")]
+use hypervisor_backends::get_mmio_guard;
+
+#[cfg(target_arch = "aarch64")]
+use rust_support::Error as LkError;
 
 /// Result type with kvm error.
 pub type KvmResult<T> = Result<T, KvmError>;
 
+/// The mmio granule size used by the hypervisor
+#[cfg(target_arch = "aarch64")]
+static MMIO_GRANULE: Once<Result<usize, LkError>> = Once::new();
+
+#[cfg(target_arch = "aarch64")]
+fn get_mmio_granule() -> Result<usize, LkError> {
+    *MMIO_GRANULE.call_once(|| {
+        let hypervisor = get_mmio_guard()
+            .ok_or(LkError::ERR_NOT_SUPPORTED)
+            .inspect_err(|_| error!("failed to get hypervisor"))?;
+
+        let granule = hypervisor
+            .granule()
+            .inspect_err(|e| error!("failed to get granule: {e:?}"))
+            .map_err(|_| LkError::ERR_NOT_SUPPORTED)?;
+
+        if !granule.is_power_of_two() {
+            error!("invalid memory protection granule");
+            return Err(LkError::ERR_INVALID_ARGS);
+        }
+
+        Ok(granule)
+    })
+}
+
+/// # Safety
+///  - paddr must be a valid physical address
+///  - paddr + size must be a valid physical address
+///  - the caller must be aware that after the call the [paddr .. paddr + size] memory
+///    is available for reading by the host.
+#[cfg(target_arch = "aarch64")]
+pub unsafe fn mmio_map_region(paddr: usize, size: usize) -> Result<(), LkError> {
+    let Some(hypervisor) = get_mmio_guard() else {
+        return Ok(());
+    };
+    let hypervisor_page_size = get_mmio_granule()?;
+
+    if !paddr.is_multiple_of(hypervisor_page_size) {
+        error!("paddr not aligned");
+        return Err(LkError::ERR_INVALID_ARGS);
+    }
+
+    if !size.is_multiple_of(hypervisor_page_size) {
+        error!("size ({size}) not aligned to page size ({hypervisor_page_size})");
+        return Err(LkError::ERR_INVALID_ARGS);
+    }
+
+    for page in (paddr..paddr + size).step_by(hypervisor_page_size) {
+        hypervisor.map(page).map_err(|err| {
+            error!("failed to mmio guard map page 0x{page:x}: {err}");
+
+            // unmap any previously shared mmio pages on error
+            // if sharing fail on the first page, the half-open range below is empty
+            for prev in (paddr..page).step_by(hypervisor_page_size) {
+                // keep going even if we fail
+                let _ = hypervisor.unmap(prev);
+            }
+
+            match err {
+                HypError::KvmError(KvmError::NotSupported, _) => LkError::ERR_NOT_SUPPORTED,
+                HypError::KvmError(KvmError::InvalidParameter, _) => LkError::ERR_INVALID_ARGS,
+                HypError::KvmError(_, _) => LkError::ERR_GENERIC,
+                _ => panic!("MMIO Guard unmap returned unexpected error: {err:?}"),
+            }
+        })?;
+    }
+
+    Ok(())
+}
+
 /// The granule size used by the hypervisor
 static GRANULE: Once<KvmResult<usize>> = Once::new();
 
@@ -54,18 +127,20 @@ fn get_granule() -> KvmResult<usize> {
     })
 }
 
-pub(crate) fn share_pages(paddr: usize, size: usize) -> KvmResult<()> {
-    let hypervisor = get_mem_sharer()
-        .ok_or(KvmError::NotSupported)
-        .inspect_err(|_| error!("failed to get hypervisor"))?;
+pub fn share_pages(paddr: usize, size: usize) -> KvmResult<()> {
+    let hypervisor = match get_mem_sharer() {
+        Some(h) => h,
+        None => return Ok(()), // not in a protected vm
+    };
+
     let hypervisor_page_size = get_granule()?;
 
-    if !paddr.is_multiple_of(&hypervisor_page_size) {
+    if !paddr.is_multiple_of(hypervisor_page_size) {
         error!("paddr not aligned");
         return Err(KvmError::InvalidParameter);
     }
 
-    if !size.is_multiple_of(&hypervisor_page_size) {
+    if !size.is_multiple_of(hypervisor_page_size) {
         error!("size ({size}) not aligned to page size ({hypervisor_page_size})");
         return Err(KvmError::InvalidParameter);
     }
@@ -82,7 +157,7 @@ pub(crate) fn share_pages(paddr: usize, size: usize) -> KvmResult<()> {
             }
 
             match err {
-                Error::KvmError(e, _) => e,
+                HypError::KvmError(e, _) => e,
                 _ => panic!("unexpected share error: {err:?}"),
             }
         })?;
@@ -91,24 +166,20 @@ pub(crate) fn share_pages(paddr: usize, size: usize) -> KvmResult<()> {
     Ok(())
 }
 
-pub(crate) fn unshare_pages(paddr: usize, size: usize) -> KvmResult<()> {
-    let hypervisor = get_mem_sharer()
-        .ok_or(KvmError::NotSupported)
-        .inspect_err(|_| error!("failed to get hypervisor"))?;
+pub fn unshare_pages(paddr: usize, size: usize) -> KvmResult<()> {
+    let hypervisor = match get_mem_sharer() {
+        Some(h) => h,
+        None => return Ok(()), // not in a protected vm
+    };
 
     let hypervisor_page_size = get_granule()?;
 
-    if !hypervisor_page_size.is_power_of_two() {
-        error!("invalid memory protection granule");
-        return Err(KvmError::InvalidParameter);
-    }
-
-    if !paddr.is_multiple_of(&hypervisor_page_size) {
+    if !paddr.is_multiple_of(hypervisor_page_size) {
         error!("paddr not aligned");
         return Err(KvmError::InvalidParameter);
     }
 
-    if !size.is_multiple_of(&hypervisor_page_size) {
+    if !size.is_multiple_of(hypervisor_page_size) {
         error!("size ({size}) not aligned to page size ({hypervisor_page_size})");
         return Err(KvmError::InvalidParameter);
     }
@@ -118,7 +189,7 @@ pub(crate) fn unshare_pages(paddr: usize, size: usize) -> KvmResult<()> {
             error!("failed to unshare page 0x{page:x}: {err:?}");
 
             match err {
-                Error::KvmError(e, _) => e,
+                HypError::KvmError(e, _) => e,
                 _ => panic!("unexpected unshare error: {err:?}"),
             }
         })?;
diff --git a/lib/libhypervisor/src/lib.rs b/lib/libhypervisor/src/lib.rs
new file mode 100644
index 00000000..ba447a6e
--- /dev/null
+++ b/lib/libhypervisor/src/lib.rs
@@ -0,0 +1,56 @@
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
+#![no_std]
+#![feature(unsigned_is_multiple_of)]
+
+use core::ffi::c_int;
+
+use rust_support::paddr_t;
+use rust_support::Error as LkError;
+
+#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
+mod hyp;
+
+// TODO: Enable for x86_64 once it's supported.
+#[cfg(target_arch = "aarch64")]
+pub use hyp::mmio_map_region;
+
+#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
+pub use hyp::{share_pages, unshare_pages};
+
+/// # Safety
+/// Actually not unsafe for targets other then aarch64
+#[cfg(not(target_arch = "aarch64"))]
+pub unsafe fn mmio_map_region(_paddr: usize, _size: usize) -> Result<(), LkError> {
+    Err(LkError::ERR_NOT_SUPPORTED)
+}
+
+/// # Safety
+///  - paddr must be a valid physical address
+///  - paddr + size must be a valid physical address
+///  - the caller must be aware that after the call the [paddr .. paddr + size] memory
+///    is available for reading by the host.
+#[no_mangle]
+pub unsafe extern "C" fn hypervisor_mmio_map_region(paddr: paddr_t, size: usize) -> c_int {
+    crate::mmio_map_region(paddr, size).err().unwrap_or(LkError::NO_ERROR).into()
+}
diff --git a/lib/rust_support/bindings.h b/lib/rust_support/bindings.h
index a6be22ff..95ddcd8f 100644
--- a/lib/rust_support/bindings.h
+++ b/lib/rust_support/bindings.h
@@ -1,15 +1,45 @@
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
 #include <arch/mmu.h>
+#include <kernel/event.h>
 #include <kernel/mutex.h>
 #include <kernel/thread.h>
 #include <kernel/vm.h>
+#include <lib/ktipc/ktipc.h>
 #include <lib/trusty/handle.h>
 #include <lib/trusty/handle_set.h>
 #include <lib/trusty/ipc.h>
 #include <lib/trusty/uuid.h>
+#include <lib/vmm_obj_service/vmm_obj_service.h>
 #include <lk/init.h>
 #include <panic.h>
+#include <spinlock.h>
 #include <stdio.h>
 #include <streams.h> /* stubs for stdin, stdout, stderr */
+#include "wrappers/include/reflist.h"
 
 #include "error.h"
 #include "config.h" /* for LK_LOGLEVEL_RUST */
diff --git a/lib/rust_support/event.rs b/lib/rust_support/event.rs
new file mode 100644
index 00000000..33e459dc
--- /dev/null
+++ b/lib/rust_support/event.rs
@@ -0,0 +1,73 @@
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
+use crate::sys::{event_init, event_signal, event_wait_timeout};
+use crate::sys::{event_t, status_t, uint};
+use crate::INFINITE_TIME;
+use alloc::boxed::Box;
+use core::cell::UnsafeCell;
+use core::mem;
+
+pub use crate::sys::EVENT_FLAG_AUTOUNSIGNAL;
+
+// `event_t`s should not move since they contain wait queues which contains
+// linked list nodes. The kernel may write back to the non-node fields as well.
+// TODO: add Unpin as a negative trait bound once the rustc feature is stabilized.
+// impl !Unpin for event_t {}
+
+#[derive(Debug)]
+pub struct Event(Box<UnsafeCell<event_t>>);
+
+impl Event {
+    pub fn new(initial: bool, flags: uint) -> Self {
+        // SAFETY: event_t is a C type which can be zeroed out
+        let event = unsafe { mem::zeroed() };
+        let mut boxed_event = Box::new(UnsafeCell::new(event));
+        // SAFETY: event_init just writes to the fields of event_t. The self-referential `wait`
+        // field is written to after the event_t is placed on the heap so it won't become
+        // invalidated until it's dropped.
+        unsafe { event_init(boxed_event.get_mut(), initial, flags) };
+        Self(boxed_event)
+    }
+
+    pub fn wait(&self) -> status_t {
+        // SAFETY: One or more threads are allowed to wait for an event to be signaled
+        unsafe { event_wait_timeout(self.0.get(), INFINITE_TIME) }
+    }
+
+    pub fn signal(&self) -> status_t {
+        // SAFETY: Events may be signaled from any thread or interrupt context if the reschedule
+        // parameter is false
+        unsafe {
+            event_signal(self.0.get(), false /* reschedule */)
+        }
+    }
+}
+
+// SAFETY: More than one thread may wait using an &Event but only one will be woken up and change
+// its signaled field. &Event provides no other APIs to modify its state
+unsafe impl Sync for Event {}
+
+// SAFETY: Event is heap allocated so it may be freely sent across threads without invalidating it.
+// It may also be waited on and signaled from any thread.
+unsafe impl Send for Event {}
diff --git a/lib/rust_support/handle.rs b/lib/rust_support/handle.rs
index 6e10b997..68f88fff 100644
--- a/lib/rust_support/handle.rs
+++ b/lib/rust_support/handle.rs
@@ -40,9 +40,9 @@ pub use crate::sys::IPC_HANDLE_POLL_SEND_UNBLOCKED;
 pub use crate::sys::handle;
 pub use crate::sys::handle_ref;
 
-use crate::sys::list_node;
-
 use crate::handle_set::handle_set_detach_ref;
+use crate::sys::handle_ref_is_attached;
+use crate::sys::list_node;
 
 impl Default for list_node {
     fn default() -> Self {
@@ -79,15 +79,19 @@ impl Default for handle_ref {
 pub struct HandleRef {
     // Box the `handle_ref` so it doesn't get moved with the `HandleRef`
     inner: Box<handle_ref>,
-    pub(crate) attached: bool,
 }
 
 impl HandleRef {
+    pub fn is_attached(&self) -> bool {
+        // SAFETY: `self.inner` was initialized, and `handle_ref_is_attached`
+        // is otherwise safe to call no matter the state of the `handle_ref`.
+        unsafe { handle_ref_is_attached(&*self.inner) }
+    }
+
     pub fn detach(&mut self) {
-        if self.attached {
+        if self.is_attached() {
             // Safety: `inner` was initialized and attached to a handle set
             unsafe { handle_set_detach_ref(&mut *self.inner) }
-            self.attached = false;
         }
     }
 
@@ -108,8 +112,12 @@ impl HandleRef {
         unsafe { handle_decref(self.inner.handle) };
     }
 
+    pub fn as_ptr(&self) -> *const handle_ref {
+        Box::as_ptr(&self.inner)
+    }
+
     pub fn as_mut_ptr(&mut self) -> *mut handle_ref {
-        &mut *self.inner
+        Box::as_mut_ptr(&mut self.inner)
     }
 
     pub fn cookie(&self) -> *mut c_void {
diff --git a/lib/rust_support/handle_set.rs b/lib/rust_support/handle_set.rs
index e7b900d1..c74e272d 100644
--- a/lib/rust_support/handle_set.rs
+++ b/lib/rust_support/handle_set.rs
@@ -58,16 +58,13 @@ impl HandleSet {
     }
 
     pub fn attach(&self, href: &mut HandleRef) -> Result<(), Error> {
-        if href.attached {
-            panic!("HandleRef is already attached.");
-        }
+        assert!(!href.is_attached(), "HandleRef is already attached.");
         // Safety:
         // `self` contains a properly initialized handle
         // `href.inner` is a properly initialized handle_ref that is not attached
         let ret = unsafe { handle_set_attach(self.0, href.as_mut_ptr()) };
         Error::from_lk(ret)?;
 
-        href.attached = true;
         Ok(())
     }
 
diff --git a/lib/rust_support/interrupt.rs b/lib/rust_support/interrupt.rs
new file mode 100644
index 00000000..ad88d3ad
--- /dev/null
+++ b/lib/rust_support/interrupt.rs
@@ -0,0 +1,253 @@
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
+use bitflags::bitflags;
+
+use crate::sys::lk_interrupt_restore;
+use crate::sys::lk_interrupt_save;
+use crate::sys::lk_ints_disabled;
+use crate::sys::spin_lock_save_flags_t;
+use crate::sys::spin_lock_saved_state_t;
+use crate::sys::SPIN_LOCK_FLAG_INTERRUPTS;
+use crate::sys::SPIN_LOCK_FLAG_IRQ;
+use crate::sys::SPIN_LOCK_FLAG_IRQ_FIQ;
+
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+use crate::sys::{lk_fiqs_disabled, SPIN_LOCK_FLAG_FIQ};
+
+fn interrupt_save(state: &mut spin_lock_saved_state_t, flags: spin_lock_save_flags_t) {
+    // SAFETY: `lk_interrupt_save` can be called in any context,
+    // and the `statep` arg is from a `&mut`, so it can be written to.
+    unsafe { lk_interrupt_save(state, flags) }
+}
+
+/// `state` should be from the corresponding call to [`interrupt_save`],
+/// and `flags` should be the same `flags` from that [`interrupt_save`] call.
+fn interrupt_restore(state: spin_lock_saved_state_t, flags: spin_lock_save_flags_t) {
+    // SAFETY: `lk_interrupt_restore` is safe and can be called in any context.
+    unsafe { lk_interrupt_restore(state, flags) }
+}
+
+pub fn irqs_disabled() -> bool {
+    // SAFETY: `lk_ints_disabled` can be called in any context.
+    unsafe { lk_ints_disabled() }
+}
+
+#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+fn fiqs_disabled() -> bool {
+    // SAFETY: `lk_fiqs_disabled` can be called in any context.
+    unsafe { lk_fiqs_disabled() }
+}
+
+/// See [`InterruptFlags::check`] for what combinations of [`InterruptFlags`]
+/// are allowed to be disabled compared to what is already disabled.
+#[derive(Clone, Copy, PartialEq, Eq)]
+pub struct InterruptFlags(u32);
+
+bitflags! {
+    impl InterruptFlags: u32 {
+        /// Disable IRQs (interrupt requests).
+        ///
+        /// IRQs (without FIQs) cannot safely (risking deadlocks)
+        /// be disabled if only FIQs are currently disabled.
+        /// (see [`Self::check`] for more).
+        const IRQ = SPIN_LOCK_FLAG_IRQ;
+
+        /// Disable FIQs (fast interrupt requests).
+        ///
+        /// These are generally lower latency and higher priority than IRQs.
+        ///
+        /// FIQs (without IRQs) cannot safely (risking deadlocks)
+        /// be disabled if only IRQs are currently disabled
+        /// (see [`Self::check`] for more).
+        ///
+        /// Currently, FIQs do not exist on `x86`/`x86_64` `target_arch`es,
+        /// while they always exist on `arm`/`aarch64` `target_arch`es.
+        /// However, in the latter, they are sometimes merged with IRQs.
+        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+        const FIQ = SPIN_LOCK_FLAG_FIQ;
+
+        /// Disable both IRQs and FIQs.
+        ///
+        /// This is still defined for convenience on platforms with no FIQs,
+        /// where this does not disable FIQs, but FIQs just don't exist at all.
+        const IRQ_FIQ = SPIN_LOCK_FLAG_IRQ_FIQ;
+
+        /// Disable interrupts in general in a platform-agnostic way.
+        ///
+        /// On `arm`/`aarch64` `target_arch`es, this only disables IRQs.
+        const INTERRUPTS = SPIN_LOCK_FLAG_INTERRUPTS;
+    }
+}
+
+impl Default for InterruptFlags {
+    fn default() -> Self {
+        Self::INTERRUPTS
+    }
+}
+
+impl InterruptFlags {
+    const fn as_raw(&self) -> spin_lock_save_flags_t {
+        self.bits()
+    }
+
+    /// Returns `self` if `select` is `true`,
+    /// or [`Self::empty`] if `select` is `false`.
+    pub const fn select(self, select: bool) -> Self {
+        if select {
+            self
+        } else {
+            Self::empty()
+        }
+    }
+
+    /// Checks if these [`InterruptFlags`] can safely (risking potential deadlocks) be disabled
+    /// depending on what is currently already disabled.
+    ///
+    /// More specifically, considering only [IRQ]s and [FIQ]s,
+    /// if only [IRQ]s are requested, then only [FIQ]s being disabled already is not allowed,
+    /// and if only [FIQ]s are requested, then only [IRQ]s being disabled already is not allowed.
+    ///
+    /// Panics on error.
+    ///
+    /// [IRQ]: Self::IRQ
+    /// [FIQ]: Self::FIQ
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    #[track_caller]
+    pub fn check(&self) {
+        let irq = Self::IRQ;
+        let fiq = Self::FIQ;
+
+        let this = *self & (irq | fiq);
+        let disabled = irq.select(irqs_disabled()) | fiq.select(fiqs_disabled());
+
+        if (this == irq && disabled == fiq) || (this == fiq && disabled == irq) {
+            error(this, disabled);
+        }
+
+        #[track_caller]
+        // This function is cold, so don't inline it to save on code size,
+        // which helps the rest of the function be inlined more easily.
+        #[cold]
+        #[inline(never)]
+        fn error(this: InterruptFlags, disabled: InterruptFlags) {
+            let [this, disabled] =
+                [this, disabled]
+                    .map(|flags| if flags == InterruptFlags::IRQ { "IRQ" } else { "FIQ" });
+            panic!("can't disable only {this}s for a SpinLock when only {disabled}s are currently disabled");
+        }
+    }
+
+    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
+    pub fn check(&self) {
+        // FIQs don't exist.
+    }
+}
+
+/// Go through this `trait` instead of just [`InterruptFlags`]
+/// so that when the [`InterruptFlags`] are known at compile time,
+/// we don't need to store them (see [`IRQInterruptFlags`]).
+pub trait GetInterruptFlags: Clone + Copy + Send + Sync {
+    /// This should always return the same flags for the same `self`.
+    fn get(&self) -> InterruptFlags;
+}
+
+impl GetInterruptFlags for InterruptFlags {
+    fn get(&self) -> InterruptFlags {
+        *self
+    }
+}
+
+/// A ZST implementation of [`GetInterruptFlags`] that stores the [`InterruptFlags`] at compile time.
+/// Most uses should use this (with convenient type aliases in [`interrupt::flags`])
+/// instead of [`InterruptFlags`] directly
+///
+/// [`interrupt::flags`]: crate::interrupt::flags
+// TODO use `#![feature(adt_const_params)]` once stabilized,
+// with `const FLAGS: InterruptFlags` instead of `u32`.
+#[derive(Clone, Copy)]
+pub struct ConstInterruptFlags<const FLAGS: u32>;
+
+impl<const FLAGS: u32> GetInterruptFlags for ConstInterruptFlags<FLAGS> {
+    fn get(&self) -> InterruptFlags {
+        // Truncate instead of retain since the `FLAGS: u32` is unchecked.
+        InterruptFlags::from_bits_truncate(FLAGS)
+    }
+}
+
+pub mod flags {
+    use super::*;
+
+    // Type aliases can't be used as constructors,
+    // so we define separate `const`s/constructors.
+    // This makes initialization much simpler.
+
+    pub type None = ConstInterruptFlags<{ InterruptFlags::empty().bits() }>;
+    pub const NONE: None = ConstInterruptFlags;
+
+    pub type Irq = ConstInterruptFlags<{ InterruptFlags::IRQ.bits() }>;
+    pub const IRQ: Irq = ConstInterruptFlags;
+
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub type Fiq = ConstInterruptFlags<{ InterruptFlags::FIQ.bits() }>;
+    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
+    pub const FIQ: Fiq = ConstInterruptFlags;
+
+    pub type IrqFiq = ConstInterruptFlags<{ InterruptFlags::IRQ_FIQ.bits() }>;
+    pub const IRQ_FIQ: IrqFiq = ConstInterruptFlags;
+
+    pub type Interrupts = ConstInterruptFlags<{ InterruptFlags::INTERRUPTS.bits() }>;
+    pub const INTERRUPTS: Interrupts = ConstInterruptFlags;
+
+    pub type All = ConstInterruptFlags<{ InterruptFlags::all().bits() }>;
+    pub const ALL: All = ConstInterruptFlags;
+}
+
+pub struct InterruptState<F: GetInterruptFlags> {
+    state: spin_lock_saved_state_t,
+    flags: F,
+}
+
+impl<F: GetInterruptFlags> InterruptState<F> {
+    /// Disables interrupts and saves the interrupt state.
+    pub fn save(flags: F) -> Self {
+        let mut state = Default::default();
+        let raw_flags = flags.get().as_raw();
+        interrupt_save(&mut state, raw_flags);
+        Self { state, flags }
+    }
+}
+
+impl<F: GetInterruptFlags> Drop for InterruptState<F> {
+    fn drop(&mut self) {
+        let raw_flags = self.flags.get().as_raw();
+        interrupt_restore(self.state, raw_flags);
+    }
+}
+
+impl<F: GetInterruptFlags> InterruptState<F> {
+    /// A more explicit restore, equivalent to [`drop`].
+    pub fn restore(self) {
+        drop(self)
+    }
+}
diff --git a/lib/rust_support/ipc.rs b/lib/rust_support/ipc.rs
index 9e74e15e..115677e6 100644
--- a/lib/rust_support/ipc.rs
+++ b/lib/rust_support/ipc.rs
@@ -24,7 +24,10 @@
 use core::ptr::null_mut;
 
 pub use crate::sys::ipc_get_msg;
+pub use crate::sys::ipc_port_accept;
 pub use crate::sys::ipc_port_connect_async;
+pub use crate::sys::ipc_port_create;
+pub use crate::sys::ipc_port_publish;
 pub use crate::sys::ipc_put_msg;
 pub use crate::sys::ipc_read_msg;
 pub use crate::sys::ipc_send_msg;
@@ -33,8 +36,11 @@ pub use crate::sys::iovec_kern;
 pub use crate::sys::ipc_msg_info;
 pub use crate::sys::ipc_msg_kern;
 
+pub use crate::sys::kernel_uuid;
 pub use crate::sys::zero_uuid;
 pub use crate::sys::IPC_CONNECT_WAIT_FOR_PORT;
+pub use crate::sys::IPC_PORT_ALLOW_NS_CONNECT;
+pub use crate::sys::IPC_PORT_ALLOW_TA_CONNECT;
 pub use crate::sys::IPC_PORT_PATH_MAX;
 
 impl Default for ipc_msg_kern {
diff --git a/dev/virtio/vsock-rust/src/pci/arch/x86_64.rs b/lib/rust_support/ktipc.rs
similarity index 61%
rename from dev/virtio/vsock-rust/src/pci/arch/x86_64.rs
rename to lib/rust_support/ktipc.rs
index 1bf5f43d..44dbc14a 100644
--- a/dev/virtio/vsock-rust/src/pci/arch/x86_64.rs
+++ b/lib/rust_support/ktipc.rs
@@ -21,27 +21,22 @@
  * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */
 
-use core::ptr::NonNull;
+pub use crate::sys::ktipc_port_acl;
+pub use crate::sys::ktipc_server;
+pub use crate::sys::ktipc_server_init;
+pub use crate::sys::ktipc_server_start;
+pub use crate::sys::uuid;
 
-use virtio_drivers::BufferDirection;
-use virtio_drivers::PhysAddr;
+use core::ffi::CStr;
+use trusty_std::boxed::Box;
 
-use rust_support::vmm::vaddr_to_paddr;
-
-pub(crate) fn dma_alloc_share(_paddr: usize, _size: usize) {}
-pub(crate) fn dma_dealloc_unshare(_paddr: PhysAddr, _size: usize) {}
-
-// Safety: buffer must be a valid kernel virtual address for the duration of the call.
-pub(crate) unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
-    // no-op on x86_64
-    // Safety: buffer is a valid kernel virtual address
-    unsafe { vaddr_to_paddr(buffer.as_ptr().cast()) }
-}
-
-// Safety: not actually unsafe.
-pub(crate) unsafe fn unshare(
-    _paddr: PhysAddr,
-    _buffer: NonNull<[u8]>,
-    _direction: BufferDirection,
-) {
+// TODO(b/384572144): Port ktipc_server to rust instead of using FFI.
+pub fn ktipc_server_new(name: &'static CStr) -> Box<ktipc_server> {
+    let mut srv = Box::<ktipc_server>::new_uninit();
+    // SAFETY: Initializes object declared above. name is static.
+    unsafe {
+        ktipc_server_init(srv.as_mut_ptr(), name.as_ptr());
+    }
+    // SAFETY: Initialized above with a function that cannot fail.
+    unsafe { srv.assume_init() }
 }
diff --git a/lib/rust_support/lib.rs b/lib/rust_support/lib.rs
index d4d580d8..7e5bc4f7 100644
--- a/lib/rust_support/lib.rs
+++ b/lib/rust_support/lib.rs
@@ -28,6 +28,11 @@
 // C string literals were stabilized in Rust 1.77
 #![cfg_attr(not(version("1.77")), feature(c_str_literals))]
 #![deny(unsafe_op_in_unsafe_fn)]
+// new_uninit is stable as of Rust 1.82
+#![cfg_attr(not(version("1.82")), feature(new_uninit))]
+// raw_ref_op is stable as of Rust 1.82
+#![cfg_attr(not(version("1.82")), feature(raw_ref_op))]
+#![feature(box_as_ptr)]
 
 use alloc::format;
 use core::ffi::CStr;
@@ -38,24 +43,34 @@ mod sys {
     #![allow(unused)]
     #![allow(non_camel_case_types)]
     #![allow(non_upper_case_globals)]
+    #![allow(unsafe_op_in_unsafe_fn)]
+    #![allow(clippy::missing_safety_doc)]
     use num_derive::FromPrimitive;
     include!(env!("BINDGEN_INC_FILE"));
 }
 
 pub mod err;
+pub mod event;
 pub mod handle;
 pub mod handle_set;
 pub mod init;
+pub mod interrupt;
 pub mod ipc;
+pub mod ktipc;
 pub mod log;
 pub mod macros;
 pub mod mmu;
+pub mod spinlock;
 pub mod sync;
 pub mod thread;
+pub mod uuid;
 pub mod vmm;
 
+pub use sys::lk_obj_ref_init;
+pub use sys::obj_ref;
 pub use sys::paddr_t;
 pub use sys::status_t;
+pub use sys::uuid_t;
 pub use sys::vaddr_t;
 pub use sys::Error;
 
diff --git a/lib/rust_support/rules.mk b/lib/rust_support/rules.mk
index 56ad372b..fd23e763 100644
--- a/lib/rust_support/rules.mk
+++ b/lib/rust_support/rules.mk
@@ -34,9 +34,12 @@ MODULE_SRCS := \
 MODULE_ADD_IMPLICIT_DEPS := false
 
 MODULE_DEPS := \
+	$(call FIND_CRATE,bitflags) \
 	$(call FIND_CRATE,num-derive) \
 	$(call FIND_CRATE,num-traits) \
 	$(call FIND_CRATE,log) \
+	trusty/kernel/lib/ktipc \
+	trusty/kernel/lib/vmm_obj_service \
 	trusty/user/base/lib/liballoc-rust \
 	trusty/user/base/lib/libcompiler_builtins-rust \
 	trusty/user/base/lib/libcore-rust \
@@ -45,6 +48,9 @@ MODULE_DEPS := \
 
 MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	_panic \
+	event_init \
+	event_signal \
+	event_wait_timeout \
 	fflush \
 	fputs \
 	handle_close \
@@ -54,11 +60,25 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	handle_set_create \
 	handle_set_wait \
 	handle_wait \
+	handle_ref_is_attached \
 	ipc_get_msg \
+	ipc_port_accept \
 	ipc_port_connect_async \
+	ipc_port_create \
+	ipc_port_publish \
 	ipc_put_msg \
 	ipc_read_msg \
 	ipc_send_msg \
+	ktipc_server_init \
+	ktipc_server_start \
+	lk_fiqs_disabled \
+	lk_interrupt_restore \
+	lk_interrupt_save \
+	lk_ints_disabled \
+	lk_obj_ref_init \
+	lk_spin_lock \
+	lk_spin_trylock \
+	lk_spin_unlock \
 	lk_stdin \
 	lk_stdout \
 	lk_stderr \
@@ -67,36 +87,67 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	mutex_init \
 	mutex_release \
 	thread_create \
+	thread_join \
 	thread_resume \
 	thread_sleep_ns \
 	vaddr_to_paddr \
+	vmm_alloc \
+	vmm_alloc_obj \
 	vmm_alloc_physical_etc \
 	vmm_alloc_contiguous \
 	vmm_free_region \
+	vmm_get_obj \
+	vmm_obj_del_ref \
+	vmm_obj_slice_init \
+	vmm_obj_slice_release \
+	vmm_obj_service_add \
+	vmm_obj_service_create_ro \
+	vmm_obj_service_destroy \
 
 MODULE_BINDGEN_ALLOW_TYPES := \
 	Error \
+	event_t \
 	handle \
 	handle_ref \
 	iovec_kern \
 	ipc_msg_.* \
+	ktipc_port_acl \
+	ktipc_server \
 	lk_init_.* \
 	lk_time_.* \
+	obj_ref \
+	spin_lock_save_flags_t \
+	spin_lock_saved_state_t \
+	spin_lock_t \
 	trusty_ipc_event_type \
+	uuid \
+	uuid_t \
+	vmm_obj \
+	vmm_obj_service \
+	vmm_obj_slice \
 
 MODULE_BINDGEN_ALLOW_VARS := \
 	.*_PRIORITY \
 	_kernel_aspace \
 	ARCH_MMU_FLAG_.* \
 	DEFAULT_STACK_SIZE \
+	EVENT_FLAG_AUTOUNSIGNAL \
 	FILE \
 	IPC_CONNECT_WAIT_FOR_PORT \
 	IPC_HANDLE_POLL_.* \
+	IPC_PORT_ALLOW_NS_CONNECT \
+	IPC_PORT_ALLOW_TA_CONNECT \
 	IPC_PORT_PATH_MAX \
+	kernel_uuid \
 	LK_LOGLEVEL_RUST \
 	NUM_PRIORITIES \
 	PAGE_SIZE \
 	PAGE_SIZE_SHIFT \
+	SPIN_LOCK_FLAG_FIQ \
+	SPIN_LOCK_FLAG_INTERRUPTS \
+	SPIN_LOCK_FLAG_IRQ \
+	SPIN_LOCK_FLAG_IRQ_FIQ \
+	SPIN_LOCK_INITIAL_VALUE \
 	zero_uuid \
 
 MODULE_BINDGEN_FLAGS := \
@@ -110,6 +161,10 @@ MODULE_BINDGEN_FLAGS := \
 
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
+# This lets us include wrappers/include/reflist.h instead of the wrapped header:
+# trusty/kernel/shared/lk/reflist.h.
+MODULE_INCLUDES := $(LOCAL_DIR)
+
 MODULE_RUSTFLAGS += \
 	-A clippy::disallowed_names \
 	-A clippy::type-complexity \
diff --git a/lib/rust_support/spinlock.rs b/lib/rust_support/spinlock.rs
new file mode 100644
index 00000000..7d2b5e37
--- /dev/null
+++ b/lib/rust_support/spinlock.rs
@@ -0,0 +1,355 @@
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
+use core::cell::UnsafeCell;
+use core::ffi::c_int;
+use core::fmt;
+use core::fmt::Debug;
+use core::fmt::Formatter;
+use core::ops::Deref;
+use core::ops::DerefMut;
+
+use crate::interrupt;
+use crate::interrupt::ConstInterruptFlags;
+use crate::interrupt::GetInterruptFlags;
+use crate::interrupt::InterruptState;
+use crate::sys::lk_spin_lock;
+use crate::sys::lk_spin_trylock;
+use crate::sys::lk_spin_unlock;
+use crate::sys::spin_lock_t;
+use crate::sys::SPIN_LOCK_INITIAL_VALUE;
+
+/// Interrupts must be disabled ([`InterruptState::save`]) before calling this,
+/// or else this might deadlock.
+/// Furthermore, if [`InterruptFlags::check`] fails (panics), then deadlocks might happen.
+///
+/// # Safety
+///
+/// `lock` must have been initialized with [`SPIN_LOCK_INITIAL_VALUE`].
+///
+/// This function is thread-safe and can be called concurrently from multiple threads.
+/// Only one thread is guaranteed to successfully lock it at a time.
+unsafe fn spin_lock(lock: *mut spin_lock_t) {
+    // SAFETY: See above.
+    unsafe { lk_spin_lock(lock) }
+}
+
+/// Returns 0 on a successful lock.
+///
+/// # Safety
+///
+/// Same as [`spin_lock`] (including deadlock safety).
+unsafe fn spin_trylock(lock: *mut spin_lock_t) -> c_int {
+    // SAFETY: See above.
+    unsafe { lk_spin_trylock(lock) }
+}
+
+/// # Safety
+///
+/// `lock` must already be locked by either [`spin_lock`] or [`spin_trylock`].
+unsafe fn spin_unlock(lock: *mut spin_lock_t) {
+    // SAFETY: See above.
+    unsafe { lk_spin_unlock(lock) }
+}
+
+/// A spin lock that does not encapsulate the data it protects.
+struct LoneSpinLock {
+    inner: UnsafeCell<spin_lock_t>,
+}
+
+impl LoneSpinLock {
+    pub const fn new() -> Self {
+        let inner = UnsafeCell::new(SPIN_LOCK_INITIAL_VALUE as _);
+        Self { inner }
+    }
+
+    fn get_raw(&self) -> *mut spin_lock_t {
+        self.inner.get()
+    }
+}
+
+impl Default for LoneSpinLock {
+    fn default() -> Self {
+        Self::new()
+    }
+}
+
+/// A spin lock wrapping the C [`spin_lock_t`].
+/// Its API is modeled after [`std::sync::Mutex`].
+///
+/// # Specifying [`InterruptFlags`]
+///
+/// To safely use a [`SpinLock`] without risking deadlocks,
+/// [`interrupts`] must be disabled first.
+/// Therefore, [`SpinLock`] requires [`InterruptFlags`] to be specified,
+/// which it uses to disable interrupts in [`SpinLock::lock_save`] and [`SpinLock::try_lock_save`].
+/// This can be bypassed with [`SpinLock::lock_unsaved`] and [`SpinLock::try_lock_unsaved`]
+/// if interrupts have already been disabled elsewhere with [`InterruptState::save`].
+///
+/// To ensure maximal flexibility, these [`InterruptFlags`]
+/// can be specified at runtime or at compile time
+/// (this is what `F: `[`GetInterruptFlags`] is for).
+/// To specify it at runtime, [`InterruptFlags`] can be used directly,
+/// but in most cases, the flags are known at compile time already,
+/// so [`ConstInterruptFlags`] can be used instead.
+/// Since [`ConstInterruptFlags`] uses a const generic,
+/// it is much simpler to use the aliases in [`interrupt::flags`] instead,
+/// which correspond to the variants of [`InterruptFlags`].
+///
+/// If this is confusing, the best default is to [`IRQSpinLock`] instead.
+/// This type alias is [`SpinLock`] with [`interrupt::flags::Interrupts`],
+/// which is the default [`InterruptFlags`].
+/// Using this corresponds to `spin_lock_irqsave` and `spin_lock_irqrestore` in C.
+///
+/// ## Examples
+///
+/// ### With Runtime [`InterruptFlags`]
+///
+/// ```
+/// let lock = SpinLock::new("value", InterruptFlags::IRQ_FIQ);
+/// ```
+///
+/// ### With Compile Time [`ConstInterruptFlags`]
+///
+/// ```
+/// let lock = SpinLock::new("value", interrupt::flags::IRQ);
+/// ```
+///
+/// ### With [`IRQSpinLock`]
+///
+/// ```
+/// let lock = IRQSpinLock::new_irq("value");
+/// ```
+///
+/// ## [`InterruptFlags`] Runtime Checks
+///
+/// Certain combinations of [`InterruptFlags`] being disabled and already disabled
+/// can lead to deadlocks, so this is checked against at runtime by [`InterruptFlags::check`].
+/// See [`InterruptFlags::check`] for what combinations of [`InterruptFlags`] these are.
+/// These will be checked before locking, panicking if the check fails.
+///
+/// [`InterruptFlags`]: interrupt::InterruptFlags
+/// [`InterruptFlags::check`]: interrupt::InterruptFlags::check
+#[derive(Default)]
+pub struct SpinLock<T: ?Sized, F: GetInterruptFlags> {
+    lock: LoneSpinLock,
+    interrupt_flags: F,
+    value: UnsafeCell<T>,
+}
+
+impl<T, F: GetInterruptFlags> SpinLock<T, F> {
+    /// See [`SpinLock`] for more information on `interrupt_flags`
+    /// and the `F: `[`GetInterruptFlags`] generic.
+    pub const fn new(value: T, interrupt_flags: F) -> Self {
+        Self { lock: LoneSpinLock::new(), interrupt_flags, value: UnsafeCell::new(value) }
+    }
+
+    pub fn into_inner(self) -> T {
+        self.value.into_inner()
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> SpinLock<T, F> {
+    fn get_raw(&self) -> *mut spin_lock_t {
+        self.lock.get_raw()
+    }
+
+    pub fn get_mut(&mut self) -> &mut T {
+        self.value.get_mut()
+    }
+}
+
+pub struct SpinLockGuard<'a, T: ?Sized, F: GetInterruptFlags> {
+    lock: &'a SpinLock<T, F>,
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> SpinLock<T, F> {
+    /// Interrupts must be disabled ([`InterruptState::save`]) before calling this,
+    /// or else this might deadlock.
+    ///
+    /// [`Self::lock_save`] should be preferred.
+    ///
+    /// This is the analogue to `spin_lock` in C.
+    #[track_caller] // For `InterruptFlags::check`.
+    pub fn lock_unsaved(&self) -> SpinLockGuard<'_, T, F> {
+        self.interrupt_flags.get().check();
+        // SAFETY: `LoneSpinLock::new` initialized `self.lock` with `SPIN_LOCK_INITIAL_VALUE`.
+        unsafe { spin_lock(self.lock.get_raw()) };
+        SpinLockGuard { lock: self }
+    }
+
+    /// Interrupts must be disabled ([`InterruptState::save`]) before calling this,
+    /// or else this might deadlock.
+    ///
+    /// [`Self::try_lock_save`] should be preferred.
+    ///
+    /// This is the analogue to `spin_trylock` in C.
+    #[track_caller] // For `InterruptFlags::check`.
+    pub fn try_lock_unsaved(&self) -> Option<SpinLockGuard<'_, T, F>> {
+        self.interrupt_flags.get().check();
+        // SAFETY: `LoneSpinLock::new` initialized `self.lock` with `SPIN_LOCK_INITIAL_VALUE`.
+        let status = unsafe { spin_trylock(self.lock.get_raw()) };
+        // `spin_trylock` returns 0 on success, but doesn't specify what other non-zero values mean.
+        if status != 0 {
+            return None;
+        }
+        Some(SpinLockGuard { lock: self })
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> Drop for SpinLockGuard<'_, T, F> {
+    fn drop(&mut self) {
+        // SAFETY: `SpinLockGuard` is only created with a locked spin lock
+        // with either `spin_lock` or `spin_trylock`.
+        unsafe { spin_unlock(self.lock.get_raw()) };
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> SpinLockGuard<'_, T, F> {
+    /// A more explicit unlock, equivalent to [`drop`].
+    ///
+    /// This is the analogue to `spin_unlock` in C.
+    pub fn unlock(self) {
+        drop(self);
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> Deref for SpinLockGuard<'_, T, F> {
+    type Target = T;
+
+    fn deref(&self) -> &Self::Target {
+        // SAFETY: Only one thread could have `spin_lock` or `spin_trylock`ed,
+        // so we have a unique reference to `self.lock.value`.
+        unsafe { &*self.lock.value.get() }
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> DerefMut for SpinLockGuard<'_, T, F> {
+    fn deref_mut(&mut self) -> &mut Self::Target {
+        // SAFETY: Only one thread could have `spin_lock` or `spin_trylock`ed,
+        // so we have a unique reference to `self.lock.value`.
+        unsafe { &mut *self.lock.value.get() }
+    }
+}
+
+/// SAFETY: This is a spin lock wrapping [`spin_lock_t`].
+/// [`GetInterruptFlags`] is also `Send + Sync`.
+unsafe impl<T: ?Sized + Send, F: GetInterruptFlags> Send for SpinLock<T, F> {}
+
+/// SAFETY: This is a spin lock wrapping [`spin_lock_t`].
+/// [`GetInterruptFlags`] is also `Send + Sync`.
+unsafe impl<T: ?Sized + Send, F: GetInterruptFlags> Sync for SpinLock<T, F> {}
+
+// Note: We don't impl `UnwindSafe` and `RefUnwindSafe`
+// because we don't poison our `SpinLock` upon panicking
+// like `std::sync::Mutex` does.
+
+pub struct SpinLockGuardState<'a, T: ?Sized, F: GetInterruptFlags> {
+    // The order is important here.
+    // The guard needs to be dropped (unlocked) first before the state (is restored).
+    guard: SpinLockGuard<'a, T, F>,
+
+    // The `#[allow(dead_code)]` is because this is only used for dropping.
+    #[allow(dead_code)]
+    state: InterruptState<F>,
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> SpinLock<T, F> {
+    /// This is the analogue to `spin_lock_save` in C.
+    #[track_caller] // For `InterruptFlags::check`.
+    pub fn lock_save(&self) -> SpinLockGuardState<'_, T, F> {
+        let state = InterruptState::save(self.interrupt_flags);
+        let guard = self.lock_unsaved();
+        SpinLockGuardState { guard, state }
+    }
+
+    /// This has no direct C analogue, but it is a combination of
+    /// `spin_trylock` and `spin_lock_save`.
+    #[track_caller] // For `InterruptFlags::check`.
+    pub fn try_lock_save(&self) -> Option<SpinLockGuardState<'_, T, F>> {
+        let state = InterruptState::save(self.interrupt_flags);
+        let guard = self.try_lock_unsaved()?;
+        Some(SpinLockGuardState { guard, state })
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> SpinLockGuardState<'_, T, F> {
+    /// A more explicit unlock, equivalent to [`drop`].
+    ///
+    /// This is the analogue of `spin_unlock_restore` in C.
+    pub fn unlock_restore(self) {
+        drop(self);
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> Deref for SpinLockGuardState<'_, T, F> {
+    type Target = T;
+
+    fn deref(&self) -> &Self::Target {
+        self.guard.deref()
+    }
+}
+
+impl<T: ?Sized, F: GetInterruptFlags> DerefMut for SpinLockGuardState<'_, T, F> {
+    fn deref_mut(&mut self) -> &mut Self::Target {
+        self.guard.deref_mut()
+    }
+}
+
+/// Copied from [`std::sync::Mutex`],
+/// with minor changes as [`SpinLock`] has no poisoning.
+impl<T: ?Sized + Debug, F: GetInterruptFlags> Debug for SpinLock<T, F> {
+    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
+        let mut d = f.debug_struct("SpinLock");
+        match self.try_lock_save() {
+            Some(guard) => {
+                d.field("data", &&*guard);
+            }
+            None => {
+                d.field("data", &format_args!("<locked>"));
+            }
+        }
+        d.finish_non_exhaustive()
+    }
+}
+
+/// [`Self::lock_save`] and [`Self::unlock_restore`] on this type
+/// are the analogues of `spin_lock_irqsave` and `spin_lock_irqrestore` in C.
+///
+/// This type defaults to [`interrupt::flags::Interrupts`]
+/// (the ZST version of [`InterruptFlags::INTERRUPTS`])
+/// for the `F: `[`GetInterruptFlags`] generic of [`SpinLock`].
+/// Generally, this means it will disable IRQs but not FIQs
+/// (if they even exist on the platform).
+///
+/// If you're unsure which [`GetInterruptFlags`] generic to use,
+/// this is a good default.
+///
+/// [`InterruptFlags::INTERRUPTS`]: interrupt::InterruptFlags::INTERRUPTS
+pub type IRQSpinLock<T> = SpinLock<T, interrupt::flags::Interrupts>;
+
+impl<T> IRQSpinLock<T> {
+    pub const fn new_irq(value: T) -> Self {
+        Self::new(value, ConstInterruptFlags)
+    }
+}
diff --git a/lib/rust_support/thread.rs b/lib/rust_support/thread.rs
index 517adf19..6211c8f3 100644
--- a/lib/rust_support/thread.rs
+++ b/lib/rust_support/thread.rs
@@ -34,9 +34,12 @@ use core::ptr::NonNull;
 use core::time::Duration;
 
 use crate::Error;
+use crate::INFINITE_TIME;
 
 use crate::sys::lk_time_ns_t;
+use crate::sys::lk_time_t;
 use crate::sys::thread_create;
+use crate::sys::thread_join;
 use crate::sys::thread_resume;
 use crate::sys::thread_sleep_ns;
 use crate::sys::thread_t;
@@ -132,7 +135,24 @@ impl Sub<c_int> for Priority {
 }
 
 pub struct JoinHandle {
-    _thread: NonNull<thread_t>,
+    thread: NonNull<thread_t>,
+}
+
+impl JoinHandle {
+    /// Waits a given amount of time for the associated thread to finish. Waits indefinitely if
+    /// timeout is None.
+    pub fn join(self, timeout: Option<Duration>) -> Result<c_int, Error> {
+        let timeout_ms: lk_time_t = timeout.map_or(INFINITE_TIME, |t| {
+            t.as_millis().try_into().expect("could not convert timeout to milliseconds")
+        });
+        let mut rc = 0;
+        // SAFETY: The thread pointer came from a call to thread_create and must be non-null. The
+        // retcode pointer points to the stack of the calling thread which will live as long as
+        // needed since thread_join blocks.
+        let status = unsafe { thread_join(self.thread.as_ptr(), &raw mut rc, timeout_ms) };
+        Error::from_lk(status)?;
+        Ok(rc)
+    }
 }
 
 #[derive(Debug)]
@@ -142,7 +162,7 @@ pub struct Builder<'a> {
     pub stack_size: usize,
 }
 
-impl<'a> Default for Builder<'a> {
+impl Default for Builder<'_> {
     fn default() -> Self {
         Self::new()
     }
@@ -210,7 +230,7 @@ impl<'a> Builder<'a> {
         // SAFETY: `thread` is non-null, so `thread_create` initialized it properly.
         let status = unsafe { thread_resume(thread.as_ptr()) };
         if status == Error::NO_ERROR.into() {
-            Ok(JoinHandle { _thread: thread })
+            Ok(JoinHandle { thread })
         } else {
             Err(status)
         }
diff --git a/lib/rust_support/uuid.rs b/lib/rust_support/uuid.rs
new file mode 100644
index 00000000..81de2a05
--- /dev/null
+++ b/lib/rust_support/uuid.rs
@@ -0,0 +1,39 @@
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
+use crate::sys::uuid_t;
+
+// TODO: split this into a separate trusty module to share bindings with userspace
+#[derive(Debug)]
+pub struct Uuid(pub uuid_t);
+
+impl Uuid {
+    pub const fn new(
+        time_low: u32,
+        time_mid: u16,
+        time_hi_and_version: u16,
+        clock_seq_and_node: [u8; 8],
+    ) -> Self {
+        Self(uuid_t { time_low, time_mid, time_hi_and_version, clock_seq_and_node })
+    }
+}
diff --git a/lib/rust_support/vmm.rs b/lib/rust_support/vmm.rs
index 56147572..972cc184 100644
--- a/lib/rust_support/vmm.rs
+++ b/lib/rust_support/vmm.rs
@@ -24,23 +24,43 @@
 use core::ffi::c_char;
 use core::ffi::c_uint;
 use core::ffi::c_void;
-use core::ptr::{addr_of, addr_of_mut};
+use core::ptr::addr_of;
 
 use crate::paddr_t;
 use crate::status_t;
+use crate::Error;
 
 pub use crate::sys::vaddr_to_paddr;
+pub use crate::sys::vmm_alloc;
 pub use crate::sys::vmm_alloc_contiguous;
+pub use crate::sys::vmm_alloc_obj;
 pub use crate::sys::vmm_alloc_physical_etc;
 pub use crate::sys::vmm_aspace_t;
 pub use crate::sys::vmm_free_region;
+pub use crate::sys::vmm_get_obj;
+pub use crate::sys::vmm_obj;
+pub use crate::sys::vmm_obj_del_ref;
+pub use crate::sys::vmm_obj_service;
+pub use crate::sys::vmm_obj_service_add;
+pub use crate::sys::vmm_obj_service_create_ro;
+pub use crate::sys::vmm_obj_service_destroy;
+pub use crate::sys::vmm_obj_slice;
+pub use crate::sys::vmm_obj_slice_init;
+pub use crate::sys::vmm_obj_slice_release;
 
+use core::ffi::CStr;
+
+#[cfg(version("1.82"))]
+#[inline]
+pub fn vmm_get_kernel_aspace() -> *mut vmm_aspace_t {
+    &raw mut crate::sys::_kernel_aspace
+}
+
+#[cfg(not(version("1.82")))]
 #[inline]
 pub fn vmm_get_kernel_aspace() -> *mut vmm_aspace_t {
-    // SAFETY: The returned raw pointer holds the same safety invariants as accessing a `static mut`,
-    // so this `unsafe` is unconditionally sound, and may become safe in edition 2024:
-    // <https://github.com/rust-lang/rust/issues/114447>.
-    unsafe { addr_of_mut!(crate::sys::_kernel_aspace) }
+    // SAFETY: Safe in Rust 1.82; see above.
+    unsafe { core::ptr::addr_of_mut!(crate::sys::_kernel_aspace) }
 }
 
 /// # Safety
@@ -73,3 +93,94 @@ pub unsafe fn vmm_alloc_physical(
         )
     }
 }
+
+/// A wrapper for an array allocated by Trusty's vmm library.
+pub struct VmmPageArray {
+    ptr: *mut c_void,
+    size: usize,
+}
+
+impl VmmPageArray {
+    /// Allocates memory with vmm_alloc. size is automatically aligned up to the next page size.
+    /// Memory is automatically freed in drop.
+    pub fn new(
+        name: &'static CStr,
+        size: usize,
+        align_log2: u8,
+        vmm_flags: c_uint,
+    ) -> Result<Self, Error> {
+        let aspace = vmm_get_kernel_aspace();
+        let mut aligned_ptr: *mut c_void = core::ptr::null_mut();
+        // SAFETY: Name is static and will therefore outlive the allocation. The return code is
+        // checked before returning the array to the caller.
+        let rc = unsafe {
+            crate::sys::vmm_alloc(
+                aspace,
+                name.as_ptr(),
+                size,
+                &mut aligned_ptr,
+                align_log2,
+                vmm_flags,
+                crate::mmu::ARCH_MMU_FLAG_CACHED | crate::mmu::ARCH_MMU_FLAG_PERM_NO_EXECUTE,
+            )
+        };
+        if rc < 0 {
+            Error::from_lk(rc)?;
+        }
+        Ok(Self { ptr: aligned_ptr, size })
+    }
+
+    /// Allocates address space with vmm_alloc_physical backed by physical memory starting at
+    /// paddr. size is automatically aligned up to the next page size. Mapping is automatically
+    /// freed in drop.
+    pub fn new_physical(
+        name: &'static CStr,
+        paddr: usize,
+        size: usize,
+        align_log2: u8,
+        vmm_flags: c_uint,
+    ) -> Result<Self, Error> {
+        let aspace = vmm_get_kernel_aspace();
+        let aligned_ptr: *mut c_void = core::ptr::null_mut();
+        // SAFETY: Name is static and will therefore outlive the allocation. The return code is
+        // checked before returning the array to the caller.
+        let rc = unsafe {
+            vmm_alloc_physical(
+                aspace,
+                name.as_ptr(),
+                size,
+                &aligned_ptr as *const *mut c_void,
+                align_log2,
+                paddr,
+                vmm_flags,
+                crate::mmu::ARCH_MMU_FLAG_CACHED | crate::mmu::ARCH_MMU_FLAG_PERM_NO_EXECUTE,
+            )
+        };
+        if rc < 0 {
+            Error::from_lk(rc)?;
+        }
+        Ok(Self { ptr: aligned_ptr, size })
+    }
+
+    pub fn ptr(&self) -> *mut c_void {
+        self.ptr
+    }
+
+    pub fn size(&self) -> usize {
+        self.size
+    }
+
+    pub fn as_mut_slice(&mut self) -> &mut [u8] {
+        // SAFETY: Aligned pointer was successfully allocated by vmm_alloc and the same size is
+        // being used.
+        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
+    }
+}
+
+impl Drop for VmmPageArray {
+    fn drop(&mut self) {
+        let aspace = vmm_get_kernel_aspace();
+        // SAFETY: Freeing a pointer allocated by vmm_alloc.
+        unsafe { vmm_free_region(aspace, self.ptr as usize) };
+    }
+}
diff --git a/lib/rust_support/wrappers/include/reflist.h b/lib/rust_support/wrappers/include/reflist.h
new file mode 100644
index 00000000..a72e0ecc
--- /dev/null
+++ b/lib/rust_support/wrappers/include/reflist.h
@@ -0,0 +1,28 @@
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
+#include <shared/lk/reflist.h>
+
+void lk_obj_ref_init(struct obj_ref* ref);
diff --git a/lib/rust_support/wrappers/include/spinlock.h b/lib/rust_support/wrappers/include/spinlock.h
new file mode 100644
index 00000000..d5ecf59b
--- /dev/null
+++ b/lib/rust_support/wrappers/include/spinlock.h
@@ -0,0 +1,80 @@
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
+#include <kernel/spinlock.h>
+
+/**
+ * Can be safely called in any context.
+ */
+void lk_interrupt_save(spin_lock_saved_state_t *statep,
+                       spin_lock_save_flags_t flags);
+
+/**
+ * Can be safely called in any context.
+ *
+ * `state` should be from the corresponding call to `lk_interrupt_save`,
+ * and `flags` should be the same `flags` from that `lk_interrupt_save` call.
+ */
+void lk_interrupt_restore(spin_lock_saved_state_t old_state,
+                          spin_lock_save_flags_t flags);
+
+/**
+ * Can be safely called in any context.
+ */
+bool lk_ints_disabled(void);
+
+#if defined(__arm__) || defined(__aarch64__)
+/**
+ * Can be safely called in any context.
+ */
+bool lk_fiqs_disabled(void);
+#endif
+
+/**
+ * Interrupts must be disabled ([`InterruptState::save`]) before calling this,
+ * or else this might deadlock.
+ *
+ * # Safety
+ *
+ * `lock` must have been initialized with [`SPIN_LOCK_INITIAL_VALUE`].
+ *
+ * This function is thread-safe and can be called concurrently from multiple threads.
+ * Only one thread is guaranteed to successfully lock it at a time.
+ */
+void lk_spin_lock(spin_lock_t *lock);
+
+/**
+ * # Safety
+ *
+ * Same as `lk_spin_lock`.
+ */
+int lk_spin_trylock(spin_lock_t *lock);
+
+/**
+ * # Safety
+ *
+ * `lock` must already be locked by either `lk_spin_lock` or `lk_spin_trylock`.
+ */
+void lk_spin_unlock(spin_lock_t *lock);
diff --git a/lib/rust_support/wrappers/include/streams.h b/lib/rust_support/wrappers/include/streams.h
index 7709b654..53c493fa 100644
--- a/lib/rust_support/wrappers/include/streams.h
+++ b/lib/rust_support/wrappers/include/streams.h
@@ -1,3 +1,28 @@
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
 #include <stdio.h>
 
 FILE* lk_stdin(void);
diff --git a/lib/rust_support/wrappers/reflist.c b/lib/rust_support/wrappers/reflist.c
new file mode 100644
index 00000000..785835c6
--- /dev/null
+++ b/lib/rust_support/wrappers/reflist.c
@@ -0,0 +1,28 @@
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
+#include <reflist.h>
+
+void lk_obj_ref_init(struct obj_ref* ref) {
+    obj_ref_init(ref);
+}
diff --git a/lib/rust_support/wrappers/rules.mk b/lib/rust_support/wrappers/rules.mk
index badb948a..2908a1e4 100644
--- a/lib/rust_support/wrappers/rules.mk
+++ b/lib/rust_support/wrappers/rules.mk
@@ -26,6 +26,8 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 MODULE := $(LOCAL_DIR)
 
 MODULE_SRCS := \
+	$(LOCAL_DIR)/reflist.c \
+	$(LOCAL_DIR)/spinlock.c \
 	$(LOCAL_DIR)/streams.c \
 
 MODULE_EXPORT_INCLUDES := \
diff --git a/lib/rust_support/wrappers/spinlock.c b/lib/rust_support/wrappers/spinlock.c
new file mode 100644
index 00000000..1c1dc5b7
--- /dev/null
+++ b/lib/rust_support/wrappers/spinlock.c
@@ -0,0 +1,54 @@
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
+#include <spinlock.h>
+
+void lk_interrupt_save(spin_lock_saved_state_t *statep, spin_lock_save_flags_t flags) {
+    arch_interrupt_save(statep, flags);
+}
+
+void lk_interrupt_restore(spin_lock_saved_state_t old_state, spin_lock_save_flags_t flags) {
+    arch_interrupt_restore(old_state, flags);
+}
+
+bool lk_ints_disabled(void) {
+    return arch_ints_disabled();
+}
+
+#if defined(__arm__) || defined(__aarch64__)
+bool lk_fiqs_disabled(void) {
+    return arch_fiqs_disabled();
+}
+#endif
+
+void lk_spin_lock(spin_lock_t *lock) {
+    spin_lock(lock);
+}
+
+int lk_spin_trylock(spin_lock_t *lock) {
+    return spin_trylock(lock);
+}
+
+void lk_spin_unlock(spin_lock_t *lock) {
+    spin_unlock(lock);
+}
diff --git a/lib/rust_support/wrappers/streams.c b/lib/rust_support/wrappers/streams.c
index 66a97d5b..9d3cdab3 100644
--- a/lib/rust_support/wrappers/streams.c
+++ b/lib/rust_support/wrappers/streams.c
@@ -1,3 +1,26 @@
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
 #include <streams.h>
 
 FILE* lk_stdin(void) {
diff --git a/make/compile.mk b/make/compile.mk
index 8c136f10..f13793f5 100644
--- a/make/compile.mk
+++ b/make/compile.mk
@@ -13,20 +13,20 @@ MODULE_CPPSRCS := $(filter %.cpp,$(MODULE_OUTPLACE_SRCS))
 MODULE_CCSRCS := $(filter %.cc,$(MODULE_OUTPLACE_SRCS))
 MODULE_ASMSRCS := $(filter %.S,$(MODULE_OUTPLACE_SRCS))
 
-MODULE_COBJS := $(call TOBUILDDIR,$(patsubst %.c,%.o,$(MODULE_CSRCS)))
-MODULE_CPPOBJS := $(call TOBUILDDIR,$(patsubst %.cpp,%.o,$(MODULE_CPPSRCS)))
-MODULE_CCOBJS := $(call TOBUILDDIR,$(patsubst %.cc,%.o,$(MODULE_CCSRCS)))
-MODULE_ASMOBJS := $(call TOBUILDDIR,$(patsubst %.S,%.o,$(MODULE_ASMSRCS)))
+MODULE_COBJS := $(call TOBUILDDIR,$(patsubst %.c,%.c.o,$(MODULE_CSRCS)))
+MODULE_CPPOBJS := $(call TOBUILDDIR,$(patsubst %.cpp,%.cpp.o,$(MODULE_CPPSRCS)))
+MODULE_CCOBJS := $(call TOBUILDDIR,$(patsubst %.cc,%.cc.o,$(MODULE_CCSRCS)))
+MODULE_ASMOBJS := $(call TOBUILDDIR,$(patsubst %.S,%.S.o,$(MODULE_ASMSRCS)))
 
 MODULE_CSRCS_FIRST := $(filter %.c,$(MODULE_OUTPLACE_SRCS_FIRST))
 MODULE_CPPSRCS_FIRST := $(filter %.cpp,$(MODULE_OUTPLACE_SRCS_FIRST))
 MODULE_CCSRCS_FIRST := $(filter %.cc,$(MODULE_OUTPLACE_SRCS_FIRST))
 MODULE_ASMSRCS_FIRST := $(filter %.S,$(MODULE_OUTPLACE_SRCS_FIRST))
 
-MODULE_COBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.c,%.o,$(MODULE_CSRCS_FIRST)))
-MODULE_CPPOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.cpp,%.o,$(MODULE_CPPSRCS_FIRST)))
-MODULE_CCOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.cc,%.o,$(MODULE_CCSRCS_FIRST)))
-MODULE_ASMOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.S,%.o,$(MODULE_ASMSRCS_FIRST)))
+MODULE_COBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.c,%.c.o,$(MODULE_CSRCS_FIRST)))
+MODULE_CPPOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.cpp,%.cpp.o,$(MODULE_CPPSRCS_FIRST)))
+MODULE_CCOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.cc,%.cc.o,$(MODULE_CCSRCS_FIRST)))
+MODULE_ASMOBJS_FIRST := $(call TOBUILDDIR,$(patsubst %.S,%.S.o,$(MODULE_ASMSRCS_FIRST)))
 
 # same for INPLACE sources
 MODULE_INPLACE_CSRCS := $(filter %.c,$(MODULE_INPLACE_SRCS))
@@ -34,20 +34,20 @@ MODULE_INPLACE_CPPSRCS := $(filter %.cpp,$(MODULE_INPLACE_SRCS))
 MODULE_INPLACE_CCSRCS := $(filter %.cc,$(MODULE_INPLACE_SRCS))
 MODULE_INPLACE_ASMSRCS := $(filter %.S,$(MODULE_INPLACE_SRCS))
 
-MODULE_INPLACE_COBJS := $(patsubst %.c,%.o,$(MODULE_INPLACE_CSRCS))
-MODULE_INPLACE_CPPOBJS := $(patsubst %.cpp,%.o,$(MODULE_INPLACE_CPPSRCS))
-MODULE_INPLACE_CCOBJS := $(patsubst %.cc,%.o,$(MODULE_INPLACE_CCSRCS))
-MODULE_INPLACE_ASMOBJS := $(patsubst %.S,%.o,$(MODULE_INPLACE_ASMSRCS))
+MODULE_INPLACE_COBJS := $(patsubst %.c,%.c.o,$(MODULE_INPLACE_CSRCS))
+MODULE_INPLACE_CPPOBJS := $(patsubst %.cpp,%.cpp.o,$(MODULE_INPLACE_CPPSRCS))
+MODULE_INPLACE_CCOBJS := $(patsubst %.cc,%.cc.o,$(MODULE_INPLACE_CCSRCS))
+MODULE_INPLACE_ASMOBJS := $(patsubst %.S,%.S.o,$(MODULE_INPLACE_ASMSRCS))
 
 MODULE_INPLACE_CSRCS_FIRST := $(filter %.c,$(MODULE_INPLACE_SRCS_FIRST))
 MODULE_INPLACE_CPPSRCS_FIRST := $(filter %.cpp,$(MODULE_INPLACE_SRCS_FIRST))
 MODULE_INPLACE_CCSRCS_FIRST := $(filter %.cc,$(MODULE_INPLACE_SRCS_FIRST))
 MODULE_INPLACE_ASMSRCS_FIRST := $(filter %.S,$(MODULE_INPLACE_SRCS_FIRST))
 
-MODULE_INPLACE_COBJS_FIRST := $(patsubst %.c,%.o,$(MODULE_INPLACE_CSRCS_FIRST))
-MODULE_INPLACE_CPPOBJS_FIRST := $(patsubst %.cpp,%.o,$(MODULE_INPLACE_CPPSRCS_FIRST))
-MODULE_INPLACE_CCOBJS_FIRST := $(patsubst %.cc,%.o,$(MODULE_INPLACE_CCSRCS_FIRST))
-MODULE_INPLACE_ASMOBJS_FIRST := $(patsubst %.S,%.o,$(MODULE_INPLACE_ASMSRCS_FIRST))
+MODULE_INPLACE_COBJS_FIRST := $(patsubst %.c,%.c.o,$(MODULE_INPLACE_CSRCS_FIRST))
+MODULE_INPLACE_CPPOBJS_FIRST := $(patsubst %.cpp,%.cpp.o,$(MODULE_INPLACE_CPPSRCS_FIRST))
+MODULE_INPLACE_CCOBJS_FIRST := $(patsubst %.cc,%.cc.o,$(MODULE_INPLACE_CCSRCS_FIRST))
+MODULE_INPLACE_ASMOBJS_FIRST := $(patsubst %.S,%.S.o,$(MODULE_INPLACE_ASMSRCS_FIRST))
 
 # do the same thing for files specified in arm override mode
 MODULE_ARM_CSRCS := $(filter %.c,$(MODULE_ARM_OVERRIDE_SRCS))
@@ -55,10 +55,10 @@ MODULE_ARM_CPPSRCS := $(filter %.cpp,$(MODULE_ARM_OVERRIDE_SRCS))
 MODULE_ARM_CCSRCS := $(filter %.cc,$(MODULE_ARM_OVERRIDE_SRCS))
 MODULE_ARM_ASMSRCS := $(filter %.S,$(MODULE_ARM_OVERRIDE_SRCS))
 
-MODULE_ARM_COBJS := $(call TOBUILDDIR,$(patsubst %.c,%.o,$(MODULE_ARM_CSRCS)))
-MODULE_ARM_CPPOBJS := $(call TOBUILDDIR,$(patsubst %.cpp,%.o,$(MODULE_ARM_CPPSRCS)))
-MODULE_ARM_CCOBJS := $(call TOBUILDDIR,$(patsubst %.cc,%.o,$(MODULE_ARM_CCSRCS)))
-MODULE_ARM_ASMOBJS := $(call TOBUILDDIR,$(patsubst %.S,%.o,$(MODULE_ARM_ASMSRCS)))
+MODULE_ARM_COBJS := $(call TOBUILDDIR,$(patsubst %.c,%.c.o,$(MODULE_ARM_CSRCS)))
+MODULE_ARM_CPPOBJS := $(call TOBUILDDIR,$(patsubst %.cpp,%.cpp.o,$(MODULE_ARM_CPPSRCS)))
+MODULE_ARM_CCOBJS := $(call TOBUILDDIR,$(patsubst %.cc,%.cc.o,$(MODULE_ARM_CCSRCS)))
+MODULE_ARM_ASMOBJS := $(call TOBUILDDIR,$(patsubst %.S,%.S.o,$(MODULE_ARM_ASMSRCS)))
 
 MODULE_OBJS := $(MODULE_COBJS) \
                $(MODULE_CPPOBJS) \
@@ -127,75 +127,75 @@ $(MODULE_OBJS): MODULE_ASMFLAGS:=$(MODULE_ASMFLAGS)
 $(MODULE_OBJS): MODULE_SRCDEPS:=$(MODULE_SRCDEPS)
 $(MODULE_OBJS): MODULE_INCLUDES:=$(MODULE_INCLUDES)
 
-$(MODULE_COBJS): $(BUILDDIR)/%.o: %.c $(MODULE_SRCDEPS)
+$(MODULE_COBJS): $(BUILDDIR)/%.c.o: %.c $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CFLAGS) $(ARCH_CFLAGS) $(MODULE_CFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_CPPOBJS): $(BUILDDIR)/%.o: %.cpp $(MODULE_SRCDEPS)
+$(MODULE_CPPOBJS): $(BUILDDIR)/%.cpp.o: %.cpp $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_CCOBJS): $(BUILDDIR)/%.o: %.cc $(MODULE_SRCDEPS)
+$(MODULE_CCOBJS): $(BUILDDIR)/%.cc.o: %.cc $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_ASMOBJS): $(BUILDDIR)/%.o: %.S $(MODULE_SRCDEPS)
+$(MODULE_ASMOBJS): $(BUILDDIR)/%.S.o: %.S $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_ASMFLAGS) $(ARCH_ASMFLAGS) $(MODULE_ASMFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
 # Same rules as normal sources but output file is %.o rather then $(BUILDDIR)/%.o
-$(MODULE_INPLACE_COBJS): %.o : %.c $(MODULE_SRCDEPS)
+$(MODULE_INPLACE_COBJS): %.c.o : %.c $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CFLAGS) $(ARCH_CFLAGS) $(MODULE_CFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_INPLACE_CPPOBJS): %.o : %.cpp $(MODULE_SRCDEPS)
+$(MODULE_INPLACE_CPPOBJS): %.cpp.o : %.cpp $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_INPLACE_CCOBJS): %.o : %.cc $(MODULE_SRCDEPS)
+$(MODULE_INPLACE_CCOBJS): %.cc.o : %.cc $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_INPLACE_ASMOBJS): %.o : %.S $(MODULE_SRCDEPS)
+$(MODULE_INPLACE_ASMOBJS): %.S.o : %.S $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_ASMFLAGS) $(ARCH_ASMFLAGS) $(MODULE_ASMFLAGS) $(THUMBCFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
 # overridden arm versions
-$(MODULE_ARM_COBJS): $(BUILDDIR)/%.o: %.c $(MODULE_SRCDEPS)
+$(MODULE_ARM_COBJS): $(BUILDDIR)/%.c.o: %.c $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CFLAGS) $(ARCH_CFLAGS) $(MODULE_CFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_ARM_CPPOBJS): $(BUILDDIR)/%.o: %.cpp $(MODULE_SRCDEPS)
+$(MODULE_ARM_CPPOBJS): $(BUILDDIR)/%.cpp.o: %.cpp $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_ARM_CCOBJS): $(BUILDDIR)/%.o: %.cc $(MODULE_SRCDEPS)
+$(MODULE_ARM_CCOBJS): $(BUILDDIR)/%.cc.o: %.cc $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_CPPFLAGS) $(ARCH_CPPFLAGS) $(MODULE_CPPFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
 	@$(call ECHO_DONE_SILENT,$(MODULE),compiling,$<)
 
-$(MODULE_ARM_ASMOBJS): $(BUILDDIR)/%.o: %.S $(MODULE_SRCDEPS)
+$(MODULE_ARM_ASMOBJS): $(BUILDDIR)/%.S.o: %.S $(MODULE_SRCDEPS)
 	@$(MKDIR)
 	@$(call ECHO,$(MODULE),compiling,$<)
 	$(NOECHO)$(CC) $(GLOBAL_OPTFLAGS) $(MODULE_OPTFLAGS) $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(MODULE_COMPILEFLAGS) $(GLOBAL_ASMFLAGS) $(ARCH_ASMFLAGS) $(MODULE_ASMFLAGS) $(MODULE_INCLUDES) $(GLOBAL_INCLUDES) -c $< -MD -MP -MT $@ -MF $(@:%o=%d) -o $@
diff --git a/make/module.mk b/make/module.mk
index 80d4b21a..a926d207 100644
--- a/make/module.mk
+++ b/make/module.mk
@@ -253,8 +253,8 @@ ifeq ($(call TOBOOL,$(MODULE_ADD_IMPLICIT_DEPS)),true)
 # In the kernel, it adds core, compiler_builtins and
 # lib/rust_support (except for external crates).
 MODULE_ALL_DEPS += \
-	trusty/user/base/lib/libcore-rust/ \
-	trusty/user/base/lib/libcompiler_builtins-rust/ \
+	trusty/user/base/lib/libcore-rust \
+	trusty/user/base/lib/libcompiler_builtins-rust \
 
 # rust_support depends on some external crates. We cannot
 # add it as an implicit dependency to any of them because
@@ -263,9 +263,11 @@ MODULE_ALL_DEPS += \
 # external/rust/android-crates-io/crates.
 ifeq ($(filter external/rust/crates/%,$(MODULE)),)
 ifeq ($(filter external/rust/android-crates-io/crates/%,$(MODULE)),)
+ifeq ($(filter external/rust/android-crates-io/extra_versions/crates/%,$(MODULE)),)
 MODULE_ALL_DEPS += $(LKROOT)/lib/rust_support
 endif
 endif
+endif
 
 endif
 
@@ -359,6 +361,19 @@ ALLMODULE_OBJS := $(MODULE_INIT_OBJS) $(ALLMODULE_OBJS) $(MODULE_OBJECT) $(MODUL
 
 endif # kernel/userspace rust
 
+# trigger rebuild with any of the rust compiler flags change
+MODULE_RUSTFLAGS_CONFIG := $(MODULE_BUILDDIR)/rustflags.config
+
+# TODO(b/383631031): properly include $(GLOBAL_RUSTFLAGS) as set in rust.mk in MODULE_RUSTFLAGS
+$(MODULE_RUSTFLAGS_CONFIG): MODULE_RUSTFLAGS:=$(ARCH_$(ARCH)_RUSTFLAGS) $(MODULE_RUSTFLAGS)
+$(MODULE_RUSTFLAGS_CONFIG): MODULE:=$(MODULE)
+$(MODULE_RUSTFLAGS_CONFIG): configheader
+	@$(call INFO_DONE,$(MODULE),generating module rustflags.config, $@)
+	@$(call MAKECONFIGHEADER,$@,MODULE_RUSTFLAGS)
+
+GENERATED += $(MODULE_RUSTFLAGS_CONFIG)
+$(MODULE_RSOBJS): $(MODULE_RUSTFLAGS_CONFIG)
+
 # Build Rust sources
 $(addsuffix .d,$(MODULE_RSOBJS)):
 
@@ -466,5 +481,6 @@ MODULE_RUST_DEPS :=
 MODULE_RUST_STEM :=
 MODULE_SKIP_DOCS :=
 MODULE_ADD_IMPLICIT_DEPS := true
+MODULE_RUSTFLAGS_CONFIG :=
 
 endif # QUERY_MODULE (this line should stay after all other processing)
diff --git a/make/query.mk b/make/query.mk
index 02679270..07b85235 100644
--- a/make/query.mk
+++ b/make/query.mk
@@ -30,7 +30,7 @@
 # sets:
 # QUERY_foo for each variable "foo" named in QUERY_VARIABLES
 
-# these come from module.mk, rust.mk, and library.mk (in sections):
+# these come from module.mk, rust.mk, library.mk, and bindgen.mk (in sections):
 define QUERY_STOMPED_VARIABLES
 MODULE
 MODULE_SRCDIR
@@ -91,6 +91,17 @@ MODULE_DISABLED
 MODULE_SDK_LIB_NAME
 MODULE_SDK_HEADER_INSTALL_DIR
 MODULE_SDK_HEADERS
+
+MODULE_BINDGEN_ALLOW_FILES
+MODULE_BINDGEN_ALLOW_FUNCTIONS
+MODULE_BINDGEN_ALLOW_TYPES
+MODULE_BINDGEN_ALLOW_VARS
+MODULE_BINDGEN_BLOCK_TYPES
+MODULE_BINDGEN_CTYPES_PREFIX
+MODULE_BINDGEN_FLAGS
+MODULE_BINDGEN_OUTPUT_ENV_VAR
+MODULE_BINDGEN_SRC_HEADER
+MODULE_BINDGEN_OUTPUT_FILE_NAME
 endef
 
 ifeq ($(QUERY_MODULE),)
diff --git a/make/rust-toplevel.mk b/make/rust-toplevel.mk
index 5fb68d56..ecf89987 100644
--- a/make/rust-toplevel.mk
+++ b/make/rust-toplevel.mk
@@ -57,6 +57,18 @@ $(RUST_WRAPPER_OBJ): ARCH_RUSTFLAGS := $(ARCH_$(ARCH)_RUSTFLAGS)
 $(RUST_WRAPPER_OBJ): $(ALLMODULE_RLIBS) $(RUST_WRAPPER)
 	+$(NOECHO)$(RUSTC) $(GLOBAL_KERNEL_RUSTFLAGS) $(GLOBAL_SHARED_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(WRAPPER_RUSTFLAGS) -o $@ $(RUST_WRAPPER)
 
+# trigger rebuild with any of the rust compiler flags change
+RUST_WRAPPER_CONFIG := $(BUILDDIR)/rustflags.config
+
+$(RUST_WRAPPER_CONFIG): WRAPPER_RUSTFLAGS:=$(GLOBAL_KERNEL_RUSTFLAGS) $(GLOBAL_SHARED_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(WRAPPER_RUSTFLAGS)
+$(RUST_WRAPPER_CONFIG): RUST_WRAPPER_OBJ:=$(RUST_WRAPPER_OBJ)
+$(RUST_WRAPPER_CONFIG): configheader
+	@$(call INFO_DONE,$(RUST_WRAPPER_OBJ),generating rustflags.config, $@)
+	@$(call MAKECONFIGHEADER,$@,WRAPPER_RUSTFLAGS)
+
+GENERATED += $(RUST_WRAPPER_CONFIG)
+$(RUST_WRAPPER_OBJ): $(RUST_WRAPPER_CONFIG)
+
 # if there were no rust crates, don't build the .a
 ifneq ($(ALLMODULE_CRATE_STEMS),)
 EXTRA_OBJS += $(RUST_WRAPPER_OBJ)
@@ -103,3 +115,4 @@ RUST_WRAPPER_SRC :=
 WRAPPER_RUSTFLAGS :=
 WRAPPER_RUST_EXTERN_PATHS :=
 ALLMODULE_CRATE_STEMS_SORTED :=
+RUST_WRAPPER_CONFIG :=
diff --git a/make/rust.mk b/make/rust.mk
index 85c700cb..16a3ed1d 100644
--- a/make/rust.mk
+++ b/make/rust.mk
@@ -139,11 +139,16 @@ TRUSTY_APP_RUST_MAIN_SRC := $(filter %.rs,$(MODULE_SRCS))
 TRUSTY_APP_RUST_SRCDEPS := $(MODULE_SRCDEPS)
 endif
 
+TRUSTY_SKIP_DOCS ?= false
+ifeq ($(call TOBOOL,$(TRUSTY_SKIP_DOCS)),false)
 ifeq ($(call TOBOOL,$(MODULE_SKIP_DOCS)),false)
 ifneq ($(TRUSTY_SDK_LIB_DIR),)
 MODULE_RUSTDOC_OBJECT := $(TRUSTY_SDK_LIB_DIR)/doc/built/$(MODULE_RUST_STEM)
 endif
-else
+else # MODULE_SKIP_DOCS is true
+MODULE_RUSTDOC_OBJECT :=
+endif
+else # TRUSTY_SKIP_DOCS is true
 MODULE_RUSTDOC_OBJECT :=
 endif
 
@@ -159,6 +164,8 @@ $(MODULE_RSOBJS) $(MODULE_RUSTDOC_OBJECT): MODULE_RUST_ENV := $(MODULE_RUST_ENV)
 # Is module a kernel module? (not an app or using the library build system)
 ifeq ($(call TOBOOL,$(SAVED_MODULE_STACK)$(TRUSTY_NEW_MODULE_SYSTEM)$(TRUSTY_APP)),false)
 $(MODULE_RSOBJS) $(MODULE_RUSTDOC_OBJECT): GLOBAL_RUSTFLAGS := $(GLOBAL_SHARED_RUSTFLAGS) $(GLOBAL_KERNEL_RUSTFLAGS)
+# trigger rebuild if the custom kernel target changes
+$(MODULE_RSOBJS): $(ARCH_$(ARCH)_RUST_TARGET)
 else
 $(MODULE_RSOBJS) $(MODULE_RUSTDOC_OBJECT): GLOBAL_RUSTFLAGS := $(GLOBAL_SHARED_RUSTFLAGS) $(GLOBAL_USER_RUSTFLAGS)
 endif
```

