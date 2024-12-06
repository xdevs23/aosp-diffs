```diff
diff --git a/arch/arm/arm/cache-ops.S b/arch/arm/arm/cache-ops.S
index 9cb1f33f..45949064 100644
--- a/arch/arm/arm/cache-ops.S
+++ b/arch/arm/arm/cache-ops.S
@@ -315,7 +315,7 @@ FUNCTION(arch_clean_cache_range)
     add     r2, r0, r1                  // calculate the end address
     bic     r0, #(CACHE_LINE-1)         // align the start with a cache line
 0:
-    mcr     p15, 0, r0, c7, c10, 1      // clean cache to PoC by MVA
+    mcr     p15, 0, r0, c7, c10, 1      // clean cache to PoC by MVA (DCCMVAC)
     add     r0, #CACHE_LINE
     cmp     r0, r2
     blo     0b
@@ -341,7 +341,7 @@ FUNCTION(arch_clean_invalidate_cache_range)
     add     r2, r0, r1                  // calculate the end address
     bic     r0, #(CACHE_LINE-1)         // align the start with a cache line
 0:
-    mcr     p15, 0, r0, c7, c14, 1      // clean & invalidate dcache to PoC by MVA
+    mcr     p15, 0, r0, c7, c14, 1      // clean & invalidate dcache to PoC by MVA (DCCIMVAC)
     add     r0, r0, #CACHE_LINE
     cmp     r0, r2
     blo     0b
@@ -367,7 +367,7 @@ FUNCTION(arch_invalidate_cache_range)
     add     r2, r0, r1                  // calculate the end address
     bic     r0, #(CACHE_LINE-1)         // align the start with a cache line
 0:
-    mcr     p15, 0, r0, c7, c6, 1       // invalidate dcache to PoC by MVA
+    mcr     p15, 0, r0, c7, c6, 1       // invalidate dcache to PoC by MVA (DCIMVAC)
     add     r0, r0, #CACHE_LINE
     cmp     r0, r2
     blo     0b
@@ -392,7 +392,7 @@ FUNCTION(arch_sync_cache_range)
     bl      arch_clean_cache_range
 
     mov     r0, #0
-    mcr     p15, 0, r0, c7, c5, 0       // invalidate icache to PoU
+    mcr     p15, 0, r0, c7, c5, 0       // invalidate all icache to PoU (ICIALLU)
 
     pop     { pc }
 
diff --git a/arch/arm64/mmu.c b/arch/arm64/mmu.c
index 160e1923..ebc65ec1 100644
--- a/arch/arm64/mmu.c
+++ b/arch/arm64/mmu.c
@@ -344,7 +344,7 @@ static pte_t *arm64_mmu_get_page_table(vaddr_t index, uint page_size_shift, pte_
         case MMU_PTE_DESCRIPTOR_INVALID:
             ret = alloc_page_table(&paddr, page_size_shift);
             if (ret) {
-                TRACEF("failed to allocate page table\n");
+                TRACEF("failed to allocate page table, page_size_shift %u\n", page_size_shift);
                 return NULL;
             }
             vaddr = paddr_to_kvaddr(paddr);
diff --git a/arch/x86/64/exceptions.S b/arch/x86/64/exceptions.S
index 934ee768..6a7eb16a 100644
--- a/arch/x86/64/exceptions.S
+++ b/arch/x86/64/exceptions.S
@@ -150,7 +150,15 @@ DATA(_idt)
 .rept NUM_INT
     .short 0        /* low 16 bits of ISR offset (_isr#i & 0FFFFh) */
     .short CODE_64_SELECTOR   /* selector */
-.if i == INT_DOUBLE_FAULT /* Use dedicated stack ist1 for Double Fault Exception */
+.if i == INT_DOUBLE_FAULT || i == INT_NMI
+     /*
+      * Use dedicated stack ist1 for Double Fault Exception and
+      * Non-Maskable-Interrupt Exception. Resetting the stack pointer for
+      * double faults allows the kernel to recover from kernel stack
+      * overflows. Resetting the stack on NMI exceptions allows the NMI
+      * exception handler to run if the NMI triggered when the stack pointer
+      * was invalid, e.g. on syscall entry.
+      */
     .byte  1
 .else
     .byte  0
diff --git a/arch/x86/64/start.S b/arch/x86/64/start.S
index 27654049..ea181ca5 100644
--- a/arch/x86/64/start.S
+++ b/arch/x86/64/start.S
@@ -41,6 +41,7 @@
 
 #define MSR_EFER    0xc0000080
 #define EFER_NXE    0x00000800
+#define EFER_SCE    0x00000001
 #define MSR_GS_BASE 0xc0000101
 
 #define PHYS(x) ((x) - KERNEL_BASE + MEMBASE)
@@ -90,7 +91,7 @@
  *   src_addr: base address of PT if fill in PDE
  *             base address of physical address if fill in PTE
  *   attr:     X86_KERNEL_PD_FLAGS if fill in PDE
- *             X86_KERNEL_PD_LP_FLAGS if fill in PTE
+ *             X86_KERNEL_PT_FLAGS if fill in PTE
  */
 .macro fill_page_table_entry src_addr, attr
     movq \src_addr, %rsi
@@ -144,7 +145,7 @@
     movq $MEMBASE, %rsi
     addq $KERNEL_LOAD_OFFSET, %rsi
     andq $X86_PAGE_ALIGN, %rsi
-    orq  $X86_KERNEL_PD_LP_FLAGS, %rsi
+    orq  $X86_KERNEL_PT_FLAGS, %rsi
     movq %rsi, (%rdi)
 
     /* Check whether gdtr and bootstrap code share same PDE */
@@ -182,7 +183,7 @@
     shlq $3, %rax
     addq %rax, %rdi
     movq $PHYS(_gdtr_phys), %rsi
-    orq  $X86_KERNEL_PD_LP_FLAGS, %rsi
+    orq  $X86_KERNEL_PT_FLAGS, %rsi
     movq %rsi, (%rdi)
 .endm
 
@@ -333,7 +334,7 @@
 .Lfill_upper_mem_pte:
     movq %rax, %rdx
     shlq $PAGE_DIV_SHIFT, %rdx
-    addq $X86_KERNEL_PD_LP_FLAGS, %rdx
+    addq $X86_KERNEL_PT_FLAGS, %rdx
     movq %rdx, (%rsi)
     incq %rax
     addq $8, %rsi
@@ -440,7 +441,8 @@ paging_setup:
     movl $MSR_EFER ,%ecx
     rdmsr
     /* NXE bit should be set, since we update XD bit in page table */
-    orl $EFER_NXE,%eax
+    /* Set SCE to enable AMD compatible syscall support */
+    orl $(EFER_NXE | EFER_SCE),%eax
     wrmsr
 
     /* setting the corresponding PML4E to map from KERNEL_BASE */
@@ -491,7 +493,7 @@ paging_setup:
     movq $PHYS(pt), %rdi
 
     /* fill in PTEs */
-    fill_page_table_entry $MEMBASE, $X86_KERNEL_PD_LP_FLAGS
+    fill_page_table_entry $MEMBASE, $X86_KERNEL_PT_FLAGS
 
     update_mapping_attribute_of_each_section
 
diff --git a/arch/x86/arch.c b/arch/x86/arch.c
index 7f11314d..99bb440d 100644
--- a/arch/x86/arch.c
+++ b/arch/x86/arch.c
@@ -35,6 +35,7 @@
 #include <platform.h>
 #include <sys/types.h>
 #include <string.h>
+#include "arch/arch_thread.h"
 
 /* early stack */
 uint8_t _kstack[PAGE_SIZE] __ALIGNED(8);
@@ -69,6 +70,27 @@ static void init_per_cpu_state(uint cpu)
     }
 }
 
+void x86_check_and_fix_gs(void)
+{
+    uint cpu = arch_curr_cpu_num();
+    x86_per_cpu_states_t *expected_gs_base = &per_cpu_states[cpu];
+    x86_per_cpu_states_t *current_gs_base = (void *)read_msr(X86_MSR_GS_BASE);
+
+    if (current_gs_base != expected_gs_base) {
+        printf("GS base is wrong %p != %p, try swapgs\n", current_gs_base, expected_gs_base);
+        __asm__ __volatile__ (
+            "swapgs"
+        );
+        current_gs_base = (void *)read_msr(X86_MSR_GS_BASE);
+        if (current_gs_base != expected_gs_base) {
+            printf("GS base is still wrong after swapgs %p != %p\n",
+                   current_gs_base, expected_gs_base);
+            write_msr(X86_MSR_GS_BASE, (uint64_t)expected_gs_base);
+            current_gs_base = (void *)read_msr(X86_MSR_GS_BASE);
+        }
+    }
+}
+
 static void set_tss_segment_percpu(void)
 {
     uint64_t addr;
@@ -122,10 +144,50 @@ static void setup_syscall_percpu(void)
      *      RIP          <-  SYSENTER_EIP_MSR
      *      CS.Selector  <-  SYSENTER_CS_MSR[15:0] & 0xFFFCH
      *      SS.Selector  <-  CS.Selector + 8
+     * SYSEXIT (w/64-bit operand):
+     *      CS.Selector  <-  (SYSENTER_CS_MSR[15:0] + 32) | 3
+     *      SS.Selector  <-  CS.Selector + 8
      */
+    static_assert(CODE_64_SELECTOR + 8 == STACK_64_SELECTOR);
+    static_assert(CODE_64_SELECTOR + 32 == USER_CODE_64_SELECTOR);
+    static_assert(CODE_64_SELECTOR + 32 + 8 == USER_DATA_64_SELECTOR);
+
     write_msr(SYSENTER_CS_MSR, CODE_64_SELECTOR);
     write_msr(SYSENTER_ESP_MSR, x86_read_gs_with_offset(SYSCALL_STACK_OFF));
     write_msr(SYSENTER_EIP_MSR, (uint64_t)(x86_syscall));
+
+    /*
+     * SYSCALL:
+     *      RIP          <-  LSTAR_MSR
+     *      CS.Selector  <-  STAR_MSR[47:32] & 0xFFFCH
+     *      SS.Selector  <-  STAR_MSR[47:32] + 8
+     * SYSRET (w/64-bit operand):
+     *      CS.Selector  <-  (STAR_MSR[63:48] + 16) | 3
+     *      SS.Selector  <-  (STAR_MSR[63:48] + 8) | 3 - On Intel
+     *      SS.Selector  <-  (STAR_MSR[63:48] + 8) - On AMD
+     *
+     * AMD says the hidden parts of SS are set to fixed values for SYSCALL but
+     * perplexingly left unchanged for SYSRET. Intel sets the SS hidden parts
+     * to (different) fixed values for both SYSCALL and SYSRET.
+     *
+     * AMD also states that the hidden parts of SS are ignored in 64 bit mode,
+     * but IRET throws a GP exception if SS.RPL != CS.RPL. We therefore need
+     * to set STAR_MSR[49:48] to 3 (USER_RPL) to be compatible with AMD CPUs.
+     */
+    static_assert(CODE_64_SELECTOR + 8 == STACK_64_SELECTOR);
+    static_assert(USER_CODE_COMPAT_SELECTOR + 16 == USER_CODE_64_SELECTOR);
+    /*
+     * Note that USER_DATA_COMPAT_SELECTOR is not the same value as
+     * USER_DATA_64_SELECTOR (since these instructions use hardcoded offsets),
+     * but the content of the descriptor is the same. The process will start
+     * with one SS value, but then get a different value after the syscall.
+     */
+    static_assert(USER_CODE_COMPAT_SELECTOR + 8 == USER_DATA_COMPAT_SELECTOR);
+
+    write_msr(STAR_MSR, (uint64_t)CODE_64_SELECTOR << 32 |
+                        (uint64_t)(USER_CODE_COMPAT_SELECTOR | USER_RPL) << 48);
+    write_msr(LSTAR_MSR, (uint64_t)(x86_syscall));
+    write_msr(SFMASK_MSR, IF_MASK | DF_MASK);
 }
 
 void arch_early_init(void)
@@ -217,6 +279,10 @@ void arch_enter_uspace(vaddr_t ep,
      *
      * More details please refer "IRET/IRETD -- Interrupt Return" in Intel
      * ISDM VOL2 <Instruction Set Reference>.
+     *
+     * Disable interrupts before swapgs so avoid getting entering the
+     * interrupt vector with a user-space gs descriptor and a kernel cs
+     * selector (which exceptions.S:interrupt_common checks).
      */
     __asm__ __volatile__ (
             "pushq %0   \n"
@@ -225,6 +291,7 @@ void arch_enter_uspace(vaddr_t ep,
             "pushq %3   \n"
             "pushq %4   \n"
             "pushq %5   \n"
+            "cli \n"
             "swapgs \n"
             "xorq %%r15, %%r15 \n"
             "xorq %%r14, %%r14 \n"
diff --git a/arch/x86/faults.c b/arch/x86/faults.c
index 5ecfa01c..8b783970 100644
--- a/arch/x86/faults.c
+++ b/arch/x86/faults.c
@@ -239,7 +239,23 @@ void x86_exception_handler(x86_iframe_t *frame)
 #endif
             break;
 
+        case INT_NMI:
+            /*
+             * Don't trust GS for NMI exceptions. The NMI exception could
+             * trigger right before swap_gs in the exception entry code.
+             */
+            x86_check_and_fix_gs();
+            x86_unhandled_exception(frame);
+            break;
+
         case INT_DOUBLE_FAULT:
+            /*
+             * Don't trust GS for double fault exceptions. If a bug allowed
+             * user-space to run with a near full kernel stack (in TSS:RSP0),
+             * then a double fault might occur after the switch to the kernel
+             * CS, but before runs swap_gs in the original exception handler.
+             */
+            x86_check_and_fix_gs();
             exception_die(frame, "double fault (kernel stack overflow?)\n");
             break;
 
diff --git a/arch/x86/include/arch/arch_thread.h b/arch/x86/include/arch/arch_thread.h
index 3db01d59..8835a765 100644
--- a/arch/x86/include/arch/arch_thread.h
+++ b/arch/x86/include/arch/arch_thread.h
@@ -26,6 +26,7 @@
 #include <sys/types.h>
 
 #define IF_MASK             0x0200
+#define DF_MASK             0x0400
 #define IOPL_MASK           0x3000
 #define RSVD                0x0002
 
@@ -37,6 +38,11 @@
 #define SYSENTER_ESP_MSR    0x175
 #define SYSENTER_EIP_MSR    0x176
 
+#define STAR_MSR (0xC0000081)
+#define LSTAR_MSR (0xC0000082)
+#define CSTAR_MSR (0xC0000083)
+#define SFMASK_MSR (0xC0000084)
+
 struct arch_thread {
     vaddr_t sp;
     vaddr_t fs_base;
diff --git a/arch/x86/include/arch/x86.h b/arch/x86/include/arch/x86.h
index 0480193b..2a3852b3 100644
--- a/arch/x86/include/arch/x86.h
+++ b/arch/x86/include/arch/x86.h
@@ -910,6 +910,7 @@ static inline void x86_disallow_explicit_smap(void) {
 }
 
 void x86_syscall(void);
+void x86_check_and_fix_gs(void);
 
 #endif // ARCH_X86_64
 
diff --git a/arch/x86/include/arch/x86/exceptions.h b/arch/x86/include/arch/x86/exceptions.h
index 193414ae..d12d7ae5 100644
--- a/arch/x86/include/arch/x86/exceptions.h
+++ b/arch/x86/include/arch/x86/exceptions.h
@@ -25,6 +25,7 @@
 
 #define INT_DIVIDE_0        0x00
 #define INT_DEBUG_EX        0x01
+#define INT_NMI             0x02
 #define INT_INVALID_OP      0x06
 #define INT_DEV_NA_EX       0x07
 #define INT_DOUBLE_FAULT    0x08
diff --git a/arch/x86/include/arch/x86/mmu.h b/arch/x86/include/arch/x86/mmu.h
index bda287c8..fa321cd1 100644
--- a/arch/x86/include/arch/x86/mmu.h
+++ b/arch/x86/include/arch/x86/mmu.h
@@ -40,11 +40,14 @@
 #define X86_MMU_CACHE_DISABLE   0x010       /* C Cache disable */
 
 /* default flags for inner page directory entries */
-#define X86_KERNEL_PD_FLAGS (X86_MMU_PG_G | X86_MMU_PG_RW | X86_MMU_PG_P | X86_MMU_PG_U)
+#define X86_KERNEL_PD_FLAGS (X86_MMU_PG_RW | X86_MMU_PG_P | X86_MMU_PG_U)
 
 /* default flags for 2MB/4MB/1GB page directory entries */
 #define X86_KERNEL_PD_LP_FLAGS (X86_MMU_PG_G | X86_MMU_PG_PS | X86_MMU_PG_RW | X86_MMU_PG_P)
 
+/* default flags for 4K page table entries */
+#define X86_KERNEL_PT_FLAGS (X86_MMU_PG_G | X86_MMU_PG_RW | X86_MMU_PG_P)
+
 #if !defined(PAGE_SIZE)
 #define PAGE_SIZE       4096
 #elif PAGE_SIZE != 4096
diff --git a/arch/x86/thread.c b/arch/x86/thread.c
index cf452f7f..083a259e 100644
--- a/arch/x86/thread.c
+++ b/arch/x86/thread.c
@@ -143,8 +143,16 @@ void arch_context_switch(thread_t *oldthread, thread_t *newthread)
 #if X86_WITH_FPU
     fpu_context_switch(oldthread, newthread);
 #endif
+    /* Exceptions and interrupts from user-space sets RSP to TSS:RSP0 */
     tss_base->rsp0 = stack_top;
+    /* SYSENTER instruction sets RSP to SYSENTER_ESP_MSR */
     write_msr(SYSENTER_ESP_MSR, stack_top);
+    /*
+     * The SYSCALL instruction does not set RSP, so we also store the stack
+     * pointer in GS:SYSCALL_STACK_OFF so the syscall handler can easily get
+     * it.
+     */
+    x86_write_gs_with_offset(SYSCALL_STACK_OFF, stack_top);
 
     /* Switch fs base which used to store tls */
     oldthread->arch.fs_base = read_msr(X86_MSR_FS_BASE);
diff --git a/arch/x86/x86_64-unknown-trusty-kernel.json b/arch/x86/x86_64-unknown-trusty-kernel.json
index c540868c..51c8fa25 100644
--- a/arch/x86/x86_64-unknown-trusty-kernel.json
+++ b/arch/x86/x86_64-unknown-trusty-kernel.json
@@ -3,7 +3,7 @@
     "cpu": "x86-64",
     "crt-objects-fallback": "musl",
     "crt-static-default": false,
-    "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128",
+    "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
     "dynamic-linking": false,
     "env": "musl",
     "has-rpath": false,
diff --git a/dev/virtio/vsock-rust/src/err.rs b/dev/virtio/vsock-rust/src/err.rs
index f65929fd..39ff21bb 100644
--- a/dev/virtio/vsock-rust/src/err.rs
+++ b/dev/virtio/vsock-rust/src/err.rs
@@ -26,8 +26,11 @@ use virtio_drivers::transport::pci::VirtioPciError;
 use rust_support::Error as LkError;
 use virtio_drivers::Error as VirtioError;
 
+#[derive(Debug)]
 pub enum Error {
+    #[allow(dead_code)]
     Pci(VirtioPciError),
+    #[allow(dead_code)]
     Virtio(VirtioError),
     Lk(LkError),
 }
diff --git a/dev/virtio/vsock-rust/src/hal.rs b/dev/virtio/vsock-rust/src/hal.rs
index 0f3af9cf..42574f5b 100644
--- a/dev/virtio/vsock-rust/src/hal.rs
+++ b/dev/virtio/vsock-rust/src/hal.rs
@@ -104,6 +104,9 @@ impl TrustyHal {
     }
 }
 
+// Safety: TrustyHal is stateless and thus trivially safe to send to another thread
+unsafe impl Send for TrustyHal {}
+
 unsafe impl Hal for TrustyHal {
     // Safety:
     // Function either returns a non-null, properly aligned pointer or panics the kernel.
diff --git a/dev/virtio/vsock-rust/src/lib.rs b/dev/virtio/vsock-rust/src/lib.rs
index 6bf377ca..0796e052 100644
--- a/dev/virtio/vsock-rust/src/lib.rs
+++ b/dev/virtio/vsock-rust/src/lib.rs
@@ -7,3 +7,6 @@
 mod err;
 mod hal;
 mod pci;
+mod vsock;
+
+pub use pci::pci_init_mmio;
diff --git a/dev/virtio/vsock-rust/src/pci.rs b/dev/virtio/vsock-rust/src/pci.rs
index 6624cea0..07771e7d 100644
--- a/dev/virtio/vsock-rust/src/pci.rs
+++ b/dev/virtio/vsock-rust/src/pci.rs
@@ -22,10 +22,11 @@
  */
 
 #![deny(unsafe_op_in_unsafe_fn)]
-
 use core::ffi::c_int;
 use core::ptr;
 
+use alloc::sync::Arc;
+
 use log::debug;
 
 use virtio_drivers::device::socket::VirtIOSocket;
@@ -49,18 +50,25 @@ use rust_support::Error as LkError;
 
 use crate::err::Error;
 use crate::hal::TrustyHal;
+use crate::vsock::VsockDevice;
 
 impl TrustyHal {
     fn init_vsock(pci_root: &mut PciRoot, device_function: DeviceFunction) -> Result<(), Error> {
         let transport = PciTransport::new::<Self>(pci_root, device_function)?;
-        let driver: VirtIOSocket<TrustyHal, PciTransport> = VirtIOSocket::new(transport)?;
-        let _manager = VsockConnectionManager::new(driver); // TODO move
+        let driver: VirtIOSocket<TrustyHal, PciTransport, 4096> = VirtIOSocket::new(transport)?;
+        let manager = VsockConnectionManager::new_with_capacity(driver, 4096);
+
+        let device_for_rx = Arc::new(VsockDevice::new(manager));
+        let device_for_tx = device_for_rx.clone();
 
         Builder::new()
             .name(c"virtio_vsock_rx")
             .priority(Priority::HIGH)
             .spawn(move || {
-                todo!("Call routine for virtio rx worker");
+                crate::vsock::vsock_rx_loop(device_for_rx)
+                    .err()
+                    .unwrap_or(LkError::NO_ERROR.into())
+                    .into_c()
             })
             .map_err(|e| LkError::from_lk(e).unwrap_err())?;
 
@@ -68,7 +76,10 @@ impl TrustyHal {
             .name(c"virtio_vsock_tx")
             .priority(Priority::HIGH)
             .spawn(move || {
-                todo!("Call routine for virtio tx worker");
+                crate::vsock::vsock_tx_loop(device_for_tx)
+                    .err()
+                    .unwrap_or(LkError::NO_ERROR.into())
+                    .into_c()
             })
             .map_err(|e| LkError::from_lk(e).unwrap_err())?;
 
diff --git a/dev/virtio/vsock-rust/src/vsock.rs b/dev/virtio/vsock-rust/src/vsock.rs
new file mode 100644
index 00000000..e21d704a
--- /dev/null
+++ b/dev/virtio/vsock-rust/src/vsock.rs
@@ -0,0 +1,581 @@
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
+#![deny(unsafe_op_in_unsafe_fn)]
+use core::ffi::c_void;
+use core::ops::Deref;
+use core::ops::DerefMut;
+use core::ptr::eq;
+use core::ptr::null_mut;
+use core::time::Duration;
+
+use alloc::boxed::Box;
+use alloc::ffi::CString;
+use alloc::format;
+use alloc::sync::Arc;
+use alloc::vec;
+use alloc::vec::Vec;
+
+use log::debug;
+use log::error;
+use log::info;
+use log::warn;
+
+use rust_support::handle::IPC_HANDLE_POLL_HUP;
+use rust_support::handle::IPC_HANDLE_POLL_MSG;
+use rust_support::handle::IPC_HANDLE_POLL_READY;
+use rust_support::ipc::iovec_kern;
+use rust_support::ipc::ipc_get_msg;
+use rust_support::ipc::ipc_msg_info;
+use rust_support::ipc::ipc_msg_kern;
+use rust_support::ipc::ipc_port_connect_async;
+use rust_support::ipc::ipc_put_msg;
+use rust_support::ipc::ipc_read_msg;
+use rust_support::ipc::ipc_send_msg;
+use rust_support::ipc::zero_uuid;
+use rust_support::ipc::IPC_CONNECT_WAIT_FOR_PORT;
+use rust_support::ipc::IPC_PORT_PATH_MAX;
+use rust_support::sync::Mutex;
+use rust_support::thread;
+use rust_support::thread::sleep;
+use virtio_drivers::device::socket::VsockAddr;
+use virtio_drivers::device::socket::VsockConnectionManager;
+use virtio_drivers::device::socket::VsockEvent;
+use virtio_drivers::device::socket::VsockEventType;
+use virtio_drivers::transport::Transport;
+use virtio_drivers::Hal;
+use virtio_drivers::PAGE_SIZE;
+
+use rust_support::handle::HandleRef;
+use rust_support::handle_set::HandleSet;
+
+use rust_support::Error as LkError;
+
+use crate::err::Error;
+
+const ACTIVE_TIMEOUT: Duration = Duration::from_secs(5);
+
+#[allow(dead_code)]
+#[derive(Clone, Copy, Debug, Default, PartialEq)]
+enum VsockConnectionState {
+    #[default]
+    Invalid = 0,
+    VsockOnly,
+    TipcOnly,
+    TipcConnecting,
+    Active,
+    TipcClosed,
+    Closed,
+}
+
+#[derive(Default)]
+struct VsockConnection {
+    peer: VsockAddr,
+    local_port: u32,
+    state: VsockConnectionState,
+    tipc_port_name: Option<CString>,
+    href: HandleRef,
+    tx_count: u64,
+    tx_since_rx: u64,
+    rx_count: u64,
+    rx_since_tx: u64,
+}
+
+impl VsockConnection {
+    fn new(peer: VsockAddr, local_port: u32) -> Self {
+        Self {
+            peer,
+            local_port,
+            state: VsockConnectionState::VsockOnly,
+            tipc_port_name: None,
+            ..Default::default()
+        }
+    }
+
+    fn tipc_port_name(&self) -> &str {
+        self.tipc_port_name
+            .as_ref()
+            .expect("port name not set")
+            .to_str()
+            .expect("invalid port name")
+    }
+
+    fn print_stats(&self) {
+        info!(
+            "vsock: tx {:?} ({:>5?}) rx {:?} ({:>5?}) port: {}, remote {}, state {:?}",
+            self.tx_since_rx,
+            self.tx_count,
+            self.rx_since_tx,
+            self.rx_count,
+            self.tipc_port_name(),
+            self.peer.port,
+            self.state
+        );
+    }
+}
+
+fn vsock_connection_lookup(
+    connections: &mut Vec<VsockConnection>,
+    remote_port: u32,
+) -> Option<(usize, &mut VsockConnection)> {
+    connections
+        .iter_mut()
+        .enumerate()
+        .find(|(_idx, connection)| connection.peer.port == remote_port)
+}
+
+pub struct VsockDevice<H, T>
+where
+    H: Hal,
+    T: Transport,
+{
+    connections: Mutex<Vec<VsockConnection>>,
+    handle_set: HandleSet,
+    connection_manager: Mutex<VsockConnectionManager<H, T, 4096>>,
+}
+
+impl<H, T> VsockDevice<H, T>
+where
+    H: Hal,
+    T: Transport,
+{
+    pub(crate) fn new(manager: VsockConnectionManager<H, T, 4096>) -> Self {
+        Self {
+            connections: Mutex::new(Vec::new()),
+            handle_set: HandleSet::new(),
+            connection_manager: Mutex::new(manager),
+        }
+    }
+
+    fn vsock_rx_op_request(&self, peer: VsockAddr, local: VsockAddr) {
+        debug!("dst_port {}, src_port {}", local.port, peer.port);
+
+        // do we already have a connection?
+        let mut guard = self.connections.lock();
+        if let Some(_) = guard
+            .deref()
+            .iter()
+            .find(|connection| connection.peer == peer && connection.local_port == local.port)
+        {
+            panic!("connection already exists");
+        };
+
+        guard.deref_mut().push(VsockConnection::new(peer, local.port));
+    }
+
+    fn vsock_connect_tipc(
+        &self,
+        c: &mut VsockConnection,
+        length: usize,
+        source: VsockAddr,
+        destination: VsockAddr,
+    ) -> Result<(), Error> {
+        let mut buffer = [0; IPC_PORT_PATH_MAX as usize];
+        assert!(length < buffer.len());
+        let mut data_len = self
+            .connection_manager
+            .lock()
+            .deref_mut()
+            .recv(source, destination.port, &mut buffer)
+            .unwrap();
+        assert!(data_len == length);
+        // allow manual connect from nc in line mode
+        if buffer[data_len - 1] == '\n' as _ {
+            data_len -= 1;
+        }
+        let port_name = &buffer[0..data_len];
+        // should not contain any null bytes
+        c.tipc_port_name = CString::new(port_name).ok();
+
+        // Safety:
+        // - `cid`` is a valid uuid because we use a bindgen'd constant
+        // - `path` points to a null-terminated C-string. The null byte was appended by
+        //   `CString::new`.
+        // - `max_path` is the length of `path` in bytes including the null terminator.
+        //   It is always less than or equal to IPC_PORT_PATH_MAX.
+        // - `flags` contains a flag value accepted by the callee
+        // - `chandle_ptr` points to memory that the kernel can store a pointer into
+        //   after the callee returns.
+        let ret = unsafe {
+            ipc_port_connect_async(
+                &zero_uuid,
+                c.tipc_port_name.as_ref().unwrap().as_ptr(),
+                data_len + /* null byte added by CString::new */ 1,
+                IPC_CONNECT_WAIT_FOR_PORT,
+                &mut (*c.href.as_mut_ptr()).handle,
+            )
+        };
+        if ret != 0 {
+            warn!(
+                "failed to connect to {}, remote {}, connect err {ret}",
+                c.tipc_port_name(),
+                c.peer.port
+            )
+        }
+
+        info!("wait for connection to {}, remote {}", c.tipc_port_name(), c.peer.port);
+
+        c.state = VsockConnectionState::TipcConnecting;
+
+        // We cannot use the address of the connection as the cookie as it may move.
+        // Use the heap address of the `handle_ref` instead as it will not get moved.
+        let cookie = c.href.as_mut_ptr() as *mut c_void;
+        c.href.set_cookie(cookie);
+        c.href.set_emask(!0);
+        c.href.set_id(c.peer.port);
+
+        self.handle_set.attach(&mut c.href).map_err(|e| {
+            c.href.handle_close();
+            Error::Lk(e)
+        })
+    }
+
+    fn vsock_tx_tipc_ready(&self, c: &mut VsockConnection) {
+        if c.state != VsockConnectionState::TipcConnecting {
+            panic!("warning, got poll ready in unexpected state: {:?}", c.state);
+        }
+        info!("connected to {}, remote {:?}", c.tipc_port_name(), c.peer.port);
+        c.state = VsockConnectionState::Active;
+
+        let buffer = [0u8];
+        let res = self.connection_manager.lock().send(c.peer, c.local_port, &buffer);
+        if res.is_err() {
+            warn!("failed to send connected status message");
+        }
+    }
+
+    fn vsock_rx_channel(
+        &self,
+        c: &mut VsockConnection,
+        length: usize,
+        source: VsockAddr,
+        destination: VsockAddr,
+        rx_buffer: &mut Box<[u8]>,
+    ) -> Result<(), Error> {
+        assert!(length <= rx_buffer.len());
+        let data_len = self
+            .connection_manager
+            .lock()
+            .deref_mut()
+            .recv(source, destination.port, rx_buffer)
+            .unwrap();
+
+        // TODO: handle large messages properly
+        assert!(data_len == length);
+
+        let mut iov = iovec_kern { iov_base: rx_buffer.as_mut_ptr() as _, iov_len: data_len };
+        let mut msg = ipc_msg_kern::new(&mut iov);
+
+        c.rx_count += 1;
+        c.rx_since_tx += 1;
+        c.tx_since_rx = 0;
+        // Safety:
+        // `c.href.handle` is a handle attached to a tipc channel.
+        // `msg` contains an `iov` which points to a buffer from which
+        // the kernel can read `iov_len` bytes.
+        let ret = unsafe { ipc_send_msg(c.href.handle(), &mut msg) };
+        if ret < 0 {
+            error!("failed to send {length} bytes to {}: {ret} ", c.tipc_port_name());
+            LkError::from_lk(ret)?;
+        }
+        if ret as usize != length {
+            error!("sent {ret} bytes but expected to send {length} bytes");
+            Err(LkError::ERR_IO)?;
+        }
+
+        debug!("sent {length} bytes to {}", c.tipc_port_name());
+        self.connection_manager.lock().deref_mut().update_credit(c.peer, c.local_port).unwrap();
+
+        Ok(())
+    }
+
+    fn vsock_connection_close(&self, c: &mut VsockConnection, vsock_done: bool) -> bool {
+        info!(
+            "remote_port {}, tipc_port_name {}, state {:?}",
+            c.peer.port,
+            c.tipc_port_name(),
+            c.state
+        );
+
+        if c.state == VsockConnectionState::VsockOnly {
+            info!("tipc vsock only connection closed");
+            c.state = VsockConnectionState::TipcClosed;
+        }
+
+        if c.state == VsockConnectionState::Active
+            || c.state == VsockConnectionState::TipcConnecting
+        {
+            // The handle set owns the only reference we have to the handle and
+            // handle_set_wait might have already returned a pointer to c
+            c.href.detach();
+            c.href.handle_close();
+            c.href.set_cookie(null_mut());
+            info!("tipc handle closed");
+            c.state = VsockConnectionState::TipcClosed;
+        }
+        if vsock_done && c.state == VsockConnectionState::TipcClosed {
+            info!("vsock closed");
+            c.state = VsockConnectionState::Closed;
+        }
+        if c.state == VsockConnectionState::Closed && c.href.cookie().is_null() {
+            info!("remove connection");
+            c.print_stats();
+            return true; // remove connection
+        }
+        return false; // keep connection
+    }
+
+    fn print_stats(&self) {
+        let guard = self.connections.lock();
+        let connections = guard.deref();
+        for connection in connections {
+            connection.print_stats();
+        }
+    }
+}
+
+// Safety: each field of a `VsockDevice` is safe to transfer across thread boundaries
+// TODO: remove this once https://github.com/rcore-os/virtio-drivers/pull/146 lands
+unsafe impl<H, T> Send for VsockDevice<H, T>
+where
+    H: Hal,
+    T: Transport,
+{
+}
+
+// Safety: each field of a `VsockDevice` is safe to share between threads
+// TODO: remove this once https://github.com/rcore-os/virtio-drivers/pull/146 lands
+unsafe impl<H, T> Sync for VsockDevice<H, T>
+where
+    H: Hal,
+    T: Transport,
+{
+}
+
+pub(crate) fn vsock_rx_loop<H, T>(device: Arc<VsockDevice<H, T>>) -> Result<(), Error>
+where
+    H: Hal,
+    T: Transport,
+{
+    let local_port = 1;
+    let ten_ms = Duration::from_millis(10);
+    let mut rx_buffer = vec![0u8; PAGE_SIZE].into_boxed_slice();
+
+    debug!("starting vsock_rx_loop");
+    device.connection_manager.lock().deref_mut().listen(local_port);
+
+    loop {
+        // TODO: use interrupts instead of polling
+        let event = device.connection_manager.lock().deref_mut().poll()?;
+        if let Some(VsockEvent { source, destination, event_type, .. }) = event {
+            match event_type {
+                VsockEventType::ConnectionRequest => {
+                    device.vsock_rx_op_request(source, destination);
+                }
+                VsockEventType::Connected => {
+                    panic!("outbound connections not supported");
+                }
+                VsockEventType::Received { length } => {
+                    debug!("recv destination: {destination:?}");
+
+                    let mut guard = device.connections.lock();
+                    if let Some((conn_idx, mut connection)) =
+                        vsock_connection_lookup(guard.deref_mut(), source.port)
+                    {
+                        if let Err(e) = match connection {
+                            ref mut c @ VsockConnection {
+                                state: VsockConnectionState::VsockOnly,
+                                ..
+                            } => device.vsock_connect_tipc(c, length, source, destination),
+                            ref mut c @ VsockConnection {
+                                state: VsockConnectionState::Active,
+                                ..
+                            } => device.vsock_rx_channel(
+                                *c,
+                                length,
+                                source,
+                                destination,
+                                &mut rx_buffer,
+                            ),
+                            VsockConnection {
+                                state: VsockConnectionState::TipcConnecting, ..
+                            } => {
+                                warn!("got data while still waiting for tipc connection");
+                                Err(LkError::ERR_BAD_STATE.into())
+                            }
+                            VsockConnection { state: s, .. } => {
+                                error!("got data for connection in state {s:?}");
+                                Err(LkError::ERR_BAD_STATE.into())
+                            }
+                        } {
+                            error!("failed to receive data from vsock connection:  {e:?}");
+                            // TODO: add reset function to device or connection?
+                            let _ = device
+                                .connection_manager
+                                .lock()
+                                .deref_mut()
+                                .force_close(connection.peer, connection.local_port);
+
+                            if device.vsock_connection_close(connection, true) {
+                                // TODO: find a proper way to satisfy the borrow checker
+                                guard.deref_mut().swap_remove(conn_idx);
+                            }
+                        }
+                    } else {
+                        warn!("got packet for unknown connection");
+                    }
+                }
+                VsockEventType::Disconnected { reason } => {
+                    debug!("disconnected from peer. reason: {reason:?}");
+                    let mut guard = device.connections.lock();
+                    let connections = guard.deref_mut();
+                    if let Some((c_idx, c)) = vsock_connection_lookup(connections, source.port) {
+                        let vsock_done = true;
+                        if device.vsock_connection_close(c, vsock_done) {
+                            // TODO: find a proper way to satisfy the borrow checker
+                            connections.swap_remove(c_idx);
+                        }
+                    } else {
+                        warn!("got disconnect ({reason:?}) for unknown connection");
+                    }
+                }
+                VsockEventType::CreditUpdate => { /* nothing to do */ }
+                VsockEventType::CreditRequest => {
+                    // Polling the VsockConnectionManager won't return this event type
+                    panic!("don't know how to handle credit requests");
+                }
+            }
+        } else {
+            sleep(ten_ms);
+        }
+    }
+}
+
+pub(crate) fn vsock_tx_loop<H, T>(device: Arc<VsockDevice<H, T>>) -> Result<(), Error>
+where
+    H: Hal,
+    T: Transport,
+{
+    let mut timeout = Duration::MAX;
+    let ten_secs = Duration::from_secs(10);
+    let mut tx_buffer = vec![0u8; PAGE_SIZE].into_boxed_slice();
+    loop {
+        let mut href = HandleRef::default();
+        let mut ret = device.handle_set.handle_set_wait(&mut href, timeout);
+        if ret == Err(LkError::ERR_NOT_FOUND) {
+            // handle_set_wait returns ERR_NOT_FOUND if the handle_set is empty
+            // but we can wait for it to become non-empty using handle_wait.
+            // Once that that returns we have to call handle_set_wait again to
+            // get the event we care about.
+            info!("handle_set_wait failed: {}", ret.unwrap_err());
+            ret = device.handle_set.handle_wait(&mut href.emask(), timeout);
+            if ret != Err(LkError::ERR_TIMED_OUT.into()) {
+                info!("handle_wait on handle set returned: {ret:?}");
+                continue;
+            }
+            // fall through to ret == ERR_TIMED_OUT case, then continue
+        }
+        if ret == Err(LkError::ERR_TIMED_OUT) {
+            info!("tx inactive for {timeout:?} ms");
+            timeout = Duration::MAX;
+            device.print_stats();
+            continue;
+        }
+        if ret.is_err() {
+            warn!("handle_set_wait failed: {}", ret.unwrap_err());
+            thread::sleep(ten_secs);
+            continue;
+        }
+
+        let mut guard = device.connections.lock();
+        let connections = guard.deref_mut();
+        if let Some((_, c)) = vsock_connection_lookup(connections, href.id()) {
+            if !eq(c.href.as_mut_ptr() as *mut c_void, href.cookie()) {
+                panic!(
+                    "unexpected cookie {:?} != {:?} for connection {}",
+                    href.cookie(),
+                    c.href.as_mut_ptr(),
+                    c.tipc_port_name()
+                );
+            }
+
+            if href.emask() & IPC_HANDLE_POLL_READY != 0 {
+                device.vsock_tx_tipc_ready(c);
+            }
+            if href.emask() & IPC_HANDLE_POLL_MSG != 0 {
+                // Print stats if we don't send any more packets for a while
+                timeout = ACTIVE_TIMEOUT;
+                // TODO: loop and read all messages?
+                let mut msg_info = ipc_msg_info::default();
+
+                // TODO: add more idiomatic Rust interface
+                // Safety:
+                // `c.href.handle` is a valid handle to a tipc channel.
+                // `ipc_get_msg` can store a message descriptor in `msg_info`.
+                let ret = unsafe { ipc_get_msg(c.href.handle(), &mut msg_info) };
+                if ret == rust_support::Error::NO_ERROR.into() {
+                    let mut iov: iovec_kern = tx_buffer.as_mut().into();
+                    let mut msg = ipc_msg_kern::new(&mut iov);
+
+                    // Safety:
+                    // `c.href.handle` is a valid handle to a tipc channel.
+                    // `msg_info` holds the results of a successful call to `ipc_get_msg`
+                    // using the same handle.
+                    let ret = unsafe { ipc_read_msg(c.href.handle(), msg_info.id, 0, &mut msg) };
+
+                    // Safety:
+                    // `ipc_put_msg` was called with the same handle and msg_info arguments.
+                    unsafe { ipc_put_msg(c.href.handle(), msg_info.id) };
+                    if ret >= 0 && ret as usize == msg_info.len {
+                        c.tx_count += 1;
+                        c.tx_since_rx += 1;
+                        c.rx_since_tx = 0;
+                        device
+                            .connection_manager
+                            .lock()
+                            .send(c.peer, c.local_port, &tx_buffer[..msg_info.len])
+                            .expect(&format!("failed to send message from {}", c.tipc_port_name()));
+                        debug!("sent {} bytes from {}", msg_info.len, c.tipc_port_name());
+                    } else {
+                        error!("ipc_read_msg failed: {ret}");
+                    }
+                }
+            }
+            if href.emask() & IPC_HANDLE_POLL_HUP != 0 {
+                // Print stats if we don't send any more packets for a while
+                timeout = ACTIVE_TIMEOUT;
+                info!("got hup");
+                debug!(
+                    "shut down connection {}, {:?}, {:?}",
+                    c.tipc_port_name(),
+                    c.peer,
+                    c.local_port
+                );
+                device.connection_manager.lock().shutdown(c.peer, c.local_port)?;
+                device.vsock_connection_close(c, /* vsock_done */ false);
+            }
+        }
+        drop(guard);
+        href.handle_decref();
+    }
+}
diff --git a/engine.mk b/engine.mk
index 70090fb9..4cda6a24 100644
--- a/engine.mk
+++ b/engine.mk
@@ -282,6 +282,16 @@ GLOBAL_DEFINES += \
 	LK_LOGLEVEL=$(LOG_LEVEL_KERNEL) \
 	TLOG_LVL_DEFAULT=$$(($(LOG_LEVEL_USER)+2)) \
 
+# add some automatic rust configuration flags
+GLOBAL_SHARED_RUSTFLAGS += \
+	--cfg='PLAT_$(call normalize-rust-cfg,$(PLATFORM))' \
+	--cfg='TARGET_$(call normalize-rust-cfg,$(TARGET))'
+
+# Add configuration flag if this is a test build
+ifeq (true,$(call TOBOOL,$(TEST_BUILD)))
+GLOBAL_SHARED_RUSTFLAGS += --cfg='TEST_BUILD'
+endif
+
 GLOBAL_USER_INCLUDES += $(addsuffix /arch/$(ARCH)/include,$(LKINC))
 
 # test build?
@@ -409,7 +419,9 @@ $(TOOLCHAIN_CONFIG): configheader
 
 GENERATED += $(TOOLCHAIN_CONFIG)
 
-GLOBAL_HOST_RUSTFLAGS += -C linker="$(CLANG_BINDIR)/clang++" -C link-args="-B $(CLANG_BINDIR) -fuse-ld=lld"
+GLOBAL_HOST_RUST_LINK_ARGS := -B $(CLANG_BINDIR) -B $(CLANG_HOST_SEARCHDIR) \
+	$(addprefix -L ,$(CLANG_HOST_LDDIRS)) --sysroot $(CLANG_HOST_SYSROOT) -fuse-ld=lld
+GLOBAL_HOST_RUSTFLAGS += -C linker="$(CLANG_BINDIR)/clang++" -C link-args="$(GLOBAL_HOST_RUST_LINK_ARGS)"
 GLOBAL_SHARED_RUSTFLAGS += -C linker="$(LD)"
 
 # TODO: we could find the runtime like this.
diff --git a/include/lib/dpc.h b/include/lib/dpc.h
index 78380c6e..31e35749 100644
--- a/include/lib/dpc.h
+++ b/include/lib/dpc.h
@@ -109,7 +109,8 @@ void dpc_work_init(struct dpc* work, dpc_callback cb, uint32_t flags);
 int dpc_enqueue_work(struct dpc_queue* q, struct dpc* work, bool resched);
 
 /**
- * dpc_queue_start(): initialize and start DPC queue
+ * dpc_queue_create(): initialize and start a DPC queue
+ * @pq: Pointer to be filled with a pointer to the new queue structure
  * @name: DPC queue name
  * @thread_priority: a priority of DPC queue handling thread
  * @thread_stack_size: stack size of DPC queue handling thread
@@ -117,7 +118,7 @@ int dpc_enqueue_work(struct dpc_queue* q, struct dpc* work, bool resched);
  *
  * Return: NO_ERROR on success, a negative error code otherwise
  */
-status_t dpc_queue_start(struct dpc_queue* q,
+status_t dpc_queue_create(struct dpc_queue** pq,
                          const char* name,
                          int thread_priority,
                          size_t thread_stack_size);
diff --git a/kernel/vm/vmm.c b/kernel/vm/vmm.c
index f6d99353..1790daf8 100644
--- a/kernel/vm/vmm.c
+++ b/kernel/vm/vmm.c
@@ -1555,6 +1555,10 @@ status_t vmm_create_aspace_with_quota(vmm_aspace_t** _aspace,
         struct res_group* new_res_group = res_group_create(num_pages,
                                               &aspace->quota_res_group_ref);
         if (!new_res_group) {
+            if (!(aspace->flags & VMM_ASPACE_FLAG_KERNEL)) {
+                arch_mmu_destroy_aspace(&aspace->arch_aspace);
+            }
+            free(aspace);
             return ERR_NO_MEMORY;
         }
         aspace->quota_res_group = new_res_group;
diff --git a/lib/dpc/dpc.c b/lib/dpc/dpc.c
index a02c1f95..b23eff43 100644
--- a/lib/dpc/dpc.c
+++ b/lib/dpc/dpc.c
@@ -100,7 +100,7 @@ static int dpc_thread_routine(void* arg) {
     return 0;
 }
 
-status_t dpc_queue_start(struct dpc_queue* q,
+static status_t dpc_queue_start(struct dpc_queue* q,
                          const char* name,
                          int thread_priority,
                          size_t thread_stack_size) {
@@ -135,3 +135,24 @@ static void dpc_init(uint level) {
 }
 
 LK_INIT_HOOK(libdpc, &dpc_init, LK_INIT_LEVEL_THREADING);
+
+status_t dpc_queue_create(struct dpc_queue** pq,
+                         const char* name,
+                         int thread_priority,
+                         size_t thread_stack_size) {
+    status_t rc;
+
+    DEBUG_ASSERT(pq);
+
+    *pq = calloc(sizeof(struct dpc_queue), 1);
+    if (!*pq)
+        return ERR_NO_MEMORY;
+
+    rc = dpc_queue_start(*pq, name, thread_priority, thread_stack_size);
+    if (rc) {
+        free(*pq);
+        *pq = NULL;
+    }
+
+    return rc;
+}
diff --git a/lib/libc/rand/rules.mk b/lib/libc/rand/rules.mk
index bad5b9b3..cf051d80 100644
--- a/lib/libc/rand/rules.mk
+++ b/lib/libc/rand/rules.mk
@@ -7,7 +7,8 @@ LOCAL_DIR := $(GET_LOCAL_DIR)
 MODULE := $(LOCAL_DIR)
 
 # Generate a random 32-bit seed for the RNG
-KERNEL_LIBC_RANDSEED_HEX := $(shell xxd -l4 -g0 -p /dev/urandom)
+XXD := $(PATH_TOOLS_BINDIR)/xxd
+KERNEL_LIBC_RANDSEED_HEX := $(shell $(XXD) -l4 -g0 -p /dev/urandom)
 KERNEL_LIBC_RANDSEED := 0x$(KERNEL_LIBC_RANDSEED_HEX)U
 
 MODULE_DEFINES += \
diff --git a/lib/rust_support/bindings.h b/lib/rust_support/bindings.h
index bf049d55..98b51bcd 100644
--- a/lib/rust_support/bindings.h
+++ b/lib/rust_support/bindings.h
@@ -2,6 +2,8 @@
 #include <kernel/mutex.h>
 #include <kernel/thread.h>
 #include <kernel/vm.h>
+#include <lib/trusty/handle.h>
+#include <lib/trusty/handle_set.h>
 #include <lib/trusty/ipc.h>
 #include <lib/trusty/uuid.h>
 #include <lk/init.h>
diff --git a/lib/rust_support/handle.rs b/lib/rust_support/handle.rs
new file mode 100644
index 00000000..6e10b997
--- /dev/null
+++ b/lib/rust_support/handle.rs
@@ -0,0 +1,156 @@
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
+use alloc::boxed::Box;
+
+use core::ffi::c_void;
+use core::ptr::null_mut;
+
+pub use crate::sys::handle_close;
+pub use crate::sys::handle_decref;
+pub use crate::sys::handle_wait;
+
+pub use crate::sys::IPC_HANDLE_POLL_ERROR;
+pub use crate::sys::IPC_HANDLE_POLL_HUP;
+pub use crate::sys::IPC_HANDLE_POLL_MSG;
+pub use crate::sys::IPC_HANDLE_POLL_NONE;
+pub use crate::sys::IPC_HANDLE_POLL_READY;
+pub use crate::sys::IPC_HANDLE_POLL_SEND_UNBLOCKED;
+
+pub use crate::sys::handle;
+pub use crate::sys::handle_ref;
+
+use crate::sys::list_node;
+
+use crate::handle_set::handle_set_detach_ref;
+
+impl Default for list_node {
+    fn default() -> Self {
+        Self { prev: core::ptr::null_mut(), next: core::ptr::null_mut() }
+    }
+}
+
+// nodes in a linked list refer to adjacent nodes by address and should be pinned
+// TODO: add Unpin as a negative trait bound once the rustc feature is stabilized.
+// impl !Unpin for list_node {}
+
+impl Default for handle_ref {
+    fn default() -> Self {
+        Self {
+            set_node: Default::default(),
+            ready_node: Default::default(),
+            uctx_node: Default::default(),
+            waiter: Default::default(),
+            parent: core::ptr::null_mut(),
+            handle: core::ptr::null_mut(),
+            id: 0,
+            emask: 0,
+            cookie: core::ptr::null_mut(),
+        }
+    }
+}
+
+// `handle_ref`s should not move since they are inserted as nodes in linked lists
+// and the kernel may write back to the non-node fields as well.
+// TODO: add Unpin as a negative trait bound once the rustc feature is stabilized.
+// impl !Unpin for handle_ref {}
+
+#[derive(Default)]
+pub struct HandleRef {
+    // Box the `handle_ref` so it doesn't get moved with the `HandleRef`
+    inner: Box<handle_ref>,
+    pub(crate) attached: bool,
+}
+
+impl HandleRef {
+    pub fn detach(&mut self) {
+        if self.attached {
+            // Safety: `inner` was initialized and attached to a handle set
+            unsafe { handle_set_detach_ref(&mut *self.inner) }
+            self.attached = false;
+        }
+    }
+
+    pub fn handle_close(&mut self) {
+        if !self.inner.handle.is_null() {
+            // Safety: `handle` is non-null so it wasn't closed
+            unsafe { handle_close(self.inner.handle) };
+            self.inner.handle = null_mut();
+        }
+    }
+
+    pub fn handle_decref(&mut self) {
+        if self.inner.handle.is_null() {
+            panic!("handle is null; can't decrease its reference count");
+        }
+
+        // Safety: `handle` is non-null so it wasn't closed
+        unsafe { handle_decref(self.inner.handle) };
+    }
+
+    pub fn as_mut_ptr(&mut self) -> *mut handle_ref {
+        &mut *self.inner
+    }
+
+    pub fn cookie(&self) -> *mut c_void {
+        self.inner.cookie
+    }
+
+    pub fn set_cookie(&mut self, cookie: *mut c_void) {
+        self.inner.cookie = cookie;
+    }
+
+    pub fn emask(&self) -> u32 {
+        self.inner.emask
+    }
+
+    pub fn set_emask(&mut self, emask: u32) {
+        self.inner.emask = emask;
+    }
+
+    pub fn handle(&mut self) -> *mut handle {
+        self.inner.handle
+    }
+
+    pub fn id(&mut self) -> u32 {
+        self.inner.id
+    }
+
+    pub fn set_id(&mut self, id: u32) {
+        self.inner.id = id;
+    }
+}
+
+impl Drop for HandleRef {
+    fn drop(&mut self) {
+        self.detach()
+    }
+}
+
+// Safety: the kernel synchronizes operations on handle refs so they can be passed
+// from one thread to another
+unsafe impl Send for HandleRef {}
+
+// Safety: the kernel synchronizes operations on handle refs so it safe to share
+// references between threads
+unsafe impl Sync for HandleRef {}
diff --git a/lib/rust_support/handle_set.rs b/lib/rust_support/handle_set.rs
new file mode 100644
index 00000000..3166616a
--- /dev/null
+++ b/lib/rust_support/handle_set.rs
@@ -0,0 +1,106 @@
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
+use core::time::Duration;
+
+use crate::Error;
+use crate::INFINITE_TIME;
+
+pub use crate::sys::handle_set_attach;
+pub use crate::sys::handle_set_create;
+pub use crate::sys::handle_set_detach_ref;
+pub use crate::sys::handle_set_wait;
+
+use crate::sys::handle;
+use crate::sys::handle_close;
+use crate::sys::handle_wait;
+
+use crate::handle::HandleRef;
+
+pub struct HandleSet(*mut handle);
+
+fn duration_as_ms(dur: Duration) -> Result<u32, Error> {
+    match dur {
+        Duration::MAX => Ok(INFINITE_TIME),
+        dur => dur.as_millis().try_into().map_err(|_| Error::ERR_OUT_OF_RANGE),
+    }
+}
+
+impl HandleSet {
+    pub fn new() -> Self {
+        // Safety: `handle_set_create` places no preconditions on callers.
+        let handle = unsafe { handle_set_create() };
+        if handle.is_null() {
+            panic!("handle_set_create failed.");
+        }
+        Self(handle)
+    }
+
+    pub fn attach(&self, href: &mut HandleRef) -> Result<(), Error> {
+        if href.attached {
+            panic!("HandleRef is already attached.");
+        }
+        // Safety:
+        // `self` contains a properly initialized handle
+        // `href.inner` is a properly initialized handle_ref that is not attached
+        let ret = unsafe { handle_set_attach(self.0, href.as_mut_ptr()) };
+        Error::from_lk(ret)?;
+
+        href.attached = true;
+        Ok(())
+    }
+
+    pub fn handle_set_wait(&self, href: &mut HandleRef, timeout: Duration) -> Result<(), Error> {
+        let timeout = duration_as_ms(timeout)?;
+        // Safety:
+        // `self` contains a properly initialized handle
+        // `href` references a valid storage location for a handle_ref
+        let ret = unsafe { handle_set_wait(self.0, href.as_mut_ptr(), timeout) };
+        Error::from_lk(ret)
+    }
+
+    pub fn handle_wait(&self, event_mask: &mut u32, timeout: Duration) -> Result<(), Error> {
+        let timeout = duration_as_ms(timeout)?;
+        // Safety:
+        // `self` contains a properly initialized handle
+        // `event_mask` references a valid storage location for a u32
+        let ret = unsafe { handle_wait(self.0, event_mask, timeout) };
+        Error::from_lk(ret)
+    }
+}
+
+impl Drop for HandleSet {
+    fn drop(&mut self) {
+        // Safety:
+        // `handle_set_create` returned a valid handle that wasn't closed already.
+        unsafe { handle_close(self.0) }
+    }
+}
+
+// Safety: the kernel synchronizes operations on handle sets so they can be passed
+// from one thread to another
+unsafe impl Send for HandleSet {}
+
+// Safety: the kernel synchronizes operations on handle sets so it is safe to share
+// handle sets between threads
+unsafe impl Sync for HandleSet {}
diff --git a/lib/rust_support/init.rs b/lib/rust_support/init.rs
index 6bcae416..809ea401 100644
--- a/lib/rust_support/init.rs
+++ b/lib/rust_support/init.rs
@@ -50,7 +50,7 @@ impl lk_init_struct {
     pub const fn new(
         level: lk_init_level,
         flags: lk_init_flags,
-        hook: extern "C" fn(uint),
+        hook: unsafe extern "C" fn(uint),
         name: *const c_char,
     ) -> Self {
         lk_init_struct { level: level.0, flags: flags.0, hook: Option::Some(hook), name: name }
diff --git a/lib/rust_support/ipc.rs b/lib/rust_support/ipc.rs
index 4eddf562..d18f1ae8 100644
--- a/lib/rust_support/ipc.rs
+++ b/lib/rust_support/ipc.rs
@@ -1,4 +1,28 @@
-// TODO: present a more Rust-y interface
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
+use core::ptr::null_mut;
+
 pub use crate::sys::ipc_get_msg;
 pub use crate::sys::ipc_port_connect_async;
 pub use crate::sys::ipc_put_msg;
@@ -11,3 +35,28 @@ pub use crate::sys::ipc_msg_kern;
 
 pub use crate::sys::zero_uuid;
 pub use crate::sys::IPC_CONNECT_WAIT_FOR_PORT;
+pub use crate::sys::IPC_PORT_PATH_MAX;
+
+impl Default for ipc_msg_info {
+    fn default() -> Self {
+        Self { id: 0, len: 0, num_handles: 0 }
+    }
+}
+
+impl Default for ipc_msg_kern {
+    fn default() -> Self {
+        Self { iov: null_mut(), num_iov: 0, handles: null_mut(), num_handles: 0 }
+    }
+}
+
+impl ipc_msg_kern {
+    pub fn new(iov: &mut iovec_kern) -> Self {
+        Self { iov, num_iov: 1, ..ipc_msg_kern::default() }
+    }
+}
+
+impl From<&mut [u8]> for iovec_kern {
+    fn from(value: &mut [u8]) -> Self {
+        Self { iov_base: value.as_mut_ptr() as _, iov_len: value.len() }
+    }
+}
diff --git a/lib/rust_support/lib.rs b/lib/rust_support/lib.rs
index 72fe1008..ffa70b5d 100644
--- a/lib/rust_support/lib.rs
+++ b/lib/rust_support/lib.rs
@@ -42,6 +42,8 @@ mod sys {
 }
 
 pub mod err;
+pub mod handle;
+pub mod handle_set;
 pub mod init;
 pub mod ipc;
 pub mod log;
@@ -55,6 +57,12 @@ pub use sys::status_t;
 pub use sys::vaddr_t;
 pub use sys::Error;
 
+// NOTE: `INFINITE_TIME` is defined in `lk/types.h` as `UINT32_MAX`,
+// which in turn is defined as `UINT_MAX`, which is not recognized
+// by bindgen according to the bug below so we use `u32::MAX`.
+// See <https://github.com/rust-lang/rust-bindgen/issues/1636>.
+pub const INFINITE_TIME: u32 = u32::MAX;
+
 #[panic_handler]
 fn handle_panic(info: &PanicInfo) -> ! {
     let panic_message = format!("{info}\0");
diff --git a/lib/rust_support/rules.mk b/lib/rust_support/rules.mk
index 0a90fad5..49d97737 100644
--- a/lib/rust_support/rules.mk
+++ b/lib/rust_support/rules.mk
@@ -47,6 +47,13 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	_panic \
 	fflush \
 	fputs \
+	handle_close \
+	handle_decref \
+	handle_set_detach_ref \
+	handle_set_attach \
+	handle_set_create \
+	handle_set_wait \
+	handle_wait \
 	ipc_get_msg \
 	ipc_port_connect_async \
 	ipc_put_msg \
@@ -61,6 +68,7 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 	mutex_release \
 	thread_create \
 	thread_resume \
+	thread_sleep_ns \
 	vaddr_to_paddr \
 	vmm_alloc_physical_etc \
 	vmm_alloc_contiguous \
@@ -68,9 +76,12 @@ MODULE_BINDGEN_ALLOW_FUNCTIONS := \
 
 MODULE_BINDGEN_ALLOW_TYPES := \
 	Error \
+	handle \
+	handle_ref \
 	iovec_kern \
 	ipc_msg_.* \
 	lk_init_.* \
+	lk_time_.* \
 	trusty_ipc_event_type \
 
 MODULE_BINDGEN_ALLOW_VARS := \
@@ -81,6 +92,7 @@ MODULE_BINDGEN_ALLOW_VARS := \
 	FILE \
 	IPC_CONNECT_WAIT_FOR_PORT \
 	IPC_HANDLE_POLL_.* \
+	IPC_PORT_PATH_MAX \
 	NUM_PRIORITIES \
 	PAGE_SIZE \
 	PAGE_SIZE_SHIFT \
@@ -92,6 +104,7 @@ MODULE_BINDGEN_FLAGS := \
 	--bitfield-enum lk_init_flags \
 	--no-prepend-enum-name \
 	--with-derive-custom Error=FromPrimitive \
+	--with-derive-custom handle_waiter=Default \
 
 MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h
 
diff --git a/lib/rust_support/sync.rs b/lib/rust_support/sync.rs
index 96f89204..06fc2796 100644
--- a/lib/rust_support/sync.rs
+++ b/lib/rust_support/sync.rs
@@ -29,6 +29,7 @@ use core::ops::DerefMut;
 use alloc::boxed::Box;
 
 use crate::Error;
+use crate::INFINITE_TIME;
 
 use crate::sys::mutex_acquire_timeout;
 use crate::sys::mutex_destroy;
@@ -37,12 +38,6 @@ use crate::sys::mutex_release;
 use crate::sys::mutex_t;
 use crate::sys::status_t;
 
-// TODO: `INFINITE_TIME` is defined in `lk/types.h` as `UINT32_MAX`,
-// which in turn is defined as `UINT_MAX`, which is not recognized
-// by bindgen according to the bug below so we use `u32::MAX`.
-// See <https://github.com/rust-lang/rust-bindgen/issues/1636>.
-const INFINITE_TIME: u32 = u32::MAX;
-
 /// Try to acquire the mutex with a timeout value.
 ///
 /// # Safety
diff --git a/lib/rust_support/thread.rs b/lib/rust_support/thread.rs
index 3d53c473..517adf19 100644
--- a/lib/rust_support/thread.rs
+++ b/lib/rust_support/thread.rs
@@ -31,11 +31,14 @@ use core::fmt::Formatter;
 use core::ops::Add;
 use core::ops::Sub;
 use core::ptr::NonNull;
+use core::time::Duration;
 
 use crate::Error;
 
+use crate::sys::lk_time_ns_t;
 use crate::sys::thread_create;
 use crate::sys::thread_resume;
+use crate::sys::thread_sleep_ns;
 use crate::sys::thread_t;
 use crate::sys::DEFAULT_PRIORITY;
 use crate::sys::DPC_PRIORITY;
@@ -48,6 +51,12 @@ use crate::sys::NUM_PRIORITIES;
 
 use crate::sys::DEFAULT_STACK_SIZE;
 
+pub fn sleep(dur: Duration) {
+    let dur_ns: lk_time_ns_t = dur.as_nanos().try_into().expect("could not convert duration to ns");
+    // Safety: trivially safe
+    unsafe { thread_sleep_ns(dur_ns) };
+}
+
 #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
 pub struct Priority(c_int);
 
diff --git a/make/macros.mk b/make/macros.mk
index 7f00ef20..83fbdbe6 100644
--- a/make/macros.mk
+++ b/make/macros.mk
@@ -16,7 +16,7 @@ FIND_EXTERNAL = $(if $(wildcard external/trusty/$1),external/trusty/$1,external/
 
 # try to find a Rust crate at external/rust/crates/$CRATE and fall back to
 # trusty/user/base/host/$CRATE and then trusty/user/base/lib/$CRATE-rust
-FIND_CRATE = $(if $(wildcard external/rust/crates/$1/rules.mk),external/rust/crates/$1,$(if $(wildcard trusty/user/base/host/$1/rules.mk),trusty/user/base/host/$1,$(if $(wildcard trusty/user/base/host/$1-rust/rules.mk),trusty/user/base/host/$1-rust,trusty/user/base/lib/$1-rust)))
+FIND_CRATE = $(dir $(firstword $(wildcard external/rust/android-crates-io/crates/$1/rules.mk external/rust/crates/$1/rules.mk trusty/user/base/host/$1/rules.mk trusty/user/base/host/$1-rust/rules.mk)))
 
 # checks if module with a given path exists
 FIND_MODULE = $(wildcard $1/rules.mk)$(wildcard $(addsuffix /$1/rules.mk,$(.INCLUDE_DIRS)))
@@ -30,7 +30,12 @@ define NEWLINE
 
 endef
 
-STRIP_TRAILING_COMMA = $(if $(1),$(subst $(COMMA)END_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA,,$(strip $(1))END_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA))
+# Remove last comma in $1 if it is at the end or before a newline at the end.
+STRIP_TRAILING_COMMA = \
+	$(subst END_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA,,\
+		$(subst $(COMMA)\nEND_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA,\n,\
+			$(subst $(COMMA)END_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA,,\
+				$(strip $(1))END_OF_LIST_MARKER_FOR_STRIP_TRAILING_COMMA)))
 
 # return $1 with the first word removed
 rest-of-words = $(wordlist 2,$(words $1),$1)
@@ -38,6 +43,9 @@ rest-of-words = $(wordlist 2,$(words $1),$1)
 pairmap = $(and $(strip $2),$(strip $3),\
 	$(call $1,$(firstword $2),$(firstword $3)) $(call pairmap,$1,$(call rest-of-words,$2),$(call rest-of-words,$3)))
 
+# Normalize rust cfg, Uppercase everything and swap (`-` and `/` with `_`)
+normalize-rust-cfg = $(subst /,_,$(subst -,_,$(shell echo $1 | tr '[:lower:]' '[:upper:]')))
+
 # test if two files are different, replacing the first
 # with the second if so
 # args: $1 - temporary file to test
diff --git a/make/module.mk b/make/module.mk
index 1ef6b9ed..20157372 100644
--- a/make/module.mk
+++ b/make/module.mk
@@ -307,6 +307,9 @@ MODULE_$(MODULE_RUST_STEM)_CRATE_DEPS := $(DEP_CRATE_STEMS)
 ALL_KERNEL_HOST_CRATE_NAMES := $(ALL_KERNEL_HOST_CRATE_NAMES) $(HOST_DEP_CRATE_NAMES)
 ALL_KERNEL_HOST_CRATE_STEMS := $(ALL_KERNEL_HOST_CRATE_STEMS) $(HOST_DEP_CRATE_STEMS)
 
+# save all --cfg RUSTFLAGS so they can be included in rust-project.json
+MODULE_$(MODULE_RUST_STEM)_CRATE_CFG := $(patsubst --cfg=%,%,$(filter --cfg=%,$(subst --cfg ,--cfg=,$(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS))))
+
 # change BUILDDIR so RSOBJS for kernel are distinct targets from userspace ones
 OLD_BUILDDIR := $(BUILDDIR)
 BUILDDIR := $(TRUSTY_KERNEL_LIBRARY_BUILDDIR)
@@ -373,7 +376,7 @@ ifneq ($(call TOBOOL,$(MODULE_SKIP_DOCS)),true)
 $(MODULE_RUSTDOC_OBJECT): $(MODULE_RSSRC) | $(MODULE_RSOBJS)
 	@$(MKDIR)
 	@$(call ECHO,rustdoc,generating documentation,for $(MODULE_CRATE_NAME))
-	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTDOC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTDOCFLAGS) -L $(TRUSTY_LIBRARY_BUILDDIR) --out-dir $(MODULE_RUSTDOC_OUT_DIR) $<
+	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTDOC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS_PRELINK) $(MODULE_RUSTDOCFLAGS) -L $(TRUSTY_LIBRARY_BUILDDIR) --out-dir $(MODULE_RUSTDOC_OUT_DIR) $<
 	@touch $@
 	@$(call ECHO_DONE_SILENT,rustdoc,generating documentation,for $(MODULE_CRATE_NAME))
 
diff --git a/make/rust-project-json.mk b/make/rust-project-json.mk
index 11c97abc..a1135c25 100644
--- a/make/rust-project-json.mk
+++ b/make/rust-project-json.mk
@@ -13,7 +13,7 @@ RUST_PROJECT_JSON := $(BUILDDIR)/rust-project.json
 define RUST_PROJECT_JSON_CONTENTS :=
 {
 	"crates": [
-		$(call STRIP_TRAILING_COMMA,$(RUST_ANALYZER_CONTENTS))
+$(call STRIP_TRAILING_COMMA,$(RUST_ANALYZER_CONTENTS))
 	]
 }
 endef
diff --git a/make/rust-toplevel.mk b/make/rust-toplevel.mk
index 13e2ebf4..f231bad1 100644
--- a/make/rust-toplevel.mk
+++ b/make/rust-toplevel.mk
@@ -70,15 +70,22 @@ $(foreach crate,$(ALLMODULE_CRATE_STEMS_SORTED),\
 )
 
 define CRATE_CONFIG =
-{
-	"display_name": "$(crate)",
-	"root_module": "$(filter %.rs,$(MODULE_$(crate)_RUST_SRC))",
-	"edition": "$(MODULE_$(crate)_RUST_EDITION)",
-	"deps": [
+\t\t{\n
+	\t\t\t"display_name": "$(crate)",\n
+	\t\t\t"root_module": "$(abspath $(filter %.rs,$(MODULE_$(crate)_RUST_SRC)))",\n
+	\t\t\t"edition": "$(MODULE_$(crate)_RUST_EDITION)",\n
+	\t\t\t"deps": [\n
 		$(call STRIP_TRAILING_COMMA,$(foreach dep,$(sort $(MODULE_$(crate)_CRATE_DEPS)),\
-				{"name": "$(dep)"$(COMMA) "crate": $(RUST_TOPLEVEL_$(dep)_CRATE_INDEX)}$(COMMA)))
-	]
-},
+			\t\t\t\t{\n
+			\t\t\t\t\t"name": "$(dep)"$(COMMA)\n
+			\t\t\t\t\t"crate": $(RUST_TOPLEVEL_$(dep)_CRATE_INDEX)\n
+			\t\t\t\t}$(COMMA)\n))
+	\t\t\t],\n
+	\t\t\t"cfg": [\n
+		$(call STRIP_TRAILING_COMMA,$(foreach f, $(MODULE_$(crate)_CRATE_CFG),\
+			\t\t\t\t"$(subst ",\\\\\\\",$(f))"$(COMMA)\n))
+	\t\t\t]\n
+\t\t},\n
 
 endef
 
diff --git a/make/rust.mk b/make/rust.mk
index 016c80ac..85c700cb 100644
--- a/make/rust.mk
+++ b/make/rust.mk
@@ -169,5 +169,6 @@ $(MODULE_RSOBJS): MODULE_RUST_STEM := $(MODULE_RUST_STEM)
 
 $(MODULE_RUSTDOC_OBJECT): RUSTDOC := $(RUST_BINDIR)/rustdoc
 $(MODULE_RUSTDOC_OBJECT): MODULE_RUSTDOC_OUT_DIR := $(TRUSTY_SDK_LIB_DIR)/doc
-$(MODULE_RUSTDOC_OBJECT): MODULE_RUSTDOCFLAGS := $(MODULE_RUSTFLAGS_PRELINK) $(MODULE_RUSTDOCFLAGS)
+$(MODULE_RUSTDOC_OBJECT): MODULE_RUSTDOCFLAGS := $(MODULE_RUSTDOCFLAGS)
+$(MODULE_RUSTDOC_OBJECT): MODULE_RUSTFLAGS_PRELINK := $(MODULE_RUSTFLAGS_PRELINK)
 $(MODULE_RUSTDOC_OBJECT): MODULE_CRATE_NAME := $(MODULE_CRATE_NAME)
diff --git a/platform/power.c b/platform/power.c
index 1acc7903..f67e52f1 100644
--- a/platform/power.c
+++ b/platform/power.c
@@ -28,6 +28,7 @@
 #include <kernel/thread.h>
 #include <stdio.h>
 #include <lib/console.h>
+#include <version.h>
 
 /*
  * default implementations of these routines, if the platform code
@@ -46,6 +47,7 @@ __WEAK void platform_halt(platform_halt_action suggested_action,
 
 #endif  // ENABLE_PANIC_SHELL
 
+    dprintf(ALWAYS, "%s\n", lk_version);
     dprintf(ALWAYS, "HALT: spinning forever... (reason = %d)\n", reason);
     arch_disable_ints();
     for (;;);
```

