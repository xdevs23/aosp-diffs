```diff
diff --git a/original/uapi/asm-arm/asm/unistd-eabi.h b/original/uapi/asm-arm/asm/unistd-eabi.h
index 956d4d8..6175e34 100644
--- a/original/uapi/asm-arm/asm/unistd-eabi.h
+++ b/original/uapi/asm-arm/asm/unistd-eabi.h
@@ -416,5 +416,9 @@
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
 #define __NR_mseal (__NR_SYSCALL_BASE + 462)
+#define __NR_setxattrat (__NR_SYSCALL_BASE + 463)
+#define __NR_getxattrat (__NR_SYSCALL_BASE + 464)
+#define __NR_listxattrat (__NR_SYSCALL_BASE + 465)
+#define __NR_removexattrat (__NR_SYSCALL_BASE + 466)
 
 #endif /* _UAPI_ASM_UNISTD_EABI_H */
diff --git a/original/uapi/asm-arm/asm/unistd-oabi.h b/original/uapi/asm-arm/asm/unistd-oabi.h
index 122232d..41e269e 100644
--- a/original/uapi/asm-arm/asm/unistd-oabi.h
+++ b/original/uapi/asm-arm/asm/unistd-oabi.h
@@ -428,5 +428,9 @@
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
 #define __NR_mseal (__NR_SYSCALL_BASE + 462)
+#define __NR_setxattrat (__NR_SYSCALL_BASE + 463)
+#define __NR_getxattrat (__NR_SYSCALL_BASE + 464)
+#define __NR_listxattrat (__NR_SYSCALL_BASE + 465)
+#define __NR_removexattrat (__NR_SYSCALL_BASE + 466)
 
 #endif /* _UAPI_ASM_UNISTD_OABI_H */
diff --git a/original/uapi/asm-arm64/asm/hwcap.h b/original/uapi/asm-arm64/asm/hwcap.h
index 055381b..705a7af 100644
--- a/original/uapi/asm-arm64/asm/hwcap.h
+++ b/original/uapi/asm-arm64/asm/hwcap.h
@@ -21,7 +21,7 @@
  * HWCAP flags - for AT_HWCAP
  *
  * Bits 62 and 63 are reserved for use by libc.
- * Bits 32-61 are unallocated for potential use by libc.
+ * Bits 33-61 are unallocated for potential use by libc.
  */
 #define HWCAP_FP		(1 << 0)
 #define HWCAP_ASIMD		(1 << 1)
@@ -55,6 +55,22 @@
 #define HWCAP_SB		(1 << 29)
 #define HWCAP_PACA		(1 << 30)
 #define HWCAP_PACG		(1UL << 31)
+#define HWCAP_GCS		(1UL << 32)
+#define HWCAP_CMPBR		(1UL << 33)
+#define HWCAP_FPRCVT		(1UL << 34)
+#define HWCAP_F8MM8		(1UL << 35)
+#define HWCAP_F8MM4		(1UL << 36)
+#define HWCAP_SVE_F16MM		(1UL << 37)
+#define HWCAP_SVE_ELTPERM	(1UL << 38)
+#define HWCAP_SVE_AES2		(1UL << 39)
+#define HWCAP_SVE_BFSCALE	(1UL << 40)
+#define HWCAP_SVE2P2		(1UL << 41)
+#define HWCAP_SME2P2		(1UL << 42)
+#define HWCAP_SME_SBITPERM	(1UL << 43)
+#define HWCAP_SME_AES		(1UL << 44)
+#define HWCAP_SME_SFEXPA	(1UL << 45)
+#define HWCAP_SME_STMOP		(1UL << 46)
+#define HWCAP_SME_SMOP4		(1UL << 47)
 
 /*
  * HWCAP2 flags - for AT_HWCAP2
@@ -124,4 +140,8 @@
 #define HWCAP2_SME_SF8DP2	(1UL << 62)
 #define HWCAP2_POE		(1UL << 63)
 
+/*
+ * HWCAP3 flags - for AT_HWCAP3
+ */
+
 #endif /* _UAPI__ASM_HWCAP_H */
diff --git a/original/uapi/asm-arm64/asm/kvm.h b/original/uapi/asm-arm64/asm/kvm.h
index 964df31..568bf85 100644
--- a/original/uapi/asm-arm64/asm/kvm.h
+++ b/original/uapi/asm-arm64/asm/kvm.h
@@ -43,9 +43,6 @@
 #define KVM_COALESCED_MMIO_PAGE_OFFSET 1
 #define KVM_DIRTY_LOG_PAGE_OFFSET 64
 
-#define KVM_REG_SIZE(id)						\
-	(1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
-
 struct kvm_regs {
 	struct user_pt_regs regs;	/* sp = sp_el0 */
 
@@ -484,6 +481,12 @@ enum {
  */
 #define KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2	(1ULL << 0)
 
+/*
+ * Shutdown caused by a PSCI v1.3 SYSTEM_OFF2 call.
+ * Valid only when the system event has a type of KVM_SYSTEM_EVENT_SHUTDOWN.
+ */
+#define KVM_SYSTEM_EVENT_SHUTDOWN_FLAG_PSCI_OFF2	(1ULL << 0)
+
 /* run->fail_entry.hardware_entry_failure_reason codes. */
 #define KVM_EXIT_FAIL_ENTRY_CPU_UNSUPPORTED	(1ULL << 0)
 
diff --git a/original/uapi/asm-arm64/asm/ptrace.h b/original/uapi/asm-arm64/asm/ptrace.h
index 7fa2f70..0f39ba4 100644
--- a/original/uapi/asm-arm64/asm/ptrace.h
+++ b/original/uapi/asm-arm64/asm/ptrace.h
@@ -324,6 +324,14 @@ struct user_za_header {
 #define ZA_PT_SIZE(vq)						\
 	(ZA_PT_ZA_OFFSET + ZA_PT_ZA_SIZE(vq))
 
+/* GCS state (NT_ARM_GCS) */
+
+struct user_gcs {
+	__u64 features_enabled;
+	__u64 features_locked;
+	__u64 gcspr_el0;
+};
+
 #endif /* __ASSEMBLY__ */
 
 #endif /* _UAPI__ASM_PTRACE_H */
diff --git a/original/uapi/asm-arm64/asm/sigcontext.h b/original/uapi/asm-arm64/asm/sigcontext.h
index bb7af77..d42f7a9 100644
--- a/original/uapi/asm-arm64/asm/sigcontext.h
+++ b/original/uapi/asm-arm64/asm/sigcontext.h
@@ -183,6 +183,15 @@ struct zt_context {
 	__u16 __reserved[3];
 };
 
+#define GCS_MAGIC	0x47435300
+
+struct gcs_context {
+	struct _aarch64_ctx head;
+	__u64 gcspr;
+	__u64 features_enabled;
+	__u64 reserved;
+};
+
 #endif /* !__ASSEMBLY__ */
 
 #include <asm/sve_context.h>
diff --git a/original/uapi/asm-arm64/asm/unistd_64.h b/original/uapi/asm-arm64/asm/unistd_64.h
index efc29fc..c390136 100644
--- a/original/uapi/asm-arm64/asm/unistd_64.h
+++ b/original/uapi/asm-arm64/asm/unistd_64.h
@@ -319,9 +319,13 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 
 #ifdef __KERNEL__
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-generic/fcntl.h b/original/uapi/asm-generic/fcntl.h
index 80f37a0..6134752 100644
--- a/original/uapi/asm-generic/fcntl.h
+++ b/original/uapi/asm-generic/fcntl.h
@@ -6,7 +6,6 @@
 
 /*
  * FMODE_EXEC is 0x20
- * FMODE_NONOTIFY is 0x4000000
  * These cannot be used by userspace O_* until internal and external open
  * flags are split.
  * -Eric Paris
diff --git a/original/uapi/asm-generic/ioctl.h b/original/uapi/asm-generic/ioctl.h
index a84f4db..e3290a5 100644
--- a/original/uapi/asm-generic/ioctl.h
+++ b/original/uapi/asm-generic/ioctl.h
@@ -82,13 +82,13 @@
  * NOTE: _IOW means userland is writing and kernel is reading. _IOR
  * means userland is reading and kernel is writing.
  */
-#define _IO(type,nr)		_IOC(_IOC_NONE,(type),(nr),0)
-#define _IOR(type,nr,size)	_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
-#define _IOW(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
-#define _IOWR(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
-#define _IOR_BAD(type,nr,size)	_IOC(_IOC_READ,(type),(nr),sizeof(size))
-#define _IOW_BAD(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),sizeof(size))
-#define _IOWR_BAD(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))
+#define _IO(type,nr)			_IOC(_IOC_NONE,(type),(nr),0)
+#define _IOR(type,nr,argtype)		_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(argtype)))
+#define _IOW(type,nr,argtype)		_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(argtype)))
+#define _IOWR(type,nr,argtype)		_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(argtype)))
+#define _IOR_BAD(type,nr,argtype)	_IOC(_IOC_READ,(type),(nr),sizeof(argtype))
+#define _IOW_BAD(type,nr,argtype)	_IOC(_IOC_WRITE,(type),(nr),sizeof(argtype))
+#define _IOWR_BAD(type,nr,argtype)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(argtype))
 
 /* used to decode ioctl numbers.. */
 #define _IOC_DIR(nr)		(((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
diff --git a/original/uapi/asm-generic/mman-common.h b/original/uapi/asm-generic/mman-common.h
index 6ce1f1c..1ea2c4c 100644
--- a/original/uapi/asm-generic/mman-common.h
+++ b/original/uapi/asm-generic/mman-common.h
@@ -79,6 +79,9 @@
 
 #define MADV_COLLAPSE	25		/* Synchronous hugepage collapse */
 
+#define MADV_GUARD_INSTALL 102		/* fatal signal on access to range */
+#define MADV_GUARD_REMOVE 103		/* unguard range */
+
 /* compatibility flags */
 #define MAP_FILE	0
 
diff --git a/original/uapi/asm-generic/mman.h b/original/uapi/asm-generic/mman.h
index 57e8195..5e3d61d 100644
--- a/original/uapi/asm-generic/mman.h
+++ b/original/uapi/asm-generic/mman.h
@@ -19,4 +19,8 @@
 #define MCL_FUTURE	2		/* lock all future mappings */
 #define MCL_ONFAULT	4		/* lock all pages that are faulted in */
 
+#define SHADOW_STACK_SET_TOKEN (1ULL << 0)     /* Set up a restore token in the shadow stack */
+#define SHADOW_STACK_SET_MARKER (1ULL << 1)     /* Set up a top of stack marker in the shadow stack */
+
+
 #endif /* __ASM_GENERIC_MMAN_H */
diff --git a/original/uapi/asm-generic/siginfo.h b/original/uapi/asm-generic/siginfo.h
index b7bc545..5a1ca43 100644
--- a/original/uapi/asm-generic/siginfo.h
+++ b/original/uapi/asm-generic/siginfo.h
@@ -46,7 +46,7 @@ union __sifields {
 		__kernel_timer_t _tid;	/* timer id */
 		int _overrun;		/* overrun count */
 		sigval_t _sigval;	/* same as below */
-		int _sys_private;       /* not to be passed to user */
+		int _sys_private;       /* Not used by the kernel. Historic leftover. Always 0. */
 	} _timer;
 
 	/* POSIX.1b signals */
diff --git a/original/uapi/asm-generic/socket.h b/original/uapi/asm-generic/socket.h
index 3b4e3e8..aa5016f 100644
--- a/original/uapi/asm-generic/socket.h
+++ b/original/uapi/asm-generic/socket.h
@@ -141,6 +141,10 @@
 #define SCM_DEVMEM_DMABUF	SO_DEVMEM_DMABUF
 #define SO_DEVMEM_DONTNEED	80
 
+#define SCM_TS_OPT_ID		81
+
+#define SO_RCVPRIORITY		82
+
 #if !defined(__KERNEL__)
 
 #if __BITS_PER_LONG == 64 || (defined(__x86_64__) && defined(__ILP32__))
diff --git a/original/uapi/asm-generic/unistd.h b/original/uapi/asm-generic/unistd.h
index 5bf6148..88dc393 100644
--- a/original/uapi/asm-generic/unistd.h
+++ b/original/uapi/asm-generic/unistd.h
@@ -841,8 +841,17 @@ __SYSCALL(__NR_lsm_list_modules, sys_lsm_list_modules)
 #define __NR_mseal 462
 __SYSCALL(__NR_mseal, sys_mseal)
 
+#define __NR_setxattrat 463
+__SYSCALL(__NR_setxattrat, sys_setxattrat)
+#define __NR_getxattrat 464
+__SYSCALL(__NR_getxattrat, sys_getxattrat)
+#define __NR_listxattrat 465
+__SYSCALL(__NR_listxattrat, sys_listxattrat)
+#define __NR_removexattrat 466
+__SYSCALL(__NR_removexattrat, sys_removexattrat)
+
 #undef __NR_syscalls
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 
 /*
  * 32 bit systems traditionally used different
diff --git a/original/uapi/asm-riscv/asm/hwprobe.h b/original/uapi/asm-riscv/asm/hwprobe.h
index 1e153cd..c3c1cc9 100644
--- a/original/uapi/asm-riscv/asm/hwprobe.h
+++ b/original/uapi/asm-riscv/asm/hwprobe.h
@@ -1,6 +1,6 @@
 /* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
 /*
- * Copyright 2023 Rivos, Inc
+ * Copyright 2023-2024 Rivos, Inc
  */
 
 #ifndef _UAPI_ASM_HWPROBE_H
@@ -72,6 +72,7 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZCF		(1ULL << 46)
 #define		RISCV_HWPROBE_EXT_ZCMOP		(1ULL << 47)
 #define		RISCV_HWPROBE_EXT_ZAWRS		(1ULL << 48)
+#define		RISCV_HWPROBE_EXT_SUPM		(1ULL << 49)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
@@ -88,6 +89,12 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_MISALIGNED_SCALAR_SLOW		2
 #define		RISCV_HWPROBE_MISALIGNED_SCALAR_FAST		3
 #define		RISCV_HWPROBE_MISALIGNED_SCALAR_UNSUPPORTED	4
+#define RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF	10
+#define		RISCV_HWPROBE_MISALIGNED_VECTOR_UNKNOWN		0
+#define		RISCV_HWPROBE_MISALIGNED_VECTOR_SLOW		2
+#define		RISCV_HWPROBE_MISALIGNED_VECTOR_FAST		3
+#define		RISCV_HWPROBE_MISALIGNED_VECTOR_UNSUPPORTED	4
+#define RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0	11
 /* Increase RISCV_HWPROBE_MAX_KEY when adding items. */
 
 /* Flags */
diff --git a/original/uapi/asm-riscv/asm/kvm.h b/original/uapi/asm-riscv/asm/kvm.h
index e97db32..f06bc5e 100644
--- a/original/uapi/asm-riscv/asm/kvm.h
+++ b/original/uapi/asm-riscv/asm/kvm.h
@@ -175,6 +175,13 @@ enum KVM_RISCV_ISA_EXT_ID {
 	KVM_RISCV_ISA_EXT_ZCF,
 	KVM_RISCV_ISA_EXT_ZCMOP,
 	KVM_RISCV_ISA_EXT_ZAWRS,
+	KVM_RISCV_ISA_EXT_SMNPM,
+	KVM_RISCV_ISA_EXT_SSNPM,
+	KVM_RISCV_ISA_EXT_SVADE,
+	KVM_RISCV_ISA_EXT_SVADU,
+	KVM_RISCV_ISA_EXT_SVVPTC,
+	KVM_RISCV_ISA_EXT_ZABHA,
+	KVM_RISCV_ISA_EXT_ZICCRSE,
 	KVM_RISCV_ISA_EXT_MAX,
 };
 
@@ -194,6 +201,7 @@ enum KVM_RISCV_SBI_EXT_ID {
 	KVM_RISCV_SBI_EXT_VENDOR,
 	KVM_RISCV_SBI_EXT_DBCN,
 	KVM_RISCV_SBI_EXT_STA,
+	KVM_RISCV_SBI_EXT_SUSP,
 	KVM_RISCV_SBI_EXT_MAX,
 };
 
@@ -207,9 +215,6 @@ struct kvm_riscv_sbi_sta {
 #define KVM_RISCV_TIMER_STATE_OFF	0
 #define KVM_RISCV_TIMER_STATE_ON	1
 
-#define KVM_REG_SIZE(id)		\
-	(1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
-
 /* If you need to interpret the index values, here is the key: */
 #define KVM_REG_RISCV_TYPE_MASK		0x00000000FF000000
 #define KVM_REG_RISCV_TYPE_SHIFT	24
diff --git a/original/uapi/asm-riscv/asm/unistd_32.h b/original/uapi/asm-riscv/asm/unistd_32.h
index 1d67ed1..69153a3 100644
--- a/original/uapi/asm-riscv/asm/unistd_32.h
+++ b/original/uapi/asm-riscv/asm/unistd_32.h
@@ -310,9 +310,13 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 
 #ifdef __KERNEL__
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_32_H */
diff --git a/original/uapi/asm-riscv/asm/unistd_64.h b/original/uapi/asm-riscv/asm/unistd_64.h
index b42cfbb..a2cc6e3 100644
--- a/original/uapi/asm-riscv/asm/unistd_64.h
+++ b/original/uapi/asm-riscv/asm/unistd_64.h
@@ -320,9 +320,13 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 
 #ifdef __KERNEL__
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-riscv/asm/vendor/thead.h b/original/uapi/asm-riscv/asm/vendor/thead.h
new file mode 100644
index 0000000..43790eb
--- /dev/null
+++ b/original/uapi/asm-riscv/asm/vendor/thead.h
@@ -0,0 +1,3 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+
+#define		RISCV_HWPROBE_VENDOR_EXT_XTHEADVECTOR	(1 << 0)
diff --git a/original/uapi/asm-x86/asm/amd_hsmp.h b/original/uapi/asm-x86/asm/amd_hsmp.h
index e5d182c..92d8f25 100644
--- a/original/uapi/asm-x86/asm/amd_hsmp.h
+++ b/original/uapi/asm-x86/asm/amd_hsmp.h
@@ -50,6 +50,12 @@ enum hsmp_message_ids {
 	HSMP_GET_METRIC_TABLE_VER,	/* 23h Get metrics table version */
 	HSMP_GET_METRIC_TABLE,		/* 24h Get metrics table */
 	HSMP_GET_METRIC_TABLE_DRAM_ADDR,/* 25h Get metrics table dram address */
+	HSMP_SET_XGMI_PSTATE_RANGE,	/* 26h Set xGMI P-state range */
+	HSMP_CPU_RAIL_ISO_FREQ_POLICY,	/* 27h Get/Set Cpu Iso frequency policy */
+	HSMP_DFC_ENABLE_CTRL,		/* 28h Enable/Disable DF C-state */
+	HSMP_GET_RAPL_UNITS = 0x30,	/* 30h Get scaling factor for energy */
+	HSMP_GET_RAPL_CORE_COUNTER,	/* 31h Get core energy counter value */
+	HSMP_GET_RAPL_PACKAGE_COUNTER,	/* 32h Get package energy counter value */
 	HSMP_MSG_ID_MAX,
 };
 
@@ -65,6 +71,7 @@ enum hsmp_msg_type {
 	HSMP_RSVD = -1,
 	HSMP_SET  = 0,
 	HSMP_GET  = 1,
+	HSMP_SET_GET	= 2,
 };
 
 enum hsmp_proto_versions {
@@ -72,7 +79,8 @@ enum hsmp_proto_versions {
 	HSMP_PROTO_VER3,
 	HSMP_PROTO_VER4,
 	HSMP_PROTO_VER5,
-	HSMP_PROTO_VER6
+	HSMP_PROTO_VER6,
+	HSMP_PROTO_VER7
 };
 
 struct hsmp_msg_desc {
@@ -88,7 +96,8 @@ struct hsmp_msg_desc {
  *
  * Not supported messages would return -ENOMSG.
  */
-static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
+static const struct hsmp_msg_desc hsmp_msg_desc_table[]
+				__attribute__((unused)) = {
 	/* RESERVED */
 	{0, 0, HSMP_RSVD},
 
@@ -299,7 +308,7 @@ static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
 	 * HSMP_SET_POWER_MODE, num_args = 1, response_sz = 0
 	 * input: args[0] = power efficiency mode[2:0]
 	 */
-	{1, 0, HSMP_SET},
+	{1, 1, HSMP_SET_GET},
 
 	/*
 	 * HSMP_SET_PSTATE_MAX_MIN, num_args = 1, response_sz = 0
@@ -324,6 +333,58 @@ static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
 	 * output: args[1] = upper 32 bits of the address
 	 */
 	{0, 2, HSMP_GET},
+
+	/*
+	 * HSMP_SET_XGMI_PSTATE_RANGE, num_args = 1, response_sz = 0
+	 * input: args[0] = min xGMI p-state[15:8] + max xGMI p-state[7:0]
+	 */
+	{1, 0, HSMP_SET},
+
+	/*
+	 * HSMP_CPU_RAIL_ISO_FREQ_POLICY, num_args = 1, response_sz = 1
+	 * input: args[0] = set/get policy[31] +
+	 * disable/enable independent control[0]
+	 * output: args[0] = current policy[0]
+	 */
+	{1, 1, HSMP_SET_GET},
+
+	/*
+	 * HSMP_DFC_ENABLE_CTRL, num_args = 1, response_sz = 1
+	 * input: args[0] = set/get policy[31] + enable/disable DFC[0]
+	 * output: args[0] = current policy[0]
+	 */
+	{1, 1, HSMP_SET_GET},
+
+	/* RESERVED(0x29-0x2f) */
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+	{0, 0, HSMP_RSVD},
+
+	/*
+	 * HSMP_GET_RAPL_UNITS, response_sz = 1
+	 * output: args[0] = tu value[19:16] + esu value[12:8]
+	 */
+	{0, 1, HSMP_GET},
+
+	/*
+	 * HSMP_GET_RAPL_CORE_COUNTER, num_args = 1, response_sz = 1
+	 * input: args[0] = apic id[15:0]
+	 * output: args[0] = lower 32 bits of energy
+	 * output: args[1] = upper 32 bits of energy
+	 */
+	{1, 2, HSMP_GET},
+
+	/*
+	 * HSMP_GET_RAPL_PACKAGE_COUNTER, num_args = 0, response_sz = 1
+	 * output: args[0] = lower 32 bits of energy
+	 * output: args[1] = upper 32 bits of energy
+	 */
+	{0, 2, HSMP_GET},
+
 };
 
 /* Metrics table (supported only with proto version 6) */
diff --git a/original/uapi/asm-x86/asm/kvm.h b/original/uapi/asm-x86/asm/kvm.h
index a8debbf..9e75da9 100644
--- a/original/uapi/asm-x86/asm/kvm.h
+++ b/original/uapi/asm-x86/asm/kvm.h
@@ -440,6 +440,7 @@ struct kvm_sync_regs {
 #define KVM_X86_QUIRK_FIX_HYPERCALL_INSN	(1 << 5)
 #define KVM_X86_QUIRK_MWAIT_NEVER_UD_FAULTS	(1 << 6)
 #define KVM_X86_QUIRK_SLOT_ZAP_ALL		(1 << 7)
+#define KVM_X86_QUIRK_STUFF_FEATURE_MSRS	(1 << 8)
 
 #define KVM_STATE_NESTED_FORMAT_VMX	0
 #define KVM_STATE_NESTED_FORMAT_SVM	1
@@ -924,5 +925,6 @@ struct kvm_hyperv_eventfd {
 #define KVM_X86_SEV_VM		2
 #define KVM_X86_SEV_ES_VM	3
 #define KVM_X86_SNP_VM		4
+#define KVM_X86_TDX_VM		5
 
 #endif /* _ASM_X86_KVM_H */
diff --git a/original/uapi/asm-x86/asm/mce.h b/original/uapi/asm-x86/asm/mce.h
index db9adc0..cb6b48a 100644
--- a/original/uapi/asm-x86/asm/mce.h
+++ b/original/uapi/asm-x86/asm/mce.h
@@ -8,7 +8,8 @@
 /*
  * Fields are zero when not available. Also, this struct is shared with
  * userspace mcelog and thus must keep existing fields at current offsets.
- * Only add new fields to the end of the structure
+ * Only add new, shared fields to the end of the structure.
+ * Do not add vendor-specific fields.
  */
 struct mce {
 	__u64 status;		/* Bank's MCi_STATUS MSR */
diff --git a/original/uapi/asm-x86/asm/mman.h b/original/uapi/asm-x86/asm/mman.h
index 46cdc94..ac1e627 100644
--- a/original/uapi/asm-x86/asm/mman.h
+++ b/original/uapi/asm-x86/asm/mman.h
@@ -5,9 +5,6 @@
 #define MAP_32BIT	0x40		/* only give out 32bit addresses */
 #define MAP_ABOVE4G	0x80		/* only map above 4GB */
 
-/* Flags for map_shadow_stack(2) */
-#define SHADOW_STACK_SET_TOKEN	(1ULL << 0)	/* Set up a restore token in the shadow stack */
-
 #include <asm-generic/mman.h>
 
 #endif /* _ASM_X86_MMAN_H */
diff --git a/original/uapi/asm-x86/asm/unistd_32.h b/original/uapi/asm-x86/asm/unistd_32.h
index 940eaeb..b0e5657 100644
--- a/original/uapi/asm-x86/asm/unistd_32.h
+++ b/original/uapi/asm-x86/asm/unistd_32.h
@@ -453,9 +453,13 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 
 #ifdef __KERNEL__
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_32_H */
diff --git a/original/uapi/asm-x86/asm/unistd_64.h b/original/uapi/asm-x86/asm/unistd_64.h
index 7fc8789..c58a1f4 100644
--- a/original/uapi/asm-x86/asm/unistd_64.h
+++ b/original/uapi/asm-x86/asm/unistd_64.h
@@ -376,9 +376,13 @@
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
 #define __NR_mseal 462
+#define __NR_setxattrat 463
+#define __NR_getxattrat 464
+#define __NR_listxattrat 465
+#define __NR_removexattrat 466
 
 #ifdef __KERNEL__
-#define __NR_syscalls 463
+#define __NR_syscalls 467
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-x86/asm/unistd_x32.h b/original/uapi/asm-x86/asm/unistd_x32.h
index 644bcdb..e04d05a 100644
--- a/original/uapi/asm-x86/asm/unistd_x32.h
+++ b/original/uapi/asm-x86/asm/unistd_x32.h
@@ -329,6 +329,10 @@
 #define __NR_lsm_set_self_attr (__X32_SYSCALL_BIT + 460)
 #define __NR_lsm_list_modules (__X32_SYSCALL_BIT + 461)
 #define __NR_mseal (__X32_SYSCALL_BIT + 462)
+#define __NR_setxattrat (__X32_SYSCALL_BIT + 463)
+#define __NR_getxattrat (__X32_SYSCALL_BIT + 464)
+#define __NR_listxattrat (__X32_SYSCALL_BIT + 465)
+#define __NR_removexattrat (__X32_SYSCALL_BIT + 466)
 #define __NR_rt_sigaction (__X32_SYSCALL_BIT + 512)
 #define __NR_rt_sigreturn (__X32_SYSCALL_BIT + 513)
 #define __NR_ioctl (__X32_SYSCALL_BIT + 514)
diff --git a/original/uapi/drm/amdgpu_drm.h b/original/uapi/drm/amdgpu_drm.h
index efe5de6..aaa4f3b 100644
--- a/original/uapi/drm/amdgpu_drm.h
+++ b/original/uapi/drm/amdgpu_drm.h
@@ -411,13 +411,20 @@ struct drm_amdgpu_gem_userptr {
 /* GFX12 and later: */
 #define AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT			0
 #define AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK			0x7
-/* These are DCC recompression setting for memory management: */
+/* These are DCC recompression settings for memory management: */
 #define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT	3
 #define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK	0x3 /* 0:64B, 1:128B, 2:256B */
 #define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT		5
 #define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK		0x7 /* CB_COLOR0_INFO.NUMBER_TYPE */
 #define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT		8
 #define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK		0x3f /* [0:4]:CB_COLOR0_INFO.FORMAT, [5]:MM */
+/* When clearing the buffer or moving it from VRAM to GTT, don't compress and set DCC metadata
+ * to uncompressed. Set when parts of an allocation bypass DCC and read raw data. */
+#define AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_SHIFT	14
+#define AMDGPU_TILING_GFX12_DCC_WRITE_COMPRESS_DISABLE_MASK	0x1
+/* bit gap */
+#define AMDGPU_TILING_GFX12_SCANOUT_SHIFT			63
+#define AMDGPU_TILING_GFX12_SCANOUT_MASK			0x1
 
 /* Set/Get helpers for tiling flags. */
 #define AMDGPU_TILING_SET(field, value) \
diff --git a/original/uapi/drm/amdxdna_accel.h b/original/uapi/drm/amdxdna_accel.h
new file mode 100644
index 0000000..a706ead
--- /dev/null
+++ b/original/uapi/drm/amdxdna_accel.h
@@ -0,0 +1,501 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
+ */
+
+#ifndef _UAPI_AMDXDNA_ACCEL_H_
+#define _UAPI_AMDXDNA_ACCEL_H_
+
+#include <linux/stddef.h>
+#include "drm.h"
+
+#if defined(__cplusplus)
+extern "C" {
+#endif
+
+#define AMDXDNA_INVALID_CMD_HANDLE	(~0UL)
+#define AMDXDNA_INVALID_ADDR		(~0UL)
+#define AMDXDNA_INVALID_CTX_HANDLE	0
+#define AMDXDNA_INVALID_BO_HANDLE	0
+#define AMDXDNA_INVALID_FENCE_HANDLE	0
+
+enum amdxdna_device_type {
+	AMDXDNA_DEV_TYPE_UNKNOWN = -1,
+	AMDXDNA_DEV_TYPE_KMQ,
+};
+
+enum amdxdna_drm_ioctl_id {
+	DRM_AMDXDNA_CREATE_HWCTX,
+	DRM_AMDXDNA_DESTROY_HWCTX,
+	DRM_AMDXDNA_CONFIG_HWCTX,
+	DRM_AMDXDNA_CREATE_BO,
+	DRM_AMDXDNA_GET_BO_INFO,
+	DRM_AMDXDNA_SYNC_BO,
+	DRM_AMDXDNA_EXEC_CMD,
+	DRM_AMDXDNA_GET_INFO,
+	DRM_AMDXDNA_SET_STATE,
+};
+
+/**
+ * struct qos_info - QoS information for driver.
+ * @gops: Giga operations per second.
+ * @fps: Frames per second.
+ * @dma_bandwidth: DMA bandwidtha.
+ * @latency: Frame response latency.
+ * @frame_exec_time: Frame execution time.
+ * @priority: Request priority.
+ *
+ * User program can provide QoS hints to driver.
+ */
+struct amdxdna_qos_info {
+	__u32 gops;
+	__u32 fps;
+	__u32 dma_bandwidth;
+	__u32 latency;
+	__u32 frame_exec_time;
+	__u32 priority;
+};
+
+/**
+ * struct amdxdna_drm_create_hwctx - Create hardware context.
+ * @ext: MBZ.
+ * @ext_flags: MBZ.
+ * @qos_p: Address of QoS info.
+ * @umq_bo: BO handle for user mode queue(UMQ).
+ * @log_buf_bo: BO handle for log buffer.
+ * @max_opc: Maximum operations per cycle.
+ * @num_tiles: Number of AIE tiles.
+ * @mem_size: Size of AIE tile memory.
+ * @umq_doorbell: Returned offset of doorbell associated with UMQ.
+ * @handle: Returned hardware context handle.
+ * @syncobj_handle: Returned syncobj handle for command completion.
+ */
+struct amdxdna_drm_create_hwctx {
+	__u64 ext;
+	__u64 ext_flags;
+	__u64 qos_p;
+	__u32 umq_bo;
+	__u32 log_buf_bo;
+	__u32 max_opc;
+	__u32 num_tiles;
+	__u32 mem_size;
+	__u32 umq_doorbell;
+	__u32 handle;
+	__u32 syncobj_handle;
+};
+
+/**
+ * struct amdxdna_drm_destroy_hwctx - Destroy hardware context.
+ * @handle: Hardware context handle.
+ * @pad: MBZ.
+ */
+struct amdxdna_drm_destroy_hwctx {
+	__u32 handle;
+	__u32 pad;
+};
+
+/**
+ * struct amdxdna_cu_config - configuration for one CU
+ * @cu_bo: CU configuration buffer bo handle.
+ * @cu_func: Function of a CU.
+ * @pad: MBZ.
+ */
+struct amdxdna_cu_config {
+	__u32 cu_bo;
+	__u8  cu_func;
+	__u8  pad[3];
+};
+
+/**
+ * struct amdxdna_hwctx_param_config_cu - configuration for CUs in hardware context
+ * @num_cus: Number of CUs to configure.
+ * @pad: MBZ.
+ * @cu_configs: Array of CU configurations of struct amdxdna_cu_config.
+ */
+struct amdxdna_hwctx_param_config_cu {
+	__u16 num_cus;
+	__u16 pad[3];
+	struct amdxdna_cu_config cu_configs[] __counted_by(num_cus);
+};
+
+enum amdxdna_drm_config_hwctx_param {
+	DRM_AMDXDNA_HWCTX_CONFIG_CU,
+	DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF,
+	DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF,
+};
+
+/**
+ * struct amdxdna_drm_config_hwctx - Configure hardware context.
+ * @handle: hardware context handle.
+ * @param_type: Value in enum amdxdna_drm_config_hwctx_param. Specifies the
+ *              structure passed in via param_val.
+ * @param_val: A structure specified by the param_type struct member.
+ * @param_val_size: Size of the parameter buffer pointed to by the param_val.
+ *		    If param_val is not a pointer, driver can ignore this.
+ * @pad: MBZ.
+ *
+ * Note: if the param_val is a pointer pointing to a buffer, the maximum size
+ * of the buffer is 4KiB(PAGE_SIZE).
+ */
+struct amdxdna_drm_config_hwctx {
+	__u32 handle;
+	__u32 param_type;
+	__u64 param_val;
+	__u32 param_val_size;
+	__u32 pad;
+};
+
+enum amdxdna_bo_type {
+	AMDXDNA_BO_INVALID = 0,
+	AMDXDNA_BO_SHMEM,
+	AMDXDNA_BO_DEV_HEAP,
+	AMDXDNA_BO_DEV,
+	AMDXDNA_BO_CMD,
+};
+
+/**
+ * struct amdxdna_drm_create_bo - Create a buffer object.
+ * @flags: Buffer flags. MBZ.
+ * @vaddr: User VA of buffer if applied. MBZ.
+ * @size: Size in bytes.
+ * @type: Buffer type.
+ * @handle: Returned DRM buffer object handle.
+ */
+struct amdxdna_drm_create_bo {
+	__u64	flags;
+	__u64	vaddr;
+	__u64	size;
+	__u32	type;
+	__u32	handle;
+};
+
+/**
+ * struct amdxdna_drm_get_bo_info - Get buffer object information.
+ * @ext: MBZ.
+ * @ext_flags: MBZ.
+ * @handle: DRM buffer object handle.
+ * @pad: MBZ.
+ * @map_offset: Returned DRM fake offset for mmap().
+ * @vaddr: Returned user VA of buffer. 0 in case user needs mmap().
+ * @xdna_addr: Returned XDNA device virtual address.
+ */
+struct amdxdna_drm_get_bo_info {
+	__u64 ext;
+	__u64 ext_flags;
+	__u32 handle;
+	__u32 pad;
+	__u64 map_offset;
+	__u64 vaddr;
+	__u64 xdna_addr;
+};
+
+/**
+ * struct amdxdna_drm_sync_bo - Sync buffer object.
+ * @handle: Buffer object handle.
+ * @direction: Direction of sync, can be from device or to device.
+ * @offset: Offset in the buffer to sync.
+ * @size: Size in bytes.
+ */
+struct amdxdna_drm_sync_bo {
+	__u32 handle;
+#define SYNC_DIRECT_TO_DEVICE	0U
+#define SYNC_DIRECT_FROM_DEVICE	1U
+	__u32 direction;
+	__u64 offset;
+	__u64 size;
+};
+
+enum amdxdna_cmd_type {
+	AMDXDNA_CMD_SUBMIT_EXEC_BUF = 0,
+	AMDXDNA_CMD_SUBMIT_DEPENDENCY,
+	AMDXDNA_CMD_SUBMIT_SIGNAL,
+};
+
+/**
+ * struct amdxdna_drm_exec_cmd - Execute command.
+ * @ext: MBZ.
+ * @ext_flags: MBZ.
+ * @hwctx: Hardware context handle.
+ * @type: One of command type in enum amdxdna_cmd_type.
+ * @cmd_handles: Array of command handles or the command handle itself
+ *               in case of just one.
+ * @args: Array of arguments for all command handles.
+ * @cmd_count: Number of command handles in the cmd_handles array.
+ * @arg_count: Number of arguments in the args array.
+ * @seq: Returned sequence number for this command.
+ */
+struct amdxdna_drm_exec_cmd {
+	__u64 ext;
+	__u64 ext_flags;
+	__u32 hwctx;
+	__u32 type;
+	__u64 cmd_handles;
+	__u64 args;
+	__u32 cmd_count;
+	__u32 arg_count;
+	__u64 seq;
+};
+
+/**
+ * struct amdxdna_drm_query_aie_status - Query the status of the AIE hardware
+ * @buffer: The user space buffer that will return the AIE status.
+ * @buffer_size: The size of the user space buffer.
+ * @cols_filled: A bitmap of AIE columns whose data has been returned in the buffer.
+ */
+struct amdxdna_drm_query_aie_status {
+	__u64 buffer; /* out */
+	__u32 buffer_size; /* in */
+	__u32 cols_filled; /* out */
+};
+
+/**
+ * struct amdxdna_drm_query_aie_version - Query the version of the AIE hardware
+ * @major: The major version number.
+ * @minor: The minor version number.
+ */
+struct amdxdna_drm_query_aie_version {
+	__u32 major; /* out */
+	__u32 minor; /* out */
+};
+
+/**
+ * struct amdxdna_drm_query_aie_tile_metadata - Query the metadata of AIE tile (core, mem, shim)
+ * @row_count: The number of rows.
+ * @row_start: The starting row number.
+ * @dma_channel_count: The number of dma channels.
+ * @lock_count: The number of locks.
+ * @event_reg_count: The number of events.
+ * @pad: Structure padding.
+ */
+struct amdxdna_drm_query_aie_tile_metadata {
+	__u16 row_count;
+	__u16 row_start;
+	__u16 dma_channel_count;
+	__u16 lock_count;
+	__u16 event_reg_count;
+	__u16 pad[3];
+};
+
+/**
+ * struct amdxdna_drm_query_aie_metadata - Query the metadata of the AIE hardware
+ * @col_size: The size of a column in bytes.
+ * @cols: The total number of columns.
+ * @rows: The total number of rows.
+ * @version: The version of the AIE hardware.
+ * @core: The metadata for all core tiles.
+ * @mem: The metadata for all mem tiles.
+ * @shim: The metadata for all shim tiles.
+ */
+struct amdxdna_drm_query_aie_metadata {
+	__u32 col_size;
+	__u16 cols;
+	__u16 rows;
+	struct amdxdna_drm_query_aie_version version;
+	struct amdxdna_drm_query_aie_tile_metadata core;
+	struct amdxdna_drm_query_aie_tile_metadata mem;
+	struct amdxdna_drm_query_aie_tile_metadata shim;
+};
+
+/**
+ * struct amdxdna_drm_query_clock - Metadata for a clock
+ * @name: The clock name.
+ * @freq_mhz: The clock frequency.
+ * @pad: Structure padding.
+ */
+struct amdxdna_drm_query_clock {
+	__u8 name[16];
+	__u32 freq_mhz;
+	__u32 pad;
+};
+
+/**
+ * struct amdxdna_drm_query_clock_metadata - Query metadata for clocks
+ * @mp_npu_clock: The metadata for MP-NPU clock.
+ * @h_clock: The metadata for H clock.
+ */
+struct amdxdna_drm_query_clock_metadata {
+	struct amdxdna_drm_query_clock mp_npu_clock;
+	struct amdxdna_drm_query_clock h_clock;
+};
+
+enum amdxdna_sensor_type {
+	AMDXDNA_SENSOR_TYPE_POWER
+};
+
+/**
+ * struct amdxdna_drm_query_sensor - The data for single sensor.
+ * @label: The name for a sensor.
+ * @input: The current value of the sensor.
+ * @max: The maximum value possible for the sensor.
+ * @average: The average value of the sensor.
+ * @highest: The highest recorded sensor value for this driver load for the sensor.
+ * @status: The sensor status.
+ * @units: The sensor units.
+ * @unitm: Translates value member variables into the correct unit via (pow(10, unitm) * value).
+ * @type: The sensor type from enum amdxdna_sensor_type.
+ * @pad: Structure padding.
+ */
+struct amdxdna_drm_query_sensor {
+	__u8  label[64];
+	__u32 input;
+	__u32 max;
+	__u32 average;
+	__u32 highest;
+	__u8  status[64];
+	__u8  units[16];
+	__s8  unitm;
+	__u8  type;
+	__u8  pad[6];
+};
+
+/**
+ * struct amdxdna_drm_query_hwctx - The data for single context.
+ * @context_id: The ID for this context.
+ * @start_col: The starting column for the partition assigned to this context.
+ * @num_col: The number of columns in the partition assigned to this context.
+ * @pad: Structure padding.
+ * @pid: The Process ID of the process that created this context.
+ * @command_submissions: The number of commands submitted to this context.
+ * @command_completions: The number of commands completed by this context.
+ * @migrations: The number of times this context has been moved to a different partition.
+ * @preemptions: The number of times this context has been preempted by another context in the
+ *               same partition.
+ * @errors: The errors for this context.
+ */
+struct amdxdna_drm_query_hwctx {
+	__u32 context_id;
+	__u32 start_col;
+	__u32 num_col;
+	__u32 pad;
+	__s64 pid;
+	__u64 command_submissions;
+	__u64 command_completions;
+	__u64 migrations;
+	__u64 preemptions;
+	__u64 errors;
+};
+
+enum amdxdna_power_mode_type {
+	POWER_MODE_DEFAULT, /* Fallback to calculated DPM */
+	POWER_MODE_LOW,     /* Set frequency to lowest DPM */
+	POWER_MODE_MEDIUM,  /* Set frequency to medium DPM */
+	POWER_MODE_HIGH,    /* Set frequency to highest DPM */
+	POWER_MODE_TURBO,   /* Maximum power */
+};
+
+/**
+ * struct amdxdna_drm_get_power_mode - Get the configured power mode
+ * @power_mode: The mode type from enum amdxdna_power_mode_type
+ * @pad: Structure padding.
+ */
+struct amdxdna_drm_get_power_mode {
+	__u8 power_mode;
+	__u8 pad[7];
+};
+
+/**
+ * struct amdxdna_drm_query_firmware_version - Query the firmware version
+ * @major: The major version number
+ * @minor: The minor version number
+ * @patch: The patch level version number
+ * @build: The build ID
+ */
+struct amdxdna_drm_query_firmware_version {
+	__u32 major; /* out */
+	__u32 minor; /* out */
+	__u32 patch; /* out */
+	__u32 build; /* out */
+};
+
+enum amdxdna_drm_get_param {
+	DRM_AMDXDNA_QUERY_AIE_STATUS,
+	DRM_AMDXDNA_QUERY_AIE_METADATA,
+	DRM_AMDXDNA_QUERY_AIE_VERSION,
+	DRM_AMDXDNA_QUERY_CLOCK_METADATA,
+	DRM_AMDXDNA_QUERY_SENSORS,
+	DRM_AMDXDNA_QUERY_HW_CONTEXTS,
+	DRM_AMDXDNA_QUERY_FIRMWARE_VERSION = 8,
+	DRM_AMDXDNA_GET_POWER_MODE,
+};
+
+/**
+ * struct amdxdna_drm_get_info - Get some information from the AIE hardware.
+ * @param: Value in enum amdxdna_drm_get_param. Specifies the structure passed in the buffer.
+ * @buffer_size: Size of the input buffer. Size needed/written by the kernel.
+ * @buffer: A structure specified by the param struct member.
+ */
+struct amdxdna_drm_get_info {
+	__u32 param; /* in */
+	__u32 buffer_size; /* in/out */
+	__u64 buffer; /* in/out */
+};
+
+enum amdxdna_drm_set_param {
+	DRM_AMDXDNA_SET_POWER_MODE,
+	DRM_AMDXDNA_WRITE_AIE_MEM,
+	DRM_AMDXDNA_WRITE_AIE_REG,
+};
+
+/**
+ * struct amdxdna_drm_set_state - Set the state of the AIE hardware.
+ * @param: Value in enum amdxdna_drm_set_param.
+ * @buffer_size: Size of the input param.
+ * @buffer: Pointer to the input param.
+ */
+struct amdxdna_drm_set_state {
+	__u32 param; /* in */
+	__u32 buffer_size; /* in */
+	__u64 buffer; /* in */
+};
+
+/**
+ * struct amdxdna_drm_set_power_mode - Set the power mode of the AIE hardware
+ * @power_mode: The sensor type from enum amdxdna_power_mode_type
+ * @pad: MBZ.
+ */
+struct amdxdna_drm_set_power_mode {
+	__u8 power_mode;
+	__u8 pad[7];
+};
+
+#define DRM_IOCTL_AMDXDNA_CREATE_HWCTX \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_HWCTX, \
+		 struct amdxdna_drm_create_hwctx)
+
+#define DRM_IOCTL_AMDXDNA_DESTROY_HWCTX \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_DESTROY_HWCTX, \
+		 struct amdxdna_drm_destroy_hwctx)
+
+#define DRM_IOCTL_AMDXDNA_CONFIG_HWCTX \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CONFIG_HWCTX, \
+		 struct amdxdna_drm_config_hwctx)
+
+#define DRM_IOCTL_AMDXDNA_CREATE_BO \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_CREATE_BO, \
+		 struct amdxdna_drm_create_bo)
+
+#define DRM_IOCTL_AMDXDNA_GET_BO_INFO \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_BO_INFO, \
+		 struct amdxdna_drm_get_bo_info)
+
+#define DRM_IOCTL_AMDXDNA_SYNC_BO \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SYNC_BO, \
+		 struct amdxdna_drm_sync_bo)
+
+#define DRM_IOCTL_AMDXDNA_EXEC_CMD \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_EXEC_CMD, \
+		 struct amdxdna_drm_exec_cmd)
+
+#define DRM_IOCTL_AMDXDNA_GET_INFO \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_GET_INFO, \
+		 struct amdxdna_drm_get_info)
+
+#define DRM_IOCTL_AMDXDNA_SET_STATE \
+	DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_SET_STATE, \
+		 struct amdxdna_drm_set_state)
+
+#if defined(__cplusplus)
+} /* extern c end */
+#endif
+
+#endif /* _UAPI_AMDXDNA_ACCEL_H_ */
diff --git a/original/uapi/drm/drm.h b/original/uapi/drm/drm.h
index 1612281..7fba37b 100644
--- a/original/uapi/drm/drm.h
+++ b/original/uapi/drm/drm.h
@@ -1024,6 +1024,13 @@ struct drm_crtc_queue_sequence {
 	__u64 user_data;	/* user data passed to event */
 };
 
+#define DRM_CLIENT_NAME_MAX_LEN		64
+struct drm_set_client_name {
+	__u64 name_len;
+	__u64 name;
+};
+
+
 #if defined(__cplusplus)
 }
 #endif
@@ -1288,6 +1295,16 @@ extern "C" {
  */
 #define DRM_IOCTL_MODE_CLOSEFB		DRM_IOWR(0xD0, struct drm_mode_closefb)
 
+/**
+ * DRM_IOCTL_SET_CLIENT_NAME - Attach a name to a drm_file
+ *
+ * Having a name allows for easier tracking and debugging.
+ * The length of the name (without null ending char) must be
+ * <= DRM_CLIENT_NAME_MAX_LEN.
+ * The call will fail if the name contains whitespaces or non-printable chars.
+ */
+#define DRM_IOCTL_SET_CLIENT_NAME	DRM_IOWR(0xD1, struct drm_set_client_name)
+
 /*
  * Device specific ioctls should only be in their respective headers
  * The device specific ioctl range is from 0x40 to 0x9f.
diff --git a/original/uapi/drm/drm_fourcc.h b/original/uapi/drm/drm_fourcc.h
index 78abd81..70f3b00 100644
--- a/original/uapi/drm/drm_fourcc.h
+++ b/original/uapi/drm/drm_fourcc.h
@@ -1516,6 +1516,7 @@ drm_fourcc_canonicalize_nvidia_format_mod(__u64 modifier)
  * 64K_D_2D on GFX12 is identical to 64K_D on GFX11.
  */
 #define AMD_FMT_MOD_TILE_GFX9_64K_D 10
+#define AMD_FMT_MOD_TILE_GFX9_4K_D_X 22
 #define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
 #define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
 #define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
diff --git a/original/uapi/drm/ivpu_accel.h b/original/uapi/drm/ivpu_accel.h
index 084fb52..a35b97b 100644
--- a/original/uapi/drm/ivpu_accel.h
+++ b/original/uapi/drm/ivpu_accel.h
@@ -12,9 +12,6 @@
 extern "C" {
 #endif
 
-#define DRM_IVPU_DRIVER_MAJOR 1
-#define DRM_IVPU_DRIVER_MINOR 0
-
 #define DRM_IVPU_GET_PARAM		  0x00
 #define DRM_IVPU_SET_PARAM		  0x01
 #define DRM_IVPU_BO_CREATE		  0x02
@@ -261,7 +258,7 @@ struct drm_ivpu_bo_info {
 
 /* drm_ivpu_submit engines */
 #define DRM_IVPU_ENGINE_COMPUTE 0
-#define DRM_IVPU_ENGINE_COPY    1
+#define DRM_IVPU_ENGINE_COPY    1 /* Deprecated */
 
 /**
  * struct drm_ivpu_submit - Submit commands to the VPU
@@ -292,10 +289,6 @@ struct drm_ivpu_submit {
 	 * %DRM_IVPU_ENGINE_COMPUTE:
 	 *
 	 * Performs Deep Learning Neural Compute Inference Operations
-	 *
-	 * %DRM_IVPU_ENGINE_COPY:
-	 *
-	 * Performs memory copy operations to/from system memory allocated for VPU
 	 */
 	__u32 engine;
 
diff --git a/original/uapi/drm/msm_drm.h b/original/uapi/drm/msm_drm.h
index 2377147..2342cb9 100644
--- a/original/uapi/drm/msm_drm.h
+++ b/original/uapi/drm/msm_drm.h
@@ -90,6 +90,7 @@ struct drm_msm_timespec {
 #define MSM_PARAM_RAYTRACING 0x11 /* RO */
 #define MSM_PARAM_UBWC_SWIZZLE 0x12 /* RO */
 #define MSM_PARAM_MACROTILE_MODE 0x13 /* RO */
+#define MSM_PARAM_UCHE_TRAP_BASE 0x14 /* RO */
 
 /* For backwards compat.  The original support for preemption was based on
  * a single ring per priority level so # of priority levels equals the #
@@ -347,7 +348,10 @@ struct drm_msm_gem_madvise {
  * backwards compatibility as a "default" submitqueue
  */
 
-#define MSM_SUBMITQUEUE_FLAGS (0)
+#define MSM_SUBMITQUEUE_ALLOW_PREEMPT	0x00000001
+#define MSM_SUBMITQUEUE_FLAGS		    ( \
+		MSM_SUBMITQUEUE_ALLOW_PREEMPT | \
+		0)
 
 /*
  * The submitqueue priority should be between 0 and MSM_PARAM_PRIORITIES-1,
diff --git a/original/uapi/drm/panfrost_drm.h b/original/uapi/drm/panfrost_drm.h
index 9f231d4..568724b 100644
--- a/original/uapi/drm/panfrost_drm.h
+++ b/original/uapi/drm/panfrost_drm.h
@@ -40,6 +40,7 @@ extern "C" {
 #define DRM_IOCTL_PANFROST_PERFCNT_DUMP		DRM_IOW(DRM_COMMAND_BASE + DRM_PANFROST_PERFCNT_DUMP, struct drm_panfrost_perfcnt_dump)
 
 #define PANFROST_JD_REQ_FS (1 << 0)
+#define PANFROST_JD_REQ_CYCLE_COUNT (1 << 1)
 /**
  * struct drm_panfrost_submit - ioctl argument for submitting commands to the 3D
  * engine.
@@ -172,6 +173,8 @@ enum drm_panfrost_param {
 	DRM_PANFROST_PARAM_NR_CORE_GROUPS,
 	DRM_PANFROST_PARAM_THREAD_TLS_ALLOC,
 	DRM_PANFROST_PARAM_AFBC_FEATURES,
+	DRM_PANFROST_PARAM_SYSTEM_TIMESTAMP,
+	DRM_PANFROST_PARAM_SYSTEM_TIMESTAMP_FREQUENCY,
 };
 
 struct drm_panfrost_get_param {
diff --git a/original/uapi/drm/panthor_drm.h b/original/uapi/drm/panthor_drm.h
index e23a7f9..b99763c 100644
--- a/original/uapi/drm/panthor_drm.h
+++ b/original/uapi/drm/panthor_drm.h
@@ -260,6 +260,14 @@ enum drm_panthor_dev_query_type {
 
 	/** @DRM_PANTHOR_DEV_QUERY_CSIF_INFO: Query command-stream interface information. */
 	DRM_PANTHOR_DEV_QUERY_CSIF_INFO,
+
+	/** @DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO: Query timestamp information. */
+	DRM_PANTHOR_DEV_QUERY_TIMESTAMP_INFO,
+
+	/**
+	 * @DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO: Query allowed group priorities information.
+	 */
+	DRM_PANTHOR_DEV_QUERY_GROUP_PRIORITIES_INFO,
 };
 
 /**
@@ -377,6 +385,42 @@ struct drm_panthor_csif_info {
 	__u32 pad;
 };
 
+/**
+ * struct drm_panthor_timestamp_info - Timestamp information
+ *
+ * Structure grouping all queryable information relating to the GPU timestamp.
+ */
+struct drm_panthor_timestamp_info {
+	/**
+	 * @timestamp_frequency: The frequency of the timestamp timer or 0 if
+	 * unknown.
+	 */
+	__u64 timestamp_frequency;
+
+	/** @current_timestamp: The current timestamp. */
+	__u64 current_timestamp;
+
+	/** @timestamp_offset: The offset of the timestamp timer. */
+	__u64 timestamp_offset;
+};
+
+/**
+ * struct drm_panthor_group_priorities_info - Group priorities information
+ *
+ * Structure grouping all queryable information relating to the allowed group priorities.
+ */
+struct drm_panthor_group_priorities_info {
+	/**
+	 * @allowed_mask: Bitmask of the allowed group priorities.
+	 *
+	 * Each bit represents a variant of the enum drm_panthor_group_priority.
+	 */
+	__u8 allowed_mask;
+
+	/** @pad: Padding fields, MBZ. */
+	__u8 pad[3];
+};
+
 /**
  * struct drm_panthor_dev_query - Arguments passed to DRM_PANTHOR_IOCTL_DEV_QUERY
  */
@@ -698,6 +742,13 @@ enum drm_panthor_group_priority {
 	 * Requires CAP_SYS_NICE or DRM_MASTER.
 	 */
 	PANTHOR_GROUP_PRIORITY_HIGH,
+
+	/**
+	 * @PANTHOR_GROUP_PRIORITY_REALTIME: Realtime priority group.
+	 *
+	 * Requires CAP_SYS_NICE or DRM_MASTER.
+	 */
+	PANTHOR_GROUP_PRIORITY_REALTIME,
 };
 
 /**
@@ -872,6 +923,15 @@ enum drm_panthor_group_state_flags {
 	 * When a group ends up with this flag set, no jobs can be submitted to its queues.
 	 */
 	DRM_PANTHOR_GROUP_STATE_FATAL_FAULT = 1 << 1,
+
+	/**
+	 * @DRM_PANTHOR_GROUP_STATE_INNOCENT: Group was killed during a reset caused by other
+	 * groups.
+	 *
+	 * This flag can only be set if DRM_PANTHOR_GROUP_STATE_TIMEDOUT is set and
+	 * DRM_PANTHOR_GROUP_STATE_FATAL_FAULT is not.
+	 */
+	DRM_PANTHOR_GROUP_STATE_INNOCENT = 1 << 2,
 };
 
 /**
diff --git a/original/uapi/drm/qaic_accel.h b/original/uapi/drm/qaic_accel.h
index d3ca876..c92d030 100644
--- a/original/uapi/drm/qaic_accel.h
+++ b/original/uapi/drm/qaic_accel.h
@@ -64,7 +64,7 @@ struct qaic_manage_trans_hdr {
 /**
  * struct qaic_manage_trans_passthrough - Defines a passthrough transaction.
  * @hdr: In. Header to identify this transaction.
- * @data: In. Payload of this ransaction. Opaque to the driver. Userspace must
+ * @data: In. Payload of this transaction. Opaque to the driver. Userspace must
  *	  encode in little endian and align/pad to 64-bit.
  */
 struct qaic_manage_trans_passthrough {
diff --git a/original/uapi/drm/v3d_drm.h b/original/uapi/drm/v3d_drm.h
index 87fc5bb..dbbc404 100644
--- a/original/uapi/drm/v3d_drm.h
+++ b/original/uapi/drm/v3d_drm.h
@@ -43,6 +43,7 @@ extern "C" {
 #define DRM_V3D_PERFMON_GET_VALUES                0x0a
 #define DRM_V3D_SUBMIT_CPU                        0x0b
 #define DRM_V3D_PERFMON_GET_COUNTER               0x0c
+#define DRM_V3D_PERFMON_SET_GLOBAL                0x0d
 
 #define DRM_IOCTL_V3D_SUBMIT_CL           DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CL, struct drm_v3d_submit_cl)
 #define DRM_IOCTL_V3D_WAIT_BO             DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_WAIT_BO, struct drm_v3d_wait_bo)
@@ -61,6 +62,8 @@ extern "C" {
 #define DRM_IOCTL_V3D_SUBMIT_CPU          DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CPU, struct drm_v3d_submit_cpu)
 #define DRM_IOCTL_V3D_PERFMON_GET_COUNTER DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_COUNTER, \
 						   struct drm_v3d_perfmon_get_counter)
+#define DRM_IOCTL_V3D_PERFMON_SET_GLOBAL  DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_PERFMON_SET_GLOBAL, \
+						   struct drm_v3d_perfmon_set_global)
 
 #define DRM_V3D_SUBMIT_CL_FLUSH_CACHE             0x01
 #define DRM_V3D_SUBMIT_EXTENSION		  0x02
@@ -290,6 +293,7 @@ enum drm_v3d_param {
 	DRM_V3D_PARAM_SUPPORTS_MULTISYNC_EXT,
 	DRM_V3D_PARAM_SUPPORTS_CPU_QUEUE,
 	DRM_V3D_PARAM_MAX_PERF_COUNTERS,
+	DRM_V3D_PARAM_SUPPORTS_SUPER_PAGES,
 };
 
 struct drm_v3d_get_param {
@@ -765,6 +769,21 @@ struct drm_v3d_perfmon_get_counter {
 	__u8 reserved[7];
 };
 
+#define DRM_V3D_PERFMON_CLEAR_GLOBAL    0x0001
+
+/**
+ * struct drm_v3d_perfmon_set_global - ioctl to define a global performance
+ * monitor
+ *
+ * The global performance monitor will be used for all jobs. If a global
+ * performance monitor is defined, jobs with a self-defined performance
+ * monitor won't be allowed.
+ */
+struct drm_v3d_perfmon_set_global {
+	__u32 flags;
+	__u32 id;
+};
+
 #if defined(__cplusplus)
 }
 #endif
diff --git a/original/uapi/drm/xe_drm.h b/original/uapi/drm/xe_drm.h
index b6fbe49..f62689c 100644
--- a/original/uapi/drm/xe_drm.h
+++ b/original/uapi/drm/xe_drm.h
@@ -512,7 +512,9 @@ struct drm_xe_query_gt_list {
  *    containing the following in mask:
  *    ``DSS_COMPUTE    ff ff ff ff 00 00 00 00``
  *    means 32 DSS are available for compute.
- *  - %DRM_XE_TOPO_L3_BANK - To query the mask of enabled L3 banks
+ *  - %DRM_XE_TOPO_L3_BANK - To query the mask of enabled L3 banks.  This type
+ *    may be omitted if the driver is unable to query the mask from the
+ *    hardware.
  *  - %DRM_XE_TOPO_EU_PER_DSS - To query the mask of Execution Units (EU)
  *    available per Dual Sub Slices (DSS). For example a query response
  *    containing the following in mask:
@@ -1483,6 +1485,9 @@ struct drm_xe_oa_unit {
 	/** @capabilities: OA capabilities bit-mask */
 	__u64 capabilities;
 #define DRM_XE_OA_CAPS_BASE		(1 << 0)
+#define DRM_XE_OA_CAPS_SYNCS		(1 << 1)
+#define DRM_XE_OA_CAPS_OA_BUFFER_SIZE	(1 << 2)
+#define DRM_XE_OA_CAPS_WAIT_NUM_REPORTS	(1 << 3)
 
 	/** @oa_timestamp_freq: OA timestamp freq */
 	__u64 oa_timestamp_freq;
@@ -1632,6 +1637,36 @@ enum drm_xe_oa_property_id {
 	 * to be disabled for the stream exec queue.
 	 */
 	DRM_XE_OA_PROPERTY_NO_PREEMPT,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_NUM_SYNCS: Number of syncs in the sync array
+	 * specified in @DRM_XE_OA_PROPERTY_SYNCS
+	 */
+	DRM_XE_OA_PROPERTY_NUM_SYNCS,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_SYNCS: Pointer to struct @drm_xe_sync array
+	 * with array size specified via @DRM_XE_OA_PROPERTY_NUM_SYNCS. OA
+	 * configuration will wait till input fences signal. Output fences
+	 * will signal after the new OA configuration takes effect. For
+	 * @DRM_XE_SYNC_TYPE_USER_FENCE, @addr is a user pointer, similar
+	 * to the VM bind case.
+	 */
+	DRM_XE_OA_PROPERTY_SYNCS,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_OA_BUFFER_SIZE: Size of OA buffer to be
+	 * allocated by the driver in bytes. Supported sizes are powers of
+	 * 2 from 128 KiB to 128 MiB. When not specified, a 16 MiB OA
+	 * buffer is allocated by default.
+	 */
+	DRM_XE_OA_PROPERTY_OA_BUFFER_SIZE,
+
+	/**
+	 * @DRM_XE_OA_PROPERTY_WAIT_NUM_REPORTS: Number of reports to wait
+	 * for before unblocking poll or read
+	 */
+	DRM_XE_OA_PROPERTY_WAIT_NUM_REPORTS,
 };
 
 /**
diff --git a/original/uapi/linux/audit.h b/original/uapi/linux/audit.h
index 75e21a1..d9a069b 100644
--- a/original/uapi/linux/audit.h
+++ b/original/uapi/linux/audit.h
@@ -161,6 +161,7 @@
 #define AUDIT_INTEGRITY_RULE	    1805 /* policy rule */
 #define AUDIT_INTEGRITY_EVM_XATTR   1806 /* New EVM-covered xattr */
 #define AUDIT_INTEGRITY_POLICY_RULE 1807 /* IMA policy rules */
+#define AUDIT_INTEGRITY_USERSPACE   1808 /* Userspace enforced data integrity */
 
 #define AUDIT_KERNEL		2000	/* Asynchronous audit record. NOT A REQUEST. */
 
diff --git a/original/uapi/linux/batadv_packet.h b/original/uapi/linux/batadv_packet.h
index 6e25753..439132a 100644
--- a/original/uapi/linux/batadv_packet.h
+++ b/original/uapi/linux/batadv_packet.h
@@ -9,6 +9,7 @@
 
 #include <asm/byteorder.h>
 #include <linux/if_ether.h>
+#include <linux/stddef.h>
 #include <linux/types.h>
 
 /**
@@ -592,19 +593,6 @@ struct batadv_tvlv_gateway_data {
 	__be32 bandwidth_up;
 };
 
-/**
- * struct batadv_tvlv_tt_data - tt data propagated through the tt tvlv container
- * @flags: translation table flags (see batadv_tt_data_flags)
- * @ttvn: translation table version number
- * @num_vlan: number of announced VLANs. In the TVLV this struct is followed by
- *  one batadv_tvlv_tt_vlan_data object per announced vlan
- */
-struct batadv_tvlv_tt_data {
-	__u8   flags;
-	__u8   ttvn;
-	__be16 num_vlan;
-};
-
 /**
  * struct batadv_tvlv_tt_vlan_data - vlan specific tt data propagated through
  *  the tt tvlv container
@@ -618,6 +606,21 @@ struct batadv_tvlv_tt_vlan_data {
 	__u16  reserved;
 };
 
+/**
+ * struct batadv_tvlv_tt_data - tt data propagated through the tt tvlv container
+ * @flags: translation table flags (see batadv_tt_data_flags)
+ * @ttvn: translation table version number
+ * @num_vlan: number of announced VLANs. In the TVLV this struct is followed by
+ *  one batadv_tvlv_tt_vlan_data object per announced vlan
+ * @vlan_data: array of batadv_tvlv_tt_vlan_data objects
+ */
+struct batadv_tvlv_tt_data {
+	__u8   flags;
+	__u8   ttvn;
+	__be16 num_vlan;
+	struct batadv_tvlv_tt_vlan_data vlan_data[] __counted_by_be(num_vlan);
+};
+
 /**
  * struct batadv_tvlv_tt_change - translation table diff data
  * @flags: status indicators concerning the non-mesh client (see
diff --git a/original/uapi/linux/blk-crypto.h b/original/uapi/linux/blk-crypto.h
new file mode 100644
index 0000000..97302c6
--- /dev/null
+++ b/original/uapi/linux/blk-crypto.h
@@ -0,0 +1,44 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+#ifndef _UAPI_LINUX_BLK_CRYPTO_H
+#define _UAPI_LINUX_BLK_CRYPTO_H
+
+#include <linux/ioctl.h>
+#include <linux/types.h>
+
+struct blk_crypto_import_key_arg {
+	/* Raw key (input) */
+	__u64 raw_key_ptr;
+	__u64 raw_key_size;
+	/* Long-term wrapped key blob (output) */
+	__u64 lt_key_ptr;
+	__u64 lt_key_size;
+	__u64 reserved[4];
+};
+
+struct blk_crypto_generate_key_arg {
+	/* Long-term wrapped key blob (output) */
+	__u64 lt_key_ptr;
+	__u64 lt_key_size;
+	__u64 reserved[4];
+};
+
+struct blk_crypto_prepare_key_arg {
+	/* Long-term wrapped key blob (input) */
+	__u64 lt_key_ptr;
+	__u64 lt_key_size;
+	/* Ephemerally-wrapped key blob (output) */
+	__u64 eph_key_ptr;
+	__u64 eph_key_size;
+	__u64 reserved[4];
+};
+
+/*
+ * These ioctls share the block device ioctl space; see uapi/linux/fs.h.
+ * 140-141 are reserved for future blk-crypto ioctls; any more than that would
+ * require an additional allocation from the block device ioctl space.
+ */
+#define BLKCRYPTOIMPORTKEY _IOWR(0x12, 137, struct blk_crypto_import_key_arg)
+#define BLKCRYPTOGENERATEKEY _IOWR(0x12, 138, struct blk_crypto_generate_key_arg)
+#define BLKCRYPTOPREPAREKEY _IOWR(0x12, 139, struct blk_crypto_prepare_key_arg)
+
+#endif /* _UAPI_LINUX_BLK_CRYPTO_H */
diff --git a/original/uapi/linux/bpf.h b/original/uapi/linux/bpf.h
index 4a939c9..2acf9b3 100644
--- a/original/uapi/linux/bpf.h
+++ b/original/uapi/linux/bpf.h
@@ -1116,6 +1116,7 @@ enum bpf_attach_type {
 	BPF_NETKIT_PRIMARY,
 	BPF_NETKIT_PEER,
 	BPF_TRACE_KPROBE_SESSION,
+	BPF_TRACE_UPROBE_SESSION,
 	__MAX_BPF_ATTACH_TYPE
 };
 
@@ -1572,6 +1573,16 @@ union bpf_attr {
 		 * If provided, prog_flags should have BPF_F_TOKEN_FD flag set.
 		 */
 		__s32		prog_token_fd;
+		/* The fd_array_cnt can be used to pass the length of the
+		 * fd_array array. In this case all the [map] file descriptors
+		 * passed in this array will be bound to the program, even if
+		 * the maps are not referenced directly. The functionality is
+		 * similar to the BPF_PROG_BIND_MAP syscall, but maps can be
+		 * used by the verifier during the program load. If provided,
+		 * then the fd_array[0,...,fd_array_cnt-1] is expected to be
+		 * continuous.
+		 */
+		__u32		fd_array_cnt;
 	};
 
 	struct { /* anonymous struct used by BPF_OBJ_* commands */
@@ -1973,6 +1984,8 @@ union bpf_attr {
  * 		program.
  * 	Return
  * 		The SMP id of the processor running the program.
+ * 	Attributes
+ * 		__bpf_fastcall
  *
  * long bpf_skb_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len, u64 flags)
  * 	Description
@@ -3104,10 +3117,6 @@ union bpf_attr {
  * 		with the **CONFIG_BPF_KPROBE_OVERRIDE** configuration
  * 		option, and in this case it only works on functions tagged with
  * 		**ALLOW_ERROR_INJECTION** in the kernel code.
- *
- * 		Also, the helper is only available for the architectures having
- * 		the CONFIG_FUNCTION_ERROR_INJECTION option. As of this writing,
- * 		x86 architecture is the only one to support this feature.
  * 	Return
  * 		0
  *
@@ -5372,7 +5381,7 @@ union bpf_attr {
  *		Currently, the **flags** must be 0. Currently, nr_loops is
  *		limited to 1 << 23 (~8 million) loops.
  *
- *		long (\*callback_fn)(u32 index, void \*ctx);
+ *		long (\*callback_fn)(u64 index, void \*ctx);
  *
  *		where **index** is the current index in the loop. The index
  *		is zero-indexed.
diff --git a/original/uapi/linux/btrfs.h b/original/uapi/linux/btrfs.h
index cdf6ad8..d3b222d 100644
--- a/original/uapi/linux/btrfs.h
+++ b/original/uapi/linux/btrfs.h
@@ -1049,6 +1049,29 @@ struct btrfs_ioctl_encoded_io_args {
 #define BTRFS_ENCODED_IO_ENCRYPTION_NONE 0
 #define BTRFS_ENCODED_IO_ENCRYPTION_TYPES 1
 
+/*
+ * Wait for subvolume cleaning process. This queries the kernel queue and it
+ * can change between the calls.
+ *
+ * - FOR_ONE	- specify the subvolid
+ * - FOR_QUEUED - wait for all currently queued
+ * - COUNT	- count number of queued
+ * - PEEK_FIRST - read which is the first in the queue (to be cleaned or being
+ * 		  cleaned already), or 0 if the queue is empty
+ * - PEEK_LAST  - read the last subvolid in the queue, or 0 if the queue is empty
+ */
+struct btrfs_ioctl_subvol_wait {
+	__u64 subvolid;
+	__u32 mode;
+	__u32 count;
+};
+
+#define BTRFS_SUBVOL_SYNC_WAIT_FOR_ONE		(0)
+#define BTRFS_SUBVOL_SYNC_WAIT_FOR_QUEUED	(1)
+#define BTRFS_SUBVOL_SYNC_COUNT			(2)
+#define BTRFS_SUBVOL_SYNC_PEEK_FIRST		(3)
+#define BTRFS_SUBVOL_SYNC_PEEK_LAST		(4)
+
 /* Error codes as returned by the kernel */
 enum btrfs_err_code {
 	BTRFS_ERROR_DEV_RAID1_MIN_NOT_MET = 1,
@@ -1181,6 +1204,8 @@ enum btrfs_err_code {
 				    struct btrfs_ioctl_encoded_io_args)
 #define BTRFS_IOC_ENCODED_WRITE _IOW(BTRFS_IOCTL_MAGIC, 64, \
 				     struct btrfs_ioctl_encoded_io_args)
+#define BTRFS_IOC_SUBVOL_SYNC_WAIT _IOW(BTRFS_IOCTL_MAGIC, 65, \
+					struct btrfs_ioctl_subvol_wait)
 
 #ifdef __cplusplus
 }
diff --git a/original/uapi/linux/cryptouser.h b/original/uapi/linux/cryptouser.h
index 20a6c0f..db05e04 100644
--- a/original/uapi/linux/cryptouser.h
+++ b/original/uapi/linux/cryptouser.h
@@ -64,6 +64,7 @@ enum crypto_attr_type_t {
 	CRYPTOCFGA_STAT_AKCIPHER,	/* No longer supported, do not use. */
 	CRYPTOCFGA_STAT_KPP,		/* No longer supported, do not use. */
 	CRYPTOCFGA_STAT_ACOMP,		/* No longer supported, do not use. */
+	CRYPTOCFGA_REPORT_SIG,		/* struct crypto_report_sig */
 	__CRYPTOCFGA_MAX
 
 #define CRYPTOCFGA_MAX (__CRYPTOCFGA_MAX - 1)
@@ -207,6 +208,10 @@ struct crypto_report_acomp {
 	char type[CRYPTO_MAX_NAME];
 };
 
+struct crypto_report_sig {
+	char type[CRYPTO_MAX_NAME];
+};
+
 #define CRYPTO_REPORT_MAXSIZE (sizeof(struct crypto_user_alg) + \
 			       sizeof(struct crypto_report_blkcipher))
 
diff --git a/original/uapi/linux/dm-ioctl.h b/original/uapi/linux/dm-ioctl.h
index 1990b57..b08c737 100644
--- a/original/uapi/linux/dm-ioctl.h
+++ b/original/uapi/linux/dm-ioctl.h
@@ -286,9 +286,9 @@ enum {
 #define DM_DEV_SET_GEOMETRY	_IOWR(DM_IOCTL, DM_DEV_SET_GEOMETRY_CMD, struct dm_ioctl)
 
 #define DM_VERSION_MAJOR	4
-#define DM_VERSION_MINOR	48
+#define DM_VERSION_MINOR	49
 #define DM_VERSION_PATCHLEVEL	0
-#define DM_VERSION_EXTRA	"-ioctl (2023-03-01)"
+#define DM_VERSION_EXTRA	"-ioctl (2025-01-17)"
 
 /* Status bits */
 #define DM_READONLY_FLAG	(1 << 0) /* In/Out */
diff --git a/original/uapi/linux/dpll.h b/original/uapi/linux/dpll.h
index b0654ad..bf97d4b 100644
--- a/original/uapi/linux/dpll.h
+++ b/original/uapi/linux/dpll.h
@@ -79,6 +79,29 @@ enum dpll_lock_status_error {
 	DPLL_LOCK_STATUS_ERROR_MAX = (__DPLL_LOCK_STATUS_ERROR_MAX - 1)
 };
 
+/*
+ * level of quality of a clock device. This mainly applies when the dpll
+ * lock-status is DPLL_LOCK_STATUS_HOLDOVER. The current list is defined
+ * according to the table 11-7 contained in ITU-T G.8264/Y.1364 document. One
+ * may extend this list freely by other ITU-T defined clock qualities, or
+ * different ones defined by another standardization body (for those, please
+ * use different prefix).
+ */
+enum dpll_clock_quality_level {
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC = 1,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC,
+	DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC,
+
+	/* private: */
+	__DPLL_CLOCK_QUALITY_LEVEL_MAX,
+	DPLL_CLOCK_QUALITY_LEVEL_MAX = (__DPLL_CLOCK_QUALITY_LEVEL_MAX - 1)
+};
+
 #define DPLL_TEMP_DIVIDER	1000
 
 /**
@@ -180,6 +203,7 @@ enum dpll_a {
 	DPLL_A_TEMP,
 	DPLL_A_TYPE,
 	DPLL_A_LOCK_STATUS_ERROR,
+	DPLL_A_CLOCK_QUALITY_LEVEL,
 
 	__DPLL_A_MAX,
 	DPLL_A_MAX = (__DPLL_A_MAX - 1)
diff --git a/original/uapi/linux/elf.h b/original/uapi/linux/elf.h
index b993598..b44069d 100644
--- a/original/uapi/linux/elf.h
+++ b/original/uapi/linux/elf.h
@@ -443,6 +443,7 @@ typedef struct elf64_shdr {
 #define NT_ARM_ZT	0x40d		/* ARM SME ZT registers */
 #define NT_ARM_FPMR	0x40e		/* ARM floating point mode register */
 #define NT_ARM_POE	0x40f		/* ARM POE registers */
+#define NT_ARM_GCS	0x410		/* ARM GCS state */
 #define NT_ARC_V2	0x600		/* ARCv2 accumulator/extra registers */
 #define NT_VMCOREDD	0x700		/* Vmcore Device Dump Note */
 #define NT_MIPS_DSP	0x800		/* MIPS DSP ASE registers */
@@ -450,6 +451,7 @@ typedef struct elf64_shdr {
 #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
 #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
 #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
+#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
 #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
 #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
 #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
diff --git a/original/uapi/linux/ethtool.h b/original/uapi/linux/ethtool.h
index c405ed6..9b18c4c 100644
--- a/original/uapi/linux/ethtool.h
+++ b/original/uapi/linux/ethtool.h
@@ -681,6 +681,8 @@ enum ethtool_link_ext_substate_module {
  * @ETH_SS_STATS_ETH_MAC: names of IEEE 802.3 MAC statistics
  * @ETH_SS_STATS_ETH_CTRL: names of IEEE 802.3 MAC Control statistics
  * @ETH_SS_STATS_RMON: names of RMON statistics
+ * @ETH_SS_STATS_PHY: names of PHY(dev) statistics
+ * @ETH_SS_TS_FLAGS: hardware timestamping flags
  *
  * @ETH_SS_COUNT: number of defined string sets
  */
@@ -706,6 +708,8 @@ enum ethtool_stringset {
 	ETH_SS_STATS_ETH_MAC,
 	ETH_SS_STATS_ETH_CTRL,
 	ETH_SS_STATS_RMON,
+	ETH_SS_STATS_PHY,
+	ETH_SS_TS_FLAGS,
 
 	/* add new constants above here */
 	ETH_SS_COUNT
@@ -2526,12 +2530,19 @@ struct ethtool_link_settings {
 	__u8	master_slave_state;
 	__u8	rate_matching;
 	__u32	reserved[7];
+#ifndef __KERNEL__
+	/* Linux builds with -Wflex-array-member-not-at-end but does
+	 * not use the "link_mode_masks" member. Leave it defined for
+	 * userspace for now, and when userspace wants to start using
+	 * -Wfamnae, we'll need a new solution.
+	 */
 	__u32	link_mode_masks[];
 	/* layout of link_mode_masks fields:
 	 * __u32 map_supported[link_mode_masks_nwords];
 	 * __u32 map_advertising[link_mode_masks_nwords];
 	 * __u32 map_lp_advertising[link_mode_masks_nwords];
 	 */
+#endif
 };
 
 /**
diff --git a/original/uapi/linux/ethtool_netlink.h b/original/uapi/linux/ethtool_netlink.h
index 283305f..9ff72cf 100644
--- a/original/uapi/linux/ethtool_netlink.h
+++ b/original/uapi/linux/ethtool_netlink.h
@@ -10,545 +10,12 @@
 #define _UAPI_LINUX_ETHTOOL_NETLINK_H_
 
 #include <linux/ethtool.h>
-
-/* message types - userspace to kernel */
-enum {
-	ETHTOOL_MSG_USER_NONE,
-	ETHTOOL_MSG_STRSET_GET,
-	ETHTOOL_MSG_LINKINFO_GET,
-	ETHTOOL_MSG_LINKINFO_SET,
-	ETHTOOL_MSG_LINKMODES_GET,
-	ETHTOOL_MSG_LINKMODES_SET,
-	ETHTOOL_MSG_LINKSTATE_GET,
-	ETHTOOL_MSG_DEBUG_GET,
-	ETHTOOL_MSG_DEBUG_SET,
-	ETHTOOL_MSG_WOL_GET,
-	ETHTOOL_MSG_WOL_SET,
-	ETHTOOL_MSG_FEATURES_GET,
-	ETHTOOL_MSG_FEATURES_SET,
-	ETHTOOL_MSG_PRIVFLAGS_GET,
-	ETHTOOL_MSG_PRIVFLAGS_SET,
-	ETHTOOL_MSG_RINGS_GET,
-	ETHTOOL_MSG_RINGS_SET,
-	ETHTOOL_MSG_CHANNELS_GET,
-	ETHTOOL_MSG_CHANNELS_SET,
-	ETHTOOL_MSG_COALESCE_GET,
-	ETHTOOL_MSG_COALESCE_SET,
-	ETHTOOL_MSG_PAUSE_GET,
-	ETHTOOL_MSG_PAUSE_SET,
-	ETHTOOL_MSG_EEE_GET,
-	ETHTOOL_MSG_EEE_SET,
-	ETHTOOL_MSG_TSINFO_GET,
-	ETHTOOL_MSG_CABLE_TEST_ACT,
-	ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
-	ETHTOOL_MSG_TUNNEL_INFO_GET,
-	ETHTOOL_MSG_FEC_GET,
-	ETHTOOL_MSG_FEC_SET,
-	ETHTOOL_MSG_MODULE_EEPROM_GET,
-	ETHTOOL_MSG_STATS_GET,
-	ETHTOOL_MSG_PHC_VCLOCKS_GET,
-	ETHTOOL_MSG_MODULE_GET,
-	ETHTOOL_MSG_MODULE_SET,
-	ETHTOOL_MSG_PSE_GET,
-	ETHTOOL_MSG_PSE_SET,
-	ETHTOOL_MSG_RSS_GET,
-	ETHTOOL_MSG_PLCA_GET_CFG,
-	ETHTOOL_MSG_PLCA_SET_CFG,
-	ETHTOOL_MSG_PLCA_GET_STATUS,
-	ETHTOOL_MSG_MM_GET,
-	ETHTOOL_MSG_MM_SET,
-	ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
-	ETHTOOL_MSG_PHY_GET,
-
-	/* add new constants above here */
-	__ETHTOOL_MSG_USER_CNT,
-	ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
-};
-
-/* message types - kernel to userspace */
-enum {
-	ETHTOOL_MSG_KERNEL_NONE,
-	ETHTOOL_MSG_STRSET_GET_REPLY,
-	ETHTOOL_MSG_LINKINFO_GET_REPLY,
-	ETHTOOL_MSG_LINKINFO_NTF,
-	ETHTOOL_MSG_LINKMODES_GET_REPLY,
-	ETHTOOL_MSG_LINKMODES_NTF,
-	ETHTOOL_MSG_LINKSTATE_GET_REPLY,
-	ETHTOOL_MSG_DEBUG_GET_REPLY,
-	ETHTOOL_MSG_DEBUG_NTF,
-	ETHTOOL_MSG_WOL_GET_REPLY,
-	ETHTOOL_MSG_WOL_NTF,
-	ETHTOOL_MSG_FEATURES_GET_REPLY,
-	ETHTOOL_MSG_FEATURES_SET_REPLY,
-	ETHTOOL_MSG_FEATURES_NTF,
-	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
-	ETHTOOL_MSG_PRIVFLAGS_NTF,
-	ETHTOOL_MSG_RINGS_GET_REPLY,
-	ETHTOOL_MSG_RINGS_NTF,
-	ETHTOOL_MSG_CHANNELS_GET_REPLY,
-	ETHTOOL_MSG_CHANNELS_NTF,
-	ETHTOOL_MSG_COALESCE_GET_REPLY,
-	ETHTOOL_MSG_COALESCE_NTF,
-	ETHTOOL_MSG_PAUSE_GET_REPLY,
-	ETHTOOL_MSG_PAUSE_NTF,
-	ETHTOOL_MSG_EEE_GET_REPLY,
-	ETHTOOL_MSG_EEE_NTF,
-	ETHTOOL_MSG_TSINFO_GET_REPLY,
-	ETHTOOL_MSG_CABLE_TEST_NTF,
-	ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
-	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
-	ETHTOOL_MSG_FEC_GET_REPLY,
-	ETHTOOL_MSG_FEC_NTF,
-	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
-	ETHTOOL_MSG_STATS_GET_REPLY,
-	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
-	ETHTOOL_MSG_MODULE_GET_REPLY,
-	ETHTOOL_MSG_MODULE_NTF,
-	ETHTOOL_MSG_PSE_GET_REPLY,
-	ETHTOOL_MSG_RSS_GET_REPLY,
-	ETHTOOL_MSG_PLCA_GET_CFG_REPLY,
-	ETHTOOL_MSG_PLCA_GET_STATUS_REPLY,
-	ETHTOOL_MSG_PLCA_NTF,
-	ETHTOOL_MSG_MM_GET_REPLY,
-	ETHTOOL_MSG_MM_NTF,
-	ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
-	ETHTOOL_MSG_PHY_GET_REPLY,
-	ETHTOOL_MSG_PHY_NTF,
-
-	/* add new constants above here */
-	__ETHTOOL_MSG_KERNEL_CNT,
-	ETHTOOL_MSG_KERNEL_MAX = __ETHTOOL_MSG_KERNEL_CNT - 1
-};
-
-/* request header */
-
-enum ethtool_header_flags {
-	ETHTOOL_FLAG_COMPACT_BITSETS	= 1 << 0,	/* use compact bitsets in reply */
-	ETHTOOL_FLAG_OMIT_REPLY		= 1 << 1,	/* provide optional reply for SET or ACT requests */
-	ETHTOOL_FLAG_STATS		= 1 << 2,	/* request statistics, if supported by the driver */
-};
+#include <linux/ethtool_netlink_generated.h>
 
 #define ETHTOOL_FLAG_ALL (ETHTOOL_FLAG_COMPACT_BITSETS | \
 			  ETHTOOL_FLAG_OMIT_REPLY | \
 			  ETHTOOL_FLAG_STATS)
 
-enum {
-	ETHTOOL_A_HEADER_UNSPEC,
-	ETHTOOL_A_HEADER_DEV_INDEX,		/* u32 */
-	ETHTOOL_A_HEADER_DEV_NAME,		/* string */
-	ETHTOOL_A_HEADER_FLAGS,			/* u32 - ETHTOOL_FLAG_* */
-	ETHTOOL_A_HEADER_PHY_INDEX,		/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_HEADER_CNT,
-	ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
-};
-
-/* bit sets */
-
-enum {
-	ETHTOOL_A_BITSET_BIT_UNSPEC,
-	ETHTOOL_A_BITSET_BIT_INDEX,		/* u32 */
-	ETHTOOL_A_BITSET_BIT_NAME,		/* string */
-	ETHTOOL_A_BITSET_BIT_VALUE,		/* flag */
-
-	/* add new constants above here */
-	__ETHTOOL_A_BITSET_BIT_CNT,
-	ETHTOOL_A_BITSET_BIT_MAX = __ETHTOOL_A_BITSET_BIT_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_BITSET_BITS_UNSPEC,
-	ETHTOOL_A_BITSET_BITS_BIT,		/* nest - _A_BITSET_BIT_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_BITSET_BITS_CNT,
-	ETHTOOL_A_BITSET_BITS_MAX = __ETHTOOL_A_BITSET_BITS_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_BITSET_UNSPEC,
-	ETHTOOL_A_BITSET_NOMASK,		/* flag */
-	ETHTOOL_A_BITSET_SIZE,			/* u32 */
-	ETHTOOL_A_BITSET_BITS,			/* nest - _A_BITSET_BITS_* */
-	ETHTOOL_A_BITSET_VALUE,			/* binary */
-	ETHTOOL_A_BITSET_MASK,			/* binary */
-
-	/* add new constants above here */
-	__ETHTOOL_A_BITSET_CNT,
-	ETHTOOL_A_BITSET_MAX = __ETHTOOL_A_BITSET_CNT - 1
-};
-
-/* string sets */
-
-enum {
-	ETHTOOL_A_STRING_UNSPEC,
-	ETHTOOL_A_STRING_INDEX,			/* u32 */
-	ETHTOOL_A_STRING_VALUE,			/* string */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STRING_CNT,
-	ETHTOOL_A_STRING_MAX = __ETHTOOL_A_STRING_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_STRINGS_UNSPEC,
-	ETHTOOL_A_STRINGS_STRING,		/* nest - _A_STRINGS_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STRINGS_CNT,
-	ETHTOOL_A_STRINGS_MAX = __ETHTOOL_A_STRINGS_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_STRINGSET_UNSPEC,
-	ETHTOOL_A_STRINGSET_ID,			/* u32 */
-	ETHTOOL_A_STRINGSET_COUNT,		/* u32 */
-	ETHTOOL_A_STRINGSET_STRINGS,		/* nest - _A_STRINGS_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STRINGSET_CNT,
-	ETHTOOL_A_STRINGSET_MAX = __ETHTOOL_A_STRINGSET_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_STRINGSETS_UNSPEC,
-	ETHTOOL_A_STRINGSETS_STRINGSET,		/* nest - _A_STRINGSET_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STRINGSETS_CNT,
-	ETHTOOL_A_STRINGSETS_MAX = __ETHTOOL_A_STRINGSETS_CNT - 1
-};
-
-/* STRSET */
-
-enum {
-	ETHTOOL_A_STRSET_UNSPEC,
-	ETHTOOL_A_STRSET_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_STRSET_STRINGSETS,		/* nest - _A_STRINGSETS_* */
-	ETHTOOL_A_STRSET_COUNTS_ONLY,		/* flag */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STRSET_CNT,
-	ETHTOOL_A_STRSET_MAX = __ETHTOOL_A_STRSET_CNT - 1
-};
-
-/* LINKINFO */
-
-enum {
-	ETHTOOL_A_LINKINFO_UNSPEC,
-	ETHTOOL_A_LINKINFO_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_LINKINFO_PORT,		/* u8 */
-	ETHTOOL_A_LINKINFO_PHYADDR,		/* u8 */
-	ETHTOOL_A_LINKINFO_TP_MDIX,		/* u8 */
-	ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,	/* u8 */
-	ETHTOOL_A_LINKINFO_TRANSCEIVER,		/* u8 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_LINKINFO_CNT,
-	ETHTOOL_A_LINKINFO_MAX = __ETHTOOL_A_LINKINFO_CNT - 1
-};
-
-/* LINKMODES */
-
-enum {
-	ETHTOOL_A_LINKMODES_UNSPEC,
-	ETHTOOL_A_LINKMODES_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_LINKMODES_AUTONEG,		/* u8 */
-	ETHTOOL_A_LINKMODES_OURS,		/* bitset */
-	ETHTOOL_A_LINKMODES_PEER,		/* bitset */
-	ETHTOOL_A_LINKMODES_SPEED,		/* u32 */
-	ETHTOOL_A_LINKMODES_DUPLEX,		/* u8 */
-	ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,	/* u8 */
-	ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE,	/* u8 */
-	ETHTOOL_A_LINKMODES_LANES,		/* u32 */
-	ETHTOOL_A_LINKMODES_RATE_MATCHING,	/* u8 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_LINKMODES_CNT,
-	ETHTOOL_A_LINKMODES_MAX = __ETHTOOL_A_LINKMODES_CNT - 1
-};
-
-/* LINKSTATE */
-
-enum {
-	ETHTOOL_A_LINKSTATE_UNSPEC,
-	ETHTOOL_A_LINKSTATE_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_LINKSTATE_LINK,		/* u8 */
-	ETHTOOL_A_LINKSTATE_SQI,		/* u32 */
-	ETHTOOL_A_LINKSTATE_SQI_MAX,		/* u32 */
-	ETHTOOL_A_LINKSTATE_EXT_STATE,		/* u8 */
-	ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,	/* u8 */
-	ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,	/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_LINKSTATE_CNT,
-	ETHTOOL_A_LINKSTATE_MAX = __ETHTOOL_A_LINKSTATE_CNT - 1
-};
-
-/* DEBUG */
-
-enum {
-	ETHTOOL_A_DEBUG_UNSPEC,
-	ETHTOOL_A_DEBUG_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_DEBUG_MSGMASK,		/* bitset */
-
-	/* add new constants above here */
-	__ETHTOOL_A_DEBUG_CNT,
-	ETHTOOL_A_DEBUG_MAX = __ETHTOOL_A_DEBUG_CNT - 1
-};
-
-/* WOL */
-
-enum {
-	ETHTOOL_A_WOL_UNSPEC,
-	ETHTOOL_A_WOL_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_WOL_MODES,			/* bitset */
-	ETHTOOL_A_WOL_SOPASS,			/* binary */
-
-	/* add new constants above here */
-	__ETHTOOL_A_WOL_CNT,
-	ETHTOOL_A_WOL_MAX = __ETHTOOL_A_WOL_CNT - 1
-};
-
-/* FEATURES */
-
-enum {
-	ETHTOOL_A_FEATURES_UNSPEC,
-	ETHTOOL_A_FEATURES_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_FEATURES_HW,				/* bitset */
-	ETHTOOL_A_FEATURES_WANTED,			/* bitset */
-	ETHTOOL_A_FEATURES_ACTIVE,			/* bitset */
-	ETHTOOL_A_FEATURES_NOCHANGE,			/* bitset */
-
-	/* add new constants above here */
-	__ETHTOOL_A_FEATURES_CNT,
-	ETHTOOL_A_FEATURES_MAX = __ETHTOOL_A_FEATURES_CNT - 1
-};
-
-/* PRIVFLAGS */
-
-enum {
-	ETHTOOL_A_PRIVFLAGS_UNSPEC,
-	ETHTOOL_A_PRIVFLAGS_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_PRIVFLAGS_FLAGS,			/* bitset */
-
-	/* add new constants above here */
-	__ETHTOOL_A_PRIVFLAGS_CNT,
-	ETHTOOL_A_PRIVFLAGS_MAX = __ETHTOOL_A_PRIVFLAGS_CNT - 1
-};
-
-/* RINGS */
-
-enum {
-	ETHTOOL_TCP_DATA_SPLIT_UNKNOWN = 0,
-	ETHTOOL_TCP_DATA_SPLIT_DISABLED,
-	ETHTOOL_TCP_DATA_SPLIT_ENABLED,
-};
-
-enum {
-	ETHTOOL_A_RINGS_UNSPEC,
-	ETHTOOL_A_RINGS_HEADER,				/* nest - _A_HEADER_* */
-	ETHTOOL_A_RINGS_RX_MAX,				/* u32 */
-	ETHTOOL_A_RINGS_RX_MINI_MAX,			/* u32 */
-	ETHTOOL_A_RINGS_RX_JUMBO_MAX,			/* u32 */
-	ETHTOOL_A_RINGS_TX_MAX,				/* u32 */
-	ETHTOOL_A_RINGS_RX,				/* u32 */
-	ETHTOOL_A_RINGS_RX_MINI,			/* u32 */
-	ETHTOOL_A_RINGS_RX_JUMBO,			/* u32 */
-	ETHTOOL_A_RINGS_TX,				/* u32 */
-	ETHTOOL_A_RINGS_RX_BUF_LEN,                     /* u32 */
-	ETHTOOL_A_RINGS_TCP_DATA_SPLIT,			/* u8 */
-	ETHTOOL_A_RINGS_CQE_SIZE,			/* u32 */
-	ETHTOOL_A_RINGS_TX_PUSH,			/* u8 */
-	ETHTOOL_A_RINGS_RX_PUSH,			/* u8 */
-	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,		/* u32 */
-	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,		/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_RINGS_CNT,
-	ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
-};
-
-/* CHANNELS */
-
-enum {
-	ETHTOOL_A_CHANNELS_UNSPEC,
-	ETHTOOL_A_CHANNELS_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_CHANNELS_RX_MAX,			/* u32 */
-	ETHTOOL_A_CHANNELS_TX_MAX,			/* u32 */
-	ETHTOOL_A_CHANNELS_OTHER_MAX,			/* u32 */
-	ETHTOOL_A_CHANNELS_COMBINED_MAX,		/* u32 */
-	ETHTOOL_A_CHANNELS_RX_COUNT,			/* u32 */
-	ETHTOOL_A_CHANNELS_TX_COUNT,			/* u32 */
-	ETHTOOL_A_CHANNELS_OTHER_COUNT,			/* u32 */
-	ETHTOOL_A_CHANNELS_COMBINED_COUNT,		/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_CHANNELS_CNT,
-	ETHTOOL_A_CHANNELS_MAX = (__ETHTOOL_A_CHANNELS_CNT - 1)
-};
-
-/* COALESCE */
-
-enum {
-	ETHTOOL_A_COALESCE_UNSPEC,
-	ETHTOOL_A_COALESCE_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_COALESCE_RX_USECS,			/* u32 */
-	ETHTOOL_A_COALESCE_RX_MAX_FRAMES,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_USECS_IRQ,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_USECS,			/* u32 */
-	ETHTOOL_A_COALESCE_TX_MAX_FRAMES,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_USECS_IRQ,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ,		/* u32 */
-	ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,		/* u32 */
-	ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX,		/* u8 */
-	ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX,		/* u8 */
-	ETHTOOL_A_COALESCE_PKT_RATE_LOW,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_USECS_LOW,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_USECS_LOW,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW,		/* u32 */
-	ETHTOOL_A_COALESCE_PKT_RATE_HIGH,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_USECS_HIGH,		/* u32 */
-	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_USECS_HIGH,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH,		/* u32 */
-	ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,	/* u32 */
-	ETHTOOL_A_COALESCE_USE_CQE_MODE_TX,		/* u8 */
-	ETHTOOL_A_COALESCE_USE_CQE_MODE_RX,		/* u8 */
-	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,		/* u32 */
-	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,		/* u32 */
-	/* nest - _A_PROFILE_IRQ_MODERATION */
-	ETHTOOL_A_COALESCE_RX_PROFILE,
-	/* nest - _A_PROFILE_IRQ_MODERATION */
-	ETHTOOL_A_COALESCE_TX_PROFILE,
-
-	/* add new constants above here */
-	__ETHTOOL_A_COALESCE_CNT,
-	ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_PROFILE_UNSPEC,
-	/* nest, _A_IRQ_MODERATION_* */
-	ETHTOOL_A_PROFILE_IRQ_MODERATION,
-	__ETHTOOL_A_PROFILE_CNT,
-	ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_IRQ_MODERATION_UNSPEC,
-	ETHTOOL_A_IRQ_MODERATION_USEC,			/* u32 */
-	ETHTOOL_A_IRQ_MODERATION_PKTS,			/* u32 */
-	ETHTOOL_A_IRQ_MODERATION_COMPS,			/* u32 */
-
-	__ETHTOOL_A_IRQ_MODERATION_CNT,
-	ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
-};
-
-/* PAUSE */
-
-enum {
-	ETHTOOL_A_PAUSE_UNSPEC,
-	ETHTOOL_A_PAUSE_HEADER,				/* nest - _A_HEADER_* */
-	ETHTOOL_A_PAUSE_AUTONEG,			/* u8 */
-	ETHTOOL_A_PAUSE_RX,				/* u8 */
-	ETHTOOL_A_PAUSE_TX,				/* u8 */
-	ETHTOOL_A_PAUSE_STATS,				/* nest - _PAUSE_STAT_* */
-	ETHTOOL_A_PAUSE_STATS_SRC,			/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_PAUSE_CNT,
-	ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_PAUSE_STAT_UNSPEC,
-	ETHTOOL_A_PAUSE_STAT_PAD,
-
-	ETHTOOL_A_PAUSE_STAT_TX_FRAMES,
-	ETHTOOL_A_PAUSE_STAT_RX_FRAMES,
-
-	/* add new constants above here
-	 * adjust ETHTOOL_PAUSE_STAT_CNT if adding non-stats!
-	 */
-	__ETHTOOL_A_PAUSE_STAT_CNT,
-	ETHTOOL_A_PAUSE_STAT_MAX = (__ETHTOOL_A_PAUSE_STAT_CNT - 1)
-};
-
-/* EEE */
-
-enum {
-	ETHTOOL_A_EEE_UNSPEC,
-	ETHTOOL_A_EEE_HEADER,				/* nest - _A_HEADER_* */
-	ETHTOOL_A_EEE_MODES_OURS,			/* bitset */
-	ETHTOOL_A_EEE_MODES_PEER,			/* bitset */
-	ETHTOOL_A_EEE_ACTIVE,				/* u8 */
-	ETHTOOL_A_EEE_ENABLED,				/* u8 */
-	ETHTOOL_A_EEE_TX_LPI_ENABLED,			/* u8 */
-	ETHTOOL_A_EEE_TX_LPI_TIMER,			/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_EEE_CNT,
-	ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
-};
-
-/* TSINFO */
-
-enum {
-	ETHTOOL_A_TSINFO_UNSPEC,
-	ETHTOOL_A_TSINFO_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_TSINFO_TIMESTAMPING,			/* bitset */
-	ETHTOOL_A_TSINFO_TX_TYPES,			/* bitset */
-	ETHTOOL_A_TSINFO_RX_FILTERS,			/* bitset */
-	ETHTOOL_A_TSINFO_PHC_INDEX,			/* u32 */
-	ETHTOOL_A_TSINFO_STATS,				/* nest - _A_TSINFO_STAT */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TSINFO_CNT,
-	ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_TS_STAT_UNSPEC,
-
-	ETHTOOL_A_TS_STAT_TX_PKTS,			/* uint */
-	ETHTOOL_A_TS_STAT_TX_LOST,			/* uint */
-	ETHTOOL_A_TS_STAT_TX_ERR,			/* uint */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TS_STAT_CNT,
-	ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
-
-};
-
-/* PHC VCLOCKS */
-
-enum {
-	ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
-	ETHTOOL_A_PHC_VCLOCKS_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_PHC_VCLOCKS_NUM,			/* u32 */
-	ETHTOOL_A_PHC_VCLOCKS_INDEX,			/* array, s32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_PHC_VCLOCKS_CNT,
-	ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
-};
-
-/* CABLE TEST */
-
-enum {
-	ETHTOOL_A_CABLE_TEST_UNSPEC,
-	ETHTOOL_A_CABLE_TEST_HEADER,		/* nest - _A_HEADER_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_CABLE_TEST_CNT,
-	ETHTOOL_A_CABLE_TEST_MAX = __ETHTOOL_A_CABLE_TEST_CNT - 1
-};
-
 /* CABLE TEST NOTIFY */
 enum {
 	ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,
@@ -582,74 +49,12 @@ enum {
 	ETHTOOL_A_CABLE_INF_SRC_ALCD,
 };
 
-enum {
-	ETHTOOL_A_CABLE_RESULT_UNSPEC,
-	ETHTOOL_A_CABLE_RESULT_PAIR,		/* u8 ETHTOOL_A_CABLE_PAIR_ */
-	ETHTOOL_A_CABLE_RESULT_CODE,		/* u8 ETHTOOL_A_CABLE_RESULT_CODE_ */
-	ETHTOOL_A_CABLE_RESULT_SRC,		/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
-
-	__ETHTOOL_A_CABLE_RESULT_CNT,
-	ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
-	ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,	/* u8 ETHTOOL_A_CABLE_PAIR_ */
-	ETHTOOL_A_CABLE_FAULT_LENGTH_CM,	/* u32 */
-	ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,	/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
-
-	__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
-	ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
-};
-
 enum {
 	ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC,
 	ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED,
 	ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED
 };
 
-enum {
-	ETHTOOL_A_CABLE_NEST_UNSPEC,
-	ETHTOOL_A_CABLE_NEST_RESULT,		/* nest - ETHTOOL_A_CABLE_RESULT_ */
-	ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,	/* nest - ETHTOOL_A_CABLE_FAULT_LENGTH_ */
-	__ETHTOOL_A_CABLE_NEST_CNT,
-	ETHTOOL_A_CABLE_NEST_MAX = (__ETHTOOL_A_CABLE_NEST_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_CABLE_TEST_NTF_UNSPEC,
-	ETHTOOL_A_CABLE_TEST_NTF_HEADER,	/* nest - ETHTOOL_A_HEADER_* */
-	ETHTOOL_A_CABLE_TEST_NTF_STATUS,	/* u8 - _STARTED/_COMPLETE */
-	ETHTOOL_A_CABLE_TEST_NTF_NEST,		/* nest - of results: */
-
-	__ETHTOOL_A_CABLE_TEST_NTF_CNT,
-	ETHTOOL_A_CABLE_TEST_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_NTF_CNT - 1)
-};
-
-/* CABLE TEST TDR */
-
-enum {
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC,
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST,		/* u32 */
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST,		/* u32 */
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP,		/* u32 */
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR,		/* u8 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT,
-	ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT - 1
-};
-
-enum {
-	ETHTOOL_A_CABLE_TEST_TDR_UNSPEC,
-	ETHTOOL_A_CABLE_TEST_TDR_HEADER,	/* nest - _A_HEADER_* */
-	ETHTOOL_A_CABLE_TEST_TDR_CFG,		/* nest - *_TDR_CFG_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_CABLE_TEST_TDR_CNT,
-	ETHTOOL_A_CABLE_TEST_TDR_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CNT - 1
-};
-
 /* CABLE TEST TDR NOTIFY */
 
 enum {
@@ -689,163 +94,17 @@ enum {
 	ETHTOOL_A_CABLE_TDR_NEST_MAX = (__ETHTOOL_A_CABLE_TDR_NEST_CNT - 1)
 };
 
-enum {
-	ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC,
-	ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER,	/* nest - ETHTOOL_A_HEADER_* */
-	ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS,	/* u8 - _STARTED/_COMPLETE */
-	ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,	/* nest - of results: */
-
-	/* add new constants above here */
-	__ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT,
-	ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX = __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT - 1
-};
-
-/* TUNNEL INFO */
-
-enum {
-	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN,
-	ETHTOOL_UDP_TUNNEL_TYPE_GENEVE,
-	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE,
-
-	__ETHTOOL_UDP_TUNNEL_TYPE_CNT
-};
-
-enum {
-	ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC,
-
-	ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT,		/* be16 */
-	ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE,		/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT,
-	ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX = (__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC,
-
-	ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE,		/* u32 */
-	ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES,		/* bitset */
-	ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY,		/* nest - _UDP_ENTRY_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT,
-	ETHTOOL_A_TUNNEL_UDP_TABLE_MAX = (__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_TUNNEL_UDP_UNSPEC,
-
-	ETHTOOL_A_TUNNEL_UDP_TABLE,			/* nest - _UDP_TABLE_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TUNNEL_UDP_CNT,
-	ETHTOOL_A_TUNNEL_UDP_MAX = (__ETHTOOL_A_TUNNEL_UDP_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_TUNNEL_INFO_UNSPEC,
-	ETHTOOL_A_TUNNEL_INFO_HEADER,			/* nest - _A_HEADER_* */
-
-	ETHTOOL_A_TUNNEL_INFO_UDP_PORTS,		/* nest - _UDP_TABLE */
-
-	/* add new constants above here */
-	__ETHTOOL_A_TUNNEL_INFO_CNT,
-	ETHTOOL_A_TUNNEL_INFO_MAX = (__ETHTOOL_A_TUNNEL_INFO_CNT - 1)
-};
-
-/* FEC */
-
-enum {
-	ETHTOOL_A_FEC_UNSPEC,
-	ETHTOOL_A_FEC_HEADER,				/* nest - _A_HEADER_* */
-	ETHTOOL_A_FEC_MODES,				/* bitset */
-	ETHTOOL_A_FEC_AUTO,				/* u8 */
-	ETHTOOL_A_FEC_ACTIVE,				/* u32 */
-	ETHTOOL_A_FEC_STATS,				/* nest - _A_FEC_STAT */
-
-	__ETHTOOL_A_FEC_CNT,
-	ETHTOOL_A_FEC_MAX = (__ETHTOOL_A_FEC_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_FEC_STAT_UNSPEC,
-	ETHTOOL_A_FEC_STAT_PAD,
-
-	ETHTOOL_A_FEC_STAT_CORRECTED,			/* array, u64 */
-	ETHTOOL_A_FEC_STAT_UNCORR,			/* array, u64 */
-	ETHTOOL_A_FEC_STAT_CORR_BITS,			/* array, u64 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_FEC_STAT_CNT,
-	ETHTOOL_A_FEC_STAT_MAX = (__ETHTOOL_A_FEC_STAT_CNT - 1)
-};
-
-/* MODULE EEPROM */
-
-enum {
-	ETHTOOL_A_MODULE_EEPROM_UNSPEC,
-	ETHTOOL_A_MODULE_EEPROM_HEADER,			/* nest - _A_HEADER_* */
-
-	ETHTOOL_A_MODULE_EEPROM_OFFSET,			/* u32 */
-	ETHTOOL_A_MODULE_EEPROM_LENGTH,			/* u32 */
-	ETHTOOL_A_MODULE_EEPROM_PAGE,			/* u8 */
-	ETHTOOL_A_MODULE_EEPROM_BANK,			/* u8 */
-	ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS,		/* u8 */
-	ETHTOOL_A_MODULE_EEPROM_DATA,			/* binary */
-
-	__ETHTOOL_A_MODULE_EEPROM_CNT,
-	ETHTOOL_A_MODULE_EEPROM_MAX = (__ETHTOOL_A_MODULE_EEPROM_CNT - 1)
-};
-
-/* STATS */
-
-enum {
-	ETHTOOL_A_STATS_UNSPEC,
-	ETHTOOL_A_STATS_PAD,
-	ETHTOOL_A_STATS_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_STATS_GROUPS,			/* bitset */
-
-	ETHTOOL_A_STATS_GRP,			/* nest - _A_STATS_GRP_* */
-
-	ETHTOOL_A_STATS_SRC,			/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STATS_CNT,
-	ETHTOOL_A_STATS_MAX = (__ETHTOOL_A_STATS_CNT - 1)
-};
-
 enum {
 	ETHTOOL_STATS_ETH_PHY,
 	ETHTOOL_STATS_ETH_MAC,
 	ETHTOOL_STATS_ETH_CTRL,
 	ETHTOOL_STATS_RMON,
+	ETHTOOL_STATS_PHY,
 
 	/* add new constants above here */
 	__ETHTOOL_STATS_CNT
 };
 
-enum {
-	ETHTOOL_A_STATS_GRP_UNSPEC,
-	ETHTOOL_A_STATS_GRP_PAD,
-
-	ETHTOOL_A_STATS_GRP_ID,			/* u32 */
-	ETHTOOL_A_STATS_GRP_SS_ID,		/* u32 */
-
-	ETHTOOL_A_STATS_GRP_STAT,		/* nest */
-
-	ETHTOOL_A_STATS_GRP_HIST_RX,		/* nest */
-	ETHTOOL_A_STATS_GRP_HIST_TX,		/* nest */
-
-	ETHTOOL_A_STATS_GRP_HIST_BKT_LOW,	/* u32 */
-	ETHTOOL_A_STATS_GRP_HIST_BKT_HI,	/* u32 */
-	ETHTOOL_A_STATS_GRP_HIST_VAL,		/* u64 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_STATS_GRP_CNT,
-	ETHTOOL_A_STATS_GRP_MAX = (__ETHTOOL_A_STATS_GRP_CNT - 1)
-};
-
 enum {
 	/* 30.3.2.1.5 aSymbolErrorDuringCarrier */
 	ETHTOOL_A_STATS_ETH_PHY_5_SYM_ERR,
@@ -935,154 +194,18 @@ enum {
 	ETHTOOL_A_STATS_RMON_MAX = (__ETHTOOL_A_STATS_RMON_CNT - 1)
 };
 
-/* MODULE */
-
-enum {
-	ETHTOOL_A_MODULE_UNSPEC,
-	ETHTOOL_A_MODULE_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_MODULE_POWER_MODE_POLICY,	/* u8 */
-	ETHTOOL_A_MODULE_POWER_MODE,		/* u8 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_MODULE_CNT,
-	ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
-};
-
-/* Power Sourcing Equipment */
-enum {
-	ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
-	ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,	/* u32 */
-	ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,	/* u32 */
-};
-
-enum {
-	ETHTOOL_A_PSE_UNSPEC,
-	ETHTOOL_A_PSE_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_PODL_PSE_ADMIN_STATE,		/* u32 */
-	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,	/* u32 */
-	ETHTOOL_A_PODL_PSE_PW_D_STATUS,		/* u32 */
-	ETHTOOL_A_C33_PSE_ADMIN_STATE,		/* u32 */
-	ETHTOOL_A_C33_PSE_ADMIN_CONTROL,	/* u32 */
-	ETHTOOL_A_C33_PSE_PW_D_STATUS,		/* u32 */
-	ETHTOOL_A_C33_PSE_PW_CLASS,		/* u32 */
-	ETHTOOL_A_C33_PSE_ACTUAL_PW,		/* u32 */
-	ETHTOOL_A_C33_PSE_EXT_STATE,		/* u32 */
-	ETHTOOL_A_C33_PSE_EXT_SUBSTATE,		/* u32 */
-	ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,	/* u32 */
-	ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,	/* nest - _C33_PSE_PW_LIMIT_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_PSE_CNT,
-	ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_RSS_UNSPEC,
-	ETHTOOL_A_RSS_HEADER,
-	ETHTOOL_A_RSS_CONTEXT,		/* u32 */
-	ETHTOOL_A_RSS_HFUNC,		/* u32 */
-	ETHTOOL_A_RSS_INDIR,		/* binary */
-	ETHTOOL_A_RSS_HKEY,		/* binary */
-	ETHTOOL_A_RSS_INPUT_XFRM,	/* u32 */
-	ETHTOOL_A_RSS_START_CONTEXT,	/* u32 */
-
-	__ETHTOOL_A_RSS_CNT,
-	ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
-};
-
-/* PLCA */
-
-enum {
-	ETHTOOL_A_PLCA_UNSPEC,
-	ETHTOOL_A_PLCA_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_PLCA_VERSION,			/* u16 */
-	ETHTOOL_A_PLCA_ENABLED,			/* u8  */
-	ETHTOOL_A_PLCA_STATUS,			/* u8  */
-	ETHTOOL_A_PLCA_NODE_CNT,		/* u32 */
-	ETHTOOL_A_PLCA_NODE_ID,			/* u32 */
-	ETHTOOL_A_PLCA_TO_TMR,			/* u32 */
-	ETHTOOL_A_PLCA_BURST_CNT,		/* u32 */
-	ETHTOOL_A_PLCA_BURST_TMR,		/* u32 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_PLCA_CNT,
-	ETHTOOL_A_PLCA_MAX = (__ETHTOOL_A_PLCA_CNT - 1)
-};
-
-/* MAC Merge (802.3) */
-
-enum {
-	ETHTOOL_A_MM_STAT_UNSPEC,
-	ETHTOOL_A_MM_STAT_PAD,
-
-	/* aMACMergeFrameAssErrorCount */
-	ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,	/* u64 */
-	/* aMACMergeFrameSmdErrorCount */
-	ETHTOOL_A_MM_STAT_SMD_ERRORS,		/* u64 */
-	/* aMACMergeFrameAssOkCount */
-	ETHTOOL_A_MM_STAT_REASSEMBLY_OK,	/* u64 */
-	/* aMACMergeFragCountRx */
-	ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,	/* u64 */
-	/* aMACMergeFragCountTx */
-	ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,	/* u64 */
-	/* aMACMergeHoldCount */
-	ETHTOOL_A_MM_STAT_HOLD_COUNT,		/* u64 */
-
-	/* add new constants above here */
-	__ETHTOOL_A_MM_STAT_CNT,
-	ETHTOOL_A_MM_STAT_MAX = (__ETHTOOL_A_MM_STAT_CNT - 1)
-};
-
-enum {
-	ETHTOOL_A_MM_UNSPEC,
-	ETHTOOL_A_MM_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_MM_PMAC_ENABLED,		/* u8 */
-	ETHTOOL_A_MM_TX_ENABLED,		/* u8 */
-	ETHTOOL_A_MM_TX_ACTIVE,			/* u8 */
-	ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,		/* u32 */
-	ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,		/* u32 */
-	ETHTOOL_A_MM_VERIFY_ENABLED,		/* u8 */
-	ETHTOOL_A_MM_VERIFY_STATUS,		/* u8 */
-	ETHTOOL_A_MM_VERIFY_TIME,		/* u32 */
-	ETHTOOL_A_MM_MAX_VERIFY_TIME,		/* u32 */
-	ETHTOOL_A_MM_STATS,			/* nest - _A_MM_STAT_* */
-
-	/* add new constants above here */
-	__ETHTOOL_A_MM_CNT,
-	ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
-};
-
-/* MODULE_FW_FLASH */
-
-enum {
-	ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
-	ETHTOOL_A_MODULE_FW_FLASH_HEADER,		/* nest - _A_HEADER_* */
-	ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,		/* string */
-	ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,		/* u32 */
-	ETHTOOL_A_MODULE_FW_FLASH_STATUS,		/* u32 */
-	ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,		/* string */
-	ETHTOOL_A_MODULE_FW_FLASH_DONE,			/* uint */
-	ETHTOOL_A_MODULE_FW_FLASH_TOTAL,		/* uint */
-
-	/* add new constants above here */
-	__ETHTOOL_A_MODULE_FW_FLASH_CNT,
-	ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
-};
-
 enum {
-	ETHTOOL_A_PHY_UNSPEC,
-	ETHTOOL_A_PHY_HEADER,			/* nest - _A_HEADER_* */
-	ETHTOOL_A_PHY_INDEX,			/* u32 */
-	ETHTOOL_A_PHY_DRVNAME,			/* string */
-	ETHTOOL_A_PHY_NAME,			/* string */
-	ETHTOOL_A_PHY_UPSTREAM_TYPE,		/* u32 */
-	ETHTOOL_A_PHY_UPSTREAM_INDEX,		/* u32 */
-	ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,	/* string */
-	ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,	/* string */
+	/* Basic packet counters if PHY has separate counters from the MAC */
+	ETHTOOL_A_STATS_PHY_RX_PKTS,
+	ETHTOOL_A_STATS_PHY_RX_BYTES,
+	ETHTOOL_A_STATS_PHY_RX_ERRORS,
+	ETHTOOL_A_STATS_PHY_TX_PKTS,
+	ETHTOOL_A_STATS_PHY_TX_BYTES,
+	ETHTOOL_A_STATS_PHY_TX_ERRORS,
 
 	/* add new constants above here */
-	__ETHTOOL_A_PHY_CNT,
-	ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+	__ETHTOOL_A_STATS_PHY_CNT,
+	ETHTOOL_A_STATS_PHY_MAX = (__ETHTOOL_A_STATS_PHY_CNT - 1)
 };
 
 /* generic netlink info */
diff --git a/original/uapi/linux/ethtool_netlink_generated.h b/original/uapi/linux/ethtool_netlink_generated.h
new file mode 100644
index 0000000..fe24c34
--- /dev/null
+++ b/original/uapi/linux/ethtool_netlink_generated.h
@@ -0,0 +1,821 @@
+/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
+/* Do not edit directly, auto-generated from: */
+/*	Documentation/netlink/specs/ethtool.yaml */
+/* YNL-GEN uapi header */
+
+#ifndef _UAPI_LINUX_ETHTOOL_NETLINK_GENERATED_H
+#define _UAPI_LINUX_ETHTOOL_NETLINK_GENERATED_H
+
+#define ETHTOOL_FAMILY_NAME	"ethtool"
+#define ETHTOOL_FAMILY_VERSION	1
+
+enum {
+	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN,
+	ETHTOOL_UDP_TUNNEL_TYPE_GENEVE,
+	ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE,
+
+	/* private: */
+	__ETHTOOL_UDP_TUNNEL_TYPE_CNT,
+	ETHTOOL_UDP_TUNNEL_TYPE_MAX = (__ETHTOOL_UDP_TUNNEL_TYPE_CNT - 1)
+};
+
+/**
+ * enum ethtool_header_flags - common ethtool header flags
+ * @ETHTOOL_FLAG_COMPACT_BITSETS: use compact bitsets in reply
+ * @ETHTOOL_FLAG_OMIT_REPLY: provide optional reply for SET or ACT requests
+ * @ETHTOOL_FLAG_STATS: request statistics, if supported by the driver
+ */
+enum ethtool_header_flags {
+	ETHTOOL_FLAG_COMPACT_BITSETS = 1,
+	ETHTOOL_FLAG_OMIT_REPLY = 2,
+	ETHTOOL_FLAG_STATS = 4,
+};
+
+enum {
+	ETHTOOL_PHY_UPSTREAM_TYPE_MAC,
+	ETHTOOL_PHY_UPSTREAM_TYPE_PHY,
+};
+
+enum ethtool_tcp_data_split {
+	ETHTOOL_TCP_DATA_SPLIT_UNKNOWN,
+	ETHTOOL_TCP_DATA_SPLIT_DISABLED,
+	ETHTOOL_TCP_DATA_SPLIT_ENABLED,
+};
+
+enum {
+	ETHTOOL_A_HEADER_UNSPEC,
+	ETHTOOL_A_HEADER_DEV_INDEX,
+	ETHTOOL_A_HEADER_DEV_NAME,
+	ETHTOOL_A_HEADER_FLAGS,
+	ETHTOOL_A_HEADER_PHY_INDEX,
+
+	__ETHTOOL_A_HEADER_CNT,
+	ETHTOOL_A_HEADER_MAX = (__ETHTOOL_A_HEADER_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_BITSET_BIT_UNSPEC,
+	ETHTOOL_A_BITSET_BIT_INDEX,
+	ETHTOOL_A_BITSET_BIT_NAME,
+	ETHTOOL_A_BITSET_BIT_VALUE,
+
+	__ETHTOOL_A_BITSET_BIT_CNT,
+	ETHTOOL_A_BITSET_BIT_MAX = (__ETHTOOL_A_BITSET_BIT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_BITSET_BITS_UNSPEC,
+	ETHTOOL_A_BITSET_BITS_BIT,
+
+	__ETHTOOL_A_BITSET_BITS_CNT,
+	ETHTOOL_A_BITSET_BITS_MAX = (__ETHTOOL_A_BITSET_BITS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_BITSET_UNSPEC,
+	ETHTOOL_A_BITSET_NOMASK,
+	ETHTOOL_A_BITSET_SIZE,
+	ETHTOOL_A_BITSET_BITS,
+	ETHTOOL_A_BITSET_VALUE,
+	ETHTOOL_A_BITSET_MASK,
+
+	__ETHTOOL_A_BITSET_CNT,
+	ETHTOOL_A_BITSET_MAX = (__ETHTOOL_A_BITSET_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STRING_UNSPEC,
+	ETHTOOL_A_STRING_INDEX,
+	ETHTOOL_A_STRING_VALUE,
+
+	__ETHTOOL_A_STRING_CNT,
+	ETHTOOL_A_STRING_MAX = (__ETHTOOL_A_STRING_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STRINGS_UNSPEC,
+	ETHTOOL_A_STRINGS_STRING,
+
+	__ETHTOOL_A_STRINGS_CNT,
+	ETHTOOL_A_STRINGS_MAX = (__ETHTOOL_A_STRINGS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STRINGSET_UNSPEC,
+	ETHTOOL_A_STRINGSET_ID,
+	ETHTOOL_A_STRINGSET_COUNT,
+	ETHTOOL_A_STRINGSET_STRINGS,
+
+	__ETHTOOL_A_STRINGSET_CNT,
+	ETHTOOL_A_STRINGSET_MAX = (__ETHTOOL_A_STRINGSET_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STRINGSETS_UNSPEC,
+	ETHTOOL_A_STRINGSETS_STRINGSET,
+
+	__ETHTOOL_A_STRINGSETS_CNT,
+	ETHTOOL_A_STRINGSETS_MAX = (__ETHTOOL_A_STRINGSETS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STRSET_UNSPEC,
+	ETHTOOL_A_STRSET_HEADER,
+	ETHTOOL_A_STRSET_STRINGSETS,
+	ETHTOOL_A_STRSET_COUNTS_ONLY,
+
+	__ETHTOOL_A_STRSET_CNT,
+	ETHTOOL_A_STRSET_MAX = (__ETHTOOL_A_STRSET_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PRIVFLAGS_UNSPEC,
+	ETHTOOL_A_PRIVFLAGS_HEADER,
+	ETHTOOL_A_PRIVFLAGS_FLAGS,
+
+	__ETHTOOL_A_PRIVFLAGS_CNT,
+	ETHTOOL_A_PRIVFLAGS_MAX = (__ETHTOOL_A_PRIVFLAGS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_RINGS_UNSPEC,
+	ETHTOOL_A_RINGS_HEADER,
+	ETHTOOL_A_RINGS_RX_MAX,
+	ETHTOOL_A_RINGS_RX_MINI_MAX,
+	ETHTOOL_A_RINGS_RX_JUMBO_MAX,
+	ETHTOOL_A_RINGS_TX_MAX,
+	ETHTOOL_A_RINGS_RX,
+	ETHTOOL_A_RINGS_RX_MINI,
+	ETHTOOL_A_RINGS_RX_JUMBO,
+	ETHTOOL_A_RINGS_TX,
+	ETHTOOL_A_RINGS_RX_BUF_LEN,
+	ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
+	ETHTOOL_A_RINGS_CQE_SIZE,
+	ETHTOOL_A_RINGS_TX_PUSH,
+	ETHTOOL_A_RINGS_RX_PUSH,
+	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,
+	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,
+	ETHTOOL_A_RINGS_HDS_THRESH,
+	ETHTOOL_A_RINGS_HDS_THRESH_MAX,
+
+	__ETHTOOL_A_RINGS_CNT,
+	ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_MM_STAT_UNSPEC,
+	ETHTOOL_A_MM_STAT_PAD,
+	ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,
+	ETHTOOL_A_MM_STAT_SMD_ERRORS,
+	ETHTOOL_A_MM_STAT_REASSEMBLY_OK,
+	ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,
+	ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,
+	ETHTOOL_A_MM_STAT_HOLD_COUNT,
+
+	__ETHTOOL_A_MM_STAT_CNT,
+	ETHTOOL_A_MM_STAT_MAX = (__ETHTOOL_A_MM_STAT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_MM_UNSPEC,
+	ETHTOOL_A_MM_HEADER,
+	ETHTOOL_A_MM_PMAC_ENABLED,
+	ETHTOOL_A_MM_TX_ENABLED,
+	ETHTOOL_A_MM_TX_ACTIVE,
+	ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,
+	ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,
+	ETHTOOL_A_MM_VERIFY_ENABLED,
+	ETHTOOL_A_MM_VERIFY_STATUS,
+	ETHTOOL_A_MM_VERIFY_TIME,
+	ETHTOOL_A_MM_MAX_VERIFY_TIME,
+	ETHTOOL_A_MM_STATS,
+
+	__ETHTOOL_A_MM_CNT,
+	ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_LINKINFO_UNSPEC,
+	ETHTOOL_A_LINKINFO_HEADER,
+	ETHTOOL_A_LINKINFO_PORT,
+	ETHTOOL_A_LINKINFO_PHYADDR,
+	ETHTOOL_A_LINKINFO_TP_MDIX,
+	ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
+	ETHTOOL_A_LINKINFO_TRANSCEIVER,
+
+	__ETHTOOL_A_LINKINFO_CNT,
+	ETHTOOL_A_LINKINFO_MAX = (__ETHTOOL_A_LINKINFO_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_LINKMODES_UNSPEC,
+	ETHTOOL_A_LINKMODES_HEADER,
+	ETHTOOL_A_LINKMODES_AUTONEG,
+	ETHTOOL_A_LINKMODES_OURS,
+	ETHTOOL_A_LINKMODES_PEER,
+	ETHTOOL_A_LINKMODES_SPEED,
+	ETHTOOL_A_LINKMODES_DUPLEX,
+	ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,
+	ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE,
+	ETHTOOL_A_LINKMODES_LANES,
+	ETHTOOL_A_LINKMODES_RATE_MATCHING,
+
+	__ETHTOOL_A_LINKMODES_CNT,
+	ETHTOOL_A_LINKMODES_MAX = (__ETHTOOL_A_LINKMODES_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_LINKSTATE_UNSPEC,
+	ETHTOOL_A_LINKSTATE_HEADER,
+	ETHTOOL_A_LINKSTATE_LINK,
+	ETHTOOL_A_LINKSTATE_SQI,
+	ETHTOOL_A_LINKSTATE_SQI_MAX,
+	ETHTOOL_A_LINKSTATE_EXT_STATE,
+	ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
+	ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
+
+	__ETHTOOL_A_LINKSTATE_CNT,
+	ETHTOOL_A_LINKSTATE_MAX = (__ETHTOOL_A_LINKSTATE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_DEBUG_UNSPEC,
+	ETHTOOL_A_DEBUG_HEADER,
+	ETHTOOL_A_DEBUG_MSGMASK,
+
+	__ETHTOOL_A_DEBUG_CNT,
+	ETHTOOL_A_DEBUG_MAX = (__ETHTOOL_A_DEBUG_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_WOL_UNSPEC,
+	ETHTOOL_A_WOL_HEADER,
+	ETHTOOL_A_WOL_MODES,
+	ETHTOOL_A_WOL_SOPASS,
+
+	__ETHTOOL_A_WOL_CNT,
+	ETHTOOL_A_WOL_MAX = (__ETHTOOL_A_WOL_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_FEATURES_UNSPEC,
+	ETHTOOL_A_FEATURES_HEADER,
+	ETHTOOL_A_FEATURES_HW,
+	ETHTOOL_A_FEATURES_WANTED,
+	ETHTOOL_A_FEATURES_ACTIVE,
+	ETHTOOL_A_FEATURES_NOCHANGE,
+
+	__ETHTOOL_A_FEATURES_CNT,
+	ETHTOOL_A_FEATURES_MAX = (__ETHTOOL_A_FEATURES_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CHANNELS_UNSPEC,
+	ETHTOOL_A_CHANNELS_HEADER,
+	ETHTOOL_A_CHANNELS_RX_MAX,
+	ETHTOOL_A_CHANNELS_TX_MAX,
+	ETHTOOL_A_CHANNELS_OTHER_MAX,
+	ETHTOOL_A_CHANNELS_COMBINED_MAX,
+	ETHTOOL_A_CHANNELS_RX_COUNT,
+	ETHTOOL_A_CHANNELS_TX_COUNT,
+	ETHTOOL_A_CHANNELS_OTHER_COUNT,
+	ETHTOOL_A_CHANNELS_COMBINED_COUNT,
+
+	__ETHTOOL_A_CHANNELS_CNT,
+	ETHTOOL_A_CHANNELS_MAX = (__ETHTOOL_A_CHANNELS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_IRQ_MODERATION_UNSPEC,
+	ETHTOOL_A_IRQ_MODERATION_USEC,
+	ETHTOOL_A_IRQ_MODERATION_PKTS,
+	ETHTOOL_A_IRQ_MODERATION_COMPS,
+
+	__ETHTOOL_A_IRQ_MODERATION_CNT,
+	ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PROFILE_UNSPEC,
+	ETHTOOL_A_PROFILE_IRQ_MODERATION,
+
+	__ETHTOOL_A_PROFILE_CNT,
+	ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_COALESCE_UNSPEC,
+	ETHTOOL_A_COALESCE_HEADER,
+	ETHTOOL_A_COALESCE_RX_USECS,
+	ETHTOOL_A_COALESCE_RX_MAX_FRAMES,
+	ETHTOOL_A_COALESCE_RX_USECS_IRQ,
+	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ,
+	ETHTOOL_A_COALESCE_TX_USECS,
+	ETHTOOL_A_COALESCE_TX_MAX_FRAMES,
+	ETHTOOL_A_COALESCE_TX_USECS_IRQ,
+	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ,
+	ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,
+	ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX,
+	ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX,
+	ETHTOOL_A_COALESCE_PKT_RATE_LOW,
+	ETHTOOL_A_COALESCE_RX_USECS_LOW,
+	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW,
+	ETHTOOL_A_COALESCE_TX_USECS_LOW,
+	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW,
+	ETHTOOL_A_COALESCE_PKT_RATE_HIGH,
+	ETHTOOL_A_COALESCE_RX_USECS_HIGH,
+	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH,
+	ETHTOOL_A_COALESCE_TX_USECS_HIGH,
+	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH,
+	ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,
+	ETHTOOL_A_COALESCE_USE_CQE_MODE_TX,
+	ETHTOOL_A_COALESCE_USE_CQE_MODE_RX,
+	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,
+	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,
+	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,
+	ETHTOOL_A_COALESCE_RX_PROFILE,
+	ETHTOOL_A_COALESCE_TX_PROFILE,
+
+	__ETHTOOL_A_COALESCE_CNT,
+	ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PAUSE_STAT_UNSPEC,
+	ETHTOOL_A_PAUSE_STAT_PAD,
+	ETHTOOL_A_PAUSE_STAT_TX_FRAMES,
+	ETHTOOL_A_PAUSE_STAT_RX_FRAMES,
+
+	__ETHTOOL_A_PAUSE_STAT_CNT,
+	ETHTOOL_A_PAUSE_STAT_MAX = (__ETHTOOL_A_PAUSE_STAT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PAUSE_UNSPEC,
+	ETHTOOL_A_PAUSE_HEADER,
+	ETHTOOL_A_PAUSE_AUTONEG,
+	ETHTOOL_A_PAUSE_RX,
+	ETHTOOL_A_PAUSE_TX,
+	ETHTOOL_A_PAUSE_STATS,
+	ETHTOOL_A_PAUSE_STATS_SRC,
+
+	__ETHTOOL_A_PAUSE_CNT,
+	ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_EEE_UNSPEC,
+	ETHTOOL_A_EEE_HEADER,
+	ETHTOOL_A_EEE_MODES_OURS,
+	ETHTOOL_A_EEE_MODES_PEER,
+	ETHTOOL_A_EEE_ACTIVE,
+	ETHTOOL_A_EEE_ENABLED,
+	ETHTOOL_A_EEE_TX_LPI_ENABLED,
+	ETHTOOL_A_EEE_TX_LPI_TIMER,
+
+	__ETHTOOL_A_EEE_CNT,
+	ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TS_STAT_UNSPEC,
+	ETHTOOL_A_TS_STAT_TX_PKTS,
+	ETHTOOL_A_TS_STAT_TX_LOST,
+	ETHTOOL_A_TS_STAT_TX_ERR,
+	ETHTOOL_A_TS_STAT_TX_ONESTEP_PKTS_UNCONFIRMED,
+
+	__ETHTOOL_A_TS_STAT_CNT,
+	ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TS_HWTSTAMP_PROVIDER_UNSPEC,
+	ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,
+	ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,
+
+	__ETHTOOL_A_TS_HWTSTAMP_PROVIDER_CNT,
+	ETHTOOL_A_TS_HWTSTAMP_PROVIDER_MAX = (__ETHTOOL_A_TS_HWTSTAMP_PROVIDER_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TSINFO_UNSPEC,
+	ETHTOOL_A_TSINFO_HEADER,
+	ETHTOOL_A_TSINFO_TIMESTAMPING,
+	ETHTOOL_A_TSINFO_TX_TYPES,
+	ETHTOOL_A_TSINFO_RX_FILTERS,
+	ETHTOOL_A_TSINFO_PHC_INDEX,
+	ETHTOOL_A_TSINFO_STATS,
+	ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER,
+
+	__ETHTOOL_A_TSINFO_CNT,
+	ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_RESULT_UNSPEC,
+	ETHTOOL_A_CABLE_RESULT_PAIR,
+	ETHTOOL_A_CABLE_RESULT_CODE,
+	ETHTOOL_A_CABLE_RESULT_SRC,
+
+	__ETHTOOL_A_CABLE_RESULT_CNT,
+	ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
+	ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
+	ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
+	ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
+
+	__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
+	ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_NEST_UNSPEC,
+	ETHTOOL_A_CABLE_NEST_RESULT,
+	ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,
+
+	__ETHTOOL_A_CABLE_NEST_CNT,
+	ETHTOOL_A_CABLE_NEST_MAX = (__ETHTOOL_A_CABLE_NEST_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_TEST_UNSPEC,
+	ETHTOOL_A_CABLE_TEST_HEADER,
+
+	__ETHTOOL_A_CABLE_TEST_CNT,
+	ETHTOOL_A_CABLE_TEST_MAX = (__ETHTOOL_A_CABLE_TEST_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_TEST_NTF_UNSPEC,
+	ETHTOOL_A_CABLE_TEST_NTF_HEADER,
+	ETHTOOL_A_CABLE_TEST_NTF_STATUS,
+	ETHTOOL_A_CABLE_TEST_NTF_NEST,
+
+	__ETHTOOL_A_CABLE_TEST_NTF_CNT,
+	ETHTOOL_A_CABLE_TEST_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_NTF_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR,
+
+	__ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC,
+	ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER,
+	ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS,
+	ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,
+
+	__ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT,
+	ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_CABLE_TEST_TDR_UNSPEC,
+	ETHTOOL_A_CABLE_TEST_TDR_HEADER,
+	ETHTOOL_A_CABLE_TEST_TDR_CFG,
+
+	__ETHTOOL_A_CABLE_TEST_TDR_CNT,
+	ETHTOOL_A_CABLE_TEST_TDR_MAX = (__ETHTOOL_A_CABLE_TEST_TDR_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC,
+	ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT,
+	ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE,
+
+	__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT,
+	ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX = (__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC,
+	ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE,
+	ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES,
+	ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY,
+
+	__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT,
+	ETHTOOL_A_TUNNEL_UDP_TABLE_MAX = (__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TUNNEL_UDP_UNSPEC,
+	ETHTOOL_A_TUNNEL_UDP_TABLE,
+
+	__ETHTOOL_A_TUNNEL_UDP_CNT,
+	ETHTOOL_A_TUNNEL_UDP_MAX = (__ETHTOOL_A_TUNNEL_UDP_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TUNNEL_INFO_UNSPEC,
+	ETHTOOL_A_TUNNEL_INFO_HEADER,
+	ETHTOOL_A_TUNNEL_INFO_UDP_PORTS,
+
+	__ETHTOOL_A_TUNNEL_INFO_CNT,
+	ETHTOOL_A_TUNNEL_INFO_MAX = (__ETHTOOL_A_TUNNEL_INFO_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_FEC_STAT_UNSPEC,
+	ETHTOOL_A_FEC_STAT_PAD,
+	ETHTOOL_A_FEC_STAT_CORRECTED,
+	ETHTOOL_A_FEC_STAT_UNCORR,
+	ETHTOOL_A_FEC_STAT_CORR_BITS,
+
+	__ETHTOOL_A_FEC_STAT_CNT,
+	ETHTOOL_A_FEC_STAT_MAX = (__ETHTOOL_A_FEC_STAT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_FEC_UNSPEC,
+	ETHTOOL_A_FEC_HEADER,
+	ETHTOOL_A_FEC_MODES,
+	ETHTOOL_A_FEC_AUTO,
+	ETHTOOL_A_FEC_ACTIVE,
+	ETHTOOL_A_FEC_STATS,
+
+	__ETHTOOL_A_FEC_CNT,
+	ETHTOOL_A_FEC_MAX = (__ETHTOOL_A_FEC_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_MODULE_EEPROM_UNSPEC,
+	ETHTOOL_A_MODULE_EEPROM_HEADER,
+	ETHTOOL_A_MODULE_EEPROM_OFFSET,
+	ETHTOOL_A_MODULE_EEPROM_LENGTH,
+	ETHTOOL_A_MODULE_EEPROM_PAGE,
+	ETHTOOL_A_MODULE_EEPROM_BANK,
+	ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS,
+	ETHTOOL_A_MODULE_EEPROM_DATA,
+
+	__ETHTOOL_A_MODULE_EEPROM_CNT,
+	ETHTOOL_A_MODULE_EEPROM_MAX = (__ETHTOOL_A_MODULE_EEPROM_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STATS_GRP_UNSPEC,
+	ETHTOOL_A_STATS_GRP_PAD,
+	ETHTOOL_A_STATS_GRP_ID,
+	ETHTOOL_A_STATS_GRP_SS_ID,
+	ETHTOOL_A_STATS_GRP_STAT,
+	ETHTOOL_A_STATS_GRP_HIST_RX,
+	ETHTOOL_A_STATS_GRP_HIST_TX,
+	ETHTOOL_A_STATS_GRP_HIST_BKT_LOW,
+	ETHTOOL_A_STATS_GRP_HIST_BKT_HI,
+	ETHTOOL_A_STATS_GRP_HIST_VAL,
+
+	__ETHTOOL_A_STATS_GRP_CNT,
+	ETHTOOL_A_STATS_GRP_MAX = (__ETHTOOL_A_STATS_GRP_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_STATS_UNSPEC,
+	ETHTOOL_A_STATS_PAD,
+	ETHTOOL_A_STATS_HEADER,
+	ETHTOOL_A_STATS_GROUPS,
+	ETHTOOL_A_STATS_GRP,
+	ETHTOOL_A_STATS_SRC,
+
+	__ETHTOOL_A_STATS_CNT,
+	ETHTOOL_A_STATS_MAX = (__ETHTOOL_A_STATS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
+	ETHTOOL_A_PHC_VCLOCKS_HEADER,
+	ETHTOOL_A_PHC_VCLOCKS_NUM,
+	ETHTOOL_A_PHC_VCLOCKS_INDEX,
+
+	__ETHTOOL_A_PHC_VCLOCKS_CNT,
+	ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_MODULE_UNSPEC,
+	ETHTOOL_A_MODULE_HEADER,
+	ETHTOOL_A_MODULE_POWER_MODE_POLICY,
+	ETHTOOL_A_MODULE_POWER_MODE,
+
+	__ETHTOOL_A_MODULE_CNT,
+	ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,
+
+	__ETHTOOL_A_C33_PSE_PW_LIMIT_CNT,
+	__ETHTOOL_A_C33_PSE_PW_LIMIT_MAX = (__ETHTOOL_A_C33_PSE_PW_LIMIT_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PSE_UNSPEC,
+	ETHTOOL_A_PSE_HEADER,
+	ETHTOOL_A_PODL_PSE_ADMIN_STATE,
+	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,
+	ETHTOOL_A_PODL_PSE_PW_D_STATUS,
+	ETHTOOL_A_C33_PSE_ADMIN_STATE,
+	ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
+	ETHTOOL_A_C33_PSE_PW_D_STATUS,
+	ETHTOOL_A_C33_PSE_PW_CLASS,
+	ETHTOOL_A_C33_PSE_ACTUAL_PW,
+	ETHTOOL_A_C33_PSE_EXT_STATE,
+	ETHTOOL_A_C33_PSE_EXT_SUBSTATE,
+	ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
+	ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,
+
+	__ETHTOOL_A_PSE_CNT,
+	ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_RSS_UNSPEC,
+	ETHTOOL_A_RSS_HEADER,
+	ETHTOOL_A_RSS_CONTEXT,
+	ETHTOOL_A_RSS_HFUNC,
+	ETHTOOL_A_RSS_INDIR,
+	ETHTOOL_A_RSS_HKEY,
+	ETHTOOL_A_RSS_INPUT_XFRM,
+	ETHTOOL_A_RSS_START_CONTEXT,
+
+	__ETHTOOL_A_RSS_CNT,
+	ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PLCA_UNSPEC,
+	ETHTOOL_A_PLCA_HEADER,
+	ETHTOOL_A_PLCA_VERSION,
+	ETHTOOL_A_PLCA_ENABLED,
+	ETHTOOL_A_PLCA_STATUS,
+	ETHTOOL_A_PLCA_NODE_CNT,
+	ETHTOOL_A_PLCA_NODE_ID,
+	ETHTOOL_A_PLCA_TO_TMR,
+	ETHTOOL_A_PLCA_BURST_CNT,
+	ETHTOOL_A_PLCA_BURST_TMR,
+
+	__ETHTOOL_A_PLCA_CNT,
+	ETHTOOL_A_PLCA_MAX = (__ETHTOOL_A_PLCA_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
+	ETHTOOL_A_MODULE_FW_FLASH_HEADER,
+	ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
+	ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS,
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,
+	ETHTOOL_A_MODULE_FW_FLASH_DONE,
+	ETHTOOL_A_MODULE_FW_FLASH_TOTAL,
+
+	__ETHTOOL_A_MODULE_FW_FLASH_CNT,
+	ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PHY_UNSPEC,
+	ETHTOOL_A_PHY_HEADER,
+	ETHTOOL_A_PHY_INDEX,
+	ETHTOOL_A_PHY_DRVNAME,
+	ETHTOOL_A_PHY_NAME,
+	ETHTOOL_A_PHY_UPSTREAM_TYPE,
+	ETHTOOL_A_PHY_UPSTREAM_INDEX,
+	ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,
+	ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,
+
+	__ETHTOOL_A_PHY_CNT,
+	ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_TSCONFIG_UNSPEC,
+	ETHTOOL_A_TSCONFIG_HEADER,
+	ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER,
+	ETHTOOL_A_TSCONFIG_TX_TYPES,
+	ETHTOOL_A_TSCONFIG_RX_FILTERS,
+	ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS,
+
+	__ETHTOOL_A_TSCONFIG_CNT,
+	ETHTOOL_A_TSCONFIG_MAX = (__ETHTOOL_A_TSCONFIG_CNT - 1)
+};
+
+enum {
+	ETHTOOL_MSG_USER_NONE = 0,
+	ETHTOOL_MSG_STRSET_GET = 1,
+	ETHTOOL_MSG_LINKINFO_GET,
+	ETHTOOL_MSG_LINKINFO_SET,
+	ETHTOOL_MSG_LINKMODES_GET,
+	ETHTOOL_MSG_LINKMODES_SET,
+	ETHTOOL_MSG_LINKSTATE_GET,
+	ETHTOOL_MSG_DEBUG_GET,
+	ETHTOOL_MSG_DEBUG_SET,
+	ETHTOOL_MSG_WOL_GET,
+	ETHTOOL_MSG_WOL_SET,
+	ETHTOOL_MSG_FEATURES_GET,
+	ETHTOOL_MSG_FEATURES_SET,
+	ETHTOOL_MSG_PRIVFLAGS_GET,
+	ETHTOOL_MSG_PRIVFLAGS_SET,
+	ETHTOOL_MSG_RINGS_GET,
+	ETHTOOL_MSG_RINGS_SET,
+	ETHTOOL_MSG_CHANNELS_GET,
+	ETHTOOL_MSG_CHANNELS_SET,
+	ETHTOOL_MSG_COALESCE_GET,
+	ETHTOOL_MSG_COALESCE_SET,
+	ETHTOOL_MSG_PAUSE_GET,
+	ETHTOOL_MSG_PAUSE_SET,
+	ETHTOOL_MSG_EEE_GET,
+	ETHTOOL_MSG_EEE_SET,
+	ETHTOOL_MSG_TSINFO_GET,
+	ETHTOOL_MSG_CABLE_TEST_ACT,
+	ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
+	ETHTOOL_MSG_TUNNEL_INFO_GET,
+	ETHTOOL_MSG_FEC_GET,
+	ETHTOOL_MSG_FEC_SET,
+	ETHTOOL_MSG_MODULE_EEPROM_GET,
+	ETHTOOL_MSG_STATS_GET,
+	ETHTOOL_MSG_PHC_VCLOCKS_GET,
+	ETHTOOL_MSG_MODULE_GET,
+	ETHTOOL_MSG_MODULE_SET,
+	ETHTOOL_MSG_PSE_GET,
+	ETHTOOL_MSG_PSE_SET,
+	ETHTOOL_MSG_RSS_GET,
+	ETHTOOL_MSG_PLCA_GET_CFG,
+	ETHTOOL_MSG_PLCA_SET_CFG,
+	ETHTOOL_MSG_PLCA_GET_STATUS,
+	ETHTOOL_MSG_MM_GET,
+	ETHTOOL_MSG_MM_SET,
+	ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+	ETHTOOL_MSG_PHY_GET,
+	ETHTOOL_MSG_TSCONFIG_GET,
+	ETHTOOL_MSG_TSCONFIG_SET,
+
+	__ETHTOOL_MSG_USER_CNT,
+	ETHTOOL_MSG_USER_MAX = (__ETHTOOL_MSG_USER_CNT - 1)
+};
+
+enum {
+	ETHTOOL_MSG_KERNEL_NONE = 0,
+	ETHTOOL_MSG_STRSET_GET_REPLY = 1,
+	ETHTOOL_MSG_LINKINFO_GET_REPLY,
+	ETHTOOL_MSG_LINKINFO_NTF,
+	ETHTOOL_MSG_LINKMODES_GET_REPLY,
+	ETHTOOL_MSG_LINKMODES_NTF,
+	ETHTOOL_MSG_LINKSTATE_GET_REPLY,
+	ETHTOOL_MSG_DEBUG_GET_REPLY,
+	ETHTOOL_MSG_DEBUG_NTF,
+	ETHTOOL_MSG_WOL_GET_REPLY,
+	ETHTOOL_MSG_WOL_NTF,
+	ETHTOOL_MSG_FEATURES_GET_REPLY,
+	ETHTOOL_MSG_FEATURES_SET_REPLY,
+	ETHTOOL_MSG_FEATURES_NTF,
+	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
+	ETHTOOL_MSG_PRIVFLAGS_NTF,
+	ETHTOOL_MSG_RINGS_GET_REPLY,
+	ETHTOOL_MSG_RINGS_NTF,
+	ETHTOOL_MSG_CHANNELS_GET_REPLY,
+	ETHTOOL_MSG_CHANNELS_NTF,
+	ETHTOOL_MSG_COALESCE_GET_REPLY,
+	ETHTOOL_MSG_COALESCE_NTF,
+	ETHTOOL_MSG_PAUSE_GET_REPLY,
+	ETHTOOL_MSG_PAUSE_NTF,
+	ETHTOOL_MSG_EEE_GET_REPLY,
+	ETHTOOL_MSG_EEE_NTF,
+	ETHTOOL_MSG_TSINFO_GET_REPLY,
+	ETHTOOL_MSG_CABLE_TEST_NTF,
+	ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
+	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
+	ETHTOOL_MSG_FEC_GET_REPLY,
+	ETHTOOL_MSG_FEC_NTF,
+	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
+	ETHTOOL_MSG_STATS_GET_REPLY,
+	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
+	ETHTOOL_MSG_MODULE_GET_REPLY,
+	ETHTOOL_MSG_MODULE_NTF,
+	ETHTOOL_MSG_PSE_GET_REPLY,
+	ETHTOOL_MSG_RSS_GET_REPLY,
+	ETHTOOL_MSG_PLCA_GET_CFG_REPLY,
+	ETHTOOL_MSG_PLCA_GET_STATUS_REPLY,
+	ETHTOOL_MSG_PLCA_NTF,
+	ETHTOOL_MSG_MM_GET_REPLY,
+	ETHTOOL_MSG_MM_NTF,
+	ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
+	ETHTOOL_MSG_PHY_GET_REPLY,
+	ETHTOOL_MSG_PHY_NTF,
+	ETHTOOL_MSG_TSCONFIG_GET_REPLY,
+	ETHTOOL_MSG_TSCONFIG_SET_REPLY,
+
+	__ETHTOOL_MSG_KERNEL_CNT,
+	ETHTOOL_MSG_KERNEL_MAX = (__ETHTOOL_MSG_KERNEL_CNT - 1)
+};
+
+#endif /* _UAPI_LINUX_ETHTOOL_NETLINK_GENERATED_H */
diff --git a/original/uapi/linux/f2fs.h b/original/uapi/linux/f2fs.h
index 955d440..f7aaf8d 100644
--- a/original/uapi/linux/f2fs.h
+++ b/original/uapi/linux/f2fs.h
@@ -43,6 +43,7 @@
 #define F2FS_IOC_DECOMPRESS_FILE	_IO(F2FS_IOCTL_MAGIC, 23)
 #define F2FS_IOC_COMPRESS_FILE		_IO(F2FS_IOCTL_MAGIC, 24)
 #define F2FS_IOC_START_ATOMIC_REPLACE	_IO(F2FS_IOCTL_MAGIC, 25)
+#define F2FS_IOC_GET_DEV_ALIAS_FILE	_IOR(F2FS_IOCTL_MAGIC, 26, __u32)
 
 /*
  * should be same as XFS_IOC_GOINGDOWN.
diff --git a/original/uapi/linux/fanotify.h b/original/uapi/linux/fanotify.h
index a37de58..bd81679 100644
--- a/original/uapi/linux/fanotify.h
+++ b/original/uapi/linux/fanotify.h
@@ -25,6 +25,9 @@
 #define FAN_OPEN_PERM		0x00010000	/* File open in perm check */
 #define FAN_ACCESS_PERM		0x00020000	/* File accessed in perm check */
 #define FAN_OPEN_EXEC_PERM	0x00040000	/* File open/exec in perm check */
+/* #define FAN_DIR_MODIFY	0x00080000 */	/* Deprecated (reserved) */
+
+#define FAN_PRE_ACCESS		0x00100000	/* Pre-content access hook */
 
 #define FAN_EVENT_ON_CHILD	0x08000000	/* Interested in child events */
 
@@ -60,6 +63,7 @@
 #define FAN_REPORT_DIR_FID	0x00000400	/* Report unique directory id */
 #define FAN_REPORT_NAME		0x00000800	/* Report events with name */
 #define FAN_REPORT_TARGET_FID	0x00001000	/* Report dirent target id  */
+#define FAN_REPORT_FD_ERROR	0x00002000	/* event->fd can report error */
 
 /* Convenience macro - FAN_REPORT_NAME requires FAN_REPORT_DIR_FID */
 #define FAN_REPORT_DFID_NAME	(FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
@@ -142,6 +146,7 @@ struct fanotify_event_metadata {
 #define FAN_EVENT_INFO_TYPE_DFID	3
 #define FAN_EVENT_INFO_TYPE_PIDFD	4
 #define FAN_EVENT_INFO_TYPE_ERROR	5
+#define FAN_EVENT_INFO_TYPE_RANGE	6
 
 /* Special info types for FAN_RENAME */
 #define FAN_EVENT_INFO_TYPE_OLD_DFID_NAME	10
@@ -188,6 +193,13 @@ struct fanotify_event_info_error {
 	__u32 error_count;
 };
 
+struct fanotify_event_info_range {
+	struct fanotify_event_info_header hdr;
+	__u32 pad;
+	__u64 offset;
+	__u64 count;
+};
+
 /*
  * User space may need to record additional information about its decision.
  * The extra information type records what kind of information is included.
@@ -223,6 +235,13 @@ struct fanotify_response_info_audit_rule {
 /* Legit userspace responses to a _PERM event */
 #define FAN_ALLOW	0x01
 #define FAN_DENY	0x02
+/* errno other than EPERM can specified in upper byte of deny response */
+#define FAN_ERRNO_BITS	8
+#define FAN_ERRNO_SHIFT (32 - FAN_ERRNO_BITS)
+#define FAN_ERRNO_MASK	((1 << FAN_ERRNO_BITS) - 1)
+#define FAN_DENY_ERRNO(err) \
+	(FAN_DENY | ((((__u32)(err)) & FAN_ERRNO_MASK) << FAN_ERRNO_SHIFT))
+
 #define FAN_AUDIT	0x10	/* Bitmask to create audit record for result */
 #define FAN_INFO	0x20	/* Bitmask to indicate additional information */
 
diff --git a/original/uapi/linux/fcntl.h b/original/uapi/linux/fcntl.h
index 87e2dec..a15ac2f 100644
--- a/original/uapi/linux/fcntl.h
+++ b/original/uapi/linux/fcntl.h
@@ -153,9 +153,10 @@
 					   object identity and may not be
 					   usable with open_by_handle_at(2). */
 #define AT_HANDLE_MNT_ID_UNIQUE	0x001	/* Return the u64 unique mount ID. */
+#define AT_HANDLE_CONNECTABLE	0x002	/* Request a connectable file handle */
 
-#if defined(__KERNEL__)
-#define AT_GETATTR_NOSEC	0x80000000
-#endif
+/* Flags for execveat2(2). */
+#define AT_EXECVE_CHECK		0x10000	/* Only perform a check if execution
+					   would be allowed. */
 
 #endif /* _UAPI_LINUX_FCNTL_H */
diff --git a/original/uapi/linux/fib_rules.h b/original/uapi/linux/fib_rules.h
index a6924dd..00e9890 100644
--- a/original/uapi/linux/fib_rules.h
+++ b/original/uapi/linux/fib_rules.h
@@ -68,6 +68,8 @@ enum {
 	FRA_SPORT_RANGE, /* sport */
 	FRA_DPORT_RANGE, /* dport */
 	FRA_DSCP,	/* dscp */
+	FRA_FLOWLABEL,	/* flowlabel */
+	FRA_FLOWLABEL_MASK,	/* flowlabel mask */
 	__FRA_MAX
 };
 
diff --git a/original/uapi/linux/fiemap.h b/original/uapi/linux/fiemap.h
index 24ca0c0..9d9e8ae 100644
--- a/original/uapi/linux/fiemap.h
+++ b/original/uapi/linux/fiemap.h
@@ -14,37 +14,56 @@
 
 #include <linux/types.h>
 
+/**
+ * struct fiemap_extent - description of one fiemap extent
+ * @fe_logical: byte offset of the extent in the file
+ * @fe_physical: byte offset of extent on disk
+ * @fe_length: length in bytes for this extent
+ * @fe_flags: FIEMAP_EXTENT_* flags for this extent
+ */
 struct fiemap_extent {
-	__u64 fe_logical;  /* logical offset in bytes for the start of
-			    * the extent from the beginning of the file */
-	__u64 fe_physical; /* physical offset in bytes for the start
-			    * of the extent from the beginning of the disk */
-	__u64 fe_length;   /* length in bytes for this extent */
+	__u64 fe_logical;
+	__u64 fe_physical;
+	__u64 fe_length;
+	/* private: */
 	__u64 fe_reserved64[2];
-	__u32 fe_flags;    /* FIEMAP_EXTENT_* flags for this extent */
+	/* public: */
+	__u32 fe_flags;
+	/* private: */
 	__u32 fe_reserved[3];
 };
 
+/**
+ * struct fiemap - file extent mappings
+ * @fm_start: byte offset (inclusive) at which to start mapping (in)
+ * @fm_length: logical length of mapping which userspace wants (in)
+ * @fm_flags: FIEMAP_FLAG_* flags for request (in/out)
+ * @fm_mapped_extents: number of extents that were mapped (out)
+ * @fm_extent_count: size of fm_extents array (in)
+ * @fm_extents: array of mapped extents (out)
+ */
 struct fiemap {
-	__u64 fm_start;		/* logical offset (inclusive) at
-				 * which to start mapping (in) */
-	__u64 fm_length;	/* logical length of mapping which
-				 * userspace wants (in) */
-	__u32 fm_flags;		/* FIEMAP_FLAG_* flags for request (in/out) */
-	__u32 fm_mapped_extents;/* number of extents that were mapped (out) */
-	__u32 fm_extent_count;  /* size of fm_extents array (in) */
+	__u64 fm_start;
+	__u64 fm_length;
+	__u32 fm_flags;
+	__u32 fm_mapped_extents;
+	__u32 fm_extent_count;
+	/* private: */
 	__u32 fm_reserved;
-	struct fiemap_extent fm_extents[]; /* array of mapped extents (out) */
+	/* public: */
+	struct fiemap_extent fm_extents[];
 };
 
 #define FIEMAP_MAX_OFFSET	(~0ULL)
 
+/* flags used in fm_flags: */
 #define FIEMAP_FLAG_SYNC	0x00000001 /* sync file data before map */
 #define FIEMAP_FLAG_XATTR	0x00000002 /* map extended attribute tree */
 #define FIEMAP_FLAG_CACHE	0x00000004 /* request caching of the extents */
 
 #define FIEMAP_FLAGS_COMPAT	(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR)
 
+/* flags used in fe_flags: */
 #define FIEMAP_EXTENT_LAST		0x00000001 /* Last extent in file. */
 #define FIEMAP_EXTENT_UNKNOWN		0x00000002 /* Data location unknown. */
 #define FIEMAP_EXTENT_DELALLOC		0x00000004 /* Location still pending.
diff --git a/original/uapi/linux/fs.h b/original/uapi/linux/fs.h
index 7539717..e762e1a 100644
--- a/original/uapi/linux/fs.h
+++ b/original/uapi/linux/fs.h
@@ -40,6 +40,15 @@
 #define BLOCK_SIZE_BITS 10
 #define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
 
+/* flags for integrity meta */
+#define IO_INTEGRITY_CHK_GUARD		(1U << 0) /* enforce guard check */
+#define IO_INTEGRITY_CHK_REFTAG		(1U << 1) /* enforce ref check */
+#define IO_INTEGRITY_CHK_APPTAG		(1U << 2) /* enforce app check */
+
+#define IO_INTEGRITY_VALID_FLAGS (IO_INTEGRITY_CHK_GUARD | \
+				  IO_INTEGRITY_CHK_REFTAG | \
+				  IO_INTEGRITY_CHK_APPTAG)
+
 #define SEEK_SET	0	/* seek relative to beginning of file */
 #define SEEK_CUR	1	/* seek relative to current file position */
 #define SEEK_END	2	/* seek relative to end of file */
@@ -203,10 +212,8 @@ struct fsxattr {
 #define BLKROTATIONAL _IO(0x12,126)
 #define BLKZEROOUT _IO(0x12,127)
 #define BLKGETDISKSEQ _IOR(0x12,128,__u64)
-/*
- * A jump here: 130-136 are reserved for zoned block devices
- * (see uapi/linux/blkzoned.h)
- */
+/* 130-136 are used by zoned block device ioctls (uapi/linux/blkzoned.h) */
+/* 137-141 are used by blk-crypto ioctls (uapi/linux/blk-crypto.h) */
 
 #define BMAP_IOCTL 1		/* obsolete - kept for compatibility */
 #define FIBMAP	   _IO(0x00,1)	/* bmap access */
@@ -332,9 +339,13 @@ typedef int __bitwise __kernel_rwf_t;
 /* Atomic Write */
 #define RWF_ATOMIC	((__force __kernel_rwf_t)0x00000040)
 
+/* buffered IO that drops the cache after reading or writing data */
+#define RWF_DONTCACHE	((__force __kernel_rwf_t)0x00000080)
+
 /* mask of flags supported by the kernel */
 #define RWF_SUPPORTED	(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT |\
-			 RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC)
+			 RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC |\
+			 RWF_DONTCACHE)
 
 #define PROCFS_IOCTL_MAGIC 'f'
 
diff --git a/original/uapi/linux/fscrypt.h b/original/uapi/linux/fscrypt.h
index 5156f00..37fedfd 100644
--- a/original/uapi/linux/fscrypt.h
+++ b/original/uapi/linux/fscrypt.h
@@ -119,7 +119,7 @@ struct fscrypt_key_specifier {
  */
 struct fscrypt_provisioning_key_payload {
 	__u32 type;
-	__u32 __reserved;
+	__u32 flags;
 	__u8 raw[];
 };
 
@@ -128,7 +128,9 @@ struct fscrypt_add_key_arg {
 	struct fscrypt_key_specifier key_spec;
 	__u32 raw_size;
 	__u32 key_id;
-	__u32 __reserved[7];
+#define FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED	0x00000001
+	__u32 flags;
+	__u32 __reserved[6];
 	/* N.B.: "temporary" flag, not reserved upstream */
 #define __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED		0x00000001
 	__u32 __flags;
diff --git a/original/uapi/linux/fuse.h b/original/uapi/linux/fuse.h
index ab9ee78..0c6df51 100644
--- a/original/uapi/linux/fuse.h
+++ b/original/uapi/linux/fuse.h
@@ -220,6 +220,15 @@
  *
  *  7.41
  *  - add FUSE_ALLOW_IDMAP
+ *  7.42
+ *  - Add FUSE_OVER_IO_URING and all other io-uring related flags and data
+ *    structures:
+ *    - struct fuse_uring_ent_in_out
+ *    - struct fuse_uring_req_header
+ *    - struct fuse_uring_cmd_req
+ *    - FUSE_URING_IN_OUT_HEADER_SZ
+ *    - FUSE_URING_OP_IN_OUT_SZ
+ *    - enum fuse_uring_cmd
  */
 
 #ifndef _LINUX_FUSE_H
@@ -255,7 +264,7 @@
 #define FUSE_KERNEL_VERSION 7
 
 /** Minor version number of this interface */
-#define FUSE_KERNEL_MINOR_VERSION 41
+#define FUSE_KERNEL_MINOR_VERSION 42
 
 /** The node ID of the root inode */
 #define FUSE_ROOT_ID 1
@@ -425,6 +434,7 @@ struct fuse_file_lock {
  * FUSE_HAS_RESEND: kernel supports resending pending requests, and the high bit
  *		    of the request ID indicates resend requests
  * FUSE_ALLOW_IDMAP: allow creation of idmapped mounts
+ * FUSE_OVER_IO_URING: Indicate that client supports io-uring
  */
 #define FUSE_ASYNC_READ		(1 << 0)
 #define FUSE_POSIX_LOCKS	(1 << 1)
@@ -471,6 +481,7 @@ struct fuse_file_lock {
 /* Obsolete alias for FUSE_DIRECT_IO_ALLOW_MMAP */
 #define FUSE_DIRECT_IO_RELAX	FUSE_DIRECT_IO_ALLOW_MMAP
 #define FUSE_ALLOW_IDMAP	(1ULL << 40)
+#define FUSE_OVER_IO_URING	(1ULL << 41)
 
 /**
  * CUSE INIT request/reply flags
@@ -1207,4 +1218,67 @@ struct fuse_supp_groups {
 	uint32_t	groups[];
 };
 
+/**
+ * Size of the ring buffer header
+ */
+#define FUSE_URING_IN_OUT_HEADER_SZ 128
+#define FUSE_URING_OP_IN_OUT_SZ 128
+
+/* Used as part of the fuse_uring_req_header */
+struct fuse_uring_ent_in_out {
+	uint64_t flags;
+
+	/*
+	 * commit ID to be used in a reply to a ring request (see also
+	 * struct fuse_uring_cmd_req)
+	 */
+	uint64_t commit_id;
+
+	/* size of user payload buffer */
+	uint32_t payload_sz;
+	uint32_t padding;
+
+	uint64_t reserved;
+};
+
+/**
+ * Header for all fuse-io-uring requests
+ */
+struct fuse_uring_req_header {
+	/* struct fuse_in_header / struct fuse_out_header */
+	char in_out[FUSE_URING_IN_OUT_HEADER_SZ];
+
+	/* per op code header */
+	char op_in[FUSE_URING_OP_IN_OUT_SZ];
+
+	struct fuse_uring_ent_in_out ring_ent_in_out;
+};
+
+/**
+ * sqe commands to the kernel
+ */
+enum fuse_uring_cmd {
+	FUSE_IO_URING_CMD_INVALID = 0,
+
+	/* register the request buffer and fetch a fuse request */
+	FUSE_IO_URING_CMD_REGISTER = 1,
+
+	/* commit fuse request result and fetch next request */
+	FUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2,
+};
+
+/**
+ * In the 80B command area of the SQE.
+ */
+struct fuse_uring_cmd_req {
+	uint64_t flags;
+
+	/* entry identifier for commits */
+	uint64_t commit_id;
+
+	/* queue the command is for (queue index) */
+	uint16_t qid;
+	uint8_t padding[6];
+};
+
 #endif /* _LINUX_FUSE_H */
diff --git a/original/uapi/linux/if_link.h b/original/uapi/linux/if_link.h
index 6dc2589..bfe880f 100644
--- a/original/uapi/linux/if_link.h
+++ b/original/uapi/linux/if_link.h
@@ -377,6 +377,7 @@ enum {
 	IFLA_GSO_IPV4_MAX_SIZE,
 	IFLA_GRO_IPV4_MAX_SIZE,
 	IFLA_DPLL_PIN,
+	IFLA_MAX_PACING_OFFLOAD_HORIZON,
 	__IFLA_MAX
 };
 
@@ -1292,6 +1293,19 @@ enum netkit_mode {
 	NETKIT_L3,
 };
 
+/* NETKIT_SCRUB_NONE leaves clearing skb->{mark,priority} up to
+ * the BPF program if attached. This also means the latter can
+ * consume the two fields if they were populated earlier.
+ *
+ * NETKIT_SCRUB_DEFAULT zeroes skb->{mark,priority} fields before
+ * invoking the attached BPF program when the peer device resides
+ * in a different network namespace. This is the default behavior.
+ */
+enum netkit_scrub {
+	NETKIT_SCRUB_NONE,
+	NETKIT_SCRUB_DEFAULT,
+};
+
 enum {
 	IFLA_NETKIT_UNSPEC,
 	IFLA_NETKIT_PEER_INFO,
@@ -1299,6 +1313,10 @@ enum {
 	IFLA_NETKIT_POLICY,
 	IFLA_NETKIT_PEER_POLICY,
 	IFLA_NETKIT_MODE,
+	IFLA_NETKIT_SCRUB,
+	IFLA_NETKIT_PEER_SCRUB,
+	IFLA_NETKIT_HEADROOM,
+	IFLA_NETKIT_TAILROOM,
 	__IFLA_NETKIT_MAX,
 };
 #define IFLA_NETKIT_MAX	(__IFLA_NETKIT_MAX - 1)
@@ -1378,6 +1396,7 @@ enum {
 	IFLA_VXLAN_VNIFILTER, /* only applicable with COLLECT_METADATA mode */
 	IFLA_VXLAN_LOCALBYPASS,
 	IFLA_VXLAN_LABEL_POLICY, /* IPv6 flow label policy; ifla_vxlan_label_policy */
+	IFLA_VXLAN_RESERVED_BITS,
 	__IFLA_VXLAN_MAX
 };
 #define IFLA_VXLAN_MAX	(__IFLA_VXLAN_MAX - 1)
@@ -1942,6 +1961,7 @@ struct ifla_rmnet_flags {
 enum {
 	IFLA_MCTP_UNSPEC,
 	IFLA_MCTP_NET,
+	IFLA_MCTP_PHYS_BINDING,
 	__IFLA_MCTP_MAX,
 };
 
diff --git a/original/uapi/linux/iio/types.h b/original/uapi/linux/iio/types.h
index f2e0b2d..12886d4 100644
--- a/original/uapi/linux/iio/types.h
+++ b/original/uapi/linux/iio/types.h
@@ -51,6 +51,7 @@ enum iio_chan_type {
 	IIO_DELTA_VELOCITY,
 	IIO_COLORTEMP,
 	IIO_CHROMATICITY,
+	IIO_ATTENTION,
 };
 
 enum iio_modifier {
diff --git a/original/uapi/linux/in.h b/original/uapi/linux/in.h
index 5d32d53..ced0fc3 100644
--- a/original/uapi/linux/in.h
+++ b/original/uapi/linux/in.h
@@ -79,6 +79,8 @@ enum {
 #define IPPROTO_MPLS		IPPROTO_MPLS
   IPPROTO_ETHERNET = 143,	/* Ethernet-within-IPv6 Encapsulation	*/
 #define IPPROTO_ETHERNET	IPPROTO_ETHERNET
+  IPPROTO_AGGFRAG = 144,	/* AGGFRAG in ESP (RFC 9347)		*/
+#define IPPROTO_AGGFRAG		IPPROTO_AGGFRAG
   IPPROTO_RAW = 255,		/* Raw IP packets			*/
 #define IPPROTO_RAW		IPPROTO_RAW
   IPPROTO_SMC = 256,		/* Shared Memory Communications		*/
diff --git a/original/uapi/linux/input-event-codes.h b/original/uapi/linux/input-event-codes.h
index a420672..5a199f3 100644
--- a/original/uapi/linux/input-event-codes.h
+++ b/original/uapi/linux/input-event-codes.h
@@ -519,6 +519,7 @@
 #define KEY_NOTIFICATION_CENTER	0x1bc	/* Show/hide the notification center */
 #define KEY_PICKUP_PHONE	0x1bd	/* Answer incoming call */
 #define KEY_HANGUP_PHONE	0x1be	/* Decline incoming call */
+#define KEY_LINK_PHONE		0x1bf   /* AL Phone Syncing */
 
 #define KEY_DEL_EOL		0x1c0
 #define KEY_DEL_EOS		0x1c1
diff --git a/original/uapi/linux/io_uring.h b/original/uapi/linux/io_uring.h
index 1fe79e7..050fa8e 100644
--- a/original/uapi/linux/io_uring.h
+++ b/original/uapi/linux/io_uring.h
@@ -98,6 +98,10 @@ struct io_uring_sqe {
 			__u64	addr3;
 			__u64	__pad2[1];
 		};
+		struct {
+			__u64	attr_ptr; /* pointer to attribute information */
+			__u64	attr_type_mask; /* bit mask of attributes */
+		};
 		__u64	optval;
 		/*
 		 * If the ring is initialized with IORING_SETUP_SQE128, then
@@ -107,6 +111,18 @@ struct io_uring_sqe {
 	};
 };
 
+/* sqe->attr_type_mask flags */
+#define IORING_RW_ATTR_FLAG_PI	(1U << 0)
+/* PI attribute information */
+struct io_uring_attr_pi {
+		__u16	flags;
+		__u16	app_tag;
+		__u32	len;
+		__u64	addr;
+		__u64	seed;
+		__u64	rsvd;
+};
+
 /*
  * If sqe->file_index is set to this for opcodes that instantiate a new
  * direct descriptor (like openat/openat2/accept), then io_uring will allocate
@@ -200,6 +216,9 @@ enum io_uring_sqe_flags_bit {
  */
 #define IORING_SETUP_NO_SQARRAY		(1U << 16)
 
+/* Use hybrid poll in iopoll process */
+#define IORING_SETUP_HYBRID_IOPOLL	(1U << 17)
+
 enum io_uring_op {
 	IORING_OP_NOP,
 	IORING_OP_READV,
@@ -361,7 +380,7 @@ enum io_uring_op {
  *				result 	will be the number of buffers send, with
  *				the starting buffer ID in cqe->flags as per
  *				usual for provided buffer usage. The buffers
- *				will be	contigious from the starting buffer ID.
+ *				will be	contiguous from the starting buffer ID.
  */
 #define IORING_RECVSEND_POLL_FIRST	(1U << 0)
 #define IORING_RECV_MULTISHOT		(1U << 1)
@@ -416,6 +435,9 @@ enum io_uring_msg_ring_flags {
  * IORING_NOP_INJECT_RESULT	Inject result from sqe->result
  */
 #define IORING_NOP_INJECT_RESULT	(1U << 0)
+#define IORING_NOP_FILE			(1U << 1)
+#define IORING_NOP_FIXED_FILE		(1U << 2)
+#define IORING_NOP_FIXED_BUFFER		(1U << 3)
 
 /*
  * IO completion data structure (Completion Queue Entry)
@@ -518,6 +540,7 @@ struct io_cqring_offsets {
 #define IORING_ENTER_EXT_ARG		(1U << 3)
 #define IORING_ENTER_REGISTERED_RING	(1U << 4)
 #define IORING_ENTER_ABS_TIMER		(1U << 5)
+#define IORING_ENTER_EXT_ARG_REG	(1U << 6)
 
 /*
  * Passed in for io_uring_setup(2). Copied back with updated info on success
@@ -554,6 +577,7 @@ struct io_uring_params {
 #define IORING_FEAT_REG_REG_RING	(1U << 13)
 #define IORING_FEAT_RECVSEND_BUNDLE	(1U << 14)
 #define IORING_FEAT_MIN_TIMEOUT		(1U << 15)
+#define IORING_FEAT_RW_ATTR		(1U << 16)
 
 /*
  * io_uring_register(2) opcodes and arguments
@@ -612,6 +636,16 @@ enum io_uring_register_op {
 	/* clone registered buffers from source ring to current ring */
 	IORING_REGISTER_CLONE_BUFFERS		= 30,
 
+	/* send MSG_RING without having a ring */
+	IORING_REGISTER_SEND_MSG_RING		= 31,
+
+	/* 32 reserved for zc rx */
+
+	/* resize CQ ring */
+	IORING_REGISTER_RESIZE_RINGS		= 33,
+
+	IORING_REGISTER_MEM_REGION		= 34,
+
 	/* this goes last */
 	IORING_REGISTER_LAST,
 
@@ -632,6 +666,31 @@ struct io_uring_files_update {
 	__aligned_u64 /* __s32 * */ fds;
 };
 
+enum {
+	/* initialise with user provided memory pointed by user_addr */
+	IORING_MEM_REGION_TYPE_USER		= 1,
+};
+
+struct io_uring_region_desc {
+	__u64 user_addr;
+	__u64 size;
+	__u32 flags;
+	__u32 id;
+	__u64 mmap_offset;
+	__u64 __resv[4];
+};
+
+enum {
+	/* expose the region as registered wait arguments */
+	IORING_MEM_REGION_REG_WAIT_ARG		= 1,
+};
+
+struct io_uring_mem_region_reg {
+	__u64 region_uptr; /* struct io_uring_region_desc * */
+	__u64 flags;
+	__u64 __resv[2];
+};
+
 /*
  * Register a fully sparse file space, rather than pass in an array of all
  * -1 file descriptors.
@@ -698,13 +757,17 @@ struct io_uring_clock_register {
 };
 
 enum {
-	IORING_REGISTER_SRC_REGISTERED = 1,
+	IORING_REGISTER_SRC_REGISTERED	= (1U << 0),
+	IORING_REGISTER_DST_REPLACE	= (1U << 1),
 };
 
 struct io_uring_clone_buffers {
 	__u32	src_fd;
 	__u32	flags;
-	__u32	pad[6];
+	__u32	src_off;
+	__u32	dst_off;
+	__u32	nr;
+	__u32	pad[3];
 };
 
 struct io_uring_buf {
@@ -768,12 +831,40 @@ struct io_uring_buf_status {
 	__u32	resv[8];
 };
 
+enum io_uring_napi_op {
+	/* register/ungister backward compatible opcode */
+	IO_URING_NAPI_REGISTER_OP = 0,
+
+	/* opcodes to update napi_list when static tracking is used */
+	IO_URING_NAPI_STATIC_ADD_ID = 1,
+	IO_URING_NAPI_STATIC_DEL_ID = 2
+};
+
+enum io_uring_napi_tracking_strategy {
+	/* value must be 0 for backward compatibility */
+	IO_URING_NAPI_TRACKING_DYNAMIC = 0,
+	IO_URING_NAPI_TRACKING_STATIC = 1,
+	IO_URING_NAPI_TRACKING_INACTIVE = 255
+};
+
 /* argument for IORING_(UN)REGISTER_NAPI */
 struct io_uring_napi {
 	__u32	busy_poll_to;
 	__u8	prefer_busy_poll;
-	__u8	pad[3];
-	__u64	resv;
+
+	/* a io_uring_napi_op value */
+	__u8	opcode;
+	__u8	pad[2];
+
+	/*
+	 * for IO_URING_NAPI_REGISTER_OP, it is a
+	 * io_uring_napi_tracking_strategy value.
+	 *
+	 * for IO_URING_NAPI_STATIC_ADD_ID/IO_URING_NAPI_STATIC_DEL_ID
+	 * it is the napi id to add/del from napi_list.
+	 */
+	__u32	op_param;
+	__u32	resv;
 };
 
 /*
@@ -795,6 +886,29 @@ enum io_uring_register_restriction_op {
 	IORING_RESTRICTION_LAST
 };
 
+enum {
+	IORING_REG_WAIT_TS		= (1U << 0),
+};
+
+/*
+ * Argument for io_uring_enter(2) with
+ * IORING_GETEVENTS | IORING_ENTER_EXT_ARG_REG set, where the actual argument
+ * is an index into a previously registered fixed wait region described by
+ * the below structure.
+ */
+struct io_uring_reg_wait {
+	struct __kernel_timespec	ts;
+	__u32				min_wait_usec;
+	__u32				flags;
+	__u64				sigmask;
+	__u32				sigmask_sz;
+	__u32				pad[3];
+	__u64				pad2[2];
+};
+
+/*
+ * Argument for io_uring_enter(2) with IORING_GETEVENTS | IORING_ENTER_EXT_ARG
+ */
 struct io_uring_getevents_arg {
 	__u64	sigmask;
 	__u32	sigmask_sz;
diff --git a/original/uapi/linux/iommufd.h b/original/uapi/linux/iommufd.h
index 72010f7..78747b2 100644
--- a/original/uapi/linux/iommufd.h
+++ b/original/uapi/linux/iommufd.h
@@ -51,6 +51,10 @@ enum {
 	IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP = 0x8c,
 	IOMMUFD_CMD_HWPT_INVALIDATE = 0x8d,
 	IOMMUFD_CMD_FAULT_QUEUE_ALLOC = 0x8e,
+	IOMMUFD_CMD_IOAS_MAP_FILE = 0x8f,
+	IOMMUFD_CMD_VIOMMU_ALLOC = 0x90,
+	IOMMUFD_CMD_VDEVICE_ALLOC = 0x91,
+	IOMMUFD_CMD_IOAS_CHANGE_PROCESS = 0x92,
 };
 
 /**
@@ -213,6 +217,30 @@ struct iommu_ioas_map {
 };
 #define IOMMU_IOAS_MAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP)
 
+/**
+ * struct iommu_ioas_map_file - ioctl(IOMMU_IOAS_MAP_FILE)
+ * @size: sizeof(struct iommu_ioas_map_file)
+ * @flags: same as for iommu_ioas_map
+ * @ioas_id: same as for iommu_ioas_map
+ * @fd: the memfd to map
+ * @start: byte offset from start of file to map from
+ * @length: same as for iommu_ioas_map
+ * @iova: same as for iommu_ioas_map
+ *
+ * Set an IOVA mapping from a memfd file.  All other arguments and semantics
+ * match those of IOMMU_IOAS_MAP.
+ */
+struct iommu_ioas_map_file {
+	__u32 size;
+	__u32 flags;
+	__u32 ioas_id;
+	__s32 fd;
+	__aligned_u64 start;
+	__aligned_u64 length;
+	__aligned_u64 iova;
+};
+#define IOMMU_IOAS_MAP_FILE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP_FILE)
+
 /**
  * struct iommu_ioas_copy - ioctl(IOMMU_IOAS_COPY)
  * @size: sizeof(struct iommu_ioas_copy)
@@ -269,7 +297,7 @@ struct iommu_ioas_unmap {
  *                       ioctl(IOMMU_OPTION_HUGE_PAGES)
  * @IOMMU_OPTION_RLIMIT_MODE:
  *    Change how RLIMIT_MEMLOCK accounting works. The caller must have privilege
- *    to invoke this. Value 0 (default) is user based accouting, 1 uses process
+ *    to invoke this. Value 0 (default) is user based accounting, 1 uses process
  *    based accounting. Global option, object_id must be 0
  * @IOMMU_OPTION_HUGE_PAGES:
  *    Value 1 (default) allows contiguous pages to be combined when generating
@@ -359,11 +387,19 @@ struct iommu_vfio_ioas {
  *                                   enforced on device attachment
  * @IOMMU_HWPT_FAULT_ID_VALID: The fault_id field of hwpt allocation data is
  *                             valid.
+ * @IOMMU_HWPT_ALLOC_PASID: Requests a domain that can be used with PASID. The
+ *                          domain can be attached to any PASID on the device.
+ *                          Any domain attached to the non-PASID part of the
+ *                          device must also be flagged, otherwise attaching a
+ *                          PASID will blocked.
+ *                          If IOMMU does not support PASID it will return
+ *                          error (-EOPNOTSUPP).
  */
 enum iommufd_hwpt_alloc_flags {
 	IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
 	IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
 	IOMMU_HWPT_FAULT_ID_VALID = 1 << 2,
+	IOMMU_HWPT_ALLOC_PASID = 1 << 3,
 };
 
 /**
@@ -394,14 +430,36 @@ struct iommu_hwpt_vtd_s1 {
 	__u32 __reserved;
 };
 
+/**
+ * struct iommu_hwpt_arm_smmuv3 - ARM SMMUv3 nested STE
+ *                                (IOMMU_HWPT_DATA_ARM_SMMUV3)
+ *
+ * @ste: The first two double words of the user space Stream Table Entry for
+ *       the translation. Must be little-endian.
+ *       Allowed fields: (Refer to "5.2 Stream Table Entry" in SMMUv3 HW Spec)
+ *       - word-0: V, Cfg, S1Fmt, S1ContextPtr, S1CDMax
+ *       - word-1: EATS, S1DSS, S1CIR, S1COR, S1CSH, S1STALLD
+ *
+ * -EIO will be returned if @ste is not legal or contains any non-allowed field.
+ * Cfg can be used to select a S1, Bypass or Abort configuration. A Bypass
+ * nested domain will translate the same as the nesting parent. The S1 will
+ * install a Context Descriptor Table pointing at userspace memory translated
+ * by the nesting parent.
+ */
+struct iommu_hwpt_arm_smmuv3 {
+	__aligned_le64 ste[2];
+};
+
 /**
  * enum iommu_hwpt_data_type - IOMMU HWPT Data Type
  * @IOMMU_HWPT_DATA_NONE: no data
  * @IOMMU_HWPT_DATA_VTD_S1: Intel VT-d stage-1 page table
+ * @IOMMU_HWPT_DATA_ARM_SMMUV3: ARM SMMUv3 Context Descriptor Table
  */
 enum iommu_hwpt_data_type {
 	IOMMU_HWPT_DATA_NONE = 0,
 	IOMMU_HWPT_DATA_VTD_S1 = 1,
+	IOMMU_HWPT_DATA_ARM_SMMUV3 = 2,
 };
 
 /**
@@ -409,7 +467,7 @@ enum iommu_hwpt_data_type {
  * @size: sizeof(struct iommu_hwpt_alloc)
  * @flags: Combination of enum iommufd_hwpt_alloc_flags
  * @dev_id: The device to allocate this HWPT for
- * @pt_id: The IOAS or HWPT to connect this HWPT to
+ * @pt_id: The IOAS or HWPT or vIOMMU to connect this HWPT to
  * @out_hwpt_id: The ID of the new HWPT
  * @__reserved: Must be 0
  * @data_type: One of enum iommu_hwpt_data_type
@@ -428,11 +486,13 @@ enum iommu_hwpt_data_type {
  * IOMMU_HWPT_DATA_NONE. The HWPT can be allocated as a parent HWPT for a
  * nesting configuration by passing IOMMU_HWPT_ALLOC_NEST_PARENT via @flags.
  *
- * A user-managed nested HWPT will be created from a given parent HWPT via
- * @pt_id, in which the parent HWPT must be allocated previously via the
- * same ioctl from a given IOAS (@pt_id). In this case, the @data_type
- * must be set to a pre-defined type corresponding to an I/O page table
- * type supported by the underlying IOMMU hardware.
+ * A user-managed nested HWPT will be created from a given vIOMMU (wrapping a
+ * parent HWPT) or a parent HWPT via @pt_id, in which the parent HWPT must be
+ * allocated previously via the same ioctl from a given IOAS (@pt_id). In this
+ * case, the @data_type must be set to a pre-defined type corresponding to an
+ * I/O page table type supported by the underlying IOMMU hardware. The device
+ * via @dev_id and the vIOMMU via @pt_id must be associated to the same IOMMU
+ * instance.
  *
  * If the @data_type is set to IOMMU_HWPT_DATA_NONE, @data_len and
  * @data_uptr should be zero. Otherwise, both @data_len and @data_uptr
@@ -484,15 +544,59 @@ struct iommu_hw_info_vtd {
 	__aligned_u64 ecap_reg;
 };
 
+/**
+ * struct iommu_hw_info_arm_smmuv3 - ARM SMMUv3 hardware information
+ *                                   (IOMMU_HW_INFO_TYPE_ARM_SMMUV3)
+ *
+ * @flags: Must be set to 0
+ * @__reserved: Must be 0
+ * @idr: Implemented features for ARM SMMU Non-secure programming interface
+ * @iidr: Information about the implementation and implementer of ARM SMMU,
+ *        and architecture version supported
+ * @aidr: ARM SMMU architecture version
+ *
+ * For the details of @idr, @iidr and @aidr, please refer to the chapters
+ * from 6.3.1 to 6.3.6 in the SMMUv3 Spec.
+ *
+ * This reports the raw HW capability, and not all bits are meaningful to be
+ * read by userspace. Only the following fields should be used:
+ *
+ * idr[0]: ST_LEVEL, TERM_MODEL, STALL_MODEL, TTENDIAN , CD2L, ASID16, TTF
+ * idr[1]: SIDSIZE, SSIDSIZE
+ * idr[3]: BBML, RIL
+ * idr[5]: VAX, GRAN64K, GRAN16K, GRAN4K
+ *
+ * - S1P should be assumed to be true if a NESTED HWPT can be created
+ * - VFIO/iommufd only support platforms with COHACC, it should be assumed to be
+ *   true.
+ * - ATS is a per-device property. If the VMM describes any devices as ATS
+ *   capable in ACPI/DT it should set the corresponding idr.
+ *
+ * This list may expand in future (eg E0PD, AIE, PBHA, D128, DS etc). It is
+ * important that VMMs do not read bits outside the list to allow for
+ * compatibility with future kernels. Several features in the SMMUv3
+ * architecture are not currently supported by the kernel for nesting: HTTU,
+ * BTM, MPAM and others.
+ */
+struct iommu_hw_info_arm_smmuv3 {
+	__u32 flags;
+	__u32 __reserved;
+	__u32 idr[6];
+	__u32 iidr;
+	__u32 aidr;
+};
+
 /**
  * enum iommu_hw_info_type - IOMMU Hardware Info Types
  * @IOMMU_HW_INFO_TYPE_NONE: Used by the drivers that do not report hardware
  *                           info
  * @IOMMU_HW_INFO_TYPE_INTEL_VTD: Intel VT-d iommu info type
+ * @IOMMU_HW_INFO_TYPE_ARM_SMMUV3: ARM SMMUv3 iommu info type
  */
 enum iommu_hw_info_type {
 	IOMMU_HW_INFO_TYPE_NONE = 0,
 	IOMMU_HW_INFO_TYPE_INTEL_VTD = 1,
+	IOMMU_HW_INFO_TYPE_ARM_SMMUV3 = 2,
 };
 
 /**
@@ -627,9 +731,11 @@ struct iommu_hwpt_get_dirty_bitmap {
  * enum iommu_hwpt_invalidate_data_type - IOMMU HWPT Cache Invalidation
  *                                        Data Type
  * @IOMMU_HWPT_INVALIDATE_DATA_VTD_S1: Invalidation data for VTD_S1
+ * @IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3: Invalidation data for ARM SMMUv3
  */
 enum iommu_hwpt_invalidate_data_type {
 	IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0,
+	IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3 = 1,
 };
 
 /**
@@ -668,10 +774,32 @@ struct iommu_hwpt_vtd_s1_invalidate {
 	__u32 __reserved;
 };
 
+/**
+ * struct iommu_viommu_arm_smmuv3_invalidate - ARM SMMUv3 cache invalidation
+ *         (IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3)
+ * @cmd: 128-bit cache invalidation command that runs in SMMU CMDQ.
+ *       Must be little-endian.
+ *
+ * Supported command list only when passing in a vIOMMU via @hwpt_id:
+ *     CMDQ_OP_TLBI_NSNH_ALL
+ *     CMDQ_OP_TLBI_NH_VA
+ *     CMDQ_OP_TLBI_NH_VAA
+ *     CMDQ_OP_TLBI_NH_ALL
+ *     CMDQ_OP_TLBI_NH_ASID
+ *     CMDQ_OP_ATC_INV
+ *     CMDQ_OP_CFGI_CD
+ *     CMDQ_OP_CFGI_CD_ALL
+ *
+ * -EIO will be returned if the command is not supported.
+ */
+struct iommu_viommu_arm_smmuv3_invalidate {
+	__aligned_le64 cmd[2];
+};
+
 /**
  * struct iommu_hwpt_invalidate - ioctl(IOMMU_HWPT_INVALIDATE)
  * @size: sizeof(struct iommu_hwpt_invalidate)
- * @hwpt_id: ID of a nested HWPT for cache invalidation
+ * @hwpt_id: ID of a nested HWPT or a vIOMMU, for cache invalidation
  * @data_uptr: User pointer to an array of driver-specific cache invalidation
  *             data.
  * @data_type: One of enum iommu_hwpt_invalidate_data_type, defining the data
@@ -682,8 +810,11 @@ struct iommu_hwpt_vtd_s1_invalidate {
  *             Output the number of requests successfully handled by kernel.
  * @__reserved: Must be 0.
  *
- * Invalidate the iommu cache for user-managed page table. Modifications on a
- * user-managed page table should be followed by this operation to sync cache.
+ * Invalidate iommu cache for user-managed page table or vIOMMU. Modifications
+ * on a user-managed page table should be followed by this operation, if a HWPT
+ * is passed in via @hwpt_id. Other caches, such as device cache or descriptor
+ * cache can be flushed if a vIOMMU is passed in via the @hwpt_id field.
+ *
  * Each ioctl can support one or more cache invalidation requests in the array
  * that has a total size of @entry_len * @entry_num.
  *
@@ -737,6 +868,7 @@ enum iommu_hwpt_pgfault_perm {
  * @pasid: Process Address Space ID
  * @grpid: Page Request Group Index
  * @perm: Combination of enum iommu_hwpt_pgfault_perm
+ * @__reserved: Must be 0.
  * @addr: Fault address
  * @length: a hint of how much data the requestor is expecting to fetch. For
  *          example, if the PRI initiator knows it is going to do a 10MB
@@ -752,7 +884,8 @@ struct iommu_hwpt_pgfault {
 	__u32 pasid;
 	__u32 grpid;
 	__u32 perm;
-	__u64 addr;
+	__u32 __reserved;
+	__aligned_u64 addr;
 	__u32 length;
 	__u32 cookie;
 };
@@ -797,4 +930,88 @@ struct iommu_fault_alloc {
 	__u32 out_fault_fd;
 };
 #define IOMMU_FAULT_QUEUE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_FAULT_QUEUE_ALLOC)
+
+/**
+ * enum iommu_viommu_type - Virtual IOMMU Type
+ * @IOMMU_VIOMMU_TYPE_DEFAULT: Reserved for future use
+ * @IOMMU_VIOMMU_TYPE_ARM_SMMUV3: ARM SMMUv3 driver specific type
+ */
+enum iommu_viommu_type {
+	IOMMU_VIOMMU_TYPE_DEFAULT = 0,
+	IOMMU_VIOMMU_TYPE_ARM_SMMUV3 = 1,
+};
+
+/**
+ * struct iommu_viommu_alloc - ioctl(IOMMU_VIOMMU_ALLOC)
+ * @size: sizeof(struct iommu_viommu_alloc)
+ * @flags: Must be 0
+ * @type: Type of the virtual IOMMU. Must be defined in enum iommu_viommu_type
+ * @dev_id: The device's physical IOMMU will be used to back the virtual IOMMU
+ * @hwpt_id: ID of a nesting parent HWPT to associate to
+ * @out_viommu_id: Output virtual IOMMU ID for the allocated object
+ *
+ * Allocate a virtual IOMMU object, representing the underlying physical IOMMU's
+ * virtualization support that is a security-isolated slice of the real IOMMU HW
+ * that is unique to a specific VM. Operations global to the IOMMU are connected
+ * to the vIOMMU, such as:
+ * - Security namespace for guest owned ID, e.g. guest-controlled cache tags
+ * - Non-device-affiliated event reporting, e.g. invalidation queue errors
+ * - Access to a sharable nesting parent pagetable across physical IOMMUs
+ * - Virtualization of various platforms IDs, e.g. RIDs and others
+ * - Delivery of paravirtualized invalidation
+ * - Direct assigned invalidation queues
+ * - Direct assigned interrupts
+ */
+struct iommu_viommu_alloc {
+	__u32 size;
+	__u32 flags;
+	__u32 type;
+	__u32 dev_id;
+	__u32 hwpt_id;
+	__u32 out_viommu_id;
+};
+#define IOMMU_VIOMMU_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VIOMMU_ALLOC)
+
+/**
+ * struct iommu_vdevice_alloc - ioctl(IOMMU_VDEVICE_ALLOC)
+ * @size: sizeof(struct iommu_vdevice_alloc)
+ * @viommu_id: vIOMMU ID to associate with the virtual device
+ * @dev_id: The physical device to allocate a virtual instance on the vIOMMU
+ * @out_vdevice_id: Object handle for the vDevice. Pass to IOMMU_DESTORY
+ * @virt_id: Virtual device ID per vIOMMU, e.g. vSID of ARM SMMUv3, vDeviceID
+ *           of AMD IOMMU, and vRID of a nested Intel VT-d to a Context Table
+ *
+ * Allocate a virtual device instance (for a physical device) against a vIOMMU.
+ * This instance holds the device's information (related to its vIOMMU) in a VM.
+ */
+struct iommu_vdevice_alloc {
+	__u32 size;
+	__u32 viommu_id;
+	__u32 dev_id;
+	__u32 out_vdevice_id;
+	__aligned_u64 virt_id;
+};
+#define IOMMU_VDEVICE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VDEVICE_ALLOC)
+
+/**
+ * struct iommu_ioas_change_process - ioctl(VFIO_IOAS_CHANGE_PROCESS)
+ * @size: sizeof(struct iommu_ioas_change_process)
+ * @__reserved: Must be 0
+ *
+ * This transfers pinned memory counts for every memory map in every IOAS
+ * in the context to the current process.  This only supports maps created
+ * with IOMMU_IOAS_MAP_FILE, and returns EINVAL if other maps are present.
+ * If the ioctl returns a failure status, then nothing is changed.
+ *
+ * This API is useful for transferring operation of a device from one process
+ * to another, such as during userland live update.
+ */
+struct iommu_ioas_change_process {
+	__u32 size;
+	__u32 __reserved;
+};
+
+#define IOMMU_IOAS_CHANGE_PROCESS \
+	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_CHANGE_PROCESS)
+
 #endif
diff --git a/original/uapi/linux/ip.h b/original/uapi/linux/ip.h
index 283dec7..5bd7ce9 100644
--- a/original/uapi/linux/ip.h
+++ b/original/uapi/linux/ip.h
@@ -137,6 +137,22 @@ struct ip_beet_phdr {
 	__u8 reserved;
 };
 
+struct ip_iptfs_hdr {
+	__u8 subtype;		/* 0*: basic, 1: CC */
+	__u8 flags;
+	__be16 block_offset;
+};
+
+struct ip_iptfs_cc_hdr {
+	__u8 subtype;		/* 0: basic, 1*: CC */
+	__u8 flags;
+	__be16 block_offset;
+	__be32 loss_rate;
+	__be64 rtt_adelay_xdelay;
+	__be32 tval;
+	__be32 techo;
+};
+
 /* index values for the variables in ipv4_devconf */
 enum
 {
diff --git a/original/uapi/linux/ipsec.h b/original/uapi/linux/ipsec.h
index 50d8ee1..696b790 100644
--- a/original/uapi/linux/ipsec.h
+++ b/original/uapi/linux/ipsec.h
@@ -14,7 +14,8 @@ enum {
 	IPSEC_MODE_ANY		= 0,	/* We do not support this for SA */
 	IPSEC_MODE_TRANSPORT	= 1,
 	IPSEC_MODE_TUNNEL	= 2,
-	IPSEC_MODE_BEET         = 3
+	IPSEC_MODE_BEET         = 3,
+	IPSEC_MODE_IPTFS        = 4
 };
 
 enum {
diff --git a/original/uapi/linux/kfd_ioctl.h b/original/uapi/linux/kfd_ioctl.h
index 717307d..fa9f984 100644
--- a/original/uapi/linux/kfd_ioctl.h
+++ b/original/uapi/linux/kfd_ioctl.h
@@ -609,6 +609,7 @@ struct kfd_ioctl_smi_events_args {
  *    migrate_update: GPU page fault is recovered by 'M' for migrate, 'U' for update
  *    rw: 'W' for write page fault, 'R' for read page fault
  *    rescheduled: 'R' if the queue restore failed and rescheduled to try again
+ *    error_code: migrate failure error code, 0 if no error
  */
 #define KFD_EVENT_FMT_UPDATE_GPU_RESET(reset_seq_num, reset_cause)\
 		"%x %s\n", (reset_seq_num), (reset_cause)
@@ -630,9 +631,9 @@ struct kfd_ioctl_smi_events_args {
 		"%lld -%d @%lx(%lx) %x->%x %x:%x %d\n", (ns), (pid), (start), (size),\
 		(from), (to), (prefetch_loc), (preferred_loc), (migrate_trigger)
 
-#define KFD_EVENT_FMT_MIGRATE_END(ns, pid, start, size, from, to, migrate_trigger)\
-		"%lld -%d @%lx(%lx) %x->%x %d\n", (ns), (pid), (start), (size),\
-		(from), (to), (migrate_trigger)
+#define KFD_EVENT_FMT_MIGRATE_END(ns, pid, start, size, from, to, migrate_trigger, error_code) \
+		"%lld -%d @%lx(%lx) %x->%x %d %d\n", (ns), (pid), (start), (size),\
+		(from), (to), (migrate_trigger), (error_code)
 
 #define KFD_EVENT_FMT_QUEUE_EVICTION(ns, pid, node, evict_trigger)\
 		"%lld -%d %x %d\n", (ns), (pid), (node), (evict_trigger)
diff --git a/original/uapi/linux/kfd_sysfs.h b/original/uapi/linux/kfd_sysfs.h
index 5e8d286..859b8e9 100644
--- a/original/uapi/linux/kfd_sysfs.h
+++ b/original/uapi/linux/kfd_sysfs.h
@@ -60,7 +60,8 @@
 #define HSA_CAP_FLAGS_COHERENTHOSTACCESS			0x10000000
 #define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED			0x20000000
 #define HSA_CAP_TRAP_DEBUG_PRECISE_ALU_OPERATIONS_SUPPORTED	0x40000000
-#define HSA_CAP_RESERVED					0x800f8000
+#define HSA_CAP_PER_QUEUE_RESET_SUPPORTED			0x80000000
+#define HSA_CAP_RESERVED					0x000f8000
 
 /* debug_prop bits in node properties */
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_MASK     0x0000000f
diff --git a/original/uapi/linux/kvm.h b/original/uapi/linux/kvm.h
index 637efc0..45e6d8f 100644
--- a/original/uapi/linux/kvm.h
+++ b/original/uapi/linux/kvm.h
@@ -617,10 +617,6 @@ struct kvm_ioeventfd {
 #define KVM_X86_DISABLE_EXITS_HLT            (1 << 1)
 #define KVM_X86_DISABLE_EXITS_PAUSE          (1 << 2)
 #define KVM_X86_DISABLE_EXITS_CSTATE         (1 << 3)
-#define KVM_X86_DISABLE_VALID_EXITS          (KVM_X86_DISABLE_EXITS_MWAIT | \
-                                              KVM_X86_DISABLE_EXITS_HLT | \
-                                              KVM_X86_DISABLE_EXITS_PAUSE | \
-                                              KVM_X86_DISABLE_EXITS_CSTATE)
 
 /* for KVM_ENABLE_CAP */
 struct kvm_enable_cap {
@@ -1070,6 +1066,10 @@ struct kvm_dirty_tlb {
 
 #define KVM_REG_SIZE_SHIFT	52
 #define KVM_REG_SIZE_MASK	0x00f0000000000000ULL
+
+#define KVM_REG_SIZE(id)		\
+	(1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
+
 #define KVM_REG_SIZE_U8		0x0000000000000000ULL
 #define KVM_REG_SIZE_U16	0x0010000000000000ULL
 #define KVM_REG_SIZE_U32	0x0020000000000000ULL
@@ -1158,7 +1158,15 @@ enum kvm_device_type {
 #define KVM_DEV_TYPE_ARM_PV_TIME	KVM_DEV_TYPE_ARM_PV_TIME
 	KVM_DEV_TYPE_RISCV_AIA,
 #define KVM_DEV_TYPE_RISCV_AIA		KVM_DEV_TYPE_RISCV_AIA
+	KVM_DEV_TYPE_LOONGARCH_IPI,
+#define KVM_DEV_TYPE_LOONGARCH_IPI	KVM_DEV_TYPE_LOONGARCH_IPI
+	KVM_DEV_TYPE_LOONGARCH_EIOINTC,
+#define KVM_DEV_TYPE_LOONGARCH_EIOINTC	KVM_DEV_TYPE_LOONGARCH_EIOINTC
+	KVM_DEV_TYPE_LOONGARCH_PCHPIC,
+#define KVM_DEV_TYPE_LOONGARCH_PCHPIC	KVM_DEV_TYPE_LOONGARCH_PCHPIC
+
 	KVM_DEV_TYPE_MAX,
+
 };
 
 struct kvm_vfio_spapr_tce {
diff --git a/original/uapi/linux/landlock.h b/original/uapi/linux/landlock.h
index 3374564..e1d2c27 100644
--- a/original/uapi/linux/landlock.h
+++ b/original/uapi/linux/landlock.h
@@ -268,7 +268,9 @@ struct landlock_net_port_attr {
  * ~~~~~~~~~~~~~~~~
  *
  * These flags enable to restrict a sandboxed process to a set of network
- * actions. This is supported since the Landlock ABI version 4.
+ * actions.
+ *
+ * This is supported since Landlock ABI version 4.
  *
  * The following access rights apply to TCP port numbers:
  *
@@ -291,11 +293,13 @@ struct landlock_net_port_attr {
  * Setting a flag for a ruleset will isolate the Landlock domain to forbid
  * connections to resources outside the domain.
  *
+ * This is supported since Landlock ABI version 6.
+ *
  * Scopes:
  *
  * - %LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: Restrict a sandboxed process from
  *   connecting to an abstract UNIX socket created by a process outside the
- *   related Landlock domain (e.g. a parent domain or a non-sandboxed process).
+ *   related Landlock domain (e.g., a parent domain or a non-sandboxed process).
  * - %LANDLOCK_SCOPE_SIGNAL: Restrict a sandboxed process from sending a signal
  *   to another process outside the domain.
  */
diff --git a/original/uapi/linux/mdio.h b/original/uapi/linux/mdio.h
index f0d3f26..6975f18 100644
--- a/original/uapi/linux/mdio.h
+++ b/original/uapi/linux/mdio.h
@@ -125,6 +125,7 @@
 #define MDIO_STAT1_LPOWERABLE		0x0002	/* Low-power ability */
 #define MDIO_STAT1_LSTATUS		BMSR_LSTATUS
 #define MDIO_STAT1_FAULT		0x0080	/* Fault */
+#define MDIO_PCS_STAT1_CLKSTOP_CAP	0x0040
 #define MDIO_AN_STAT1_LPABLE		0x0001	/* Link partner AN ability */
 #define MDIO_AN_STAT1_ABLE		BMSR_ANEGCAPABLE
 #define MDIO_AN_STAT1_RFAULT		BMSR_RFAULT
diff --git a/original/uapi/linux/media-bus-format.h b/original/uapi/linux/media-bus-format.h
index d4c1d99..ff62056 100644
--- a/original/uapi/linux/media-bus-format.h
+++ b/original/uapi/linux/media-bus-format.h
@@ -34,7 +34,7 @@
 
 #define MEDIA_BUS_FMT_FIXED			0x0001
 
-/* RGB - next is	0x1026 */
+/* RGB - next is	0x1028 */
 #define MEDIA_BUS_FMT_RGB444_1X12		0x1016
 #define MEDIA_BUS_FMT_RGB444_2X8_PADHI_BE	0x1001
 #define MEDIA_BUS_FMT_RGB444_2X8_PADHI_LE	0x1002
@@ -68,6 +68,8 @@
 #define MEDIA_BUS_FMT_ARGB8888_1X32		0x100d
 #define MEDIA_BUS_FMT_RGB888_1X32_PADHI		0x100f
 #define MEDIA_BUS_FMT_RGB101010_1X30		0x1018
+#define MEDIA_BUS_FMT_RGB101010_1X7X5_SPWG	0x1026
+#define MEDIA_BUS_FMT_RGB101010_1X7X5_JEIDA	0x1027
 #define MEDIA_BUS_FMT_RGB666_1X36_CPADLO	0x1020
 #define MEDIA_BUS_FMT_RGB888_1X36_CPADLO	0x1021
 #define MEDIA_BUS_FMT_RGB121212_1X36		0x1019
diff --git a/original/uapi/linux/media/raspberrypi/pisp_fe_config.h b/original/uapi/linux/media/raspberrypi/pisp_fe_config.h
new file mode 100644
index 0000000..7723746
--- /dev/null
+++ b/original/uapi/linux/media/raspberrypi/pisp_fe_config.h
@@ -0,0 +1,273 @@
+/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
+/*
+ * RP1 PiSP Front End Driver Configuration structures
+ *
+ * Copyright (C) 2021 - Raspberry Pi Ltd.
+ *
+ */
+#ifndef _UAPI_PISP_FE_CONFIG_
+#define _UAPI_PISP_FE_CONFIG_
+
+#include <linux/types.h>
+
+#include "pisp_common.h"
+#include "pisp_fe_statistics.h"
+
+#define PISP_FE_NUM_OUTPUTS 2
+
+enum pisp_fe_enable {
+	PISP_FE_ENABLE_INPUT = 0x000001,
+	PISP_FE_ENABLE_DECOMPRESS = 0x000002,
+	PISP_FE_ENABLE_DECOMPAND = 0x000004,
+	PISP_FE_ENABLE_BLA = 0x000008,
+	PISP_FE_ENABLE_DPC = 0x000010,
+	PISP_FE_ENABLE_STATS_CROP = 0x000020,
+	PISP_FE_ENABLE_DECIMATE = 0x000040,
+	PISP_FE_ENABLE_BLC = 0x000080,
+	PISP_FE_ENABLE_CDAF_STATS = 0x000100,
+	PISP_FE_ENABLE_AWB_STATS = 0x000200,
+	PISP_FE_ENABLE_RGBY = 0x000400,
+	PISP_FE_ENABLE_LSC = 0x000800,
+	PISP_FE_ENABLE_AGC_STATS = 0x001000,
+	PISP_FE_ENABLE_CROP0 = 0x010000,
+	PISP_FE_ENABLE_DOWNSCALE0 = 0x020000,
+	PISP_FE_ENABLE_COMPRESS0 = 0x040000,
+	PISP_FE_ENABLE_OUTPUT0 = 0x080000,
+	PISP_FE_ENABLE_CROP1 = 0x100000,
+	PISP_FE_ENABLE_DOWNSCALE1 = 0x200000,
+	PISP_FE_ENABLE_COMPRESS1 = 0x400000,
+	PISP_FE_ENABLE_OUTPUT1 = 0x800000
+};
+
+#define PISP_FE_ENABLE_CROP(i) (PISP_FE_ENABLE_CROP0 << (4 * (i)))
+#define PISP_FE_ENABLE_DOWNSCALE(i) (PISP_FE_ENABLE_DOWNSCALE0 << (4 * (i)))
+#define PISP_FE_ENABLE_COMPRESS(i) (PISP_FE_ENABLE_COMPRESS0 << (4 * (i)))
+#define PISP_FE_ENABLE_OUTPUT(i) (PISP_FE_ENABLE_OUTPUT0 << (4 * (i)))
+
+/*
+ * We use the enable flags to show when blocks are "dirty", but we need some
+ * extra ones too.
+ */
+enum pisp_fe_dirty {
+	PISP_FE_DIRTY_GLOBAL = 0x0001,
+	PISP_FE_DIRTY_FLOATING = 0x0002,
+	PISP_FE_DIRTY_OUTPUT_AXI = 0x0004
+};
+
+struct pisp_fe_global_config {
+	__u32 enables;
+	__u8 bayer_order;
+	__u8 pad[3];
+} __attribute__((packed));
+
+struct pisp_fe_input_axi_config {
+	/* burst length minus one, in the range 0..15; OR'd with flags */
+	__u8 maxlen_flags;
+	/* { prot[2:0], cache[3:0] } fields */
+	__u8 cache_prot;
+	/* QoS (only 4 LS bits are used) */
+	__u16 qos;
+} __attribute__((packed));
+
+struct pisp_fe_output_axi_config {
+	/* burst length minus one, in the range 0..15; OR'd with flags */
+	__u8 maxlen_flags;
+	/* { prot[2:0], cache[3:0] } fields */
+	__u8 cache_prot;
+	/* QoS (4 bitfields of 4 bits each for different panic levels) */
+	__u16 qos;
+	/*  For Panic mode: Output FIFO panic threshold */
+	__u16 thresh;
+	/*  For Panic mode: Output FIFO statistics throttle threshold */
+	__u16 throttle;
+} __attribute__((packed));
+
+struct pisp_fe_input_config {
+	__u8 streaming;
+	__u8 pad[3];
+	struct pisp_image_format_config format;
+	struct pisp_fe_input_axi_config axi;
+	/* Extra cycles delay before issuing each burst request */
+	__u8 holdoff;
+	__u8 pad2[3];
+} __attribute__((packed));
+
+struct pisp_fe_output_config {
+	struct pisp_image_format_config format;
+	__u16 ilines;
+	__u8 pad[2];
+} __attribute__((packed));
+
+struct pisp_fe_input_buffer_config {
+	__u32 addr_lo;
+	__u32 addr_hi;
+	__u16 frame_id;
+	__u16 pad;
+} __attribute__((packed));
+
+#define PISP_FE_DECOMPAND_LUT_SIZE 65
+
+struct pisp_fe_decompand_config {
+	__u16 lut[PISP_FE_DECOMPAND_LUT_SIZE];
+	__u16 pad;
+} __attribute__((packed));
+
+struct pisp_fe_dpc_config {
+	__u8 coeff_level;
+	__u8 coeff_range;
+	__u8 coeff_range2;
+#define PISP_FE_DPC_FLAG_FOLDBACK 1
+#define PISP_FE_DPC_FLAG_VFLAG 2
+	__u8 flags;
+} __attribute__((packed));
+
+#define PISP_FE_LSC_LUT_SIZE 16
+
+struct pisp_fe_lsc_config {
+	__u8 shift;
+	__u8 pad0;
+	__u16 scale;
+	__u16 centre_x;
+	__u16 centre_y;
+	__u16 lut[PISP_FE_LSC_LUT_SIZE];
+} __attribute__((packed));
+
+struct pisp_fe_rgby_config {
+	__u16 gain_r;
+	__u16 gain_g;
+	__u16 gain_b;
+	__u8 maxflag;
+	__u8 pad;
+} __attribute__((packed));
+
+struct pisp_fe_agc_stats_config {
+	__u16 offset_x;
+	__u16 offset_y;
+	__u16 size_x;
+	__u16 size_y;
+	/* each weight only 4 bits */
+	__u8 weights[PISP_AGC_STATS_NUM_ZONES / 2];
+	__u16 row_offset_x;
+	__u16 row_offset_y;
+	__u16 row_size_x;
+	__u16 row_size_y;
+	__u8 row_shift;
+	__u8 float_shift;
+	__u8 pad1[2];
+} __attribute__((packed));
+
+struct pisp_fe_awb_stats_config {
+	__u16 offset_x;
+	__u16 offset_y;
+	__u16 size_x;
+	__u16 size_y;
+	__u8 shift;
+	__u8 pad[3];
+	__u16 r_lo;
+	__u16 r_hi;
+	__u16 g_lo;
+	__u16 g_hi;
+	__u16 b_lo;
+	__u16 b_hi;
+} __attribute__((packed));
+
+struct pisp_fe_floating_stats_region {
+	__u16 offset_x;
+	__u16 offset_y;
+	__u16 size_x;
+	__u16 size_y;
+} __attribute__((packed));
+
+struct pisp_fe_floating_stats_config {
+	struct pisp_fe_floating_stats_region
+		regions[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+
+#define PISP_FE_CDAF_NUM_WEIGHTS 8
+
+struct pisp_fe_cdaf_stats_config {
+	__u16 noise_constant;
+	__u16 noise_slope;
+	__u16 offset_x;
+	__u16 offset_y;
+	__u16 size_x;
+	__u16 size_y;
+	__u16 skip_x;
+	__u16 skip_y;
+	__u32 mode;
+} __attribute__((packed));
+
+struct pisp_fe_stats_buffer_config {
+	__u32 addr_lo;
+	__u32 addr_hi;
+} __attribute__((packed));
+
+struct pisp_fe_crop_config {
+	__u16 offset_x;
+	__u16 offset_y;
+	__u16 width;
+	__u16 height;
+} __attribute__((packed));
+
+enum pisp_fe_downscale_flags {
+	/* downscale the four Bayer components independently... */
+	DOWNSCALE_BAYER = 1,
+	/* ...without trying to preserve their spatial relationship */
+	DOWNSCALE_BIN = 2,
+};
+
+struct pisp_fe_downscale_config {
+	__u8 xin;
+	__u8 xout;
+	__u8 yin;
+	__u8 yout;
+	__u8 flags; /* enum pisp_fe_downscale_flags */
+	__u8 pad[3];
+	__u16 output_width;
+	__u16 output_height;
+} __attribute__((packed));
+
+struct pisp_fe_output_buffer_config {
+	__u32 addr_lo;
+	__u32 addr_hi;
+} __attribute__((packed));
+
+/* Each of the two output channels/branches: */
+struct pisp_fe_output_branch_config {
+	struct pisp_fe_crop_config crop;
+	struct pisp_fe_downscale_config downscale;
+	struct pisp_compress_config compress;
+	struct pisp_fe_output_config output;
+	__u32 pad;
+} __attribute__((packed));
+
+/* And finally one to rule them all: */
+struct pisp_fe_config {
+	/* I/O configuration: */
+	struct pisp_fe_stats_buffer_config stats_buffer;
+	struct pisp_fe_output_buffer_config output_buffer[PISP_FE_NUM_OUTPUTS];
+	struct pisp_fe_input_buffer_config input_buffer;
+	/* processing configuration: */
+	struct pisp_fe_global_config global;
+	struct pisp_fe_input_config input;
+	struct pisp_decompress_config decompress;
+	struct pisp_fe_decompand_config decompand;
+	struct pisp_bla_config bla;
+	struct pisp_fe_dpc_config dpc;
+	struct pisp_fe_crop_config stats_crop;
+	__u32 spare1; /* placeholder for future decimate configuration */
+	struct pisp_bla_config blc;
+	struct pisp_fe_rgby_config rgby;
+	struct pisp_fe_lsc_config lsc;
+	struct pisp_fe_agc_stats_config agc_stats;
+	struct pisp_fe_awb_stats_config awb_stats;
+	struct pisp_fe_cdaf_stats_config cdaf_stats;
+	struct pisp_fe_floating_stats_config floating_stats;
+	struct pisp_fe_output_axi_config output_axi;
+	struct pisp_fe_output_branch_config ch[PISP_FE_NUM_OUTPUTS];
+	/* non-register fields: */
+	__u32 dirty_flags; /* these use pisp_fe_enable */
+	__u32 dirty_flags_extra; /* these use pisp_fe_dirty */
+} __attribute__((packed));
+
+#endif /* _UAPI_PISP_FE_CONFIG_ */
diff --git a/original/uapi/linux/media/raspberrypi/pisp_fe_statistics.h b/original/uapi/linux/media/raspberrypi/pisp_fe_statistics.h
new file mode 100644
index 0000000..a7d4298
--- /dev/null
+++ b/original/uapi/linux/media/raspberrypi/pisp_fe_statistics.h
@@ -0,0 +1,64 @@
+/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
+/*
+ * RP1 PiSP Front End statistics definitions
+ *
+ * Copyright (C) 2021 - Raspberry Pi Ltd.
+ *
+ */
+#ifndef _UAPI_PISP_FE_STATISTICS_H_
+#define _UAPI_PISP_FE_STATISTICS_H_
+
+#include <linux/types.h>
+
+#define PISP_FLOATING_STATS_NUM_ZONES 4
+#define PISP_AGC_STATS_NUM_BINS 1024
+#define PISP_AGC_STATS_SIZE 16
+#define PISP_AGC_STATS_NUM_ZONES (PISP_AGC_STATS_SIZE * PISP_AGC_STATS_SIZE)
+#define PISP_AGC_STATS_NUM_ROW_SUMS 512
+
+struct pisp_agc_statistics_zone {
+	__u64 Y_sum;
+	__u32 counted;
+	__u32 pad;
+} __attribute__((packed));
+
+struct pisp_agc_statistics {
+	__u32 row_sums[PISP_AGC_STATS_NUM_ROW_SUMS];
+	/*
+	 * 32-bits per bin means an image (just less than) 16384x16384 pixels
+	 * in size can weight every pixel from 0 to 15.
+	 */
+	__u32 histogram[PISP_AGC_STATS_NUM_BINS];
+	struct pisp_agc_statistics_zone floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+
+#define PISP_AWB_STATS_SIZE 32
+#define PISP_AWB_STATS_NUM_ZONES (PISP_AWB_STATS_SIZE * PISP_AWB_STATS_SIZE)
+
+struct pisp_awb_statistics_zone {
+	__u32 R_sum;
+	__u32 G_sum;
+	__u32 B_sum;
+	__u32 counted;
+} __attribute__((packed));
+
+struct pisp_awb_statistics {
+	struct pisp_awb_statistics_zone zones[PISP_AWB_STATS_NUM_ZONES];
+	struct pisp_awb_statistics_zone floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+
+#define PISP_CDAF_STATS_SIZE 8
+#define PISP_CDAF_STATS_NUM_FOMS (PISP_CDAF_STATS_SIZE * PISP_CDAF_STATS_SIZE)
+
+struct pisp_cdaf_statistics {
+	__u64 foms[PISP_CDAF_STATS_NUM_FOMS];
+	__u64 floating[PISP_FLOATING_STATS_NUM_ZONES];
+} __attribute__((packed));
+
+struct pisp_statistics {
+	struct pisp_awb_statistics awb;
+	struct pisp_agc_statistics agc;
+	struct pisp_cdaf_statistics cdaf;
+} __attribute__((packed));
+
+#endif /* _UAPI_PISP_FE_STATISTICS_H_ */
diff --git a/original/uapi/linux/mount.h b/original/uapi/linux/mount.h
index 225bc36..c070088 100644
--- a/original/uapi/linux/mount.h
+++ b/original/uapi/linux/mount.h
@@ -154,7 +154,7 @@ struct mount_attr {
  */
 struct statmount {
 	__u32 size;		/* Total size, including strings */
-	__u32 mnt_opts;		/* [str] Mount options of the mount */
+	__u32 mnt_opts;		/* [str] Options (comma separated, escaped) */
 	__u64 mask;		/* What results were written */
 	__u32 sb_dev_major;	/* Device ID */
 	__u32 sb_dev_minor;
@@ -173,7 +173,13 @@ struct statmount {
 	__u32 mnt_root;		/* [str] Root of mount relative to root of fs */
 	__u32 mnt_point;	/* [str] Mountpoint relative to current root */
 	__u64 mnt_ns_id;	/* ID of the mount namespace */
-	__u64 __spare2[49];
+	__u32 fs_subtype;	/* [str] Subtype of fs_type (if any) */
+	__u32 sb_source;	/* [str] Source string of the mount */
+	__u32 opt_num;		/* Number of fs options */
+	__u32 opt_array;	/* [str] Array of nul terminated fs options */
+	__u32 opt_sec_num;	/* Number of security options */
+	__u32 opt_sec_array;	/* [str] Array of nul terminated security options */
+	__u64 __spare2[46];
 	char str[];		/* Variable size part containing strings */
 };
 
@@ -207,6 +213,10 @@ struct mnt_id_req {
 #define STATMOUNT_FS_TYPE		0x00000020U	/* Want/got fs_type */
 #define STATMOUNT_MNT_NS_ID		0x00000040U	/* Want/got mnt_ns_id */
 #define STATMOUNT_MNT_OPTS		0x00000080U	/* Want/got mnt_opts */
+#define STATMOUNT_FS_SUBTYPE		0x00000100U	/* Want/got fs_subtype */
+#define STATMOUNT_SB_SOURCE		0x00000200U	/* Want/got sb_source */
+#define STATMOUNT_OPT_ARRAY		0x00000400U	/* Want/got opt_... */
+#define STATMOUNT_OPT_SEC_ARRAY		0x00000800U	/* Want/got opt_sec... */
 
 /*
  * Special @mnt_id values that can be passed to listmount
diff --git a/original/uapi/linux/mptcp_pm.h b/original/uapi/linux/mptcp_pm.h
index 50589e5..84fa8a2 100644
--- a/original/uapi/linux/mptcp_pm.h
+++ b/original/uapi/linux/mptcp_pm.h
@@ -12,31 +12,33 @@
 /**
  * enum mptcp_event_type
  * @MPTCP_EVENT_UNSPEC: unused event
- * @MPTCP_EVENT_CREATED: token, family, saddr4 | saddr6, daddr4 | daddr6,
- *   sport, dport A new MPTCP connection has been created. It is the good time
- *   to allocate memory and send ADD_ADDR if needed. Depending on the
+ * @MPTCP_EVENT_CREATED: A new MPTCP connection has been created. It is the
+ *   good time to allocate memory and send ADD_ADDR if needed. Depending on the
  *   traffic-patterns it can take a long time until the MPTCP_EVENT_ESTABLISHED
- *   is sent.
- * @MPTCP_EVENT_ESTABLISHED: token, family, saddr4 | saddr6, daddr4 | daddr6,
- *   sport, dport A MPTCP connection is established (can start new subflows).
- * @MPTCP_EVENT_CLOSED: token A MPTCP connection has stopped.
- * @MPTCP_EVENT_ANNOUNCED: token, rem_id, family, daddr4 | daddr6 [, dport] A
- *   new address has been announced by the peer.
- * @MPTCP_EVENT_REMOVED: token, rem_id An address has been lost by the peer.
- * @MPTCP_EVENT_SUB_ESTABLISHED: token, family, loc_id, rem_id, saddr4 |
- *   saddr6, daddr4 | daddr6, sport, dport, backup, if_idx [, error] A new
- *   subflow has been established. 'error' should not be set.
- * @MPTCP_EVENT_SUB_CLOSED: token, family, loc_id, rem_id, saddr4 | saddr6,
- *   daddr4 | daddr6, sport, dport, backup, if_idx [, error] A subflow has been
- *   closed. An error (copy of sk_err) could be set if an error has been
- *   detected for this subflow.
- * @MPTCP_EVENT_SUB_PRIORITY: token, family, loc_id, rem_id, saddr4 | saddr6,
- *   daddr4 | daddr6, sport, dport, backup, if_idx [, error] The priority of a
- *   subflow has changed. 'error' should not be set.
- * @MPTCP_EVENT_LISTENER_CREATED: family, sport, saddr4 | saddr6 A new PM
- *   listener is created.
- * @MPTCP_EVENT_LISTENER_CLOSED: family, sport, saddr4 | saddr6 A PM listener
- *   is closed.
+ *   is sent. Attributes: token, family, saddr4 | saddr6, daddr4 | daddr6,
+ *   sport, dport, server-side.
+ * @MPTCP_EVENT_ESTABLISHED: A MPTCP connection is established (can start new
+ *   subflows). Attributes: token, family, saddr4 | saddr6, daddr4 | daddr6,
+ *   sport, dport, server-side.
+ * @MPTCP_EVENT_CLOSED: A MPTCP connection has stopped. Attribute: token.
+ * @MPTCP_EVENT_ANNOUNCED: A new address has been announced by the peer.
+ *   Attributes: token, rem_id, family, daddr4 | daddr6 [, dport].
+ * @MPTCP_EVENT_REMOVED: An address has been lost by the peer. Attributes:
+ *   token, rem_id.
+ * @MPTCP_EVENT_SUB_ESTABLISHED: A new subflow has been established. 'error'
+ *   should not be set. Attributes: token, family, loc_id, rem_id, saddr4 |
+ *   saddr6, daddr4 | daddr6, sport, dport, backup, if_idx [, error].
+ * @MPTCP_EVENT_SUB_CLOSED: A subflow has been closed. An error (copy of
+ *   sk_err) could be set if an error has been detected for this subflow.
+ *   Attributes: token, family, loc_id, rem_id, saddr4 | saddr6, daddr4 |
+ *   daddr6, sport, dport, backup, if_idx [, error].
+ * @MPTCP_EVENT_SUB_PRIORITY: The priority of a subflow has changed. 'error'
+ *   should not be set. Attributes: token, family, loc_id, rem_id, saddr4 |
+ *   saddr6, daddr4 | daddr6, sport, dport, backup, if_idx [, error].
+ * @MPTCP_EVENT_LISTENER_CREATED: A new PM listener is created. Attributes:
+ *   family, sport, saddr4 | saddr6.
+ * @MPTCP_EVENT_LISTENER_CLOSED: A PM listener is closed. Attributes: family,
+ *   sport, saddr4 | saddr6.
  */
 enum mptcp_event_type {
 	MPTCP_EVENT_UNSPEC,
diff --git a/original/uapi/linux/net_shaper.h b/original/uapi/linux/net_shaper.h
new file mode 100644
index 0000000..d8834b5
--- /dev/null
+++ b/original/uapi/linux/net_shaper.h
@@ -0,0 +1,95 @@
+/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
+/* Do not edit directly, auto-generated from: */
+/*	Documentation/netlink/specs/net_shaper.yaml */
+/* YNL-GEN uapi header */
+
+#ifndef _UAPI_LINUX_NET_SHAPER_H
+#define _UAPI_LINUX_NET_SHAPER_H
+
+#define NET_SHAPER_FAMILY_NAME		"net-shaper"
+#define NET_SHAPER_FAMILY_VERSION	1
+
+/**
+ * enum net_shaper_scope - Defines the shaper @id interpretation.
+ * @NET_SHAPER_SCOPE_UNSPEC: The scope is not specified.
+ * @NET_SHAPER_SCOPE_NETDEV: The main shaper for the given network device.
+ * @NET_SHAPER_SCOPE_QUEUE: The shaper is attached to the given device queue,
+ *   the @id represents the queue number.
+ * @NET_SHAPER_SCOPE_NODE: The shaper allows grouping of queues or other node
+ *   shapers; can be nested in either @netdev shapers or other @node shapers,
+ *   allowing placement in any location of the scheduling tree, except leaves
+ *   and root.
+ */
+enum net_shaper_scope {
+	NET_SHAPER_SCOPE_UNSPEC,
+	NET_SHAPER_SCOPE_NETDEV,
+	NET_SHAPER_SCOPE_QUEUE,
+	NET_SHAPER_SCOPE_NODE,
+
+	/* private: */
+	__NET_SHAPER_SCOPE_MAX,
+	NET_SHAPER_SCOPE_MAX = (__NET_SHAPER_SCOPE_MAX - 1)
+};
+
+/**
+ * enum net_shaper_metric - Different metric supported by the shaper.
+ * @NET_SHAPER_METRIC_BPS: Shaper operates on a bits per second basis.
+ * @NET_SHAPER_METRIC_PPS: Shaper operates on a packets per second basis.
+ */
+enum net_shaper_metric {
+	NET_SHAPER_METRIC_BPS,
+	NET_SHAPER_METRIC_PPS,
+};
+
+enum {
+	NET_SHAPER_A_HANDLE = 1,
+	NET_SHAPER_A_METRIC,
+	NET_SHAPER_A_BW_MIN,
+	NET_SHAPER_A_BW_MAX,
+	NET_SHAPER_A_BURST,
+	NET_SHAPER_A_PRIORITY,
+	NET_SHAPER_A_WEIGHT,
+	NET_SHAPER_A_IFINDEX,
+	NET_SHAPER_A_PARENT,
+	NET_SHAPER_A_LEAVES,
+
+	__NET_SHAPER_A_MAX,
+	NET_SHAPER_A_MAX = (__NET_SHAPER_A_MAX - 1)
+};
+
+enum {
+	NET_SHAPER_A_HANDLE_SCOPE = 1,
+	NET_SHAPER_A_HANDLE_ID,
+
+	__NET_SHAPER_A_HANDLE_MAX,
+	NET_SHAPER_A_HANDLE_MAX = (__NET_SHAPER_A_HANDLE_MAX - 1)
+};
+
+enum {
+	NET_SHAPER_A_CAPS_IFINDEX = 1,
+	NET_SHAPER_A_CAPS_SCOPE,
+	NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS,
+	NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS,
+	NET_SHAPER_A_CAPS_SUPPORT_NESTING,
+	NET_SHAPER_A_CAPS_SUPPORT_BW_MIN,
+	NET_SHAPER_A_CAPS_SUPPORT_BW_MAX,
+	NET_SHAPER_A_CAPS_SUPPORT_BURST,
+	NET_SHAPER_A_CAPS_SUPPORT_PRIORITY,
+	NET_SHAPER_A_CAPS_SUPPORT_WEIGHT,
+
+	__NET_SHAPER_A_CAPS_MAX,
+	NET_SHAPER_A_CAPS_MAX = (__NET_SHAPER_A_CAPS_MAX - 1)
+};
+
+enum {
+	NET_SHAPER_CMD_GET = 1,
+	NET_SHAPER_CMD_SET,
+	NET_SHAPER_CMD_DELETE,
+	NET_SHAPER_CMD_GROUP,
+	NET_SHAPER_CMD_CAP_GET,
+
+	__NET_SHAPER_CMD_MAX,
+	NET_SHAPER_CMD_MAX = (__NET_SHAPER_CMD_MAX - 1)
+};
+
+#endif /* _UAPI_LINUX_NET_SHAPER_H */
diff --git a/original/uapi/linux/net_tstamp.h b/original/uapi/linux/net_tstamp.h
index 858339d..55b0ab5 100644
--- a/original/uapi/linux/net_tstamp.h
+++ b/original/uapi/linux/net_tstamp.h
@@ -13,6 +13,17 @@
 #include <linux/types.h>
 #include <linux/socket.h>   /* for SO_TIMESTAMPING */
 
+/*
+ * Possible type of hwtstamp provider. Mainly "precise" the default one
+ * is for IEEE 1588 quality and "approx" is for NICs DMA point.
+ */
+enum hwtstamp_provider_qualifier {
+	HWTSTAMP_PROVIDER_QUALIFIER_PRECISE,
+	HWTSTAMP_PROVIDER_QUALIFIER_APPROX,
+
+	HWTSTAMP_PROVIDER_QUALIFIER_CNT,
+};
+
 /* SO_TIMESTAMPING flags */
 enum {
 	SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
diff --git a/original/uapi/linux/netdev.h b/original/uapi/linux/netdev.h
index 7c308f0..e4be227 100644
--- a/original/uapi/linux/netdev.h
+++ b/original/uapi/linux/netdev.h
@@ -122,6 +122,9 @@ enum {
 	NETDEV_A_NAPI_ID,
 	NETDEV_A_NAPI_IRQ,
 	NETDEV_A_NAPI_PID,
+	NETDEV_A_NAPI_DEFER_HARD_IRQS,
+	NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT,
+	NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT,
 
 	__NETDEV_A_NAPI_MAX,
 	NETDEV_A_NAPI_MAX = (__NETDEV_A_NAPI_MAX - 1)
@@ -199,6 +202,7 @@ enum {
 	NETDEV_CMD_NAPI_GET,
 	NETDEV_CMD_QSTATS_GET,
 	NETDEV_CMD_BIND_RX,
+	NETDEV_CMD_NAPI_SET,
 
 	__NETDEV_CMD_MAX,
 	NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
diff --git a/original/uapi/linux/netfilter/nf_tables.h b/original/uapi/linux/netfilter/nf_tables.h
index 9e90793..49c944e 100644
--- a/original/uapi/linux/netfilter/nf_tables.h
+++ b/original/uapi/linux/netfilter/nf_tables.h
@@ -564,16 +564,26 @@ enum nft_immediate_attributes {
 /**
  * enum nft_bitwise_ops - nf_tables bitwise operations
  *
- * @NFT_BITWISE_BOOL: mask-and-xor operation used to implement NOT, AND, OR and
- *                    XOR boolean operations
+ * @NFT_BITWISE_MASK_XOR: mask-and-xor operation used to implement NOT, AND, OR
+ *                        and XOR boolean operations
  * @NFT_BITWISE_LSHIFT: left-shift operation
  * @NFT_BITWISE_RSHIFT: right-shift operation
+ * @NFT_BITWISE_AND: and operation
+ * @NFT_BITWISE_OR: or operation
+ * @NFT_BITWISE_XOR: xor operation
  */
 enum nft_bitwise_ops {
-	NFT_BITWISE_BOOL,
+	NFT_BITWISE_MASK_XOR,
 	NFT_BITWISE_LSHIFT,
 	NFT_BITWISE_RSHIFT,
+	NFT_BITWISE_AND,
+	NFT_BITWISE_OR,
+	NFT_BITWISE_XOR,
 };
+/*
+ * Old name for NFT_BITWISE_MASK_XOR.  Retained for backwards-compatibility.
+ */
+#define NFT_BITWISE_BOOL NFT_BITWISE_MASK_XOR
 
 /**
  * enum nft_bitwise_attributes - nf_tables bitwise expression netlink attributes
@@ -586,6 +596,7 @@ enum nft_bitwise_ops {
  * @NFTA_BITWISE_OP: type of operation (NLA_U32: nft_bitwise_ops)
  * @NFTA_BITWISE_DATA: argument for non-boolean operations
  *                     (NLA_NESTED: nft_data_attributes)
+ * @NFTA_BITWISE_SREG2: second source register (NLA_U32: nft_registers)
  *
  * The bitwise expression supports boolean and shift operations.  It implements
  * the boolean operations by performing the following operation:
@@ -609,6 +620,7 @@ enum nft_bitwise_attributes {
 	NFTA_BITWISE_XOR,
 	NFTA_BITWISE_OP,
 	NFTA_BITWISE_DATA,
+	NFTA_BITWISE_SREG2,
 	__NFTA_BITWISE_MAX
 };
 #define NFTA_BITWISE_MAX	(__NFTA_BITWISE_MAX - 1)
diff --git a/original/uapi/linux/netfilter/nfnetlink_conntrack.h b/original/uapi/linux/netfilter/nfnetlink_conntrack.h
index c2ac726..43233af 100644
--- a/original/uapi/linux/netfilter/nfnetlink_conntrack.h
+++ b/original/uapi/linux/netfilter/nfnetlink_conntrack.h
@@ -57,6 +57,7 @@ enum ctattr_type {
 	CTA_SYNPROXY,
 	CTA_FILTER,
 	CTA_STATUS_MASK,
+	CTA_TIMESTAMP_EVENT,
 	__CTA_MAX
 };
 #define CTA_MAX (__CTA_MAX - 1)
diff --git a/original/uapi/linux/nfc.h b/original/uapi/linux/nfc.h
index 4fa4e97..2f5b4be 100644
--- a/original/uapi/linux/nfc.h
+++ b/original/uapi/linux/nfc.h
@@ -164,6 +164,7 @@ enum nfc_commands {
  * @NFC_ATTR_VENDOR_SUBCMD: Vendor specific sub command
  * @NFC_ATTR_VENDOR_DATA: Vendor specific data, to be optionally passed
  *	to a vendor specific command implementation
+ * @NFC_ATTR_TARGET_ATS: ISO 14443 type A target Answer To Select
  */
 enum nfc_attrs {
 	NFC_ATTR_UNSPEC,
@@ -198,6 +199,7 @@ enum nfc_attrs {
 	NFC_ATTR_VENDOR_ID,
 	NFC_ATTR_VENDOR_SUBCMD,
 	NFC_ATTR_VENDOR_DATA,
+	NFC_ATTR_TARGET_ATS,
 /* private: internal use only */
 	__NFC_ATTR_AFTER_LAST
 };
@@ -225,6 +227,7 @@ enum nfc_sdp_attr {
 #define NFC_GB_MAXSIZE			48
 #define NFC_FIRMWARE_NAME_MAXSIZE	32
 #define NFC_ISO15693_UID_MAXSIZE	8
+#define NFC_ATS_MAXSIZE			20
 
 /* NFC protocols */
 #define NFC_PROTO_JEWEL		1
diff --git a/original/uapi/linux/nfs4.h b/original/uapi/linux/nfs4.h
index caf4db2..4273e02 100644
--- a/original/uapi/linux/nfs4.h
+++ b/original/uapi/linux/nfs4.h
@@ -58,7 +58,7 @@
 #define NFS4_SHARE_DENY_BOTH	0x0003
 
 /* nfs41 */
-#define NFS4_SHARE_WANT_MASK		0xFF00
+#define NFS4_SHARE_WANT_TYPE_MASK	0xFF00
 #define NFS4_SHARE_WANT_NO_PREFERENCE	0x0000
 #define NFS4_SHARE_WANT_READ_DELEG	0x0100
 #define NFS4_SHARE_WANT_WRITE_DELEG	0x0200
@@ -66,13 +66,16 @@
 #define NFS4_SHARE_WANT_NO_DELEG	0x0400
 #define NFS4_SHARE_WANT_CANCEL		0x0500
 
-#define NFS4_SHARE_WHEN_MASK		0xF0000
+#define NFS4_SHARE_WHEN_MASK				0xF0000
 #define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL	0x10000
 #define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED		0x20000
 
+#define NFS4_SHARE_WANT_MOD_MASK			0xF00000
 #define NFS4_SHARE_WANT_DELEG_TIMESTAMPS		0x100000
 #define NFS4_SHARE_WANT_OPEN_XOR_DELEGATION		0x200000
 
+#define NFS4_SHARE_WANT_MASK	(NFS4_SHARE_WANT_TYPE_MASK | NFS4_SHARE_WANT_MOD_MASK)
+
 #define NFS4_CDFC4_FORE	0x1
 #define NFS4_CDFC4_BACK 0x2
 #define NFS4_CDFC4_BOTH 0x3
diff --git a/original/uapi/linux/nl80211.h b/original/uapi/linux/nl80211.h
index f97f5ad..f6c1b18 100644
--- a/original/uapi/linux/nl80211.h
+++ b/original/uapi/linux/nl80211.h
@@ -1329,6 +1329,13 @@
  *      %NL80211_ATTR_MLO_TTLM_ULINK attributes are used to specify the
  *      TID to Link mapping for downlink/uplink traffic.
  *
+ * @NL80211_CMD_ASSOC_MLO_RECONF: For a non-AP MLD station, request to
+ *      add/remove links to/from the association.
+ *
+ * @NL80211_CMD_EPCS_CFG: EPCS configuration for a station. Used by userland to
+ *	control EPCS configuration. Used to notify userland on the current state
+ *	of EPCS.
+ *
  * @NL80211_CMD_MAX: highest used command number
  * @__NL80211_CMD_AFTER_LAST: internal use
  */
@@ -1586,6 +1593,9 @@ enum nl80211_commands {
 
 	NL80211_CMD_SET_TID_TO_LINK_MAPPING,
 
+	NL80211_CMD_ASSOC_MLO_RECONF,
+	NL80211_CMD_EPCS_CFG,
+
 	/* add new commands above here */
 
 	/* used to define NL80211_CMD_MAX below */
@@ -2868,6 +2878,21 @@ enum nl80211_commands {
  *	nested item, it contains attributes defined in
  *	&enum nl80211_if_combination_attrs.
  *
+ * @NL80211_ATTR_VIF_RADIO_MASK: Bitmask of allowed radios (u32).
+ *	A value of 0 means all radios.
+ *
+ * @NL80211_ATTR_SUPPORTED_SELECTORS: supported selectors, array of
+ *	supported selectors as defined by IEEE 802.11 7.3.2.2 but without the
+ *	length restriction (at most %NL80211_MAX_SUPP_SELECTORS).
+ *	This can be used to provide a list of selectors that are implemented
+ *	by the supplicant. If not given, support for SAE_H2E is assumed.
+ *
+ * @NL80211_ATTR_MLO_RECONF_REM_LINKS: (u16) A bitmask of the links requested
+ *      to be removed from the MLO association.
+ *
+ * @NL80211_ATTR_EPCS: Flag attribute indicating that EPCS is enabled for a
+ *	station interface.
+ *
  * @NUM_NL80211_ATTR: total number of nl80211_attrs available
  * @NL80211_ATTR_MAX: highest attribute number currently defined
  * @__NL80211_ATTR_AFTER_LAST: internal use
@@ -3416,6 +3441,13 @@ enum nl80211_attrs {
 	NL80211_ATTR_WIPHY_RADIOS,
 	NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS,
 
+	NL80211_ATTR_VIF_RADIO_MASK,
+
+	NL80211_ATTR_SUPPORTED_SELECTORS,
+
+	NL80211_ATTR_MLO_RECONF_REM_LINKS,
+	NL80211_ATTR_EPCS,
+
 	/* add attributes here, update the policy in nl80211.c */
 
 	__NL80211_ATTR_AFTER_LAST,
@@ -3460,6 +3492,7 @@ enum nl80211_attrs {
 #define NL80211_WIPHY_NAME_MAXLEN		64
 
 #define NL80211_MAX_SUPP_RATES			32
+#define NL80211_MAX_SUPP_SELECTORS		128
 #define NL80211_MAX_SUPP_HT_RATES		77
 #define NL80211_MAX_SUPP_REG_RULES		128
 #define NL80211_TKIP_DATA_OFFSET_ENCR_KEY	0
@@ -4698,6 +4731,7 @@ enum nl80211_survey_info {
  *	overrides all other flags.
  * @NL80211_MNTR_FLAG_ACTIVE: use the configured MAC address
  *	and ACK incoming unicast packets.
+ * @NL80211_MNTR_FLAG_SKIP_TX: do not pass local tx packets
  *
  * @__NL80211_MNTR_FLAG_AFTER_LAST: internal use
  * @NL80211_MNTR_FLAG_MAX: highest possible monitor flag
@@ -4710,6 +4744,7 @@ enum nl80211_mntr_flags {
 	NL80211_MNTR_FLAG_OTHER_BSS,
 	NL80211_MNTR_FLAG_COOK_FRAMES,
 	NL80211_MNTR_FLAG_ACTIVE,
+	NL80211_MNTR_FLAG_SKIP_TX,
 
 	/* keep last */
 	__NL80211_MNTR_FLAG_AFTER_LAST,
@@ -8031,6 +8066,8 @@ enum nl80211_ap_settings_flags {
  * @NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION: Supported interface
  *	combination for this radio. Attribute may be present multiple times
  *	and contains attributes defined in &enum nl80211_if_combination_attrs.
+ * @NL80211_WIPHY_RADIO_ATTR_ANTENNA_MASK: bitmask (u32) of antennas
+ *	connected to this radio.
  *
  * @__NL80211_WIPHY_RADIO_ATTR_LAST: Internal
  * @NL80211_WIPHY_RADIO_ATTR_MAX: Highest attribute
@@ -8041,6 +8078,7 @@ enum nl80211_wiphy_radio_attrs {
 	NL80211_WIPHY_RADIO_ATTR_INDEX,
 	NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE,
 	NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION,
+	NL80211_WIPHY_RADIO_ATTR_ANTENNA_MASK,
 
 	/* keep last */
 	__NL80211_WIPHY_RADIO_ATTR_LAST,
diff --git a/original/uapi/linux/ntsync.h b/original/uapi/linux/ntsync.h
index dcfa38f..6d06793 100644
--- a/original/uapi/linux/ntsync.h
+++ b/original/uapi/linux/ntsync.h
@@ -11,13 +11,49 @@
 #include <linux/types.h>
 
 struct ntsync_sem_args {
-	__u32 sem;
 	__u32 count;
 	__u32 max;
 };
 
-#define NTSYNC_IOC_CREATE_SEM		_IOWR('N', 0x80, struct ntsync_sem_args)
+struct ntsync_mutex_args {
+	__u32 owner;
+	__u32 count;
+};
+
+struct ntsync_event_args {
+	__u32 manual;
+	__u32 signaled;
+};
+
+#define NTSYNC_WAIT_REALTIME	0x1
+
+struct ntsync_wait_args {
+	__u64 timeout;
+	__u64 objs;
+	__u32 count;
+	__u32 index;
+	__u32 flags;
+	__u32 owner;
+	__u32 alert;
+	__u32 pad;
+};
+
+#define NTSYNC_MAX_WAIT_COUNT 64
+
+#define NTSYNC_IOC_CREATE_SEM		_IOW ('N', 0x80, struct ntsync_sem_args)
+#define NTSYNC_IOC_WAIT_ANY		_IOWR('N', 0x82, struct ntsync_wait_args)
+#define NTSYNC_IOC_WAIT_ALL		_IOWR('N', 0x83, struct ntsync_wait_args)
+#define NTSYNC_IOC_CREATE_MUTEX		_IOW ('N', 0x84, struct ntsync_mutex_args)
+#define NTSYNC_IOC_CREATE_EVENT		_IOW ('N', 0x87, struct ntsync_event_args)
 
-#define NTSYNC_IOC_SEM_POST		_IOWR('N', 0x81, __u32)
+#define NTSYNC_IOC_SEM_RELEASE		_IOWR('N', 0x81, __u32)
+#define NTSYNC_IOC_MUTEX_UNLOCK		_IOWR('N', 0x85, struct ntsync_mutex_args)
+#define NTSYNC_IOC_MUTEX_KILL		_IOW ('N', 0x86, __u32)
+#define NTSYNC_IOC_EVENT_SET		_IOR ('N', 0x88, __u32)
+#define NTSYNC_IOC_EVENT_RESET		_IOR ('N', 0x89, __u32)
+#define NTSYNC_IOC_EVENT_PULSE		_IOR ('N', 0x8a, __u32)
+#define NTSYNC_IOC_SEM_READ		_IOR ('N', 0x8b, struct ntsync_sem_args)
+#define NTSYNC_IOC_MUTEX_READ		_IOR ('N', 0x8c, struct ntsync_mutex_args)
+#define NTSYNC_IOC_EVENT_READ		_IOR ('N', 0x8d, struct ntsync_event_args)
 
 #endif
diff --git a/original/uapi/linux/pci_regs.h b/original/uapi/linux/pci_regs.h
index 12323b3..3445c49 100644
--- a/original/uapi/linux/pci_regs.h
+++ b/original/uapi/linux/pci_regs.h
@@ -340,7 +340,8 @@
 #define PCI_MSIX_ENTRY_UPPER_ADDR	0x4  /* Message Upper Address */
 #define PCI_MSIX_ENTRY_DATA		0x8  /* Message Data */
 #define PCI_MSIX_ENTRY_VECTOR_CTRL	0xc  /* Vector Control */
-#define  PCI_MSIX_ENTRY_CTRL_MASKBIT	0x00000001
+#define  PCI_MSIX_ENTRY_CTRL_MASKBIT	0x00000001  /* Mask Bit */
+#define  PCI_MSIX_ENTRY_CTRL_ST		0xffff0000  /* Steering Tag */
 
 /* CompactPCI Hotswap Register */
 
@@ -532,7 +533,7 @@
 #define  PCI_EXP_DEVSTA_TRPND	0x0020	/* Transactions Pending */
 #define PCI_CAP_EXP_RC_ENDPOINT_SIZEOF_V1	12	/* v1 endpoints without link end here */
 #define PCI_EXP_LNKCAP		0x0c	/* Link Capabilities */
-#define  PCI_EXP_LNKCAP_SLS	0x0000000f /* Supported Link Speeds */
+#define  PCI_EXP_LNKCAP_SLS	0x0000000f /* Max Link Speed (prior to PCIe r3.0: Supported Link Speeds) */
 #define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 /* LNKCAP2 SLS Vector bit 0 */
 #define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS Vector bit 1 */
 #define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 /* LNKCAP2 SLS Vector bit 2 */
@@ -659,10 +660,12 @@
 #define  PCI_EXP_DEVCAP2_ATOMIC_COMP64	0x00000100 /* 64b AtomicOp completion */
 #define  PCI_EXP_DEVCAP2_ATOMIC_COMP128	0x00000200 /* 128b AtomicOp completion */
 #define  PCI_EXP_DEVCAP2_LTR		0x00000800 /* Latency tolerance reporting */
+#define  PCI_EXP_DEVCAP2_TPH_COMP_MASK	0x00003000 /* TPH completer support */
 #define  PCI_EXP_DEVCAP2_OBFF_MASK	0x000c0000 /* OBFF support mechanism */
 #define  PCI_EXP_DEVCAP2_OBFF_MSG	0x00040000 /* New message signaling */
 #define  PCI_EXP_DEVCAP2_OBFF_WAKE	0x00080000 /* Re-use WAKE# for OBFF */
 #define  PCI_EXP_DEVCAP2_EE_PREFIX	0x00200000 /* End-End TLP Prefix */
+#define  PCI_EXP_DEVCAP2_EE_PREFIX_MAX	0x00c00000 /* Max End-End TLP Prefixes */
 #define PCI_EXP_DEVCTL2		0x28	/* Device Control 2 */
 #define  PCI_EXP_DEVCTL2_COMP_TIMEOUT	0x000f	/* Completion Timeout Value */
 #define  PCI_EXP_DEVCTL2_COMP_TMOUT_DIS	0x0010	/* Completion Timeout Disable */
@@ -678,6 +681,7 @@
 #define PCI_EXP_DEVSTA2		0x2a	/* Device Status 2 */
 #define PCI_CAP_EXP_RC_ENDPOINT_SIZEOF_V2 0x2c	/* end of v2 EPs w/o link */
 #define PCI_EXP_LNKCAP2		0x2c	/* Link Capabilities 2 */
+#define  PCI_EXP_LNKCAP2_SLS		0x000000fe /* Supported Link Speeds Vector */
 #define  PCI_EXP_LNKCAP2_SLS_2_5GB	0x00000002 /* Supported Speed 2.5GT/s */
 #define  PCI_EXP_LNKCAP2_SLS_5_0GB	0x00000004 /* Supported Speed 5GT/s */
 #define  PCI_EXP_LNKCAP2_SLS_8_0GB	0x00000008 /* Supported Speed 8GT/s */
@@ -786,10 +790,11 @@
 	/* Same bits as above */
 #define PCI_ERR_CAP		0x18	/* Advanced Error Capabilities & Ctrl*/
 #define  PCI_ERR_CAP_FEP(x)	((x) & 0x1f)	/* First Error Pointer */
-#define  PCI_ERR_CAP_ECRC_GENC	0x00000020	/* ECRC Generation Capable */
-#define  PCI_ERR_CAP_ECRC_GENE	0x00000040	/* ECRC Generation Enable */
-#define  PCI_ERR_CAP_ECRC_CHKC	0x00000080	/* ECRC Check Capable */
-#define  PCI_ERR_CAP_ECRC_CHKE	0x00000100	/* ECRC Check Enable */
+#define  PCI_ERR_CAP_ECRC_GENC		0x00000020 /* ECRC Generation Capable */
+#define  PCI_ERR_CAP_ECRC_GENE		0x00000040 /* ECRC Generation Enable */
+#define  PCI_ERR_CAP_ECRC_CHKC		0x00000080 /* ECRC Check Capable */
+#define  PCI_ERR_CAP_ECRC_CHKE		0x00000100 /* ECRC Check Enable */
+#define  PCI_ERR_CAP_PREFIX_LOG_PRESENT	0x00000800 /* TLP Prefix Log Present */
 #define PCI_ERR_HEADER_LOG	0x1c	/* Header Log Register (16 bytes) */
 #define PCI_ERR_ROOT_COMMAND	0x2c	/* Root Error Command */
 #define  PCI_ERR_ROOT_CMD_COR_EN	0x00000001 /* Correctable Err Reporting Enable */
@@ -805,6 +810,7 @@
 #define  PCI_ERR_ROOT_FATAL_RCV		0x00000040 /* Fatal Received */
 #define  PCI_ERR_ROOT_AER_IRQ		0xf8000000 /* Advanced Error Interrupt Message Number */
 #define PCI_ERR_ROOT_ERR_SRC	0x34	/* Error Source Identification */
+#define PCI_ERR_PREFIX_LOG	0x38	/* TLP Prefix LOG Register (up to 16 bytes) */
 
 /* Virtual Channel */
 #define PCI_VC_PORT_CAP1	0x04
@@ -998,9 +1004,6 @@
 #define PCI_ACS_CTRL		0x06	/* ACS Control Register */
 #define PCI_ACS_EGRESS_CTL_V	0x08	/* ACS Egress Control Vector */
 
-#define PCI_VSEC_HDR		4	/* extended cap - vendor-specific */
-#define  PCI_VSEC_HDR_LEN_SHIFT	20	/* shift for length field */
-
 /* SATA capability */
 #define PCI_SATA_REGS		4	/* SATA REGs specifier */
 #define  PCI_SATA_REGS_MASK	0xF	/* location - BAR#/inline */
@@ -1023,15 +1026,34 @@
 #define  PCI_DPA_CAP_SUBSTATE_MASK	0x1F	/* # substates - 1 */
 #define PCI_DPA_BASE_SIZEOF	16	/* size with 0 substates */
 
+/* TPH Completer Support */
+#define PCI_EXP_DEVCAP2_TPH_COMP_NONE		0x0 /* None */
+#define PCI_EXP_DEVCAP2_TPH_COMP_TPH_ONLY	0x1 /* TPH only */
+#define PCI_EXP_DEVCAP2_TPH_COMP_EXT_TPH	0x3 /* TPH and Extended TPH */
+
 /* TPH Requester */
 #define PCI_TPH_CAP		4	/* capability register */
-#define  PCI_TPH_CAP_LOC_MASK	0x600	/* location mask */
-#define   PCI_TPH_LOC_NONE	0x000	/* no location */
-#define   PCI_TPH_LOC_CAP	0x200	/* in capability */
-#define   PCI_TPH_LOC_MSIX	0x400	/* in MSI-X */
-#define PCI_TPH_CAP_ST_MASK	0x07FF0000	/* ST table mask */
-#define PCI_TPH_CAP_ST_SHIFT	16	/* ST table shift */
-#define PCI_TPH_BASE_SIZEOF	0xc	/* size with no ST table */
+#define  PCI_TPH_CAP_ST_NS	0x00000001 /* No ST Mode Supported */
+#define  PCI_TPH_CAP_ST_IV	0x00000002 /* Interrupt Vector Mode Supported */
+#define  PCI_TPH_CAP_ST_DS	0x00000004 /* Device Specific Mode Supported */
+#define  PCI_TPH_CAP_EXT_TPH	0x00000100 /* Ext TPH Requester Supported */
+#define  PCI_TPH_CAP_LOC_MASK	0x00000600 /* ST Table Location */
+#define   PCI_TPH_LOC_NONE	0x00000000 /* Not present */
+#define   PCI_TPH_LOC_CAP	0x00000200 /* In capability */
+#define   PCI_TPH_LOC_MSIX	0x00000400 /* In MSI-X */
+#define  PCI_TPH_CAP_ST_MASK	0x07FF0000 /* ST Table Size */
+#define  PCI_TPH_CAP_ST_SHIFT	16	/* ST Table Size shift */
+#define PCI_TPH_BASE_SIZEOF	0xc	/* Size with no ST table */
+
+#define PCI_TPH_CTRL		8	/* control register */
+#define  PCI_TPH_CTRL_MODE_SEL_MASK	0x00000007 /* ST Mode Select */
+#define   PCI_TPH_ST_NS_MODE		0x0 /* No ST Mode */
+#define   PCI_TPH_ST_IV_MODE		0x1 /* Interrupt Vector Mode */
+#define   PCI_TPH_ST_DS_MODE		0x2 /* Device Specific Mode */
+#define  PCI_TPH_CTRL_REQ_EN_MASK	0x00000300 /* TPH Requester Enable */
+#define   PCI_TPH_REQ_DISABLE		0x0 /* No TPH requests allowed */
+#define   PCI_TPH_REQ_TPH_ONLY		0x1 /* TPH only requests allowed */
+#define   PCI_TPH_REQ_EXT_TPH		0x3 /* Extended TPH requests allowed */
 
 /* Downstream Port Containment */
 #define PCI_EXP_DPC_CAP			0x04	/* DPC Capability */
diff --git a/original/uapi/linux/pcitest.h b/original/uapi/linux/pcitest.h
index 94b46b0..acd261f 100644
--- a/original/uapi/linux/pcitest.h
+++ b/original/uapi/linux/pcitest.h
@@ -20,6 +20,7 @@
 #define PCITEST_MSIX		_IOW('P', 0x7, int)
 #define PCITEST_SET_IRQTYPE	_IOW('P', 0x8, int)
 #define PCITEST_GET_IRQTYPE	_IO('P', 0x9)
+#define PCITEST_BARS		_IO('P', 0xa)
 #define PCITEST_CLEAR_IRQ	_IO('P', 0x10)
 
 #define PCITEST_FLAGS_USE_DMA	0x00000001
diff --git a/original/uapi/linux/perf_event.h b/original/uapi/linux/perf_event.h
index 4842c36..0524d54 100644
--- a/original/uapi/linux/perf_event.h
+++ b/original/uapi/linux/perf_event.h
@@ -511,7 +511,16 @@ struct perf_event_attr {
 	__u16	sample_max_stack;
 	__u16	__reserved_2;
 	__u32	aux_sample_size;
-	__u32	__reserved_3;
+
+	union {
+		__u32	aux_action;
+		struct {
+			__u32	aux_start_paused :  1, /* start AUX area tracing paused */
+				aux_pause        :  1, /* on overflow, pause AUX area tracing */
+				aux_resume       :  1, /* on overflow, resume AUX area tracing */
+				__reserved_3     : 29;
+		};
+	};
 
 	/*
 	 * User provided data if sigtrap=1, passed back to user via
diff --git a/original/uapi/linux/pidfd.h b/original/uapi/linux/pidfd.h
index 565fc06..4540f63 100644
--- a/original/uapi/linux/pidfd.h
+++ b/original/uapi/linux/pidfd.h
@@ -16,6 +16,55 @@
 #define PIDFD_SIGNAL_THREAD_GROUP	(1UL << 1)
 #define PIDFD_SIGNAL_PROCESS_GROUP	(1UL << 2)
 
+/* Flags for pidfd_info. */
+#define PIDFD_INFO_PID			(1UL << 0) /* Always returned, even if not requested */
+#define PIDFD_INFO_CREDS		(1UL << 1) /* Always returned, even if not requested */
+#define PIDFD_INFO_CGROUPID		(1UL << 2) /* Always returned if available, even if not requested */
+
+#define PIDFD_INFO_SIZE_VER0		64 /* sizeof first published struct */
+
+struct pidfd_info {
+	/*
+	 * This mask is similar to the request_mask in statx(2).
+	 *
+	 * Userspace indicates what extensions or expensive-to-calculate fields
+	 * they want by setting the corresponding bits in mask. The kernel
+	 * will ignore bits that it does not know about.
+	 *
+	 * When filling the structure, the kernel will only set bits
+	 * corresponding to the fields that were actually filled by the kernel.
+	 * This also includes any future extensions that might be automatically
+	 * filled. If the structure size is too small to contain a field
+	 * (requested or not), to avoid confusion the mask will not
+	 * contain a bit for that field.
+	 *
+	 * As such, userspace MUST verify that mask contains the
+	 * corresponding flags after the ioctl(2) returns to ensure that it is
+	 * using valid data.
+	 */
+	__u64 mask;
+	/*
+	 * The information contained in the following fields might be stale at the
+	 * time it is received, as the target process might have exited as soon as
+	 * the IOCTL was processed, and there is no way to avoid that. However, it
+	 * is guaranteed that if the call was successful, then the information was
+	 * correct and referred to the intended process at the time the work was
+	 * performed. */
+	__u64 cgroupid;
+	__u32 pid;
+	__u32 tgid;
+	__u32 ppid;
+	__u32 ruid;
+	__u32 rgid;
+	__u32 euid;
+	__u32 egid;
+	__u32 suid;
+	__u32 sgid;
+	__u32 fsuid;
+	__u32 fsgid;
+	__u32 spare0[1];
+};
+
 #define PIDFS_IOCTL_MAGIC 0xFF
 
 #define PIDFD_GET_CGROUP_NAMESPACE            _IO(PIDFS_IOCTL_MAGIC, 1)
@@ -28,5 +77,6 @@
 #define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
 #define PIDFD_GET_USER_NAMESPACE              _IO(PIDFS_IOCTL_MAGIC, 9)
 #define PIDFD_GET_UTS_NAMESPACE               _IO(PIDFS_IOCTL_MAGIC, 10)
+#define PIDFD_GET_INFO                        _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
 
 #endif /* _UAPI_LINUX_PIDFD_H */
diff --git a/original/uapi/linux/pkt_sched.h b/original/uapi/linux/pkt_sched.h
index a3cd0c2..25a9a47 100644
--- a/original/uapi/linux/pkt_sched.h
+++ b/original/uapi/linux/pkt_sched.h
@@ -836,6 +836,8 @@ enum {
 
 	TCA_FQ_WEIGHTS,		/* Weights for each band */
 
+	TCA_FQ_OFFLOAD_HORIZON, /* dequeue paced packets within this horizon immediately (us units) */
+
 	__TCA_FQ_MAX
 };
 
diff --git a/original/uapi/linux/pps_gen.h b/original/uapi/linux/pps_gen.h
new file mode 100644
index 0000000..60a5d0f
--- /dev/null
+++ b/original/uapi/linux/pps_gen.h
@@ -0,0 +1,37 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * PPS generator API header
+ *
+ * Copyright (C) 2024 Rodolfo Giometti <giometti@enneenne.com>
+ */
+
+#ifndef _PPS_GEN_H_
+#define _PPS_GEN_H_
+
+#include <linux/types.h>
+#include <linux/ioctl.h>
+
+/**
+ * struct pps_gen_event - the PPS generator events
+ * @event: the event type
+ * @sequence: the event sequence number
+ *
+ * Userspace can get the last PPS generator event by using the
+ * ioctl(pps_gen, PPS_GEN_FETCHEVENT, ...) syscall.
+ * The sequence field can be used to save the last event ID, while in the
+ * event field is stored the last event type. Currently known event is:
+ *
+ *     PPS_GEN_EVENT_MISSEDPULSE	: last pulse was not generated
+ */
+struct pps_gen_event {
+	unsigned int event;
+	unsigned int sequence;
+};
+
+#define PPS_GEN_EVENT_MISSEDPULSE	1
+
+#define PPS_GEN_SETENABLE		_IOW('p', 0xb1, unsigned int *)
+#define PPS_GEN_USESYSTEMCLOCK		_IOR('p', 0xb2, unsigned int *)
+#define PPS_GEN_FETCHEVENT		_IOR('p', 0xb3, struct pps_gen_event *)
+
+#endif /* _PPS_GEN_H_ */
diff --git a/original/uapi/linux/prctl.h b/original/uapi/linux/prctl.h
index 3579179..5c60806 100644
--- a/original/uapi/linux/prctl.h
+++ b/original/uapi/linux/prctl.h
@@ -230,7 +230,7 @@ struct prctl_mm_map {
 # define PR_PAC_APDBKEY			(1UL << 3)
 # define PR_PAC_APGAKEY			(1UL << 4)
 
-/* Tagged user address controls for arm64 */
+/* Tagged user address controls for arm64 and RISC-V */
 #define PR_SET_TAGGED_ADDR_CTRL		55
 #define PR_GET_TAGGED_ADDR_CTRL		56
 # define PR_TAGGED_ADDR_ENABLE		(1UL << 0)
@@ -244,6 +244,9 @@ struct prctl_mm_map {
 # define PR_MTE_TAG_MASK		(0xffffUL << PR_MTE_TAG_SHIFT)
 /* Unused; kept only for source compatibility */
 # define PR_MTE_TCF_SHIFT		1
+/* RISC-V pointer masking tag length */
+# define PR_PMLEN_SHIFT			24
+# define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
 
 /* Control reclaim behavior when allocating memory */
 #define PR_SET_IO_FLUSHER		57
@@ -328,4 +331,26 @@ struct prctl_mm_map {
 # define PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC	0x10 /* Clear the aspect on exec */
 # define PR_PPC_DEXCR_CTRL_MASK		0x1f
 
+/*
+ * Get the current shadow stack configuration for the current thread,
+ * this will be the value configured via PR_SET_SHADOW_STACK_STATUS.
+ */
+#define PR_GET_SHADOW_STACK_STATUS      74
+
+/*
+ * Set the current shadow stack configuration.  Enabling the shadow
+ * stack will cause a shadow stack to be allocated for the thread.
+ */
+#define PR_SET_SHADOW_STACK_STATUS      75
+# define PR_SHADOW_STACK_ENABLE         (1UL << 0)
+# define PR_SHADOW_STACK_WRITE		(1UL << 1)
+# define PR_SHADOW_STACK_PUSH		(1UL << 2)
+
+/*
+ * Prevent further changes to the specified shadow stack
+ * configuration.  All bits may be locked via this call, including
+ * undefined bits.
+ */
+#define PR_LOCK_SHADOW_STACK_STATUS      76
+
 #endif /* _LINUX_PRCTL_H */
diff --git a/original/uapi/linux/psci.h b/original/uapi/linux/psci.h
index 42a40ad..81759ff 100644
--- a/original/uapi/linux/psci.h
+++ b/original/uapi/linux/psci.h
@@ -59,6 +59,7 @@
 #define PSCI_1_1_FN_SYSTEM_RESET2		PSCI_0_2_FN(18)
 #define PSCI_1_1_FN_MEM_PROTECT			PSCI_0_2_FN(19)
 #define PSCI_1_1_FN_MEM_PROTECT_CHECK_RANGE	PSCI_0_2_FN(20)
+#define PSCI_1_3_FN_SYSTEM_OFF2			PSCI_0_2_FN(21)
 
 #define PSCI_1_0_FN64_CPU_DEFAULT_SUSPEND	PSCI_0_2_FN64(12)
 #define PSCI_1_0_FN64_NODE_HW_STATE		PSCI_0_2_FN64(13)
@@ -68,6 +69,7 @@
 
 #define PSCI_1_1_FN64_SYSTEM_RESET2		PSCI_0_2_FN64(18)
 #define PSCI_1_1_FN64_MEM_PROTECT_CHECK_RANGE	PSCI_0_2_FN64(20)
+#define PSCI_1_3_FN64_SYSTEM_OFF2		PSCI_0_2_FN64(21)
 
 /* PSCI v0.2 power state encoding for CPU_SUSPEND function */
 #define PSCI_0_2_POWER_STATE_ID_MASK		0xffff
@@ -100,6 +102,9 @@
 #define PSCI_1_1_RESET_TYPE_SYSTEM_WARM_RESET	0
 #define PSCI_1_1_RESET_TYPE_VENDOR_START	0x80000000U
 
+/* PSCI v1.3 hibernate type for SYSTEM_OFF2 */
+#define PSCI_1_3_OFF_TYPE_HIBERNATE_OFF		BIT(0)
+
 /* PSCI version decoding (independent of PSCI version) */
 #define PSCI_VERSION_MAJOR_SHIFT		16
 #define PSCI_VERSION_MINOR_MASK			\
diff --git a/original/uapi/linux/raid/md_p.h b/original/uapi/linux/raid/md_p.h
index 5a43c23..ff47b6f 100644
--- a/original/uapi/linux/raid/md_p.h
+++ b/original/uapi/linux/raid/md_p.h
@@ -233,7 +233,7 @@ struct mdp_superblock_1 {
 	char	set_name[32];	/* set and interpreted by user-space */
 
 	__le64	ctime;		/* lo 40 bits are seconds, top 24 are microseconds or 0*/
-	__le32	level;		/* 0,1,4,5 */
+	__le32	level;		/* 0,1,4,5, -1 (linear) */
 	__le32	layout;		/* only for raid5 and raid10 currently */
 	__le64	size;		/* used size of component devices, in 512byte sectors */
 
diff --git a/original/uapi/linux/raid/md_u.h b/original/uapi/linux/raid/md_u.h
index 7be89a4..a893010 100644
--- a/original/uapi/linux/raid/md_u.h
+++ b/original/uapi/linux/raid/md_u.h
@@ -103,6 +103,8 @@ typedef struct mdu_array_info_s {
 
 } mdu_array_info_t;
 
+#define LEVEL_LINEAR		(-1)
+
 /* we need a value for 'no level specified' and 0
  * means 'raid0', so we need something else.  This is
  * for internal use only
diff --git a/original/uapi/linux/reiserfs_fs.h b/original/uapi/linux/reiserfs_fs.h
deleted file mode 100644
index 5bb9214..0000000
--- a/original/uapi/linux/reiserfs_fs.h
+++ /dev/null
@@ -1,27 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
-/*
- * Copyright 1996, 1997, 1998 Hans Reiser, see reiserfs/README for licensing and copyright details
- */
-#ifndef _LINUX_REISER_FS_H
-#define _LINUX_REISER_FS_H
-
-#include <linux/types.h>
-#include <linux/magic.h>
-
-/*
- *  include/linux/reiser_fs.h
- *
- *  Reiser File System constants and structures
- *
- */
-
-/* ioctl's command */
-#define REISERFS_IOC_UNPACK		_IOW(0xCD,1,long)
-/* define following flags to be the same as in ext2, so that chattr(1),
-   lsattr(1) will work with us. */
-#define REISERFS_IOC_GETFLAGS		FS_IOC_GETFLAGS
-#define REISERFS_IOC_SETFLAGS		FS_IOC_SETFLAGS
-#define REISERFS_IOC_GETVERSION		FS_IOC_GETVERSION
-#define REISERFS_IOC_SETVERSION		FS_IOC_SETVERSION
-
-#endif				/* _LINUX_REISER_FS_H */
diff --git a/original/uapi/linux/reiserfs_xattr.h b/original/uapi/linux/reiserfs_xattr.h
deleted file mode 100644
index 503ad01..0000000
--- a/original/uapi/linux/reiserfs_xattr.h
+++ /dev/null
@@ -1,25 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
-/*
-  File: linux/reiserfs_xattr.h
-*/
-
-#ifndef _LINUX_REISERFS_XATTR_H
-#define _LINUX_REISERFS_XATTR_H
-
-#include <linux/types.h>
-
-/* Magic value in header */
-#define REISERFS_XATTR_MAGIC 0x52465841	/* "RFXA" */
-
-struct reiserfs_xattr_header {
-	__le32 h_magic;		/* magic number for identification */
-	__le32 h_hash;		/* hash of the value */
-};
-
-struct reiserfs_security_handle {
-	const char *name;
-	void *value;
-	__kernel_size_t length;
-};
-
-#endif  /*  _LINUX_REISERFS_XATTR_H  */
diff --git a/original/uapi/linux/rtnetlink.h b/original/uapi/linux/rtnetlink.h
index 3b687d2..66c3903 100644
--- a/original/uapi/linux/rtnetlink.h
+++ b/original/uapi/linux/rtnetlink.h
@@ -93,10 +93,18 @@ enum {
 	RTM_NEWPREFIX	= 52,
 #define RTM_NEWPREFIX	RTM_NEWPREFIX
 
-	RTM_GETMULTICAST = 58,
+	RTM_NEWMULTICAST = 56,
+#define RTM_NEWMULTICAST RTM_NEWMULTICAST
+	RTM_DELMULTICAST,
+#define RTM_DELMULTICAST RTM_DELMULTICAST
+	RTM_GETMULTICAST,
 #define RTM_GETMULTICAST RTM_GETMULTICAST
 
-	RTM_GETANYCAST	= 62,
+	RTM_NEWANYCAST	= 60,
+#define RTM_NEWANYCAST RTM_NEWANYCAST
+	RTM_DELANYCAST,
+#define RTM_DELANYCAST RTM_DELANYCAST
+	RTM_GETANYCAST,
 #define RTM_GETANYCAST	RTM_GETANYCAST
 
 	RTM_NEWNEIGHTBL	= 64,
@@ -174,7 +182,7 @@ enum {
 #define RTM_GETLINKPROP	RTM_GETLINKPROP
 
 	RTM_NEWVLAN = 112,
-#define RTM_NEWNVLAN	RTM_NEWVLAN
+#define RTM_NEWVLAN	RTM_NEWVLAN
 	RTM_DELVLAN,
 #define RTM_DELVLAN	RTM_DELVLAN
 	RTM_GETVLAN,
@@ -389,6 +397,7 @@ enum rtattr_type_t {
 	RTA_SPORT,
 	RTA_DPORT,
 	RTA_NH_ID,
+	RTA_FLOWLABEL,
 	__RTA_MAX
 };
 
@@ -774,6 +783,12 @@ enum rtnetlink_groups {
 #define RTNLGRP_TUNNEL		RTNLGRP_TUNNEL
 	RTNLGRP_STATS,
 #define RTNLGRP_STATS		RTNLGRP_STATS
+	RTNLGRP_IPV4_MCADDR,
+#define RTNLGRP_IPV4_MCADDR	RTNLGRP_IPV4_MCADDR
+	RTNLGRP_IPV6_MCADDR,
+#define RTNLGRP_IPV6_MCADDR	RTNLGRP_IPV6_MCADDR
+	RTNLGRP_IPV6_ACADDR,
+#define RTNLGRP_IPV6_ACADDR	RTNLGRP_IPV6_ACADDR
 	__RTNLGRP_MAX
 };
 #define RTNLGRP_MAX	(__RTNLGRP_MAX - 1)
diff --git a/original/uapi/linux/securebits.h b/original/uapi/linux/securebits.h
index d6d9887..3fba30d 100644
--- a/original/uapi/linux/securebits.h
+++ b/original/uapi/linux/securebits.h
@@ -52,10 +52,32 @@
 #define SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED \
 			(issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE_LOCKED))
 
+/* See Documentation/userspace-api/check_exec.rst */
+#define SECURE_EXEC_RESTRICT_FILE		8
+#define SECURE_EXEC_RESTRICT_FILE_LOCKED	9  /* make bit-8 immutable */
+
+#define SECBIT_EXEC_RESTRICT_FILE (issecure_mask(SECURE_EXEC_RESTRICT_FILE))
+#define SECBIT_EXEC_RESTRICT_FILE_LOCKED \
+			(issecure_mask(SECURE_EXEC_RESTRICT_FILE_LOCKED))
+
+/* See Documentation/userspace-api/check_exec.rst */
+#define SECURE_EXEC_DENY_INTERACTIVE		10
+#define SECURE_EXEC_DENY_INTERACTIVE_LOCKED	11  /* make bit-10 immutable */
+
+#define SECBIT_EXEC_DENY_INTERACTIVE \
+			(issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
+#define SECBIT_EXEC_DENY_INTERACTIVE_LOCKED \
+			(issecure_mask(SECURE_EXEC_DENY_INTERACTIVE_LOCKED))
+
 #define SECURE_ALL_BITS		(issecure_mask(SECURE_NOROOT) | \
 				 issecure_mask(SECURE_NO_SETUID_FIXUP) | \
 				 issecure_mask(SECURE_KEEP_CAPS) | \
-				 issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE))
+				 issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE) | \
+				 issecure_mask(SECURE_EXEC_RESTRICT_FILE) | \
+				 issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
 #define SECURE_ALL_LOCKS	(SECURE_ALL_BITS << 1)
 
+#define SECURE_ALL_UNPRIVILEGED (issecure_mask(SECURE_EXEC_RESTRICT_FILE) | \
+				 issecure_mask(SECURE_EXEC_DENY_INTERACTIVE))
+
 #endif /* _UAPI_LINUX_SECUREBITS_H */
diff --git a/original/uapi/linux/sed-opal.h b/original/uapi/linux/sed-opal.h
index d3994b7..9025dd5 100644
--- a/original/uapi/linux/sed-opal.h
+++ b/original/uapi/linux/sed-opal.h
@@ -215,5 +215,6 @@ struct opal_revert_lsp {
 #define IOC_OPAL_GET_GEOMETRY       _IOR('p', 238, struct opal_geometry)
 #define IOC_OPAL_DISCOVERY          _IOW('p', 239, struct opal_discovery)
 #define IOC_OPAL_REVERT_LSP         _IOW('p', 240, struct opal_revert_lsp)
+#define IOC_OPAL_SET_SID_PW         _IOW('p', 241, struct opal_new_pw)
 
 #endif /* _UAPI_SED_OPAL_H */
diff --git a/original/uapi/linux/snmp.h b/original/uapi/linux/snmp.h
index adf5fd7..848c778 100644
--- a/original/uapi/linux/snmp.h
+++ b/original/uapi/linux/snmp.h
@@ -186,6 +186,7 @@ enum
 	LINUX_MIB_TIMEWAITKILLED,		/* TimeWaitKilled */
 	LINUX_MIB_PAWSACTIVEREJECTED,		/* PAWSActiveRejected */
 	LINUX_MIB_PAWSESTABREJECTED,		/* PAWSEstabRejected */
+	LINUX_MIB_PAWS_OLD_ACK,			/* PAWSOldAck */
 	LINUX_MIB_DELAYEDACKS,			/* DelayedACKs */
 	LINUX_MIB_DELAYEDACKLOCKED,		/* DelayedACKLocked */
 	LINUX_MIB_DELAYEDACKLOST,		/* DelayedACKLost */
@@ -339,6 +340,8 @@ enum
 	LINUX_MIB_XFRMACQUIREERROR,		/* XfrmAcquireError */
 	LINUX_MIB_XFRMOUTSTATEDIRERROR,		/* XfrmOutStateDirError */
 	LINUX_MIB_XFRMINSTATEDIRERROR,		/* XfrmInStateDirError */
+	LINUX_MIB_XFRMINIPTFSERROR,		/* XfrmInIptfsError */
+	LINUX_MIB_XFRMOUTNOQSPACE,		/* XfrmOutNoQueueSpace */
 	__LINUX_MIB_XFRMMAX
 };
 
@@ -358,6 +361,11 @@ enum
 	LINUX_MIB_TLSRXDEVICERESYNC,		/* TlsRxDeviceResync */
 	LINUX_MIB_TLSDECRYPTRETRY,		/* TlsDecryptRetry */
 	LINUX_MIB_TLSRXNOPADVIOL,		/* TlsRxNoPadViolation */
+	LINUX_MIB_TLSRXREKEYOK,			/* TlsRxRekeyOk */
+	LINUX_MIB_TLSRXREKEYERROR,		/* TlsRxRekeyError */
+	LINUX_MIB_TLSTXREKEYOK,			/* TlsTxRekeyOk */
+	LINUX_MIB_TLSTXREKEYERROR,		/* TlsTxRekeyError */
+	LINUX_MIB_TLSRXREKEYRECEIVED,		/* TlsRxRekeyReceived */
 	__LINUX_MIB_TLSMAX
 };
 
diff --git a/original/uapi/linux/stat.h b/original/uapi/linux/stat.h
index 887a252..f78ee36 100644
--- a/original/uapi/linux/stat.h
+++ b/original/uapi/linux/stat.h
@@ -98,43 +98,93 @@ struct statx_timestamp {
  */
 struct statx {
 	/* 0x00 */
-	__u32	stx_mask;	/* What results were written [uncond] */
-	__u32	stx_blksize;	/* Preferred general I/O size [uncond] */
-	__u64	stx_attributes;	/* Flags conveying information about the file [uncond] */
+	/* What results were written [uncond] */
+	__u32	stx_mask;
+
+	/* Preferred general I/O size [uncond] */
+	__u32	stx_blksize;
+
+	/* Flags conveying information about the file [uncond] */
+	__u64	stx_attributes;
+
 	/* 0x10 */
-	__u32	stx_nlink;	/* Number of hard links */
-	__u32	stx_uid;	/* User ID of owner */
-	__u32	stx_gid;	/* Group ID of owner */
-	__u16	stx_mode;	/* File mode */
+	/* Number of hard links */
+	__u32	stx_nlink;
+
+	/* User ID of owner */
+	__u32	stx_uid;
+
+	/* Group ID of owner */
+	__u32	stx_gid;
+
+	/* File mode */
+	__u16	stx_mode;
 	__u16	__spare0[1];
+
 	/* 0x20 */
-	__u64	stx_ino;	/* Inode number */
-	__u64	stx_size;	/* File size */
-	__u64	stx_blocks;	/* Number of 512-byte blocks allocated */
-	__u64	stx_attributes_mask; /* Mask to show what's supported in stx_attributes */
+	/* Inode number */
+	__u64	stx_ino;
+
+	/* File size */
+	__u64	stx_size;
+
+	/* Number of 512-byte blocks allocated */
+	__u64	stx_blocks;
+
+	/* Mask to show what's supported in stx_attributes */
+	__u64	stx_attributes_mask;
+
 	/* 0x40 */
-	struct statx_timestamp	stx_atime;	/* Last access time */
-	struct statx_timestamp	stx_btime;	/* File creation time */
-	struct statx_timestamp	stx_ctime;	/* Last attribute change time */
-	struct statx_timestamp	stx_mtime;	/* Last data modification time */
+	/* Last access time */
+	struct statx_timestamp	stx_atime;
+
+	/* File creation time */
+	struct statx_timestamp	stx_btime;
+
+	/* Last attribute change time */
+	struct statx_timestamp	stx_ctime;
+
+	/* Last data modification time */
+	struct statx_timestamp	stx_mtime;
+
 	/* 0x80 */
-	__u32	stx_rdev_major;	/* Device ID of special file [if bdev/cdev] */
+	/* Device ID of special file [if bdev/cdev] */
+	__u32	stx_rdev_major;
 	__u32	stx_rdev_minor;
-	__u32	stx_dev_major;	/* ID of device containing file [uncond] */
+
+	/* ID of device containing file [uncond] */
+	__u32	stx_dev_major;
 	__u32	stx_dev_minor;
+
 	/* 0x90 */
 	__u64	stx_mnt_id;
-	__u32	stx_dio_mem_align;	/* Memory buffer alignment for direct I/O */
-	__u32	stx_dio_offset_align;	/* File offset alignment for direct I/O */
+
+	/* Memory buffer alignment for direct I/O */
+	__u32	stx_dio_mem_align;
+
+	/* File offset alignment for direct I/O */
+	__u32	stx_dio_offset_align;
+
 	/* 0xa0 */
-	__u64	stx_subvol;	/* Subvolume identifier */
-	__u32	stx_atomic_write_unit_min;	/* Min atomic write unit in bytes */
-	__u32	stx_atomic_write_unit_max;	/* Max atomic write unit in bytes */
+	/* Subvolume identifier */
+	__u64	stx_subvol;
+
+	/* Min atomic write unit in bytes */
+	__u32	stx_atomic_write_unit_min;
+
+	/* Max atomic write unit in bytes */
+	__u32	stx_atomic_write_unit_max;
+
 	/* 0xb0 */
-	__u32   stx_atomic_write_segments_max;	/* Max atomic write segment count */
-	__u32   __spare1[1];
+	/* Max atomic write segment count */
+	__u32   stx_atomic_write_segments_max;
+
+	/* File offset alignment for direct I/O reads */
+	__u32	stx_dio_read_offset_align;
+
 	/* 0xb8 */
 	__u64	__spare3[9];	/* Spare space for future expansion */
+
 	/* 0x100 */
 };
 
@@ -164,6 +214,7 @@ struct statx {
 #define STATX_MNT_ID_UNIQUE	0x00004000U	/* Want/got extended stx_mount_id */
 #define STATX_SUBVOL		0x00008000U	/* Want/got stx_subvol */
 #define STATX_WRITE_ATOMIC	0x00010000U	/* Want/got atomic_write_* fields */
+#define STATX_DIO_READ_ALIGN	0x00020000U	/* Want/got dio read alignment info */
 
 #define STATX__RESERVED		0x80000000U	/* Reserved for future struct statx expansion */
 
diff --git a/original/uapi/linux/stddef.h b/original/uapi/linux/stddef.h
index 5815411..a6fce46 100644
--- a/original/uapi/linux/stddef.h
+++ b/original/uapi/linux/stddef.h
@@ -8,6 +8,13 @@
 #define __always_inline inline
 #endif
 
+/* Not all C++ standards support type declarations inside an anonymous union */
+#ifndef __cplusplus
+#define __struct_group_tag(TAG)		TAG
+#else
+#define __struct_group_tag(TAG)
+#endif
+
 /**
  * __struct_group() - Create a mirrored named and anonyomous struct
  *
@@ -20,13 +27,13 @@
  * and size: one anonymous and one named. The former's members can be used
  * normally without sub-struct naming, and the latter can be used to
  * reason about the start, end, and size of the group of struct members.
- * The named struct can also be explicitly tagged for layer reuse, as well
- * as both having struct attributes appended.
+ * The named struct can also be explicitly tagged for layer reuse (C only),
+ * as well as both having struct attributes appended.
  */
 #define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
 	union { \
 		struct { MEMBERS } ATTRS; \
-		struct TAG { MEMBERS } ATTRS NAME; \
+		struct __struct_group_tag(TAG) { MEMBERS } ATTRS NAME; \
 	} ATTRS
 
 #ifdef __cplusplus
diff --git a/original/uapi/linux/taskstats.h b/original/uapi/linux/taskstats.h
index b50b2eb..9576223 100644
--- a/original/uapi/linux/taskstats.h
+++ b/original/uapi/linux/taskstats.h
@@ -34,7 +34,7 @@
  */
 
 
-#define TASKSTATS_VERSION	14
+#define TASKSTATS_VERSION	15
 #define TS_COMM_LEN		32	/* should be >= TASK_COMM_LEN
 					 * in linux/sched.h */
 
@@ -72,6 +72,8 @@ struct taskstats {
 	 */
 	__u64	cpu_count __attribute__((aligned(8)));
 	__u64	cpu_delay_total;
+	__u64	cpu_delay_max;
+	__u64	cpu_delay_min;
 
 	/* Following four fields atomically updated using task->delays->lock */
 
@@ -80,10 +82,14 @@ struct taskstats {
 	 */
 	__u64	blkio_count;
 	__u64	blkio_delay_total;
+	__u64	blkio_delay_max;
+	__u64	blkio_delay_min;
 
 	/* Delay waiting for page fault I/O (swap in only) */
 	__u64	swapin_count;
 	__u64	swapin_delay_total;
+	__u64	swapin_delay_max;
+	__u64	swapin_delay_min;
 
 	/* cpu "wall-clock" running time
 	 * On some architectures, value will adjust for cpu time stolen
@@ -166,10 +172,14 @@ struct taskstats {
 	/* Delay waiting for memory reclaim */
 	__u64	freepages_count;
 	__u64	freepages_delay_total;
+	__u64	freepages_delay_max;
+	__u64	freepages_delay_min;
 
 	/* Delay waiting for thrashing page */
 	__u64	thrashing_count;
 	__u64	thrashing_delay_total;
+	__u64	thrashing_delay_max;
+	__u64	thrashing_delay_min;
 
 	/* v10: 64-bit btime to avoid overflow */
 	__u64	ac_btime64;		/* 64-bit begin time */
@@ -177,6 +187,8 @@ struct taskstats {
 	/* v11: Delay waiting for memory compact */
 	__u64	compact_count;
 	__u64	compact_delay_total;
+	__u64	compact_delay_max;
+	__u64	compact_delay_min;
 
 	/* v12 begin */
 	__u32   ac_tgid;	/* thread group ID */
@@ -198,10 +210,15 @@ struct taskstats {
 	/* v13: Delay waiting for write-protect copy */
 	__u64    wpcopy_count;
 	__u64    wpcopy_delay_total;
+	__u64    wpcopy_delay_max;
+	__u64    wpcopy_delay_min;
 
 	/* v14: Delay waiting for IRQ/SOFTIRQ */
 	__u64    irq_count;
 	__u64    irq_delay_total;
+	__u64    irq_delay_max;
+	__u64    irq_delay_min;
+	/* v15: add Delay max */
 };
 
 
diff --git a/original/uapi/linux/thermal.h b/original/uapi/linux/thermal.h
index fc78bf3..46a2633 100644
--- a/original/uapi/linux/thermal.h
+++ b/original/uapi/linux/thermal.h
@@ -3,6 +3,8 @@
 #define _UAPI_LINUX_THERMAL_H
 
 #define THERMAL_NAME_LENGTH	20
+#define THERMAL_THRESHOLD_WAY_UP	0x1
+#define THERMAL_THRESHOLD_WAY_DOWN	0x2
 
 enum thermal_device_mode {
 	THERMAL_DEVICE_DISABLED = 0,
@@ -18,7 +20,7 @@ enum thermal_trip_type {
 
 /* Adding event notification support elements */
 #define THERMAL_GENL_FAMILY_NAME		"thermal"
-#define THERMAL_GENL_VERSION			0x01
+#define THERMAL_GENL_VERSION			0x02
 #define THERMAL_GENL_SAMPLING_GROUP_NAME	"sampling"
 #define THERMAL_GENL_EVENT_GROUP_NAME		"event"
 
@@ -48,6 +50,10 @@ enum thermal_genl_attr {
 	THERMAL_GENL_ATTR_CPU_CAPABILITY_ID,
 	THERMAL_GENL_ATTR_CPU_CAPABILITY_PERFORMANCE,
 	THERMAL_GENL_ATTR_CPU_CAPABILITY_EFFICIENCY,
+	THERMAL_GENL_ATTR_THRESHOLD,
+	THERMAL_GENL_ATTR_THRESHOLD_TEMP,
+	THERMAL_GENL_ATTR_THRESHOLD_DIRECTION,
+	THERMAL_GENL_ATTR_TZ_PREV_TEMP,
 	__THERMAL_GENL_ATTR_MAX,
 };
 #define THERMAL_GENL_ATTR_MAX (__THERMAL_GENL_ATTR_MAX - 1)
@@ -75,6 +81,11 @@ enum thermal_genl_event {
 	THERMAL_GENL_EVENT_CDEV_STATE_UPDATE,	/* Cdev state updated */
 	THERMAL_GENL_EVENT_TZ_GOV_CHANGE,	/* Governor policy changed  */
 	THERMAL_GENL_EVENT_CPU_CAPABILITY_CHANGE,	/* CPU capability changed */
+	THERMAL_GENL_EVENT_THRESHOLD_ADD,	/* A thresold has been added */
+	THERMAL_GENL_EVENT_THRESHOLD_DELETE,	/* A thresold has been deleted */
+	THERMAL_GENL_EVENT_THRESHOLD_FLUSH,	/* All thresolds have been deleted */
+	THERMAL_GENL_EVENT_THRESHOLD_UP,	/* A thresold has been crossed the way up */
+	THERMAL_GENL_EVENT_THRESHOLD_DOWN,	/* A thresold has been crossed the way down */
 	__THERMAL_GENL_EVENT_MAX,
 };
 #define THERMAL_GENL_EVENT_MAX (__THERMAL_GENL_EVENT_MAX - 1)
@@ -82,12 +93,16 @@ enum thermal_genl_event {
 /* Commands supported by the thermal_genl_family */
 enum thermal_genl_cmd {
 	THERMAL_GENL_CMD_UNSPEC,
-	THERMAL_GENL_CMD_TZ_GET_ID,	/* List of thermal zones id */
-	THERMAL_GENL_CMD_TZ_GET_TRIP,	/* List of thermal trips */
-	THERMAL_GENL_CMD_TZ_GET_TEMP,	/* Get the thermal zone temperature */
-	THERMAL_GENL_CMD_TZ_GET_GOV,	/* Get the thermal zone governor */
-	THERMAL_GENL_CMD_TZ_GET_MODE,	/* Get the thermal zone mode */
-	THERMAL_GENL_CMD_CDEV_GET,	/* List of cdev id */
+	THERMAL_GENL_CMD_TZ_GET_ID,		/* List of thermal zones id */
+	THERMAL_GENL_CMD_TZ_GET_TRIP,		/* List of thermal trips */
+	THERMAL_GENL_CMD_TZ_GET_TEMP,		/* Get the thermal zone temperature */
+	THERMAL_GENL_CMD_TZ_GET_GOV,		/* Get the thermal zone governor */
+	THERMAL_GENL_CMD_TZ_GET_MODE,		/* Get the thermal zone mode */
+	THERMAL_GENL_CMD_CDEV_GET,		/* List of cdev id */
+	THERMAL_GENL_CMD_THRESHOLD_GET,		/* List of thresholds */
+	THERMAL_GENL_CMD_THRESHOLD_ADD,		/* Add a threshold */
+	THERMAL_GENL_CMD_THRESHOLD_DELETE,	/* Delete a threshold */
+	THERMAL_GENL_CMD_THRESHOLD_FLUSH,	/* Flush all the thresholds */
 	__THERMAL_GENL_CMD_MAX,
 };
 #define THERMAL_GENL_CMD_MAX (__THERMAL_GENL_CMD_MAX - 1)
diff --git a/original/uapi/linux/types.h b/original/uapi/linux/types.h
index 6375a06..48b9339 100644
--- a/original/uapi/linux/types.h
+++ b/original/uapi/linux/types.h
@@ -53,6 +53,7 @@ typedef __u32 __bitwise __wsum;
  * No conversions are necessary between 32-bit user-space and a 64-bit kernel.
  */
 #define __aligned_u64 __u64 __attribute__((aligned(8)))
+#define __aligned_s64 __s64 __attribute__((aligned(8)))
 #define __aligned_be64 __be64 __attribute__((aligned(8)))
 #define __aligned_le64 __le64 __attribute__((aligned(8)))
 
diff --git a/original/uapi/linux/ublk_cmd.h b/original/uapi/linux/ublk_cmd.h
index 1287363..a8bc98b 100644
--- a/original/uapi/linux/ublk_cmd.h
+++ b/original/uapi/linux/ublk_cmd.h
@@ -147,8 +147,18 @@
  */
 #define UBLK_F_NEED_GET_DATA (1UL << 2)
 
+/*
+ * - Block devices are recoverable if ublk server exits and restarts
+ * - Outstanding I/O when ublk server exits is met with errors
+ * - I/O issued while there is no ublk server queues
+ */
 #define UBLK_F_USER_RECOVERY	(1UL << 3)
 
+/*
+ * - Block devices are recoverable if ublk server exits and restarts
+ * - Outstanding I/O when ublk server exits is reissued
+ * - I/O issued while there is no ublk server queues
+ */
 #define UBLK_F_USER_RECOVERY_REISSUE	(1UL << 4)
 
 /*
@@ -190,10 +200,18 @@
  */
 #define UBLK_F_ZONED (1ULL << 8)
 
+/*
+ * - Block devices are recoverable if ublk server exits and restarts
+ * - Outstanding I/O when ublk server exits is met with errors
+ * - I/O issued while there is no ublk server is met with errors
+ */
+#define UBLK_F_USER_RECOVERY_FAIL_IO (1ULL << 9)
+
 /* device state */
 #define UBLK_S_DEV_DEAD	0
 #define UBLK_S_DEV_LIVE	1
 #define UBLK_S_DEV_QUIESCED	2
+#define UBLK_S_DEV_FAIL_IO 	3
 
 /* shipped via sqe->cmd of io_uring command */
 struct ublksrv_ctrl_cmd {
diff --git a/original/uapi/linux/udp.h b/original/uapi/linux/udp.h
index 1a0fe8b..d85d671 100644
--- a/original/uapi/linux/udp.h
+++ b/original/uapi/linux/udp.h
@@ -31,7 +31,7 @@ struct udphdr {
 #define UDP_CORK	1	/* Never send partially complete segments */
 #define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */
 #define UDP_NO_CHECK6_TX 101	/* Disable sending checksum for UDP6X */
-#define UDP_NO_CHECK6_RX 102	/* Disable accpeting checksum for UDP6 */
+#define UDP_NO_CHECK6_RX 102	/* Disable accepting checksum for UDP6 */
 #define UDP_SEGMENT	103	/* Set GSO segmentation size */
 #define UDP_GRO		104	/* This socket can receive UDP GRO packets */
 
diff --git a/original/uapi/linux/usb/functionfs.h b/original/uapi/linux/usb/functionfs.h
index 2ebdba1..beef175 100644
--- a/original/uapi/linux/usb/functionfs.h
+++ b/original/uapi/linux/usb/functionfs.h
@@ -206,7 +206,7 @@ struct usb_ffs_dmabuf_transfer_req {
  * +-----+-----------------+------+--------------------------+
  * | off | name            | type | description              |
  * +-----+-----------------+------+--------------------------+
- * |   0 | inteface        | U8   | related interface number |
+ * |   0 | interface       | U8   | related interface number |
  * +-----+-----------------+------+--------------------------+
  * |   1 | dwLength        | U32  | length of the descriptor |
  * +-----+-----------------+------+--------------------------+
@@ -224,7 +224,7 @@ struct usb_ffs_dmabuf_transfer_req {
  * +-----+-----------------+------+--------------------------+
  * | off | name            | type | description              |
  * +-----+-----------------+------+--------------------------+
- * |   0 | inteface        | U8   | related interface number |
+ * |   0 | interface       | U8   | related interface number |
  * +-----+-----------------+------+--------------------------+
  * |   1 | dwLength        | U32  | length of the descriptor |
  * +-----+-----------------+------+--------------------------+
@@ -237,7 +237,7 @@ struct usb_ffs_dmabuf_transfer_req {
  * |  11 | ExtProp[]       |      | list of ext. prop. d.    |
  * +-----+-----------------+------+--------------------------+
  *
- * ExtCompat[] is an array of valid Extended Compatiblity descriptors
+ * ExtCompat[] is an array of valid Extended Compatibility descriptors
  * which have the following format:
  *
  * +-----+-----------------------+------+-------------------------------------+
@@ -295,7 +295,7 @@ struct usb_functionfs_strings_head {
  * |  16 | stringtab  | StringTab[lang_count] | table of strings per lang  |
  *
  * For each language there is one stringtab entry (ie. there are lang_count
- * stringtab entires).  Each StringTab has following format:
+ * stringtab entries).  Each StringTab has following format:
  *
  * | off | name    | type              | description                        |
  * |-----+---------+-------------------+------------------------------------|
diff --git a/original/uapi/linux/usb/video.h b/original/uapi/linux/usb/video.h
index 2ff0e8a..526b515 100644
--- a/original/uapi/linux/usb/video.h
+++ b/original/uapi/linux/usb/video.h
@@ -597,5 +597,63 @@ struct UVC_FRAME_MJPEG(n) {				\
 	__le32 dwFrameInterval[n];			\
 } __attribute__ ((packed))
 
+/* Frame Based Payload - 3.1.1. Frame Based Video Format Descriptor */
+struct uvc_format_framebased {
+	__u8  bLength;
+	__u8  bDescriptorType;
+	__u8  bDescriptorSubType;
+	__u8  bFormatIndex;
+	__u8  bNumFrameDescriptors;
+	__u8  guidFormat[16];
+	__u8  bBitsPerPixel;
+	__u8  bDefaultFrameIndex;
+	__u8  bAspectRatioX;
+	__u8  bAspectRatioY;
+	__u8  bmInterfaceFlags;
+	__u8  bCopyProtect;
+	__u8  bVariableSize;
+} __attribute__((__packed__));
+
+#define UVC_DT_FORMAT_FRAMEBASED_SIZE                  28
+
+/* Frame Based Payload - 3.1.2. Frame Based Video Frame Descriptor */
+struct uvc_frame_framebased {
+	__u8  bLength;
+	__u8  bDescriptorType;
+	__u8  bDescriptorSubType;
+	__u8  bFrameIndex;
+	__u8  bmCapabilities;
+	__u16 wWidth;
+	__u16 wHeight;
+	__u32 dwMinBitRate;
+	__u32 dwMaxBitRate;
+	__u32 dwDefaultFrameInterval;
+	__u8  bFrameIntervalType;
+	__u32 dwBytesPerLine;
+	__u32 dwFrameInterval[];
+} __attribute__((__packed__));
+
+#define UVC_DT_FRAME_FRAMEBASED_SIZE(n)                        (26+4*(n))
+
+#define UVC_FRAME_FRAMEBASED(n) \
+	uvc_frame_framebased_##n
+
+#define DECLARE_UVC_FRAME_FRAMEBASED(n)			\
+struct UVC_FRAME_FRAMEBASED(n) {			\
+	__u8  bLength;					\
+	__u8  bDescriptorType;				\
+	__u8  bDescriptorSubType;                       \
+	__u8  bFrameIndex;                              \
+	__u8  bmCapabilities;                           \
+	__u16 wWidth;                                   \
+	__u16 wHeight;                                  \
+	__u32 dwMinBitRate;                             \
+	__u32 dwMaxBitRate;                             \
+	__u32 dwDefaultFrameInterval;                   \
+	__u8  bFrameIntervalType;                       \
+	__u32 dwBytesPerLine;                           \
+	__u32 dwFrameInterval[n];                       \
+} __attribute__ ((packed))
+
 #endif /* __LINUX_USB_VIDEO_H */
 
diff --git a/original/uapi/linux/v4l2-dv-timings.h b/original/uapi/linux/v4l2-dv-timings.h
index ef0128c..44a16e0 100644
--- a/original/uapi/linux/v4l2-dv-timings.h
+++ b/original/uapi/linux/v4l2-dv-timings.h
@@ -2,7 +2,7 @@
 /*
  * V4L2 DV timings header.
  *
- * Copyright (C) 2012-2016  Hans Verkuil <hans.verkuil@cisco.com>
+ * Copyright (C) 2012-2016  Hans Verkuil <hansverk@cisco.com>
  */
 
 #ifndef _V4L2_DV_TIMINGS_H
diff --git a/original/uapi/linux/vduse.h b/original/uapi/linux/vduse.h
index 11bd48c..68a627d 100644
--- a/original/uapi/linux/vduse.h
+++ b/original/uapi/linux/vduse.h
@@ -1,4 +1,4 @@
-/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
 #ifndef _UAPI_VDUSE_H_
 #define _UAPI_VDUSE_H_
 
diff --git a/original/uapi/linux/version.h b/original/uapi/linux/version.h
index 6fbb2f8..0db853c 100644
--- a/original/uapi/linux/version.h
+++ b/original/uapi/linux/version.h
@@ -1,5 +1,5 @@
-#define LINUX_VERSION_CODE 396288
+#define LINUX_VERSION_CODE 396800
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 12
+#define LINUX_VERSION_PATCHLEVEL 14
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/original/uapi/linux/vfio.h b/original/uapi/linux/vfio.h
index 2b68e6c..c8dbf82 100644
--- a/original/uapi/linux/vfio.h
+++ b/original/uapi/linux/vfio.h
@@ -35,7 +35,7 @@
 #define VFIO_EEH			5
 
 /* Two-stage IOMMU */
-#define VFIO_TYPE1_NESTING_IOMMU	6	/* Implies v2 */
+#define __VFIO_RESERVED_TYPE1_NESTING_IOMMU	6	/* Implies v2 */
 
 #define VFIO_SPAPR_TCE_v2_IOMMU		7
 
diff --git a/original/uapi/linux/videodev2.h b/original/uapi/linux/videodev2.h
index ac7919b..6254159 100644
--- a/original/uapi/linux/videodev2.h
+++ b/original/uapi/linux/videodev2.h
@@ -798,6 +798,7 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_S5C_UYVY_JPG v4l2_fourcc('S', '5', 'C', 'I') /* S5C73M3 interleaved UYVY/JPEG */
 #define V4L2_PIX_FMT_Y8I      v4l2_fourcc('Y', '8', 'I', ' ') /* Greyscale 8-bit L/R interleaved */
 #define V4L2_PIX_FMT_Y12I     v4l2_fourcc('Y', '1', '2', 'I') /* Greyscale 12-bit L/R interleaved */
+#define V4L2_PIX_FMT_Y16I     v4l2_fourcc('Y', '1', '6', 'I') /* Greyscale 16-bit L/R interleaved */
 #define V4L2_PIX_FMT_Z16      v4l2_fourcc('Z', '1', '6', ' ') /* Depth data 16-bit */
 #define V4L2_PIX_FMT_MT21C    v4l2_fourcc('M', 'T', '2', '1') /* Mediatek compressed block mode  */
 #define V4L2_PIX_FMT_MM21     v4l2_fourcc('M', 'M', '2', '1') /* Mediatek 8-bit block mode, two non-contiguous planes */
@@ -859,6 +860,8 @@ struct v4l2_pix_format {
 
 /* Vendor specific - used for RaspberryPi PiSP */
 #define V4L2_META_FMT_RPI_BE_CFG	v4l2_fourcc('R', 'P', 'B', 'C') /* PiSP BE configuration */
+#define V4L2_META_FMT_RPI_FE_CFG	v4l2_fourcc('R', 'P', 'F', 'C') /* PiSP FE configuration */
+#define V4L2_META_FMT_RPI_FE_STATS	v4l2_fourcc('R', 'P', 'F', 'S') /* PiSP FE stats */
 
 #ifdef __KERNEL__
 /*
@@ -906,6 +909,9 @@ struct v4l2_fmtdesc {
 #define V4L2_FMT_FLAG_CSC_QUANTIZATION		0x0100
 #define V4L2_FMT_FLAG_META_LINE_BASED		0x0200
 
+/*  Format description flag, to be ORed with the index */
+#define V4L2_FMTDESC_FLAG_ENUM_ALL		0x80000000
+
 	/* Frame Size and frame rate enumeration */
 /*
  *	F R A M E   S I Z E   E N U M E R A T I O N
diff --git a/original/uapi/linux/virtio_crypto.h b/original/uapi/linux/virtio_crypto.h
index 71a54a6..2fccb64 100644
--- a/original/uapi/linux/virtio_crypto.h
+++ b/original/uapi/linux/virtio_crypto.h
@@ -329,6 +329,7 @@ struct virtio_crypto_op_header {
 	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x00)
 #define VIRTIO_CRYPTO_AKCIPHER_DECRYPT \
 	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x01)
+	/* akcipher sign/verify opcodes are deprecated */
 #define VIRTIO_CRYPTO_AKCIPHER_SIGN \
 	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x02)
 #define VIRTIO_CRYPTO_AKCIPHER_VERIFY \
diff --git a/original/uapi/linux/virtio_pci.h b/original/uapi/linux/virtio_pci.h
index a820849..8549d45 100644
--- a/original/uapi/linux/virtio_pci.h
+++ b/original/uapi/linux/virtio_pci.h
@@ -40,6 +40,7 @@
 #define _LINUX_VIRTIO_PCI_H
 
 #include <linux/types.h>
+#include <linux/kernel.h>
 
 #ifndef VIRTIO_PCI_NO_LEGACY
 
@@ -115,6 +116,8 @@
 #define VIRTIO_PCI_CAP_PCI_CFG		5
 /* Additional shared memory capability */
 #define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8
+/* PCI vendor data configuration */
+#define VIRTIO_PCI_CAP_VENDOR_CFG	9
 
 /* This is the PCI capability header: */
 struct virtio_pci_cap {
@@ -129,6 +132,18 @@ struct virtio_pci_cap {
 	__le32 length;		/* Length of the structure, in bytes. */
 };
 
+/* This is the PCI vendor data capability header: */
+struct virtio_pci_vndr_data {
+	__u8 cap_vndr;		/* Generic PCI field: PCI_CAP_ID_VNDR */
+	__u8 cap_next;		/* Generic PCI field: next ptr. */
+	__u8 cap_len;		/* Generic PCI field: capability length */
+	__u8 cfg_type;		/* Identifies the structure. */
+	__u16 vendor_id;	/* Identifies the vendor-specific format. */
+	/* For Vendor Definition */
+	/* Pads structure to a multiple of 4 bytes */
+	/* Reads must not have side effects */
+};
+
 struct virtio_pci_cap64 {
 	struct virtio_pci_cap cap;
 	__le32 offset_hi;             /* Most sig 32 bits of offset */
@@ -240,6 +255,17 @@ struct virtio_pci_cfg_cap {
 #define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_READ		0x5
 #define VIRTIO_ADMIN_CMD_LEGACY_NOTIFY_INFO		0x6
 
+/* Device parts access commands. */
+#define VIRTIO_ADMIN_CMD_CAP_ID_LIST_QUERY		0x7
+#define VIRTIO_ADMIN_CMD_DEVICE_CAP_GET			0x8
+#define VIRTIO_ADMIN_CMD_DRIVER_CAP_SET			0x9
+#define VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE		0xa
+#define VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY		0xd
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET		0xe
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET			0xf
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_SET			0x10
+#define VIRTIO_ADMIN_CMD_DEV_MODE_SET			0x11
+
 struct virtio_admin_cmd_hdr {
 	__le16 opcode;
 	/*
@@ -286,4 +312,123 @@ struct virtio_admin_cmd_notify_info_result {
 	struct virtio_admin_cmd_notify_info_data entries[VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO];
 };
 
+#define VIRTIO_DEV_PARTS_CAP 0x0000
+
+struct virtio_dev_parts_cap {
+	__u8 get_parts_resource_objects_limit;
+	__u8 set_parts_resource_objects_limit;
+};
+
+#define MAX_CAP_ID __KERNEL_DIV_ROUND_UP(VIRTIO_DEV_PARTS_CAP + 1, 64)
+
+struct virtio_admin_cmd_query_cap_id_result {
+	__le64 supported_caps[MAX_CAP_ID];
+};
+
+struct virtio_admin_cmd_cap_get_data {
+	__le16 id;
+	__u8 reserved[6];
+};
+
+struct virtio_admin_cmd_cap_set_data {
+	__le16 id;
+	__u8 reserved[6];
+	__u8 cap_specific_data[];
+};
+
+struct virtio_admin_cmd_resource_obj_cmd_hdr {
+	__le16 type;
+	__u8 reserved[2];
+	__le32 id; /* Indicates unique resource object id per resource object type */
+};
+
+struct virtio_admin_cmd_resource_obj_create_data {
+	struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+	__le64 flags;
+	__u8 resource_obj_specific_data[];
+};
+
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS 0
+
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS_TYPE_GET 0
+#define VIRTIO_RESOURCE_OBJ_DEV_PARTS_TYPE_SET 1
+
+struct virtio_resource_obj_dev_parts {
+	__u8 type;
+	__u8 reserved[7];
+};
+
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_SIZE 0
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_COUNT 1
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_TYPE_LIST 2
+
+struct virtio_admin_cmd_dev_parts_metadata_data {
+	struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+	__u8 type;
+	__u8 reserved[7];
+};
+
+#define VIRTIO_DEV_PART_F_OPTIONAL 0
+
+struct virtio_dev_part_hdr {
+	__le16 part_type;
+	__u8 flags;
+	__u8 reserved;
+	union {
+		struct {
+			__le32 offset;
+			__le32 reserved;
+		} pci_common_cfg;
+		struct {
+			__le16 index;
+			__u8 reserved[6];
+		} vq_index;
+	} selector;
+	__le32 length;
+};
+
+struct virtio_dev_part {
+	struct virtio_dev_part_hdr hdr;
+	__u8 value[];
+};
+
+struct virtio_admin_cmd_dev_parts_metadata_result {
+	union {
+		struct {
+			__le32 size;
+			__le32 reserved;
+		} parts_size;
+		struct {
+			__le32 count;
+			__le32 reserved;
+		} hdr_list_count;
+		struct {
+			__le32 count;
+			__le32 reserved;
+			struct virtio_dev_part_hdr hdrs[];
+		} hdr_list;
+	};
+};
+
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET_TYPE_SELECTED 0
+#define VIRTIO_ADMIN_CMD_DEV_PARTS_GET_TYPE_ALL 1
+
+struct virtio_admin_cmd_dev_parts_get_data {
+	struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+	__u8 type;
+	__u8 reserved[7];
+	struct virtio_dev_part_hdr hdr_list[];
+};
+
+struct virtio_admin_cmd_dev_parts_set_data {
+	struct virtio_admin_cmd_resource_obj_cmd_hdr hdr;
+	struct virtio_dev_part parts[];
+};
+
+#define VIRTIO_ADMIN_CMD_DEV_MODE_F_STOPPED 0
+
+struct virtio_admin_cmd_dev_mode_set_data {
+	__u8 flags;
+};
+
 #endif
diff --git a/original/uapi/linux/virtio_snd.h b/original/uapi/linux/virtio_snd.h
index 5f4100c..a4cfb9f 100644
--- a/original/uapi/linux/virtio_snd.h
+++ b/original/uapi/linux/virtio_snd.h
@@ -25,7 +25,7 @@ struct virtio_snd_config {
 	__le32 streams;
 	/* # of available channel maps */
 	__le32 chmaps;
-	/* # of available control elements */
+	/* # of available control elements (if VIRTIO_SND_F_CTLS) */
 	__le32 controls;
 };
 
diff --git a/original/uapi/linux/vmclock-abi.h b/original/uapi/linux/vmclock-abi.h
new file mode 100644
index 0000000..2d99b29
--- /dev/null
+++ b/original/uapi/linux/vmclock-abi.h
@@ -0,0 +1,182 @@
+/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
+
+/*
+ * This structure provides a vDSO-style clock to VM guests, exposing the
+ * relationship (or lack thereof) between the CPU clock (TSC, timebase, arch
+ * counter, etc.) and real time. It is designed to address the problem of
+ * live migration, which other clock enlightenments do not.
+ *
+ * When a guest is live migrated, this affects the clock in two ways.
+ *
+ * First, even between identical hosts the actual frequency of the underlying
+ * counter will change within the tolerances of its specification (typically
+ * ±50PPM, or 4 seconds a day). This frequency also varies over time on the
+ * same host, but can be tracked by NTP as it generally varies slowly. With
+ * live migration there is a step change in the frequency, with no warning.
+ *
+ * Second, there may be a step change in the value of the counter itself, as
+ * its accuracy is limited by the precision of the NTP synchronization on the
+ * source and destination hosts.
+ *
+ * So any calibration (NTP, PTP, etc.) which the guest has done on the source
+ * host before migration is invalid, and needs to be redone on the new host.
+ *
+ * In its most basic mode, this structure provides only an indication to the
+ * guest that live migration has occurred. This allows the guest to know that
+ * its clock is invalid and take remedial action. For applications that need
+ * reliable accurate timestamps (e.g. distributed databases), the structure
+ * can be mapped all the way to userspace. This allows the application to see
+ * directly for itself that the clock is disrupted and take appropriate
+ * action, even when using a vDSO-style method to get the time instead of a
+ * system call.
+ *
+ * In its more advanced mode. this structure can also be used to expose the
+ * precise relationship of the CPU counter to real time, as calibrated by the
+ * host. This means that userspace applications can have accurate time
+ * immediately after live migration, rather than having to pause operations
+ * and wait for NTP to recover. This mode does, of course, rely on the
+ * counter being reliable and consistent across CPUs.
+ *
+ * Note that this must be true UTC, never with smeared leap seconds. If a
+ * guest wishes to construct a smeared clock, it can do so. Presenting a
+ * smeared clock through this interface would be problematic because it
+ * actually messes with the apparent counter *period*. A linear smearing
+ * of 1 ms per second would effectively tweak the counter period by 1000PPM
+ * at the start/end of the smearing period, while a sinusoidal smear would
+ * basically be impossible to represent.
+ *
+ * This structure is offered with the intent that it be adopted into the
+ * nascent virtio-rtc standard, as a virtio-rtc that does not address the live
+ * migration problem seems a little less than fit for purpose. For that
+ * reason, certain fields use precisely the same numeric definitions as in
+ * the virtio-rtc proposal. The structure can also be exposed through an ACPI
+ * device with the CID "VMCLOCK", modelled on the "VMGENID" device except for
+ * the fact that it uses a real _CRS to convey the address of the structure
+ * (which should be a full page, to allow for mapping directly to userspace).
+ */
+
+#ifndef __VMCLOCK_ABI_H__
+#define __VMCLOCK_ABI_H__
+
+#include <linux/types.h>
+
+struct vmclock_abi {
+	/* CONSTANT FIELDS */
+	__le32 magic;
+#define VMCLOCK_MAGIC	0x4b4c4356 /* "VCLK" */
+	__le32 size;		/* Size of region containing this structure */
+	__le16 version;	/* 1 */
+	__u8 counter_id; /* Matches VIRTIO_RTC_COUNTER_xxx except INVALID */
+#define VMCLOCK_COUNTER_ARM_VCNT	0
+#define VMCLOCK_COUNTER_X86_TSC		1
+#define VMCLOCK_COUNTER_INVALID		0xff
+	__u8 time_type; /* Matches VIRTIO_RTC_TYPE_xxx */
+#define VMCLOCK_TIME_UTC			0	/* Since 1970-01-01 00:00:00z */
+#define VMCLOCK_TIME_TAI			1	/* Since 1970-01-01 00:00:00z */
+#define VMCLOCK_TIME_MONOTONIC			2	/* Since undefined epoch */
+#define VMCLOCK_TIME_INVALID_SMEARED		3	/* Not supported */
+#define VMCLOCK_TIME_INVALID_MAYBE_SMEARED	4	/* Not supported */
+
+	/* NON-CONSTANT FIELDS PROTECTED BY SEQCOUNT LOCK */
+	__le32 seq_count;	/* Low bit means an update is in progress */
+	/*
+	 * This field changes to another non-repeating value when the CPU
+	 * counter is disrupted, for example on live migration. This lets
+	 * the guest know that it should discard any calibration it has
+	 * performed of the counter against external sources (NTP/PTP/etc.).
+	 */
+	__le64 disruption_marker;
+	__le64 flags;
+	/* Indicates that the tai_offset_sec field is valid */
+#define VMCLOCK_FLAG_TAI_OFFSET_VALID		(1 << 0)
+	/*
+	 * Optionally used to notify guests of pending maintenance events.
+	 * A guest which provides latency-sensitive services may wish to
+	 * remove itself from service if an event is coming up. Two flags
+	 * indicate the approximate imminence of the event.
+	 */
+#define VMCLOCK_FLAG_DISRUPTION_SOON		(1 << 1) /* About a day */
+#define VMCLOCK_FLAG_DISRUPTION_IMMINENT	(1 << 2) /* About an hour */
+#define VMCLOCK_FLAG_PERIOD_ESTERROR_VALID	(1 << 3)
+#define VMCLOCK_FLAG_PERIOD_MAXERROR_VALID	(1 << 4)
+#define VMCLOCK_FLAG_TIME_ESTERROR_VALID	(1 << 5)
+#define VMCLOCK_FLAG_TIME_MAXERROR_VALID	(1 << 6)
+	/*
+	 * If the MONOTONIC flag is set then (other than leap seconds) it is
+	 * guaranteed that the time calculated according this structure at
+	 * any given moment shall never appear to be later than the time
+	 * calculated via the structure at any *later* moment.
+	 *
+	 * In particular, a timestamp based on a counter reading taken
+	 * immediately after setting the low bit of seq_count (and the
+	 * associated memory barrier), using the previously-valid time and
+	 * period fields, shall never be later than a timestamp based on
+	 * a counter reading taken immediately before *clearing* the low
+	 * bit again after the update, using the about-to-be-valid fields.
+	 */
+#define VMCLOCK_FLAG_TIME_MONOTONIC		(1 << 7)
+
+	__u8 pad[2];
+	__u8 clock_status;
+#define VMCLOCK_STATUS_UNKNOWN		0
+#define VMCLOCK_STATUS_INITIALIZING	1
+#define VMCLOCK_STATUS_SYNCHRONIZED	2
+#define VMCLOCK_STATUS_FREERUNNING	3
+#define VMCLOCK_STATUS_UNRELIABLE	4
+
+	/*
+	 * The time exposed through this device is never smeared. This field
+	 * corresponds to the 'subtype' field in virtio-rtc, which indicates
+	 * the smearing method. However in this case it provides a *hint* to
+	 * the guest operating system, such that *if* the guest OS wants to
+	 * provide its users with an alternative clock which does not follow
+	 * UTC, it may do so in a fashion consistent with the other systems
+	 * in the nearby environment.
+	 */
+	__u8 leap_second_smearing_hint; /* Matches VIRTIO_RTC_SUBTYPE_xxx */
+#define VMCLOCK_SMEARING_STRICT		0
+#define VMCLOCK_SMEARING_NOON_LINEAR	1
+#define VMCLOCK_SMEARING_UTC_SLS	2
+	__le16 tai_offset_sec; /* Actually two's complement signed */
+	__u8 leap_indicator;
+	/*
+	 * This field is based on the VIRTIO_RTC_LEAP_xxx values as defined
+	 * in the current draft of virtio-rtc, but since smearing cannot be
+	 * used with the shared memory device, some values are not used.
+	 *
+	 * The _POST_POS and _POST_NEG values allow the guest to perform
+	 * its own smearing during the day or so after a leap second when
+	 * such smearing may need to continue being applied for a leap
+	 * second which is now theoretically "historical".
+	 */
+#define VMCLOCK_LEAP_NONE	0x00	/* No known nearby leap second */
+#define VMCLOCK_LEAP_PRE_POS	0x01	/* Positive leap second at EOM */
+#define VMCLOCK_LEAP_PRE_NEG	0x02	/* Negative leap second at EOM */
+#define VMCLOCK_LEAP_POS	0x03	/* Set during 23:59:60 second */
+#define VMCLOCK_LEAP_POST_POS	0x04
+#define VMCLOCK_LEAP_POST_NEG	0x05
+
+	/* Bit shift for counter_period_frac_sec and its error rate */
+	__u8 counter_period_shift;
+	/*
+	 * Paired values of counter and UTC at a given point in time.
+	 */
+	__le64 counter_value;
+	/*
+	 * Counter period, and error margin of same. The unit of these
+	 * fields is 1/2^(64 + counter_period_shift) of a second.
+	 */
+	__le64 counter_period_frac_sec;
+	__le64 counter_period_esterror_rate_frac_sec;
+	__le64 counter_period_maxerror_rate_frac_sec;
+
+	/*
+	 * Time according to time_type field above.
+	 */
+	__le64 time_sec;		/* Seconds since time_type epoch */
+	__le64 time_frac_sec;		/* Units of 1/2^64 of a second */
+	__le64 time_esterror_nanosec;
+	__le64 time_maxerror_nanosec;
+};
+
+#endif /*  __VMCLOCK_ABI_H__ */
diff --git a/original/uapi/linux/xattr.h b/original/uapi/linux/xattr.h
index 9463db2..9854f9c 100644
--- a/original/uapi/linux/xattr.h
+++ b/original/uapi/linux/xattr.h
@@ -11,6 +11,7 @@
 */
 
 #include <linux/libc-compat.h>
+#include <linux/types.h>
 
 #ifndef _UAPI_LINUX_XATTR_H
 #define _UAPI_LINUX_XATTR_H
@@ -20,6 +21,12 @@
 
 #define XATTR_CREATE	0x1	/* set value, fail if attr already exists */
 #define XATTR_REPLACE	0x2	/* set value, fail if attr does not exist */
+
+struct xattr_args {
+	__aligned_u64 __user value;
+	__u32 size;
+	__u32 flags;
+};
 #endif
 
 /* Namespaces */
diff --git a/original/uapi/linux/xfrm.h b/original/uapi/linux/xfrm.h
index f287015..a23495c 100644
--- a/original/uapi/linux/xfrm.h
+++ b/original/uapi/linux/xfrm.h
@@ -158,7 +158,8 @@ enum {
 #define XFRM_MODE_ROUTEOPTIMIZATION 2
 #define XFRM_MODE_IN_TRIGGER 3
 #define XFRM_MODE_BEET 4
-#define XFRM_MODE_MAX 5
+#define XFRM_MODE_IPTFS 5
+#define XFRM_MODE_MAX 6
 
 /* Netlink configuration messages.  */
 enum {
@@ -322,6 +323,13 @@ enum xfrm_attr_type_t {
 	XFRMA_MTIMER_THRESH,	/* __u32 in seconds for input SA */
 	XFRMA_SA_DIR,		/* __u8 */
 	XFRMA_NAT_KEEPALIVE_INTERVAL,	/* __u32 in seconds for NAT keepalive */
+	XFRMA_SA_PCPU,		/* __u32 */
+	XFRMA_IPTFS_DROP_TIME,	/* __u32 in: usec to wait for next seq */
+	XFRMA_IPTFS_REORDER_WINDOW, /* __u16 in: reorder window size (pkts) */
+	XFRMA_IPTFS_DONT_FRAG,	/* out: don't use fragmentation */
+	XFRMA_IPTFS_INIT_DELAY,	/* __u32 out: initial packet wait delay (usec) */
+	XFRMA_IPTFS_MAX_QSIZE,	/* __u32 out: max ingress queue size (octets) */
+	XFRMA_IPTFS_PKT_SIZE,	/* __u32 out: size of outer packet, 0 for PMTU */
 	__XFRMA_MAX
 
 #define XFRMA_OUTPUT_MARK XFRMA_SET_MARK	/* Compatibility */
@@ -437,6 +445,7 @@ struct xfrm_userpolicy_info {
 #define XFRM_POLICY_LOCALOK	1	/* Allow user to override global policy */
 	/* Automatically expand selector to include matching ICMP payloads. */
 #define XFRM_POLICY_ICMP	2
+#define XFRM_POLICY_CPU_ACQUIRE	4
 	__u8				share;
 };
 
diff --git a/original/uapi/mtd/ubi-user.h b/original/uapi/mtd/ubi-user.h
index e157160..aa872a4 100644
--- a/original/uapi/mtd/ubi-user.h
+++ b/original/uapi/mtd/ubi-user.h
@@ -175,6 +175,8 @@
 #define UBI_IOCRPEB _IOW(UBI_IOC_MAGIC, 4, __s32)
 /* Force scrubbing on the specified PEB */
 #define UBI_IOCSPEB _IOW(UBI_IOC_MAGIC, 5, __s32)
+/* Read detailed device erase counter information */
+#define UBI_IOCECNFO _IOWR(UBI_IOC_MAGIC, 6, struct ubi_ecinfo_req)
 
 /* ioctl commands of the UBI control character device */
 
@@ -412,6 +414,37 @@ struct ubi_rnvol_req {
 	} ents[UBI_MAX_RNVOL];
 } __packed;
 
+/**
+ * struct ubi_ecinfo_req - a data structure used for requesting and receiving
+ * erase block counter information from a UBI device.
+ *
+ * @start: index of first physical erase block to read (in)
+ * @length: number of erase counters to read (in)
+ * @read_length: number of erase counters that was actually read (out)
+ * @padding: reserved for future, not used, has to be zeroed
+ * @erase_counters: array of erase counter values (out)
+ *
+ * This structure is used to retrieve erase counter information for a specified
+ * range of PEBs on a UBI device.
+ * Erase counters are read from @start and attempts to read @length number of
+ * erase counters.
+ * The retrieved values are stored in the @erase_counters array. It is the
+ * responsibility of the caller to allocate enough memory for storing @length
+ * elements in the @erase_counters array.
+ * If a block is bad or if the erase counter is unknown the corresponding value
+ * in the array will be set to -1.
+ * The @read_length field will indicate the number of erase counters actually
+ * read. Typically @read_length will be limited due to memory or the number of
+ * PEBs on the UBI device.
+ */
+struct ubi_ecinfo_req {
+	__s32 start;
+	__s32 length;
+	__s32 read_length;
+	__s8  padding[16];
+	__s32 erase_counters[];
+}  __packed;
+
 /**
  * struct ubi_leb_change_req - a data structure used in atomic LEB change
  *                             requests.
diff --git a/original/uapi/rdma/efa-abi.h b/original/uapi/rdma/efa-abi.h
index d689b8b..11b94b0 100644
--- a/original/uapi/rdma/efa-abi.h
+++ b/original/uapi/rdma/efa-abi.h
@@ -95,7 +95,8 @@ struct efa_ibv_create_qp {
 	__u32 sq_ring_size; /* bytes */
 	__u32 driver_qp_type;
 	__u16 flags;
-	__u8 reserved_90[6];
+	__u8 sl;
+	__u8 reserved_98[5];
 };
 
 struct efa_ibv_create_qp_resp {
diff --git a/original/uapi/rdma/mlx5-abi.h b/original/uapi/rdma/mlx5-abi.h
index d4f6a36..8a6ad6c 100644
--- a/original/uapi/rdma/mlx5-abi.h
+++ b/original/uapi/rdma/mlx5-abi.h
@@ -252,6 +252,7 @@ enum mlx5_ib_query_dev_resp_flags {
 	MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD  = 1 << 1,
 	MLX5_IB_QUERY_DEV_RESP_PACKET_BASED_CREDIT_MODE = 1 << 2,
 	MLX5_IB_QUERY_DEV_RESP_FLAGS_SCAT2CQE_DCT = 1 << 3,
+	MLX5_IB_QUERY_DEV_RESP_FLAGS_OOO_DP = 1 << 4,
 };
 
 enum mlx5_ib_tunnel_offloads {
@@ -439,6 +440,10 @@ struct mlx5_ib_burst_info {
 	__u16       reserved;
 };
 
+enum mlx5_ib_modify_qp_mask {
+	MLX5_IB_MODIFY_QP_OOO_DP = 1 << 0,
+};
+
 struct mlx5_ib_modify_qp {
 	__u32			   comp_mask;
 	struct mlx5_ib_burst_info  burst_info;
diff --git a/original/uapi/rdma/rdma_netlink.h b/original/uapi/rdma/rdma_netlink.h
index 39be09c..9f9cf20 100644
--- a/original/uapi/rdma/rdma_netlink.h
+++ b/original/uapi/rdma/rdma_netlink.h
@@ -638,6 +638,8 @@ enum rdma_nl_notify_event_type {
 	RDMA_UNREGISTER_EVENT,
 	RDMA_NETDEV_ATTACH_EVENT,
 	RDMA_NETDEV_DETACH_EVENT,
+	RDMA_RENAME_EVENT,
+	RDMA_NETDEV_RENAME_EVENT,
 };
 
 #endif /* _UAPI_RDMA_NETLINK_H */
diff --git a/original/uapi/sound/asequencer.h b/original/uapi/sound/asequencer.h
index bc30c1f..a5c41f7 100644
--- a/original/uapi/sound/asequencer.h
+++ b/original/uapi/sound/asequencer.h
@@ -10,7 +10,7 @@
 #include <sound/asound.h>
 
 /** version of the sequencer */
-#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 4)
+#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 5)
 
 /**
  * definition of sequencer event types
@@ -92,6 +92,9 @@
 #define SNDRV_SEQ_EVENT_PORT_SUBSCRIBED	66	/* ports connected */
 #define SNDRV_SEQ_EVENT_PORT_UNSUBSCRIBED 67	/* ports disconnected */
 
+#define SNDRV_SEQ_EVENT_UMP_EP_CHANGE	68	/* UMP EP info has changed */
+#define SNDRV_SEQ_EVENT_UMP_BLOCK_CHANGE 69	/* UMP block info has changed */
+
 /* 70-89:  synthesizer events - obsoleted */
 
 /** user-defined events with fixed length
@@ -253,6 +256,12 @@ struct snd_seq_ev_quote {
 	struct snd_seq_event *event;		/* quoted event */
 } __packed;
 
+	/* UMP info change notify */
+struct snd_seq_ev_ump_notify {
+	unsigned char client;	/**< Client number */
+	unsigned char block;	/**< Block number (optional) */
+};
+
 union snd_seq_event_data { /* event data... */
 	struct snd_seq_ev_note note;
 	struct snd_seq_ev_ctrl control;
@@ -265,6 +274,7 @@ union snd_seq_event_data { /* event data... */
 	struct snd_seq_connect connect;
 	struct snd_seq_result result;
 	struct snd_seq_ev_quote quote;
+	struct snd_seq_ev_ump_notify ump_notify;
 };
 
 	/* sequencer event */
diff --git a/original/uapi/sound/asound.h b/original/uapi/sound/asound.h
index 4cd5132..5a049ee 100644
--- a/original/uapi/sound/asound.h
+++ b/original/uapi/sound/asound.h
@@ -716,7 +716,7 @@ enum {
  *  Raw MIDI section - /dev/snd/midi??
  */
 
-#define SNDRV_RAWMIDI_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 4)
+#define SNDRV_RAWMIDI_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 5)
 
 enum {
 	SNDRV_RAWMIDI_STREAM_OUTPUT = 0,
@@ -728,6 +728,9 @@ enum {
 #define SNDRV_RAWMIDI_INFO_INPUT		0x00000002
 #define SNDRV_RAWMIDI_INFO_DUPLEX		0x00000004
 #define SNDRV_RAWMIDI_INFO_UMP			0x00000008
+#define SNDRV_RAWMIDI_INFO_STREAM_INACTIVE	0x00000010
+
+#define SNDRV_RAWMIDI_DEVICE_UNKNOWN		0
 
 struct snd_rawmidi_info {
 	unsigned int device;		/* RO/WR (control): device number */
@@ -740,7 +743,8 @@ struct snd_rawmidi_info {
 	unsigned char subname[32];	/* name of active or selected subdevice */
 	unsigned int subdevices_count;
 	unsigned int subdevices_avail;
-	unsigned char reserved[64];	/* reserved for future use */
+	int tied_device;		/* R: tied rawmidi device (UMP/legacy) */
+	unsigned char reserved[60];	/* reserved for future use */
 };
 
 #define SNDRV_RAWMIDI_MODE_FRAMING_MASK		(7<<0)
diff --git a/original/uapi/sound/compress_offload.h b/original/uapi/sound/compress_offload.h
index d185957..d62eb93 100644
--- a/original/uapi/sound/compress_offload.h
+++ b/original/uapi/sound/compress_offload.h
@@ -14,7 +14,7 @@
 #include <sound/compress_params.h>
 
 
-#define SNDRV_COMPRESS_VERSION SNDRV_PROTOCOL_VERSION(0, 2, 0)
+#define SNDRV_COMPRESS_VERSION SNDRV_PROTOCOL_VERSION(0, 3, 0)
 /**
  * struct snd_compressed_buffer - compressed buffer
  * @fragment_size: size of buffer fragment in bytes
@@ -68,7 +68,8 @@ struct snd_compr_avail {
 
 enum snd_compr_direction {
 	SND_COMPRESS_PLAYBACK = 0,
-	SND_COMPRESS_CAPTURE
+	SND_COMPRESS_CAPTURE,
+	SND_COMPRESS_ACCEL
 };
 
 /**
@@ -127,6 +128,59 @@ struct snd_compr_metadata {
 	 __u32 value[8];
 } __attribute__((packed, aligned(4)));
 
+/* flags for struct snd_compr_task */
+#define SND_COMPRESS_TFLG_NEW_STREAM		(1<<0)	/* mark for the new stream data */
+
+/**
+ * struct snd_compr_task - task primitive for non-realtime operation
+ * @seqno: sequence number (task identifier)
+ * @origin_seqno: previous sequence number (task identifier) - for reuse
+ * @input_fd: data input file descriptor (dma-buf)
+ * @output_fd: data output file descriptor (dma-buf)
+ * @input_size: filled data in bytes (from caller, must not exceed fragment size)
+ * @flags: see SND_COMPRESS_TFLG_* defines
+ * @reserved: reserved for future extension
+ */
+struct snd_compr_task {
+	__u64 seqno;
+	__u64 origin_seqno;
+	int input_fd;
+	int output_fd;
+	__u64 input_size;
+	__u32 flags;
+	__u8 reserved[16];
+} __attribute__((packed, aligned(4)));
+
+/**
+ * enum snd_compr_state - task state
+ * @SND_COMPRESS_TASK_STATE_IDLE: task is not queued
+ * @SND_COMPRESS_TASK_STATE_ACTIVE: task is in the queue
+ * @SND_COMPRESS_TASK_STATE_FINISHED: task was processed, output is available
+ */
+enum snd_compr_state {
+	SND_COMPRESS_TASK_STATE_IDLE = 0,
+	SND_COMPRESS_TASK_STATE_ACTIVE,
+	SND_COMPRESS_TASK_STATE_FINISHED
+};
+
+/**
+ * struct snd_compr_task_status - task status
+ * @seqno: sequence number (task identifier)
+ * @input_size: filled data in bytes (from user space)
+ * @output_size: filled data in bytes (from driver)
+ * @output_flags: reserved for future (all zeros - from driver)
+ * @state: actual task state (SND_COMPRESS_TASK_STATE_*)
+ * @reserved: reserved for future extension
+ */
+struct snd_compr_task_status {
+	__u64 seqno;
+	__u64 input_size;
+	__u64 output_size;
+	__u32 output_flags;
+	__u8 state;
+	__u8 reserved[15];
+} __attribute__((packed, aligned(4)));
+
 /*
  * compress path ioctl definitions
  * SNDRV_COMPRESS_GET_CAPS: Query capability of DSP
@@ -164,6 +218,14 @@ struct snd_compr_metadata {
 #define SNDRV_COMPRESS_DRAIN		_IO('C', 0x34)
 #define SNDRV_COMPRESS_NEXT_TRACK	_IO('C', 0x35)
 #define SNDRV_COMPRESS_PARTIAL_DRAIN	_IO('C', 0x36)
+
+
+#define SNDRV_COMPRESS_TASK_CREATE	_IOWR('C', 0x60, struct snd_compr_task)
+#define SNDRV_COMPRESS_TASK_FREE	_IOW('C', 0x61, __u64)
+#define SNDRV_COMPRESS_TASK_START	_IOWR('C', 0x62, struct snd_compr_task)
+#define SNDRV_COMPRESS_TASK_STOP	_IOW('C', 0x63, __u64)
+#define SNDRV_COMPRESS_TASK_STATUS	_IOWR('C', 0x68, struct snd_compr_task_status)
+
 /*
  * TODO
  * 1. add mmap support
diff --git a/original/uapi/sound/compress_params.h b/original/uapi/sound/compress_params.h
index ddc7732..bc7648a 100644
--- a/original/uapi/sound/compress_params.h
+++ b/original/uapi/sound/compress_params.h
@@ -334,6 +334,14 @@ union snd_codec_options {
 	struct snd_dec_wma wma_d;
 	struct snd_dec_alac alac_d;
 	struct snd_dec_ape ape_d;
+	struct {
+		__u32 out_sample_rate;
+	} src_d;
+} __attribute__((packed, aligned(4)));
+
+struct snd_codec_desc_src {
+	__u32 out_sample_rate_min;
+	__u32 out_sample_rate_max;
 } __attribute__((packed, aligned(4)));
 
 /** struct snd_codec_desc - description of codec capabilities
@@ -347,6 +355,9 @@ union snd_codec_options {
  * @modes: Supported modes. See SND_AUDIOMODE defines
  * @formats: Supported formats. See SND_AUDIOSTREAMFORMAT defines
  * @min_buffer: Minimum buffer size handled by codec implementation
+ * @pcm_formats: Output (for decoders) or input (for encoders)
+ *               PCM formats (required to accel mode, 0 for other modes)
+ * @u_space: union space (for codec dependent data)
  * @reserved: reserved for future use
  *
  * This structure provides a scalar value for profiles, modes and stream
@@ -370,7 +381,12 @@ struct snd_codec_desc {
 	__u32 modes;
 	__u32 formats;
 	__u32 min_buffer;
-	__u32 reserved[15];
+	__u32 pcm_formats;
+	union {
+		__u32 u_space[6];
+		struct snd_codec_desc_src src;
+	} __attribute__((packed, aligned(4)));
+	__u32 reserved[8];
 } __attribute__((packed, aligned(4)));
 
 /** struct snd_codec
@@ -395,6 +411,8 @@ struct snd_codec_desc {
  * @align: Block alignment in bytes of an audio sample.
  *		Only required for PCM or IEC formats.
  * @options: encoder-specific settings
+ * @pcm_format: Output (for decoders) or input (for encoders)
+ *               PCM formats (required to accel mode, 0 for other modes)
  * @reserved: reserved for future use
  */
 
@@ -411,7 +429,8 @@ struct snd_codec {
 	__u32 format;
 	__u32 align;
 	union snd_codec_options options;
-	__u32 reserved[3];
+	__u32 pcm_format;
+	__u32 reserved[2];
 } __attribute__((packed, aligned(4)));
 
 #endif
diff --git a/original/uapi/sound/fcp.h b/original/uapi/sound/fcp.h
new file mode 100644
index 0000000..aea4289
--- /dev/null
+++ b/original/uapi/sound/fcp.h
@@ -0,0 +1,120 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * Focusrite Control Protocol Driver for ALSA
+ *
+ * Copyright (c) 2024-2025 by Geoffrey D. Bennett <g at b4.vu>
+ */
+/*
+ * DOC: FCP (Focusrite Control Protocol) User-Space API
+ *
+ * This header defines the interface between the FCP kernel driver and
+ * user-space programs to enable the use of the proprietary features
+ * available in Focusrite USB audio interfaces. This includes Scarlett
+ * 2nd Gen, 3rd Gen, 4th Gen, Clarett USB, Clarett+, and Vocaster
+ * series devices.
+ *
+ * The interface is provided via ALSA's hwdep interface. Opening the
+ * hwdep device requires CAP_SYS_RAWIO privileges as this interface
+ * provides near-direct access.
+ *
+ * For details on the FCP protocol, refer to the kernel scarlett2
+ * driver in sound/usb/mixer_scarlett2.c and the fcp-support project
+ * at https://github.com/geoffreybennett/fcp-support
+ *
+ * For examples of using these IOCTLs, see the fcp-server source in
+ * the fcp-support project.
+ *
+ * IOCTL Interface
+ * --------------
+ * FCP_IOCTL_PVERSION:
+ *   Returns the protocol version supported by the driver.
+ *
+ * FCP_IOCTL_INIT:
+ *   Initialises the protocol and synchronises sequence numbers
+ *   between the driver and device. Must be called at least once
+ *   before sending commands. Can be safely called again at any time.
+ *
+ * FCP_IOCTL_CMD:
+ *   Sends an FCP command to the device and returns the response.
+ *   Requires prior initialisation via FCP_IOCTL_INIT.
+ *
+ * FCP_IOCTL_SET_METER_MAP:
+ *   Configures the Level Meter control's mapping between device
+ *   meters and control channels. Requires FCP_IOCTL_INIT to have been
+ *   called first. The map size and number of slots cannot be changed
+ *   after initial configuration, although the map itself can be
+ *   updated. Once configured, the Level Meter remains functional even
+ *   after the hwdep device is closed.
+ *
+ * FCP_IOCTL_SET_METER_LABELS:
+ *   Set the labels for the Level Meter control. Requires
+ *   FCP_IOCTL_SET_METER_MAP to have been called first. labels[]
+ *   should contain a sequence of null-terminated labels corresponding
+ *   to the control's channels.
+ */
+#ifndef __UAPI_SOUND_FCP_H
+#define __UAPI_SOUND_FCP_H
+
+#include <linux/types.h>
+#include <linux/ioctl.h>
+
+#define FCP_HWDEP_MAJOR 2
+#define FCP_HWDEP_MINOR 0
+#define FCP_HWDEP_SUBMINOR 0
+
+#define FCP_HWDEP_VERSION \
+	((FCP_HWDEP_MAJOR << 16) | \
+	 (FCP_HWDEP_MINOR << 8) | \
+	  FCP_HWDEP_SUBMINOR)
+
+#define FCP_HWDEP_VERSION_MAJOR(v) (((v) >> 16) & 0xFF)
+#define FCP_HWDEP_VERSION_MINOR(v) (((v) >> 8) & 0xFF)
+#define FCP_HWDEP_VERSION_SUBMINOR(v) ((v) & 0xFF)
+
+/* Get protocol version */
+#define FCP_IOCTL_PVERSION _IOR('S', 0x60, int)
+
+/* Start the protocol */
+
+/* Step 0 and step 2 responses are variable length and placed in
+ * resp[] one after the other.
+ */
+struct fcp_init {
+	__u16 step0_resp_size;
+	__u16 step2_resp_size;
+	__u32 init1_opcode;
+	__u32 init2_opcode;
+	__u8  resp[];
+} __attribute__((packed));
+
+#define FCP_IOCTL_INIT _IOWR('S', 0x64, struct fcp_init)
+
+/* Perform a command */
+
+/* The request data is placed in data[] and the response data will
+ * overwrite it.
+ */
+struct fcp_cmd {
+	__u32 opcode;
+	__u16 req_size;
+	__u16 resp_size;
+	__u8  data[];
+} __attribute__((packed));
+#define FCP_IOCTL_CMD _IOWR('S', 0x65, struct fcp_cmd)
+
+/* Set the meter map */
+struct fcp_meter_map {
+	__u16 map_size;
+	__u16 meter_slots;
+	__s16 map[];
+} __attribute__((packed));
+#define FCP_IOCTL_SET_METER_MAP _IOW('S', 0x66, struct fcp_meter_map)
+
+/* Set the meter labels */
+struct fcp_meter_labels {
+	__u16 labels_size;
+	char  labels[];
+} __attribute__((packed));
+#define FCP_IOCTL_SET_METER_LABELS _IOW('S', 0x67, struct fcp_meter_labels)
+
+#endif /* __UAPI_SOUND_FCP_H */
diff --git a/original/uapi/sound/sof/tokens.h b/original/uapi/sound/sof/tokens.h
index 0a246bc..c28c766 100644
--- a/original/uapi/sound/sof/tokens.h
+++ b/original/uapi/sound/sof/tokens.h
@@ -153,6 +153,8 @@
 /* Stream */
 #define SOF_TKN_STREAM_PLAYBACK_COMPATIBLE_D0I3	1200
 #define SOF_TKN_STREAM_CAPTURE_COMPATIBLE_D0I3	1201
+#define SOF_TKN_STREAM_PLAYBACK_PAUSE_SUPPORTED	1202
+#define SOF_TKN_STREAM_CAPTURE_PAUSE_SUPPORTED	1203
 
 /* Led control for mute switches */
 #define SOF_TKN_MUTE_LED_USE			1300
diff --git a/original/uapi/sound/tlv.h b/original/uapi/sound/tlv.h
index b99a241..5bb55c8 100644
--- a/original/uapi/sound/tlv.h
+++ b/original/uapi/sound/tlv.h
@@ -18,6 +18,8 @@
 #define SNDRV_CTL_TLVT_CHMAP_VAR	0x102	/* channels freely swappable */
 #define SNDRV_CTL_TLVT_CHMAP_PAIRED	0x103	/* pair-wise swappable */
 
+#define SNDRV_CTL_TLVT_FCP_CHANNEL_LABELS	0x110	/* channel labels */
+
 /*
  * TLV structure is right behind the struct snd_ctl_tlv:
  *   unsigned int type  	- see SNDRV_CTL_TLVT_*
```

