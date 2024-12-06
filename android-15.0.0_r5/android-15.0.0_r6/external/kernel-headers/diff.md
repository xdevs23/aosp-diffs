```diff
diff --git a/modified/scsi/scsi.h b/modified/scsi/scsi.h
index 7a9ca9d..ff326d5 100644
--- a/modified/scsi/scsi.h
+++ b/modified/scsi/scsi.h
@@ -8,9 +8,9 @@
 
 #include <linux/types.h>
 
+#include <asm/param.h>
+
 #ifdef __KERNEL__
-#include <linux/scatterlist.h>
-#include <linux/kernel.h>
 #include <scsi/scsi_common.h>
 #endif /* __KERNEL__ */
 #include <scsi/scsi_proto.h>
@@ -75,7 +75,7 @@ static inline int scsi_is_wlun(u64 lun)
  * @status: the status passed up from the driver (including host and
  *          driver components)
  *
- * This returns true if the status code is SAM_STAT_CHECK_CONDITION.
+ * Returns: %true if the status code is SAM_STAT_CHECK_CONDITION.
  */
 static inline int scsi_status_is_check_condition(int status)
 {
@@ -199,12 +199,13 @@ enum scsi_disposition {
 /* Used to obtain the PCI location of a device */
 #define SCSI_IOCTL_GET_PCI		0x5387
 
-/** scsi_status_is_good - check the status return.
+/**
+ * scsi_status_is_good - check the status return.
  *
  * @status: the status passed up from the driver (including host and
  *          driver components)
  *
- * This returns true for known good conditions that may be treated as
+ * Returns: %true for known good conditions that may be treated as
  * command completed normally
  */
 static inline bool scsi_status_is_good(int status)
diff --git a/modified/scsi/scsi_proto.h b/modified/scsi/scsi_proto.h
index 9ee4c24..501749b 100644
--- a/modified/scsi/scsi_proto.h
+++ b/modified/scsi/scsi_proto.h
@@ -10,6 +10,9 @@
 #ifndef _SCSI_PROTO_H_
 #define _SCSI_PROTO_H_
 
+#ifdef __KERNEL__
+#include <linux/build_bug.h>
+#endif /* __KERNEL__ */
 #include <linux/types.h>
 
 /*
@@ -127,6 +130,7 @@
 #define	SAI_READ_CAPACITY_16  0x10
 #define SAI_GET_LBA_STATUS    0x12
 #define SAI_REPORT_REFERRALS  0x13
+#define SAI_GET_STREAM_STATUS 0x16
 /* values for maintenance in */
 #define MI_REPORT_IDENTIFYING_INFORMATION 0x05
 #define MI_REPORT_TARGET_PGS  0x0a
@@ -277,6 +281,82 @@ enum scsi_protocol {
 struct scsi_lun {
 	__u8 scsi_lun[8];
 };
+
+/* SBC-5 IO advice hints group descriptor */
+struct scsi_io_group_descriptor {
+#if defined(__BIG_ENDIAN)
+	u8 io_advice_hints_mode: 2;
+	u8 reserved1: 3;
+	u8 st_enble: 1;
+	u8 cs_enble: 1;
+	u8 ic_enable: 1;
+#elif defined(__LITTLE_ENDIAN)
+	u8 ic_enable: 1;
+	u8 cs_enble: 1;
+	u8 st_enble: 1;
+	u8 reserved1: 3;
+	u8 io_advice_hints_mode: 2;
+#else
+#error
+#endif
+	u8 reserved2[3];
+	/* Logical block markup descriptor */
+#if defined(__BIG_ENDIAN)
+	u8 acdlu: 1;
+	u8 reserved3: 1;
+	u8 rlbsr: 2;
+	u8 lbm_descriptor_type: 4;
+#elif defined(__LITTLE_ENDIAN)
+	u8 lbm_descriptor_type: 4;
+	u8 rlbsr: 2;
+	u8 reserved3: 1;
+	u8 acdlu: 1;
+#else
+#error
+#endif
+	u8 params[2];
+	u8 reserved4;
+	u8 reserved5[8];
+};
+
+static_assert(sizeof(struct scsi_io_group_descriptor) == 16);
+
+/* SCSI stream status descriptor */
+struct scsi_stream_status {
+#if defined(__BIG_ENDIAN)
+	u8 perm: 1;
+	u8 reserved1: 7;
+#elif defined(__LITTLE_ENDIAN)
+	u8 reserved1: 7;
+	u8 perm: 1;
+#else
+#error
+#endif
+	u8 reserved2;
+	__be16 stream_identifier;
+#if defined(__BIG_ENDIAN)
+	u8 reserved3: 2;
+	u8 rel_lifetime: 6;
+#elif defined(__LITTLE_ENDIAN)
+	u8 rel_lifetime: 6;
+	u8 reserved3: 2;
+#else
+#error
+#endif
+	u8 reserved4[3];
+};
+
+static_assert(sizeof(struct scsi_stream_status) == 8);
+
+/* GET STREAM STATUS parameter data */
+struct scsi_stream_status_header {
+	__be32 len;	/* length in bytes of stream_status[] array. */
+	u16 reserved;
+	__be16 number_of_open_streams;
+	DECLARE_FLEX_ARRAY(struct scsi_stream_status, stream_status);
+};
+
+static_assert(sizeof(struct scsi_stream_status_header) == 8);
 #endif /* __KERNEL__ */
 
 /* SPC asymmetric access states */
diff --git a/original/scsi/scsi.h b/original/scsi/scsi.h
index 4498f84..96b3503 100644
--- a/original/scsi/scsi.h
+++ b/original/scsi/scsi.h
@@ -7,8 +7,9 @@
 #define _SCSI_SCSI_H
 
 #include <linux/types.h>
-#include <linux/scatterlist.h>
-#include <linux/kernel.h>
+
+#include <asm/param.h>
+
 #include <scsi/scsi_common.h>
 #include <scsi/scsi_proto.h>
 #include <scsi/scsi_status.h>
@@ -69,7 +70,7 @@ static inline int scsi_is_wlun(u64 lun)
  * @status: the status passed up from the driver (including host and
  *          driver components)
  *
- * This returns true if the status code is SAM_STAT_CHECK_CONDITION.
+ * Returns: %true if the status code is SAM_STAT_CHECK_CONDITION.
  */
 static inline int scsi_status_is_check_condition(int status)
 {
@@ -189,12 +190,13 @@ enum scsi_disposition {
 /* Used to obtain the PCI location of a device */
 #define SCSI_IOCTL_GET_PCI		0x5387
 
-/** scsi_status_is_good - check the status return.
+/**
+ * scsi_status_is_good - check the status return.
  *
  * @status: the status passed up from the driver (including host and
  *          driver components)
  *
- * This returns true for known good conditions that may be treated as
+ * Returns: %true for known good conditions that may be treated as
  * command completed normally
  */
 static inline bool scsi_status_is_good(int status)
diff --git a/original/scsi/scsi_proto.h b/original/scsi/scsi_proto.h
index 07d65c1..843106e 100644
--- a/original/scsi/scsi_proto.h
+++ b/original/scsi/scsi_proto.h
@@ -10,6 +10,7 @@
 #ifndef _SCSI_PROTO_H_
 #define _SCSI_PROTO_H_
 
+#include <linux/build_bug.h>
 #include <linux/types.h>
 
 /*
@@ -126,6 +127,7 @@
 #define	SAI_READ_CAPACITY_16  0x10
 #define SAI_GET_LBA_STATUS    0x12
 #define SAI_REPORT_REFERRALS  0x13
+#define SAI_GET_STREAM_STATUS 0x16
 /* values for maintenance in */
 #define MI_REPORT_IDENTIFYING_INFORMATION 0x05
 #define MI_REPORT_TARGET_PGS  0x0a
@@ -275,6 +277,82 @@ struct scsi_lun {
 	__u8 scsi_lun[8];
 };
 
+/* SBC-5 IO advice hints group descriptor */
+struct scsi_io_group_descriptor {
+#if defined(__BIG_ENDIAN)
+	u8 io_advice_hints_mode: 2;
+	u8 reserved1: 3;
+	u8 st_enble: 1;
+	u8 cs_enble: 1;
+	u8 ic_enable: 1;
+#elif defined(__LITTLE_ENDIAN)
+	u8 ic_enable: 1;
+	u8 cs_enble: 1;
+	u8 st_enble: 1;
+	u8 reserved1: 3;
+	u8 io_advice_hints_mode: 2;
+#else
+#error
+#endif
+	u8 reserved2[3];
+	/* Logical block markup descriptor */
+#if defined(__BIG_ENDIAN)
+	u8 acdlu: 1;
+	u8 reserved3: 1;
+	u8 rlbsr: 2;
+	u8 lbm_descriptor_type: 4;
+#elif defined(__LITTLE_ENDIAN)
+	u8 lbm_descriptor_type: 4;
+	u8 rlbsr: 2;
+	u8 reserved3: 1;
+	u8 acdlu: 1;
+#else
+#error
+#endif
+	u8 params[2];
+	u8 reserved4;
+	u8 reserved5[8];
+};
+
+static_assert(sizeof(struct scsi_io_group_descriptor) == 16);
+
+/* SCSI stream status descriptor */
+struct scsi_stream_status {
+#if defined(__BIG_ENDIAN)
+	u8 perm: 1;
+	u8 reserved1: 7;
+#elif defined(__LITTLE_ENDIAN)
+	u8 reserved1: 7;
+	u8 perm: 1;
+#else
+#error
+#endif
+	u8 reserved2;
+	__be16 stream_identifier;
+#if defined(__BIG_ENDIAN)
+	u8 reserved3: 2;
+	u8 rel_lifetime: 6;
+#elif defined(__LITTLE_ENDIAN)
+	u8 rel_lifetime: 6;
+	u8 reserved3: 2;
+#else
+#error
+#endif
+	u8 reserved4[3];
+};
+
+static_assert(sizeof(struct scsi_stream_status) == 8);
+
+/* GET STREAM STATUS parameter data */
+struct scsi_stream_status_header {
+	__be32 len;	/* length in bytes of stream_status[] array. */
+	u16 reserved;
+	__be16 number_of_open_streams;
+	DECLARE_FLEX_ARRAY(struct scsi_stream_status, stream_status);
+};
+
+static_assert(sizeof(struct scsi_stream_status_header) == 8);
+
 /* SPC asymmetric access states */
 #define SCSI_ACCESS_STATE_OPTIMAL     0x00
 #define SCSI_ACCESS_STATE_ACTIVE      0x01
diff --git a/original/uapi/asm-arm/asm/unistd-eabi.h b/original/uapi/asm-arm/asm/unistd-eabi.h
index 4c1bd50..956d4d8 100644
--- a/original/uapi/asm-arm/asm/unistd-eabi.h
+++ b/original/uapi/asm-arm/asm/unistd-eabi.h
@@ -415,5 +415,6 @@
 #define __NR_lsm_get_self_attr (__NR_SYSCALL_BASE + 459)
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
+#define __NR_mseal (__NR_SYSCALL_BASE + 462)
 
 #endif /* _UAPI_ASM_UNISTD_EABI_H */
diff --git a/original/uapi/asm-arm/asm/unistd-oabi.h b/original/uapi/asm-arm/asm/unistd-oabi.h
index a85ea39..122232d 100644
--- a/original/uapi/asm-arm/asm/unistd-oabi.h
+++ b/original/uapi/asm-arm/asm/unistd-oabi.h
@@ -427,5 +427,6 @@
 #define __NR_lsm_get_self_attr (__NR_SYSCALL_BASE + 459)
 #define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
 #define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
+#define __NR_mseal (__NR_SYSCALL_BASE + 462)
 
 #endif /* _UAPI_ASM_UNISTD_OABI_H */
diff --git a/original/uapi/asm-generic/unistd.h b/original/uapi/asm-generic/unistd.h
index 75f0096..d4cc269 100644
--- a/original/uapi/asm-generic/unistd.h
+++ b/original/uapi/asm-generic/unistd.h
@@ -737,7 +737,7 @@ __SC_COMP(__NR_pselect6_time64, sys_pselect6, compat_sys_pselect6_time64)
 #define __NR_ppoll_time64 414
 __SC_COMP(__NR_ppoll_time64, sys_ppoll, compat_sys_ppoll_time64)
 #define __NR_io_pgetevents_time64 416
-__SYSCALL(__NR_io_pgetevents_time64, sys_io_pgetevents)
+__SC_COMP(__NR_io_pgetevents_time64, sys_io_pgetevents, compat_sys_io_pgetevents_time64)
 #define __NR_recvmmsg_time64 417
 __SC_COMP(__NR_recvmmsg_time64, sys_recvmmsg, compat_sys_recvmmsg_time64)
 #define __NR_mq_timedsend_time64 418
@@ -842,8 +842,11 @@ __SYSCALL(__NR_lsm_set_self_attr, sys_lsm_set_self_attr)
 #define __NR_lsm_list_modules 461
 __SYSCALL(__NR_lsm_list_modules, sys_lsm_list_modules)
 
+#define __NR_mseal 462
+__SYSCALL(__NR_mseal, sys_mseal)
+
 #undef __NR_syscalls
-#define __NR_syscalls 462
+#define __NR_syscalls 463
 
 /*
  * 32 bit systems traditionally used different
diff --git a/original/uapi/asm-riscv/asm/hwprobe.h b/original/uapi/asm-riscv/asm/hwprobe.h
index 2902f68..dda76a0 100644
--- a/original/uapi/asm-riscv/asm/hwprobe.h
+++ b/original/uapi/asm-riscv/asm/hwprobe.h
@@ -59,6 +59,7 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZTSO		(1ULL << 33)
 #define		RISCV_HWPROBE_EXT_ZACAS		(1ULL << 34)
 #define		RISCV_HWPROBE_EXT_ZICOND	(1ULL << 35)
+#define		RISCV_HWPROBE_EXT_ZIHINTPAUSE	(1ULL << 36)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
diff --git a/original/uapi/asm-riscv/asm/kvm.h b/original/uapi/asm-riscv/asm/kvm.h
index b1c503c..e878e7c 100644
--- a/original/uapi/asm-riscv/asm/kvm.h
+++ b/original/uapi/asm-riscv/asm/kvm.h
@@ -167,6 +167,7 @@ enum KVM_RISCV_ISA_EXT_ID {
 	KVM_RISCV_ISA_EXT_ZFA,
 	KVM_RISCV_ISA_EXT_ZTSO,
 	KVM_RISCV_ISA_EXT_ZACAS,
+	KVM_RISCV_ISA_EXT_SSCOFPMF,
 	KVM_RISCV_ISA_EXT_MAX,
 };
 
diff --git a/original/uapi/asm-x86/asm/kvm.h b/original/uapi/asm-x86/asm/kvm.h
index ef11aa4..9fae1b7 100644
--- a/original/uapi/asm-x86/asm/kvm.h
+++ b/original/uapi/asm-x86/asm/kvm.h
@@ -457,8 +457,13 @@ struct kvm_sync_regs {
 
 #define KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE	0x00000001
 
-/* attributes for system fd (group 0) */
-#define KVM_X86_XCOMP_GUEST_SUPP	0
+/* vendor-independent attributes for system fd (group 0) */
+#define KVM_X86_GRP_SYSTEM		0
+#  define KVM_X86_XCOMP_GUEST_SUPP	0
+
+/* vendor-specific groups and attributes for system fd */
+#define KVM_X86_GRP_SEV			1
+#  define KVM_X86_SEV_VMSA_FEATURES	0
 
 struct kvm_vmx_nested_state_data {
 	__u8 vmcs12[KVM_STATE_NESTED_VMX_VMCS_SIZE];
@@ -689,6 +694,9 @@ enum sev_cmd_id {
 	/* Guest Migration Extension */
 	KVM_SEV_SEND_CANCEL,
 
+	/* Second time is the charm; improved versions of the above ioctls.  */
+	KVM_SEV_INIT2,
+
 	KVM_SEV_NR_MAX,
 };
 
@@ -700,6 +708,14 @@ struct kvm_sev_cmd {
 	__u32 sev_fd;
 };
 
+struct kvm_sev_init {
+	__u64 vmsa_features;
+	__u32 flags;
+	__u16 ghcb_version;
+	__u16 pad1;
+	__u32 pad2[8];
+};
+
 struct kvm_sev_launch_start {
 	__u32 handle;
 	__u32 policy;
@@ -856,5 +872,7 @@ struct kvm_hyperv_eventfd {
 
 #define KVM_X86_DEFAULT_VM	0
 #define KVM_X86_SW_PROTECTED_VM	1
+#define KVM_X86_SEV_VM		2
+#define KVM_X86_SEV_ES_VM	3
 
 #endif /* _ASM_X86_KVM_H */
diff --git a/original/uapi/asm-x86/asm/unistd_32.h b/original/uapi/asm-x86/asm/unistd_32.h
index 8621e6e..940eaeb 100644
--- a/original/uapi/asm-x86/asm/unistd_32.h
+++ b/original/uapi/asm-x86/asm/unistd_32.h
@@ -452,9 +452,10 @@
 #define __NR_lsm_get_self_attr 459
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
+#define __NR_mseal 462
 
 #ifdef __KERNEL__
-#define __NR_syscalls 462
+#define __NR_syscalls 463
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_32_H */
diff --git a/original/uapi/asm-x86/asm/unistd_64.h b/original/uapi/asm-x86/asm/unistd_64.h
index 1073959..b9c5cd5 100644
--- a/original/uapi/asm-x86/asm/unistd_64.h
+++ b/original/uapi/asm-x86/asm/unistd_64.h
@@ -374,9 +374,10 @@
 #define __NR_lsm_get_self_attr 459
 #define __NR_lsm_set_self_attr 460
 #define __NR_lsm_list_modules 461
+#define __NR_mseal 462
 
 #ifdef __KERNEL__
-#define __NR_syscalls 462
+#define __NR_syscalls 463
 #endif
 
 #endif /* _UAPI_ASM_UNISTD_64_H */
diff --git a/original/uapi/asm-x86/asm/unistd_x32.h b/original/uapi/asm-x86/asm/unistd_x32.h
index 81dcb36..1c632b6 100644
--- a/original/uapi/asm-x86/asm/unistd_x32.h
+++ b/original/uapi/asm-x86/asm/unistd_x32.h
@@ -318,6 +318,7 @@
 #define __NR_set_mempolicy_home_node (__X32_SYSCALL_BIT + 450)
 #define __NR_cachestat (__X32_SYSCALL_BIT + 451)
 #define __NR_fchmodat2 (__X32_SYSCALL_BIT + 452)
+#define __NR_map_shadow_stack (__X32_SYSCALL_BIT + 453)
 #define __NR_futex_wake (__X32_SYSCALL_BIT + 454)
 #define __NR_futex_wait (__X32_SYSCALL_BIT + 455)
 #define __NR_futex_requeue (__X32_SYSCALL_BIT + 456)
@@ -326,6 +327,7 @@
 #define __NR_lsm_get_self_attr (__X32_SYSCALL_BIT + 459)
 #define __NR_lsm_set_self_attr (__X32_SYSCALL_BIT + 460)
 #define __NR_lsm_list_modules (__X32_SYSCALL_BIT + 461)
+#define __NR_mseal (__X32_SYSCALL_BIT + 462)
 #define __NR_rt_sigaction (__X32_SYSCALL_BIT + 512)
 #define __NR_rt_sigreturn (__X32_SYSCALL_BIT + 513)
 #define __NR_ioctl (__X32_SYSCALL_BIT + 514)
diff --git a/original/uapi/drm/drm_mode.h b/original/uapi/drm/drm_mode.h
index 7040e7e..1ca5c7e 100644
--- a/original/uapi/drm/drm_mode.h
+++ b/original/uapi/drm/drm_mode.h
@@ -865,6 +865,17 @@ struct drm_color_lut {
 	__u16 reserved;
 };
 
+/**
+ * struct drm_plane_size_hint - Plane size hints
+ *
+ * The plane SIZE_HINTS property blob contains an
+ * array of struct drm_plane_size_hint.
+ */
+struct drm_plane_size_hint {
+	__u16 width;
+	__u16 height;
+};
+
 /**
  * struct hdr_metadata_infoframe - HDR Metadata Infoframe Data.
  *
diff --git a/original/uapi/drm/i915_drm.h b/original/uapi/drm/i915_drm.h
index 2ee3388..d4d86e5 100644
--- a/original/uapi/drm/i915_drm.h
+++ b/original/uapi/drm/i915_drm.h
@@ -806,6 +806,12 @@ typedef struct drm_i915_irq_wait {
  */
 #define I915_PARAM_PXP_STATUS		 58
 
+/*
+ * Query if kernel allows marking a context to send a Freq hint to SLPC. This
+ * will enable use of the strategies allowed by the SLPC algorithm.
+ */
+#define I915_PARAM_HAS_CONTEXT_FREQ_HINT	59
+
 /* Must be kept compact -- no holes and well documented */
 
 /**
@@ -2148,6 +2154,15 @@ struct drm_i915_gem_context_param {
  * -EIO: The firmware did not succeed in creating the protected context.
  */
 #define I915_CONTEXT_PARAM_PROTECTED_CONTENT    0xd
+
+/*
+ * I915_CONTEXT_PARAM_LOW_LATENCY:
+ *
+ * Mark this context as a low latency workload which requires aggressive GT
+ * frequency scaling. Use I915_PARAM_HAS_CONTEXT_FREQ_HINT to check if the kernel
+ * supports this per context flag.
+ */
+#define I915_CONTEXT_PARAM_LOW_LATENCY		0xe
 /* Must be kept compact -- no holes and well documented */
 
 	/** @value: Context parameter value to be set or queried */
@@ -2623,19 +2638,29 @@ struct drm_i915_reg_read {
  *
  */
 
+/*
+ * struct drm_i915_reset_stats - Return global reset and other context stats
+ *
+ * Driver keeps few stats for each contexts and also global reset count.
+ * This struct can be used to query those stats.
+ */
 struct drm_i915_reset_stats {
+	/** @ctx_id: ID of the requested context */
 	__u32 ctx_id;
+
+	/** @flags: MBZ */
 	__u32 flags;
 
-	/* All resets since boot/module reload, for all contexts */
+	/** @reset_count: All resets since boot/module reload, for all contexts */
 	__u32 reset_count;
 
-	/* Number of batches lost when active in GPU, for this context */
+	/** @batch_active: Number of batches lost when active in GPU, for this context */
 	__u32 batch_active;
 
-	/* Number of batches lost pending for execution, for this context */
+	/** @batch_pending: Number of batches lost pending for execution, for this context */
 	__u32 batch_pending;
 
+	/** @pad: MBZ */
 	__u32 pad;
 };
 
diff --git a/original/uapi/drm/nouveau_drm.h b/original/uapi/drm/nouveau_drm.h
index cd84227..dd87f8f 100644
--- a/original/uapi/drm/nouveau_drm.h
+++ b/original/uapi/drm/nouveau_drm.h
@@ -68,11 +68,28 @@ extern "C" {
  */
 #define NOUVEAU_GETPARAM_VRAM_USED 19
 
+/*
+ * NOUVEAU_GETPARAM_HAS_VMA_TILEMODE
+ *
+ * Query whether tile mode and PTE kind are accepted with VM allocs or not.
+ */
+#define NOUVEAU_GETPARAM_HAS_VMA_TILEMODE 20
+
 struct drm_nouveau_getparam {
 	__u64 param;
 	__u64 value;
 };
 
+/*
+ * Those are used to support selecting the main engine used on Kepler.
+ * This goes into drm_nouveau_channel_alloc::tt_ctxdma_handle
+ */
+#define NOUVEAU_FIFO_ENGINE_GR  0x01
+#define NOUVEAU_FIFO_ENGINE_VP  0x02
+#define NOUVEAU_FIFO_ENGINE_PPP 0x04
+#define NOUVEAU_FIFO_ENGINE_BSP 0x08
+#define NOUVEAU_FIFO_ENGINE_CE  0x30
+
 struct drm_nouveau_channel_alloc {
 	__u32     fb_ctxdma_handle;
 	__u32     tt_ctxdma_handle;
@@ -95,6 +112,18 @@ struct drm_nouveau_channel_free {
 	__s32 channel;
 };
 
+struct drm_nouveau_notifierobj_alloc {
+	__u32 channel;
+	__u32 handle;
+	__u32 size;
+	__u32 offset;
+};
+
+struct drm_nouveau_gpuobj_free {
+	__s32 channel;
+	__u32 handle;
+};
+
 #define NOUVEAU_GEM_DOMAIN_CPU       (1 << 0)
 #define NOUVEAU_GEM_DOMAIN_VRAM      (1 << 1)
 #define NOUVEAU_GEM_DOMAIN_GART      (1 << 2)
diff --git a/original/uapi/drm/panthor_drm.h b/original/uapi/drm/panthor_drm.h
new file mode 100644
index 0000000..926b1de
--- /dev/null
+++ b/original/uapi/drm/panthor_drm.h
@@ -0,0 +1,962 @@
+/* SPDX-License-Identifier: MIT */
+/* Copyright (C) 2023 Collabora ltd. */
+#ifndef _PANTHOR_DRM_H_
+#define _PANTHOR_DRM_H_
+
+#include "drm.h"
+
+#if defined(__cplusplus)
+extern "C" {
+#endif
+
+/**
+ * DOC: Introduction
+ *
+ * This documentation describes the Panthor IOCTLs.
+ *
+ * Just a few generic rules about the data passed to the Panthor IOCTLs:
+ *
+ * - Structures must be aligned on 64-bit/8-byte. If the object is not
+ *   naturally aligned, a padding field must be added.
+ * - Fields must be explicitly aligned to their natural type alignment with
+ *   pad[0..N] fields.
+ * - All padding fields will be checked by the driver to make sure they are
+ *   zeroed.
+ * - Flags can be added, but not removed/replaced.
+ * - New fields can be added to the main structures (the structures
+ *   directly passed to the ioctl). Those fields can be added at the end of
+ *   the structure, or replace existing padding fields. Any new field being
+ *   added must preserve the behavior that existed before those fields were
+ *   added when a value of zero is passed.
+ * - New fields can be added to indirect objects (objects pointed by the
+ *   main structure), iff those objects are passed a size to reflect the
+ *   size known by the userspace driver (see drm_panthor_obj_array::stride
+ *   or drm_panthor_dev_query::size).
+ * - If the kernel driver is too old to know some fields, those will be
+ *   ignored if zero, and otherwise rejected (and so will be zero on output).
+ * - If userspace is too old to know some fields, those will be zeroed
+ *   (input) before the structure is parsed by the kernel driver.
+ * - Each new flag/field addition must come with a driver version update so
+ *   the userspace driver doesn't have to trial and error to know which
+ *   flags are supported.
+ * - Structures should not contain unions, as this would defeat the
+ *   extensibility of such structures.
+ * - IOCTLs can't be removed or replaced. New IOCTL IDs should be placed
+ *   at the end of the drm_panthor_ioctl_id enum.
+ */
+
+/**
+ * DOC: MMIO regions exposed to userspace.
+ *
+ * .. c:macro:: DRM_PANTHOR_USER_MMIO_OFFSET
+ *
+ * File offset for all MMIO regions being exposed to userspace. Don't use
+ * this value directly, use DRM_PANTHOR_USER_<name>_OFFSET values instead.
+ * pgoffset passed to mmap2() is an unsigned long, which forces us to use a
+ * different offset on 32-bit and 64-bit systems.
+ *
+ * .. c:macro:: DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET
+ *
+ * File offset for the LATEST_FLUSH_ID register. The Userspace driver controls
+ * GPU cache flushing through CS instructions, but the flush reduction
+ * mechanism requires a flush_id. This flush_id could be queried with an
+ * ioctl, but Arm provides a well-isolated register page containing only this
+ * read-only register, so let's expose this page through a static mmap offset
+ * and allow direct mapping of this MMIO region so we can avoid the
+ * user <-> kernel round-trip.
+ */
+#define DRM_PANTHOR_USER_MMIO_OFFSET_32BIT	(1ull << 43)
+#define DRM_PANTHOR_USER_MMIO_OFFSET_64BIT	(1ull << 56)
+#define DRM_PANTHOR_USER_MMIO_OFFSET		(sizeof(unsigned long) < 8 ? \
+						 DRM_PANTHOR_USER_MMIO_OFFSET_32BIT : \
+						 DRM_PANTHOR_USER_MMIO_OFFSET_64BIT)
+#define DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET	(DRM_PANTHOR_USER_MMIO_OFFSET | 0)
+
+/**
+ * DOC: IOCTL IDs
+ *
+ * enum drm_panthor_ioctl_id - IOCTL IDs
+ *
+ * Place new ioctls at the end, don't re-order, don't replace or remove entries.
+ *
+ * These IDs are not meant to be used directly. Use the DRM_IOCTL_PANTHOR_xxx
+ * definitions instead.
+ */
+enum drm_panthor_ioctl_id {
+	/** @DRM_PANTHOR_DEV_QUERY: Query device information. */
+	DRM_PANTHOR_DEV_QUERY = 0,
+
+	/** @DRM_PANTHOR_VM_CREATE: Create a VM. */
+	DRM_PANTHOR_VM_CREATE,
+
+	/** @DRM_PANTHOR_VM_DESTROY: Destroy a VM. */
+	DRM_PANTHOR_VM_DESTROY,
+
+	/** @DRM_PANTHOR_VM_BIND: Bind/unbind memory to a VM. */
+	DRM_PANTHOR_VM_BIND,
+
+	/** @DRM_PANTHOR_VM_GET_STATE: Get VM state. */
+	DRM_PANTHOR_VM_GET_STATE,
+
+	/** @DRM_PANTHOR_BO_CREATE: Create a buffer object. */
+	DRM_PANTHOR_BO_CREATE,
+
+	/**
+	 * @DRM_PANTHOR_BO_MMAP_OFFSET: Get the file offset to pass to
+	 * mmap to map a GEM object.
+	 */
+	DRM_PANTHOR_BO_MMAP_OFFSET,
+
+	/** @DRM_PANTHOR_GROUP_CREATE: Create a scheduling group. */
+	DRM_PANTHOR_GROUP_CREATE,
+
+	/** @DRM_PANTHOR_GROUP_DESTROY: Destroy a scheduling group. */
+	DRM_PANTHOR_GROUP_DESTROY,
+
+	/**
+	 * @DRM_PANTHOR_GROUP_SUBMIT: Submit jobs to queues belonging
+	 * to a specific scheduling group.
+	 */
+	DRM_PANTHOR_GROUP_SUBMIT,
+
+	/** @DRM_PANTHOR_GROUP_GET_STATE: Get the state of a scheduling group. */
+	DRM_PANTHOR_GROUP_GET_STATE,
+
+	/** @DRM_PANTHOR_TILER_HEAP_CREATE: Create a tiler heap. */
+	DRM_PANTHOR_TILER_HEAP_CREATE,
+
+	/** @DRM_PANTHOR_TILER_HEAP_DESTROY: Destroy a tiler heap. */
+	DRM_PANTHOR_TILER_HEAP_DESTROY,
+};
+
+/**
+ * DRM_IOCTL_PANTHOR() - Build a Panthor IOCTL number
+ * @__access: Access type. Must be R, W or RW.
+ * @__id: One of the DRM_PANTHOR_xxx id.
+ * @__type: Suffix of the type being passed to the IOCTL.
+ *
+ * Don't use this macro directly, use the DRM_IOCTL_PANTHOR_xxx
+ * values instead.
+ *
+ * Return: An IOCTL number to be passed to ioctl() from userspace.
+ */
+#define DRM_IOCTL_PANTHOR(__access, __id, __type) \
+	DRM_IO ## __access(DRM_COMMAND_BASE + DRM_PANTHOR_ ## __id, \
+			   struct drm_panthor_ ## __type)
+
+#define DRM_IOCTL_PANTHOR_DEV_QUERY \
+	DRM_IOCTL_PANTHOR(WR, DEV_QUERY, dev_query)
+#define DRM_IOCTL_PANTHOR_VM_CREATE \
+	DRM_IOCTL_PANTHOR(WR, VM_CREATE, vm_create)
+#define DRM_IOCTL_PANTHOR_VM_DESTROY \
+	DRM_IOCTL_PANTHOR(WR, VM_DESTROY, vm_destroy)
+#define DRM_IOCTL_PANTHOR_VM_BIND \
+	DRM_IOCTL_PANTHOR(WR, VM_BIND, vm_bind)
+#define DRM_IOCTL_PANTHOR_VM_GET_STATE \
+	DRM_IOCTL_PANTHOR(WR, VM_GET_STATE, vm_get_state)
+#define DRM_IOCTL_PANTHOR_BO_CREATE \
+	DRM_IOCTL_PANTHOR(WR, BO_CREATE, bo_create)
+#define DRM_IOCTL_PANTHOR_BO_MMAP_OFFSET \
+	DRM_IOCTL_PANTHOR(WR, BO_MMAP_OFFSET, bo_mmap_offset)
+#define DRM_IOCTL_PANTHOR_GROUP_CREATE \
+	DRM_IOCTL_PANTHOR(WR, GROUP_CREATE, group_create)
+#define DRM_IOCTL_PANTHOR_GROUP_DESTROY \
+	DRM_IOCTL_PANTHOR(WR, GROUP_DESTROY, group_destroy)
+#define DRM_IOCTL_PANTHOR_GROUP_SUBMIT \
+	DRM_IOCTL_PANTHOR(WR, GROUP_SUBMIT, group_submit)
+#define DRM_IOCTL_PANTHOR_GROUP_GET_STATE \
+	DRM_IOCTL_PANTHOR(WR, GROUP_GET_STATE, group_get_state)
+#define DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE \
+	DRM_IOCTL_PANTHOR(WR, TILER_HEAP_CREATE, tiler_heap_create)
+#define DRM_IOCTL_PANTHOR_TILER_HEAP_DESTROY \
+	DRM_IOCTL_PANTHOR(WR, TILER_HEAP_DESTROY, tiler_heap_destroy)
+
+/**
+ * DOC: IOCTL arguments
+ */
+
+/**
+ * struct drm_panthor_obj_array - Object array.
+ *
+ * This object is used to pass an array of objects whose size is subject to changes in
+ * future versions of the driver. In order to support this mutability, we pass a stride
+ * describing the size of the object as known by userspace.
+ *
+ * You shouldn't fill drm_panthor_obj_array fields directly. You should instead use
+ * the DRM_PANTHOR_OBJ_ARRAY() macro that takes care of initializing the stride to
+ * the object size.
+ */
+struct drm_panthor_obj_array {
+	/** @stride: Stride of object struct. Used for versioning. */
+	__u32 stride;
+
+	/** @count: Number of objects in the array. */
+	__u32 count;
+
+	/** @array: User pointer to an array of objects. */
+	__u64 array;
+};
+
+/**
+ * DRM_PANTHOR_OBJ_ARRAY() - Initialize a drm_panthor_obj_array field.
+ * @cnt: Number of elements in the array.
+ * @ptr: Pointer to the array to pass to the kernel.
+ *
+ * Macro initializing a drm_panthor_obj_array based on the object size as known
+ * by userspace.
+ */
+#define DRM_PANTHOR_OBJ_ARRAY(cnt, ptr) \
+	{ .stride = sizeof((ptr)[0]), .count = (cnt), .array = (__u64)(uintptr_t)(ptr) }
+
+/**
+ * enum drm_panthor_sync_op_flags - Synchronization operation flags.
+ */
+enum drm_panthor_sync_op_flags {
+	/** @DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK: Synchronization handle type mask. */
+	DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK = 0xff,
+
+	/** @DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ: Synchronization object type. */
+	DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ = 0,
+
+	/**
+	 * @DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ: Timeline synchronization
+	 * object type.
+	 */
+	DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ = 1,
+
+	/** @DRM_PANTHOR_SYNC_OP_WAIT: Wait operation. */
+	DRM_PANTHOR_SYNC_OP_WAIT = 0 << 31,
+
+	/** @DRM_PANTHOR_SYNC_OP_SIGNAL: Signal operation. */
+	DRM_PANTHOR_SYNC_OP_SIGNAL = (int)(1u << 31),
+};
+
+/**
+ * struct drm_panthor_sync_op - Synchronization operation.
+ */
+struct drm_panthor_sync_op {
+	/** @flags: Synchronization operation flags. Combination of DRM_PANTHOR_SYNC_OP values. */
+	__u32 flags;
+
+	/** @handle: Sync handle. */
+	__u32 handle;
+
+	/**
+	 * @timeline_value: MBZ if
+	 * (flags & DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK) !=
+	 * DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ.
+	 */
+	__u64 timeline_value;
+};
+
+/**
+ * enum drm_panthor_dev_query_type - Query type
+ *
+ * Place new types at the end, don't re-order, don't remove or replace.
+ */
+enum drm_panthor_dev_query_type {
+	/** @DRM_PANTHOR_DEV_QUERY_GPU_INFO: Query GPU information. */
+	DRM_PANTHOR_DEV_QUERY_GPU_INFO = 0,
+
+	/** @DRM_PANTHOR_DEV_QUERY_CSIF_INFO: Query command-stream interface information. */
+	DRM_PANTHOR_DEV_QUERY_CSIF_INFO,
+};
+
+/**
+ * struct drm_panthor_gpu_info - GPU information
+ *
+ * Structure grouping all queryable information relating to the GPU.
+ */
+struct drm_panthor_gpu_info {
+	/** @gpu_id : GPU ID. */
+	__u32 gpu_id;
+#define DRM_PANTHOR_ARCH_MAJOR(x)		((x) >> 28)
+#define DRM_PANTHOR_ARCH_MINOR(x)		(((x) >> 24) & 0xf)
+#define DRM_PANTHOR_ARCH_REV(x)			(((x) >> 20) & 0xf)
+#define DRM_PANTHOR_PRODUCT_MAJOR(x)		(((x) >> 16) & 0xf)
+#define DRM_PANTHOR_VERSION_MAJOR(x)		(((x) >> 12) & 0xf)
+#define DRM_PANTHOR_VERSION_MINOR(x)		(((x) >> 4) & 0xff)
+#define DRM_PANTHOR_VERSION_STATUS(x)		((x) & 0xf)
+
+	/** @gpu_rev: GPU revision. */
+	__u32 gpu_rev;
+
+	/** @csf_id: Command stream frontend ID. */
+	__u32 csf_id;
+#define DRM_PANTHOR_CSHW_MAJOR(x)		(((x) >> 26) & 0x3f)
+#define DRM_PANTHOR_CSHW_MINOR(x)		(((x) >> 20) & 0x3f)
+#define DRM_PANTHOR_CSHW_REV(x)			(((x) >> 16) & 0xf)
+#define DRM_PANTHOR_MCU_MAJOR(x)		(((x) >> 10) & 0x3f)
+#define DRM_PANTHOR_MCU_MINOR(x)		(((x) >> 4) & 0x3f)
+#define DRM_PANTHOR_MCU_REV(x)			((x) & 0xf)
+
+	/** @l2_features: L2-cache features. */
+	__u32 l2_features;
+
+	/** @tiler_features: Tiler features. */
+	__u32 tiler_features;
+
+	/** @mem_features: Memory features. */
+	__u32 mem_features;
+
+	/** @mmu_features: MMU features. */
+	__u32 mmu_features;
+#define DRM_PANTHOR_MMU_VA_BITS(x)		((x) & 0xff)
+
+	/** @thread_features: Thread features. */
+	__u32 thread_features;
+
+	/** @max_threads: Maximum number of threads. */
+	__u32 max_threads;
+
+	/** @thread_max_workgroup_size: Maximum workgroup size. */
+	__u32 thread_max_workgroup_size;
+
+	/**
+	 * @thread_max_barrier_size: Maximum number of threads that can wait
+	 * simultaneously on a barrier.
+	 */
+	__u32 thread_max_barrier_size;
+
+	/** @coherency_features: Coherency features. */
+	__u32 coherency_features;
+
+	/** @texture_features: Texture features. */
+	__u32 texture_features[4];
+
+	/** @as_present: Bitmask encoding the number of address-space exposed by the MMU. */
+	__u32 as_present;
+
+	/** @shader_present: Bitmask encoding the shader cores exposed by the GPU. */
+	__u64 shader_present;
+
+	/** @l2_present: Bitmask encoding the L2 caches exposed by the GPU. */
+	__u64 l2_present;
+
+	/** @tiler_present: Bitmask encoding the tiler units exposed by the GPU. */
+	__u64 tiler_present;
+
+	/** @core_features: Used to discriminate core variants when they exist. */
+	__u32 core_features;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+};
+
+/**
+ * struct drm_panthor_csif_info - Command stream interface information
+ *
+ * Structure grouping all queryable information relating to the command stream interface.
+ */
+struct drm_panthor_csif_info {
+	/** @csg_slot_count: Number of command stream group slots exposed by the firmware. */
+	__u32 csg_slot_count;
+
+	/** @cs_slot_count: Number of command stream slots per group. */
+	__u32 cs_slot_count;
+
+	/** @cs_reg_count: Number of command stream registers. */
+	__u32 cs_reg_count;
+
+	/** @scoreboard_slot_count: Number of scoreboard slots. */
+	__u32 scoreboard_slot_count;
+
+	/**
+	 * @unpreserved_cs_reg_count: Number of command stream registers reserved by
+	 * the kernel driver to call a userspace command stream.
+	 *
+	 * All registers can be used by a userspace command stream, but the
+	 * [cs_slot_count - unpreserved_cs_reg_count .. cs_slot_count] registers are
+	 * used by the kernel when DRM_PANTHOR_IOCTL_GROUP_SUBMIT is called.
+	 */
+	__u32 unpreserved_cs_reg_count;
+
+	/**
+	 * @pad: Padding field, set to zero.
+	 */
+	__u32 pad;
+};
+
+/**
+ * struct drm_panthor_dev_query - Arguments passed to DRM_PANTHOR_IOCTL_DEV_QUERY
+ */
+struct drm_panthor_dev_query {
+	/** @type: the query type (see drm_panthor_dev_query_type). */
+	__u32 type;
+
+	/**
+	 * @size: size of the type being queried.
+	 *
+	 * If pointer is NULL, size is updated by the driver to provide the
+	 * output structure size. If pointer is not NULL, the driver will
+	 * only copy min(size, actual_structure_size) bytes to the pointer,
+	 * and update the size accordingly. This allows us to extend query
+	 * types without breaking userspace.
+	 */
+	__u32 size;
+
+	/**
+	 * @pointer: user pointer to a query type struct.
+	 *
+	 * Pointer can be NULL, in which case, nothing is copied, but the
+	 * actual structure size is returned. If not NULL, it must point to
+	 * a location that's large enough to hold size bytes.
+	 */
+	__u64 pointer;
+};
+
+/**
+ * struct drm_panthor_vm_create - Arguments passed to DRM_PANTHOR_IOCTL_VM_CREATE
+ */
+struct drm_panthor_vm_create {
+	/** @flags: VM flags, MBZ. */
+	__u32 flags;
+
+	/** @id: Returned VM ID. */
+	__u32 id;
+
+	/**
+	 * @user_va_range: Size of the VA space reserved for user objects.
+	 *
+	 * The kernel will pick the remaining space to map kernel-only objects to the
+	 * VM (heap chunks, heap context, ring buffers, kernel synchronization objects,
+	 * ...). If the space left for kernel objects is too small, kernel object
+	 * allocation will fail further down the road. One can use
+	 * drm_panthor_gpu_info::mmu_features to extract the total virtual address
+	 * range, and chose a user_va_range that leaves some space to the kernel.
+	 *
+	 * If user_va_range is zero, the kernel will pick a sensible value based on
+	 * TASK_SIZE and the virtual range supported by the GPU MMU (the kernel/user
+	 * split should leave enough VA space for userspace processes to support SVM,
+	 * while still allowing the kernel to map some amount of kernel objects in
+	 * the kernel VA range). The value chosen by the driver will be returned in
+	 * @user_va_range.
+	 *
+	 * User VA space always starts at 0x0, kernel VA space is always placed after
+	 * the user VA range.
+	 */
+	__u64 user_va_range;
+};
+
+/**
+ * struct drm_panthor_vm_destroy - Arguments passed to DRM_PANTHOR_IOCTL_VM_DESTROY
+ */
+struct drm_panthor_vm_destroy {
+	/** @id: ID of the VM to destroy. */
+	__u32 id;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+};
+
+/**
+ * enum drm_panthor_vm_bind_op_flags - VM bind operation flags
+ */
+enum drm_panthor_vm_bind_op_flags {
+	/**
+	 * @DRM_PANTHOR_VM_BIND_OP_MAP_READONLY: Map the memory read-only.
+	 *
+	 * Only valid with DRM_PANTHOR_VM_BIND_OP_TYPE_MAP.
+	 */
+	DRM_PANTHOR_VM_BIND_OP_MAP_READONLY = 1 << 0,
+
+	/**
+	 * @DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC: Map the memory not-executable.
+	 *
+	 * Only valid with DRM_PANTHOR_VM_BIND_OP_TYPE_MAP.
+	 */
+	DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC = 1 << 1,
+
+	/**
+	 * @DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED: Map the memory uncached.
+	 *
+	 * Only valid with DRM_PANTHOR_VM_BIND_OP_TYPE_MAP.
+	 */
+	DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED = 1 << 2,
+
+	/**
+	 * @DRM_PANTHOR_VM_BIND_OP_TYPE_MASK: Mask used to determine the type of operation.
+	 */
+	DRM_PANTHOR_VM_BIND_OP_TYPE_MASK = (int)(0xfu << 28),
+
+	/** @DRM_PANTHOR_VM_BIND_OP_TYPE_MAP: Map operation. */
+	DRM_PANTHOR_VM_BIND_OP_TYPE_MAP = 0 << 28,
+
+	/** @DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP: Unmap operation. */
+	DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP = 1 << 28,
+
+	/**
+	 * @DRM_PANTHOR_VM_BIND_OP_TYPE_SYNC_ONLY: No VM operation.
+	 *
+	 * Just serves as a synchronization point on a VM queue.
+	 *
+	 * Only valid if %DRM_PANTHOR_VM_BIND_ASYNC is set in drm_panthor_vm_bind::flags,
+	 * and drm_panthor_vm_bind_op::syncs contains at least one element.
+	 */
+	DRM_PANTHOR_VM_BIND_OP_TYPE_SYNC_ONLY = 2 << 28,
+};
+
+/**
+ * struct drm_panthor_vm_bind_op - VM bind operation
+ */
+struct drm_panthor_vm_bind_op {
+	/** @flags: Combination of drm_panthor_vm_bind_op_flags flags. */
+	__u32 flags;
+
+	/**
+	 * @bo_handle: Handle of the buffer object to map.
+	 * MBZ for unmap or sync-only operations.
+	 */
+	__u32 bo_handle;
+
+	/**
+	 * @bo_offset: Buffer object offset.
+	 * MBZ for unmap or sync-only operations.
+	 */
+	__u64 bo_offset;
+
+	/**
+	 * @va: Virtual address to map/unmap.
+	 * MBZ for sync-only operations.
+	 */
+	__u64 va;
+
+	/**
+	 * @size: Size to map/unmap.
+	 * MBZ for sync-only operations.
+	 */
+	__u64 size;
+
+	/**
+	 * @syncs: Array of struct drm_panthor_sync_op synchronization
+	 * operations.
+	 *
+	 * This array must be empty if %DRM_PANTHOR_VM_BIND_ASYNC is not set on
+	 * the drm_panthor_vm_bind object containing this VM bind operation.
+	 *
+	 * This array shall not be empty for sync-only operations.
+	 */
+	struct drm_panthor_obj_array syncs;
+
+};
+
+/**
+ * enum drm_panthor_vm_bind_flags - VM bind flags
+ */
+enum drm_panthor_vm_bind_flags {
+	/**
+	 * @DRM_PANTHOR_VM_BIND_ASYNC: VM bind operations are queued to the VM
+	 * queue instead of being executed synchronously.
+	 */
+	DRM_PANTHOR_VM_BIND_ASYNC = 1 << 0,
+};
+
+/**
+ * struct drm_panthor_vm_bind - Arguments passed to DRM_IOCTL_PANTHOR_VM_BIND
+ */
+struct drm_panthor_vm_bind {
+	/** @vm_id: VM targeted by the bind request. */
+	__u32 vm_id;
+
+	/** @flags: Combination of drm_panthor_vm_bind_flags flags. */
+	__u32 flags;
+
+	/** @ops: Array of struct drm_panthor_vm_bind_op bind operations. */
+	struct drm_panthor_obj_array ops;
+};
+
+/**
+ * enum drm_panthor_vm_state - VM states.
+ */
+enum drm_panthor_vm_state {
+	/**
+	 * @DRM_PANTHOR_VM_STATE_USABLE: VM is usable.
+	 *
+	 * New VM operations will be accepted on this VM.
+	 */
+	DRM_PANTHOR_VM_STATE_USABLE,
+
+	/**
+	 * @DRM_PANTHOR_VM_STATE_UNUSABLE: VM is unusable.
+	 *
+	 * Something put the VM in an unusable state (like an asynchronous
+	 * VM_BIND request failing for any reason).
+	 *
+	 * Once the VM is in this state, all new MAP operations will be
+	 * rejected, and any GPU job targeting this VM will fail.
+	 * UNMAP operations are still accepted.
+	 *
+	 * The only way to recover from an unusable VM is to create a new
+	 * VM, and destroy the old one.
+	 */
+	DRM_PANTHOR_VM_STATE_UNUSABLE,
+};
+
+/**
+ * struct drm_panthor_vm_get_state - Get VM state.
+ */
+struct drm_panthor_vm_get_state {
+	/** @vm_id: VM targeted by the get_state request. */
+	__u32 vm_id;
+
+	/**
+	 * @state: state returned by the driver.
+	 *
+	 * Must be one of the enum drm_panthor_vm_state values.
+	 */
+	__u32 state;
+};
+
+/**
+ * enum drm_panthor_bo_flags - Buffer object flags, passed at creation time.
+ */
+enum drm_panthor_bo_flags {
+	/** @DRM_PANTHOR_BO_NO_MMAP: The buffer object will never be CPU-mapped in userspace. */
+	DRM_PANTHOR_BO_NO_MMAP = (1 << 0),
+};
+
+/**
+ * struct drm_panthor_bo_create - Arguments passed to DRM_IOCTL_PANTHOR_BO_CREATE.
+ */
+struct drm_panthor_bo_create {
+	/**
+	 * @size: Requested size for the object
+	 *
+	 * The (page-aligned) allocated size for the object will be returned.
+	 */
+	__u64 size;
+
+	/**
+	 * @flags: Flags. Must be a combination of drm_panthor_bo_flags flags.
+	 */
+	__u32 flags;
+
+	/**
+	 * @exclusive_vm_id: Exclusive VM this buffer object will be mapped to.
+	 *
+	 * If not zero, the field must refer to a valid VM ID, and implies that:
+	 *  - the buffer object will only ever be bound to that VM
+	 *  - cannot be exported as a PRIME fd
+	 */
+	__u32 exclusive_vm_id;
+
+	/**
+	 * @handle: Returned handle for the object.
+	 *
+	 * Object handles are nonzero.
+	 */
+	__u32 handle;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+};
+
+/**
+ * struct drm_panthor_bo_mmap_offset - Arguments passed to DRM_IOCTL_PANTHOR_BO_MMAP_OFFSET.
+ */
+struct drm_panthor_bo_mmap_offset {
+	/** @handle: Handle of the object we want an mmap offset for. */
+	__u32 handle;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+
+	/** @offset: The fake offset to use for subsequent mmap calls. */
+	__u64 offset;
+};
+
+/**
+ * struct drm_panthor_queue_create - Queue creation arguments.
+ */
+struct drm_panthor_queue_create {
+	/**
+	 * @priority: Defines the priority of queues inside a group. Goes from 0 to 15,
+	 * 15 being the highest priority.
+	 */
+	__u8 priority;
+
+	/** @pad: Padding fields, MBZ. */
+	__u8 pad[3];
+
+	/** @ringbuf_size: Size of the ring buffer to allocate to this queue. */
+	__u32 ringbuf_size;
+};
+
+/**
+ * enum drm_panthor_group_priority - Scheduling group priority
+ */
+enum drm_panthor_group_priority {
+	/** @PANTHOR_GROUP_PRIORITY_LOW: Low priority group. */
+	PANTHOR_GROUP_PRIORITY_LOW = 0,
+
+	/** @PANTHOR_GROUP_PRIORITY_MEDIUM: Medium priority group. */
+	PANTHOR_GROUP_PRIORITY_MEDIUM,
+
+	/** @PANTHOR_GROUP_PRIORITY_HIGH: High priority group. */
+	PANTHOR_GROUP_PRIORITY_HIGH,
+};
+
+/**
+ * struct drm_panthor_group_create - Arguments passed to DRM_IOCTL_PANTHOR_GROUP_CREATE
+ */
+struct drm_panthor_group_create {
+	/** @queues: Array of drm_panthor_queue_create elements. */
+	struct drm_panthor_obj_array queues;
+
+	/**
+	 * @max_compute_cores: Maximum number of cores that can be used by compute
+	 * jobs across CS queues bound to this group.
+	 *
+	 * Must be less or equal to the number of bits set in @compute_core_mask.
+	 */
+	__u8 max_compute_cores;
+
+	/**
+	 * @max_fragment_cores: Maximum number of cores that can be used by fragment
+	 * jobs across CS queues bound to this group.
+	 *
+	 * Must be less or equal to the number of bits set in @fragment_core_mask.
+	 */
+	__u8 max_fragment_cores;
+
+	/**
+	 * @max_tiler_cores: Maximum number of tilers that can be used by tiler jobs
+	 * across CS queues bound to this group.
+	 *
+	 * Must be less or equal to the number of bits set in @tiler_core_mask.
+	 */
+	__u8 max_tiler_cores;
+
+	/** @priority: Group priority (see enum drm_panthor_group_priority). */
+	__u8 priority;
+
+	/** @pad: Padding field, MBZ. */
+	__u32 pad;
+
+	/**
+	 * @compute_core_mask: Mask encoding cores that can be used for compute jobs.
+	 *
+	 * This field must have at least @max_compute_cores bits set.
+	 *
+	 * The bits set here should also be set in drm_panthor_gpu_info::shader_present.
+	 */
+	__u64 compute_core_mask;
+
+	/**
+	 * @fragment_core_mask: Mask encoding cores that can be used for fragment jobs.
+	 *
+	 * This field must have at least @max_fragment_cores bits set.
+	 *
+	 * The bits set here should also be set in drm_panthor_gpu_info::shader_present.
+	 */
+	__u64 fragment_core_mask;
+
+	/**
+	 * @tiler_core_mask: Mask encoding cores that can be used for tiler jobs.
+	 *
+	 * This field must have at least @max_tiler_cores bits set.
+	 *
+	 * The bits set here should also be set in drm_panthor_gpu_info::tiler_present.
+	 */
+	__u64 tiler_core_mask;
+
+	/**
+	 * @vm_id: VM ID to bind this group to.
+	 *
+	 * All submission to queues bound to this group will use this VM.
+	 */
+	__u32 vm_id;
+
+	/**
+	 * @group_handle: Returned group handle. Passed back when submitting jobs or
+	 * destroying a group.
+	 */
+	__u32 group_handle;
+};
+
+/**
+ * struct drm_panthor_group_destroy - Arguments passed to DRM_IOCTL_PANTHOR_GROUP_DESTROY
+ */
+struct drm_panthor_group_destroy {
+	/** @group_handle: Group to destroy */
+	__u32 group_handle;
+
+	/** @pad: Padding field, MBZ. */
+	__u32 pad;
+};
+
+/**
+ * struct drm_panthor_queue_submit - Job submission arguments.
+ *
+ * This is describing the userspace command stream to call from the kernel
+ * command stream ring-buffer. Queue submission is always part of a group
+ * submission, taking one or more jobs to submit to the underlying queues.
+ */
+struct drm_panthor_queue_submit {
+	/** @queue_index: Index of the queue inside a group. */
+	__u32 queue_index;
+
+	/**
+	 * @stream_size: Size of the command stream to execute.
+	 *
+	 * Must be 64-bit/8-byte aligned (the size of a CS instruction)
+	 *
+	 * Can be zero if stream_addr is zero too.
+	 *
+	 * When the stream size is zero, the queue submit serves as a
+	 * synchronization point.
+	 */
+	__u32 stream_size;
+
+	/**
+	 * @stream_addr: GPU address of the command stream to execute.
+	 *
+	 * Must be aligned on 64-byte.
+	 *
+	 * Can be zero is stream_size is zero too.
+	 */
+	__u64 stream_addr;
+
+	/**
+	 * @latest_flush: FLUSH_ID read at the time the stream was built.
+	 *
+	 * This allows cache flush elimination for the automatic
+	 * flush+invalidate(all) done at submission time, which is needed to
+	 * ensure the GPU doesn't get garbage when reading the indirect command
+	 * stream buffers. If you want the cache flush to happen
+	 * unconditionally, pass a zero here.
+	 *
+	 * Ignored when stream_size is zero.
+	 */
+	__u32 latest_flush;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+
+	/** @syncs: Array of struct drm_panthor_sync_op sync operations. */
+	struct drm_panthor_obj_array syncs;
+};
+
+/**
+ * struct drm_panthor_group_submit - Arguments passed to DRM_IOCTL_PANTHOR_GROUP_SUBMIT
+ */
+struct drm_panthor_group_submit {
+	/** @group_handle: Handle of the group to queue jobs to. */
+	__u32 group_handle;
+
+	/** @pad: MBZ. */
+	__u32 pad;
+
+	/** @queue_submits: Array of drm_panthor_queue_submit objects. */
+	struct drm_panthor_obj_array queue_submits;
+};
+
+/**
+ * enum drm_panthor_group_state_flags - Group state flags
+ */
+enum drm_panthor_group_state_flags {
+	/**
+	 * @DRM_PANTHOR_GROUP_STATE_TIMEDOUT: Group had unfinished jobs.
+	 *
+	 * When a group ends up with this flag set, no jobs can be submitted to its queues.
+	 */
+	DRM_PANTHOR_GROUP_STATE_TIMEDOUT = 1 << 0,
+
+	/**
+	 * @DRM_PANTHOR_GROUP_STATE_FATAL_FAULT: Group had fatal faults.
+	 *
+	 * When a group ends up with this flag set, no jobs can be submitted to its queues.
+	 */
+	DRM_PANTHOR_GROUP_STATE_FATAL_FAULT = 1 << 1,
+};
+
+/**
+ * struct drm_panthor_group_get_state - Arguments passed to DRM_IOCTL_PANTHOR_GROUP_GET_STATE
+ *
+ * Used to query the state of a group and decide whether a new group should be created to
+ * replace it.
+ */
+struct drm_panthor_group_get_state {
+	/** @group_handle: Handle of the group to query state on */
+	__u32 group_handle;
+
+	/**
+	 * @state: Combination of DRM_PANTHOR_GROUP_STATE_* flags encoding the
+	 * group state.
+	 */
+	__u32 state;
+
+	/** @fatal_queues: Bitmask of queues that faced fatal faults. */
+	__u32 fatal_queues;
+
+	/** @pad: MBZ */
+	__u32 pad;
+};
+
+/**
+ * struct drm_panthor_tiler_heap_create - Arguments passed to DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE
+ */
+struct drm_panthor_tiler_heap_create {
+	/** @vm_id: VM ID the tiler heap should be mapped to */
+	__u32 vm_id;
+
+	/** @initial_chunk_count: Initial number of chunks to allocate. Must be at least one. */
+	__u32 initial_chunk_count;
+
+	/**
+	 * @chunk_size: Chunk size.
+	 *
+	 * Must be page-aligned and lie in the [128k:8M] range.
+	 */
+	__u32 chunk_size;
+
+	/**
+	 * @max_chunks: Maximum number of chunks that can be allocated.
+	 *
+	 * Must be at least @initial_chunk_count.
+	 */
+	__u32 max_chunks;
+
+	/**
+	 * @target_in_flight: Maximum number of in-flight render passes.
+	 *
+	 * If the heap has more than tiler jobs in-flight, the FW will wait for render
+	 * passes to finish before queuing new tiler jobs.
+	 */
+	__u32 target_in_flight;
+
+	/** @handle: Returned heap handle. Passed back to DESTROY_TILER_HEAP. */
+	__u32 handle;
+
+	/** @tiler_heap_ctx_gpu_va: Returned heap GPU virtual address returned */
+	__u64 tiler_heap_ctx_gpu_va;
+
+	/**
+	 * @first_heap_chunk_gpu_va: First heap chunk.
+	 *
+	 * The tiler heap is formed of heap chunks forming a single-link list. This
+	 * is the first element in the list.
+	 */
+	__u64 first_heap_chunk_gpu_va;
+};
+
+/**
+ * struct drm_panthor_tiler_heap_destroy - Arguments passed to DRM_IOCTL_PANTHOR_TILER_HEAP_DESTROY
+ */
+struct drm_panthor_tiler_heap_destroy {
+	/**
+	 * @handle: Handle of the tiler heap to destroy.
+	 *
+	 * Must be a valid heap handle returned by DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE.
+	 */
+	__u32 handle;
+
+	/** @pad: Padding field, MBZ. */
+	__u32 pad;
+};
+
+#if defined(__cplusplus)
+}
+#endif
+
+#endif /* _PANTHOR_DRM_H_ */
diff --git a/original/uapi/drm/xe_drm.h b/original/uapi/drm/xe_drm.h
index 538a3ac..1446c3b 100644
--- a/original/uapi/drm/xe_drm.h
+++ b/original/uapi/drm/xe_drm.h
@@ -459,8 +459,16 @@ struct drm_xe_gt {
 	 * by struct drm_xe_query_mem_regions' mem_class.
 	 */
 	__u64 far_mem_regions;
+	/** @ip_ver_major: Graphics/media IP major version on GMD_ID platforms */
+	__u16 ip_ver_major;
+	/** @ip_ver_minor: Graphics/media IP minor version on GMD_ID platforms */
+	__u16 ip_ver_minor;
+	/** @ip_ver_rev: Graphics/media IP revision version on GMD_ID platforms */
+	__u16 ip_ver_rev;
+	/** @pad2: MBZ */
+	__u16 pad2;
 	/** @reserved: Reserved */
-	__u64 reserved[8];
+	__u64 reserved[7];
 };
 
 /**
@@ -510,9 +518,9 @@ struct drm_xe_query_topology_mask {
 	/** @gt_id: GT ID the mask is associated with */
 	__u16 gt_id;
 
-#define DRM_XE_TOPO_DSS_GEOMETRY	(1 << 0)
-#define DRM_XE_TOPO_DSS_COMPUTE		(1 << 1)
-#define DRM_XE_TOPO_EU_PER_DSS		(1 << 2)
+#define DRM_XE_TOPO_DSS_GEOMETRY	1
+#define DRM_XE_TOPO_DSS_COMPUTE		2
+#define DRM_XE_TOPO_EU_PER_DSS		4
 	/** @type: type of mask */
 	__u16 type;
 
@@ -583,6 +591,7 @@ struct drm_xe_query_engine_cycles {
 struct drm_xe_query_uc_fw_version {
 	/** @uc_type: The micro-controller type to query firmware version */
 #define XE_QUERY_UC_TYPE_GUC_SUBMISSION 0
+#define XE_QUERY_UC_TYPE_HUC 1
 	__u16 uc_type;
 
 	/** @pad: MBZ */
@@ -862,6 +871,12 @@ struct drm_xe_vm_destroy {
  *  - %DRM_XE_VM_BIND_OP_PREFETCH
  *
  * and the @flags can be:
+ *  - %DRM_XE_VM_BIND_FLAG_READONLY - Setup the page tables as read-only
+ *    to ensure write protection
+ *  - %DRM_XE_VM_BIND_FLAG_IMMEDIATE - On a faulting VM, do the
+ *    MAP operation immediately rather than deferring the MAP to the page
+ *    fault handler. This is implied on a non-faulting VM as there is no
+ *    fault handler to defer to.
  *  - %DRM_XE_VM_BIND_FLAG_NULL - When the NULL flag is set, the page
  *    tables are setup with a special bit which indicates writes are
  *    dropped and all reads return zero. In the future, the NULL flags
@@ -954,6 +969,8 @@ struct drm_xe_vm_bind_op {
 	/** @op: Bind operation to perform */
 	__u32 op;
 
+#define DRM_XE_VM_BIND_FLAG_READONLY	(1 << 0)
+#define DRM_XE_VM_BIND_FLAG_IMMEDIATE	(1 << 1)
 #define DRM_XE_VM_BIND_FLAG_NULL	(1 << 2)
 #define DRM_XE_VM_BIND_FLAG_DUMPABLE	(1 << 3)
 	/** @flags: Bind flags */
diff --git a/original/uapi/linux/bpf.h b/original/uapi/linux/bpf.h
index 3c42b9f..90706a4 100644
--- a/original/uapi/linux/bpf.h
+++ b/original/uapi/linux/bpf.h
@@ -1115,6 +1115,7 @@ enum bpf_attach_type {
 	BPF_CGROUP_UNIX_GETSOCKNAME,
 	BPF_NETKIT_PRIMARY,
 	BPF_NETKIT_PEER,
+	BPF_TRACE_KPROBE_SESSION,
 	__MAX_BPF_ATTACH_TYPE
 };
 
@@ -1135,6 +1136,7 @@ enum bpf_link_type {
 	BPF_LINK_TYPE_TCX = 11,
 	BPF_LINK_TYPE_UPROBE_MULTI = 12,
 	BPF_LINK_TYPE_NETKIT = 13,
+	BPF_LINK_TYPE_SOCKMAP = 14,
 	__MAX_BPF_LINK_TYPE,
 };
 
@@ -1662,8 +1664,10 @@ union bpf_attr {
 	} query;
 
 	struct { /* anonymous struct used by BPF_RAW_TRACEPOINT_OPEN command */
-		__u64 name;
-		__u32 prog_fd;
+		__u64		name;
+		__u32		prog_fd;
+		__u32		:32;
+		__aligned_u64	cookie;
 	} raw_tracepoint;
 
 	struct { /* anonymous struct for BPF_BTF_LOAD */
@@ -3392,6 +3396,10 @@ union bpf_attr {
  *			for the nexthop. If the src addr cannot be derived,
  *			**BPF_FIB_LKUP_RET_NO_SRC_ADDR** is returned. In this
  *			case, *params*->dmac and *params*->smac are not set either.
+ *		**BPF_FIB_LOOKUP_MARK**
+ *			Use the mark present in *params*->mark for the fib lookup.
+ *			This option should not be used with BPF_FIB_LOOKUP_DIRECT,
+ *			as it only has meaning for full lookups.
  *
  *		*ctx* is either **struct xdp_md** for XDP programs or
  *		**struct sk_buff** tc cls_act programs.
@@ -5020,7 +5028,7 @@ union bpf_attr {
  *		bytes will be copied to *dst*
  *	Return
  *		The **hash_algo** is returned on success,
- *		**-EOPNOTSUP** if IMA is disabled or **-EINVAL** if
+ *		**-EOPNOTSUPP** if IMA is disabled or **-EINVAL** if
  *		invalid arguments are passed.
  *
  * struct socket *bpf_sock_from_file(struct file *file)
@@ -5506,7 +5514,7 @@ union bpf_attr {
  *		bytes will be copied to *dst*
  *	Return
  *		The **hash_algo** is returned on success,
- *		**-EOPNOTSUP** if the hash calculation failed or **-EINVAL** if
+ *		**-EOPNOTSUPP** if the hash calculation failed or **-EINVAL** if
  *		invalid arguments are passed.
  *
  * void *bpf_kptr_xchg(void *map_value, void *ptr)
@@ -6718,6 +6726,10 @@ struct bpf_link_info {
 			__u32 ifindex;
 			__u32 attach_type;
 		} netkit;
+		struct {
+			__u32 map_id;
+			__u32 attach_type;
+		} sockmap;
 	};
 } __attribute__((aligned(8)));
 
@@ -6936,6 +6948,8 @@ enum {
 					 * socket transition to LISTEN state.
 					 */
 	BPF_SOCK_OPS_RTT_CB,		/* Called on every RTT.
+					 * Arg1: measured RTT input (mrtt)
+					 * Arg2: updated srtt
 					 */
 	BPF_SOCK_OPS_PARSE_HDR_OPT_CB,	/* Parse the header option.
 					 * It will be called to handle
@@ -7118,6 +7132,7 @@ enum {
 	BPF_FIB_LOOKUP_SKIP_NEIGH = (1U << 2),
 	BPF_FIB_LOOKUP_TBID    = (1U << 3),
 	BPF_FIB_LOOKUP_SRC     = (1U << 4),
+	BPF_FIB_LOOKUP_MARK    = (1U << 5),
 };
 
 enum {
@@ -7150,7 +7165,7 @@ struct bpf_fib_lookup {
 
 		/* output: MTU value */
 		__u16	mtu_result;
-	};
+	} __attribute__((packed, aligned(2)));
 	/* input: L3 device index for lookup
 	 * output: device index from FIB lookup
 	 */
@@ -7195,8 +7210,19 @@ struct bpf_fib_lookup {
 		__u32	tbid;
 	};
 
-	__u8	smac[6];     /* ETH_ALEN */
-	__u8	dmac[6];     /* ETH_ALEN */
+	union {
+		/* input */
+		struct {
+			__u32	mark;   /* policy routing */
+			/* 2 4-byte holes for input */
+		};
+
+		/* output: source and dest mac */
+		struct {
+			__u8	smac[6];	/* ETH_ALEN */
+			__u8	dmac[6];	/* ETH_ALEN */
+		};
+	};
 };
 
 struct bpf_redir_neigh {
@@ -7283,6 +7309,10 @@ struct bpf_timer {
 	__u64 __opaque[2];
 } __attribute__((aligned(8)));
 
+struct bpf_wq {
+	__u64 __opaque[2];
+} __attribute__((aligned(8)));
+
 struct bpf_dynptr {
 	__u64 __opaque[2];
 } __attribute__((aligned(8)));
diff --git a/original/uapi/linux/cn_proc.h b/original/uapi/linux/cn_proc.h
index f2afb7c..18e3745 100644
--- a/original/uapi/linux/cn_proc.h
+++ b/original/uapi/linux/cn_proc.h
@@ -69,8 +69,7 @@ struct proc_input {
 
 static inline enum proc_cn_event valid_event(enum proc_cn_event ev_type)
 {
-	ev_type &= PROC_EVENT_ALL;
-	return ev_type;
+	return (enum proc_cn_event)(ev_type & PROC_EVENT_ALL);
 }
 
 /*
diff --git a/original/uapi/linux/cryptouser.h b/original/uapi/linux/cryptouser.h
index 5730c67..20a6c0f 100644
--- a/original/uapi/linux/cryptouser.h
+++ b/original/uapi/linux/cryptouser.h
@@ -32,7 +32,7 @@ enum {
 	CRYPTO_MSG_UPDATEALG,
 	CRYPTO_MSG_GETALG,
 	CRYPTO_MSG_DELRNG,
-	CRYPTO_MSG_GETSTAT,
+	CRYPTO_MSG_GETSTAT, /* No longer supported, do not use. */
 	__CRYPTO_MSG_MAX
 };
 #define CRYPTO_MSG_MAX (__CRYPTO_MSG_MAX - 1)
@@ -54,16 +54,16 @@ enum crypto_attr_type_t {
 	CRYPTOCFGA_REPORT_AKCIPHER,	/* struct crypto_report_akcipher */
 	CRYPTOCFGA_REPORT_KPP,		/* struct crypto_report_kpp */
 	CRYPTOCFGA_REPORT_ACOMP,	/* struct crypto_report_acomp */
-	CRYPTOCFGA_STAT_LARVAL,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_HASH,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_BLKCIPHER,	/* struct crypto_stat */
-	CRYPTOCFGA_STAT_AEAD,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_COMPRESS,	/* struct crypto_stat */
-	CRYPTOCFGA_STAT_RNG,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_CIPHER,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_AKCIPHER,	/* struct crypto_stat */
-	CRYPTOCFGA_STAT_KPP,		/* struct crypto_stat */
-	CRYPTOCFGA_STAT_ACOMP,		/* struct crypto_stat */
+	CRYPTOCFGA_STAT_LARVAL,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_HASH,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_BLKCIPHER,	/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_AEAD,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_COMPRESS,	/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_RNG,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_CIPHER,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_AKCIPHER,	/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_KPP,		/* No longer supported, do not use. */
+	CRYPTOCFGA_STAT_ACOMP,		/* No longer supported, do not use. */
 	__CRYPTOCFGA_MAX
 
 #define CRYPTOCFGA_MAX (__CRYPTOCFGA_MAX - 1)
@@ -79,6 +79,7 @@ struct crypto_user_alg {
 	__u32 cru_flags;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_aead {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_encrypt_cnt;
@@ -88,6 +89,7 @@ struct crypto_stat_aead {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_akcipher {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_encrypt_cnt;
@@ -99,6 +101,7 @@ struct crypto_stat_akcipher {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_cipher {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_encrypt_cnt;
@@ -108,6 +111,7 @@ struct crypto_stat_cipher {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_compress {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_compress_cnt;
@@ -117,6 +121,7 @@ struct crypto_stat_compress {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_hash {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_hash_cnt;
@@ -124,6 +129,7 @@ struct crypto_stat_hash {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_kpp {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_setsecret_cnt;
@@ -132,6 +138,7 @@ struct crypto_stat_kpp {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_rng {
 	char type[CRYPTO_MAX_NAME];
 	__u64 stat_generate_cnt;
@@ -140,6 +147,7 @@ struct crypto_stat_rng {
 	__u64 stat_err_cnt;
 };
 
+/* No longer supported, do not use. */
 struct crypto_stat_larval {
 	char type[CRYPTO_MAX_NAME];
 };
diff --git a/original/uapi/linux/cxl_mem.h b/original/uapi/linux/cxl_mem.h
index 42066f4..c6c0fe2 100644
--- a/original/uapi/linux/cxl_mem.h
+++ b/original/uapi/linux/cxl_mem.h
@@ -47,6 +47,9 @@
 	___DEPRECATED(SCAN_MEDIA, "Scan Media"),                          \
 	___DEPRECATED(GET_SCAN_MEDIA, "Get Scan Media Results"),          \
 	___C(GET_TIMESTAMP, "Get Timestamp"),                             \
+	___C(GET_LOG_CAPS, "Get Log Capabilities"),			  \
+	___C(CLEAR_LOG, "Clear Log"),					  \
+	___C(GET_SUP_LOG_SUBLIST, "Get Supported Logs Sub-List"),	  \
 	___C(MAX, "invalid / last command")
 
 #define ___C(a, b) CXL_MEM_COMMAND_ID_##a
diff --git a/original/uapi/linux/devlink.h b/original/uapi/linux/devlink.h
index 2da0c7e..9401aa3 100644
--- a/original/uapi/linux/devlink.h
+++ b/original/uapi/linux/devlink.h
@@ -686,6 +686,7 @@ enum devlink_port_function_attr {
 	DEVLINK_PORT_FN_ATTR_OPSTATE,	/* u8 */
 	DEVLINK_PORT_FN_ATTR_CAPS,	/* bitfield32 */
 	DEVLINK_PORT_FN_ATTR_DEVLINK,	/* nested */
+	DEVLINK_PORT_FN_ATTR_MAX_IO_EQS,	/* u32 */
 
 	__DEVLINK_PORT_FUNCTION_ATTR_MAX,
 	DEVLINK_PORT_FUNCTION_ATTR_MAX = __DEVLINK_PORT_FUNCTION_ATTR_MAX - 1
diff --git a/original/uapi/linux/dvb/frontend.h b/original/uapi/linux/dvb/frontend.h
index 7e0983b..8d38c6b 100644
--- a/original/uapi/linux/dvb/frontend.h
+++ b/original/uapi/linux/dvb/frontend.h
@@ -854,7 +854,7 @@ struct dtv_stats {
 	union {
 		__u64 uvalue;	/* for counters and relative scales */
 		__s64 svalue;	/* for 0.001 dB measures */
-	};
+	}  __attribute__ ((packed));
 } __attribute__ ((packed));
 
 
diff --git a/original/uapi/linux/ethtool.h b/original/uapi/linux/ethtool.h
index 11fc189..8733a31 100644
--- a/original/uapi/linux/ethtool.h
+++ b/original/uapi/linux/ethtool.h
@@ -752,6 +752,61 @@ enum ethtool_module_power_mode {
 	ETHTOOL_MODULE_POWER_MODE_HIGH,
 };
 
+/**
+ * enum ethtool_pse_types - Types of PSE controller.
+ * @ETHTOOL_PSE_UNKNOWN: Type of PSE controller is unknown
+ * @ETHTOOL_PSE_PODL: PSE controller which support PoDL
+ * @ETHTOOL_PSE_C33: PSE controller which support Clause 33 (PoE)
+ */
+enum ethtool_pse_types {
+	ETHTOOL_PSE_UNKNOWN =	1 << 0,
+	ETHTOOL_PSE_PODL =	1 << 1,
+	ETHTOOL_PSE_C33 =	1 << 2,
+};
+
+/**
+ * enum ethtool_c33_pse_admin_state - operational state of the PoDL PSE
+ *	functions. IEEE 802.3-2022 30.9.1.1.2 aPSEAdminState
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN: state of PSE functions is unknown
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED: PSE functions are disabled
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED: PSE functions are enabled
+ */
+enum ethtool_c33_pse_admin_state {
+	ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN = 1,
+	ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED,
+	ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED,
+};
+
+/**
+ * enum ethtool_c33_pse_pw_d_status - power detection status of the PSE.
+ *	IEEE 802.3-2022 30.9.1.1.3 aPoDLPSEPowerDetectionStatus:
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN: PSE status is unknown
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED: The enumeration "disabled"
+ *	indicates that the PSE State diagram is in the state DISABLED.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING: The enumeration "searching"
+ *	indicates the PSE State diagram is in a state other than those
+ *	listed.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING: The enumeration
+ *	"deliveringPower" indicates that the PSE State diagram is in the
+ *	state POWER_ON.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_TEST: The enumeration "test" indicates that
+ *	the PSE State diagram is in the state TEST_MODE.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_FAULT: The enumeration "fault" indicates that
+ *	the PSE State diagram is in the state TEST_ERROR.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT: The enumeration "otherFault"
+ *	indicates that the PSE State diagram is in the state IDLE due to
+ *	the variable error_condition = true.
+ */
+enum ethtool_c33_pse_pw_d_status {
+	ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN = 1,
+	ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED,
+	ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING,
+	ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING,
+	ETHTOOL_C33_PSE_PW_D_STATUS_TEST,
+	ETHTOOL_C33_PSE_PW_D_STATUS_FAULT,
+	ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT,
+};
+
 /**
  * enum ethtool_podl_pse_admin_state - operational state of the PoDL PSE
  *	functions. IEEE 802.3-2018 30.15.1.1.2 aPoDLPSEAdminState
diff --git a/original/uapi/linux/ethtool_netlink.h b/original/uapi/linux/ethtool_netlink.h
index 3f89074..b49b804 100644
--- a/original/uapi/linux/ethtool_netlink.h
+++ b/original/uapi/linux/ethtool_netlink.h
@@ -117,12 +117,11 @@ enum {
 
 /* request header */
 
-/* use compact bitsets in reply */
-#define ETHTOOL_FLAG_COMPACT_BITSETS	(1 << 0)
-/* provide optional reply for SET or ACT requests */
-#define ETHTOOL_FLAG_OMIT_REPLY	(1 << 1)
-/* request statistics, if supported by the driver */
-#define ETHTOOL_FLAG_STATS		(1 << 2)
+enum ethtool_header_flags {
+	ETHTOOL_FLAG_COMPACT_BITSETS	= 1 << 0,	/* use compact bitsets in reply */
+	ETHTOOL_FLAG_OMIT_REPLY		= 1 << 1,	/* provide optional reply for SET or ACT requests */
+	ETHTOOL_FLAG_STATS		= 1 << 2,	/* request statistics, if supported by the driver */
+};
 
 #define ETHTOOL_FLAG_ALL (ETHTOOL_FLAG_COMPACT_BITSETS | \
 			  ETHTOOL_FLAG_OMIT_REPLY | \
@@ -478,12 +477,26 @@ enum {
 	ETHTOOL_A_TSINFO_TX_TYPES,			/* bitset */
 	ETHTOOL_A_TSINFO_RX_FILTERS,			/* bitset */
 	ETHTOOL_A_TSINFO_PHC_INDEX,			/* u32 */
+	ETHTOOL_A_TSINFO_STATS,				/* nest - _A_TSINFO_STAT */
 
 	/* add new constants above here */
 	__ETHTOOL_A_TSINFO_CNT,
 	ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
 };
 
+enum {
+	ETHTOOL_A_TS_STAT_UNSPEC,
+
+	ETHTOOL_A_TS_STAT_TX_PKTS,			/* uint */
+	ETHTOOL_A_TS_STAT_TX_LOST,			/* uint */
+	ETHTOOL_A_TS_STAT_TX_ERR,			/* uint */
+
+	/* add new constants above here */
+	__ETHTOOL_A_TS_STAT_CNT,
+	ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
+
+};
+
 /* PHC VCLOCKS */
 
 enum {
@@ -515,6 +528,10 @@ enum {
 	ETHTOOL_A_CABLE_RESULT_CODE_OPEN,
 	ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
 	ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
+	/* detected reflection caused by the impedance discontinuity between
+	 * a regular 100 Ohm cable and a part with the abnormal impedance value
+	 */
+	ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
 };
 
 enum {
@@ -895,6 +912,9 @@ enum {
 	ETHTOOL_A_PODL_PSE_ADMIN_STATE,		/* u32 */
 	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,	/* u32 */
 	ETHTOOL_A_PODL_PSE_PW_D_STATUS,		/* u32 */
+	ETHTOOL_A_C33_PSE_ADMIN_STATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_ADMIN_CONTROL,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_D_STATUS,		/* u32 */
 
 	/* add new constants above here */
 	__ETHTOOL_A_PSE_CNT,
diff --git a/original/uapi/linux/fcntl.h b/original/uapi/linux/fcntl.h
index 282e90a..c0bcc18 100644
--- a/original/uapi/linux/fcntl.h
+++ b/original/uapi/linux/fcntl.h
@@ -8,6 +8,14 @@
 #define F_SETLEASE	(F_LINUX_SPECIFIC_BASE + 0)
 #define F_GETLEASE	(F_LINUX_SPECIFIC_BASE + 1)
 
+/*
+ * Request nofications on a directory.
+ * See below for events that may be notified.
+ */
+#define F_NOTIFY	(F_LINUX_SPECIFIC_BASE + 2)
+
+#define F_DUPFD_QUERY	(F_LINUX_SPECIFIC_BASE + 3)
+
 /*
  * Cancel a blocking posix lock; internal use only until we expose an
  * asynchronous lock api to userspace:
@@ -17,12 +25,6 @@
 /* Create a file descriptor with FD_CLOEXEC set. */
 #define F_DUPFD_CLOEXEC	(F_LINUX_SPECIFIC_BASE + 6)
 
-/*
- * Request nofications on a directory.
- * See below for events that may be notified.
- */
-#define F_NOTIFY	(F_LINUX_SPECIFIC_BASE+2)
-
 /*
  * Set and get of pipe page size array
  */
diff --git a/original/uapi/linux/gtp.h b/original/uapi/linux/gtp.h
index 3dcdb9e..40f5388 100644
--- a/original/uapi/linux/gtp.h
+++ b/original/uapi/linux/gtp.h
@@ -31,6 +31,9 @@ enum gtp_attrs {
 	GTPA_I_TEI,	/* for GTPv1 only */
 	GTPA_O_TEI,	/* for GTPv1 only */
 	GTPA_PAD,
+	GTPA_PEER_ADDR6,
+	GTPA_MS_ADDR6,
+	GTPA_FAMILY,
 	__GTPA_MAX,
 };
 #define GTPA_MAX (__GTPA_MAX - 1)
diff --git a/original/uapi/linux/icmpv6.h b/original/uapi/linux/icmpv6.h
index ecaece3..4eaab89 100644
--- a/original/uapi/linux/icmpv6.h
+++ b/original/uapi/linux/icmpv6.h
@@ -112,6 +112,7 @@ struct icmp6hdr {
 #define ICMPV6_MOBILE_PREFIX_ADV	147
 
 #define ICMPV6_MRDISC_ADV		151
+#define ICMPV6_MRDISC_SOL		152
 
 #define ICMPV6_MSG_MAX          255
 
diff --git a/original/uapi/linux/if_link.h b/original/uapi/linux/if_link.h
index ffa637b..6dc2589 100644
--- a/original/uapi/linux/if_link.h
+++ b/original/uapi/linux/if_link.h
@@ -1466,6 +1466,8 @@ enum {
 	IFLA_GTP_ROLE,
 	IFLA_GTP_CREATE_SOCKETS,
 	IFLA_GTP_RESTART_COUNT,
+	IFLA_GTP_LOCAL,
+	IFLA_GTP_LOCAL6,
 	__IFLA_GTP_MAX,
 };
 #define IFLA_GTP_MAX (__IFLA_GTP_MAX - 1)
@@ -1771,6 +1773,7 @@ enum {
 	IFLA_HSR_PROTOCOL,		/* Indicate different protocol than
 					 * HSR. For example PRP.
 					 */
+	IFLA_HSR_INTERLINK,		/* HSR interlink network device */
 	__IFLA_HSR_MAX,
 };
 
diff --git a/original/uapi/linux/if_team.h b/original/uapi/linux/if_team.h
index 13c61fe..a5c0624 100644
--- a/original/uapi/linux/if_team.h
+++ b/original/uapi/linux/if_team.h
@@ -1,108 +1,78 @@
-/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
-/*
- * include/linux/if_team.h - Network team device driver header
- * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; either version 2 of the License, or
- * (at your option) any later version.
- */
+/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
+/* Do not edit directly, auto-generated from: */
+/*	Documentation/netlink/specs/team.yaml */
+/* YNL-GEN uapi header */
 
-#ifndef _UAPI_LINUX_IF_TEAM_H_
-#define _UAPI_LINUX_IF_TEAM_H_
+#ifndef _UAPI_LINUX_IF_TEAM_H
+#define _UAPI_LINUX_IF_TEAM_H
 
+#define TEAM_GENL_NAME		"team"
+#define TEAM_GENL_VERSION	1
 
-#define TEAM_STRING_MAX_LEN 32
-
-/**********************************
- * NETLINK_GENERIC netlink family.
- **********************************/
-
-enum {
-	TEAM_CMD_NOOP,
-	TEAM_CMD_OPTIONS_SET,
-	TEAM_CMD_OPTIONS_GET,
-	TEAM_CMD_PORT_LIST_GET,
-
-	__TEAM_CMD_MAX,
-	TEAM_CMD_MAX = (__TEAM_CMD_MAX - 1),
-};
+#define TEAM_STRING_MAX_LEN			32
+#define TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME	"change_event"
 
 enum {
 	TEAM_ATTR_UNSPEC,
-	TEAM_ATTR_TEAM_IFINDEX,		/* u32 */
-	TEAM_ATTR_LIST_OPTION,		/* nest */
-	TEAM_ATTR_LIST_PORT,		/* nest */
+	TEAM_ATTR_TEAM_IFINDEX,
+	TEAM_ATTR_LIST_OPTION,
+	TEAM_ATTR_LIST_PORT,
 
 	__TEAM_ATTR_MAX,
-	TEAM_ATTR_MAX = __TEAM_ATTR_MAX - 1,
+	TEAM_ATTR_MAX = (__TEAM_ATTR_MAX - 1)
 };
 
-/* Nested layout of get/set msg:
- *
- *	[TEAM_ATTR_LIST_OPTION]
- *		[TEAM_ATTR_ITEM_OPTION]
- *			[TEAM_ATTR_OPTION_*], ...
- *		[TEAM_ATTR_ITEM_OPTION]
- *			[TEAM_ATTR_OPTION_*], ...
- *		...
- *	[TEAM_ATTR_LIST_PORT]
- *		[TEAM_ATTR_ITEM_PORT]
- *			[TEAM_ATTR_PORT_*], ...
- *		[TEAM_ATTR_ITEM_PORT]
- *			[TEAM_ATTR_PORT_*], ...
- *		...
- */
-
 enum {
 	TEAM_ATTR_ITEM_OPTION_UNSPEC,
-	TEAM_ATTR_ITEM_OPTION,		/* nest */
+	TEAM_ATTR_ITEM_OPTION,
 
 	__TEAM_ATTR_ITEM_OPTION_MAX,
-	TEAM_ATTR_ITEM_OPTION_MAX = __TEAM_ATTR_ITEM_OPTION_MAX - 1,
+	TEAM_ATTR_ITEM_OPTION_MAX = (__TEAM_ATTR_ITEM_OPTION_MAX - 1)
 };
 
 enum {
 	TEAM_ATTR_OPTION_UNSPEC,
-	TEAM_ATTR_OPTION_NAME,		/* string */
-	TEAM_ATTR_OPTION_CHANGED,	/* flag */
-	TEAM_ATTR_OPTION_TYPE,		/* u8 */
-	TEAM_ATTR_OPTION_DATA,		/* dynamic */
-	TEAM_ATTR_OPTION_REMOVED,	/* flag */
-	TEAM_ATTR_OPTION_PORT_IFINDEX,	/* u32 */ /* for per-port options */
-	TEAM_ATTR_OPTION_ARRAY_INDEX,	/* u32 */ /* for array options */
+	TEAM_ATTR_OPTION_NAME,
+	TEAM_ATTR_OPTION_CHANGED,
+	TEAM_ATTR_OPTION_TYPE,
+	TEAM_ATTR_OPTION_DATA,
+	TEAM_ATTR_OPTION_REMOVED,
+	TEAM_ATTR_OPTION_PORT_IFINDEX,
+	TEAM_ATTR_OPTION_ARRAY_INDEX,
 
 	__TEAM_ATTR_OPTION_MAX,
-	TEAM_ATTR_OPTION_MAX = __TEAM_ATTR_OPTION_MAX - 1,
+	TEAM_ATTR_OPTION_MAX = (__TEAM_ATTR_OPTION_MAX - 1)
 };
 
 enum {
 	TEAM_ATTR_ITEM_PORT_UNSPEC,
-	TEAM_ATTR_ITEM_PORT,		/* nest */
+	TEAM_ATTR_ITEM_PORT,
 
 	__TEAM_ATTR_ITEM_PORT_MAX,
-	TEAM_ATTR_ITEM_PORT_MAX = __TEAM_ATTR_ITEM_PORT_MAX - 1,
+	TEAM_ATTR_ITEM_PORT_MAX = (__TEAM_ATTR_ITEM_PORT_MAX - 1)
 };
 
 enum {
 	TEAM_ATTR_PORT_UNSPEC,
-	TEAM_ATTR_PORT_IFINDEX,		/* u32 */
-	TEAM_ATTR_PORT_CHANGED,		/* flag */
-	TEAM_ATTR_PORT_LINKUP,		/* flag */
-	TEAM_ATTR_PORT_SPEED,		/* u32 */
-	TEAM_ATTR_PORT_DUPLEX,		/* u8 */
-	TEAM_ATTR_PORT_REMOVED,		/* flag */
+	TEAM_ATTR_PORT_IFINDEX,
+	TEAM_ATTR_PORT_CHANGED,
+	TEAM_ATTR_PORT_LINKUP,
+	TEAM_ATTR_PORT_SPEED,
+	TEAM_ATTR_PORT_DUPLEX,
+	TEAM_ATTR_PORT_REMOVED,
 
 	__TEAM_ATTR_PORT_MAX,
-	TEAM_ATTR_PORT_MAX = __TEAM_ATTR_PORT_MAX - 1,
+	TEAM_ATTR_PORT_MAX = (__TEAM_ATTR_PORT_MAX - 1)
 };
 
-/*
- * NETLINK_GENERIC related info
- */
-#define TEAM_GENL_NAME "team"
-#define TEAM_GENL_VERSION 0x1
-#define TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME "change_event"
+enum {
+	TEAM_CMD_NOOP,
+	TEAM_CMD_OPTIONS_SET,
+	TEAM_CMD_OPTIONS_GET,
+	TEAM_CMD_PORT_LIST_GET,
+
+	__TEAM_CMD_MAX,
+	TEAM_CMD_MAX = (__TEAM_CMD_MAX - 1)
+};
 
-#endif /* _UAPI_LINUX_IF_TEAM_H_ */
+#endif /* _UAPI_LINUX_IF_TEAM_H */
diff --git a/original/uapi/linux/if_tunnel.h b/original/uapi/linux/if_tunnel.h
index 1021196..e1a246d 100644
--- a/original/uapi/linux/if_tunnel.h
+++ b/original/uapi/linux/if_tunnel.h
@@ -161,6 +161,14 @@ enum {
 
 #define IFLA_VTI_MAX	(__IFLA_VTI_MAX - 1)
 
+#ifndef __KERNEL__
+/* Historically, tunnel flags have been defined as __be16 and now there are
+ * no free bits left. It is strongly advised to switch the already existing
+ * userspace code to the new *_BIT definitions from down below, as __be16
+ * can't be simply cast to a wider type on LE systems. All new flags and
+ * code must use *_BIT only.
+ */
+
 #define TUNNEL_CSUM		__cpu_to_be16(0x01)
 #define TUNNEL_ROUTING		__cpu_to_be16(0x02)
 #define TUNNEL_KEY		__cpu_to_be16(0x04)
@@ -181,5 +189,33 @@ enum {
 #define TUNNEL_OPTIONS_PRESENT \
 		(TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT | TUNNEL_ERSPAN_OPT | \
 		TUNNEL_GTP_OPT)
+#endif
+
+enum {
+	IP_TUNNEL_CSUM_BIT		= 0U,
+	IP_TUNNEL_ROUTING_BIT,
+	IP_TUNNEL_KEY_BIT,
+	IP_TUNNEL_SEQ_BIT,
+	IP_TUNNEL_STRICT_BIT,
+	IP_TUNNEL_REC_BIT,
+	IP_TUNNEL_VERSION_BIT,
+	IP_TUNNEL_NO_KEY_BIT,
+	IP_TUNNEL_DONT_FRAGMENT_BIT,
+	IP_TUNNEL_OAM_BIT,
+	IP_TUNNEL_CRIT_OPT_BIT,
+	IP_TUNNEL_GENEVE_OPT_BIT,	/* OPTIONS_PRESENT */
+	IP_TUNNEL_VXLAN_OPT_BIT,	/* OPTIONS_PRESENT */
+	IP_TUNNEL_NOCACHE_BIT,
+	IP_TUNNEL_ERSPAN_OPT_BIT,	/* OPTIONS_PRESENT */
+	IP_TUNNEL_GTP_OPT_BIT,		/* OPTIONS_PRESENT */
+
+	IP_TUNNEL_VTI_BIT,
+	IP_TUNNEL_SIT_ISATAP_BIT	= IP_TUNNEL_VTI_BIT,
+
+	/* Flags starting from here are not available via the old UAPI */
+	IP_TUNNEL_PFCP_OPT_BIT,		/* OPTIONS_PRESENT */
+
+	__IP_TUNNEL_FLAG_NUM,
+};
 
 #endif /* _UAPI_IF_TUNNEL_H_ */
diff --git a/original/uapi/linux/input-event-codes.h b/original/uapi/linux/input-event-codes.h
index 03edf2c..a420672 100644
--- a/original/uapi/linux/input-event-codes.h
+++ b/original/uapi/linux/input-event-codes.h
@@ -618,6 +618,8 @@
 #define KEY_CAMERA_ACCESS_ENABLE	0x24b	/* Enables programmatic access to camera devices. (HUTRR72) */
 #define KEY_CAMERA_ACCESS_DISABLE	0x24c	/* Disables programmatic access to camera devices. (HUTRR72) */
 #define KEY_CAMERA_ACCESS_TOGGLE	0x24d	/* Toggles the current state of the camera access control. (HUTRR72) */
+#define KEY_ACCESSIBILITY		0x24e	/* Toggles the system bound accessibility UI/command (HUTRR116) */
+#define KEY_DO_NOT_DISTURB		0x24f	/* Toggles the system-wide "Do Not Disturb" control (HUTRR94)*/
 
 #define KEY_BRIGHTNESS_MIN		0x250	/* Set Brightness to Minimum */
 #define KEY_BRIGHTNESS_MAX		0x251	/* Set Brightness to Maximum */
diff --git a/original/uapi/linux/io_uring.h b/original/uapi/linux/io_uring.h
index 7bd1020..994bf7a 100644
--- a/original/uapi/linux/io_uring.h
+++ b/original/uapi/linux/io_uring.h
@@ -72,6 +72,7 @@ struct io_uring_sqe {
 		__u32		waitid_flags;
 		__u32		futex_flags;
 		__u32		install_fd_flags;
+		__u32		nop_flags;
 	};
 	__u64	user_data;	/* data to be passed back at completion time */
 	/* pack this to avoid bogus arm OABI complaints */
@@ -115,7 +116,7 @@ struct io_uring_sqe {
  */
 #define IORING_FILE_INDEX_ALLOC		(~0U)
 
-enum {
+enum io_uring_sqe_flags_bit {
 	IOSQE_FIXED_FILE_BIT,
 	IOSQE_IO_DRAIN_BIT,
 	IOSQE_IO_LINK_BIT,
@@ -351,11 +352,20 @@ enum io_uring_op {
  *				0 is reported if zerocopy was actually possible.
  *				IORING_NOTIF_USAGE_ZC_COPIED if data was copied
  *				(at least partially).
+ *
+ * IORING_RECVSEND_BUNDLE	Used with IOSQE_BUFFER_SELECT. If set, send or
+ *				recv will grab as many buffers from the buffer
+ *				group ID given and send them all. The completion
+ *				result 	will be the number of buffers send, with
+ *				the starting buffer ID in cqe->flags as per
+ *				usual for provided buffer usage. The buffers
+ *				will be	contigious from the starting buffer ID.
  */
 #define IORING_RECVSEND_POLL_FIRST	(1U << 0)
 #define IORING_RECV_MULTISHOT		(1U << 1)
 #define IORING_RECVSEND_FIXED_BUF	(1U << 2)
 #define IORING_SEND_ZC_REPORT_USAGE	(1U << 3)
+#define IORING_RECVSEND_BUNDLE		(1U << 4)
 
 /*
  * cqe.res for IORING_CQE_F_NOTIF if
@@ -370,11 +380,13 @@ enum io_uring_op {
  * accept flags stored in sqe->ioprio
  */
 #define IORING_ACCEPT_MULTISHOT	(1U << 0)
+#define IORING_ACCEPT_DONTWAIT	(1U << 1)
+#define IORING_ACCEPT_POLL_FIRST	(1U << 2)
 
 /*
  * IORING_OP_MSG_RING command types, stored in sqe->addr
  */
-enum {
+enum io_uring_msg_ring_flags {
 	IORING_MSG_DATA,	/* pass sqe->len as 'res' and off as user_data */
 	IORING_MSG_SEND_FD,	/* send a registered fd to another ring */
 };
@@ -396,6 +408,13 @@ enum {
  */
 #define IORING_FIXED_FD_NO_CLOEXEC	(1U << 0)
 
+/*
+ * IORING_OP_NOP flags (sqe->nop_flags)
+ *
+ * IORING_NOP_INJECT_RESULT	Inject result from sqe->result
+ */
+#define IORING_NOP_INJECT_RESULT	(1U << 0)
+
 /*
  * IO completion data structure (Completion Queue Entry)
  */
@@ -425,9 +444,7 @@ struct io_uring_cqe {
 #define IORING_CQE_F_SOCK_NONEMPTY	(1U << 2)
 #define IORING_CQE_F_NOTIF		(1U << 3)
 
-enum {
-	IORING_CQE_BUFFER_SHIFT		= 16,
-};
+#define IORING_CQE_BUFFER_SHIFT		16
 
 /*
  * Magic offsets for the application to mmap the data it needs
@@ -522,11 +539,12 @@ struct io_uring_params {
 #define IORING_FEAT_CQE_SKIP		(1U << 11)
 #define IORING_FEAT_LINKED_FILE		(1U << 12)
 #define IORING_FEAT_REG_REG_RING	(1U << 13)
+#define IORING_FEAT_RECVSEND_BUNDLE	(1U << 14)
 
 /*
  * io_uring_register(2) opcodes and arguments
  */
-enum {
+enum io_uring_register_op {
 	IORING_REGISTER_BUFFERS			= 0,
 	IORING_UNREGISTER_BUFFERS		= 1,
 	IORING_REGISTER_FILES			= 2,
@@ -583,7 +601,7 @@ enum {
 };
 
 /* io-wq worker categories */
-enum {
+enum io_wq_type {
 	IO_WQ_BOUND,
 	IO_WQ_UNBOUND,
 };
@@ -688,7 +706,7 @@ struct io_uring_buf_ring {
  *			IORING_OFF_PBUF_RING | (bgid << IORING_OFF_PBUF_SHIFT)
  *			to get a virtual mapping for the ring.
  */
-enum {
+enum io_uring_register_pbuf_ring_flags {
 	IOU_PBUF_RING_MMAP	= 1,
 };
 
@@ -719,7 +737,7 @@ struct io_uring_napi {
 /*
  * io_uring_restriction->opcode values
  */
-enum {
+enum io_uring_register_restriction_op {
 	/* Allow an io_uring_register(2) opcode */
 	IORING_RESTRICTION_REGISTER_OP		= 0,
 
@@ -775,7 +793,7 @@ struct io_uring_recvmsg_out {
 /*
  * Argument for IORING_OP_URING_CMD when file is a socket
  */
-enum {
+enum io_uring_socket_op {
 	SOCKET_URING_OP_SIOCINQ		= 0,
 	SOCKET_URING_OP_SIOCOUTQ,
 	SOCKET_URING_OP_GETSOCKOPT,
diff --git a/original/uapi/linux/kexec.h b/original/uapi/linux/kexec.h
index c17bb09..5ae1741 100644
--- a/original/uapi/linux/kexec.h
+++ b/original/uapi/linux/kexec.h
@@ -13,6 +13,7 @@
 #define KEXEC_ON_CRASH		0x00000001
 #define KEXEC_PRESERVE_CONTEXT	0x00000002
 #define KEXEC_UPDATE_ELFCOREHDR	0x00000004
+#define KEXEC_CRASH_HOTPLUG_SUPPORT 0x00000008
 #define KEXEC_ARCH_MASK		0xffff0000
 
 /*
diff --git a/original/uapi/linux/kvm.h b/original/uapi/linux/kvm.h
index 2190adb..d03842a 100644
--- a/original/uapi/linux/kvm.h
+++ b/original/uapi/linux/kvm.h
@@ -1221,9 +1221,9 @@ struct kvm_vfio_spapr_tce {
 /* Available with KVM_CAP_SPAPR_RESIZE_HPT */
 #define KVM_PPC_RESIZE_HPT_PREPARE _IOR(KVMIO, 0xad, struct kvm_ppc_resize_hpt)
 #define KVM_PPC_RESIZE_HPT_COMMIT  _IOR(KVMIO, 0xae, struct kvm_ppc_resize_hpt)
-/* Available with KVM_CAP_PPC_RADIX_MMU or KVM_CAP_PPC_HASH_MMU_V3 */
+/* Available with KVM_CAP_PPC_MMU_RADIX or KVM_CAP_PPC_MMU_HASH_V3 */
 #define KVM_PPC_CONFIGURE_V3_MMU  _IOW(KVMIO,  0xaf, struct kvm_ppc_mmuv3_cfg)
-/* Available with KVM_CAP_PPC_RADIX_MMU */
+/* Available with KVM_CAP_PPC_MMU_RADIX */
 #define KVM_PPC_GET_RMMU_INFO	  _IOW(KVMIO,  0xb0, struct kvm_ppc_rmmu_info)
 /* Available with KVM_CAP_PPC_GET_CPU_CHAR */
 #define KVM_PPC_GET_CPU_CHAR	  _IOR(KVMIO,  0xb1, struct kvm_ppc_cpu_char)
diff --git a/original/uapi/linux/landlock.h b/original/uapi/linux/landlock.h
index 25c8d76..68625e7 100644
--- a/original/uapi/linux/landlock.h
+++ b/original/uapi/linux/landlock.h
@@ -128,7 +128,7 @@ struct landlock_net_port_attr {
  * files and directories.  Files or directories opened before the sandboxing
  * are not subject to these restrictions.
  *
- * A file can only receive these access rights:
+ * The following access rights apply only to files:
  *
  * - %LANDLOCK_ACCESS_FS_EXECUTE: Execute a file.
  * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Open a file with write access. Note that
@@ -138,12 +138,13 @@ struct landlock_net_port_attr {
  * - %LANDLOCK_ACCESS_FS_READ_FILE: Open a file with read access.
  * - %LANDLOCK_ACCESS_FS_TRUNCATE: Truncate a file with :manpage:`truncate(2)`,
  *   :manpage:`ftruncate(2)`, :manpage:`creat(2)`, or :manpage:`open(2)` with
- *   ``O_TRUNC``. Whether an opened file can be truncated with
- *   :manpage:`ftruncate(2)` is determined during :manpage:`open(2)`, in the
- *   same way as read and write permissions are checked during
- *   :manpage:`open(2)` using %LANDLOCK_ACCESS_FS_READ_FILE and
- *   %LANDLOCK_ACCESS_FS_WRITE_FILE. This access right is available since the
- *   third version of the Landlock ABI.
+ *   ``O_TRUNC``.  This access right is available since the third version of the
+ *   Landlock ABI.
+ *
+ * Whether an opened file can be truncated with :manpage:`ftruncate(2)` or used
+ * with `ioctl(2)` is determined during :manpage:`open(2)`, in the same way as
+ * read and write permissions are checked during :manpage:`open(2)` using
+ * %LANDLOCK_ACCESS_FS_READ_FILE and %LANDLOCK_ACCESS_FS_WRITE_FILE.
  *
  * A directory can receive access rights related to files or directories.  The
  * following access right is applied to the directory itself, and the
@@ -198,13 +199,33 @@ struct landlock_net_port_attr {
  *   If multiple requirements are not met, the ``EACCES`` error code takes
  *   precedence over ``EXDEV``.
  *
+ * The following access right applies both to files and directories:
+ *
+ * - %LANDLOCK_ACCESS_FS_IOCTL_DEV: Invoke :manpage:`ioctl(2)` commands on an opened
+ *   character or block device.
+ *
+ *   This access right applies to all `ioctl(2)` commands implemented by device
+ *   drivers.  However, the following common IOCTL commands continue to be
+ *   invokable independent of the %LANDLOCK_ACCESS_FS_IOCTL_DEV right:
+ *
+ *   * IOCTL commands targeting file descriptors (``FIOCLEX``, ``FIONCLEX``),
+ *   * IOCTL commands targeting file descriptions (``FIONBIO``, ``FIOASYNC``),
+ *   * IOCTL commands targeting file systems (``FIFREEZE``, ``FITHAW``,
+ *     ``FIGETBSZ``, ``FS_IOC_GETFSUUID``, ``FS_IOC_GETFSSYSFSPATH``)
+ *   * Some IOCTL commands which do not make sense when used with devices, but
+ *     whose implementations are safe and return the right error codes
+ *     (``FS_IOC_FIEMAP``, ``FICLONE``, ``FICLONERANGE``, ``FIDEDUPERANGE``)
+ *
+ *   This access right is available since the fifth version of the Landlock
+ *   ABI.
+ *
  * .. warning::
  *
  *   It is currently not possible to restrict some file-related actions
  *   accessible through these syscall families: :manpage:`chdir(2)`,
  *   :manpage:`stat(2)`, :manpage:`flock(2)`, :manpage:`chmod(2)`,
  *   :manpage:`chown(2)`, :manpage:`setxattr(2)`, :manpage:`utime(2)`,
- *   :manpage:`ioctl(2)`, :manpage:`fcntl(2)`, :manpage:`access(2)`.
+ *   :manpage:`fcntl(2)`, :manpage:`access(2)`.
  *   Future Landlock evolutions will enable to restrict them.
  */
 /* clang-format off */
@@ -223,6 +244,7 @@ struct landlock_net_port_attr {
 #define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 12)
 #define LANDLOCK_ACCESS_FS_REFER			(1ULL << 13)
 #define LANDLOCK_ACCESS_FS_TRUNCATE			(1ULL << 14)
+#define LANDLOCK_ACCESS_FS_IOCTL_DEV			(1ULL << 15)
 /* clang-format on */
 
 /**
diff --git a/original/uapi/linux/magic.h b/original/uapi/linux/magic.h
index 1b40a96..bb575f3 100644
--- a/original/uapi/linux/magic.h
+++ b/original/uapi/linux/magic.h
@@ -37,6 +37,7 @@
 #define HOSTFS_SUPER_MAGIC	0x00c0ffee
 #define OVERLAYFS_SUPER_MAGIC	0x794c7630
 #define FUSE_SUPER_MAGIC	0x65735546
+#define BCACHEFS_SUPER_MAGIC	0xca451a4e
 
 #define MINIX_SUPER_MAGIC	0x137F		/* minix v1 fs, 14 char names */
 #define MINIX_SUPER_MAGIC2	0x138F		/* minix v1 fs, 30 char names */
diff --git a/original/uapi/linux/media-bus-format.h b/original/uapi/linux/media-bus-format.h
index f05f747..d4c1d99 100644
--- a/original/uapi/linux/media-bus-format.h
+++ b/original/uapi/linux/media-bus-format.h
@@ -174,4 +174,13 @@
  */
 #define MEDIA_BUS_FMT_METADATA_FIXED		0x7001
 
+/* Generic line based metadata formats for serial buses. Next is 0x8008. */
+#define MEDIA_BUS_FMT_META_8			0x8001
+#define MEDIA_BUS_FMT_META_10			0x8002
+#define MEDIA_BUS_FMT_META_12			0x8003
+#define MEDIA_BUS_FMT_META_14			0x8004
+#define MEDIA_BUS_FMT_META_16			0x8005
+#define MEDIA_BUS_FMT_META_20			0x8006
+#define MEDIA_BUS_FMT_META_24			0x8007
+
 #endif /* __LINUX_MEDIA_BUS_FORMAT_H */
diff --git a/original/uapi/linux/mptcp.h b/original/uapi/linux/mptcp.h
index 74cfe49..67d015d 100644
--- a/original/uapi/linux/mptcp.h
+++ b/original/uapi/linux/mptcp.h
@@ -58,6 +58,10 @@ struct mptcp_info {
 	__u64	mptcpi_bytes_received;
 	__u64	mptcpi_bytes_acked;
 	__u8	mptcpi_subflows_total;
+	__u8	reserved[3];
+	__u32	mptcpi_last_data_sent;
+	__u32	mptcpi_last_data_recv;
+	__u32	mptcpi_last_ack_recv;
 };
 
 /* MPTCP Reset reason codes, rfc8684 */
diff --git a/original/uapi/linux/netdev.h b/original/uapi/linux/netdev.h
index bb65ee8..43742ac 100644
--- a/original/uapi/linux/netdev.h
+++ b/original/uapi/linux/netdev.h
@@ -146,6 +146,28 @@ enum {
 	NETDEV_A_QSTATS_TX_PACKETS,
 	NETDEV_A_QSTATS_TX_BYTES,
 	NETDEV_A_QSTATS_RX_ALLOC_FAIL,
+	NETDEV_A_QSTATS_RX_HW_DROPS,
+	NETDEV_A_QSTATS_RX_HW_DROP_OVERRUNS,
+	NETDEV_A_QSTATS_RX_CSUM_COMPLETE,
+	NETDEV_A_QSTATS_RX_CSUM_UNNECESSARY,
+	NETDEV_A_QSTATS_RX_CSUM_NONE,
+	NETDEV_A_QSTATS_RX_CSUM_BAD,
+	NETDEV_A_QSTATS_RX_HW_GRO_PACKETS,
+	NETDEV_A_QSTATS_RX_HW_GRO_BYTES,
+	NETDEV_A_QSTATS_RX_HW_GRO_WIRE_PACKETS,
+	NETDEV_A_QSTATS_RX_HW_GRO_WIRE_BYTES,
+	NETDEV_A_QSTATS_RX_HW_DROP_RATELIMITS,
+	NETDEV_A_QSTATS_TX_HW_DROPS,
+	NETDEV_A_QSTATS_TX_HW_DROP_ERRORS,
+	NETDEV_A_QSTATS_TX_CSUM_NONE,
+	NETDEV_A_QSTATS_TX_NEEDS_CSUM,
+	NETDEV_A_QSTATS_TX_HW_GSO_PACKETS,
+	NETDEV_A_QSTATS_TX_HW_GSO_BYTES,
+	NETDEV_A_QSTATS_TX_HW_GSO_WIRE_PACKETS,
+	NETDEV_A_QSTATS_TX_HW_GSO_WIRE_BYTES,
+	NETDEV_A_QSTATS_TX_HW_DROP_RATELIMITS,
+	NETDEV_A_QSTATS_TX_STOP,
+	NETDEV_A_QSTATS_TX_WAKE,
 
 	__NETDEV_A_QSTATS_MAX,
 	NETDEV_A_QSTATS_MAX = (__NETDEV_A_QSTATS_MAX - 1)
diff --git a/original/uapi/linux/nfs.h b/original/uapi/linux/nfs.h
index 946cb62..f356f2b 100644
--- a/original/uapi/linux/nfs.h
+++ b/original/uapi/linux/nfs.h
@@ -61,7 +61,6 @@
 	NFSERR_NOSPC = 28,		/* v2 v3 v4 */
 	NFSERR_ROFS = 30,		/* v2 v3 v4 */
 	NFSERR_MLINK = 31,		/*    v3 v4 */
-	NFSERR_OPNOTSUPP = 45,		/* v2 v3 */
 	NFSERR_NAMETOOLONG = 63,	/* v2 v3 v4 */
 	NFSERR_NOTEMPTY = 66,		/* v2 v3 v4 */
 	NFSERR_DQUOT = 69,		/* v2 v3 v4 */
diff --git a/original/uapi/linux/nfsd_netlink.h b/original/uapi/linux/nfsd_netlink.h
index 3cd044e..24c86db 100644
--- a/original/uapi/linux/nfsd_netlink.h
+++ b/original/uapi/linux/nfsd_netlink.h
@@ -29,8 +29,55 @@ enum {
 	NFSD_A_RPC_STATUS_MAX = (__NFSD_A_RPC_STATUS_MAX - 1)
 };
 
+enum {
+	NFSD_A_SERVER_THREADS = 1,
+	NFSD_A_SERVER_GRACETIME,
+	NFSD_A_SERVER_LEASETIME,
+	NFSD_A_SERVER_SCOPE,
+
+	__NFSD_A_SERVER_MAX,
+	NFSD_A_SERVER_MAX = (__NFSD_A_SERVER_MAX - 1)
+};
+
+enum {
+	NFSD_A_VERSION_MAJOR = 1,
+	NFSD_A_VERSION_MINOR,
+	NFSD_A_VERSION_ENABLED,
+
+	__NFSD_A_VERSION_MAX,
+	NFSD_A_VERSION_MAX = (__NFSD_A_VERSION_MAX - 1)
+};
+
+enum {
+	NFSD_A_SERVER_PROTO_VERSION = 1,
+
+	__NFSD_A_SERVER_PROTO_MAX,
+	NFSD_A_SERVER_PROTO_MAX = (__NFSD_A_SERVER_PROTO_MAX - 1)
+};
+
+enum {
+	NFSD_A_SOCK_ADDR = 1,
+	NFSD_A_SOCK_TRANSPORT_NAME,
+
+	__NFSD_A_SOCK_MAX,
+	NFSD_A_SOCK_MAX = (__NFSD_A_SOCK_MAX - 1)
+};
+
+enum {
+	NFSD_A_SERVER_SOCK_ADDR = 1,
+
+	__NFSD_A_SERVER_SOCK_MAX,
+	NFSD_A_SERVER_SOCK_MAX = (__NFSD_A_SERVER_SOCK_MAX - 1)
+};
+
 enum {
 	NFSD_CMD_RPC_STATUS_GET = 1,
+	NFSD_CMD_THREADS_SET,
+	NFSD_CMD_THREADS_GET,
+	NFSD_CMD_VERSION_SET,
+	NFSD_CMD_VERSION_GET,
+	NFSD_CMD_LISTENER_SET,
+	NFSD_CMD_LISTENER_GET,
 
 	__NFSD_CMD_MAX,
 	NFSD_CMD_MAX = (__NFSD_CMD_MAX - 1)
diff --git a/original/uapi/linux/nl80211.h b/original/uapi/linux/nl80211.h
index f23ecbd..f917bc6 100644
--- a/original/uapi/linux/nl80211.h
+++ b/original/uapi/linux/nl80211.h
@@ -413,8 +413,8 @@
  *	are like for %NL80211_CMD_SET_BEACON, and additionally parameters that
  *	do not change are used, these include %NL80211_ATTR_BEACON_INTERVAL,
  *	%NL80211_ATTR_DTIM_PERIOD, %NL80211_ATTR_SSID,
- *	%NL80211_ATTR_HIDDEN_SSID, %NL80211_ATTR_CIPHERS_PAIRWISE,
- *	%NL80211_ATTR_CIPHER_GROUP, %NL80211_ATTR_WPA_VERSIONS,
+ *	%NL80211_ATTR_HIDDEN_SSID, %NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
+ *	%NL80211_ATTR_CIPHER_SUITE_GROUP, %NL80211_ATTR_WPA_VERSIONS,
  *	%NL80211_ATTR_AKM_SUITES, %NL80211_ATTR_PRIVACY,
  *	%NL80211_ATTR_AUTH_TYPE, %NL80211_ATTR_INACTIVITY_TIMEOUT,
  *	%NL80211_ATTR_ACL_POLICY and %NL80211_ATTR_MAC_ADDRS.
@@ -442,20 +442,15 @@
  *	stations connected and using at least that link as one of its links.
  *
  * @NL80211_CMD_GET_MPATH: Get mesh path attributes for mesh path to
- * 	destination %NL80211_ATTR_MAC on the interface identified by
- * 	%NL80211_ATTR_IFINDEX.
+ *	destination %NL80211_ATTR_MAC on the interface identified by
+ *	%NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_SET_MPATH:  Set mesh path attributes for mesh path to
- * 	destination %NL80211_ATTR_MAC on the interface identified by
- * 	%NL80211_ATTR_IFINDEX.
+ *	destination %NL80211_ATTR_MAC on the interface identified by
+ *	%NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_NEW_MPATH: Create a new mesh path for the destination given by
  *	%NL80211_ATTR_MAC via %NL80211_ATTR_MPATH_NEXT_HOP.
  * @NL80211_CMD_DEL_MPATH: Delete a mesh path to the destination given by
  *	%NL80211_ATTR_MAC.
- * @NL80211_CMD_NEW_PATH: Add a mesh path with given attributes to the
- *	interface identified by %NL80211_ATTR_IFINDEX.
- * @NL80211_CMD_DEL_PATH: Remove a mesh path identified by %NL80211_ATTR_MAC
- *	or, if no MAC address given, all mesh paths, on the interface identified
- *	by %NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_SET_BSS: Set BSS attributes for BSS identified by
  *	%NL80211_ATTR_IFINDEX.
  *
@@ -476,15 +471,15 @@
  *	after being queried by the kernel. CRDA replies by sending a regulatory
  *	domain structure which consists of %NL80211_ATTR_REG_ALPHA set to our
  *	current alpha2 if it found a match. It also provides
- * 	NL80211_ATTR_REG_RULE_FLAGS, and a set of regulatory rules. Each
- * 	regulatory rule is a nested set of attributes  given by
- * 	%NL80211_ATTR_REG_RULE_FREQ_[START|END] and
- * 	%NL80211_ATTR_FREQ_RANGE_MAX_BW with an attached power rule given by
- * 	%NL80211_ATTR_REG_RULE_POWER_MAX_ANT_GAIN and
- * 	%NL80211_ATTR_REG_RULE_POWER_MAX_EIRP.
+ *	NL80211_ATTR_REG_RULE_FLAGS, and a set of regulatory rules. Each
+ *	regulatory rule is a nested set of attributes  given by
+ *	%NL80211_ATTR_REG_RULE_FREQ_[START|END] and
+ *	%NL80211_ATTR_FREQ_RANGE_MAX_BW with an attached power rule given by
+ *	%NL80211_ATTR_REG_RULE_POWER_MAX_ANT_GAIN and
+ *	%NL80211_ATTR_REG_RULE_POWER_MAX_EIRP.
  * @NL80211_CMD_REQ_SET_REG: ask the wireless core to set the regulatory domain
- * 	to the specified ISO/IEC 3166-1 alpha2 country code. The core will
- * 	store this as a valid request and then query userspace for it.
+ *	to the specified ISO/IEC 3166-1 alpha2 country code. The core will
+ *	store this as a valid request and then query userspace for it.
  *
  * @NL80211_CMD_GET_MESH_CONFIG: Get mesh networking properties for the
  *	interface identified by %NL80211_ATTR_IFINDEX
@@ -574,31 +569,31 @@
  * @NL80211_CMD_FLUSH_PMKSA: Flush all PMKSA cache entries.
  *
  * @NL80211_CMD_REG_CHANGE: indicates to userspace the regulatory domain
- * 	has been changed and provides details of the request information
- * 	that caused the change such as who initiated the regulatory request
- * 	(%NL80211_ATTR_REG_INITIATOR), the wiphy_idx
- * 	(%NL80211_ATTR_REG_ALPHA2) on which the request was made from if
- * 	the initiator was %NL80211_REGDOM_SET_BY_COUNTRY_IE or
- * 	%NL80211_REGDOM_SET_BY_DRIVER, the type of regulatory domain
- * 	set (%NL80211_ATTR_REG_TYPE), if the type of regulatory domain is
- * 	%NL80211_REG_TYPE_COUNTRY the alpha2 to which we have moved on
- * 	to (%NL80211_ATTR_REG_ALPHA2).
+ *	has been changed and provides details of the request information
+ *	that caused the change such as who initiated the regulatory request
+ *	(%NL80211_ATTR_REG_INITIATOR), the wiphy_idx
+ *	(%NL80211_ATTR_REG_ALPHA2) on which the request was made from if
+ *	the initiator was %NL80211_REGDOM_SET_BY_COUNTRY_IE or
+ *	%NL80211_REGDOM_SET_BY_DRIVER, the type of regulatory domain
+ *	set (%NL80211_ATTR_REG_TYPE), if the type of regulatory domain is
+ *	%NL80211_REG_TYPE_COUNTRY the alpha2 to which we have moved on
+ *	to (%NL80211_ATTR_REG_ALPHA2).
  * @NL80211_CMD_REG_BEACON_HINT: indicates to userspace that an AP beacon
- * 	has been found while world roaming thus enabling active scan or
- * 	any mode of operation that initiates TX (beacons) on a channel
- * 	where we would not have been able to do either before. As an example
- * 	if you are world roaming (regulatory domain set to world or if your
- * 	driver is using a custom world roaming regulatory domain) and while
- * 	doing a passive scan on the 5 GHz band you find an AP there (if not
- * 	on a DFS channel) you will now be able to actively scan for that AP
- * 	or use AP mode on your card on that same channel. Note that this will
- * 	never be used for channels 1-11 on the 2 GHz band as they are always
- * 	enabled world wide. This beacon hint is only sent if your device had
- * 	either disabled active scanning or beaconing on a channel. We send to
- * 	userspace the wiphy on which we removed a restriction from
- * 	(%NL80211_ATTR_WIPHY) and the channel on which this occurred
- * 	before (%NL80211_ATTR_FREQ_BEFORE) and after (%NL80211_ATTR_FREQ_AFTER)
- * 	the beacon hint was processed.
+ *	has been found while world roaming thus enabling active scan or
+ *	any mode of operation that initiates TX (beacons) on a channel
+ *	where we would not have been able to do either before. As an example
+ *	if you are world roaming (regulatory domain set to world or if your
+ *	driver is using a custom world roaming regulatory domain) and while
+ *	doing a passive scan on the 5 GHz band you find an AP there (if not
+ *	on a DFS channel) you will now be able to actively scan for that AP
+ *	or use AP mode on your card on that same channel. Note that this will
+ *	never be used for channels 1-11 on the 2 GHz band as they are always
+ *	enabled world wide. This beacon hint is only sent if your device had
+ *	either disabled active scanning or beaconing on a channel. We send to
+ *	userspace the wiphy on which we removed a restriction from
+ *	(%NL80211_ATTR_WIPHY) and the channel on which this occurred
+ *	before (%NL80211_ATTR_FREQ_BEFORE) and after (%NL80211_ATTR_FREQ_AFTER)
+ *	the beacon hint was processed.
  *
  * @NL80211_CMD_AUTHENTICATE: authentication request and notification.
  *	This command is used both as a command (request to authenticate) and
@@ -1120,7 +1115,7 @@
  *	current configuration is not changed.  If it is present but
  *	set to zero, the configuration is changed to don't-care
  *	(i.e. the device can decide what to do).
- * @NL80211_CMD_NAN_FUNC_MATCH: Notification sent when a match is reported.
+ * @NL80211_CMD_NAN_MATCH: Notification sent when a match is reported.
  *	This will contain a %NL80211_ATTR_NAN_MATCH nested attribute and
  *	%NL80211_ATTR_COOKIE.
  *
@@ -1715,21 +1710,21 @@ enum nl80211_commands {
  *	(see &enum nl80211_plink_action).
  * @NL80211_ATTR_MPATH_NEXT_HOP: MAC address of the next hop for a mesh path.
  * @NL80211_ATTR_MPATH_INFO: information about a mesh_path, part of mesh path
- * 	info given for %NL80211_CMD_GET_MPATH, nested attribute described at
+ *	info given for %NL80211_CMD_GET_MPATH, nested attribute described at
  *	&enum nl80211_mpath_info.
  *
  * @NL80211_ATTR_MNTR_FLAGS: flags, nested element with NLA_FLAG attributes of
  *      &enum nl80211_mntr_flags.
  *
  * @NL80211_ATTR_REG_ALPHA2: an ISO-3166-alpha2 country code for which the
- * 	current regulatory domain should be set to or is already set to.
- * 	For example, 'CR', for Costa Rica. This attribute is used by the kernel
- * 	to query the CRDA to retrieve one regulatory domain. This attribute can
- * 	also be used by userspace to query the kernel for the currently set
- * 	regulatory domain. We chose an alpha2 as that is also used by the
- * 	IEEE-802.11 country information element to identify a country.
- * 	Users can also simply ask the wireless core to set regulatory domain
- * 	to a specific alpha2.
+ *	current regulatory domain should be set to or is already set to.
+ *	For example, 'CR', for Costa Rica. This attribute is used by the kernel
+ *	to query the CRDA to retrieve one regulatory domain. This attribute can
+ *	also be used by userspace to query the kernel for the currently set
+ *	regulatory domain. We chose an alpha2 as that is also used by the
+ *	IEEE-802.11 country information element to identify a country.
+ *	Users can also simply ask the wireless core to set regulatory domain
+ *	to a specific alpha2.
  * @NL80211_ATTR_REG_RULES: a nested array of regulatory domain regulatory
  *	rules.
  *
@@ -1772,9 +1767,9 @@ enum nl80211_commands {
  * @NL80211_ATTR_BSS: scan result BSS
  *
  * @NL80211_ATTR_REG_INITIATOR: indicates who requested the regulatory domain
- * 	currently in effect. This could be any of the %NL80211_REGDOM_SET_BY_*
+ *	currently in effect. This could be any of the %NL80211_REGDOM_SET_BY_*
  * @NL80211_ATTR_REG_TYPE: indicates the type of the regulatory domain currently
- * 	set. This can be one of the nl80211_reg_type (%NL80211_REGDOM_TYPE_*)
+ *	set. This can be one of the nl80211_reg_type (%NL80211_REGDOM_TYPE_*)
  *
  * @NL80211_ATTR_SUPPORTED_COMMANDS: wiphy attribute that specifies
  *	an array of command numbers (i.e. a mapping index to command number)
@@ -1793,15 +1788,15 @@ enum nl80211_commands {
  *	a u32
  *
  * @NL80211_ATTR_FREQ_BEFORE: A channel which has suffered a regulatory change
- * 	due to considerations from a beacon hint. This attribute reflects
- * 	the state of the channel _before_ the beacon hint processing. This
- * 	attributes consists of a nested attribute containing
- * 	NL80211_FREQUENCY_ATTR_*
+ *	due to considerations from a beacon hint. This attribute reflects
+ *	the state of the channel _before_ the beacon hint processing. This
+ *	attributes consists of a nested attribute containing
+ *	NL80211_FREQUENCY_ATTR_*
  * @NL80211_ATTR_FREQ_AFTER: A channel which has suffered a regulatory change
- * 	due to considerations from a beacon hint. This attribute reflects
- * 	the state of the channel _after_ the beacon hint processing. This
- * 	attributes consists of a nested attribute containing
- * 	NL80211_FREQUENCY_ATTR_*
+ *	due to considerations from a beacon hint. This attribute reflects
+ *	the state of the channel _after_ the beacon hint processing. This
+ *	attributes consists of a nested attribute containing
+ *	NL80211_FREQUENCY_ATTR_*
  *
  * @NL80211_ATTR_CIPHER_SUITES: a set of u32 values indicating the supported
  *	cipher suites
@@ -1862,12 +1857,6 @@ enum nl80211_commands {
  *	that protected APs should be used. This is also used with NEW_BEACON to
  *	indicate that the BSS is to use protection.
  *
- * @NL80211_ATTR_CIPHERS_PAIRWISE: Used with CONNECT, ASSOCIATE, and NEW_BEACON
- *	to indicate which unicast key ciphers will be used with the connection
- *	(an array of u32).
- * @NL80211_ATTR_CIPHER_GROUP: Used with CONNECT, ASSOCIATE, and NEW_BEACON to
- *	indicate which group key cipher will be used with the connection (a
- *	u32).
  * @NL80211_ATTR_WPA_VERSIONS: Used with CONNECT, ASSOCIATE, and NEW_BEACON to
  *	indicate which WPA version(s) the AP we want to associate with is using
  *	(a u32 with flags from &enum nl80211_wpa_versions).
@@ -1898,6 +1887,7 @@ enum nl80211_commands {
  *	with %NL80211_KEY_* sub-attributes
  *
  * @NL80211_ATTR_PID: Process ID of a network namespace.
+ * @NL80211_ATTR_NETNS_FD: File descriptor of a network namespace.
  *
  * @NL80211_ATTR_GENERATION: Used to indicate consistent snapshots for
  *	dumps. This number increases whenever the object list being
@@ -1952,6 +1942,7 @@ enum nl80211_commands {
  *
  * @NL80211_ATTR_ACK: Flag attribute indicating that the frame was
  *	acknowledged by the recipient.
+ * @NL80211_ATTR_ACK_SIGNAL: Station's ack signal strength (s32)
  *
  * @NL80211_ATTR_PS_STATE: powersave state, using &enum nl80211_ps_state values.
  *
@@ -2149,6 +2140,9 @@ enum nl80211_commands {
  * @NL80211_ATTR_DISABLE_HE: Force HE capable interfaces to disable
  *      this feature during association. This is a flag attribute.
  *	Currently only supported in mac80211 drivers.
+ * @NL80211_ATTR_DISABLE_EHT: Force EHT capable interfaces to disable
+ *      this feature during association. This is a flag attribute.
+ *	Currently only supported in mac80211 drivers.
  * @NL80211_ATTR_HT_CAPABILITY_MASK: Specify which bits of the
  *      ATTR_HT_CAPABILITY to which attention should be paid.
  *      Currently, only mac80211 NICs support this feature.
@@ -2158,6 +2152,12 @@ enum nl80211_commands {
  *      All values are treated as suggestions and may be ignored
  *      by the driver as required.  The actual values may be seen in
  *      the station debugfs ht_caps file.
+ * @NL80211_ATTR_VHT_CAPABILITY_MASK: Specify which bits of the
+ *      ATTR_VHT_CAPABILITY to which attention should be paid.
+ *      Currently, only mac80211 NICs support this feature.
+ *      All values are treated as suggestions and may be ignored
+ *      by the driver as required.  The actual values may be seen in
+ *      the station debugfs vht_caps file.
  *
  * @NL80211_ATTR_DFS_REGION: region for regulatory rules which this country
  *    abides to when initiating radiation on DFS channels. A country maps
@@ -2416,7 +2416,7 @@ enum nl80211_commands {
  *	scheduled scan is started.  Or the delay before a WoWLAN
  *	net-detect scan is started, counting from the moment the
  *	system is suspended.  This value is a u32, in seconds.
-
+ *
  * @NL80211_ATTR_REG_INDOOR: flag attribute, if set indicates that the device
  *      is operating in an indoor environment.
  *
@@ -3565,7 +3565,7 @@ enum nl80211_sta_flags {
  * enum nl80211_sta_p2p_ps_status - station support of P2P PS
  *
  * @NL80211_P2P_PS_UNSUPPORTED: station doesn't support P2P PS mechanism
- * @@NL80211_P2P_PS_SUPPORTED: station supports P2P PS mechanism
+ * @NL80211_P2P_PS_SUPPORTED: station supports P2P PS mechanism
  * @NUM_NL80211_P2P_PS_STATUS: number of values
  */
 enum nl80211_sta_p2p_ps_status {
@@ -3603,9 +3603,9 @@ enum nl80211_he_gi {
 
 /**
  * enum nl80211_he_ltf - HE long training field
- * @NL80211_RATE_INFO_HE_1xLTF: 3.2 usec
- * @NL80211_RATE_INFO_HE_2xLTF: 6.4 usec
- * @NL80211_RATE_INFO_HE_4xLTF: 12.8 usec
+ * @NL80211_RATE_INFO_HE_1XLTF: 3.2 usec
+ * @NL80211_RATE_INFO_HE_2XLTF: 6.4 usec
+ * @NL80211_RATE_INFO_HE_4XLTF: 12.8 usec
  */
 enum nl80211_he_ltf {
 	NL80211_RATE_INFO_HE_1XLTF,
@@ -3720,7 +3720,7 @@ enum nl80211_eht_ru_alloc {
  * @NL80211_RATE_INFO_HE_GI: HE guard interval identifier
  *	(u8, see &enum nl80211_he_gi)
  * @NL80211_RATE_INFO_HE_DCM: HE DCM value (u8, 0/1)
- * @NL80211_RATE_INFO_RU_ALLOC: HE RU allocation, if not present then
+ * @NL80211_RATE_INFO_HE_RU_ALLOC: HE RU allocation, if not present then
  *	non-OFDMA was used (u8, see &enum nl80211_he_ru_alloc)
  * @NL80211_RATE_INFO_320_MHZ_WIDTH: 320 MHz bitrate
  * @NL80211_RATE_INFO_EHT_MCS: EHT MCS index (u8, 0-15)
@@ -3823,7 +3823,7 @@ enum nl80211_sta_bss_param {
  *	(u64, to this station)
  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
  * @NL80211_STA_INFO_TX_BITRATE: current unicast tx rate, nested attribute
- * 	containing info as possible, see &enum nl80211_rate_info
+ *	containing info as possible, see &enum nl80211_rate_info
  * @NL80211_STA_INFO_RX_PACKETS: total received packet (MSDUs and MMPDUs)
  *	(u32, from this station)
  * @NL80211_STA_INFO_TX_PACKETS: total transmitted packets (MSDUs and MMPDUs)
@@ -3852,8 +3852,8 @@ enum nl80211_sta_bss_param {
  *	Contains a nested array of signal strength attributes (u8, dBm)
  * @NL80211_STA_INFO_CHAIN_SIGNAL_AVG: per-chain signal strength average
  *	Same format as NL80211_STA_INFO_CHAIN_SIGNAL.
- * @NL80211_STA_EXPECTED_THROUGHPUT: expected throughput considering also the
- *	802.11 header (u32, kbps)
+ * @NL80211_STA_INFO_EXPECTED_THROUGHPUT: expected throughput considering also
+ *	the 802.11 header (u32, kbps)
  * @NL80211_STA_INFO_RX_DROP_MISC: RX packets dropped for unspecified reasons
  *	(u64)
  * @NL80211_STA_INFO_BEACON_RX: number of beacons received from this peer (u64)
@@ -4039,7 +4039,7 @@ enum nl80211_mpath_flags {
  * @NL80211_MPATH_INFO_METRIC: metric (cost) of this mesh path
  * @NL80211_MPATH_INFO_EXPTIME: expiration time for the path, in msec from now
  * @NL80211_MPATH_INFO_FLAGS: mesh path flags, enumerated in
- * 	&enum nl80211_mpath_flags;
+ *	&enum nl80211_mpath_flags;
  * @NL80211_MPATH_INFO_DISCOVERY_TIMEOUT: total path discovery timeout, in msec
  * @NL80211_MPATH_INFO_DISCOVERY_RETRIES: mesh path discovery retries
  * @NL80211_MPATH_INFO_HOP_COUNT: hop count to destination
@@ -4179,7 +4179,7 @@ enum nl80211_band_attr {
  * @NL80211_WMMR_CW_MAX: Maximum contention window slot.
  * @NL80211_WMMR_AIFSN: Arbitration Inter Frame Space.
  * @NL80211_WMMR_TXOP: Maximum allowed tx operation time.
- * @nl80211_WMMR_MAX: highest possible wmm rule.
+ * @NL80211_WMMR_MAX: highest possible wmm rule.
  * @__NL80211_WMMR_LAST: Internal use.
  */
 enum nl80211_wmm_rule {
@@ -4201,8 +4201,9 @@ enum nl80211_wmm_rule {
  * @NL80211_FREQUENCY_ATTR_DISABLED: Channel is disabled in current
  *	regulatory domain.
  * @NL80211_FREQUENCY_ATTR_NO_IR: no mechanisms that initiate radiation
- * 	are permitted on this channel, this includes sending probe
- * 	requests, or modes of operation that require beaconing.
+ *	are permitted on this channel, this includes sending probe
+ *	requests, or modes of operation that require beaconing.
+ * @__NL80211_FREQUENCY_ATTR_NO_IBSS: obsolete, same as _NO_IR
  * @NL80211_FREQUENCY_ATTR_RADAR: Radar detection is mandatory
  *	on this channel in current regulatory domain.
  * @NL80211_FREQUENCY_ATTR_MAX_TX_POWER: Maximum transmission power in mBm
@@ -4357,16 +4358,16 @@ enum nl80211_bitrate_attr {
 };
 
 /**
- * enum nl80211_initiator - Indicates the initiator of a reg domain request
+ * enum nl80211_reg_initiator - Indicates the initiator of a reg domain request
  * @NL80211_REGDOM_SET_BY_CORE: Core queried CRDA for a dynamic world
- * 	regulatory domain.
+ *	regulatory domain.
  * @NL80211_REGDOM_SET_BY_USER: User asked the wireless core to set the
- * 	regulatory domain.
+ *	regulatory domain.
  * @NL80211_REGDOM_SET_BY_DRIVER: a wireless drivers has hinted to the
- * 	wireless core it thinks its knows the regulatory domain we should be in.
+ *	wireless core it thinks its knows the regulatory domain we should be in.
  * @NL80211_REGDOM_SET_BY_COUNTRY_IE: the wireless core has received an
- * 	802.11 country information element with regulatory information it
- * 	thinks we should consider. cfg80211 only processes the country
+ *	802.11 country information element with regulatory information it
+ *	thinks we should consider. cfg80211 only processes the country
  *	code from the IE, and relies on the regulatory domain information
  *	structure passed by userspace (CRDA) from our wireless-regdb.
  *	If a channel is enabled but the country code indicates it should
@@ -4385,11 +4386,11 @@ enum nl80211_reg_initiator {
  *	to a specific country. When this is set you can count on the
  *	ISO / IEC 3166 alpha2 country code being valid.
  * @NL80211_REGDOM_TYPE_WORLD: the regulatory set domain is the world regulatory
- * 	domain.
+ *	domain.
  * @NL80211_REGDOM_TYPE_CUSTOM_WORLD: the regulatory domain set is a custom
- * 	driver specific world regulatory domain. These do not apply system-wide
- * 	and are only applicable to the individual devices which have requested
- * 	them to be applied.
+ *	driver specific world regulatory domain. These do not apply system-wide
+ *	and are only applicable to the individual devices which have requested
+ *	them to be applied.
  * @NL80211_REGDOM_TYPE_INTERSECTION: the regulatory domain set is the product
  *	of an intersection between two regulatory domains -- the previously
  *	set regulatory domain on the system and the last accepted regulatory
@@ -4406,21 +4407,21 @@ enum nl80211_reg_type {
  * enum nl80211_reg_rule_attr - regulatory rule attributes
  * @__NL80211_REG_RULE_ATTR_INVALID: attribute number 0 is reserved
  * @NL80211_ATTR_REG_RULE_FLAGS: a set of flags which specify additional
- * 	considerations for a given frequency range. These are the
- * 	&enum nl80211_reg_rule_flags.
+ *	considerations for a given frequency range. These are the
+ *	&enum nl80211_reg_rule_flags.
  * @NL80211_ATTR_FREQ_RANGE_START: starting frequencry for the regulatory
- * 	rule in KHz. This is not a center of frequency but an actual regulatory
- * 	band edge.
+ *	rule in KHz. This is not a center of frequency but an actual regulatory
+ *	band edge.
  * @NL80211_ATTR_FREQ_RANGE_END: ending frequency for the regulatory rule
- * 	in KHz. This is not a center a frequency but an actual regulatory
- * 	band edge.
+ *	in KHz. This is not a center a frequency but an actual regulatory
+ *	band edge.
  * @NL80211_ATTR_FREQ_RANGE_MAX_BW: maximum allowed bandwidth for this
  *	frequency range, in KHz.
  * @NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN: the maximum allowed antenna gain
- * 	for a given frequency range. The value is in mBi (100 * dBi).
- * 	If you don't have one then don't send this.
+ *	for a given frequency range. The value is in mBi (100 * dBi).
+ *	If you don't have one then don't send this.
  * @NL80211_ATTR_POWER_RULE_MAX_EIRP: the maximum allowed EIRP for
- * 	a given frequency range. The value is in mBm (100 * dBm).
+ *	a given frequency range. The value is in mBm (100 * dBm).
  * @NL80211_ATTR_DFS_CAC_TIME: DFS CAC time in milliseconds.
  *	If not present or 0 default CAC time will be used.
  * @NL80211_ATTR_POWER_RULE_PSD: power spectral density (in dBm).
@@ -4507,8 +4508,9 @@ enum nl80211_sched_scan_match_attr {
  * @NL80211_RRF_PTP_ONLY: this is only for Point To Point links
  * @NL80211_RRF_PTMP_ONLY: this is only for Point To Multi Point links
  * @NL80211_RRF_NO_IR: no mechanisms that initiate radiation are allowed,
- * 	this includes probe requests or modes of operation that require
- * 	beaconing.
+ *	this includes probe requests or modes of operation that require
+ *	beaconing.
+ * @__NL80211_RRF_NO_IBSS: obsolete, same as NO_IR
  * @NL80211_RRF_AUTO_BW: maximum available bandwidth should be calculated
  *	base on contiguous rules and wider channels will be allowed to cross
  *	multiple contiguous/overlapping frequency ranges.
@@ -4522,9 +4524,9 @@ enum nl80211_sched_scan_match_attr {
  * @NL80211_RRF_NO_EHT: EHT operation not allowed
  * @NL80211_RRF_PSD: Ruleset has power spectral density value
  * @NL80211_RRF_DFS_CONCURRENT: Operation on this channel is allowed for
-	peer-to-peer or adhoc communication under the control of a DFS master
-	which operates on the same channel (FCC-594280 D01 Section B.3).
-	Should be used together with %NL80211_RRF_DFS only.
+ *	peer-to-peer or adhoc communication under the control of a DFS master
+ *	which operates on the same channel (FCC-594280 D01 Section B.3).
+ *	Should be used together with %NL80211_RRF_DFS only.
  * @NL80211_RRF_NO_6GHZ_VLP_CLIENT: Client connection to VLP AP not allowed
  * @NL80211_RRF_NO_6GHZ_AFC_CLIENT: Client connection to AFC AP not allowed
  */
@@ -4707,8 +4709,8 @@ enum nl80211_mntr_flags {
  *	alternate between Active and Doze states, but may not wake up
  *	for neighbor's beacons.
  *
- * @__NL80211_MESH_POWER_AFTER_LAST - internal use
- * @NL80211_MESH_POWER_MAX - highest possible power save level
+ * @__NL80211_MESH_POWER_AFTER_LAST: internal use
+ * @NL80211_MESH_POWER_MAX: highest possible power save level
  */
 
 enum nl80211_mesh_power_mode {
@@ -5728,7 +5730,7 @@ struct nl80211_pattern_support {
  *	"TCP connection wakeup" for more details. This is a nested attribute
  *	containing the exact information for establishing and keeping alive
  *	the TCP connection.
- * @NL80211_WOWLAN_TRIG_TCP_WAKEUP_MATCH: For wakeup reporting only, the
+ * @NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH: For wakeup reporting only, the
  *	wakeup packet was received on the TCP connection
  * @NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST: For wakeup reporting only, the
  *	TCP connection was lost or failed to be established
@@ -6077,7 +6079,7 @@ enum nl80211_plink_state {
  * @NL80211_PLINK_ACTION_BLOCK: block traffic from this mesh peer
  * @NUM_NL80211_PLINK_ACTIONS: number of possible actions
  */
-enum plink_actions {
+enum nl80211_plink_action {
 	NL80211_PLINK_ACTION_NO_ACTION,
 	NL80211_PLINK_ACTION_OPEN,
 	NL80211_PLINK_ACTION_BLOCK,
@@ -6404,6 +6406,7 @@ enum nl80211_feature_flags {
  *	receiving control port frames over nl80211 instead of the netdevice.
  * @NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT: This driver/device supports
  *	(average) ACK signal strength reporting.
+ * @NL80211_EXT_FEATURE_DATA_ACK_SIGNAL_SUPPORT: Backward-compatible ID
  * @NL80211_EXT_FEATURE_TXQS: Driver supports FQ-CoDel-enabled intermediate
  *      TXQs.
  * @NL80211_EXT_FEATURE_SCAN_RANDOM_SN: Driver/device supports randomizing the
@@ -6787,6 +6790,8 @@ enum nl80211_acl_policy {
  * @NL80211_SMPS_STATIC: static SMPS (use a single antenna)
  * @NL80211_SMPS_DYNAMIC: dynamic smps (start with a single antenna and
  *	turn on other antennas after CTS/RTS).
+ * @__NL80211_SMPS_AFTER_LAST: internal
+ * @NL80211_SMPS_MAX: highest used enumeration
  */
 enum nl80211_smps_mode {
 	NL80211_SMPS_OFF,
@@ -7008,6 +7013,8 @@ enum nl80211_bss_select_attr {
  * @NL80211_NAN_FUNC_PUBLISH: function is publish
  * @NL80211_NAN_FUNC_SUBSCRIBE: function is subscribe
  * @NL80211_NAN_FUNC_FOLLOW_UP: function is follow-up
+ * @__NL80211_NAN_FUNC_TYPE_AFTER_LAST: internal use
+ * @NL80211_NAN_FUNC_MAX_TYPE: internal use
  */
 enum nl80211_nan_function_type {
 	NL80211_NAN_FUNC_PUBLISH,
@@ -7168,7 +7175,7 @@ enum nl80211_nan_match_attributes {
 };
 
 /**
- * nl80211_external_auth_action - Action to perform with external
+ * enum nl80211_external_auth_action - Action to perform with external
  *     authentication request. Used by NL80211_ATTR_EXTERNAL_AUTH_ACTION.
  * @NL80211_EXTERNAL_AUTH_START: Start the authentication.
  * @NL80211_EXTERNAL_AUTH_ABORT: Abort the ongoing authentication.
@@ -7186,7 +7193,7 @@ enum nl80211_external_auth_action {
  * @NL80211_FTM_RESP_ATTR_LCI: The content of Measurement Report Element
  *	(9.4.2.22 in 802.11-2016) with type 8 - LCI (9.4.2.22.10),
  *	i.e. starting with the measurement token
- * @NL80211_FTM_RESP_ATTR_CIVIC: The content of Measurement Report Element
+ * @NL80211_FTM_RESP_ATTR_CIVICLOC: The content of Measurement Report Element
  *	(9.4.2.22 in 802.11-2016) with type 11 - Civic (Section 9.4.2.22.13),
  *	i.e. starting with the measurement token
  * @__NL80211_FTM_RESP_ATTR_LAST: Internal
@@ -7829,6 +7836,7 @@ enum nl80211_sae_pwe_mechanism {
  *
  * @NL80211_SAR_TYPE_POWER: power limitation specified in 0.25dBm unit
  *
+ * @NUM_NL80211_SAR_TYPE: internal
  */
 enum nl80211_sar_type {
 	NL80211_SAR_TYPE_POWER,
@@ -7842,6 +7850,8 @@ enum nl80211_sar_type {
 /**
  * enum nl80211_sar_attrs - Attributes for SAR spec
  *
+ * @__NL80211_SAR_ATTR_INVALID: Invalid
+ *
  * @NL80211_SAR_ATTR_TYPE: the SAR type as defined in &enum nl80211_sar_type.
  *
  * @NL80211_SAR_ATTR_SPECS: Nested array of SAR power
@@ -7873,6 +7883,8 @@ enum nl80211_sar_attrs {
 /**
  * enum nl80211_sar_specs_attrs - Attributes for SAR power limit specs
  *
+ * @__NL80211_SAR_ATTR_SPECS_INVALID: Invalid
+ *
  * @NL80211_SAR_ATTR_SPECS_POWER: Required (s32)value to specify the actual
  *	power limit value in units of 0.25 dBm if type is
  *	NL80211_SAR_TYPE_POWER. (i.e., a value of 44 represents 11 dBm).
diff --git a/original/uapi/linux/ntsync.h b/original/uapi/linux/ntsync.h
new file mode 100644
index 0000000..dcfa38f
--- /dev/null
+++ b/original/uapi/linux/ntsync.h
@@ -0,0 +1,23 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * Kernel support for NT synchronization primitive emulation
+ *
+ * Copyright (C) 2021-2022 Elizabeth Figura <zfigura@codeweavers.com>
+ */
+
+#ifndef __LINUX_NTSYNC_H
+#define __LINUX_NTSYNC_H
+
+#include <linux/types.h>
+
+struct ntsync_sem_args {
+	__u32 sem;
+	__u32 count;
+	__u32 max;
+};
+
+#define NTSYNC_IOC_CREATE_SEM		_IOWR('N', 0x80, struct ntsync_sem_args)
+
+#define NTSYNC_IOC_SEM_POST		_IOWR('N', 0x81, __u32)
+
+#endif
diff --git a/original/uapi/linux/papr_pdsm.h b/original/uapi/linux/papr_pdsm.h
new file mode 100644
index 0000000..1743992
--- /dev/null
+++ b/original/uapi/linux/papr_pdsm.h
@@ -0,0 +1,165 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * PAPR nvDimm Specific Methods (PDSM) and structs for libndctl
+ *
+ * (C) Copyright IBM 2020
+ *
+ * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
+ */
+
+#ifndef _UAPI_ASM_POWERPC_PAPR_PDSM_H_
+#define _UAPI_ASM_POWERPC_PAPR_PDSM_H_
+
+#include <linux/types.h>
+#include <linux/ndctl.h>
+
+/*
+ * PDSM Envelope:
+ *
+ * The ioctl ND_CMD_CALL exchange data between user-space and kernel via
+ * envelope which consists of 2 headers sections and payload sections as
+ * illustrated below:
+ *  +-----------------+---------------+---------------------------+
+ *  |   64-Bytes      |   8-Bytes     |       Max 184-Bytes       |
+ *  +-----------------+---------------+---------------------------+
+ *  | ND-HEADER       |  PDSM-HEADER  |      PDSM-PAYLOAD         |
+ *  +-----------------+---------------+---------------------------+
+ *  | nd_family       |               |                           |
+ *  | nd_size_out     | cmd_status    |                           |
+ *  | nd_size_in      | reserved      |     nd_pdsm_payload       |
+ *  | nd_command      | payload   --> |                           |
+ *  | nd_fw_size      |               |                           |
+ *  | nd_payload ---> |               |                           |
+ *  +---------------+-----------------+---------------------------+
+ *
+ * ND Header:
+ * This is the generic libnvdimm header described as 'struct nd_cmd_pkg'
+ * which is interpreted by libnvdimm before passed on to papr_scm. Important
+ * member fields used are:
+ * 'nd_family'		: (In) NVDIMM_FAMILY_PAPR_SCM
+ * 'nd_size_in'		: (In) PDSM-HEADER + PDSM-IN-PAYLOAD (usually 0)
+ * 'nd_size_out'        : (In) PDSM-HEADER + PDSM-RETURN-PAYLOAD
+ * 'nd_command'         : (In) One of PAPR_PDSM_XXX
+ * 'nd_fw_size'         : (Out) PDSM-HEADER + size of actual payload returned
+ *
+ * PDSM Header:
+ * This is papr-scm specific header that precedes the payload. This is defined
+ * as nd_cmd_pdsm_pkg.  Following fields aare available in this header:
+ *
+ * 'cmd_status'		: (Out) Errors if any encountered while servicing PDSM.
+ * 'reserved'		: Not used, reserved for future and should be set to 0.
+ * 'payload'            : A union of all the possible payload structs
+ *
+ * PDSM Payload:
+ *
+ * The layout of the PDSM Payload is defined by various structs shared between
+ * papr_scm and libndctl so that contents of payload can be interpreted. As such
+ * its defined as a union of all possible payload structs as
+ * 'union nd_pdsm_payload'. Based on the value of 'nd_cmd_pkg.nd_command'
+ * appropriate member of the union is accessed.
+ */
+
+/* Max payload size that we can handle */
+#define ND_PDSM_PAYLOAD_MAX_SIZE 184
+
+/* Max payload size that we can handle */
+#define ND_PDSM_HDR_SIZE \
+	(sizeof(struct nd_pkg_pdsm) - ND_PDSM_PAYLOAD_MAX_SIZE)
+
+/* Various nvdimm health indicators */
+#define PAPR_PDSM_DIMM_HEALTHY       0
+#define PAPR_PDSM_DIMM_UNHEALTHY     1
+#define PAPR_PDSM_DIMM_CRITICAL      2
+#define PAPR_PDSM_DIMM_FATAL         3
+
+/* struct nd_papr_pdsm_health.extension_flags field flags */
+
+/* Indicate that the 'dimm_fuel_gauge' field is valid */
+#define PDSM_DIMM_HEALTH_RUN_GAUGE_VALID 1
+
+/* Indicate that the 'dimm_dsc' field is valid */
+#define PDSM_DIMM_DSC_VALID 2
+
+/*
+ * Struct exchanged between kernel & ndctl in for PAPR_PDSM_HEALTH
+ * Various flags indicate the health status of the dimm.
+ *
+ * extension_flags	: Any extension fields present in the struct.
+ * dimm_unarmed		: Dimm not armed. So contents wont persist.
+ * dimm_bad_shutdown	: Previous shutdown did not persist contents.
+ * dimm_bad_restore	: Contents from previous shutdown werent restored.
+ * dimm_scrubbed	: Contents of the dimm have been scrubbed.
+ * dimm_locked		: Contents of the dimm cant be modified until CEC reboot
+ * dimm_encrypted	: Contents of dimm are encrypted.
+ * dimm_health		: Dimm health indicator. One of PAPR_PDSM_DIMM_XXXX
+ * dimm_fuel_gauge	: Life remaining of DIMM as a percentage from 0-100
+ */
+struct nd_papr_pdsm_health {
+	union {
+		struct {
+			__u32 extension_flags;
+			__u8 dimm_unarmed;
+			__u8 dimm_bad_shutdown;
+			__u8 dimm_bad_restore;
+			__u8 dimm_scrubbed;
+			__u8 dimm_locked;
+			__u8 dimm_encrypted;
+			__u16 dimm_health;
+
+			/* Extension flag PDSM_DIMM_HEALTH_RUN_GAUGE_VALID */
+			__u16 dimm_fuel_gauge;
+
+			/* Extension flag PDSM_DIMM_DSC_VALID */
+			__u64 dimm_dsc;
+		};
+		__u8 buf[ND_PDSM_PAYLOAD_MAX_SIZE];
+	};
+};
+
+/* Flags for injecting specific smart errors */
+#define PDSM_SMART_INJECT_HEALTH_FATAL		(1 << 0)
+#define PDSM_SMART_INJECT_BAD_SHUTDOWN		(1 << 1)
+
+struct nd_papr_pdsm_smart_inject {
+	union {
+		struct {
+			/* One or more of PDSM_SMART_INJECT_ */
+			__u32 flags;
+			__u8 fatal_enable;
+			__u8 unsafe_shutdown_enable;
+		};
+		__u8 buf[ND_PDSM_PAYLOAD_MAX_SIZE];
+	};
+};
+
+/*
+ * Methods to be embedded in ND_CMD_CALL request. These are sent to the kernel
+ * via 'nd_cmd_pkg.nd_command' member of the ioctl struct
+ */
+enum papr_pdsm {
+	PAPR_PDSM_MIN = 0x0,
+	PAPR_PDSM_HEALTH,
+	PAPR_PDSM_SMART_INJECT,
+	PAPR_PDSM_MAX,
+};
+
+/* Maximal union that can hold all possible payload types */
+union nd_pdsm_payload {
+	struct nd_papr_pdsm_health health;
+	struct nd_papr_pdsm_smart_inject smart_inject;
+	__u8 buf[ND_PDSM_PAYLOAD_MAX_SIZE];
+} __packed;
+
+/*
+ * PDSM-header + payload expected with ND_CMD_CALL ioctl from libnvdimm
+ * Valid member of union 'payload' is identified via 'nd_cmd_pkg.nd_command'
+ * that should always precede this struct when sent to papr_scm via CMD_CALL
+ * interface.
+ */
+struct nd_pkg_pdsm {
+	__s32 cmd_status;	/* Out: Sub-cmd status returned back */
+	__u16 reserved[2];	/* Ignored and to be set as '0' */
+	union nd_pdsm_payload payload;
+} __packed;
+
+#endif /* _UAPI_ASM_POWERPC_PAPR_PDSM_H_ */
diff --git a/original/uapi/linux/pci_regs.h b/original/uapi/linux/pci_regs.h
index a391932..94c0099 100644
--- a/original/uapi/linux/pci_regs.h
+++ b/original/uapi/linux/pci_regs.h
@@ -1144,8 +1144,14 @@
 #define PCI_DOE_DATA_OBJECT_HEADER_2_LENGTH		0x0003ffff
 
 #define PCI_DOE_DATA_OBJECT_DISC_REQ_3_INDEX		0x000000ff
+#define PCI_DOE_DATA_OBJECT_DISC_REQ_3_VER		0x0000ff00
 #define PCI_DOE_DATA_OBJECT_DISC_RSP_3_VID		0x0000ffff
 #define PCI_DOE_DATA_OBJECT_DISC_RSP_3_PROTOCOL		0x00ff0000
 #define PCI_DOE_DATA_OBJECT_DISC_RSP_3_NEXT_INDEX	0xff000000
 
+/* Compute Express Link (CXL r3.1, sec 8.1.5) */
+#define PCI_DVSEC_CXL_PORT				3
+#define PCI_DVSEC_CXL_PORT_CTL				0x0c
+#define PCI_DVSEC_CXL_PORT_CTL_UNMASK_SBR		0x00000001
+
 #endif /* LINUX_PCI_REGS_H */
diff --git a/original/uapi/linux/pkt_cls.h b/original/uapi/linux/pkt_cls.h
index ea27703..229fc92 100644
--- a/original/uapi/linux/pkt_cls.h
+++ b/original/uapi/linux/pkt_cls.h
@@ -587,6 +587,10 @@ enum {
 					 * TCA_FLOWER_KEY_ENC_OPT_GTP_
 					 * attributes
 					 */
+	TCA_FLOWER_KEY_ENC_OPTS_PFCP,	/* Nested
+					 * TCA_FLOWER_KEY_ENC_IPT_PFCP
+					 * attributes
+					 */
 	__TCA_FLOWER_KEY_ENC_OPTS_MAX,
 };
 
@@ -636,6 +640,16 @@ enum {
 #define TCA_FLOWER_KEY_ENC_OPT_GTP_MAX \
 		(__TCA_FLOWER_KEY_ENC_OPT_GTP_MAX - 1)
 
+enum {
+	TCA_FLOWER_KEY_ENC_OPT_PFCP_UNSPEC,
+	TCA_FLOWER_KEY_ENC_OPT_PFCP_TYPE,		/* u8 */
+	TCA_FLOWER_KEY_ENC_OPT_PFCP_SEID,		/* be64 */
+	__TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX,
+};
+
+#define TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX \
+		(__TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX - 1)
+
 enum {
 	TCA_FLOWER_KEY_MPLS_OPTS_UNSPEC,
 	TCA_FLOWER_KEY_MPLS_OPTS_LSE,
diff --git a/original/uapi/linux/prctl.h b/original/uapi/linux/prctl.h
index 370ed14..3579179 100644
--- a/original/uapi/linux/prctl.h
+++ b/original/uapi/linux/prctl.h
@@ -306,4 +306,26 @@ struct prctl_mm_map {
 # define PR_RISCV_V_VSTATE_CTRL_NEXT_MASK	0xc
 # define PR_RISCV_V_VSTATE_CTRL_MASK		0x1f
 
+#define PR_RISCV_SET_ICACHE_FLUSH_CTX	71
+# define PR_RISCV_CTX_SW_FENCEI_ON	0
+# define PR_RISCV_CTX_SW_FENCEI_OFF	1
+# define PR_RISCV_SCOPE_PER_PROCESS	0
+# define PR_RISCV_SCOPE_PER_THREAD	1
+
+/* PowerPC Dynamic Execution Control Register (DEXCR) controls */
+#define PR_PPC_GET_DEXCR		72
+#define PR_PPC_SET_DEXCR		73
+/* DEXCR aspect to act on */
+# define PR_PPC_DEXCR_SBHE		0 /* Speculative branch hint enable */
+# define PR_PPC_DEXCR_IBRTPD		1 /* Indirect branch recurrent target prediction disable */
+# define PR_PPC_DEXCR_SRAPD		2 /* Subroutine return address prediction disable */
+# define PR_PPC_DEXCR_NPHIE		3 /* Non-privileged hash instruction enable */
+/* Action to apply / return */
+# define PR_PPC_DEXCR_CTRL_EDITABLE	 0x1 /* Aspect can be modified with PR_PPC_SET_DEXCR */
+# define PR_PPC_DEXCR_CTRL_SET		 0x2 /* Set the aspect for this process */
+# define PR_PPC_DEXCR_CTRL_CLEAR	 0x4 /* Clear the aspect for this process */
+# define PR_PPC_DEXCR_CTRL_SET_ONEXEC	 0x8 /* Set the aspect on exec */
+# define PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC	0x10 /* Clear the aspect on exec */
+# define PR_PPC_DEXCR_CTRL_MASK		0x1f
+
 #endif /* _LINUX_PRCTL_H */
diff --git a/original/uapi/linux/snmp.h b/original/uapi/linux/snmp.h
index a0819c6..adf5fd7 100644
--- a/original/uapi/linux/snmp.h
+++ b/original/uapi/linux/snmp.h
@@ -337,6 +337,8 @@ enum
 	LINUX_MIB_XFRMFWDHDRERROR,		/* XfrmFwdHdrError*/
 	LINUX_MIB_XFRMOUTSTATEINVALID,		/* XfrmOutStateInvalid */
 	LINUX_MIB_XFRMACQUIREERROR,		/* XfrmAcquireError */
+	LINUX_MIB_XFRMOUTSTATEDIRERROR,		/* XfrmOutStateDirError */
+	LINUX_MIB_XFRMINSTATEDIRERROR,		/* XfrmInStateDirError */
 	__LINUX_MIB_XFRMMAX
 };
 
diff --git a/original/uapi/linux/stat.h b/original/uapi/linux/stat.h
index 2f2ee82..9577094 100644
--- a/original/uapi/linux/stat.h
+++ b/original/uapi/linux/stat.h
@@ -127,7 +127,8 @@ struct statx {
 	__u32	stx_dio_mem_align;	/* Memory buffer alignment for direct I/O */
 	__u32	stx_dio_offset_align;	/* File offset alignment for direct I/O */
 	/* 0xa0 */
-	__u64	__spare3[12];	/* Spare space for future expansion */
+	__u64	stx_subvol;	/* Subvolume identifier */
+	__u64	__spare3[11];	/* Spare space for future expansion */
 	/* 0x100 */
 };
 
@@ -155,6 +156,7 @@ struct statx {
 #define STATX_MNT_ID		0x00001000U	/* Got stx_mnt_id */
 #define STATX_DIOALIGN		0x00002000U	/* Want/got direct I/O alignment info */
 #define STATX_MNT_ID_UNIQUE	0x00004000U	/* Want/got extended stx_mount_id */
+#define STATX_SUBVOL		0x00008000U	/* Want/got stx_subvol */
 
 #define STATX__RESERVED		0x80000000U	/* Reserved for future struct statx expansion */
 
diff --git a/original/uapi/linux/stddef.h b/original/uapi/linux/stddef.h
index 2ec6f35..5815411 100644
--- a/original/uapi/linux/stddef.h
+++ b/original/uapi/linux/stddef.h
@@ -55,4 +55,12 @@
 #define __counted_by(m)
 #endif
 
+#ifndef __counted_by_le
+#define __counted_by_le(m)
+#endif
+
+#ifndef __counted_by_be
+#define __counted_by_be(m)
+#endif
+
 #endif /* _UAPI_LINUX_STDDEF_H */
diff --git a/original/uapi/linux/tcp.h b/original/uapi/linux/tcp.h
index c07e9f9..dbf896f 100644
--- a/original/uapi/linux/tcp.h
+++ b/original/uapi/linux/tcp.h
@@ -135,6 +135,8 @@ enum {
 #define TCP_AO_GET_KEYS		41	/* List MKT(s) */
 #define TCP_AO_REPAIR		42	/* Get/Set SNEs and ISNs */
 
+#define TCP_IS_MPTCP		43	/* Is MPTCP being used? */
+
 #define TCP_REPAIR_ON		1
 #define TCP_REPAIR_OFF		0
 #define TCP_REPAIR_OFF_NO_WP	-1	/* Turn off without window probes */
diff --git a/original/uapi/linux/tee.h b/original/uapi/linux/tee.h
index 23e5716..d0430be 100644
--- a/original/uapi/linux/tee.h
+++ b/original/uapi/linux/tee.h
@@ -56,6 +56,7 @@
  */
 #define TEE_IMPL_ID_OPTEE	1
 #define TEE_IMPL_ID_AMDTEE	2
+#define TEE_IMPL_ID_TSTEE	3
 
 /*
  * OP-TEE specific capabilities
diff --git a/original/uapi/linux/trace_mmap.h b/original/uapi/linux/trace_mmap.h
new file mode 100644
index 0000000..c102ef3
--- /dev/null
+++ b/original/uapi/linux/trace_mmap.h
@@ -0,0 +1,48 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+#ifndef _TRACE_MMAP_H_
+#define _TRACE_MMAP_H_
+
+#include <linux/types.h>
+
+/**
+ * struct trace_buffer_meta - Ring-buffer Meta-page description
+ * @meta_page_size:	Size of this meta-page.
+ * @meta_struct_len:	Size of this structure.
+ * @subbuf_size:	Size of each sub-buffer.
+ * @nr_subbufs:		Number of subbfs in the ring-buffer, including the reader.
+ * @reader.lost_events:	Number of events lost at the time of the reader swap.
+ * @reader.id:		subbuf ID of the current reader. ID range [0 : @nr_subbufs - 1]
+ * @reader.read:	Number of bytes read on the reader subbuf.
+ * @flags:		Placeholder for now, 0 until new features are supported.
+ * @entries:		Number of entries in the ring-buffer.
+ * @overrun:		Number of entries lost in the ring-buffer.
+ * @read:		Number of entries that have been read.
+ * @Reserved1:		Internal use only.
+ * @Reserved2:		Internal use only.
+ */
+struct trace_buffer_meta {
+	__u32		meta_page_size;
+	__u32		meta_struct_len;
+
+	__u32		subbuf_size;
+	__u32		nr_subbufs;
+
+	struct {
+		__u64	lost_events;
+		__u32	id;
+		__u32	read;
+	} reader;
+
+	__u64	flags;
+
+	__u64	entries;
+	__u64	overrun;
+	__u64	read;
+
+	__u64	Reserved1;
+	__u64	Reserved2;
+};
+
+#define TRACE_MMAP_IOCTL_GET_READER		_IO('R', 0x20)
+
+#endif /* _TRACE_MMAP_H_ */
diff --git a/original/uapi/linux/udp.h b/original/uapi/linux/udp.h
index 4828794..1a0fe8b 100644
--- a/original/uapi/linux/udp.h
+++ b/original/uapi/linux/udp.h
@@ -36,7 +36,7 @@ struct udphdr {
 #define UDP_GRO		104	/* This socket can receive UDP GRO packets */
 
 /* UDP encapsulation types */
-#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
+#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* unused  draft-ietf-ipsec-nat-t-ike-00/01 */
 #define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */
 #define UDP_ENCAP_L2TPINUDP	3 /* rfc2661 */
 #define UDP_ENCAP_GTP0		4 /* GSM TS 09.60 */
diff --git a/original/uapi/linux/v4l2-mediabus.h b/original/uapi/linux/v4l2-mediabus.h
index 6b07b73..946520b 100644
--- a/original/uapi/linux/v4l2-mediabus.h
+++ b/original/uapi/linux/v4l2-mediabus.h
@@ -19,12 +19,18 @@
  * @width:	image width
  * @height:	image height
  * @code:	data format code (from enum v4l2_mbus_pixelcode)
- * @field:	used interlacing type (from enum v4l2_field)
- * @colorspace:	colorspace of the data (from enum v4l2_colorspace)
- * @ycbcr_enc:	YCbCr encoding of the data (from enum v4l2_ycbcr_encoding)
- * @hsv_enc:	HSV encoding of the data (from enum v4l2_hsv_encoding)
- * @quantization: quantization of the data (from enum v4l2_quantization)
- * @xfer_func:  transfer function of the data (from enum v4l2_xfer_func)
+ * @field:	used interlacing type (from enum v4l2_field), zero for metadata
+ *		mbus codes
+ * @colorspace:	colorspace of the data (from enum v4l2_colorspace), zero on
+ *		metadata mbus codes
+ * @ycbcr_enc:	YCbCr encoding of the data (from enum v4l2_ycbcr_encoding), zero
+ *		for metadata mbus codes
+ * @hsv_enc:	HSV encoding of the data (from enum v4l2_hsv_encoding), zero for
+ *		metadata mbus codes
+ * @quantization: quantization of the data (from enum v4l2_quantization), zero
+ *		for metadata mbus codes
+ * @xfer_func:  transfer function of the data (from enum v4l2_xfer_func), zero
+ *		for metadata mbus codes
  * @flags:	flags (V4L2_MBUS_FRAMEFMT_*)
  * @reserved:  reserved bytes that can be later used
  */
diff --git a/original/uapi/linux/v4l2-subdev.h b/original/uapi/linux/v4l2-subdev.h
index 7048c51..2347e26 100644
--- a/original/uapi/linux/v4l2-subdev.h
+++ b/original/uapi/linux/v4l2-subdev.h
@@ -50,6 +50,10 @@ struct v4l2_subdev_format {
  * @rect: pad crop rectangle boundaries
  * @stream: stream number, defined in subdev routing
  * @reserved: drivers and applications must zero this array
+ *
+ * The subdev crop API is an obsolete interface and may be removed in the
+ * future. It is superseded by the selection API. No new extensions to this
+ * structure will be accepted.
  */
 struct v4l2_subdev_crop {
 	__u32 which;
@@ -224,15 +228,19 @@ struct v4l2_subdev_route {
  * struct v4l2_subdev_routing - Subdev routing information
  *
  * @which: configuration type (from enum v4l2_subdev_format_whence)
- * @num_routes: the total number of routes in the routes array
+ * @len_routes: the length of the routes array, in routes; set by the user, not
+ *		modified by the kernel
  * @routes: pointer to the routes array
+ * @num_routes: the total number of routes, possibly more than fits in the
+ *		routes array
  * @reserved: drivers and applications must zero this array
  */
 struct v4l2_subdev_routing {
 	__u32 which;
-	__u32 num_routes;
+	__u32 len_routes;
 	__u64 routes;
-	__u32 reserved[6];
+	__u32 num_routes;
+	__u32 reserved[11];
 };
 
 /*
diff --git a/original/uapi/linux/version.h b/original/uapi/linux/version.h
index 547cbcf..833a3ce 100644
--- a/original/uapi/linux/version.h
+++ b/original/uapi/linux/version.h
@@ -1,5 +1,5 @@
-#define LINUX_VERSION_CODE 395520
+#define LINUX_VERSION_CODE 395776
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 9
+#define LINUX_VERSION_PATCHLEVEL 10
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/original/uapi/linux/videodev2.h b/original/uapi/linux/videodev2.h
index afad27e..4a6392f 100644
--- a/original/uapi/linux/videodev2.h
+++ b/original/uapi/linux/videodev2.h
@@ -599,6 +599,8 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_Y10BPACK    v4l2_fourcc('Y', '1', '0', 'B') /* 10  Greyscale bit-packed */
 #define V4L2_PIX_FMT_Y10P    v4l2_fourcc('Y', '1', '0', 'P') /* 10  Greyscale, MIPI RAW10 packed */
 #define V4L2_PIX_FMT_IPU3_Y10		v4l2_fourcc('i', 'p', '3', 'y') /* IPU3 packed 10-bit greyscale */
+#define V4L2_PIX_FMT_Y12P    v4l2_fourcc('Y', '1', '2', 'P') /* 12  Greyscale, MIPI RAW12 packed */
+#define V4L2_PIX_FMT_Y14P    v4l2_fourcc('Y', '1', '4', 'P') /* 14  Greyscale, MIPI RAW14 packed */
 
 /* Palette formats */
 #define V4L2_PIX_FMT_PAL8    v4l2_fourcc('P', 'A', 'L', '8') /*  8  8-bit palette */
@@ -839,6 +841,20 @@ struct v4l2_pix_format {
 #define V4L2_META_FMT_RK_ISP1_PARAMS	v4l2_fourcc('R', 'K', '1', 'P') /* Rockchip ISP1 3A Parameters */
 #define V4L2_META_FMT_RK_ISP1_STAT_3A	v4l2_fourcc('R', 'K', '1', 'S') /* Rockchip ISP1 3A Statistics */
 
+#ifdef __KERNEL__
+/*
+ * Line-based metadata formats. Remember to update v4l_fill_fmtdesc() when
+ * adding new ones!
+ */
+#define V4L2_META_FMT_GENERIC_8		v4l2_fourcc('M', 'E', 'T', '8') /* Generic 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_10	v4l2_fourcc('M', 'C', '1', 'A') /* 10-bit CSI-2 packed 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_12	v4l2_fourcc('M', 'C', '1', 'C') /* 12-bit CSI-2 packed 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_14	v4l2_fourcc('M', 'C', '1', 'E') /* 14-bit CSI-2 packed 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_16	v4l2_fourcc('M', 'C', '1', 'G') /* 16-bit CSI-2 packed 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_20	v4l2_fourcc('M', 'C', '1', 'K') /* 20-bit CSI-2 packed 8-bit metadata */
+#define V4L2_META_FMT_GENERIC_CSI2_24	v4l2_fourcc('M', 'C', '1', 'O') /* 24-bit CSI-2 packed 8-bit metadata */
+#endif
+
 /* priv field value to indicates that subsequent fields are valid. */
 #define V4L2_PIX_FMT_PRIV_MAGIC		0xfeedcafe
 
@@ -869,6 +885,7 @@ struct v4l2_fmtdesc {
 #define V4L2_FMT_FLAG_CSC_YCBCR_ENC		0x0080
 #define V4L2_FMT_FLAG_CSC_HSV_ENC		V4L2_FMT_FLAG_CSC_YCBCR_ENC
 #define V4L2_FMT_FLAG_CSC_QUANTIZATION		0x0100
+#define V4L2_FMT_FLAG_META_LINE_BASED		0x0200
 
 	/* Frame Size and frame rate enumeration */
 /*
@@ -1036,6 +1053,7 @@ struct v4l2_requestbuffers {
 #define V4L2_BUF_CAP_SUPPORTS_M2M_HOLD_CAPTURE_BUF	(1 << 5)
 #define V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS		(1 << 6)
 #define V4L2_BUF_CAP_SUPPORTS_MAX_NUM_BUFFERS		(1 << 7)
+#define V4L2_BUF_CAP_SUPPORTS_REMOVE_BUFS		(1 << 8)
 
 /**
  * struct v4l2_plane - plane info for multi-planar buffers
@@ -1841,7 +1859,7 @@ struct v4l2_ext_control {
 		struct v4l2_ctrl_hdr10_cll_info __user *p_hdr10_cll_info;
 		struct v4l2_ctrl_hdr10_mastering_display __user *p_hdr10_mastering_display;
 		void __user *ptr;
-	};
+	} __attribute__ ((packed));
 } __attribute__ ((packed));
 
 struct v4l2_ext_controls {
@@ -2415,10 +2433,19 @@ struct v4l2_sdr_format {
  * struct v4l2_meta_format - metadata format definition
  * @dataformat:		little endian four character code (fourcc)
  * @buffersize:		maximum size in bytes required for data
+ * @width:		number of data units of data per line (valid for line
+ *			based formats only, see format documentation)
+ * @height:		number of lines of data per buffer (valid for line based
+ *			formats only)
+ * @bytesperline:	offset between the beginnings of two adjacent lines in
+ *			bytes (valid for line based formats only)
  */
 struct v4l2_meta_format {
 	__u32				dataformat;
 	__u32				buffersize;
+	__u32				width;
+	__u32				height;
+	__u32				bytesperline;
 } __attribute__ ((packed));
 
 /**
@@ -2624,6 +2651,20 @@ struct v4l2_create_buffers {
 	__u32			reserved[5];
 };
 
+/**
+ * struct v4l2_remove_buffers - VIDIOC_REMOVE_BUFS argument
+ * @index:	the first buffer to be removed
+ * @count:	number of buffers to removed
+ * @type:	enum v4l2_buf_type
+ * @reserved:	future extensions
+ */
+struct v4l2_remove_buffers {
+	__u32			index;
+	__u32			count;
+	__u32			type;
+	__u32			reserved[13];
+};
+
 /*
  *	I O C T L   C O D E S   F O R   V I D E O   D E V I C E S
  *
@@ -2723,6 +2764,8 @@ struct v4l2_create_buffers {
 #define VIDIOC_DBG_G_CHIP_INFO  _IOWR('V', 102, struct v4l2_dbg_chip_info)
 
 #define VIDIOC_QUERY_EXT_CTRL	_IOWR('V', 103, struct v4l2_query_ext_ctrl)
+#define VIDIOC_REMOVE_BUFS	_IOWR('V', 104, struct v4l2_remove_buffers)
+
 
 /* Reminder: when adding new ioctls please add support for them to
    drivers/media/v4l2-core/v4l2-compat-ioctl32.c as well! */
diff --git a/original/uapi/linux/virtio_bt.h b/original/uapi/linux/virtio_bt.h
index af798f4..3cc7d63 100644
--- a/original/uapi/linux/virtio_bt.h
+++ b/original/uapi/linux/virtio_bt.h
@@ -13,7 +13,6 @@
 
 enum virtio_bt_config_type {
 	VIRTIO_BT_CONFIG_TYPE_PRIMARY	= 0,
-	VIRTIO_BT_CONFIG_TYPE_AMP	= 1,
 };
 
 enum virtio_bt_config_vendor {
diff --git a/original/uapi/linux/virtio_mem.h b/original/uapi/linux/virtio_mem.h
index e9122f1..6e4b2cf 100644
--- a/original/uapi/linux/virtio_mem.h
+++ b/original/uapi/linux/virtio_mem.h
@@ -90,6 +90,8 @@
 #define VIRTIO_MEM_F_ACPI_PXM		0
 /* unplugged memory must not be accessed */
 #define VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE	1
+/* plugged memory will remain plugged when suspending+resuming */
+#define VIRTIO_MEM_F_PERSISTENT_SUSPEND		2
 
 
 /* --- virtio-mem: guest -> host requests --- */
diff --git a/original/uapi/linux/virtio_net.h b/original/uapi/linux/virtio_net.h
index cc65ef0..ac91747 100644
--- a/original/uapi/linux/virtio_net.h
+++ b/original/uapi/linux/virtio_net.h
@@ -56,6 +56,7 @@
 #define VIRTIO_NET_F_MQ	22	/* Device supports Receive Flow
 					 * Steering */
 #define VIRTIO_NET_F_CTRL_MAC_ADDR 23	/* Set MAC address */
+#define VIRTIO_NET_F_DEVICE_STATS 50	/* Device can provide device-level statistics. */
 #define VIRTIO_NET_F_VQ_NOTF_COAL 52	/* Device supports virtqueue notification coalescing */
 #define VIRTIO_NET_F_NOTF_COAL	53	/* Device supports notifications coalescing */
 #define VIRTIO_NET_F_GUEST_USO4	54	/* Guest can handle USOv4 in. */
@@ -406,4 +407,146 @@ struct  virtio_net_ctrl_coal_vq {
 	struct virtio_net_ctrl_coal coal;
 };
 
+/*
+ * Device Statistics
+ */
+#define VIRTIO_NET_CTRL_STATS         8
+#define VIRTIO_NET_CTRL_STATS_QUERY   0
+#define VIRTIO_NET_CTRL_STATS_GET     1
+
+struct virtio_net_stats_capabilities {
+
+#define VIRTIO_NET_STATS_TYPE_CVQ       (1ULL << 32)
+
+#define VIRTIO_NET_STATS_TYPE_RX_BASIC  (1ULL << 0)
+#define VIRTIO_NET_STATS_TYPE_RX_CSUM   (1ULL << 1)
+#define VIRTIO_NET_STATS_TYPE_RX_GSO    (1ULL << 2)
+#define VIRTIO_NET_STATS_TYPE_RX_SPEED  (1ULL << 3)
+
+#define VIRTIO_NET_STATS_TYPE_TX_BASIC  (1ULL << 16)
+#define VIRTIO_NET_STATS_TYPE_TX_CSUM   (1ULL << 17)
+#define VIRTIO_NET_STATS_TYPE_TX_GSO    (1ULL << 18)
+#define VIRTIO_NET_STATS_TYPE_TX_SPEED  (1ULL << 19)
+
+	__le64 supported_stats_types[1];
+};
+
+struct virtio_net_ctrl_queue_stats {
+	struct {
+		__le16 vq_index;
+		__le16 reserved[3];
+		__le64 types_bitmap[1];
+	} stats[1];
+};
+
+struct virtio_net_stats_reply_hdr {
+#define VIRTIO_NET_STATS_TYPE_REPLY_CVQ       32
+
+#define VIRTIO_NET_STATS_TYPE_REPLY_RX_BASIC  0
+#define VIRTIO_NET_STATS_TYPE_REPLY_RX_CSUM   1
+#define VIRTIO_NET_STATS_TYPE_REPLY_RX_GSO    2
+#define VIRTIO_NET_STATS_TYPE_REPLY_RX_SPEED  3
+
+#define VIRTIO_NET_STATS_TYPE_REPLY_TX_BASIC  16
+#define VIRTIO_NET_STATS_TYPE_REPLY_TX_CSUM   17
+#define VIRTIO_NET_STATS_TYPE_REPLY_TX_GSO    18
+#define VIRTIO_NET_STATS_TYPE_REPLY_TX_SPEED  19
+	__u8 type;
+	__u8 reserved;
+	__le16 vq_index;
+	__le16 reserved1;
+	__le16 size;
+};
+
+struct virtio_net_stats_cvq {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 command_num;
+	__le64 ok_num;
+};
+
+struct virtio_net_stats_rx_basic {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 rx_notifications;
+
+	__le64 rx_packets;
+	__le64 rx_bytes;
+
+	__le64 rx_interrupts;
+
+	__le64 rx_drops;
+	__le64 rx_drop_overruns;
+};
+
+struct virtio_net_stats_tx_basic {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 tx_notifications;
+
+	__le64 tx_packets;
+	__le64 tx_bytes;
+
+	__le64 tx_interrupts;
+
+	__le64 tx_drops;
+	__le64 tx_drop_malformed;
+};
+
+struct virtio_net_stats_rx_csum {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 rx_csum_valid;
+	__le64 rx_needs_csum;
+	__le64 rx_csum_none;
+	__le64 rx_csum_bad;
+};
+
+struct virtio_net_stats_tx_csum {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 tx_csum_none;
+	__le64 tx_needs_csum;
+};
+
+struct virtio_net_stats_rx_gso {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 rx_gso_packets;
+	__le64 rx_gso_bytes;
+	__le64 rx_gso_packets_coalesced;
+	__le64 rx_gso_bytes_coalesced;
+};
+
+struct virtio_net_stats_tx_gso {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	__le64 tx_gso_packets;
+	__le64 tx_gso_bytes;
+	__le64 tx_gso_segments;
+	__le64 tx_gso_segments_bytes;
+	__le64 tx_gso_packets_noseg;
+	__le64 tx_gso_bytes_noseg;
+};
+
+struct virtio_net_stats_rx_speed {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	/* rx_{packets,bytes}_allowance_exceeded are too long. So rename to
+	 * short name.
+	 */
+	__le64 rx_ratelimit_packets;
+	__le64 rx_ratelimit_bytes;
+};
+
+struct virtio_net_stats_tx_speed {
+	struct virtio_net_stats_reply_hdr hdr;
+
+	/* tx_{packets,bytes}_allowance_exceeded are too long. So rename to
+	 * short name.
+	 */
+	__le64 tx_ratelimit_packets;
+	__le64 tx_ratelimit_bytes;
+};
+
 #endif /* _UAPI_LINUX_VIRTIO_NET_H */
diff --git a/original/uapi/linux/xfrm.h b/original/uapi/linux/xfrm.h
index 594b66e..d950d02 100644
--- a/original/uapi/linux/xfrm.h
+++ b/original/uapi/linux/xfrm.h
@@ -141,6 +141,11 @@ enum {
 	XFRM_POLICY_MAX	= 3
 };
 
+enum xfrm_sa_dir {
+	XFRM_SA_DIR_IN	= 1,
+	XFRM_SA_DIR_OUT = 2
+};
+
 enum {
 	XFRM_SHARE_ANY,		/* No limitations */
 	XFRM_SHARE_SESSION,	/* For this session only */
@@ -315,6 +320,7 @@ enum xfrm_attr_type_t {
 	XFRMA_SET_MARK_MASK,	/* __u32 */
 	XFRMA_IF_ID,		/* __u32 */
 	XFRMA_MTIMER_THRESH,	/* __u32 in seconds for input SA */
+	XFRMA_SA_DIR,		/* __u8 */
 	__XFRMA_MAX
 
 #define XFRMA_OUTPUT_MARK XFRMA_SET_MARK	/* Compatibility */
diff --git a/original/uapi/misc/fastrpc.h b/original/uapi/misc/fastrpc.h
index f33d914..9158369 100644
--- a/original/uapi/misc/fastrpc.h
+++ b/original/uapi/misc/fastrpc.h
@@ -8,11 +8,14 @@
 #define FASTRPC_IOCTL_ALLOC_DMA_BUFF	_IOWR('R', 1, struct fastrpc_alloc_dma_buf)
 #define FASTRPC_IOCTL_FREE_DMA_BUFF	_IOWR('R', 2, __u32)
 #define FASTRPC_IOCTL_INVOKE		_IOWR('R', 3, struct fastrpc_invoke)
+/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_ATTACH	_IO('R', 4)
 #define FASTRPC_IOCTL_INIT_CREATE	_IOWR('R', 5, struct fastrpc_init_create)
 #define FASTRPC_IOCTL_MMAP		_IOWR('R', 6, struct fastrpc_req_mmap)
 #define FASTRPC_IOCTL_MUNMAP		_IOWR('R', 7, struct fastrpc_req_munmap)
+/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_ATTACH_SNS	_IO('R', 8)
+/* This ioctl is only supported with secure device nodes */
 #define FASTRPC_IOCTL_INIT_CREATE_STATIC _IOWR('R', 9, struct fastrpc_init_create_static)
 #define FASTRPC_IOCTL_MEM_MAP		_IOWR('R', 10, struct fastrpc_mem_map)
 #define FASTRPC_IOCTL_MEM_UNMAP		_IOWR('R', 11, struct fastrpc_mem_unmap)
diff --git a/original/uapi/misc/pvpanic.h b/original/uapi/misc/pvpanic.h
index 54b7485..3f1745c 100644
--- a/original/uapi/misc/pvpanic.h
+++ b/original/uapi/misc/pvpanic.h
@@ -3,7 +3,10 @@
 #ifndef __PVPANIC_H__
 #define __PVPANIC_H__
 
-#define PVPANIC_PANICKED	(1 << 0)
-#define PVPANIC_CRASH_LOADED	(1 << 1)
+#include <linux/const.h>
+
+#define PVPANIC_PANICKED	_BITUL(0)
+#define PVPANIC_CRASH_LOADED	_BITUL(1)
+#define PVPANIC_SHUTDOWN	_BITUL(2)
 
 #endif /* __PVPANIC_H__ */
diff --git a/original/uapi/rdma/efa-abi.h b/original/uapi/rdma/efa-abi.h
index 701e2d5..d689b8b 100644
--- a/original/uapi/rdma/efa-abi.h
+++ b/original/uapi/rdma/efa-abi.h
@@ -85,11 +85,17 @@ enum {
 	EFA_QP_DRIVER_TYPE_SRD = 0,
 };
 
+enum {
+	EFA_CREATE_QP_WITH_UNSOLICITED_WRITE_RECV = 1 << 0,
+};
+
 struct efa_ibv_create_qp {
 	__u32 comp_mask;
 	__u32 rq_ring_size; /* bytes */
 	__u32 sq_ring_size; /* bytes */
 	__u32 driver_qp_type;
+	__u16 flags;
+	__u8 reserved_90[6];
 };
 
 struct efa_ibv_create_qp_resp {
@@ -123,6 +129,7 @@ enum {
 	EFA_QUERY_DEVICE_CAPS_CQ_WITH_SGID     = 1 << 3,
 	EFA_QUERY_DEVICE_CAPS_DATA_POLLING_128 = 1 << 4,
 	EFA_QUERY_DEVICE_CAPS_RDMA_WRITE = 1 << 5,
+	EFA_QUERY_DEVICE_CAPS_UNSOLICITED_WRITE_RECV = 1 << 6,
 };
 
 struct efa_ibv_ex_query_device_resp {
diff --git a/original/uapi/rdma/hns-abi.h b/original/uapi/rdma/hns-abi.h
index 158670d..94e8618 100644
--- a/original/uapi/rdma/hns-abi.h
+++ b/original/uapi/rdma/hns-abi.h
@@ -109,6 +109,12 @@ struct hns_roce_ib_create_qp_resp {
 	__aligned_u64 dwqe_mmap_key;
 };
 
+struct hns_roce_ib_modify_qp_resp {
+	__u8	tc_mode;
+	__u8	priority;
+	__u8	reserved[6];
+};
+
 enum {
 	HNS_ROCE_EXSGE_FLAGS = 1 << 0,
 	HNS_ROCE_RQ_INLINE_FLAGS = 1 << 1,
@@ -143,7 +149,8 @@ struct hns_roce_ib_alloc_pd_resp {
 
 struct hns_roce_ib_create_ah_resp {
 	__u8 dmac[6];
-	__u8 reserved[2];
+	__u8 priority;
+	__u8 tc_mode;
 };
 
 #endif /* HNS_ABI_USER_H */
diff --git a/original/uapi/rdma/mana-abi.h b/original/uapi/rdma/mana-abi.h
index 5fcb31b..2c41cc3 100644
--- a/original/uapi/rdma/mana-abi.h
+++ b/original/uapi/rdma/mana-abi.h
@@ -16,8 +16,20 @@
 
 #define MANA_IB_UVERBS_ABI_VERSION 1
 
+enum mana_ib_create_cq_flags {
+	MANA_IB_CREATE_RNIC_CQ	= 1 << 0,
+};
+
 struct mana_ib_create_cq {
 	__aligned_u64 buf_addr;
+	__u16	flags;
+	__u16	reserved0;
+	__u32	reserved1;
+};
+
+struct mana_ib_create_cq_resp {
+	__u32 cqid;
+	__u32 reserved;
 };
 
 struct mana_ib_create_qp {
diff --git a/original/uapi/rdma/rdma_netlink.h b/original/uapi/rdma/rdma_netlink.h
index 723bbb0..a214fc2 100644
--- a/original/uapi/rdma/rdma_netlink.h
+++ b/original/uapi/rdma/rdma_netlink.h
@@ -558,6 +558,12 @@ enum rdma_nldev_attr {
 
 	RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE, /* u8 */
 
+	RDMA_NLDEV_ATTR_DRIVER_DETAILS,		/* u8 */
+	/*
+	 * QP subtype string, used for driver QPs
+	 */
+	RDMA_NLDEV_ATTR_RES_SUBTYPE,		/* string */
+
 	/*
 	 * Always the end
 	 */
diff --git a/original/uapi/scsi/scsi_bsg_mpi3mr.h b/original/uapi/scsi/scsi_bsg_mpi3mr.h
index 30a5c1a..a3ba779 100644
--- a/original/uapi/scsi/scsi_bsg_mpi3mr.h
+++ b/original/uapi/scsi/scsi_bsg_mpi3mr.h
@@ -401,7 +401,7 @@ struct mpi3mr_buf_entry {
 	__u32	buf_len;
 };
 /**
- * struct mpi3mr_bsg_buf_entry_list - list of user buffer
+ * struct mpi3mr_buf_entry_list - list of user buffer
  * descriptor for MPI Passthrough requests.
  *
  * @num_of_entries: Number of buffer descriptors
@@ -424,6 +424,7 @@ struct mpi3mr_buf_entry_list {
  * @mrioc_id: Controller ID
  * @rsvd1: Reserved
  * @timeout: MPI request timeout
+ * @rsvd2: Reserved
  * @buf_entry_list: Buffer descriptor list
  */
 struct mpi3mr_bsg_mptcmd {
@@ -441,8 +442,9 @@ struct mpi3mr_bsg_mptcmd {
  * @cmd_type: represents drvrcmd or mptcmd
  * @rsvd1: Reserved
  * @rsvd2: Reserved
- * @drvrcmd: driver request structure
- * @mptcmd: mpt request structure
+ * @rsvd3: Reserved
+ * @cmd.drvrcmd: driver request structure
+ * @cmd.mptcmd: mpt request structure
  */
 struct mpi3mr_bsg_packet {
 	__u8	cmd_type;
diff --git a/original/uapi/scsi/scsi_bsg_ufs.h b/original/uapi/scsi/scsi_bsg_ufs.h
index 03f2bea..8c29e49 100644
--- a/original/uapi/scsi/scsi_bsg_ufs.h
+++ b/original/uapi/scsi/scsi_bsg_ufs.h
@@ -123,6 +123,7 @@ struct utp_upiu_query {
  * @idn: a value that indicates the particular type of data B-1
  * @index: Index to further identify data B-2
  * @selector: Index to further identify data B-3
+ * @osf3: spec field B-4
  * @osf4: spec field B-5
  * @osf5: spec field B 6,7
  * @osf6: spec field DW 8,9
@@ -138,12 +139,13 @@ struct utp_upiu_query_v4_0 {
 	__be16 osf5;
 	__be32 osf6;
 	__be32 osf7;
+	/* private: */
 	__be32 reserved;
 };
 
 /**
  * struct utp_upiu_cmd - Command UPIU structure
- * @data_transfer_len: Data Transfer Length DW-3
+ * @exp_data_transfer_len: Data Transfer Length DW-3
  * @cdb: Command Descriptor Block CDB DW-4 to DW-7
  */
 struct utp_upiu_cmd {
diff --git a/original/uapi/sound/asoc.h b/original/uapi/sound/asoc.h
index 10851bc..99333cb 100644
--- a/original/uapi/sound/asoc.h
+++ b/original/uapi/sound/asoc.h
@@ -576,60 +576,4 @@ struct snd_soc_tplg_dai {
 	struct snd_soc_tplg_private priv;
 } __attribute__((packed));
 
-/*
- * Old version of ABI structs, supported for backward compatibility.
- */
-
-/* Manifest v4 */
-struct snd_soc_tplg_manifest_v4 {
-	__le32 size;		/* in bytes of this structure */
-	__le32 control_elems;	/* number of control elements */
-	__le32 widget_elems;	/* number of widget elements */
-	__le32 graph_elems;	/* number of graph elements */
-	__le32 pcm_elems;	/* number of PCM elements */
-	__le32 dai_link_elems;	/* number of DAI link elements */
-	struct snd_soc_tplg_private priv;
-} __packed;
-
-/* Stream Capabilities v4 */
-struct snd_soc_tplg_stream_caps_v4 {
-	__le32 size;		/* in bytes of this structure */
-	char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
-	__le64 formats;	/* supported formats SNDRV_PCM_FMTBIT_* */
-	__le32 rates;		/* supported rates SNDRV_PCM_RATE_* */
-	__le32 rate_min;	/* min rate */
-	__le32 rate_max;	/* max rate */
-	__le32 channels_min;	/* min channels */
-	__le32 channels_max;	/* max channels */
-	__le32 periods_min;	/* min number of periods */
-	__le32 periods_max;	/* max number of periods */
-	__le32 period_size_min;	/* min period size bytes */
-	__le32 period_size_max;	/* max period size bytes */
-	__le32 buffer_size_min;	/* min buffer size bytes */
-	__le32 buffer_size_max;	/* max buffer size bytes */
-} __packed;
-
-/* PCM v4 */
-struct snd_soc_tplg_pcm_v4 {
-	__le32 size;		/* in bytes of this structure */
-	char pcm_name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
-	char dai_name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
-	__le32 pcm_id;		/* unique ID - used to match with DAI link */
-	__le32 dai_id;		/* unique ID - used to match */
-	__le32 playback;	/* supports playback mode */
-	__le32 capture;		/* supports capture mode */
-	__le32 compress;	/* 1 = compressed; 0 = PCM */
-	struct snd_soc_tplg_stream stream[SND_SOC_TPLG_STREAM_CONFIG_MAX]; /* for DAI link */
-	__le32 num_streams;	/* number of streams */
-	struct snd_soc_tplg_stream_caps_v4 caps[2]; /* playback and capture for DAI */
-} __packed;
-
-/* Physical link config v4 */
-struct snd_soc_tplg_link_config_v4 {
-	__le32 size;            /* in bytes of this structure */
-	__le32 id;              /* unique ID - used to match */
-	struct snd_soc_tplg_stream stream[SND_SOC_TPLG_STREAM_CONFIG_MAX]; /* supported configs playback and captrure */
-	__le32 num_streams;     /* number of streams */
-} __packed;
-
 #endif
diff --git a/original/uapi/sound/intel/avs/tokens.h b/original/uapi/sound/intel/avs/tokens.h
index 4beca03..3e3fb25 100644
--- a/original/uapi/sound/intel/avs/tokens.h
+++ b/original/uapi/sound/intel/avs/tokens.h
@@ -1,6 +1,6 @@
 /* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
 /*
- * Copyright(c) 2021 Intel Corporation. All rights reserved.
+ * Copyright(c) 2021 Intel Corporation
  *
  * Authors: Cezary Rojewski <cezary.rojewski@intel.com>
  *          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
diff --git a/original/uapi/sound/skl-tplg-interface.h b/original/uapi/sound/skl-tplg-interface.h
index 4bf9c4f..940c426 100644
--- a/original/uapi/sound/skl-tplg-interface.h
+++ b/original/uapi/sound/skl-tplg-interface.h
@@ -165,78 +165,4 @@ enum skl_tuple_type {
 	SKL_TYPE_DATA
 };
 
-/* v4 configuration data */
-
-struct skl_dfw_v4_module_pin {
-	__u16 module_id;
-	__u16 instance_id;
-} __packed;
-
-struct skl_dfw_v4_module_fmt {
-	__u32 channels;
-	__u32 freq;
-	__u32 bit_depth;
-	__u32 valid_bit_depth;
-	__u32 ch_cfg;
-	__u32 interleaving_style;
-	__u32 sample_type;
-	__u32 ch_map;
-} __packed;
-
-struct skl_dfw_v4_module_caps {
-	__u32 set_params:2;
-	__u32 rsvd:30;
-	__u32 param_id;
-	__u32 caps_size;
-	__u32 caps[HDA_SST_CFG_MAX];
-} __packed;
-
-struct skl_dfw_v4_pipe {
-	__u8 pipe_id;
-	__u8 pipe_priority;
-	__u16 conn_type:4;
-	__u16 rsvd:4;
-	__u16 memory_pages:8;
-} __packed;
-
-struct skl_dfw_v4_module {
-	char uuid[SKL_UUID_STR_SZ];
-
-	__u16 module_id;
-	__u16 instance_id;
-	__u32 max_mcps;
-	__u32 mem_pages;
-	__u32 obs;
-	__u32 ibs;
-	__u32 vbus_id;
-
-	__u32 max_in_queue:8;
-	__u32 max_out_queue:8;
-	__u32 time_slot:8;
-	__u32 core_id:4;
-	__u32 rsvd1:4;
-
-	__u32 module_type:8;
-	__u32 conn_type:4;
-	__u32 dev_type:4;
-	__u32 hw_conn_type:4;
-	__u32 rsvd2:12;
-
-	__u32 params_fixup:8;
-	__u32 converter:8;
-	__u32 input_pin_type:1;
-	__u32 output_pin_type:1;
-	__u32 is_dynamic_in_pin:1;
-	__u32 is_dynamic_out_pin:1;
-	__u32 is_loadable:1;
-	__u32 rsvd3:11;
-
-	struct skl_dfw_v4_pipe pipe;
-	struct skl_dfw_v4_module_fmt in_fmt[MAX_IN_QUEUE];
-	struct skl_dfw_v4_module_fmt out_fmt[MAX_OUT_QUEUE];
-	struct skl_dfw_v4_module_pin in_pin[MAX_IN_QUEUE];
-	struct skl_dfw_v4_module_pin out_pin[MAX_OUT_QUEUE];
-	struct skl_dfw_v4_module_caps caps;
-} __packed;
-
 #endif
diff --git a/original/uapi/sound/sof/abi.h b/original/uapi/sound/sof/abi.h
index 45c657c..937ed94 100644
--- a/original/uapi/sound/sof/abi.h
+++ b/original/uapi/sound/sof/abi.h
@@ -3,7 +3,7 @@
  * This file is provided under a dual BSD/GPLv2 license.  When using or
  * redistributing this file, you may do so under either license.
  *
- * Copyright(c) 2018 Intel Corporation. All rights reserved.
+ * Copyright(c) 2018 Intel Corporation
  */
 
 /**
diff --git a/original/uapi/sound/sof/fw.h b/original/uapi/sound/sof/fw.h
index e9f6974..fcfa71f 100644
--- a/original/uapi/sound/sof/fw.h
+++ b/original/uapi/sound/sof/fw.h
@@ -3,7 +3,7 @@
  * This file is provided under a dual BSD/GPLv2 license.  When using or
  * redistributing this file, you may do so under either license.
  *
- * Copyright(c) 2018 Intel Corporation. All rights reserved.
+ * Copyright(c) 2018 Intel Corporation
  */
 
 /*
diff --git a/original/uapi/sound/sof/header.h b/original/uapi/sound/sof/header.h
index cb3c1ac..228d4c3 100644
--- a/original/uapi/sound/sof/header.h
+++ b/original/uapi/sound/sof/header.h
@@ -3,7 +3,7 @@
  * This file is provided under a dual BSD/GPLv2 license.  When using or
  * redistributing this file, you may do so under either license.
  *
- * Copyright(c) 2018 Intel Corporation. All rights reserved.
+ * Copyright(c) 2018 Intel Corporation
  */
 
 #ifndef __INCLUDE_UAPI_SOUND_SOF_USER_HEADER_H__
diff --git a/original/uapi/sound/sof/tokens.h b/original/uapi/sound/sof/tokens.h
index 6bf00c0..0a246bc 100644
--- a/original/uapi/sound/sof/tokens.h
+++ b/original/uapi/sound/sof/tokens.h
@@ -3,7 +3,7 @@
  * This file is provided under a dual BSD/GPLv2 license.  When using or
  * redistributing this file, you may do so under either license.
  *
- * Copyright(c) 2018 Intel Corporation. All rights reserved.
+ * Copyright(c) 2018 Intel Corporation
  * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
  *         Keyon Jie <yang.jie@linux.intel.com>
  */
```

