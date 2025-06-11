```diff
diff --git a/OWNERS b/OWNERS
index a466875..613f8a9 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@
 # Please update this list if you find better candidates.
 cferris@google.com
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/original/uapi/asm-arm64/asm/hwcap.h b/original/uapi/asm-arm64/asm/hwcap.h
index 285610e..055381b 100644
--- a/original/uapi/asm-arm64/asm/hwcap.h
+++ b/original/uapi/asm-arm64/asm/hwcap.h
@@ -122,5 +122,6 @@
 #define HWCAP2_SME_SF8FMA	(1UL << 60)
 #define HWCAP2_SME_SF8DP4	(1UL << 61)
 #define HWCAP2_SME_SF8DP2	(1UL << 62)
+#define HWCAP2_POE		(1UL << 63)
 
 #endif /* _UAPI__ASM_HWCAP_H */
diff --git a/original/uapi/asm-arm64/asm/mman.h b/original/uapi/asm-arm64/asm/mman.h
index 1e6482a..e7e0c82 100644
--- a/original/uapi/asm-arm64/asm/mman.h
+++ b/original/uapi/asm-arm64/asm/mman.h
@@ -7,4 +7,13 @@
 #define PROT_BTI	0x10		/* BTI guarded page */
 #define PROT_MTE	0x20		/* Normal Tagged mapping */
 
+/* Override any generic PKEY permission defines */
+#define PKEY_DISABLE_EXECUTE	0x4
+#define PKEY_DISABLE_READ	0x8
+#undef PKEY_ACCESS_MASK
+#define PKEY_ACCESS_MASK       (PKEY_DISABLE_ACCESS |\
+				PKEY_DISABLE_WRITE  |\
+				PKEY_DISABLE_READ   |\
+				PKEY_DISABLE_EXECUTE)
+
 #endif /* ! _UAPI__ASM_MMAN_H */
diff --git a/original/uapi/asm-arm64/asm/sigcontext.h b/original/uapi/asm-arm64/asm/sigcontext.h
index 8a45b7a..bb7af77 100644
--- a/original/uapi/asm-arm64/asm/sigcontext.h
+++ b/original/uapi/asm-arm64/asm/sigcontext.h
@@ -98,6 +98,13 @@ struct esr_context {
 	__u64 esr;
 };
 
+#define POE_MAGIC	0x504f4530
+
+struct poe_context {
+	struct _aarch64_ctx head;
+	__u64 por_el0;
+};
+
 /*
  * extra_context: describes extra space in the signal frame for
  * additional structures that don't fit in sigcontext.__reserved[].
@@ -320,10 +327,10 @@ struct zt_context {
 	((sizeof(struct za_context) + (__SVE_VQ_BYTES - 1))	\
 		/ __SVE_VQ_BYTES * __SVE_VQ_BYTES)
 
-#define ZA_SIG_REGS_SIZE(vq) ((vq * __SVE_VQ_BYTES) * (vq * __SVE_VQ_BYTES))
+#define ZA_SIG_REGS_SIZE(vq) (((vq) * __SVE_VQ_BYTES) * ((vq) * __SVE_VQ_BYTES))
 
 #define ZA_SIG_ZAV_OFFSET(vq, n) (ZA_SIG_REGS_OFFSET + \
-				  (SVE_SIG_ZREG_SIZE(vq) * n))
+				  (SVE_SIG_ZREG_SIZE(vq) * (n)))
 
 #define ZA_SIG_CONTEXT_SIZE(vq) \
 		(ZA_SIG_REGS_OFFSET + ZA_SIG_REGS_SIZE(vq))
@@ -334,7 +341,7 @@ struct zt_context {
 
 #define ZT_SIG_REGS_OFFSET sizeof(struct zt_context)
 
-#define ZT_SIG_REGS_SIZE(n) (ZT_SIG_REG_BYTES * n)
+#define ZT_SIG_REGS_SIZE(n) (ZT_SIG_REG_BYTES * (n))
 
 #define ZT_SIG_CONTEXT_SIZE(n) \
 	(sizeof(struct zt_context) + ZT_SIG_REGS_SIZE(n))
diff --git a/original/uapi/asm-generic/socket.h b/original/uapi/asm-generic/socket.h
index 8ce8a39..3b4e3e8 100644
--- a/original/uapi/asm-generic/socket.h
+++ b/original/uapi/asm-generic/socket.h
@@ -135,6 +135,12 @@
 #define SO_PASSPIDFD		76
 #define SO_PEERPIDFD		77
 
+#define SO_DEVMEM_LINEAR	78
+#define SCM_DEVMEM_LINEAR	SO_DEVMEM_LINEAR
+#define SO_DEVMEM_DMABUF	79
+#define SCM_DEVMEM_DMABUF	SO_DEVMEM_DMABUF
+#define SO_DEVMEM_DONTNEED	80
+
 #if !defined(__KERNEL__)
 
 #if __BITS_PER_LONG == 64 || (defined(__x86_64__) && defined(__ILP32__))
diff --git a/original/uapi/asm-x86/asm/elf.h b/original/uapi/asm-x86/asm/elf.h
new file mode 100644
index 0000000..468e135
--- /dev/null
+++ b/original/uapi/asm-x86/asm/elf.h
@@ -0,0 +1,16 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+#ifndef _UAPI_ASM_X86_ELF_H
+#define _UAPI_ASM_X86_ELF_H
+
+#include <linux/types.h>
+
+struct x86_xfeat_component {
+	__u32 type;
+	__u32 size;
+	__u32 offset;
+	__u32 flags;
+} __packed;
+
+_Static_assert(sizeof(struct x86_xfeat_component) % 4 == 0, "x86_xfeat_component is not aligned");
+
+#endif /* _UAPI_ASM_X86_ELF_H */
diff --git a/original/uapi/asm-x86/asm/kvm.h b/original/uapi/asm-x86/asm/kvm.h
index bf57a82..a8debbf 100644
--- a/original/uapi/asm-x86/asm/kvm.h
+++ b/original/uapi/asm-x86/asm/kvm.h
@@ -439,6 +439,7 @@ struct kvm_sync_regs {
 #define KVM_X86_QUIRK_MISC_ENABLE_NO_MWAIT	(1 << 4)
 #define KVM_X86_QUIRK_FIX_HYPERCALL_INSN	(1 << 5)
 #define KVM_X86_QUIRK_MWAIT_NEVER_UD_FAULTS	(1 << 6)
+#define KVM_X86_QUIRK_SLOT_ZAP_ALL		(1 << 7)
 
 #define KVM_STATE_NESTED_FORMAT_VMX	0
 #define KVM_STATE_NESTED_FORMAT_SVM	1
diff --git a/original/uapi/drm/drm_fourcc.h b/original/uapi/drm/drm_fourcc.h
index 2d84a80..78abd81 100644
--- a/original/uapi/drm/drm_fourcc.h
+++ b/original/uapi/drm/drm_fourcc.h
@@ -702,6 +702,31 @@ extern "C" {
  */
 #define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC fourcc_mod_code(INTEL, 15)
 
+/*
+ * Intel Color Control Surfaces (CCS) for graphics ver. 20 unified compression
+ * on integrated graphics
+ *
+ * The main surface is Tile 4 and at plane index 0. For semi-planar formats
+ * like NV12, the Y and UV planes are Tile 4 and are located at plane indices
+ * 0 and 1, respectively. The CCS for all planes are stored outside of the
+ * GEM object in a reserved memory area dedicated for the storage of the
+ * CCS data for all compressible GEM objects.
+ */
+#define I915_FORMAT_MOD_4_TILED_LNL_CCS fourcc_mod_code(INTEL, 16)
+
+/*
+ * Intel Color Control Surfaces (CCS) for graphics ver. 20 unified compression
+ * on discrete graphics
+ *
+ * The main surface is Tile 4 and at plane index 0. For semi-planar formats
+ * like NV12, the Y and UV planes are Tile 4 and are located at plane indices
+ * 0 and 1, respectively. The CCS for all planes are stored outside of the
+ * GEM object in a reserved memory area dedicated for the storage of the
+ * CCS data for all compressible GEM objects. The GEM object must be stored in
+ * contiguous memory with a size aligned to 64KB
+ */
+#define I915_FORMAT_MOD_4_TILED_BMG_CCS fourcc_mod_code(INTEL, 17)
+
 /*
  * Tiled, NV12MT, grouped in 64 (pixels) x 32 (lines) -sized macroblocks
  *
diff --git a/original/uapi/drm/drm_mode.h b/original/uapi/drm/drm_mode.h
index d390011..c082810 100644
--- a/original/uapi/drm/drm_mode.h
+++ b/original/uapi/drm/drm_mode.h
@@ -859,6 +859,8 @@ struct drm_color_lut {
 
 /**
  * struct drm_plane_size_hint - Plane size hints
+ * @width: The width of the plane in pixel
+ * @height: The height of the plane in pixel
  *
  * The plane SIZE_HINTS property blob contains an
  * array of struct drm_plane_size_hint.
diff --git a/original/uapi/drm/msm_drm.h b/original/uapi/drm/msm_drm.h
index 3fca72f..2377147 100644
--- a/original/uapi/drm/msm_drm.h
+++ b/original/uapi/drm/msm_drm.h
@@ -88,6 +88,8 @@ struct drm_msm_timespec {
 #define MSM_PARAM_VA_SIZE    0x0f  /* RO: size of valid GPU iova range (bytes) */
 #define MSM_PARAM_HIGHEST_BANK_BIT 0x10 /* RO */
 #define MSM_PARAM_RAYTRACING 0x11 /* RO */
+#define MSM_PARAM_UBWC_SWIZZLE 0x12 /* RO */
+#define MSM_PARAM_MACROTILE_MODE 0x13 /* RO */
 
 /* For backwards compat.  The original support for preemption was based on
  * a single ring per priority level so # of priority levels equals the #
diff --git a/original/uapi/drm/xe_drm.h b/original/uapi/drm/xe_drm.h
index db232a2..b6fbe49 100644
--- a/original/uapi/drm/xe_drm.h
+++ b/original/uapi/drm/xe_drm.h
@@ -517,7 +517,14 @@ struct drm_xe_query_gt_list {
  *    available per Dual Sub Slices (DSS). For example a query response
  *    containing the following in mask:
  *    ``EU_PER_DSS    ff ff 00 00 00 00 00 00``
- *    means each DSS has 16 EU.
+ *    means each DSS has 16 SIMD8 EUs. This type may be omitted if device
+ *    doesn't have SIMD8 EUs.
+ *  - %DRM_XE_TOPO_SIMD16_EU_PER_DSS - To query the mask of SIMD16 Execution
+ *    Units (EU) available per Dual Sub Slices (DSS). For example a query
+ *    response containing the following in mask:
+ *    ``SIMD16_EU_PER_DSS    ff ff 00 00 00 00 00 00``
+ *    means each DSS has 16 SIMD16 EUs. This type may be omitted if device
+ *    doesn't have SIMD16 EUs.
  */
 struct drm_xe_query_topology_mask {
 	/** @gt_id: GT ID the mask is associated with */
@@ -527,6 +534,7 @@ struct drm_xe_query_topology_mask {
 #define DRM_XE_TOPO_DSS_COMPUTE		2
 #define DRM_XE_TOPO_L3_BANK		3
 #define DRM_XE_TOPO_EU_PER_DSS		4
+#define DRM_XE_TOPO_SIMD16_EU_PER_DSS	5
 	/** @type: type of mask */
 	__u16 type;
 
diff --git a/original/uapi/linux/android/binder.h b/original/uapi/linux/android/binder.h
index e67742d..e38c3eb 100644
--- a/original/uapi/linux/android/binder.h
+++ b/original/uapi/linux/android/binder.h
@@ -284,6 +284,12 @@ struct binder_frozen_status_info {
 	__u32            async_recv;
 };
 
+struct binder_frozen_state_info {
+	binder_uintptr_t cookie;
+	__u32            is_frozen;
+	__u32            reserved;
+};
+
 /* struct binder_extened_error - extended error information
  * @id:		identifier for the failed operation
  * @command:	command as defined by binder_driver_return_protocol
@@ -515,6 +521,17 @@ enum binder_driver_return_protocol {
 	/*
 	 * The target of the last async transaction is frozen.  No parameters.
 	 */
+
+	BR_FROZEN_BINDER = _IOR('r', 21, struct binder_frozen_state_info),
+	/*
+	 * The cookie and a boolean (is_frozen) that indicates whether the process
+	 * transitioned into a frozen or an unfrozen state.
+	 */
+
+	BR_CLEAR_FREEZE_NOTIFICATION_DONE = _IOR('r', 22, binder_uintptr_t),
+	/*
+	 * void *: cookie
+	 */
 };
 
 enum binder_driver_command_protocol {
@@ -598,6 +615,25 @@ enum binder_driver_command_protocol {
 	/*
 	 * binder_transaction_data_sg: the sent command.
 	 */
+
+	BC_REQUEST_FREEZE_NOTIFICATION =
+			_IOW('c', 19, struct binder_handle_cookie),
+	/*
+	 * int: handle
+	 * void *: cookie
+	 */
+
+	BC_CLEAR_FREEZE_NOTIFICATION = _IOW('c', 20,
+					    struct binder_handle_cookie),
+	/*
+	 * int: handle
+	 * void *: cookie
+	 */
+
+	BC_FREEZE_NOTIFICATION_DONE = _IOW('c', 21, binder_uintptr_t),
+	/*
+	 * void *: cookie
+	 */
 };
 
 #endif /* _UAPI_LINUX_BINDER_H */
diff --git a/original/uapi/linux/audit.h b/original/uapi/linux/audit.h
index d676ed2..75e21a1 100644
--- a/original/uapi/linux/audit.h
+++ b/original/uapi/linux/audit.h
@@ -143,6 +143,9 @@
 #define AUDIT_MAC_UNLBL_STCDEL	1417	/* NetLabel: del a static label */
 #define AUDIT_MAC_CALIPSO_ADD	1418	/* NetLabel: add CALIPSO DOI entry */
 #define AUDIT_MAC_CALIPSO_DEL	1419	/* NetLabel: del CALIPSO DOI entry */
+#define AUDIT_IPE_ACCESS	1420	/* IPE denial or grant */
+#define AUDIT_IPE_CONFIG_CHANGE	1421	/* IPE config change */
+#define AUDIT_IPE_POLICY_LOAD	1422	/* IPE policy load */
 
 #define AUDIT_FIRST_KERN_ANOM_MSG   1700
 #define AUDIT_LAST_KERN_ANOM_MSG    1799
diff --git a/original/uapi/linux/auto_fs.h b/original/uapi/linux/auto_fs.h
index 1f7925a..8081df8 100644
--- a/original/uapi/linux/auto_fs.h
+++ b/original/uapi/linux/auto_fs.h
@@ -23,7 +23,7 @@
 #define AUTOFS_MIN_PROTO_VERSION	3
 #define AUTOFS_MAX_PROTO_VERSION	5
 
-#define AUTOFS_PROTO_SUBVERSION		5
+#define AUTOFS_PROTO_SUBVERSION		6
 
 /*
  * The wait_queue_token (autofs_wqt_t) is part of a structure which is passed
diff --git a/original/uapi/linux/bits.h b/original/uapi/linux/bits.h
index 3c2a101..5ee30f8 100644
--- a/original/uapi/linux/bits.h
+++ b/original/uapi/linux/bits.h
@@ -12,4 +12,7 @@
         (((~_ULL(0)) - (_ULL(1) << (l)) + 1) & \
          (~_ULL(0) >> (__BITS_PER_LONG_LONG - 1 - (h))))
 
+#define __GENMASK_U128(h, l) \
+	((_BIT128((h)) << 1) - (_BIT128(l)))
+
 #endif /* _UAPI_LINUX_BITS_H */
diff --git a/original/uapi/linux/blkdev.h b/original/uapi/linux/blkdev.h
new file mode 100644
index 0000000..66373cd
--- /dev/null
+++ b/original/uapi/linux/blkdev.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+#ifndef _UAPI_LINUX_BLKDEV_H
+#define _UAPI_LINUX_BLKDEV_H
+
+#include <linux/ioctl.h>
+#include <linux/types.h>
+
+/*
+ * io_uring block file commands, see IORING_OP_URING_CMD.
+ * It's a different number space from ioctl(), reuse the block's code 0x12.
+ */
+#define BLOCK_URING_CMD_DISCARD			_IO(0x12, 0)
+
+#endif
diff --git a/original/uapi/linux/bpf.h b/original/uapi/linux/bpf.h
index 35bcf52..4a939c9 100644
--- a/original/uapi/linux/bpf.h
+++ b/original/uapi/linux/bpf.h
@@ -1121,6 +1121,9 @@ enum bpf_attach_type {
 
 #define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
 
+/* Add BPF_LINK_TYPE(type, name) in bpf_types.h to keep bpf_link_type_strs[]
+ * in sync with the definitions below.
+ */
 enum bpf_link_type {
 	BPF_LINK_TYPE_UNSPEC = 0,
 	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
@@ -2851,7 +2854,7 @@ union bpf_attr {
  * 		  **TCP_SYNCNT**, **TCP_USER_TIMEOUT**, **TCP_NOTSENT_LOWAT**,
  * 		  **TCP_NODELAY**, **TCP_MAXSEG**, **TCP_WINDOW_CLAMP**,
  * 		  **TCP_THIN_LINEAR_TIMEOUTS**, **TCP_BPF_DELACK_MAX**,
- * 		  **TCP_BPF_RTO_MIN**.
+ *		  **TCP_BPF_RTO_MIN**, **TCP_BPF_SOCK_OPS_CB_FLAGS**.
  * 		* **IPPROTO_IP**, which supports *optname* **IP_TOS**.
  * 		* **IPPROTO_IPV6**, which supports the following *optname*\ s:
  * 		  **IPV6_TCLASS**, **IPV6_AUTOFLOWLABEL**.
@@ -5519,11 +5522,12 @@ union bpf_attr {
  *		**-EOPNOTSUPP** if the hash calculation failed or **-EINVAL** if
  *		invalid arguments are passed.
  *
- * void *bpf_kptr_xchg(void *map_value, void *ptr)
+ * void *bpf_kptr_xchg(void *dst, void *ptr)
  *	Description
- *		Exchange kptr at pointer *map_value* with *ptr*, and return the
- *		old value. *ptr* can be NULL, otherwise it must be a referenced
- *		pointer which will be released when this helper is called.
+ *		Exchange kptr at pointer *dst* with *ptr*, and return the old value.
+ *		*dst* can be map value or local kptr. *ptr* can be NULL, otherwise
+ *		it must be a referenced pointer which will be released when this helper
+ *		is called.
  *	Return
  *		The old value of kptr (which can be NULL). The returned pointer
  *		if not NULL, is a reference which must be released using its
@@ -6046,11 +6050,6 @@ enum {
 	BPF_F_MARK_ENFORCE		= (1ULL << 6),
 };
 
-/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
-enum {
-	BPF_F_INGRESS			= (1ULL << 0),
-};
-
 /* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
 enum {
 	BPF_F_TUNINFO_IPV6		= (1ULL << 0),
@@ -6197,10 +6196,12 @@ enum {
 	BPF_F_BPRM_SECUREEXEC	= (1ULL << 0),
 };
 
-/* Flags for bpf_redirect_map helper */
+/* Flags for bpf_redirect and bpf_redirect_map helpers */
 enum {
-	BPF_F_BROADCAST		= (1ULL << 3),
-	BPF_F_EXCLUDE_INGRESS	= (1ULL << 4),
+	BPF_F_INGRESS		= (1ULL << 0), /* used for skb path */
+	BPF_F_BROADCAST		= (1ULL << 3), /* used for XDP path */
+	BPF_F_EXCLUDE_INGRESS	= (1ULL << 4), /* used for XDP path */
+#define BPF_F_REDIRECT_FLAGS (BPF_F_INGRESS | BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)
 };
 
 #define __bpf_md_ptr(type, name)	\
@@ -7080,6 +7081,7 @@ enum {
 	TCP_BPF_SYN		= 1005, /* Copy the TCP header */
 	TCP_BPF_SYN_IP		= 1006, /* Copy the IP[46] and TCP header */
 	TCP_BPF_SYN_MAC         = 1007, /* Copy the MAC, IP[46], and TCP header */
+	TCP_BPF_SOCK_OPS_CB_FLAGS = 1008, /* Get or Set TCP sock ops flags */
 };
 
 enum {
@@ -7512,4 +7514,13 @@ struct bpf_iter_num {
 	__u64 __opaque[1];
 } __attribute__((aligned(8)));
 
+/*
+ * Flags to control BPF kfunc behaviour.
+ *     - BPF_F_PAD_ZEROS: Pad destination buffer with zeros. (See the respective
+ *       helper documentation for details.)
+ */
+enum bpf_kfunc_flags {
+	BPF_F_PAD_ZEROS = (1ULL << 0),
+};
+
 #endif /* _UAPI__LINUX_BPF_H__ */
diff --git a/original/uapi/linux/cec.h b/original/uapi/linux/cec.h
index b8e071a..b2af1dd 100644
--- a/original/uapi/linux/cec.h
+++ b/original/uapi/linux/cec.h
@@ -132,6 +132,8 @@ static inline void cec_msg_init(struct cec_msg *msg,
  * Set the msg destination to the orig initiator and the msg initiator to the
  * orig destination. Note that msg and orig may be the same pointer, in which
  * case the change is done in place.
+ *
+ * It also zeroes the reply, timeout and flags fields.
  */
 static inline void cec_msg_set_reply_to(struct cec_msg *msg,
 					struct cec_msg *orig)
@@ -139,7 +141,9 @@ static inline void cec_msg_set_reply_to(struct cec_msg *msg,
 	/* The destination becomes the initiator and vice versa */
 	msg->msg[0] = (cec_msg_destination(orig) << 4) |
 		      cec_msg_initiator(orig);
-	msg->reply = msg->timeout = 0;
+	msg->reply = 0;
+	msg->timeout = 0;
+	msg->flags = 0;
 }
 
 /**
@@ -165,6 +169,7 @@ static inline int cec_msg_recv_is_rx_result(const struct cec_msg *msg)
 /* cec_msg flags field */
 #define CEC_MSG_FL_REPLY_TO_FOLLOWERS	(1 << 0)
 #define CEC_MSG_FL_RAW			(1 << 1)
+#define CEC_MSG_FL_REPLY_VENDOR_ID	(1 << 2)
 
 /* cec_msg tx/rx_status field */
 #define CEC_TX_STATUS_OK		(1 << 0)
@@ -339,6 +344,8 @@ static inline int cec_is_unconfigured(__u16 log_addr_mask)
 #define CEC_CAP_MONITOR_PIN	(1 << 7)
 /* CEC_ADAP_G_CONNECTOR_INFO is available */
 #define CEC_CAP_CONNECTOR_INFO	(1 << 8)
+/* CEC_MSG_FL_REPLY_VENDOR_ID is available */
+#define CEC_CAP_REPLY_VENDOR_ID	(1 << 9)
 
 /**
  * struct cec_caps - CEC capabilities structure.
diff --git a/original/uapi/linux/const.h b/original/uapi/linux/const.h
index a429381..e16be0d 100644
--- a/original/uapi/linux/const.h
+++ b/original/uapi/linux/const.h
@@ -28,6 +28,23 @@
 #define _BITUL(x)	(_UL(1) << (x))
 #define _BITULL(x)	(_ULL(1) << (x))
 
+#if !defined(__ASSEMBLY__)
+/*
+ * Missing asm support
+ *
+ * __BIT128() would not work in the asm code, as it shifts an
+ * 'unsigned __init128' data type as direct representation of
+ * 128 bit constants is not supported in the gcc compiler, as
+ * they get silently truncated.
+ *
+ * TODO: Please revisit this implementation when gcc compiler
+ * starts representing 128 bit constants directly like long
+ * and unsigned long etc. Subsequently drop the comment for
+ * GENMASK_U128() which would then start supporting asm code.
+ */
+#define _BIT128(x)	((unsigned __int128)(1) << (x))
+#endif
+
 #define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
 #define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
 
diff --git a/original/uapi/linux/dpll.h b/original/uapi/linux/dpll.h
index 0c13d7f..b0654ad 100644
--- a/original/uapi/linux/dpll.h
+++ b/original/uapi/linux/dpll.h
@@ -210,6 +210,9 @@ enum dpll_a_pin {
 	DPLL_A_PIN_PHASE_ADJUST,
 	DPLL_A_PIN_PHASE_OFFSET,
 	DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,
+	DPLL_A_PIN_ESYNC_FREQUENCY,
+	DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED,
+	DPLL_A_PIN_ESYNC_PULSE,
 
 	__DPLL_A_PIN_MAX,
 	DPLL_A_PIN_MAX = (__DPLL_A_PIN_MAX - 1)
diff --git a/original/uapi/linux/elf.h b/original/uapi/linux/elf.h
index b54b313..b993598 100644
--- a/original/uapi/linux/elf.h
+++ b/original/uapi/linux/elf.h
@@ -411,6 +411,7 @@ typedef struct elf64_shdr {
 #define NT_X86_XSTATE	0x202		/* x86 extended state using xsave */
 /* Old binutils treats 0x203 as a CET state */
 #define NT_X86_SHSTK	0x204		/* x86 SHSTK state */
+#define NT_X86_XSAVE_LAYOUT	0x205	/* XSAVE layout description */
 #define NT_S390_HIGH_GPRS	0x300	/* s390 upper register halves */
 #define NT_S390_TIMER	0x301		/* s390 timer register */
 #define NT_S390_TODCMP	0x302		/* s390 TOD clock comparator register */
@@ -441,6 +442,7 @@ typedef struct elf64_shdr {
 #define NT_ARM_ZA	0x40c		/* ARM SME ZA registers */
 #define NT_ARM_ZT	0x40d		/* ARM SME ZT registers */
 #define NT_ARM_FPMR	0x40e		/* ARM floating point mode register */
+#define NT_ARM_POE	0x40f		/* ARM POE registers */
 #define NT_ARC_V2	0x600		/* ARCv2 accumulator/extra registers */
 #define NT_VMCOREDD	0x700		/* Vmcore Device Dump Note */
 #define NT_MIPS_DSP	0x800		/* MIPS DSP ASE registers */
diff --git a/original/uapi/linux/ethtool.h b/original/uapi/linux/ethtool.h
index 4a0a6e7..c405ed6 100644
--- a/original/uapi/linux/ethtool.h
+++ b/original/uapi/linux/ethtool.h
@@ -2533,4 +2533,20 @@ struct ethtool_link_settings {
 	 * __u32 map_lp_advertising[link_mode_masks_nwords];
 	 */
 };
+
+/**
+ * enum phy_upstream - Represents the upstream component a given PHY device
+ * is connected to, as in what is on the other end of the MII bus. Most PHYs
+ * will be attached to an Ethernet MAC controller, but in some cases, there's
+ * an intermediate PHY used as a media-converter, which will driver another
+ * MII interface as its output.
+ * @PHY_UPSTREAM_MAC: Upstream component is a MAC (a switch port,
+ *		      or ethernet controller)
+ * @PHY_UPSTREAM_PHY: Upstream component is a PHY (likely a media converter)
+ */
+enum phy_upstream {
+	PHY_UPSTREAM_MAC,
+	PHY_UPSTREAM_PHY,
+};
+
 #endif /* _UAPI_LINUX_ETHTOOL_H */
diff --git a/original/uapi/linux/ethtool_netlink.h b/original/uapi/linux/ethtool_netlink.h
index 6d5bdcc..283305f 100644
--- a/original/uapi/linux/ethtool_netlink.h
+++ b/original/uapi/linux/ethtool_netlink.h
@@ -58,6 +58,7 @@ enum {
 	ETHTOOL_MSG_MM_GET,
 	ETHTOOL_MSG_MM_SET,
 	ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+	ETHTOOL_MSG_PHY_GET,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_USER_CNT,
@@ -111,6 +112,8 @@ enum {
 	ETHTOOL_MSG_MM_GET_REPLY,
 	ETHTOOL_MSG_MM_NTF,
 	ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
+	ETHTOOL_MSG_PHY_GET_REPLY,
+	ETHTOOL_MSG_PHY_NTF,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_KERNEL_CNT,
@@ -134,6 +137,7 @@ enum {
 	ETHTOOL_A_HEADER_DEV_INDEX,		/* u32 */
 	ETHTOOL_A_HEADER_DEV_NAME,		/* string */
 	ETHTOOL_A_HEADER_FLAGS,			/* u32 - ETHTOOL_FLAG_* */
+	ETHTOOL_A_HEADER_PHY_INDEX,		/* u32 */
 
 	/* add new constants above here */
 	__ETHTOOL_A_HEADER_CNT,
@@ -556,6 +560,10 @@ enum {
 	 * a regular 100 Ohm cable and a part with the abnormal impedance value
 	 */
 	ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
+	/* TDR not possible due to high noise level */
+	ETHTOOL_A_CABLE_RESULT_CODE_NOISE,
+	/* TDR resolution not possible / out of distance */
+	ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE,
 };
 
 enum {
@@ -565,10 +573,20 @@ enum {
 	ETHTOOL_A_CABLE_PAIR_D,
 };
 
+/* Information source for specific results. */
+enum {
+	ETHTOOL_A_CABLE_INF_SRC_UNSPEC,
+	/* Results provided by the Time Domain Reflectometry (TDR) */
+	ETHTOOL_A_CABLE_INF_SRC_TDR,
+	/* Results provided by the Active Link Cable Diagnostic (ALCD) */
+	ETHTOOL_A_CABLE_INF_SRC_ALCD,
+};
+
 enum {
 	ETHTOOL_A_CABLE_RESULT_UNSPEC,
 	ETHTOOL_A_CABLE_RESULT_PAIR,		/* u8 ETHTOOL_A_CABLE_PAIR_ */
 	ETHTOOL_A_CABLE_RESULT_CODE,		/* u8 ETHTOOL_A_CABLE_RESULT_CODE_ */
+	ETHTOOL_A_CABLE_RESULT_SRC,		/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
 
 	__ETHTOOL_A_CABLE_RESULT_CNT,
 	ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
@@ -578,6 +596,7 @@ enum {
 	ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
 	ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,	/* u8 ETHTOOL_A_CABLE_PAIR_ */
 	ETHTOOL_A_CABLE_FAULT_LENGTH_CM,	/* u32 */
+	ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,	/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
 
 	__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
 	ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
@@ -965,6 +984,7 @@ enum {
 	ETHTOOL_A_RSS_INDIR,		/* binary */
 	ETHTOOL_A_RSS_HKEY,		/* binary */
 	ETHTOOL_A_RSS_INPUT_XFRM,	/* u32 */
+	ETHTOOL_A_RSS_START_CONTEXT,	/* u32 */
 
 	__ETHTOOL_A_RSS_CNT,
 	ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
@@ -1049,6 +1069,22 @@ enum {
 	ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
 };
 
+enum {
+	ETHTOOL_A_PHY_UNSPEC,
+	ETHTOOL_A_PHY_HEADER,			/* nest - _A_HEADER_* */
+	ETHTOOL_A_PHY_INDEX,			/* u32 */
+	ETHTOOL_A_PHY_DRVNAME,			/* string */
+	ETHTOOL_A_PHY_NAME,			/* string */
+	ETHTOOL_A_PHY_UPSTREAM_TYPE,		/* u32 */
+	ETHTOOL_A_PHY_UPSTREAM_INDEX,		/* u32 */
+	ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,	/* string */
+	ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,	/* string */
+
+	/* add new constants above here */
+	__ETHTOOL_A_PHY_CNT,
+	ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+};
+
 /* generic netlink info */
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
diff --git a/original/uapi/linux/exfat.h b/original/uapi/linux/exfat.h
new file mode 100644
index 0000000..46d95b1
--- /dev/null
+++ b/original/uapi/linux/exfat.h
@@ -0,0 +1,25 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * Copyright (C) 2024 Unisoc Technologies Co., Ltd.
+ */
+
+#ifndef _UAPI_LINUX_EXFAT_H
+#define _UAPI_LINUX_EXFAT_H
+#include <linux/types.h>
+#include <linux/ioctl.h>
+
+/*
+ * exfat-specific ioctl commands
+ */
+
+#define EXFAT_IOC_SHUTDOWN _IOR('X', 125, __u32)
+
+/*
+ * Flags used by EXFAT_IOC_SHUTDOWN
+ */
+
+#define EXFAT_GOING_DOWN_DEFAULT	0x0	/* default with full sync */
+#define EXFAT_GOING_DOWN_FULLSYNC	0x1     /* going down with full sync*/
+#define EXFAT_GOING_DOWN_NOSYNC         0x2     /* going down */
+
+#endif /* _UAPI_LINUX_EXFAT_H */
diff --git a/original/uapi/linux/falloc.h b/original/uapi/linux/falloc.h
index 51398fa..5810371 100644
--- a/original/uapi/linux/falloc.h
+++ b/original/uapi/linux/falloc.h
@@ -2,6 +2,7 @@
 #ifndef _UAPI_FALLOC_H_
 #define _UAPI_FALLOC_H_
 
+#define FALLOC_FL_ALLOCATE_RANGE 0x00 /* allocate range */
 #define FALLOC_FL_KEEP_SIZE	0x01 /* default is extend size */
 #define FALLOC_FL_PUNCH_HOLE	0x02 /* de-allocates range */
 #define FALLOC_FL_NO_HIDE_STALE	0x04 /* reserved codepoint */
diff --git a/original/uapi/linux/fcntl.h b/original/uapi/linux/fcntl.h
index c0bcc18..87e2dec 100644
--- a/original/uapi/linux/fcntl.h
+++ b/original/uapi/linux/fcntl.h
@@ -16,6 +16,9 @@
 
 #define F_DUPFD_QUERY	(F_LINUX_SPECIFIC_BASE + 3)
 
+/* Was the file just created? */
+#define F_CREATED_QUERY	(F_LINUX_SPECIFIC_BASE + 4)
+
 /*
  * Cancel a blocking posix lock; internal use only until we expose an
  * asynchronous lock api to userspace:
@@ -87,37 +90,70 @@
 #define DN_ATTRIB	0x00000020	/* File changed attibutes */
 #define DN_MULTISHOT	0x80000000	/* Don't remove notifier */
 
+#define AT_FDCWD		-100    /* Special value for dirfd used to
+					   indicate openat should use the
+					   current working directory. */
+
+
+/* Generic flags for the *at(2) family of syscalls. */
+
+/* Reserved for per-syscall flags	0xff. */
+#define AT_SYMLINK_NOFOLLOW		0x100   /* Do not follow symbolic
+						   links. */
+/* Reserved for per-syscall flags	0x200 */
+#define AT_SYMLINK_FOLLOW		0x400   /* Follow symbolic links. */
+#define AT_NO_AUTOMOUNT			0x800	/* Suppress terminal automount
+						   traversal. */
+#define AT_EMPTY_PATH			0x1000	/* Allow empty relative
+						   pathname to operate on dirfd
+						   directly. */
+/*
+ * These flags are currently statx(2)-specific, but they could be made generic
+ * in the future and so they should not be used for other per-syscall flags.
+ */
+#define AT_STATX_SYNC_TYPE		0x6000	/* Type of synchronisation required from statx() */
+#define AT_STATX_SYNC_AS_STAT		0x0000	/* - Do whatever stat() does */
+#define AT_STATX_FORCE_SYNC		0x2000	/* - Force the attributes to be sync'd with the server */
+#define AT_STATX_DONT_SYNC		0x4000	/* - Don't sync attributes with the server */
+
+#define AT_RECURSIVE			0x8000	/* Apply to the entire subtree */
+
 /*
- * The constants AT_REMOVEDIR and AT_EACCESS have the same value.  AT_EACCESS is
- * meaningful only to faccessat, while AT_REMOVEDIR is meaningful only to
- * unlinkat.  The two functions do completely different things and therefore,
- * the flags can be allowed to overlap.  For example, passing AT_REMOVEDIR to
- * faccessat would be undefined behavior and thus treating it equivalent to
- * AT_EACCESS is valid undefined behavior.
+ * Per-syscall flags for the *at(2) family of syscalls.
+ *
+ * These are flags that are so syscall-specific that a user passing these flags
+ * to the wrong syscall is so "clearly wrong" that we can safely call such
+ * usage "undefined behaviour".
+ *
+ * For example, the constants AT_REMOVEDIR and AT_EACCESS have the same value.
+ * AT_EACCESS is meaningful only to faccessat, while AT_REMOVEDIR is meaningful
+ * only to unlinkat. The two functions do completely different things and
+ * therefore, the flags can be allowed to overlap. For example, passing
+ * AT_REMOVEDIR to faccessat would be undefined behavior and thus treating it
+ * equivalent to AT_EACCESS is valid undefined behavior.
+ *
+ * Note for implementers: When picking a new per-syscall AT_* flag, try to
+ * reuse already existing flags first. This leaves us with as many unused bits
+ * as possible, so we can use them for generic bits in the future if necessary.
  */
-#define AT_FDCWD		-100    /* Special value used to indicate
-                                           openat should use the current
-                                           working directory. */
-#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
+
+/* Flags for renameat2(2) (must match legacy RENAME_* flags). */
+#define AT_RENAME_NOREPLACE	0x0001
+#define AT_RENAME_EXCHANGE	0x0002
+#define AT_RENAME_WHITEOUT	0x0004
+
+/* Flag for faccessat(2). */
 #define AT_EACCESS		0x200	/* Test access permitted for
                                            effective IDs, not real IDs.  */
+/* Flag for unlinkat(2). */
 #define AT_REMOVEDIR		0x200   /* Remove directory instead of
                                            unlinking file.  */
-#define AT_SYMLINK_FOLLOW	0x400   /* Follow symbolic links.  */
-#define AT_NO_AUTOMOUNT		0x800	/* Suppress terminal automount traversal */
-#define AT_EMPTY_PATH		0x1000	/* Allow empty relative pathname */
-
-#define AT_STATX_SYNC_TYPE	0x6000	/* Type of synchronisation required from statx() */
-#define AT_STATX_SYNC_AS_STAT	0x0000	/* - Do whatever stat() does */
-#define AT_STATX_FORCE_SYNC	0x2000	/* - Force the attributes to be sync'd with the server */
-#define AT_STATX_DONT_SYNC	0x4000	/* - Don't sync attributes with the server */
-
-#define AT_RECURSIVE		0x8000	/* Apply to the entire subtree */
+/* Flags for name_to_handle_at(2). */
+#define AT_HANDLE_FID		0x200	/* File handle is needed to compare
+					   object identity and may not be
+					   usable with open_by_handle_at(2). */
+#define AT_HANDLE_MNT_ID_UNIQUE	0x001	/* Return the u64 unique mount ID. */
 
-/* Flags for name_to_handle_at(2). We reuse AT_ flag space to save bits... */
-#define AT_HANDLE_FID		AT_REMOVEDIR	/* file handle is needed to
-					compare object identity and may not
-					be usable to open_by_handle_at(2) */
 #if defined(__KERNEL__)
 #define AT_GETATTR_NOSEC	0x80000000
 #endif
diff --git a/original/uapi/linux/fib_rules.h b/original/uapi/linux/fib_rules.h
index 232df14..a6924dd 100644
--- a/original/uapi/linux/fib_rules.h
+++ b/original/uapi/linux/fib_rules.h
@@ -67,6 +67,7 @@ enum {
 	FRA_IP_PROTO,	/* ip proto */
 	FRA_SPORT_RANGE, /* sport */
 	FRA_DPORT_RANGE, /* dport */
+	FRA_DSCP,	/* dscp */
 	__FRA_MAX
 };
 
diff --git a/original/uapi/linux/fuse.h b/original/uapi/linux/fuse.h
index d08b99d..ab9ee78 100644
--- a/original/uapi/linux/fuse.h
+++ b/original/uapi/linux/fuse.h
@@ -217,6 +217,9 @@
  *  - add backing_id to fuse_open_out, add FOPEN_PASSTHROUGH open flag
  *  - add FUSE_NO_EXPORT_SUPPORT init flag
  *  - add FUSE_NOTIFY_RESEND, add FUSE_HAS_RESEND init flag
+ *
+ *  7.41
+ *  - add FUSE_ALLOW_IDMAP
  */
 
 #ifndef _LINUX_FUSE_H
@@ -252,7 +255,7 @@
 #define FUSE_KERNEL_VERSION 7
 
 /** Minor version number of this interface */
-#define FUSE_KERNEL_MINOR_VERSION 40
+#define FUSE_KERNEL_MINOR_VERSION 41
 
 /** The node ID of the root inode */
 #define FUSE_ROOT_ID 1
@@ -421,6 +424,7 @@ struct fuse_file_lock {
  * FUSE_NO_EXPORT_SUPPORT: explicitly disable export support
  * FUSE_HAS_RESEND: kernel supports resending pending requests, and the high bit
  *		    of the request ID indicates resend requests
+ * FUSE_ALLOW_IDMAP: allow creation of idmapped mounts
  */
 #define FUSE_ASYNC_READ		(1 << 0)
 #define FUSE_POSIX_LOCKS	(1 << 1)
@@ -466,6 +470,7 @@ struct fuse_file_lock {
 
 /* Obsolete alias for FUSE_DIRECT_IO_ALLOW_MMAP */
 #define FUSE_DIRECT_IO_RELAX	FUSE_DIRECT_IO_ALLOW_MMAP
+#define FUSE_ALLOW_IDMAP	(1ULL << 40)
 
 /**
  * CUSE INIT request/reply flags
@@ -633,6 +638,7 @@ enum fuse_opcode {
 	FUSE_SYNCFS		= 50,
 	FUSE_TMPFILE		= 51,
 	FUSE_STATX		= 52,
+	FUSE_CANONICAL_PATH	= 2016,
 
 	/* CUSE specific operations */
 	CUSE_INIT		= 4096,
@@ -984,6 +990,21 @@ struct fuse_fallocate_in {
  */
 #define FUSE_UNIQUE_RESEND (1ULL << 63)
 
+/**
+ * This value will be set by the kernel to
+ * (struct fuse_in_header).{uid,gid} fields in
+ * case when:
+ * - fuse daemon enabled FUSE_ALLOW_IDMAP
+ * - idmapping information is not available and uid/gid
+ *   can not be mapped in accordance with an idmapping.
+ *
+ * Note: an idmapping information always available
+ * for inode creation operations like:
+ * FUSE_MKNOD, FUSE_SYMLINK, FUSE_MKDIR, FUSE_TMPFILE,
+ * FUSE_CREATE and FUSE_RENAME2 (with RENAME_WHITEOUT).
+ */
+#define FUSE_INVALID_UIDGID ((uint32_t)(-1))
+
 struct fuse_in_header {
 	uint32_t	len;
 	uint32_t	opcode;
diff --git a/original/uapi/linux/hidraw.h b/original/uapi/linux/hidraw.h
index 33ebad8..d5ee269 100644
--- a/original/uapi/linux/hidraw.h
+++ b/original/uapi/linux/hidraw.h
@@ -46,6 +46,7 @@ struct hidraw_devinfo {
 /* The first byte of SOUTPUT and GOUTPUT is the report number */
 #define HIDIOCSOUTPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0B, len)
 #define HIDIOCGOUTPUT(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x0C, len)
+#define HIDIOCREVOKE	      _IOW('H', 0x0D, int) /* Revoke device access */
 
 #define HIDRAW_FIRST_MINOR 0
 #define HIDRAW_MAX_DEVICES 64
diff --git a/original/uapi/linux/if_packet.h b/original/uapi/linux/if_packet.h
index 9efc423..1d2718d 100644
--- a/original/uapi/linux/if_packet.h
+++ b/original/uapi/linux/if_packet.h
@@ -230,8 +230,8 @@ struct tpacket_hdr_v1 {
 	 * ts_first_pkt:
 	 *		Is always the time-stamp when the block was opened.
 	 *		Case a)	ZERO packets
-	 *			No packets to deal with but atleast you know the
-	 *			time-interval of this block.
+	 *			No packets to deal with but at least you know
+	 *			the time-interval of this block.
 	 *		Case b) Non-zero packets
 	 *			Use the ts of the first packet in the block.
 	 *
@@ -265,7 +265,8 @@ enum tpacket_versions {
    - struct tpacket_hdr
    - pad to TPACKET_ALIGNMENT=16
    - struct sockaddr_ll
-   - Gap, chosen so that packet data (Start+tp_net) alignes to TPACKET_ALIGNMENT=16
+   - Gap, chosen so that packet data (Start+tp_net) aligns to
+     TPACKET_ALIGNMENT=16
    - Start+tp_mac: [ Optional MAC header ]
    - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
    - Pad to align to TPACKET_ALIGNMENT=16
diff --git a/original/uapi/linux/in.h b/original/uapi/linux/in.h
index d358add..5d32d53 100644
--- a/original/uapi/linux/in.h
+++ b/original/uapi/linux/in.h
@@ -141,7 +141,7 @@ struct in_addr {
  */
 #define IP_PMTUDISC_INTERFACE		4
 /* weaker version of IP_PMTUDISC_INTERFACE, which allows packets to get
- * fragmented if they exeed the interface mtu
+ * fragmented if they exceed the interface mtu
  */
 #define IP_PMTUDISC_OMIT		5
 
diff --git a/original/uapi/linux/inet_diag.h b/original/uapi/linux/inet_diag.h
index 50655de..86bb2e8 100644
--- a/original/uapi/linux/inet_diag.h
+++ b/original/uapi/linux/inet_diag.h
@@ -143,7 +143,7 @@ enum {
 	INET_DIAG_SHUTDOWN,
 
 	/*
-	 * Next extenstions cannot be requested in struct inet_diag_req_v2:
+	 * Next extensions cannot be requested in struct inet_diag_req_v2:
 	 * its field idiag_ext has only 8 bits.
 	 */
 
diff --git a/original/uapi/linux/io_uring.h b/original/uapi/linux/io_uring.h
index adc2524..1fe79e7 100644
--- a/original/uapi/linux/io_uring.h
+++ b/original/uapi/linux/io_uring.h
@@ -440,11 +440,21 @@ struct io_uring_cqe {
  * IORING_CQE_F_SOCK_NONEMPTY	If set, more data to read after socket recv
  * IORING_CQE_F_NOTIF	Set for notification CQEs. Can be used to distinct
  * 			them from sends.
+ * IORING_CQE_F_BUF_MORE If set, the buffer ID set in the completion will get
+ *			more completions. In other words, the buffer is being
+ *			partially consumed, and will be used by the kernel for
+ *			more completions. This is only set for buffers used via
+ *			the incremental buffer consumption, as provided by
+ *			a ring buffer setup with IOU_PBUF_RING_INC. For any
+ *			other provided buffer type, all completions with a
+ *			buffer passed back is automatically returned to the
+ *			application.
  */
 #define IORING_CQE_F_BUFFER		(1U << 0)
 #define IORING_CQE_F_MORE		(1U << 1)
 #define IORING_CQE_F_SOCK_NONEMPTY	(1U << 2)
 #define IORING_CQE_F_NOTIF		(1U << 3)
+#define IORING_CQE_F_BUF_MORE		(1U << 4)
 
 #define IORING_CQE_BUFFER_SHIFT		16
 
@@ -507,6 +517,7 @@ struct io_cqring_offsets {
 #define IORING_ENTER_SQ_WAIT		(1U << 2)
 #define IORING_ENTER_EXT_ARG		(1U << 3)
 #define IORING_ENTER_REGISTERED_RING	(1U << 4)
+#define IORING_ENTER_ABS_TIMER		(1U << 5)
 
 /*
  * Passed in for io_uring_setup(2). Copied back with updated info on success
@@ -542,6 +553,7 @@ struct io_uring_params {
 #define IORING_FEAT_LINKED_FILE		(1U << 12)
 #define IORING_FEAT_REG_REG_RING	(1U << 13)
 #define IORING_FEAT_RECVSEND_BUNDLE	(1U << 14)
+#define IORING_FEAT_MIN_TIMEOUT		(1U << 15)
 
 /*
  * io_uring_register(2) opcodes and arguments
@@ -595,6 +607,11 @@ enum io_uring_register_op {
 	IORING_REGISTER_NAPI			= 27,
 	IORING_UNREGISTER_NAPI			= 28,
 
+	IORING_REGISTER_CLOCK			= 29,
+
+	/* clone registered buffers from source ring to current ring */
+	IORING_REGISTER_CLONE_BUFFERS		= 30,
+
 	/* this goes last */
 	IORING_REGISTER_LAST,
 
@@ -675,6 +692,21 @@ struct io_uring_restriction {
 	__u32 resv2[3];
 };
 
+struct io_uring_clock_register {
+	__u32	clockid;
+	__u32	__resv[3];
+};
+
+enum {
+	IORING_REGISTER_SRC_REGISTERED = 1,
+};
+
+struct io_uring_clone_buffers {
+	__u32	src_fd;
+	__u32	flags;
+	__u32	pad[6];
+};
+
 struct io_uring_buf {
 	__u64	addr;
 	__u32	len;
@@ -707,9 +739,17 @@ struct io_uring_buf_ring {
  *			mmap(2) with the offset set as:
  *			IORING_OFF_PBUF_RING | (bgid << IORING_OFF_PBUF_SHIFT)
  *			to get a virtual mapping for the ring.
+ * IOU_PBUF_RING_INC:	If set, buffers consumed from this buffer ring can be
+ *			consumed incrementally. Normally one (or more) buffers
+ *			are fully consumed. With incremental consumptions, it's
+ *			feasible to register big ranges of buffers, and each
+ *			use of it will consume only as much as it needs. This
+ *			requires that both the kernel and application keep
+ *			track of where the current read/recv index is at.
  */
 enum io_uring_register_pbuf_ring_flags {
 	IOU_PBUF_RING_MMAP	= 1,
+	IOU_PBUF_RING_INC	= 2,
 };
 
 /* argument for IORING_(UN)REGISTER_PBUF_RING */
@@ -758,7 +798,7 @@ enum io_uring_register_restriction_op {
 struct io_uring_getevents_arg {
 	__u64	sigmask;
 	__u32	sigmask_sz;
-	__u32	pad;
+	__u32	min_wait_usec;
 	__u64	ts;
 };
 
diff --git a/original/uapi/linux/ioam6_iptunnel.h b/original/uapi/linux/ioam6_iptunnel.h
index 38f6a8f..8aef21e 100644
--- a/original/uapi/linux/ioam6_iptunnel.h
+++ b/original/uapi/linux/ioam6_iptunnel.h
@@ -50,6 +50,12 @@ enum {
 	IOAM6_IPTUNNEL_FREQ_K,		/* u32 */
 	IOAM6_IPTUNNEL_FREQ_N,		/* u32 */
 
+	/* Tunnel src address.
+	 * For encap,auto modes.
+	 * Optional (automatic if not provided).
+	 */
+	IOAM6_IPTUNNEL_SRC,		/* struct in6_addr */
+
 	__IOAM6_IPTUNNEL_MAX,
 };
 
diff --git a/original/uapi/linux/iommufd.h b/original/uapi/linux/iommufd.h
index 4dde745..72010f7 100644
--- a/original/uapi/linux/iommufd.h
+++ b/original/uapi/linux/iommufd.h
@@ -4,8 +4,8 @@
 #ifndef _UAPI_IOMMUFD_H
 #define _UAPI_IOMMUFD_H
 
-#include <linux/types.h>
 #include <linux/ioctl.h>
+#include <linux/types.h>
 
 #define IOMMUFD_TYPE (';')
 
diff --git a/original/uapi/linux/kfd_ioctl.h b/original/uapi/linux/kfd_ioctl.h
index 285a366..717307d 100644
--- a/original/uapi/linux/kfd_ioctl.h
+++ b/original/uapi/linux/kfd_ioctl.h
@@ -42,9 +42,10 @@
  * - 1.14 - Update kfd_event_data
  * - 1.15 - Enable managing mappings in compute VMs with GEM_VA ioctl
  * - 1.16 - Add contiguous VRAM allocation flag
+ * - 1.17 - Add SDMA queue creation with target SDMA engine ID
  */
 #define KFD_IOCTL_MAJOR_VERSION 1
-#define KFD_IOCTL_MINOR_VERSION 16
+#define KFD_IOCTL_MINOR_VERSION 17
 
 struct kfd_ioctl_get_version_args {
 	__u32 major_version;	/* from KFD */
@@ -56,6 +57,7 @@ struct kfd_ioctl_get_version_args {
 #define KFD_IOC_QUEUE_TYPE_SDMA			0x1
 #define KFD_IOC_QUEUE_TYPE_COMPUTE_AQL		0x2
 #define KFD_IOC_QUEUE_TYPE_SDMA_XGMI		0x3
+#define KFD_IOC_QUEUE_TYPE_SDMA_BY_ENG_ID	0x4
 
 #define KFD_MAX_QUEUE_PERCENTAGE	100
 #define KFD_MAX_QUEUE_PRIORITY		15
@@ -78,6 +80,8 @@ struct kfd_ioctl_create_queue_args {
 	__u64 ctx_save_restore_address; /* to KFD */
 	__u32 ctx_save_restore_size;	/* to KFD */
 	__u32 ctl_stack_size;		/* to KFD */
+	__u32 sdma_engine_id;		/* to KFD */
+	__u32 pad;
 };
 
 struct kfd_ioctl_destroy_queue_args {
@@ -536,26 +540,29 @@ enum kfd_smi_event {
 	KFD_SMI_EVENT_ALL_PROCESS = 64
 };
 
+/* The reason of the page migration event */
 enum KFD_MIGRATE_TRIGGERS {
-	KFD_MIGRATE_TRIGGER_PREFETCH,
-	KFD_MIGRATE_TRIGGER_PAGEFAULT_GPU,
-	KFD_MIGRATE_TRIGGER_PAGEFAULT_CPU,
-	KFD_MIGRATE_TRIGGER_TTM_EVICTION
+	KFD_MIGRATE_TRIGGER_PREFETCH,		/* Prefetch to GPU VRAM or system memory */
+	KFD_MIGRATE_TRIGGER_PAGEFAULT_GPU,	/* GPU page fault recover */
+	KFD_MIGRATE_TRIGGER_PAGEFAULT_CPU,	/* CPU page fault recover */
+	KFD_MIGRATE_TRIGGER_TTM_EVICTION	/* TTM eviction */
 };
 
+/* The reason of user queue evition event */
 enum KFD_QUEUE_EVICTION_TRIGGERS {
-	KFD_QUEUE_EVICTION_TRIGGER_SVM,
-	KFD_QUEUE_EVICTION_TRIGGER_USERPTR,
-	KFD_QUEUE_EVICTION_TRIGGER_TTM,
-	KFD_QUEUE_EVICTION_TRIGGER_SUSPEND,
-	KFD_QUEUE_EVICTION_CRIU_CHECKPOINT,
-	KFD_QUEUE_EVICTION_CRIU_RESTORE
+	KFD_QUEUE_EVICTION_TRIGGER_SVM,		/* SVM buffer migration */
+	KFD_QUEUE_EVICTION_TRIGGER_USERPTR,	/* userptr movement */
+	KFD_QUEUE_EVICTION_TRIGGER_TTM,		/* TTM move buffer */
+	KFD_QUEUE_EVICTION_TRIGGER_SUSPEND,	/* GPU suspend */
+	KFD_QUEUE_EVICTION_CRIU_CHECKPOINT,	/* CRIU checkpoint */
+	KFD_QUEUE_EVICTION_CRIU_RESTORE		/* CRIU restore */
 };
 
+/* The reason of unmap buffer from GPU event */
 enum KFD_SVM_UNMAP_TRIGGERS {
-	KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY,
-	KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY_MIGRATE,
-	KFD_SVM_UNMAP_TRIGGER_UNMAP_FROM_CPU
+	KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY,	/* MMU notifier CPU buffer movement */
+	KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY_MIGRATE,/* MMU notifier page migration */
+	KFD_SVM_UNMAP_TRIGGER_UNMAP_FROM_CPU	/* Unmap to free the buffer */
 };
 
 #define KFD_SMI_EVENT_MASK_FROM_INDEX(i) (1ULL << ((i) - 1))
@@ -566,6 +573,77 @@ struct kfd_ioctl_smi_events_args {
 	__u32 anon_fd;	/* from KFD */
 };
 
+/*
+ * SVM event tracing via SMI system management interface
+ *
+ * Open event file descriptor
+ *    use ioctl AMDKFD_IOC_SMI_EVENTS, pass in gpuid and return a anonymous file
+ *    descriptor to receive SMI events.
+ *    If calling with sudo permission, then file descriptor can be used to receive
+ *    SVM events from all processes, otherwise, to only receive SVM events of same
+ *    process.
+ *
+ * To enable the SVM event
+ *    Write event file descriptor with KFD_SMI_EVENT_MASK_FROM_INDEX(event) bitmap
+ *    mask to start record the event to the kfifo, use bitmap mask combination
+ *    for multiple events. New event mask will overwrite the previous event mask.
+ *    KFD_SMI_EVENT_MASK_FROM_INDEX(KFD_SMI_EVENT_ALL_PROCESS) bit requires sudo
+ *    permisson to receive SVM events from all process.
+ *
+ * To receive the event
+ *    Application can poll file descriptor to wait for the events, then read event
+ *    from the file into a buffer. Each event is one line string message, starting
+ *    with the event id, then the event specific information.
+ *
+ * To decode event information
+ *    The following event format string macro can be used with sscanf to decode
+ *    the specific event information.
+ *    event triggers: the reason to generate the event, defined as enum for unmap,
+ *    eviction and migrate events.
+ *    node, from, to, prefetch_loc, preferred_loc: GPU ID, or 0 for system memory.
+ *    addr: user mode address, in pages
+ *    size: in pages
+ *    pid: the process ID to generate the event
+ *    ns: timestamp in nanosecond-resolution, starts at system boot time but
+ *        stops during suspend
+ *    migrate_update: GPU page fault is recovered by 'M' for migrate, 'U' for update
+ *    rw: 'W' for write page fault, 'R' for read page fault
+ *    rescheduled: 'R' if the queue restore failed and rescheduled to try again
+ */
+#define KFD_EVENT_FMT_UPDATE_GPU_RESET(reset_seq_num, reset_cause)\
+		"%x %s\n", (reset_seq_num), (reset_cause)
+
+#define KFD_EVENT_FMT_THERMAL_THROTTLING(bitmask, counter)\
+		"%llx:%llx\n", (bitmask), (counter)
+
+#define KFD_EVENT_FMT_VMFAULT(pid, task_name)\
+		"%x:%s\n", (pid), (task_name)
+
+#define KFD_EVENT_FMT_PAGEFAULT_START(ns, pid, addr, node, rw)\
+		"%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (rw)
+
+#define KFD_EVENT_FMT_PAGEFAULT_END(ns, pid, addr, node, migrate_update)\
+		"%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (migrate_update)
+
+#define KFD_EVENT_FMT_MIGRATE_START(ns, pid, start, size, from, to, prefetch_loc,\
+		preferred_loc, migrate_trigger)\
+		"%lld -%d @%lx(%lx) %x->%x %x:%x %d\n", (ns), (pid), (start), (size),\
+		(from), (to), (prefetch_loc), (preferred_loc), (migrate_trigger)
+
+#define KFD_EVENT_FMT_MIGRATE_END(ns, pid, start, size, from, to, migrate_trigger)\
+		"%lld -%d @%lx(%lx) %x->%x %d\n", (ns), (pid), (start), (size),\
+		(from), (to), (migrate_trigger)
+
+#define KFD_EVENT_FMT_QUEUE_EVICTION(ns, pid, node, evict_trigger)\
+		"%lld -%d %x %d\n", (ns), (pid), (node), (evict_trigger)
+
+#define KFD_EVENT_FMT_QUEUE_RESTORE(ns, pid, node, rescheduled)\
+		"%lld -%d %x %c\n", (ns), (pid), (node), (rescheduled)
+
+#define KFD_EVENT_FMT_UNMAP_FROM_GPU(ns, pid, addr, size, node, unmap_trigger)\
+		"%lld -%d @%lx(%lx) %x %d\n", (ns), (pid), (addr), (size),\
+		(node), (unmap_trigger)
+
 /**************************************************************************************************
  * CRIU IOCTLs (Checkpoint Restore In Userspace)
  *
diff --git a/original/uapi/linux/landlock.h b/original/uapi/linux/landlock.h
index 2c8dbc7..3374564 100644
--- a/original/uapi/linux/landlock.h
+++ b/original/uapi/linux/landlock.h
@@ -44,6 +44,12 @@ struct landlock_ruleset_attr {
 	 * flags`_).
 	 */
 	__u64 handled_access_net;
+	/**
+	 * @scoped: Bitmask of scopes (cf. `Scope flags`_)
+	 * restricting a Landlock domain from accessing outside
+	 * resources (e.g. IPCs).
+	 */
+	__u64 scoped;
 };
 
 /*
@@ -274,4 +280,28 @@ struct landlock_net_port_attr {
 #define LANDLOCK_ACCESS_NET_BIND_TCP			(1ULL << 0)
 #define LANDLOCK_ACCESS_NET_CONNECT_TCP			(1ULL << 1)
 /* clang-format on */
+
+/**
+ * DOC: scope
+ *
+ * Scope flags
+ * ~~~~~~~~~~~
+ *
+ * These flags enable to isolate a sandboxed process from a set of IPC actions.
+ * Setting a flag for a ruleset will isolate the Landlock domain to forbid
+ * connections to resources outside the domain.
+ *
+ * Scopes:
+ *
+ * - %LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: Restrict a sandboxed process from
+ *   connecting to an abstract UNIX socket created by a process outside the
+ *   related Landlock domain (e.g. a parent domain or a non-sandboxed process).
+ * - %LANDLOCK_SCOPE_SIGNAL: Restrict a sandboxed process from sending a signal
+ *   to another process outside the domain.
+ */
+/* clang-format off */
+#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET		(1ULL << 0)
+#define LANDLOCK_SCOPE_SIGNAL		                (1ULL << 1)
+/* clang-format on*/
+
 #endif /* _UAPI_LINUX_LANDLOCK_H */
diff --git a/original/uapi/linux/libc-compat.h b/original/uapi/linux/libc-compat.h
index 8254c93..0eca95c 100644
--- a/original/uapi/linux/libc-compat.h
+++ b/original/uapi/linux/libc-compat.h
@@ -140,25 +140,6 @@
 
 #endif /* _NETINET_IN_H */
 
-/* Coordinate with glibc netipx/ipx.h header. */
-#if defined(__NETIPX_IPX_H)
-
-#define __UAPI_DEF_SOCKADDR_IPX			0
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		0
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	0
-#define __UAPI_DEF_IPX_CONFIG_DATA		0
-#define __UAPI_DEF_IPX_ROUTE_DEF		0
-
-#else /* defined(__NETIPX_IPX_H) */
-
-#define __UAPI_DEF_SOCKADDR_IPX			1
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		1
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	1
-#define __UAPI_DEF_IPX_CONFIG_DATA		1
-#define __UAPI_DEF_IPX_ROUTE_DEF		1
-
-#endif /* defined(__NETIPX_IPX_H) */
-
 /* Definitions for xattr.h */
 #if defined(_SYS_XATTR_H)
 #define __UAPI_DEF_XATTR		0
@@ -240,23 +221,6 @@
 #define __UAPI_DEF_IP6_MTUINFO		1
 #endif
 
-/* Definitions for ipx.h */
-#ifndef __UAPI_DEF_SOCKADDR_IPX
-#define __UAPI_DEF_SOCKADDR_IPX			1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEFINITION
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		1
-#endif
-#ifndef __UAPI_DEF_IPX_INTERFACE_DEFINITION
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	1
-#endif
-#ifndef __UAPI_DEF_IPX_CONFIG_DATA
-#define __UAPI_DEF_IPX_CONFIG_DATA		1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEF
-#define __UAPI_DEF_IPX_ROUTE_DEF		1
-#endif
-
 /* Definitions for xattr.h */
 #ifndef __UAPI_DEF_XATTR
 #define __UAPI_DEF_XATTR		1
diff --git a/original/uapi/linux/lsm.h b/original/uapi/linux/lsm.h
index 33d8c9f..938593d 100644
--- a/original/uapi/linux/lsm.h
+++ b/original/uapi/linux/lsm.h
@@ -64,6 +64,7 @@ struct lsm_ctx {
 #define LSM_ID_LANDLOCK		110
 #define LSM_ID_IMA		111
 #define LSM_ID_EVM		112
+#define LSM_ID_IPE		113
 
 /*
  * LSM_ATTR_XXX definitions identify different LSM attributes
diff --git a/original/uapi/linux/mdio.h b/original/uapi/linux/mdio.h
index c0c8ec9..f0d3f26 100644
--- a/original/uapi/linux/mdio.h
+++ b/original/uapi/linux/mdio.h
@@ -23,6 +23,7 @@
 #define MDIO_MMD_DTEXS		5	/* DTE Extender Sublayer */
 #define MDIO_MMD_TC		6	/* Transmission Convergence */
 #define MDIO_MMD_AN		7	/* Auto-Negotiation */
+#define MDIO_MMD_POWER_UNIT	13	/* PHY Power Unit */
 #define MDIO_MMD_C22EXT		29	/* Clause 22 extension */
 #define MDIO_MMD_VEND1		30	/* Vendor specific 1 */
 #define MDIO_MMD_VEND2		31	/* Vendor specific 2 */
diff --git a/original/uapi/linux/nbd.h b/original/uapi/linux/nbd.h
index 80ce0ef..f1d468a 100644
--- a/original/uapi/linux/nbd.h
+++ b/original/uapi/linux/nbd.h
@@ -42,8 +42,9 @@ enum {
 	NBD_CMD_WRITE = 1,
 	NBD_CMD_DISC = 2,
 	NBD_CMD_FLUSH = 3,
-	NBD_CMD_TRIM = 4
+	NBD_CMD_TRIM = 4,
 	/* userspace defines additional extension commands */
+	NBD_CMD_WRITE_ZEROES = 6,
 };
 
 /* values for flags field, these are server interaction specific. */
@@ -51,12 +52,15 @@ enum {
 #define NBD_FLAG_READ_ONLY	(1 << 1) /* device is read-only */
 #define NBD_FLAG_SEND_FLUSH	(1 << 2) /* can flush writeback cache */
 #define NBD_FLAG_SEND_FUA	(1 << 3) /* send FUA (forced unit access) */
-/* there is a gap here to match userspace */
+#define NBD_FLAG_ROTATIONAL	(1 << 4) /* device is rotational */
 #define NBD_FLAG_SEND_TRIM	(1 << 5) /* send trim/discard */
+#define NBD_FLAG_SEND_WRITE_ZEROES (1 << 6) /* supports WRITE_ZEROES */
+/* there is a gap here to match userspace */
 #define NBD_FLAG_CAN_MULTI_CONN	(1 << 8)	/* Server supports multiple connections per export. */
 
 /* values for cmd flags in the upper 16 bits of request type */
 #define NBD_CMD_FLAG_FUA	(1 << 16) /* FUA (forced unit access) op */
+#define NBD_CMD_FLAG_NO_HOLE	(1 << 17) /* Do not punch a hole for WRITE_ZEROES */
 
 /* These are client behavior specific flags. */
 #define NBD_CFLAG_DESTROY_ON_DISCONNECT	(1 << 0) /* delete the nbd device on
diff --git a/original/uapi/linux/net_tstamp.h b/original/uapi/linux/net_tstamp.h
index a2c66b3..858339d 100644
--- a/original/uapi/linux/net_tstamp.h
+++ b/original/uapi/linux/net_tstamp.h
@@ -32,8 +32,9 @@ enum {
 	SOF_TIMESTAMPING_OPT_TX_SWHW = (1<<14),
 	SOF_TIMESTAMPING_BIND_PHC = (1 << 15),
 	SOF_TIMESTAMPING_OPT_ID_TCP = (1 << 16),
+	SOF_TIMESTAMPING_OPT_RX_FILTER = (1 << 17),
 
-	SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_ID_TCP,
+	SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_RX_FILTER,
 	SOF_TIMESTAMPING_MASK = (SOF_TIMESTAMPING_LAST - 1) |
 				 SOF_TIMESTAMPING_LAST
 };
diff --git a/original/uapi/linux/netdev.h b/original/uapi/linux/netdev.h
index 43742ac..7c308f0 100644
--- a/original/uapi/linux/netdev.h
+++ b/original/uapi/linux/netdev.h
@@ -93,6 +93,7 @@ enum {
 	NETDEV_A_PAGE_POOL_INFLIGHT,
 	NETDEV_A_PAGE_POOL_INFLIGHT_MEM,
 	NETDEV_A_PAGE_POOL_DETACH_TIME,
+	NETDEV_A_PAGE_POOL_DMABUF,
 
 	__NETDEV_A_PAGE_POOL_MAX,
 	NETDEV_A_PAGE_POOL_MAX = (__NETDEV_A_PAGE_POOL_MAX - 1)
@@ -131,6 +132,7 @@ enum {
 	NETDEV_A_QUEUE_IFINDEX,
 	NETDEV_A_QUEUE_TYPE,
 	NETDEV_A_QUEUE_NAPI_ID,
+	NETDEV_A_QUEUE_DMABUF,
 
 	__NETDEV_A_QUEUE_MAX,
 	NETDEV_A_QUEUE_MAX = (__NETDEV_A_QUEUE_MAX - 1)
@@ -173,6 +175,16 @@ enum {
 	NETDEV_A_QSTATS_MAX = (__NETDEV_A_QSTATS_MAX - 1)
 };
 
+enum {
+	NETDEV_A_DMABUF_IFINDEX = 1,
+	NETDEV_A_DMABUF_QUEUES,
+	NETDEV_A_DMABUF_FD,
+	NETDEV_A_DMABUF_ID,
+
+	__NETDEV_A_DMABUF_MAX,
+	NETDEV_A_DMABUF_MAX = (__NETDEV_A_DMABUF_MAX - 1)
+};
+
 enum {
 	NETDEV_CMD_DEV_GET = 1,
 	NETDEV_CMD_DEV_ADD_NTF,
@@ -186,6 +198,7 @@ enum {
 	NETDEV_CMD_QUEUE_GET,
 	NETDEV_CMD_NAPI_GET,
 	NETDEV_CMD_QSTATS_GET,
+	NETDEV_CMD_BIND_RX,
 
 	__NETDEV_CMD_MAX,
 	NETDEV_CMD_MAX = (__NETDEV_CMD_MAX - 1)
diff --git a/original/uapi/linux/netfilter/nf_tables.h b/original/uapi/linux/netfilter/nf_tables.h
index 639894e..9e90793 100644
--- a/original/uapi/linux/netfilter/nf_tables.h
+++ b/original/uapi/linux/netfilter/nf_tables.h
@@ -436,7 +436,7 @@ enum nft_set_elem_flags {
  * @NFTA_SET_ELEM_KEY: key value (NLA_NESTED: nft_data)
  * @NFTA_SET_ELEM_DATA: data value of mapping (NLA_NESTED: nft_data_attributes)
  * @NFTA_SET_ELEM_FLAGS: bitmask of nft_set_elem_flags (NLA_U32)
- * @NFTA_SET_ELEM_TIMEOUT: timeout value (NLA_U64)
+ * @NFTA_SET_ELEM_TIMEOUT: timeout value, zero means never times out (NLA_U64)
  * @NFTA_SET_ELEM_EXPIRATION: expiration time (NLA_U64)
  * @NFTA_SET_ELEM_USERDATA: user data (NLA_BINARY)
  * @NFTA_SET_ELEM_EXPR: expression (NLA_NESTED: nft_expr_attributes)
@@ -1694,7 +1694,7 @@ enum nft_flowtable_flags {
  *
  * @NFTA_FLOWTABLE_TABLE: name of the table containing the expression (NLA_STRING)
  * @NFTA_FLOWTABLE_NAME: name of this flow table (NLA_STRING)
- * @NFTA_FLOWTABLE_HOOK: netfilter hook configuration(NLA_U32)
+ * @NFTA_FLOWTABLE_HOOK: netfilter hook configuration (NLA_NESTED)
  * @NFTA_FLOWTABLE_USE: number of references to this flow table (NLA_U32)
  * @NFTA_FLOWTABLE_HANDLE: object handle (NLA_U64)
  * @NFTA_FLOWTABLE_FLAGS: flags (NLA_U32)
diff --git a/original/uapi/linux/nexthop.h b/original/uapi/linux/nexthop.h
index dd8787f..bc49baf 100644
--- a/original/uapi/linux/nexthop.h
+++ b/original/uapi/linux/nexthop.h
@@ -16,10 +16,15 @@ struct nhmsg {
 struct nexthop_grp {
 	__u32	id;	  /* nexthop id - must exist */
 	__u8	weight;   /* weight of this nexthop */
-	__u8	resvd1;
+	__u8	weight_high;	/* high order bits of weight */
 	__u16	resvd2;
 };
 
+static inline __u16 nexthop_grp_weight(const struct nexthop_grp *entry)
+{
+	return ((entry->weight_high << 8) | entry->weight) + 1;
+}
+
 enum {
 	NEXTHOP_GRP_TYPE_MPATH,  /* hash-threshold nexthop group
 				  * default type if not specified
@@ -33,6 +38,9 @@ enum {
 #define NHA_OP_FLAG_DUMP_STATS		BIT(0)
 #define NHA_OP_FLAG_DUMP_HW_STATS	BIT(1)
 
+/* Response OP_FLAGS. */
+#define NHA_OP_FLAG_RESP_GRP_RESVD_0	BIT(31)	/* Dump clears resvd fields. */
+
 enum {
 	NHA_UNSPEC,
 	NHA_ID,		/* u32; id for nexthop. id == 0 means auto-assign */
diff --git a/original/uapi/linux/nsfs.h b/original/uapi/linux/nsfs.h
index 5fad3d0..3412765 100644
--- a/original/uapi/linux/nsfs.h
+++ b/original/uapi/linux/nsfs.h
@@ -27,4 +27,19 @@
 /* Return thread-group leader id of pid in the target pid namespace. */
 #define NS_GET_TGID_IN_PIDNS	_IOR(NSIO, 0x9, int)
 
+struct mnt_ns_info {
+	__u32 size;
+	__u32 nr_mounts;
+	__u64 mnt_ns_id;
+};
+
+#define MNT_NS_INFO_SIZE_VER0 16 /* size of first published struct */
+
+/* Get information about namespace. */
+#define NS_MNT_GET_INFO		_IOR(NSIO, 10, struct mnt_ns_info)
+/* Get next namespace. */
+#define NS_MNT_GET_NEXT		_IOR(NSIO, 11, struct mnt_ns_info)
+/* Get previous namespace. */
+#define NS_MNT_GET_PREV		_IOR(NSIO, 12, struct mnt_ns_info)
+
 #endif /* __LINUX_NSFS_H */
diff --git a/original/uapi/linux/pci_regs.h b/original/uapi/linux/pci_regs.h
index 94c0099..12323b3 100644
--- a/original/uapi/linux/pci_regs.h
+++ b/original/uapi/linux/pci_regs.h
@@ -634,9 +634,11 @@
 #define  PCI_EXP_RTCTL_SENFEE	0x0002	/* System Error on Non-Fatal Error */
 #define  PCI_EXP_RTCTL_SEFEE	0x0004	/* System Error on Fatal Error */
 #define  PCI_EXP_RTCTL_PMEIE	0x0008	/* PME Interrupt Enable */
-#define  PCI_EXP_RTCTL_CRSSVE	0x0010	/* CRS Software Visibility Enable */
+#define  PCI_EXP_RTCTL_RRS_SVE	0x0010	/* Config RRS Software Visibility Enable */
+#define  PCI_EXP_RTCTL_CRSSVE PCI_EXP_RTCTL_RRS_SVE /* compatibility */
 #define PCI_EXP_RTCAP		0x1e	/* Root Capabilities */
-#define  PCI_EXP_RTCAP_CRSVIS	0x0001	/* CRS Software Visibility capability */
+#define  PCI_EXP_RTCAP_RRS_SV	0x0001	/* Config RRS Software Visibility */
+#define  PCI_EXP_RTCAP_CRSVIS PCI_EXP_RTCAP_RRS_SV /* compatibility */
 #define PCI_EXP_RTSTA		0x20	/* Root Status */
 #define  PCI_EXP_RTSTA_PME_RQ_ID 0x0000ffff /* PME Requester ID */
 #define  PCI_EXP_RTSTA_PME	0x00010000 /* PME status */
@@ -740,6 +742,7 @@
 #define PCI_EXT_CAP_ID_DVSEC	0x23	/* Designated Vendor-Specific */
 #define PCI_EXT_CAP_ID_DLF	0x25	/* Data Link Feature */
 #define PCI_EXT_CAP_ID_PL_16GT	0x26	/* Physical Layer 16.0 GT/s */
+#define PCI_EXT_CAP_ID_NPEM	0x29	/* Native PCIe Enclosure Management */
 #define PCI_EXT_CAP_ID_PL_32GT  0x2A    /* Physical Layer 32.0 GT/s */
 #define PCI_EXT_CAP_ID_DOE	0x2E	/* Data Object Exchange */
 #define PCI_EXT_CAP_ID_MAX	PCI_EXT_CAP_ID_DOE
@@ -1121,6 +1124,40 @@
 #define  PCI_PL_16GT_LE_CTRL_USP_TX_PRESET_MASK		0x000000F0
 #define  PCI_PL_16GT_LE_CTRL_USP_TX_PRESET_SHIFT	4
 
+/* Native PCIe Enclosure Management */
+#define PCI_NPEM_CAP     0x04 /* NPEM capability register */
+#define  PCI_NPEM_CAP_CAPABLE     0x00000001 /* NPEM Capable */
+
+#define PCI_NPEM_CTRL    0x08 /* NPEM control register */
+#define  PCI_NPEM_CTRL_ENABLE     0x00000001 /* NPEM Enable */
+
+/*
+ * Native PCIe Enclosure Management indication bits and Reset command bit
+ * are corresponding for capability and control registers.
+ */
+#define  PCI_NPEM_CMD_RESET       0x00000002 /* Reset Command */
+#define  PCI_NPEM_IND_OK          0x00000004 /* OK */
+#define  PCI_NPEM_IND_LOCATE      0x00000008 /* Locate */
+#define  PCI_NPEM_IND_FAIL        0x00000010 /* Fail */
+#define  PCI_NPEM_IND_REBUILD     0x00000020 /* Rebuild */
+#define  PCI_NPEM_IND_PFA         0x00000040 /* Predicted Failure Analysis */
+#define  PCI_NPEM_IND_HOTSPARE    0x00000080 /* Hot Spare */
+#define  PCI_NPEM_IND_ICA         0x00000100 /* In Critical Array */
+#define  PCI_NPEM_IND_IFA         0x00000200 /* In Failed Array */
+#define  PCI_NPEM_IND_IDT         0x00000400 /* Device Type */
+#define  PCI_NPEM_IND_DISABLED    0x00000800 /* Disabled */
+#define  PCI_NPEM_IND_SPEC_0      0x01000000
+#define  PCI_NPEM_IND_SPEC_1      0x02000000
+#define  PCI_NPEM_IND_SPEC_2      0x04000000
+#define  PCI_NPEM_IND_SPEC_3      0x08000000
+#define  PCI_NPEM_IND_SPEC_4      0x10000000
+#define  PCI_NPEM_IND_SPEC_5      0x20000000
+#define  PCI_NPEM_IND_SPEC_6      0x40000000
+#define  PCI_NPEM_IND_SPEC_7      0x80000000
+
+#define PCI_NPEM_STATUS  0x0c /* NPEM status register */
+#define  PCI_NPEM_STATUS_CC       0x00000001 /* Command Completed */
+
 /* Data Object Exchange */
 #define PCI_DOE_CAP		0x04    /* DOE Capabilities Register */
 #define  PCI_DOE_CAP_INT_SUP			0x00000001  /* Interrupt Support */
diff --git a/original/uapi/linux/pkt_cls.h b/original/uapi/linux/pkt_cls.h
index d36d9cd..2c32080 100644
--- a/original/uapi/linux/pkt_cls.h
+++ b/original/uapi/linux/pkt_cls.h
@@ -246,16 +246,19 @@ struct tc_u32_key {
 };
 
 struct tc_u32_sel {
-	unsigned char		flags;
-	unsigned char		offshift;
-	unsigned char		nkeys;
-
-	__be16			offmask;
-	__u16			off;
-	short			offoff;
-
-	short			hoff;
-	__be32			hmask;
+	/* New members MUST be added within the __struct_group() macro below. */
+	__struct_group(tc_u32_sel_hdr, hdr, /* no attrs */,
+		unsigned char		flags;
+		unsigned char		offshift;
+		unsigned char		nkeys;
+
+		__be16			offmask;
+		__u16			off;
+		short			offoff;
+
+		short			hoff;
+		__be32			hmask;
+	);
 	struct tc_u32_key	keys[];
 };
 
diff --git a/original/uapi/linux/ptp_clock.h b/original/uapi/linux/ptp_clock.h
index 053b40d..18eefa6 100644
--- a/original/uapi/linux/ptp_clock.h
+++ b/original/uapi/linux/ptp_clock.h
@@ -155,13 +155,25 @@ struct ptp_sys_offset {
 	struct ptp_clock_time ts[2 * PTP_MAX_SAMPLES + 1];
 };
 
+/*
+ * ptp_sys_offset_extended - data structure for IOCTL operation
+ *			     PTP_SYS_OFFSET_EXTENDED
+ *
+ * @n_samples:	Desired number of measurements.
+ * @clockid:	clockid of a clock-base used for pre/post timestamps.
+ * @rsv:	Reserved for future use.
+ * @ts:		Array of samples in the form [pre-TS, PHC, post-TS]. The
+ *		kernel provides @n_samples.
+ *
+ * Starting from kernel 6.12 and onwards, the first word of the reserved-field
+ * is used for @clockid. That's backward compatible since previous kernel
+ * expect all three reserved words (@rsv[3]) to be 0 while the clockid (first
+ * word in the new structure) for CLOCK_REALTIME is '0'.
+ */
 struct ptp_sys_offset_extended {
-	unsigned int n_samples; /* Desired number of measurements. */
-	unsigned int rsv[3];    /* Reserved for future use. */
-	/*
-	 * Array of [system, phc, system] time stamps. The kernel will provide
-	 * 3*n_samples time stamps.
-	 */
+	unsigned int n_samples;
+	__kernel_clockid_t clockid;
+	unsigned int rsv[2];
 	struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
 };
 
diff --git a/original/uapi/linux/rkisp1-config.h b/original/uapi/linux/rkisp1-config.h
index 6eeaf8b..430dace 100644
--- a/original/uapi/linux/rkisp1-config.h
+++ b/original/uapi/linux/rkisp1-config.h
@@ -164,6 +164,11 @@
 #define RKISP1_CIF_ISP_DPF_MAX_NLF_COEFFS      17
 #define RKISP1_CIF_ISP_DPF_MAX_SPATIAL_COEFFS  6
 
+/*
+ * Compand
+ */
+#define RKISP1_CIF_ISP_COMPAND_NUM_POINTS	64
+
 /*
  * Measurement types
  */
@@ -851,6 +856,39 @@ struct rkisp1_params_cfg {
 	struct rkisp1_cif_isp_isp_other_cfg others;
 };
 
+/**
+ * struct rkisp1_cif_isp_compand_bls_config - Rockchip ISP1 Companding parameters (BLS)
+ * @r: Fixed subtraction value for Bayer pattern R
+ * @gr: Fixed subtraction value for Bayer pattern Gr
+ * @gb: Fixed subtraction value for Bayer pattern Gb
+ * @b: Fixed subtraction value for Bayer pattern B
+ *
+ * The values will be subtracted from the sensor values. Note that unlike the
+ * dedicated BLS block, the BLS values in the compander are 20-bit unsigned.
+ */
+struct rkisp1_cif_isp_compand_bls_config {
+	__u32 r;
+	__u32 gr;
+	__u32 gb;
+	__u32 b;
+};
+
+/**
+ * struct rkisp1_cif_isp_compand_curve_config - Rockchip ISP1 Companding
+ * parameters (expand and compression curves)
+ * @px: Compand curve x-values. Each value stores the distance from the
+ *      previous x-value, expressed as log2 of the distance on 5 bits.
+ * @x: Compand curve x-values. The functionality of these parameters are
+ *     unknown due to do a lack of hardware documentation, but these are left
+ *     here for future compatibility purposes.
+ * @y: Compand curve y-values
+ */
+struct rkisp1_cif_isp_compand_curve_config {
+	__u8 px[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+	__u32 x[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+	__u32 y[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
+};
+
 /*---------- PART2: Measurement Statistics ------------*/
 
 /**
@@ -996,4 +1034,544 @@ struct rkisp1_stat_buffer {
 	struct rkisp1_cif_isp_stat params;
 };
 
+/*---------- PART3: Extensible Configuration Parameters  ------------*/
+
+/**
+ * enum rkisp1_ext_params_block_type - RkISP1 extensible params block type
+ *
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS: Black level subtraction
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC: Defect pixel cluster correction
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_SDG: Sensor de-gamma
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_GAIN: Auto white balance gains
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_FLT: ISP filtering
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_BDM: Bayer de-mosaic
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_CTK: Cross-talk correction
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_GOC: Gamma out correction
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF: De-noise pre-filter
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF_STRENGTH: De-noise pre-filter strength
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_CPROC: Color processing
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_IE: Image effects
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_LSC: Lens shading correction
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_MEAS: Auto white balance statistics
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_HST_MEAS: Histogram statistics
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_AEC_MEAS: Auto exposure statistics
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_AFC_MEAS: Auto-focus statistics
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_BLS: BLS in the compand block
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_EXPAND: Companding expand curve
+ * @RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_COMPRESS: Companding compress curve
+ */
+enum rkisp1_ext_params_block_type {
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_SDG,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_GAIN,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_FLT,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_BDM,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_CTK,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_GOC,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF_STRENGTH,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_CPROC,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_IE,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_LSC,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_MEAS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_HST_MEAS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_AEC_MEAS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_AFC_MEAS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_BLS,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_EXPAND,
+	RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_COMPRESS,
+};
+
+#define RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE	(1U << 0)
+#define RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE	(1U << 1)
+
+/**
+ * struct rkisp1_ext_params_block_header - RkISP1 extensible parameters block
+ *					   header
+ *
+ * This structure represents the common part of all the ISP configuration
+ * blocks. Each parameters block shall embed an instance of this structure type
+ * as its first member, followed by the block-specific configuration data. The
+ * driver inspects this common header to discern the block type and its size and
+ * properly handle the block content by casting it to the correct block-specific
+ * type.
+ *
+ * The @type field is one of the values enumerated by
+ * :c:type:`rkisp1_ext_params_block_type` and specifies how the data should be
+ * interpreted by the driver. The @size field specifies the size of the
+ * parameters block and is used by the driver for validation purposes.
+ *
+ * The @flags field is a bitmask of per-block flags RKISP1_EXT_PARAMS_FL_*.
+ *
+ * When userspace wants to configure and enable an ISP block it shall fully
+ * populate the block configuration and set the
+ * RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE bit in the @flags field.
+ *
+ * When userspace simply wants to disable an ISP block the
+ * RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE bit should be set in @flags field. The
+ * driver ignores the rest of the block configuration structure in this case.
+ *
+ * If a new configuration of an ISP block has to be applied userspace shall
+ * fully populate the ISP block configuration and omit setting the
+ * RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE and RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE bits
+ * in the @flags field.
+ *
+ * Setting both the RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE and
+ * RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE bits in the @flags field is not allowed
+ * and not accepted by the driver.
+ *
+ * Userspace is responsible for correctly populating the parameters block header
+ * fields (@type, @flags and @size) and the block-specific parameters.
+ *
+ * For example:
+ *
+ * .. code-block:: c
+ *
+ *	void populate_bls(struct rkisp1_ext_params_block_header *block) {
+ *		struct rkisp1_ext_params_bls_config *bls =
+ *			(struct rkisp1_ext_params_bls_config *)block;
+ *
+ *		bls->header.type = RKISP1_EXT_PARAMS_BLOCK_ID_BLS;
+ *		bls->header.flags = RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE;
+ *		bls->header.size = sizeof(*bls);
+ *
+ *		bls->config.enable_auto = 0;
+ *		bls->config.fixed_val.r = blackLevelRed_;
+ *		bls->config.fixed_val.gr = blackLevelGreenR_;
+ *		bls->config.fixed_val.gb = blackLevelGreenB_;
+ *		bls->config.fixed_val.b = blackLevelBlue_;
+ *	}
+ *
+ * @type: The parameters block type, see
+ *	  :c:type:`rkisp1_ext_params_block_type`
+ * @flags: A bitmask of block flags
+ * @size: Size (in bytes) of the parameters block, including this header
+ */
+struct rkisp1_ext_params_block_header {
+	__u16 type;
+	__u16 flags;
+	__u32 size;
+};
+
+/**
+ * struct rkisp1_ext_params_bls_config - RkISP1 extensible params BLS config
+ *
+ * RkISP1 extensible parameters Black Level Subtraction configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Black Level Subtraction configuration, see
+ *	    :c:type:`rkisp1_cif_isp_bls_config`
+ */
+struct rkisp1_ext_params_bls_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_bls_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_dpcc_config - RkISP1 extensible params DPCC config
+ *
+ * RkISP1 extensible parameters Defective Pixel Cluster Correction configuration
+ * block. Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Defective Pixel Cluster Correction configuration, see
+ *	    :c:type:`rkisp1_cif_isp_dpcc_config`
+ */
+struct rkisp1_ext_params_dpcc_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_dpcc_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_sdg_config - RkISP1 extensible params SDG config
+ *
+ * RkISP1 extensible parameters Sensor Degamma configuration block. Identified
+ * by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_SDG`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Sensor Degamma configuration, see
+ *	    :c:type:`rkisp1_cif_isp_sdg_config`
+ */
+struct rkisp1_ext_params_sdg_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_sdg_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_lsc_config - RkISP1 extensible params LSC config
+ *
+ * RkISP1 extensible parameters Lens Shading Correction configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_LSC`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Lens Shading Correction configuration, see
+ *	    :c:type:`rkisp1_cif_isp_lsc_config`
+ */
+struct rkisp1_ext_params_lsc_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_lsc_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_awb_gain_config - RkISP1 extensible params AWB
+ *					      gain config
+ *
+ * RkISP1 extensible parameters Auto-White Balance Gains configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_GAIN`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Auto-White Balance Gains configuration, see
+ *	    :c:type:`rkisp1_cif_isp_awb_gain_config`
+ */
+struct rkisp1_ext_params_awb_gain_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_awb_gain_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_flt_config - RkISP1 extensible params FLT config
+ *
+ * RkISP1 extensible parameters Filter configuration block. Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_FLT`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Filter configuration, see :c:type:`rkisp1_cif_isp_flt_config`
+ */
+struct rkisp1_ext_params_flt_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_flt_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_bdm_config - RkISP1 extensible params BDM config
+ *
+ * RkISP1 extensible parameters Demosaicing configuration block. Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_BDM`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Demosaicing configuration, see :c:type:`rkisp1_cif_isp_bdm_config`
+ */
+struct rkisp1_ext_params_bdm_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_bdm_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_ctk_config - RkISP1 extensible params CTK config
+ *
+ * RkISP1 extensible parameters Cross-Talk configuration block. Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_CTK`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Cross-Talk configuration, see :c:type:`rkisp1_cif_isp_ctk_config`
+ */
+struct rkisp1_ext_params_ctk_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_ctk_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_goc_config - RkISP1 extensible params GOC config
+ *
+ * RkISP1 extensible parameters Gamma-Out configuration block. Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_GOC`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Gamma-Out configuration, see :c:type:`rkisp1_cif_isp_goc_config`
+ */
+struct rkisp1_ext_params_goc_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_goc_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_dpf_config - RkISP1 extensible params DPF config
+ *
+ * RkISP1 extensible parameters De-noise Pre-Filter configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: De-noise Pre-Filter configuration, see
+ *	    :c:type:`rkisp1_cif_isp_dpf_config`
+ */
+struct rkisp1_ext_params_dpf_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_dpf_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_dpf_strength_config - RkISP1 extensible params DPF
+ *						  strength config
+ *
+ * RkISP1 extensible parameters De-noise Pre-Filter strength configuration
+ * block. Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF_STRENGTH`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: De-noise Pre-Filter strength configuration, see
+ *	    :c:type:`rkisp1_cif_isp_dpf_strength_config`
+ */
+struct rkisp1_ext_params_dpf_strength_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_dpf_strength_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_cproc_config - RkISP1 extensible params CPROC config
+ *
+ * RkISP1 extensible parameters Color Processing configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_CPROC`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Color processing configuration, see
+ *	    :c:type:`rkisp1_cif_isp_cproc_config`
+ */
+struct rkisp1_ext_params_cproc_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_cproc_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_ie_config - RkISP1 extensible params IE config
+ *
+ * RkISP1 extensible parameters Image Effect configuration block. Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_IE`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Image Effect configuration, see :c:type:`rkisp1_cif_isp_ie_config`
+ */
+struct rkisp1_ext_params_ie_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_ie_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_awb_meas_config - RkISP1 extensible params AWB
+ *					      Meas config
+ *
+ * RkISP1 extensible parameters Auto-White Balance Measurement configuration
+ * block. Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_MEAS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Auto-White Balance measure configuration, see
+ *	    :c:type:`rkisp1_cif_isp_awb_meas_config`
+ */
+struct rkisp1_ext_params_awb_meas_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_awb_meas_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_hst_config - RkISP1 extensible params Histogram config
+ *
+ * RkISP1 extensible parameters Histogram statistics configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_HST_MEAS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Histogram statistics configuration, see
+ *	    :c:type:`rkisp1_cif_isp_hst_config`
+ */
+struct rkisp1_ext_params_hst_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_hst_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_aec_config - RkISP1 extensible params AEC config
+ *
+ * RkISP1 extensible parameters Auto-Exposure statistics configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_AEC_MEAS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Auto-Exposure statistics configuration, see
+ *	    :c:type:`rkisp1_cif_isp_aec_config`
+ */
+struct rkisp1_ext_params_aec_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_aec_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_afc_config - RkISP1 extensible params AFC config
+ *
+ * RkISP1 extensible parameters Auto-Focus statistics configuration block.
+ * Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_AFC_MEAS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Auto-Focus statistics configuration, see
+ *	    :c:type:`rkisp1_cif_isp_afc_config`
+ */
+struct rkisp1_ext_params_afc_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_afc_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_compand_bls_config - RkISP1 extensible params
+ * Compand BLS config
+ *
+ * RkISP1 extensible parameters Companding configuration block (black level
+ * subtraction). Identified by :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_BLS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Companding BLS configuration, see
+ *	    :c:type:`rkisp1_cif_isp_compand_bls_config`
+ */
+struct rkisp1_ext_params_compand_bls_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_compand_bls_config config;
+} __attribute__((aligned(8)));
+
+/**
+ * struct rkisp1_ext_params_compand_curve_config - RkISP1 extensible params
+ * Compand curve config
+ *
+ * RkISP1 extensible parameters Companding configuration block (expand and
+ * compression curves). Identified by
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_EXPAND` or
+ * :c:type:`RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_COMPRESS`.
+ *
+ * @header: The RkISP1 extensible parameters header, see
+ *	    :c:type:`rkisp1_ext_params_block_header`
+ * @config: Companding curve configuration, see
+ *	    :c:type:`rkisp1_cif_isp_compand_curve_config`
+ */
+struct rkisp1_ext_params_compand_curve_config {
+	struct rkisp1_ext_params_block_header header;
+	struct rkisp1_cif_isp_compand_curve_config config;
+} __attribute__((aligned(8)));
+
+/*
+ * The rkisp1_ext_params_compand_curve_config structure is counted twice as it
+ * is used for both the COMPAND_EXPAND and COMPAND_COMPRESS block types.
+ */
+#define RKISP1_EXT_PARAMS_MAX_SIZE					\
+	(sizeof(struct rkisp1_ext_params_bls_config)			+\
+	sizeof(struct rkisp1_ext_params_dpcc_config)			+\
+	sizeof(struct rkisp1_ext_params_sdg_config)			+\
+	sizeof(struct rkisp1_ext_params_lsc_config)			+\
+	sizeof(struct rkisp1_ext_params_awb_gain_config)		+\
+	sizeof(struct rkisp1_ext_params_flt_config)			+\
+	sizeof(struct rkisp1_ext_params_bdm_config)			+\
+	sizeof(struct rkisp1_ext_params_ctk_config)			+\
+	sizeof(struct rkisp1_ext_params_goc_config)			+\
+	sizeof(struct rkisp1_ext_params_dpf_config)			+\
+	sizeof(struct rkisp1_ext_params_dpf_strength_config)		+\
+	sizeof(struct rkisp1_ext_params_cproc_config)			+\
+	sizeof(struct rkisp1_ext_params_ie_config)			+\
+	sizeof(struct rkisp1_ext_params_awb_meas_config)		+\
+	sizeof(struct rkisp1_ext_params_hst_config)			+\
+	sizeof(struct rkisp1_ext_params_aec_config)			+\
+	sizeof(struct rkisp1_ext_params_afc_config)			+\
+	sizeof(struct rkisp1_ext_params_compand_bls_config)		+\
+	sizeof(struct rkisp1_ext_params_compand_curve_config)		+\
+	sizeof(struct rkisp1_ext_params_compand_curve_config))
+
+/**
+ * enum rksip1_ext_param_buffer_version - RkISP1 extensible parameters version
+ *
+ * @RKISP1_EXT_PARAM_BUFFER_V1: First version of RkISP1 extensible parameters
+ */
+enum rksip1_ext_param_buffer_version {
+	RKISP1_EXT_PARAM_BUFFER_V1 = 1,
+};
+
+/**
+ * struct rkisp1_ext_params_cfg - RkISP1 extensible parameters configuration
+ *
+ * This struct contains the configuration parameters of the RkISP1 ISP
+ * algorithms, serialized by userspace into a data buffer. Each configuration
+ * parameter block is represented by a block-specific structure which contains a
+ * :c:type:`rkisp1_ext_params_block_header` entry as first member. Userspace
+ * populates the @data buffer with configuration parameters for the blocks that
+ * it intends to configure. As a consequence, the data buffer effective size
+ * changes according to the number of ISP blocks that userspace intends to
+ * configure and is set by userspace in the @data_size field.
+ *
+ * The parameters buffer is versioned by the @version field to allow modifying
+ * and extending its definition. Userspace shall populate the @version field to
+ * inform the driver about the version it intends to use. The driver will parse
+ * and handle the @data buffer according to the data layout specific to the
+ * indicated version and return an error if the desired version is not
+ * supported.
+ *
+ * Currently the single RKISP1_EXT_PARAM_BUFFER_V1 version is supported.
+ * When a new format version will be added, a mechanism for userspace to query
+ * the supported format versions will be implemented in the form of a read-only
+ * V4L2 control. If such control is not available, userspace should assume only
+ * RKISP1_EXT_PARAM_BUFFER_V1 is supported by the driver.
+ *
+ * For each ISP block that userspace wants to configure, a block-specific
+ * structure is appended to the @data buffer, one after the other without gaps
+ * in between nor overlaps. Userspace shall populate the @data_size field with
+ * the effective size, in bytes, of the @data buffer.
+ *
+ * The expected memory layout of the parameters buffer is::
+ *
+ *	+-------------------- struct rkisp1_ext_params_cfg -------------------+
+ *	| version = RKISP_EXT_PARAMS_BUFFER_V1;                               |
+ *	| data_size = sizeof(struct rkisp1_ext_params_bls_config)             |
+ *	|           + sizeof(struct rkisp1_ext_params_dpcc_config);           |
+ *	| +------------------------- data  ---------------------------------+ |
+ *	| | +------------- struct rkisp1_ext_params_bls_config -----------+ | |
+ *	| | | +-------- struct rkisp1_ext_params_block_header  ---------+ | | |
+ *	| | | | type = RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS;                | | | |
+ *	| | | | flags = RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE;              | | | |
+ *	| | | | size = sizeof(struct rkisp1_ext_params_bls_config);     | | | |
+ *	| | | +---------------------------------------------------------+ | | |
+ *	| | | +---------- struct rkisp1_cif_isp_bls_config -------------+ | | |
+ *	| | | | enable_auto = 0;                                        | | | |
+ *	| | | | fixed_val.r = 256;                                      | | | |
+ *	| | | | fixed_val.gr = 256;                                     | | | |
+ *	| | | | fixed_val.gb = 256;                                     | | | |
+ *	| | | | fixed_val.b = 256;                                      | | | |
+ *	| | | +---------------------------------------------------------+ | | |
+ *	| | +------------ struct rkisp1_ext_params_dpcc_config -----------+ | |
+ *	| | | +-------- struct rkisp1_ext_params_block_header  ---------+ | | |
+ *	| | | | type = RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC;               | | | |
+ *	| | | | flags = RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE;              | | | |
+ *	| | | | size = sizeof(struct rkisp1_ext_params_dpcc_config);    | | | |
+ *	| | | +---------------------------------------------------------+ | | |
+ *	| | | +---------- struct rkisp1_cif_isp_dpcc_config ------------+ | | |
+ *	| | | | mode = RKISP1_CIF_ISP_DPCC_MODE_STAGE1_ENABLE;          | | | |
+ *	| | | | output_mode =                                           | | | |
+ *	| | | |   RKISP1_CIF_ISP_DPCC_OUTPUT_MODE_STAGE1_INCL_G_CENTER; | | | |
+ *	| | | | set_use = ... ;                                         | | | |
+ *	| | | | ...  = ... ;                                            | | | |
+ *	| | | +---------------------------------------------------------+ | | |
+ *	| | +-------------------------------------------------------------+ | |
+ *	| +-----------------------------------------------------------------+ |
+ *	+---------------------------------------------------------------------+
+ *
+ * @version: The RkISP1 extensible parameters buffer version, see
+ *	     :c:type:`rksip1_ext_param_buffer_version`
+ * @data_size: The RkISP1 configuration data effective size, excluding this
+ *	       header
+ * @data: The RkISP1 extensible configuration data blocks
+ */
+struct rkisp1_ext_params_cfg {
+	__u32 version;
+	__u32 data_size;
+	__u8 data[RKISP1_EXT_PARAMS_MAX_SIZE];
+};
+
 #endif /* _UAPI_RKISP1_CONFIG_H */
diff --git a/original/uapi/linux/sched.h b/original/uapi/linux/sched.h
index 3bac0a8..359a14c 100644
--- a/original/uapi/linux/sched.h
+++ b/original/uapi/linux/sched.h
@@ -118,6 +118,7 @@ struct clone_args {
 /* SCHED_ISO: reserved but not implemented yet */
 #define SCHED_IDLE		5
 #define SCHED_DEADLINE		6
+#define SCHED_EXT		7
 
 /* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
 #define SCHED_RESET_ON_FORK     0x40000000
diff --git a/original/uapi/linux/sched/types.h b/original/uapi/linux/sched/types.h
index 9066238..bf6e9ae 100644
--- a/original/uapi/linux/sched/types.h
+++ b/original/uapi/linux/sched/types.h
@@ -58,9 +58,9 @@
  *
  * This is reflected by the following fields of the sched_attr structure:
  *
- *  @sched_deadline	representative of the task's deadline
- *  @sched_runtime	representative of the task's runtime
- *  @sched_period	representative of the task's period
+ *  @sched_deadline	representative of the task's deadline in nanoseconds
+ *  @sched_runtime	representative of the task's runtime in nanoseconds
+ *  @sched_period	representative of the task's period in nanoseconds
  *
  * Given this task model, there are a multiplicity of scheduling algorithms
  * and policies, that can be used to ensure all the tasks will make their
diff --git a/original/uapi/linux/serio.h b/original/uapi/linux/serio.h
index ed2a96f..5a2af09 100644
--- a/original/uapi/linux/serio.h
+++ b/original/uapi/linux/serio.h
@@ -83,5 +83,6 @@
 #define SERIO_PULSE8_CEC	0x40
 #define SERIO_RAINSHADOW_CEC	0x41
 #define SERIO_FSIA6B	0x42
+#define SERIO_EXTRON_DA_HD_4K_PLUS	0x43
 
 #endif /* _UAPI_SERIO_H */
diff --git a/original/uapi/linux/smc.h b/original/uapi/linux/smc.h
index b531e3e..1f58cb0 100644
--- a/original/uapi/linux/smc.h
+++ b/original/uapi/linux/smc.h
@@ -127,6 +127,8 @@ enum {
 	SMC_NLA_LGR_R_NET_COOKIE,	/* u64 */
 	SMC_NLA_LGR_R_PAD,		/* flag */
 	SMC_NLA_LGR_R_BUF_TYPE,		/* u8 */
+	SMC_NLA_LGR_R_SNDBUF_ALLOC,	/* uint */
+	SMC_NLA_LGR_R_RMB_ALLOC,	/* uint */
 	__SMC_NLA_LGR_R_MAX,
 	SMC_NLA_LGR_R_MAX = __SMC_NLA_LGR_R_MAX - 1
 };
@@ -162,6 +164,8 @@ enum {
 	SMC_NLA_LGR_D_V2_COMMON,	/* nest */
 	SMC_NLA_LGR_D_EXT_GID,		/* u64 */
 	SMC_NLA_LGR_D_PEER_EXT_GID,	/* u64 */
+	SMC_NLA_LGR_D_SNDBUF_ALLOC,	/* uint */
+	SMC_NLA_LGR_D_DMB_ALLOC,	/* uint */
 	__SMC_NLA_LGR_D_MAX,
 	SMC_NLA_LGR_D_MAX = __SMC_NLA_LGR_D_MAX - 1
 };
@@ -249,6 +253,8 @@ enum {
 	SMC_NLA_STATS_T_TX_BYTES,	/* u64 */
 	SMC_NLA_STATS_T_RX_CNT,		/* u64 */
 	SMC_NLA_STATS_T_TX_CNT,		/* u64 */
+	SMC_NLA_STATS_T_RX_RMB_USAGE,	/* uint */
+	SMC_NLA_STATS_T_TX_RMB_USAGE,	/* uint */
 	__SMC_NLA_STATS_T_MAX,
 	SMC_NLA_STATS_T_MAX = __SMC_NLA_STATS_T_MAX - 1
 };
diff --git a/original/uapi/linux/spi/spi.h b/original/uapi/linux/spi/spi.h
index ca56e47..ee4ac81 100644
--- a/original/uapi/linux/spi/spi.h
+++ b/original/uapi/linux/spi/spi.h
@@ -28,7 +28,8 @@
 #define	SPI_RX_OCTAL		_BITUL(14)	/* receive with 8 wires */
 #define	SPI_3WIRE_HIZ		_BITUL(15)	/* high impedance turnaround */
 #define	SPI_RX_CPHA_FLIP	_BITUL(16)	/* flip CPHA on Rx only xfer */
-#define SPI_MOSI_IDLE_LOW	_BITUL(17)	/* leave mosi line low when idle */
+#define SPI_MOSI_IDLE_LOW	_BITUL(17)	/* leave MOSI line low when idle */
+#define SPI_MOSI_IDLE_HIGH	_BITUL(18)	/* leave MOSI line high when idle */
 
 /*
  * All the bits defined above should be covered by SPI_MODE_USER_MASK.
@@ -38,6 +39,6 @@
  * These bits must not overlap. A static assert check should make sure of that.
  * If adding extra bits, make sure to increase the bit index below as well.
  */
-#define SPI_MODE_USER_MASK	(_BITUL(18) - 1)
+#define SPI_MODE_USER_MASK	(_BITUL(19) - 1)
 
 #endif /* _UAPI_SPI_H */
diff --git a/original/uapi/linux/ublk_cmd.h b/original/uapi/linux/ublk_cmd.h
index c8dc5f8..1287363 100644
--- a/original/uapi/linux/ublk_cmd.h
+++ b/original/uapi/linux/ublk_cmd.h
@@ -175,7 +175,13 @@
 /* use ioctl encoding for uring command */
 #define UBLK_F_CMD_IOCTL_ENCODE	(1UL << 6)
 
-/* Copy between request and user buffer by pread()/pwrite() */
+/*
+ *  Copy between request and user buffer by pread()/pwrite()
+ *
+ *  Not available for UBLK_F_UNPRIVILEGED_DEV, otherwise userspace may
+ *  deceive us by not filling request buffer, then kernel uninitialized
+ *  data may be leaked.
+ */
 #define UBLK_F_USER_COPY	(1UL << 7)
 
 /*
diff --git a/original/uapi/linux/uio.h b/original/uapi/linux/uio.h
index 059b1a9..649739e 100644
--- a/original/uapi/linux/uio.h
+++ b/original/uapi/linux/uio.h
@@ -20,6 +20,24 @@ struct iovec
 	__kernel_size_t iov_len; /* Must be size_t (1003.1g) */
 };
 
+struct dmabuf_cmsg {
+	__u64 frag_offset;	/* offset into the dmabuf where the frag starts.
+				 */
+	__u32 frag_size;	/* size of the frag. */
+	__u32 frag_token;	/* token representing this frag for
+				 * DEVMEM_DONTNEED.
+				 */
+	__u32  dmabuf_id;	/* dmabuf id this frag belongs to. */
+	__u32 flags;		/* Currently unused. Reserved for future
+				 * uses.
+				 */
+};
+
+struct dmabuf_token {
+	__u32 token_start;
+	__u32 token_count;
+};
+
 /*
  *	UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
  */
diff --git a/original/uapi/linux/usb/ch9.h b/original/uapi/linux/usb/ch9.h
index 44d73ba..91f0f7e 100644
--- a/original/uapi/linux/usb/ch9.h
+++ b/original/uapi/linux/usb/ch9.h
@@ -254,6 +254,9 @@ struct usb_ctrlrequest {
 #define USB_DT_DEVICE_CAPABILITY	0x10
 #define USB_DT_WIRELESS_ENDPOINT_COMP	0x11
 #define USB_DT_WIRE_ADAPTER		0x21
+/* From USB Device Firmware Upgrade Specification, Revision 1.1 */
+#define USB_DT_DFU_FUNCTIONAL		0x21
+/* these are from the Wireless USB spec */
 #define USB_DT_RPIPE			0x22
 #define USB_DT_CS_RADIO_CONTROL		0x23
 /* From the T10 UAS specification */
@@ -329,9 +332,10 @@ struct usb_device_descriptor {
 #define USB_CLASS_USB_TYPE_C_BRIDGE	0x12
 #define USB_CLASS_MISC			0xef
 #define USB_CLASS_APP_SPEC		0xfe
-#define USB_CLASS_VENDOR_SPEC		0xff
+#define USB_SUBCLASS_DFU			0x01
 
-#define USB_SUBCLASS_VENDOR_SPEC	0xff
+#define USB_CLASS_VENDOR_SPEC		0xff
+#define USB_SUBCLASS_VENDOR_SPEC		0xff
 
 /*-------------------------------------------------------------------------*/
 
diff --git a/original/uapi/linux/usb/functionfs.h b/original/uapi/linux/usb/functionfs.h
index 9f88de9..2ebdba1 100644
--- a/original/uapi/linux/usb/functionfs.h
+++ b/original/uapi/linux/usb/functionfs.h
@@ -3,6 +3,7 @@
 #define _UAPI__LINUX_FUNCTIONFS_H__
 
 
+#include <linux/const.h>
 #include <linux/types.h>
 #include <linux/ioctl.h>
 
@@ -37,6 +38,31 @@ struct usb_endpoint_descriptor_no_audio {
 	__u8  bInterval;
 } __attribute__((packed));
 
+/**
+ * struct usb_dfu_functional_descriptor - DFU Functional descriptor
+ * @bLength:		Size of the descriptor (bytes)
+ * @bDescriptorType:	USB_DT_DFU_FUNCTIONAL
+ * @bmAttributes:	DFU attributes
+ * @wDetachTimeOut:	Maximum time to wait after DFU_DETACH (ms, le16)
+ * @wTransferSize:	Maximum number of bytes per control-write (le16)
+ * @bcdDFUVersion:	DFU Spec version (BCD, le16)
+ */
+struct usb_dfu_functional_descriptor {
+	__u8  bLength;
+	__u8  bDescriptorType;
+	__u8  bmAttributes;
+	__le16 wDetachTimeOut;
+	__le16 wTransferSize;
+	__le16 bcdDFUVersion;
+} __attribute__ ((packed));
+
+/* from DFU functional descriptor bmAttributes */
+#define DFU_FUNC_ATT_CAN_DOWNLOAD	_BITUL(0)
+#define DFU_FUNC_ATT_CAN_UPLOAD		_BITUL(1)
+#define DFU_FUNC_ATT_MANIFEST_TOLERANT	_BITUL(2)
+#define DFU_FUNC_ATT_WILL_DETACH	_BITUL(3)
+
+
 struct usb_functionfs_descs_head_v2 {
 	__le32 magic;
 	__le32 length;
@@ -104,23 +130,38 @@ struct usb_ffs_dmabuf_transfer_req {
 
 #ifndef __KERNEL__
 
-/*
+/**
+ * DOC: descriptors
+ *
  * Descriptors format:
  *
+ * +-----+-----------+--------------+--------------------------------------+
  * | off | name      | type         | description                          |
- * |-----+-----------+--------------+--------------------------------------|
+ * +-----+-----------+--------------+--------------------------------------+
  * |   0 | magic     | LE32         | FUNCTIONFS_DESCRIPTORS_MAGIC_V2      |
+ * +-----+-----------+--------------+--------------------------------------+
  * |   4 | length    | LE32         | length of the whole data chunk       |
+ * +-----+-----------+--------------+--------------------------------------+
  * |   8 | flags     | LE32         | combination of functionfs_flags      |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | eventfd   | LE32         | eventfd file descriptor              |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | fs_count  | LE32         | number of full-speed descriptors     |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | hs_count  | LE32         | number of high-speed descriptors     |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | ss_count  | LE32         | number of super-speed descriptors    |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | os_count  | LE32         | number of MS OS descriptors          |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | fs_descrs | Descriptor[] | list of full-speed descriptors       |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | hs_descrs | Descriptor[] | list of high-speed descriptors       |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | ss_descrs | Descriptor[] | list of super-speed descriptors      |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | os_descrs | OSDesc[]     | list of MS OS descriptors            |
+ * +-----+-----------+--------------+--------------------------------------+
  *
  * Depending on which flags are set, various fields may be missing in the
  * structure.  Any flags that are not recognised cause the whole block to be
@@ -128,71 +169,111 @@ struct usb_ffs_dmabuf_transfer_req {
  *
  * Legacy descriptors format (deprecated as of 3.14):
  *
+ * +-----+-----------+--------------+--------------------------------------+
  * | off | name      | type         | description                          |
- * |-----+-----------+--------------+--------------------------------------|
+ * +-----+-----------+--------------+--------------------------------------+
  * |   0 | magic     | LE32         | FUNCTIONFS_DESCRIPTORS_MAGIC         |
+ * +-----+-----------+--------------+--------------------------------------+
  * |   4 | length    | LE32         | length of the whole data chunk       |
+ * +-----+-----------+--------------+--------------------------------------+
  * |   8 | fs_count  | LE32         | number of full-speed descriptors     |
+ * +-----+-----------+--------------+--------------------------------------+
  * |  12 | hs_count  | LE32         | number of high-speed descriptors     |
+ * +-----+-----------+--------------+--------------------------------------+
  * |  16 | fs_descrs | Descriptor[] | list of full-speed descriptors       |
+ * +-----+-----------+--------------+--------------------------------------+
  * |     | hs_descrs | Descriptor[] | list of high-speed descriptors       |
+ * +-----+-----------+--------------+--------------------------------------+
  *
  * All numbers must be in little endian order.
  *
  * Descriptor[] is an array of valid USB descriptors which have the following
  * format:
  *
+ * +-----+-----------------+------+--------------------------+
  * | off | name            | type | description              |
- * |-----+-----------------+------+--------------------------|
+ * +-----+-----------------+------+--------------------------+
  * |   0 | bLength         | U8   | length of the descriptor |
+ * +-----+-----------------+------+--------------------------+
  * |   1 | bDescriptorType | U8   | descriptor type          |
+ * +-----+-----------------+------+--------------------------+
  * |   2 | payload         |      | descriptor's payload     |
+ * +-----+-----------------+------+--------------------------+
  *
  * OSDesc[] is an array of valid MS OS Feature Descriptors which have one of
  * the following formats:
  *
+ * +-----+-----------------+------+--------------------------+
  * | off | name            | type | description              |
- * |-----+-----------------+------+--------------------------|
+ * +-----+-----------------+------+--------------------------+
  * |   0 | inteface        | U8   | related interface number |
+ * +-----+-----------------+------+--------------------------+
  * |   1 | dwLength        | U32  | length of the descriptor |
+ * +-----+-----------------+------+--------------------------+
  * |   5 | bcdVersion      | U16  | currently supported: 1   |
+ * +-----+-----------------+------+--------------------------+
  * |   7 | wIndex          | U16  | currently supported: 4   |
+ * +-----+-----------------+------+--------------------------+
  * |   9 | bCount          | U8   | number of ext. compat.   |
+ * +-----+-----------------+------+--------------------------+
  * |  10 | Reserved        | U8   | 0                        |
+ * +-----+-----------------+------+--------------------------+
  * |  11 | ExtCompat[]     |      | list of ext. compat. d.  |
+ * +-----+-----------------+------+--------------------------+
  *
+ * +-----+-----------------+------+--------------------------+
  * | off | name            | type | description              |
- * |-----+-----------------+------+--------------------------|
+ * +-----+-----------------+------+--------------------------+
  * |   0 | inteface        | U8   | related interface number |
+ * +-----+-----------------+------+--------------------------+
  * |   1 | dwLength        | U32  | length of the descriptor |
+ * +-----+-----------------+------+--------------------------+
  * |   5 | bcdVersion      | U16  | currently supported: 1   |
+ * +-----+-----------------+------+--------------------------+
  * |   7 | wIndex          | U16  | currently supported: 5   |
+ * +-----+-----------------+------+--------------------------+
  * |   9 | wCount          | U16  | number of ext. compat.   |
+ * +-----+-----------------+------+--------------------------+
  * |  11 | ExtProp[]       |      | list of ext. prop. d.    |
+ * +-----+-----------------+------+--------------------------+
  *
  * ExtCompat[] is an array of valid Extended Compatiblity descriptors
  * which have the following format:
  *
+ * +-----+-----------------------+------+-------------------------------------+
  * | off | name                  | type | description                         |
- * |-----+-----------------------+------+-------------------------------------|
+ * +-----+-----------------------+------+-------------------------------------+
  * |   0 | bFirstInterfaceNumber | U8   | index of the interface or of the 1st|
+ * +-----+-----------------------+------+-------------------------------------+
  * |     |                       |      | interface in an IAD group           |
+ * +-----+-----------------------+------+-------------------------------------+
  * |   1 | Reserved              | U8   | 1                                   |
+ * +-----+-----------------------+------+-------------------------------------+
  * |   2 | CompatibleID          | U8[8]| compatible ID string                |
+ * +-----+-----------------------+------+-------------------------------------+
  * |  10 | SubCompatibleID       | U8[8]| subcompatible ID string             |
+ * +-----+-----------------------+------+-------------------------------------+
  * |  18 | Reserved              | U8[6]| 0                                   |
+ * +-----+-----------------------+------+-------------------------------------+
  *
  * ExtProp[] is an array of valid Extended Properties descriptors
  * which have the following format:
  *
+ * +-----+-----------------------+------+-------------------------------------+
  * | off | name                  | type | description                         |
- * |-----+-----------------------+------+-------------------------------------|
+ * +-----+-----------------------+------+-------------------------------------+
  * |   0 | dwSize                | U32  | length of the descriptor            |
+ * +-----+-----------------------+------+-------------------------------------+
  * |   4 | dwPropertyDataType    | U32  | 1..7                                |
+ * +-----+-----------------------+------+-------------------------------------+
  * |   8 | wPropertyNameLength   | U16  | bPropertyName length (NL)           |
+ * +-----+-----------------------+------+-------------------------------------+
  * |  10 | bPropertyName         |U8[NL]| name of this property               |
+ * +-----+-----------------------+------+-------------------------------------+
  * |10+NL| dwPropertyDataLength  | U32  | bPropertyData length (DL)           |
+ * +-----+-----------------------+------+-------------------------------------+
  * |14+NL| bProperty             |U8[DL]| payload of this property            |
+ * +-----+-----------------------+------+-------------------------------------+
  */
 
 struct usb_functionfs_strings_head {
diff --git a/original/uapi/linux/usb/g_hid.h b/original/uapi/linux/usb/g_hid.h
new file mode 100644
index 0000000..b965092
--- /dev/null
+++ b/original/uapi/linux/usb/g_hid.h
@@ -0,0 +1,40 @@
+/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
+
+#ifndef __UAPI_LINUX_USB_G_HID_H
+#define __UAPI_LINUX_USB_G_HID_H
+
+#include <linux/types.h>
+
+/* Maximum HID report length for High-Speed USB (i.e. USB 2.0) */
+#define MAX_REPORT_LENGTH 64
+
+/**
+ * struct usb_hidg_report - response to GET_REPORT
+ * @report_id: report ID that this is a response for
+ * @userspace_req:
+ *    !0 this report is used for any pending GET_REPORT request
+ *       but wait on userspace to issue a new report on future requests
+ *    0  this report is to be used for any future GET_REPORT requests
+ * @length: length of the report response
+ * @data: report response
+ * @padding: padding for 32/64 bit compatibility
+ *
+ * Structure used by GADGET_HID_WRITE_GET_REPORT ioctl on /dev/hidg*.
+ */
+struct usb_hidg_report {
+	__u8 report_id;
+	__u8 userspace_req;
+	__u16 length;
+	__u8 data[MAX_REPORT_LENGTH];
+	__u8 padding[4];
+};
+
+/* The 'g' code is used by gadgetfs and hid gadget ioctl requests.
+ * Don't add any colliding codes to either driver, and keep
+ * them in unique ranges.
+ */
+
+#define GADGET_HID_READ_GET_REPORT_ID   _IOR('g', 0x41, __u8)
+#define GADGET_HID_WRITE_GET_REPORT     _IOW('g', 0x42, struct usb_hidg_report)
+
+#endif /* __UAPI_LINUX_USB_G_HID_H */
diff --git a/original/uapi/linux/usb/gadgetfs.h b/original/uapi/linux/usb/gadgetfs.h
index 8354739..9754822 100644
--- a/original/uapi/linux/usb/gadgetfs.h
+++ b/original/uapi/linux/usb/gadgetfs.h
@@ -62,7 +62,7 @@ struct usb_gadgetfs_event {
 };
 
 
-/* The 'g' code is also used by printer gadget ioctl requests.
+/* The 'g' code is also used by printer and hid gadget ioctl requests.
  * Don't add any colliding codes to either driver, and keep
  * them in unique ranges (size 0x20 for now).
  */
diff --git a/original/uapi/linux/vbox_vmmdev_types.h b/original/uapi/linux/vbox_vmmdev_types.h
index f8a8d6b..6073858 100644
--- a/original/uapi/linux/vbox_vmmdev_types.h
+++ b/original/uapi/linux/vbox_vmmdev_types.h
@@ -282,7 +282,10 @@ struct vmmdev_hgcm_pagelist {
 	__u32 flags;             /** VMMDEV_HGCM_F_PARM_*. */
 	__u16 offset_first_page; /** Data offset in the first page. */
 	__u16 page_count;        /** Number of pages. */
-	__u64 pages[1];          /** Page addresses. */
+	union {
+		__u64 unused;	/** Deprecated place-holder for first "pages" entry. */
+		__DECLARE_FLEX_ARRAY(__u64, pages); /** Page addresses. */
+	};
 };
 VMMDEV_ASSERT_SIZE(vmmdev_hgcm_pagelist, 4 + 2 + 2 + 8);
 
diff --git a/original/uapi/linux/vdpa.h b/original/uapi/linux/vdpa.h
index 842bf12..71edf2c 100644
--- a/original/uapi/linux/vdpa.h
+++ b/original/uapi/linux/vdpa.h
@@ -19,6 +19,7 @@ enum vdpa_command {
 	VDPA_CMD_DEV_GET,		/* can dump */
 	VDPA_CMD_DEV_CONFIG_GET,	/* can dump */
 	VDPA_CMD_DEV_VSTATS_GET,
+	VDPA_CMD_DEV_ATTR_SET,
 };
 
 enum vdpa_attr {
diff --git a/original/uapi/linux/version.h b/original/uapi/linux/version.h
index d051cab..6fbb2f8 100644
--- a/original/uapi/linux/version.h
+++ b/original/uapi/linux/version.h
@@ -1,5 +1,5 @@
-#define LINUX_VERSION_CODE 396032
+#define LINUX_VERSION_CODE 396288
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 11
+#define LINUX_VERSION_PATCHLEVEL 12
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/original/uapi/linux/videodev2.h b/original/uapi/linux/videodev2.h
index bcc9d64..ac7919b 100644
--- a/original/uapi/linux/videodev2.h
+++ b/original/uapi/linux/videodev2.h
@@ -502,6 +502,7 @@ struct v4l2_capability {
 #define V4L2_CAP_META_CAPTURE		0x00800000  /* Is a metadata capture device */
 
 #define V4L2_CAP_READWRITE              0x01000000  /* read/write systemcalls */
+#define V4L2_CAP_EDID			0x02000000  /* Is an EDID-only device */
 #define V4L2_CAP_STREAMING              0x04000000  /* streaming I/O ioctls */
 #define V4L2_CAP_META_OUTPUT		0x08000000  /* Is a metadata output device */
 
@@ -854,6 +855,7 @@ struct v4l2_pix_format {
 /* Vendor specific - used for RK_ISP1 camera sub-system */
 #define V4L2_META_FMT_RK_ISP1_PARAMS	v4l2_fourcc('R', 'K', '1', 'P') /* Rockchip ISP1 3A Parameters */
 #define V4L2_META_FMT_RK_ISP1_STAT_3A	v4l2_fourcc('R', 'K', '1', 'S') /* Rockchip ISP1 3A Statistics */
+#define V4L2_META_FMT_RK_ISP1_EXT_PARAMS	v4l2_fourcc('R', 'K', '1', 'E') /* Rockchip ISP1 3a Extensible Parameters */
 
 /* Vendor specific - used for RaspberryPi PiSP */
 #define V4L2_META_FMT_RPI_BE_CFG	v4l2_fourcc('R', 'P', 'B', 'C') /* PiSP BE configuration */
diff --git a/original/uapi/linux/virtio_balloon.h b/original/uapi/linux/virtio_balloon.h
index ddaa45e..ee35a37 100644
--- a/original/uapi/linux/virtio_balloon.h
+++ b/original/uapi/linux/virtio_balloon.h
@@ -71,7 +71,13 @@ struct virtio_balloon_config {
 #define VIRTIO_BALLOON_S_CACHES   7   /* Disk caches */
 #define VIRTIO_BALLOON_S_HTLB_PGALLOC  8  /* Hugetlb page allocations */
 #define VIRTIO_BALLOON_S_HTLB_PGFAIL   9  /* Hugetlb page allocation failures */
-#define VIRTIO_BALLOON_S_NR       10
+#define VIRTIO_BALLOON_S_OOM_KILL      10 /* OOM killer invocations */
+#define VIRTIO_BALLOON_S_ALLOC_STALL   11 /* Stall count of memory allocatoin */
+#define VIRTIO_BALLOON_S_ASYNC_SCAN    12 /* Amount of memory scanned asynchronously */
+#define VIRTIO_BALLOON_S_DIRECT_SCAN   13 /* Amount of memory scanned directly */
+#define VIRTIO_BALLOON_S_ASYNC_RECLAIM 14 /* Amount of memory reclaimed asynchronously */
+#define VIRTIO_BALLOON_S_DIRECT_RECLAIM 15 /* Amount of memory reclaimed directly */
+#define VIRTIO_BALLOON_S_NR       16
 
 #define VIRTIO_BALLOON_S_NAMES_WITH_PREFIX(VIRTIO_BALLOON_S_NAMES_prefix) { \
 	VIRTIO_BALLOON_S_NAMES_prefix "swap-in", \
@@ -83,7 +89,13 @@ struct virtio_balloon_config {
 	VIRTIO_BALLOON_S_NAMES_prefix "available-memory", \
 	VIRTIO_BALLOON_S_NAMES_prefix "disk-caches", \
 	VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-allocations", \
-	VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-failures" \
+	VIRTIO_BALLOON_S_NAMES_prefix "hugetlb-failures", \
+	VIRTIO_BALLOON_S_NAMES_prefix "oom-kills", \
+	VIRTIO_BALLOON_S_NAMES_prefix "alloc-stalls", \
+	VIRTIO_BALLOON_S_NAMES_prefix "async-scans", \
+	VIRTIO_BALLOON_S_NAMES_prefix "direct-scans", \
+	VIRTIO_BALLOON_S_NAMES_prefix "async-reclaims", \
+	VIRTIO_BALLOON_S_NAMES_prefix "direct-reclaims" \
 }
 
 #define VIRTIO_BALLOON_S_NAMES VIRTIO_BALLOON_S_NAMES_WITH_PREFIX("")
diff --git a/original/uapi/linux/virtio_gpu.h b/original/uapi/linux/virtio_gpu.h
index 0e21f39..bf2c9ca 100644
--- a/original/uapi/linux/virtio_gpu.h
+++ b/original/uapi/linux/virtio_gpu.h
@@ -311,6 +311,7 @@ struct virtio_gpu_cmd_submit {
 #define VIRTIO_GPU_CAPSET_VIRGL2 2
 /* 3 is reserved for gfxstream */
 #define VIRTIO_GPU_CAPSET_VENUS 4
+#define VIRTIO_GPU_CAPSET_DRM 6
 
 /* VIRTIO_GPU_CMD_GET_CAPSET_INFO */
 struct virtio_gpu_get_capset_info {
diff --git a/original/uapi/rdma/bnxt_re-abi.h b/original/uapi/rdma/bnxt_re-abi.h
index e61104f..faa9d62 100644
--- a/original/uapi/rdma/bnxt_re-abi.h
+++ b/original/uapi/rdma/bnxt_re-abi.h
@@ -66,6 +66,7 @@ enum bnxt_re_wqe_mode {
 
 enum {
 	BNXT_RE_COMP_MASK_REQ_UCNTX_POW2_SUPPORT = 0x01,
+	BNXT_RE_COMP_MASK_REQ_UCNTX_VAR_WQE_SUPPORT = 0x02,
 };
 
 struct bnxt_re_uctx_req {
@@ -118,10 +119,16 @@ struct bnxt_re_resize_cq_req {
 	__aligned_u64 cq_va;
 };
 
+enum bnxt_re_qp_mask {
+	BNXT_RE_QP_REQ_MASK_VAR_WQE_SQ_SLOTS = 0x1,
+};
+
 struct bnxt_re_qp_req {
 	__aligned_u64 qpsva;
 	__aligned_u64 qprva;
 	__aligned_u64 qp_handle;
+	__aligned_u64 comp_mask;
+	__u32 sq_slots;
 };
 
 struct bnxt_re_qp_resp {
@@ -134,8 +141,14 @@ struct bnxt_re_srq_req {
 	__aligned_u64 srq_handle;
 };
 
+enum bnxt_re_srq_mask {
+	BNXT_RE_SRQ_TOGGLE_PAGE_SUPPORT = 0x1,
+};
+
 struct bnxt_re_srq_resp {
 	__u32 srqid;
+	__u32 rsvd; /* padding */
+	__aligned_u64 comp_mask;
 };
 
 enum bnxt_re_shpg_offt {
diff --git a/original/uapi/rdma/mlx5_user_ioctl_cmds.h b/original/uapi/rdma/mlx5_user_ioctl_cmds.h
index 5b74d65..fd2e4a3 100644
--- a/original/uapi/rdma/mlx5_user_ioctl_cmds.h
+++ b/original/uapi/rdma/mlx5_user_ioctl_cmds.h
@@ -274,6 +274,10 @@ enum mlx5_ib_create_cq_attrs {
 	MLX5_IB_ATTR_CREATE_CQ_UAR_INDEX = UVERBS_ID_DRIVER_NS_WITH_UHW,
 };
 
+enum mlx5_ib_reg_dmabuf_mr_attrs {
+	MLX5_IB_ATTR_REG_DMABUF_MR_ACCESS_FLAGS = (1U << UVERBS_ID_NS_SHIFT),
+};
+
 #define MLX5_IB_DW_MATCH_PARAM 0xA0
 
 struct mlx5_ib_match_params {
@@ -344,6 +348,7 @@ enum mlx5_ib_pd_methods {
 
 enum mlx5_ib_device_methods {
 	MLX5_IB_METHOD_QUERY_PORT = (1U << UVERBS_ID_NS_SHIFT),
+	MLX5_IB_METHOD_GET_DATA_DIRECT_SYSFS_PATH,
 };
 
 enum mlx5_ib_query_port_attrs {
@@ -351,4 +356,8 @@ enum mlx5_ib_query_port_attrs {
 	MLX5_IB_ATTR_QUERY_PORT,
 };
 
+enum mlx5_ib_get_data_direct_sysfs_path_attrs {
+	MLX5_IB_ATTR_GET_DATA_DIRECT_SYSFS_PATH = (1U << UVERBS_ID_NS_SHIFT),
+};
+
 #endif
diff --git a/original/uapi/rdma/mlx5_user_ioctl_verbs.h b/original/uapi/rdma/mlx5_user_ioctl_verbs.h
index 3189c7f..7c233df 100644
--- a/original/uapi/rdma/mlx5_user_ioctl_verbs.h
+++ b/original/uapi/rdma/mlx5_user_ioctl_verbs.h
@@ -54,6 +54,10 @@ enum mlx5_ib_uapi_flow_action_packet_reformat_type {
 	MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL = 0x3,
 };
 
+enum mlx5_ib_uapi_reg_dmabuf_flags {
+	MLX5_IB_UAPI_REG_DMABUF_ACCESS_DATA_DIRECT = 1 << 0,
+};
+
 struct mlx5_ib_uapi_devx_async_cmd_hdr {
 	__aligned_u64	wr_id;
 	__u8		out_data[];
diff --git a/original/uapi/rdma/rdma_netlink.h b/original/uapi/rdma/rdma_netlink.h
index 2f37568..39be09c 100644
--- a/original/uapi/rdma/rdma_netlink.h
+++ b/original/uapi/rdma/rdma_netlink.h
@@ -15,6 +15,7 @@ enum {
 enum {
 	RDMA_NL_GROUP_IWPM = 2,
 	RDMA_NL_GROUP_LS,
+	RDMA_NL_GROUP_NOTIFY,
 	RDMA_NL_NUM_GROUPS
 };
 
@@ -305,6 +306,8 @@ enum rdma_nldev_command {
 
 	RDMA_NLDEV_CMD_DELDEV,
 
+	RDMA_NLDEV_CMD_MONITOR,
+
 	RDMA_NLDEV_NUM_OPS
 };
 
@@ -574,6 +577,9 @@ enum rdma_nldev_attr {
 
 	RDMA_NLDEV_ATTR_NAME_ASSIGN_TYPE,	/* u8 */
 
+	RDMA_NLDEV_ATTR_EVENT_TYPE,		/* u8 */
+
+	RDMA_NLDEV_SYS_ATTR_MONITOR_MODE,	/* u8 */
 	/*
 	 * Always the end
 	 */
@@ -624,4 +630,14 @@ enum rdma_nl_name_assign_type {
 	RDMA_NAME_ASSIGN_TYPE_USER = 1, /* Provided by user-space */
 };
 
+/*
+ * Supported rdma monitoring event types.
+ */
+enum rdma_nl_notify_event_type {
+	RDMA_REGISTER_EVENT,
+	RDMA_UNREGISTER_EVENT,
+	RDMA_NETDEV_ATTACH_EVENT,
+	RDMA_NETDEV_DETACH_EVENT,
+};
+
 #endif /* _UAPI_RDMA_NETLINK_H */
diff --git a/original/uapi/sound/asequencer.h b/original/uapi/sound/asequencer.h
index 39b37ed..bc30c1f 100644
--- a/original/uapi/sound/asequencer.h
+++ b/original/uapi/sound/asequencer.h
@@ -461,6 +461,8 @@ struct snd_seq_remove_events {
 #define SNDRV_SEQ_PORT_FLG_TIMESTAMP	(1<<1)
 #define SNDRV_SEQ_PORT_FLG_TIME_REAL	(1<<2)
 
+#define SNDRV_SEQ_PORT_FLG_IS_MIDI1	(1<<3)	/* Keep MIDI 1.0 protocol */
+
 /* port direction */
 #define SNDRV_SEQ_PORT_DIR_UNKNOWN	0
 #define SNDRV_SEQ_PORT_DIR_INPUT	1
diff --git a/original/uapi/sound/asoc.h b/original/uapi/sound/asoc.h
index 99333cb..c117672 100644
--- a/original/uapi/sound/asoc.h
+++ b/original/uapi/sound/asoc.h
@@ -88,7 +88,7 @@
 
 /* ABI version */
 #define SND_SOC_TPLG_ABI_VERSION	0x5	/* current version */
-#define SND_SOC_TPLG_ABI_VERSION_MIN	0x4	/* oldest version supported */
+#define SND_SOC_TPLG_ABI_VERSION_MIN	0x5	/* oldest version supported */
 
 /* Max size of TLV data */
 #define SND_SOC_TPLG_TLV_SIZE		32
diff --git a/original/uapi/sound/asound.h b/original/uapi/sound/asound.h
index 8bf7e8a..4cd5132 100644
--- a/original/uapi/sound/asound.h
+++ b/original/uapi/sound/asound.h
@@ -869,7 +869,7 @@ struct snd_ump_block_info {
  *  Timer section - /dev/snd/timer
  */
 
-#define SNDRV_TIMER_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 7)
+#define SNDRV_TIMER_VERSION		SNDRV_PROTOCOL_VERSION(2, 0, 8)
 
 enum {
 	SNDRV_TIMER_CLASS_NONE = -1,
@@ -894,6 +894,7 @@ enum {
 #define SNDRV_TIMER_GLOBAL_RTC		1	/* unused */
 #define SNDRV_TIMER_GLOBAL_HPET		2
 #define SNDRV_TIMER_GLOBAL_HRTIMER	3
+#define SNDRV_TIMER_GLOBAL_UDRIVEN	4
 
 /* info flags */
 #define SNDRV_TIMER_FLG_SLAVE		(1<<0)	/* cannot be controlled */
@@ -974,6 +975,18 @@ struct snd_timer_status {
 };
 #endif
 
+/*
+ * This structure describes the userspace-driven timer. Such timers are purely virtual,
+ * and can only be triggered from software (for instance, by userspace application).
+ */
+struct snd_timer_uinfo {
+	/* To pretend being a normal timer, we need to know the resolution in ns. */
+	__u64 resolution;
+	int fd;
+	unsigned int id;
+	unsigned char reserved[16];
+};
+
 #define SNDRV_TIMER_IOCTL_PVERSION	_IOR('T', 0x00, int)
 #define SNDRV_TIMER_IOCTL_NEXT_DEVICE	_IOWR('T', 0x01, struct snd_timer_id)
 #define SNDRV_TIMER_IOCTL_TREAD_OLD	_IOW('T', 0x02, int)
@@ -990,6 +1003,8 @@ struct snd_timer_status {
 #define SNDRV_TIMER_IOCTL_CONTINUE	_IO('T', 0xa2)
 #define SNDRV_TIMER_IOCTL_PAUSE		_IO('T', 0xa3)
 #define SNDRV_TIMER_IOCTL_TREAD64	_IOW('T', 0xa4, int)
+#define SNDRV_TIMER_IOCTL_CREATE	_IOWR('T', 0xa5, struct snd_timer_uinfo)
+#define SNDRV_TIMER_IOCTL_TRIGGER	_IO('T', 0xa6)
 
 #if __BITS_PER_LONG == 64
 #define SNDRV_TIMER_IOCTL_TREAD SNDRV_TIMER_IOCTL_TREAD_OLD
diff --git a/original/uapi/xen/privcmd.h b/original/uapi/xen/privcmd.h
index 8b8c5d1..8e2c8fd 100644
--- a/original/uapi/xen/privcmd.h
+++ b/original/uapi/xen/privcmd.h
@@ -126,6 +126,11 @@ struct privcmd_ioeventfd {
 	__u8 pad[2];
 };
 
+struct privcmd_pcidev_get_gsi {
+	__u32 sbdf;
+	__u32 gsi;
+};
+
 /*
  * @cmd: IOCTL_PRIVCMD_HYPERCALL
  * @arg: &privcmd_hypercall_t
@@ -157,5 +162,7 @@ struct privcmd_ioeventfd {
 	_IOW('P', 8, struct privcmd_irqfd)
 #define IOCTL_PRIVCMD_IOEVENTFD					\
 	_IOW('P', 9, struct privcmd_ioeventfd)
+#define IOCTL_PRIVCMD_PCIDEV_GET_GSI				\
+	_IOC(_IOC_NONE, 'P', 10, sizeof(struct privcmd_pcidev_get_gsi))
 
 #endif /* __LINUX_PUBLIC_PRIVCMD_H__ */
```

