```diff
diff --git a/METADATA b/METADATA
index f6a6703..7aa96e9 100644
--- a/METADATA
+++ b/METADATA
@@ -1,18 +1,21 @@
-name: "ublksrv"
-description:
-    "Userspace block driver (UBLK) infrastructure to create and manage block "
-    "devices in userspace."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/ublksrv
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "ublksrv"
+description: "Userspace block driver (UBLK) infrastructure to create and manage block devices in userspace."
 third_party {
-homepage: "https://github.com/ublk-org/ublksrv"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 21
+  }
+  homepage: "https://github.com/ublk-org/ublksrv"
   identifier {
     type: "Git"
     value: "https://github.com/ublk-org/ublksrv.git"
+    version: "v1.3"
     primary_source: true
-    version: "v1.2"
   }
-  version: "v1.2"
-  last_upgrade_date { year: 2024 month: 10 day: 31 }
-  # Dual-licensed, using the least restrictive per go/thirdpartylicenses#same.
-  license_type: NOTICE
 }
diff --git a/Makefile.am b/Makefile.am
index 99cb3b5..22ea09d 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -15,9 +15,7 @@ sbin_PROGRAMS = ublk ublk_user_id
 noinst_PROGRAMS = demo_null demo_event
 dist_sbin_SCRIPTS = utils/ublk_chown.sh utils/ublk_chown_docker.sh
 
-ublk_SOURCES = ublksrv_tgt.cpp tgt_null.cpp tgt_loop.cpp qcow2/tgt_qcow2.cpp \
-			   qcow2/qcow2.cpp qcow2/qcow2_meta.cpp qcow2/utils.cpp \
-			   qcow2/qcow2_flush_meta.cpp \
+ublk_SOURCES = ublksrv_tgt.cpp tgt_null.cpp tgt_loop.cpp \
 			   nbd/tgt_nbd.cpp nbd/cliserv.c nbd/nbd-client.c
 ublk_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
 ublk_CPPFLAGS = $(ublk_CFLAGS) -I$(top_srcdir)/include
@@ -41,7 +39,7 @@ ublk_user_id_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)
 pkgconfigdir = $(libdir)/pkgconfig
 pkgconfig_DATA = ublksrv.pc
 
-CLEANFILES = *~ test cscope.* include/*~ *.d qcow2/*~ nbd/*~ utils/*~ doc/html/*
+CLEANFILES = *~ test cscope.* include/*~ *.d nbd/*~ utils/*~ doc/html/*
 
 R = 10
 D = tests/tmp/
diff --git a/OWNERS b/OWNERS
index 2e8f086..a2a4268 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.rst b/README.rst
index 480600b..2b26577 100644
--- a/README.rst
+++ b/README.rst
@@ -103,16 +103,6 @@ or
 
 - ublk add -t loop -f 1.img
 
-
-add one qcow2 disk
-------------------
-
-- ublk add -t qcow2 -f test.qcow2
-
-note: qcow2 support is experimental, see details in qcow2 status [#qcow2_status]_
-and readme [#qcow2_readme]_
-
-
 remove one ublk disk
 --------------------
 
@@ -305,8 +295,6 @@ by MIT license.
 The library functions (all code in lib/ directory and include/ublksrv.h)
 are covered by dual licensed LGPL and MIT, see COPYING.LGPL and LICENSE.
 
-qcow2 target code is covered by GPL-2.0, see COPYING.
-
 All other source code are covered by dual licensed GPL and MIT, see
 COPYING and LICENSE.
 
@@ -316,7 +304,5 @@ References
 .. [#ublk_driver] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0
 .. [#zero_copy] https://lore.kernel.org/all/20220318095531.15479-1-xiaoguang.wang@linux.alibaba.com/
 .. [#nlohmann] https://github.com/nlohmann/json
-.. [#qcow2_status] https://github.com/ming1/ubdsrv/blob/master/qcow2/STATUS.rst
-.. [#qcow2_readme] https://github.com/ming1/ubdsrv/blob/master/qcow2/README.rst
 .. [#build_with_liburing_src] https://github.com/ming1/ubdsrv/blob/master/build_with_liburing_src
 .. [#stefan_container] https://lore.kernel.org/linux-block/YoOr6jBfgVm8GvWg@stefanha-x1.localdomain/
diff --git a/configure.ac b/configure.ac
index e44a0a4..4e6c37f 100644
--- a/configure.ac
+++ b/configure.ac
@@ -153,6 +153,24 @@ else
   AC_MSG_RESULT([no])
 fi
 
+ublk_control=/dev/ublk-control
+AC_ARG_WITH(
+  [ublk_control],
+  [AS_HELP_STRING([--with-ublk_control], [Set the ublk control device. Defaults to /dev/ublk-control.])],
+  [ublk_control="$withval"]
+  [],
+)
+AC_DEFINE_UNQUOTED([UBLK_CONTROL], ["${ublk_control}"], [ublk control device.])
+
+ublkc_prefix=/dev
+AC_ARG_WITH(
+  [ublkc_prefix],
+  [AS_HELP_STRING([--with-ublkc_prefix], [Set the directory prefix for ublkc devices. Defaults to /dev.])],
+  [ublkc_prefix="$withval"]
+  [],
+)
+AC_DEFINE_UNQUOTED([UBLKC_PREFIX], ["${ublkc_prefix}"], [prefix for ublkc devices.])
+
 AC_CHECK_PROGS([DOXYGEN], [doxygen])
 if test -z "$DOXYGEN"; then
    AC_MSG_WARN([Doxygen not found - continue without Doxygen support])
diff --git a/include/ublk_cmd.h b/include/ublk_cmd.h
index 4abddfd..0150003 100644
--- a/include/ublk_cmd.h
+++ b/include/ublk_cmd.h
@@ -1,4 +1,4 @@
-/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) or MIT */
 #ifndef USER_BLK_DRV_CMD_INC_H
 #define USER_BLK_DRV_CMD_INC_H
 
@@ -53,7 +53,7 @@
 	_IOR('u', 0x14, struct ublksrv_ctrl_cmd)
 
 /*
- * 64bit are enough now, and it should be easy to extend in case of
+ * 64bits are enough now, and it should be easy to extend in case of
  * running out of feature flags
  */
 #define UBLK_FEATURES_LEN  8
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
@@ -178,10 +188,24 @@
 /* Copy between request and user buffer by pread()/pwrite() */
 #define UBLK_F_USER_COPY	(1UL << 7)
 
+/*
+ * User space sets this flag when setting up the device to request zoned storage support. Kernel may
+ * deny the request by returning an error.
+ */
+#define UBLK_F_ZONED (1ULL << 8)
+
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
@@ -234,9 +258,27 @@ struct ublksrv_ctrl_dev_info {
 #define		UBLK_IO_OP_READ		0
 #define		UBLK_IO_OP_WRITE		1
 #define		UBLK_IO_OP_FLUSH		2
-#define		UBLK_IO_OP_DISCARD	3
-#define		UBLK_IO_OP_WRITE_SAME	4
-#define		UBLK_IO_OP_WRITE_ZEROES	5
+#define		UBLK_IO_OP_DISCARD		3
+#define		UBLK_IO_OP_WRITE_SAME		4
+#define		UBLK_IO_OP_WRITE_ZEROES		5
+#define		UBLK_IO_OP_ZONE_OPEN		10
+#define		UBLK_IO_OP_ZONE_CLOSE		11
+#define		UBLK_IO_OP_ZONE_FINISH		12
+#define		UBLK_IO_OP_ZONE_APPEND		13
+#define		UBLK_IO_OP_ZONE_RESET_ALL	14
+#define		UBLK_IO_OP_ZONE_RESET		15
+/*
+ * Construct a zone report. The report request is carried in `struct
+ * ublksrv_io_desc`. The `start_sector` field must be the first sector of a zone
+ * and shall indicate the first zone of the report. The `nr_zones` shall
+ * indicate how many zones should be reported at most. The report shall be
+ * delivered as a `struct blk_zone` array. To report fewer zones than requested,
+ * zero the last entry of the returned array.
+ *
+ * Related definitions(blk_zone, blk_zone_cond, blk_zone_type, ...) in
+ * include/uapi/linux/blkzoned.h are part of ublk UAPI.
+ */
+#define		UBLK_IO_OP_REPORT_ZONES		18
 
 #define		UBLK_IO_F_FAILFAST_DEV		(1U << 8)
 #define		UBLK_IO_F_FAILFAST_TRANSPORT	(1U << 9)
@@ -257,7 +299,10 @@ struct ublksrv_io_desc {
 	/* op: bit 0-7, flags: bit 8-31 */
 	__u32		op_flags;
 
-	__u32		nr_sectors;
+	union {
+		__u32		nr_sectors;
+		__u32		nr_zones; /* for UBLK_IO_OP_REPORT_ZONES */
+	};
 
 	/* start sector for this io */
 	__u64		start_sector;
@@ -286,11 +331,21 @@ struct ublksrv_io_cmd {
 	/* io result, it is valid for COMMIT* command only */
 	__s32	result;
 
-	/*
-	 * userspace buffer address in ublksrv daemon process, valid for
-	 * FETCH* command only
-	 */
-	__u64	addr;
+	union {
+		/*
+		 * userspace buffer address in ublksrv daemon process, valid for
+		 * FETCH* command only
+		 *
+		 * `addr` should not be used when UBLK_F_USER_COPY is enabled,
+		 * because userspace handles data copy by pread()/pwrite() over
+		 * /dev/ublkcN. But in case of UBLK_F_ZONED, this union is
+		 * re-used to pass back the allocated LBA for
+		 * UBLK_IO_OP_ZONE_APPEND which actually depends on
+		 * UBLK_F_USER_COPY
+		 */
+		__u64	addr;
+		__u64	zone_append_lba;
+	};
 };
 
 struct ublk_param_basic {
@@ -333,6 +388,13 @@ struct ublk_param_devt {
 	__u32   disk_minor;
 };
 
+struct ublk_param_zoned {
+	__u32	max_open_zones;
+	__u32	max_active_zones;
+	__u32	max_zone_append_sectors;
+	__u8	reserved[20];
+};
+
 struct ublk_params {
 	/*
 	 * Total length of parameters, userspace has to set 'len' for both
@@ -344,11 +406,13 @@ struct ublk_params {
 #define UBLK_PARAM_TYPE_BASIC           (1 << 0)
 #define UBLK_PARAM_TYPE_DISCARD         (1 << 1)
 #define UBLK_PARAM_TYPE_DEVT            (1 << 2)
+#define UBLK_PARAM_TYPE_ZONED           (1 << 3)
 	__u32	types;			/* types of parameter included */
 
 	struct ublk_param_basic		basic;
 	struct ublk_param_discard	discard;
 	struct ublk_param_devt		devt;
+	struct ublk_param_zoned	zoned;
 };
 
 #endif
diff --git a/include/ublksrv_priv.h b/include/ublksrv_priv.h
index f37bc44..d7e6fa9 100644
--- a/include/ublksrv_priv.h
+++ b/include/ublksrv_priv.h
@@ -26,7 +26,11 @@
 
 
 /* todo: relace the hardcode name with /dev/char/maj:min */
-#define UBLKC_DEV	"/dev/ublkc"
+#ifdef UBLKC_PREFIX
+#define	UBLKC_DEV	UBLKC_PREFIX "/ublkc"
+#else
+#define	UBLKC_DEV	"/dev/ublkc"
+#endif
 #define UBLKC_PATH_MAX	32
 
 #ifdef __cplusplus
@@ -211,17 +215,12 @@ static inline int is_target_io(__u64 user_data)
 	return (user_data & (1ULL << 63)) != 0;
 }
 
-/* two helpers for setting up io_uring */
-static inline int ublksrv_setup_ring(struct io_uring *r, int depth,
+static inline void ublksrv_setup_ring_params(struct io_uring_params *p,
 		int cq_depth, unsigned flags)
 {
-	struct io_uring_params p;
-
-	memset(&p, 0, sizeof(p));
-	p.flags = flags | IORING_SETUP_CQSIZE;
-	p.cq_entries = cq_depth;
-
-	return io_uring_queue_init_params(depth, r, &p);
+	memset(p, 0, sizeof(*p));
+	p->flags = flags | IORING_SETUP_CQSIZE;
+	p->cq_entries = cq_depth;
 }
 
 static inline struct io_uring_sqe *ublksrv_uring_get_sqe(struct io_uring *r,
diff --git a/include/ublksrv_tgt_endian.h b/include/ublksrv_tgt_endian.h
index 03d98e6..df06172 100644
--- a/include/ublksrv_tgt_endian.h
+++ b/include/ublksrv_tgt_endian.h
@@ -1,4 +1,4 @@
-// SPDX-License-Identifier: GPL-2.0
+// SPDX-License-Identifier: MIT or GPL-2.0-only
 #ifndef UBLK_TGT_ENDIAN_H
 #define UBLK_TGT_ENDIAN_H
 
@@ -6,136 +6,23 @@
 
 /* ublksrv target code private header, not for libublksrv user */
 
-static inline uint16_t bswap16(uint16_t x)
-{
-    return bswap_16(x);
-}
-static inline uint32_t bswap32(uint32_t x)
-{
-    return bswap_32(x);
-}
-static inline uint64_t bswap64(uint64_t x)
-{
-    return bswap_64(x);
-}
-
-static inline void bswap16s(uint16_t *s)
-{
-    *s = bswap16(*s);
-}
-
-static inline void bswap32s(uint32_t *s)
-{
-    *s = bswap32(*s);
-}
-
-static inline void bswap64s(uint64_t *s)
-{
-    *s = bswap64(*s);
-}
-
-#ifndef glue
-#define xglue(x, y) x ## y
-#define glue(x, y) xglue(x, y)
-#endif
-
-#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
-#define be_bswap(v, size) (v)
-#define le_bswap(v, size) glue(bswap, size)(v)
-#define be_bswaps(v, size)
-#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
-#else
-#define le_bswap(v, size) (v)
-#define be_bswap(v, size) glue(bswap, size)(v)
-#define le_bswaps(v, size)
-#define be_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
-#endif
-
-/**
- * Endianness conversion functions between host cpu and specified endianness.
- * (We list the complete set of prototypes produced by the macros below
- * to assist people who search the headers to find their definitions.)
- *
- * uint16_t le16_to_cpu(uint16_t v);
- * uint32_t le32_to_cpu(uint32_t v);
- * uint64_t le64_to_cpu(uint64_t v);
- * uint16_t be16_to_cpu(uint16_t v);
- * uint32_t be32_to_cpu(uint32_t v);
- * uint64_t be64_to_cpu(uint64_t v);
- *
- * Convert the value @v from the specified format to the native
- * endianness of the host CPU by byteswapping if necessary, and
- * return the converted value.
- *
- * uint16_t cpu_to_le16(uint16_t v);
- * uint32_t cpu_to_le32(uint32_t v);
- * uint64_t cpu_to_le64(uint64_t v);
- * uint16_t cpu_to_be16(uint16_t v);
- * uint32_t cpu_to_be32(uint32_t v);
- * uint64_t cpu_to_be64(uint64_t v);
- *
- * Convert the value @v from the native endianness of the host CPU to
- * the specified format by byteswapping if necessary, and return
- * the converted value.
- *
- * void le16_to_cpus(uint16_t *v);
- * void le32_to_cpus(uint32_t *v);
- * void le64_to_cpus(uint64_t *v);
- * void be16_to_cpus(uint16_t *v);
- * void be32_to_cpus(uint32_t *v);
- * void be64_to_cpus(uint64_t *v);
- *
- * Do an in-place conversion of the value pointed to by @v from the
- * specified format to the native endianness of the host CPU.
- *
- * void cpu_to_le16s(uint16_t *v);
- * void cpu_to_le32s(uint32_t *v);
- * void cpu_to_le64s(uint64_t *v);
- * void cpu_to_be16s(uint16_t *v);
- * void cpu_to_be32s(uint32_t *v);
- * void cpu_to_be64s(uint64_t *v);
- *
- * Do an in-place conversion of the value pointed to by @v from the
- * native endianness of the host CPU to the specified format.
- *
- * Both X_to_cpu() and cpu_to_X() perform the same operation; you
- * should use whichever one is better documenting of the function your
- * code is performing.
- *
- * Do not use these functions for conversion of values which are in guest
- * memory, since the data may not be sufficiently aligned for the host CPU's
- * load and store instructions. Instead you should use the ld*_p() and
- * st*_p() functions, which perform loads and stores of data of any
- * required size and endianness and handle possible misalignment.
- */
-
-#define CPU_CONVERT(endian, size, type)\
+#define HOST_CONVERT(endian, size, type)\
 static inline type endian ## size ## _to_cpu(type v)\
 {\
-    return glue(endian, _bswap)(v, size);\
+	return endian ## size ## toh(v); \
 }\
 \
 static inline type cpu_to_ ## endian ## size(type v)\
 {\
-    return glue(endian, _bswap)(v, size);\
+	return hto ## endian ## size(v); \
 }\
-\
-static inline void endian ## size ## _to_cpus(type *p)\
-{\
-    glue(endian, _bswaps)(p, size);\
-}\
-\
-static inline void cpu_to_ ## endian ## size ## s(type *p)\
-{\
-    glue(endian, _bswaps)(p, size);\
-}
 
-CPU_CONVERT(be, 16, uint16_t)
-CPU_CONVERT(be, 32, uint32_t)
-CPU_CONVERT(be, 64, uint64_t)
+HOST_CONVERT(be, 16, uint16_t)
+HOST_CONVERT(be, 32, uint32_t)
+HOST_CONVERT(be, 64, uint64_t)
 
-CPU_CONVERT(le, 16, uint16_t)
-CPU_CONVERT(le, 32, uint32_t)
-CPU_CONVERT(le, 64, uint64_t)
+HOST_CONVERT(le, 16, uint16_t)
+HOST_CONVERT(le, 32, uint32_t)
+HOST_CONVERT(le, 64, uint64_t)
 
 #endif
diff --git a/lib/ublksrv.c b/lib/ublksrv.c
index 8368561..1717d7e 100644
--- a/lib/ublksrv.c
+++ b/lib/ublksrv.c
@@ -69,8 +69,6 @@ static int __ublksrv_tgt_init(struct _ublksrv_dev *dev, const char *type_name,
 	if (strcmp(ops->name, type_name))
 		return -EINVAL;
 
-	if (!ops->init_tgt)
-		return -EINVAL;
 	if (!ops->handle_io_async)
 		return -EINVAL;
 	if (!ops->alloc_io_buf ^ !ops->free_io_buf)
@@ -79,9 +77,12 @@ static int __ublksrv_tgt_init(struct _ublksrv_dev *dev, const char *type_name,
 	optind = 0;     /* so that we can parse our arguments */
 	tgt->ops = ops;
 
-	if (!ublksrv_is_recovering(dev->ctrl_dev))
-		ret = ops->init_tgt(local_to_tdev(dev), type, argc, argv);
-	else {
+	if (!ublksrv_is_recovering(dev->ctrl_dev)) {
+		if (ops->init_tgt)
+			ret = ops->init_tgt(local_to_tdev(dev), type, argc, argv);
+		else
+			ret = 0;
+	} else {
 		if (ops->recovery_tgt)
 			ret = ops->recovery_tgt(local_to_tdev(dev), type);
 		else
@@ -330,6 +331,14 @@ static int ublksrv_queue_cmd_buf_sz(struct _ublksrv_queue *q)
 	return round_up(size, page_sz);
 }
 
+static int queue_max_cmd_buf_sz(void)
+{
+	unsigned int page_sz = getpagesize();
+
+	return round_up(UBLK_MAX_QUEUE_DEPTH * sizeof(struct ublksrv_io_desc),
+			page_sz);
+}
+
 int ublksrv_queue_unconsumed_cqes(const struct ublksrv_queue *tq)
 {
 	if (tq->ring_ptr)
@@ -400,11 +409,8 @@ static void ublksrv_set_sched_affinity(struct _ublksrv_dev *dev,
 	const struct ublksrv_ctrl_dev *cdev = dev->ctrl_dev;
 	unsigned dev_id = cdev->dev_info.dev_id;
 	cpu_set_t *cpuset = ublksrv_get_queue_affinity(cdev, q_id);
-	pthread_t thread = pthread_self();
-	int ret;
 
-	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), cpuset);
-	if (ret)
+	if (sched_setaffinity(0, sizeof(cpu_set_t), cpuset) < 0)
 		ublk_err("ublk dev %u queue %u set affinity failed",
 				dev_id, q_id);
 }
@@ -509,6 +515,7 @@ static void ublksrv_calculate_depths(const struct _ublksrv_dev *dev, int
 const struct ublksrv_queue *ublksrv_queue_init(const struct ublksrv_dev *tdev,
 		unsigned short q_id, void *queue_data)
 {
+	struct io_uring_params p;
 	struct _ublksrv_dev *dev = tdev_to_local(tdev);
 	struct _ublksrv_queue *q;
 	const struct ublksrv_ctrl_dev *ctrl_dev = dev->ctrl_dev;
@@ -548,8 +555,7 @@ const struct ublksrv_queue *ublksrv_queue_init(const struct ublksrv_dev *tdev,
 	q->tid = ublksrv_gettid();
 
 	cmd_buf_size = ublksrv_queue_cmd_buf_sz(q);
-	off = UBLKSRV_CMD_BUF_OFFSET +
-		q_id * (UBLK_MAX_QUEUE_DEPTH * sizeof(struct ublksrv_io_desc));
+	off = UBLKSRV_CMD_BUF_OFFSET + q_id * queue_max_cmd_buf_sz();
 	q->io_cmd_buf = (char *)mmap(0, cmd_buf_size, PROT_READ,
 			MAP_SHARED | MAP_POPULATE, dev->cdev_fd, off);
 	if (q->io_cmd_buf == MAP_FAILED) {
@@ -595,8 +601,9 @@ skip_alloc_buf:
 		//ublk_assert(io_data_size ^ (unsigned long)q->ios[i].data.private_data);
 	}
 
-	ret = ublksrv_setup_ring(&q->ring, ring_depth, cq_depth,
+	ublksrv_setup_ring_params(&p, cq_depth,
 			IORING_SETUP_SQE128 | IORING_SETUP_COOP_TASKRUN);
+	ret = io_uring_queue_init_params(ring_depth, &q->ring, &p);
 	if (ret < 0) {
 		ublk_err("ublk dev %d queue %d setup io_uring failed %d",
 				q->dev->ctrl_dev->dev_info.dev_id, q->q_id, ret);
diff --git a/lib/ublksrv_cmd.c b/lib/ublksrv_cmd.c
index b9781f4..5211bb9 100644
--- a/lib/ublksrv_cmd.c
+++ b/lib/ublksrv_cmd.c
@@ -4,7 +4,11 @@
 
 #include "ublksrv_priv.h"
 
+#ifdef UBLK_CONTROL
+#define	CTRL_DEV	UBLK_CONTROL
+#else
 #define	CTRL_DEV	"/dev/ublk-control"
+#endif
 
 #define CTRL_CMD_HAS_DATA	1
 #define CTRL_CMD_HAS_BUF	2
@@ -119,7 +123,9 @@ static int __ublksrv_ctrl_cmd(struct ublksrv_ctrl_dev *dev,
 		return ret;
 	}
 
-	ret = io_uring_wait_cqe(&dev->ring, &cqe);
+	do {
+		ret = io_uring_wait_cqe(&dev->ring, &cqe);
+	} while (ret == -EINTR);
 	if (ret < 0) {
 		fprintf(stderr, "wait cqe: %s\n", strerror(-ret));
 		return ret;
@@ -141,6 +147,7 @@ void ublksrv_ctrl_deinit(struct ublksrv_ctrl_dev *dev)
 
 struct ublksrv_ctrl_dev *ublksrv_ctrl_init(struct ublksrv_dev_data *data)
 {
+	struct io_uring_params p;
 	struct ublksrv_ctrl_dev *dev = (struct ublksrv_ctrl_dev *)calloc(1,
 			sizeof(*dev));
 	struct ublksrv_ctrl_dev_info *info = &dev->dev_info;
@@ -167,7 +174,8 @@ struct ublksrv_ctrl_dev *ublksrv_ctrl_init(struct ublksrv_dev_data *data)
 	dev->tgt_argv = data->tgt_argv;
 
 	/* 32 is enough to send ctrl commands */
-	ret = ublksrv_setup_ring(&dev->ring, 32, 32, IORING_SETUP_SQE128);
+	ublksrv_setup_ring_params(&p, 32, IORING_SETUP_SQE128);
+	ret = io_uring_queue_init_params(32, &dev->ring, &p);
 	if (ret < 0) {
 		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
 		free(dev);
@@ -438,6 +446,8 @@ static const char *ublksrv_dev_state_desc(struct ublksrv_ctrl_dev *dev)
 		return "LIVE";
 	case UBLK_S_DEV_QUIESCED:
 		return "QUIESCED";
+	case UBLK_S_DEV_FAIL_IO:
+		return "FAIL_IO";
 	default:
 		return "UNKNOWN";
 	};
diff --git a/nbd/tgt_nbd.cpp b/nbd/tgt_nbd.cpp
index ca9f432..de229dd 100644
--- a/nbd/tgt_nbd.cpp
+++ b/nbd/tgt_nbd.cpp
@@ -808,7 +808,6 @@ static int nbd_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
 
 	ublk_assert(jbuf);
 	ublk_assert(type == UBLKSRV_TGT_TYPE_NBD);
-	ublk_assert(!recovery || info->state == UBLK_S_DEV_QUIESCED);
 
 	ublksrv_json_read_target_str_info(jbuf, NBD_MAX_NAME, "host",
 			host_name);
@@ -834,8 +833,10 @@ static int nbd_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
 					needed_flags, cflags, opts, certfile,
 					keyfile, cacertfile, tlshostname, tls,
 					can_opt_go);
-		else
+		else {
 			ublk_err("%s: open socket failed %d\n", __func__, sock);
+			return sock;
+		}
 
 		tgt->fds[i + 1] = sock;
 		NBD_HS_DBG("%s:qid %d %s-%s size %luMB flags %x sock %d\n",
@@ -919,6 +920,10 @@ static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
 	const char *exp_name = NULL;
 	uint16_t flags = 0;
 	int ret;
+	unsigned int attrs = UBLK_ATTR_VOLATILE_CACHE;
+
+	if (read_only)
+		attrs |= UBLK_ATTR_READ_ONLY;
 
 	strcpy(tgt_json.name, "nbd");
 
@@ -963,7 +968,7 @@ static int nbd_init_tgt(struct ublksrv_dev *dev, int type, int argc,
 	struct ublk_params p = {
 		.types = UBLK_PARAM_TYPE_BASIC,
 		.basic = {
-			.attrs = read_only ? UBLK_ATTR_READ_ONLY : 0U,
+			.attrs = attrs,
 			.logical_bs_shift	= bs_shift,
 			.physical_bs_shift	= 12,
 			.io_opt_shift		= 12,
diff --git a/qcow2/README.rst b/qcow2/README.rst
deleted file mode 100644
index 145da9b..0000000
--- a/qcow2/README.rst
+++ /dev/null
@@ -1,263 +0,0 @@
-
-==========
-ublk-qcow2
-==========
-
-Motivation
-==========
-
-ublk-qcow2 is started for serving for the four purposes:
-
-- building one complicated target from scratch helps libublksrv APIs/functions
-  become mature/stable more quickly, since qcow2 is complicated and needs more
-  requirement from libublksrv compared with other simple ones(loop, null)
-
-- there are several attempts of implementing qcow2 driver in kernel, such as
-  ``qloop`` [#qloop]_, ``dm-qcow2`` [#dm_qcow2]_ and
-  ``in kernel qcow2(ro)`` [#in_kernel_qcow2_ro]_, so ublk-qcow2 might useful
-  for covering requirement in this field
-
-- performance comparison with qemu-nbd, and it was my 1st thought to evaluate
-  performance of ublk/io_uring backend by writing one ublk-qcow2 since ublksrv
-  is started
-
-- help to abstract common building block or design pattern for writing new ublk
-  target/backend
-
-Howto
-=====
-
-ublk add -t qcow2 -f $PATH_QCOW2_IMG
-
-So far not add any command line options yet. The default L2 cache size is 1MB,
-and default refcount cache size is 256KB. Both l2 and refcount slice size is
-4K. With DEBUG_QCOW2_META_STRESS enabled, two l2 slices and refcount slices
-are allowed, and ublk-qcow2 is verified with this minimum cache size setting.
-
-
-Design
-======
-
-Based on ublk framework
------------------------
-
-Based on libublksrv and common target code
-
-IO size
--------
-
-For simplifying handling of cluster mapping, the chunk_sectors of block layer
-queue limit is aligned with QCOW2's cluster size, this way guarantees that at
-most one l2 lookup is needed for handling one ublk-qcow2 IO, meantime one time
-of IO is enough to handling one ublk-qcow2 IO. But this way may hurt big chunk
-sequential IO a bit. In future, the chunk_sectors may be increased to 512KB,
-then it is enough to load L2 slice at most once for handling one ublk IO, but
-this big IO needs to be splitted to at most 512K/cluster_size small IOs.
-
-
-Async io
---------
-
-Target/backend is implemented by io_uring only, and shares same io_uring
-for handling both ublk io command and qcow2 IOs.
-
-Any IO from ublk driver has one unique tag, and any meta IO is assigned by one
-tag from ublk-qcow2 too. Each IO(includes meta IO) is handled in one coroutine
-context, so coroutine is always bound with one unique IO tag. IO is always
-submitted via io_uring in async style, then the coroutine is suspended after
-the submission. Once the IO is completed, the coroutine is resumed for further
-processing.
-
-Metadata update
----------------
-
-soft update approach is taken for maintaining qcow2 meta-data integrity in the
-event of a crash or power outage.
-
-All metadata is updated asynchronously.
-
-- meta entry dependency on cluster
-
-  When one entry of l1/refcount table/l2/refcount blk table needs to be
-  updated: 1) if the pointed cluster needs to be allocated, the entry is
-  updated after the allocated cluster is discarded/zeroed, then any
-  following reading on this mapping will get correct data. During the
-  period, any read on any sectors in this cluster will return zero, and
-  any write IO won't be started until the entry is updated. So cluster
-  discard/zeroed is always done before updating meta entry pointing to
-  this cluster and writing io data to any sector in this cluster.
-
-- io data writing depends on zeroed cluster
-
-  If the cluster isn't zeroed, the io write has to wait until the zeroing
-  is done; the io read has to return zero during the period of zeroing
-  cluster
-
-- L2/refcount blk entry can be writeback iff the pointed cluster is zeroed
-
-  Meantime the cluster for holding the table needs to be zeroed too
-
-- L1 entry depends on l2 table(cache slice)
-
-  The L1 dirty entry can only be updated iff the pointed l2 table becomes
-  clean, that means: 1) the pointed cluster needs to be zeroed; 2) all dirty
-  slices need to be updated
-
-- refcount table entry depends on refcount blk
-
-  The refcount table dirty entry can only be updated iff the pointed refcount
-  blk becomes clean, that means: 1) the pointed cluster needs to be zeroed; 2)
-  all dirty slices need to be updated
-
-
-Meta data flushing to image
----------------------------
-
-When any meta(L1/L2/refcount table/refcount blk) is being flushed to image,
-IO code path can't update the in-ram meta data until the meta is flushed to
-image, when the dirty flag is cleared.
-
-Any meta is always flushed in background:
-
-- when cache slice is added to dirty list, these cache slices will be started
-  to flush after all current IOs are handled
-
-- meta data flushing when io_uring is idle
-
-- periodic meta data flushing
-
-How to flushing meta data
-~~~~~~~~~~~~~~~~~~~~~~~~~
-
-1) allocate one tag for flushing one meta chain, and soft update has to be
-  respected, start from the lowest cluster zeroing IO to the upper layer of
-  updating l1 or refcount table
-
-2) from implementation viewpoint, find the meta flush chains from top to bottom
-
-  - find one oldest dirty entry in top meta(l1 or refcount table) or
-  specified index(flushing from slice dirty list), suppose the index is A,
-  then figure out all dirty entries in the 512 byte range which includes
-  index A
-
-  - for each dirty entry in the candidates
-     -- for each dirty slices in this cluster pointed by the dirty entry,
-     check if any pointed cluster by the slice is zeroed, if there is any,
-     wait until all clusters are zeroed
-
-     -- figure out the pointed cluster, if the cluster isn't zeroed yet,
-     zero it now
-
-     -- flushing all dirty slices in this cluster
-
-  - flush all meta entries in this 512byte area
-
-How to retrieve meta object after the meta io is done
------------------------------------------------------
-
-- use add_meta_io/del_meta_io/get_meta_io to meta flushing
-
-
-L2/refcount blk slice lifetime
-------------------------------
-
-- meta slice idea is from QEMU, and both l2/refcount block table takes one
-  cluster, and slice size is configurable, and at default both l2 &
-  refcount block slice is 4K, so either one l2 mapping is needed or
-  refcount block meta is needed, just the 4k part is loaded from image,
-  and when flushing slice to image, it is still the whole slice flushed
-  out.
-
-- For each kind of slice, one lru cache is maintained, new slice is added
-  to the lru cache, and if it is less accessed, the slice will be moved
-  towards end of the lru cache. The lru cache capacity is fixed when
-  starting ublk-qcow2, but it is configurable, and the default size is 1MB,
-  so one lru cache may hold at most 256 l2 or refcount block slices.
-  Finally, one slice may be evicted from the lru cache.
-
-- Grab two reference count in slice_cache<T>::alloc_slice(), so alloc_slice()
-  always returns one valid slice object, but it may not be in the lru list
-  because it can be evicted in nested alloc_slice() if lru capacity is
-  run out of. Note, ->wakeup_all() could trigger another alloc_slice.
-
-- When one slice is evicted from lru cache, one reference is dropped. If
-  the slice is clean, it will be added into per-device free list, which
-  will be iterated over for slice releasing when current IO batch are
-  handled. If the slice is dirty, the slice will be delayed to add to the
-  free list after flushing of this slice is completed.
-
-- when one slice is evicted from lru cache, it is moved to evicted slices
-  map, and the slice is still visible via find_slice(slice key, true), but
-  it becomes read only after being evicted from lru cache.
-
-- one slice is visible via find_slice() from allocation to freeing, and the
-  slice becomes invisible in when the slice is destructed, see
-  Qcow2L2Table::~Qcow2L2Table() and Qcow2RefcountBlock::~Qcow2RefcountBlock()
-
-Cluster state object lifetime
------------------------------
-
-Cluster state object is for tracking if one cluster is zeroed, and will be freed
-anytime after its state becomes QCOW2_ALLOC_ZEROED.
-
-Tracking dirty index
---------------------
-
-For both l2 slice and refcount blk slice, the minimum flushing unit is single
-slice, so we don't trace exact dirty index for the two.
-
-For l1 table and refcount table, the minimum flushing unit is 512byte or logical
-block size, so just track which 512byte unit is dirty.
-
-IOWaiter
------------------
-- can't write one slice when the slice is being loaded from image or being
-  stored to image 
-- after one slice is evicted from lru cache, it becomes read only automatically,
-  but the in-progress load/flush is guaranteed to be completed.
-- ``class IOWaiter`` is invented for handling all kinds of wait/wakeup, which
-  could become part of libublksrv in future
-
-
-Implementation
-==============
-
-C++
----
-
-ublk-qcow2 is basically implemented by C++, not depends on any 3rd party
-library, except for in-tree lrucache helper and nlohmann jason lib(only for
-setting up target), and built on c++ standard library almost completely.
-The frequently used component is c++'s unordered map, which is for building
-l2/refcount blk slice lru cache.
-
-c++20 is needed just for the coroutine feature, but the usage(only co_wait()
-and co_resume() is used) is simple, and could be replaced with other
-coroutine implementation if c++20 is one blocker.
-
-
-Coroutine with exception & IO tag
----------------------------------
-
-IO tag is 1:1 with coroutine context, where the IO is submitted to io_uring, and
-completed finally in this coroutine context. When waiting for io completion,
-coroutine is suspended, and once the io is done by io_uring, the coroutine
-is resumed, then IO handling can move on.
-
-Anywhere depends on one event which is usually modeled as one state change,
-the context represented by io tag is added via io_waiter.add_waiter(),
-then one io exception is thrown, and the exception is caught and the current
-coroutine is suspended. Once the state is changed to expected value, the
-waiter will be waken up via io_waiter.wakeup_all(), then the coroutine
-context waiting for the state change is resumed.
-
-C++20 coroutine is stackless, and it is very efficient, but hard to use,
-and it doesn't support nested coroutine, so programming with C++20 coroutine
-is not very easy, and this area should be improved in future.
-
-References
-==========
-
-.. [#qloop] https://upcommons.upc.edu/bitstream/handle/2099.1/9619/65757.pdf?sequence=1&isAllowed=y
-.. [#dm_qcow2] https://lwn.net/Articles/889429/
-.. [#in_kernel_qcow2_ro] https://lab.ks.uni-freiburg.de/projects/kernel-qcow2/repository 
diff --git a/qcow2/STATUS.rst b/qcow2/STATUS.rst
deleted file mode 100644
index 1330941..0000000
--- a/qcow2/STATUS.rst
+++ /dev/null
@@ -1,42 +0,0 @@
-Status
-======
-
-So far, only verified on images created by 'qemu-img create -f qcow2 $IMG $SIZE'.
-
-And only support basic read/write function on qcow2 image, not support compression
-yet, not support snapshot, not support extra options which require extra command
-line options.
-
-Not see regression on xfstest tests(XFS) by using ublk-qcow2 as test device, and
-pass kernel building test(mount ublk-qcow2 as XFS, and clone & build linux kernel).
-Not see image destruction by killing ublk daemon when running IO on this image,
-only issue is cluster leak in this test, which is usually harmless.
-
-So far it is experimental.
-
-
-TODO
-====
-
-Compression is planned to be added, so that cloud image use case can be covered.
-
-Sequential IO code path could be improved by increasing block queue limit of
-chunk_sectors to 512K or other proper size.
-
-C++ style cleanup. The last time I programming C++ is ~20years ago. So maybe
-modern C++ features/styles should be applied more.
-
-Meta data flushing improvement, this part of code isn't clean enough, IMO.
-
-All kinds of cleanup, such as slice_cache<Template> should be converted to
-slice_cache<Qcow2SliceMeta>.
-
-Cover more tests with supported qcow2 options.
-
-Coroutine improvement, the current c++20 stackless coroutine doesn't support
-nested calling, it is a bit hard to use. If this area can be improved without
-hurting performance, it will help much on building new ublk target/backend.
-
-MQ support, and one problem is still related with coroutine, where more than
-one per-queue pthread may wait for one single event, which is usually done
-in one single queue/pthread.
diff --git a/qcow2/lrucache.hpp b/qcow2/lrucache.hpp
deleted file mode 100644
index 69d0f59..0000000
--- a/qcow2/lrucache.hpp
+++ /dev/null
@@ -1,124 +0,0 @@
-/* 
- * File:   lrucache.hpp
- * Author: Alexander Ponomarev
- *
- * Created on June 20, 2013, 5:09 PM
- */
-
-/*
- * Redistribution and use in source and binary forms, with or without
-   modification, are permitted provided that the following conditions are met:
-
- * Redistributions of source code must retain the above copyright notice, this
-   list of conditions and the following disclaimer.
-
- * Redistributions in binary form must reproduce the above copyright notice,
-   this list of conditions and the following disclaimer in the documentation
-   and/or other materials provided with the distribution.
-
- * Neither the name of lamerman nor the names of its
-   contributors may be used to endorse or promote products derived from
-   this software without specific prior written permission.
-
- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
- DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
- SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
- CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
- OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef _LRUCACHE_HPP_INCLUDED_
-#define	_LRUCACHE_HPP_INCLUDED_
-
-#include <unordered_map>
-#include <list>
-#include <cstddef>
-#include <stdexcept>
-
-namespace cache {
-
-template<typename key_t, typename value_t>
-class lru_cache {
-public:
-	typedef typename std::pair<key_t, value_t> key_value_pair_t;
-	typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;
-
-	lru_cache(size_t max_size) :
-		_max_size(max_size) {
-	}
-
-	value_t remove_last() {
-		auto last = _cache_items_list.end();
-		last--;
-		auto t = last->second;
-		_cache_items_map.erase(last->first);
-		_cache_items_list.pop_back();
-
-		return t;
-	}
-
-	value_t put(const key_t& key, const value_t& value) {
-		auto it = _cache_items_map.find(key);
-		_cache_items_list.push_front(key_value_pair_t(key, value));
-		if (it != _cache_items_map.end()) {
-			_cache_items_list.erase(it->second);
-			_cache_items_map.erase(it);
-		}
-		_cache_items_map[key] = _cache_items_list.begin();
-
-		if (_cache_items_map.size() > _max_size) {
-			auto t = remove_last();
-			return t;
-		} else {
-			//throw std::range_error("no cache dropped from put");
-			return nullptr;
-		}
-	}
-
-	//just retrieve value without updating position in the lru list
-	value_t __get(const key_t& key) {
-		auto it = _cache_items_map.find(key);
-		if (it == _cache_items_map.end())
-			return nullptr;
-		else
-			return it->second->second;
-	}
-
-	value_t get(const key_t& key) {
-		auto it = _cache_items_map.find(key);
-		if (it == _cache_items_map.end()) {
-			//throw std::range_error("There is no such key in cache");
-			return nullptr;
-		} else {
-			_cache_items_list.splice(_cache_items_list.begin(), _cache_items_list, it->second);
-			return it->second->second;
-		}
-	}
-
-	bool exists(const key_t& key) const {
-		return _cache_items_map.find(key) != _cache_items_map.end();
-	}
-
-	size_t size() const {
-		return _cache_items_map.size();
-	}
-
-	const std::list<key_value_pair_t>& get_lru_list_ro() const {
-		return _cache_items_list;
-	}
-
-private:
-	std::list<key_value_pair_t> _cache_items_list;
-	std::unordered_map<key_t, list_iterator_t> _cache_items_map;
-	size_t _max_size;
-};
-
-} // namespace cache
-
-#endif	/* _LRUCACHE_HPP_INCLUDED_ */
-
diff --git a/qcow2/qcow2.cpp b/qcow2/qcow2.cpp
deleted file mode 100644
index 76bf95d..0000000
--- a/qcow2/qcow2.cpp
+++ /dev/null
@@ -1,1020 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#include "qcow2.h"
-
-Qcow2Image:: Qcow2Image(const char *path): fpath(path) {
-	fd = open(path, O_RDWR);
-	if (fd < 0)
-		ublk_err( "%s: backing file %s can't be opened %d\n",
-				__func__, path, fd);
-	fcntl(fd, F_SETFL, O_DIRECT);
-}
-
-Qcow2Image:: ~Qcow2Image() {
-	if (fd >= 0)
-		close(fd);
-}
-
-Qcow2State:: Qcow2State(const char *path, const struct ublksrv_dev *d):
-	dev_info(ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(d))),
-	min_bs_bits(9), dev(d), img(path), header(*this), l1_table(*this),
-	refcount_table(*this), cluster_allocator(*this),
-	cluster_map(*this),
-	meta_io_map(dev_info->nr_hw_queues),
-	meta_flushing(*this)
-{
-	u64 l1_bytes = get_l1_table_max_size();
-	u64 ref_table_bytes = get_refcount_table_act_size();
-
-	l1_table.load(*this, 0, l1_bytes, true);
-	//l1_table.dump();
-
-	refcount_table.load(*this, 0, ref_table_bytes, true);
-	//refcount_table.dump();
-
-	cluster_allocator.setup();
-}
-
-Qcow2State:: ~Qcow2State() {
-}
-
-u32 Qcow2State::get_l1_table_max_size()
-{
-	u32 l2_entry_size = 8;
-	u64 l2_size, res;
-
-	l2_entry_size = header.is_extended_l2_entries() ? 16 : 8;
-
-	l2_size = ((1 << header.cluster_bits) / l2_entry_size) <<
-		header.cluster_bits;
-	res = (header.get_size() + l2_size - 1) / l2_size;
-	res *= 8;
-
-	//qcow2_log("%s: cls bit %d, l2 entry size %d, l2_size %d, l1 tbl size %d\n",
-	//		__func__, header.cluster_bits, l2_entry_size, l2_size, res);
-	if (res < QCOW_MAX_L1_SIZE)
-		return round_up(res, 1UL << min_bs_bits);
-	return  QCOW_MAX_L1_SIZE;
-}
-
-u32 Qcow2State::get_refcount_table_max_size()
-{
-	u64 blk_size, res;
-
-	blk_size = 1ULL << (2 * header.cluster_bits + 3 - header.refcount_order);
-	res = (header.get_size() + blk_size - 1) / blk_size;
-	res *= 8;
-
-	//qcow2_log("%s: cls bit %d, refcount_order %d, blk_size %llu, ref tbl size %d\n",
-	//		__func__, header.cluster_bits, header.refcount_order, blk_size, res);
-	if (res < QCOW_MAX_REFTABLE_SIZE)
-		return round_up(res, 1UL << min_bs_bits);
-	return  QCOW_MAX_REFTABLE_SIZE;
-}
-
-u32 Qcow2State::get_refcount_table_act_size()
-{
-	u64 ref_table_bytes = header.get_refcount_table_clusters() <<
-		header.cluster_bits;
-
-	if (ref_table_bytes > get_refcount_table_max_size())
-		ref_table_bytes = get_refcount_table_max_size();
-
-	return round_up(ref_table_bytes, 1UL << min_bs_bits);
-}
-
-u64  Qcow2State::get_l1_table_offset()
-{
-	return header.get_l1_table_offset();
-}
-
-u64 Qcow2State::get_refcount_table_offset()
-{
-	return header.get_refcount_table_offset();
-}
-
-u32 Qcow2State::get_l2_slices_count()
-{
-	u32 mapping_bytes = get_dev_size() >> (header.cluster_bits - 3);
-
-	//align with qemu, at most 32MB
-	if (mapping_bytes > (32U << 20))
-		mapping_bytes = 32U << 20;
-
-	return mapping_bytes >> QCOW2_PARA::L2_TABLE_SLICE_BITS;
-}
-
-u32 Qcow2State::add_meta_io(u32 qid, Qcow2MappingMeta *m)
-{
-	struct meta_mapping *map = &meta_io_map[qid];
-	std::vector <Qcow2MappingMeta *> &v = map->meta;
-	int i;
-
-	for (i = 0; i < v.size(); i++)
-		if (v[i] == nullptr)
-			break;
-	if (i < v.size()) {
-		v[i] = m;
-	} else {
-		v.push_back(m);
-		i = v.size() - 1;
-	}
-
-	map->nr += 1;
-
-	return i;
-}
-
-bool Qcow2State::has_dirty_slice()
-{
-	return cluster_map.cache.has_dirty_slice(*this) ||
-		cluster_allocator.cache.has_dirty_slice(*this);
-}
-
-void Qcow2State::reclaim_slice(Qcow2SliceMeta *m)
-{
-	if (m->is_mapping_meta()) {
-		Qcow2L2Table *t =
-			static_cast<Qcow2L2Table *>(m);
-
-		cluster_map.cache.add_slice_to_reclaim_list(t);
-	} else {
-		Qcow2RefcountBlock *t =
-			static_cast<Qcow2RefcountBlock *>(m);
-
-		cluster_allocator.cache.add_slice_to_reclaim_list(t);
-	}
-}
-
-void Qcow2State::remove_slice_from_evicted_list(Qcow2SliceMeta *m)
-{
-	if (m->is_mapping_meta()) {
-		Qcow2L2Table *t =
-			static_cast<Qcow2L2Table *>(m);
-
-		cluster_map.cache.remove_slice_from_evicted_list(t);
-	} else {
-		Qcow2RefcountBlock *t =
-			static_cast<Qcow2RefcountBlock *>(m);
-
-		cluster_allocator.cache.remove_slice_from_evicted_list(t);
-	}
-}
-
-void Qcow2State::dump_meta()
-{
-	cluster_allocator.dump_meta();
-	cluster_map.dump_meta();
-	meta_flushing.dump();
-}
-
-//todo: allocate from slices from reclaim_slices
-void Qcow2State::kill_slices(const struct ublksrv_queue *q)
-{
-	std::vector<Qcow2SliceMeta *> tmp(move(freed_slices));
-
-	if (tmp.empty())
-		return;
-
-	qcow2_assert(!tmp.empty() && freed_slices.empty());
-
-	//can't free new added slice from ->wakeup_all()
-	for (auto it = tmp.cbegin(); it != tmp.cend(); ++it) {
-		auto m = *it;
-
-		m->put_ref();
-	}
-}
-
-void Qcow2State::shrink_cache()
-{
-	cluster_map.cache.shrink(*this);
-	cluster_allocator.cache.shrink(*this);
-}
-
-#ifdef DEBUG_QCOW2_META_VALIDATE
-void Qcow2State::validate_cluster_use(u64 host_off, u64 virt_off, u32 use) {
-	auto it = cluster_use.find(host_off);
-
-	if (it == cluster_use.end())
-		cluster_use[host_off] = ((u64)use << 56) | virt_off;
-	else {
-		qcow2_log("%s: duplicated cluster assignment host off "
-				"%llx, virt_off %llx use %d, old entry %llx\n",
-				__func__, host_off, virt_off, use,
-				it->second);
-		qcow2_assert(0);
-	}
-}
-
-// call it for each entry before flushing the slice
-bool Qcow2State::validate_cluster_map(u64 host_off, u64 virt_off) {
-	auto it = cluster_validate_map.find(host_off);
-
-	if (it == cluster_validate_map.end()) {
-		cluster_validate_map[host_off] = virt_off;
-		return true;
-	}
-
-	if (virt_off == it->second)
-		return true;
-
-	qcow2_log("%s: duplicated cluster assignment host off "
-			"%llx, virt_off %llx old virt_offset %llx\n",
-			__func__, host_off, virt_off, it->second);
-	return false;
-}
-#endif
-
-/* Make any kind of Qcow2State, so far only support the plain one */
-Qcow2State *make_qcow2state(const char *file, struct ublksrv_dev *dev)
-{
-	return new Qcow2StatePlain(file, dev);
-}
-
-template <class T>
-slice_cache<T>::slice_cache(u8 slice_bits, u8 cluster_bits, u8 slice_virt_bits,
-		u32 max_size):
-	slice_size_bits(slice_bits),
-	cluster_size_bits(cluster_bits),
-	slice_virt_size_bits(slice_virt_bits),
-	slices(max_size >> slice_bits),
-	evicted_slices({})
-{
-}
-
-template <class T>
-T *slice_cache<T>::__find_slice(u64 key, bool use_evicted_cache) {
-	T *t = slices.__get(key);
-
-	if (t)
-		return t;
-
-	if (use_evicted_cache) {
-		auto it = evicted_slices.find(key);
-
-		if (it != evicted_slices.end())
-			return it->second;
-	}
-	return nullptr;
-}
-
-template <class T>
-T *slice_cache<T>::alloc_slice(Qcow2State &state, const qcow2_io_ctx_t &ioc,
-		u64 virt_offset, u64 host_offset, u32 parent_idx)
-{
-	T *t;
-	u32 flags;
-	bool zero_buf;
-
-	qcow2_assert(__find_slice(virt_offset, true) == nullptr);
-	qcow2_assert(!(virt_offset & ((1ULL << cluster_size_bits) - 1)));
-
-	if (!state.cluster_allocator.alloc_cluster_is_zeroed(host_offset &
-				~((1ULL << cluster_size_bits) - 1))) {
-		flags = QCOW2_META_UPDATE | QCOW2_META_DIRTY;
-		zero_buf = true;
-	} else {
-		flags = 0;
-		zero_buf = false;
-	}
-
-	t = pick_slice_from_reclaim_list();
-	if (t == nullptr)
-		t = new T(state, host_offset, parent_idx, flags);
-	else
-		t->reset(state, host_offset, parent_idx, flags);
-
-	if (t->get_dirty(-1))
-		state.meta_flushing.inc_dirtied_slice(t->is_mapping_meta());
-
-	if (zero_buf)
-		t->zero_buf();
-
-	T *old = slices.put(virt_offset, t);
-	if (old) {
-#ifdef DEBUG_QCOW2_META_OBJ
-		qcow2_assert(__find_slice(old->virt_offset(), true)
-				== nullptr);
-#endif
-		//loading or flushing may be in-progress, that is allowed.
-		//and we guarantee that the slice isn't released until
-		//the loading or flushing is done
-		old->set_evicted();
-		add_slice_to_evicted_list(old->virt_offset(), old);
-
-		//can't free one dirty slice, but one clean slice can't
-		//be dirtied after it is evicted, so safe to move clean
-		//slice into free list for release
-		if (!old->get_dirty(-1))
-			state.add_slice_to_free_list(old);
-		old->put_ref();
-
-#ifdef QCOW2_DEBUG
-		ublk_dbg(UBLK_DBG_QCOW2_META, "%s: %s evicted from tag %d, obj %p flags %x offset %lx ref %d\n",
-				__func__, old->get_id(), ioc.get_tag(), old,
-				old->get_flags(), old->get_offset(),
-				old->read_ref());
-#endif
-	}
-
-	if (virt_offset != t->virt_offset()) {
-		ublk_err( "%s %d: %s %" PRIx64 "/%" PRIx64 " parent_idx %d host_off %" PRIx64 " flags %x\n",
-			__func__, __LINE__, typeid(*t).name(),
-			virt_offset, t->virt_offset(), parent_idx,
-			host_offset, flags);
-		qcow2_assert(virt_offset == t->virt_offset());
-	}
-
-	return t;
-}
-
-template <class T>
-void slice_cache<T>::add_slice_to_evicted_list(u64 virt_offset, T *t)
-{
-	auto it = evicted_slices.find(virt_offset);
-
-	qcow2_assert(virt_offset == t->virt_offset());
-
-	if (it == evicted_slices.end())
-		evicted_slices[virt_offset] = t;
-	else {
-#if 1
-		auto m = it->second;
-		qcow2_log("%s: add duplicated cache virt_offset %" PRIx64 ", remove old entry(%p %lx/%lx %x %d)\n",
-				__func__, virt_offset, m, m->virt_offset(),
-				m->get_offset(), m->get_flags(), m->read_ref());
-		it->second->show(__func__, __LINE__);
-		qcow2_assert(0);
-#endif
-
-		//this slice has been in handled in prep_flushing,
-		//so it is fine to remove it from freed list now
-		evicted_slices.erase(it);
-		evicted_slices[virt_offset] = t;
-	}
-}
-
-template <class T>
-void slice_cache<T>::dump(Qcow2State &qs) {
-	auto lru_list = slices.get_lru_list_ro();
-
-	ublk_log("cache size %zu, dirty cache size %zu\n",
-			slices.size(), evicted_slices.size());
-
-	//todo: use lrucache iterator to cut the loop time
-	for (auto it = lru_list.cbegin(); it != lru_list.cend(); ++it) {
-		T *t = it->second;
-
-		if (t)
-			t->dump();
-	}
-}
-
-template <class T>
-int slice_cache<T>::figure_group_from_dirty_list(Qcow2State &qs) {
-	std::unordered_map<u32, int> cnt;
-	int val = -1;
-	int idx = -1;
-
-	for (auto it = evicted_slices.cbegin(); it != evicted_slices.cend(); ++it) {
-		u32 key = (it->second->parent_idx * 8) / 512;
-		auto it1 = cnt.find(key);
-
-		if (it1 == cnt.end())
-			cnt[key] = 0;
-		else
-			cnt[key] += 1;
-	}
-
-	for (auto it = cnt.cbegin(); it != cnt.cend(); ++it) {
-		if (it->second > val) {
-			idx = it->first;
-			val = it->second;
-		}
-	}
-
-	flush_log("%s: dirty list: idx %d cnt %u\n", __func__, idx, val);
-
-	qcow2_assert(idx != -1);
-	return idx;
-}
-
-template <class T>
-int slice_cache<T>::__figure_group_for_flush(Qcow2State &qs)
-{
-	std::unordered_map<u32, int> cnt;
-	int val = -1;
-	int idx = -1;
-	auto lru_list = slices.get_lru_list_ro();
-
-	//todo: use lrucache iterator to cut the loop time
-	for (auto it = lru_list.cbegin(); it != lru_list.cend(); ++it) {
-		T *t = it->second;
-
-		if (t != nullptr && t->get_dirty(-1) && !t->is_flushing()) {
-			u32 key = (t->parent_idx * 8) / 512;
-			auto it1 = cnt.find(key);
-
-			if (it1 == cnt.end())
-				cnt[key] = 0;
-			else
-				cnt[key] += 1;
-		}
-	}
-
-	if (cnt.size() == 0)
-		return -1;
-
-	for (auto it = cnt.cbegin(); it != cnt.cend(); ++it) {
-		if (it->second > val) {
-			idx = it->first;
-			val = it->second;
-		}
-	}
-	qcow2_assert(idx != -1);
-	flush_log("%s: lru list: idx %d cnt %u\n", __func__, idx, val);
-	return idx;
-}
-
-template <class T>
-int slice_cache<T>::figure_group_for_flush(Qcow2State &qs)
-{
-	if (evicted_slices.size() > 0)
-		return figure_group_from_dirty_list(qs);
-
-	return __figure_group_for_flush(qs);
-}
-
-template <class T>
-bool slice_cache<T>::has_dirty_slice(Qcow2State &qs)
-{
-	auto lru_list = slices.get_lru_list_ro();
-
-	//todo: use lrucache iterator to cut the loop time
-	for (auto it = lru_list.cbegin(); it != lru_list.cend(); ++it) {
-		T *t = it->second;
-
-		if (t != nullptr && t->get_dirty(-1) && !t->is_flushing())
-			return true;
-	}
-
-	return has_evicted_dirty_slices();
-}
-
-template <class T>
-void slice_cache<T>::shrink(Qcow2State &qs)
-{
-	u32 cnt = qs.get_l2_slices_count();
-
-	for (auto it = reclaimed_slices.cbegin();
-			it != reclaimed_slices.cend(); ++it) {
-		delete *it;
-	}
-
-	reclaimed_slices.clear();
-
-	cnt >>= 3;
-
-	//shrink cache until 1/8 slices are kept
-	while (slices.size() > cnt) {
-		auto t = slices.remove_last();
-
-		delete t;
-	}
-}
-
-// refcount table shouldn't be so big
-Qcow2ClusterAllocator::Qcow2ClusterAllocator(Qcow2State &qs): state(qs),
-	cache(REFCOUNT_BLK_SLICE_BITS, qs.header.cluster_bits,
-		qs.header.cluster_bits + 3 - qs.header.refcount_order +
-		QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS,
-		QCOW2_PARA::REFCOUNT_BLK_MAX_CACHE_BYTES),
-	alloc_state({})
-{
-	max_alloc_states = 0;
-};
-
-Qcow2RefcountBlock* Qcow2ClusterAllocator::__find_slice(u64 key)
-{
-	return cache.__find_slice(key, true);
-}
-
-int Qcow2ClusterAllocator::figure_group_from_refcount_table()
-{
-	int ret = cache.figure_group_for_flush(state);
-
-	if (ret == -1)
-		return state.refcount_table.get_1st_dirty_blk();
-	return ret;
-}
-
-void Qcow2ClusterAllocator::alloc_cluster_started(const qcow2_io_ctx_t &ioc,
-		u64 cluster_offset, u8 purpose)
-{
-	auto it = alloc_state.find(cluster_offset);
-	u32 sz;
-
-	qcow2_assert(it == alloc_state.end());
-
-	alloc_state[cluster_offset] = new Qcow2ClusterState(
-			QCOW2_ALLOC_STARTED, purpose);
-
-	sz = alloc_state.size();
-
-	if (sz > max_alloc_states)
-		max_alloc_states = sz;
-
-	alloc_log("%s: offset %lx state %d purpose %d\n",
-			__func__, cluster_offset,
-			QCOW2_ALLOC_STARTED, purpose);
-}
-
-void Qcow2ClusterAllocator::alloc_cluster_zeroing(const qcow2_io_ctx_t &ioc,
-		u64 cluster_offset)
-{
-	auto it = alloc_state.find(cluster_offset);
-
-	qcow2_assert(it != alloc_state.end());
-
-	it->second->set_state(QCOW2_ALLOC_ZEROING);
-
-	alloc_log("%s: offset %lx state %d purpose %d\n", __func__,
-			cluster_offset, it->second->get_state(),
-			it->second->get_purpose());
-}
-
-void Qcow2ClusterAllocator::alloc_cluster_zeroed(const struct ublksrv_queue *q,
-		int tag, u64 cluster_offset)
-{
-	auto it = alloc_state.find(cluster_offset);
-
-	if (it == alloc_state.end())
-		ublk_err( "%s: offset %lx\n", __func__, cluster_offset);
-	qcow2_assert(it != alloc_state.end());
-
-	it->second->set_state(QCOW2_ALLOC_ZEROED);
-	alloc_log("%s: offset %lx state %d purpose %d\n", __func__,
-			cluster_offset, it->second->get_state(),
-			it->second->get_purpose());
-
-	it->second->wakeup_all(q, tag);
-
-	/* safe to remove it now */
-	delete it->second;
-	alloc_state.erase(it);
-}
-
-//called after mapping is setup for this cluster
-void Qcow2ClusterAllocator::alloc_cluster_done(const qcow2_io_ctx_t &ioc,
-		u64 cluster_offset)
-{
-	auto it = alloc_state.find(cluster_offset);
-
-	qcow2_assert(it != alloc_state.end());
-
-	delete it->second;
-
-	alloc_state.erase(it);
-}
-
-void Qcow2ClusterAllocator::dump_meta() {
-
-	qcow2_log("cluster allocator %s: total allocates %" PRIu64 " clusters, bytes %" PRIu64 "KB, max states %u/%lu\n",
-			__func__, alloc_cnt, (alloc_cnt <<
-			state.header.cluster_bits) >> 10,
-			max_alloc_states, alloc_state.size());
-	state.refcount_table.dump();
-	cache.dump(state);
-}
-
-void Qcow2ClusterAllocator::setup() {
-	long i = 0;
-
-	for (i = (state.refcount_table.get_data_len() / 8) - 1; i >= 0; i--)
-		if (state.refcount_table.get_entry(i) != 0)
-			break;
-	/*
-	 * most of times this entry has slot available yet, otherwise
-	 * allocate_cluster() will move to next refcount block cache
-	 */
-	state.refcount_table.set_next_free_idx(i);
-
-	table_entry_virt_size_bits = 2 * state.header.cluster_bits + 3 -
-		state.header.refcount_order;
-	slice_idx = 0;
-	alloc_cnt = 0;
-
-	//just one estimation, for runtime check only
-	max_physical_size = ((u64)(i + 1)) << table_entry_virt_size_bits;
-}
-
-void Qcow2ClusterAllocator::allocate_refcount_blk(const qcow2_io_ctx_t &ioc,
-		s32 idx)
-{
-	Qcow2RefcountBlock *rb;
-	u64 virt_offset = (u64)idx << table_entry_virt_size_bits;
-	u64 host_offset = virt_offset;
-
-	if (state.refcount_table.is_flushing(idx)) {
-		state.refcount_table.add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	max_physical_size = ((u64)(idx + 1)) << table_entry_virt_size_bits;
-	state.refcount_table.set_next_free_idx(idx);
-	qcow2_assert(!state.refcount_table.get_entry(idx));
-	state.refcount_table.set_entry(idx, host_offset);
-
-	//track the new allocated cluster
-	alloc_cluster_started(ioc, host_offset,
-			QCOW2_CLUSTER_USE::REFCOUNT_BLK);
-	state.validate_cluster_use(host_offset, virt_offset,
-			QCOW2_CLUSTER_USE::REFCOUNT_BLK);
-
-	rb = cache.alloc_slice(state, ioc, virt_offset, host_offset, idx);
-	qcow2_assert(rb != nullptr);
-	qcow2_assert(rb->get_update() && !rb->get_evicted() &&
-			!rb->is_flushing());
-
-	//the first cluster is for this refcount block
-	rb->set_entry(0, 1);
-	rb->set_next_free_idx(1);
-}
-
-u64 Qcow2ClusterAllocator::allocate_cluster(const qcow2_io_ctx_t &ioc)
-{
-	Qcow2RefcountBlock *rb;
-	s32 free_idx;
-	u64 virt_offset, host_offset;
-
-again:
-	free_idx = state.refcount_table.get_next_free_idx();
-	virt_offset = ((u64)free_idx << table_entry_virt_size_bits) +
-		((u64)slice_idx << cache.get_slice_virt_size_bits());
-	rb = cache.find_slice(virt_offset, true);
-	if (rb == nullptr)
-		goto alloc_refcount_blk;
-	qcow2_assert(rb->read_ref() > 0);
-
-check_new:
-	/* the cache has been allocated & being loaded */
-	if (!rb->get_update()) {
-		rb->add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	//if we are being flushed, can't touch the in-ram table,
-	//so wait until the flushing is done
-	if (rb->is_flushing() || rb->get_evicted()) {
-		rb->add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-#ifdef QCOW2_CACHE_DEBUG
-	qcow2_log("%s: hit: next free %d entries %d virt_off %llx slice_idx %d\n",
-			__func__, rb->get_next_free_idx(), rb->get_nr_entries(),
-			virt_offset, slice_idx);
-#endif
-	//todo: cache the last free entry
-	for (int i = rb->get_next_free_idx(); i < rb->get_nr_entries(); i++) {
-		if (i < 0)
-			continue;
-		//qcow2_log("\t entry[%d]=%llx\n", i, rb->get_entry(i));
-		if (rb->get_entry_fast(i) == 0) {
-			u64 res = virt_offset + (((u64)i) <<
-					state.header.cluster_bits);
-
-			if (!rb->get_dirty(-1))
-				state.meta_flushing.inc_dirtied_slice(false);
-			qcow2_assert(rb->get_update() && !rb->is_flushing() &&
-				!rb->get_evicted());
-			rb->set_entry(i, 1);
-			rb->set_next_free_idx(i + 1);
-
-			alloc_cnt++;
-			return res;
-		}
-	}
-
-	if (++slice_idx < cache.get_nr_slices())
-		goto again;
-
-	// this current cache is full, so move to next one.
-	//
-	// Here it is different with l2 table's cache which is sliced, but
-	// refcount blk cache size is always equal to one cluster
-	qcow2_assert(free_idx < state.refcount_table.get_nr_entries());
-	allocate_refcount_blk(ioc, free_idx + 1);
-	slice_idx = 0;
-	goto again;
-
-alloc_refcount_blk:
-	//start is host offset of refcount block object
-	host_offset = state.refcount_table.get_entry(free_idx) +
-			    + (u64(slice_idx) << cache.get_slice_size_bits());
-
-	rb = cache.alloc_slice(state, ioc, virt_offset, host_offset, free_idx);
-
-	/* the cluster may be allocated just in ram, no need to load */
-	if (rb->get_update())
-		goto check_new;
-
-	rb->load(state, ioc, QCOW2_PARA::REFCOUNT_BLK_SLICE_BYTES, false);
-
-	//add our tag into io_waiters, so once we get updated,
-	//the current io context will be resumed when handling cqe
-	//
-	//we have to call it explicitly here for both io contexts
-	//which starts to load meta and wait for in-flight meta
-	rb->add_waiter(ioc.get_tag());
-
-	//->handle_io_async() has to handle this exception
-	throw MetaIoException();
-
-	return 0;
-}
-
-// refcount table shouldn't be so big
-Qcow2ClusterMapping::Qcow2ClusterMapping(Qcow2State &qs): state(qs),
-	cache(QCOW2_PARA::L2_TABLE_SLICE_BITS,
-		qs.header.cluster_bits,
-		qs.header.cluster_bits + L2_TABLE_SLICE_BITS - 3,
-		qs.get_l2_slices_count() * QCOW2_PARA::L2_TABLE_SLICE_BYTES),
-	cluster_bits(state.header.cluster_bits),
-	l2_entries_order(state.header.cluster_bits - 3),
-	max_alloc_entries(0)
-{
-}
-
-Qcow2L2Table* Qcow2ClusterMapping::__find_slice(u64 key, bool use_dirty)
-{
-	return cache.__find_slice(key, use_dirty);
-}
-
-int Qcow2ClusterMapping::figure_group_from_l1_table()
-{
-	int ret = cache.figure_group_for_flush(state);
-
-	if (ret == -1)
-		return state.l1_table.get_1st_dirty_blk();
-	return ret;
-}
-
-Qcow2L2Table *Qcow2ClusterMapping::create_and_add_l2(const qcow2_io_ctx_t &ioc,
-		u64 offset)
-{
-	const unsigned idx = l1_idx(offset);
-	u64 l1_entry = state.l1_table.get_entry(idx);
-	u64 l2_cluster = -1;
-	const struct ublksrv_queue *q = ublksrv_get_queue(state.dev, ioc.get_qid());
-	Qcow2L2Table *l2 = nullptr;
-
-	qcow2_assert(!state.l1_table.entry_allocated(l1_entry));
-
-	//in case of being flushed, we can't update in-ram meta, so
-	//exit and wait for flush completion
-	if (state.l1_table.is_flushing(idx)) {
-		state.l1_table.add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	//if someone is allocating cluster for this entry, wait until
-	//the entry becomes valid or failed
-	if (entry_is_allocating(offset, true)) {
-		u32 owner = entry_get_alloc_owner(offset, true);
-
-		if (owner != ioc.get_tag()) {
-			state.l1_table.add_waiter_idx(ioc.get_tag(), idx);
-			throw MetaUpdateException();
-		}
-	} else {
-		//store owner into the entry for marking we are allocating, so
-		//others can't allocate for this entry any more, and others
-		//just need to wait until the allocation is done
-		entry_mark_allocating(offset, ioc.get_tag(), true);
-	}
-
-	l2_cluster = state.cluster_allocator.allocate_cluster(ioc);
-	if (l2_cluster == -1) {
-		state.l1_table.set_entry(idx, 0);
-	} else {
-		unsigned long s_idx = cache.get_slice_idx(l2_slice_key(offset));
-		u64 host_offset = l2_cluster +
-			(s_idx << cache.get_slice_size_bits());
-
-		state.cluster_allocator.alloc_cluster_started(ioc,
-				l2_cluster, QCOW2_CLUSTER_USE::L2_TABLE);
-		state.validate_cluster_use(l2_cluster, l2_slice_key(offset),
-				QCOW2_CLUSTER_USE::L2_TABLE);
-		//allocate l2 cache
-		l2 = cache.alloc_slice(state, ioc, l2_slice_key(offset),
-				host_offset, idx);
-		l2->get_ref();
-		qcow2_assert(l2->get_update());
-
-		l2_cluster |= 1ULL << 63;
-		state.l1_table.set_entry(idx, l2_cluster);
-	}
-
-	entry_mark_allocated(offset, true);
-	state.l1_table.wakeup_all_idx(q, ioc.get_tag(), idx);
-
-	return l2;
-}
-
-Qcow2L2Table *Qcow2ClusterMapping::load_l2_slice(const qcow2_io_ctx_t &ioc, u64 offset,
-		u64 l1_entry)
-{
-	const u64 slice_offset = (l2_idx(offset) << 3) &
-		~(QCOW2_PARA::L2_TABLE_SLICE_BYTES - 1);
-	u64 start = (l1_entry & ((1ULL << 63) - 1)) + slice_offset;
-	Qcow2L2Table *l2;
-
-	l2 = cache.alloc_slice(state, ioc, l2_slice_key(offset), start,
-			l1_idx(offset));
-	//start may point to one new allocated cluster
-	if (l2->get_update()) {
-		l2->get_ref();
-		return l2;
-	}
-
-	ublk_dbg(UBLK_DBG_QCOW2_META_L2, "cache: alloc: key %" PRIx64 " val %p, update %d\n",
-			start, l2, l2->get_update());
-	l2->load(state, ioc, QCOW2_PARA::L2_TABLE_SLICE_BYTES, false);
-	l2->add_waiter(ioc.get_tag());
-	throw MetaIoException();
-
-	return l2;
-}
-
-//return l2 slice object with holding one extra reference
-Qcow2L2Table *Qcow2ClusterMapping::create_l2_map(const qcow2_io_ctx_t &ioc,
-		u64 offset, bool create_l2)
-{
-	u64 l1_entry = state.l1_table.get_entry_fast(l1_idx(offset));
-	Qcow2L2Table *l2 = nullptr;
-
-	if (state.l1_table.entry_allocated(l1_entry))
-		return load_l2_slice(ioc, offset, l1_entry);
-
-	if (create_l2) {
-		// l2 table isn't allocated yet, so create one and add it here
-		l2 = create_and_add_l2(ioc, offset);
-		if (!l2)
-			ublk_err( "%s: tag %d: allocate l2 failed for %" PRIx64 "\n",
-				__func__, ioc.get_tag(), offset);
-	}
-	return l2;
-}
-
-//virt_offset's l2 table doesn't include this entry yet, so allocate
-//one cluster and install the mapping
-int Qcow2ClusterMapping::build_mapping(const qcow2_io_ctx_t &ioc,
-		u64 virt_offset, Qcow2L2Table *l2, u32 idx_in_slice,
-		u64 *l2_entry)
-{
-	const struct ublksrv_queue *q = ublksrv_get_queue(state.dev, ioc.get_qid());
-	u64 data_cluster = -1;
-	int ret;
-
-	qcow2_assert(l2->get_update());
-
-	//in case of being flushed, we can't update in-ram meta, so
-	//exit and wait for flush completion
-	//
-	//If this slice is marked as PREP_FLUSH, the dependent refcount
-	//block tables are being flushed, so delay this slice update
-	//until our flushing is done
-	if (l2->is_flushing() || l2->get_evicted() || l2->get_prep_flush()) {
-		l2->add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	qcow2_assert(l2->read_ref() > 0);
-
-	if (entry_is_allocating(virt_offset, false)) {
-		u32 owner = entry_get_alloc_owner(virt_offset, false);
-
-		if (owner != ioc.get_tag()) {
-			l2->add_waiter_idx(ioc.get_tag(), idx_in_slice);
-			throw MetaUpdateException();
-		}
-	} else {
-		entry_mark_allocating(virt_offset, ioc.get_tag(), false);
-	}
-
-	data_cluster = state.cluster_allocator.allocate_cluster(ioc);
-	qcow2_assert(l2->get_update() && !l2->is_flushing() &&
-			!l2->get_evicted());
-	if (data_cluster == -1) {
-		l2->set_entry(idx_in_slice, 0);
-		ret = -ENOSPC;
-	} else {
-		state.cluster_allocator.alloc_cluster_started(ioc,
-				data_cluster, QCOW2_CLUSTER_USE::DATA);
-		state.validate_cluster_use(data_cluster, virt_offset,
-				QCOW2_CLUSTER_USE::DATA);
-		data_cluster |= 1ULL << 63;
-		*l2_entry = data_cluster;
-		if (!l2->get_dirty(-1))
-			state.meta_flushing.inc_dirtied_slice(true);
-		l2->set_entry(idx_in_slice, data_cluster);
-		ret = 0;
-	}
-
-	l2->check(state, __func__, __LINE__);
-
-	entry_mark_allocated(virt_offset, false);
-	l2->wakeup_all_idx(q, ioc.get_tag(), idx_in_slice);
-	return ret;
-}
-
-//we get one extra reference of l2 when calling this function.
-u64 Qcow2ClusterMapping::__map_cluster(const qcow2_io_ctx_t &ioc,
-		Qcow2L2Table *l2, u64 offset, bool create_l2)
-{
-	const u32 idx_in_slice = ((l2_idx(offset) << 3) &
-			(QCOW2_PARA::L2_TABLE_SLICE_BYTES - 1)) >> 3;
-	u64 l2_entry;
-	int ret;
-
-	qcow2_assert(l2->read_ref() > 0);
-	l2->check(state, __func__, __LINE__);
-
-	/* the cache is being loaded */
-	if (!l2->get_update()) {
-		l2->add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	l2_entry = l2->get_entry_fast(idx_in_slice);
-	if (l2->entry_allocated(l2_entry))
-		goto exit;
-
-	if (!create_l2)
-		return 0;
-
-	ret = build_mapping(ioc, offset, l2, idx_in_slice, &l2_entry);
-	if (ret) {
-		qcow2_log("%s %d: tag %d build l2 mapping failed %d\n",
-				__func__, __LINE__, ioc.get_tag(), ret);
-		return 0;
-	}
-exit:
-	qcow2_assert(l2->entry_allocated(l2_entry));
-	return l2_entry & ((1ULL << 63) - 1);
-}
-
-
-//any caller has to catch both MetaIoException and MetaUpdateException
-u64 Qcow2ClusterMapping::map_cluster(const qcow2_io_ctx_t &ioc, u64 offset,
-		bool create_l2)
-{
-	Qcow2L2Table *l2 = cache.find_slice(l2_slice_key(offset), true);
-	u64 off_in_cls = offset & ((1ULL << cluster_bits) - 1);
-	u64 host_off = 0;
-
-	offset = offset & ~((1ULL << cluster_bits) - 1);
-
-	// l2 could be freed when wakeup() is called, so refcount
-	// has to be grabbed
-	if (l2) {
-		l2->get_ref();
-	} else {
-		try {
-			l2 = create_l2_map(ioc, offset, create_l2);
-		} catch (MetaIoException &meta_error) {
-			throw MetaIoException();
-		} catch (MetaUpdateException &meta_update_error) {
-			throw MetaUpdateException();
-		}
-	}
-
-	if (l2 == nullptr)
-		return 0;
-
-	try {
-		host_off = __map_cluster(ioc, l2, offset, create_l2);
-	} catch (MetaIoException &meta_error) {
-		l2->put_ref();
-		throw MetaIoException();
-	} catch (MetaUpdateException &meta_update_error) {
-		l2->put_ref();
-		throw MetaUpdateException();
-	}
-
-	l2->put_ref();
-
-	if (host_off & QCOW_OFLAG_COMPRESSED)
-		return (u64)-1;
-
-	return host_off + off_in_cls;
-}
-
-void Qcow2ClusterMapping::dump_meta()
-{
-	qcow2_log("cluster mapping%s: max_alloc_entries %u/%lu\n", __func__,
-			max_alloc_entries, entry_alloc.size());
-	state.l1_table.dump();
-	cache.dump(state);
-}
diff --git a/qcow2/qcow2.h b/qcow2/qcow2.h
deleted file mode 100644
index 2af94a8..0000000
--- a/qcow2/qcow2.h
+++ /dev/null
@@ -1,755 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#ifndef UBLK_QCOW2_H_
-#define UBLK_QCOW2_H_
-
-#include <string>
-#include <iostream>
-#include <valarray>
-#include <unordered_set>
-#include <unordered_map>
-#include <bits/stdc++.h>
-#include <exception>
-#include <chrono>
-#include <deque>
-#include "lrucache.hpp"
-#include "qcow2_format.h"
-#include "qcow2_meta.h"
-
-class Qcow2State;
-class Qcow2Header;
-
-/*
- * Design overview
- *
- * 1) code reuse:
- *    - such as code can be reused as one libqcow2
- *
- *    - internal implementation maximize reusing design & code	
- *
- * 2) io isolation: io handling code often depends on os or platform or
- * user choice, so io handling isolation is considered from the beginning;
- * but focus on aio style
- * 
- * 3) completely aio: for read/write io and meta
- */
-
-/* MQ support:
- *
- * 1) how to share meta data among queues?  meta data has to be protected for
- * support MQ
- *
- * 2) we can start from SQ support.
- */
-
-/*
- * Buffer management and cache design:
- *
- * 1) fixed amount of buffer is pre-allocated & shared for all l2 cache slice,
- * refcount blk, just like qcow2
- *
- * 2) fixed buffer is pre-allocated for header, l1, refcount table and other
- * kind of meta, but the buffer is dedicated
- *
- * Cache design(L2 table cache, refcount block cache):
- *
- * 1) why can't support for l1/refcount table
- *
- */
-
-class MetaIoException: public std::exception
-{
-public:
-	const char * what() { return "MetaIO exception"; }
-};
-
-class MetaUpdateException: public std::exception
-{
-public:
-	const char * what() { return "MetaEntry update exception"; }
-};
-
-template <class T>
-class slice_cache {
-private:
-	u8 slice_size_bits, cluster_size_bits, slice_virt_size_bits;
-
-	cache::lru_cache<u64, T *> slices;
-	std::unordered_map<u64, T *> evicted_slices;
-
-	std::deque<T *> reclaimed_slices;
-
-	int __figure_group_for_flush(Qcow2State &qs);
-	int figure_group_from_dirty_list(Qcow2State &qs);
-public:
-	void add_slice_to_reclaim_list(T *t) {
-		reclaimed_slices.push_back(t);
-	}
-
-	T *pick_slice_from_reclaim_list() {
-		if (reclaimed_slices.empty())
-			return nullptr;
-		auto t = reclaimed_slices.front();
-		reclaimed_slices.pop_front();
-
-		return t;
-	}
-
-	unsigned get_nr_slices() {
-		return 1U << (cluster_size_bits - slice_size_bits);
-	}
-
-	u64 get_slice_virt_size_bits() {
-		return slice_virt_size_bits;
-	}
-
-	u64 get_slice_size_bits() {
-		return slice_size_bits;
-	}
-
-	unsigned get_slices_size() {
-		return slices.size();
-	}
-
-	unsigned get_evicted_slices_size() {
-		return evicted_slices.size();
-	}
-
-	unsigned get_slice_idx(u64 virt_offset) {
-		u32 nr_slices = 1ULL << (cluster_size_bits - slice_size_bits);
-		const u64 virt_size = ((u64)nr_slices) << slice_virt_size_bits;
-		u64 virt_base = virt_offset & ~(virt_size - 1);
-
-		return (virt_offset - virt_base) >> slice_virt_size_bits;
-	}
-
-	T *find_slice(u64 key, bool use_evicted_cache) {
-		T *t = slices.get(key);
-
-		if (t)
-			return t;
-
-		if (use_evicted_cache) {
-			auto it = evicted_slices.find(key);
-
-			if (it != evicted_slices.end())
-				return it->second;
-		}
-		return nullptr;
-	}
-
-	void remove_slice_from_evicted_list(T *t) {
-		auto it = evicted_slices.find(t->virt_offset());
-
-		if (it != evicted_slices.end())
-			evicted_slices.erase(it);
-	}
-
-	//called in running flush contex
-	bool has_evicted_dirty_slices()
-	{
-		if (evicted_slices.empty())
-			return false;
-
-		for (auto it = evicted_slices.cbegin(); it !=
-				evicted_slices.cend(); ++it) {
-			if (it->second->get_dirty(-1))
-				return true;
-		}
-		return false;
-	}
-
-	slice_cache(u8 slice_bits, u8 cluster_bits, u8 slice_virt_bits,
-			u32 max_size);
-
-	//only called from meta flushing code path
-	T *__find_slice(u64 key, bool use_evicted_cache);
-	T *alloc_slice(Qcow2State& qs, const qcow2_io_ctx_t &ioc,
-		u64 virt_offset, u64 host_offset, u32 parent_idx);
-	void add_slice_to_evicted_list(u64 virt_offset, T *l2);
-	void dump(Qcow2State &qs);
-	int figure_group_for_flush(Qcow2State &qs);
-	bool has_dirty_slice(Qcow2State &qs);
-	void shrink(Qcow2State &qs);
-};
-
-/* todo: remove caches in destructor */
-class Qcow2ClusterMapping {
-private:
-	Qcow2State &state;
-	slice_cache <Qcow2L2Table> cache;
-
-	friend class Qcow2State;
-
-	u32 cluster_bits, l2_entries_order;
-
-	//l1/l2 entry alloc state
-	//
-	//added before allocating one l1/l2 entry, and freed after
-	//the allocation is done
-	//
-	//For l1, the key is (1ULL << 63) | offset & ~((1ULL << (cluster_bits + l2 entries bits)) - 1)
-	//
-	//for l2, the key is offset & ~((1ULL << cluster_bits) - 1)
-	std::unordered_map<u64, u32> entry_alloc;
-	u32 max_alloc_entries;
-
-	u64 l2_slice_virt_size() {
-		return 1ULL << (cluster_bits + L2_TABLE_SLICE_BITS - 3);
-	}
-
-	u64 l2_slice_key(u64 virt_offset) {
-		return ((virt_offset) & ~(l2_slice_virt_size() - 1));
-	}
-
-	u32 __entry_get_alloc_state(u64 key) {
-		auto it = entry_alloc.find(key);
-
-		if (it != entry_alloc.end())
-			return it->second;
-		return -1;
-	}
-
-	bool __entry_is_allocating(u64 key) {
-		u32 state = __entry_get_alloc_state(key);
-
-		return state != -1;
-	}
-
-	void __entry_mark_allocating(u64 key, u32 owner) {
-		auto it = entry_alloc.find(key);
-		u32 sz;
-
-		qcow2_assert(it == entry_alloc.end());
-
-		entry_alloc[key] = owner;
-
-		sz = entry_alloc.size();
-		if (sz > max_alloc_entries)
-			max_alloc_entries = sz;
-	}
-
-	void __entry_mark_allocated(u64 key) {
-		auto it = entry_alloc.find(key);
-
-		qcow2_assert(it != entry_alloc.end());
-
-		entry_alloc.erase(it);
-	}
-
-	u64 l1_entry_alloc_key(u64 offset) {
-		return (offset & ~((1ULL << (cluster_bits +
-					     l2_entries_order)) - 1)) |
-				(1ULL << 63);
-	}
-
-	u64 l2_entry_alloc_key(u64 offset) {
-		u64 key = (offset & ~((1ULL << cluster_bits) - 1));
-
-		qcow2_assert(!(key & (1ULL << 63)));
-		return key;
-	}
-
-	u64 entry_alloc_key(u64 offset, bool l1) {
-		if (l1)
-			return l1_entry_alloc_key(offset);
-		return l2_entry_alloc_key(offset);
-	}
-
-	bool entry_is_allocating(u64 offset, bool l1) {
-		u64 key = entry_alloc_key(offset, l1);
-
-		return __entry_is_allocating(key);
-	}
-
-	u32 entry_get_alloc_owner(u64 offset, bool l1) {
-		u64 key = entry_alloc_key(offset, l1);
-		u32 state = __entry_get_alloc_state(key);
-
-		qcow2_assert(state != -1);
-		return state;
-	}
-
-	void entry_mark_allocating(u64 offset, u32 owner, bool l1) {
-		u64 key = entry_alloc_key(offset, l1);
-
-		__entry_mark_allocating(key, owner);
-	}
-
-	void entry_mark_allocated(u64 offset, bool l1) {
-		u64 key = entry_alloc_key(offset, l1);
-
-		__entry_mark_allocated(key);
-	}
-
-	Qcow2L2Table *create_and_add_l2(const qcow2_io_ctx_t &ioc, u64 offset);
-	Qcow2L2Table *load_l2_slice(const qcow2_io_ctx_t &ioc, u64 offset,
-			u64 l1_entry);
-	int build_mapping(const qcow2_io_ctx_t &ioc,
-		u64 virt_offset, Qcow2L2Table *l2, u32 idx_in_slice,
-		u64 *l2_entry);
-	u64 __map_cluster(const qcow2_io_ctx_t &ioc,
-		Qcow2L2Table *l2, u64 offset, bool create_l2);
-	Qcow2L2Table *create_l2_map(const qcow2_io_ctx_t &ioc, u64 offset,
-			bool create_l2);
-public:
-	// refcount table shouldn't be so big
-	Qcow2ClusterMapping(Qcow2State &qs);
-
-	//the main logic for mapping cluster
-	//create l2 and setup the mapping if 'create_l2' is true & l2 isn't
-	//present for this 'offset'
-	u64 map_cluster(const qcow2_io_ctx_t &ioc, u64 offset, bool create_l2);
-	int figure_group_from_l1_table();
-
-	Qcow2L2Table* __find_slice(u64 key, bool use_dirty=true);
-
-	u64 l1_idx(u64 offset) {
-		return offset >> (cluster_bits + l2_entries_order);
-	}
-
-	u64 l2_idx(u64 offset) {
-		return (offset >> cluster_bits) &
-			((1ULL << l2_entries_order) - 1);
-	}
-
-	bool has_evicted_dirty_slices()
-	{
-		return cache.has_evicted_dirty_slices();
-	}
-
-	void dump_meta();
-};
-
-enum QCOW2_CLUSTER_USE {
-	L2_TABLE = 0,
-	REFCOUNT_BLK = 1,
-	DATA = 2,
-};
-
-/*
- * Think about lifetime issue. Is it possible that one state is removed
- * but it is being used somewhere?
- *
- * So far the simple rule is that the state can only be removed after
- * its state becomes QCOW2_ALLOC_ZEROED.
- *
- * So except for being absolute safety, don't call get_cluster_state()
- * directly.
- */
-class Qcow2ClusterState {
-#define QCOW2_ALLOC_STARTED	0	//cluster allocated in ram
-#define QCOW2_ALLOC_ZEROING	1	//IO for zeroing this cluster is submitted
-#define QCOW2_ALLOC_ZEROED	2	//cluster zeroed
-#define QCOW2_ALLOC_DONE	3	//mapping setup
-private:
-	u8 state;
-	u8 purpose;
-	IOWaiters io_waiters;
-
-public:
-	Qcow2ClusterState() {
-		state = QCOW2_ALLOC_STARTED;
-	}
-
-	Qcow2ClusterState(u8 s, u8 p) {
-		state = s;
-		purpose = p;
-	}
-
-	//called after the cluster is allocated from ram
-	u8 get_state() {
-		return state;
-	}
-
-	void set_state(u8 s) {
-		state = s;
-	}
-
-	u8 get_purpose() {
-		return purpose;
-	}
-
-	void add_waiter(unsigned tag) {
-		io_waiters.add_waiter(tag);
-	}
-
-	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
-		io_waiters.wakeup_all(q, my_tag);
-	}
-};
-
-/* todo: remove caches in destructor */
-class Qcow2ClusterAllocator {
-private:
-	Qcow2State &state;
-	s32 slice_idx;
-	u8  table_entry_virt_size_bits;
-	u64 alloc_cnt;
-	slice_cache <Qcow2RefcountBlock> cache;
-
-	u32 refcount_block_entries();
-	void allocate_refcount_blk(const qcow2_io_ctx_t &ioc, s32 idx);
-
-	friend class Qcow2State;
-
-public:
-	//key is cluster start offset, val is its allocate status
-	std::unordered_map<u64, Qcow2ClusterState *> alloc_state;
-	u32 max_alloc_states;
-	u64 max_physical_size;
-
-	// refcount table shouldn't be so big
-	Qcow2ClusterAllocator(Qcow2State &qs);
-
-	//called after refcount table is loaded
-	void setup();
-	u64 allocate_cluster(const qcow2_io_ctx_t &ioc);
-	u64 refcount_blk_key(const Qcow2RefcountBlock *rb);
-	void dump_meta();
-	int figure_group_from_refcount_table();
-
-	Qcow2RefcountBlock* __find_slice(u64 key);
-
-	bool has_evicted_dirty_slices()
-	{
-		return cache.has_evicted_dirty_slices();
-	}
-
-	/* the following helpers are for implementing soft update */
-
-	//don't refer to one state after one cycle of coroutine wait &
-	//wakeup, and caller has to check if the return value
-	Qcow2ClusterState *get_cluster_state(u64 cluster_offset) {
-		auto it = alloc_state.find(cluster_offset);
-
-		if (it == alloc_state.end())
-			return nullptr;
-
-		return it->second;
-	}
-
-	//the zeroing io may return -EAGAIN, then we need to
-	//reset its state for re-issuing zeroing IO
-	bool alloc_cluster_reset(u64 cluster_offset) {
-		auto it = alloc_state.find(cluster_offset);
-
-		if (it == alloc_state.end())
-			return false;
-
-		//maybe the cluster has been zeroed, so double check
-		if (it->second->get_state() < QCOW2_ALLOC_ZEROED) {
-			it->second->set_state(QCOW2_ALLOC_STARTED);
-			return true;
-		}
-		return false;
-	}
-
-	//called after the cluster is allocated from ram
-	void alloc_cluster_started(const qcow2_io_ctx_t &ioc,
-			u64 cluster_offset, u8 purpose);
-
-	//check if the allocated cluster is zeroed
-	bool alloc_cluster_is_zeroed(u64 cluster_offset) {
-		Qcow2ClusterState * cs = get_cluster_state(cluster_offset);
-
-		return cs == nullptr || cs->get_state() >= QCOW2_ALLOC_ZEROED;
-	}
-
-	//called after IO for zeroing this cluster is started
-	void alloc_cluster_zeroing(const qcow2_io_ctx_t &ioc, u64 cluster_offset);
-
-	//called after the cluster is zeroed
-	void alloc_cluster_zeroed(const struct ublksrv_queue *q,
-			int tag, u64 cluster_offset);
-
-	//called after the cluster is zeroed and associated mapping is updated
-	void alloc_cluster_done(const qcow2_io_ctx_t &ioc, u64 cluster_offset);
-
-	//called after the cluster is zeroed and associated mapping is updated
-	void alloc_cluster_add_waiter(const qcow2_io_ctx_t &ioc,
-			u64 cluster_offset);
-};
-
-class Qcow2Image {
-private:
-	std::string	fpath;
-public:
-	int fd;
-	Qcow2Image(const char *path);
-	~Qcow2Image();
-};
-
-enum qcow2_meta_flush {
-	IDLE,
-	PREP_WRITE_SLICES, //all slices are added to list for flush
-	ZERO_MY_CLUSTER,
-	WAIT,	//valid only for mapping table, wait for refcount table flushing done
-	WRITE_SLICES,
-	WRITE_TOP,
-	DONE,
-};
-
-class MetaFlushingState {
-private:
-	// for flushing slices depended by current parent_idx, and for
-	// handling state of WRITE_SLICE
-	//
-	//any slices depended by current parent_idx are added to this list,
-	//and it is removed after the flushing is done
-	//
-	//once the list becomes empty, the state is switched to
-	//WRITE_TOP.
-	std::vector <Qcow2SliceMeta *> slices_to_flush;
-	std::vector <Qcow2SliceMeta *> slices_in_flight;
-	unsigned state;
-	int parent_blk_idx;
-	int parent_entry_idx;
-	bool mapping;
-
-	void del_meta_from_list(std::vector <Qcow2SliceMeta *> &v,
-		const Qcow2SliceMeta *t);
-
-	void __prep_write_slice(Qcow2State &qs, const struct ublksrv_queue *q);
-
-	void __zero_my_cluster(Qcow2State &qs, const struct ublksrv_queue *q);
-	co_io_job __zero_my_cluster_co(Qcow2State &qs,
-		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag,
-		Qcow2SliceMeta *m);
-
-	void __write_slices(Qcow2State &qs, const struct ublksrv_queue *q);
-	co_io_job __write_slice_co(Qcow2State &qs,
-		const struct ublksrv_queue *q, Qcow2SliceMeta *m,
-		struct ublk_io_tgt *io, int tag);
-
-	void __write_top(Qcow2State &qs, const struct ublksrv_queue *q);
-	co_io_job  __write_top_co(Qcow2State &qs, const struct ublksrv_queue *q,
-			struct ublk_io_tgt *io, int tag);
-
-	void __done(Qcow2State &qs, const struct ublksrv_queue *q);
-	bool __need_flush(int queued);
-	void mark_no_update();
-public:
-	Qcow2TopTable &top;
-	unsigned slice_dirtied;
-	std::chrono::system_clock::time_point last_flush;
-
-	unsigned get_state() const {
-		return state;
-	}
-	void set_state(u32 s) {
-		ublk_dbg(UBLK_DBG_QCOW2_FLUSH, "%s: map %d slice_dirtied %u parent_blk_idx %d"
-				" parent_entry_idx %d %d->%d to_flush %zd in_flight %zd\n",
-				__func__, mapping, slice_dirtied,
-				parent_blk_idx, parent_entry_idx, state,
-				s, slices_to_flush.size(),
-				slices_in_flight.size());
-		state = s;
-	}
-
-	MetaFlushingState(Qcow2TopTable &t, bool is_mapping);
-	void slice_is_done(const Qcow2SliceMeta*);
-	void add_slice_to_flush(Qcow2SliceMeta *m);
-	void run_flush(Qcow2State &qs, const struct ublksrv_queue *q,
-			int top_blk_idx);
-	bool need_flush(Qcow2State &qs, int *top_idx, unsigned queued);
-	void dump(const char *func, int line) const;
-	int calc_refcount_dirty_blk_range(Qcow2State& qs,
-			int *refcnt_blk_start, int *refcnt_blk_end);
-};
-
-/*
- * For any kind of meta flushing, one tag or io slot is required,
- * so start the meta flushing class with meta tag allocator.
- *
- * Meta data updating is never forground task, so if running out
- * of tags, let's wait until one tag is released.
- */
-class Qcow2MetaFlushing {
-private:
-	std::vector <bool> tags;
-
-	int refcnt_blk_start;
-	int refcnt_blk_end;
-
-	bool handle_mapping_dependency_start_end(Qcow2State *qs,
-			const struct ublksrv_queue *q);
-	void handle_mapping_dependency(Qcow2State *qs,
-			const struct ublksrv_queue *q);
-public:
-	Qcow2State &state;
-
-	MetaFlushingState mapping_stat;
-	MetaFlushingState refcount_stat;
-
-	void inc_dirtied_slice(bool mapping) {
-		if (mapping)
-			mapping_stat.slice_dirtied += 1;
-		else
-			refcount_stat.slice_dirtied += 1;
-	}
-
-	void dec_dirtied_slice(bool mapping) {
-		if (mapping)
-			mapping_stat.slice_dirtied -= 1;
-		else
-			refcount_stat.slice_dirtied -= 1;
-	}
-
-	Qcow2MetaFlushing(Qcow2State &qs);
-	void dump();
-	int alloc_tag(const struct ublksrv_queue *q);
-	void free_tag(const struct ublksrv_queue *q, int tag);
-	void run_flush(const struct ublksrv_queue *q, int queued);
-	bool is_flushing();
-};
-
-class Qcow2State {
-private:
-	std::vector <Qcow2SliceMeta *> freed_slices;
-public:
-	const struct ublksrv_ctrl_dev_info *dev_info;
-	unsigned min_bs_bits;
-	struct meta_mapping {
-		int nr;
-		std::vector <Qcow2MappingMeta *> meta;
-	};
-	typedef std::valarray<struct meta_mapping> MetaArray;
-
-	const struct ublksrv_dev *dev;
-	Qcow2Image img;
-	Qcow2Header header;
-
-	/* must be declared after header */
-	Qcow2L1Table l1_table;
-
-	/* must be declared after header */
-	Qcow2RefcountTable refcount_table;
-
-	Qcow2ClusterAllocator cluster_allocator;
-	Qcow2ClusterMapping cluster_map;
-
-	// map meta io object with one per-queue unique ID, which is set
-	// in sqe->user_data, so we can retrieve the meta io object by
-	// cqe->user_data after the io is done.
-	MetaArray meta_io_map;
-
-	Qcow2MetaFlushing meta_flushing;
-
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	std::unordered_map<u64, u64> cluster_use;
-	std::unordered_map<u64, u64> cluster_validate_map;
-#endif
-
-	Qcow2State(const char *img_path, const struct ublksrv_dev *dev);
-	virtual ~Qcow2State();
-
-	virtual	u32 get_l1_table_max_size();
-	virtual	u64 get_l1_table_offset();
-
-	virtual	u32 get_refcount_table_max_size();
-	virtual	u32 get_refcount_table_act_size();
-	virtual	u64 get_refcount_table_offset();
-
-	Qcow2MappingMeta *get_meta_io(u32 qid, u32 pos) {
-		return meta_io_map[qid].meta[pos];
-	}
-
-	void del_meta_io(u32 qid, u32 pos) {
-		meta_io_map[qid].meta[pos] = nullptr;
-		meta_io_map[qid].nr--;
-
-		if (!meta_io_map[qid].nr)
-			meta_io_map[qid].meta.clear();
-	}
-
-	u64 get_dev_size() {
-		return dev->tgt.dev_size;
-	}
-
-	unsigned get_min_flush_unit_bits(){
-		return min_bs_bits;
-	}
-
-	void add_slice_to_free_list(Qcow2SliceMeta *m) {
-		freed_slices.push_back(m);
-	}
-
-	void kill_slices(const struct ublksrv_queue *q);
-	u32 add_meta_io(u32 qid, Qcow2MappingMeta *m);
-	void dump_meta();
-	void reclaim_slice(Qcow2SliceMeta *m);
-	void remove_slice_from_evicted_list(Qcow2SliceMeta *m);
-	bool has_dirty_slice();
-	u32 get_l2_slices_count();
-	void shrink_cache();
-
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	void validate_cluster_use(u64 host_off, u64 virt_off, u32 use);
-	bool validate_cluster_map(u64 host_off, u64 virt_off);
-#else
-	void validate_cluster_use(u64 host_off, u64 virt_off, u32 use) {}
-	bool validate_cluster_map(u64 host_off, u64 virt_off) { return true;}
-#endif
-};
-
-static inline Qcow2State *dev_to_qcow2state(const struct ublksrv_dev *dev)
-{
-	return (Qcow2State *)dev->tgt.tgt_data;
-}
-
-static inline Qcow2State *queue_to_qcow2state(const struct ublksrv_queue *q)
-{
-	return (Qcow2State *)q->private_data;
-}
-
-Qcow2State *make_qcow2state(const char *file, struct ublksrv_dev *dev);
-
-class Qcow2StatePlain : public Qcow2State {
-public:
-	Qcow2StatePlain(const char *img_path, const struct ublksrv_dev *dev):
-		Qcow2State(img_path, dev) {}
-};
-
-class Qcow2StateSnapshot : public Qcow2State {
-public:
-	Qcow2StateSnapshot(const char *img_path, const struct ublksrv_dev *dev):
-		Qcow2State(img_path, dev) {}
-};
-
-class Qcow2StateExternalDataFile : public Qcow2State {
-public:
-	Qcow2StateExternalDataFile(const char *img_path, const struct ublksrv_dev *dev):
-		Qcow2State(img_path, dev) {}
-};
-
-static inline int qcow2_meta_io_done(const struct ublksrv_queue *q,
-		const struct io_uring_cqe *cqe)
-{
-	if (!cqe)
-		return -EAGAIN;
-
-	int op = user_data_to_op(cqe->user_data);
-	int tag = user_data_to_tag(cqe->user_data);
-	u32 tgt_data = user_data_to_tgt_data(cqe->user_data);
-
-	/* plain IO's tgt_data is zero */
-	if (tgt_data == 0) {
-		ublk_err( "%s target data is zero for meta io(tag %d op %u %llx)\n",
-				__func__, tag, op, cqe->user_data);
-		return -EAGAIN;
-	}
-
-	Qcow2State *qs = queue_to_qcow2state(q);
-	/* retrieve meta data from target data part of cqe->user_data */
-	Qcow2MappingMeta *meta = qs->get_meta_io(q->q_id, tgt_data - 1);
-
-	if (cqe->res < 0)
-		ublk_err( "%s: tag %d op %d tgt_data %d meta %p userdata %d\n",
-			__func__, tag, user_data_to_op(cqe->user_data),
-			tgt_data, meta, cqe->res);
-	meta->io_done(*qs, q, cqe);
-
-	return -EAGAIN;
-}
-
-#endif
diff --git a/qcow2/qcow2_common.h b/qcow2/qcow2_common.h
deleted file mode 100644
index ed74c22..0000000
--- a/qcow2/qcow2_common.h
+++ /dev/null
@@ -1,170 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#ifndef UBLK_QCOW2_COMMON_H_
-#define UBLK_QCOW2_COMMON_H_
-
-#include "ublksrv_tgt.h"
-
-#define qcow2_assert(x)  ublk_assert(x)
-
-#ifdef DEBUG
-#define QCOW2_DEBUG  DEBUG
-#else
-#undef QCOW2_DEBUG
-#endif
-
-#define UBLK_DBG_QCOW2_FLUSH   (1U << 16)
-#define UBLK_DBG_QCOW2_META_L2  (1U << 17)
-#define UBLK_DBG_QCOW2_META_L1  (1U << 18)
-#define UBLK_DBG_QCOW2_META_RB  (1U << 19)
-#define UBLK_DBG_QCOW2_IO_WAITER  (1U << 20)
-#define UBLK_DBG_QCOW2_ALLOCATOR  (1U << 21)
-
-#define UBLK_DBG_QCOW2_META (UBLK_DBG_QCOW2_META_L2 | UBLK_DBG_QCOW2_META_RB)
-
-enum QCOW2_PARA {
-#ifdef DEBUG_QCOW2_META_STRESS
-	REFCOUNT_BLK_MAX_CACHE_BYTES = 8U << 10,
-#else
-	REFCOUNT_BLK_MAX_CACHE_BYTES = 256U << 10,
-#endif
-	REFCOUNT_BLK_SLICE_BITS = 12,
-	REFCOUNT_BLK_SLICE_BYTES = 1U << REFCOUNT_BLK_SLICE_BITS,
-
-#ifdef DEBUG_QCOW2_META_STRESS
-	L2_TABLE_MAX_CACHE_BYTES = 1U << 13,
-#else
-	L2_TABLE_MAX_CACHE_BYTES = 1U << 20,
-#endif
-	L2_TABLE_SLICE_BITS = 12,
-	L2_TABLE_SLICE_BYTES = 1U << L2_TABLE_SLICE_BITS,
-
-#ifdef DEBUG_QCOW2_META_STRESS
-	META_MAX_TAGS = 1,
-#else
-	META_MAX_TAGS = 16,
-#endif
-	//at most 500ms delay if not any slice is running of
-	//lru cache, otherwise the flush is started immediately
-	MAX_META_FLUSH_DELAY_MS = 500,
-};
-
-#define qcow2_log ublk_log
-
-//be careful
-//#DEBUG_QCOW2_META_OBJ, still required for some meta debug
-
-#ifdef QCOW2_DEBUG
-static inline void alloc_log(const char *fmt, ...)
-{
-    va_list ap;
-
-    va_start(ap, fmt);
-    ublk_dbg(UBLK_DBG_QCOW2_ALLOCATOR, fmt, ap);
-}
-
-static inline void flush_log(const char *fmt, ...)
-{
-    va_list ap;
-
-    va_start(ap, fmt);
-    ublk_dbg(UBLK_DBG_QCOW2_FLUSH, fmt, ap);
-}
-
-static inline void qcow2_io_log(const char *fmt, ...)
-{
-    va_list ap;
-
-    va_start(ap, fmt);
-    ublk_dbg(UBLK_DBG_IO, fmt, ap);
-}
-
-#else
-#define alloc_log(...)  do {}while(0)
-#define flush_log(...)  do {}while(0)
-#define qcow2_io_log(...)  do {}while(0)
-#endif
-
-/*
- * 00 ~ 11: tag
- * 12 ~ 23: qid
- * 24 ~ 31: type_id, 0 ~ 254: meta, 255: data,
- * 	so which meta data can be looked up via this type_id in each io
- */
-class qcow2_io_ctx_t {
-public:
-	u32 data;
-
-	u32 get_tag() const {
-		return data & 0xfff;
-	}
-
-	u32 get_qid() const {
-		return (data >> 12) & 0xfff;
-	}
-
-	u32 get_type() const {
-		return (data >> 24) & 0xff;
-	}
-
-	void set_type(u8 type) {
-		data &= 0x00ffffff;
-		data |= type << 24;
-	}
-
-	qcow2_io_ctx_t() {
-		data = 255U << 24;
-	}
-	qcow2_io_ctx_t(u32 val) {
-		data = val;
-	}
-	qcow2_io_ctx_t(u32 tag, u32 qid) {
-		data = (qid << 12) | tag;
-	}
-	qcow2_io_ctx_t(u32 tag, u32 qid, u8 type) {
-		data = (type << 24) | (qid << 12) | tag;
-	}
-	qcow2_io_ctx_t operator=(const u32 val) {
-		return qcow2_io_ctx_t(val);
-	}
-};
-
-
-//L1 max size is 32MB which can have 4M entries, so at most 22 bits
-//needed, so define QCOW2_TAG_BITS as 10, so the upper 22 bits can
-//hold entry index.
-#define	QCOW2_TAG_BITS	10
-#define	QCOW2_MAX_QUEUE_DEPTH	(1U<<10)
-
-class IOWaiters {
-private:
-	//io waiters for this meta data, once this meta is updated,
-	//call resume() on each io in io_waiters, so before io ctx
-	//is waiting, it has to be added to io_waiters.
-	//
-	//Support to wait on single entry update, and the entry index
-	//is stored in bit 31~12, tag is stored in bit 11~0. All one
-	//entry index means that waitting on whole meta data.
-	//
-	std::unordered_set<unsigned int> io_waiters;
-
-	void __mapping_meta_add_waiter(unsigned tag, unsigned entry_idx) {
-		unsigned val;
-
-		qcow2_assert(!(tag & ~(QCOW2_MAX_QUEUE_DEPTH - 1)));
-		qcow2_assert(!(entry_idx & ~((1U << (32 - QCOW2_TAG_BITS)) - 1)));
-
-		val = tag | (entry_idx << QCOW2_TAG_BITS);
-		io_waiters.insert(val);
-	}
-	void __mapping_meta_wakeup_all(const struct ublksrv_queue *q,
-			unsigned my_tag, unsigned entry_idx, bool all);
-public:
-	IOWaiters();
-	void add_waiter(unsigned tag);
-	void add_waiter_idx(unsigned tag, unsigned entry_idx);
-	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag);
-	void wakeup_all_idx(const struct ublksrv_queue *q,
-			unsigned my_tag, unsigned entry_idx);
-};
-
-#endif
diff --git a/qcow2/qcow2_flush_meta.cpp b/qcow2/qcow2_flush_meta.cpp
deleted file mode 100644
index e027406..0000000
--- a/qcow2/qcow2_flush_meta.cpp
+++ /dev/null
@@ -1,654 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#include "qcow2.h"
-
-MetaFlushingState::MetaFlushingState(Qcow2TopTable &t, bool is_mapping):
-	mapping(is_mapping), top(t)
-{
-	state = qcow2_meta_flush::IDLE;
-	slice_dirtied = 0;
-	parent_blk_idx = -1;
-	last_flush = std::chrono::system_clock::now();
-}
-
-void MetaFlushingState::del_meta_from_list(std::vector <Qcow2SliceMeta *> &v,
-		const Qcow2SliceMeta *t)
-{
-	auto it = find(v.cbegin(), v.cend(), t);
-
-	qcow2_assert(it != v.cend());
-	v.erase(it);
-}
-
-void MetaFlushingState::slice_is_done(const Qcow2SliceMeta *t)
-{
-	del_meta_from_list(slices_in_flight, t);
-
-	qcow2_assert(state == WRITE_SLICES);
-
-	if (slices_in_flight.empty() && slices_to_flush.empty()) {
-		if (++parent_entry_idx >= (512/8))
-			set_state(qcow2_meta_flush::WRITE_TOP);
-		else
-			//handle next entry in this block of top table
-			set_state(qcow2_meta_flush::PREP_WRITE_SLICES);
-	}
-}
-
-void MetaFlushingState::add_slice_to_flush(Qcow2SliceMeta *m)
-{
-	qcow2_assert(state == PREP_WRITE_SLICES);
-	qcow2_assert(m->get_dirty(-1));
-
-	auto it = find(slices_to_flush.cbegin(), slices_to_flush.cend(), m);
-	qcow2_assert(it == slices_to_flush.cend());
-
-	auto it1 = find(slices_in_flight.cbegin(), slices_in_flight.cend(), m);
-	qcow2_assert(it1 == slices_in_flight.cend());
-
-	slices_to_flush.push_back(m);
-}
-
-co_io_job MetaFlushingState::__write_slice_co(Qcow2State &qs,
-		const struct ublksrv_queue *q, Qcow2SliceMeta *m,
-		struct ublk_io_tgt *io, int tag)
-{
-	int ret;
-	qcow2_io_ctx_t ioc(tag, q->q_id);
-	bool wait;
-
-	slices_in_flight.push_back(m);
-again:
-	try {
-		ret = m->flush(qs, ioc, m->get_offset(), m->get_buf_size());
-		wait = false;
-	} catch (MetaUpdateException &meta_update_error) {
-		wait = true;
-	}
-
-	if (wait) {
-		co_await__suspend_always(tag);
-		goto again;
-	}
-
-	if (ret < 0) {
-		ublk_err( "%s: zero my cluster failed %d\n",
-				__func__, ret);
-		goto exit;
-	}
-
-	if (ret > 0) {
-		const struct io_uring_cqe *cqe;
-		bool done = false;
-		int io_ret = 0;
-
-		co_await__suspend_always(tag);
-
-		cqe = io->tgt_io_cqe;
-		done = (cqe && cqe->res != -EAGAIN);
-		if (done)
-			io_ret = cqe->res;
-		ret = qcow2_meta_io_done(q, cqe);
-		if (!done && ret == -EAGAIN)
-			goto again;
-
-		//here we can't retry since the slice may be
-		//dirtied just after io_done()
-		if (!done) {
-			if (ret < 0)
-				goto exit;
-		} else {
-			if (io_ret < 0)
-				goto exit;
-			ret = io_ret;
-		}
-	}
-exit:
-	if (m->get_prep_flush()) {
-		m->set_prep_flush(false);
-		m->wakeup_all(q, tag);
-	}
-	qs.meta_flushing.free_tag(q, tag);
-	if (ret >= 0)
-		slice_is_done(m);
-	else
-		del_meta_from_list(slices_in_flight, m);
-	m->put_ref();
-}
-
-void MetaFlushingState::__write_slices(Qcow2State &qs,
-		const struct ublksrv_queue *q)
-{
-	std::vector<Qcow2SliceMeta *> &v1 = slices_to_flush;
-	std::vector<Qcow2SliceMeta *>::const_iterator it = v1.cbegin();
-
-	flush_log("%s: mapping %d to_flush %d, in_flight %d\n",
-			__func__, mapping, v1.size(), slices_in_flight.size());
-
-	if (v1.empty())
-		return;
-
-	while (it != v1.cend()) {
-		int tag;
-		struct ublk_io_tgt *io;
-		Qcow2SliceMeta *m;
-
-		tag = qs.meta_flushing.alloc_tag(q);
-		if (tag == -1)
-			return;
-		m = *it;
-		it = v1.erase(it);
-		m->get_ref();
-		io = ublk_get_io_tgt_data(q, tag);
-		io->co = __write_slice_co(qs, q, m, io, tag);
-	}
-}
-
-//todo: run fsync before flushing top table, and global fsync should be
-//fine, given top table seldom becomes dirty
-co_io_job MetaFlushingState::__write_top_co(Qcow2State &qs,
-		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag)
-{
-	int ret;
-	qcow2_io_ctx_t ioc(tag, q->q_id);
-	bool wait;
-
-again:
-	try {
-		ret = top.flush(qs, ioc,
-				top.get_offset() + parent_blk_idx * 512, 512);
-		wait = false;
-	} catch (MetaUpdateException &meta_update_error) {
-		wait = true;
-	}
-
-	if (wait) {
-		co_await__suspend_always(tag);
-		goto again;
-	}
-
-	if (ret < 0) {
-		ublk_err( "%s: zero my cluster failed %d\n",
-				__func__, ret);
-		goto exit;
-	}
-
-	if (ret > 0) {
-		const struct io_uring_cqe *cqe;
-
-		co_await__suspend_always(tag);
-
-		cqe = io->tgt_io_cqe;
-		ret = qcow2_meta_io_done(q, cqe);
-		if (ret == -EAGAIN)
-			goto again;
-		if (ret < 0)
-			goto exit;
-	}
-exit:
-	qs.meta_flushing.free_tag(q, tag);
-
-	if (!top.get_blk_dirty(parent_blk_idx))
-		set_state(qcow2_meta_flush::DONE);
-}
-
-void MetaFlushingState::__write_top(Qcow2State &qs,
-		const struct ublksrv_queue *q)
-{
-	int tag;
-	struct ublk_io_tgt *io;
-
-	if (top.is_flushing(parent_blk_idx))
-		return;
-
-	tag = qs.meta_flushing.alloc_tag(q);
-	if (tag == -1)
-		return;
-
-	io = ublk_get_io_tgt_data(q, tag);
-	io->co = __write_top_co(qs, q, io, tag);
-}
-
-void MetaFlushingState::__done(Qcow2State &qs, const struct ublksrv_queue *q)
-{
-	set_state(qcow2_meta_flush::IDLE);
-	last_flush = std::chrono::system_clock::now();
-}
-
-void MetaFlushingState::mark_no_update()
-{
-	auto it = slices_to_flush.begin();
-
-	for (; it != slices_to_flush.end(); it++)
-		(*it)->set_prep_flush(true);
-}
-
-void MetaFlushingState::__prep_write_slice(Qcow2State &qs,
-		const struct ublksrv_queue *q)
-{
-	u64 entry;
-	u64 idx = -1;
-	u64 start, end, offset, step;
-
-	do {
-		qcow2_assert(parent_entry_idx >= 0 && parent_entry_idx < (512/8));
-
-		idx = (parent_blk_idx * 512 / 8) + parent_entry_idx;
-
-		qcow2_assert(idx >= 0 && idx < top.get_nr_entries());
-
-		entry = top.get_entry(idx);
-		if (entry && top.has_dirty_slices(qs, idx))
-			break;
-
-		if (++parent_entry_idx == (512/8)) {
-			parent_entry_idx = 0;
-			set_state(qcow2_meta_flush::WRITE_TOP);
-			return;
-		}
-	} while (true);
-
-	if (mapping)
-		step = 1ULL << (QCOW2_PARA::L2_TABLE_SLICE_BITS - 3 +
-				qs.header.cluster_bits);
-	else
-		step = 1ULL << (QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS - 3 +
-				qs.header.cluster_bits);
-
-	start = idx << top.single_entry_order();
-	end = start + (1ULL << top.single_entry_order());
-	for (offset = start; offset < end; offset += step) {
-		Qcow2SliceMeta *t;
-
-		if (mapping)
-			t = qs.cluster_map.__find_slice(offset);
-		else
-			t = qs.cluster_allocator.__find_slice(offset);
-
-		if (t && t->get_dirty(-1)) {
-			qcow2_assert(!t->is_flushing());
-			add_slice_to_flush(t);
-		}
-	}
-
-	if (slices_to_flush.size() > 0)
-		set_state(qcow2_meta_flush::ZERO_MY_CLUSTER);
-	else
-		set_state(qcow2_meta_flush::WRITE_TOP);
-}
-
-co_io_job MetaFlushingState::__zero_my_cluster_co(Qcow2State &qs,
-		const struct ublksrv_queue *q, struct ublk_io_tgt *io, int tag,
-		Qcow2SliceMeta *m)
-
-{
-	int ret;
-	qcow2_io_ctx_t ioc(tag, q->q_id);
-	u64 cluster_off = m->get_offset() &
-		~((1ULL << qs.header.cluster_bits) - 1);
-	bool wait;
-
-again:
-	try {
-		ret = m->zero_my_cluster(qs, ioc);
-		wait = false;
-	} catch (MetaUpdateException &meta_update_error) {
-		wait = true;
-	}
-
-	if (wait) {
-		co_await__suspend_always(tag);
-		goto again;
-	}
-
-	if (ret < 0) {
-		ublk_err( "%s: zero my cluster failed %d\n",
-				__func__, ret);
-		goto exit;
-	}
-
-	if (ret > 0) {
-		const struct io_uring_cqe *cqe;
-
-		co_await__suspend_always(tag);
-
-		cqe = io->tgt_io_cqe;
-		ret = qcow2_meta_io_done(q, cqe);
-		if (ret == -EAGAIN)
-			goto again;
-		if (ret < 0)
-			goto exit;
-	}
-exit:
-	qs.meta_flushing.free_tag(q, tag);
-	if (qs.cluster_allocator.alloc_cluster_is_zeroed(cluster_off)) {
-		//for mapping table, wait until the associated refcount
-		//tables are flushed out
-		if (mapping) {
-			mark_no_update();
-			set_state(qcow2_meta_flush::WAIT);
-		} else
-			set_state(qcow2_meta_flush::WRITE_SLICES);
-	}
-	m->put_ref();
-}
-
-
-void MetaFlushingState::__zero_my_cluster(Qcow2State &qs,
-		const struct ublksrv_queue *q)
-{
-	int tag;
-	struct ublk_io_tgt *io;
-	Qcow2SliceMeta *m = slices_to_flush[0];
-	u64 cluster_off = m->get_offset() &
-		~((1ULL << qs.header.cluster_bits) - 1);
-	Qcow2ClusterState *s =
-		qs.cluster_allocator.get_cluster_state(cluster_off);
-
-	if (s != nullptr && s->get_state() == QCOW2_ALLOC_ZEROING)
-		return;
-
-	tag = qs.meta_flushing.alloc_tag(q);
-	if (tag == -1)
-		return;
-
-	m->get_ref();
-	io = ublk_get_io_tgt_data(q, tag);
-	io->co = __zero_my_cluster_co(qs, q, io, tag, m);
-}
-
-void MetaFlushingState::run_flush(Qcow2State &qs,
-		const struct ublksrv_queue *q, int top_blk_idx)
-{
-	if (state == qcow2_meta_flush::IDLE) {
-		if (top_blk_idx >= 0 && top_blk_idx < top.dirty_blk_size()) {
-			parent_blk_idx = top_blk_idx;
-			parent_entry_idx = 0;
-			set_state(qcow2_meta_flush::PREP_WRITE_SLICES);
-		}
-	}
-again:
-	if (state == qcow2_meta_flush::PREP_WRITE_SLICES)
-		__prep_write_slice(qs, q);
-
-	if (state == qcow2_meta_flush::ZERO_MY_CLUSTER)
-		__zero_my_cluster(qs, q);
-
-	if (state == qcow2_meta_flush::WAIT) {
-		qcow2_assert(mapping);
-		return;
-	}
-
-	if (state == qcow2_meta_flush::WRITE_SLICES)
-		__write_slices(qs, q);
-
-	if (state == qcow2_meta_flush::WRITE_TOP)
-		__write_top(qs, q);
-
-	if (state == qcow2_meta_flush::DONE)
-		__done(qs, q);
-
-	if (state == qcow2_meta_flush::PREP_WRITE_SLICES)
-		goto again;
-}
-
-void MetaFlushingState::dump(const char *func, int line) const {
-	qcow2_log("%s %d: mapping %d state %d blk_idx %d entry_idx %d list size(%ld %ld)"
-			" dirty slices %u, top table dirty blocks %u\n",
-			func, line, mapping, state,
-			parent_blk_idx, parent_entry_idx,
-			slices_to_flush.size(),
-			slices_in_flight.size(),
-			slice_dirtied, top.dirty_blks());
-}
-
-bool MetaFlushingState::__need_flush(int queued)
-{
-	bool need_flush = slice_dirtied > 0;
-
-	if (!need_flush)
-		need_flush = top.dirty_blks() > 0;
-
-	if (!need_flush)
-		return false;
-
-	if (queued) {
-		auto diff = std::chrono::system_clock::now() - last_flush;
-		std::chrono::milliseconds ms = std::chrono::duration_cast<
-			std::chrono::milliseconds>(diff);
-
-		//timeout, so flush now
-		if (ms.count() > MAX_META_FLUSH_DELAY_MS)
-			return true;
-		else
-			return false;
-	}
-
-	/* queue is idle, so have to flush immediately */
-	return true;
-}
-
-bool MetaFlushingState::need_flush(Qcow2State &qs, int *top_idx,
-		unsigned queued)
-{
-	bool need_flush = get_state() > qcow2_meta_flush::IDLE;
-	int idx = -1;
-
-	if (!need_flush) {
-		if (mapping)
-			need_flush = qs.cluster_map.
-				has_evicted_dirty_slices();
-		else
-			need_flush = qs.cluster_allocator.
-				has_evicted_dirty_slices();
-
-		//only flush refcount tables actively if there
-		//are evicted dirty refcount slices
-		if (!need_flush)
-			need_flush = __need_flush(queued);
-	}
-
-	if (need_flush && get_state() == qcow2_meta_flush::IDLE) {
-		if (mapping)
-			idx = qs.cluster_map.figure_group_from_l1_table();
-		else
-			idx = qs.cluster_allocator.figure_group_from_refcount_table();
-
-		//idx is more accurate than slice_dirtied
-		//FIXME: make slice_dirtied more accurate
-		if (idx == -1) {
-			need_flush = false;
-			slice_dirtied = 0;
-		}
-	}
-
-	*top_idx = idx;
-	return need_flush;
-}
-
-//calculate the 1st index of refcount table, in which the to-be-flushed
-//l2's entries depend on
-int MetaFlushingState::calc_refcount_dirty_blk_range(Qcow2State& qs,
-			int *refcnt_blk_start, int *refcnt_blk_end)
-{
-	u64 s = (u64)-1;
-	u64 e = 0;
-	u64 l2_offset = 0;
-	int start_idx, end_idx;
-
-	qcow2_assert(mapping);
-
-	for (auto it = slices_to_flush.begin(); it != slices_to_flush.end();
-			it++) {
-		u64 ts, te;
-
-		qcow2_assert((*it)->get_dirty(-1));
-
-		(*it)->get_dirty_range(&ts, &te);
-
-		if (!l2_offset)
-			l2_offset = (*it)->get_offset() & ~((1ULL <<
-					qs.header.cluster_bits) - 1);
-
-		if (ts > te)
-			continue;
-		if (ts < s)
-			s = ts;
-		if (te > e)
-			e = te;
-	}
-
-	if (s > e)
-		return -EINVAL;
-
-	//this l2 should be considered too
-	if (l2_offset && l2_offset < s)
-		s = l2_offset;
-
-	start_idx = qs.refcount_table.offset_to_idx(s);
-	*refcnt_blk_start = start_idx >> (qs.get_min_flush_unit_bits() - 3);
-
-	end_idx = qs.refcount_table.offset_to_idx(e);
-	*refcnt_blk_end = end_idx >> (qs.get_min_flush_unit_bits() - 3);
-	*refcnt_blk_end += 1;
-
-	flush_log("%s: %lx-%lx idx (%d %d) blk idx(%d %d)\n", __func__, s, e,
-			start_idx, end_idx, *refcnt_blk_start, *refcnt_blk_end);
-
-	if (*refcnt_blk_start == *refcnt_blk_end)
-		*refcnt_blk_end = *refcnt_blk_start + 1;
-
-	if (*refcnt_blk_start >= *refcnt_blk_end)
-		qcow2_log("%s: %lx-%lx bad idx %d %d\n", __func__, s, e,
-				*refcnt_blk_start, *refcnt_blk_end);
-
-	qcow2_assert(*refcnt_blk_start < *refcnt_blk_end);
-
-	return 0;
-}
-
-Qcow2MetaFlushing::Qcow2MetaFlushing(Qcow2State &qs):
-	tags(QCOW2_PARA::META_MAX_TAGS),
-	refcnt_blk_start(-1),
-	refcnt_blk_end(-1),
-	state(qs),
-	mapping_stat(qs.l1_table, true),
-	refcount_stat(qs.refcount_table, false)
-{
-	for (int i = 0; i < tags.size(); i++)
-		tags[i] = true;
-}
-
-int Qcow2MetaFlushing::alloc_tag(const struct ublksrv_queue *q) {
-	for (size_t i = 0; i < tags.size(); i++) {
-		if (tags[i]) {
-			tags[i] = false;
-			return i + q->q_depth;
-		}
-	}
-	return -1;
-}
-
-void Qcow2MetaFlushing::free_tag(const struct ublksrv_queue *q, int tag) {
-	int depth = q->q_depth;
-
-	qcow2_assert(tag >= depth && tag < depth + tags.size());
-	tags[tag - depth] = true;
-}
-
-void Qcow2MetaFlushing::dump()
-{
-	ublk_err( "meta flushing: mapping: dirty slices %u, l1 dirty blocks %u\n",
-			mapping_stat.slice_dirtied,
-			state.l1_table.dirty_blks());
-	ublk_err( "meta flushing: refcount: dirty slices %u, refcount table dirty blocks %u\n",
-			refcount_stat.slice_dirtied,
-			state.refcount_table.dirty_blks());
-}
-
-bool Qcow2MetaFlushing::handle_mapping_dependency_start_end(Qcow2State *qs,
-		const struct ublksrv_queue *q)
-{
-	if (refcount_stat.get_state() == qcow2_meta_flush::IDLE &&
-			(refcnt_blk_start == refcnt_blk_end)) {
-		int ret;
-
-		//current flushing refcnt is done
-		if (refcnt_blk_start >= 0) {
-			mapping_stat.set_state(
-					qcow2_meta_flush::WRITE_SLICES);
-			refcnt_blk_start = refcnt_blk_end = -1;
-			mapping_stat.run_flush(state, q, -1);
-
-			return true;
-		} else { //current flushing is just started
-			ret = mapping_stat.calc_refcount_dirty_blk_range(
-					*qs, &refcnt_blk_start, &refcnt_blk_end);
-
-			if (ret < 0) {
-				mapping_stat.set_state(
-					qcow2_meta_flush::WRITE_SLICES);
-				mapping_stat.run_flush(state, q, -1);
-				return true;
-			}
-		}
-	}
-
-	return false;
-}
-
-void Qcow2MetaFlushing::handle_mapping_dependency(Qcow2State *qs,
-		const struct ublksrv_queue *q)
-{
-	qcow2_assert(mapping_stat.get_state() == qcow2_meta_flush::WAIT);
-
-	if (!handle_mapping_dependency_start_end(qs, q)) {
-
-		refcount_stat.run_flush(state, q, refcnt_blk_start);
-
-		while (refcount_stat.get_state() == qcow2_meta_flush::IDLE &&
-				(++refcnt_blk_start < refcnt_blk_end))
-			refcount_stat.run_flush(state, q, refcnt_blk_start);
-		handle_mapping_dependency_start_end(qs, q);
-	}
-
-	if (mapping_stat.get_state() != qcow2_meta_flush::WAIT)
-		mapping_stat.run_flush(state, q, -1);
-}
-
-bool Qcow2MetaFlushing::is_flushing()
-{
-	return mapping_stat.get_state() != qcow2_meta_flush::IDLE ||
-			refcount_stat.get_state() != qcow2_meta_flush::IDLE;
-}
-
-void Qcow2MetaFlushing::run_flush(const struct ublksrv_queue *q, int queued)
-{
-	Qcow2State *qs = queue_to_qcow2state(q);
-	bool need_flush;
-	int map_idx = -1;
-	int refcnt_idx = -1;
-
-	need_flush = mapping_stat.need_flush(*qs, &map_idx, queued);
-	need_flush |= refcount_stat.need_flush(*qs, &refcnt_idx, queued);
-
-	if (need_flush)
-		flush_log("%s: enter flush: state %d/%d top blk idx %d/%d queued %d, refcnt blks(%d %d)\n",
-			__func__, mapping_stat.get_state(),
-			refcount_stat.get_state(), map_idx, refcnt_idx,
-			queued, refcnt_blk_start, refcnt_blk_end);
-
-	//refcount tables flushing is always triggered by flushing mapping
-	//tables
-	if (need_flush)
-		mapping_stat.run_flush(state, q, map_idx);
-
-	if (mapping_stat.get_state() == qcow2_meta_flush::WAIT)
-		handle_mapping_dependency(qs, q);
-
-	if (need_flush)
-		flush_log("%s: exit flush: state %d/%d queued %d refcnt blks(%d %d) has dirty slice %d\n",
-			__func__, mapping_stat.get_state(),
-			refcount_stat.get_state(), queued,
-			refcnt_blk_start, refcnt_blk_end,
-			qs->has_dirty_slice());
-}
diff --git a/qcow2/qcow2_format.h b/qcow2/qcow2_format.h
deleted file mode 100644
index 7be1d65..0000000
--- a/qcow2/qcow2_format.h
+++ /dev/null
@@ -1,378 +0,0 @@
-/*
- * Block driver for the QCOW version 2 format
- *
- * Copyright (c) 2004-2006 Fabrice Bellard
- *
- * Permission is hereby granted, free of charge, to any person obtaining a copy
- * of this software and associated documentation files (the "Software"), to deal
- * in the Software without restriction, including without limitation the rights
- * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
- * copies of the Software, and to permit persons to whom the Software is
- * furnished to do so, subject to the following conditions:
- *
- * The above copyright notice and this permission notice shall be included in
- * all copies or substantial portions of the Software.
- *
- * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
- * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
- * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
- * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
- * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
- * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
- * THE SOFTWARE.
- */
-
-#ifndef BLOCK_QCOW2_H
-#define BLOCK_QCOW2_H
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-#include "qemu_dep.h"
-
-//#define DEBUG_ALLOC
-//#define DEBUG_ALLOC2
-//#define DEBUG_EXT
-
-#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
-
-#define QCOW_CRYPT_NONE 0
-#define QCOW_CRYPT_AES  1
-#define QCOW_CRYPT_LUKS 2
-
-#define QCOW_MAX_CRYPT_CLUSTERS 32
-#define QCOW_MAX_SNAPSHOTS 65536
-
-/* Field widths in qcow2 mean normal cluster offsets cannot reach
- * 64PB; depending on cluster size, compressed clusters can have a
- * smaller limit (64PB for up to 16k clusters, then ramps down to
- * 512TB for 2M clusters).  */
-#define QCOW_MAX_CLUSTER_OFFSET ((1ULL << 56) - 1)
-
-/* 8 MB refcount table is enough for 2 PB images at 64k cluster size
- * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
-#define QCOW_MAX_REFTABLE_SIZE (8 * MiB)
-
-/* 32 MB L1 table is enough for 2 PB images at 64k cluster size
- * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
-#define QCOW_MAX_L1_SIZE (32 * MiB)
-
-/* Allow for an average of 1k per snapshot table entry, should be plenty of
- * space for snapshot names and IDs */
-#define QCOW_MAX_SNAPSHOTS_SIZE (1024 * QCOW_MAX_SNAPSHOTS)
-
-/* Maximum amount of extra data per snapshot table entry to accept */
-#define QCOW_MAX_SNAPSHOT_EXTRA_DATA 1024
-
-/* Bitmap header extension constraints */
-#define QCOW2_MAX_BITMAPS 65535
-#define QCOW2_MAX_BITMAP_DIRECTORY_SIZE (1024 * QCOW2_MAX_BITMAPS)
-
-/* indicate that the refcount of the referenced cluster is exactly one. */
-#define QCOW_OFLAG_COPIED     (1ULL << 63)
-/* indicate that the cluster is compressed (they never have the copied flag) */
-#define QCOW_OFLAG_COMPRESSED (1ULL << 62)
-/* The cluster reads as all zeros */
-#define QCOW_OFLAG_ZERO (1ULL << 0)
-
-#define QCOW_EXTL2_SUBCLUSTERS_PER_CLUSTER 32
-
-/* The subcluster X [0..31] is allocated */
-#define QCOW_OFLAG_SUB_ALLOC(X)   (1ULL << (X))
-/* The subcluster X [0..31] reads as zeroes */
-#define QCOW_OFLAG_SUB_ZERO(X)    (QCOW_OFLAG_SUB_ALLOC(X) << 32)
-/* Subclusters [X, Y) (0 <= X <= Y <= 32) are allocated */
-#define QCOW_OFLAG_SUB_ALLOC_RANGE(X, Y) \
-    (QCOW_OFLAG_SUB_ALLOC(Y) - QCOW_OFLAG_SUB_ALLOC(X))
-/* Subclusters [X, Y) (0 <= X <= Y <= 32) read as zeroes */
-#define QCOW_OFLAG_SUB_ZERO_RANGE(X, Y) \
-    (QCOW_OFLAG_SUB_ALLOC_RANGE(X, Y) << 32)
-/* L2 entry bitmap with all allocation bits set */
-#define QCOW_L2_BITMAP_ALL_ALLOC  (QCOW_OFLAG_SUB_ALLOC_RANGE(0, 32))
-/* L2 entry bitmap with all "read as zeroes" bits set */
-#define QCOW_L2_BITMAP_ALL_ZEROES (QCOW_OFLAG_SUB_ZERO_RANGE(0, 32))
-
-/* Size of normal and extended L2 entries */
-#define L2E_SIZE_NORMAL   (sizeof(uint64_t))
-#define L2E_SIZE_EXTENDED (sizeof(uint64_t) * 2)
-
-/* Size of L1 table entries */
-#define L1E_SIZE (sizeof(uint64_t))
-
-/* Size of reftable entries */
-#define REFTABLE_ENTRY_SIZE (sizeof(uint64_t))
-
-#define MIN_CLUSTER_BITS 9
-#define MAX_CLUSTER_BITS 21
-
-/* Defined in the qcow2 spec (compressed cluster descriptor) */
-#define QCOW2_COMPRESSED_SECTOR_SIZE 512U
-
-/* Must be at least 2 to cover COW */
-#define MIN_L2_CACHE_SIZE 2 /* cache entries */
-
-/* Must be at least 4 to cover all cases of refcount table growth */
-#define MIN_REFCOUNT_CACHE_SIZE 4 /* clusters */
-
-#define DEFAULT_L2_CACHE_MAX_SIZE (32 * MiB)
-#define DEFAULT_CACHE_CLEAN_INTERVAL 600  /* seconds */
-
-#define DEFAULT_CLUSTER_SIZE 65536
-
-#define QCOW2_OPT_DATA_FILE "data-file"
-#define QCOW2_OPT_LAZY_REFCOUNTS "lazy-refcounts"
-#define QCOW2_OPT_DISCARD_REQUEST "pass-discard-request"
-#define QCOW2_OPT_DISCARD_SNAPSHOT "pass-discard-snapshot"
-#define QCOW2_OPT_DISCARD_OTHER "pass-discard-other"
-#define QCOW2_OPT_OVERLAP "overlap-check"
-#define QCOW2_OPT_OVERLAP_TEMPLATE "overlap-check.template"
-#define QCOW2_OPT_OVERLAP_MAIN_HEADER "overlap-check.main-header"
-#define QCOW2_OPT_OVERLAP_ACTIVE_L1 "overlap-check.active-l1"
-#define QCOW2_OPT_OVERLAP_ACTIVE_L2 "overlap-check.active-l2"
-#define QCOW2_OPT_OVERLAP_REFCOUNT_TABLE "overlap-check.refcount-table"
-#define QCOW2_OPT_OVERLAP_REFCOUNT_BLOCK "overlap-check.refcount-block"
-#define QCOW2_OPT_OVERLAP_SNAPSHOT_TABLE "overlap-check.snapshot-table"
-#define QCOW2_OPT_OVERLAP_INACTIVE_L1 "overlap-check.inactive-l1"
-#define QCOW2_OPT_OVERLAP_INACTIVE_L2 "overlap-check.inactive-l2"
-#define QCOW2_OPT_OVERLAP_BITMAP_DIRECTORY "overlap-check.bitmap-directory"
-#define QCOW2_OPT_CACHE_SIZE "cache-size"
-#define QCOW2_OPT_L2_CACHE_SIZE "l2-cache-size"
-#define QCOW2_OPT_L2_CACHE_ENTRY_SIZE "l2-cache-entry-size"
-#define QCOW2_OPT_REFCOUNT_CACHE_SIZE "refcount-cache-size"
-#define QCOW2_OPT_CACHE_CLEAN_INTERVAL "cache-clean-interval"
-
-typedef struct QCowHeader {
-    uint32_t magic;
-    uint32_t version;
-    uint64_t backing_file_offset;
-    uint32_t backing_file_size;
-    uint32_t cluster_bits;
-    uint64_t size; /* in bytes */
-    uint32_t crypt_method;
-    uint32_t l1_size; /* XXX: save number of clusters instead ? */
-    uint64_t l1_table_offset;
-    uint64_t refcount_table_offset;
-    uint32_t refcount_table_clusters;
-    uint32_t nb_snapshots;
-    uint64_t snapshots_offset;
-
-    /* The following fields are only valid for version >= 3 */
-    uint64_t incompatible_features;
-    uint64_t compatible_features;
-    uint64_t autoclear_features;
-
-    uint32_t refcount_order;
-    uint32_t header_length;
-
-    /* Additional fields */
-    uint8_t compression_type;
-
-    /* header must be a multiple of 8 */
-    uint8_t padding[7];
-} QEMU_PACKED QCowHeader;
-
-//QEMU_BUILD_BUG_ON(!QEMU_IS_ALIGNED(sizeof(QCowHeader), 8));
-
-typedef struct QEMU_PACKED QCowSnapshotHeader {
-    /* header is 8 byte aligned */
-    uint64_t l1_table_offset;
-
-    uint32_t l1_size;
-    uint16_t id_str_size;
-    uint16_t name_size;
-
-    uint32_t date_sec;
-    uint32_t date_nsec;
-
-    uint64_t vm_clock_nsec;
-
-    uint32_t vm_state_size;
-    uint32_t extra_data_size; /* for extension */
-    /* extra data follows */
-    /* id_str follows */
-    /* name follows  */
-} QCowSnapshotHeader;
-
-typedef struct QEMU_PACKED QCowSnapshotExtraData {
-    uint64_t vm_state_size_large;
-    uint64_t disk_size;
-    uint64_t icount;
-} QCowSnapshotExtraData;
-
-
-typedef struct Qcow2CryptoHeaderExtension {
-    uint64_t offset;
-    uint64_t length;
-} QEMU_PACKED Qcow2CryptoHeaderExtension;
-
-enum {
-    QCOW2_FEAT_TYPE_INCOMPATIBLE    = 0,
-    QCOW2_FEAT_TYPE_COMPATIBLE      = 1,
-    QCOW2_FEAT_TYPE_AUTOCLEAR       = 2,
-};
-
-/* Incompatible feature bits */
-enum {
-    QCOW2_INCOMPAT_DIRTY_BITNR      = 0,
-    QCOW2_INCOMPAT_CORRUPT_BITNR    = 1,
-    QCOW2_INCOMPAT_DATA_FILE_BITNR  = 2,
-    QCOW2_INCOMPAT_COMPRESSION_BITNR = 3,
-    QCOW2_INCOMPAT_EXTL2_BITNR      = 4,
-    QCOW2_INCOMPAT_DIRTY            = 1 << QCOW2_INCOMPAT_DIRTY_BITNR,
-    QCOW2_INCOMPAT_CORRUPT          = 1 << QCOW2_INCOMPAT_CORRUPT_BITNR,
-    QCOW2_INCOMPAT_DATA_FILE        = 1 << QCOW2_INCOMPAT_DATA_FILE_BITNR,
-    QCOW2_INCOMPAT_COMPRESSION      = 1 << QCOW2_INCOMPAT_COMPRESSION_BITNR,
-    QCOW2_INCOMPAT_EXTL2            = 1 << QCOW2_INCOMPAT_EXTL2_BITNR,
-
-    QCOW2_INCOMPAT_MASK             = QCOW2_INCOMPAT_DIRTY
-                                    | QCOW2_INCOMPAT_CORRUPT
-                                    | QCOW2_INCOMPAT_DATA_FILE
-                                    | QCOW2_INCOMPAT_COMPRESSION
-                                    | QCOW2_INCOMPAT_EXTL2,
-};
-
-/* Compatible feature bits */
-enum {
-    QCOW2_COMPAT_LAZY_REFCOUNTS_BITNR = 0,
-    QCOW2_COMPAT_LAZY_REFCOUNTS       = 1 << QCOW2_COMPAT_LAZY_REFCOUNTS_BITNR,
-
-    QCOW2_COMPAT_FEAT_MASK            = QCOW2_COMPAT_LAZY_REFCOUNTS,
-};
-
-/* Autoclear feature bits */
-enum {
-    QCOW2_AUTOCLEAR_BITMAPS_BITNR       = 0,
-    QCOW2_AUTOCLEAR_DATA_FILE_RAW_BITNR = 1,
-    QCOW2_AUTOCLEAR_BITMAPS             = 1 << QCOW2_AUTOCLEAR_BITMAPS_BITNR,
-    QCOW2_AUTOCLEAR_DATA_FILE_RAW       = 1 << QCOW2_AUTOCLEAR_DATA_FILE_RAW_BITNR,
-
-    QCOW2_AUTOCLEAR_MASK                = QCOW2_AUTOCLEAR_BITMAPS
-                                        | QCOW2_AUTOCLEAR_DATA_FILE_RAW,
-};
-
-enum qcow2_discard_type {
-    QCOW2_DISCARD_NEVER = 0,
-    QCOW2_DISCARD_ALWAYS,
-    QCOW2_DISCARD_REQUEST,
-    QCOW2_DISCARD_SNAPSHOT,
-    QCOW2_DISCARD_OTHER,
-    QCOW2_DISCARD_MAX
-};
-
-typedef struct Qcow2Feature {
-    uint8_t type;
-    uint8_t bit;
-    char    name[46];
-} QEMU_PACKED Qcow2Feature;
-
-
-typedef struct Qcow2BitmapHeaderExt {
-    uint32_t nb_bitmaps;
-    uint32_t reserved32;
-    uint64_t bitmap_directory_size;
-    uint64_t bitmap_directory_offset;
-} QEMU_PACKED Qcow2BitmapHeaderExt;
-
-
-/*
- * In images with standard L2 entries all clusters are treated as if
- * they had one subcluster so QCow2ClusterType and QCow2SubclusterType
- * can be mapped to each other and have the exact same meaning
- * (QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC cannot happen in these images).
- *
- * In images with extended L2 entries QCow2ClusterType refers to the
- * complete cluster and QCow2SubclusterType to each of the individual
- * subclusters, so there are several possible combinations:
- *
- *     |--------------+---------------------------|
- *     | Cluster type | Possible subcluster types |
- *     |--------------+---------------------------|
- *     | UNALLOCATED  |         UNALLOCATED_PLAIN |
- *     |              |                ZERO_PLAIN |
- *     |--------------+---------------------------|
- *     | NORMAL       |         UNALLOCATED_ALLOC |
- *     |              |                ZERO_ALLOC |
- *     |              |                    NORMAL |
- *     |--------------+---------------------------|
- *     | COMPRESSED   |                COMPRESSED |
- *     |--------------+---------------------------|
- *
- * QCOW2_SUBCLUSTER_INVALID means that the L2 entry is incorrect and
- * the image should be marked corrupt.
- */
-
-typedef enum QCow2ClusterType {
-    QCOW2_CLUSTER_UNALLOCATED,
-    QCOW2_CLUSTER_ZERO_PLAIN,
-    QCOW2_CLUSTER_ZERO_ALLOC,
-    QCOW2_CLUSTER_NORMAL,
-    QCOW2_CLUSTER_COMPRESSED,
-} QCow2ClusterType;
-
-typedef enum QCow2SubclusterType {
-    QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN,
-    QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
-    QCOW2_SUBCLUSTER_ZERO_PLAIN,
-    QCOW2_SUBCLUSTER_ZERO_ALLOC,
-    QCOW2_SUBCLUSTER_NORMAL,
-    QCOW2_SUBCLUSTER_COMPRESSED,
-    QCOW2_SUBCLUSTER_INVALID,
-} QCow2SubclusterType;
-
-typedef enum QCow2MetadataOverlap {
-    QCOW2_OL_MAIN_HEADER_BITNR      = 0,
-    QCOW2_OL_ACTIVE_L1_BITNR        = 1,
-    QCOW2_OL_ACTIVE_L2_BITNR        = 2,
-    QCOW2_OL_REFCOUNT_TABLE_BITNR   = 3,
-    QCOW2_OL_REFCOUNT_BLOCK_BITNR   = 4,
-    QCOW2_OL_SNAPSHOT_TABLE_BITNR   = 5,
-    QCOW2_OL_INACTIVE_L1_BITNR      = 6,
-    QCOW2_OL_INACTIVE_L2_BITNR      = 7,
-    QCOW2_OL_BITMAP_DIRECTORY_BITNR = 8,
-
-    QCOW2_OL_MAX_BITNR              = 9,
-
-    QCOW2_OL_NONE             = 0,
-    QCOW2_OL_MAIN_HEADER      = (1 << QCOW2_OL_MAIN_HEADER_BITNR),
-    QCOW2_OL_ACTIVE_L1        = (1 << QCOW2_OL_ACTIVE_L1_BITNR),
-    QCOW2_OL_ACTIVE_L2        = (1 << QCOW2_OL_ACTIVE_L2_BITNR),
-    QCOW2_OL_REFCOUNT_TABLE   = (1 << QCOW2_OL_REFCOUNT_TABLE_BITNR),
-    QCOW2_OL_REFCOUNT_BLOCK   = (1 << QCOW2_OL_REFCOUNT_BLOCK_BITNR),
-    QCOW2_OL_SNAPSHOT_TABLE   = (1 << QCOW2_OL_SNAPSHOT_TABLE_BITNR),
-    QCOW2_OL_INACTIVE_L1      = (1 << QCOW2_OL_INACTIVE_L1_BITNR),
-    /* NOTE: Checking overlaps with inactive L2 tables will result in bdrv
-     * reads. */
-    QCOW2_OL_INACTIVE_L2      = (1 << QCOW2_OL_INACTIVE_L2_BITNR),
-    QCOW2_OL_BITMAP_DIRECTORY = (1 << QCOW2_OL_BITMAP_DIRECTORY_BITNR),
-} QCow2MetadataOverlap;
-
-/* Perform all overlap checks which can be done in constant time */
-#define QCOW2_OL_CONSTANT \
-    (QCOW2_OL_MAIN_HEADER | QCOW2_OL_ACTIVE_L1 | QCOW2_OL_REFCOUNT_TABLE | \
-     QCOW2_OL_SNAPSHOT_TABLE | QCOW2_OL_BITMAP_DIRECTORY)
-
-/* Perform all overlap checks which don't require disk access */
-#define QCOW2_OL_CACHED \
-    (QCOW2_OL_CONSTANT | QCOW2_OL_ACTIVE_L2 | QCOW2_OL_REFCOUNT_BLOCK | \
-     QCOW2_OL_INACTIVE_L1)
-
-/* Perform all overlap checks */
-#define QCOW2_OL_ALL \
-    (QCOW2_OL_CACHED | QCOW2_OL_INACTIVE_L2)
-
-#define L1E_OFFSET_MASK 0x00fffffffffffe00ULL
-#define L1E_RESERVED_MASK 0x7f000000000001ffULL
-#define L2E_OFFSET_MASK 0x00fffffffffffe00ULL
-#define L2E_STD_RESERVED_MASK 0x3f000000000001feULL
-
-#define REFT_OFFSET_MASK 0xfffffffffffffe00ULL
-#define REFT_RESERVED_MASK 0x1ffULL
-
-#define INV_OFFSET (-1ULL)
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif
diff --git a/qcow2/qcow2_meta.cpp b/qcow2/qcow2_meta.cpp
deleted file mode 100644
index eb4d2c1..0000000
--- a/qcow2/qcow2_meta.cpp
+++ /dev/null
@@ -1,1135 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#include <cassert>
-
-#include "qcow2.h"
-#include "ublksrv_tgt.h"
-
-
-// refcnt is for slice only, and initialize it as two, one is for submission
-// side, another is for free side. This way guarantees that the returned slice
-// from alloc_slice is always valid
-Qcow2Meta::Qcow2Meta(Qcow2Header &h, u64 off, u32 sz, const char *name, u32 f):
-	header(h), offset(off), buf_sz(sz), flags(f), refcnt(2)
-{
-	//used for implementing slice's ->reset() only
-	if (f & QCOW2_META_DONT_ALLOC_BUF)
-		return;
-
-	if (posix_memalign((void **)&addr, getpagesize(), sz))
-		ublk_err( "allocate memory %d bytes failed, %s\n",
-				sz, name);
-#ifdef DEBUG_QCOW2_META_OBJ
-	id = name;
-	qcow2_log("%s: constructed, obj %p, buf size %d off %lx flags %x\n",
-			name, this, sz, off, flags);
-#endif
-}
-
-void Qcow2Meta::show(const char *func, int line)
-{
-#ifdef DEBUG_QCOW2_META_OBJ
-	qcow2_log("%s:%d id %s obj %p flags %x off %lx ref %d\n",
-			func, line, id, this, flags, offset, refcnt);
-#else
-	qcow2_log("%s:%d obj %p flags %x off %lx ref %d\n",
-			func, line, this, flags, offset, refcnt);
-#endif
-}
-
-Qcow2Meta::~Qcow2Meta()
-{
-#ifdef DEBUG_QCOW2_META_OBJ
-	qcow2_log("%s: destructed, obj %p flags %x off %lx ref %d\n",
-			id, this, flags, offset, refcnt);
-#endif
-	if (flags & QCOW2_META_DONT_ALLOC_BUF)
-		return;
-
-	if (!is_top_meta() && (get_dirty(-1) || is_flushing() ||
-				(!get_update() && !get_evicted()))) {
-		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
-				__func__, this, flags, offset);
-		qcow2_assert(0);
-	}
-	free(addr);
-}
-
-int Qcow2Meta::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
-{
-	int fd;
-
-	if (addr == NULL)
-		return -EINVAL;
-	if (len > buf_sz) {
-		ublk_err( "%s %s: load too much %d(%d) \n",
-				__func__, typeid(*this).name(), len, buf_sz);
-		return -EINVAL;
-	}
-	if (!sync)
-		return -EOPNOTSUPP;
-
-	//qcow2_log("%s: read %s offset %llx len %lu  \n", __func__,
-	//		typeid(*this).name(), offset, len);
-	fd = qs.img.fd;
-	lseek(fd, offset, SEEK_SET);
-	data_len = read(fd, addr, len);
-	if (data_len != len)
-		qcow2_log("%s: read %u(%u)\n", __func__, len, data_len);
-	if (data_len > 0)
-		flags |= QCOW2_META_UPDATE;
-	return data_len;
-}
-
-int Qcow2Meta::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-		u32 len)
-{
-	int fd = qs.img.fd;
-	int ret;
-
-	if (!(flags & QCOW2_META_DIRTY))
-		return 0;
-
-	if (!(flags & QCOW2_META_UPDATE))
-		ublk_err( "%s %s: buf isn't update\n", __func__,
-				typeid(*this).name());
-
-	//qcow2_log("%s: write %s offset %llx len %lu  \n", __func__,
-	//		typeid(*this).name(), offset, buf_sz);
-	lseek(fd, off, SEEK_SET);
-	ret = write(fd, addr, len);
-	if (len != ret)
-		qcow2_log("%s: write %u(%u)\n", __func__, len, ret);
-	if (ret > 0)
-		flags &= ~QCOW2_META_DIRTY;
-
-	return len;
-}
-
-void Qcow2Meta::zero_buf() {
-	memset((void *)addr, 0, buf_sz);
-}
-
-// Base class is constructed first, then follows member class/objects,
-// and member classes are done in the order of their declaration,
-// so here __a can be setup correctly.
-Qcow2HeaderExtFeatureNameTable::Qcow2HeaderExtFeatureNameTable(
-		char *addr, u64 offset): Qcow2HeaderExt(addr, offset),
-	__a(len / sizeof(struct feature_entry))
-{
-	unsigned off = offset;
-
-	for (int i = 0; i < __a.size(); i++) {
-		__a[i].feature_type = *(addr + off + 8);
-		__a[i].bit_num = *(addr + off + 9);
-		strncpy(__a[i].feature_name, addr + off + 10, 46);
-		off += 48;
-	}
-}
-
-void Qcow2HeaderExtFeatureNameTable::dump() const
-{
-	Qcow2HeaderExt::dump();
-
-	for (int i = 0; i < __a.size(); i++)
-		qcow2_log("\t %d: type %x bit_num %u name %s\n",
-			i, __a[i].feature_type, __a[i].bit_num,
-			__a[i].feature_name);
-}
-
-Qcow2Header::Qcow2Header(Qcow2State &state): Qcow2Meta(*this, 0, 4096,
-	typeid(this).name(), 0), magic(0), version(0), cluster_bits(0),
-	refcount_order(0), qs(state)
-{
-	backingfile_format_name = NULL;
-	feature_name_table = NULL;
-	enc_header_pointer = NULL;
-	bitmaps = NULL;
-	ext_data_file_name = NULL;
-
-	load(state, 0, buf_sz, true);
-}
-
-int Qcow2Header::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len)
-{
-	return Qcow2Meta::flush(qs, ioc, off, len);
-}
-
-Qcow2Header::~Qcow2Header()
-{
-	delete	backingfile_format_name;
-	delete	feature_name_table;
-	delete	enc_header_pointer;
-	delete	bitmaps;
-	delete	ext_data_file_name;
-}
-
-void Qcow2Header::dump_ext() const
-{
-	if (backingfile_format_name)
-		backingfile_format_name->dump();
-
-	if (ext_data_file_name)
-		ext_data_file_name->dump();
-
-	if (feature_name_table)
-		feature_name_table->dump();
-
-	if (bitmaps)
-		bitmaps->dump();
-
-	if (enc_header_pointer)
-		enc_header_pointer->dump();
-}
-
-/*
- * populate header extensions
- *
- * The header may take more than 4k, which should be decided by
- * backing_file_offset & backing_file_size __or__ populate
- * header extensions.
- */
-int Qcow2Header::populate()
-{
-	char *buf = (char *)addr;
-	u64 start = (get_header_length() + 7) & ~0x7ULL;
-	u32 *p_magic =  const_cast<u32 *> (&magic);
-	u32 *p_version =  const_cast<u32 *> (&version);
-	u32 *p_cluster_bits = const_cast<u32 *> (&cluster_bits);
-	u32 *p_refcount_order = const_cast<u32 *> (&refcount_order);
-
-	*p_magic = get_magic();
-	*p_version = get_version();
-	*p_cluster_bits = get_cluster_bits();
-	*p_refcount_order = get_refcount_order();
-
-	if (version == 2)
-		goto exit;
-
-	//todo: populate extensions
-	while (true) {
-		Qcow2HeaderExt ext(buf, start);
-
-		switch (ext.type) {
-		case QCOW2_EXT_MAGIC_END:
-			goto exit;
-		case QCOW2_EXT_MAGIC_BACKING_FORMAT:
-			this->backingfile_format_name =
-				new Qcow2HeaderExtString(buf, start);
-			break;
-		case QCOW2_EXT_MAGIC_FEATURE_TABLE:
-			this->feature_name_table =
-				new Qcow2HeaderExtFeatureNameTable(
-						buf, start);
-			break;
-		case QCOW2_EXT_MAGIC_CRYPTO_HEADER:
-			this->enc_header_pointer =
-				new Qcow2HeaderExtEncHeader(buf, start);
-			break;
-		case QCOW2_EXT_MAGIC_BITMAPS:
-			this->bitmaps =
-				new Qcow2HeaderExtBitmaps(buf, start);
-			break;
-		case QCOW2_EXT_MAGIC_DATA_FILE:
-			this->ext_data_file_name =
-				new Qcow2HeaderExtString(buf, start);
-			break;
-		};
-		start += 8 + (ext.len + 7) & ~0x7ULL;
-	}
- exit:
-	return 0;
-}
-
-int Qcow2Header::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
-{
-	int ret;
-
-	ret = Qcow2Meta::load(qs, ioc, len, sync);
-	if (ret <= 0)
-		goto fail;
-
-	ret = populate();
-	return ret;
- fail:
-	ublk_err( "%s: load failed %d", __func__, ret);
-	return ret;
-}
-
-std::ostream & operator<<(std::ostream &os, const Qcow2Header &h)
-{
-	char buf[256];
-
-	sprintf(buf, "magic: %x", h.magic);
-	std::cout << std::string(buf) << std::endl;
-	qcow2_log("%s", buf);
-
-	sprintf(buf, "version: %x\n", h.version);
-	std::cout << std::string(buf) << std::endl;
-	qcow2_log("%s", buf);
-
-	sprintf(buf, "cluster_bits: %x\n", h.cluster_bits);
-	std::cout << std::string(buf) << std::endl;
-	qcow2_log("%s", buf);
-
-	sprintf(buf, "refcount_order: %x\n", h.refcount_order);
-	std::cout << std::string(buf) << std::endl;
-	qcow2_log("%s", buf);
-
-	return os;
-}
-
-Qcow2MappingMeta::Qcow2MappingMeta(Qcow2State &qs, u64 off, u32 buf_sz,
-		const char *cls_name, u32 f):
-	Qcow2Meta(qs.header, off, buf_sz, cls_name, f)
-{
-	//default each entry is 64bits(8bytes) except for:
-	// extended l2 entry is 128bit, refcount blk has refcount_order
-	entry_bits_order = 6;
-	next_free_idx = -1;
-}
-
-/*
- * __flush() is just one worker, state check/update is done before calling
- * __flush()
- */
-int Qcow2MappingMeta::__flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u64 off, u32 len, bool run_fsync)
-{
-	int fd = qs.img.fd;
-	u32 qid = ioc.get_qid();
-	u32 tag = ioc.get_tag();
-	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
-	struct io_uring_sqe *sqe, *sqe2;
-	unsigned mio_id;
-
-	qcow2_assert(flags & QCOW2_META_DIRTY);
-
-	if (!(flags & QCOW2_META_UPDATE))
-		ublk_err( "%s %s: buf isn't update\n", __func__,
-				typeid(*this).name());
-
-	if (off < offset || off >= offset + buf_sz) {
-		ublk_err( "%s %s: offset %" PRIx64 " is wrong\n", __func__,
-				typeid(*this).name(), offset);
-		return -EINVAL;
-	}
-
-	if (len > offset + buf_sz - off) {
-		ublk_err( "%s %s: len %x is wrong\n", __func__,
-				typeid(*this).name(), len);
-		return -EINVAL;
-	}
-
-	sqe = io_uring_get_sqe(q->ring_ptr);
-	if (!sqe) {
-		ublk_err( "%s %s: not get sqe allocated",
-				__func__, typeid(*this).name());
-		return -ENOMEM;
-	}
-
-	if (run_fsync) {
-		sqe2 = io_uring_get_sqe(q->ring_ptr);
-		if (!sqe2) {
-			ublk_err( "%s %s: not get sqe2 allocated",
-				__func__, typeid(*this).name());
-			return -ENOMEM;
-		}
-		io_uring_prep_fsync(sqe2, fd, IORING_FSYNC_DATASYNC);
-		sqe2->user_data = build_user_data(0xffff, IORING_OP_FSYNC, 0, 1);
-		sqe2->flags |= IOSQE_IO_LINK;
-	}
-
-	mio_id = qs.add_meta_io(qid, this);
-
-	io_uring_prep_write(sqe, fd, (void *)((u64)addr + (off - offset)),
-			len, off);
-	sqe->user_data = build_user_data(tag, IORING_OP_WRITE, mio_id + 1, 1);
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: flushing %p tag %d off %lx sz %d flags %x refcnt %d\n",
-			__func__, typeid(*this).name(), this, tag, off,
-			len, flags, read_ref());
-	return 1;
-}
-
-void Qcow2MappingMeta::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe)
-{
-	u32 tag = user_data_to_tag(cqe->user_data);
-	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
-	u32 op = user_data_to_op(cqe->user_data);
-
-	qs.del_meta_io(q->q_id, meta_id);
-
-	//zero my cluster needn't to wakeup events on me
-	if (op != IORING_OP_FALLOCATE)
-		wakeup_all(q, tag);
-}
-
-Qcow2TopTable::Qcow2TopTable(Qcow2State &qs, u64 off, u32 buf_sz,
-		const char *cls_name, u32 f):
-	Qcow2MappingMeta(qs, off, buf_sz, cls_name, f),
-	min_bs_bits(qs.min_bs_bits),
-	dirty(qs.get_l1_table_max_size() >> qs.min_bs_bits)
-{
-	ublk_dbg(UBLK_DBG_QCOW2_META_L1, "%s: %s dirty size %zd %u/%u\n",
-			__func__,
-			cls_name, dirty.size(),
-		qs.get_l1_table_max_size(),qs.min_bs_bits);
-	for (int i = 0; i < dirty.size(); i++)
-		dirty[i] = false;
-}
-
-bool Qcow2TopTable::prep_flush(const qcow2_io_ctx_t &ioc, u32 blk_idx)
-{
-	if (!(flags & QCOW2_META_DIRTY))
-		return false;
-
-	//so far, just allow one in-progress unit for l1/refcount table
-	if (flags & QCOW2_META_FLUSHING)
-		return false;
-
-	flags |= QCOW2_META_FLUSHING;
-	return true;
-}
-
-void Qcow2TopTable::unprep_flush(u32 blk_idx) {
-	flags &= ~QCOW2_META_FLUSHING;
-}
-
-void Qcow2TopTable::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe)
-{
-	u32 op = user_data_to_op(cqe->user_data);
-
-	//only for write l1 or refcount table
-	qcow2_assert(op == IORING_OP_WRITE);
-
-	unprep_flush(get_flush_blk_idx());
-
-	if (cqe->res < 0)
-		return;
-
-	set_blk_dirty(get_flush_blk_idx(), false);
-
-	Qcow2MappingMeta::io_done(qs, q, cqe);
-}
-
-int Qcow2TopTable::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u64 off, u32 len)
-{
-	int blk_idx = (off - offset) >> min_bs_bits;
-	int ret;
-
-	qcow2_assert(len == 512 && blk_idx < dirty.size());
-
-	if (!prep_flush(ioc, blk_idx))
-		return 0;
-
-	if (!get_blk_dirty(blk_idx)) {
-		ret = 0;
-		goto exit;
-	}
-
-	set_flush_blk_idx(blk_idx);
-
-	//need to run fsync before writting l1/refcount table, so
-	//that write order between top and l2/refcount blk is respected
-	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len, true);
-exit:
-	if (ret <= 0)
-		unprep_flush(blk_idx);
-	return ret;
-}
-
-bool Qcow2TopTable::has_dirty_slices(Qcow2State &qs, int idx)
-{
-	u64 entry = get_entry(idx);
-	u64 start, end, step, offset;
-
-	if (!entry)
-		return false;
-
-	if (is_mapping_meta())
-		step = 1ULL << (QCOW2_PARA::L2_TABLE_SLICE_BITS - 3 +
-				qs.header.cluster_bits);
-	else
-		step = 1ULL << (QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS - 3 +
-				qs.header.cluster_bits);
-
-	start = ((u64)idx) << single_entry_order();
-	end = start + (1ULL << single_entry_order());
-	for (offset = start; offset < end; offset += step) {
-		Qcow2SliceMeta *t;
-
-		if (is_mapping_meta())
-			t = qs.cluster_map.__find_slice(offset);
-		else
-			t = qs.cluster_allocator.__find_slice(offset);
-
-		if (t && t->get_dirty(-1))
-			return true;
-	}
-
-	return false;
-}
-
-Qcow2L1Table::Qcow2L1Table(Qcow2State &qs): Qcow2TopTable(qs,
-		qs.get_l1_table_offset(), qs.get_l1_table_max_size(),
-		typeid(*this).name(), QCOW2_META_TOP | QCOW2_META_MAPPING)
-{
-}
-
-int Qcow2L1Table::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync)
-{
-	int ret;
-
-	ret = Qcow2Meta::load(qs, ioc, len, sync);
-	if (ret < 0)
-		ublk_err( "%s %s: load failed %d", __func__,
-				typeid(*this).name(), ret);
-	return ret;
-}
-
-void Qcow2L1Table::dump()
-{
-	qcow2_log("%s %s: sizeof %zd\n", __func__, typeid(*this).name(),
-			sizeof(*this));
-	for (int i = 0; i < header.get_l1_size(); i++)
-		qcow2_log("%d: %lx\n", i, get_entry(i));
-}
-
-u64  Qcow2L1Table::get_entry(u32 idx) {
-	return get_entry_fast(idx);
-}
-
-void Qcow2L1Table::set_entry(u32 idx, u64 val) {
-	set_entry_fast(idx, val);
-}
-
-Qcow2RefcountTable::Qcow2RefcountTable(Qcow2State &qs):
-	Qcow2TopTable(qs, qs.get_refcount_table_offset(),
-		qs.get_refcount_table_max_size(),
-		typeid(*this).name(), QCOW2_META_TOP)
-{
-}
-
-int Qcow2RefcountTable::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u32 len, bool sync)
-{
-	int ret;
-
-	ret = Qcow2Meta::load(qs, ioc, len, sync);
-	if (ret < 0)
-		ublk_err( "%s %s: load failed %d", __func__,
-				typeid(*this).name(), ret);
-	return ret;
-}
-
-u64  Qcow2RefcountTable::get_entry(u32 idx) {
-	return get_entry_fast(idx);
-}
-
-void Qcow2RefcountTable::set_entry(u32 idx, u64 val) {
-	set_entry_fast(idx, val);
-}
-
-void Qcow2RefcountTable::dump()
-{
-	qcow2_log("%s %s: sizeof %zd\n", __func__, typeid(*this).name(),
-			sizeof(*this));
-	for (int i = 0; i < data_len / 8; i++) {
-		u64 entry = get_entry(i);
-
-		if (entry != 0)
-			qcow2_log("%d: %lx\n", i, entry);
-	}
-}
-
-Qcow2SliceMeta::Qcow2SliceMeta(Qcow2State &qs, u64 off, u32 buf_sz,
-		const char *cls_name, u32 p_idx, u32 f):
-	Qcow2MappingMeta(qs, off, buf_sz, cls_name, f),
-	parent_idx(p_idx)
-{
-#ifdef QCOW2_CACHE_DEBUG
-        qcow2_log("slice meta %llx/%p/%d allocated\n", off, addr, buf_sz);
-#endif
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	if (posix_memalign((void **)&validate_addr, getpagesize(), buf_sz))
-		ublk_err( "%s: allocate validate memory %d bytes failed\n",
-				__func__, buf_sz);
-#endif
-}
-
-Qcow2SliceMeta::~Qcow2SliceMeta() {
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	free(validate_addr);
-#endif
-}
-
-bool Qcow2SliceMeta::prep_flush(const qcow2_io_ctx_t &ioc)
-{
-	if (!(flags & QCOW2_META_DIRTY))
-		return false;
-
-	if (flags & QCOW2_META_FLUSHING) {
-		add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-	flags |= QCOW2_META_FLUSHING;
-	return true;
-}
-
-void Qcow2SliceMeta::unprep_flush() {
-	flags &= ~QCOW2_META_FLUSHING;
-}
-
-int Qcow2SliceMeta::zero_my_cluster(Qcow2State &qs,
-		const qcow2_io_ctx_t &ioc)
-{
-	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);
-	Qcow2ClusterState *s = qs.cluster_allocator.get_cluster_state(
-			 cluster_off);
-	u32 qid = ioc.get_qid();
-	u32 tag = ioc.get_tag();
-	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
-	int fd = q->dev->tgt.fds[1];
-	struct io_uring_sqe *sqe;
-	int mode = FALLOC_FL_ZERO_RANGE;
-	unsigned mio_id;
-
-	if (s == nullptr)
-		return 0;
-
-	if (s->get_state() >= QCOW2_ALLOC_ZEROED)
-		return 0;
-
-	if (s->get_state() == QCOW2_ALLOC_ZEROING) {
-		s->add_waiter(ioc.get_tag());
-		throw MetaUpdateException();
-	}
-
-	sqe = io_uring_get_sqe(q->ring_ptr);
-	if (!sqe) {
-		ublk_err("%s: tag %d offset %" PRIu64 "op %d, no sqe for zeroing\n",
-			__func__, tag, offset, IORING_OP_FALLOCATE);
-		return -ENOMEM;
-	}
-
-	get_ref();
-
-	mio_id = qs.add_meta_io(qid, this);
-	s->set_state(QCOW2_ALLOC_ZEROING);
-	io_uring_prep_fallocate(sqe, fd, mode, cluster_off,
-			(1ULL << qs.header.cluster_bits));
-	sqe->user_data = build_user_data(tag,
-			IORING_OP_FALLOCATE, mio_id + 1, 1);
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: zeroing %p tag %d off %lx sz %d flags %x ref %d\n",
-			__func__, typeid(*this).name(), this, tag, cluster_off,
-			(1ULL << qs.header.cluster_bits), flags, refcnt);
-	return 1;
-}
-
-int Qcow2SliceMeta::load(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u32 len, bool sync)
-{
-	int ret = -EINVAL;
-	u32 qid = ioc.get_qid();
-	u32 tag = ioc.get_tag();
-	const struct ublksrv_queue *q = ublksrv_get_queue(qs.dev, qid);
-	struct io_uring_sqe *sqe;
-	int mio_id;
-
-	if (sync) {
-		ublk_err( "%s %s: we only support async load",
-				__func__, typeid(*this).name());
-		return -EINVAL;
-	}
-
-	if (flags & QCOW2_META_UPDATE) {
-		ublk_err( "%s %s: we are update, need to load?",
-				__func__, typeid(*this).name());
-		return -EINVAL;
-	}
-
-	sqe = io_uring_get_sqe(q->ring_ptr);
-	if (!sqe) {
-		ublk_err( "%s %s: not get sqe allocated",
-				__func__, typeid(*this).name());
-		return ret;
-	}
-
-	get_ref();
-
-	mio_id = qs.add_meta_io(qid, this);
-
-	io_uring_prep_read(sqe, 1, (void *)addr, buf_sz, offset);
-	sqe->flags = IOSQE_FIXED_FILE;
-	/* meta io id starts from one and zero is reserved for plain ublk io */
-	sqe->user_data = build_user_data(tag, IORING_OP_READ, mio_id + 1, 1);
-
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: queue io op %d(%llx %x %llx)"
-				" (qid %d tag %u, cmd_op %u target: %d tgt_data %d)\n",
-			__func__, sqe->opcode, sqe->off, sqe->len, sqe->addr,
-			q->q_id, tag, sqe->opcode, 1, mio_id + 1);
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s %s: loading %p tag %d off %lx sz %d flags %x ref %d\n",
-			__func__, typeid(*this).name(), this, tag,
-			offset, buf_sz, flags, refcnt);
-
-	return 0;
-}
-
-#ifdef DEBUG_QCOW2_META_VALIDATE
-void Qcow2SliceMeta::io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
-			struct io_uring_cqe *cqe)
-{
-	u32 tag = user_data_to_tag(cqe->user_data);
-	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
-	u32 op = user_data_to_op(cqe->user_data);
-	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);
-	bool res;
-
-	//for write, buffer data has been saved to validate_addr before
-	//submitting the WRITE io
-	if (op != IORING_OP_WRITE) {
-		lseek(qs.img.fd, offset, SEEK_SET);
-		read(qs.img.fd, validate_addr, buf_sz);
-	}
-
-	if (op == IORING_OP_FALLOCATE) {
-		for (int i = 0; i < buf_sz; i++) {
-			char *buf = (char *)validate_addr;
-
-			qcow2_assert(buf[i] == 0);
-		}
-	} else if (op == IORING_OP_WRITE || op == IORING_OP_READ) {
-		unsigned long *buf = (unsigned long *)addr;
-		unsigned long *buf2 = (unsigned long *)validate_addr;
-
-		res = bcmp(addr, validate_addr, buf_sz);
-
-		if (res == 0)
-			return;
-
-		for (int i = 0; i < buf_sz / 8; i++) {
-			if (buf[i] != buf2[i]) {
-				qcow2_log("%s: not same in %d %lx %lx\n",
-					__func__, i, buf[i], buf2[i]);
-				qcow2_log("%s: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
-					__func__, tag, meta_id, op, this,
-					get_flags(), get_offset(),
-					refcnt, cqe->res);
-			}
-		}
-		qcow2_assert(0);
-	}
-}
-#endif
-
-/* called for both load() and flush() */
-void Qcow2SliceMeta::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe)
-{
-	u32 tag = user_data_to_tag(cqe->user_data);
-	u32 meta_id = user_data_to_tgt_data(cqe->user_data) - 1;
-	u32 op = user_data_to_op(cqe->user_data);
-	u64 cluster_off = offset & ~((1ULL << qs.header.cluster_bits) - 1);
-
-	if (cqe->res < 0) {
-		qcow2_log("%s: failure: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
-			__func__, tag, meta_id, op, this,
-			get_flags(), get_offset(), refcnt, cqe->res);
-		//zeroing the cluster for holding me is done
-		if (op == IORING_OP_FALLOCATE) {
-			if (qs.cluster_allocator.
-			    alloc_cluster_reset(cluster_off))
-				goto exit;
-		} else if (op == IORING_OP_WRITE) {
-			unprep_flush();
-			goto exit;
-		} else
-			goto exit;
-	}
-
-	io_done_validate(qs, q, cqe);
-
-	if (op == IORING_OP_READ)
-		set_update(true);
-	else if (op == IORING_OP_WRITE) {
-		unprep_flush();
-		qs.meta_flushing.dec_dirtied_slice(is_mapping_meta());
-		set_dirty(-1, false);
-		set_prep_flush(false);
-	} else if (op == IORING_OP_FALLOCATE)
-		qs.cluster_allocator.alloc_cluster_zeroed(q, tag, cluster_off);
-	else
-		ublk_err( "%s: unknown op: tag %d op %d meta_id %d res %d\n",
-			__func__, tag, op, meta_id, cqe->res);
-
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: tag %d, tgt_data %d op %d meta (%p %x %lx %d) res %d\n",
-			__func__, tag, meta_id, op, this,
-			get_flags(), get_offset(), refcnt, cqe->res);
-
-	//wake up waiters
-	Qcow2MappingMeta::io_done(qs, q, cqe);
-
-	//if it is evicted, now it is ready to free it
-	if ((op == IORING_OP_WRITE) && cqe->res >= 0 && get_evicted())
-		qs.add_slice_to_free_list(this);
-
-exit:
-	//drop the reference grabbed in either load() or flush()
-	put_ref();
-	return;
-}
-
-void Qcow2SliceMeta::wait_clusters(Qcow2State &qs,
-		const qcow2_io_ctx_t &ioc)
-{
-	for (int i = 0; i < get_nr_entries(); i++) {
-		u64 entry = get_entry(i);
-
-		if (entry) {
-			u64 cluster_off;
-
-			//mapping meta means this is one l2 table, otherwise
-			//it is one refcount block table
-			if (is_mapping_meta())
-				cluster_off = entry & L1E_OFFSET_MASK;
-			else
-				cluster_off = virt_offset() + (u64)i << qs.header.cluster_bits;
-
-			 Qcow2ClusterState *s = qs.cluster_allocator.
-				 get_cluster_state(cluster_off);
-
-			if (s == nullptr)
-				continue;
-
-			if (s->get_state() < QCOW2_ALLOC_ZEROED) {
-				s->add_waiter(ioc.get_tag());
-				throw MetaUpdateException();
-			}
-		}
-	}
-}
-
-void Qcow2SliceMeta::reclaim_me()
-{
-	unsigned queues = header.qs.dev_info->nr_hw_queues;
-
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: %p off %llx flags %x\n", __func__,
-			this, get_offset(), flags);
-
-	header.qs.remove_slice_from_evicted_list(this);
-
-	ublk_dbg(UBLK_DBG_QCOW2_META, "%s: %p off %llx\n", __func__, this, get_offset());
-
-	//Tell the whole world, I am leaving
-	for (int i = 0; i < queues; i++) {
-		const struct ublksrv_queue *q = ublksrv_get_queue(header.qs.dev, i);
-
-		wakeup_all(q, -1);
-	}
-	header.qs.reclaim_slice(this);
-}
-
-Qcow2RefcountBlock::Qcow2RefcountBlock(Qcow2State &qs, u64 off, u32 p_idx, u32 f):
-	Qcow2SliceMeta(qs, off, QCOW2_PARA::REFCOUNT_BLK_SLICE_BYTES,
-			typeid(*this).name(), p_idx, f),
-	dirty_start_idx((unsigned)-1)
-{
-	entry_bits_order = qs.header.refcount_order;
-	ublk_dbg(UBLK_DBG_QCOW2_META_RB, "rb meta %p %llx -> %llx \n", this, virt_offset(), off);
-}
-
-
-void Qcow2RefcountBlock::reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f)
-{
-	Qcow2RefcountBlock tmp(qs, off, p_idx, f | QCOW2_META_DONT_ALLOC_BUF);
-
-	qcow2_assert(refcnt == 0);
-
-	offset = tmp.get_offset();
-	flags  = tmp.get_flags() & ~QCOW2_META_DONT_ALLOC_BUF;
-	refcnt = tmp.read_ref();
-
-	ublk_dbg(UBLK_DBG_QCOW2_META_RB, "%s: %p refcnt %d flags %x offset %lx \n",
-			__func__, this, refcnt, flags, offset);
-
-	next_free_idx = tmp.get_next_free_idx();
-
-	parent_idx = tmp.parent_idx;
-
-	dirty_start_idx = tmp.dirty_start_idx;
-}
-
-u64  Qcow2RefcountBlock::get_entry(u32 idx) {
-	return get_entry_fast(idx);
-}
-
-void Qcow2RefcountBlock::set_entry(u32 idx, u64 val) {
-	set_entry_fast(idx, val);
-
-	if (is_flushing() || !get_update()) {
-		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
-				__func__, this, flags, offset);
-		qcow2_assert(0);
-	}
-}
-
-int Qcow2RefcountBlock::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u64 off, u32 len)
-{
-	int ret;
-
-	//wait_clusters(qs, ioc);
-
-	if (!prep_flush(ioc))
-		return 0;
-
-	//flush can't be started unless the above two are done
-	//
-	//the ref is released in io_done()
-	get_ref();
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	memcpy(validate_addr, addr, buf_sz);
-#endif
-	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len);
-	if (ret <= 0) {
-		unprep_flush();
-		put_ref();
-	}
-	return ret;
-}
-
-Qcow2RefcountBlock::~Qcow2RefcountBlock()
-{
-}
-
-void Qcow2RefcountBlock::get_dirty_range(u64 *start, u64 *end)
-{
-	*start = 1;
-	*end = 0;
-}
-
-void Qcow2RefcountBlock::dump()
-{
-	unsigned cnt = 0;
-	int f = -1, l;
-	for (int i = 0; i < get_nr_entries(); i++) {
-		u64 entry = get_entry(i);
-
-		if (entry != 0) {
-			if (f == -1)
-				f = i;
-			l = i;
-			cnt++; //qcow2_log("%d: %lx\n", i, entry);
-		}
-	}
-
-	if (!cnt)
-		return;
-
-	qcow2_log("%s %s: buf_sz %u offset %" PRIx64 " sizeof %zd entries %u parent_idx %u virt_off %" PRIx64 " flags %x\n",
-			__func__, typeid(*this).name(), buf_sz, offset, sizeof(*this),
-			cnt, parent_idx, virt_offset(),
-			flags);
-	qcow2_log("\t [%d] = %" PRIx64 "/%" PRIx64 " [%d] = %" PRIx64 "/%" PRIx64 "\n",
-			f, get_entry(f),
-			virt_offset() + (f << header.cluster_bits),
-			l, get_entry(l),
-			virt_offset() + (l << header.cluster_bits));
-}
-
-Qcow2L2Table::Qcow2L2Table(Qcow2State &qs, u64 off, u32 p_idx, u32 f):
-	Qcow2SliceMeta(qs, off, QCOW2_PARA::L2_TABLE_SLICE_BYTES,
-		typeid(*this).name(), p_idx, f | QCOW2_META_MAPPING)
-{
-	if (header.is_extended_l2_entries())
-		entry_bits_order <<= 1;
-	dirty_start = (u64)-1;
-	dirty_end = 0;
-        ublk_dbg(UBLK_DBG_QCOW2_META_L2, "l2 meta %p %llx -> %llx \n", this, virt_offset(), off);
-}
-
-void Qcow2L2Table::reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f)
-{
-	Qcow2L2Table tmp(qs, off, p_idx, f | QCOW2_META_DONT_ALLOC_BUF);
-
-	qcow2_assert(refcnt == 0);
-
-	offset = tmp.get_offset();
-	flags = tmp.get_flags() & ~QCOW2_META_DONT_ALLOC_BUF;
-	refcnt = tmp.read_ref();
-
-	ublk_dbg(UBLK_DBG_QCOW2_META_L2, "%s: %p refcnt %d flags %x offset %lx \n",
-			__func__, this, refcnt, flags, offset);
-
-	next_free_idx = tmp.get_next_free_idx();
-
-	parent_idx = tmp.parent_idx;
-
-	tmp.get_dirty_range(&dirty_start, &dirty_end);
-}
-
-Qcow2L2Table::~Qcow2L2Table()
-{
-}
-
-void Qcow2L2Table::io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe)
-{
-	get_ref();
-	Qcow2SliceMeta::io_done(qs, q, cqe);
-	check(qs, __func__, __LINE__);
-	put_ref();
-}
-
-u64  Qcow2L2Table::get_entry(u32 idx) {
-	return get_entry_fast(idx);
-}
-
-void Qcow2L2Table::get_dirty_range(u64 *start, u64 *end)
-{
-	*start = dirty_start;
-	*end = dirty_end;
-}
-
-void Qcow2L2Table::set_entry(u32 idx, u64 val) {
-	set_entry_fast(idx, val);
-
-	if (is_flushing() || !get_update()) {
-		qcow2_log("BUG %s: obj %p flags %x off %lx\n",
-				__func__, this, flags, offset);
-		qcow2_assert(0);
-	}
-
-	val &= L2E_OFFSET_MASK;
-
-	qcow2_assert(!(val & ((1ULL << header.cluster_bits) - 1)));
-
-	if (val < dirty_start)
-		dirty_start = val;
-	if (val > dirty_end)
-		dirty_end = val;
-}
-
-int Qcow2L2Table::flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u64 off, u32 len)
-{
-	int ret;
-
-	wait_clusters(qs, ioc);
-
-	if (!prep_flush(ioc))
-		return 0;
-
-	//flush can't be started unless the above two are done
-	//
-	//the ref is released in io_done()
-	get_ref();
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	memcpy(validate_addr, addr, buf_sz);
-	check_duplicated_clusters(qs, ioc.get_tag(), __func__, __LINE__);
-#endif
-	ret = Qcow2MappingMeta::__flush(qs, ioc, off, len);
-	if (ret <= 0) {
-		unprep_flush();
-		put_ref();
-	}
-	return ret;
-}
-
-void Qcow2L2Table::dump()
-{
-	unsigned cnt = 0;
-	int f = -1, l;
-
-	for (int i = 0; i < get_nr_entries(); i++) {
-		u64 entry = get_entry(i);
-
-		if (entry != 0) {
-			if (f == -1)
-				f = i;
-			l = i;
-			cnt++; //qcow2_log("%d: %lx\n", i, entry);
-		}
-	}
-
-	if (!cnt)
-		return;
-
-	qcow2_log("%s %s: buf_sz %u offset %" PRIx64 " sizeof %zd entries %u parent_idx %u virt_off %" PRIx64 " flags %x\n",
-			__func__, typeid(*this).name(), buf_sz, offset, sizeof(*this),
-			cnt, parent_idx, virt_offset(), flags);
-	qcow2_log("\t [%d] = %" PRIx64 "[%u] = %" PRIx64 "\n", f,
-			get_entry(f), l, get_entry(l));
-}
-
-#ifdef DEBUG_QCOW2_META_VALIDATE
-void Qcow2L2Table::check(Qcow2State &qs, const char *func, int line)
-{
-	int i, cnt = 0;
-	bool bad = false;
-
-	if (!get_update())
-		return;
-
-	//don't check evicted obj, which can't be used by anyone
-	if (get_evicted())
-		return;
-
-	for (i = 0; i < get_nr_entries(); i++) {
-		u64 entry = get_entry(i) & ((1ULL << 63) - 1);
-
-		if (entry == 0)
-			continue;
-
-		cnt++;
-
-		if (entry + (1ULL << qs.header.cluster_bits) >
-				qs.cluster_allocator.max_physical_size) {
-			qcow2_log("%s %d: entry %llx(parent idx %d, idx %d) offset %llx is too big\n",
-					func, line, entry, parent_idx, i,
-					get_offset());
-			bad = true;
-		}
-
-		if (entry & ((1ULL << qs.header.cluster_bits) - 1)) {
-			qcow2_log("%s: entry %llx(parent idx %d, idx %d) offset %llx isn't aligned\n",
-					func, line, entry, parent_idx, i,
-					get_offset());
-			bad = true;
-		}
-	}
-
-	if (bad) {
-		qcow2_log("%s %s: %p buf_sz %u offset %llx sizeof %d parent_idx %u virt_off %llx flags %x refcnt %d\n",
-				__func__, typeid(*this).name(), this, buf_sz, offset, sizeof(*this),
-				parent_idx, virt_offset(), flags, read_ref());
-		qcow2_log("\t total entries %d\n", cnt);
-		assert(0);
-	}
-}
-
-void Qcow2L2Table::check_duplicated_clusters(Qcow2State &qs, int tag,
-		const char *func, int line)
-{
-	for (int i = 0; i < get_nr_entries(); i++) {
-		u64 entry = get_entry(i);
-
-		if (entry != 0) {
-			u64 host_off = entry & ((1ULL << 63) - 1);
-			u64 virt_off = virt_offset() + (((u64)i) <<
-				qs.header.cluster_bits);
-
-			if (qs.validate_cluster_map(host_off, virt_off))
-				continue;
-			qcow2_log("BUG %s %d: tag %d obj %p flags %x off %lx virt_off "
-					"%lx(#%d) parent_idx %d\n",
-				func, line, tag, this, flags, offset,
-				virt_offset(), i, parent_idx);
-			qcow2_assert(0);
-		}
-	}
-}
-#endif
diff --git a/qcow2/qcow2_meta.h b/qcow2/qcow2_meta.h
deleted file mode 100644
index cc67ccb..0000000
--- a/qcow2/qcow2_meta.h
+++ /dev/null
@@ -1,762 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#ifndef UBLK_QCOW2_META_H_
-#define UBLK_QCOW2_META_H_
-
-#include "qcow2_common.h"
-
-class Qcow2State;
-class Qcow2Header;
-
-/*
- * Class design:
- * 1) copy constructor / operator assign overloading / 
- *
- * 2) one friend function for dumping object
- *
- *
- * Loading meta:
- *
- *
- * Flushing meta:
- */
-class Qcow2Meta {
-protected:
-#ifdef DEBUG_QCOW2_META_OBJ
-	const char *id;
-#endif
-	Qcow2Header	&header;
-	void *addr;	//buffer address
-	u64   offset;	//offset in host image
-	u32   buf_sz;	//buffer size
-	u32   data_len; //current data length in the buffer, valid iff update is
-			//true
-
-#define QCOW2_META_DIRTY    (1U << 0)
-#define QCOW2_META_UPDATE   (1U << 1)
-
-//l1 & refcount table is top meta, set in constructor, should only
-//be used for flush meta
-#define QCOW2_META_TOP       (1U << 2)
-
-//the meta slice is being flushed to image
-#define QCOW2_META_FLUSHING  (1U << 3)
-
-#define QCOW2_META_PREP_FLUSH (1U << 4)
-
-//set for L1/L2 meta
-#define QCOW2_META_MAPPING   (1U << 5)
-
-//only used for .reset()
-#define QCOW2_META_DONT_ALLOC_BUF   (1U << 6)
-
-//evicted from lru cache, and may be in loading or flushing, and will
-//be freed after loading or flushing is done.
-//
-//But can't be re-dirtied any more, so slice marked as EVICTED is readonly
-#define QCOW2_META_EVICTED   (1U << 7)
-	u32	flags;
-
-	int	refcnt;
-public:
-	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len);
-	Qcow2Meta(Qcow2Header &h, u64 off, u32 buf_sz, const char *, u32 f);
-	virtual ~Qcow2Meta();
-	void zero_buf();
-	virtual void show(const char *f = "", int line = 0);
-
-#ifdef DEBUG_QCOW2_META_OBJ
-	const char *get_id() {
-		return id;
-	}
-#endif
-	void set_evicted() {
-		flags |= QCOW2_META_EVICTED;
-	}
-	bool get_evicted() {
-		return flags & QCOW2_META_EVICTED;
-	}
-
-	void set_dirty(unsigned int idx, bool val) {
-		if (val)
-			flags |= QCOW2_META_DIRTY;
-		else
-			flags &= ~QCOW2_META_DIRTY;
-	}
-
-	bool get_dirty(unsigned int idx) const {
-		return flags & QCOW2_META_DIRTY;
-	}
-
-	u64 get_offset() const {
-		return offset;
-	}
-
-	u64 get_buf_size() const {
-		return buf_sz;
-	}
-
-	u32 get_data_len() const {
-		return data_len;
-	}
-	bool get_update() const {
-		return !!(flags & QCOW2_META_UPDATE);
-	}
-	void set_update(bool val) {
-		if (val)
-			flags |= QCOW2_META_UPDATE;
-		else
-			flags &= ~QCOW2_META_UPDATE;
-	}
-
-	bool is_top_meta() const
-	{
-		return !!(flags & QCOW2_META_TOP);
-	}
-
-	bool is_mapping_meta() const
-	{
-		return !!(flags & QCOW2_META_MAPPING);
-	}
-
-	bool is_flushing() const {
-		return !!(flags & QCOW2_META_FLUSHING);
-	}
-
-	unsigned get_flags() const {
-		return flags;
-	}
-
-	int read_ref() const {
-		return refcnt;
-	}
-
-	bool get_prep_flush() const {
-		return !!(flags & QCOW2_META_PREP_FLUSH);
-	}
-
-	void set_prep_flush(bool val)
-	{
-		if (val)
-			flags |= QCOW2_META_PREP_FLUSH;
-		else
-			flags &= ~QCOW2_META_PREP_FLUSH;
-	}
-};
-
-#define  QCOW2_EXT_MAGIC_END 0
-#define  QCOW2_EXT_MAGIC_BACKING_FORMAT 0xe2792aca
-#define  QCOW2_EXT_MAGIC_FEATURE_TABLE 0x6803f857
-#define  QCOW2_EXT_MAGIC_CRYPTO_HEADER 0x0537be77
-#define  QCOW2_EXT_MAGIC_BITMAPS 0x23852875
-#define  QCOW2_EXT_MAGIC_DATA_FILE 0x44415441
-
-class Qcow2HeaderExt {
-private:
-	u64 offset;
-public:
-	u32 type;
-	u32 len;
-
-	Qcow2HeaderExt(char *addr, u64 off): offset(off)
-	{
-		u32 *buf = (u32 *)(addr + offset);
-		type = be32_to_cpu(buf[0]);
-
-		buf = (u32 *)(addr + offset + 4);
-		len = be32_to_cpu(buf[0]);
-	}
-
-	virtual ~Qcow2HeaderExt() {}
-
-	virtual void dump() const
-	{
-		qcow2_log("%s: type %x len %d\n",
-				typeid(*this).name(), type, len);
-	}
-};
-
-class Qcow2HeaderExtString : public Qcow2HeaderExt {
-public:
-	std::string str;
-
-	Qcow2HeaderExtString(char *addr, u64 offset):
-		Qcow2HeaderExt(addr, offset), str((char *)addr, 0, len)
-	{
-	}
-
-	virtual void dump() const
-	{
-		qcow2_log("%s: type %x len %d string %s\n",
-				typeid(*this).name(), type, len, str.c_str());
-	}
-};
-
-class Qcow2HeaderExtFeatureNameTable : public Qcow2HeaderExt {
-public:
-	struct feature_entry {
-		char feature_type;
-		char bit_num;
-		char feature_name[46];
-	};
-	typedef std::valarray<feature_entry> ArrayFeature;
-	ArrayFeature __a;
-
-	Qcow2HeaderExtFeatureNameTable(char *addr, u64 offset);
-	~Qcow2HeaderExtFeatureNameTable() {};
-	void dump() const;
-};
-
-class Qcow2HeaderExtBitmaps : public Qcow2HeaderExt {
-public:
-	u32  nr_bitmap;
-	u64  bitmap_directory_size;
-	u64  bitmap_directory_offset;
-	Qcow2HeaderExtBitmaps(char *addr, u64 offset):
-		Qcow2HeaderExt(addr, offset)
-	{
-		nr_bitmap = be32_to_cpu(*(u32 *)(addr + offset + 8));
-		bitmap_directory_size = be64_to_cpu(*(u64 *)(addr +
-					offset + 12));
-		bitmap_directory_offset = be64_to_cpu(*(u64 *)(addr +
-					offset + 20));
-	}
-	virtual void dump() const
-	{
-		qcow2_log("%s: type %x len %d nr_bitmap %d bitmap_dir(offset %lx sz %lu)\n",
-				typeid(*this).name(), type, len,
-				nr_bitmap, bitmap_directory_offset,
-				bitmap_directory_size);
-	}
-};
-
-class Qcow2HeaderExtEncHeader : public Qcow2HeaderExt {
-public:
-	u64  enc_offset;
-	u64  enc_len;
-	Qcow2HeaderExtEncHeader(char *addr, u64 offset):
-		Qcow2HeaderExt(addr, offset)
-	{
-		enc_offset = be64_to_cpu(*(u64 *)(addr +
-					offset + 8));
-		enc_len = be64_to_cpu(*(u64 *)(addr +
-					offset + 16));
-	}
-	virtual void dump() const
-	{
-		qcow2_log("%s: type %x len %d enc(offset %" PRIx64 " sz %" PRIu64 ")\n",
-				typeid(*this).name(), type, len,
-				enc_offset, enc_len);
-	}
-};
-
-#define __INLINE_SET_GET(type, prop, v2_val)			\
-type get_##prop() const						\
-{								\
-	if (offsetof(QCowHeader, prop) >= 72 && version == 2)	\
-		return v2_val;					\
-	switch(sizeof(type)) {					\
-	case 8:							\
-		return be64_to_cpu(((QCowHeader*)addr)->prop);	\
-	case 4:							\
-		return be32_to_cpu(((QCowHeader*)addr)->prop);	\
-	case 2:							\
-		return be16_to_cpu(((QCowHeader*)addr)->prop);	\
-	case 1:							\
-		return ((QCowHeader*)addr)->prop;		\
-	}							\
-}								\
-void set_##prop(type v)						\
-{								\
-	QCowHeader *h = (QCowHeader *)addr;			\
-	if (offsetof(QCowHeader, prop) >= 72 && version == 2)	\
-		return;						\
-	switch(sizeof(type)) {					\
-	case 8:							\
-		h->prop = cpu_to_be64(v);			\
-		break;						\
-	case 4:							\
-		h->prop = cpu_to_be32(v);			\
-		break;						\
-	case 2:							\
-		h->prop = cpu_to_be16(v);			\
-		break;						\
-	case 1:							\
-		h->prop = v;					\
-		break;						\
-	}							\
-	Qcow2Meta::set_dirty(-1, true);				\
-}
-
-#define INLINE_SET_GET(type, prop) __INLINE_SET_GET(type, prop, 0)
-
-class Qcow2Header: public Qcow2Meta {
-private:
-	int populate();
-	Qcow2HeaderExtString		*backingfile_format_name;
-	Qcow2HeaderExtString		*ext_data_file_name;
-	Qcow2HeaderExtFeatureNameTable	*feature_name_table;
-	Qcow2HeaderExtBitmaps		*bitmaps;
-	Qcow2HeaderExtEncHeader		*enc_header_pointer;
-public:
-	const u32 magic;
-	const u32 version;
-	const u32 cluster_bits;
-	const u32 refcount_order;
-
-	//this way looks ugly, but just for retrieve qs in destructor of
-	//Qcow2SliceMeta
-	Qcow2State &qs;
-
-	Qcow2Header(Qcow2State &qs);
-	virtual ~Qcow2Header();
-	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len);
-	void dump_ext() const;
-
-	INLINE_SET_GET(u32, magic);
-	INLINE_SET_GET(u32, version);
-	INLINE_SET_GET(u64, backing_file_offset);
-	INLINE_SET_GET(u32, backing_file_size);
-	INLINE_SET_GET(u32, cluster_bits);
-	INLINE_SET_GET(u64, size);
-	INLINE_SET_GET(u32, crypt_method);
-	INLINE_SET_GET(u32, l1_size);
-	INLINE_SET_GET(u64, l1_table_offset);
-	INLINE_SET_GET(u64, refcount_table_offset);
-	INLINE_SET_GET(u32, refcount_table_clusters);
-	INLINE_SET_GET(u32, nb_snapshots);
-	INLINE_SET_GET(u64, snapshots_offset);
-	__INLINE_SET_GET(u64, incompatible_features, 0);
-	__INLINE_SET_GET(u64, compatible_features, 0);
-	__INLINE_SET_GET(u64, autoclear_features, 0);
-	__INLINE_SET_GET(u32, refcount_order, 4);
-	__INLINE_SET_GET(u32, header_length, 72);
-	__INLINE_SET_GET(u8, compression_type, 0);
-
-	friend std::ostream & operator<<(std::ostream &os, const Qcow2Header &h);
-
-	bool is_extended_l2_entries() {
-		return get_incompatible_features() & 0x8;
-	}
-};
-
-class Qcow2MappingMeta: public Qcow2Meta {
-private:
-	IOWaiters io_waiters;
-protected:
-	u32 entry_bits_order;
-	s32 next_free_idx;	//cache the next free idx
-
-	//deprecate now
-	bool entry_val_is_dirty(u64 val) {
-		qcow2_assert(false);
-		return true;
-	}
-
-	int __flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc,
-		u64 off, u32 len, bool run_fsync = false);
-	int clear_dirty_entries(Qcow2State &qs,
-		const qcow2_io_ctx_t &ioc, u64 off, u32 len);
-public:
-	Qcow2MappingMeta(Qcow2State &qs, u64 off, u32 buf_sz,
-			const char *cls_name, u32 f);
-	s32 get_nr_entries() {
-		return (buf_sz << 3) >> entry_bits_order;
-	}
-	s32 get_next_free_idx() {
-		return next_free_idx;
-	}
-	void set_next_free_idx(s32 idx) {
-		if (idx < get_nr_entries())
-			next_free_idx = idx;
-	}
-
-	void add_waiter(unsigned tag) {
-		io_waiters.add_waiter(tag);
-	}
-
-	void add_waiter_idx(unsigned tag, unsigned entry_idx) {
-		io_waiters.add_waiter_idx(tag, entry_idx);
-	}
-
-	void wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
-		io_waiters.wakeup_all(q, my_tag);
-	}
-
-	void wakeup_all_idx(const struct ublksrv_queue *q,
-			unsigned my_tag, unsigned entry_idx) {
-		io_waiters.wakeup_all_idx(q, my_tag, entry_idx);
-	}
-
-	virtual u64  get_entry(u32 idx) = 0;
-	virtual void set_entry(u32 idx, u64 val) = 0;
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len) = 0;
-
-	//both load() and flush() should be async, and done() needs to be called
-	//after both load() and flush() meta IO are done.
-	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe);
-};
-
-class Qcow2TopTable: public Qcow2MappingMeta {
-private:
-	u32 flush_blk_idx;
-
-protected:
-	u32 min_bs_bits;
-	std::vector <bool> dirty;
-public:
-	Qcow2TopTable(Qcow2State &qs, u64 off, u32 buf_sz,
-			const char *cls_name, u32 f);
-
-	bool is_flushing(u32 idx) {
-		if (Qcow2Meta::is_flushing() && idx == flush_blk_idx)
-			return true;
-		return false;
-	}
-
-	bool get_blk_dirty(u32 idx)
-	{
-		return dirty[idx];
-	}
-
-	void set_blk_dirty(u32 idx, bool val)
-	{
-		dirty[idx] = val;
-	}
-
-	u32 dirty_blks() {
-		u32 total = 0;
-
-		for (int i = 0; i < dirty.size(); i++)
-			if (dirty[i])
-				total += 1;
-		return total;
-	}
-
-	u32 dirty_blk_size() {
-		return dirty.size();
-	}
-
-	int get_1st_dirty_blk() {
-		for (int i = 0; i < dirty.size(); i++)
-			if (dirty[i])
-				return i;
-		return -1;
-	}
-
-	void set_flush_blk_idx(u32 idx)
-	{
-		flush_blk_idx = idx;
-	}
-
-	u32 get_flush_blk_idx()
-	{
-		return flush_blk_idx;
-	}
-
-	u64 single_entry_order() const
-	{
-		if (is_mapping_meta())
-			return (2 * header.cluster_bits - 3);
-		return 2 * header.cluster_bits + 3 - header.refcount_order;
-	}
-
-	bool prep_flush(const qcow2_io_ctx_t &ioc, u32 blk_idx);
-	void unprep_flush(u32 blk_idx);
-
-	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off, u32 len);
-	bool has_dirty_slices(Qcow2State &qs, int idx);
-};
-
-//allocating detection needs to review!!!
-class Qcow2L1Table: public Qcow2TopTable {
-public:
-	u32  offset_to_idx(u64 virt_offset) {
-		u32 cluster_bits = header.cluster_bits;
-		bool has_extended_l2_entries = header.is_extended_l2_entries();
-		u32 idx = (virt_offset >> cluster_bits) >>
-			(cluster_bits - 3 - !!has_extended_l2_entries);
-
-		return idx;
-	}
-
-	u64  get_entry_fast(u32 idx) {
-		u64 val = be64_to_cpu(((const u64 *)addr)[idx]);
-
-		return val;
-	}
-
-	void set_entry_fast(u32 idx, u64 val) {
-		unsigned i = idx >> (min_bs_bits - 3);
-
-		((u64 *)addr)[idx] = cpu_to_be64(val);
-		set_dirty(idx, true);
-
-		qcow2_assert(i < dirty.size());
-		dirty[i] = true;
-	}
-
-	bool entry_allocated(u64 entry) {
-		return entry != 0;
-	}
-
-	bool entry_is_dirty(u32 idx) {
-		return entry_val_is_dirty(get_entry(idx));
-	}
-
-	Qcow2L1Table(Qcow2State &qs);
-	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
-	virtual u64  get_entry(u32 idx);
-	virtual void set_entry(u32 idx, u64 val);
-	void dump();
-};
-
-class Qcow2RefcountTable: public Qcow2TopTable {
-public:
-	u32  offset_to_idx(u64 virt_offset) {
-		u32 cluster_bits = header.cluster_bits;
-		u32 idx = (virt_offset >> cluster_bits) >>
-			(cluster_bits + 3 - header.refcount_order);
-
-		return idx;
-	}
-	void set_entry_fast(u32 idx, u64 val) {
-		unsigned i = idx >> (min_bs_bits - 3);
-
-		((u64 *)addr)[idx] = cpu_to_be64(val);
-		set_dirty(idx, true);
-
-		qcow2_assert(i < dirty.size());
-		dirty[i] = true;
-	}
-	u64  get_entry_fast(u32 idx) {
-		return be64_to_cpu(((u64 *)addr)[idx]);
-	}
-	bool entry_is_dirty(u32 idx) {
-		return entry_val_is_dirty(get_entry(idx));
-	}
-
-	Qcow2RefcountTable(Qcow2State &qs);
-	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
-	virtual u64  get_entry(u32 idx);
-	virtual void set_entry(u32 idx, u64 val);
-	void dump();
-};
-
-class Qcow2SliceMeta: public Qcow2MappingMeta {
-protected:
-	bool prep_flush(const qcow2_io_ctx_t &ioc);
-	void unprep_flush();
-	virtual void wait_clusters(Qcow2State &qs, const qcow2_io_ctx_t &ioc);
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	void *validate_addr;
-#endif
-public:
-	unsigned int parent_idx; //parent's this entry points to us
-
-	Qcow2SliceMeta(Qcow2State &qs, u64 off, u32 buf_sz,
-			const char *cls_name, u32 p_idx, u32 f);
-	virtual int load(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u32 len, bool sync);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len) = 0;
-	virtual void dump() = 0;
-	virtual ~Qcow2SliceMeta();
-	virtual void get_dirty_range(u64 *start, u64 *end) = 0;
-
-	//both load() and flush() should be async, and done() needs to be called
-	//after both load() and flush() meta IO are done.
-	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe);
-	int zero_my_cluster(Qcow2State &qs, const qcow2_io_ctx_t &ioc);
-
-	void reclaim_me();
-
-	u64 get_offset() const {
-		return offset;
-	}
-
-	void get_ref() {
-		qcow2_assert(refcnt > 0);
-		refcnt += 1;
-	}
-
-	void put_ref() {
-		qcow2_assert(refcnt > 0);
-		if (--refcnt == 0)
-			reclaim_me();
-	}
-
-	//In theory, virt_offset() should be implemented as virtual function.
-	//However, it is actually one helper for fast path, so move it to
-	//parent class, and use base flag to return the proper return value.
-	u64 virt_offset() {
-		if (is_mapping_meta()) {
-			u64 base = ((u64)parent_idx) << (header.cluster_bits -
-					3 + header.cluster_bits);
-			u64 clusters = (get_offset() &
-				((1ULL << header.cluster_bits) - 1)) >> 3;
-
-			return base + (clusters << header.cluster_bits);
-		}
-
-		const u64 single_entry_order = 2 * header.cluster_bits +
-			3 - header.refcount_order;
-		u32 slice_idx = (get_offset() & ((1U << header.cluster_bits) - 1)) >>
-			QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;
-		u32 slice_virt_bits = header.cluster_bits + 3 -
-			header.refcount_order + QCOW2_PARA::REFCOUNT_BLK_SLICE_BITS;
-
-		return ((u64)parent_idx << single_entry_order) +
-			((u64)slice_idx << slice_virt_bits);
-	}
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	void io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe);
-#else
-	void io_done_validate(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe) {}
-#endif
-};
-
-class Qcow2RefcountBlock: public Qcow2SliceMeta {
-public:
-	unsigned dirty_start_idx;
-	u64  get_entry_fast(u32 idx) {
-		switch (header.refcount_order) {
-		case 0:
-		return (((const u8 *)addr)[idx / 8] >> (idx % 8)) & 0x1;
-
-		case 1:
-		return (((const u8 *)addr)[idx / 4] >> (2 * (idx % 4))) & 0x3;
-
-		case 2:
-		return (((const u8 *)addr)[idx / 2] >> (4 * (idx % 2))) & 0xf;
-
-		case 3:
-		return ((const u8 *)addr)[idx];
-
-		case 4:
-		return be16_to_cpu(((const u16 *)addr)[idx]);
-
-		case 5:
-		return be32_to_cpu(((const u32 *)addr)[idx]);
-
-		case 6:
-		return be64_to_cpu(((const u64 *)addr)[idx]);
-		}
-		return 0;
-	}
-
-	void set_entry_fast(u32 idx, u64 val) {
-		switch (header.refcount_order) {
-		case 0:
-			qcow2_assert(!(val >> 1));
-			((u8 *)addr)[idx / 8] &= ~(0x1 << (idx % 8));
-			((u8 *)addr)[idx / 8] |= val << (idx % 8);
-			break;
-		case 1:
-			qcow2_assert(!(val >> 2));
-			((u8 *)addr)[idx / 4] &= ~(0x3 << (2 * (idx % 4)));
-			((u8 *)addr)[idx / 4] |= val << (2 * (idx % 4));
-			break;
-		case 2:
-			qcow2_assert(!(val >> 4));
-			((u8 *)addr)[idx / 2] &= ~(0xf << (4 * (idx % 2)));
-			((u8 *)addr)[idx / 2] |= val << (4 * (idx % 2));
-			break;
-		case 3:
-			qcow2_assert(!(val >> 8));
-			((u8 *)addr)[idx] = val;
-			break;
-		case 4:
-			qcow2_assert(!(val >> 16));
-			((u16 *)addr)[idx] = cpu_to_be16(val);
-			break;
-		case 5:
-			qcow2_assert(!(val >> 32));
-			((u32 *)addr)[idx] = cpu_to_be32(val);
-			break;
-		case 6:
-			((u64 *)addr)[idx] = cpu_to_be64(val);
-			break;
-		}
-		set_dirty(idx, true);
-		if (dirty_start_idx == ((unsigned)-1))
-			dirty_start_idx = idx;
-	}
-
-	bool entry_is_dirty(u32 idx) {
-		return idx >= dirty_start_idx;
-	}
-
-	Qcow2RefcountBlock(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
-	void reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
-	virtual ~Qcow2RefcountBlock();
-	virtual u64  get_entry(u32 idx);
-	virtual void set_entry(u32 idx, u64 val);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len);
-	virtual void dump();
-	virtual void get_dirty_range(u64 *start, u64 *end);
-};
-
-//allocating detection needs to review!!!
-class Qcow2L2Table: public Qcow2SliceMeta {
-private:
-	//the two is valid only iff this slice is dirty
-	u64 dirty_start, dirty_end;
-public:
-	u64  get_entry_fast(u32 idx) {
-		u64 val = be64_to_cpu(((const u64 *)addr)[idx]);
-
-		return val;
-	}
-
-	u64  get_extended_entry(u32 idx) {
-		return 0;
-	}
-
-	void set_entry_fast(u32 idx, u64 val) {
-		((u64 *)addr)[idx] = cpu_to_be64(val);
-		set_dirty(idx, true);
-	}
-
-	bool entry_allocated(u64 entry) {
-		return entry != 0;
-	}
-
-	bool entry_is_dirty(u32 idx) {
-		return entry_val_is_dirty(get_entry(idx));
-	}
-
-	Qcow2L2Table(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
-	void reset(Qcow2State &qs, u64 off, u32 p_idx, u32 f);
-	virtual ~Qcow2L2Table();
-	virtual u64  get_entry(u32 idx);
-	virtual void set_entry(u32 idx, u64 val);
-	virtual int flush(Qcow2State &qs, const qcow2_io_ctx_t &ioc, u64 off,
-			u32 len);
-	virtual void dump();
-	virtual void get_dirty_range(u64 *start, u64 *end);
-	//virtual int flush(Qcow2State &qs, qcow2_io_ctx_t ioc, bool auto_free = false);
-	virtual void io_done(Qcow2State &qs, const struct ublksrv_queue *q,
-			const struct io_uring_cqe *cqe);
-#ifdef DEBUG_QCOW2_META_VALIDATE
-	void check(Qcow2State &qs, const char *func, int line);
-	void check_duplicated_clusters(Qcow2State &qs, int tag,
-			const char *func, int line);
-#else
-	void check(Qcow2State &qs, const char *func, int line) {}
-	void check_duplicated_clusters(Qcow2State &qs, int tag,
-			const char *func, int line) {}
-#endif
-};
-
-#endif
diff --git a/qcow2/qemu_dep.h b/qcow2/qemu_dep.h
deleted file mode 100644
index d5fa0e9..0000000
--- a/qcow2/qemu_dep.h
+++ /dev/null
@@ -1,27 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#ifndef QEMU_DEP_H 
-#define QEMU_DEP_H
-
-#include <stdint.h>
-
-#define	 u64	uint64_t
-#define	 u32	uint32_t
-#define	 u16	uint16_t
-#define	 u8	uint8_t
-
-#define	 s64	int64_t
-#define	 s32	int32_t
-#define	 s16	int16_t
-#define	 s8	int8_t
-
-#define MiB (1U << 20)
-
-#define QEMU_PACKED __attribute__((packed))
-
-#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
-#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)
-#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)
-
-#include "ublksrv_tgt_endian.h"
-
-#endif
diff --git a/qcow2/tgt_qcow2.cpp b/qcow2/tgt_qcow2.cpp
deleted file mode 100644
index c8c8ece..0000000
--- a/qcow2/tgt_qcow2.cpp
+++ /dev/null
@@ -1,556 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#include "ublksrv_tgt.h"
-#include "qcow2_format.h"
-#include "qcow2.h"
-
-#define HEADER_SIZE  512
-#define QCOW2_UNMAPPED   (u64)(-1)
-
-static int qcow2_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
-		*argv[])
-{
-	struct ublksrv_tgt_info *tgt = &dev->tgt;
-	const struct ublksrv_ctrl_dev_info *info =
-		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
-	static const struct option lo_longopts[] = {
-		{ "file",		1,	NULL, 'f' },
-		{ NULL }
-	};
-	int jbuf_size;
-	char *jbuf;
-	int fd, opt, ret;
-	void *header_buf;
-	QCowHeader *header;
-	char *file = NULL;
-	struct ublksrv_tgt_base_json tgt_json = {
-		.type = type,
-	};
-	struct ublk_params p = {
-		.types = UBLK_PARAM_TYPE_BASIC,
-		.basic = {
-			//.attrs = UBLK_ATTR_READ_ONLY,
-			.logical_bs_shift	= 9,
-			.physical_bs_shift	= 12,
-			.io_opt_shift	= 12,
-			.io_min_shift	= 9,
-			.max_sectors		= info->max_io_buf_bytes >> 9,
-		},
-	};
-	Qcow2State *qs;
-
-	/* qcow2 doesn't support user copy yet */
-	if (info->flags & UBLK_F_USER_COPY)
-		return -EINVAL;
-
-	//1024 queue depth is enough for qcow2, then we can store
-	//tag & l1 entry index in single u32 variable.
-	if (info->queue_depth > QCOW2_MAX_QUEUE_DEPTH)
-		return -EINVAL;
-
-	//qcow2 target doesn't support MQ yet
-	if (info->nr_hw_queues > 1)
-		return -EINVAL;
-
-	strcpy(tgt_json.name, "qcow2");
-
-	if (type != UBLKSRV_TGT_TYPE_QCOW2)
-		return -EINVAL;
-
-	while ((opt = getopt_long(argc, argv, "-:f:",
-				  lo_longopts, NULL)) != -1) {
-		switch (opt) {
-		case 'f':
-			file = strdup(optarg);
-			break;
-		}
-	}
-
-	if (!file)
-		return -EINVAL;
-
-	if (posix_memalign((void **)&header_buf, 512, HEADER_SIZE))
-		return -EINVAL;
-
-	header = (QCowHeader *)header_buf;
-	fd = open(file, O_RDWR);
-	if (fd < 0) {
-		ublk_err( "%s backing file %s can't be opened\n",
-				__func__, file);
-		return -EINVAL;
-	}
-
-	if (fcntl(fd, F_SETFL, O_DIRECT))
-		ublk_err( "%s direct io on file %s isn't supported\n",
-				__func__, file);
-
-	ret = read(fd, header_buf, HEADER_SIZE);
-	if (ret != HEADER_SIZE) {
-		ublk_err( "%s: return backing file %s %d %d\n",
-				__func__, file, HEADER_SIZE, ret);
-		return -EINVAL;
-	}
-
-	if (be64_to_cpu(header->nb_snapshots) != 0) {
-		ublk_err( "%s: not support snapshots\n", __func__);
-		return -EINVAL;
-	}
-
-	tgt_json.dev_size = tgt->dev_size = be64_to_cpu(header->size);
-	p.basic.dev_sectors = tgt->dev_size >> 9,
-	p.basic.chunk_sectors = 1 << (be32_to_cpu(header->cluster_bits) - 9);
-	tgt->tgt_ring_depth = info->queue_depth * 4;
-	tgt->extra_ios = QCOW2_PARA::META_MAX_TAGS;
-	tgt->iowq_max_workers[0] = 1;
-	tgt->nr_fds = 1;
-	tgt->fds[1] = fd;
-	tgt->tgt_data = qs = make_qcow2state(file, dev);
-	ublksrv_tgt_set_io_data_size(tgt);
-
-	jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
-	ublk_json_write_dev_info(dev, &jbuf, &jbuf_size);
-	ublk_json_write_target_base(dev, &jbuf, &jbuf_size, &tgt_json);
-
-	ublk_json_write_params(dev, &jbuf, &jbuf_size, &p);
-
-	ublk_json_write_tgt_str(dev, &jbuf, &jbuf_size,
-			"backing_file", file);
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-		"version", qs->header.get_version());
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-		"cluster_bits", qs->header.get_cluster_bits());
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-		"header_length", qs->header.get_header_length());
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-		"l1_size", qs->header.get_l1_size());
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-		"refcount_table_clusters",
-		qs->header.get_refcount_table_clusters());
-	ublk_json_write_tgt_ulong(dev, &jbuf, &jbuf_size,
-			"refcount_order", qs->header.get_refcount_order());
-
-	qs->header.dump_ext();
-
-	return 0;
-}
-
-static int qcow2_recovery_tgt(struct ublksrv_dev *dev, int type)
-{
-	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
-	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);
-	const struct ublksrv_ctrl_dev_info *info =
-		ublksrv_ctrl_get_dev_info(cdev);
-	struct ublksrv_tgt_info *tgt = &dev->tgt;
-	int fd, ret;
-	char file[PATH_MAX];
-	struct ublk_params p;
-	int tgt_depth;
-
-	ublk_assert(jbuf);
-	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);
-	ublk_assert(type == UBLKSRV_TGT_TYPE_QCOW2);
-
-	/* qcow2 doesn't support user copy yet */
-	if (info->flags & UBLK_F_USER_COPY)
-		return -EINVAL;
-
-	ret = ublksrv_json_read_target_str_info(jbuf, PATH_MAX, "backing_file", file);
-	if (ret < 0) {
-		ublk_err( "%s: backing file can't be retrieved from jbuf %d\n",
-				__func__, ret);
-		return ret;
-	}
-
-	ret = ublksrv_json_read_params(&p, jbuf);
-	if (ret) {
-		ublk_err( "%s: read ublk params failed %d\n",
-				__func__, ret);
-		return ret;
-	}
-
-	fd = open(file, O_RDWR);
-	if (fd < 0) {
-		ublk_err( "%s: backing file %s can't be opened\n",
-				__func__, file);
-		return fd;
-	}
-	if (fcntl(fd, F_SETFL, O_DIRECT))
-		ublk_err( "%s direct io on file %s isn't supported\n",
-				__func__, file);
-
-	tgt_depth = QCOW2_PARA::META_MAX_TAGS > info->queue_depth * 2 ?
-			QCOW2_PARA::META_MAX_TAGS : info->queue_depth * 2;
-	tgt->dev_size = p.basic.dev_sectors << 9;
-	tgt->extra_ios = QCOW2_PARA::META_MAX_TAGS;
-	tgt->tgt_ring_depth = tgt_depth;
-	tgt->iowq_max_workers[0] = 1;
-	tgt->nr_fds = 1;
-	tgt->fds[1] = fd;
-	tgt->tgt_data = make_qcow2state(file, dev);
-	ublksrv_tgt_set_io_data_size(tgt);
-
-	return 0;
-}
-
-static void qcow2_usage_for_add(void)
-{
-	printf("           qcow2: -f backing_file\n");
-}
-
-/* todo: flush meta dirty data */
-static inline int qcow2_queue_tgt_fsync(const struct ublksrv_queue *q,
-		unsigned io_op, int tag, u32 len, u64 offset)
-{
-	int fd = q->dev->tgt.fds[1];
-	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
-
-	if (!sqe) {
-		ublk_err("%s: tag %d offset %lx op %d, no sqe\n",
-				__func__, tag, offset, io_op);
-		return -ENOMEM;
-	}
-
-	io_uring_prep_sync_file_range(sqe, fd, len ,offset,
-			IORING_FSYNC_DATASYNC);
-	sqe->user_data = build_user_data(tag, io_op, 0, 1);
-	qcow2_io_log("%s: queue io op %d(%llu %llx %llx)"
-				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
-			__func__, io_op, sqe->off, sqe->len, sqe->addr,
-			q->q_id, tag, io_op, 1, sqe->user_data);
-	return 1;
-}
-
-static inline int qcow2_queue_tgt_zero_cluster(const Qcow2State *qs,
-		const struct ublksrv_queue *q, int tag, u64 offset)
-{
-	int mode = FALLOC_FL_ZERO_RANGE;
-	int fd = q->dev->tgt.fds[1];
-	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
-
-	if (!sqe) {
-		ublk_err("%s: tag %d offset %lx op %d, no sqe for zeroing\n",
-			__func__, tag, offset, IORING_OP_FALLOCATE);
-		return -ENOMEM;
-	}
-
-	io_uring_prep_fallocate(sqe, fd, mode, offset,
-			(1ULL << qs->header.cluster_bits));
-	sqe->user_data = build_user_data(tag,
-			IORING_OP_FALLOCATE, 0, 1);
-	qcow2_io_log("%s: queue io op %d(%llx %llx %llx)"
-				" (qid %d tag %u, target: %d, user_data %llx)\n",
-			__func__, IORING_OP_FALLOCATE, offset,
-			sqe->len, sqe->addr, q->q_id, tag, 1, sqe->user_data);
-	return 1;
-}
-
-static inline int qcow2_queue_tgt_rw_fast(const struct ublksrv_queue *q,
-		unsigned io_op, int tag, u64 offset,
-		const struct ublksrv_io_desc *iod)
-{
-	struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
-
-	if (!sqe) {
-		ublk_err("%s: tag %d offset %lx op %d, no sqe for rw\n",
-				__func__, tag, offset, io_op);
-		return -ENOMEM;
-	}
-
-	io_uring_prep_rw(io_op, sqe, 1, (void *)iod->addr,
-			iod->nr_sectors << 9, offset);
-	sqe->flags = IOSQE_FIXED_FILE;
-	sqe->user_data = build_user_data(tag, io_op, 0, 1);
-	qcow2_io_log("%s: queue io op %d(%llu %llx %llx)"
-				" (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
-			__func__, io_op, sqe->off, sqe->len, sqe->addr,
-			q->q_id, tag, io_op, 1, sqe->user_data);
-
-	return 1;
-
-}
-
-static inline int qcow2_queue_tgt_rw(const struct ublksrv_queue *q, unsigned io_op,
-		int tag, u64 offset, const struct ublksrv_io_desc *iod,
-		u32 *expected_op)
-{
-	Qcow2State *qs = queue_to_qcow2state(q);
-	u64 cluster_start = offset & ~((1ULL << qs->header.cluster_bits) - 1);
-	Qcow2ClusterState *cs = qs->cluster_allocator.
-		get_cluster_state(cluster_start);
-	u8 cs_state = (cs == nullptr ? QCOW2_ALLOC_DONE : cs->get_state());
-
-	if (cs_state >= QCOW2_ALLOC_ZEROED) {
-		*expected_op = io_op;
-		return qcow2_queue_tgt_rw_fast(q, io_op, tag, offset, iod);
-	}
-
-	if (io_op == IORING_OP_WRITE) {
-		if (cs_state == QCOW2_ALLOC_ZEROING) {
-			cs->add_waiter(tag);
-			throw MetaUpdateException();
-		}
-
-		if (cs_state == QCOW2_ALLOC_STARTED) {
-			int ret = qcow2_queue_tgt_zero_cluster(qs, q, tag,
-					cluster_start);
-			if (ret >= 0)
-				cs->set_state(QCOW2_ALLOC_ZEROING);
-			*expected_op = IORING_OP_FALLOCATE;
-			return ret;
-		}
-		return 0;
-	} else {
-		memset((void *)iod->addr, 0,
-				iod->nr_sectors << 9);
-		return 0;
-	}
-}
-
-/* return how many sqes queued */
-static int qcow2_queue_tgt_io(const struct ublksrv_queue *q, unsigned io_op,
-		int tag, u64 offset, u32 *exp_op,
-		const struct ublksrv_io_desc *iod)
-{
-	int ret;
-
-	//we don't support discard yet
-	if (io_op == IORING_OP_FALLOCATE)
-		return -ENOTSUP;
-
-	if (io_op == IORING_OP_FSYNC) {
-		ret = qcow2_queue_tgt_fsync(q, io_op, tag,
-				iod->nr_sectors << 9, offset);
-		*exp_op = io_op;
-	} else
-		ret = qcow2_queue_tgt_rw(q, io_op, tag, offset, iod, exp_op);
-
-	return ret;
-}
-
-static inline bool l2_entry_read_as_zero(u64 entry)
-{
-	if (!entry || (entry & 0x1))
-		return true;
-	return false;
-}
-
-static co_io_job __qcow2_handle_io_async(const struct ublksrv_queue *q,
-		const struct ublk_io_data *data, int tag)
-{
-	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
-	Qcow2State *qs = queue_to_qcow2state(q);
-	const struct ublksrv_io_desc *iod = data->iod;
-	unsigned long start = iod->start_sector << 9;
-	u64 mapped_start;
-	qcow2_io_ctx_t ioc(tag, q->q_id);
-	const struct io_uring_cqe *cqe;
-	int ret = 0;
-	unsigned int op = ublksrv_get_op(iod);
-	bool wait;
-
-	qcow2_io_log("%s: tag %d, ublk op %x virt %llx/%u\n",
-			__func__, tag, op, start, (iod->nr_sectors << 9));
-
-	qcow2_assert((start + (unsigned long)(iod->nr_sectors << 9)) <=
-			qs->get_dev_size());
-again:
-	try {
-		mapped_start = qs->cluster_map.map_cluster(ioc, start,
-				op == UBLK_IO_OP_WRITE);
-		wait = false;
-	} catch (MetaIoException &meta_error) {
-		wait = true;
-	} catch (MetaUpdateException &meta_update_error) {
-		wait = true;
-	}
-
-	if (wait) {
-		co_await__suspend_always(tag);
-
-		cqe = io->tgt_io_cqe;
-		io->tgt_io_cqe = NULL;
-		ret = qcow2_meta_io_done(q, cqe);
-		if (ret == -EAGAIN)
-			goto again;
-		if (ret < 0)
-			goto exit;
-	}
-
-	qcow2_io_log("%s: tag %d, ublk op %x virt %llx/%u to host %llx\n",
-			__func__, tag, op, start, (iod->nr_sectors << 9),
-			mapped_start);
-
-	if (mapped_start == -1) {
-		ublk_err("%s: tag %d virt %lx op %d, unsupported format\n",
-				__func__, tag, start, op);
-		ret = -EIO;
-	} else if (!mapped_start) {
-		// write to unallocated cluster, so have to allocate first
-		if ((op == UBLK_IO_OP_READ) &&
-			l2_entry_read_as_zero(mapped_start)) {
-			ret = iod->nr_sectors << 9;
-			memset((void *)iod->addr, 0, ret);
-		} else {
-			ublk_err("%s: tag %d virt %lx op %d map failed\n",
-					__func__, tag, start, op);
-			ret = -EIO;
-		}
-	} else {
-		unsigned io_op = ublksrv_convert_cmd_op(iod);
-		unsigned exp_op;
-
-		mapped_start &= ((1ULL << 63) - 1);
-
-		qcow2_assert(mapped_start + (iod->nr_sectors << 9) <=
-				qs->cluster_allocator.max_physical_size);
-queue_io:
-		//the only exception is from handling zeroing cluster
-		try {
-			ret = qcow2_queue_tgt_io(q, io_op, tag, mapped_start,
-					&exp_op, iod);
-			wait = false;
-		} catch (MetaUpdateException &meta_error) {
-			wait = true;
-		}
-
-		if (wait) {
-			co_await__suspend_always(tag);
-			goto queue_io;
-		}
-
-		if (ret > 0) {
-			u64 cluster_start = mapped_start &
-				~((1ULL << qs->header.cluster_bits) - 1);
-
-			co_await__suspend_always(tag);
-			cqe = io->tgt_io_cqe;
-			ret = cqe->res;
-			if (ret == -EAGAIN) {
-				qcow2_log("%s zeroing cluster IO eagain\n",
-							__func__);
-				//submit this write IO again
-				if (user_data_to_op(cqe->user_data) == io_op)
-					goto queue_io;
-
-				//if the cluster zeroing IO isn't done, retry
-				if (qs->cluster_allocator.
-				    alloc_cluster_reset(cluster_start))
-					goto queue_io;
-			}
-
-			qcow2_io_log("%s: io done, tag %d res %d user_data %llx\n",
-							__func__, tag, ret,
-							cqe->user_data);
-			if (exp_op != io_op) {
-				if (user_data_to_op(cqe->user_data) == IORING_OP_FALLOCATE)
-					qs->cluster_allocator.alloc_cluster_zeroed(q,
-						tag, cluster_start);
-				goto queue_io;
-			}
-		} else if (ret == 0) {
-			ret = iod->nr_sectors << 9;
-		}
-	}
-exit:
-	if (ret < 0)
-		ublk_err("%s io failed(%d %lx %u) ret %d\n", __func__,
-				op, start, iod->nr_sectors, ret);
-	qcow2_io_log("%s tag %d io complete(%d %llx %lu) ret %d\n", __func__,
-				tag, op, start, iod->nr_sectors, ret);
-	ublksrv_complete_io(q, tag, ret);
-}
-
-static int qcow2_handle_io_async(const struct ublksrv_queue *q,
-		const struct ublk_io_data *data)
-{
-	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
-
-	io->co = __qcow2_handle_io_async(q, data, data->tag);
-	return 0;
-}
-
-static void qcow2_deinit_tgt(const struct ublksrv_dev *dev)
-{
-	Qcow2State *qs = dev_to_qcow2state(dev);
-
-	//now all io slots are available, just use the zero tag
-	qcow2_io_ctx_t ioc(0, 0);
-
-	qs->dump_meta();
-
-	delete qs;
-}
-
-static void qcow2_tgt_io_done(const struct ublksrv_queue *q,
-		const struct ublk_io_data *data, const struct io_uring_cqe *cqe)
-{
-	unsigned tag = user_data_to_tag(cqe->user_data);
-
-	qcow2_io_log("%s: res %d qid %u tag %u, cmd_op %u\n",
-			__func__, cqe->res, q->q_id,
-			user_data_to_tag(cqe->user_data),
-			user_data_to_op(cqe->user_data));
-	//special tag is ignored, so far it is used in sending
-	//fsync during flushing meta
-	if (tag != 0xffff) {
-		struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
-		io->tgt_io_cqe = cqe;
-		io->co.resume();
-	}
-}
-
-static void qcow2_handle_io_bg(const struct ublksrv_queue *q, int nr_queued_io)
-{
-	Qcow2State *qs = queue_to_qcow2state(q);
-
-	ublk_dbg(UBLK_DBG_QCOW2_FLUSH | UBLK_DBG_QCOW2_META,
-			"%s %d, queued io %d\n", __func__, __LINE__, nr_queued_io);
-	qs->kill_slices(q);
-again:
-	qs->meta_flushing.run_flush(q, nr_queued_io);
-
-	if (!nr_queued_io && !qs->meta_flushing.is_flushing()) {
-		if (qs->has_dirty_slice())
-			goto again;
-	}
-}
-
-static void qcow2_idle(const struct ublksrv_queue *q, bool enter)
-{
-	Qcow2State *qs = queue_to_qcow2state(q);
-
-	if (!enter)
-		return;
-
-	qs->shrink_cache();
-}
-
-static int qcow2_init_queue(const struct ublksrv_queue *q,
-		void **queue_data_ptr)
-{
-	Qcow2State *qs = dev_to_qcow2state(q->dev);
-
-	*queue_data_ptr = (void *)qs;
-
-	return 0;
-}
-
-struct ublksrv_tgt_type  qcow2_tgt_type = {
-	.handle_io_async = qcow2_handle_io_async,
-	.tgt_io_done = qcow2_tgt_io_done,
-	.handle_io_background = qcow2_handle_io_bg,
-	.usage_for_add	=  qcow2_usage_for_add,
-	.init_tgt = qcow2_init_tgt,
-	.deinit_tgt	=  qcow2_deinit_tgt,
-	.idle_fn	=  qcow2_idle,
-	.type	= UBLKSRV_TGT_TYPE_QCOW2,
-	.name	=  "qcow2",
-	.recovery_tgt = qcow2_recovery_tgt,
-	.init_queue = qcow2_init_queue,
-};
-
-static void tgt_qcow2_init() __attribute__((constructor));
-
-static void tgt_qcow2_init(void)
-{
-	ublksrv_register_tgt_type(&qcow2_tgt_type);
-}
diff --git a/qcow2/utils.cpp b/qcow2/utils.cpp
deleted file mode 100644
index 8ae7545..0000000
--- a/qcow2/utils.cpp
+++ /dev/null
@@ -1,80 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0
-#include <cassert>
-
-#include "qcow2.h"
-#include "ublksrv_tgt.h"
-
-IOWaiters::IOWaiters(): io_waiters({})
-{
-}
-
-void IOWaiters::add_waiter(unsigned tag) {
-	__mapping_meta_add_waiter(tag, 0x3fffff);
-}
-
-/* The caller is waiting on the specified entry update */
-void IOWaiters::add_waiter_idx(unsigned tag, unsigned entry_idx) {
-	__mapping_meta_add_waiter(tag, entry_idx);
-}
-
-/*
- * For wakeup other IOs waiting for this meta.
- *
- * qcow2_tgt_io_done() will wakeup for current IO, that isn't covered
- * by here.
- */
-void IOWaiters::__mapping_meta_wakeup_all(const struct ublksrv_queue *q,
-		unsigned my_tag, unsigned entry_idx, bool all) {
-	std::unordered_set<unsigned> tags(move(io_waiters));
-	std::unordered_set<unsigned>::const_iterator it = tags.cbegin();
-
-	ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d enter\n",
-			__func__, __LINE__, this, my_tag);
-	while (it != tags.cend()) {
-		unsigned t = *it;
-		unsigned tag = t & (QCOW2_MAX_QUEUE_DEPTH - 1);
-		unsigned idx = t >> QCOW2_TAG_BITS;
-
-		/* can't wakeup me */
-		if (tag == my_tag) {
-			it = tags.erase(it);
-			continue;
-		}
-
-		ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d my tag %d tag %d idx %x\n",
-				__func__, __LINE__, my_tag, tag, idx);
-		if (all || idx == entry_idx) {
-			struct ublk_io_tgt *__io =
-				ublk_get_io_tgt_data(q, tag);
-
-			it = tags.erase(it);
-			__io->tgt_io_cqe = NULL;
-
-			try {
-				((struct ublk_io_tgt *)__io)->co.resume();
-			} catch (MetaIoException &meta_error) {
-				io_waiters.merge(tags);
-				throw MetaIoException();
-			} catch (MetaUpdateException &meta_update_error) {
-				io_waiters.merge(tags);
-				throw MetaUpdateException();
-			}
-		} else {
-			it++;
-		}
-		ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d tag %d idx %x\n",
-				__func__, __LINE__, this, my_tag, tag, idx);
-	}
-	io_waiters.merge(tags);
-	ublk_dbg(UBLK_DBG_QCOW2_IO_WAITER, "%s: %d %p my tag %d exit\n",
-			__func__, __LINE__, this, my_tag);
-}
-
-void IOWaiters::wakeup_all(const struct ublksrv_queue *q, unsigned my_tag) {
-	__mapping_meta_wakeup_all(q, my_tag, 0x3fffff, true);
-}
-
-void IOWaiters::wakeup_all_idx(const struct ublksrv_queue *q, unsigned my_tag,
-		unsigned entry_idx) {
-	__mapping_meta_wakeup_all(q, my_tag, entry_idx, false);
-}
diff --git a/tests/common/fio_common b/tests/common/fio_common
index 259681c..57a4221 100755
--- a/tests/common/fio_common
+++ b/tests/common/fio_common
@@ -240,7 +240,11 @@ __create_ublk_dev()
 	[ ${id} == "-" ] && echo "no free ublk device nodes" && exit -1
 	eval $UBLK add ${T_TYPE_PARAMS} -n $id > /dev/null 2>&1
 	udevadm settle
-	echo "/dev/ublkb${id}"
+	if [ -b /dev/ublkb0 ]; then
+		echo "/dev/ublkb${id}"
+	else
+		echo "/dev/ublkb-unknown"
+	fi
 }
 
 __recover_ublk_dev()
diff --git a/tests/common/nbd_common b/tests/common/nbd_common
index ab4eda5..aabccc9 100755
--- a/tests/common/nbd_common
+++ b/tests/common/nbd_common
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 export NBDSRV=127.0.0.1
 export NBD_SIZE=2G
diff --git a/tests/common/qcow2_common b/tests/common/qcow2_common
deleted file mode 100755
index 9c4b340..0000000
--- a/tests/common/qcow2_common
+++ /dev/null
@@ -1,77 +0,0 @@
-# SPDX-License-Identifier: GPL-2.0
-#!/bin/bash
-
-export QCOW2_IMG_SZ=2G
-
-_create_qcow2_null_image() {
-	local type=$1
-	local size=$2
-	local my_file=`mktemp -p ${UBLK_TMP_DIR}  ublk_${type}_${size}_XXXXX.qcow2`
-	qemu-img create -f qcow2 $my_file $size  > /dev/null 2>&1
-	echo $my_file
-}
-
-_qcow2_image_alloc_data() {
-	local my_dev=`__create_nbd_dev "$1"`
-	local my_size=`blockdev --getsz $my_dev`
-	local my_count=`expr ${my_size} / 2048`
-
-	dd if=/dev/zero of=$my_dev bs=1M count=${my_count} oflag=direct > /dev/null 2>&1
-	__remove_nbd_dev $my_dev
-}
-
-_create_qcow2_image() {
-	local type=$1
-	local size=$2
-
-	local file=`_create_qcow2_null_image $type $size`
-	if [ "$type" == "data" ]; then
-		local nbd_params="-c /dev/nbd11 -n --aio=native $file"
-		_qcow2_image_alloc_data "$nbd_params"
-	fi
-	echo $file
-}
-
-_check_qcow2_image() {
-	local my_file=$1
-	qemu-img check -r leaks $my_file > ${UBLK_TMP} 2>&1
-	[ $? -ne 0 ] && echo "qcow2 image $my_file is broken" && cat ${UBLK_TMP} && exit
-}
-
-_remove_qcow2_image() {
-	local file=$1
-
-	if [ -f "$file" ]; then
-		_check_qcow2_image $file
-		rm -f $file
-	fi
-}
-
-
-__remove_nbd_dev() {
-	local DEV=$1
-	sync $DEV
-	qemu-nbd -d $DEV  > /dev/null 2>&1
-	udevadm settle
-}
-
-__create_nbd_dev() {
-	local nbd_params="$1"
-	local DEV=`echo ${nbd_params} | awk '{ for(i=1; i<=NF; ++i) if (substr($i, 1, 8) == "/dev/nbd") printf $i}'`
-	modprobe nbd > /dev/null 2>&1
-	qemu-nbd -d $DEV > /dev/null 2>&1
-	eval qemu-nbd ${nbd_params} > /dev/null 2>&1
-	echo "$DEV"
-	udevadm settle
-}
-
-__run_nbd_dev_perf()
-{
-	local JOBS=$1
-	local DEV=`__create_nbd_dev "${T_TYPE_PARAMS}"`
-
-	echo -e "\t$T_TYPE $T_TYPE_PARAMS, fio($DEV, libaio, dio, io jobs $JOB)..."
-	__run_dev_perf_no_create "nbd" $JOBS $DEV
-
-	__remove_nbd_dev $DEV
-}
diff --git a/tests/debug/test_dev b/tests/debug/test_dev
index b1ed84d..b5c0ba6 100755
--- a/tests/debug/test_dev
+++ b/tests/debug/test_dev
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0-only
 #
 #usage:
 #	export UBLK_DBG_DEV=/dev/vdc; make test T=debug/test_dev
diff --git a/tests/generic/003 b/tests/generic/003
index 8fe0c70..f936c33 100755
--- a/tests/generic/003
+++ b/tests/generic/003
@@ -3,7 +3,6 @@
 
 . common/fio_common
 . common/loop_common
-. common/qcow2_common
 . common/nbd_common
 
 ublk_run_mount_test()
@@ -55,7 +54,7 @@ ublk_run_mount_type()
 
 MNT=`mktemp -d`
 
-for TYPE in "loop" "qcow2" "nbd"; do
+for TYPE in "loop" "nbd"; do
 	ublk_run_mount_type $TYPE $MNT
 done
 
diff --git a/tests/generic/005 b/tests/generic/005
index 162ef5b..bb4d5fe 100755
--- a/tests/generic/005
+++ b/tests/generic/005
@@ -3,7 +3,6 @@
 
 . common/fio_common
 . common/loop_common
-. common/qcow2_common
 . common/nbd_common
 
 echo -e "\trun fio with dev recovery, type 1:"
@@ -33,11 +32,7 @@ ublk_run_recover_test()
 		local backing="-f $file"
 	fi
 
-	if [ "$type" == "qcow2" ]; then
-		QUEUES=1
-	else
-		QUEUES=2
-	fi
+	QUEUES=2
 
 	for CNT in `seq $LOOPS`; do
 		export T_TYPE_PARAMS="-t $type -q $QUEUES -u $URING_COMP -g $NEED_GET_DATA -r $RECOVERY -i $RECOVERY_REISSUE $backing"
diff --git a/tests/generic/007 b/tests/generic/007
new file mode 100755
index 0000000..8e37040
--- /dev/null
+++ b/tests/generic/007
@@ -0,0 +1,163 @@
+#!/bin/bash
+# SPDX-License-Identifier: MIT or GPL-2.0-only
+
+. common/fio_common
+
+echo -e "\ttest nosrv (state after ublk server is killed) and recovery behavior"
+echo -e "\tfor all valid recovery options"
+echo
+
+DD_PID=0
+
+# submit an I/O async and store pid into DD_PID
+submit_io()
+{
+	dd if=$1 of=/dev/null iflag=direct count=1 bs=4k 2>/dev/null &
+	DD_PID=$!
+}
+
+# check the status of the I/O issued by DD_PID
+# 0 - I/O succeeded
+# 1 - I/O error
+# 2 - I/O queued
+check_io_status()
+{
+	sleep 1
+	# if process is still alive after 1 second, I/O is likely queued
+	if ps -p $DD_PID > /dev/null 2>/dev/null; then
+		return 2
+	else
+		if wait $DD_PID; then return 0; else return 1; fi
+	fi
+}
+
+del_dev()
+{
+	sleep 2
+	RES=`__remove_ublk_dev_return $1`
+	if [ $RES -ne 0 ]; then
+		echo -e "\t\tdelete $1 failed"
+		return 1
+	fi
+	wait
+	sleep 3
+}
+
+ublk_run_recovery_test()
+{
+	export T_TYPE_PARAMS="-t null -r $RECOVERY -i $RECOVERY_REISSUE -e $RECOVERY_FAIL_IO"
+	echo -e "\trunning with params: $T_TYPE_PARAMS"
+	DEV=`__create_ublk_dev`
+
+	echo -e "\t\tcheck behavior before nosrv - expect no error"
+	submit_io $DEV
+	check_io_status
+	RES=$?
+	if [ $RES -ne 0 ]; then
+		echo -e "\t\tI/O error while ublk server still up!"
+		return 1
+	fi
+
+	pid1=`__ublk_get_pid $DEV`
+	kill -9 $pid1
+	sleep 2
+	echo -ne "\t\tcheck behavior during nosrv - "
+	submit_io $DEV
+	check_io_status
+	RES=$?
+	if [ $RECOVERY_FAIL_IO -ne 0 ]; then
+		echo "expect I/O error"
+		if [ $RES -ne 1 ]; then
+			echo -e "\t\tincorrect nosrv behavior!"
+			echo -e "\t\texpected io error, got $RES"
+			return 1
+		fi
+	elif [ $RECOVERY -ne 0 ]; then
+		echo "expect I/O queued"
+		if [ $RES -ne 2 ]; then
+			echo -e "\t\tincorrect nosrv behavior!"
+			echo -e "\t\texpected queued io, got $RES"
+			return 1
+		fi
+	else
+		echo "expect I/O error" # because device should be gone
+		if [ $RES -ne 1 ]; then
+			echo -e "\t\tincorrect nosrv behavior!"
+			echo -e "\t\texpected io error, got $RES"
+			return 1
+		fi
+	fi
+
+	echo -e "\t\ttry to recover the device"
+	secs=0
+	while [ $secs -lt 10 ]; do
+		RES=`__recover_ublk_dev $DEV`
+		[ $RES -eq 0 ] && break
+		sleep 1
+		let secs++
+	done
+	if [ $RES -ne 0 ]; then
+		echo -e "\t\tfailed to recover device!"
+		if [ $RECOVERY -ne 0 ]; then
+			return 1
+		else
+			echo -e "\t\tforgiving expected recovery failure"
+			del_dev $DEV
+			echo
+			return 0
+		fi
+	else
+		if [ $RECOVERY -eq 0 ]; then
+			echo -e "\t\trecovery unexpectedly succeeded!"
+			return 1
+		fi
+	fi
+
+	# if I/O queued before, make sure it completes now
+	if [ $RECOVERY_FAIL_IO -eq 0 ] && [ $RECOVERY -ne 0 ]; then
+		echo -e "\t\tchecking that I/O completed after recovery"
+		check_io_status
+		RES=$?
+		if [ $RES -ne 0 ]; then
+			echo -e "\t\tpreviously queued I/O did not succeed!"
+			echo -e "\t\texpected success got $RES"
+			return 1
+		fi
+	fi
+
+	echo -e "\t\tcheck behavior after recovery - expect no error"
+	submit_io $DEV
+	check_io_status
+	RES=$?
+	if [ $RES -ne 0 ]; then
+		echo -e "\t\tI/O error after recovery!"
+		return 1
+	fi
+
+	# cleanup
+	pid2=`__ublk_get_pid $DEV`
+	kill -9 $pid2
+	del_dev $DEV
+
+	echo
+}
+
+RECOVERY=0
+RECOVERY_REISSUE=0
+RECOVERY_FAIL_IO=0
+ublk_run_recovery_test
+
+RECOVERY=1
+RECOVERY_REISSUE=0
+RECOVERY_FAIL_IO=0
+ublk_run_recovery_test
+
+RECOVERY=1
+RECOVERY_REISSUE=1
+RECOVERY_FAIL_IO=0
+ublk_run_recovery_test
+
+RECOVERY=1
+RECOVERY_REISSUE=0
+RECOVERY_FAIL_IO=1
+ublk_run_recovery_test
diff --git a/tests/nbd/001 b/tests/nbd/001
index 6768f6a..c1e6a47 100755
--- a/tests/nbd/001
+++ b/tests/nbd/001
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/002 b/tests/nbd/002
index aab4299..3bf2943 100755
--- a/tests/nbd/002
+++ b/tests/nbd/002
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/003 b/tests/nbd/003
index 338187b..f35412a 100755
--- a/tests/nbd/003
+++ b/tests/nbd/003
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/021 b/tests/nbd/021
index 2921bf9..af49106 100755
--- a/tests/nbd/021
+++ b/tests/nbd/021
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/022 b/tests/nbd/022
index 8ddd038..72d88ee 100755
--- a/tests/nbd/022
+++ b/tests/nbd/022
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/023 b/tests/nbd/023
index e37a010..eef0bd8 100755
--- a/tests/nbd/023
+++ b/tests/nbd/023
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/041 b/tests/nbd/041
index 5c49536..70c5653 100755
--- a/tests/nbd/041
+++ b/tests/nbd/041
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/042 b/tests/nbd/042
index b5f673b..c3d1c32 100755
--- a/tests/nbd/042
+++ b/tests/nbd/042
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/nbd/043 b/tests/nbd/043
index e463774..4608554 100755
--- a/tests/nbd/043
+++ b/tests/nbd/043
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0
 
 . common/fio_common
 . common/nbd_common
diff --git a/tests/qcow2/001 b/tests/qcow2/001
deleted file mode 100755
index 7367dc3..0000000
--- a/tests/qcow2/001
+++ /dev/null
@@ -1,16 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run perf test on empty qcow2 image via nbd"
-
-file=`_create_qcow2_image "null" $QCOW2_IMG_SZ`
-
-export T_TYPE="qemu-nbd"
-export T_TYPE_PARAMS="-c /dev/nbd11 -n --aio=native $file"
-
-__run_nbd_dev_perf 1
-
-_remove_qcow2_image $file
diff --git a/tests/qcow2/002 b/tests/qcow2/002
deleted file mode 100755
index 0e67a47..0000000
--- a/tests/qcow2/002
+++ /dev/null
@@ -1,16 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run perf test on pre-allocated qcow2 image via nbd"
-
-file=`_create_qcow2_image "data" $QCOW2_IMG_SZ`
-
-export T_TYPE="qemu-nbd"
-export T_TYPE_PARAMS="-c /dev/nbd11 -n --aio=native $file"
-
-__run_nbd_dev_perf 1
-
-_remove_qcow2_image $file
diff --git a/tests/qcow2/021 b/tests/qcow2/021
deleted file mode 100755
index d820fcf..0000000
--- a/tests/qcow2/021
+++ /dev/null
@@ -1,14 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run perf test on empty qcow2 image via ublk"
-
-file=`_create_qcow2_image "null" $QCOW2_IMG_SZ`
-export T_TYPE_PARAMS="-t qcow2 -q 1 -f $file"
-
-__run_dev_perf 1
-
-_remove_qcow2_image $file
diff --git a/tests/qcow2/022 b/tests/qcow2/022
deleted file mode 100755
index 972a985..0000000
--- a/tests/qcow2/022
+++ /dev/null
@@ -1,14 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run perf test on pre-allocated qcow2 image via ublk"
-
-file=`_create_qcow2_image "data" $QCOW2_IMG_SZ`
-export T_TYPE_PARAMS="-t qcow2 -q 1 -f $file"
-
-__run_dev_perf 1
-
-_remove_qcow2_image $file
diff --git a/tests/qcow2/040 b/tests/qcow2/040
deleted file mode 100755
index b7c879d..0000000
--- a/tests/qcow2/040
+++ /dev/null
@@ -1,53 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "check qcow2 image integrity after ubq_deamon is killed when running fio"
-
-BS=4k
-RW=rw
-JOBS=4
-QUEUES=1
-RT=$TRUNTIME
-LOOPS=4
-URING_COMP=1
-NEED_GET_DATA=1
-
-ublk_run_abort_test()
-{
-	for CNT in `seq $LOOPS`; do
-		export T_TYPE_PARAMS="-t qcow2 -q $QUEUES -u $URING_COMP -g $NEED_GET_DATA -f $file"
-		DEV=`__create_ublk_dev`
-		echo -e "\trun fio with killing $DEV(ublk add $T_TYPE_PARAMS) with check image integrity $CNT"
-		__run_fio_libaio $DEV $BS $RW $JOBS $RT > /dev/null 2 >& 1 &
-		sleep 2
-		queue_tid=`__ublk_get_queue_tid $DEV 0`
-		kill -9 $queue_tid
-		sleep 2
-		secs=0
-		while [ $secs -lt 10 ]; do
-			state=`__ublk_get_dev_state $DEV`
-			[ "$state" == "DEAD" ] && break
-			sleep 1
-			let secs++
-		done
-		[ "$state" != "DEAD" ] && echo "device isn't dead after killing queue daemon" && exit -1
-		RES=`__remove_ublk_dev_return $DEV`
-		if [ $RES -ne 0 ]; then
-				echo -e "\tdelete $DEV failed"
-				exit -1
-		fi
-		qemu-img check -r leaks $file > ${UBLK_TMP} 2>&1
-		RES=$?
-		wait
-		[ $RES -ne 0 ] && cat ${UBLK_TMP} && break
-	done
-}
-
-file=`_create_qcow2_image "null" 2G`
-
-ublk_run_abort_test
-
-_remove_qcow2_image $file
diff --git a/tests/qcow2/041 b/tests/qcow2/041
deleted file mode 100755
index 3edc08a..0000000
--- a/tests/qcow2/041
+++ /dev/null
@@ -1,40 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run fs randwrite with verify over ublk-qcow2"
-
-file=`_create_qcow2_image "null" $QCOW2_IMG_SZ`
-
-QUEUES=1
-URING_COMP=0
-NEED_GET_DATA=0
-
-export T_TYPE_PARAMS="-t qcow2 -q $QUEUES -u $URING_COMP -g $NEED_GET_DATA -f $file"
-echo -e "\trun fio(fs randwrite with verify) over ublk($T_TYPE_PARAMS)"
-
-DEV=`__create_ublk_dev`
-
-MNT=`mktemp -d`
-
-mkfs.xfs -f $DEV > /dev/null 2>&1
-mount $DEV $MNT > /dev/null 2>&1
-
-fio --size=128M --bsrange=4k-128k --runtime=20 --numjobs=12 --ioengine=libaio \
-	--iodepth=64 --iodepth_batch_submit=16 --iodepth_batch_complete_min=16 \
-	--directory=$MNT --group_reporting=1 --unlink=0 \
-	--direct=1 --fsync=0 --name=f1 --stonewall \
-	--overwrite=1 --rw=randwrite --verify=md5 > /dev/null 2>&1
-umount $MNT > /dev/null 2>&1
-
-RES=`__remove_ublk_dev_return $DEV`
-if [ $RES -ne 0 ]; then
-	echo -e "\tdelete ublk0 failed"
-	exit -1
-fi
-
-_remove_qcow2_image $file
-
-rm -fr $MNT
diff --git a/tests/qcow2/big_size_fs_io b/tests/qcow2/big_size_fs_io
deleted file mode 100755
index 7c736c0..0000000
--- a/tests/qcow2/big_size_fs_io
+++ /dev/null
@@ -1,41 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run fs randwrite with verify over ublk-qcow2"
-
-IMG_SIZE=64G
-file=`_create_qcow2_image "null" $IMG_SIZE`
-
-QUEUES=1
-URING_COMP=0
-NEED_GET_DATA=0
-
-export T_TYPE_PARAMS="-t qcow2 -q $QUEUES -u $URING_COMP -g $NEED_GET_DATA -f $file"
-echo -e "\trun fio(fs randwrite with verify) over ublk($T_TYPE_PARAMS)"
-
-DEV=`__create_ublk_dev`
-
-MNT=`mktemp -d`
-
-mkfs.xfs -f $DEV > /dev/null 2>&1
-mount $DEV $MNT > /dev/null 2>&1
-
-fio --size=8G --bsrange=4k-128k --runtime=20 --numjobs=12 --ioengine=libaio \
-	--iodepth=64 --iodepth_batch_submit=16 --iodepth_batch_complete_min=16 \
-	--directory=$MNT --group_reporting=1 --unlink=0 \
-	--direct=1 --fsync=0 --name=f1 --stonewall \
-	--overwrite=1 --rw=randwrite --verify=md5 > /dev/null 2>&1
-umount $MNT > /dev/null 2>&1
-
-RES=`__remove_ublk_dev_return $DEV`
-if [ $RES -ne 0 ]; then
-	echo -e "\tdelete ublk0 failed"
-	exit -1
-fi
-
-_remove_qcow2_image $file
-
-rm -fr $MNT
diff --git a/tests/qcow2/big_size_io b/tests/qcow2/big_size_io
deleted file mode 100755
index 0fca12a..0000000
--- a/tests/qcow2/big_size_io
+++ /dev/null
@@ -1,14 +0,0 @@
-#!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
-
-. common/fio_common
-. common/qcow2_common
-
-echo "run perf test on empty qcow2 image via ublk"
-
-file=`_create_qcow2_image "null" 64G`
-export T_TYPE_PARAMS="-t qcow2 -q 1 -f $file"
-
-__run_dev_perf 1
-
-_remove_qcow2_image $file
diff --git a/tests/run_test.sh b/tests/run_test.sh
index e054856..8774ada 100755
--- a/tests/run_test.sh
+++ b/tests/run_test.sh
@@ -80,7 +80,7 @@ if [ "${TDIR:0:1}" != "/" ]; then
 	TDIR=`dirname $PWD`/${TDIR}
 fi
 
-export ALL_TGTS="null loop qcow2 nbd"
+export ALL_TGTS="null loop nbd"
 export TRUNTIME=$2
 export UBLK_TMP_DIR=$TDIR
 export T_TYPE_PARAMS=""
diff --git a/tgt_loop.cpp b/tgt_loop.cpp
index e177da8..0f16676 100644
--- a/tgt_loop.cpp
+++ b/tgt_loop.cpp
@@ -94,12 +94,9 @@ static int loop_setup_tgt(struct ublksrv_dev *dev, int type, bool recovery,
 static int loop_recovery_tgt(struct ublksrv_dev *dev, int type)
 {
 	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
-	const struct ublksrv_ctrl_dev_info *info =
-		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
 	const char *jbuf = ublksrv_ctrl_get_recovery_jbuf(cdev);
 
 	ublk_assert(type == UBLKSRV_TGT_TYPE_LOOP);
-	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);
 
 	return loop_setup_tgt(dev, type, true, jbuf);
 }
@@ -306,6 +303,7 @@ static void loop_queue_tgt_write(const struct ublksrv_queue *q,
 			buf, iod->nr_sectors << 9,
 			iod->start_sector << 9);
 		io_uring_sqe_set_flags(sqe2, IOSQE_FIXED_FILE);
+		sqe2->rw_flags |= RWF_DSYNC;
 		/* bit63 marks us as tgt io */
 		sqe2->user_data = build_user_data(tag, ublk_op, 0, 1);
 	} else {
@@ -318,6 +316,7 @@ static void loop_queue_tgt_write(const struct ublksrv_queue *q,
 			iod->nr_sectors << 9,
 			iod->start_sector << 9);
 		io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
+		sqe->rw_flags |= RWF_DSYNC;
 		/* bit63 marks us as tgt io */
 		sqe->user_data = build_user_data(tag, ublk_op, 0, 1);
 	}
diff --git a/tgt_null.cpp b/tgt_null.cpp
index 0d93dae..261cfc6 100644
--- a/tgt_null.cpp
+++ b/tgt_null.cpp
@@ -33,6 +33,9 @@ static int null_init_tgt(struct ublksrv_dev *dev, int type, int argc,
 	if (type != UBLKSRV_TGT_TYPE_NULL)
 		return -1;
 
+	if (info->flags & UBLK_F_UNPRIVILEGED_DEV)
+		return -1;
+
 	tgt_json.dev_size = tgt->dev_size = dev_size;
 	tgt->tgt_ring_depth = info->queue_depth;
 	tgt->nr_fds = 0;
@@ -56,7 +59,6 @@ static int null_recovery_tgt(struct ublksrv_dev *dev, int type)
 	struct ublk_params p;
 
 	ublk_assert(jbuf);
-	ublk_assert(info->state == UBLK_S_DEV_QUIESCED);
 	ublk_assert(type == UBLKSRV_TGT_TYPE_NULL);
 
 	ret = ublksrv_json_read_params(&p, jbuf);
diff --git a/ublksrv_tgt.cpp b/ublksrv_tgt.cpp
index aaf0d25..10a5107 100644
--- a/ublksrv_tgt.cpp
+++ b/ublksrv_tgt.cpp
@@ -685,6 +685,7 @@ static int cmd_dev_add(int argc, char *argv[])
 		{ "uring_comp",		1,	NULL, 'u' },
 		{ "need_get_data",	1,	NULL, 'g' },
 		{ "user_recovery",	1,	NULL, 'r'},
+		{ "user_recovery_fail_io",	1,	NULL, 'e'},
 		{ "user_recovery_reissue",	1,	NULL, 'i'},
 		{ "debug_mask",	1,	NULL, 0},
 		{ "unprivileged",	0,	NULL, 0},
@@ -698,6 +699,7 @@ static int cmd_dev_add(int argc, char *argv[])
 	int uring_comp = 0;
 	int need_get_data = 0;
 	int user_recovery = 0;
+	int user_recovery_fail_io = 0;
 	int user_recovery_reissue = 0;
 	int unprivileged = 0;
 	const char *dump_buf;
@@ -711,7 +713,7 @@ static int cmd_dev_add(int argc, char *argv[])
 
 	mkpath(data.run_dir);
 
-	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:r:i:z",
+	while ((opt = getopt_long(argc, argv, "-:t:n:d:q:u:g:r:e:i:z",
 				  longopts, &option_index)) != -1) {
 		switch (opt) {
 		case 'n':
@@ -738,6 +740,9 @@ static int cmd_dev_add(int argc, char *argv[])
 		case 'r':
 			user_recovery = strtol(optarg, NULL, 10);
 			break;
+		case 'e':
+			user_recovery_fail_io = strtol(optarg, NULL, 10);
+			break;
 		case 'i':
 			user_recovery_reissue = strtol(optarg, NULL, 10);
 			break;
@@ -765,6 +770,8 @@ static int cmd_dev_add(int argc, char *argv[])
 		data.flags |= UBLK_F_NEED_GET_DATA;
 	if (user_recovery)
 		data.flags |= UBLK_F_USER_RECOVERY;
+	if (user_recovery_fail_io)
+		data.flags |= UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_FAIL_IO;
 	if (user_recovery_reissue)
 		data.flags |= UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE;
 	if (unprivileged)
@@ -789,7 +796,7 @@ static int cmd_dev_add(int argc, char *argv[])
 	dev = ublksrv_ctrl_init(&data);
 	if (!dev) {
 		fprintf(stderr, "can't init dev %d\n", data.dev_id);
-		return -ENODEV;
+		return -EOPNOTSUPP;
 	}
 
 	ret = ublksrv_ctrl_add_dev(dev);
@@ -871,8 +878,8 @@ static void cmd_dev_add_usage(const char *cmd)
 	printf("%s add -t %s\n", cmd, data.names);
 	printf("\t-n DEV_ID -q NR_HW_QUEUES -d QUEUE_DEPTH\n");
 	printf("\t-u URING_COMP -g NEED_GET_DATA -r USER_RECOVERY\n");
-	printf("\t-i USER_RECOVERY_REISSUE --debug_mask=0x{DBG_MASK}\n");
-	printf("\t--unprivileged\n\n");
+	printf("\t-i USER_RECOVERY_REISSUE -e USER_RECOVERY_FAIL_IO\n");
+	printf("\t--debug_mask=0x{DBG_MASK} --unprivileged\n\n");
 	printf("\ttarget specific command line:\n");
 	ublksrv_for_each_tgt_type(show_tgt_add_usage, NULL);
 }
@@ -887,6 +894,10 @@ static int __cmd_dev_del(int number, bool log, bool async)
 	};
 
 	dev = ublksrv_ctrl_init(&data);
+	if (!dev) {
+		fprintf(stderr, "ublksrv_ctrl_init failed id %d\n", number);
+		return -EOPNOTSUPP;
+	}
 
 	ret = ublksrv_ctrl_get_info(dev);
 	if (ret < 0) {
@@ -951,8 +962,11 @@ static int cmd_dev_del(int argc, char *argv[])
 	if (number >= 0)
 		return __cmd_dev_del(number, true, async);
 
-	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
+	for (i = 0; i < MAX_NR_UBLK_DEVS; i++) {
 		ret = __cmd_dev_del(i, false, async);
+		if (ret == -EOPNOTSUPP)
+			return ret;
+	}
 
 	return ret;
 }
@@ -971,6 +985,10 @@ static int list_one_dev(int number, bool log, bool verbose)
 	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
 	int ret;
 
+	if (!dev) {
+		fprintf(stderr, "ublksrv_ctrl_init failed id %d\n", number);
+		return -EOPNOTSUPP;
+	}
 	ret = ublksrv_ctrl_get_info(dev);
 	if (ret < 0) {
 		if (log)
@@ -1015,8 +1033,12 @@ static int cmd_list_dev_info(int argc, char *argv[])
 	if (number >= 0)
 		return list_one_dev(number, true, verbose);
 
-	for (i = 0; i < MAX_NR_UBLK_DEVS; i++)
-		list_one_dev(i, false, verbose);
+	for (i = 0; i < MAX_NR_UBLK_DEVS; i++) {
+		int ret = list_one_dev(i, false, verbose);
+
+		if (ret == -EOPNOTSUPP)
+			return ret;
+	}
 
 	return 0;
 }
@@ -1045,15 +1067,23 @@ static int cmd_dev_get_features(int argc, char *argv[])
 		[const_ilog2(UBLK_F_USER_RECOVERY_REISSUE)] = "RECOVERY_REISSUE",
 		[const_ilog2(UBLK_F_UNPRIVILEGED_DEV)] = "UNPRIVILEGED_DEV",
 		[const_ilog2(UBLK_F_CMD_IOCTL_ENCODE)] = "CMD_IOCTL_ENCODE",
+		[const_ilog2(UBLK_F_USER_COPY)] = "USER_COPY",
+		[const_ilog2(UBLK_F_ZONED)] = "ZONED",
+		[const_ilog2(UBLK_F_USER_RECOVERY_FAIL_IO)] = "RECOVERY_FAIL_IO",
 	};
 
+	if (!dev) {
+		fprintf(stderr, "ublksrv_ctrl_init failed id\n");
+		return -EOPNOTSUPP;
+	}
+
 	ret = ublksrv_ctrl_get_features(dev, &features);
 	if (!ret) {
 		int i;
 
 		printf("ublk_drv features: 0x%llx\n", features);
 
-		for (i = 0; i < sizeof(features); i++) {
+		for (i = 0; i < sizeof(features) * 8; i++) {
 			const char *feat;
 
 			if (!((1ULL << i)  & features))
@@ -1092,7 +1122,7 @@ static int __cmd_dev_user_recover(int number, bool verbose)
 	dev = ublksrv_ctrl_init(&data);
 	if (!dev) {
 		fprintf(stderr, "ublksrv_ctrl_init failure dev %d\n", number);
-		return -ENOMEM;
+		return -EOPNOTSUPP;
 	}
 
 	ret = ublksrv_ctrl_get_info(dev);
diff --git a/utils/genver.sh b/utils/genver.sh
index 50479df..acdf535 100755
--- a/utils/genver.sh
+++ b/utils/genver.sh
@@ -1,5 +1,5 @@
 #!/bin/sh
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0-only
 
 GITDESC=$(git describe --dirty|sed -e 's/^v//' 2>/dev/null)
 
diff --git a/utils/nop.c b/utils/nop.c
deleted file mode 100644
index 5515683..0000000
--- a/utils/nop.c
+++ /dev/null
@@ -1,65 +0,0 @@
-/* SPDX-License-Identifier: MIT */
-#include <errno.h>
-#include <stdio.h>
-#include <unistd.h>
-#include <stdlib.h>
-#include <string.h>
-#include <fcntl.h>
-#include <liburing.h>
-
-/* gcc -g -o nop nop.c -luring */
-
-/* test nop over uring and see io_uring is working */
-static int test_nop()
-{
-	struct io_uring _ring;
-	struct io_uring *ring = &_ring;
-	struct io_uring_params p = { };
-	int ret, i;
-	struct io_uring_cqe *cqe;
-	struct io_uring_sqe *sqe;
-
-	p.flags = IORING_SETUP_SQE128;
-	ret = io_uring_queue_init_params(64, ring, &p);
-	if (ret < 0) {
-		fprintf(stderr, "ring can't be setup %d\n", ret);
-		goto err;
-	}
-
-	ret = -EINVAL;
-	sqe = io_uring_get_sqe(ring);
-	if (!sqe) {
-		fprintf(stderr, "get sqe failed ret %d\n", ret);
-		return ret;
-	}
-
-	io_uring_prep_nop(sqe);
-	sqe->user_data = 1;
-	ret = io_uring_submit(ring);
-	if (ret <= 0) {
-		fprintf(stderr, "sqe submit failed: %d\n", ret);
-		goto err;
-	}
-
-	ret = io_uring_wait_cqe(ring, &cqe);
-	if (ret < 0) {
-		fprintf(stderr, "wait completion %d\n", ret);
-		goto err;
-	}
-	if (!cqe->user_data) {
-		fprintf(stderr, "Unexpected 0 user_data\n");
-		goto err;
-	}
-	io_uring_cqe_seen(ring, cqe);
-	fprintf(stdout, "nop over uring run successfully\n");
-err:
-	io_uring_queue_exit(ring);
-	return ret;
-}
-
-int main(int argc, char *argv[])
-{
-	test_nop();
-
-	return 0;
-}
diff --git a/utils/ublk_chown_docker.sh b/utils/ublk_chown_docker.sh
index a0e7841..68a2fd7 100755
--- a/utils/ublk_chown_docker.sh
+++ b/utils/ublk_chown_docker.sh
@@ -1,5 +1,5 @@
 #!/bin/bash
-# SPDX-License-Identifier: GPL-2.0
+# SPDX-License-Identifier: MIT or GPL-2.0-only
 
 ublk_docker_add()
 {
```

