```diff
diff --git a/Android.bp b/Android.bp
index 08dbeaf..0d758fd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,8 +44,8 @@ cc_defaults {
     cflags: [
         "-DF2FS_MAJOR_VERSION=1",
         "-DF2FS_MINOR_VERSION=16",
-        "-DF2FS_TOOLS_VERSION=\"1.16.0\"",
         "-DF2FS_TOOLS_DATE=\"2023-04-11\"",
+        "-DF2FS_TOOLS_VERSION=\"1.16.0\"",
         "-DWITH_ANDROID",
         "-D_FILE_OFFSET_BITS=64",
         "-Wall",
@@ -56,9 +56,9 @@ cc_defaults {
         "-Wno-sign-compare",
     ],
     local_include_dirs: [
+        "fsck",
         "include",
         "mkfs",
-        "fsck",
     ],
     target: {
         windows: {
@@ -72,10 +72,10 @@ cc_defaults {
     cflags: ["-DWITH_BLKDISCARD"],
     srcs: [
         "lib/libf2fs.c",
-        "mkfs/f2fs_format.c",
-        "mkfs/f2fs_format_utils.c",
         "lib/libf2fs_zoned.c",
         "lib/nls_utf8.c",
+        "mkfs/f2fs_format.c",
+        "mkfs/f2fs_format_utils.c",
     ],
     static_libs: [
         "libext2_uuid",
@@ -93,22 +93,22 @@ cc_defaults {
 cc_defaults {
     name: "fsck_main_src_files",
     srcs: [
-        "fsck/dir.c",
         "fsck/dict.c",
+        "fsck/dir.c",
+        "fsck/dump.c",
+        "fsck/main.c",
         "fsck/mkquota.c",
+        "fsck/mount.c",
+        "fsck/node.c",
         "fsck/quotaio.c",
         "fsck/quotaio_tree.c",
         "fsck/quotaio_v2.c",
-        "fsck/node.c",
         "fsck/segment.c",
         "fsck/xattr.c",
-        "fsck/main.c",
-        "fsck/mount.c",
         "lib/libf2fs.c",
         "lib/libf2fs_io.c",
         "lib/libf2fs_zoned.c",
         "lib/nls_utf8.c",
-        "fsck/dump.c",
     ],
 }
 
@@ -117,7 +117,7 @@ cc_library_static {
     recovery_available: true,
     defaults: [
         "f2fs-tools-defaults",
-        "libf2fs_src_files"
+        "libf2fs_src_files",
     ],
 }
 
@@ -125,17 +125,17 @@ cc_library_host_static {
     name: "libf2fs_fmt_host",
     defaults: [
         "f2fs-tools-defaults",
-        "libf2fs_src_files"
+        "libf2fs_src_files",
     ],
     target: {
         windows: {
-            include_dirs: [ "external/e2fsprogs/include/mingw" ],
+            include_dirs: ["external/e2fsprogs/include/mingw"],
             cflags: [
                 "-DANDROID_WINDOWS_HOST",
                 "-Wno-typedef-redefinition",
                 "-Wno-unused-parameter",
             ],
-            enabled: true
+            enabled: true,
         },
     },
 }
@@ -152,9 +152,9 @@ cc_defaults {
                 "libf2fs_fmt",
             ],
             shared_libs: [
+                "libbase",
                 "libext2_uuid",
                 "libsparse",
-                "libbase",
             ],
         },
     },
@@ -169,19 +169,19 @@ cc_defaults {
     target: {
         host: {
             static_libs: [
-                "libf2fs_fmt_host",
+                "libbase",
                 "libext2_uuid",
+                "libf2fs_fmt_host",
                 "libsparse",
-                "libbase",
                 "libz",
             ],
         },
         windows: {
-            include_dirs: [ "external/e2fsprogs/include/mingw" ],
+            include_dirs: ["external/e2fsprogs/include/mingw"],
             cflags: ["-DANDROID_WINDOWS_HOST"],
             ldflags: ["-static"],
             host_ldlibs: ["-lws2_32"],
-            enabled: true
+            enabled: true,
         },
     },
 }
@@ -191,6 +191,16 @@ cc_binary {
     defaults: [
         "make_f2fs_host_defaults",
     ],
+    target: {
+        host: {
+            dist: {
+                targets: [
+                    "dist_files",
+                    "sdk",
+                ],
+            },
+        },
+    },
 }
 
 cc_binary {
@@ -210,10 +220,22 @@ cc_binary_host {
     recovery_available: true,
     target: {
         host: {
-            cflags: ["-DCONF_CASEFOLD", "-DCONF_PROJID"],
+            cflags: [
+                "-DCONF_CASEFOLD",
+                "-DCONF_PROJID",
+            ],
+            dist: {
+                targets: [
+                    "dist_files",
+                    "sdk",
+                ],
+            },
         },
         windows: {
-            cflags: ["-DCONF_CASEFOLD", "-DCONF_PROJID"],
+            cflags: [
+                "-DCONF_CASEFOLD",
+                "-DCONF_PROJID",
+            ],
         },
     },
 }
@@ -234,22 +256,34 @@ cc_defaults {
         "f2fs-tools-defaults",
         "fsck_main_src_files",
     ],
-    cflags: ["-DWITH_RESIZE", "-DWITH_DEFRAG", "-DWITH_DUMP"],
-    srcs: ["fsck/fsck.c", "fsck/resize.c", "fsck/defrag.c"],
+    cflags: [
+        "-DWITH_DEFRAG",
+        "-DWITH_DUMP",
+        "-DWITH_RESIZE",
+    ],
+    srcs: [
+        "fsck/defrag.c",
+        "fsck/fsck.c",
+        "fsck/resize.c",
+    ],
 }
 
 cc_defaults {
     name: "fsck.f2fs_partition_common_defaults",
     defaults: [
         "f2fs-tools-defaults",
-        "fsck_main_src_files",
         "fsck.f2fs_defaults",
+        "fsck_main_src_files",
+    ],
+    symlinks: [
+        "defrag.f2fs",
+        "dump.f2fs",
+        "resize.f2fs",
     ],
-    symlinks: ["resize.f2fs", "defrag.f2fs", "dump.f2fs"],
     shared_libs: [
+        "libbase",
         "libext2_uuid",
         "libsparse",
-        "libbase",
     ],
     bootstrap: true,
 }
@@ -280,8 +314,8 @@ cc_binary {
     stem: "fsck.f2fs",
     defaults: [
         "f2fs-tools-defaults",
-        "fsck_main_src_files",
         "fsck.f2fs_defaults",
+        "fsck_main_src_files",
     ],
     static_executable: true,
     ramdisk: true,
@@ -301,21 +335,21 @@ cc_defaults {
     ],
     cflags: ["-DWITH_SLOAD"],
     srcs: [
+        "fsck/compress.c",
         "fsck/fsck.c",
         "fsck/sload.c",
-        "fsck/compress.c",
-        ],
+    ],
     target: {
         android: {
             shared_libs: [
-                "libext2_uuid",
-                "libsparse",
                 "libbase",
                 "libcrypto",
-                "libselinux",
                 "libcutils",
+                "libext2_uuid",
                 "liblog",
                 "liblz4",
+                "libselinux",
+                "libsparse",
             ],
         },
     },
@@ -330,15 +364,15 @@ cc_binary {
     target: {
         host: {
             static_libs: [
-                "libext2_uuid",
-                "libsparse",
                 "libbase",
                 "libcrypto",
-                "libselinux",
                 "libcutils",
+                "libext2_uuid",
                 "liblog",
-                "libz",
                 "liblz4",
+                "libselinux",
+                "libsparse",
+                "libz",
             ],
         },
     },
@@ -359,8 +393,8 @@ cc_binary {
     cflags: [
         "--static",
         "-U_FORTIFY_SOURCE",
-	"-Wall",
-	"-Werror",
+        "-Wall",
+        "-Werror",
     ],
     srcs: ["tools/check_f2fs.c"],
     product_specific: true,
@@ -369,8 +403,8 @@ cc_binary {
 cc_defaults {
     name: "tools-defaults",
     cflags: [
-	"-Wall",
-	"-Werror",
+        "-Wall",
+        "-Werror",
     ],
     local_include_dirs: [
         "include",
diff --git a/METADATA b/METADATA
index 79bcd6a..413e3d7 100644
--- a/METADATA
+++ b/METADATA
@@ -7,14 +7,14 @@ description: "F2FS filesystem tools"
 third_party {
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 13
+    year: 2025
+    month: 3
+    day: 20
   }
   homepage: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git/"
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git"
-    version: "ad3736cca5284ca1b1521e5826f81f496d86d0ff"
+    version: "33c5b9539af24468b4eb9493f7a9eb2ab7e98b64"
   }
 }
diff --git a/OWNERS b/OWNERS
index 6a5c011..3e6b112 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 jaegeuk@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/configure.ac b/configure.ac
index 2053a65..ddfc3b0 100644
--- a/configure.ac
+++ b/configure.ac
@@ -182,6 +182,7 @@ AC_TYPE_SIZE_T
 AC_FUNC_GETMNTENT
 AC_CHECK_FUNCS_ONCE([
 	add_key
+	clock_gettime
 	fallocate
 	fsetxattr
 	fstat
@@ -192,8 +193,9 @@ AC_CHECK_FUNCS_ONCE([
 	getuid
 	keyctl
 	memset
+	pread
+	pwrite
 	setmntent
-	clock_gettime
 ])
 
 AS_IF([test "$ac_cv_header_byteswap_h" = "yes"],
diff --git a/fsck/fsck.c b/fsck/fsck.c
index aa3fb97..8155cbd 100644
--- a/fsck/fsck.c
+++ b/fsck/fsck.c
@@ -942,6 +942,22 @@ check_next:
 		if (f2fs_test_main_bitmap(sbi, ni->blk_addr) == 0) {
 			f2fs_set_main_bitmap(sbi, ni->blk_addr,
 							CURSEG_WARM_NODE);
+
+			if (i_links == 0 && (ftype == F2FS_FT_CHRDEV ||
+				ftype == F2FS_FT_BLKDEV ||
+				ftype == F2FS_FT_FIFO ||
+				ftype == F2FS_FT_SOCK ||
+				ftype == F2FS_FT_SYMLINK ||
+				ftype == F2FS_FT_REG_FILE)) {
+				ASSERT_MSG("ino: 0x%x ftype: %d has i_links: %u",
+							nid, ftype, i_links);
+				if (c.fix_on) {
+					node_blk->i.i_links = cpu_to_le32(1);
+					need_fix = 1;
+					FIX_MSG("ino: 0x%x ftype: %d fix i_links: %u -> 1",
+						nid, ftype, i_links);
+				}
+			}
 			if (i_links > 1 && ftype != F2FS_FT_ORPHAN &&
 					!is_qf_ino(F2FS_RAW_SUPER(sbi), nid)) {
 				/* First time. Create new hard link node */
diff --git a/fsck/main.c b/fsck/main.c
index 25d50e2..47ba6c9 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -215,17 +215,22 @@ static void error_out(char *prog)
 		MSG(0, "\nWrong program.\n");
 }
 
-static void __add_fsck_options(void)
-{
-	/* -a */
-	c.auto_fix = 1;
-}
-
 static void add_default_options(void)
 {
 	switch (c.defset) {
 	case CONF_ANDROID:
-		__add_fsck_options();
+		if (c.func == FSCK) {
+			/* -a */
+			c.auto_fix = 1;
+		}
+
+		/*
+		 * global config for fsck family tools, including dump,
+		 * defrag, resize, sload, label and inject.
+		 */
+
+		/* disable nat_bits feature by default */
+		c.disabled_feature |= F2FS_FEATURE_NAT_BITS;
 	}
 	c.quota_fix = 1;
 }
diff --git a/fsck/mount.c b/fsck/mount.c
index a189ba7..0b05f00 100644
--- a/fsck/mount.c
+++ b/fsck/mount.c
@@ -318,6 +318,11 @@ void print_inode_info(struct f2fs_sb_info *sbi,
 	if (en[0]) {
 		DISP_u32(inode, i_namelen);
 		printf("%-30s\t\t[%s]\n", "i_name", en);
+
+		printf("%-30s\t\t[", "i_name(hex)");
+		for (i = 0; i < F2FS_NAME_LEN && en[i]; i++)
+			printf("0x%x ", (unsigned char)en[i]);
+		printf("0x%x]\n", (unsigned char)en[i]);
 	}
 
 	printf("i_ext: fofs:%x blkaddr:%x len:%x\n",
@@ -1708,7 +1713,8 @@ u32 update_nat_bits_flags(struct f2fs_super_block *sb,
 	nat_bits_bytes = get_sb(segment_count_nat) << 5;
 	nat_bits_blocks = F2FS_BYTES_TO_BLK((nat_bits_bytes << 1) + 8 +
 						F2FS_BLKSIZE - 1);
-	if (get_cp(cp_pack_total_block_count) <=
+	if (!(c.disabled_feature & F2FS_FEATURE_NAT_BITS) &&
+			get_cp(cp_pack_total_block_count) <=
 			(1 << get_sb(log_blocks_per_seg)) - nat_bits_blocks)
 		flags |= CP_NAT_BITS_FLAG;
 	else
diff --git a/include/android_config.h b/include/android_config.h
index f5cd4de..b11e2e4 100644
--- a/include/android_config.h
+++ b/include/android_config.h
@@ -36,6 +36,8 @@
 #define HAVE_FSTAT64 1
 #define HAVE_GETMNTENT 1
 #define HAVE_MEMSET 1
+#define HAVE_PREAD 1
+#define HAVE_PWRITE 1
 #define HAVE_SELINUX_ANDROID_H 1
 #define HAVE_SETMNTENT 1
 #define HAVE_SPARSE_SPARSE_H 1
diff --git a/include/f2fs_fs.h b/include/f2fs_fs.h
index 0cb9228..bb40adc 100644
--- a/include/f2fs_fs.h
+++ b/include/f2fs_fs.h
@@ -1471,6 +1471,11 @@ enum {
 
 #define MAX_CACHE_SUMS			8
 
+/* feature list in Android */
+enum {
+	F2FS_FEATURE_NAT_BITS = 0x0001,
+};
+
 struct f2fs_configuration {
 	uint32_t conf_reserved_sections;
 	uint32_t reserved_segments;
@@ -1537,6 +1542,7 @@ struct f2fs_configuration {
 	int large_nat_bitmap;
 	int fix_chksum;			/* fix old cp.chksum position */
 	unsigned int feature;			/* defined features */
+	unsigned int disabled_feature;	/* disabled feature, used for Android only */
 	unsigned int quota_bits;	/* quota bits */
 	time_t fixed_time;
 	int roll_forward;
diff --git a/lib/libf2fs_io.c b/lib/libf2fs_io.c
index 520ae03..2030440 100644
--- a/lib/libf2fs_io.c
+++ b/lib/libf2fs_io.c
@@ -279,6 +279,12 @@ static int dcache_io_read(long entry, __u64 offset, off_t blk)
 	if (fd < 0)
 		return fd;
 
+#ifdef HAVE_PREAD
+	if (pread(fd, dcache_buf + entry * F2FS_BLKSIZE, F2FS_BLKSIZE, offset) < 0) {
+		MSG(0, "\n pread() fail.\n");
+		return -1;
+	}
+#else
 	if (lseek(fd, offset, SEEK_SET) < 0) {
 		MSG(0, "\n lseek fail.\n");
 		return -1;
@@ -287,6 +293,7 @@ static int dcache_io_read(long entry, __u64 offset, off_t blk)
 		MSG(0, "\n read() fail.\n");
 		return -1;
 	}
+#endif
 	dcache_lastused[entry] = ++dcache_usetick;
 	dcache_valid[entry] = true;
 	dcache_blk[entry] = blk;
@@ -393,10 +400,15 @@ int dev_read_version(void *buf, __u64 offset, size_t len)
 {
 	if (c.sparse_mode)
 		return 0;
+#ifdef HAVE_RPEAD
+	if (pread(c.kd, buf, len, (off_t)offset) < 0)
+		return -1;
+#else
 	if (lseek(c.kd, (off_t)offset, SEEK_SET) < 0)
 		return -1;
 	if (read(c.kd, buf, len) < 0)
 		return -1;
+#endif
 	return 0;
 }
 
@@ -535,10 +547,15 @@ int dev_read(void *buf, __u64 offset, size_t len)
 	fd = __get_device_fd(&offset);
 	if (fd < 0)
 		return fd;
+#ifdef HAVE_PREAD
+	if (pread(fd, buf, len, (off_t)offset) < 0)
+		return -1;
+#else
 	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
 		return -1;
 	if (read(fd, buf, len) < 0)
 		return -1;
+#endif
 	return 0;
 }
 
@@ -615,9 +632,6 @@ static int __dev_write(void *buf, __u64 offset, size_t len, enum rw_hint whint)
 	if (fd < 0)
 		return fd;
 
-	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
-		return -1;
-
 #if ! defined(__MINGW32__)
 	if (c.need_whint && (c.whint != whint)) {
 		u64 hint = whint;
@@ -629,8 +643,15 @@ static int __dev_write(void *buf, __u64 offset, size_t len, enum rw_hint whint)
 	}
 #endif
 
+#ifdef HAVE_PWRITE
+	if (pwrite(fd, buf, len, (off_t)offset) < 0)
+		return -1;
+#else
+	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
+		return -1;
 	if (write(fd, buf, len) < 0)
 		return -1;
+#endif
 
 	c.need_fsync = true;
 
@@ -663,10 +684,15 @@ int dev_write_block(void *buf, __u64 blk_addr, enum rw_hint whint)
 
 int dev_write_dump(void *buf, __u64 offset, size_t len)
 {
+#ifdef HAVE_PWRITE
+	if (pwrite(c.dump_fd, buf, len, (off_t)offset) < 0)
+		return -1;
+#else
 	if (lseek(c.dump_fd, (off_t)offset, SEEK_SET) < 0)
 		return -1;
 	if (write(c.dump_fd, buf, len) < 0)
 		return -1;
+#endif
 	return 0;
 }
 
diff --git a/man/f2fs_io.8 b/man/f2fs_io.8
index 2ff22f7..e0f659e 100644
--- a/man/f2fs_io.8
+++ b/man/f2fs_io.8
@@ -54,7 +54,8 @@ going down with fsck mark
 Get or set the pinning status on a file.
 .TP
 \fBfadvise\fR \fI[advice] [offset] [length] [file]\fR
-Pass an advice to the specified file. The advice can be willneed and sequential.
+Pass an advice to the specified file. The advice can be willneed, dontneed,
+noreuse, sequential, random.
 .TP
 \fBfallocate\fR \fI[-c] [-i] [-p] [-z] [keep_size] [offset] [length] [file]\fR
 Request that space be allocated on a file.  The
@@ -180,6 +181,9 @@ Trigger gc to move data blocks from specified address range
 .TP
 \fBget_advise\fR \fI[file]\fR
 Get i_advise value and info in file
+.TP
+\fBioprio\fR \fI[hint] [file]\fR
+Set ioprio to the file. The ioprio can be ioprio_write.
 .SH AUTHOR
 This version of
 .B f2fs_io
diff --git a/mkfs/f2fs_format.c b/mkfs/f2fs_format.c
index 6635eed..c28ebb0 100644
--- a/mkfs/f2fs_format.c
+++ b/mkfs/f2fs_format.c
@@ -893,7 +893,8 @@ static int f2fs_write_check_point_pack(void)
 	/* cp page (2), data summaries (1), node summaries (3) */
 	set_cp(cp_pack_total_block_count, 6 + get_sb(cp_payload));
 	flags = CP_UMOUNT_FLAG | CP_COMPACT_SUM_FLAG;
-	if (get_cp(cp_pack_total_block_count) <=
+	if (!(c.disabled_feature & F2FS_FEATURE_NAT_BITS) &&
+			get_cp(cp_pack_total_block_count) <=
 			(1 << get_sb(log_blocks_per_seg)) - nat_bits_blocks)
 		flags |= CP_NAT_BITS_FLAG;
 
diff --git a/mkfs/f2fs_format_main.c b/mkfs/f2fs_format_main.c
index 9407f5b..5b4569d 100644
--- a/mkfs/f2fs_format_main.c
+++ b/mkfs/f2fs_format_main.c
@@ -143,6 +143,7 @@ static void add_default_options(void)
 		force_overwrite = 1;
 		c.wanted_sector_size = F2FS_BLKSIZE;
 		c.root_uid = c.root_gid = 0;
+		c.disabled_feature |= F2FS_FEATURE_NAT_BITS;
 
 		/* RO doesn't need any other features */
 		if (c.feature & F2FS_FEATURE_RO)
diff --git a/tools/f2fs_io/f2fs_io.c b/tools/f2fs_io/f2fs_io.c
index fa01f8f..57a931d 100644
--- a/tools/f2fs_io/f2fs_io.c
+++ b/tools/f2fs_io/f2fs_io.c
@@ -441,7 +441,10 @@ static void do_shutdown(int argc, char **argv, const struct cmd_desc *cmd)
 "fadvice given the file\n"					\
 "advice can be\n"						\
 " willneed\n"							\
+" dontneed\n"							\
+" noreuse\n"							\
 " sequential\n"							\
+" random\n"							\
 
 static void do_fadvise(int argc, char **argv, const struct cmd_desc *cmd)
 {
@@ -458,8 +461,14 @@ static void do_fadvise(int argc, char **argv, const struct cmd_desc *cmd)
 
 	if (!strcmp(argv[1], "willneed")) {
 		advice = POSIX_FADV_WILLNEED;
+	} else if (!strcmp(argv[1], "dontneed")) {
+		advice = POSIX_FADV_DONTNEED;
+	} else if (!strcmp(argv[1], "noreuse")) {
+		advice = POSIX_FADV_NOREUSE;
 	} else if (!strcmp(argv[1], "sequential")) {
 		advice = POSIX_FADV_SEQUENTIAL;
+	} else if (!strcmp(argv[1], "random")) {
+		advice = POSIX_FADV_RANDOM;
 	} else {
 		fputs("Wrong advice\n\n", stderr);
 		fputs(cmd->cmd_help, stderr);
@@ -476,23 +485,58 @@ static void do_fadvise(int argc, char **argv, const struct cmd_desc *cmd)
 	exit(0);
 }
 
+#define ioprio_desc "ioprio"
+#define ioprio_help						\
+"f2fs_io ioprio [hint] [file]\n\n"				\
+"ioprio given the file\n"					\
+"hint can be\n"							\
+" ioprio_write\n"						\
+
+static void do_ioprio(int argc, char **argv, const struct cmd_desc *cmd)
+{
+	int fd, hint;
+
+	if (argc != 3) {
+		fputs("Excess arguments\n\n", stderr);
+		fputs(cmd->cmd_help, stderr);
+		exit(1);
+	}
+
+	fd = xopen(argv[2], O_RDWR, 0);
+
+	if (!strcmp(argv[1], "ioprio_write")) {
+		hint = F2FS_IOPRIO_WRITE;
+	} else {
+		fputs("Not supported hint\n\n", stderr);
+		fputs(cmd->cmd_help, stderr);
+		exit(1);
+	}
+
+	if (ioctl(fd, F2FS_IOC_IO_PRIO, &hint) != 0)
+		die_errno("ioprio failed");
+
+	printf("ioprio_hint %d to a file: %s\n", hint, argv[2]);
+	exit(0);
+}
+
 #define pinfile_desc "pin file control"
 #define pinfile_help						\
-"f2fs_io pinfile [get|set|unset] [file]\n\n"			\
-"get/set pinning given the file\n"				\
+"f2fs_io pinfile [get|set|unset] [file] {size}\n\n"		\
+"get/set/unset pinning given the file\n"			\
+"{size} is fallocate length and optional only for set operations\n"
 
 static void do_pinfile(int argc, char **argv, const struct cmd_desc *cmd)
 {
 	u32 pin;
 	int ret, fd;
 
-	if (argc != 3) {
+	if (argc < 3 || argc > 4) {
 		fputs("Excess arguments\n\n", stderr);
 		fputs(cmd->cmd_help, stderr);
 		exit(1);
 	}
 
-	fd = xopen(argv[2], O_RDONLY, 0);
+	fd = xopen(argv[2], O_RDWR, 0);
 
 	ret = -1;
 	if (!strcmp(argv[1], "set")) {
@@ -500,8 +544,19 @@ static void do_pinfile(int argc, char **argv, const struct cmd_desc *cmd)
 		ret = ioctl(fd, F2FS_IOC_SET_PIN_FILE, &pin);
 		if (ret != 0)
 			die_errno("F2FS_IOC_SET_PIN_FILE failed");
-		printf("%s pinfile: %u blocks moved in %s\n",
-					argv[1], ret, argv[2]);
+		if (argc != 4) {
+			printf("%s pinfile: %u blocks moved in %s\n",
+						argv[1], ret, argv[2]);
+			exit(0);
+		}
+
+		struct stat st;
+		if (fallocate(fd, 0, 0, atoll(argv[3])) != 0)
+			die_errno("fallocate failed");
+		if (fstat(fd, &st) != 0)
+			die_errno("fstat failed");
+		printf("%s pinfile: %u blocks moved and fallocate %"PRIu64" bytes in %s\n",
+					argv[1], ret, st.st_size, argv[2]);
 	} else if (!strcmp(argv[1], "unset")) {
 		pin = 0;
 		ret = ioctl(fd, F2FS_IOC_SET_PIN_FILE, &pin);
@@ -950,6 +1005,119 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 	exit(0);
 }
 
+#define fragread_desc "read data with a fragmented buffer from file"
+#define fragread_help					\
+"f2fs_io fragread [chunk_size in 4kb] [offset in chunk_size] [count] [advice] [file_path]\n\n"	\
+"Read data in file_path and print nbytes\n"		\
+"advice can be\n"					\
+" 1 : set sequential|willneed\n"			\
+" 0 : none\n"						\
+
+#ifndef PAGE_SIZE
+#define PAGE_SIZE sysconf(_SC_PAGESIZE)
+#endif
+#define ALLOC_SIZE (2 * 1024 * 1024 - 4 * 1024) // 2MB - 4KB
+
+static void do_fragread(int argc, char **argv, const struct cmd_desc *cmd)
+{
+	u64 buf_size = 0, ret = 0, read_cnt = 0;
+	u64 offset;
+	char *buf = NULL;
+	uintptr_t idx, ptr;
+	unsigned bs, count, i;
+	u64 total_time = 0;
+	int flags = 0, alloc_count = 0;
+	void *mem_hole, **mem_holes;
+	int fd, advice;
+
+	if (argc != 6) {
+		fputs("Excess arguments\n\n", stderr);
+		fputs(cmd->cmd_help, stderr);
+		exit(1);
+	}
+
+	bs = atoi(argv[1]);
+	if (bs > 256 * 1024)
+		die("Too big chunk size - limit: 1GB");
+	buf_size = bs * F2FS_DEFAULT_BLKSIZE;
+
+	offset = atoi(argv[2]) * buf_size;
+	count = atoi(argv[3]);
+	advice = atoi(argv[4]);
+	mem_holes = xmalloc(sizeof(void *) * (buf_size / PAGE_SIZE));
+
+	/* 1. Allocate the buffer using mmap. */
+	buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
+				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+
+	/* 2. Loop and touch each page. */
+	for (idx = (uintptr_t)buf; idx < (uintptr_t)buf + buf_size;
+						idx += PAGE_SIZE)
+	{
+		/* Touch the current page. */
+		volatile char *page = (volatile char *)idx;
+		*page;
+
+		/* 3. Allocate (2M - 4K) memory using mmap and touch all of it. */
+		mem_hole = mmap(NULL, ALLOC_SIZE, PROT_READ | PROT_WRITE,
+					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+		if (mem_hole == MAP_FAILED)
+			die_errno("map failed");
+
+		/* Store the allocated memory pointer. */
+		mem_holes[alloc_count++] = mem_hole;
+
+		/* Touch all allocated memory. */
+		for (ptr = (uintptr_t)mem_hole;
+			ptr < (uintptr_t)mem_hole + ALLOC_SIZE;
+						ptr += PAGE_SIZE) {
+			volatile char *alloc_page = (volatile char *)ptr;
+			*alloc_page;
+		}
+	}
+	printf("Touched allocated memory: count = %u\n", alloc_count);
+	printf(" - allocated memory: = ");
+	for (idx = 0; idx < 5; idx++)
+		printf(" %p", mem_holes[idx]);
+	printf("\n");
+
+	/* Pin the pages. */
+	if (mlock(buf, buf_size))
+		die_errno("mlock failed");
+
+	fd = xopen(argv[5], O_RDONLY | flags, 0);
+
+	if (advice) {
+		if (posix_fadvise(fd, 0, F2FS_DEFAULT_BLKSIZE,
+				POSIX_FADV_SEQUENTIAL) != 0)
+			die_errno("fadvise failed");
+		if (posix_fadvise(fd, 0, F2FS_DEFAULT_BLKSIZE,
+				POSIX_FADV_WILLNEED) != 0)
+			die_errno("fadvise failed");
+		printf("fadvise SEQUENTIAL|WILLNEED to a file: %s\n", argv[5]);
+	}
+
+	total_time = get_current_us();
+
+	for (i = 0; i < count; i++) {
+		ret = pread(fd, buf, buf_size, offset + buf_size * i);
+		if (ret != buf_size) {
+			printf("pread expected: %"PRIu64", readed: %"PRIu64"\n",
+					buf_size, ret);
+			if (ret > 0)
+				read_cnt += ret;
+			break;
+		}
+
+		read_cnt += ret;
+	}
+	printf("Fragmented_Read %"PRIu64" bytes total_time = %"PRIu64" us, BW = %.Lf MB/s\n",
+		read_cnt, get_current_us() - total_time,
+		((long double)read_cnt / (get_current_us() - total_time)));
+	printf("\n");
+	exit(0);
+}
+
 #define randread_desc "random read data from file"
 #define randread_help					\
 "f2fs_io randread [chunk_size in 4kb] [count] [IO] [advise] [file_path]\n\n"	\
@@ -1887,6 +2055,31 @@ static void do_get_advise(int argc, char **argv, const struct cmd_desc *cmd)
 	printf("\n");
 }
 
+#define ftruncate_desc "ftruncate a file"
+#define ftruncate_help					\
+"f2fs_io ftruncate [length] [file_path]\n\n"	\
+"Do ftruncate a file in file_path with the length\n"	\
+
+static void do_ftruncate(int argc, char **argv, const struct cmd_desc *cmd)
+{
+	int fd, ret;
+	off_t length;
+
+	if (argc != 3) {
+		fputs("Excess arguments\n\n", stderr);
+		fputs(cmd->cmd_help, stderr);
+		exit(1);
+	}
+
+	length = atoll(argv[1]);
+	fd = xopen(argv[2], O_WRONLY, 0);
+
+	ret = ftruncate(fd, length);
+	if (ret < 0)
+		die_errno("ftruncate failed");
+	exit(0);
+}
+
 #define CMD_HIDDEN 	0x0001
 #define CMD(name) { #name, do_##name, name##_desc, name##_help, 0 }
 #define _CMD(name) { #name, do_##name, NULL, NULL, CMD_HIDDEN }
@@ -1909,6 +2102,7 @@ const struct cmd_desc cmd_list[] = {
 	CMD(write_advice),
 	CMD(read),
 	CMD(randread),
+	CMD(fragread),
 	CMD(fiemap),
 	CMD(gc_urgent),
 	CMD(defrag_file),
@@ -1932,6 +2126,8 @@ const struct cmd_desc cmd_list[] = {
 	CMD(removexattr),
 	CMD(lseek),
 	CMD(get_advise),
+	CMD(ioprio),
+	CMD(ftruncate),
 	{ NULL, NULL, NULL, NULL, 0 }
 };
 
diff --git a/tools/f2fs_io/f2fs_io.h b/tools/f2fs_io/f2fs_io.h
index 14c9dc1..21fd386 100644
--- a/tools/f2fs_io/f2fs_io.h
+++ b/tools/f2fs_io/f2fs_io.h
@@ -94,6 +94,8 @@ typedef u32	__be32;
 #define F2FS_IOC_DECOMPRESS_FILE        _IO(F2FS_IOCTL_MAGIC, 23)
 #define F2FS_IOC_COMPRESS_FILE          _IO(F2FS_IOCTL_MAGIC, 24)
 #define F2FS_IOC_START_ATOMIC_REPLACE	_IO(F2FS_IOCTL_MAGIC, 25)
+#define F2FS_IOC_GET_DEV_ALIAS_FILE	_IOR(F2FS_IOCTL_MAGIC, 26, __u32)
+#define F2FS_IOC_IO_PRIO		_IOW(F2FS_IOCTL_MAGIC, 27, __u32)
 
 #ifndef FSCRYPT_POLICY_V1
 #define FSCRYPT_POLICY_V1		0
@@ -193,6 +195,11 @@ struct fsverity_enable_arg {
 #define FADVISE_VERITY_BIT	0x40
 #define FADVISE_TRUNC_BIT	0x80
 
+/* used for F2FS_IOC_IO_PRIO */
+enum {
+	F2FS_IOPRIO_WRITE = 1,  /* high write priority */
+};
+
 #ifndef FS_IMMUTABLE_FL
 #define FS_IMMUTABLE_FL			0x00000010 /* Immutable file */
 #endif
```

