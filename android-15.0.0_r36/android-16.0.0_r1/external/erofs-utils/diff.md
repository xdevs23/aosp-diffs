```diff
diff --git a/Android.bp b/Android.bp
index ac930f4..7ca293f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -76,6 +76,9 @@ cc_defaults {
         "-D_FILE_OFFSET_BITS=64",
         "-DEROFS_MAX_BLOCK_SIZE=16384",
         "-DHAVE_UTIMENSAT",
+        "-DHAVE_UNISTD_H",
+        "-DHAVE_SYSCONF",
+        "-DEROFS_MT_ENABLED",
     ],
 }
 
@@ -103,6 +106,7 @@ cc_defaults {
                 "liblz4",
                 "libselinux",
             ],
+            stl: "none",
         },
         host: {
             static_libs: [
@@ -113,6 +117,7 @@ cc_defaults {
                 "liblz4",
                 "libselinux",
             ],
+            stl: "c++_static",
         },
     },
 }
@@ -128,7 +133,6 @@ cc_library {
     exclude_srcs: [
         "lib/compressor_libdeflate.c",
         "lib/compressor_libzstd.c",
-        "lib/workqueue.c",
     ],
     export_include_dirs: ["include"],
 
@@ -172,13 +176,6 @@ cc_binary {
     stem: "mkfs.erofs",
 }
 
-cc_binary_host {
-    name: "make_erofs",
-
-    defaults: ["mkfs-erofs_defaults"],
-    stl: "libc++_static"
-}
-
 cc_defaults {
     name: "dump.erofs_defaults",
     defaults: ["erofs-utils_defaults"],
@@ -235,4 +232,4 @@ cc_binary {
     defaults: ["fsck.erofs_defaults"],
     recovery: true,
     stem: "fsck.erofs",
-}
\ No newline at end of file
+}
diff --git a/ChangeLog b/ChangeLog
index 676243c..bdfa66c 100644
--- a/ChangeLog
+++ b/ChangeLog
@@ -1,3 +1,35 @@
+erofs-utils 1.8.3
+
+ * Another maintenance release includes the following fixes:
+   - (mkfs.erofs) Fix multi-threaded compression with `-Eall-fragments`;
+   - (mkfs.erofs) Fix large chunk-based image generation;
+   - (mkfs.erofs) Avoid large arrays on the stack (Jianan Huang);
+   - (mkfs.erofs) Fix PAX format parsing in headerball mode (Mike Baynton);
+   - (mkfs.erofs) Several fixes for incremental builds (Hongzhen Luo);
+   - (mkfs.erofs) Fix reproducible builds due to `i_ino` (Jooyung Han);
+   - Use pkg-config for liblz4 configuration;
+   - Get rid of pthread_cancel() dependencies;
+   - (mkfs.erofs) Add `-U <clear|random>` support;
+   - (mkfs.erofs) Add `--hard-dereference` for NixOS reproducibility (Paul Meyer);
+   - Several minor random fixes.
+
+ -- Gao Xiang <xiang@kernel.org>  Sat, 14 Dec 2024 00:00:00 +0800
+
+erofs-utils 1.8.2
+
+ * Another maintenance release includes the following fixes:
+   - (mkfs.erofs) Fix build on GNU/Hurd (Ahelenia Ziemiańska);
+   - (mkfs.erofs) Fix maximum volume label length (Naoto Yamaguchi);
+   - (mkfs.erofs) Correctly skip unidentified xattrs (Sandeep Dhavale);
+   - (fsck.erofs) Support exporting xattrs optionally (Hongzhen Luo);
+   - (mkfs.erofs) Correctly sort shared xattrs (Sheng Yong);
+   - (mkfs.erofs) Allow pax headers with empty names;
+   - (mkfs.erofs) Add `--sort=none` option for tarballs;
+   - (mkfs.erofs) Fix broken compressed packed inodes (Danny Lin);
+   - Several minor random fixes.
+
+ -- Gao Xiang <xiang@kernel.org>  Tue, 24 Sep 2024 00:00:00 +0800
+
 erofs-utils 1.8.1
 
  * A quick maintenance release includes the following fixes:
diff --git a/METADATA b/METADATA
index e32d588..ec4763d 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 9
-    day: 16
+    month: 12
+    day: 18
   }
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"
-    version: "v1.8.1"
+    version: "v1.8.3"
   }
 }
diff --git a/OWNERS b/OWNERS
index 78e2649..1fb8288 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ dvander@google.com
 jaegeuk@google.com
 daehojeong@google.com
 dhavale@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/VERSION b/VERSION
index 20a0e9a..205d56c 100644
--- a/VERSION
+++ b/VERSION
@@ -1,2 +1,2 @@
-1.8.1
-2024-08-10
+1.8.3
+2024-12-14
diff --git a/configure.ac b/configure.ac
index 945e254..45a7d33 100644
--- a/configure.ac
+++ b/configure.ac
@@ -123,8 +123,8 @@ AC_ARG_ENABLE([fuzzing],
     [enable_fuzzing="no"])
 
 AC_ARG_ENABLE(lz4,
-   [AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=enabled@:>@])],
-   [enable_lz4="$enableval"], [enable_lz4="yes"])
+   [AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=auto@:>@])],
+   [enable_lz4="$enableval"])
 
 AC_ARG_ENABLE(lzma,
    [AS_HELP_STRING([--disable-lzma], [disable LZMA compression support @<:@default=auto@:>@])],
@@ -172,17 +172,6 @@ AC_ARG_WITH(selinux,
     esac], [with_selinux=no])
 
 # Checks for libraries.
-# Use customized LZ4 library path when specified.
-AC_ARG_WITH(lz4-incdir,
-   [AS_HELP_STRING([--with-lz4-incdir=DIR], [LZ4 include directory])], [
-   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])
-
-AC_ARG_WITH(lz4-libdir,
-   [AS_HELP_STRING([--with-lz4-libdir=DIR], [LZ4 lib directory])], [
-   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])
-
-AC_ARG_VAR([LZ4_CFLAGS], [C compiler flags for lz4])
-AC_ARG_VAR([LZ4_LIBS], [linker flags for lz4])
 
 # Checks for header files.
 AC_CHECK_HEADERS(m4_flatten([
@@ -260,6 +249,7 @@ AC_CHECK_FUNCS(m4_flatten([
 	gettimeofday
 	lgetxattr
 	llistxattr
+	lsetxattr
 	memset
 	realpath
 	lseek64
@@ -395,36 +385,35 @@ AS_IF([test "x$enable_fuse" != "xno"], [
   CPPFLAGS="${saved_CPPFLAGS}"], [have_fuse="no"])
 
 # Configure lz4
-test -z $LZ4_LIBS && LZ4_LIBS='-llz4'
-
-if test "x$enable_lz4" = "xyes"; then
-  test -z "${with_lz4_incdir}" || LZ4_CFLAGS="-I$with_lz4_incdir $LZ4_CFLAGS"
-
+AS_IF([test "x$enable_lz4" != "xno"], [
   saved_CPPFLAGS=${CPPFLAGS}
-  CPPFLAGS="${LZ4_CFLAGS} ${CPPFLAGS}"
-
-  AC_CHECK_HEADERS([lz4.h],[have_lz4h="yes"], [])
-
-  if test "x${have_lz4h}" = "xyes" ; then
+  PKG_CHECK_MODULES([liblz4], [liblz4], [
+    # Paranoia: don't trust the result reported by pkgconfig before trying out
     saved_LIBS="$LIBS"
-    saved_LDFLAGS=${LDFLAGS}
-    test -z "${with_lz4_libdir}" || LDFLAGS="-L$with_lz4_libdir ${LDFLAGS}"
-    AC_CHECK_LIB(lz4, LZ4_compress_destSize, [
-      have_lz4="yes"
-      have_lz4hc="yes"
-      AC_CHECK_LIB(lz4, LZ4_compress_HC_destSize, [], [
-        AC_CHECK_DECL(LZ4_compress_HC_destSize, [lz4_force_static="yes"],
-          [have_lz4hc="no"], [[
-#define LZ4_HC_STATIC_LINKING_ONLY (1)
+    saved_CPPFLAGS=${CPPFLAGS}
+    CPPFLAGS="${liblz4_CFLAGS} ${CPPFLAGS}"
+    LIBS="${liblz4_LIBS} $LIBS"
+    AC_CHECK_HEADERS([lz4.h],[
+      AC_CHECK_LIB(lz4, LZ4_compress_destSize, [
+        AC_CHECK_DECL(LZ4_compress_destSize, [have_lz4="yes"],
+          [], [[
+#include <lz4.h>
+        ]])
+      ])
+      AC_CHECK_LIB(lz4, LZ4_compress_HC_destSize, [
+        AC_CHECK_DECL(LZ4_compress_HC_destSize, [have_lz4hc="yes"],
+          [], [[
 #include <lz4hc.h>
         ]])
       ])
-    ], [AC_MSG_ERROR([Cannot find proper lz4 version (>= 1.8.0)])])
-    LDFLAGS=${saved_LDFLAGS}
+    ])
     LIBS="${saved_LIBS}"
-  fi
-  CPPFLAGS=${saved_CPPFLAGS}
-fi
+    CPPFLAGS="${saved_CPPFLAGS}"
+  ], [[]])
+  AS_IF([test "x$enable_lz4" = "xyes" -a "x$have_lz4" != "xyes"], [
+    AC_MSG_ERROR([Cannot find a proper liblz4 version])
+  ])
+])
 
 # Configure liblzma
 have_liblzma="no"
@@ -580,16 +569,7 @@ if test "x${have_lz4}" = "xyes"; then
   if test "x${have_lz4hc}" = "xyes"; then
     AC_DEFINE([LZ4HC_ENABLED], [1], [Define to 1 if lz4hc is enabled.])
   fi
-
-  if test "x${lz4_force_static}" = "xyes"; then
-    LZ4_LIBS="-Wl,-Bstatic -Wl,-whole-archive -Xlinker ${LZ4_LIBS} -Wl,-no-whole-archive -Wl,-Bdynamic"
-    test -z "${with_lz4_libdir}" || LZ4_LIBS="-L${with_lz4_libdir} $LZ4_LIBS"
-  else
-    test -z "${with_lz4_libdir}" || LZ4_LIBS="-L${with_lz4_libdir} -R${with_lz4_libdir} $LZ4_LIBS"
-  fi
-  liblz4_LIBS="${LZ4_LIBS}"
 fi
-AC_SUBST([liblz4_LIBS])
 
 if test "x${have_liblzma}" = "xyes"; then
   AC_DEFINE([HAVE_LIBLZMA], [1], [Define to 1 if liblzma is enabled.])
diff --git a/fsck/main.c b/fsck/main.c
index 28f1e7e..f20b767 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -9,10 +9,12 @@
 #include <utime.h>
 #include <unistd.h>
 #include <sys/stat.h>
+#include <sys/xattr.h>
 #include "erofs/print.h"
 #include "erofs/compress.h"
 #include "erofs/decompress.h"
 #include "erofs/dir.h"
+#include "erofs/xattr.h"
 #include "../lib/compressor.h"
 
 static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);
@@ -31,6 +33,7 @@ struct erofsfsck_cfg {
 	bool overwrite;
 	bool preserve_owner;
 	bool preserve_perms;
+	bool dump_xattrs;
 };
 static struct erofsfsck_cfg fsckcfg;
 
@@ -48,6 +51,8 @@ static struct option long_options[] = {
 	{"no-preserve-owner", no_argument, 0, 10},
 	{"no-preserve-perms", no_argument, 0, 11},
 	{"offset", required_argument, 0, 12},
+	{"xattrs", no_argument, 0, 13},
+	{"no-xattrs", no_argument, 0, 14},
 	{0, 0, 0, 0},
 };
 
@@ -98,6 +103,7 @@ static void usage(int argc, char **argv)
 		" --extract[=X]          check if all files are well encoded, optionally\n"
 		"                        extract to X\n"
 		" --offset=#             skip # bytes at the beginning of IMAGE\n"
+		" --[no-]xattrs          whether to dump extended attributes (default off)\n"
 		"\n"
 		" -a, -A, -y             no-op, for compatibility with fsck of other filesystems\n"
 		"\n"
@@ -225,6 +231,12 @@ static int erofsfsck_parse_options_cfg(int argc, char **argv)
 				return -EINVAL;
 			}
 			break;
+		case 13:
+			fsckcfg.dump_xattrs = true;
+			break;
+		case 14:
+			fsckcfg.dump_xattrs = false;
+			break;
 		default:
 			return -EINVAL;
 		}
@@ -411,6 +423,95 @@ out:
 	return ret;
 }
 
+static int erofsfsck_dump_xattrs(struct erofs_inode *inode)
+{
+	static bool ignore_xattrs = false;
+	char *keylst, *key;
+	ssize_t kllen;
+	int ret;
+
+	kllen = erofs_listxattr(inode, NULL, 0);
+	if (kllen <= 0)
+		return kllen;
+	keylst = malloc(kllen);
+	if (!keylst)
+		return -ENOMEM;
+	ret = erofs_listxattr(inode, keylst, kllen);
+	if (ret != kllen) {
+		erofs_err("failed to list xattrs @ nid %llu",
+			  inode->nid | 0ULL);
+		ret = -EINVAL;
+		goto out;
+	}
+	ret = 0;
+	for (key = keylst; key < keylst + kllen; key += strlen(key) + 1) {
+		unsigned int index, len;
+		void *value = NULL;
+		size_t size = 0;
+
+		ret = erofs_getxattr(inode, key, NULL, 0);
+		if (ret <= 0) {
+			DBG_BUGON(1);
+			erofs_err("failed to get xattr value size of `%s` @ nid %llu",
+				  key, inode->nid | 0ULL);
+			break;
+		}
+		size = ret;
+		value = malloc(size);
+		if (!value) {
+			ret = -ENOMEM;
+			break;
+		}
+		ret = erofs_getxattr(inode, key, value, size);
+		if (ret < 0) {
+			erofs_err("failed to get xattr `%s` @ nid %llu, because of `%s`", key,
+				  inode->nid | 0ULL, erofs_strerror(ret));
+			free(value);
+			break;
+		}
+		if (fsckcfg.extract_path)
+#ifdef HAVE_LSETXATTR
+			ret = lsetxattr(fsckcfg.extract_path, key, value, size,
+					0);
+#elif defined(__APPLE__)
+			ret = setxattr(fsckcfg.extract_path, key, value, size,
+				       0, XATTR_NOFOLLOW);
+#else
+			ret = -EOPNOTSUPP;
+#endif
+		else
+			ret = 0;
+		free(value);
+		if (ret == -EPERM && !fsckcfg.superuser) {
+			if (__erofs_unlikely(!erofs_xattr_prefix_matches(key,
+					&index, &len))) {
+				erofs_err("failed to match the prefix of `%s` @ nid %llu",
+					  key, inode->nid | 0ULL);
+				ret = -EINVAL;
+				break;
+			}
+			if (index != EROFS_XATTR_INDEX_USER) {
+				if (!ignore_xattrs) {
+					erofs_warn("ignored xattr `%s` @ nid %llu, due to non-superuser",
+						   key, inode->nid | 0ULL);
+					ignore_xattrs = true;
+				}
+				ret = 0;
+				continue;
+			}
+
+		}
+		if (ret) {
+			erofs_err("failed to set xattr `%s` @ nid %llu because of `%s`",
+				  key, inode->nid | 0ULL, erofs_strerror(ret));
+			break;
+		}
+	}
+out:
+	free(keylst);
+	return ret;
+}
+
 static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
 {
 	struct erofs_map_blocks map = {
@@ -807,8 +908,8 @@ static int erofsfsck_dirent_iter(struct erofs_dir_context *ctx)
 	curr_pos = prev_pos;
 
 	if (prev_pos + ctx->de_namelen >= PATH_MAX) {
-		erofs_err("unable to fsck since the path is too long (%u)",
-			  curr_pos + ctx->de_namelen);
+		erofs_err("unable to fsck since the path is too long (%llu)",
+			  (curr_pos + ctx->de_namelen) | 0ULL);
 		return -EOPNOTSUPP;
 	}
 
@@ -900,15 +1001,23 @@ static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid)
 		goto out;
 	}
 
-	/* verify xattr field */
-	ret = erofs_verify_xattr(&inode);
-	if (ret)
-		goto out;
+	if (!(fsckcfg.check_decomp && fsckcfg.dump_xattrs)) {
+		/* verify xattr field */
+		ret = erofs_verify_xattr(&inode);
+		if (ret)
+			goto out;
+	}
 
 	ret = erofsfsck_extract_inode(&inode);
 	if (ret && ret != -ECANCELED)
 		goto out;
 
+	if (fsckcfg.check_decomp && fsckcfg.dump_xattrs) {
+		ret = erofsfsck_dump_xattrs(&inode);
+		if (ret)
+			return ret;
+	}
+
 	/* XXXX: the dir depth should be restricted in order to avoid loops */
 	if (S_ISDIR(inode.i_mode)) {
 		struct erofs_dir_context ctx = {
@@ -955,6 +1064,7 @@ int main(int argc, char *argv[])
 	fsckcfg.overwrite = false;
 	fsckcfg.preserve_owner = fsckcfg.superuser;
 	fsckcfg.preserve_perms = fsckcfg.superuser;
+	fsckcfg.dump_xattrs = false;
 
 	err = erofsfsck_parse_options_cfg(argc, argv);
 	if (err) {
diff --git a/fuse/Makefile.am b/fuse/Makefile.am
index 1062b73..50186da 100644
--- a/fuse/Makefile.am
+++ b/fuse/Makefile.am
@@ -11,9 +11,9 @@ erofsfuse_LDADD = $(top_builddir)/lib/liberofs.la ${libfuse2_LIBS} ${libfuse3_LI
 	${libqpl_LIBS}
 
 if ENABLE_STATIC_FUSE
-lib_LIBRARIES = liberofsfuse.a
-liberofsfuse_a_SOURCES = main.c
-liberofsfuse_a_CFLAGS  = -Wall -I$(top_srcdir)/include
-liberofsfuse_a_CFLAGS += -Dmain=erofsfuse_main ${libfuse2_CFLAGS} ${libfuse3_CFLAGS} ${libselinux_CFLAGS}
-liberofsfuse_a_LIBADD  = $(top_builddir)/lib/liberofs.la
+lib_LTLIBRARIES = liberofsfuse.la
+liberofsfuse_la_SOURCES = main.c
+liberofsfuse_la_CFLAGS  = -Wall -I$(top_srcdir)/include
+liberofsfuse_la_CFLAGS += -Dmain=erofsfuse_main ${libfuse2_CFLAGS} ${libfuse3_CFLAGS} ${libselinux_CFLAGS}
+liberofsfuse_la_LIBADD  = $(top_builddir)/lib/liberofs.la
 endif
diff --git a/include/erofs/block_list.h b/include/erofs/block_list.h
index 7db4d0c..8cc87d7 100644
--- a/include/erofs/block_list.h
+++ b/include/erofs/block_list.h
@@ -17,7 +17,7 @@ int erofs_blocklist_open(FILE *fp, bool srcmap);
 FILE *erofs_blocklist_close(void);
 
 void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
-			      erofs_off_t srcoff);
+			      erofs_off_t srcoff, unsigned int zeroedlen);
 #ifdef WITH_ANDROID
 void erofs_droid_blocklist_write(struct erofs_inode *inode,
 				 erofs_blk_t blk_start, erofs_blk_t nblocks);
diff --git a/include/erofs/config.h b/include/erofs/config.h
index ae366c1..bb03e70 100644
--- a/include/erofs/config.h
+++ b/include/erofs/config.h
@@ -46,10 +46,6 @@ struct erofs_configure {
 	int c_dbg_lvl;
 	bool c_dry_run;
 	bool c_legacy_compress;
-#ifndef NDEBUG
-	bool c_random_pclusterblks;
-	bool c_random_algorithms;
-#endif
 	char c_timeinherit;
 	char c_chunkbits;
 	bool c_inline_data;
@@ -62,6 +58,7 @@ struct erofs_configure {
 	bool c_extra_ea_name_prefixes;
 	bool c_xattr_name_filter;
 	bool c_ovlfs_strip;
+	bool c_hard_dereference;
 
 #ifdef HAVE_LIBSELINUX
 	struct selabel_handle *sehnd;
@@ -94,6 +91,10 @@ struct erofs_configure {
 	char *fs_config_file;
 	char *block_list_file;
 #endif
+#ifndef NDEBUG
+	bool c_random_pclusterblks;
+	bool c_random_algorithms;
+#endif
 };
 
 extern struct erofs_configure cfg;
diff --git a/include/erofs/inode.h b/include/erofs/inode.h
index 604161c..eb8f45b 100644
--- a/include/erofs/inode.h
+++ b/include/erofs/inode.h
@@ -34,6 +34,7 @@ erofs_nid_t erofs_lookupnid(struct erofs_inode *inode);
 int erofs_iflush(struct erofs_inode *inode);
 struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
 				   const char *name);
+int erofs_allocate_inode_bh_data(struct erofs_inode *inode, erofs_blk_t nblocks);
 bool erofs_dentry_is_wht(struct erofs_sb_info *sbi, struct erofs_dentry *d);
 int erofs_rebuild_dump_tree(struct erofs_inode *dir, bool incremental);
 int erofs_init_empty_dir(struct erofs_inode *dir);
diff --git a/include/erofs/tar.h b/include/erofs/tar.h
index 6fa72eb..6981f9e 100644
--- a/include/erofs/tar.h
+++ b/include/erofs/tar.h
@@ -7,9 +7,6 @@ extern "C"
 {
 #endif
 
-#if defined(HAVE_ZLIB)
-#include <zlib.h>
-#endif
 #include <sys/stat.h>
 
 #include "internal.h"
@@ -28,14 +25,7 @@ struct erofs_pax_header {
 #define EROFS_IOS_DECODER_GZIP		1
 #define EROFS_IOS_DECODER_LIBLZMA	2
 
-#ifdef HAVE_LIBLZMA
-#include <lzma.h>
-struct erofs_iostream_liblzma {
-	u8 inbuf[32768];
-	lzma_stream strm;
-	int fd;
-};
-#endif
+struct erofs_iostream_liblzma;
 
 struct erofs_iostream {
 	union {
@@ -62,6 +52,7 @@ struct erofs_tarfile {
 	u64 offset;
 	bool index_mode, headeronly_mode, rvsp_mode, aufs;
 	bool ddtaridx_mode;
+	bool try_no_reorder;
 };
 
 void erofs_iostream_close(struct erofs_iostream *ios);
diff --git a/include/erofs/xattr.h b/include/erofs/xattr.h
index 7643611..804f565 100644
--- a/include/erofs/xattr.h
+++ b/include/erofs/xattr.h
@@ -61,6 +61,9 @@ void erofs_clear_opaque_xattr(struct erofs_inode *inode);
 int erofs_set_origin_xattr(struct erofs_inode *inode);
 int erofs_read_xattrs_from_disk(struct erofs_inode *inode);
 
+bool erofs_xattr_prefix_matches(const char *key, unsigned int *index,
+				unsigned int *len);
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/include/erofs_fs.h b/include/erofs_fs.h
index fc21915..9c69aac 100644
--- a/include/erofs_fs.h
+++ b/include/erofs_fs.h
@@ -414,8 +414,7 @@ enum {
 	Z_EROFS_LCLUSTER_TYPE_MAX
 };
 
-#define Z_EROFS_LI_LCLUSTER_TYPE_BITS        2
-#define Z_EROFS_LI_LCLUSTER_TYPE_BIT         0
+#define Z_EROFS_LI_LCLUSTER_TYPE_MASK	(Z_EROFS_LCLUSTER_TYPE_MAX - 1)
 
 /* (noncompact only, HEAD) This pcluster refers to partial decompressed data */
 #define Z_EROFS_LI_PARTIAL_REF		(1 << 15)
@@ -474,8 +473,6 @@ static inline void erofs_check_ondisk_layout_definitions(void)
 		     sizeof(struct z_erofs_lcluster_index));
 	BUILD_BUG_ON(sizeof(struct erofs_deviceslot) != 128);
 
-	BUILD_BUG_ON(BIT(Z_EROFS_LI_LCLUSTER_TYPE_BITS) <
-		     Z_EROFS_LCLUSTER_TYPE_MAX - 1);
 #ifndef __cplusplus
 	/* exclude old compiler versions like gcc 7.5.0 */
 	BUILD_BUG_ON(__builtin_constant_p(fmh.v) ?
diff --git a/lib/Makefile.am b/lib/Makefile.am
index 2cb4cab..9c0604d 100644
--- a/lib/Makefile.am
+++ b/lib/Makefile.am
@@ -38,7 +38,7 @@ liberofs_la_SOURCES = config.c io.c cache.c super.c inode.c xattr.c exclude.c \
 
 liberofs_la_CFLAGS = -Wall ${libuuid_CFLAGS} -I$(top_srcdir)/include
 if ENABLE_LZ4
-liberofs_la_CFLAGS += ${LZ4_CFLAGS}
+liberofs_la_CFLAGS += ${liblz4_CFLAGS}
 liberofs_la_SOURCES += compressor_lz4.c
 if ENABLE_LZ4HC
 liberofs_la_SOURCES += compressor_lz4hc.c
@@ -51,9 +51,11 @@ endif
 
 liberofs_la_SOURCES += kite_deflate.c compressor_deflate.c
 if ENABLE_LIBDEFLATE
+liberofs_la_CFLAGS += ${libdeflate_CFLAGS}
 liberofs_la_SOURCES += compressor_libdeflate.c
 endif
 if ENABLE_LIBZSTD
+liberofs_la_CFLAGS += ${libzstd_CFLAGS}
 liberofs_la_SOURCES += compressor_libzstd.c
 endif
 if ENABLE_EROFS_MT
diff --git a/lib/blobchunk.c b/lib/blobchunk.c
index 2835755..119dd82 100644
--- a/lib/blobchunk.c
+++ b/lib/blobchunk.c
@@ -95,7 +95,8 @@ static struct erofs_blobchunk *erofs_blob_getchunk(struct erofs_sb_info *sbi,
 		chunk->device_id = 0;
 	chunk->blkaddr = erofs_blknr(sbi, blkpos);
 
-	erofs_dbg("Writing chunk (%u bytes) to %u", chunksize, chunk->blkaddr);
+	erofs_dbg("Writing chunk (%llu bytes) to %u", chunksize | 0ULL,
+		  chunk->blkaddr);
 	ret = fwrite(buf, chunksize, 1, blobfile);
 	if (ret == 1) {
 		padding = erofs_blkoff(sbi, chunksize);
@@ -132,11 +133,13 @@ static int erofs_blob_hashmap_cmp(const void *a, const void *b,
 int erofs_blob_write_chunk_indexes(struct erofs_inode *inode,
 				   erofs_off_t off)
 {
+	struct erofs_sb_info *sbi = inode->sbi;
+	erofs_blk_t remaining_blks = BLK_ROUND_UP(sbi, inode->i_size);
 	struct erofs_inode_chunk_index idx = {0};
 	erofs_blk_t extent_start = EROFS_NULL_ADDR;
 	erofs_blk_t extent_end, chunkblks;
 	erofs_off_t source_offset;
-	unsigned int dst, src, unit;
+	unsigned int dst, src, unit, zeroedlen;
 	bool first_extent = true;
 
 	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
@@ -164,9 +167,10 @@ int erofs_blob_write_chunk_indexes(struct erofs_inode *inode,
 		if (extent_start == EROFS_NULL_ADDR ||
 		    idx.blkaddr != extent_end) {
 			if (extent_start != EROFS_NULL_ADDR) {
+				remaining_blks -= extent_end - extent_start;
 				tarerofs_blocklist_write(extent_start,
 						extent_end - extent_start,
-						source_offset);
+						source_offset, 0);
 				erofs_droid_blocklist_write_extent(inode,
 					extent_start,
 					extent_end - extent_start,
@@ -186,9 +190,14 @@ int erofs_blob_write_chunk_indexes(struct erofs_inode *inode,
 			memcpy(inode->chunkindexes + dst, &idx, sizeof(idx));
 	}
 	off = roundup(off, unit);
-	if (extent_start != EROFS_NULL_ADDR)
+	extent_end = min(extent_end, extent_start + remaining_blks);
+	if (extent_start != EROFS_NULL_ADDR) {
+		zeroedlen = inode->i_size & (erofs_blksiz(sbi) - 1);
+		if (zeroedlen)
+			zeroedlen = erofs_blksiz(sbi) - zeroedlen;
 		tarerofs_blocklist_write(extent_start, extent_end - extent_start,
-					 source_offset);
+					 source_offset, zeroedlen);
+	}
 	erofs_droid_blocklist_write_extent(inode, extent_start,
 			extent_start == EROFS_NULL_ADDR ?
 					0 : extent_end - extent_start,
@@ -476,9 +485,8 @@ int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset)
 int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 {
 	struct erofs_buffer_head *bh;
-	ssize_t length;
+	ssize_t length, ret;
 	u64 pos_in, pos_out;
-	ssize_t ret;
 
 	if (blobfile) {
 		fflush(blobfile);
@@ -528,9 +536,21 @@ int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 	pos_out += sbi->bdev.offset;
 	if (blobfile) {
 		pos_in = 0;
-		ret = erofs_copy_file_range(fileno(blobfile), &pos_in,
-				sbi->bdev.fd, &pos_out, datablob_size);
-		ret = ret < datablob_size ? -EIO : 0;
+		do {
+			length = min_t(erofs_off_t, datablob_size,  SSIZE_MAX);
+			ret = erofs_copy_file_range(fileno(blobfile), &pos_in,
+					sbi->bdev.fd, &pos_out, length);
+		} while (ret > 0 && (datablob_size -= ret));
+
+		if (ret >= 0) {
+			if (datablob_size) {
+				erofs_err("failed to append the remaining %llu-byte chunk data",
+					  datablob_size);
+				ret = -EIO;
+			} else {
+				ret = 0;
+			}
+		}
 	} else {
 		ret = erofs_io_ftruncate(&sbi->bdev, pos_out + datablob_size);
 	}
diff --git a/lib/block_list.c b/lib/block_list.c
index 261e9ff..6bbe4ec 100644
--- a/lib/block_list.c
+++ b/lib/block_list.c
@@ -32,13 +32,17 @@ FILE *erofs_blocklist_close(void)
 
 /* XXX: really need to be cleaned up */
 void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
-			      erofs_off_t srcoff)
+			      erofs_off_t srcoff, unsigned int zeroedlen)
 {
 	if (!block_list_fp || !nblocks || !srcmap_enabled)
 		return;
 
-	fprintf(block_list_fp, "%08x %8x %08" PRIx64 "\n",
-		blkaddr, nblocks, srcoff);
+	if (zeroedlen)
+		fprintf(block_list_fp, "%08x %8x %08" PRIx64 " %08u\n",
+			blkaddr, nblocks, srcoff, zeroedlen);
+	else
+		fprintf(block_list_fp, "%08x %8x %08" PRIx64 "\n",
+			blkaddr, nblocks, srcoff);
 }
 
 #ifdef WITH_ANDROID
diff --git a/lib/compress.c b/lib/compress.c
index 8655e78..65edd00 100644
--- a/lib/compress.c
+++ b/lib/compress.c
@@ -8,6 +8,9 @@
 #ifndef _LARGEFILE64_SOURCE
 #define _LARGEFILE64_SOURCE
 #endif
+#ifdef EROFS_MT_ENABLED
+#include <pthread.h>
+#endif
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
@@ -126,7 +129,7 @@ static void z_erofs_write_indexes_final(struct z_erofs_compress_ictx *ctx)
 
 	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);
 	di.di_u.blkaddr = 0;
-	di.di_advise = cpu_to_le16(type << Z_EROFS_LI_LCLUSTER_TYPE_BIT);
+	di.di_advise = cpu_to_le16(type);
 
 	memcpy(ctx->metacur, &di, sizeof(di));
 	ctx->metacur += sizeof(di);
@@ -156,8 +159,7 @@ static void z_erofs_write_extent(struct z_erofs_compress_ictx *ctx,
 		DBG_BUGON(e->partial);
 		type = e->raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
 			Z_EROFS_LCLUSTER_TYPE_HEAD1;
-		advise = type << Z_EROFS_LI_LCLUSTER_TYPE_BIT;
-		di.di_advise = cpu_to_le16(advise);
+		di.di_advise = cpu_to_le16(type);
 
 		if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL &&
 		    !e->compressedblks)
@@ -215,8 +217,7 @@ static void z_erofs_write_extent(struct z_erofs_compress_ictx *ctx,
 				advise |= Z_EROFS_LI_PARTIAL_REF;
 			}
 		}
-		advise |= type << Z_EROFS_LI_LCLUSTER_TYPE_BIT;
-		di.di_advise = cpu_to_le16(advise);
+		di.di_advise = cpu_to_le16(advise | type);
 
 		memcpy(ctx->metacur, &di, sizeof(di));
 		ctx->metacur += sizeof(di);
@@ -448,31 +449,39 @@ static int z_erofs_fill_inline_data(struct erofs_inode *inode, void *data,
 	return len;
 }
 
-static void tryrecompress_trailing(struct z_erofs_compress_sctx *ctx,
-				   struct erofs_compress *ec,
-				   void *in, unsigned int *insize,
-				   void *out, unsigned int *compressedsize)
+static int tryrecompress_trailing(struct z_erofs_compress_sctx *ctx,
+				  struct erofs_compress *ec,
+				  void *in, unsigned int *insize,
+				  void *out, unsigned int *compressedsize)
 {
 	struct erofs_sb_info *sbi = ctx->ictx->inode->sbi;
-	char tmp[Z_EROFS_PCLUSTER_MAX_SIZE];
+	char *tmp;
 	unsigned int count;
 	int ret = *compressedsize;
 
 	/* no need to recompress */
 	if (!(ret & (erofs_blksiz(sbi) - 1)))
-		return;
+		return 0;
+
+	tmp = malloc(Z_EROFS_PCLUSTER_MAX_SIZE);
+	if (!tmp)
+		return -ENOMEM;
 
 	count = *insize;
 	ret = erofs_compress_destsize(ec, in, &count, (void *)tmp,
 				      rounddown(ret, erofs_blksiz(sbi)));
 	if (ret <= 0 || ret + (*insize - count) >=
 			roundup(*compressedsize, erofs_blksiz(sbi)))
-		return;
+		goto out;
 
 	/* replace the original compressed data if any gain */
 	memcpy(out, tmp, ret);
 	*insize = count;
 	*compressedsize = ret;
+
+out:
+	free(tmp);
+	return 0;
 }
 
 static bool z_erofs_fixup_deduped_fragment(struct z_erofs_compress_sctx *ctx,
@@ -497,8 +506,8 @@ static bool z_erofs_fixup_deduped_fragment(struct z_erofs_compress_sctx *ctx,
 	inode->fragmentoff += inode->fragment_size - newsize;
 	inode->fragment_size = newsize;
 
-	erofs_dbg("Reducing fragment size to %u at %llu",
-		  inode->fragment_size, inode->fragmentoff | 0ULL);
+	erofs_dbg("Reducing fragment size to %llu at %llu",
+		  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);
 
 	/* it's the end */
 	DBG_BUGON(ctx->tail - ctx->head + ctx->remaining != newsize);
@@ -628,9 +637,14 @@ frag_packing:
 			goto fix_dedupedfrag;
 		}
 
-		if (may_inline && len == e->length)
-			tryrecompress_trailing(ctx, h, ctx->queue + ctx->head,
-					&e->length, dst, &compressedsize);
+		if (may_inline && len == e->length) {
+			ret = tryrecompress_trailing(ctx, h,
+						     ctx->queue + ctx->head,
+						     &e->length, dst,
+						     &compressedsize);
+			if (ret)
+				return ret;
+		}
 
 		e->compressedblks = BLK_ROUND_UP(sbi, compressedsize);
 		DBG_BUGON(e->compressedblks * blksz >= e->length);
@@ -742,8 +756,7 @@ static void *parse_legacy_indexes(struct z_erofs_compressindex_vec *cv,
 		struct z_erofs_lcluster_index *const di = db + i;
 		const unsigned int advise = le16_to_cpu(di->di_advise);
 
-		cv->clustertype = (advise >> Z_EROFS_LI_LCLUSTER_TYPE_BIT) &
-			((1 << Z_EROFS_LI_LCLUSTER_TYPE_BITS) - 1);
+		cv->clustertype = advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK;
 		cv->clusterofs = le16_to_cpu(di->di_clusterofs);
 
 		if (cv->clustertype == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
@@ -971,10 +984,8 @@ void z_erofs_drop_inline_pcluster(struct erofs_inode *inode)
 		struct z_erofs_lcluster_index *di =
 			(inode->compressmeta + inode->extent_isize) -
 			sizeof(struct z_erofs_lcluster_index);
-		__le16 advise =
-			cpu_to_le16(type << Z_EROFS_LI_LCLUSTER_TYPE_BIT);
 
-		di->di_advise = advise;
+		di->di_advise = cpu_to_le16(type);
 	} else if (inode->datalayout == EROFS_INODE_COMPRESSED_COMPACT) {
 		/* handle the last compacted 4B pack */
 		unsigned int eofs, base, pos, v, lo;
@@ -1453,12 +1464,8 @@ void *erofs_begin_compressed_file(struct erofs_inode *inode, int fd, u64 fpos)
 	inode->idata_size = 0;
 	inode->fragment_size = 0;
 
-	if (z_erofs_mt_enabled) {
-		ictx = malloc(sizeof(*ictx));
-		if (!ictx)
-			return ERR_PTR(-ENOMEM);
-		ictx->fd = dup(fd);
-	} else {
+	if (!z_erofs_mt_enabled ||
+	    (cfg.c_all_fragments && !erofs_is_packed_inode(inode))) {
 #ifdef EROFS_MT_ENABLED
 		pthread_mutex_lock(&g_ictx.mutex);
 		if (g_ictx.seg_num)
@@ -1468,6 +1475,11 @@ void *erofs_begin_compressed_file(struct erofs_inode *inode, int fd, u64 fpos)
 #endif
 		ictx = &g_ictx;
 		ictx->fd = fd;
+	} else {
+		ictx = malloc(sizeof(*ictx));
+		if (!ictx)
+			return ERR_PTR(-ENOMEM);
+		ictx->fd = dup(fd);
 	}
 
 	ictx->ccfg = &erofs_ccfg[inode->z_algorithmtype[0]];
@@ -1778,7 +1790,9 @@ int z_erofs_compress_init(struct erofs_sb_info *sbi, struct erofs_buffer_head *s
 					    cfg.c_mt_workers << 2,
 					    z_erofs_mt_wq_tls_alloc,
 					    z_erofs_mt_wq_tls_free);
-		z_erofs_mt_enabled = !ret;
+		if (ret)
+			return ret;
+		z_erofs_mt_enabled = true;
 	}
 	pthread_mutex_init(&g_ictx.mutex, NULL);
 	pthread_cond_init(&g_ictx.cond, NULL);
diff --git a/lib/compressor_lz4hc.c b/lib/compressor_lz4hc.c
index 1e1ccc7..9955c0d 100644
--- a/lib/compressor_lz4hc.c
+++ b/lib/compressor_lz4hc.c
@@ -4,7 +4,6 @@
  *             http://www.huawei.com/
  * Created by Gao Xiang <xiang@kernel.org>
  */
-#define LZ4_HC_STATIC_LINKING_ONLY (1)
 #include <lz4hc.h>
 #include "erofs/internal.h"
 #include "erofs/print.h"
diff --git a/lib/exclude.c b/lib/exclude.c
index e3c4ed5..5f6107b 100644
--- a/lib/exclude.c
+++ b/lib/exclude.c
@@ -8,6 +8,7 @@
 #include "erofs/list.h"
 #include "erofs/print.h"
 #include "erofs/exclude.h"
+#include "erofs/internal.h"
 
 #define EXCLUDE_RULE_EXACT_SIZE	offsetof(struct erofs_exclude_rule, reg)
 #define EXCLUDE_RULE_REGEX_SIZE	sizeof(struct erofs_exclude_rule)
diff --git a/lib/fragments.c b/lib/fragments.c
index 7591718..e2d3343 100644
--- a/lib/fragments.c
+++ b/lib/fragments.c
@@ -138,7 +138,7 @@ static int z_erofs_fragments_dedupe_find(struct erofs_inode *inode, int fd,
 	inode->fragment_size = deduped;
 	inode->fragmentoff = pos;
 
-	erofs_dbg("Dedupe %u tail data at %llu", inode->fragment_size,
+	erofs_dbg("Dedupe %llu tail data at %llu", inode->fragment_size | 0ULL,
 		  inode->fragmentoff | 0ULL);
 out:
 	free(data);
@@ -283,8 +283,8 @@ int z_erofs_pack_file_from_fd(struct erofs_inode *inode, int fd,
 		goto out;
 	}
 
-	erofs_dbg("Recording %u fragment data at %lu", inode->fragment_size,
-		  inode->fragmentoff);
+	erofs_dbg("Recording %llu fragment data at %llu",
+		  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);
 
 	if (memblock)
 		rc = z_erofs_fragments_dedupe_insert(memblock,
@@ -316,8 +316,8 @@ int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
 	if (fwrite(data, len, 1, packedfile) != 1)
 		return -EIO;
 
-	erofs_dbg("Recording %u fragment data at %lu", inode->fragment_size,
-		  inode->fragmentoff);
+	erofs_dbg("Recording %llu fragment data at %llu",
+		  inode->fragment_size | 0ULL, inode->fragmentoff | 0ULL);
 
 	ret = z_erofs_fragments_dedupe_insert(data, len, inode->fragmentoff,
 					      tofcrc);
diff --git a/lib/inode.c b/lib/inode.c
index b9dbbd6..0404a8d 100644
--- a/lib/inode.c
+++ b/lib/inode.c
@@ -6,6 +6,9 @@
  * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #define _GNU_SOURCE
+#ifdef EROFS_MT_ENABLED
+#include <pthread.h>
+#endif
 #include <string.h>
 #include <stdlib.h>
 #include <stdio.h>
@@ -171,14 +174,12 @@ struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
 	return d;
 }
 
-/* allocate main data for a inode */
-static int __allocate_inode_bh_data(struct erofs_inode *inode,
-				    unsigned long nblocks,
-				    int type)
+/* allocate main data for an inode */
+int erofs_allocate_inode_bh_data(struct erofs_inode *inode, erofs_blk_t nblocks)
 {
 	struct erofs_bufmgr *bmgr = inode->sbi->bmgr;
 	struct erofs_buffer_head *bh;
-	int ret;
+	int ret, type;
 
 	if (!nblocks) {
 		/* it has only tail-end data */
@@ -187,6 +188,7 @@ static int __allocate_inode_bh_data(struct erofs_inode *inode,
 	}
 
 	/* allocate main data buffer */
+	type = S_ISDIR(inode->i_mode) ? DIRA : DATA;
 	bh = erofs_balloc(bmgr, type, erofs_pos(inode->sbi, nblocks), 0, 0);
 	if (IS_ERR(bh))
 		return PTR_ERR(bh);
@@ -431,7 +433,7 @@ static int erofs_write_dir_file(struct erofs_inode *dir)
 	q = used = blkno = 0;
 
 	/* allocate dir main data */
-	ret = __allocate_inode_bh_data(dir, erofs_blknr(sbi, dir->i_size), DIRA);
+	ret = erofs_allocate_inode_bh_data(dir, erofs_blknr(sbi, dir->i_size));
 	if (ret)
 		return ret;
 
@@ -487,7 +489,7 @@ int erofs_write_file_from_buffer(struct erofs_inode *inode, char *buf)
 
 	inode->datalayout = EROFS_INODE_FLAT_INLINE;
 
-	ret = __allocate_inode_bh_data(inode, nblocks, DATA);
+	ret = erofs_allocate_inode_bh_data(inode, nblocks);
 	if (ret)
 		return ret;
 
@@ -514,15 +516,15 @@ static bool erofs_file_is_compressible(struct erofs_inode *inode)
 
 static int write_uncompressed_file_from_fd(struct erofs_inode *inode, int fd)
 {
-	int ret;
+	struct erofs_sb_info *sbi = inode->sbi;
 	erofs_blk_t nblocks, i;
 	unsigned int len;
-	struct erofs_sb_info *sbi = inode->sbi;
+	int ret;
 
 	inode->datalayout = EROFS_INODE_FLAT_INLINE;
 	nblocks = inode->i_size >> sbi->blkszbits;
 
-	ret = __allocate_inode_bh_data(inode, nblocks, DATA);
+	ret = erofs_allocate_inode_bh_data(inode, nblocks);
 	if (ret)
 		return ret;
 
@@ -819,6 +821,7 @@ noinline:
 	bh->fsprivate = erofs_igrab(inode);
 	bh->op = &erofs_write_inode_bhops;
 	inode->bh = bh;
+	inode->i_ino[0] = ++inode->sbi->inos;  /* inode serial number */
 	return 0;
 }
 
@@ -1112,7 +1115,6 @@ struct erofs_inode *erofs_new_inode(struct erofs_sb_info *sbi)
 		return ERR_PTR(-ENOMEM);
 
 	inode->sbi = sbi;
-	inode->i_ino[0] = sbi->inos++;	/* inode serial number */
 	inode->i_count = 1;
 	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
 
@@ -1139,7 +1141,7 @@ static struct erofs_inode *erofs_iget_from_srcpath(struct erofs_sb_info *sbi,
 	 * hard-link, just return it. Also don't lookup for directories
 	 * since hard-link directory isn't allowed.
 	 */
-	if (!S_ISDIR(st.st_mode)) {
+	if (!S_ISDIR(st.st_mode) && (!cfg.c_hard_dereference)) {
 		inode = erofs_iget(st.st_dev, st.st_ino);
 		if (inode)
 			return inode;
@@ -1196,7 +1198,8 @@ static int erofs_inode_reserve_data_blocks(struct erofs_inode *inode)
 	erofs_bdrop(bh, false);
 
 	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
-	tarerofs_blocklist_write(inode->u.i_blkaddr, nblocks, inode->i_ino[1]);
+	tarerofs_blocklist_write(inode->u.i_blkaddr, nblocks, inode->i_ino[1],
+				 alignedsz - inode->i_size);
 	return 0;
 }
 
@@ -1326,6 +1329,7 @@ struct erofs_mkfs_dfops {
 	pthread_cond_t full, empty, drain;
 	struct erofs_mkfs_jobitem *queue;
 	unsigned int entries, head, tail;
+	bool idle;	/* initialize as false before the dfops worker runs */
 };
 
 #define EROFS_MT_QUEUE_SIZE 128
@@ -1335,7 +1339,8 @@ static void erofs_mkfs_flushjobs(struct erofs_sb_info *sbi)
 	struct erofs_mkfs_dfops *q = sbi->mkfs_dfops;
 
 	pthread_mutex_lock(&q->lock);
-	pthread_cond_wait(&q->drain, &q->lock);
+	if (!q->idle)
+		pthread_cond_wait(&q->drain, &q->lock);
 	pthread_mutex_unlock(&q->lock);
 }
 
@@ -1345,6 +1350,8 @@ static void *erofs_mkfs_pop_jobitem(struct erofs_mkfs_dfops *q)
 
 	pthread_mutex_lock(&q->lock);
 	while (q->head == q->tail) {
+		/* the worker has handled everything only if sleeping here */
+		q->idle = true;
 		pthread_cond_signal(&q->drain);
 		pthread_cond_wait(&q->empty, &q->lock);
 	}
@@ -1388,8 +1395,10 @@ static int erofs_mkfs_go(struct erofs_sb_info *sbi,
 
 	item = q->queue + q->tail;
 	item->type = type;
-	memcpy(&item->u, elem, size);
+	if (size)
+		memcpy(&item->u, elem, size);
 	q->tail = (q->tail + 1) & (q->entries - 1);
+	q->idle = false;
 
 	pthread_cond_signal(&q->empty);
 	pthread_mutex_unlock(&q->lock);
@@ -1697,7 +1706,7 @@ static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
 {
 	struct erofs_sb_info *sbi = root->sbi;
 	struct erofs_inode *dumpdir = erofs_igrab(root);
-	int err;
+	int err, err2;
 
 	erofs_mark_parent_inode(root, root);	/* rootdir mark */
 	root->next_dirwrite = NULL;
@@ -1708,6 +1717,12 @@ static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
 		list_del(&root->i_hash);
 		erofs_insert_ihash(root);
 	} else if (cfg.c_root_xattr_isize) {
+		if (cfg.c_root_xattr_isize > EROFS_XATTR_ALIGN(
+				UINT16_MAX - sizeof(struct erofs_xattr_entry))) {
+			erofs_err("Invalid configuration for c_root_xattr_isize: %u (too large)",
+				  cfg.c_root_xattr_isize);
+			return -EINVAL;
+		}
 		root->xattr_isize = cfg.c_root_xattr_isize;
 	}
 
@@ -1724,7 +1739,6 @@ static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
 	}
 
 	do {
-		int err;
 		struct erofs_inode *dir = dumpdir;
 		/* used for adding sub-directories in reverse order due to FIFO */
 		struct erofs_inode *head, **last = &head;
@@ -1738,7 +1752,8 @@ static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
 				continue;
 
 			if (!erofs_inode_visited(inode)) {
-				DBG_BUGON(rebuild &&
+				DBG_BUGON(rebuild && (inode->i_nlink == 1 ||
+					  S_ISDIR(inode->i_mode)) &&
 					  erofs_parent_inode(inode) != dir);
 				erofs_mark_parent_inode(inode, dir);
 
@@ -1760,10 +1775,10 @@ static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
 		}
 		*last = dumpdir;	/* fixup the last (or the only) one */
 		dumpdir = head;
-		err = erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR_BH,
+		err2 = erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR_BH,
 				    &dir, sizeof(dir));
-		if (err)
-			return err;
+		if (err || err2)
+			return err ? err : err2;
 	} while (dumpdir);
 
 	return err;
@@ -1812,7 +1827,7 @@ static int erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
 	int err, err2;
 	struct erofs_sb_info *sbi = ctx->sbi ? ctx->sbi : ctx->u.root->sbi;
 
-	q = malloc(sizeof(*q));
+	q = calloc(1, sizeof(*q));
 	if (!q)
 		return -ENOMEM;
 
@@ -1827,8 +1842,6 @@ static int erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
 	pthread_cond_init(&q->full, NULL);
 	pthread_cond_init(&q->drain, NULL);
 
-	q->head = 0;
-	q->tail = 0;
 	sbi->mkfs_dfops = q;
 	err = pthread_create(&sbi->dfops_worker, NULL,
 			     z_erofs_mt_dfops_worker, sbi);
@@ -1922,7 +1935,9 @@ struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
 
 		DBG_BUGON(!ictx);
 		ret = erofs_write_compressed_file(ictx);
-		if (ret && ret != -ENOSPC)
+		if (!ret)
+			goto out;
+		if (ret != -ENOSPC)
 			 return ERR_PTR(ret);
 
 		ret = lseek(fd, 0, SEEK_SET);
@@ -1932,6 +1947,7 @@ struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
 	ret = write_uncompressed_file_from_fd(inode, fd);
 	if (ret)
 		return ERR_PTR(ret);
+out:
 	erofs_prepare_inode_buffer(inode);
 	erofs_write_tail_end(inode);
 	return inode;
diff --git a/lib/io.c b/lib/io.c
index b101c07..dacf8dc 100644
--- a/lib/io.c
+++ b/lib/io.c
@@ -342,7 +342,7 @@ ssize_t erofs_dev_read(struct erofs_sb_info *sbi, int device_id,
 	ssize_t read;
 
 	if (device_id) {
-		if (device_id >= sbi->nblobs) {
+		if (device_id > sbi->nblobs) {
 			erofs_err("invalid device id %d", device_id);
 			return -EIO;
 		}
diff --git a/lib/kite_deflate.c b/lib/kite_deflate.c
index 8581834..592c4d1 100644
--- a/lib/kite_deflate.c
+++ b/lib/kite_deflate.c
@@ -834,7 +834,7 @@ static int kite_mf_init(struct kite_matchfinder *mf, unsigned int wsiz,
 		return -EINVAL;
 	cfg = &kite_mfcfg[level];
 
-	if (wsiz > kHistorySize32 || (1 << ilog2(wsiz)) != wsiz)
+	if (wsiz > kHistorySize32 || (wsiz & (wsiz - 1)))
 		return -EINVAL;
 
 	mf->hash = calloc(0x10000, sizeof(mf->hash[0]));
@@ -892,7 +892,7 @@ static bool deflate_count_code(struct kite_deflate *s, bool literal,
 {
 	struct kite_deflate_table *t = s->tab;
 	unsigned int lenbase = (literal ? 0 : kSymbolMatch);
-	u64 rem = (s->outlen - s->pos_out) * 8 - s->bitpos;
+	u64 rem = (s->outlen - s->pos_out) * 8ULL - s->bitpos;
 	bool recalc = false;
 	unsigned int bits;
 
diff --git a/lib/rebuild.c b/lib/rebuild.c
index 08c1b86..3e58f00 100644
--- a/lib/rebuild.c
+++ b/lib/rebuild.c
@@ -46,6 +46,7 @@ static struct erofs_dentry *erofs_rebuild_mkdir(struct erofs_inode *dir,
 	inode->i_gid = getgid();
 	inode->i_mtime = inode->sbi->build_time;
 	inode->i_mtime_nsec = inode->sbi->build_time_nsec;
+	inode->dev = dir->dev;
 	erofs_init_empty_dir(inode);
 
 	d = erofs_d_alloc(dir, s);
@@ -465,7 +466,9 @@ static int erofs_rebuild_basedir_dirent_iter(struct erofs_dir_context *ctx)
 		struct erofs_inode *inode = d->inode;
 
 		/* update sub-directories only for recursively loading */
-		if (S_ISDIR(inode->i_mode)) {
+		if (S_ISDIR(inode->i_mode) &&
+		    (ctx->de_ftype == EROFS_FT_DIR ||
+		     ctx->de_ftype == EROFS_FT_UNKNOWN)) {
 			list_del(&inode->i_hash);
 			inode->dev = dir->sbi->dev;
 			inode->i_ino[1] = ctx->de_nid;
@@ -497,6 +500,15 @@ int erofs_rebuild_load_basedir(struct erofs_inode *dir)
 	if (__erofs_unlikely(IS_ROOT(dir)))
 		dir->xattr_isize = fakeinode.xattr_isize;
 
+	/*
+	 * May be triggered if ftype == EROFS_FT_UNKNOWN, which is impossible
+	 * with the current mkfs.
+	 */
+	if (__erofs_unlikely(!S_ISDIR(fakeinode.i_mode))) {
+		DBG_BUGON(1);
+		return 0;
+	}
+
 	ctx = (struct erofs_rebuild_dir_context) {
 		.ctx.dir = &fakeinode,
 		.ctx.cb = erofs_rebuild_basedir_dirent_iter,
diff --git a/lib/super.c b/lib/super.c
index 32e10cd..d4cea50 100644
--- a/lib/super.c
+++ b/lib/super.c
@@ -213,7 +213,8 @@ struct erofs_buffer_head *erofs_reserve_sb(struct erofs_bufmgr *bmgr)
 
 	bh = erofs_balloc(bmgr, META, 0, 0, 0);
 	if (IS_ERR(bh)) {
-		erofs_err("failed to allocate super: %s", PTR_ERR(bh));
+		erofs_err("failed to allocate super: %s",
+			  erofs_strerror(PTR_ERR(bh)));
 		return bh;
 	}
 	bh->op = &erofs_skip_write_bhops;
diff --git a/lib/tar.c b/lib/tar.c
index a9b425e..0dd990e 100644
--- a/lib/tar.c
+++ b/lib/tar.c
@@ -3,9 +3,6 @@
 #include <stdlib.h>
 #include <string.h>
 #include <sys/stat.h>
-#if defined(HAVE_ZLIB)
-#include <zlib.h>
-#endif
 #include "erofs/print.h"
 #include "erofs/cache.h"
 #include "erofs/diskbuf.h"
@@ -15,6 +12,9 @@
 #include "erofs/xattr.h"
 #include "erofs/blobchunk.h"
 #include "erofs/rebuild.h"
+#if defined(HAVE_ZLIB)
+#include <zlib.h>
+#endif
 
 /* This file is a tape/volume header.  Ignore it on extraction.  */
 #define GNUTYPE_VOLHDR 'V'
@@ -39,6 +39,15 @@ struct tar_header {
 	char padding[12];	/* 500-512 (pad to exactly the 512 byte) */
 };
 
+#ifdef HAVE_LIBLZMA
+#include <lzma.h>
+struct erofs_iostream_liblzma {
+	u8 inbuf[32768];
+	lzma_stream strm;
+	int fd;
+};
+#endif
+
 void erofs_iostream_close(struct erofs_iostream *ios)
 {
 	free(ios->buffer);
@@ -110,7 +119,7 @@ int erofs_iostream_open(struct erofs_iostream *ios, int fd, int decoder)
 					   erofs_strerror(-errno));
 #endif
 		}
-		ios->bufsize = 16384;
+		ios->bufsize = 32768;
 	}
 
 	do {
@@ -274,9 +283,9 @@ static long long tarerofs_otoi(const char *ptr, int len)
 	inp[len] = '\0';
 
 	errno = 0;
-	val = strtol(ptr, &endp, 8);
-	if ((!val && endp == inp) |
-	     (*endp && *endp != ' '))
+	val = strtol(inp, &endp, 8);
+	if ((*endp == '\0' && endp == inp) |
+	    (*endp != '\0' && *endp != ' '))
 		errno = EINVAL;
 	return val;
 }
@@ -577,6 +586,38 @@ void tarerofs_remove_inode(struct erofs_inode *inode)
 	--inode->i_parent->i_nlink;
 }
 
+static int tarerofs_write_uncompressed_file(struct erofs_inode *inode,
+					    struct erofs_tarfile *tar)
+{
+	struct erofs_sb_info *sbi = inode->sbi;
+	erofs_blk_t nblocks;
+	erofs_off_t pos;
+	void *buf;
+	int ret;
+
+	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
+	nblocks = DIV_ROUND_UP(inode->i_size, 1U << sbi->blkszbits);
+
+	ret = erofs_allocate_inode_bh_data(inode, nblocks);
+	if (ret)
+		return ret;
+
+	for (pos = 0; pos < inode->i_size; pos += ret) {
+		ret = erofs_iostream_read(&tar->ios, &buf, inode->i_size - pos);
+		if (ret < 0)
+			break;
+		if (erofs_dev_write(sbi, buf,
+				    erofs_pos(sbi, inode->u.i_blkaddr) + pos,
+				    ret)) {
+			ret = -EIO;
+			break;
+		}
+	}
+	inode->idata_size = 0;
+	inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
+	return 0;
+}
+
 static int tarerofs_write_file_data(struct erofs_inode *inode,
 				    struct erofs_tarfile *tar)
 {
@@ -626,6 +667,7 @@ int tarerofs_parse_tar(struct erofs_inode *root, struct erofs_tarfile *tar)
 	unsigned int j, csum, cksum;
 	int ckksum, ret, rem;
 
+	root->dev = tar->dev;
 	if (eh.path)
 		eh.path = strdup(eh.path);
 	if (eh.link)
@@ -654,18 +696,19 @@ restart:
 		goto out;
 	}
 	tar->offset += sizeof(*th);
-	if (*th->name == '\0') {
-		if (e) {	/* end of tar 2 empty blocks */
-			ret = 1;
-			goto out;
-		}
-		e = true;	/* empty jump to next block */
-		goto restart;
-	}
 
 	/* chksum field itself treated as ' ' */
 	csum = tarerofs_otoi(th->chksum, sizeof(th->chksum));
 	if (errno) {
+		if (*th->name == '\0') {
+out_eot:
+			if (e) {	/* end of tar 2 empty blocks */
+				ret = 1;
+				goto out;
+			}
+			e = true;	/* empty jump to next block */
+			goto restart;
+		}
 		erofs_err("invalid chksum @ %llu", tar_offset);
 		ret = -EBADMSG;
 		goto out;
@@ -683,6 +726,11 @@ restart:
 		ckksum += (int)((char*)th)[j];
 	}
 	if (!tar->ddtaridx_mode && csum != cksum && csum != ckksum) {
+		/* should not bail out here, just in case */
+		if (*th->name == '\0') {
+			DBG_BUGON(1);
+			goto out_eot;
+		}
 		erofs_err("chksum mismatch @ %llu", tar_offset);
 		ret = -EBADMSG;
 		goto out;
@@ -761,13 +809,14 @@ restart:
 	}
 
 	dataoff = tar->offset;
-	if (!(tar->headeronly_mode || tar->ddtaridx_mode))
-		tar->offset += st.st_size;
+	tar->offset += st.st_size;
 	switch(th->typeflag) {
 	case '0':
 	case '7':
 	case '1':
 		st.st_mode |= S_IFREG;
+		if (tar->headeronly_mode || tar->ddtaridx_mode)
+			tar->offset -= st.st_size;
 		break;
 	case '2':
 		st.st_mode |= S_IFLNK;
@@ -997,6 +1046,10 @@ new_inode:
 				if (!ret && erofs_iostream_lskip(&tar->ios,
 								 inode->i_size))
 					ret = -EIO;
+			} else if (tar->try_no_reorder &&
+				   !cfg.c_compr_opts[0].alg &&
+				   !cfg.c_inline_data) {
+				ret = tarerofs_write_uncompressed_file(inode, tar);
 			} else {
 				ret = tarerofs_write_file_data(inode, tar);
 			}
diff --git a/lib/workqueue.c b/lib/workqueue.c
index 47cec9b..18ee0f9 100644
--- a/lib/workqueue.c
+++ b/lib/workqueue.c
@@ -15,9 +15,9 @@ static void *worker_thread(void *arg)
 	while (true) {
 		pthread_mutex_lock(&wq->lock);
 
-		while (wq->job_count == 0 && !wq->shutdown)
+		while (!wq->job_count && !wq->shutdown)
 			pthread_cond_wait(&wq->cond_empty, &wq->lock);
-		if (wq->job_count == 0 && wq->shutdown) {
+		if (!wq->job_count && wq->shutdown) {
 			pthread_mutex_unlock(&wq->lock);
 			break;
 		}
@@ -40,6 +40,30 @@ static void *worker_thread(void *arg)
 	return NULL;
 }
 
+int erofs_destroy_workqueue(struct erofs_workqueue *wq)
+{
+	if (!wq)
+		return -EINVAL;
+
+	pthread_mutex_lock(&wq->lock);
+	wq->shutdown = true;
+	pthread_cond_broadcast(&wq->cond_empty);
+	pthread_mutex_unlock(&wq->lock);
+
+	while (wq->nworker) {
+		int ret = -pthread_join(wq->workers[wq->nworker - 1], NULL);
+
+		if (ret)
+			return ret;
+		--wq->nworker;
+	}
+	free(wq->workers);
+	pthread_mutex_destroy(&wq->lock);
+	pthread_cond_destroy(&wq->cond_empty);
+	pthread_cond_destroy(&wq->cond_full);
+	return 0;
+}
+
 int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
 			  unsigned int max_jobs, erofs_wq_func_t on_start,
 			  erofs_wq_func_t on_exit)
@@ -51,7 +75,6 @@ int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
 		return -EINVAL;
 
 	wq->head = wq->tail = NULL;
-	wq->nworker = nworker;
 	wq->max_jobs = max_jobs;
 	wq->job_count = 0;
 	wq->shutdown = false;
@@ -66,15 +89,14 @@ int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
 		return -ENOMEM;
 
 	for (i = 0; i < nworker; i++) {
-		ret = pthread_create(&wq->workers[i], NULL, worker_thread, wq);
-		if (ret) {
-			while (i)
-				pthread_cancel(wq->workers[--i]);
-			free(wq->workers);
-			return ret;
-		}
+		ret = -pthread_create(&wq->workers[i], NULL, worker_thread, wq);
+		if (ret)
+			break;
 	}
-	return 0;
+	wq->nworker = i;
+	if (ret)
+		erofs_destroy_workqueue(wq);
+	return ret;
 }
 
 int erofs_queue_work(struct erofs_workqueue *wq, struct erofs_work *work)
@@ -99,25 +121,3 @@ int erofs_queue_work(struct erofs_workqueue *wq, struct erofs_work *work)
 	pthread_mutex_unlock(&wq->lock);
 	return 0;
 }
-
-int erofs_destroy_workqueue(struct erofs_workqueue *wq)
-{
-	unsigned int i;
-
-	if (!wq)
-		return -EINVAL;
-
-	pthread_mutex_lock(&wq->lock);
-	wq->shutdown = true;
-	pthread_cond_broadcast(&wq->cond_empty);
-	pthread_mutex_unlock(&wq->lock);
-
-	for (i = 0; i < wq->nworker; i++)
-		pthread_join(wq->workers[i], NULL);
-
-	free(wq->workers);
-	pthread_mutex_destroy(&wq->lock);
-	pthread_cond_destroy(&wq->cond_empty);
-	pthread_cond_destroy(&wq->cond_full);
-	return 0;
-}
diff --git a/lib/xattr.c b/lib/xattr.c
index 651657f..e420775 100644
--- a/lib/xattr.c
+++ b/lib/xattr.c
@@ -138,8 +138,8 @@ struct ea_type_node {
 static LIST_HEAD(ea_name_prefixes);
 static unsigned int ea_prefix_count;
 
-static bool match_prefix(const char *key, unsigned int *index,
-			 unsigned int *len)
+bool erofs_xattr_prefix_matches(const char *key, unsigned int *index,
+				unsigned int *len)
 {
 	struct xattr_prefix *p;
 
@@ -169,6 +169,7 @@ static unsigned int put_xattritem(struct xattr_item *item)
 {
 	if (item->count > 1)
 		return --item->count;
+	hash_del(&item->node);
 	free(item);
 	return 0;
 }
@@ -196,7 +197,8 @@ static struct xattr_item *get_xattritem(char *kvbuf, unsigned int len[2])
 	if (!item)
 		return ERR_PTR(-ENOMEM);
 
-	if (!match_prefix(kvbuf, &item->base_index, &item->prefix_len)) {
+	if (!erofs_xattr_prefix_matches(kvbuf, &item->base_index,
+					&item->prefix_len)) {
 		free(item);
 		return ERR_PTR(-ENODATA);
 	}
@@ -448,6 +450,9 @@ static int read_xattrs_from_file(const char *path, mode_t mode,
 			ret = PTR_ERR(item);
 			goto err;
 		}
+		/* skip unidentified xattrs */
+		if (!item)
+			continue;
 
 		ret = erofs_xattr_add(ixattrs, item);
 		if (ret < 0)
@@ -794,10 +799,10 @@ static int comp_shared_xattr_item(const void *a, const void *b)
 
 	ia = *((const struct xattr_item **)a);
 	ib = *((const struct xattr_item **)b);
-	la = ia->len[0] + ia->len[1];
-	lb = ib->len[0] + ib->len[1];
+	la = EROFS_XATTR_KVSIZE(ia->len);
+	lb = EROFS_XATTR_KVSIZE(ib->len);
 
-	ret = strncmp(ia->kvbuf, ib->kvbuf, min(la, lb));
+	ret = memcmp(ia->kvbuf, ib->kvbuf, min(la, lb));
 	if (ret != 0)
 		return ret;
 
@@ -1422,7 +1427,7 @@ int erofs_getxattr(struct erofs_inode *vi, const char *name, char *buffer,
 	if (ret)
 		return ret;
 
-	if (!match_prefix(name, &prefix, &prefixlen))
+	if (!erofs_xattr_prefix_matches(name, &prefix, &prefixlen))
 		return -ENODATA;
 
 	it.it.sbi = vi->sbi;
@@ -1597,7 +1602,8 @@ int erofs_xattr_insert_name_prefix(const char *prefix)
 	if (!tnode)
 		return -ENOMEM;
 
-	if (!match_prefix(prefix, &tnode->base_index, &tnode->base_len)) {
+	if (!erofs_xattr_prefix_matches(prefix, &tnode->base_index,
+					&tnode->base_len)) {
 		free(tnode);
 		return -ENODATA;
 	}
diff --git a/lib/zmap.c b/lib/zmap.c
index a5c5b00..f1cdc66 100644
--- a/lib/zmap.c
+++ b/lib/zmap.c
@@ -142,8 +142,8 @@ static int z_erofs_reload_indexes(struct z_erofs_maprecorder *m,
 	return 0;
 }
 
-static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
-					 unsigned long lcn)
+static int z_erofs_load_full_lcluster(struct z_erofs_maprecorder *m,
+				      unsigned long lcn)
 {
 	struct erofs_inode *const vi = m->inode;
 	struct erofs_sb_info *sbi = vi->sbi;
@@ -152,7 +152,7 @@ static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
 			vi->inode_isize + vi->xattr_isize) +
 		lcn * sizeof(struct z_erofs_lcluster_index);
 	struct z_erofs_lcluster_index *di;
-	unsigned int advise, type;
+	unsigned int advise;
 	int err;
 
 	err = z_erofs_reload_indexes(m, erofs_blknr(sbi, pos));
@@ -164,10 +164,8 @@ static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
 	di = m->kaddr + erofs_blkoff(sbi, pos);
 
 	advise = le16_to_cpu(di->di_advise);
-	type = (advise >> Z_EROFS_LI_LCLUSTER_TYPE_BIT) &
-		((1 << Z_EROFS_LI_LCLUSTER_TYPE_BITS) - 1);
-	switch (type) {
-	case Z_EROFS_LCLUSTER_TYPE_NONHEAD:
+	m->type = advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK;
+	if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
 		m->clusterofs = 1 << vi->z_logical_clusterbits;
 		m->delta[0] = le16_to_cpu(di->di_u.delta[0]);
 		if (m->delta[0] & Z_EROFS_LI_D0_CBLKCNT) {
@@ -180,19 +178,11 @@ static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
 			m->delta[0] = 1;
 		}
 		m->delta[1] = le16_to_cpu(di->di_u.delta[1]);
-		break;
-	case Z_EROFS_LCLUSTER_TYPE_PLAIN:
-	case Z_EROFS_LCLUSTER_TYPE_HEAD1:
-		if (advise & Z_EROFS_LI_PARTIAL_REF)
-			m->partialref = true;
+	} else {
+		m->partialref = !!(advise & Z_EROFS_LI_PARTIAL_REF);
 		m->clusterofs = le16_to_cpu(di->di_clusterofs);
 		m->pblk = le32_to_cpu(di->di_u.blkaddr);
-		break;
-	default:
-		DBG_BUGON(1);
-		return -EOPNOTSUPP;
 	}
-	m->type = type;
 	return 0;
 }
 
@@ -337,8 +327,8 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 	return 0;
 }
 
-static int compacted_load_cluster_from_disk(struct z_erofs_maprecorder *m,
-					    unsigned long lcn, bool lookahead)
+static int z_erofs_load_compact_lcluster(struct z_erofs_maprecorder *m,
+					 unsigned long lcn, bool lookahead)
 {
 	struct erofs_inode *const vi = m->inode;
 	struct erofs_sb_info *sbi = vi->sbi;
@@ -389,18 +379,17 @@ out:
 	return unpack_compacted_index(m, amortizedshift, pos, lookahead);
 }
 
-static int z_erofs_load_cluster_from_disk(struct z_erofs_maprecorder *m,
-					  unsigned int lcn, bool lookahead)
+static int z_erofs_load_lcluster_from_disk(struct z_erofs_maprecorder *m,
+					   unsigned int lcn, bool lookahead)
 {
-	const unsigned int datamode = m->inode->datalayout;
-
-	if (datamode == EROFS_INODE_COMPRESSED_FULL)
-		return legacy_load_cluster_from_disk(m, lcn);
-
-	if (datamode == EROFS_INODE_COMPRESSED_COMPACT)
-		return compacted_load_cluster_from_disk(m, lcn, lookahead);
-
-	return -EINVAL;
+	switch (m->inode->datalayout) {
+	case EROFS_INODE_COMPRESSED_FULL:
+		return z_erofs_load_full_lcluster(m, lcn);
+	case EROFS_INODE_COMPRESSED_COMPACT:
+		return z_erofs_load_compact_lcluster(m, lcn, lookahead);
+	default:
+		return -EINVAL;
+	}
 }
 
 static int z_erofs_extent_lookback(struct z_erofs_maprecorder *m,
@@ -421,7 +410,7 @@ static int z_erofs_extent_lookback(struct z_erofs_maprecorder *m,
 
 	/* load extent head logical cluster if needed */
 	lcn -= lookback_distance;
-	err = z_erofs_load_cluster_from_disk(m, lcn, false);
+	err = z_erofs_load_lcluster_from_disk(m, lcn, false);
 	if (err)
 		return err;
 
@@ -471,7 +460,7 @@ static int z_erofs_get_extent_compressedlen(struct z_erofs_maprecorder *m,
 	if (m->compressedblks)
 		goto out;
 
-	err = z_erofs_load_cluster_from_disk(m, lcn, false);
+	err = z_erofs_load_lcluster_from_disk(m, lcn, false);
 	if (err)
 		return err;
 
@@ -532,7 +521,7 @@ static int z_erofs_get_extent_decompressedlen(struct z_erofs_maprecorder *m)
 			return 0;
 		}
 
-		err = z_erofs_load_cluster_from_disk(m, lcn, true);
+		err = z_erofs_load_lcluster_from_disk(m, lcn, true);
 		if (err)
 			return err;
 
@@ -581,7 +570,7 @@ static int z_erofs_do_map_blocks(struct erofs_inode *vi,
 	initial_lcn = ofs >> lclusterbits;
 	endoff = ofs & ((1 << lclusterbits) - 1);
 
-	err = z_erofs_load_cluster_from_disk(&m, initial_lcn, false);
+	err = z_erofs_load_lcluster_from_disk(&m, initial_lcn, false);
 	if (err)
 		goto out;
 
diff --git a/man/fsck.erofs.1 b/man/fsck.erofs.1
index 393ae9e..af0e6ab 100644
--- a/man/fsck.erofs.1
+++ b/man/fsck.erofs.1
@@ -34,6 +34,9 @@ take a long time depending on the image size.
 
 Optionally extract contents of the \fIIMAGE\fR to \fIdirectory\fR.
 .TP
+.BI "--[no-]xattrs"
+Whether to dump extended attributes during extraction (default off).
+.TP
 \fB\-h\fR, \fB\-\-help\fR
 Display help string and exit.
 .TP
diff --git a/man/mkfs.erofs.1 b/man/mkfs.erofs.1
index d599fac..0093839 100644
--- a/man/mkfs.erofs.1
+++ b/man/mkfs.erofs.1
@@ -110,6 +110,17 @@ Set the universally unique identifier (UUID) of the filesystem to
 .IR UUID .
 The format of the UUID is a series of hex digits separated by hyphens,
 like this: "c1b9d5a2-f162-11cf-9ece-0020afc76f16".
+The
+.I UUID
+parameter may also be one of the following:
+.RS 1.2i
+.TP
+.I clear
+clear the file system UUID
+.TP
+.I random
+generate a new randomly-generated UUID
+.RE
 .TP
 .B \-\-all-root
 Make all files owned by root.
@@ -192,7 +203,18 @@ Use extended inodes instead of compact inodes if the file modification time
 would overflow compact inodes. This is the default. Overrides
 .BR --ignore-mtime .
 .TP
-.BI "\-\-tar, \-\-tar="MODE
+.BI "\-\-sort=" MODE
+Inode data sorting order for tarballs as input.
+
+\fIMODE\fR may be one of \fBnone\fR or \fBpath\fR.
+
+\fBnone\fR: No particular data order is specified for the target image to
+avoid unnecessary overhead; Currently, it takes effect if `-E^inline_data` is
+specified and no compression is applied.
+
+\fBpath\fR: Data order strictly follows the tree generation order. (default)
+.TP
+.BI "\-\-tar, \-\-tar=" MODE
 Treat \fISOURCE\fR as a tarball or tarball-like "headerball" rather than as a
 directory.
 
diff --git a/mkfs/main.c b/mkfs/main.c
index b7129eb..9ca7dad 100644
--- a/mkfs/main.c
+++ b/mkfs/main.c
@@ -84,6 +84,8 @@ static struct option long_options[] = {
 	{"root-xattr-isize", required_argument, NULL, 524},
 	{"mkfs-time", no_argument, NULL, 525},
 	{"all-time", no_argument, NULL, 526},
+	{"sort", required_argument, NULL, 527},
+	{"hard-dereference", no_argument, NULL, 528},
 	{0, 0, 0, 0},
 };
 
@@ -151,7 +153,7 @@ static void usage(int argc, char **argv)
 	printf(
 		" -C#                   specify the size of compress physical cluster in bytes\n"
 		" -EX[,...]             X=extended options\n"
-		" -L volume-label       set the volume label (maximum 16)\n"
+		" -L volume-label       set the volume label (maximum 15 bytes)\n"
 		" -T#                   specify a fixed UNIX timestamp # as build time\n"
 		"    --all-time         the timestamp is also applied to all files (default)\n"
 		"    --mkfs-time        the timestamp is applied as build time only\n"
@@ -173,6 +175,7 @@ static void usage(int argc, char **argv)
 		" --force-gid=#         set all file gids to # (# = GID)\n"
 		" --uid-offset=#        add offset # to all file uids (# = id offset)\n"
 		" --gid-offset=#        add offset # to all file gids (# = id offset)\n"
+		" --hard-dereference    dereference hardlinks, add links as separate inodes\n"
 		" --ignore-mtime        use build time instead of strict per-file modification time\n"
 		" --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
 		" --mount-point=X       X=prefix of target fs path (default: /)\n"
@@ -180,6 +183,7 @@ static void usage(int argc, char **argv)
 		" --offset=#            skip # bytes at the beginning of IMAGE.\n"
 		" --root-xattr-isize=#  ensure the inline xattr size of the root directory is # bytes at least\n"
 		" --aufs                replace aufs special files with overlayfs metadata\n"
+		" --sort=<path,none>    data sorting order for tarballs as input (default: path)\n"
 		" --tar=X               generate a full or index-only image from a tarball(-ish) source\n"
 		"                       (X = f|i|headerball; f=full mode, i=index mode,\n"
 		"                                            headerball=file data is omited in the source stream)\n"
@@ -274,7 +278,7 @@ static int erofs_mkfs_feat_set_fragments(bool en, const char *val,
 		u64 i = strtoull(val, &endptr, 0);
 
 		if (endptr - val != vallen) {
-			erofs_err("invalid pcluster size %s for the packed file %s", val);
+			erofs_err("invalid pcluster size %s for the packed file", val);
 			return -EINVAL;
 		}
 		pclustersize_packed = i;
@@ -598,7 +602,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 
 		case 'L':
 			if (optarg == NULL ||
-			    strlen(optarg) > sizeof(g_sbi.volume_name)) {
+			    strlen(optarg) > (sizeof(g_sbi.volume_name) - 1u)) {
 				erofs_err("invalid volume label");
 				return -EINVAL;
 			}
@@ -615,7 +619,12 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 			has_timestamp = true;
 			break;
 		case 'U':
-			if (erofs_uuid_parse(optarg, fixeduuid)) {
+			if (!strcmp(optarg, "clear")) {
+				memset(fixeduuid, 0, 16);
+			} else if (!strcmp(optarg, "random")) {
+				valid_fixeduuid = false;
+				break;
+			} else if (erofs_uuid_parse(optarg, fixeduuid)) {
 				erofs_err("invalid UUID %s", optarg);
 				return -EINVAL;
 			}
@@ -840,6 +849,13 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 		case 526:
 			cfg.c_timeinherit = TIMESTAMP_FIXED;
 			break;
+		case 527:
+			if (!strcmp(optarg, "none"))
+				erofstar.try_no_reorder = true;
+			break;
+		case 528:
+			cfg.c_hard_dereference = true;
+			break;
 		case 'V':
 			version();
 			exit(0);
@@ -965,11 +981,6 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 		cfg.c_showprogress = false;
 	}
 
-	if (cfg.c_compr_opts[0].alg && erofs_blksiz(&g_sbi) != getpagesize())
-		erofs_warn("Please note that subpage blocksize with compression isn't yet supported in kernel. "
-			   "This compressed image will only work with bs = ps = %u bytes",
-			   erofs_blksiz(&g_sbi));
-
 	if (pclustersize_max) {
 		if (pclustersize_max < erofs_blksiz(&g_sbi) ||
 		    pclustersize_max % erofs_blksiz(&g_sbi)) {
@@ -1091,7 +1102,8 @@ static int erofs_mkfs_rebuild_load_trees(struct erofs_inode *root)
 	if (datamode != EROFS_REBUILD_DATA_BLOB_INDEX)
 		return 0;
 
-	if (extra_devices != rebuild_src_count) {
+	/* Each blob has either no extra device or only one device for TarFS */
+	if (extra_devices && extra_devices != rebuild_src_count) {
 		erofs_err("extra_devices(%u) is mismatched with source images(%u)",
 			  extra_devices, rebuild_src_count);
 		return -EOPNOTSUPP;
diff --git a/scripts/get-version-number b/scripts/get-version-number
index 26f0b5a..d216b7a 100755
--- a/scripts/get-version-number
+++ b/scripts/get-version-number
@@ -9,7 +9,7 @@ scm_version()
 		# If we are at a tagged commit, we ignore it.
 		if [ -z "$(git describe --exact-match 2>/dev/null)" ]; then
 			# Add -g and 8 hex chars.
-			printf '%s%s' -g "$(echo $head | cut -c1-8)"
+			printf -- '-g%.8s' "$head"
 		fi
 		# Check for uncommitted changes.
 		# This script must avoid any write attempt to the source tree,
@@ -30,4 +30,8 @@ scm_version()
 	fi
 }
 
-echo $(sed -n '1p' VERSION | tr -d '\n')$(scm_version)
+if [ -n "$EROFS_UTILS_VERSION" ]; then
+	echo "$EROFS_UTILS_VERSION"
+else
+	echo $(head -n1 VERSION)$(scm_version)
+fi
```

