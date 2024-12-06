```diff
diff --git a/Android.bp b/Android.bp
index 9c565e0..9d1518d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -126,6 +126,8 @@ cc_library {
     ],
     exclude_srcs: [
         "lib/compressor_libdeflate.c",
+        "lib/compressor_libzstd.c",
+        "lib/workqueue.c",
     ],
     export_include_dirs: ["include"],
 
diff --git a/ChangeLog b/ChangeLog
index 99220c8..676243c 100644
--- a/ChangeLog
+++ b/ChangeLog
@@ -1,3 +1,28 @@
+erofs-utils 1.8.1
+
+ * A quick maintenance release includes the following fixes:
+   - (mkfs.erofs) fix unexpected data truncation of large uncompressed files;
+   - (erofsfuse) fix decompression errors when using libdeflate compressor;
+   - (mkfs.erofs) fix an out-of-bound memory read issue with kite-deflate.
+
+ -- Gao Xiang <xiang@kernel.org>  Sat, 10 Aug 2024 00:00:00 +0800
+
+erofs-utils 1.8
+
+ * This release includes the following updates:
+   - (mkfs.erofs) support multi-threaded compression (Yifan Zhao);
+   - support Intel IAA hardware accelerator with Intel QPL;
+   - add preliminary Zstandard support;
+   - (erofsfuse) use FUSE low-level APIs and support multi-threading (Li Yiyan);
+   - (mkfs.erofs) support tar source without data (Mike Baynton);
+   - (mkfs.erofs) support incremental builds (incomplete, EXPERIMENTAL);
+   - (mkfs.erofs) other build performance improvements;
+   - (erofsfuse) support building erofsfuse as a static library (ComixHe);
+   - various bugfixes and cleanups (Sandeep Dhavale, Noboru Asai,
+           Luke T. Shumaker, Yifan Zhao, Hongzhen Luo and Tianyi Liu).
+
+ -- Gao Xiang <xiang@kernel.org>  Fri, 09 Aug 2024 00:00:00 +0800
+
 erofs-utils 1.7.1
 
  * A quick maintenance release includes the following fixes:
diff --git a/METADATA b/METADATA
index 2b7423b..e32d588 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update erofs-utils
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/erofs-utils
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "erofs-utils"
 description: "EROFS Utilities"
 third_party {
-  url {
-    type: GIT
-    value: "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"
-  }
-  version: "v1.7.1"
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2023
-    month: 10
-    day: 23
+    year: 2024
+    month: 9
+    day: 16
+  }
+  identifier {
+    type: "Git"
+    value: "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"
+    version: "v1.8.1"
   }
 }
diff --git a/README b/README
index e224b23..077b62b 100644
--- a/README
+++ b/README
@@ -54,51 +54,91 @@ mkfs.erofs
 
 Two main kinds of EROFS images can be generated: (un)compressed images.
 
- - For uncompressed images, there will be none of compresssed files in
-   these images.  However, it can decide whether the tail block of a
-   file should be inlined or not properly [1].
+ - For uncompressed images, there will be no compressed files in these
+   images.  However, an EROFS image can contain files which consist of
+   various aligned data blocks and then a tail that is stored inline in
+   order to compact images [1].
 
- - For compressed images, it'll try to use the given algorithms first
+ - For compressed images, it will try to use the given algorithms first
    for each regular file and see if storage space can be saved with
-   compression. If not, fallback to an uncompressed file.
+   compression. If not, it will fall back to an uncompressed file.
 
-How to generate EROFS images (LZ4 for Linux 5.3+, LZMA for Linux 5.16+)
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+Note that EROFS supports per-file compression configuration, proper
+configuration options need to be enabled to parse compressed files by
+the Linux kernel.
 
-Currently lz4(hc) and lzma are available for compression, e.g.
+How to generate EROFS images
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+Compression algorithms could be specified with the command-line option
+`-z` to build a compressed EROFS image from a local directory:
  $ mkfs.erofs -zlz4hc foo.erofs.img foo/
 
-Or leave all files uncompressed as an option:
+Supported algorithms by the Linux kernel:
+ - LZ4 (Linux 5.3+);
+ - LZMA (Linux 5.16+);
+ - DEFLATE (Linux 6.6+);
+ - Zstandard (Linux 6.10+).
+
+Alternatively, generate an uncompressed EROFS from a local directory:
  $ mkfs.erofs foo.erofs.img foo/
 
-In addition, you could specify a higher compression level to get a
-(slightly) better compression ratio than the default level, e.g.
+Additionally, you can specify a higher compression level to get a
+(slightly) smaller image than the default level:
  $ mkfs.erofs -zlz4hc,12 foo.erofs.img foo/
 
-Note that all compressors are still single-threaded for now, thus it
-could take more time on the multiprocessor platform. Multi-threaded
-approach is already in our TODO list.
+Multi-threaded support can be explicitly enabled with the ./configure
+option `--enable-multithreading`; otherwise, single-threaded compression
+will be used for now.  It may take more time on multiprocessor platforms
+if multi-threaded support is not enabled.
+
+Currently, both `-Efragments` (not `-Eall-fragments`) and `-Ededupe`
+don't support multi-threading due to time limitations.
+
+Reproducible builds
+~~~~~~~~~~~~~~~~~~~
+
+Reproducible builds are typically used for verification and security,
+ensuring the same binaries/distributions to be reproduced in a
+deterministic way.
+
+Images generated by the same version of `mkfs.erofs` will be identical
+to previous runs if the same input is specified, and the same options
+are used.
+
+Specifically, variable timestamps and filesystem UUIDs can result in
+unreproducible EROFS images.  `-T` and `-U` can be used to fix them.
 
 How to generate EROFS big pcluster images (Linux 5.13+)
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
-In order to get much better compression ratios (thus better sequential
-read performance for common storage devices), big pluster feature has
-been introduced since linux-5.13, which is not forward-compatible with
-old kernels.
-
-In details, -C is used to specify the maximum size of each big pcluster
-in bytes, e.g.
+By default, EROFS formatter compresses data into separate one-block
+(e.g. 4KiB) filesystem physical clusters for outstanding random read
+performance.  In other words, each EROFS filesystem block can be
+independently decompressed.  However, other similar filesystems
+typically compress data into "blocks" of 128KiB or more for much smaller
+images.  Users may prefer smaller images for archiving purposes, even if
+random performance is compromised with those configurations, and even
+worse when using 4KiB blocks.
+
+In order to fulfill users' needs, big plusters has been introduced
+since Linux 5.13, in which each physical clusters will be more than one
+blocks.
+
+Specifically, `-C` is used to specify the maximum size of each pcluster
+in bytes:
  $ mkfs.erofs -zlz4hc -C65536 foo.erofs.img foo/
 
-So in that case, pcluster size can be 64KiB at most.
+Thus, in this case, pcluster sizes can be up to 64KiB.
 
-Note that large pcluster size can cause bad random performance, so
-please evaluate carefully in advance. Or make your own per-(sub)file
-compression strategies according to file access patterns if needed.
+Note that large pcluster size can degrade random performance (though it
+may improve sequential read performance for typical storage devices), so
+please evaluate carefully in advance.  Alternatively, you can make
+per-(sub)file compression strategies according to file access patterns
+if needed.
 
-How to generate EROFS images with multiple algorithms (Linux 5.16+)
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+How to generate EROFS images with multiple algorithms
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 It's possible to generate an EROFS image with files in different
 algorithms due to various purposes.  For example, LZMA for archival
diff --git a/VERSION b/VERSION
index 8cf9ed8..20a0e9a 100644
--- a/VERSION
+++ b/VERSION
@@ -1,2 +1,2 @@
-1.7.1
-2023-10-20
+1.8.1
+2024-08-10
diff --git a/configure.ac b/configure.ac
index a546310..945e254 100644
--- a/configure.ac
+++ b/configure.ac
@@ -96,6 +96,14 @@ AC_DEFUN([EROFS_UTILS_PARSE_DIRECTORY],
 
 AC_ARG_VAR([MAX_BLOCK_SIZE], [The maximum block size which erofs-utils supports])
 
+AC_MSG_CHECKING([whether to enable multi-threading support])
+AC_ARG_ENABLE([multithreading],
+    AS_HELP_STRING([--enable-multithreading],
+                   [enable multi-threading support (EXPERIMENTAL) @<:@default=no@:>@]),
+    [enable_multithreading="$enableval"],
+    [enable_multithreading="no"])
+AC_MSG_RESULT([$enable_multithreading])
+
 AC_ARG_ENABLE([debug],
     [AS_HELP_STRING([--enable-debug],
                     [enable debugging mode @<:@default=no@:>@])],
@@ -119,22 +127,37 @@ AC_ARG_ENABLE(lz4,
    [enable_lz4="$enableval"], [enable_lz4="yes"])
 
 AC_ARG_ENABLE(lzma,
-   [AS_HELP_STRING([--enable-lzma], [enable LZMA compression support @<:@default=no@:>@])],
-   [enable_lzma="$enableval"], [enable_lzma="no"])
+   [AS_HELP_STRING([--disable-lzma], [disable LZMA compression support @<:@default=auto@:>@])],
+   [enable_lzma="$enableval"])
 
 AC_ARG_WITH(zlib,
    [AS_HELP_STRING([--without-zlib],
-      [Ignore presence of zlib inflate support @<:@default=enabled@:>@])])
+      [Ignore presence of zlib inflate support @<:@default=auto@:>@])])
 
 AC_ARG_WITH(libdeflate,
    [AS_HELP_STRING([--with-libdeflate],
       [Enable and build with libdeflate inflate support @<:@default=disabled@:>@])], [],
       [with_libdeflate="no"])
 
+AC_ARG_WITH(libzstd,
+   [AS_HELP_STRING([--with-libzstd],
+      [Enable and build with of libzstd support @<:@default=auto@:>@])])
+
+AC_ARG_WITH(qpl,
+   [AS_HELP_STRING([--with-qpl],
+      [Enable and build with Intel QPL support @<:@default=disabled@:>@])], [],
+      [with_qpl="no"])
+
 AC_ARG_ENABLE(fuse,
    [AS_HELP_STRING([--enable-fuse], [enable erofsfuse @<:@default=no@:>@])],
    [enable_fuse="$enableval"], [enable_fuse="no"])
 
+AC_ARG_ENABLE([static-fuse],
+    [AS_HELP_STRING([--enable-static-fuse],
+                    [build erofsfuse as a static library @<:@default=no@:>@])],
+    [enable_static_fuse="$enableval"],
+    [enable_static_fuse="no"])
+
 AC_ARG_WITH(uuid,
    [AS_HELP_STRING([--without-uuid],
       [Ignore presence of libuuid and disable uuid support @<:@default=enabled@:>@])])
@@ -161,14 +184,6 @@ AC_ARG_WITH(lz4-libdir,
 AC_ARG_VAR([LZ4_CFLAGS], [C compiler flags for lz4])
 AC_ARG_VAR([LZ4_LIBS], [linker flags for lz4])
 
-AC_ARG_WITH(liblzma-incdir,
-   [AS_HELP_STRING([--with-liblzma-incdir=DIR], [liblzma include directory])], [
-   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])
-
-AC_ARG_WITH(liblzma-libdir,
-   [AS_HELP_STRING([--with-liblzma-libdir=DIR], [liblzma lib directory])], [
-   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])
-
 # Checks for header files.
 AC_CHECK_HEADERS(m4_flatten([
 	dirent.h
@@ -189,6 +204,7 @@ AC_CHECK_HEADERS(m4_flatten([
 	sys/ioctl.h
 	sys/mman.h
 	sys/random.h
+	sys/sendfile.h
 	sys/stat.h
 	sys/statfs.h
 	sys/sysmacros.h
@@ -252,10 +268,12 @@ AC_CHECK_FUNCS(m4_flatten([
 	pwrite64
 	posix_fadvise
 	fstatfs
+	sendfile
 	strdup
 	strerror
 	strrchr
 	strtoull
+	sysconf
 	tmpfile64
 	utimensat]))
 
@@ -288,6 +306,14 @@ AS_IF([test "x$MAX_BLOCK_SIZE" = "x"], [
                              [erofs_cv_max_block_size=4096]))
 ], [erofs_cv_max_block_size=$MAX_BLOCK_SIZE])
 
+# Configure multi-threading support
+AS_IF([test "x$enable_multithreading" != "xno"], [
+  AC_CHECK_HEADERS([pthread.h])
+  AC_CHECK_LIB([pthread], [pthread_mutex_lock], [],
+    AC_MSG_ERROR([libpthread is required for multi-threaded build]))
+  AC_DEFINE(EROFS_MT_ENABLED, 1, [Enable multi-threading support])
+], [])
+
 # Configure debug mode
 AS_IF([test "x$enable_debug" != "xno"], [], [
   dnl Turn off all assert checking.
@@ -339,15 +365,32 @@ AS_IF([test "x$with_selinux" != "xno"], [
 
 # Configure fuse
 AS_IF([test "x$enable_fuse" != "xno"], [
-  PKG_CHECK_MODULES([libfuse], [fuse >= 2.6])
   # Paranoia: don't trust the result reported by pkgconfig before trying out
   saved_LIBS="$LIBS"
   saved_CPPFLAGS=${CPPFLAGS}
-  CPPFLAGS="${libfuse_CFLAGS} ${CPPFLAGS}"
-  LIBS="${libfuse_LIBS} $LIBS"
-  AC_CHECK_LIB(fuse, fuse_main, [
-    have_fuse="yes" ], [
-    AC_MSG_ERROR([libfuse (>= 2.6) doesn't work properly])])
+  PKG_CHECK_MODULES([libfuse3], [fuse3 >= 3.0], [
+    PKG_CHECK_MODULES([libfuse3_0], [fuse3 >= 3.0 fuse3 < 3.2], [
+      AC_DEFINE([FUSE_USE_VERSION], [30], [used FUSE API version])
+    ], [
+      PKG_CHECK_MODULES([libfuse3_2], [fuse3 >= 3.2], [
+        AC_DEFINE([FUSE_USE_VERSION], [32], [used FUSE API version])
+      ])
+    ])
+    CPPFLAGS="${libfuse3_CFLAGS} ${CPPFLAGS}"
+    LIBS="${libfuse3_LIBS} $LIBS"
+    AC_CHECK_LIB(fuse3, fuse_session_new, [], [
+    AC_MSG_ERROR([libfuse3 (>= 3.0) doesn't work properly for lowlevel api])])
+    have_fuse="yes"
+  ], [
+    PKG_CHECK_MODULES([libfuse2], [fuse >= 2.6], [
+      AC_DEFINE([FUSE_USE_VERSION], [26], [used FUSE API version])
+      CPPFLAGS="${libfuse2_CFLAGS} ${CPPFLAGS}"
+      LIBS="${libfuse2_LIBS} $LIBS"
+      AC_CHECK_LIB(fuse, fuse_lowlevel_new, [], [
+        AC_MSG_ERROR([libfuse (>= 2.6) doesn't work properly for lowlevel api])])
+      have_fuse="yes"
+    ], [have_fuse="no"])
+  ])
   LIBS="${saved_LIBS}"
   CPPFLAGS="${saved_CPPFLAGS}"], [have_fuse="no"])
 
@@ -383,44 +426,56 @@ if test "x$enable_lz4" = "xyes"; then
   CPPFLAGS=${saved_CPPFLAGS}
 fi
 
-if test "x$enable_lzma" = "xyes"; then
+# Configure liblzma
+have_liblzma="no"
+AS_IF([test "x$enable_lzma" != "xno"], [
   saved_CPPFLAGS=${CPPFLAGS}
-  test -z "${with_liblzma_incdir}" ||
-    CPPFLAGS="-I$with_liblzma_incdir $CPPFLAGS"
-  AC_CHECK_HEADERS([lzma.h],[have_lzmah="yes"], [])
-
-  if test "x${have_lzmah}" = "xyes" ; then
+  PKG_CHECK_MODULES([liblzma], [liblzma], [
+    # Paranoia: don't trust the result reported by pkgconfig before trying out
     saved_LIBS="$LIBS"
-    saved_LDFLAGS="$LDFLAGS"
-
-    test -z "${with_liblzma_libdir}" ||
-      LDFLAGS="-L$with_liblzma_libdir ${LDFLAGS}"
-    AC_CHECK_LIB(lzma, lzma_microlzma_encoder, [],
-      [AC_MSG_ERROR([Cannot find proper liblzma])])
-
-    AC_CHECK_DECL(lzma_microlzma_encoder, [have_liblzma="yes"],
-      [AC_MSG_ERROR([Cannot find proper liblzma])], [[
+    saved_CPPFLAGS=${CPPFLAGS}
+    CPPFLAGS="${liblzma_CFLAGS} ${CPPFLAGS}"
+    LIBS="${liblzma_LIBS} $LIBS"
+    AC_CHECK_HEADERS([lzma.h],[
+      AC_CHECK_LIB(lzma, lzma_microlzma_encoder, [
+        AC_CHECK_DECL(lzma_microlzma_encoder, [have_liblzma="yes"],
+          [], [[
 #include <lzma.h>
-    ]])
-    LDFLAGS="${saved_LDFLAGS}"
+        ]])
+      ])
+    ])
     LIBS="${saved_LIBS}"
-  fi
-  CPPFLAGS="${saved_CPPFLAGS}"
-fi
+    CPPFLAGS="${saved_CPPFLAGS}"
+  ], [[]])
+  AS_IF([test "x$enable_lzma" = "xyes" -a "x$have_liblzma" != "xyes"], [
+    AC_MSG_ERROR([Cannot find a proper liblzma version])
+  ])
+])
 
 # Configure zlib
+have_zlib="no"
 AS_IF([test "x$with_zlib" != "xno"], [
-  PKG_CHECK_MODULES([zlib], [zlib])
-  # Paranoia: don't trust the result reported by pkgconfig before trying out
-  saved_LIBS="$LIBS"
-  saved_CPPFLAGS=${CPPFLAGS}
-  CPPFLAGS="${zlib_CFLAGS} ${CPPFLAGS}"
-  LIBS="${zlib_LIBS} $LIBS"
-  AC_CHECK_LIB(z, inflate, [
-    have_zlib="yes" ], [
-    AC_MSG_ERROR([zlib doesn't work properly])])
-  LIBS="${saved_LIBS}"
-  CPPFLAGS="${saved_CPPFLAGS}"], [have_zlib="no"])
+  PKG_CHECK_MODULES([zlib], [zlib], [
+    # Paranoia: don't trust the result reported by pkgconfig before trying out
+    saved_LIBS="$LIBS"
+    saved_CPPFLAGS=${CPPFLAGS}
+    CPPFLAGS="${zlib_CFLAGS} ${CPPFLAGS}"
+    LIBS="${zlib_LIBS} $LIBS"
+    AC_CHECK_HEADERS([zlib.h],[
+      AC_CHECK_LIB(z, inflate, [], [
+        AC_MSG_ERROR([zlib doesn't work properly])])
+      AC_CHECK_DECL(inflate, [have_zlib="yes"],
+        [AC_MSG_ERROR([zlib doesn't work properly])], [[
+#include <zlib.h>
+      ]])
+    ])
+    LIBS="${saved_LIBS}"
+    CPPFLAGS="${saved_CPPFLAGS}"], [
+    AS_IF([test "x$with_zlib" = "xyes"], [
+      AC_MSG_ERROR([Cannot find proper zlib])
+    ])
+  ])
+])
 
 # Configure libdeflate
 AS_IF([test "x$with_libdeflate" != "xno"], [
@@ -436,6 +491,57 @@ AS_IF([test "x$with_libdeflate" != "xno"], [
   LIBS="${saved_LIBS}"
   CPPFLAGS="${saved_CPPFLAGS}"], [have_libdeflate="no"])
 
+# Configure libzstd
+have_libzstd="no"
+AS_IF([test "x$with_libzstd" != "xno"], [
+  PKG_CHECK_MODULES([libzstd], [libzstd >= 1.4.0], [
+    # Paranoia: don't trust the result reported by pkgconfig before trying out
+    saved_LIBS="$LIBS"
+    saved_CPPFLAGS=${CPPFLAGS}
+    CPPFLAGS="${libzstd_CFLAGS} ${CPPFLAGS}"
+    LIBS="${libzstd_LIBS} $LIBS"
+    AC_CHECK_HEADERS([zstd.h],[
+      AC_CHECK_LIB(zstd, ZSTD_compress2, [], [
+        AC_MSG_ERROR([libzstd doesn't work properly])])
+      AC_CHECK_DECL(ZSTD_compress2, [have_libzstd="yes"],
+        [AC_MSG_ERROR([libzstd doesn't work properly])], [[
+#include <zstd.h>
+      ]])
+      AC_CHECK_FUNCS([ZSTD_getFrameContentSize])
+    ])
+    LIBS="${saved_LIBS}"
+    CPPFLAGS="${saved_CPPFLAGS}"], [
+    AS_IF([test "x$with_libzstd" = "xyes"], [
+      AC_MSG_ERROR([Cannot find proper libzstd])
+    ])
+  ])
+])
+
+# Configure Intel QPL
+have_qpl="no"
+AS_IF([test "x$with_qpl" != "xno"], [
+  PKG_CHECK_MODULES([libqpl], [qpl >= 1.5.0], [
+    # Paranoia: don't trust the result reported by pkgconfig before trying out
+    saved_LIBS="$LIBS"
+    saved_CPPFLAGS=${CPPFLAGS}
+    CPPFLAGS="${libqpl_CFLAGS} ${CPPFLAGS}"
+    LIBS="${libqpl_LIBS} $LIBS"
+    AC_CHECK_HEADERS([qpl/qpl.h],[
+      AC_CHECK_LIB(qpl, qpl_execute_job, [], [
+        AC_MSG_ERROR([libqpl doesn't work properly])])
+      AC_CHECK_DECL(qpl_execute_job, [have_qpl="yes"],
+        [AC_MSG_ERROR([libqpl doesn't work properly])], [[
+#include <qpl/qpl.h>
+      ]])
+    ])
+    LIBS="${saved_LIBS}"
+    CPPFLAGS="${saved_CPPFLAGS}"], [
+    AS_IF([test "x$with_qpl" = "xyes"], [
+      AC_MSG_ERROR([Cannot find proper libqpl])
+    ])
+  ])
+])
+
 # Enable 64-bit off_t
 CFLAGS+=" -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"
 
@@ -450,11 +556,15 @@ AS_IF([test "x$enable_fuzzing" != "xyes"], [], [
 AM_CONDITIONAL([ENABLE_FUZZING], [test "x${enable_fuzzing}" = "xyes"])
 
 # Set up needed symbols, conditionals and compiler/linker flags
+AM_CONDITIONAL([ENABLE_EROFS_MT], [test "x${enable_multithreading}" != "xno"])
 AM_CONDITIONAL([ENABLE_LZ4], [test "x${have_lz4}" = "xyes"])
 AM_CONDITIONAL([ENABLE_LZ4HC], [test "x${have_lz4hc}" = "xyes"])
 AM_CONDITIONAL([ENABLE_FUSE], [test "x${have_fuse}" = "xyes"])
 AM_CONDITIONAL([ENABLE_LIBLZMA], [test "x${have_liblzma}" = "xyes"])
 AM_CONDITIONAL([ENABLE_LIBDEFLATE], [test "x${have_libdeflate}" = "xyes"])
+AM_CONDITIONAL([ENABLE_LIBZSTD], [test "x${have_libzstd}" = "xyes"])
+AM_CONDITIONAL([ENABLE_QPL], [test "x${have_qpl}" = "xyes"])
+AM_CONDITIONAL([ENABLE_STATIC_FUSE], [test "x${enable_static_fuse}" = "xyes"])
 
 if test "x$have_uuid" = "xyes"; then
   AC_DEFINE([HAVE_LIBUUID], 1, [Define to 1 if libuuid is found])
@@ -500,6 +610,16 @@ if test "x$have_libdeflate" = "xyes"; then
   AC_DEFINE([HAVE_LIBDEFLATE], 1, [Define to 1 if libdeflate is found])
 fi
 
+if test "x$have_libzstd" = "xyes"; then
+  AC_DEFINE([HAVE_LIBZSTD], 1, [Define to 1 if libzstd is found])
+fi
+
+if test "x$have_qpl" = "xyes"; then
+  AC_DEFINE([HAVE_QPL], 1, [Define to 1 if qpl is found])
+  AC_SUBST([libqpl_LIBS])
+  AC_SUBST([libqpl_CFLAGS])
+fi
+
 # Dump maximum block size
 AS_IF([test "x$erofs_cv_max_block_size" = "x"],
       [$erofs_cv_max_block_size = 4096], [])
diff --git a/dump/Makefile.am b/dump/Makefile.am
index aed20c2..2a4f67a 100644
--- a/dump/Makefile.am
+++ b/dump/Makefile.am
@@ -7,4 +7,5 @@ AM_CPPFLAGS = ${libuuid_CFLAGS}
 dump_erofs_SOURCES = main.c
 dump_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
 dump_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
-	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS}
+	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} \
+	${libzstd_LIBS} ${libqpl_LIBS}
diff --git a/dump/main.c b/dump/main.c
index 5425b7b..372162e 100644
--- a/dump/main.c
+++ b/dump/main.c
@@ -12,7 +12,6 @@
 #include <sys/stat.h>
 #include "erofs/print.h"
 #include "erofs/inode.h"
-#include "erofs/io.h"
 #include "erofs/dir.h"
 #include "erofs/compress.h"
 #include "erofs/fragments.h"
@@ -74,11 +73,13 @@ struct erofs_statistics {
 static struct erofs_statistics stats;
 
 static struct option long_options[] = {
-	{"help", no_argument, NULL, 1},
+	{"version", no_argument, NULL, 'V'},
+	{"help", no_argument, NULL, 'h'},
 	{"nid", required_argument, NULL, 2},
 	{"device", required_argument, NULL, 3},
 	{"path", required_argument, NULL, 4},
 	{"ls", no_argument, NULL, 5},
+	{"offset", required_argument, NULL, 6},
 	{0, 0, 0, 0},
 };
 
@@ -105,32 +106,40 @@ static struct erofsdump_feature feature_lists[] = {
 
 static int erofsdump_readdir(struct erofs_dir_context *ctx);
 
-static void usage(void)
+static void usage(int argc, char **argv)
 {
-	fputs("usage: [options] IMAGE\n\n"
-	      "Dump erofs layout from IMAGE, and [options] are:\n"
-	      " -S              show statistic information of the image\n"
-	      " -V              print the version number of dump.erofs and exit.\n"
-	      " -e              show extent info (INODE required)\n"
-	      " -s              show information about superblock\n"
-	      " --device=X      specify an extra device to be used together\n"
-	      " --ls            show directory contents (INODE required)\n"
-	      " --nid=#         show the target inode info of nid #\n"
-	      " --path=X        show the target inode info of path X\n"
-	      " --help          display this help and exit.\n",
-	      stderr);
+	//	"         1         2         3         4         5         6         7         8  "
+	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
+	printf(
+		"Usage: %s [OPTIONS] IMAGE\n"
+		"Dump erofs layout from IMAGE.\n"
+		"\n"
+		"General options:\n"
+		" -V, --version   print the version number of dump.erofs and exit\n"
+		" -h, --help      display this help and exit\n"
+		"\n"
+		" -S              show statistic information of the image\n"
+		" -e              show extent info (INODE required)\n"
+		" -s              show information about superblock\n"
+		" --device=X      specify an extra device to be used together\n"
+		" --ls            show directory contents (INODE required)\n"
+		" --nid=#         show the target inode info of nid #\n"
+		" --offset=#      skip # bytes at the beginning of IMAGE\n"
+		" --path=X        show the target inode info of path X\n",
+		argv[0]);
 }
 
 static void erofsdump_print_version(void)
 {
-	printf("dump.erofs %s\n", cfg.c_version);
+	printf("dump.erofs (erofs-utils) %s\n", cfg.c_version);
 }
 
 static int erofsdump_parse_options_cfg(int argc, char **argv)
 {
 	int opt, err;
+	char *endptr;
 
-	while ((opt = getopt_long(argc, argv, "SVes",
+	while ((opt = getopt_long(argc, argv, "SVesh",
 				  long_options, NULL)) != -1) {
 		switch (opt) {
 		case 'e':
@@ -153,14 +162,14 @@ static int erofsdump_parse_options_cfg(int argc, char **argv)
 			dumpcfg.nid = (erofs_nid_t)atoll(optarg);
 			++dumpcfg.totalshow;
 			break;
-		case 1:
-			usage();
+		case 'h':
+			usage(argc, argv);
 			exit(0);
 		case 3:
-			err = blob_open_ro(&sbi, optarg);
+			err = erofs_blob_open_ro(&g_sbi, optarg);
 			if (err)
 				return err;
-			++sbi.extra_devices;
+			++g_sbi.extra_devices;
 			break;
 		case 4:
 			dumpcfg.inode_path = optarg;
@@ -170,6 +179,13 @@ static int erofsdump_parse_options_cfg(int argc, char **argv)
 		case 5:
 			dumpcfg.show_subdirectories = true;
 			break;
+		case 6:
+			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
+			if (*endptr != '\0') {
+				erofs_err("invalid disk offset %s", optarg);
+				return -EINVAL;
+			}
+			break;
 		default:
 			return -EINVAL;
 		}
@@ -273,9 +289,9 @@ static int erofsdump_read_packed_inode(void)
 {
 	int err;
 	erofs_off_t occupied_size = 0;
-	struct erofs_inode vi = { .sbi = &sbi, .nid = sbi.packed_nid };
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = g_sbi.packed_nid };
 
-	if (!(erofs_sb_has_fragments(&sbi) && sbi.packed_nid > 0))
+	if (!(erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0))
 		return 0;
 
 	err = erofs_read_inode_from_disk(&vi);
@@ -299,7 +315,7 @@ static int erofsdump_readdir(struct erofs_dir_context *ctx)
 {
 	int err;
 	erofs_off_t occupied_size = 0;
-	struct erofs_inode vi = { .sbi = &sbi, .nid = ctx->de_nid };
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = ctx->de_nid };
 
 	err = erofs_read_inode_from_disk(&vi);
 	if (err) {
@@ -354,7 +370,7 @@ static void erofsdump_show_fileinfo(bool show_extent)
 	int err, i;
 	erofs_off_t size;
 	u16 access_mode;
-	struct erofs_inode inode = { .sbi = &sbi, .nid = dumpcfg.nid };
+	struct erofs_inode inode = { .sbi = &g_sbi, .nid = dumpcfg.nid };
 	char path[PATH_MAX];
 	char access_mode_str[] = "rwxrwxrwx";
 	char timebuf[128] = {0};
@@ -566,7 +582,7 @@ static void erofsdump_print_statistic(void)
 		.pnid = 0,
 		.dir = NULL,
 		.cb = erofsdump_dirent_iter,
-		.de_nid = sbi.root_nid,
+		.de_nid = g_sbi.root_nid,
 		.dname = "",
 		.de_namelen = 0,
 	};
@@ -610,46 +626,48 @@ static void erofsdump_print_supported_compressors(FILE *f, unsigned int mask)
 
 static void erofsdump_show_superblock(void)
 {
-	time_t time = sbi.build_time;
+	time_t time = g_sbi.build_time;
 	char uuid_str[37];
 	int i = 0;
 
 	fprintf(stdout, "Filesystem magic number:                      0x%04X\n",
 			EROFS_SUPER_MAGIC_V1);
+	fprintf(stdout, "Filesystem blocksize:                         %u\n",
+			erofs_blksiz(&g_sbi));
 	fprintf(stdout, "Filesystem blocks:                            %llu\n",
-			sbi.total_blocks | 0ULL);
+			g_sbi.total_blocks | 0ULL);
 	fprintf(stdout, "Filesystem inode metadata start block:        %u\n",
-			sbi.meta_blkaddr);
+			g_sbi.meta_blkaddr);
 	fprintf(stdout, "Filesystem shared xattr metadata start block: %u\n",
-			sbi.xattr_blkaddr);
+			g_sbi.xattr_blkaddr);
 	fprintf(stdout, "Filesystem root nid:                          %llu\n",
-			sbi.root_nid | 0ULL);
-	if (erofs_sb_has_fragments(&sbi) && sbi.packed_nid > 0)
+			g_sbi.root_nid | 0ULL);
+	if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0)
 		fprintf(stdout, "Filesystem packed nid:                        %llu\n",
-			sbi.packed_nid | 0ULL);
-	if (erofs_sb_has_compr_cfgs(&sbi)) {
+			g_sbi.packed_nid | 0ULL);
+	if (erofs_sb_has_compr_cfgs(&g_sbi)) {
 		fprintf(stdout, "Filesystem compr_algs:                        ");
 		erofsdump_print_supported_compressors(stdout,
-			sbi.available_compr_algs);
+			g_sbi.available_compr_algs);
 	} else {
 		fprintf(stdout, "Filesystem lz4_max_distance:                  %u\n",
-			sbi.lz4_max_distance | 0U);
+			g_sbi.lz4.max_distance | 0U);
 	}
-	fprintf(stdout, "Filesystem sb_extslots:                       %u\n",
-			sbi.extslots | 0U);
+	fprintf(stdout, "Filesystem sb_size:                           %u\n",
+			g_sbi.sb_size | 0U);
 	fprintf(stdout, "Filesystem inode count:                       %llu\n",
-			sbi.inos | 0ULL);
+			g_sbi.inos | 0ULL);
 	fprintf(stdout, "Filesystem created:                           %s",
 			ctime(&time));
 	fprintf(stdout, "Filesystem features:                          ");
 	for (; i < ARRAY_SIZE(feature_lists); i++) {
 		u32 feat = le32_to_cpu(feature_lists[i].compat ?
-				       sbi.feature_compat :
-				       sbi.feature_incompat);
+				       g_sbi.feature_compat :
+				       g_sbi.feature_incompat);
 		if (feat & feature_lists[i].flag)
 			fprintf(stdout, "%s ", feature_lists[i].name);
 	}
-	erofs_uuid_unparse_lower(sbi.uuid, uuid_str);
+	erofs_uuid_unparse_lower(g_sbi.uuid, uuid_str);
 	fprintf(stdout, "\nFilesystem UUID:                              %s\n",
 			uuid_str);
 }
@@ -662,17 +680,17 @@ int main(int argc, char **argv)
 	err = erofsdump_parse_options_cfg(argc, argv);
 	if (err) {
 		if (err == -EINVAL)
-			usage();
+			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		goto exit;
 	}
 
-	err = dev_open_ro(&sbi, cfg.c_img_path);
+	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDONLY | O_TRUNC);
 	if (err) {
 		erofs_err("failed to open image file");
 		goto exit;
 	}
 
-	err = erofs_read_superblock(&sbi);
+	err = erofs_read_superblock(&g_sbi);
 	if (err) {
 		erofs_err("failed to read superblock");
 		goto exit_dev_close;
@@ -689,7 +707,7 @@ int main(int argc, char **argv)
 		erofsdump_print_statistic();
 
 	if (dumpcfg.show_extent && !dumpcfg.show_inode) {
-		usage();
+		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		goto exit_put_super;
 	}
 
@@ -697,11 +715,11 @@ int main(int argc, char **argv)
 		erofsdump_show_fileinfo(dumpcfg.show_extent);
 
 exit_put_super:
-	erofs_put_super(&sbi);
+	erofs_put_super(&g_sbi);
 exit_dev_close:
-	dev_close(&sbi);
+	erofs_dev_close(&g_sbi);
 exit:
-	blob_closeall(&sbi);
+	erofs_blob_closeall(&g_sbi);
 	erofs_exit_configure();
 	return err;
 }
diff --git a/fsck/Makefile.am b/fsck/Makefile.am
index d024405..5bdee4d 100644
--- a/fsck/Makefile.am
+++ b/fsck/Makefile.am
@@ -7,7 +7,8 @@ AM_CPPFLAGS = ${libuuid_CFLAGS}
 fsck_erofs_SOURCES = main.c
 fsck_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
 fsck_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
-	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS}
+	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} \
+	${libzstd_LIBS} ${libqpl_LIBS}
 
 if ENABLE_FUZZING
 noinst_PROGRAMS   = fuzz_erofsfsck
@@ -15,5 +16,6 @@ fuzz_erofsfsck_SOURCES = main.c
 fuzz_erofsfsck_CFLAGS = -Wall -I$(top_srcdir)/include -DFUZZING
 fuzz_erofsfsck_LDFLAGS = -fsanitize=address,fuzzer
 fuzz_erofsfsck_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
-	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS}
+	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} \
+	${libzstd_LIBS} ${libqpl_LIBS}
 endif
diff --git a/fsck/main.c b/fsck/main.c
index 3f86da4..28f1e7e 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -10,10 +10,10 @@
 #include <unistd.h>
 #include <sys/stat.h>
 #include "erofs/print.h"
-#include "erofs/io.h"
 #include "erofs/compress.h"
 #include "erofs/decompress.h"
 #include "erofs/dir.h"
+#include "../lib/compressor.h"
 
 static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);
 
@@ -35,7 +35,8 @@ struct erofsfsck_cfg {
 static struct erofsfsck_cfg fsckcfg;
 
 static struct option long_options[] = {
-	{"help", no_argument, 0, 1},
+	{"version", no_argument, 0, 'V'},
+	{"help", no_argument, 0, 'h'},
 	{"extract", optional_argument, 0, 2},
 	{"device", required_argument, 0, 3},
 	{"force", no_argument, 0, 4},
@@ -46,6 +47,7 @@ static struct option long_options[] = {
 	{"no-preserve", no_argument, 0, 9},
 	{"no-preserve-owner", no_argument, 0, 10},
 	{"no-preserve-perms", no_argument, 0, 11},
+	{"offset", required_argument, 0, 12},
 	{0, 0, 0, 0},
 };
 
@@ -63,53 +65,70 @@ static void print_available_decompressors(FILE *f, const char *delim)
 {
 	int i = 0;
 	bool comma = false;
-	const char *s;
+	const struct erofs_algorithm *s;
 
 	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
 		if (comma)
 			fputs(delim, f);
-		fputs(s, f);
+		fputs(s->name, f);
 		comma = true;
 	}
 	fputc('\n', f);
 }
 
-static void usage(void)
+static void usage(int argc, char **argv)
 {
-	fputs("usage: [options] IMAGE\n\n"
-	      "Check erofs filesystem compatibility and integrity of IMAGE, and [options] are:\n"
-	      " -V                     print the version number of fsck.erofs and exit\n"
-	      " -d#                    set output message level to # (maximum 9)\n"
-	      " -p                     print total compression ratio of all files\n"
-	      " --device=X             specify an extra device to be used together\n"
-	      " --extract[=X]          check if all files are well encoded, optionally extract to X\n"
-	      " --help                 display this help and exit\n"
-	      "\nExtraction options (--extract=X is required):\n"
-	      " --force                allow extracting to root\n"
-	      " --overwrite            overwrite files that already exist\n"
-	      " --preserve             extract with the same ownership and permissions as on the filesystem\n"
-	      "                        (default for superuser)\n"
-	      " --preserve-owner       extract with the same ownership as on the filesystem\n"
-	      " --preserve-perms       extract with the same permissions as on the filesystem\n"
-	      " --no-preserve          extract as yourself and apply user's umask on permissions\n"
-	      "                        (default for ordinary users)\n"
-	      " --no-preserve-owner    extract as yourself\n"
-	      " --no-preserve-perms    apply user's umask when extracting permissions\n"
-	      "\nSupported algorithms are: ", stderr);
-	print_available_decompressors(stderr, ", ");
+	//	"         1         2         3         4         5         6         7         8  "
+	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
+	printf(
+		"Usage: %s [OPTIONS] IMAGE\n"
+		"Check erofs filesystem compatibility and integrity of IMAGE.\n"
+		"\n"
+		"This version of fsck.erofs is capable of checking images that use any of the\n"
+		"following algorithms: ", argv[0]);
+	print_available_decompressors(stdout, ", ");
+	printf("\n"
+		"General options:\n"
+		" -V, --version          print the version number of fsck.erofs and exit\n"
+		" -h, --help             display this help and exit\n"
+		"\n"
+		" -d<0-9>                set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
+		" -p                     print total compression ratio of all files\n"
+		" --device=X             specify an extra device to be used together\n"
+		" --extract[=X]          check if all files are well encoded, optionally\n"
+		"                        extract to X\n"
+		" --offset=#             skip # bytes at the beginning of IMAGE\n"
+		"\n"
+		" -a, -A, -y             no-op, for compatibility with fsck of other filesystems\n"
+		"\n"
+		"Extraction options (--extract=X is required):\n"
+		" --force                allow extracting to root\n"
+		" --overwrite            overwrite files that already exist\n"
+		" --[no-]preserve        same as --[no-]preserve-owner --[no-]preserve-perms\n"
+		" --[no-]preserve-owner  whether to preserve the ownership from the\n"
+		"                        filesystem (default for superuser), or to extract as\n"
+		"                        yourself (default for ordinary users)\n"
+		" --[no-]preserve-perms  whether to preserve the exact permissions from the\n"
+		"                        filesystem without applying umask (default for\n"
+		"                        superuser), or to modify the permissions by applying\n"
+		"                        umask (default for ordinary users)\n",
+		EROFS_WARN);
 }
 
 static void erofsfsck_print_version(void)
 {
-	printf("fsck.erofs %s\n", cfg.c_version);
+	printf("fsck.erofs (erofs-utils) %s\navailable decompressors: ",
+	       cfg.c_version);
+	print_available_decompressors(stdout, ", ");
 }
 
 static int erofsfsck_parse_options_cfg(int argc, char **argv)
 {
+	char *endptr;
 	int opt, ret;
 	bool has_opt_preserve = false;
 
-	while ((opt = getopt_long(argc, argv, "Vd:p",
+	while ((opt = getopt_long(argc, argv, "Vd:phaAy",
 				  long_options, NULL)) != -1) {
 		switch (opt) {
 		case 'V':
@@ -126,9 +145,13 @@ static int erofsfsck_parse_options_cfg(int argc, char **argv)
 		case 'p':
 			fsckcfg.print_comp_ratio = true;
 			break;
-		case 1:
-			usage();
+		case 'h':
+			usage(argc, argv);
 			exit(0);
+		case 'a':
+		case 'A':
+		case 'y':
+			break;
 		case 2:
 			fsckcfg.check_decomp = true;
 			if (optarg) {
@@ -160,10 +183,10 @@ static int erofsfsck_parse_options_cfg(int argc, char **argv)
 			}
 			break;
 		case 3:
-			ret = blob_open_ro(&sbi, optarg);
+			ret = erofs_blob_open_ro(&g_sbi, optarg);
 			if (ret)
 				return ret;
-			++sbi.extra_devices;
+			++g_sbi.extra_devices;
 			break;
 		case 4:
 			fsckcfg.force = true;
@@ -195,6 +218,13 @@ static int erofsfsck_parse_options_cfg(int argc, char **argv)
 			fsckcfg.preserve_perms = false;
 			has_opt_preserve = true;
 			break;
+		case 12:
+			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
+			if (*endptr != '\0') {
+				erofs_err("invalid disk offset %s", optarg);
+				return -EINVAL;
+			}
+			break;
 		default:
 			return -EINVAL;
 		}
@@ -281,7 +311,7 @@ static int erofs_check_sb_chksum(void)
 	struct erofs_super_block *sb;
 	int ret;
 
-	ret = blk_read(&sbi, 0, buf, 0, 1);
+	ret = erofs_blk_read(&g_sbi, 0, buf, 0, 1);
 	if (ret) {
 		erofs_err("failed to read superblock to check checksum: %d",
 			  ret);
@@ -291,10 +321,10 @@ static int erofs_check_sb_chksum(void)
 	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);
 	sb->checksum = 0;
 
-	crc = erofs_crc32c(~0, (u8 *)sb, erofs_blksiz(&sbi) - EROFS_SUPER_OFFSET);
-	if (crc != sbi.checksum) {
+	crc = erofs_crc32c(~0, (u8 *)sb, erofs_blksiz(&g_sbi) - EROFS_SUPER_OFFSET);
+	if (crc != g_sbi.checksum) {
 		erofs_err("superblock chksum doesn't match: saved(%08xh) calculated(%08xh)",
-			  sbi.checksum, crc);
+			  g_sbi.checksum, crc);
 		fsckcfg.corrupted = true;
 		return -1;
 	}
@@ -329,7 +359,7 @@ static int erofs_verify_xattr(struct erofs_inode *inode)
 	}
 
 	addr = erofs_iloc(inode) + inode->inode_isize;
-	ret = dev_read(sbi, 0, buf, addr, xattr_hdr_size);
+	ret = erofs_dev_read(sbi, 0, buf, addr, xattr_hdr_size);
 	if (ret < 0) {
 		erofs_err("failed to read xattr header @ nid %llu: %d",
 			  inode->nid | 0ULL, ret);
@@ -359,7 +389,7 @@ static int erofs_verify_xattr(struct erofs_inode *inode)
 	while (remaining > 0) {
 		unsigned int entry_sz;
 
-		ret = dev_read(sbi, 0, buf, addr, xattr_entry_size);
+		ret = erofs_dev_read(sbi, 0, buf, addr, xattr_entry_size);
 		if (ret) {
 			erofs_err("failed to read xattr entry @ nid %llu: %d",
 				  inode->nid | 0ULL, ret);
@@ -439,8 +469,17 @@ static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
 		pos += map.m_llen;
 
 		/* should skip decomp? */
-		if (!(map.m_flags & EROFS_MAP_MAPPED) || !fsckcfg.check_decomp)
+		if (map.m_la >= inode->i_size || !fsckcfg.check_decomp)
+			continue;
+
+		if (outfd >= 0 && !(map.m_flags & EROFS_MAP_MAPPED)) {
+			ret = lseek(outfd, map.m_llen, SEEK_CUR);
+			if (ret < 0) {
+				ret = -errno;
+				goto out;
+			}
 			continue;
+		}
 
 		if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
 			if (compressed) {
@@ -468,9 +507,15 @@ static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
 
 		if (compressed) {
 			if (map.m_llen > buffer_size) {
+				char *newbuffer;
+
 				buffer_size = map.m_llen;
-				buffer = realloc(buffer, buffer_size);
-				BUG_ON(!buffer);
+				newbuffer = realloc(buffer, buffer_size);
+				if (!newbuffer) {
+					ret = -ENOMEM;
+					goto out;
+				}
+				buffer = newbuffer;
 			}
 			ret = z_erofs_read_one_data(inode, &map, raw, buffer,
 						    0, map.m_llen, false);
@@ -657,11 +702,7 @@ again:
 
 	/* verify data chunk layout */
 	ret = erofs_verify_inode_data(inode, fd);
-	if (ret)
-		return ret;
-
-	if (close(fd))
-		return -errno;
+	close(fd);
 	return ret;
 }
 
@@ -850,7 +891,7 @@ static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid)
 	erofs_dbg("check inode: nid(%llu)", nid | 0ULL);
 
 	inode.nid = nid;
-	inode.sbi = &sbi;
+	inode.sbi = &g_sbi;
 	ret = erofs_read_inode_from_disk(&inode);
 	if (ret) {
 		if (ret == -EIO)
@@ -918,7 +959,7 @@ int main(int argc, char *argv[])
 	err = erofsfsck_parse_options_cfg(argc, argv);
 	if (err) {
 		if (err == -EINVAL)
-			usage();
+			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		goto exit;
 	}
 
@@ -926,19 +967,19 @@ int main(int argc, char *argv[])
 	cfg.c_dbg_lvl = -1;
 #endif
 
-	err = dev_open_ro(&sbi, cfg.c_img_path);
+	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDONLY);
 	if (err) {
 		erofs_err("failed to open image file");
 		goto exit;
 	}
 
-	err = erofs_read_superblock(&sbi);
+	err = erofs_read_superblock(&g_sbi);
 	if (err) {
 		erofs_err("failed to read superblock");
 		goto exit_dev_close;
 	}
 
-	if (erofs_sb_has_sb_chksum(&sbi) && erofs_check_sb_chksum()) {
+	if (erofs_sb_has_sb_chksum(&g_sbi) && erofs_check_sb_chksum()) {
 		erofs_err("failed to verify superblock checksum");
 		goto exit_put_super;
 	}
@@ -946,15 +987,15 @@ int main(int argc, char *argv[])
 	if (fsckcfg.extract_path)
 		erofsfsck_hardlink_init();
 
-	if (erofs_sb_has_fragments(&sbi) && sbi.packed_nid > 0) {
-		err = erofsfsck_check_inode(sbi.packed_nid, sbi.packed_nid);
+	if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0) {
+		err = erofsfsck_check_inode(g_sbi.packed_nid, g_sbi.packed_nid);
 		if (err) {
 			erofs_err("failed to verify packed file");
 			goto exit_hardlink;
 		}
 	}
 
-	err = erofsfsck_check_inode(sbi.root_nid, sbi.root_nid);
+	err = erofsfsck_check_inode(g_sbi.root_nid, g_sbi.root_nid);
 	if (fsckcfg.corrupted) {
 		if (!fsckcfg.extract_path)
 			erofs_err("Found some filesystem corruption");
@@ -980,11 +1021,11 @@ exit_hardlink:
 	if (fsckcfg.extract_path)
 		erofsfsck_hardlink_exit();
 exit_put_super:
-	erofs_put_super(&sbi);
+	erofs_put_super(&g_sbi);
 exit_dev_close:
-	dev_close(&sbi);
+	erofs_dev_close(&g_sbi);
 exit:
-	blob_closeall(&sbi);
+	erofs_blob_closeall(&g_sbi);
 	erofs_exit_configure();
 	return err ? 1 : 0;
 }
diff --git a/fuse/Makefile.am b/fuse/Makefile.am
index 50be783..1062b73 100644
--- a/fuse/Makefile.am
+++ b/fuse/Makefile.am
@@ -5,6 +5,15 @@ noinst_HEADERS = $(top_srcdir)/fuse/macosx.h
 bin_PROGRAMS     = erofsfuse
 erofsfuse_SOURCES = main.c
 erofsfuse_CFLAGS = -Wall -I$(top_srcdir)/include
-erofsfuse_CFLAGS += -DFUSE_USE_VERSION=26 ${libfuse_CFLAGS} ${libselinux_CFLAGS}
-erofsfuse_LDADD = $(top_builddir)/lib/liberofs.la ${libfuse_LIBS} ${liblz4_LIBS} \
-	${libselinux_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS}
+erofsfuse_CFLAGS += ${libfuse2_CFLAGS} ${libfuse3_CFLAGS} ${libselinux_CFLAGS}
+erofsfuse_LDADD = $(top_builddir)/lib/liberofs.la ${libfuse2_LIBS} ${libfuse3_LIBS} ${liblz4_LIBS} \
+	${libselinux_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} ${libzstd_LIBS} \
+	${libqpl_LIBS}
+
+if ENABLE_STATIC_FUSE
+lib_LIBRARIES = liberofsfuse.a
+liberofsfuse_a_SOURCES = main.c
+liberofsfuse_a_CFLAGS  = -Wall -I$(top_srcdir)/include
+liberofsfuse_a_CFLAGS += -Dmain=erofsfuse_main ${libfuse2_CFLAGS} ${libfuse3_CFLAGS} ${libselinux_CFLAGS}
+liberofsfuse_a_LIBADD  = $(top_builddir)/lib/liberofs.la
+endif
diff --git a/fuse/main.c b/fuse/main.c
index 821d98c..f6c04e8 100644
--- a/fuse/main.c
+++ b/fuse/main.c
@@ -1,191 +1,516 @@
 // SPDX-License-Identifier: GPL-2.0+
 /*
  * Created by Li Guifu <blucerlee@gmail.com>
+ * Lowlevel added by Li Yiyan <lyy0627@sjtu.edu.cn>
  */
 #include <stdlib.h>
 #include <string.h>
 #include <signal.h>
 #include <libgen.h>
-#include <fuse.h>
-#include <fuse_opt.h>
 #include "macosx.h"
 #include "erofs/config.h"
 #include "erofs/print.h"
-#include "erofs/io.h"
 #include "erofs/dir.h"
 #include "erofs/inode.h"
 
-struct erofsfuse_dir_context {
+#include <float.h>
+#include <fuse.h>
+#include <fuse_lowlevel.h>
+
+#define EROFSFUSE_TIMEOUT DBL_MAX
+
+struct erofsfuse_readdir_context {
 	struct erofs_dir_context ctx;
-	fuse_fill_dir_t filler;
-	struct fuse_file_info *fi;
+
+	fuse_req_t req;
 	void *buf;
+	int is_plus;
+	size_t index;
+	size_t buf_rem;
+	size_t offset;
+	struct fuse_file_info *fi;
+};
+
+struct erofsfuse_lookupdir_context {
+	struct erofs_dir_context ctx;
+
+	const char *target_name;
+	struct fuse_entry_param *ent;
 };
 
-static int erofsfuse_fill_dentries(struct erofs_dir_context *ctx)
+static inline erofs_nid_t erofsfuse_to_nid(fuse_ino_t ino)
 {
-	struct erofsfuse_dir_context *fusectx = (void *)ctx;
-	struct stat st = {0};
+	if (ino == FUSE_ROOT_ID)
+		return g_sbi.root_nid;
+	return (erofs_nid_t)(ino - FUSE_ROOT_ID);
+}
+
+static inline fuse_ino_t erofsfuse_to_ino(erofs_nid_t nid)
+{
+	if (nid == g_sbi.root_nid)
+		return FUSE_ROOT_ID;
+	return (nid + FUSE_ROOT_ID);
+}
+
+static void erofsfuse_fill_stat(struct erofs_inode *vi, struct stat *stbuf)
+{
+	if (S_ISBLK(vi->i_mode) || S_ISCHR(vi->i_mode))
+		stbuf->st_rdev = vi->u.i_rdev;
+
+	stbuf->st_mode = vi->i_mode;
+	stbuf->st_nlink = vi->i_nlink;
+	stbuf->st_size = vi->i_size;
+	stbuf->st_blocks = roundup(vi->i_size, erofs_blksiz(&g_sbi)) >> 9;
+	stbuf->st_uid = vi->i_uid;
+	stbuf->st_gid = vi->i_gid;
+	stbuf->st_ctime = vi->i_mtime;
+	stbuf->st_mtime = stbuf->st_ctime;
+	stbuf->st_atime = stbuf->st_ctime;
+}
+
+static int erofsfuse_add_dentry(struct erofs_dir_context *ctx)
+{
+	size_t entsize = 0;
 	char dname[EROFS_NAME_LEN + 1];
+	struct erofsfuse_readdir_context *readdir_ctx = (void *)ctx;
+
+	if (readdir_ctx->index < readdir_ctx->offset) {
+		readdir_ctx->index++;
+		return 0;
+	}
 
 	strncpy(dname, ctx->dname, ctx->de_namelen);
 	dname[ctx->de_namelen] = '\0';
-	st.st_mode = erofs_ftype_to_dtype(ctx->de_ftype) << 12;
-	fusectx->filler(fusectx->buf, dname, &st, 0);
+
+	if (!readdir_ctx->is_plus) { /* fuse 3 still use non-plus readdir */
+		struct stat st = { 0 };
+
+		st.st_mode = erofs_ftype_to_mode(ctx->de_ftype, 0);
+		st.st_ino = erofsfuse_to_ino(ctx->de_nid);
+		entsize = fuse_add_direntry(readdir_ctx->req, readdir_ctx->buf,
+					 readdir_ctx->buf_rem, dname, &st,
+					 readdir_ctx->index + 1);
+	} else {
+#if FUSE_MAJOR_VERSION >= 3
+		int ret;
+		struct erofs_inode vi = {
+			.sbi = &g_sbi,
+			.nid = ctx->de_nid
+		};
+
+		ret = erofs_read_inode_from_disk(&vi);
+		if (ret < 0)
+			return ret;
+
+		struct fuse_entry_param param = {
+			.ino = erofsfuse_to_ino(ctx->de_nid),
+			.attr.st_ino = erofsfuse_to_ino(ctx->de_nid),
+			.generation = 0,
+
+			.attr_timeout = EROFSFUSE_TIMEOUT,
+			.entry_timeout = EROFSFUSE_TIMEOUT,
+		};
+		erofsfuse_fill_stat(&vi, &(param.attr));
+
+		entsize = fuse_add_direntry_plus(readdir_ctx->req,
+					      readdir_ctx->buf,
+					      readdir_ctx->buf_rem, dname,
+					      &param, readdir_ctx->index + 1);
+#else
+		return -EOPNOTSUPP;
+#endif
+	}
+
+	if (entsize > readdir_ctx->buf_rem)
+		return 1;
+	readdir_ctx->index++;
+	readdir_ctx->buf += entsize;
+	readdir_ctx->buf_rem -= entsize;
 	return 0;
 }
 
-int erofsfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
-		      off_t offset, struct fuse_file_info *fi)
+static int erofsfuse_lookup_dentry(struct erofs_dir_context *ctx)
 {
-	int ret;
-	struct erofs_inode dir;
-	struct erofsfuse_dir_context ctx = {
-		.ctx.dir = &dir,
-		.ctx.cb = erofsfuse_fill_dentries,
-		.filler = filler,
-		.fi = fi,
-		.buf = buf,
-	};
-	erofs_dbg("readdir:%s offset=%llu", path, (long long)offset);
-
-	dir.sbi = &sbi;
-	ret = erofs_ilookup(path, &dir);
-	if (ret)
-		return ret;
+	struct erofsfuse_lookupdir_context *lookup_ctx = (void *)ctx;
 
-	erofs_dbg("path=%s nid = %llu", path, dir.nid | 0ULL);
-	if (!S_ISDIR(dir.i_mode))
-		return -ENOTDIR;
-
-	if (!dir.i_size)
+	if (lookup_ctx->ent->ino != 0 ||
+	    strlen(lookup_ctx->target_name) != ctx->de_namelen)
 		return 0;
+
+	if (!strncmp(lookup_ctx->target_name, ctx->dname, ctx->de_namelen)) {
+		int ret;
+		struct erofs_inode vi = {
+			.sbi = &g_sbi,
+			.nid = (erofs_nid_t)ctx->de_nid,
+		};
+
+		ret = erofs_read_inode_from_disk(&vi);
+		if (ret < 0)
+			return ret;
+
+		lookup_ctx->ent->ino = erofsfuse_to_ino(ctx->de_nid);
+		lookup_ctx->ent->attr.st_ino = erofsfuse_to_ino(ctx->de_nid);
+
+		erofsfuse_fill_stat(&vi, &(lookup_ctx->ent->attr));
+	}
+	return 0;
+}
+
+static inline void erofsfuse_readdir_general(fuse_req_t req, fuse_ino_t ino,
+					     size_t size, off_t off,
+					     struct fuse_file_info *fi,
+					     int plus)
+{
+	int ret = 0;
+	char *buf = NULL;
+	struct erofsfuse_readdir_context ctx = { 0 };
+	struct erofs_inode *vi = (struct erofs_inode *)fi->fh;
+
+	erofs_dbg("readdir(%llu): size: %zu, off: %lu, plus: %d", ino | 0ULL,
+		  size, off, plus);
+
+	buf = malloc(size);
+	if (!buf) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
+	ctx.ctx.dir = vi;
+	ctx.ctx.cb = erofsfuse_add_dentry;
+
+	ctx.fi = fi;
+	ctx.buf = buf;
+	ctx.buf_rem = size;
+	ctx.req = req;
+	ctx.index = 0;
+	ctx.offset = off;
+	ctx.is_plus = plus;
+
 #ifdef NDEBUG
-	return erofs_iterate_dir(&ctx.ctx, false);
+	ret = erofs_iterate_dir(&ctx.ctx, false);
 #else
-	return erofs_iterate_dir(&ctx.ctx, true);
+	ret = erofs_iterate_dir(&ctx.ctx, true);
 #endif
+
+	if (ret < 0) /* if buffer insufficient, return 1 */
+		fuse_reply_err(req, -ret);
+	else
+		fuse_reply_buf(req, buf, size - ctx.buf_rem);
+
+	free(buf);
 }
 
-static void *erofsfuse_init(struct fuse_conn_info *info)
+static void erofsfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
+			      off_t off, struct fuse_file_info *fi)
 {
-	erofs_info("Using FUSE protocol %d.%d", info->proto_major, info->proto_minor);
-	return NULL;
+	erofsfuse_readdir_general(req, ino, size, off, fi, 0);
 }
 
-static int erofsfuse_open(const char *path, struct fuse_file_info *fi)
+#if FUSE_MAJOR_VERSION >= 3
+static void erofsfuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
+				  off_t off, struct fuse_file_info *fi)
 {
-	erofs_dbg("open path=%s", path);
+	erofsfuse_readdir_general(req, ino, size, off, fi, 1);
+}
+#endif
 
-	if ((fi->flags & O_ACCMODE) != O_RDONLY)
-		return -EACCES;
+static void erofsfuse_init(void *userdata, struct fuse_conn_info *conn)
+{
+	erofs_info("Using FUSE protocol %d.%d", conn->proto_major,
+		   conn->proto_minor);
+}
 
-	return 0;
+static void erofsfuse_open(fuse_req_t req, fuse_ino_t ino,
+			   struct fuse_file_info *fi)
+{
+	int ret = 0;
+	struct erofs_inode *vi;
+
+	if (fi->flags & (O_WRONLY | O_RDWR)) {
+		fuse_reply_err(req, EROFS);
+		return;
+	}
+
+	vi = (struct erofs_inode *)malloc(sizeof(struct erofs_inode));
+	if (!vi) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
+
+	vi->sbi = &g_sbi;
+	vi->nid = erofsfuse_to_nid(ino);
+	ret = erofs_read_inode_from_disk(vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
+
+	if (!S_ISREG(vi->i_mode)) {
+		fuse_reply_err(req, EISDIR);
+	} else {
+		fi->fh = (uint64_t)vi;
+		fi->keep_cache = 1;
+		fuse_reply_open(req, fi);
+		return;
+	}
+
+out:
+	free(vi);
 }
 
-static int erofsfuse_getattr(const char *path, struct stat *stbuf)
+static void erofsfuse_getattr(fuse_req_t req, fuse_ino_t ino,
+			      struct fuse_file_info *fi)
 {
-	struct erofs_inode vi = { .sbi = &sbi };
 	int ret;
+	struct stat stbuf = { 0 };
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };
 
-	erofs_dbg("getattr(%s)", path);
-	ret = erofs_ilookup(path, &vi);
-	if (ret)
-		return -ENOENT;
-
-	stbuf->st_mode  = vi.i_mode;
-	stbuf->st_nlink = vi.i_nlink;
-	stbuf->st_size  = vi.i_size;
-	stbuf->st_blocks = roundup(vi.i_size, erofs_blksiz(vi.sbi)) >> 9;
-	stbuf->st_uid = vi.i_uid;
-	stbuf->st_gid = vi.i_gid;
-	if (S_ISBLK(vi.i_mode) || S_ISCHR(vi.i_mode))
-		stbuf->st_rdev = vi.u.i_rdev;
-	stbuf->st_ctime = vi.i_mtime;
-	stbuf->st_mtime = stbuf->st_ctime;
-	stbuf->st_atime = stbuf->st_ctime;
-	return 0;
+	ret = erofs_read_inode_from_disk(&vi);
+	if (ret < 0)
+		fuse_reply_err(req, -ret);
+
+	erofsfuse_fill_stat(&vi, &stbuf);
+	stbuf.st_ino = ino;
+
+	fuse_reply_attr(req, &stbuf, EROFSFUSE_TIMEOUT);
 }
 
-static int erofsfuse_read(const char *path, char *buffer,
-			  size_t size, off_t offset,
-			  struct fuse_file_info *fi)
+static void erofsfuse_opendir(fuse_req_t req, fuse_ino_t ino,
+			      struct fuse_file_info *fi)
 {
 	int ret;
-	struct erofs_inode vi;
+	struct erofs_inode *vi;
 
-	erofs_dbg("path:%s size=%zd offset=%llu", path, size, (long long)offset);
+	vi = (struct erofs_inode *)malloc(sizeof(struct erofs_inode));
+	if (!vi) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
 
-	vi.sbi = &sbi;
-	ret = erofs_ilookup(path, &vi);
-	if (ret)
-		return ret;
+	vi->sbi = &g_sbi;
+	vi->nid = erofsfuse_to_nid(ino);
+	ret = erofs_read_inode_from_disk(vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
 
-	ret = erofs_pread(&vi, buffer, size, offset);
-	if (ret)
-		return ret;
-	if (offset >= vi.i_size)
-		return 0;
-	if (offset + size > vi.i_size)
-		return vi.i_size - offset;
-	return size;
+	if (!S_ISDIR(vi->i_mode)) {
+		fuse_reply_err(req, ENOTDIR);
+		goto out;
+	}
+
+	fi->fh = (uint64_t)vi;
+	fuse_reply_open(req, fi);
+	return;
+
+out:
+	free(vi);
 }
 
-static int erofsfuse_readlink(const char *path, char *buffer, size_t size)
+static void erofsfuse_release(fuse_req_t req, fuse_ino_t ino,
+			      struct fuse_file_info *fi)
 {
-	int ret = erofsfuse_read(path, buffer, size, 0, NULL);
+	free((struct erofs_inode *)fi->fh);
+	fi->fh = 0;
+	fuse_reply_err(req, 0);
+}
 
-	if (ret < 0)
-		return ret;
-	DBG_BUGON(ret > size);
-	if (ret == size)
-		buffer[size - 1] = '\0';
-	erofs_dbg("readlink(%s): %s", path, buffer);
-	return 0;
+static void erofsfuse_lookup(fuse_req_t req, fuse_ino_t parent,
+			     const char *name)
+{
+	int ret;
+	struct erofs_inode *vi;
+	struct fuse_entry_param fentry = { 0 };
+	struct erofsfuse_lookupdir_context ctx = { 0 };
+
+	vi = (struct erofs_inode *)malloc(sizeof(struct erofs_inode));
+	if (!vi) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
+
+	vi->sbi = &g_sbi;
+	vi->nid = erofsfuse_to_nid(parent);
+	ret = erofs_read_inode_from_disk(vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
+
+	memset(&fentry, 0, sizeof(fentry));
+	fentry.ino = 0;
+	fentry.attr_timeout = fentry.entry_timeout = EROFSFUSE_TIMEOUT;
+	ctx.ctx.dir = vi;
+	ctx.ctx.cb = erofsfuse_lookup_dentry;
+
+	ctx.ent = &fentry;
+	ctx.target_name = name;
+
+#ifdef NDEBUG
+	ret = erofs_iterate_dir(&ctx.ctx, false);
+#else
+	ret = erofs_iterate_dir(&ctx.ctx, true);
+#endif
+
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
+	fuse_reply_entry(req, &fentry);
+
+out:
+	free(vi);
 }
 
-static int erofsfuse_getxattr(const char *path, const char *name, char *value,
-			size_t size
+static void erofsfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size,
+			   off_t off, struct fuse_file_info *fi)
+{
+	int ret;
+	char *buf = NULL;
+	struct erofs_inode *vi = (struct erofs_inode *)fi->fh;
+
+	erofs_dbg("read(%llu): size = %zu, off = %lu", ino | 0ULL, size, off);
+
+	buf = malloc(size);
+	if (!buf) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
+
+	ret = erofs_pread(vi, buf, size, off);
+	if (ret) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
+	if (off >= vi->i_size)
+		ret = 0;
+	else if (off + size > vi->i_size)
+		ret = vi->i_size - off;
+	else
+		ret = size;
+
+	fuse_reply_buf(req, buf, ret);
+
+out:
+	free(buf);
+}
+
+static void erofsfuse_readlink(fuse_req_t req, fuse_ino_t ino)
+{
+	int ret;
+	char *buf = NULL;
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };
+
+	ret = erofs_read_inode_from_disk(&vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		return;
+	}
+
+	buf = malloc(vi.i_size + 1);
+	if (!buf) {
+		fuse_reply_err(req, ENOMEM);
+		return;
+	}
+
+	ret = erofs_pread(&vi, buf, vi.i_size, 0);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		goto out;
+	}
+
+	buf[vi.i_size] = '\0';
+	fuse_reply_readlink(req, buf);
+
+out:
+	free(buf);
+}
+
+static void erofsfuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
+			       size_t size
 #ifdef __APPLE__
-			, uint32_t position)
+			       , uint32_t position)
 #else
-			)
+			       )
 #endif
 {
 	int ret;
-	struct erofs_inode vi;
+	char *buf = NULL;
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };
 
-	erofs_dbg("getxattr(%s): name=%s size=%llu", path, name, size);
+	erofs_dbg("getattr(%llu): name = %s, size = %zu", ino | 0ULL, name, size);
 
-	vi.sbi = &sbi;
-	ret = erofs_ilookup(path, &vi);
-	if (ret)
-		return ret;
+	ret = erofs_read_inode_from_disk(&vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		return;
+	}
 
-	return erofs_getxattr(&vi, name, value, size);
+	if (size != 0) {
+		buf = malloc(size);
+		if (!buf) {
+			fuse_reply_err(req, ENOMEM);
+			return;
+		}
+	}
+
+	ret = erofs_getxattr(&vi, name, buf, size);
+	if (ret < 0)
+		fuse_reply_err(req, -ret);
+	else if (size == 0)
+		fuse_reply_xattr(req, ret);
+	else
+		fuse_reply_buf(req, buf, ret);
+
+	free(buf);
 }
 
-static int erofsfuse_listxattr(const char *path, char *list, size_t size)
+static void erofsfuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
 {
 	int ret;
-	struct erofs_inode vi;
+	char *buf = NULL;
+	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };
 
-	erofs_dbg("listxattr(%s): size=%llu", path, size);
+	erofs_dbg("listxattr(%llu): size = %zu", ino | 0ULL, size);
 
-	vi.sbi = &sbi;
-	ret = erofs_ilookup(path, &vi);
-	if (ret)
-		return ret;
+	ret = erofs_read_inode_from_disk(&vi);
+	if (ret < 0) {
+		fuse_reply_err(req, -ret);
+		return;
+	}
+
+	if (size != 0) {
+		buf = malloc(size);
+		if (!buf) {
+			fuse_reply_err(req, ENOMEM);
+			return;
+		}
+	}
 
-	return erofs_listxattr(&vi, list, size);
+	ret = erofs_listxattr(&vi, buf, size);
+	if (ret < 0)
+		fuse_reply_err(req, -ret);
+	else if (size == 0)
+		fuse_reply_xattr(req, ret);
+	else
+		fuse_reply_buf(req, buf, ret);
+
+	free(buf);
 }
 
-static struct fuse_operations erofs_ops = {
+static struct fuse_lowlevel_ops erofsfuse_lops = {
 	.getxattr = erofsfuse_getxattr,
+	.opendir = erofsfuse_opendir,
+	.releasedir = erofsfuse_release,
+	.release = erofsfuse_release,
+	.lookup = erofsfuse_lookup,
 	.listxattr = erofsfuse_listxattr,
 	.readlink = erofsfuse_readlink,
 	.getattr = erofsfuse_getattr,
 	.readdir = erofsfuse_readdir,
+#if FUSE_MAJOR_VERSION >= 3
+	.readdirplus = erofsfuse_readdirplus,
+#endif
 	.open = erofsfuse_open,
 	.read = erofsfuse_read,
 	.init = erofsfuse_init,
@@ -197,6 +522,7 @@ static struct options {
 	u64 offset;
 	unsigned int debug_lvl;
 	bool show_help;
+	bool show_version;
 	bool odebug;
 } fusecfg;
 
@@ -205,25 +531,32 @@ static const struct fuse_opt option_spec[] = {
 	OPTION("--offset=%lu", offset),
 	OPTION("--dbglevel=%u", debug_lvl),
 	OPTION("--help", show_help),
+	OPTION("--version", show_version),
 	FUSE_OPT_KEY("--device=", 1),
 	FUSE_OPT_END
 };
 
 static void usage(void)
 {
+#if FUSE_MAJOR_VERSION < 3
 	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
 
+#else
+	fuse_lowlevel_version();
+#endif
 	fputs("usage: [options] IMAGE MOUNTPOINT\n\n"
 	      "Options:\n"
-	      "    --offset=#             skip # bytes when reading IMAGE\n"
+	      "    --offset=#             skip # bytes at the beginning of IMAGE\n"
 	      "    --dbglevel=#           set output message level to # (maximum 9)\n"
 	      "    --device=#             specify an extra device to be used together\n"
 #if FUSE_MAJOR_VERSION < 3
 	      "    --help                 display this help and exit\n"
+	      "    --version              display erofsfuse version\n"
 #endif
 	      "\n", stderr);
 
 #if FUSE_MAJOR_VERSION >= 3
+	fputs("\nFUSE options:\n", stderr);
 	fuse_cmdline_help();
 #else
 	fuse_opt_add_arg(&args, ""); /* progname */
@@ -233,14 +566,6 @@ static void usage(void)
 	exit(EXIT_FAILURE);
 }
 
-static void erofsfuse_dumpcfg(void)
-{
-	erofs_dump("disk: %s\n", fusecfg.disk);
-	erofs_dump("offset: %llu\n", fusecfg.offset | 0ULL);
-	erofs_dump("mountpoint: %s\n", fusecfg.mountpoint);
-	erofs_dump("dbglevel: %u\n", cfg.c_dbg_lvl);
-}
-
 static int optional_opt_func(void *data, const char *arg, int key,
 			     struct fuse_args *outargs)
 {
@@ -248,10 +573,10 @@ static int optional_opt_func(void *data, const char *arg, int key,
 
 	switch (key) {
 	case 1:
-		ret = blob_open_ro(&sbi, arg + sizeof("--device=") - 1);
+		ret = erofs_blob_open_ro(&g_sbi, arg + sizeof("--device=") - 1);
 		if (ret)
 			return -1;
-		++sbi.extra_devices;
+		++g_sbi.extra_devices;
 		return 0;
 	case FUSE_OPT_KEY_NONOPT:
 		if (fusecfg.mountpoint)
@@ -266,12 +591,12 @@ static int optional_opt_func(void *data, const char *arg, int key,
 	case FUSE_OPT_KEY_OPT:
 		if (!strcmp(arg, "-d"))
 			fusecfg.odebug = true;
-		break;
-	default:
-		DBG_BUGON(1);
-		break;
+		if (!strcmp(arg, "-h"))
+			fusecfg.show_help = true;
+		if (!strcmp(arg, "-V"))
+			fusecfg.show_version = true;
 	}
-	return 1;
+	return 1; // keep arg
 }
 
 #if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE)
@@ -298,13 +623,28 @@ static void signal_handle_sigsegv(int signal)
 }
 #endif
 
+#define EROFSFUSE_MOUNT_MSG	\
+	erofs_warn("%s mounted on %s with offset %u",	\
+		   fusecfg.disk, fusecfg.mountpoint, fusecfg.offset);
+
 int main(int argc, char *argv[])
 {
 	int ret;
+	struct fuse_session *se;
 	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
+#if FUSE_MAJOR_VERSION >= 3
+	struct fuse_cmdline_opts opts = {};
+#else
+	struct fuse_chan *ch;
+	struct {
+		char *mountpoint;
+		int mt, foreground;
+	} opts = {};
+#endif
 
 	erofs_init_configure();
-	printf("%s %s\n", basename(argv[0]), cfg.c_version);
+	fusecfg.debug_lvl = cfg.c_dbg_lvl;
+	printf("erofsfuse %s\n", cfg.c_version);
 
 #if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE)
 	if (signal(SIGSEGV, signal_handle_sigsegv) == SIG_ERR) {
@@ -319,35 +659,97 @@ int main(int argc, char *argv[])
 	if (ret)
 		goto err;
 
-	if (fusecfg.show_help || !fusecfg.mountpoint)
+#if FUSE_MAJOR_VERSION >= 3
+	ret = fuse_parse_cmdline(&args, &opts);
+#else
+	ret = (fuse_parse_cmdline(&args, &opts.mountpoint, &opts.mt,
+				  &opts.foreground) < 0);
+#endif
+	if (ret)
+		goto err_fuse_free_args;
+
+	if (fusecfg.show_help || fusecfg.show_version || !opts.mountpoint)
 		usage();
 	cfg.c_dbg_lvl = fusecfg.debug_lvl;
 
 	if (fusecfg.odebug && cfg.c_dbg_lvl < EROFS_DBG)
 		cfg.c_dbg_lvl = EROFS_DBG;
 
-	cfg.c_offset = fusecfg.offset;
-
-	erofsfuse_dumpcfg();
-	ret = dev_open_ro(&sbi, fusecfg.disk);
+	g_sbi.bdev.offset = fusecfg.offset;
+	ret = erofs_dev_open(&g_sbi, fusecfg.disk, O_RDONLY);
 	if (ret) {
 		fprintf(stderr, "failed to open: %s\n", fusecfg.disk);
 		goto err_fuse_free_args;
 	}
 
-	ret = erofs_read_superblock(&sbi);
+	ret = erofs_read_superblock(&g_sbi);
 	if (ret) {
 		fprintf(stderr, "failed to read erofs super block\n");
 		goto err_dev_close;
 	}
 
-	ret = fuse_main(args.argc, args.argv, &erofs_ops, NULL);
+#if FUSE_MAJOR_VERSION >= 3
+	se = fuse_session_new(&args, &erofsfuse_lops, sizeof(erofsfuse_lops),
+			      NULL);
+	if (!se)
+		goto err_super_put;
+
+	if (fuse_session_mount(se, opts.mountpoint) >= 0) {
+		EROFSFUSE_MOUNT_MSG
+		if (fuse_daemonize(opts.foreground) >= 0) {
+			if (fuse_set_signal_handlers(se) >= 0) {
+				if (opts.singlethread) {
+					ret = fuse_session_loop(se);
+				} else {
+#if FUSE_USE_VERSION == 30
+					ret = fuse_session_loop_mt(se, opts.clone_fd);
+#elif FUSE_USE_VERSION == 32
+					struct fuse_loop_config config = {
+						.clone_fd = opts.clone_fd,
+						.max_idle_threads = opts.max_idle_threads
+					};
+					ret = fuse_session_loop_mt(se, &config);
+#else
+#error "FUSE_USE_VERSION not supported"
+#endif
+				}
+				fuse_remove_signal_handlers(se);
+			}
+			fuse_session_unmount(se);
+			fuse_session_destroy(se);
+		}
+	}
+#else
+	ch = fuse_mount(opts.mountpoint, &args);
+	if (!ch)
+		goto err_super_put;
+	EROFSFUSE_MOUNT_MSG
+	se = fuse_lowlevel_new(&args, &erofsfuse_lops, sizeof(erofsfuse_lops),
+			       NULL);
+	if (se) {
+		if (fuse_daemonize(opts.foreground) != -1) {
+			if (fuse_set_signal_handlers(se) != -1) {
+				fuse_session_add_chan(se, ch);
+				if (opts.mt)
+					ret = fuse_session_loop_mt(se);
+				else
+					ret = fuse_session_loop(se);
+				fuse_remove_signal_handlers(se);
+				fuse_session_remove_chan(ch);
+			}
+		}
+		fuse_session_destroy(se);
+	}
+	fuse_unmount(opts.mountpoint, ch);
+#endif
 
-	erofs_put_super(&sbi);
+err_super_put:
+	erofs_put_super(&g_sbi);
 err_dev_close:
-	blob_closeall(&sbi);
-	dev_close(&sbi);
+	erofs_blob_closeall(&g_sbi);
+	erofs_dev_close(&g_sbi);
 err_fuse_free_args:
+	free(opts.mountpoint);
 	fuse_opt_free_args(&args);
 err:
 	erofs_exit_configure();
diff --git a/include/erofs/atomic.h b/include/erofs/atomic.h
new file mode 100644
index 0000000..f28687e
--- /dev/null
+++ b/include/erofs/atomic.h
@@ -0,0 +1,38 @@
+/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
+/*
+ * Copyright (C) 2024 Alibaba Cloud
+ */
+#ifndef __EROFS_ATOMIC_H
+#define __EROFS_ATOMIC_H
+
+/*
+ * Just use GCC/clang built-in functions for now
+ * See: https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
+ */
+typedef unsigned long erofs_atomic_t;
+typedef char erofs_atomic_bool_t;
+
+#define erofs_atomic_read(ptr) ({ \
+	typeof(*ptr) __n;    \
+	__atomic_load(ptr, &__n, __ATOMIC_RELAXED); \
+__n;})
+
+#define erofs_atomic_set(ptr, n) do { \
+	typeof(*ptr) __n = (n);    \
+	__atomic_store(ptr, &__n, __ATOMIC_RELAXED); \
+} while(0)
+
+#define erofs_atomic_test_and_set(ptr) \
+	__atomic_test_and_set(ptr, __ATOMIC_RELAXED)
+
+#define erofs_atomic_add_return(ptr, i) \
+	__atomic_add_fetch(ptr, i, __ATOMIC_RELAXED)
+
+#define erofs_atomic_sub_return(ptr, i) \
+	__atomic_sub_fetch(ptr, i, __ATOMIC_RELAXED)
+
+#define erofs_atomic_inc_return(ptr) erofs_atomic_add_return(ptr, 1)
+
+#define erofs_atomic_dec_return(ptr) erofs_atomic_sub_return(ptr, 1)
+
+#endif
diff --git a/include/erofs/blobchunk.h b/include/erofs/blobchunk.h
index a426111..ebe2efe 100644
--- a/include/erofs/blobchunk.h
+++ b/include/erofs/blobchunk.h
@@ -19,6 +19,7 @@ struct erofs_blobchunk *erofs_get_unhashed_chunk(unsigned int device_id,
 int erofs_blob_write_chunk_indexes(struct erofs_inode *inode, erofs_off_t off);
 int erofs_blob_write_chunked_file(struct erofs_inode *inode, int fd,
 				  erofs_off_t startoff);
+int erofs_write_zero_inode(struct erofs_inode *inode);
 int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset);
 int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi);
 void erofs_blob_exit(void);
diff --git a/include/erofs/block_list.h b/include/erofs/block_list.h
index 9f9975e..7db4d0c 100644
--- a/include/erofs/block_list.h
+++ b/include/erofs/block_list.h
@@ -13,8 +13,8 @@ extern "C"
 
 #include "internal.h"
 
-int erofs_blocklist_open(char *filename, bool srcmap);
-void erofs_blocklist_close(void);
+int erofs_blocklist_open(FILE *fp, bool srcmap);
+FILE *erofs_blocklist_close(void);
 
 void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
 			      erofs_off_t srcoff);
diff --git a/include/erofs/cache.h b/include/erofs/cache.h
index de5584e..5411eed 100644
--- a/include/erofs/cache.h
+++ b/include/erofs/cache.h
@@ -3,7 +3,7 @@
  * Copyright (C) 2018 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Miao Xie <miaoxie@huawei.com>
- * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
+ * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_CACHE_H
 #define __EROFS_CACHE_H
@@ -30,8 +30,7 @@ struct erofs_buffer_block;
 #define DEVT		5
 
 struct erofs_bhops {
-	bool (*preflush)(struct erofs_buffer_head *bh);
-	bool (*flush)(struct erofs_buffer_head *bh);
+	int (*flush)(struct erofs_buffer_head *bh);
 };
 
 struct erofs_buffer_head {
@@ -54,17 +53,31 @@ struct erofs_buffer_block {
 	struct erofs_buffer_head buffers;
 };
 
-static inline const int get_alignsize(int type, int *type_ret)
+struct erofs_bufmgr {
+	struct erofs_sb_info *sbi;
+
+	/* buckets for all mapped buffer blocks to boost up allocation */
+	struct list_head mapped_buckets[META + 1][EROFS_MAX_BLOCK_SIZE];
+
+	struct erofs_buffer_block blkh;
+	erofs_blk_t tail_blkaddr, metablkcnt;
+
+	/* last mapped buffer block to accelerate erofs_mapbh() */
+	struct erofs_buffer_block *last_mapped_block;
+};
+
+static inline const int get_alignsize(struct erofs_sb_info *sbi, int type,
+				      int *type_ret)
 {
 	if (type == DATA)
-		return erofs_blksiz(&sbi);
+		return erofs_blksiz(sbi);
 
 	if (type == INODE) {
 		*type_ret = META;
 		return sizeof(struct erofs_inode_compact);
 	} else if (type == DIRA) {
 		*type_ret = META;
-		return erofs_blksiz(&sbi);
+		return erofs_blksiz(sbi);
 	} else if (type == XATTR) {
 		*type_ret = META;
 		return sizeof(struct erofs_xattr_entry);
@@ -84,35 +97,42 @@ extern const struct erofs_bhops erofs_skip_write_bhops;
 static inline erofs_off_t erofs_btell(struct erofs_buffer_head *bh, bool end)
 {
 	const struct erofs_buffer_block *bb = bh->block;
+	struct erofs_bufmgr *bmgr =
+			(struct erofs_bufmgr *)bb->buffers.fsprivate;
 
 	if (bb->blkaddr == NULL_ADDR)
 		return NULL_ADDR_UL;
 
-	return erofs_pos(&sbi, bb->blkaddr) +
+	return erofs_pos(bmgr->sbi, bb->blkaddr) +
 		(end ? list_next_entry(bh, list)->off : bh->off);
 }
 
-static inline bool erofs_bh_flush_generic_end(struct erofs_buffer_head *bh)
+static inline int erofs_bh_flush_generic_end(struct erofs_buffer_head *bh)
 {
 	list_del(&bh->list);
 	free(bh);
-	return true;
+	return 0;
 }
 
-struct erofs_buffer_head *erofs_buffer_init(void);
+struct erofs_bufmgr *erofs_buffer_init(struct erofs_sb_info *sbi,
+				       erofs_blk_t startblk);
 int erofs_bh_balloon(struct erofs_buffer_head *bh, erofs_off_t incr);
 
-struct erofs_buffer_head *erofs_balloc(int type, erofs_off_t size,
+struct erofs_buffer_head *erofs_balloc(struct erofs_bufmgr *bmgr,
+				       int type, erofs_off_t size,
 				       unsigned int required_ext,
 				       unsigned int inline_ext);
 struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
 					int type, unsigned int size);
 
-erofs_blk_t erofs_mapbh(struct erofs_buffer_block *bb);
-bool erofs_bflush(struct erofs_buffer_block *bb);
+erofs_blk_t erofs_mapbh(struct erofs_bufmgr *bmgr,
+			struct erofs_buffer_block *bb);
+int erofs_bflush(struct erofs_bufmgr *bmgr,
+		 struct erofs_buffer_block *bb);
 
 void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke);
-erofs_blk_t erofs_total_metablocks(void);
+erofs_blk_t erofs_total_metablocks(struct erofs_bufmgr *bmgr);
+void erofs_buffer_exit(struct erofs_bufmgr *bmgr);
 
 #ifdef __cplusplus
 }
diff --git a/include/erofs/compress.h b/include/erofs/compress.h
index 46cff03..c9831a7 100644
--- a/include/erofs/compress.h
+++ b/include/erofs/compress.h
@@ -2,7 +2,7 @@
 /*
  * Copyright (C) 2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_COMPRESS_H
 #define __EROFS_COMPRESS_H
@@ -14,17 +14,21 @@ extern "C"
 
 #include "internal.h"
 
-#define EROFS_CONFIG_COMPR_MAX_SZ           (4000 * 1024)
+#define EROFS_CONFIG_COMPR_MAX_SZ	(4000 * 1024)
+#define Z_EROFS_COMPR_QUEUE_SZ		(EROFS_CONFIG_COMPR_MAX_SZ * 2)
+
+struct z_erofs_compress_ictx;
 
 void z_erofs_drop_inline_pcluster(struct erofs_inode *inode);
-int erofs_write_compressed_file(struct erofs_inode *inode, int fd);
+void *erofs_begin_compressed_file(struct erofs_inode *inode, int fd, u64 fpos);
+int erofs_write_compressed_file(struct z_erofs_compress_ictx *ictx);
 
 int z_erofs_compress_init(struct erofs_sb_info *sbi,
 			  struct erofs_buffer_head *bh);
 int z_erofs_compress_exit(void);
 
 const char *z_erofs_list_supported_algorithms(int i, unsigned int *mask);
-const char *z_erofs_list_available_compressors(int *i);
+const struct erofs_algorithm *z_erofs_list_available_compressors(int *i);
 
 static inline bool erofs_is_packed_inode(struct erofs_inode *inode)
 {
diff --git a/include/erofs/config.h b/include/erofs/config.h
index e342722..ae366c1 100644
--- a/include/erofs/config.h
+++ b/include/erofs/config.h
@@ -27,6 +27,7 @@ enum {
 };
 
 enum {
+	TIMESTAMP_UNSPECIFIED,
 	TIMESTAMP_NONE,
 	TIMESTAMP_FIXED,
 	TIMESTAMP_CLAMPING,
@@ -34,6 +35,12 @@ enum {
 
 #define EROFS_MAX_COMPR_CFGS		64
 
+struct erofs_compr_opts {
+	char *alg;
+	int level;
+	u32 dict_size;
+};
+
 struct erofs_configure {
 	const char *c_version;
 	int c_dbg_lvl;
@@ -64,28 +71,29 @@ struct erofs_configure {
 	char *c_src_path;
 	char *c_blobdev_path;
 	char *c_compress_hints_file;
-	char *c_compr_alg[EROFS_MAX_COMPR_CFGS];
-	int c_compr_level[EROFS_MAX_COMPR_CFGS];
+	struct erofs_compr_opts c_compr_opts[EROFS_MAX_COMPR_CFGS];
 	char c_force_inodeversion;
 	char c_force_chunkformat;
 	/* < 0, xattr disabled and INT_MAX, always use inline xattrs */
 	int c_inline_xattr_tolerance;
-
-	u32 c_pclusterblks_max, c_pclusterblks_def, c_pclusterblks_packed;
+#ifdef EROFS_MT_ENABLED
+	u64 c_mkfs_segment_size;
+	u32 c_mt_workers;
+#endif
+	u32 c_mkfs_pclustersize_max;
+	u32 c_mkfs_pclustersize_def;
+	u32 c_mkfs_pclustersize_packed;
 	u32 c_max_decompressed_extent_bytes;
-	u32 c_dict_size;
 	u64 c_unix_timestamp;
 	u32 c_uid, c_gid;
 	const char *mount_point;
 	long long c_uid_offset, c_gid_offset;
+	u32 c_root_xattr_isize;
 #ifdef WITH_ANDROID
 	char *target_out_path;
 	char *fs_config_file;
 	char *block_list_file;
 #endif
-
-	/* offset when reading multi partition images */
-	u64 c_offset;
 };
 
 extern struct erofs_configure cfg;
@@ -94,6 +102,9 @@ void erofs_init_configure(void);
 void erofs_show_config(void);
 void erofs_exit_configure(void);
 
+/* (will be deprecated) temporary helper for updating global the cfg */
+struct erofs_configure *erofs_get_configure();
+
 void erofs_set_fs_root(const char *rootdir);
 const char *erofs_fspath(const char *fullpath);
 
@@ -108,6 +119,7 @@ static inline int erofs_selabel_open(const char *file_contexts)
 
 void erofs_update_progressinfo(const char *fmt, ...);
 char *erofs_trim_for_progressinfo(const char *str, int placeholder);
+unsigned int erofs_get_available_processors(void);
 
 #ifdef __cplusplus
 }
diff --git a/include/erofs/dedupe.h b/include/erofs/dedupe.h
index 153bd4c..4cbfb2c 100644
--- a/include/erofs/dedupe.h
+++ b/include/erofs/dedupe.h
@@ -16,7 +16,7 @@ struct z_erofs_inmem_extent {
 	erofs_blk_t blkaddr;
 	unsigned int compressedblks;
 	unsigned int length;
-	bool raw, partial;
+	bool raw, partial, inlined;
 };
 
 struct z_erofs_dedupe_ctx {
diff --git a/include/erofs/defs.h b/include/erofs/defs.h
index fefa7e7..e462338 100644
--- a/include/erofs/defs.h
+++ b/include/erofs/defs.h
@@ -3,7 +3,7 @@
  * Copyright (C) 2018 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Li Guifu <bluce.liguifu@huawei.com>
- * Modified by Gao Xiang <gaoxiang25@huawei.com>
+ * Modified by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_DEFS_H
 #define __EROFS_DEFS_H
@@ -204,6 +204,11 @@ static inline void put_unaligned_le32(u32 val, void *p)
 	__put_unaligned_t(__le32, cpu_to_le32(val), p);
 }
 
+static inline u32 get_unaligned_le64(const void *p)
+{
+	return le64_to_cpu(__get_unaligned_t(__le64, p));
+}
+
 /**
  * ilog2 - log of base 2 of 32-bit or a 64-bit unsigned value
  * @n - parameter
@@ -283,7 +288,7 @@ static inline void put_unaligned_le32(u32 val, void *p)
 
 static inline unsigned int fls_long(unsigned long x)
 {
-	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
+	return x ? sizeof(x) * 8 - __builtin_clzl(x) : 0;
 }
 
 static inline unsigned long lowbit(unsigned long n)
@@ -327,17 +332,23 @@ unsigned long __roundup_pow_of_two(unsigned long n)
 #define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atim.tv_nsec)
 #define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctim.tv_nsec)
 #define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtim.tv_nsec)
+#define ST_MTIM_NSEC_SET(stbuf, val) (stbuf)->st_mtim.tv_nsec = (val)
 #elif defined(HAVE_STRUCT_STAT_ST_ATIMENSEC)
 /* macOS */
 #define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atimensec)
 #define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctimensec)
 #define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtimensec)
+#define ST_MTIM_NSEC_SET(stbuf, val) (stbuf)->st_mtimensec = (val)
 #else
 #define ST_ATIM_NSEC(stbuf) 0
 #define ST_CTIM_NSEC(stbuf) 0
 #define ST_MTIM_NSEC(stbuf) 0
+#define ST_MTIM_NSEC_SET(stbuf, val) do { } while (0)
 #endif
 
+#define __erofs_likely(x)      __builtin_expect(!!(x), 1)
+#define __erofs_unlikely(x)    __builtin_expect(!!(x), 0)
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/include/erofs/fragments.h b/include/erofs/fragments.h
index 4c6f755..65910f5 100644
--- a/include/erofs/fragments.h
+++ b/include/erofs/fragments.h
@@ -17,7 +17,7 @@ extern const char *erofs_frags_packedname;
 
 FILE *erofs_packedfile_init(void);
 void erofs_packedfile_exit(void);
-struct erofs_inode *erofs_mkfs_build_packedfile(void);
+int erofs_flush_packed_inode(struct erofs_sb_info *sbi);
 
 int z_erofs_fragments_dedupe(struct erofs_inode *inode, int fd, u32 *tofcrc);
 int z_erofs_pack_file_from_fd(struct erofs_inode *inode, int fd, u32 tofcrc);
diff --git a/include/erofs/hashmap.h b/include/erofs/hashmap.h
index d25092d..484948e 100644
--- a/include/erofs/hashmap.h
+++ b/include/erofs/hashmap.h
@@ -97,6 +97,10 @@ static inline void *hashmap_iter_first(struct hashmap *map,
 	return hashmap_iter_next(iter);
 }
 
+static inline void hashmap_disable_shrink(struct hashmap * map)
+{
+	map->shrink_at = 0;
+}
 /* string interning */
 const void *memintern(const void *data, size_t len);
 static inline const char *strintern(const char *string)
diff --git a/include/erofs/inode.h b/include/erofs/inode.h
index bcfd98e..604161c 100644
--- a/include/erofs/inode.h
+++ b/include/erofs/inode.h
@@ -3,7 +3,7 @@
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Li Guifu <bluce.liguifu@huawei.com>
- * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
+ * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_INODE_H
 #define __EROFS_INODE_H
@@ -17,28 +17,35 @@ extern "C"
 
 static inline struct erofs_inode *erofs_igrab(struct erofs_inode *inode)
 {
-	++inode->i_count;
+	(void)erofs_atomic_inc_return(&inode->i_count);
 	return inode;
 }
 
 u32 erofs_new_encode_dev(dev_t dev);
 unsigned char erofs_mode_to_ftype(umode_t mode);
+umode_t erofs_ftype_to_mode(unsigned int ftype, unsigned int perm);
 unsigned char erofs_ftype_to_dtype(unsigned int filetype);
 void erofs_inode_manager_init(void);
-void erofs_insert_ihash(struct erofs_inode *inode, dev_t dev, ino_t ino);
+void erofs_insert_ihash(struct erofs_inode *inode);
 struct erofs_inode *erofs_iget(dev_t dev, ino_t ino);
 struct erofs_inode *erofs_iget_by_nid(erofs_nid_t nid);
 unsigned int erofs_iput(struct erofs_inode *inode);
 erofs_nid_t erofs_lookupnid(struct erofs_inode *inode);
+int erofs_iflush(struct erofs_inode *inode);
 struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
 				   const char *name);
-int erofs_rebuild_dump_tree(struct erofs_inode *dir);
+bool erofs_dentry_is_wht(struct erofs_sb_info *sbi, struct erofs_dentry *d);
+int erofs_rebuild_dump_tree(struct erofs_inode *dir, bool incremental);
 int erofs_init_empty_dir(struct erofs_inode *dir);
 int __erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
 		       const char *path);
-struct erofs_inode *erofs_new_inode(void);
-struct erofs_inode *erofs_mkfs_build_tree_from_path(const char *path);
-struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name);
+struct erofs_inode *erofs_new_inode(struct erofs_sb_info *sbi);
+struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_sb_info *sbi,
+						    const char *path);
+struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
+						     int fd, const char *name);
+int erofs_fixup_root_inode(struct erofs_inode *root);
+struct erofs_inode *erofs_rebuild_make_root(struct erofs_sb_info *sbi);
 
 #ifdef __cplusplus
 }
diff --git a/include/erofs/internal.h b/include/erofs/internal.h
index c1ff582..2edc1b4 100644
--- a/include/erofs/internal.h
+++ b/include/erofs/internal.h
@@ -2,7 +2,7 @@
 /*
  * Copyright (C) 2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_INTERNAL_H
 #define __EROFS_INTERNAL_H
@@ -22,6 +22,11 @@ typedef unsigned short umode_t;
 #include <sys/types.h> /* for off_t definition */
 #include <sys/stat.h> /* for S_ISCHR definition */
 #include <stdio.h>
+#ifdef HAVE_PTHREAD_H
+#include <pthread.h>
+#endif
+#include "atomic.h"
+#include "io.h"
 
 #ifndef PATH_MAX
 #define PATH_MAX        4096    /* # chars in a path name including nul */
@@ -43,15 +48,17 @@ typedef u32 erofs_blk_t;
 #define NULL_ADDR_UL	((unsigned long)-1)
 
 /* global sbi */
-extern struct erofs_sb_info sbi;
+extern struct erofs_sb_info g_sbi;
 
 #define erofs_blksiz(sbi)	(1u << (sbi)->blkszbits)
 #define erofs_blknr(sbi, addr)  ((addr) >> (sbi)->blkszbits)
 #define erofs_blkoff(sbi, addr) ((addr) & (erofs_blksiz(sbi) - 1))
 #define erofs_pos(sbi, nr)      ((erofs_off_t)(nr) << (sbi)->blkszbits)
-#define BLK_ROUND_UP(sbi, addr)	DIV_ROUND_UP(addr, erofs_blksiz(sbi))
+#define BLK_ROUND_UP(sbi, addr)	\
+	(roundup(addr, erofs_blksiz(sbi)) >> (sbi)->blkszbits)
 
 struct erofs_buffer_head;
+struct erofs_bufmgr;
 
 struct erofs_device_info {
 	u8 tag[64];
@@ -59,6 +66,13 @@ struct erofs_device_info {
 	u32 mapped_blkaddr;
 };
 
+/* all filesystem-wide lz4 configurations */
+struct erofs_sb_lz4_info {
+	u16 max_distance;
+	/* maximum possible blocks for pclusters in the filesystem */
+	u16 max_pclusterblks;
+};
+
 struct erofs_xattr_prefix_item {
 	struct erofs_xattr_long_prefix *prefix;
 	u8 infix_len;
@@ -66,7 +80,9 @@ struct erofs_xattr_prefix_item {
 
 #define EROFS_PACKED_NID_UNALLOCATED	-1
 
+struct erofs_mkfs_dfops;
 struct erofs_sb_info {
+	struct erofs_sb_lz4_info lz4;
 	struct erofs_device_info *devs;
 	char *devname;
 
@@ -78,13 +94,14 @@ struct erofs_sb_info {
 
 	u32 feature_compat;
 	u32 feature_incompat;
-	u64 build_time;
-	u32 build_time_nsec;
 
-	u8  extslots;
 	unsigned char islotbits;
 	unsigned char blkszbits;
 
+	u32 sb_size;			/* total superblock size */
+	u32 build_time_nsec;
+	u64 build_time;
+
 	/* what we really care is nid, rather than ino.. */
 	erofs_nid_t root_nid;
 	/* used for statfs, f_files - f_favail */
@@ -93,10 +110,8 @@ struct erofs_sb_info {
 	u8 uuid[16];
 	char volume_name[16];
 
-	u16 available_compr_algs;
-	u16 lz4_max_distance;
-
 	u32 checksum;
+	u16 available_compr_algs;
 	u16 extra_devices;
 	union {
 		u16 devt_slotoff;		/* used for mkfs */
@@ -108,7 +123,8 @@ struct erofs_sb_info {
 	u8 xattr_prefix_count;
 	struct erofs_xattr_prefix_item *xattr_prefixes;
 
-	int devfd, devblksz;
+	struct erofs_vfile bdev;
+	int devblksz;
 	u64 devsz;
 	dev_t dev;
 	unsigned int nblobs;
@@ -117,8 +133,17 @@ struct erofs_sb_info {
 	struct list_head list;
 
 	u64 saved_by_deduplication;
+
+#ifdef EROFS_MT_ENABLED
+	pthread_t dfops_worker;
+	struct erofs_mkfs_dfops *mkfs_dfops;
+#endif
+	struct erofs_bufmgr *bmgr;
+	bool useqpl;
 };
 
+#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))
+
 /* make sure that any user of the erofs headers has atleast 64bit off_t type */
 extern int erofs_assert_largefile[sizeof(off_t)-8];
 
@@ -153,6 +178,11 @@ EROFS_FEATURE_FUNCS(xattr_filter, compat, COMPAT_XATTR_FILTER)
 
 struct erofs_diskbuf;
 
+#define EROFS_INODE_DATA_SOURCE_NONE		0
+#define EROFS_INODE_DATA_SOURCE_LOCALPATH	1
+#define EROFS_INODE_DATA_SOURCE_DISKBUF		2
+#define EROFS_INODE_DATA_SOURCE_RESVSP		3
+
 struct erofs_inode {
 	struct list_head i_hash, i_subdirs, i_xattrs;
 
@@ -163,7 +193,7 @@ struct erofs_inode {
 		/* (mkfs.erofs) next pointer for directory dumping */
 		struct erofs_inode *next_dirwrite;
 	};
-	unsigned int i_count;
+	erofs_atomic_t i_count;
 	struct erofs_sb_info *sbi;
 	struct erofs_inode *i_parent;
 
@@ -199,9 +229,9 @@ struct erofs_inode {
 	unsigned char inode_isize;
 	/* inline tail-end packing size */
 	unsigned short idata_size;
+	char datasource;
 	bool compressed_idata;
 	bool lazy_tailblock;
-	bool with_diskbuf;
 	bool opaque;
 	/* OVL: non-merge dir that may contain whiteout entries */
 	bool whiteouts;
@@ -230,16 +260,20 @@ struct erofs_inode {
 			uint8_t  z_algorithmtype[2];
 			uint8_t  z_logical_clusterbits;
 			uint8_t  z_physical_clusterblks;
-			uint64_t z_tailextent_headlcn;
-			unsigned int    z_idataoff;
+			union {
+				uint64_t z_tailextent_headlcn;
+				erofs_off_t fragment_size;
+			};
+			union {
+				unsigned int z_idataoff;
+				erofs_off_t fragmentoff;
+			};
 #define z_idata_size	idata_size
 		};
 	};
 #ifdef WITH_ANDROID
 	uint64_t capabilities;
 #endif
-	erofs_off_t fragmentoff;
-	unsigned int fragment_size;
 };
 
 static inline erofs_off_t erofs_iloc(struct erofs_inode *inode)
@@ -273,17 +307,22 @@ static inline unsigned int erofs_inode_datalayout(unsigned int value)
 			      EROFS_I_DATALAYOUT_BITS);
 }
 
-#define IS_ROOT(x)	((x) == (x)->i_parent)
+static inline struct erofs_inode *erofs_parent_inode(struct erofs_inode *inode)
+{
+	return (struct erofs_inode *)((unsigned long)inode->i_parent & ~1UL);
+}
+
+#define IS_ROOT(x)	((x) == erofs_parent_inode(x))
 
 struct erofs_dentry {
 	struct list_head d_child;	/* child of parent list */
-
-	unsigned int type;
-	char name[EROFS_NAME_LEN];
 	union {
 		struct erofs_inode *inode;
 		erofs_nid_t nid;
 	};
+	char name[EROFS_NAME_LEN];
+	u8 type;
+	bool validnid;
 };
 
 static inline bool is_dot_dotdot_len(const char *name, unsigned int len)
@@ -369,6 +408,10 @@ struct erofs_map_dev {
 /* super.c */
 int erofs_read_superblock(struct erofs_sb_info *sbi);
 void erofs_put_super(struct erofs_sb_info *sbi);
+int erofs_writesb(struct erofs_sb_info *sbi, struct erofs_buffer_head *sb_bh,
+		  erofs_blk_t *blocks);
+struct erofs_buffer_head *erofs_reserve_sb(struct erofs_bufmgr *bmgr);
+int erofs_enable_sb_chksum(struct erofs_sb_info *sbi, u32 *crc);
 
 /* namei.c */
 int erofs_read_inode_from_disk(struct erofs_inode *vi);
@@ -387,6 +430,7 @@ int z_erofs_read_one_data(struct erofs_inode *inode,
 			erofs_off_t skip, erofs_off_t length, bool trimmed);
 void *erofs_read_metadata(struct erofs_sb_info *sbi, erofs_nid_t nid,
 			  erofs_off_t *offset, int *lengthp);
+int z_erofs_parse_cfgs(struct erofs_sb_info *sbi, struct erofs_super_block *dsb);
 
 static inline int erofs_get_occupied_size(const struct erofs_inode *inode,
 					  erofs_off_t *size)
@@ -418,6 +462,49 @@ int z_erofs_fill_inode(struct erofs_inode *vi);
 int z_erofs_map_blocks_iter(struct erofs_inode *vi,
 			    struct erofs_map_blocks *map, int flags);
 
+/* io.c */
+int erofs_dev_open(struct erofs_sb_info *sbi, const char *dev, int flags);
+void erofs_dev_close(struct erofs_sb_info *sbi);
+void erofs_blob_closeall(struct erofs_sb_info *sbi);
+int erofs_blob_open_ro(struct erofs_sb_info *sbi, const char *dev);
+
+ssize_t erofs_dev_read(struct erofs_sb_info *sbi, int device_id,
+		       void *buf, u64 offset, size_t len);
+
+static inline int erofs_dev_write(struct erofs_sb_info *sbi, const void *buf,
+				  u64 offset, size_t len)
+{
+	if (erofs_io_pwrite(&sbi->bdev, buf, offset, len) != (ssize_t)len)
+		return -EIO;
+	return 0;
+}
+
+static inline int erofs_dev_fillzero(struct erofs_sb_info *sbi, u64 offset,
+				     size_t len, bool pad)
+{
+	return erofs_io_fallocate(&sbi->bdev, offset, len, pad);
+}
+
+static inline int erofs_dev_resize(struct erofs_sb_info *sbi,
+				   erofs_blk_t blocks)
+{
+	return erofs_io_ftruncate(&sbi->bdev, (u64)blocks * erofs_blksiz(sbi));
+}
+
+static inline int erofs_blk_write(struct erofs_sb_info *sbi, const void *buf,
+				  erofs_blk_t blkaddr, u32 nblocks)
+{
+	return erofs_dev_write(sbi, buf, erofs_pos(sbi, blkaddr),
+			       erofs_pos(sbi, nblocks));
+}
+
+static inline int erofs_blk_read(struct erofs_sb_info *sbi, int device_id,
+				 void *buf, erofs_blk_t start, u32 nblocks)
+{
+	return erofs_dev_read(sbi, device_id, buf, erofs_pos(sbi, start),
+			      erofs_pos(sbi, nblocks));
+}
+
 #ifdef EUCLEAN
 #define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */
 #else
diff --git a/include/erofs/io.h b/include/erofs/io.h
index 4db5716..d9b33d2 100644
--- a/include/erofs/io.h
+++ b/include/erofs/io.h
@@ -16,43 +16,52 @@ extern "C"
 #define _GNU_SOURCE
 #endif
 #include <unistd.h>
-#include "internal.h"
+#include "defs.h"
 
 #ifndef O_BINARY
 #define O_BINARY	0
 #endif
 
-void blob_closeall(struct erofs_sb_info *sbi);
-int blob_open_ro(struct erofs_sb_info *sbi, const char *dev);
-int dev_open(struct erofs_sb_info *sbi, const char *devname);
-int dev_open_ro(struct erofs_sb_info *sbi, const char *dev);
-void dev_close(struct erofs_sb_info *sbi);
-int dev_write(struct erofs_sb_info *sbi, const void *buf,
-	      u64 offset, size_t len);
-int dev_read(struct erofs_sb_info *sbi, int device_id,
-	     void *buf, u64 offset, size_t len);
-int dev_fillzero(struct erofs_sb_info *sbi, u64 offset,
-		 size_t len, bool padding);
-int dev_fsync(struct erofs_sb_info *sbi);
-int dev_resize(struct erofs_sb_info *sbi, erofs_blk_t nblocks);
-
-ssize_t erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
-			      int fd_out, erofs_off_t *off_out,
-			      size_t length);
+struct erofs_vfile;
 
-static inline int blk_write(struct erofs_sb_info *sbi, const void *buf,
-			    erofs_blk_t blkaddr, u32 nblocks)
-{
-	return dev_write(sbi, buf, erofs_pos(sbi, blkaddr),
-			 erofs_pos(sbi, nblocks));
-}
+struct erofs_vfops {
+	ssize_t (*pread)(struct erofs_vfile *vf, void *buf, u64 offset, size_t len);
+	ssize_t (*pwrite)(struct erofs_vfile *vf, const void *buf, u64 offset, size_t len);
+	int (*fsync)(struct erofs_vfile *vf);
+	int (*fallocate)(struct erofs_vfile *vf, u64 offset, size_t len, bool pad);
+	int (*ftruncate)(struct erofs_vfile *vf, u64 length);
+	ssize_t (*read)(struct erofs_vfile *vf, void *buf, size_t len);
+	off_t (*lseek)(struct erofs_vfile *vf, u64 offset, int whence);
+	int (*fstat)(struct erofs_vfile *vf, struct stat *buf);
+	int (*xcopy)(struct erofs_vfile *vout, off_t pos,
+		     struct erofs_vfile *vin, unsigned int len, bool noseek);
+};
 
-static inline int blk_read(struct erofs_sb_info *sbi, int device_id, void *buf,
-			   erofs_blk_t start, u32 nblocks)
-{
-	return dev_read(sbi, device_id, buf, erofs_pos(sbi, start),
-			erofs_pos(sbi, nblocks));
-}
+/* don't extend this; instead, use payload for any extra information */
+struct erofs_vfile {
+	struct erofs_vfops *ops;
+	union {
+		struct {
+			u64 offset;
+			int fd;
+		};
+		u8 payload[16];
+	};
+};
+
+int erofs_io_fstat(struct erofs_vfile *vf, struct stat *buf);
+ssize_t erofs_io_pwrite(struct erofs_vfile *vf, const void *buf, u64 pos, size_t len);
+int erofs_io_fsync(struct erofs_vfile *vf);
+ssize_t erofs_io_fallocate(struct erofs_vfile *vf, u64 offset, size_t len, bool pad);
+int erofs_io_ftruncate(struct erofs_vfile *vf, u64 length);
+ssize_t erofs_io_pread(struct erofs_vfile *vf, void *buf, u64 offset, size_t len);
+ssize_t erofs_io_read(struct erofs_vfile *vf, void *buf, size_t len);
+off_t erofs_io_lseek(struct erofs_vfile *vf, u64 offset, int whence);
+
+ssize_t erofs_copy_file_range(int fd_in, u64 *off_in, int fd_out, u64 *off_out,
+			      size_t length);
+int erofs_io_xcopy(struct erofs_vfile *vout, off_t pos,
+		   struct erofs_vfile *vin, unsigned int len, bool noseek);
 
 #ifdef __cplusplus
 }
diff --git a/include/erofs/rebuild.h b/include/erofs/rebuild.h
index e99ce74..59b2f6f 100644
--- a/include/erofs/rebuild.h
+++ b/include/erofs/rebuild.h
@@ -9,10 +9,17 @@ extern "C"
 
 #include "internal.h"
 
+enum erofs_rebuild_datamode {
+	EROFS_REBUILD_DATA_BLOB_INDEX,
+	EROFS_REBUILD_DATA_RESVSP,
+	EROFS_REBUILD_DATA_FULL,
+};
+
 struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
 		char *path, bool aufs, bool *whout, bool *opq, bool to_head);
 
-int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi);
+int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi,
+			    enum erofs_rebuild_datamode mode);
 
 #ifdef __cplusplus
 }
diff --git a/include/erofs/tar.h b/include/erofs/tar.h
index a76f740..6fa72eb 100644
--- a/include/erofs/tar.h
+++ b/include/erofs/tar.h
@@ -26,27 +26,42 @@ struct erofs_pax_header {
 
 #define EROFS_IOS_DECODER_NONE		0
 #define EROFS_IOS_DECODER_GZIP		1
+#define EROFS_IOS_DECODER_LIBLZMA	2
+
+#ifdef HAVE_LIBLZMA
+#include <lzma.h>
+struct erofs_iostream_liblzma {
+	u8 inbuf[32768];
+	lzma_stream strm;
+	int fd;
+};
+#endif
 
 struct erofs_iostream {
 	union {
-		int fd;			/* original fd */
+		struct erofs_vfile vf;
 		void *handler;
+#ifdef HAVE_LIBLZMA
+		struct erofs_iostream_liblzma *lzma;
+#endif
 	};
 	u64 sz;
 	char *buffer;
 	unsigned int head, tail, bufsize;
-	int decoder;
+	int decoder, dumpfd;
 	bool feof;
 };
 
 struct erofs_tarfile {
 	struct erofs_pax_header global;
 	struct erofs_iostream ios;
-	char *mapfile;
+	char *mapfile, *dumpfile;
 
+	u32 dev;
 	int fd;
 	u64 offset;
-	bool index_mode, aufs;
+	bool index_mode, headeronly_mode, rvsp_mode, aufs;
+	bool ddtaridx_mode;
 };
 
 void erofs_iostream_close(struct erofs_iostream *ios);
diff --git a/include/erofs/workqueue.h b/include/erofs/workqueue.h
new file mode 100644
index 0000000..36037c3
--- /dev/null
+++ b/include/erofs/workqueue.h
@@ -0,0 +1,34 @@
+/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
+#ifndef __EROFS_WORKQUEUE_H
+#define __EROFS_WORKQUEUE_H
+
+#include "internal.h"
+
+struct erofs_workqueue;
+
+typedef void *(*erofs_wq_func_t)(struct erofs_workqueue *, void *);
+
+struct erofs_work {
+	struct erofs_work *next;
+	void (*fn)(struct erofs_work *work, void *tlsp);
+};
+
+struct erofs_workqueue {
+	struct erofs_work *head, *tail;
+	pthread_mutex_t lock;
+	pthread_cond_t cond_empty;
+	pthread_cond_t cond_full;
+	pthread_t *workers;
+	unsigned int nworker;
+	unsigned int max_jobs;
+	unsigned int job_count;
+	bool shutdown;
+	erofs_wq_func_t on_start, on_exit;
+};
+
+int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
+			  unsigned int max_jobs, erofs_wq_func_t on_start,
+			  erofs_wq_func_t on_exit);
+int erofs_queue_work(struct erofs_workqueue *wq, struct erofs_work *work);
+int erofs_destroy_workqueue(struct erofs_workqueue *wq);
+#endif
diff --git a/include/erofs/xattr.h b/include/erofs/xattr.h
index 0f76037..7643611 100644
--- a/include/erofs/xattr.h
+++ b/include/erofs/xattr.h
@@ -44,7 +44,7 @@ static inline unsigned int xattrblock_offset(struct erofs_inode *vi,
 	sizeof(struct erofs_xattr_entry) + 1; })
 
 int erofs_scan_file_xattrs(struct erofs_inode *inode);
-int erofs_prepare_xattr_ibody(struct erofs_inode *inode);
+int erofs_prepare_xattr_ibody(struct erofs_inode *inode, bool noroom);
 char *erofs_export_xattr_ibody(struct erofs_inode *inode);
 int erofs_build_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *path);
 
diff --git a/include/erofs/xxhash.h b/include/erofs/xxhash.h
deleted file mode 100644
index 5441209..0000000
--- a/include/erofs/xxhash.h
+++ /dev/null
@@ -1,27 +0,0 @@
-/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */
-#ifndef __EROFS_XXHASH_H
-#define __EROFS_XXHASH_H
-
-#ifdef __cplusplus
-extern "C"
-{
-#endif
-
-#include <stdint.h>
-
-/**
- * xxh32() - calculate the 32-bit hash of the input with a given seed.
- *
- * @input:  The data to hash.
- * @length: The length of the data to hash.
- * @seed:   The seed can be used to alter the result predictably.
- *
- * Return:  The 32-bit hash of the data.
- */
-uint32_t xxh32(const void *input, size_t length, uint32_t seed);
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif
diff --git a/include/erofs_fs.h b/include/erofs_fs.h
index eba6c26..fc21915 100644
--- a/include/erofs_fs.h
+++ b/include/erofs_fs.h
@@ -304,6 +304,7 @@ enum {
 	Z_EROFS_COMPRESSION_LZ4		= 0,
 	Z_EROFS_COMPRESSION_LZMA	= 1,
 	Z_EROFS_COMPRESSION_DEFLATE	= 2,
+	Z_EROFS_COMPRESSION_ZSTD	= 3,
 	Z_EROFS_COMPRESSION_MAX
 };
 #define Z_EROFS_ALL_COMPR_ALGS		((1 << Z_EROFS_COMPRESSION_MAX) - 1)
@@ -330,6 +331,15 @@ struct z_erofs_deflate_cfgs {
 	u8 reserved[5];
 } __packed;
 
+/* 6 bytes (+ length field = 8 bytes) */
+struct z_erofs_zstd_cfgs {
+	u8 format;
+	u8 windowlog;		/* windowLog - ZSTD_WINDOWLOG_ABSOLUTEMIN(10) */
+	u8 reserved[4];
+} __packed;
+
+#define Z_EROFS_ZSTD_MAX_DICT_SIZE	Z_EROFS_PCLUSTER_MAX_SIZE
+
 /*
  * bit 0 : COMPACTED_2B indexes (0 - off; 1 - on)
  *  e.g. for 4k logical cluster size,      4B        if compacted 2B is off;
@@ -440,12 +450,14 @@ struct z_erofs_lcluster_index {
 /* check the EROFS on-disk layout strictly at compile time */
 static inline void erofs_check_ondisk_layout_definitions(void)
 {
+#ifndef __cplusplus
 	const union {
 		struct z_erofs_map_header h;
 		__le64 v;
 	} fmh __maybe_unused = {
 		.h.h_clusterbits = 1 << Z_EROFS_FRAGMENT_INODE_BIT,
 	};
+#endif
 
 	BUILD_BUG_ON(sizeof(struct erofs_super_block) != 128);
 	BUILD_BUG_ON(sizeof(struct erofs_inode_compact) != 32);
@@ -464,9 +476,11 @@ static inline void erofs_check_ondisk_layout_definitions(void)
 
 	BUILD_BUG_ON(BIT(Z_EROFS_LI_LCLUSTER_TYPE_BITS) <
 		     Z_EROFS_LCLUSTER_TYPE_MAX - 1);
+#ifndef __cplusplus
 	/* exclude old compiler versions like gcc 7.5.0 */
 	BUILD_BUG_ON(__builtin_constant_p(fmh.v) ?
 		     fmh.v != cpu_to_le64(1ULL << 63) : 0);
+#endif
 }
 
 #endif
diff --git a/lib/Makefile.am b/lib/Makefile.am
index 483d410..2cb4cab 100644
--- a/lib/Makefile.am
+++ b/lib/Makefile.am
@@ -25,15 +25,15 @@ noinst_HEADERS = $(top_srcdir)/include/erofs_fs.h \
       $(top_srcdir)/include/erofs/xattr.h \
       $(top_srcdir)/include/erofs/compress_hints.h \
       $(top_srcdir)/include/erofs/fragments.h \
-      $(top_srcdir)/include/erofs/xxhash.h \
       $(top_srcdir)/include/erofs/rebuild.h \
-      $(top_srcdir)/lib/liberofs_private.h
+      $(top_srcdir)/lib/liberofs_private.h \
+      $(top_srcdir)/lib/xxhash.h
 
 noinst_HEADERS += compressor.h
 liberofs_la_SOURCES = config.c io.c cache.c super.c inode.c xattr.c exclude.c \
 		      namei.c data.c compress.c compressor.c zmap.c decompress.c \
 		      compress_hints.c hashmap.c sha256.c blobchunk.c dir.c \
-		      fragments.c rb_tree.c dedupe.c uuid_unparse.c uuid.c tar.c \
+		      fragments.c dedupe.c uuid_unparse.c uuid.c tar.c \
 		      block_list.c xxhash.c rebuild.c diskbuf.c
 
 liberofs_la_CFLAGS = -Wall ${libuuid_CFLAGS} -I$(top_srcdir)/include
@@ -53,3 +53,10 @@ liberofs_la_SOURCES += kite_deflate.c compressor_deflate.c
 if ENABLE_LIBDEFLATE
 liberofs_la_SOURCES += compressor_libdeflate.c
 endif
+if ENABLE_LIBZSTD
+liberofs_la_SOURCES += compressor_libzstd.c
+endif
+if ENABLE_EROFS_MT
+liberofs_la_LDFLAGS = -lpthread
+liberofs_la_SOURCES += workqueue.c
+endif
diff --git a/lib/blobchunk.c b/lib/blobchunk.c
index b74bb36..2835755 100644
--- a/lib/blobchunk.c
+++ b/lib/blobchunk.c
@@ -9,7 +9,6 @@
 #include "erofs/blobchunk.h"
 #include "erofs/block_list.h"
 #include "erofs/cache.h"
-#include "erofs/io.h"
 #include "sha256.h"
 #include <unistd.h>
 
@@ -195,7 +194,8 @@ int erofs_blob_write_chunk_indexes(struct erofs_inode *inode,
 					0 : extent_end - extent_start,
 					   first_extent, true);
 
-	return dev_write(inode->sbi, inode->chunkindexes, off, inode->extent_isize);
+	return erofs_dev_write(inode->sbi, inode->chunkindexes, off,
+			       inode->extent_isize);
 }
 
 int erofs_blob_mergechunks(struct erofs_inode *inode, unsigned int chunkbits,
@@ -374,6 +374,47 @@ err:
 	return ret;
 }
 
+int erofs_write_zero_inode(struct erofs_inode *inode)
+{
+	struct erofs_sb_info *sbi = inode->sbi;
+	unsigned int chunkbits = ilog2(inode->i_size - 1) + 1;
+	unsigned int count;
+	erofs_off_t chunksize, len, pos;
+	struct erofs_inode_chunk_index *idx;
+
+	if (chunkbits < sbi->blkszbits)
+		chunkbits = sbi->blkszbits;
+	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
+		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;
+
+	inode->u.chunkformat |= chunkbits - sbi->blkszbits;
+
+	chunksize = 1ULL << chunkbits;
+	count = DIV_ROUND_UP(inode->i_size, chunksize);
+
+	inode->extent_isize = count * EROFS_BLOCK_MAP_ENTRY_SIZE;
+	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
+	if (!idx)
+		return -ENOMEM;
+	inode->chunkindexes = idx;
+
+	for (pos = 0; pos < inode->i_size; pos += len) {
+		struct erofs_blobchunk *chunk;
+
+		len = min_t(erofs_off_t, inode->i_size - pos, chunksize);
+		chunk = erofs_get_unhashed_chunk(0, EROFS_NULL_ADDR, -1);
+		if (IS_ERR(chunk)) {
+			free(inode->chunkindexes);
+			inode->chunkindexes = NULL;
+			return PTR_ERR(chunk);
+		}
+
+		*(void **)idx++ = chunk;
+	}
+	inode->datalayout = EROFS_INODE_CHUNK_BASED;
+	return 0;
+}
+
 int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset)
 {
 	struct erofs_sb_info *sbi = inode->sbi;
@@ -436,7 +477,7 @@ int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 {
 	struct erofs_buffer_head *bh;
 	ssize_t length;
-	erofs_off_t pos_in, pos_out;
+	u64 pos_in, pos_out;
 	ssize_t ret;
 
 	if (blobfile) {
@@ -455,7 +496,7 @@ int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 		unsigned int i, ret;
 		erofs_blk_t nblocks;
 
-		nblocks = erofs_mapbh(NULL);
+		nblocks = erofs_mapbh(sbi->bmgr, NULL);
 		pos_out = erofs_btell(bh_devt, false);
 		i = 0;
 		do {
@@ -465,7 +506,7 @@ int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 			};
 
 			memcpy(dis.tag, sbi->devs[i].tag, sizeof(dis.tag));
-			ret = dev_write(sbi, &dis, pos_out, sizeof(dis));
+			ret = erofs_dev_write(sbi, &dis, pos_out, sizeof(dis));
 			if (ret)
 				return ret;
 			pos_out += sizeof(dis);
@@ -476,21 +517,22 @@ int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
 		return 0;
 	}
 
-	bh = erofs_balloc(DATA, blobfile ? datablob_size : 0, 0, 0);
+	bh = erofs_balloc(sbi->bmgr, DATA, datablob_size, 0, 0);
 	if (IS_ERR(bh))
 		return PTR_ERR(bh);
 
-	erofs_mapbh(bh->block);
+	erofs_mapbh(NULL, bh->block);
 
 	pos_out = erofs_btell(bh, false);
 	remapped_base = erofs_blknr(sbi, pos_out);
+	pos_out += sbi->bdev.offset;
 	if (blobfile) {
 		pos_in = 0;
 		ret = erofs_copy_file_range(fileno(blobfile), &pos_in,
-				sbi->devfd, &pos_out, datablob_size);
+				sbi->bdev.fd, &pos_out, datablob_size);
 		ret = ret < datablob_size ? -EIO : 0;
 	} else {
-		ret = 0;
+		ret = erofs_io_ftruncate(&sbi->bdev, pos_out + datablob_size);
 	}
 	bh->op = &erofs_drop_directly_bhops;
 	erofs_bdrop(bh, false);
@@ -506,11 +548,17 @@ void erofs_blob_exit(void)
 	if (blobfile)
 		fclose(blobfile);
 
-	while ((e = hashmap_iter_first(&blob_hashmap, &iter))) {
+	/* Disable hashmap shrink, effectively disabling rehash.
+	 * This way we can iterate over entire hashmap efficiently
+	 * and safely by using hashmap_iter_next() */
+	hashmap_disable_shrink(&blob_hashmap);
+	e = hashmap_iter_first(&blob_hashmap, &iter);
+	while (e) {
 		bc = container_of((struct hashmap_entry *)e,
 				  struct erofs_blobchunk, ent);
 		DBG_BUGON(hashmap_remove(&blob_hashmap, e) != e);
 		free(bc);
+		e = hashmap_iter_next(&iter);
 	}
 	DBG_BUGON(hashmap_free(&blob_hashmap));
 
@@ -578,13 +626,13 @@ int erofs_mkfs_init_devices(struct erofs_sb_info *sbi, unsigned int devices)
 	if (!sbi->devs)
 		return -ENOMEM;
 
-	bh_devt = erofs_balloc(DEVT,
+	bh_devt = erofs_balloc(sbi->bmgr, DEVT,
 		sizeof(struct erofs_deviceslot) * devices, 0, 0);
 	if (IS_ERR(bh_devt)) {
 		free(sbi->devs);
 		return PTR_ERR(bh_devt);
 	}
-	erofs_mapbh(bh_devt->block);
+	erofs_mapbh(NULL, bh_devt->block);
 	bh_devt->op = &erofs_skip_write_bhops;
 	sbi->devt_slotoff = erofs_btell(bh_devt, false) / EROFS_DEVT_SLOT_SIZE;
 	sbi->extra_devices = devices;
diff --git a/lib/block_list.c b/lib/block_list.c
index f47a746..261e9ff 100644
--- a/lib/block_list.c
+++ b/lib/block_list.c
@@ -13,23 +13,21 @@
 static FILE *block_list_fp;
 bool srcmap_enabled;
 
-int erofs_blocklist_open(char *filename, bool srcmap)
+int erofs_blocklist_open(FILE *fp, bool srcmap)
 {
-	block_list_fp = fopen(filename, "w");
-
-	if (!block_list_fp)
-		return -errno;
+	if (!fp)
+		return -ENOENT;
+	block_list_fp = fp;
 	srcmap_enabled = srcmap;
 	return 0;
 }
 
-void erofs_blocklist_close(void)
+FILE *erofs_blocklist_close(void)
 {
-	if (!block_list_fp)
-		return;
+	FILE *fp = block_list_fp;
 
-	fclose(block_list_fp);
 	block_list_fp = NULL;
+	return fp;
 }
 
 /* XXX: really need to be cleaned up */
diff --git a/lib/cache.c b/lib/cache.c
index caca49b..3208e9f 100644
--- a/lib/cache.c
+++ b/lib/cache.c
@@ -3,25 +3,13 @@
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Miao Xie <miaoxie@huawei.com>
- * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
+ * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #include <stdlib.h>
 #include <erofs/cache.h>
-#include "erofs/io.h"
 #include "erofs/print.h"
 
-static struct erofs_buffer_block blkh = {
-	.list = LIST_HEAD_INIT(blkh.list),
-	.blkaddr = NULL_ADDR,
-};
-static erofs_blk_t tail_blkaddr, erofs_metablkcnt;
-
-/* buckets for all mapped buffer blocks to boost up allocation */
-static struct list_head mapped_buckets[META + 1][EROFS_MAX_BLOCK_SIZE];
-/* last mapped buffer block to accelerate erofs_mapbh() */
-static struct erofs_buffer_block *last_mapped_block = &blkh;
-
-static bool erofs_bh_flush_drop_directly(struct erofs_buffer_head *bh)
+static int erofs_bh_flush_drop_directly(struct erofs_buffer_head *bh)
 {
 	return erofs_bh_flush_generic_end(bh);
 }
@@ -30,41 +18,48 @@ const struct erofs_bhops erofs_drop_directly_bhops = {
 	.flush = erofs_bh_flush_drop_directly,
 };
 
-static bool erofs_bh_flush_skip_write(struct erofs_buffer_head *bh)
+static int erofs_bh_flush_skip_write(struct erofs_buffer_head *bh)
 {
-	return false;
+	return -EBUSY;
 }
 
 const struct erofs_bhops erofs_skip_write_bhops = {
 	.flush = erofs_bh_flush_skip_write,
 };
 
-/* return buffer_head of erofs super block (with size 0) */
-struct erofs_buffer_head *erofs_buffer_init(void)
+struct erofs_bufmgr *erofs_buffer_init(struct erofs_sb_info *sbi,
+				       erofs_blk_t startblk)
 {
+	struct erofs_bufmgr *bufmgr;
 	int i, j;
-	struct erofs_buffer_head *bh = erofs_balloc(META, 0, 0, 0);
 
-	if (IS_ERR(bh))
-		return bh;
+	bufmgr = malloc(sizeof(struct erofs_bufmgr));
+	if (!bufmgr)
+		return NULL;
 
-	bh->op = &erofs_skip_write_bhops;
+	init_list_head(&bufmgr->blkh.list);
+	bufmgr->blkh.blkaddr = NULL_ADDR;
+	bufmgr->last_mapped_block = &bufmgr->blkh;
 
-	for (i = 0; i < ARRAY_SIZE(mapped_buckets); i++)
-		for (j = 0; j < ARRAY_SIZE(mapped_buckets[0]); j++)
-			init_list_head(&mapped_buckets[i][j]);
-	return bh;
+	for (i = 0; i < ARRAY_SIZE(bufmgr->mapped_buckets); i++)
+		for (j = 0; j < ARRAY_SIZE(bufmgr->mapped_buckets[0]); j++)
+			init_list_head(&bufmgr->mapped_buckets[i][j]);
+	bufmgr->tail_blkaddr = startblk;
+	bufmgr->sbi = sbi;
+	return bufmgr;
 }
 
 static void erofs_bupdate_mapped(struct erofs_buffer_block *bb)
 {
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
+	struct erofs_sb_info *sbi = bmgr->sbi;
 	struct list_head *bkt;
 
 	if (bb->blkaddr == NULL_ADDR)
 		return;
 
-	bkt = mapped_buckets[bb->type] +
-		(bb->buffers.off & (erofs_blksiz(&sbi) - 1));
+	bkt = bmgr->mapped_buckets[bb->type] +
+		(bb->buffers.off & (erofs_blksiz(sbi) - 1));
 	list_del(&bb->mapped_list);
 	list_add_tail(&bb->mapped_list, bkt);
 }
@@ -77,11 +72,14 @@ static int __erofs_battach(struct erofs_buffer_block *bb,
 			   unsigned int extrasize,
 			   bool dryrun)
 {
-	const unsigned int blksiz = erofs_blksiz(&sbi);
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
+	struct erofs_sb_info *sbi = bmgr->sbi;
+	const unsigned int blksiz = erofs_blksiz(sbi);
 	const unsigned int blkmask = blksiz - 1;
-	const erofs_off_t alignedoffset = roundup(bb->buffers.off, alignsize);
-	const int oob = cmpsgn(roundup(((bb->buffers.off - 1) & blkmask) + 1,
-				       alignsize) + incr + extrasize, blksiz);
+	erofs_off_t boff = bb->buffers.off;
+	const erofs_off_t alignedoffset = roundup(boff, alignsize);
+	const int oob = cmpsgn(roundup(((boff - 1) & blkmask) + 1, alignsize) +
+					incr + extrasize, blksiz);
 	bool tailupdate = false;
 	erofs_blk_t blkaddr;
 
@@ -92,8 +90,8 @@ static int __erofs_battach(struct erofs_buffer_block *bb,
 
 		blkaddr = bb->blkaddr;
 		if (blkaddr != NULL_ADDR) {
-			tailupdate = (tail_blkaddr == blkaddr +
-				      DIV_ROUND_UP(bb->buffers.off, blksiz));
+			tailupdate = (bmgr->tail_blkaddr == blkaddr +
+				      BLK_ROUND_UP(sbi, boff));
 			if (oob && !tailupdate)
 				return -EINVAL;
 		}
@@ -105,11 +103,12 @@ static int __erofs_battach(struct erofs_buffer_block *bb,
 			bh->block = bb;
 			list_add_tail(&bh->list, &bb->buffers.list);
 		}
-		bb->buffers.off = alignedoffset + incr;
+		boff = alignedoffset + incr;
+		bb->buffers.off = boff;
 		/* need to update the tail_blkaddr */
 		if (tailupdate)
-			tail_blkaddr = blkaddr +
-					DIV_ROUND_UP(bb->buffers.off, blksiz);
+			bmgr->tail_blkaddr = blkaddr +
+						BLK_ROUND_UP(sbi, boff);
 		erofs_bupdate_mapped(bb);
 	}
 	return ((alignedoffset + incr - 1) & blkmask) + 1;
@@ -126,13 +125,14 @@ int erofs_bh_balloon(struct erofs_buffer_head *bh, erofs_off_t incr)
 	return __erofs_battach(bb, NULL, incr, 1, 0, false);
 }
 
-static int erofs_bfind_for_attach(int type, erofs_off_t size,
+static int erofs_bfind_for_attach(struct erofs_bufmgr *bmgr,
+				  int type, erofs_off_t size,
 				  unsigned int required_ext,
 				  unsigned int inline_ext,
 				  unsigned int alignsize,
 				  struct erofs_buffer_block **bbp)
 {
-	const unsigned int blksiz = erofs_blksiz(&sbi);
+	const unsigned int blksiz = erofs_blksiz(bmgr->sbi);
 	struct erofs_buffer_block *cur, *bb;
 	unsigned int used0, used_before, usedmax, used;
 	int ret;
@@ -157,7 +157,7 @@ static int erofs_bfind_for_attach(int type, erofs_off_t size,
 	used_before = rounddown(blksiz -
 				(size + required_ext + inline_ext), alignsize);
 	for (; used_before; --used_before) {
-		struct list_head *bt = mapped_buckets[type] + used_before;
+		struct list_head *bt = bmgr->mapped_buckets[type] + used_before;
 
 		if (list_empty(bt))
 			continue;
@@ -166,7 +166,7 @@ static int erofs_bfind_for_attach(int type, erofs_off_t size,
 
 		/* last mapped block can be expended, don't handle it here */
 		if (list_next_entry(cur, list)->blkaddr == NULL_ADDR) {
-			DBG_BUGON(cur != last_mapped_block);
+			DBG_BUGON(cur != bmgr->last_mapped_block);
 			continue;
 		}
 
@@ -192,10 +192,10 @@ static int erofs_bfind_for_attach(int type, erofs_off_t size,
 
 skip_mapped:
 	/* try to start from the last mapped one, which can be expended */
-	cur = last_mapped_block;
-	if (cur == &blkh)
+	cur = bmgr->last_mapped_block;
+	if (cur == &bmgr->blkh)
 		cur = list_next_entry(cur, list);
-	for (; cur != &blkh; cur = list_next_entry(cur, list)) {
+	for (; cur != &bmgr->blkh; cur = list_next_entry(cur, list)) {
 		used_before = cur->buffers.off & (blksiz - 1);
 
 		/* skip if buffer block is just full */
@@ -233,16 +233,17 @@ skip_mapped:
 	return 0;
 }
 
-struct erofs_buffer_head *erofs_balloc(int type, erofs_off_t size,
+struct erofs_buffer_head *erofs_balloc(struct erofs_bufmgr *bmgr,
+				       int type, erofs_off_t size,
 				       unsigned int required_ext,
 				       unsigned int inline_ext)
 {
 	struct erofs_buffer_block *bb;
 	struct erofs_buffer_head *bh;
 	unsigned int alignsize;
+	int ret;
 
-	int ret = get_alignsize(type, &type);
-
+	ret = get_alignsize(bmgr->sbi, type, &type);
 	if (ret < 0)
 		return ERR_PTR(ret);
 
@@ -250,7 +251,7 @@ struct erofs_buffer_head *erofs_balloc(int type, erofs_off_t size,
 	alignsize = ret;
 
 	/* try to find if we could reuse an allocated buffer block */
-	ret = erofs_bfind_for_attach(type, size, required_ext, inline_ext,
+	ret = erofs_bfind_for_attach(bmgr, type, size, required_ext, inline_ext,
 				     alignsize, &bb);
 	if (ret)
 		return ERR_PTR(ret);
@@ -268,11 +269,13 @@ struct erofs_buffer_head *erofs_balloc(int type, erofs_off_t size,
 		bb->type = type;
 		bb->blkaddr = NULL_ADDR;
 		bb->buffers.off = 0;
+		bb->buffers.fsprivate = bmgr;
 		init_list_head(&bb->buffers.list);
 		if (type == DATA)
-			list_add(&bb->list, &last_mapped_block->list);
+			list_add(&bb->list,
+				 &bmgr->last_mapped_block->list);
 		else
-			list_add_tail(&bb->list, &blkh.list);
+			list_add_tail(&bb->list, &bmgr->blkh.list);
 		init_list_head(&bb->mapped_list);
 
 		bh = malloc(sizeof(struct erofs_buffer_head));
@@ -295,9 +298,10 @@ struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
 					int type, unsigned int size)
 {
 	struct erofs_buffer_block *const bb = bh->block;
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
 	struct erofs_buffer_head *nbh;
 	unsigned int alignsize;
-	int ret = get_alignsize(type, &type);
+	int ret = get_alignsize(bmgr->sbi, type, &type);
 
 	if (ret < 0)
 		return ERR_PTR(ret);
@@ -321,75 +325,86 @@ struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
 
 static erofs_blk_t __erofs_mapbh(struct erofs_buffer_block *bb)
 {
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
 	erofs_blk_t blkaddr;
 
 	if (bb->blkaddr == NULL_ADDR) {
-		bb->blkaddr = tail_blkaddr;
-		last_mapped_block = bb;
+		bb->blkaddr = bmgr->tail_blkaddr;
+		bmgr->last_mapped_block = bb;
 		erofs_bupdate_mapped(bb);
 	}
 
-	blkaddr = bb->blkaddr + BLK_ROUND_UP(&sbi, bb->buffers.off);
-	if (blkaddr > tail_blkaddr)
-		tail_blkaddr = blkaddr;
-
+	blkaddr = bb->blkaddr + BLK_ROUND_UP(bmgr->sbi, bb->buffers.off);
+	if (blkaddr > bmgr->tail_blkaddr)
+		bmgr->tail_blkaddr = blkaddr;
 	return blkaddr;
 }
 
-erofs_blk_t erofs_mapbh(struct erofs_buffer_block *bb)
+erofs_blk_t erofs_mapbh(struct erofs_bufmgr *bmgr,
+			struct erofs_buffer_block *bb)
 {
-	struct erofs_buffer_block *t = last_mapped_block;
+	struct erofs_buffer_block *t;
+
+	if (!bmgr)
+		bmgr = bb->buffers.fsprivate;
+	t = bmgr->last_mapped_block;
 
 	if (bb && bb->blkaddr != NULL_ADDR)
 		return bb->blkaddr;
 	do {
 		t = list_next_entry(t, list);
-		if (t == &blkh)
+		if (t == &bmgr->blkh)
 			break;
 
 		DBG_BUGON(t->blkaddr != NULL_ADDR);
 		(void)__erofs_mapbh(t);
 	} while (t != bb);
-	return tail_blkaddr;
+	return bmgr->tail_blkaddr;
 }
 
 static void erofs_bfree(struct erofs_buffer_block *bb)
 {
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
+
 	DBG_BUGON(!list_empty(&bb->buffers.list));
 
-	if (bb == last_mapped_block)
-		last_mapped_block = list_prev_entry(bb, list);
+	if (bb == bmgr->last_mapped_block)
+		bmgr->last_mapped_block = list_prev_entry(bb, list);
 
 	list_del(&bb->mapped_list);
 	list_del(&bb->list);
 	free(bb);
 }
 
-bool erofs_bflush(struct erofs_buffer_block *bb)
+int erofs_bflush(struct erofs_bufmgr *bmgr,
+		 struct erofs_buffer_block *bb)
 {
-	const unsigned int blksiz = erofs_blksiz(&sbi);
+	struct erofs_sb_info *sbi = bmgr->sbi;
+	const unsigned int blksiz = erofs_blksiz(sbi);
 	struct erofs_buffer_block *p, *n;
 	erofs_blk_t blkaddr;
 
-	list_for_each_entry_safe(p, n, &blkh.list, list) {
+	list_for_each_entry_safe(p, n, &bmgr->blkh.list, list) {
 		struct erofs_buffer_head *bh, *nbh;
 		unsigned int padding;
 		bool skip = false;
+		int ret;
 
 		if (p == bb)
 			break;
 
-		/* check if the buffer block can flush */
-		list_for_each_entry(bh, &p->buffers.list, list)
-			if (bh->op->preflush && !bh->op->preflush(bh))
-				return false;
-
 		blkaddr = __erofs_mapbh(p);
 
 		list_for_each_entry_safe(bh, nbh, &p->buffers.list, list) {
-			/* flush and remove bh */
-			if (!bh->op->flush(bh))
+			if (bh->op == &erofs_skip_write_bhops) {
 				skip = true;
+				continue;
+			}
+
+			/* flush and remove bh */
+			ret = bh->op->flush(bh);
+			if (ret < 0)
+				return ret;
 		}
 
 		if (skip)
@@ -397,26 +412,29 @@ bool erofs_bflush(struct erofs_buffer_block *bb)
 
 		padding = blksiz - (p->buffers.off & (blksiz - 1));
 		if (padding != blksiz)
-			dev_fillzero(&sbi, erofs_pos(&sbi, blkaddr) - padding,
-				     padding, true);
+			erofs_dev_fillzero(sbi, erofs_pos(sbi, blkaddr) - padding,
+					   padding, true);
 
 		if (p->type != DATA)
-			erofs_metablkcnt += BLK_ROUND_UP(&sbi, p->buffers.off);
+			bmgr->metablkcnt +=
+				BLK_ROUND_UP(sbi, p->buffers.off);
 		erofs_dbg("block %u to %u flushed", p->blkaddr, blkaddr - 1);
 		erofs_bfree(p);
 	}
-	return true;
+	return 0;
 }
 
 void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke)
 {
 	struct erofs_buffer_block *const bb = bh->block;
+	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
+	struct erofs_sb_info *sbi = bmgr->sbi;
 	const erofs_blk_t blkaddr = bh->block->blkaddr;
 	bool rollback = false;
 
 	/* tail_blkaddr could be rolled back after revoking all bhs */
 	if (tryrevoke && blkaddr != NULL_ADDR &&
-	    tail_blkaddr == blkaddr + BLK_ROUND_UP(&sbi, bb->buffers.off))
+	    bmgr->tail_blkaddr == blkaddr + BLK_ROUND_UP(sbi, bb->buffers.off))
 		rollback = true;
 
 	bh->op = &erofs_drop_directly_bhops;
@@ -426,13 +444,18 @@ void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke)
 		return;
 
 	if (!rollback && bb->type != DATA)
-		erofs_metablkcnt += BLK_ROUND_UP(&sbi, bb->buffers.off);
+		bmgr->metablkcnt += BLK_ROUND_UP(sbi, bb->buffers.off);
 	erofs_bfree(bb);
 	if (rollback)
-		tail_blkaddr = blkaddr;
+		bmgr->tail_blkaddr = blkaddr;
+}
+
+erofs_blk_t erofs_total_metablocks(struct erofs_bufmgr *bmgr)
+{
+	return bmgr->metablkcnt;
 }
 
-erofs_blk_t erofs_total_metablocks(void)
+void erofs_buffer_exit(struct erofs_bufmgr *bmgr)
 {
-	return erofs_metablkcnt;
+	free(bmgr);
 }
diff --git a/lib/compress.c b/lib/compress.c
index f6dc12a..8655e78 100644
--- a/lib/compress.c
+++ b/lib/compress.c
@@ -3,7 +3,7 @@
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Miao Xie <miaoxie@huawei.com>
- * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
+ * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #ifndef _LARGEFILE64_SOURCE
 #define _LARGEFILE64_SOURCE
@@ -12,7 +12,6 @@
 #include <stdlib.h>
 #include <unistd.h>
 #include "erofs/print.h"
-#include "erofs/io.h"
 #include "erofs/cache.h"
 #include "erofs/compress.h"
 #include "erofs/dedupe.h"
@@ -20,6 +19,9 @@
 #include "erofs/block_list.h"
 #include "erofs/compress_hints.h"
 #include "erofs/fragments.h"
+#ifdef EROFS_MT_ENABLED
+#include "erofs/workqueue.h"
+#endif
 
 /* compressing configuration specified by users */
 struct erofs_compress_cfg {
@@ -28,28 +30,93 @@ struct erofs_compress_cfg {
 	bool enable;
 } erofs_ccfg[EROFS_MAX_COMPR_CFGS];
 
-struct z_erofs_vle_compress_ctx {
-	u8 queue[EROFS_CONFIG_COMPR_MAX_SZ * 2];
-	struct z_erofs_inmem_extent e;	/* (lookahead) extent */
+struct z_erofs_extent_item {
+	struct list_head list;
+	struct z_erofs_inmem_extent e;
+};
 
+struct z_erofs_compress_ictx {		/* inode context */
 	struct erofs_inode *inode;
 	struct erofs_compress_cfg *ccfg;
+	int fd;
+	u64 fpos;
+
+	u32 tof_chksum;
+	bool fix_dedupedfrag;
+	bool fragemitted;
 
+	/* fields for write indexes */
 	u8 *metacur;
-	unsigned int head, tail;
+	struct list_head extents;
+	u16 clusterofs;
+
+	int seg_num;
+
+#if EROFS_MT_ENABLED
+	pthread_mutex_t mutex;
+	pthread_cond_t cond;
+	int nfini;
+
+	struct erofs_compress_work *mtworks;
+#endif
+};
+
+struct z_erofs_compress_sctx {		/* segment context */
+	struct z_erofs_compress_ictx *ictx;
+
+	u8 *queue;
+	struct list_head extents;
+	struct z_erofs_extent_item *pivot;
+
+	struct erofs_compress *chandle;
+	char *destbuf;
+
 	erofs_off_t remaining;
+	unsigned int head, tail;
+
 	unsigned int pclustersize;
 	erofs_blk_t blkaddr;		/* pointing to the next blkaddr */
 	u16 clusterofs;
 
-	u32 tof_chksum;
-	bool fix_dedupedfrag;
-	bool fragemitted;
+	int seg_idx;
+
+	void *membuf;
+	erofs_off_t memoff;
+};
+
+#ifdef EROFS_MT_ENABLED
+struct erofs_compress_wq_tls {
+	u8 *queue;
+	char *destbuf;
+	struct erofs_compress_cfg *ccfg;
 };
 
+struct erofs_compress_work {
+	/* Note: struct erofs_work must be the first member */
+	struct erofs_work work;
+	struct z_erofs_compress_sctx ctx;
+	struct erofs_compress_work *next;
+
+	unsigned int alg_id;
+	char *alg_name;
+	unsigned int comp_level;
+	unsigned int dict_size;
+
+	int errcode;
+};
+
+static struct {
+	struct erofs_workqueue wq;
+	struct erofs_compress_work *idle;
+	pthread_mutex_t mutex;
+} z_erofs_mt_ctrl;
+#endif
+
+static bool z_erofs_mt_enabled;
+
 #define Z_EROFS_LEGACY_MAP_HEADER_SIZE	Z_EROFS_FULL_INDEX_ALIGN(0)
 
-static void z_erofs_write_indexes_final(struct z_erofs_vle_compress_ctx *ctx)
+static void z_erofs_write_indexes_final(struct z_erofs_compress_ictx *ctx)
 {
 	const unsigned int type = Z_EROFS_LCLUSTER_TYPE_PLAIN;
 	struct z_erofs_lcluster_index di;
@@ -65,20 +132,18 @@ static void z_erofs_write_indexes_final(struct z_erofs_vle_compress_ctx *ctx)
 	ctx->metacur += sizeof(di);
 }
 
-static void z_erofs_write_indexes(struct z_erofs_vle_compress_ctx *ctx)
+static void z_erofs_write_extent(struct z_erofs_compress_ictx *ctx,
+				 struct z_erofs_inmem_extent *e)
 {
 	struct erofs_inode *inode = ctx->inode;
 	struct erofs_sb_info *sbi = inode->sbi;
 	unsigned int clusterofs = ctx->clusterofs;
-	unsigned int count = ctx->e.length;
+	unsigned int count = e->length;
 	unsigned int d0 = 0, d1 = (clusterofs + count) / erofs_blksiz(sbi);
 	struct z_erofs_lcluster_index di;
 	unsigned int type, advise;
 
-	if (!count)
-		return;
-
-	ctx->e.length = 0;	/* mark as written first */
+	DBG_BUGON(!count);
 	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);
 
 	/* whether the tail-end (un)compressed block or not */
@@ -87,18 +152,18 @@ static void z_erofs_write_indexes(struct z_erofs_vle_compress_ctx *ctx)
 		 * A lcluster cannot have three parts with the middle one which
 		 * is well-compressed for !ztailpacking cases.
 		 */
-		DBG_BUGON(!ctx->e.raw && !cfg.c_ztailpacking && !cfg.c_fragments);
-		DBG_BUGON(ctx->e.partial);
-		type = ctx->e.raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
+		DBG_BUGON(!e->raw && !cfg.c_ztailpacking && !cfg.c_fragments);
+		DBG_BUGON(e->partial);
+		type = e->raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
 			Z_EROFS_LCLUSTER_TYPE_HEAD1;
 		advise = type << Z_EROFS_LI_LCLUSTER_TYPE_BIT;
 		di.di_advise = cpu_to_le16(advise);
 
 		if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL &&
-		    !ctx->e.compressedblks)
+		    !e->compressedblks)
 			di.di_u.blkaddr = cpu_to_le32(inode->fragmentoff >> 32);
 		else
-			di.di_u.blkaddr = cpu_to_le32(ctx->e.blkaddr);
+			di.di_u.blkaddr = cpu_to_le32(e->blkaddr);
 		memcpy(ctx->metacur, &di, sizeof(di));
 		ctx->metacur += sizeof(di);
 
@@ -112,7 +177,7 @@ static void z_erofs_write_indexes(struct z_erofs_vle_compress_ctx *ctx)
 		/* XXX: big pcluster feature should be per-inode */
 		if (d0 == 1 && erofs_sb_has_big_pcluster(sbi)) {
 			type = Z_EROFS_LCLUSTER_TYPE_NONHEAD;
-			di.di_u.delta[0] = cpu_to_le16(ctx->e.compressedblks |
+			di.di_u.delta[0] = cpu_to_le16(e->compressedblks |
 						       Z_EROFS_LI_D0_CBLKCNT);
 			di.di_u.delta[1] = cpu_to_le16(d1);
 		} else if (d0) {
@@ -136,17 +201,17 @@ static void z_erofs_write_indexes(struct z_erofs_vle_compress_ctx *ctx)
 				di.di_u.delta[0] = cpu_to_le16(d0);
 			di.di_u.delta[1] = cpu_to_le16(d1);
 		} else {
-			type = ctx->e.raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
+			type = e->raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
 				Z_EROFS_LCLUSTER_TYPE_HEAD1;
 
 			if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL &&
-			    !ctx->e.compressedblks)
+			    !e->compressedblks)
 				di.di_u.blkaddr = cpu_to_le32(inode->fragmentoff >> 32);
 			else
-				di.di_u.blkaddr = cpu_to_le32(ctx->e.blkaddr);
+				di.di_u.blkaddr = cpu_to_le32(e->blkaddr);
 
-			if (ctx->e.partial) {
-				DBG_BUGON(ctx->e.raw);
+			if (e->partial) {
+				DBG_BUGON(e->raw);
 				advise |= Z_EROFS_LI_PARTIAL_REF;
 			}
 		}
@@ -166,13 +231,62 @@ static void z_erofs_write_indexes(struct z_erofs_vle_compress_ctx *ctx)
 	ctx->clusterofs = clusterofs + count;
 }
 
-static int z_erofs_compress_dedupe(struct z_erofs_vle_compress_ctx *ctx,
+static void z_erofs_write_indexes(struct z_erofs_compress_ictx *ctx)
+{
+	struct z_erofs_extent_item *ei, *n;
+
+	ctx->clusterofs = 0;
+	list_for_each_entry_safe(ei, n, &ctx->extents, list) {
+		z_erofs_write_extent(ctx, &ei->e);
+
+		list_del(&ei->list);
+		free(ei);
+	}
+	z_erofs_write_indexes_final(ctx);
+}
+
+static bool z_erofs_need_refill(struct z_erofs_compress_sctx *ctx)
+{
+	const bool final = !ctx->remaining;
+	unsigned int qh_aligned, qh_after;
+	struct erofs_inode *inode = ctx->ictx->inode;
+
+	if (final || ctx->head < EROFS_CONFIG_COMPR_MAX_SZ)
+		return false;
+
+	qh_aligned = round_down(ctx->head, erofs_blksiz(inode->sbi));
+	qh_after = ctx->head - qh_aligned;
+	memmove(ctx->queue, ctx->queue + qh_aligned, ctx->tail - qh_aligned);
+	ctx->tail -= qh_aligned;
+	ctx->head = qh_after;
+	return true;
+}
+
+static struct z_erofs_extent_item dummy_pivot = {
+	.e.length = 0
+};
+
+static void z_erofs_commit_extent(struct z_erofs_compress_sctx *ctx,
+				  struct z_erofs_extent_item *ei)
+{
+	if (ei == &dummy_pivot)
+		return;
+
+	list_add_tail(&ei->list, &ctx->extents);
+	ctx->clusterofs = (ctx->clusterofs + ei->e.length) &
+			  (erofs_blksiz(ctx->ictx->inode->sbi) - 1);
+}
+
+static int z_erofs_compress_dedupe(struct z_erofs_compress_sctx *ctx,
 				   unsigned int *len)
 {
-	struct erofs_inode *inode = ctx->inode;
+	struct erofs_inode *inode = ctx->ictx->inode;
 	const unsigned int lclustermask = (1 << inode->z_logical_clusterbits) - 1;
 	struct erofs_sb_info *sbi = inode->sbi;
-	int ret = 0;
+	struct z_erofs_extent_item *ei = ctx->pivot;
+
+	if (!ei)
+		return 0;
 
 	/*
 	 * No need dedupe for packed inode since it is composed of
@@ -184,12 +298,12 @@ static int z_erofs_compress_dedupe(struct z_erofs_vle_compress_ctx *ctx,
 	do {
 		struct z_erofs_dedupe_ctx dctx = {
 			.start = ctx->queue + ctx->head - ({ int rc;
-				if (ctx->e.length <= erofs_blksiz(sbi))
+				if (ei->e.length <= erofs_blksiz(sbi))
 					rc = 0;
-				else if (ctx->e.length - erofs_blksiz(sbi) >= ctx->head)
+				else if (ei->e.length - erofs_blksiz(sbi) >= ctx->head)
 					rc = ctx->head;
 				else
-					rc = ctx->e.length - erofs_blksiz(sbi);
+					rc = ei->e.length - erofs_blksiz(sbi);
 				rc; }),
 			.end = ctx->queue + ctx->head + *len,
 			.cur = ctx->queue + ctx->head,
@@ -199,6 +313,7 @@ static int z_erofs_compress_dedupe(struct z_erofs_vle_compress_ctx *ctx,
 		if (z_erofs_dedupe_match(&dctx))
 			break;
 
+		DBG_BUGON(dctx.e.inlined);
 		delta = ctx->queue + ctx->head - dctx.cur;
 		/*
 		 * For big pcluster dedupe, leave two indices at least to store
@@ -206,25 +321,31 @@ static int z_erofs_compress_dedupe(struct z_erofs_vle_compress_ctx *ctx,
 		 * decompresssion could be done as another try in practice.
 		 */
 		if (dctx.e.compressedblks > 1 &&
-		    ((ctx->clusterofs + ctx->e.length - delta) & lclustermask) +
+		    ((ctx->clusterofs + ei->e.length - delta) & lclustermask) +
 			dctx.e.length < 2 * (lclustermask + 1))
 			break;
 
+		ctx->pivot = malloc(sizeof(struct z_erofs_extent_item));
+		if (!ctx->pivot) {
+			z_erofs_commit_extent(ctx, ei);
+			return -ENOMEM;
+		}
+
 		if (delta) {
 			DBG_BUGON(delta < 0);
-			DBG_BUGON(!ctx->e.length);
+			DBG_BUGON(!ei->e.length);
 
 			/*
 			 * For big pcluster dedupe, if we decide to shorten the
 			 * previous big pcluster, make sure that the previous
 			 * CBLKCNT is still kept.
 			 */
-			if (ctx->e.compressedblks > 1 &&
-			    (ctx->clusterofs & lclustermask) + ctx->e.length
+			if (ei->e.compressedblks > 1 &&
+			    (ctx->clusterofs & lclustermask) + ei->e.length
 				- delta < 2 * (lclustermask + 1))
 				break;
-			ctx->e.partial = true;
-			ctx->e.length -= delta;
+			ei->e.partial = true;
+			ei->e.length -= delta;
 		}
 
 		/* fall back to noncompact indexes for deduplication */
@@ -237,50 +358,36 @@ static int z_erofs_compress_dedupe(struct z_erofs_vle_compress_ctx *ctx,
 		erofs_dbg("Dedupe %u %scompressed data (delta %d) to %u of %u blocks",
 			  dctx.e.length, dctx.e.raw ? "un" : "",
 			  delta, dctx.e.blkaddr, dctx.e.compressedblks);
-		z_erofs_write_indexes(ctx);
-		ctx->e = dctx.e;
+
+		z_erofs_commit_extent(ctx, ei);
+		ei = ctx->pivot;
+		init_list_head(&ei->list);
+		ei->e = dctx.e;
+
 		ctx->head += dctx.e.length - delta;
 		DBG_BUGON(*len < dctx.e.length - delta);
 		*len -= dctx.e.length - delta;
 
-		if (ctx->head >= EROFS_CONFIG_COMPR_MAX_SZ) {
-			const unsigned int qh_aligned =
-				round_down(ctx->head, erofs_blksiz(sbi));
-			const unsigned int qh_after = ctx->head - qh_aligned;
-
-			memmove(ctx->queue, ctx->queue + qh_aligned,
-				*len + qh_after);
-			ctx->head = qh_after;
-			ctx->tail = qh_after + *len;
-			ret = -EAGAIN;
-			break;
-		}
+		if (z_erofs_need_refill(ctx))
+			return 1;
 	} while (*len);
-
 out:
-	z_erofs_write_indexes(ctx);
-	return ret;
+	z_erofs_commit_extent(ctx, ei);
+	ctx->pivot = NULL;
+	return 0;
 }
 
-static int write_uncompressed_extent(struct z_erofs_vle_compress_ctx *ctx,
-				     unsigned int *len, char *dst)
+static int write_uncompressed_extent(struct z_erofs_compress_sctx *ctx,
+				     unsigned int len, char *dst)
 {
+	struct erofs_inode *inode = ctx->ictx->inode;
+	struct erofs_sb_info *sbi = inode->sbi;
+	unsigned int count = min(erofs_blksiz(sbi), len);
+	unsigned int interlaced_offset, rightpart;
 	int ret;
-	struct erofs_sb_info *sbi = ctx->inode->sbi;
-	unsigned int count, interlaced_offset, rightpart;
-
-	/* reset clusterofs to 0 if permitted */
-	if (!erofs_sb_has_lz4_0padding(sbi) && ctx->clusterofs &&
-	    ctx->head >= ctx->clusterofs) {
-		ctx->head -= ctx->clusterofs;
-		*len += ctx->clusterofs;
-		ctx->clusterofs = 0;
-	}
-
-	count = min(erofs_blksiz(sbi), *len);
 
 	/* write interlaced uncompressed data if needed */
-	if (ctx->inode->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER)
+	if (inode->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER)
 		interlaced_offset = ctx->clusterofs;
 	else
 		interlaced_offset = 0;
@@ -291,32 +398,38 @@ static int write_uncompressed_extent(struct z_erofs_vle_compress_ctx *ctx,
 	memcpy(dst + interlaced_offset, ctx->queue + ctx->head, rightpart);
 	memcpy(dst, ctx->queue + ctx->head + rightpart, count - rightpart);
 
-	erofs_dbg("Writing %u uncompressed data to block %u",
-		  count, ctx->blkaddr);
-	ret = blk_write(sbi, dst, ctx->blkaddr, 1);
-	if (ret)
-		return ret;
+	if (ctx->membuf) {
+		erofs_dbg("Writing %u uncompressed data of %s", count,
+			  inode->i_srcpath);
+		memcpy(ctx->membuf + ctx->memoff, dst, erofs_blksiz(sbi));
+		ctx->memoff += erofs_blksiz(sbi);
+	} else {
+		erofs_dbg("Writing %u uncompressed data to block %u", count,
+			  ctx->blkaddr);
+		ret = erofs_blk_write(sbi, dst, ctx->blkaddr, 1);
+		if (ret)
+			return ret;
+	}
 	return count;
 }
 
 static unsigned int z_erofs_get_max_pclustersize(struct erofs_inode *inode)
 {
-	unsigned int pclusterblks;
-
-	if (erofs_is_packed_inode(inode))
-		pclusterblks = cfg.c_pclusterblks_packed;
+	if (erofs_is_packed_inode(inode)) {
+		return cfg.c_mkfs_pclustersize_packed;
 #ifndef NDEBUG
-	else if (cfg.c_random_pclusterblks)
-		pclusterblks = 1 + rand() % cfg.c_pclusterblks_max;
+	} else if (cfg.c_random_pclusterblks) {
+		unsigned int pclusterblks =
+			cfg.c_mkfs_pclustersize_max >> inode->sbi->blkszbits;
+
+		return (1 + rand() % pclusterblks) << inode->sbi->blkszbits;
 #endif
-	else if (cfg.c_compress_hints_file) {
+	} else if (cfg.c_compress_hints_file) {
 		z_erofs_apply_compress_hints(inode);
 		DBG_BUGON(!inode->z_physical_clusterblks);
-		pclusterblks = inode->z_physical_clusterblks;
-	} else {
-		pclusterblks = cfg.c_pclusterblks_def;
+		return inode->z_physical_clusterblks << inode->sbi->blkszbits;
 	}
-	return pclusterblks * erofs_blksiz(inode->sbi);
+	return cfg.c_mkfs_pclustersize_def;
 }
 
 static int z_erofs_fill_inline_data(struct erofs_inode *inode, void *data,
@@ -335,13 +448,13 @@ static int z_erofs_fill_inline_data(struct erofs_inode *inode, void *data,
 	return len;
 }
 
-static void tryrecompress_trailing(struct z_erofs_vle_compress_ctx *ctx,
+static void tryrecompress_trailing(struct z_erofs_compress_sctx *ctx,
 				   struct erofs_compress *ec,
 				   void *in, unsigned int *insize,
-				   void *out, int *compressedsize)
+				   void *out, unsigned int *compressedsize)
 {
-	struct erofs_sb_info *sbi = ctx->inode->sbi;
-	static char tmp[Z_EROFS_PCLUSTER_MAX_SIZE];
+	struct erofs_sb_info *sbi = ctx->ictx->inode->sbi;
+	char tmp[Z_EROFS_PCLUSTER_MAX_SIZE];
 	unsigned int count;
 	int ret = *compressedsize;
 
@@ -351,7 +464,7 @@ static void tryrecompress_trailing(struct z_erofs_vle_compress_ctx *ctx,
 
 	count = *insize;
 	ret = erofs_compress_destsize(ec, in, &count, (void *)tmp,
-				      rounddown(ret, erofs_blksiz(sbi)), false);
+				      rounddown(ret, erofs_blksiz(sbi)));
 	if (ret <= 0 || ret + (*insize - count) >=
 			roundup(*compressedsize, erofs_blksiz(sbi)))
 		return;
@@ -362,10 +475,11 @@ static void tryrecompress_trailing(struct z_erofs_vle_compress_ctx *ctx,
 	*compressedsize = ret;
 }
 
-static bool z_erofs_fixup_deduped_fragment(struct z_erofs_vle_compress_ctx *ctx,
+static bool z_erofs_fixup_deduped_fragment(struct z_erofs_compress_sctx *ctx,
 					   unsigned int len)
 {
-	struct erofs_inode *inode = ctx->inode;
+	struct z_erofs_compress_ictx *ictx = ctx->ictx;
+	struct erofs_inode *inode = ictx->inode;
 	struct erofs_sb_info *sbi = inode->sbi;
 	const unsigned int newsize = ctx->remaining + len;
 
@@ -373,9 +487,10 @@ static bool z_erofs_fixup_deduped_fragment(struct z_erofs_vle_compress_ctx *ctx,
 
 	/* try to fix again if it gets larger (should be rare) */
 	if (inode->fragment_size < newsize) {
-		ctx->pclustersize = min(z_erofs_get_max_pclustersize(inode),
-					roundup(newsize - inode->fragment_size,
-						erofs_blksiz(sbi)));
+		ctx->pclustersize = min_t(erofs_off_t,
+				z_erofs_get_max_pclustersize(inode),
+				roundup(newsize - inode->fragment_size,
+					erofs_blksiz(sbi)));
 		return false;
 	}
 
@@ -392,190 +507,219 @@ static bool z_erofs_fixup_deduped_fragment(struct z_erofs_vle_compress_ctx *ctx,
 	return true;
 }
 
-static int vle_compress_one(struct z_erofs_vle_compress_ctx *ctx)
+static int __z_erofs_compress_one(struct z_erofs_compress_sctx *ctx,
+				  struct z_erofs_inmem_extent *e)
 {
-	static char dstbuf[EROFS_CONFIG_COMPR_MAX_SZ + EROFS_MAX_BLOCK_SIZE];
-	struct erofs_inode *inode = ctx->inode;
+	static char g_dstbuf[EROFS_CONFIG_COMPR_MAX_SZ + EROFS_MAX_BLOCK_SIZE];
+	char *dstbuf = ctx->destbuf ?: g_dstbuf;
+	struct z_erofs_compress_ictx *ictx = ctx->ictx;
+	struct erofs_inode *inode = ictx->inode;
 	struct erofs_sb_info *sbi = inode->sbi;
-	char *const dst = dstbuf + erofs_blksiz(sbi);
-	struct erofs_compress *const h = &ctx->ccfg->handle;
+	unsigned int blksz = erofs_blksiz(sbi);
+	char *const dst = dstbuf + blksz;
+	struct erofs_compress *const h = ctx->chandle;
 	unsigned int len = ctx->tail - ctx->head;
 	bool is_packed_inode = erofs_is_packed_inode(inode);
-	bool final = !ctx->remaining;
+	bool tsg = (ctx->seg_idx + 1 >= ictx->seg_num), final = !ctx->remaining;
+	bool may_packing = (cfg.c_fragments && tsg && final &&
+			    !is_packed_inode && !z_erofs_mt_enabled);
+	bool may_inline = (cfg.c_ztailpacking && tsg && final && !may_packing);
+	unsigned int compressedsize;
 	int ret;
 
-	while (len) {
-		bool may_packing = (cfg.c_fragments && final &&
-				   !is_packed_inode);
-		bool may_inline = (cfg.c_ztailpacking && final &&
-				  !may_packing);
-		bool fix_dedupedfrag = ctx->fix_dedupedfrag;
-
-		if (z_erofs_compress_dedupe(ctx, &len) && !final)
-			break;
-
-		if (len <= ctx->pclustersize) {
-			if (!final || !len)
-				break;
-			if (may_packing) {
-				if (inode->fragment_size && !fix_dedupedfrag) {
-					ctx->pclustersize =
-						roundup(len, erofs_blksiz(sbi));
-					goto fix_dedupedfrag;
-				}
-				ctx->e.length = len;
-				goto frag_packing;
-			}
-			if (!may_inline && len <= erofs_blksiz(sbi))
-				goto nocompression;
+	*e = (struct z_erofs_inmem_extent){};
+	if (len <= ctx->pclustersize) {
+		if (!final || !len)
+			return 1;
+		if (inode->fragment_size && !ictx->fix_dedupedfrag) {
+			ctx->pclustersize = roundup(len, blksz);
+			goto fix_dedupedfrag;
+		}
+		if (may_packing) {
+			e->length = len;
+			goto frag_packing;
 		}
+		if (!may_inline && len <= blksz)
+			goto nocompression;
+	}
 
-		ctx->e.length = min(len,
-				cfg.c_max_decompressed_extent_bytes);
-		ret = erofs_compress_destsize(h, ctx->queue + ctx->head,
-				&ctx->e.length, dst, ctx->pclustersize,
-				!(final && len == ctx->e.length));
-		if (ret <= 0) {
-			if (ret != -EAGAIN) {
-				erofs_err("failed to compress %s: %s",
-					  inode->i_srcpath,
-					  erofs_strerror(ret));
-			}
+	e->length = min(len, cfg.c_max_decompressed_extent_bytes);
+	ret = erofs_compress_destsize(h, ctx->queue + ctx->head,
+				      &e->length, dst, ctx->pclustersize);
+	if (ret <= 0) {
+		erofs_err("failed to compress %s: %s", inode->i_srcpath,
+			  erofs_strerror(ret));
+		return ret;
+	}
 
-			if (may_inline && len < erofs_blksiz(sbi)) {
-				ret = z_erofs_fill_inline_data(inode,
-						ctx->queue + ctx->head,
-						len, true);
-			} else {
-				may_inline = false;
-				may_packing = false;
-nocompression:
-				ret = write_uncompressed_extent(ctx, &len, dst);
-			}
+	compressedsize = ret;
+	/* even compressed size is smaller, there is no real gain */
+	if (!(may_inline && e->length == len && ret < blksz))
+		ret = roundup(ret, blksz);
 
+	/* check if there is enough gain to keep the compressed data */
+	if (ret * h->compress_threshold / 100 >= e->length) {
+		if (may_inline && len < blksz) {
+			ret = z_erofs_fill_inline_data(inode,
+					ctx->queue + ctx->head, len, true);
 			if (ret < 0)
 				return ret;
-			ctx->e.length = ret;
-
-			/*
-			 * XXX: For now, we have to leave `ctx->compressedblks
-			 * = 1' since there is no way to generate compressed
-			 * indexes after the time that ztailpacking is decided.
-			 */
-			ctx->e.compressedblks = 1;
-			ctx->e.raw = true;
-		} else if (may_packing && len == ctx->e.length &&
-			   ret < ctx->pclustersize &&
-			   (!inode->fragment_size || fix_dedupedfrag)) {
-frag_packing:
-			ret = z_erofs_pack_fragments(inode,
-						     ctx->queue + ctx->head,
-						     len, ctx->tof_chksum);
+			e->inlined = true;
+		} else {
+			may_inline = false;
+			may_packing = false;
+nocompression:
+			/* TODO: reset clusterofs to 0 if permitted */
+			ret = write_uncompressed_extent(ctx, len, dst);
 			if (ret < 0)
 				return ret;
-			ctx->e.compressedblks = 0; /* indicate a fragment */
-			ctx->e.raw = false;
-			ctx->fragemitted = true;
-			fix_dedupedfrag = false;
-		/* tailpcluster should be less than 1 block */
-		} else if (may_inline && len == ctx->e.length &&
-			   ret < erofs_blksiz(sbi)) {
-			if (ctx->clusterofs + len <= erofs_blksiz(sbi)) {
-				inode->eof_tailraw = malloc(len);
-				if (!inode->eof_tailraw)
-					return -ENOMEM;
-
-				memcpy(inode->eof_tailraw,
-				       ctx->queue + ctx->head, len);
-				inode->eof_tailrawsize = len;
-			}
+		}
+		e->length = ret;
 
-			ret = z_erofs_fill_inline_data(inode, dst, ret, false);
-			if (ret < 0)
-				return ret;
-			ctx->e.compressedblks = 1;
-			ctx->e.raw = false;
-		} else {
-			unsigned int tailused, padding;
+		/*
+		 * XXX: For now, we have to leave `ctx->compressedblk = 1'
+		 * since there is no way to generate compressed indexes after
+		 * the time that ztailpacking is decided.
+		 */
+		e->compressedblks = 1;
+		e->raw = true;
+	} else if (may_packing && len == e->length &&
+		   compressedsize < ctx->pclustersize &&
+		   (!inode->fragment_size || ictx->fix_dedupedfrag)) {
+frag_packing:
+		ret = z_erofs_pack_fragments(inode, ctx->queue + ctx->head,
+					     len, ictx->tof_chksum);
+		if (ret < 0)
+			return ret;
+		e->compressedblks = 0; /* indicate a fragment */
+		e->raw = false;
+		ictx->fragemitted = true;
+	/* tailpcluster should be less than 1 block */
+	} else if (may_inline && len == e->length && compressedsize < blksz) {
+		if (ctx->clusterofs + len <= blksz) {
+			inode->eof_tailraw = malloc(len);
+			if (!inode->eof_tailraw)
+				return -ENOMEM;
+
+			memcpy(inode->eof_tailraw, ctx->queue + ctx->head, len);
+			inode->eof_tailrawsize = len;
+		}
 
-			/*
-			 * If there's space left for the last round when
-			 * deduping fragments, try to read the fragment and
-			 * recompress a little more to check whether it can be
-			 * filled up. Fix up the fragment if succeeds.
-			 * Otherwise, just drop it and go to packing.
-			 */
-			if (may_packing && len == ctx->e.length &&
-			    (ret & (erofs_blksiz(sbi) - 1)) &&
-			    ctx->tail < sizeof(ctx->queue)) {
-				ctx->pclustersize = BLK_ROUND_UP(sbi, ret) *
-						erofs_blksiz(sbi);
-				goto fix_dedupedfrag;
-			}
+		ret = z_erofs_fill_inline_data(inode, dst,
+				compressedsize, false);
+		if (ret < 0)
+			return ret;
+		e->inlined = true;
+		e->compressedblks = 1;
+		e->raw = false;
+	} else {
+		unsigned int tailused, padding;
+
+		/*
+		 * If there's space left for the last round when deduping
+		 * fragments, try to read the fragment and recompress a little
+		 * more to check whether it can be filled up.  Fix the fragment
+		 * if succeeds.  Otherwise, just drop it and go on packing.
+		 */
+		if (may_packing && len == e->length &&
+		    (compressedsize & (blksz - 1)) &&
+		    ctx->tail < Z_EROFS_COMPR_QUEUE_SZ) {
+			ctx->pclustersize = roundup(compressedsize, blksz);
+			goto fix_dedupedfrag;
+		}
+
+		if (may_inline && len == e->length)
+			tryrecompress_trailing(ctx, h, ctx->queue + ctx->head,
+					&e->length, dst, &compressedsize);
 
-			if (may_inline && len == ctx->e.length)
-				tryrecompress_trailing(ctx, h,
-						ctx->queue + ctx->head,
-						&ctx->e.length, dst, &ret);
+		e->compressedblks = BLK_ROUND_UP(sbi, compressedsize);
+		DBG_BUGON(e->compressedblks * blksz >= e->length);
 
-			tailused = ret & (erofs_blksiz(sbi) - 1);
+		padding = 0;
+		tailused = compressedsize & (blksz - 1);
+		if (tailused)
+			padding = blksz - tailused;
+
+		/* zero out garbage trailing data for non-0padding */
+		if (!erofs_sb_has_lz4_0padding(sbi)) {
+			memset(dst + compressedsize, 0, padding);
 			padding = 0;
-			ctx->e.compressedblks = BLK_ROUND_UP(sbi, ret);
-			DBG_BUGON(ctx->e.compressedblks * erofs_blksiz(sbi) >=
-				  ctx->e.length);
-
-			/* zero out garbage trailing data for non-0padding */
-			if (!erofs_sb_has_lz4_0padding(sbi))
-				memset(dst + ret, 0,
-				       roundup(ret, erofs_blksiz(sbi)) - ret);
-			else if (tailused)
-				padding = erofs_blksiz(sbi) - tailused;
-
-			/* write compressed data */
+		}
+
+		/* write compressed data */
+		if (ctx->membuf) {
+			erofs_dbg("Writing %u compressed data of %u blocks of %s",
+				  e->length, e->compressedblks, inode->i_srcpath);
+
+			memcpy(ctx->membuf + ctx->memoff, dst - padding,
+			       e->compressedblks * blksz);
+			ctx->memoff += e->compressedblks * blksz;
+		} else {
 			erofs_dbg("Writing %u compressed data to %u of %u blocks",
-				  ctx->e.length, ctx->blkaddr,
-				  ctx->e.compressedblks);
+				  e->length, ctx->blkaddr, e->compressedblks);
 
-			ret = blk_write(sbi, dst - padding, ctx->blkaddr,
-					ctx->e.compressedblks);
+			ret = erofs_blk_write(sbi, dst - padding, ctx->blkaddr,
+					      e->compressedblks);
 			if (ret)
 				return ret;
-			ctx->e.raw = false;
-			may_inline = false;
-			may_packing = false;
-		}
-		ctx->e.partial = false;
-		ctx->e.blkaddr = ctx->blkaddr;
-		if (!may_inline && !may_packing && !is_packed_inode)
-			(void)z_erofs_dedupe_insert(&ctx->e,
-						    ctx->queue + ctx->head);
-		ctx->blkaddr += ctx->e.compressedblks;
-		ctx->head += ctx->e.length;
-		len -= ctx->e.length;
-
-		if (fix_dedupedfrag &&
-		    z_erofs_fixup_deduped_fragment(ctx, len))
-			break;
-
-		if (!final && ctx->head >= EROFS_CONFIG_COMPR_MAX_SZ) {
-			const unsigned int qh_aligned =
-				round_down(ctx->head, erofs_blksiz(sbi));
-			const unsigned int qh_after = ctx->head - qh_aligned;
-
-			memmove(ctx->queue, ctx->queue + qh_aligned,
-				len + qh_after);
-			ctx->head = qh_after;
-			ctx->tail = qh_after + len;
-			break;
 		}
+		e->raw = false;
+		may_inline = false;
+		may_packing = false;
 	}
+	e->partial = false;
+	e->blkaddr = ctx->blkaddr;
+	if (ctx->blkaddr != EROFS_NULL_ADDR)
+		ctx->blkaddr += e->compressedblks;
+	if (!may_inline && !may_packing && !is_packed_inode)
+		(void)z_erofs_dedupe_insert(e, ctx->queue + ctx->head);
+	ctx->head += e->length;
 	return 0;
 
 fix_dedupedfrag:
 	DBG_BUGON(!inode->fragment_size);
 	ctx->remaining += inode->fragment_size;
-	ctx->e.length = 0;
-	ctx->fix_dedupedfrag = true;
+	ictx->fix_dedupedfrag = true;
+	return 1;
+}
+
+static int z_erofs_compress_one(struct z_erofs_compress_sctx *ctx)
+{
+	struct z_erofs_compress_ictx *ictx = ctx->ictx;
+	unsigned int len = ctx->tail - ctx->head;
+	struct z_erofs_extent_item *ei;
+
+	while (len) {
+		int ret = z_erofs_compress_dedupe(ctx, &len);
+
+		if (ret > 0)
+			break;
+		else if (ret < 0)
+			return ret;
+
+		DBG_BUGON(ctx->pivot);
+		ei = malloc(sizeof(*ei));
+		if (!ei)
+			return -ENOMEM;
+
+		init_list_head(&ei->list);
+		ret = __z_erofs_compress_one(ctx, &ei->e);
+		if (ret) {
+			free(ei);
+			if (ret > 0)
+				break;		/* need more data */
+			return ret;
+		}
+
+		len -= ei->e.length;
+		ctx->pivot = ei;
+		if (ictx->fix_dedupedfrag && !ictx->fragemitted &&
+		    z_erofs_fixup_deduped_fragment(ctx, len))
+			break;
+
+		if (z_erofs_need_refill(ctx))
+			break;
+	}
 	return 0;
 }
 
@@ -616,19 +760,20 @@ static void *write_compacted_indexes(u8 *out,
 				     struct z_erofs_compressindex_vec *cv,
 				     erofs_blk_t *blkaddr_ret,
 				     unsigned int destsize,
-				     unsigned int logical_clusterbits,
+				     unsigned int lclusterbits,
 				     bool final, bool *dummy_head,
 				     bool update_blkaddr)
 {
-	unsigned int vcnt, encodebits, pos, i, cblks;
+	unsigned int vcnt, lobits, encodebits, pos, i, cblks;
 	erofs_blk_t blkaddr;
 
 	if (destsize == 4)
 		vcnt = 2;
-	else if (destsize == 2 && logical_clusterbits == 12)
+	else if (destsize == 2 && lclusterbits <= 12)
 		vcnt = 16;
 	else
 		return ERR_PTR(-EINVAL);
+	lobits = max(lclusterbits, ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1U);
 	encodebits = (vcnt * destsize * 8 - 32) / vcnt;
 	blkaddr = *blkaddr_ret;
 
@@ -645,7 +790,7 @@ static void *write_compacted_indexes(u8 *out,
 				*dummy_head = false;
 			} else if (i + 1 == vcnt) {
 				offset = min_t(u16, cv[i].u.delta[1],
-						(1 << logical_clusterbits) - 1);
+						(1 << lobits) - 1);
 			} else {
 				offset = cv[i].u.delta[0];
 			}
@@ -665,7 +810,7 @@ static void *write_compacted_indexes(u8 *out,
 				DBG_BUGON(cv[i].u.blkaddr);
 			}
 		}
-		v = (cv[i].clustertype << logical_clusterbits) | offset;
+		v = (cv[i].clustertype << lobits) | offset;
 		rem = pos & 7;
 		ch = out[pos / 8] & ((1 << rem) - 1);
 		out[pos / 8] = (v << rem) | ch;
@@ -700,7 +845,7 @@ int z_erofs_convert_to_compacted_format(struct erofs_inode *inode,
 	bool dummy_head;
 	bool big_pcluster = erofs_sb_has_big_pcluster(sbi);
 
-	if (logical_clusterbits < sbi->blkszbits || sbi->blkszbits < 12)
+	if (logical_clusterbits < sbi->blkszbits)
 		return -EINVAL;
 	if (logical_clusterbits > 14) {
 		erofs_err("compact format is unsupported for lcluster size %u",
@@ -709,7 +854,7 @@ int z_erofs_convert_to_compacted_format(struct erofs_inode *inode,
 	}
 
 	if (inode->z_advise & Z_EROFS_ADVISE_COMPACTED_2B) {
-		if (logical_clusterbits != 12) {
+		if (logical_clusterbits > 12) {
 			erofs_err("compact 2B is unsupported for lcluster size %u",
 				  1 << logical_clusterbits);
 			return -EINVAL;
@@ -856,145 +1001,108 @@ void z_erofs_drop_inline_pcluster(struct erofs_inode *inode)
 	inode->eof_tailraw = NULL;
 }
 
-int erofs_write_compressed_file(struct erofs_inode *inode, int fd)
+int z_erofs_compress_segment(struct z_erofs_compress_sctx *ctx,
+			     u64 offset, erofs_blk_t blkaddr)
 {
-	struct erofs_buffer_head *bh;
-	static struct z_erofs_vle_compress_ctx ctx;
-	erofs_blk_t blkaddr, compressed_blocks;
-	unsigned int legacymetasize;
-	int ret;
-	struct erofs_sb_info *sbi = inode->sbi;
-	u8 *compressmeta = malloc(BLK_ROUND_UP(sbi, inode->i_size) *
-				  sizeof(struct z_erofs_lcluster_index) +
-				  Z_EROFS_LEGACY_MAP_HEADER_SIZE);
-
-	if (!compressmeta)
-		return -ENOMEM;
-
-	/* allocate main data buffer */
-	bh = erofs_balloc(DATA, 0, 0, 0);
-	if (IS_ERR(bh)) {
-		ret = PTR_ERR(bh);
-		goto err_free_meta;
-	}
-
-	/* initialize per-file compression setting */
-	inode->z_advise = 0;
-	inode->z_logical_clusterbits = sbi->blkszbits;
-	if (!cfg.c_legacy_compress && inode->z_logical_clusterbits <= 14) {
-		if (inode->z_logical_clusterbits <= 12)
-			inode->z_advise |= Z_EROFS_ADVISE_COMPACTED_2B;
-		inode->datalayout = EROFS_INODE_COMPRESSED_COMPACT;
-	} else {
-		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
-	}
-
-	if (erofs_sb_has_big_pcluster(sbi)) {
-		inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_1;
-		if (inode->datalayout == EROFS_INODE_COMPRESSED_COMPACT)
-			inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_2;
+	struct z_erofs_compress_ictx *ictx = ctx->ictx;
+	int fd = ictx->fd;
+
+	ctx->blkaddr = blkaddr;
+	while (ctx->remaining) {
+		const u64 rx = min_t(u64, ctx->remaining,
+				     Z_EROFS_COMPR_QUEUE_SZ - ctx->tail);
+		int ret;
+
+		ret = (offset == -1 ?
+			read(fd, ctx->queue + ctx->tail, rx) :
+			pread(fd, ctx->queue + ctx->tail, rx,
+			      ictx->fpos + offset));
+		if (ret != rx)
+			return -errno;
+
+		ctx->remaining -= rx;
+		ctx->tail += rx;
+		if (offset != -1)
+			offset += rx;
+
+		ret = z_erofs_compress_one(ctx);
+		if (ret)
+			return ret;
 	}
-	if (cfg.c_fragments && !cfg.c_dedupe)
-		inode->z_advise |= Z_EROFS_ADVISE_INTERLACED_PCLUSTER;
+	DBG_BUGON(ctx->head != ctx->tail);
 
-#ifndef NDEBUG
-	if (cfg.c_random_algorithms) {
-		while (1) {
-			inode->z_algorithmtype[0] =
-				rand() % EROFS_MAX_COMPR_CFGS;
-			if (erofs_ccfg[inode->z_algorithmtype[0]].enable)
-				break;
-		}
+	if (ctx->pivot) {
+		z_erofs_commit_extent(ctx, ctx->pivot);
+		ctx->pivot = NULL;
 	}
-#endif
-	ctx.ccfg = &erofs_ccfg[inode->z_algorithmtype[0]];
-	inode->z_algorithmtype[0] = ctx.ccfg[0].algorithmtype;
-	inode->z_algorithmtype[1] = 0;
-
-	inode->idata_size = 0;
-	inode->fragment_size = 0;
 
-	/*
-	 * Handle tails in advance to avoid writing duplicated
-	 * parts into the packed inode.
-	 */
-	if (cfg.c_fragments && !erofs_is_packed_inode(inode)) {
-		ret = z_erofs_fragments_dedupe(inode, fd, &ctx.tof_chksum);
-		if (ret < 0)
-			goto err_bdrop;
+	/* generate an extra extent for the deduplicated fragment */
+	if (ctx->seg_idx >= ictx->seg_num - 1 &&
+	    ictx->inode->fragment_size && !ictx->fragemitted) {
+		struct z_erofs_extent_item *ei;
+
+		ei = malloc(sizeof(*ei));
+		if (!ei)
+			return -ENOMEM;
+
+		ei->e = (struct z_erofs_inmem_extent) {
+			.length = ictx->inode->fragment_size,
+			.compressedblks = 0,
+			.raw = false,
+			.partial = false,
+			.blkaddr = ctx->blkaddr,
+		};
+		init_list_head(&ei->list);
+		z_erofs_commit_extent(ctx, ei);
 	}
+	return 0;
+}
 
-	blkaddr = erofs_mapbh(bh->block);	/* start_blkaddr */
-	ctx.inode = inode;
-	ctx.pclustersize = z_erofs_get_max_pclustersize(inode);
-	ctx.blkaddr = blkaddr;
-	ctx.metacur = compressmeta + Z_EROFS_LEGACY_MAP_HEADER_SIZE;
-	ctx.head = ctx.tail = 0;
-	ctx.clusterofs = 0;
-	ctx.e.length = 0;
-	ctx.remaining = inode->i_size - inode->fragment_size;
-	ctx.fix_dedupedfrag = false;
-	ctx.fragemitted = false;
-	if (cfg.c_all_fragments && !erofs_is_packed_inode(inode) &&
-	    !inode->fragment_size) {
-		ret = z_erofs_pack_file_from_fd(inode, fd, ctx.tof_chksum);
-		if (ret)
-			goto err_free_idata;
-	} else {
-		while (ctx.remaining) {
-			const u64 rx = min_t(u64, ctx.remaining,
-					     sizeof(ctx.queue) - ctx.tail);
-
-			ret = read(fd, ctx.queue + ctx.tail, rx);
-			if (ret != rx) {
-				ret = -errno;
-				goto err_bdrop;
-			}
-			ctx.remaining -= rx;
-			ctx.tail += rx;
+int erofs_commit_compressed_file(struct z_erofs_compress_ictx *ictx,
+				 struct erofs_buffer_head *bh,
+				 erofs_blk_t blkaddr,
+				 erofs_blk_t compressed_blocks)
+{
+	struct erofs_inode *inode = ictx->inode;
+	struct erofs_sb_info *sbi = inode->sbi;
+	unsigned int legacymetasize;
+	u8 *compressmeta;
+	int ret;
 
-			ret = vle_compress_one(&ctx);
-			if (ret)
-				goto err_free_idata;
-		}
-	}
-	DBG_BUGON(ctx.head != ctx.tail);
+	z_erofs_fragments_commit(inode);
 
 	/* fall back to no compression mode */
-	compressed_blocks = ctx.blkaddr - blkaddr;
 	DBG_BUGON(compressed_blocks < !!inode->idata_size);
 	compressed_blocks -= !!inode->idata_size;
 
-	/* generate an extent for the deduplicated fragment */
-	if (inode->fragment_size && !ctx.fragemitted) {
-		z_erofs_write_indexes(&ctx);
-		ctx.e.length = inode->fragment_size;
-		ctx.e.compressedblks = 0;
-		ctx.e.raw = false;
-		ctx.e.partial = false;
-		ctx.e.blkaddr = ctx.blkaddr;
+	compressmeta = malloc(BLK_ROUND_UP(sbi, inode->i_size) *
+			      sizeof(struct z_erofs_lcluster_index) +
+			      Z_EROFS_LEGACY_MAP_HEADER_SIZE);
+	if (!compressmeta) {
+		ret = -ENOMEM;
+		goto err_free_idata;
 	}
-	z_erofs_fragments_commit(inode);
+	ictx->metacur = compressmeta + Z_EROFS_LEGACY_MAP_HEADER_SIZE;
+	z_erofs_write_indexes(ictx);
 
-	z_erofs_write_indexes(&ctx);
-	z_erofs_write_indexes_final(&ctx);
-	legacymetasize = ctx.metacur - compressmeta;
+	legacymetasize = ictx->metacur - compressmeta;
 	/* estimate if data compression saves space or not */
 	if (!inode->fragment_size &&
 	    compressed_blocks * erofs_blksiz(sbi) + inode->idata_size +
 	    legacymetasize >= inode->i_size) {
 		z_erofs_dedupe_commit(true);
 		ret = -ENOSPC;
-		goto err_free_idata;
+		goto err_free_meta;
 	}
 	z_erofs_dedupe_commit(false);
 	z_erofs_write_mapheader(inode, compressmeta);
 
-	if (!ctx.fragemitted)
+	if (!ictx->fragemitted)
 		sbi->saved_by_deduplication += inode->fragment_size;
 
 	/* if the entire file is a fragment, a simplified form is used. */
-	if (inode->i_size == inode->fragment_size) {
+	if (inode->i_size <= inode->fragment_size) {
+		DBG_BUGON(inode->i_size < inode->fragment_size);
 		DBG_BUGON(inode->fragmentoff >> 63);
 		*(__le64 *)compressmeta =
 			cpu_to_le64(inode->fragmentoff | 1ULL << 63);
@@ -1036,20 +1144,441 @@ int erofs_write_compressed_file(struct erofs_inode *inode, int fd)
 		erofs_droid_blocklist_write(inode, blkaddr, compressed_blocks);
 	return 0;
 
+err_free_meta:
+	free(compressmeta);
+	inode->compressmeta = NULL;
+err_free_idata:
+	erofs_bdrop(bh, true);	/* revoke buffer */
+	if (inode->idata) {
+		free(inode->idata);
+		inode->idata = NULL;
+	}
+	return ret;
+}
+
+#ifdef EROFS_MT_ENABLED
+void *z_erofs_mt_wq_tls_alloc(struct erofs_workqueue *wq, void *ptr)
+{
+	struct erofs_compress_wq_tls *tls;
+
+	tls = calloc(1, sizeof(*tls));
+	if (!tls)
+		return NULL;
+
+	tls->queue = malloc(Z_EROFS_COMPR_QUEUE_SZ);
+	if (!tls->queue)
+		goto err_free_priv;
+
+	tls->destbuf = calloc(1, EROFS_CONFIG_COMPR_MAX_SZ +
+			      EROFS_MAX_BLOCK_SIZE);
+	if (!tls->destbuf)
+		goto err_free_queue;
+
+	tls->ccfg = calloc(EROFS_MAX_COMPR_CFGS, sizeof(*tls->ccfg));
+	if (!tls->ccfg)
+		goto err_free_destbuf;
+	return tls;
+
+err_free_destbuf:
+	free(tls->destbuf);
+err_free_queue:
+	free(tls->queue);
+err_free_priv:
+	free(tls);
+	return NULL;
+}
+
+int z_erofs_mt_wq_tls_init_compr(struct erofs_sb_info *sbi,
+				 struct erofs_compress_wq_tls *tls,
+				 unsigned int alg_id, char *alg_name,
+				 unsigned int comp_level,
+				 unsigned int dict_size)
+{
+	struct erofs_compress_cfg *lc = &tls->ccfg[alg_id];
+	int ret;
+
+	if (__erofs_likely(lc->enable))
+		return 0;
+
+	ret = erofs_compressor_init(sbi, &lc->handle, alg_name,
+				    comp_level, dict_size);
+	if (ret)
+		return ret;
+	lc->algorithmtype = alg_id;
+	lc->enable = true;
+	return 0;
+}
+
+void *z_erofs_mt_wq_tls_free(struct erofs_workqueue *wq, void *priv)
+{
+	struct erofs_compress_wq_tls *tls = priv;
+	int i;
+
+	for (i = 0; i < EROFS_MAX_COMPR_CFGS; i++)
+		if (tls->ccfg[i].enable)
+			erofs_compressor_exit(&tls->ccfg[i].handle);
+
+	free(tls->ccfg);
+	free(tls->destbuf);
+	free(tls->queue);
+	free(tls);
+	return NULL;
+}
+
+void z_erofs_mt_workfn(struct erofs_work *work, void *tlsp)
+{
+	struct erofs_compress_work *cwork = (struct erofs_compress_work *)work;
+	struct erofs_compress_wq_tls *tls = tlsp;
+	struct z_erofs_compress_sctx *sctx = &cwork->ctx;
+	struct z_erofs_compress_ictx *ictx = sctx->ictx;
+	struct erofs_inode *inode = ictx->inode;
+	struct erofs_sb_info *sbi = inode->sbi;
+	int ret = 0;
+
+	ret = z_erofs_mt_wq_tls_init_compr(sbi, tls, cwork->alg_id,
+					   cwork->alg_name, cwork->comp_level,
+					   cwork->dict_size);
+	if (ret)
+		goto out;
+
+	sctx->pclustersize = z_erofs_get_max_pclustersize(inode);
+	sctx->queue = tls->queue;
+	sctx->destbuf = tls->destbuf;
+	sctx->chandle = &tls->ccfg[cwork->alg_id].handle;
+	erofs_compressor_reset(sctx->chandle);
+	sctx->membuf = malloc(round_up(sctx->remaining, erofs_blksiz(sbi)));
+	if (!sctx->membuf) {
+		ret = -ENOMEM;
+		goto out;
+	}
+	sctx->memoff = 0;
+
+	ret = z_erofs_compress_segment(sctx, sctx->seg_idx * cfg.c_mkfs_segment_size,
+				       EROFS_NULL_ADDR);
+
+out:
+	cwork->errcode = ret;
+	pthread_mutex_lock(&ictx->mutex);
+	if (++ictx->nfini >= ictx->seg_num) {
+		DBG_BUGON(ictx->nfini > ictx->seg_num);
+		pthread_cond_signal(&ictx->cond);
+	}
+	pthread_mutex_unlock(&ictx->mutex);
+}
+
+int z_erofs_merge_segment(struct z_erofs_compress_ictx *ictx,
+			  struct z_erofs_compress_sctx *sctx)
+{
+	struct z_erofs_extent_item *ei, *n;
+	struct erofs_sb_info *sbi = ictx->inode->sbi;
+	erofs_blk_t blkoff = 0;
+	int ret = 0, ret2;
+
+	list_for_each_entry_safe(ei, n, &sctx->extents, list) {
+		list_del(&ei->list);
+		list_add_tail(&ei->list, &ictx->extents);
+
+		if (ei->e.blkaddr != EROFS_NULL_ADDR)	/* deduped extents */
+			continue;
+
+		ei->e.blkaddr = sctx->blkaddr;
+		sctx->blkaddr += ei->e.compressedblks;
+
+		/* skip write data but leave blkaddr for inline fallback */
+		if (ei->e.inlined || !ei->e.compressedblks)
+			continue;
+		ret2 = erofs_blk_write(sbi, sctx->membuf + blkoff * erofs_blksiz(sbi),
+				       ei->e.blkaddr, ei->e.compressedblks);
+		blkoff += ei->e.compressedblks;
+		if (ret2) {
+			ret = ret2;
+			continue;
+		}
+	}
+	free(sctx->membuf);
+	return ret;
+}
+
+int z_erofs_mt_compress(struct z_erofs_compress_ictx *ictx)
+{
+	struct erofs_compress_work *cur, *head = NULL, **last = &head;
+	struct erofs_compress_cfg *ccfg = ictx->ccfg;
+	struct erofs_inode *inode = ictx->inode;
+	int nsegs = DIV_ROUND_UP(inode->i_size, cfg.c_mkfs_segment_size);
+	int i;
+
+	ictx->seg_num = nsegs;
+	ictx->nfini = 0;
+	pthread_mutex_init(&ictx->mutex, NULL);
+	pthread_cond_init(&ictx->cond, NULL);
+
+	for (i = 0; i < nsegs; i++) {
+		pthread_mutex_lock(&z_erofs_mt_ctrl.mutex);
+		cur = z_erofs_mt_ctrl.idle;
+		if (cur) {
+			z_erofs_mt_ctrl.idle = cur->next;
+			cur->next = NULL;
+		}
+		pthread_mutex_unlock(&z_erofs_mt_ctrl.mutex);
+		if (!cur) {
+			cur = calloc(1, sizeof(*cur));
+			if (!cur)
+				return -ENOMEM;
+		}
+		*last = cur;
+		last = &cur->next;
+
+		cur->ctx = (struct z_erofs_compress_sctx) {
+			.ictx = ictx,
+			.seg_idx = i,
+			.pivot = &dummy_pivot,
+		};
+		init_list_head(&cur->ctx.extents);
+
+		if (i == nsegs - 1)
+			cur->ctx.remaining = inode->i_size -
+					      inode->fragment_size -
+					      i * cfg.c_mkfs_segment_size;
+		else
+			cur->ctx.remaining = cfg.c_mkfs_segment_size;
+
+		cur->alg_id = ccfg->handle.alg->id;
+		cur->alg_name = ccfg->handle.alg->name;
+		cur->comp_level = ccfg->handle.compression_level;
+		cur->dict_size = ccfg->handle.dict_size;
+
+		cur->work.fn = z_erofs_mt_workfn;
+		erofs_queue_work(&z_erofs_mt_ctrl.wq, &cur->work);
+	}
+	ictx->mtworks = head;
+	return 0;
+}
+
+int erofs_mt_write_compressed_file(struct z_erofs_compress_ictx *ictx)
+{
+	struct erofs_sb_info *sbi = ictx->inode->sbi;
+	struct erofs_buffer_head *bh = NULL;
+	struct erofs_compress_work *head = ictx->mtworks, *cur;
+	erofs_blk_t blkaddr, compressed_blocks = 0;
+	int ret;
+
+	pthread_mutex_lock(&ictx->mutex);
+	while (ictx->nfini < ictx->seg_num)
+		pthread_cond_wait(&ictx->cond, &ictx->mutex);
+	pthread_mutex_unlock(&ictx->mutex);
+
+	bh = erofs_balloc(sbi->bmgr, DATA, 0, 0, 0);
+	if (IS_ERR(bh)) {
+		ret = PTR_ERR(bh);
+		goto out;
+	}
+
+	DBG_BUGON(!head);
+	blkaddr = erofs_mapbh(NULL, bh->block);
+
+	ret = 0;
+	do {
+		cur = head;
+		head = cur->next;
+
+		if (cur->errcode) {
+			ret = cur->errcode;
+		} else {
+			int ret2;
+
+			cur->ctx.blkaddr = blkaddr;
+			ret2 = z_erofs_merge_segment(ictx, &cur->ctx);
+			if (ret2)
+				ret = ret2;
+
+			compressed_blocks += cur->ctx.blkaddr - blkaddr;
+			blkaddr = cur->ctx.blkaddr;
+		}
+
+		pthread_mutex_lock(&z_erofs_mt_ctrl.mutex);
+		cur->next = z_erofs_mt_ctrl.idle;
+		z_erofs_mt_ctrl.idle = cur;
+		pthread_mutex_unlock(&z_erofs_mt_ctrl.mutex);
+	} while (head);
+
+	if (ret)
+		goto out;
+	ret = erofs_commit_compressed_file(ictx, bh,
+			blkaddr - compressed_blocks, compressed_blocks);
+
+out:
+	close(ictx->fd);
+	free(ictx);
+	return ret;
+}
+#endif
+
+static struct z_erofs_compress_ictx g_ictx;
+
+void *erofs_begin_compressed_file(struct erofs_inode *inode, int fd, u64 fpos)
+{
+	struct erofs_sb_info *sbi = inode->sbi;
+	struct z_erofs_compress_ictx *ictx;
+	int ret;
+
+	/* initialize per-file compression setting */
+	inode->z_advise = 0;
+	inode->z_logical_clusterbits = sbi->blkszbits;
+	if (!cfg.c_legacy_compress && inode->z_logical_clusterbits <= 14) {
+		if (inode->z_logical_clusterbits <= 12)
+			inode->z_advise |= Z_EROFS_ADVISE_COMPACTED_2B;
+		inode->datalayout = EROFS_INODE_COMPRESSED_COMPACT;
+	} else {
+		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
+	}
+
+	if (erofs_sb_has_big_pcluster(sbi)) {
+		inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_1;
+		if (inode->datalayout == EROFS_INODE_COMPRESSED_COMPACT)
+			inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_2;
+	}
+	if (cfg.c_fragments && !cfg.c_dedupe)
+		inode->z_advise |= Z_EROFS_ADVISE_INTERLACED_PCLUSTER;
+
+#ifndef NDEBUG
+	if (cfg.c_random_algorithms) {
+		while (1) {
+			inode->z_algorithmtype[0] =
+				rand() % EROFS_MAX_COMPR_CFGS;
+			if (erofs_ccfg[inode->z_algorithmtype[0]].enable)
+				break;
+		}
+	}
+#endif
+	inode->idata_size = 0;
+	inode->fragment_size = 0;
+
+	if (z_erofs_mt_enabled) {
+		ictx = malloc(sizeof(*ictx));
+		if (!ictx)
+			return ERR_PTR(-ENOMEM);
+		ictx->fd = dup(fd);
+	} else {
+#ifdef EROFS_MT_ENABLED
+		pthread_mutex_lock(&g_ictx.mutex);
+		if (g_ictx.seg_num)
+			pthread_cond_wait(&g_ictx.cond, &g_ictx.mutex);
+		g_ictx.seg_num = 1;
+		pthread_mutex_unlock(&g_ictx.mutex);
+#endif
+		ictx = &g_ictx;
+		ictx->fd = fd;
+	}
+
+	ictx->ccfg = &erofs_ccfg[inode->z_algorithmtype[0]];
+	inode->z_algorithmtype[0] = ictx->ccfg->algorithmtype;
+	inode->z_algorithmtype[1] = 0;
+
+	/*
+	 * Handle tails in advance to avoid writing duplicated
+	 * parts into the packed inode.
+	 */
+	if (cfg.c_fragments && !erofs_is_packed_inode(inode)) {
+		ret = z_erofs_fragments_dedupe(inode, fd, &ictx->tof_chksum);
+		if (ret < 0)
+			goto err_free_ictx;
+	}
+
+	ictx->inode = inode;
+	ictx->fpos = fpos;
+	init_list_head(&ictx->extents);
+	ictx->fix_dedupedfrag = false;
+	ictx->fragemitted = false;
+
+	if (cfg.c_all_fragments && !erofs_is_packed_inode(inode) &&
+	    !inode->fragment_size) {
+		ret = z_erofs_pack_file_from_fd(inode, fd, ictx->tof_chksum);
+		if (ret)
+			goto err_free_idata;
+	}
+#ifdef EROFS_MT_ENABLED
+	if (ictx != &g_ictx) {
+		ret = z_erofs_mt_compress(ictx);
+		if (ret)
+			goto err_free_idata;
+	}
+#endif
+	return ictx;
+
 err_free_idata:
 	if (inode->idata) {
 		free(inode->idata);
 		inode->idata = NULL;
 	}
-err_bdrop:
+err_free_ictx:
+	if (ictx != &g_ictx)
+		free(ictx);
+	return ERR_PTR(ret);
+}
+
+int erofs_write_compressed_file(struct z_erofs_compress_ictx *ictx)
+{
+	static u8 g_queue[Z_EROFS_COMPR_QUEUE_SZ];
+	struct erofs_buffer_head *bh;
+	static struct z_erofs_compress_sctx sctx;
+	struct erofs_compress_cfg *ccfg = ictx->ccfg;
+	struct erofs_inode *inode = ictx->inode;
+	erofs_blk_t blkaddr;
+	int ret;
+
+#ifdef EROFS_MT_ENABLED
+	if (ictx != &g_ictx)
+		return erofs_mt_write_compressed_file(ictx);
+#endif
+
+	/* allocate main data buffer */
+	bh = erofs_balloc(inode->sbi->bmgr, DATA, 0, 0, 0);
+	if (IS_ERR(bh)) {
+		ret = PTR_ERR(bh);
+		goto err_free_idata;
+	}
+	blkaddr = erofs_mapbh(NULL, bh->block); /* start_blkaddr */
+
+	ictx->seg_num = 1;
+	sctx = (struct z_erofs_compress_sctx) {
+		.ictx = ictx,
+		.queue = g_queue,
+		.chandle = &ccfg->handle,
+		.remaining = inode->i_size - inode->fragment_size,
+		.seg_idx = 0,
+		.pivot = &dummy_pivot,
+		.pclustersize = z_erofs_get_max_pclustersize(inode),
+	};
+	init_list_head(&sctx.extents);
+
+	ret = z_erofs_compress_segment(&sctx, -1, blkaddr);
+	if (ret)
+		goto err_free_idata;
+
+	list_splice_tail(&sctx.extents, &ictx->extents);
+	ret = erofs_commit_compressed_file(ictx, bh, blkaddr,
+					   sctx.blkaddr - blkaddr);
+	goto out;
+
+err_free_idata:
 	erofs_bdrop(bh, true);	/* revoke buffer */
-err_free_meta:
-	free(compressmeta);
+	if (inode->idata) {
+		free(inode->idata);
+		inode->idata = NULL;
+	}
+out:
+#ifdef EROFS_MT_ENABLED
+	pthread_mutex_lock(&ictx->mutex);
+	ictx->seg_num = 0;
+	pthread_cond_signal(&ictx->cond);
+	pthread_mutex_unlock(&ictx->mutex);
+#endif
 	return ret;
 }
 
 static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
-				    struct erofs_buffer_head *sb_bh)
+				    struct erofs_buffer_head *sb_bh,
+				    u32 *max_dict_size)
 {
 	struct erofs_buffer_head *bh = sb_bh;
 	int ret = 0;
@@ -1062,8 +1591,9 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 			.size = cpu_to_le16(sizeof(struct z_erofs_lz4_cfgs)),
 			.lz4 = {
 				.max_distance =
-					cpu_to_le16(sbi->lz4_max_distance),
-				.max_pclusterblks = cfg.c_pclusterblks_max,
+					cpu_to_le16(sbi->lz4.max_distance),
+				.max_pclusterblks =
+					cfg.c_mkfs_pclustersize_max >> sbi->blkszbits,
 			}
 		};
 
@@ -1072,9 +1602,9 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 			DBG_BUGON(1);
 			return PTR_ERR(bh);
 		}
-		erofs_mapbh(bh->block);
-		ret = dev_write(sbi, &lz4alg, erofs_btell(bh, false),
-				sizeof(lz4alg));
+		erofs_mapbh(NULL, bh->block);
+		ret = erofs_dev_write(sbi, &lz4alg, erofs_btell(bh, false),
+				      sizeof(lz4alg));
 		bh->op = &erofs_drop_directly_bhops;
 	}
 #ifdef HAVE_LIBLZMA
@@ -1085,7 +1615,9 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 		} __packed lzmaalg = {
 			.size = cpu_to_le16(sizeof(struct z_erofs_lzma_cfgs)),
 			.lzma = {
-				.dict_size = cpu_to_le32(cfg.c_dict_size),
+				.dict_size = cpu_to_le32(
+					max_dict_size
+						[Z_EROFS_COMPRESSION_LZMA]),
 			}
 		};
 
@@ -1094,9 +1626,9 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 			DBG_BUGON(1);
 			return PTR_ERR(bh);
 		}
-		erofs_mapbh(bh->block);
-		ret = dev_write(sbi, &lzmaalg, erofs_btell(bh, false),
-				sizeof(lzmaalg));
+		erofs_mapbh(NULL, bh->block);
+		ret = erofs_dev_write(sbi, &lzmaalg, erofs_btell(bh, false),
+				      sizeof(lzmaalg));
 		bh->op = &erofs_drop_directly_bhops;
 	}
 #endif
@@ -1107,8 +1639,32 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 		} __packed zalg = {
 			.size = cpu_to_le16(sizeof(struct z_erofs_deflate_cfgs)),
 			.z = {
-				.windowbits =
-					cpu_to_le32(ilog2(cfg.c_dict_size)),
+				.windowbits = cpu_to_le32(ilog2(
+					max_dict_size
+						[Z_EROFS_COMPRESSION_DEFLATE])),
+			}
+		};
+
+		bh = erofs_battach(bh, META, sizeof(zalg));
+		if (IS_ERR(bh)) {
+			DBG_BUGON(1);
+			return PTR_ERR(bh);
+		}
+		erofs_mapbh(NULL, bh->block);
+		ret = erofs_dev_write(sbi, &zalg, erofs_btell(bh, false),
+				      sizeof(zalg));
+		bh->op = &erofs_drop_directly_bhops;
+	}
+#ifdef HAVE_LIBZSTD
+	if (sbi->available_compr_algs & (1 << Z_EROFS_COMPRESSION_ZSTD)) {
+		struct {
+			__le16 size;
+			struct z_erofs_zstd_cfgs z;
+		} __packed zalg = {
+			.size = cpu_to_le16(sizeof(struct z_erofs_zstd_cfgs)),
+			.z = {
+				.windowlog =
+					ilog2(max_dict_size[Z_EROFS_COMPRESSION_ZSTD]) - 10,
 			}
 		};
 
@@ -1117,68 +1673,116 @@ static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
 			DBG_BUGON(1);
 			return PTR_ERR(bh);
 		}
-		erofs_mapbh(bh->block);
-		ret = dev_write(sbi, &zalg, erofs_btell(bh, false),
-				sizeof(zalg));
+		erofs_mapbh(NULL, bh->block);
+		ret = erofs_dev_write(sbi, &zalg, erofs_btell(bh, false),
+				      sizeof(zalg));
 		bh->op = &erofs_drop_directly_bhops;
 	}
+#endif
 	return ret;
 }
 
 int z_erofs_compress_init(struct erofs_sb_info *sbi, struct erofs_buffer_head *sb_bh)
 {
-	int i, ret;
+	int i, ret, id;
+	u32 max_dict_size[Z_EROFS_COMPRESSION_MAX] = {};
+	u32 available_compr_algs = 0;
 
-	for (i = 0; cfg.c_compr_alg[i]; ++i) {
+	for (i = 0; cfg.c_compr_opts[i].alg; ++i) {
 		struct erofs_compress *c = &erofs_ccfg[i].handle;
 
-		ret = erofs_compressor_init(sbi, c, cfg.c_compr_alg[i]);
-		if (ret)
-			return ret;
-
-		ret = erofs_compressor_setlevel(c, cfg.c_compr_level[i]);
+		ret = erofs_compressor_init(sbi, c, cfg.c_compr_opts[i].alg,
+					    cfg.c_compr_opts[i].level,
+					    cfg.c_compr_opts[i].dict_size);
 		if (ret)
 			return ret;
 
-		erofs_ccfg[i].algorithmtype =
-			z_erofs_get_compress_algorithm_id(c);
+		id = z_erofs_get_compress_algorithm_id(c);
+		erofs_ccfg[i].algorithmtype = id;
 		erofs_ccfg[i].enable = true;
-		sbi->available_compr_algs |= 1 << erofs_ccfg[i].algorithmtype;
+		available_compr_algs |= 1 << erofs_ccfg[i].algorithmtype;
 		if (erofs_ccfg[i].algorithmtype != Z_EROFS_COMPRESSION_LZ4)
 			erofs_sb_set_compr_cfgs(sbi);
+		if (c->dict_size > max_dict_size[id])
+			max_dict_size[id] = c->dict_size;
 	}
 
 	/*
 	 * if primary algorithm is empty (e.g. compression off),
 	 * clear 0PADDING feature for old kernel compatibility.
 	 */
-	if (!cfg.c_compr_alg[0] ||
-	    (cfg.c_legacy_compress && !strncmp(cfg.c_compr_alg[0], "lz4", 3)))
+	if (!available_compr_algs ||
+	    (cfg.c_legacy_compress && available_compr_algs == 1))
 		erofs_sb_clear_lz4_0padding(sbi);
 
-	if (!cfg.c_compr_alg[0])
+	if (!available_compr_algs)
 		return 0;
 
+	if (!sb_bh) {
+		u32 dalg = available_compr_algs & (~sbi->available_compr_algs);
+
+		if (dalg) {
+			erofs_err("unavailable algorithms 0x%x on incremental builds",
+				  dalg);
+			return -EOPNOTSUPP;
+		}
+		if (available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZ4) &&
+		    sbi->lz4.max_pclusterblks << sbi->blkszbits <
+			cfg.c_mkfs_pclustersize_max) {
+			erofs_err("pclustersize %u is too large on incremental builds",
+				  cfg.c_mkfs_pclustersize_max);
+			return -EOPNOTSUPP;
+		}
+	} else {
+		sbi->available_compr_algs = available_compr_algs;
+	}
+
 	/*
 	 * if big pcluster is enabled, an extra CBLKCNT lcluster index needs
 	 * to be loaded in order to get those compressed block counts.
 	 */
-	if (cfg.c_pclusterblks_max > 1) {
-		if (cfg.c_pclusterblks_max >
-		    Z_EROFS_PCLUSTER_MAX_SIZE / erofs_blksiz(sbi)) {
-			erofs_err("unsupported clusterblks %u (too large)",
-				  cfg.c_pclusterblks_max);
+	if (cfg.c_mkfs_pclustersize_max > erofs_blksiz(sbi)) {
+		if (cfg.c_mkfs_pclustersize_max > Z_EROFS_PCLUSTER_MAX_SIZE) {
+			erofs_err("unsupported pclustersize %u (too large)",
+				  cfg.c_mkfs_pclustersize_max);
 			return -EINVAL;
 		}
 		erofs_sb_set_big_pcluster(sbi);
 	}
-	if (cfg.c_pclusterblks_packed > cfg.c_pclusterblks_max) {
-		erofs_err("invalid physical cluster size for the packed file");
+	if (cfg.c_mkfs_pclustersize_packed > cfg.c_mkfs_pclustersize_max) {
+		erofs_err("invalid pclustersize for the packed file %u",
+			  cfg.c_mkfs_pclustersize_packed);
 		return -EINVAL;
 	}
 
-	if (erofs_sb_has_compr_cfgs(sbi))
-		return z_erofs_build_compr_cfgs(sbi, sb_bh);
+	if (sb_bh && erofs_sb_has_compr_cfgs(sbi)) {
+		ret = z_erofs_build_compr_cfgs(sbi, sb_bh, max_dict_size);
+		if (ret)
+			return ret;
+	}
+
+	z_erofs_mt_enabled = false;
+#ifdef EROFS_MT_ENABLED
+	if (cfg.c_mt_workers >= 1 && (cfg.c_dedupe ||
+				      (cfg.c_fragments && !cfg.c_all_fragments))) {
+		if (cfg.c_dedupe)
+			erofs_warn("multi-threaded dedupe is NOT implemented for now");
+		if (cfg.c_fragments)
+			erofs_warn("multi-threaded fragments is NOT implemented for now");
+		cfg.c_mt_workers = 0;
+	}
+
+	if (cfg.c_mt_workers >= 1) {
+		ret = erofs_alloc_workqueue(&z_erofs_mt_ctrl.wq,
+					    cfg.c_mt_workers,
+					    cfg.c_mt_workers << 2,
+					    z_erofs_mt_wq_tls_alloc,
+					    z_erofs_mt_wq_tls_free);
+		z_erofs_mt_enabled = !ret;
+	}
+	pthread_mutex_init(&g_ictx.mutex, NULL);
+	pthread_cond_init(&g_ictx.cond, NULL);
+#endif
 	return 0;
 }
 
@@ -1186,10 +1790,24 @@ int z_erofs_compress_exit(void)
 {
 	int i, ret;
 
-	for (i = 0; cfg.c_compr_alg[i]; ++i) {
+	for (i = 0; cfg.c_compr_opts[i].alg; ++i) {
 		ret = erofs_compressor_exit(&erofs_ccfg[i].handle);
 		if (ret)
 			return ret;
 	}
+
+	if (z_erofs_mt_enabled) {
+#ifdef EROFS_MT_ENABLED
+		ret = erofs_destroy_workqueue(&z_erofs_mt_ctrl.wq);
+		if (ret)
+			return ret;
+		while (z_erofs_mt_ctrl.idle) {
+			struct erofs_compress_work *tmp =
+				z_erofs_mt_ctrl.idle->next;
+			free(z_erofs_mt_ctrl.idle);
+			z_erofs_mt_ctrl.idle = tmp;
+		}
+#endif
+	}
 	return 0;
 }
diff --git a/lib/compress_hints.c b/lib/compress_hints.c
index afc9f8f..e79bd48 100644
--- a/lib/compress_hints.c
+++ b/lib/compress_hints.c
@@ -55,7 +55,7 @@ bool z_erofs_apply_compress_hints(struct erofs_inode *inode)
 		return true;
 
 	s = erofs_fspath(inode->i_srcpath);
-	pclusterblks = cfg.c_pclusterblks_def;
+	pclusterblks = cfg.c_mkfs_pclustersize_def >> inode->sbi->blkszbits;
 	algorithmtype = 0;
 
 	list_for_each_entry(r, &compress_hints_head, list) {
@@ -125,7 +125,7 @@ int erofs_load_compress_hints(struct erofs_sb_info *sbi)
 		} else {
 			ccfg = atoi(alg);
 			if (ccfg >= EROFS_MAX_COMPR_CFGS ||
-			    !cfg.c_compr_alg[ccfg]) {
+			    !cfg.c_compr_opts[ccfg].alg) {
 				erofs_err("invalid compressing configuration \"%s\" at line %u",
 					  alg, line);
 				ret = -EINVAL;
@@ -136,7 +136,7 @@ int erofs_load_compress_hints(struct erofs_sb_info *sbi)
 		if (pclustersize % erofs_blksiz(sbi)) {
 			erofs_warn("invalid physical clustersize %u, "
 				   "use default pclusterblks %u",
-				   pclustersize, cfg.c_pclusterblks_def);
+				   pclustersize, cfg.c_mkfs_pclustersize_def);
 			continue;
 		}
 		erofs_insert_compress_hints(pattern,
@@ -146,9 +146,10 @@ int erofs_load_compress_hints(struct erofs_sb_info *sbi)
 			max_pclustersize = pclustersize;
 	}
 
-	if (cfg.c_pclusterblks_max * erofs_blksiz(sbi) < max_pclustersize) {
-		cfg.c_pclusterblks_max = max_pclustersize / erofs_blksiz(sbi);
-		erofs_warn("update max pclusterblks to %u", cfg.c_pclusterblks_max);
+	if (cfg.c_mkfs_pclustersize_max < max_pclustersize) {
+		cfg.c_mkfs_pclustersize_max = max_pclustersize;
+		erofs_warn("update max pclustersize to %u",
+			   cfg.c_mkfs_pclustersize_max);
 	}
 out:
 	fclose(f);
diff --git a/lib/compressor.c b/lib/compressor.c
index 93f5617..41f49ff 100644
--- a/lib/compressor.c
+++ b/lib/compressor.c
@@ -2,22 +2,13 @@
 /*
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #include "erofs/internal.h"
 #include "compressor.h"
 #include "erofs/print.h"
 
-#define EROFS_CONFIG_COMPR_DEF_BOUNDARY		(128)
-
-static const struct erofs_algorithm {
-	char *name;
-	const struct erofs_compressor *c;
-	unsigned int id;
-
-	/* its name won't be shown as a supported algorithm */
-	bool optimisor;
-} erofs_algs[] = {
+static const struct erofs_algorithm erofs_algs[] = {
 	{ "lz4",
 #if LZ4_ENABLED
 		&erofs_compressor_lz4,
@@ -46,6 +37,14 @@ static const struct erofs_algorithm {
 	{ "libdeflate", &erofs_compressor_libdeflate,
 	  Z_EROFS_COMPRESSION_DEFLATE, true },
 #endif
+
+	{ "zstd",
+#ifdef HAVE_LIBZSTD
+		&erofs_compressor_libzstd,
+#else
+		NULL,
+#endif
+	  Z_EROFS_COMPRESSION_ZSTD, false },
 };
 
 int z_erofs_get_compress_algorithm_id(const struct erofs_compress *c)
@@ -65,59 +64,29 @@ const char *z_erofs_list_supported_algorithms(int i, unsigned int *mask)
 	return "";
 }
 
-const char *z_erofs_list_available_compressors(int *i)
+const struct erofs_algorithm *z_erofs_list_available_compressors(int *i)
 {
 	for (;*i < ARRAY_SIZE(erofs_algs); ++*i) {
 		if (!erofs_algs[*i].c)
 			continue;
-		return erofs_algs[(*i)++].name;
+		return &erofs_algs[(*i)++];
 	}
 	return NULL;
 }
 
 int erofs_compress_destsize(const struct erofs_compress *c,
 			    const void *src, unsigned int *srcsize,
-			    void *dst, unsigned int dstsize, bool inblocks)
+			    void *dst, unsigned int dstsize)
 {
-	unsigned int uncompressed_capacity, compressed_size;
-	int ret;
-
 	DBG_BUGON(!c->alg);
 	if (!c->alg->c->compress_destsize)
-		return -ENOTSUP;
-
-	uncompressed_capacity = *srcsize;
-	ret = c->alg->c->compress_destsize(c, src, srcsize, dst, dstsize);
-	if (ret < 0)
-		return ret;
-
-	/* XXX: ret >= destsize_alignsize is a temporary hack for ztailpacking */
-	if (inblocks || ret >= c->destsize_alignsize ||
-	    uncompressed_capacity != *srcsize)
-		compressed_size = roundup(ret, c->destsize_alignsize);
-	else
-		compressed_size = ret;
-	DBG_BUGON(c->compress_threshold < 100);
-	/* check if there is enough gains to compress */
-	if (*srcsize <= compressed_size * c->compress_threshold / 100)
-		return -EAGAIN;
-	return ret;
-}
-
-int erofs_compressor_setlevel(struct erofs_compress *c, int compression_level)
-{
-	DBG_BUGON(!c->alg);
-	if (c->alg->c->setlevel)
-		return c->alg->c->setlevel(c, compression_level);
+		return -EOPNOTSUPP;
 
-	if (compression_level >= 0)
-		return -EINVAL;
-	c->compression_level = 0;
-	return 0;
+	return c->alg->c->compress_destsize(c, src, srcsize, dst, dstsize);
 }
 
-int erofs_compressor_init(struct erofs_sb_info *sbi,
-			  struct erofs_compress *c, char *alg_name)
+int erofs_compressor_init(struct erofs_sb_info *sbi, struct erofs_compress *c,
+			  char *alg_name, int compression_level, u32 dict_size)
 {
 	int ret, i;
 
@@ -125,11 +94,8 @@ int erofs_compressor_init(struct erofs_sb_info *sbi,
 
 	/* should be written in "minimum compression ratio * 100" */
 	c->compress_threshold = 100;
-
-	/* optimize for 4k size page */
-	c->destsize_alignsize = erofs_blksiz(sbi);
-	c->destsize_redzone_begin = erofs_blksiz(sbi) - 16;
-	c->destsize_redzone_end = EROFS_CONFIG_COMPR_DEF_BOUNDARY;
+	c->compression_level = -1;
+	c->dict_size = 0;
 
 	if (!alg_name) {
 		c->alg = NULL;
@@ -144,7 +110,36 @@ int erofs_compressor_init(struct erofs_sb_info *sbi,
 		if (!erofs_algs[i].c)
 			continue;
 
+		if (erofs_algs[i].c->setlevel) {
+			ret = erofs_algs[i].c->setlevel(c, compression_level);
+			if (ret) {
+				erofs_err("failed to set compression level %d for %s",
+					  compression_level, alg_name);
+				return ret;
+			}
+		} else if (compression_level >= 0) {
+			erofs_err("compression level %d is not supported for %s",
+				  compression_level, alg_name);
+			return -EINVAL;
+		}
+
+		if (erofs_algs[i].c->setdictsize) {
+			ret = erofs_algs[i].c->setdictsize(c, dict_size);
+			if (ret) {
+				erofs_err("failed to set dict size %u for %s",
+					  dict_size, alg_name);
+				return ret;
+			}
+		} else if (dict_size) {
+			erofs_err("dict size is not supported for %s",
+				  alg_name);
+			return -EINVAL;
+		}
+
 		ret = erofs_algs[i].c->init(c);
+		if (ret)
+			return ret;
+
 		if (!ret) {
 			c->alg = &erofs_algs[i];
 			return 0;
@@ -160,3 +155,9 @@ int erofs_compressor_exit(struct erofs_compress *c)
 		return c->alg->c->exit(c);
 	return 0;
 }
+
+void erofs_compressor_reset(struct erofs_compress *c)
+{
+	if (c->alg && c->alg->c->reset)
+		c->alg->c->reset(c);
+}
diff --git a/lib/compressor.h b/lib/compressor.h
index 9fa01d1..8d322d5 100644
--- a/lib/compressor.h
+++ b/lib/compressor.h
@@ -2,7 +2,7 @@
 /*
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #ifndef __EROFS_LIB_COMPRESSOR_H
 #define __EROFS_LIB_COMPRESSOR_H
@@ -14,17 +14,28 @@ struct erofs_compress;
 struct erofs_compressor {
 	int default_level;
 	int best_level;
+	u32 default_dictsize;
+	u32 max_dictsize;
 
 	int (*init)(struct erofs_compress *c);
 	int (*exit)(struct erofs_compress *c);
+	void (*reset)(struct erofs_compress *c);
 	int (*setlevel)(struct erofs_compress *c, int compression_level);
+	int (*setdictsize)(struct erofs_compress *c, u32 dict_size);
 
 	int (*compress_destsize)(const struct erofs_compress *c,
 				 const void *src, unsigned int *srcsize,
 				 void *dst, unsigned int dstsize);
 };
 
-struct erofs_algorithm;
+struct erofs_algorithm {
+	char *name;
+	const struct erofs_compressor *c;
+	unsigned int id;
+
+	/* its name won't be shown as a supported algorithm */
+	bool optimisor;
+};
 
 struct erofs_compress {
 	struct erofs_sb_info *sbi;
@@ -32,11 +43,7 @@ struct erofs_compress {
 
 	unsigned int compress_threshold;
 	unsigned int compression_level;
-
-	/* *_destsize specific */
-	unsigned int destsize_alignsize;
-	unsigned int destsize_redzone_begin;
-	unsigned int destsize_redzone_end;
+	unsigned int dict_size;
 
 	void *private_data;
 };
@@ -47,15 +54,16 @@ extern const struct erofs_compressor erofs_compressor_lz4hc;
 extern const struct erofs_compressor erofs_compressor_lzma;
 extern const struct erofs_compressor erofs_compressor_deflate;
 extern const struct erofs_compressor erofs_compressor_libdeflate;
+extern const struct erofs_compressor erofs_compressor_libzstd;
 
 int z_erofs_get_compress_algorithm_id(const struct erofs_compress *c);
 int erofs_compress_destsize(const struct erofs_compress *c,
 			    const void *src, unsigned int *srcsize,
-			    void *dst, unsigned int dstsize, bool inblocks);
+			    void *dst, unsigned int dstsize);
 
-int erofs_compressor_setlevel(struct erofs_compress *c, int compression_level);
-int erofs_compressor_init(struct erofs_sb_info *sbi,
-		struct erofs_compress *c, char *alg_name);
+int erofs_compressor_init(struct erofs_sb_info *sbi, struct erofs_compress *c,
+			  char *alg_name, int compression_level, u32 dict_size);
 int erofs_compressor_exit(struct erofs_compress *c);
+void erofs_compressor_reset(struct erofs_compress *c);
 
 #endif
diff --git a/lib/compressor_deflate.c b/lib/compressor_deflate.c
index 4e5902e..e482224 100644
--- a/lib/compressor_deflate.c
+++ b/lib/compressor_deflate.c
@@ -7,6 +7,7 @@
 #include "erofs/print.h"
 #include "erofs/config.h"
 #include "compressor.h"
+#include "erofs/atomic.h"
 
 void *kite_deflate_init(int level, unsigned int dict_size);
 void kite_deflate_end(void *s);
@@ -36,41 +37,60 @@ static int compressor_deflate_exit(struct erofs_compress *c)
 
 static int compressor_deflate_init(struct erofs_compress *c)
 {
-	c->private_data = NULL;
+	static erofs_atomic_bool_t __warnonce;
 
-	erofs_warn("EXPERIMENTAL DEFLATE algorithm in use. Use at your own risk!");
-	erofs_warn("*Carefully* check filesystem data correctness to avoid corruption!");
-	erofs_warn("Please send a report to <linux-erofs@lists.ozlabs.org> if something is wrong.");
+	if (c->private_data) {
+		kite_deflate_end(c->private_data);
+		c->private_data = NULL;
+	}
+	c->private_data = kite_deflate_init(c->compression_level, c->dict_size);
+	if (IS_ERR_VALUE(c->private_data))
+		return PTR_ERR(c->private_data);
+
+	if (!erofs_atomic_test_and_set(&__warnonce)) {
+		erofs_warn("EXPERIMENTAL DEFLATE algorithm in use. Use at your own risk!");
+		erofs_warn("*Carefully* check filesystem data correctness to avoid corruption!");
+		erofs_warn("Please send a report to <linux-erofs@lists.ozlabs.org> if something is wrong.");
+	}
 	return 0;
 }
 
 static int erofs_compressor_deflate_setlevel(struct erofs_compress *c,
 					     int compression_level)
 {
-	void *s;
-
-	if (c->private_data) {
-		kite_deflate_end(c->private_data);
-		c->private_data = NULL;
-	}
-
 	if (compression_level < 0)
 		compression_level = erofs_compressor_deflate.default_level;
 
-	s = kite_deflate_init(compression_level, cfg.c_dict_size);
-	if (IS_ERR(s))
-		return PTR_ERR(s);
-
-	c->private_data = s;
+	if (compression_level > erofs_compressor_deflate.best_level) {
+		erofs_err("invalid compression level %d", compression_level);
+		return -EINVAL;
+	}
 	c->compression_level = compression_level;
 	return 0;
 }
 
+static int erofs_compressor_deflate_setdictsize(struct erofs_compress *c,
+						u32 dict_size)
+{
+	if (!dict_size)
+		dict_size = erofs_compressor_deflate.default_dictsize;
+
+	if (dict_size > erofs_compressor_deflate.max_dictsize) {
+		erofs_err("dictionary size %u is too large", dict_size);
+		return -EINVAL;
+	}
+	c->dict_size = dict_size;
+	return 0;
+}
+
 const struct erofs_compressor erofs_compressor_deflate = {
 	.default_level = 1,
 	.best_level = 9,
+	.default_dictsize = 1 << 15,
+	.max_dictsize = 1 << 15,
 	.init = compressor_deflate_init,
 	.exit = compressor_deflate_exit,
 	.setlevel = erofs_compressor_deflate_setlevel,
+	.setdictsize = erofs_compressor_deflate_setdictsize,
 	.compress_destsize = deflate_compress_destsize,
 };
diff --git a/lib/compressor_libdeflate.c b/lib/compressor_libdeflate.c
index c0b019a..aaf4684 100644
--- a/lib/compressor_libdeflate.c
+++ b/lib/compressor_libdeflate.c
@@ -3,21 +3,28 @@
 #include "erofs/print.h"
 #include "erofs/config.h"
 #include <libdeflate.h>
+#include <stdlib.h>
 #include "compressor.h"
+#include "erofs/atomic.h"
+
+struct erofs_libdeflate_context {
+	struct libdeflate_compressor *strm;
+	size_t last_uncompressed_size;
+};
 
 static int libdeflate_compress_destsize(const struct erofs_compress *c,
 				        const void *src, unsigned int *srcsize,
 				        void *dst, unsigned int dstsize)
 {
-	static size_t last_uncompressed_size = 0;
+	struct erofs_libdeflate_context *ctx = c->private_data;
 	size_t l = 0; /* largest input that fits so far */
 	size_t l_csize = 0;
 	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
 	size_t m;
 	u8 tmpbuf[dstsize + 9];
 
-	if (last_uncompressed_size)
-		m = last_uncompressed_size * 15 / 16;
+	if (ctx->last_uncompressed_size)
+		m = ctx->last_uncompressed_size * 15 / 16;
 	else
 		m = dstsize * 4;
 	for (;;) {
@@ -26,7 +33,7 @@ static int libdeflate_compress_destsize(const struct erofs_compress *c,
 		m = max(m, l + 1);
 		m = min(m, r - 1);
 
-		csize = libdeflate_deflate_compress(c->private_data, src, m,
+		csize = libdeflate_deflate_compress(ctx->strm, src, m,
 						    tmpbuf, dstsize + 9);
 		/*printf("Tried %zu => %zu\n", m, csize);*/
 		if (csize > 0 && csize <= dstsize) {
@@ -67,37 +74,58 @@ static int libdeflate_compress_destsize(const struct erofs_compress *c,
 
 	/*printf("Choosing %zu => %zu\n", l, l_csize);*/
 	*srcsize = l;
-	last_uncompressed_size = l;
+	ctx->last_uncompressed_size = l;
 	return l_csize;
 }
 
 static int compressor_libdeflate_exit(struct erofs_compress *c)
 {
-	if (!c->private_data)
-		return -EINVAL;
+	struct erofs_libdeflate_context *ctx = c->private_data;
 
-	libdeflate_free_compressor(c->private_data);
+	if (!ctx)
+		return -EINVAL;
+	libdeflate_free_compressor(ctx->strm);
+	free(ctx);
 	return 0;
 }
 
 static int compressor_libdeflate_init(struct erofs_compress *c)
 {
-	c->private_data = NULL;
+	static erofs_atomic_bool_t __warnonce;
+	struct erofs_libdeflate_context *ctx;
 
-	erofs_warn("EXPERIMENTAL libdeflate compressor in use. Use at your own risk!");
+	DBG_BUGON(c->private_data);
+	ctx = calloc(1, sizeof(struct erofs_libdeflate_context));
+	if (!ctx)
+		return -ENOMEM;
+	ctx->strm = libdeflate_alloc_compressor(c->compression_level);
+	if (!ctx->strm) {
+		free(ctx);
+		return -ENOMEM;
+	}
+	c->private_data = ctx;
+	if (!erofs_atomic_test_and_set(&__warnonce))
+		erofs_warn("EXPERIMENTAL libdeflate compressor in use. Use at your own risk!");
 	return 0;
 }
 
+static void compressor_libdeflate_reset(struct erofs_compress *c)
+{
+	struct erofs_libdeflate_context *ctx = c->private_data;
+
+	ctx->last_uncompressed_size = 0;
+}
+
 static int erofs_compressor_libdeflate_setlevel(struct erofs_compress *c,
 						int compression_level)
 {
 	if (compression_level < 0)
-		compression_level = erofs_compressor_deflate.default_level;
+		compression_level = erofs_compressor_libdeflate.default_level;
 
-	libdeflate_free_compressor(c->private_data);
-	c->private_data = libdeflate_alloc_compressor(compression_level);
-	if (!c->private_data)
-		return -ENOMEM;
+	if (compression_level > erofs_compressor_libdeflate.best_level) {
+		erofs_err("invalid compression level %d", compression_level);
+		return -EINVAL;
+	}
 	c->compression_level = compression_level;
 	return 0;
 }
@@ -107,6 +135,7 @@ const struct erofs_compressor erofs_compressor_libdeflate = {
 	.best_level = 12,
 	.init = compressor_libdeflate_init,
 	.exit = compressor_libdeflate_exit,
+	.reset = compressor_libdeflate_reset,
 	.setlevel = erofs_compressor_libdeflate_setlevel,
 	.compress_destsize = libdeflate_compress_destsize,
 };
diff --git a/lib/compressor_liblzma.c b/lib/compressor_liblzma.c
index 0ed6f23..d609a28 100644
--- a/lib/compressor_liblzma.c
+++ b/lib/compressor_liblzma.c
@@ -9,6 +9,7 @@
 #include "erofs/config.h"
 #include "erofs/print.h"
 #include "erofs/internal.h"
+#include "erofs/atomic.h"
 #include "compressor.h"
 
 struct erofs_liblzma_context {
@@ -55,55 +56,72 @@ static int erofs_compressor_liblzma_exit(struct erofs_compress *c)
 static int erofs_compressor_liblzma_setlevel(struct erofs_compress *c,
 					     int compression_level)
 {
-	struct erofs_liblzma_context *ctx = c->private_data;
-	u32 preset;
-
 	if (compression_level < 0)
-		preset = LZMA_PRESET_DEFAULT;
-	else if (compression_level >= 100)
-		preset = (compression_level - 100) | LZMA_PRESET_EXTREME;
-	else
-		preset = compression_level;
+		compression_level = erofs_compressor_lzma.default_level;
 
-	if (lzma_lzma_preset(&ctx->opt, preset))
+	if (compression_level > erofs_compressor_lzma.best_level) {
+		erofs_err("invalid compression level %d", compression_level);
 		return -EINVAL;
+	}
+	c->compression_level = compression_level;
+	return 0;
+}
 
-	/* XXX: temporary hack */
-	if (cfg.c_dict_size) {
-		if (cfg.c_dict_size > Z_EROFS_LZMA_MAX_DICT_SIZE) {
-			erofs_err("dict size %u is too large", cfg.c_dict_size);
-			return -EINVAL;
+static int erofs_compressor_liblzma_setdictsize(struct erofs_compress *c,
+						u32 dict_size)
+{
+	if (!dict_size) {
+		if (erofs_compressor_lzma.default_dictsize) {
+			dict_size = erofs_compressor_lzma.default_dictsize;
+		} else {
+			dict_size = min_t(u32, Z_EROFS_LZMA_MAX_DICT_SIZE,
+					  cfg.c_mkfs_pclustersize_max << 3);
+			if (dict_size < 32768)
+				dict_size = 32768;
 		}
-		ctx->opt.dict_size = cfg.c_dict_size;
-	} else {
-		if (ctx->opt.dict_size > Z_EROFS_LZMA_MAX_DICT_SIZE)
-			ctx->opt.dict_size = Z_EROFS_LZMA_MAX_DICT_SIZE;
-		cfg.c_dict_size = ctx->opt.dict_size;
 	}
-	c->compression_level = compression_level;
+
+	if (dict_size > Z_EROFS_LZMA_MAX_DICT_SIZE || dict_size < 4096) {
+		erofs_err("invalid dictionary size %u", dict_size);
+		return -EINVAL;
+	}
+	c->dict_size = dict_size;
 	return 0;
 }
 
 static int erofs_compressor_liblzma_init(struct erofs_compress *c)
 {
 	struct erofs_liblzma_context *ctx;
+	u32 preset;
 
 	ctx = malloc(sizeof(*ctx));
 	if (!ctx)
 		return -ENOMEM;
 	ctx->strm = (lzma_stream)LZMA_STREAM_INIT;
+
+	if (c->compression_level < 0)
+		preset = LZMA_PRESET_DEFAULT;
+	else if (c->compression_level >= 100)
+		preset = (c->compression_level - 100) | LZMA_PRESET_EXTREME;
+	else
+		preset = c->compression_level;
+
+	if (lzma_lzma_preset(&ctx->opt, preset))
+		return -EINVAL;
+	ctx->opt.dict_size = c->dict_size;
+
 	c->private_data = ctx;
-	erofs_warn("EXPERIMENTAL MicroLZMA feature in use. Use at your own risk!");
-	erofs_warn("Note that it may take more time since the compressor is still single-threaded for now.");
 	return 0;
 }
 
 const struct erofs_compressor erofs_compressor_lzma = {
 	.default_level = LZMA_PRESET_DEFAULT,
 	.best_level = 109,
+	.max_dictsize = Z_EROFS_LZMA_MAX_DICT_SIZE,
 	.init = erofs_compressor_liblzma_init,
 	.exit = erofs_compressor_liblzma_exit,
 	.setlevel = erofs_compressor_liblzma_setlevel,
+	.setdictsize = erofs_compressor_liblzma_setdictsize,
 	.compress_destsize = erofs_liblzma_compress_destsize,
 };
 #endif
diff --git a/lib/compressor_libzstd.c b/lib/compressor_libzstd.c
new file mode 100644
index 0000000..223806e
--- /dev/null
+++ b/lib/compressor_libzstd.c
@@ -0,0 +1,143 @@
+// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
+#include "erofs/internal.h"
+#include "erofs/print.h"
+#include "erofs/config.h"
+#include <zstd.h>
+#include <zstd_errors.h>
+#include <alloca.h>
+#include "compressor.h"
+#include "erofs/atomic.h"
+
+static int libzstd_compress_destsize(const struct erofs_compress *c,
+				     const void *src, unsigned int *srcsize,
+				     void *dst, unsigned int dstsize)
+{
+	ZSTD_CCtx *cctx = c->private_data;
+	size_t l = 0;		/* largest input that fits so far */
+	size_t l_csize = 0;
+	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
+	size_t m;
+	u8 *fitblk_buffer = alloca(dstsize + 32);
+
+	m = dstsize * 4;
+	for (;;) {
+		size_t csize;
+
+		m = max(m, l + 1);
+		m = min(m, r - 1);
+
+		csize = ZSTD_compress2(cctx, fitblk_buffer,
+				       dstsize + 32, src, m);
+		if (ZSTD_isError(csize)) {
+			if (ZSTD_getErrorCode(csize) == ZSTD_error_dstSize_tooSmall)
+				goto doesnt_fit;
+			return -EFAULT;
+		}
+
+		if (csize > 0 && csize <= dstsize) {
+			/* Fits */
+			memcpy(dst, fitblk_buffer, csize);
+			l = m;
+			l_csize = csize;
+			if (r <= l + 1 || csize + 1 >= dstsize)
+				break;
+			/*
+			 * Estimate needed input prefix size based on current
+			 * compression ratio.
+			 */
+			m = (dstsize * m) / csize;
+		} else {
+doesnt_fit:
+			/* Doesn't fit */
+			r = m;
+			if (r <= l + 1)
+				break;
+			m = (l + r) / 2;
+		}
+	}
+	*srcsize = l;
+	return l_csize;
+}
+
+static int compressor_libzstd_exit(struct erofs_compress *c)
+{
+	if (!c->private_data)
+		return -EINVAL;
+	ZSTD_freeCCtx(c->private_data);
+	return 0;
+}
+
+static int erofs_compressor_libzstd_setlevel(struct erofs_compress *c,
+					     int compression_level)
+{
+	if (compression_level > erofs_compressor_libzstd.best_level) {
+		erofs_err("invalid compression level %d", compression_level);
+		return -EINVAL;
+	}
+	c->compression_level = compression_level;
+	return 0;
+}
+
+static int erofs_compressor_libzstd_setdictsize(struct erofs_compress *c,
+						u32 dict_size)
+{
+	if (!dict_size) {
+		if (erofs_compressor_libzstd.default_dictsize) {
+			dict_size = erofs_compressor_libzstd.default_dictsize;
+		} else {
+			dict_size = min_t(u32, Z_EROFS_ZSTD_MAX_DICT_SIZE,
+					  cfg.c_mkfs_pclustersize_max << 3);
+			dict_size = 1 << ilog2(dict_size);
+		}
+	}
+	if (dict_size != 1 << ilog2(dict_size) ||
+	    dict_size > Z_EROFS_ZSTD_MAX_DICT_SIZE) {
+		erofs_err("invalid dictionary size %u", dict_size);
+		return -EINVAL;
+	}
+	c->dict_size = dict_size;
+	return 0;
+}
+
+static int compressor_libzstd_init(struct erofs_compress *c)
+{
+	static erofs_atomic_bool_t __warnonce;
+	ZSTD_CCtx *cctx = c->private_data;
+	size_t err;
+
+	ZSTD_freeCCtx(cctx);
+	cctx = ZSTD_createCCtx();
+	if (!cctx)
+		return -ENOMEM;
+
+	err = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, c->compression_level);
+	if (ZSTD_isError(err)) {
+		erofs_err("failed to set compression level: %s",
+			  ZSTD_getErrorName(err));
+		return -EINVAL;
+	}
+	err = ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, ilog2(c->dict_size));
+	if (ZSTD_isError(err)) {
+		erofs_err("failed to set window log: %s", ZSTD_getErrorName(err));
+		return -EINVAL;
+	}
+	c->private_data = cctx;
+
+	if (!erofs_atomic_test_and_set(&__warnonce)) {
+		erofs_warn("EXPERIMENTAL libzstd compressor in use. Note that `fitblk` isn't supported by upstream zstd for now.");
+		erofs_warn("Therefore it will takes more time in order to get the optimal result.");
+		erofs_info("You could clarify further needs in zstd repository <https://github.com/facebook/zstd/issues> for reference too.");
+	}
+	return 0;
+}
+
+const struct erofs_compressor erofs_compressor_libzstd = {
+	.default_level = ZSTD_CLEVEL_DEFAULT,
+	.best_level = 22,
+	.max_dictsize = Z_EROFS_ZSTD_MAX_DICT_SIZE,
+	.init = compressor_libzstd_init,
+	.exit = compressor_libzstd_exit,
+	.setlevel = erofs_compressor_libzstd_setlevel,
+	.setdictsize = erofs_compressor_libzstd_setdictsize,
+	.compress_destsize = libzstd_compress_destsize,
+};
diff --git a/lib/compressor_lz4.c b/lib/compressor_lz4.c
index 6677693..f3d88b0 100644
--- a/lib/compressor_lz4.c
+++ b/lib/compressor_lz4.c
@@ -2,7 +2,7 @@
 /*
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #include <lz4.h>
 #include "erofs/internal.h"
@@ -32,13 +32,12 @@ static int compressor_lz4_exit(struct erofs_compress *c)
 
 static int compressor_lz4_init(struct erofs_compress *c)
 {
-	c->sbi->lz4_max_distance = LZ4_DISTANCE_MAX;
+	c->sbi->lz4.max_distance = max_t(u16, c->sbi->lz4.max_distance,
+					 LZ4_DISTANCE_MAX);
 	return 0;
 }
 
 const struct erofs_compressor erofs_compressor_lz4 = {
-	.default_level = 0,
-	.best_level = 0,
 	.init = compressor_lz4_init,
 	.exit = compressor_lz4_exit,
 	.compress_destsize = lz4_compress_destsize,
diff --git a/lib/compressor_lz4hc.c b/lib/compressor_lz4hc.c
index b410e15..1e1ccc7 100644
--- a/lib/compressor_lz4hc.c
+++ b/lib/compressor_lz4hc.c
@@ -2,11 +2,12 @@
 /*
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  */
 #define LZ4_HC_STATIC_LINKING_ONLY (1)
 #include <lz4hc.h>
 #include "erofs/internal.h"
+#include "erofs/print.h"
 #include "compressor.h"
 
 #ifndef LZ4_DISTANCE_MAX	/* history window size */
@@ -42,15 +43,18 @@ static int compressor_lz4hc_init(struct erofs_compress *c)
 	if (!c->private_data)
 		return -ENOMEM;
 
-	c->sbi->lz4_max_distance = LZ4_DISTANCE_MAX;
+	c->sbi->lz4.max_distance = max_t(u16, c->sbi->lz4.max_distance,
+					 LZ4_DISTANCE_MAX);
 	return 0;
 }
 
 static int compressor_lz4hc_setlevel(struct erofs_compress *c,
 				     int compression_level)
 {
-	if (compression_level > LZ4HC_CLEVEL_MAX)
+	if (compression_level > erofs_compressor_lz4hc.best_level) {
+		erofs_err("invalid compression level %d", compression_level);
 		return -EINVAL;
+	}
 
 	c->compression_level = compression_level < 0 ?
 		LZ4HC_CLEVEL_DEFAULT : compression_level;
diff --git a/lib/config.c b/lib/config.c
index 2f3df37..8585c85 100644
--- a/lib/config.c
+++ b/lib/config.c
@@ -7,15 +7,20 @@
 #include <string.h>
 #include <stdlib.h>
 #include <stdarg.h>
+#include <unistd.h>
 #include "erofs/print.h"
 #include "erofs/internal.h"
 #include "liberofs_private.h"
 #ifdef HAVE_SYS_IOCTL_H
 #include <sys/ioctl.h>
 #endif
+#ifdef HAVE_UNISTD_H
+#include <unistd.h>
+#endif
 
 struct erofs_configure cfg;
-struct erofs_sb_info sbi;
+struct erofs_sb_info g_sbi;
+bool erofs_stdout_tty;
 
 void erofs_init_configure(void)
 {
@@ -30,9 +35,8 @@ void erofs_init_configure(void)
 	cfg.c_unix_timestamp = -1;
 	cfg.c_uid = -1;
 	cfg.c_gid = -1;
-	cfg.c_pclusterblks_max = 1;
-	cfg.c_pclusterblks_def = 1;
 	cfg.c_max_decompressed_extent_bytes = -1;
+	erofs_stdout_tty = isatty(STDOUT_FILENO);
 }
 
 void erofs_show_config(void)
@@ -48,12 +52,23 @@ void erofs_show_config(void)
 
 void erofs_exit_configure(void)
 {
+	int i;
+
 #ifdef HAVE_LIBSELINUX
 	if (cfg.sehnd)
 		selabel_close(cfg.sehnd);
 #endif
 	if (cfg.c_img_path)
 		free(cfg.c_img_path);
+	if (cfg.c_src_path)
+		free(cfg.c_src_path);
+	for (i = 0; i < EROFS_MAX_COMPR_CFGS && cfg.c_compr_opts[i].alg; i++)
+		free(cfg.c_compr_opts[i].alg);
+}
+
+struct erofs_configure *erofs_get_configure()
+{
+	return &cfg;
 }
 
 static unsigned int fullpath_prefix;	/* root directory prefix length */
@@ -101,6 +116,9 @@ char *erofs_trim_for_progressinfo(const char *str, int placeholder)
 {
 	int col, len;
 
+	if (!erofs_stdout_tty) {
+		return strdup(str);
+	} else {
 #ifdef GWINSZ_IN_SYS_IOCTL
 	struct winsize winsize;
 	if(ioctl(1, TIOCGWINSZ, &winsize) >= 0 &&
@@ -108,7 +126,8 @@ char *erofs_trim_for_progressinfo(const char *str, int placeholder)
 		col = winsize.ws_col;
 	else
 #endif
-		col = 80;
+			col = 80;
+	}
 
 	if (col <= placeholder)
 		return strdup("");
@@ -133,7 +152,7 @@ void erofs_msg(int dbglv, const char *fmt, ...)
 	FILE *f = dbglv >= EROFS_ERR ? stderr : stdout;
 
 	if (__erofs_is_progressmsg) {
-		fputc('\n', f);
+		fputc('\n', stdout);
 		__erofs_is_progressmsg = false;
 	}
 	va_start(ap, fmt);
@@ -153,7 +172,21 @@ void erofs_update_progressinfo(const char *fmt, ...)
 	vsprintf(msg, fmt, ap);
 	va_end(ap);
 
-	printf("\r\033[K%s", msg);
-	__erofs_is_progressmsg = true;
-	fflush(stdout);
+	if (erofs_stdout_tty) {
+		printf("\r\033[K%s", msg);
+		__erofs_is_progressmsg = true;
+		fflush(stdout);
+		return;
+	}
+	fputs(msg, stdout);
+	fputc('\n', stdout);
+}
+
+unsigned int erofs_get_available_processors(void)
+{
+#if defined(HAVE_UNISTD_H) && defined(HAVE_SYSCONF)
+	return sysconf(_SC_NPROCESSORS_ONLN);
+#else
+	return 0;
+#endif
 }
diff --git a/lib/data.c b/lib/data.c
index a87053f..f37f8f0 100644
--- a/lib/data.c
+++ b/lib/data.c
@@ -6,7 +6,6 @@
 #include <stdlib.h>
 #include "erofs/print.h"
 #include "erofs/internal.h"
-#include "erofs/io.h"
 #include "erofs/trace.h"
 #include "erofs/decompress.h"
 
@@ -95,7 +94,7 @@ int erofs_map_blocks(struct erofs_inode *inode,
 	pos = roundup(erofs_iloc(vi) + vi->inode_isize +
 		      vi->xattr_isize, unit) + unit * chunknr;
 
-	err = blk_read(sbi, 0, buf, erofs_blknr(sbi, pos), 1);
+	err = erofs_blk_read(sbi, 0, buf, erofs_blknr(sbi, pos), 1);
 	if (err < 0)
 		return -EIO;
 
@@ -176,7 +175,7 @@ int erofs_read_one_data(struct erofs_inode *inode, struct erofs_map_blocks *map,
 	if (ret)
 		return ret;
 
-	ret = dev_read(sbi, mdev.m_deviceid, buffer, mdev.m_pa + offset, len);
+	ret = erofs_dev_read(sbi, mdev.m_deviceid, buffer, mdev.m_pa + offset, len);
 	if (ret < 0)
 		return -EIO;
 	return 0;
@@ -266,7 +265,7 @@ int z_erofs_read_one_data(struct erofs_inode *inode,
 		return ret;
 	}
 
-	ret = dev_read(sbi, mdev.m_deviceid, raw, mdev.m_pa, map->m_plen);
+	ret = erofs_dev_read(sbi, mdev.m_deviceid, raw, mdev.m_pa, map->m_plen);
 	if (ret < 0)
 		return ret;
 
@@ -338,12 +337,15 @@ static int z_erofs_read_data(struct erofs_inode *inode, char *buffer,
 		}
 
 		if (map.m_plen > bufsize) {
+			char *newraw;
+
 			bufsize = map.m_plen;
-			raw = realloc(raw, bufsize);
-			if (!raw) {
+			newraw = realloc(raw, bufsize);
+			if (!newraw) {
 				ret = -ENOMEM;
 				break;
 			}
+			raw = newraw;
 		}
 
 		ret = z_erofs_read_one_data(inode, &map, raw,
@@ -417,10 +419,10 @@ static void *erofs_read_metadata_bdi(struct erofs_sb_info *sbi,
 	u8 data[EROFS_MAX_BLOCK_SIZE];
 
 	*offset = round_up(*offset, 4);
-	ret = blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
+	ret = erofs_blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
 	if (ret)
 		return ERR_PTR(ret);
-	len = le16_to_cpu(*(__le16 *)&data[erofs_blkoff(sbi, *offset)]);
+	len = le16_to_cpu(*(__le16 *)(data + erofs_blkoff(sbi, *offset)));
 	if (!len)
 		return ERR_PTR(-EFSCORRUPTED);
 
@@ -433,7 +435,7 @@ static void *erofs_read_metadata_bdi(struct erofs_sb_info *sbi,
 	for (i = 0; i < len; i += cnt) {
 		cnt = min_t(int, erofs_blksiz(sbi) - erofs_blkoff(sbi, *offset),
 			    len - i);
-		ret = blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
+		ret = erofs_blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
 		if (ret) {
 			free(buffer);
 			return ERR_PTR(ret);
diff --git a/lib/decompress.c b/lib/decompress.c
index fe8a40c..3f553a8 100644
--- a/lib/decompress.c
+++ b/lib/decompress.c
@@ -9,49 +9,285 @@
 #include "erofs/err.h"
 #include "erofs/print.h"
 
+static unsigned int z_erofs_fixup_insize(const u8 *padbuf, unsigned int padbufsize)
+{
+	unsigned int inputmargin;
+
+	for (inputmargin = 0; inputmargin < padbufsize &&
+	     !padbuf[inputmargin]; ++inputmargin);
+	return inputmargin;
+}
+
+#ifdef HAVE_LIBZSTD
+#include <zstd.h>
+#include <zstd_errors.h>
+
+/* also a very preliminary userspace version */
+static int z_erofs_decompress_zstd(struct z_erofs_decompress_req *rq)
+{
+	int ret = 0;
+	char *dest = rq->out;
+	char *src = rq->in;
+	char *buff = NULL;
+	unsigned int inputmargin = 0;
+	unsigned long long total;
+
+	inputmargin = z_erofs_fixup_insize((u8 *)src, rq->inputsize);
+	if (inputmargin >= rq->inputsize)
+		return -EFSCORRUPTED;
+
+#ifdef HAVE_ZSTD_GETFRAMECONTENTSIZE
+	total = ZSTD_getFrameContentSize(src + inputmargin,
+					 rq->inputsize - inputmargin);
+	if (total == ZSTD_CONTENTSIZE_UNKNOWN ||
+	    total == ZSTD_CONTENTSIZE_ERROR)
+		return -EFSCORRUPTED;
+#else
+	total = ZSTD_getDecompressedSize(src + inputmargin,
+					 rq->inputsize - inputmargin);
+#endif
+	if (rq->decodedskip || total != rq->decodedlength) {
+		buff = malloc(total);
+		if (!buff)
+			return -ENOMEM;
+		dest = buff;
+	}
+
+	ret = ZSTD_decompress(dest, total,
+			      src + inputmargin, rq->inputsize - inputmargin);
+	if (ZSTD_isError(ret)) {
+		erofs_err("ZSTD decompress failed %d: %s", ZSTD_getErrorCode(ret),
+			  ZSTD_getErrorName(ret));
+		ret = -EIO;
+		goto out;
+	}
+
+	if (ret != (int)total) {
+		erofs_err("ZSTD decompress length mismatch %d, expected %d",
+			  ret, total);
+		goto out;
+	}
+	if (rq->decodedskip || total != rq->decodedlength)
+		memcpy(rq->out, dest + rq->decodedskip,
+		       rq->decodedlength - rq->decodedskip);
+out:
+	if (buff)
+		free(buff);
+	return ret;
+}
+#endif
+
+#ifdef HAVE_QPL
+#include <qpl/qpl.h>
+
+struct z_erofs_qpl_job {
+	struct z_erofs_qpl_job *next;
+	u8 job[];
+};
+static struct z_erofs_qpl_job *z_erofs_qpl_jobs;
+static unsigned int z_erofs_qpl_reclaim_quot;
+#ifdef HAVE_PTHREAD_H
+static pthread_mutex_t z_erofs_qpl_mutex;
+#endif
+
+int z_erofs_load_deflate_config(struct erofs_sb_info *sbi,
+				struct erofs_super_block *dsb, void *data, int size)
+{
+	struct z_erofs_deflate_cfgs *dfl = data;
+	static erofs_atomic_bool_t inited;
+
+	if (!dfl || size < sizeof(struct z_erofs_deflate_cfgs)) {
+		erofs_err("invalid deflate cfgs, size=%u", size);
+		return -EINVAL;
+	}
+
+	/*
+	 * In Intel QPL, decompression is supported for DEFLATE streams where
+	 * the size of the history buffer is no more than 4 KiB, otherwise
+	 * QPL_STS_BAD_DIST_ERR code is returned.
+	 */
+	sbi->useqpl = (dfl->windowbits <= 12);
+	if (sbi->useqpl) {
+		if (!erofs_atomic_test_and_set(&inited))
+			z_erofs_qpl_reclaim_quot = erofs_get_available_processors();
+		erofs_info("Intel QPL will be used for DEFLATE decompression");
+	}
+	return 0;
+}
+
+static qpl_job *z_erofs_qpl_get_job(void)
+{
+	qpl_path_t execution_path = qpl_path_auto;
+	struct z_erofs_qpl_job *job;
+	int32_t jobsize = 0;
+	qpl_status status;
+
+#ifdef HAVE_PTHREAD_H
+	pthread_mutex_lock(&z_erofs_qpl_mutex);
+#endif
+	job = z_erofs_qpl_jobs;
+	if (job)
+		z_erofs_qpl_jobs = job->next;
+#ifdef HAVE_PTHREAD_H
+	pthread_mutex_unlock(&z_erofs_qpl_mutex);
+#endif
+
+	if (!job) {
+		status = qpl_get_job_size(execution_path, &jobsize);
+		if (status != QPL_STS_OK) {
+			erofs_err("failed to get job size: %d", status);
+			return ERR_PTR(-EOPNOTSUPP);
+		}
+
+		job = malloc(jobsize + sizeof(struct z_erofs_qpl_job));
+		if (!job)
+			return ERR_PTR(-ENOMEM);
+
+		status = qpl_init_job(execution_path, (qpl_job *)job->job);
+		if (status != QPL_STS_OK) {
+			erofs_err("failed to initialize job: %d", status);
+			return ERR_PTR(-EOPNOTSUPP);
+		}
+		erofs_atomic_dec_return(&z_erofs_qpl_reclaim_quot);
+	}
+	return (qpl_job *)job->job;
+}
+
+static bool z_erofs_qpl_put_job(qpl_job *qjob)
+{
+	struct z_erofs_qpl_job *job =
+		container_of((void *)qjob, struct z_erofs_qpl_job, job);
+
+	if (erofs_atomic_inc_return(&z_erofs_qpl_reclaim_quot) <= 0) {
+		qpl_status status = qpl_fini_job(qjob);
+
+		free(job);
+		if (status != QPL_STS_OK)
+			erofs_err("failed to finalize job: %d", status);
+		return status == QPL_STS_OK;
+	}
+#ifdef HAVE_PTHREAD_H
+	pthread_mutex_lock(&z_erofs_qpl_mutex);
+#endif
+	job->next = z_erofs_qpl_jobs;
+	z_erofs_qpl_jobs = job;
+#ifdef HAVE_PTHREAD_H
+	pthread_mutex_unlock(&z_erofs_qpl_mutex);
+#endif
+	return true;
+}
+
+static int z_erofs_decompress_qpl(struct z_erofs_decompress_req *rq)
+{
+	u8 *dest = (u8 *)rq->out;
+	u8 *src = (u8 *)rq->in;
+	u8 *buff = NULL;
+	unsigned int inputmargin;
+	qpl_status status;
+	qpl_job *job;
+	int ret;
+
+	job = z_erofs_qpl_get_job();
+	if (IS_ERR(job))
+		return PTR_ERR(job);
+
+	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
+	if (inputmargin >= rq->inputsize)
+		return -EFSCORRUPTED;
+
+	if (rq->decodedskip) {
+		buff = malloc(rq->decodedlength);
+		if (!buff)
+			return -ENOMEM;
+		dest = buff;
+	}
+
+	job->op            = qpl_op_decompress;
+	job->next_in_ptr   = src + inputmargin;
+	job->next_out_ptr  = dest;
+	job->available_in  = rq->inputsize - inputmargin;
+	job->available_out = rq->decodedlength;
+	job->flags         = QPL_FLAG_FIRST | QPL_FLAG_LAST;
+	status = qpl_execute_job(job);
+	if (status != QPL_STS_OK) {
+		erofs_err("failed to decompress: %d", status);
+		ret = -EIO;
+		goto out_inflate_end;
+	}
+
+	if (rq->decodedskip)
+		memcpy(rq->out, dest + rq->decodedskip,
+		       rq->decodedlength - rq->decodedskip);
+	ret = 0;
+out_inflate_end:
+	if (!z_erofs_qpl_put_job(job))
+		ret = -EFAULT;
+	if (buff)
+		free(buff);
+	return ret;
+}
+#else
+int z_erofs_load_deflate_config(struct erofs_sb_info *sbi,
+				struct erofs_super_block *dsb, void *data, int size)
+{
+	return 0;
+}
+#endif
+
 #ifdef HAVE_LIBDEFLATE
 /* if libdeflate is available, use libdeflate instead. */
 #include <libdeflate.h>
 
 static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
 {
-	struct erofs_sb_info *sbi = rq->sbi;
 	u8 *dest = (u8 *)rq->out;
 	u8 *src = (u8 *)rq->in;
 	u8 *buff = NULL;
 	size_t actual_out;
-	unsigned int inputmargin = 0;
+	unsigned int inputmargin;
 	struct libdeflate_decompressor *inf;
 	enum libdeflate_result ret;
+	unsigned int decodedcapacity;
 
-	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
-		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
-			break;
-
+	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
 	if (inputmargin >= rq->inputsize)
 		return -EFSCORRUPTED;
 
-	if (rq->decodedskip) {
-		buff = malloc(rq->decodedlength);
+	decodedcapacity = rq->decodedlength << (4 * rq->partial_decoding);
+	if (rq->decodedskip || rq->partial_decoding) {
+		buff = malloc(decodedcapacity);
 		if (!buff)
 			return -ENOMEM;
 		dest = buff;
 	}
 
 	inf = libdeflate_alloc_decompressor();
-	if (!inf)
-		return -ENOMEM;
+	if (!inf) {
+		ret = -ENOMEM;
+		goto out_free_mem;
+	}
 
 	if (rq->partial_decoding) {
-		ret = libdeflate_deflate_decompress(inf, src + inputmargin,
-				rq->inputsize - inputmargin, dest,
-				rq->decodedlength, &actual_out);
-		if (ret && ret != LIBDEFLATE_INSUFFICIENT_SPACE) {
-			ret = -EIO;
-			goto out_inflate_end;
+		while (1) {
+			ret = libdeflate_deflate_decompress(inf, src + inputmargin,
+					rq->inputsize - inputmargin, dest,
+					decodedcapacity, &actual_out);
+			if (ret == LIBDEFLATE_SUCCESS)
+				break;
+			if (ret != LIBDEFLATE_INSUFFICIENT_SPACE) {
+				ret = -EIO;
+				goto out_inflate_end;
+			}
+			decodedcapacity = decodedcapacity << 1;
+			dest = realloc(buff, decodedcapacity);
+			if (!dest) {
+				ret = -ENOMEM;
+				goto out_inflate_end;
+			}
+			buff = dest;
 		}
 
-		if (actual_out != rq->decodedlength) {
+		if (actual_out < rq->decodedlength) {
 			ret = -EIO;
 			goto out_inflate_end;
 		}
@@ -59,18 +295,19 @@ static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
 		ret = libdeflate_deflate_decompress(inf, src + inputmargin,
 				rq->inputsize - inputmargin, dest,
 				rq->decodedlength, NULL);
-		if (ret) {
+		if (ret != LIBDEFLATE_SUCCESS) {
 			ret = -EIO;
 			goto out_inflate_end;
 		}
 	}
 
-	if (rq->decodedskip)
+	if (rq->decodedskip || rq->partial_decoding)
 		memcpy(rq->out, dest + rq->decodedskip,
 		       rq->decodedlength - rq->decodedskip);
 
 out_inflate_end:
 	libdeflate_free_decompressor(inf);
+out_free_mem:
 	if (buff)
 		free(buff);
 	return ret;
@@ -97,18 +334,14 @@ static int zerr(int ret)
 
 static int z_erofs_decompress_deflate(struct z_erofs_decompress_req *rq)
 {
-	struct erofs_sb_info *sbi = rq->sbi;
 	u8 *dest = (u8 *)rq->out;
 	u8 *src = (u8 *)rq->in;
 	u8 *buff = NULL;
-	unsigned int inputmargin = 0;
+	unsigned int inputmargin;
 	z_stream strm;
 	int ret;
 
-	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
-		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
-			break;
-
+	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
 	if (inputmargin >= rq->inputsize)
 		return -EFSCORRUPTED;
 
@@ -162,18 +395,14 @@ out_inflate_end:
 static int z_erofs_decompress_lzma(struct z_erofs_decompress_req *rq)
 {
 	int ret = 0;
-	struct erofs_sb_info *sbi = rq->sbi;
 	u8 *dest = (u8 *)rq->out;
 	u8 *src = (u8 *)rq->in;
 	u8 *buff = NULL;
-	unsigned int inputmargin = 0;
+	unsigned int inputmargin;
 	lzma_stream strm;
 	lzma_ret ret2;
 
-	while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
-		if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
-			break;
-
+	inputmargin = z_erofs_fixup_insize(src, rq->inputsize);
 	if (inputmargin >= rq->inputsize)
 		return -EFSCORRUPTED;
 
@@ -234,12 +463,9 @@ static int z_erofs_decompress_lz4(struct z_erofs_decompress_req *rq)
 	if (erofs_sb_has_lz4_0padding(sbi)) {
 		support_0padding = true;
 
-		while (!src[inputmargin & (erofs_blksiz(sbi) - 1)])
-			if (!(++inputmargin & (erofs_blksiz(sbi) - 1)))
-				break;
-
+		inputmargin = z_erofs_fixup_insize((u8 *)src, rq->inputsize);
 		if (inputmargin >= rq->inputsize)
-			return -EIO;
+			return -EFSCORRUPTED;
 	}
 
 	if (rq->decodedskip) {
@@ -319,9 +545,86 @@ int z_erofs_decompress(struct z_erofs_decompress_req *rq)
 	if (rq->alg == Z_EROFS_COMPRESSION_LZMA)
 		return z_erofs_decompress_lzma(rq);
 #endif
+#ifdef HAVE_QPL
+	if (rq->alg == Z_EROFS_COMPRESSION_DEFLATE && rq->sbi->useqpl)
+		if (!z_erofs_decompress_qpl(rq))
+			return 0;
+#endif
 #if defined(HAVE_ZLIB) || defined(HAVE_LIBDEFLATE)
 	if (rq->alg == Z_EROFS_COMPRESSION_DEFLATE)
 		return z_erofs_decompress_deflate(rq);
+#endif
+#ifdef HAVE_LIBZSTD
+	if (rq->alg == Z_EROFS_COMPRESSION_ZSTD)
+		return z_erofs_decompress_zstd(rq);
 #endif
 	return -EOPNOTSUPP;
 }
+
+static int z_erofs_load_lz4_config(struct erofs_sb_info *sbi,
+			    struct erofs_super_block *dsb, void *data, int size)
+{
+	struct z_erofs_lz4_cfgs *lz4 = data;
+	u16 distance;
+
+	if (lz4) {
+		if (size < sizeof(struct z_erofs_lz4_cfgs)) {
+			erofs_err("invalid lz4 cfgs, size=%u", size);
+			return -EINVAL;
+		}
+		distance = le16_to_cpu(lz4->max_distance);
+
+		sbi->lz4.max_pclusterblks = le16_to_cpu(lz4->max_pclusterblks);
+		if (!sbi->lz4.max_pclusterblks)
+			sbi->lz4.max_pclusterblks = 1;	/* reserved case */
+	} else {
+		distance = le16_to_cpu(dsb->u1.lz4_max_distance);
+		sbi->lz4.max_pclusterblks = 1;
+	}
+	sbi->lz4.max_distance = distance;
+	return 0;
+}
+
+int z_erofs_parse_cfgs(struct erofs_sb_info *sbi, struct erofs_super_block *dsb)
+{
+	unsigned int algs, alg;
+	erofs_off_t offset;
+	int size, ret = 0;
+
+	if (!erofs_sb_has_compr_cfgs(sbi)) {
+		sbi->available_compr_algs = 1 << Z_EROFS_COMPRESSION_LZ4;
+		return z_erofs_load_lz4_config(sbi, dsb, NULL, 0);
+	}
+
+	sbi->available_compr_algs = le16_to_cpu(dsb->u1.available_compr_algs);
+	if (sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS) {
+		erofs_err("unidentified algorithms %x, please upgrade erofs-utils",
+			  sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS);
+		return -EOPNOTSUPP;
+	}
+
+	offset = EROFS_SUPER_OFFSET + sbi->sb_size;
+	alg = 0;
+	for (algs = sbi->available_compr_algs; algs; algs >>= 1, ++alg) {
+		void *data;
+
+		if (!(algs & 1))
+			continue;
+
+		data = erofs_read_metadata(sbi, 0, &offset, &size);
+		if (IS_ERR(data)) {
+			ret = PTR_ERR(data);
+			break;
+		}
+
+		ret = 0;
+		if (alg == Z_EROFS_COMPRESSION_LZ4)
+			ret = z_erofs_load_lz4_config(sbi, dsb, data, size);
+		else if (alg == Z_EROFS_COMPRESSION_DEFLATE)
+			ret = z_erofs_load_deflate_config(sbi, dsb, data, size);
+		free(data);
+		if (ret)
+			break;
+	}
+	return ret;
+}
diff --git a/lib/dedupe.c b/lib/dedupe.c
index 17da452..665915a 100644
--- a/lib/dedupe.c
+++ b/lib/dedupe.c
@@ -2,10 +2,11 @@
 /*
  * Copyright (C) 2022 Alibaba Cloud
  */
+#include <stdlib.h>
 #include "erofs/dedupe.h"
 #include "erofs/print.h"
-#include "rb_tree.h"
 #include "rolling_hash.h"
+#include "xxhash.h"
 #include "sha256.h"
 
 unsigned long erofs_memcmp2(const u8 *s1, const u8 *s2,
@@ -61,11 +62,15 @@ out_bytes:
 }
 
 static unsigned int window_size, rollinghash_rm;
-static struct rb_tree *dedupe_tree, *dedupe_subtree;
+static struct list_head dedupe_tree[65536];
+struct z_erofs_dedupe_item *dedupe_subtree;
 
 struct z_erofs_dedupe_item {
+	struct list_head list;
+	struct z_erofs_dedupe_item *chain;
 	long long	hash;
 	u8		prefix_sha256[32];
+	u64		prefix_xxh64;
 
 	erofs_blk_t	compressed_blkaddr;
 	unsigned int	compressed_blks;
@@ -75,22 +80,13 @@ struct z_erofs_dedupe_item {
 	u8		extra_data[];
 };
 
-static int z_erofs_dedupe_rbtree_cmp(struct rb_tree *self,
-		struct rb_node *node_a, struct rb_node *node_b)
-{
-	struct z_erofs_dedupe_item *e_a = node_a->value;
-	struct z_erofs_dedupe_item *e_b = node_b->value;
-
-	return (e_a->hash > e_b->hash) - (e_a->hash < e_b->hash);
-}
-
 int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
 {
 	struct z_erofs_dedupe_item e_find;
 	u8 *cur;
 	bool initial = true;
 
-	if (!dedupe_tree)
+	if (!window_size)
 		return -ENOENT;
 
 	if (ctx->cur > ctx->end - window_size)
@@ -100,8 +96,11 @@ int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
 
 	/* move backward byte-by-byte */
 	for (; cur >= ctx->start; --cur) {
+		struct list_head *p;
 		struct z_erofs_dedupe_item *e;
-		unsigned int extra;
+
+		unsigned int extra = 0;
+		u64 xxh64_csum = 0;
 		u8 sha256[32];
 
 		if (initial) {
@@ -113,13 +112,21 @@ int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
 				rollinghash_rm, cur[window_size], cur[0]);
 		}
 
-		e = rb_tree_find(dedupe_tree, &e_find);
-		if (!e) {
-			e = rb_tree_find(dedupe_subtree, &e_find);
-			if (!e)
+		p = &dedupe_tree[e_find.hash & (ARRAY_SIZE(dedupe_tree) - 1)];
+		list_for_each_entry(e, p, list) {
+			if (e->hash != e_find.hash)
 				continue;
+			if (!extra) {
+				xxh64_csum = xxh64(cur, window_size, 0);
+				extra = 1;
+			}
+			if (e->prefix_xxh64 == xxh64_csum)
+				break;
 		}
 
+		if (&e->list == p)
+			continue;
+
 		erofs_sha256(cur, window_size, sha256);
 		if (memcmp(sha256, e->prefix_sha256, sizeof(sha256)))
 			continue;
@@ -134,6 +141,7 @@ int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
 		ctx->e.partial = e->partial ||
 			(window_size + extra < e->original_length);
 		ctx->e.raw = e->raw;
+		ctx->e.inlined = false;
 		ctx->e.blkaddr = e->compressed_blkaddr;
 		ctx->e.compressedblks = e->compressed_blks;
 		return 0;
@@ -144,9 +152,10 @@ int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
 int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
 			  void *original_data)
 {
-	struct z_erofs_dedupe_item *di;
+	struct list_head *p;
+	struct z_erofs_dedupe_item *di, *k;
 
-	if (!dedupe_subtree || e->length < window_size)
+	if (!window_size || e->length < window_size)
 		return 0;
 
 	di = malloc(sizeof(*di) + e->length - window_size);
@@ -155,6 +164,8 @@ int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
 
 	di->original_length = e->length;
 	erofs_sha256(original_data, window_size, di->prefix_sha256);
+
+	di->prefix_xxh64 = xxh64(original_data, window_size, 0);
 	di->hash = erofs_rolling_hash_init(original_data,
 			window_size, true);
 	memcpy(di->extra_data, original_data + window_size,
@@ -164,52 +175,44 @@ int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
 	di->partial = e->partial;
 	di->raw = e->raw;
 
-	/* with the same rolling hash */
-	if (!rb_tree_insert(dedupe_subtree, di))
-		free(di);
+	/* skip the same xxh64 hash */
+	p = &dedupe_tree[di->hash & (ARRAY_SIZE(dedupe_tree) - 1)];
+	list_for_each_entry(k, p, list) {
+		if (k->prefix_xxh64 == di->prefix_xxh64) {
+			free(di);
+			return 0;
+		}
+	}
+	di->chain = dedupe_subtree;
+	dedupe_subtree = di;
+	list_add_tail(&di->list, p);
 	return 0;
 }
 
-static void z_erofs_dedupe_node_free_cb(struct rb_tree *self,
-					struct rb_node *node)
-{
-	free(node->value);
-	rb_tree_node_dealloc_cb(self, node);
-}
-
 void z_erofs_dedupe_commit(bool drop)
 {
 	if (!dedupe_subtree)
 		return;
-	if (!drop) {
-		struct rb_iter iter;
-		struct z_erofs_dedupe_item *di;
-
-		di = rb_iter_first(&iter, dedupe_subtree);
-		while (di) {
-			if (!rb_tree_insert(dedupe_tree, di))
-				DBG_BUGON(1);
-			di = rb_iter_next(&iter);
+	if (drop) {
+		struct z_erofs_dedupe_item *di, *n;
+
+		for (di = dedupe_subtree; di; di = n) {
+			n = di->chain;
+			list_del(&di->list);
+			free(di);
 		}
-		/*rb_iter_dealloc(iter);*/
-		rb_tree_dealloc(dedupe_subtree, rb_tree_node_dealloc_cb);
-	} else {
-		rb_tree_dealloc(dedupe_subtree, z_erofs_dedupe_node_free_cb);
 	}
-	dedupe_subtree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
+	dedupe_subtree = NULL;
 }
 
 int z_erofs_dedupe_init(unsigned int wsiz)
 {
-	dedupe_tree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
-	if (!dedupe_tree)
-		return -ENOMEM;
+	struct list_head *p;
+
+	for (p = dedupe_tree;
+		p < dedupe_tree + ARRAY_SIZE(dedupe_tree); ++p)
+		init_list_head(p);
 
-	dedupe_subtree = rb_tree_create(z_erofs_dedupe_rbtree_cmp);
-	if (!dedupe_subtree) {
-		rb_tree_dealloc(dedupe_subtree, NULL);
-		return -ENOMEM;
-	}
 	window_size = wsiz;
 	rollinghash_rm = erofs_rollinghash_calc_rm(window_size);
 	return 0;
@@ -217,7 +220,20 @@ int z_erofs_dedupe_init(unsigned int wsiz)
 
 void z_erofs_dedupe_exit(void)
 {
+	struct z_erofs_dedupe_item *di, *n;
+	struct list_head *p;
+
+	if (!window_size)
+		return;
+
 	z_erofs_dedupe_commit(true);
-	rb_tree_dealloc(dedupe_subtree, NULL);
-	rb_tree_dealloc(dedupe_tree, z_erofs_dedupe_node_free_cb);
+
+	for (p = dedupe_tree;
+		p < dedupe_tree + ARRAY_SIZE(dedupe_tree); ++p) {
+		list_for_each_entry_safe(di, n, p, list) {
+			list_del(&di->list);
+			free(di);
+		}
+	}
+	dedupe_subtree = NULL;
 }
diff --git a/lib/diskbuf.c b/lib/diskbuf.c
index 8205ba5..3789654 100644
--- a/lib/diskbuf.c
+++ b/lib/diskbuf.c
@@ -10,7 +10,7 @@
 
 /* A simple approach to avoid creating too many temporary files */
 static struct erofs_diskbufstrm {
-	u64 count;
+	erofs_atomic_t count;
 	u64 tailoffset, devpos;
 	int fd;
 	unsigned int alignsize;
@@ -25,8 +25,6 @@ int erofs_diskbuf_getfd(struct erofs_diskbuf *db, u64 *fpos)
 	if (!strm)
 		return -1;
 	offset = db->offset + strm->devpos;
-	if (lseek(strm->fd, offset, SEEK_SET) != offset)
-		return -E2BIG;
 	if (fpos)
 		*fpos = offset;
 	return strm->fd;
@@ -46,7 +44,7 @@ int erofs_diskbuf_reserve(struct erofs_diskbuf *db, int sid, u64 *off)
 	if (off)
 		*off = db->offset + strm->devpos;
 	db->sp = strm;
-	++strm->count;
+	(void)erofs_atomic_inc_return(&strm->count);
 	strm->locked = true;	/* TODO: need a real lock for MT */
 	return strm->fd;
 }
@@ -66,8 +64,8 @@ void erofs_diskbuf_close(struct erofs_diskbuf *db)
 	struct erofs_diskbufstrm *strm = db->sp;
 
 	DBG_BUGON(!strm);
-	DBG_BUGON(strm->count <= 1);
-	--strm->count;
+	DBG_BUGON(erofs_atomic_read(&strm->count) <= 1);
+	(void)erofs_atomic_dec_return(&strm->count);
 	db->sp = NULL;
 }
 
@@ -106,10 +104,10 @@ int erofs_diskbuf_init(unsigned int nstrms)
 		struct stat st;
 
 		/* try to use the devfd for regfiles on stream 0 */
-		if (strm == dbufstrm && sbi.devsz == INT64_MAX) {
+		if (strm == dbufstrm && !g_sbi.bdev.ops) {
 			strm->devpos = 1ULL << 40;
-			if (!ftruncate(sbi.devfd, strm->devpos << 1)) {
-				strm->fd = dup(sbi.devfd);
+			if (!ftruncate(g_sbi.bdev.fd, strm->devpos << 1)) {
+				strm->fd = dup(g_sbi.bdev.fd);
 				if (lseek(strm->fd, strm->devpos,
 					  SEEK_SET) != strm->devpos)
 					return -EIO;
@@ -122,7 +120,7 @@ int erofs_diskbuf_init(unsigned int nstrms)
 			return -ENOSPC;
 setupone:
 		strm->tailoffset = 0;
-		strm->count = 1;
+		erofs_atomic_set(&strm->count, 1);
 		if (fstat(strm->fd, &st))
 			return -errno;
 		strm->alignsize = max_t(u32, st.st_blksize, getpagesize());
@@ -138,7 +136,7 @@ void erofs_diskbuf_exit(void)
 		return;
 
 	for (strm = dbufstrm; strm->fd >= 0; ++strm) {
-		DBG_BUGON(strm->count != 1);
+		DBG_BUGON(erofs_atomic_read(&strm->count) != 1);
 
 		close(strm->fd);
 		strm->fd = -1;
diff --git a/lib/fragments.c b/lib/fragments.c
index d4f6be1..7591718 100644
--- a/lib/fragments.c
+++ b/lib/fragments.c
@@ -289,6 +289,8 @@ int z_erofs_pack_file_from_fd(struct erofs_inode *inode, int fd,
 	if (memblock)
 		rc = z_erofs_fragments_dedupe_insert(memblock,
 			inode->fragment_size, inode->fragmentoff, tofcrc);
+	else
+		rc = 0;
 out:
 	if (memblock)
 		munmap(memblock, inode->i_size);
@@ -324,12 +326,21 @@ int z_erofs_pack_fragments(struct erofs_inode *inode, void *data,
 	return len;
 }
 
-struct erofs_inode *erofs_mkfs_build_packedfile(void)
+int erofs_flush_packed_inode(struct erofs_sb_info *sbi)
 {
+	struct erofs_inode *inode;
+
+	if (!erofs_sb_has_fragments(sbi))
+		return -EINVAL;
 	fflush(packedfile);
+	if (!ftello(packedfile))
+		return 0;
 
-	return erofs_mkfs_build_special_from_fd(fileno(packedfile),
-						EROFS_PACKED_INODE);
+	inode = erofs_mkfs_build_special_from_fd(sbi, fileno(packedfile),
+						 EROFS_PACKED_INODE);
+	sbi->packed_nid = erofs_lookupnid(inode);
+	erofs_iput(inode);
+	return 0;
 }
 
 void erofs_packedfile_exit(void)
diff --git a/lib/inode.c b/lib/inode.c
index 8409ccd..b9dbbd6 100644
--- a/lib/inode.c
+++ b/lib/inode.c
@@ -3,7 +3,7 @@
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             http://www.huawei.com/
  * Created by Li Guifu <bluce.liguifu@huawei.com>
- * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
+ * with heavy changes by Gao Xiang <xiang@kernel.org>
  */
 #define _GNU_SOURCE
 #include <string.h>
@@ -19,7 +19,6 @@
 #include "erofs/diskbuf.h"
 #include "erofs/inode.h"
 #include "erofs/cache.h"
-#include "erofs/io.h"
 #include "erofs/compress.h"
 #include "erofs/xattr.h"
 #include "erofs/exclude.h"
@@ -56,6 +55,25 @@ static const unsigned char erofs_dtype_by_ftype[EROFS_FT_MAX] = {
 	[EROFS_FT_SYMLINK]	= DT_LNK
 };
 
+static const umode_t erofs_dtype_by_umode[EROFS_FT_MAX] = {
+	[EROFS_FT_UNKNOWN]	= S_IFMT,
+	[EROFS_FT_REG_FILE]	= S_IFREG,
+	[EROFS_FT_DIR]		= S_IFDIR,
+	[EROFS_FT_CHRDEV]	= S_IFCHR,
+	[EROFS_FT_BLKDEV]	= S_IFBLK,
+	[EROFS_FT_FIFO]		= S_IFIFO,
+	[EROFS_FT_SOCK]		= S_IFSOCK,
+	[EROFS_FT_SYMLINK]	= S_IFLNK
+};
+
+umode_t erofs_ftype_to_mode(unsigned int ftype, unsigned int perm)
+{
+	if (ftype >= EROFS_FT_MAX)
+		ftype = EROFS_FT_UNKNOWN;
+
+	return erofs_dtype_by_umode[ftype] | perm;
+}
+
 unsigned char erofs_ftype_to_dtype(unsigned int filetype)
 {
 	if (filetype >= EROFS_FT_MAX)
@@ -76,10 +94,11 @@ void erofs_inode_manager_init(void)
 		init_list_head(&inode_hashtable[i]);
 }
 
-void erofs_insert_ihash(struct erofs_inode *inode, dev_t dev, ino_t ino)
+void erofs_insert_ihash(struct erofs_inode *inode)
 {
-	list_add(&inode->i_hash,
-		 &inode_hashtable[(ino ^ dev) % NR_INODE_HASHTABLE]);
+	unsigned int nr = (inode->i_ino[1] ^ inode->dev) % NR_INODE_HASHTABLE;
+
+	list_add(&inode->i_hash, &inode_hashtable[nr]);
 }
 
 /* get the inode from the (source) inode # */
@@ -110,19 +129,22 @@ struct erofs_inode *erofs_iget_by_nid(erofs_nid_t nid)
 unsigned int erofs_iput(struct erofs_inode *inode)
 {
 	struct erofs_dentry *d, *t;
+	unsigned long got = erofs_atomic_dec_return(&inode->i_count);
 
-	if (inode->i_count > 1)
-		return --inode->i_count;
+	if (got >= 1)
+		return got;
 
 	list_for_each_entry_safe(d, t, &inode->i_subdirs, d_child)
 		free(d);
 
+	free(inode->compressmeta);
 	if (inode->eof_tailraw)
 		free(inode->eof_tailraw);
 	list_del(&inode->i_hash);
 	if (inode->i_srcpath)
 		free(inode->i_srcpath);
-	if (inode->with_diskbuf) {
+
+	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
 		erofs_diskbuf_close(inode->i_diskbuf);
 		free(inode->i_diskbuf);
 	} else if (inode->i_link) {
@@ -142,7 +164,9 @@ struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
 
 	strncpy(d->name, name, EROFS_NAME_LEN - 1);
 	d->name[EROFS_NAME_LEN - 1] = '\0';
-
+	d->inode = NULL;
+	d->type = EROFS_FT_UNKNOWN;
+	d->validnid = false;
 	list_add_tail(&d->d_child, &parent->i_subdirs);
 	return d;
 }
@@ -152,6 +176,7 @@ static int __allocate_inode_bh_data(struct erofs_inode *inode,
 				    unsigned long nblocks,
 				    int type)
 {
+	struct erofs_bufmgr *bmgr = inode->sbi->bmgr;
 	struct erofs_buffer_head *bh;
 	int ret;
 
@@ -162,7 +187,7 @@ static int __allocate_inode_bh_data(struct erofs_inode *inode,
 	}
 
 	/* allocate main data buffer */
-	bh = erofs_balloc(type, erofs_pos(inode->sbi, nblocks), 0, 0);
+	bh = erofs_balloc(bmgr, type, erofs_pos(inode->sbi, nblocks), 0, 0);
 	if (IS_ERR(bh))
 		return PTR_ERR(bh);
 
@@ -170,7 +195,7 @@ static int __allocate_inode_bh_data(struct erofs_inode *inode,
 	inode->bh_data = bh;
 
 	/* get blkaddr of the bh */
-	ret = erofs_mapbh(bh->block);
+	ret = erofs_mapbh(NULL, bh->block);
 	DBG_BUGON(ret < 0);
 
 	/* write blocks except for the tail-end block */
@@ -187,8 +212,30 @@ static int comp_subdir(const void *a, const void *b)
 	return strcmp(da->name, db->name);
 }
 
-static int erofs_prepare_dir_layout(struct erofs_inode *dir,
-				    unsigned int nr_subdirs)
+int erofs_init_empty_dir(struct erofs_inode *dir)
+{
+	struct erofs_dentry *d;
+
+	/* dot is pointed to the current dir inode */
+	d = erofs_d_alloc(dir, ".");
+	if (IS_ERR(d))
+		return PTR_ERR(d);
+	d->inode = erofs_igrab(dir);
+	d->type = EROFS_FT_DIR;
+
+	/* dotdot is pointed to the parent dir */
+	d = erofs_d_alloc(dir, "..");
+	if (IS_ERR(d))
+		return PTR_ERR(d);
+	d->inode = erofs_igrab(erofs_parent_inode(dir));
+	d->type = EROFS_FT_DIR;
+
+	dir->i_nlink = 2;
+	return 0;
+}
+
+static int erofs_prepare_dir_file(struct erofs_inode *dir,
+				  unsigned int nr_subdirs)
 {
 	struct erofs_sb_info *sbi = dir->sbi;
 	struct erofs_dentry *d, *n, **sorted_d;
@@ -227,41 +274,6 @@ static int erofs_prepare_dir_layout(struct erofs_inode *dir,
 	return 0;
 }
 
-int erofs_init_empty_dir(struct erofs_inode *dir)
-{
-	struct erofs_dentry *d;
-
-	/* dot is pointed to the current dir inode */
-	d = erofs_d_alloc(dir, ".");
-	if (IS_ERR(d))
-		return PTR_ERR(d);
-	d->inode = erofs_igrab(dir);
-	d->type = EROFS_FT_DIR;
-
-	/* dotdot is pointed to the parent dir */
-	d = erofs_d_alloc(dir, "..");
-	if (IS_ERR(d))
-		return PTR_ERR(d);
-	d->inode = erofs_igrab(dir->i_parent);
-	d->type = EROFS_FT_DIR;
-
-	dir->i_nlink = 2;
-	return 0;
-}
-
-int erofs_prepare_dir_file(struct erofs_inode *dir, unsigned int nr_subdirs)
-{
-	int ret;
-
-	ret = erofs_init_empty_dir(dir);
-	if (ret)
-		return ret;
-
-	/* sort subdirs */
-	nr_subdirs += 2;
-	return erofs_prepare_dir_layout(dir, nr_subdirs);
-}
-
 static void fill_dirblock(char *buf, unsigned int size, unsigned int q,
 			  struct erofs_dentry *head, struct erofs_dentry *end)
 {
@@ -293,7 +305,7 @@ static int write_dirblock(struct erofs_sb_info *sbi,
 	char buf[EROFS_MAX_BLOCK_SIZE];
 
 	fill_dirblock(buf, erofs_blksiz(sbi), q, head, end);
-	return blk_write(sbi, buf, blkaddr, 1);
+	return erofs_blk_write(sbi, buf, blkaddr, 1);
 }
 
 erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
@@ -302,17 +314,18 @@ erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
 	struct erofs_sb_info *sbi = inode->sbi;
 	erofs_off_t off, meta_offset;
 
-	if (!bh || (long long)inode->nid > 0)
-		return inode->nid;
-
-	erofs_mapbh(bh->block);
-	off = erofs_btell(bh, false);
+	if (bh && (long long)inode->nid <= 0) {
+		erofs_mapbh(NULL, bh->block);
+		off = erofs_btell(bh, false);
 
-	meta_offset = erofs_pos(sbi, sbi->meta_blkaddr);
-	DBG_BUGON(off < meta_offset);
-	inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
-	erofs_dbg("Assign nid %llu to file %s (mode %05o)",
-		  inode->nid, inode->i_srcpath, inode->i_mode);
+		meta_offset = erofs_pos(sbi, sbi->meta_blkaddr);
+		DBG_BUGON(off < meta_offset);
+		inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
+		erofs_dbg("Assign nid %llu to file %s (mode %05o)",
+			  inode->nid, inode->i_srcpath, inode->i_mode);
+	}
+	if (__erofs_unlikely(IS_ROOT(inode)) && inode->nid > 0xffff)
+		return sbi->root_nid;
 	return inode->nid;
 }
 
@@ -320,10 +333,91 @@ static void erofs_d_invalidate(struct erofs_dentry *d)
 {
 	struct erofs_inode *const inode = d->inode;
 
+	if (d->validnid)
+		return;
 	d->nid = erofs_lookupnid(inode);
+	d->validnid = true;
 	erofs_iput(inode);
 }
 
+static int erofs_rebuild_inode_fix_pnid(struct erofs_inode *parent,
+					erofs_nid_t nid)
+{
+	struct erofs_inode dir = {
+		.sbi = parent->sbi,
+		.nid = nid
+	};
+	unsigned int bsz = erofs_blksiz(dir.sbi);
+	unsigned int err, isz;
+	erofs_off_t boff, off;
+	erofs_nid_t pnid;
+	bool fixed = false;
+
+	err = erofs_read_inode_from_disk(&dir);
+	if (err)
+		return err;
+
+	if (!S_ISDIR(dir.i_mode))
+		return -ENOTDIR;
+
+	if (dir.datalayout != EROFS_INODE_FLAT_INLINE &&
+	    dir.datalayout != EROFS_INODE_FLAT_PLAIN)
+		return -EOPNOTSUPP;
+
+	pnid = erofs_lookupnid(parent);
+	isz = dir.inode_isize + dir.xattr_isize;
+	boff = erofs_pos(dir.sbi, dir.u.i_blkaddr);
+	for (off = 0; off < dir.i_size; off += bsz) {
+		char buf[EROFS_MAX_BLOCK_SIZE];
+		struct erofs_dirent *de = (struct erofs_dirent *)buf;
+		unsigned int nameoff, count, de_nameoff;
+
+		count = min_t(erofs_off_t, bsz, dir.i_size - off);
+		err = erofs_pread(&dir, buf, count, off);
+		if (err)
+			return err;
+
+		nameoff = le16_to_cpu(de->nameoff);
+		if (nameoff < sizeof(struct erofs_dirent) ||
+		    nameoff >= count) {
+			erofs_err("invalid de[0].nameoff %u @ nid %llu, offset %llu",
+				  nameoff, dir.nid | 0ULL, off | 0ULL);
+			return -EFSCORRUPTED;
+		}
+
+		while ((char *)de < buf + nameoff) {
+			de_nameoff = le16_to_cpu(de->nameoff);
+			if (((char *)(de + 1) >= buf + nameoff ?
+				strnlen(buf + de_nameoff, count - de_nameoff) == 2 :
+				le16_to_cpu(de[1].nameoff) == de_nameoff + 2) &&
+			   !memcmp(buf + de_nameoff, "..", 2)) {
+				if (de->nid == cpu_to_le64(pnid))
+					return 0;
+				de->nid = cpu_to_le64(pnid);
+				fixed = true;
+				break;
+			}
+			++de;
+		}
+
+		if (!fixed)
+			continue;
+		err = erofs_dev_write(dir.sbi, buf,
+			(off + bsz > dir.i_size &&
+				dir.datalayout == EROFS_INODE_FLAT_INLINE ?
+				erofs_iloc(&dir) + isz : boff + off), count);
+		erofs_dbg("directory %llu pNID is updated to %llu",
+			  nid | 0ULL, pnid | 0ULL);
+		break;
+	}
+	if (err || fixed)
+		return err;
+
+	erofs_err("directory data %llu is corrupted (\"..\" not found)",
+		  nid | 0ULL);
+	return -EFSCORRUPTED;
+}
+
 static int erofs_write_dir_file(struct erofs_inode *dir)
 {
 	struct erofs_dentry *head = list_first_entry(&dir->i_subdirs,
@@ -345,6 +439,13 @@ static int erofs_write_dir_file(struct erofs_inode *dir)
 		const unsigned int len = strlen(d->name) +
 			sizeof(struct erofs_dirent);
 
+		/* XXX: a bit hacky, but to avoid another traversal */
+		if (d->validnid && d->type == EROFS_FT_DIR) {
+			ret = erofs_rebuild_inode_fix_pnid(dir, d->nid);
+			if (ret)
+				return ret;
+		}
+
 		erofs_d_invalidate(d);
 		if (used + len > erofs_blksiz(sbi)) {
 			ret = write_dirblock(sbi, q, head, d,
@@ -391,7 +492,7 @@ int erofs_write_file_from_buffer(struct erofs_inode *inode, char *buf)
 		return ret;
 
 	if (nblocks)
-		blk_write(sbi, buf, inode->u.i_blkaddr, nblocks);
+		erofs_blk_write(sbi, buf, inode->u.i_blkaddr, nblocks);
 	inode->idata_size = inode->i_size % erofs_blksiz(sbi);
 	if (inode->idata_size) {
 		inode->idata = malloc(inode->idata_size);
@@ -414,27 +515,24 @@ static bool erofs_file_is_compressible(struct erofs_inode *inode)
 static int write_uncompressed_file_from_fd(struct erofs_inode *inode, int fd)
 {
 	int ret;
-	unsigned int nblocks, i;
+	erofs_blk_t nblocks, i;
+	unsigned int len;
 	struct erofs_sb_info *sbi = inode->sbi;
 
 	inode->datalayout = EROFS_INODE_FLAT_INLINE;
-	nblocks = inode->i_size / erofs_blksiz(sbi);
+	nblocks = inode->i_size >> sbi->blkszbits;
 
 	ret = __allocate_inode_bh_data(inode, nblocks, DATA);
 	if (ret)
 		return ret;
 
-	for (i = 0; i < nblocks; ++i) {
-		char buf[EROFS_MAX_BLOCK_SIZE];
-
-		ret = read(fd, buf, erofs_blksiz(sbi));
-		if (ret != erofs_blksiz(sbi)) {
-			if (ret < 0)
-				return -errno;
-			return -EAGAIN;
-		}
-
-		ret = blk_write(sbi, buf, inode->u.i_blkaddr + i, 1);
+	for (i = 0; i < nblocks; i += (len >> sbi->blkszbits)) {
+		len = min_t(u64, round_down(UINT_MAX, 1U << sbi->blkszbits),
+			    erofs_pos(sbi, nblocks - i));
+		ret = erofs_io_xcopy(&sbi->bdev,
+				     erofs_pos(sbi, inode->u.i_blkaddr + i),
+				     &((struct erofs_vfile){ .fd = fd }), len,
+			inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF);
 		if (ret)
 			return ret;
 	}
@@ -457,12 +555,8 @@ static int write_uncompressed_file_from_fd(struct erofs_inode *inode, int fd)
 	return 0;
 }
 
-int erofs_write_file(struct erofs_inode *inode, int fd, u64 fpos)
+int erofs_write_unencoded_file(struct erofs_inode *inode, int fd, u64 fpos)
 {
-	int ret;
-
-	DBG_BUGON(!inode->i_size);
-
 	if (cfg.c_chunkbits) {
 		inode->u.chunkbits = cfg.c_chunkbits;
 		/* chunk indexes when explicitly specified */
@@ -472,32 +566,26 @@ int erofs_write_file(struct erofs_inode *inode, int fd, u64 fpos)
 		return erofs_blob_write_chunked_file(inode, fd, fpos);
 	}
 
-	if (cfg.c_compr_alg[0] && erofs_file_is_compressible(inode)) {
-		ret = erofs_write_compressed_file(inode, fd);
-		if (!ret || ret != -ENOSPC)
-			return ret;
-
-		ret = lseek(fd, fpos, SEEK_SET);
-		if (ret < 0)
-			return -errno;
-	}
-
 	/* fallback to all data uncompressed */
 	return write_uncompressed_file_from_fd(inode, fd);
 }
 
-static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
+int erofs_iflush(struct erofs_inode *inode)
 {
-	struct erofs_inode *const inode = bh->fsprivate;
-	struct erofs_sb_info *sbi = inode->sbi;
 	const u16 icount = EROFS_INODE_XATTR_ICOUNT(inode->xattr_isize);
-	erofs_off_t off = erofs_btell(bh, false);
+	struct erofs_sb_info *sbi = inode->sbi;
+	erofs_off_t off;
 	union {
 		struct erofs_inode_compact dic;
 		struct erofs_inode_extended die;
-	} u = { {0}, };
+	} u = {};
 	int ret;
 
+	if (inode->bh)
+		off = erofs_btell(inode->bh, false);
+	else
+		off = erofs_iloc(inode);
+
 	switch (inode->inode_isize) {
 	case sizeof(struct erofs_inode_compact):
 		u.dic.i_format = cpu_to_le16(0 | (inode->datalayout << 1));
@@ -576,21 +664,21 @@ static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
 		BUG_ON(1);
 	}
 
-	ret = dev_write(sbi, &u, off, inode->inode_isize);
+	ret = erofs_dev_write(sbi, &u, off, inode->inode_isize);
 	if (ret)
-		return false;
+		return ret;
 	off += inode->inode_isize;
 
 	if (inode->xattr_isize) {
 		char *xattrs = erofs_export_xattr_ibody(inode);
 
 		if (IS_ERR(xattrs))
-			return false;
+			return PTR_ERR(xattrs);
 
-		ret = dev_write(sbi, xattrs, off, inode->xattr_isize);
+		ret = erofs_dev_write(sbi, xattrs, off, inode->xattr_isize);
 		free(xattrs);
 		if (ret)
-			return false;
+			return ret;
 
 		off += inode->xattr_isize;
 	}
@@ -599,18 +687,28 @@ static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
 		if (inode->datalayout == EROFS_INODE_CHUNK_BASED) {
 			ret = erofs_blob_write_chunk_indexes(inode, off);
 			if (ret)
-				return false;
+				return ret;
 		} else {
 			/* write compression metadata */
 			off = roundup(off, 8);
-			ret = dev_write(sbi, inode->compressmeta, off,
-					inode->extent_isize);
+			ret = erofs_dev_write(sbi, inode->compressmeta, off,
+					      inode->extent_isize);
 			if (ret)
-				return false;
-			free(inode->compressmeta);
+				return ret;
 		}
 	}
+	return 0;
+}
+
+static int erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
+{
+	struct erofs_inode *inode = bh->fsprivate;
+	int ret;
 
+	DBG_BUGON(inode->bh != bh);
+	ret = erofs_iflush(inode);
+	if (ret)
+		return ret;
 	inode->bh = NULL;
 	erofs_iput(inode);
 	return erofs_bh_flush_generic_end(bh);
@@ -640,11 +738,14 @@ static int erofs_prepare_tail_block(struct erofs_inode *inode)
 	} else {
 		inode->lazy_tailblock = true;
 	}
+	if (is_inode_layout_compression(inode))
+		inode->u.i_blocks += 1;
 	return 0;
 }
 
 static int erofs_prepare_inode_buffer(struct erofs_inode *inode)
 {
+	struct erofs_bufmgr *bmgr = inode->sbi->bmgr;
 	unsigned int inodesize;
 	struct erofs_buffer_head *bh, *ibh;
 
@@ -654,6 +755,9 @@ static int erofs_prepare_inode_buffer(struct erofs_inode *inode)
 	if (inode->extent_isize)
 		inodesize = roundup(inodesize, 8) + inode->extent_isize;
 
+	if (inode->datalayout == EROFS_INODE_FLAT_PLAIN)
+		goto noinline;
+
 	/* TODO: tailpacking inline of chunk-based format isn't finalized */
 	if (inode->datalayout == EROFS_INODE_CHUNK_BASED)
 		goto noinline;
@@ -671,7 +775,7 @@ static int erofs_prepare_inode_buffer(struct erofs_inode *inode)
 			inode->datalayout = EROFS_INODE_FLAT_PLAIN;
 	}
 
-	bh = erofs_balloc(INODE, inodesize, 0, inode->idata_size);
+	bh = erofs_balloc(bmgr, INODE, inodesize, 0, inode->idata_size);
 	if (bh == ERR_PTR(-ENOSPC)) {
 		int ret;
 
@@ -684,7 +788,7 @@ noinline:
 		ret = erofs_prepare_tail_block(inode);
 		if (ret)
 			return ret;
-		bh = erofs_balloc(INODE, inodesize, 0, 0);
+		bh = erofs_balloc(bmgr, INODE, inodesize, 0, 0);
 		if (IS_ERR(bh))
 			return PTR_ERR(bh);
 		DBG_BUGON(inode->bh_inline);
@@ -718,17 +822,16 @@ noinline:
 	return 0;
 }
 
-static bool erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
+static int erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
 {
 	struct erofs_inode *const inode = bh->fsprivate;
 	const erofs_off_t off = erofs_btell(bh, false);
 	int ret;
 
-	ret = dev_write(inode->sbi, inode->idata, off, inode->idata_size);
+	ret = erofs_dev_write(inode->sbi, inode->idata, off, inode->idata_size);
 	if (ret)
-		return false;
+		return ret;
 
-	inode->idata_size = 0;
 	free(inode->idata);
 	inode->idata = NULL;
 
@@ -750,6 +853,7 @@ static int erofs_write_tail_end(struct erofs_inode *inode)
 	if (!inode->idata_size)
 		goto out;
 
+	DBG_BUGON(!inode->idata);
 	/* have enough room to inline data */
 	if (inode->bh_inline) {
 		ibh = inode->bh_inline;
@@ -763,13 +867,14 @@ static int erofs_write_tail_end(struct erofs_inode *inode)
 		erofs_off_t pos, zero_pos;
 
 		if (!bh) {
-			bh = erofs_balloc(DATA, erofs_blksiz(sbi), 0, 0);
+			bh = erofs_balloc(sbi->bmgr, DATA,
+					  erofs_blksiz(sbi), 0, 0);
 			if (IS_ERR(bh))
 				return PTR_ERR(bh);
 			bh->op = &erofs_skip_write_bhops;
 
 			/* get blkaddr of bh */
-			ret = erofs_mapbh(bh->block);
+			ret = erofs_mapbh(NULL, bh->block);
 			inode->u.i_blkaddr = bh->block->blkaddr;
 			inode->bh_data = bh;
 		} else {
@@ -782,7 +887,7 @@ static int erofs_write_tail_end(struct erofs_inode *inode)
 				}
 				inode->lazy_tailblock = false;
 			}
-			ret = erofs_mapbh(bh->block);
+			ret = erofs_mapbh(NULL, bh->block);
 		}
 		DBG_BUGON(ret < 0);
 		pos = erofs_btell(bh, true) - erofs_blksiz(sbi);
@@ -795,13 +900,13 @@ static int erofs_write_tail_end(struct erofs_inode *inode)
 			/* pad 0'ed data for the other cases */
 			zero_pos = pos + inode->idata_size;
 		}
-		ret = dev_write(sbi, inode->idata, pos, inode->idata_size);
+		ret = erofs_dev_write(sbi, inode->idata, pos, inode->idata_size);
 		if (ret)
 			return ret;
 
 		DBG_BUGON(inode->idata_size > erofs_blksiz(sbi));
 		if (inode->idata_size < erofs_blksiz(sbi)) {
-			ret = dev_fillzero(sbi, zero_pos,
+			ret = erofs_dev_fillzero(sbi, zero_pos,
 					   erofs_blksiz(sbi) - inode->idata_size,
 					   false);
 			if (ret)
@@ -981,11 +1086,6 @@ static int erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
 	if (!inode->i_srcpath)
 		return -ENOMEM;
 
-	if (!S_ISDIR(inode->i_mode)) {
-		inode->dev = st->st_dev;
-		inode->i_ino[1] = st->st_ino;
-	}
-
 	if (erofs_should_use_inode_extended(inode)) {
 		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
 			erofs_err("file %s cannot be in compact form",
@@ -997,11 +1097,13 @@ static int erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
 		inode->inode_isize = sizeof(struct erofs_inode_compact);
 	}
 
-	erofs_insert_ihash(inode, st->st_dev, st->st_ino);
+	inode->dev = st->st_dev;
+	inode->i_ino[1] = st->st_ino;
+	erofs_insert_ihash(inode);
 	return 0;
 }
 
-struct erofs_inode *erofs_new_inode(void)
+struct erofs_inode *erofs_new_inode(struct erofs_sb_info *sbi)
 {
 	struct erofs_inode *inode;
 
@@ -1009,8 +1111,8 @@ struct erofs_inode *erofs_new_inode(void)
 	if (!inode)
 		return ERR_PTR(-ENOMEM);
 
-	inode->sbi = &sbi;
-	inode->i_ino[0] = sbi.inos++;	/* inode serial number */
+	inode->sbi = sbi;
+	inode->i_ino[0] = sbi->inos++;	/* inode serial number */
 	inode->i_count = 1;
 	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
 
@@ -1020,17 +1122,14 @@ struct erofs_inode *erofs_new_inode(void)
 	return inode;
 }
 
-/* get the inode from the (source) path */
-static struct erofs_inode *erofs_iget_from_path(const char *path, bool is_src)
+/* get the inode from the source path */
+static struct erofs_inode *erofs_iget_from_srcpath(struct erofs_sb_info *sbi,
+						   const char *path)
 {
 	struct stat st;
 	struct erofs_inode *inode;
 	int ret;
 
-	/* currently, only source path is supported */
-	if (!is_src)
-		return ERR_PTR(-EINVAL);
-
 	ret = lstat(path, &st);
 	if (ret)
 		return ERR_PTR(-errno);
@@ -1047,7 +1146,7 @@ static struct erofs_inode *erofs_iget_from_path(const char *path, bool is_src)
 	}
 
 	/* cannot find in the inode cache */
-	inode = erofs_new_inode();
+	inode = erofs_new_inode(sbi);
 	if (IS_ERR(inode))
 		return inode;
 
@@ -1066,7 +1165,7 @@ static void erofs_fixup_meta_blkaddr(struct erofs_inode *rootdir)
 	struct erofs_sb_info *sbi = rootdir->sbi;
 	erofs_off_t off, meta_offset;
 
-	erofs_mapbh(bh->block);
+	erofs_mapbh(NULL, bh->block);
 	off = erofs_btell(bh, false);
 
 	if (off > rootnid_maxoffset)
@@ -1077,73 +1176,279 @@ static void erofs_fixup_meta_blkaddr(struct erofs_inode *rootdir)
 	rootdir->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
 }
 
-static int erofs_mkfs_build_tree(struct erofs_inode *dir, struct list_head *dirs)
+static int erofs_inode_reserve_data_blocks(struct erofs_inode *inode)
 {
+	struct erofs_sb_info *sbi = inode->sbi;
+	erofs_off_t alignedsz = round_up(inode->i_size, erofs_blksiz(sbi));
+	erofs_blk_t nblocks = alignedsz >> sbi->blkszbits;
+	struct erofs_buffer_head *bh;
+
+	/* allocate data blocks */
+	bh = erofs_balloc(sbi->bmgr, DATA, alignedsz, 0, 0);
+	if (IS_ERR(bh))
+		return PTR_ERR(bh);
+
+	/* get blkaddr of the bh */
+	(void)erofs_mapbh(NULL, bh->block);
+
+	/* write blocks except for the tail-end block */
+	inode->u.i_blkaddr = bh->block->blkaddr;
+	erofs_bdrop(bh, false);
+
+	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
+	tarerofs_blocklist_write(inode->u.i_blkaddr, nblocks, inode->i_ino[1]);
+	return 0;
+}
+
+struct erofs_mkfs_job_ndir_ctx {
+	struct erofs_inode *inode;
+	void *ictx;
+	int fd;
+	u64 fpos;
+};
+
+static int erofs_mkfs_job_write_file(struct erofs_mkfs_job_ndir_ctx *ctx)
+{
+	struct erofs_inode *inode = ctx->inode;
 	int ret;
-	DIR *_dir;
-	struct dirent *dp;
-	struct erofs_dentry *d;
-	unsigned int nr_subdirs, i_nlink;
 
-	ret = erofs_scan_file_xattrs(dir);
-	if (ret < 0)
-		return ret;
+	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF &&
+	    lseek(ctx->fd, ctx->fpos, SEEK_SET) < 0) {
+		ret = -errno;
+		goto out;
+	}
 
-	ret = erofs_prepare_xattr_ibody(dir);
-	if (ret < 0)
-		return ret;
+	if (ctx->ictx) {
+		ret = erofs_write_compressed_file(ctx->ictx);
+		if (ret != -ENOSPC)
+			goto out;
+		if (lseek(ctx->fd, ctx->fpos, SEEK_SET) < 0) {
+			ret = -errno;
+			goto out;
+		}
+	}
+	/* fallback to all data uncompressed */
+	ret = erofs_write_unencoded_file(inode, ctx->fd, ctx->fpos);
+out:
+	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
+		erofs_diskbuf_close(inode->i_diskbuf);
+		free(inode->i_diskbuf);
+		inode->i_diskbuf = NULL;
+		inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
+	} else {
+		close(ctx->fd);
+	}
+	return ret;
+}
+
+static int erofs_mkfs_handle_nondirectory(struct erofs_mkfs_job_ndir_ctx *ctx)
+{
+	struct erofs_inode *inode = ctx->inode;
+	int ret = 0;
 
-	if (!S_ISDIR(dir->i_mode)) {
-		if (S_ISLNK(dir->i_mode)) {
-			char *const symlink = malloc(dir->i_size);
+	if (S_ISLNK(inode->i_mode)) {
+		char *symlink = inode->i_link;
 
+		if (!symlink) {
+			symlink = malloc(inode->i_size);
 			if (!symlink)
 				return -ENOMEM;
-			ret = readlink(dir->i_srcpath, symlink, dir->i_size);
+			ret = readlink(inode->i_srcpath, symlink, inode->i_size);
 			if (ret < 0) {
 				free(symlink);
 				return -errno;
 			}
-			ret = erofs_write_file_from_buffer(dir, symlink);
-			free(symlink);
-		} else if (dir->i_size) {
-			int fd = open(dir->i_srcpath, O_RDONLY | O_BINARY);
-			if (fd < 0)
-				return -errno;
-
-			ret = erofs_write_file(dir, fd, 0);
-			close(fd);
-		} else {
-			ret = 0;
 		}
+		ret = erofs_write_file_from_buffer(inode, symlink);
+		free(symlink);
+		inode->i_link = NULL;
+	} else if (inode->i_size) {
+		if (inode->datasource == EROFS_INODE_DATA_SOURCE_RESVSP)
+			ret = erofs_inode_reserve_data_blocks(inode);
+		else if (ctx->fd >= 0)
+			ret = erofs_mkfs_job_write_file(ctx);
+	}
+	if (ret)
+		return ret;
+	erofs_prepare_inode_buffer(inode);
+	erofs_write_tail_end(inode);
+	return 0;
+}
+
+enum erofs_mkfs_jobtype {	/* ordered job types */
+	EROFS_MKFS_JOB_NDIR,
+	EROFS_MKFS_JOB_DIR,
+	EROFS_MKFS_JOB_DIR_BH,
+	EROFS_MKFS_JOB_MAX
+};
+
+struct erofs_mkfs_jobitem {
+	enum erofs_mkfs_jobtype type;
+	union {
+		struct erofs_inode *inode;
+		struct erofs_mkfs_job_ndir_ctx ndir;
+	} u;
+};
+
+static int erofs_mkfs_jobfn(struct erofs_mkfs_jobitem *item)
+{
+	struct erofs_inode *inode = item->u.inode;
+	int ret;
+
+	if (item->type == EROFS_MKFS_JOB_NDIR)
+		return erofs_mkfs_handle_nondirectory(&item->u.ndir);
+
+	if (item->type == EROFS_MKFS_JOB_DIR) {
+		ret = erofs_prepare_inode_buffer(inode);
 		if (ret)
 			return ret;
+		inode->bh->op = &erofs_skip_write_bhops;
+		return 0;
+	}
 
-		erofs_prepare_inode_buffer(dir);
-		erofs_write_tail_end(dir);
+	if (item->type == EROFS_MKFS_JOB_DIR_BH) {
+		ret = erofs_write_dir_file(inode);
+		if (ret)
+			return ret;
+		erofs_write_tail_end(inode);
+		inode->bh->op = &erofs_write_inode_bhops;
+		erofs_iput(inode);
 		return 0;
 	}
+	return -EINVAL;
+}
+
+#ifdef EROFS_MT_ENABLED
+
+struct erofs_mkfs_dfops {
+	pthread_t worker;
+	pthread_mutex_t lock;
+	pthread_cond_t full, empty, drain;
+	struct erofs_mkfs_jobitem *queue;
+	unsigned int entries, head, tail;
+};
+
+#define EROFS_MT_QUEUE_SIZE 128
+
+static void erofs_mkfs_flushjobs(struct erofs_sb_info *sbi)
+{
+	struct erofs_mkfs_dfops *q = sbi->mkfs_dfops;
+
+	pthread_mutex_lock(&q->lock);
+	pthread_cond_wait(&q->drain, &q->lock);
+	pthread_mutex_unlock(&q->lock);
+}
+
+static void *erofs_mkfs_pop_jobitem(struct erofs_mkfs_dfops *q)
+{
+	struct erofs_mkfs_jobitem *item;
+
+	pthread_mutex_lock(&q->lock);
+	while (q->head == q->tail) {
+		pthread_cond_signal(&q->drain);
+		pthread_cond_wait(&q->empty, &q->lock);
+	}
+
+	item = q->queue + q->head;
+	q->head = (q->head + 1) & (q->entries - 1);
+
+	pthread_cond_signal(&q->full);
+	pthread_mutex_unlock(&q->lock);
+	return item;
+}
+
+static void *z_erofs_mt_dfops_worker(void *arg)
+{
+	struct erofs_sb_info *sbi = arg;
+	int ret = 0;
+
+	while (1) {
+		struct erofs_mkfs_jobitem *item;
+
+		item = erofs_mkfs_pop_jobitem(sbi->mkfs_dfops);
+		if (item->type >= EROFS_MKFS_JOB_MAX)
+			break;
+		ret = erofs_mkfs_jobfn(item);
+		if (ret)
+			break;
+	}
+	pthread_exit((void *)(uintptr_t)ret);
+}
+
+static int erofs_mkfs_go(struct erofs_sb_info *sbi,
+			 enum erofs_mkfs_jobtype type, void *elem, int size)
+{
+	struct erofs_mkfs_jobitem *item;
+	struct erofs_mkfs_dfops *q = sbi->mkfs_dfops;
+
+	pthread_mutex_lock(&q->lock);
+
+	while (((q->tail + 1) & (q->entries - 1)) == q->head)
+		pthread_cond_wait(&q->full, &q->lock);
+
+	item = q->queue + q->tail;
+	item->type = type;
+	memcpy(&item->u, elem, size);
+	q->tail = (q->tail + 1) & (q->entries - 1);
+
+	pthread_cond_signal(&q->empty);
+	pthread_mutex_unlock(&q->lock);
+	return 0;
+}
+#else
+static int erofs_mkfs_go(struct erofs_sb_info *sbi,
+			 enum erofs_mkfs_jobtype type, void *elem, int size)
+{
+	struct erofs_mkfs_jobitem item;
+
+	item.type = type;
+	memcpy(&item.u, elem, size);
+	return erofs_mkfs_jobfn(&item);
+}
+static void erofs_mkfs_flushjobs(struct erofs_sb_info *sbi)
+{
+}
+#endif
+
+static int erofs_mkfs_handle_directory(struct erofs_inode *dir)
+{
+	struct erofs_sb_info *sbi = dir->sbi;
+	DIR *_dir;
+	struct dirent *dp;
+	struct erofs_dentry *d;
+	unsigned int nr_subdirs, i_nlink;
+	int ret;
 
 	_dir = opendir(dir->i_srcpath);
 	if (!_dir) {
 		erofs_err("failed to opendir at %s: %s",
-			  dir->i_srcpath, erofs_strerror(errno));
+			  dir->i_srcpath, erofs_strerror(-errno));
 		return -errno;
 	}
 
 	nr_subdirs = 0;
+	i_nlink = 0;
 	while (1) {
+		char buf[PATH_MAX];
+		struct erofs_inode *inode;
+
 		/*
 		 * set errno to 0 before calling readdir() in order to
 		 * distinguish end of stream and from an error.
 		 */
 		errno = 0;
 		dp = readdir(_dir);
-		if (!dp)
-			break;
+		if (!dp) {
+			if (!errno)
+				break;
+			ret = -errno;
+			goto err_closedir;
+		}
 
-		if (is_dot_dotdot(dp->d_name))
+		if (is_dot_dotdot(dp->d_name)) {
+			++i_nlink;
 			continue;
+		}
 
 		/* skip if it's a exclude file */
 		if (erofs_is_exclude_path(dir->i_srcpath, dp->d_name))
@@ -1154,70 +1459,104 @@ static int erofs_mkfs_build_tree(struct erofs_inode *dir, struct list_head *dirs
 			ret = PTR_ERR(d);
 			goto err_closedir;
 		}
-		nr_subdirs++;
-	}
 
-	if (errno) {
-		ret = -errno;
-		goto err_closedir;
+		ret = snprintf(buf, PATH_MAX, "%s/%s", dir->i_srcpath, d->name);
+		if (ret < 0 || ret >= PATH_MAX)
+			goto err_closedir;
+
+		inode = erofs_iget_from_srcpath(sbi, buf);
+		if (IS_ERR(inode)) {
+			ret = PTR_ERR(inode);
+			goto err_closedir;
+		}
+		d->inode = inode;
+		d->type = erofs_mode_to_ftype(inode->i_mode);
+		i_nlink += S_ISDIR(inode->i_mode);
+		erofs_dbg("file %s added (type %u)", buf, d->type);
+		nr_subdirs++;
 	}
 	closedir(_dir);
 
-	ret = erofs_prepare_dir_file(dir, nr_subdirs);
+	ret = erofs_init_empty_dir(dir);
 	if (ret)
 		return ret;
 
-	ret = erofs_prepare_inode_buffer(dir);
+	ret = erofs_prepare_dir_file(dir, nr_subdirs + 2); /* sort subdirs */
 	if (ret)
 		return ret;
-	dir->bh->op = &erofs_skip_write_bhops;
 
-	if (IS_ROOT(dir))
-		erofs_fixup_meta_blkaddr(dir);
+	/*
+	 * if there're too many subdirs as compact form, set nlink=1
+	 * rather than upgrade to use extented form instead.
+	 */
+	if (i_nlink > USHRT_MAX &&
+	    dir->inode_isize == sizeof(struct erofs_inode_compact))
+		dir->i_nlink = 1;
+	else
+		dir->i_nlink = i_nlink;
 
-	i_nlink = 0;
-	list_for_each_entry(d, &dir->i_subdirs, d_child) {
-		char buf[PATH_MAX];
-		unsigned char ftype;
-		struct erofs_inode *inode;
+	return erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR, &dir, sizeof(dir));
 
-		if (is_dot_dotdot(d->name)) {
-			++i_nlink;
-			continue;
-		}
+err_closedir:
+	closedir(_dir);
+	return ret;
+}
 
-		ret = snprintf(buf, PATH_MAX, "%s/%s",
-			       dir->i_srcpath, d->name);
-		if (ret < 0 || ret >= PATH_MAX) {
-			/* ignore the too long path */
-			goto fail;
-		}
+int erofs_rebuild_load_basedir(struct erofs_inode *dir);
 
-		inode = erofs_iget_from_path(buf, true);
+bool erofs_dentry_is_wht(struct erofs_sb_info *sbi, struct erofs_dentry *d)
+{
+	if (!d->validnid)
+		return erofs_inode_is_whiteout(d->inode);
+	if (d->type == EROFS_FT_CHRDEV) {
+		struct erofs_inode ei = { .sbi = sbi, .nid = d->nid };
+		int ret;
 
-		if (IS_ERR(inode)) {
-			ret = PTR_ERR(inode);
-fail:
-			d->inode = NULL;
-			d->type = EROFS_FT_UNKNOWN;
-			return ret;
+		ret = erofs_read_inode_from_disk(&ei);
+		if (ret) {
+			erofs_err("failed to check DT_WHT: %s",
+				  erofs_strerror(ret));
+			DBG_BUGON(1);
+			return false;
 		}
+		return erofs_inode_is_whiteout(&ei);
+	}
+	return false;
+}
 
-		/* a hardlink to the existed inode */
-		if (inode->i_parent) {
-			++inode->i_nlink;
-		} else {
-			inode->i_parent = dir;
-			erofs_igrab(inode);
-			list_add_tail(&inode->i_subdirs, dirs);
+static int erofs_rebuild_handle_directory(struct erofs_inode *dir,
+					  bool incremental)
+{
+	struct erofs_sb_info *sbi = dir->sbi;
+	struct erofs_dentry *d, *n;
+	unsigned int nr_subdirs, i_nlink;
+	bool delwht = cfg.c_ovlfs_strip && dir->whiteouts;
+	int ret;
+
+	nr_subdirs = 0;
+	i_nlink = 0;
+
+	list_for_each_entry_safe(d, n, &dir->i_subdirs, d_child) {
+		if (delwht && erofs_dentry_is_wht(sbi, d)) {
+			erofs_dbg("remove whiteout %s", d->inode->i_srcpath);
+			list_del(&d->d_child);
+			erofs_d_invalidate(d);
+			free(d);
+			continue;
 		}
-		ftype = erofs_mode_to_ftype(inode->i_mode);
-		i_nlink += (ftype == EROFS_FT_DIR);
-		d->inode = inode;
-		d->type = ftype;
-		erofs_info("file %s/%s dumped (type %u)",
-			   dir->i_srcpath, d->name, d->type);
+		i_nlink += (d->type == EROFS_FT_DIR);
+		++nr_subdirs;
 	}
+
+	DBG_BUGON(i_nlink < 2);		/* should have `.` and `..` */
+	DBG_BUGON(nr_subdirs < i_nlink);
+	ret = erofs_prepare_dir_file(dir, nr_subdirs);
+	if (ret)
+		return ret;
+
+	if (IS_ROOT(dir) && incremental)
+		dir->datalayout = EROFS_INODE_FLAT_PLAIN;
+
 	/*
 	 * if there're too many subdirs as compact form, set nlink=1
 	 * rather than upgrade to use extented form instead.
@@ -1227,70 +1566,324 @@ fail:
 		dir->i_nlink = 1;
 	else
 		dir->i_nlink = i_nlink;
-	return 0;
 
-err_closedir:
-	closedir(_dir);
+	return erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR, &dir, sizeof(dir));
+}
+
+static int erofs_mkfs_handle_inode(struct erofs_inode *inode)
+{
+	const char *relpath = erofs_fspath(inode->i_srcpath);
+	char *trimmed;
+	int ret;
+
+	trimmed = erofs_trim_for_progressinfo(relpath[0] ? relpath : "/",
+					      sizeof("Processing  ...") - 1);
+	erofs_update_progressinfo("Processing %s ...", trimmed);
+	free(trimmed);
+
+	ret = erofs_scan_file_xattrs(inode);
+	if (ret < 0)
+		return ret;
+
+	ret = erofs_prepare_xattr_ibody(inode, false);
+	if (ret < 0)
+		return ret;
+
+	if (!S_ISDIR(inode->i_mode)) {
+		struct erofs_mkfs_job_ndir_ctx ctx = { .inode = inode };
+
+		if (!S_ISLNK(inode->i_mode) && inode->i_size) {
+			ctx.fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
+			if (ctx.fd < 0)
+				return -errno;
+
+			if (cfg.c_compr_opts[0].alg &&
+			    erofs_file_is_compressible(inode)) {
+				ctx.ictx = erofs_begin_compressed_file(inode,
+								ctx.fd, 0);
+				if (IS_ERR(ctx.ictx))
+					return PTR_ERR(ctx.ictx);
+			}
+		}
+		ret = erofs_mkfs_go(inode->sbi, EROFS_MKFS_JOB_NDIR,
+				    &ctx, sizeof(ctx));
+	} else {
+		ret = erofs_mkfs_handle_directory(inode);
+	}
+	erofs_info("file /%s dumped (mode %05o)", relpath, inode->i_mode);
 	return ret;
 }
 
-struct erofs_inode *erofs_mkfs_build_tree_from_path(const char *path)
+static int erofs_rebuild_handle_inode(struct erofs_inode *inode,
+				      bool incremental)
 {
-	LIST_HEAD(dirs);
-	struct erofs_inode *inode, *root, *dumpdir;
+	char *trimmed;
+	int ret;
 
-	root = erofs_iget_from_path(path, true);
-	if (IS_ERR(root))
-		return root;
+	trimmed = erofs_trim_for_progressinfo(erofs_fspath(inode->i_srcpath),
+					      sizeof("Processing  ...") - 1);
+	erofs_update_progressinfo("Processing %s ...", trimmed);
+	free(trimmed);
 
-	(void)erofs_igrab(root);
-	root->i_parent = root;	/* rootdir mark */
-	list_add(&root->i_subdirs, &dirs);
+	if (erofs_should_use_inode_extended(inode)) {
+		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
+			erofs_err("file %s cannot be in compact form",
+				  inode->i_srcpath);
+			return -EINVAL;
+		}
+		inode->inode_isize = sizeof(struct erofs_inode_extended);
+	} else {
+		inode->inode_isize = sizeof(struct erofs_inode_compact);
+	}
 
-	dumpdir = NULL;
-	do {
-		int err;
-		char *trimmed;
+	if (incremental && S_ISDIR(inode->i_mode) &&
+	    inode->dev == inode->sbi->dev && !inode->opaque) {
+		ret = erofs_rebuild_load_basedir(inode);
+		if (ret)
+			return ret;
+	}
 
-		inode = list_first_entry(&dirs, struct erofs_inode, i_subdirs);
-		list_del(&inode->i_subdirs);
-		init_list_head(&inode->i_subdirs);
+	/* strip all unnecessary overlayfs xattrs when ovlfs_strip is enabled */
+	if (cfg.c_ovlfs_strip)
+		erofs_clear_opaque_xattr(inode);
+	else if (inode->whiteouts)
+		erofs_set_origin_xattr(inode);
 
-		trimmed = erofs_trim_for_progressinfo(
-				erofs_fspath(inode->i_srcpath),
-				sizeof("Processing  ...") - 1);
-		erofs_update_progressinfo("Processing %s ...", trimmed);
-		free(trimmed);
+	ret = erofs_prepare_xattr_ibody(inode, incremental && IS_ROOT(inode));
+	if (ret < 0)
+		return ret;
 
-		err = erofs_mkfs_build_tree(inode, &dirs);
-		if (err) {
-			root = ERR_PTR(err);
-			break;
+	if (!S_ISDIR(inode->i_mode)) {
+		struct erofs_mkfs_job_ndir_ctx ctx =
+			{ .inode = inode, .fd = -1 };
+
+		if (S_ISREG(inode->i_mode) && inode->i_size &&
+		    inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
+			ctx.fd = erofs_diskbuf_getfd(inode->i_diskbuf, &ctx.fpos);
+			if (ctx.fd < 0)
+				return ret;
+
+			if (cfg.c_compr_opts[0].alg &&
+			    erofs_file_is_compressible(inode)) {
+				ctx.ictx = erofs_begin_compressed_file(inode,
+							ctx.fd, ctx.fpos);
+				if (IS_ERR(ctx.ictx))
+					return PTR_ERR(ctx.ictx);
+			}
 		}
+		ret = erofs_mkfs_go(inode->sbi, EROFS_MKFS_JOB_NDIR,
+				    &ctx, sizeof(ctx));
+	} else {
+		ret = erofs_rebuild_handle_directory(inode, incremental);
+	}
+	erofs_info("file %s dumped (mode %05o)", erofs_fspath(inode->i_srcpath),
+		   inode->i_mode);
+	return ret;
+}
 
-		if (S_ISDIR(inode->i_mode)) {
-			inode->next_dirwrite = dumpdir;
-			dumpdir = inode;
-		} else {
-			erofs_iput(inode);
+static bool erofs_inode_visited(struct erofs_inode *inode)
+{
+	return (unsigned long)inode->i_parent & 1UL;
+}
+
+static void erofs_mark_parent_inode(struct erofs_inode *inode,
+				    struct erofs_inode *dir)
+{
+	inode->i_parent = (void *)((unsigned long)dir | 1);
+}
+
+static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
+				bool incremental)
+{
+	struct erofs_sb_info *sbi = root->sbi;
+	struct erofs_inode *dumpdir = erofs_igrab(root);
+	int err;
+
+	erofs_mark_parent_inode(root, root);	/* rootdir mark */
+	root->next_dirwrite = NULL;
+	/* update dev/i_ino[1] to keep track of the base image */
+	if (incremental) {
+		root->dev = root->sbi->dev;
+		root->i_ino[1] = sbi->root_nid;
+		list_del(&root->i_hash);
+		erofs_insert_ihash(root);
+	} else if (cfg.c_root_xattr_isize) {
+		root->xattr_isize = cfg.c_root_xattr_isize;
+	}
+
+	err = !rebuild ? erofs_mkfs_handle_inode(root) :
+			erofs_rebuild_handle_inode(root, incremental);
+	if (err)
+		return err;
+
+	/* assign root NID immediately for non-incremental builds */
+	if (!incremental) {
+		erofs_mkfs_flushjobs(sbi);
+		erofs_fixup_meta_blkaddr(root);
+		sbi->root_nid = root->nid;
+	}
+
+	do {
+		int err;
+		struct erofs_inode *dir = dumpdir;
+		/* used for adding sub-directories in reverse order due to FIFO */
+		struct erofs_inode *head, **last = &head;
+		struct erofs_dentry *d;
+
+		dumpdir = dir->next_dirwrite;
+		list_for_each_entry(d, &dir->i_subdirs, d_child) {
+			struct erofs_inode *inode = d->inode;
+
+			if (is_dot_dotdot(d->name) || d->validnid)
+				continue;
+
+			if (!erofs_inode_visited(inode)) {
+				DBG_BUGON(rebuild &&
+					  erofs_parent_inode(inode) != dir);
+				erofs_mark_parent_inode(inode, dir);
+
+				if (!rebuild)
+					err = erofs_mkfs_handle_inode(inode);
+				else
+					err = erofs_rebuild_handle_inode(inode,
+								incremental);
+				if (err)
+					break;
+				if (S_ISDIR(inode->i_mode)) {
+					*last = inode;
+					last = &inode->next_dirwrite;
+					(void)erofs_igrab(inode);
+				}
+			} else if (!rebuild) {
+				++inode->i_nlink;
+			}
 		}
-	} while (!list_empty(&dirs));
+		*last = dumpdir;	/* fixup the last (or the only) one */
+		dumpdir = head;
+		err = erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR_BH,
+				    &dir, sizeof(dir));
+		if (err)
+			return err;
+	} while (dumpdir);
+
+	return err;
+}
 
-	while (dumpdir) {
-		inode = dumpdir;
-		erofs_write_dir_file(inode);
-		erofs_write_tail_end(inode);
-		inode->bh->op = &erofs_write_inode_bhops;
-		dumpdir = inode->next_dirwrite;
-		erofs_iput(inode);
+struct erofs_mkfs_buildtree_ctx {
+	struct erofs_sb_info *sbi;
+	union {
+		const char *path;
+		struct erofs_inode *root;
+	} u;
+	bool incremental;
+};
+#ifndef EROFS_MT_ENABLED
+#define __erofs_mkfs_build_tree erofs_mkfs_build_tree
+#endif
+
+static int __erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
+{
+	bool from_path = !!ctx->sbi;
+	struct erofs_inode *root;
+	int err;
+
+	if (from_path) {
+		root = erofs_iget_from_srcpath(ctx->sbi, ctx->u.path);
+		if (IS_ERR(root))
+			return PTR_ERR(root);
+	} else {
+		root = ctx->u.root;
 	}
-	return root;
+
+	err = erofs_mkfs_dump_tree(root, !from_path, ctx->incremental);
+	if (err) {
+		if (from_path)
+			erofs_iput(root);
+		return err;
+	}
+	ctx->u.root = root;
+	return 0;
+}
+
+#ifdef EROFS_MT_ENABLED
+static int erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
+{
+	struct erofs_mkfs_dfops *q;
+	int err, err2;
+	struct erofs_sb_info *sbi = ctx->sbi ? ctx->sbi : ctx->u.root->sbi;
+
+	q = malloc(sizeof(*q));
+	if (!q)
+		return -ENOMEM;
+
+	q->entries = EROFS_MT_QUEUE_SIZE;
+	q->queue = malloc(q->entries * sizeof(*q->queue));
+	if (!q->queue) {
+		free(q);
+		return -ENOMEM;
+	}
+	pthread_mutex_init(&q->lock, NULL);
+	pthread_cond_init(&q->empty, NULL);
+	pthread_cond_init(&q->full, NULL);
+	pthread_cond_init(&q->drain, NULL);
+
+	q->head = 0;
+	q->tail = 0;
+	sbi->mkfs_dfops = q;
+	err = pthread_create(&sbi->dfops_worker, NULL,
+			     z_erofs_mt_dfops_worker, sbi);
+	if (err)
+		goto fail;
+
+	err = __erofs_mkfs_build_tree(ctx);
+	erofs_mkfs_go(sbi, ~0, NULL, 0);
+	err2 = pthread_join(sbi->dfops_worker, NULL);
+	if (!err)
+		err = err2;
+
+fail:
+	pthread_cond_destroy(&q->empty);
+	pthread_cond_destroy(&q->full);
+	pthread_cond_destroy(&q->drain);
+	pthread_mutex_destroy(&q->lock);
+	free(q->queue);
+	free(q);
+	return err;
+}
+#endif
+
+struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_sb_info *sbi,
+						    const char *path)
+{
+	struct erofs_mkfs_buildtree_ctx ctx = {
+		.sbi = sbi,
+		.u.path = path,
+	};
+	int err;
+
+	if (!sbi)
+		return ERR_PTR(-EINVAL);
+	err = erofs_mkfs_build_tree(&ctx);
+	if (err)
+		return ERR_PTR(err);
+	return ctx.u.root;
 }
 
-struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name)
+int erofs_rebuild_dump_tree(struct erofs_inode *root, bool incremental)
+{
+	return erofs_mkfs_build_tree(&((struct erofs_mkfs_buildtree_ctx) {
+		.sbi = NULL,
+		.u.root = root,
+		.incremental = incremental,
+	}));
+}
+
+struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
+						     int fd, const char *name)
 {
 	struct stat st;
 	struct erofs_inode *inode;
+	void *ictx;
 	int ret;
 
 	ret = lseek(fd, 0, SEEK_SET);
@@ -1301,7 +1894,7 @@ struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name)
 	if (ret)
 		return ERR_PTR(-errno);
 
-	inode = erofs_new_inode();
+	inode = erofs_new_inode(sbi);
 	if (IS_ERR(inode))
 		return inode;
 
@@ -1321,119 +1914,94 @@ struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name)
 		inode->nid = inode->sbi->packed_nid;
 	}
 
-	ret = erofs_write_compressed_file(inode, fd);
-	if (ret == -ENOSPC) {
+	if (cfg.c_compr_opts[0].alg &&
+	    erofs_file_is_compressible(inode)) {
+		ictx = erofs_begin_compressed_file(inode, fd, 0);
+		if (IS_ERR(ictx))
+			return ERR_CAST(ictx);
+
+		DBG_BUGON(!ictx);
+		ret = erofs_write_compressed_file(ictx);
+		if (ret && ret != -ENOSPC)
+			 return ERR_PTR(ret);
+
 		ret = lseek(fd, 0, SEEK_SET);
 		if (ret < 0)
 			return ERR_PTR(-errno);
-
-		ret = write_uncompressed_file_from_fd(inode, fd);
 	}
-
-	if (ret) {
-		DBG_BUGON(ret == -ENOSPC);
+	ret = write_uncompressed_file_from_fd(inode, fd);
+	if (ret)
 		return ERR_PTR(ret);
-	}
 	erofs_prepare_inode_buffer(inode);
 	erofs_write_tail_end(inode);
 	return inode;
 }
 
-int erofs_rebuild_dump_tree(struct erofs_inode *dir)
+int erofs_fixup_root_inode(struct erofs_inode *root)
 {
-	struct erofs_dentry *d, *n;
-	unsigned int nr_subdirs;
-	int ret;
+	struct erofs_sb_info *sbi = root->sbi;
+	struct erofs_inode oi;
+	unsigned int ondisk_capacity, ondisk_size;
+	char *ibuf;
+	int err;
 
-	if (erofs_should_use_inode_extended(dir)) {
-		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
-			erofs_err("file %s cannot be in compact form",
-				  dir->i_srcpath);
-			return -EINVAL;
-		}
-		dir->inode_isize = sizeof(struct erofs_inode_extended);
-	} else {
-		dir->inode_isize = sizeof(struct erofs_inode_compact);
-	}
-
-	/* strip all unnecessary overlayfs xattrs when ovlfs_strip is enabled */
-	if (cfg.c_ovlfs_strip)
-		erofs_clear_opaque_xattr(dir);
-	else if (dir->whiteouts)
-		erofs_set_origin_xattr(dir);
-
-	ret = erofs_prepare_xattr_ibody(dir);
-	if (ret < 0)
-		return ret;
+	if (sbi->root_nid == root->nid)		/* for most mkfs cases */
+		return 0;
 
-	if (!S_ISDIR(dir->i_mode)) {
-		if (dir->bh)
-			return 0;
-		if (S_ISLNK(dir->i_mode)) {
-			ret = erofs_write_file_from_buffer(dir, dir->i_link);
-			free(dir->i_link);
-			dir->i_link = NULL;
-		} else if (dir->with_diskbuf) {
-			u64 fpos;
-
-			ret = erofs_diskbuf_getfd(dir->i_diskbuf, &fpos);
-			if (ret >= 0)
-				ret = erofs_write_file(dir, ret, fpos);
-			erofs_diskbuf_close(dir->i_diskbuf);
-			free(dir->i_diskbuf);
-			dir->i_diskbuf = NULL;
-			dir->with_diskbuf = false;
-		} else {
-			ret = 0;
-		}
-		if (ret)
-			return ret;
-		ret = erofs_prepare_inode_buffer(dir);
-		if (ret)
-			return ret;
-		erofs_write_tail_end(dir);
+	if (root->nid <= 0xffff) {
+		sbi->root_nid = root->nid;
 		return 0;
 	}
 
-	nr_subdirs = 0;
-	list_for_each_entry_safe(d, n, &dir->i_subdirs, d_child) {
-		if (cfg.c_ovlfs_strip && erofs_inode_is_whiteout(d->inode)) {
-			erofs_dbg("remove whiteout %s", d->inode->i_srcpath);
-			list_del(&d->d_child);
-			erofs_d_invalidate(d);
-			free(d);
-			continue;
-		}
-		++nr_subdirs;
+	oi = (struct erofs_inode){ .sbi = sbi, .nid = sbi->root_nid };
+	err = erofs_read_inode_from_disk(&oi);
+	if (err) {
+		erofs_err("failed to read root inode: %s",
+			  erofs_strerror(err));
+		return err;
 	}
 
-	ret = erofs_prepare_dir_layout(dir, nr_subdirs);
-	if (ret)
-		return ret;
+	if (oi.datalayout != EROFS_INODE_FLAT_INLINE &&
+	    oi.datalayout != EROFS_INODE_FLAT_PLAIN)
+		return -EOPNOTSUPP;
 
-	ret = erofs_prepare_inode_buffer(dir);
-	if (ret)
-		return ret;
-	dir->bh->op = &erofs_skip_write_bhops;
+	ondisk_capacity = oi.inode_isize + oi.xattr_isize;
+	if (oi.datalayout == EROFS_INODE_FLAT_INLINE)
+		ondisk_capacity += erofs_blkoff(sbi, oi.i_size);
 
-	if (IS_ROOT(dir))
-		erofs_fixup_meta_blkaddr(dir);
+	ondisk_size = root->inode_isize + root->xattr_isize;
+	if (root->extent_isize)
+		ondisk_size = roundup(ondisk_size, 8) + root->extent_isize;
+	ondisk_size += root->idata_size;
 
-	list_for_each_entry(d, &dir->i_subdirs, d_child) {
-		struct erofs_inode *inode;
+	if (ondisk_size > ondisk_capacity) {
+		erofs_err("no enough room for the root inode from nid %llu",
+			  root->nid);
+		return -ENOSPC;
+	}
 
-		if (is_dot_dotdot(d->name))
-			continue;
+	ibuf = malloc(ondisk_size);
+	if (!ibuf)
+		return -ENOMEM;
+	err = erofs_dev_read(sbi, 0, ibuf, erofs_iloc(root), ondisk_size);
+	if (err >= 0)
+		err = erofs_dev_write(sbi, ibuf, erofs_iloc(&oi), ondisk_size);
+	free(ibuf);
+	return err;
+}
 
-		inode = erofs_igrab(d->inode);
-		ret = erofs_rebuild_dump_tree(inode);
-		dir->i_nlink += (erofs_mode_to_ftype(inode->i_mode) == EROFS_FT_DIR);
-		erofs_iput(inode);
-		if (ret)
-			return ret;
-	}
-	erofs_write_dir_file(dir);
-	erofs_write_tail_end(dir);
-	dir->bh->op = &erofs_write_inode_bhops;
-	return 0;
+struct erofs_inode *erofs_rebuild_make_root(struct erofs_sb_info *sbi)
+{
+	struct erofs_inode *root;
+
+	root = erofs_new_inode(sbi);
+	if (IS_ERR(root))
+		return root;
+	root->i_srcpath = strdup("/");
+	root->i_mode = S_IFDIR | 0777;
+	root->i_parent = root;
+	root->i_mtime = root->sbi->build_time;
+	root->i_mtime_nsec = root->sbi->build_time_nsec;
+	erofs_init_empty_dir(root);
+	return root;
 }
diff --git a/lib/io.c b/lib/io.c
index c92f16c..b101c07 100644
--- a/lib/io.c
+++ b/lib/io.c
@@ -13,7 +13,7 @@
 #include <stdlib.h>
 #include <sys/stat.h>
 #include <sys/ioctl.h>
-#include "erofs/io.h"
+#include "erofs/internal.h"
 #ifdef HAVE_LINUX_FS_H
 #include <linux/fs.h>
 #endif
@@ -26,7 +26,156 @@
 #define EROFS_MODNAME	"erofs_io"
 #include "erofs/print.h"
 
-static int dev_get_blkdev_size(int fd, u64 *bytes)
+int erofs_io_fstat(struct erofs_vfile *vf, struct stat *buf)
+{
+	if (__erofs_unlikely(cfg.c_dry_run)) {
+		buf->st_size = 0;
+		buf->st_mode = S_IFREG | 0777;
+		return 0;
+	}
+
+	if (vf->ops)
+		return vf->ops->fstat(vf, buf);
+	return fstat(vf->fd, buf);
+}
+
+ssize_t erofs_io_pwrite(struct erofs_vfile *vf, const void *buf,
+			u64 pos, size_t len)
+{
+	ssize_t ret, written = 0;
+
+	if (__erofs_unlikely(cfg.c_dry_run))
+		return 0;
+
+	if (vf->ops)
+		return vf->ops->pwrite(vf, buf, pos, len);
+
+	pos += vf->offset;
+	do {
+#ifdef HAVE_PWRITE64
+		ret = pwrite64(vf->fd, buf, len, (off64_t)pos);
+#else
+		ret = pwrite(vf->fd, buf, len, (off_t)pos);
+#endif
+		if (ret <= 0) {
+			if (!ret)
+				break;
+			if (errno != EINTR) {
+				erofs_err("failed to write: %s", strerror(errno));
+				return -errno;
+			}
+			ret = 0;
+		}
+		buf += ret;
+		pos += ret;
+		written += ret;
+	} while (written < len);
+
+	return written;
+}
+
+int erofs_io_fsync(struct erofs_vfile *vf)
+{
+	int ret;
+
+	if (__erofs_unlikely(cfg.c_dry_run))
+		return 0;
+
+	if (vf->ops)
+		return vf->ops->fsync(vf);
+
+	ret = fsync(vf->fd);
+	if (ret) {
+		erofs_err("failed to fsync(!): %s", strerror(errno));
+		return -errno;
+	}
+	return 0;
+}
+
+ssize_t erofs_io_fallocate(struct erofs_vfile *vf, u64 offset,
+			   size_t len, bool zeroout)
+{
+	static const char zero[EROFS_MAX_BLOCK_SIZE] = {0};
+	ssize_t ret;
+
+	if (__erofs_unlikely(cfg.c_dry_run))
+		return 0;
+
+	if (vf->ops)
+		return vf->ops->fallocate(vf, offset, len, zeroout);
+
+#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
+	if (!zeroout && fallocate(vf->fd, FALLOC_FL_PUNCH_HOLE |
+		    FALLOC_FL_KEEP_SIZE, offset + vf->offset, len) >= 0)
+		return 0;
+#endif
+	while (len > EROFS_MAX_BLOCK_SIZE) {
+		ret = erofs_io_pwrite(vf, zero, offset, EROFS_MAX_BLOCK_SIZE);
+		if (ret < 0)
+			return ret;
+		len -= ret;
+		offset += ret;
+	}
+	return erofs_io_pwrite(vf, zero, offset, len) == len ? 0 : -EIO;
+}
+
+int erofs_io_ftruncate(struct erofs_vfile *vf, u64 length)
+{
+	int ret;
+	struct stat st;
+
+	if (__erofs_unlikely(cfg.c_dry_run))
+		return 0;
+
+	if (vf->ops)
+		return vf->ops->ftruncate(vf, length);
+
+	ret = fstat(vf->fd, &st);
+	if (ret) {
+		erofs_err("failed to fstat: %s", strerror(errno));
+		return -errno;
+	}
+	length += vf->offset;
+	if (S_ISBLK(st.st_mode) || st.st_size == length)
+		return 0;
+	return ftruncate(vf->fd, length);
+}
+
+ssize_t erofs_io_pread(struct erofs_vfile *vf, void *buf, u64 pos, size_t len)
+{
+	ssize_t ret, read = 0;
+
+	if (__erofs_unlikely(cfg.c_dry_run))
+		return 0;
+
+	if (vf->ops)
+		return vf->ops->pread(vf, buf, pos, len);
+
+	pos += vf->offset;
+	do {
+#ifdef HAVE_PREAD64
+		ret = pread64(vf->fd, buf, len, (off64_t)pos);
+#else
+		ret = pread(vf->fd, buf, len, (off_t)pos);
+#endif
+		if (ret <= 0) {
+			if (!ret)
+				break;
+			if (errno != EINTR) {
+				erofs_err("failed to read: %s", strerror(errno));
+				return -errno;
+			}
+			ret = 0;
+		}
+		pos += ret;
+		buf += ret;
+		read += ret;
+	} while (read < len);
+
+	return read;
+}
+
+static int erofs_get_bdev_size(int fd, u64 *bytes)
 {
 	errno = ENOTSUP;
 #ifdef BLKGETSIZE64
@@ -46,17 +195,25 @@ static int dev_get_blkdev_size(int fd, u64 *bytes)
 	return -errno;
 }
 
-void dev_close(struct erofs_sb_info *sbi)
+#if defined(__linux__) && !defined(BLKDISCARD)
+#define BLKDISCARD	_IO(0x12, 119)
+#endif
+
+static int erofs_bdev_discard(int fd, u64 block, u64 count)
 {
-	close(sbi->devfd);
-	free(sbi->devname);
-	sbi->devname = NULL;
-	sbi->devfd   = -1;
-	sbi->devsz   = 0;
+#ifdef BLKDISCARD
+	u64 range[2] = { block, count };
+
+	return ioctl(fd, BLKDISCARD, &range);
+#else
+	return -EOPNOTSUPP;
+#endif
 }
 
-int dev_open(struct erofs_sb_info *sbi, const char *dev)
+int erofs_dev_open(struct erofs_sb_info *sbi, const char *dev, int flags)
 {
+	bool ro = (flags & O_ACCMODE) == O_RDONLY;
+	bool truncate = flags & O_TRUNC;
 	struct stat st;
 	int fd, ret;
 
@@ -65,36 +222,46 @@ int dev_open(struct erofs_sb_info *sbi, const char *dev)
 
 repeat:
 #endif
-	fd = open(dev, O_RDWR | O_CREAT | O_BINARY, 0644);
+	fd = open(dev, (ro ? O_RDONLY : O_RDWR | O_CREAT) | O_BINARY, 0644);
 	if (fd < 0) {
-		erofs_err("failed to open(%s).", dev);
+		erofs_err("failed to open %s: %s", dev, strerror(errno));
 		return -errno;
 	}
 
+	if (ro || !truncate)
+		goto out;
+
 	ret = fstat(fd, &st);
 	if (ret) {
-		erofs_err("failed to fstat(%s).", dev);
+		erofs_err("failed to fstat(%s): %s", dev, strerror(errno));
 		close(fd);
 		return -errno;
 	}
 
 	switch (st.st_mode & S_IFMT) {
 	case S_IFBLK:
-		ret = dev_get_blkdev_size(fd, &sbi->devsz);
+		ret = erofs_get_bdev_size(fd, &sbi->devsz);
 		if (ret) {
-			erofs_err("failed to get block device size(%s).", dev);
+			erofs_err("failed to get block device size(%s): %s",
+				  dev, strerror(errno));
 			close(fd);
 			return ret;
 		}
 		sbi->devsz = round_down(sbi->devsz, erofs_blksiz(sbi));
+		ret = erofs_bdev_discard(fd, 0, sbi->devsz);
+		if (ret)
+			erofs_err("failed to erase block device(%s): %s",
+				  dev, erofs_strerror(ret));
 		break;
 	case S_IFREG:
 		if (st.st_size) {
 #if defined(HAVE_SYS_STATFS_H) && defined(HAVE_FSTATFS)
 			struct statfs stfs;
 
-			if (again)
+			if (again) {
+				close(fd);
 				return -ENOTEMPTY;
+			}
 
 			/*
 			 * fses like EXT4 and BTRFS will flush dirty blocks
@@ -117,8 +284,6 @@ repeat:
 				return -errno;
 			}
 		}
-		/* INT64_MAX is the limit of kernel vfs */
-		sbi->devsz = INT64_MAX;
 		sbi->devblksz = st.st_blksize;
 		break;
 	default:
@@ -127,18 +292,27 @@ repeat:
 		return -EINVAL;
 	}
 
+out:
 	sbi->devname = strdup(dev);
 	if (!sbi->devname) {
 		close(fd);
 		return -ENOMEM;
 	}
-	sbi->devfd = fd;
-
+	sbi->bdev.fd = fd;
 	erofs_info("successfully to open %s", dev);
 	return 0;
 }
 
-void blob_closeall(struct erofs_sb_info *sbi)
+void erofs_dev_close(struct erofs_sb_info *sbi)
+{
+	if (!sbi->bdev.ops)
+		close(sbi->bdev.fd);
+	free(sbi->devname);
+	sbi->devname = NULL;
+	sbi->bdev.fd = -1;
+}
+
+void erofs_blob_closeall(struct erofs_sb_info *sbi)
 {
 	unsigned int i;
 
@@ -147,7 +321,7 @@ void blob_closeall(struct erofs_sb_info *sbi)
 	sbi->nblobs = 0;
 }
 
-int blob_open_ro(struct erofs_sb_info *sbi, const char *dev)
+int erofs_blob_open_ro(struct erofs_sb_info *sbi, const char *dev)
 {
 	int fd = open(dev, O_RDONLY | O_BINARY);
 
@@ -162,180 +336,35 @@ int blob_open_ro(struct erofs_sb_info *sbi, const char *dev)
 	return 0;
 }
 
-/* XXX: temporary soluation. Disk I/O implementation needs to be refactored. */
-int dev_open_ro(struct erofs_sb_info *sbi, const char *dev)
-{
-	int fd = open(dev, O_RDONLY | O_BINARY);
-
-	if (fd < 0) {
-		erofs_err("failed to open(%s).", dev);
-		return -errno;
-	}
-
-	sbi->devname = strdup(dev);
-	if (!sbi->devname) {
-		close(fd);
-		return -ENOMEM;
-	}
-	sbi->devfd = fd;
-	sbi->devsz = INT64_MAX;
-	return 0;
-}
-
-int dev_write(struct erofs_sb_info *sbi, const void *buf, u64 offset, size_t len)
-{
-	int ret;
-
-	if (cfg.c_dry_run)
-		return 0;
-
-	if (!buf) {
-		erofs_err("buf is NULL");
-		return -EINVAL;
-	}
-
-	if (offset >= sbi->devsz || len > sbi->devsz ||
-	    offset > sbi->devsz - len) {
-		erofs_err("Write posion[%" PRIu64 ", %zd] is too large beyond the end of device(%" PRIu64 ").",
-			  offset, len, sbi->devsz);
-		return -EINVAL;
-	}
-
-#ifdef HAVE_PWRITE64
-	ret = pwrite64(sbi->devfd, buf, len, (off64_t)offset);
-#else
-	ret = pwrite(sbi->devfd, buf, len, (off_t)offset);
-#endif
-	if (ret != (int)len) {
-		if (ret < 0) {
-			erofs_err("Failed to write data into device - %s:[%" PRIu64 ", %zd].",
-				  sbi->devname, offset, len);
-			return -errno;
-		}
-
-		erofs_err("Writing data into device - %s:[%" PRIu64 ", %zd] - was truncated.",
-			  sbi->devname, offset, len);
-		return -ERANGE;
-	}
-	return 0;
-}
-
-int dev_fillzero(struct erofs_sb_info *sbi, u64 offset, size_t len, bool padding)
-{
-	static const char zero[EROFS_MAX_BLOCK_SIZE] = {0};
-	int ret;
-
-	if (cfg.c_dry_run)
-		return 0;
-
-#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
-	if (!padding && fallocate(sbi->devfd, FALLOC_FL_PUNCH_HOLE |
-				  FALLOC_FL_KEEP_SIZE, offset, len) >= 0)
-		return 0;
-#endif
-	while (len > erofs_blksiz(sbi)) {
-		ret = dev_write(sbi, zero, offset, erofs_blksiz(sbi));
-		if (ret)
-			return ret;
-		len -= erofs_blksiz(sbi);
-		offset += erofs_blksiz(sbi);
-	}
-	return dev_write(sbi, zero, offset, len);
-}
-
-int dev_fsync(struct erofs_sb_info *sbi)
-{
-	int ret;
-
-	ret = fsync(sbi->devfd);
-	if (ret) {
-		erofs_err("Could not fsync device!!!");
-		return -EIO;
-	}
-	return 0;
-}
-
-int dev_resize(struct erofs_sb_info *sbi, unsigned int blocks)
+ssize_t erofs_dev_read(struct erofs_sb_info *sbi, int device_id,
+		       void *buf, u64 offset, size_t len)
 {
-	int ret;
-	struct stat st;
-	u64 length;
-
-	if (cfg.c_dry_run || sbi->devsz != INT64_MAX)
-		return 0;
-
-	ret = fstat(sbi->devfd, &st);
-	if (ret) {
-		erofs_err("failed to fstat.");
-		return -errno;
-	}
-
-	length = (u64)blocks * erofs_blksiz(sbi);
-	if (st.st_size == length)
-		return 0;
-	if (st.st_size > length)
-		return ftruncate(sbi->devfd, length);
+	ssize_t read;
 
-	length = length - st.st_size;
-#if defined(HAVE_FALLOCATE)
-	if (fallocate(sbi->devfd, 0, st.st_size, length) >= 0)
-		return 0;
-#endif
-	return dev_fillzero(sbi, st.st_size, length, true);
-}
-
-int dev_read(struct erofs_sb_info *sbi, int device_id,
-	     void *buf, u64 offset, size_t len)
-{
-	int read_count, fd;
-
-	if (cfg.c_dry_run)
-		return 0;
-
-	offset += cfg.c_offset;
-
-	if (!buf) {
-		erofs_err("buf is NULL");
-		return -EINVAL;
-	}
-
-	if (!device_id) {
-		fd = sbi->devfd;
-	} else {
-		if (device_id > sbi->nblobs) {
+	if (device_id) {
+		if (device_id >= sbi->nblobs) {
 			erofs_err("invalid device id %d", device_id);
-			return -ENODEV;
+			return -EIO;
 		}
-		fd = sbi->blobfd[device_id - 1];
+		read = erofs_io_pread(&((struct erofs_vfile) {
+				.fd = sbi->blobfd[device_id - 1],
+			}), buf, offset, len);
+	} else {
+		read = erofs_io_pread(&sbi->bdev, buf, offset, len);
 	}
 
-	while (len > 0) {
-#ifdef HAVE_PREAD64
-		read_count = pread64(fd, buf, len, (off64_t)offset);
-#else
-		read_count = pread(fd, buf, len, (off_t)offset);
-#endif
-		if (read_count < 1) {
-			if (!read_count) {
-				erofs_info("Reach EOF of device - %s:[%" PRIu64 ", %zd].",
-					   sbi->devname, offset, len);
-				memset(buf, 0, len);
-				return 0;
-			} else if (errno != EINTR) {
-				erofs_err("Failed to read data from device - %s:[%" PRIu64 ", %zd].",
-					  sbi->devname, offset, len);
-				return -errno;
-			}
-		}
-		offset += read_count;
-		len -= read_count;
-		buf += read_count;
+	if (read < 0)
+		return read;
+	if (read < len) {
+		erofs_info("reach EOF of device @ %llu, pading with zeroes",
+			   offset | 0ULL);
+		memset(buf + read, 0, len - read);
 	}
 	return 0;
 }
 
-static ssize_t __erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
-				       int fd_out, erofs_off_t *off_out,
+static ssize_t __erofs_copy_file_range(int fd_in, u64 *off_in,
+				       int fd_out, u64 *off_out,
 				       size_t length)
 {
 	size_t copied = 0;
@@ -406,8 +435,7 @@ static ssize_t __erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
 	return copied;
 }
 
-ssize_t erofs_copy_file_range(int fd_in, erofs_off_t *off_in,
-			      int fd_out, erofs_off_t *off_out,
+ssize_t erofs_copy_file_range(int fd_in, u64 *off_in, int fd_out, u64 *off_out,
 			      size_t length)
 {
 #ifdef HAVE_COPY_FILE_RANGE
@@ -428,3 +456,88 @@ out:
 #endif
 	return __erofs_copy_file_range(fd_in, off_in, fd_out, off_out, length);
 }
+
+ssize_t erofs_io_read(struct erofs_vfile *vf, void *buf, size_t bytes)
+{
+	ssize_t i = 0;
+
+	if (vf->ops)
+		return vf->ops->read(vf, buf, bytes);
+
+	while (bytes) {
+		int len = bytes > INT_MAX ? INT_MAX : bytes;
+		int ret;
+
+		ret = read(vf->fd, buf + i, len);
+		if (ret < 1) {
+			if (ret == 0) {
+				break;
+			} else if (errno != EINTR) {
+				erofs_err("failed to read : %s",
+					  strerror(errno));
+				return -errno;
+			}
+		}
+		bytes -= ret;
+		i += ret;
+        }
+        return i;
+}
+
+#ifdef HAVE_SYS_SENDFILE_H
+#include <sys/sendfile.h>
+#endif
+
+off_t erofs_io_lseek(struct erofs_vfile *vf, u64 offset, int whence)
+{
+	if (vf->ops)
+		return vf->ops->lseek(vf, offset, whence);
+
+	return lseek(vf->fd, offset, whence);
+}
+
+int erofs_io_xcopy(struct erofs_vfile *vout, off_t pos,
+		   struct erofs_vfile *vin, unsigned int len, bool noseek)
+{
+	if (vout->ops)
+		return vout->ops->xcopy(vout, pos, vin, len, noseek);
+
+	if (len && !vin->ops) {
+		off_t ret __maybe_unused;
+
+#ifdef HAVE_COPY_FILE_RANGE
+		ret = copy_file_range(vin->fd, NULL, vout->fd, &pos, len, 0);
+		if (ret > 0)
+			len -= ret;
+#endif
+#if defined(HAVE_SYS_SENDFILE_H) && defined(HAVE_SENDFILE)
+		if (len && !noseek) {
+			ret = lseek(vout->fd, pos, SEEK_SET);
+			if (ret == pos) {
+				ret = sendfile(vout->fd, vin->fd, NULL, len);
+				if (ret > 0) {
+					pos += ret;
+					len -= ret;
+				}
+			}
+		}
+#endif
+	}
+
+	do {
+		char buf[32768];
+		int ret = min_t(unsigned int, len, sizeof(buf));
+
+		ret = erofs_io_read(vin, buf, ret);
+		if (ret < 0)
+			return ret;
+		if (ret > 0) {
+			ret = erofs_io_pwrite(vout, buf, pos, ret);
+			if (ret < 0)
+				return ret;
+			pos += ret;
+		}
+		len -= ret;
+	} while (len);
+	return 0;
+}
diff --git a/lib/kite_deflate.c b/lib/kite_deflate.c
index 8667954..8581834 100644
--- a/lib/kite_deflate.c
+++ b/lib/kite_deflate.c
@@ -746,7 +746,7 @@ int kite_mf_getmatches_hc3(struct kite_matchfinder *mf, u16 depth, u16 bestlen)
 	unsigned int v, hv, i, k, p, wsiz;
 
 	if (mf->end - cur < bestlen + 1)
-		return 0;
+		return -1;
 
 	v = get_unaligned((u16 *)cur);
 	hv = v ^ crc_ccitt_table[cur[2]];
@@ -795,6 +795,14 @@ int kite_mf_getmatches_hc3(struct kite_matchfinder *mf, u16 depth, u16 bestlen)
 	return k - 1;
 }
 
+static void kite_mf_hc3_skip(struct kite_matchfinder *mf)
+{
+	if (kite_mf_getmatches_hc3(mf, 0, 2) >= 0)
+		return;
+	mf->offset++;
+	/* mf->cyclic_pos = (mf->cyclic_pos + 1) & (mf->wsiz - 1); */
+}
+
 /* let's align with zlib */
 static const struct kite_matchfinder_cfg {
 	u16  good_length;	/* reduce lazy search above this match length */
@@ -817,7 +825,8 @@ static const struct kite_matchfinder_cfg {
 /* 9 */ {32, 258, 258, 4096, true},	/* maximum compression */
 };
 
-static int kite_mf_init(struct kite_matchfinder *mf, int wsiz, int level)
+static int kite_mf_init(struct kite_matchfinder *mf, unsigned int wsiz,
+			int level)
 {
 	const struct kite_matchfinder_cfg *cfg;
 
@@ -859,6 +868,17 @@ static void kite_mf_reset(struct kite_matchfinder *mf,
 	 */
 	mf->base += mf->offset + kHistorySize32 + 1;
 
+	/*
+	 * Unlike other LZ encoders like liblzma [1], we simply reset the hash
+	 * chain instead of normalization.  This avoids extra complexity, as we
+	 * don't consider extreme large input buffers in one go.
+	 *
+	 * [1] https://github.com/tukaani-project/xz/blob/v5.4.0/src/liblzma/lz/lz_encoder_mf.c#L94
+	 */
+	if (__erofs_unlikely(mf->base > ((typeof(mf->base))-1) >> 1)) {
+		mf->base = kHistorySize32 + 1;
+		memset(mf->hash, 0, 0x10000 * sizeof(mf->hash[0]));
+	}
 	mf->offset = 0;
 	mf->cyclic_pos = 0;
 
@@ -1045,7 +1065,7 @@ static bool kite_deflate_fast(struct kite_deflate *s)
 		int matches = kite_mf_getmatches_hc3(mf, mf->depth,
 				kMatchMinLen - 1);
 
-		if (matches) {
+		if (matches > 0) {
 			unsigned int len = mf->matches[matches].len;
 			unsigned int dist = mf->matches[matches].dist;
 
@@ -1060,7 +1080,7 @@ static bool kite_deflate_fast(struct kite_deflate *s)
 			s->pos_in += len;
 			/* skip the rest bytes */
 			while (--len)
-				(void)kite_mf_getmatches_hc3(mf, 0, 0);
+				kite_mf_hc3_skip(mf);
 		} else {
 nomatch:
 			mf->matches[0].dist = s->in[s->pos_in];
@@ -1103,17 +1123,19 @@ static bool kite_deflate_slow(struct kite_deflate *s)
 		if (len0 < mf->max_lazy) {
 			matches = kite_mf_getmatches_hc3(mf, mf->depth >>
 				(len0 >= mf->good_len), len0);
-			if (matches) {
+			if (matches > 0) {
 				len = mf->matches[matches].len;
 				if (len == kMatchMinLen &&
 				    mf->matches[matches].dist > ZLIB_DISTANCE_TOO_FAR) {
 					matches = 0;
 					len = kMatchMinLen - 1;
 				}
+			} else {
+				matches = 0;
 			}
 		} else {
 			matches = 0;
-			(void)kite_mf_getmatches_hc3(mf, 0, 0);
+			kite_mf_hc3_skip(mf);
 		}
 
 		if (len < len0) {
@@ -1124,7 +1146,7 @@ static bool kite_deflate_slow(struct kite_deflate *s)
 			s->pos_in += --len0;
 			/* skip the rest bytes */
 			while (--len0)
-				(void)kite_mf_getmatches_hc3(mf, 0, 0);
+				kite_mf_hc3_skip(mf);
 			s->prev_valid = false;
 			s->prev_longest = 0;
 		} else {
diff --git a/lib/namei.c b/lib/namei.c
index 294d7a3..6f35ee6 100644
--- a/lib/namei.c
+++ b/lib/namei.c
@@ -12,7 +12,7 @@
 #include <sys/sysmacros.h>
 #endif
 #include "erofs/print.h"
-#include "erofs/io.h"
+#include "erofs/internal.h"
 
 static dev_t erofs_new_decode_dev(u32 dev)
 {
@@ -34,7 +34,7 @@ int erofs_read_inode_from_disk(struct erofs_inode *vi)
 	DBG_BUGON(!sbi);
 	inode_loc = erofs_iloc(vi);
 
-	ret = dev_read(sbi, 0, buf, inode_loc, sizeof(*dic));
+	ret = erofs_dev_read(sbi, 0, buf, inode_loc, sizeof(*dic));
 	if (ret < 0)
 		return -EIO;
 
@@ -51,7 +51,7 @@ int erofs_read_inode_from_disk(struct erofs_inode *vi)
 	case EROFS_INODE_LAYOUT_EXTENDED:
 		vi->inode_isize = sizeof(struct erofs_inode_extended);
 
-		ret = dev_read(sbi, 0, buf + sizeof(*dic),
+		ret = erofs_dev_read(sbi, 0, buf + sizeof(*dic),
 			       inode_loc + sizeof(*dic),
 			       sizeof(*die) - sizeof(*dic));
 		if (ret < 0)
diff --git a/lib/rb_tree.c b/lib/rb_tree.c
deleted file mode 100644
index 28800a9..0000000
--- a/lib/rb_tree.c
+++ /dev/null
@@ -1,512 +0,0 @@
-// SPDX-License-Identifier: Unlicense
-//
-// Based on Julienne Walker's <http://eternallyconfuzzled.com/> rb_tree
-// implementation.
-//
-// Modified by Mirek Rusin <http://github.com/mirek/rb_tree>.
-//
-// This is free and unencumbered software released into the public domain.
-//
-// Anyone is free to copy, modify, publish, use, compile, sell, or
-// distribute this software, either in source code form or as a compiled
-// binary, for any purpose, commercial or non-commercial, and by any
-// means.
-//
-// In jurisdictions that recognize copyright laws, the author or authors
-// of this software dedicate any and all copyright interest in the
-// software to the public domain. We make this dedication for the benefit
-// of the public at large and to the detriment of our heirs and
-// successors. We intend this dedication to be an overt act of
-// relinquishment in perpetuity of all present and future rights to this
-// software under copyright law.
-//
-// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
-// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
-// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
-// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
-// OTHER DEALINGS IN THE SOFTWARE.
-//
-// For more information, please refer to <http://unlicense.org/>
-//
-
-#include "rb_tree.h"
-
-// rb_node
-
-struct rb_node *
-rb_node_alloc () {
-    return malloc(sizeof(struct rb_node));
-}
-
-struct rb_node *
-rb_node_init (struct rb_node *self, void *value) {
-    if (self) {
-        self->red = 1;
-        self->link[0] = self->link[1] = NULL;
-        self->value = value;
-    }
-    return self;
-}
-
-struct rb_node *
-rb_node_create (void *value) {
-    return rb_node_init(rb_node_alloc(), value);
-}
-
-void
-rb_node_dealloc (struct rb_node *self) {
-    if (self) {
-        free(self);
-    }
-}
-
-static int
-rb_node_is_red (const struct rb_node *self) {
-    return self ? self->red : 0;
-}
-
-static struct rb_node *
-rb_node_rotate (struct rb_node *self, int dir) {
-    struct rb_node *result = NULL;
-    if (self) {
-        result = self->link[!dir];
-        self->link[!dir] = result->link[dir];
-        result->link[dir] = self;
-        self->red = 1;
-        result->red = 0;
-    }
-    return result;
-}
-
-static struct rb_node *
-rb_node_rotate2 (struct rb_node *self, int dir) {
-    struct rb_node *result = NULL;
-    if (self) {
-        self->link[!dir] = rb_node_rotate(self->link[!dir], !dir);
-        result = rb_node_rotate(self, dir);
-    }
-    return result;
-}
-
-// rb_tree - default callbacks
-
-int
-rb_tree_node_cmp_ptr_cb (struct rb_tree *self, struct rb_node *a, struct rb_node *b) {
-    return (a->value > b->value) - (a->value < b->value);
-}
-
-void
-rb_tree_node_dealloc_cb (struct rb_tree *self, struct rb_node *node) {
-    if (self) {
-        if (node) {
-            rb_node_dealloc(node);
-        }
-    }
-}
-
-// rb_tree
-
-struct rb_tree *
-rb_tree_alloc () {
-    return malloc(sizeof(struct rb_tree));
-}
-
-struct rb_tree *
-rb_tree_init (struct rb_tree *self, rb_tree_node_cmp_f node_cmp_cb) {
-    if (self) {
-        self->root = NULL;
-        self->size = 0;
-        self->cmp = node_cmp_cb ? node_cmp_cb : rb_tree_node_cmp_ptr_cb;
-    }
-    return self;
-}
-
-struct rb_tree *
-rb_tree_create (rb_tree_node_cmp_f node_cb) {
-    return rb_tree_init(rb_tree_alloc(), node_cb);
-}
-
-void
-rb_tree_dealloc (struct rb_tree *self, rb_tree_node_f node_cb) {
-    if (self) {
-        if (node_cb) {
-            struct rb_node *node = self->root;
-            struct rb_node *save = NULL;
-
-            // Rotate away the left links so that
-            // we can treat this like the destruction
-            // of a linked list
-            while (node) {
-                if (node->link[0] == NULL) {
-
-                    // No left links, just kill the node and move on
-                    save = node->link[1];
-                    node_cb(self, node);
-                    node = NULL;
-                } else {
-
-                    // Rotate away the left link and check again
-                    save = node->link[0];
-                    node->link[0] = save->link[1];
-                    save->link[1] = node;
-                }
-                node = save;
-            }
-        }
-        free(self);
-    }
-}
-
-int
-rb_tree_test (struct rb_tree *self, struct rb_node *root) {
-    int lh, rh;
-
-    if ( root == NULL )
-        return 1;
-    else {
-        struct rb_node *ln = root->link[0];
-        struct rb_node *rn = root->link[1];
-
-        /* Consecutive red links */
-        if (rb_node_is_red(root)) {
-            if (rb_node_is_red(ln) || rb_node_is_red(rn)) {
-                printf("Red violation");
-                return 0;
-            }
-        }
-
-        lh = rb_tree_test(self, ln);
-        rh = rb_tree_test(self, rn);
-
-        /* Invalid binary search tree */
-        if ( ( ln != NULL && self->cmp(self, ln, root) >= 0 )
-            || ( rn != NULL && self->cmp(self, rn, root) <= 0))
-        {
-            puts ( "Binary tree violation" );
-            return 0;
-        }
-
-        /* Black height mismatch */
-        if ( lh != 0 && rh != 0 && lh != rh ) {
-            puts ( "Black violation" );
-            return 0;
-        }
-
-        /* Only count black links */
-        if ( lh != 0 && rh != 0 )
-            return rb_node_is_red ( root ) ? lh : lh + 1;
-        else
-            return 0;
-    }
-}
-
-void *
-rb_tree_find(struct rb_tree *self, void *value) {
-    void *result = NULL;
-    if (self) {
-        struct rb_node node = { .value = value };
-        struct rb_node *it = self->root;
-        int cmp = 0;
-        while (it) {
-            if ((cmp = self->cmp(self, it, &node))) {
-
-                // If the tree supports duplicates, they should be
-                // chained to the right subtree for this to work
-                it = it->link[cmp < 0];
-            } else {
-                break;
-            }
-        }
-        result = it ? it->value : NULL;
-    }
-    return result;
-}
-
-// Creates (malloc'ates)
-int
-rb_tree_insert (struct rb_tree *self, void *value) {
-    return rb_tree_insert_node(self, rb_node_create(value));
-}
-
-// Returns 1 on success, 0 otherwise.
-int
-rb_tree_insert_node (struct rb_tree *self, struct rb_node *node) {
-    if (self && node) {
-        if (self->root == NULL) {
-            self->root = node;
-        } else {
-            struct rb_node head = { 0 }; // False tree root
-            struct rb_node *g, *t;       // Grandparent & parent
-            struct rb_node *p, *q;       // Iterator & parent
-            int dir = 0, last = 0;
-
-            // Set up our helpers
-            t = &head;
-            g = p = NULL;
-            q = t->link[1] = self->root;
-
-            // Search down the tree for a place to insert
-            while (1) {
-                if (q == NULL) {
-
-                    // Insert node at the first null link.
-                    p->link[dir] = q = node;
-                } else if (rb_node_is_red(q->link[0]) && rb_node_is_red(q->link[1])) {
-
-                    // Simple red violation: color flip
-                    q->red = 1;
-                    q->link[0]->red = 0;
-                    q->link[1]->red = 0;
-                }
-
-                if (rb_node_is_red(q) && rb_node_is_red(p)) {
-
-                    // Hard red violation: rotations necessary
-                    int dir2 = t->link[1] == g;
-                    if (q == p->link[last]) {
-                        t->link[dir2] = rb_node_rotate(g, !last);
-                    } else {
-                        t->link[dir2] = rb_node_rotate2(g, !last);
-                    }
-                }
-
-                // Stop working if we inserted a node. This
-                // check also disallows duplicates in the tree
-                if (self->cmp(self, q, node) == 0) {
-                    break;
-                }
-
-                last = dir;
-                dir = self->cmp(self, q, node) < 0;
-
-                // Move the helpers down
-                if (g != NULL) {
-                    t = g;
-                }
-
-                g = p, p = q;
-                q = q->link[dir];
-            }
-
-            // Update the root (it may be different)
-            self->root = head.link[1];
-        }
-
-        // Make the root black for simplified logic
-        self->root->red = 0;
-        ++self->size;
-        return 1;
-    }
-    return 0;
-}
-
-// Returns 1 if the value was removed, 0 otherwise. Optional node callback
-// can be provided to dealloc node and/or user data. Use rb_tree_node_dealloc
-// default callback to deallocate node created by rb_tree_insert(...).
-int
-rb_tree_remove_with_cb (struct rb_tree *self, void *value, rb_tree_node_f node_cb) {
-    if (self->root != NULL) {
-        struct rb_node head = {0}; // False tree root
-        struct rb_node node = { .value = value }; // Value wrapper node
-        struct rb_node *q, *p, *g; // Helpers
-        struct rb_node *f = NULL;  // Found item
-        int dir = 1;
-
-        // Set up our helpers
-        q = &head;
-        g = p = NULL;
-        q->link[1] = self->root;
-
-        // Search and push a red node down
-        // to fix red violations as we go
-        while (q->link[dir] != NULL) {
-            int last = dir;
-
-            // Move the helpers down
-            g = p, p = q;
-            q = q->link[dir];
-            dir = self->cmp(self, q, &node) < 0;
-
-            // Save the node with matching value and keep
-            // going; we'll do removal tasks at the end
-            if (self->cmp(self, q, &node) == 0) {
-                f = q;
-            }
-
-            // Push the red node down with rotations and color flips
-            if (!rb_node_is_red(q) && !rb_node_is_red(q->link[dir])) {
-                if (rb_node_is_red(q->link[!dir])) {
-                    p = p->link[last] = rb_node_rotate(q, dir);
-                } else if (!rb_node_is_red(q->link[!dir])) {
-                    struct rb_node *s = p->link[!last];
-                    if (s) {
-                        if (!rb_node_is_red(s->link[!last]) && !rb_node_is_red(s->link[last])) {
-
-                            // Color flip
-                            p->red = 0;
-                            s->red = 1;
-                            q->red = 1;
-                        } else {
-                            int dir2 = g->link[1] == p;
-                            if (rb_node_is_red(s->link[last])) {
-                                g->link[dir2] = rb_node_rotate2(p, last);
-                            } else if (rb_node_is_red(s->link[!last])) {
-                                g->link[dir2] = rb_node_rotate(p, last);
-                            }
-
-                            // Ensure correct coloring
-                            q->red = g->link[dir2]->red = 1;
-                            g->link[dir2]->link[0]->red = 0;
-                            g->link[dir2]->link[1]->red = 0;
-                        }
-                    }
-                }
-            }
-        }
-
-        // Replace and remove the saved node
-        if (f) {
-            void *tmp = f->value;
-            f->value = q->value;
-            q->value = tmp;
-
-            p->link[p->link[1] == q] = q->link[q->link[0] == NULL];
-
-            if (node_cb) {
-                node_cb(self, q);
-            }
-            q = NULL;
-        }
-
-        // Update the root (it may be different)
-        self->root = head.link[1];
-
-        // Make the root black for simplified logic
-        if (self->root != NULL) {
-            self->root->red = 0;
-        }
-
-        --self->size;
-    }
-    return 1;
-}
-
-int
-rb_tree_remove (struct rb_tree *self, void *value) {
-    int result = 0;
-    if (self) {
-        result = rb_tree_remove_with_cb(self, value, rb_tree_node_dealloc_cb);
-    }
-    return result;
-}
-
-size_t
-rb_tree_size (struct rb_tree *self) {
-    size_t result = 0;
-    if (self) {
-        result = self->size;
-    }
-    return result;
-}
-
-// rb_iter
-
-struct rb_iter *
-rb_iter_alloc () {
-    return malloc(sizeof(struct rb_iter));
-}
-
-struct rb_iter *
-rb_iter_init (struct rb_iter *self) {
-    if (self) {
-        self->tree = NULL;
-        self->node = NULL;
-        self->top = 0;
-    }
-    return self;
-}
-
-struct rb_iter *
-rb_iter_create () {
-    return rb_iter_init(rb_iter_alloc());
-}
-
-void
-rb_iter_dealloc (struct rb_iter *self) {
-    if (self) {
-        free(self);
-    }
-}
-
-// Internal function, init traversal object, dir determines whether
-// to begin traversal at the smallest or largest valued node.
-static void *
-rb_iter_start (struct rb_iter *self, struct rb_tree *tree, int dir) {
-    void *result = NULL;
-    if (self) {
-        self->tree = tree;
-        self->node = tree->root;
-        self->top = 0;
-
-        // Save the path for later selfersal
-        if (self->node != NULL) {
-            while (self->node->link[dir] != NULL) {
-                self->path[self->top++] = self->node;
-                self->node = self->node->link[dir];
-            }
-        }
-
-        result = self->node == NULL ? NULL : self->node->value;
-    }
-    return result;
-}
-
-// Traverse a red black tree in the user-specified direction (0 asc, 1 desc)
-static void *
-rb_iter_move (struct rb_iter *self, int dir) {
-    if (self->node->link[dir] != NULL) {
-
-        // Continue down this branch
-        self->path[self->top++] = self->node;
-        self->node = self->node->link[dir];
-        while ( self->node->link[!dir] != NULL ) {
-            self->path[self->top++] = self->node;
-            self->node = self->node->link[!dir];
-        }
-    } else {
-
-        // Move to the next branch
-        struct rb_node *last = NULL;
-        do {
-            if (self->top == 0) {
-                self->node = NULL;
-                break;
-            }
-            last = self->node;
-            self->node = self->path[--self->top];
-        } while (last == self->node->link[dir]);
-    }
-    return self->node == NULL ? NULL : self->node->value;
-}
-
-void *
-rb_iter_first (struct rb_iter *self, struct rb_tree *tree) {
-    return rb_iter_start(self, tree, 0);
-}
-
-void *
-rb_iter_last (struct rb_iter *self, struct rb_tree *tree) {
-    return rb_iter_start(self, tree, 1);
-}
-
-void *
-rb_iter_next (struct rb_iter *self) {
-    return rb_iter_move(self, 1);
-}
-
-void *
-rb_iter_prev (struct rb_iter *self) {
-    return rb_iter_move(self, 0);
-}
diff --git a/lib/rb_tree.h b/lib/rb_tree.h
deleted file mode 100644
index 67ec0a7..0000000
--- a/lib/rb_tree.h
+++ /dev/null
@@ -1,104 +0,0 @@
-/* SPDX-License-Identifier: Unlicense */
-//
-// Based on Julienne Walker's <http://eternallyconfuzzled.com/> rb_tree
-// implementation.
-//
-// Modified by Mirek Rusin <http://github.com/mirek/rb_tree>.
-//
-// This is free and unencumbered software released into the public domain.
-//
-// Anyone is free to copy, modify, publish, use, compile, sell, or
-// distribute this software, either in source code form or as a compiled
-// binary, for any purpose, commercial or non-commercial, and by any
-// means.
-//
-// In jurisdictions that recognize copyright laws, the author or authors
-// of this software dedicate any and all copyright interest in the
-// software to the public domain. We make this dedication for the benefit
-// of the public at large and to the detriment of our heirs and
-// successors. We intend this dedication to be an overt act of
-// relinquishment in perpetuity of all present and future rights to this
-// software under copyright law.
-//
-// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
-// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
-// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
-// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
-// OTHER DEALINGS IN THE SOFTWARE.
-//
-// For more information, please refer to <http://unlicense.org/>
-//
-
-#ifndef __RB_TREE_H__
-#define __RB_TREE_H__ 1
-
-#include <stdio.h>
-#include <stdint.h>
-#include <stddef.h>
-#include <stdlib.h>
-
-#ifndef RB_ITER_MAX_HEIGHT
-#define RB_ITER_MAX_HEIGHT 64 // Tallest allowable tree to iterate
-#endif
-
-struct rb_node;
-struct rb_tree;
-
-typedef int  (*rb_tree_node_cmp_f) (struct rb_tree *self, struct rb_node *a, struct rb_node *b);
-typedef void (*rb_tree_node_f)     (struct rb_tree *self, struct rb_node *node);
-
-struct rb_node {
-    int             red;     // Color red (1), black (0)
-    struct rb_node *link[2]; // Link left [0] and right [1]
-    void           *value;   // User provided, used indirectly via rb_tree_node_cmp_f.
-};
-
-struct rb_tree {
-    struct rb_node    *root;
-    rb_tree_node_cmp_f cmp;
-    size_t             size;
-    void              *info; // User provided, not used by rb_tree.
-};
-
-struct rb_iter {
-    struct rb_tree *tree;
-    struct rb_node *node;                     // Current node
-    struct rb_node *path[RB_ITER_MAX_HEIGHT]; // Traversal path
-    size_t          top;                      // Top of stack
-    void           *info;                     // User provided, not used by rb_iter.
-};
-
-int             rb_tree_node_cmp_ptr_cb (struct rb_tree *self, struct rb_node *a, struct rb_node *b);
-void            rb_tree_node_dealloc_cb (struct rb_tree *self, struct rb_node *node);
-
-struct rb_node *rb_node_alloc           ();
-struct rb_node *rb_node_create          (void *value);
-struct rb_node *rb_node_init            (struct rb_node *self, void *value);
-void            rb_node_dealloc         (struct rb_node *self);
-
-struct rb_tree *rb_tree_alloc           ();
-struct rb_tree *rb_tree_create          (rb_tree_node_cmp_f cmp);
-struct rb_tree *rb_tree_init            (struct rb_tree *self, rb_tree_node_cmp_f cmp);
-void            rb_tree_dealloc         (struct rb_tree *self, rb_tree_node_f node_cb);
-void           *rb_tree_find            (struct rb_tree *self, void *value);
-int             rb_tree_insert          (struct rb_tree *self, void *value);
-int             rb_tree_remove          (struct rb_tree *self, void *value);
-size_t          rb_tree_size            (struct rb_tree *self);
-
-int             rb_tree_insert_node     (struct rb_tree *self, struct rb_node *node);
-int             rb_tree_remove_with_cb  (struct rb_tree *self, void *value, rb_tree_node_f node_cb);
-
-int             rb_tree_test            (struct rb_tree *self, struct rb_node *root);
-
-struct rb_iter *rb_iter_alloc           ();
-struct rb_iter *rb_iter_init            (struct rb_iter *self);
-struct rb_iter *rb_iter_create          ();
-void            rb_iter_dealloc         (struct rb_iter *self);
-void           *rb_iter_first           (struct rb_iter *self, struct rb_tree *tree);
-void           *rb_iter_last            (struct rb_iter *self, struct rb_tree *tree);
-void           *rb_iter_next            (struct rb_iter *self);
-void           *rb_iter_prev            (struct rb_iter *self);
-
-#endif
diff --git a/lib/rebuild.c b/lib/rebuild.c
index 5993730..08c1b86 100644
--- a/lib/rebuild.c
+++ b/lib/rebuild.c
@@ -11,11 +11,11 @@
 #include "erofs/print.h"
 #include "erofs/inode.h"
 #include "erofs/rebuild.h"
-#include "erofs/io.h"
 #include "erofs/dir.h"
 #include "erofs/xattr.h"
 #include "erofs/blobchunk.h"
 #include "erofs/internal.h"
+#include "liberofs_uuid.h"
 
 #ifdef HAVE_LINUX_AUFS_TYPE_H
 #include <linux/aufs_type.h>
@@ -31,10 +31,15 @@ static struct erofs_dentry *erofs_rebuild_mkdir(struct erofs_inode *dir,
 	struct erofs_inode *inode;
 	struct erofs_dentry *d;
 
-	inode = erofs_new_inode();
+	inode = erofs_new_inode(dir->sbi);
 	if (IS_ERR(inode))
 		return ERR_CAST(inode);
 
+	if (asprintf(&inode->i_srcpath, "%s/%s",
+		     dir->i_srcpath ? : "", s) < 0) {
+		erofs_iput(inode);
+		return ERR_PTR(-ENOMEM);
+	}
 	inode->i_mode = S_IFDIR | 0755;
 	inode->i_parent = dir;
 	inode->i_uid = getuid();
@@ -44,7 +49,9 @@ static struct erofs_dentry *erofs_rebuild_mkdir(struct erofs_inode *dir,
 	erofs_init_empty_dir(inode);
 
 	d = erofs_d_alloc(dir, s);
-	if (!IS_ERR(d)) {
+	if (IS_ERR(d)) {
+		erofs_iput(inode);
+	} else {
 		d->type = EROFS_FT_DIR;
 		d->inode = inode;
 	}
@@ -128,7 +135,8 @@ struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
 	return d;
 }
 
-static int erofs_rebuild_fixup_inode_index(struct erofs_inode *inode)
+static int erofs_rebuild_write_blob_index(struct erofs_sb_info *dst_sb,
+					  struct erofs_inode *inode)
 {
 	int ret;
 	unsigned int count, unit, chunkbits, i;
@@ -137,26 +145,26 @@ static int erofs_rebuild_fixup_inode_index(struct erofs_inode *inode)
 	erofs_blk_t blkaddr;
 
 	/* TODO: fill data map in other layouts */
-	if (inode->datalayout != EROFS_INODE_CHUNK_BASED &&
-	    inode->datalayout != EROFS_INODE_FLAT_PLAIN) {
-		erofs_err("%s: unsupported datalayout %d", inode->i_srcpath, inode->datalayout);
-		return -EOPNOTSUPP;
-	}
-
-	if (inode->sbi->extra_devices) {
+	if (inode->datalayout == EROFS_INODE_CHUNK_BASED) {
 		chunkbits = inode->u.chunkbits;
-		if (chunkbits < sbi.blkszbits) {
-			erofs_err("%s: chunk size %u is too small to fit the target block size %u",
-				  inode->i_srcpath, 1U << chunkbits, 1U << sbi.blkszbits);
+		if (chunkbits < dst_sb->blkszbits) {
+			erofs_err("%s: chunk size %u is smaller than the target block size %u",
+				  inode->i_srcpath, 1U << chunkbits,
+				  1U << dst_sb->blkszbits);
 			return -EINVAL;
 		}
-	} else {
+	} else if (inode->datalayout == EROFS_INODE_FLAT_PLAIN) {
 		chunkbits = ilog2(inode->i_size - 1) + 1;
-		if (chunkbits < sbi.blkszbits)
-			chunkbits = sbi.blkszbits;
-		if (chunkbits - sbi.blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
-			chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi.blkszbits;
+		if (chunkbits < dst_sb->blkszbits)
+			chunkbits = dst_sb->blkszbits;
+		if (chunkbits - dst_sb->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
+			chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + dst_sb->blkszbits;
+	} else {
+		erofs_err("%s: unsupported datalayout %d ", inode->i_srcpath,
+			  inode->datalayout);
+		return -EOPNOTSUPP;
 	}
+
 	chunksize = 1ULL << chunkbits;
 	count = DIV_ROUND_UP(inode->i_size, chunksize);
 
@@ -178,7 +186,7 @@ static int erofs_rebuild_fixup_inode_index(struct erofs_inode *inode)
 		if (ret)
 			goto err;
 
-		blkaddr = erofs_blknr(&sbi, map.m_pa);
+		blkaddr = erofs_blknr(dst_sb, map.m_pa);
 		chunk = erofs_get_unhashed_chunk(inode->dev, blkaddr, 0);
 		if (IS_ERR(chunk)) {
 			ret = PTR_ERR(chunk);
@@ -189,7 +197,7 @@ static int erofs_rebuild_fixup_inode_index(struct erofs_inode *inode)
 	}
 	inode->datalayout = EROFS_INODE_CHUNK_BASED;
 	inode->u.chunkformat = EROFS_CHUNK_FORMAT_INDEXES;
-	inode->u.chunkformat |= chunkbits - sbi.blkszbits;
+	inode->u.chunkformat |= chunkbits - dst_sb->blkszbits;
 	return 0;
 err:
 	free(inode->chunkindexes);
@@ -197,8 +205,12 @@ err:
 	return ret;
 }
 
-static int erofs_rebuild_fill_inode(struct erofs_inode *inode)
+static int erofs_rebuild_update_inode(struct erofs_sb_info *dst_sb,
+				      struct erofs_inode *inode,
+				      enum erofs_rebuild_datamode datamode)
 {
+	int err = 0;
+
 	switch (inode->i_mode & S_IFMT) {
 	case S_IFCHR:
 		if (erofs_inode_is_whiteout(inode))
@@ -211,42 +223,50 @@ static int erofs_rebuild_fill_inode(struct erofs_inode *inode)
 		erofs_dbg("\tdev: %d %d", major(inode->u.i_rdev),
 			  minor(inode->u.i_rdev));
 		inode->u.i_rdev = erofs_new_encode_dev(inode->u.i_rdev);
-		return 0;
+		break;
 	case S_IFDIR:
-		return erofs_init_empty_dir(inode);
-	case S_IFLNK: {
-		int ret;
-
+		err = erofs_init_empty_dir(inode);
+		break;
+	case S_IFLNK:
 		inode->i_link = malloc(inode->i_size + 1);
 		if (!inode->i_link)
 			return -ENOMEM;
-		ret = erofs_pread(inode, inode->i_link, inode->i_size, 0);
+		err = erofs_pread(inode, inode->i_link, inode->i_size, 0);
 		erofs_dbg("\tsymlink: %s -> %s", inode->i_srcpath, inode->i_link);
-		return ret;
-	}
+		break;
 	case S_IFREG:
-		if (inode->i_size)
-			return erofs_rebuild_fixup_inode_index(inode);
-		return 0;
-	default:
+		if (!inode->i_size) {
+			inode->u.i_blkaddr = NULL_ADDR;
+			break;
+		}
+		if (datamode == EROFS_REBUILD_DATA_BLOB_INDEX)
+			err = erofs_rebuild_write_blob_index(dst_sb, inode);
+		else if (datamode == EROFS_REBUILD_DATA_RESVSP)
+			inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
+		else
+			err = -EOPNOTSUPP;
 		break;
+	default:
+		return -EINVAL;
 	}
-	return -EINVAL;
+	return err;
 }
 
 /*
- * @parent:  parent directory in inode tree
- * @ctx.dir: parent directory when itering erofs_iterate_dir()
+ * @mergedir: parent directory in the merged tree
+ * @ctx.dir:  parent directory when itering erofs_iterate_dir()
+ * @datamode: indicate how to import inode data
  */
 struct erofs_rebuild_dir_context {
 	struct erofs_dir_context ctx;
-	struct erofs_inode *parent;
+	struct erofs_inode *mergedir;
+	enum erofs_rebuild_datamode datamode;
 };
 
 static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 {
 	struct erofs_rebuild_dir_context *rctx = (void *)ctx;
-	struct erofs_inode *parent = rctx->parent;
+	struct erofs_inode *mergedir = rctx->mergedir;
 	struct erofs_inode *dir = ctx->dir;
 	struct erofs_inode *inode, *candidate;
 	struct erofs_inode src;
@@ -258,15 +278,15 @@ static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 	if (ctx->dot_dotdot)
 		return 0;
 
-	ret = asprintf(&path, "%s/%.*s", rctx->parent->i_srcpath,
+	ret = asprintf(&path, "%s/%.*s", rctx->mergedir->i_srcpath,
 		       ctx->de_namelen, ctx->dname);
 	if (ret < 0)
 		return ret;
 
 	erofs_dbg("parsing %s", path);
-	dname = path + strlen(parent->i_srcpath) + 1;
+	dname = path + strlen(mergedir->i_srcpath) + 1;
 
-	d = erofs_rebuild_get_dentry(parent, dname, false,
+	d = erofs_rebuild_get_dentry(mergedir, dname, false,
 				     &dumb, &dumb, false);
 	if (IS_ERR(d)) {
 		ret = PTR_ERR(d);
@@ -290,13 +310,13 @@ static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 		ret = erofs_read_inode_from_disk(&src);
 		if (ret || !S_ISDIR(src.i_mode))
 			goto out;
-		parent = d->inode;
+		mergedir = d->inode;
 		inode = dir = &src;
 	} else {
 		u64 nid;
 
-		DBG_BUGON(parent != d->inode);
-		inode = erofs_new_inode();
+		DBG_BUGON(mergedir != d->inode);
+		inode = erofs_new_inode(dir->sbi);
 		if (IS_ERR(inode)) {
 			ret = PTR_ERR(inode);
 			goto out;
@@ -340,14 +360,15 @@ static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 			inode->i_ino[1] = inode->nid;
 			inode->i_nlink = 1;
 
-			ret = erofs_rebuild_fill_inode(inode);
+			ret = erofs_rebuild_update_inode(&g_sbi, inode,
+							 rctx->datamode);
 			if (ret) {
 				erofs_iput(inode);
 				goto out;
 			}
 
-			erofs_insert_ihash(inode, inode->dev, inode->i_ino[1]);
-			parent = dir = inode;
+			erofs_insert_ihash(inode);
+			mergedir = dir = inode;
 		}
 
 		d->inode = inode;
@@ -357,7 +378,7 @@ static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 	if (S_ISDIR(inode->i_mode)) {
 		struct erofs_rebuild_dir_context nctx = *rctx;
 
-		nctx.parent = parent;
+		nctx.mergedir = mergedir;
 		nctx.ctx.dir = dir;
 		ret = erofs_iterate_dir(&nctx.ctx, false);
 		if (ret)
@@ -365,27 +386,29 @@ static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
 	}
 
 	/* reset sbi, nid after subdirs are all loaded for the final dump */
-	inode->sbi = &sbi;
+	inode->sbi = &g_sbi;
 	inode->nid = 0;
 out:
 	free(path);
 	return ret;
 }
 
-int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi)
+int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi,
+			    enum erofs_rebuild_datamode mode)
 {
 	struct erofs_inode inode = {};
 	struct erofs_rebuild_dir_context ctx;
+	char uuid_str[37];
+	char *fsid = sbi->devname;
 	int ret;
 
-	if (!sbi->devname) {
-		erofs_err("failed to find a device for rebuilding");
-		return -EINVAL;
+	if (!fsid) {
+		erofs_uuid_unparse_lower(sbi->uuid, uuid_str);
+		fsid = uuid_str;
 	}
-
 	ret = erofs_read_superblock(sbi);
 	if (ret) {
-		erofs_err("failed to read superblock of %s", sbi->devname);
+		erofs_err("failed to read superblock of %s", fsid);
 		return ret;
 	}
 
@@ -393,7 +416,7 @@ int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi)
 	inode.sbi = sbi;
 	ret = erofs_read_inode_from_disk(&inode);
 	if (ret) {
-		erofs_err("failed to read root inode of %s", sbi->devname);
+		erofs_err("failed to read root inode of %s", fsid);
 		return ret;
 	}
 	inode.i_srcpath = strdup("/");
@@ -401,9 +424,83 @@ int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi)
 	ctx = (struct erofs_rebuild_dir_context) {
 		.ctx.dir = &inode,
 		.ctx.cb = erofs_rebuild_dirent_iter,
-		.parent = root,
+		.mergedir = root,
+		.datamode = mode,
 	};
 	ret = erofs_iterate_dir(&ctx.ctx, false);
 	free(inode.i_srcpath);
 	return ret;
 }
+
+static int erofs_rebuild_basedir_dirent_iter(struct erofs_dir_context *ctx)
+{
+	struct erofs_rebuild_dir_context *rctx = (void *)ctx;
+	struct erofs_inode *dir = ctx->dir;
+	struct erofs_inode *mergedir = rctx->mergedir;
+	struct erofs_dentry *d;
+	char *dname;
+	bool dumb;
+	int ret;
+
+	if (ctx->dot_dotdot)
+		return 0;
+
+	dname = strndup(ctx->dname, ctx->de_namelen);
+	if (!dname)
+		return -ENOMEM;
+	d = erofs_rebuild_get_dentry(mergedir, dname, false,
+				     &dumb, &dumb, false);
+	if (IS_ERR(d)) {
+		ret = PTR_ERR(d);
+		goto out;
+	}
+
+	if (d->type == EROFS_FT_UNKNOWN) {
+		d->nid = ctx->de_nid;
+		d->type = ctx->de_ftype;
+		d->validnid = true;
+		if (!mergedir->whiteouts && erofs_dentry_is_wht(dir->sbi, d))
+			mergedir->whiteouts = true;
+	} else {
+		struct erofs_inode *inode = d->inode;
+
+		/* update sub-directories only for recursively loading */
+		if (S_ISDIR(inode->i_mode)) {
+			list_del(&inode->i_hash);
+			inode->dev = dir->sbi->dev;
+			inode->i_ino[1] = ctx->de_nid;
+			erofs_insert_ihash(inode);
+		}
+	}
+	ret = 0;
+out:
+	free(dname);
+	return ret;
+}
+
+int erofs_rebuild_load_basedir(struct erofs_inode *dir)
+{
+	struct erofs_inode fakeinode = {
+		.sbi = dir->sbi,
+		.nid = dir->i_ino[1],
+	};
+	struct erofs_rebuild_dir_context ctx;
+	int ret;
+
+	ret = erofs_read_inode_from_disk(&fakeinode);
+	if (ret) {
+		erofs_err("failed to read inode @ %llu", fakeinode.nid);
+		return ret;
+	}
+
+	/* Inherit the maximum xattr size for the root directory */
+	if (__erofs_unlikely(IS_ROOT(dir)))
+		dir->xattr_isize = fakeinode.xattr_isize;
+
+	ctx = (struct erofs_rebuild_dir_context) {
+		.ctx.dir = &fakeinode,
+		.ctx.cb = erofs_rebuild_basedir_dirent_iter,
+		.mergedir = dir,
+	};
+	return erofs_iterate_dir(&ctx.ctx, false);
+}
diff --git a/lib/super.c b/lib/super.c
index f952f7e..32e10cd 100644
--- a/lib/super.c
+++ b/lib/super.c
@@ -4,9 +4,9 @@
  */
 #include <string.h>
 #include <stdlib.h>
-#include "erofs/io.h"
 #include "erofs/print.h"
 #include "erofs/xattr.h"
+#include "erofs/cache.h"
 
 static bool check_layout_compatibility(struct erofs_sb_info *sbi,
 				       struct erofs_super_block *dsb)
@@ -56,7 +56,7 @@ static int erofs_init_devices(struct erofs_sb_info *sbi,
 		struct erofs_deviceslot dis;
 		int ret;
 
-		ret = dev_read(sbi, 0, &dis, pos, sizeof(dis));
+		ret = erofs_dev_read(sbi, 0, &dis, pos, sizeof(dis));
 		if (ret < 0) {
 			free(sbi->devs);
 			sbi->devs = NULL;
@@ -79,7 +79,7 @@ int erofs_read_superblock(struct erofs_sb_info *sbi)
 	int ret;
 
 	sbi->blkszbits = ilog2(EROFS_MAX_BLOCK_SIZE);
-	ret = blk_read(sbi, 0, data, 0, erofs_blknr(sbi, sizeof(data)));
+	ret = erofs_blk_read(sbi, 0, data, 0, erofs_blknr(sbi, sizeof(data)));
 	if (ret < 0) {
 		erofs_err("cannot read erofs superblock: %d", ret);
 		return -EIO;
@@ -104,6 +104,12 @@ int erofs_read_superblock(struct erofs_sb_info *sbi)
 		return ret;
 	}
 
+	sbi->sb_size = 128 + dsb->sb_extslots * EROFS_SB_EXTSLOT_SIZE;
+	if (sbi->sb_size > (1 << sbi->blkszbits) - EROFS_SUPER_OFFSET) {
+		erofs_err("invalid sb_extslots %u (more than a fs block)",
+			  dsb->sb_extslots);
+		return -EINVAL;
+	}
 	sbi->primarydevice_blocks = le32_to_cpu(dsb->blocks);
 	sbi->meta_blkaddr = le32_to_cpu(dsb->meta_blkaddr);
 	sbi->xattr_blkaddr = le32_to_cpu(dsb->xattr_blkaddr);
@@ -114,17 +120,15 @@ int erofs_read_superblock(struct erofs_sb_info *sbi)
 	sbi->packed_nid = le64_to_cpu(dsb->packed_nid);
 	sbi->inos = le64_to_cpu(dsb->inos);
 	sbi->checksum = le32_to_cpu(dsb->checksum);
-	sbi->extslots = dsb->sb_extslots;
 
 	sbi->build_time = le64_to_cpu(dsb->build_time);
 	sbi->build_time_nsec = le32_to_cpu(dsb->build_time_nsec);
 
 	memcpy(&sbi->uuid, dsb->uuid, sizeof(dsb->uuid));
 
-	if (erofs_sb_has_compr_cfgs(sbi))
-		sbi->available_compr_algs = le16_to_cpu(dsb->u1.available_compr_algs);
-	else
-		sbi->lz4_max_distance = le16_to_cpu(dsb->u1.lz4_max_distance);
+	ret = z_erofs_parse_cfgs(sbi, dsb);
+	if (ret)
+		return ret;
 
 	ret = erofs_init_devices(sbi, dsb);
 	if (ret)
@@ -145,4 +149,136 @@ void erofs_put_super(struct erofs_sb_info *sbi)
 		sbi->devs = NULL;
 	}
 	erofs_xattr_prefixes_cleanup(sbi);
+	if (sbi->bmgr) {
+		erofs_buffer_exit(sbi->bmgr);
+		sbi->bmgr = NULL;
+	}
+}
+
+int erofs_writesb(struct erofs_sb_info *sbi, struct erofs_buffer_head *sb_bh,
+		  erofs_blk_t *blocks)
+{
+	struct erofs_super_block sb = {
+		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
+		.blkszbits = sbi->blkszbits,
+		.root_nid  = cpu_to_le16(sbi->root_nid),
+		.inos      = cpu_to_le64(sbi->inos),
+		.build_time = cpu_to_le64(sbi->build_time),
+		.build_time_nsec = cpu_to_le32(sbi->build_time_nsec),
+		.meta_blkaddr  = cpu_to_le32(sbi->meta_blkaddr),
+		.xattr_blkaddr = cpu_to_le32(sbi->xattr_blkaddr),
+		.xattr_prefix_count = sbi->xattr_prefix_count,
+		.xattr_prefix_start = cpu_to_le32(sbi->xattr_prefix_start),
+		.feature_incompat = cpu_to_le32(sbi->feature_incompat),
+		.feature_compat = cpu_to_le32(sbi->feature_compat &
+					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
+		.extra_devices = cpu_to_le16(sbi->extra_devices),
+		.devt_slotoff = cpu_to_le16(sbi->devt_slotoff),
+		.packed_nid = cpu_to_le64(sbi->packed_nid),
+	};
+	const u32 sb_blksize = round_up(EROFS_SUPER_END, erofs_blksiz(sbi));
+	char *buf;
+	int ret;
+
+	*blocks         = erofs_mapbh(sbi->bmgr, NULL);
+	sb.blocks       = cpu_to_le32(*blocks);
+	memcpy(sb.uuid, sbi->uuid, sizeof(sb.uuid));
+	memcpy(sb.volume_name, sbi->volume_name, sizeof(sb.volume_name));
+
+	if (erofs_sb_has_compr_cfgs(sbi))
+		sb.u1.available_compr_algs = cpu_to_le16(sbi->available_compr_algs);
+	else
+		sb.u1.lz4_max_distance = cpu_to_le16(sbi->lz4.max_distance);
+
+	buf = calloc(sb_blksize, 1);
+	if (!buf) {
+		erofs_err("failed to allocate memory for sb: %s",
+			  erofs_strerror(-errno));
+		return -ENOMEM;
+	}
+	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));
+
+	ret = erofs_dev_write(sbi, buf, sb_bh ? erofs_btell(sb_bh, false) : 0,
+			      EROFS_SUPER_END);
+	free(buf);
+	if (sb_bh)
+		erofs_bdrop(sb_bh, false);
+	return ret;
+}
+
+struct erofs_buffer_head *erofs_reserve_sb(struct erofs_bufmgr *bmgr)
+{
+	struct erofs_buffer_head *bh;
+	int err;
+
+	bh = erofs_balloc(bmgr, META, 0, 0, 0);
+	if (IS_ERR(bh)) {
+		erofs_err("failed to allocate super: %s", PTR_ERR(bh));
+		return bh;
+	}
+	bh->op = &erofs_skip_write_bhops;
+	err = erofs_bh_balloon(bh, EROFS_SUPER_END);
+	if (err < 0) {
+		erofs_err("failed to balloon super: %s", erofs_strerror(err));
+		goto err_bdrop;
+	}
+
+	/* make sure that the super block should be the very first blocks */
+	(void)erofs_mapbh(NULL, bh->block);
+	if (erofs_btell(bh, false) != 0) {
+		erofs_err("failed to pin super block @ 0");
+		err = -EFAULT;
+		goto err_bdrop;
+	}
+	return bh;
+err_bdrop:
+	erofs_bdrop(bh, true);
+	return ERR_PTR(err);
+}
+
+int erofs_enable_sb_chksum(struct erofs_sb_info *sbi, u32 *crc)
+{
+	int ret;
+	u8 buf[EROFS_MAX_BLOCK_SIZE];
+	unsigned int len;
+	struct erofs_super_block *sb;
+
+	ret = erofs_blk_read(sbi, 0, buf, 0, erofs_blknr(sbi, EROFS_SUPER_END) + 1);
+	if (ret) {
+		erofs_err("failed to read superblock to set checksum: %s",
+			  erofs_strerror(ret));
+		return ret;
+	}
+
+	/*
+	 * skip the first 1024 bytes, to allow for the installation
+	 * of x86 boot sectors and other oddities.
+	 */
+	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);
+
+	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
+		erofs_err("internal error: not an erofs valid image");
+		return -EFAULT;
+	}
+
+	/* turn on checksum feature */
+	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
+					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
+	if (erofs_blksiz(sbi) > EROFS_SUPER_OFFSET)
+		len = erofs_blksiz(sbi) - EROFS_SUPER_OFFSET;
+	else
+		len = erofs_blksiz(sbi);
+	*crc = erofs_crc32c(~0, (u8 *)sb, len);
+
+	/* set up checksum field to erofs_super_block */
+	sb->checksum = cpu_to_le32(*crc);
+
+	ret = erofs_blk_write(sbi, buf, 0, 1);
+	if (ret) {
+		erofs_err("failed to write checksummed superblock: %s",
+			  erofs_strerror(ret));
+		return ret;
+	}
+
+	return 0;
 }
diff --git a/lib/tar.c b/lib/tar.c
index 8204939..a9b425e 100644
--- a/lib/tar.c
+++ b/lib/tar.c
@@ -12,7 +12,6 @@
 #include "erofs/inode.h"
 #include "erofs/list.h"
 #include "erofs/tar.h"
-#include "erofs/io.h"
 #include "erofs/xattr.h"
 #include "erofs/blobchunk.h"
 #include "erofs/rebuild.h"
@@ -40,48 +39,33 @@ struct tar_header {
 	char padding[12];	/* 500-512 (pad to exactly the 512 byte) */
 };
 
-s64 erofs_read_from_fd(int fd, void *buf, u64 bytes)
-{
-	s64 i = 0;
-
-	while (bytes) {
-		int len = bytes > INT_MAX ? INT_MAX : bytes;
-		int ret;
-
-		ret = read(fd, buf + i, len);
-		if (ret < 1) {
-			if (ret == 0) {
-				break;
-			} else if (errno != EINTR) {
-				erofs_err("failed to read : %s\n",
-					  strerror(errno));
-				return -errno;
-			}
-		}
-		bytes -= ret;
-		i += ret;
-        }
-        return i;
-}
-
 void erofs_iostream_close(struct erofs_iostream *ios)
 {
 	free(ios->buffer);
 	if (ios->decoder == EROFS_IOS_DECODER_GZIP) {
 #if defined(HAVE_ZLIB)
 		gzclose(ios->handler);
+#endif
+		return;
+	} else if (ios->decoder == EROFS_IOS_DECODER_LIBLZMA) {
+#if defined(HAVE_LIBLZMA)
+		lzma_end(&ios->lzma->strm);
+		close(ios->lzma->fd);
+		free(ios->lzma);
 #endif
 		return;
 	}
-	close(ios->fd);
+	close(ios->vf.fd);
 }
 
 int erofs_iostream_open(struct erofs_iostream *ios, int fd, int decoder)
 {
 	s64 fsz;
 
+	ios->feof = false;
 	ios->tail = ios->head = 0;
 	ios->decoder = decoder;
+	ios->dumpfd = -1;
 	if (decoder == EROFS_IOS_DECODER_GZIP) {
 #if defined(HAVE_ZLIB)
 		ios->handler = gzdopen(fd, "r");
@@ -91,22 +75,39 @@ int erofs_iostream_open(struct erofs_iostream *ios, int fd, int decoder)
 		ios->bufsize = 32768;
 #else
 		return -EOPNOTSUPP;
+#endif
+	} else if (decoder == EROFS_IOS_DECODER_LIBLZMA) {
+#ifdef HAVE_LIBLZMA
+		lzma_ret ret;
+
+		ios->lzma = malloc(sizeof(*ios->lzma));
+		if (!ios->lzma)
+			return -ENOMEM;
+		ios->lzma->fd = fd;
+		ios->lzma->strm = (lzma_stream)LZMA_STREAM_INIT;
+		ret = lzma_auto_decoder(&ios->lzma->strm,
+					UINT64_MAX, LZMA_CONCATENATED);
+		if (ret != LZMA_OK)
+			return -EFAULT;
+		ios->sz = fsz = 0;
+		ios->bufsize = 32768;
+#else
+		return -EOPNOTSUPP;
 #endif
 	} else {
-		ios->fd = fd;
+		ios->vf.fd = fd;
 		fsz = lseek(fd, 0, SEEK_END);
 		if (fsz <= 0) {
 			ios->feof = !fsz;
 			ios->sz = 0;
 		} else {
-			ios->feof = false;
 			ios->sz = fsz;
 			if (lseek(fd, 0, SEEK_SET))
 				return -EIO;
 #ifdef HAVE_POSIX_FADVISE
 			if (posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL))
 				erofs_warn("failed to fadvise: %s, ignored.",
-					   erofs_strerror(errno));
+					   erofs_strerror(-errno));
 #endif
 		}
 		ios->bufsize = 16384;
@@ -160,19 +161,54 @@ int erofs_iostream_read(struct erofs_iostream *ios, void **buf, u64 bytes)
 			ios->tail += ret;
 #else
 			return -EOPNOTSUPP;
+#endif
+		} else if (ios->decoder == EROFS_IOS_DECODER_LIBLZMA) {
+#ifdef HAVE_LIBLZMA
+			struct erofs_iostream_liblzma *lzma = ios->lzma;
+			lzma_action action = LZMA_RUN;
+			lzma_ret ret2;
+
+			if (!lzma->strm.avail_in) {
+				lzma->strm.next_in = lzma->inbuf;
+				ret = read(lzma->fd, lzma->inbuf,
+					   sizeof(lzma->inbuf));
+				if (ret < 0)
+					return -errno;
+				lzma->strm.avail_in = ret;
+				if (ret < sizeof(lzma->inbuf))
+					action = LZMA_FINISH;
+			}
+			lzma->strm.next_out = (u8 *)ios->buffer + rabytes;
+			lzma->strm.avail_out = ios->bufsize - rabytes;
+
+			ret2 = lzma_code(&lzma->strm, action);
+			if (ret2 != LZMA_OK) {
+				if (ret2 == LZMA_STREAM_END)
+					ios->feof = true;
+				else
+					return -EIO;
+			}
+			ret = ios->bufsize - rabytes - lzma->strm.avail_out;
+			ios->tail += ret;
+#else
+			return -EOPNOTSUPP;
 #endif
 		} else {
-			ret = erofs_read_from_fd(ios->fd, ios->buffer + rabytes,
-						 ios->bufsize - rabytes);
+			ret = erofs_io_read(&ios->vf, ios->buffer + rabytes,
+					    ios->bufsize - rabytes);
 			if (ret < 0)
 				return ret;
 			ios->tail += ret;
 			if (ret < ios->bufsize - rabytes)
 				ios->feof = true;
 		}
+		if (__erofs_unlikely(ios->dumpfd >= 0))
+			if (write(ios->dumpfd, ios->buffer + rabytes, ret) < ret)
+				erofs_err("failed to dump %d bytes of the raw stream: %s",
+					  ret, erofs_strerror(-errno));
 	}
 	*buf = ios->buffer;
-	ret = min_t(int, ios->tail, bytes);
+	ret = min_t(int, ios->tail, min_t(u64, bytes, INT_MAX));
 	ios->head = ret;
 	return ret;
 }
@@ -210,8 +246,8 @@ int erofs_iostream_lskip(struct erofs_iostream *ios, u64 sz)
 	if (ios->feof)
 		return sz;
 
-	if (ios->sz) {
-		s64 cur = lseek(ios->fd, sz, SEEK_CUR);
+	if (ios->sz && __erofs_likely(ios->dumpfd < 0)) {
+		s64 cur = erofs_io_lseek(&ios->vf, sz, SEEK_CUR);
 
 		if (cur > ios->sz)
 			return cur - ios->sz;
@@ -454,9 +490,9 @@ int tarerofs_parse_pax_header(struct erofs_iostream *ios,
 						ret = -EIO;
 						goto out;
 					}
-#if ST_MTIM_NSEC
-					ST_MTIM_NSEC(&eh->st) = n;
-#endif
+					ST_MTIM_NSEC_SET(&eh->st, n);
+				} else {
+					ST_MTIM_NSEC_SET(&eh->st, 0);
 				}
 				eh->use_mtime = true;
 			} else if (!strncmp(kv, "size=",
@@ -544,10 +580,9 @@ void tarerofs_remove_inode(struct erofs_inode *inode)
 static int tarerofs_write_file_data(struct erofs_inode *inode,
 				    struct erofs_tarfile *tar)
 {
-	unsigned int j;
 	void *buf;
 	int fd, nread;
-	u64 off;
+	u64 off, j;
 
 	if (!inode->i_diskbuf) {
 		inode->i_diskbuf = calloc(1, sizeof(*inode->i_diskbuf));
@@ -572,20 +607,7 @@ static int tarerofs_write_file_data(struct erofs_inode *inode,
 		j -= nread;
 	}
 	erofs_diskbuf_commit(inode->i_diskbuf, inode->i_size);
-	inode->with_diskbuf = true;
-	return 0;
-}
-
-static int tarerofs_write_file_index(struct erofs_inode *inode,
-		struct erofs_tarfile *tar, erofs_off_t data_offset)
-{
-	int ret;
-
-	ret = tarerofs_write_chunkes(inode, data_offset);
-	if (ret)
-		return ret;
-	if (erofs_iostream_lskip(&tar->ios, inode->i_size))
-		return -EIO;
+	inode->datasource = EROFS_INODE_DATA_SOURCE_DISKBUF;
 	return 0;
 }
 
@@ -596,7 +618,7 @@ int tarerofs_parse_tar(struct erofs_inode *root, struct erofs_tarfile *tar)
 	struct erofs_sb_info *sbi = root->sbi;
 	bool whout, opq, e = false;
 	struct stat st;
-	erofs_off_t tar_offset, data_offset;
+	erofs_off_t tar_offset, dataoff;
 
 	struct tar_header *th;
 	struct erofs_dentry *d;
@@ -623,6 +645,10 @@ restart:
 	tar_offset = tar->offset;
 	ret = erofs_iostream_read(&tar->ios, (void **)&th, sizeof(*th));
 	if (ret != sizeof(*th)) {
+		if (tar->headeronly_mode || tar->ddtaridx_mode) {
+			ret = 1;
+			goto out;
+		}
 		erofs_err("failed to read header block @ %llu", tar_offset);
 		ret = -EIO;
 		goto out;
@@ -656,7 +682,7 @@ restart:
 		cksum += (unsigned int)((u8*)th)[j];
 		ckksum += (int)((char*)th)[j];
 	}
-	if (csum != cksum && csum != ckksum) {
+	if (!tar->ddtaridx_mode && csum != cksum && csum != ckksum) {
 		erofs_err("chksum mismatch @ %llu", tar_offset);
 		ret = -EBADMSG;
 		goto out;
@@ -707,13 +733,12 @@ restart:
 
 	if (eh.use_mtime) {
 		st.st_mtime = eh.st.st_mtime;
-#if ST_MTIM_NSEC
-		ST_MTIM_NSEC(&st) = ST_MTIM_NSEC(&eh.st);
-#endif
+		ST_MTIM_NSEC_SET(&st, ST_MTIM_NSEC(&eh.st));
 	} else {
 		st.st_mtime = tarerofs_parsenum(th->mtime, sizeof(th->mtime));
 		if (errno)
 			goto invalid_tar;
+		ST_MTIM_NSEC_SET(&st, 0);
 	}
 
 	if (th->typeflag <= '7' && !eh.path) {
@@ -735,8 +760,9 @@ restart:
 			path[--j] = '\0';
 	}
 
-	data_offset = tar->offset;
-	tar->offset += st.st_size;
+	dataoff = tar->offset;
+	if (!(tar->headeronly_mode || tar->ddtaridx_mode))
+		tar->offset += st.st_size;
 	switch(th->typeflag) {
 	case '0':
 	case '7':
@@ -823,8 +849,9 @@ restart:
 			eh.link = strndup(th->linkname, sizeof(th->linkname));
 	}
 
-	if (tar->index_mode && !tar->mapfile &&
-	    erofs_blkoff(sbi, data_offset)) {
+	/* EROFS metadata index referring to the original tar data */
+	if (tar->index_mode && sbi->extra_devices &&
+	    erofs_blkoff(sbi, dataoff)) {
 		erofs_err("invalid tar data alignment @ %llu", tar_offset);
 		ret = -EIO;
 		goto out;
@@ -848,6 +875,11 @@ restart:
 	} else if (opq) {
 		DBG_BUGON(d->type == EROFS_FT_UNKNOWN);
 		DBG_BUGON(!d->inode);
+		/*
+		 * needed if the tar tree is used soon, thus we have no chance
+		 * to generate it from xattrs.  No impact to mergefs.
+		 */
+		d->inode->opaque = true;
 		ret = erofs_set_opaque_xattr(d->inode);
 		goto out;
 	} else if (th->typeflag == '1') {	/* hard link cases */
@@ -897,11 +929,12 @@ restart:
 		inode = d->inode;
 	} else {
 new_inode:
-		inode = erofs_new_inode();
+		inode = erofs_new_inode(sbi);
 		if (IS_ERR(inode)) {
 			ret = PTR_ERR(inode);
 			goto out;
 		}
+		inode->dev = tar->dev;
 		inode->i_parent = d->inode;
 		d->inode = inode;
 		d->type = erofs_mode_to_ftype(st.st_mode);
@@ -941,11 +974,32 @@ new_inode:
 			inode->i_link = malloc(inode->i_size + 1);
 			memcpy(inode->i_link, eh.link, inode->i_size + 1);
 		} else if (inode->i_size) {
-			if (tar->index_mode)
-				ret = tarerofs_write_file_index(inode, tar,
-								data_offset);
-			else
+			if (tar->headeronly_mode) {
+				ret = erofs_write_zero_inode(inode);
+			} else if (tar->ddtaridx_mode) {
+				dataoff = le64_to_cpu(*(__le64 *)(th->devmajor));
+				if (tar->rvsp_mode) {
+					inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
+					inode->i_ino[1] = dataoff;
+					ret = 0;
+				} else {
+					ret = tarerofs_write_chunkes(inode, dataoff);
+				}
+			} else if (tar->rvsp_mode) {
+				inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
+				inode->i_ino[1] = dataoff;
+				if (erofs_iostream_lskip(&tar->ios, inode->i_size))
+					ret = -EIO;
+				else
+					ret = 0;
+			} else if (tar->index_mode) {
+				ret = tarerofs_write_chunkes(inode, dataoff);
+				if (!ret && erofs_iostream_lskip(&tar->ios,
+								 inode->i_size))
+					ret = -EIO;
+			} else {
 				ret = tarerofs_write_file_data(inode, tar);
+			}
 			if (ret)
 				goto out;
 		}
diff --git a/lib/uuid.c b/lib/uuid.c
index ec0f9d9..3fb88a3 100644
--- a/lib/uuid.c
+++ b/lib/uuid.c
@@ -38,18 +38,30 @@ static int s_getrandom(void *out, unsigned size, bool insecure)
 
 	for (;;)
 	{
+		ssize_t r;
+		int err;
+
 #ifdef HAVE_SYS_RANDOM_H
-		ssize_t r = getrandom(out, size, flags);
+		r = getrandom(out, size, flags);
+#elif defined(__NR_getrandom)
+		r = (ssize_t)syscall(__NR_getrandom, out, size, flags);
 #else
-		ssize_t r = (ssize_t)syscall(__NR_getrandom, out, size, flags);
+		r = -1;
+		errno = ENOSYS;
+		(void)flags;
 #endif
-		int err;
 
 		if (r == size)
 			break;
 		err = errno;
 		if (err != EINTR) {
-			if (err == EINVAL && kflags) {
+			if (__erofs_unlikely(err == ENOSYS && insecure)) {
+				while (size) {
+					*(u8 *)out++ = rand() % 256;
+					--size;
+				}
+				err = 0;
+			} else if (err == EINVAL && kflags) {
 				// Kernel likely does not support GRND_INSECURE
 				erofs_grnd_flag = 0;
 				kflags = 0;
diff --git a/lib/workqueue.c b/lib/workqueue.c
new file mode 100644
index 0000000..47cec9b
--- /dev/null
+++ b/lib/workqueue.c
@@ -0,0 +1,123 @@
+// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
+#include <pthread.h>
+#include <stdlib.h>
+#include "erofs/workqueue.h"
+
+static void *worker_thread(void *arg)
+{
+	struct erofs_workqueue *wq = arg;
+	struct erofs_work *work;
+	void *tlsp = NULL;
+
+	if (wq->on_start)
+		tlsp = (wq->on_start)(wq, NULL);
+
+	while (true) {
+		pthread_mutex_lock(&wq->lock);
+
+		while (wq->job_count == 0 && !wq->shutdown)
+			pthread_cond_wait(&wq->cond_empty, &wq->lock);
+		if (wq->job_count == 0 && wq->shutdown) {
+			pthread_mutex_unlock(&wq->lock);
+			break;
+		}
+
+		work = wq->head;
+		wq->head = work->next;
+		if (!wq->head)
+			wq->tail = NULL;
+		wq->job_count--;
+
+		if (wq->job_count == wq->max_jobs - 1)
+			pthread_cond_broadcast(&wq->cond_full);
+
+		pthread_mutex_unlock(&wq->lock);
+		work->fn(work, tlsp);
+	}
+
+	if (wq->on_exit)
+		(void)(wq->on_exit)(wq, tlsp);
+	return NULL;
+}
+
+int erofs_alloc_workqueue(struct erofs_workqueue *wq, unsigned int nworker,
+			  unsigned int max_jobs, erofs_wq_func_t on_start,
+			  erofs_wq_func_t on_exit)
+{
+	unsigned int i;
+	int ret;
+
+	if (!wq || nworker <= 0 || max_jobs <= 0)
+		return -EINVAL;
+
+	wq->head = wq->tail = NULL;
+	wq->nworker = nworker;
+	wq->max_jobs = max_jobs;
+	wq->job_count = 0;
+	wq->shutdown = false;
+	wq->on_start = on_start;
+	wq->on_exit = on_exit;
+	pthread_mutex_init(&wq->lock, NULL);
+	pthread_cond_init(&wq->cond_empty, NULL);
+	pthread_cond_init(&wq->cond_full, NULL);
+
+	wq->workers = malloc(nworker * sizeof(pthread_t));
+	if (!wq->workers)
+		return -ENOMEM;
+
+	for (i = 0; i < nworker; i++) {
+		ret = pthread_create(&wq->workers[i], NULL, worker_thread, wq);
+		if (ret) {
+			while (i)
+				pthread_cancel(wq->workers[--i]);
+			free(wq->workers);
+			return ret;
+		}
+	}
+	return 0;
+}
+
+int erofs_queue_work(struct erofs_workqueue *wq, struct erofs_work *work)
+{
+	if (!wq || !work)
+		return -EINVAL;
+
+	pthread_mutex_lock(&wq->lock);
+
+	while (wq->job_count == wq->max_jobs)
+		pthread_cond_wait(&wq->cond_full, &wq->lock);
+
+	work->next = NULL;
+	if (!wq->head)
+		wq->head = work;
+	else
+		wq->tail->next = work;
+	wq->tail = work;
+	wq->job_count++;
+
+	pthread_cond_signal(&wq->cond_empty);
+	pthread_mutex_unlock(&wq->lock);
+	return 0;
+}
+
+int erofs_destroy_workqueue(struct erofs_workqueue *wq)
+{
+	unsigned int i;
+
+	if (!wq)
+		return -EINVAL;
+
+	pthread_mutex_lock(&wq->lock);
+	wq->shutdown = true;
+	pthread_cond_broadcast(&wq->cond_empty);
+	pthread_mutex_unlock(&wq->lock);
+
+	for (i = 0; i < wq->nworker; i++)
+		pthread_join(wq->workers[i], NULL);
+
+	free(wq->workers);
+	pthread_mutex_destroy(&wq->lock);
+	pthread_cond_destroy(&wq->cond_empty);
+	pthread_cond_destroy(&wq->cond_full);
+	return 0;
+}
diff --git a/lib/xattr.c b/lib/xattr.c
index 6c8ebf4..651657f 100644
--- a/lib/xattr.c
+++ b/lib/xattr.c
@@ -16,9 +16,8 @@
 #include "erofs/hashtable.h"
 #include "erofs/xattr.h"
 #include "erofs/cache.h"
-#include "erofs/io.h"
 #include "erofs/fragments.h"
-#include "erofs/xxhash.h"
+#include "xxhash.h"
 #include "liberofs_private.h"
 
 #ifndef XATTR_SYSTEM_PREFIX
@@ -166,14 +165,6 @@ static unsigned int BKDRHash(char *str, unsigned int len)
 	return hash;
 }
 
-static unsigned int xattr_item_hash(char *buf, unsigned int len[2],
-				    unsigned int hash[2])
-{
-	hash[0] = BKDRHash(buf, len[0]);	/* key */
-	hash[1] = BKDRHash(buf + len[0], len[1]);	/* value */
-	return hash[0] ^ hash[1];
-}
-
 static unsigned int put_xattritem(struct xattr_item *item)
 {
 	if (item->count > 1)
@@ -188,11 +179,13 @@ static struct xattr_item *get_xattritem(char *kvbuf, unsigned int len[2])
 	struct ea_type_node *tnode;
 	unsigned int hash[2], hkey;
 
-	hkey = xattr_item_hash(kvbuf, len, hash);
+	hash[0] = BKDRHash(kvbuf, len[0]);
+	hash[1] = BKDRHash(kvbuf + EROFS_XATTR_KSIZE(len), len[1]);
+	hkey = hash[0] ^ hash[1];
 	hash_for_each_possible(ea_hashtable, item, node, hkey) {
 		if (item->len[0] == len[0] && item->len[1] == len[1] &&
 		    item->hash[0] == hash[0] && item->hash[1] == hash[1] &&
-		    !memcmp(kvbuf, item->kvbuf, len[0] + len[1])) {
+		    !memcmp(kvbuf, item->kvbuf, EROFS_XATTR_KVSIZE(len))) {
 			free(kvbuf);
 			++item->count;
 			return item;
@@ -200,14 +193,11 @@ static struct xattr_item *get_xattritem(char *kvbuf, unsigned int len[2])
 	}
 
 	item = malloc(sizeof(*item));
-	if (!item) {
-		free(kvbuf);
+	if (!item)
 		return ERR_PTR(-ENOMEM);
-	}
 
 	if (!match_prefix(kvbuf, &item->base_index, &item->prefix_len)) {
 		free(item);
-		free(kvbuf);
 		return ERR_PTR(-ENODATA);
 	}
 	DBG_BUGON(len[0] < item->prefix_len);
@@ -239,6 +229,7 @@ static struct xattr_item *parse_one_xattr(const char *path, const char *key,
 					  unsigned int keylen)
 {
 	ssize_t ret;
+	struct xattr_item *item;
 	unsigned int len[2];
 	char *kvbuf;
 
@@ -273,20 +264,32 @@ static struct xattr_item *parse_one_xattr(const char *path, const char *key,
 		ret = getxattr(path, key, kvbuf + EROFS_XATTR_KSIZE(len),
 			       len[1], 0, XATTR_NOFOLLOW);
 #else
-		free(kvbuf);
-		return ERR_PTR(-EOPNOTSUPP);
+		ret = -EOPNOTSUPP;
+		goto out;
 #endif
 		if (ret < 0) {
-			free(kvbuf);
-			return ERR_PTR(-errno);
+			ret = -errno;
+			goto out;
 		}
 		if (len[1] != ret) {
-			erofs_err("size of xattr value got changed just now (%u-> %ld)",
+			erofs_warn("size of xattr value got changed just now (%u-> %ld)",
 				  len[1], (long)ret);
 			len[1] = ret;
 		}
 	}
-	return get_xattritem(kvbuf, len);
+
+	item = get_xattritem(kvbuf, len);
+	if (!IS_ERR(item))
+		return item;
+	if (item == ERR_PTR(-ENODATA)) {
+		erofs_warn("skipped unidentified xattr: %s", key);
+		ret = 0;
+	} else {
+		ret = PTR_ERR(item);
+	}
+out:
+	free(kvbuf);
+	return ERR_PTR(ret);
 }
 
 static struct xattr_item *erofs_get_selabel_xattr(const char *srcpath,
@@ -298,6 +301,7 @@ static struct xattr_item *erofs_get_selabel_xattr(const char *srcpath,
 		int ret;
 		unsigned int len[2];
 		char *kvbuf, *fspath;
+		struct xattr_item *item;
 
 		if (cfg.mount_point)
 			ret = asprintf(&fspath, "/%s/%s", cfg.mount_point,
@@ -331,7 +335,10 @@ static struct xattr_item *erofs_get_selabel_xattr(const char *srcpath,
 		sprintf(kvbuf, "%s", XATTR_NAME_SECURITY_SELINUX);
 		memcpy(kvbuf + EROFS_XATTR_KSIZE(len), secontext, len[1]);
 		freecon(secontext);
-		return get_xattritem(kvbuf, len);
+		item = get_xattritem(kvbuf, len);
+		if (IS_ERR(item))
+			free(kvbuf);
+		return item;
 	}
 #endif
 	return NULL;
@@ -377,18 +384,6 @@ static bool erofs_is_skipped_xattr(const char *key)
 	if (cfg.sehnd && !strcmp(key, XATTR_SECURITY_PREFIX "selinux"))
 		return true;
 #endif
-
-	/* skip xattrs with unidentified "system." prefix */
-	if (!strncmp(key, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN)) {
-		if (!strcmp(key, XATTR_NAME_POSIX_ACL_ACCESS) ||
-		    !strcmp(key, XATTR_NAME_POSIX_ACL_DEFAULT)) {
-			return false;
-		} else {
-			erofs_warn("skip unidentified xattr: %s", key);
-			return true;
-		}
-	}
-
 	return false;
 }
 
@@ -492,8 +487,10 @@ int erofs_setxattr(struct erofs_inode *inode, char *key,
 	memcpy(kvbuf + EROFS_XATTR_KSIZE(len), value, size);
 
 	item = get_xattritem(kvbuf, len);
-	if (IS_ERR(item))
+	if (IS_ERR(item)) {
+		free(kvbuf);
 		return PTR_ERR(item);
+	}
 	DBG_BUGON(!item);
 
 	return erofs_xattr_add(&inode->i_xattrs, item);
@@ -555,8 +552,10 @@ static int erofs_droid_xattr_set_caps(struct erofs_inode *inode)
 	memcpy(kvbuf + EROFS_XATTR_KSIZE(len), &caps, len[1]);
 
 	item = get_xattritem(kvbuf, len);
-	if (IS_ERR(item))
+	if (IS_ERR(item)) {
+		free(kvbuf);
 		return PTR_ERR(item);
+	}
 	DBG_BUGON(!item);
 
 	return erofs_xattr_add(&inode->i_xattrs, item);
@@ -660,16 +659,17 @@ static inline unsigned int erofs_next_xattr_align(unsigned int pos,
 			item->len[0] + item->len[1] - item->prefix_len);
 }
 
-int erofs_prepare_xattr_ibody(struct erofs_inode *inode)
+int erofs_prepare_xattr_ibody(struct erofs_inode *inode, bool noroom)
 {
-	int ret;
-	struct inode_xattr_node *node;
+	unsigned int target_xattr_isize = inode->xattr_isize;
 	struct list_head *ixattrs = &inode->i_xattrs;
+	struct inode_xattr_node *node;
 	unsigned int h_shared_count;
+	int ret;
 
 	if (list_empty(ixattrs)) {
-		inode->xattr_isize = 0;
-		return 0;
+		ret = 0;
+		goto out;
 	}
 
 	/* get xattr ibody size */
@@ -685,6 +685,18 @@ int erofs_prepare_xattr_ibody(struct erofs_inode *inode)
 		}
 		ret = erofs_next_xattr_align(ret, item);
 	}
+out:
+	while (ret < target_xattr_isize) {
+		ret += sizeof(struct erofs_xattr_entry);
+		if (ret < target_xattr_isize)
+			ret = EROFS_XATTR_ALIGN(ret +
+				min_t(int, target_xattr_isize - ret, UINT16_MAX));
+	}
+	if (noroom && target_xattr_isize && ret > target_xattr_isize) {
+		erofs_err("no enough space to keep xattrs @ nid %llu",
+			  inode->nid | 0ULL);
+		return -ENOSPC;
+	}
 	inode->xattr_isize = ret;
 	return ret;
 }
@@ -698,7 +710,7 @@ static int erofs_count_all_xattrs_from_path(const char *path)
 	_dir = opendir(path);
 	if (!_dir) {
 		erofs_err("failed to opendir at %s: %s",
-			  path, erofs_strerror(errno));
+			  path, erofs_strerror(-errno));
 		return -errno;
 	}
 
@@ -907,7 +919,7 @@ int erofs_build_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *p
 		return -ENOMEM;
 	}
 
-	bh = erofs_balloc(XATTR, shared_xattrs_size, 0, 0);
+	bh = erofs_balloc(sbi->bmgr, XATTR, shared_xattrs_size, 0, 0);
 	if (IS_ERR(bh)) {
 		free(sorted_n);
 		free(buf);
@@ -915,7 +927,7 @@ int erofs_build_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *p
 	}
 	bh->op = &erofs_skip_write_bhops;
 
-	erofs_mapbh(bh->block);
+	erofs_mapbh(NULL, bh->block);
 	off = erofs_btell(bh, false);
 
 	sbi->xattr_blkaddr = off / erofs_blksiz(sbi);
@@ -931,7 +943,7 @@ int erofs_build_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *p
 	shared_xattrs_list = sorted_n[0];
 	free(sorted_n);
 	bh->op = &erofs_drop_directly_bhops;
-	ret = dev_write(sbi, buf, erofs_btell(bh, false), shared_xattrs_size);
+	ret = erofs_dev_write(sbi, buf, erofs_btell(bh, false), shared_xattrs_size);
 	free(buf);
 	erofs_bdrop(bh, false);
 out:
@@ -1004,7 +1016,13 @@ char *erofs_export_xattr_ibody(struct erofs_inode *inode)
 		free(node);
 		put_xattritem(item);
 	}
-	DBG_BUGON(p > size);
+	if (p < size) {
+		memset(buf + p, 0, size - p);
+	} else if (__erofs_unlikely(p > size)) {
+		DBG_BUGON(1);
+		free(buf);
+		return ERR_PTR(-EFAULT);
+	}
 	return buf;
 }
 
@@ -1054,7 +1072,7 @@ static int init_inode_xattrs(struct erofs_inode *vi)
 	it.blkaddr = erofs_blknr(sbi, erofs_iloc(vi) + vi->inode_isize);
 	it.ofs = erofs_blkoff(sbi, erofs_iloc(vi) + vi->inode_isize);
 
-	ret = blk_read(sbi, 0, it.page, it.blkaddr, 1);
+	ret = erofs_blk_read(sbi, 0, it.page, it.blkaddr, 1);
 	if (ret < 0)
 		return -EIO;
 
@@ -1074,7 +1092,7 @@ static int init_inode_xattrs(struct erofs_inode *vi)
 			/* cannot be unaligned */
 			DBG_BUGON(it.ofs != erofs_blksiz(sbi));
 
-			ret = blk_read(sbi, 0, it.page, ++it.blkaddr, 1);
+			ret = erofs_blk_read(sbi, 0, it.page, ++it.blkaddr, 1);
 			if (ret < 0) {
 				free(vi->xattr_shared_xattrs);
 				vi->xattr_shared_xattrs = NULL;
@@ -1120,7 +1138,7 @@ static inline int xattr_iter_fixup(struct xattr_iter *it)
 
 	it->blkaddr += erofs_blknr(sbi, it->ofs);
 
-	ret = blk_read(sbi, 0, it->page, it->blkaddr, 1);
+	ret = erofs_blk_read(sbi, 0, it->page, it->blkaddr, 1);
 	if (ret < 0)
 		return -EIO;
 
@@ -1147,7 +1165,7 @@ static int inline_xattr_iter_pre(struct xattr_iter *it,
 	it->blkaddr = erofs_blknr(sbi, erofs_iloc(vi) + inline_xattr_ofs);
 	it->ofs = erofs_blkoff(sbi, erofs_iloc(vi) + inline_xattr_ofs);
 
-	ret = blk_read(sbi, 0, it->page, it->blkaddr, 1);
+	ret = erofs_blk_read(sbi, 0, it->page, it->blkaddr, 1);
 	if (ret < 0)
 		return -EIO;
 
@@ -1374,7 +1392,7 @@ static int shared_getxattr(struct erofs_inode *vi, struct getxattr_iter *it)
 		it->it.ofs = xattrblock_offset(vi, vi->xattr_shared_xattrs[i]);
 
 		if (!i || blkaddr != it->it.blkaddr) {
-			ret = blk_read(vi->sbi, 0, it->it.page, blkaddr, 1);
+			ret = erofs_blk_read(vi->sbi, 0, it->it.page, blkaddr, 1);
 			if (ret < 0)
 				return -EIO;
 
@@ -1451,7 +1469,7 @@ static int xattr_entrylist(struct xattr_iter *_it,
 		base_index = pf->prefix->base_index;
 	}
 
-	if (base_index >= ARRAY_SIZE(xattr_types))
+	if (!base_index || base_index >= ARRAY_SIZE(xattr_types))
 		return 1;
 	prefix = xattr_types[base_index].prefix;
 	prefix_len = xattr_types[base_index].prefix_len;
@@ -1530,7 +1548,7 @@ static int shared_listxattr(struct erofs_inode *vi, struct listxattr_iter *it)
 
 		it->it.ofs = xattrblock_offset(vi, vi->xattr_shared_xattrs[i]);
 		if (!i || blkaddr != it->it.blkaddr) {
-			ret = blk_read(vi->sbi, 0, it->it.page, blkaddr, 1);
+			ret = erofs_blk_read(vi->sbi, 0, it->it.page, blkaddr, 1);
 			if (ret < 0)
 				return -EIO;
 
diff --git a/lib/xxhash.c b/lib/xxhash.c
index 7289c77..2768375 100644
--- a/lib/xxhash.c
+++ b/lib/xxhash.c
@@ -43,14 +43,14 @@
  * - xxHash homepage: https://cyan4973.github.io/xxHash/
  * - xxHash source repository: https://github.com/Cyan4973/xxHash
  */
-
 #include "erofs/defs.h"
-#include "erofs/xxhash.h"
+#include "xxhash.h"
 
 /*-*************************************
  * Macros
  **************************************/
 #define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))
+#define xxh_rotl64(x, r) ((x << r) | (x >> (64 - r)))
 
 /*-*************************************
  * Constants
@@ -61,6 +61,12 @@ static const uint32_t PRIME32_3 = 3266489917U;
 static const uint32_t PRIME32_4 =  668265263U;
 static const uint32_t PRIME32_5 =  374761393U;
 
+static const uint64_t PRIME64_1 = 11400714785074694791ULL;
+static const uint64_t PRIME64_2 = 14029467366897019727ULL;
+static const uint64_t PRIME64_3 =  1609587929392839161ULL;
+static const uint64_t PRIME64_4 =  9650029242287828579ULL;
+static const uint64_t PRIME64_5 =  2870177450012600261ULL;
+
 /*-***************************
  * Simple Hash Functions
  ****************************/
@@ -124,3 +130,85 @@ uint32_t xxh32(const void *input, const size_t len, const uint32_t seed)
 
 	return h32;
 }
+
+static uint64_t xxh64_round(uint64_t acc, const uint64_t input)
+{
+	acc += input * PRIME64_2;
+	acc = xxh_rotl64(acc, 31);
+	acc *= PRIME64_1;
+	return acc;
+}
+
+static uint64_t xxh64_merge_round(uint64_t acc, uint64_t val)
+{
+	val = xxh64_round(0, val);
+	acc ^= val;
+	acc = acc * PRIME64_1 + PRIME64_4;
+	return acc;
+}
+
+uint64_t xxh64(const void *input, const size_t len, const uint64_t seed)
+{
+	const uint8_t *p = (const uint8_t *)input;
+	const uint8_t *const b_end = p + len;
+	uint64_t h64;
+
+	if (len >= 32) {
+		const uint8_t *const limit = b_end - 32;
+		uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
+		uint64_t v2 = seed + PRIME64_2;
+		uint64_t v3 = seed + 0;
+		uint64_t v4 = seed - PRIME64_1;
+
+		do {
+			v1 = xxh64_round(v1, get_unaligned_le64(p));
+			p += 8;
+			v2 = xxh64_round(v2, get_unaligned_le64(p));
+			p += 8;
+			v3 = xxh64_round(v3, get_unaligned_le64(p));
+			p += 8;
+			v4 = xxh64_round(v4, get_unaligned_le64(p));
+			p += 8;
+		} while (p <= limit);
+
+		h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) +
+			xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
+		h64 = xxh64_merge_round(h64, v1);
+		h64 = xxh64_merge_round(h64, v2);
+		h64 = xxh64_merge_round(h64, v3);
+		h64 = xxh64_merge_round(h64, v4);
+
+	} else {
+		h64  = seed + PRIME64_5;
+	}
+
+	h64 += (uint64_t)len;
+
+	while (p + 8 <= b_end) {
+		const uint64_t k1 = xxh64_round(0, get_unaligned_le64(p));
+
+		h64 ^= k1;
+		h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
+		p += 8;
+	}
+
+	if (p + 4 <= b_end) {
+		h64 ^= (uint64_t)(get_unaligned_le32(p)) * PRIME64_1;
+		h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
+		p += 4;
+	}
+
+	while (p < b_end) {
+		h64 ^= (*p) * PRIME64_5;
+		h64 = xxh_rotl64(h64, 11) * PRIME64_1;
+		p++;
+	}
+
+	h64 ^= h64 >> 33;
+	h64 *= PRIME64_2;
+	h64 ^= h64 >> 29;
+	h64 *= PRIME64_3;
+	h64 ^= h64 >> 32;
+
+	return h64;
+}
diff --git a/lib/xxhash.h b/lib/xxhash.h
new file mode 100644
index 0000000..723c3a5
--- /dev/null
+++ b/lib/xxhash.h
@@ -0,0 +1,40 @@
+/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */
+#ifndef __EROFS_LIB_XXHASH_H
+#define __EROFS_LIB_XXHASH_H
+
+#ifdef __cplusplus
+extern "C"
+{
+#endif
+
+#include <stdint.h>
+
+/*
+ * xxh32() - calculate the 32-bit hash of the input with a given seed.
+ *
+ * @input:  The data to hash.
+ * @length: The length of the data to hash.
+ * @seed:   The seed can be used to alter the result predictably.
+ *
+ * Return:  The 32-bit hash of the data.
+ */
+uint32_t xxh32(const void *input, size_t length, uint32_t seed);
+
+/*
+ * xxh64() - calculate the 64-bit hash of the input with a given seed.
+ *
+ * @input:  The data to hash.
+ * @length: The length of the data to hash.
+ * @seed:   The seed can be used to alter the result predictably.
+ *
+ * This function runs 2x faster on 64-bit systems, but slower on 32-bit systems.
+ *
+ * Return:  The 64-bit hash of the data.
+ */
+uint64_t xxh64(const void *input, const size_t len, const uint64_t seed);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif
diff --git a/lib/zmap.c b/lib/zmap.c
index 81fa22b..a5c5b00 100644
--- a/lib/zmap.c
+++ b/lib/zmap.c
@@ -4,10 +4,10 @@
  *
  * Copyright (C) 2018-2019 HUAWEI, Inc.
  *             https://www.huawei.com/
- * Created by Gao Xiang <gaoxiang25@huawei.com>
+ * Created by Gao Xiang <xiang@kernel.org>
  * Modified by Huang Jianan <huangjianan@oppo.com>
  */
-#include "erofs/io.h"
+#include "erofs/internal.h"
 #include "erofs/print.h"
 
 static int z_erofs_do_map_blocks(struct erofs_inode *vi,
@@ -43,7 +43,7 @@ static int z_erofs_fill_inode_lazy(struct erofs_inode *vi)
 		return 0;
 
 	pos = round_up(erofs_iloc(vi) + vi->inode_isize + vi->xattr_isize, 8);
-	ret = dev_read(sbi, 0, buf, pos, sizeof(buf));
+	ret = erofs_dev_read(sbi, 0, buf, pos, sizeof(buf));
 	if (ret < 0)
 		return -EIO;
 
@@ -133,7 +133,7 @@ static int z_erofs_reload_indexes(struct z_erofs_maprecorder *m,
 	if (map->index == eblk)
 		return 0;
 
-	ret = blk_read(m->inode->sbi, 0, mpage, eblk, 1);
+	ret = erofs_blk_read(m->inode->sbi, 0, mpage, eblk, 1);
 	if (ret < 0)
 		return -EIO;
 
@@ -197,29 +197,26 @@ static int legacy_load_cluster_from_disk(struct z_erofs_maprecorder *m,
 }
 
 static unsigned int decode_compactedbits(unsigned int lobits,
-					 unsigned int lomask,
 					 u8 *in, unsigned int pos, u8 *type)
 {
 	const unsigned int v = get_unaligned_le32(in + pos / 8) >> (pos & 7);
-	const unsigned int lo = v & lomask;
+	const unsigned int lo = v & ((1 << lobits) - 1);
 
 	*type = (v >> lobits) & 3;
 	return lo;
 }
 
-static int get_compacted_la_distance(unsigned int lclusterbits,
+static int get_compacted_la_distance(unsigned int lobits,
 				     unsigned int encodebits,
 				     unsigned int vcnt, u8 *in, int i)
 {
-	const unsigned int lomask = (1 << lclusterbits) - 1;
 	unsigned int lo, d1 = 0;
 	u8 type;
 
 	DBG_BUGON(i >= vcnt);
 
 	do {
-		lo = decode_compactedbits(lclusterbits, lomask,
-					  in, encodebits * i, &type);
+		lo = decode_compactedbits(lobits, in, encodebits * i, &type);
 
 		if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
 			return d1;
@@ -238,15 +235,14 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 {
 	struct erofs_inode *const vi = m->inode;
 	const unsigned int lclusterbits = vi->z_logical_clusterbits;
-	const unsigned int lomask = (1 << lclusterbits) - 1;
-	unsigned int vcnt, base, lo, encodebits, nblk, eofs;
+	unsigned int vcnt, base, lo, lobits, encodebits, nblk, eofs;
 	int i;
 	u8 *in, type;
 	bool big_pcluster;
 
 	if (1 << amortizedshift == 4 && lclusterbits <= 14)
 		vcnt = 2;
-	else if (1 << amortizedshift == 2 && lclusterbits == 12)
+	else if (1 << amortizedshift == 2 && lclusterbits <= 12)
 		vcnt = 16;
 	else
 		return -EOPNOTSUPP;
@@ -255,6 +251,7 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 	m->nextpackoff = round_down(pos, vcnt << amortizedshift) +
 			 (vcnt << amortizedshift);
 	big_pcluster = vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1;
+	lobits = max(lclusterbits, ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1U);
 	encodebits = ((vcnt << amortizedshift) - sizeof(__le32)) * 8 / vcnt;
 	eofs = erofs_blkoff(vi->sbi, pos);
 	base = round_down(eofs, vcnt << amortizedshift);
@@ -262,15 +259,14 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 
 	i = (eofs - base) >> amortizedshift;
 
-	lo = decode_compactedbits(lclusterbits, lomask,
-				  in, encodebits * i, &type);
+	lo = decode_compactedbits(lobits, in, encodebits * i, &type);
 	m->type = type;
 	if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
 		m->clusterofs = 1 << lclusterbits;
 
 		/* figure out lookahead_distance: delta[1] if needed */
 		if (lookahead)
-			m->delta[1] = get_compacted_la_distance(lclusterbits,
+			m->delta[1] = get_compacted_la_distance(lobits,
 						encodebits, vcnt, in, i);
 		if (lo & Z_EROFS_LI_D0_CBLKCNT) {
 			if (!big_pcluster) {
@@ -289,8 +285,8 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 		 * of which lo saves delta[1] rather than delta[0].
 		 * Hence, get delta[0] by the previous lcluster indirectly.
 		 */
-		lo = decode_compactedbits(lclusterbits, lomask,
-					  in, encodebits * (i - 1), &type);
+		lo = decode_compactedbits(lobits, in,
+					  encodebits * (i - 1), &type);
 		if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
 			lo = 0;
 		else if (lo & Z_EROFS_LI_D0_CBLKCNT)
@@ -305,8 +301,8 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 		nblk = 1;
 		while (i > 0) {
 			--i;
-			lo = decode_compactedbits(lclusterbits, lomask,
-						  in, encodebits * i, &type);
+			lo = decode_compactedbits(lobits, in,
+						  encodebits * i, &type);
 			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD)
 				i -= lo;
 
@@ -317,8 +313,8 @@ static int unpack_compacted_index(struct z_erofs_maprecorder *m,
 		nblk = 0;
 		while (i > 0) {
 			--i;
-			lo = decode_compactedbits(lclusterbits, lomask,
-						  in, encodebits * i, &type);
+			lo = decode_compactedbits(lobits, in,
+						  encodebits * i, &type);
 			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
 				if (lo & Z_EROFS_LI_D0_CBLKCNT) {
 					--i;
diff --git a/man/dump.erofs.1 b/man/dump.erofs.1
index 7316f4b..6237ead 100644
--- a/man/dump.erofs.1
+++ b/man/dump.erofs.1
@@ -45,9 +45,12 @@ or
 .I path
 required.
 .TP
-.BI \-V
+\fB\-V\fR, \fB\-\-version\fR
 Print the version number and exit.
 .TP
+\fB\-h\fR, \fB\-\-help\fR
+Display help string and exit.
+.TP
 .BI \-s
 Show superblock information.
 This is the default if no options are specified.
diff --git a/man/fsck.erofs.1 b/man/fsck.erofs.1
index 364219a..393ae9e 100644
--- a/man/fsck.erofs.1
+++ b/man/fsck.erofs.1
@@ -10,7 +10,7 @@ fsck.erofs is used to scan an EROFS filesystem \fIIMAGE\fR and check the
 integrity of it.
 .SH OPTIONS
 .TP
-.B \-V
+\fB\-V\fR, \fB\-\-version\fR
 Print the version number of fsck.erofs and exit.
 .TP
 .BI "\-d " #
@@ -27,13 +27,19 @@ You may give multiple
 .B --device
 options in the correct order.
 .TP
-.B \-\-extract
-Check if all files are well encoded. This read all compressed files,
-and hence create more I/O load,
-so it might take too much time depending on the image.
+.BI "\-\-extract" "[=directory]"
+Test to extract the whole file system. It scans all inode data, including
+compressed inode data, which leads to more I/O and CPU load, so it might
+take a long time depending on the image size.
+
+Optionally extract contents of the \fIIMAGE\fR to \fIdirectory\fR.
 .TP
-.B \-\-help
+\fB\-h\fR, \fB\-\-help\fR
 Display help string and exit.
+.TP
+\fB\-a\fR, \fB\-A\fR, \fB-y\fR
+These options do nothing at all; they are provided only for compatibility with
+the fsck programs of other filesystems.
 .SH AUTHOR
 This version of \fBfsck.erofs\fR is written by
 Daeho Jeong <daehojeong@google.com>.
diff --git a/man/mkfs.erofs.1 b/man/mkfs.erofs.1
index 00ac2ac..d599fac 100644
--- a/man/mkfs.erofs.1
+++ b/man/mkfs.erofs.1
@@ -17,14 +17,16 @@ achieve high performance for embedded devices with limited memory since it has
 unnoticable memory overhead and page cache thrashing.
 .PP
 mkfs.erofs is used to create such EROFS filesystem \fIDESTINATION\fR image file
-from \fISOURCE\fR directory.
+from \fISOURCE\fR directory or tarball.
 .SH OPTIONS
 .TP
 .BI "\-z " compression-algorithm \fR[\fP, # \fR][\fP: ... \fR]\fP
-Set a primary algorithm for data compression, which can be set with an optional
-compression level (1 to 12 for LZ4HC, 0 to 9 for LZMA and 100 to 109 for LZMA
-extreme compression) separated by a comma.  Alternative algorithms could be
-specified and separated by colons.
+Set a primary algorithm for data compression, which can be set with an
+optional compression level. Alternative algorithms could be specified
+and separated by colons.  See the output of
+.B mkfs.erofs \-\-help
+for a listing of the algorithms that \fBmkfs.erofs\fR is compiled with
+and what their respective level ranges are.
 .TP
 .BI "\-b " block-size
 Set the fundamental block size of the filesystem in bytes.  In other words,
@@ -98,8 +100,10 @@ Set the volume label for the filesystem to
 The maximum length of the volume label is 16 bytes.
 .TP
 .BI "\-T " #
-Set all files to the given UNIX timestamp. Reproducible builds require setting
-all to a specific one. By default, the source file's modification time is used.
+Specify a UNIX timestamp for image creation time for reproducible builds.
+If \fI--mkfs-time\fR is not specified, it will behave as \fI--all-time\fR:
+setting all files to the specified UNIX timestamp instead of using the
+modification times of the source files.
 .TP
 .BI "\-U " UUID
 Set the universally unique identifier (UUID) of the filesystem to
@@ -110,6 +114,10 @@ like this: "c1b9d5a2-f162-11cf-9ece-0020afc76f16".
 .B \-\-all-root
 Make all files owned by root.
 .TP
+.B \-\-all-time
+(used together with \fB-T\fR) set all files to the fixed timestamp. This is the
+default.
+.TP
 .BI "\-\-blobdev " file
 Specify an extra blob device to store chunk-based data.
 .TP
@@ -160,10 +168,10 @@ When this option is used together with
 the final file gids are
 set to \fIGID\fR + \fIGID-OFFSET\fR.
 .TP
-.B \-\-gzip
-Filter tarball streams through gzip.
+\fB\-V\fR, \fB\-\-version\fR
+Print the version number and exit.
 .TP
-.B \-\-help
+\fB\-h\fR, \fB\-\-help\fR
 Display help string and exit.
 .TP
 .B "\-\-ignore-mtime"
@@ -175,16 +183,31 @@ can reduce total metadata size. Implied by
 .BI "\-\-max-extent-bytes " #
 Specify maximum decompressed extent size in bytes.
 .TP
+.B \-\-mkfs-time
+(used together with \fB-T\fR) the given timestamp is only applied to the build
+time.
+.TP
 .B "\-\-preserve-mtime"
 Use extended inodes instead of compact inodes if the file modification time
 would overflow compact inodes. This is the default. Overrides
 .BR --ignore-mtime .
 .TP
-.B "\-\-tar=f"
-Generate a full EROFS image from a tarball.
-.TP
-.B "\-\-tar=i"
-Generate an meta-only EROFS image from a tarball.
+.BI "\-\-tar, \-\-tar="MODE
+Treat \fISOURCE\fR as a tarball or tarball-like "headerball" rather than as a
+directory.
+
+\fIMODE\fR may be one of \fBf\fR, \fBi\fR, or \fBheaderball\fR.
+
+\fBf\fR: Generate a full EROFS image from a regular tarball. (default)
+
+\fBi\fR: Generate a meta-only EROFS image from a regular tarball. Only
+metadata such as dentries, inodes, and xattrs will be added to the image,
+without file data. Uses for such images include as a layer in an overlay
+filesystem with other data-only layers.
+
+\fBheaderball\fR: Generate a meta-only EROFS image from a stream identical
+to a tarball except that file data is not present after each file header.
+It can improve performance especially when \fISOURCE\fR is not seekable.
 .TP
 .BI "\-\-uid-offset=" UIDOFFSET
 Add \fIUIDOFFSET\fR to all file UIDs.
@@ -193,6 +216,14 @@ When this option is used together with
 the final file uids are
 set to \fIUID\fR + \fIUIDOFFSET\fR.
 .TP
+.BI \-\-ungzip\fR[\fP= file \fR]\fP
+Filter tarball streams through gzip. Optionally, raw streams can be dumped
+together.
+.TP
+.BI \-\-unxz\fR[\fP= file \fR]\fP
+Filter tarball streams through xz, lzma, or lzip. Optionally, raw streams can
+be dumped together.
+.TP
 .BI "\-\-xattr-prefix=" PREFIX
 Specify a customized extended attribute namespace prefix for space saving,
 e.g. "trusted.overlay.".  You may give multiple
diff --git a/mkfs/Makefile.am b/mkfs/Makefile.am
index dd75485..6354712 100644
--- a/mkfs/Makefile.am
+++ b/mkfs/Makefile.am
@@ -7,4 +7,4 @@ mkfs_erofs_SOURCES = main.c
 mkfs_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
 mkfs_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
 	${libuuid_LIBS} ${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} \
-	${libdeflate_LIBS}
+	${libdeflate_LIBS} ${libzstd_LIBS} ${libqpl_LIBS}
diff --git a/mkfs/main.c b/mkfs/main.c
index ccb64ae..b7129eb 100644
--- a/mkfs/main.c
+++ b/mkfs/main.c
@@ -5,6 +5,7 @@
  * Created by Li Guifu <bluce.liguifu@huawei.com>
  */
 #define _GNU_SOURCE
+#include <ctype.h>
 #include <time.h>
 #include <sys/time.h>
 #include <stdlib.h>
@@ -18,7 +19,6 @@
 #include "erofs/diskbuf.h"
 #include "erofs/inode.h"
 #include "erofs/tar.h"
-#include "erofs/io.h"
 #include "erofs/compress.h"
 #include "erofs/dedupe.h"
 #include "erofs/xattr.h"
@@ -30,11 +30,11 @@
 #include "erofs/rebuild.h"
 #include "../lib/liberofs_private.h"
 #include "../lib/liberofs_uuid.h"
-
-#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))
+#include "../lib/compressor.h"
 
 static struct option long_options[] = {
-	{"help", no_argument, 0, 1},
+	{"version", no_argument, 0, 'V'},
+	{"help", no_argument, 0, 'h'},
 	{"exclude-path", required_argument, NULL, 2},
 	{"exclude-regex", required_argument, NULL, 3},
 #ifdef HAVE_LIBSELINUX
@@ -66,9 +66,24 @@ static struct option long_options[] = {
 	{"block-list-file", required_argument, NULL, 515},
 #endif
 	{"ovlfs-strip", optional_argument, NULL, 516},
+	{"offset", required_argument, NULL, 517},
 #ifdef HAVE_ZLIB
-	{"gzip", no_argument, NULL, 517},
+	{"gzip", no_argument, NULL, 518},
+	{"ungzip", optional_argument, NULL, 518},
+#endif
+#ifdef HAVE_LIBLZMA
+	{"unlzma", optional_argument, NULL, 519},
+	{"unxz", optional_argument, NULL, 519},
 #endif
+#ifdef EROFS_MT_ENABLED
+	{"workers", required_argument, NULL, 520},
+#endif
+	{"zfeature-bits", required_argument, NULL, 521},
+	{"clean", optional_argument, NULL, 522},
+	{"incremental", optional_argument, NULL, 523},
+	{"root-xattr-isize", required_argument, NULL, 524},
+	{"mkfs-time", no_argument, NULL, 525},
+	{"all-time", no_argument, NULL, 526},
 	{0, 0, 0, 0},
 };
 
@@ -76,84 +91,230 @@ static void print_available_compressors(FILE *f, const char *delim)
 {
 	int i = 0;
 	bool comma = false;
-	const char *s;
+	const struct erofs_algorithm *s;
 
 	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
 		if (comma)
 			fputs(delim, f);
-		fputs(s, f);
+		fputs(s->name, f);
 		comma = true;
 	}
 	fputc('\n', f);
 }
 
-static void usage(void)
+static void usage(int argc, char **argv)
 {
-	fputs("usage: [options] FILE SOURCE(s)\n"
-	      "Generate EROFS image (FILE) from DIRECTORY, TARBALL and/or EROFS images.  And [options] are:\n"
-	      " -b#                   set block size to # (# = page size by default)\n"
-	      " -d#                   set output message level to # (maximum 9)\n"
-	      " -x#                   set xattr tolerance to # (< 0, disable xattrs; default 2)\n"
-	      " -zX[,Y][:..]          X=compressor (Y=compression level, optional)\n"
-	      "                       alternative algorithms can be separated by colons(:)\n"
-	      " -C#                   specify the size of compress physical cluster in bytes\n"
-	      " -EX[,...]             X=extended options\n"
-	      " -L volume-label       set the volume label (maximum 16)\n"
-	      " -T#                   set a fixed UNIX timestamp # to all files\n"
-	      " -UX                   use a given filesystem UUID\n"
-	      " --all-root            make all files owned by root\n"
-	      " --blobdev=X           specify an extra device X to store chunked data\n"
-	      " --chunksize=#         generate chunk-based files with #-byte chunks\n"
-	      " --compress-hints=X    specify a file to configure per-file compression strategy\n"
-	      " --exclude-path=X      avoid including file X (X = exact literal path)\n"
-	      " --exclude-regex=X     avoid including files that match X (X = regular expression)\n"
+	int i = 0;
+	const struct erofs_algorithm *s;
+
+	//	"         1         2         3         4         5         6         7         8  "
+	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
+	printf(
+		"Usage: %s [OPTIONS] FILE SOURCE(s)\n"
+		"Generate EROFS image (FILE) from SOURCE(s).\n"
+		"\n"
+		"General options:\n"
+		" -V, --version         print the version number of mkfs.erofs and exit\n"
+		" -h, --help            display this help and exit\n"
+		"\n"
+		" -b#                   set block size to # (# = page size by default)\n"
+		" -d<0-9>               set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
+		" -x#                   set xattr tolerance to # (< 0, disable xattrs; default 2)\n"
+		" -zX[,level=Y]         X=compressor (Y=compression level, Z=dictionary size, optional)\n"
+		"    [,dictsize=Z]      alternative compressors can be separated by colons(:)\n"
+		"    [:...]             supported compressors and their option ranges are:\n",
+		argv[0], EROFS_WARN);
+	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
+		const char spaces[] = "                         ";
+
+		printf("%s%s\n", spaces, s->name);
+		if (s->c->setlevel) {
+			if (!strcmp(s->name, "lzma"))
+				/* A little kludge to show the range as disjointed
+				 * "0-9,100-109" instead of a continuous "0-109", and to
+				 * state what those two subranges respectively mean.  */
+				printf("%s  [,level=<0-9,100-109>]\t0-9=normal, 100-109=extreme (default=%i)\n",
+				       spaces, s->c->default_level);
+			else
+				printf("%s  [,level=<0-%i>]\t\t(default=%i)\n",
+				       spaces, s->c->best_level, s->c->default_level);
+		}
+		if (s->c->setdictsize) {
+			if (s->c->default_dictsize)
+				printf("%s  [,dictsize=<dictsize>]\t(default=%u, max=%u)\n",
+				       spaces, s->c->default_dictsize, s->c->max_dictsize);
+			else
+				printf("%s  [,dictsize=<dictsize>]\t(default=<auto>, max=%u)\n",
+				       spaces, s->c->max_dictsize);
+		}
+	}
+	printf(
+		" -C#                   specify the size of compress physical cluster in bytes\n"
+		" -EX[,...]             X=extended options\n"
+		" -L volume-label       set the volume label (maximum 16)\n"
+		" -T#                   specify a fixed UNIX timestamp # as build time\n"
+		"    --all-time         the timestamp is also applied to all files (default)\n"
+		"    --mkfs-time        the timestamp is applied as build time only\n"
+		" -UX                   use a given filesystem UUID\n"
+		" --all-root            make all files owned by root\n"
+		" --blobdev=X           specify an extra device X to store chunked data\n"
+		" --chunksize=#         generate chunk-based files with #-byte chunks\n"
+		" --clean=X             run full clean build (default) or:\n"
+		" --incremental=X       run incremental build\n"
+		"                       (X = data|rvsp; data=full data, rvsp=space is allocated\n"
+		"                                       and filled with zeroes)\n"
+		" --compress-hints=X    specify a file to configure per-file compression strategy\n"
+		" --exclude-path=X      avoid including file X (X = exact literal path)\n"
+		" --exclude-regex=X     avoid including files that match X (X = regular expression)\n"
 #ifdef HAVE_LIBSELINUX
-	      " --file-contexts=X     specify a file contexts file to setup selinux labels\n"
+		" --file-contexts=X     specify a file contexts file to setup selinux labels\n"
+#endif
+		" --force-uid=#         set all file uids to # (# = UID)\n"
+		" --force-gid=#         set all file gids to # (# = GID)\n"
+		" --uid-offset=#        add offset # to all file uids (# = id offset)\n"
+		" --gid-offset=#        add offset # to all file gids (# = id offset)\n"
+		" --ignore-mtime        use build time instead of strict per-file modification time\n"
+		" --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
+		" --mount-point=X       X=prefix of target fs path (default: /)\n"
+		" --preserve-mtime      keep per-file modification time strictly\n"
+		" --offset=#            skip # bytes at the beginning of IMAGE.\n"
+		" --root-xattr-isize=#  ensure the inline xattr size of the root directory is # bytes at least\n"
+		" --aufs                replace aufs special files with overlayfs metadata\n"
+		" --tar=X               generate a full or index-only image from a tarball(-ish) source\n"
+		"                       (X = f|i|headerball; f=full mode, i=index mode,\n"
+		"                                            headerball=file data is omited in the source stream)\n"
+		" --ovlfs-strip=<0,1>   strip overlayfs metadata in the target image (e.g. whiteouts)\n"
+		" --quiet               quiet execution (do not write anything to standard output.)\n"
+#ifndef NDEBUG
+		" --random-pclusterblks randomize pclusterblks for big pcluster (debugging only)\n"
+		" --random-algorithms   randomize per-file algorithms (debugging only)\n"
 #endif
-	      " --force-uid=#         set all file uids to # (# = UID)\n"
-	      " --force-gid=#         set all file gids to # (# = GID)\n"
-	      " --uid-offset=#        add offset # to all file uids (# = id offset)\n"
-	      " --gid-offset=#        add offset # to all file gids (# = id offset)\n"
 #ifdef HAVE_ZLIB
-	      " --gzip                try to filter the tarball stream through gzip\n"
+		" --ungzip[=X]          try to filter the tarball stream through gzip\n"
+		"                       (and optionally dump the raw stream to X together)\n"
 #endif
-	      " --help                display this help and exit\n"
-	      " --ignore-mtime        use build time instead of strict per-file modification time\n"
-	      " --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
-	      " --preserve-mtime      keep per-file modification time strictly\n"
-	      " --aufs                replace aufs special files with overlayfs metadata\n"
-	      " --tar=[fi]            generate an image from tarball(s)\n"
-	      " --ovlfs-strip=[01]    strip overlayfs metadata in the target image (e.g. whiteouts)\n"
-	      " --quiet               quiet execution (do not write anything to standard output.)\n"
-#ifndef NDEBUG
-	      " --random-pclusterblks randomize pclusterblks for big pcluster (debugging only)\n"
-	      " --random-algorithms   randomize per-file algorithms (debugging only)\n"
+#ifdef HAVE_LIBLZMA
+		" --unxz[=X]            try to filter the tarball stream through xz/lzma/lzip\n"
+		"                       (and optionally dump the raw stream to X together)\n"
+#endif
+#ifdef EROFS_MT_ENABLED
+		" --workers=#           set the number of worker threads to # (default: %u)\n"
 #endif
-	      " --xattr-prefix=X      X=extra xattr name prefix\n"
-	      " --mount-point=X       X=prefix of target fs path (default: /)\n"
+		" --xattr-prefix=X      X=extra xattr name prefix\n"
+		" --zfeature-bits=#     toggle filesystem compression features according to given bits #\n"
 #ifdef WITH_ANDROID
-	      "\nwith following android-specific options:\n"
-	      " --product-out=X       X=product_out directory\n"
-	      " --fs-config-file=X    X=fs_config file\n"
-	      " --block-list-file=X   X=block_list file\n"
+		"\n"
+		"Android-specific options:\n"
+		" --product-out=X       X=product_out directory\n"
+		" --fs-config-file=X    X=fs_config file\n"
+		" --block-list-file=X   X=block_list file\n"
+#endif
+#ifdef EROFS_MT_ENABLED
+		, erofs_get_available_processors() /* --workers= */
 #endif
-	      "\nAvailable compressors are: ", stderr);
-	print_available_compressors(stderr, ", ");
+	);
+}
+
+static void version(void)
+{
+	printf("mkfs.erofs (erofs-utils) %s\navailable compressors: ",
+	       cfg.c_version);
+	print_available_compressors(stdout, ", ");
 }
 
 static unsigned int pclustersize_packed, pclustersize_max;
 static struct erofs_tarfile erofstar = {
 	.global.xattrs = LIST_HEAD_INIT(erofstar.global.xattrs)
 };
-static bool tar_mode, rebuild_mode, gzip_supported;
+static bool tar_mode, rebuild_mode, incremental_mode;
+
+enum {
+	EROFS_MKFS_DATA_IMPORT_DEFAULT,
+	EROFS_MKFS_DATA_IMPORT_FULLDATA,
+	EROFS_MKFS_DATA_IMPORT_RVSP,
+	EROFS_MKFS_DATA_IMPORT_SPARSE,
+} dataimport_mode;
 
 static unsigned int rebuild_src_count;
 static LIST_HEAD(rebuild_src_list);
+static u8 fixeduuid[16];
+static bool valid_fixeduuid;
+
+static int erofs_mkfs_feat_set_legacy_compress(bool en, const char *val,
+					       unsigned int vallen)
+{
+	if (vallen)
+		return -EINVAL;
+	/* disable compacted indexes and 0padding */
+	cfg.c_legacy_compress = en;
+	return 0;
+}
+
+static int erofs_mkfs_feat_set_ztailpacking(bool en, const char *val,
+					    unsigned int vallen)
+{
+	if (vallen)
+		return -EINVAL;
+	cfg.c_ztailpacking = en;
+	return 0;
+}
+
+static int erofs_mkfs_feat_set_fragments(bool en, const char *val,
+					 unsigned int vallen)
+{
+	if (!en) {
+		if (vallen)
+			return -EINVAL;
+		cfg.c_fragments = false;
+		return 0;
+	}
+
+	if (vallen) {
+		char *endptr;
+		u64 i = strtoull(val, &endptr, 0);
+
+		if (endptr - val != vallen) {
+			erofs_err("invalid pcluster size %s for the packed file %s", val);
+			return -EINVAL;
+		}
+		pclustersize_packed = i;
+	}
+	cfg.c_fragments = true;
+	return 0;
+}
+
+static int erofs_mkfs_feat_set_all_fragments(bool en, const char *val,
+					     unsigned int vallen)
+{
+	cfg.c_all_fragments = en;
+	return erofs_mkfs_feat_set_fragments(en, val, vallen);
+}
+
+static int erofs_mkfs_feat_set_dedupe(bool en, const char *val,
+				      unsigned int vallen)
+{
+	if (vallen)
+		return -EINVAL;
+	cfg.c_dedupe = en;
+	return 0;
+}
+
+static struct {
+	char *feat;
+	int (*set)(bool en, const char *val, unsigned int len);
+} z_erofs_mkfs_features[] = {
+	{"legacy-compress", erofs_mkfs_feat_set_legacy_compress},
+	{"ztailpacking", erofs_mkfs_feat_set_ztailpacking},
+	{"fragments", erofs_mkfs_feat_set_fragments},
+	{"all-fragments", erofs_mkfs_feat_set_all_fragments},
+	{"dedupe", erofs_mkfs_feat_set_dedupe},
+	{NULL, NULL},
+};
 
 static int parse_extended_opts(const char *opts)
 {
 #define MATCH_EXTENTED_OPT(opt, token, keylen) \
-	(keylen == sizeof(opt) - 1 && !memcmp(token, opt, sizeof(opt) - 1))
+	(keylen == strlen(opt) && !memcmp(token, opt, keylen))
 
 	const char *token, *next, *tokenend, *value __maybe_unused;
 	unsigned int keylen, vallen;
@@ -192,12 +353,7 @@ static int parse_extended_opts(const char *opts)
 			clear = true;
 		}
 
-		if (MATCH_EXTENTED_OPT("legacy-compress", token, keylen)) {
-			if (vallen)
-				return -EINVAL;
-			/* disable compacted indexes and 0padding */
-			cfg.c_legacy_compress = true;
-		} else if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
+		if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
 			if (vallen)
 				return -EINVAL;
 			cfg.c_force_inodeversion = FORCE_INODE_COMPACT;
@@ -209,7 +365,7 @@ static int parse_extended_opts(const char *opts)
 		} else if (MATCH_EXTENTED_OPT("nosbcrc", token, keylen)) {
 			if (vallen)
 				return -EINVAL;
-			erofs_sb_clear_sb_chksum(&sbi);
+			erofs_sb_clear_sb_chksum(&g_sbi);
 		} else if (MATCH_EXTENTED_OPT("noinline_data", token, keylen)) {
 			if (vallen)
 				return -EINVAL;
@@ -226,42 +382,135 @@ static int parse_extended_opts(const char *opts)
 			if (vallen)
 				return -EINVAL;
 			cfg.c_force_chunkformat = FORCE_INODE_CHUNK_INDEXES;
-		} else if (MATCH_EXTENTED_OPT("ztailpacking", token, keylen)) {
+		} else if (MATCH_EXTENTED_OPT("xattr-name-filter", token, keylen)) {
 			if (vallen)
 				return -EINVAL;
-			cfg.c_ztailpacking = !clear;
-		} else if (MATCH_EXTENTED_OPT("all-fragments", token, keylen)) {
-			cfg.c_all_fragments = true;
-			goto handle_fragment;
-		} else if (MATCH_EXTENTED_OPT("fragments", token, keylen)) {
-			char *endptr;
-			u64 i;
-
-handle_fragment:
-			cfg.c_fragments = true;
-			if (vallen) {
-				i = strtoull(value, &endptr, 0);
-				if (endptr - value != vallen) {
-					erofs_err("invalid pcluster size for the packed file %s",
-						  next);
-					return -EINVAL;
-				}
-				pclustersize_packed = i;
+			cfg.c_xattr_name_filter = !clear;
+		} else {
+			int i, err;
+
+			for (i = 0; z_erofs_mkfs_features[i].feat; ++i) {
+				if (!MATCH_EXTENTED_OPT(z_erofs_mkfs_features[i].feat,
+							token, keylen))
+					continue;
+				err = z_erofs_mkfs_features[i].set(!clear, value, vallen);
+				if (err)
+					return err;
+				break;
 			}
-		} else if (MATCH_EXTENTED_OPT("dedupe", token, keylen)) {
-			if (vallen)
+
+			if (!z_erofs_mkfs_features[i].feat) {
+				erofs_err("unknown extended option %.*s",
+					  (int)(p - token), token);
 				return -EINVAL;
-			cfg.c_dedupe = !clear;
-		} else if (MATCH_EXTENTED_OPT("xattr-name-filter", token, keylen)) {
-			if (vallen)
+			}
+		}
+	}
+	return 0;
+}
+
+static int mkfs_apply_zfeature_bits(uintmax_t bits)
+{
+	int i;
+
+	for (i = 0; bits; ++i) {
+		int err;
+
+		if (!z_erofs_mkfs_features[i].feat) {
+			erofs_err("unsupported zfeature bit %u", i);
+			return -EINVAL;
+		}
+		err = z_erofs_mkfs_features[i].set(bits & 1, NULL, 0);
+		if (err) {
+			erofs_err("failed to apply zfeature %s",
+				  z_erofs_mkfs_features[i].feat);
+			return err;
+		}
+		bits >>= 1;
+	}
+	return 0;
+}
+
+static void mkfs_parse_tar_cfg(char *cfg)
+{
+	char *p;
+
+	tar_mode = true;
+	if (!cfg)
+		return;
+	p = strchr(cfg, ',');
+	if (p) {
+		*p = '\0';
+		if ((*++p) != '\0')
+			erofstar.mapfile = strdup(p);
+	}
+	if (!strcmp(cfg, "headerball"))
+		erofstar.headeronly_mode = true;
+
+	if (erofstar.headeronly_mode || !strcmp(optarg, "i") ||
+	    !strcmp(optarg, "0"))
+		erofstar.index_mode = true;
+}
+
+static int mkfs_parse_one_compress_alg(char *alg,
+				       struct erofs_compr_opts *copts)
+{
+	char *p, *q, *opt, *endptr;
+
+	copts->level = -1;
+	copts->dict_size = 0;
+
+	p = strchr(alg, ',');
+	if (p) {
+		copts->alg = strndup(alg, p - alg);
+
+		/* support old '-zlzma,9' form */
+		if (isdigit(*(p + 1))) {
+			copts->level = strtol(p + 1, &endptr, 10);
+			if (*endptr && *endptr != ',') {
+				erofs_err("invalid compression level %s",
+					  p + 1);
 				return -EINVAL;
-			cfg.c_xattr_name_filter = !clear;
+			}
+			return 0;
+		}
+	} else {
+		copts->alg = strdup(alg);
+		return 0;
+	}
+
+	opt = p + 1;
+	while (opt) {
+		q = strchr(opt, ',');
+		if (q)
+			*q = '\0';
+
+		if ((p = strstr(opt, "level="))) {
+			p += strlen("level=");
+			copts->level = strtol(p, &endptr, 10);
+			if ((endptr == p) || (*endptr && *endptr != ',')) {
+				erofs_err("invalid compression level %s", p);
+				return -EINVAL;
+			}
+		} else if ((p = strstr(opt, "dictsize="))) {
+			p += strlen("dictsize=");
+			copts->dict_size = strtoul(p, &endptr, 10);
+			if (*endptr == 'k' || *endptr == 'K')
+				copts->dict_size <<= 10;
+			else if (*endptr == 'm' || *endptr == 'M')
+				copts->dict_size <<= 20;
+			else if ((endptr == p) || (*endptr && *endptr != ',')) {
+				erofs_err("invalid compression dictsize %s", p);
+				return -EINVAL;
+			}
 		} else {
-			erofs_err("unknown extended option %.*s",
-				  p - token, token);
+			erofs_err("invalid compression option %s", opt);
 			return -EINVAL;
 		}
+
+		opt = q ? q + 1 : NULL;
 	}
+
 	return 0;
 }
 
@@ -269,23 +518,17 @@ static int mkfs_parse_compress_algs(char *algs)
 {
 	unsigned int i;
 	char *s;
+	int ret;
 
 	for (s = strtok(algs, ":"), i = 0; s; s = strtok(NULL, ":"), ++i) {
-		const char *lv;
-
 		if (i >= EROFS_MAX_COMPR_CFGS - 1) {
 			erofs_err("too many algorithm types");
 			return -EINVAL;
 		}
 
-		lv = strchr(s, ',');
-		if (lv) {
-			cfg.c_compr_level[i] = atoi(lv + 1);
-			cfg.c_compr_alg[i] = strndup(s, lv - s);
-		} else {
-			cfg.c_compr_level[i] = -1;
-			cfg.c_compr_alg[i] = strdup(s);
-		}
+		ret = mkfs_parse_one_compress_alg(s, &cfg.c_compr_opts[i]);
+		if (ret)
+			return ret;
 	}
 	return 0;
 }
@@ -297,7 +540,7 @@ static void erofs_rebuild_cleanup(void)
 	list_for_each_entry_safe(src, n, &rebuild_src_list, list) {
 		list_del(&src->list);
 		erofs_put_super(src);
-		dev_close(src);
+		erofs_dev_close(src);
 		free(src);
 	}
 	rebuild_src_count = 0;
@@ -308,8 +551,10 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 	char *endptr;
 	int opt, i, err;
 	bool quiet = false;
+	int tarerofs_decoder = 0;
+	bool has_timestamp = false;
 
-	while ((opt = getopt_long(argc, argv, "C:E:L:T:U:b:d:x:z:",
+	while ((opt = getopt_long(argc, argv, "C:E:L:T:U:b:d:x:z:Vh",
 				  long_options, NULL)) != -1) {
 		switch (opt) {
 		case 'z':
@@ -324,7 +569,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 				erofs_err("invalid block size %s", optarg);
 				return -EINVAL;
 			}
-			sbi.blkszbits = ilog2(i);
+			g_sbi.blkszbits = ilog2(i);
 			break;
 
 		case 'd':
@@ -353,12 +598,12 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 
 		case 'L':
 			if (optarg == NULL ||
-			    strlen(optarg) > sizeof(sbi.volume_name)) {
+			    strlen(optarg) > sizeof(g_sbi.volume_name)) {
 				erofs_err("invalid volume label");
 				return -EINVAL;
 			}
-			strncpy(sbi.volume_name, optarg,
-				sizeof(sbi.volume_name));
+			strncpy(g_sbi.volume_name, optarg,
+				sizeof(g_sbi.volume_name));
 			break;
 
 		case 'T':
@@ -367,13 +612,14 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 				erofs_err("invalid UNIX timestamp %s", optarg);
 				return -EINVAL;
 			}
-			cfg.c_timeinherit = TIMESTAMP_FIXED;
+			has_timestamp = true;
 			break;
 		case 'U':
-			if (erofs_uuid_parse(optarg, sbi.uuid)) {
+			if (erofs_uuid_parse(optarg, fixeduuid)) {
 				erofs_err("invalid UUID %s", optarg);
 				return -EINVAL;
 			}
+			valid_fixeduuid = true;
 			break;
 		case 2:
 			opt = erofs_parse_exclude_path(optarg, false);
@@ -473,7 +719,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 					  optarg);
 				return -EINVAL;
 			}
-			erofs_sb_set_chunked_file(&sbi);
+			erofs_sb_set_chunked_file(&g_sbi);
 			break;
 		case 12:
 			quiet = true;
@@ -514,13 +760,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 			cfg.c_extra_ea_name_prefixes = true;
 			break;
 		case 20:
-			if (optarg && (!strcmp(optarg, "i") ||
-				!strcmp(optarg, "0") || !memcmp(optarg, "0,", 2))) {
-				erofstar.index_mode = true;
-				if (!memcmp(optarg, "0,", 2))
-					erofstar.mapfile = strdup(optarg + 2);
-			}
-			tar_mode = true;
+			mkfs_parse_tar_cfg(optarg);
 			break;
 		case 21:
 			erofstar.aufs = true;
@@ -532,10 +772,79 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 				cfg.c_ovlfs_strip = false;
 			break;
 		case 517:
-			gzip_supported = true;
+			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
+			if (*endptr != '\0') {
+				erofs_err("invalid disk offset %s", optarg);
+				return -EINVAL;
+			}
+			break;
+		case 518:
+		case 519:
+			if (optarg)
+				erofstar.dumpfile = strdup(optarg);
+			tarerofs_decoder = EROFS_IOS_DECODER_GZIP + (opt - 518);
+			break;
+#ifdef EROFS_MT_ENABLED
+		case 520: {
+			unsigned int processors;
+
+			cfg.c_mt_workers = strtoul(optarg, &endptr, 0);
+			if (errno || *endptr != '\0') {
+				erofs_err("invalid worker number %s", optarg);
+				return -EINVAL;
+			}
+
+			processors = erofs_get_available_processors();
+			if (cfg.c_mt_workers > processors)
+				erofs_warn("%d workers exceed %d processors, potentially impacting performance.",
+					   cfg.c_mt_workers, processors);
+			break;
+		}
+#endif
+		case 521:
+			i = strtol(optarg, &endptr, 0);
+			if (errno || *endptr != '\0') {
+				erofs_err("invalid zfeature bits %s", optarg);
+				return -EINVAL;
+			}
+			err = mkfs_apply_zfeature_bits(i);
+			if (err)
+				return err;
+			break;
+		case 522:
+		case 523:
+			if (!optarg || !strcmp(optarg, "data")) {
+				dataimport_mode = EROFS_MKFS_DATA_IMPORT_FULLDATA;
+			} else if (!strcmp(optarg, "rvsp")) {
+				dataimport_mode = EROFS_MKFS_DATA_IMPORT_RVSP;
+			} else {
+				dataimport_mode = strtol(optarg, &endptr, 0);
+				if (errno || *endptr != '\0') {
+					erofs_err("invalid --%s=%s",
+						  opt == 523 ? "incremental" : "clean", optarg);
+					return -EINVAL;
+				}
+			}
+			incremental_mode = (opt == 523);
+			break;
+		case 524:
+			cfg.c_root_xattr_isize = strtoull(optarg, &endptr, 0);
+			if (*endptr != '\0') {
+				erofs_err("invalid the minimum inline xattr size %s", optarg);
+				return -EINVAL;
+			}
+			break;
+		case 525:
+			cfg.c_timeinherit = TIMESTAMP_NONE;
 			break;
-		case 1:
-			usage();
+		case 526:
+			cfg.c_timeinherit = TIMESTAMP_FIXED;
+			break;
+		case 'V':
+			version();
+			exit(0);
+		case 'h':
+			usage(argc, argv);
 			exit(0);
 
 		default: /* '?' */
@@ -543,7 +852,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 		}
 	}
 
-	if (cfg.c_blobdev_path && cfg.c_chunkbits < sbi.blkszbits) {
+	if (cfg.c_blobdev_path && cfg.c_chunkbits < g_sbi.blkszbits) {
 		erofs_err("--blobdev must be used together with --chunksize");
 		return -EINVAL;
 	}
@@ -577,7 +886,8 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 					  strerror(errno));
 				return -errno;
 			}
-			err = erofs_iostream_open(&erofstar.ios, dupfd, gzip_supported);
+			err = erofs_iostream_open(&erofstar.ios, dupfd,
+						  tarerofs_decoder);
 			if (err)
 				return err;
 		}
@@ -598,9 +908,21 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 				erofs_err("failed to open file: %s", cfg.c_src_path);
 				return -errno;
 			}
-			err = erofs_iostream_open(&erofstar.ios, fd, gzip_supported);
+			err = erofs_iostream_open(&erofstar.ios, fd,
+						  tarerofs_decoder);
 			if (err)
 				return err;
+
+			if (erofstar.dumpfile) {
+				fd = open(erofstar.dumpfile,
+					  O_WRONLY | O_CREAT | O_TRUNC, 0644);
+				if (fd < 0) {
+					erofs_err("failed to open dumpfile: %s",
+						  erofstar.dumpfile);
+					return -errno;
+				}
+				erofstar.ios.dumpfd = fd;
+			}
 		} else {
 			err = lstat(cfg.c_src_path, &st);
 			if (err)
@@ -622,7 +944,7 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 					return -ENOMEM;
 				}
 
-				err = dev_open_ro(src, srcpath);
+				err = erofs_dev_open(src, srcpath, O_RDONLY);
 				if (err) {
 					free(src);
 					erofs_rebuild_cleanup();
@@ -643,137 +965,39 @@ static int mkfs_parse_options_cfg(int argc, char *argv[])
 		cfg.c_showprogress = false;
 	}
 
-	if (cfg.c_compr_alg[0] && erofs_blksiz(&sbi) != getpagesize())
+	if (cfg.c_compr_opts[0].alg && erofs_blksiz(&g_sbi) != getpagesize())
 		erofs_warn("Please note that subpage blocksize with compression isn't yet supported in kernel. "
 			   "This compressed image will only work with bs = ps = %u bytes",
-			   erofs_blksiz(&sbi));
+			   erofs_blksiz(&g_sbi));
 
 	if (pclustersize_max) {
-		if (pclustersize_max < erofs_blksiz(&sbi) ||
-		    pclustersize_max % erofs_blksiz(&sbi)) {
+		if (pclustersize_max < erofs_blksiz(&g_sbi) ||
+		    pclustersize_max % erofs_blksiz(&g_sbi)) {
 			erofs_err("invalid physical clustersize %u",
 				  pclustersize_max);
 			return -EINVAL;
 		}
-		cfg.c_pclusterblks_max = pclustersize_max >> sbi.blkszbits;
-		cfg.c_pclusterblks_def = cfg.c_pclusterblks_max;
+		cfg.c_mkfs_pclustersize_max = pclustersize_max;
+		cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
 	}
-	if (cfg.c_chunkbits && cfg.c_chunkbits < sbi.blkszbits) {
+	if (cfg.c_chunkbits && cfg.c_chunkbits < g_sbi.blkszbits) {
 		erofs_err("chunksize %u must be larger than block size",
 			  1u << cfg.c_chunkbits);
 		return -EINVAL;
 	}
 
 	if (pclustersize_packed) {
-		if (pclustersize_max < erofs_blksiz(&sbi) ||
-		    pclustersize_max % erofs_blksiz(&sbi)) {
+		if (pclustersize_packed < erofs_blksiz(&g_sbi) ||
+		    pclustersize_packed % erofs_blksiz(&g_sbi)) {
 			erofs_err("invalid pcluster size for the packed file %u",
 				  pclustersize_packed);
 			return -EINVAL;
 		}
-		cfg.c_pclusterblks_packed = pclustersize_packed >> sbi.blkszbits;
-	}
-	return 0;
-}
-
-int erofs_mkfs_update_super_block(struct erofs_buffer_head *bh,
-				  erofs_nid_t root_nid,
-				  erofs_blk_t *blocks,
-				  erofs_nid_t packed_nid)
-{
-	struct erofs_super_block sb = {
-		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
-		.blkszbits = sbi.blkszbits,
-		.inos   = cpu_to_le64(sbi.inos),
-		.build_time = cpu_to_le64(sbi.build_time),
-		.build_time_nsec = cpu_to_le32(sbi.build_time_nsec),
-		.blocks = 0,
-		.meta_blkaddr  = cpu_to_le32(sbi.meta_blkaddr),
-		.xattr_blkaddr = cpu_to_le32(sbi.xattr_blkaddr),
-		.xattr_prefix_count = sbi.xattr_prefix_count,
-		.xattr_prefix_start = cpu_to_le32(sbi.xattr_prefix_start),
-		.feature_incompat = cpu_to_le32(sbi.feature_incompat),
-		.feature_compat = cpu_to_le32(sbi.feature_compat &
-					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
-		.extra_devices = cpu_to_le16(sbi.extra_devices),
-		.devt_slotoff = cpu_to_le16(sbi.devt_slotoff),
-	};
-	const u32 sb_blksize = round_up(EROFS_SUPER_END, erofs_blksiz(&sbi));
-	char *buf;
-	int ret;
-
-	*blocks         = erofs_mapbh(NULL);
-	sb.blocks       = cpu_to_le32(*blocks);
-	sb.root_nid     = cpu_to_le16(root_nid);
-	sb.packed_nid    = cpu_to_le64(packed_nid);
-	memcpy(sb.uuid, sbi.uuid, sizeof(sb.uuid));
-	memcpy(sb.volume_name, sbi.volume_name, sizeof(sb.volume_name));
-
-	if (erofs_sb_has_compr_cfgs(&sbi))
-		sb.u1.available_compr_algs = cpu_to_le16(sbi.available_compr_algs);
-	else
-		sb.u1.lz4_max_distance = cpu_to_le16(sbi.lz4_max_distance);
-
-	buf = calloc(sb_blksize, 1);
-	if (!buf) {
-		erofs_err("failed to allocate memory for sb: %s",
-			  erofs_strerror(-errno));
-		return -ENOMEM;
-	}
-	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));
-
-	ret = dev_write(&sbi, buf, erofs_btell(bh, false), EROFS_SUPER_END);
-	free(buf);
-	erofs_bdrop(bh, false);
-	return ret;
-}
-
-static int erofs_mkfs_superblock_csum_set(void)
-{
-	int ret;
-	u8 buf[EROFS_MAX_BLOCK_SIZE];
-	u32 crc;
-	unsigned int len;
-	struct erofs_super_block *sb;
-
-	ret = blk_read(&sbi, 0, buf, 0, erofs_blknr(&sbi, EROFS_SUPER_END) + 1);
-	if (ret) {
-		erofs_err("failed to read superblock to set checksum: %s",
-			  erofs_strerror(ret));
-		return ret;
-	}
-
-	/*
-	 * skip the first 1024 bytes, to allow for the installation
-	 * of x86 boot sectors and other oddities.
-	 */
-	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);
-
-	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
-		erofs_err("internal error: not an erofs valid image");
-		return -EFAULT;
+		cfg.c_mkfs_pclustersize_packed = pclustersize_packed;
 	}
 
-	/* turn on checksum feature */
-	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
-					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
-	if (erofs_blksiz(&sbi) > EROFS_SUPER_OFFSET)
-		len = erofs_blksiz(&sbi) - EROFS_SUPER_OFFSET;
-	else
-		len = erofs_blksiz(&sbi);
-	crc = erofs_crc32c(~0, (u8 *)sb, len);
-
-	/* set up checksum field to erofs_super_block */
-	sb->checksum = cpu_to_le32(crc);
-
-	ret = blk_write(&sbi, buf, 0, 1);
-	if (ret) {
-		erofs_err("failed to write checksummed superblock: %s",
-			  erofs_strerror(ret));
-		return ret;
-	}
-
-	erofs_info("superblock checksum 0x%08x written", crc);
+	if (has_timestamp && cfg.c_timeinherit == TIMESTAMP_UNSPECIFIED)
+		cfg.c_timeinherit = TIMESTAMP_FIXED;
 	return 0;
 }
 
@@ -783,13 +1007,16 @@ static void erofs_mkfs_default_options(void)
 	cfg.c_legacy_compress = false;
 	cfg.c_inline_data = true;
 	cfg.c_xattr_name_filter = true;
-	sbi.blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
-	sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_ZERO_PADDING;
-	sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM |
+#ifdef EROFS_MT_ENABLED
+	cfg.c_mt_workers = erofs_get_available_processors();
+	cfg.c_mkfs_segment_size = 16ULL * 1024 * 1024;
+#endif
+	g_sbi.blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
+	cfg.c_mkfs_pclustersize_max = erofs_blksiz(&g_sbi);
+	cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
+	g_sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_ZERO_PADDING;
+	g_sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM |
 			     EROFS_FEATURE_COMPAT_MTIME;
-
-	/* generate a default uuid first */
-	erofs_uuid_generate(sbi.uuid);
 }
 
 /* https://reproducible-builds.org/specs/source-date-epoch/ for more details */
@@ -824,50 +1051,53 @@ void erofs_show_progs(int argc, char *argv[])
 	if (cfg.c_dbg_lvl >= EROFS_WARN)
 		printf("%s %s\n", basename(argv[0]), cfg.c_version);
 }
-static struct erofs_inode *erofs_alloc_root_inode(void)
-{
-	struct erofs_inode *root;
-
-	root = erofs_new_inode();
-	if (IS_ERR(root))
-		return root;
-	root->i_srcpath = strdup("/");
-	root->i_mode = S_IFDIR | 0777;
-	root->i_parent = root;
-	root->i_mtime = root->sbi->build_time;
-	root->i_mtime_nsec = root->sbi->build_time_nsec;
-	erofs_init_empty_dir(root);
-	return root;
-}
 
-static int erofs_rebuild_load_trees(struct erofs_inode *root)
+static int erofs_mkfs_rebuild_load_trees(struct erofs_inode *root)
 {
 	struct erofs_sb_info *src;
 	unsigned int extra_devices = 0;
 	erofs_blk_t nblocks;
 	int ret, idx;
+	enum erofs_rebuild_datamode datamode;
+
+	switch (dataimport_mode) {
+	case EROFS_MKFS_DATA_IMPORT_DEFAULT:
+		datamode = EROFS_REBUILD_DATA_BLOB_INDEX;
+		break;
+	case EROFS_MKFS_DATA_IMPORT_FULLDATA:
+		datamode = EROFS_REBUILD_DATA_FULL;
+		break;
+	case EROFS_MKFS_DATA_IMPORT_RVSP:
+		datamode = EROFS_REBUILD_DATA_RESVSP;
+		break;
+	default:
+		return -EINVAL;
+	}
 
 	list_for_each_entry(src, &rebuild_src_list, list) {
-		ret = erofs_rebuild_load_tree(root, src);
+		ret = erofs_rebuild_load_tree(root, src, datamode);
 		if (ret) {
 			erofs_err("failed to load %s", src->devname);
 			return ret;
 		}
 		if (src->extra_devices > 1) {
-			erofs_err("%s: unsupported number of extra devices",
+			erofs_err("%s: unsupported number %u of extra devices",
 				  src->devname, src->extra_devices);
 			return -EOPNOTSUPP;
 		}
 		extra_devices += src->extra_devices;
 	}
 
-	if (extra_devices && extra_devices != rebuild_src_count) {
+	if (datamode != EROFS_REBUILD_DATA_BLOB_INDEX)
+		return 0;
+
+	if (extra_devices != rebuild_src_count) {
 		erofs_err("extra_devices(%u) is mismatched with source images(%u)",
 			  extra_devices, rebuild_src_count);
 		return -EOPNOTSUPP;
 	}
 
-	ret = erofs_mkfs_init_devices(&sbi, rebuild_src_count);
+	ret = erofs_mkfs_init_devices(&g_sbi, rebuild_src_count);
 	if (ret)
 		return ret;
 
@@ -882,12 +1112,12 @@ static int erofs_rebuild_load_trees(struct erofs_inode *root)
 		}
 		DBG_BUGON(src->dev < 1);
 		idx = src->dev - 1;
-		sbi.devs[idx].blocks = nblocks;
+		g_sbi.devs[idx].blocks = nblocks;
 		if (tag && *tag)
-			memcpy(sbi.devs[idx].tag, tag, sizeof(sbi.devs[0].tag));
+			memcpy(g_sbi.devs[idx].tag, tag, sizeof(g_sbi.devs[0].tag));
 		else
 			/* convert UUID of the source image to a hex string */
-			sprintf((char *)sbi.devs[idx].tag,
+			sprintf((char *)g_sbi.devs[idx].tag,
 				"%04x%04x%04x%04x%04x%04x%04x%04x",
 				(src->uuid[0] << 8) | src->uuid[1],
 				(src->uuid[2] << 8) | src->uuid[3],
@@ -904,31 +1134,33 @@ static int erofs_rebuild_load_trees(struct erofs_inode *root)
 static void erofs_mkfs_showsummaries(erofs_blk_t nblocks)
 {
 	char uuid_str[37] = {};
+	char *incr = incremental_mode ? "new" : "total";
 
 	if (!(cfg.c_dbg_lvl > EROFS_ERR && cfg.c_showprogress))
 		return;
 
-	erofs_uuid_unparse_lower(sbi.uuid, uuid_str);
+	erofs_uuid_unparse_lower(g_sbi.uuid, uuid_str);
 
 	fprintf(stdout, "------\nFilesystem UUID: %s\n"
 		"Filesystem total blocks: %u (of %u-byte blocks)\n"
 		"Filesystem total inodes: %llu\n"
-		"Filesystem total metadata blocks: %u\n"
-		"Filesystem total deduplicated bytes (of source files): %llu\n",
-		uuid_str, nblocks, 1U << sbi.blkszbits, sbi.inos | 0ULL,
-		erofs_total_metablocks(),
-		sbi.saved_by_deduplication | 0ULL);
+		"Filesystem %s metadata blocks: %u\n"
+		"Filesystem %s deduplicated bytes (of source files): %llu\n",
+		uuid_str, nblocks, 1U << g_sbi.blkszbits, g_sbi.inos | 0ULL,
+		incr, erofs_total_metablocks(g_sbi.bmgr),
+		incr, g_sbi.saved_by_deduplication | 0ULL);
 }
 
 int main(int argc, char **argv)
 {
 	int err = 0;
 	struct erofs_buffer_head *sb_bh;
-	struct erofs_inode *root_inode, *packed_inode;
-	erofs_nid_t root_nid, packed_nid;
-	erofs_blk_t nblocks;
+	struct erofs_inode *root = NULL;
+	erofs_blk_t nblocks = 0;
 	struct timeval t;
 	FILE *packedfile = NULL;
+	FILE *blklst = NULL;
+	u32 crc;
 
 	erofs_init_configure();
 	erofs_mkfs_default_options();
@@ -937,38 +1169,31 @@ int main(int argc, char **argv)
 	erofs_show_progs(argc, argv);
 	if (err) {
 		if (err == -EINVAL)
-			usage();
+			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		return 1;
 	}
 
 	err = parse_source_date_epoch();
 	if (err) {
-		usage();
+		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		return 1;
 	}
 
 	if (cfg.c_unix_timestamp != -1) {
-		sbi.build_time      = cfg.c_unix_timestamp;
-		sbi.build_time_nsec = 0;
+		g_sbi.build_time      = cfg.c_unix_timestamp;
+		g_sbi.build_time_nsec = 0;
 	} else if (!gettimeofday(&t, NULL)) {
-		sbi.build_time      = t.tv_sec;
-		sbi.build_time_nsec = t.tv_usec;
+		g_sbi.build_time      = t.tv_sec;
+		g_sbi.build_time_nsec = t.tv_usec;
 	}
 
-	err = dev_open(&sbi, cfg.c_img_path);
+	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDWR |
+				(incremental_mode ? 0 : O_TRUNC));
 	if (err) {
-		usage();
+		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
 		return 1;
 	}
 
-	if (tar_mode && !erofstar.index_mode) {
-		err = erofs_diskbuf_init(1);
-		if (err) {
-			erofs_err("failed to initialize diskbuf: %s",
-				   strerror(-err));
-			goto exit;
-		}
-	}
 #ifdef WITH_ANDROID
 	if (cfg.fs_config_file &&
 	    load_canned_fs_config(cfg.fs_config_file) < 0) {
@@ -976,16 +1201,18 @@ int main(int argc, char **argv)
 		return 1;
 	}
 
-	if (cfg.block_list_file &&
-	    erofs_blocklist_open(cfg.block_list_file, false)) {
-		erofs_err("failed to open %s", cfg.block_list_file);
-		return 1;
+	if (cfg.block_list_file) {
+		blklst = fopen(cfg.block_list_file, "w");
+		if (!blklst || erofs_blocklist_open(blklst, false)) {
+			erofs_err("failed to open %s", cfg.block_list_file);
+			return 1;
+		}
 	}
 #endif
 	erofs_show_config();
 	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
-		if (!cfg.c_pclusterblks_packed)
-			cfg.c_pclusterblks_packed = cfg.c_pclusterblks_def;
+		if (!cfg.c_mkfs_pclustersize_packed)
+			cfg.c_mkfs_pclustersize_packed = cfg.c_mkfs_pclustersize_def;
 
 		packedfile = erofs_packedfile_init();
 		if (IS_ERR(packedfile)) {
@@ -1006,15 +1233,24 @@ int main(int argc, char **argv)
 	if (cfg.c_random_pclusterblks)
 		srand(time(NULL));
 #endif
-	if (tar_mode && erofstar.index_mode) {
+	if (tar_mode) {
+		if (dataimport_mode == EROFS_MKFS_DATA_IMPORT_RVSP)
+			erofstar.rvsp_mode = true;
+		erofstar.dev = rebuild_src_count + 1;
+
 		if (erofstar.mapfile) {
-			err = erofs_blocklist_open(erofstar.mapfile, true);
-			if (err) {
+			blklst = fopen(erofstar.mapfile, "w");
+			if (!blklst || erofs_blocklist_open(blklst, true)) {
+				err = -errno;
 				erofs_err("failed to open %s", erofstar.mapfile);
 				goto exit;
 			}
-		} else {
-			sbi.blkszbits = 9;
+		} else if (erofstar.index_mode) {
+			/*
+			 * If mapfile is unspecified for tarfs index mode,
+			 * 512-byte block size is enforced here.
+			 */
+			g_sbi.blkszbits = 9;
 		}
 	}
 
@@ -1031,38 +1267,69 @@ int main(int argc, char **argv)
 			erofs_err("failed to read superblock of %s", src->devname);
 			goto exit;
 		}
-		sbi.blkszbits = src->blkszbits;
+		g_sbi.blkszbits = src->blkszbits;
 	}
 
-	sb_bh = erofs_buffer_init();
-	if (IS_ERR(sb_bh)) {
-		err = PTR_ERR(sb_bh);
-		erofs_err("failed to initialize buffers: %s",
-			  erofs_strerror(err));
-		goto exit;
-	}
-	err = erofs_bh_balloon(sb_bh, EROFS_SUPER_END);
-	if (err < 0) {
-		erofs_err("failed to balloon erofs_super_block: %s",
-			  erofs_strerror(err));
-		goto exit;
+	if (!incremental_mode) {
+		g_sbi.bmgr = erofs_buffer_init(&g_sbi, 0);
+		if (!g_sbi.bmgr) {
+			err = -ENOMEM;
+			goto exit;
+		}
+		sb_bh = erofs_reserve_sb(g_sbi.bmgr);
+		if (IS_ERR(sb_bh)) {
+			err = PTR_ERR(sb_bh);
+			goto exit;
+		}
+	} else {
+		union {
+			struct stat st;
+			erofs_blk_t startblk;
+		} u;
+
+		erofs_warn("EXPERIMENTAL incremental build in use. Use at your own risk!");
+		err = erofs_read_superblock(&g_sbi);
+		if (err) {
+			erofs_err("failed to read superblock of %s", g_sbi.devname);
+			goto exit;
+		}
+
+		err = erofs_io_fstat(&g_sbi.bdev, &u.st);
+		if (!err && S_ISREG(u.st.st_mode))
+			u.startblk = DIV_ROUND_UP(u.st.st_size, erofs_blksiz(&g_sbi));
+		else
+			u.startblk = g_sbi.primarydevice_blocks;
+		g_sbi.bmgr = erofs_buffer_init(&g_sbi, u.startblk);
+		if (!g_sbi.bmgr) {
+			err = -ENOMEM;
+			goto exit;
+		}
+		sb_bh = NULL;
 	}
 
-	/* make sure that the super block should be the very first blocks */
-	(void)erofs_mapbh(sb_bh->block);
-	if (erofs_btell(sb_bh, false) != 0) {
-		erofs_err("failed to reserve erofs_super_block");
-		goto exit;
+	/* Use the user-defined UUID or generate one for clean builds */
+	if (valid_fixeduuid)
+		memcpy(g_sbi.uuid, fixeduuid, sizeof(g_sbi.uuid));
+	else if (!incremental_mode)
+		erofs_uuid_generate(g_sbi.uuid);
+
+	if (tar_mode && !erofstar.index_mode) {
+		err = erofs_diskbuf_init(1);
+		if (err) {
+			erofs_err("failed to initialize diskbuf: %s",
+				   strerror(-err));
+			goto exit;
+		}
 	}
 
-	err = erofs_load_compress_hints(&sbi);
+	err = erofs_load_compress_hints(&g_sbi);
 	if (err) {
 		erofs_err("failed to load compress hints %s",
 			  cfg.c_compress_hints_file);
 		goto exit;
 	}
 
-	err = z_erofs_compress_init(&sbi, sb_bh);
+	err = z_erofs_compress_init(&g_sbi, sb_bh);
 	if (err) {
 		erofs_err("failed to initialize compressor: %s",
 			  erofs_strerror(err));
@@ -1070,11 +1337,11 @@ int main(int argc, char **argv)
 	}
 
 	if (cfg.c_dedupe) {
-		if (!cfg.c_compr_alg[0]) {
+		if (!cfg.c_compr_opts[0].alg) {
 			erofs_err("Compression is not enabled.  Turn on chunk-based data deduplication instead.");
-			cfg.c_chunkbits = sbi.blkszbits;
+			cfg.c_chunkbits = g_sbi.blkszbits;
 		} else {
-			err = z_erofs_dedupe_init(erofs_blksiz(&sbi));
+			err = z_erofs_dedupe_init(erofs_blksiz(&g_sbi));
 			if (err) {
 				erofs_err("failed to initialize deduplication: %s",
 					  erofs_strerror(err));
@@ -1089,46 +1356,48 @@ int main(int argc, char **argv)
 			return 1;
 	}
 
-	if ((erofstar.index_mode && !erofstar.mapfile) || cfg.c_blobdev_path)
-		err = erofs_mkfs_init_devices(&sbi, 1);
-	if (err) {
-		erofs_err("failed to generate device table: %s",
-			  erofs_strerror(err));
-		goto exit;
+	if (((erofstar.index_mode && !erofstar.headeronly_mode) &&
+	    !erofstar.mapfile) || cfg.c_blobdev_path) {
+		err = erofs_mkfs_init_devices(&g_sbi, 1);
+		if (err) {
+			erofs_err("failed to generate device table: %s",
+				  erofs_strerror(err));
+			goto exit;
+		}
 	}
 
 	erofs_inode_manager_init();
 
 	if (tar_mode) {
-		root_inode = erofs_alloc_root_inode();
-		if (IS_ERR(root_inode)) {
-			err = PTR_ERR(root_inode);
+		root = erofs_rebuild_make_root(&g_sbi);
+		if (IS_ERR(root)) {
+			err = PTR_ERR(root);
 			goto exit;
 		}
 
-		while (!(err = tarerofs_parse_tar(root_inode, &erofstar)));
+		while (!(err = tarerofs_parse_tar(root, &erofstar)));
 
 		if (err < 0)
 			goto exit;
 
-		err = erofs_rebuild_dump_tree(root_inode);
+		err = erofs_rebuild_dump_tree(root, incremental_mode);
 		if (err < 0)
 			goto exit;
 	} else if (rebuild_mode) {
-		root_inode = erofs_alloc_root_inode();
-		if (IS_ERR(root_inode)) {
-			err = PTR_ERR(root_inode);
+		root = erofs_rebuild_make_root(&g_sbi);
+		if (IS_ERR(root)) {
+			err = PTR_ERR(root);
 			goto exit;
 		}
 
-		err = erofs_rebuild_load_trees(root_inode);
+		err = erofs_mkfs_rebuild_load_trees(root);
 		if (err)
 			goto exit;
-		err = erofs_rebuild_dump_tree(root_inode);
+		err = erofs_rebuild_dump_tree(root, incremental_mode);
 		if (err)
 			goto exit;
 	} else {
-		err = erofs_build_shared_xattrs_from_path(&sbi, cfg.c_src_path);
+		err = erofs_build_shared_xattrs_from_path(&g_sbi, cfg.c_src_path);
 		if (err) {
 			erofs_err("failed to build shared xattrs: %s",
 				  erofs_strerror(err));
@@ -1136,63 +1405,65 @@ int main(int argc, char **argv)
 		}
 
 		if (cfg.c_extra_ea_name_prefixes)
-			erofs_xattr_write_name_prefixes(&sbi, packedfile);
+			erofs_xattr_write_name_prefixes(&g_sbi, packedfile);
 
-		root_inode = erofs_mkfs_build_tree_from_path(cfg.c_src_path);
-		if (IS_ERR(root_inode)) {
-			err = PTR_ERR(root_inode);
+		root = erofs_mkfs_build_tree_from_path(&g_sbi, cfg.c_src_path);
+		if (IS_ERR(root)) {
+			err = PTR_ERR(root);
 			goto exit;
 		}
 	}
-	root_nid = erofs_lookupnid(root_inode);
-	erofs_iput(root_inode);
-
-	if (erofstar.index_mode || cfg.c_chunkbits || sbi.extra_devices) {
-		if (erofstar.index_mode && !erofstar.mapfile)
-			sbi.devs[0].blocks =
-				BLK_ROUND_UP(&sbi, erofstar.offset);
-		err = erofs_mkfs_dump_blobs(&sbi);
+
+	if (erofstar.index_mode && g_sbi.extra_devices && !erofstar.mapfile)
+		g_sbi.devs[0].blocks = BLK_ROUND_UP(&g_sbi, erofstar.offset);
+
+	if (erofs_sb_has_fragments(&g_sbi)) {
+		erofs_update_progressinfo("Handling packed data ...");
+		err = erofs_flush_packed_inode(&g_sbi);
 		if (err)
 			goto exit;
 	}
 
-	packed_nid = 0;
-	if ((cfg.c_fragments || cfg.c_extra_ea_name_prefixes) &&
-	    erofs_sb_has_fragments(&sbi)) {
-		erofs_update_progressinfo("Handling packed_file ...");
-		packed_inode = erofs_mkfs_build_packedfile();
-		if (IS_ERR(packed_inode)) {
-			err = PTR_ERR(packed_inode);
+	if (erofstar.index_mode || cfg.c_chunkbits || g_sbi.extra_devices) {
+		err = erofs_mkfs_dump_blobs(&g_sbi);
+		if (err)
 			goto exit;
-		}
-		packed_nid = erofs_lookupnid(packed_inode);
-		erofs_iput(packed_inode);
 	}
 
 	/* flush all buffers except for the superblock */
-	if (!erofs_bflush(NULL)) {
-		err = -EIO;
+	err = erofs_bflush(g_sbi.bmgr, NULL);
+	if (err)
 		goto exit;
-	}
 
-	err = erofs_mkfs_update_super_block(sb_bh, root_nid, &nblocks,
-					    packed_nid);
+	erofs_fixup_root_inode(root);
+	erofs_iput(root);
+	root = NULL;
+
+	err = erofs_writesb(&g_sbi, sb_bh, &nblocks);
 	if (err)
 		goto exit;
 
 	/* flush all remaining buffers */
-	if (!erofs_bflush(NULL))
-		err = -EIO;
-	else
-		err = dev_resize(&sbi, nblocks);
+	err = erofs_bflush(g_sbi.bmgr, NULL);
+	if (err)
+		goto exit;
+
+	err = erofs_dev_resize(&g_sbi, nblocks);
 
-	if (!err && erofs_sb_has_sb_chksum(&sbi))
-		err = erofs_mkfs_superblock_csum_set();
+	if (!err && erofs_sb_has_sb_chksum(&g_sbi)) {
+		err = erofs_enable_sb_chksum(&g_sbi, &crc);
+		if (!err)
+			erofs_info("superblock checksum 0x%08x written", crc);
+	}
 exit:
+	if (root)
+		erofs_iput(root);
 	z_erofs_compress_exit();
 	z_erofs_dedupe_exit();
-	erofs_blocklist_close();
-	dev_close(&sbi);
+	blklst = erofs_blocklist_close();
+	if (blklst)
+		fclose(blklst);
+	erofs_dev_close(&g_sbi);
 	erofs_cleanup_compress_hints();
 	erofs_cleanup_exclude_rules();
 	if (cfg.c_chunkbits)
@@ -1204,8 +1475,11 @@ exit:
 	erofs_rebuild_cleanup();
 	erofs_diskbuf_exit();
 	erofs_exit_configure();
-	if (tar_mode)
+	if (tar_mode) {
 		erofs_iostream_close(&erofstar.ios);
+		if (erofstar.ios.dumpfd >= 0)
+			close(erofstar.ios.dumpfd);
+	}
 
 	if (err) {
 		erofs_err("\tCould not format the device : %s\n",
@@ -1214,5 +1488,6 @@ exit:
 	}
 	erofs_update_progressinfo("Build completed.\n");
 	erofs_mkfs_showsummaries(nblocks);
+	erofs_put_super(&g_sbi);
 	return 0;
 }
```

