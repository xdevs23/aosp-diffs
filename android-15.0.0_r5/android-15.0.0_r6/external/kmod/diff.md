```diff
diff --git a/.gitignore b/.gitignore
index cad86ea..e71025a 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,6 +1,7 @@
 *.o
 *.gcda
 *.gcno
+*.pc
 /*.tar.xz
 /*.md5sum
 /*.mbx
@@ -13,8 +14,6 @@
 /aclocal.m4
 /autom4te.cache/
 /build-aux/
-/config.h
-/config.h.in
 /config.log
 /config.status
 /configure
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 2adb3c6..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,33 +0,0 @@
-language: c
-dist: focal
-
-matrix:
-  include:
-    - compiler: gcc
-      env: CC=gcc
-    - compiler: clang
-      env: CC=clang
-
-before_install:
-  - sudo apt-get update -qq
-  - sudo apt-get install -qq libzstd-dev zstd
-  - sudo apt-get install -qq liblzma-dev
-  - sudo apt-get install -qq zlib1g-dev
-  - sudo apt-get install -qq xsltproc docbook-xsl
-  - sudo apt-get install -qq cython
-  - sudo apt-get install -qq linux-headers-generic
-
-before_script:
-  - unset PYTHON_CFLAGS # hack to broken travis setup
-  - export KDIR="$(find  /lib/modules/* -maxdepth  1 -name build | sort -n --reverse | head -1)"
-
-script:
-  - ./autogen.sh c --without-openssl && make -j
-  - make -j check
-
-notifications:
-  irc:
-    channels:
-      - "irc.freenode.org#kmod"
-    template:
-      - "%{commit}: %{author} - %{message}"
diff --git a/Android.bp b/Android.bp
index 4854a76..7e85bcc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,33 +40,35 @@ license {
 
 cc_defaults {
     name: "libkmod_cflags_common",
-    local_include_dirs: ["port-gnu"],
     cflags: [
-        "-include config.h",
-        "-ffunction-sections",
-        "-fdata-sections",
+        "-include android/port.h",
         "-Wall",
         "-Werror",
         "-Wno-format",
         "-Wno-unused-parameter",
         "-Wno-unused-variable",
         "-Dsecure_getenv=getenv",
+
         "-DHAVE_CONFIG_H",
-        "-DANOTHER_BRICK_IN_THE",
+        "-include config.h",
+
+        "-DDISTCONFDIR=\"/lib\"",
+        "-DMODULE_DIRECTORY=\"/lib/modules\"",
         "-DSYSCONFDIR=\"/tmp\"",
         "-UNDEBUG",
     ],
     target: {
         glibc: {
-            cflags: ["-DHAVE_DECL_STRNDUPA"]
-        }
-    }
+            cflags: ["-DHAVE_DECL_STRNDUPA"],
+        },
+    },
 }
 
 cc_library_static {
     defaults: ["libkmod_cflags_common"],
     export_include_dirs: ["libkmod"],
     host_supported: true,
+    vendor_available: true,
     name: "libkmod",
     srcs: [
         "libkmod/libkmod.c",
@@ -84,7 +86,11 @@ cc_library_static {
         "shared/hash.c",
         "shared/strbuf.c",
     ],
-    visibility: ["//external/igt-gpu-tools"],
+    visibility: [
+        "//external/igt-gpu-tools",
+        "//external/pciutils",
+        "//vendor:__subpackages__",
+    ],
 }
 
 cc_binary_host {
@@ -96,13 +102,11 @@ cc_binary_host {
         "tools/kmod.c",
         "tools/modinfo.c",
         "tools/rmmod.c",
-        "tools/insert.c",
         "tools/log.c",
         "tools/modprobe.c",
         "tools/static-nodes.c",
         "tools/insmod.c",
         "tools/lsmod.c",
-        "tools/remove.c",
     ],
     static_libs: ["libkmod"],
 }
diff --git a/METADATA b/METADATA
index f19e9ca..2aefca2 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,19 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/kmod
+# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+
 name: "kmod"
 description: "Linux kernel module handling."
 third_party {
-  url {
-    type: GIT
-    value: "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git"
-  }
-  version: "v30"
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2022
-    month: 10
-    day: 3
+    year: 2024
+    month: 7
+    day: 9
+  }
+  identifier {
+    type: "Git"
+    value: "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git"
+    version: "v32"
   }
 }
diff --git a/Makefile.am b/Makefile.am
index 0e48770..d37b56d 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -19,31 +19,13 @@ AM_CPPFLAGS = \
 	-include $(top_builddir)/config.h \
 	-I$(top_srcdir) \
 	-DSYSCONFDIR=\""$(sysconfdir)"\" \
+	-DDISTCONFDIR=\""$(distconfdir)"\" \
+	-DMODULE_DIRECTORY=\""$(module_directory)"\" \
 	${zlib_CFLAGS}
 
 AM_CFLAGS = $(OUR_CFLAGS)
 AM_LDFLAGS = $(OUR_LDFLAGS)
 
-SED_PROCESS = \
-	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
-	-e 's,@VERSION\@,$(VERSION),g' \
-	-e 's,@prefix\@,$(prefix),g' \
-	-e 's,@exec_prefix\@,$(exec_prefix),g' \
-	-e 's,@libdir\@,$(libdir),g' \
-	-e 's,@includedir\@,$(includedir),g' \
-	-e 's,@libzstd_CFLAGS\@,${libzstd_CFLAGS},g' \
-	-e 's,@libzstd_LIBS\@,${libzstd_LIBS},g' \
-	-e 's,@liblzma_CFLAGS\@,${liblzma_CFLAGS},g' \
-	-e 's,@liblzma_LIBS\@,${liblzma_LIBS},g' \
-	-e 's,@zlib_CFLAGS\@,${zlib_CFLAGS},g' \
-	-e 's,@zlib_LIBS\@,${zlib_LIBS},g' \
-	-e 's,@libcrypto_CFLAGS\@,${libcrypto_CFLAGS},g' \
-	-e 's,@libcrypto_LIBS\@,${libcrypto_LIBS},g' \
-	< $< > $@ || rm $@
-
-%.pc: %.pc.in Makefile
-	$(SED_PROCESS)
-
 # Rules for libtool versioning (from https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html)
 # 1. Start with version information of ‘0:0:0’ for each libtool library.
 # 2. Update the version information only immediately before a public release of
@@ -58,7 +40,7 @@ SED_PROCESS = \
 # 6. If any interfaces have been removed or changed since the last public
 #    release, then set age to 0.
 LIBKMOD_CURRENT=6
-LIBKMOD_REVISION=0
+LIBKMOD_REVISION=2
 LIBKMOD_AGE=4
 
 noinst_LTLIBRARIES = shared/libshared.la
@@ -115,9 +97,7 @@ libkmod_libkmod_internal_la_DEPENDENCIES  = $(libkmod_libkmod_la_DEPENDENCIES)
 libkmod_libkmod_internal_la_LIBADD = $(libkmod_libkmod_la_LIBADD)
 
 pkgconfigdir = $(libdir)/pkgconfig
-pkgconfig_DATA = libkmod/libkmod.pc
-EXTRA_DIST += libkmod/libkmod.pc.in
-CLEANFILES += libkmod/libkmod.pc
+pkgconfig_DATA = libkmod/libkmod.pc tools/kmod.pc
 
 bashcompletiondir=@bashcompletiondir@
 dist_bashcompletion_DATA = \
@@ -131,9 +111,19 @@ install-exec-hook:
 		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libkmod.so && \
 		mv $(DESTDIR)$(libdir)/libkmod.so.* $(DESTDIR)$(rootlibdir); \
 	fi
+if BUILD_TOOLS
+	for tool in insmod lsmod rmmod depmod modprobe modinfo; do \
+		$(LN_S) kmod $(DESTDIR)$(bindir)/$$tool; \
+	done
+endif
 
 uninstall-hook:
 	rm -f $(DESTDIR)$(rootlibdir)/libkmod.so*
+if BUILD_TOOLS
+	for tool in insmod lsmod rmmod depmod modprobe modinfo; do \
+		rm -f $(DESTDIR)$(bindir)/$$tool; \
+	done
+endif
 
 if BUILD_TOOLS
 bin_PROGRAMS = tools/kmod
@@ -149,12 +139,6 @@ tools_kmod_SOURCES = \
 	tools/depmod.c tools/log.h tools/log.c \
 	tools/static-nodes.c
 
-if BUILD_EXPERIMENTAL
-tools_kmod_SOURCES += \
-	tools/insert.c \
-	tools/remove.c
-endif
-
 tools_kmod_LDADD = \
 	shared/libshared.la \
 	libkmod/libkmod-internal.la
@@ -164,97 +148,21 @@ ${noinst_SCRIPTS}: tools/kmod
 		$(LN_S) $(notdir $<) $@)
 endif
 
-# ------------------------------------------------------------------------------
-# PYTHON BINDINGS
-# ------------------------------------------------------------------------------
-
-CYTHON_FLAGS_VERBOSE_ =
-CYTHON_FLAGS_VERBOSE_0 =
-CYTHON_FLAGS_VERBOSE_1 = -v
-CYTHON_FLAGS = $(CYTHON_FLAGS_VERBOSE_$(V))
-AM_V_CYTHON = $(am__v_CYTHON_$(V))
-am__v_CYTHON_ = $(am__v_CYTHON_$(AM_DEFAULT_VERBOSITY))
-am__v_CYTHON_0 = @echo "  CYTHON " $@;
-
-.pyx.c:
-	$(AM_V_CYTHON)$(CYTHON) -o $@ $<
-
-%.py: %.py.in Makefile
-	$(SED_PROCESS)
-
-# Remove some warnings for generated code
-PYTHON_NOWARN = -Wno-redundant-decls -Wno-shadow -Wno-strict-aliasing
-
-CPYTHON_MODULE_CFLAGS = \
-	$(AM_CFLAGS) -DCPYTHON_COMPILING_IN_PYPY=0 \
-	$(PYTHON_NOWARN) $(PYTHON_CFLAGS) \
-	-fvisibility=default
-# Filter -Wl,--no-undefined to fix build with python 3.8
-comma = ,
-CPYTHON_MODULE_LDFLAGS = $(subst -Wl$(comma)--no-undefined,,$(AM_LDFLAGS))
-CPYTHON_MODULE_LDFLAGS += -module -avoid-version -shared
-
-if BUILD_PYTHON
-pkgpyexec_LTLIBRARIES = \
-	libkmod/python/kmod/kmod.la \
-	libkmod/python/kmod/list.la \
-	libkmod/python/kmod/module.la \
-	libkmod/python/kmod/_util.la
-
-libkmod_python_kmod_kmod_la_SOURCES = libkmod/python/kmod/kmod.c
-libkmod_python_kmod_kmod_la_CFLAGS = $(CPYTHON_MODULE_CFLAGS)
-libkmod_python_kmod_kmod_la_LDFLAGS = $(CPYTHON_MODULE_LDFLAGS)
-libkmod_python_kmod_kmod_la_LIBADD = $(PYTHON_LIBS) libkmod/libkmod.la
-
-libkmod_python_kmod_list_la_SOURCES = libkmod/python/kmod/list.c
-libkmod_python_kmod_list_la_CFLAGS = $(CPYTHON_MODULE_CFLAGS)
-libkmod_python_kmod_list_la_LDFLAGS = $(CPYTHON_MODULE_LDFLAGS)
-libkmod_python_kmod_list_la_LIBADD = $(PYTHON_LIBS) libkmod/libkmod.la
-
-libkmod_python_kmod_module_la_SOURCES = libkmod/python/kmod/module.c
-libkmod_python_kmod_module_la_CFLAGS = $(CPYTHON_MODULE_CFLAGS)
-libkmod_python_kmod_module_la_LDFLAGS = $(CPYTHON_MODULE_LDFLAGS)
-libkmod_python_kmod_module_la_LIBADD = $(PYTHON_LIBS) libkmod/libkmod.la
-
-libkmod_python_kmod__util_la_SOURCES = libkmod/python/kmod/_util.c
-libkmod_python_kmod__util_la_CFLAGS = $(CPYTHON_MODULE_CFLAGS)
-libkmod_python_kmod__util_la_LDFLAGS = $(CPYTHON_MODULE_LDFLAGS)
-libkmod_python_kmod__util_la_LIBADD = $(PYTHON_LIBS) libkmod/libkmod.la
-
-BUILT_FILES += \
-	$(libkmod_python_kmod_kmod_la_SOURCES) \
-	$(libkmod_python_kmod_list_la_SOURCES) \
-	$(libkmod_python_kmod_module_la_SOURCES) \
-	$(libkmod_python_kmod__util_la_SOURCES)
-
-dist_pkgpyexec_PYTHON = \
-	libkmod/python/kmod/error.py \
-	libkmod/python/kmod/__init__.py \
-	libkmod/python/kmod/version.py
-
-BUILT_FILES += libkmod/python/kmod/version.py
-
-endif
 # ------------------------------------------------------------------------------
 # TESTSUITE
 # ------------------------------------------------------------------------------
 
-EXTRA_DIST += testsuite/populate-modules.sh
+EXTRA_DIST += testsuite/setup-rootfs.sh
 
 MODULE_PLAYGROUND = testsuite/module-playground
 ROOTFS = testsuite/rootfs
 ROOTFS_PRISTINE = $(top_srcdir)/testsuite/rootfs-pristine
-CREATE_ROOTFS = $(AM_V_GEN) ( $(RM) -rf $(ROOTFS) && mkdir -p $(dir $(ROOTFS)) && \
-				cp -r $(ROOTFS_PRISTINE) $(ROOTFS) && \
-				find $(ROOTFS) -type d -exec chmod +w {} \; && \
-				find $(ROOTFS) -type f -name .gitignore -exec rm -f {} \; && \
-				$(top_srcdir)/testsuite/populate-modules.sh \
-					$(MODULE_PLAYGROUND) $(ROOTFS) $(top_builddir)/config.h ) && \
-				touch testsuite/stamp-rootfs
+CREATE_ROOTFS = $(AM_V_GEN) MODULE_DIRECTORY=$(module_directory) $(top_srcdir)/testsuite/setup-rootfs.sh $(ROOTFS_PRISTINE) $(ROOTFS) $(MODULE_PLAYGROUND) $(top_builddir)/config.h $(sysconfdir)
 
 build-module-playground:
 	$(AM_V_GEN)if test "$(top_srcdir)" != "$(top_builddir)"; then \
 		$(RM) -rf testsuite/module-playground && \
+		mkdir -p testsuite/ && \
 		cp -r $(top_srcdir)/$(MODULE_PLAYGROUND) $(top_builddir)/$(MODULE_PLAYGROUND) && \
 		find $(top_builddir)/$(MODULE_PLAYGROUND) -type d -exec chmod +w {} \; ; \
 		fi
@@ -335,10 +243,6 @@ TESTSUITE_LDADD = \
 	testsuite/libtestsuite.la libkmod/libkmod-internal.la \
 	shared/libshared.la
 
-if KMOD_SYSCONFDIR_NOT_ETC
-TESTSUITE_CPPFLAGS += -DKMOD_SYSCONFDIR_NOT_ETC
-endif
-
 check_LTLIBRARIES += testsuite/libtestsuite.la
 testsuite_libtestsuite_la_SOURCES = \
 	testsuite/testsuite.c testsuite/testsuite.h
@@ -360,11 +264,6 @@ TESTSUITE = \
 	testsuite/test-dependencies testsuite/test-depmod \
 	testsuite/test-list
 
-if BUILD_EXPERIMENTAL
-TESTSUITE += \
-	testsuite/test-tools
-endif
-
 check_PROGRAMS = $(TESTSUITE)
 TESTS = $(TESTSUITE)
 
@@ -407,11 +306,6 @@ testsuite_test_depmod_CPPFLAGS = $(TESTSUITE_CPPFLAGS)
 testsuite_test_list_LDADD = $(TESTSUITE_LDADD)
 testsuite_test_list_CPPFLAGS = $(TESTSUITE_CPPFLAGS)
 
-if BUILD_EXPERIMENTAL
-testsuite_test_tools_LDADD = $(TESTSUITE_LDADD)
-testsuite_test_tools_CPPFLAGS = $(TESTSUITE_CPPFLAGS)
-endif
-
 testsuite-distclean:
 	$(RM) -r $(ROOTFS)
 	$(RM) testsuite/stamp-rootfs
@@ -423,7 +317,7 @@ testsuite-distclean:
 DISTCLEAN_LOCAL_HOOKS += testsuite-distclean
 EXTRA_DIST += testsuite/rootfs-pristine
 
-DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-python --sysconfdir=/etc \
+DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --sysconfdir=/etc \
 	--with-zlib --with-zstd --with-openssl \
 	--with-bashcompletiondir=$$dc_install_base/$(bashcompletiondir)
 
@@ -477,7 +371,7 @@ endif
 
 kmod-coverity-%.tar.xz:
 	rm -rf $< cov-int
-	./autogen.sh c --disable-python --disable-manpages
+	./autogen.sh c --disable-manpages
 	make clean
 	cov-build --dir cov-int make -j 4
 	tar caf $@ cov-int
@@ -516,13 +410,3 @@ tar: kmod-$(VERSION).tar.xz kmod-$(VERSION).tar.sign
 
 tar-sync: kmod-$(VERSION).tar.xz kmod-$(VERSION).tar.sign
 	kup put kmod-$(VERSION).tar.xz  kmod-$(VERSION).tar.sign /pub/linux/utils/kernel/kmod/
-
-# ------------------------------------------------------------------------------
-# mkosi
-# ------------------------------------------------------------------------------
-
-DISTRO ?= "arch"
-
-mkosi:
-	-$(MKDIR_P) $(top_srcdir)/testsuite/mkosi/mkosi.cache
-	$(MKOSI) -C $(top_srcdir)/testsuite/mkosi --build-sources ../../ --default mkosi.${DISTRO} -fi
diff --git a/NEWS b/NEWS
index fe95103..6b628f9 100644
--- a/NEWS
+++ b/NEWS
@@ -1,3 +1,105 @@
+kmod 32
+=======
+
+- Improvements
+
+	- Use any hash algo known by kernel/openssl instead of keep needing
+	  to update the mapping
+
+	- Teach kmod to load modprobe.d/depmod.d configuration from ${prefix}/lib
+	  and allow it to be overriden during build with --with-distconfdir=DIR
+
+	- Make kernel modules directory configurable. This allows distro to
+	  make kmod use only files from /usr regardless of having a compat
+	  symlink in place.
+
+	- Install kmod.pc containing the features selected at build time.
+
+	- Install all tools and symlinks by default. Previously kmod relied on
+	  distro packaging to set up the symlinks in place like modprobe,
+	  depmod, lsmod, etc. Now those symlinks are created by kmod itself
+	  and they are always placed in $bindir.
+
+- Bug Fixes
+
+	- Fix warnings due to -Walloc-size
+
+- Others
+
+	- Drop python bindings. Those were not update in ages and not compatible
+	  with latest python releases.
+
+	- Cleanup test infra, dropping what was not used anymore
+
+	- Drop experimental tools `kmod insert` / `kmod remove`. Building those
+	  was protected by a configure option never set by distros. They also
+	  didn't gain enough traction to replace the older interfaces via
+	  modprobe/insmod/rmmod.
+
+kmod 31
+=======
+
+- Improvements
+
+	- Allow passing a path to modprobe so the module is loaded from
+	  anywhere from the filesystem, but still handling the module
+	  dependencies recorded in the indexes. This is mostly intended for kernel
+	  developers to speedup testing their kernel modules without having to load the
+	  dependencies manually or override the module in /usr/lib/modules/.
+	  Now it's possible to do:
+
+		# modprobe ./drivers/gpu/drm/i915/i915.ko
+
+	  As long as the dependencies didn't change, this should do the right thing
+
+	- Use in-kernel decompression if available. This will check the runtime support
+	  in the kernel for decompressing modules and use it through finit_module().
+	  Previously kmod would fallback to the older init_module() when using
+	  compressed modules since there wasn't a way to instruct the kernel to
+	  uncompress it on load or check if the kernel supported it or not.
+	  This requires a recent kernel (>= 6.4) to have that support and
+	  in-kernel decompression properly working in the kernel.
+
+	- Make modprobe fallback to syslog when stderr is not available, as was
+	  documented in the man page, but not implemented
+
+	- Better explaing `modprobe -r` and how it differentiates from rmmod
+
+	- depmod learned a `-o <dir>` option to allow using a separate output
+	  directory. With this, it's possible to split the output files from
+	  the ones used as input from the kernel build system
+
+	- Add compat with glibc >= 2.32.9000 that dropped __xstat
+
+	- Improve testsuite to stop skipping tests when sysconfdir is something
+	  other than /etc
+
+	- Build system improvements and updates
+
+	- Change a few return codes from -ENOENT to -ENODATA to avoid confusing output
+	  in depmod when the module itself lacks a particular ELF section due to e.g.
+	  CONFIG_MODVERSIONS=n in the kernel.
+
+
+- Bug Fixes
+
+	- Fix testsuite using uninitialized memory when testing module removal
+	  with --wait
+
+	- Fix testsuite not correctly overriding the stat syscall on 32-bit
+	  platforms. For most architectures this was harmless, but for MIPS it
+	  was causing some tests to fail.
+
+	- Fix handling unknown signature algorithm
+
+	- Fix linking with a static liblzma, libzstd or zlib
+
+	- Fix memory leak when removing module holders
+
+	- Fix out-of-bounds access when using very long paths as argument to rmmod
+
+	- Fix warnings reported by UBSan
+
 kmod 30
 =======
 
diff --git a/README.md b/README.md
index 590c8a8..9b22bd7 100644
--- a/README.md
+++ b/README.md
@@ -67,8 +67,7 @@ Hacking
 =======
 
 Run 'autogen.sh' script before configure. If you want to accept the recommended
-flags, you just need to run 'autogen.sh c'. Note that the recommended
-flags require cython be installed to compile successfully.
+flags, you just need to run 'autogen.sh c'.
 
 Make sure to read the CODING-STYLE file and the other READMEs: libkmod/README
 and testsuite/README.
diff --git a/android/port.h b/android/port.h
new file mode 100644
index 0000000..ecc23d8
--- /dev/null
+++ b/android/port.h
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#define _GNU_SOURCE
+
+#include <endian.h>
+
+#if defined(__APPLE__)
+
+#include <endian-darwin.h>
+#define HAVE_DECL_STRNDUPA
+#define strndupa(_s,_l)        strdup(_s)
+char* basename(const char*);
+#define init_module     darwin_init_module
+#define delete_module   darwin_delete_module
+#define program_invocation_short_name "depmod"
+
+#endif
+
+#if defined(__ANDROID__) || defined(__APPLE__)
+#include <stdlib.h>
+#include <unistd.h>
+static inline char *get_current_dir_name(void) {
+    return getcwd(malloc(PATH_MAX), PATH_MAX);
+}
+#endif
+
+#if defined(ANDROID_HOST_MUSL)
+
+// musl string.h doesn't have basename. libgen.h's basename is
+// different from GNU basename. Define our own basename to avoid confusion.
+
+extern char* strrchr(const char*, int);
+static inline char* basename(const char* path) {
+  const char* last_slash = strrchr(path, '/');
+  return (char*)((last_slash != 0) ? last_slash + 1 : path);
+}
+
+#endif // defined(ANDROID_HOST_MUSL)
diff --git a/autogen.sh b/autogen.sh
index e4997c4..a7a6022 100755
--- a/autogen.sh
+++ b/autogen.sh
@@ -25,7 +25,6 @@ fi
 
 if [ ! -L /bin ]; then
     args="$args \
-        --with-rootprefix= \
         --with-rootlibdir=$(libdir /lib) \
         "
 fi
@@ -34,7 +33,6 @@ cd $oldpwd
 
 hackargs="\
 --enable-debug \
---enable-python \
 --with-zstd \
 --with-xz \
 --with-zlib \
diff --git a/port-gnu/config.h b/config.h
similarity index 55%
rename from port-gnu/config.h
rename to config.h
index 29c216e..b68596f 100644
--- a/port-gnu/config.h
+++ b/config.h
@@ -4,9 +4,6 @@
 /* Debug messages. */
 /* #undef ENABLE_DEBUG */
 
-/* Experimental features. */
-/* #undef ENABLE_EXPERIMENTAL */
-
 /* System logging. */
 #define ENABLE_LOGGING 1
 
@@ -19,13 +16,16 @@
 /* Enable zlib for modules. */
 /* #undef ENABLE_ZLIB */
 
+/* Enable Zstandard for modules. */
+/* #undef ENABLE_ZSTD */
+
 /* Define to 1 if you have the declaration of `be32toh', and to 0 if you
    don't. */
 #define HAVE_DECL_BE32TOH 1
 
 /* Define to 1 if you have the declaration of `strndupa', and to 0 if you
    don't. */
-/* #define HAVE_DECL_STRNDUPA */
+/* #undef HAVE_DECL_STRNDUPA */
 
 /* Define to 1 if you have the <dlfcn.h> header file. */
 #define HAVE_DLFCN_H 1
@@ -39,8 +39,8 @@
 /* Define to 1 if you have the <linux/module.h> header file. */
 /* #undef HAVE_LINUX_MODULE_H */
 
-/* Define to 1 if you have the <memory.h> header file. */
-#define HAVE_MEMORY_H 1
+/* Define to 1 if you have the <minix/config.h> header file. */
+/* #undef HAVE_MINIX_CONFIG_H */
 
 /* Define if _Noreturn is available */
 #define HAVE_NORETURN 1
@@ -54,6 +54,9 @@
 /* Define to 1 if you have the <stdint.h> header file. */
 #define HAVE_STDINT_H 1
 
+/* Define to 1 if you have the <stdio.h> header file. */
+#define HAVE_STDIO_H 1
+
 /* Define to 1 if you have the <stdlib.h> header file. */
 #define HAVE_STDLIB_H 1
 
@@ -64,7 +67,7 @@
 #define HAVE_STRING_H 1
 
 /* Define to 1 if `st_mtim' is a member of `struct stat'. */
-/*#define HAVE_STRUCT_STAT_ST_MTIM 1*/
+#define HAVE_STRUCT_STAT_ST_MTIM 1
 
 /* Define to 1 if you have the <sys/stat.h> header file. */
 #define HAVE_SYS_STAT_H 1
@@ -75,6 +78,9 @@
 /* Define to 1 if you have the <unistd.h> header file. */
 #define HAVE_UNISTD_H 1
 
+/* Define to 1 if you have the <wchar.h> header file. */
+#define HAVE_WCHAR_H 1
+
 /* Define to 1 if compiler has __builtin_clz() builtin function */
 #define HAVE___BUILTIN_CLZ 1
 
@@ -83,10 +89,10 @@
 #define HAVE___BUILTIN_TYPES_COMPATIBLE_P 1
 
 /* Define to 1 if compiler has __builtin_uaddll_overflow() builtin function */
-#define HAVE___BUILTIN_UADDLL_OVERFLOW 0
+#define HAVE___BUILTIN_UADDLL_OVERFLOW 1
 
 /* Define to 1 if compiler has __builtin_uaddl_overflow() builtin function */
-#define HAVE___BUILTIN_UADDL_OVERFLOW 0
+#define HAVE___BUILTIN_UADDL_OVERFLOW 1
 
 /* Define to 1 if you have the `__secure_getenv' function. */
 /* #undef HAVE___SECURE_GETENV */
@@ -95,7 +101,7 @@
 #define HAVE___XSTAT 1
 
 /* Features in this build */
-#define KMOD_FEATURES "-XZ -ZLIB -OPENSSL -EXPERIMENTAL"
+#define KMOD_FEATURES "-ZSTD -XZ -ZLIB -LIBCRYPTO"
 
 /* Define to the sub-directory where libtool stores uninstalled libraries. */
 #define LT_OBJDIR ".libs/"
@@ -110,7 +116,7 @@
 #define PACKAGE_NAME "kmod"
 
 /* Define to the full name and version of this package. */
-#define PACKAGE_STRING "kmod 26"
+#define PACKAGE_STRING "kmod 32"
 
 /* Define to the one symbol short name of this package. */
 #define PACKAGE_TARNAME "kmod"
@@ -119,76 +125,106 @@
 #define PACKAGE_URL "http://git.kernel.org/?p=utils/kernel/kmod/kmod.git"
 
 /* Define to the version of this package. */
-#define PACKAGE_VERSION "26"
+#define PACKAGE_VERSION "32"
 
-/* Define to 1 if you have the ANSI C header files. */
+/* Define to 1 if all of the C90 standard headers exist (not just the ones
+   required in a freestanding environment). This macro is provided for
+   backward compatibility; new code need not use it. */
 #define STDC_HEADERS 1
 
 /* Enable extensions on AIX 3, Interix.  */
 #ifndef _ALL_SOURCE
 # define _ALL_SOURCE 1
 #endif
+/* Enable general extensions on macOS.  */
+#ifndef _DARWIN_C_SOURCE
+# define _DARWIN_C_SOURCE 1
+#endif
+/* Enable general extensions on Solaris.  */
+#ifndef __EXTENSIONS__
+# define __EXTENSIONS__ 1
+#endif
 /* Enable GNU extensions on systems that have them.  */
 #ifndef _GNU_SOURCE
 # define _GNU_SOURCE 1
 #endif
-/* Enable threading extensions on Solaris.  */
+/* Enable X/Open compliant socket functions that do not require linking
+   with -lxnet on HP-UX 11.11.  */
+#ifndef _HPUX_ALT_XOPEN_SOCKET_API
+# define _HPUX_ALT_XOPEN_SOCKET_API 1
+#endif
+/* Identify the host operating system as Minix.
+   This macro does not affect the system headers' behavior.
+   A future release of Autoconf may stop defining this macro.  */
+#ifndef _MINIX
+/* # undef _MINIX */
+#endif
+/* Enable general extensions on NetBSD.
+   Enable NetBSD compatibility extensions on Minix.  */
+#ifndef _NETBSD_SOURCE
+# define _NETBSD_SOURCE 1
+#endif
+/* Enable OpenBSD compatibility extensions on NetBSD.
+   Oddly enough, this does nothing on OpenBSD.  */
+#ifndef _OPENBSD_SOURCE
+# define _OPENBSD_SOURCE 1
+#endif
+/* Define to 1 if needed for POSIX-compatible behavior.  */
+#ifndef _POSIX_SOURCE
+/* # undef _POSIX_SOURCE */
+#endif
+/* Define to 2 if needed for POSIX-compatible behavior.  */
+#ifndef _POSIX_1_SOURCE
+/* # undef _POSIX_1_SOURCE */
+#endif
+/* Enable POSIX-compatible threading on Solaris.  */
 #ifndef _POSIX_PTHREAD_SEMANTICS
 # define _POSIX_PTHREAD_SEMANTICS 1
 #endif
+/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
+#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
+# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
+#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
+# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
+#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
+# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
+#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
+# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-3:2015.  */
+#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
+# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
+#endif
+/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
+#ifndef __STDC_WANT_LIB_EXT2__
+# define __STDC_WANT_LIB_EXT2__ 1
+#endif
+/* Enable extensions specified by ISO/IEC 24747:2009.  */
+#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
+# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
+#endif
 /* Enable extensions on HP NonStop.  */
 #ifndef _TANDEM_SOURCE
 # define _TANDEM_SOURCE 1
 #endif
-/* Enable general extensions on Solaris.  */
-#ifndef __EXTENSIONS__
-# define __EXTENSIONS__ 1
+/* Enable X/Open extensions.  Define to 500 only if necessary
+   to make mbstate_t available.  */
+#ifndef _XOPEN_SOURCE
+/* # undef _XOPEN_SOURCE */
 #endif
 
 
 /* Version number of package */
-#define VERSION "26"
-
-/* Enable large inode numbers on Mac OS X 10.5.  */
-#ifndef _DARWIN_USE_64_BIT_INODE
-# define _DARWIN_USE_64_BIT_INODE 1
-#endif
+#define VERSION "32"
 
 /* Number of bits in a file offset, on hosts where this is settable. */
 /* #undef _FILE_OFFSET_BITS */
 
 /* Define for large files, on AIX-style hosts. */
 /* #undef _LARGE_FILES */
-
-/* Define to 1 if on MINIX. */
-/* #undef _MINIX */
-
-/* Define to 2 if the system does not provide POSIX.1 features except with
-   this defined. */
-/* #undef _POSIX_1_SOURCE */
-
-/* Define to 1 if you need to in order for `stat' and other things to work. */
-/* #undef _POSIX_SOURCE */
-
-#if defined(__APPLE__)
-
-#define get_current_dir_name()	getwd(malloc(128))
-#define strndupa(_s,_l)        strdup(_s)
-char* basename(const char*);
-#define init_module	darwin_init_module
-#define delete_module	darwin_delete_module
-#define program_invocation_short_name "depmod"
-#include <endian-darwin.h>
-#else
-#include <endian.h>
-
-#endif
-
-#if defined(__ANDROID__)
-#include <stdlib.h>
-#include <unistd.h>
-static inline char *get_current_dir_name(void)
-{
-    return getcwd(malloc(PATH_MAX), PATH_MAX);
-}
-#endif
diff --git a/config.h.in b/config.h.in
new file mode 100644
index 0000000..491d6c7
--- /dev/null
+++ b/config.h.in
@@ -0,0 +1,229 @@
+/* config.h.in.  Generated from configure.ac by autoheader.  */
+
+/* Debug messages. */
+#undef ENABLE_DEBUG
+
+/* System logging. */
+#undef ENABLE_LOGGING
+
+/* Enable openssl for modinfo. */
+#undef ENABLE_OPENSSL
+
+/* Enable Xz for modules. */
+#undef ENABLE_XZ
+
+/* Enable zlib for modules. */
+#undef ENABLE_ZLIB
+
+/* Enable Zstandard for modules. */
+#undef ENABLE_ZSTD
+
+/* Define to 1 if you have the declaration of `be32toh', and to 0 if you
+   don't. */
+#undef HAVE_DECL_BE32TOH
+
+/* Define to 1 if you have the declaration of `strndupa', and to 0 if you
+   don't. */
+#undef HAVE_DECL_STRNDUPA
+
+/* Define to 1 if you have the <dlfcn.h> header file. */
+#undef HAVE_DLFCN_H
+
+/* Define to 1 if you have the `finit_module' function. */
+#undef HAVE_FINIT_MODULE
+
+/* Define to 1 if you have the <inttypes.h> header file. */
+#undef HAVE_INTTYPES_H
+
+/* Define to 1 if you have the <linux/module.h> header file. */
+#undef HAVE_LINUX_MODULE_H
+
+/* Define to 1 if you have the <minix/config.h> header file. */
+#undef HAVE_MINIX_CONFIG_H
+
+/* Define if _Noreturn is available */
+#undef HAVE_NORETURN
+
+/* Define to 1 if you have the `secure_getenv' function. */
+#undef HAVE_SECURE_GETENV
+
+/* Define if _Static_assert() is available */
+#undef HAVE_STATIC_ASSERT
+
+/* Define to 1 if you have the <stdint.h> header file. */
+#undef HAVE_STDINT_H
+
+/* Define to 1 if you have the <stdio.h> header file. */
+#undef HAVE_STDIO_H
+
+/* Define to 1 if you have the <stdlib.h> header file. */
+#undef HAVE_STDLIB_H
+
+/* Define to 1 if you have the <strings.h> header file. */
+#undef HAVE_STRINGS_H
+
+/* Define to 1 if you have the <string.h> header file. */
+#undef HAVE_STRING_H
+
+/* Define to 1 if `st_mtim' is a member of `struct stat'. */
+#undef HAVE_STRUCT_STAT_ST_MTIM
+
+/* Define to 1 if you have the <sys/stat.h> header file. */
+#undef HAVE_SYS_STAT_H
+
+/* Define to 1 if you have the <sys/types.h> header file. */
+#undef HAVE_SYS_TYPES_H
+
+/* Define to 1 if you have the <unistd.h> header file. */
+#undef HAVE_UNISTD_H
+
+/* Define to 1 if you have the <wchar.h> header file. */
+#undef HAVE_WCHAR_H
+
+/* Define to 1 if compiler has __builtin_clz() builtin function */
+#undef HAVE___BUILTIN_CLZ
+
+/* Define to 1 if compiler has __builtin_types_compatible_p() builtin function
+   */
+#undef HAVE___BUILTIN_TYPES_COMPATIBLE_P
+
+/* Define to 1 if compiler has __builtin_uaddll_overflow() builtin function */
+#undef HAVE___BUILTIN_UADDLL_OVERFLOW
+
+/* Define to 1 if compiler has __builtin_uaddl_overflow() builtin function */
+#undef HAVE___BUILTIN_UADDL_OVERFLOW
+
+/* Define to 1 if you have the `__secure_getenv' function. */
+#undef HAVE___SECURE_GETENV
+
+/* Define to 1 if you have the `__xstat' function. */
+#undef HAVE___XSTAT
+
+/* Features in this build */
+#undef KMOD_FEATURES
+
+/* Define to the sub-directory where libtool stores uninstalled libraries. */
+#undef LT_OBJDIR
+
+/* Name of package */
+#undef PACKAGE
+
+/* Define to the address where bug reports for this package should be sent. */
+#undef PACKAGE_BUGREPORT
+
+/* Define to the full name of this package. */
+#undef PACKAGE_NAME
+
+/* Define to the full name and version of this package. */
+#undef PACKAGE_STRING
+
+/* Define to the one symbol short name of this package. */
+#undef PACKAGE_TARNAME
+
+/* Define to the home page for this package. */
+#undef PACKAGE_URL
+
+/* Define to the version of this package. */
+#undef PACKAGE_VERSION
+
+/* Define to 1 if all of the C90 standard headers exist (not just the ones
+   required in a freestanding environment). This macro is provided for
+   backward compatibility; new code need not use it. */
+#undef STDC_HEADERS
+
+/* Enable extensions on AIX 3, Interix.  */
+#ifndef _ALL_SOURCE
+# undef _ALL_SOURCE
+#endif
+/* Enable general extensions on macOS.  */
+#ifndef _DARWIN_C_SOURCE
+# undef _DARWIN_C_SOURCE
+#endif
+/* Enable general extensions on Solaris.  */
+#ifndef __EXTENSIONS__
+# undef __EXTENSIONS__
+#endif
+/* Enable GNU extensions on systems that have them.  */
+#ifndef _GNU_SOURCE
+# undef _GNU_SOURCE
+#endif
+/* Enable X/Open compliant socket functions that do not require linking
+   with -lxnet on HP-UX 11.11.  */
+#ifndef _HPUX_ALT_XOPEN_SOCKET_API
+# undef _HPUX_ALT_XOPEN_SOCKET_API
+#endif
+/* Identify the host operating system as Minix.
+   This macro does not affect the system headers' behavior.
+   A future release of Autoconf may stop defining this macro.  */
+#ifndef _MINIX
+# undef _MINIX
+#endif
+/* Enable general extensions on NetBSD.
+   Enable NetBSD compatibility extensions on Minix.  */
+#ifndef _NETBSD_SOURCE
+# undef _NETBSD_SOURCE
+#endif
+/* Enable OpenBSD compatibility extensions on NetBSD.
+   Oddly enough, this does nothing on OpenBSD.  */
+#ifndef _OPENBSD_SOURCE
+# undef _OPENBSD_SOURCE
+#endif
+/* Define to 1 if needed for POSIX-compatible behavior.  */
+#ifndef _POSIX_SOURCE
+# undef _POSIX_SOURCE
+#endif
+/* Define to 2 if needed for POSIX-compatible behavior.  */
+#ifndef _POSIX_1_SOURCE
+# undef _POSIX_1_SOURCE
+#endif
+/* Enable POSIX-compatible threading on Solaris.  */
+#ifndef _POSIX_PTHREAD_SEMANTICS
+# undef _POSIX_PTHREAD_SEMANTICS
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
+#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
+# undef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
+#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
+# undef __STDC_WANT_IEC_60559_BFP_EXT__
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
+#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
+# undef __STDC_WANT_IEC_60559_DFP_EXT__
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
+#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
+# undef __STDC_WANT_IEC_60559_FUNCS_EXT__
+#endif
+/* Enable extensions specified by ISO/IEC TS 18661-3:2015.  */
+#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
+# undef __STDC_WANT_IEC_60559_TYPES_EXT__
+#endif
+/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
+#ifndef __STDC_WANT_LIB_EXT2__
+# undef __STDC_WANT_LIB_EXT2__
+#endif
+/* Enable extensions specified by ISO/IEC 24747:2009.  */
+#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
+# undef __STDC_WANT_MATH_SPEC_FUNCS__
+#endif
+/* Enable extensions on HP NonStop.  */
+#ifndef _TANDEM_SOURCE
+# undef _TANDEM_SOURCE
+#endif
+/* Enable X/Open extensions.  Define to 500 only if necessary
+   to make mbstate_t available.  */
+#ifndef _XOPEN_SOURCE
+# undef _XOPEN_SOURCE
+#endif
+
+
+/* Version number of package */
+#undef VERSION
+
+/* Number of bits in a file offset, on hosts where this is settable. */
+#undef _FILE_OFFSET_BITS
+
+/* Define for large files, on AIX-style hosts. */
+#undef _LARGE_FILES
diff --git a/configure.ac b/configure.ac
index 6989e93..b651b5f 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1,6 +1,6 @@
 AC_PREREQ(2.64)
 AC_INIT([kmod],
-	[30],
+	[32],
 	[linux-modules@vger.kernel.org],
 	[kmod],
 	[http://git.kernel.org/?p=utils/kernel/kmod/kmod.git])
@@ -21,6 +21,9 @@ LT_INIT([disable-static pic-only])
 AS_IF([test "x$enable_static" = "xyes"], [AC_MSG_ERROR([--enable-static is not supported by kmod])])
 AS_IF([test "x$enable_largefile" = "xno"], [AC_MSG_ERROR([--disable-largefile is not supported by kmod])])
 
+module_compressions=""
+module_signatures="legacy"
+
 #####################################################################
 # Program checks and configurations
 #####################################################################
@@ -30,7 +33,6 @@ AC_PROG_MKDIR_P
 AC_PROG_LN_S
 PKG_PROG_PKG_CONFIG
 AC_PATH_PROG([XSLTPROC], [xsltproc])
-AC_PATH_PROG([MKOSI], [mkosi])
 
 AC_PROG_CC_C99
 
@@ -68,7 +70,8 @@ AC_COMPILE_IFELSE(
 
 AC_MSG_CHECKING([whether _Noreturn is supported])
 AC_COMPILE_IFELSE(
-	[AC_LANG_SOURCE([[_Noreturn int foo(void) { exit(0); }]])],
+	[AC_LANG_SOURCE([[#include <stdlib.h>
+	_Noreturn int foo(void) { exit(0); }]])],
         [AC_DEFINE([HAVE_NORETURN], [1], [Define if _Noreturn is available])
 	 AC_MSG_RESULT([yes])],
 	[AC_MSG_RESULT([no])])
@@ -78,17 +81,45 @@ AC_COMPILE_IFELSE(
 # --with-
 #####################################################################
 
+AC_ARG_WITH([distconfdir], AS_HELP_STRING([--with-distconfdir=DIR], [directory to search for distribution configuration files]),
+        [], [with_distconfdir='${prefix}/lib'])
+AC_SUBST([distconfdir], [$with_distconfdir])
+
 AC_ARG_WITH([rootlibdir],
         AS_HELP_STRING([--with-rootlibdir=DIR], [rootfs directory to install shared libraries]),
         [], [with_rootlibdir=$libdir])
 AC_SUBST([rootlibdir], [$with_rootlibdir])
 
+# Ideally this would be $prefix/lib/modules but default to /lib/modules for compatibility with earlier versions
+AC_ARG_WITH([module_directory],
+        AS_HELP_STRING([--with-module-directory=DIR], [directory in which to look for kernel modules @<:@default=/lib/modules@:>@]),
+        [], [with_module_directory=/lib/modules])
+AC_SUBST([module_directory], [$with_module_directory])
+
+# Check all directory arguments for consistency.
+for ac_var in	distconfdir rootlibdir module_directory
+do
+  eval ac_val=\$$ac_var
+  # Remove trailing slashes.
+  case $ac_val in
+    */ )
+      ac_val=`expr "X$ac_val" : 'X\(.*@<:@^/@:>@\)' \| "X$ac_val" : 'X\(.*\)'`
+      eval $ac_var=\$ac_val;;
+  esac
+  # Be sure to have absolute directory names.
+  case $ac_val in
+    @<:@\\/$@:>@* | ?:@<:@\\/@:>@* )  continue;;
+  esac
+  as_fn_error $? "expected an absolute directory name for --$ac_var: $ac_val"
+done
+
 AC_ARG_WITH([zstd],
 	AS_HELP_STRING([--with-zstd], [handle Zstandard-compressed modules @<:@default=disabled@:>@]),
 	[], [with_zstd=no])
 AS_IF([test "x$with_zstd" != "xno"], [
-	PKG_CHECK_MODULES([libzstd], [libzstd >= 1.4.4])
+	PKG_CHECK_MODULES([libzstd], [libzstd >= 1.4.4], [LIBS="$LIBS $libzstd_LIBS"])
 	AC_DEFINE([ENABLE_ZSTD], [1], [Enable Zstandard for modules.])
+	module_compressions="zstd $module_compressions"
 ], [
 	AC_MSG_NOTICE([Zstandard support not requested])
 ])
@@ -98,8 +129,9 @@ AC_ARG_WITH([xz],
 	AS_HELP_STRING([--with-xz], [handle Xz-compressed modules @<:@default=disabled@:>@]),
 	[], [with_xz=no])
 AS_IF([test "x$with_xz" != "xno"], [
-	PKG_CHECK_MODULES([liblzma], [liblzma >= 4.99])
+	PKG_CHECK_MODULES([liblzma], [liblzma >= 4.99], [LIBS="$LIBS $liblzma_LIBS"])
 	AC_DEFINE([ENABLE_XZ], [1], [Enable Xz for modules.])
+	module_compressions="xz $module_compressions"
 ], [
 	AC_MSG_NOTICE([Xz support not requested])
 ])
@@ -109,8 +141,9 @@ AC_ARG_WITH([zlib],
 	AS_HELP_STRING([--with-zlib], [handle gzipped modules @<:@default=disabled@:>@]),
 	[], [with_zlib=no])
 AS_IF([test "x$with_zlib" != "xno"], [
-	PKG_CHECK_MODULES([zlib], [zlib])
+	PKG_CHECK_MODULES([zlib], [zlib], [LIBS="$LIBS $zlib_LIBS"])
 	AC_DEFINE([ENABLE_ZLIB], [1], [Enable zlib for modules.])
+	module_compressions="gzip $module_compressions"
 ], [
 	AC_MSG_NOTICE([zlib support not requested])
 ])
@@ -120,8 +153,9 @@ AC_ARG_WITH([openssl],
 	AS_HELP_STRING([--with-openssl], [handle PKCS7 signatures @<:@default=disabled@:>@]),
 	[], [with_openssl=no])
 AS_IF([test "x$with_openssl" != "xno"], [
-	PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.1.0])
+	PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.1.0], [LIBS="$LIBS $libcrypto_LIBS"])
 	AC_DEFINE([ENABLE_OPENSSL], [1], [Enable openssl for modinfo.])
+	module_signatures="PKCS7 $module_signatures"
 ], [
 	AC_MSG_NOTICE([openssl support not requested])
 ])
@@ -141,15 +175,6 @@ AC_SUBST([bashcompletiondir], [$with_bashcompletiondir])
 # --enable-
 #####################################################################
 
-AC_ARG_ENABLE([experimental],
-        AS_HELP_STRING([--enable-experimental], [enable experimental tools and features. Do not enable it unless you know what you are doing. @<:@default=disabled@:>@]),
-        [], enable_experimental=no)
-AM_CONDITIONAL([BUILD_EXPERIMENTAL], [test "x$enable_experimental" = "xyes"])
-AS_IF([test "x$enable_experimental" = "xyes"], [
-	AC_DEFINE(ENABLE_EXPERIMENTAL, [1], [Experimental features.])
-])
-CC_FEATURE_APPEND([with_features], [enable_experimental], [EXPERIMENTAL])
-
 AC_ARG_ENABLE([tools],
         AS_HELP_STRING([--disable-tools], [disable building tools that provide same functionality as module-init-tools @<:@default=enabled@:>@]),
 	[], enable_tools=yes)
@@ -179,24 +204,6 @@ AS_IF([test "x$enable_debug" = "xyes"], [
 	AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
 ])
 
-AC_ARG_ENABLE([python],
-	AS_HELP_STRING([--enable-python], [enable Python libkmod bindings @<:@default=disabled@:>@]),
-	[], [enable_python=no])
-AS_IF([test "x$enable_python" = "xyes"], [
-	AM_PATH_PYTHON(,,[:])
-	AC_PATH_PROG([CYTHON], [cython], [:])
-
-	PKG_CHECK_MODULES([PYTHON], [python-${PYTHON_VERSION}],
-			  [have_python=yes],
-			  [PKG_CHECK_MODULES([PYTHON], [python],
-					     [have_python=yes],
-					     [have_python=no])])
-
-	AS_IF([test "x$have_python" = xno],
-	      [AC_MSG_ERROR([*** python support requested but libraries not found])])
-])
-AM_CONDITIONAL([BUILD_PYTHON], [test "x$enable_python" = "xyes"])
-
 AC_ARG_ENABLE([coverage],
 	AS_HELP_STRING([--enable-coverage], [enable test coverage @<:@default=disabled@:>@]),
 	[], [enable_coverage=no])
@@ -224,9 +231,6 @@ GTK_DOC_CHECK([1.14],[--flavour no-tmpl-flat])
 ], [
 AM_CONDITIONAL([ENABLE_GTK_DOC], false)])
 
-# Some tests are skipped when sysconfdir != /etc.
-AM_CONDITIONAL([KMOD_SYSCONFDIR_NOT_ETC], [test "x$sysconfdir" != "x/etc"])
-
 #####################################################################
 # Default CFLAGS and LDFLAGS
 #####################################################################
@@ -289,11 +293,16 @@ AC_DEFINE_UNQUOTED(KMOD_FEATURES, ["$with_features"], [Features in this build])
 # Generate files from *.in
 #####################################################################
 
+AC_SUBST([module_compressions], $module_compressions)
+AC_SUBST([module_signatures], $module_signatures)
+
 AC_CONFIG_FILES([
 	Makefile
 	man/Makefile
 	libkmod/docs/Makefile
 	libkmod/docs/version.xml
+	libkmod/libkmod.pc
+	tools/kmod.pc
 ])
 
 
@@ -304,8 +313,10 @@ AC_MSG_RESULT([
 	$PACKAGE $VERSION
 	=======
 
+	module_directory:	${module_directory}
 	prefix:			${prefix}
 	sysconfdir:		${sysconfdir}
+	distconfdir:		${distconfdir}
 	libdir:			${libdir}
 	rootlibdir:		${rootlibdir}
 	includedir:		${includedir}
@@ -316,9 +327,7 @@ AC_MSG_RESULT([
 	cflags:			${with_cflags} ${CFLAGS}
 	ldflags:		${with_ldflags} ${LDFLAGS}
 
-	experimental features:  ${enable_experimental}
 	tools:			${enable_tools}
-	python bindings:	${enable_python}
 	logging:		${enable_logging}
 	compression:		zstd=${with_zstd}  xz=${with_xz}  zlib=${with_zlib}
 	debug:			${enable_debug}
diff --git a/libkmod/libkmod-builtin.c b/libkmod/libkmod-builtin.c
index a002cb5..65334a8 100644
--- a/libkmod/libkmod-builtin.c
+++ b/libkmod/libkmod-builtin.c
@@ -54,7 +54,7 @@ struct kmod_builtin_iter {
 	char *buf;
 };
 
-struct kmod_builtin_iter *kmod_builtin_iter_new(struct kmod_ctx *ctx)
+static struct kmod_builtin_iter *kmod_builtin_iter_new(struct kmod_ctx *ctx)
 {
 	char path[PATH_MAX];
 	int file, sv_errno;
@@ -108,7 +108,7 @@ fail:
 	return iter;
 }
 
-void kmod_builtin_iter_free(struct kmod_builtin_iter *iter)
+static void kmod_builtin_iter_free(struct kmod_builtin_iter *iter)
 {
 	close(iter->file);
 	free(iter->buf);
@@ -165,7 +165,7 @@ fail:
 	return -1;
 }
 
-bool kmod_builtin_iter_next(struct kmod_builtin_iter *iter)
+static bool kmod_builtin_iter_next(struct kmod_builtin_iter *iter)
 {
 	char *line,  *modname;
 	size_t linesz;
@@ -216,7 +216,7 @@ bool kmod_builtin_iter_next(struct kmod_builtin_iter *iter)
 	return (iter->pos < iter->size);
 }
 
-bool kmod_builtin_iter_get_modname(struct kmod_builtin_iter *iter,
+static bool kmod_builtin_iter_get_modname(struct kmod_builtin_iter *iter,
 				char modname[static PATH_MAX])
 {
 	int sv_errno;
diff --git a/libkmod/libkmod-elf.c b/libkmod/libkmod-elf.c
index ef4a8a3..933825b 100644
--- a/libkmod/libkmod-elf.c
+++ b/libkmod/libkmod-elf.c
@@ -281,6 +281,11 @@ struct kmod_elf *kmod_elf_new(const void *memory, off_t size)
 	assert_cc(sizeof(uint32_t) == sizeof(Elf32_Word));
 	assert_cc(sizeof(uint32_t) == sizeof(Elf64_Word));
 
+	if (!memory) {
+		errno = -EINVAL;
+		return NULL;
+	}
+
 	class = elf_identify(memory, size);
 	if (class < 0) {
 		errno = -class;
@@ -392,7 +397,7 @@ static int elf_find_section(const struct kmod_elf *elf, const char *section)
 		return i;
 	}
 
-	return -ENOENT;
+	return -ENODATA;
 }
 
 int kmod_elf_get_section(const struct kmod_elf *elf, const char *section, const void **buf, uint64_t *buf_size)
@@ -422,7 +427,7 @@ int kmod_elf_get_section(const struct kmod_elf *elf, const char *section, const
 		return 0;
 	}
 
-	return -ENOENT;
+	return -ENODATA;
 }
 
 /* array will be allocated with strings in a single malloc, just free *array */
@@ -653,7 +658,7 @@ int kmod_elf_strip_vermagic(struct kmod_elf *elf)
 	}
 
 	ELFDBG(elf, "no vermagic found in .modinfo\n");
-	return -ENOENT;
+	return -ENODATA;
 }
 
 
diff --git a/libkmod/libkmod-file.c b/libkmod/libkmod-file.c
index b6a8cc9..b138e7e 100644
--- a/libkmod/libkmod-file.c
+++ b/libkmod/libkmod-file.c
@@ -58,7 +58,7 @@ struct kmod_file {
 	gzFile gzf;
 #endif
 	int fd;
-	bool direct;
+	enum kmod_file_compression_type compression;
 	off_t size;
 	void *memory;
 	const struct file_ops *ops;
@@ -376,19 +376,20 @@ static const char magic_zlib[] = {0x1f, 0x8b};
 
 static const struct comp_type {
 	size_t magic_size;
+	enum kmod_file_compression_type compression;
 	const char *magic_bytes;
 	const struct file_ops ops;
 } comp_types[] = {
 #ifdef ENABLE_ZSTD
-	{sizeof(magic_zstd), magic_zstd, {load_zstd, unload_zstd}},
+	{sizeof(magic_zstd),	KMOD_FILE_COMPRESSION_ZSTD, magic_zstd, {load_zstd, unload_zstd}},
 #endif
 #ifdef ENABLE_XZ
-	{sizeof(magic_xz), magic_xz, {load_xz, unload_xz}},
+	{sizeof(magic_xz),	KMOD_FILE_COMPRESSION_XZ, magic_xz, {load_xz, unload_xz}},
 #endif
 #ifdef ENABLE_ZLIB
-	{sizeof(magic_zlib), magic_zlib, {load_zlib, unload_zlib}},
+	{sizeof(magic_zlib),	KMOD_FILE_COMPRESSION_ZLIB, magic_zlib, {load_zlib, unload_zlib}},
 #endif
-	{0, NULL, {NULL, NULL}}
+	{0,			KMOD_FILE_COMPRESSION_NONE, NULL, {NULL, NULL}}
 };
 
 static int load_reg(struct kmod_file *file)
@@ -403,7 +404,7 @@ static int load_reg(struct kmod_file *file)
 			    file->fd, 0);
 	if (file->memory == MAP_FAILED)
 		return -errno;
-	file->direct = true;
+
 	return 0;
 }
 
@@ -421,6 +422,7 @@ struct kmod_elf *kmod_file_get_elf(struct kmod_file *file)
 	if (file->elf)
 		return file->elf;
 
+	kmod_file_load_contents(file);
 	file->elf = kmod_elf_new(file->memory, file->size);
 	return file->elf;
 }
@@ -431,7 +433,7 @@ struct kmod_file *kmod_file_open(const struct kmod_ctx *ctx,
 	struct kmod_file *file = calloc(1, sizeof(struct kmod_file));
 	const struct comp_type *itr;
 	size_t magic_size_max = 0;
-	int err;
+	int err = 0;
 
 	if (file == NULL)
 		return NULL;
@@ -447,7 +449,6 @@ struct kmod_file *kmod_file_open(const struct kmod_ctx *ctx,
 			magic_size_max = itr->magic_size;
 	}
 
-	file->direct = false;
 	if (magic_size_max > 0) {
 		char *buf = alloca(magic_size_max + 1);
 		ssize_t sz;
@@ -467,18 +468,21 @@ struct kmod_file *kmod_file_open(const struct kmod_ctx *ctx,
 		}
 
 		for (itr = comp_types; itr->ops.load != NULL; itr++) {
-			if (memcmp(buf, itr->magic_bytes, itr->magic_size) == 0)
+			if (memcmp(buf, itr->magic_bytes, itr->magic_size) == 0) {
+				file->ops = &itr->ops;
+				file->compression = itr->compression;
 				break;
+			}
 		}
-		if (itr->ops.load != NULL)
-			file->ops = &itr->ops;
 	}
 
-	if (file->ops == NULL)
+	if (file->ops == NULL) {
 		file->ops = &reg_ops;
+		file->compression = KMOD_FILE_COMPRESSION_NONE;
+	}
 
-	err = file->ops->load(file);
 	file->ctx = ctx;
+
 error:
 	if (err < 0) {
 		if (file->fd >= 0)
@@ -491,6 +495,18 @@ error:
 	return file;
 }
 
+/*
+ *  Callers should just check file->memory got updated
+ */
+void kmod_file_load_contents(struct kmod_file *file)
+{
+	if (file->memory)
+		return;
+
+	/*  The load functions already log possible errors. */
+	file->ops->load(file);
+}
+
 void *kmod_file_get_contents(const struct kmod_file *file)
 {
 	return file->memory;
@@ -501,9 +517,9 @@ off_t kmod_file_get_size(const struct kmod_file *file)
 	return file->size;
 }
 
-bool kmod_file_get_direct(const struct kmod_file *file)
+enum kmod_file_compression_type kmod_file_get_compression(const struct kmod_file *file)
 {
-	return file->direct;
+	return file->compression;
 }
 
 int kmod_file_get_fd(const struct kmod_file *file)
@@ -516,7 +532,9 @@ void kmod_file_unref(struct kmod_file *file)
 	if (file->elf)
 		kmod_elf_unref(file->elf);
 
-	file->ops->unload(file);
+	if (file->memory)
+		file->ops->unload(file);
+
 	if (file->fd >= 0)
 		close(file->fd);
 	free(file);
diff --git a/libkmod/libkmod-internal.h b/libkmod/libkmod-internal.h
index c22644a..26a7e28 100644
--- a/libkmod/libkmod-internal.h
+++ b/libkmod/libkmod-internal.h
@@ -61,6 +61,13 @@ struct kmod_list {
 	void *data;
 };
 
+enum kmod_file_compression_type {
+	KMOD_FILE_COMPRESSION_NONE = 0,
+	KMOD_FILE_COMPRESSION_ZSTD,
+	KMOD_FILE_COMPRESSION_XZ,
+	KMOD_FILE_COMPRESSION_ZLIB,
+};
+
 struct kmod_list *kmod_list_append(struct kmod_list *list, const void *data) _must_check_ __attribute__((nonnull(2)));
 struct kmod_list *kmod_list_prepend(struct kmod_list *list, const void *data) _must_check_ __attribute__((nonnull(2)));
 struct kmod_list *kmod_list_remove(struct kmod_list *list) _must_check_;
@@ -105,6 +112,7 @@ void kmod_pool_add_module(struct kmod_ctx *ctx, struct kmod_module *mod, const c
 void kmod_pool_del_module(struct kmod_ctx *ctx, struct kmod_module *mod, const char *key) __attribute__((nonnull(1, 2, 3)));
 
 const struct kmod_config *kmod_get_config(const struct kmod_ctx *ctx) __attribute__((nonnull(1)));
+enum kmod_file_compression_type kmod_get_kernel_compression(const struct kmod_ctx *ctx) __attribute__((nonnull(1)));
 
 /* libkmod-config.c */
 struct kmod_config_path {
@@ -148,14 +156,14 @@ void kmod_module_set_visited(struct kmod_module *mod, bool visited) __attribute_
 void kmod_module_set_builtin(struct kmod_module *mod, bool builtin) __attribute__((nonnull((1))));
 void kmod_module_set_required(struct kmod_module *mod, bool required) __attribute__((nonnull(1)));
 bool kmod_module_is_builtin(struct kmod_module *mod) __attribute__((nonnull(1)));
-int kmod_module_get_builtin(struct kmod_ctx *ctx, struct kmod_list **list) __attribute__((nonnull(1, 2)));
 
 /* libkmod-file.c */
 struct kmod_file *kmod_file_open(const struct kmod_ctx *ctx, const char *filename) _must_check_ __attribute__((nonnull(1,2)));
 struct kmod_elf *kmod_file_get_elf(struct kmod_file *file) __attribute__((nonnull(1)));
+void kmod_file_load_contents(struct kmod_file *file) __attribute__((nonnull(1)));
 void *kmod_file_get_contents(const struct kmod_file *file) _must_check_ __attribute__((nonnull(1)));
 off_t kmod_file_get_size(const struct kmod_file *file) _must_check_ __attribute__((nonnull(1)));
-bool kmod_file_get_direct(const struct kmod_file *file) _must_check_ __attribute__((nonnull(1)));
+enum kmod_file_compression_type kmod_file_get_compression(const struct kmod_file *file) _must_check_ __attribute__((nonnull(1)));
 int kmod_file_get_fd(const struct kmod_file *file) _must_check_ __attribute__((nonnull(1)));
 void kmod_file_unref(struct kmod_file *file) __attribute__((nonnull(1)));
 
@@ -167,7 +175,7 @@ struct kmod_modversion {
 	char *symbol;
 };
 
-struct kmod_elf *kmod_elf_new(const void *memory, off_t size) _must_check_ __attribute__((nonnull(1)));
+struct kmod_elf *kmod_elf_new(const void *memory, off_t size) _must_check_;
 void kmod_elf_unref(struct kmod_elf *elf) __attribute__((nonnull(1)));
 const void *kmod_elf_get_memory(const struct kmod_elf *elf) _must_check_ __attribute__((nonnull(1)));
 int kmod_elf_get_strings(const struct kmod_elf *elf, const char *section, char ***array) _must_check_ __attribute__((nonnull(1,2,3)));
@@ -199,9 +207,4 @@ bool kmod_module_signature_info(const struct kmod_file *file, struct kmod_signat
 void kmod_module_signature_info_free(struct kmod_signature_info *sig_info) __attribute__((nonnull));
 
 /* libkmod-builtin.c */
-struct kmod_builtin_iter;
-struct kmod_builtin_iter *kmod_builtin_iter_new(struct kmod_ctx *ctx) __attribute__((nonnull(1)));
-void kmod_builtin_iter_free(struct kmod_builtin_iter *iter) __attribute__((nonnull(1)));
-bool kmod_builtin_iter_next(struct kmod_builtin_iter *iter) __attribute__((nonnull(1)));
-bool kmod_builtin_iter_get_modname(struct kmod_builtin_iter *iter, char modname[static PATH_MAX]) __attribute__((nonnull(1, 2)));
 ssize_t kmod_builtin_get_modinfo(struct kmod_ctx *ctx, const char *modname, char ***modinfo) __attribute__((nonnull(1, 2, 3)));
diff --git a/libkmod/libkmod-module.c b/libkmod/libkmod-module.c
index 12d8ed1..585da41 100644
--- a/libkmod/libkmod-module.c
+++ b/libkmod/libkmod-module.c
@@ -551,7 +551,7 @@ KMOD_EXPORT int kmod_module_new_from_lookup(struct kmod_ctx *ctx,
 						const char *given_alias,
 						struct kmod_list **list)
 {
-	const lookup_func lookup[] = {
+	static const lookup_func lookup[] = {
 		kmod_lookup_alias_from_config,
 		kmod_lookup_alias_from_moddep_file,
 		kmod_lookup_alias_from_symbols_file,
@@ -619,7 +619,7 @@ KMOD_EXPORT int kmod_module_new_from_name_lookup(struct kmod_ctx *ctx,
 						 const char *modname,
 						 struct kmod_module **mod)
 {
-	const lookup_func lookup[] = {
+	static const lookup_func lookup[] = {
 		kmod_lookup_alias_from_moddep_file,
 		kmod_lookup_alias_from_builtin_file,
 		kmod_lookup_alias_from_kernel_builtin_file,
@@ -861,6 +861,82 @@ KMOD_EXPORT int kmod_module_remove_module(struct kmod_module *mod,
 
 extern long init_module(const void *mem, unsigned long len, const char *args);
 
+static int do_finit_module(struct kmod_module *mod, unsigned int flags,
+			   const char *args)
+{
+	enum kmod_file_compression_type compression, kernel_compression;
+	unsigned int kernel_flags = 0;
+	int err;
+
+	/*
+	 * When module is not compressed or its compression type matches the
+	 * one in use by the kernel, there is no need to read the file
+	 * in userspace. Otherwise, re-use ENOSYS to trigger the same fallback
+	 * as when finit_module() is not supported.
+	 */
+	compression = kmod_file_get_compression(mod->file);
+	kernel_compression = kmod_get_kernel_compression(mod->ctx);
+	if (!(compression == KMOD_FILE_COMPRESSION_NONE ||
+	      compression == kernel_compression))
+		return -ENOSYS;
+
+	if (compression != KMOD_FILE_COMPRESSION_NONE)
+		kernel_flags |= MODULE_INIT_COMPRESSED_FILE;
+
+	if (flags & KMOD_INSERT_FORCE_VERMAGIC)
+		kernel_flags |= MODULE_INIT_IGNORE_VERMAGIC;
+	if (flags & KMOD_INSERT_FORCE_MODVERSION)
+		kernel_flags |= MODULE_INIT_IGNORE_MODVERSIONS;
+
+	err = finit_module(kmod_file_get_fd(mod->file), args, kernel_flags);
+	if (err < 0)
+		err = -errno;
+
+	return err;
+}
+
+static int do_init_module(struct kmod_module *mod, unsigned int flags,
+			  const char *args)
+{
+	struct kmod_elf *elf;
+	const void *mem;
+	off_t size;
+	int err;
+
+	kmod_file_load_contents(mod->file);
+
+	if (flags & (KMOD_INSERT_FORCE_VERMAGIC | KMOD_INSERT_FORCE_MODVERSION)) {
+		elf = kmod_file_get_elf(mod->file);
+		if (elf == NULL) {
+			err = -errno;
+			return err;
+		}
+
+		if (flags & KMOD_INSERT_FORCE_MODVERSION) {
+			err = kmod_elf_strip_section(elf, "__versions");
+			if (err < 0)
+				INFO(mod->ctx, "Failed to strip modversion: %s\n", strerror(-err));
+		}
+
+		if (flags & KMOD_INSERT_FORCE_VERMAGIC) {
+			err = kmod_elf_strip_vermagic(elf);
+			if (err < 0)
+				INFO(mod->ctx, "Failed to strip vermagic: %s\n", strerror(-err));
+		}
+
+		mem = kmod_elf_get_memory(elf);
+	} else {
+		mem = kmod_file_get_contents(mod->file);
+	}
+	size = kmod_file_get_size(mod->file);
+
+	err = init_module(mem, size, args);
+	if (err < 0)
+		err = -errno;
+
+	return err;
+}
+
 /**
  * kmod_module_insert_module:
  * @mod: kmod module
@@ -881,9 +957,6 @@ KMOD_EXPORT int kmod_module_insert_module(struct kmod_module *mod,
 							const char *options)
 {
 	int err;
-	const void *mem;
-	off_t size;
-	struct kmod_elf *elf;
 	const char *path;
 	const char *args = options ? options : "";
 
@@ -904,50 +977,14 @@ KMOD_EXPORT int kmod_module_insert_module(struct kmod_module *mod,
 		}
 	}
 
-	if (kmod_file_get_direct(mod->file)) {
-		unsigned int kernel_flags = 0;
-
-		if (flags & KMOD_INSERT_FORCE_VERMAGIC)
-			kernel_flags |= MODULE_INIT_IGNORE_VERMAGIC;
-		if (flags & KMOD_INSERT_FORCE_MODVERSION)
-			kernel_flags |= MODULE_INIT_IGNORE_MODVERSIONS;
+	err = do_finit_module(mod, flags, args);
+	if (err == -ENOSYS)
+		err = do_init_module(mod, flags, args);
 
-		err = finit_module(kmod_file_get_fd(mod->file), args, kernel_flags);
-		if (err == 0 || errno != ENOSYS)
-			goto init_finished;
-	}
-
-	if (flags & (KMOD_INSERT_FORCE_VERMAGIC | KMOD_INSERT_FORCE_MODVERSION)) {
-		elf = kmod_file_get_elf(mod->file);
-		if (elf == NULL) {
-			err = -errno;
-			return err;
-		}
-
-		if (flags & KMOD_INSERT_FORCE_MODVERSION) {
-			err = kmod_elf_strip_section(elf, "__versions");
-			if (err < 0)
-				INFO(mod->ctx, "Failed to strip modversion: %s\n", strerror(-err));
-		}
-
-		if (flags & KMOD_INSERT_FORCE_VERMAGIC) {
-			err = kmod_elf_strip_vermagic(elf);
-			if (err < 0)
-				INFO(mod->ctx, "Failed to strip vermagic: %s\n", strerror(-err));
-		}
-
-		mem = kmod_elf_get_memory(elf);
-	} else {
-		mem = kmod_file_get_contents(mod->file);
-	}
-	size = kmod_file_get_size(mod->file);
+	if (err < 0)
+		INFO(mod->ctx, "Failed to insert module '%s': %s\n",
+		     path, strerror(-err));
 
-	err = init_module(mem, size, args);
-init_finished:
-	if (err < 0) {
-		err = -errno;
-		INFO(mod->ctx, "Failed to insert module '%s': %m\n", path);
-	}
 	return err;
 }
 
@@ -1810,6 +1847,10 @@ KMOD_EXPORT int kmod_module_get_initstate(const struct kmod_module *mod)
 
 	pathlen = snprintf(path, sizeof(path),
 				"/sys/module/%s/initstate", mod->name);
+	if (pathlen >= (int)sizeof(path)) {
+		/* Too long path was truncated */
+		return -ENAMETOOLONG;
+	}
 	fd = open(path, O_RDONLY|O_CLOEXEC);
 	if (fd < 0) {
 		err = -errno;
@@ -2943,46 +2984,3 @@ KMOD_EXPORT void kmod_module_dependency_symbols_free_list(struct kmod_list *list
 		list = kmod_list_remove(list);
 	}
 }
-
-/**
- * kmod_module_get_builtin:
- * @ctx: kmod library context
- * @list: where to save the builtin module list
- *
- * Returns: 0 on success or < 0 otherwise.
- */
-int kmod_module_get_builtin(struct kmod_ctx *ctx, struct kmod_list **list)
-{
-	struct kmod_builtin_iter *iter;
-	int err = 0;
-
-	iter = kmod_builtin_iter_new(ctx);
-	if (!iter)
-		return -errno;
-
-	while (kmod_builtin_iter_next(iter)) {
-		struct kmod_module *mod = NULL;
-		char modname[PATH_MAX];
-
-		if (!kmod_builtin_iter_get_modname(iter, modname)) {
-			err = -errno;
-			goto fail;
-		}
-
-		err = kmod_module_new_from_name(ctx, modname, &mod);
-		if (err < 0)
-			goto fail;
-
-		kmod_module_set_builtin(mod, true);
-
-		*list = kmod_list_append(*list, mod);
-	}
-
-	kmod_builtin_iter_free(iter);
-	return err;
-fail:
-	kmod_builtin_iter_free(iter);
-	kmod_module_unref_list(*list);
-	*list = NULL;
-	return err;
-}
diff --git a/libkmod/libkmod-signature.c b/libkmod/libkmod-signature.c
index 47aedd0..2474e3e 100644
--- a/libkmod/libkmod-signature.c
+++ b/libkmod/libkmod-signature.c
@@ -126,6 +126,7 @@ struct pkcs7_private {
 	PKCS7 *pkcs7;
 	unsigned char *key_id;
 	BIGNUM *sno;
+	char *hash_algo;
 };
 
 static void pkcs7_free(void *s)
@@ -136,42 +137,11 @@ static void pkcs7_free(void *s)
 	PKCS7_free(pvt->pkcs7);
 	BN_free(pvt->sno);
 	free(pvt->key_id);
+	free(pvt->hash_algo);
 	free(pvt);
 	si->private = NULL;
 }
 
-static int obj_to_hash_algo(const ASN1_OBJECT *o)
-{
-	int nid;
-
-	nid = OBJ_obj2nid(o);
-	switch (nid) {
-	case NID_md4:
-		return PKEY_HASH_MD4;
-	case NID_md5:
-		return PKEY_HASH_MD5;
-	case NID_sha1:
-		return PKEY_HASH_SHA1;
-	case NID_ripemd160:
-		return PKEY_HASH_RIPE_MD_160;
-	case NID_sha256:
-		return PKEY_HASH_SHA256;
-	case NID_sha384:
-		return PKEY_HASH_SHA384;
-	case NID_sha512:
-		return PKEY_HASH_SHA512;
-	case NID_sha224:
-		return PKEY_HASH_SHA224;
-# ifndef OPENSSL_NO_SM3
-	case NID_sm3:
-		return PKEY_HASH_SM3;
-# endif
-	default:
-		return -1;
-	}
-	return -1;
-}
-
 static const char *x509_name_to_str(X509_NAME *name)
 {
 	int i;
@@ -218,6 +188,8 @@ static bool fill_pkcs7(const char *mem, off_t size,
 	unsigned char *key_id_str;
 	struct pkcs7_private *pvt;
 	const char *issuer_str;
+	char *hash_algo;
+	int hash_algo_len;
 
 	size -= sig_len;
 	pkcs7_raw = mem + size;
@@ -276,21 +248,37 @@ static bool fill_pkcs7(const char *mem, off_t size,
 
 	X509_ALGOR_get0(&o, NULL, NULL, dig_alg);
 
-	sig_info->hash_algo = pkey_hash_algo[obj_to_hash_algo(o)];
+	// Use OBJ_obj2txt to calculate string length
+	hash_algo_len = OBJ_obj2txt(NULL, 0, o, 0);
+	if (hash_algo_len < 0)
+		goto err3;
+	hash_algo = malloc(hash_algo_len + 1);
+	if (hash_algo == NULL)
+		goto err3;
+	hash_algo_len = OBJ_obj2txt(hash_algo, hash_algo_len + 1, o, 0);
+	if (hash_algo_len < 0)
+		goto err4;
+
+	// Assign libcrypto hash algo string or number
+	sig_info->hash_algo = hash_algo;
+
 	sig_info->id_type = pkey_id_type[modsig->id_type];
 
 	pvt = malloc(sizeof(*pvt));
 	if (pvt == NULL)
-		goto err3;
+		goto err4;
 
 	pvt->pkcs7 = pkcs7;
 	pvt->key_id = key_id_str;
 	pvt->sno = sno_bn;
+	pvt->hash_algo = hash_algo;
 	sig_info->private = pvt;
 
 	sig_info->free = pkcs7_free;
 
 	return true;
+err4:
+	free(hash_algo);
 err3:
 	free(key_id_str);
 err2:
diff --git a/libkmod/libkmod.c b/libkmod/libkmod.c
index 7c2b889..213b424 100644
--- a/libkmod/libkmod.c
+++ b/libkmod/libkmod.c
@@ -50,7 +50,7 @@
  * and is passed to all library operations.
  */
 
-static struct _index_files {
+static const struct {
 	const char *fn;
 	const char *prefix;
 } index_files[] = {
@@ -61,10 +61,11 @@ static struct _index_files {
 	[KMOD_INDEX_MODULES_BUILTIN] = { .fn = "modules.builtin", .prefix = ""},
 };
 
-static const char *default_config_paths[] = {
+static const char *const default_config_paths[] = {
 	SYSCONFDIR "/modprobe.d",
 	"/run/modprobe.d",
 	"/usr/local/lib/modprobe.d",
+	DISTCONFDIR "/modprobe.d",
 	"/lib/modprobe.d",
 	NULL
 };
@@ -83,6 +84,7 @@ struct kmod_ctx {
 	void *log_data;
 	const void *userdata;
 	char *dirname;
+	enum kmod_file_compression_type kernel_compression;
 	struct kmod_config *config;
 	struct hash *modules_by_name;
 	struct index_mm *indexes[_KMOD_INDEX_MODULES_SIZE];
@@ -208,7 +210,7 @@ static int log_priority(const char *priority)
 	return 0;
 }
 
-static const char *dirname_default_prefix = "/lib/modules";
+static const char *dirname_default_prefix = MODULE_DIRECTORY;
 
 static char *get_kernel_release(const char *dirname)
 {
@@ -227,19 +229,53 @@ static char *get_kernel_release(const char *dirname)
 	return p;
 }
 
+static enum kmod_file_compression_type get_kernel_compression(struct kmod_ctx *ctx)
+{
+	const char *path = "/sys/module/compression";
+	char buf[16];
+	int fd;
+	int err;
+
+	fd = open(path, O_RDONLY|O_CLOEXEC);
+	if (fd < 0) {
+		/* Not having the file is not an error: kernel may be too old */
+		DBG(ctx, "could not open '%s' for reading: %m\n", path);
+		return KMOD_FILE_COMPRESSION_NONE;
+	}
+
+	err = read_str_safe(fd, buf, sizeof(buf));
+	close(fd);
+	if (err < 0) {
+		ERR(ctx, "could not read from '%s': %s\n",
+		    path, strerror(-err));
+		return KMOD_FILE_COMPRESSION_NONE;
+	}
+
+	if (streq(buf, "zstd\n"))
+		return KMOD_FILE_COMPRESSION_ZSTD;
+	else if (streq(buf, "xz\n"))
+		return KMOD_FILE_COMPRESSION_XZ;
+	else if (streq(buf, "gzip\n"))
+		return KMOD_FILE_COMPRESSION_ZLIB;
+
+	ERR(ctx, "unknown kernel compression %s", buf);
+
+	return KMOD_FILE_COMPRESSION_NONE;
+}
+
 /**
  * kmod_new:
  * @dirname: what to consider as linux module's directory, if NULL
- *           defaults to /lib/modules/`uname -r`. If it's relative,
+ *           defaults to $MODULE_DIRECTORY/`uname -r`. If it's relative,
  *           it's treated as relative to the current working directory.
  *           Otherwise, give an absolute dirname.
  * @config_paths: ordered array of paths (directories or files) where
  *                to load from user-defined configuration parameters such as
  *                alias, blacklists, commands (install, remove). If NULL
  *                defaults to /etc/modprobe.d, /run/modprobe.d,
- *                /usr/local/lib/modprobe.d and /lib/modprobe.d. Give an empty
- *                vector if configuration should not be read. This array must
- *                be null terminated.
+ *                /usr/local/lib/modprobe.d, DISTCONFDIR/modprobe.d, and
+ *                /lib/modprobe.d. Give an empty vector if configuration should
+ *                not be read. This array must be null terminated.
  *
  * Create kmod library context. This reads the kmod configuration
  * and fills in the default values.
@@ -272,6 +308,8 @@ KMOD_EXPORT struct kmod_ctx *kmod_new(const char *dirname,
 	if (env != NULL)
 		kmod_set_log_priority(ctx, log_priority(env));
 
+	ctx->kernel_compression = get_kernel_compression(ctx);
+
 	if (config_paths == NULL)
 		config_paths = default_config_paths;
 	err = kmod_config_new(ctx, &ctx->config, config_paths);
@@ -979,3 +1017,8 @@ const struct kmod_config *kmod_get_config(const struct kmod_ctx *ctx)
 {
 	return ctx->config;
 }
+
+enum kmod_file_compression_type kmod_get_kernel_compression(const struct kmod_ctx *ctx)
+{
+	return ctx->kernel_compression;
+}
diff --git a/libkmod/python/.gitignore b/libkmod/python/.gitignore
deleted file mode 100644
index 69af451..0000000
--- a/libkmod/python/.gitignore
+++ /dev/null
@@ -1,6 +0,0 @@
-__pycache__
-dist
-*.c
-*.pyc
-*.so
-kmod/version.py
diff --git a/libkmod/python/README b/libkmod/python/README
deleted file mode 100644
index 75c2636..0000000
--- a/libkmod/python/README
+++ /dev/null
@@ -1,23 +0,0 @@
-python-kmod
-===========
-
-Python bindings for kmod/libkmod
-
-python-kmod is a Python wrapper module for libkmod, exposing common
-module operations: listing installed modules, modprobe, and rmmod.
-It is at:
-
-Example (python invoked as root)
---------------------------------
-
-::
-
-  >>> import kmod
-  >>> km = kmod.Kmod()
-  >>> [(m.name, m.size) for m in km.loaded()]
-  [(u'nfs', 407706),
-   (u'nfs_acl', 12741)
-   ...
-   (u'virtio_blk', 17549)]
-  >>> km.modprobe("btrfs")
-  >>> km.rmmod("btrfs")
diff --git a/libkmod/python/kmod/__init__.py b/libkmod/python/kmod/__init__.py
deleted file mode 100644
index 0d79787..0000000
--- a/libkmod/python/kmod/__init__.py
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-"Libkmod -- Python interface to kmod API."
-
-from .version import __version__
-try:
-    from .kmod import Kmod
-except ImportError:
-    # this is a non-Linux platform
-    pass
diff --git a/libkmod/python/kmod/_libkmod_h.pxd b/libkmod/python/kmod/_libkmod_h.pxd
deleted file mode 100644
index 7191953..0000000
--- a/libkmod/python/kmod/_libkmod_h.pxd
+++ /dev/null
@@ -1,113 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport libc.stdint as _stdint
-
-
-cdef extern from *:
-    ctypedef char* const_char_ptr 'const char *'
-    ctypedef char* const_char_const_ptr 'const char const *'
-    ctypedef void* const_void_ptr 'const void *'
-
-
-cdef extern from 'stdbool.h':
-    ctypedef struct bool:
-        pass
-
-
-cdef extern from 'libkmod/libkmod.h':
-    # library user context - reads the config and system
-    # environment, user variables, allows custom logging
-    cdef struct kmod_ctx:
-        pass
-
-    kmod_ctx *kmod_new(
-        const_char_ptr dirname, const_char_const_ptr config_paths)
-    kmod_ctx *kmod_ref(kmod_ctx *ctx)
-    kmod_ctx *kmod_unref(kmod_ctx *ctx)
-
-    # Management of libkmod's resources
-    int kmod_load_resources(kmod_ctx *ctx)
-    void kmod_unload_resources(kmod_ctx *ctx)
-
-    # access to kmod generated lists
-    cdef struct kmod_list:
-        pass
-    ctypedef kmod_list* const_kmod_list_ptr 'const struct kmod_list *'
-    kmod_list *kmod_list_next(
-        const_kmod_list_ptr list, const_kmod_list_ptr curr)
-    kmod_list *kmod_list_prev(
-        const_kmod_list_ptr list, const_kmod_list_ptr curr)
-    kmod_list *kmod_list_last(const_kmod_list_ptr list)
-
-    # Operate on kernel modules
-    cdef struct kmod_module:
-        pass
-    ctypedef kmod_module* const_kmod_module_ptr 'const struct kmod_module *'
-    int kmod_module_new_from_name(
-        kmod_ctx *ctx, const_char_ptr name, kmod_module **mod)
-    int kmod_module_new_from_lookup(
-        kmod_ctx *ctx, const_char_ptr given_alias, kmod_list **list)
-    int kmod_module_new_from_loaded(kmod_ctx *ctx, kmod_list **list)
-
-    kmod_module *kmod_module_ref(kmod_module *mod)
-    kmod_module *kmod_module_unref(kmod_module *mod)
-    int kmod_module_unref_list(kmod_list *list)
-    kmod_module *kmod_module_get_module(kmod_list *entry)
-
-    # Flags to kmod_module_probe_insert_module
-    # codes below can be used in return value, too
-    enum: KMOD_PROBE_APPLY_BLACKLIST
-
-    #ctypedef int (*install_callback_t)(
-    #    kmod_module *m, const_char_ptr cmdline, const_void_ptr data)
-    #ctypedef void (*print_action_callback_t)(
-    #    kmod_module *m, bool install, const_char_ptr options)
-
-    int kmod_module_remove_module(
-        kmod_module *mod, unsigned int flags)
-    int kmod_module_insert_module(
-        kmod_module *mod, unsigned int flags, const_char_ptr options)
-    int kmod_module_probe_insert_module(
-        kmod_module *mod, unsigned int flags, const_char_ptr extra_options,
-        int (*run_install)(
-            kmod_module *m, const_char_ptr cmdline, void *data),
-        const_void_ptr data,
-        void (*print_action)(
-            kmod_module *m, bool install, const_char_ptr options),
-        )
-
-    const_char_ptr kmod_module_get_name(const_kmod_module_ptr mod)
-    const_char_ptr kmod_module_get_path(const_kmod_module_ptr mod)
-    const_char_ptr kmod_module_get_options(const_kmod_module_ptr mod)
-    const_char_ptr kmod_module_get_install_commands(const_kmod_module_ptr mod)
-    const_char_ptr kmod_module_get_remove_commands(const_kmod_module_ptr mod)
-
-    # Information regarding "live information" from module's state, as
-    # returned by kernel
-    int kmod_module_get_refcnt(const_kmod_module_ptr mod)
-    long kmod_module_get_size(const_kmod_module_ptr mod)
-
-    # Information retrieved from ELF headers and section
-    int kmod_module_get_info(const_kmod_module_ptr mod, kmod_list **list)
-    const_char_ptr kmod_module_info_get_key(const_kmod_list_ptr entry)
-    const_char_ptr kmod_module_info_get_value(const_kmod_list_ptr entry)
-    void kmod_module_info_free_list(kmod_list *list)
-
-    int kmod_module_get_versions(const_kmod_module_ptr mod, kmod_list **list)
-    const_char_ptr kmod_module_version_get_symbol(const_kmod_list_ptr entry)
-    _stdint.uint64_t kmod_module_version_get_crc(const_kmod_list_ptr entry)
-    void kmod_module_versions_free_list(kmod_list *list)
diff --git a/libkmod/python/kmod/_util.pxd b/libkmod/python/kmod/_util.pxd
deleted file mode 100644
index 80cbb28..0000000
--- a/libkmod/python/kmod/_util.pxd
+++ /dev/null
@@ -1,20 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport _libkmod_h
-
-
-cdef object char_ptr_to_str(_libkmod_h.const_char_ptr bytes)
diff --git a/libkmod/python/kmod/_util.pyx b/libkmod/python/kmod/_util.pyx
deleted file mode 100644
index 39eec3a..0000000
--- a/libkmod/python/kmod/_util.pyx
+++ /dev/null
@@ -1,28 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-import sys as _sys
-
-cimport _libkmod_h
-
-
-cdef object char_ptr_to_str(_libkmod_h.const_char_ptr char_ptr):
-    if char_ptr is NULL:
-        return None
-    if _sys.version_info >= (3,):  # Python 3
-        return str(char_ptr, 'ascii')
-    # Python 2
-    return unicode(char_ptr, 'ascii')
diff --git a/libkmod/python/kmod/error.py b/libkmod/python/kmod/error.py
deleted file mode 100644
index 123f4ce..0000000
--- a/libkmod/python/kmod/error.py
+++ /dev/null
@@ -1,18 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-class KmodError (Exception):
-    pass
diff --git a/libkmod/python/kmod/kmod.pxd b/libkmod/python/kmod/kmod.pxd
deleted file mode 100644
index 7805d71..0000000
--- a/libkmod/python/kmod/kmod.pxd
+++ /dev/null
@@ -1,22 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport _libkmod_h
-
-
-cdef class Kmod (object):
-    cdef _libkmod_h.kmod_ctx *_kmod_ctx
-    cdef object mod_dir
diff --git a/libkmod/python/kmod/kmod.pyx b/libkmod/python/kmod/kmod.pyx
deleted file mode 100644
index 3e73a1c..0000000
--- a/libkmod/python/kmod/kmod.pyx
+++ /dev/null
@@ -1,125 +0,0 @@
-# Copyright (C) 2012 Red Hat, Inc.
-#                    W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-"Define the Kmod class"
-
-cimport cython as _cython
-cimport _libkmod_h
-from error import KmodError as _KmodError
-cimport module as _module
-import module as _module
-cimport list as _list
-import list as _list
-
-
-cdef class Kmod (object):
-    "Wrap a struct kmod_ctx* item"
-    def __cinit__(self):
-        self._kmod_ctx = NULL
-        self.mod_dir = None
-
-    def __dealloc__(self):
-        self._cleanup()
-
-    def __init__(self, mod_dir=None):
-        self.set_mod_dir(mod_dir=mod_dir)
-
-    def set_mod_dir(self, mod_dir=None):
-        self.mod_dir = mod_dir
-        self._setup()
-
-    def _setup(self):
-        cdef char *mod_dir = NULL
-        self._cleanup()
-        if self.mod_dir:
-            mod_dir = self.mod_dir
-        self._kmod_ctx = _libkmod_h.kmod_new(mod_dir, NULL);
-        if self._kmod_ctx is NULL:
-            raise _KmodError('Could not initialize')
-        _libkmod_h.kmod_load_resources(self._kmod_ctx)
-
-    def _cleanup(self):
-        if self._kmod_ctx is not NULL:
-            _libkmod_h.kmod_unload_resources(self._kmod_ctx);
-            self._kmod_ctx = NULL
-
-    def loaded(self):
-        "iterate through currently loaded modules"
-        cdef _list.ModList ml = _list.ModList()
-        cdef _list.ModListItem mli
-        err = _libkmod_h.kmod_module_new_from_loaded(self._kmod_ctx, &ml.list)
-        if err < 0:
-            raise _KmodError('Could not get loaded modules')
-        for item in ml:
-            mli = <_list.ModListItem> item
-            mod = _module.Module()
-            mod.from_mod_list_item(item)
-            yield mod
-
-    def lookup(self, alias_name, flags=_libkmod_h.KMOD_PROBE_APPLY_BLACKLIST):
-        "iterate through modules matching `alias_name`"
-        cdef _list.ModList ml = _list.ModList()
-        cdef _list.ModListItem mli
-        if hasattr(alias_name, 'encode'):
-            alias_name = alias_name.encode('ascii')
-        err = _libkmod_h.kmod_module_new_from_lookup(
-            self._kmod_ctx, alias_name, &ml.list)
-        if err < 0:
-            raise _KmodError('Could not modprobe')
-        for item in ml:
-            mli = <_list.ModListItem> item
-            mod = _module.Module()
-            mod.from_mod_list_item(item)
-            yield mod
-
-    @_cython.always_allow_keywords(True)
-    def module_from_name(self, name):
-        cdef _module.Module mod = _module.Module()
-        if hasattr(name, 'encode'):
-            name = name.encode('ascii')
-        err = _libkmod_h.kmod_module_new_from_name(
-            self._kmod_ctx, name, &mod.module)
-        if err < 0:
-            raise _KmodError('Could not get module')
-        return mod
-
-    def list(self):
-        "iterate through currently loaded modules and sizes"
-        for mod in self.loaded():
-            yield (mod.name, mod.size)
-
-    def modprobe(self, name, quiet=False, *args, **kwargs):
-        """
-        Load a module (or alias) and all modules on which it depends.
-        The 'quiet' option defaults to False; set to True to mimic the behavior
-        of the '--quiet' commandline option.
-        """
-        mods = list(self.lookup(alias_name=name))
-
-        if not mods and not quiet:
-            raise _KmodError('Could not modprobe %s' % name)
-
-        for mod in mods:
-            mod.insert(*args, **kwargs)
-
-    def rmmod(self, module_name, *args, **kwargs):
-       """
-       remove module from current tree
-       e.g. km.rmmod("thinkpad_acpi")
-       """
-       mod = self.module_from_name(name=module_name)
-       mod.remove(*args, **kwargs)
diff --git a/libkmod/python/kmod/list.pxd b/libkmod/python/kmod/list.pxd
deleted file mode 100644
index 8e5b388..0000000
--- a/libkmod/python/kmod/list.pxd
+++ /dev/null
@@ -1,25 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport _libkmod_h
-
-
-cdef class ModListItem (object):
-    cdef _libkmod_h.kmod_list *list
-
-
-cdef class ModList (ModListItem):
-    cdef _libkmod_h.kmod_list *_next
diff --git a/libkmod/python/kmod/list.pyx b/libkmod/python/kmod/list.pyx
deleted file mode 100644
index ef0e0d4..0000000
--- a/libkmod/python/kmod/list.pyx
+++ /dev/null
@@ -1,45 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport _libkmod_h
-
-
-cdef class ModListItem (object):
-    "Wrap a struct kmod_list* list item"
-    def __cinit__(self):
-        self.list = NULL
-
-
-cdef class ModList (ModListItem):
-    "Wrap a struct kmod_list* list with iteration"
-    def __cinit__(self):
-        self._next = NULL
-
-    def __dealloc__(self):
-        if self.list is not NULL:
-            _libkmod_h.kmod_module_unref_list(self.list)
-
-    def __iter__(self):
-        self._next = self.list
-        return self
-
-    def __next__(self):
-        if self._next is NULL:
-            raise StopIteration()
-        mli = ModListItem()
-        mli.list = self._next
-        self._next = _libkmod_h.kmod_list_next(self.list, self._next)
-        return mli
diff --git a/libkmod/python/kmod/module.pxd b/libkmod/python/kmod/module.pxd
deleted file mode 100644
index c7d7da4..0000000
--- a/libkmod/python/kmod/module.pxd
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-cimport _libkmod_h
-cimport list as _list
-
-
-cdef class Module (object):
-    cdef _libkmod_h.kmod_module *module
-
-    cpdef from_mod_list_item(self, _list.ModListItem item)
diff --git a/libkmod/python/kmod/module.pyx b/libkmod/python/kmod/module.pyx
deleted file mode 100644
index 42aa92e..0000000
--- a/libkmod/python/kmod/module.pyx
+++ /dev/null
@@ -1,158 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-import collections as _collections
-
-cimport libc.errno as _errno
-
-cimport _libkmod_h
-from error import KmodError as _KmodError
-cimport list as _list
-import list as _list
-cimport _util
-import _util
-
-
-cdef class Module (object):
-    "Wrap a struct kmod_module* item"
-    def __cinit__(self):
-        self.module = NULL
-
-    def __dealloc__(self):
-        self._cleanup()
-
-    def _cleanup(self):
-        if self.module is not NULL:
-            _libkmod_h.kmod_module_unref(self.module)
-            self.module = NULL
-
-    cpdef from_mod_list_item(self, _list.ModListItem item):
-        self._cleanup()
-        self.module = _libkmod_h.kmod_module_get_module(item.list)
-
-    def _name_get(self):
-        return _util.char_ptr_to_str(
-            _libkmod_h.kmod_module_get_name(self.module))
-    name = property(fget=_name_get)
-
-    def _path_get(self):
-        return _util.char_ptr_to_str(
-            _libkmod_h.kmod_module_get_path(self.module))
-    path = property(fget=_path_get)
-
-    def _options_get(self):
-        return _util.char_ptr_to_str(
-            _libkmod_h.kmod_module_get_options(self.module))
-    options = property(fget=_options_get)
-
-    def _install_commands_get(self):
-        return _util.char_ptr_to_str(
-            _libkmod_h.kmod_module_get_install_commands(self.module))
-    install_commands = property(fget=_install_commands_get)
-
-    def _remove_commands_get(self):
-        return _util.char_ptr_to_str(
-            _libkmod_h.kmod_module_get_remove_commands(self.module))
-    remove_commands = property(fget=_remove_commands_get)
-
-    def _refcnt_get(self):
-        return _libkmod_h.kmod_module_get_refcnt(self.module)
-    refcnt = property(fget=_refcnt_get)
-
-    def _size_get(self):
-        return _libkmod_h.kmod_module_get_size(self.module)
-    size = property(fget=_size_get)
-
-    def _info_get(self):
-        cdef _list.ModList ml = _list.ModList()
-        cdef _list.ModListItem mli
-        err = _libkmod_h.kmod_module_get_info(self.module, &ml.list)
-        if err < 0:
-            raise _KmodError('Could not get info')
-        info = _collections.OrderedDict()
-        try:
-            for item in ml:
-                mli = <_list.ModListItem> item
-                key = _util.char_ptr_to_str(
-                    _libkmod_h.kmod_module_info_get_key(mli.list))
-                value = _util.char_ptr_to_str(
-                    _libkmod_h.kmod_module_info_get_value(mli.list))
-                info[key] = value
-        finally:
-            _libkmod_h.kmod_module_info_free_list(ml.list)
-            ml.list = NULL
-        return info
-    info = property(fget=_info_get)
-
-    def _versions_get(self):
-        cdef _list.ModList ml = _list.ModList()
-        cdef _list.ModListItem mli
-        err = _libkmod_h.kmod_module_get_versions(self.module, &ml.list)
-        if err < 0:
-            raise _KmodError('Could not get versions')
-        try:
-            for item in ml:
-                mli = <_list.ModListItem> item
-                symbol = _util.char_ptr_to_str(
-                    _libkmod_h.kmod_module_version_get_symbol(mli.list))
-                crc = _libkmod_h.kmod_module_version_get_crc(mli.list)
-                yield {'symbol': symbol, 'crc': crc}
-        finally:
-            _libkmod_h.kmod_module_versions_free_list(ml.list)
-            ml.list = NULL
-    versions = property(fget=_versions_get)
-
-    def insert(self, flags=0, extra_options=None, install_callback=None,
-               data=None, print_action_callback=None):
-        """
-        insert module to current tree. 
-        e.g.
-        km = kmod.Kmod()
-        tp = km.module_from_name("thinkpad_acpi")
-        tp.insert(extra_options='fan_control=1')
-        """
-        cdef char *opt = NULL
-        #cdef _libkmod_h.install_callback_t install = NULL
-        cdef int (*install)(
-            _libkmod_h.kmod_module *, _libkmod_h.const_char_ptr, void *)
-        install = NULL
-        cdef void *d = NULL
-        #cdef _libkmod_h.print_action_callback_t print_action = NULL
-        cdef void (*print_action)(
-            _libkmod_h.kmod_module *, _libkmod_h.bool,
-            _libkmod_h.const_char_ptr)
-        print_action = NULL
-        if extra_options:
-            opt = extra_options
-        # TODO: convert callbacks and data from Python object to C types
-        err = _libkmod_h.kmod_module_probe_insert_module(
-            self.module, flags, opt, install, d, print_action)
-        if err == -_errno.EEXIST:
-            raise _KmodError('Module already loaded')
-        elif err < 0:
-            raise _KmodError('Could not load module')
-
-    def remove(self, flags=0):
-        """
-        remove module from current tree
-        e.g.
-        km = kmod.Kmod()
-        tp = km.module_from_name("thinkpad_acpi")
-        tp.remove()
-        """
-        err = _libkmod_h.kmod_module_remove_module(self.module, flags)
-        if err < 0:
-            raise _KmodError('Could not remove module')
diff --git a/libkmod/python/kmod/version.py.in b/libkmod/python/kmod/version.py.in
deleted file mode 100644
index 4daa94d..0000000
--- a/libkmod/python/kmod/version.py.in
+++ /dev/null
@@ -1,17 +0,0 @@
-# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
-#
-# This file is part of python-kmod.
-#
-# python-kmod is free software: you can redistribute it and/or modify it under
-# the terms of the GNU Lesser General Public License version 2.1 as published
-# by the Free Software Foundation.
-#
-# python-kmod is distributed in the hope that it will be useful, but WITHOUT
-# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
-# details.
-#
-# You should have received a copy of the GNU Lesser General Public License
-# along with python-kmod.  If not, see <http://www.gnu.org/licenses/>.
-
-__version__ = '@VERSION@'
diff --git a/man/Makefile.am b/man/Makefile.am
index 11514d5..d62ff21 100644
--- a/man/Makefile.am
+++ b/man/Makefile.am
@@ -13,13 +13,26 @@ dist_man_MANS = $(MAN5) $(MAN8) $(MAN_STUB)
 modules.dep.bin.5: modules.dep.5
 endif
 
-EXTRA_DIST = $(MAN5:%.5=%.xml) $(MAN8:%.8=%.xml)
+EXTRA_DIST = $(MAN5:%.5=%.5.xml) $(MAN8:%.8=%.8.xml)
 CLEANFILES = $(dist_man_MANS)
 
-%.5 %.8: %.xml
-	$(AM_V_XSLT)$(XSLT) \
+define generate_manpage
+	$(AM_V_XSLT)if [ '$(distconfdir)' != '/lib' ] ; then \
+		sed -e 's|@DISTCONFDIR@|$(distconfdir)|g' $< ; \
+	else \
+		sed -e '/@DISTCONFDIR@/d' $< ; \
+	fi | \
+	sed -e 's|@MODULE_DIRECTORY@|$(module_directory)|g' | \
+	$(XSLT) \
 		-o $@ \
 		--nonet \
 		--stringparam man.output.quietly 1 \
 		--param funcsynopsis.style "'ansi'" \
-		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
+		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl -
+endef
+
+%.5: %.5.xml
+	$(generate_manpage)
+
+%.8: %.8.xml
+	$(generate_manpage)
diff --git a/man/depmod.xml b/man/depmod.8.xml
similarity index 91%
rename from man/depmod.xml
rename to man/depmod.8.xml
index ea0be27..fce2a4a 100644
--- a/man/depmod.xml
+++ b/man/depmod.8.xml
@@ -45,6 +45,7 @@
     <cmdsynopsis>
       <command>depmod</command>
       <arg><option>-b <replaceable>basedir</replaceable></option></arg>
+      <arg><option>-o <replaceable>outdir</replaceable></option></arg>
       <arg><option>-e</option></arg>
       <arg><option>-E <replaceable>Module.symvers</replaceable></option></arg>
       <arg><option>-F <replaceable>System.map</replaceable></option></arg>
@@ -79,7 +80,7 @@
     </para>
     <para> <command>depmod</command> creates a list of module dependencies by
       reading each module under
-      <filename>/lib/modules/</filename><replaceable>version</replaceable> and
+      <filename>@MODULE_DIRECTORY@/</filename><replaceable>version</replaceable> and
       determining what symbols it exports and what symbols it needs.  By
       default, this list is written to <filename>modules.dep</filename>, and a
       binary hashed version named <filename>modules.dep.bin</filename>, in the
@@ -140,7 +141,7 @@
         <listitem>
           <para>
             If your modules are not currently in the (normal) directory
-            <filename>/lib/modules/</filename><replaceable>version</replaceable>,
+            <filename>@MODULE_DIRECTORY@/</filename><replaceable>version</replaceable>,
             but in a staging area, you can specify a
             <replaceable>basedir</replaceable> which is prepended to the
             directory name.  This <replaceable>basedir</replaceable> is
@@ -151,6 +152,25 @@
           </para>
         </listitem>
       </varlistentry>
+      <varlistentry>
+        <term>
+          <option>-o <replaceable>outdir</replaceable></option>
+        </term>
+        <term>
+          <option>--outdir <replaceable>outdir</replaceable></option>
+        </term>
+        <listitem>
+          <para>
+            Set the output directory where depmod will store any generated file.
+            <replaceable>outdir</replaceable> serves as a root to that location,
+            similar to how <replaceable>basedir</replaceable> is used. Also this
+            setting takes precedence and if used together with
+            <replaceable>basedir</replaceable> it will result in the input being
+            that directory, but the output being the one set by
+            <replaceable>outdir</replaceable>.
+          </para>
+        </listitem>
+      </varlistentry>
       <varlistentry>
         <term>
           <option>-C</option>
diff --git a/man/depmod.d.xml b/man/depmod.d.5.xml
similarity index 94%
rename from man/depmod.d.xml
rename to man/depmod.d.5.xml
index 76548e9..b07e6a2 100644
--- a/man/depmod.d.xml
+++ b/man/depmod.d.5.xml
@@ -39,7 +39,8 @@
   </refnamediv>
 
   <refsynopsisdiv>
-    <para><filename>/usr/lib/depmod.d/*.conf</filename></para>
+    <para><filename>/lib/depmod.d/*.conf</filename></para>
+    <para><filename>@DISTCONFDIR@/depmod.d/*.conf</filename></para>
     <para><filename>/usr/local/lib/depmod.d/*.conf</filename></para>
     <para><filename>/run/depmod.d/*.conf</filename></para>
     <para><filename>/etc/depmod.d/*.conf</filename></para>
@@ -69,7 +70,7 @@
         </term>
         <listitem>
           <para>
-            This allows you to specify the order in which /lib/modules
+            This allows you to specify the order in which @MODULE_DIRECTORY@
             (or other configured module location) subdirectories will
             be processed by <command>depmod</command>. Directories are
             listed in order, with the highest priority given to the
@@ -100,7 +101,7 @@
             <command>depmod</command> command. It is possible to
             specify one kernel or all kernels using the * wildcard.
             <replaceable>modulesubdirectory</replaceable> is the
-            name of the subdirectory under /lib/modules (or other
+            name of the subdirectory under @MODULE_DIRECTORY@ (or other
             module location) where the target module is installed.
           </para>
           <para>
@@ -109,7 +110,7 @@
             specifying the following command: "override kmod * extra".
             This will ensure that any matching module name installed
             under the <command>extra</command> subdirectory within
-            /lib/modules (or other module location) will take priority
+            @MODULE_DIRECTORY@ (or other module location) will take priority
             over any likenamed module already provided by the kernel.
           </para>
         </listitem>
diff --git a/man/insmod.xml b/man/insmod.8.xml
similarity index 100%
rename from man/insmod.xml
rename to man/insmod.8.xml
diff --git a/man/kmod.xml b/man/kmod.8.xml
similarity index 100%
rename from man/kmod.xml
rename to man/kmod.8.xml
diff --git a/man/lsmod.xml b/man/lsmod.8.xml
similarity index 100%
rename from man/lsmod.xml
rename to man/lsmod.8.xml
diff --git a/man/modinfo.xml b/man/modinfo.8.xml
similarity index 98%
rename from man/modinfo.xml
rename to man/modinfo.8.xml
index 9fe0324..b6c4d60 100644
--- a/man/modinfo.xml
+++ b/man/modinfo.8.xml
@@ -54,7 +54,7 @@
       <command>modinfo</command> extracts information from the Linux Kernel
       modules given on the command line.  If the module name is not a filename,
       then the
-      <filename>/lib/modules/</filename><replaceable>version</replaceable>
+      <filename>@MODULE_DIRECTORY@/</filename><replaceable>version</replaceable>
       directory is searched, as is also done by
       <citerefentry><refentrytitle>modprobe</refentrytitle><manvolnum>8</manvolnum></citerefentry>
       when loading kernel modules.
diff --git a/man/modprobe.xml b/man/modprobe.8.xml
similarity index 98%
rename from man/modprobe.xml
rename to man/modprobe.8.xml
index db39c7a..4d1fd59 100644
--- a/man/modprobe.xml
+++ b/man/modprobe.8.xml
@@ -78,7 +78,7 @@
       is no difference between _ and - in module names (automatic
       underscore conversion is performed).
       <command>modprobe</command> looks in the module directory
-      <filename>/lib/modules/`uname -r`</filename> for all
+      <filename>@MODULE_DIRECTORY@/`uname -r`</filename> for all
       the modules and other files, except for the optional
       configuration files in the
       <filename>/etc/modprobe.d</filename> directory
@@ -115,6 +115,13 @@
       kernel (in addition to any options listed in the configuration
       file).
     </para>
+    <para>
+      When loading modules, <replaceable>modulename</replaceable> can also
+      be a path to the module. If the path is relative, it must
+      explicitly start with "./". Note that this may fail when using a
+      path to a module with dependencies not matching the installed depmod
+      database.
+    </para>
   </refsect1>
 
   <refsect1><title>OPTIONS</title>
diff --git a/man/modprobe.d.xml b/man/modprobe.d.5.xml
similarity index 99%
rename from man/modprobe.d.xml
rename to man/modprobe.d.5.xml
index 0ab3e91..2bf6537 100644
--- a/man/modprobe.d.xml
+++ b/man/modprobe.d.5.xml
@@ -41,6 +41,7 @@
 
   <refsynopsisdiv>
     <para><filename>/lib/modprobe.d/*.conf</filename></para>
+    <para><filename>@DISTCONFDIR@/modprobe.d/*.conf</filename></para>
     <para><filename>/usr/local/lib/modprobe.d/*.conf</filename></para>
     <para><filename>/run/modprobe.d/*.conf</filename></para>
     <para><filename>/etc/modprobe.d/*.conf</filename></para>
diff --git a/man/modules.dep.xml b/man/modules.dep.5.xml
similarity index 91%
rename from man/modules.dep.xml
rename to man/modules.dep.5.xml
index ed63369..8ef6d8b 100644
--- a/man/modules.dep.xml
+++ b/man/modules.dep.5.xml
@@ -34,8 +34,8 @@
   </refnamediv>
 
   <refsynopsisdiv>
-    <para><filename>/lib/modules/modules.dep</filename></para>
-    <para><filename>/lib/modules/modules.dep.bin</filename></para>
+    <para><filename>@MODULE_DIRECTORY@/modules.dep</filename></para>
+    <para><filename>@MODULE_DIRECTORY@/modules.dep.bin</filename></para>
   </refsynopsisdiv>
 
   <refsect1><title>DESCRIPTION</title>
@@ -43,7 +43,7 @@
       <filename>modules.dep.bin</filename> is a binary file generated by
       <command>depmod</command> listing the dependencies for
       every module in the directories under
-      <filename>/lib/modules/</filename><replaceable>version</replaceable>.
+      <filename>@MODULE_DIRECTORY@/</filename><replaceable>version</replaceable>.
       It is used by kmod tools such as <command>modprobe</command> and
       libkmod.
     </para>
diff --git a/man/rmmod.xml b/man/rmmod.8.xml
similarity index 98%
rename from man/rmmod.xml
rename to man/rmmod.8.xml
index e7c7e5f..67bcbed 100644
--- a/man/rmmod.xml
+++ b/man/rmmod.8.xml
@@ -52,7 +52,8 @@
       want to use
       <citerefentry>
         <refentrytitle>modprobe</refentrytitle><manvolnum>8</manvolnum>
-      </citerefentry> with the <option>-r</option> option instead.
+      </citerefentry> with the <option>-r</option> option instead
+      since it removes unused dependent modules as well.
     </para>
   </refsect1>
 
diff --git a/port-gnu/elf.h b/port-gnu/elf.h
deleted file mode 100644
index 6aae290..0000000
--- a/port-gnu/elf.h
+++ /dev/null
@@ -1,3558 +0,0 @@
-/* This file defines standard ELF types, structures, and macros.
-   Copyright (C) 1995-2015 Free Software Foundation, Inc.
-   This file is part of the GNU C Library.
-
-   The GNU C Library is free software; you can redistribute it and/or
-   modify it under the terms of the GNU Lesser General Public
-   License as published by the Free Software Foundation; either
-   version 2.1 of the License, or (at your option) any later version.
-
-   The GNU C Library is distributed in the hope that it will be useful,
-   but WITHOUT ANY WARRANTY; without even the implied warranty of
-   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-   Lesser General Public License for more details.
-
-   You should have received a copy of the GNU Lesser General Public
-   License along with the GNU C Library; if not, see
-   <http://www.gnu.org/licenses/>.  */
-
-#ifndef _ELF_H
-#define	_ELF_H 1
-
-#include <sys/cdefs.h>
-
-__BEGIN_DECLS
-
-/* Standard ELF types.  */
-
-#include <stdint.h>
-
-/* Type for a 16-bit quantity.  */
-typedef uint16_t Elf32_Half;
-typedef uint16_t Elf64_Half;
-
-/* Types for signed and unsigned 32-bit quantities.  */
-typedef uint32_t Elf32_Word;
-typedef	int32_t  Elf32_Sword;
-typedef uint32_t Elf64_Word;
-typedef	int32_t  Elf64_Sword;
-
-/* Types for signed and unsigned 64-bit quantities.  */
-typedef uint64_t Elf32_Xword;
-typedef	int64_t  Elf32_Sxword;
-typedef uint64_t Elf64_Xword;
-typedef	int64_t  Elf64_Sxword;
-
-/* Type of addresses.  */
-typedef uint32_t Elf32_Addr;
-typedef uint64_t Elf64_Addr;
-
-/* Type of file offsets.  */
-typedef uint32_t Elf32_Off;
-typedef uint64_t Elf64_Off;
-
-/* Type for section indices, which are 16-bit quantities.  */
-typedef uint16_t Elf32_Section;
-typedef uint16_t Elf64_Section;
-
-/* Type for version symbol information.  */
-typedef Elf32_Half Elf32_Versym;
-typedef Elf64_Half Elf64_Versym;
-
-
-/* The ELF file header.  This appears at the start of every ELF file.  */
-
-#define EI_NIDENT (16)
-
-typedef struct
-{
-  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
-  Elf32_Half	e_type;			/* Object file type */
-  Elf32_Half	e_machine;		/* Architecture */
-  Elf32_Word	e_version;		/* Object file version */
-  Elf32_Addr	e_entry;		/* Entry point virtual address */
-  Elf32_Off	e_phoff;		/* Program header table file offset */
-  Elf32_Off	e_shoff;		/* Section header table file offset */
-  Elf32_Word	e_flags;		/* Processor-specific flags */
-  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
-  Elf32_Half	e_phentsize;		/* Program header table entry size */
-  Elf32_Half	e_phnum;		/* Program header table entry count */
-  Elf32_Half	e_shentsize;		/* Section header table entry size */
-  Elf32_Half	e_shnum;		/* Section header table entry count */
-  Elf32_Half	e_shstrndx;		/* Section header string table index */
-} Elf32_Ehdr;
-
-typedef struct
-{
-  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
-  Elf64_Half	e_type;			/* Object file type */
-  Elf64_Half	e_machine;		/* Architecture */
-  Elf64_Word	e_version;		/* Object file version */
-  Elf64_Addr	e_entry;		/* Entry point virtual address */
-  Elf64_Off	e_phoff;		/* Program header table file offset */
-  Elf64_Off	e_shoff;		/* Section header table file offset */
-  Elf64_Word	e_flags;		/* Processor-specific flags */
-  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
-  Elf64_Half	e_phentsize;		/* Program header table entry size */
-  Elf64_Half	e_phnum;		/* Program header table entry count */
-  Elf64_Half	e_shentsize;		/* Section header table entry size */
-  Elf64_Half	e_shnum;		/* Section header table entry count */
-  Elf64_Half	e_shstrndx;		/* Section header string table index */
-} Elf64_Ehdr;
-
-/* Fields in the e_ident array.  The EI_* macros are indices into the
-   array.  The macros under each EI_* macro are the values the byte
-   may have.  */
-
-#define EI_MAG0		0		/* File identification byte 0 index */
-#define ELFMAG0		0x7f		/* Magic number byte 0 */
-
-#define EI_MAG1		1		/* File identification byte 1 index */
-#define ELFMAG1		'E'		/* Magic number byte 1 */
-
-#define EI_MAG2		2		/* File identification byte 2 index */
-#define ELFMAG2		'L'		/* Magic number byte 2 */
-
-#define EI_MAG3		3		/* File identification byte 3 index */
-#define ELFMAG3		'F'		/* Magic number byte 3 */
-
-/* Conglomeration of the identification bytes, for easy testing as a word.  */
-#define	ELFMAG		"\177ELF"
-#define	SELFMAG		4
-
-#define EI_CLASS	4		/* File class byte index */
-#define ELFCLASSNONE	0		/* Invalid class */
-#define ELFCLASS32	1		/* 32-bit objects */
-#define ELFCLASS64	2		/* 64-bit objects */
-#define ELFCLASSNUM	3
-
-#define EI_DATA		5		/* Data encoding byte index */
-#define ELFDATANONE	0		/* Invalid data encoding */
-#define ELFDATA2LSB	1		/* 2's complement, little endian */
-#define ELFDATA2MSB	2		/* 2's complement, big endian */
-#define ELFDATANUM	3
-
-#define EI_VERSION	6		/* File version byte index */
-					/* Value must be EV_CURRENT */
-
-#define EI_OSABI	7		/* OS ABI identification */
-#define ELFOSABI_NONE		0	/* UNIX System V ABI */
-#define ELFOSABI_SYSV		0	/* Alias.  */
-#define ELFOSABI_HPUX		1	/* HP-UX */
-#define ELFOSABI_NETBSD		2	/* NetBSD.  */
-#define ELFOSABI_GNU		3	/* Object uses GNU ELF extensions.  */
-#define ELFOSABI_LINUX		ELFOSABI_GNU /* Compatibility alias.  */
-#define ELFOSABI_SOLARIS	6	/* Sun Solaris.  */
-#define ELFOSABI_AIX		7	/* IBM AIX.  */
-#define ELFOSABI_IRIX		8	/* SGI Irix.  */
-#define ELFOSABI_FREEBSD	9	/* FreeBSD.  */
-#define ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX.  */
-#define ELFOSABI_MODESTO	11	/* Novell Modesto.  */
-#define ELFOSABI_OPENBSD	12	/* OpenBSD.  */
-#define ELFOSABI_ARM_AEABI	64	/* ARM EABI */
-#define ELFOSABI_ARM		97	/* ARM */
-#define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */
-
-#define EI_ABIVERSION	8		/* ABI version */
-
-#define EI_PAD		9		/* Byte index of padding bytes */
-
-/* Legal values for e_type (object file type).  */
-
-#define ET_NONE		0		/* No file type */
-#define ET_REL		1		/* Relocatable file */
-#define ET_EXEC		2		/* Executable file */
-#define ET_DYN		3		/* Shared object file */
-#define ET_CORE		4		/* Core file */
-#define	ET_NUM		5		/* Number of defined types */
-#define ET_LOOS		0xfe00		/* OS-specific range start */
-#define ET_HIOS		0xfeff		/* OS-specific range end */
-#define ET_LOPROC	0xff00		/* Processor-specific range start */
-#define ET_HIPROC	0xffff		/* Processor-specific range end */
-
-/* Legal values for e_machine (architecture).  */
-
-#define EM_NONE		 0		/* No machine */
-#define EM_M32		 1		/* AT&T WE 32100 */
-#define EM_SPARC	 2		/* SUN SPARC */
-#define EM_386		 3		/* Intel 80386 */
-#define EM_68K		 4		/* Motorola m68k family */
-#define EM_88K		 5		/* Motorola m88k family */
-#define EM_860		 7		/* Intel 80860 */
-#define EM_MIPS		 8		/* MIPS R3000 big-endian */
-#define EM_S370		 9		/* IBM System/370 */
-#define EM_MIPS_RS3_LE	10		/* MIPS R3000 little-endian */
-
-#define EM_PARISC	15		/* HPPA */
-#define EM_VPP500	17		/* Fujitsu VPP500 */
-#define EM_SPARC32PLUS	18		/* Sun's "v8plus" */
-#define EM_960		19		/* Intel 80960 */
-#define EM_PPC		20		/* PowerPC */
-#define EM_PPC64	21		/* PowerPC 64-bit */
-#define EM_S390		22		/* IBM S390 */
-
-#define EM_V800		36		/* NEC V800 series */
-#define EM_FR20		37		/* Fujitsu FR20 */
-#define EM_RH32		38		/* TRW RH-32 */
-#define EM_RCE		39		/* Motorola RCE */
-#define EM_ARM		40		/* ARM */
-#define EM_FAKE_ALPHA	41		/* Digital Alpha */
-#define EM_SH		42		/* Hitachi SH */
-#define EM_SPARCV9	43		/* SPARC v9 64-bit */
-#define EM_TRICORE	44		/* Siemens Tricore */
-#define EM_ARC		45		/* Argonaut RISC Core */
-#define EM_H8_300	46		/* Hitachi H8/300 */
-#define EM_H8_300H	47		/* Hitachi H8/300H */
-#define EM_H8S		48		/* Hitachi H8S */
-#define EM_H8_500	49		/* Hitachi H8/500 */
-#define EM_IA_64	50		/* Intel Merced */
-#define EM_MIPS_X	51		/* Stanford MIPS-X */
-#define EM_COLDFIRE	52		/* Motorola Coldfire */
-#define EM_68HC12	53		/* Motorola M68HC12 */
-#define EM_MMA		54		/* Fujitsu MMA Multimedia Accelerator*/
-#define EM_PCP		55		/* Siemens PCP */
-#define EM_NCPU		56		/* Sony nCPU embeeded RISC */
-#define EM_NDR1		57		/* Denso NDR1 microprocessor */
-#define EM_STARCORE	58		/* Motorola Start*Core processor */
-#define EM_ME16		59		/* Toyota ME16 processor */
-#define EM_ST100	60		/* STMicroelectronic ST100 processor */
-#define EM_TINYJ	61		/* Advanced Logic Corp. Tinyj emb.fam*/
-#define EM_X86_64	62		/* AMD x86-64 architecture */
-#define EM_PDSP		63		/* Sony DSP Processor */
-
-#define EM_FX66		66		/* Siemens FX66 microcontroller */
-#define EM_ST9PLUS	67		/* STMicroelectronics ST9+ 8/16 mc */
-#define EM_ST7		68		/* STmicroelectronics ST7 8 bit mc */
-#define EM_68HC16	69		/* Motorola MC68HC16 microcontroller */
-#define EM_68HC11	70		/* Motorola MC68HC11 microcontroller */
-#define EM_68HC08	71		/* Motorola MC68HC08 microcontroller */
-#define EM_68HC05	72		/* Motorola MC68HC05 microcontroller */
-#define EM_SVX		73		/* Silicon Graphics SVx */
-#define EM_ST19		74		/* STMicroelectronics ST19 8 bit mc */
-#define EM_VAX		75		/* Digital VAX */
-#define EM_CRIS		76		/* Axis Communications 32-bit embedded processor */
-#define EM_JAVELIN	77		/* Infineon Technologies 32-bit embedded processor */
-#define EM_FIREPATH	78		/* Element 14 64-bit DSP Processor */
-#define EM_ZSP		79		/* LSI Logic 16-bit DSP Processor */
-#define EM_MMIX		80		/* Donald Knuth's educational 64-bit processor */
-#define EM_HUANY	81		/* Harvard University machine-independent object files */
-#define EM_PRISM	82		/* SiTera Prism */
-#define EM_AVR		83		/* Atmel AVR 8-bit microcontroller */
-#define EM_FR30		84		/* Fujitsu FR30 */
-#define EM_D10V		85		/* Mitsubishi D10V */
-#define EM_D30V		86		/* Mitsubishi D30V */
-#define EM_V850		87		/* NEC v850 */
-#define EM_M32R		88		/* Mitsubishi M32R */
-#define EM_MN10300	89		/* Matsushita MN10300 */
-#define EM_MN10200	90		/* Matsushita MN10200 */
-#define EM_PJ		91		/* picoJava */
-#define EM_OPENRISC	92		/* OpenRISC 32-bit embedded processor */
-#define EM_ARC_A5	93		/* ARC Cores Tangent-A5 */
-#define EM_XTENSA	94		/* Tensilica Xtensa Architecture */
-#define EM_ALTERA_NIOS2 113		/* Altera Nios II */
-#define EM_AARCH64	183		/* ARM AARCH64 */
-#define EM_TILEPRO	188		/* Tilera TILEPro */
-#define EM_MICROBLAZE	189		/* Xilinx MicroBlaze */
-#define EM_TILEGX	191		/* Tilera TILE-Gx */
-#define EM_NUM		192
-
-/* If it is necessary to assign new unofficial EM_* values, please
-   pick large random numbers (0x8523, 0xa7f2, etc.) to minimize the
-   chances of collision with official or non-GNU unofficial values.  */
-
-#define EM_ALPHA	0x9026
-
-/* Legal values for e_version (version).  */
-
-#define EV_NONE		0		/* Invalid ELF version */
-#define EV_CURRENT	1		/* Current version */
-#define EV_NUM		2
-
-/* Section header.  */
-
-typedef struct
-{
-  Elf32_Word	sh_name;		/* Section name (string tbl index) */
-  Elf32_Word	sh_type;		/* Section type */
-  Elf32_Word	sh_flags;		/* Section flags */
-  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
-  Elf32_Off	sh_offset;		/* Section file offset */
-  Elf32_Word	sh_size;		/* Section size in bytes */
-  Elf32_Word	sh_link;		/* Link to another section */
-  Elf32_Word	sh_info;		/* Additional section information */
-  Elf32_Word	sh_addralign;		/* Section alignment */
-  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
-} Elf32_Shdr;
-
-typedef struct
-{
-  Elf64_Word	sh_name;		/* Section name (string tbl index) */
-  Elf64_Word	sh_type;		/* Section type */
-  Elf64_Xword	sh_flags;		/* Section flags */
-  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
-  Elf64_Off	sh_offset;		/* Section file offset */
-  Elf64_Xword	sh_size;		/* Section size in bytes */
-  Elf64_Word	sh_link;		/* Link to another section */
-  Elf64_Word	sh_info;		/* Additional section information */
-  Elf64_Xword	sh_addralign;		/* Section alignment */
-  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
-} Elf64_Shdr;
-
-/* Special section indices.  */
-
-#define SHN_UNDEF	0		/* Undefined section */
-#define SHN_LORESERVE	0xff00		/* Start of reserved indices */
-#define SHN_LOPROC	0xff00		/* Start of processor-specific */
-#define SHN_BEFORE	0xff00		/* Order section before all others
-					   (Solaris).  */
-#define SHN_AFTER	0xff01		/* Order section after all others
-					   (Solaris).  */
-#define SHN_HIPROC	0xff1f		/* End of processor-specific */
-#define SHN_LOOS	0xff20		/* Start of OS-specific */
-#define SHN_HIOS	0xff3f		/* End of OS-specific */
-#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
-#define SHN_COMMON	0xfff2		/* Associated symbol is common */
-#define SHN_XINDEX	0xffff		/* Index is in extra table.  */
-#define SHN_HIRESERVE	0xffff		/* End of reserved indices */
-
-/* Legal values for sh_type (section type).  */
-
-#define SHT_NULL	  0		/* Section header table entry unused */
-#define SHT_PROGBITS	  1		/* Program data */
-#define SHT_SYMTAB	  2		/* Symbol table */
-#define SHT_STRTAB	  3		/* String table */
-#define SHT_RELA	  4		/* Relocation entries with addends */
-#define SHT_HASH	  5		/* Symbol hash table */
-#define SHT_DYNAMIC	  6		/* Dynamic linking information */
-#define SHT_NOTE	  7		/* Notes */
-#define SHT_NOBITS	  8		/* Program space with no data (bss) */
-#define SHT_REL		  9		/* Relocation entries, no addends */
-#define SHT_SHLIB	  10		/* Reserved */
-#define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
-#define SHT_INIT_ARRAY	  14		/* Array of constructors */
-#define SHT_FINI_ARRAY	  15		/* Array of destructors */
-#define SHT_PREINIT_ARRAY 16		/* Array of pre-constructors */
-#define SHT_GROUP	  17		/* Section group */
-#define SHT_SYMTAB_SHNDX  18		/* Extended section indeces */
-#define	SHT_NUM		  19		/* Number of defined types.  */
-#define SHT_LOOS	  0x60000000	/* Start OS-specific.  */
-#define SHT_GNU_ATTRIBUTES 0x6ffffff5	/* Object attributes.  */
-#define SHT_GNU_HASH	  0x6ffffff6	/* GNU-style hash table.  */
-#define SHT_GNU_LIBLIST	  0x6ffffff7	/* Prelink library list */
-#define SHT_CHECKSUM	  0x6ffffff8	/* Checksum for DSO content.  */
-#define SHT_LOSUNW	  0x6ffffffa	/* Sun-specific low bound.  */
-#define SHT_SUNW_move	  0x6ffffffa
-#define SHT_SUNW_COMDAT   0x6ffffffb
-#define SHT_SUNW_syminfo  0x6ffffffc
-#define SHT_GNU_verdef	  0x6ffffffd	/* Version definition section.  */
-#define SHT_GNU_verneed	  0x6ffffffe	/* Version needs section.  */
-#define SHT_GNU_versym	  0x6fffffff	/* Version symbol table.  */
-#define SHT_HISUNW	  0x6fffffff	/* Sun-specific high bound.  */
-#define SHT_HIOS	  0x6fffffff	/* End OS-specific type */
-#define SHT_LOPROC	  0x70000000	/* Start of processor-specific */
-#define SHT_HIPROC	  0x7fffffff	/* End of processor-specific */
-#define SHT_LOUSER	  0x80000000	/* Start of application-specific */
-#define SHT_HIUSER	  0x8fffffff	/* End of application-specific */
-
-/* Legal values for sh_flags (section flags).  */
-
-#define SHF_WRITE	     (1 << 0)	/* Writable */
-#define SHF_ALLOC	     (1 << 1)	/* Occupies memory during execution */
-#define SHF_EXECINSTR	     (1 << 2)	/* Executable */
-#define SHF_MERGE	     (1 << 4)	/* Might be merged */
-#define SHF_STRINGS	     (1 << 5)	/* Contains nul-terminated strings */
-#define SHF_INFO_LINK	     (1 << 6)	/* `sh_info' contains SHT index */
-#define SHF_LINK_ORDER	     (1 << 7)	/* Preserve order after combining */
-#define SHF_OS_NONCONFORMING (1 << 8)	/* Non-standard OS specific handling
-					   required */
-#define SHF_GROUP	     (1 << 9)	/* Section is member of a group.  */
-#define SHF_TLS		     (1 << 10)	/* Section hold thread-local data.  */
-#define SHF_COMPRESSED	     (1 << 11)	/* Section with compressed data. */
-#define SHF_MASKOS	     0x0ff00000	/* OS-specific.  */
-#define SHF_MASKPROC	     0xf0000000	/* Processor-specific */
-#define SHF_ORDERED	     (1 << 30)	/* Special ordering requirement
-					   (Solaris).  */
-#define SHF_EXCLUDE	     (1U << 31)	/* Section is excluded unless
-					   referenced or allocated (Solaris).*/
-
-/* Section compression header.  Used when SHF_COMPRESSED is set.  */
-
-typedef struct
-{
-  Elf32_Word	ch_type;	/* Compression format.  */
-  Elf32_Word	ch_size;	/* Uncompressed data size.  */
-  Elf32_Word	ch_addralign;	/* Uncompressed data alignment.  */
-} Elf32_Chdr;
-
-typedef struct
-{
-  Elf64_Word	ch_type;	/* Compression format.  */
-  Elf64_Word	ch_reserved;
-  Elf64_Xword	ch_size;	/* Uncompressed data size.  */
-  Elf64_Xword	ch_addralign;	/* Uncompressed data alignment.  */
-} Elf64_Chdr;
-
-/* Legal values for ch_type (compression algorithm).  */
-#define ELFCOMPRESS_ZLIB	1	   /* ZLIB/DEFLATE algorithm.  */
-#define ELFCOMPRESS_LOOS	0x60000000 /* Start of OS-specific.  */
-#define ELFCOMPRESS_HIOS	0x6fffffff /* End of OS-specific.  */
-#define ELFCOMPRESS_LOPROC	0x70000000 /* Start of processor-specific.  */
-#define ELFCOMPRESS_HIPROC	0x7fffffff /* End of processor-specific.  */
-
-/* Section group handling.  */
-#define GRP_COMDAT	0x1		/* Mark group as COMDAT.  */
-
-/* Symbol table entry.  */
-
-typedef struct
-{
-  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
-  Elf32_Addr	st_value;		/* Symbol value */
-  Elf32_Word	st_size;		/* Symbol size */
-  unsigned char	st_info;		/* Symbol type and binding */
-  unsigned char	st_other;		/* Symbol visibility */
-  Elf32_Section	st_shndx;		/* Section index */
-} Elf32_Sym;
-
-typedef struct
-{
-  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
-  unsigned char	st_info;		/* Symbol type and binding */
-  unsigned char st_other;		/* Symbol visibility */
-  Elf64_Section	st_shndx;		/* Section index */
-  Elf64_Addr	st_value;		/* Symbol value */
-  Elf64_Xword	st_size;		/* Symbol size */
-} Elf64_Sym;
-
-/* The syminfo section if available contains additional information about
-   every dynamic symbol.  */
-
-typedef struct
-{
-  Elf32_Half si_boundto;		/* Direct bindings, symbol bound to */
-  Elf32_Half si_flags;			/* Per symbol flags */
-} Elf32_Syminfo;
-
-typedef struct
-{
-  Elf64_Half si_boundto;		/* Direct bindings, symbol bound to */
-  Elf64_Half si_flags;			/* Per symbol flags */
-} Elf64_Syminfo;
-
-/* Possible values for si_boundto.  */
-#define SYMINFO_BT_SELF		0xffff	/* Symbol bound to self */
-#define SYMINFO_BT_PARENT	0xfffe	/* Symbol bound to parent */
-#define SYMINFO_BT_LOWRESERVE	0xff00	/* Beginning of reserved entries */
-
-/* Possible bitmasks for si_flags.  */
-#define SYMINFO_FLG_DIRECT	0x0001	/* Direct bound symbol */
-#define SYMINFO_FLG_PASSTHRU	0x0002	/* Pass-thru symbol for translator */
-#define SYMINFO_FLG_COPY	0x0004	/* Symbol is a copy-reloc */
-#define SYMINFO_FLG_LAZYLOAD	0x0008	/* Symbol bound to object to be lazy
-					   loaded */
-/* Syminfo version values.  */
-#define SYMINFO_NONE		0
-#define SYMINFO_CURRENT		1
-#define SYMINFO_NUM		2
-
-
-/* How to extract and insert information held in the st_info field.  */
-
-#define ELF32_ST_BIND(val)		(((unsigned char) (val)) >> 4)
-#define ELF32_ST_TYPE(val)		((val) & 0xf)
-#define ELF32_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))
-
-/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
-#define ELF64_ST_BIND(val)		ELF32_ST_BIND (val)
-#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
-#define ELF64_ST_INFO(bind, type)	ELF32_ST_INFO ((bind), (type))
-
-/* Legal values for ST_BIND subfield of st_info (symbol binding).  */
-
-#define STB_LOCAL	0		/* Local symbol */
-#define STB_GLOBAL	1		/* Global symbol */
-#define STB_WEAK	2		/* Weak symbol */
-#define	STB_NUM		3		/* Number of defined types.  */
-#define STB_LOOS	10		/* Start of OS-specific */
-#define STB_GNU_UNIQUE	10		/* Unique symbol.  */
-#define STB_HIOS	12		/* End of OS-specific */
-#define STB_LOPROC	13		/* Start of processor-specific */
-#define STB_HIPROC	15		/* End of processor-specific */
-
-/* Legal values for ST_TYPE subfield of st_info (symbol type).  */
-
-#define STT_NOTYPE	0		/* Symbol type is unspecified */
-#define STT_OBJECT	1		/* Symbol is a data object */
-#define STT_FUNC	2		/* Symbol is a code object */
-#define STT_SECTION	3		/* Symbol associated with a section */
-#define STT_FILE	4		/* Symbol's name is file name */
-#define STT_COMMON	5		/* Symbol is a common data object */
-#define STT_TLS		6		/* Symbol is thread-local data object*/
-#define	STT_NUM		7		/* Number of defined types.  */
-#define STT_LOOS	10		/* Start of OS-specific */
-#define STT_GNU_IFUNC	10		/* Symbol is indirect code object */
-#define STT_HIOS	12		/* End of OS-specific */
-#define STT_LOPROC	13		/* Start of processor-specific */
-#define STT_HIPROC	15		/* End of processor-specific */
-
-
-/* Symbol table indices are found in the hash buckets and chain table
-   of a symbol hash table section.  This special index value indicates
-   the end of a chain, meaning no further symbols are found in that bucket.  */
-
-#define STN_UNDEF	0		/* End of a chain.  */
-
-
-/* How to extract and insert information held in the st_other field.  */
-
-#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
-
-/* For ELF64 the definitions are the same.  */
-#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)
-
-/* Symbol visibility specification encoded in the st_other field.  */
-#define STV_DEFAULT	0		/* Default symbol visibility rules */
-#define STV_INTERNAL	1		/* Processor specific hidden class */
-#define STV_HIDDEN	2		/* Sym unavailable in other modules */
-#define STV_PROTECTED	3		/* Not preemptible, not exported */
-
-
-/* Relocation table entry without addend (in section of type SHT_REL).  */
-
-typedef struct
-{
-  Elf32_Addr	r_offset;		/* Address */
-  Elf32_Word	r_info;			/* Relocation type and symbol index */
-} Elf32_Rel;
-
-/* I have seen two different definitions of the Elf64_Rel and
-   Elf64_Rela structures, so we'll leave them out until Novell (or
-   whoever) gets their act together.  */
-/* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */
-
-typedef struct
-{
-  Elf64_Addr	r_offset;		/* Address */
-  Elf64_Xword	r_info;			/* Relocation type and symbol index */
-} Elf64_Rel;
-
-/* Relocation table entry with addend (in section of type SHT_RELA).  */
-
-typedef struct
-{
-  Elf32_Addr	r_offset;		/* Address */
-  Elf32_Word	r_info;			/* Relocation type and symbol index */
-  Elf32_Sword	r_addend;		/* Addend */
-} Elf32_Rela;
-
-typedef struct
-{
-  Elf64_Addr	r_offset;		/* Address */
-  Elf64_Xword	r_info;			/* Relocation type and symbol index */
-  Elf64_Sxword	r_addend;		/* Addend */
-} Elf64_Rela;
-
-/* How to extract and insert information held in the r_info field.  */
-
-#define ELF32_R_SYM(val)		((val) >> 8)
-#define ELF32_R_TYPE(val)		((val) & 0xff)
-#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))
-
-#define ELF64_R_SYM(i)			((i) >> 32)
-#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
-#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))
-
-/* Program segment header.  */
-
-typedef struct
-{
-  Elf32_Word	p_type;			/* Segment type */
-  Elf32_Off	p_offset;		/* Segment file offset */
-  Elf32_Addr	p_vaddr;		/* Segment virtual address */
-  Elf32_Addr	p_paddr;		/* Segment physical address */
-  Elf32_Word	p_filesz;		/* Segment size in file */
-  Elf32_Word	p_memsz;		/* Segment size in memory */
-  Elf32_Word	p_flags;		/* Segment flags */
-  Elf32_Word	p_align;		/* Segment alignment */
-} Elf32_Phdr;
-
-typedef struct
-{
-  Elf64_Word	p_type;			/* Segment type */
-  Elf64_Word	p_flags;		/* Segment flags */
-  Elf64_Off	p_offset;		/* Segment file offset */
-  Elf64_Addr	p_vaddr;		/* Segment virtual address */
-  Elf64_Addr	p_paddr;		/* Segment physical address */
-  Elf64_Xword	p_filesz;		/* Segment size in file */
-  Elf64_Xword	p_memsz;		/* Segment size in memory */
-  Elf64_Xword	p_align;		/* Segment alignment */
-} Elf64_Phdr;
-
-/* Special value for e_phnum.  This indicates that the real number of
-   program headers is too large to fit into e_phnum.  Instead the real
-   value is in the field sh_info of section 0.  */
-
-#define PN_XNUM		0xffff
-
-/* Legal values for p_type (segment type).  */
-
-#define	PT_NULL		0		/* Program header table entry unused */
-#define PT_LOAD		1		/* Loadable program segment */
-#define PT_DYNAMIC	2		/* Dynamic linking information */
-#define PT_INTERP	3		/* Program interpreter */
-#define PT_NOTE		4		/* Auxiliary information */
-#define PT_SHLIB	5		/* Reserved */
-#define PT_PHDR		6		/* Entry for header table itself */
-#define PT_TLS		7		/* Thread-local storage segment */
-#define	PT_NUM		8		/* Number of defined types */
-#define PT_LOOS		0x60000000	/* Start of OS-specific */
-#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
-#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
-#define PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */
-#define PT_LOSUNW	0x6ffffffa
-#define PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment */
-#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
-#define PT_HISUNW	0x6fffffff
-#define PT_HIOS		0x6fffffff	/* End of OS-specific */
-#define PT_LOPROC	0x70000000	/* Start of processor-specific */
-#define PT_HIPROC	0x7fffffff	/* End of processor-specific */
-
-/* Legal values for p_flags (segment flags).  */
-
-#define PF_X		(1 << 0)	/* Segment is executable */
-#define PF_W		(1 << 1)	/* Segment is writable */
-#define PF_R		(1 << 2)	/* Segment is readable */
-#define PF_MASKOS	0x0ff00000	/* OS-specific */
-#define PF_MASKPROC	0xf0000000	/* Processor-specific */
-
-/* Legal values for note segment descriptor types for core files. */
-
-#define NT_PRSTATUS	1		/* Contains copy of prstatus struct */
-#define NT_FPREGSET	2		/* Contains copy of fpregset struct */
-#define NT_PRPSINFO	3		/* Contains copy of prpsinfo struct */
-#define NT_PRXREG	4		/* Contains copy of prxregset struct */
-#define NT_TASKSTRUCT	4		/* Contains copy of task structure */
-#define NT_PLATFORM	5		/* String from sysinfo(SI_PLATFORM) */
-#define NT_AUXV		6		/* Contains copy of auxv array */
-#define NT_GWINDOWS	7		/* Contains copy of gwindows struct */
-#define NT_ASRS		8		/* Contains copy of asrset struct */
-#define NT_PSTATUS	10		/* Contains copy of pstatus struct */
-#define NT_PSINFO	13		/* Contains copy of psinfo struct */
-#define NT_PRCRED	14		/* Contains copy of prcred struct */
-#define NT_UTSNAME	15		/* Contains copy of utsname struct */
-#define NT_LWPSTATUS	16		/* Contains copy of lwpstatus struct */
-#define NT_LWPSINFO	17		/* Contains copy of lwpinfo struct */
-#define NT_PRFPXREG	20		/* Contains copy of fprxregset struct */
-#define NT_SIGINFO	0x53494749	/* Contains copy of siginfo_t,
-					   size might increase */
-#define NT_FILE		0x46494c45	/* Contains information about mapped
-					   files */
-#define NT_PRXFPREG	0x46e62b7f	/* Contains copy of user_fxsr_struct */
-#define NT_PPC_VMX	0x100		/* PowerPC Altivec/VMX registers */
-#define NT_PPC_SPE	0x101		/* PowerPC SPE/EVR registers */
-#define NT_PPC_VSX	0x102		/* PowerPC VSX registers */
-#define NT_386_TLS	0x200		/* i386 TLS slots (struct user_desc) */
-#define NT_386_IOPERM	0x201		/* x86 io permission bitmap (1=deny) */
-#define NT_X86_XSTATE	0x202		/* x86 extended state using xsave */
-#define NT_S390_HIGH_GPRS	0x300	/* s390 upper register halves */
-#define NT_S390_TIMER	0x301		/* s390 timer register */
-#define NT_S390_TODCMP	0x302		/* s390 TOD clock comparator register */
-#define NT_S390_TODPREG	0x303		/* s390 TOD programmable register */
-#define NT_S390_CTRS	0x304		/* s390 control registers */
-#define NT_S390_PREFIX	0x305		/* s390 prefix register */
-#define NT_S390_LAST_BREAK	0x306	/* s390 breaking event address */
-#define NT_S390_SYSTEM_CALL	0x307	/* s390 system call restart data */
-#define NT_S390_TDB	0x308		/* s390 transaction diagnostic block */
-#define NT_ARM_VFP	0x400		/* ARM VFP/NEON registers */
-#define NT_ARM_TLS	0x401		/* ARM TLS register */
-#define NT_ARM_HW_BREAK	0x402		/* ARM hardware breakpoint registers */
-#define NT_ARM_HW_WATCH	0x403		/* ARM hardware watchpoint registers */
-
-/* Legal values for the note segment descriptor types for object files.  */
-
-#define NT_VERSION	1		/* Contains a version string.  */
-
-
-/* Dynamic section entry.  */
-
-typedef struct
-{
-  Elf32_Sword	d_tag;			/* Dynamic entry type */
-  union
-    {
-      Elf32_Word d_val;			/* Integer value */
-      Elf32_Addr d_ptr;			/* Address value */
-    } d_un;
-} Elf32_Dyn;
-
-typedef struct
-{
-  Elf64_Sxword	d_tag;			/* Dynamic entry type */
-  union
-    {
-      Elf64_Xword d_val;		/* Integer value */
-      Elf64_Addr d_ptr;			/* Address value */
-    } d_un;
-} Elf64_Dyn;
-
-/* Legal values for d_tag (dynamic entry type).  */
-
-#define DT_NULL		0		/* Marks end of dynamic section */
-#define DT_NEEDED	1		/* Name of needed library */
-#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
-#define DT_PLTGOT	3		/* Processor defined value */
-#define DT_HASH		4		/* Address of symbol hash table */
-#define DT_STRTAB	5		/* Address of string table */
-#define DT_SYMTAB	6		/* Address of symbol table */
-#define DT_RELA		7		/* Address of Rela relocs */
-#define DT_RELASZ	8		/* Total size of Rela relocs */
-#define DT_RELAENT	9		/* Size of one Rela reloc */
-#define DT_STRSZ	10		/* Size of string table */
-#define DT_SYMENT	11		/* Size of one symbol table entry */
-#define DT_INIT		12		/* Address of init function */
-#define DT_FINI		13		/* Address of termination function */
-#define DT_SONAME	14		/* Name of shared object */
-#define DT_RPATH	15		/* Library search path (deprecated) */
-#define DT_SYMBOLIC	16		/* Start symbol search here */
-#define DT_REL		17		/* Address of Rel relocs */
-#define DT_RELSZ	18		/* Total size of Rel relocs */
-#define DT_RELENT	19		/* Size of one Rel reloc */
-#define DT_PLTREL	20		/* Type of reloc in PLT */
-#define DT_DEBUG	21		/* For debugging; unspecified */
-#define DT_TEXTREL	22		/* Reloc might modify .text */
-#define DT_JMPREL	23		/* Address of PLT relocs */
-#define	DT_BIND_NOW	24		/* Process relocations of object */
-#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
-#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
-#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
-#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
-#define DT_RUNPATH	29		/* Library search path */
-#define DT_FLAGS	30		/* Flags for the object being loaded */
-#define DT_ENCODING	32		/* Start of encoded range */
-#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
-#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
-#define	DT_NUM		34		/* Number used */
-#define DT_LOOS		0x6000000d	/* Start of OS-specific */
-#define DT_HIOS		0x6ffff000	/* End of OS-specific */
-#define DT_LOPROC	0x70000000	/* Start of processor-specific */
-#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
-#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */
-
-/* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
-   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
-   approach.  */
-#define DT_VALRNGLO	0x6ffffd00
-#define DT_GNU_PRELINKED 0x6ffffdf5	/* Prelinking timestamp */
-#define DT_GNU_CONFLICTSZ 0x6ffffdf6	/* Size of conflict section */
-#define DT_GNU_LIBLISTSZ 0x6ffffdf7	/* Size of library list */
-#define DT_CHECKSUM	0x6ffffdf8
-#define DT_PLTPADSZ	0x6ffffdf9
-#define DT_MOVEENT	0x6ffffdfa
-#define DT_MOVESZ	0x6ffffdfb
-#define DT_FEATURE_1	0x6ffffdfc	/* Feature selection (DTF_*).  */
-#define DT_POSFLAG_1	0x6ffffdfd	/* Flags for DT_* entries, effecting
-					   the following DT_* entry.  */
-#define DT_SYMINSZ	0x6ffffdfe	/* Size of syminfo table (in bytes) */
-#define DT_SYMINENT	0x6ffffdff	/* Entry size of syminfo */
-#define DT_VALRNGHI	0x6ffffdff
-#define DT_VALTAGIDX(tag)	(DT_VALRNGHI - (tag))	/* Reverse order! */
-#define DT_VALNUM 12
-
-/* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
-   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
-
-   If any adjustment is made to the ELF object after it has been
-   built these entries will need to be adjusted.  */
-#define DT_ADDRRNGLO	0x6ffffe00
-#define DT_GNU_HASH	0x6ffffef5	/* GNU-style hash table.  */
-#define DT_TLSDESC_PLT	0x6ffffef6
-#define DT_TLSDESC_GOT	0x6ffffef7
-#define DT_GNU_CONFLICT	0x6ffffef8	/* Start of conflict section */
-#define DT_GNU_LIBLIST	0x6ffffef9	/* Library list */
-#define DT_CONFIG	0x6ffffefa	/* Configuration information.  */
-#define DT_DEPAUDIT	0x6ffffefb	/* Dependency auditing.  */
-#define DT_AUDIT	0x6ffffefc	/* Object auditing.  */
-#define	DT_PLTPAD	0x6ffffefd	/* PLT padding.  */
-#define	DT_MOVETAB	0x6ffffefe	/* Move table.  */
-#define DT_SYMINFO	0x6ffffeff	/* Syminfo table.  */
-#define DT_ADDRRNGHI	0x6ffffeff
-#define DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	/* Reverse order! */
-#define DT_ADDRNUM 11
-
-/* The versioning entry types.  The next are defined as part of the
-   GNU extension.  */
-#define DT_VERSYM	0x6ffffff0
-
-#define DT_RELACOUNT	0x6ffffff9
-#define DT_RELCOUNT	0x6ffffffa
-
-/* These were chosen by Sun.  */
-#define DT_FLAGS_1	0x6ffffffb	/* State flags, see DF_1_* below.  */
-#define	DT_VERDEF	0x6ffffffc	/* Address of version definition
-					   table */
-#define	DT_VERDEFNUM	0x6ffffffd	/* Number of version definitions */
-#define	DT_VERNEED	0x6ffffffe	/* Address of table with needed
-					   versions */
-#define	DT_VERNEEDNUM	0x6fffffff	/* Number of needed versions */
-#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	/* Reverse order! */
-#define DT_VERSIONTAGNUM 16
-
-/* Sun added these machine-independent extensions in the "processor-specific"
-   range.  Be compatible.  */
-#define DT_AUXILIARY    0x7ffffffd      /* Shared object to load before self */
-#define DT_FILTER       0x7fffffff      /* Shared object to get values from */
-#define DT_EXTRATAGIDX(tag)	((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
-#define DT_EXTRANUM	3
-
-/* Values of `d_un.d_val' in the DT_FLAGS entry.  */
-#define DF_ORIGIN	0x00000001	/* Object may use DF_ORIGIN */
-#define DF_SYMBOLIC	0x00000002	/* Symbol resolutions starts here */
-#define DF_TEXTREL	0x00000004	/* Object contains text relocations */
-#define DF_BIND_NOW	0x00000008	/* No lazy binding for this object */
-#define DF_STATIC_TLS	0x00000010	/* Module uses the static TLS model */
-
-/* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
-   entry in the dynamic section.  */
-#define DF_1_NOW	0x00000001	/* Set RTLD_NOW for this object.  */
-#define DF_1_GLOBAL	0x00000002	/* Set RTLD_GLOBAL for this object.  */
-#define DF_1_GROUP	0x00000004	/* Set RTLD_GROUP for this object.  */
-#define DF_1_NODELETE	0x00000008	/* Set RTLD_NODELETE for this object.*/
-#define DF_1_LOADFLTR	0x00000010	/* Trigger filtee loading at runtime.*/
-#define DF_1_INITFIRST	0x00000020	/* Set RTLD_INITFIRST for this object*/
-#define DF_1_NOOPEN	0x00000040	/* Set RTLD_NOOPEN for this object.  */
-#define DF_1_ORIGIN	0x00000080	/* $ORIGIN must be handled.  */
-#define DF_1_DIRECT	0x00000100	/* Direct binding enabled.  */
-#define DF_1_TRANS	0x00000200
-#define DF_1_INTERPOSE	0x00000400	/* Object is used to interpose.  */
-#define DF_1_NODEFLIB	0x00000800	/* Ignore default lib search path.  */
-#define DF_1_NODUMP	0x00001000	/* Object can't be dldump'ed.  */
-#define DF_1_CONFALT	0x00002000	/* Configuration alternative created.*/
-#define DF_1_ENDFILTEE	0x00004000	/* Filtee terminates filters search. */
-#define	DF_1_DISPRELDNE	0x00008000	/* Disp reloc applied at build time. */
-#define	DF_1_DISPRELPND	0x00010000	/* Disp reloc applied at run-time.  */
-#define	DF_1_NODIRECT	0x00020000	/* Object has no-direct binding. */
-#define	DF_1_IGNMULDEF	0x00040000
-#define	DF_1_NOKSYMS	0x00080000
-#define	DF_1_NOHDR	0x00100000
-#define	DF_1_EDITED	0x00200000	/* Object is modified after built.  */
-#define	DF_1_NORELOC	0x00400000
-#define	DF_1_SYMINTPOSE	0x00800000	/* Object has individual interposers.  */
-#define	DF_1_GLOBAUDIT	0x01000000	/* Global auditing required.  */
-#define	DF_1_SINGLETON	0x02000000	/* Singleton symbols are used.  */
-
-/* Flags for the feature selection in DT_FEATURE_1.  */
-#define DTF_1_PARINIT	0x00000001
-#define DTF_1_CONFEXP	0x00000002
-
-/* Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.  */
-#define DF_P1_LAZYLOAD	0x00000001	/* Lazyload following object.  */
-#define DF_P1_GROUPPERM	0x00000002	/* Symbols from next object are not
-					   generally available.  */
-
-/* Version definition sections.  */
-
-typedef struct
-{
-  Elf32_Half	vd_version;		/* Version revision */
-  Elf32_Half	vd_flags;		/* Version information */
-  Elf32_Half	vd_ndx;			/* Version Index */
-  Elf32_Half	vd_cnt;			/* Number of associated aux entries */
-  Elf32_Word	vd_hash;		/* Version name hash value */
-  Elf32_Word	vd_aux;			/* Offset in bytes to verdaux array */
-  Elf32_Word	vd_next;		/* Offset in bytes to next verdef
-					   entry */
-} Elf32_Verdef;
-
-typedef struct
-{
-  Elf64_Half	vd_version;		/* Version revision */
-  Elf64_Half	vd_flags;		/* Version information */
-  Elf64_Half	vd_ndx;			/* Version Index */
-  Elf64_Half	vd_cnt;			/* Number of associated aux entries */
-  Elf64_Word	vd_hash;		/* Version name hash value */
-  Elf64_Word	vd_aux;			/* Offset in bytes to verdaux array */
-  Elf64_Word	vd_next;		/* Offset in bytes to next verdef
-					   entry */
-} Elf64_Verdef;
-
-
-/* Legal values for vd_version (version revision).  */
-#define VER_DEF_NONE	0		/* No version */
-#define VER_DEF_CURRENT	1		/* Current version */
-#define VER_DEF_NUM	2		/* Given version number */
-
-/* Legal values for vd_flags (version information flags).  */
-#define VER_FLG_BASE	0x1		/* Version definition of file itself */
-#define VER_FLG_WEAK	0x2		/* Weak version identifier */
-
-/* Versym symbol index values.  */
-#define	VER_NDX_LOCAL		0	/* Symbol is local.  */
-#define	VER_NDX_GLOBAL		1	/* Symbol is global.  */
-#define	VER_NDX_LORESERVE	0xff00	/* Beginning of reserved entries.  */
-#define	VER_NDX_ELIMINATE	0xff01	/* Symbol is to be eliminated.  */
-
-/* Auxialiary version information.  */
-
-typedef struct
-{
-  Elf32_Word	vda_name;		/* Version or dependency names */
-  Elf32_Word	vda_next;		/* Offset in bytes to next verdaux
-					   entry */
-} Elf32_Verdaux;
-
-typedef struct
-{
-  Elf64_Word	vda_name;		/* Version or dependency names */
-  Elf64_Word	vda_next;		/* Offset in bytes to next verdaux
-					   entry */
-} Elf64_Verdaux;
-
-
-/* Version dependency section.  */
-
-typedef struct
-{
-  Elf32_Half	vn_version;		/* Version of structure */
-  Elf32_Half	vn_cnt;			/* Number of associated aux entries */
-  Elf32_Word	vn_file;		/* Offset of filename for this
-					   dependency */
-  Elf32_Word	vn_aux;			/* Offset in bytes to vernaux array */
-  Elf32_Word	vn_next;		/* Offset in bytes to next verneed
-					   entry */
-} Elf32_Verneed;
-
-typedef struct
-{
-  Elf64_Half	vn_version;		/* Version of structure */
-  Elf64_Half	vn_cnt;			/* Number of associated aux entries */
-  Elf64_Word	vn_file;		/* Offset of filename for this
-					   dependency */
-  Elf64_Word	vn_aux;			/* Offset in bytes to vernaux array */
-  Elf64_Word	vn_next;		/* Offset in bytes to next verneed
-					   entry */
-} Elf64_Verneed;
-
-
-/* Legal values for vn_version (version revision).  */
-#define VER_NEED_NONE	 0		/* No version */
-#define VER_NEED_CURRENT 1		/* Current version */
-#define VER_NEED_NUM	 2		/* Given version number */
-
-/* Auxiliary needed version information.  */
-
-typedef struct
-{
-  Elf32_Word	vna_hash;		/* Hash value of dependency name */
-  Elf32_Half	vna_flags;		/* Dependency specific information */
-  Elf32_Half	vna_other;		/* Unused */
-  Elf32_Word	vna_name;		/* Dependency name string offset */
-  Elf32_Word	vna_next;		/* Offset in bytes to next vernaux
-					   entry */
-} Elf32_Vernaux;
-
-typedef struct
-{
-  Elf64_Word	vna_hash;		/* Hash value of dependency name */
-  Elf64_Half	vna_flags;		/* Dependency specific information */
-  Elf64_Half	vna_other;		/* Unused */
-  Elf64_Word	vna_name;		/* Dependency name string offset */
-  Elf64_Word	vna_next;		/* Offset in bytes to next vernaux
-					   entry */
-} Elf64_Vernaux;
-
-
-/* Legal values for vna_flags.  */
-#define VER_FLG_WEAK	0x2		/* Weak version identifier */
-
-
-/* Auxiliary vector.  */
-
-/* This vector is normally only used by the program interpreter.  The
-   usual definition in an ABI supplement uses the name auxv_t.  The
-   vector is not usually defined in a standard <elf.h> file, but it
-   can't hurt.  We rename it to avoid conflicts.  The sizes of these
-   types are an arrangement between the exec server and the program
-   interpreter, so we don't fully specify them here.  */
-
-typedef struct
-{
-  uint32_t a_type;		/* Entry type */
-  union
-    {
-      uint32_t a_val;		/* Integer value */
-      /* We use to have pointer elements added here.  We cannot do that,
-	 though, since it does not work when using 32-bit definitions
-	 on 64-bit platforms and vice versa.  */
-    } a_un;
-} Elf32_auxv_t;
-
-typedef struct
-{
-  uint64_t a_type;		/* Entry type */
-  union
-    {
-      uint64_t a_val;		/* Integer value */
-      /* We use to have pointer elements added here.  We cannot do that,
-	 though, since it does not work when using 32-bit definitions
-	 on 64-bit platforms and vice versa.  */
-    } a_un;
-} Elf64_auxv_t;
-
-/* Legal values for a_type (entry type).  */
-
-#define AT_NULL		0		/* End of vector */
-#define AT_IGNORE	1		/* Entry should be ignored */
-#define AT_EXECFD	2		/* File descriptor of program */
-#define AT_PHDR		3		/* Program headers for program */
-#define AT_PHENT	4		/* Size of program header entry */
-#define AT_PHNUM	5		/* Number of program headers */
-#define AT_PAGESZ	6		/* System page size */
-#define AT_BASE		7		/* Base address of interpreter */
-#define AT_FLAGS	8		/* Flags */
-#define AT_ENTRY	9		/* Entry point of program */
-#define AT_NOTELF	10		/* Program is not ELF */
-#define AT_UID		11		/* Real uid */
-#define AT_EUID		12		/* Effective uid */
-#define AT_GID		13		/* Real gid */
-#define AT_EGID		14		/* Effective gid */
-#define AT_CLKTCK	17		/* Frequency of times() */
-
-/* Some more special a_type values describing the hardware.  */
-#define AT_PLATFORM	15		/* String identifying platform.  */
-#define AT_HWCAP	16		/* Machine-dependent hints about
-					   processor capabilities.  */
-
-/* This entry gives some information about the FPU initialization
-   performed by the kernel.  */
-#define AT_FPUCW	18		/* Used FPU control word.  */
-
-/* Cache block sizes.  */
-#define AT_DCACHEBSIZE	19		/* Data cache block size.  */
-#define AT_ICACHEBSIZE	20		/* Instruction cache block size.  */
-#define AT_UCACHEBSIZE	21		/* Unified cache block size.  */
-
-/* A special ignored value for PPC, used by the kernel to control the
-   interpretation of the AUXV. Must be > 16.  */
-#define AT_IGNOREPPC	22		/* Entry should be ignored.  */
-
-#define	AT_SECURE	23		/* Boolean, was exec setuid-like?  */
-
-#define AT_BASE_PLATFORM 24		/* String identifying real platforms.*/
-
-#define AT_RANDOM	25		/* Address of 16 random bytes.  */
-
-#define AT_HWCAP2	26		/* More machine-dependent hints about
-					   processor capabilities.  */
-
-#define AT_EXECFN	31		/* Filename of executable.  */
-
-/* Pointer to the global system page used for system calls and other
-   nice things.  */
-#define AT_SYSINFO	32
-#define AT_SYSINFO_EHDR	33
-
-/* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
-   log2 of line size; mask those to get cache size.  */
-#define AT_L1I_CACHESHAPE	34
-#define AT_L1D_CACHESHAPE	35
-#define AT_L2_CACHESHAPE	36
-#define AT_L3_CACHESHAPE	37
-
-/* Note section contents.  Each entry in the note section begins with
-   a header of a fixed form.  */
-
-typedef struct
-{
-  Elf32_Word n_namesz;			/* Length of the note's name.  */
-  Elf32_Word n_descsz;			/* Length of the note's descriptor.  */
-  Elf32_Word n_type;			/* Type of the note.  */
-} Elf32_Nhdr;
-
-typedef struct
-{
-  Elf64_Word n_namesz;			/* Length of the note's name.  */
-  Elf64_Word n_descsz;			/* Length of the note's descriptor.  */
-  Elf64_Word n_type;			/* Type of the note.  */
-} Elf64_Nhdr;
-
-/* Known names of notes.  */
-
-/* Solaris entries in the note section have this name.  */
-#define ELF_NOTE_SOLARIS	"SUNW Solaris"
-
-/* Note entries for GNU systems have this name.  */
-#define ELF_NOTE_GNU		"GNU"
-
-
-/* Defined types of notes for Solaris.  */
-
-/* Value of descriptor (one word) is desired pagesize for the binary.  */
-#define ELF_NOTE_PAGESIZE_HINT	1
-
-
-/* Defined note types for GNU systems.  */
-
-/* ABI information.  The descriptor consists of words:
-   word 0: OS descriptor
-   word 1: major version of the ABI
-   word 2: minor version of the ABI
-   word 3: subminor version of the ABI
-*/
-#define NT_GNU_ABI_TAG	1
-#define ELF_NOTE_ABI	NT_GNU_ABI_TAG /* Old name.  */
-
-/* Known OSes.  These values can appear in word 0 of an
-   NT_GNU_ABI_TAG note section entry.  */
-#define ELF_NOTE_OS_LINUX	0
-#define ELF_NOTE_OS_GNU		1
-#define ELF_NOTE_OS_SOLARIS2	2
-#define ELF_NOTE_OS_FREEBSD	3
-
-/* Synthetic hwcap information.  The descriptor begins with two words:
-   word 0: number of entries
-   word 1: bitmask of enabled entries
-   Then follow variable-length entries, one byte followed by a
-   '\0'-terminated hwcap name string.  The byte gives the bit
-   number to test if enabled, (1U << bit) & bitmask.  */
-#define NT_GNU_HWCAP	2
-
-/* Build ID bits as generated by ld --build-id.
-   The descriptor consists of any nonzero number of bytes.  */
-#define NT_GNU_BUILD_ID	3
-
-/* Version note generated by GNU gold containing a version string.  */
-#define NT_GNU_GOLD_VERSION	4
-
-
-/* Move records.  */
-typedef struct
-{
-  Elf32_Xword m_value;		/* Symbol value.  */
-  Elf32_Word m_info;		/* Size and index.  */
-  Elf32_Word m_poffset;		/* Symbol offset.  */
-  Elf32_Half m_repeat;		/* Repeat count.  */
-  Elf32_Half m_stride;		/* Stride info.  */
-} Elf32_Move;
-
-typedef struct
-{
-  Elf64_Xword m_value;		/* Symbol value.  */
-  Elf64_Xword m_info;		/* Size and index.  */
-  Elf64_Xword m_poffset;	/* Symbol offset.  */
-  Elf64_Half m_repeat;		/* Repeat count.  */
-  Elf64_Half m_stride;		/* Stride info.  */
-} Elf64_Move;
-
-/* Macro to construct move records.  */
-#define ELF32_M_SYM(info)	((info) >> 8)
-#define ELF32_M_SIZE(info)	((unsigned char) (info))
-#define ELF32_M_INFO(sym, size)	(((sym) << 8) + (unsigned char) (size))
-
-#define ELF64_M_SYM(info)	ELF32_M_SYM (info)
-#define ELF64_M_SIZE(info)	ELF32_M_SIZE (info)
-#define ELF64_M_INFO(sym, size)	ELF32_M_INFO (sym, size)
-
-
-/* Motorola 68k specific definitions.  */
-
-/* Values for Elf32_Ehdr.e_flags.  */
-#define EF_CPU32	0x00810000
-
-/* m68k relocs.  */
-
-#define R_68K_NONE	0		/* No reloc */
-#define R_68K_32	1		/* Direct 32 bit  */
-#define R_68K_16	2		/* Direct 16 bit  */
-#define R_68K_8		3		/* Direct 8 bit  */
-#define R_68K_PC32	4		/* PC relative 32 bit */
-#define R_68K_PC16	5		/* PC relative 16 bit */
-#define R_68K_PC8	6		/* PC relative 8 bit */
-#define R_68K_GOT32	7		/* 32 bit PC relative GOT entry */
-#define R_68K_GOT16	8		/* 16 bit PC relative GOT entry */
-#define R_68K_GOT8	9		/* 8 bit PC relative GOT entry */
-#define R_68K_GOT32O	10		/* 32 bit GOT offset */
-#define R_68K_GOT16O	11		/* 16 bit GOT offset */
-#define R_68K_GOT8O	12		/* 8 bit GOT offset */
-#define R_68K_PLT32	13		/* 32 bit PC relative PLT address */
-#define R_68K_PLT16	14		/* 16 bit PC relative PLT address */
-#define R_68K_PLT8	15		/* 8 bit PC relative PLT address */
-#define R_68K_PLT32O	16		/* 32 bit PLT offset */
-#define R_68K_PLT16O	17		/* 16 bit PLT offset */
-#define R_68K_PLT8O	18		/* 8 bit PLT offset */
-#define R_68K_COPY	19		/* Copy symbol at runtime */
-#define R_68K_GLOB_DAT	20		/* Create GOT entry */
-#define R_68K_JMP_SLOT	21		/* Create PLT entry */
-#define R_68K_RELATIVE	22		/* Adjust by program base */
-#define R_68K_TLS_GD32      25          /* 32 bit GOT offset for GD */
-#define R_68K_TLS_GD16      26          /* 16 bit GOT offset for GD */
-#define R_68K_TLS_GD8       27          /* 8 bit GOT offset for GD */
-#define R_68K_TLS_LDM32     28          /* 32 bit GOT offset for LDM */
-#define R_68K_TLS_LDM16     29          /* 16 bit GOT offset for LDM */
-#define R_68K_TLS_LDM8      30          /* 8 bit GOT offset for LDM */
-#define R_68K_TLS_LDO32     31          /* 32 bit module-relative offset */
-#define R_68K_TLS_LDO16     32          /* 16 bit module-relative offset */
-#define R_68K_TLS_LDO8      33          /* 8 bit module-relative offset */
-#define R_68K_TLS_IE32      34          /* 32 bit GOT offset for IE */
-#define R_68K_TLS_IE16      35          /* 16 bit GOT offset for IE */
-#define R_68K_TLS_IE8       36          /* 8 bit GOT offset for IE */
-#define R_68K_TLS_LE32      37          /* 32 bit offset relative to
-					   static TLS block */
-#define R_68K_TLS_LE16      38          /* 16 bit offset relative to
-					   static TLS block */
-#define R_68K_TLS_LE8       39          /* 8 bit offset relative to
-					   static TLS block */
-#define R_68K_TLS_DTPMOD32  40          /* 32 bit module number */
-#define R_68K_TLS_DTPREL32  41          /* 32 bit module-relative offset */
-#define R_68K_TLS_TPREL32   42          /* 32 bit TP-relative offset */
-/* Keep this the last entry.  */
-#define R_68K_NUM	43
-
-/* Intel 80386 specific definitions.  */
-
-/* i386 relocs.  */
-
-#define R_386_NONE	   0		/* No reloc */
-#define R_386_32	   1		/* Direct 32 bit  */
-#define R_386_PC32	   2		/* PC relative 32 bit */
-#define R_386_GOT32	   3		/* 32 bit GOT entry */
-#define R_386_PLT32	   4		/* 32 bit PLT address */
-#define R_386_COPY	   5		/* Copy symbol at runtime */
-#define R_386_GLOB_DAT	   6		/* Create GOT entry */
-#define R_386_JMP_SLOT	   7		/* Create PLT entry */
-#define R_386_RELATIVE	   8		/* Adjust by program base */
-#define R_386_GOTOFF	   9		/* 32 bit offset to GOT */
-#define R_386_GOTPC	   10		/* 32 bit PC relative offset to GOT */
-#define R_386_32PLT	   11
-#define R_386_TLS_TPOFF	   14		/* Offset in static TLS block */
-#define R_386_TLS_IE	   15		/* Address of GOT entry for static TLS
-					   block offset */
-#define R_386_TLS_GOTIE	   16		/* GOT entry for static TLS block
-					   offset */
-#define R_386_TLS_LE	   17		/* Offset relative to static TLS
-					   block */
-#define R_386_TLS_GD	   18		/* Direct 32 bit for GNU version of
-					   general dynamic thread local data */
-#define R_386_TLS_LDM	   19		/* Direct 32 bit for GNU version of
-					   local dynamic thread local data
-					   in LE code */
-#define R_386_16	   20
-#define R_386_PC16	   21
-#define R_386_8		   22
-#define R_386_PC8	   23
-#define R_386_TLS_GD_32	   24		/* Direct 32 bit for general dynamic
-					   thread local data */
-#define R_386_TLS_GD_PUSH  25		/* Tag for pushl in GD TLS code */
-#define R_386_TLS_GD_CALL  26		/* Relocation for call to
-					   __tls_get_addr() */
-#define R_386_TLS_GD_POP   27		/* Tag for popl in GD TLS code */
-#define R_386_TLS_LDM_32   28		/* Direct 32 bit for local dynamic
-					   thread local data in LE code */
-#define R_386_TLS_LDM_PUSH 29		/* Tag for pushl in LDM TLS code */
-#define R_386_TLS_LDM_CALL 30		/* Relocation for call to
-					   __tls_get_addr() in LDM code */
-#define R_386_TLS_LDM_POP  31		/* Tag for popl in LDM TLS code */
-#define R_386_TLS_LDO_32   32		/* Offset relative to TLS block */
-#define R_386_TLS_IE_32	   33		/* GOT entry for negated static TLS
-					   block offset */
-#define R_386_TLS_LE_32	   34		/* Negated offset relative to static
-					   TLS block */
-#define R_386_TLS_DTPMOD32 35		/* ID of module containing symbol */
-#define R_386_TLS_DTPOFF32 36		/* Offset in TLS block */
-#define R_386_TLS_TPOFF32  37		/* Negated offset in static TLS block */
-#define R_386_SIZE32	   38 		/* 32-bit symbol size */
-#define R_386_TLS_GOTDESC  39		/* GOT offset for TLS descriptor.  */
-#define R_386_TLS_DESC_CALL 40		/* Marker of call through TLS
-					   descriptor for
-					   relaxation.  */
-#define R_386_TLS_DESC     41		/* TLS descriptor containing
-					   pointer to code and to
-					   argument, returning the TLS
-					   offset for the symbol.  */
-#define R_386_IRELATIVE	   42		/* Adjust indirectly by program base */
-/* Keep this the last entry.  */
-#define R_386_NUM	   43
-
-/* SUN SPARC specific definitions.  */
-
-/* Legal values for ST_TYPE subfield of st_info (symbol type).  */
-
-#define STT_SPARC_REGISTER	13	/* Global register reserved to app. */
-
-/* Values for Elf64_Ehdr.e_flags.  */
-
-#define EF_SPARCV9_MM		3
-#define EF_SPARCV9_TSO		0
-#define EF_SPARCV9_PSO		1
-#define EF_SPARCV9_RMO		2
-#define EF_SPARC_LEDATA		0x800000 /* little endian data */
-#define EF_SPARC_EXT_MASK	0xFFFF00
-#define EF_SPARC_32PLUS		0x000100 /* generic V8+ features */
-#define EF_SPARC_SUN_US1	0x000200 /* Sun UltraSPARC1 extensions */
-#define EF_SPARC_HAL_R1		0x000400 /* HAL R1 extensions */
-#define EF_SPARC_SUN_US3	0x000800 /* Sun UltraSPARCIII extensions */
-
-/* SPARC relocs.  */
-
-#define R_SPARC_NONE		0	/* No reloc */
-#define R_SPARC_8		1	/* Direct 8 bit */
-#define R_SPARC_16		2	/* Direct 16 bit */
-#define R_SPARC_32		3	/* Direct 32 bit */
-#define R_SPARC_DISP8		4	/* PC relative 8 bit */
-#define R_SPARC_DISP16		5	/* PC relative 16 bit */
-#define R_SPARC_DISP32		6	/* PC relative 32 bit */
-#define R_SPARC_WDISP30		7	/* PC relative 30 bit shifted */
-#define R_SPARC_WDISP22		8	/* PC relative 22 bit shifted */
-#define R_SPARC_HI22		9	/* High 22 bit */
-#define R_SPARC_22		10	/* Direct 22 bit */
-#define R_SPARC_13		11	/* Direct 13 bit */
-#define R_SPARC_LO10		12	/* Truncated 10 bit */
-#define R_SPARC_GOT10		13	/* Truncated 10 bit GOT entry */
-#define R_SPARC_GOT13		14	/* 13 bit GOT entry */
-#define R_SPARC_GOT22		15	/* 22 bit GOT entry shifted */
-#define R_SPARC_PC10		16	/* PC relative 10 bit truncated */
-#define R_SPARC_PC22		17	/* PC relative 22 bit shifted */
-#define R_SPARC_WPLT30		18	/* 30 bit PC relative PLT address */
-#define R_SPARC_COPY		19	/* Copy symbol at runtime */
-#define R_SPARC_GLOB_DAT	20	/* Create GOT entry */
-#define R_SPARC_JMP_SLOT	21	/* Create PLT entry */
-#define R_SPARC_RELATIVE	22	/* Adjust by program base */
-#define R_SPARC_UA32		23	/* Direct 32 bit unaligned */
-
-/* Additional Sparc64 relocs.  */
-
-#define R_SPARC_PLT32		24	/* Direct 32 bit ref to PLT entry */
-#define R_SPARC_HIPLT22		25	/* High 22 bit PLT entry */
-#define R_SPARC_LOPLT10		26	/* Truncated 10 bit PLT entry */
-#define R_SPARC_PCPLT32		27	/* PC rel 32 bit ref to PLT entry */
-#define R_SPARC_PCPLT22		28	/* PC rel high 22 bit PLT entry */
-#define R_SPARC_PCPLT10		29	/* PC rel trunc 10 bit PLT entry */
-#define R_SPARC_10		30	/* Direct 10 bit */
-#define R_SPARC_11		31	/* Direct 11 bit */
-#define R_SPARC_64		32	/* Direct 64 bit */
-#define R_SPARC_OLO10		33	/* 10bit with secondary 13bit addend */
-#define R_SPARC_HH22		34	/* Top 22 bits of direct 64 bit */
-#define R_SPARC_HM10		35	/* High middle 10 bits of ... */
-#define R_SPARC_LM22		36	/* Low middle 22 bits of ... */
-#define R_SPARC_PC_HH22		37	/* Top 22 bits of pc rel 64 bit */
-#define R_SPARC_PC_HM10		38	/* High middle 10 bit of ... */
-#define R_SPARC_PC_LM22		39	/* Low miggle 22 bits of ... */
-#define R_SPARC_WDISP16		40	/* PC relative 16 bit shifted */
-#define R_SPARC_WDISP19		41	/* PC relative 19 bit shifted */
-#define R_SPARC_GLOB_JMP	42	/* was part of v9 ABI but was removed */
-#define R_SPARC_7		43	/* Direct 7 bit */
-#define R_SPARC_5		44	/* Direct 5 bit */
-#define R_SPARC_6		45	/* Direct 6 bit */
-#define R_SPARC_DISP64		46	/* PC relative 64 bit */
-#define R_SPARC_PLT64		47	/* Direct 64 bit ref to PLT entry */
-#define R_SPARC_HIX22		48	/* High 22 bit complemented */
-#define R_SPARC_LOX10		49	/* Truncated 11 bit complemented */
-#define R_SPARC_H44		50	/* Direct high 12 of 44 bit */
-#define R_SPARC_M44		51	/* Direct mid 22 of 44 bit */
-#define R_SPARC_L44		52	/* Direct low 10 of 44 bit */
-#define R_SPARC_REGISTER	53	/* Global register usage */
-#define R_SPARC_UA64		54	/* Direct 64 bit unaligned */
-#define R_SPARC_UA16		55	/* Direct 16 bit unaligned */
-#define R_SPARC_TLS_GD_HI22	56
-#define R_SPARC_TLS_GD_LO10	57
-#define R_SPARC_TLS_GD_ADD	58
-#define R_SPARC_TLS_GD_CALL	59
-#define R_SPARC_TLS_LDM_HI22	60
-#define R_SPARC_TLS_LDM_LO10	61
-#define R_SPARC_TLS_LDM_ADD	62
-#define R_SPARC_TLS_LDM_CALL	63
-#define R_SPARC_TLS_LDO_HIX22	64
-#define R_SPARC_TLS_LDO_LOX10	65
-#define R_SPARC_TLS_LDO_ADD	66
-#define R_SPARC_TLS_IE_HI22	67
-#define R_SPARC_TLS_IE_LO10	68
-#define R_SPARC_TLS_IE_LD	69
-#define R_SPARC_TLS_IE_LDX	70
-#define R_SPARC_TLS_IE_ADD	71
-#define R_SPARC_TLS_LE_HIX22	72
-#define R_SPARC_TLS_LE_LOX10	73
-#define R_SPARC_TLS_DTPMOD32	74
-#define R_SPARC_TLS_DTPMOD64	75
-#define R_SPARC_TLS_DTPOFF32	76
-#define R_SPARC_TLS_DTPOFF64	77
-#define R_SPARC_TLS_TPOFF32	78
-#define R_SPARC_TLS_TPOFF64	79
-#define R_SPARC_GOTDATA_HIX22	80
-#define R_SPARC_GOTDATA_LOX10	81
-#define R_SPARC_GOTDATA_OP_HIX22	82
-#define R_SPARC_GOTDATA_OP_LOX10	83
-#define R_SPARC_GOTDATA_OP	84
-#define R_SPARC_H34		85
-#define R_SPARC_SIZE32		86
-#define R_SPARC_SIZE64		87
-#define R_SPARC_WDISP10		88
-#define R_SPARC_JMP_IREL	248
-#define R_SPARC_IRELATIVE	249
-#define R_SPARC_GNU_VTINHERIT	250
-#define R_SPARC_GNU_VTENTRY	251
-#define R_SPARC_REV32		252
-/* Keep this the last entry.  */
-#define R_SPARC_NUM		253
-
-/* For Sparc64, legal values for d_tag of Elf64_Dyn.  */
-
-#define DT_SPARC_REGISTER	0x70000001
-#define DT_SPARC_NUM		2
-
-/* MIPS R3000 specific definitions.  */
-
-/* Legal values for e_flags field of Elf32_Ehdr.  */
-
-#define EF_MIPS_NOREORDER	1     /* A .noreorder directive was used.  */
-#define EF_MIPS_PIC		2     /* Contains PIC code.  */
-#define EF_MIPS_CPIC		4     /* Uses PIC calling sequence.  */
-#define EF_MIPS_XGOT		8
-#define EF_MIPS_64BIT_WHIRL	16
-#define EF_MIPS_ABI2		32
-#define EF_MIPS_ABI_ON32	64
-#define EF_MIPS_FP64		512  /* Uses FP64 (12 callee-saved).  */
-#define EF_MIPS_NAN2008	1024  /* Uses IEEE 754-2008 NaN encoding.  */
-#define EF_MIPS_ARCH		0xf0000000 /* MIPS architecture level.  */
-
-/* Legal values for MIPS architecture level.  */
-
-#define EF_MIPS_ARCH_1		0x00000000 /* -mips1 code.  */
-#define EF_MIPS_ARCH_2		0x10000000 /* -mips2 code.  */
-#define EF_MIPS_ARCH_3		0x20000000 /* -mips3 code.  */
-#define EF_MIPS_ARCH_4		0x30000000 /* -mips4 code.  */
-#define EF_MIPS_ARCH_5		0x40000000 /* -mips5 code.  */
-#define EF_MIPS_ARCH_32		0x50000000 /* MIPS32 code.  */
-#define EF_MIPS_ARCH_64		0x60000000 /* MIPS64 code.  */
-#define EF_MIPS_ARCH_32R2	0x70000000 /* MIPS32r2 code.  */
-#define EF_MIPS_ARCH_64R2	0x80000000 /* MIPS64r2 code.  */
-
-/* The following are unofficial names and should not be used.  */
-
-#define E_MIPS_ARCH_1		EF_MIPS_ARCH_1
-#define E_MIPS_ARCH_2		EF_MIPS_ARCH_2
-#define E_MIPS_ARCH_3		EF_MIPS_ARCH_3
-#define E_MIPS_ARCH_4		EF_MIPS_ARCH_4
-#define E_MIPS_ARCH_5		EF_MIPS_ARCH_5
-#define E_MIPS_ARCH_32		EF_MIPS_ARCH_32
-#define E_MIPS_ARCH_64		EF_MIPS_ARCH_64
-
-/* Special section indices.  */
-
-#define SHN_MIPS_ACOMMON	0xff00	/* Allocated common symbols.  */
-#define SHN_MIPS_TEXT		0xff01	/* Allocated test symbols.  */
-#define SHN_MIPS_DATA		0xff02	/* Allocated data symbols.  */
-#define SHN_MIPS_SCOMMON 	0xff03	/* Small common symbols.  */
-#define SHN_MIPS_SUNDEFINED	0xff04	/* Small undefined symbols.  */
-
-/* Legal values for sh_type field of Elf32_Shdr.  */
-
-#define SHT_MIPS_LIBLIST	0x70000000 /* Shared objects used in link.  */
-#define SHT_MIPS_MSYM		0x70000001
-#define SHT_MIPS_CONFLICT	0x70000002 /* Conflicting symbols.  */
-#define SHT_MIPS_GPTAB		0x70000003 /* Global data area sizes.  */
-#define SHT_MIPS_UCODE		0x70000004 /* Reserved for SGI/MIPS compilers */
-#define SHT_MIPS_DEBUG		0x70000005 /* MIPS ECOFF debugging info.  */
-#define SHT_MIPS_REGINFO	0x70000006 /* Register usage information.  */
-#define SHT_MIPS_PACKAGE	0x70000007
-#define SHT_MIPS_PACKSYM	0x70000008
-#define SHT_MIPS_RELD		0x70000009
-#define SHT_MIPS_IFACE		0x7000000b
-#define SHT_MIPS_CONTENT	0x7000000c
-#define SHT_MIPS_OPTIONS	0x7000000d /* Miscellaneous options.  */
-#define SHT_MIPS_SHDR		0x70000010
-#define SHT_MIPS_FDESC		0x70000011
-#define SHT_MIPS_EXTSYM		0x70000012
-#define SHT_MIPS_DENSE		0x70000013
-#define SHT_MIPS_PDESC		0x70000014
-#define SHT_MIPS_LOCSYM		0x70000015
-#define SHT_MIPS_AUXSYM		0x70000016
-#define SHT_MIPS_OPTSYM		0x70000017
-#define SHT_MIPS_LOCSTR		0x70000018
-#define SHT_MIPS_LINE		0x70000019
-#define SHT_MIPS_RFDESC		0x7000001a
-#define SHT_MIPS_DELTASYM	0x7000001b
-#define SHT_MIPS_DELTAINST	0x7000001c
-#define SHT_MIPS_DELTACLASS	0x7000001d
-#define SHT_MIPS_DWARF		0x7000001e /* DWARF debugging information.  */
-#define SHT_MIPS_DELTADECL	0x7000001f
-#define SHT_MIPS_SYMBOL_LIB	0x70000020
-#define SHT_MIPS_EVENTS		0x70000021 /* Event section.  */
-#define SHT_MIPS_TRANSLATE	0x70000022
-#define SHT_MIPS_PIXIE		0x70000023
-#define SHT_MIPS_XLATE		0x70000024
-#define SHT_MIPS_XLATE_DEBUG	0x70000025
-#define SHT_MIPS_WHIRL		0x70000026
-#define SHT_MIPS_EH_REGION	0x70000027
-#define SHT_MIPS_XLATE_OLD	0x70000028
-#define SHT_MIPS_PDR_EXCEPTION	0x70000029
-
-/* Legal values for sh_flags field of Elf32_Shdr.  */
-
-#define SHF_MIPS_GPREL		0x10000000 /* Must be in global data area.  */
-#define SHF_MIPS_MERGE		0x20000000
-#define SHF_MIPS_ADDR		0x40000000
-#define SHF_MIPS_STRINGS	0x80000000
-#define SHF_MIPS_NOSTRIP	0x08000000
-#define SHF_MIPS_LOCAL		0x04000000
-#define SHF_MIPS_NAMES		0x02000000
-#define SHF_MIPS_NODUPE		0x01000000
-
-
-/* Symbol tables.  */
-
-/* MIPS specific values for `st_other'.  */
-#define STO_MIPS_DEFAULT		0x0
-#define STO_MIPS_INTERNAL		0x1
-#define STO_MIPS_HIDDEN			0x2
-#define STO_MIPS_PROTECTED		0x3
-#define STO_MIPS_PLT			0x8
-#define STO_MIPS_SC_ALIGN_UNUSED	0xff
-
-/* MIPS specific values for `st_info'.  */
-#define STB_MIPS_SPLIT_COMMON		13
-
-/* Entries found in sections of type SHT_MIPS_GPTAB.  */
-
-typedef union
-{
-  struct
-    {
-      Elf32_Word gt_current_g_value;	/* -G value used for compilation.  */
-      Elf32_Word gt_unused;		/* Not used.  */
-    } gt_header;			/* First entry in section.  */
-  struct
-    {
-      Elf32_Word gt_g_value;		/* If this value were used for -G.  */
-      Elf32_Word gt_bytes;		/* This many bytes would be used.  */
-    } gt_entry;				/* Subsequent entries in section.  */
-} Elf32_gptab;
-
-/* Entry found in sections of type SHT_MIPS_REGINFO.  */
-
-typedef struct
-{
-  Elf32_Word ri_gprmask;		/* General registers used.  */
-  Elf32_Word ri_cprmask[4];		/* Coprocessor registers used.  */
-  Elf32_Sword ri_gp_value;		/* $gp register value.  */
-} Elf32_RegInfo;
-
-/* Entries found in sections of type SHT_MIPS_OPTIONS.  */
-
-typedef struct
-{
-  unsigned char kind;		/* Determines interpretation of the
-				   variable part of descriptor.  */
-  unsigned char size;		/* Size of descriptor, including header.  */
-  Elf32_Section section;	/* Section header index of section affected,
-				   0 for global options.  */
-  Elf32_Word info;		/* Kind-specific information.  */
-} Elf_Options;
-
-/* Values for `kind' field in Elf_Options.  */
-
-#define ODK_NULL	0	/* Undefined.  */
-#define ODK_REGINFO	1	/* Register usage information.  */
-#define ODK_EXCEPTIONS	2	/* Exception processing options.  */
-#define ODK_PAD		3	/* Section padding options.  */
-#define ODK_HWPATCH	4	/* Hardware workarounds performed */
-#define ODK_FILL	5	/* record the fill value used by the linker. */
-#define ODK_TAGS	6	/* reserve space for desktop tools to write. */
-#define ODK_HWAND	7	/* HW workarounds.  'AND' bits when merging. */
-#define ODK_HWOR	8	/* HW workarounds.  'OR' bits when merging.  */
-
-/* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */
-
-#define OEX_FPU_MIN	0x1f	/* FPE's which MUST be enabled.  */
-#define OEX_FPU_MAX	0x1f00	/* FPE's which MAY be enabled.  */
-#define OEX_PAGE0	0x10000	/* page zero must be mapped.  */
-#define OEX_SMM		0x20000	/* Force sequential memory mode?  */
-#define OEX_FPDBUG	0x40000	/* Force floating point debug mode?  */
-#define OEX_PRECISEFP	OEX_FPDBUG
-#define OEX_DISMISS	0x80000	/* Dismiss invalid address faults?  */
-
-#define OEX_FPU_INVAL	0x10
-#define OEX_FPU_DIV0	0x08
-#define OEX_FPU_OFLO	0x04
-#define OEX_FPU_UFLO	0x02
-#define OEX_FPU_INEX	0x01
-
-/* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */
-
-#define OHW_R4KEOP	0x1	/* R4000 end-of-page patch.  */
-#define OHW_R8KPFETCH	0x2	/* may need R8000 prefetch patch.  */
-#define OHW_R5KEOP	0x4	/* R5000 end-of-page patch.  */
-#define OHW_R5KCVTL	0x8	/* R5000 cvt.[ds].l bug.  clean=1.  */
-
-#define OPAD_PREFIX	0x1
-#define OPAD_POSTFIX	0x2
-#define OPAD_SYMBOL	0x4
-
-/* Entry found in `.options' section.  */
-
-typedef struct
-{
-  Elf32_Word hwp_flags1;	/* Extra flags.  */
-  Elf32_Word hwp_flags2;	/* Extra flags.  */
-} Elf_Options_Hw;
-
-/* Masks for `info' in ElfOptions for ODK_HWAND and ODK_HWOR entries.  */
-
-#define OHWA0_R4KEOP_CHECKED	0x00000001
-#define OHWA1_R4KEOP_CLEAN	0x00000002
-
-/* MIPS relocs.  */
-
-#define R_MIPS_NONE		0	/* No reloc */
-#define R_MIPS_16		1	/* Direct 16 bit */
-#define R_MIPS_32		2	/* Direct 32 bit */
-#define R_MIPS_REL32		3	/* PC relative 32 bit */
-#define R_MIPS_26		4	/* Direct 26 bit shifted */
-#define R_MIPS_HI16		5	/* High 16 bit */
-#define R_MIPS_LO16		6	/* Low 16 bit */
-#define R_MIPS_GPREL16		7	/* GP relative 16 bit */
-#define R_MIPS_LITERAL		8	/* 16 bit literal entry */
-#define R_MIPS_GOT16		9	/* 16 bit GOT entry */
-#define R_MIPS_PC16		10	/* PC relative 16 bit */
-#define R_MIPS_CALL16		11	/* 16 bit GOT entry for function */
-#define R_MIPS_GPREL32		12	/* GP relative 32 bit */
-
-#define R_MIPS_SHIFT5		16
-#define R_MIPS_SHIFT6		17
-#define R_MIPS_64		18
-#define R_MIPS_GOT_DISP		19
-#define R_MIPS_GOT_PAGE		20
-#define R_MIPS_GOT_OFST		21
-#define R_MIPS_GOT_HI16		22
-#define R_MIPS_GOT_LO16		23
-#define R_MIPS_SUB		24
-#define R_MIPS_INSERT_A		25
-#define R_MIPS_INSERT_B		26
-#define R_MIPS_DELETE		27
-#define R_MIPS_HIGHER		28
-#define R_MIPS_HIGHEST		29
-#define R_MIPS_CALL_HI16	30
-#define R_MIPS_CALL_LO16	31
-#define R_MIPS_SCN_DISP		32
-#define R_MIPS_REL16		33
-#define R_MIPS_ADD_IMMEDIATE	34
-#define R_MIPS_PJUMP		35
-#define R_MIPS_RELGOT		36
-#define R_MIPS_JALR		37
-#define R_MIPS_TLS_DTPMOD32	38	/* Module number 32 bit */
-#define R_MIPS_TLS_DTPREL32	39	/* Module-relative offset 32 bit */
-#define R_MIPS_TLS_DTPMOD64	40	/* Module number 64 bit */
-#define R_MIPS_TLS_DTPREL64	41	/* Module-relative offset 64 bit */
-#define R_MIPS_TLS_GD		42	/* 16 bit GOT offset for GD */
-#define R_MIPS_TLS_LDM		43	/* 16 bit GOT offset for LDM */
-#define R_MIPS_TLS_DTPREL_HI16	44	/* Module-relative offset, high 16 bits */
-#define R_MIPS_TLS_DTPREL_LO16	45	/* Module-relative offset, low 16 bits */
-#define R_MIPS_TLS_GOTTPREL	46	/* 16 bit GOT offset for IE */
-#define R_MIPS_TLS_TPREL32	47	/* TP-relative offset, 32 bit */
-#define R_MIPS_TLS_TPREL64	48	/* TP-relative offset, 64 bit */
-#define R_MIPS_TLS_TPREL_HI16	49	/* TP-relative offset, high 16 bits */
-#define R_MIPS_TLS_TPREL_LO16	50	/* TP-relative offset, low 16 bits */
-#define R_MIPS_GLOB_DAT		51
-#define R_MIPS_COPY		126
-#define R_MIPS_JUMP_SLOT        127
-/* Keep this the last entry.  */
-#define R_MIPS_NUM		128
-
-/* Legal values for p_type field of Elf32_Phdr.  */
-
-#define PT_MIPS_REGINFO	  0x70000000	/* Register usage information. */
-#define PT_MIPS_RTPROC	  0x70000001	/* Runtime procedure table. */
-#define PT_MIPS_OPTIONS	  0x70000002
-#define PT_MIPS_ABIFLAGS  0x70000003	/* FP mode requirement. */
-
-/* Special program header types.  */
-
-#define PF_MIPS_LOCAL	0x10000000
-
-/* Legal values for d_tag field of Elf32_Dyn.  */
-
-#define DT_MIPS_RLD_VERSION  0x70000001	/* Runtime linker interface version */
-#define DT_MIPS_TIME_STAMP   0x70000002	/* Timestamp */
-#define DT_MIPS_ICHECKSUM    0x70000003	/* Checksum */
-#define DT_MIPS_IVERSION     0x70000004	/* Version string (string tbl index) */
-#define DT_MIPS_FLAGS	     0x70000005	/* Flags */
-#define DT_MIPS_BASE_ADDRESS 0x70000006	/* Base address */
-#define DT_MIPS_MSYM	     0x70000007
-#define DT_MIPS_CONFLICT     0x70000008	/* Address of CONFLICT section */
-#define DT_MIPS_LIBLIST	     0x70000009	/* Address of LIBLIST section */
-#define DT_MIPS_LOCAL_GOTNO  0x7000000a	/* Number of local GOT entries */
-#define DT_MIPS_CONFLICTNO   0x7000000b	/* Number of CONFLICT entries */
-#define DT_MIPS_LIBLISTNO    0x70000010	/* Number of LIBLIST entries */
-#define DT_MIPS_SYMTABNO     0x70000011	/* Number of DYNSYM entries */
-#define DT_MIPS_UNREFEXTNO   0x70000012	/* First external DYNSYM */
-#define DT_MIPS_GOTSYM	     0x70000013	/* First GOT entry in DYNSYM */
-#define DT_MIPS_HIPAGENO     0x70000014	/* Number of GOT page table entries */
-#define DT_MIPS_RLD_MAP	     0x70000016	/* Address of run time loader map.  */
-#define DT_MIPS_DELTA_CLASS  0x70000017	/* Delta C++ class definition.  */
-#define DT_MIPS_DELTA_CLASS_NO    0x70000018 /* Number of entries in
-						DT_MIPS_DELTA_CLASS.  */
-#define DT_MIPS_DELTA_INSTANCE    0x70000019 /* Delta C++ class instances.  */
-#define DT_MIPS_DELTA_INSTANCE_NO 0x7000001a /* Number of entries in
-						DT_MIPS_DELTA_INSTANCE.  */
-#define DT_MIPS_DELTA_RELOC  0x7000001b /* Delta relocations.  */
-#define DT_MIPS_DELTA_RELOC_NO 0x7000001c /* Number of entries in
-					     DT_MIPS_DELTA_RELOC.  */
-#define DT_MIPS_DELTA_SYM    0x7000001d /* Delta symbols that Delta
-					   relocations refer to.  */
-#define DT_MIPS_DELTA_SYM_NO 0x7000001e /* Number of entries in
-					   DT_MIPS_DELTA_SYM.  */
-#define DT_MIPS_DELTA_CLASSSYM 0x70000020 /* Delta symbols that hold the
-					     class declaration.  */
-#define DT_MIPS_DELTA_CLASSSYM_NO 0x70000021 /* Number of entries in
-						DT_MIPS_DELTA_CLASSSYM.  */
-#define DT_MIPS_CXX_FLAGS    0x70000022 /* Flags indicating for C++ flavor.  */
-#define DT_MIPS_PIXIE_INIT   0x70000023
-#define DT_MIPS_SYMBOL_LIB   0x70000024
-#define DT_MIPS_LOCALPAGE_GOTIDX 0x70000025
-#define DT_MIPS_LOCAL_GOTIDX 0x70000026
-#define DT_MIPS_HIDDEN_GOTIDX 0x70000027
-#define DT_MIPS_PROTECTED_GOTIDX 0x70000028
-#define DT_MIPS_OPTIONS	     0x70000029 /* Address of .options.  */
-#define DT_MIPS_INTERFACE    0x7000002a /* Address of .interface.  */
-#define DT_MIPS_DYNSTR_ALIGN 0x7000002b
-#define DT_MIPS_INTERFACE_SIZE 0x7000002c /* Size of the .interface section. */
-#define DT_MIPS_RLD_TEXT_RESOLVE_ADDR 0x7000002d /* Address of rld_text_rsolve
-						    function stored in GOT.  */
-#define DT_MIPS_PERF_SUFFIX  0x7000002e /* Default suffix of dso to be added
-					   by rld on dlopen() calls.  */
-#define DT_MIPS_COMPACT_SIZE 0x7000002f /* (O32)Size of compact rel section. */
-#define DT_MIPS_GP_VALUE     0x70000030 /* GP value for aux GOTs.  */
-#define DT_MIPS_AUX_DYNAMIC  0x70000031 /* Address of aux .dynamic.  */
-/* The address of .got.plt in an executable using the new non-PIC ABI.  */
-#define DT_MIPS_PLTGOT	     0x70000032
-/* The base of the PLT in an executable using the new non-PIC ABI if that
-   PLT is writable.  For a non-writable PLT, this is omitted or has a zero
-   value.  */
-#define DT_MIPS_RWPLT        0x70000034
-#define DT_MIPS_NUM	     0x35
-
-/* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */
-
-#define RHF_NONE		   0		/* No flags */
-#define RHF_QUICKSTART		   (1 << 0)	/* Use quickstart */
-#define RHF_NOTPOT		   (1 << 1)	/* Hash size not power of 2 */
-#define RHF_NO_LIBRARY_REPLACEMENT (1 << 2)	/* Ignore LD_LIBRARY_PATH */
-#define RHF_NO_MOVE		   (1 << 3)
-#define RHF_SGI_ONLY		   (1 << 4)
-#define RHF_GUARANTEE_INIT	   (1 << 5)
-#define RHF_DELTA_C_PLUS_PLUS	   (1 << 6)
-#define RHF_GUARANTEE_START_INIT   (1 << 7)
-#define RHF_PIXIE		   (1 << 8)
-#define RHF_DEFAULT_DELAY_LOAD	   (1 << 9)
-#define RHF_REQUICKSTART	   (1 << 10)
-#define RHF_REQUICKSTARTED	   (1 << 11)
-#define RHF_CORD		   (1 << 12)
-#define RHF_NO_UNRES_UNDEF	   (1 << 13)
-#define RHF_RLD_ORDER_SAFE	   (1 << 14)
-
-/* Entries found in sections of type SHT_MIPS_LIBLIST.  */
-
-typedef struct
-{
-  Elf32_Word l_name;		/* Name (string table index) */
-  Elf32_Word l_time_stamp;	/* Timestamp */
-  Elf32_Word l_checksum;	/* Checksum */
-  Elf32_Word l_version;		/* Interface version */
-  Elf32_Word l_flags;		/* Flags */
-} Elf32_Lib;
-
-typedef struct
-{
-  Elf64_Word l_name;		/* Name (string table index) */
-  Elf64_Word l_time_stamp;	/* Timestamp */
-  Elf64_Word l_checksum;	/* Checksum */
-  Elf64_Word l_version;		/* Interface version */
-  Elf64_Word l_flags;		/* Flags */
-} Elf64_Lib;
-
-
-/* Legal values for l_flags.  */
-
-#define LL_NONE		  0
-#define LL_EXACT_MATCH	  (1 << 0)	/* Require exact match */
-#define LL_IGNORE_INT_VER (1 << 1)	/* Ignore interface version */
-#define LL_REQUIRE_MINOR  (1 << 2)
-#define LL_EXPORTS	  (1 << 3)
-#define LL_DELAY_LOAD	  (1 << 4)
-#define LL_DELTA	  (1 << 5)
-
-/* Entries found in sections of type SHT_MIPS_CONFLICT.  */
-
-typedef Elf32_Addr Elf32_Conflict;
-
-typedef struct
-{
-  /* Version of flags structure.  */
-  Elf32_Half version;
-  /* The level of the ISA: 1-5, 32, 64.  */
-  unsigned char isa_level;
-  /* The revision of ISA: 0 for MIPS V and below, 1-n otherwise.  */
-  unsigned char isa_rev;
-  /* The size of general purpose registers.  */
-  unsigned char gpr_size;
-  /* The size of co-processor 1 registers.  */
-  unsigned char cpr1_size;
-  /* The size of co-processor 2 registers.  */
-  unsigned char cpr2_size;
-  /* The floating-point ABI.  */
-  unsigned char fp_abi;
-  /* Processor-specific extension.  */
-  Elf32_Word isa_ext;
-  /* Mask of ASEs used.  */
-  Elf32_Word ases;
-  /* Mask of general flags.  */
-  Elf32_Word flags1;
-  Elf32_Word flags2;
-} Elf_MIPS_ABIFlags_v0;
-
-/* Values for the register size bytes of an abi flags structure.  */
-
-#define MIPS_AFL_REG_NONE	0x00	 /* No registers.  */
-#define MIPS_AFL_REG_32		0x01	 /* 32-bit registers.  */
-#define MIPS_AFL_REG_64		0x02	 /* 64-bit registers.  */
-#define MIPS_AFL_REG_128	0x03	 /* 128-bit registers.  */
-
-/* Masks for the ases word of an ABI flags structure.  */
-
-#define MIPS_AFL_ASE_DSP	0x00000001 /* DSP ASE.  */
-#define MIPS_AFL_ASE_DSPR2	0x00000002 /* DSP R2 ASE.  */
-#define MIPS_AFL_ASE_EVA	0x00000004 /* Enhanced VA Scheme.  */
-#define MIPS_AFL_ASE_MCU	0x00000008 /* MCU (MicroController) ASE.  */
-#define MIPS_AFL_ASE_MDMX	0x00000010 /* MDMX ASE.  */
-#define MIPS_AFL_ASE_MIPS3D	0x00000020 /* MIPS-3D ASE.  */
-#define MIPS_AFL_ASE_MT		0x00000040 /* MT ASE.  */
-#define MIPS_AFL_ASE_SMARTMIPS	0x00000080 /* SmartMIPS ASE.  */
-#define MIPS_AFL_ASE_VIRT	0x00000100 /* VZ ASE.  */
-#define MIPS_AFL_ASE_MSA	0x00000200 /* MSA ASE.  */
-#define MIPS_AFL_ASE_MIPS16	0x00000400 /* MIPS16 ASE.  */
-#define MIPS_AFL_ASE_MICROMIPS	0x00000800 /* MICROMIPS ASE.  */
-#define MIPS_AFL_ASE_XPA	0x00001000 /* XPA ASE.  */
-#define MIPS_AFL_ASE_MASK	0x00001fff /* All ASEs.  */
-
-/* Values for the isa_ext word of an ABI flags structure.  */
-
-#define MIPS_AFL_EXT_XLR	  1   /* RMI Xlr instruction.  */
-#define MIPS_AFL_EXT_OCTEON2	  2   /* Cavium Networks Octeon2.  */
-#define MIPS_AFL_EXT_OCTEONP	  3   /* Cavium Networks OcteonP.  */
-#define MIPS_AFL_EXT_LOONGSON_3A  4   /* Loongson 3A.  */
-#define MIPS_AFL_EXT_OCTEON	  5   /* Cavium Networks Octeon.  */
-#define MIPS_AFL_EXT_5900	  6   /* MIPS R5900 instruction.  */
-#define MIPS_AFL_EXT_4650	  7   /* MIPS R4650 instruction.  */
-#define MIPS_AFL_EXT_4010	  8   /* LSI R4010 instruction.  */
-#define MIPS_AFL_EXT_4100	  9   /* NEC VR4100 instruction.  */
-#define MIPS_AFL_EXT_3900	  10  /* Toshiba R3900 instruction.  */
-#define MIPS_AFL_EXT_10000	  11  /* MIPS R10000 instruction.  */
-#define MIPS_AFL_EXT_SB1	  12  /* Broadcom SB-1 instruction.  */
-#define MIPS_AFL_EXT_4111	  13  /* NEC VR4111/VR4181 instruction.  */
-#define MIPS_AFL_EXT_4120	  14  /* NEC VR4120 instruction.  */
-#define MIPS_AFL_EXT_5400	  15  /* NEC VR5400 instruction.  */
-#define MIPS_AFL_EXT_5500	  16  /* NEC VR5500 instruction.  */
-#define MIPS_AFL_EXT_LOONGSON_2E  17  /* ST Microelectronics Loongson 2E.  */
-#define MIPS_AFL_EXT_LOONGSON_2F  18  /* ST Microelectronics Loongson 2F.  */
-
-/* Masks for the flags1 word of an ABI flags structure.  */
-#define MIPS_AFL_FLAGS1_ODDSPREG  1  /* Uses odd single-precision registers.  */
-
-/* Object attribute values.  */
-enum
-{
-  /* Not tagged or not using any ABIs affected by the differences.  */
-  Val_GNU_MIPS_ABI_FP_ANY = 0,
-  /* Using hard-float -mdouble-float.  */
-  Val_GNU_MIPS_ABI_FP_DOUBLE = 1,
-  /* Using hard-float -msingle-float.  */
-  Val_GNU_MIPS_ABI_FP_SINGLE = 2,
-  /* Using soft-float.  */
-  Val_GNU_MIPS_ABI_FP_SOFT = 3,
-  /* Using -mips32r2 -mfp64.  */
-  Val_GNU_MIPS_ABI_FP_OLD_64 = 4,
-  /* Using -mfpxx.  */
-  Val_GNU_MIPS_ABI_FP_XX = 5,
-  /* Using -mips32r2 -mfp64.  */
-  Val_GNU_MIPS_ABI_FP_64 = 6,
-  /* Using -mips32r2 -mfp64 -mno-odd-spreg.  */
-  Val_GNU_MIPS_ABI_FP_64A = 7,
-  /* Maximum allocated FP ABI value.  */
-  Val_GNU_MIPS_ABI_FP_MAX = 7
-};
-
-/* HPPA specific definitions.  */
-
-/* Legal values for e_flags field of Elf32_Ehdr.  */
-
-#define EF_PARISC_TRAPNIL	0x00010000 /* Trap nil pointer dereference.  */
-#define EF_PARISC_EXT		0x00020000 /* Program uses arch. extensions. */
-#define EF_PARISC_LSB		0x00040000 /* Program expects little endian. */
-#define EF_PARISC_WIDE		0x00080000 /* Program expects wide mode.  */
-#define EF_PARISC_NO_KABP	0x00100000 /* No kernel assisted branch
-					      prediction.  */
-#define EF_PARISC_LAZYSWAP	0x00400000 /* Allow lazy swapping.  */
-#define EF_PARISC_ARCH		0x0000ffff /* Architecture version.  */
-
-/* Defined values for `e_flags & EF_PARISC_ARCH' are:  */
-
-#define EFA_PARISC_1_0		    0x020b /* PA-RISC 1.0 big-endian.  */
-#define EFA_PARISC_1_1		    0x0210 /* PA-RISC 1.1 big-endian.  */
-#define EFA_PARISC_2_0		    0x0214 /* PA-RISC 2.0 big-endian.  */
-
-/* Additional section indeces.  */
-
-#define SHN_PARISC_ANSI_COMMON	0xff00	   /* Section for tenatively declared
-					      symbols in ANSI C.  */
-#define SHN_PARISC_HUGE_COMMON	0xff01	   /* Common blocks in huge model.  */
-
-/* Legal values for sh_type field of Elf32_Shdr.  */
-
-#define SHT_PARISC_EXT		0x70000000 /* Contains product specific ext. */
-#define SHT_PARISC_UNWIND	0x70000001 /* Unwind information.  */
-#define SHT_PARISC_DOC		0x70000002 /* Debug info for optimized code. */
-
-/* Legal values for sh_flags field of Elf32_Shdr.  */
-
-#define SHF_PARISC_SHORT	0x20000000 /* Section with short addressing. */
-#define SHF_PARISC_HUGE		0x40000000 /* Section far from gp.  */
-#define SHF_PARISC_SBP		0x80000000 /* Static branch prediction code. */
-
-/* Legal values for ST_TYPE subfield of st_info (symbol type).  */
-
-#define STT_PARISC_MILLICODE	13	/* Millicode function entry point.  */
-
-#define STT_HP_OPAQUE		(STT_LOOS + 0x1)
-#define STT_HP_STUB		(STT_LOOS + 0x2)
-
-/* HPPA relocs.  */
-
-#define R_PARISC_NONE		0	/* No reloc.  */
-#define R_PARISC_DIR32		1	/* Direct 32-bit reference.  */
-#define R_PARISC_DIR21L		2	/* Left 21 bits of eff. address.  */
-#define R_PARISC_DIR17R		3	/* Right 17 bits of eff. address.  */
-#define R_PARISC_DIR17F		4	/* 17 bits of eff. address.  */
-#define R_PARISC_DIR14R		6	/* Right 14 bits of eff. address.  */
-#define R_PARISC_PCREL32	9	/* 32-bit rel. address.  */
-#define R_PARISC_PCREL21L	10	/* Left 21 bits of rel. address.  */
-#define R_PARISC_PCREL17R	11	/* Right 17 bits of rel. address.  */
-#define R_PARISC_PCREL17F	12	/* 17 bits of rel. address.  */
-#define R_PARISC_PCREL14R	14	/* Right 14 bits of rel. address.  */
-#define R_PARISC_DPREL21L	18	/* Left 21 bits of rel. address.  */
-#define R_PARISC_DPREL14R	22	/* Right 14 bits of rel. address.  */
-#define R_PARISC_GPREL21L	26	/* GP-relative, left 21 bits.  */
-#define R_PARISC_GPREL14R	30	/* GP-relative, right 14 bits.  */
-#define R_PARISC_LTOFF21L	34	/* LT-relative, left 21 bits.  */
-#define R_PARISC_LTOFF14R	38	/* LT-relative, right 14 bits.  */
-#define R_PARISC_SECREL32	41	/* 32 bits section rel. address.  */
-#define R_PARISC_SEGBASE	48	/* No relocation, set segment base.  */
-#define R_PARISC_SEGREL32	49	/* 32 bits segment rel. address.  */
-#define R_PARISC_PLTOFF21L	50	/* PLT rel. address, left 21 bits.  */
-#define R_PARISC_PLTOFF14R	54	/* PLT rel. address, right 14 bits.  */
-#define R_PARISC_LTOFF_FPTR32	57	/* 32 bits LT-rel. function pointer. */
-#define R_PARISC_LTOFF_FPTR21L	58	/* LT-rel. fct ptr, left 21 bits. */
-#define R_PARISC_LTOFF_FPTR14R	62	/* LT-rel. fct ptr, right 14 bits. */
-#define R_PARISC_FPTR64		64	/* 64 bits function address.  */
-#define R_PARISC_PLABEL32	65	/* 32 bits function address.  */
-#define R_PARISC_PLABEL21L	66	/* Left 21 bits of fdesc address.  */
-#define R_PARISC_PLABEL14R	70	/* Right 14 bits of fdesc address.  */
-#define R_PARISC_PCREL64	72	/* 64 bits PC-rel. address.  */
-#define R_PARISC_PCREL22F	74	/* 22 bits PC-rel. address.  */
-#define R_PARISC_PCREL14WR	75	/* PC-rel. address, right 14 bits.  */
-#define R_PARISC_PCREL14DR	76	/* PC rel. address, right 14 bits.  */
-#define R_PARISC_PCREL16F	77	/* 16 bits PC-rel. address.  */
-#define R_PARISC_PCREL16WF	78	/* 16 bits PC-rel. address.  */
-#define R_PARISC_PCREL16DF	79	/* 16 bits PC-rel. address.  */
-#define R_PARISC_DIR64		80	/* 64 bits of eff. address.  */
-#define R_PARISC_DIR14WR	83	/* 14 bits of eff. address.  */
-#define R_PARISC_DIR14DR	84	/* 14 bits of eff. address.  */
-#define R_PARISC_DIR16F		85	/* 16 bits of eff. address.  */
-#define R_PARISC_DIR16WF	86	/* 16 bits of eff. address.  */
-#define R_PARISC_DIR16DF	87	/* 16 bits of eff. address.  */
-#define R_PARISC_GPREL64	88	/* 64 bits of GP-rel. address.  */
-#define R_PARISC_GPREL14WR	91	/* GP-rel. address, right 14 bits.  */
-#define R_PARISC_GPREL14DR	92	/* GP-rel. address, right 14 bits.  */
-#define R_PARISC_GPREL16F	93	/* 16 bits GP-rel. address.  */
-#define R_PARISC_GPREL16WF	94	/* 16 bits GP-rel. address.  */
-#define R_PARISC_GPREL16DF	95	/* 16 bits GP-rel. address.  */
-#define R_PARISC_LTOFF64	96	/* 64 bits LT-rel. address.  */
-#define R_PARISC_LTOFF14WR	99	/* LT-rel. address, right 14 bits.  */
-#define R_PARISC_LTOFF14DR	100	/* LT-rel. address, right 14 bits.  */
-#define R_PARISC_LTOFF16F	101	/* 16 bits LT-rel. address.  */
-#define R_PARISC_LTOFF16WF	102	/* 16 bits LT-rel. address.  */
-#define R_PARISC_LTOFF16DF	103	/* 16 bits LT-rel. address.  */
-#define R_PARISC_SECREL64	104	/* 64 bits section rel. address.  */
-#define R_PARISC_SEGREL64	112	/* 64 bits segment rel. address.  */
-#define R_PARISC_PLTOFF14WR	115	/* PLT-rel. address, right 14 bits.  */
-#define R_PARISC_PLTOFF14DR	116	/* PLT-rel. address, right 14 bits.  */
-#define R_PARISC_PLTOFF16F	117	/* 16 bits LT-rel. address.  */
-#define R_PARISC_PLTOFF16WF	118	/* 16 bits PLT-rel. address.  */
-#define R_PARISC_PLTOFF16DF	119	/* 16 bits PLT-rel. address.  */
-#define R_PARISC_LTOFF_FPTR64	120	/* 64 bits LT-rel. function ptr.  */
-#define R_PARISC_LTOFF_FPTR14WR	123	/* LT-rel. fct. ptr., right 14 bits. */
-#define R_PARISC_LTOFF_FPTR14DR	124	/* LT-rel. fct. ptr., right 14 bits. */
-#define R_PARISC_LTOFF_FPTR16F	125	/* 16 bits LT-rel. function ptr.  */
-#define R_PARISC_LTOFF_FPTR16WF	126	/* 16 bits LT-rel. function ptr.  */
-#define R_PARISC_LTOFF_FPTR16DF	127	/* 16 bits LT-rel. function ptr.  */
-#define R_PARISC_LORESERVE	128
-#define R_PARISC_COPY		128	/* Copy relocation.  */
-#define R_PARISC_IPLT		129	/* Dynamic reloc, imported PLT */
-#define R_PARISC_EPLT		130	/* Dynamic reloc, exported PLT */
-#define R_PARISC_TPREL32	153	/* 32 bits TP-rel. address.  */
-#define R_PARISC_TPREL21L	154	/* TP-rel. address, left 21 bits.  */
-#define R_PARISC_TPREL14R	158	/* TP-rel. address, right 14 bits.  */
-#define R_PARISC_LTOFF_TP21L	162	/* LT-TP-rel. address, left 21 bits. */
-#define R_PARISC_LTOFF_TP14R	166	/* LT-TP-rel. address, right 14 bits.*/
-#define R_PARISC_LTOFF_TP14F	167	/* 14 bits LT-TP-rel. address.  */
-#define R_PARISC_TPREL64	216	/* 64 bits TP-rel. address.  */
-#define R_PARISC_TPREL14WR	219	/* TP-rel. address, right 14 bits.  */
-#define R_PARISC_TPREL14DR	220	/* TP-rel. address, right 14 bits.  */
-#define R_PARISC_TPREL16F	221	/* 16 bits TP-rel. address.  */
-#define R_PARISC_TPREL16WF	222	/* 16 bits TP-rel. address.  */
-#define R_PARISC_TPREL16DF	223	/* 16 bits TP-rel. address.  */
-#define R_PARISC_LTOFF_TP64	224	/* 64 bits LT-TP-rel. address.  */
-#define R_PARISC_LTOFF_TP14WR	227	/* LT-TP-rel. address, right 14 bits.*/
-#define R_PARISC_LTOFF_TP14DR	228	/* LT-TP-rel. address, right 14 bits.*/
-#define R_PARISC_LTOFF_TP16F	229	/* 16 bits LT-TP-rel. address.  */
-#define R_PARISC_LTOFF_TP16WF	230	/* 16 bits LT-TP-rel. address.  */
-#define R_PARISC_LTOFF_TP16DF	231	/* 16 bits LT-TP-rel. address.  */
-#define R_PARISC_GNU_VTENTRY	232
-#define R_PARISC_GNU_VTINHERIT	233
-#define R_PARISC_TLS_GD21L	234	/* GD 21-bit left.  */
-#define R_PARISC_TLS_GD14R	235	/* GD 14-bit right.  */
-#define R_PARISC_TLS_GDCALL	236	/* GD call to __t_g_a.  */
-#define R_PARISC_TLS_LDM21L	237	/* LD module 21-bit left.  */
-#define R_PARISC_TLS_LDM14R	238	/* LD module 14-bit right.  */
-#define R_PARISC_TLS_LDMCALL	239	/* LD module call to __t_g_a.  */
-#define R_PARISC_TLS_LDO21L	240	/* LD offset 21-bit left.  */
-#define R_PARISC_TLS_LDO14R	241	/* LD offset 14-bit right.  */
-#define R_PARISC_TLS_DTPMOD32	242	/* DTP module 32-bit.  */
-#define R_PARISC_TLS_DTPMOD64	243	/* DTP module 64-bit.  */
-#define R_PARISC_TLS_DTPOFF32	244	/* DTP offset 32-bit.  */
-#define R_PARISC_TLS_DTPOFF64	245	/* DTP offset 32-bit.  */
-#define R_PARISC_TLS_LE21L	R_PARISC_TPREL21L
-#define R_PARISC_TLS_LE14R	R_PARISC_TPREL14R
-#define R_PARISC_TLS_IE21L	R_PARISC_LTOFF_TP21L
-#define R_PARISC_TLS_IE14R	R_PARISC_LTOFF_TP14R
-#define R_PARISC_TLS_TPREL32	R_PARISC_TPREL32
-#define R_PARISC_TLS_TPREL64	R_PARISC_TPREL64
-#define R_PARISC_HIRESERVE	255
-
-/* Legal values for p_type field of Elf32_Phdr/Elf64_Phdr.  */
-
-#define PT_HP_TLS		(PT_LOOS + 0x0)
-#define PT_HP_CORE_NONE		(PT_LOOS + 0x1)
-#define PT_HP_CORE_VERSION	(PT_LOOS + 0x2)
-#define PT_HP_CORE_KERNEL	(PT_LOOS + 0x3)
-#define PT_HP_CORE_COMM		(PT_LOOS + 0x4)
-#define PT_HP_CORE_PROC		(PT_LOOS + 0x5)
-#define PT_HP_CORE_LOADABLE	(PT_LOOS + 0x6)
-#define PT_HP_CORE_STACK	(PT_LOOS + 0x7)
-#define PT_HP_CORE_SHM		(PT_LOOS + 0x8)
-#define PT_HP_CORE_MMF		(PT_LOOS + 0x9)
-#define PT_HP_PARALLEL		(PT_LOOS + 0x10)
-#define PT_HP_FASTBIND		(PT_LOOS + 0x11)
-#define PT_HP_OPT_ANNOT		(PT_LOOS + 0x12)
-#define PT_HP_HSL_ANNOT		(PT_LOOS + 0x13)
-#define PT_HP_STACK		(PT_LOOS + 0x14)
-
-#define PT_PARISC_ARCHEXT	0x70000000
-#define PT_PARISC_UNWIND	0x70000001
-
-/* Legal values for p_flags field of Elf32_Phdr/Elf64_Phdr.  */
-
-#define PF_PARISC_SBP		0x08000000
-
-#define PF_HP_PAGE_SIZE		0x00100000
-#define PF_HP_FAR_SHARED	0x00200000
-#define PF_HP_NEAR_SHARED	0x00400000
-#define PF_HP_CODE		0x01000000
-#define PF_HP_MODIFY		0x02000000
-#define PF_HP_LAZYSWAP		0x04000000
-#define PF_HP_SBP		0x08000000
-
-
-/* Alpha specific definitions.  */
-
-/* Legal values for e_flags field of Elf64_Ehdr.  */
-
-#define EF_ALPHA_32BIT		1	/* All addresses must be < 2GB.  */
-#define EF_ALPHA_CANRELAX	2	/* Relocations for relaxing exist.  */
-
-/* Legal values for sh_type field of Elf64_Shdr.  */
-
-/* These two are primerily concerned with ECOFF debugging info.  */
-#define SHT_ALPHA_DEBUG		0x70000001
-#define SHT_ALPHA_REGINFO	0x70000002
-
-/* Legal values for sh_flags field of Elf64_Shdr.  */
-
-#define SHF_ALPHA_GPREL		0x10000000
-
-/* Legal values for st_other field of Elf64_Sym.  */
-#define STO_ALPHA_NOPV		0x80	/* No PV required.  */
-#define STO_ALPHA_STD_GPLOAD	0x88	/* PV only used for initial ldgp.  */
-
-/* Alpha relocs.  */
-
-#define R_ALPHA_NONE		0	/* No reloc */
-#define R_ALPHA_REFLONG		1	/* Direct 32 bit */
-#define R_ALPHA_REFQUAD		2	/* Direct 64 bit */
-#define R_ALPHA_GPREL32		3	/* GP relative 32 bit */
-#define R_ALPHA_LITERAL		4	/* GP relative 16 bit w/optimization */
-#define R_ALPHA_LITUSE		5	/* Optimization hint for LITERAL */
-#define R_ALPHA_GPDISP		6	/* Add displacement to GP */
-#define R_ALPHA_BRADDR		7	/* PC+4 relative 23 bit shifted */
-#define R_ALPHA_HINT		8	/* PC+4 relative 16 bit shifted */
-#define R_ALPHA_SREL16		9	/* PC relative 16 bit */
-#define R_ALPHA_SREL32		10	/* PC relative 32 bit */
-#define R_ALPHA_SREL64		11	/* PC relative 64 bit */
-#define R_ALPHA_GPRELHIGH	17	/* GP relative 32 bit, high 16 bits */
-#define R_ALPHA_GPRELLOW	18	/* GP relative 32 bit, low 16 bits */
-#define R_ALPHA_GPREL16		19	/* GP relative 16 bit */
-#define R_ALPHA_COPY		24	/* Copy symbol at runtime */
-#define R_ALPHA_GLOB_DAT	25	/* Create GOT entry */
-#define R_ALPHA_JMP_SLOT	26	/* Create PLT entry */
-#define R_ALPHA_RELATIVE	27	/* Adjust by program base */
-#define R_ALPHA_TLS_GD_HI	28
-#define R_ALPHA_TLSGD		29
-#define R_ALPHA_TLS_LDM		30
-#define R_ALPHA_DTPMOD64	31
-#define R_ALPHA_GOTDTPREL	32
-#define R_ALPHA_DTPREL64	33
-#define R_ALPHA_DTPRELHI	34
-#define R_ALPHA_DTPRELLO	35
-#define R_ALPHA_DTPREL16	36
-#define R_ALPHA_GOTTPREL	37
-#define R_ALPHA_TPREL64		38
-#define R_ALPHA_TPRELHI		39
-#define R_ALPHA_TPRELLO		40
-#define R_ALPHA_TPREL16		41
-/* Keep this the last entry.  */
-#define R_ALPHA_NUM		46
-
-/* Magic values of the LITUSE relocation addend.  */
-#define LITUSE_ALPHA_ADDR	0
-#define LITUSE_ALPHA_BASE	1
-#define LITUSE_ALPHA_BYTOFF	2
-#define LITUSE_ALPHA_JSR	3
-#define LITUSE_ALPHA_TLS_GD	4
-#define LITUSE_ALPHA_TLS_LDM	5
-
-/* Legal values for d_tag of Elf64_Dyn.  */
-#define DT_ALPHA_PLTRO		(DT_LOPROC + 0)
-#define DT_ALPHA_NUM		1
-
-/* PowerPC specific declarations */
-
-/* Values for Elf32/64_Ehdr.e_flags.  */
-#define EF_PPC_EMB		0x80000000	/* PowerPC embedded flag */
-
-/* Cygnus local bits below */
-#define EF_PPC_RELOCATABLE	0x00010000	/* PowerPC -mrelocatable flag*/
-#define EF_PPC_RELOCATABLE_LIB	0x00008000	/* PowerPC -mrelocatable-lib
-						   flag */
-
-/* PowerPC relocations defined by the ABIs */
-#define R_PPC_NONE		0
-#define R_PPC_ADDR32		1	/* 32bit absolute address */
-#define R_PPC_ADDR24		2	/* 26bit address, 2 bits ignored.  */
-#define R_PPC_ADDR16		3	/* 16bit absolute address */
-#define R_PPC_ADDR16_LO		4	/* lower 16bit of absolute address */
-#define R_PPC_ADDR16_HI		5	/* high 16bit of absolute address */
-#define R_PPC_ADDR16_HA		6	/* adjusted high 16bit */
-#define R_PPC_ADDR14		7	/* 16bit address, 2 bits ignored */
-#define R_PPC_ADDR14_BRTAKEN	8
-#define R_PPC_ADDR14_BRNTAKEN	9
-#define R_PPC_REL24		10	/* PC relative 26 bit */
-#define R_PPC_REL14		11	/* PC relative 16 bit */
-#define R_PPC_REL14_BRTAKEN	12
-#define R_PPC_REL14_BRNTAKEN	13
-#define R_PPC_GOT16		14
-#define R_PPC_GOT16_LO		15
-#define R_PPC_GOT16_HI		16
-#define R_PPC_GOT16_HA		17
-#define R_PPC_PLTREL24		18
-#define R_PPC_COPY		19
-#define R_PPC_GLOB_DAT		20
-#define R_PPC_JMP_SLOT		21
-#define R_PPC_RELATIVE		22
-#define R_PPC_LOCAL24PC		23
-#define R_PPC_UADDR32		24
-#define R_PPC_UADDR16		25
-#define R_PPC_REL32		26
-#define R_PPC_PLT32		27
-#define R_PPC_PLTREL32		28
-#define R_PPC_PLT16_LO		29
-#define R_PPC_PLT16_HI		30
-#define R_PPC_PLT16_HA		31
-#define R_PPC_SDAREL16		32
-#define R_PPC_SECTOFF		33
-#define R_PPC_SECTOFF_LO	34
-#define R_PPC_SECTOFF_HI	35
-#define R_PPC_SECTOFF_HA	36
-
-/* PowerPC relocations defined for the TLS access ABI.  */
-#define R_PPC_TLS		67 /* none	(sym+add)@tls */
-#define R_PPC_DTPMOD32		68 /* word32	(sym+add)@dtpmod */
-#define R_PPC_TPREL16		69 /* half16*	(sym+add)@tprel */
-#define R_PPC_TPREL16_LO	70 /* half16	(sym+add)@tprel@l */
-#define R_PPC_TPREL16_HI	71 /* half16	(sym+add)@tprel@h */
-#define R_PPC_TPREL16_HA	72 /* half16	(sym+add)@tprel@ha */
-#define R_PPC_TPREL32		73 /* word32	(sym+add)@tprel */
-#define R_PPC_DTPREL16		74 /* half16*	(sym+add)@dtprel */
-#define R_PPC_DTPREL16_LO	75 /* half16	(sym+add)@dtprel@l */
-#define R_PPC_DTPREL16_HI	76 /* half16	(sym+add)@dtprel@h */
-#define R_PPC_DTPREL16_HA	77 /* half16	(sym+add)@dtprel@ha */
-#define R_PPC_DTPREL32		78 /* word32	(sym+add)@dtprel */
-#define R_PPC_GOT_TLSGD16	79 /* half16*	(sym+add)@got@tlsgd */
-#define R_PPC_GOT_TLSGD16_LO	80 /* half16	(sym+add)@got@tlsgd@l */
-#define R_PPC_GOT_TLSGD16_HI	81 /* half16	(sym+add)@got@tlsgd@h */
-#define R_PPC_GOT_TLSGD16_HA	82 /* half16	(sym+add)@got@tlsgd@ha */
-#define R_PPC_GOT_TLSLD16	83 /* half16*	(sym+add)@got@tlsld */
-#define R_PPC_GOT_TLSLD16_LO	84 /* half16	(sym+add)@got@tlsld@l */
-#define R_PPC_GOT_TLSLD16_HI	85 /* half16	(sym+add)@got@tlsld@h */
-#define R_PPC_GOT_TLSLD16_HA	86 /* half16	(sym+add)@got@tlsld@ha */
-#define R_PPC_GOT_TPREL16	87 /* half16*	(sym+add)@got@tprel */
-#define R_PPC_GOT_TPREL16_LO	88 /* half16	(sym+add)@got@tprel@l */
-#define R_PPC_GOT_TPREL16_HI	89 /* half16	(sym+add)@got@tprel@h */
-#define R_PPC_GOT_TPREL16_HA	90 /* half16	(sym+add)@got@tprel@ha */
-#define R_PPC_GOT_DTPREL16	91 /* half16*	(sym+add)@got@dtprel */
-#define R_PPC_GOT_DTPREL16_LO	92 /* half16*	(sym+add)@got@dtprel@l */
-#define R_PPC_GOT_DTPREL16_HI	93 /* half16*	(sym+add)@got@dtprel@h */
-#define R_PPC_GOT_DTPREL16_HA	94 /* half16*	(sym+add)@got@dtprel@ha */
-#define R_PPC_TLSGD		95 /* none	(sym+add)@tlsgd */
-#define R_PPC_TLSLD		96 /* none	(sym+add)@tlsld */
-
-/* The remaining relocs are from the Embedded ELF ABI, and are not
-   in the SVR4 ELF ABI.  */
-#define R_PPC_EMB_NADDR32	101
-#define R_PPC_EMB_NADDR16	102
-#define R_PPC_EMB_NADDR16_LO	103
-#define R_PPC_EMB_NADDR16_HI	104
-#define R_PPC_EMB_NADDR16_HA	105
-#define R_PPC_EMB_SDAI16	106
-#define R_PPC_EMB_SDA2I16	107
-#define R_PPC_EMB_SDA2REL	108
-#define R_PPC_EMB_SDA21		109	/* 16 bit offset in SDA */
-#define R_PPC_EMB_MRKREF	110
-#define R_PPC_EMB_RELSEC16	111
-#define R_PPC_EMB_RELST_LO	112
-#define R_PPC_EMB_RELST_HI	113
-#define R_PPC_EMB_RELST_HA	114
-#define R_PPC_EMB_BIT_FLD	115
-#define R_PPC_EMB_RELSDA	116	/* 16 bit relative offset in SDA */
-
-/* Diab tool relocations.  */
-#define R_PPC_DIAB_SDA21_LO	180	/* like EMB_SDA21, but lower 16 bit */
-#define R_PPC_DIAB_SDA21_HI	181	/* like EMB_SDA21, but high 16 bit */
-#define R_PPC_DIAB_SDA21_HA	182	/* like EMB_SDA21, adjusted high 16 */
-#define R_PPC_DIAB_RELSDA_LO	183	/* like EMB_RELSDA, but lower 16 bit */
-#define R_PPC_DIAB_RELSDA_HI	184	/* like EMB_RELSDA, but high 16 bit */
-#define R_PPC_DIAB_RELSDA_HA	185	/* like EMB_RELSDA, adjusted high 16 */
-
-/* GNU extension to support local ifunc.  */
-#define R_PPC_IRELATIVE		248
-
-/* GNU relocs used in PIC code sequences.  */
-#define R_PPC_REL16		249	/* half16   (sym+add-.) */
-#define R_PPC_REL16_LO		250	/* half16   (sym+add-.)@l */
-#define R_PPC_REL16_HI		251	/* half16   (sym+add-.)@h */
-#define R_PPC_REL16_HA		252	/* half16   (sym+add-.)@ha */
-
-/* This is a phony reloc to handle any old fashioned TOC16 references
-   that may still be in object files.  */
-#define R_PPC_TOC16		255
-
-/* PowerPC specific values for the Dyn d_tag field.  */
-#define DT_PPC_GOT		(DT_LOPROC + 0)
-#define DT_PPC_OPT		(DT_LOPROC + 1)
-#define DT_PPC_NUM		2
-
-/* PowerPC specific values for the DT_PPC_OPT Dyn entry.  */
-#define PPC_OPT_TLS		1
-
-/* PowerPC64 relocations defined by the ABIs */
-#define R_PPC64_NONE		R_PPC_NONE
-#define R_PPC64_ADDR32		R_PPC_ADDR32 /* 32bit absolute address */
-#define R_PPC64_ADDR24		R_PPC_ADDR24 /* 26bit address, word aligned */
-#define R_PPC64_ADDR16		R_PPC_ADDR16 /* 16bit absolute address */
-#define R_PPC64_ADDR16_LO	R_PPC_ADDR16_LO	/* lower 16bits of address */
-#define R_PPC64_ADDR16_HI	R_PPC_ADDR16_HI	/* high 16bits of address. */
-#define R_PPC64_ADDR16_HA	R_PPC_ADDR16_HA /* adjusted high 16bits.  */
-#define R_PPC64_ADDR14		R_PPC_ADDR14 /* 16bit address, word aligned */
-#define R_PPC64_ADDR14_BRTAKEN	R_PPC_ADDR14_BRTAKEN
-#define R_PPC64_ADDR14_BRNTAKEN	R_PPC_ADDR14_BRNTAKEN
-#define R_PPC64_REL24		R_PPC_REL24 /* PC-rel. 26 bit, word aligned */
-#define R_PPC64_REL14		R_PPC_REL14 /* PC relative 16 bit */
-#define R_PPC64_REL14_BRTAKEN	R_PPC_REL14_BRTAKEN
-#define R_PPC64_REL14_BRNTAKEN	R_PPC_REL14_BRNTAKEN
-#define R_PPC64_GOT16		R_PPC_GOT16
-#define R_PPC64_GOT16_LO	R_PPC_GOT16_LO
-#define R_PPC64_GOT16_HI	R_PPC_GOT16_HI
-#define R_PPC64_GOT16_HA	R_PPC_GOT16_HA
-
-#define R_PPC64_COPY		R_PPC_COPY
-#define R_PPC64_GLOB_DAT	R_PPC_GLOB_DAT
-#define R_PPC64_JMP_SLOT	R_PPC_JMP_SLOT
-#define R_PPC64_RELATIVE	R_PPC_RELATIVE
-
-#define R_PPC64_UADDR32		R_PPC_UADDR32
-#define R_PPC64_UADDR16		R_PPC_UADDR16
-#define R_PPC64_REL32		R_PPC_REL32
-#define R_PPC64_PLT32		R_PPC_PLT32
-#define R_PPC64_PLTREL32	R_PPC_PLTREL32
-#define R_PPC64_PLT16_LO	R_PPC_PLT16_LO
-#define R_PPC64_PLT16_HI	R_PPC_PLT16_HI
-#define R_PPC64_PLT16_HA	R_PPC_PLT16_HA
-
-#define R_PPC64_SECTOFF		R_PPC_SECTOFF
-#define R_PPC64_SECTOFF_LO	R_PPC_SECTOFF_LO
-#define R_PPC64_SECTOFF_HI	R_PPC_SECTOFF_HI
-#define R_PPC64_SECTOFF_HA	R_PPC_SECTOFF_HA
-#define R_PPC64_ADDR30		37 /* word30 (S + A - P) >> 2 */
-#define R_PPC64_ADDR64		38 /* doubleword64 S + A */
-#define R_PPC64_ADDR16_HIGHER	39 /* half16 #higher(S + A) */
-#define R_PPC64_ADDR16_HIGHERA	40 /* half16 #highera(S + A) */
-#define R_PPC64_ADDR16_HIGHEST	41 /* half16 #highest(S + A) */
-#define R_PPC64_ADDR16_HIGHESTA	42 /* half16 #highesta(S + A) */
-#define R_PPC64_UADDR64		43 /* doubleword64 S + A */
-#define R_PPC64_REL64		44 /* doubleword64 S + A - P */
-#define R_PPC64_PLT64		45 /* doubleword64 L + A */
-#define R_PPC64_PLTREL64	46 /* doubleword64 L + A - P */
-#define R_PPC64_TOC16		47 /* half16* S + A - .TOC */
-#define R_PPC64_TOC16_LO	48 /* half16 #lo(S + A - .TOC.) */
-#define R_PPC64_TOC16_HI	49 /* half16 #hi(S + A - .TOC.) */
-#define R_PPC64_TOC16_HA	50 /* half16 #ha(S + A - .TOC.) */
-#define R_PPC64_TOC		51 /* doubleword64 .TOC */
-#define R_PPC64_PLTGOT16	52 /* half16* M + A */
-#define R_PPC64_PLTGOT16_LO	53 /* half16 #lo(M + A) */
-#define R_PPC64_PLTGOT16_HI	54 /* half16 #hi(M + A) */
-#define R_PPC64_PLTGOT16_HA	55 /* half16 #ha(M + A) */
-
-#define R_PPC64_ADDR16_DS	56 /* half16ds* (S + A) >> 2 */
-#define R_PPC64_ADDR16_LO_DS	57 /* half16ds  #lo(S + A) >> 2 */
-#define R_PPC64_GOT16_DS	58 /* half16ds* (G + A) >> 2 */
-#define R_PPC64_GOT16_LO_DS	59 /* half16ds  #lo(G + A) >> 2 */
-#define R_PPC64_PLT16_LO_DS	60 /* half16ds  #lo(L + A) >> 2 */
-#define R_PPC64_SECTOFF_DS	61 /* half16ds* (R + A) >> 2 */
-#define R_PPC64_SECTOFF_LO_DS	62 /* half16ds  #lo(R + A) >> 2 */
-#define R_PPC64_TOC16_DS	63 /* half16ds* (S + A - .TOC.) >> 2 */
-#define R_PPC64_TOC16_LO_DS	64 /* half16ds  #lo(S + A - .TOC.) >> 2 */
-#define R_PPC64_PLTGOT16_DS	65 /* half16ds* (M + A) >> 2 */
-#define R_PPC64_PLTGOT16_LO_DS	66 /* half16ds  #lo(M + A) >> 2 */
-
-/* PowerPC64 relocations defined for the TLS access ABI.  */
-#define R_PPC64_TLS		67 /* none	(sym+add)@tls */
-#define R_PPC64_DTPMOD64	68 /* doubleword64 (sym+add)@dtpmod */
-#define R_PPC64_TPREL16		69 /* half16*	(sym+add)@tprel */
-#define R_PPC64_TPREL16_LO	70 /* half16	(sym+add)@tprel@l */
-#define R_PPC64_TPREL16_HI	71 /* half16	(sym+add)@tprel@h */
-#define R_PPC64_TPREL16_HA	72 /* half16	(sym+add)@tprel@ha */
-#define R_PPC64_TPREL64		73 /* doubleword64 (sym+add)@tprel */
-#define R_PPC64_DTPREL16	74 /* half16*	(sym+add)@dtprel */
-#define R_PPC64_DTPREL16_LO	75 /* half16	(sym+add)@dtprel@l */
-#define R_PPC64_DTPREL16_HI	76 /* half16	(sym+add)@dtprel@h */
-#define R_PPC64_DTPREL16_HA	77 /* half16	(sym+add)@dtprel@ha */
-#define R_PPC64_DTPREL64	78 /* doubleword64 (sym+add)@dtprel */
-#define R_PPC64_GOT_TLSGD16	79 /* half16*	(sym+add)@got@tlsgd */
-#define R_PPC64_GOT_TLSGD16_LO	80 /* half16	(sym+add)@got@tlsgd@l */
-#define R_PPC64_GOT_TLSGD16_HI	81 /* half16	(sym+add)@got@tlsgd@h */
-#define R_PPC64_GOT_TLSGD16_HA	82 /* half16	(sym+add)@got@tlsgd@ha */
-#define R_PPC64_GOT_TLSLD16	83 /* half16*	(sym+add)@got@tlsld */
-#define R_PPC64_GOT_TLSLD16_LO	84 /* half16	(sym+add)@got@tlsld@l */
-#define R_PPC64_GOT_TLSLD16_HI	85 /* half16	(sym+add)@got@tlsld@h */
-#define R_PPC64_GOT_TLSLD16_HA	86 /* half16	(sym+add)@got@tlsld@ha */
-#define R_PPC64_GOT_TPREL16_DS	87 /* half16ds*	(sym+add)@got@tprel */
-#define R_PPC64_GOT_TPREL16_LO_DS 88 /* half16ds (sym+add)@got@tprel@l */
-#define R_PPC64_GOT_TPREL16_HI	89 /* half16	(sym+add)@got@tprel@h */
-#define R_PPC64_GOT_TPREL16_HA	90 /* half16	(sym+add)@got@tprel@ha */
-#define R_PPC64_GOT_DTPREL16_DS	91 /* half16ds*	(sym+add)@got@dtprel */
-#define R_PPC64_GOT_DTPREL16_LO_DS 92 /* half16ds (sym+add)@got@dtprel@l */
-#define R_PPC64_GOT_DTPREL16_HI	93 /* half16	(sym+add)@got@dtprel@h */
-#define R_PPC64_GOT_DTPREL16_HA	94 /* half16	(sym+add)@got@dtprel@ha */
-#define R_PPC64_TPREL16_DS	95 /* half16ds*	(sym+add)@tprel */
-#define R_PPC64_TPREL16_LO_DS	96 /* half16ds	(sym+add)@tprel@l */
-#define R_PPC64_TPREL16_HIGHER	97 /* half16	(sym+add)@tprel@higher */
-#define R_PPC64_TPREL16_HIGHERA	98 /* half16	(sym+add)@tprel@highera */
-#define R_PPC64_TPREL16_HIGHEST	99 /* half16	(sym+add)@tprel@highest */
-#define R_PPC64_TPREL16_HIGHESTA 100 /* half16	(sym+add)@tprel@highesta */
-#define R_PPC64_DTPREL16_DS	101 /* half16ds* (sym+add)@dtprel */
-#define R_PPC64_DTPREL16_LO_DS	102 /* half16ds	(sym+add)@dtprel@l */
-#define R_PPC64_DTPREL16_HIGHER	103 /* half16	(sym+add)@dtprel@higher */
-#define R_PPC64_DTPREL16_HIGHERA 104 /* half16	(sym+add)@dtprel@highera */
-#define R_PPC64_DTPREL16_HIGHEST 105 /* half16	(sym+add)@dtprel@highest */
-#define R_PPC64_DTPREL16_HIGHESTA 106 /* half16	(sym+add)@dtprel@highesta */
-#define R_PPC64_TLSGD		107 /* none	(sym+add)@tlsgd */
-#define R_PPC64_TLSLD		108 /* none	(sym+add)@tlsld */
-#define R_PPC64_TOCSAVE		109 /* none */
-
-/* Added when HA and HI relocs were changed to report overflows.  */
-#define R_PPC64_ADDR16_HIGH	110
-#define R_PPC64_ADDR16_HIGHA	111
-#define R_PPC64_TPREL16_HIGH	112
-#define R_PPC64_TPREL16_HIGHA	113
-#define R_PPC64_DTPREL16_HIGH	114
-#define R_PPC64_DTPREL16_HIGHA	115
-
-/* GNU extension to support local ifunc.  */
-#define R_PPC64_JMP_IREL	247
-#define R_PPC64_IRELATIVE	248
-#define R_PPC64_REL16		249	/* half16   (sym+add-.) */
-#define R_PPC64_REL16_LO	250	/* half16   (sym+add-.)@l */
-#define R_PPC64_REL16_HI	251	/* half16   (sym+add-.)@h */
-#define R_PPC64_REL16_HA	252	/* half16   (sym+add-.)@ha */
-
-/* e_flags bits specifying ABI.
-   1 for original function descriptor using ABI,
-   2 for revised ABI without function descriptors,
-   0 for unspecified or not using any features affected by the differences.  */
-#define EF_PPC64_ABI	3
-
-/* PowerPC64 specific values for the Dyn d_tag field.  */
-#define DT_PPC64_GLINK  (DT_LOPROC + 0)
-#define DT_PPC64_OPD	(DT_LOPROC + 1)
-#define DT_PPC64_OPDSZ	(DT_LOPROC + 2)
-#define DT_PPC64_OPT	(DT_LOPROC + 3)
-#define DT_PPC64_NUM    4
-
-/* PowerPC64 specific values for the DT_PPC64_OPT Dyn entry.  */
-#define PPC64_OPT_TLS		1
-#define PPC64_OPT_MULTI_TOC	2
-
-/* PowerPC64 specific values for the Elf64_Sym st_other field.  */
-#define STO_PPC64_LOCAL_BIT	5
-#define STO_PPC64_LOCAL_MASK	(7 << STO_PPC64_LOCAL_BIT)
-#define PPC64_LOCAL_ENTRY_OFFSET(other)				\
- (((1 << (((other) & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT)) >> 2) << 2)
-
-
-/* ARM specific declarations */
-
-/* Processor specific flags for the ELF header e_flags field.  */
-#define EF_ARM_RELEXEC		0x01
-#define EF_ARM_HASENTRY		0x02
-#define EF_ARM_INTERWORK	0x04
-#define EF_ARM_APCS_26		0x08
-#define EF_ARM_APCS_FLOAT	0x10
-#define EF_ARM_PIC		0x20
-#define EF_ARM_ALIGN8		0x40 /* 8-bit structure alignment is in use */
-#define EF_ARM_NEW_ABI		0x80
-#define EF_ARM_OLD_ABI		0x100
-#define EF_ARM_SOFT_FLOAT	0x200
-#define EF_ARM_VFP_FLOAT	0x400
-#define EF_ARM_MAVERICK_FLOAT	0x800
-
-#define EF_ARM_ABI_FLOAT_SOFT	0x200   /* NB conflicts with EF_ARM_SOFT_FLOAT */
-#define EF_ARM_ABI_FLOAT_HARD	0x400   /* NB conflicts with EF_ARM_VFP_FLOAT */
-
-
-/* Other constants defined in the ARM ELF spec. version B-01.  */
-/* NB. These conflict with values defined above.  */
-#define EF_ARM_SYMSARESORTED	0x04
-#define EF_ARM_DYNSYMSUSESEGIDX	0x08
-#define EF_ARM_MAPSYMSFIRST	0x10
-#define EF_ARM_EABIMASK		0XFF000000
-
-/* Constants defined in AAELF.  */
-#define EF_ARM_BE8	    0x00800000
-#define EF_ARM_LE8	    0x00400000
-
-#define EF_ARM_EABI_VERSION(flags)	((flags) & EF_ARM_EABIMASK)
-#define EF_ARM_EABI_UNKNOWN	0x00000000
-#define EF_ARM_EABI_VER1	0x01000000
-#define EF_ARM_EABI_VER2	0x02000000
-#define EF_ARM_EABI_VER3	0x03000000
-#define EF_ARM_EABI_VER4	0x04000000
-#define EF_ARM_EABI_VER5	0x05000000
-
-/* Additional symbol types for Thumb.  */
-#define STT_ARM_TFUNC		STT_LOPROC /* A Thumb function.  */
-#define STT_ARM_16BIT		STT_HIPROC /* A Thumb label.  */
-
-/* ARM-specific values for sh_flags */
-#define SHF_ARM_ENTRYSECT	0x10000000 /* Section contains an entry point */
-#define SHF_ARM_COMDEF		0x80000000 /* Section may be multiply defined
-					      in the input to a link step.  */
-
-/* ARM-specific program header flags */
-#define PF_ARM_SB		0x10000000 /* Segment contains the location
-					      addressed by the static base. */
-#define PF_ARM_PI		0x20000000 /* Position-independent segment.  */
-#define PF_ARM_ABS		0x40000000 /* Absolute segment.  */
-
-/* Processor specific values for the Phdr p_type field.  */
-#define PT_ARM_EXIDX		(PT_LOPROC + 1)	/* ARM unwind segment.  */
-
-/* Processor specific values for the Shdr sh_type field.  */
-#define SHT_ARM_EXIDX		(SHT_LOPROC + 1) /* ARM unwind section.  */
-#define SHT_ARM_PREEMPTMAP	(SHT_LOPROC + 2) /* Preemption details.  */
-#define SHT_ARM_ATTRIBUTES	(SHT_LOPROC + 3) /* ARM attributes section.  */
-
-
-/* AArch64 relocs.  */
-
-#define R_AARCH64_NONE            0	/* No relocation.  */
-
-/* ILP32 AArch64 relocs.  */
-#define R_AARCH64_P32_ABS32		  1	/* Direct 32 bit.  */
-#define R_AARCH64_P32_COPY		180	/* Copy symbol at runtime.  */
-#define R_AARCH64_P32_GLOB_DAT		181	/* Create GOT entry.  */
-#define R_AARCH64_P32_JUMP_SLOT		182	/* Create PLT entry.  */
-#define R_AARCH64_P32_RELATIVE		183	/* Adjust by program base.  */
-#define R_AARCH64_P32_TLS_DTPMOD	184	/* Module number, 32 bit.  */
-#define R_AARCH64_P32_TLS_DTPREL	185	/* Module-relative offset, 32 bit.  */
-#define R_AARCH64_P32_TLS_TPREL		186	/* TP-relative offset, 32 bit.  */
-#define R_AARCH64_P32_TLSDESC		187	/* TLS Descriptor.  */
-#define R_AARCH64_P32_IRELATIVE		188	/* STT_GNU_IFUNC relocation. */
-
-/* LP64 AArch64 relocs.  */
-#define R_AARCH64_ABS64         257	/* Direct 64 bit. */
-#define R_AARCH64_ABS32         258	/* Direct 32 bit.  */
-#define R_AARCH64_ABS16		259	/* Direct 16-bit.  */
-#define R_AARCH64_PREL64	260	/* PC-relative 64-bit.	*/
-#define R_AARCH64_PREL32	261	/* PC-relative 32-bit.	*/
-#define R_AARCH64_PREL16	262	/* PC-relative 16-bit.	*/
-#define R_AARCH64_MOVW_UABS_G0	263	/* Dir. MOVZ imm. from bits 15:0.  */
-#define R_AARCH64_MOVW_UABS_G0_NC 264	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_UABS_G1	265	/* Dir. MOVZ imm. from bits 31:16.  */
-#define R_AARCH64_MOVW_UABS_G1_NC 266	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_UABS_G2	267	/* Dir. MOVZ imm. from bits 47:32.  */
-#define R_AARCH64_MOVW_UABS_G2_NC 268	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_UABS_G3	269	/* Dir. MOV{K,Z} imm. from 63:48.  */
-#define R_AARCH64_MOVW_SABS_G0	270	/* Dir. MOV{N,Z} imm. from 15:0.  */
-#define R_AARCH64_MOVW_SABS_G1	271	/* Dir. MOV{N,Z} imm. from 31:16.  */
-#define R_AARCH64_MOVW_SABS_G2	272	/* Dir. MOV{N,Z} imm. from 47:32.  */
-#define R_AARCH64_LD_PREL_LO19	273	/* PC-rel. LD imm. from bits 20:2.  */
-#define R_AARCH64_ADR_PREL_LO21	274	/* PC-rel. ADR imm. from bits 20:0.  */
-#define R_AARCH64_ADR_PREL_PG_HI21 275	/* Page-rel. ADRP imm. from 32:12.  */
-#define R_AARCH64_ADR_PREL_PG_HI21_NC 276 /* Likewise; no overflow check.  */
-#define R_AARCH64_ADD_ABS_LO12_NC 277	/* Dir. ADD imm. from bits 11:0.  */
-#define R_AARCH64_LDST8_ABS_LO12_NC 278	/* Likewise for LD/ST; no check. */
-#define R_AARCH64_TSTBR14	279	/* PC-rel. TBZ/TBNZ imm. from 15:2.  */
-#define R_AARCH64_CONDBR19	280	/* PC-rel. cond. br. imm. from 20:2. */
-#define R_AARCH64_JUMP26	282	/* PC-rel. B imm. from bits 27:2.  */
-#define R_AARCH64_CALL26	283	/* Likewise for CALL.  */
-#define R_AARCH64_LDST16_ABS_LO12_NC 284 /* Dir. ADD imm. from bits 11:1.  */
-#define R_AARCH64_LDST32_ABS_LO12_NC 285 /* Likewise for bits 11:2.  */
-#define R_AARCH64_LDST64_ABS_LO12_NC 286 /* Likewise for bits 11:3.  */
-#define R_AARCH64_MOVW_PREL_G0	287	/* PC-rel. MOV{N,Z} imm. from 15:0.  */
-#define R_AARCH64_MOVW_PREL_G0_NC 288	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_PREL_G1	289	/* PC-rel. MOV{N,Z} imm. from 31:16. */
-#define R_AARCH64_MOVW_PREL_G1_NC 290	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_PREL_G2	291	/* PC-rel. MOV{N,Z} imm. from 47:32. */
-#define R_AARCH64_MOVW_PREL_G2_NC 292	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_PREL_G3	293	/* PC-rel. MOV{N,Z} imm. from 63:48. */
-#define R_AARCH64_LDST128_ABS_LO12_NC 299 /* Dir. ADD imm. from bits 11:4.  */
-#define R_AARCH64_MOVW_GOTOFF_G0 300	/* GOT-rel. off. MOV{N,Z} imm. 15:0. */
-#define R_AARCH64_MOVW_GOTOFF_G0_NC 301	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_GOTOFF_G1 302	/* GOT-rel. o. MOV{N,Z} imm. 31:16.  */
-#define R_AARCH64_MOVW_GOTOFF_G1_NC 303	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_GOTOFF_G2 304	/* GOT-rel. o. MOV{N,Z} imm. 47:32.  */
-#define R_AARCH64_MOVW_GOTOFF_G2_NC 305	/* Likewise for MOVK; no check.  */
-#define R_AARCH64_MOVW_GOTOFF_G3 306	/* GOT-rel. o. MOV{N,Z} imm. 63:48.  */
-#define R_AARCH64_GOTREL64	307	/* GOT-relative 64-bit.  */
-#define R_AARCH64_GOTREL32	308	/* GOT-relative 32-bit.  */
-#define R_AARCH64_GOT_LD_PREL19	309	/* PC-rel. GOT off. load imm. 20:2.  */
-#define R_AARCH64_LD64_GOTOFF_LO15 310	/* GOT-rel. off. LD/ST imm. 14:3.  */
-#define R_AARCH64_ADR_GOT_PAGE	311	/* P-page-rel. GOT off. ADRP 32:12.  */
-#define R_AARCH64_LD64_GOT_LO12_NC 312	/* Dir. GOT off. LD/ST imm. 11:3.  */
-#define R_AARCH64_LD64_GOTPAGE_LO15 313	/* GOT-page-rel. GOT off. LD/ST 14:3 */
-#define R_AARCH64_TLSGD_ADR_PREL21 512	/* PC-relative ADR imm. 20:0.  */
-#define R_AARCH64_TLSGD_ADR_PAGE21 513	/* page-rel. ADRP imm. 32:12.  */
-#define R_AARCH64_TLSGD_ADD_LO12_NC 514	/* direct ADD imm. from 11:0.  */
-#define R_AARCH64_TLSGD_MOVW_G1	515	/* GOT-rel. MOV{N,Z} 31:16.  */
-#define R_AARCH64_TLSGD_MOVW_G0_NC 516	/* GOT-rel. MOVK imm. 15:0.  */
-#define R_AARCH64_TLSLD_ADR_PREL21 517	/* Like 512; local dynamic model.  */
-#define R_AARCH64_TLSLD_ADR_PAGE21 518	/* Like 513; local dynamic model.  */
-#define R_AARCH64_TLSLD_ADD_LO12_NC 519	/* Like 514; local dynamic model.  */
-#define R_AARCH64_TLSLD_MOVW_G1	520	/* Like 515; local dynamic model.  */
-#define R_AARCH64_TLSLD_MOVW_G0_NC 521	/* Like 516; local dynamic model.  */
-#define R_AARCH64_TLSLD_LD_PREL19 522	/* TLS PC-rel. load imm. 20:2.  */
-#define R_AARCH64_TLSLD_MOVW_DTPREL_G2 523 /* TLS DTP-rel. MOV{N,Z} 47:32.  */
-#define R_AARCH64_TLSLD_MOVW_DTPREL_G1 524 /* TLS DTP-rel. MOV{N,Z} 31:16.  */
-#define R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC 525 /* Likewise; MOVK; no check.  */
-#define R_AARCH64_TLSLD_MOVW_DTPREL_G0 526 /* TLS DTP-rel. MOV{N,Z} 15:0.  */
-#define R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC 527 /* Likewise; MOVK; no check.  */
-#define R_AARCH64_TLSLD_ADD_DTPREL_HI12 528 /* DTP-rel. ADD imm. from 23:12. */
-#define R_AARCH64_TLSLD_ADD_DTPREL_LO12 529 /* DTP-rel. ADD imm. from 11:0.  */
-#define R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC 530 /* Likewise; no ovfl. check.  */
-#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12 531 /* DTP-rel. LD/ST imm. 11:0.  */
-#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC 532 /* Likewise; no check.  */
-#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12 533 /* DTP-rel. LD/ST imm. 11:1.  */
-#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC 534 /* Likewise; no check.  */
-#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12 535 /* DTP-rel. LD/ST imm. 11:2.  */
-#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536 /* Likewise; no check.  */
-#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12 537 /* DTP-rel. LD/ST imm. 11:3.  */
-#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC 538 /* Likewise; no check.  */
-#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 539 /* GOT-rel. MOV{N,Z} 31:16.  */
-#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC 540 /* GOT-rel. MOVK 15:0.  */
-#define R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 541 /* Page-rel. ADRP 32:12.  */
-#define R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 542 /* Direct LD off. 11:3.  */
-#define R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 543 /* PC-rel. load imm. 20:2.  */
-#define R_AARCH64_TLSLE_MOVW_TPREL_G2 544 /* TLS TP-rel. MOV{N,Z} 47:32.  */
-#define R_AARCH64_TLSLE_MOVW_TPREL_G1 545 /* TLS TP-rel. MOV{N,Z} 31:16.  */
-#define R_AARCH64_TLSLE_MOVW_TPREL_G1_NC 546 /* Likewise; MOVK; no check.  */
-#define R_AARCH64_TLSLE_MOVW_TPREL_G0 547 /* TLS TP-rel. MOV{N,Z} 15:0.  */
-#define R_AARCH64_TLSLE_MOVW_TPREL_G0_NC 548 /* Likewise; MOVK; no check.  */
-#define R_AARCH64_TLSLE_ADD_TPREL_HI12 549 /* TP-rel. ADD imm. 23:12.  */
-#define R_AARCH64_TLSLE_ADD_TPREL_LO12 550 /* TP-rel. ADD imm. 11:0.  */
-#define R_AARCH64_TLSLE_ADD_TPREL_LO12_NC 551 /* Likewise; no ovfl. check.  */
-#define R_AARCH64_TLSLE_LDST8_TPREL_LO12 552 /* TP-rel. LD/ST off. 11:0.  */
-#define R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC 553 /* Likewise; no ovfl. check. */
-#define R_AARCH64_TLSLE_LDST16_TPREL_LO12 554 /* TP-rel. LD/ST off. 11:1.  */
-#define R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC 555 /* Likewise; no check.  */
-#define R_AARCH64_TLSLE_LDST32_TPREL_LO12 556 /* TP-rel. LD/ST off. 11:2.  */
-#define R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC 557 /* Likewise; no check.  */
-#define R_AARCH64_TLSLE_LDST64_TPREL_LO12 558 /* TP-rel. LD/ST off. 11:3.  */
-#define R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC 559 /* Likewise; no check.  */
-#define R_AARCH64_TLSDESC_LD_PREL19 560	/* PC-rel. load immediate 20:2.  */
-#define R_AARCH64_TLSDESC_ADR_PREL21 561 /* PC-rel. ADR immediate 20:0.  */
-#define R_AARCH64_TLSDESC_ADR_PAGE21 562 /* Page-rel. ADRP imm. 32:12.  */
-#define R_AARCH64_TLSDESC_LD64_LO12 563	/* Direct LD off. from 11:3.  */
-#define R_AARCH64_TLSDESC_ADD_LO12 564	/* Direct ADD imm. from 11:0.  */
-#define R_AARCH64_TLSDESC_OFF_G1 565	/* GOT-rel. MOV{N,Z} imm. 31:16.  */
-#define R_AARCH64_TLSDESC_OFF_G0_NC 566	/* GOT-rel. MOVK imm. 15:0; no ck.  */
-#define R_AARCH64_TLSDESC_LDR	567	/* Relax LDR.  */
-#define R_AARCH64_TLSDESC_ADD	568	/* Relax ADD.  */
-#define R_AARCH64_TLSDESC_CALL	569	/* Relax BLR.  */
-#define R_AARCH64_TLSLE_LDST128_TPREL_LO12 570 /* TP-rel. LD/ST off. 11:4.  */
-#define R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC 571 /* Likewise; no check.  */
-#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12 572 /* DTP-rel. LD/ST imm. 11:4. */
-#define R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC 573 /* Likewise; no check.  */
-#define R_AARCH64_COPY         1024	/* Copy symbol at runtime.  */
-#define R_AARCH64_GLOB_DAT     1025	/* Create GOT entry.  */
-#define R_AARCH64_JUMP_SLOT    1026	/* Create PLT entry.  */
-#define R_AARCH64_RELATIVE     1027	/* Adjust by program base.  */
-#define R_AARCH64_TLS_DTPMOD   1028	/* Module number, 64 bit.  */
-#define R_AARCH64_TLS_DTPREL   1029	/* Module-relative offset, 64 bit.  */
-#define R_AARCH64_TLS_TPREL    1030	/* TP-relative offset, 64 bit.  */
-#define R_AARCH64_TLSDESC      1031	/* TLS Descriptor.  */
-#define R_AARCH64_IRELATIVE	1032	/* STT_GNU_IFUNC relocation.  */
-
-/* ARM relocs.  */
-
-#define R_ARM_NONE		0	/* No reloc */
-#define R_ARM_PC24		1	/* Deprecated PC relative 26
-					   bit branch.  */
-#define R_ARM_ABS32		2	/* Direct 32 bit  */
-#define R_ARM_REL32		3	/* PC relative 32 bit */
-#define R_ARM_PC13		4
-#define R_ARM_ABS16		5	/* Direct 16 bit */
-#define R_ARM_ABS12		6	/* Direct 12 bit */
-#define R_ARM_THM_ABS5		7	/* Direct & 0x7C (LDR, STR).  */
-#define R_ARM_ABS8		8	/* Direct 8 bit */
-#define R_ARM_SBREL32		9
-#define R_ARM_THM_PC22		10	/* PC relative 24 bit (Thumb32 BL).  */
-#define R_ARM_THM_PC8		11	/* PC relative & 0x3FC
-					   (Thumb16 LDR, ADD, ADR).  */
-#define R_ARM_AMP_VCALL9	12
-#define R_ARM_SWI24		13	/* Obsolete static relocation.  */
-#define R_ARM_TLS_DESC		13      /* Dynamic relocation.  */
-#define R_ARM_THM_SWI8		14	/* Reserved.  */
-#define R_ARM_XPC25		15	/* Reserved.  */
-#define R_ARM_THM_XPC22		16	/* Reserved.  */
-#define R_ARM_TLS_DTPMOD32	17	/* ID of module containing symbol */
-#define R_ARM_TLS_DTPOFF32	18	/* Offset in TLS block */
-#define R_ARM_TLS_TPOFF32	19	/* Offset in static TLS block */
-#define R_ARM_COPY		20	/* Copy symbol at runtime */
-#define R_ARM_GLOB_DAT		21	/* Create GOT entry */
-#define R_ARM_JUMP_SLOT		22	/* Create PLT entry */
-#define R_ARM_RELATIVE		23	/* Adjust by program base */
-#define R_ARM_GOTOFF		24	/* 32 bit offset to GOT */
-#define R_ARM_GOTPC		25	/* 32 bit PC relative offset to GOT */
-#define R_ARM_GOT32		26	/* 32 bit GOT entry */
-#define R_ARM_PLT32		27	/* Deprecated, 32 bit PLT address.  */
-#define R_ARM_CALL		28	/* PC relative 24 bit (BL, BLX).  */
-#define R_ARM_JUMP24		29	/* PC relative 24 bit
-					   (B, BL<cond>).  */
-#define R_ARM_THM_JUMP24	30	/* PC relative 24 bit (Thumb32 B.W).  */
-#define R_ARM_BASE_ABS		31	/* Adjust by program base.  */
-#define R_ARM_ALU_PCREL_7_0	32	/* Obsolete.  */
-#define R_ARM_ALU_PCREL_15_8	33	/* Obsolete.  */
-#define R_ARM_ALU_PCREL_23_15	34	/* Obsolete.  */
-#define R_ARM_LDR_SBREL_11_0	35	/* Deprecated, prog. base relative.  */
-#define R_ARM_ALU_SBREL_19_12	36	/* Deprecated, prog. base relative.  */
-#define R_ARM_ALU_SBREL_27_20	37	/* Deprecated, prog. base relative.  */
-#define R_ARM_TARGET1		38
-#define R_ARM_SBREL31		39	/* Program base relative.  */
-#define R_ARM_V4BX		40
-#define R_ARM_TARGET2		41
-#define R_ARM_PREL31		42	/* 32 bit PC relative.  */
-#define R_ARM_MOVW_ABS_NC	43	/* Direct 16-bit (MOVW).  */
-#define R_ARM_MOVT_ABS		44	/* Direct high 16-bit (MOVT).  */
-#define R_ARM_MOVW_PREL_NC	45	/* PC relative 16-bit (MOVW).  */
-#define R_ARM_MOVT_PREL		46	/* PC relative (MOVT).  */
-#define R_ARM_THM_MOVW_ABS_NC	47	/* Direct 16 bit (Thumb32 MOVW).  */
-#define R_ARM_THM_MOVT_ABS	48	/* Direct high 16 bit
-					   (Thumb32 MOVT).  */
-#define R_ARM_THM_MOVW_PREL_NC	49	/* PC relative 16 bit
-					   (Thumb32 MOVW).  */
-#define R_ARM_THM_MOVT_PREL	50	/* PC relative high 16 bit
-					   (Thumb32 MOVT).  */
-#define R_ARM_THM_JUMP19	51	/* PC relative 20 bit
-					   (Thumb32 B<cond>.W).  */
-#define R_ARM_THM_JUMP6		52	/* PC relative X & 0x7E
-					   (Thumb16 CBZ, CBNZ).  */
-#define R_ARM_THM_ALU_PREL_11_0	53	/* PC relative 12 bit
-					   (Thumb32 ADR.W).  */
-#define R_ARM_THM_PC12		54	/* PC relative 12 bit
-					   (Thumb32 LDR{D,SB,H,SH}).  */
-#define R_ARM_ABS32_NOI		55	/* Direct 32-bit.  */
-#define R_ARM_REL32_NOI		56	/* PC relative 32-bit.  */
-#define R_ARM_ALU_PC_G0_NC	57	/* PC relative (ADD, SUB).  */
-#define R_ARM_ALU_PC_G0		58	/* PC relative (ADD, SUB).  */
-#define R_ARM_ALU_PC_G1_NC	59	/* PC relative (ADD, SUB).  */
-#define R_ARM_ALU_PC_G1		60	/* PC relative (ADD, SUB).  */
-#define R_ARM_ALU_PC_G2		61	/* PC relative (ADD, SUB).  */
-#define R_ARM_LDR_PC_G1		62	/* PC relative (LDR,STR,LDRB,STRB).  */
-#define R_ARM_LDR_PC_G2		63	/* PC relative (LDR,STR,LDRB,STRB).  */
-#define R_ARM_LDRS_PC_G0	64	/* PC relative (STR{D,H},
-					   LDR{D,SB,H,SH}).  */
-#define R_ARM_LDRS_PC_G1	65	/* PC relative (STR{D,H},
-					   LDR{D,SB,H,SH}).  */
-#define R_ARM_LDRS_PC_G2	66	/* PC relative (STR{D,H},
-					   LDR{D,SB,H,SH}).  */
-#define R_ARM_LDC_PC_G0		67	/* PC relative (LDC, STC).  */
-#define R_ARM_LDC_PC_G1		68	/* PC relative (LDC, STC).  */
-#define R_ARM_LDC_PC_G2		69	/* PC relative (LDC, STC).  */
-#define R_ARM_ALU_SB_G0_NC	70	/* Program base relative (ADD,SUB).  */
-#define R_ARM_ALU_SB_G0		71	/* Program base relative (ADD,SUB).  */
-#define R_ARM_ALU_SB_G1_NC	72	/* Program base relative (ADD,SUB).  */
-#define R_ARM_ALU_SB_G1		73	/* Program base relative (ADD,SUB).  */
-#define R_ARM_ALU_SB_G2		74	/* Program base relative (ADD,SUB).  */
-#define R_ARM_LDR_SB_G0		75	/* Program base relative (LDR,
-					   STR, LDRB, STRB).  */
-#define R_ARM_LDR_SB_G1		76	/* Program base relative
-					   (LDR, STR, LDRB, STRB).  */
-#define R_ARM_LDR_SB_G2		77	/* Program base relative
-					   (LDR, STR, LDRB, STRB).  */
-#define R_ARM_LDRS_SB_G0	78	/* Program base relative
-					   (LDR, STR, LDRB, STRB).  */
-#define R_ARM_LDRS_SB_G1	79	/* Program base relative
-					   (LDR, STR, LDRB, STRB).  */
-#define R_ARM_LDRS_SB_G2	80	/* Program base relative
-					   (LDR, STR, LDRB, STRB).  */
-#define R_ARM_LDC_SB_G0		81	/* Program base relative (LDC,STC).  */
-#define R_ARM_LDC_SB_G1		82	/* Program base relative (LDC,STC).  */
-#define R_ARM_LDC_SB_G2		83	/* Program base relative (LDC,STC).  */
-#define R_ARM_MOVW_BREL_NC	84	/* Program base relative 16
-					   bit (MOVW).  */
-#define R_ARM_MOVT_BREL		85	/* Program base relative high
-					   16 bit (MOVT).  */
-#define R_ARM_MOVW_BREL		86	/* Program base relative 16
-					   bit (MOVW).  */
-#define R_ARM_THM_MOVW_BREL_NC	87	/* Program base relative 16
-					   bit (Thumb32 MOVW).  */
-#define R_ARM_THM_MOVT_BREL	88	/* Program base relative high
-					   16 bit (Thumb32 MOVT).  */
-#define R_ARM_THM_MOVW_BREL	89	/* Program base relative 16
-					   bit (Thumb32 MOVW).  */
-#define R_ARM_TLS_GOTDESC	90
-#define R_ARM_TLS_CALL		91
-#define R_ARM_TLS_DESCSEQ	92	/* TLS relaxation.  */
-#define R_ARM_THM_TLS_CALL	93
-#define R_ARM_PLT32_ABS		94
-#define R_ARM_GOT_ABS		95	/* GOT entry.  */
-#define R_ARM_GOT_PREL		96	/* PC relative GOT entry.  */
-#define R_ARM_GOT_BREL12	97	/* GOT entry relative to GOT
-					   origin (LDR).  */
-#define R_ARM_GOTOFF12		98	/* 12 bit, GOT entry relative
-					   to GOT origin (LDR, STR).  */
-#define R_ARM_GOTRELAX		99
-#define R_ARM_GNU_VTENTRY	100
-#define R_ARM_GNU_VTINHERIT	101
-#define R_ARM_THM_PC11		102	/* PC relative & 0xFFE (Thumb16 B).  */
-#define R_ARM_THM_PC9		103	/* PC relative & 0x1FE
-					   (Thumb16 B/B<cond>).  */
-#define R_ARM_TLS_GD32		104	/* PC-rel 32 bit for global dynamic
-					   thread local data */
-#define R_ARM_TLS_LDM32		105	/* PC-rel 32 bit for local dynamic
-					   thread local data */
-#define R_ARM_TLS_LDO32		106	/* 32 bit offset relative to TLS
-					   block */
-#define R_ARM_TLS_IE32		107	/* PC-rel 32 bit for GOT entry of
-					   static TLS block offset */
-#define R_ARM_TLS_LE32		108	/* 32 bit offset relative to static
-					   TLS block */
-#define R_ARM_TLS_LDO12		109	/* 12 bit relative to TLS
-					   block (LDR, STR).  */
-#define R_ARM_TLS_LE12		110	/* 12 bit relative to static
-					   TLS block (LDR, STR).  */
-#define R_ARM_TLS_IE12GP	111	/* 12 bit GOT entry relative
-					   to GOT origin (LDR).  */
-#define R_ARM_ME_TOO		128	/* Obsolete.  */
-#define R_ARM_THM_TLS_DESCSEQ	129
-#define R_ARM_THM_TLS_DESCSEQ16	129
-#define R_ARM_THM_TLS_DESCSEQ32	130
-#define R_ARM_THM_GOT_BREL12	131	/* GOT entry relative to GOT
-					   origin, 12 bit (Thumb32 LDR).  */
-#define R_ARM_IRELATIVE		160
-#define R_ARM_RXPC25		249
-#define R_ARM_RSBREL32		250
-#define R_ARM_THM_RPC22		251
-#define R_ARM_RREL32		252
-#define R_ARM_RABS22		253
-#define R_ARM_RPC24		254
-#define R_ARM_RBASE		255
-/* Keep this the last entry.  */
-#define R_ARM_NUM		256
-
-/* IA-64 specific declarations.  */
-
-/* Processor specific flags for the Ehdr e_flags field.  */
-#define EF_IA_64_MASKOS		0x0000000f	/* os-specific flags */
-#define EF_IA_64_ABI64		0x00000010	/* 64-bit ABI */
-#define EF_IA_64_ARCH		0xff000000	/* arch. version mask */
-
-/* Processor specific values for the Phdr p_type field.  */
-#define PT_IA_64_ARCHEXT	(PT_LOPROC + 0)	/* arch extension bits */
-#define PT_IA_64_UNWIND		(PT_LOPROC + 1)	/* ia64 unwind bits */
-#define PT_IA_64_HP_OPT_ANOT	(PT_LOOS + 0x12)
-#define PT_IA_64_HP_HSL_ANOT	(PT_LOOS + 0x13)
-#define PT_IA_64_HP_STACK	(PT_LOOS + 0x14)
-
-/* Processor specific flags for the Phdr p_flags field.  */
-#define PF_IA_64_NORECOV	0x80000000	/* spec insns w/o recovery */
-
-/* Processor specific values for the Shdr sh_type field.  */
-#define SHT_IA_64_EXT		(SHT_LOPROC + 0) /* extension bits */
-#define SHT_IA_64_UNWIND	(SHT_LOPROC + 1) /* unwind bits */
-
-/* Processor specific flags for the Shdr sh_flags field.  */
-#define SHF_IA_64_SHORT		0x10000000	/* section near gp */
-#define SHF_IA_64_NORECOV	0x20000000	/* spec insns w/o recovery */
-
-/* Processor specific values for the Dyn d_tag field.  */
-#define DT_IA_64_PLT_RESERVE	(DT_LOPROC + 0)
-#define DT_IA_64_NUM		1
-
-/* IA-64 relocations.  */
-#define R_IA64_NONE		0x00	/* none */
-#define R_IA64_IMM14		0x21	/* symbol + addend, add imm14 */
-#define R_IA64_IMM22		0x22	/* symbol + addend, add imm22 */
-#define R_IA64_IMM64		0x23	/* symbol + addend, mov imm64 */
-#define R_IA64_DIR32MSB		0x24	/* symbol + addend, data4 MSB */
-#define R_IA64_DIR32LSB		0x25	/* symbol + addend, data4 LSB */
-#define R_IA64_DIR64MSB		0x26	/* symbol + addend, data8 MSB */
-#define R_IA64_DIR64LSB		0x27	/* symbol + addend, data8 LSB */
-#define R_IA64_GPREL22		0x2a	/* @gprel(sym + add), add imm22 */
-#define R_IA64_GPREL64I		0x2b	/* @gprel(sym + add), mov imm64 */
-#define R_IA64_GPREL32MSB	0x2c	/* @gprel(sym + add), data4 MSB */
-#define R_IA64_GPREL32LSB	0x2d	/* @gprel(sym + add), data4 LSB */
-#define R_IA64_GPREL64MSB	0x2e	/* @gprel(sym + add), data8 MSB */
-#define R_IA64_GPREL64LSB	0x2f	/* @gprel(sym + add), data8 LSB */
-#define R_IA64_LTOFF22		0x32	/* @ltoff(sym + add), add imm22 */
-#define R_IA64_LTOFF64I		0x33	/* @ltoff(sym + add), mov imm64 */
-#define R_IA64_PLTOFF22		0x3a	/* @pltoff(sym + add), add imm22 */
-#define R_IA64_PLTOFF64I	0x3b	/* @pltoff(sym + add), mov imm64 */
-#define R_IA64_PLTOFF64MSB	0x3e	/* @pltoff(sym + add), data8 MSB */
-#define R_IA64_PLTOFF64LSB	0x3f	/* @pltoff(sym + add), data8 LSB */
-#define R_IA64_FPTR64I		0x43	/* @fptr(sym + add), mov imm64 */
-#define R_IA64_FPTR32MSB	0x44	/* @fptr(sym + add), data4 MSB */
-#define R_IA64_FPTR32LSB	0x45	/* @fptr(sym + add), data4 LSB */
-#define R_IA64_FPTR64MSB	0x46	/* @fptr(sym + add), data8 MSB */
-#define R_IA64_FPTR64LSB	0x47	/* @fptr(sym + add), data8 LSB */
-#define R_IA64_PCREL60B		0x48	/* @pcrel(sym + add), brl */
-#define R_IA64_PCREL21B		0x49	/* @pcrel(sym + add), ptb, call */
-#define R_IA64_PCREL21M		0x4a	/* @pcrel(sym + add), chk.s */
-#define R_IA64_PCREL21F		0x4b	/* @pcrel(sym + add), fchkf */
-#define R_IA64_PCREL32MSB	0x4c	/* @pcrel(sym + add), data4 MSB */
-#define R_IA64_PCREL32LSB	0x4d	/* @pcrel(sym + add), data4 LSB */
-#define R_IA64_PCREL64MSB	0x4e	/* @pcrel(sym + add), data8 MSB */
-#define R_IA64_PCREL64LSB	0x4f	/* @pcrel(sym + add), data8 LSB */
-#define R_IA64_LTOFF_FPTR22	0x52	/* @ltoff(@fptr(s+a)), imm22 */
-#define R_IA64_LTOFF_FPTR64I	0x53	/* @ltoff(@fptr(s+a)), imm64 */
-#define R_IA64_LTOFF_FPTR32MSB	0x54	/* @ltoff(@fptr(s+a)), data4 MSB */
-#define R_IA64_LTOFF_FPTR32LSB	0x55	/* @ltoff(@fptr(s+a)), data4 LSB */
-#define R_IA64_LTOFF_FPTR64MSB	0x56	/* @ltoff(@fptr(s+a)), data8 MSB */
-#define R_IA64_LTOFF_FPTR64LSB	0x57	/* @ltoff(@fptr(s+a)), data8 LSB */
-#define R_IA64_SEGREL32MSB	0x5c	/* @segrel(sym + add), data4 MSB */
-#define R_IA64_SEGREL32LSB	0x5d	/* @segrel(sym + add), data4 LSB */
-#define R_IA64_SEGREL64MSB	0x5e	/* @segrel(sym + add), data8 MSB */
-#define R_IA64_SEGREL64LSB	0x5f	/* @segrel(sym + add), data8 LSB */
-#define R_IA64_SECREL32MSB	0x64	/* @secrel(sym + add), data4 MSB */
-#define R_IA64_SECREL32LSB	0x65	/* @secrel(sym + add), data4 LSB */
-#define R_IA64_SECREL64MSB	0x66	/* @secrel(sym + add), data8 MSB */
-#define R_IA64_SECREL64LSB	0x67	/* @secrel(sym + add), data8 LSB */
-#define R_IA64_REL32MSB		0x6c	/* data 4 + REL */
-#define R_IA64_REL32LSB		0x6d	/* data 4 + REL */
-#define R_IA64_REL64MSB		0x6e	/* data 8 + REL */
-#define R_IA64_REL64LSB		0x6f	/* data 8 + REL */
-#define R_IA64_LTV32MSB		0x74	/* symbol + addend, data4 MSB */
-#define R_IA64_LTV32LSB		0x75	/* symbol + addend, data4 LSB */
-#define R_IA64_LTV64MSB		0x76	/* symbol + addend, data8 MSB */
-#define R_IA64_LTV64LSB		0x77	/* symbol + addend, data8 LSB */
-#define R_IA64_PCREL21BI	0x79	/* @pcrel(sym + add), 21bit inst */
-#define R_IA64_PCREL22		0x7a	/* @pcrel(sym + add), 22bit inst */
-#define R_IA64_PCREL64I		0x7b	/* @pcrel(sym + add), 64bit inst */
-#define R_IA64_IPLTMSB		0x80	/* dynamic reloc, imported PLT, MSB */
-#define R_IA64_IPLTLSB		0x81	/* dynamic reloc, imported PLT, LSB */
-#define R_IA64_COPY		0x84	/* copy relocation */
-#define R_IA64_SUB		0x85	/* Addend and symbol difference */
-#define R_IA64_LTOFF22X		0x86	/* LTOFF22, relaxable.  */
-#define R_IA64_LDXMOV		0x87	/* Use of LTOFF22X.  */
-#define R_IA64_TPREL14		0x91	/* @tprel(sym + add), imm14 */
-#define R_IA64_TPREL22		0x92	/* @tprel(sym + add), imm22 */
-#define R_IA64_TPREL64I		0x93	/* @tprel(sym + add), imm64 */
-#define R_IA64_TPREL64MSB	0x96	/* @tprel(sym + add), data8 MSB */
-#define R_IA64_TPREL64LSB	0x97	/* @tprel(sym + add), data8 LSB */
-#define R_IA64_LTOFF_TPREL22	0x9a	/* @ltoff(@tprel(s+a)), imm2 */
-#define R_IA64_DTPMOD64MSB	0xa6	/* @dtpmod(sym + add), data8 MSB */
-#define R_IA64_DTPMOD64LSB	0xa7	/* @dtpmod(sym + add), data8 LSB */
-#define R_IA64_LTOFF_DTPMOD22	0xaa	/* @ltoff(@dtpmod(sym + add)), imm22 */
-#define R_IA64_DTPREL14		0xb1	/* @dtprel(sym + add), imm14 */
-#define R_IA64_DTPREL22		0xb2	/* @dtprel(sym + add), imm22 */
-#define R_IA64_DTPREL64I	0xb3	/* @dtprel(sym + add), imm64 */
-#define R_IA64_DTPREL32MSB	0xb4	/* @dtprel(sym + add), data4 MSB */
-#define R_IA64_DTPREL32LSB	0xb5	/* @dtprel(sym + add), data4 LSB */
-#define R_IA64_DTPREL64MSB	0xb6	/* @dtprel(sym + add), data8 MSB */
-#define R_IA64_DTPREL64LSB	0xb7	/* @dtprel(sym + add), data8 LSB */
-#define R_IA64_LTOFF_DTPREL22	0xba	/* @ltoff(@dtprel(s+a)), imm22 */
-
-/* SH specific declarations */
-
-/* Processor specific flags for the ELF header e_flags field.  */
-#define EF_SH_MACH_MASK		0x1f
-#define EF_SH_UNKNOWN		0x0
-#define EF_SH1			0x1
-#define EF_SH2			0x2
-#define EF_SH3			0x3
-#define EF_SH_DSP		0x4
-#define EF_SH3_DSP		0x5
-#define EF_SH4AL_DSP		0x6
-#define EF_SH3E			0x8
-#define EF_SH4			0x9
-#define EF_SH2E			0xb
-#define EF_SH4A			0xc
-#define EF_SH2A			0xd
-#define EF_SH4_NOFPU		0x10
-#define EF_SH4A_NOFPU		0x11
-#define EF_SH4_NOMMU_NOFPU	0x12
-#define EF_SH2A_NOFPU		0x13
-#define EF_SH3_NOMMU		0x14
-#define EF_SH2A_SH4_NOFPU	0x15
-#define EF_SH2A_SH3_NOFPU	0x16
-#define EF_SH2A_SH4		0x17
-#define EF_SH2A_SH3E		0x18
-
-/* SH relocs.  */
-#define	R_SH_NONE		0
-#define	R_SH_DIR32		1
-#define	R_SH_REL32		2
-#define	R_SH_DIR8WPN		3
-#define	R_SH_IND12W		4
-#define	R_SH_DIR8WPL		5
-#define	R_SH_DIR8WPZ		6
-#define	R_SH_DIR8BP		7
-#define	R_SH_DIR8W		8
-#define	R_SH_DIR8L		9
-#define	R_SH_SWITCH16		25
-#define	R_SH_SWITCH32		26
-#define	R_SH_USES		27
-#define	R_SH_COUNT		28
-#define	R_SH_ALIGN		29
-#define	R_SH_CODE		30
-#define	R_SH_DATA		31
-#define	R_SH_LABEL		32
-#define	R_SH_SWITCH8		33
-#define	R_SH_GNU_VTINHERIT	34
-#define	R_SH_GNU_VTENTRY	35
-#define	R_SH_TLS_GD_32		144
-#define	R_SH_TLS_LD_32		145
-#define	R_SH_TLS_LDO_32		146
-#define	R_SH_TLS_IE_32		147
-#define	R_SH_TLS_LE_32		148
-#define	R_SH_TLS_DTPMOD32	149
-#define	R_SH_TLS_DTPOFF32	150
-#define	R_SH_TLS_TPOFF32	151
-#define	R_SH_GOT32		160
-#define	R_SH_PLT32		161
-#define	R_SH_COPY		162
-#define	R_SH_GLOB_DAT		163
-#define	R_SH_JMP_SLOT		164
-#define	R_SH_RELATIVE		165
-#define	R_SH_GOTOFF		166
-#define	R_SH_GOTPC		167
-/* Keep this the last entry.  */
-#define	R_SH_NUM		256
-
-/* S/390 specific definitions.  */
-
-/* Valid values for the e_flags field.  */
-
-#define EF_S390_HIGH_GPRS    0x00000001  /* High GPRs kernel facility needed.  */
-
-/* Additional s390 relocs */
-
-#define R_390_NONE		0	/* No reloc.  */
-#define R_390_8			1	/* Direct 8 bit.  */
-#define R_390_12		2	/* Direct 12 bit.  */
-#define R_390_16		3	/* Direct 16 bit.  */
-#define R_390_32		4	/* Direct 32 bit.  */
-#define R_390_PC32		5	/* PC relative 32 bit.	*/
-#define R_390_GOT12		6	/* 12 bit GOT offset.  */
-#define R_390_GOT32		7	/* 32 bit GOT offset.  */
-#define R_390_PLT32		8	/* 32 bit PC relative PLT address.  */
-#define R_390_COPY		9	/* Copy symbol at runtime.  */
-#define R_390_GLOB_DAT		10	/* Create GOT entry.  */
-#define R_390_JMP_SLOT		11	/* Create PLT entry.  */
-#define R_390_RELATIVE		12	/* Adjust by program base.  */
-#define R_390_GOTOFF32		13	/* 32 bit offset to GOT.	 */
-#define R_390_GOTPC		14	/* 32 bit PC relative offset to GOT.  */
-#define R_390_GOT16		15	/* 16 bit GOT offset.  */
-#define R_390_PC16		16	/* PC relative 16 bit.	*/
-#define R_390_PC16DBL		17	/* PC relative 16 bit shifted by 1.  */
-#define R_390_PLT16DBL		18	/* 16 bit PC rel. PLT shifted by 1.  */
-#define R_390_PC32DBL		19	/* PC relative 32 bit shifted by 1.  */
-#define R_390_PLT32DBL		20	/* 32 bit PC rel. PLT shifted by 1.  */
-#define R_390_GOTPCDBL		21	/* 32 bit PC rel. GOT shifted by 1.  */
-#define R_390_64		22	/* Direct 64 bit.  */
-#define R_390_PC64		23	/* PC relative 64 bit.	*/
-#define R_390_GOT64		24	/* 64 bit GOT offset.  */
-#define R_390_PLT64		25	/* 64 bit PC relative PLT address.  */
-#define R_390_GOTENT		26	/* 32 bit PC rel. to GOT entry >> 1. */
-#define R_390_GOTOFF16		27	/* 16 bit offset to GOT. */
-#define R_390_GOTOFF64		28	/* 64 bit offset to GOT. */
-#define R_390_GOTPLT12		29	/* 12 bit offset to jump slot.	*/
-#define R_390_GOTPLT16		30	/* 16 bit offset to jump slot.	*/
-#define R_390_GOTPLT32		31	/* 32 bit offset to jump slot.	*/
-#define R_390_GOTPLT64		32	/* 64 bit offset to jump slot.	*/
-#define R_390_GOTPLTENT		33	/* 32 bit rel. offset to jump slot.  */
-#define R_390_PLTOFF16		34	/* 16 bit offset from GOT to PLT. */
-#define R_390_PLTOFF32		35	/* 32 bit offset from GOT to PLT. */
-#define R_390_PLTOFF64		36	/* 16 bit offset from GOT to PLT. */
-#define R_390_TLS_LOAD		37	/* Tag for load insn in TLS code.  */
-#define R_390_TLS_GDCALL	38	/* Tag for function call in general
-					   dynamic TLS code. */
-#define R_390_TLS_LDCALL	39	/* Tag for function call in local
-					   dynamic TLS code. */
-#define R_390_TLS_GD32		40	/* Direct 32 bit for general dynamic
-					   thread local data.  */
-#define R_390_TLS_GD64		41	/* Direct 64 bit for general dynamic
-					  thread local data.  */
-#define R_390_TLS_GOTIE12	42	/* 12 bit GOT offset for static TLS
-					   block offset.  */
-#define R_390_TLS_GOTIE32	43	/* 32 bit GOT offset for static TLS
-					   block offset.  */
-#define R_390_TLS_GOTIE64	44	/* 64 bit GOT offset for static TLS
-					   block offset. */
-#define R_390_TLS_LDM32		45	/* Direct 32 bit for local dynamic
-					   thread local data in LE code.  */
-#define R_390_TLS_LDM64		46	/* Direct 64 bit for local dynamic
-					   thread local data in LE code.  */
-#define R_390_TLS_IE32		47	/* 32 bit address of GOT entry for
-					   negated static TLS block offset.  */
-#define R_390_TLS_IE64		48	/* 64 bit address of GOT entry for
-					   negated static TLS block offset.  */
-#define R_390_TLS_IEENT		49	/* 32 bit rel. offset to GOT entry for
-					   negated static TLS block offset.  */
-#define R_390_TLS_LE32		50	/* 32 bit negated offset relative to
-					   static TLS block.  */
-#define R_390_TLS_LE64		51	/* 64 bit negated offset relative to
-					   static TLS block.  */
-#define R_390_TLS_LDO32		52	/* 32 bit offset relative to TLS
-					   block.  */
-#define R_390_TLS_LDO64		53	/* 64 bit offset relative to TLS
-					   block.  */
-#define R_390_TLS_DTPMOD	54	/* ID of module containing symbol.  */
-#define R_390_TLS_DTPOFF	55	/* Offset in TLS block.	 */
-#define R_390_TLS_TPOFF		56	/* Negated offset in static TLS
-					   block.  */
-#define R_390_20		57	/* Direct 20 bit.  */
-#define R_390_GOT20		58	/* 20 bit GOT offset.  */
-#define R_390_GOTPLT20		59	/* 20 bit offset to jump slot.  */
-#define R_390_TLS_GOTIE20	60	/* 20 bit GOT offset for static TLS
-					   block offset.  */
-#define R_390_IRELATIVE         61      /* STT_GNU_IFUNC relocation.  */
-/* Keep this the last entry.  */
-#define R_390_NUM		62
-
-
-/* CRIS relocations.  */
-#define R_CRIS_NONE		0
-#define R_CRIS_8		1
-#define R_CRIS_16		2
-#define R_CRIS_32		3
-#define R_CRIS_8_PCREL		4
-#define R_CRIS_16_PCREL		5
-#define R_CRIS_32_PCREL		6
-#define R_CRIS_GNU_VTINHERIT	7
-#define R_CRIS_GNU_VTENTRY	8
-#define R_CRIS_COPY		9
-#define R_CRIS_GLOB_DAT		10
-#define R_CRIS_JUMP_SLOT	11
-#define R_CRIS_RELATIVE		12
-#define R_CRIS_16_GOT		13
-#define R_CRIS_32_GOT		14
-#define R_CRIS_16_GOTPLT	15
-#define R_CRIS_32_GOTPLT	16
-#define R_CRIS_32_GOTREL	17
-#define R_CRIS_32_PLT_GOTREL	18
-#define R_CRIS_32_PLT_PCREL	19
-
-#define R_CRIS_NUM		20
-
-
-/* AMD x86-64 relocations.  */
-#define R_X86_64_NONE		0	/* No reloc */
-#define R_X86_64_64		1	/* Direct 64 bit  */
-#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
-#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
-#define R_X86_64_PLT32		4	/* 32 bit PLT address */
-#define R_X86_64_COPY		5	/* Copy symbol at runtime */
-#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
-#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
-#define R_X86_64_RELATIVE	8	/* Adjust by program base */
-#define R_X86_64_GOTPCREL	9	/* 32 bit signed PC relative
-					   offset to GOT */
-#define R_X86_64_32		10	/* Direct 32 bit zero extended */
-#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
-#define R_X86_64_16		12	/* Direct 16 bit zero extended */
-#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
-#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
-#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
-#define R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
-#define R_X86_64_DTPOFF64	17	/* Offset in module's TLS block */
-#define R_X86_64_TPOFF64	18	/* Offset in initial TLS block */
-#define R_X86_64_TLSGD		19	/* 32 bit signed PC relative offset
-					   to two GOT entries for GD symbol */
-#define R_X86_64_TLSLD		20	/* 32 bit signed PC relative offset
-					   to two GOT entries for LD symbol */
-#define R_X86_64_DTPOFF32	21	/* Offset in TLS block */
-#define R_X86_64_GOTTPOFF	22	/* 32 bit signed PC relative offset
-					   to GOT entry for IE symbol */
-#define R_X86_64_TPOFF32	23	/* Offset in initial TLS block */
-#define R_X86_64_PC64		24	/* PC relative 64 bit */
-#define R_X86_64_GOTOFF64	25	/* 64 bit offset to GOT */
-#define R_X86_64_GOTPC32	26	/* 32 bit signed pc relative
-					   offset to GOT */
-#define R_X86_64_GOT64		27	/* 64-bit GOT entry offset */
-#define R_X86_64_GOTPCREL64	28	/* 64-bit PC relative offset
-					   to GOT entry */
-#define R_X86_64_GOTPC64	29	/* 64-bit PC relative offset to GOT */
-#define R_X86_64_GOTPLT64	30 	/* like GOT64, says PLT entry needed */
-#define R_X86_64_PLTOFF64	31	/* 64-bit GOT relative offset
-					   to PLT entry */
-#define R_X86_64_SIZE32		32	/* Size of symbol plus 32-bit addend */
-#define R_X86_64_SIZE64		33	/* Size of symbol plus 64-bit addend */
-#define R_X86_64_GOTPC32_TLSDESC 34	/* GOT offset for TLS descriptor.  */
-#define R_X86_64_TLSDESC_CALL   35	/* Marker for call through TLS
-					   descriptor.  */
-#define R_X86_64_TLSDESC        36	/* TLS descriptor.  */
-#define R_X86_64_IRELATIVE	37	/* Adjust indirectly by program base */
-#define R_X86_64_RELATIVE64	38	/* 64-bit adjust by program base */
-
-#define R_X86_64_NUM		39
-
-
-/* AM33 relocations.  */
-#define R_MN10300_NONE		0	/* No reloc.  */
-#define R_MN10300_32		1	/* Direct 32 bit.  */
-#define R_MN10300_16		2	/* Direct 16 bit.  */
-#define R_MN10300_8		3	/* Direct 8 bit.  */
-#define R_MN10300_PCREL32	4	/* PC-relative 32-bit.  */
-#define R_MN10300_PCREL16	5	/* PC-relative 16-bit signed.  */
-#define R_MN10300_PCREL8	6	/* PC-relative 8-bit signed.  */
-#define R_MN10300_GNU_VTINHERIT	7	/* Ancient C++ vtable garbage... */
-#define R_MN10300_GNU_VTENTRY	8	/* ... collection annotation.  */
-#define R_MN10300_24		9	/* Direct 24 bit.  */
-#define R_MN10300_GOTPC32	10	/* 32-bit PCrel offset to GOT.  */
-#define R_MN10300_GOTPC16	11	/* 16-bit PCrel offset to GOT.  */
-#define R_MN10300_GOTOFF32	12	/* 32-bit offset from GOT.  */
-#define R_MN10300_GOTOFF24	13	/* 24-bit offset from GOT.  */
-#define R_MN10300_GOTOFF16	14	/* 16-bit offset from GOT.  */
-#define R_MN10300_PLT32		15	/* 32-bit PCrel to PLT entry.  */
-#define R_MN10300_PLT16		16	/* 16-bit PCrel to PLT entry.  */
-#define R_MN10300_GOT32		17	/* 32-bit offset to GOT entry.  */
-#define R_MN10300_GOT24		18	/* 24-bit offset to GOT entry.  */
-#define R_MN10300_GOT16		19	/* 16-bit offset to GOT entry.  */
-#define R_MN10300_COPY		20	/* Copy symbol at runtime.  */
-#define R_MN10300_GLOB_DAT	21	/* Create GOT entry.  */
-#define R_MN10300_JMP_SLOT	22	/* Create PLT entry.  */
-#define R_MN10300_RELATIVE	23	/* Adjust by program base.  */
-#define R_MN10300_TLS_GD	24	/* 32-bit offset for global dynamic.  */
-#define R_MN10300_TLS_LD	25	/* 32-bit offset for local dynamic.  */
-#define R_MN10300_TLS_LDO	26	/* Module-relative offset.  */
-#define R_MN10300_TLS_GOTIE	27	/* GOT offset for static TLS block
-					   offset.  */
-#define R_MN10300_TLS_IE	28	/* GOT address for static TLS block
-					   offset.  */
-#define R_MN10300_TLS_LE	29	/* Offset relative to static TLS
-					   block.  */
-#define R_MN10300_TLS_DTPMOD	30	/* ID of module containing symbol.  */
-#define R_MN10300_TLS_DTPOFF	31	/* Offset in module TLS block.  */
-#define R_MN10300_TLS_TPOFF	32	/* Offset in static TLS block.  */
-#define R_MN10300_SYM_DIFF	33	/* Adjustment for next reloc as needed
-					   by linker relaxation.  */
-#define R_MN10300_ALIGN		34	/* Alignment requirement for linker
-					   relaxation.  */
-#define R_MN10300_NUM		35
-
-
-/* M32R relocs.  */
-#define R_M32R_NONE		0	/* No reloc. */
-#define R_M32R_16		1	/* Direct 16 bit. */
-#define R_M32R_32		2	/* Direct 32 bit. */
-#define R_M32R_24		3	/* Direct 24 bit. */
-#define R_M32R_10_PCREL		4	/* PC relative 10 bit shifted. */
-#define R_M32R_18_PCREL		5	/* PC relative 18 bit shifted. */
-#define R_M32R_26_PCREL		6	/* PC relative 26 bit shifted. */
-#define R_M32R_HI16_ULO		7	/* High 16 bit with unsigned low. */
-#define R_M32R_HI16_SLO		8	/* High 16 bit with signed low. */
-#define R_M32R_LO16		9	/* Low 16 bit. */
-#define R_M32R_SDA16		10	/* 16 bit offset in SDA. */
-#define R_M32R_GNU_VTINHERIT	11
-#define R_M32R_GNU_VTENTRY	12
-/* M32R relocs use SHT_RELA.  */
-#define R_M32R_16_RELA		33	/* Direct 16 bit. */
-#define R_M32R_32_RELA		34	/* Direct 32 bit. */
-#define R_M32R_24_RELA		35	/* Direct 24 bit. */
-#define R_M32R_10_PCREL_RELA	36	/* PC relative 10 bit shifted. */
-#define R_M32R_18_PCREL_RELA	37	/* PC relative 18 bit shifted. */
-#define R_M32R_26_PCREL_RELA	38	/* PC relative 26 bit shifted. */
-#define R_M32R_HI16_ULO_RELA	39	/* High 16 bit with unsigned low */
-#define R_M32R_HI16_SLO_RELA	40	/* High 16 bit with signed low */
-#define R_M32R_LO16_RELA	41	/* Low 16 bit */
-#define R_M32R_SDA16_RELA	42	/* 16 bit offset in SDA */
-#define R_M32R_RELA_GNU_VTINHERIT	43
-#define R_M32R_RELA_GNU_VTENTRY	44
-#define R_M32R_REL32		45	/* PC relative 32 bit.  */
-
-#define R_M32R_GOT24		48	/* 24 bit GOT entry */
-#define R_M32R_26_PLTREL	49	/* 26 bit PC relative to PLT shifted */
-#define R_M32R_COPY		50	/* Copy symbol at runtime */
-#define R_M32R_GLOB_DAT		51	/* Create GOT entry */
-#define R_M32R_JMP_SLOT		52	/* Create PLT entry */
-#define R_M32R_RELATIVE		53	/* Adjust by program base */
-#define R_M32R_GOTOFF		54	/* 24 bit offset to GOT */
-#define R_M32R_GOTPC24		55	/* 24 bit PC relative offset to GOT */
-#define R_M32R_GOT16_HI_ULO	56	/* High 16 bit GOT entry with unsigned
-					   low */
-#define R_M32R_GOT16_HI_SLO	57	/* High 16 bit GOT entry with signed
-					   low */
-#define R_M32R_GOT16_LO		58	/* Low 16 bit GOT entry */
-#define R_M32R_GOTPC_HI_ULO	59	/* High 16 bit PC relative offset to
-					   GOT with unsigned low */
-#define R_M32R_GOTPC_HI_SLO	60	/* High 16 bit PC relative offset to
-					   GOT with signed low */
-#define R_M32R_GOTPC_LO		61	/* Low 16 bit PC relative offset to
-					   GOT */
-#define R_M32R_GOTOFF_HI_ULO	62	/* High 16 bit offset to GOT
-					   with unsigned low */
-#define R_M32R_GOTOFF_HI_SLO	63	/* High 16 bit offset to GOT
-					   with signed low */
-#define R_M32R_GOTOFF_LO	64	/* Low 16 bit offset to GOT */
-#define R_M32R_NUM		256	/* Keep this the last entry. */
-
-/* MicroBlaze relocations */
-#define R_MICROBLAZE_NONE		0	/* No reloc. */
-#define R_MICROBLAZE_32 		1	/* Direct 32 bit. */
-#define R_MICROBLAZE_32_PCREL		2	/* PC relative 32 bit. */
-#define R_MICROBLAZE_64_PCREL		3	/* PC relative 64 bit. */
-#define R_MICROBLAZE_32_PCREL_LO	4	/* Low 16 bits of PCREL32. */
-#define R_MICROBLAZE_64 		5	/* Direct 64 bit. */
-#define R_MICROBLAZE_32_LO		6	/* Low 16 bit. */
-#define R_MICROBLAZE_SRO32		7	/* Read-only small data area. */
-#define R_MICROBLAZE_SRW32		8	/* Read-write small data area. */
-#define R_MICROBLAZE_64_NONE		9	/* No reloc. */
-#define R_MICROBLAZE_32_SYM_OP_SYM	10	/* Symbol Op Symbol relocation. */
-#define R_MICROBLAZE_GNU_VTINHERIT	11	/* GNU C++ vtable hierarchy. */
-#define R_MICROBLAZE_GNU_VTENTRY	12	/* GNU C++ vtable member usage. */
-#define R_MICROBLAZE_GOTPC_64		13	/* PC-relative GOT offset.  */
-#define R_MICROBLAZE_GOT_64		14	/* GOT entry offset.  */
-#define R_MICROBLAZE_PLT_64		15	/* PLT offset (PC-relative).  */
-#define R_MICROBLAZE_REL		16	/* Adjust by program base.  */
-#define R_MICROBLAZE_JUMP_SLOT		17	/* Create PLT entry.  */
-#define R_MICROBLAZE_GLOB_DAT		18	/* Create GOT entry.  */
-#define R_MICROBLAZE_GOTOFF_64		19	/* 64 bit offset to GOT. */
-#define R_MICROBLAZE_GOTOFF_32		20	/* 32 bit offset to GOT. */
-#define R_MICROBLAZE_COPY		21	/* Runtime copy.  */
-#define R_MICROBLAZE_TLS		22	/* TLS Reloc. */
-#define R_MICROBLAZE_TLSGD		23	/* TLS General Dynamic. */
-#define R_MICROBLAZE_TLSLD		24	/* TLS Local Dynamic. */
-#define R_MICROBLAZE_TLSDTPMOD32	25	/* TLS Module ID. */
-#define R_MICROBLAZE_TLSDTPREL32	26	/* TLS Offset Within TLS Block. */
-#define R_MICROBLAZE_TLSDTPREL64	27	/* TLS Offset Within TLS Block. */
-#define R_MICROBLAZE_TLSGOTTPREL32	28	/* TLS Offset From Thread Pointer. */
-#define R_MICROBLAZE_TLSTPREL32 	29	/* TLS Offset From Thread Pointer. */
-
-/* Legal values for d_tag (dynamic entry type).  */
-#define DT_NIOS2_GP             0x70000002 /* Address of _gp.  */
-
-/* Nios II relocations.  */
-#define R_NIOS2_NONE		0	/* No reloc.  */
-#define R_NIOS2_S16		1	/* Direct signed 16 bit.  */
-#define R_NIOS2_U16		2	/* Direct unsigned 16 bit.  */
-#define R_NIOS2_PCREL16		3	/* PC relative 16 bit.  */
-#define R_NIOS2_CALL26		4	/* Direct call.  */
-#define R_NIOS2_IMM5		5	/* 5 bit constant expression.  */
-#define R_NIOS2_CACHE_OPX	6	/* 5 bit expression, shift 22.  */
-#define R_NIOS2_IMM6		7	/* 6 bit constant expression.  */
-#define R_NIOS2_IMM8		8	/* 8 bit constant expression.  */
-#define R_NIOS2_HI16		9	/* High 16 bit.  */
-#define R_NIOS2_LO16		10	/* Low 16 bit.  */
-#define R_NIOS2_HIADJ16		11	/* High 16 bit, adjusted.  */
-#define R_NIOS2_BFD_RELOC_32	12	/* 32 bit symbol value + addend.  */
-#define R_NIOS2_BFD_RELOC_16	13	/* 16 bit symbol value + addend.  */
-#define R_NIOS2_BFD_RELOC_8	14	/* 8 bit symbol value + addend.  */
-#define R_NIOS2_GPREL		15	/* 16 bit GP pointer offset.  */
-#define R_NIOS2_GNU_VTINHERIT	16	/* GNU C++ vtable hierarchy.  */
-#define R_NIOS2_GNU_VTENTRY	17	/* GNU C++ vtable member usage.  */
-#define R_NIOS2_UJMP		18	/* Unconditional branch.  */
-#define R_NIOS2_CJMP		19	/* Conditional branch.  */
-#define R_NIOS2_CALLR		20	/* Indirect call through register.  */
-#define R_NIOS2_ALIGN		21	/* Alignment requirement for
-					   linker relaxation.  */
-#define R_NIOS2_GOT16		22	/* 16 bit GOT entry.  */
-#define R_NIOS2_CALL16		23	/* 16 bit GOT entry for function.  */
-#define R_NIOS2_GOTOFF_LO	24	/* %lo of offset to GOT pointer.  */
-#define R_NIOS2_GOTOFF_HA	25	/* %hiadj of offset to GOT pointer.  */
-#define R_NIOS2_PCREL_LO	26	/* %lo of PC relative offset.  */
-#define R_NIOS2_PCREL_HA	27	/* %hiadj of PC relative offset.  */
-#define R_NIOS2_TLS_GD16	28	/* 16 bit GOT offset for TLS GD.  */
-#define R_NIOS2_TLS_LDM16	29	/* 16 bit GOT offset for TLS LDM.  */
-#define R_NIOS2_TLS_LDO16	30	/* 16 bit module relative offset.  */
-#define R_NIOS2_TLS_IE16	31	/* 16 bit GOT offset for TLS IE.  */
-#define R_NIOS2_TLS_LE16	32	/* 16 bit LE TP-relative offset.  */
-#define R_NIOS2_TLS_DTPMOD	33	/* Module number.  */
-#define R_NIOS2_TLS_DTPREL	34	/* Module-relative offset.  */
-#define R_NIOS2_TLS_TPREL	35	/* TP-relative offset.  */
-#define R_NIOS2_COPY		36	/* Copy symbol at runtime.  */
-#define R_NIOS2_GLOB_DAT	37	/* Create GOT entry.  */
-#define R_NIOS2_JUMP_SLOT	38	/* Create PLT entry.  */
-#define R_NIOS2_RELATIVE	39	/* Adjust by program base.  */
-#define R_NIOS2_GOTOFF		40	/* 16 bit offset to GOT pointer.  */
-#define R_NIOS2_CALL26_NOAT	41	/* Direct call in .noat section.  */
-#define R_NIOS2_GOT_LO		42	/* %lo() of GOT entry.  */
-#define R_NIOS2_GOT_HA		43	/* %hiadj() of GOT entry.  */
-#define R_NIOS2_CALL_LO		44	/* %lo() of function GOT entry.  */
-#define R_NIOS2_CALL_HA		45	/* %hiadj() of function GOT entry.  */
-
-/* TILEPro relocations.  */
-#define R_TILEPRO_NONE		0	/* No reloc */
-#define R_TILEPRO_32		1	/* Direct 32 bit */
-#define R_TILEPRO_16		2	/* Direct 16 bit */
-#define R_TILEPRO_8		3	/* Direct 8 bit */
-#define R_TILEPRO_32_PCREL	4	/* PC relative 32 bit */
-#define R_TILEPRO_16_PCREL	5	/* PC relative 16 bit */
-#define R_TILEPRO_8_PCREL	6	/* PC relative 8 bit */
-#define R_TILEPRO_LO16		7	/* Low 16 bit */
-#define R_TILEPRO_HI16		8	/* High 16 bit */
-#define R_TILEPRO_HA16		9	/* High 16 bit, adjusted */
-#define R_TILEPRO_COPY		10	/* Copy relocation */
-#define R_TILEPRO_GLOB_DAT	11	/* Create GOT entry */
-#define R_TILEPRO_JMP_SLOT	12	/* Create PLT entry */
-#define R_TILEPRO_RELATIVE	13	/* Adjust by program base */
-#define R_TILEPRO_BROFF_X1	14	/* X1 pipe branch offset */
-#define R_TILEPRO_JOFFLONG_X1	15	/* X1 pipe jump offset */
-#define R_TILEPRO_JOFFLONG_X1_PLT 16	/* X1 pipe jump offset to PLT */
-#define R_TILEPRO_IMM8_X0	17	/* X0 pipe 8-bit */
-#define R_TILEPRO_IMM8_Y0	18	/* Y0 pipe 8-bit */
-#define R_TILEPRO_IMM8_X1	19	/* X1 pipe 8-bit */
-#define R_TILEPRO_IMM8_Y1	20	/* Y1 pipe 8-bit */
-#define R_TILEPRO_MT_IMM15_X1	21	/* X1 pipe mtspr */
-#define R_TILEPRO_MF_IMM15_X1	22	/* X1 pipe mfspr */
-#define R_TILEPRO_IMM16_X0	23	/* X0 pipe 16-bit */
-#define R_TILEPRO_IMM16_X1	24	/* X1 pipe 16-bit */
-#define R_TILEPRO_IMM16_X0_LO	25	/* X0 pipe low 16-bit */
-#define R_TILEPRO_IMM16_X1_LO	26	/* X1 pipe low 16-bit */
-#define R_TILEPRO_IMM16_X0_HI	27	/* X0 pipe high 16-bit */
-#define R_TILEPRO_IMM16_X1_HI	28	/* X1 pipe high 16-bit */
-#define R_TILEPRO_IMM16_X0_HA	29	/* X0 pipe high 16-bit, adjusted */
-#define R_TILEPRO_IMM16_X1_HA	30	/* X1 pipe high 16-bit, adjusted */
-#define R_TILEPRO_IMM16_X0_PCREL 31	/* X0 pipe PC relative 16 bit */
-#define R_TILEPRO_IMM16_X1_PCREL 32	/* X1 pipe PC relative 16 bit */
-#define R_TILEPRO_IMM16_X0_LO_PCREL 33	/* X0 pipe PC relative low 16 bit */
-#define R_TILEPRO_IMM16_X1_LO_PCREL 34	/* X1 pipe PC relative low 16 bit */
-#define R_TILEPRO_IMM16_X0_HI_PCREL 35	/* X0 pipe PC relative high 16 bit */
-#define R_TILEPRO_IMM16_X1_HI_PCREL 36	/* X1 pipe PC relative high 16 bit */
-#define R_TILEPRO_IMM16_X0_HA_PCREL 37	/* X0 pipe PC relative ha() 16 bit */
-#define R_TILEPRO_IMM16_X1_HA_PCREL 38	/* X1 pipe PC relative ha() 16 bit */
-#define R_TILEPRO_IMM16_X0_GOT	39	/* X0 pipe 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X1_GOT	40	/* X1 pipe 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X0_GOT_LO 41	/* X0 pipe low 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X1_GOT_LO 42	/* X1 pipe low 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X0_GOT_HI 43	/* X0 pipe high 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X1_GOT_HI 44	/* X1 pipe high 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X0_GOT_HA 45	/* X0 pipe ha() 16-bit GOT offset */
-#define R_TILEPRO_IMM16_X1_GOT_HA 46	/* X1 pipe ha() 16-bit GOT offset */
-#define R_TILEPRO_MMSTART_X0	47	/* X0 pipe mm "start" */
-#define R_TILEPRO_MMEND_X0	48	/* X0 pipe mm "end" */
-#define R_TILEPRO_MMSTART_X1	49	/* X1 pipe mm "start" */
-#define R_TILEPRO_MMEND_X1	50	/* X1 pipe mm "end" */
-#define R_TILEPRO_SHAMT_X0	51	/* X0 pipe shift amount */
-#define R_TILEPRO_SHAMT_X1	52	/* X1 pipe shift amount */
-#define R_TILEPRO_SHAMT_Y0	53	/* Y0 pipe shift amount */
-#define R_TILEPRO_SHAMT_Y1	54	/* Y1 pipe shift amount */
-#define R_TILEPRO_DEST_IMM8_X1	55	/* X1 pipe destination 8-bit */
-/* Relocs 56-59 are currently not defined.  */
-#define R_TILEPRO_TLS_GD_CALL	60	/* "jal" for TLS GD */
-#define R_TILEPRO_IMM8_X0_TLS_GD_ADD 61	/* X0 pipe "addi" for TLS GD */
-#define R_TILEPRO_IMM8_X1_TLS_GD_ADD 62	/* X1 pipe "addi" for TLS GD */
-#define R_TILEPRO_IMM8_Y0_TLS_GD_ADD 63	/* Y0 pipe "addi" for TLS GD */
-#define R_TILEPRO_IMM8_Y1_TLS_GD_ADD 64	/* Y1 pipe "addi" for TLS GD */
-#define R_TILEPRO_TLS_IE_LOAD	65	/* "lw_tls" for TLS IE */
-#define R_TILEPRO_IMM16_X0_TLS_GD 66	/* X0 pipe 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X1_TLS_GD 67	/* X1 pipe 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X0_TLS_GD_LO 68	/* X0 pipe low 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X1_TLS_GD_LO 69	/* X1 pipe low 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X0_TLS_GD_HI 70	/* X0 pipe high 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X1_TLS_GD_HI 71	/* X1 pipe high 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X0_TLS_GD_HA 72	/* X0 pipe ha() 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X1_TLS_GD_HA 73	/* X1 pipe ha() 16-bit TLS GD offset */
-#define R_TILEPRO_IMM16_X0_TLS_IE 74	/* X0 pipe 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X1_TLS_IE 75	/* X1 pipe 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X0_TLS_IE_LO 76	/* X0 pipe low 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X1_TLS_IE_LO 77	/* X1 pipe low 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X0_TLS_IE_HI 78	/* X0 pipe high 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X1_TLS_IE_HI 79	/* X1 pipe high 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X0_TLS_IE_HA 80	/* X0 pipe ha() 16-bit TLS IE offset */
-#define R_TILEPRO_IMM16_X1_TLS_IE_HA 81	/* X1 pipe ha() 16-bit TLS IE offset */
-#define R_TILEPRO_TLS_DTPMOD32	82	/* ID of module containing symbol */
-#define R_TILEPRO_TLS_DTPOFF32	83	/* Offset in TLS block */
-#define R_TILEPRO_TLS_TPOFF32	84	/* Offset in static TLS block */
-#define R_TILEPRO_IMM16_X0_TLS_LE 85	/* X0 pipe 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X1_TLS_LE 86	/* X1 pipe 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X0_TLS_LE_LO 87	/* X0 pipe low 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X1_TLS_LE_LO 88	/* X1 pipe low 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X0_TLS_LE_HI 89	/* X0 pipe high 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X1_TLS_LE_HI 90	/* X1 pipe high 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X0_TLS_LE_HA 91	/* X0 pipe ha() 16-bit TLS LE offset */
-#define R_TILEPRO_IMM16_X1_TLS_LE_HA 92	/* X1 pipe ha() 16-bit TLS LE offset */
-
-#define R_TILEPRO_GNU_VTINHERIT	128	/* GNU C++ vtable hierarchy */
-#define R_TILEPRO_GNU_VTENTRY	129	/* GNU C++ vtable member usage */
-
-#define R_TILEPRO_NUM		130
-
-
-/* TILE-Gx relocations.  */
-#define R_TILEGX_NONE		0	/* No reloc */
-#define R_TILEGX_64		1	/* Direct 64 bit */
-#define R_TILEGX_32		2	/* Direct 32 bit */
-#define R_TILEGX_16		3	/* Direct 16 bit */
-#define R_TILEGX_8		4	/* Direct 8 bit */
-#define R_TILEGX_64_PCREL	5	/* PC relative 64 bit */
-#define R_TILEGX_32_PCREL	6	/* PC relative 32 bit */
-#define R_TILEGX_16_PCREL	7	/* PC relative 16 bit */
-#define R_TILEGX_8_PCREL	8	/* PC relative 8 bit */
-#define R_TILEGX_HW0		9	/* hword 0 16-bit */
-#define R_TILEGX_HW1		10	/* hword 1 16-bit */
-#define R_TILEGX_HW2		11	/* hword 2 16-bit */
-#define R_TILEGX_HW3		12	/* hword 3 16-bit */
-#define R_TILEGX_HW0_LAST	13	/* last hword 0 16-bit */
-#define R_TILEGX_HW1_LAST	14	/* last hword 1 16-bit */
-#define R_TILEGX_HW2_LAST	15	/* last hword 2 16-bit */
-#define R_TILEGX_COPY		16	/* Copy relocation */
-#define R_TILEGX_GLOB_DAT	17	/* Create GOT entry */
-#define R_TILEGX_JMP_SLOT	18	/* Create PLT entry */
-#define R_TILEGX_RELATIVE	19	/* Adjust by program base */
-#define R_TILEGX_BROFF_X1	20	/* X1 pipe branch offset */
-#define R_TILEGX_JUMPOFF_X1	21	/* X1 pipe jump offset */
-#define R_TILEGX_JUMPOFF_X1_PLT	22	/* X1 pipe jump offset to PLT */
-#define R_TILEGX_IMM8_X0	23	/* X0 pipe 8-bit */
-#define R_TILEGX_IMM8_Y0	24	/* Y0 pipe 8-bit */
-#define R_TILEGX_IMM8_X1	25	/* X1 pipe 8-bit */
-#define R_TILEGX_IMM8_Y1	26	/* Y1 pipe 8-bit */
-#define R_TILEGX_DEST_IMM8_X1	27	/* X1 pipe destination 8-bit */
-#define R_TILEGX_MT_IMM14_X1	28	/* X1 pipe mtspr */
-#define R_TILEGX_MF_IMM14_X1	29	/* X1 pipe mfspr */
-#define R_TILEGX_MMSTART_X0	30	/* X0 pipe mm "start" */
-#define R_TILEGX_MMEND_X0	31	/* X0 pipe mm "end" */
-#define R_TILEGX_SHAMT_X0	32	/* X0 pipe shift amount */
-#define R_TILEGX_SHAMT_X1	33	/* X1 pipe shift amount */
-#define R_TILEGX_SHAMT_Y0	34	/* Y0 pipe shift amount */
-#define R_TILEGX_SHAMT_Y1	35	/* Y1 pipe shift amount */
-#define R_TILEGX_IMM16_X0_HW0	36	/* X0 pipe hword 0 */
-#define R_TILEGX_IMM16_X1_HW0	37	/* X1 pipe hword 0 */
-#define R_TILEGX_IMM16_X0_HW1	38	/* X0 pipe hword 1 */
-#define R_TILEGX_IMM16_X1_HW1	39	/* X1 pipe hword 1 */
-#define R_TILEGX_IMM16_X0_HW2	40	/* X0 pipe hword 2 */
-#define R_TILEGX_IMM16_X1_HW2	41	/* X1 pipe hword 2 */
-#define R_TILEGX_IMM16_X0_HW3	42	/* X0 pipe hword 3 */
-#define R_TILEGX_IMM16_X1_HW3	43	/* X1 pipe hword 3 */
-#define R_TILEGX_IMM16_X0_HW0_LAST 44	/* X0 pipe last hword 0 */
-#define R_TILEGX_IMM16_X1_HW0_LAST 45	/* X1 pipe last hword 0 */
-#define R_TILEGX_IMM16_X0_HW1_LAST 46	/* X0 pipe last hword 1 */
-#define R_TILEGX_IMM16_X1_HW1_LAST 47	/* X1 pipe last hword 1 */
-#define R_TILEGX_IMM16_X0_HW2_LAST 48	/* X0 pipe last hword 2 */
-#define R_TILEGX_IMM16_X1_HW2_LAST 49	/* X1 pipe last hword 2 */
-#define R_TILEGX_IMM16_X0_HW0_PCREL 50	/* X0 pipe PC relative hword 0 */
-#define R_TILEGX_IMM16_X1_HW0_PCREL 51	/* X1 pipe PC relative hword 0 */
-#define R_TILEGX_IMM16_X0_HW1_PCREL 52	/* X0 pipe PC relative hword 1 */
-#define R_TILEGX_IMM16_X1_HW1_PCREL 53	/* X1 pipe PC relative hword 1 */
-#define R_TILEGX_IMM16_X0_HW2_PCREL 54	/* X0 pipe PC relative hword 2 */
-#define R_TILEGX_IMM16_X1_HW2_PCREL 55	/* X1 pipe PC relative hword 2 */
-#define R_TILEGX_IMM16_X0_HW3_PCREL 56	/* X0 pipe PC relative hword 3 */
-#define R_TILEGX_IMM16_X1_HW3_PCREL 57	/* X1 pipe PC relative hword 3 */
-#define R_TILEGX_IMM16_X0_HW0_LAST_PCREL 58 /* X0 pipe PC-rel last hword 0 */
-#define R_TILEGX_IMM16_X1_HW0_LAST_PCREL 59 /* X1 pipe PC-rel last hword 0 */
-#define R_TILEGX_IMM16_X0_HW1_LAST_PCREL 60 /* X0 pipe PC-rel last hword 1 */
-#define R_TILEGX_IMM16_X1_HW1_LAST_PCREL 61 /* X1 pipe PC-rel last hword 1 */
-#define R_TILEGX_IMM16_X0_HW2_LAST_PCREL 62 /* X0 pipe PC-rel last hword 2 */
-#define R_TILEGX_IMM16_X1_HW2_LAST_PCREL 63 /* X1 pipe PC-rel last hword 2 */
-#define R_TILEGX_IMM16_X0_HW0_GOT 64	/* X0 pipe hword 0 GOT offset */
-#define R_TILEGX_IMM16_X1_HW0_GOT 65	/* X1 pipe hword 0 GOT offset */
-#define R_TILEGX_IMM16_X0_HW0_PLT_PCREL 66 /* X0 pipe PC-rel PLT hword 0 */
-#define R_TILEGX_IMM16_X1_HW0_PLT_PCREL 67 /* X1 pipe PC-rel PLT hword 0 */
-#define R_TILEGX_IMM16_X0_HW1_PLT_PCREL 68 /* X0 pipe PC-rel PLT hword 1 */
-#define R_TILEGX_IMM16_X1_HW1_PLT_PCREL 69 /* X1 pipe PC-rel PLT hword 1 */
-#define R_TILEGX_IMM16_X0_HW2_PLT_PCREL 70 /* X0 pipe PC-rel PLT hword 2 */
-#define R_TILEGX_IMM16_X1_HW2_PLT_PCREL 71 /* X1 pipe PC-rel PLT hword 2 */
-#define R_TILEGX_IMM16_X0_HW0_LAST_GOT 72 /* X0 pipe last hword 0 GOT offset */
-#define R_TILEGX_IMM16_X1_HW0_LAST_GOT 73 /* X1 pipe last hword 0 GOT offset */
-#define R_TILEGX_IMM16_X0_HW1_LAST_GOT 74 /* X0 pipe last hword 1 GOT offset */
-#define R_TILEGX_IMM16_X1_HW1_LAST_GOT 75 /* X1 pipe last hword 1 GOT offset */
-#define R_TILEGX_IMM16_X0_HW3_PLT_PCREL 76 /* X0 pipe PC-rel PLT hword 3 */
-#define R_TILEGX_IMM16_X1_HW3_PLT_PCREL 77 /* X1 pipe PC-rel PLT hword 3 */
-#define R_TILEGX_IMM16_X0_HW0_TLS_GD 78	/* X0 pipe hword 0 TLS GD offset */
-#define R_TILEGX_IMM16_X1_HW0_TLS_GD 79	/* X1 pipe hword 0 TLS GD offset */
-#define R_TILEGX_IMM16_X0_HW0_TLS_LE 80	/* X0 pipe hword 0 TLS LE offset */
-#define R_TILEGX_IMM16_X1_HW0_TLS_LE 81	/* X1 pipe hword 0 TLS LE offset */
-#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_LE 82 /* X0 pipe last hword 0 LE off */
-#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_LE 83 /* X1 pipe last hword 0 LE off */
-#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_LE 84 /* X0 pipe last hword 1 LE off */
-#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_LE 85 /* X1 pipe last hword 1 LE off */
-#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_GD 86 /* X0 pipe last hword 0 GD off */
-#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_GD 87 /* X1 pipe last hword 0 GD off */
-#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_GD 88 /* X0 pipe last hword 1 GD off */
-#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_GD 89 /* X1 pipe last hword 1 GD off */
-/* Relocs 90-91 are currently not defined.  */
-#define R_TILEGX_IMM16_X0_HW0_TLS_IE 92	/* X0 pipe hword 0 TLS IE offset */
-#define R_TILEGX_IMM16_X1_HW0_TLS_IE 93	/* X1 pipe hword 0 TLS IE offset */
-#define R_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL 94 /* X0 pipe PC-rel PLT last hword 0 */
-#define R_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL 95 /* X1 pipe PC-rel PLT last hword 0 */
-#define R_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL 96 /* X0 pipe PC-rel PLT last hword 1 */
-#define R_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL 97 /* X1 pipe PC-rel PLT last hword 1 */
-#define R_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL 98 /* X0 pipe PC-rel PLT last hword 2 */
-#define R_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL 99 /* X1 pipe PC-rel PLT last hword 2 */
-#define R_TILEGX_IMM16_X0_HW0_LAST_TLS_IE 100 /* X0 pipe last hword 0 IE off */
-#define R_TILEGX_IMM16_X1_HW0_LAST_TLS_IE 101 /* X1 pipe last hword 0 IE off */
-#define R_TILEGX_IMM16_X0_HW1_LAST_TLS_IE 102 /* X0 pipe last hword 1 IE off */
-#define R_TILEGX_IMM16_X1_HW1_LAST_TLS_IE 103 /* X1 pipe last hword 1 IE off */
-/* Relocs 104-105 are currently not defined.  */
-#define R_TILEGX_TLS_DTPMOD64	106	/* 64-bit ID of symbol's module */
-#define R_TILEGX_TLS_DTPOFF64	107	/* 64-bit offset in TLS block */
-#define R_TILEGX_TLS_TPOFF64	108	/* 64-bit offset in static TLS block */
-#define R_TILEGX_TLS_DTPMOD32	109	/* 32-bit ID of symbol's module */
-#define R_TILEGX_TLS_DTPOFF32	110	/* 32-bit offset in TLS block */
-#define R_TILEGX_TLS_TPOFF32	111	/* 32-bit offset in static TLS block */
-#define R_TILEGX_TLS_GD_CALL	112	/* "jal" for TLS GD */
-#define R_TILEGX_IMM8_X0_TLS_GD_ADD 113	/* X0 pipe "addi" for TLS GD */
-#define R_TILEGX_IMM8_X1_TLS_GD_ADD 114	/* X1 pipe "addi" for TLS GD */
-#define R_TILEGX_IMM8_Y0_TLS_GD_ADD 115	/* Y0 pipe "addi" for TLS GD */
-#define R_TILEGX_IMM8_Y1_TLS_GD_ADD 116	/* Y1 pipe "addi" for TLS GD */
-#define R_TILEGX_TLS_IE_LOAD	117	/* "ld_tls" for TLS IE */
-#define R_TILEGX_IMM8_X0_TLS_ADD 118	/* X0 pipe "addi" for TLS GD/IE */
-#define R_TILEGX_IMM8_X1_TLS_ADD 119	/* X1 pipe "addi" for TLS GD/IE */
-#define R_TILEGX_IMM8_Y0_TLS_ADD 120	/* Y0 pipe "addi" for TLS GD/IE */
-#define R_TILEGX_IMM8_Y1_TLS_ADD 121	/* Y1 pipe "addi" for TLS GD/IE */
-
-#define R_TILEGX_GNU_VTINHERIT	128	/* GNU C++ vtable hierarchy */
-#define R_TILEGX_GNU_VTENTRY	129	/* GNU C++ vtable member usage */
-
-#define R_TILEGX_NUM		130
-
-
-__END_DECLS
-
-#endif	/* elf.h */
diff --git a/port-gnu/endian-darwin.h b/port-gnu/endian-darwin.h
deleted file mode 100644
index 2b43378..0000000
--- a/port-gnu/endian-darwin.h
+++ /dev/null
@@ -1,118 +0,0 @@
-// "License": Public Domain
-// I, Mathias Panzenböck, place this file hereby into the public domain. Use it at your own risk for whatever you like.
-// In case there are jurisdictions that don't support putting things in the public domain you can also consider it to
-// be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This code is trivial anyway. Consider it
-// an example on how to get the endian conversion functions on different platforms.
-
-#ifndef PORTABLE_ENDIAN_H__
-#define PORTABLE_ENDIAN_H__
-
-#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
-
-#	define __WINDOWS__
-
-#endif
-
-#if defined(__linux__) || defined(__CYGWIN__)
-
-#	include <endian.h>
-
-#elif defined(__APPLE__)
-
-#	include <libkern/OSByteOrder.h>
-
-#	define htobe16(x) OSSwapHostToBigInt16(x)
-#	define htole16(x) OSSwapHostToLittleInt16(x)
-#	define be16toh(x) OSSwapBigToHostInt16(x)
-#	define le16toh(x) OSSwapLittleToHostInt16(x)
-
-#	define htobe32(x) OSSwapHostToBigInt32(x)
-#	define htole32(x) OSSwapHostToLittleInt32(x)
-#	define be32toh(x) OSSwapBigToHostInt32(x)
-#	define le32toh(x) OSSwapLittleToHostInt32(x)
-
-#	define htobe64(x) OSSwapHostToBigInt64(x)
-#	define htole64(x) OSSwapHostToLittleInt64(x)
-#	define be64toh(x) OSSwapBigToHostInt64(x)
-#	define le64toh(x) OSSwapLittleToHostInt64(x)
-
-#	define __BYTE_ORDER    BYTE_ORDER
-#	define __BIG_ENDIAN    BIG_ENDIAN
-#	define __LITTLE_ENDIAN LITTLE_ENDIAN
-#	define __PDP_ENDIAN    PDP_ENDIAN
-
-#elif defined(__OpenBSD__)
-
-#	include <sys/endian.h>
-
-#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
-
-#	include <sys/endian.h>
-
-#	define be16toh(x) betoh16(x)
-#	define le16toh(x) letoh16(x)
-
-#	define be32toh(x) betoh32(x)
-#	define le32toh(x) letoh32(x)
-
-#	define be64toh(x) betoh64(x)
-#	define le64toh(x) letoh64(x)
-
-#elif defined(__WINDOWS__)
-
-#	include <winsock2.h>
-#	include <sys/param.h>
-
-#	if BYTE_ORDER == LITTLE_ENDIAN
-
-#		define htobe16(x) htons(x)
-#		define htole16(x) (x)
-#		define be16toh(x) ntohs(x)
-#		define le16toh(x) (x)
-
-#		define htobe32(x) htonl(x)
-#		define htole32(x) (x)
-#		define be32toh(x) ntohl(x)
-#		define le32toh(x) (x)
-
-#		define htobe64(x) htonll(x)
-#		define htole64(x) (x)
-#		define be64toh(x) ntohll(x)
-#		define le64toh(x) (x)
-
-#	elif BYTE_ORDER == BIG_ENDIAN
-
-		/* that would be xbox 360 */
-#		define htobe16(x) (x)
-#		define htole16(x) __builtin_bswap16(x)
-#		define be16toh(x) (x)
-#		define le16toh(x) __builtin_bswap16(x)
-
-#		define htobe32(x) (x)
-#		define htole32(x) __builtin_bswap32(x)
-#		define be32toh(x) (x)
-#		define le32toh(x) __builtin_bswap32(x)
-
-#		define htobe64(x) (x)
-#		define htole64(x) __builtin_bswap64(x)
-#		define be64toh(x) (x)
-#		define le64toh(x) __builtin_bswap64(x)
-
-#	else
-
-#		error byte order not supported
-
-#	endif
-
-#	define __BYTE_ORDER    BYTE_ORDER
-#	define __BIG_ENDIAN    BIG_ENDIAN
-#	define __LITTLE_ENDIAN LITTLE_ENDIAN
-#	define __PDP_ENDIAN    PDP_ENDIAN
-
-#else
-
-#	error platform not supported
-
-#endif
-
-#endif
diff --git a/shared/hash.c b/shared/hash.c
index 7fe3f80..a87bc50 100644
--- a/shared/hash.c
+++ b/shared/hash.c
@@ -241,12 +241,15 @@ void *hash_find(const struct hash *hash, const char *key)
 		.key = key,
 		.value = NULL
 	};
-	const struct hash_entry *entry = bsearch(
-		&se, bucket->entries, bucket->used,
-		sizeof(struct hash_entry), hash_entry_cmp);
-	if (entry == NULL)
+	const struct hash_entry *entry;
+
+	if (!bucket->entries)
 		return NULL;
-	return (void *)entry->value;
+
+	entry = bsearch(&se, bucket->entries, bucket->used,
+			sizeof(struct hash_entry), hash_entry_cmp);
+
+	return entry ? (void *)entry->value : NULL;
 }
 
 int hash_del(struct hash *hash, const char *key)
diff --git a/shared/missing.h b/shared/missing.h
index 72aaa95..2629444 100644
--- a/shared/missing.h
+++ b/shared/missing.h
@@ -15,6 +15,10 @@
 # define MODULE_INIT_IGNORE_VERMAGIC 2
 #endif
 
+#ifndef MODULE_INIT_COMPRESSED_FILE
+# define MODULE_INIT_COMPRESSED_FILE 4
+#endif
+
 #ifndef __NR_finit_module
 # define __NR_finit_module -1
 #endif
@@ -33,7 +37,7 @@ static inline int finit_module(int fd, const char *uargs, int flags)
 }
 #endif
 
-#if (!HAVE_DECL_STRNDUPA && !defined(__APPLE__))
+#if !HAVE_DECL_STRNDUPA
 #define strndupa(s, n)							\
 	({								\
 		const char *__old = (s);				\
diff --git a/shared/util.c b/shared/util.c
index 4b547ff..e2bab83 100644
--- a/shared/util.c
+++ b/shared/util.c
@@ -354,7 +354,7 @@ char *freadline_wrapped(FILE *fp, unsigned int *linenum)
 /* path handling functions                                                  */
 /* ************************************************************************ */
 
-bool path_is_absolute(const char *p)
+static bool path_is_absolute(const char *p)
 {
 	assert(p != NULL);
 
@@ -460,13 +460,13 @@ int mkdir_parents(const char *path, mode_t mode)
 	return mkdir_p(path, end - path, mode);
 }
 
-unsigned long long ts_usec(const struct timespec *ts)
+static unsigned long long ts_usec(const struct timespec *ts)
 {
 	return (unsigned long long) ts->tv_sec * USEC_PER_SEC +
 	       (unsigned long long) ts->tv_nsec / NSEC_PER_USEC;
 }
 
-unsigned long long ts_msec(const struct timespec *ts)
+static unsigned long long ts_msec(const struct timespec *ts)
 {
 	return (unsigned long long) ts->tv_sec * MSEC_PER_SEC +
 	       (unsigned long long) ts->tv_nsec / NSEC_PER_MSEC;
diff --git a/shared/util.h b/shared/util.h
index 7030653..c4a3916 100644
--- a/shared/util.h
+++ b/shared/util.h
@@ -38,7 +38,6 @@ char *freadline_wrapped(FILE *fp, unsigned int *linenum) __attribute__((nonnull(
 
 /* path handling functions                                                  */
 /* ************************************************************************ */
-bool path_is_absolute(const char *p) _must_check_ __attribute__((nonnull(1)));
 char *path_make_absolute_cwd(const char *p) _must_check_ __attribute__((nonnull(1)));
 int mkdir_p(const char *path, int len, mode_t mode);
 int mkdir_parents(const char *path, mode_t mode);
@@ -51,8 +50,6 @@ unsigned long long stat_mstamp(const struct stat *st);
 #define MSEC_PER_SEC	1000ULL
 #define NSEC_PER_MSEC	1000000ULL
 
-unsigned long long ts_usec(const struct timespec *ts);
-unsigned long long ts_msec(const struct timespec *ts);
 unsigned long long now_usec(void);
 unsigned long long now_msec(void);
 int sleep_until_msec(unsigned long long msec);
diff --git a/testsuite/.gitignore b/testsuite/.gitignore
index 9d26b88..5465b1a 100644
--- a/testsuite/.gitignore
+++ b/testsuite/.gitignore
@@ -18,7 +18,6 @@
 /test-modprobe
 /test-hash
 /test-list
-/test-tools
 /rootfs
 /stamp-rootfs
 /test-scratchbuf.log
@@ -53,5 +52,3 @@
 /test-testsuite.trs
 /test-list.log
 /test-list.trs
-/test-tools.log
-/test-tools.trs
diff --git a/testsuite/mkosi/.gitignore b/testsuite/mkosi/.gitignore
deleted file mode 100644
index 0e0981a..0000000
--- a/testsuite/mkosi/.gitignore
+++ /dev/null
@@ -1,3 +0,0 @@
-/*-image.raw*
-/.mkosi-*
-/mkosi.cache
diff --git a/testsuite/mkosi/mkosi.arch b/testsuite/mkosi/mkosi.arch
deleted file mode 100644
index ace5d95..0000000
--- a/testsuite/mkosi/mkosi.arch
+++ /dev/null
@@ -1,26 +0,0 @@
-[Distribution]
-Distribution=arch
-Release=(rolling)
-
-[Output]
-Output = arch-image.raw
-
-[Packages]
-Packages = valgrind
-BuildPackages =
-	automake
-	gcc
-	git
-	make
-	pkg-config
-	python2
-	python2-future
-	autoconf
-	gtk-doc
-	docbook-xml
-	docbook-xsl
-	linux-headers
-	openssl
-
-[Partitions]
-RootSize = 3G
diff --git a/testsuite/mkosi/mkosi.build b/testsuite/mkosi/mkosi.build
deleted file mode 100755
index c0ba549..0000000
--- a/testsuite/mkosi/mkosi.build
+++ /dev/null
@@ -1,38 +0,0 @@
-#!/bin/bash -ex
-
-function find_kdir() {
-    local kdirs=(/usr/lib/modules/*/build/Makefile /usr/src/kernels/*/Makefile)
-    local kdir=""
-
-    for f in "${kdirs[@]}"; do
-        if [ -f "$f" ]; then
-            kdir=$f
-            break
-        fi
-    done
-
-    if [ -z "$kdir" ]; then
-        printf '==> Unable to find kernel headers to build modules for tests\n' >&2
-        exit 1
-    fi
-
-    kdir=${kdir%/Makefile}
-
-    echo $kdir
-}
-
-if [ -f configure ]; then
-    make distclean
-fi
-
-rm -rf build
-mkdir build
-cd build
-
-kdir=$(find_kdir)
-IFS=/ read _ _ _ kver _ <<<"$kdir"
-
-../autogen.sh c --disable-python
-make -j
-make check KDIR="$kdir" KVER="$kver"
-make install
diff --git a/testsuite/mkosi/mkosi.clear b/testsuite/mkosi/mkosi.clear
deleted file mode 100644
index 03ba2f0..0000000
--- a/testsuite/mkosi/mkosi.clear
+++ /dev/null
@@ -1,20 +0,0 @@
-[Distribution]
-Distribution=clear
-Release=latest
-
-[Output]
-Output = clear-image.raw
-
-[Packages]
-Packages=
-	os-core-update
-BuildPackages=
-	os-core-dev
-	linux-dev
-
-[Partitions]
-RootSize = 5G
-
-[Host]
-# This is where swupd-extract is usually installed.
-ExtraSearchPaths=$SUDO_HOME/go/bin
\ No newline at end of file
diff --git a/testsuite/mkosi/mkosi.fedora b/testsuite/mkosi/mkosi.fedora
deleted file mode 100644
index 7a2ee5e..0000000
--- a/testsuite/mkosi/mkosi.fedora
+++ /dev/null
@@ -1,28 +0,0 @@
-[Distribution]
-Distribution=fedora
-Release=29
-
-[Output]
-Output = fedora-image.raw
-
-[Packages]
-Packages = valgrind
-BuildPackages =
-	autoconf
-	automake
-	gcc
-	git
-	gtk-doc
-	kernel-devel
-	libtool
-	libxslt
-	make
-	pkgconf-pkg-config
-	xml-common
-	libzstd-devel
-	xz-devel
-	zlib-devel
-	openssl-devel
-
-[Partitions]
-RootSize = 2G
diff --git a/testsuite/module-playground/Makefile b/testsuite/module-playground/Makefile
index e6045b0..a7ab09b 100644
--- a/testsuite/module-playground/Makefile
+++ b/testsuite/module-playground/Makefile
@@ -47,7 +47,7 @@ endif
 
 else
 # normal makefile
-KDIR ?= /lib/modules/`uname -r`/build
+KDIR ?= $(module_prefix)/lib/modules/`uname -r`/build
 KVER ?= `uname -r`
 ifeq ($(FAKE_BUILD),)
     FAKE_BUILD=0
diff --git a/testsuite/path.c b/testsuite/path.c
index fa5fceb..5a291b1 100644
--- a/testsuite/path.c
+++ b/testsuite/path.c
@@ -15,6 +15,10 @@
  * License along with this library; if not, see <http://www.gnu.org/licenses/>.
  */
 
+/* We unset _FILE_OFFSET_BITS here so we can override both stat and stat64 on
+ * 32-bit architectures and forward each to the right libc function */
+#undef _FILE_OFFSET_BITS
+
 #include <assert.h>
 #include <dirent.h>
 #include <dlfcn.h>
@@ -159,8 +163,15 @@ TS_EXPORT int open ## suffix (const char *path, int flags, ...)	\
 	return _fn(p, flags);					\
 }
 
-/* wrapper template for __xstat family */
+/*
+ * wrapper template for __xstat family
+ * This family got deprecated/dropped in glibc 2.32.9000, but we still need
+ * to keep it for a while for programs that were built against previous versions
+ */
 #define WRAP_VERSTAT(prefix, suffix)			    \
+TS_EXPORT int prefix ## stat ## suffix (int ver,	    \
+			      const char *path,		    \
+	                      struct stat ## suffix *st);   \
 TS_EXPORT int prefix ## stat ## suffix (int ver,	    \
 			      const char *path,		    \
 	                      struct stat ## suffix *st)    \
@@ -181,25 +192,23 @@ TS_EXPORT int prefix ## stat ## suffix (int ver,	    \
 }
 
 WRAP_1ARG(DIR*, NULL, opendir);
+WRAP_1ARG(int, -1, chdir);
 
 WRAP_2ARGS(FILE*, NULL, fopen, const char*);
+WRAP_2ARGS(FILE*, NULL, fopen64, const char*);
 WRAP_2ARGS(int, -1, mkdir, mode_t);
 WRAP_2ARGS(int, -1, access, int);
 WRAP_2ARGS(int, -1, stat, struct stat*);
 WRAP_2ARGS(int, -1, lstat, struct stat*);
-#ifndef _FILE_OFFSET_BITS
 WRAP_2ARGS(int, -1, stat64, struct stat64*);
 WRAP_2ARGS(int, -1, lstat64, struct stat64*);
 WRAP_OPEN(64);
-#endif
 
 WRAP_OPEN();
 
 #ifdef HAVE___XSTAT
 WRAP_VERSTAT(__x,);
 WRAP_VERSTAT(__lx,);
-#ifndef _FILE_OFFSET_BITS
 WRAP_VERSTAT(__x,64);
 WRAP_VERSTAT(__lx,64);
 #endif
-#endif
diff --git a/testsuite/populate-modules.sh b/testsuite/populate-modules.sh
deleted file mode 100755
index 099f026..0000000
--- a/testsuite/populate-modules.sh
+++ /dev/null
@@ -1,140 +0,0 @@
-#!/bin/bash
-
-set -e
-
-MODULE_PLAYGROUND=$1
-ROOTFS=$2
-CONFIG_H=$3
-
-feature_enabled() {
-	local feature=$1
-	grep KMOD_FEATURES  $CONFIG_H | head -n 1 | grep -q \+$feature
-}
-
-declare -A map
-map=(
-    ["test-depmod/search-order-simple/lib/modules/4.4.4/kernel/crypto/"]="mod-simple.ko"
-    ["test-depmod/search-order-simple/lib/modules/4.4.4/updates/"]="mod-simple.ko"
-    ["test-depmod/search-order-same-prefix/lib/modules/4.4.4/foo/"]="mod-simple.ko"
-    ["test-depmod/search-order-same-prefix/lib/modules/4.4.4/foobar/"]="mod-simple.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-c.ko"]="mod-loop-c.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-d.ko"]="mod-loop-d.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-e.ko"]="mod-loop-e.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-f.ko"]="mod-loop-f.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-g.ko"]="mod-loop-g.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-h.ko"]="mod-loop-h.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-i.ko"]="mod-loop-i.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-j.ko"]="mod-loop-j.ko"
-    ["test-depmod/detect-loop/lib/modules/4.4.4/kernel/mod-loop-k.ko"]="mod-loop-k.ko"
-    ["test-depmod/search-order-external-first/lib/modules/4.4.4/foo/"]="mod-simple.ko"
-    ["test-depmod/search-order-external-first/lib/modules/4.4.4/foobar/"]="mod-simple.ko"
-    ["test-depmod/search-order-external-first/lib/modules/external/"]="mod-simple.ko"
-    ["test-depmod/search-order-external-last/lib/modules/4.4.4/foo/"]="mod-simple.ko"
-    ["test-depmod/search-order-external-last/lib/modules/4.4.4/foobar/"]="mod-simple.ko"
-    ["test-depmod/search-order-external-last/lib/modules/external/"]="mod-simple.ko"
-    ["test-depmod/search-order-override/lib/modules/4.4.4/foo/"]="mod-simple.ko"
-    ["test-depmod/search-order-override/lib/modules/4.4.4/override/"]="mod-simple.ko"
-    ["test-dependencies/lib/modules/4.0.20-kmod/kernel/fs/foo/"]="mod-foo-b.ko"
-    ["test-dependencies/lib/modules/4.0.20-kmod/kernel/"]="mod-foo-c.ko"
-    ["test-dependencies/lib/modules/4.0.20-kmod/kernel/lib/"]="mod-foo-a.ko"
-    ["test-dependencies/lib/modules/4.0.20-kmod/kernel/fs/"]="mod-foo.ko"
-    ["test-init/"]="mod-simple.ko"
-    ["test-remove/"]="mod-simple.ko"
-    ["test-modprobe/show-depends/lib/modules/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
-    ["test-modprobe/show-depends/lib/modules/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
-    ["test-modprobe/show-depends/lib/modules/4.4.4/kernel/mod-simple.ko"]="mod-simple.ko"
-    ["test-modprobe/show-exports/mod-loop-a.ko"]="mod-loop-a.ko"
-    ["test-modprobe/softdep-loop/lib/modules/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
-    ["test-modprobe/softdep-loop/lib/modules/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
-    ["test-modprobe/install-cmd-loop/lib/modules/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
-    ["test-modprobe/install-cmd-loop/lib/modules/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
-    ["test-modprobe/force/lib/modules/4.4.4/kernel/"]="mod-simple.ko"
-    ["test-modprobe/oldkernel/lib/modules/3.3.3/kernel/"]="mod-simple.ko"
-    ["test-modprobe/oldkernel-force/lib/modules/3.3.3/kernel/"]="mod-simple.ko"
-    ["test-modprobe/alias-to-none/lib/modules/4.4.4/kernel/"]="mod-simple.ko"
-    ["test-modprobe/module-param-kcmdline/lib/modules/4.4.4/kernel/"]="mod-simple.ko"
-    ["test-modprobe/external/lib/modules/external/"]="mod-simple.ko"
-    ["test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/block/cciss.ko"]="mod-fake-cciss.ko"
-    ["test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/scsi/hpsa.ko"]="mod-fake-hpsa.ko"
-    ["test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/scsi/scsi_mod.ko"]="mod-fake-scsi-mod.ko"
-    ["test-modinfo/mod-simple-i386.ko"]="mod-simple-i386.ko"
-    ["test-modinfo/mod-simple-x86_64.ko"]="mod-simple-x86_64.ko"
-    ["test-modinfo/mod-simple-sparc64.ko"]="mod-simple-sparc64.ko"
-    ["test-modinfo/mod-simple-sha1.ko"]="mod-simple.ko"
-    ["test-modinfo/mod-simple-sha256.ko"]="mod-simple.ko"
-    ["test-modinfo/mod-simple-pkcs7.ko"]="mod-simple.ko"
-    ["test-modinfo/external/lib/modules/external/mod-simple.ko"]="mod-simple.ko"
-    ["test-tools/insert/lib/modules/4.4.4/kernel/"]="mod-simple.ko"
-    ["test-tools/remove/lib/modules/4.4.4/kernel/"]="mod-simple.ko"
-)
-
-gzip_array=(
-    "test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/block/cciss.ko"
-    )
-
-xz_array=(
-    "test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/scsi/scsi_mod.ko"
-    )
-
-zstd_array=(
-    "test-depmod/modules-order-compressed/lib/modules/4.4.4/kernel/drivers/scsi/hpsa.ko"
-    )
-
-attach_sha256_array=(
-    "test-modinfo/mod-simple-sha256.ko"
-    )
-
-attach_sha1_array=(
-    "test-modinfo/mod-simple-sha1.ko"
-    )
-
-attach_pkcs7_array=(
-    "test-modinfo/mod-simple-pkcs7.ko"
-    )
-
-for k in "${!map[@]}"; do
-    dst=${ROOTFS}/$k
-    src=${MODULE_PLAYGROUND}/${map[$k]}
-
-    if [[ $dst = */ ]]; then
-        install -d "$dst"
-        install -t "$dst" "$src"
-    else
-        install -D "$src" "$dst"
-    fi
-done
-
-# start poking the final rootfs...
-
-# compress modules with each format if feature is enabled
-if feature_enabled ZLIB; then
-	for m in "${gzip_array[@]}"; do
-	    gzip "$ROOTFS/$m"
-	done
-fi
-
-if feature_enabled XZ; then
-	for m in "${xz_array[@]}"; do
-	    xz "$ROOTFS/$m"
-	done
-fi
-
-if feature_enabled ZSTD; then
-	for m in "${zstd_array[@]}"; do
-	    zstd --rm $ROOTFS/$m
-	done
-fi
-
-for m in "${attach_sha1_array[@]}"; do
-    cat "${MODULE_PLAYGROUND}/dummy.sha1" >>"${ROOTFS}/$m"
-done
-
-for m in "${attach_sha256_array[@]}"; do
-    cat "${MODULE_PLAYGROUND}/dummy.sha256" >>"${ROOTFS}/$m"
-done
-
-for m in "${attach_pkcs7_array[@]}"; do
-    cat "${MODULE_PLAYGROUND}/dummy.pkcs7" >>"${ROOTFS}/$m"
-done
diff --git a/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.alias b/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.alias
new file mode 100644
index 0000000..5675329
--- /dev/null
+++ b/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.alias
@@ -0,0 +1,37 @@
+# Aliases extracted from modules themselves.
+alias pci:v0000103Cd00003230sv0000103Csd0000323Dbc*sc*i* cciss
+alias pci:v0000103Cd00003230sv0000103Csd00003237bc*sc*i* cciss
+alias pci:v0000103Cd00003238sv0000103Csd00003215bc*sc*i* cciss
+alias pci:v0000103Cd00003238sv0000103Csd00003214bc*sc*i* cciss
+alias pci:v0000103Cd00003238sv0000103Csd00003213bc*sc*i* cciss
+alias pci:v0000103Cd00003238sv0000103Csd00003212bc*sc*i* cciss
+alias pci:v0000103Cd00003238sv0000103Csd00003211bc*sc*i* cciss
+alias pci:v0000103Cd00003230sv0000103Csd00003235bc*sc*i* cciss
+alias pci:v0000103Cd00003230sv0000103Csd00003234bc*sc*i* cciss
+alias pci:v0000103Cd00003230sv0000103Csd00003223bc*sc*i* cciss
+alias pci:v0000103Cd00003220sv0000103Csd00003225bc*sc*i* cciss
+alias pci:v00000E11d00000046sv00000E11sd0000409Dbc*sc*i* cciss
+alias pci:v00000E11d00000046sv00000E11sd0000409Cbc*sc*i* cciss
+alias pci:v00000E11d00000046sv00000E11sd0000409Bbc*sc*i* cciss
+alias pci:v00000E11d00000046sv00000E11sd0000409Abc*sc*i* cciss
+alias pci:v00000E11d00000046sv00000E11sd00004091bc*sc*i* cciss
+alias pci:v00000E11d0000B178sv00000E11sd00004083bc*sc*i* cciss
+alias pci:v00000E11d0000B178sv00000E11sd00004082bc*sc*i* cciss
+alias pci:v00000E11d0000B178sv00000E11sd00004080bc*sc*i* cciss
+alias pci:v00000E11d0000B060sv00000E11sd00004070bc*sc*i* cciss
+alias pci:v0000103Cd*sv*sd*bc01sc04i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003356bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003355bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003354bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003353bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003352bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003351bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Bsv0000103Csd00003350bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003233bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd0000324Bbc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd0000324Abc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003249bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003247bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003245bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003243bc*sc*i* hpsa
+alias pci:v0000103Cd0000323Asv0000103Csd00003241bc*sc*i* hpsa
diff --git a/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.dep b/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.dep
new file mode 100644
index 0000000..ec50ac3
--- /dev/null
+++ b/testsuite/rootfs-pristine/test-depmod/modules-outdir/correct-modules.dep
@@ -0,0 +1,3 @@
+kernel/drivers/block/cciss.ko:
+kernel/drivers/scsi/scsi_mod.ko:
+kernel/drivers/scsi/hpsa.ko: kernel/drivers/scsi/scsi_mod.ko
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.builtin b/testsuite/rootfs-pristine/test-depmod/modules-outdir/lib/modules/4.4.4/modules.builtin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.builtin
rename to testsuite/rootfs-pristine/test-depmod/modules-outdir/lib/modules/4.4.4/modules.builtin
diff --git a/testsuite/rootfs-pristine/test-depmod/modules-outdir/lib/modules/4.4.4/modules.order b/testsuite/rootfs-pristine/test-depmod/modules-outdir/lib/modules/4.4.4/modules.order
new file mode 100644
index 0000000..4b64309
--- /dev/null
+++ b/testsuite/rootfs-pristine/test-depmod/modules-outdir/lib/modules/4.4.4/modules.order
@@ -0,0 +1,7 @@
+#336
+kernel/drivers/block/cciss.ko
+#2094
+kernel/drivers/scsi/scsi_mod.ko
+#2137
+kernel/drivers/scsi/hpsa.ko
+
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.alias b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.alias
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.alias
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.alias
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.alias.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.alias.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.alias.bin
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.alias.bin
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.order b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.builtin.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.order
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.builtin.bin
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep
new file mode 100644
index 0000000..e612900
--- /dev/null
+++ b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep
@@ -0,0 +1 @@
+/lib/modules/external/mod-simple.ko:
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep.bin
new file mode 100644
index 0000000..556e3c8
Binary files /dev/null and b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.dep.bin differ
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.builtin b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.devname
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.builtin
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.devname
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.softdep b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.softdep
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.softdep
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.softdep
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.symbols b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.symbols
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.symbols
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.symbols
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.symbols.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.symbols.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.symbols.bin
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/lib/modules/4.4.4/modules.symbols.bin
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.order b/testsuite/rootfs-pristine/test-modprobe/module-from-abspath/proc/modules
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.order
rename to testsuite/rootfs-pristine/test-modprobe/module-from-abspath/proc/modules
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.alias b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.alias
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.alias
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.alias
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.alias.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.alias.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.alias.bin
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.alias.bin
diff --git a/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/holders/.gitignore b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.builtin.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/holders/.gitignore
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.builtin.bin
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep
new file mode 100644
index 0000000..e612900
--- /dev/null
+++ b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep
@@ -0,0 +1 @@
+/lib/modules/external/mod-simple.ko:
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep.bin
new file mode 100644
index 0000000..556e3c8
Binary files /dev/null and b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.dep.bin differ
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.devname b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.devname
new file mode 100644
index 0000000..e69de29
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.softdep b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.softdep
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.softdep
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.softdep
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.symbols b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.symbols
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.symbols
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.symbols
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.symbols.bin b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.symbols.bin
similarity index 100%
rename from testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.symbols.bin
rename to testsuite/rootfs-pristine/test-modprobe/module-from-relpath/lib/modules/4.4.4/modules.symbols.bin
diff --git a/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/proc/modules b/testsuite/rootfs-pristine/test-modprobe/module-from-relpath/proc/modules
new file mode 100644
index 0000000..e69de29
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.builtin.bin b/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.builtin.bin
deleted file mode 100644
index 7075435..0000000
Binary files a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.builtin.bin and /dev/null differ
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep b/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep
deleted file mode 100644
index 5476653..0000000
--- a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep
+++ /dev/null
@@ -1 +0,0 @@
-kernel/mod-simple.ko:
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep.bin b/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep.bin
deleted file mode 100644
index b09a854..0000000
Binary files a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.dep.bin and /dev/null differ
diff --git a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.devname b/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.devname
deleted file mode 100644
index 58f6d6d..0000000
--- a/testsuite/rootfs-pristine/test-tools/insert/lib/modules/4.4.4/modules.devname
+++ /dev/null
@@ -1 +0,0 @@
-# Device nodes to trigger on-demand module loading.
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.builtin.bin b/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.builtin.bin
deleted file mode 100644
index 7075435..0000000
Binary files a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.builtin.bin and /dev/null differ
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep b/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep
deleted file mode 100644
index 5476653..0000000
--- a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep
+++ /dev/null
@@ -1 +0,0 @@
-kernel/mod-simple.ko:
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep.bin b/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep.bin
deleted file mode 100644
index b09a854..0000000
Binary files a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.dep.bin and /dev/null differ
diff --git a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.devname b/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.devname
deleted file mode 100644
index 58f6d6d..0000000
--- a/testsuite/rootfs-pristine/test-tools/remove/lib/modules/4.4.4/modules.devname
+++ /dev/null
@@ -1 +0,0 @@
-# Device nodes to trigger on-demand module loading.
diff --git a/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/initstate b/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/initstate
deleted file mode 100644
index e23fe64..0000000
--- a/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/initstate
+++ /dev/null
@@ -1 +0,0 @@
-live
diff --git a/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/refcnt b/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/refcnt
deleted file mode 100644
index 573541a..0000000
--- a/testsuite/rootfs-pristine/test-tools/remove/sys/module/mod_simple/refcnt
+++ /dev/null
@@ -1 +0,0 @@
-0
diff --git a/testsuite/setup-rootfs.sh b/testsuite/setup-rootfs.sh
new file mode 100755
index 0000000..5477c69
--- /dev/null
+++ b/testsuite/setup-rootfs.sh
@@ -0,0 +1,179 @@
+#!/bin/bash
+
+set -e
+
+ROOTFS_PRISTINE=$1
+ROOTFS=$2
+MODULE_PLAYGROUND=$3
+CONFIG_H=$4
+SYSCONFDIR=$5
+
+# create rootfs from rootfs-pristine
+
+create_rootfs() {
+	rm -rf "$ROOTFS"
+	mkdir -p $(dirname "$ROOTFS")
+	cp -r "$ROOTFS_PRISTINE" "$ROOTFS"
+	find "$ROOTFS" -type d -exec chmod +w {} \;
+	find "$ROOTFS" -type f -name .gitignore -exec rm -f {} \;
+	if [ "$MODULE_DIRECTORY" != "/lib/modules" ] ; then
+		sed -i -e "s|/lib/modules|$MODULE_DIRECTORY|g" $(find "$ROOTFS" -name \*.txt -o -name \*.conf -o -name \*.dep)
+		sed -i -e "s|$MODULE_DIRECTORY/external|/lib/modules/external|g" $(find "$ROOTFS" -name \*.txt -o -name \*.conf -o -name \*.dep)
+		for i in "$ROOTFS"/*/lib/modules/* "$ROOTFS"/*/*/lib/modules/* ; do
+			version="$(basename $i)"
+			[ $version != 'external' ] || continue
+			mod="$(dirname $i)"
+			lib="$(dirname $mod)"
+			up="$(dirname $lib)$MODULE_DIRECTORY"
+			mkdir -p "$up"
+			mv "$i" "$up"
+		done
+	fi
+
+	if [ "$SYSCONFDIR" != "/etc" ]; then
+		find "$ROOTFS" -type d -name etc -printf "%h\n" | while read -r e; do
+			mkdir -p "$(dirname $e/$SYSCONFDIR)"
+			mv $e/{etc,$SYSCONFDIR}
+		done
+	fi
+}
+
+feature_enabled() {
+	local feature=$1
+	grep KMOD_FEATURES  $CONFIG_H | head -n 1 | grep -q \+$feature
+}
+
+declare -A map
+map=(
+    ["test-depmod/search-order-simple$MODULE_DIRECTORY/4.4.4/kernel/crypto/"]="mod-simple.ko"
+    ["test-depmod/search-order-simple$MODULE_DIRECTORY/4.4.4/updates/"]="mod-simple.ko"
+    ["test-depmod/search-order-same-prefix$MODULE_DIRECTORY/4.4.4/foo/"]="mod-simple.ko"
+    ["test-depmod/search-order-same-prefix$MODULE_DIRECTORY/4.4.4/foobar/"]="mod-simple.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-c.ko"]="mod-loop-c.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-d.ko"]="mod-loop-d.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-e.ko"]="mod-loop-e.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-f.ko"]="mod-loop-f.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-g.ko"]="mod-loop-g.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-h.ko"]="mod-loop-h.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-i.ko"]="mod-loop-i.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-j.ko"]="mod-loop-j.ko"
+    ["test-depmod/detect-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-k.ko"]="mod-loop-k.ko"
+    ["test-depmod/search-order-external-first$MODULE_DIRECTORY/4.4.4/foo/"]="mod-simple.ko"
+    ["test-depmod/search-order-external-first$MODULE_DIRECTORY/4.4.4/foobar/"]="mod-simple.ko"
+    ["test-depmod/search-order-external-first/lib/modules/external/"]="mod-simple.ko"
+    ["test-depmod/search-order-external-last$MODULE_DIRECTORY/4.4.4/foo/"]="mod-simple.ko"
+    ["test-depmod/search-order-external-last$MODULE_DIRECTORY/4.4.4/foobar/"]="mod-simple.ko"
+    ["test-depmod/search-order-external-last/lib/modules/external/"]="mod-simple.ko"
+    ["test-depmod/search-order-override$MODULE_DIRECTORY/4.4.4/foo/"]="mod-simple.ko"
+    ["test-depmod/search-order-override$MODULE_DIRECTORY/4.4.4/override/"]="mod-simple.ko"
+    ["test-dependencies$MODULE_DIRECTORY/4.0.20-kmod/kernel/fs/foo/"]="mod-foo-b.ko"
+    ["test-dependencies$MODULE_DIRECTORY/4.0.20-kmod/kernel/"]="mod-foo-c.ko"
+    ["test-dependencies$MODULE_DIRECTORY/4.0.20-kmod/kernel/lib/"]="mod-foo-a.ko"
+    ["test-dependencies$MODULE_DIRECTORY/4.0.20-kmod/kernel/fs/"]="mod-foo.ko"
+    ["test-init/"]="mod-simple.ko"
+    ["test-remove/"]="mod-simple.ko"
+    ["test-modprobe/show-depends$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
+    ["test-modprobe/show-depends$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
+    ["test-modprobe/show-depends$MODULE_DIRECTORY/4.4.4/kernel/mod-simple.ko"]="mod-simple.ko"
+    ["test-modprobe/show-exports/mod-loop-a.ko"]="mod-loop-a.ko"
+    ["test-modprobe/softdep-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
+    ["test-modprobe/softdep-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
+    ["test-modprobe/install-cmd-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-a.ko"]="mod-loop-a.ko"
+    ["test-modprobe/install-cmd-loop$MODULE_DIRECTORY/4.4.4/kernel/mod-loop-b.ko"]="mod-loop-b.ko"
+    ["test-modprobe/force$MODULE_DIRECTORY/4.4.4/kernel/"]="mod-simple.ko"
+    ["test-modprobe/oldkernel$MODULE_DIRECTORY/3.3.3/kernel/"]="mod-simple.ko"
+    ["test-modprobe/oldkernel-force$MODULE_DIRECTORY/3.3.3/kernel/"]="mod-simple.ko"
+    ["test-modprobe/alias-to-none$MODULE_DIRECTORY/4.4.4/kernel/"]="mod-simple.ko"
+    ["test-modprobe/module-param-kcmdline$MODULE_DIRECTORY/4.4.4/kernel/"]="mod-simple.ko"
+    ["test-modprobe/external/lib/modules/external/"]="mod-simple.ko"
+    ["test-modprobe/module-from-abspath/home/foo/"]="mod-simple.ko"
+    ["test-modprobe/module-from-relpath/home/foo/"]="mod-simple.ko"
+    ["test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/block/cciss.ko"]="mod-fake-cciss.ko"
+    ["test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/hpsa.ko"]="mod-fake-hpsa.ko"
+    ["test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/scsi_mod.ko"]="mod-fake-scsi-mod.ko"
+    ["test-depmod/modules-outdir$MODULE_DIRECTORY/4.4.4/kernel/drivers/block/cciss.ko"]="mod-fake-cciss.ko"
+    ["test-depmod/modules-outdir$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/hpsa.ko"]="mod-fake-hpsa.ko"
+    ["test-depmod/modules-outdir$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/scsi_mod.ko"]="mod-fake-scsi-mod.ko"
+    ["test-modinfo/mod-simple-i386.ko"]="mod-simple-i386.ko"
+    ["test-modinfo/mod-simple-x86_64.ko"]="mod-simple-x86_64.ko"
+    ["test-modinfo/mod-simple-sparc64.ko"]="mod-simple-sparc64.ko"
+    ["test-modinfo/mod-simple-sha1.ko"]="mod-simple.ko"
+    ["test-modinfo/mod-simple-sha256.ko"]="mod-simple.ko"
+    ["test-modinfo/mod-simple-pkcs7.ko"]="mod-simple.ko"
+    ["test-modinfo/external/lib/modules/external/mod-simple.ko"]="mod-simple.ko"
+)
+
+gzip_array=(
+    "test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/block/cciss.ko"
+    )
+
+xz_array=(
+    "test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/scsi_mod.ko"
+    )
+
+zstd_array=(
+    "test-depmod/modules-order-compressed$MODULE_DIRECTORY/4.4.4/kernel/drivers/scsi/hpsa.ko"
+    )
+
+attach_sha256_array=(
+    "test-modinfo/mod-simple-sha256.ko"
+    )
+
+attach_sha1_array=(
+    "test-modinfo/mod-simple-sha1.ko"
+    )
+
+attach_pkcs7_array=(
+    "test-modinfo/mod-simple-pkcs7.ko"
+    )
+
+create_rootfs
+
+for k in "${!map[@]}"; do
+    dst=${ROOTFS}/$k
+    src=${MODULE_PLAYGROUND}/${map[$k]}
+
+    if [[ $dst = */ ]]; then
+        install -d "$dst"
+        install -t "$dst" "$src"
+    else
+        install -D "$src" "$dst"
+    fi
+done
+
+# start poking the final rootfs...
+
+# compress modules with each format if feature is enabled
+if feature_enabled ZLIB; then
+	for m in "${gzip_array[@]}"; do
+	    gzip "$ROOTFS/$m"
+	done
+fi
+
+if feature_enabled XZ; then
+	for m in "${xz_array[@]}"; do
+	    xz "$ROOTFS/$m"
+	done
+fi
+
+if feature_enabled ZSTD; then
+	for m in "${zstd_array[@]}"; do
+	    zstd --rm $ROOTFS/$m
+	done
+fi
+
+for m in "${attach_sha1_array[@]}"; do
+    cat "${MODULE_PLAYGROUND}/dummy.sha1" >>"${ROOTFS}/$m"
+done
+
+for m in "${attach_sha256_array[@]}"; do
+    cat "${MODULE_PLAYGROUND}/dummy.sha256" >>"${ROOTFS}/$m"
+done
+
+for m in "${attach_pkcs7_array[@]}"; do
+    cat "${MODULE_PLAYGROUND}/dummy.pkcs7" >>"${ROOTFS}/$m"
+done
+
+touch testsuite/stamp-rootfs
diff --git a/testsuite/test-blacklist.c b/testsuite/test-blacklist.c
index d03eedb..969567d 100644
--- a/testsuite/test-blacklist.c
+++ b/testsuite/test-blacklist.c
@@ -95,9 +95,6 @@ fail_lookup:
 }
 
 DEFINE_TEST(blacklist_1,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if modules are correctly blacklisted",
 	.config = {
 		[TC_ROOTFS] = TESTSUITE_ROOTFS "test-blacklist/",
diff --git a/testsuite/test-depmod.c b/testsuite/test-depmod.c
index d7802d7..c96dbf0 100644
--- a/testsuite/test-depmod.c
+++ b/testsuite/test-depmod.c
@@ -25,9 +25,9 @@
 
 #include "testsuite.h"
 
-#define MODULES_ORDER_UNAME "4.4.4"
+#define MODULES_UNAME "4.4.4"
 #define MODULES_ORDER_ROOTFS TESTSUITE_ROOTFS "test-depmod/modules-order-compressed"
-#define MODULES_ORDER_LIB_MODULES MODULES_ORDER_ROOTFS "/lib/modules/" MODULES_ORDER_UNAME
+#define MODULES_ORDER_LIB_MODULES MODULES_ORDER_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_modules_order_for_compressed(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -41,12 +41,9 @@ static noreturn int depmod_modules_order_for_compressed(const struct test *t)
 }
 
 DEFINE_TEST(depmod_modules_order_for_compressed,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if depmod let aliases in right order when using compressed modules",
 	.config = {
-		[TC_UNAME_R] = MODULES_ORDER_UNAME,
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = MODULES_ORDER_ROOTFS,
 	},
 	.output = {
@@ -57,7 +54,40 @@ DEFINE_TEST(depmod_modules_order_for_compressed,
 		},
 	});
 
+#define MODULES_OUTDIR_ROOTFS TESTSUITE_ROOTFS "test-depmod/modules-outdir"
+#define MODULES_OUTDIR_LIB_MODULES_OUTPUT MODULES_OUTDIR_ROOTFS "/outdir" MODULE_DIRECTORY "/" MODULES_UNAME
+#define MODULES_OUTDIR_LIB_MODULES_INPUT MODULES_OUTDIR_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
+static noreturn int depmod_modules_outdir(const struct test *t)
+{
+	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
+	const char *const args[] = {
+		progname,
+		"--outdir", MODULES_OUTDIR_ROOTFS "/outdir/",
+		NULL,
+	};
+
+	test_spawn_prog(progname, args);
+	exit(EXIT_FAILURE);
+}
+
+DEFINE_TEST(depmod_modules_outdir,
+	.description = "check if depmod honours the outdir option",
+	.config = {
+		[TC_UNAME_R] = MODULES_UNAME,
+		[TC_ROOTFS] = MODULES_OUTDIR_ROOTFS,
+	},
+	.output = {
+		.files = (const struct keyval[]) {
+			{ MODULES_OUTDIR_LIB_MODULES_OUTPUT "/modules.dep",
+			  MODULES_OUTDIR_ROOTFS "/correct-modules.dep" },
+			{ MODULES_OUTDIR_LIB_MODULES_OUTPUT "/modules.alias",
+			  MODULES_OUTDIR_ROOTFS "/correct-modules.alias" },
+			{ }
+		},
+	});
+
 #define SEARCH_ORDER_SIMPLE_ROOTFS TESTSUITE_ROOTFS "test-depmod/search-order-simple"
+#define SEARCH_ORDER_SIMPLE_LIB_MODULES SEARCH_ORDER_SIMPLE_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_search_order_simple(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -72,18 +102,19 @@ static noreturn int depmod_search_order_simple(const struct test *t)
 DEFINE_TEST(depmod_search_order_simple,
 	.description = "check if depmod honor search order in config",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = SEARCH_ORDER_SIMPLE_ROOTFS,
 	},
 	.output = {
 		.files = (const struct keyval[]) {
-			{ SEARCH_ORDER_SIMPLE_ROOTFS "/lib/modules/4.4.4/correct-modules.dep",
-			  SEARCH_ORDER_SIMPLE_ROOTFS "/lib/modules/4.4.4/modules.dep" },
+			{ SEARCH_ORDER_SIMPLE_LIB_MODULES "/correct-modules.dep",
+			  SEARCH_ORDER_SIMPLE_LIB_MODULES "/modules.dep" },
 			{ }
 		},
 	});
 
 #define SEARCH_ORDER_SAME_PREFIX_ROOTFS TESTSUITE_ROOTFS "test-depmod/search-order-same-prefix"
+#define SEARCH_ORDER_SAME_PREFIX_LIB_MODULES SEARCH_ORDER_SAME_PREFIX_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_search_order_same_prefix(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -98,13 +129,13 @@ static noreturn int depmod_search_order_same_prefix(const struct test *t)
 DEFINE_TEST(depmod_search_order_same_prefix,
 	.description = "check if depmod honor search order in config with same prefix",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = SEARCH_ORDER_SAME_PREFIX_ROOTFS,
 	},
 	.output = {
 		.files = (const struct keyval[]) {
-			{ SEARCH_ORDER_SAME_PREFIX_ROOTFS "/lib/modules/4.4.4/correct-modules.dep",
-			  SEARCH_ORDER_SAME_PREFIX_ROOTFS "/lib/modules/4.4.4/modules.dep" },
+			{ SEARCH_ORDER_SAME_PREFIX_LIB_MODULES "/correct-modules.dep",
+			  SEARCH_ORDER_SAME_PREFIX_LIB_MODULES "/modules.dep" },
 			{ }
 		},
 	});
@@ -122,12 +153,9 @@ static noreturn int depmod_detect_loop(const struct test *t)
 	exit(EXIT_FAILURE);
 }
 DEFINE_TEST(depmod_detect_loop,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if depmod detects module loops correctly",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = DETECT_LOOP_ROOTFS,
 	},
 	.expected_fail = true,
@@ -136,6 +164,7 @@ DEFINE_TEST(depmod_detect_loop,
 	});
 
 #define SEARCH_ORDER_EXTERNAL_FIRST_ROOTFS TESTSUITE_ROOTFS "test-depmod/search-order-external-first"
+#define SEARCH_ORDER_EXTERNAL_FIRST_LIB_MODULES SEARCH_ORDER_EXTERNAL_FIRST_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_search_order_external_first(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -148,23 +177,21 @@ static noreturn int depmod_search_order_external_first(const struct test *t)
 	exit(EXIT_FAILURE);
 }
 DEFINE_TEST(depmod_search_order_external_first,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if depmod honor external keyword with higher priority",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = SEARCH_ORDER_EXTERNAL_FIRST_ROOTFS,
 	},
 	.output = {
 		.files = (const struct keyval[]) {
-			{ SEARCH_ORDER_EXTERNAL_FIRST_ROOTFS "/lib/modules/4.4.4/correct-modules.dep",
-			  SEARCH_ORDER_EXTERNAL_FIRST_ROOTFS "/lib/modules/4.4.4/modules.dep" },
+			{ SEARCH_ORDER_EXTERNAL_FIRST_LIB_MODULES "/correct-modules.dep",
+			  SEARCH_ORDER_EXTERNAL_FIRST_LIB_MODULES "/modules.dep" },
 			{ }
 		},
 	});
 
 #define SEARCH_ORDER_EXTERNAL_LAST_ROOTFS TESTSUITE_ROOTFS "test-depmod/search-order-external-last"
+#define SEARCH_ORDER_EXTERNAL_LAST_LIB_MODULES SEARCH_ORDER_EXTERNAL_LAST_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_search_order_external_last(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -179,18 +206,19 @@ static noreturn int depmod_search_order_external_last(const struct test *t)
 DEFINE_TEST(depmod_search_order_external_last,
 	.description = "check if depmod honor external keyword with lower priority",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = SEARCH_ORDER_EXTERNAL_LAST_ROOTFS,
 	},
 	.output = {
 		.files = (const struct keyval[]) {
-			{ SEARCH_ORDER_EXTERNAL_LAST_ROOTFS "/lib/modules/4.4.4/correct-modules.dep",
-			  SEARCH_ORDER_EXTERNAL_LAST_ROOTFS "/lib/modules/4.4.4/modules.dep" },
+			{ SEARCH_ORDER_EXTERNAL_LAST_LIB_MODULES "/correct-modules.dep",
+			  SEARCH_ORDER_EXTERNAL_LAST_LIB_MODULES "/modules.dep" },
 			{ }
 		},
 	});
 
 #define SEARCH_ORDER_OVERRIDE_ROOTFS TESTSUITE_ROOTFS "test-depmod/search-order-override"
+#define SEARCH_ORDER_OVERRIDE_LIB_MODULES SEARCH_ORDER_OVERRIDE_ROOTFS MODULE_DIRECTORY "/" MODULES_UNAME
 static noreturn int depmod_search_order_override(const struct test *t)
 {
 	const char *progname = ABS_TOP_BUILDDIR "/tools/depmod";
@@ -203,18 +231,15 @@ static noreturn int depmod_search_order_override(const struct test *t)
 	exit(EXIT_FAILURE);
 }
 DEFINE_TEST(depmod_search_order_override,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if depmod honor override keyword",
 	.config = {
-		[TC_UNAME_R] = "4.4.4",
+		[TC_UNAME_R] = MODULES_UNAME,
 		[TC_ROOTFS] = SEARCH_ORDER_OVERRIDE_ROOTFS,
 	},
 	.output = {
 		.files = (const struct keyval[]) {
-			{ SEARCH_ORDER_OVERRIDE_ROOTFS "/lib/modules/4.4.4/correct-modules.dep",
-			  SEARCH_ORDER_OVERRIDE_ROOTFS "/lib/modules/4.4.4/modules.dep" },
+			{ SEARCH_ORDER_OVERRIDE_LIB_MODULES "/correct-modules.dep",
+			  SEARCH_ORDER_OVERRIDE_LIB_MODULES "/modules.dep" },
 			{ }
 		},
 	});
diff --git a/testsuite/test-modprobe.c b/testsuite/test-modprobe.c
index 0255f1a..309f3e3 100644
--- a/testsuite/test-modprobe.c
+++ b/testsuite/test-modprobe.c
@@ -83,9 +83,6 @@ static noreturn int modprobe_show_alias_to_none(const struct test *t)
 	exit(EXIT_FAILURE);
 }
 DEFINE_TEST(modprobe_show_alias_to_none,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if modprobe --show-depends doesn't explode with an alias to nothing",
 	.config = {
 		[TC_UNAME_R] = "4.4.4",
@@ -175,9 +172,6 @@ static noreturn int modprobe_softdep_loop(const struct test *t)
 	exit(EXIT_FAILURE);
 }
 DEFINE_TEST(modprobe_softdep_loop,
-#if defined(KMOD_SYSCONFDIR_NOT_ETC)
-        .skip = true,
-#endif
 	.description = "check if modprobe breaks softdep loop",
 	.config = {
 		[TC_UNAME_R] = "4.4.4",
@@ -422,4 +416,54 @@ DEFINE_TEST(modprobe_external,
 	.modules_loaded = "mod-simple",
 	);
 
+static noreturn int modprobe_module_from_abspath(const struct test *t)
+{
+	const char *progname = ABS_TOP_BUILDDIR "/tools/modprobe";
+	const char *const args[] = {
+		progname,
+		"/home/foo/mod-simple.ko",
+		NULL,
+	};
+
+	test_spawn_prog(progname, args);
+	exit(EXIT_FAILURE);
+}
+DEFINE_TEST(modprobe_module_from_abspath,
+	.description = "check modprobe able to load module given as an absolute path",
+	.config = {
+		[TC_UNAME_R] = "4.4.4",
+		[TC_ROOTFS] = TESTSUITE_ROOTFS "test-modprobe/module-from-abspath",
+		[TC_INIT_MODULE_RETCODES] = "",
+	},
+	.modules_loaded = "mod-simple",
+	);
+
+static noreturn int modprobe_module_from_relpath(const struct test *t)
+{
+	const char *progname = ABS_TOP_BUILDDIR "/tools/modprobe";
+	const char *const args[] = {
+		progname,
+		"./mod-simple.ko",
+		NULL,
+	};
+
+	if (chdir("/home/foo") != 0) {
+		perror("failed to change into /home/foo");
+		exit(EXIT_FAILURE);
+	}
+
+	test_spawn_prog(progname, args);
+	exit(EXIT_FAILURE);
+}
+DEFINE_TEST(modprobe_module_from_relpath,
+	.description = "check modprobe able to load module given as a relative path",
+	.config = {
+		[TC_UNAME_R] = "4.4.4",
+		[TC_ROOTFS] = TESTSUITE_ROOTFS "test-modprobe/module-from-relpath",
+		[TC_INIT_MODULE_RETCODES] = "",
+	},
+	.need_spawn = true,
+	.modules_loaded = "mod-simple",
+	);
+
 TESTSUITE_MAIN();
diff --git a/testsuite/test-new-module.c b/testsuite/test-new-module.c
index 360065c..9872b78 100644
--- a/testsuite/test-new-module.c
+++ b/testsuite/test-new-module.c
@@ -29,7 +29,7 @@
 
 static int from_name(const struct test *t)
 {
-	static const char *modnames[] = {
+	static const char *const modnames[] = {
 		"ext4",
 		"balbalbalbbalbalbalbalbalbalbal",
 		"snd-hda-intel",
@@ -37,7 +37,7 @@ static int from_name(const struct test *t)
 		"iTCO_wdt",
 		NULL,
 	};
-	const char **p;
+	const char *const *p;
 	struct kmod_ctx *ctx;
 	struct kmod_module *mod;
 	const char *null_config = NULL;
@@ -72,11 +72,11 @@ DEFINE_TEST(from_name,
 
 static int from_alias(const struct test *t)
 {
-	static const char *modnames[] = {
+	static const char *const modnames[] = {
 		"ext4.*",
 		NULL,
 	};
-	const char **p;
+	const char *const *p;
 	struct kmod_ctx *ctx;
 	int err;
 
diff --git a/testsuite/test-testsuite.c b/testsuite/test-testsuite.c
index 56e7360..c77c4bb 100644
--- a/testsuite/test-testsuite.c
+++ b/testsuite/test-testsuite.c
@@ -64,7 +64,7 @@ static int testsuite_rootfs_fopen(const struct test *t)
 	char s[100];
 	int n;
 
-	fp = fopen("/lib/modules/a", "r");
+	fp = fopen(MODULE_DIRECTORY "/a", "r");
 	if (fp == NULL)
 		return EXIT_FAILURE;;
 
@@ -89,7 +89,7 @@ static int testsuite_rootfs_open(const struct test *t)
 	char buf[100];
 	int fd, done;
 
-	fd = open("/lib/modules/a", O_RDONLY);
+	fd = open(MODULE_DIRECTORY "/a", O_RDONLY);
 	if (fd < 0)
 		return EXIT_FAILURE;
 
@@ -121,12 +121,12 @@ static int testsuite_rootfs_stat_access(const struct test *t)
 {
 	struct stat st;
 
-	if (access("/lib/modules/a", F_OK) < 0) {
+	if (access(MODULE_DIRECTORY "/a", F_OK) < 0) {
 		ERR("access failed: %m\n");
 		return EXIT_FAILURE;
 	}
 
-	if (stat("/lib/modules/a", &st) < 0) {
+	if (stat(MODULE_DIRECTORY "/a", &st) < 0) {
 		ERR("stat failed: %m\n");
 		return EXIT_FAILURE;
 	}
diff --git a/testsuite/test-tools.c b/testsuite/test-tools.c
deleted file mode 100644
index 4a9ee9b..0000000
--- a/testsuite/test-tools.c
+++ /dev/null
@@ -1,71 +0,0 @@
-/*
- * Copyright (C) 2015 Intel Corporation. All rights reserved.
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of the GNU Lesser General Public
- * License as published by the Free Software Foundation; either
- * version 2.1 of the License, or (at your option) any later version.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
- * Lesser General Public License for more details.
- *
- * You should have received a copy of the GNU Lesser General Public
- * License along with this library; if not, see <http://www.gnu.org/licenses/>.
- */
-
-#include <errno.h>
-#include <inttypes.h>
-#include <stddef.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
-#include <unistd.h>
-
-#include "testsuite.h"
-
-static noreturn int kmod_tool_insert(const struct test *t)
-{
-	const char *progname = ABS_TOP_BUILDDIR "/tools/kmod";
-	const char *const args[] = {
-		progname,
-		"insert", "mod-simple",
-		NULL,
-	};
-
-	test_spawn_prog(progname, args);
-	exit(EXIT_FAILURE);
-}
-DEFINE_TEST(kmod_tool_insert,
-	.description = "check kmod insert",
-	.config = {
-		[TC_UNAME_R] = "4.4.4",
-		[TC_ROOTFS] = TESTSUITE_ROOTFS "test-tools/insert",
-		[TC_INIT_MODULE_RETCODES] = "",
-	},
-	.modules_loaded = "mod-simple",
-	);
-
-static noreturn int kmod_tool_remove(const struct test *t)
-{
-	const char *progname = ABS_TOP_BUILDDIR "/tools/kmod";
-	const char *const args[] = {
-		progname,
-		"remove", "mod-simple",
-		NULL,
-	};
-
-	test_spawn_prog(progname, args);
-	exit(EXIT_FAILURE);
-}
-DEFINE_TEST(kmod_tool_remove,
-	.description = "check kmod remove",
-	.config = {
-		[TC_UNAME_R] = "4.4.4",
-		[TC_ROOTFS] = TESTSUITE_ROOTFS "test-tools/remove",
-		[TC_DELETE_MODULE_RETCODES] = "",
-	},
-	);
-
-TESTSUITE_MAIN();
diff --git a/testsuite/test-util.c b/testsuite/test-util.c
index fb8c9ef..e3243e8 100644
--- a/testsuite/test-util.c
+++ b/testsuite/test-util.c
@@ -31,7 +31,7 @@
 
 static int alias_1(const struct test *t)
 {
-	static const char *input[] = {
+	static const char *const input[] = {
 		"test1234",
 		"test[abcfoobar]2211",
 		"bar[aaa][bbbb]sss",
@@ -42,7 +42,7 @@ static int alias_1(const struct test *t)
 
 	char buf[PATH_MAX];
 	size_t len;
-	const char **alias;
+	const char *const *alias;
 
 	for (alias = input; *alias != NULL; alias++) {
 		int ret;
@@ -231,7 +231,7 @@ DEFINE_TEST(test_addu64_overflow,
 
 static int test_backoff_time(const struct test *t)
 {
-	unsigned long long delta;
+	unsigned long long delta = 0;
 
 	/* Check exponential increments */
 	get_backoff_delta_msec(now_msec(), now_msec() + 10, &delta);
diff --git a/testsuite/testsuite.c b/testsuite/testsuite.c
index 6a2d296..318343a 100644
--- a/testsuite/testsuite.c
+++ b/testsuite/testsuite.c
@@ -53,7 +53,7 @@ static const struct option options[] = {
 #define OVERRIDE_LIBDIR ABS_TOP_BUILDDIR "/testsuite/.libs/"
 #define TEST_TIMEOUT_USEC 2 * USEC_PER_SEC
 
-struct _env_config {
+static const struct {
 	const char *key;
 	const char *ldpreload;
 } env_config[_TC_LAST] = {
diff --git a/tools/depmod.c b/tools/depmod.c
index 364b7d4..43fc354 100644
--- a/tools/depmod.c
+++ b/tools/depmod.c
@@ -50,19 +50,21 @@ static int verbose = DEFAULT_VERBOSE;
 
 static const char CFG_BUILTIN_KEY[] = "built-in";
 static const char CFG_EXTERNAL_KEY[] = "external";
-static const char *default_cfg_paths[] = {
+static const char *const default_cfg_paths[] = {
 	SYSCONFDIR "/depmod.d",
 	"/run/depmod.d",
 	"/usr/local/lib/depmod.d",
+	DISTCONFDIR "/depmod.d",
 	"/lib/depmod.d",
 	NULL
 };
 
-static const char cmdopts_s[] = "aAb:C:E:F:euqrvnP:wmVh";
+static const char cmdopts_s[] = "aAb:o:C:E:F:euqrvnP:wmVh";
 static const struct option cmdopts[] = {
 	{ "all", no_argument, 0, 'a' },
 	{ "quick", no_argument, 0, 'A' },
 	{ "basedir", required_argument, 0, 'b' },
+	{ "outdir", required_argument, 0, 'o' },
 	{ "config", required_argument, 0, 'C' },
 	{ "symvers", required_argument, 0, 'E' },
 	{ "filesyms", required_argument, 0, 'F' },
@@ -104,6 +106,7 @@ static void help(void)
 		"\n"
 		"The following options are useful for people managing distributions:\n"
 		"\t-b, --basedir=DIR    Use an image of a module tree.\n"
+		"\t-o, --outdir=DIR     Output directory for generated files.\n"
 		"\t-F, --filesyms=FILE  Use the file instead of the\n"
 		"\t                     current kernel symbols.\n"
 		"\t-E, --symvers=FILE   Use Module.symvers file to check\n"
@@ -187,7 +190,7 @@ static struct index_node *index_create(void)
 {
 	struct index_node *node;
 
-	node = NOFAIL(calloc(sizeof(struct index_node), 1));
+	node = NOFAIL(calloc(1, sizeof(struct index_node)));
 	node->prefix = NOFAIL(strdup(""));
 	node->first = INDEX_CHILDMAX;
 
@@ -250,7 +253,7 @@ static int index_add_value(struct index_value **values,
 		values = &(*values)->next;
 
 	len = strlen(value);
-	v = NOFAIL(calloc(sizeof(struct index_value) + len + 1, 1));
+	v = NOFAIL(calloc(1, sizeof(struct index_value) + len + 1));
 	v->next = *values;
 	v->priority = priority;
 	memcpy(v->value, value, len + 1);
@@ -281,7 +284,7 @@ static int index_insert(struct index_node *node, const char *key,
 				struct index_node *n;
 
 				/* New child is copy of node with prefix[j+1..N] */
-				n = NOFAIL(calloc(sizeof(struct index_node), 1));
+				n = NOFAIL(calloc(1, sizeof(struct index_node)));
 				memcpy(n, node, sizeof(struct index_node));
 				n->prefix = NOFAIL(strdup(&prefix[j+1]));
 
@@ -310,7 +313,7 @@ static int index_insert(struct index_node *node, const char *key,
 				node->first = ch;
 			if (ch > node->last)
 				node->last = ch;
-			node->children[ch] = NOFAIL(calloc(sizeof(struct index_node), 1));
+			node->children[ch] = NOFAIL(calloc(1, sizeof(struct index_node)));
 
 			child = node->children[ch];
 			child->prefix = NOFAIL(strdup(&key[i+1]));
@@ -467,6 +470,8 @@ struct cfg {
 	const char *kversion;
 	char dirname[PATH_MAX];
 	size_t dirnamelen;
+	char outdirname[PATH_MAX];
+	size_t outdirnamelen;
 	char sym_prefix;
 	uint8_t check_symvers;
 	uint8_t print_unknown;
@@ -906,7 +911,7 @@ struct vertex;
 struct mod {
 	struct kmod_module *kmod;
 	char *path;
-	const char *relpath; /* path relative to '$ROOT/lib/modules/$VER/' */
+	const char *relpath; /* path relative to '$ROOT$MODULE_DIRECTORY/$VER/' */
 	char *uncrelpath; /* same as relpath but ending in .ko */
 	struct kmod_list *info_list;
 	struct kmod_list *dep_sym_list;
@@ -1582,7 +1587,7 @@ static int depmod_load_modules(struct depmod *depmod)
 		struct kmod_list *l, *list = NULL;
 		int err = kmod_module_get_symbols(mod->kmod, &list);
 		if (err < 0) {
-			if (err == -ENOENT)
+			if (err == -ENODATA)
 				DBG("ignoring %s: no symbols\n", mod->path);
 			else
 				ERR("failed to load symbols from %s: %s\n",
@@ -2576,7 +2581,7 @@ static int depmod_output(struct depmod *depmod, FILE *out)
 		{ "modules.devname", output_devname },
 		{ }
 	};
-	const char *dname = depmod->cfg->dirname;
+	const char *dname = depmod->cfg->outdirname;
 	int dfd, err = 0;
 	struct timeval tv;
 
@@ -2585,6 +2590,11 @@ static int depmod_output(struct depmod *depmod, FILE *out)
 	if (out != NULL)
 		dfd = -1;
 	else {
+		err = mkdir_p(dname, strlen(dname), 0755);
+		if (err < 0) {
+			CRIT("could not create directory %s: %m\n", dname);
+			return err;
+		}
 		dfd = open(dname, O_RDONLY);
 		if (dfd < 0) {
 			err = -errno;
@@ -2898,6 +2908,7 @@ static int do_depmod(int argc, char *argv[])
 	FILE *out = NULL;
 	int err = 0, all = 0, maybe_all = 0, n_config_paths = 0;
 	_cleanup_free_ char *root = NULL;
+	_cleanup_free_ char *out_root = NULL;
 	_cleanup_free_ const char **config_paths = NULL;
 	const char *system_map = NULL;
 	const char *module_symvers = NULL;
@@ -2927,6 +2938,11 @@ static int do_depmod(int argc, char *argv[])
 				free(root);
 			root = path_make_absolute_cwd(optarg);
 			break;
+		case 'o':
+			if (out_root)
+				free(out_root);
+			out_root = path_make_absolute_cwd(optarg);
+			break;
 		case 'C': {
 			size_t bytes = sizeof(char *) * (n_config_paths + 2);
 			void *tmp = realloc(config_paths, bytes);
@@ -3008,8 +3024,12 @@ static int do_depmod(int argc, char *argv[])
 	}
 
 	cfg.dirnamelen = snprintf(cfg.dirname, PATH_MAX,
-				  "%s/lib/modules/%s",
-				  root == NULL ? "" : root, cfg.kversion);
+				  "%s" MODULE_DIRECTORY "/%s",
+				  root ?: "", cfg.kversion);
+
+	cfg.outdirnamelen = snprintf(cfg.outdirname, PATH_MAX,
+				     "%s" MODULE_DIRECTORY "/%s",
+				     out_root ?: (root ?: ""), cfg.kversion);
 
 	if (optind == argc)
 		all = 1;
diff --git a/tools/insert.c b/tools/insert.c
deleted file mode 100644
index 0ebcef9..0000000
--- a/tools/insert.c
+++ /dev/null
@@ -1,128 +0,0 @@
-/*
- * kmod-insert - insert a module into the kernel.
- *
- * Copyright (C) 2015 Intel Corporation. All rights reserved.
- * Copyright (C) 2011-2013  ProFUSION embedded systems
- *
- * This program is free software: you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation, either version 2 of the License, or
- * (at your option) any later version.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- *
- * You should have received a copy of the GNU General Public License
- * along with this program.  If not, see <http://www.gnu.org/licenses/>.
- */
-
-#include <errno.h>
-#include <getopt.h>
-#include <stdlib.h>
-#include <string.h>
-
-#include <libkmod/libkmod.h>
-
-#include "kmod.h"
-
-static const char cmdopts_s[] = "h";
-static const struct option cmdopts[] = {
-	{"help", no_argument, 0, 'h'},
-	{ }
-};
-
-static void help(void)
-{
-	printf("Usage:\n"
-	       "\t%s insert [options] module\n"
-	       "Options:\n"
-	       "\t-h, --help        show this help\n",
-	       program_invocation_short_name);
-}
-
-static const char *mod_strerror(int err)
-{
-	switch (err) {
-	case KMOD_PROBE_APPLY_BLACKLIST:
-		return "Module is blacklisted";
-	case -EEXIST:
-		return "Module already in kernel";
-	case -ENOENT:
-		return "Unknown symbol in module or unknown parameter (see dmesg)";
-	default:
-		return strerror(-err);
-	}
-}
-
-static int do_insert(int argc, char *argv[])
-{
-	struct kmod_ctx *ctx;
-	struct kmod_list *list = NULL, *l;
-	const char *name;
-	int err, r = EXIT_SUCCESS;
-
-	for (;;) {
-		int c, idx = 0;
-		c = getopt_long(argc, argv, cmdopts_s, cmdopts, &idx);
-		if (c == -1)
-			break;
-		switch (c) {
-		case 'h':
-			help();
-			return EXIT_SUCCESS;
-		default:
-			ERR("Unexpected getopt_long() value '%c'.\n", c);
-			return EXIT_FAILURE;
-		}
-	}
-
-	if (optind >= argc) {
-		ERR("Missing module name\n");
-		return EXIT_FAILURE;
-	}
-
-	ctx = kmod_new(NULL, NULL);
-	if (!ctx) {
-		ERR("kmod_new() failed!\n");
-		return EXIT_FAILURE;
-	}
-
-	name = argv[optind];
-	err = kmod_module_new_from_lookup(ctx, name, &list);
-	if (err < 0) {
-		ERR("Could not lookup module matching '%s': %s\n", name, strerror(-err));
-		r = EXIT_FAILURE;
-		goto end;
-	}
-
-	if (list == NULL) {
-		ERR("No module matches '%s'\n", name);
-		r = EXIT_FAILURE;
-		goto end;
-	}
-
-	kmod_list_foreach(l, list) {
-		struct kmod_module *mod = kmod_module_get_module(l);
-
-		err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
-		if (err != 0) {
-			r = EXIT_FAILURE;
-			ERR("Could not insert '%s': %s\n", kmod_module_get_name(mod), mod_strerror(err));
-		}
-
-		kmod_module_unref(mod);
-	}
-
-	kmod_module_unref_list(list);
-end:
-	kmod_unref(ctx);
-	return r;
-}
-
-const struct kmod_cmd kmod_cmd_insert = {
-	.name = "insert",
-	.cmd = do_insert,
-	.help = "insert a module into the kernel",
-};
diff --git a/tools/kmod.c b/tools/kmod.c
index 55689c0..1015575 100644
--- a/tools/kmod.c
+++ b/tools/kmod.c
@@ -42,11 +42,6 @@ static const struct kmod_cmd *kmod_cmds[] = {
 	&kmod_cmd_help,
 	&kmod_cmd_list,
 	&kmod_cmd_static_nodes,
-
-#ifdef ENABLE_EXPERIMENTAL
-	&kmod_cmd_insert,
-	&kmod_cmd_remove,
-#endif
 };
 
 static const struct kmod_cmd *kmod_compat_cmds[] = {
diff --git a/tools/kmod.pc.in b/tools/kmod.pc.in
new file mode 100644
index 0000000..97215c8
--- /dev/null
+++ b/tools/kmod.pc.in
@@ -0,0 +1,10 @@
+prefix=@prefix@
+sysconfdir=@sysconfdir@
+distconfdir=@distconfdir@
+module_directory=@module_directory@
+module_compressions=@module_compressions@
+module_signatures=@module_signatures@
+
+Name: kmod
+Description: Tools to deal with kernel modules
+Version: @VERSION@
diff --git a/tools/modinfo.c b/tools/modinfo.c
index d0aab20..cacc32d 100644
--- a/tools/modinfo.c
+++ b/tools/modinfo.c
@@ -367,7 +367,7 @@ static void help(void)
 		"\t-m, --modname               Handle argument as module name instead of alias or filename\n"
 		"\t-F, --field=FIELD           Print only provided FIELD\n"
 		"\t-k, --set-version=VERSION   Use VERSION instead of `uname -r`\n"
-		"\t-b, --basedir=DIR           Use DIR as filesystem root for /lib/modules\n"
+		"\t-b, --basedir=DIR           Use DIR as filesystem root for " MODULE_DIRECTORY "\n"
 		"\t-V, --version               Show version\n"
 		"\t-h, --help                  Show this help\n",
 		program_invocation_short_name);
@@ -462,7 +462,7 @@ static int do_modinfo(int argc, char *argv[])
 			}
 			kversion = u.release;
 		}
-		snprintf(dirname_buf, sizeof(dirname_buf), "%s/lib/modules/%s",
+		snprintf(dirname_buf, sizeof(dirname_buf), "%s" MODULE_DIRECTORY "/%s",
 			 root, kversion);
 		dirname = dirname_buf;
 	}
diff --git a/tools/modprobe.c b/tools/modprobe.c
index 2a2ae21..5306bef 100644
--- a/tools/modprobe.c
+++ b/tools/modprobe.c
@@ -142,7 +142,7 @@ static void help(void)
 		"\t-n, --show                  Same as --dry-run\n"
 
 		"\t-C, --config=FILE           Use FILE instead of default search paths\n"
-		"\t-d, --dirname=DIR           Use DIR as filesystem root for /lib/modules\n"
+		"\t-d, --dirname=DIR           Use DIR as filesystem root for " MODULE_DIRECTORY "\n"
 		"\t-S, --set-version=VERSION   Use VERSION instead of `uname -r`\n"
 
 		"\t-s, --syslog                print to syslog, not stderr\n"
@@ -455,6 +455,7 @@ static int rmmod_do_module(struct kmod_module *mod, int flags)
 		struct kmod_list *holders = kmod_module_get_holders(mod);
 
 		err = rmmod_do_modlist(holders, true);
+		kmod_module_unref_list(holders);
 		if (err < 0)
 			goto error;
 	}
@@ -569,21 +570,68 @@ static void print_action(struct kmod_module *m, bool install,
 		printf("insmod %s %s\n", kmod_module_get_path(m), options);
 }
 
+static int insmod_insert(struct kmod_module *mod, int flags,
+				const char *extra_options)
+{
+	int err = 0;
+	void (*show)(struct kmod_module *m, bool install,
+						const char *options) = NULL;
+
+	if (do_show || verbose > DEFAULT_VERBOSE)
+		show = &print_action;
+
+	if (lookup_only)
+		printf("%s\n", kmod_module_get_name(mod));
+	else
+		err = kmod_module_probe_insert_module(mod, flags,
+				extra_options, NULL, NULL, show);
+
+	if (err >= 0)
+		/* ignore flag return values such as a mod being blacklisted */
+		err = 0;
+	else {
+		switch (err) {
+		case -EEXIST:
+			ERR("could not insert '%s': Module already in kernel\n",
+						kmod_module_get_name(mod));
+			break;
+		case -ENOENT:
+			ERR("could not insert '%s': Unknown symbol in module, "
+					"or unknown parameter (see dmesg)\n",
+					kmod_module_get_name(mod));
+			break;
+		default:
+			ERR("could not insert '%s': %s\n",
+					kmod_module_get_name(mod),
+					strerror(-err));
+			break;
+		}
+	}
+
+	return err;
+}
+
 static int insmod(struct kmod_ctx *ctx, const char *alias,
 						const char *extra_options)
 {
 	struct kmod_list *l, *list = NULL;
+	struct kmod_module *mod = NULL;
 	int err, flags = 0;
 
-	void (*show)(struct kmod_module *m, bool install,
-						const char *options) = NULL;
-
-	err = kmod_module_new_from_lookup(ctx, alias, &list);
-
-	if (list == NULL || err < 0) {
-		LOG("Module %s not found in directory %s\n", alias,
-			ctx ? kmod_get_dirname(ctx) : "(missing)");
-		return -ENOENT;
+	if (strncmp(alias, "/", 1) == 0 || strncmp(alias, "./", 2) == 0) {
+		err = kmod_module_new_from_path(ctx, alias, &mod);
+		if (err < 0) {
+			LOG("Failed to get module from path %s: %s\n", alias,
+				strerror(-err));
+			return -ENOENT;
+		}
+	} else {
+		err = kmod_module_new_from_lookup(ctx, alias, &list);
+		if (list == NULL || err < 0) {
+			LOG("Module %s not found in directory %s\n", alias,
+				ctx ? kmod_get_dirname(ctx) : "(missing)");
+			return -ENOENT;
+		}
 	}
 
 	if (strip_modversion || force)
@@ -596,8 +644,6 @@ static int insmod(struct kmod_ctx *ctx, const char *alias,
 		flags |= KMOD_PROBE_IGNORE_LOADED;
 	if (dry_run)
 		flags |= KMOD_PROBE_DRY_RUN;
-	if (do_show || verbose > DEFAULT_VERBOSE)
-		show = &print_action;
 
 	flags |= KMOD_PROBE_APPLY_BLACKLIST_ALIAS_ONLY;
 
@@ -606,42 +652,18 @@ static int insmod(struct kmod_ctx *ctx, const char *alias,
 	if (first_time)
 		flags |= KMOD_PROBE_FAIL_ON_LOADED;
 
-	kmod_list_foreach(l, list) {
-		struct kmod_module *mod = kmod_module_get_module(l);
-
-		if (lookup_only)
-			printf("%s\n", kmod_module_get_name(mod));
-		else {
-			err = kmod_module_probe_insert_module(mod, flags,
-					extra_options, NULL, NULL, show);
-		}
-
-		if (err >= 0)
-			/* ignore flag return values such as a mod being blacklisted */
-			err = 0;
-		else {
-			switch (err) {
-			case -EEXIST:
-				ERR("could not insert '%s': Module already in kernel\n",
-							kmod_module_get_name(mod));
-				break;
-			case -ENOENT:
-				ERR("could not insert '%s': Unknown symbol in module, "
-						"or unknown parameter (see dmesg)\n",
-						kmod_module_get_name(mod));
-				break;
-			default:
-				ERR("could not insert '%s': %s\n",
-						kmod_module_get_name(mod),
-						strerror(-err));
-				break;
-			}
-		}
-
+	/* If module is loaded from path */
+	if (mod != NULL) {
+		err = insmod_insert(mod, flags, extra_options);
 		kmod_module_unref(mod);
+	} else {
+		kmod_list_foreach(l, list) {
+			mod = kmod_module_get_module(l);
+			err = insmod_insert(mod, flags, extra_options);
+			kmod_module_unref(mod);
+		}
+		kmod_module_unref_list(list);
 	}
-
-	kmod_module_unref_list(list);
 	return err;
 }
 
@@ -819,6 +841,7 @@ static int do_modprobe(int argc, char **orig_argv)
 	int do_show_modversions = 0;
 	int do_show_exports = 0;
 	int err;
+	struct stat stat_buf;
 
 	argv = prepend_options_from_env(&argc, orig_argv);
 	if (argv == NULL) {
@@ -947,6 +970,12 @@ static int do_modprobe(int argc, char **orig_argv)
 	args = argv + optind;
 	nargs = argc - optind;
 
+	if (!use_syslog &&
+	    (!stderr ||
+	     fileno(stderr) == -1 ||
+	     fstat(fileno(stderr), &stat_buf)))
+		use_syslog = 1;
+
 	log_open(use_syslog);
 
 	if (!do_show_config) {
@@ -970,7 +999,7 @@ static int do_modprobe(int argc, char **orig_argv)
 			kversion = u.release;
 		}
 		snprintf(dirname_buf, sizeof(dirname_buf),
-				"%s/lib/modules/%s", root,
+				"%s" MODULE_DIRECTORY "/%s", root,
 				kversion);
 		dirname = dirname_buf;
 	}
diff --git a/tools/remove.c b/tools/remove.c
deleted file mode 100644
index 387ef0e..0000000
--- a/tools/remove.c
+++ /dev/null
@@ -1,153 +0,0 @@
-/*
- * kmod-remove - remove modules from the kernel.
- *
- * Copyright (C) 2015 Intel Corporation. All rights reserved.
- * Copyright (C) 2011-2013  ProFUSION embedded systems
- *
- * This program is free software: you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation, either version 2 of the License, or
- * (at your option) any later version.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- *
- * You should have received a copy of the GNU General Public License
- * along with this program.  If not, see <http://www.gnu.org/licenses/>.
- */
-
-#include <errno.h>
-#include <getopt.h>
-#include <stdlib.h>
-#include <string.h>
-
-#include <libkmod/libkmod.h>
-
-#include "kmod.h"
-
-static const char cmdopts_s[] = "h";
-static const struct option cmdopts[] = {
-	{"help", no_argument, 0, 'h'},
-	{ }
-};
-
-static void help(void)
-{
-	printf("Usage:\n"
-	       "\t%s remove [options] module\n"
-	       "Options:\n"
-	       "\t-h, --help        show this help\n",
-	       program_invocation_short_name);
-}
-
-static int check_module_inuse(struct kmod_module *mod) {
-	struct kmod_list *holders;
-	int state, ret;
-
-	state = kmod_module_get_initstate(mod);
-
-	if (state == KMOD_MODULE_BUILTIN) {
-		ERR("Module %s is builtin.\n", kmod_module_get_name(mod));
-		return -ENOENT;
-	} else if (state < 0) {
-		ERR("Module %s is not currently loaded\n",
-				kmod_module_get_name(mod));
-		return -ENOENT;
-	}
-
-	holders = kmod_module_get_holders(mod);
-	if (holders != NULL) {
-		struct kmod_list *itr;
-
-		ERR("Module %s is in use by:", kmod_module_get_name(mod));
-
-		kmod_list_foreach(itr, holders) {
-			struct kmod_module *hm = kmod_module_get_module(itr);
-			fprintf(stderr, " %s", kmod_module_get_name(hm));
-			kmod_module_unref(hm);
-		}
-		fputc('\n', stderr);
-
-		kmod_module_unref_list(holders);
-		return -EBUSY;
-	}
-
-	ret = kmod_module_get_refcnt(mod);
-	if (ret > 0) {
-		ERR("Module %s is in use\n", kmod_module_get_name(mod));
-		return -EBUSY;
-	} else if (ret == -ENOENT) {
-		ERR("Module unloading is not supported\n");
-	}
-
-	return ret;
-}
-
-static int do_remove(int argc, char *argv[])
-{
-	struct kmod_ctx *ctx;
-	struct kmod_module *mod;
-	const char *name;
-	int err, r = EXIT_SUCCESS;
-
-	for (;;) {
-		int c, idx =0;
-		c = getopt_long(argc, argv, cmdopts_s, cmdopts, &idx);
-		if (c == -1)
-			break;
-		switch (c) {
-		case 'h':
-			help();
-			return EXIT_SUCCESS;
-
-		default:
-			ERR("Unexpected getopt_long() value '%c'.\n", c);
-			return EXIT_FAILURE;
-		}
-	}
-
-	if (optind >= argc) {
-		ERR("Missing module name\n");
-		return EXIT_FAILURE;
-	}
-
-	ctx = kmod_new(NULL, NULL);
-	if (!ctx) {
-		ERR("kmod_new() failed!\n");
-		return EXIT_FAILURE;
-	}
-
-	name = argv[optind];
-	err = kmod_module_new_from_name(ctx, name, &mod);
-	if (err < 0) {
-		ERR("Could not remove module %s: %s\n", name, strerror(-err));
-		goto end;
-	}
-
-	err = check_module_inuse(mod);
-	if (err < 0)
-		goto unref;
-
-	err = kmod_module_remove_module(mod, 0);
-	if (err < 0)
-		goto unref;
-
-unref:
-	kmod_module_unref(mod);
-
-end:
-	kmod_unref(ctx);
-	if (err < 0) {
-		r = EXIT_FAILURE;
-		ERR("Could not remove module %s: %s\n", name, strerror(-err));
-	}
-	return r;
-}
-
-const struct kmod_cmd kmod_cmd_remove = {
-	.name = "remove",
-	.cmd = do_remove,
-	.help = "remove module from kernel",
-};
diff --git a/tools/static-nodes.c b/tools/static-nodes.c
index 8d2356d..5ef3743 100644
--- a/tools/static-nodes.c
+++ b/tools/static-nodes.c
@@ -212,15 +212,15 @@ static int do_static_nodes(int argc, char *argv[])
 		goto finish;
 	}
 
-	snprintf(modules, sizeof(modules), "/lib/modules/%s/modules.devname", kernel.release);
+	snprintf(modules, sizeof(modules), MODULE_DIRECTORY "/%s/modules.devname", kernel.release);
 	in = fopen(modules, "re");
 	if (in == NULL) {
 		if (errno == ENOENT) {
-			fprintf(stderr, "Warning: /lib/modules/%s/modules.devname not found - ignoring\n",
+			fprintf(stderr, "Warning: " MODULE_DIRECTORY "/%s/modules.devname not found - ignoring\n",
 				kernel.release);
 			ret = EXIT_SUCCESS;
 		} else {
-			fprintf(stderr, "Error: could not open /lib/modules/%s/modules.devname - %m\n",
+			fprintf(stderr, "Error: could not open " MODULE_DIRECTORY "/%s/modules.devname - %m\n",
 				kernel.release);
 			ret = EXIT_FAILURE;
 		}
```

