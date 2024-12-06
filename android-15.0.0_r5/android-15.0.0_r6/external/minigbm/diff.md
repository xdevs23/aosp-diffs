```diff
diff --git a/Android.bp b/Android.bp
index 1f62e5b..57f44d5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -142,6 +142,16 @@ cc_defaults {
     srcs: [":minigbm_gralloc0_files"],
 }
 
+generic_cflags = ["-DHAS_DMABUF_SYSTEM_HEAP"]
+intel_cflags = ["-DDRV_I915"]
+meson_cflags = ["-DDRV_MESON"]
+msm_cflags = [
+    "-DDRV_MSM",
+    "-DQCOM_DISABLE_COMPRESSED_NV12",
+    "-DHAS_DMABUF_SYSTEM_HEAP",
+]
+arcvm_cflags = ["-DVIRTIO_GPU_NEXT"]
+
 cc_library {
     name: "libgbm",
     defaults: ["minigbm_defaults"],
@@ -151,8 +161,18 @@ cc_library {
         ":minigbm_core_files",
         "gbm.c",
         "gbm_helpers.c",
+        "minigbm_helpers.c",
     ],
 
+    cflags: select(soong_config_variable("minigbm", "platform"), {
+        "generic": generic_cflags,
+        "intel": intel_cflags,
+        "meson": meson_cflags,
+        "msm": msm_cflags,
+        "arcvm": arcvm_cflags,
+        default: [],
+    }),
+
     target: {
         host: {
             // Avoid linking to another host copy of libdrm; this library will cause
@@ -203,7 +223,7 @@ rust_bindgen {
         "//apex_available:platform",
     ],
     visibility: [
-        "//external/rust/crates/gbm",
+        "//external/rust/android-crates-io/crates/gbm",
     ],
 }
 
@@ -211,7 +231,7 @@ rust_bindgen {
 cc_library_shared {
     name: "libminigbm_gralloc",
     defaults: ["minigbm_cros_gralloc_library_defaults"],
-    cflags: ["-DHAS_DMABUF_SYSTEM_HEAP"],
+    cflags: generic_cflags,
 }
 
 cc_library_shared {
@@ -234,7 +254,7 @@ cc_library_headers {
 cc_library_shared {
     name: "libminigbm_gralloc_intel",
     defaults: ["minigbm_cros_gralloc_library_defaults"],
-    cflags: ["-DDRV_I915"],
+    cflags: intel_cflags,
     enabled: false,
     arch: {
         x86: {
@@ -265,7 +285,7 @@ cc_library_shared {
 cc_library_shared {
     name: "libminigbm_gralloc_meson",
     defaults: ["minigbm_cros_gralloc_library_defaults"],
-    cflags: ["-DDRV_MESON"],
+    cflags: meson_cflags,
 }
 
 cc_library_shared {
@@ -278,11 +298,7 @@ cc_library_shared {
 cc_library_shared {
     name: "libminigbm_gralloc_msm",
     defaults: ["minigbm_cros_gralloc_library_defaults"],
-    cflags: [
-        "-DDRV_MSM",
-        "-DQCOM_DISABLE_COMPRESSED_NV12",
-        "-DHAS_DMABUF_SYSTEM_HEAP",
-    ],
+    cflags: msm_cflags,
 }
 
 cc_library_shared {
@@ -295,7 +311,7 @@ cc_library_shared {
 cc_library_shared {
     name: "libminigbm_gralloc_arcvm",
     defaults: ["minigbm_cros_gralloc_library_defaults"],
-    cflags: ["-DVIRTIO_GPU_NEXT"],
+    cflags: arcvm_cflags,
 }
 
 cc_library_shared {
diff --git a/Makefile b/Makefile
index db27cf6..90805dd 100644
--- a/Makefile
+++ b/Makefile
@@ -42,14 +42,16 @@ endif
 CPPFLAGS += $(PC_CFLAGS)
 LDLIBS += $(PC_LIBS)
 
-LIBDIR ?= /usr/lib/
+DESTDIR ?= $(OUT)/install
+LIBDIR ?= /usr/lib
+INCLUDEDIR ?= /usr/include
 
-GBM_VERSION_MAJOR := 1
-MINIGBM_VERSION := $(GBM_VERSION_MAJOR).0.0
+MINIGBM_VERSION_MAJOR := 1
+MINIGBM_VERSION := $(MINIGBM_VERSION_MAJOR).0.0
 MINIGBM_FILENAME := libminigbm.so.$(MINIGBM_VERSION)
 
-CC_LIBRARY($(MINIGBM_FILENAME)): LDFLAGS += -Wl,-soname,libgbm.so.$(GBM_VERSION_MAJOR)
-CC_LIBRARY($(MINIGBM_FILENAME)): $(C_OBJECTS)
+CC_LIBRARY($(MINIGBM_FILENAME)): LDFLAGS += -Wl,-soname,libgbm.so.$(MINIGBM_VERSION_MAJOR)
+CC_LIBRARY($(MINIGBM_FILENAME)): $(C_OBJECTS) pkgconfig
 CC_STATIC_LIBRARY(libminigbm.pie.a): $(C_OBJECTS)
 
 all: CC_LIBRARY($(MINIGBM_FILENAME))
@@ -63,11 +65,33 @@ CXX_BINARY(gbm_unittest): $(UNITTEST_DEPS)
 clean: CLEAN(gbm_unittest)
 tests: TEST(CXX_BINARY(gbm_unittest))
 
+define pkgconfig_contents
+prefix=$(DESTDIR)
+exec_prefix=$${prefix}
+includedir=$${prefix}/$(INCLUDEDIR)
+libdir=$${prefix}/$(LIBDIR)
+
+Name: libgbm
+Description: A small gbm implementation
+Version: 18.0.0
+Cflags: -I$${includedir}
+Libs: -L$${libdir} -lgbm
+Requires.private: libdrm >= 2.4.50
+endef
+
+.PHONY: pkgconfig
+pkgconfig:
+	@echo "generating $(OUT)gbm.pc"
+	$(file > $(OUT)/gbm.pc,$(pkgconfig_contents))
+clean:
+	rm -f $(OUT)gbm.pc
+
 install: all
 	mkdir -p $(DESTDIR)/$(LIBDIR)
 	install -D -m 755 $(OUT)/$(MINIGBM_FILENAME) $(DESTDIR)/$(LIBDIR)
 	ln -sf $(MINIGBM_FILENAME) $(DESTDIR)/$(LIBDIR)/libgbm.so
-	ln -sf $(MINIGBM_FILENAME) $(DESTDIR)/$(LIBDIR)/libgbm.so.$(GBM_VERSION_MAJOR)
-	install -D -m 0644 $(SRC)/gbm.pc $(DESTDIR)$(LIBDIR)/pkgconfig/gbm.pc
-	install -D -m 0644 $(SRC)/gbm.h $(DESTDIR)/usr/include/gbm.h
-	install -D -m 0644 $(SRC)/minigbm_helpers.h $(DESTDIR)/usr/include/minigbm/minigbm_helpers.h
+	ln -sf $(MINIGBM_FILENAME) $(DESTDIR)/$(LIBDIR)/libgbm.so.$(MINIGBM_VERSION_MAJOR)
+	ln -sf $(MINIGBM_FILENAME) $(DESTDIR)/$(LIBDIR)/libgbm.so.$(MINIGBM_VERSION)
+	install -D -m 0644 $(OUT)/gbm.pc $(DESTDIR)/$(LIBDIR)/pkgconfig/gbm.pc
+	install -D -m 0644 $(SRC)/gbm.h $(DESTDIR)/$(INCLUDEDIR)/gbm.h
+	install -D -m 0644 $(SRC)/minigbm_helpers.h $(DESTDIR)/$(INCLUDEDIR)/minigbm/minigbm_helpers.h
diff --git a/OWNERS b/OWNERS
index e47b7b8..e03c24d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,20 +1,21 @@
 basni@chromium.org
+dawnhan@google.com
 dbehr@chromium.org
 ddavenport@chromium.org
 gurchetansingh@chromium.org
 hiroh@chromium.org
-hoegsberg@chromium.org
 marcheu@chromium.org
 mcasas@chromium.org
+niwa@chromium.org
 olv@google.com
 robdclark@chromium.org
 tfiga@chromium.org
 zzyiwei@chromium.org
 
 # just reference for backend specific reviews
-per-file amdgpu.c = basni@chromium.org, ddavenport@chromium.org
-per-file i915.c = chadversary@chromium.org, linyaa@google.com, hoegsberg@chromium.org
-per-file mediatek.c = fshao@chromium.org, hsinyi@chromium.org, tzungbi@chromium.org
-per-file msm.c = robdclark@chromium.org, hoegsberg@chromium.org
+per-file amdgpu.c = basni@chromium.org, ddavenport@chromium.org, olv@google.com
+per-file i915.c = linyaa@google.com, msturner@google.com
+per-file mediatek.c = fshao@chromium.org, hsinyi@chromium.org
+per-file msm.c = robdclark@chromium.org
 per-file rockchip.c = tfiga@chromium.org
-per-file virtgpu* = jbates@chromium.org, natsu@google.com, olv@google.com, zzyiwei@chromium.org
+per-file virtgpu* = dawnhan@google.com, natsu@google.com, zzyiwei@chromium.org
diff --git a/backend_mock.c b/backend_mock.c
index ae0d758..67012ad 100644
--- a/backend_mock.c
+++ b/backend_mock.c
@@ -6,7 +6,8 @@
 
 #include "drv_priv.h"
 
-static int backend_mock_init(struct driver *drv) {
+static int backend_mock_init(struct driver *drv)
+{
 	return 0;
 }
 
diff --git a/common.mk b/common.mk
index ea9d204..0c24778 100644
--- a/common.mk
+++ b/common.mk
@@ -1,4 +1,4 @@
-# Copyright 2012 The Chromium OS Authors. All rights reserved.
+# Copyright 2012 The ChromiumOS Authors
 # Use of this source code is governed by a BSD-style license that can be
 # found in the LICENSE file.
 #
@@ -63,7 +63,7 @@
 #
 # Possible command line variables:
 #   - COLOR=[0|1] to set ANSI color output (default: 1)
-#   - VERBOSE=[0|1] to hide/show commands (default: 0)
+#   - VERBOSE=[0|1] V=[0|1] to hide/show commands (default: 0)
 #   - MODE=[opt|dbg|profiling] (default: opt)
 #          opt - Enable optimizations for release builds
 #          dbg - Turn down optimization for debugging
@@ -98,9 +98,11 @@ SPLITDEBUG ?= 0
 NOSTRIP ?= 1
 VALGRIND ?= 0
 COLOR ?= 1
-VERBOSE ?= 0
+V ?= 0
+VERBOSE ?= $(V)
 MODE ?= opt
 CXXEXCEPTIONS ?= 0
+RUN_TESTS ?= 1
 ARCH ?= $(shell uname -m)
 
 # Put objects in a separate tree based on makefile locations
@@ -258,13 +260,13 @@ $(eval $(call override_var,STRIP,strip))
 RMDIR ?= rmdir
 ECHO = /bin/echo -e
 
-ifeq ($(lastword $(subst /, ,$(CC))),clang)
+ifeq ($(filter clang,$(subst -, ,$(notdir $(CC)))),clang)
 CDRIVER = clang
 else
 CDRIVER = gcc
 endif
 
-ifeq ($(lastword $(subst /, ,$(CXX))),clang++)
+ifeq ($(filter clang++,$(subst -, ,$(notdir $(CXX)))),clang++)
 CXXDRIVER = clang
 else
 CXXDRIVER = gcc
@@ -310,12 +312,30 @@ endif
 #  CXXFLAGS := $(filter-out badflag,$(CXXFLAGS)) # Filter out a value
 # The same goes for CFLAGS.
 COMMON_CFLAGS-gcc := -fvisibility=internal -ggdb3 -Wa,--noexecstack
-COMMON_CFLAGS-clang := -fvisibility=hidden -ggdb
-COMMON_CFLAGS := -Wall -Werror -fno-strict-aliasing $(SSP_CFLAGS) -O1 -Wformat=2
-CXXFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CXXDRIVER))
-CFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CDRIVER))
+# minigbm: Disable -Wimplicit-fallthrough to unbreak compilation.
+COMMON_CFLAGS-clang := -fvisibility=hidden -ggdb \
+  -Wstring-plus-int
+# When a class is exported through __attribute__((visibility("default"))), we
+# still want to eliminate symbols from inline class member functions to reduce
+# symbol resolution overhead. Therefore, pass -fvisibility-inlines-hidden in
+# addition to -fvisibility=hidden. (go/cros-symbol-slimming)
+# minigbm: Disable -Wunreachable-code to unbreak compilation.
+COMMON_CFLAGS := -Wall -Wunused -Wno-unused-parameter \
+  -Wbool-operation -Wstring-compare -Wxor-used-as-pow \
+  -Wint-in-bool-context -Wfree-nonheap-object \
+  -Werror -Wformat=2 -fno-strict-aliasing \
+  $(SSP_CFLAGS) -O1
+CXXFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CXXDRIVER)) -std=gnu++20 \
+			-fvisibility-inlines-hidden
+CFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CDRIVER)) -std=gnu17
+# We undefine _FORTIFY_SOURCE because some distros enable it by default in
+# their toolchains.  This makes the compiler issue warnings about redefines
+# and our -Werror usage breaks it all.
 CPPFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
 
+# Enable large file support.
+CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
+
 # Disable exceptions based on the CXXEXCEPTIONS setting.
 ifeq ($(CXXEXCEPTIONS),0)
   CXXFLAGS := $(CXXFLAGS) -fno-exceptions -fno-unwind-tables \
@@ -340,7 +360,11 @@ ifeq ($(MODE),profiling)
   LDFLAGS := $(LDFLAGS) --coverage
 endif
 
-LDFLAGS := $(LDFLAGS) -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now
+# Pass -Bsymbolic-non-weak which pre-binds symbols in the same DSO to improve
+# startup performance. We don't support interposing non-weak symbols.
+# (go/cros-symbol-slimming)
+LDFLAGS := $(LDFLAGS) -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now \
+  -Wl,-Bsymbolic-non-weak
 
 # Fancy helpers for color if a prompt is defined
 ifeq ($(COLOR),1)
@@ -510,8 +534,11 @@ CC_STATIC_LIBARY(%):
 	$(error Typo alert! LIBARY != LIBRARY)
 
 
-TEST(%): % qemu_chroot_install
+TEST(%): %
 	$(call TEST_implementation)
+ifneq ($(RUN_TESTS),0)
+TEST(%): qemu_chroot_install
+endif
 .PHONY: TEST
 
 # multiple targets with a wildcard need to share an directory.
@@ -577,13 +604,12 @@ $(1): %.o: %.pic.o %.pie.o
 	$$(QUIET)touch "$$@"
 endef
 
+# Wrap all the deps in $$(wildcard) so a missing header won't cause weirdness.
+# First we remove newlines and \, then wrap it.
 define OBJECT_PATTERN_implementation
   @$(ECHO) "$(1)		$(subst $(SRC)/,,$<) -> $(2).o"
   $(call auto_mkdir,$@)
   $(QUIET)$($(1)) -c -MD -MF $(2).d $(3) -o $(2).o $<
-  $(QUIET)# Wrap all the deps in $$(wildcard) so a missing header
-  $(QUIET)# won't cause weirdness.  First we remove newlines and \,
-  $(QUIET)# then wrap it.
   $(QUIET)sed -i -e :j -e '$$!N;s|\\\s*\n| |;tj' \
     -e 's|^\(.*\s*:\s*\)\(.*\)$$|\1 $$\(wildcard \2\)|' $(2).d
 endef
@@ -722,7 +748,9 @@ ifeq ($(MODE),profiling)
 		fi
 	@$(ECHO) "COVERAGE [$(COLOR_YELLOW)FINISHED$(COLOR_RESET)]"
 endif
-.PHONY: tests
+# Standard name everyone else uses.
+check: tests
+.PHONY: check tests
 
 qemu_chroot_install:
 ifeq ($(USE_QEMU),1)
@@ -795,12 +823,17 @@ ifeq ($(VALGRIND),1)
   VALGRIND_CMD = /usr/bin/valgrind --tool=memcheck $(VALGRIND_ARGS) --
 endif
 
+ifneq ($(RUN_TESTS),0)
 define TEST_implementation
   $(QUIET)$(call TEST_setup)
   $(QUIET)$(call TEST_run)
   $(QUIET)$(call TEST_teardown)
   $(QUIET)exit $$(cat $(OUT)$(TARGET_OR_MEMBER).status.test)
 endef
+else
+define TEST_implementation
+endef
+endif
 
 define TEST_setup
   @$(ECHO) -n "TEST		$(TARGET_OR_MEMBER) "
diff --git a/cros_gralloc/cros_gralloc_helpers.cc b/cros_gralloc/cros_gralloc_helpers.cc
index 67a53a0..4b40bfd 100644
--- a/cros_gralloc/cros_gralloc_helpers.cc
+++ b/cros_gralloc/cros_gralloc_helpers.cc
@@ -78,6 +78,16 @@ uint32_t cros_gralloc_convert_format(int format)
 	case HAL_PIXEL_FORMAT_YCBCR_P010:
 		return DRM_FORMAT_P010;
 #endif
+	case HAL_PIXEL_FORMAT_DEPTH_16:
+		return DRM_FORMAT_DEPTH16;
+	case HAL_PIXEL_FORMAT_DEPTH_24:
+		return DRM_FORMAT_DEPTH24;
+	case HAL_PIXEL_FORMAT_DEPTH_24_STENCIL_8:
+		return DRM_FORMAT_DEPTH24_STENCIL8;
+	case HAL_PIXEL_FORMAT_DEPTH_32F:
+		return DRM_FORMAT_DEPTH32;
+	case HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8:
+		return DRM_FORMAT_DEPTH32_STENCIL8;
 	}
 
 	return DRM_FORMAT_NONE;
diff --git a/cros_gralloc/gralloc0/tests/gralloctest.c b/cros_gralloc/gralloc0/tests/gralloctest.c
index 9d8101c..1641b8a 100644
--- a/cros_gralloc/gralloc0/tests/gralloctest.c
+++ b/cros_gralloc/gralloc0/tests/gralloctest.c
@@ -22,7 +22,7 @@
 #include <sync/sync.h>
 #include <system/graphics.h>
 
-#define ALIGN(A, B) (((A) + (B)-1) / (B) * (B))
+#define ALIGN(A, B) (((A) + (B) - 1) / (B) * (B))
 #define ARRAY_SIZE(A) (sizeof(A) / sizeof(*(A)))
 
 #define CHECK(cond)                                                                                \
diff --git a/cros_gralloc/gralloc4/Android.bp b/cros_gralloc/gralloc4/Android.bp
index fb6aca9..73588f7 100644
--- a/cros_gralloc/gralloc4/Android.bp
+++ b/cros_gralloc/gralloc4/Android.bp
@@ -79,11 +79,17 @@ cc_defaults {
     srcs: [":minigbm_gralloc4_allocator_files"],
 }
 
+vintf_fragment {
+    name: "android.hardware.graphics.allocator@4.0.xml",
+    src: "android.hardware.graphics.allocator@4.0.xml",
+    vendor: true,
+}
+
 cc_binary {
     name: "android.hardware.graphics.allocator@4.0-service.minigbm",
     defaults: ["minigbm_gralloc4_allocator_defaults"],
     shared_libs: ["libminigbm_gralloc"],
-    vintf_fragments: ["android.hardware.graphics.allocator@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.allocator@4.0.xml"],
     init_rc: ["android.hardware.graphics.allocator@4.0-service.minigbm.rc"],
 }
 
@@ -91,7 +97,7 @@ cc_binary {
     name: "android.hardware.graphics.allocator@4.0-service.minigbm_msm",
     defaults: ["minigbm_gralloc4_allocator_defaults"],
     shared_libs: ["libminigbm_gralloc_msm"],
-    vintf_fragments: ["android.hardware.graphics.allocator@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.allocator@4.0.xml"],
     init_rc: ["android.hardware.graphics.allocator@4.0-service.minigbm_msm.rc"],
 }
 
@@ -99,7 +105,7 @@ cc_binary {
     name: "android.hardware.graphics.allocator@4.0-service.minigbm_arcvm",
     defaults: ["minigbm_gralloc4_allocator_defaults"],
     shared_libs: ["libminigbm_gralloc_arcvm"],
-    vintf_fragments: ["android.hardware.graphics.allocator@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.allocator@4.0.xml"],
     init_rc: ["android.hardware.graphics.allocator@4.0-service.minigbm_arcvm.rc"],
 }
 
@@ -107,7 +113,7 @@ cc_binary {
     name: "android.hardware.graphics.allocator@4.0-service.minigbm_intel",
     defaults: ["minigbm_gralloc4_allocator_defaults"],
     shared_libs: ["libminigbm_gralloc_intel"],
-    vintf_fragments: ["android.hardware.graphics.allocator@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.allocator@4.0.xml"],
     init_rc: ["android.hardware.graphics.allocator@4.0-service.minigbm_intel.rc"],
     enabled: false,
     arch: {
@@ -120,11 +126,17 @@ cc_binary {
     },
 }
 
+vintf_fragment {
+    name: "android.hardware.graphics.mapper@4.0.xml",
+    src: "android.hardware.graphics.mapper@4.0.xml",
+    vendor: true,
+}
+
 cc_library_shared {
     name: "android.hardware.graphics.mapper@4.0-impl.minigbm",
     defaults: ["minigbm_gralloc4_common_defaults"],
     shared_libs: ["libminigbm_gralloc"],
-    vintf_fragments: ["android.hardware.graphics.mapper@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.mapper@4.0.xml"],
     srcs: [":minigbm_gralloc4_mapper_files"],
 }
 
@@ -132,7 +144,7 @@ cc_library_shared {
     name: "android.hardware.graphics.mapper@4.0-impl.minigbm_msm",
     defaults: ["minigbm_gralloc4_common_defaults"],
     shared_libs: ["libminigbm_gralloc_msm"],
-    vintf_fragments: ["android.hardware.graphics.mapper@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.mapper@4.0.xml"],
     srcs: [":minigbm_gralloc4_mapper_files"],
 }
 
@@ -140,7 +152,7 @@ cc_library_shared {
     name: "android.hardware.graphics.mapper@4.0-impl.minigbm_arcvm",
     defaults: ["minigbm_gralloc4_common_defaults"],
     shared_libs: ["libminigbm_gralloc_arcvm"],
-    vintf_fragments: ["android.hardware.graphics.mapper@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.mapper@4.0.xml"],
     srcs: [":minigbm_gralloc4_mapper_files"],
 }
 
@@ -148,7 +160,7 @@ cc_library_shared {
     name: "android.hardware.graphics.mapper@4.0-impl.minigbm_intel",
     defaults: ["minigbm_gralloc4_common_defaults"],
     shared_libs: ["libminigbm_gralloc_intel"],
-    vintf_fragments: ["android.hardware.graphics.mapper@4.0.xml"],
+    vintf_fragment_modules: ["android.hardware.graphics.mapper@4.0.xml"],
     srcs: [":minigbm_gralloc4_mapper_files"],
     enabled: false,
     arch: {
diff --git a/drv.c b/drv.c
index ea3bd64..7fd2250 100644
--- a/drv.c
+++ b/drv.c
@@ -121,7 +121,8 @@ struct driver *drv_create(int fd)
 
 	const char *minigbm_debug;
 	minigbm_debug = drv_get_os_option(MINIGBM_DEBUG);
-	drv->compression = (minigbm_debug == NULL) || (strstr(minigbm_debug, "nocompression") == NULL);
+	drv->compression =
+	    (minigbm_debug == NULL) || (strstr(minigbm_debug, "nocompression") == NULL);
 	drv->log_bos = (minigbm_debug && strstr(minigbm_debug, "log_bos") != NULL);
 
 	drv->fd = fd;
@@ -732,19 +733,15 @@ void drv_bo_log_info(const struct bo *bo, const char *prefix)
 {
 	const struct bo_metadata *meta = &bo->meta;
 
-	drv_logd("%s %s bo %p: %dx%d '%c%c%c%c' tiling %d plane %zu mod 0x%" PRIx64 " use 0x%" PRIx64 " size %zu\n",
-		 prefix, bo->drv->backend->name, bo,
-		 meta->width, meta->height,
-		 meta->format & 0xff,
-		 (meta->format >> 8) & 0xff,
-		 (meta->format >> 16) & 0xff,
-		 (meta->format >> 24) & 0xff,
-		 meta->tiling, meta->num_planes, meta->format_modifier,
+	drv_logd("%s %s bo %p: %dx%d '%c%c%c%c' tiling %d plane %zu mod 0x%" PRIx64
+		 " use 0x%" PRIx64 " size %zu\n",
+		 prefix, bo->drv->backend->name, bo, meta->width, meta->height, meta->format & 0xff,
+		 (meta->format >> 8) & 0xff, (meta->format >> 16) & 0xff,
+		 (meta->format >> 24) & 0xff, meta->tiling, meta->num_planes, meta->format_modifier,
 		 meta->use_flags, meta->total_size);
 	for (uint32_t i = 0; i < meta->num_planes; i++) {
-		drv_logd("  bo %p plane %d: offset %d size %d stride %d\n",
-			 bo, i, meta->offsets[i], meta->sizes[i],
-			 meta->strides[i]);
+		drv_logd("  bo %p plane %d: offset %d size %d stride %d\n", bo, i, meta->offsets[i],
+			 meta->sizes[i], meta->strides[i]);
 	}
 }
 
diff --git a/drv.h b/drv.h
index b61aedf..bd380b5 100644
--- a/drv.h
+++ b/drv.h
@@ -64,6 +64,14 @@ extern "C" {
 #define DRM_FORMAT_FLEX_IMPLEMENTATION_DEFINED	fourcc_code('9', '9', '9', '8')
 #define DRM_FORMAT_FLEX_YCbCr_420_888		fourcc_code('9', '9', '9', '9')
 
+#ifndef DRM_FORMAT_DEPTH16
+#define DRM_FORMAT_DEPTH16 fourcc_code('D', '1', '6', ' ')
+#define DRM_FORMAT_DEPTH24 fourcc_code('D', '2', '4', 'X')
+#define DRM_FORMAT_DEPTH24_STENCIL8 fourcc_code('D', '2', '4', 'S')
+#define DRM_FORMAT_DEPTH32 fourcc_code('D', '3', '2', 'F')
+#define DRM_FORMAT_DEPTH32_STENCIL8 fourcc_code('D', 'F', 'S', '8')
+#endif
+
 /* This is a 10-bit bayer format for private reprocessing on MediaTek ISP. It's
  * a private RAW format that other DRM drivers will never support and thus
  * making it not upstreamable (i.e., defined in official DRM headers). */
@@ -98,6 +106,22 @@ extern "C" {
 #define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS fourcc_mod_code(INTEL, 13)
 #endif
 
+#ifndef I915_FORMAT_MOD_4_TILED_MTL_MC_CCS
+//TODO: remove this defination once drm_fourcc.h contains it.
+/*
+ * Intel color control surfaces (CCS) for display ver 14 media compression
+ *
+ * The main surface is tile4 and at plane index 0, the CCS is linear and
+ * at index 1. A 64B CCS cache line corresponds to an area of 4x1 tiles in
+ * main surface. In other words, 4 bits in CCS map to a main surface cache
+ * line pair. The main surface pitch is required to be a multiple of four
+ * tile4 widths. For semi-planar formats like NV12, CCS planes follow the
+ * Y and UV planes i.e., planes 0 and 1 are used for Y and UV surfaces,
+ * planes 2 and 3 for the respective CCS.
+ */
+#define I915_FORMAT_MOD_4_TILED_MTL_MC_CCS fourcc_mod_code(INTEL, 14)
+#endif
+
 // clang-format on
 struct driver;
 struct bo;
diff --git a/drv_helpers.c b/drv_helpers.c
index c810d8e..12b671a 100644
--- a/drv_helpers.c
+++ b/drv_helpers.c
@@ -100,6 +100,7 @@ static const struct planar_layout *layout_from_format(uint32_t format)
 		return &packed_1bpp_layout;
 
 	case DRM_FORMAT_R16:
+	case DRM_FORMAT_DEPTH16:
 		return &packed_2bpp_layout;
 
 	case DRM_FORMAT_YVU420:
@@ -144,6 +145,9 @@ static const struct planar_layout *layout_from_format(uint32_t format)
 	case DRM_FORMAT_RGB888:
 		return &packed_3bpp_layout;
 
+	case DRM_FORMAT_DEPTH24:
+	case DRM_FORMAT_DEPTH24_STENCIL8:
+	case DRM_FORMAT_DEPTH32:
 	case DRM_FORMAT_ABGR2101010:
 	case DRM_FORMAT_ABGR8888:
 	case DRM_FORMAT_ARGB2101010:
@@ -163,6 +167,7 @@ static const struct planar_layout *layout_from_format(uint32_t format)
 	case DRM_FORMAT_XRGB8888:
 		return &packed_4bpp_layout;
 
+	case DRM_FORMAT_DEPTH32_STENCIL8:
 	case DRM_FORMAT_ABGR16161616F:
 		return &packed_8bpp_layout;
 
diff --git a/external/virtgpu_gfxstream_protocol.h b/external/virtgpu_gfxstream_protocol.h
new file mode 100644
index 0000000..8253e64
--- /dev/null
+++ b/external/virtgpu_gfxstream_protocol.h
@@ -0,0 +1,147 @@
+// Copyright 2022 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef VIRTGPU_GFXSTREAM_PROTOCOL_H
+#define VIRTGPU_GFXSTREAM_PROTOCOL_H
+
+#include <stdint.h>
+
+// See definitions in rutabaga_gfx_ffi.h
+#define VIRTGPU_CAPSET_VIRGL 1
+#define VIRTGPU_CAPSET_VIRGL2 2
+#define VIRTGPU_CAPSET_GFXSTREAM_VULKAN 3
+#define VIRTGPU_CAPSET_VENUS 4
+#define VIRTGPU_CAPSET_CROSS_DOMAIN 5
+#define VIRTGPU_CAPSET_DRM 6
+#define VIRTGPU_CAPSET_GFXSTREAM_MAGMA 7
+#define VIRTGPU_CAPSET_GFXSTREAM_GLES 8
+#define VIRTGPU_CAPSET_GFXSTREAM_COMPOSER 9
+
+// Address Space Graphics contexts
+#define GFXSTREAM_CONTEXT_CREATE                0x1001
+#define GFXSTREAM_CONTEXT_PING                  0x1002
+#define GFXSTREAM_CONTEXT_PING_WITH_RESPONSE    0x1003
+
+// Native Sync FD
+#define GFXSTREAM_CREATE_EXPORT_SYNC            0x9000
+#define GFXSTREAM_CREATE_IMPORT_SYNC            0x9001
+
+// Vulkan Sync
+#define GFXSTREAM_CREATE_EXPORT_SYNC_VK         0xa000
+#define GFXSTREAM_CREATE_IMPORT_SYNC_VK         0xa001
+#define GFXSTREAM_CREATE_QSRI_EXPORT_VK         0xa002
+#define GFXSTREAM_RESOURCE_CREATE_3D            0xa003
+
+// clang-format off
+// A placeholder command to ensure virtio-gpu completes
+#define GFXSTREAM_PLACEHOLDER_COMMAND_VK        0xf002
+// clang-format on
+
+struct gfxstreamHeader {
+    uint32_t opCode;
+};
+
+struct gfxstreamContextCreate {
+    struct gfxstreamHeader hdr;
+    uint32_t resourceId;
+};
+
+struct gfxstreamContextPing {
+    struct gfxstreamHeader hdr;
+    uint32_t resourceId;
+};
+
+struct gfxstreamCreateExportSync {
+    struct gfxstreamHeader hdr;
+    uint32_t syncHandleLo;
+    uint32_t syncHandleHi;
+};
+
+struct gfxstreamCreateExportSyncVK {
+    struct gfxstreamHeader hdr;
+    uint32_t deviceHandleLo;
+    uint32_t deviceHandleHi;
+    uint32_t fenceHandleLo;
+    uint32_t fenceHandleHi;
+};
+
+struct gfxstreamCreateQSRIExportVK {
+    struct gfxstreamHeader hdr;
+    uint32_t imageHandleLo;
+    uint32_t imageHandleHi;
+};
+
+struct gfxstreamPlaceholderCommandVk {
+    struct gfxstreamHeader hdr;
+    uint32_t pad;
+    uint32_t padding;
+};
+
+struct gfxstreamResourceCreate3d {
+    struct gfxstreamHeader hdr;
+    uint32_t target;
+    uint32_t format;
+    uint32_t bind;
+    uint32_t width;
+    uint32_t height;
+    uint32_t depth;
+    uint32_t arraySize;
+    uint32_t lastLevel;
+    uint32_t nrSamples;
+    uint32_t flags;
+    uint32_t pad;
+    uint64_t blobId;
+};
+
+struct vulkanCapset {
+    uint32_t protocolVersion;
+
+    // ASG Ring Parameters
+    uint32_t ringSize;
+    uint32_t bufferSize;
+
+    uint32_t colorBufferMemoryIndex;
+    uint32_t deferredMapping;
+    uint32_t blobAlignment;
+    uint32_t noRenderControlEnc;
+    uint32_t alwaysBlob;
+    uint32_t externalSync;
+    uint32_t virglSupportedFormats[16];
+};
+
+struct magmaCapset {
+    uint32_t protocolVersion;
+    // ASG Ring Parameters
+    uint32_t ringSize;
+    uint32_t bufferSize;
+    uint32_t blobAlignment;
+};
+
+struct glesCapset {
+    uint32_t protocolVersion;
+    // ASG Ring Parameters
+    uint32_t ringSize;
+    uint32_t bufferSize;
+    uint32_t blobAlignment;
+};
+
+struct composerCapset {
+    uint32_t protocolVersion;
+    // ASG Ring Parameters
+    uint32_t ringSize;
+    uint32_t bufferSize;
+    uint32_t blobAlignment;
+};
+
+#endif
diff --git a/gbm.h b/gbm.h
index 8e32769..197324c 100644
--- a/gbm.h
+++ b/gbm.h
@@ -413,6 +413,18 @@ gbm_bo_map(struct gbm_bo *bo,
            uint32_t x, uint32_t y, uint32_t width, uint32_t height,
            uint32_t flags, uint32_t *stride, void **map_data);
 
+/* Neither gbm_bo_map_cache_mode nor gbm_bo_get_map_info are defined in mesa's gbm.h, or older
+ * versions of minigbm. For backwards-compatibility, users should first test for availability and
+ * provide a fallback implementation with:
+ *
+ *   #if defined(MINIGBM) && defined(MINIGBM_HAS_GBM_BO_GET_MAP_INFO)
+ *   // use gbm_bo_get_map_info()
+ *   #else
+ *   // fallback
+ *   #endif
+ */
+#define MINIGBM_HAS_GBM_BO_GET_MAP_INFO
+
 /**
  * Enum to indicate the cache attributes of CPU mapping returned by
  * gbm_bo_map()
diff --git a/gbm.pc b/gbm.pc
deleted file mode 100644
index a7509fc..0000000
--- a/gbm.pc
+++ /dev/null
@@ -1,10 +0,0 @@
-prefix=/usr
-exec_prefix=${prefix}
-includedir=${prefix}/include
-libdir=${exec_prefix}/lib
-
-Name: libgbm
-Description: A small gbm implementation
-Version: 18.0.0
-Cflags: -I${includedir}
-Libs: -L${libdir} -lgbm
diff --git a/gbm_unittest.cc b/gbm_unittest.cc
index 9f2a46f..bad568f 100644
--- a/gbm_unittest.cc
+++ b/gbm_unittest.cc
@@ -14,7 +14,7 @@
 
 class MockDrm
 {
- public:
+      public:
 	MOCK_METHOD(drmVersionPtr, drmGetVersion, (int fd));
 	MOCK_METHOD(void, drmFreeVersion, (drmVersionPtr v));
 };
@@ -30,7 +30,7 @@ drmVersionPtr drmGetVersion(int fd)
 // Define a mock version of drmFreeVersion
 void drmFreeVersion(drmVersionPtr v)
 {
-	delete(v);
+	delete (v);
 }
 
 /* TODO : This is a protocol to add unit tests for the public APIs in minigbm.
diff --git a/i915.c b/i915.c
index b9e377f..f9b79b1 100644
--- a/i915.c
+++ b/i915.c
@@ -37,15 +37,16 @@ static const uint32_t texture_only_formats[] = { DRM_FORMAT_R8, DRM_FORMAT_NV12,
 static const uint64_t gen_modifier_order[] = { I915_FORMAT_MOD_Y_TILED_CCS, I915_FORMAT_MOD_Y_TILED,
 					       I915_FORMAT_MOD_X_TILED, DRM_FORMAT_MOD_LINEAR };
 
-static const uint64_t gen12_modifier_order[] = {
-	I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS, I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS,
-	I915_FORMAT_MOD_Y_TILED, I915_FORMAT_MOD_X_TILED, DRM_FORMAT_MOD_LINEAR
-};
+static const uint64_t gen12_modifier_order[] = { I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS,
+						 I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS,
+						 I915_FORMAT_MOD_Y_TILED, I915_FORMAT_MOD_X_TILED,
+						 DRM_FORMAT_MOD_LINEAR };
 
 static const uint64_t gen11_modifier_order[] = { I915_FORMAT_MOD_Y_TILED, I915_FORMAT_MOD_X_TILED,
 						 DRM_FORMAT_MOD_LINEAR };
 
 static const uint64_t xe_lpdp_modifier_order[] = { I915_FORMAT_MOD_4_TILED_MTL_RC_CCS,
+						   I915_FORMAT_MOD_4_TILED_MTL_MC_CCS,
 						   I915_FORMAT_MOD_4_TILED, I915_FORMAT_MOD_X_TILED,
 						   DRM_FORMAT_MOD_LINEAR };
 
@@ -112,12 +113,13 @@ static void i915_info_from_device_id(struct i915_device *i915)
 		0x46b3, 0x46c0, 0x46c1, 0x46c2, 0x46c3, 0x9A40, 0x9A49, 0x9A59, 0x9A60, 0x9A68,
 		0x9A70, 0x9A78, 0x9AC0, 0x9AC9, 0x9AD9, 0x9AF8, 0x4905, 0x4906, 0x4907, 0x4908
 	};
-	const uint16_t adlp_ids[] = { 0x46A0, 0x46A1, 0x46A2, 0x46A3, 0x46A6, 0x46A8, 0x46AA,
-				      0x462A, 0x4626, 0x4628, 0x46B0, 0x46B1, 0x46B2, 0x46B3,
-				      0x46C0, 0x46C1, 0x46C2, 0x46C3, 0x46D0, 0x46D1, 0x46D2,
-				      0x46D3, 0x46D4 };
+	const uint16_t adlp_ids[] = { 0x46A0, 0x46A1, 0x46A2, 0x46A3, 0x46A6, 0x46A8,
+				      0x46AA, 0x462A, 0x4626, 0x4628, 0x46B0, 0x46B1,
+				      0x46B2, 0x46B3, 0x46C0, 0x46C1, 0x46C2, 0x46C3,
+				      0x46D0, 0x46D1, 0x46D2, 0x46D3, 0x46D4 };
 
-	const uint16_t rplp_ids[] = { 0xA720, 0xA721, 0xA7A0, 0xA7A1, 0xA7A8, 0xA7A9, 0xA7AA, 0xA7AB, 0xA7AC, 0xA7AD };
+	const uint16_t rplp_ids[] = { 0xA720, 0xA721, 0xA7A0, 0xA7A1, 0xA7A8,
+				      0xA7A9, 0xA7AA, 0xA7AB, 0xA7AC, 0xA7AD };
 
 	const uint16_t mtl_ids[] = { 0x7D40, 0x7D60, 0x7D45, 0x7D55, 0x7DD5 };
 
@@ -562,7 +564,8 @@ static size_t i915_num_planes_from_modifier(struct driver *drv, uint32_t format,
 	    modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) {
 		assert(num_planes == 1);
 		return 2;
-	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS) {
+	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
+		   modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) {
 		assert(num_planes == 2);
 		return 4;
 	}
@@ -570,6 +573,13 @@ static size_t i915_num_planes_from_modifier(struct driver *drv, uint32_t format,
 	return num_planes;
 }
 
+#define gbm_fls(x)                                                                                 \
+	((x) ? __builtin_choose_expr(sizeof(x) == 8, 64 - __builtin_clzll(x),                      \
+				     32 - __builtin_clz(x))                                        \
+	     : 0)
+
+#define roundup_power_of_two(x) ((x) != 0 ? 1ULL << gbm_fls((x) - 1) : 0)
+
 static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
 				    uint64_t use_flags, const uint64_t *modifiers, uint32_t count)
 {
@@ -590,11 +600,13 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		 * on |use_flags|. Instead the client should request them explicitly through
 		 * gbm_bo_create_with_modifiers().
 		 */
-		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS);
+		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS &&
+		       modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS);
 		/* TODO(b/323863689): Account for driver's bandwidth compression in minigbm for
 		 * media compressed buffers. */
 	}
-	if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS &&
+	if ((modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
+	     modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) &&
 	    !(format == DRM_FORMAT_NV12 || format == DRM_FORMAT_P010)) {
 		drv_loge("Media compression is only supported for NV12 and P010\n");
 		return -EINVAL;
@@ -656,6 +668,7 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		break;
 	case I915_FORMAT_MOD_4_TILED:
 	case I915_FORMAT_MOD_4_TILED_MTL_RC_CCS:
+	case I915_FORMAT_MOD_4_TILED_MTL_MC_CCS:
 		bo->meta.tiling = I915_TILING_4;
 		break;
 	}
@@ -782,39 +795,68 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		/* Total number of planes & sizes */
 		bo->meta.num_planes = plane + a_plane;
 		bo->meta.total_size = offset;
-	} else if (modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) {
-
-		/*
-		 * considering only 128 byte compression and one cache line of
-		 * aux buffer(64B) contains compression status of 4-Y tiles.
-		 * Which is 4 * (128B * 32L).
-		 * line stride(bytes) is 4 * 128B
-		 * and tile stride(lines) is 32L
+	} else if (modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS ||
+		   modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) {
+		/* Media compression modifiers should only be possible via the
+		 * gbm_bo_create_with_modifiers() path, i.e., the minigbm client needs to
+		 * explicitly request it.
 		 */
-		uint32_t stride = ALIGN(drv_stride_from_format(format, width, 0), 512);
-		stride = ALIGN(stride, 256);
+		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS || use_flags == BO_USE_NONE);
+		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
+		       bo->meta.use_flags == BO_USE_NONE);
+		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
+		       (!!modifiers && count > 0));
+		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
+		       (format == DRM_FORMAT_NV12 || format == DRM_FORMAT_P010 ||
+			format == DRM_FORMAT_XRGB8888 || format == DRM_FORMAT_XBGR8888));
+		assert(drv_num_planes_from_format(format) > 0);
 
-		height = ALIGN(drv_height_from_format(format, height, 0), 32);
+		uint32_t offset = 0, stride = 0;
+		size_t plane = 0;
+		size_t a_plane = 0;
+		for (plane = 0; plane < drv_num_planes_from_format(format); plane++) {
+			uint32_t alignment = 0, val, tmpoffset = 0;
 
+			/*
+			 * tile_align = 4 (for width) for CCS and
+			 * tile_width = 128, tile_height = 32 for MC CCS
+			 */
+			stride = ALIGN(drv_stride_from_format(format, width, plane), 512);
+			height = ALIGN(drv_height_from_format(format, height, plane), 32);
+			bo->meta.strides[plane] = stride;
 
-		bo->meta.strides[0] = stride;
-		/* size calculation and alignment are 64KB aligned
-		 * size as per spec
-		 */
-		bo->meta.sizes[0] = ALIGN(stride * height, 65536);
-		bo->meta.offsets[0] = 0;
+			/* MTL needs 1MB Alignment */
+			bo->meta.sizes[plane] = ALIGN(stride * height, 0x100000);
+			if (plane == 1 &&
+			    (format == DRM_FORMAT_NV12 || format == DRM_FORMAT_P010)) {
+				alignment = 1 << 20;
+				offset += alignment - (offset % alignment);
+				tmpoffset = offset;
+				val = roundup_power_of_two(stride);
+				if ((stride * val) > tmpoffset)
+					offset = stride * val;
+			}
+
+			bo->meta.offsets[plane] = offset;
+			offset += bo->meta.sizes[plane];
+		}
 
 		/* Aux buffer is linear and page aligned. It is placed after
 		 * other planes and aligned to main buffer stride.
 		 */
-		bo->meta.strides[1] = bo->meta.strides[0] / 8;
+		for (a_plane = 0; a_plane < plane; a_plane++) {
+			stride = bo->meta.strides[a_plane] / 8;
+			bo->meta.strides[a_plane + plane] = stride;
 
-		/* Aligned to page size */
-		bo->meta.sizes[1] = ALIGN(bo->meta.sizes[0] / 256, getpagesize());
-		bo->meta.offsets[1] = bo->meta.sizes[0];
-		/* Total number of planes & sizes */
-		bo->meta.num_planes = 2;
-		bo->meta.total_size = bo->meta.sizes[0] + bo->meta.sizes[1];
+			/* Aligned to page size */
+			bo->meta.sizes[a_plane + plane] =
+			    ALIGN(bo->meta.sizes[a_plane] / 256, getpagesize());
+			bo->meta.offsets[a_plane + plane] = offset;
+			/* next buffer offset */
+			offset += bo->meta.sizes[plane + a_plane];
+		}
+		bo->meta.num_planes = a_plane + plane;
+		bo->meta.total_size = offset;
 	} else {
 		return i915_bo_from_format(bo, width, height, format);
 	}
@@ -880,8 +922,7 @@ static int i915_bo_create_from_metadata(struct bo *bo)
 		}
 	}
 
-	bo->meta.cached = (i915->has_llc || i915->is_mtl) &&
-			  !(bo->meta.use_flags & BO_USE_SCANOUT);
+	bo->meta.cached = (i915->has_llc || i915->is_mtl) && !(bo->meta.use_flags & BO_USE_SCANOUT);
 
 	return 0;
 }
@@ -933,7 +974,8 @@ static void *i915_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 	    (bo->meta.format_modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS) ||
 	    (bo->meta.format_modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS) ||
 	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED) ||
-	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS))
+	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) ||
+	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS))
 		return MAP_FAILED;
 
 	if (bo->meta.tiling == I915_TILING_NONE) {
diff --git a/mediatek.c b/mediatek.c
index 6ebde6e..693af78 100644
--- a/mediatek.c
+++ b/mediatek.c
@@ -10,9 +10,13 @@
 #include <errno.h>
 #include <fcntl.h>
 #include <inttypes.h>
+#if !defined(ANDROID) || (ANDROID_API_LEVEL >= 31 && defined(HAS_DMABUF_SYSTEM_HEAP))
+#include <linux/dma-heap.h>
+#endif
 #include <poll.h>
 #include <stdio.h>
 #include <string.h>
+#include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <unistd.h>
 #include <xf86drm.h>
@@ -39,7 +43,8 @@
     defined(MTK_MT8186) || \
     defined(MTK_MT8188G) || \
     defined(MTK_MT8192) || \
-    defined(MTK_MT8195)
+    defined(MTK_MT8195) || \
+    defined(MTK_MT8196)
 // clang-format on
 #define USE_NV12_FOR_HW_VIDEO_DECODING
 #define SUPPORT_FP16_AND_10BIT_ABGR
@@ -66,6 +71,10 @@
 #define USE_EXTRA_PADDING_FOR_YVU420
 #endif
 
+struct mediatek_private_drv_data {
+	int dma_heap_fd;
+};
+
 struct mediatek_private_map_data {
 	void *cached_addr;
 	void *gem_addr;
@@ -119,6 +128,16 @@ static bool is_video_yuv_format(uint32_t format)
 static int mediatek_init(struct driver *drv)
 {
 	struct format_metadata metadata;
+	struct mediatek_private_drv_data *priv;
+
+	priv = calloc(1, sizeof(*priv));
+	if (!priv) {
+		drv_loge("Failed calloc private data, errno=%d\n", -errno);
+		return -errno;
+	}
+
+	priv->dma_heap_fd = -1;
+	drv->priv = priv;
 
 	drv_add_combinations(drv, render_target_formats, ARRAY_SIZE(render_target_formats),
 			     &LINEAR_METADATA,
@@ -198,6 +217,17 @@ static int mediatek_init(struct driver *drv)
 	return drv_modify_linear_combinations(drv);
 }
 
+static void mediatek_close(struct driver *drv)
+{
+	struct mediatek_private_drv_data *priv = (struct mediatek_private_drv_data *)drv->priv;
+
+	if (priv->dma_heap_fd >= 0)
+		close(priv->dma_heap_fd);
+
+	free(priv);
+	drv->priv = NULL;
+}
+
 static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint32_t height,
 					     uint32_t format, const uint64_t *modifiers,
 					     uint32_t count)
@@ -206,13 +236,17 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 	size_t plane;
 	uint32_t stride;
 	struct drm_mtk_gem_create gem_create = { 0 };
+
+	const bool is_camera_write = bo->meta.use_flags & BO_USE_CAMERA_WRITE;
+	const bool is_hw_video_encoder = bo->meta.use_flags & BO_USE_HW_VIDEO_ENCODER;
+	const bool is_linear = bo->meta.use_flags & BO_USE_LINEAR;
+	const bool is_protected = bo->meta.use_flags & BO_USE_PROTECTED;
+	const bool is_scanout = bo->meta.use_flags & BO_USE_SCANOUT;
 	/*
 	 * We identify the ChromeOS Camera App buffers via these two USE flags. Those buffers need
 	 * the same alignment as the video hardware encoding.
 	 */
-	const bool is_camera_preview =
-	    (bo->meta.use_flags & BO_USE_SCANOUT) && (bo->meta.use_flags & BO_USE_CAMERA_WRITE);
-	const bool is_hw_video_encoder = bo->meta.use_flags & BO_USE_HW_VIDEO_ENCODER;
+	const bool is_camera_preview = is_scanout && is_camera_write;
 #ifdef MTK_MT8173
 	const bool is_mt8173_video_decoder = bo->meta.use_flags & BO_USE_HW_VIDEO_DECODER;
 #else
@@ -324,11 +358,75 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 #endif
 	}
 
-	gem_create.size = bo->meta.total_size;
+	/* For protected data buffer needs to allocate from DMA_HEAP directly */
+	if (is_protected) {
+#if !defined(ANDROID) || (ANDROID_API_LEVEL >= 31 && defined(HAS_DMABUF_SYSTEM_HEAP))
+		int ret;
+		struct mediatek_private_drv_data *priv = (struct mediatek_private_drv_data *)bo->drv->priv;
+		struct dma_heap_allocation_data heap_data = {
+			.len = bo->meta.total_size,
+			.fd_flags = O_RDWR | O_CLOEXEC,
+		};
 
-	/* For protected data buffer needs to be allocated from GEM */
-	if (bo->meta.use_flags & BO_USE_PROTECTED)
-		gem_create.flags |= DRM_MTK_GEM_CREATE_ENCRYPTED;
+		if (format == DRM_FORMAT_P010) {
+			/*
+			 * Adjust the size so we don't waste tons of space. This was allocated
+			 * with 16 bpp, but we only need 10 bpp. We can safely divide by 8 because
+			 * we are aligned at a multiple higher than that.
+			 */
+			bo->meta.strides[0] = bo->meta.strides[0] * 10 / 16;
+			bo->meta.strides[1] = bo->meta.strides[1] * 10 / 16;
+			bo->meta.sizes[0] = bo->meta.sizes[0] * 10 / 16;
+			bo->meta.sizes[1] = bo->meta.sizes[1] * 10 / 16;
+			bo->meta.offsets[1] = bo->meta.sizes[0];
+			bo->meta.total_size = bo->meta.total_size * 10 / 16;
+		}
+
+		if (priv->dma_heap_fd < 0) {
+			priv->dma_heap_fd = open("/dev/dma_heap/restricted_mtk_cma", O_RDWR | O_CLOEXEC);
+			if (priv->dma_heap_fd < 0) {
+				drv_loge("Failed opening secure CMA heap errno=%d\n", -errno);
+				return -errno;
+			}
+		}
+
+		ret = ioctl(priv->dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &heap_data);
+		if (ret < 0) {
+			drv_loge("Failed allocating CMA buffer ret=%d\n", ret);
+			return ret;
+		}
+
+		/* Create GEM handle for secure CMA and close FD here */
+		ret = drmPrimeFDToHandle(bo->drv->fd, heap_data.fd, &bo->handle.u32);
+		close(heap_data.fd);
+		if (ret) {
+			drv_loge("Failed drmPrimeFDToHandle(fd:%d) ret=%d\n", heap_data.fd, ret);
+			return ret;
+		}
+#else
+		drv_loge("Protected allocation not supported\n");
+		return -1;
+#endif
+		return 0;
+	}
+
+	/*
+	 * For linear scanout buffers, the read/write pattern is usually linear i.e. each address is
+	 * accessed sequentially, and there are fewer chances that an address will be repeatedly
+	 * accessed.
+	 * This behavior leads to less TLB dependency and cache misses i.e. no need to translate the
+	 * same virtual address to a physical address multiple times.
+	 *
+	 * With that premise, it's safe to allow the DMA framework to fulfill such allocation
+	 * requests with non-continuous smaller chunks of memory (e.g., 4KiB single pages) which
+	 * are generally easier to allocate compared to large continuous chunks of memory, improving
+	 * memory allocation efficiency and reduce the risk of allocation failures, especially when
+	 * available memory budget is low or on memory-constrained devices.
+	 */
+	if (is_linear && is_scanout)
+		gem_create.flags |= DRM_MTK_GEM_CREATE_FLAG_ALLOC_SINGLE_PAGES;
+
+	gem_create.size = bo->meta.total_size;
 
 	ret = drmIoctl(bo->drv->fd, DRM_IOCTL_MTK_GEM_CREATE, &gem_create);
 	if (ret) {
@@ -524,6 +622,7 @@ static void mediatek_resolve_format_and_use_flags(struct driver *drv, uint32_t f
 const struct backend backend_mediatek = {
 	.name = "mediatek",
 	.init = mediatek_init,
+	.close = mediatek_close,
 	.bo_create = mediatek_bo_create,
 	.bo_create_with_modifiers = mediatek_bo_create_with_modifiers,
 	.bo_destroy = drv_gem_bo_destroy,
diff --git a/msm.c b/msm.c
index d6f74cc..ee585c7 100644
--- a/msm.c
+++ b/msm.c
@@ -152,6 +152,13 @@ static void msm_calculate_layout(struct bo *bo)
 
 		/* Calculate size and assign stride, size, offset to each plane based on format */
 		drv_bo_from_format(bo, stride, 1, alignh, bo->meta.format);
+		if (bo->meta.format == DRM_FORMAT_YVU420_ANDROID ||
+		    bo->meta.format == DRM_FORMAT_YVU420) {
+			const uint32_t u_size =
+			    drv_size_from_format(bo->meta.format, bo->meta.strides[2], alignh, 2);
+			const uint32_t padding = ALIGN(u_size, PLANE_SIZE_ALIGN) - u_size;
+			bo->meta.total_size += padding;
+		}
 
 		/* For all RGB UBWC formats */
 		if (bo->meta.tiling == MSM_UBWC_TILING) {
diff --git a/util.h b/util.h
index 8f8bb0d..aa1e79e 100644
--- a/util.h
+++ b/util.h
@@ -10,9 +10,9 @@
 #define MAX(A, B) ((A) > (B) ? (A) : (B))
 #define ARRAY_SIZE(A) (sizeof(A) / sizeof(*(A)))
 #define PUBLIC __attribute__((visibility("default")))
-#define ALIGN(A, B) (((A) + (B)-1) & ~((B)-1))
+#define ALIGN(A, B) (((A) + (B) - 1) & ~((B) - 1))
 #define IS_ALIGNED(A, B) (ALIGN((A), (B)) == (A))
-#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
+#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
 #define STRINGIZE_NO_EXPANSION(x) #x
 #define STRINGIZE(x) STRINGIZE_NO_EXPANSION(x)
 
diff --git a/virtgpu.h b/virtgpu.h
index b2f82ba..e74afd2 100644
--- a/virtgpu.h
+++ b/virtgpu.h
@@ -26,6 +26,6 @@ enum virtgpu_param_id {
 
 #define VIRTIO_GPU_CAPSET_VIRGL 1
 #define VIRTIO_GPU_CAPSET_VIRGL2 2
-#define VIRTIO_GPU_CAPSET_GFXSTREAM 3
+#define VIRTIO_GPU_CAPSET_GFXSTREAM_VULKAN 3
 #define VIRTIO_GPU_CAPSET_VENUS 4
 #define VIRTIO_GPU_CAPSET_CROSS_DOMAIN 5
diff --git a/virtgpu_virgl.c b/virtgpu_virgl.c
index 222703e..b438498 100644
--- a/virtgpu_virgl.c
+++ b/virtgpu_virgl.c
@@ -21,6 +21,7 @@
 #include "external/virgl_hw.h"
 #include "external/virgl_protocol.h"
 #include "external/virtgpu_drm.h"
+#include "external/virtgpu_gfxstream_protocol.h"
 #include "util.h"
 #include "virtgpu.h"
 
@@ -52,6 +53,11 @@ static const uint32_t texture_source_formats[] = {
 	DRM_FORMAT_ABGR2101010, DRM_FORMAT_ABGR16161616F
 };
 
+static const uint32_t depth_stencil_formats[] = {
+	DRM_FORMAT_DEPTH16, DRM_FORMAT_DEPTH24, DRM_FORMAT_DEPTH24_STENCIL8,
+	DRM_FORMAT_DEPTH32, DRM_FORMAT_DEPTH32_STENCIL8
+};
+
 extern struct virtgpu_param params[];
 
 struct virgl_blob_metadata_cache {
@@ -66,6 +72,8 @@ struct virgl_blob_metadata_cache {
 struct virgl_priv {
 	int caps_is_v2;
 	union virgl_caps caps;
+	int caps_is_gfxstream;
+	struct vulkanCapset gfxstream_vulkan_caps;
 	int host_gbm_enabled;
 	atomic_int next_blob_id;
 
@@ -108,6 +116,16 @@ static uint32_t translate_format(uint32_t drm_fourcc)
 	case DRM_FORMAT_YVU420:
 	case DRM_FORMAT_YVU420_ANDROID:
 		return VIRGL_FORMAT_YV12;
+	case DRM_FORMAT_DEPTH16:
+		return VIRGL_FORMAT_Z16_UNORM;
+	case DRM_FORMAT_DEPTH24:
+		return VIRGL_FORMAT_Z24X8_UNORM;
+	case DRM_FORMAT_DEPTH24_STENCIL8:
+		return VIRGL_FORMAT_Z24_UNORM_S8_UINT;
+	case DRM_FORMAT_DEPTH32:
+		return VIRGL_FORMAT_Z32_FLOAT;
+	case DRM_FORMAT_DEPTH32_STENCIL8:
+		return VIRGL_FORMAT_Z32_FLOAT_S8X24_UINT;
 	default:
 		drv_loge("Unhandled format:%d\n", drm_fourcc);
 		return 0;
@@ -315,6 +333,17 @@ static bool virgl_supports_combination_natively(struct driver *drv, uint32_t drm
 {
 	struct virgl_priv *priv = (struct virgl_priv *)drv->priv;
 
+	if (priv->caps_is_gfxstream) {
+		// If the data is invalid or an older version just accept all formats as previously
+		if (priv->gfxstream_vulkan_caps.protocolVersion == 0 ||
+		    priv->gfxstream_vulkan_caps.virglSupportedFormats[0] == 0)
+			return true;
+		bool supported_format = virgl_bitmask_supports_format(
+		    (struct virgl_supported_format_mask *)&priv->gfxstream_vulkan_caps
+			.virglSupportedFormats[0],
+		    drm_format);
+		return supported_format;
+	}
 	if (priv->caps.max_version == 0)
 		return true;
 
@@ -544,34 +573,42 @@ static uint32_t virgl_3d_get_max_texture_2d_size(struct driver *drv)
 	return UINT32_MAX;
 }
 
-static int virgl_get_caps(struct driver *drv, union virgl_caps *caps, int *caps_is_v2)
+static int virgl_get_caps(struct driver *drv, struct virgl_priv *priv)
 {
 	int ret;
 	struct drm_virtgpu_get_caps cap_args = { 0 };
 
-	memset(caps, 0, sizeof(union virgl_caps));
-	*caps_is_v2 = 0;
+	memset(&priv->caps, 0, sizeof(union virgl_caps));
+	priv->caps_is_v2 = 0;
+	memset(&priv->gfxstream_vulkan_caps, 0, sizeof(struct vulkanCapset));
 
 	if (params[param_supported_capset_ids].value) {
 		drv_logi("Supported CAPSET IDs: %u.", params[param_supported_capset_ids].value);
 		if (params[param_supported_capset_ids].value & (1 << VIRTIO_GPU_CAPSET_VIRGL2)) {
-			*caps_is_v2 = 1;
+			priv->caps_is_v2 = 1;
 		} else if (params[param_supported_capset_ids].value &
 			   (1 << VIRTIO_GPU_CAPSET_VIRGL)) {
-			*caps_is_v2 = 0;
+			priv->caps_is_v2 = 0;
+		} else if (params[param_supported_capset_ids].value &
+			   (1 << VIRTIO_GPU_CAPSET_GFXSTREAM_VULKAN)) {
+			priv->caps_is_gfxstream = 1;
 		} else {
 			drv_logi("Unrecognized CAPSET IDs: %u. Assuming all zero caps.",
 				 params[param_supported_capset_ids].value);
 			return 0;
 		}
 	} else if (params[param_capset_fix].value) {
-		*caps_is_v2 = 1;
+		priv->caps_is_v2 = 1;
 	}
 
-	cap_args.addr = (unsigned long long)caps;
-	if (*caps_is_v2) {
+	cap_args.addr = (unsigned long long)&priv->caps;
+	if (priv->caps_is_v2) {
 		cap_args.cap_set_id = VIRTIO_GPU_CAPSET_VIRGL2;
 		cap_args.size = sizeof(union virgl_caps);
+	} else if (priv->caps_is_gfxstream) {
+		cap_args.addr = (unsigned long long)&priv->gfxstream_vulkan_caps;
+		cap_args.cap_set_id = VIRTIO_GPU_CAPSET_GFXSTREAM_VULKAN;
+		cap_args.size = sizeof(struct vulkanCapset);
 	} else {
 		cap_args.cap_set_id = VIRTIO_GPU_CAPSET_VIRGL;
 		cap_args.size = sizeof(struct virgl_caps_v1);
@@ -580,7 +617,9 @@ static int virgl_get_caps(struct driver *drv, union virgl_caps *caps, int *caps_
 	ret = drmIoctl(drv->fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &cap_args);
 	if (ret) {
 		drv_loge("DRM_IOCTL_VIRTGPU_GET_CAPS failed with %s\n", strerror(errno));
-		*caps_is_v2 = 0;
+		priv->caps_is_v2 = 0;
+		priv->caps_is_gfxstream = 0;
+		cap_args.addr = (unsigned long long)&priv->caps;
 
 		// Fallback to v1
 		cap_args.cap_set_id = VIRTIO_GPU_CAPSET_VIRGL;
@@ -598,7 +637,7 @@ static void virgl_init_params_and_caps(struct driver *drv)
 {
 	struct virgl_priv *priv = (struct virgl_priv *)drv->priv;
 	if (params[param_3d].value) {
-		virgl_get_caps(drv, &priv->caps, &priv->caps_is_v2);
+		virgl_get_caps(drv, priv);
 
 		// We use two criteria to determine whether host minigbm is used on the host for
 		// swapchain allocations.
@@ -639,6 +678,9 @@ static int virgl_init(struct driver *drv)
 		virgl_add_combinations(drv, texture_source_formats,
 				       ARRAY_SIZE(texture_source_formats), &LINEAR_METADATA,
 				       BO_USE_TEXTURE_MASK);
+		virgl_add_combinations(drv, depth_stencil_formats,
+				       ARRAY_SIZE(depth_stencil_formats), &LINEAR_METADATA,
+				       BO_USE_GPU_HW);
 		/* NV12 with scanout must flow through virgl_add_combination, so that the native
 		 * support is checked and scanout use_flag can be conditionally stripped. */
 		virgl_add_combination(drv, DRM_FORMAT_NV12, &LINEAR_METADATA,
```

