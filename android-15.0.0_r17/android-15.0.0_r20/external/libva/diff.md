```diff
diff --git a/Android.bp b/Android.bp
index 39bd5a1..5c6cae0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,117 +1,179 @@
+// Copyright (c) 2017-2023 Intel Corporation
+//
+// Permission is hereby granted, free of charge, to any person obtaining a copy
+// of this software and associated documentation files (the "Software"), to deal
+// in the Software without restriction, including without limitation the rights
+// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+// copies of the Software, and to permit persons to whom the Software is
+// furnished to do so, subject to the following conditions:
+//
+// The above copyright notice and this permission notice shall be included in all
+// copies or substantial portions of the Software.
+//
+// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
+// SOFTWARE.
+
 package {
-    default_applicable_licenses: ["external_intel_license"],
+    default_applicable_licenses: ["external_intel_libva_license"],
 }
 
 license {
-    name: "external_intel_license",
+    name: "external_intel_libva_license",
     visibility: [":__subpackages__"],
     license_text: [
-        "LICENSE",
+        "COPYING",
     ],
 }
 
-cc_genrule {
-    name: "libva-gen-version",
+sh_binary_host {
+    name: "libva_gen_version_script",
+    src: "build/gen_version.sh",
+}
+
+genrule {
+    name: "libva_gen_headers",
     srcs: [
         "configure.ac",
         "va/va_version.h.in",
+        "va/drm/va_drm.h",
     ],
-    out: ["va/va_version.h"],
-    tool_files: ["build/gen_version.sh"],
-    cmd: "$(location build/gen_version.sh) --configure_ac $(in) > $(out)",
-    proprietary: true,
+    tools: [
+        "libva_gen_version_script",
+    ],
+    out: [
+        "va/va_version.h",
+        "va/va_drm.h",
+    ],
+    cmd: "$(location libva_gen_version_script) " +
+        "$$(dirname $(location configure.ac)) " +
+        "$(location va/va_version.h.in) > $(location va/va_version.h);" +
+        "cp $(location va/drm/va_drm.h) $(location va/va_drm.h)",
 }
 
-cc_library_shared {
-    name: "libva",
-    srcs: [
-        "va/va.c",
-        "va/va_trace.c",
-        "va/va_str.c",
-        "va/drm/va_drm.c",
-        "va/drm/va_drm_auth.c",
-        "va/drm/va_drm_utils.c",
+cc_library_headers {
+    name: "libva_headers",
+
+    export_include_dirs: [
+        ".",
+        "va",
+        "va/drm",
     ],
+
     generated_headers: [
-        "libva-gen-version",
+        "libva_gen_headers",
     ],
     export_generated_headers: [
-        "libva-gen-version",
-    ],
-    cflags: [
-        "-Wno-sign-compare",
-        "-Wno-missing-field-initializers",
-        "-Wno-unused-parameter",
-        "-DLOG_TAG=\"libva\"",
-        "-DSYSCONFDIR=\"/vendor/etc\"",
+        "libva_gen_headers",
     ],
-    multilib: {
-        lib32: {
-            cflags: [
-                "-DVA_DRIVERS_PATH=\"/vendor/lib/dri\"",
-            ],
-        },
-        lib64: {
-            cflags: [
-                "-DVA_DRIVERS_PATH=\"/vendor/lib64/dri\"",
-            ],
+
+    vendor: true,
+    enabled: false,
+    arch: {
+        x86_64: {
+            enabled: true,
         },
     },
-    local_include_dirs: [
-        "va",
-    ],
-    export_include_dirs: ["headers"],
+}
+
+cc_library_shared {
+    name: "libva",
+
     shared_libs: [
         "libdl",
         "libdrm",
         "libcutils",
         "liblog",
     ],
-    header_libs: [
-        "libutils_headers",
+
+    local_include_dirs: [
+        "va",
     ],
-    proprietary: true,
-}
 
-cc_library_headers {
-    name: "libva-headers",
-    proprietary: true,
-    export_include_dirs: ["headers"],
     generated_headers: [
-        "libva-gen-version",
+        "libva_gen_headers",
     ],
     export_generated_headers: [
-        "libva-gen-version",
+        "libva_gen_headers",
+    ],
+    export_include_dirs: [
+        ".",
+    ],
+
+    header_libs: [
+        "liblog_headers",
     ],
-}
 
-cc_library_shared {
-    name: "libva-android",
     srcs: [
-        "va/android/va_android.cpp",
+        "va/va.c",
+        "va/va_trace.c",
+        "va/va_str.c",
+        "va/drm/va_drm.c",
+        "va/drm/va_drm_auth.c",
         "va/drm/va_drm_utils.c",
     ],
+
     cflags: [
-        "-Wno-sign-compare",
-        "-Wno-missing-field-initializers",
-        "-Wno-unused-parameter",
-        "-DLOG_TAG=\"libva-android\"",
-    ],
-    local_include_dirs: [
-        "va",
-        "va/drm",
+        "-Werror",
+        "-Winvalid-pch",
+        "-DSYSCONFDIR=\"/vendor/etc\"",
+        "-DLOG_TAG=\"libva\"",
     ],
+
+    arch: {
+        x86_64: {
+            cflags: ["-DVA_DRIVERS_PATH=\"/vendor/lib64\""],
+            enabled: true,
+        },
+    },
+
+    vendor: true,
+    enabled: false,
+}
+
+cc_library_shared {
+    name: "libva-android",
+
     shared_libs: [
         "libva",
         "libdrm",
         "liblog",
     ],
-    static_libs: [
-        "libarect",
+
+    local_include_dirs: [
+        "va",
+        "va/drm",
     ],
-    header_libs: [
-        "libnativebase_headers",
-        "libutils_headers",
+    generated_headers: [
+        "libva_gen_headers",
+    ],
+    export_generated_headers: [
+        "libva_gen_headers",
+    ],
+    export_include_dirs: [
+        ".",
+    ],
+
+    srcs: [
+        "va/android/va_android.cpp",
+        "va/drm/va_drm_utils.c",
     ],
-    proprietary: true,
+
+    cflags: [
+        "-Werror",
+        "-Winvalid-pch",
+        "-DLOG_TAG=\"libva-android\"",
+    ],
+
+    vendor: true,
+    enabled: false,
+    arch: {
+        x86_64: {
+            enabled: true,
+        },
+    },
 }
diff --git a/Android.mk.disabled b/Android.mk.disabled
deleted file mode 100644
index 5cbb9d8..0000000
--- a/Android.mk.disabled
+++ /dev/null
@@ -1,4 +0,0 @@
-# Recursive call sub-folder Android.mk
-#
-
- include $(call all-subdir-makefiles)
diff --git a/METADATA b/METADATA
index 3d6d69b..3885cec 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
-name: "libva"
-description:
-    "Libva is an implementation for VA-API (Video Acceleration API) "
-    " "
-    "VA-API is an open-source library and API specification, which provides "
-    "access to graphics hardware acceleration capabilities for video "
-    "processing. It consists of a main library and driver-specific acceleration "
-    "backends for each supported hardware vendor."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/libva
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "libva"
+description: "Libva is an implementation for VA-API (Video Acceleration API)  VA-API is an open-source library and API specification, which provides access to graphics hardware acceleration capabilities for video processing. It consists of a main library and driver-specific acceleration backends for each supported hardware vendor."
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 10
+    day: 14
+  }
   identifier {
     type: "Git"
     value: "https://github.com/intel/libva"
+    version: "2.22.0"
     primary_source: true
-    version: "2.21.0"
   }
-  version: "2.21.0"
-  last_upgrade_date { year: 2024 month: 7 day: 11 }
-  license_type: NOTICE
 }
diff --git a/NEWS b/NEWS
index ed5eb1e..3230e9c 100644
--- a/NEWS
+++ b/NEWS
@@ -1,6 +1,13 @@
-libva NEWS -- summary of user visible changes.  2024-03-12
+libva NEWS -- summary of user visible changes.  2024-06-20
 Copyright (C) 2009-2024 Intel Corporation
 
+version 2.22.0 - 20.Jun.2024
+* va:Add VVC decode LibVA interface.
+* va: fix --version-script detection for lld >= 17
+* wayland: add support for linux-dmabuf
+* meson:remove autogen.sh from the meson script
+* trace: Add bit_depth capturing in trace log
+
 version 2.21.0 - 12.Mar.2024
 * va: Add allow_content_tools and force_intger_mv to AV1 enc
 * va: add VASurfaceAttribAlignmentSize
diff --git a/build/gen_version.sh b/build/gen_version.sh
old mode 100755
new mode 100644
index 4c7204b..8864f7d
--- a/build/gen_version.sh
+++ b/build/gen_version.sh
@@ -26,25 +26,17 @@ libva_topdir="$1"
 version_h_in="$2"
 
 parse_configure_ac() {
-    sed -n "/^m4_define.*${1}.*\[\([0-9]*\)\].*/s//\1/p" ${2}
+    sed -n "/^m4_define.*${1}.*\[\([0-9]*\)\].*/s//\1/p" ${libva_topdir}/configure.ac
 }
 
 parse_configure() {
     sed -n "/^${1}=\([0-9]*\)/s//\1/p" ${libva_topdir}/configure
 }
 
-if [ "$1" = "--configure_ac" ]; then
-    # $2 specifies the path to configure.ac, $3 the path to version.h.in
-    libva_topdir="///"
-    version_h_in="$3"
-    va_api_major_version=`parse_configure_ac va_api_major_version $2`
-    va_api_minor_version=`parse_configure_ac va_api_minor_version $2`
-    va_api_micro_version=`parse_configure_ac va_api_micro_version $2`
-elif test -f "${libva_topdir}/configure.ac"; then
-    CONFIGURE_AC_PATH=${libva_topdir}/configure.ac
-    va_api_major_version=`parse_configure_ac va_api_major_version $CONFIGURE_AC_PATH`
-    va_api_minor_version=`parse_configure_ac va_api_minor_version $CONFIGURE_AC_PATH`
-    va_api_micro_version=`parse_configure_ac va_api_micro_version $CONFIGURE_AC_PATH`
+if test -f "${libva_topdir}/configure.ac"; then
+    va_api_major_version=`parse_configure_ac va_api_major_version`
+    va_api_minor_version=`parse_configure_ac va_api_minor_version`
+    va_api_micro_version=`parse_configure_ac va_api_micro_version`
 elif test -f "${libva_topdir}/configure"; then
     va_api_major_version=`parse_configure VA_API_MAJOR_VERSION`
     va_api_minor_version=`parse_configure VA_API_MINOR_VERSION`
diff --git a/configure.ac b/configure.ac
index 53627ad..0bf9b1c 100644
--- a/configure.ac
+++ b/configure.ac
@@ -27,7 +27,7 @@
 # - reset micro version to zero when minor version is incremented
 # - reset minor version to zero when major version is incremented
 m4_define([va_api_major_version], [1])
-m4_define([va_api_minor_version], [21])
+m4_define([va_api_minor_version], [22])
 m4_define([va_api_micro_version], [0])
 
 m4_define([va_api_version],
@@ -75,7 +75,8 @@ m4_define([libva_lt_age],
           [m4_eval(libva_binary_age - libva_interface_age)])
 
 # libdrm minimun version requirement
-m4_define([libdrm_version], [2.4.60])
+# 2.4.75 for drmGetDevices2
+m4_define([libdrm_version], [2.4.75])
 
 # Wayland minimum version number
 # 1.11.0 for wl_proxy_create_wrapper
diff --git a/headers/va b/headers/va
deleted file mode 120000
index b74099e..0000000
--- a/headers/va
+++ /dev/null
@@ -1 +0,0 @@
-../va
\ No newline at end of file
diff --git a/meson.build b/meson.build
index ac145d6..9b71bf7 100644
--- a/meson.build
+++ b/meson.build
@@ -7,7 +7,7 @@
 # - reset micro version to zero when VA-API major or minor version is changed
 project(
   'libva', 'c',
-  version : '2.21.0',
+  version : '2.22.0',
   meson_version : '>= 0.53.0',
   default_options : [ 'warning_level=1',
                       'buildtype=debugoptimized' ])
@@ -19,7 +19,7 @@ project(
 # - reset micro version to zero when minor version is incremented
 # - reset minor version to zero when major version is incremented
 va_api_major_version = 1
-va_api_minor_version = 21
+va_api_minor_version = 22
 va_api_micro_version = 0
 
 va_api_version = '@0@.@1@.@2@'.format(va_api_major_version,
@@ -85,7 +85,7 @@ cc = meson.get_compiler('c')
 dl_dep = cc.find_library('dl', required : false)
 
 WITH_DRM = not get_option('disable_drm') and (host_machine.system() != 'windows')
-libdrm_dep = dependency('libdrm', version : '>= 2.4.60', required : (host_machine.system() != 'windows'))
+libdrm_dep = dependency('libdrm', version : '>= 2.4.75', required : (host_machine.system() != 'windows'))
 
 WITH_X11 = false
 if get_option('with_x11') != 'no'
@@ -158,4 +158,3 @@ if get_option('enable_docs') and doxygen.found()
   subdir('doc')
 endif
 
-meson.add_dist_script('./autogen.sh')
diff --git a/va/Android.mk.disabled b/va/Android.mk.disabled
deleted file mode 100644
index a8f05f1..0000000
--- a/va/Android.mk.disabled
+++ /dev/null
@@ -1,102 +0,0 @@
-# Copyright (c) 2007 Intel Corporation. All Rights Reserved.
-#
-# Permission is hereby granted, free of charge, to any person obtaining a
-# copy of this software and associated documentation files (the
-# "Software"), to deal in the Software without restriction, including
-# without limitation the rights to use, copy, modify, merge, publish,
-# distribute, sub license, and/or sell copies of the Software, and to
-# permit persons to whom the Software is furnished to do so, subject to
-# the following conditions:
-# 
-# The above copyright notice and this permission notice (including the
-# next paragraph) shall be included in all copies or substantial portions
-# of the Software.
-# 
-# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
-# IN NO EVENT SHALL PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR
-# ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
-# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
-# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
-
-# For libva
-# =====================================================
-
-LOCAL_PATH:= $(call my-dir)
-
-LIBVA_DRIVERS_PATH_32 := /vendor/lib/dri
-LIBVA_DRIVERS_PATH_64 := /vendor/lib64/dri
-
-include $(CLEAR_VARS)
-
-#LIBVA_MINOR_VERSION := 31
-#LIBVA_MAJOR_VERSION := 0
-
-IGNORED_WARNNING = \
-	-Wno-sign-compare \
-	-Wno-missing-field-initializers \
-	-Wno-unused-parameter \
-
-LOCAL_SRC_FILES := \
-	va.c \
-	va_trace.c \
-	va_str.c
-
-LOCAL_CFLAGS_32 += \
-	-DVA_DRIVERS_PATH="\"$(LIBVA_DRIVERS_PATH_32)\"" \
-
-LOCAL_CFLAGS_64 += \
-	-DVA_DRIVERS_PATH="\"$(LIBVA_DRIVERS_PATH_64)\"" \
-
-LOCAL_CFLAGS := \
-	$(IGNORED_WARNNING) \
-	-DLOG_TAG=\"libva\"
-
-LOCAL_C_INCLUDES := $(LOCAL_PATH)/..
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE := libva
-LOCAL_MODULE_CLASS := SHARED_LIBRARIES
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_SHARED_LIBRARIES := libdl libdrm libcutils liblog
-
-intermediates := $(call local-generated-sources-dir)
-
-LOCAL_EXPORT_C_INCLUDE_DIRS := \
-	$(intermediates) \
-	$(LOCAL_C_INCLUDES)
-
-GEN := $(intermediates)/va/va_version.h
-$(GEN): SCRIPT := $(LOCAL_PATH)/../build/gen_version.sh
-$(GEN): PRIVATE_CUSTOM_TOOL = sh $(SCRIPT) $(<D)/.. $< > $@
-$(GEN): $(intermediates)/va/%.h : $(LOCAL_PATH)/%.h.in $(LOCAL_PATH)/../configure.ac
-	$(transform-generated-source)
-LOCAL_GENERATED_SOURCES += $(GEN) 
-
-include $(BUILD_SHARED_LIBRARY)
-
-# For libva-android
-# =====================================================
-
-include $(CLEAR_VARS)
-
-LOCAL_SRC_FILES := \
-	android/va_android.cpp \
-	drm/va_drm_utils.c
-
-LOCAL_CFLAGS += \
-	-DLOG_TAG=\"libva-android\" \
-	$(IGNORED_WARNNING)
-
-LOCAL_C_INCLUDES += \
-	$(LOCAL_PATH)/drm
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE := libva-android
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_SHARED_LIBRARIES := libva libdrm liblog
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/va/Makefile.am b/va/Makefile.am
index 8d16d42..37a8423 100644
--- a/va/Makefile.am
+++ b/va/Makefile.am
@@ -48,6 +48,7 @@ libva_source_h = \
 	va_dec_jpeg.h		\
 	va_dec_vp8.h		\
 	va_dec_vp9.h		\
+	va_dec_vvc.h		\
 	va_drmcommon.h		\
 	va_egl.h		\
 	va_enc_hevc.h		\
diff --git a/va/meson.build b/va/meson.build
index 5e969eb..6005cf8 100644
--- a/va/meson.build
+++ b/va/meson.build
@@ -27,6 +27,7 @@ libva_headers = [
   'va_dec_vp8.h',
   'va_dec_vp9.h',
   'va_dec_av1.h',
+  'va_dec_vvc.h',
   'va_drmcommon.h',
   'va_egl.h',
   'va_enc_hevc.h',
@@ -60,7 +61,7 @@ libva_sym_arg = '-Wl,-version-script,' + '@0@/@1@'.format(meson.current_source_d
 
 libva_link_args = []
 libva_link_depends = []
-if cc.links('', name: '-Wl,--version-script', args: ['-shared', libva_sym_arg])
+if cc.links('void vaCreateSurfaces_0_32_0(void) {} void vaCreateSurfaces() {}', name: '-Wl,--version-script', args: ['-shared', libva_sym_arg])
   libva_link_args = libva_sym_arg
   libva_link_depends = libva_sym
 endif
@@ -228,6 +229,7 @@ endif
 if WITH_WAYLAND
   libva_wayland_sources = [
     'wayland/va_wayland.c',
+    'wayland/va_wayland_linux_dmabuf.c',
     'wayland/va_wayland_drm.c',
     'wayland/va_wayland_emgd.c',
     'drm/va_drm_utils.c',
@@ -241,24 +243,31 @@ if WITH_WAYLAND
   libva_headers_subproject += libva_wayland_headers
 
   libva_wayland_headers_priv = [
+    'wayland/va_wayland_linux_dmabuf.h',
     'wayland/va_wayland_drm.h',
     'wayland/va_wayland_emgd.h',
     'wayland/va_wayland_private.h',
   ]
 
-  protocol_files = [
-    custom_target(
-      'wayland-drm-client-protocol.c',
-      output : 'wayland-drm-client-protocol.c',
-      input : 'wayland/wayland-drm.xml',
-      command : [wl_scanner, 'private-code', '@INPUT@', '@OUTPUT@']),
-
-    custom_target(
-      'wayland-drm-client-protocol.h',
-      output : 'wayland-drm-client-protocol.h',
-      input : 'wayland/wayland-drm.xml',
+  # XXX: grab linux-dmabuf-v1.xml from wayland-protocols
+  protocols = {
+    'wayland-drm': 'wayland/wayland-drm.xml',
+    'linux-dmabuf-v1': 'wayland/linux-dmabuf-v1.xml',
+  }
+
+  protocol_files = []
+  foreach name, xml : protocols
+    protocol_files += custom_target(
+      name + '-client-protocol.c',
+      output : name + '-client-protocol.c',
+      input : xml,
+      command : [wl_scanner, 'private-code', '@INPUT@', '@OUTPUT@'])
+    protocol_files += custom_target(
+      name + '-client-protocol.h',
+      output : name + '-client-protocol.h',
+      input : xml,
       command : [wl_scanner, 'client-header', '@INPUT@', '@OUTPUT@'])
-  ]
+  endforeach
 
   install_headers(libva_wayland_headers, subdir : 'va')
 
diff --git a/va/va.h b/va/va.h
index d349704..1d99fa6 100644
--- a/va/va.h
+++ b/va/va.h
@@ -120,12 +120,13 @@ extern "C" {
  *  - \ref api_enc_vp8
  *  - \ref api_enc_vp9
  *  - \ref api_enc_av1
- * - Decoder (HEVC, JPEG, VP8, VP9, AV1)
+ * - Decoder (HEVC, JPEG, VP8, VP9, AV1, VVC)
  *      - \ref api_dec_hevc
  *      - \ref api_dec_jpeg
  *      - \ref api_dec_vp8
  *      - \ref api_dec_vp9
  *      - \ref api_dec_av1
+ *      - \ref api_dec_vvc
  * - \ref api_vpp
  * - \ref api_prot
  * - FEI (H264, HEVC)
@@ -538,7 +539,9 @@ typedef enum {
     VAProfileHEVCSccMain444_10          = 34,
     /** \brief Profile ID used for protected video playback. */
     VAProfileProtected                  = 35,
-    VAProfileH264High10                 = 36
+    VAProfileH264High10                 = 36,
+    VAProfileVVCMain10                  = 37,
+    VAProfileVVCMultilayerMain10        = 38
 } VAProfile;
 
 /**
@@ -2149,6 +2152,37 @@ typedef enum {
      */
     VAEncDeltaQpPerBlockBufferType   = 61,
 
+    /**
+     * \brief VVC ALF data buffer
+     *
+     * Refer to \c VAAlfDataVVC
+     */
+    VAAlfBufferType = 62,
+    /**
+     * \brief VVC LMCS data buffer
+     *
+     * Refer to \c VALmcsDataVVC
+     */
+    VALmcsBufferType = 63,
+    /**
+     * \brief VVC SubPic data buffer
+     *
+     * Refer to \c VASubPicVVC
+     */
+    VASubPicBufferType = 64,
+    /**
+     * \brief VVC Tile Dimension data buffer
+     *
+     * Data buffer of tile widths and heights, with each element formatted as uint16_t
+     */
+    VATileBufferType = 65,
+    /**
+     * \brief VVC Slice Structure data buffer
+     *
+     * Refer to \c VASliceStructVVC
+     */
+    VASliceStructBufferType = 66,
+
     VABufferTypeMax
 } VABufferType;
 
@@ -5283,6 +5317,43 @@ typedef struct _VAPictureHEVC {
  */
 #define VA_PICTURE_HEVC_RPS_LT_CURR             0x00000040
 
+/****************************
+ * VVC data structures
+ ****************************/
+/**
+ * \brief Description of picture properties of those in DPB surfaces.
+ *
+ * Only progressive scan is supported, each surface contains one whole
+ * frame picture.
+ */
+
+typedef struct _VAPictureVVC {
+    /** \brief reconstructed picture buffer surface index
+     * invalid when taking value VA_INVALID_SURFACE.
+     */
+    VASurfaceID             picture_id;
+
+    /** \brief picture order count. */
+    int32_t                 pic_order_cnt;
+
+    /* described below */
+    uint32_t                flags;
+
+    /** \brief Reserved bytes for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_LOW];
+} VAPictureVVC;
+
+/* flags in VAPictureVVC could be OR of the following */
+#define VA_PICTURE_VVC_INVALID                  0x00000001
+/** \brief Long term reference picture */
+#define VA_PICTURE_VVC_LONG_TERM_REFERENCE      0x00000002
+/** \brief Unavailable reference picture
+ * This flag indicates the situation that the process of
+ * "generating unavailable reference pictures" (spec section 8.3.4)
+ * is required.
+ */
+#define VA_PICTURE_VVC_UNAVAILABLE_REFERENCE    0x00000004
+
 typedef enum {
     VACopyObjectSurface = 0,
     VACopyObjectBuffer  = 1,
@@ -5328,6 +5399,7 @@ VAStatus vaCopy(VADisplay dpy, VACopyObject * dst, VACopyObject * src, VACopyOpt
 #include <va/va_dec_vp8.h>
 #include <va/va_dec_vp9.h>
 #include <va/va_dec_av1.h>
+#include <va/va_dec_vvc.h>
 #include <va/va_enc_hevc.h>
 #include <va/va_fei_hevc.h>
 #include <va/va_enc_h264.h>
diff --git a/va/va_dec_vvc.h b/va/va_dec_vvc.h
new file mode 100644
index 0000000..bbd4039
--- /dev/null
+++ b/va/va_dec_vvc.h
@@ -0,0 +1,688 @@
+/*
+ * Copyright (c) 2024 Intel Corporation. All Rights Reserved.
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the
+ * "Software"), to deal in the Software without restriction, including
+ * without limitation the rights to use, copy, modify, merge, publish,
+ * distribute, sub license, and/or sell copies of the Software, and to
+ * permit persons to whom the Software is furnished to do so, subject to
+ * the following conditions:
+ *
+ * The above copyright notice and this permission notice (including the
+ * next paragraph) shall be included in all copies or substantial portions
+ * of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+ * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
+ * IN NO EVENT SHALL INTEL AND/OR ITS SUPPLIERS BE LIABLE FOR
+ * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+/**
+ * \file va_dec_vvc.h
+ * \brief The VVC decoding API
+ *
+ * This file contains the \ref api_dec_vvc "VVC decoding API".
+ */
+
+#ifndef VA_DEC_VVC_H
+#define VA_DEC_VVC_H
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * \defgroup api_dec_vvc VVC decoding API
+ *
+ * This VVC decoding API supports Main 10 profile and Multilayer Main 10 profile.
+ * And it supports only long slice format.
+ *
+ * @{
+ */
+
+/**
+ * \brief Weighted Prediction Parameters.
+ */
+typedef struct _VAWeightedPredInfo {
+    /** \brief Weighted Prediction parameters.
+     *  All the parameters except reserved bytes are VVC syntax.
+     */
+    uint8_t                 luma_log2_weight_denom;
+    int8_t                  delta_chroma_log2_weight_denom;
+    uint8_t                 num_l0_weights;
+    uint8_t                 luma_weight_l0_flag[15];
+    uint8_t                 chroma_weight_l0_flag[15];
+    int8_t                  delta_luma_weight_l0[15];
+    int8_t                  luma_offset_l0[15];
+    int8_t                  delta_chroma_weight_l0[15][2];
+    int16_t                 delta_chroma_offset_l0[15][2];
+    uint8_t                 num_l1_weights;
+    uint8_t                 luma_weight_l1_flag[15];
+    uint8_t                 chroma_weight_l1_flag[15];
+    int8_t                  delta_luma_weight_l1[15];
+    int8_t                  luma_offset_l1[15];
+    int8_t                  delta_chroma_weight_l1[15][2];
+    int16_t                 delta_chroma_offset_l1[15][2];
+    /** \brief Reserved for future use, must be zero */
+    uint16_t                reserved16b;
+    uint32_t                reserved32b;
+} VAWeightedPredInfo;
+
+/**
+ * \brief VVC Decoding Picture Parameter Buffer Structure
+ *
+ * This structure conveys picture level parameters and should be sent once
+ * per frame.
+ *
+ * Host decoder is required to send in a buffer of VAPictureParameterBufferVVC
+ * as the first va buffer for each frame.
+ *
+ */
+typedef struct  _VAPictureParameterBufferVVC {
+    /** \brief buffer description of decoded current picture
+     */
+    VAPictureVVC            CurrPic;
+    /** \brief buffer description of reference frames in DPB */
+    VAPictureVVC            ReferenceFrames[15];
+    /** \brief picture width, shall be integer multiple of Max(8, MinCbSizeY). */
+    uint16_t                pps_pic_width_in_luma_samples;
+    /** \brief picture height, shall be integer multiple of Max(8, MinCbSizeY). */
+    uint16_t                pps_pic_height_in_luma_samples;
+
+    /** \brief sequence level parameters.
+     *  All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    uint16_t                sps_num_subpics_minus1;
+    uint8_t                 sps_chroma_format_idc;
+    uint8_t                 sps_bitdepth_minus8;
+    uint8_t                 sps_log2_ctu_size_minus5;
+    uint8_t                 sps_log2_min_luma_coding_block_size_minus2;
+    uint8_t                 sps_log2_transform_skip_max_size_minus2;
+    /** \brief chroma QP mapping table.
+     *  ChromaQpTable[][] corresponds to VVC spec variable with the same name.
+     *  It is derived according to formula (57) in VVC spec section 7.4.3.4.
+     */
+    int8_t                  ChromaQpTable[3][111];
+    uint8_t                 sps_six_minus_max_num_merge_cand;
+    uint8_t                 sps_five_minus_max_num_subblock_merge_cand;
+    uint8_t                 sps_max_num_merge_cand_minus_max_num_gpm_cand;
+    uint8_t                 sps_log2_parallel_merge_level_minus2;
+    uint8_t                 sps_min_qp_prime_ts;
+    uint8_t                 sps_six_minus_max_num_ibc_merge_cand;
+    uint8_t                 sps_num_ladf_intervals_minus2;
+    int8_t                  sps_ladf_lowest_interval_qp_offset;
+    int8_t                  sps_ladf_qp_offset[4];
+    uint16_t                sps_ladf_delta_threshold_minus1[4];
+    /** \brief Reserved for future use, must be zero */
+    uint32_t                reserved32b01[VA_PADDING_LOW - 2];
+
+    union {
+        struct {
+            uint64_t        sps_subpic_info_present_flag                                    : 1;
+            uint64_t        sps_independent_subpics_flag                                    : 1;
+            uint64_t        sps_subpic_same_size_flag                                       : 1;
+            uint64_t        sps_entropy_coding_sync_enabled_flag                            : 1;
+            uint64_t        sps_qtbtt_dual_tree_intra_flag                                  : 1;
+            uint64_t        sps_max_luma_transform_size_64_flag                             : 1;
+            uint64_t        sps_transform_skip_enabled_flag                                 : 1;
+            uint64_t        sps_bdpcm_enabled_flag                                          : 1;
+            uint64_t        sps_mts_enabled_flag                                            : 1;
+            uint64_t        sps_explicit_mts_intra_enabled_flag                             : 1;
+            uint64_t        sps_explicit_mts_inter_enabled_flag                             : 1;
+            uint64_t        sps_lfnst_enabled_flag                                          : 1;
+            uint64_t        sps_joint_cbcr_enabled_flag                                     : 1;
+            uint64_t        sps_same_qp_table_for_chroma_flag                               : 1;
+            uint64_t        sps_sao_enabled_flag                                            : 1;
+            uint64_t        sps_alf_enabled_flag                                            : 1;
+            uint64_t        sps_ccalf_enabled_flag                                          : 1;
+            uint64_t        sps_lmcs_enabled_flag                                           : 1;
+            uint64_t        sps_sbtmvp_enabled_flag                                         : 1;
+            uint64_t        sps_amvr_enabled_flag                                           : 1;
+            uint64_t        sps_smvd_enabled_flag                                           : 1;
+            uint64_t        sps_mmvd_enabled_flag                                           : 1;
+            uint64_t        sps_sbt_enabled_flag                                            : 1;
+            uint64_t        sps_affine_enabled_flag                                         : 1;
+            uint64_t        sps_6param_affine_enabled_flag                                  : 1;
+            uint64_t        sps_affine_amvr_enabled_flag                                    : 1;
+            uint64_t        sps_affine_prof_enabled_flag                                    : 1;
+            uint64_t        sps_bcw_enabled_flag                                            : 1;
+            uint64_t        sps_ciip_enabled_flag                                           : 1;
+            uint64_t        sps_gpm_enabled_flag                                            : 1;
+            uint64_t        sps_isp_enabled_flag                                            : 1;
+            uint64_t        sps_mrl_enabled_flag                                            : 1;
+            uint64_t        sps_mip_enabled_flag                                            : 1;
+            uint64_t        sps_cclm_enabled_flag                                           : 1;
+            uint64_t        sps_chroma_horizontal_collocated_flag                           : 1;
+            uint64_t        sps_chroma_vertical_collocated_flag                             : 1;
+            uint64_t        sps_palette_enabled_flag                                        : 1;
+            uint64_t        sps_act_enabled_flag                                            : 1;
+            uint64_t        sps_ibc_enabled_flag                                            : 1;
+            uint64_t        sps_ladf_enabled_flag                                           : 1;
+            uint64_t        sps_explicit_scaling_list_enabled_flag                          : 1;
+            uint64_t        sps_scaling_matrix_for_lfnst_disabled_flag                      : 1;
+            uint64_t        sps_scaling_matrix_for_alternative_colour_space_disabled_flag   : 1;
+            uint64_t        sps_scaling_matrix_designated_colour_space_flag                 : 1;
+            uint64_t        sps_virtual_boundaries_enabled_flag                             : 1;
+            uint64_t        sps_virtual_boundaries_present_flag                             : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint64_t        reserved                                                        : 18;
+        } bits;
+        uint64_t            value;
+    } sps_flags;
+
+    /** \brief picture level parameters.
+     *  All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    /** \brief number of vertical virtual boundaries on the picture.
+     *  NumVerVirtualBoundaries corresponds to VVC spec variable with the same name.
+     *  It is derived according to formula (78) in VVC spec section 7.4.3.8.
+     */
+    uint8_t                 NumVerVirtualBoundaries;
+    /** \brief number of horizontal virtual boundaries on the picture.
+     *  NumHorVirtualBoundaries corresponds to VVC spec variable with the same name.
+     *  It is derived according to formula (80) in VVC spec section 7.4.3.8.
+     */
+    uint8_t                 NumHorVirtualBoundaries;
+    /** \brief location of the vertical virtual boundary in units of luma samples.
+     *  VirtualBoundaryPosX[] corresponds to VVC spec variable with the same name.
+     *  It is derived according to formula (79) in VVC spec section 7.4.3.8.
+     */
+    uint16_t                VirtualBoundaryPosX[3];
+    /** \brief location of the horizontal virtual boundary in units of luma samples.
+     *  VirtualBoundaryPosY[] corresponds to VVC spec variable with the same name.
+     *  It is derived according to formula (81) in VVC spec section 7.4.3.8.
+     */
+    uint16_t                VirtualBoundaryPosY[3];
+
+    int32_t                 pps_scaling_win_left_offset;
+    int32_t                 pps_scaling_win_right_offset;
+    int32_t                 pps_scaling_win_top_offset;
+    int32_t                 pps_scaling_win_bottom_offset;
+
+    int8_t                  pps_num_exp_tile_columns_minus1;
+    uint16_t                pps_num_exp_tile_rows_minus1;
+    uint16_t                pps_num_slices_in_pic_minus1;
+    uint16_t                pps_pic_width_minus_wraparound_offset;
+    int8_t                  pps_cb_qp_offset;
+    int8_t                  pps_cr_qp_offset;
+    int8_t                  pps_joint_cbcr_qp_offset_value;
+    uint8_t                 pps_chroma_qp_offset_list_len_minus1;
+    int8_t                  pps_cb_qp_offset_list[6];
+    int8_t                  pps_cr_qp_offset_list[6];
+    int8_t                  pps_joint_cbcr_qp_offset_list[6];
+    /** \brief Reserved for future use, must be zero */
+    uint16_t                reserved16b01;
+    uint32_t                reserved32b02[VA_PADDING_LOW - 2];
+
+    union {
+        struct {
+            uint32_t        pps_loop_filter_across_tiles_enabled_flag                       : 1;
+            uint32_t        pps_rect_slice_flag                                             : 1;
+            uint32_t        pps_single_slice_per_subpic_flag                                : 1;
+            uint32_t        pps_loop_filter_across_slices_enabled_flag                      : 1;
+            uint32_t        pps_weighted_pred_flag                                          : 1;
+            uint32_t        pps_weighted_bipred_flag                                        : 1;
+            uint32_t        pps_ref_wraparound_enabled_flag                                 : 1;
+            uint32_t        pps_cu_qp_delta_enabled_flag                                    : 1;
+            uint32_t        pps_cu_chroma_qp_offset_list_enabled_flag                       : 1;
+            uint32_t        pps_deblocking_filter_override_enabled_flag                     : 1;
+            uint32_t        pps_deblocking_filter_disabled_flag                             : 1;
+            uint32_t        pps_dbf_info_in_ph_flag                                         : 1;
+            uint32_t        pps_sao_info_in_ph_flag                                         : 1;
+            uint32_t        pps_alf_info_in_ph_flag                                         : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint32_t        reserved                                                        : 18;
+        } bits;
+        uint32_t            value;
+    } pps_flags;
+
+    /** \brief picture header parameters.
+     *  All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    uint8_t                 ph_lmcs_aps_id;
+    uint8_t                 ph_scaling_list_aps_id;
+    uint8_t                 ph_log2_diff_min_qt_min_cb_intra_slice_luma;
+    uint8_t                 ph_max_mtt_hierarchy_depth_intra_slice_luma;
+    uint8_t                 ph_log2_diff_max_bt_min_qt_intra_slice_luma;
+    uint8_t                 ph_log2_diff_max_tt_min_qt_intra_slice_luma;
+    uint8_t                 ph_log2_diff_min_qt_min_cb_intra_slice_chroma;
+    uint8_t                 ph_max_mtt_hierarchy_depth_intra_slice_chroma;
+    uint8_t                 ph_log2_diff_max_bt_min_qt_intra_slice_chroma;
+    uint8_t                 ph_log2_diff_max_tt_min_qt_intra_slice_chroma;
+    uint8_t                 ph_cu_qp_delta_subdiv_intra_slice;
+    uint8_t                 ph_cu_chroma_qp_offset_subdiv_intra_slice;
+    uint8_t                 ph_log2_diff_min_qt_min_cb_inter_slice;
+    uint8_t                 ph_max_mtt_hierarchy_depth_inter_slice;
+    uint8_t                 ph_log2_diff_max_bt_min_qt_inter_slice;
+    uint8_t                 ph_log2_diff_max_tt_min_qt_inter_slice;
+    uint8_t                 ph_cu_qp_delta_subdiv_inter_slice;
+    uint8_t                 ph_cu_chroma_qp_offset_subdiv_inter_slice;
+    /** \brief Reserved for future use, must be zero */
+    uint16_t                reserved16b02;
+    uint32_t                reserved32b03[VA_PADDING_LOW - 2];
+
+    union {
+        struct {
+            uint32_t        ph_non_ref_pic_flag                                             : 1;
+            uint32_t        ph_alf_enabled_flag                                             : 1;
+            uint32_t        ph_alf_cb_enabled_flag                                          : 1;
+            uint32_t        ph_alf_cr_enabled_flag                                          : 1;
+            uint32_t        ph_alf_cc_cb_enabled_flag                                       : 1;
+            uint32_t        ph_alf_cc_cr_enabled_flag                                       : 1;
+            uint32_t        ph_lmcs_enabled_flag                                            : 1;
+            uint32_t        ph_chroma_residual_scale_flag                                   : 1;
+            uint32_t        ph_explicit_scaling_list_enabled_flag                           : 1;
+            uint32_t        ph_virtual_boundaries_present_flag                              : 1;
+            uint32_t        ph_temporal_mvp_enabled_flag                                    : 1;
+            uint32_t        ph_mmvd_fullpel_only_flag                                       : 1;
+            uint32_t        ph_mvd_l1_zero_flag                                             : 1;
+            uint32_t        ph_bdof_disabled_flag                                           : 1;
+            uint32_t        ph_dmvr_disabled_flag                                           : 1;
+            uint32_t        ph_prof_disabled_flag                                           : 1;
+            uint32_t        ph_joint_cbcr_sign_flag                                         : 1;
+            uint32_t        ph_sao_luma_enabled_flag                                        : 1;
+            uint32_t        ph_sao_chroma_enabled_flag                                      : 1;
+            uint32_t        ph_deblocking_filter_disabled_flag                              : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint32_t        reserved                                                        : 12;
+        } bits;
+        uint32_t            value;
+    } ph_flags;
+
+    /** \brief Reserved for future use, must be zero */
+    uint32_t                reserved32b04;
+
+    union {
+        struct {
+            /** \brief Flag to indicate if current picture is an intra picture.
+             *  Takes value 1 when all slices of current picture are intra slices.
+             *  Takes value 0 when some slices of current picture may not be
+             *  intra slices.
+             */
+            uint32_t        IntraPicFlag                                                    : 1;    // [0..1]
+            /** \brief Reserved for future use, must be zero */
+            uint32_t        reserved                                                        : 31;
+        } fields;
+        uint32_t            value;
+    } PicMiscFlags;
+
+    /** \brief Reserved bytes for future use, must be zero */
+    uint32_t                reserved32b[VA_PADDING_HIGH + 1];
+
+} VAPictureParameterBufferVVC;
+
+/**
+ * \brief VVC Slice Parameter Buffer Structure
+ *
+ * VASliceParameterBufferVVC structure should be accompanied by a
+ * slice data buffer, which holds the whole packed slice NAL unit bit stream
+ * with emulation prevention bytes not removed.
+ *
+ * This structure conveys parameters related to slice header and should
+ * be sent once per slice.
+ */
+typedef struct  _VASliceParameterBufferVVC {
+    /** @name Codec-independent Slice Parameter Buffer base. */
+
+    /**@{*/
+
+    /** \brief Number of bytes in the slice data buffer for this slice
+     * counting from and including NAL unit header.
+     */
+    uint32_t                slice_data_size;
+    /** \brief The offset to the NAL unit header for this slice */
+    uint32_t                slice_data_offset;
+    /** \brief Slice data buffer flags. See \c VA_SLICE_DATA_FLAG_XXX. */
+    uint32_t                slice_data_flag;
+    /**
+     * \brief Byte offset from NAL unit header to the beginning of slice_data().
+     *
+     * This byte offset is relative to and includes the NAL unit header
+     * and represents the number of bytes parsed in the slice_header()
+     * after the removal of any emulation prevention bytes in
+     * there. However, the slice data buffer passed to the hardware is
+     * the original bitstream, thus including any emulation prevention
+     * bytes.
+     */
+    uint32_t                slice_data_byte_offset;
+    /** \brief index into ReferenceFrames[]
+     * RefPicList[][] corresponds to VVC spec variable with the same name.
+     * Value range [0..14, 0xFF], where 0xFF indicates invalid entry.
+     */
+    uint8_t                 RefPicList[2][15];
+
+    /**
+     * \brief the subpicture ID of the subpicture that contains the slice.
+     * The value of the variable CurrSubpicIdx
+     * is derived to be such that SubpicIdVal[CurrSubpicIdx] is equal
+     * to sh_subpic_id. CurrSubpicIdx is the index of array VASubPicArrayBufferVVC.SubPicSet[].
+     * And it is the spec variable with the same name.
+     */
+    uint16_t                sh_subpic_id;
+    /* parameters below are VVC syntax or spec variables. */
+    uint16_t                sh_slice_address;
+    uint16_t                sh_num_tiles_in_slice_minus1;
+    uint8_t                 sh_slice_type;
+    uint8_t                 sh_num_alf_aps_ids_luma;
+    uint8_t                 sh_alf_aps_id_luma[7];
+    uint8_t                 sh_alf_aps_id_chroma;
+    uint8_t                 sh_alf_cc_cb_aps_id;
+    uint8_t                 sh_alf_cc_cr_aps_id;
+    /**
+     * \brief NumRefIdxActive[i] - 1 specifies the maximum reference index
+     * for RPL i that may be used to decode the slice. When NumRefIdxActive[i]
+     * is equal to 0, no reference index for RPL i is used to decode the slice.
+     * NumRefIdxActive[] corresponds to VVC spec variable with the same name.
+     * It is derived according to formula (138) in VVC spec section 7.4.8.
+     */
+    uint8_t                 NumRefIdxActive[2];
+    uint8_t                 sh_collocated_ref_idx;
+    /**
+     * \brief initial value of the QpY quantization parameter for the slice.
+     * SliceQpY corresponds to VVC spec variable with the same name.
+     * It is derived according to formula (86) in VVC spec section 7.4.3.8
+     * and formula (139) in VVC Spec section 7.4.8.
+     */
+    int8_t                  SliceQpY;
+    /* parameters below are VVC syntax. */
+    int8_t                  sh_cb_qp_offset;
+    int8_t                  sh_cr_qp_offset;
+    int8_t                  sh_joint_cbcr_qp_offset;
+    int8_t                  sh_luma_beta_offset_div2;
+    int8_t                  sh_luma_tc_offset_div2;
+    int8_t                  sh_cb_beta_offset_div2;
+    int8_t                  sh_cb_tc_offset_div2;
+    int8_t                  sh_cr_beta_offset_div2;
+    int8_t                  sh_cr_tc_offset_div2;
+    /** \brief Reserved bytes for future use, must be zero */
+    uint8_t                 reserved8b[VA_PADDING_LOW - 1];
+    uint32_t                reserved32b;
+
+    // weighted prediction info
+    VAWeightedPredInfo      WPInfo;
+
+    union {
+        struct {
+            /* flags below are VVC syntax. */
+            uint32_t        sh_alf_enabled_flag                                             : 1;
+            uint32_t        sh_alf_cb_enabled_flag                                          : 1;
+            uint32_t        sh_alf_cr_enabled_flag                                          : 1;
+            uint32_t        sh_alf_cc_cb_enabled_flag                                       : 1;
+            uint32_t        sh_alf_cc_cr_enabled_flag                                       : 1;
+            uint32_t        sh_lmcs_used_flag                                               : 1;
+            uint32_t        sh_explicit_scaling_list_used_flag                              : 1;
+            uint32_t        sh_cabac_init_flag                                              : 1;
+            uint32_t        sh_collocated_from_l0_flag                                      : 1;
+            uint32_t        sh_cu_chroma_qp_offset_enabled_flag                             : 1;
+            uint32_t        sh_sao_luma_used_flag                                           : 1;
+            uint32_t        sh_sao_chroma_used_flag                                         : 1;
+            uint32_t        sh_deblocking_filter_disabled_flag                              : 1;
+            uint32_t        sh_dep_quant_used_flag                                          : 1;
+            uint32_t        sh_sign_data_hiding_used_flag                                   : 1;
+            uint32_t        sh_ts_residual_coding_disabled_flag                             : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint32_t        reserved                                                        : 16;
+        } bits;
+        uint32_t            value;
+    } sh_flags;
+
+    /** \brief Reserved bytes for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_MEDIUM];
+} VASliceParameterBufferVVC;
+
+/**
+ * \brief VVC Scaling List Data Structure
+ *
+ * Host decoder sends in an array of VVC Scaling Lists through one or multiple
+ * buffers which may contain 1 to 8 VAScalingListVVC data structures in total.
+ * Each buffer contains an integer number of VAScalingListVVC data structures
+ * with no gap in between.
+ * Driver may store the data internally. Host decoder may choose not to
+ * send the same scaling list data for each frame. When a VAScalingListVVC
+ * structure carries a same value of aps_adaptation_parameter_set_id
+ * as a previously stored structure, driver should override the old structure
+ * with values in the new structure.
+ * VAIQMatrixBufferType is used to send this buffer.
+ */
+typedef struct _VAScalingListVVC {
+    /** \brief VVC syntax to specify the identifier for the APS.*/
+    uint8_t                 aps_adaptation_parameter_set_id;
+    /** \brief Reserved for future use, must be zero */
+    uint8_t                 reserved8b;
+    /**
+     * \brief Specifies the spec variable ScalingMatrixDCRec[id−14],
+     * where id = [14..27].
+     */
+    uint8_t                 ScalingMatrixDCRec[14];
+    /**
+     * \brief Specifies the spec variable ScalingMatrixRec[id][x][y],
+     * where id = [0..1]. Check section 7.4.3.20 for derivation process.
+     */
+    uint8_t                 ScalingMatrixRec2x2[2][2][2];
+    /**
+     * \brief Specifies the spec variable ScalingMatrixRec[id][x][y],
+     * where id = [2..7]. Check section 7.4.3.20 for derivation process.
+     */
+    uint8_t                 ScalingMatrixRec4x4[6][4][4];
+    /**
+     * \brief Specifies the spec variable ScalingMatrixRec[id][x][y],
+     * where id = [8..27]. Check section 7.4.3.20 for derivation process.
+     */
+    uint8_t                 ScalingMatrixRec8x8[20][8][8];
+
+    /** \brief Reserved bytes for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_MEDIUM];
+} VAScalingListVVC;
+
+/**
+ * \brief VVC Adaptive Loop Filter Data Structure
+ *
+ * Host decoder sends in an array of VVC ALF sets through one or multiple
+ * buffers which may contain 1 to 8 VAAlfDataVVC data structures in total.
+ * Each buffer contains an integer number of VAAlfDataVVC data structures
+ * with no gap in between.
+ * Driver may store the data internally. Host decoder may choose not to
+ * send the same ALF data for each frame. When a VAAlfDataVVC structure
+ * carries a same value of aps_adaptation_parameter_set_id as a previously
+ * stored structure, driver should override the old structure
+ * with values in the new structure.
+ * VAAlfBufferType is used to send this buffer.
+ */
+typedef struct _VAAlfDataVVC {
+    /**
+     * \brief VVC Adaptive Loop Filter parameters.
+     * All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    uint8_t                 aps_adaptation_parameter_set_id;
+    uint8_t                 alf_luma_num_filters_signalled_minus1;
+    uint8_t                 alf_luma_coeff_delta_idx[25];
+    int8_t                  filtCoeff[25][12];
+    uint8_t                 alf_luma_clip_idx[25][12];
+    uint8_t                 alf_chroma_num_alt_filters_minus1;
+    int8_t                  AlfCoeffC[8][6];
+    uint8_t                 alf_chroma_clip_idx[8][6];
+    uint8_t                 alf_cc_cb_filters_signalled_minus1;
+    int8_t                  CcAlfApsCoeffCb[4][7];
+    uint8_t                 alf_cc_cr_filters_signalled_minus1;
+    int8_t                  CcAlfApsCoeffCr[4][7];
+    /** \brief Reserved bytes for future use, must be zero */
+    uint16_t                reserved16b;
+    uint32_t                reserved32b;
+
+    union {
+        struct {
+            uint32_t        alf_luma_filter_signal_flag                                     : 1;
+            uint32_t        alf_chroma_filter_signal_flag                                   : 1;
+            uint32_t        alf_cc_cb_filter_signal_flag                                    : 1;
+            uint32_t        alf_cc_cr_filter_signal_flag                                    : 1;
+            uint32_t        alf_luma_clip_flag                                              : 1;
+            uint32_t        alf_chroma_clip_flag                                            : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint32_t        reserved                                                        : 26;
+        } bits;
+        uint32_t            value;
+    } alf_flags;
+
+    /** \brief Reserved for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_MEDIUM];
+} VAAlfDataVVC;
+
+/**
+ * \brief VVC Luma Mapping with Chroma Scaling Data Structure
+ *
+ * Host decoder sends in an array of VVC LMCS sets through one or multiple
+ * buffers which may contain 1 to 4 VALmcsDataVVC data structures in total.
+ * Each buffer contains an integer number of VALmcsDataVVC data structures
+ * with no gap in between.
+ * Driver may store the data internally. Host decoder may choose not to
+ * send the same LMCS data for each frame. When a VALmcsDataVVC structure
+ * carries a same value of aps_adaptation_parameter_set_id as a previously
+ * stored structure, driver should override the old structure
+ * with values in the new structure.
+ * VALmcsBufferType is used to send this buffer.
+ */
+typedef struct _VALmcsDataVVC {
+    /**
+     * \brief VVC Luma Mapping with Chroma Scaling parameters.
+     * All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    uint8_t                 aps_adaptation_parameter_set_id;
+    uint8_t                 lmcs_min_bin_idx;
+    uint8_t                 lmcs_delta_max_bin_idx;
+    int16_t                 lmcsDeltaCW[16];
+    int8_t                  lmcsDeltaCrs;
+    /** \brief Reserved for future use, must be zero */
+    uint8_t                 reserved8b[VA_PADDING_LOW - 1];
+    uint32_t                va_reserved[VA_PADDING_MEDIUM];
+} VALmcsDataVVC;
+
+/**
+ * \brief VVC SubPicture Data Structure
+ *
+ * Host decoder sends in an array of VVC SubPic sets through one or
+ * multiple buffers which contain sps_num_subpics_minus1 + 1
+ * VASubPicVVC data structures in total. Each buffer contains
+ * an integer number of VASubPicVVC data structures with no gap in between.
+ * The Subpic sets are sent sequentially in the order of indices
+ * from 0 to sps_num_subpics_minus1 according to the bitstream.
+ * VASubPicBufferType is used to send this buffer.
+ */
+typedef struct _VASubPicVVC {
+    /**
+     * \brief VVC SubPicture layout parameters.
+     * All the parameters except reserved bytes are VVC syntax or spec variables.
+     */
+    uint16_t                sps_subpic_ctu_top_left_x;
+    uint16_t                sps_subpic_ctu_top_left_y;
+    uint16_t                sps_subpic_width_minus1;
+    uint16_t                sps_subpic_height_minus1;
+    /** \brief the subpicture ID of the i-th subpicture.
+     *  It is same variable as in VVC spec.
+     */
+    uint16_t                SubpicIdVal;
+
+    union {
+        struct {
+            uint16_t        sps_subpic_treated_as_pic_flag                                  : 1;
+            uint16_t        sps_loop_filter_across_subpic_enabled_flag                      : 1;
+            /** \brief Reserved for future use, must be zero */
+            uint16_t        reserved                                                        : 14;
+        } bits;
+        uint16_t            value;
+    } subpic_flags;
+
+    /** \brief Reserved for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_LOW];
+} VASubPicVVC;
+
+/**
+ * \brief data buffer of tile widths and heights.
+ * VATileBufferType is used to send this buffer.
+ *
+ * Host decoder sends in number of pps_num_exp_tile_columns_minus1 + 1
+ * tile column widths of pps_tile_column_width_minus1[i], followed by
+ * number of pps_num_exp_tile_rows_minus1 + 1 of tile row heights of
+ * pps_tile_row_height_minus1[i], through one or multiple buffers.
+ * Each tile width or height is formatted as
+     uint16_t                tile_dimension;
+ * Each buffer contains an integer number of tile_dimension with
+ * no gap in between.
+ * The buffers with type VATileBufferType should be submitted for each
+ * picture. And driver will derive the tile structure from it.
+ * When pps_num_exp_tile_columns_minus1 + pps_num_exp_tile_rows_minus1 equals 0,
+ * this buffer is still submitted by app to driver.
+ */
+
+
+/**
+  * \brief VVC SliceStruct Data Structure
+  *
+  * Host decoder sends in an array of SliceStruct sets through one or multiple
+  * buffers. These SliceStruct sets contain only the "explicit" slices parsed
+  * from PPS header.
+  * Each SliceStruct set is described by VASliceStructVVC data structure.
+  * Each buffer contains an integer number of VASliceStructVVC data structures,
+  * which are laid out sequentially in the order of
+  * ascending slice indices according to the spec with no gap in between.
+  *
+  * When pps_rect_slice_flag equals 0 or there are no explicit slices,
+  * this buffer is not submitted by app to driver. Otherwise, for each picture,
+  * this buffer should be submitted.
+  *
+  * Note: When pps_slice_width_in_tiles_minus1 + pps_slice_height_in_tiles_minus1
+  * equals 0, if the sum of pps_exp_slice_height_in_ctus_minus1 + 1 of all those
+  * slices with same SliceTopLeftTileIdx value is less than the height of tile
+  * SliceTopLeftTileIdx in unit of CTUs, driver should derive the rest slices in
+  * that tile according to equation (21) in spec section 6.5.1. And VASliceStructVVC
+  * for these (derived) slices are not passed in to LibVA by App.
+  *
+  * App should populate the data entries regardless of values of
+  * pps_single_slice_per_subpic_flag or sps_subpic_info_present_flag.
+  *
+  * VASliceStructBufferType is used to send this buffer.
+  */
+typedef struct _VASliceStructVVC {
+    /** \brief the tile index of which the starting CTU (top-left) of
+     *  the slice belongs to. The tile index is in raster scan order.
+     *  Same syntax variable as in VVC spec.
+     */
+    uint16_t                SliceTopLeftTileIdx;
+    /* plus 1 specifies the width of the rectangular slice in units
+     * of tile columns.
+     */
+    uint16_t                pps_slice_width_in_tiles_minus1;
+    /* plus 1 specifies the height of the rectangular slice in units
+     * of tile rows. If the slice does not cover the whole tile,
+     * pps_slice_height_in_tiles_minus1 shall be 0.
+     */
+    uint16_t                pps_slice_height_in_tiles_minus1;
+    /* plus 1 specifies the height of the rectangular slice in units
+     * of CTU rows.
+     * If pps_slice_width_in_tiles_minus1 + pps_slice_height_in_tiles_minus1 > 0,
+     * set this value to 0.
+     * If pps_slice_width_in_tiles_minus1 + pps_slice_height_in_tiles_minus1 == 0,
+     * and if there is only one slice in tile, set this value to the number of
+     * CTU rows of the tile minus 1, otherwise, set the value equal to
+     * corresponding pps_exp_slice_height_in_ctus_minus1 from bitstream.
+     */
+    uint16_t                pps_exp_slice_height_in_ctus_minus1;
+
+    /** \brief Reserved for future use, must be zero */
+    uint32_t                va_reserved[VA_PADDING_LOW];
+} VASliceStructVVC;
+
+
+/**@}*/
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif /* VA_DEC_VVC_H */
diff --git a/va/va_drm.h b/va/va_drm.h
deleted file mode 120000
index 9424106..0000000
--- a/va/va_drm.h
+++ /dev/null
@@ -1 +0,0 @@
-drm/va_drm.h
\ No newline at end of file
diff --git a/va/va_str.c b/va/va_str.c
index 3d96f9b..9d651d0 100644
--- a/va/va_str.c
+++ b/va/va_str.c
@@ -66,6 +66,8 @@ const char *vaProfileStr(VAProfile profile)
         TOSTR(VAProfileAV1Profile1);
         TOSTR(VAProfileHEVCSccMain444_10);
         TOSTR(VAProfileProtected);
+        TOSTR(VAProfileVVCMain10);
+        TOSTR(VAProfileVVCMultilayerMain10);
     default:
         break;
     }
@@ -205,6 +207,11 @@ const char *vaBufferTypeStr(VABufferType bufferType)
         TOSTR(VAProtectedSessionExecuteBufferType);
         TOSTR(VAEncryptionParameterBufferType);
         TOSTR(VAEncDeltaQpPerBlockBufferType);
+        TOSTR(VAAlfBufferType);
+        TOSTR(VALmcsBufferType);
+        TOSTR(VASubPicBufferType);
+        TOSTR(VATileBufferType);
+        TOSTR(VASliceStructBufferType);
     case VABufferTypeMax:
         break;
     }
diff --git a/va/va_trace.c b/va/va_trace.c
index 365708c..8993d62 100644
--- a/va/va_trace.c
+++ b/va/va_trace.c
@@ -1,6 +1,6 @@
 
 /*
- * Copyright (c) 2009-2011 Intel Corporation. All Rights Reserved.
+ * Copyright (c) 2009-2024 Intel Corporation. All Rights Reserved.
  *
  * Permission is hereby granted, free of charge, to any person obtaining a
  * copy of this software and associated documentation files (the
@@ -37,6 +37,7 @@
 #include "va_dec_vp8.h"
 #include "va_dec_vp9.h"
 #include "va_dec_hevc.h"
+#include "va_dec_vvc.h"
 #include "va_str.h"
 #include "va_vpp.h"
 #include <assert.h>
@@ -2341,6 +2342,804 @@ static inline void va_TraceFlagIfNotZero(
     }
 }
 
+static void va_TraceVAPictureParameterBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i, j;
+    VAPictureParameterBufferVVC* p = (VAPictureParameterBufferVVC*)data;
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VAPictureParameterBufferVVC\n");
+
+    va_TraceMsg(trace_ctx, "\tCurrPic.picture_id = 0x%08x\n", p->CurrPic.picture_id);
+    va_TraceMsg(trace_ctx, "\tCurrPic.frame_idx = %d\n", p->CurrPic.pic_order_cnt);
+    va_TraceMsg(trace_ctx, "\tCurrPic.flags = %d\n", p->CurrPic.flags);
+
+    va_TraceMsg(trace_ctx, "\tReferenceFrames (picture_id-pic_order_cnt-flags):\n");
+    for (i = 0; i < 15; i++) {
+        if ((p->ReferenceFrames[i].picture_id != VA_INVALID_SURFACE) &&
+            ((p->ReferenceFrames[i].flags & VA_PICTURE_VVC_INVALID) == 0)) {
+            va_TraceMsg(trace_ctx, "\t\t0x%08x-%08d-0x%08x\n",
+                        p->ReferenceFrames[i].picture_id,
+                        p->ReferenceFrames[i].pic_order_cnt,
+                        p->ReferenceFrames[i].flags);
+        } else
+            va_TraceMsg(trace_ctx, "\t\tinv-inv-inv-inv-inv\n");
+    }
+    va_TraceMsg(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tpps_pic_width_in_luma_samples = %d\n", p->pps_pic_width_in_luma_samples);
+    va_TraceMsg(trace_ctx, "\tpps_pic_height_in_luma_samples = %d\n", p->pps_pic_height_in_luma_samples);
+    va_TraceMsg(trace_ctx, "\tsps_num_subpics_minus1 = %d\n", p->sps_num_subpics_minus1);
+    va_TraceMsg(trace_ctx, "\tsps_chroma_format_idc = %d\n", p->sps_chroma_format_idc);
+    va_TraceMsg(trace_ctx, "\tsps_bitdepth_minus8 = %d\n", p->sps_bitdepth_minus8);
+    va_TraceMsg(trace_ctx, "\tsps_log2_ctu_size_minus5 = %d\n", p->sps_log2_ctu_size_minus5);
+    va_TraceMsg(trace_ctx, "\tsps_log2_min_luma_coding_block_size_minus2 = %d\n", p->sps_log2_min_luma_coding_block_size_minus2);
+    va_TraceMsg(trace_ctx, "\tsps_log2_transform_skip_max_size_minus2 = %d\n", p->sps_log2_transform_skip_max_size_minus2);
+
+    va_TraceMsg(trace_ctx, "\tChromaQpTable[3][111] =\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 3; i++) {
+        for (j = 0; j < 111; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->ChromaQpTable[i][j]);
+            if ((j + 1) % 8 == 0)
+                TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tsps_six_minus_max_num_merge_cand = %d\n", p->sps_six_minus_max_num_merge_cand);
+    va_TraceMsg(trace_ctx, "\tsps_five_minus_max_num_subblock_merge_cand = %d\n", p->sps_five_minus_max_num_subblock_merge_cand);
+    va_TraceMsg(trace_ctx, "\tsps_max_num_merge_cand_minus_max_num_gpm_cand = %d\n", p->sps_max_num_merge_cand_minus_max_num_gpm_cand);
+    va_TraceMsg(trace_ctx, "\tsps_log2_parallel_merge_level_minus2 = %d\n", p->sps_log2_parallel_merge_level_minus2);
+    va_TraceMsg(trace_ctx, "\tsps_min_qp_prime_ts = %d\n", p->sps_min_qp_prime_ts);
+    va_TraceMsg(trace_ctx, "\tsps_six_minus_max_num_ibc_merge_cand = %d\n", p->sps_six_minus_max_num_ibc_merge_cand);
+    va_TraceMsg(trace_ctx, "\tsps_num_ladf_intervals_minus2 = %d\n", p->sps_num_ladf_intervals_minus2);
+    va_TraceMsg(trace_ctx, "\tsps_ladf_lowest_interval_qp_offset = %d\n", p->sps_ladf_lowest_interval_qp_offset);
+
+    va_TraceMsg(trace_ctx, "\tsps_ladf_qp_offset[4]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->sps_ladf_qp_offset[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tsps_ladf_delta_threshold_minus1[4]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->sps_ladf_delta_threshold_minus1[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\treserved32b01[2]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved32b01[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tsps_flags = %llu\n", p->sps_flags.value);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_info_present_flag = %llu\n", p->sps_flags.bits.sps_subpic_info_present_flag);
+    va_TraceMsg(trace_ctx, "\tsps_independent_subpics_flag = %llu\n", p->sps_flags.bits.sps_independent_subpics_flag);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_same_size_flag = %llu\n", p->sps_flags.bits.sps_subpic_same_size_flag);
+    va_TraceMsg(trace_ctx, "\tsps_entropy_coding_sync_enabled_flag = %llu\n", p->sps_flags.bits.sps_entropy_coding_sync_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_qtbtt_dual_tree_intra_flag = %llu\n", p->sps_flags.bits.sps_qtbtt_dual_tree_intra_flag);
+    va_TraceMsg(trace_ctx, "\tsps_max_luma_transform_size_64_flag = %llu\n", p->sps_flags.bits.sps_max_luma_transform_size_64_flag);
+    va_TraceMsg(trace_ctx, "\tsps_transform_skip_enabled_flag = %llu\n", p->sps_flags.bits.sps_transform_skip_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_bdpcm_enabled_flag = %llu\n", p->sps_flags.bits.sps_bdpcm_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_mts_enabled_flag = %llu\n", p->sps_flags.bits.sps_mts_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_explicit_mts_intra_enabled_flag = %llu\n", p->sps_flags.bits.sps_explicit_mts_intra_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_explicit_mts_inter_enabled_flag = %llu\n", p->sps_flags.bits.sps_explicit_mts_inter_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_lfnst_enabled_flag = %llu\n", p->sps_flags.bits.sps_lfnst_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_joint_cbcr_enabled_flag = %llu\n", p->sps_flags.bits.sps_joint_cbcr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_same_qp_table_for_chroma_flag = %llu\n", p->sps_flags.bits.sps_same_qp_table_for_chroma_flag);
+    va_TraceMsg(trace_ctx, "\tsps_sao_enabled_flag = %llu\n", p->sps_flags.bits.sps_sao_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_alf_enabled_flag = %llu\n", p->sps_flags.bits.sps_alf_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_ccalf_enabled_flag = %llu\n", p->sps_flags.bits.sps_ccalf_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_lmcs_enabled_flag = %llu\n", p->sps_flags.bits.sps_lmcs_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_sbtmvp_enabled_flag = %llu\n", p->sps_flags.bits.sps_sbtmvp_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_amvr_enabled_flag = %llu\n", p->sps_flags.bits.sps_amvr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_smvd_enabled_flag = %llu\n", p->sps_flags.bits.sps_smvd_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_mmvd_enabled_flag = %llu\n", p->sps_flags.bits.sps_mmvd_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_sbt_enabled_flag = %llu\n", p->sps_flags.bits.sps_sbt_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_affine_enabled_flag = %llu\n", p->sps_flags.bits.sps_affine_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_6param_affine_enabled_flag = %llu\n", p->sps_flags.bits.sps_6param_affine_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_affine_amvr_enabled_flag = %llu\n", p->sps_flags.bits.sps_affine_amvr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_affine_prof_enabled_flag = %llu\n", p->sps_flags.bits.sps_affine_prof_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_bcw_enabled_flag = %llu\n", p->sps_flags.bits.sps_bcw_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_ciip_enabled_flag = %llu\n", p->sps_flags.bits.sps_ciip_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_gpm_enabled_flag = %llu\n", p->sps_flags.bits.sps_gpm_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_isp_enabled_flag = %llu\n", p->sps_flags.bits.sps_isp_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_mrl_enabled_flag = %llu\n", p->sps_flags.bits.sps_mrl_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_mip_enabled_flag = %llu\n", p->sps_flags.bits.sps_mip_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_cclm_enabled_flag = %llu\n", p->sps_flags.bits.sps_cclm_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_chroma_horizontal_collocated_flag = %llu\n", p->sps_flags.bits.sps_chroma_horizontal_collocated_flag);
+    va_TraceMsg(trace_ctx, "\tsps_chroma_vertical_collocated_flag = %llu\n", p->sps_flags.bits.sps_chroma_vertical_collocated_flag);
+    va_TraceMsg(trace_ctx, "\tsps_palette_enabled_flag = %llu\n", p->sps_flags.bits.sps_palette_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_act_enabled_flag = %llu\n", p->sps_flags.bits.sps_act_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_ibc_enabled_flag = %llu\n", p->sps_flags.bits.sps_ibc_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_ladf_enabled_flag = %llu\n", p->sps_flags.bits.sps_ladf_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_explicit_scaling_list_enabled_flag = %llu\n", p->sps_flags.bits.sps_explicit_scaling_list_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_scaling_matrix_for_lfnst_disabled_flag = %llu\n", p->sps_flags.bits.sps_scaling_matrix_for_lfnst_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_scaling_matrix_for_alternative_colour_space_disabled_flag = %llu\n", p->sps_flags.bits.sps_scaling_matrix_for_alternative_colour_space_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_scaling_matrix_designated_colour_space_flag = %llu\n", p->sps_flags.bits.sps_scaling_matrix_designated_colour_space_flag);
+    va_TraceMsg(trace_ctx, "\tsps_virtual_boundaries_enabled_flag = %llu\n", p->sps_flags.bits.sps_virtual_boundaries_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsps_virtual_boundaries_present_flag = %llu\n", p->sps_flags.bits.sps_virtual_boundaries_present_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %llu\n", p->sps_flags.bits.reserved);
+
+    va_TraceMsg(trace_ctx, "\tNumVerVirtualBoundaries = %d\n", p->NumVerVirtualBoundaries);
+    va_TraceMsg(trace_ctx, "\tNumHorVirtualBoundaries = %d\n", p->NumHorVirtualBoundaries);
+    va_TraceMsg(trace_ctx, "\tVirtualBoundaryPosX[3]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 3; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->VirtualBoundaryPosX[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+    va_TraceMsg(trace_ctx, "\tVirtualBoundaryPosY[3]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 3; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->VirtualBoundaryPosY[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tpps_scaling_win_left_offset = %d\n", p->pps_scaling_win_left_offset);
+    va_TraceMsg(trace_ctx, "\tpps_scaling_win_right_offset = %d\n", p->pps_scaling_win_right_offset);
+    va_TraceMsg(trace_ctx, "\tpps_scaling_win_top_offset = %d\n", p->pps_scaling_win_top_offset);
+    va_TraceMsg(trace_ctx, "\tpps_scaling_win_bottom_offset = %d\n", p->pps_scaling_win_bottom_offset);
+
+    va_TraceMsg(trace_ctx, "\tpps_num_exp_tile_columns_minus1 = %d\n", p->pps_num_exp_tile_columns_minus1);
+    va_TraceMsg(trace_ctx, "\tpps_num_exp_tile_rows_minus1 = %d\n", p->pps_num_exp_tile_rows_minus1);
+    va_TraceMsg(trace_ctx, "\tpps_num_slices_in_pic_minus1 = %d\n", p->pps_num_slices_in_pic_minus1);
+    va_TraceMsg(trace_ctx, "\tpps_pic_width_minus_wraparound_offset = %d\n", p->pps_pic_width_minus_wraparound_offset);
+    va_TraceMsg(trace_ctx, "\tpps_cb_qp_offset = %d\n", p->pps_cb_qp_offset);
+    va_TraceMsg(trace_ctx, "\tpps_cr_qp_offset = %d\n", p->pps_cr_qp_offset);
+    va_TraceMsg(trace_ctx, "\tpps_joint_cbcr_qp_offset_value = %d\n", p->pps_joint_cbcr_qp_offset_value);
+    va_TraceMsg(trace_ctx, "\tpps_chroma_qp_offset_list_len_minus1 = %d\n", p->pps_chroma_qp_offset_list_len_minus1);
+
+    va_TraceMsg(trace_ctx, "\tpps_cb_qp_offset_list[6]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 6; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->pps_cb_qp_offset_list[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tpps_cr_qp_offset_list[6]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 6; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->pps_cr_qp_offset_list[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tpps_joint_cbcr_qp_offset_list[6]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 6; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->pps_joint_cbcr_qp_offset_list[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\treserved16b01 = %d\n", p->reserved16b01);
+    va_TraceMsg(trace_ctx, "\treserved32b02[2]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved32b02[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tpps_flags = %d\n", p->pps_flags.value);
+    va_TraceMsg(trace_ctx, "\tpps_loop_filter_across_tiles_enabled_flag = %d\n", p->pps_flags.bits.pps_loop_filter_across_tiles_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_rect_slice_flag = %d\n", p->pps_flags.bits.pps_rect_slice_flag);
+    va_TraceMsg(trace_ctx, "\tpps_single_slice_per_subpic_flag = %d\n", p->pps_flags.bits.pps_single_slice_per_subpic_flag);
+    va_TraceMsg(trace_ctx, "\tpps_loop_filter_across_slices_enabled_flag = %d\n", p->pps_flags.bits.pps_loop_filter_across_slices_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_weighted_pred_flag = %d\n", p->pps_flags.bits.pps_weighted_pred_flag);
+    va_TraceMsg(trace_ctx, "\tpps_weighted_bipred_flag = %d\n", p->pps_flags.bits.pps_weighted_bipred_flag);
+    va_TraceMsg(trace_ctx, "\tpps_ref_wraparound_enabled_flag = %d\n", p->pps_flags.bits.pps_ref_wraparound_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_cu_qp_delta_enabled_flag = %d\n", p->pps_flags.bits.pps_cu_qp_delta_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_cu_chroma_qp_offset_list_enabled_flag = %d\n", p->pps_flags.bits.pps_cu_chroma_qp_offset_list_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_deblocking_filter_override_enabled_flag = %d\n", p->pps_flags.bits.pps_deblocking_filter_override_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_deblocking_filter_disabled_flag = %d\n", p->pps_flags.bits.pps_deblocking_filter_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tpps_dbf_info_in_ph_flag = %d\n", p->pps_flags.bits.pps_dbf_info_in_ph_flag);
+    va_TraceMsg(trace_ctx, "\tpps_sao_info_in_ph_flag = %d\n", p->pps_flags.bits.pps_sao_info_in_ph_flag);
+    va_TraceMsg(trace_ctx, "\tpps_alf_info_in_ph_flag = %d\n", p->pps_flags.bits.pps_alf_info_in_ph_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->pps_flags.bits.reserved);
+
+    va_TraceMsg(trace_ctx, "\tph_lmcs_aps_id = %d\n", p->ph_lmcs_aps_id);
+    va_TraceMsg(trace_ctx, "\tph_scaling_list_aps_id = %d\n", p->ph_scaling_list_aps_id);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_min_qt_min_cb_intra_slice_luma = %d\n", p->ph_log2_diff_min_qt_min_cb_intra_slice_luma);
+    va_TraceMsg(trace_ctx, "\tph_max_mtt_hierarchy_depth_intra_slice_luma = %d\n", p->ph_max_mtt_hierarchy_depth_intra_slice_luma);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_bt_min_qt_intra_slice_luma = %d\n", p->ph_log2_diff_max_bt_min_qt_intra_slice_luma);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_tt_min_qt_intra_slice_luma = %d\n", p->ph_log2_diff_max_tt_min_qt_intra_slice_luma);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_min_qt_min_cb_intra_slice_chroma = %d\n", p->ph_log2_diff_min_qt_min_cb_intra_slice_chroma);
+    va_TraceMsg(trace_ctx, "\tph_max_mtt_hierarchy_depth_intra_slice_chroma = %d\n", p->ph_max_mtt_hierarchy_depth_intra_slice_chroma);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_bt_min_qt_intra_slice_chroma = %d\n", p->ph_log2_diff_max_bt_min_qt_intra_slice_chroma);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_tt_min_qt_intra_slice_chroma = %d\n", p->ph_log2_diff_max_tt_min_qt_intra_slice_chroma);
+    va_TraceMsg(trace_ctx, "\tph_cu_qp_delta_subdiv_intra_slice = %d\n", p->ph_cu_qp_delta_subdiv_intra_slice);
+    va_TraceMsg(trace_ctx, "\tph_cu_chroma_qp_offset_subdiv_intra_slice = %d\n", p->ph_cu_chroma_qp_offset_subdiv_intra_slice);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_min_qt_min_cb_inter_slice = %d\n", p->ph_log2_diff_min_qt_min_cb_inter_slice);
+    va_TraceMsg(trace_ctx, "\tph_max_mtt_hierarchy_depth_inter_slice = %d\n", p->ph_max_mtt_hierarchy_depth_inter_slice);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_bt_min_qt_inter_slice = %d\n", p->ph_log2_diff_max_bt_min_qt_inter_slice);
+    va_TraceMsg(trace_ctx, "\tph_log2_diff_max_tt_min_qt_inter_slice = %d\n", p->ph_log2_diff_max_tt_min_qt_inter_slice);
+    va_TraceMsg(trace_ctx, "\tph_cu_qp_delta_subdiv_inter_slice = %d\n", p->ph_cu_qp_delta_subdiv_inter_slice);
+    va_TraceMsg(trace_ctx, "\tph_cu_chroma_qp_offset_subdiv_inter_slice = %d\n", p->ph_cu_chroma_qp_offset_subdiv_inter_slice);
+    va_TraceMsg(trace_ctx, "\treserved16b02 = %d\n", p->reserved16b02);
+    va_TraceMsg(trace_ctx, "\treserved32b03[2]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved32b03[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tph_flags = %d\n", p->ph_flags.value);
+    va_TraceMsg(trace_ctx, "\tph_non_ref_pic_flag = %d\n", p->ph_flags.bits.ph_non_ref_pic_flag);
+    va_TraceMsg(trace_ctx, "\tph_alf_enabled_flag = %d\n", p->ph_flags.bits.ph_alf_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_alf_cb_enabled_flag = %d\n", p->ph_flags.bits.ph_alf_cb_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_alf_cr_enabled_flag = %d\n", p->ph_flags.bits.ph_alf_cr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_alf_cc_cb_enabled_flag = %d\n", p->ph_flags.bits.ph_alf_cc_cb_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_alf_cc_cr_enabled_flag = %d\n", p->ph_flags.bits.ph_alf_cc_cr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_lmcs_enabled_flag = %d\n", p->ph_flags.bits.ph_lmcs_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_chroma_residual_scale_flag = %d\n", p->ph_flags.bits.ph_chroma_residual_scale_flag);
+    va_TraceMsg(trace_ctx, "\tph_explicit_scaling_list_enabled_flag = %d\n", p->ph_flags.bits.ph_explicit_scaling_list_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_virtual_boundaries_present_flag = %d\n", p->ph_flags.bits.ph_virtual_boundaries_present_flag);
+    va_TraceMsg(trace_ctx, "\tph_temporal_mvp_enabled_flag = %d\n", p->ph_flags.bits.ph_temporal_mvp_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_mmvd_fullpel_only_flag = %d\n", p->ph_flags.bits.ph_mmvd_fullpel_only_flag);
+    va_TraceMsg(trace_ctx, "\tph_mvd_l1_zero_flag = %d\n", p->ph_flags.bits.ph_mvd_l1_zero_flag);
+    va_TraceMsg(trace_ctx, "\tph_bdof_disabled_flag = %d\n", p->ph_flags.bits.ph_bdof_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_dmvr_disabled_flag = %d\n", p->ph_flags.bits.ph_dmvr_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_prof_disabled_flag = %d\n", p->ph_flags.bits.ph_prof_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_joint_cbcr_sign_flag = %d\n", p->ph_flags.bits.ph_joint_cbcr_sign_flag);
+    va_TraceMsg(trace_ctx, "\tph_sao_luma_enabled_flag = %d\n", p->ph_flags.bits.ph_sao_luma_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_sao_chroma_enabled_flag = %d\n", p->ph_flags.bits.ph_sao_chroma_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tph_deblocking_filter_disabled_flag = %d\n", p->ph_flags.bits.ph_deblocking_filter_disabled_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->ph_flags.bits.reserved);
+    va_TraceMsg(trace_ctx, "\treserved32b04 = %d\n", p->reserved32b04);
+
+    va_TraceMsg(trace_ctx, "\tPicMiscFlags = %d\n", p->PicMiscFlags.value);
+    va_TraceMsg(trace_ctx, "\tIntraPicFlag = %d\n", p->PicMiscFlags.fields.IntraPicFlag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->PicMiscFlags.fields.reserved);
+    va_TraceMsg(trace_ctx, "\treserved32b[17]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 17; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved32b[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+    return;
+}
+
+static void va_TraceVASliceParameterBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i, j;
+    VASliceParameterBufferVVC* p = (VASliceParameterBufferVVC*)data;
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    trace_ctx->trace_slice_no++;
+    trace_ctx->trace_slice_size = p->slice_data_size;
+
+    va_TraceMsg(trace_ctx, "\t--VASliceParameterBufferVVC\n");
+    va_TraceMsg(trace_ctx, "\tslice_data_size = %d\n", p->slice_data_size);
+    va_TraceMsg(trace_ctx, "\tslice_data_offset = %d\n", p->slice_data_offset);
+    va_TraceMsg(trace_ctx, "\tslice_data_flag = %d\n", p->slice_data_flag);
+    va_TraceMsg(trace_ctx, "\tslice_data_byte_offset = %d\n", p->slice_data_byte_offset);
+
+    va_TraceMsg(trace_ctx, "\tRefPicList[2][15]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        for (j = 0; j < 15; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->RefPicList[i][j]);
+            if ((j + 1) % 8 == 0)
+                TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+
+    va_TraceMsg(trace_ctx, "\tsh_subpic_id = %d\n", p->sh_subpic_id);
+    va_TraceMsg(trace_ctx, "\tsh_slice_address = %d\n", p->sh_slice_address);
+    va_TraceMsg(trace_ctx, "\tsh_num_tiles_in_slice_minus1 = %d\n", p->sh_num_tiles_in_slice_minus1);
+    va_TraceMsg(trace_ctx, "\tsh_slice_type = %d\n", p->sh_slice_type);
+    va_TraceMsg(trace_ctx, "\tsh_num_alf_aps_ids_luma = %d\n", p->sh_num_alf_aps_ids_luma);
+
+    va_TraceMsg(trace_ctx, "\tsh_alf_aps_id_luma[7]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 7; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->sh_alf_aps_id_luma[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tsh_alf_aps_id_chroma = %d\n", p->sh_alf_aps_id_chroma);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cc_cb_aps_id = %d\n", p->sh_alf_cc_cb_aps_id);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cc_cr_aps_id = %d\n", p->sh_alf_cc_cr_aps_id);
+
+    va_TraceMsg(trace_ctx, "\tNumRefIdxActive[2]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->NumRefIdxActive[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tsh_collocated_ref_idx = %d\n", p->sh_collocated_ref_idx);
+    va_TraceMsg(trace_ctx, "\tSliceQpY = %d\n", p->SliceQpY);
+    va_TraceMsg(trace_ctx, "\tsh_cb_qp_offset = %d\n", p->sh_cb_qp_offset);
+    va_TraceMsg(trace_ctx, "\tsh_cr_qp_offset = %d\n", p->sh_cr_qp_offset);
+    va_TraceMsg(trace_ctx, "\tsh_joint_cbcr_qp_offset = %d\n", p->sh_joint_cbcr_qp_offset);
+    va_TraceMsg(trace_ctx, "\tsh_luma_beta_offset_div2 = %d\n", p->sh_luma_beta_offset_div2);
+    va_TraceMsg(trace_ctx, "\tsh_luma_tc_offset_div2 = %d\n", p->sh_luma_tc_offset_div2);
+    va_TraceMsg(trace_ctx, "\tsh_cb_beta_offset_div2 = %d\n", p->sh_cb_beta_offset_div2);
+    va_TraceMsg(trace_ctx, "\tsh_cb_tc_offset_div2 = %d\n", p->sh_cb_tc_offset_div2);
+    va_TraceMsg(trace_ctx, "\tsh_cr_beta_offset_div2 = %d\n", p->sh_cr_beta_offset_div2);
+    va_TraceMsg(trace_ctx, "\tsh_cr_tc_offset_div2 = %d\n", p->sh_cr_tc_offset_div2);
+    va_TraceMsg(trace_ctx, "\treserved8b[3]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 3; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved8b[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+    va_TraceMsg(trace_ctx, "\treserved32b = %d\n", p->reserved32b);
+
+    va_TraceMsg(trace_ctx, "\tWPInfo=\n");
+    va_TraceMsg(trace_ctx, "\tluma_log2_weight_denom = %d\n", p->WPInfo.luma_log2_weight_denom);
+    va_TraceMsg(trace_ctx, "\tdelta_chroma_log2_weight_denom = %d\n", p->WPInfo.delta_chroma_log2_weight_denom);
+    va_TraceMsg(trace_ctx, "\tnum_l0_weights = %d\n", p->WPInfo.num_l0_weights);
+    va_TraceMsg(trace_ctx, "\tluma_weight_l0_flag[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.luma_weight_l0_flag[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tchroma_weight_l0_flag[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.chroma_weight_l0_flag[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_luma_weight_l0[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.delta_luma_weight_l0[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tluma_offset_l0[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.luma_offset_l0[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_chroma_weight_l0[15][2] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 15; i++) {
+        for (j = 0; j < 2; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->WPInfo.delta_chroma_weight_l0[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_chroma_offset_l0[15][2] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 15; i++) {
+        for (j = 0; j < 2; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->WPInfo.delta_chroma_offset_l0[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tnum_l1_weights = %d\n", p->WPInfo.num_l1_weights);
+    va_TraceMsg(trace_ctx, "\tluma_weight_l1_flag[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.luma_weight_l1_flag[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tchroma_weight_l1_flag[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.chroma_weight_l1_flag[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_luma_weight_l1[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.delta_luma_weight_l1[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tluma_offset_l1[15]=\n");
+    for (i = 0; i < 15; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->WPInfo.luma_offset_l1[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_chroma_weight_l1[15][2] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 15; i++) {
+        for (j = 0; j < 2; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->WPInfo.delta_chroma_weight_l1[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tdelta_chroma_offset_l1[15][2] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 15; i++) {
+        for (j = 0; j < 2; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->WPInfo.delta_chroma_offset_l1[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+    va_TraceMsg(trace_ctx, "\treserved16b = %d\n", p->WPInfo.reserved16b);
+    va_TraceMsg(trace_ctx, "\treserved32b = %d\n", p->WPInfo.reserved32b);
+
+    va_TraceMsg(trace_ctx, "\tsh_flags = %d\n", p->sh_flags.value);
+    va_TraceMsg(trace_ctx, "\tsh_alf_enabled_flag = %d\n", p->sh_flags.bits.sh_alf_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cb_enabled_flag = %d\n", p->sh_flags.bits.sh_alf_cb_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cr_enabled_flag = %d\n", p->sh_flags.bits.sh_alf_cr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cc_cb_enabled_flag = %d\n", p->sh_flags.bits.sh_alf_cc_cb_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_alf_cc_cr_enabled_flag = %d\n", p->sh_flags.bits.sh_alf_cc_cr_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_lmcs_used_flag = %d\n", p->sh_flags.bits.sh_lmcs_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_explicit_scaling_list_used_flag = %d\n", p->sh_flags.bits.sh_explicit_scaling_list_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_cabac_init_flag = %d\n", p->sh_flags.bits.sh_cabac_init_flag);
+    va_TraceMsg(trace_ctx, "\tsh_collocated_from_l0_flag = %d\n", p->sh_flags.bits.sh_collocated_from_l0_flag);
+    va_TraceMsg(trace_ctx, "\tsh_cu_chroma_qp_offset_enabled_flag = %d\n", p->sh_flags.bits.sh_cu_chroma_qp_offset_enabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_sao_luma_used_flag = %d\n", p->sh_flags.bits.sh_sao_luma_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_sao_chroma_used_flag = %d\n", p->sh_flags.bits.sh_sao_chroma_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_deblocking_filter_disabled_flag = %d\n", p->sh_flags.bits.sh_deblocking_filter_disabled_flag);
+    va_TraceMsg(trace_ctx, "\tsh_dep_quant_used_flag = %d\n", p->sh_flags.bits.sh_dep_quant_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_sign_data_hiding_used_flag = %d\n", p->sh_flags.bits.sh_sign_data_hiding_used_flag);
+    va_TraceMsg(trace_ctx, "\tsh_ts_residual_coding_disabled_flag = %d\n", p->sh_flags.bits.sh_ts_residual_coding_disabled_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->sh_flags.bits.reserved);
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVAScalingListBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i, j, k;
+    VAScalingListVVC* p = (VAScalingListVVC*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VAScalingListBufferVVC\n");
+
+    va_TraceMsg(trace_ctx, "\taps_adaptation_parameter_set_id = %d\n", p->aps_adaptation_parameter_set_id);
+    va_TraceMsg(trace_ctx, "\treserved8b = %d\n", p->reserved8b);
+    va_TraceMsg(trace_ctx, "\tScalingMatrixDCRec[14]=\n");
+    for (i = 0; i < 14; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->ScalingMatrixDCRec[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tScalingMatrixRec2x2[2][2][2] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 2; i++) {
+        for (j = 0; j < 2; j++) {
+            for (k = 0; k < 2; k++) {
+                va_TracePrint(trace_ctx, "\t%d", p->ScalingMatrixRec2x2[i][j][k]);
+            }
+            TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tScalingMatrixRec4x4[6][4][4] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 6; i++) {
+        for (j = 0; j < 4; j++) {
+            for (k = 0; k < 4; k++) {
+                va_TracePrint(trace_ctx, "\t%d", p->ScalingMatrixRec4x4[i][j][k]);
+            }
+            TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tScalingMatrixRec8x8[20][8][8] = \n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 20; i++) {
+        for (j = 0; j < 8; j++) {
+            for (k = 0; k < 8; k++) {
+                va_TracePrint(trace_ctx, "\t%d", p->ScalingMatrixRec8x8[i][j][k]);
+            }
+            TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tva_reserved[8]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 8; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->va_reserved[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVAAlfBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i, j;
+    VAAlfDataVVC* p = (VAAlfDataVVC*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VAAlfDataBufferVVC\n");
+
+    va_TraceMsg(trace_ctx, "\taps_adaptation_parameter_set_id = %d\n", p->aps_adaptation_parameter_set_id);
+    va_TraceMsg(trace_ctx, "\talf_luma_num_filters_signalled_minus1 = %d\n", p->alf_luma_num_filters_signalled_minus1);
+    va_TraceMsg(trace_ctx, "\talf_luma_coeff_delta_idx[25]=\n");
+    for (i = 0; i < 25; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->alf_luma_coeff_delta_idx[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tfiltCoeff[25][12]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 25; i++) {
+        for (j = 0; j < 12; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->filtCoeff[i][j]);
+            if ((j + 1) % 8 == 0)
+                TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+
+    va_TraceMsg(trace_ctx, "\talf_luma_clip_idx[25][12]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 25; i++) {
+        for (j = 0; j < 12; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->alf_luma_clip_idx[i][j]);
+            if ((j + 1) % 8 == 0)
+                TRACE_NEWLINE();
+        }
+        TRACE_NEWLINE();
+    }
+
+    va_TraceMsg(trace_ctx, "\talf_chroma_num_alt_filters_minus1 = %d\n", p->alf_chroma_num_alt_filters_minus1);
+    va_TraceMsg(trace_ctx, "\tAlfCoeffC[8][6]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 8; i++) {
+        for (j = 0; j < 6; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->AlfCoeffC[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\talf_chroma_clip_idx[8][6]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 8; i++) {
+        for (j = 0; j < 6; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->alf_chroma_clip_idx[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\talf_cc_cb_filters_signalled_minus1 = %d\n", p->alf_cc_cb_filters_signalled_minus1);
+    va_TraceMsg(trace_ctx, "\tCcAlfApsCoeffCb[4][7]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        for (j = 0; j < 7; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->CcAlfApsCoeffCb[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\talf_cc_cr_filters_signalled_minus1 = %d\n", p->alf_cc_cr_filters_signalled_minus1);
+    va_TraceMsg(trace_ctx, "\tCcAlfApsCoeffCr[4][7]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        for (j = 0; j < 7; j++) {
+            va_TracePrint(trace_ctx, "\t%d", p->CcAlfApsCoeffCr[i][j]);
+        }
+        TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\treserved16b = %d\n", p->reserved16b);
+    va_TraceMsg(trace_ctx, "\treserved32b = %d\n", p->reserved32b);
+
+    va_TraceMsg(trace_ctx, "\talf_flags = %d\n", p->alf_flags.value);
+    va_TraceMsg(trace_ctx, "\talf_luma_filter_signal_flag = %d\n", p->alf_flags.bits.alf_luma_filter_signal_flag);
+    va_TraceMsg(trace_ctx, "\talf_chroma_filter_signal_flag = %d\n", p->alf_flags.bits.alf_chroma_filter_signal_flag);
+    va_TraceMsg(trace_ctx, "\talf_cc_cb_filter_signal_flag = %d\n", p->alf_flags.bits.alf_cc_cb_filter_signal_flag);
+    va_TraceMsg(trace_ctx, "\talf_cc_cr_filter_signal_flag = %d\n", p->alf_flags.bits.alf_cc_cr_filter_signal_flag);
+    va_TraceMsg(trace_ctx, "\talf_luma_clip_flag = %d\n", p->alf_flags.bits.alf_luma_clip_flag);
+    va_TraceMsg(trace_ctx, "\talf_chroma_clip_flag = %d\n", p->alf_flags.bits.alf_chroma_clip_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->alf_flags.bits.reserved);
+
+    va_TraceMsg(trace_ctx, "\tva_reserved[8]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 8; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->va_reserved[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVALmcsBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i;
+    VALmcsDataVVC* p = (VALmcsDataVVC*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VALmcsDataBufferVVC\n");
+    va_TraceMsg(trace_ctx, "\taps_adaptation_parameter_set_id = %d\n", p->aps_adaptation_parameter_set_id);
+    va_TraceMsg(trace_ctx, "\tlmcs_min_bin_idx = %d\n", p->lmcs_min_bin_idx);
+    va_TraceMsg(trace_ctx, "\tlmcs_delta_max_bin_idx = %d\n", p->lmcs_delta_max_bin_idx);
+
+    va_TraceMsg(trace_ctx, "\tlmcsDeltaCW[16]=\n");
+    for (i = 0; i < 16; i++) {
+        va_TraceMsg(trace_ctx, "\t%d", p->lmcsDeltaCW[i]);
+        if ((i + 1) % 8 == 0)
+            TRACE_NEWLINE();
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tlmcsDeltaCrs = %d\n", p->lmcsDeltaCrs);
+    va_TraceMsg(trace_ctx, "\treserved8b[3]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 3; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->reserved8b[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, "\tva_reserved[8]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 8; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->va_reserved[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVASubPicBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i;
+    VASubPicVVC* p = (VASubPicVVC*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VASubPicBufferVVC\n");
+
+    va_TraceMsg(trace_ctx, "\tsps_subpic_ctu_top_left_x = %d\n", p->sps_subpic_ctu_top_left_x);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_ctu_top_left_y = %d\n", p->sps_subpic_ctu_top_left_y);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_width_minus1 = %d\n", p->sps_subpic_width_minus1);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_height_minus1 = %d\n", p->sps_subpic_height_minus1);
+    va_TraceMsg(trace_ctx, "\tSubpicIdVal = %d\n", p->SubpicIdVal);
+
+    va_TraceMsg(trace_ctx, "\tsubpic_flags = %d\n", p->subpic_flags.value);
+    va_TraceMsg(trace_ctx, "\tsps_subpic_treated_as_pic_flag = %d\n", p->subpic_flags.bits.sps_subpic_treated_as_pic_flag);
+    va_TraceMsg(trace_ctx, "\tsps_loop_filter_across_subpic_enabled_flag = %d\n", p->subpic_flags.bits.sps_loop_filter_across_subpic_enabled_flag);
+    va_TraceMsg(trace_ctx, "\treserved = %d\n", p->subpic_flags.bits.reserved);
+
+    va_TraceMsg(trace_ctx, "\tva_reserved[4]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->va_reserved[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVATileBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    uint16_t* p = (uint16_t*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VATileBufferVVC\n");
+    va_TraceMsg(trace_ctx, "\ttile_dimension = %d\n", *p);
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+static void va_TraceVASliceStructBufferVVC(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* data)
+{
+    int i;
+    VASliceStructVVC* p = (VASliceStructVVC*)data;
+
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    va_TraceMsg(trace_ctx, "\t--VASliceStructBufferVVC\n");
+    va_TraceMsg(trace_ctx, "\tSliceTopLeftTileIdx = %d\n", p->SliceTopLeftTileIdx);
+    va_TraceMsg(trace_ctx, "\tpps_slice_width_in_tiles_minus1 = %d\n", p->pps_slice_width_in_tiles_minus1);
+    va_TraceMsg(trace_ctx, "\tpps_slice_height_in_tiles_minus1 = %d\n", p->pps_slice_height_in_tiles_minus1);
+    va_TraceMsg(trace_ctx, "\tpps_exp_slice_height_in_ctus_minus1 = %d\n", p->pps_exp_slice_height_in_ctus_minus1);
+
+    va_TraceMsg(trace_ctx, "\tva_reserved[4]=\n");
+    va_TraceMsg(trace_ctx, "");
+    for (i = 0; i < 4; i++) {
+        va_TracePrint(trace_ctx, "\t%d", p->va_reserved[i]);
+    }
+    va_TracePrint(trace_ctx, "\n");
+
+    va_TraceMsg(trace_ctx, NULL);
+}
+
+
 static inline void va_TraceIsRextProfile(
     VADisplay dpy,
     VAContextID context,
@@ -4168,6 +4967,7 @@ static void va_TraceVAPictureParameterBufferVP9(
     va_TraceMsg(trace_ctx, "\tsegment_pred_probs[3]: [0x%02x, 0x%02x, 0x%02x]\n", p->segment_pred_probs[0], p->segment_pred_probs[1], p->segment_pred_probs[2]);
 
     va_TraceMsg(trace_ctx, "\tprofile = %d\n", p->profile);
+    va_TraceMsg(trace_ctx, "\tbit_depth = %d\n", p->bit_depth);
 
     va_TraceMsg(trace_ctx, NULL);
 
@@ -5260,6 +6060,49 @@ static void va_TraceMPEG4Buf(
     }
 }
 
+static void va_TraceVVCBuf(
+    VADisplay dpy,
+    VAContextID context,
+    VABufferID buffer,
+    VABufferType type,
+    unsigned int size,
+    unsigned int num_elements,
+    void* pbuf
+)
+{
+    DPY2TRACECTX(dpy, context, VA_INVALID_ID);
+
+    switch (type) {
+    case VAPictureParameterBufferType:
+        va_TraceVAPictureParameterBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VASliceParameterBufferType:
+        va_TraceVASliceParameterBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VAIQMatrixBufferType:
+        va_TraceVAScalingListBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VAAlfBufferType:
+        va_TraceVAAlfBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VALmcsBufferType:
+        va_TraceVALmcsBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VASubPicBufferType:
+        va_TraceVASubPicBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VATileBufferType:
+        va_TraceVATileBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    case VASliceStructBufferType:
+        va_TraceVASliceStructBufferVVC(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    default:
+        va_TraceVABuffers(dpy, context, buffer, type, size, num_elements, pbuf);
+        break;
+    }
+}
+
 static void va_TraceHEVCBuf(
     VADisplay dpy,
     VAContextID context,
@@ -5912,6 +6755,14 @@ void va_TraceRenderPicture(
                 va_TraceHEVCBuf(dpy, context, buffers[i], type, size, num_elements, pbuf + size * j);
             }
             break;
+        case VAProfileVVCMain10:
+        case VAProfileVVCMultilayerMain10:
+            for (j = 0; j < num_elements; j++) {
+                va_TraceMsg(trace_ctx, "\telement[%d] = \n", j);
+
+                va_TraceVVCBuf(dpy, context, buffers[i], type, size, num_elements, pbuf + size * j);
+            }
+            break;
         case VAProfileVP9Profile0:
         case VAProfileVP9Profile1:
         case VAProfileVP9Profile2:
diff --git a/va/wayland/Makefile.am b/va/wayland/Makefile.am
index d163887..1f61aa4 100644
--- a/va/wayland/Makefile.am
+++ b/va/wayland/Makefile.am
@@ -29,6 +29,7 @@ AM_CPPFLAGS = \
 
 source_c = \
 	va_wayland.c		\
+	va_wayland_linux_dmabuf.c \
 	va_wayland_drm.c	\
 	va_wayland_emgd.c	\
 	../drm/va_drm_utils.c 	\
@@ -40,16 +41,19 @@ source_h = \
 	$(NULL)
 
 source_h_priv = \
+	va_wayland_linux_dmabuf.h \
 	va_wayland_drm.h	\
 	va_wayland_emgd.h	\
 	va_wayland_private.h	\
 	$(NULL)
 
 protocol_source_c = \
+	linux-dmabuf-v1-client-protocol.c \
 	wayland-drm-client-protocol.c	\
 	$(NULL)
 
 protocol_source_h = \
+	linux-dmabuf-v1-client-protocol.h \
 	wayland-drm-client-protocol.h	\
 	$(NULL)
 
@@ -61,6 +65,7 @@ noinst_HEADERS			= $(source_h_priv)
 
 # Wayland protocol
 va_wayland_drm.c: $(protocol_source_h)
+va_wayland_linux_dmabuf.c: $(protocol_source_h)
 %-client-protocol.h : %.xml
 	$(AM_V_GEN)$(WAYLAND_SCANNER) client-header < $< > $@
 %-client-protocol.c : %.xml
@@ -68,6 +73,7 @@ va_wayland_drm.c: $(protocol_source_h)
 
 EXTRA_DIST = \
 	wayland-drm.xml         \
+	linux-dmabuf-v1.xml     \
 	$(NULL)
 
 BUILT_SOURCES = $(protocol_source_h) $(protocol_source_c)
diff --git a/va/wayland/linux-dmabuf-v1.xml b/va/wayland/linux-dmabuf-v1.xml
new file mode 100644
index 0000000..38e06f5
--- /dev/null
+++ b/va/wayland/linux-dmabuf-v1.xml
@@ -0,0 +1,585 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<protocol name="linux_dmabuf_v1">
+
+  <copyright>
+    Copyright © 2014, 2015 Collabora, Ltd.
+
+    Permission is hereby granted, free of charge, to any person obtaining a
+    copy of this software and associated documentation files (the "Software"),
+    to deal in the Software without restriction, including without limitation
+    the rights to use, copy, modify, merge, publish, distribute, sublicense,
+    and/or sell copies of the Software, and to permit persons to whom the
+    Software is furnished to do so, subject to the following conditions:
+
+    The above copyright notice and this permission notice (including the next
+    paragraph) shall be included in all copies or substantial portions of the
+    Software.
+
+    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
+    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
+    DEALINGS IN THE SOFTWARE.
+  </copyright>
+
+  <interface name="zwp_linux_dmabuf_v1" version="5">
+    <description summary="factory for creating dmabuf-based wl_buffers">
+      Following the interfaces from:
+      https://www.khronos.org/registry/egl/extensions/EXT/EGL_EXT_image_dma_buf_import.txt
+      https://www.khronos.org/registry/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt
+      and the Linux DRM sub-system's AddFb2 ioctl.
+
+      This interface offers ways to create generic dmabuf-based wl_buffers.
+
+      Clients can use the get_surface_feedback request to get dmabuf feedback
+      for a particular surface. If the client wants to retrieve feedback not
+      tied to a surface, they can use the get_default_feedback request.
+
+      The following are required from clients:
+
+      - Clients must ensure that either all data in the dma-buf is
+        coherent for all subsequent read access or that coherency is
+        correctly handled by the underlying kernel-side dma-buf
+        implementation.
+
+      - Don't make any more attachments after sending the buffer to the
+        compositor. Making more attachments later increases the risk of
+        the compositor not being able to use (re-import) an existing
+        dmabuf-based wl_buffer.
+
+      The underlying graphics stack must ensure the following:
+
+      - The dmabuf file descriptors relayed to the server will stay valid
+        for the whole lifetime of the wl_buffer. This means the server may
+        at any time use those fds to import the dmabuf into any kernel
+        sub-system that might accept it.
+
+      However, when the underlying graphics stack fails to deliver the
+      promise, because of e.g. a device hot-unplug which raises internal
+      errors, after the wl_buffer has been successfully created the
+      compositor must not raise protocol errors to the client when dmabuf
+      import later fails.
+
+      To create a wl_buffer from one or more dmabufs, a client creates a
+      zwp_linux_dmabuf_params_v1 object with a zwp_linux_dmabuf_v1.create_params
+      request. All planes required by the intended format are added with
+      the 'add' request. Finally, a 'create' or 'create_immed' request is
+      issued, which has the following outcome depending on the import success.
+
+      The 'create' request,
+      - on success, triggers a 'created' event which provides the final
+        wl_buffer to the client.
+      - on failure, triggers a 'failed' event to convey that the server
+        cannot use the dmabufs received from the client.
+
+      For the 'create_immed' request,
+      - on success, the server immediately imports the added dmabufs to
+        create a wl_buffer. No event is sent from the server in this case.
+      - on failure, the server can choose to either:
+        - terminate the client by raising a fatal error.
+        - mark the wl_buffer as failed, and send a 'failed' event to the
+          client. If the client uses a failed wl_buffer as an argument to any
+          request, the behaviour is compositor implementation-defined.
+
+      For all DRM formats and unless specified in another protocol extension,
+      pre-multiplied alpha is used for pixel values.
+
+      Unless specified otherwise in another protocol extension, implicit
+      synchronization is used. In other words, compositors and clients must
+      wait and signal fences implicitly passed via the DMA-BUF's reservation
+      mechanism.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="unbind the factory">
+        Objects created through this interface, especially wl_buffers, will
+        remain valid.
+      </description>
+    </request>
+
+    <request name="create_params">
+      <description summary="create a temporary object for buffer parameters">
+        This temporary object is used to collect multiple dmabuf handles into
+        a single batch to create a wl_buffer. It can only be used once and
+        should be destroyed after a 'created' or 'failed' event has been
+        received.
+      </description>
+      <arg name="params_id" type="new_id" interface="zwp_linux_buffer_params_v1"
+           summary="the new temporary"/>
+    </request>
+
+    <event name="format">
+      <description summary="supported buffer format">
+        This event advertises one buffer format that the server supports.
+        All the supported formats are advertised once when the client
+        binds to this interface. A roundtrip after binding guarantees
+        that the client has received all supported formats.
+
+        For the definition of the format codes, see the
+        zwp_linux_buffer_params_v1::create request.
+
+        Starting version 4, the format event is deprecated and must not be
+        sent by compositors. Instead, use get_default_feedback or
+        get_surface_feedback.
+      </description>
+      <arg name="format" type="uint" summary="DRM_FORMAT code"/>
+    </event>
+
+    <event name="modifier" since="3">
+      <description summary="supported buffer format modifier">
+        This event advertises the formats that the server supports, along with
+        the modifiers supported for each format. All the supported modifiers
+        for all the supported formats are advertised once when the client
+        binds to this interface. A roundtrip after binding guarantees that
+        the client has received all supported format-modifier pairs.
+
+        For legacy support, DRM_FORMAT_MOD_INVALID (that is, modifier_hi ==
+        0x00ffffff and modifier_lo == 0xffffffff) is allowed in this event.
+        It indicates that the server can support the format with an implicit
+        modifier. When a plane has DRM_FORMAT_MOD_INVALID as its modifier, it
+        is as if no explicit modifier is specified. The effective modifier
+        will be derived from the dmabuf.
+
+        A compositor that sends valid modifiers and DRM_FORMAT_MOD_INVALID for
+        a given format supports both explicit modifiers and implicit modifiers.
+
+        For the definition of the format and modifier codes, see the
+        zwp_linux_buffer_params_v1::create and zwp_linux_buffer_params_v1::add
+        requests.
+
+        Starting version 4, the modifier event is deprecated and must not be
+        sent by compositors. Instead, use get_default_feedback or
+        get_surface_feedback.
+      </description>
+      <arg name="format" type="uint" summary="DRM_FORMAT code"/>
+      <arg name="modifier_hi" type="uint"
+           summary="high 32 bits of layout modifier"/>
+      <arg name="modifier_lo" type="uint"
+           summary="low 32 bits of layout modifier"/>
+    </event>
+
+    <!-- Version 4 additions -->
+
+    <request name="get_default_feedback" since="4">
+      <description summary="get default feedback">
+        This request creates a new wp_linux_dmabuf_feedback object not bound
+        to a particular surface. This object will deliver feedback about dmabuf
+        parameters to use if the client doesn't support per-surface feedback
+        (see get_surface_feedback).
+      </description>
+      <arg name="id" type="new_id" interface="zwp_linux_dmabuf_feedback_v1"/>
+    </request>
+
+    <request name="get_surface_feedback" since="4">
+      <description summary="get feedback for a surface">
+        This request creates a new wp_linux_dmabuf_feedback object for the
+        specified wl_surface. This object will deliver feedback about dmabuf
+        parameters to use for buffers attached to this surface.
+
+        If the surface is destroyed before the wp_linux_dmabuf_feedback object,
+        the feedback object becomes inert.
+      </description>
+      <arg name="id" type="new_id" interface="zwp_linux_dmabuf_feedback_v1"/>
+      <arg name="surface" type="object" interface="wl_surface"/>
+    </request>
+  </interface>
+
+  <interface name="zwp_linux_buffer_params_v1" version="5">
+    <description summary="parameters for creating a dmabuf-based wl_buffer">
+      This temporary object is a collection of dmabufs and other
+      parameters that together form a single logical buffer. The temporary
+      object may eventually create one wl_buffer unless cancelled by
+      destroying it before requesting 'create'.
+
+      Single-planar formats only require one dmabuf, however
+      multi-planar formats may require more than one dmabuf. For all
+      formats, an 'add' request must be called once per plane (even if the
+      underlying dmabuf fd is identical).
+
+      You must use consecutive plane indices ('plane_idx' argument for 'add')
+      from zero to the number of planes used by the drm_fourcc format code.
+      All planes required by the format must be given exactly once, but can
+      be given in any order. Each plane index can be set only once.
+    </description>
+
+    <enum name="error">
+      <entry name="already_used" value="0"
+             summary="the dmabuf_batch object has already been used to create a wl_buffer"/>
+      <entry name="plane_idx" value="1"
+             summary="plane index out of bounds"/>
+      <entry name="plane_set" value="2"
+             summary="the plane index was already set"/>
+      <entry name="incomplete" value="3"
+             summary="missing or too many planes to create a buffer"/>
+      <entry name="invalid_format" value="4"
+             summary="format not supported"/>
+      <entry name="invalid_dimensions" value="5"
+             summary="invalid width or height"/>
+      <entry name="out_of_bounds" value="6"
+             summary="offset + stride * height goes out of dmabuf bounds"/>
+      <entry name="invalid_wl_buffer" value="7"
+             summary="invalid wl_buffer resulted from importing dmabufs via
+               the create_immed request on given buffer_params"/>
+    </enum>
+
+    <request name="destroy" type="destructor">
+      <description summary="delete this object, used or not">
+        Cleans up the temporary data sent to the server for dmabuf-based
+        wl_buffer creation.
+      </description>
+    </request>
+
+    <request name="add">
+      <description summary="add a dmabuf to the temporary set">
+        This request adds one dmabuf to the set in this
+        zwp_linux_buffer_params_v1.
+
+        The 64-bit unsigned value combined from modifier_hi and modifier_lo
+        is the dmabuf layout modifier. DRM AddFB2 ioctl calls this the
+        fb modifier, which is defined in drm_mode.h of Linux UAPI.
+        This is an opaque token. Drivers use this token to express tiling,
+        compression, etc. driver-specific modifications to the base format
+        defined by the DRM fourcc code.
+
+        Starting from version 4, the invalid_format protocol error is sent if
+        the format + modifier pair was not advertised as supported.
+
+        Starting from version 5, the invalid_format protocol error is sent if
+        all planes don't use the same modifier.
+
+        This request raises the PLANE_IDX error if plane_idx is too large.
+        The error PLANE_SET is raised if attempting to set a plane that
+        was already set.
+      </description>
+      <arg name="fd" type="fd" summary="dmabuf fd"/>
+      <arg name="plane_idx" type="uint" summary="plane index"/>
+      <arg name="offset" type="uint" summary="offset in bytes"/>
+      <arg name="stride" type="uint" summary="stride in bytes"/>
+      <arg name="modifier_hi" type="uint"
+           summary="high 32 bits of layout modifier"/>
+      <arg name="modifier_lo" type="uint"
+           summary="low 32 bits of layout modifier"/>
+    </request>
+
+    <enum name="flags" bitfield="true">
+      <entry name="y_invert" value="1" summary="contents are y-inverted"/>
+      <entry name="interlaced" value="2" summary="content is interlaced"/>
+      <entry name="bottom_first" value="4" summary="bottom field first"/>
+    </enum>
+
+    <request name="create">
+      <description summary="create a wl_buffer from the given dmabufs">
+        This asks for creation of a wl_buffer from the added dmabuf
+        buffers. The wl_buffer is not created immediately but returned via
+        the 'created' event if the dmabuf sharing succeeds. The sharing
+        may fail at runtime for reasons a client cannot predict, in
+        which case the 'failed' event is triggered.
+
+        The 'format' argument is a DRM_FORMAT code, as defined by the
+        libdrm's drm_fourcc.h. The Linux kernel's DRM sub-system is the
+        authoritative source on how the format codes should work.
+
+        The 'flags' is a bitfield of the flags defined in enum "flags".
+        'y_invert' means the that the image needs to be y-flipped.
+
+        Flag 'interlaced' means that the frame in the buffer is not
+        progressive as usual, but interlaced. An interlaced buffer as
+        supported here must always contain both top and bottom fields.
+        The top field always begins on the first pixel row. The temporal
+        ordering between the two fields is top field first, unless
+        'bottom_first' is specified. It is undefined whether 'bottom_first'
+        is ignored if 'interlaced' is not set.
+
+        This protocol does not convey any information about field rate,
+        duration, or timing, other than the relative ordering between the
+        two fields in one buffer. A compositor may have to estimate the
+        intended field rate from the incoming buffer rate. It is undefined
+        whether the time of receiving wl_surface.commit with a new buffer
+        attached, applying the wl_surface state, wl_surface.frame callback
+        trigger, presentation, or any other point in the compositor cycle
+        is used to measure the frame or field times. There is no support
+        for detecting missed or late frames/fields/buffers either, and
+        there is no support whatsoever for cooperating with interlaced
+        compositor output.
+
+        The composited image quality resulting from the use of interlaced
+        buffers is explicitly undefined. A compositor may use elaborate
+        hardware features or software to deinterlace and create progressive
+        output frames from a sequence of interlaced input buffers, or it
+        may produce substandard image quality. However, compositors that
+        cannot guarantee reasonable image quality in all cases are recommended
+        to just reject all interlaced buffers.
+
+        Any argument errors, including non-positive width or height,
+        mismatch between the number of planes and the format, bad
+        format, bad offset or stride, may be indicated by fatal protocol
+        errors: INCOMPLETE, INVALID_FORMAT, INVALID_DIMENSIONS,
+        OUT_OF_BOUNDS.
+
+        Dmabuf import errors in the server that are not obvious client
+        bugs are returned via the 'failed' event as non-fatal. This
+        allows attempting dmabuf sharing and falling back in the client
+        if it fails.
+
+        This request can be sent only once in the object's lifetime, after
+        which the only legal request is destroy. This object should be
+        destroyed after issuing a 'create' request. Attempting to use this
+        object after issuing 'create' raises ALREADY_USED protocol error.
+
+        It is not mandatory to issue 'create'. If a client wants to
+        cancel the buffer creation, it can just destroy this object.
+      </description>
+      <arg name="width" type="int" summary="base plane width in pixels"/>
+      <arg name="height" type="int" summary="base plane height in pixels"/>
+      <arg name="format" type="uint" summary="DRM_FORMAT code"/>
+      <arg name="flags" type="uint" enum="flags" summary="see enum flags"/>
+    </request>
+
+    <event name="created">
+      <description summary="buffer creation succeeded">
+        This event indicates that the attempted buffer creation was
+        successful. It provides the new wl_buffer referencing the dmabuf(s).
+
+        Upon receiving this event, the client should destroy the
+        zwp_linux_buffer_params_v1 object.
+      </description>
+      <arg name="buffer" type="new_id" interface="wl_buffer"
+           summary="the newly created wl_buffer"/>
+    </event>
+
+    <event name="failed">
+      <description summary="buffer creation failed">
+        This event indicates that the attempted buffer creation has
+        failed. It usually means that one of the dmabuf constraints
+        has not been fulfilled.
+
+        Upon receiving this event, the client should destroy the
+        zwp_linux_buffer_params_v1 object.
+      </description>
+    </event>
+
+    <request name="create_immed" since="2">
+      <description summary="immediately create a wl_buffer from the given
+                     dmabufs">
+        This asks for immediate creation of a wl_buffer by importing the
+        added dmabufs.
+
+        In case of import success, no event is sent from the server, and the
+        wl_buffer is ready to be used by the client.
+
+        Upon import failure, either of the following may happen, as seen fit
+        by the implementation:
+        - the client is terminated with one of the following fatal protocol
+          errors:
+          - INCOMPLETE, INVALID_FORMAT, INVALID_DIMENSIONS, OUT_OF_BOUNDS,
+            in case of argument errors such as mismatch between the number
+            of planes and the format, bad format, non-positive width or
+            height, or bad offset or stride.
+          - INVALID_WL_BUFFER, in case the cause for failure is unknown or
+            plaform specific.
+        - the server creates an invalid wl_buffer, marks it as failed and
+          sends a 'failed' event to the client. The result of using this
+          invalid wl_buffer as an argument in any request by the client is
+          defined by the compositor implementation.
+
+        This takes the same arguments as a 'create' request, and obeys the
+        same restrictions.
+      </description>
+      <arg name="buffer_id" type="new_id" interface="wl_buffer"
+           summary="id for the newly created wl_buffer"/>
+      <arg name="width" type="int" summary="base plane width in pixels"/>
+      <arg name="height" type="int" summary="base plane height in pixels"/>
+      <arg name="format" type="uint" summary="DRM_FORMAT code"/>
+      <arg name="flags" type="uint" enum="flags" summary="see enum flags"/>
+    </request>
+  </interface>
+
+  <interface name="zwp_linux_dmabuf_feedback_v1" version="5">
+    <description summary="dmabuf feedback">
+      This object advertises dmabuf parameters feedback. This includes the
+      preferred devices and the supported formats/modifiers.
+
+      The parameters are sent once when this object is created and whenever they
+      change. The done event is always sent once after all parameters have been
+      sent. When a single parameter changes, all parameters are re-sent by the
+      compositor.
+
+      Compositors can re-send the parameters when the current client buffer
+      allocations are sub-optimal. Compositors should not re-send the
+      parameters if re-allocating the buffers would not result in a more optimal
+      configuration. In particular, compositors should avoid sending the exact
+      same parameters multiple times in a row.
+
+      The tranche_target_device and tranche_formats events are grouped by
+      tranches of preference. For each tranche, a tranche_target_device, one
+      tranche_flags and one or more tranche_formats events are sent, followed
+      by a tranche_done event finishing the list. The tranches are sent in
+      descending order of preference. All formats and modifiers in the same
+      tranche have the same preference.
+
+      To send parameters, the compositor sends one main_device event, tranches
+      (each consisting of one tranche_target_device event, one tranche_flags
+      event, tranche_formats events and then a tranche_done event), then one
+      done event.
+    </description>
+
+    <request name="destroy" type="destructor">
+      <description summary="destroy the feedback object">
+        Using this request a client can tell the server that it is not going to
+        use the wp_linux_dmabuf_feedback object anymore.
+      </description>
+    </request>
+
+    <event name="done">
+      <description summary="all feedback has been sent">
+        This event is sent after all parameters of a wp_linux_dmabuf_feedback
+        object have been sent.
+
+        This allows changes to the wp_linux_dmabuf_feedback parameters to be
+        seen as atomic, even if they happen via multiple events.
+      </description>
+    </event>
+
+    <event name="format_table">
+      <description summary="format and modifier table">
+        This event provides a file descriptor which can be memory-mapped to
+        access the format and modifier table.
+
+        The table contains a tightly packed array of consecutive format +
+        modifier pairs. Each pair is 16 bytes wide. It contains a format as a
+        32-bit unsigned integer, followed by 4 bytes of unused padding, and a
+        modifier as a 64-bit unsigned integer. The native endianness is used.
+
+        The client must map the file descriptor in read-only private mode.
+
+        Compositors are not allowed to mutate the table file contents once this
+        event has been sent. Instead, compositors must create a new, separate
+        table file and re-send feedback parameters. Compositors are allowed to
+        store duplicate format + modifier pairs in the table.
+      </description>
+      <arg name="fd" type="fd" summary="table file descriptor"/>
+      <arg name="size" type="uint" summary="table size, in bytes"/>
+    </event>
+
+    <event name="main_device">
+      <description summary="preferred main device">
+        This event advertises the main device that the server prefers to use
+        when direct scan-out to the target device isn't possible. The
+        advertised main device may be different for each
+        wp_linux_dmabuf_feedback object, and may change over time.
+
+        There is exactly one main device. The compositor must send at least
+        one preference tranche with tranche_target_device equal to main_device.
+
+        Clients need to create buffers that the main device can import and
+        read from, otherwise creating the dmabuf wl_buffer will fail (see the
+        wp_linux_buffer_params.create and create_immed requests for details).
+        The main device will also likely be kept active by the compositor,
+        so clients can use it instead of waking up another device for power
+        savings.
+
+        In general the device is a DRM node. The DRM node type (primary vs.
+        render) is unspecified. Clients must not rely on the compositor sending
+        a particular node type. Clients cannot check two devices for equality
+        by comparing the dev_t value.
+
+        If explicit modifiers are not supported and the client performs buffer
+        allocations on a different device than the main device, then the client
+        must force the buffer to have a linear layout.
+      </description>
+      <arg name="device" type="array" summary="device dev_t value"/>
+    </event>
+
+    <event name="tranche_done">
+      <description summary="a preference tranche has been sent">
+        This event splits tranche_target_device and tranche_formats events in
+        preference tranches. It is sent after a set of tranche_target_device
+        and tranche_formats events; it represents the end of a tranche. The
+        next tranche will have a lower preference.
+      </description>
+    </event>
+
+    <event name="tranche_target_device">
+      <description summary="target device">
+        This event advertises the target device that the server prefers to use
+        for a buffer created given this tranche. The advertised target device
+        may be different for each preference tranche, and may change over time.
+
+        There is exactly one target device per tranche.
+
+        The target device may be a scan-out device, for example if the
+        compositor prefers to directly scan-out a buffer created given this
+        tranche. The target device may be a rendering device, for example if
+        the compositor prefers to texture from said buffer.
+
+        The client can use this hint to allocate the buffer in a way that makes
+        it accessible from the target device, ideally directly. The buffer must
+        still be accessible from the main device, either through direct import
+        or through a potentially more expensive fallback path. If the buffer
+        can't be directly imported from the main device then clients must be
+        prepared for the compositor changing the tranche priority or making
+        wl_buffer creation fail (see the wp_linux_buffer_params.create and
+        create_immed requests for details).
+
+        If the device is a DRM node, the DRM node type (primary vs. render) is
+        unspecified. Clients must not rely on the compositor sending a
+        particular node type. Clients cannot check two devices for equality by
+        comparing the dev_t value.
+
+        This event is tied to a preference tranche, see the tranche_done event.
+      </description>
+      <arg name="device" type="array" summary="device dev_t value"/>
+    </event>
+
+    <event name="tranche_formats">
+      <description summary="supported buffer format modifier">
+        This event advertises the format + modifier combinations that the
+        compositor supports.
+
+        It carries an array of indices, each referring to a format + modifier
+        pair in the last received format table (see the format_table event).
+        Each index is a 16-bit unsigned integer in native endianness.
+
+        For legacy support, DRM_FORMAT_MOD_INVALID is an allowed modifier.
+        It indicates that the server can support the format with an implicit
+        modifier. When a buffer has DRM_FORMAT_MOD_INVALID as its modifier, it
+        is as if no explicit modifier is specified. The effective modifier
+        will be derived from the dmabuf.
+
+        A compositor that sends valid modifiers and DRM_FORMAT_MOD_INVALID for
+        a given format supports both explicit modifiers and implicit modifiers.
+
+        Compositors must not send duplicate format + modifier pairs within the
+        same tranche or across two different tranches with the same target
+        device and flags.
+
+        This event is tied to a preference tranche, see the tranche_done event.
+
+        For the definition of the format and modifier codes, see the
+        wp_linux_buffer_params.create request.
+      </description>
+      <arg name="indices" type="array" summary="array of 16-bit indexes"/>
+    </event>
+
+    <enum name="tranche_flags" bitfield="true">
+      <entry name="scanout" value="1" summary="direct scan-out tranche"/>
+    </enum>
+
+    <event name="tranche_flags">
+      <description summary="tranche flags">
+        This event sets tranche-specific flags.
+
+        The scanout flag is a hint that direct scan-out may be attempted by the
+        compositor on the target device if the client appropriately allocates a
+        buffer. How to allocate a buffer that can be scanned out on the target
+        device is implementation-defined.
+
+        This event is tied to a preference tranche, see the tranche_done event.
+      </description>
+      <arg name="flags" type="uint" enum="tranche_flags" summary="tranche flags"/>
+    </event>
+  </interface>
+
+</protocol>
diff --git a/va/wayland/va_wayland.c b/va/wayland/va_wayland.c
index 95ac3c3..759b055 100644
--- a/va/wayland/va_wayland.c
+++ b/va/wayland/va_wayland.c
@@ -27,6 +27,7 @@
 #include "sysdeps.h"
 #include <stdarg.h>
 #include "va_wayland.h"
+#include "va_wayland_linux_dmabuf.h"
 #include "va_wayland_drm.h"
 #include "va_wayland_emgd.h"
 #include "va_wayland_private.h"
@@ -90,6 +91,10 @@ struct va_wayland_backend {
 };
 
 static const struct va_wayland_backend g_backends[] = {
+    {
+        va_wayland_linux_dmabuf_create,
+        va_wayland_linux_dmabuf_destroy
+    },
     {
         va_wayland_drm_create,
         va_wayland_drm_destroy
diff --git a/va/wayland/va_wayland_linux_dmabuf.c b/va/wayland/va_wayland_linux_dmabuf.c
new file mode 100644
index 0000000..27e357c
--- /dev/null
+++ b/va/wayland/va_wayland_linux_dmabuf.c
@@ -0,0 +1,364 @@
+/*
+ * va_wayland_drm.c - Wayland/linux-dmabuf helpers
+ *
+ * Copyright (c) 2024 Simon Ser
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the
+ * "Software"), to deal in the Software without restriction, including
+ * without limitation the rights to use, copy, modify, merge, publish,
+ * distribute, sub license, and/or sell copies of the Software, and to
+ * permit persons to whom the Software is furnished to do so, subject to
+ * the following conditions:
+ *
+ * The above copyright notice and this permission notice (including the
+ * next paragraph) shall be included in all copies or substantial portions
+ * of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+ * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
+ * IN NO EVENT SHALL INTEL AND/OR ITS SUPPLIERS BE LIABLE FOR
+ * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#include "sysdeps.h"
+#include <unistd.h>
+#include <errno.h>
+#include <fcntl.h>
+#include <dlfcn.h>
+#include <sys/stat.h>
+#include <xf86drm.h>
+#include "va_drmcommon.h"
+#include "drm/va_drm_utils.h"
+#include "va_wayland_linux_dmabuf.h"
+#include "va_wayland_private.h"
+#include "linux-dmabuf-v1-client-protocol.h"
+
+typedef struct va_wayland_linux_dmabuf_context {
+    struct va_wayland_context base;
+    bool                      has_linux_dmabuf;
+    bool                      default_feedback_done;
+} VADisplayContextWaylandLinuxDmabuf;
+
+static void
+feedback_handle_done(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback
+)
+{
+    VADisplayContextP const pDisplayContext = data;
+    struct va_wayland_linux_dmabuf_context *wl_linux_dmabuf_ctx = pDisplayContext->opaque;
+
+    wl_linux_dmabuf_ctx->default_feedback_done = true;
+
+    zwp_linux_dmabuf_feedback_v1_destroy(feedback);
+}
+
+static void
+feedback_handle_format_table(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback,
+    int                                  fd,
+    uint32_t                             size
+)
+{
+    close(fd);
+}
+
+/* XXX: replace with drmGetDeviceFromDevId() */
+static drmDevice *
+get_drm_device_from_dev_id(dev_t dev_id)
+{
+    uint32_t flags = 0;
+    int devices_len, i, node_type;
+    drmDevice *match = NULL, *dev;
+    struct stat statbuf;
+
+    devices_len = drmGetDevices2(flags, NULL, 0);
+    if (devices_len < 0) {
+        return NULL;
+    }
+    drmDevice **devices = calloc(devices_len, sizeof(*devices));
+    if (devices == NULL) {
+        return NULL;
+    }
+    devices_len = drmGetDevices2(flags, devices, devices_len);
+    if (devices_len < 0) {
+        free(devices);
+        return NULL;
+    }
+
+    for (i = 0; i < devices_len; i++) {
+        dev = devices[i];
+        for (node_type = 0; node_type < DRM_NODE_MAX; node_type++) {
+            if (!(dev->available_nodes & (1 << node_type)))
+                continue;
+
+            if (stat(dev->nodes[node_type], &statbuf) != 0) {
+                va_wayland_error("stat() failed for %s", dev->nodes[node_type]);
+                continue;
+            }
+
+            if (statbuf.st_rdev == dev_id) {
+                match = dev;
+                break;
+            }
+        }
+    }
+
+    for (i = 0; i < devices_len; i++) {
+        dev = devices[i];
+        if (dev != match)
+            drmFreeDevice(&dev);
+    }
+    free(devices);
+
+    return match;
+}
+
+static void
+feedback_handle_main_device(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback,
+    struct wl_array                     *device_array
+)
+{
+    dev_t dev_id;
+    drmDevice *dev;
+    const char *dev_path;
+    VADisplayContextP const pDisplayContext = data;
+    VADriverContextP const ctx = pDisplayContext->pDriverContext;
+    struct drm_state * const drm_state = ctx->drm_state;
+
+    assert(device_array->size == sizeof(dev_id));
+    memcpy(&dev_id, device_array->data, sizeof(dev_id));
+
+    dev = get_drm_device_from_dev_id(dev_id);
+    if (!dev) {
+        va_wayland_error("failed to get DRM device from device ID");
+        return;
+    }
+
+    if (!(dev->available_nodes & (1 << DRM_NODE_RENDER)))
+        goto end;
+
+    dev_path = dev->nodes[DRM_NODE_RENDER];
+    drm_state->fd = open(dev_path, O_RDWR | O_CLOEXEC);
+    if (drm_state->fd < 0) {
+        va_wayland_error("failed to open %s", dev_path);
+        goto end;
+    }
+
+    drm_state->auth_type = VA_DRM_AUTH_CUSTOM;
+
+end:
+    drmFreeDevice(&dev);
+}
+
+static void
+feedback_handle_tranche_done(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback
+)
+{
+}
+
+static void
+feedback_handle_tranche_target_device(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback,
+    struct wl_array                     *device_array
+)
+{
+}
+
+static void
+feedback_handle_tranche_formats(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback,
+    struct wl_array                     *indices_array
+)
+{
+}
+
+static void
+feedback_handle_tranche_flags(
+    void                                *data,
+    struct zwp_linux_dmabuf_feedback_v1 *feedback,
+    uint32_t                             flags
+)
+{
+}
+
+static const struct zwp_linux_dmabuf_feedback_v1_listener feedback_listener = {
+    .done = feedback_handle_done,
+    .format_table = feedback_handle_format_table,
+    .main_device = feedback_handle_main_device,
+    .tranche_done = feedback_handle_tranche_done,
+    .tranche_target_device = feedback_handle_tranche_target_device,
+    .tranche_formats = feedback_handle_tranche_formats,
+    .tranche_flags = feedback_handle_tranche_flags,
+};
+
+static void
+registry_handle_global(
+    void               *data,
+    struct wl_registry *registry,
+    uint32_t            name,
+    const char         *interface,
+    uint32_t            version
+)
+{
+    VADisplayContextP const pDisplayContext = data;
+    struct va_wayland_linux_dmabuf_context *wl_linux_dmabuf_ctx = pDisplayContext->opaque;
+    struct zwp_linux_dmabuf_v1 *linux_dmabuf;
+    struct zwp_linux_dmabuf_feedback_v1 *feedback;
+
+    if (strcmp(interface, zwp_linux_dmabuf_v1_interface.name) == 0 &&
+        version >= 4) {
+        wl_linux_dmabuf_ctx->has_linux_dmabuf = true;
+        linux_dmabuf =
+            wl_registry_bind(registry, name, &zwp_linux_dmabuf_v1_interface, 4);
+        feedback = zwp_linux_dmabuf_v1_get_default_feedback(linux_dmabuf);
+        zwp_linux_dmabuf_feedback_v1_add_listener(feedback, &feedback_listener, data);
+        zwp_linux_dmabuf_v1_destroy(linux_dmabuf);
+    }
+}
+
+static void
+registry_handle_global_remove(
+    void               *data,
+    struct wl_registry *registry,
+    uint32_t            name
+)
+{
+}
+
+static const struct wl_registry_listener registry_listener = {
+    .global        = registry_handle_global,
+    .global_remove = registry_handle_global_remove,
+};
+
+static VAStatus
+va_DisplayContextGetDriverNames(
+    VADisplayContextP pDisplayContext,
+    char            **drivers,
+    unsigned         *num_drivers
+)
+{
+    VADriverContextP const ctx = pDisplayContext->pDriverContext;
+
+    return VA_DRM_GetDriverNames(ctx, drivers, num_drivers);
+}
+
+bool
+va_wayland_linux_dmabuf_create(VADisplayContextP pDisplayContext)
+{
+    bool result = false;
+    VADriverContextP const ctx = pDisplayContext->pDriverContext;
+    struct VADriverVTableWayland *vtable = ctx->vtable_wayland;
+    struct va_wayland_linux_dmabuf_context *wl_linux_dmabuf_ctx;
+    struct drm_state *drm_state;
+    struct wl_event_queue *queue = NULL;
+    struct wl_display *display = NULL;
+    struct wl_registry *registry = NULL;
+
+    wl_linux_dmabuf_ctx = calloc(1, sizeof(*wl_linux_dmabuf_ctx));
+    if (!wl_linux_dmabuf_ctx) {
+        va_wayland_error("could not allocate wl_linux_dmabuf_ctx");
+        goto end;
+    }
+    wl_linux_dmabuf_ctx->base.destroy = va_wayland_linux_dmabuf_destroy;
+    pDisplayContext->opaque           = wl_linux_dmabuf_ctx;
+    pDisplayContext->vaGetDriverNames = va_DisplayContextGetDriverNames;
+
+    drm_state = calloc(1, sizeof(*drm_state));
+    if (!drm_state) {
+        va_wayland_error("could not allocate drm_state");
+        goto end;
+    }
+    drm_state->fd        = -1;
+    drm_state->auth_type = 0;
+    ctx->drm_state       = drm_state;
+
+    vtable->has_prime_sharing = 0;
+
+    /* Use wrapped wl_display with private event queue to prevent
+     * thread safety issues with applications that e.g. run an event pump
+     * parallel to libva initialization.
+     * Using the default queue, events might get lost and crashes occur
+     * because wl_display_roundtrip is not thread-safe with respect to the
+     * same queue.
+     */
+    queue = wl_display_create_queue(ctx->native_dpy);
+    if (!queue) {
+        va_wayland_error("could not create Wayland event queue");
+        goto end;
+    }
+
+    display = wl_proxy_create_wrapper(ctx->native_dpy);
+    if (!display) {
+        va_wayland_error("could not create Wayland proxy wrapper");
+        goto end;
+    }
+    wl_proxy_set_queue((struct wl_proxy *) display, queue);
+
+    registry = wl_display_get_registry(display);
+    if (!registry) {
+        va_wayland_error("could not create wl_registry");
+        goto end;
+    }
+    wl_registry_add_listener(registry, &registry_listener, pDisplayContext);
+
+    if (wl_display_roundtrip_queue(ctx->native_dpy, queue) < 0) {
+        va_wayland_error("failed to roundtrip Wayland queue");
+        goto end;
+    }
+
+    if (!wl_linux_dmabuf_ctx->has_linux_dmabuf)
+        goto end;
+
+    while (!wl_linux_dmabuf_ctx->default_feedback_done) {
+        if (wl_display_dispatch_queue(ctx->native_dpy, queue) < 0) {
+            va_wayland_error("failed to dispatch Wayland queue");
+            goto end;
+        }
+    }
+
+    if (drm_state->fd < 0)
+        goto end;
+
+    result = true;
+    vtable->has_prime_sharing = true;
+
+end:
+    if (registry)
+        wl_registry_destroy(registry);
+    if (display)
+        wl_proxy_wrapper_destroy(display);
+    if (queue)
+        wl_event_queue_destroy(queue);
+    return result;
+}
+
+void
+va_wayland_linux_dmabuf_destroy(VADisplayContextP pDisplayContext)
+{
+    VADriverContextP const ctx = pDisplayContext->pDriverContext;
+    struct drm_state * const drm_state = ctx->drm_state;
+    struct VADriverVTableWayland *vtable = ctx->vtable_wayland;
+
+    vtable->has_prime_sharing = 0;
+
+    if (drm_state) {
+        if (drm_state->fd >= 0) {
+            close(drm_state->fd);
+            drm_state->fd = -1;
+        }
+        free(ctx->drm_state);
+        ctx->drm_state = NULL;
+    }
+}
diff --git a/va/wayland/va_wayland_linux_dmabuf.h b/va/wayland/va_wayland_linux_dmabuf.h
new file mode 100644
index 0000000..aeea38b
--- /dev/null
+++ b/va/wayland/va_wayland_linux_dmabuf.h
@@ -0,0 +1,52 @@
+/*
+ * va_wayland_linux_dmabuf.h - Wayland/linux-dmabuf helpers
+ *
+ * Copyright (c) 2024 Simon Ser
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the
+ * "Software"), to deal in the Software without restriction, including
+ * without limitation the rights to use, copy, modify, merge, publish,
+ * distribute, sub license, and/or sell copies of the Software, and to
+ * permit persons to whom the Software is furnished to do so, subject to
+ * the following conditions:
+ *
+ * The above copyright notice and this permission notice (including the
+ * next paragraph) shall be included in all copies or substantial portions
+ * of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+ * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
+ * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
+ * IN NO EVENT SHALL INTEL AND/OR ITS SUPPLIERS BE LIABLE FOR
+ * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
+ * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
+ * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
+ */
+
+#ifndef VA_WAYLAND_LINUX_DMABUF_H
+#define VA_WAYLAND_LINUX_DMABUF_H
+
+#include <stdbool.h>
+#include "va_wayland.h"
+#include "va_backend.h"
+#include "va_backend_wayland.h"
+
+/**
+ * \brief Initializes Wayland/linux-dmabuf layer.
+ *
+ * This is an internal function used to initialize the VA/linux-dmabuf subsystem
+ * if the application is running on a linux-dmabuf-based server.
+ *
+ * @param[in]   pDisplayContext the VA display context
+ * @return true if successful
+ */
+DLL_HIDDEN
+bool
+va_wayland_linux_dmabuf_create(VADisplayContextP pDisplayContext);
+
+DLL_HIDDEN
+void
+va_wayland_linux_dmabuf_destroy(VADisplayContextP pDisplayContext);
+
+#endif /* VA_WAYLAND_LINUX_DMABUF_H */
```

