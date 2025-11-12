```diff
diff --git a/Android.bp b/Android.bp
index eac2642b0..66b29bdcd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -517,6 +517,27 @@ libvpx_arm64_c_srcs = [
     "vpx_util/vpx_write_yuv_frame.c",
 ]
 
+vpxdec_arm64_c_srcs = [
+    "args.c",
+    "ivfdec.c",
+    "md5_utils.c",
+    "tools_common.c",
+    "vpxdec.c",
+    "y4menc.c",
+    "y4minput.c",
+]
+
+vpxdec_arm64_cc_srcs = [
+    "webmdec.cc",
+]
+
+tiny_ssim_arm64_c_srcs = [
+    "tools/tiny_ssim.c",
+    "vpx/src/vpx_image.c",
+    "vpx_mem/vpx_mem.c",
+    "y4minput.c",
+]
+
 libvpx_generic_c_srcs = [
     "config/generic/vpx_config.c",
     "vp8/common/alloccommon.c",
@@ -1379,6 +1400,27 @@ libvpxrc_x86_64_asm_srcs = [
     "vp9/encoder/x86/vp9_error_sse2.asm",
 ]
 
+vpxdec_x86_64_c_srcs = [
+    "args.c",
+    "ivfdec.c",
+    "md5_utils.c",
+    "tools_common.c",
+    "vpxdec.c",
+    "y4menc.c",
+    "y4minput.c",
+]
+
+vpxdec_x86_64_cc_srcs = [
+    "webmdec.cc",
+]
+
+tiny_ssim_x86_64_c_srcs = [
+    "tools/tiny_ssim.c",
+    "vpx/src/vpx_image.c",
+    "vpx_mem/vpx_mem.c",
+    "y4minput.c",
+]
+
 package {
     default_applicable_licenses: ["external_libvpx_license"],
 }
@@ -1824,3 +1866,40 @@ cc_fuzz {
         "libvpx",
     ],
 }
+
+cc_binary {
+    name: "vpxdec",
+    defaults: ["libvpx_defaults"],
+    vendor_available: true,
+    static_libs: [
+        "libvpx",
+        "libwebm_mkvreader",
+        "libyuv_cfi",
+    ],
+
+    arch: {
+        arm64: {
+            srcs: vpxdec_arm64_c_srcs +
+                vpxdec_arm64_cc_srcs,
+        },
+        x86_64: {
+            srcs: vpxdec_x86_64_c_srcs +
+                vpxdec_x86_64_cc_srcs,
+        },
+    },
+}
+
+cc_binary {
+    name: "tiny_ssim",
+    defaults: ["libvpx_defaults"],
+    vendor_available: true,
+
+    arch: {
+        arm64: {
+            srcs: tiny_ssim_arm64_c_srcs,
+        },
+        x86_64: {
+            srcs: tiny_ssim_x86_64_c_srcs,
+        },
+    },
+}
diff --git a/Android.bp.in b/Android.bp.in
index 493fabf50..9d64e9946 100644
--- a/Android.bp.in
+++ b/Android.bp.in
@@ -443,3 +443,40 @@ cc_fuzz {
         "libvpx",
     ],
 }
+
+cc_binary {
+    name: "vpxdec",
+    defaults: ["libvpx_defaults"],
+    vendor_available: true,
+    static_libs: [
+        "libvpx",
+        "libwebm_mkvreader",
+        "libyuv_cfi",
+    ],
+
+    arch: {
+        arm64: {
+            srcs: vpxdec_arm64_c_srcs +
+                vpxdec_arm64_cc_srcs,
+        },
+        x86_64: {
+            srcs: vpxdec_x86_64_c_srcs +
+                vpxdec_x86_64_cc_srcs,
+        },
+    },
+}
+
+cc_binary {
+    name: "tiny_ssim",
+    defaults: ["libvpx_defaults"],
+    vendor_available: true,
+
+    arch: {
+        arm64: {
+            srcs: tiny_ssim_arm64_c_srcs,
+        },
+        x86_64: {
+            srcs: tiny_ssim_x86_64_c_srcs,
+        },
+    },
+}
diff --git a/CHANGELOG b/CHANGELOG
index 2c8d25646..554ff4190 100644
--- a/CHANGELOG
+++ b/CHANGELOG
@@ -1,9 +1,17 @@
+2025-01-09 v1.15.1 "Wigeon Duck"
+  This release bumps up the SO major version and fixes the language about ABI
+  compatibility in the previous release changelog.
+
 2024-10-22 v1.15.0 "Wigeon Duck"
   This release includes new codec control for key frame filtering, more Neon
   optimizations, improvements to RTC encoding and bug fixes.
 
   - Upgrading:
-    This release is ABI compatible with the previous release.
+    This release is ABI incompatible with the previous release.
+
+    It is strongly recommended to skip this release and upgrade to v1.15.1 since
+    the shared object was versioned incorrectly, as shown in
+    https://issues.webmproject.org/issues/384672478.
 
     Temporal filtering improvement that can be turned on with the new codec
     control VP9E_SET_KEY_FRAME_FILTERING, which gives 1+% BD-rate saving with
diff --git a/METADATA b/METADATA
index 6b0719da6..6231d4595 100644
--- a/METADATA
+++ b/METADATA
@@ -10,13 +10,13 @@ third_party {
     tag: "NVD-CPE2.3:cpe:/a:webmproject:libvpx:-"
   }
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 4
+    year: 2025
+    month: 4
+    day: 10
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/webm/libvpx"
-    version: "v1.15.0"
+    version: "v1.15.1"
   }
 }
diff --git a/README b/README
index 2ffc00d07..9f17a63f0 100644
--- a/README
+++ b/README
@@ -65,6 +65,7 @@ COMPILING THE APPLICATIONS/LIBRARIES:
     arm64-darwin21-gcc
     arm64-darwin22-gcc
     arm64-darwin23-gcc
+    arm64-darwin24-gcc
     arm64-linux-gcc
     arm64-win64-gcc
     arm64-win64-vs15
@@ -129,6 +130,7 @@ COMPILING THE APPLICATIONS/LIBRARIES:
     x86_64-darwin21-gcc
     x86_64-darwin22-gcc
     x86_64-darwin23-gcc
+    x86_64-darwin24-gcc
     x86_64-iphonesimulator-gcc
     x86_64-linux-gcc
     x86_64-linux-icc
diff --git a/README.android b/README.android
index aed53f627..704e49beb 100644
--- a/README.android
+++ b/README.android
@@ -6,6 +6,8 @@ License File: libvpx/LICENSE
 Cherry-picks:
 24b568e6f libs.mk: Expose RC_RTC_SRCS as libvpxrc_srcs.txt
 7e78c7169 examples.mk: Expose vpxdec.SRCS as vpxdec_srcs.txt
+b2a919773 Fix test VP8/9 encoder CTS failure
+748eb8338 tools.mk: Expose tiny_ssim.SRCS as tiny_ssim_srcs.txt
 
 Description:
 Contains the sources used to compile libvpx.
diff --git a/build/make/configure.sh b/build/make/configure.sh
index 8220d5cbe..cc5bf6ce4 100644
--- a/build/make/configure.sh
+++ b/build/make/configure.sh
@@ -832,7 +832,7 @@ process_common_toolchain() {
         tgt_isa=x86_64
         tgt_os=`echo $gcctarget | sed 's/.*\(darwin1[0-9]\).*/\1/'`
         ;;
-      *darwin2[0-3]*)
+      *darwin2[0-4]*)
         tgt_isa=`uname -m`
         tgt_os=`echo $gcctarget | sed 's/.*\(darwin2[0-9]\).*/\1/'`
         ;;
@@ -991,7 +991,7 @@ EOF
       add_cflags  "-mmacosx-version-min=10.15"
       add_ldflags "-mmacosx-version-min=10.15"
       ;;
-    *-darwin2[0-3]-*)
+    *-darwin2[0-4]-*)
       add_cflags  "-arch ${toolchain%%-*}"
       add_ldflags "-arch ${toolchain%%-*}"
       ;;
diff --git a/config/arm-neon/vpx_version.h b/config/arm-neon/vpx_version.h
index ecbe6f320..fe20aa1dd 100644
--- a/config/arm-neon/vpx_version.h
+++ b/config/arm-neon/vpx_version.h
@@ -3,9 +3,9 @@
 #define VPX_VERSION_H_
 #define VERSION_MAJOR  1
 #define VERSION_MINOR  15
-#define VERSION_PATCH  0
-#define VERSION_EXTRA  "1679-ge326c38abc"
+#define VERSION_PATCH  1
+#define VERSION_EXTRA  "1727-g22c514c92"
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.15.0-1679-ge326c38abc"
-#define VERSION_STRING      " v1.15.0-1679-ge326c38abc"
+#define VERSION_STRING_NOSP "v1.15.1-1727-g22c514c92"
+#define VERSION_STRING      " v1.15.1-1727-g22c514c92"
 #endif  // VPX_VERSION_H_
diff --git a/config/arm64/vpx_version.h b/config/arm64/vpx_version.h
index ecbe6f320..fe20aa1dd 100644
--- a/config/arm64/vpx_version.h
+++ b/config/arm64/vpx_version.h
@@ -3,9 +3,9 @@
 #define VPX_VERSION_H_
 #define VERSION_MAJOR  1
 #define VERSION_MINOR  15
-#define VERSION_PATCH  0
-#define VERSION_EXTRA  "1679-ge326c38abc"
+#define VERSION_PATCH  1
+#define VERSION_EXTRA  "1727-g22c514c92"
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.15.0-1679-ge326c38abc"
-#define VERSION_STRING      " v1.15.0-1679-ge326c38abc"
+#define VERSION_STRING_NOSP "v1.15.1-1727-g22c514c92"
+#define VERSION_STRING      " v1.15.1-1727-g22c514c92"
 #endif  // VPX_VERSION_H_
diff --git a/config/generic/vpx_version.h b/config/generic/vpx_version.h
index ecbe6f320..fe20aa1dd 100644
--- a/config/generic/vpx_version.h
+++ b/config/generic/vpx_version.h
@@ -3,9 +3,9 @@
 #define VPX_VERSION_H_
 #define VERSION_MAJOR  1
 #define VERSION_MINOR  15
-#define VERSION_PATCH  0
-#define VERSION_EXTRA  "1679-ge326c38abc"
+#define VERSION_PATCH  1
+#define VERSION_EXTRA  "1727-g22c514c92"
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.15.0-1679-ge326c38abc"
-#define VERSION_STRING      " v1.15.0-1679-ge326c38abc"
+#define VERSION_STRING_NOSP "v1.15.1-1727-g22c514c92"
+#define VERSION_STRING      " v1.15.1-1727-g22c514c92"
 #endif  // VPX_VERSION_H_
diff --git a/config/x86/vpx_version.h b/config/x86/vpx_version.h
index ecbe6f320..fe20aa1dd 100644
--- a/config/x86/vpx_version.h
+++ b/config/x86/vpx_version.h
@@ -3,9 +3,9 @@
 #define VPX_VERSION_H_
 #define VERSION_MAJOR  1
 #define VERSION_MINOR  15
-#define VERSION_PATCH  0
-#define VERSION_EXTRA  "1679-ge326c38abc"
+#define VERSION_PATCH  1
+#define VERSION_EXTRA  "1727-g22c514c92"
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.15.0-1679-ge326c38abc"
-#define VERSION_STRING      " v1.15.0-1679-ge326c38abc"
+#define VERSION_STRING_NOSP "v1.15.1-1727-g22c514c92"
+#define VERSION_STRING      " v1.15.1-1727-g22c514c92"
 #endif  // VPX_VERSION_H_
diff --git a/config/x86_64/vpx_version.h b/config/x86_64/vpx_version.h
index ecbe6f320..fe20aa1dd 100644
--- a/config/x86_64/vpx_version.h
+++ b/config/x86_64/vpx_version.h
@@ -3,9 +3,9 @@
 #define VPX_VERSION_H_
 #define VERSION_MAJOR  1
 #define VERSION_MINOR  15
-#define VERSION_PATCH  0
-#define VERSION_EXTRA  "1679-ge326c38abc"
+#define VERSION_PATCH  1
+#define VERSION_EXTRA  "1727-g22c514c92"
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.15.0-1679-ge326c38abc"
-#define VERSION_STRING      " v1.15.0-1679-ge326c38abc"
+#define VERSION_STRING_NOSP "v1.15.1-1727-g22c514c92"
+#define VERSION_STRING      " v1.15.1-1727-g22c514c92"
 #endif  // VPX_VERSION_H_
diff --git a/configure b/configure
index 97e78996e..457bd6b38 100755
--- a/configure
+++ b/configure
@@ -103,6 +103,7 @@ all_platforms="${all_platforms} arm64-darwin20-gcc"
 all_platforms="${all_platforms} arm64-darwin21-gcc"
 all_platforms="${all_platforms} arm64-darwin22-gcc"
 all_platforms="${all_platforms} arm64-darwin23-gcc"
+all_platforms="${all_platforms} arm64-darwin24-gcc"
 all_platforms="${all_platforms} arm64-linux-gcc"
 all_platforms="${all_platforms} arm64-win64-gcc"
 all_platforms="${all_platforms} arm64-win64-vs15"
@@ -167,6 +168,7 @@ all_platforms="${all_platforms} x86_64-darwin20-gcc"
 all_platforms="${all_platforms} x86_64-darwin21-gcc"
 all_platforms="${all_platforms} x86_64-darwin22-gcc"
 all_platforms="${all_platforms} x86_64-darwin23-gcc"
+all_platforms="${all_platforms} x86_64-darwin24-gcc"
 all_platforms="${all_platforms} x86_64-iphonesimulator-gcc"
 all_platforms="${all_platforms} x86_64-linux-gcc"
 all_platforms="${all_platforms} x86_64-linux-icc"
diff --git a/libs.mk b/libs.mk
index d5076b7e8..9025c25af 100644
--- a/libs.mk
+++ b/libs.mk
@@ -318,8 +318,8 @@ $(BUILD_PFX)libvpx_g.a: $(LIBVPX_OBJS)
 # To determine SO_VERSION_{MAJOR,MINOR,PATCH}, calculate c,a,r with current
 # SO_VERSION_* then follow the rules in the link to detemine the new version
 # (c1, a1, r1) and set MAJOR to [c1-a1], MINOR to a1 and PATCH to r1
-SO_VERSION_MAJOR := 9
-SO_VERSION_MINOR := 1
+SO_VERSION_MAJOR := 11
+SO_VERSION_MINOR := 0
 SO_VERSION_PATCH := 0
 ifeq ($(filter darwin%,$(TGT_OS)),$(TGT_OS))
 LIBVPX_SO               := libvpx.$(SO_VERSION_MAJOR).dylib
diff --git a/post_update.sh b/post_update.sh
index 8d587fd96..9b2887184 100755
--- a/post_update.sh
+++ b/post_update.sh
@@ -142,8 +142,12 @@ function gen_source_list {
     config=$(print_config $1)
   fi
   make libvpx_srcs.txt libvpxrc_srcs.txt target=libs $config > /dev/null
+  make vpxdec_srcs.txt target=examples $config > /dev/null
+  make tiny_ssim_srcs.txt target=tools $config > /dev/null
   mv libvpx_srcs.txt libvpx_srcs_$1.txt
   mv libvpxrc_srcs.txt libvpxrc_srcs_$1.txt
+  mv vpxdec_srcs.txt vpxdec_srcs_$1.txt
+  mv tiny_ssim_srcs.txt tiny_ssim_srcs_$1.txt
 }
 
 # Extract a list of C sources from a libvpx_srcs.txt file
@@ -242,6 +246,37 @@ function gen_bp_srcs {
       echo "]"
     fi
 
+    # Collect the vpxdec sources into variables. Note that we're only
+    # interested in x86_64 and arm64 for now, but this can be expanded later.
+    varprefix=vpxdec_${1//-/_}
+    case "$1" in
+      arm64 | x86_64)
+        echo
+        echo "${varprefix}_c_srcs = ["
+        libvpx_srcs_txt_to_c_srcs vpxdec_srcs_$1.txt "\\.c$" ""
+        echo "]"
+        echo
+        echo "${varprefix}_cc_srcs = ["
+        negative_pattern="^third_party/libwebm/\|^third_party/libyuv/"
+        libvpx_srcs_txt_to_c_srcs vpxdec_srcs_$1.txt "\\.cc$" \
+          "${negative_pattern}"
+        echo "]"
+        ;;
+    esac
+    echo
+
+    # Collect the tiny_ssim sources into variables. Note that we're only
+    # interested in x86_64 and arm64 for now, but this can be expanded later.
+    varprefix=tiny_ssim_${1//-/_}
+    case "$1" in
+      arm64 | x86_64)
+        echo
+        echo "${varprefix}_c_srcs = ["
+        libvpx_srcs_txt_to_c_srcs tiny_ssim_srcs_$1.txt "\\.c$" ""
+        echo "]"
+        echo
+        ;;
+    esac
     echo
   ) > config_$1.bp
 }
diff --git a/tools.mk b/tools.mk
index dd2ebeb3d..79bb0cb8d 100644
--- a/tools.mk
+++ b/tools.mk
@@ -91,6 +91,13 @@ INSTALL-BINS-$(CONFIG_MSVS) += $(foreach p,$(VS_PLATFORMS),\
 $(foreach proj,$(call enabled,PROJECTS),\
     $(eval $(call vcproj_template,$(proj))))
 
+# Generate a list of all enabled sources, in particular for exporting to gyp
+# based build systems.
+tiny_ssim_srcs.txt:
+	@echo "    [CREATE] $@"
+	@echo $(tiny_ssim.SRCS) | xargs -n1 echo | LC_ALL=C sort -u > $@
+CLEAN-OBJS += tiny_ssim_srcs.txt
+
 #
 # Documentation Rules
 #
diff --git a/vpx/vp8cx.h b/vpx/vp8cx.h
index 94516d400..4e29725c2 100644
--- a/vpx/vp8cx.h
+++ b/vpx/vp8cx.h
@@ -673,14 +673,6 @@ enum vp8e_enc_control_id {
    */
   VP9E_SET_TPL,
 
-  /*!\brief Codec control function to enable key frame temporal filtering.
-   *
-   * Vp9 allows the encoder to run key frame temporal filtering and use it to
-   * improve the compression performance. To enable, set this parameter to be
-   * 1. The default value is set to be 0.
-   */
-  VP9E_SET_KEY_FRAME_FILTERING,
-
   /*!\brief Codec control function to enable postencode frame drop.
    *
    * This will allow encoder to drop frame after it's encoded.
@@ -776,6 +768,14 @@ enum vp8e_enc_control_id {
    *
    */
   VP9E_SET_QUANTIZER_ONE_PASS,
+
+  /*!\brief Codec control function to enable key frame temporal filtering.
+   *
+   * Vp9 allows the encoder to run key frame temporal filtering and use it to
+   * improve the compression performance. To enable, set this parameter to be
+   * 1. The default value is set to be 0.
+   */
+  VP9E_SET_KEY_FRAME_FILTERING,
 };
 
 /*!\brief vpx 1-D scaling mode
@@ -1086,8 +1086,6 @@ VPX_CTRL_USE_TYPE(VP9E_SET_SVC_SPATIAL_LAYER_SYNC,
 #define VPX_CTRL_VP9E_SET_SVC_SPATIAL_LAYER_SYNC
 VPX_CTRL_USE_TYPE(VP9E_SET_TPL, int)
 #define VPX_CTRL_VP9E_SET_TPL
-VPX_CTRL_USE_TYPE(VP9E_SET_KEY_FRAME_FILTERING, int)
-#define VPX_CTRL_VP9E_SET_KEY_FRAME_FILTERING
 VPX_CTRL_USE_TYPE(VP9E_SET_POSTENCODE_DROP, unsigned int)
 #define VPX_CTRL_VP9E_SET_POSTENCODE_DROP
 VPX_CTRL_USE_TYPE(VP9E_SET_DELTA_Q_UV, int)
@@ -1108,6 +1106,8 @@ VPX_CTRL_USE_TYPE(VP8E_SET_RTC_EXTERNAL_RATECTRL, int)
 #define VPX_CTRL_VP8E_SET_RTC_EXTERNAL_RATECTRL
 VPX_CTRL_USE_TYPE(VP9E_SET_QUANTIZER_ONE_PASS, int)
 #define VPX_CTRL_VP9E_SET_QUANTIZER_ONE_PASS
+VPX_CTRL_USE_TYPE(VP9E_SET_KEY_FRAME_FILTERING, int)
+#define VPX_CTRL_VP9E_SET_KEY_FRAME_FILTERING
 
 /*!\endcond */
 /*! @} - end defgroup vp8_encoder */
diff --git a/vpx/vpx_ext_ratectrl.h b/vpx/vpx_ext_ratectrl.h
index 2396f874a..4820d3676 100644
--- a/vpx/vpx_ext_ratectrl.h
+++ b/vpx/vpx_ext_ratectrl.h
@@ -30,7 +30,7 @@ extern "C" {
  * types, removing or reassigning enums, adding/removing/rearranging
  * fields to structures.
  */
-#define VPX_EXT_RATECTRL_ABI_VERSION (5 + VPX_TPL_ABI_VERSION)
+#define VPX_EXT_RATECTRL_ABI_VERSION (6 + VPX_TPL_ABI_VERSION)
 
 /*!\brief Corresponds to MAX_STATIC_GF_GROUP_LENGTH defined in vp9_ratectrl.h
  */
diff --git a/vpx_ports/vpx_timer.h b/vpx_ports/vpx_timer.h
index 4934d5296..55e7891e1 100644
--- a/vpx_ports/vpx_timer.h
+++ b/vpx_ports/vpx_timer.h
@@ -31,17 +31,17 @@
 /*
  * POSIX specific includes
  */
-#include <sys/time.h>
+#include <time.h>
 
 /* timersub is not provided by msys at this time. */
-#ifndef timersub
-#define timersub(a, b, result)                       \
+#ifndef timersub_ns
+#define timersub_ns(a, b, result)                    \
   do {                                               \
     (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
-    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
-    if ((result)->tv_usec < 0) {                     \
+    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec; \
+    if ((result)->tv_nsec < 0) {                     \
       --(result)->tv_sec;                            \
-      (result)->tv_usec += 1000000;                  \
+      (result)->tv_nsec += 1000000000;               \
     }                                                \
   } while (0)
 #endif
@@ -51,23 +51,27 @@ struct vpx_usec_timer {
 #if defined(_WIN32)
   LARGE_INTEGER begin, end;
 #else
-  struct timeval begin, end;
+  struct timespec begin, end;
 #endif
 };
 
 static INLINE void vpx_usec_timer_start(struct vpx_usec_timer *t) {
 #if defined(_WIN32)
   QueryPerformanceCounter(&t->begin);
+#elif defined(CLOCK_MONOTONIC_RAW)
+  clock_gettime(CLOCK_MONOTONIC_RAW, &t->begin);
 #else
-  gettimeofday(&t->begin, NULL);
+  clock_gettime(CLOCK_MONOTONIC, &t->begin);
 #endif
 }
 
 static INLINE void vpx_usec_timer_mark(struct vpx_usec_timer *t) {
 #if defined(_WIN32)
   QueryPerformanceCounter(&t->end);
+#elif defined(CLOCK_MONOTONIC_RAW)
+  clock_gettime(CLOCK_MONOTONIC_RAW, &t->end);
 #else
-  gettimeofday(&t->end, NULL);
+  clock_gettime(CLOCK_MONOTONIC, &t->end);
 #endif
 }
 
@@ -80,18 +84,18 @@ static INLINE int64_t vpx_usec_timer_elapsed(struct vpx_usec_timer *t) {
   QueryPerformanceFrequency(&freq);
   return diff.QuadPart * 1000000 / freq.QuadPart;
 #else
-  struct timeval diff;
+  struct timespec diff;
 
-  timersub(&t->end, &t->begin, &diff);
-  return (int64_t)diff.tv_sec * 1000000 + diff.tv_usec;
+  timersub_ns(&t->end, &t->begin, &diff);
+  return (int64_t)diff.tv_sec * 1000000 + diff.tv_nsec / 1000;
 #endif
 }
 
 #else /* CONFIG_OS_SUPPORT = 0*/
 
 /* Empty timer functions if CONFIG_OS_SUPPORT = 0 */
-#ifndef timersub
-#define timersub(a, b, result)
+#ifndef timersub_ns
+#define timersub_ns(a, b, result)
 #endif
 
 struct vpx_usec_timer {
```

