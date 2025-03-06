```diff
diff --git a/Android.bp b/Android.bp
index 2f727d20..c38c56f8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,8 @@ build = ["Android.sources.bp"]
 cc_defaults {
     name: "libdrm_defaults",
     cflags: [
+        "-D_GNU_SOURCE",
+
         // XXX: Consider moving these to config.h analogous to autoconf.
         "-DMAJOR_IN_SYSMACROS=1",
         "-DHAVE_VISIBILITY=1",
@@ -52,7 +54,6 @@ cc_defaults {
         "-Wno-deprecated-declarations",
         "-Wno-format",
         "-Wno-gnu-variable-sized-type-not-at-end",
-        "-Wno-implicit-function-declaration",
         "-Wno-int-conversion",
         "-Wno-missing-field-initializers",
         "-Wno-pointer-arith",
@@ -77,6 +78,14 @@ cc_library_headers {
     ],
 }
 
+genrule {
+    name: "generated_static_table_fourcc_h",
+    out: ["generated_static_table_fourcc.h"],
+    srcs: ["include/drm/drm_fourcc.h"],
+    tool_files: ["gen_table_fourcc.py"],
+    cmd: "python3 $(location gen_table_fourcc.py) $(in) $(out)",
+}
+
 // Library for the device
 cc_library {
     name: "libdrm",
@@ -93,11 +102,12 @@ cc_library {
         "libdrm_sources",
     ],
 
-    export_include_dirs: [
-        "include/drm",
-        "android",
+    generated_headers: [
+        "generated_static_table_fourcc_h",
     ],
 
+    export_include_dirs: ["include/drm", "android"],
+
     cflags: [
         "-Wno-enum-conversion",
         "-Wno-pointer-arith",
@@ -148,6 +158,6 @@ rust_bindgen {
         "//apex_available:platform",
     ],
     visibility: [
-        "//external/rust/crates/drm-ffi",
+        "//external/rust/android-crates-io/crates/drm-ffi",
     ],
 }
diff --git a/METADATA b/METADATA
index 22eb00a9..8ba2f5d3 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update libdrm
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/libdrm
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libdrm"
 description: "libdrm Direct Rendering Manager library and headers"
 third_party {
-  url {
-    type: GIT
-    value: "https://gitlab.freedesktop.org/mesa/drm.git"
-  }
-  version: "libdrm-2.4.109"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 2
-    day: 17
+    year: 2024
+    month: 12
+    day: 4
+  }
+  identifier {
+    type: "Git"
+    value: "https://gitlab.freedesktop.org/mesa/drm.git"
+    version: "libdrm-2.4.124"
   }
 }
diff --git a/include/drm/README b/include/drm/README
index ea2320cc..750a5a5a 100644
--- a/include/drm/README
+++ b/include/drm/README
@@ -71,7 +71,7 @@ Note: One should not do _any_ changes to the files apart from the steps below.
 
 In order to update the files do the following:
  - Switch to a Linux kernel tree/branch which is not rebased.
-   For example: drm-next (https://cgit.freedesktop.org/drm/drm)
+   For example: drm-next (https://gitlab.freedesktop.org/drm/kernel/)
  - Install the headers via `make headers_install' to a separate location.
  - Copy the drm header[s] + git add + git commit.
  - Note: Your commit message must include:
diff --git a/meson.build b/meson.build
index 80e92779..2991c8ff 100644
--- a/meson.build
+++ b/meson.build
@@ -26,7 +26,7 @@
 project(
   'libdrm',
   ['c'],
-  version : '2.4.122',
+  version : '2.4.124',
   license : 'MIT',
   meson_version : '>= 0.59',
   default_options : ['buildtype=debugoptimized', 'c_std=c11'],
@@ -178,7 +178,7 @@ else
 endif
 
 # The header is not required on Linux, and is in fact deprecated in glibc 2.30+
-if ['linux'].contains(host_machine.system())
+if host_machine.system() == 'linux'
   config.set10('HAVE_SYS_SYSCTL_H', false)
 else
   # From Niclas Zeising:
@@ -252,6 +252,10 @@ if target_machine.endian() == 'big'
   config.set('HAVE_BIG_ENDIAN', 1)
 endif
 
+if android
+  config.set('BIONIC_IOCTL_NO_SIGNEDNESS_OVERLOAD', 1)
+endif
+
 config_file = configure_file(
   configuration : config,
   output : 'config.h',
diff --git a/tests/Android.bp b/tests/Android.bp
index bff7f991..05a3b3a2 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -12,4 +12,5 @@ subdirs = ["*"]
 cc_library_headers {
     name: "libdrm_test_headers",
     export_include_dirs: ["."],
+    vendor_available: true,
 }
diff --git a/tests/modetest/Android.bp b/tests/modetest/Android.bp
index 87120121..10843c39 100644
--- a/tests/modetest/Android.bp
+++ b/tests/modetest/Android.bp
@@ -18,4 +18,5 @@ cc_binary {
 
     shared_libs: ["libdrm"],
     static_libs: ["libdrm_util"],
+    vendor_available: true,
 }
diff --git a/tests/modetest/buffers.c b/tests/modetest/buffers.c
index 576e2cc7..165b9529 100644
--- a/tests/modetest/buffers.c
+++ b/tests/modetest/buffers.c
@@ -116,9 +116,10 @@ bo_create(int fd, unsigned int format,
 	  unsigned int handles[4], unsigned int pitches[4],
 	  unsigned int offsets[4], enum util_fill_pattern pattern)
 {
-	unsigned int virtual_height;
+	unsigned int virtual_height, xsub, ysub;
 	struct bo *bo;
 	unsigned int bpp;
+	bool is_planar;
 	void *planes[3] = { 0, };
 	void *virtual;
 	int ret;
@@ -145,6 +146,10 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_NV42:
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
+	case DRM_FORMAT_YUV422:
+	case DRM_FORMAT_YVU422:
+	case DRM_FORMAT_YUV444:
+	case DRM_FORMAT_YVU444:
 		bpp = 8;
 		break;
 
@@ -223,26 +228,42 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_NV15:
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
-		virtual_height = height * 3 / 2;
+		is_planar = true;
+		xsub = 2;
+		ysub = 2;
 		break;
 
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
 	case DRM_FORMAT_NV20:
-		virtual_height = height * 2;
+	case DRM_FORMAT_YUV422:
+	case DRM_FORMAT_YVU422:
+		is_planar = true;
+		xsub = 2;
+		ysub = 1;
 		break;
 
 	case DRM_FORMAT_NV24:
 	case DRM_FORMAT_NV42:
 	case DRM_FORMAT_NV30:
-		virtual_height = height * 3;
+	case DRM_FORMAT_YUV444:
+	case DRM_FORMAT_YVU444:
+		is_planar = true;
+		xsub = 1;
+		ysub = 1;
 		break;
 
 	default:
-		virtual_height = height;
+		is_planar = false;
+		xsub = 1;
+		ysub = 1;
 		break;
 	}
 
+	virtual_height = height;
+	if (is_planar)
+		virtual_height += height * 2 / xsub / ysub;
+
 	bo = bo_create_dumb(fd, width, virtual_height, bpp);
 	if (!bo)
 		return NULL;
@@ -275,25 +296,14 @@ bo_create(int fd, unsigned int format,
 	case DRM_FORMAT_NV16:
 	case DRM_FORMAT_NV61:
 	case DRM_FORMAT_NV15:
-	case DRM_FORMAT_NV20:
-		offsets[0] = 0;
-		handles[0] = bo->handle;
-		pitches[0] = bo->pitch;
-		pitches[1] = pitches[0];
-		offsets[1] = pitches[0] * height;
-		handles[1] = bo->handle;
-
-		planes[0] = virtual;
-		planes[1] = virtual + offsets[1];
-		break;
-
 	case DRM_FORMAT_NV24:
 	case DRM_FORMAT_NV42:
+	case DRM_FORMAT_NV20:
 	case DRM_FORMAT_NV30:
 		offsets[0] = 0;
 		handles[0] = bo->handle;
 		pitches[0] = bo->pitch;
-		pitches[1] = pitches[0] * 2;
+		pitches[1] = pitches[0] * 2 / xsub;
 		offsets[1] = pitches[0] * height;
 		handles[1] = bo->handle;
 
@@ -303,14 +313,18 @@ bo_create(int fd, unsigned int format,
 
 	case DRM_FORMAT_YUV420:
 	case DRM_FORMAT_YVU420:
+	case DRM_FORMAT_YUV422:
+	case DRM_FORMAT_YVU422:
+	case DRM_FORMAT_YUV444:
+	case DRM_FORMAT_YVU444:
 		offsets[0] = 0;
 		handles[0] = bo->handle;
 		pitches[0] = bo->pitch;
-		pitches[1] = pitches[0] / 2;
+		pitches[1] = pitches[0] / xsub;
 		offsets[1] = pitches[0] * height;
 		handles[1] = bo->handle;
 		pitches[2] = pitches[1];
-		offsets[2] = offsets[1] + pitches[1] * height / 2;
+		offsets[2] = offsets[1] + pitches[1] * height / ysub;
 		handles[2] = bo->handle;
 
 		planes[0] = virtual;
diff --git a/tests/util/Android.bp b/tests/util/Android.bp
index 0322c2ac..7cc95a17 100644
--- a/tests/util/Android.bp
+++ b/tests/util/Android.bp
@@ -41,4 +41,5 @@ cc_library_static {
     shared_libs: ["libdrm"],
     header_libs: ["libdrm_test_headers"],
     export_header_lib_headers: ["libdrm_test_headers"],
+    vendor_available: true,
 }
diff --git a/tests/util/format.c b/tests/util/format.c
index eda3c671..c6235441 100644
--- a/tests/util/format.c
+++ b/tests/util/format.c
@@ -62,6 +62,10 @@ static const struct util_format_info format_info[] = {
 	/* YUV planar */
 	{ DRM_FORMAT_YUV420, "YU12", MAKE_YUV_INFO(YUV_YCbCr, 2, 2, 1) },
 	{ DRM_FORMAT_YVU420, "YV12", MAKE_YUV_INFO(YUV_YCrCb, 2, 2, 1) },
+	{ DRM_FORMAT_YUV422, "YU16", MAKE_YUV_INFO(YUV_YCbCr, 2, 1, 1) },
+	{ DRM_FORMAT_YVU422, "YV16", MAKE_YUV_INFO(YUV_YCrCb, 2, 1, 1) },
+	{ DRM_FORMAT_YUV444, "YU24", MAKE_YUV_INFO(YUV_YCbCr, 1, 1, 1) },
+	{ DRM_FORMAT_YVU444, "YV24", MAKE_YUV_INFO(YUV_YCrCb, 1, 1, 1) },
 	/* RGB16 */
 	{ DRM_FORMAT_ARGB4444, "AR12", MAKE_RGB_INFO(4, 8, 4, 4, 4, 0, 4, 12) },
 	{ DRM_FORMAT_XRGB4444, "XR12", MAKE_RGB_INFO(4, 8, 4, 4, 4, 0, 0, 0) },
diff --git a/tests/util/kms.c b/tests/util/kms.c
index 8bbc2275..5c66da3f 100644
--- a/tests/util/kms.c
+++ b/tests/util/kms.c
@@ -42,6 +42,8 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#include <fcntl.h>
+#include <unistd.h>
 
 #include "xf86drm.h"
 #include "xf86drmMode.h"
@@ -96,59 +98,42 @@ const char *util_lookup_connector_status_name(unsigned int status)
 				     ARRAY_SIZE(connector_status_names));
 }
 
-static const char * const modules[] = {
-	"i915",
-	"amdgpu",
-	"radeon",
-	"nouveau",
-	"vmwgfx",
-	"omapdrm",
-	"exynos",
-	"tilcdc",
-	"msm",
-	"sti",
-	"tegra",
-	"imx-drm",
-	"rockchip",
-	"atmel-hlcdc",
-	"fsl-dcu-drm",
-	"vc4",
-	"virtio_gpu",
-	"mediatek",
-	"meson",
-	"pl111",
-	"stm",
-	"sun4i-drm",
-	"armada-drm",
-	"komeda",
-	"imx-dcss",
-	"mxsfb-drm",
-	"simpledrm",
-	"imx-lcdif",
-	"vkms",
-	"tidss",
-};
-
 int util_open(const char *device, const char *module)
 {
-	int fd;
+	int fd = -1;
+	drmVersionPtr version;
 
-	if (module) {
+	if (module || device) {
 		fd = drmOpen(module, device);
 		if (fd < 0) {
-			fprintf(stderr, "failed to open device '%s': %s\n",
-				module, strerror(errno));
+			fprintf(stderr, "failed to open device '%s' with busid '%s': %s\n",
+				module, device, strerror(errno));
 			return -errno;
 		}
 	} else {
 		unsigned int i;
+		drmDevicePtr devices[64];
+		int num_devices = drmGetDevices2(0, devices, ARRAY_SIZE(devices));
+		if (num_devices < 0) {
+			fprintf(stderr, "drmGetDevices2() failed with %s\n", strerror(num_devices));
+			return num_devices;
+		}
 
-		for (i = 0; i < ARRAY_SIZE(modules); i++) {
-			printf("trying to open device '%s'...", modules[i]);
+		for (i = 0; i < num_devices; i++) {
+			drmDevicePtr device = devices[i];
+			// Select only primary nodes
+			if ((device->available_nodes & 1 << DRM_NODE_PRIMARY) == 0)
+				continue;
+
+			printf("trying to open device '%s'... ", device->nodes[DRM_NODE_PRIMARY]);
+			fd = open(device->nodes[DRM_NODE_PRIMARY], O_RDWR | O_CLOEXEC);
 
-			fd = drmOpen(modules[i], device);
 			if (fd < 0) {
 				printf("failed\n");
+			} else if (!drmIsKMS(fd)) {
+				printf("is not a KMS device\n");
+				close(fd);
+				fd = -1;
 			} else {
 				printf("done\n");
 				break;
@@ -161,5 +146,15 @@ int util_open(const char *device, const char *module)
 		}
 	}
 
+	version = drmGetVersion(fd);
+	printf("opened device `%s` on driver `%s` (version %d.%d.%d at %s)\n",
+	       version->desc,
+	       version->name,
+	       version->version_major,
+	       version->version_minor,
+	       version->version_patchlevel,
+	       version->date);
+	drmFreeVersion(version);
+
 	return fd;
 }
diff --git a/tests/util/pattern.c b/tests/util/pattern.c
index 2ff9c033..e5f20c50 100644
--- a/tests/util/pattern.c
+++ b/tests/util/pattern.c
@@ -1229,10 +1229,14 @@ static void fill_smpte(const struct util_format_info *info, void *planes[3],
 						   stride);
 
 	case DRM_FORMAT_YUV420:
+	case DRM_FORMAT_YUV422:
+	case DRM_FORMAT_YUV444:
 		return fill_smpte_yuv_planar(&info->yuv, planes[0], planes[1],
 					     planes[2], width, height, stride);
 
 	case DRM_FORMAT_YVU420:
+	case DRM_FORMAT_YVU422:
+	case DRM_FORMAT_YVU444:
 		return fill_smpte_yuv_planar(&info->yuv, planes[0], planes[2],
 					     planes[1], width, height, stride);
 
@@ -1646,10 +1650,14 @@ static void fill_tiles(const struct util_format_info *info, void *planes[3],
 						   width, height, stride);
 
 	case DRM_FORMAT_YUV420:
+	case DRM_FORMAT_YUV422:
+	case DRM_FORMAT_YUV444:
 		return fill_tiles_yuv_planar(info, planes[0], planes[1],
 					     planes[2], width, height, stride);
 
 	case DRM_FORMAT_YVU420:
+	case DRM_FORMAT_YVU422:
+	case DRM_FORMAT_YVU444:
 		return fill_tiles_yuv_planar(info, planes[0], planes[2],
 					     planes[1], width, height, stride);
 
diff --git a/xf86drm.c b/xf86drm.c
index 5f0eddc4..6ca56263 100644
--- a/xf86drm.c
+++ b/xf86drm.c
@@ -201,18 +201,6 @@ static const struct drmFormatVendorModifierInfo arm_mode_value_table[] = {
     { AFBC_FORMAT_MOD_USM,          "USM" },
 };
 
-static bool is_x_t_amd_gfx9_tile(uint64_t tile)
-{
-    switch (tile) {
-    case AMD_FMT_MOD_TILE_GFX9_64K_S_X:
-    case AMD_FMT_MOD_TILE_GFX9_64K_D_X:
-    case AMD_FMT_MOD_TILE_GFX9_64K_R_X:
-           return true;
-    }
-
-    return false;
-}
-
 static bool
 drmGetAfbcFormatModifierNameFromArm(uint64_t modifier, FILE *fp)
 {
@@ -368,158 +356,159 @@ drmGetFormatModifierNameFromNvidia(uint64_t modifier)
     return  NULL;
 }
 
-static void
-drmGetFormatModifierNameFromAmdDcc(uint64_t modifier, FILE *fp)
-{
-    uint64_t dcc_max_compressed_block =
-                AMD_FMT_MOD_GET(DCC_MAX_COMPRESSED_BLOCK, modifier);
-    uint64_t dcc_retile = AMD_FMT_MOD_GET(DCC_RETILE, modifier);
-
-    const char *dcc_max_compressed_block_str = NULL;
-
-    fprintf(fp, ",DCC");
-
-    if (dcc_retile)
-        fprintf(fp, ",DCC_RETILE");
-
-    if (!dcc_retile && AMD_FMT_MOD_GET(DCC_PIPE_ALIGN, modifier))
-        fprintf(fp, ",DCC_PIPE_ALIGN");
-
-    if (AMD_FMT_MOD_GET(DCC_INDEPENDENT_64B, modifier))
-        fprintf(fp, ",DCC_INDEPENDENT_64B");
-
-    if (AMD_FMT_MOD_GET(DCC_INDEPENDENT_128B, modifier))
-        fprintf(fp, ",DCC_INDEPENDENT_128B");
-
-    switch (dcc_max_compressed_block) {
-    case AMD_FMT_MOD_DCC_BLOCK_64B:
-        dcc_max_compressed_block_str = "64B";
-        break;
-    case AMD_FMT_MOD_DCC_BLOCK_128B:
-        dcc_max_compressed_block_str = "128B";
-        break;
-    case AMD_FMT_MOD_DCC_BLOCK_256B:
-        dcc_max_compressed_block_str = "256B";
-        break;
-    }
-
-    if (dcc_max_compressed_block_str)
-        fprintf(fp, ",DCC_MAX_COMPRESSED_BLOCK=%s",
-                dcc_max_compressed_block_str);
-
-    if (AMD_FMT_MOD_GET(DCC_CONSTANT_ENCODE, modifier))
-        fprintf(fp, ",DCC_CONSTANT_ENCODE");
-}
-
-static void
-drmGetFormatModifierNameFromAmdTile(uint64_t modifier, FILE *fp)
-{
-    uint64_t pipe_xor_bits, bank_xor_bits, packers, rb;
-    uint64_t pipe, pipe_align, dcc, dcc_retile, tile_version;
-
-    pipe_align = AMD_FMT_MOD_GET(DCC_PIPE_ALIGN, modifier);
-    pipe_xor_bits = AMD_FMT_MOD_GET(PIPE_XOR_BITS, modifier);
-    dcc = AMD_FMT_MOD_GET(DCC, modifier);
-    dcc_retile = AMD_FMT_MOD_GET(DCC_RETILE, modifier);
-    tile_version = AMD_FMT_MOD_GET(TILE_VERSION, modifier);
-
-    fprintf(fp, ",PIPE_XOR_BITS=%"PRIu64, pipe_xor_bits);
-
-    if (tile_version == AMD_FMT_MOD_TILE_VER_GFX9) {
-        bank_xor_bits = AMD_FMT_MOD_GET(BANK_XOR_BITS, modifier);
-        fprintf(fp, ",BANK_XOR_BITS=%"PRIu64, bank_xor_bits);
-    }
-
-    if (tile_version == AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS) {
-        packers = AMD_FMT_MOD_GET(PACKERS, modifier);
-        fprintf(fp, ",PACKERS=%"PRIu64, packers);
-    }
-
-    if (dcc && tile_version == AMD_FMT_MOD_TILE_VER_GFX9) {
-        rb = AMD_FMT_MOD_GET(RB, modifier);
-        fprintf(fp, ",RB=%"PRIu64, rb);
-    }
-
-    if (dcc && tile_version == AMD_FMT_MOD_TILE_VER_GFX9 &&
-        (dcc_retile || pipe_align)) {
-        pipe = AMD_FMT_MOD_GET(PIPE, modifier);
-        fprintf(fp, ",PIPE_%"PRIu64, pipe);
-    }
-}
-
 static char *
 drmGetFormatModifierNameFromAmd(uint64_t modifier)
 {
-    uint64_t tile, tile_version, dcc;
+    static const char *gfx9_gfx11_tile_strings[32] = {
+        "LINEAR",
+        "256B_S",
+        "256B_D",
+        "256B_R",
+        "4KB_Z",
+        "4KB_S",
+        "4KB_D",
+        "4KB_R",
+        "64KB_Z",
+        "64KB_S",
+        "64KB_D",
+        "64KB_R",
+        "INVALID12",
+        "INVALID13",
+        "INVALID14",
+        "INVALID15",
+        "64KB_Z_T",
+        "64KB_S_T",
+        "64KB_D_T",
+        "64KB_R_T",
+        "4KB_Z_X",
+        "4KB_S_X",
+        "4KB_D_X",
+        "4KB_R_X",
+        "64KB_Z_X",
+        "64KB_S_X",
+        "64KB_D_X",
+        "64KB_R_X",
+        "256KB_Z_X",
+        "256KB_S_X",
+        "256KB_D_X",
+        "256KB_R_X",
+    };
+    static const char *gfx12_tile_strings[32] = {
+        "LINEAR",
+        "256B_2D",
+        "4KB_2D",
+        "64KB_2D",
+        "256KB_2D",
+        "4KB_3D",
+        "64KB_3D",
+        "256KB_3D",
+        /* other values are unused */
+    };
+    uint64_t tile_version = AMD_FMT_MOD_GET(TILE_VERSION, modifier);
     FILE *fp;
     char *mod_amd = NULL;
     size_t size = 0;
 
-    const char *str_tile = NULL;
-    const char *str_tile_version = NULL;
-
-    tile = AMD_FMT_MOD_GET(TILE, modifier);
-    tile_version = AMD_FMT_MOD_GET(TILE_VERSION, modifier);
-    dcc = AMD_FMT_MOD_GET(DCC, modifier);
-
     fp = open_memstream(&mod_amd, &size);
     if (!fp)
         return NULL;
 
-    /* add tile  */
     switch (tile_version) {
     case AMD_FMT_MOD_TILE_VER_GFX9:
-        str_tile_version = "GFX9";
+        fprintf(fp, "GFX9");
         break;
     case AMD_FMT_MOD_TILE_VER_GFX10:
-        str_tile_version = "GFX10";
+        fprintf(fp, "GFX10");
         break;
     case AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS:
-        str_tile_version = "GFX10_RBPLUS";
+        fprintf(fp, "GFX10_RBPLUS");
         break;
     case AMD_FMT_MOD_TILE_VER_GFX11:
-        str_tile_version = "GFX11";
+        fprintf(fp, "GFX11");
         break;
-    }
-
-    if (str_tile_version) {
-        fprintf(fp, "%s", str_tile_version);
-    } else {
+    case AMD_FMT_MOD_TILE_VER_GFX12:
+        fprintf(fp, "GFX12");
+        break;
+    default:
         fclose(fp);
         free(mod_amd);
         return NULL;
     }
 
-    /* add tile str */
-    switch (tile) {
-    case AMD_FMT_MOD_TILE_GFX9_64K_S:
-        str_tile = "GFX9_64K_S";
-        break;
-    case AMD_FMT_MOD_TILE_GFX9_64K_D:
-        str_tile = "GFX9_64K_D";
-        break;
-    case AMD_FMT_MOD_TILE_GFX9_64K_S_X:
-        str_tile = "GFX9_64K_S_X";
-        break;
-    case AMD_FMT_MOD_TILE_GFX9_64K_D_X:
-        str_tile = "GFX9_64K_D_X";
-        break;
-    case AMD_FMT_MOD_TILE_GFX9_64K_R_X:
-        str_tile = "GFX9_64K_R_X";
-        break;
-    case AMD_FMT_MOD_TILE_GFX11_256K_R_X:
-        str_tile = "GFX11_256K_R_X";
-        break;
-    }
+    if (tile_version >= AMD_FMT_MOD_TILE_VER_GFX12) {
+        unsigned tile = AMD_FMT_MOD_GET(TILE, modifier);
+
+        fprintf(fp, ",%s", gfx12_tile_strings[tile]);
+
+        if (AMD_FMT_MOD_GET(DCC, modifier)) {
+            fprintf(fp, ",DCC,DCC_MAX_COMPRESSED_BLOCK=%uB",
+                    64 << AMD_FMT_MOD_GET(DCC_MAX_COMPRESSED_BLOCK, modifier));
+
+            /* Other DCC fields are unused by GFX12. */
+        }
+    } else {
+        unsigned tile = AMD_FMT_MOD_GET(TILE, modifier);
+
+        fprintf(fp, ",%s", gfx9_gfx11_tile_strings[tile]);
+
+        /* All *_T and *_X modes are affected by chip-specific fields. */
+        if (tile >= 16) {
+            fprintf(fp, ",PIPE_XOR_BITS=%u",
+                    (unsigned)AMD_FMT_MOD_GET(PIPE_XOR_BITS, modifier));
+
+            switch (tile_version) {
+            case AMD_FMT_MOD_TILE_VER_GFX9:
+                fprintf(fp, ",BANK_XOR_BITS=%u",
+                        (unsigned)AMD_FMT_MOD_GET(BANK_XOR_BITS, modifier));
+                break;
+
+            case AMD_FMT_MOD_TILE_VER_GFX10:
+                /* Nothing else for GFX10. */
+                break;
+
+            case AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS:
+            case AMD_FMT_MOD_TILE_VER_GFX11:
+                /* This also determines the DCC layout, but DCC is only legal
+                 * with tile=27 and tile=31 (*_R_X modes).
+                 */
+                fprintf(fp, ",PACKERS=%u",
+                        (unsigned)AMD_FMT_MOD_GET(PACKERS, modifier));
+                break;
+            }
+        }
+
+        if (AMD_FMT_MOD_GET(DCC, modifier)) {
+            if (tile_version == AMD_FMT_MOD_TILE_VER_GFX9 &&
+                (AMD_FMT_MOD_GET(DCC_PIPE_ALIGN, modifier) ||
+                 AMD_FMT_MOD_GET(DCC_RETILE, modifier))) {
+                /* These two only determine the layout of
+                 * the non-displayable DCC plane.
+                 */
+                fprintf(fp, ",RB=%u",
+                        (unsigned)AMD_FMT_MOD_GET(RB, modifier));
+                fprintf(fp, ",PIPE=%u",
+                        (unsigned)AMD_FMT_MOD_GET(PIPE, modifier));
+            }
+
+            fprintf(fp, ",DCC,DCC_MAX_COMPRESSED_BLOCK=%uB",
+                    64 << AMD_FMT_MOD_GET(DCC_MAX_COMPRESSED_BLOCK, modifier));
 
-    if (str_tile)
-        fprintf(fp, ",%s", str_tile);
+            if (AMD_FMT_MOD_GET(DCC_INDEPENDENT_64B, modifier))
+                fprintf(fp, ",DCC_INDEPENDENT_64B");
 
-    if (dcc)
-        drmGetFormatModifierNameFromAmdDcc(modifier, fp);
+            if (AMD_FMT_MOD_GET(DCC_INDEPENDENT_128B, modifier))
+                fprintf(fp, ",DCC_INDEPENDENT_128B");
 
-    if (tile_version >= AMD_FMT_MOD_TILE_VER_GFX9 && is_x_t_amd_gfx9_tile(tile))
-        drmGetFormatModifierNameFromAmdTile(modifier, fp);
+            if (AMD_FMT_MOD_GET(DCC_CONSTANT_ENCODE, modifier))
+                fprintf(fp, ",DCC_CONSTANT_ENCODE");
+
+            if (AMD_FMT_MOD_GET(DCC_PIPE_ALIGN, modifier))
+                fprintf(fp, ",DCC_PIPE_ALIGN");
+
+            if (AMD_FMT_MOD_GET(DCC_RETILE, modifier))
+                fprintf(fp, ",DCC_RETILE");
+        }
+    }
 
     fclose(fp);
     return mod_amd;
```

