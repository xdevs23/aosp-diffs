```diff
diff --git a/OWNERS b/OWNERS
index e03c24d..3a6b617 100644
--- a/OWNERS
+++ b/OWNERS
@@ -9,6 +9,7 @@ mcasas@chromium.org
 niwa@chromium.org
 olv@google.com
 robdclark@chromium.org
+ryanneph@google.com
 tfiga@chromium.org
 zzyiwei@chromium.org
 
diff --git a/amdgpu.c b/amdgpu.c
index a775cb7..85b34e9 100644
--- a/amdgpu.c
+++ b/amdgpu.c
@@ -38,11 +38,12 @@
 #define CHROME_HEIGHT_ALIGN 16
 
 struct amdgpu_priv {
-	struct dri_driver dri;
 	int drm_version;
 
-	/* sdma */
 	struct drm_amdgpu_info_device dev_info;
+	struct dri_driver *dri;
+
+	/* sdma */
 	uint32_t sdma_ctx;
 	uint32_t sdma_cmdbuf_bo;
 	uint64_t sdma_cmdbuf_addr;
@@ -385,7 +386,9 @@ static int amdgpu_init(struct driver *drv)
 		drv->priv = NULL;
 		return -ENODEV;
 	}
-	if (dri_init(drv, DRI_PATH, "radeonsi")) {
+
+	priv->dri = dri_init(drv, DRI_PATH, "radeonsi");
+	if (!priv->dri) {
 		free(priv);
 		drv->priv = NULL;
 		return -ENODEV;
@@ -460,9 +463,9 @@ static int amdgpu_init(struct driver *drv)
 	for (unsigned f = 0; f < ARRAY_SIZE(render_target_formats); ++f) {
 		uint32_t format = render_target_formats[f];
 		int mod_cnt;
-		if (dri_query_modifiers(drv, format, 0, NULL, &mod_cnt) && mod_cnt) {
+		if (dri_query_modifiers(priv->dri, format, 0, NULL, &mod_cnt) && mod_cnt) {
 			uint64_t *modifiers = calloc(mod_cnt, sizeof(uint64_t));
-			dri_query_modifiers(drv, format, mod_cnt, modifiers, &mod_cnt);
+			dri_query_modifiers(priv->dri, format, mod_cnt, modifiers, &mod_cnt);
 			metadata.tiling = TILE_TYPE_DRI_MODIFIER;
 			for (int i = 0; i < mod_cnt; ++i) {
 				bool scanout =
@@ -473,7 +476,7 @@ static int amdgpu_init(struct driver *drv)
 					continue;
 
 				/* The virtgpu minigbm can't handle auxiliary planes in the host. */
-				if (dri_num_planes_from_modifier(drv, format, modifiers[i]) !=
+				if (dri_num_planes_from_modifier(priv->dri, format, modifiers[i]) !=
 				    drv_num_planes_from_format(format))
 					continue;
 
@@ -508,9 +511,12 @@ static int amdgpu_init(struct driver *drv)
 
 static void amdgpu_close(struct driver *drv)
 {
-	sdma_finish(drv->priv, drv_get_fd(drv));
-	dri_close(drv);
-	free(drv->priv);
+	struct amdgpu_priv *priv = drv->priv;
+
+	sdma_finish(priv, drv_get_fd(drv));
+	dri_close(priv->dri);
+	free(priv);
+
 	drv->priv = NULL;
 }
 
@@ -633,9 +639,9 @@ static int amdgpu_create_bo(struct bo *bo, uint32_t width, uint32_t height, uint
 			width = ALIGN(width, 256 / bytes_per_pixel);
 		}
 
-		return dri_bo_create(bo, width, height, format, use_flags);
+		return dri_bo_create(priv->dri, bo, width, height, format, use_flags);
 	} else if (combo->metadata.tiling == TILE_TYPE_DRI_MODIFIER) {
-		return dri_bo_create_with_modifiers(bo, width, height, format,
+		return dri_bo_create_with_modifiers(priv->dri, bo, width, height, format, use_flags,
 						    &combo->metadata.modifier, 1);
 	}
 
@@ -646,6 +652,7 @@ static int amdgpu_create_bo_with_modifiers(struct bo *bo, uint32_t width, uint32
 					   uint32_t format, const uint64_t *modifiers,
 					   uint32_t count)
 {
+	struct amdgpu_priv *priv = bo->drv->priv;
 	bool only_use_linear = true;
 
 	for (uint32_t i = 0; i < count; ++i)
@@ -655,11 +662,13 @@ static int amdgpu_create_bo_with_modifiers(struct bo *bo, uint32_t width, uint32
 	if (only_use_linear)
 		return amdgpu_create_bo_linear(bo, width, height, format, BO_USE_SCANOUT);
 
-	return dri_bo_create_with_modifiers(bo, width, height, format, modifiers, count);
+	return dri_bo_create_with_modifiers(priv->dri, bo, width, height, format, 0, modifiers,
+					    count);
 }
 
 static int amdgpu_import_bo(struct bo *bo, struct drv_import_fd_data *data)
 {
+	struct amdgpu_priv *priv = bo->drv->priv;
 	bool dri_tiling = data->format_modifier != DRM_FORMAT_MOD_LINEAR;
 	if (data->format_modifier == DRM_FORMAT_MOD_INVALID) {
 		struct combination *combo;
@@ -671,26 +680,30 @@ static int amdgpu_import_bo(struct bo *bo, struct drv_import_fd_data *data)
 	}
 
 	bo->meta.num_planes =
-	    dri_num_planes_from_modifier(bo->drv, data->format, data->format_modifier);
+	    dri_num_planes_from_modifier(priv->dri, data->format, data->format_modifier);
 
 	if (dri_tiling)
-		return dri_bo_import(bo, data);
+		return dri_bo_import(priv->dri, bo, data);
 	else
 		return drv_prime_bo_import(bo, data);
 }
 
 static int amdgpu_release_bo(struct bo *bo)
 {
+	struct amdgpu_priv *priv = bo->drv->priv;
+
 	if (bo->priv)
-		return dri_bo_release(bo);
+		return dri_bo_release(priv->dri, bo);
 
 	return 0;
 }
 
 static int amdgpu_destroy_bo(struct bo *bo)
 {
+	struct amdgpu_priv *priv = bo->drv->priv;
+
 	if (bo->priv)
-		return dri_bo_destroy(bo);
+		return dri_bo_destroy(priv->dri, bo);
 	else
 		return drv_gem_bo_destroy(bo);
 }
@@ -704,12 +717,11 @@ static void *amdgpu_map_bo(struct bo *bo, struct vma *vma, uint32_t map_flags)
 	struct drm_amdgpu_gem_op gem_op = { 0 };
 	uint32_t handle = bo->handle.u32;
 	struct amdgpu_linear_vma_priv *priv = NULL;
-	struct amdgpu_priv *drv_priv;
+	struct amdgpu_priv *drv_priv = bo->drv->priv;
 
 	if (bo->priv)
-		return dri_bo_map(bo, vma, 0, map_flags);
+		return dri_bo_map(drv_priv->dri, bo, vma, 0, map_flags);
 
-	drv_priv = bo->drv->priv;
 	gem_op.handle = handle;
 	gem_op.op = AMDGPU_GEM_OP_GET_GEM_CREATE_INFO;
 	gem_op.value = (uintptr_t)&bo_info;
@@ -779,8 +791,10 @@ fail:
 
 static int amdgpu_unmap_bo(struct bo *bo, struct vma *vma)
 {
+	struct amdgpu_priv *priv = bo->drv->priv;
+
 	if (bo->priv) {
-		return dri_bo_unmap(bo, vma);
+		return dri_bo_unmap(priv->dri, bo, vma);
 	} else {
 		int r = munmap(vma->addr, vma->length);
 		if (r)
@@ -830,6 +844,13 @@ static int amdgpu_bo_invalidate(struct bo *bo, struct mapping *mapping)
 	return 0;
 }
 
+static size_t amdgpu_num_planes_from_modifier(struct driver *drv, uint32_t format,
+					      uint64_t modifier)
+{
+	struct amdgpu_priv *priv = drv->priv;
+	return dri_num_planes_from_modifier(priv->dri, format, modifier);
+}
+
 const struct backend backend_amdgpu = {
 	.name = "amdgpu",
 	.preload = amdgpu_preload,
@@ -844,7 +865,7 @@ const struct backend backend_amdgpu = {
 	.bo_unmap = amdgpu_unmap_bo,
 	.bo_invalidate = amdgpu_bo_invalidate,
 	.resolve_format_and_use_flags = drv_resolve_format_and_use_flags_helper,
-	.num_planes_from_modifier = dri_num_planes_from_modifier,
+	.num_planes_from_modifier = amdgpu_num_planes_from_modifier,
 };
 
 #endif
diff --git a/common.mk b/common.mk
index 0c24778..619efb8 100644
--- a/common.mk
+++ b/common.mk
@@ -323,10 +323,10 @@ COMMON_CFLAGS-clang := -fvisibility=hidden -ggdb \
 COMMON_CFLAGS := -Wall -Wunused -Wno-unused-parameter \
   -Wbool-operation -Wstring-compare -Wxor-used-as-pow \
   -Wint-in-bool-context -Wfree-nonheap-object \
-  -Werror -Wformat=2 -fno-strict-aliasing \
+  -Werror -Wformat=2 -fno-strict-aliasing  \
   $(SSP_CFLAGS) -O1
 CXXFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CXXDRIVER)) -std=gnu++20 \
-			-fvisibility-inlines-hidden
+  -fvisibility-inlines-hidden
 CFLAGS += $(COMMON_CFLAGS) $(COMMON_CFLAGS-$(CDRIVER)) -std=gnu17
 # We undefine _FORTIFY_SOURCE because some distros enable it by default in
 # their toolchains.  This makes the compiler issue warnings about redefines
@@ -363,8 +363,11 @@ endif
 # Pass -Bsymbolic-non-weak which pre-binds symbols in the same DSO to improve
 # startup performance. We don't support interposing non-weak symbols.
 # (go/cros-symbol-slimming)
-LDFLAGS := $(LDFLAGS) -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now \
-  -Wl,-Bsymbolic-non-weak
+LDFLAGS := $(LDFLAGS) \
+  -z relro \
+  -z noexecstack \
+  -z now \
+  $(call check_cc,-Xlinker -Bsymbolic-non-weak)
 
 # Fancy helpers for color if a prompt is defined
 ifeq ($(COLOR),1)
diff --git a/cros_gralloc/OWNERS b/cros_gralloc/OWNERS
index cd8d003..1d5ce32 100644
--- a/cros_gralloc/OWNERS
+++ b/cros_gralloc/OWNERS
@@ -1,3 +1,4 @@
 set noparent
 natsu@google.com
+ryanneph@google.com
 zzyiwei@chromium.org
diff --git a/cros_gralloc/cros_gralloc_driver.cc b/cros_gralloc/cros_gralloc_driver.cc
index ed7d954..cb8b94b 100644
--- a/cros_gralloc/cros_gralloc_driver.cc
+++ b/cros_gralloc/cros_gralloc_driver.cc
@@ -14,6 +14,8 @@
 #include <syscall.h>
 #include <xf86drm.h>
 
+#include "../drv_helpers.h"
+#include "../drv_priv.h"
 #include "../util.h"
 #include "cros_gralloc_buffer_metadata.h"
 
@@ -156,7 +158,15 @@ static void drv_destroy_and_close(struct driver *drv)
 	close(fd);
 }
 
-cros_gralloc_driver::cros_gralloc_driver() : drv_(init_try_nodes(), drv_destroy_and_close)
+static bool is_running_with_software_rendering()
+{
+	const char *vulkan_driver = drv_get_os_option("ro.hardware.vulkan");
+	return (vulkan_driver != nullptr && strstr(vulkan_driver, "pastel") != nullptr);
+}
+
+cros_gralloc_driver::cros_gralloc_driver()
+    : drv_(init_try_nodes(), drv_destroy_and_close),
+      is_running_with_software_rendering_(is_running_with_software_rendering())
 {
 }
 
@@ -179,6 +189,11 @@ bool cros_gralloc_driver::get_resolved_format_and_use_flags(
 	uint64_t resolved_use_flags;
 	struct combination *combo;
 
+	uint64_t use_flags = descriptor->use_flags;
+	if (is_running_with_software_rendering_ && (use_flags & BO_USE_GPU_HW) != 0) {
+		use_flags |= (BO_USE_SW_READ_OFTEN | BO_USE_SW_WRITE_OFTEN);
+	}
+
 	drv_resolve_format_and_use_flags(drv_.get(), descriptor->drm_format, descriptor->use_flags,
 					 &resolved_format, &resolved_use_flags);
 
@@ -469,6 +484,15 @@ int32_t cros_gralloc_driver::lock(buffer_handle_t handle, int32_t acquire_fence,
 		return -EINVAL;
 	}
 
+	if (!is_running_with_software_rendering_) {
+		if ((hnd->usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK)) ==
+		    0) {
+			ALOGE("Attempted to lock() a buffer that was not allocated with a "
+			      "BufferUsage::CPU_* usage.");
+			return -EINVAL;
+		}
+	}
+
 	auto buffer = get_buffer(hnd);
 	if (!buffer) {
 		ALOGE("Invalid reference (lock() called on unregistered handle).");
diff --git a/cros_gralloc/cros_gralloc_driver.h b/cros_gralloc/cros_gralloc_driver.h
index 56390fc..4e1fdf2 100644
--- a/cros_gralloc/cros_gralloc_driver.h
+++ b/cros_gralloc/cros_gralloc_driver.h
@@ -81,6 +81,9 @@ class cros_gralloc_driver
 	std::mutex mutex_;
 	std::unordered_map<uint32_t, std::unique_ptr<cros_gralloc_buffer>> buffers_;
 	std::unordered_map<cros_gralloc_handle_t, cros_gralloc_imported_handle_info> handles_;
+
+	/* TODO(b/242184599): remove after SwiftShader is moved to the host. */
+	const bool is_running_with_software_rendering_ = false;
 };
 
 #endif
diff --git a/cros_gralloc/cros_gralloc_helpers.cc b/cros_gralloc/cros_gralloc_helpers.cc
index 4b40bfd..945552c 100644
--- a/cros_gralloc/cros_gralloc_helpers.cc
+++ b/cros_gralloc/cros_gralloc_helpers.cc
@@ -96,7 +96,7 @@ uint32_t cros_gralloc_convert_format(int format)
 static inline void handle_usage(uint64_t *gralloc_usage, uint64_t gralloc_mask,
 				uint64_t *bo_use_flags, uint64_t bo_mask)
 {
-	if ((*gralloc_usage) & gralloc_mask) {
+	if (((*gralloc_usage) & gralloc_mask) == gralloc_mask) {
 		(*gralloc_usage) &= ~gralloc_mask;
 		(*bo_use_flags) |= bo_mask;
 	}
@@ -139,7 +139,9 @@ uint64_t cros_gralloc_convert_usage(uint64_t usage)
 	handle_usage(&usage, BUFFER_USAGE_SENSOR_DIRECT_DATA, &use_flags,
 		     BO_USE_SENSOR_DIRECT_DATA);
 	handle_usage(&usage, BUFFER_USAGE_GPU_DATA_BUFFER, &use_flags, BO_USE_GPU_DATA_BUFFER);
-	handle_usage(&usage, BUFFER_USAGE_FRONT_RENDERING_MASK, &use_flags, BO_USE_FRONT_RENDERING);
+	handle_usage(&usage, BUFFER_USAGE_FRONT_RENDERING, &use_flags, BO_USE_FRONT_RENDERING);
+	handle_usage(&usage, BUFFER_USAGE_FRONT_RENDERING_PRIVATE, &use_flags,
+		     BO_USE_FRONT_RENDERING);
 
 	if (usage) {
 		ALOGE("Unhandled gralloc usage: %llx", (unsigned long long)usage);
diff --git a/cros_gralloc/cros_gralloc_helpers.h b/cros_gralloc/cros_gralloc_helpers.h
index e8dd0a5..1987eab 100644
--- a/cros_gralloc/cros_gralloc_helpers.h
+++ b/cros_gralloc/cros_gralloc_helpers.h
@@ -21,10 +21,13 @@
 // Reserve the GRALLOC_USAGE_PRIVATE_0 bit from hardware/gralloc.h for buffers
 // used for front rendering. minigbm backend later decides to use
 // BO_USE_FRONT_RENDERING or BO_USE_LINEAR upon buffer allocaton.
-#define BUFFER_USAGE_FRONT_RENDERING (1U << 28)
+#define BUFFER_USAGE_FRONT_RENDERING_PRIVATE (1U << 28)
 
 // Adopt BufferUsage::FRONT_BUFFER from api level 33
-#define BUFFER_USAGE_FRONT_RENDERING_MASK (BUFFER_USAGE_FRONT_RENDERING | (1ULL << 32))
+#define BUFFER_USAGE_FRONT_RENDERING (1ULL << 32)
+
+#define BUFFER_USAGE_FRONT_RENDERING_MASK                                                          \
+	(BUFFER_USAGE_FRONT_RENDERING | BUFFER_USAGE_FRONT_RENDERING_PRIVATE)
 
 #define CROS_GRALLOC_BUFFER_METADATA_MAX_NAME_SIZE 1024
 
diff --git a/dri.c b/dri.c
index ccce32a..bf980be 100644
--- a/dri.c
+++ b/dri.c
@@ -22,6 +22,24 @@
 #include "drv_priv.h"
 #include "util.h"
 
+// Avoid transitively including a bunch of unnecessary headers.
+#define GL_GLEXT_LEGACY
+#include "GL/internal/dri_interface.h"
+#undef GL_GLEXT_LEGACY
+
+struct dri_driver {
+	int fd;
+	void *driver_handle;
+	__DRIscreen *device;
+	__DRIcontext *context; /* Needed for map/unmap operations. */
+	const __DRIextension **extensions;
+	const __DRIcoreExtension *core_extension;
+	const __DRIdri2Extension *dri2_extension;
+	const __DRIimageExtension *image_extension;
+	const __DRI2flushExtension *flush_extension;
+	const __DRIconfig **configs;
+};
+
 static const struct {
 	uint32_t drm_format;
 	int dri_image_format;
@@ -163,24 +181,24 @@ void dri_dlclose(void *dri_so_handle)
 	dlclose(dri_so_handle);
 }
 
-/*
- * The caller is responsible for setting drv->priv to a structure that derives from dri_driver.
- */
-int dri_init(struct driver *drv, const char *dri_so_path, const char *driver_suffix)
+struct dri_driver *dri_init(struct driver *drv, const char *dri_so_path, const char *driver_suffix)
 {
 	char fname[128];
 	const __DRIextension **(*get_extensions)();
 	const __DRIextension *loader_extensions[] = { &use_invalidate.base, NULL };
 
-	struct dri_driver *dri = drv->priv;
+	struct dri_driver *dri = calloc(1, sizeof(*dri));
+	if (!dri)
+		return NULL;
+
 	char *node_name = drmGetRenderDeviceNameFromFd(drv_get_fd(drv));
 	if (!node_name)
-		return -ENODEV;
+		goto free_dri;
 
 	dri->fd = open(node_name, O_RDWR);
 	free(node_name);
 	if (dri->fd < 0)
-		return -ENODEV;
+		goto free_dri;
 
 	dri->driver_handle = dri_dlopen(dri_so_path);
 	if (!dri->driver_handle)
@@ -223,7 +241,7 @@ int dri_init(struct driver *drv, const char *dri_so_path, const char *driver_suf
 			      (const __DRIextension **)&dri->flush_extension))
 		goto free_context;
 
-	return 0;
+	return dri;
 
 free_context:
 	dri->core_extension->destroyContext(dri->context);
@@ -234,29 +252,26 @@ free_handle:
 	dri->driver_handle = NULL;
 close_dri_fd:
 	close(dri->fd);
-	return -ENODEV;
+free_dri:
+	free(dri);
+	return NULL;
 }
 
-/*
- * The caller is responsible for freeing drv->priv.
- */
-void dri_close(struct driver *drv)
+void dri_close(struct dri_driver *dri)
 {
-	struct dri_driver *dri = drv->priv;
-
 	dri->core_extension->destroyContext(dri->context);
 	dri->core_extension->destroyScreen(dri->device);
 	dri_dlclose(dri->driver_handle);
 	dri->driver_handle = NULL;
 	close(dri->fd);
+	free(dri);
 }
 
-int dri_bo_create(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
-		  uint64_t use_flags)
+int dri_bo_create(struct dri_driver *dri, struct bo *bo, uint32_t width, uint32_t height,
+		  uint32_t format, uint64_t use_flags)
 {
 	unsigned int dri_use;
 	int ret, dri_format;
-	struct dri_driver *dri = bo->drv->priv;
 
 	dri_format = drm_format_to_dri_format(format);
 
@@ -287,11 +302,11 @@ free_image:
 	return ret;
 }
 
-int dri_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
+int dri_bo_create_with_modifiers(struct dri_driver *dri, struct bo *bo, uint32_t width,
+				 uint32_t height, uint32_t format, uint64_t use_flags,
 				 const uint64_t *modifiers, uint32_t modifier_count)
 {
 	int ret, dri_format;
-	struct dri_driver *dri = bo->drv->priv;
 
 	if (!dri->image_extension->createImageWithModifiers)
 		return -ENOENT;
@@ -316,10 +331,9 @@ free_image:
 	return ret;
 }
 
-int dri_bo_import(struct bo *bo, struct drv_import_fd_data *data)
+int dri_bo_import(struct dri_driver *dri, struct bo *bo, struct drv_import_fd_data *data)
 {
 	int ret;
-	struct dri_driver *dri = bo->drv->priv;
 
 	if (data->format_modifier != DRM_FORMAT_MOD_INVALID) {
 		unsigned error;
@@ -366,17 +380,15 @@ int dri_bo_import(struct bo *bo, struct drv_import_fd_data *data)
 	return 0;
 }
 
-int dri_bo_release(struct bo *bo)
+int dri_bo_release(struct dri_driver *dri, struct bo *bo)
 {
-	struct dri_driver *dri = bo->drv->priv;
-
 	assert(bo->priv);
 	dri->image_extension->destroyImage(bo->priv);
 	/* Not clearing bo->priv as we still use it to determine which destroy to call. */
 	return 0;
 }
 
-int dri_bo_destroy(struct bo *bo)
+int dri_bo_destroy(struct dri_driver *dri, struct bo *bo)
 {
 	assert(bo->priv);
 	drv_gem_close(bo->drv, bo->handle.u32);
@@ -393,10 +405,9 @@ int dri_bo_destroy(struct bo *bo)
  * This function itself is not thread-safe; we rely on the fact that the caller
  * locks a per-driver mutex.
  */
-void *dri_bo_map(struct bo *bo, struct vma *vma, size_t plane, uint32_t map_flags)
+void *dri_bo_map(struct dri_driver *dri, struct bo *bo, struct vma *vma, size_t plane,
+		 uint32_t map_flags)
 {
-	struct dri_driver *dri = bo->drv->priv;
-
 	/* GBM flags and DRI flags are the same. */
 	vma->addr = dri->image_extension->mapImage(dri->context, bo->priv, 0, 0, bo->meta.width,
 						   bo->meta.height, map_flags,
@@ -407,10 +418,8 @@ void *dri_bo_map(struct bo *bo, struct vma *vma, size_t plane, uint32_t map_flag
 	return vma->addr;
 }
 
-int dri_bo_unmap(struct bo *bo, struct vma *vma)
+int dri_bo_unmap(struct dri_driver *dri, struct bo *bo, struct vma *vma)
 {
-	struct dri_driver *dri = bo->drv->priv;
-
 	assert(vma->priv);
 	dri->image_extension->unmapImage(dri->context, bo->priv, vma->priv);
 
@@ -426,9 +435,8 @@ int dri_bo_unmap(struct bo *bo, struct vma *vma)
 	return 0;
 }
 
-size_t dri_num_planes_from_modifier(struct driver *drv, uint32_t format, uint64_t modifier)
+size_t dri_num_planes_from_modifier(struct dri_driver *dri, uint32_t format, uint64_t modifier)
 {
-	struct dri_driver *dri = drv->priv;
 	uint64_t planes = 0;
 
 	/* We do not do any modifier checks here. The create will fail later if the modifier is not
@@ -443,10 +451,9 @@ size_t dri_num_planes_from_modifier(struct driver *drv, uint32_t format, uint64_
 	return drv_num_planes_from_format(format);
 }
 
-bool dri_query_modifiers(struct driver *drv, uint32_t format, int max, uint64_t *modifiers,
+bool dri_query_modifiers(struct dri_driver *dri, uint32_t format, int max, uint64_t *modifiers,
 			 int *count)
 {
-	struct dri_driver *dri = drv->priv;
 	if (!dri->image_extension->queryDmaBufModifiers)
 		return false;
 
diff --git a/dri.h b/dri.h
index 8136f5c..955b950 100644
--- a/dri.h
+++ b/dri.h
@@ -6,42 +6,29 @@
 
 #ifdef DRV_AMDGPU
 
-// Avoid transitively including a bunch of unnecessary headers.
-#define GL_GLEXT_LEGACY
-#include "GL/internal/dri_interface.h"
-#undef GL_GLEXT_LEGACY
-
 #include "drv.h"
 
-struct dri_driver {
-	int fd;
-	void *driver_handle;
-	__DRIscreen *device;
-	__DRIcontext *context; /* Needed for map/unmap operations. */
-	const __DRIextension **extensions;
-	const __DRIcoreExtension *core_extension;
-	const __DRIdri2Extension *dri2_extension;
-	const __DRIimageExtension *image_extension;
-	const __DRI2flushExtension *flush_extension;
-	const __DRIconfig **configs;
-};
+struct dri_driver;
 
 void *dri_dlopen(const char *dri_so_path);
 void dri_dlclose(void *dri_so_handle);
 
-int dri_init(struct driver *drv, const char *dri_so_path, const char *driver_suffix);
-void dri_close(struct driver *drv);
-int dri_bo_create(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
-		  uint64_t use_flags);
-int dri_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint32_t height, uint32_t format,
+struct dri_driver *dri_init(struct driver *drv, const char *dri_so_path, const char *driver_suffix);
+void dri_close(struct dri_driver *dri);
+
+int dri_bo_create(struct dri_driver *dri, struct bo *bo, uint32_t width, uint32_t height,
+		  uint32_t format, uint64_t use_flags);
+int dri_bo_create_with_modifiers(struct dri_driver *dri, struct bo *bo, uint32_t width,
+				 uint32_t height, uint32_t format, uint64_t use_flags,
 				 const uint64_t *modifiers, uint32_t modifier_count);
-int dri_bo_import(struct bo *bo, struct drv_import_fd_data *data);
-int dri_bo_release(struct bo *bo);
-int dri_bo_destroy(struct bo *bo);
-void *dri_bo_map(struct bo *bo, struct vma *vma, size_t plane, uint32_t map_flags);
-int dri_bo_unmap(struct bo *bo, struct vma *vma);
-size_t dri_num_planes_from_modifier(struct driver *drv, uint32_t format, uint64_t modifier);
+int dri_bo_import(struct dri_driver *dri, struct bo *bo, struct drv_import_fd_data *data);
+int dri_bo_release(struct dri_driver *dri, struct bo *bo);
+int dri_bo_destroy(struct dri_driver *dri, struct bo *bo);
+void *dri_bo_map(struct dri_driver *dri, struct bo *bo, struct vma *vma, size_t plane,
+		 uint32_t map_flags);
+int dri_bo_unmap(struct dri_driver *dri, struct bo *bo, struct vma *vma);
 
-bool dri_query_modifiers(struct driver *drv, uint32_t format, int max, uint64_t *modifiers,
+size_t dri_num_planes_from_modifier(struct dri_driver *dri, uint32_t format, uint64_t modifier);
+bool dri_query_modifiers(struct dri_driver *dri, uint32_t format, int max, uint64_t *modifiers,
 			 int *count);
 #endif
diff --git a/drv.h b/drv.h
index bd380b5..9150ec6 100644
--- a/drv.h
+++ b/drv.h
@@ -106,22 +106,6 @@ extern "C" {
 #define I915_FORMAT_MOD_4_TILED_MTL_RC_CCS fourcc_mod_code(INTEL, 13)
 #endif
 
-#ifndef I915_FORMAT_MOD_4_TILED_MTL_MC_CCS
-//TODO: remove this defination once drm_fourcc.h contains it.
-/*
- * Intel color control surfaces (CCS) for display ver 14 media compression
- *
- * The main surface is tile4 and at plane index 0, the CCS is linear and
- * at index 1. A 64B CCS cache line corresponds to an area of 4x1 tiles in
- * main surface. In other words, 4 bits in CCS map to a main surface cache
- * line pair. The main surface pitch is required to be a multiple of four
- * tile4 widths. For semi-planar formats like NV12, CCS planes follow the
- * Y and UV planes i.e., planes 0 and 1 are used for Y and UV surfaces,
- * planes 2 and 3 for the respective CCS.
- */
-#define I915_FORMAT_MOD_4_TILED_MTL_MC_CCS fourcc_mod_code(INTEL, 14)
-#endif
-
 // clang-format on
 struct driver;
 struct bo;
diff --git a/drv_helpers.h b/drv_helpers.h
index 873bd08..1c347f8 100644
--- a/drv_helpers.h
+++ b/drv_helpers.h
@@ -7,6 +7,10 @@
 #ifndef DRV_HELPERS_H
 #define DRV_HELPERS_H
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 #include <stdbool.h>
 
 #include "drv.h"
@@ -72,4 +76,8 @@ struct lru_entry *lru_find(struct lru *lru, bool (*eq)(struct lru_entry *e, void
 void lru_insert(struct lru *lru, struct lru_entry *entry);
 void lru_init(struct lru *lru, int max);
 
+#ifdef __cplusplus
+}
+#endif
+
 #endif
diff --git a/i915.c b/i915.c
index f9b79b1..995d930 100644
--- a/i915.c
+++ b/i915.c
@@ -38,7 +38,6 @@ static const uint64_t gen_modifier_order[] = { I915_FORMAT_MOD_Y_TILED_CCS, I915
 					       I915_FORMAT_MOD_X_TILED, DRM_FORMAT_MOD_LINEAR };
 
 static const uint64_t gen12_modifier_order[] = { I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS,
-						 I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS,
 						 I915_FORMAT_MOD_Y_TILED, I915_FORMAT_MOD_X_TILED,
 						 DRM_FORMAT_MOD_LINEAR };
 
@@ -46,7 +45,6 @@ static const uint64_t gen11_modifier_order[] = { I915_FORMAT_MOD_Y_TILED, I915_F
 						 DRM_FORMAT_MOD_LINEAR };
 
 static const uint64_t xe_lpdp_modifier_order[] = { I915_FORMAT_MOD_4_TILED_MTL_RC_CCS,
-						   I915_FORMAT_MOD_4_TILED_MTL_MC_CCS,
 						   I915_FORMAT_MOD_4_TILED, I915_FORMAT_MOD_X_TILED,
 						   DRM_FORMAT_MOD_LINEAR };
 
@@ -197,10 +195,6 @@ static void i915_get_modifier_order(struct i915_device *i915)
 		i915->modifier.order = xe_lpdp_modifier_order;
 		i915->modifier.count = ARRAY_SIZE(xe_lpdp_modifier_order);
 	} else if (i915->graphics_version == 12) {
-		/*
-		 * On ADL platforms of gen 12 onwards, Intel media compression is supported for
-		 * video decoding on Chrome.
-		 */
 		i915->modifier.order = gen12_modifier_order;
 		i915->modifier.count = ARRAY_SIZE(gen12_modifier_order);
 	} else if (i915->graphics_version == 11) {
@@ -258,6 +252,13 @@ static int i915_add_combinations(struct driver *drv)
 	/* P010 linear can be used for scanout too. */
 	drv_modify_combination(drv, DRM_FORMAT_P010, &metadata_linear, BO_USE_SCANOUT);
 
+	/*
+	 * Android also frequently requests YV12 formats for some camera implementations
+	 * (including the external provider implmenetation).
+	 */
+	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata_linear,
+			       BO_USE_CAMERA_WRITE);
+
 	/* Android CTS tests require this. */
 	drv_add_combination(drv, DRM_FORMAT_BGR888, &metadata_linear, BO_USE_SW_MASK);
 
@@ -564,12 +565,7 @@ static size_t i915_num_planes_from_modifier(struct driver *drv, uint32_t format,
 	    modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) {
 		assert(num_planes == 1);
 		return 2;
-	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
-		   modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) {
-		assert(num_planes == 2);
-		return 4;
 	}
-
 	return num_planes;
 }
 
@@ -595,21 +591,6 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		if (!combo)
 			return -EINVAL;
 		modifier = combo->metadata.modifier;
-		/*
-		 * Media compression modifiers should not be picked automatically by minigbm based
-		 * on |use_flags|. Instead the client should request them explicitly through
-		 * gbm_bo_create_with_modifiers().
-		 */
-		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS &&
-		       modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS);
-		/* TODO(b/323863689): Account for driver's bandwidth compression in minigbm for
-		 * media compressed buffers. */
-	}
-	if ((modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
-	     modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) &&
-	    !(format == DRM_FORMAT_NV12 || format == DRM_FORMAT_P010)) {
-		drv_loge("Media compression is only supported for NV12 and P010\n");
-		return -EINVAL;
 	}
 
 	/*
@@ -663,12 +644,10 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 	 * IPs(render/media/display)
 	 */
 	case I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS:
-	case I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS:
 		bo->meta.tiling = I915_TILING_Y;
 		break;
 	case I915_FORMAT_MOD_4_TILED:
 	case I915_FORMAT_MOD_4_TILED_MTL_RC_CCS:
-	case I915_FORMAT_MOD_4_TILED_MTL_MC_CCS:
 		bo->meta.tiling = I915_TILING_4;
 		break;
 	}
@@ -727,21 +706,8 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 
 		bo->meta.num_planes = i915_num_planes_from_modifier(bo->drv, format, modifier);
 		bo->meta.total_size = offset;
-	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS ||
-		   modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS) {
-		/*
-		 * Media compression modifiers should only be possible via the
-		 * gbm_bo_create_with_modifiers() path, i.e., the minigbm client needs to
-		 * explicitly request it.
-		 */
-		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
-		       use_flags == BO_USE_NONE);
-		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
-		       bo->meta.use_flags == BO_USE_NONE);
-		assert(modifier != I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS ||
-		       (!!modifiers && count > 0));
+	} else if (modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS) {
 		assert(drv_num_planes_from_format(format) > 0);
-
 		uint32_t offset = 0;
 		size_t plane = 0;
 		size_t a_plane = 0;
@@ -795,31 +761,15 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 		/* Total number of planes & sizes */
 		bo->meta.num_planes = plane + a_plane;
 		bo->meta.total_size = offset;
-	} else if (modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS ||
-		   modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS) {
-		/* Media compression modifiers should only be possible via the
-		 * gbm_bo_create_with_modifiers() path, i.e., the minigbm client needs to
-		 * explicitly request it.
-		 */
-		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS || use_flags == BO_USE_NONE);
-		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
-		       bo->meta.use_flags == BO_USE_NONE);
-		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
-		       (!!modifiers && count > 0));
-		assert(modifier != I915_FORMAT_MOD_4_TILED_MTL_MC_CCS ||
-		       (format == DRM_FORMAT_NV12 || format == DRM_FORMAT_P010 ||
-			format == DRM_FORMAT_XRGB8888 || format == DRM_FORMAT_XBGR8888));
+	} else if (modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) {
 		assert(drv_num_planes_from_format(format) > 0);
-
 		uint32_t offset = 0, stride = 0;
 		size_t plane = 0;
 		size_t a_plane = 0;
 		for (plane = 0; plane < drv_num_planes_from_format(format); plane++) {
 			uint32_t alignment = 0, val, tmpoffset = 0;
-
 			/*
-			 * tile_align = 4 (for width) for CCS and
-			 * tile_width = 128, tile_height = 32 for MC CCS
+			 * tile_align = 4 (for width) for CCS
 			 */
 			stride = ALIGN(drv_stride_from_format(format, width, plane), 512);
 			height = ALIGN(drv_height_from_format(format, height, plane), 32);
@@ -855,7 +805,8 @@ static int i915_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t heig
 			/* next buffer offset */
 			offset += bo->meta.sizes[plane + a_plane];
 		}
-		bo->meta.num_planes = a_plane + plane;
+
+		bo->meta.num_planes = plane + a_plane;
 		bo->meta.total_size = offset;
 	} else {
 		return i915_bo_from_format(bo, width, height, format);
@@ -972,10 +923,8 @@ static void *i915_bo_map(struct bo *bo, struct vma *vma, uint32_t map_flags)
 
 	if ((bo->meta.format_modifier == I915_FORMAT_MOD_Y_TILED_CCS) ||
 	    (bo->meta.format_modifier == I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS) ||
-	    (bo->meta.format_modifier == I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS) ||
 	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED) ||
-	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS) ||
-	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_MC_CCS))
+	    (bo->meta.format_modifier == I915_FORMAT_MOD_4_TILED_MTL_RC_CCS))
 		return MAP_FAILED;
 
 	if (bo->meta.tiling == I915_TILING_NONE) {
diff --git a/mediatek.c b/mediatek.c
index 693af78..4fbbc98 100644
--- a/mediatek.c
+++ b/mediatek.c
@@ -201,6 +201,13 @@ static int mediatek_init(struct driver *drv)
 			       BO_USE_SCANOUT | BO_USE_HW_VIDEO_ENCODER | BO_USE_CAMERA_READ |
 				   BO_USE_CAMERA_WRITE);
 
+	/*
+	 * Android also frequently requests YV12 formats for some camera implementations
+	 * (including the external provider implmenetation).
+	 */
+	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata,
+			       BO_USE_CAMERA_WRITE);
+
 #ifdef MTK_MT8183
 	/* Only for MT8183 Camera subsystem */
 	drv_modify_combination(drv, DRM_FORMAT_NV21, &metadata,
diff --git a/virtgpu_cross_domain.c b/virtgpu_cross_domain.c
index 85589dc..1bba350 100644
--- a/virtgpu_cross_domain.c
+++ b/virtgpu_cross_domain.c
@@ -152,7 +152,7 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 	struct cross_domain_private *priv = drv->priv;
 	struct CrossDomainGetImageRequirements cmd_get_reqs;
 	uint32_t *addr = (uint32_t *)priv->ring_addr;
-	uint32_t plane, remaining_size;
+	uint32_t plane;
 
 	memset(&cmd_get_reqs, 0, sizeof(cmd_get_reqs));
 	pthread_mutex_lock(&priv->metadata_cache_lock);
@@ -170,10 +170,18 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 
 	cmd_get_reqs.width = metadata->width;
 	cmd_get_reqs.height = metadata->height;
-	cmd_get_reqs.drm_format =
-	    (metadata->format == DRM_FORMAT_YVU420_ANDROID) ? DRM_FORMAT_YVU420 : metadata->format;
+	cmd_get_reqs.drm_format = metadata->format;
 	cmd_get_reqs.flags = metadata->use_flags;
 
+	// HACK(b/360937659): see also: b/172389166,  for history
+	// host minigbm has a hack that recognizes DRM_FORMAT_YVU420 + BO_USE_LINEAR and replaces
+	// the format internally back to DRM_FORMAT_YVU420_ANDROID to use the approrpriate layout
+	// rules.
+	if (cmd_get_reqs.drm_format == DRM_FORMAT_YVU420_ANDROID) {
+		cmd_get_reqs.drm_format = DRM_FORMAT_YVU420;
+		cmd_get_reqs.flags |= BO_USE_LINEAR;
+	}
+
 	/*
 	 * It is possible to avoid blocking other bo_create() calls by unlocking before
 	 * cross_domain_submit_cmd() and re-locking afterwards.  However, that would require
@@ -196,15 +204,12 @@ static int cross_domain_metadata_query(struct driver *drv, struct bo_metadata *m
 	metadata->memory_idx = addr[14];
 	metadata->physical_device_idx = addr[15];
 
-	remaining_size = metadata->total_size;
-	for (plane = 0; plane < metadata->num_planes; plane++) {
-		if (plane != 0) {
-			metadata->sizes[plane - 1] = metadata->offsets[plane];
-			remaining_size -= metadata->offsets[plane];
-		}
+	for (plane = 1; plane < metadata->num_planes; plane++) {
+		metadata->sizes[plane - 1] =
+		    metadata->offsets[plane] - metadata->offsets[plane - 1];
 	}
+	metadata->sizes[plane - 1] = metadata->total_size - metadata->offsets[plane - 1];
 
-	metadata->sizes[plane - 1] = remaining_size;
 	drv_array_append(priv->metadata_cache, metadata);
 
 out_unlock:
diff --git a/virtgpu_virgl.c b/virtgpu_virgl.c
index b438498..763bdbc 100644
--- a/virtgpu_virgl.c
+++ b/virtgpu_virgl.c
@@ -261,7 +261,7 @@ static void virgl_get_emulated_transfers_params(const struct bo *bo,
 {
 	uint32_t y_plane_height;
 	uint32_t c_plane_height;
-	struct bo_metadata emulated_metadata;
+	struct bo_metadata emulated_metadata = { 0 };
 
 	if (transfer_box->x == 0 && transfer_box->y == 0 && transfer_box->width == bo->meta.width &&
 	    transfer_box->height == bo->meta.height) {
@@ -493,7 +493,7 @@ static int virgl_3d_bo_create(struct bo *bo, uint32_t width, uint32_t height, ui
 	size_t i;
 	uint32_t stride;
 	struct drm_virtgpu_resource_create res_create = { 0 };
-	struct bo_metadata emulated_metadata;
+	struct bo_metadata emulated_metadata = { 0 };
 
 	if (virgl_supports_combination_natively(bo->drv, format, use_flags)) {
 		stride = drv_stride_from_format(format, width, 0);
```

