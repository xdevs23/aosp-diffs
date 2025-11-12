```diff
diff --git a/Android.bp b/Android.bp
index d044e7d..cfca5ba 100644
--- a/Android.bp
+++ b/Android.bp
@@ -82,6 +82,11 @@ msm_cflags = [
 ]
 arcvm_cflags = ["-DVIRTIO_GPU_NEXT"]
 
+mediatek_cflags = [
+    "-DDRV_MEDIATEK",
+    "-DHAS_DMABUF_SYSTEM_HEAP",
+]
+
 cc_defaults {
     name: "minigbm_defaults",
 
@@ -100,6 +105,9 @@ cc_defaults {
         "meson": meson_cflags,
         "msm": msm_cflags,
         "arcvm": arcvm_cflags,
+        "mt8186": mediatek_cflags + ["-DMTK_MT8186"],
+        "mt8188": mediatek_cflags + ["-DMTK_MT8188G"],
+        "mt8196": mediatek_cflags + ["-DMTK_MT8196"],
         default: [],
     }),
 
@@ -250,7 +258,7 @@ cc_library_headers {
     vendor_available: true,
     export_include_dirs: ["cros_gralloc"],
     visibility: [
-        "//device/generic/goldfish-opengl/system/hwc3:__subpackages__",
+        "//device/generic/goldfish/hals/hwc3:__subpackages__",
     ],
 }
 
@@ -323,3 +331,10 @@ cc_library_shared {
     defaults: ["minigbm_cros_gralloc0_defaults"],
     shared_libs: ["libminigbm_gralloc_arcvm"],
 }
+
+// mediatek
+cc_library_shared {
+    name: "libminigbm_gralloc_mediatek",
+    defaults: ["minigbm_cros_gralloc_library_defaults"],
+    cflags: mediatek_cflags,
+}
diff --git a/CleanSpec.mk b/CleanSpec.mk
new file mode 100644
index 0000000..c149162
--- /dev/null
+++ b/CleanSpec.mk
@@ -0,0 +1,62 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+# If you don't need to do a full clean build but would like to touch
+# a file or delete some intermediate files, add a clean step to the end
+# of the list.  These steps will only be run once, if they haven't been
+# run before.
+#
+# E.g.:
+#     $(call add-clean-step, touch -c external/sqlite/sqlite3.h)
+#     $(call add-clean-step, rm -rf $(PRODUCT_OUT)/obj/STATIC_LIBRARIES/libz_intermediates)
+#
+# Always use "touch -c" and "rm -f" or "rm -rf" to gracefully deal with
+# files that are missing or have been moved.
+#
+# Use $(PRODUCT_OUT) to get to the "out/target/product/blah/" directory.
+# Use $(OUT_DIR) to refer to the "out" directory.
+#
+# If you need to re-do something that's already mentioned, just copy
+# the command and add it to the bottom of the list.  E.g., if a change
+# that you made last week required touching a file and a change you
+# made today requires touching the same file, just copy the old
+# touch step and add it to the end of the list.
+#
+# ************************************************
+# NEWER CLEAN STEPS MUST BE AT THE END OF THE LIST
+# ************************************************
+
+# For example:
+#$(call add-clean-step, rm -rf $(OUT_DIR)/target/common/obj/APPS/AndroidTests_intermediates)
+#$(call add-clean-step, rm -rf $(OUT_DIR)/target/common/obj/JAVA_LIBRARIES/core_intermediates)
+#$(call add-clean-step, find $(OUT_DIR) -type f -name "IGTalkSession*" -print0 | xargs -0 rm -f)
+#$(call add-clean-step, rm -rf $(PRODUCT_OUT)/data/*)
+
+# ************************************************
+# NEWER CLEAN STEPS MUST BE AT THE END OF THE LIST
+# ************************************************
+
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/bin/hw/android.hardware.graphics.allocator*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/init/allocator.rc)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/init/android.hardware.graphics.allocator*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/vintf/manifest/allocator.xml)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/vintf/manifest/mapper.minigbm.xml)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/vintf/manifest/android.hardware.graphics.allocator*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/etc/vintf/manifest/android.hardware.graphics.mapper*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/lib*/libminigbm_gralloc*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/lib*/hw/gralloc.minigbm*)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/lib*/hw/mapper.minigbm.so)
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/vendor/lib*/hw/android.hardware.graphics.mapper*)
+$(call add-clean-step, rm -rf $(OUT_DIR)/soong/.intermediates/external/minigbm)
diff --git a/OWNERS.android b/OWNERS.android
index 54e65dc..b842031 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1,3 +1,15 @@
 adelva@google.com
 natsu@google.com
+prahladk@google.com
 include platform/system/core:main:/janitors/OWNERS
+
+# Intel
+per-file external/i915_drm.h = msturner@google.com, ryanneph@google.com
+per-file external/xe_drm.h = msturner@google.com, ryanneph@google.com
+per-file intel_defines.h = msturner@google.com, ryanneph@google.com
+per-file i915.c = msturner@google.com, ryanneph@google.com
+per-file xe.c = msturner@google.com, ryanneph@google.com
+
+# Mediatek
+per-file external/mediatek_drm.h = dbehr@google.com, zzyiwei@google.com
+per-file mediatek.c = dbehr@google.com, zzyiwei@google.com
diff --git a/cros_gralloc/cros_gralloc_arm.h b/cros_gralloc/cros_gralloc_arm.h
new file mode 100644
index 0000000..6389714
--- /dev/null
+++ b/cros_gralloc/cros_gralloc_arm.h
@@ -0,0 +1,69 @@
+#ifndef CROS_GRALLOC_ARM_H
+#define CROS_GRALLOC_ARM_H
+
+#include "../drv.h"
+#include "aidl/android/hardware/graphics/common/ExtendableType.h"
+
+using aidl::android::hardware::graphics::common::ExtendableType;
+
+/* from AIDL interface */
+typedef enum {
+	INVALID = 0,
+	PLANE_FDS = 1,
+	FORMAT_DATA_TYPE = 2,
+} ArmMetadataType;
+
+typedef enum {
+	UNORM = 0,
+	SNORM = 1,
+	UINT = 2,
+	SINT = 3,
+	SFLOAT = 4,
+	UNKNOWN = 0xFF,
+} ArmDataType;
+
+typedef enum {
+	AFBC = 0,
+	AFRC = 1,
+} ArmCompression;
+
+#define GRALLOC_ARM_COMPRESSION_TYPE_NAME "arm.graphics.Compression"
+const static ExtendableType Compression_AFBC{ GRALLOC_ARM_COMPRESSION_TYPE_NAME,
+					      static_cast<int64_t>(ArmCompression::AFBC) };
+
+const static ExtendableType Compression_AFRC{ GRALLOC_ARM_COMPRESSION_TYPE_NAME,
+					      static_cast<int64_t>(ArmCompression::AFRC) };
+
+#define GRALLOC_ARM_METADATA_TYPE_NAME "arm.graphics.ArmMetadataType"
+
+#define GRALLOC_ARM_FORMAT_DATA_TYPE_NAME "arm.graphics.DataType"
+
+static ArmDataType DataTypeFromDrmPixelFormat(uint32_t pf)
+{
+	switch (pf) {
+	case DRM_FORMAT_R8:
+	case DRM_FORMAT_GR88:
+	case DRM_FORMAT_RGB565:
+	case DRM_FORMAT_XRGB8888:
+	case DRM_FORMAT_ARGB8888:
+	case DRM_FORMAT_XBGR8888:
+	case DRM_FORMAT_ABGR8888:
+	case DRM_FORMAT_XRGB2101010:
+	case DRM_FORMAT_XBGR2101010:
+	case DRM_FORMAT_ARGB2101010:
+	case DRM_FORMAT_ABGR2101010:
+	case DRM_FORMAT_NV12:
+	case DRM_FORMAT_NV21:
+	case DRM_FORMAT_YUYV:
+	case DRM_FORMAT_YVU420:
+	case DRM_FORMAT_YVU420_ANDROID:
+	case DRM_FORMAT_P010:
+		return ArmDataType::UNORM;
+	case DRM_FORMAT_ABGR16161616F:
+		return ArmDataType::SFLOAT;
+	default:
+		return ArmDataType::UNKNOWN;
+	}
+}
+
+#endif // CROS_GRALLOC_ARM_H
diff --git a/cros_gralloc/cros_gralloc_buffer.cc b/cros_gralloc/cros_gralloc_buffer.cc
index b2c4dc8..5af8c46 100644
--- a/cros_gralloc/cros_gralloc_buffer.cc
+++ b/cros_gralloc/cros_gralloc_buffer.cc
@@ -142,6 +142,14 @@ uint32_t cros_gralloc_buffer::get_plane_size(uint32_t plane) const
 	return hnd_->sizes[plane];
 }
 
+int64_t cros_gralloc_buffer::get_plane_fd(uint32_t plane) const
+{
+	if (plane >= hnd_->num_planes) {
+		return -1;
+	}
+	return hnd_->fds[plane];
+}
+
 int32_t cros_gralloc_buffer::get_android_format() const
 {
 	return hnd_->droid_format;
diff --git a/cros_gralloc/cros_gralloc_buffer.h b/cros_gralloc/cros_gralloc_buffer.h
index e246602..9707aca 100644
--- a/cros_gralloc/cros_gralloc_buffer.h
+++ b/cros_gralloc/cros_gralloc_buffer.h
@@ -38,6 +38,7 @@ class cros_gralloc_buffer
 	uint32_t get_plane_offset(uint32_t plane) const;
 	uint32_t get_plane_stride(uint32_t plane) const;
 	uint32_t get_plane_size(uint32_t plane) const;
+	int64_t get_plane_fd(uint32_t plane) const;
 	int32_t get_android_format() const;
 	int64_t get_android_usage() const;
 
diff --git a/cros_gralloc/cros_gralloc_driver.cc b/cros_gralloc/cros_gralloc_driver.cc
index cb8b94b..b17c8c7 100644
--- a/cros_gralloc/cros_gralloc_driver.cc
+++ b/cros_gralloc/cros_gralloc_driver.cc
@@ -161,6 +161,8 @@ static void drv_destroy_and_close(struct driver *drv)
 static bool is_running_with_software_rendering()
 {
 	const char *vulkan_driver = drv_get_os_option("ro.hardware.vulkan");
+	if (!vulkan_driver)
+		vulkan_driver = drv_get_os_option("ro.board.platform");
 	return (vulkan_driver != nullptr && strstr(vulkan_driver, "pastel") != nullptr);
 }
 
diff --git a/cros_gralloc/cros_gralloc_helpers.cc b/cros_gralloc/cros_gralloc_helpers.cc
index 9495778..90bb6a1 100644
--- a/cros_gralloc/cros_gralloc_helpers.cc
+++ b/cros_gralloc/cros_gralloc_helpers.cc
@@ -21,6 +21,12 @@
 /* Define to match AIDL PixelFormat::R_8. */
 #define HAL_PIXEL_FORMAT_R8 0x38
 
+/* New formats from hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/PixelFormat.aidl */
+#define HAL_PIXEL_FORMAT_R16_UINT 57
+#define HAL_PIXEL_FORMAT_R16G16_UINT 58
+#define HAL_PIXEL_FORMAT_RGBA_10101010 59
+
+
 uint32_t cros_gralloc_convert_format(int format)
 {
 	/*
@@ -88,6 +94,14 @@ uint32_t cros_gralloc_convert_format(int format)
 		return DRM_FORMAT_DEPTH32;
 	case HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8:
 		return DRM_FORMAT_DEPTH32_STENCIL8;
+#if ANDROID_API_LEVEL >= 34
+	case HAL_PIXEL_FORMAT_R16_UINT:
+		return DRM_FORMAT_R16;
+	case HAL_PIXEL_FORMAT_R16G16_UINT:
+		return DRM_FORMAT_GR1616;
+	case HAL_PIXEL_FORMAT_RGBA_10101010:
+		return DRM_FORMAT_AXBXGXRX106106106106;
+#endif
 	}
 
 	return DRM_FORMAT_NONE;
diff --git a/cros_gralloc/gralloc4/Android.bp b/cros_gralloc/gralloc4/Android.bp
index 73588f7..432a89d 100644
--- a/cros_gralloc/gralloc4/Android.bp
+++ b/cros_gralloc/gralloc4/Android.bp
@@ -126,6 +126,14 @@ cc_binary {
     },
 }
 
+cc_binary {
+    name: "android.hardware.graphics.allocator@4.0-service.minigbm_mediatek",
+    defaults: ["minigbm_gralloc4_allocator_defaults"],
+    shared_libs: ["libminigbm_gralloc_mediatek"],
+    vintf_fragment_modules: ["android.hardware.graphics.allocator@4.0.xml"],
+    init_rc: ["android.hardware.graphics.allocator@4.0-service.minigbm_mediatek.rc"],
+}
+
 vintf_fragment {
     name: "android.hardware.graphics.mapper@4.0.xml",
     src: "android.hardware.graphics.mapper@4.0.xml",
@@ -172,3 +180,11 @@ cc_library_shared {
         },
     },
 }
+
+cc_library_shared {
+    name: "android.hardware.graphics.mapper@4.0-impl.minigbm_mediatek",
+    defaults: ["minigbm_gralloc4_common_defaults"],
+    shared_libs: ["libminigbm_gralloc_mediatek"],
+    vintf_fragment_modules: ["android.hardware.graphics.mapper@4.0.xml"],
+    srcs: [":minigbm_gralloc4_mapper_files"],
+}
diff --git a/cros_gralloc/gralloc4/CrosGralloc4Mapper.cc b/cros_gralloc/gralloc4/CrosGralloc4Mapper.cc
index f9f75b6..7219a3f 100644
--- a/cros_gralloc/gralloc4/CrosGralloc4Mapper.cc
+++ b/cros_gralloc/gralloc4/CrosGralloc4Mapper.cc
@@ -16,6 +16,7 @@
 #include <cutils/native_handle.h>
 #include <gralloctypes/Gralloc4.h>
 
+#include "cros_gralloc/cros_gralloc_arm.h"
 #include "cros_gralloc/cros_gralloc_helpers.h"
 #include "cros_gralloc/gralloc4/CrosGralloc4Utils.h"
 
@@ -34,6 +35,11 @@ using android::hardware::graphics::common::V1_2::PixelFormat;
 using android::hardware::graphics::mapper::V4_0::Error;
 using android::hardware::graphics::mapper::V4_0::IMapper;
 
+const static IMapper::MetadataType kArmMetadataTypePlaneFds{
+        GRALLOC_ARM_METADATA_TYPE_NAME, static_cast<int64_t>(ArmMetadataType::PLANE_FDS)};
+const static IMapper::MetadataType kArmMetadataTypeFormatDataType{
+        GRALLOC_ARM_METADATA_TYPE_NAME, static_cast<int64_t>(ArmMetadataType::FORMAT_DATA_TYPE)};
+
 Return<void> CrosGralloc4Mapper::createDescriptor(const BufferDescriptorInfo& description,
                                                   createDescriptor_cb hidlCb) {
     hidl_vec<uint8_t> descriptor;
@@ -480,8 +486,18 @@ Return<void> CrosGralloc4Mapper::get(const cros_gralloc_buffer* crosBuffer,
                 crosBuffer->get_android_usage() & BufferUsage::PROTECTED ? 1 : 0;
         status = android::gralloc4::encodeProtectedContent(hasProtectedContent, &encodedMetadata);
     } else if (metadataType == android::gralloc4::MetadataType_Compression) {
-        status = android::gralloc4::encodeCompression(android::gralloc4::Compression_None,
-                                                      &encodedMetadata);
+        ExtendableType compression = android::gralloc4::Compression_None;
+        uint64_t modifier = crosBuffer->get_format_modifier();
+
+        if (fourcc_mod_is_vendor(modifier, ARM)) {
+            if (((modifier >> 52) & 0xF) == DRM_FORMAT_MOD_ARM_TYPE_AFBC) {
+                compression = Compression_AFBC;
+            } else if (((modifier >> 52) & 0xF) == DRM_FORMAT_MOD_ARM_TYPE_AFRC) {
+                compression = Compression_AFRC;
+            }
+        }
+
+        status = android::gralloc4::encodeCompression(compression, &encodedMetadata);
     } else if (metadataType == android::gralloc4::MetadataType_Interlaced) {
         status = android::gralloc4::encodeInterlaced(android::gralloc4::Interlaced_None,
                                                      &encodedMetadata);
@@ -557,6 +573,20 @@ Return<void> CrosGralloc4Mapper::get(const cros_gralloc_buffer* crosBuffer,
         }
     } else if (metadataType == android::gralloc4::MetadataType_Smpte2094_40) {
         status = android::gralloc4::encodeSmpte2094_40(std::nullopt, &encodedMetadata);
+    } else if (metadataType == kArmMetadataTypePlaneFds) {
+        uint32_t num_planes = crosBuffer->get_num_planes();
+        int64_t plane_fds[5];
+        plane_fds[0] = num_planes;
+        for (auto plane = 0; plane < num_planes; plane++) {
+            plane_fds[1 + plane] = crosBuffer->get_plane_fd(plane);
+        }
+        encodedMetadata.resize(sizeof(uint64_t) * (1 + num_planes));
+        memcpy(encodedMetadata.data(), plane_fds, encodedMetadata.size());
+    } else if (metadataType == kArmMetadataTypeFormatDataType) {
+        uint32_t pf = crosBuffer->get_format();
+        int64_t fdt = static_cast<int64_t>(DataTypeFromDrmPixelFormat(pf));
+        encodedMetadata.resize(sizeof(fdt));
+        memcpy(encodedMetadata.data(), &fdt, encodedMetadata.size());
     } else {
         hidlCb(Error::UNSUPPORTED, encodedMetadata);
         return Void();
@@ -940,6 +970,18 @@ Return<void> CrosGralloc4Mapper::listSupportedMetadataTypes(listSupportedMetadat
                     /*isGettable=*/true,
                     /*isSettable=*/false,
             },
+            {
+                    kArmMetadataTypePlaneFds,
+                    "Vector of file descriptors of each plane",
+                    /*isGettable=*/true,
+                    /*isSettable=*/false,
+            },
+            {
+                    kArmMetadataTypeFormatDataType,
+                    "Format data type",
+                    /*isGettable=*/true,
+                    /*isSettable=*/false,
+            },
     });
 
     hidlCb(Error::NONE, supported);
diff --git a/cros_gralloc/gralloc4/android.hardware.graphics.allocator@4.0-service.minigbm_mediatek.rc b/cros_gralloc/gralloc4/android.hardware.graphics.allocator@4.0-service.minigbm_mediatek.rc
new file mode 100644
index 0000000..d8d87fd
--- /dev/null
+++ b/cros_gralloc/gralloc4/android.hardware.graphics.allocator@4.0-service.minigbm_mediatek.rc
@@ -0,0 +1,24 @@
+#
+# Copyright 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+service vendor.graphics.allocator-4-0 /vendor/bin/hw/android.hardware.graphics.allocator@4.0-service.minigbm_mediatek
+    interface android.hardware.graphics.allocator@4.0::IAllocator default
+    class hal animation
+    user system
+    group graphics drmrpc
+    capabilities SYS_NICE
+    onrestart restart surfaceflinger
+    task_profiles ServiceCapacityLow
diff --git a/cros_gralloc/mapper_stablec/Mapper.cpp b/cros_gralloc/mapper_stablec/Mapper.cpp
index 866f0dd..a5aa795 100644
--- a/cros_gralloc/mapper_stablec/Mapper.cpp
+++ b/cros_gralloc/mapper_stablec/Mapper.cpp
@@ -17,6 +17,7 @@
 
 #include <memory>
 
+#include "cros_gralloc/cros_gralloc_arm.h"
 #include "cros_gralloc/cros_gralloc_driver.h"
 #include "cros_gralloc/cros_gralloc_handle.h"
 #include "cros_gralloc/gralloc4/CrosGralloc4Utils.h"
@@ -49,10 +50,19 @@ static_assert(CROS_GRALLOC_BUFFER_METADATA_MAX_NAME_SIZE >=
 constexpr const char* STANDARD_METADATA_NAME =
         "android.hardware.graphics.common.StandardMetadataType";
 
+constexpr const AIMapper_MetadataType kArmMetadataTypePlaneFds{
+        GRALLOC_ARM_METADATA_TYPE_NAME, static_cast<int64_t>(ArmMetadataType::PLANE_FDS)};
+constexpr const AIMapper_MetadataType kArmMetadataTypeFormatDataType{
+        GRALLOC_ARM_METADATA_TYPE_NAME, static_cast<int64_t>(ArmMetadataType::FORMAT_DATA_TYPE)};
+
 static bool isStandardMetadata(AIMapper_MetadataType metadataType) {
     return strcmp(STANDARD_METADATA_NAME, metadataType.name) == 0;
 }
 
+static bool isArmMetadata(AIMapper_MetadataType metadataType) {
+    return strcmp(GRALLOC_ARM_METADATA_TYPE_NAME, metadataType.name) == 0;
+}
+
 class CrosGrallocMapperV5 final : public vendor::mapper::IMapperV5Impl {
   private:
     std::shared_ptr<cros_gralloc_driver> mDriver = cros_gralloc_driver::get_instance();
@@ -119,6 +129,9 @@ class CrosGrallocMapperV5 final : public vendor::mapper::IMapperV5Impl {
     void dumpBuffer(
             const cros_gralloc_buffer* crosBuffer,
             std::function<void(AIMapper_MetadataType, const std::vector<uint8_t>&)> callback);
+
+    int32_t getArmMetadata(buffer_handle_t _Nonnull buffer, int64_t armMetadataType,
+                           void* _Nonnull outData, size_t outDataSize);
 };
 
 AIMapper_Error CrosGrallocMapperV5::importBuffer(
@@ -268,14 +281,65 @@ AIMapper_Error CrosGrallocMapperV5::rereadLockedBuffer(buffer_handle_t _Nonnull
 int32_t CrosGrallocMapperV5::getMetadata(buffer_handle_t _Nonnull buffer,
                                          AIMapper_MetadataType metadataType, void* _Nonnull outData,
                                          size_t outDataSize) {
-    // We don't have any vendor-specific metadata, so divert to getStandardMetadata after validating
-    // that this is a standard metadata request
     if (isStandardMetadata(metadataType)) {
         return getStandardMetadata(buffer, metadataType.value, outData, outDataSize);
     }
+
+    if (isArmMetadata(metadataType)) {
+        return getArmMetadata(buffer, metadataType.value, outData, outDataSize);
+    }
     return -AIMAPPER_ERROR_UNSUPPORTED;
 }
 
+int32_t CrosGrallocMapperV5::getArmMetadata(buffer_handle_t _Nonnull buffer,
+                                            int64_t armMetadataType, void* _Nonnull outData,
+                                            size_t outDataSize) {
+    cros_gralloc_handle_t crosHandle = cros_gralloc_convert_handle(buffer);
+    if (!crosHandle) {
+        ALOGE("Failed to get. Invalid handle.");
+        return -AIMAPPER_ERROR_BAD_BUFFER;
+    }
+    int32_t retValue = -AIMAPPER_ERROR_UNSUPPORTED;
+    switch (armMetadataType) {
+        case ArmMetadataType::PLANE_FDS: {
+            mDriver->with_buffer(crosHandle, [&](cros_gralloc_buffer* crosBuffer) {
+                uint32_t num_planes = crosBuffer->get_num_planes();
+
+                retValue = sizeof(int64_t) * (1 + num_planes);
+                if (outDataSize >= retValue) {
+                    int64_t plane_fds[DRV_MAX_PLANES + 1];
+
+                    plane_fds[0] = num_planes;
+                    for (auto plane = 0; plane < num_planes; plane++) {
+                        plane_fds[1 + plane] = crosBuffer->get_plane_fd(plane);
+                    }
+
+                    memcpy(outData, plane_fds, sizeof(uint64_t) * (1 + num_planes));
+
+                    retValue = sizeof(uint64_t) * (1 + num_planes);
+                }
+            });
+            break;
+        }
+        case ArmMetadataType::FORMAT_DATA_TYPE: {
+            mDriver->with_buffer(crosHandle, [&](cros_gralloc_buffer* crosBuffer) {
+                uint32_t pf = crosBuffer->get_format();
+                int64_t fdt = static_cast<int64_t>(DataTypeFromDrmPixelFormat(pf));
+
+                retValue = sizeof(fdt);
+                if (outDataSize >= retValue) {
+                    memcpy(outData, &fdt, sizeof(fdt));
+                    retValue = sizeof(fdt);
+                }
+            });
+            break;
+        }
+        default:
+            return -AIMAPPER_ERROR_UNSUPPORTED;
+    }
+    return retValue;
+}
+
 int32_t CrosGrallocMapperV5::getStandardMetadata(buffer_handle_t _Nonnull bufferHandle,
                                                  int64_t standardType, void* _Nonnull outData,
                                                  size_t outDataSize) {
@@ -355,7 +419,18 @@ int32_t CrosGrallocMapperV5::getStandardMetadata(const cros_gralloc_buffer* cros
         return provide(hasProtectedContent);
     }
     if constexpr (metadataType == StandardMetadataType::COMPRESSION) {
-        return provide(android::gralloc4::Compression_None);
+        ExtendableType compression = android::gralloc4::Compression_None;
+        uint64_t modifier = crosBuffer->get_format_modifier();
+
+        if (fourcc_mod_is_vendor(modifier, ARM)) {
+            if (((modifier >> 52) & 0xF) == DRM_FORMAT_MOD_ARM_TYPE_AFBC) {
+                compression = Compression_AFBC;
+            } else if (((modifier >> 52) & 0xF) == DRM_FORMAT_MOD_ARM_TYPE_AFRC) {
+                compression = Compression_AFRC;
+            }
+        }
+
+        return provide(compression);
     }
     if constexpr (metadataType == StandardMetadataType::INTERLACED) {
         return provide(android::gralloc4::Interlaced_None);
@@ -528,7 +603,7 @@ constexpr AIMapper_MetadataTypeDescription describeStandard(StandardMetadataType
 AIMapper_Error CrosGrallocMapperV5::listSupportedMetadataTypes(
         const AIMapper_MetadataTypeDescription* _Nullable* _Nonnull outDescriptionList,
         size_t* _Nonnull outNumberOfDescriptions) {
-    static constexpr std::array<AIMapper_MetadataTypeDescription, 22> sSupportedMetadaTypes{
+    static constexpr std::array<AIMapper_MetadataTypeDescription, 24> sSupportedMetadaTypes{
             describeStandard(StandardMetadataType::BUFFER_ID, true, false),
             describeStandard(StandardMetadataType::NAME, true, false),
             describeStandard(StandardMetadataType::WIDTH, true, false),
@@ -551,6 +626,8 @@ AIMapper_Error CrosGrallocMapperV5::listSupportedMetadataTypes(
             describeStandard(StandardMetadataType::SMPTE2086, true, true),
             describeStandard(StandardMetadataType::CTA861_3, true, true),
             describeStandard(StandardMetadataType::STRIDE, true, false),
+            {kArmMetadataTypePlaneFds, "Vector of file descriptors of each plane", true, false, {0}},
+            {kArmMetadataTypeFormatDataType, "Format data type", true, false, {0}},
     };
     *outDescriptionList = sSupportedMetadaTypes.data();
     *outNumberOfDescriptions = sSupportedMetadaTypes.size();
diff --git a/drv_helpers.c b/drv_helpers.c
index 12b671a..b0979d1 100644
--- a/drv_helpers.c
+++ b/drv_helpers.c
@@ -165,10 +165,12 @@ static const struct planar_layout *layout_from_format(uint32_t format)
 	case DRM_FORMAT_XBGR8888:
 	case DRM_FORMAT_XRGB2101010:
 	case DRM_FORMAT_XRGB8888:
+	case DRM_FORMAT_GR1616:
 		return &packed_4bpp_layout;
 
 	case DRM_FORMAT_DEPTH32_STENCIL8:
 	case DRM_FORMAT_ABGR16161616F:
+	case DRM_FORMAT_AXBXGXRX106106106106:
 		return &packed_8bpp_layout;
 
 	default:
diff --git a/external/dma-heap.h b/external/dma-heap.h
new file mode 100644
index 0000000..a4cf716
--- /dev/null
+++ b/external/dma-heap.h
@@ -0,0 +1,53 @@
+/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
+/*
+ * DMABUF Heaps Userspace API
+ *
+ * Copyright (C) 2011 Google, Inc.
+ * Copyright (C) 2019 Linaro Ltd.
+ */
+#ifndef _UAPI_LINUX_DMABUF_POOL_H
+#define _UAPI_LINUX_DMABUF_POOL_H
+
+#include <linux/ioctl.h>
+#include <linux/types.h>
+
+/**
+ * DOC: DMABUF Heaps Userspace API
+ */
+
+/* Valid FD_FLAGS are O_CLOEXEC, O_RDONLY, O_WRONLY, O_RDWR */
+#define DMA_HEAP_VALID_FD_FLAGS (O_CLOEXEC | O_ACCMODE)
+
+/* Currently no heap flags */
+#define DMA_HEAP_VALID_HEAP_FLAGS (0ULL)
+
+/**
+ * struct dma_heap_allocation_data - metadata passed from userspace for
+ *                                      allocations
+ * @len:		size of the allocation
+ * @fd:			will be populated with a fd which provides the
+ *			handle to the allocated dma-buf
+ * @fd_flags:		file descriptor flags used when allocating
+ * @heap_flags:		flags passed to heap
+ *
+ * Provided by userspace as an argument to the ioctl
+ */
+struct dma_heap_allocation_data {
+	__u64 len;
+	__u32 fd;
+	__u32 fd_flags;
+	__u64 heap_flags;
+};
+
+#define DMA_HEAP_IOC_MAGIC		'H'
+
+/**
+ * DOC: DMA_HEAP_IOCTL_ALLOC - allocate memory from pool
+ *
+ * Takes a dma_heap_allocation_data struct and returns it with the fd field
+ * populated with the dmabuf handle of the allocation.
+ */
+#define DMA_HEAP_IOCTL_ALLOC	_IOWR(DMA_HEAP_IOC_MAGIC, 0x0,\
+				      struct dma_heap_allocation_data)
+
+#endif /* _UAPI_LINUX_DMABUF_POOL_H */
diff --git a/external/mediatek_drm.h b/external/mediatek_drm.h
new file mode 100644
index 0000000..51c5dc1
--- /dev/null
+++ b/external/mediatek_drm.h
@@ -0,0 +1,62 @@
+/*
+ * Copyright (c) 2015 MediaTek Inc.
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ */
+
+
+#ifndef _UAPI_MEDIATEK_DRM_H
+#define _UAPI_MEDIATEK_DRM_H
+
+#include "drm.h"
+
+/**
+ * User-desired buffer creation information structure.
+ *
+ * @size: user-desired memory allocation size.
+ *      - this size value would be page-aligned internally.
+ * @flags: user request for setting memory type or cache attributes.
+ * @handle: returned a handle to created gem object.
+ *	- this handle will be set by gem module of kernel side.
+ */
+struct drm_mtk_gem_create {
+	uint64_t size;
+	uint32_t flags;
+	uint32_t handle;
+};
+
+/**
+ * A structure for getting buffer offset.
+ *
+ * @handle: a pointer to gem object created.
+ * @pad: just padding to be 64-bit aligned.
+ * @offset: relatived offset value of the memory region allocated.
+ *	- this value should be set by user.
+ */
+struct drm_mtk_gem_map_off {
+	uint32_t handle;
+	uint32_t pad;
+	uint64_t offset;
+};
+
+#define DRM_MTK_GEM_CREATE              0x00
+#define DRM_MTK_GEM_MAP_OFFSET          0x01
+
+#define DRM_MTK_GEM_CREATE_FLAG_RESTRICTED          (1 << 0)
+#define DRM_MTK_GEM_CREATE_FLAG_ALLOC_SINGLE_PAGES  (1 << 1)
+
+#define DRM_IOCTL_MTK_GEM_CREATE        DRM_IOWR(DRM_COMMAND_BASE + \
+                DRM_MTK_GEM_CREATE, struct drm_mtk_gem_create)
+
+#define DRM_IOCTL_MTK_GEM_MAP_OFFSET    DRM_IOWR(DRM_COMMAND_BASE + \
+                DRM_MTK_GEM_MAP_OFFSET, struct drm_mtk_gem_map_off)
+
+
+#endif /* _UAPI_MEDIATEK_DRM_H */
diff --git a/intel_defines.h b/intel_defines.h
index bb00100..36d1f03 100644
--- a/intel_defines.h
+++ b/intel_defines.h
@@ -28,6 +28,20 @@ static const uint32_t texture_only_formats[] = {
 	DRM_FORMAT_YVU420_ANDROID,
 };
 
+static const uint32_t image_storage_formats[] = {
+	DRM_FORMAT_ABGR2101010,
+	DRM_FORMAT_ABGR8888,
+	DRM_FORMAT_ARGB2101010,
+	DRM_FORMAT_ARGB8888,
+	DRM_FORMAT_RGB565,
+	DRM_FORMAT_XBGR2101010,
+	DRM_FORMAT_XBGR8888,
+	DRM_FORMAT_XRGB2101010,
+	DRM_FORMAT_XRGB8888,
+	DRM_FORMAT_ABGR16161616F,
+	DRM_FORMAT_R8,
+};
+
 static const uint64_t gen12_modifier_order[] = {
 	I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS,
 	I915_FORMAT_MOD_Y_TILED,
@@ -51,12 +65,14 @@ const uint16_t gen12_ids[] = {
 };
 
 const uint16_t adlp_ids[] = {
-	0x46A0, 0x46A1, 0x46A2, 0x46A3, 0x46A6, 0x46A8, 0x46AA,
-	0x462A, 0x4626, 0x4628, 0x46B0, 0x46B1, 0x46B2, 0x46B3,
-	0x46C0, 0x46C1, 0x46C2, 0x46C3, 0x46D0, 0x46D1, 0x46D2,
+	0x46A0, 0x46A1, 0x46A2, 0x46A3, 0x46A6, 0x46A8, 0x46AA, 0x462A, 0x4626, 0x4628,
+	0x46B0, 0x46B1, 0x46B2, 0x46B3, 0x46C0, 0x46C1, 0x46C2, 0x46C3, 0x46D0, 0x46D1,
+	0x46D2, 0x46D3, 0x46D4,
 };
 
-const uint16_t rplp_ids[] = { 0xA720, 0xA721, 0xA7A0, 0xA7A1, 0xA7A8, 0xA7A9, };
+const uint16_t rplp_ids[] = {
+	0xA720, 0xA721, 0xA7A0, 0xA7A1, 0xA7A8, 0xA7A9, 0xA7AA, 0xA7AB, 0xA7AC, 0xA7AD,
+};
 
 const uint16_t mtl_ids[] = { 0x7D40, 0x7D60, 0x7D45, 0x7D55, 0x7DD5, };
 
diff --git a/mediatek.c b/mediatek.c
index e34f672..23685be 100644
--- a/mediatek.c
+++ b/mediatek.c
@@ -10,9 +10,6 @@
 #include <errno.h>
 #include <fcntl.h>
 #include <inttypes.h>
-#if !defined(ANDROID) || (ANDROID_API_LEVEL >= 31 && defined(HAS_DMABUF_SYSTEM_HEAP))
-#include <linux/dma-heap.h>
-#endif
 #include <poll.h>
 #include <stdio.h>
 #include <string.h>
@@ -20,7 +17,10 @@
 #include <sys/mman.h>
 #include <unistd.h>
 #include <xf86drm.h>
-#include <mediatek_drm.h>
+#if !defined(ANDROID) || (ANDROID_API_LEVEL >= 31 && defined(HAS_DMABUF_SYSTEM_HEAP))
+#include "external/dma-heap.h"
+#endif
+#include "external/mediatek_drm.h"
 // clang-format on
 
 #include "drv_helpers.h"
@@ -36,8 +36,7 @@
 #define SUPPORT_YUV422
 #endif
 
-// All platforms except MT8173 should USE_NV12_FOR_HW_VIDEO_DECODING
-// and SUPPORT_FP16_AND_10BIT_ABGR
+// All platforms except MT8173 should SUPPORT_FP16_AND_10BIT_ABGR
 // clang-format off
 #if defined(MTK_MT8183) || \
     defined(MTK_MT8186) || \
@@ -46,7 +45,6 @@
     defined(MTK_MT8195) || \
     defined(MTK_MT8196)
 // clang-format on
-#define USE_NV12_FOR_HW_VIDEO_DECODING
 #define SUPPORT_FP16_AND_10BIT_ABGR
 #else
 #define DONT_USE_64_ALIGNMENT_FOR_VIDEO_BUFFERS
@@ -113,6 +111,13 @@ static const uint32_t video_yuv_formats[] = {
 	DRM_FORMAT_YVU420,
 	DRM_FORMAT_YVU420_ANDROID
 };
+
+// In addition to all scanout we should also support R8 and non YUV texture formats.
+static const uint32_t gpu_data_buffer_formats[] = {
+	DRM_FORMAT_R8,
+	DRM_FORMAT_ABGR2101010,
+	DRM_FORMAT_ABGR16161616F
+};
 // clang-format on
 
 static bool is_video_yuv_format(uint32_t format)
@@ -129,6 +134,7 @@ static int mediatek_init(struct driver *drv)
 {
 	struct format_metadata metadata;
 	struct mediatek_private_drv_data *priv;
+	uint64_t protected = BO_USE_PROTECTED;
 
 	priv = calloc(1, sizeof(*priv));
 	if (!priv) {
@@ -136,28 +142,37 @@ static int mediatek_init(struct driver *drv)
 		return -errno;
 	}
 
+#if defined(HAS_DMABUF_SYSTEM_HEAP)
+	priv->dma_heap_fd = open("/dev/dma_heap/restricted_mtk_cma", O_RDWR | O_CLOEXEC);
+	if (priv->dma_heap_fd < 0) {
+		drv_loge("Failed opening secure CMA heap errno=%d\n", -errno);
+		protected = 0;
+	}
+#else
 	priv->dma_heap_fd = -1;
+	protected = 0;
+#endif
+
 	drv->priv = priv;
 
 	drv_add_combinations(drv, render_target_formats, ARRAY_SIZE(render_target_formats),
-			     &LINEAR_METADATA,
-			     BO_USE_RENDER_MASK | BO_USE_SCANOUT | BO_USE_PROTECTED);
+			     &LINEAR_METADATA, BO_USE_RENDER_MASK | BO_USE_SCANOUT | protected);
 
 	drv_add_combinations(drv, texture_source_formats, ARRAY_SIZE(texture_source_formats),
-			     &LINEAR_METADATA, BO_USE_TEXTURE_MASK | BO_USE_PROTECTED);
+			     &LINEAR_METADATA, BO_USE_TEXTURE_MASK | protected);
 
 	drv_add_combination(drv, DRM_FORMAT_R8, &LINEAR_METADATA,
-			    BO_USE_SW_MASK | BO_USE_LINEAR | BO_USE_PROTECTED);
+			    BO_USE_SW_MASK | BO_USE_LINEAR | protected);
 
 #ifdef SUPPORT_AR30_OVERLAYS
 	drv_add_combination(drv, DRM_FORMAT_ARGB2101010, &LINEAR_METADATA,
-			    BO_USE_TEXTURE | BO_USE_SCANOUT | BO_USE_PROTECTED | BO_USE_LINEAR);
+			    BO_USE_TEXTURE | BO_USE_SCANOUT | protected | BO_USE_LINEAR);
 #endif
 
 	/* YUYV format for video overlay and camera subsystem. */
 	drv_add_combination(drv, DRM_FORMAT_YUYV, &LINEAR_METADATA,
 			    BO_USE_HW_VIDEO_DECODER | BO_USE_SCANOUT | BO_USE_LINEAR |
-				BO_USE_TEXTURE | BO_USE_PROTECTED);
+				BO_USE_TEXTURE | protected);
 
 	/* Android CTS tests require this. */
 	drv_add_combination(drv, DRM_FORMAT_BGR888, &LINEAR_METADATA, BO_USE_SW_MASK);
@@ -167,7 +182,7 @@ static int mediatek_init(struct driver *drv)
 	metadata.priority = 1;
 	metadata.modifier = DRM_FORMAT_MOD_LINEAR;
 	drv_modify_combination(drv, DRM_FORMAT_YVU420, &metadata,
-			       BO_USE_HW_VIDEO_DECODER | BO_USE_PROTECTED);
+			       BO_USE_HW_VIDEO_DECODER | protected);
 #ifdef MTK_MT8173
 	/*
 	 * b/292507490: The MT8173 decoder can output YUV420 only. Some CTS tests feed the
@@ -178,14 +193,13 @@ static int mediatek_init(struct driver *drv)
 	drv_modify_combination(drv, DRM_FORMAT_YVU420, &metadata, BO_USE_HW_VIDEO_ENCODER);
 #endif
 	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata,
-			       BO_USE_HW_VIDEO_DECODER | BO_USE_PROTECTED);
-#ifdef USE_NV12_FOR_HW_VIDEO_DECODING
-	// TODO(hiroh): Switch to use NV12 for video decoder on MT8173 as well.
+			       BO_USE_HW_VIDEO_DECODER | protected);
+#ifndef MTK_MT8173
 	drv_modify_combination(drv, DRM_FORMAT_NV12, &metadata,
-			       BO_USE_HW_VIDEO_DECODER | BO_USE_PROTECTED);
+			       BO_USE_HW_VIDEO_DECODER | protected);
 #endif
 	drv_modify_combination(drv, DRM_FORMAT_P010, &metadata,
-			       BO_USE_HW_VIDEO_DECODER | BO_USE_PROTECTED);
+			       BO_USE_HW_VIDEO_DECODER | protected);
 
 	/*
 	 * R8 format is used for Android's HAL_PIXEL_FORMAT_BLOB for input/output from
@@ -197,16 +211,21 @@ static int mediatek_init(struct driver *drv)
 				   BO_USE_GPU_DATA_BUFFER | BO_USE_SENSOR_DIRECT_DATA);
 
 	/* NV12 format for encoding and display. */
+#ifndef MTK_MT8173
+	drv_modify_combination(drv, DRM_FORMAT_NV12, &metadata,
+			       BO_USE_SCANOUT | BO_USE_HW_VIDEO_ENCODER | BO_USE_CAMERA_READ |
+				   BO_USE_CAMERA_WRITE | BO_USE_SW_MASK);
+#else
 	drv_modify_combination(drv, DRM_FORMAT_NV12, &metadata,
 			       BO_USE_SCANOUT | BO_USE_HW_VIDEO_ENCODER | BO_USE_CAMERA_READ |
 				   BO_USE_CAMERA_WRITE);
+#endif
 
 	/*
 	 * Android also frequently requests YV12 formats for some camera implementations
-	 * (including the external provider implmenetation).
+	 * (including the external provider implementation).
 	 */
-	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata,
-			       BO_USE_CAMERA_WRITE);
+	drv_modify_combination(drv, DRM_FORMAT_YVU420_ANDROID, &metadata, BO_USE_CAMERA_WRITE);
 
 #ifdef MTK_MT8183
 	/* Only for MT8183 Camera subsystem */
@@ -221,6 +240,15 @@ static int mediatek_init(struct driver *drv)
 			    BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE | BO_USE_SW_MASK);
 #endif
 
+	for (unsigned i = 0; i < ARRAY_SIZE(render_target_formats); i++) {
+		drv_modify_combination(drv, render_target_formats[i], &metadata,
+				       BO_USE_GPU_DATA_BUFFER);
+	}
+	for (unsigned i = 0; i < ARRAY_SIZE(gpu_data_buffer_formats); i++) {
+		drv_modify_combination(drv, gpu_data_buffer_formats[i], &metadata,
+				       BO_USE_GPU_DATA_BUFFER);
+	}
+
 	return drv_modify_linear_combinations(drv);
 }
 
@@ -249,6 +277,7 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 	const bool is_linear = bo->meta.use_flags & BO_USE_LINEAR;
 	const bool is_protected = bo->meta.use_flags & BO_USE_PROTECTED;
 	const bool is_scanout = bo->meta.use_flags & BO_USE_SCANOUT;
+	const bool is_cursor = bo->meta.use_flags & BO_USE_CURSOR;
 	/*
 	 * We identify the ChromeOS Camera App buffers via these two USE flags. Those buffers need
 	 * the same alignment as the video hardware encoding.
@@ -272,6 +301,27 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 		return -EINVAL;
 	}
 
+	/*
+	 * For cursor buffer, add padding as needed to reach a known cursor-plane-supported
+	 * buffer size, as reported by the cursor capability properties.
+	 *
+	 * If the requested dimensions exceed either of the reported capabilities, or if the
+	 * capabilities couldn't be read, silently fallback by continuing without additional
+	 * padding. The buffer can still be used normally, and be committed to non-cursor
+	 * planes.
+	 */
+	if (is_cursor) {
+		uint64_t cursor_width = 0;
+		uint64_t cursor_height = 0;
+		bool err = drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_WIDTH, &cursor_width) ||
+			   drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_HEIGHT, &cursor_height);
+
+		if (!err && width <= cursor_width && height <= cursor_height) {
+			width = cursor_width;
+			height = cursor_height;
+		}
+	}
+
 	/*
 	 * Since the ARM L1 cache line size is 64 bytes, align to that as a
 	 * performance optimization, except for video buffers on certain platforms,
@@ -292,7 +342,7 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 	 * not allocated by minigbm. So we don't have to care about it. The tiled buffer is
 	 * converted to NV12 or YV12, which is allocated by minigbm. V4L2 MDP doesn't
 	 * require any special alignment for them.
-	 * On the other hand, the mediatek video encoder reuqires a padding on each plane.
+	 * On the other hand, the mediatek video encoder requires a padding on each plane.
 	 * When both video decoder and encoder use flag is masked (in some CTS test), we
 	 * align with the encoder alignment.
 	 * However, V4L2VideoDecodeAccelerator used on MT8173 fails handling the buffer with
@@ -369,12 +419,18 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 	if (is_protected) {
 #if !defined(ANDROID) || (ANDROID_API_LEVEL >= 31 && defined(HAS_DMABUF_SYSTEM_HEAP))
 		int ret;
-		struct mediatek_private_drv_data *priv = (struct mediatek_private_drv_data *)bo->drv->priv;
+		struct mediatek_private_drv_data *priv =
+		    (struct mediatek_private_drv_data *)bo->drv->priv;
 		struct dma_heap_allocation_data heap_data = {
 			.len = bo->meta.total_size,
 			.fd_flags = O_RDWR | O_CLOEXEC,
 		};
 
+		if (priv->dma_heap_fd < 0) {
+			drv_loge("Protected buffer requested but CMA heap doesn't exist.\n");
+			return -1;
+		}
+
 		if (format == DRM_FORMAT_P010) {
 			/*
 			 * Adjust the size so we don't waste tons of space. This was allocated
@@ -390,14 +446,6 @@ static int mediatek_bo_create_with_modifiers(struct bo *bo, uint32_t width, uint
 			heap_data.len = bo->meta.total_size;
 		}
 
-		if (priv->dma_heap_fd < 0) {
-			priv->dma_heap_fd = open("/dev/dma_heap/restricted_mtk_cma", O_RDWR | O_CLOEXEC);
-			if (priv->dma_heap_fd < 0) {
-				drv_loge("Failed opening secure CMA heap errno=%d\n", -errno);
-				return -errno;
-			}
-		}
-
 		ret = ioctl(priv->dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &heap_data);
 		if (ret < 0) {
 			drv_loge("Failed allocating CMA buffer ret=%d\n", ret);
@@ -590,35 +638,27 @@ static void mediatek_resolve_format_and_use_flags(struct driver *drv, uint32_t f
 		*out_use_flags &= ~BO_USE_HW_VIDEO_ENCODER;
 		break;
 	case DRM_FORMAT_FLEX_YCbCr_420_888:
-#ifdef USE_NV12_FOR_HW_VIDEO_DECODING
-		// TODO(hiroh): Switch to use NV12 for video decoder on MT8173 as well.
-		if (use_flags & (BO_USE_HW_VIDEO_DECODER)) {
-			*out_format = DRM_FORMAT_NV12;
-			break;
-		}
-#endif
+#ifndef MTK_MT8173
+		*out_format = DRM_FORMAT_NV12;
+		break;
+#else
 		/*
 		 * b/292507490: The MT8173 decoder can output YUV420 only. Some CTS tests feed the
 		 * decoded buffer to the hardware encoder and the tests allocate the buffer with
 		 * DRM_FORMAT_FLEX_YCbCr_420_888 with the mask of BO_USE_HW_VIDEO_ENCODER |
 		 * BO_USE_HW_VIDEO_DECODER. Therefore, we have to allocate YUV420 in the case.
 		 */
-		if (use_flags &
-		    (BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE | BO_USE_HW_VIDEO_ENCODER)) {
-#ifndef MTK_MT8173
+		if ((use_flags &
+		     (BO_USE_CAMERA_READ | BO_USE_CAMERA_WRITE | BO_USE_HW_VIDEO_ENCODER)) &&
+		    !(use_flags & BO_USE_HW_VIDEO_DECODER)) {
 			*out_format = DRM_FORMAT_NV12;
 			break;
-#else
-			if (!(use_flags & BO_USE_HW_VIDEO_DECODER)) {
-				*out_format = DRM_FORMAT_NV12;
-				break;
-			}
-#endif
 		}
 		/* HACK: See b/139714614 */
 		*out_format = DRM_FORMAT_YVU420;
 		*out_use_flags &= ~BO_USE_SCANOUT;
 		break;
+#endif
 	default:
 		break;
 	}
diff --git a/xe.c b/xe.c
index c265c30..2a14807 100644
--- a/xe.c
+++ b/xe.c
@@ -185,6 +185,12 @@ static int xe_add_combinations(struct driver *drv)
 				   BO_USE_HW_VIDEO_ENCODER | BO_USE_GPU_DATA_BUFFER |
 				   BO_USE_SENSOR_DIRECT_DATA);
 
+	/* Android AIDL gralloc allows use of AHB-backed external memory for storage images. */
+	for (unsigned i = 0; i < ARRAY_SIZE(image_storage_formats); i++) {
+		drv_modify_combination(drv, image_storage_formats[i], &metadata_linear,
+				       BO_USE_GPU_DATA_BUFFER);
+	}
+
 	const uint64_t render_not_linear = unset_flags(render, linear_mask);
 	const uint64_t scanout_and_render_not_linear = render_not_linear | BO_USE_SCANOUT;
 	struct format_metadata metadata_x_tiled = { .tiling = XE_TILING_X,
@@ -488,6 +494,26 @@ static int xe_bo_compute_metadata(struct bo *bo, uint32_t width, uint32_t height
 			modifier = combo->metadata.modifier;
 		}
 	}
+	/*
+	 * For cursor buffer, add padding as needed to reach a known cursor-plane-supported
+	 * buffer size, as reported by the cursor capability properties.
+	 *
+	 * If the requested dimensions exceed either of the reported capabilities, or if the
+	 * capabilities couldn't be read, silently fallback by continuing without additional
+	 * padding. The buffer can still be used normally, and be committed to non-cursor
+	 * planes.
+	 */
+	if (use_flags & BO_USE_CURSOR) {
+		uint64_t cursor_width = 0;
+		uint64_t cursor_height = 0;
+		bool err = drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_WIDTH, &cursor_width) ||
+			   drmGetCap(bo->drv->fd, DRM_CAP_CURSOR_HEIGHT, &cursor_height);
+
+		if (!err && width <= cursor_width && height <= cursor_height) {
+			width = cursor_width;
+			height = cursor_height;
+		}
+	}
 
 	/*
 	 * Skip I915_FORMAT_MOD_Y_TILED_CCS modifier if compression is disabled
```

