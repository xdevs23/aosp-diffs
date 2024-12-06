```diff
diff --git a/Android.bp b/Android.bp
index e1e46ae..fb83a98 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,7 +2,7 @@ soong_namespace {
     imports: [
         "hardware/google/graphics/common",
         "hardware/google/gchips/gralloc4",
-    ]
+    ],
 }
 
 package {
@@ -41,3 +41,9 @@ cc_library_headers {
 }
 
 subdirs = ["*"]
+
+cc_library_headers {
+    name: "gchips_headers",
+    export_include_dirs: ["include"],
+    proprietary: true,
+}
diff --git a/gralloc4/Android.bp b/gralloc4/Android.bp
index 33fa1db..670f7b3 100644
--- a/gralloc4/Android.bp
+++ b/gralloc4/Android.bp
@@ -75,7 +75,7 @@ soong_config_string_variable {
 soong_config_module_type {
     name: "gralloc_defaults",
     module_type: "cc_defaults",
-    config_namespace: "arm_gralloc",
+    config_namespace: "pixel_gralloc",
     variables: [
         "mapper_version",
     ],
diff --git a/gralloc4/service/aidl/service.cpp b/gralloc4/service/aidl/service.cpp
index 69c63f8..30ab3f1 100644
--- a/gralloc4/service/aidl/service.cpp
+++ b/gralloc4/service/aidl/service.cpp
@@ -21,6 +21,7 @@ int main() {
     auto service = ndk::SharedRefBase::make<GrallocAllocator>();
     auto binder = service->asBinder();
 
+    AIBinder_setInheritRt(binder.get(), true);
     AIBinder_setMinSchedulerPolicy(binder.get(), SCHED_NORMAL, -20);
 
     const auto instance = std::string() + GrallocAllocator::descriptor + "/default";
diff --git a/gralloc4/src/4.x/Android.bp b/gralloc4/src/4.x/Android.bp
index d2f75d7..7a7e48a 100644
--- a/gralloc4/src/4.x/Android.bp
+++ b/gralloc4/src/4.x/Android.bp
@@ -26,6 +26,7 @@ cc_defaults {
 		"arm_gralloc_defaults",
 		"arm_gralloc_version_defaults",
 	],
+	vintf_fragments: ["4.x/manifest.xml"],
 	relative_install_path: "hw/",
 	export_shared_lib_headers: [
 		"libhidlbase",
diff --git a/gralloc4/src/4.x/manifest.xml b/gralloc4/src/4.x/manifest.xml
new file mode 100644
index 0000000..3160c77
--- /dev/null
+++ b/gralloc4/src/4.x/manifest.xml
@@ -0,0 +1,11 @@
+<manifest version="1.0" type="device">
+    <hal format="hidl">
+        <name>android.hardware.graphics.mapper</name>
+        <transport arch="32+64">passthrough</transport>
+        <version>4.0</version>
+        <interface>
+            <name>IMapper</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</manifest>
diff --git a/gralloc4/src/Android.bp b/gralloc4/src/Android.bp
index 93d9bf5..d055e9e 100644
--- a/gralloc4/src/Android.bp
+++ b/gralloc4/src/Android.bp
@@ -43,7 +43,10 @@ gralloc_defaults {
 
 cc_library_shared {
     name: "pixel_gralloc_mapper",
-    defaults: ["gralloc_mapper_defaults"],
+    defaults: [
+        "gralloc_mapper_defaults",
+        "pixel-gralloc-headers-dependencies",
+    ],
 }
 
 gralloc_defaults {
diff --git a/gralloc4/src/aidl/GrallocAllocator2.cpp b/gralloc4/src/aidl/GrallocAllocator2.cpp
index a4ff6e9..455a2f1 100644
--- a/gralloc4/src/aidl/GrallocAllocator2.cpp
+++ b/gralloc4/src/aidl/GrallocAllocator2.cpp
@@ -97,6 +97,7 @@ buffer_descriptor_t toInternalDescriptor(
     bufferDescriptor.format_type = MALI_GRALLOC_FORMAT_TYPE_USAGE;
     bufferDescriptor.signature = sizeof(buffer_descriptor_t);
     bufferDescriptor.reserved_size = descriptor.reservedSize;
+    bufferDescriptor.additional_options = descriptor.additionalOptions;
     const char *str = (const char*) descriptor.name.data();
     bufferDescriptor.name = std::string(str);
     return bufferDescriptor;
@@ -152,7 +153,6 @@ ndk::ScopedAStatus GrallocAllocator::allocate2(
     return ndk::ScopedAStatus::ok();
 }
 
-// TODO(b/315883761): isSupported should return false for unknown-to-HAL usage
 ndk::ScopedAStatus GrallocAllocator::isSupported(
         const AidlAllocator::BufferDescriptorInfo& descriptor, bool* result) {
     buffer_descriptor_t bufferDescriptor = toInternalDescriptor(descriptor);
diff --git a/gralloc4/src/core/mali_gralloc_bufferaccess.cpp b/gralloc4/src/core/mali_gralloc_bufferaccess.cpp
index 19078c9..11c5d4a 100644
--- a/gralloc4/src/core/mali_gralloc_bufferaccess.cpp
+++ b/gralloc4/src/core/mali_gralloc_bufferaccess.cpp
@@ -155,8 +155,12 @@ int validate_lock_input_parameters(const buffer_handle_t buffer, const int l,
 		return GRALLOC1_ERROR_UNSUPPORTED;
 	}
 
-	/* Producer and consumer usage is verified in gralloc1 specific code. */
-	GRALLOC_UNUSED(usage);
+	/* Verify that we're locking a buffer that is used by CPU. */
+	if ((usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK)) == 0) {
+		MALI_GRALLOC_LOGE("Attempt to lock buffer %p with not-cpu usage (%s 0x%" PRIx64 ")",
+			buffer, describe_usage(usage).c_str(), usage);
+		return -EINVAL;
+	}
 
 	return 0;
 }
@@ -235,9 +239,7 @@ int mali_gralloc_lock(buffer_handle_t buffer,
 		buffer_sync(hnd, get_tx_direction(usage));
 		return mali_gralloc_reference_lock_retain(buffer);
 	}
-
 	return 0;
-
 }
 
 
diff --git a/gralloc4/src/core/mali_gralloc_bufferallocation.cpp b/gralloc4/src/core/mali_gralloc_bufferallocation.cpp
index 9ca0e34..5a397d1 100644
--- a/gralloc4/src/core/mali_gralloc_bufferallocation.cpp
+++ b/gralloc4/src/core/mali_gralloc_bufferallocation.cpp
@@ -266,12 +266,6 @@ void init_afbc(uint8_t *buf, const uint64_t alloc_format,
 		{ ((uint32_t)body_offset + (1 << 28)), 0x80200040, 0x1004000, 0x20080 } /* Layouts 1, 5 */
 	};
 
-	if (is_tiled)
-	{
-		/* Zero out body_offset for non-subsampled formats. */
-		memset(headers[0], 0, sizeof(size_t) * 4);
-	}
-
 	/* Map base format to AFBC header layout */
 	const uint32_t base_format = alloc_format & MALI_GRALLOC_INTFMT_FMT_MASK;
 
@@ -288,6 +282,16 @@ void init_afbc(uint8_t *buf, const uint64_t alloc_format,
 	 */
 	const uint32_t layout = is_subsampled_yuv(base_format) && !is_multi_plane ? 1 : 0;
 
+	/*
+	 * Solid colour blocks:  AFBC 1.2
+	 * This storage method is permitted for superblock_layout 0, 3, 4, or 7 with 64 bits per pixel or less.
+	 * In this case the value of the pixel is stored least significant bit aligned in bits[127:64] of the header, the payload is 0s.
+	 */
+	if (is_tiled && layout == 0 && bpp <= 64)
+	{
+		memset(headers[0], 0, sizeof(uint32_t) * 4);
+	}
+
 	/* We initialize only linear layouts*/
 	const size_t sb_bytes = is_tiled? 0 : GRALLOC_ALIGN((bpp * AFBC_PIXELS_PER_BLOCK) / 8, 128);
 
@@ -518,7 +522,11 @@ static bool validate_descriptor(buffer_descriptor_t * const bufDescriptor) {
 	}
 
 	if (usage & INVALID_USAGE) {
-		return -EINVAL;
+		return false;
+	}
+
+	if (!bufDescriptor->additional_options.empty()) {
+		return false;
 	}
 
 	// BLOB formats are used for some ML models whose size can be really large (up to 2GB)
diff --git a/gralloc4/src/core/mali_gralloc_bufferdescriptor.h b/gralloc4/src/core/mali_gralloc_bufferdescriptor.h
index 657b2af..e2ef6d0 100644
--- a/gralloc4/src/core/mali_gralloc_bufferdescriptor.h
+++ b/gralloc4/src/core/mali_gralloc_bufferdescriptor.h
@@ -22,6 +22,7 @@
 #include "mali_gralloc_buffer.h"
 #include "mali_gralloc_formats.h"
 #include <string>
+#include <aidl/android/hardware/graphics/common/ExtendableType.h>
 
 typedef uint64_t gralloc_buffer_descriptor_t;
 
@@ -45,6 +46,7 @@ struct buffer_descriptor_t
 	mali_gralloc_format_type format_type;
 	std::string name;
 	uint64_t reserved_size;
+	std::vector<::aidl::android::hardware::graphics::common::ExtendableType> additional_options;
 
 	/*
 	 * Calculated values that will be passed to the allocator in order to
diff --git a/gralloc4/src/core/mali_gralloc_reference.cpp b/gralloc4/src/core/mali_gralloc_reference.cpp
index 880e8b5..8fcf710 100644
--- a/gralloc4/src/core/mali_gralloc_reference.cpp
+++ b/gralloc4/src/core/mali_gralloc_reference.cpp
@@ -247,7 +247,7 @@ public:
         return 0;
     }
     static BufferManager &getInstance() {
-        static BufferManager instance;
+        [[clang::no_destroy]] static BufferManager instance;
         return instance;
     }
 
diff --git a/gralloc4/src/hidl_common/Mapper.cpp b/gralloc4/src/hidl_common/Mapper.cpp
index 62cac7c..4ed356c 100644
--- a/gralloc4/src/hidl_common/Mapper.cpp
+++ b/gralloc4/src/hidl_common/Mapper.cpp
@@ -30,11 +30,12 @@
 #include "core/format_info.h"
 #include "allocator/mali_gralloc_ion.h"
 #include "mali_gralloc_buffer.h"
-#include "mali_gralloc_log.h"
 
 #include "MapperMetadata.h"
 #include "SharedMetadata.h"
 
+#include "drmutils.h"
+
 #include <cstdio>
 
 /* GraphicBufferMapper is expected to be valid (and leaked) during process
@@ -56,6 +57,184 @@ buffer_handle_t getBuffer(void *buffer) {
 	return gRegisteredHandles->get(buffer);
 }
 
+using PixelMetadataType = ::pixel::graphics::MetadataType;
+
+#ifdef GRALLOC_MAPPER_5
+
+template <typename F, StandardMetadataType metadataType>
+int32_t getStandardMetadataHelper(const private_handle_t *hnd, F &&provide,
+				  StandardMetadata<metadataType>) {
+	if constexpr (metadataType == StandardMetadataType::BUFFER_ID) {
+		return provide(hnd->backing_store_id);
+	}
+	if constexpr (metadataType == StandardMetadataType::WIDTH) {
+		return provide(hnd->width);
+	}
+	if constexpr (metadataType == StandardMetadataType::HEIGHT) {
+		return provide(hnd->height);
+	}
+	if constexpr (metadataType == StandardMetadataType::LAYER_COUNT) {
+		return provide(hnd->layer_count);
+	}
+	if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_REQUESTED) {
+		return provide(static_cast<PixelFormat>(hnd->req_format));
+	}
+	if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_FOURCC) {
+		return provide(drm_fourcc_from_handle(hnd));
+	}
+	if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_MODIFIER) {
+		return provide(drm_modifier_from_handle(hnd));
+	}
+	if constexpr (metadataType == StandardMetadataType::USAGE) {
+		return provide(static_cast<BufferUsage>(hnd->consumer_usage | hnd->producer_usage));
+	}
+	if constexpr (metadataType == StandardMetadataType::ALLOCATION_SIZE) {
+		uint64_t total_size = 0;
+		for (int fidx = 0; fidx < hnd->fd_count; fidx++) {
+			total_size += hnd->alloc_sizes[fidx];
+		}
+		return provide(total_size);
+	}
+	if constexpr (metadataType == StandardMetadataType::PROTECTED_CONTENT) {
+		return provide((((hnd->consumer_usage | hnd->producer_usage) &
+				static_cast<uint64_t>(BufferUsage::PROTECTED)) == 0)
+				? 0
+				: 1);
+	}
+	if constexpr (metadataType == StandardMetadataType::COMPRESSION) {
+		ExtendableType compression = android::gralloc4::Compression_None;
+		if (hnd->alloc_format & MALI_GRALLOC_INTFMT_AFBC_BASIC)
+			compression = common::Compression_AFBC;
+		return provide(compression);
+	}
+	if constexpr (metadataType == StandardMetadataType::INTERLACED) {
+		return provide(android::gralloc4::Interlaced_None);
+	}
+	if constexpr (metadataType == StandardMetadataType::CHROMA_SITING) {
+		ExtendableType siting = android::gralloc4::ChromaSiting_None;
+		int format_index = get_format_index(hnd->alloc_format & MALI_GRALLOC_INTFMT_FMT_MASK);
+		if (formats[format_index].is_yuv) siting = android::gralloc4::ChromaSiting_Unknown;
+		return provide(siting);
+	}
+	if constexpr (metadataType == StandardMetadataType::PLANE_LAYOUTS) {
+		std::vector<PlaneLayout> layouts;
+		Error err = static_cast<Error>(common::get_plane_layouts(hnd, &layouts));
+		return provide(layouts);
+	}
+	if constexpr (metadataType == StandardMetadataType::NAME) {
+		std::string name;
+		common::get_name(hnd, &name);
+		return provide(name);
+	}
+	if constexpr (metadataType == StandardMetadataType::CROP) {
+		const int num_planes = common::get_num_planes(hnd);
+		std::vector<Rect> crops(num_planes);
+		for (size_t plane_index = 0; plane_index < num_planes; ++plane_index) {
+			Rect rect = {.top = 0,
+			.left = 0,
+			.right = static_cast<int32_t>(hnd->plane_info[plane_index].alloc_width),
+			.bottom = static_cast<int32_t>(hnd->plane_info[plane_index].alloc_height)};
+			if (plane_index == 0) {
+				std::optional<Rect> crop_rect;
+				common::get_crop_rect(hnd, &crop_rect);
+				if (crop_rect.has_value()) {
+					rect = crop_rect.value();
+				} else {
+					rect = {.top = 0, .left = 0, .right = hnd->width, .bottom = hnd->height};
+				}
+			}
+			crops[plane_index] = rect;
+		}
+		return provide(crops);
+	}
+	if constexpr (metadataType == StandardMetadataType::DATASPACE) {
+		std::optional<Dataspace> dataspace;
+		common::get_dataspace(hnd, &dataspace);
+		return provide(dataspace.value_or(Dataspace::UNKNOWN));
+	}
+	if constexpr (metadataType == StandardMetadataType::BLEND_MODE) {
+		std::optional<BlendMode> blendmode;
+		common::get_blend_mode(hnd, &blendmode);
+		return provide(blendmode.value_or(BlendMode::INVALID));
+	}
+	if constexpr (metadataType == StandardMetadataType::SMPTE2086) {
+		std::optional<Smpte2086> smpte2086;
+		common::get_smpte2086(hnd, &smpte2086);
+		return provide(smpte2086);
+	}
+	if constexpr (metadataType == StandardMetadataType::CTA861_3) {
+		std::optional<Cta861_3> cta861_3;
+		common::get_cta861_3(hnd, &cta861_3);
+		return provide(cta861_3);
+	}
+	if constexpr (metadataType == StandardMetadataType::SMPTE2094_40) {
+		std::optional<std::vector<uint8_t>> smpte2094_40;
+		common::get_smpte2094_40(hnd, &smpte2094_40);
+		return provide(smpte2094_40);
+	}
+	if constexpr (metadataType == StandardMetadataType::STRIDE) {
+		std::vector<PlaneLayout> layouts;
+		Error err = static_cast<Error>(common::get_plane_layouts(hnd, &layouts));
+		uint64_t stride = 0;
+		switch (hnd->get_alloc_format()) {
+			case HAL_PIXEL_FORMAT_RAW10:
+			case HAL_PIXEL_FORMAT_RAW12:
+				stride = layouts[0].strideInBytes;
+				break;
+			default:
+				stride = hnd->plane_info[0].alloc_width;
+				break;
+		}
+		return provide(stride);
+	}
+	return -AIMapper_Error::AIMAPPER_ERROR_UNSUPPORTED;
+}
+
+int32_t getPixelMetadataHelper(const private_handle_t *handle, const PixelMetadataType meta,
+			       void *outData, size_t outDataSize) {
+	switch (meta) {
+	case PixelMetadataType::VIDEO_HDR: {
+		auto result = ::pixel::graphics::utils::encode(common::get_video_hdr(handle));
+		if (result.size() <= outDataSize) std::memcpy(outData, result.data(), result.size());
+		return result.size();
+	}
+	case PixelMetadataType::VIDEO_ROI: {
+		auto result = ::pixel::graphics::utils::encode(common::get_video_roiinfo(handle));
+		if (result.size() <= outDataSize) std::memcpy(outData, result.data(), result.size());
+		return result.size();
+	}
+	case PixelMetadataType::VIDEO_GMV: {
+		auto result = ::pixel::graphics::utils::encode(common::get_video_gmv(handle));
+		if (result.size() <= outDataSize) std::memcpy(outData, result.data(), result.size());
+		return result.size();
+	}
+	case PixelMetadataType::PLANE_DMA_BUFS: {
+		std::vector<int> plane_fds(MAX_BUFFER_FDS, -1);
+		for (int i = 0; i < get_num_planes(handle); i++) {
+			plane_fds[i] = handle->fds[handle->plane_info[i].fd_idx];
+		}
+		auto result = ::pixel::graphics::utils::encode(plane_fds);
+		if (result.size() <= outDataSize) std::memcpy(outData, result.data(), result.size());
+		return result.size();
+	}
+	default:
+		return -AIMapper_Error::AIMAPPER_ERROR_BAD_VALUE;
+	}
+}
+
+int32_t getStandardMetadata(const private_handle_t *handle, StandardMetadataType metadata_type,
+				void *_Nonnull outData, size_t outDataSize) {
+	if (handle == nullptr) return -AIMapper_Error::AIMAPPER_ERROR_BAD_BUFFER;
+
+	auto provider = [&]<StandardMetadataType meta>(auto &&provide) -> int32_t {
+		return common::getStandardMetadataHelper(handle, provide, StandardMetadata<meta>{});
+	};
+	return android::hardware::graphics::mapper::provideStandardMetadata(metadata_type, outData,
+									    outDataSize, provider);
+}
+
+#endif
+
 /*
  * Translates the register buffer API into existing gralloc implementation
  *
@@ -656,7 +835,25 @@ static BufferDump dumpBufferHelper(const private_handle_t *handle)
 	for (const auto& metadataType: standardMetadataTypes)
 	{
 		std::vector<uint8_t> metadata;
+#ifdef GRALLOC_MAPPER_4
 		Error error = get_metadata(handle, metadataType, metadata);
+#else
+		Error error;
+		auto tmp_err =
+			::arm::mapper::common::getStandardMetadata(handle,
+								   static_cast<
+								   StandardMetadataType>(
+								   metadataType.value),
+								   metadata.data(), metadata.size());
+		if (tmp_err > 0) {
+			metadata.resize(tmp_err);
+			::arm::mapper::common::getStandardMetadata(handle,
+								   static_cast<StandardMetadataType>(
+								   metadataType.value),
+								   metadata.data(), metadata.size());
+		}
+		error = static_cast<Error>(-1 * tmp_err);
+#endif
 		if (error == Error::NONE)
 		{
 			metadataDumps.push_back(MetadataDump(MetadataType(metadataType), metadata));
@@ -686,8 +883,9 @@ std::vector<BufferDump> dumpBuffers()
 {
 	std::vector<BufferDump> bufferDumps;
 	gRegisteredHandles->for_each([&bufferDumps](buffer_handle_t buffer) {
-		BufferDump bufferDump { dumpBufferHelper(static_cast<const private_handle_t *>(buffer)) };
-		bufferDumps.push_back(bufferDump);
+	    BufferDump bufferDump;
+	    auto err = dumpBuffer(buffer, bufferDump);
+	    bufferDumps.push_back(bufferDump);
 	});
 	return bufferDumps;
 }
diff --git a/gralloc4/src/hidl_common/Mapper.h b/gralloc4/src/hidl_common/Mapper.h
index dc5655a..7092678 100644
--- a/gralloc4/src/hidl_common/Mapper.h
+++ b/gralloc4/src/hidl_common/Mapper.h
@@ -28,6 +28,9 @@
 #include "hidl_common.h"
 #include "mali_gralloc_error.h"
 
+#include <pixel-gralloc/metadata.h>
+#include <pixel-gralloc/utils.h>
+
 namespace arm
 {
 namespace mapper
@@ -40,6 +43,8 @@ using aidl::android::hardware::graphics::common::Rect;
 
 using android::hardware::Void;
 
+using PixelMetadataType = ::pixel::graphics::MetadataType;
+
 class GrallocRect {
 	public:
 	int left;
@@ -69,6 +74,9 @@ class GrallocRect {
 #endif // GRALLOC_MAPPER_4 or GRALLOC_MAPPER_5
 };
 
+#pragma GCC diagnostic push
+#pragma GCC diagnostic ignored "-Wnullability-completeness"
+
 /**
  * Imports a raw buffer handle to create an imported buffer handle for use with
  * the rest of the mapper or with other in-process libraries.
@@ -278,6 +286,13 @@ std::vector<BufferDump> dumpBuffers();
  */
 Error getReservedRegion(buffer_handle_t buffer, void **outReservedRegion, uint64_t &outReservedSize);
 
+int32_t getStandardMetadata(const private_handle_t *handle, StandardMetadataType metadata_type,
+                            void *outData, size_t outDataSize);
+
+int32_t getPixelMetadataHelper(const private_handle_t *handle, const PixelMetadataType meta,
+                               void *_Nullable outData, size_t outDataSize);
+
+#pragma GCC diagnostic pop
 } // namespace common
 } // namespace mapper
 } // namespace arm
diff --git a/gralloc4/src/stable-c/Android.bp b/gralloc4/src/stable-c/Android.bp
index 0195b4b..9e9dd8d 100644
--- a/gralloc4/src/stable-c/Android.bp
+++ b/gralloc4/src/stable-c/Android.bp
@@ -25,6 +25,10 @@ cc_defaults {
         "arm_gralloc_api_defaults",
         "arm_gralloc_defaults",
         "arm_gralloc_version_defaults",
+        "pixel-gralloc-headers-dependencies",
+    ],
+    header_libs: [
+        "pixel-gralloc-headers",
     ],
     relative_install_path: "hw/",
     vintf_fragments: ["stable-c/manifest.xml"],
diff --git a/gralloc4/src/stable-c/GrallocMapper.cpp b/gralloc4/src/stable-c/GrallocMapper.cpp
index 085b3c8..2c4c52a 100644
--- a/gralloc4/src/stable-c/GrallocMapper.cpp
+++ b/gralloc4/src/stable-c/GrallocMapper.cpp
@@ -26,6 +26,7 @@
 #include "core/format_info.h"
 #include "drmutils.h"
 #include "hidl_common/BufferDescriptor.h"
+#include "hidl_common/Mapper.h"
 #include "hidl_common/MapperMetadata.h"
 #include "hidl_common/SharedMetadata.h"
 #include "hidl_common/hidl_common.h"
@@ -35,6 +36,7 @@ namespace mapper {
 
 using namespace android::hardware::graphics::mapper;
 using PixelMetadataType = ::pixel::graphics::MetadataType;
+using aidl::android::hardware::graphics::common::StandardMetadataType;
 
 
 AIMapper_Error GrallocMapper::importBuffer(const native_handle_t* _Nonnull handle,
@@ -53,10 +55,19 @@ AIMapper_Error GrallocMapper::freeBuffer(buffer_handle_t _Nonnull buffer) {
 AIMapper_Error GrallocMapper::lock(buffer_handle_t _Nonnull buffer, uint64_t cpuUsage,
                                    ARect accessRegion, int acquireFence,
                                    void* _Nullable* _Nonnull outData) {
-    if (buffer == nullptr) return AIMapper_Error::AIMAPPER_ERROR_BAD_BUFFER;
-    AIMapper_Error err = static_cast<AIMapper_Error>(common::lock(buffer, cpuUsage,
-                                                                  common::GrallocRect(accessRegion),
-                                                                  acquireFence, outData));
+    AIMapper_Error err = AIMapper_Error::AIMAPPER_ERROR_NONE;
+    if (buffer == nullptr) {
+        err = AIMapper_Error::AIMAPPER_ERROR_BAD_BUFFER;
+    } else {
+        err = static_cast<AIMapper_Error>(common::lock(buffer, cpuUsage,
+                                                       common::GrallocRect(accessRegion),
+                                                       acquireFence, outData));
+    }
+    // we own acquireFence, but common::lock doesn't take ownership
+    // so, we have to close it anyway
+    if (acquireFence >= 0) {
+        close(acquireFence);
+    }
     return err;
 }
 
@@ -79,195 +90,33 @@ AIMapper_Error GrallocMapper::rereadLockedBuffer(buffer_handle_t _Nonnull buffer
     return static_cast<AIMapper_Error>(common::rereadLockedBuffer(buffer));
 }
 
-
-// TODO(b/315854439): getStandardMetadataHelper should be in the common code.
-template <typename F, StandardMetadataType metadataType>
-int32_t getStandardMetadataHelper(const private_handle_t* hnd, F&& provide,
-                                  StandardMetadata<metadataType>) {
-    if constexpr (metadataType == StandardMetadataType::BUFFER_ID) {
-        return provide(hnd->backing_store_id);
-    }
-    if constexpr (metadataType == StandardMetadataType::WIDTH) {
-        return provide(hnd->width);
-    }
-    if constexpr (metadataType == StandardMetadataType::HEIGHT) {
-        return provide(hnd->height);
-    }
-    if constexpr (metadataType == StandardMetadataType::LAYER_COUNT) {
-        return provide(hnd->layer_count);
-    }
-    if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_REQUESTED) {
-        return provide(static_cast<PixelFormat>(hnd->req_format));
-    }
-    if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_FOURCC) {
-        return provide(drm_fourcc_from_handle(hnd));
-    }
-    if constexpr (metadataType == StandardMetadataType::PIXEL_FORMAT_MODIFIER) {
-        return provide(drm_modifier_from_handle(hnd));
-    }
-    if constexpr (metadataType == StandardMetadataType::USAGE) {
-        return provide(static_cast<BufferUsage>(hnd->consumer_usage | hnd->producer_usage));
-    }
-    if constexpr (metadataType == StandardMetadataType::ALLOCATION_SIZE) {
-        uint64_t total_size = 0;
-        for (int fidx = 0; fidx < hnd->fd_count; fidx++) {
-            total_size += hnd->alloc_sizes[fidx];
-        }
-        return provide(total_size);
-    }
-    if constexpr (metadataType == StandardMetadataType::PROTECTED_CONTENT) {
-        return provide((((hnd->consumer_usage | hnd->producer_usage) &
-                         static_cast<uint64_t>(BufferUsage::PROTECTED)) == 0)
-                               ? 0
-                               : 1);
-    }
-    if constexpr (metadataType == StandardMetadataType::COMPRESSION) {
-        ExtendableType compression = android::gralloc4::Compression_None;
-        if (hnd->alloc_format & MALI_GRALLOC_INTFMT_AFBC_BASIC)
-            compression = common::Compression_AFBC;
-        return provide(compression);
-    }
-    if constexpr (metadataType == StandardMetadataType::INTERLACED) {
-        return provide(android::gralloc4::Interlaced_None);
-    }
-    if constexpr (metadataType == StandardMetadataType::CHROMA_SITING) {
-        ExtendableType siting = android::gralloc4::ChromaSiting_None;
-        int format_index = get_format_index(hnd->alloc_format & MALI_GRALLOC_INTFMT_FMT_MASK);
-        if (formats[format_index].is_yuv) siting = android::gralloc4::ChromaSiting_Unknown;
-        return provide(siting);
-    }
-    if constexpr (metadataType == StandardMetadataType::PLANE_LAYOUTS) {
-        std::vector<PlaneLayout> layouts;
-        Error err = static_cast<Error>(common::get_plane_layouts(hnd, &layouts));
-        return provide(layouts);
-    }
-    if constexpr (metadataType == StandardMetadataType::NAME) {
-        std::string name;
-        common::get_name(hnd, &name);
-        return provide(name);
-    }
-    if constexpr (metadataType == StandardMetadataType::CROP) {
-        const int num_planes = common::get_num_planes(hnd);
-        std::vector<Rect> crops(num_planes);
-        for (size_t plane_index = 0; plane_index < num_planes; ++plane_index) {
-            Rect rect = {.top = 0,
-                         .left = 0,
-                         .right = static_cast<int32_t>(hnd->plane_info[plane_index].alloc_width),
-                         .bottom = static_cast<int32_t>(hnd->plane_info[plane_index].alloc_height)};
-            if (plane_index == 0) {
-                std::optional<Rect> crop_rect;
-                common::get_crop_rect(hnd, &crop_rect);
-                if (crop_rect.has_value()) {
-                    rect = crop_rect.value();
-                } else {
-                    rect = {.top = 0, .left = 0, .right = hnd->width, .bottom = hnd->height};
-                }
-            }
-            crops[plane_index] = rect;
-        }
-        return provide(crops);
-    }
-    if constexpr (metadataType == StandardMetadataType::DATASPACE) {
-        std::optional<Dataspace> dataspace;
-        common::get_dataspace(hnd, &dataspace);
-        return provide(dataspace.value_or(Dataspace::UNKNOWN));
-    }
-    if constexpr (metadataType == StandardMetadataType::BLEND_MODE) {
-        std::optional<BlendMode> blendmode;
-        common::get_blend_mode(hnd, &blendmode);
-        return provide(blendmode.value_or(BlendMode::INVALID));
-    }
-    if constexpr (metadataType == StandardMetadataType::SMPTE2086) {
-        std::optional<Smpte2086> smpte2086;
-        common::get_smpte2086(hnd, &smpte2086);
-        return provide(smpte2086);
-    }
-    if constexpr (metadataType == StandardMetadataType::CTA861_3) {
-        std::optional<Cta861_3> cta861_3;
-        common::get_cta861_3(hnd, &cta861_3);
-        return provide(cta861_3);
-    }
-    if constexpr (metadataType == StandardMetadataType::SMPTE2094_40) {
-        std::optional<std::vector<uint8_t>> smpte2094_40;
-        common::get_smpte2094_40(hnd, &smpte2094_40);
-        return provide(smpte2094_40);
-    }
-    if constexpr (metadataType == StandardMetadataType::STRIDE) {
-        std::vector<PlaneLayout> layouts;
-        Error err = static_cast<Error>(common::get_plane_layouts(hnd, &layouts));
-        uint64_t stride = 0;
-        switch (hnd->get_alloc_format())
-        {
-            case HAL_PIXEL_FORMAT_RAW10:
-            case HAL_PIXEL_FORMAT_RAW12:
-                  stride = layouts[0].strideInBytes;
-                  break;
-            default:
-                  stride = (layouts[0].strideInBytes * 8) / layouts[0].sampleIncrementInBits;
-                  break;
-        }
-        return provide(stride);
-    }
-    return -AIMapper_Error::AIMAPPER_ERROR_UNSUPPORTED;
-}
-
 int32_t GrallocMapper::getStandardMetadata(buffer_handle_t _Nonnull buffer,
                                            int64_t standardMetadataType, void* _Nonnull outData,
                                            size_t outDataSize) {
     if (buffer == nullptr) return -AIMapper_Error::AIMAPPER_ERROR_BAD_BUFFER;
-
-    auto provider = [&]<StandardMetadataType meta>(auto&& provide) -> int32_t {
-        return getStandardMetadataHelper(static_cast<const private_handle_t*>(buffer), provide,
-                                         StandardMetadata<meta>{});
-    };
-    return provideStandardMetadata(static_cast<StandardMetadataType>(standardMetadataType), outData,
-                                   outDataSize, provider);
+    auto standardMeta = static_cast<StandardMetadataType>(standardMetadataType);
+    return common::getStandardMetadata(static_cast<const private_handle_t*>(buffer),
+                                                      standardMeta,
+                                                      outData, outDataSize);
 }
 
 bool isPixelMetadataType(common::MetadataType meta) {
     return (meta.name == ::pixel::graphics::kPixelMetadataTypeName);
 }
 
-int32_t getPixelMetadataHelper(buffer_handle_t handle, const PixelMetadataType meta, void* outData,
-                               size_t outDataSize) {
-    switch (meta) {
-        case PixelMetadataType::VIDEO_HDR: {
-            auto result = ::pixel::graphics::utils::encode(
-                    common::get_video_hdr(static_cast<const private_handle_t*>(handle)));
-
-            if (result.size() <= outDataSize)
-                std::memcpy(outData, result.data(), result.size());
-            return result.size();
-        }
-        case PixelMetadataType::VIDEO_ROI: {
-            auto result = ::pixel::graphics::utils::encode(
-                    common::get_video_roiinfo(static_cast<const private_handle_t*>(handle)));
-            if (result.size() <= outDataSize)
-                std::memcpy(outData, result.data(), result.size());
-            return result.size();
-        }
-        case PixelMetadataType::VIDEO_GMV: {
-            auto result = ::pixel::graphics::utils::encode(
-                    common::get_video_gmv(static_cast<const private_handle_t*>(handle)));
-            if (result.size() <= outDataSize) std::memcpy(outData, result.data(), result.size());
-            return result.size();
-        }
-
-        default:
-            return -AIMapper_Error::AIMAPPER_ERROR_BAD_VALUE;
-    }
-}
-
 int32_t GrallocMapper::getMetadata(buffer_handle_t _Nonnull buffer,
                                    AIMapper_MetadataType metadataType, void* _Nonnull outData,
                                    size_t outDataSize) {
     if (buffer == nullptr) return -AIMapper_Error::AIMAPPER_ERROR_BAD_BUFFER;
 
     if (isStandardMetadataType(common::MetadataType(metadataType))) {
-        return getStandardMetadata(buffer, metadataType.value, outData, outDataSize);
+        return getStandardMetadata(static_cast<const private_handle_t *>(buffer),
+                                   metadataType.value,
+                                   outData, outDataSize);
     } else if (isPixelMetadataType(common::MetadataType(metadataType))) {
         const PixelMetadataType pixelMeta = static_cast<PixelMetadataType>(metadataType.value);
-        return getPixelMetadataHelper(buffer, pixelMeta, outData, outDataSize);
+        return common::getPixelMetadataHelper(static_cast<const private_handle_t*>(buffer),
+                                              pixelMeta, outData, outDataSize);
     } else {
         return -AIMapper_Error::AIMAPPER_ERROR_UNSUPPORTED;
     }
diff --git a/libvendorgraphicbuffer/Android.bp b/libvendorgraphicbuffer/Android.bp
index e2957fe..bd4dd7e 100644
--- a/libvendorgraphicbuffer/Android.bp
+++ b/libvendorgraphicbuffer/Android.bp
@@ -22,7 +22,7 @@ package {
 soong_config_module_type {
 	name: "libvendorgraphicbuffer_cc_defaults",
 	module_type: "cc_defaults",
-	config_namespace: "arm_gralloc",
+	config_namespace: "pixel_gralloc",
 	variables: [
 		"mapper_version",
 	],
@@ -69,6 +69,7 @@ cc_library_shared {
 	name: "libvendorgraphicbuffer",
 	defaults: [
 		"libvendorgraphicbuffer_src_defaults",
+		"pixel-gralloc-headers-dependencies",
 	],
 	shared_libs: [
 		"libdrm",
diff --git a/libvendorgraphicbuffer/gralloc4/vendor_graphicbuffer_meta.cpp b/libvendorgraphicbuffer/gralloc4/vendor_graphicbuffer_meta.cpp
index a2bf1c4..8b6af8d 100644
--- a/libvendorgraphicbuffer/gralloc4/vendor_graphicbuffer_meta.cpp
+++ b/libvendorgraphicbuffer/gralloc4/vendor_graphicbuffer_meta.cpp
@@ -246,8 +246,7 @@ void* VendorGraphicBufferMeta::get_video_metadata(buffer_handle_t hnd)
 		return nullptr;
 	}
 
-	using namespace ::pixel::graphics;
-	auto out_oe = mapper::get<MetadataType::VIDEO_HDR>(handle);
+	auto out_oe = ::pixel::graphics::mapper::get<::pixel::graphics::MetadataType::VIDEO_HDR>(handle);
 
 	if (!out_oe.has_value()) {
 		ALOGE("Failed to get video HDR metadata");
@@ -264,8 +263,7 @@ void* VendorGraphicBufferMeta::get_video_metadata_roiinfo(buffer_handle_t hnd)
 		return nullptr;
 	}
 
-	using namespace ::pixel::graphics;
-	auto out_oe = mapper::get<MetadataType::VIDEO_ROI>(handle);
+	auto out_oe = ::pixel::graphics::mapper::get<::pixel::graphics::MetadataType::VIDEO_ROI>(handle);
 
 	if (!out_oe.has_value()) {
 		ALOGE("Failed to get video ROI metadata");
diff --git a/videoapi/Android.bp b/videoapi/Android.bp
new file mode 100644
index 0000000..9b98d78
--- /dev/null
+++ b/videoapi/Android.bp
@@ -0,0 +1,39 @@
+// Copyright (C) 2019 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+        "hardware_google_gchips_license",
+    ],
+}
+
+cc_library_static {
+    name: "libVendorVideoApi",
+    proprietary: true,
+    cflags: [
+        "-Werror",
+        "-Wno-unused-parameter",
+        "-Wno-unused-function",
+    ],
+    srcs: ["VendorVideoAPI.cpp"],
+    header_libs: [
+        "gchips_headers",
+    ],
+    shared_libs: [
+        "liblog",
+        "libutils",
+    ],
+}
diff --git a/videoapi/Android.mk b/videoapi/Android.mk
deleted file mode 100644
index 0fd176c..0000000
--- a/videoapi/Android.mk
+++ /dev/null
@@ -1,43 +0,0 @@
-# Copyright (C) 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-LOCAL_PATH:= $(call my-dir)
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_CFLAGS :=
-
-LOCAL_SRC_FILES := \
-	VendorVideoAPI.cpp
-
-LOCAL_C_INCLUDES := \
-	$(LOCAL_PATH)/../include
-
-LOCAL_SHARED_LIBRARIES := \
-	liblog \
-	libutils
-
-LOCAL_MODULE := libVendorVideoApi
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-
-LOCAL_PRELINK_MODULE := false
-LOCAL_ARM_MODE := arm
-
-LOCAL_CFLAGS += -Werror -Wno-unused-parameter -Wno-unused-function
-
-include $(BUILD_STATIC_LIBRARY)
diff --git a/videoapi/VendorVideoAPI.cpp b/videoapi/VendorVideoAPI.cpp
index e439051..0450803 100644
--- a/videoapi/VendorVideoAPI.cpp
+++ b/videoapi/VendorVideoAPI.cpp
@@ -35,6 +35,15 @@
     }                                                           \
 }
 
+/* Check array boundary before use it */
+#define CHECK_ARRAY_BOUNDARY(array_size, limit_size) {          \
+    if ((array_size) > (limit_size)) {                          \
+        ALOGE("[%s][%d] array size(%d) > limit size (%d)",      \
+              __func__, __LINE__, (array_size), (limit_size));  \
+        return -1;                                              \
+    }                                                           \
+}
+
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -444,6 +453,8 @@ int Exynos_parsing_user_data_registered_itu_t_t35 (
         extraByte   = 0;
         extraBit    = bit_offset % 8;
         data        = (extraBit != 0) ? (data >> (8 - extraBit)) : data;
+
+        CHECK_ARRAY_BOUNDARY(data, 25); // max value is 25
         pHdr10PlusInfo->data.num_rows_targeted_system_display_actual_peak_luminance = data;
         num_rows_targeted_system_display_actual_peak_luminance = data;
         data = 0;
@@ -468,6 +479,8 @@ int Exynos_parsing_user_data_registered_itu_t_t35 (
         extraByte   = 0;
         extraBit    = bit_offset % 8;
         data        = (extraBit != 0) ? (data >> (8 - extraBit)) : data;
+
+        CHECK_ARRAY_BOUNDARY(data, 25); // max value is 25
         pHdr10PlusInfo->data.num_cols_targeted_system_display_actual_peak_luminance = data;
         num_cols_targeted_system_display_actual_peak_luminance = data;
         data = 0;
@@ -673,6 +686,8 @@ int Exynos_parsing_user_data_registered_itu_t_t35 (
         extraByte   = 0;
         extraBit    = bit_offset % 8;
         data        = (extraBit != 0) ? (data >> (8 - extraBit)) : data;
+
+        CHECK_ARRAY_BOUNDARY(data, 25); // max value is 25
         pHdr10PlusInfo->data.num_rows_mastering_display_actual_peak_luminance = data;
         num_rows_mastering_display_actual_peak_luminance = data;
         data = 0;
@@ -697,6 +712,8 @@ int Exynos_parsing_user_data_registered_itu_t_t35 (
         extraByte   = 0;
         extraBit    = bit_offset % 8;
         data        = (extraBit != 0) ? (data >> (8 - extraBit)) : data;
+
+        CHECK_ARRAY_BOUNDARY(data, 25); // max value is 25
         pHdr10PlusInfo->data.num_cols_mastering_display_actual_peak_luminance = data;
         num_cols_mastering_display_actual_peak_luminance = data;
         data = 0;
```

