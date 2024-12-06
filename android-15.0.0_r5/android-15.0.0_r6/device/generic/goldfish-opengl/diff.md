```diff
diff --git a/OWNERS b/OWNERS
index ec67e03b..392be476 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,12 +3,14 @@ cstout@google.com
 doughorn@google.com
 gurchetansingh@google.com
 kaiyili@google.com
-lfy@google.com
 liyl@google.com
 msandy@google.com
 natsu@google.com
 rkir@google.com
 tutankhamen@google.com
 yahan@google.com
+kocdemir@google.com
+joshuaduong@google.com
+sergiuferentz@google.com
 
 # COMPONENT: Graphics
diff --git a/system/codecs/c2/decoders/avcdec/Android.bp b/system/codecs/c2/decoders/avcdec/Android.bp
index 672a80f1..5d840b05 100644
--- a/system/codecs/c2/decoders/avcdec/Android.bp
+++ b/system/codecs/c2/decoders/avcdec/Android.bp
@@ -27,7 +27,6 @@ cc_library_shared {
 
    header_libs: [
     "libgralloc_cb.ranchu",
-    "libgralloc_cb3.ranchu",
     ],
 
    static_libs: ["libavcdec",
diff --git a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
index ef36b3d0..d77cba07 100644
--- a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
+++ b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
@@ -723,7 +723,7 @@ C2GoldfishAvcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
         mOutBlock.reset();
     }
     if (!mOutBlock) {
-        const uint32_t format = HAL_PIXEL_FORMAT_YV12;
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
         const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
                                      C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
         c2_status_t err = pool->fetchGraphicBlock(ALIGN2(mWidth), mHeight,
diff --git a/system/codecs/c2/decoders/base/Android.bp b/system/codecs/c2/decoders/base/Android.bp
index 8dc15964..af93b417 100644
--- a/system/codecs/c2/decoders/base/Android.bp
+++ b/system/codecs/c2/decoders/base/Android.bp
@@ -41,13 +41,13 @@ cc_library_shared {
     ],
 
     static_libs: [
-        "libplatform",
-        "libGoldfishAddressSpace",
+        "mesa_platform_virtgpu",
+        "mesa_goldfish_address_space",
+        "mesa_util",
     ],
 
     header_libs: [
         "libgralloc_cb.ranchu",
-        "libgralloc_cb3.ranchu",
     ],
 
     sanitize: {
diff --git a/system/codecs/c2/decoders/base/color_buffer_utils.cpp b/system/codecs/c2/decoders/base/color_buffer_utils.cpp
index 94f9088e..86c6eff5 100644
--- a/system/codecs/c2/decoders/base/color_buffer_utils.cpp
+++ b/system/codecs/c2/decoders/base/color_buffer_utils.cpp
@@ -19,7 +19,6 @@
 #include <android-base/strings.h>
 #include <log/log.h>
 #include <gralloc_cb_bp.h>
-#include <cb_handle_30.h>
 #include <xf86drm.h>
 
 #include <C2AllocatorGralloc.h>
@@ -69,7 +68,7 @@ public:
     uint64_t getClientUsage(const std::shared_ptr<C2BlockPool> &pool) {
         std::shared_ptr<C2GraphicBlock> myOutBlock;
         const C2MemoryUsage usage = {0, 0};
-        const uint32_t format = HAL_PIXEL_FORMAT_YV12;
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
         pool->fetchGraphicBlock(2, 2, format, usage, &myOutBlock);
         auto myc2Handle = myOutBlock->handle();
         native_handle_t *mygrallocHandle =
@@ -79,7 +78,7 @@ public:
                 reinterpret_cast<cros_gralloc_handle const*>(mygrallocHandle);
             return cros_handle->usage;
         } else {
-            cb_handle_30_t* mycb = (cb_handle_30_t*)(mygrallocHandle);
+            cb_handle_t* mycb = (cb_handle_t*)(mygrallocHandle);
             return mycb->usage;
         }
     }
diff --git a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
index 922b8370..81c07a85 100644
--- a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
+++ b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
@@ -669,7 +669,7 @@ C2GoldfishHevcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool)
         mOutBlock.reset();
     }
     if (!mOutBlock) {
-        const uint32_t format = HAL_PIXEL_FORMAT_YV12;
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
         const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
                                      C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
         c2_status_t err = pool->fetchGraphicBlock(ALIGN2(mWidth), mHeight,
diff --git a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
index 37c4a519..1d2a70ec 100644
--- a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
+++ b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
@@ -852,24 +852,30 @@ void C2GoldfishVpxDec::process(const std::unique_ptr<C2Work> &work,
     }
 }
 
-static void copyOutputBufferToYuvPlanarFrame(C2GraphicView& writeView, const uint8_t* srcY,
-        const uint8_t* srcU, const uint8_t* srcV, uint32_t width, uint32_t height) {
-
-    size_t dstYStride = writeView.layout().planes[C2PlanarLayout::PLANE_Y].rowInc;
-    size_t dstUVStride = writeView.layout().planes[C2PlanarLayout::PLANE_U].rowInc;
-
-    uint8_t *pYBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_Y]);
-    uint8_t *pUBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_U]);
-    uint8_t *pVBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_V]);
-
-    for (int i = 0; i < height; ++i) {
-        memcpy(pYBuffer + i * dstYStride, srcY + i * width, width);
+static void copyOutputBufferToYuvPlanarFrame(
+    uint8_t *dst, const uint8_t *srcY, const uint8_t *srcU, const uint8_t *srcV,
+    size_t srcYStride, size_t srcUStride, size_t srcVStride, size_t dstYStride,
+    size_t dstUVStride, uint32_t width, uint32_t height) {
+    uint8_t *dstStart = dst;
+
+    for (size_t i = 0; i < height; ++i) {
+        memcpy(dst, srcY, width);
+        srcY += srcYStride;
+        dst += dstYStride;
     }
-    for (int i = 0; i < height / 2; ++i) {
-        memcpy(pUBuffer + i * dstUVStride, srcU + i * width / 2, width / 2);
+
+    dst = dstStart + dstYStride * height;
+    for (size_t i = 0; i < height / 2; ++i) {
+        memcpy(dst, srcV, width / 2);
+        srcV += srcVStride;
+        dst += dstUVStride;
     }
-    for (int i = 0; i < height / 2; ++i) {
-        memcpy(pVBuffer + i * dstUVStride, srcV + i * width / 2, width / 2);
+
+    dst = dstStart + (dstYStride * height) + (dstUVStride * height / 2);
+    for (size_t i = 0; i < height / 2; ++i) {
+        memcpy(dst, srcU, width / 2);
+        srcU += srcUStride;
+        dst += dstUVStride;
     }
 }
 
@@ -892,7 +898,7 @@ C2GoldfishVpxDec::outputBuffer(const std::shared_ptr<C2BlockPool> &pool,
 
     // now get the block
     std::shared_ptr<C2GraphicBlock> block;
-    uint32_t format = HAL_PIXEL_FORMAT_YV12;
+    uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
     const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
                                  C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
 
@@ -1006,12 +1012,13 @@ C2GoldfishVpxDec::outputBuffer(const std::shared_ptr<C2BlockPool> &pool,
         if (img->fmt == VPX_IMG_FMT_I42016) {
             ALOGW("WARNING: not I42016 is not supported !!!");
         } else if (1) {
-            // the decoded frame is YUV420 from host
             const uint8_t *srcY = (const uint8_t *)mCtx->dst;
-            const uint8_t *srcU = srcY + mWidth * mHeight;
-            const uint8_t *srcV = srcU + mWidth * mHeight / 4;
+            const uint8_t *srcV = srcY + mWidth * mHeight;
+            const uint8_t *srcU = srcV + mWidth * mHeight / 4;
             // TODO: the following crashes
-            copyOutputBufferToYuvPlanarFrame(wView, srcY, srcU, srcV, mWidth, mHeight);
+            copyOutputBufferToYuvPlanarFrame(dst, srcY, srcU, srcV, srcYStride,
+                                             srcUStride, srcVStride, dstYStride,
+                                             dstUVStride, mWidth, mHeight);
             // memcpy(dst, srcY, mWidth * mHeight / 2);
         }
     }
diff --git a/system/codecs/omx/common/Android.bp b/system/codecs/omx/common/Android.bp
index 7a7f7270..5e5af973 100644
--- a/system/codecs/omx/common/Android.bp
+++ b/system/codecs/omx/common/Android.bp
@@ -26,10 +26,10 @@ cc_library_static {
         "liblog",
     ],
     static_libs: [
-        "libGoldfishAddressSpace",
+        "mesa_goldfish_address_space",
     ],
     whole_static_libs: [
-        "libGoldfishAddressSpace",
+        "mesa_goldfish_address_space",
     ],
     export_include_dirs: [
         "include",
diff --git a/system/gralloc/Android.bp b/system/gralloc/Android.bp
index 55cc0854..05a57a4a 100644
--- a/system/gralloc/Android.bp
+++ b/system/gralloc/Android.bp
@@ -22,9 +22,6 @@ cc_library_shared {
     name: "gralloc.goldfish",
     vendor: true,
     relative_install_path: "hw",
-    defaults: [
-        "libgfxstream_guest_cc_defaults",
-    ],
     shared_libs: [
         "libcutils",
         "libdl",
@@ -36,14 +33,15 @@ cc_library_shared {
         "libOpenglSystemCommon",
     ],
     static_libs: [
-        "libGoldfishAddressSpace",
+        "mesa_goldfish_address_space",
         "libqemupipe.ranchu",
     ],
     cflags: [
         "-DVIRTIO_GPU",
         "-DLOG_TAG=\"gralloc_goldfish\"",
+        "-Wno-gnu-designator",
         "-Wno-missing-field-initializers",
-        "-Wno-gnu-designator"
+        "-Wno-unused-parameter",
     ],
     srcs: [
         "gralloc_old.cpp",
@@ -54,9 +52,6 @@ cc_library_shared {
     name: "gralloc.ranchu",
     vendor: true,
     relative_install_path: "hw",
-    defaults: [
-        "libgfxstream_guest_cc_defaults",
-    ],
     shared_libs: [
         "libcutils",
         "libdl",
@@ -68,14 +63,14 @@ cc_library_shared {
         "libOpenglSystemCommon",
     ],
     static_libs: [
-        "libGoldfishAddressSpace",
+        "mesa_goldfish_address_space",
         "libqemupipe.ranchu",
     ],
     cflags: [
         "-DVIRTIO_GPU",
         "-DLOG_TAG=\"gralloc_ranchu\"",
-        "-Wno-missing-field-initializers",
-        "-Wno-gnu-designator"
+        "-Wno-gnu-designator",
+        "-Wno-unused-parameter",
     ],
     srcs: [
         "gralloc_old.cpp",
diff --git a/system/gralloc/gralloc_old.cpp b/system/gralloc/gralloc_old.cpp
index 0fe864e4..545f397e 100644
--- a/system/gralloc/gralloc_old.cpp
+++ b/system/gralloc/gralloc_old.cpp
@@ -466,7 +466,7 @@ static HostConnection* sHostCon = NULL;
 
 static HostConnection* createOrGetHostConnection() {
     if (!sHostCon) {
-        sHostCon = HostConnection::createUnique().release();
+        sHostCon = HostConnection::createUnique(kCapsetNone).release();
     }
     return sHostCon;
 }
diff --git a/system/hals/Android.bp b/system/hals/Android.bp
deleted file mode 100644
index d13c1a07..00000000
--- a/system/hals/Android.bp
+++ /dev/null
@@ -1,93 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_generic_goldfish-opengl_license"],
-}
-
-cc_library_headers {
-    name: "libgralloc_cb3.ranchu",
-    vendor_available: true,
-    export_include_dirs: ["."],
-    header_libs: [
-        "libcutils_headers",
-        "libqemupipe-types.ranchu",
-    ],
-    export_header_lib_headers: [
-        "libcutils_headers",
-        "libqemupipe-types.ranchu",
-    ],
-}
-
-cc_defaults {
-    name: "android.hardware.graphics_defaults",
-    relative_install_path: "hw",
-    vendor: true,
-    static_libs: [
-        "libqemupipe.ranchu",
-        "libGoldfishAddressSpace",
-    ],
-    shared_libs: [
-        "android.hardware.graphics.mapper@3.0",
-        "libbase",
-        "libcutils",
-        "libdrm",
-        "libhidlbase",
-        "liblog",
-        "libutils",
-        "libOpenglCodecCommon",
-        "libOpenglSystemCommon",
-    ],
-    header_libs: ["libgralloc_cb.ranchu"],
-    include_dirs: [
-        "external/libdrm",
-        "external/minigbm/cros_gralloc",
-        "hardware/google/gfxstream/guest/include",
-        // "hardware/google/gfxstream/guest/iostream/include/libOpenglRender" does not exist.
-        "hardware/google/gfxstream/guest/platform/include",
-        "hardware/google/gfxstream/guest/renderControl_enc",
-        "hardware/google/gfxstream/guest/GoldfishAddressSpace/include",
-        "hardware/google/gfxstream/guest/OpenglCodecCommon",
-        "hardware/google/gfxstream/guest/OpenglSystemCommon",
-    ],
-    cflags: ["-DVIRTIO_GPU"],
-}
-
-cc_binary {
-    name: "android.hardware.graphics.allocator@3.0-service.ranchu",
-    defaults: ["android.hardware.graphics_defaults"],
-    srcs: ["allocator3.cpp"],
-    init_rc: ["android.hardware.graphics.allocator@3.0-service.ranchu.rc"],
-    vintf_fragments: ["android.hardware.graphics.gralloc3.ranchu.xml"],
-    shared_libs: [
-        "android.hardware.graphics.allocator@3.0",
-    ],
-}
-
-cc_library_shared {
-    name: "android.hardware.graphics.mapper@3.0-impl-ranchu",
-    defaults: ["android.hardware.graphics_defaults"],
-    srcs: ["mapper3.cpp"],
-    shared_libs: [
-        "libsync",
-        "libandroidemu",
-    ],
-}
diff --git a/system/hals/allocator3.cpp b/system/hals/allocator3.cpp
deleted file mode 100644
index 3c15b633..00000000
--- a/system/hals/allocator3.cpp
+++ /dev/null
@@ -1,446 +0,0 @@
-/*
-* Copyright (C) 2020 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#include <android-base/unique_fd.h>
-#include <android/hardware/graphics/allocator/3.0/IAllocator.h>
-#include <android/hardware/graphics/mapper/3.0/IMapper.h>
-#include <hidl/LegacySupport.h>
-#include <qemu_pipe_bp.h>
-#include <drm_fourcc.h>
-
-#include "glUtils.h"
-#include "cb_handle_30.h"
-#include "host_connection_session.h"
-#include "types.h"
-#include "debug.h"
-
-const int kOMX_COLOR_FormatYUV420Planar = 19;
-
-using ::android::hardware::hidl_handle;
-using ::android::hardware::hidl_vec;
-using ::android::hardware::hidl_bitfield;
-using ::android::hardware::Return;
-using ::android::hardware::Void;
-
-using ::android::hardware::graphics::common::V1_2::PixelFormat;
-using ::android::hardware::graphics::common::V1_0::BufferUsage;
-
-namespace AllocatorV3 = ::android::hardware::graphics::allocator::V3_0;
-namespace MapperV3 = ::android::hardware::graphics::mapper::V3_0;
-
-using IAllocator3 = AllocatorV3::IAllocator;
-using IMapper3 = MapperV3::IMapper;
-using Error3 = MapperV3::Error;
-using BufferDescriptorInfo = IMapper3::BufferDescriptorInfo;
-
-namespace {
-bool needGpuBuffer(const uint32_t usage) {
-    return usage & (BufferUsage::GPU_TEXTURE
-                    | BufferUsage::GPU_RENDER_TARGET
-                    | BufferUsage::COMPOSER_OVERLAY
-                    | BufferUsage::COMPOSER_CLIENT_TARGET
-                    | BufferUsage::GPU_DATA_BUFFER);
-}
-}  // namespace
-
-class GoldfishAllocator : public IAllocator3 {
-public:
-    GoldfishAllocator() : m_hostConn(HostConnection::createUnique()) {}
-
-    Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
-        hidl_cb("GoldfishAllocator::dumpDebugInfo is not implemented");
-        return {};
-    }
-
-    Return<void> allocate(const hidl_vec<uint32_t>& rawDescriptor,
-                          uint32_t count,
-                          allocate_cb hidl_cb) {
-        uint32_t stride = 0;
-        std::vector<cb_handle_30_t*> cbs;
-        cbs.reserve(count);
-
-        const Error3 e = allocateImpl(rawDescriptor, count, &stride, &cbs);
-        if (e == Error3::NONE) {
-            hidl_vec<hidl_handle> handles(cbs.cbegin(), cbs.cend());
-            hidl_cb(Error3::NONE, stride, handles);
-        } else {
-            hidl_cb(e, 0, {});
-        }
-
-        for (cb_handle_30_t* cb : cbs) {
-            freeCb(std::unique_ptr<cb_handle_30_t>(cb));
-        }
-
-        return {};
-    }
-
-private:
-    // this function should be in sync with GoldfishMapper::isSupportedImpl
-    Error3 allocateImpl(const hidl_vec<uint32_t>& rawDescriptor,
-                        uint32_t count,
-                        uint32_t* pStride,
-                        std::vector<cb_handle_30_t*>* cbs) {
-        BufferDescriptorInfo descriptor;
-        if (!decodeBufferDescriptorInfo(rawDescriptor, &descriptor)) {
-            RETURN_ERROR(Error3::BAD_DESCRIPTOR);
-        }
-
-        if (!descriptor.width) { RETURN_ERROR(Error3::UNSUPPORTED); }
-        if (!descriptor.height) { RETURN_ERROR(Error3::UNSUPPORTED); }
-        if (descriptor.layerCount != 1) { RETURN_ERROR(Error3::UNSUPPORTED); }
-
-        const uint32_t usage = descriptor.usage;
-
-        int bpp = 1;
-        int glFormat = 0;
-        int glType = 0;
-        int align = 1;
-        bool yuv_format = false;
-        EmulatorFrameworkFormat emulatorFrameworkFormat =
-            EmulatorFrameworkFormat::GL_COMPATIBLE;
-
-        PixelFormat format;
-        Error3 e = getBufferFormat(descriptor.format, usage, &format);
-        if (e != Error3::NONE) {
-            ALOGE("%s:%d Unsupported format: frameworkFormat=%d, usage=%x",
-                  __func__, __LINE__, descriptor.format, usage);
-            return e;
-        }
-
-        switch (format) {
-        case PixelFormat::RGBA_8888:
-        case PixelFormat::RGBX_8888:
-        case PixelFormat::BGRA_8888:
-            bpp = 4;
-            glFormat = GL_RGBA;
-            glType = GL_UNSIGNED_BYTE;
-            break;
-
-        case PixelFormat::RGB_888:
-            if (needGpuBuffer(usage)) {
-                RETURN_ERROR(Error3::UNSUPPORTED);
-            }
-            bpp = 3;
-            glFormat = GL_RGB;
-            glType = GL_UNSIGNED_BYTE;
-            break;
-
-        case PixelFormat::RGB_565:
-            bpp = 2;
-            glFormat = GL_RGB565;
-            glType = GL_UNSIGNED_SHORT_5_6_5;
-            break;
-
-        case PixelFormat::RGBA_FP16:
-            bpp = 8;
-            glFormat = GL_RGBA16F;
-            glType = GL_HALF_FLOAT;
-            break;
-
-        case PixelFormat::RGBA_1010102:
-            bpp = 4;
-            glFormat = GL_RGB10_A2;
-            glType = GL_UNSIGNED_INT_2_10_10_10_REV;
-            break;
-
-        case PixelFormat::RAW16:
-        case PixelFormat::Y16:
-            if (needGpuBuffer(usage)) {
-                RETURN_ERROR(Error3::UNSUPPORTED);
-            }
-            bpp = 2;
-            align = 16 * bpp;
-            glFormat = GL_LUMINANCE;
-            glType = GL_UNSIGNED_SHORT;
-            break;
-
-        case PixelFormat::BLOB:
-            if (needGpuBuffer(usage)) {
-                RETURN_ERROR(Error3::UNSUPPORTED);
-            }
-            glFormat = GL_LUMINANCE;
-            glType = GL_UNSIGNED_BYTE;
-            break;
-
-        case PixelFormat::YCRCB_420_SP:
-            if (needGpuBuffer(usage)) {
-                RETURN_ERROR(Error3::UNSUPPORTED);
-            }
-            yuv_format = true;
-            break;
-
-        case PixelFormat::YV12:
-            align = 16;
-            yuv_format = true;
-            // We are going to use RGB8888 on the host for Vulkan
-            glFormat = GL_RGBA;
-            glType = GL_UNSIGNED_BYTE;
-            emulatorFrameworkFormat = EmulatorFrameworkFormat::YV12;
-            break;
-
-        case PixelFormat::YCBCR_420_888:
-            yuv_format = true;
-            // We are going to use RGBA 8888 on the host
-            glFormat = GL_RGBA;
-            glType = GL_UNSIGNED_BYTE;
-            emulatorFrameworkFormat = EmulatorFrameworkFormat::YUV_420_888;
-            break;
-
-        case PixelFormat::YCBCR_P010:
-            yuv_format = true;
-            glFormat = GL_RGBA;
-            glType = GL_UNSIGNED_BYTE;
-            bpp = 2;
-            break;
-
-        default:
-            ALOGE("%s:%d Unsupported format: format=%d, frameworkFormat=%d, usage=%x",
-                  __func__, __LINE__, format, descriptor.format, usage);
-            RETURN_ERROR(Error3::UNSUPPORTED);
-        }
-
-        const uint32_t width = descriptor.width;
-        const uint32_t height = descriptor.height;
-        size_t bufferSize;
-        uint32_t stride;
-
-        if (usage & (BufferUsage::CPU_READ_MASK | BufferUsage::CPU_WRITE_MASK)) {
-            const size_t align1 = align - 1;
-            if (yuv_format) {
-                const size_t yStride = (width * bpp + align1) & ~align1;
-                const size_t uvStride = (yStride / 2 + align1) & ~align1;
-                const size_t uvHeight = height / 2;
-                bufferSize = yStride * height + 2 * (uvHeight * uvStride);
-                stride = yStride / bpp;
-            } else {
-                const size_t bpr = (width * bpp + align1) & ~align1;
-                bufferSize = bpr * height;
-                stride = bpr / bpp;
-            }
-        } else {
-            bufferSize = 0;
-            stride = 0;
-        }
-
-        *pStride = stride;
-
-        return allocateImpl2(usage,
-                             width, height,
-                             format, emulatorFrameworkFormat,
-                             glFormat, glType,
-                             bufferSize,
-                             bpp, stride,
-                             count, cbs);
-    }
-
-    Error3 allocateImpl2(const uint32_t usage,
-                         const uint32_t width, const uint32_t height,
-                         const PixelFormat format,
-                         const EmulatorFrameworkFormat emulatorFrameworkFormat,
-                         const int glFormat, const int glType,
-                         const size_t bufferSize,
-                         const uint32_t bytesPerPixel,
-                         const uint32_t stride,
-                         const uint32_t count,
-                         std::vector<cb_handle_30_t*>* cbs) {
-        for (uint32_t i = 0; i < count; ++i) {
-            cb_handle_30_t* cb;
-            Error3 e = allocateCb(usage,
-                                  width, height,
-                                  format, emulatorFrameworkFormat,
-                                  glFormat, glType,
-                                  bufferSize,
-                                  bytesPerPixel, stride,
-                                  &cb);
-            if (e == Error3::NONE) {
-                cbs->push_back(cb);
-            } else {
-                return e;
-            }
-        }
-
-        RETURN(Error3::NONE);
-    }
-
-    // see GoldfishMapper::encodeBufferDescriptorInfo
-    static bool decodeBufferDescriptorInfo(const hidl_vec<uint32_t>& raw,
-                                           BufferDescriptorInfo* d) {
-        if (raw.size() == 5) {
-            d->width = raw[0];
-            d->height = raw[1];
-            d->layerCount = raw[2];
-            d->format = static_cast<PixelFormat>(raw[3]);
-            d->usage = raw[4];
-
-            RETURN(true);
-        } else {
-            RETURN_ERROR(false);
-        }
-    }
-
-    static Error3 getBufferFormat(const PixelFormat frameworkFormat,
-                                  const uint32_t usage,
-                                  PixelFormat* format) {
-        if (frameworkFormat == PixelFormat::IMPLEMENTATION_DEFINED) {
-            RETURN_ERROR(Error3::UNSUPPORTED);
-        } else if (static_cast<int>(frameworkFormat) == kOMX_COLOR_FormatYUV420Planar &&
-               (usage & BufferUsage::VIDEO_DECODER)) {
-            ALOGW("gralloc_alloc: Requested OMX_COLOR_FormatYUV420Planar, given "
-              "YCbCr_420_888, taking experimental path. "
-              "usage=%x", usage);
-            *format = PixelFormat::YCBCR_420_888;
-            RETURN(Error3::NONE);
-        } else  {
-            *format = frameworkFormat;
-            RETURN(Error3::NONE);
-        }
-    }
-
-    Error3 allocateCb(const uint32_t usage,
-                      const uint32_t width, const uint32_t height,
-                      const PixelFormat format,
-                      const EmulatorFrameworkFormat emulatorFrameworkFormat,
-                      const int glFormat, const int glType,
-                      const size_t bufferSize,
-                      const int32_t bytesPerPixel,
-                      const int32_t stride,
-                      cb_handle_30_t** cb) {
-        const HostConnectionSession conn = getHostConnectionSession();
-        ExtendedRCEncoderContext *const rcEnc = conn.getRcEncoder();
-        CRASH_IF(!rcEnc, "conn.getRcEncoder() failed");
-
-        android::base::unique_fd cpuAlocatorFd;
-        GoldfishAddressSpaceBlock bufferBits;
-        if (bufferSize > 0) {
-            GoldfishAddressSpaceHostMemoryAllocator host_memory_allocator(
-                rcEnc->featureInfo_const()->hasSharedSlotsHostMemoryAllocator);
-            if (!host_memory_allocator.is_opened()) {
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-
-            if (host_memory_allocator.hostMalloc(&bufferBits, bufferSize)) {
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-
-            cpuAlocatorFd.reset(host_memory_allocator.release());
-        }
-
-        uint32_t hostHandle = 0;
-        android::base::unique_fd hostHandleRefCountFd;
-        if (needGpuBuffer(usage)) {
-            hostHandleRefCountFd.reset(qemu_pipe_open("refcount"));
-            if (!hostHandleRefCountFd.ok()) {
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-
-            const GLenum allocFormat =
-                (PixelFormat::RGBX_8888 == format) ? GL_RGB : glFormat;
-
-            hostHandle = rcEnc->rcCreateColorBufferDMA(
-                rcEnc,
-                width, height,
-                allocFormat, static_cast<int>(emulatorFrameworkFormat));
-
-            if (!hostHandle) {
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-
-            if (qemu_pipe_write(hostHandleRefCountFd.get(),
-                                &hostHandle,
-                                sizeof(hostHandle)) != sizeof(hostHandle)) {
-                rcEnc->rcCloseColorBuffer(rcEnc, hostHandle);
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-        }
-        uint32_t drmFormat = resolve_drm_format(format);
-        std::unique_ptr<cb_handle_30_t> handle =
-            std::make_unique<cb_handle_30_t>(
-                cpuAlocatorFd.release(),
-                hostHandleRefCountFd.release(),
-                hostHandle,
-                usage,
-                width,
-                height,
-                static_cast<int>(format),
-                drmFormat,
-                glFormat,
-                glType,
-                bufferSize,
-                bufferBits.guestPtr(),
-                bufferBits.size(),
-                bufferBits.offset(),
-                bytesPerPixel,
-                stride);
-
-        bufferBits.release();
-        *cb = handle.release();
-        RETURN(Error3::NONE);
-    }
-
-    uint32_t resolve_drm_format(const PixelFormat format) {
-        /**
-         * This aims to replicate the virtgpu format handling for YUV
-         * Moving to minigbm + virtgpu should offer the same behaviour
-         * https://cs.android.com/android/platform/superproject/main/+/main:external/minigbm/virtgpu_virgl.c;l=1206?q=virtgpu&ss=android%2Fplatform%2Fsuperproject%2Fmain
-        */
-        ALOGV("Resolving drm format from PixelFormat %d", static_cast<int>(format));
-        switch (format) {
-            case PixelFormat::YCBCR_420_888:
-                return DRM_FORMAT_YUV420;
-            default:
-                //TODO handle new formats if needed
-                ALOGV("Unknown DRM Format resolution. Proceeding with an "
-                      "invalid drm format. Later stages of the application "
-                      "should handle this.");
-                return DRM_FORMAT_INVALID;
-        }
-    }
-
-    void freeCb(std::unique_ptr<cb_handle_30_t> cb) {
-        if (cb->hostHandleRefcountFdIndex >= 0) {
-            ::close(cb->fds[cb->hostHandleRefcountFdIndex]);
-        }
-
-        if (cb->bufferFdIndex >= 0) {
-            GoldfishAddressSpaceBlock::memoryUnmap(cb->getBufferPtr(), cb->mmapedSize);
-            GoldfishAddressSpaceHostMemoryAllocator::closeHandle(cb->fds[cb->bufferFdIndex]);
-        }
-    }
-
-    HostConnectionSession getHostConnectionSession() const {
-        return HostConnectionSession(m_hostConn.get());
-    }
-
-    std::unique_ptr<HostConnection> m_hostConn;
-};
-
-int main(int, char**) {
-    using ::android::sp;
-
-    ::android::hardware::configureRpcThreadpool(4, true /* callerWillJoin */);
-
-    sp<IAllocator3> allocator(new GoldfishAllocator());
-    if (allocator->registerAsService() != ::android::NO_ERROR) {
-        ALOGE("failed to register graphics IAllocator@3.0 service");
-        return -EINVAL;
-    }
-
-    ALOGI("graphics IAllocator@3.0 service is initialized");
-    ::android::hardware::joinRpcThreadpool();
-
-    ALOGI("graphics IAllocator@3.0 service is terminating");
-    return 0;
-}
diff --git a/system/hals/android.hardware.graphics.allocator@3.0-service.ranchu.rc b/system/hals/android.hardware.graphics.allocator@3.0-service.ranchu.rc
deleted file mode 100644
index f874b144..00000000
--- a/system/hals/android.hardware.graphics.allocator@3.0-service.ranchu.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-service vendor.gralloc-3-0 /vendor/bin/hw/android.hardware.graphics.allocator@3.0-service.ranchu
-    interface android.hardware.graphics.allocator@3.0::IAllocator default
-    class hal animation
-    user system
-    group graphics drmrpc
-    capabilities SYS_NICE
-    onrestart restart surfaceflinger
diff --git a/system/hals/android.hardware.graphics.gralloc3.ranchu.xml b/system/hals/android.hardware.graphics.gralloc3.ranchu.xml
deleted file mode 100644
index f3e7d3b6..00000000
--- a/system/hals/android.hardware.graphics.gralloc3.ranchu.xml
+++ /dev/null
@@ -1,20 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="hidl">
-        <name>android.hardware.graphics.allocator</name>
-        <transport>hwbinder</transport>
-        <version>3.0</version>
-        <interface>
-            <name>IAllocator</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.graphics.mapper</name>
-        <transport arch="32+64">passthrough</transport>
-        <version>3.0</version>
-        <interface>
-            <name>IMapper</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-</manifest>
diff --git a/system/hals/cb_handle_30.h b/system/hals/cb_handle_30.h
deleted file mode 100644
index 11c8d0fb..00000000
--- a/system/hals/cb_handle_30.h
+++ /dev/null
@@ -1,125 +0,0 @@
-/*
-* Copyright 2011 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#ifndef SYSTEM_HALS_CB_HANDLE_30_H
-#define SYSTEM_HALS_CB_HANDLE_30_H
-
-#include <gralloc_cb_bp.h>
-#include "goldfish_address_space.h"
-
-const uint32_t CB_HANDLE_MAGIC_30 = CB_HANDLE_MAGIC_BASE | 0x2;
-
-struct cb_handle_30_t : public cb_handle_t {
-    cb_handle_30_t(int p_bufferFd,
-                   int p_hostHandleRefCountFd,
-                   uint32_t p_hostHandle,
-                   uint32_t p_usage,
-                   uint32_t p_width,
-                   uint32_t p_height,
-                   uint32_t p_format,
-                   uint32_t p_drmformat,
-                   uint32_t p_glFormat,
-                   uint32_t p_glType,
-                   uint32_t p_bufSize,
-                   void* p_bufPtr,
-                   uint32_t p_mmapedSize,
-                   uint64_t p_mmapedOffset,
-                   uint32_t p_bytesPerPixel,
-                   uint32_t p_stride)
-            : cb_handle_t(CB_HANDLE_MAGIC_30,
-                          p_hostHandle,
-                          p_format,
-                          p_drmformat,
-                          p_stride,
-                          p_bufSize,
-                          p_mmapedOffset),
-              usage(p_usage),
-              width(p_width),
-              height(p_height),
-              glFormat(p_glFormat),
-              glType(p_glType),
-              bytesPerPixel(p_bytesPerPixel),
-              mmapedSize(p_mmapedSize),
-              lockedUsage(0) {
-        fds[0] = -1;
-        fds[1] = -1;
-        int n = 0;
-        if (p_bufferFd >= 0) {
-            bufferFdIndex = n++;
-            fds[bufferFdIndex] = p_bufferFd;
-        } else {
-            bufferFdIndex = -1;
-        }
-
-        if (p_hostHandleRefCountFd >= 0) {
-            hostHandleRefcountFdIndex = n++;
-            fds[hostHandleRefcountFdIndex] = p_hostHandleRefCountFd;
-        } else {
-            hostHandleRefcountFdIndex = -1;
-        }
-
-        numFds = n;
-        numInts = CB_HANDLE_NUM_INTS(n);
-        setBufferPtr(p_bufPtr);
-    }
-
-    bool isValid() const { return (version == sizeof(native_handle_t)) && (magic == CB_HANDLE_MAGIC_30); }
-
-    void* getBufferPtr() const {
-        const uint64_t addr = (uint64_t(bufferPtrHi) << 32) | bufferPtrLo;
-        return reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
-    }
-
-    void setBufferPtr(void* ptr) {
-        const uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr));
-        bufferPtrLo = uint32_t(addr);
-        bufferPtrHi = uint32_t(addr >> 32);
-    }
-
-    static cb_handle_30_t* from(void* p) {
-        if (!p) { return nullptr; }
-        cb_handle_30_t* cb = static_cast<cb_handle_30_t*>(p);
-        return cb->isValid() ? cb : nullptr;
-    }
-
-    static const cb_handle_30_t* from(const void* p) {
-        return from(const_cast<void*>(p));
-    }
-
-    static cb_handle_30_t* from_unconst(const void* p) {
-        return from(const_cast<void*>(p));
-    }
-
-    uint32_t usage;         // usage bits the buffer was created with
-    uint32_t width;         // buffer width
-    uint32_t height;        // buffer height
-    uint32_t glFormat;      // OpenGL format enum used for host h/w color buffer
-    uint32_t glType;        // OpenGL type enum used when uploading to host
-    uint32_t bytesPerPixel;
-    uint32_t mmapedSize;    // real allocation side
-    uint32_t bufferPtrLo;
-    uint32_t bufferPtrHi;
-    uint8_t  lockedUsage;
-    int8_t   bufferFdIndex;
-    int8_t   hostHandleRefcountFdIndex;
-    int8_t   unused;
-    uint32_t lockedLeft;    // region of buffer locked for s/w write
-    uint32_t lockedTop;
-    uint32_t lockedWidth;
-    uint32_t lockedHeight;
-};
-
-#endif // SYSTEM_HALS_CB_HANDLE_30_H
diff --git a/system/hals/debug.h b/system/hals/debug.h
deleted file mode 100644
index f8e41b4e..00000000
--- a/system/hals/debug.h
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
-* Copyright (C) 2020 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#ifndef GOLDFISH_OPENGL_SYSTEM_HALS_DEBUG_H_INCLUDED
-#define GOLDFISH_OPENGL_SYSTEM_HALS_DEBUG_H_INCLUDED
-
-#include <log/log.h>
-
-#define RETURN(X) return (X)
-
-#define RETURN_ERROR(X) \
-    do { \
-        ALOGE("%s:%d failed with '%s'", __func__, __LINE__, #X); \
-        return (X); \
-    } while (false)
-
-#define CRASH(MSG) \
-    do { \
-        ALOGE("%s:%d crashed with '%s'", __func__, __LINE__, MSG); \
-        ::abort(); \
-    } while (false)
-
-#define CRASH_IF(COND, MSG) \
-    do { \
-        if ((COND)) { \
-            ALOGE("%s:%d crashed on '%s' with '%s'", __func__, __LINE__, #COND, MSG); \
-            ::abort(); \
-        } \
-    } while (false)
-
-#endif  // GOLDFISH_OPENGL_SYSTEM_HALS_DEBUG_H_INCLUDED
diff --git a/system/hals/host_connection_session.h b/system/hals/host_connection_session.h
deleted file mode 100644
index 12d3b76f..00000000
--- a/system/hals/host_connection_session.h
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
-* Copyright (C) 2020 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#ifndef GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
-#define GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
-
-#include "HostConnection.h"
-
-class HostConnectionSession {
-public:
-    explicit HostConnectionSession(HostConnection* hc) : conn(hc) {
-        hc->lock();
-    }
-
-    ~HostConnectionSession() {
-        if (conn) {
-            conn->unlock();
-        }
-     }
-
-    HostConnectionSession(HostConnectionSession&& rhs) : conn(rhs.conn) {
-        rhs.conn = nullptr;
-    }
-
-    HostConnectionSession& operator=(HostConnectionSession&& rhs) {
-        if (this != &rhs) {
-            std::swap(conn, rhs.conn);
-        }
-        return *this;
-    }
-
-    HostConnectionSession(const HostConnectionSession&) = delete;
-    HostConnectionSession& operator=(const HostConnectionSession&) = delete;
-
-    ExtendedRCEncoderContext* getRcEncoder() const {
-        return conn->rcEncoder();
-    }
-
-private:
-    HostConnection* conn;
-};
-
-#endif  // GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
diff --git a/system/hals/mapper3.cpp b/system/hals/mapper3.cpp
deleted file mode 100644
index 8be0b492..00000000
--- a/system/hals/mapper3.cpp
+++ /dev/null
@@ -1,669 +0,0 @@
-/*
-* Copyright (C) 2020 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#include <android/hardware/graphics/mapper/3.0/IMapper.h>
-#include <cutils/native_handle.h>
-#include <sync/sync.h>
-
-#include "cb_handle_30.h"
-#include "host_connection_session.h"
-#include "FormatConversions.h"
-#include "debug.h"
-
-#include "aemu/base/Tracing.h"
-
-#define ATRACE_TAG ATRACE_TAG_GRAPHICS
-
-const int kOMX_COLOR_FormatYUV420Planar = 19;
-
-using ::android::hardware::hidl_handle;
-using ::android::hardware::hidl_vec;
-using ::android::hardware::Return;
-using ::android::hardware::Void;
-
-using ::android::hardware::graphics::common::V1_2::PixelFormat;
-using ::android::hardware::graphics::common::V1_0::BufferUsage;
-
-namespace MapperV3 = ::android::hardware::graphics::mapper::V3_0;
-
-using IMapper3 = MapperV3::IMapper;
-using Error3 = MapperV3::Error;
-using YCbCrLayout3 = MapperV3::YCbCrLayout;
-
-namespace {
-size_t align(const size_t v, const size_t a) { return (v + a - 1) & ~(a - 1); }
-
-static int waitFenceFd(const int fd, const char* logname) {
-    const int warningTimeout = 5000;
-    if (sync_wait(fd, warningTimeout) < 0) {
-        if (errno == ETIME) {
-            ALOGW("%s: fence %d didn't signal in %d ms", logname, fd, warningTimeout);
-            if (sync_wait(fd, -1) < 0) {
-                RETURN_ERROR(errno);
-            } else {
-                RETURN(0);
-            }
-        } else {
-            RETURN_ERROR(errno);
-        }
-    } else {
-        RETURN(0);
-    }
-}
-
-int waitHidlFence(const hidl_handle& hidlHandle, const char* logname) {
-    const native_handle_t* nativeHandle = hidlHandle.getNativeHandle();
-
-    if (!nativeHandle) {
-        RETURN(0);
-    }
-    if (nativeHandle->numFds > 1) {
-        RETURN_ERROR(-EINVAL);
-    }
-    if (nativeHandle->numInts != 0) {
-        RETURN_ERROR(-EINVAL);
-    }
-
-    return waitFenceFd(nativeHandle->data[0], logname);
-}
-
-bool needGpuBuffer(const uint32_t usage) {
-    return usage & (BufferUsage::GPU_TEXTURE
-                    | BufferUsage::GPU_RENDER_TARGET
-                    | BufferUsage::COMPOSER_OVERLAY
-                    | BufferUsage::COMPOSER_CLIENT_TARGET
-                    | BufferUsage::GPU_DATA_BUFFER);
-}
-
-constexpr uint64_t one64 = 1;
-
-constexpr uint64_t ones(int from, int to) {
-    return ((one64 << (to - from + 1)) - 1) << from;
-}
-
-class GoldfishMapper : public IMapper3 {
-public:
-    GoldfishMapper() : m_hostConn(HostConnection::createUnique()) {
-        GoldfishAddressSpaceHostMemoryAllocator host_memory_allocator(false);
-        CRASH_IF(!host_memory_allocator.is_opened(),
-                 "GoldfishAddressSpaceHostMemoryAllocator failed to open");
-
-        GoldfishAddressSpaceBlock bufferBits;
-        CRASH_IF(host_memory_allocator.hostMalloc(&bufferBits, 256),
-                 "hostMalloc failed");
-
-        m_physAddrToOffset = bufferBits.physAddr() - bufferBits.offset();
-
-        host_memory_allocator.hostFree(&bufferBits);
-    }
-
-    Return<void> importBuffer(const hidl_handle& hh,
-                              importBuffer_cb hidl_cb) {
-        native_handle_t* imported = nullptr;
-        const Error3 e = importBufferImpl(hh.getNativeHandle(), &imported);
-        if (e == Error3::NONE) {
-            hidl_cb(Error3::NONE, imported);
-        } else {
-            hidl_cb(e, nullptr);
-        }
-        return {};
-    }
-
-    Return<Error3> freeBuffer(void* raw) {
-        if (!raw) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        cb_handle_30_t* cb = cb_handle_30_t::from(raw);
-        if (!cb) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-
-        if (cb->mmapedSize > 0) {
-            GoldfishAddressSpaceBlock::memoryUnmap(cb->getBufferPtr(), cb->mmapedSize);
-        }
-
-        native_handle_close(cb);
-        native_handle_delete(cb);
-
-        RETURN(Error3::NONE);
-    }
-
-    Return<void> lock(void* raw,
-                      uint64_t cpuUsage,
-                      const Rect& accessRegion,
-                      const hidl_handle& acquireFence,
-                      lock_cb hidl_cb) {
-        void* ptr = nullptr;
-        int32_t bytesPerPixel = 0;
-        int32_t bytesPerStride = 0;
-
-        const Error3 e = lockImpl(raw, cpuUsage, accessRegion, acquireFence,
-                                  &ptr, &bytesPerPixel, &bytesPerStride);
-        if (e == Error3::NONE) {
-            hidl_cb(Error3::NONE, ptr, bytesPerPixel, bytesPerStride);
-        } else {
-            hidl_cb(e, nullptr, 0, 0);
-        }
-        return {};
-    }
-
-    Return<void> lockYCbCr(void* raw,
-                           uint64_t cpuUsage,
-                           const Rect& accessRegion,
-                           const hidl_handle& acquireFence,
-                           lockYCbCr_cb hidl_cb) {
-        YCbCrLayout3 ycbcr = {};
-        const Error3 e = lockYCbCrImpl(raw, cpuUsage, accessRegion, acquireFence,
-                                       &ycbcr);
-        if (e == Error3::NONE) {
-            hidl_cb(Error3::NONE, ycbcr);
-        } else {
-            hidl_cb(e, {});
-        }
-        return {};
-    }
-
-    Return<void> unlock(void* raw, unlock_cb hidl_cb) {
-        hidl_cb(unlockImpl(raw), {});
-        return {};
-
-    }
-
-    Return<void> createDescriptor(const BufferDescriptorInfo& description,
-                                  createDescriptor_cb hidl_cb) {
-        hidl_vec<uint32_t> raw;
-        encodeBufferDescriptorInfo(description, &raw);
-        hidl_cb(Error3::NONE, raw);
-        return {};
-    }
-
-    Return<void> isSupported(const IMapper::BufferDescriptorInfo& description,
-                             isSupported_cb hidl_cb) {
-        hidl_cb(Error3::NONE, isSupportedImpl(description));
-        return {};
-    }
-
-    Return<Error3> validateBufferSize(void* buffer,
-                                      const BufferDescriptorInfo& descriptor,
-                                      uint32_t stride) {
-        const cb_handle_30_t* cb = cb_handle_30_t::from(buffer);
-        if (cb) {
-            return validateBufferSizeImpl(*cb, descriptor, stride);
-        } else {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-    }
-
-    Return<void> getTransportSize(void* buffer,
-                                  getTransportSize_cb hidl_cb) {
-        const cb_handle_30_t* cb = cb_handle_30_t::from(buffer);
-        if (cb) {
-            hidl_cb(Error3::NONE, cb->numFds, cb->numInts);
-        } else {
-            hidl_cb(Error3::BAD_BUFFER, 0, 0);
-        }
-
-        return {};
-    }
-
-private:  // **** impl ****
-    Error3 importBufferImpl(const native_handle_t* nh, native_handle_t** phandle) {
-        if (!nh) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        native_handle_t* imported = native_handle_clone(nh);
-        if (!imported) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        cb_handle_30_t* cb = cb_handle_30_t::from(imported);
-        if (!cb) {
-            native_handle_close(imported);
-            native_handle_delete(imported);
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-
-        if (cb->mmapedSize > 0) {
-            LOG_ALWAYS_FATAL_IF(cb->bufferFdIndex < 0);
-            void* ptr;
-            const int res = GoldfishAddressSpaceBlock::memoryMap(
-                cb->getBufferPtr(),
-                cb->mmapedSize,
-                cb->fds[cb->bufferFdIndex],
-                cb->getMmapedOffset(),
-                &ptr);
-            if (res) {
-                native_handle_close(imported);
-                native_handle_delete(imported);
-                RETURN_ERROR(Error3::NO_RESOURCES);
-            }
-            cb->setBufferPtr(ptr);
-        }
-
-        *phandle = imported;
-        RETURN(Error3::NONE);
-    }
-
-    void setLocked(cb_handle_30_t* cb, const uint8_t checkedUsage,
-                   const Rect& accessRegion) {
-        if (checkedUsage & BufferUsage::CPU_WRITE_MASK) {
-            cb->lockedLeft = accessRegion.left;
-            cb->lockedTop = accessRegion.top;
-            cb->lockedWidth = accessRegion.width;
-            cb->lockedHeight = accessRegion.height;
-        } else {
-            cb->lockedLeft = 0;
-            cb->lockedTop = 0;
-            cb->lockedWidth = cb->width;
-            cb->lockedHeight = cb->height;
-        }
-        cb->lockedUsage = checkedUsage;
-    }
-
-    Error3 lockImpl(void* raw,
-                    const uint64_t uncheckedUsage,
-                    const Rect& accessRegion,
-                    const hidl_handle& acquireFence,
-                    void** pptr,
-                    int32_t* pBytesPerPixel,
-                    int32_t* pBytesPerStride) {
-        if (!raw) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        cb_handle_30_t* cb = cb_handle_30_t::from(raw);
-        if (!cb) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        if (cb->lockedUsage) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-        const uint8_t checkedUsage = uncheckedUsage & cb->usage &
-            (BufferUsage::CPU_READ_MASK | BufferUsage::CPU_WRITE_MASK);
-        if (checkedUsage == 0) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-        if (!cb->bufferSize) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        char* const bufferBits = static_cast<char*>(cb->getBufferPtr());
-        if (!bufferBits) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        if (waitHidlFence(acquireFence, __func__)) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-
-        if (cb->hostHandle) {
-            const Error3 e = lockHostImpl(*cb, checkedUsage, accessRegion, bufferBits);
-            if (e != Error3::NONE) {
-                return e;
-            }
-        }
-
-        setLocked(cb, checkedUsage, accessRegion);
-
-        *pptr = bufferBits;
-        *pBytesPerPixel = cb->bytesPerPixel;
-        *pBytesPerStride = cb->bytesPerPixel * cb->stride;
-        RETURN(Error3::NONE);
-    }
-
-    Error3 lockYCbCrImpl(void* raw,
-                         const uint64_t uncheckedUsage,
-                         const Rect& accessRegion,
-                         const hidl_handle& acquireFence,
-                         YCbCrLayout3* pYcbcr) {
-        if (!raw) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        cb_handle_30_t* cb = cb_handle_30_t::from(raw);
-        if (!cb) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        if (cb->lockedUsage) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-        const uint8_t checkedUsage = uncheckedUsage & cb->usage &
-            (BufferUsage::CPU_READ_MASK | BufferUsage::CPU_WRITE_MASK);
-        if (checkedUsage == 0) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-        if (!cb->bufferSize) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        char* const bufferBits = static_cast<char*>(cb->getBufferPtr());
-        if (!bufferBits) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        if (waitHidlFence(acquireFence, __func__)) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-
-        size_t uOffset;
-        size_t vOffset;
-        size_t yStride;
-        size_t cStride;
-        size_t cStep;
-        switch (static_cast<PixelFormat>(cb->format)) {
-        case PixelFormat::YCRCB_420_SP:
-            yStride = cb->width;
-            cStride = yStride;
-            vOffset = yStride * cb->height;
-            uOffset = vOffset + 1;
-            cStep = 2;
-            break;
-
-        case PixelFormat::YV12:
-            // https://developer.android.com/reference/android/graphics/ImageFormat.html#YV12
-            yStride = align(cb->width, 16);
-            cStride = align(yStride / 2, 16);
-            vOffset = yStride * cb->height;
-            uOffset = vOffset + (cStride * cb->height / 2);
-            cStep = 1;
-            break;
-
-        case PixelFormat::YCBCR_420_888:
-            yStride = cb->width;
-            cStride = yStride / 2;
-            uOffset = cb->height * yStride;
-            vOffset = uOffset + cStride * cb->height / 2;
-            cStep = 1;
-            break;
-
-        case PixelFormat::YCBCR_P010:
-            yStride = cb->width * 2;
-            cStride = yStride;
-            uOffset = cb->height * yStride;
-            vOffset = uOffset + 2;
-            cStep = 4;
-            break;
-
-        default:
-            ALOGE("%s:%d unexpected format (%d)", __func__, __LINE__, cb->format);
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-
-        if (cb->hostHandle) {
-            const Error3 e = lockHostImpl(*cb, checkedUsage, accessRegion, bufferBits);
-            if (e != Error3::NONE) {
-                return e;
-            }
-        }
-
-        setLocked(cb, checkedUsage, accessRegion);
-
-        pYcbcr->y = bufferBits;
-        pYcbcr->cb = bufferBits + uOffset;
-        pYcbcr->cr = bufferBits + vOffset;
-        pYcbcr->yStride = yStride;
-        pYcbcr->cStride = cStride;
-        pYcbcr->chromaStep = cStep;
-
-        RETURN(Error3::NONE);
-    }
-
-    Error3 lockHostImpl(cb_handle_30_t& cb,
-                        const uint8_t checkedUsage,
-                        const Rect& accessRegion,
-                        char* const bufferBits) {
-        const HostConnectionSession conn = getHostConnectionSession();
-        ExtendedRCEncoderContext *const rcEnc = conn.getRcEncoder();
-        const bool usageSwRead = (checkedUsage & BufferUsage::CPU_READ_MASK) != 0;
-
-        const int res = rcEnc->rcColorBufferCacheFlush(
-            rcEnc, cb.hostHandle, 0, usageSwRead);
-        if (res < 0) {
-            RETURN_ERROR(Error3::NO_RESOURCES);
-        }
-
-        if (usageSwRead) {
-            if (gralloc_is_yuv_format(cb.format)) {
-                if (rcEnc->hasYUVCache()) {
-                    uint32_t bufferSize;
-                    switch (static_cast<PixelFormat>(cb.format)) {
-                    case PixelFormat::YV12:
-                        get_yv12_offsets(cb.width, cb.height,
-                                         nullptr, nullptr, &bufferSize);
-                        break;
-                    case PixelFormat::YCBCR_420_888:
-                        get_yuv420p_offsets(cb.width, cb.height,
-                                            nullptr, nullptr, &bufferSize);
-                        break;
-                    default:
-                        CRASH("Unexpected format, switch is out of sync with gralloc_is_yuv_format");
-                        break;
-                    }
-
-                    rcEnc->rcReadColorBufferYUV(rcEnc, cb.hostHandle,
-                        0, 0, cb.width, cb.height,
-                        bufferBits, bufferSize);
-                } else {
-                    // We are using RGB888
-                    std::vector<char> tmpBuf(cb.width * cb.height * 3);
-                    rcEnc->rcReadColorBuffer(rcEnc, cb.hostHandle,
-                                             0, 0, cb.width, cb.height,
-                                             cb.glFormat, cb.glType,
-                                             tmpBuf.data());
-                    switch (static_cast<PixelFormat>(cb.format)) {
-                    case PixelFormat::YV12:
-                        rgb888_to_yv12(bufferBits, tmpBuf.data(),
-                                       cb.width, cb.height,
-                                       accessRegion.left,
-                                       accessRegion.top,
-                                       accessRegion.left + accessRegion.width - 1,
-                                       accessRegion.top + accessRegion.height - 1);
-                        break;
-                    case PixelFormat::YCBCR_420_888:
-                        rgb888_to_yuv420p(bufferBits, tmpBuf.data(),
-                                          cb.width, cb.height,
-                                          accessRegion.left,
-                                          accessRegion.top,
-                                          accessRegion.left + accessRegion.width - 1,
-                                          accessRegion.top + accessRegion.height - 1);
-                        break;
-                    default:
-                        CRASH("Unexpected format, switch is out of sync with gralloc_is_yuv_format");
-                        break;
-                    }
-                }
-            } else {
-                if (rcEnc->featureInfo()->hasReadColorBufferDma) {
-                    {
-                        AEMU_SCOPED_TRACE("bindDmaDirectly");
-                        rcEnc->bindDmaDirectly(bufferBits,
-                                getMmapedPhysAddr(cb.getMmapedOffset()));
-                    }
-                    rcEnc->rcReadColorBufferDMA(rcEnc,
-                        cb.hostHandle,
-                        0, 0, cb.width, cb.height,
-                        cb.glFormat, cb.glType,
-                        bufferBits, cb.width * cb.height * cb.bytesPerPixel);
-                } else {
-                    rcEnc->rcReadColorBuffer(rcEnc,
-                        cb.hostHandle,
-                        0, 0, cb.width, cb.height,
-                        cb.glFormat, cb.glType,
-                        bufferBits);
-                }
-            }
-        }
-
-        RETURN(Error3::NONE);
-    }
-
-    Error3 unlockImpl(void* raw) {
-        AEMU_SCOPED_TRACE("unlockImpl body");
-        if (!raw) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        cb_handle_30_t* cb = cb_handle_30_t::from(raw);
-        if (!cb) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        if (cb->lockedUsage == 0) {
-            RETURN_ERROR(Error3::BAD_VALUE);
-        }
-        if (!cb->bufferSize) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-        char* const bufferBits = static_cast<char*>(cb->getBufferPtr());
-        if (!bufferBits) {
-            RETURN_ERROR(Error3::BAD_BUFFER);
-        }
-
-        if (cb->hostHandle) {
-            unlockHostImpl(*cb, bufferBits);
-        }
-
-        cb->lockedLeft = 0;
-        cb->lockedTop = 0;
-        cb->lockedWidth = 0;
-        cb->lockedHeight = 0;
-        cb->lockedUsage = 0;
-
-        RETURN(Error3::NONE);
-    }
-
-    void unlockHostImpl(cb_handle_30_t& cb, char* const bufferBits) {
-        AEMU_SCOPED_TRACE("unlockHostImpl body");
-        if (cb.lockedUsage & BufferUsage::CPU_WRITE_MASK) {
-            const int bpp = glUtilsPixelBitSize(cb.glFormat, cb.glType) >> 3;
-            const uint32_t rgbSize = cb.width * cb.height * bpp;
-            const char* bitsToSend;
-            uint32_t sizeToSend;
-
-            if (gralloc_is_yuv_format(cb.format)) {
-                bitsToSend = bufferBits;
-                switch (static_cast<PixelFormat>(cb.format)) {
-                    case PixelFormat::YV12:
-                        get_yv12_offsets(cb.width, cb.height, nullptr, nullptr, &sizeToSend);
-                        break;
-                    case PixelFormat::YCBCR_420_888:
-                        get_yuv420p_offsets(cb.width, cb.height, nullptr, nullptr, &sizeToSend);
-                        break;
-                    default:
-                        CRASH("Unexpected format, switch is out of sync with gralloc_is_yuv_format");
-                        break;
-                }
-            } else {
-                bitsToSend = bufferBits;
-                sizeToSend = rgbSize;
-            }
-
-            {
-                const HostConnectionSession conn = getHostConnectionSession();
-                ExtendedRCEncoderContext *const rcEnc = conn.getRcEncoder();
-                {
-                    AEMU_SCOPED_TRACE("bindDmaDirectly");
-                    rcEnc->bindDmaDirectly(bufferBits,
-                            getMmapedPhysAddr(cb.getMmapedOffset()));
-                }
-                {
-                    AEMU_SCOPED_TRACE("updateColorBuffer");
-                    rcEnc->rcUpdateColorBufferDMA(rcEnc, cb.hostHandle,
-                            0, 0, cb.width, cb.height,
-                            cb.glFormat, cb.glType,
-                            const_cast<char*>(bitsToSend),
-                            sizeToSend);
-                }
-            }
-        }
-    }
-
-    /* BufferUsage bits that must be zero */
-    static constexpr uint64_t kReservedUsage =
-        (one64 << 10)
-        | (one64 << 13)
-        | (one64 << 19)
-        | (one64 << 21)
-        | ones(25, 27) /* bits 25-27 must be zero and are reserved for future versions */
-        | ones(32, 47); /* bits 32-47 must be zero and are reserved for future versions */
-
-    bool isSupportedImpl(const IMapper::BufferDescriptorInfo& descriptor) const {
-        if (!descriptor.width) { RETURN(false); }
-        if (!descriptor.height) { RETURN(false); }
-        if (descriptor.layerCount != 1) { RETURN(false); }
-
-        const uint64_t usage64 = descriptor.usage;
-        if (usage64 & kReservedUsage) {
-            RETURN(false);
-        }
-
-        const uint32_t usage = usage64;
-
-        switch (descriptor.format) {
-        case PixelFormat::RGBA_8888:
-        case PixelFormat::RGBX_8888:
-        case PixelFormat::BGRA_8888:
-        case PixelFormat::RGB_565:
-        case PixelFormat::RGBA_FP16:
-        case PixelFormat::RGBA_1010102:
-        case PixelFormat::YV12:
-        case PixelFormat::YCBCR_420_888:
-        case PixelFormat::YCBCR_P010:
-            RETURN(true);
-
-        case PixelFormat::IMPLEMENTATION_DEFINED:
-            RETURN(false);
-
-        case PixelFormat::RGB_888:
-        case PixelFormat::YCRCB_420_SP:
-        case PixelFormat::RAW16:
-        case PixelFormat::Y16:
-        case PixelFormat::BLOB:
-            RETURN(!needGpuBuffer(usage));
-
-        default:
-            if (static_cast<int>(descriptor.format) == kOMX_COLOR_FormatYUV420Planar) {
-                return (usage & BufferUsage::VIDEO_DECODER) != 0;
-            }
-
-            RETURN(false);
-        }
-    }
-
-    Error3 validateBufferSizeImpl(const cb_handle_t& /*cb*/,
-                                  const BufferDescriptorInfo& /*descriptor*/,
-                                  uint32_t /*stride*/) {
-        RETURN(Error3::NONE);
-    }
-
-    HostConnectionSession getHostConnectionSession() const {
-        return HostConnectionSession(m_hostConn.get());
-    }
-
-    static void encodeBufferDescriptorInfo(const BufferDescriptorInfo& d,
-                                           hidl_vec<uint32_t>* raw) {
-        raw->resize(5);
-
-        (*raw)[0] = d.width;
-        (*raw)[1] = d.height;
-        (*raw)[2] = d.layerCount;
-        (*raw)[3] = static_cast<uint32_t>(d.format);
-        (*raw)[4] = d.usage & UINT32_MAX;
-    }
-
-    uint64_t getMmapedPhysAddr(uint64_t offset) const {
-        return m_physAddrToOffset + offset;
-    }
-
-    std::unique_ptr<HostConnection> m_hostConn;
-    uint64_t m_physAddrToOffset;
-};
-}  // namespace
-
-extern "C" IMapper3* HIDL_FETCH_IMapper(const char* /*name*/) {
-    return new GoldfishMapper;
-}
diff --git a/system/hals/types.h b/system/hals/types.h
deleted file mode 100644
index c7d26467..00000000
--- a/system/hals/types.h
+++ /dev/null
@@ -1,43 +0,0 @@
-/*
-* Copyright (C) 2020 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-* http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#ifndef GOLDFISH_OPENGL_SYSTEM_HALS_TYPES_H_INCLUDED
-#define GOLDFISH_OPENGL_SYSTEM_HALS_TYPES_H_INCLUDED
-
-/* Tell the emulator which formats need special handling. */
-enum class EmulatorFrameworkFormat {
-    GL_COMPATIBLE = 0,
-    YV12 = 1,
-    YUV_420_888 = 2, // (Y+)(U+)(V+)
-};
-
-#ifndef GL_RGBA16F
-#define GL_RGBA16F                        0x881A
-#endif // GL_RGBA16F
-
-#ifndef GL_HALF_FLOAT
-#define GL_HALF_FLOAT                     0x140B
-#endif // GL_HALF_FLOAT
-
-#ifndef GL_RGB10_A2
-#define GL_RGB10_A2                       0x8059
-#endif // GL_RGB10_A2
-
-#ifndef GL_UNSIGNED_INT_2_10_10_10_REV
-#define GL_UNSIGNED_INT_2_10_10_10_REV    0x8368
-#endif // GL_UNSIGNED_INT_2_10_10_10_REV
-
-#endif  // GOLDFISH_OPENGL_SYSTEM_HALS_TYPES_H_INCLUDED
diff --git a/system/hwc3/Android.bp b/system/hwc3/Android.bp
index 0662c6a7..9e0a1ab7 100644
--- a/system/hwc3/Android.bp
+++ b/system/hwc3/Android.bp
@@ -56,6 +56,7 @@ cc_binary {
 
     header_libs: [
         "libminigbm_gralloc_headers",
+        "mesa_gfxstream_guest_android_headers",
     ],
 
     srcs: [
@@ -137,6 +138,5 @@ genrule {
     name: "gen-hwc3-apex.rc",
     srcs: ["hwc3.rc"],
     out: ["hwc3-apex.rc"],
-    cmd: "sed -e 's@/vendor/bin/@/apex/com.android.hardware.graphics.composer.ranchu/bin/@' $(in) > $(out)",
+    cmd: "sed -e 's@/vendor/bin/@/apex/com.android.hardware.graphics.composer/bin/@' $(in) > $(out)",
 }
-
diff --git a/system/hwc3/Common.cpp b/system/hwc3/Common.cpp
index 7ee26572..4e0a1180 100644
--- a/system/hwc3/Common.cpp
+++ b/system/hwc3/Common.cpp
@@ -23,7 +23,8 @@ namespace aidl::android::hardware::graphics::composer3::impl {
 bool IsAutoDevice() {
     // gcar_emu_x86_64, sdk_car_md_x86_64, cf_x86_64_auto, cf_x86_64_only_auto_md
     const std::string product_name = ::android::base::GetProperty("ro.product.name", "");
-    return product_name.find("car_") || product_name.find("_auto");
+    return product_name.find("car_") != std::string::npos ||
+        product_name.find("_auto") != std::string::npos;
 }
 
 bool IsCuttlefish() { return ::android::base::GetProperty("ro.product.board", "") == "cutf"; }
diff --git a/system/hwc3/ComposerClient.cpp b/system/hwc3/ComposerClient.cpp
index 0fdcd195..2ae24998 100644
--- a/system/hwc3/ComposerClient.cpp
+++ b/system/hwc3/ComposerClient.cpp
@@ -23,6 +23,7 @@
 #include "Device.h"
 #include "GuestFrameComposer.h"
 #include "HostFrameComposer.h"
+#include "Time.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 namespace {
@@ -790,6 +791,8 @@ void ComposerClient::executeLayerCommand(CommandResultWriter& commandResults, Di
                            PerFrameMetadata);
     DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, perFrameMetadataBlob,
                            PerFrameMetadataBlobs);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, luts,
+                           Luts);
 }
 
 void ComposerClient::executeDisplayCommandSetColorTransform(CommandResultWriter& commandResults,
@@ -1193,6 +1196,13 @@ void ComposerClient::executeLayerCommandSetLayerPerFrameMetadataBlobs(
     }
 }
 
+void ComposerClient::executeLayerCommandSetLayerLuts(CommandResultWriter& /*commandResults*/,
+                                                     Display& /*display*/, Layer* /*layer*/,
+                                                     const std::vector<std::optional<Lut>>& /*luts*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+    //TODO(b/358188835)
+}
+
 std::shared_ptr<Display> ComposerClient::getDisplay(int64_t displayId) {
     std::lock_guard<std::mutex> lock(mDisplaysMutex);
 
@@ -1317,7 +1327,7 @@ HWC3::Error ComposerClient::destroyDisplayLocked(int64_t displayId) {
 
 HWC3::Error ComposerClient::handleHotplug(bool connected, uint32_t id, uint32_t width,
                                           uint32_t height, uint32_t dpiX, uint32_t dpiY,
-                                          uint32_t refreshRate) {
+                                          uint32_t refreshRateHz) {
     if (!mCallbacks) {
         return HWC3::Error::None;
     }
@@ -1326,9 +1336,10 @@ HWC3::Error ComposerClient::handleHotplug(bool connected, uint32_t id, uint32_t
 
     if (connected) {
         const int32_t configId = static_cast<int32_t>(id);
-        const std::vector<DisplayConfig> configs = {DisplayConfig(
-            configId, static_cast<int>(width), static_cast<int>(height), static_cast<int>(dpiX),
-            static_cast<int>(dpiY), static_cast<int>(refreshRate))};
+        int32_t vsyncPeriodNanos = HertzToPeriodNanos(refreshRateHz);
+        const std::vector<DisplayConfig> configs = {
+            DisplayConfig(configId, static_cast<int>(width), static_cast<int>(height),
+                          static_cast<int>(dpiX), static_cast<int>(dpiY), vsyncPeriodNanos)};
         {
             std::lock_guard<std::mutex> lock(mDisplaysMutex);
             createDisplayLocked(displayId, configId, configs);
@@ -1336,7 +1347,7 @@ HWC3::Error ComposerClient::handleHotplug(bool connected, uint32_t id, uint32_t
 
         ALOGI("Hotplug connecting display:%" PRIu32 " w:%" PRIu32 " h:%" PRIu32 " dpiX:%" PRIu32
               " dpiY %" PRIu32 "fps %" PRIu32,
-              id, width, height, dpiX, dpiY, refreshRate);
+              id, width, height, dpiX, dpiY, refreshRateHz);
         mCallbacks->onHotplug(displayId, /*connected=*/true);
     } else {
         ALOGI("Hotplug disconnecting display:%" PRIu64, displayId);
diff --git a/system/hwc3/ComposerClient.h b/system/hwc3/ComposerClient.h
index 2cf198f6..3cf10685 100644
--- a/system/hwc3/ComposerClient.h
+++ b/system/hwc3/ComposerClient.h
@@ -18,6 +18,7 @@
 #define ANDROID_HWC_COMPOSERCLIENT_H
 
 #include <aidl/android/hardware/graphics/composer3/BnComposerClient.h>
+#include <aidl/android/hardware/graphics/composer3/Lut.h>
 #include <android-base/thread_annotations.h>
 
 #include <memory>
@@ -202,6 +203,9 @@ class ComposerClient : public BnComposerClient {
     void executeLayerCommandSetLayerPerFrameMetadataBlobs(
         CommandResultWriter& commandResults, Display& display, Layer* layer,
         const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadataBlob);
+    void executeLayerCommandSetLayerLuts(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const std::vector<std::optional<Lut>>& luts);
 
     // Returns the display with the given id or nullptr if not found.
     std::shared_ptr<Display> getDisplay(int64_t displayId);
diff --git a/system/hwc3/Display.cpp b/system/hwc3/Display.cpp
index fa98015e..17963ddb 100644
--- a/system/hwc3/Display.cpp
+++ b/system/hwc3/Display.cpp
@@ -141,7 +141,25 @@ HWC3::Error Display::updateParameters(uint32_t width, uint32_t height, uint32_t
         return HWC3::Error::NoResources;
     }
     DisplayConfig& config = it->second;
-    config.setAttribute(DisplayAttribute::VSYNC_PERIOD, HertzToPeriodNanos(refreshRateHz));
+    int32_t oldVsyncPeriod = config.getAttribute(DisplayAttribute::VSYNC_PERIOD);
+    int32_t newVsyncPeriod = HertzToPeriodNanos(refreshRateHz);
+    if (oldVsyncPeriod != newVsyncPeriod) {
+        config.setAttribute(DisplayAttribute::VSYNC_PERIOD, newVsyncPeriod);
+
+        // Schedule a vsync update to propagate across system.
+        VsyncPeriodChangeConstraints constraints;
+        constraints.desiredTimeNanos = 0;
+
+        VsyncPeriodChangeTimeline timeline;
+
+        HWC3::Error error =
+            mVsyncThread.scheduleVsyncUpdate(newVsyncPeriod, constraints, &timeline);
+        if (error != HWC3::Error::None) {
+            ALOGE("%s: display:%" PRId64 " composer failed to schedule vsync update", __FUNCTION__,
+                  mId);
+            return error;
+        }
+    }
     config.setAttribute(DisplayAttribute::WIDTH, static_cast<int32_t>(width));
     config.setAttribute(DisplayAttribute::HEIGHT, static_cast<int32_t>(height));
     config.setAttribute(DisplayAttribute::DPI_X, static_cast<int32_t>(dpiX));
@@ -288,16 +306,7 @@ HWC3::Error Display::getDisplayConfigurations(std::vector<DisplayConfiguration>*
 }
 
 HWC3::Error Display::getDisplayConnectionType(DisplayConnectionType* outType) {
-    if (IsCuttlefishFoldable() || IsAutoDevice()) {
-        // Android Auto OS needs to set all displays to INTERNAL since they're used
-        // for the passenger displays.
-        // Workaround to force all displays to INTERNAL for cf_x86_64_foldable.
-        // TODO(b/193568008): Allow configuring internal/external per display.
-        *outType = DisplayConnectionType::INTERNAL;
-    } else {
-        // Other devices default to the first display INTERNAL, others EXTERNAL.
-        *outType = mId == 0 ? DisplayConnectionType::INTERNAL : DisplayConnectionType::EXTERNAL;
-    }
+    *outType = DisplayConnectionType::INTERNAL;
     return HWC3::Error::None;
 }
 
diff --git a/system/hwc3/HostFrameComposer.cpp b/system/hwc3/HostFrameComposer.cpp
index 018df722..d14d812c 100644
--- a/system/hwc3/HostFrameComposer.cpp
+++ b/system/hwc3/HostFrameComposer.cpp
@@ -30,7 +30,7 @@
 #include <optional>
 #include <tuple>
 
-#include "../egl/goldfish_sync.h"
+#include "gfxstream/guest/goldfish_sync.h"
 #include "Display.h"
 #include "HostUtils.h"
 #include "virtgpu_drm.h"
diff --git a/system/hwc3/HostUtils.cpp b/system/hwc3/HostUtils.cpp
index 21ec83ce..0ed178fb 100644
--- a/system/hwc3/HostUtils.cpp
+++ b/system/hwc3/HostUtils.cpp
@@ -24,7 +24,7 @@ HostConnection* createOrGetHostConnection() {
     static std::unique_ptr<HostConnection> sHostCon;
 
     if (!sHostCon) {
-        sHostCon = HostConnection::createUnique();
+        sHostCon = HostConnection::createUnique(kCapsetNone);
     }
     return sHostCon.get();
 }
diff --git a/system/hwc3/apex_manifest.json b/system/hwc3/apex_manifest.json
index 4fb19ee1..fa9e626b 100644
--- a/system/hwc3/apex_manifest.json
+++ b/system/hwc3/apex_manifest.json
@@ -1,5 +1,5 @@
 {
-    "name": "com.android.hardware.graphics.composer.ranchu",
+    "name": "com.android.hardware.graphics.composer",
     "version": 1,
     "vendorBootstrap": true
 }
\ No newline at end of file
diff --git a/system/hwc3/hwc3.xml b/system/hwc3/hwc3.xml
index 7f0d8b7a..4c4fb95e 100644
--- a/system/hwc3/hwc3.xml
+++ b/system/hwc3/hwc3.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.graphics.composer3</name>
-        <version>3</version>
+        <version>4</version>
         <interface>
             <name>IComposer</name>
             <instance>default</instance>
```

