```diff
diff --git a/Android.bp b/Android.bp
index 3de3900..4879044 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,8 +1,47 @@
 soong_namespace {
-    imports: ["hardware/google/gchips"]
+    imports: ["hardware/google/gchips"],
 }
 
 package {
     // See: http://go/android-license-faq
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
+
+cc_defaults {
+    name: "google_graphics_cc_default",
+
+    proprietary: true,
+    cflags: [
+        "-DUSES_GSCALER",
+    ] + select(soong_config_variable("google_graphics", "hwc_no_support_skip_validate"), {
+        true: ["-DHWC_NO_SUPPORT_SKIP_VALIDATE"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "hwc_support_color_transform"), {
+        true: ["-DHWC_SUPPORT_COLOR_TRANSFORM"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "hwc_support_render_intent"), {
+        true: ["-DHWC_SUPPORT_RENDER_INTENT"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "board_uses_virtual_display"), {
+        true: ["-DUSES_VIRTUAL_DISPLAY"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "board_uses_dt"), {
+        true: ["-DUSES_DT"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "board_uses_decon_64bit_address"), {
+        true: ["-DUSES_DECON_64BIT_ADDRESS"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "board_uses_hdrui_gles_conversion"), {
+        true: ["-DUSES_HDR_GLES_CONVERSION"],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "uses_idisplay_intf_sec"), {
+        true: ["-DUSES_IDISPLAY_INTF_SEC"],
+        default: [],
+    }),
+
+    arch: {
+        arm64: {
+            cflags: ["-DUSES_ARCH_ARM64"],
+        },
+    },
+}
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index c8dbf77..8aa2201 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,5 +1,6 @@
 [Builtin Hooks]
 clang_format = true
+bpfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
diff --git a/gralloc-headers/pixel-gralloc/format.h b/gralloc-headers/pixel-gralloc/format.h
index 46b2c45..5d5d898 100644
--- a/gralloc-headers/pixel-gralloc/format.h
+++ b/gralloc-headers/pixel-gralloc/format.h
@@ -47,12 +47,20 @@ enum class Format : uint32_t {
 
     // Pixel specific formats
     GOOGLE_NV12 = 0x301,
+    GOOGLE_RGBX16 = 0x302,
     GOOGLE_R8 = 0x303,
     /**
      * 48-bit format that has 16-bit R, G, B components, in that order,
      * from the lowest memory address to the highest memory address.
      */
     GOOGLE_RGB16 = 0x304,
+    GOOGLE_BGRX = 0x305,
+
+    /**
+     * 2 plane format following [x:Y2:Y1:Y0], [x:Cr2:Cb2:Cr1 x:Cb1:Cr0:Cb0]
+     * With each Y, Cr and Cb being 10 bits, and x representing 2 bits padding
+     */
+    GOOGLE_YCBCR_P030 = 0x306,
 };
 
 #undef MapFormat
diff --git a/gralloc-headers/pixel-gralloc/mapper4.h b/gralloc-headers/pixel-gralloc/mapper4.h
index 8ea0193..f560193 100644
--- a/gralloc-headers/pixel-gralloc/mapper4.h
+++ b/gralloc-headers/pixel-gralloc/mapper4.h
@@ -4,7 +4,7 @@
 #include <log/log.h>
 
 #include "metadata.h"
-#include "utils.h"
+#include "utils-internal.h"
 
 namespace pixel::graphics::mapper {
 
diff --git a/gralloc-headers/pixel-gralloc/mapper5.h b/gralloc-headers/pixel-gralloc/mapper5.h
index 07bc2ba..da8ed02 100644
--- a/gralloc-headers/pixel-gralloc/mapper5.h
+++ b/gralloc-headers/pixel-gralloc/mapper5.h
@@ -9,7 +9,7 @@
 #include <vndksupport/linker.h>
 
 #include "metadata.h"
-#include "utils.h"
+#include "utils-internal.h"
 
 namespace pixel::graphics::mapper {
 
diff --git a/gralloc-headers/pixel-gralloc/utils.h b/gralloc-headers/pixel-gralloc/utils-internal.h
similarity index 58%
rename from gralloc-headers/pixel-gralloc/utils.h
rename to gralloc-headers/pixel-gralloc/utils-internal.h
index e20a226..4918d63 100644
--- a/gralloc-headers/pixel-gralloc/utils.h
+++ b/gralloc-headers/pixel-gralloc/utils-internal.h
@@ -1,8 +1,5 @@
 #pragma once
 
-#include <pixel-gralloc/format.h>
-#include <pixel-gralloc/usage.h>
-
 #include <cstdint>
 #include <cstring>
 #include <optional>
@@ -89,69 +86,4 @@ std::optional<T> decode(const std::vector<uint8_t>& bytes) {
     return decode_helper<T>(bytes);
 }
 
-enum class Compression {
-    UNCOMPRESSED,
-};
-
-inline Usage get_usage_from_compression(Compression compression) {
-    switch (compression) {
-        case Compression::UNCOMPRESSED:
-            return static_cast<Usage>(Usage::CPU_READ_OFTEN | Usage::CPU_WRITE_OFTEN |
-                                      Usage::GPU_TEXTURE | Usage::GPU_RENDER_TARGET |
-                                      Usage::COMPOSER_OVERLAY);
-    }
-}
-
-#define FormatCase(f) \
-    case Format::f:   \
-        return #f
-
-inline std::string get_string_from_format(Format format) {
-    switch (format) {
-        FormatCase(UNSPECIFIED);
-        FormatCase(RGBA_8888);
-        FormatCase(RGBX_8888);
-        FormatCase(RGB_888);
-        FormatCase(RGB_565);
-        FormatCase(BGRA_8888);
-        FormatCase(YCBCR_422_SP);
-        FormatCase(YCRCB_420_SP);
-        FormatCase(YCBCR_422_I);
-        FormatCase(RGBA_FP16);
-        FormatCase(RAW16);
-        FormatCase(BLOB);
-        FormatCase(IMPLEMENTATION_DEFINED);
-        FormatCase(YCBCR_420_888);
-        FormatCase(RAW_OPAQUE);
-        FormatCase(RAW10);
-        FormatCase(RAW12);
-        FormatCase(RGBA_1010102);
-        FormatCase(Y8);
-        FormatCase(Y16);
-        FormatCase(YV12);
-        FormatCase(DEPTH_16);
-        FormatCase(DEPTH_24);
-        FormatCase(DEPTH_24_STENCIL_8);
-        FormatCase(DEPTH_32F);
-        FormatCase(DEPTH_32F_STENCIL_8);
-        FormatCase(STENCIL_8);
-        FormatCase(YCBCR_P010);
-        FormatCase(HSV_888);
-        FormatCase(R_8);
-        FormatCase(R_16_UINT);
-        FormatCase(RG_1616_UINT);
-        FormatCase(RGBA_10101010);
-
-        // Pixel specific formats
-        FormatCase(GOOGLE_NV12);
-        FormatCase(GOOGLE_R8);
-
-        // Unknown formats
-        default:
-            return "Unknown";
-    }
-}
-
-#undef FormatCase
-
 } // namespace pixel::graphics::utils
diff --git a/gralloc-utils/Android.bp b/gralloc-utils/Android.bp
new file mode 100644
index 0000000..f355dcb
--- /dev/null
+++ b/gralloc-utils/Android.bp
@@ -0,0 +1,21 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_static {
+    name: "pixel-gralloc-utils",
+    vendor_available: true,
+    shared_libs: [
+        "libui",
+    ],
+    header_libs: [
+        "pixel-gralloc-headers",
+    ],
+    export_header_lib_headers: [
+        "pixel-gralloc-headers",
+    ],
+    export_include_dirs: ["include"],
+    srcs: [
+        "utils.cpp",
+    ],
+}
diff --git a/gralloc-utils/OWNERS b/gralloc-utils/OWNERS
new file mode 100644
index 0000000..0b8b903
--- /dev/null
+++ b/gralloc-utils/OWNERS
@@ -0,0 +1,3 @@
+jessehall@google.com
+layog@google.com
+spyffe@google.com
diff --git a/gralloc-utils/include/pixel-gralloc/utils.h b/gralloc-utils/include/pixel-gralloc/utils.h
new file mode 100644
index 0000000..aeca209
--- /dev/null
+++ b/gralloc-utils/include/pixel-gralloc/utils.h
@@ -0,0 +1,82 @@
+#pragma once
+
+#include <aidl/android/hardware/graphics/common/PlaneLayout.h>
+#include <pixel-gralloc/format.h>
+#include <pixel-gralloc/usage.h>
+#include <cstdint>
+#include <optional>
+#include <vector>
+
+using FrameworkPlaneLayout = aidl::android::hardware::graphics::common::PlaneLayout;
+
+namespace pixel::graphics::utils {
+
+std::optional<std::vector<FrameworkPlaneLayout>> get_plane_layouts(FrameworkFormat format,
+                                                                   uint64_t usage, uint32_t width,
+                                                                   uint32_t height);
+
+enum class Compression {
+    UNCOMPRESSED,
+};
+
+inline Usage get_usage_from_compression(Compression compression) {
+    switch (compression) {
+        case Compression::UNCOMPRESSED:
+            return static_cast<Usage>(Usage::CPU_READ_OFTEN | Usage::CPU_WRITE_OFTEN |
+                                      Usage::GPU_TEXTURE | Usage::GPU_RENDER_TARGET |
+                                      Usage::COMPOSER_OVERLAY);
+    }
+}
+
+#define FormatCase(f) \
+    case Format::f:   \
+        return #f
+
+inline std::string get_string_from_format(Format format) {
+    switch (format) {
+        FormatCase(UNSPECIFIED);
+        FormatCase(RGBA_8888);
+        FormatCase(RGBX_8888);
+        FormatCase(RGB_888);
+        FormatCase(RGB_565);
+        FormatCase(BGRA_8888);
+        FormatCase(YCBCR_422_SP);
+        FormatCase(YCRCB_420_SP);
+        FormatCase(YCBCR_422_I);
+        FormatCase(RGBA_FP16);
+        FormatCase(RAW16);
+        FormatCase(BLOB);
+        FormatCase(IMPLEMENTATION_DEFINED);
+        FormatCase(YCBCR_420_888);
+        FormatCase(RAW_OPAQUE);
+        FormatCase(RAW10);
+        FormatCase(RAW12);
+        FormatCase(RGBA_1010102);
+        FormatCase(Y8);
+        FormatCase(Y16);
+        FormatCase(YV12);
+        FormatCase(DEPTH_16);
+        FormatCase(DEPTH_24);
+        FormatCase(DEPTH_24_STENCIL_8);
+        FormatCase(DEPTH_32F);
+        FormatCase(DEPTH_32F_STENCIL_8);
+        FormatCase(STENCIL_8);
+        FormatCase(YCBCR_P010);
+        FormatCase(HSV_888);
+        FormatCase(R_8);
+        FormatCase(R_16_UINT);
+        FormatCase(RG_1616_UINT);
+        FormatCase(RGBA_10101010);
+
+        // Pixel specific formats
+        FormatCase(GOOGLE_NV12);
+        FormatCase(GOOGLE_R8);
+
+        // Unknown formats
+        default:
+            return "Unknown";
+    }
+}
+
+#undef FormatCase
+} // namespace pixel::graphics::utils
diff --git a/gralloc-utils/utils.cpp b/gralloc-utils/utils.cpp
new file mode 100644
index 0000000..ddf6ee7
--- /dev/null
+++ b/gralloc-utils/utils.cpp
@@ -0,0 +1,33 @@
+#include "pixel-gralloc/utils.h"
+#include <log/log.h>
+#include <ui/GraphicBuffer.h>
+#include <ui/GraphicBufferMapper.h>
+
+using android::GraphicBuffer;
+using android::sp;
+
+namespace pixel::graphics::utils {
+
+std::optional<std::vector<FrameworkPlaneLayout>> get_plane_layouts(FrameworkFormat format,
+                                                                   uint64_t usage, uint32_t width,
+                                                                   uint32_t height) {
+    auto& mapper = android::GraphicBufferMapper::getInstance();
+
+    usage = usage | Usage::PLACEHOLDER_BUFFER;
+    auto f = static_cast<android::PixelFormat>(format);
+    auto buffer = sp<GraphicBuffer>::make(width, height, f, /*layerCount=*/1, usage);
+    if (!buffer) {
+        ALOGE("Failed to allocate buffer");
+        return std::nullopt;
+    }
+
+    std::vector<FrameworkPlaneLayout> plane_layouts;
+    auto error = mapper.getPlaneLayouts(buffer->handle, &plane_layouts);
+    if (error != android::OK) {
+        ALOGE("Failed to get plane layouts");
+        return std::nullopt;
+    }
+
+    return plane_layouts;
+}
+} // namespace pixel::graphics::utils
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
index 73b53f0..a4868fd 100644
--- a/hwc3/ComposerClient.cpp
+++ b/hwc3/ComposerClient.cpp
@@ -92,6 +92,20 @@ ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
     return TO_BINDER_STATUS(err);
 }
 
+ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t display,
+                                                              int32_t* outMaxProfiles) {
+    DEBUG_DISPLAY_FUNC(display);
+    auto err = mHal->getMaxLayerPictureProfiles(display, outMaxProfiles);
+    return TO_BINDER_STATUS(err);
+}
+
+ndk::ScopedAStatus ComposerClient::getLuts(int64_t display, const std::vector<Buffer>& /*buffers*/,
+                                           std::vector<Luts>* /*luts*/) {
+    DEBUG_DISPLAY_FUNC(display);
+    LOG(ERROR) << "not implemented";
+    return ndk::ScopedAStatus::fromStatus(EX_UNSUPPORTED_OPERATION);
+}
+
 ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display, int64_t layer) {
     DEBUG_DISPLAY_FUNC(display);
     auto err = mHal->destroyLayer(display, layer);
@@ -456,6 +470,13 @@ ndk::ScopedAStatus ComposerClient::setRefreshRateChangedCallbackDebugEnabled(int
     return TO_BINDER_STATUS(err);
 }
 
+ndk::ScopedAStatus ComposerClient::startHdcpNegotiation(int64_t display,
+                                                        const drm::HdcpLevels& /*levels*/) {
+    DEBUG_DISPLAY_FUNC(display);
+    LOG(ERROR) << "not implemented";
+    return ndk::ScopedAStatus::fromStatus(EX_UNSUPPORTED_OPERATION);
+}
+
 void ComposerClient::HalEventCallback::onRefreshRateChangedDebug(
         const RefreshRateChangedDebugData& data) {
     DEBUG_DISPLAY_FUNC(data.display);
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
index b07bdc8..7ffe33e 100644
--- a/hwc3/ComposerClient.h
+++ b/hwc3/ComposerClient.h
@@ -143,6 +143,12 @@ public:
     ndk::ScopedAStatus notifyExpectedPresent(int64_t display,
                                              const ClockMonotonicTimestamp& expectedPresentTime,
                                              int32_t frameIntervalNs) override;
+    ndk::ScopedAStatus getMaxLayerPictureProfiles(int64_t display,
+                                                  int32_t* outMaxProfiles) override;
+    ndk::ScopedAStatus startHdcpNegotiation(int64_t display,
+                                            const drm::HdcpLevels& levels) override;
+    ndk::ScopedAStatus getLuts(int64_t display, const std::vector<Buffer>&,
+                               std::vector<Luts>*) override;
 
 protected:
     ::ndk::SpAIBinder createBinder() override;
diff --git a/hwc3/impl/HalImpl.cpp b/hwc3/impl/HalImpl.cpp
index 77a27a2..22bffd8 100644
--- a/hwc3/impl/HalImpl.cpp
+++ b/hwc3/impl/HalImpl.cpp
@@ -1321,4 +1321,9 @@ int32_t HalImpl::setRefreshRateChangedCallbackDebugEnabled(int64_t display, bool
     return halDisplay->setRefreshRateChangedCallbackDebugEnabled(enabled);
 }
 
+int32_t HalImpl::getMaxLayerPictureProfiles([[maybe_unused]] int64_t display,
+                                            [[maybe_unused]] int32_t* outMaxProfiles) {
+    return HWC2_ERROR_UNSUPPORTED;
+}
+
 } // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/impl/HalImpl.h b/hwc3/impl/HalImpl.h
index c037291..9453c3c 100644
--- a/hwc3/impl/HalImpl.h
+++ b/hwc3/impl/HalImpl.h
@@ -186,6 +186,7 @@ class HalImpl : public IComposerHal {
       int32_t setRefreshRateChangedCallbackDebugEnabled(int64_t display, bool enabled) override;
       int32_t layerSf2Hwc(int64_t display, int64_t layer, hwc2_layer_t& outMappedLayer) override;
       void setHwcBatchingSupport(bool supported);
+      int32_t getMaxLayerPictureProfiles(int64_t display, int32_t* outMaxProfiles) override;
 
   private:
       void initCaps(bool batchingSupported);
diff --git a/hwc3/include/IComposerHal.h b/hwc3/include/IComposerHal.h
index 71fa2ad..8cb3832 100644
--- a/hwc3/include/IComposerHal.h
+++ b/hwc3/include/IComposerHal.h
@@ -253,6 +253,7 @@ class IComposerHal {
             const std::vector<std::optional<common::Rect>>& blockingRegion) = 0;
     virtual int32_t setRefreshRateChangedCallbackDebugEnabled(int64_t display, bool enabled) = 0;
     virtual int32_t layerSf2Hwc(int64_t display, int64_t layer, hwc2_layer_t& outMappedLayer) = 0;
+    virtual int32_t getMaxLayerPictureProfiles(int64_t display, int32_t* outMaxProfiles) = 0;
 };
 
 } // namespace aidl::android::hardware::graphics::composer3::detail
diff --git a/include/displaycolor/displaycolor.h b/include/displaycolor/displaycolor.h
index 984515c..9fc7b9e 100644
--- a/include/displaycolor/displaycolor.h
+++ b/include/displaycolor/displaycolor.h
@@ -23,7 +23,9 @@
 #include <functional>
 #include <memory>
 #include <optional>
+#include <sstream>
 #include <string>
+#include <vector>
 
 namespace displaycolor {
 
@@ -366,7 +368,8 @@ struct LtmParams {
     Roi roi;
     // for debug purpose
     bool force_enable{};
-    bool operator==(const LtmParams &rhs) const {
+    bool sr_in_gtm{true};
+    bool ConfigUpdateNeeded(const LtmParams &rhs) const {
         return display == rhs.display && roi == rhs.roi && force_enable == rhs.force_enable;
     }
 };
@@ -425,6 +428,9 @@ struct DisplayScene {
     /// dbv level
     uint32_t dbv = 0;
 
+    /// the nits value corresponding to the dbv above
+    float nits = 0;
+
     /// lhbm status
     bool lhbm_on = false;
 
@@ -611,6 +617,21 @@ class IDisplayColorGeneric {
     //deprecated by the 'int64_t display' version
     virtual bool IsEarlyPowerOnNeeded(const DisplayType display) = 0;
     virtual bool IsEarlyPowerOnNeeded(const int64_t display) = 0;
+
+    /**
+     * @brief a debug call from command line with arguments, output will show on screen.
+     * @param display id
+     * @param cur_obj for the current object
+     * @param obj_sel a path (object names concatenated by dots) to locate the target object
+     * @param action to apply to the target object
+     * @param args the arguments for the action
+     * @return string to show on screen
+     */
+    virtual std::string Debug(const int64_t display,
+                              const std::string& cur_obj,
+                              const std::string& obj_sel,
+                              const std::string& action,
+                              const std::vector<std::string>& args) = 0;
 };
 
 extern "C" {
diff --git a/libacryl/Android.bp b/libacryl/Android.bp
index bb547f8..765fd07 100644
--- a/libacryl/Android.bp
+++ b/libacryl/Android.bp
@@ -1,11 +1,124 @@
+// Copyright (C) 2016 The Android Open Source Project
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
 package {
     // See: http://go/android-license-faq
-    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_applicable_licenses: [
+        "hardware_google_graphics_common_libacryl_license",
+    ],
+}
+
+license {
+    name: "hardware_google_graphics_common_libacryl_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
 }
 
 cc_library_headers {
     name: "google_libacryl_hdrplugin_headers",
     proprietary: true,
     local_include_dirs: ["local_include"],
-    export_include_dirs: ["hdrplugin_headers", "local_include"],
+    export_include_dirs: [
+        "hdrplugin_headers",
+        "local_include",
+    ],
+}
+
+// include_dirs is not selectable right now, change to select statement after it is supported.
+soong_config_module_type {
+    name: "libacryl_acryl_cc_defaults",
+    module_type: "cc_defaults",
+    config_namespace: "acryl",
+    value_variables: [
+        "libacryl_c_include",
+    ],
+    properties: [
+        "include_dirs",
+    ],
+}
+
+libacryl_acryl_cc_defaults {
+    name: "libacryl_include_dirs_cc_defaults",
+    soong_config_variables: {
+        libacryl_c_include: {
+            include_dirs: ["%s"],
+        },
+    },
+}
+
+cc_library_shared {
+    name: "libacryl",
+
+    cflags: [
+        "-DLOG_TAG=\"hwc-libacryl\"",
+        "-Wthread-safety",
+    ] + select(soong_config_variable("acryl", "libacryl_use_g2d_hdr_plugin"), {
+        true: ["-DLIBACRYL_G2D_HDR_PLUGIN"],
+        default: [],
+    }) + select(soong_config_variable("acryl", "libacryl_default_compositor"), {
+        any @ flag_val: ["-DLIBACRYL_DEFAULT_COMPOSITOR=\"" + flag_val + "\""],
+        default: ["-DLIBACRYL_DEFAULT_COMPOSITOR=\"no_default_compositor\""],
+    }) + select(soong_config_variable("acryl", "libacryl_default_scaler"), {
+        any @ flag_val: ["-DLIBACRYL_DEFAULT_SCALER=\"" + flag_val + "\""],
+        default: ["-DLIBACRYL_DEFAULT_SCALER=\"no_default_scaler\""],
+    }) + select(soong_config_variable("acryl", "libacryl_default_blter"), {
+        any @ flag_val: ["-DLIBACRYL_DEFAULT_BLTER=\"" + flag_val + "\""],
+        default: ["-DLIBACRYL_DEFAULT_BLTER=\"no_default_blter\""],
+    }),
+
+    shared_libs: [
+        "libcutils",
+        "libion_google",
+        "liblog",
+        "libutils",
+    ] + select(soong_config_variable("acryl", "libacryl_g2d_hdr_plugin"), {
+        any @ flag_val: [flag_val],
+        default: [],
+    }),
+
+    header_libs: [
+        "google_libacryl_hdrplugin_headers",
+        "google_hal_headers",
+        "//hardware/google/gchips/gralloc4/src:libgralloc_headers",
+    ],
+
+    local_include_dirs: [
+        "include",
+        "local_include",
+    ],
+
+    export_include_dirs: ["include"],
+
+    srcs: [
+        "acrylic.cpp",
+        "acrylic_device.cpp",
+        "acrylic_factory.cpp",
+        "acrylic_formats.cpp",
+        "acrylic_g2d.cpp",
+        "acrylic_layer.cpp",
+        "acrylic_performance.cpp",
+    ],
+
+    proprietary: true,
+
+    defaults: [
+        "android.hardware.graphics.common-ndk_shared",
+        "libacryl_include_dirs_cc_defaults",
+    ],
 }
diff --git a/libacryl/Android.mk b/libacryl/Android.mk
deleted file mode 100644
index 43471e3..0000000
--- a/libacryl/Android.mk
+++ /dev/null
@@ -1,82 +0,0 @@
-# Copyright (C) 2016 The Android Open Source Project
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
-LOCAL_CFLAGS += -DLOG_TAG=\"hwc-libacryl\"
-LOCAL_CFLAGS += -Wthread-safety
-#LOCAL_CFLAGS += -DLIBACRYL_DEBUG
-
-ifdef BOARD_LIBACRYL_DEFAULT_COMPOSITOR
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_COMPOSITOR=\"$(BOARD_LIBACRYL_DEFAULT_COMPOSITOR)\"
-else
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_COMPOSITOR=\"no_default_compositor\"
-endif
-ifdef BOARD_LIBACRYL_DEFAULT_SCALER
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_SCALER=\"$(BOARD_LIBACRYL_DEFAULT_SCALER)\"
-else
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_SCALER=\"no_default_scaler\"
-endif
-ifdef BOARD_LIBACRYL_DEFAULT_BLTER
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_BLTER=\"$(BOARD_LIBACRYL_DEFAULT_BLTER)\"
-else
-    LOCAL_CFLAGS += -DLIBACRYL_DEFAULT_BLTER=\"no_default_blter\"
-endif
-
-LOCAL_SHARED_LIBRARIES := liblog libutils libcutils libion_google android.hardware.graphics.common-V3-ndk
-ifdef BOARD_LIBACRYL_G2D_HDR_PLUGIN
-    LOCAL_SHARED_LIBRARIES += $(BOARD_LIBACRYL_G2D_HDR_PLUGIN)
-    LOCAL_CFLAGS += -DLIBACRYL_G2D_HDR_PLUGIN
-endif
-
-ifeq ($(CLANG_COVERAGE),true)
-# enable code coverage (these flags are copied from build/soong/cc/coverage.go)
-LOCAL_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
-LOCAL_CFLAGS += -Wno-frame-larger-than=
-LOCAL_WHOLE_STATIC_LIBRARIES += libprofile-clang-extras_ndk
-LOCAL_LDFLAGS += -fprofile-instr-generate
-LOCAL_LDFLAGS += -Wl,--wrap,open
-
-ifeq ($(CLANG_COVERAGE_CONTINUOUS_MODE),true)
-LOCAL_CFLAGS += -mllvm -runtime-counter-relocation
-LOCAL_LDFLAGS += -Wl,-mllvm=-runtime-counter-relocation
-endif
-endif
-
-LOCAL_HEADER_LIBRARIES += google_libacryl_hdrplugin_headers
-LOCAL_HEADER_LIBRARIES += google_hal_headers
-LOCAL_HEADER_LIBRARIES += libgralloc_headers
-
-LOCAL_C_INCLUDES := $(LOCAL_PATH)/local_include
-LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
-LOCAL_C_INCLUDES += $(TOP)/hardware/google/graphics/$(TARGET_BOARD_PLATFORM)/libcap
-
-LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
-
-LOCAL_SRC_FILES := acrylic.cpp acrylic_g2d.cpp
-LOCAL_SRC_FILES += acrylic_factory.cpp acrylic_layer.cpp acrylic_formats.cpp
-LOCAL_SRC_FILES += acrylic_performance.cpp acrylic_device.cpp
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE := libacryl
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-ifeq ($(BOARD_USES_VENDORIMAGE), true)
-LOCAL_PROPRIETARY_MODULE := true
-endif
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/libgscaler/Android.bp b/libgscaler/Android.bp
new file mode 100644
index 0000000..9ab99dd
--- /dev/null
+++ b/libgscaler/Android.bp
@@ -0,0 +1,49 @@
+// Copyright (C) 2008 The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_shared {
+    name: "libexynosgscaler",
+
+    shared_libs: [
+        "liblog",
+        "libutils",
+        "libcutils",
+        "libexynosscaler",
+        "libexynosutils",
+    ],
+    header_libs: [
+        "libcutils_headers",
+        "libsystem_headers",
+        "libhardware_headers",
+        "google_hal_headers",
+    ],
+
+    export_include_dirs: ["include"],
+
+    export_shared_lib_headers: ["libexynosscaler"],
+
+    srcs: [
+        "libgscaler_obj.cpp",
+        "libgscaler.cpp",
+        "exynos_subdev.c",
+    ],
+    cflags: ["-Wno-unused-function"],
+
+    proprietary: true,
+}
diff --git a/libgscaler/Android.mk b/libgscaler/Android.mk
deleted file mode 100644
index 91e007d..0000000
--- a/libgscaler/Android.mk
+++ /dev/null
@@ -1,45 +0,0 @@
-# Copyright (C) 2008 The Android Open Source Project
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
-include $(CLEAR_VARS)
-
-LOCAL_PRELINK_MODULE := false
-LOCAL_SHARED_LIBRARIES := liblog libutils libcutils libexynosscaler libexynosutils
-LOCAL_HEADER_LIBRARIES := libcutils_headers libsystem_headers libhardware_headers google_hal_headers
-
-LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
-
-LOCAL_EXPORT_SHARED_LIBRARY_HEADERS += libexynosscaler
-
-LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
-
-LOCAL_SRC_FILES := \
-	libgscaler_obj.cpp \
-	libgscaler.cpp \
-	exynos_subdev.c
-
-LOCAL_CFLAGS += -Wno-unused-function
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE := libexynosgscaler
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-
-ifeq ($(BOARD_USES_VENDORIMAGE), true)
-    LOCAL_PROPRIETARY_MODULE := true
-endif
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/libhwc2.1/Android.bp b/libhwc2.1/Android.bp
new file mode 100644
index 0000000..0a6d6bd
--- /dev/null
+++ b/libhwc2.1/Android.bp
@@ -0,0 +1,229 @@
+// Copyright (C) 2012 The Android Open Source Project
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
+// See: http://go/android-license-faq
+package {
+    default_applicable_licenses: ["hardware_google_graphics_common_libhwc2.1_license"],
+}
+
+license {
+    name: "hardware_google_graphics_common_libhwc2.1_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_shared {
+    name: "libdrmresource",
+
+    shared_libs: [
+        "libcutils",
+        "libdrm",
+        "liblog",
+        "libutils",
+        "libhardware",
+    ],
+    proprietary: true,
+    local_include_dirs: ["libdrmresource/include"],
+    srcs: [
+        "libdrmresource/utils/worker.cpp",
+        "libdrmresource/drm/resourcemanager.cpp",
+        "libdrmresource/drm/drmdevice.cpp",
+        "libdrmresource/drm/drmconnector.cpp",
+        "libdrmresource/drm/drmcrtc.cpp",
+        "libdrmresource/drm/drmencoder.cpp",
+        "libdrmresource/drm/drmmode.cpp",
+        "libdrmresource/drm/drmplane.cpp",
+        "libdrmresource/drm/drmproperty.cpp",
+        "libdrmresource/drm/drmeventlistener.cpp",
+        "libdrmresource/drm/vsyncworker.cpp",
+    ],
+    cflags: [
+        "-DHLOG_CODE=0",
+        "-Wno-unused-parameter",
+        "-Wthread-safety",
+    ] + select(soong_config_variable("ANDROID", "target_board_platform"), {
+        any @ soc_ver: ["-DSOC_VERSION=" + soc_ver],
+        default: [],
+    }),
+    header_libs: [
+        "device_kernel_headers",
+    ],
+    export_shared_lib_headers: ["libdrm"],
+    defaults: [
+        "google_graphics_cc_default",
+    ],
+}
+
+// For converting libexynosdisplay
+filegroup {
+    name: "libexynosdisplay_common_srcs",
+    srcs: [
+        "libhwchelper/ExynosHWCHelper.cpp",
+        "DisplaySceneInfo.cpp",
+        "ExynosHWCDebug.cpp",
+        "libdevice/BrightnessController.cpp",
+        "libdevice/ExynosDisplay.cpp",
+        "libdevice/ExynosDevice.cpp",
+        "libdevice/ExynosLayer.cpp",
+        "libdevice/HistogramDevice.cpp",
+        "libdevice/DisplayTe2Manager.cpp",
+        "libmaindisplay/ExynosPrimaryDisplay.cpp",
+        "libresource/ExynosMPP.cpp",
+        "libresource/ExynosResourceManager.cpp",
+        "libexternaldisplay/ExynosExternalDisplay.cpp",
+        "libvirtualdisplay/ExynosVirtualDisplay.cpp",
+        "libdisplayinterface/ExynosDeviceInterface.cpp",
+        "libdisplayinterface/ExynosDisplayInterface.cpp",
+        "libdisplayinterface/ExynosDeviceDrmInterface.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterface.cpp",
+        "libvrr/display/common/CommonDisplayContextProvider.cpp",
+        "libvrr/display/exynos/ExynosDisplayContextProvider.cpp",
+        "libvrr/Power/PowerStatsProfileTokenGenerator.cpp",
+        "libvrr/Power/DisplayStateResidencyProvider.cpp",
+        "libvrr/Power/DisplayStateResidencyWatcher.cpp",
+        "libvrr/FileNode.cpp",
+        "libvrr/RefreshRateCalculator/InstantRefreshRateCalculator.cpp",
+        "libvrr/RefreshRateCalculator/ExitIdleRefreshRateCalculator.cpp",
+        "libvrr/RefreshRateCalculator/PeriodRefreshRateCalculator.cpp",
+        "libvrr/RefreshRateCalculator/CombinedRefreshRateCalculator.cpp",
+        "libvrr/RefreshRateCalculator/RefreshRateCalculatorFactory.cpp",
+        "libvrr/RefreshRateCalculator/VideoFrameRateCalculator.cpp",
+        "libvrr/Statistics/VariableRefreshRateStatistic.cpp",
+        "libvrr/Utils.cpp",
+        "libvrr/VariableRefreshRateController.cpp",
+        "libvrr/VariableRefreshRateVersion.cpp",
+        "pixel-display.cpp",
+        "pixelstats-display.cpp",
+        "histogram_mediator.cpp",
+    ],
+}
+
+filegroup {
+    name: "pixel_display_default_xml",
+    srcs: [
+        "pixel-display-default.xml",
+    ],
+}
+
+filegroup {
+    name: "pixel_display_secondary_xml",
+    srcs: [
+        "pixel-display-secondary.xml",
+    ],
+}
+
+cc_defaults {
+    name: "libexynosdisplay_common_cc_default",
+
+    shared_libs: [
+        "liblog",
+        "libcutils",
+        "libhardware",
+        "android.hardware.graphics.composer@2.4",
+        "android.hardware.graphics.allocator@2.0",
+        "android.hardware.graphics.mapper@2.0",
+        "libhardware_legacy",
+        "libutils",
+        "libsync",
+        "libacryl",
+        "libui",
+        "libion_google",
+        "libdrmresource",
+        "libdrm",
+        "libvendorgraphicbuffer",
+        "libbinder_ndk",
+        "android.hardware.power-V2-ndk",
+        "//hardware/google/interfaces:pixel-power-ext-V1-ndk",
+        "//hardware/google/pixel:pixel_stateresidency_provider_aidl_interface-ndk",
+        "android.hardware.graphics.composer3-V4-ndk",
+        "android.hardware.drm-V1-ndk",
+        "//hardware/google/interfaces:com.google.hardware.pixel.display-V13-ndk",
+        "android.frameworks.stats-V2-ndk",
+        "//hardware/google/pixel:libpixelatoms_defs",
+        "//hardware/google/pixel:pixelatoms-cpp",
+        "libbinder_ndk",
+        "libbase",
+        "libpng",
+        "libprocessgroup",
+    ],
+
+    header_libs: [
+        "device_kernel_headers",
+        "google_hal_headers",
+        "libbinder_headers",
+        "//hardware/google/gchips/gralloc4:libgralloc_headers",
+        "libhardware_legacy_headers",
+    ],
+
+    static_libs: [
+        "libVendorVideoApi",
+        "libjsoncpp",
+        "libaidlcommonsupport",
+    ],
+    proprietary: true,
+
+    include_dirs: [
+        "hardware/google/graphics/common/include",
+        "hardware/google/graphics/common/libhwc2.1",
+        "hardware/google/graphics/common/libhwc2.1/libdevice",
+        "hardware/google/graphics/common/libhwc2.1/libmaindisplay",
+        "hardware/google/graphics/common/libhwc2.1/libexternaldisplay",
+        "hardware/google/graphics/common/libhwc2.1/libvirtualdisplay",
+        "hardware/google/graphics/common/libhwc2.1/libhwchelper",
+        "hardware/google/graphics/common/libhwc2.1/libresource",
+        "hardware/google/graphics/common/libhwc2.1/libhwcService",
+        "hardware/google/graphics/common/libhwc2.1/libdisplayinterface",
+        "hardware/google/graphics/common/libhwc2.1/libdrmresource/include",
+        "hardware/google/graphics/common/libhwc2.1/libvrr",
+        "hardware/google/graphics/common/libhwc2.1/libvrr/interface",
+    ],
+
+    srcs: [
+        ":libexynosdisplay_common_srcs",
+    ],
+
+    export_shared_lib_headers: [
+        "libacryl",
+        "libdrm",
+        "libui",
+        "libvendorgraphicbuffer",
+    ],
+
+    vintf_fragments: [
+        ":pixel_display_default_xml",
+    ] + select(soong_config_variable("google_graphics", "uses_idisplay_intf_sec"), {
+        true: [":pixel_display_secondary_xml"],
+        default: [],
+    }),
+
+    cflags: [
+        "-DHLOG_CODE=0",
+        "-DLOG_TAG=\"hwc-display\"",
+        "-Wno-unused-parameter",
+        "-Wthread-safety",
+    ] + select(soong_config_variable("ANDROID", "target_board_platform"), {
+        any @ soc_ver: ["-DSOC_VERSION=" + soc_ver],
+        default: [],
+    }),
+
+    defaults: [
+        // include hardware/google/graphics/common/BoardConfigCFlags.mk
+        "google_graphics_cc_default",
+    ],
+}
diff --git a/libhwc2.1/Android.mk b/libhwc2.1/Android.mk
index 4df3bf1..f6c358c 100644
--- a/libhwc2.1/Android.mk
+++ b/libhwc2.1/Android.mk
@@ -19,194 +19,6 @@ LOCAL_PATH:= $(call my-dir)
 # HAL module implemenation, not prelinked and stored in
 # hw/<COPYPIX_HARDWARE_MODULE_ID>.<ro.product.board>.so
 
-include $(CLEAR_VARS)
-
-LOCAL_SHARED_LIBRARIES := libcutils libdrm liblog libutils libhardware
-
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_C_INCLUDES += \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libdrmresource/include
-
-LOCAL_SRC_FILES := \
-	libdrmresource/utils/worker.cpp \
-	libdrmresource/drm/resourcemanager.cpp \
-	libdrmresource/drm/drmdevice.cpp \
-	libdrmresource/drm/drmconnector.cpp \
-	libdrmresource/drm/drmcrtc.cpp \
-	libdrmresource/drm/drmencoder.cpp \
-	libdrmresource/drm/drmmode.cpp \
-	libdrmresource/drm/drmplane.cpp \
-	libdrmresource/drm/drmproperty.cpp \
-	libdrmresource/drm/drmeventlistener.cpp \
-	libdrmresource/drm/vsyncworker.cpp
-
-LOCAL_CFLAGS := -DHLOG_CODE=0
-LOCAL_CFLAGS += -Wno-unused-parameter
-LOCAL_CFLAGS += -DSOC_VERSION=$(soc_ver)
-LOCAL_CFLAGS += -Wthread-safety
-LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := libdrm
-
-ifeq ($(CLANG_COVERAGE),true)
-# enable code coverage (these flags are copied from build/soong/cc/coverage.go)
-LOCAL_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
-LOCAL_CFLAGS += -Wno-frame-larger-than=
-LOCAL_WHOLE_STATIC_LIBRARIES += libprofile-clang-extras_ndk
-LOCAL_LDFLAGS += -fprofile-instr-generate
-LOCAL_LDFLAGS += -Wl,--wrap,open
-
-ifeq ($(CLANG_COVERAGE_CONTINUOUS_MODE),true)
-LOCAL_CFLAGS += -mllvm -runtime-counter-relocation
-LOCAL_LDFLAGS += -Wl,-mllvm=-runtime-counter-relocation
-endif
-endif
-
-LOCAL_MODULE := libdrmresource
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_TAGS := optional
-
-include $(TOP)/hardware/google/graphics/common/BoardConfigCFlags.mk
-include $(BUILD_SHARED_LIBRARY)
-
-################################################################################
-include $(CLEAR_VARS)
-
-LOCAL_SHARED_LIBRARIES := liblog libcutils libhardware \
-	android.hardware.graphics.composer@2.4 \
-	android.hardware.graphics.allocator@2.0 \
-	android.hardware.graphics.mapper@2.0 \
-	libhardware_legacy libutils \
-	libsync libacryl libui libion_google libdrmresource libdrm \
-	libvendorgraphicbuffer libbinder_ndk \
-	android.hardware.power-V2-ndk pixel-power-ext-V1-ndk \
-	pixel_stateresidency_provider_aidl_interface-ndk
-
-LOCAL_SHARED_LIBRARIES += android.hardware.graphics.composer3-V4-ndk \
-                          android.hardware.drm-V1-ndk \
-                          com.google.hardware.pixel.display-V13-ndk \
-                          android.frameworks.stats-V2-ndk \
-                          libpixelatoms_defs \
-                          pixelatoms-cpp \
-                          libbinder_ndk \
-                          libbase \
-                          libpng \
-                          libprocessgroup
-
-LOCAL_HEADER_LIBRARIES := libhardware_legacy_headers \
-			  libbinder_headers google_hal_headers \
-			  libgralloc_headers \
-			  android.hardware.graphics.common-V3-ndk_headers
-
-LOCAL_STATIC_LIBRARIES += libVendorVideoApi
-LOCAL_STATIC_LIBRARIES += libjsoncpp
-LOCAL_STATIC_LIBRARIES += libaidlcommonsupport
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_C_INCLUDES += \
-	$(TOP)/hardware/google/graphics/common/include \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libdevice \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libmaindisplay \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libexternaldisplay \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libvirtualdisplay \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libhwchelper \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libresource \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1 \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libmaindisplay \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libexternaldisplay \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libvirtualdisplay \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libresource \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libcolormanager \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libdevice \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libresource \
-	$(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/libdisplayinterface \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libhwcService \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libdisplayinterface \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libdrmresource/include \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libvrr \
-	$(TOP)/hardware/google/graphics/common/libhwc2.1/libvrr/interface \
-	$(TOP)/hardware/google/graphics/$(soc_ver)
-LOCAL_SRC_FILES := \
-	libhwchelper/ExynosHWCHelper.cpp \
-	DisplaySceneInfo.cpp \
-	ExynosHWCDebug.cpp \
-	libdevice/BrightnessController.cpp \
-	libdevice/ExynosDisplay.cpp \
-	libdevice/ExynosDevice.cpp \
-	libdevice/ExynosLayer.cpp \
-	libdevice/HistogramDevice.cpp \
-	libdevice/DisplayTe2Manager.cpp \
-	libmaindisplay/ExynosPrimaryDisplay.cpp \
-	libresource/ExynosMPP.cpp \
-	libresource/ExynosResourceManager.cpp \
-	libexternaldisplay/ExynosExternalDisplay.cpp \
-	libvirtualdisplay/ExynosVirtualDisplay.cpp \
-	libdisplayinterface/ExynosDeviceInterface.cpp \
-	libdisplayinterface/ExynosDisplayInterface.cpp \
-	libdisplayinterface/ExynosDeviceDrmInterface.cpp \
-	libdisplayinterface/ExynosDisplayDrmInterface.cpp \
-	libvrr/display/common/CommonDisplayContextProvider.cpp \
-	libvrr/display/exynos/ExynosDisplayContextProvider.cpp \
-	libvrr/Power/PowerStatsProfileTokenGenerator.cpp \
-	libvrr/Power/DisplayStateResidencyProvider.cpp \
-	libvrr/Power/DisplayStateResidencyWatcher.cpp \
-	libvrr/FileNode.cpp \
-	libvrr/RefreshRateCalculator/InstantRefreshRateCalculator.cpp \
-	libvrr/RefreshRateCalculator/ExitIdleRefreshRateCalculator.cpp \
-	libvrr/RefreshRateCalculator/PeriodRefreshRateCalculator.cpp \
-	libvrr/RefreshRateCalculator/CombinedRefreshRateCalculator.cpp \
-	libvrr/RefreshRateCalculator/RefreshRateCalculatorFactory.cpp \
-	libvrr/RefreshRateCalculator/VideoFrameRateCalculator.cpp \
-	libvrr/Statistics/VariableRefreshRateStatistic.cpp \
-	libvrr/Utils.cpp \
-	libvrr/VariableRefreshRateController.cpp \
-	libvrr/VariableRefreshRateVersion.cpp \
-	pixel-display.cpp \
-	pixelstats-display.cpp \
-	histogram_mediator.cpp
-
-LOCAL_EXPORT_SHARED_LIBRARY_HEADERS += libacryl libdrm libui libvendorgraphicbuffer
-
-LOCAL_VINTF_FRAGMENTS         += pixel-display-default.xml
-
-ifeq ($(USES_IDISPLAY_INTF_SEC),true)
-LOCAL_VINTF_FRAGMENTS         += pixel-display-secondary.xml
-endif
-
-include $(TOP)/hardware/google/graphics/$(soc_ver)/libhwc2.1/Android.mk
-
-LOCAL_CFLAGS += -DHLOG_CODE=0
-LOCAL_CFLAGS += -DLOG_TAG=\"hwc-display\"
-LOCAL_CFLAGS += -Wno-unused-parameter
-LOCAL_CFLAGS += -DSOC_VERSION=$(soc_ver)
-LOCAL_CFLAGS += -Wthread-safety
-
-ifeq ($(CLANG_COVERAGE),true)
-# enable code coverage (these flags are copied from build/soong/cc/coverage.go)
-LOCAL_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
-LOCAL_CFLAGS += -Wno-frame-larger-than=
-LOCAL_WHOLE_STATIC_LIBRARIES += libprofile-clang-extras_ndk
-LOCAL_LDFLAGS += -fprofile-instr-generate
-LOCAL_LDFLAGS += -Wl,--wrap,open
-
-ifeq ($(CLANG_COVERAGE_CONTINUOUS_MODE),true)
-LOCAL_CFLAGS += -mllvm -runtime-counter-relocation
-LOCAL_LDFLAGS += -Wl,-mllvm=-runtime-counter-relocation
-endif
-endif
-
-LOCAL_MODULE := libexynosdisplay
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_TAGS := optional
-
-include $(TOP)/hardware/google/graphics/common/BoardConfigCFlags.mk
-include $(BUILD_SHARED_LIBRARY)
-
-################################################################################
-
 ifeq ($(BOARD_USES_HWC_SERVICES),true)
 
 include $(CLEAR_VARS)
diff --git a/libhwc2.1/libdevice/BrightnessController.cpp b/libhwc2.1/libdevice/BrightnessController.cpp
index cde1227..2c80a32 100644
--- a/libhwc2.1/libdevice/BrightnessController.cpp
+++ b/libhwc2.1/libdevice/BrightnessController.cpp
@@ -1116,28 +1116,43 @@ int BrightnessController::updateCabcMode() {
 }
 
 int BrightnessController::applyBrightnessViaSysfs(uint32_t level) {
-    if (mBrightnessOfs.is_open()) {
-        ATRACE_NAME("write_bl_sysfs");
-        mBrightnessOfs.seekp(std::ios_base::beg);
-        mBrightnessOfs << std::to_string(level);
-        mBrightnessOfs.flush();
-        if (mBrightnessOfs.fail()) {
-            ALOGE("%s fail to write brightness %d", __func__, level);
-            mBrightnessOfs.clear();
-            return HWC2_ERROR_NO_RESOURCES;
+    if (!mBrightnessOfs.is_open()) {
+        String8 nodeName;
+        nodeName.appendFormat(BRIGHTNESS_SYSFS_NODE, mPanelIndex);
+        for (int i = 0; i < 3; ++i) {
+            mBrightnessOfs.open(nodeName.c_str(), std::ofstream::out);
+            if (mBrightnessOfs.fail()) {
+                ALOGW("%s %s fail to open, retrying(%d)...", __func__, nodeName.c_str(), i);
+                std::this_thread::sleep_for(std::chrono::milliseconds(100));
+            } else {
+                ALOGI("%s open %s successfully", __func__, nodeName.c_str());
+                break;
+            }
         }
-
-        {
-            std::lock_guard<std::recursive_mutex> lock(mBrightnessMutex);
-            mBrightnessLevel.reset(level);
-            mPrevDisplayWhitePointNits = mDisplayWhitePointNits;
-            printBrightnessStates("sysfs");
+        if (!mBrightnessOfs.is_open()) {
+            ALOGI("%s failed to open %s successfully", __func__, nodeName.c_str());
+            return HWC2_ERROR_UNSUPPORTED;
         }
+    }
 
-        return NO_ERROR;
+    ATRACE_NAME("write_bl_sysfs");
+    mBrightnessOfs.seekp(std::ios_base::beg);
+    mBrightnessOfs << std::to_string(level);
+    mBrightnessOfs.flush();
+    if (mBrightnessOfs.fail()) {
+        ALOGE("%s fail to write brightness %d", __func__, level);
+        mBrightnessOfs.clear();
+        return HWC2_ERROR_NO_RESOURCES;
     }
 
-    return HWC2_ERROR_UNSUPPORTED;
+    {
+        std::lock_guard<std::recursive_mutex> lock(mBrightnessMutex);
+        mBrightnessLevel.reset(level);
+        mPrevDisplayWhitePointNits = mDisplayWhitePointNits;
+        printBrightnessStates("sysfs");
+    }
+
+    return NO_ERROR;
 }
 
 int BrightnessController::applyCabcModeViaSysfs(uint8_t mode) {
diff --git a/libhwc2.1/libdevice/DisplayTe2Manager.cpp b/libhwc2.1/libdevice/DisplayTe2Manager.cpp
index bea78d2..55aad5c 100644
--- a/libhwc2.1/libdevice/DisplayTe2Manager.cpp
+++ b/libhwc2.1/libdevice/DisplayTe2Manager.cpp
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
 #include "DisplayTe2Manager.h"
 
 DisplayTe2Manager::DisplayTe2Manager(ExynosDisplay* display, int32_t panelIndex,
@@ -180,6 +182,7 @@ DisplayTe2Manager::ProximitySensorStateNotifierWorker::~ProximitySensorStateNoti
 }
 
 void DisplayTe2Manager::ProximitySensorStateNotifierWorker::onStateChanged(bool active) {
+    ATRACE_INT("proximitySensorState(HAL)", active);
     Lock();
     mIsStateActive = active;
     Unlock();
@@ -187,6 +190,7 @@ void DisplayTe2Manager::ProximitySensorStateNotifierWorker::onStateChanged(bool
 }
 
 void DisplayTe2Manager::ProximitySensorStateNotifierWorker::Routine() {
+    ATRACE_NAME("StateNotifierWorker");
     int ret;
     Lock();
     ret = WaitForSignalOrExitLocked(ms2ns(kDebounceTimeMs));
@@ -207,9 +211,15 @@ void DisplayTe2Manager::ProximitySensorStateNotifierWorker::Routine() {
         }
     } else {
         if (ret != -ETIMEDOUT) {
-            // receive the signal within kDebounceTimeMs, update the pending state
-            mPendingState =
-                    mIsStateActive ? ProximitySensorState::ACTIVE : ProximitySensorState::INACTIVE;
+            if (!mIsStateActive) {
+                // inactive within kDebounceTimeMs, update the pending state
+                mPendingState = ProximitySensorState::INACTIVE;
+            } else {
+                // notify immediately if active
+                ALOGI("ProximitySensorStateNotifierWorker: %s: notify state (1)", __func__);
+                mTe2Manager->mDisplay->onProximitySensorStateChanged(true);
+                mPendingState = ProximitySensorState::NONE;
+            }
         } else {
             // no signal within kDebounceTimeMs, notify the pending state if it exists
             if (mPendingState != ProximitySensorState::NONE) {
@@ -222,6 +232,7 @@ void DisplayTe2Manager::ProximitySensorStateNotifierWorker::Routine() {
                 mReceivedFirstStateAfterTimeout = false;
             }
         }
+        ATRACE_INT("proximitySensorPendingState", static_cast<uint32_t>(mPendingState));
     }
     Unlock();
 }
diff --git a/libhwc2.1/libdevice/DisplayTe2Manager.h b/libhwc2.1/libdevice/DisplayTe2Manager.h
index 92cf5c5..e76e610 100644
--- a/libhwc2.1/libdevice/DisplayTe2Manager.h
+++ b/libhwc2.1/libdevice/DisplayTe2Manager.h
@@ -119,7 +119,7 @@ private:
         void Routine() override;
 
     private:
-        static constexpr uint32_t kDebounceTimeMs = 100U;
+        static constexpr uint32_t kDebounceTimeMs = 500U;
 
         DisplayTe2Manager* mTe2Manager;
         bool mIsStateActive;
diff --git a/libhwc2.1/libdevice/ExynosDisplay.cpp b/libhwc2.1/libdevice/ExynosDisplay.cpp
index d1051b3..8e89e58 100644
--- a/libhwc2.1/libdevice/ExynosDisplay.cpp
+++ b/libhwc2.1/libdevice/ExynosDisplay.cpp
@@ -2813,13 +2813,7 @@ int ExynosDisplay::setReleaseFences() {
                     continue;
                 }
             }
-            if (mType == HWC_DISPLAY_VIRTUAL)
-                mLayers[i]->mReleaseFence = -1;
-            else
-                mLayers[i]->mReleaseFence =
-                    hwcCheckFenceDebug(this, FENCE_TYPE_SRC_RELEASE, FENCE_IP_DPP,
-                            hwc_dup(config.rel_fence, this,
-                                FENCE_TYPE_SRC_RELEASE, FENCE_IP_DPP));
+            mLayers[i]->mReleaseFence = -1;
         }
         config.rel_fence = fence_close(config.rel_fence, this,
                    FENCE_TYPE_SRC_RELEASE, FENCE_IP_FB);
@@ -3525,7 +3519,7 @@ void dumpBuffer(const String8& prefix, const exynos_image& image, std::ofstream&
             bufferFile.write(static_cast<char*>(addr), gmeta.sizes[i]);
             munmap(addr, gmeta.sizes[i]);
         } else {
-            ALOGE("%s: failed to mmap fds[%d]:%d for %s", __func__, i, gmeta.fds[i]);
+            ALOGE("%s: failed to mmap fds[%d]:%d", __func__, i, gmeta.fds[i]);
         }
     }
 }
diff --git a/libhwc2.1/libdevice/ExynosDisplay.h b/libhwc2.1/libdevice/ExynosDisplay.h
index 735956d..143bf03 100644
--- a/libhwc2.1/libdevice/ExynosDisplay.h
+++ b/libhwc2.1/libdevice/ExynosDisplay.h
@@ -1405,10 +1405,12 @@ class ExynosDisplay {
         virtual int32_t setDisplayTemperature(const int __unused temperature) { return NO_ERROR; }
 
         virtual int32_t registerRefreshRateChangeListener(
-                std::shared_ptr<RefreshRateChangeListener> listener) {
+                std::shared_ptr<RefreshRateChangeListener> __unused listener) {
             return NO_ERROR;
         }
 
+        virtual void setForceColorUpdate(bool __unused force) { return; }
+
     protected:
         virtual bool getHDRException(ExynosLayer *layer);
         virtual int32_t getActiveConfigInternal(hwc2_config_t* outConfig);
diff --git a/libhwc2.1/libdevice/HistogramDevice.cpp b/libhwc2.1/libdevice/HistogramDevice.cpp
index f469186..098f7b4 100644
--- a/libhwc2.1/libdevice/HistogramDevice.cpp
+++ b/libhwc2.1/libdevice/HistogramDevice.cpp
@@ -1036,7 +1036,7 @@ int HistogramDevice::parseContextDrmEvent(const void* const event, uint32_t& blo
 }
 #endif
 
-std::set<const uint8_t>::iterator HistogramDevice::cleanupChannelInfo(const uint8_t channelId) {
+std::set<uint8_t>::iterator HistogramDevice::cleanupChannelInfo(const uint8_t channelId) {
     mChannels[channelId].mStatus = ChannelStatus_t::DISABLE_PENDING;
     mChannels[channelId].mConfigInfo.reset();
     mFreeChannels.push_back(channelId);
@@ -1109,9 +1109,8 @@ void HistogramDevice::clearChannelConfigBlob(
     }
 }
 
-uint32_t HistogramDevice::getMatchBlobId(std::list<const BlobInfo>& blobsList,
-                                         const int displayActiveH, const int displayActiveV,
-                                         bool& isPositionChanged) const {
+uint32_t HistogramDevice::getMatchBlobId(std::list<BlobInfo>& blobsList, const int displayActiveH,
+                                         const int displayActiveV, bool& isPositionChanged) const {
     auto resultIt = blobsList.end();
 
     for (auto it = blobsList.begin(); it != blobsList.end(); ++it) {
@@ -1132,7 +1131,7 @@ uint32_t HistogramDevice::getMatchBlobId(std::list<const BlobInfo>& blobsList,
     return blobsList.begin()->mBlob->getId();
 }
 
-uint32_t HistogramDevice::getActiveBlobId(const std::list<const BlobInfo>& blobsList) const {
+uint32_t HistogramDevice::getActiveBlobId(const std::list<BlobInfo>& blobsList) const {
     return blobsList.empty() ? 0 : blobsList.begin()->mBlob->getId();
 }
 
diff --git a/libhwc2.1/libdevice/HistogramDevice.h b/libhwc2.1/libdevice/HistogramDevice.h
index a73e3b5..fe9242e 100644
--- a/libhwc2.1/libdevice/HistogramDevice.h
+++ b/libhwc2.1/libdevice/HistogramDevice.h
@@ -107,7 +107,7 @@ public:
         const HistogramConfig mRequestedConfig;
         Status_t mStatus = Status_t::INITIALIZED;
         int mChannelId = -1;
-        std::list<const BlobInfo> mBlobsList;
+        std::list<BlobInfo> mBlobsList;
         std::list<std::weak_ptr<ConfigInfo>>::iterator mInactiveListIt;
         ConfigInfo(const HistogramConfig& histogramConfig) : mRequestedConfig(histogramConfig) {}
         void dump(String8& result, const char* prefix = "") const;
@@ -385,8 +385,8 @@ protected:
 
     mutable std::mutex mHistogramMutex;
     std::unordered_map<AIBinder*, TokenInfo> mTokenInfoMap GUARDED_BY(mHistogramMutex);
-    std::list<const uint8_t> mFreeChannels GUARDED_BY(mHistogramMutex); // free channel list
-    std::set<const uint8_t> mUsedChannels GUARDED_BY(mHistogramMutex);  // all - free - reserved
+    std::list<uint8_t> mFreeChannels GUARDED_BY(mHistogramMutex); // free channel list
+    std::set<uint8_t> mUsedChannels GUARDED_BY(mHistogramMutex);  // all - free - reserved
     std::vector<ChannelInfo> mChannels GUARDED_BY(mHistogramMutex);
     std::list<std::weak_ptr<ConfigInfo>> mInactiveConfigItList GUARDED_BY(mHistogramMutex);
 
@@ -664,7 +664,7 @@ protected:
      * @channelId the channel id to be cleanup.
      * @return next iterator of mUsedChannels after deletion.
      */
-    std::set<const uint8_t>::iterator cleanupChannelInfo(const uint8_t channelId)
+    std::set<uint8_t>::iterator cleanupChannelInfo(const uint8_t channelId)
             REQUIRES(mHistogramMutex) EXCLUDES(mInitDrmDoneMutex, mBlobIdDataMutex);
 
     /**
@@ -722,7 +722,7 @@ protected:
      * @displayActiveV current display active vertical size (in pixel)
      * @return the blob id if found, 0 otherwise.
      */
-    uint32_t getMatchBlobId(std::list<const BlobInfo>& blobsList, const int displayActiveH,
+    uint32_t getMatchBlobId(std::list<BlobInfo>& blobsList, const int displayActiveH,
                             const int displayActiveV, bool& isPositionChanged) const
             REQUIRES(mHistogramMutex) EXCLUDES(mInitDrmDoneMutex, mBlobIdDataMutex);
 
@@ -734,8 +734,8 @@ protected:
      *
      * @return the first blod id from the blobsList if any, else return 0.
      */
-    uint32_t getActiveBlobId(const std::list<const BlobInfo>& blobsList) const
-            REQUIRES(mHistogramMutex) EXCLUDES(mInitDrmDoneMutex, mBlobIdDataMutex);
+    uint32_t getActiveBlobId(const std::list<BlobInfo>& blobsList) const REQUIRES(mHistogramMutex)
+            EXCLUDES(mInitDrmDoneMutex, mBlobIdDataMutex);
 
     /**
      * createDrmConfig
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
index cf76d73..72de2af 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
@@ -51,6 +51,7 @@ struct _drmModeAtomicReqItem {
     uint32_t object_id;
     uint32_t property_id;
     uint64_t value;
+    uint32_t cursor;
 };
 
 struct _drmModeAtomicReq {
@@ -2218,7 +2219,8 @@ int32_t ExynosDisplayDrmInterface::deliverWinConfigData()
          * refresh rate take effect (b/202346402)
          */
         bool ignoreExpectedPresentTime = false;
-        if (mVsyncCallback.getDesiredVsyncPeriod()) {
+        bool isVrr = mXrrSettings.versionInfo.isVrr();
+        if (!isVrr && mVsyncCallback.getDesiredVsyncPeriod()) {
             ignoreExpectedPresentTime = true;
 
             /* limit the condition to avoid unexpected early present */
@@ -2241,7 +2243,7 @@ int32_t ExynosDisplayDrmInterface::deliverWinConfigData()
             }
         }
 
-        if (mXrrSettings.versionInfo.needVrrParameters()) {
+        if (isVrr) {
             auto frameInterval = mExynosDisplay->getPendingFrameInterval();
             if ((ret = drmReq.atomicAddProperty(mDrmConnector->id(),
                                                 mDrmConnector->frame_interval(),
@@ -2258,6 +2260,7 @@ int32_t ExynosDisplayDrmInterface::deliverWinConfigData()
     if ((ret = drmReq.commit(flags, true)) < 0) {
         HWC_LOGE(mExynosDisplay, "%s:: Failed to commit pset ret=%d in deliverWinConfigData()\n",
                 __func__, ret);
+        mExynosDisplay->setForceColorUpdate(true);
         return ret;
     }
 
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayInterface.h b/libhwc2.1/libdisplayinterface/ExynosDisplayInterface.h
index 6714e0b..ca6eda6 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayInterface.h
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayInterface.h
@@ -101,12 +101,14 @@ class ExynosDisplayInterface {
         virtual void setProductId(uint8_t __unused edid10, uint8_t __unused edid11){};
         virtual uint32_t getProductId() { return 0; }
 
-        virtual int32_t swapCrtcs(ExynosDisplay* anotherDisplay) { return HWC2_ERROR_UNSUPPORTED; }
+        virtual int32_t swapCrtcs(ExynosDisplay* __unused anotherDisplay) {
+            return HWC2_ERROR_UNSUPPORTED;
+        }
         virtual ExynosDisplay* borrowedCrtcFrom() { return nullptr; }
         virtual void clearOldCrtcBlobs() {}
 
-        virtual int32_t uncacheLayerBuffers(const ExynosLayer* layer,
-                                            const std::vector<buffer_handle_t>& buffers) {
+        virtual int32_t uncacheLayerBuffers(const ExynosLayer* __unused layer,
+                                            const std::vector<buffer_handle_t>& __unused buffers) {
             return NO_ERROR;
         }
 
diff --git a/libhwc2.1/libdrmresource/drm/drmconnector.cpp b/libhwc2.1/libdrmresource/drm/drmconnector.cpp
index d35aeb7..4dafcbf 100644
--- a/libhwc2.1/libdrmresource/drm/drmconnector.cpp
+++ b/libhwc2.1/libdrmresource/drm/drmconnector.cpp
@@ -264,7 +264,7 @@ std::string DrmConnector::name() const {
   }
 }
 
-int DrmConnector::UpdateModes(bool use_vrr_mode) {
+int DrmConnector::UpdateModes(bool is_vrr_mode) {
   std::lock_guard<std::recursive_mutex> lock(modes_lock_);
 
   int fd = drm_->fd();
@@ -305,12 +305,9 @@ int DrmConnector::UpdateModes(bool use_vrr_mode) {
       }
     }
     if (!exists) {
-      bool is_vrr_mode = ((c->modes[i].type & DRM_MODE_TYPE_VRR) != 0);
       // Remove modes that mismatch with the VRR setting..
-      if ((use_vrr_mode != is_vrr_mode) ||
-          (!external() && is_vrr_mode &&
-           ((c->modes[i].flags & DRM_MODE_FLAG_TE_FREQ_X2) ||
-            (c->modes[i].flags & DRM_MODE_FLAG_TE_FREQ_X4)))) {
+      if (type_ == DRM_MODE_CONNECTOR_DSI &&
+          is_vrr_mode != ((c->modes[i].type & DRM_MODE_TYPE_VRR) != 0 || c->modes[i].vscan > 0)) {
         continue;
       }
       DrmMode m(&c->modes[i]);
diff --git a/libhwc2.1/libdrmresource/drm/drmmode.cpp b/libhwc2.1/libdrmresource/drm/drmmode.cpp
index 44bf0f3..10d529a 100644
--- a/libhwc2.1/libdrmresource/drm/drmmode.cpp
+++ b/libhwc2.1/libdrmresource/drm/drmmode.cpp
@@ -132,12 +132,13 @@ float DrmMode::v_refresh() const {
   if (v_total_ == 0 || h_total_ == 0) {
     return 0.0f;
   }
-  return clock_ / (float)(v_total_ * h_total_) * 1000.0f;
+  auto v_refresh = static_cast<float>(clock_) / (float)(v_total_ * h_total_) * 1000.0F;
+  return v_scan_ > 1 ? v_refresh / v_scan_ : v_refresh;
 }
 
 float DrmMode::te_frequency() const {
   auto freq = v_refresh();
-  if (is_vrr_mode()) {
+  if (type_ & DRM_MODE_TYPE_VRR) {
     if (HasFlag(flags_, DRM_MODE_FLAG_TE_FREQ_X2)) {
       freq *= 2;
     } else if (HasFlag(flags_, DRM_MODE_FLAG_TE_FREQ_X4)) {
@@ -147,6 +148,8 @@ float DrmMode::te_frequency() const {
         return 0.0f;
       }
     }
+  } else if (v_scan_ > 1) {
+    freq *= v_scan_;
   }
   return freq;
 }
diff --git a/libhwc2.1/libdrmresource/include/drmmode.h b/libhwc2.1/libdrmresource/include/drmmode.h
index 86ac5ca..2c45d7a 100644
--- a/libhwc2.1/libdrmresource/include/drmmode.h
+++ b/libhwc2.1/libdrmresource/include/drmmode.h
@@ -47,7 +47,7 @@ class DrmMode {
   bool operator==(const drmModeModeInfo &m) const;
   void ToDrmModeModeInfo(drm_mode_modeinfo *m) const;
 
-  inline bool is_vrr_mode() const { return (type_ & DRM_MODE_TYPE_VRR); };
+  inline bool is_vrr_mode() const { return (type_ & DRM_MODE_TYPE_VRR) || (v_scan_ > 0); };
   inline bool is_ns_mode() const { return (flags_ & DRM_MODE_FLAG_NS); };
 
   uint32_t id() const;
diff --git a/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp b/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
index 791f4b6..106b020 100644
--- a/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
+++ b/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
@@ -55,6 +55,7 @@ ExynosExternalDisplay::ExynosExternalDisplay(uint32_t index, ExynosDevice* devic
     //TODO : Hard coded currently
     mNumMaxPriorityAllowed = 1;
     mPowerModeState = (hwc2_power_mode_t)HWC_POWER_MODE_OFF;
+    mDisplayControl.multiThreadedPresent = true;
 }
 
 ExynosExternalDisplay::~ExynosExternalDisplay()
@@ -81,6 +82,7 @@ int ExynosExternalDisplay::openExternalDisplay()
     mSkipFrameCount = SKIP_FRAME_COUNT;
     mSkipStartFrame = 0;
     mPlugState = true;
+    setGeometryChanged(GEOMETRY_DEVICE_DISPLAY_ADDED);
 
     if (mLayers.size() != 0) {
         mLayers.clear();
@@ -110,6 +112,7 @@ void ExynosExternalDisplay::closeExternalDisplay()
     DISPLAY_LOGD(eDebugExternalDisplay, "Close fd for External Display");
 
     mPlugState = false;
+    setGeometryChanged(GEOMETRY_DEVICE_DISPLAY_REMOVED);
     mEnabled = false;
     mBlanked = false;
     mSkipFrameCount = SKIP_FRAME_COUNT;
@@ -452,6 +455,7 @@ int ExynosExternalDisplay::enable()
 
     mEnabled = true;
     mPowerModeState = (hwc2_power_mode_t)HWC_POWER_MODE_NORMAL;
+    mDisplayInterface->triggerClearDisplayPlanes();
 
     reportUsage(true);
 
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
index 7498cea..c086c72 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
@@ -1357,6 +1357,7 @@ int32_t ExynosPrimaryDisplay::setDisplayTemperature(const int temperature) {
 void ExynosPrimaryDisplay::onProximitySensorStateChanged(bool active) {
     if (mProximitySensorStateChangeCallback) {
         ALOGI("ExynosPrimaryDisplay: %s: %d", __func__, active);
+        ATRACE_NAME("onProximitySensorStateChanged(HAL)");
         mProximitySensorStateChangeCallback->onProximitySensorStateChanged(active);
     }
 }
diff --git a/libhwc2.1/libresource/ExynosMPP.cpp b/libhwc2.1/libresource/ExynosMPP.cpp
index 38ae46c..3d22575 100644
--- a/libhwc2.1/libresource/ExynosMPP.cpp
+++ b/libhwc2.1/libresource/ExynosMPP.cpp
@@ -1682,8 +1682,7 @@ bool ExynosMPP::canSkipProcessing()
         (mLogicalType == MPP_LOGICAL_G2D_COMBO)) {
         dst = mAssignedDisplay->mExynosCompositionInfo.mDstImg;
     }
-    return ((needDstBufRealloc(dst, mCurrentDstBuf) == false) & canUsePrevFrame());
-
+    return ((needDstBufRealloc(dst, mCurrentDstBuf) == false) && canUsePrevFrame());
 }
 
 /**
diff --git a/libhwc2.1/libvrr/EventQueue.h b/libhwc2.1/libvrr/EventQueue.h
index cbd8035..e7508ae 100644
--- a/libhwc2.1/libvrr/EventQueue.h
+++ b/libhwc2.1/libvrr/EventQueue.h
@@ -61,7 +61,8 @@ public:
         std::priority_queue<VrrControllerEvent> q;
         while (!mPriorityQueue.empty()) {
             const auto& it = mPriorityQueue.top();
-            if (it.mEventType == eventType) {
+            if ((static_cast<int32_t>(it.mEventType) & static_cast<int32_t>(eventType)) ==
+                static_cast<int32_t>(eventType)) {
                 ++res;
             }
             q.push(it);
diff --git a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
index 8af158a..e0cc751 100644
--- a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
+++ b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
@@ -155,7 +155,7 @@ void VariableRefreshRateStatistic::dump(String8& result, const std::vector<std::
     }
 
     if (hasDelta) {
-        result.appendFormat("Elapsed Time: %lu \n", (curTime - mLastDumpsysTime) / 1000000);
+        result.appendFormat("Elapsed Time: %" PRId64 " \n", (curTime - mLastDumpsysTime) / 1000000);
     }
 
     std::string headerString = hasDelta ? normalizeString("StateName") + "\t" +
diff --git a/libhwc2.1/libvrr/VariableRefreshRateController.cpp b/libhwc2.1/libvrr/VariableRefreshRateController.cpp
index c233657..1325aee 100644
--- a/libhwc2.1/libvrr/VariableRefreshRateController.cpp
+++ b/libhwc2.1/libvrr/VariableRefreshRateController.cpp
@@ -270,17 +270,53 @@ void VariableRefreshRateController::setActiveVrrConfiguration(hwc2_config_t conf
             LOG(ERROR) << "VrrController: Set an undefined active configuration";
             return;
         }
+        if (mFileNode &&
+            mFileNode->writeValue("expected_present_time_ns", mLastExpectedPresentTimeNs)) {
+            ATRACE_NAME("WriteExpectedPresentTime");
+        } else {
+            std::string displayFileNodePath = mDisplay->getPanelSysfsPath();
+            ALOGE("%s(): write command to file node %s%s failed.", __func__,
+                  displayFileNodePath.c_str(), "expected_present_time_ns");
+        }
         if (mFrameRateReporter) {
             mFrameRateReporter->onPresent(getSteadyClockTimeNs(), 0);
         }
         const auto oldMaxFrameRate =
                 durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
         mVrrActiveConfig = config;
+        if ((mPendingMinimumRefreshRateRequest) &&
+            (durationNsToFreq(mVrrConfigs[mVrrActiveConfig].vsyncPeriodNs) ==
+             durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs))) {
+            LOG(INFO) << "The configuration is ready to set minimum refresh rate = "
+                      << mMinimumRefreshRate;
+            ATRACE_NAME("pending_minimum refresh_rate_with_target_config");
+            if (mLastExpectedPresentTimeNs > getSteadyClockTimeNs()) {
+                // An upcoming presentation requires aligning the minimum refresh rate configuration
+                // with the presentation cadence. Additionally, we can optimize by combining the
+                // minimum refresh rate adjustment with the upcoming presentation to directly
+                // transition to the maximum refresh rate state.
+                auto aheadOfTimeNs =
+                        std::min((static_cast<int64_t>(mVrrConfigs[mVrrActiveConfig].vsyncPeriodNs /
+                                                       2)),
+                                 (2 * kMillisecondToNanoSecond) /*200 ms*/);
+                auto scheduledTimeNs = (mLastExpectedPresentTimeNs - aheadOfTimeNs);
+                if (getSteadyClockTimeNs() > scheduledTimeNs) {
+                    scheduledTimeNs += mVrrConfigs[mVrrActiveConfig].vsyncPeriodNs;
+                }
+                createMinimumRefreshRateTimeoutEventLocked();
+                postEvent(VrrControllerEventType::kMinimumRefreshRateAlignWithPresent,
+                          scheduledTimeNs);
+            } else {
+                mMinimumRefreshRate = mPendingMinimumRefreshRateRequest.value();
+                setFixedRefreshRateRangeWorker();
+                mPendingMinimumRefreshRateRequest = std::nullopt;
+            }
+        }
         // If the minimum refresh rate is active and the maximum refresh rate timeout is set,
         // also we are stay at the maximum refresh rate, any change in the active configuration
         // needs to reconfigure the maximum refresh rate according to the newly activated
         // configuration.
-        if (mMinimumRefreshRatePresentStates >= kAtMaximumRefreshRate) {
+        else if (mMinimumRefreshRatePresentState >= kAtMaximumRefreshRate) {
             if (isMinimumRefreshRateActive() && (mMaximumRefreshRateTimeoutNs > 0)) {
                 uint32_t command = getCurrentRefreshControlStateLocked();
                 auto newMaxFrameRate = durationNsToFreq(mVrrConfigs[config].minFrameIntervalNs);
@@ -289,12 +325,13 @@ void VariableRefreshRateController::setActiveVrrConfiguration(hwc2_config_t conf
                 if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
                     LOG(WARNING) << "VrrController: write file node error, command = " << command;
                 }
+                ATRACE_INT(kMinimumRefreshRateConfiguredTraceName, newMaxFrameRate);
                 onRefreshRateChangedInternal(newMaxFrameRate);
                 LOG(INFO) << "VrrController: update maximum refresh rate from " << oldMaxFrameRate
                           << " to " << newMaxFrameRate;
             } else {
                 LOG(ERROR) << "VrrController: MinimumRefreshRatePresentState cannot be "
-                           << mMinimumRefreshRatePresentStates
+                           << mMinimumRefreshRatePresentState
                            << " when minimum refresh rate = " << mMinimumRefreshRate
                            << " , mMaximumRefreshRateTimeoutNs = " << mMaximumRefreshRateTimeoutNs;
             }
@@ -542,29 +579,53 @@ void VariableRefreshRateController::setPresentTimeoutController(uint32_t control
 
 int VariableRefreshRateController::setFixedRefreshRateRange(
         uint32_t minimumRefreshRate, uint64_t minLockTimeForPeakRefreshRate) {
+    ATRACE_CALL();
+    ATRACE_INT(kMinimumRefreshRateRequestTraceName, minimumRefreshRate);
     const std::lock_guard<std::mutex> lock(mMutex);
+    // Discontinue handling fixed refresh rate range settings after power-off, as we will
+    // immediately configure it again.
+    if (mPowerMode == HWC_POWER_MODE_OFF) {
+        return NO_ERROR;
+    }
+    if (minimumRefreshRate == 0) {
+        minimumRefreshRate = 1;
+    }
+    mMaximumRefreshRateTimeoutNs = minLockTimeForPeakRefreshRate;
 
-    // If the new setting is equivalent to the old setting.
-    if ((minimumRefreshRate) <= 1 && (mMinimumRefreshRate <= 1)) {
-        // When |mMinimumRefreshRate| is 0 or 1, it is normal mode; there's no need to compare
-        // |mMaximumRefreshRateTimeoutNs|.
+    if ((mPendingMinimumRefreshRateRequest) &&
+        (mPendingMinimumRefreshRateRequest.value() == minimumRefreshRate)) {
         return NO_ERROR;
+    }
+
+    mPendingMinimumRefreshRateRequest = std::nullopt;
+    dropEventLocked(VrrControllerEventType::kMinimumRefreshRateControlEventMask);
+    if (minimumRefreshRate == mMinimumRefreshRate) {
+        return NO_ERROR;
+    }
+
+    if ((minimumRefreshRate == 1) ||
+        (durationNsToFreq(mVrrConfigs[mVrrActiveConfig].vsyncPeriodNs) ==
+         durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs))) {
+        mMinimumRefreshRate = minimumRefreshRate;
+        return setFixedRefreshRateRangeWorker();
     } else {
-        if ((minimumRefreshRate == mMinimumRefreshRate) &&
-            (mMaximumRefreshRateTimeoutNs == minLockTimeForPeakRefreshRate)) {
-            return NO_ERROR;
-        }
+        LOG(INFO) << "Set the minimum refresh rate to " << mMinimumRefreshRate
+                  << " but wait until the configuration is ready before applying.";
+        mPendingMinimumRefreshRateRequest = minimumRefreshRate;
+        postEvent(VrrControllerEventType::kMinimumRefreshRateWaitForConfigTimeout,
+                  getSteadyClockTimeNs() + kWaitForConfigTimeoutNs);
+        return NO_ERROR;
     }
+}
+
+int VariableRefreshRateController::setFixedRefreshRateRangeWorker() {
     uint32_t command = getCurrentRefreshControlStateLocked();
-    mMinimumRefreshRate = minimumRefreshRate;
-    mMaximumRefreshRateTimeoutNs = minLockTimeForPeakRefreshRate;
-    dropEventLocked(VrrControllerEventType::kMinLockTimeForPeakRefreshRate);
     if (isMinimumRefreshRateActive()) {
         cancelPresentTimeoutHandlingLocked();
         // Delegate timeout management to hardware.
         setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
         // Configure panel to maintain the minimum refresh rate.
-        setBitField(command, minimumRefreshRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
+        setBitField(command, mMinimumRefreshRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
                     kPanelRefreshCtrlMinimumRefreshRateMask);
         // TODO(b/333204544): ensure the correct refresh rate is set when calling
         // setFixedRefreshRate().
@@ -572,48 +633,8 @@ int VariableRefreshRateController::setFixedRefreshRateRange(
         if (mVariableRefreshRateStatistic) {
             mVariableRefreshRateStatistic->setFixedRefreshRate(mMinimumRefreshRate);
         }
-        mMinimumRefreshRatePresentStates = kAtMinimumRefreshRate;
-        if (mMaximumRefreshRateTimeoutNs > 0) {
-            // Set up peak refresh rate timeout event accordingly.
-            mMinimumRefreshRateTimeoutEvent =
-                    std::make_optional<TimedEvent>("MinimumRefreshRateTimeout");
-            mMinimumRefreshRateTimeoutEvent->mFunctor = [this]() -> int {
-                if (mMinimumRefreshRatePresentStates == kAtMaximumRefreshRate) {
-                    mMinimumRefreshRatePresentStates = kTransitionToMinimumRefreshRate;
-                    mMinimumRefreshRateTimeoutEvent->mIsRelativeTime = false;
-                    auto delayNs =
-                            (std::nano::den / mMinimumRefreshRate) + kMillisecondToNanoSecond;
-                    mMinimumRefreshRateTimeoutEvent->mWhenNs = getSteadyClockTimeNs() + delayNs;
-                    postEvent(VrrControllerEventType::kMinLockTimeForPeakRefreshRate,
-                              mMinimumRefreshRateTimeoutEvent.value());
-                    return 1;
-                } else {
-                    if (mMinimumRefreshRatePresentStates != kTransitionToMinimumRefreshRate) {
-                        LOG(ERROR) << "VrrController: expect mMinimumRefreshRatePresentStates is "
-                                      "kTransitionToMinimumRefreshRate, but it is "
-                                   << mMinimumRefreshRatePresentStates;
-                        return -1;
-                    }
-                    mMinimumRefreshRatePresentStates = kAtMinimumRefreshRate;
-                    // TODO(b/333204544): ensure the correct refresh rate is set when calling
-                    // setFixedRefreshRate().
-                    if (mVariableRefreshRateStatistic) {
-                        mVariableRefreshRateStatistic->setFixedRefreshRate(mMinimumRefreshRate);
-                    }
-                    if (mPresentTimeoutController != PresentTimeoutControllerType::kHardware) {
-                        LOG(WARNING)
-                                << "VrrController: incorrect type of present timeout controller.";
-                    }
-                    uint32_t command = getCurrentRefreshControlStateLocked();
-                    setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
-                    setBitField(command, mMinimumRefreshRate,
-                                kPanelRefreshCtrlMinimumRefreshRateOffset,
-                                kPanelRefreshCtrlMinimumRefreshRateMask);
-                    onRefreshRateChangedInternal(mMinimumRefreshRate);
-                    return mFileNode->writeValue(composer::kRefreshControlNodeName, command);
-                }
-            };
-        }
+        mMinimumRefreshRatePresentState = kAtMinimumRefreshRate;
+        createMinimumRefreshRateTimeoutEventLocked();
         if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
             return -1;
         }
@@ -642,8 +663,12 @@ int VariableRefreshRateController::setFixedRefreshRateRange(
         mMaximumRefreshRateTimeoutNs = 0;
         onRefreshRateChangedInternal(1);
         mMinimumRefreshRateTimeoutEvent = std::nullopt;
-        mMinimumRefreshRatePresentStates = kMinRefreshRateUnset;
+        mMinimumRefreshRatePresentState = kMinRefreshRateUnset;
     }
+    command = getCurrentRefreshControlStateLocked();
+    ATRACE_INT(kMinimumRefreshRateConfiguredTraceName,
+               ((command & kPanelRefreshCtrlMinimumRefreshRateMask) >>
+                kPanelRefreshCtrlFrameInsertionFrameCountBits));
     return 1;
 }
 
@@ -693,14 +718,15 @@ void VariableRefreshRateController::onPresent(int fence) {
             dropEventLocked(VrrControllerEventType::kHibernateTimeout);
         }
 
-        if ((mMaximumRefreshRateTimeoutNs > 0) && (mMinimumRefreshRate > 1)) {
+        if ((mMaximumRefreshRateTimeoutNs > 0) && (mMinimumRefreshRate > 1) &&
+            (!mPendingMinimumRefreshRateRequest)) {
             auto maxFrameRate = durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
             // If the target minimum refresh rate equals the maxFrameRate, there's no need to
             // promote the refresh rate to maxFrameRate during presentation.
             // E.g. in low-light conditions, with |maxFrameRate| and |mMinimumRefreshRate| both at
             // 120, no refresh rate promotion is needed.
             if (maxFrameRate != mMinimumRefreshRate) {
-                if (mMinimumRefreshRatePresentStates == kAtMinimumRefreshRate) {
+                if (mMinimumRefreshRatePresentState == kAtMinimumRefreshRate) {
                     if (mPresentTimeoutController != PresentTimeoutControllerType::kHardware) {
                         LOG(WARNING)
                                 << "VrrController: incorrect type of present timeout controller.";
@@ -716,7 +742,8 @@ void VariableRefreshRateController::onPresent(int fence) {
                                 << "VrrController: write file node error, command = " << command;
                         return;
                     }
-                    mMinimumRefreshRatePresentStates = kAtMaximumRefreshRate;
+                    ATRACE_INT(kMinimumRefreshRateConfiguredTraceName, maxFrameRate);
+                    mMinimumRefreshRatePresentState = kAtMaximumRefreshRate;
                     onRefreshRateChangedInternal(maxFrameRate);
                     mMinimumRefreshRateTimeoutEvent->mIsRelativeTime = false;
                     mMinimumRefreshRateTimeoutEvent->mWhenNs =
@@ -724,7 +751,7 @@ void VariableRefreshRateController::onPresent(int fence) {
                             mMaximumRefreshRateTimeoutNs;
                     postEvent(VrrControllerEventType::kMinLockTimeForPeakRefreshRate,
                               mMinimumRefreshRateTimeoutEvent.value());
-                } else if (mMinimumRefreshRatePresentStates == kTransitionToMinimumRefreshRate) {
+                } else if (mMinimumRefreshRatePresentState == kTransitionToMinimumRefreshRate) {
                     dropEventLocked(VrrControllerEventType::kMinLockTimeForPeakRefreshRate);
                     mMinimumRefreshRateTimeoutEvent->mIsRelativeTime = false;
                     auto delayNs =
@@ -734,9 +761,9 @@ void VariableRefreshRateController::onPresent(int fence) {
                     postEvent(VrrControllerEventType::kMinLockTimeForPeakRefreshRate,
                               mMinimumRefreshRateTimeoutEvent.value());
                 } else {
-                    if (mMinimumRefreshRatePresentStates != kAtMaximumRefreshRate) {
+                    if (mMinimumRefreshRatePresentState != kAtMaximumRefreshRate) {
                         LOG(ERROR) << "VrrController: wrong state when setting min refresh rate: "
-                                   << mMinimumRefreshRatePresentStates;
+                                   << mMinimumRefreshRatePresentState;
                     }
                 }
             }
@@ -799,6 +826,7 @@ void VariableRefreshRateController::setExpectedPresentTime(int64_t timestampNano
     ATRACE_CALL();
 
     const std::lock_guard<std::mutex> lock(mMutex);
+    mLastExpectedPresentTimeNs = timestampNanos;
     // Drop the out of date timeout.
     dropEventLocked(VrrControllerEventType::kSystemRenderingTimeout);
     cancelPresentTimeoutHandlingLocked();
@@ -820,6 +848,46 @@ void VariableRefreshRateController::cancelPresentTimeoutHandlingLocked() {
     mPendingVendorRenderingTimeoutTasks.reset();
 }
 
+void VariableRefreshRateController::createMinimumRefreshRateTimeoutEventLocked() {
+    // Set up peak refresh rate timeout event accordingly.
+    mMinimumRefreshRateTimeoutEvent = std::make_optional<TimedEvent>("MinimumRefreshRateTimeout");
+    mMinimumRefreshRateTimeoutEvent->mFunctor = [this]() -> int {
+        if (mMinimumRefreshRatePresentState == kAtMaximumRefreshRate) {
+            mMinimumRefreshRatePresentState = kTransitionToMinimumRefreshRate;
+            mMinimumRefreshRateTimeoutEvent->mIsRelativeTime = false;
+            auto delayNs = (std::nano::den / mMinimumRefreshRate) + kMillisecondToNanoSecond;
+            mMinimumRefreshRateTimeoutEvent->mWhenNs = getSteadyClockTimeNs() + delayNs;
+            postEvent(VrrControllerEventType::kMinLockTimeForPeakRefreshRate,
+                      mMinimumRefreshRateTimeoutEvent.value());
+            return 1;
+        } else {
+            if (mMinimumRefreshRatePresentState != kTransitionToMinimumRefreshRate) {
+                LOG(ERROR) << "VrrController: expect mMinimumRefreshRatePresentState is "
+                              "kTransitionToMinimumRefreshRate, but it is "
+                           << mMinimumRefreshRatePresentState;
+                return -1;
+            }
+            mMinimumRefreshRatePresentState = kAtMinimumRefreshRate;
+            // TODO(b/333204544): ensure the correct refresh rate is set when calling
+            // setFixedRefreshRate().
+            if (mVariableRefreshRateStatistic) {
+                mVariableRefreshRateStatistic->setFixedRefreshRate(mMinimumRefreshRate);
+            }
+            if (mPresentTimeoutController != PresentTimeoutControllerType::kHardware) {
+                LOG(WARNING) << "VrrController: incorrect type of present timeout controller.";
+            }
+            uint32_t command = getCurrentRefreshControlStateLocked();
+            setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
+            setBitField(command, mMinimumRefreshRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
+                        kPanelRefreshCtrlMinimumRefreshRateMask);
+            onRefreshRateChangedInternal(mMinimumRefreshRate);
+            auto res = mFileNode->writeValue(composer::kRefreshControlNodeName, command);
+            ATRACE_INT(kMinimumRefreshRateConfiguredTraceName, mMinimumRefreshRate);
+            return res;
+        }
+    };
+}
+
 void VariableRefreshRateController::dropEventLocked() {
     mEventQueue.mPriorityQueue = std::priority_queue<VrrControllerEvent>();
 }
@@ -858,6 +926,10 @@ std::string VariableRefreshRateController::dumpEventQueueLocked() {
 
 void VariableRefreshRateController::dump(String8& result, const std::vector<std::string>& args) {
     result.appendFormat("\nVariableRefreshRateStatistic: \n");
+    if (mDisplay) {
+        result.appendFormat("[%s] ", mDisplay->mDisplayName.c_str());
+    }
+    result.appendFormat("Physical Refresh Rate = %i \n", mLastRefreshRate);
     mVariableRefreshRateStatistic->dump(result, args);
 }
 
@@ -1130,6 +1202,45 @@ void VariableRefreshRateController::threadBody() {
             if (event.mEventType == VrrControllerEventType::kUpdateDbiFrameRate) {
                 frameRate = mFrameRate;
             }
+            if (event.mEventType == VrrControllerEventType::kMinimumRefreshRateAlignWithPresent) {
+                if (mPendingMinimumRefreshRateRequest) {
+                    mMinimumRefreshRate = mPendingMinimumRefreshRateRequest.value();
+                    mPendingMinimumRefreshRateRequest = std::nullopt;
+                    auto maxFrameRate =
+                            durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
+                    uint32_t command = getCurrentRefreshControlStateLocked();
+                    // Delegate timeout management to hardware.
+                    setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
+                    // Configure panel to maintain the minimum refresh rate.
+                    setBitField(command, maxFrameRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
+                                kPanelRefreshCtrlMinimumRefreshRateMask);
+                    if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
+                        LOG(WARNING)
+                                << "VrrController: write file node error, command = " << command;
+                        return;
+                    }
+                    ATRACE_INT(kMinimumRefreshRateConfiguredTraceName, maxFrameRate);
+                    mMinimumRefreshRatePresentState = kAtMaximumRefreshRate;
+                    // Even though we transition directly to the maximum refresh rate, we still
+                    // report the refresh rate change for |mMinimumRefreshRate| to maintain
+                    // consistency. It will soon ovewrite by |maxFrameRate| below.
+                    onRefreshRateChangedInternal(mMinimumRefreshRate);
+                    onRefreshRateChangedInternal(maxFrameRate);
+                    mMinimumRefreshRateTimeoutEvent->mIsRelativeTime = false;
+                    mMinimumRefreshRateTimeoutEvent->mWhenNs =
+                            getSteadyClockTimeNs() + mMaximumRefreshRateTimeoutNs;
+                    postEvent(VrrControllerEventType::kMinLockTimeForPeakRefreshRate,
+                              mMinimumRefreshRateTimeoutEvent.value());
+                }
+                continue;
+            }
+            if (event.mEventType ==
+                VrrControllerEventType::kMinimumRefreshRateWaitForConfigTimeout) {
+                LOG(ERROR) << "Set minimum refresh rate to " << mMinimumRefreshRate
+                           << " but wait for config timeout.";
+                mPendingMinimumRefreshRateRequest = std::nullopt;
+                continue;
+            }
             if (mState == VrrControllerState::kRendering) {
                 if (event.mEventType == VrrControllerEventType::kHibernateTimeout) {
                     LOG(ERROR) << "VrrController: receiving a hibernate timeout event while in the "
diff --git a/libhwc2.1/libvrr/VariableRefreshRateController.h b/libhwc2.1/libvrr/VariableRefreshRateController.h
index 6563da4..e6bc859 100644
--- a/libhwc2.1/libvrr/VariableRefreshRateController.h
+++ b/libhwc2.1/libvrr/VariableRefreshRateController.h
@@ -133,9 +133,14 @@ public:
     void dump(String8& result, const std::vector<std::string>& args = {});
 
 private:
+    static constexpr char kMinimumRefreshRateRequestTraceName[] = "MinimumRefreshRateRequest";
+    static constexpr char kMinimumRefreshRateConfiguredTraceName[] = "MinimumRefreshRateConfigured";
+
     static constexpr int kMaxFrameRate = 120;
     static constexpr int kMaxTefrequency = 240;
 
+    static constexpr int64_t kWaitForConfigTimeoutNs = std::nano::den; // 1 second.
+
     static constexpr int kDefaultRingBufferCapacity = 128;
     static constexpr int64_t kDefaultWakeUpTimeInPowerSaving =
             500 * (std::nano::den / std::milli::den); // 500 ms
@@ -275,6 +280,8 @@ private:
 
     void cancelPresentTimeoutHandlingLocked();
 
+    void createMinimumRefreshRateTimeoutEventLocked();
+
     void dropEventLocked();
     void dropEventLocked(VrrControllerEventType eventType);
 
@@ -335,6 +342,8 @@ private:
     void postEvent(VrrControllerEventType type, TimedEvent& timedEvent);
     void postEvent(VrrControllerEventType type, int64_t when);
 
+    int setFixedRefreshRateRangeWorker();
+
     bool shouldHandleVendorRenderingTimeout() const;
 
     void stopThread(bool exit);
@@ -400,12 +409,18 @@ private:
     // only when |mMinimumRefreshRate| is greater than 1.
     uint64_t mMaximumRefreshRateTimeoutNs = 0;
     std::optional<TimedEvent> mMinimumRefreshRateTimeoutEvent;
-    MinimumRefreshRatePresentStates mMinimumRefreshRatePresentStates = kMinRefreshRateUnset;
+    MinimumRefreshRatePresentStates mMinimumRefreshRatePresentState = kMinRefreshRateUnset;
+    std::optional<uint32_t> mPendingMinimumRefreshRateRequest = std::nullopt;
 
     std::vector<std::shared_ptr<RefreshRateChangeListener>> mRefreshRateChangeListeners;
 
     PendingVendorRenderingTimeoutTasks mPendingVendorRenderingTimeoutTasks;
 
+    // It stores the last present time as a cadence hint. Note that it does not update when
+    // notifyExpectedPresent is called, as notifyExpectedPresent may not result in an actual
+    // display.
+    int64_t mLastExpectedPresentTimeNs = -1;
+
     std::mutex mMutex;
     std::condition_variable mCondition;
 };
diff --git a/libhwc2.1/libvrr/interface/Event.h b/libhwc2.1/libvrr/interface/Event.h
index 2211dee..6e1ddee 100644
--- a/libhwc2.1/libvrr/interface/Event.h
+++ b/libhwc2.1/libvrr/interface/Event.h
@@ -51,8 +51,13 @@ enum class VrrControllerEventType {
     kAodRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 4),
     kExitIdleRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 5),
     kStaticticUpdate = kCallbackEventMask + (1 << 6),
-    kMinLockTimeForPeakRefreshRate = kCallbackEventMask + (1 << 7),
     kCallbackEventMax = kCallbackEventMask + (1 << 27),
+    // Minimum refresh rate control events.
+    kMinimumRefreshRateControlEventMask = 0x40000000,
+    kMinimumRefreshRateWaitForConfigTimeout = kMinimumRefreshRateControlEventMask + (1 << 0),
+    kMinimumRefreshRateAlignWithPresent = kMinimumRefreshRateControlEventMask + (1 << 1),
+    kMinLockTimeForPeakRefreshRate =
+            ((kMinimumRefreshRateControlEventMask + (1 << 2)) | kCallbackEventMask),
     // Sensors, outer events...
 };
 
diff --git a/libmemtrack/Android.bp b/libmemtrack/Android.bp
new file mode 100644
index 0000000..219ba7b
--- /dev/null
+++ b/libmemtrack/Android.bp
@@ -0,0 +1,73 @@
+// Copyright (C) 2013 The Android Open Source Project
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
+        "hardware_google_graphics_common_libmemtrack_license",
+    ],
+}
+
+license {
+    name: "hardware_google_graphics_common_libmemtrack_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+// HAL module implementation stored in
+// hw/<POWERS_HARDWARE_MODULE_ID>.<ro.hardware>.so
+
+soong_config_module_type {
+    name: "memtrack_cc_library_shared",
+    module_type: "cc_library_shared",
+    config_namespace: "ANDROID",
+    value_variables: ["target_board_platform"],
+    properties: [
+        "name",
+    ],
+}
+
+memtrack_cc_library_shared {
+    name: "memtrack.target_board_platform",
+    relative_install_path: "hw",
+    header_libs: [
+        "libcutils_headers",
+        "libsystem_headers",
+        "libhardware_headers",
+    ],
+    shared_libs: [
+        "liblog",
+        "libion_google",
+    ],
+    srcs: [
+        "memtrack_exynos.cpp",
+        "mali.cpp",
+        "ion.cpp",
+        "dmabuf.cpp",
+    ],
+    soong_config_variables: {
+        target_board_platform: {
+            name: "memtrack.%s",
+            conditions_default: {
+                name: "memtrack.target_board_platform",
+            },
+        },
+    },
+    proprietary: true,
+}
diff --git a/libmemtrack/Android.mk b/libmemtrack/Android.mk
deleted file mode 100644
index 1f1c4e6..0000000
--- a/libmemtrack/Android.mk
+++ /dev/null
@@ -1,31 +0,0 @@
-# Copyright (C) 2013 The Android Open Source Project
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
-LOCAL_PATH := $(call my-dir)
-
-# HAL module implemenation stored in
-# hw/<POWERS_HARDWARE_MODULE_ID>.<ro.hardware>.so
-include $(CLEAR_VARS)
-
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_HEADER_LIBRARIES := libcutils_headers libsystem_headers libhardware_headers
-LOCAL_SHARED_LIBRARIES := liblog libion_google
-LOCAL_SRC_FILES := memtrack_exynos.cpp mali.cpp ion.cpp dmabuf.cpp
-LOCAL_MODULE := memtrack.$(TARGET_BOARD_PLATFORM)
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_PROPRIETARY_MODULE := true
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/libscaler/Android.bp b/libscaler/Android.bp
new file mode 100644
index 0000000..fd38653
--- /dev/null
+++ b/libscaler/Android.bp
@@ -0,0 +1,58 @@
+// Copyright (C) 2013 The Android Open Source Project
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_shared {
+    name: "libexynosscaler",
+
+    shared_libs: [
+        "liblog",
+        "libutils",
+        "libcutils",
+    ],
+    header_libs: [
+        "libcutils_headers",
+        "libsystem_headers",
+        "libhardware_headers",
+        "google_hal_headers",
+    ],
+
+    export_include_dirs: ["include"],
+
+    srcs: [
+        "libscaler.cpp",
+        "libscaler-v4l2.cpp",
+        "libscalerblend-v4l2.cpp",
+        "libscaler-m2m1shot.cpp",
+        "libscaler-swscaler.cpp",
+    ],
+
+    proprietary: true,
+
+    cflags: select(soong_config_variable("google_graphics", "board_uses_scaler_m2m1shot"), {
+        true: [
+            "-DSCALER_USE_M2M1SHOT",
+        ],
+        default: [],
+    }) + select(soong_config_variable("google_graphics", "board_uses_align_restriction"), {
+        true: [
+            "-DSCALER_ALIGN_RESTRICTION",
+        ],
+        default: [],
+    }),
+}
diff --git a/libscaler/Android.mk b/libscaler/Android.mk
deleted file mode 100644
index a89c695..0000000
--- a/libscaler/Android.mk
+++ /dev/null
@@ -1,45 +0,0 @@
-# Copyright (C) 2013 The Android Open Source Project
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
-include $(CLEAR_VARS)
-
-LOCAL_PRELINK_MODULE := false
-LOCAL_SHARED_LIBRARIES := liblog libutils libcutils
-LOCAL_HEADER_LIBRARIES := libcutils_headers libsystem_headers libhardware_headers google_hal_headers
-
-LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
-
-LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
-
-LOCAL_SRC_FILES := libscaler.cpp libscaler-v4l2.cpp libscalerblend-v4l2.cpp libscaler-m2m1shot.cpp libscaler-swscaler.cpp
-ifeq ($(BOARD_USES_SCALER_M2M1SHOT), true)
-LOCAL_CFLAGS += -DSCALER_USE_M2M1SHOT
-endif
-
-ifeq ($(BOARD_USES_ALIGN_RESTRICTION), true)
-LOCAL_CFLAGS += -DSCALER_ALIGN_RESTRICTION
-endif
-
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE := libexynosscaler
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-
-ifeq ($(BOARD_USES_VENDORIMAGE), true)
-    LOCAL_PROPRIETARY_MODULE := true
-endif
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/libv4l2/Android.bp b/libv4l2/Android.bp
new file mode 100644
index 0000000..619524d
--- /dev/null
+++ b/libv4l2/Android.bp
@@ -0,0 +1,57 @@
+// Copyright (C) 2011 The Android Open Source Project
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
+        "hardware_google_graphics_common_libv4l2_license",
+    ],
+}
+
+license {
+    name: "hardware_google_graphics_common_libv4l2_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_shared {
+    name: "libexynosv4l2",
+
+    srcs: [
+        "exynos_v4l2.c",
+        "exynos_subdev.c",
+    ],
+
+    include_dirs: [
+        "hardware/google/graphics/common/include",
+    ],
+
+    shared_libs: [
+        "liblog",
+        "libutils",
+        "libexynosutils",
+    ],
+
+    proprietary: true,
+    cflags: [
+        "-DUSES_GSCALER",
+        "-Wno-unused-parameter",
+        "-Wno-unused-function",
+    ],
+}
diff --git a/libv4l2/Android.mk b/libv4l2/Android.mk
deleted file mode 100644
index a4b2a0b..0000000
--- a/libv4l2/Android.mk
+++ /dev/null
@@ -1,41 +0,0 @@
-# Copyright (C) 2011 The Android Open Source Project
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
-LOCAL_SRC_FILES := \
-	exynos_v4l2.c \
-	exynos_subdev.c
-
-LOCAL_C_INCLUDES := \
-	$(LOCAL_PATH)/../include \
-	$(TOP)/hardware/samsung_slsi/exynos/libexynosutils
-
-LOCAL_SHARED_LIBRARIES := \
-	liblog \
-	libutils \
-	libexynosutils
-
-LOCAL_MODULE := libexynosv4l2
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_PRELINK_MODULE := false
-LOCAL_PROPRIETARY_MODULE := true
-LOCAL_CFLAGS += -Wno-unused-parameter -Wno-unused-function
-
-include $(TOP)/hardware/google/graphics/common/BoardConfigCFlags.mk
-include $(BUILD_SHARED_LIBRARY)
diff --git a/memtrack-pixel/service/memtrack.rc b/memtrack-pixel/service/memtrack.rc
index 02f5a69..4551ebe 100644
--- a/memtrack-pixel/service/memtrack.rc
+++ b/memtrack-pixel/service/memtrack.rc
@@ -2,3 +2,4 @@ service vendor.memtrack-default /vendor/bin/hw/android.hardware.memtrack-service
     class hal
     user graphics
     group system
+    task_profiles ServiceCapacityLow
```

