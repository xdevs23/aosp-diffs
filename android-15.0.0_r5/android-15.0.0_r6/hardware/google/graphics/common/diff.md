```diff
diff --git a/gralloc-headers/Android.bp b/gralloc-headers/Android.bp
index 3175328..f937b52 100644
--- a/gralloc-headers/Android.bp
+++ b/gralloc-headers/Android.bp
@@ -2,14 +2,58 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+soong_config_module_type {
+    name: "gralloc_defaults",
+    module_type: "cc_defaults",
+    config_namespace: "pixel_gralloc",
+    variables: [
+        "mapper_version",
+    ],
+    properties: [
+        "cflags",
+    ],
+}
+
+soong_config_string_variable {
+    name: "mapper_version",
+    values: [
+        "mapper4",
+        "mapper5",
+    ],
+}
+
+gralloc_defaults {
+    name: "mapper-version-defaults",
+    soong_config_variables: {
+        mapper_version: {
+            mapper5: {
+                cflags: [
+                    "-DMAPPER_5",
+                ],
+            },
+            mapper4: {
+                cflags: [
+                    "-DMAPPER_4",
+                ],
+            },
+        },
+    },
+}
+
 cc_defaults {
     name: "pixel-gralloc-headers-dependencies",
     defaults: [
         "android.hardware.graphics.common-ndk_shared",
+        "mapper-version-defaults",
     ],
     shared_libs: [
         "android.hardware.graphics.mapper@4.0",
         "libgralloctypes",
+        "libvndksupport",
+    ],
+    header_libs: [
+        "libimapper_stablec",
+        "libimapper_providerutils",
     ],
 }
 
@@ -19,6 +63,7 @@ cc_library_headers {
     vendor_available: true,
     defaults: [
         "pixel-gralloc-headers-dependencies",
+        "mapper-version-defaults",
     ],
     export_include_dirs: [
         ".",
diff --git a/gralloc-headers/pixel-gralloc/format.h b/gralloc-headers/pixel-gralloc/format.h
index 2edd3ad..46b2c45 100644
--- a/gralloc-headers/pixel-gralloc/format.h
+++ b/gralloc-headers/pixel-gralloc/format.h
@@ -48,6 +48,11 @@ enum class Format : uint32_t {
     // Pixel specific formats
     GOOGLE_NV12 = 0x301,
     GOOGLE_R8 = 0x303,
+    /**
+     * 48-bit format that has 16-bit R, G, B components, in that order,
+     * from the lowest memory address to the highest memory address.
+     */
+    GOOGLE_RGB16 = 0x304,
 };
 
 #undef MapFormat
diff --git a/gralloc-headers/pixel-gralloc/mapper.h b/gralloc-headers/pixel-gralloc/mapper.h
index ede7c33..ab588c1 100644
--- a/gralloc-headers/pixel-gralloc/mapper.h
+++ b/gralloc-headers/pixel-gralloc/mapper.h
@@ -1,123 +1,9 @@
 #pragma once
 
-#include <android/hardware/graphics/mapper/4.0/IMapper.h>
-#include <log/log.h>
-
-#include "format.h"
-#include "format_type.h"
-#include "metadata.h"
-#include "utils.h"
-
-namespace pixel::graphics::mapper {
-
-namespace {
-
-using ::aidl::android::hardware::graphics::common::PlaneLayout;
-using android::hardware::graphics::mapper::V4_0::Error;
-using android::hardware::graphics::mapper::V4_0::IMapper;
-using HidlPixelFormat = ::android::hardware::graphics::common::V1_2::PixelFormat;
-using namespace ::pixel::graphics;
-
-android::sp<IMapper> get_mapper() {
-    static android::sp<IMapper> mapper = []() {
-        auto mapper = IMapper::getService();
-        if (!mapper) {
-            ALOGE("Failed to get mapper service");
-        }
-        return mapper;
-    }();
-
-    return mapper;
-}
-
-} // namespace
-
-template <MetadataType T>
-struct always_false : std::false_type {};
-
-template <MetadataType T>
-struct ReturnType {
-    static_assert(always_false<T>::value, "Unspecialized ReturnType is not supported");
-    using type = void;
-};
-
-template <MetadataType T>
-static std::optional<typename ReturnType<T>::type> get(buffer_handle_t /*handle*/) {
-    static_assert(always_false<T>::value, "Unspecialized get is not supported");
-    return {};
-}
-
-// TODO: Add support for stable-c mapper
-#define GET(metadata, return_type)                                                       \
-    template <>                                                                          \
-    struct ReturnType<MetadataType::metadata> {                                          \
-        using type = return_type;                                                        \
-    };                                                                                   \
-                                                                                         \
-    template <>                                                                          \
-    [[maybe_unused]] std::optional<typename ReturnType<MetadataType::metadata>::type>    \
-    get<MetadataType::metadata>(buffer_handle_t handle) {                                \
-        auto mapper = get_mapper();                                                      \
-        IMapper::MetadataType type = {                                                   \
-                .name = kPixelMetadataTypeName,                                          \
-                .value = static_cast<int64_t>(MetadataType::metadata),                   \
-        };                                                                               \
-                                                                                         \
-        android::hardware::hidl_vec<uint8_t> vec;                                        \
-        Error error;                                                                     \
-        auto ret = mapper->get(const_cast<native_handle_t*>(handle), type,               \
-                               [&](const auto& tmpError,                                 \
-                                   const android::hardware::hidl_vec<uint8_t>& tmpVec) { \
-                                   error = tmpError;                                     \
-                                   vec = tmpVec;                                         \
-                               });                                                       \
-        if (!ret.isOk()) {                                                               \
-            return {};                                                                   \
-        }                                                                                \
-                                                                                         \
-        return utils::decode<return_type>(vec);                                          \
-    }
-
-#pragma clang diagnostic push
-#pragma clang diagnostic ignored "-Wunused-function"
-
-GET(PLANE_DMA_BUFS, std::vector<int>);
-GET(VIDEO_HDR, void*);
-GET(VIDEO_ROI, void*);
-GET(VIDEO_GMV, VideoGMV);
-
-GET(COMPRESSED_PLANE_LAYOUTS, std::vector<CompressedPlaneLayout>);
-GET(PIXEL_FORMAT_ALLOCATED, Format);
-GET(FORMAT_TYPE, FormatType);
-
-#pragma clang diagnostic pop
-
-#undef GET
-
-template <MetadataType T>
-static Error set(buffer_handle_t /*handle*/, typename ReturnType<T>::type /*data*/) {
-    static_assert(always_false<T>::value, "Unspecialized set is not supported");
-    return {};
-}
-
-#define SET(metadata, metadata_typename)                                                  \
-    template <>                                                                           \
-    [[maybe_unused]] Error                                                                \
-    set<MetadataType::metadata>(buffer_handle_t handle,                                   \
-                                typename ReturnType<MetadataType::metadata>::type data) { \
-        auto mapper = get_mapper();                                                       \
-        auto encoded_data = utils::encode<metadata_typename>(data);                       \
-        IMapper::MetadataType type = {                                                    \
-                .name = kPixelMetadataTypeName,                                           \
-                .value = static_cast<int64_t>(MetadataType::metadata),                    \
-        };                                                                                \
-                                                                                          \
-        auto ret = mapper->set(const_cast<native_handle_t*>(handle), type, encoded_data); \
-                                                                                          \
-        return ret;                                                                       \
-    }
-
-SET(VIDEO_GMV, VideoGMV);
-#undef SET
-
-} // namespace pixel::graphics::mapper
+#if defined(MAPPER_5)
+#include "mapper5.h"
+#elif defined(MAPPER_4)
+#include "mapper4.h"
+#else
+#error "Mapper not found"
+#endif
diff --git a/gralloc-headers/pixel-gralloc/mapper4.h b/gralloc-headers/pixel-gralloc/mapper4.h
new file mode 100644
index 0000000..8ea0193
--- /dev/null
+++ b/gralloc-headers/pixel-gralloc/mapper4.h
@@ -0,0 +1,68 @@
+#pragma once
+
+#include <android/hardware/graphics/mapper/4.0/IMapper.h>
+#include <log/log.h>
+
+#include "metadata.h"
+#include "utils.h"
+
+namespace pixel::graphics::mapper {
+
+namespace {
+
+using android::hardware::graphics::mapper::V4_0::Error;
+using android::hardware::graphics::mapper::V4_0::IMapper;
+using namespace ::pixel::graphics;
+
+static inline android::sp<IMapper> get_mapper() {
+    static android::sp<IMapper> mapper = []() {
+        auto mapper = IMapper::getService();
+        if (!mapper) {
+            ALOGE("Failed to get mapper service");
+        }
+        return mapper;
+    }();
+
+    return mapper;
+}
+
+} // namespace
+
+template <MetadataType meta>
+std::optional<typename metadata::ReturnType<meta>::type> get(buffer_handle_t handle) {
+    auto mapper = get_mapper();
+    IMapper::MetadataType type = {
+            .name = kPixelMetadataTypeName,
+            .value = static_cast<int64_t>(meta),
+    };
+
+    android::hardware::hidl_vec<uint8_t> vec;
+    Error error;
+    auto ret = mapper->get(const_cast<native_handle_t*>(handle), type,
+                           [&](const auto& tmpError,
+                               const android::hardware::hidl_vec<uint8_t>& tmpVec) {
+                               error = tmpError;
+                               vec = tmpVec;
+                           });
+    if (!ret.isOk()) {
+        return {};
+    }
+
+    return utils::decode<typename metadata::ReturnType<meta>::type>(vec);
+}
+
+template <MetadataType meta>
+int32_t set(buffer_handle_t handle, typename metadata::ReturnType<meta>::type data) {
+    android::sp<IMapper> mapper = get_mapper();
+    auto encoded_data = utils::encode<typename metadata::ReturnType<meta>::type>(data);
+    IMapper::MetadataType type = {
+            .name = kPixelMetadataTypeName,
+            .value = static_cast<int64_t>(meta),
+    };
+
+    Error err = mapper->set(const_cast<native_handle_t*>(handle), type, encoded_data);
+
+    return static_cast<int32_t>(err);
+}
+
+} // namespace pixel::graphics::mapper
diff --git a/gralloc-headers/pixel-gralloc/mapper5.h b/gralloc-headers/pixel-gralloc/mapper5.h
new file mode 100644
index 0000000..07bc2ba
--- /dev/null
+++ b/gralloc-headers/pixel-gralloc/mapper5.h
@@ -0,0 +1,80 @@
+#pragma once
+
+#include <log/log.h>
+
+#include <android/hardware/graphics/mapper/IMapper.h>
+#include <android/hardware/graphics/mapper/utils/IMapperMetadataTypes.h>
+#include <android/hardware/graphics/mapper/utils/IMapperProvider.h>
+#include <dlfcn.h>
+#include <vndksupport/linker.h>
+
+#include "metadata.h"
+#include "utils.h"
+
+namespace pixel::graphics::mapper {
+
+namespace {
+
+using namespace ::pixel::graphics;
+
+AIMapper* get_mapper() {
+    static AIMapper* mMapper = []() {
+        AIMapper* mapper = nullptr;
+        std::string_view so_name = "mapper.pixel.so";
+        void* so_lib = android_load_sphal_library(so_name.data(), RTLD_LOCAL | RTLD_NOW);
+        if (so_lib == nullptr) return mapper;
+        auto load_fn = reinterpret_cast<decltype(AIMapper_loadIMapper)*>(
+                dlsym(so_lib, "AIMapper_loadIMapper"));
+        if (load_fn == nullptr) return mapper;
+        load_fn(&mapper);
+        return mapper;
+    }();
+    if (!mMapper) {
+        ALOGI("Mapper5 unavailable");
+        return {};
+    } else {
+        return mMapper;
+    }
+}
+
+} // namespace
+
+template <MetadataType meta>
+std::optional<typename metadata::ReturnType<meta>::type> get(buffer_handle_t handle) {
+    AIMapper_MetadataType type = {
+            .name = kPixelMetadataTypeName,
+            .value = static_cast<int64_t>(meta),
+    };
+
+    auto mapper = get_mapper();
+    android::hardware::hidl_vec<uint8_t> vec;
+    std::vector<uint8_t> metabuf;
+    auto ret = mapper->v5.getMetadata(handle, type, metabuf.data(), 0);
+    if (ret < 0) {
+        return {};
+    }
+
+    metabuf.resize(ret);
+    ret = mapper->v5.getMetadata(handle, type, metabuf.data(), metabuf.size());
+
+    if (ret < 0) {
+        return {};
+    }
+    return utils::decode<typename metadata::ReturnType<meta>::type>(metabuf);
+}
+
+template <MetadataType meta>
+int64_t set(buffer_handle_t handle, typename metadata::ReturnType<meta>::type data) {
+    auto encoded_data = utils::encode<typename metadata::ReturnType<meta>::type>(data);
+    auto mapper = get_mapper();
+    AIMapper_MetadataType type = {
+            .name = kPixelMetadataTypeName,
+            .value = static_cast<int64_t>(meta),
+    };
+
+    auto ret = mapper->v5.setMetadata(handle, type, encoded_data.data(), encoded_data.size());
+
+    return ret;
+}
+
+} // namespace pixel::graphics::mapper
diff --git a/gralloc-headers/pixel-gralloc/metadata.h b/gralloc-headers/pixel-gralloc/metadata.h
index 06791f9..c59f3ee 100644
--- a/gralloc-headers/pixel-gralloc/metadata.h
+++ b/gralloc-headers/pixel-gralloc/metadata.h
@@ -6,6 +6,9 @@
 #include <cstdint>
 #include <limits>
 
+#include "format.h"
+#include "format_type.h"
+
 namespace pixel::graphics {
 
 constexpr const char* kGralloc4StandardMetadataTypeName = GRALLOC4_STANDARD_METADATA_TYPE;
@@ -105,4 +108,34 @@ struct CompressedPlaneLayout {
     bool operator!=(const CompressedPlaneLayout& other) const { return !(*this == other); }
 };
 
+template <MetadataType T>
+struct always_false : std::false_type {};
+
+namespace metadata {
+
+template <MetadataType T>
+struct ReturnType {
+    static_assert(always_false<T>::value, "Unspecialized ReturnType is not supported");
+    using type = void;
+};
+
+#define DEFINE_TYPE(meta_name, return_type)      \
+    template <>                                  \
+    struct ReturnType<MetadataType::meta_name> { \
+        using type = return_type;                \
+    };
+
+DEFINE_TYPE(PLANE_DMA_BUFS, std::vector<int>);
+DEFINE_TYPE(VIDEO_HDR, void*);
+DEFINE_TYPE(VIDEO_ROI, void*);
+DEFINE_TYPE(VIDEO_GMV, VideoGMV);
+
+DEFINE_TYPE(COMPRESSED_PLANE_LAYOUTS, std::vector<CompressedPlaneLayout>);
+DEFINE_TYPE(PIXEL_FORMAT_ALLOCATED, Format);
+DEFINE_TYPE(FORMAT_TYPE, FormatType);
+
+#undef DEFINE_TYPE
+
+} // namespace metadata
+
 } // namespace pixel::graphics
diff --git a/gralloc-headers/pixel-gralloc/usage.h b/gralloc-headers/pixel-gralloc/usage.h
index 660f495..afc0142 100644
--- a/gralloc-headers/pixel-gralloc/usage.h
+++ b/gralloc-headers/pixel-gralloc/usage.h
@@ -46,13 +46,20 @@ enum Usage : uint64_t {
 
     NO_COMPRESSION = 1ULL << 29,
 
+    JPEG = 1ULL << 30,
+
+    TPU_OUTPUT = 1ULL << 31,
+
     // Video IPs. These flags only make sense in combination with VIDEO_ENCODER/VIDEO_DECODER usage
     // flags
     MFC = 1ULL << 50,
     BO = 1ULL << 51,
     BW = BO,
 
-    // Used for the camera ISP image heap of the dual PD buffer.
+    // Used to identify the remosaic sub-block of camera
+    REMOSAIC = 1ULL << 61,
+
+    // Used for the camera ISP image heap of the dual PD buffer
     TPU_INPUT = 1ULL << 62,
 
     // Used to select specific heap for faceauth raw images used for evaluation
diff --git a/gralloc-headers/pixel-gralloc/utils.h b/gralloc-headers/pixel-gralloc/utils.h
index 993ca16..e20a226 100644
--- a/gralloc-headers/pixel-gralloc/utils.h
+++ b/gralloc-headers/pixel-gralloc/utils.h
@@ -1,8 +1,12 @@
 #pragma once
 
+#include <pixel-gralloc/format.h>
+#include <pixel-gralloc/usage.h>
+
 #include <cstdint>
 #include <cstring>
 #include <optional>
+#include <string>
 #include <type_traits>
 #include <vector>
 
@@ -85,4 +89,69 @@ std::optional<T> decode(const std::vector<uint8_t>& bytes) {
     return decode_helper<T>(bytes);
 }
 
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
+
 } // namespace pixel::graphics::utils
diff --git a/hwc3/Android.mk b/hwc3/Android.mk
index 28016fc..691fa08 100644
--- a/hwc3/Android.mk
+++ b/hwc3/Android.mk
@@ -32,12 +32,12 @@ LOCAL_CFLAGS += \
 	-Wthread-safety
 
 # hwc3 re-uses hwc2.2 ComposerResource and libexynosdisplay
-LOCAL_SHARED_LIBRARIES := android.hardware.graphics.composer3-V3-ndk \
+LOCAL_SHARED_LIBRARIES := android.hardware.graphics.composer3-V4-ndk \
 	android.hardware.graphics.composer@2.1-resources \
         android.hardware.graphics.composer@2.2-resources \
 	android.hardware.graphics.composer@2.4 \
 	android.hardware.drm-V1-ndk \
-	com.google.hardware.pixel.display-V12-ndk \
+	com.google.hardware.pixel.display-V13-ndk \
 	android.frameworks.stats-V2-ndk \
 	libpixelatoms_defs \
 	pixelatoms-cpp \
diff --git a/hwc3/Composer.cpp b/hwc3/Composer.cpp
index 1bee9cf..e8d7eec 100644
--- a/hwc3/Composer.cpp
+++ b/hwc3/Composer.cpp
@@ -61,9 +61,14 @@ ndk::ScopedAStatus Composer::createClient(std::shared_ptr<IComposerClient>* outC
     return ndk::ScopedAStatus::ok();
 }
 
-binder_status_t Composer::dump(int fd, const char** /*args*/, uint32_t /*numArgs*/) {
+binder_status_t Composer::dump(int fd, const char** args, uint32_t numArgs) {
+    std::vector<std::string> argsVector(numArgs);
+    for (uint32_t i = 0; i < numArgs; ++i) {
+        argsVector[i] = args[i];
+    }
+
     std::string output;
-    mHal->dumpDebugInfo(&output);
+    mHal->dumpDebugInfo(&output, argsVector);
     write(fd, output.c_str(), output.size());
     return STATUS_OK;
 }
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
index 6eb0dcc..73b53f0 100644
--- a/hwc3/ComposerClient.cpp
+++ b/hwc3/ComposerClient.cpp
@@ -527,6 +527,15 @@ void ComposerClient::HalEventCallback::onHotplugEvent(int64_t display,
     }
 }
 
+void ComposerClient::HalEventCallback::onHdcpLevelsChanged(int64_t display,
+                                                           drm::HdcpLevels levels) {
+    DEBUG_DISPLAY_FUNC(display);
+    auto ret = mCallback->onHdcpLevelsChanged(display, levels);
+    if (!ret.isOk()) {
+        LOG(ERROR) << "failed to send onHdcpLevelsChanged:" << ret.getDescription();
+    }
+}
+
 void ComposerClient::HalEventCallback::processDisplayResources(int64_t display, bool connected) {
     if (connected) {
         if (mResources->hasDisplay(display)) {
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
index bb07063..b07bdc8 100644
--- a/hwc3/ComposerClient.h
+++ b/hwc3/ComposerClient.h
@@ -51,6 +51,7 @@ public:
           void onSeamlessPossible(int64_t display) override;
           void onRefreshRateChangedDebug(const RefreshRateChangedDebugData& data) override;
           void onHotplugEvent(int64_t display, common::DisplayHotplugEvent event) override;
+          void onHdcpLevelsChanged(int64_t display, drm::HdcpLevels event) override;
 
       private:
         void processDisplayResources(int64_t display, bool connected);
diff --git a/hwc3/hwc3-default.xml b/hwc3/hwc3-default.xml
index 911f7f8..7debcf9 100644
--- a/hwc3/hwc3-default.xml
+++ b/hwc3/hwc3-default.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.graphics.composer3</name>
-        <version>3</version>
+        <version>4</version>
         <interface>
             <name>IComposer</name>
             <instance>default</instance>
diff --git a/hwc3/impl/HalImpl.cpp b/hwc3/impl/HalImpl.cpp
index 78c7b4a..77a27a2 100644
--- a/hwc3/impl/HalImpl.cpp
+++ b/hwc3/impl/HalImpl.cpp
@@ -133,6 +133,15 @@ void hotplugEvent(hwc2_callback_data_t callbackData, hwc2_display_t hwcDisplay,
     hal->getEventCallback()->onHotplugEvent(display, hotplugEvent);
 }
 
+void hdcpLevelsChanged(hwc2_callback_data_t callbackData, hwc2_display_t hwcDisplay,
+                       HdcpLevels levels) {
+    auto hal = static_cast<HalImpl*>(callbackData);
+    int64_t display;
+
+    h2a::translate(hwcDisplay, display);
+    hal->getEventCallback()->onHdcpLevelsChanged(display, levels);
+}
+
 } // nampesapce hook
 
 HalImpl::HalImpl(std::unique_ptr<ExynosDevice> device, bool batchingSupported)
@@ -216,11 +225,11 @@ void HalImpl::getCapabilities(std::vector<Capability>* caps) {
     caps->insert(caps->begin(), mCaps.begin(), mCaps.end());
 }
 
-void HalImpl::dumpDebugInfo(std::string* output) {
+void HalImpl::dumpDebugInfo(std::string* output, const std::vector<std::string>& args /* = {} */) {
     if (output == nullptr) return;
 
     String8 result;
-    mDevice->dump(result);
+    mDevice->dump(result, args);
 
     output->resize(result.size());
     output->assign(result.c_str());
@@ -249,6 +258,9 @@ void HalImpl::registerEventCallback(EventCallback* callback) {
     // Don't register onHotplugEvent until it's available in nextfood (b/323291596)
     // mDevice->registerHwc3Callback(IComposerCallback::TRANSACTION_onHotplugEvent, this,
     //                             reinterpret_cast<hwc2_function_pointer_t>(hook::hotplugEvent));
+    // Don't register onHdcpLevelsChanged until it's available in nextfood
+    // mDevice->registerHwc3Callback(IComposerCallback::TRANSACTION_onHdcpLevelsChanged, this,
+    //                             reinterpret_cast<hwc2_function_pointer_t>(hook::hdcpLevelsChanged));
 }
 
 void HalImpl::unregisterEventCallback() {
@@ -264,6 +276,9 @@ void HalImpl::unregisterEventCallback() {
                                   nullptr);
     // Don't register onHotplugEvent until it's available in nextfood (b/323291596)
     // mDevice->registerHwc3Callback(IComposerCallback::TRANSACTION_onHotplugEvent, this, nullptr);
+    // Don't register onHdcpLevelsChanged until it's available in nextfood
+    // mDevice->registerHwc3Callback(IComposerCallback::TRANSACTION_onHdcpLevelsChanged, this,
+    // nullptr);
 
     mEventCallback = nullptr;
 }
diff --git a/hwc3/impl/HalImpl.h b/hwc3/impl/HalImpl.h
index 8053901..c037291 100644
--- a/hwc3/impl/HalImpl.h
+++ b/hwc3/impl/HalImpl.h
@@ -40,7 +40,7 @@ class HalImpl : public IComposerHal {
       virtual ~HalImpl() = default;
 
       void getCapabilities(std::vector<Capability>* caps) override;
-      void dumpDebugInfo(std::string* output) override;
+      void dumpDebugInfo(std::string* output, const std::vector<std::string>& args) override;
       bool hasCapability(Capability cap) override;
 
       void registerEventCallback(EventCallback* callback) override;
diff --git a/hwc3/include/IComposerHal.h b/hwc3/include/IComposerHal.h
index 9961f79..71fa2ad 100644
--- a/hwc3/include/IComposerHal.h
+++ b/hwc3/include/IComposerHal.h
@@ -21,6 +21,7 @@
  * does own the fences).
  */
 #include <aidl/android/hardware/common/NativeHandle.h>
+#include <aidl/android/hardware/drm/HdcpLevels.h>
 #include <aidl/android/hardware/graphics/common/BlendMode.h>
 #include <aidl/android/hardware/graphics/common/ColorTransform.h>
 #include <aidl/android/hardware/graphics/common/Dataspace.h>
@@ -98,7 +99,7 @@ class IComposerHal {
      virtual ~IComposerHal() = default;
 
      virtual void getCapabilities(std::vector<Capability>* caps) = 0;
-     virtual void dumpDebugInfo(std::string* output) = 0;
+     virtual void dumpDebugInfo(std::string* output, const std::vector<std::string>& args = {}) = 0;
      virtual bool hasCapability(Capability cap) = 0;
 
      class EventCallback {
@@ -113,6 +114,7 @@ class IComposerHal {
          virtual void onSeamlessPossible(int64_t display) = 0;
          virtual void onRefreshRateChangedDebug(const RefreshRateChangedDebugData& data) = 0;
          virtual void onHotplugEvent(int64_t display, common::DisplayHotplugEvent event) = 0;
+         virtual void onHdcpLevelsChanged(int64_t display, drm::HdcpLevels levels) = 0;
      };
     virtual void registerEventCallback(EventCallback* callback) = 0;
     virtual void unregisterEventCallback() = 0;
diff --git a/include/Android.bp b/include/Android.bp
new file mode 100644
index 0000000..fc4377d
--- /dev/null
+++ b/include/Android.bp
@@ -0,0 +1,14 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_headers {
+    name: "displaycolor_common_headers",
+    vendor_available: true,
+    export_include_dirs: [
+        ".",
+    ],
+    visibility: [
+        "//visibility:public",
+    ],
+}
diff --git a/include/displaycolor/displaycolor.h b/include/displaycolor/displaycolor.h
index b25d93b..984515c 100644
--- a/include/displaycolor/displaycolor.h
+++ b/include/displaycolor/displaycolor.h
@@ -142,6 +142,7 @@ class IBrightnessTable {
 
     virtual std::optional<std::reference_wrapper<const DisplayBrightnessRange>> GetBrightnessRange(
         BrightnessMode bm) const = 0;
+    virtual std::optional<uint32_t> BrightnessToDbv(float brightness) const = 0;
     virtual std::optional<float> BrightnessToNits(float brightness, BrightnessMode &bm) const = 0;
     virtual std::optional<uint32_t> NitsToDbv(BrightnessMode bm, float nits) const = 0;
     virtual std::optional<float> DbvToNits(BrightnessMode bm, uint32_t dbv) const = 0;
@@ -161,6 +162,10 @@ struct DisplayInfo {
 
     // If brightness table exists in pb file, it will overwrite values in brightness_ranges
     BrightnessRangeMap brightness_ranges;
+
+    // displays that no need to calibrate like virtual or external displays
+    // expect the pipeline outputs pixels with a standard color space
+    bool standard_calibrated_display{false};
 };
 
 struct Color {
@@ -329,12 +334,52 @@ struct LayerColorData {
     bool enabled = true;
 };
 
+struct LtmParams {
+    struct Display {
+        int32_t width{};
+        int32_t height{};
+        bool operator==(const Display &rhs) const {
+          return width == rhs.width && height == rhs.height;
+        }
+    };
+
+    struct Roi {
+        int32_t left{};
+        int32_t top{};
+        int32_t right{};
+        int32_t bottom{};
+
+        bool Valid(int32_t display_width, int32_t display_height) const {
+            return left >= 0 && right > left && right <= display_width &&
+                top >= 0 && bottom > top && bottom <= display_height;
+        }
+
+        bool operator==(const Roi &rhs) const {
+          return left == rhs.left &&
+              top == rhs.top &&
+              right == rhs.right &&
+              bottom == rhs.bottom;
+        }
+    };
+
+    Display display;
+    Roi roi;
+    // for debug purpose
+    bool force_enable{};
+    bool operator==(const LtmParams &rhs) const {
+        return display == rhs.display && roi == rhs.roi && force_enable == rhs.force_enable;
+    }
+};
+
 /**
  * @brief DisplayScene holds all the information required for libdisplaycolor to
  * return correct data.
  */
 struct DisplayScene {
     bool operator==(const DisplayScene &rhs) const {
+        // TODO: if lux is used by HDR tone mapping, need to check here
+        // but should trigger scene change as less as possible, for example,
+        // only when HDR is on screen and lux change exceeds some threshold.
         return layer_data == rhs.layer_data &&
                dpu_bit_depth == rhs.dpu_bit_depth &&
                color_mode == rhs.color_mode &&
@@ -394,6 +439,12 @@ struct DisplayScene {
 
     /// hdr layer state on screen
     HdrLayerState hdr_layer_state = HdrLayerState::kHdrNone;
+
+    /// ambient lux
+    float lux{};
+
+    /// Ltm params gathered in HWC
+    LtmParams ltm_params;
 };
 
 struct CalibrationInfo {
@@ -551,6 +602,15 @@ class IDisplayColorGeneric {
      * the displaycolor internal states and need to apply to next frame update.
      */
     virtual bool CheckUpdateNeeded(const int64_t display) = 0;
+
+    /**
+     * @brief Check if early power on is needed.
+     *
+     * @return true for yes.
+     */
+    //deprecated by the 'int64_t display' version
+    virtual bool IsEarlyPowerOnNeeded(const DisplayType display) = 0;
+    virtual bool IsEarlyPowerOnNeeded(const int64_t display) = 0;
 };
 
 extern "C" {
diff --git a/libhwc2.1/Android.mk b/libhwc2.1/Android.mk
index d87b87e..4df3bf1 100644
--- a/libhwc2.1/Android.mk
+++ b/libhwc2.1/Android.mk
@@ -83,9 +83,9 @@ LOCAL_SHARED_LIBRARIES := liblog libcutils libhardware \
 	android.hardware.power-V2-ndk pixel-power-ext-V1-ndk \
 	pixel_stateresidency_provider_aidl_interface-ndk
 
-LOCAL_SHARED_LIBRARIES += android.hardware.graphics.composer3-V3-ndk \
+LOCAL_SHARED_LIBRARIES += android.hardware.graphics.composer3-V4-ndk \
                           android.hardware.drm-V1-ndk \
-                          com.google.hardware.pixel.display-V12-ndk \
+                          com.google.hardware.pixel.display-V13-ndk \
                           android.frameworks.stats-V2-ndk \
                           libpixelatoms_defs \
                           pixelatoms-cpp \
@@ -148,7 +148,7 @@ LOCAL_SRC_FILES := \
 	libdisplayinterface/ExynosDisplayDrmInterface.cpp \
 	libvrr/display/common/CommonDisplayContextProvider.cpp \
 	libvrr/display/exynos/ExynosDisplayContextProvider.cpp \
-	libvrr/Power/PowerStatsPresentProfileTokenGenerator.cpp \
+	libvrr/Power/PowerStatsProfileTokenGenerator.cpp \
 	libvrr/Power/DisplayStateResidencyProvider.cpp \
 	libvrr/Power/DisplayStateResidencyWatcher.cpp \
 	libvrr/FileNode.cpp \
@@ -217,10 +217,10 @@ LOCAL_SHARED_LIBRARIES := liblog libcutils libutils libbinder libexynosdisplay l
 	android.hardware.graphics.composer@2.4 \
 	android.hardware.graphics.allocator@2.0 \
 	android.hardware.graphics.mapper@2.0 \
-	android.hardware.graphics.composer3-V3-ndk \
+	android.hardware.graphics.composer3-V4-ndk \
 	android.hardware.drm-V1-ndk
 
-LOCAL_SHARED_LIBRARIES += com.google.hardware.pixel.display-V12-ndk \
+LOCAL_SHARED_LIBRARIES += com.google.hardware.pixel.display-V13-ndk \
                           android.frameworks.stats-V2-ndk \
                           libpixelatoms_defs \
                           pixelatoms-cpp \
@@ -299,9 +299,9 @@ LOCAL_SHARED_LIBRARIES := liblog libcutils libutils libexynosdisplay libacryl \
 	android.hardware.graphics.mapper@2.0 \
 	libui
 
-LOCAL_SHARED_LIBRARIES += android.hardware.graphics.composer3-V3-ndk \
+LOCAL_SHARED_LIBRARIES += android.hardware.graphics.composer3-V4-ndk \
                           android.hardware.drm-V1-ndk \
-                          com.google.hardware.pixel.display-V12-ndk \
+                          com.google.hardware.pixel.display-V13-ndk \
                           android.frameworks.stats-V2-ndk \
                           libpixelatoms_defs \
                           pixelatoms-cpp \
diff --git a/libhwc2.1/libdevice/BrightnessController.cpp b/libhwc2.1/libdevice/BrightnessController.cpp
index d8055ed..cde1227 100644
--- a/libhwc2.1/libdevice/BrightnessController.cpp
+++ b/libhwc2.1/libdevice/BrightnessController.cpp
@@ -46,6 +46,23 @@ void BrightnessController::LinearBrightnessTable::Init(const struct brightness_c
     mIsValid = true;
 }
 
+// cannot use linear interpolation between brightness and dbv because they have
+// a bilinear relationship
+std::optional<uint32_t> BrightnessController::LinearBrightnessTable::BrightnessToDbv(
+        float brightness) const {
+    BrightnessMode bm = GetBrightnessMode(brightness);
+    if (bm == BrightnessMode::BM_INVALID) {
+        return std::nullopt;
+    }
+
+    std::optional<float> nits = BrightnessToNits(brightness, bm);
+    if (nits == std::nullopt) {
+        return std::nullopt;
+    }
+
+    return NitsToDbv(bm, nits.value());
+}
+
 std::optional<float> BrightnessController::LinearBrightnessTable::NitsToBrightness(
         float nits) const {
     BrightnessMode mode = GetBrightnessModeForNits(nits);
@@ -647,6 +664,7 @@ int BrightnessController::processOperationRate(int32_t hz) {
 }
 
 void BrightnessController::onClearDisplay(bool needModeClear) {
+    ATRACE_CALL();
     resetLhbmState();
     mInstantHbmReq.reset(false);
 
diff --git a/libhwc2.1/libdevice/BrightnessController.h b/libhwc2.1/libdevice/BrightnessController.h
index c86171c..bafbc22 100644
--- a/libhwc2.1/libdevice/BrightnessController.h
+++ b/libhwc2.1/libdevice/BrightnessController.h
@@ -287,6 +287,7 @@ private:
             }
             return mBrightnessRanges.at(bm);
         }
+        std::optional<uint32_t> BrightnessToDbv(float brightness) const override;
         std::optional<float> BrightnessToNits(float brightness, BrightnessMode& bm) const override;
         std::optional<float> NitsToBrightness(float nits) const override;
         std::optional<float> DbvToBrightness(uint32_t dbv) const override;
diff --git a/libhwc2.1/libdevice/DisplayTe2Manager.cpp b/libhwc2.1/libdevice/DisplayTe2Manager.cpp
index dd3af49..bea78d2 100644
--- a/libhwc2.1/libdevice/DisplayTe2Manager.cpp
+++ b/libhwc2.1/libdevice/DisplayTe2Manager.cpp
@@ -25,7 +25,10 @@ DisplayTe2Manager::DisplayTe2Manager(ExynosDisplay* display, int32_t panelIndex,
         mIsOptionFixedTe2(true),
         mRefreshRateChangeListenerRegistered(false),
         mPendingOptionChangeableTe2(false),
-        mPendingFixedTe2Rate(0) {}
+        mPendingFixedTe2Rate(0) {
+    mProximitySensorStateNotifierWorker =
+            std::make_unique<ProximitySensorStateNotifierWorker>(this);
+}
 
 void DisplayTe2Manager::setTe2Option(bool fixedTe2) {
     int32_t ret = writeIntToFile(getPanelTe2OptionPath(), fixedTe2);
@@ -143,6 +146,14 @@ void DisplayTe2Manager::onRefreshRateChange(int refreshRate) {
     if (!mIsOptionFixedTe2 && refreshRate) setChangeableTe2Rate(refreshRate);
 }
 
+void DisplayTe2Manager::handleProximitySensorStateChange(bool active) {
+    if (mProximitySensorStateNotifierWorker) {
+        mProximitySensorStateNotifierWorker->onStateChanged(active);
+    } else {
+        ALOGW("DisplayTe2Manager::%s unable to handle the state change", __func__);
+    }
+}
+
 void DisplayTe2Manager::dump(String8& result) const {
     result.appendFormat("DisplayTe2Manager:\n");
     result.appendFormat("\tmin refresh rate for fixed TE2: %d\n", mMinRefreshRateForFixedTe2);
@@ -153,3 +164,64 @@ void DisplayTe2Manager::dump(String8& result) const {
     }
     result.appendFormat("\n");
 }
+
+DisplayTe2Manager::ProximitySensorStateNotifierWorker::ProximitySensorStateNotifierWorker(
+        DisplayTe2Manager* te2Manager)
+      : Worker("ProximitySensorStateNotifierWorker", HAL_PRIORITY_URGENT_DISPLAY),
+        mTe2Manager(te2Manager),
+        mIsStateActive(false),
+        mReceivedFirstStateAfterTimeout(false),
+        mPendingState(ProximitySensorState::NONE) {
+    InitWorker();
+}
+
+DisplayTe2Manager::ProximitySensorStateNotifierWorker::~ProximitySensorStateNotifierWorker() {
+    Exit();
+}
+
+void DisplayTe2Manager::ProximitySensorStateNotifierWorker::onStateChanged(bool active) {
+    Lock();
+    mIsStateActive = active;
+    Unlock();
+    Signal();
+}
+
+void DisplayTe2Manager::ProximitySensorStateNotifierWorker::Routine() {
+    int ret;
+    Lock();
+    ret = WaitForSignalOrExitLocked(ms2ns(kDebounceTimeMs));
+    if (ret == -EINTR) {
+        ALOGE("ProximitySensorStateNotifierWorker: failed to wait for signal");
+        mReceivedFirstStateAfterTimeout = false;
+        Unlock();
+        return;
+    }
+
+    if (!mReceivedFirstStateAfterTimeout) {
+        if (ret != -ETIMEDOUT) {
+            // the 1st signal after timeout, send the notification immediately
+            ALOGI("ProximitySensorStateNotifierWorker: %s: notify state (%d)", __func__,
+                  mIsStateActive);
+            mTe2Manager->mDisplay->onProximitySensorStateChanged(mIsStateActive);
+            mReceivedFirstStateAfterTimeout = true;
+        }
+    } else {
+        if (ret != -ETIMEDOUT) {
+            // receive the signal within kDebounceTimeMs, update the pending state
+            mPendingState =
+                    mIsStateActive ? ProximitySensorState::ACTIVE : ProximitySensorState::INACTIVE;
+        } else {
+            // no signal within kDebounceTimeMs, notify the pending state if it exists
+            if (mPendingState != ProximitySensorState::NONE) {
+                mIsStateActive = (mPendingState == ProximitySensorState::ACTIVE);
+                ALOGI("ProximitySensorStateNotifierWorker: %s: notify pending state (%d)", __func__,
+                      mIsStateActive);
+                mTe2Manager->mDisplay->onProximitySensorStateChanged(mIsStateActive);
+                mPendingState = ProximitySensorState::NONE;
+            } else {
+                mReceivedFirstStateAfterTimeout = false;
+            }
+        }
+    }
+    Unlock();
+}
diff --git a/libhwc2.1/libdevice/DisplayTe2Manager.h b/libhwc2.1/libdevice/DisplayTe2Manager.h
index 53f5ed0..92cf5c5 100644
--- a/libhwc2.1/libdevice/DisplayTe2Manager.h
+++ b/libhwc2.1/libdevice/DisplayTe2Manager.h
@@ -20,6 +20,12 @@
 #include "ExynosDisplay.h"
 #include "ExynosHWCHelper.h"
 
+enum class ProximitySensorState : uint32_t {
+    NONE = 0,
+    ACTIVE,
+    INACTIVE,
+};
+
 // TODO: Rename this and integrate with refresh rate throttler related features into this class.
 class DisplayTe2Manager : public RefreshRateChangeListener {
 public:
@@ -48,9 +54,17 @@ public:
     // restore the previous settings to keep the request from ALSP.
     void restoreTe2FromDozeMode();
 
+    // Handle the notifications while the proximity sensor state is changed.
+    void handleProximitySensorStateChange(bool active);
+
     void dump(String8& result) const;
 
 private:
+    static constexpr const char* kTe2RateFileNode =
+            "/sys/devices/platform/exynos-drm/%s-panel/te2_rate_hz";
+    static constexpr const char* kTe2OptionFileNode =
+            "/sys/devices/platform/exynos-drm/%s-panel/te2_option";
+
     const char* getPanelString() {
         return (mPanelIndex == 0 ? "primary" : mPanelIndex == 1 ? "secondary" : "unknown");
     }
@@ -94,10 +108,26 @@ private:
 
     Mutex mTe2Mutex;
 
-    static constexpr const char* kTe2RateFileNode =
-            "/sys/devices/platform/exynos-drm/%s-panel/te2_rate_hz";
-    static constexpr const char* kTe2OptionFileNode =
-            "/sys/devices/platform/exynos-drm/%s-panel/te2_option";
+    class ProximitySensorStateNotifierWorker : public Worker {
+    public:
+        explicit ProximitySensorStateNotifierWorker(DisplayTe2Manager* te2Manager);
+        ~ProximitySensorStateNotifierWorker();
+
+        void onStateChanged(bool active);
+
+    protected:
+        void Routine() override;
+
+    private:
+        static constexpr uint32_t kDebounceTimeMs = 100U;
+
+        DisplayTe2Manager* mTe2Manager;
+        bool mIsStateActive;
+        bool mReceivedFirstStateAfterTimeout;
+        enum ProximitySensorState mPendingState;
+    };
+
+    std::unique_ptr<ProximitySensorStateNotifierWorker> mProximitySensorStateNotifierWorker;
 };
 
 #endif // _DISPLAY_TE2_MANAGER_H_
diff --git a/libhwc2.1/libdevice/ExynosDevice.cpp b/libhwc2.1/libdevice/ExynosDevice.cpp
index cf80bc1..5df8dc6 100644
--- a/libhwc2.1/libdevice/ExynosDevice.cpp
+++ b/libhwc2.1/libdevice/ExynosDevice.cpp
@@ -417,7 +417,7 @@ void ExynosDevice::dump(uint32_t *outSize, char *outBuffer) {
     }
 }
 
-void ExynosDevice::dump(String8 &result) {
+void ExynosDevice::dump(String8& result, const std::vector<std::string>& args) {
     result.append("\n\n");
 
     struct tm* localTime = (struct tm*)localtime((time_t*)&updateTimeInfo.lastUeventTime.tv_sec);
@@ -455,10 +455,14 @@ void ExynosDevice::dump(String8 &result) {
     }
     result.append("\n");
 
+    for (size_t i = 0; i < mDisplays.size(); i++) {
+        ExynosDisplay* display = mDisplays[i];
+        if (display->mPlugState == true) display->miniDump(result);
+    }
+
     for (size_t i = 0;i < mDisplays.size(); i++) {
         ExynosDisplay *display = mDisplays[i];
-        if (display->mPlugState == true)
-            display->dump(result);
+        if (display->mPlugState == true) display->dump(result, args);
     }
 }
 
@@ -704,6 +708,23 @@ void ExynosDevice::onVsyncPeriodTimingChanged(uint32_t displayId,
 void ExynosDevice::onContentProtectionUpdated(uint32_t displayId, HdcpLevels hdcpLevels) {
     Mutex::Autolock lock(mDeviceCallbackMutex);
 
+    // If the new HdcpLevelsChanged HAL API is available, use it, otherwise fall back
+    // to the old V2 API with onVsync hack, if necessary.
+    const auto& hdcpLevelsChangedCallback =
+            mHwc3CallbackInfos.find(IComposerCallback::TRANSACTION_onHdcpLevelsChanged);
+    if (hdcpLevelsChangedCallback != mHwc3CallbackInfos.end()) {
+        const auto& callbackInfo = hdcpLevelsChangedCallback->second;
+        if (callbackInfo.funcPointer != nullptr && callbackInfo.callbackData != nullptr) {
+            auto callbackFunc = reinterpret_cast<
+                    void (*)(hwc2_callback_data_t callbackData, hwc2_display_t hwcDisplay,
+                             aidl::android::hardware::drm::HdcpLevels)>(callbackInfo.funcPointer);
+            ALOGD("%s: displayId=%u hdcpLevels=%s sending to SF via v3 HAL", __func__, displayId,
+                  hdcpLevels.toString().c_str());
+            callbackFunc(callbackInfo.callbackData, displayId, hdcpLevels);
+            return;
+        }
+    }
+
     // Workaround to pass content protection updates to SurfaceFlinger
     // without changing HWC HAL interface.
     if (isCallbackRegisteredLocked(HWC2_CALLBACK_VSYNC_2_4)) {
diff --git a/libhwc2.1/libdevice/ExynosDevice.h b/libhwc2.1/libdevice/ExynosDevice.h
index 453aaf8..4f9e60d 100644
--- a/libhwc2.1/libdevice/ExynosDevice.h
+++ b/libhwc2.1/libdevice/ExynosDevice.h
@@ -315,7 +315,7 @@ class ExynosDevice {
         void checkDynamicRecompositionThread();
         int32_t setDisplayDeviceMode(int32_t display_id, int32_t mode);
         int32_t setPanelGammaTableSource(int32_t display_id, int32_t type, int32_t source);
-        void dump(String8 &result);
+        void dump(String8& result, const std::vector<std::string>& args = {});
 
         class captureReadbackClass {
             public:
diff --git a/libhwc2.1/libdevice/ExynosDisplay.cpp b/libhwc2.1/libdevice/ExynosDisplay.cpp
index f1774be..d1051b3 100644
--- a/libhwc2.1/libdevice/ExynosDisplay.cpp
+++ b/libhwc2.1/libdevice/ExynosDisplay.cpp
@@ -1155,9 +1155,8 @@ void ExynosDisplay::initDisplay() {
             ExynosMPP* m2mMPP = mLayers[i]->mM2mMPP;
 
             /* Close release fence of dst buffer of last frame */
-            if ((mLayers[i]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) &&
-                (m2mMPP != NULL) &&
-                (m2mMPP->mAssignedDisplay == this) &&
+            if ((mLayers[i]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) &&
+                (m2mMPP != NULL) && (m2mMPP->mAssignedDisplay == this) &&
                 (m2mMPP->getDstImageInfo(&outImage) == NO_ERROR)) {
                 if (m2mMPP->mPhysicalType == MPP_MSC) {
                     fence_close(outImage.releaseFenceFd, this, FENCE_TYPE_DST_RELEASE, FENCE_IP_MSC);
@@ -1254,6 +1253,7 @@ void ExynosDisplay::checkIgnoreLayers() {
         if ((layer->mLayerFlag & EXYNOS_HWC_IGNORE_LAYER) == 0) {
             mLayers.push_back(layer);
             it = mIgnoreLayers.erase(it);
+            layer->mOverlayInfo &= ~eIgnoreLayer;
         } else {
             it++;
         }
@@ -1263,7 +1263,7 @@ void ExynosDisplay::checkIgnoreLayers() {
         ExynosLayer *layer = mLayers[index];
         if (layer->mLayerFlag & EXYNOS_HWC_IGNORE_LAYER) {
             layer->resetValidateData();
-            layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE, eIgnoreLayer);
             /*
              * Directly close without counting down
              * because it was not counted by validate
@@ -1696,13 +1696,13 @@ int ExynosDisplay::skipStaticLayers(ExynosCompositionInfo& compositionInfo)
 
         for (size_t i = (size_t)compositionInfo.mFirstIndex; i <= (size_t)compositionInfo.mLastIndex; i++) {
             ExynosLayer *layer = mLayers[i];
-            if (layer->mValidateCompositionType == COMPOSITION_CLIENT) {
+            if (layer->getValidateCompositionType() == COMPOSITION_CLIENT) {
                 layer->mOverlayInfo |= eSkipStaticLayer;
             } else {
                 compositionInfo.mSkipStaticInitFlag = false;
                 if (layer->mOverlayPriority < ePriorityHigh) {
-                    DISPLAY_LOGE("[%zu] Invalid layer type: %d",
-                            i, layer->mValidateCompositionType);
+                    DISPLAY_LOGE("[%zu] Invalid layer type: %d", i,
+                                 layer->getValidateCompositionType());
                     return -EINVAL;
                 } else {
                     return NO_ERROR;
@@ -2994,14 +2994,15 @@ int32_t ExynosDisplay::acceptDisplayChanges() {
     for (size_t i = 0; i < mLayers.size(); i++) {
         if (mLayers[i] != NULL) {
             HDEBUGLOGD(eDebugDefault, "%s, Layer %zu : %d, %d", __func__, i,
-                    mLayers[i]->mExynosCompositionType, mLayers[i]->mValidateCompositionType);
+                       mLayers[i]->mExynosCompositionType,
+                       mLayers[i]->getValidateCompositionType());
             type = getLayerCompositionTypeForValidationType(i);
 
             /* update compositionType
              * SF updates their state and doesn't call back into HWC HAL
              */
             mLayers[i]->mCompositionType = type;
-            mLayers[i]->mExynosCompositionType = mLayers[i]->mValidateCompositionType;
+            mLayers[i]->mExynosCompositionType = mLayers[i]->getValidateCompositionType();
         }
         else {
             HWC_LOGE(this, "Layer %zu is NULL", i);
@@ -3057,27 +3058,27 @@ int32_t ExynosDisplay::getLayerCompositionTypeForValidationType(uint32_t layerIn
         DISPLAY_LOGE("invalid layer index (%d)", layerIndex);
         return type;
     }
-    if ((mLayers[layerIndex]->mValidateCompositionType == HWC2_COMPOSITION_CLIENT) &&
+    if ((mLayers[layerIndex]->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT) &&
         (mClientCompositionInfo.mSkipFlag) &&
         (mClientCompositionInfo.mFirstIndex <= (int32_t)layerIndex) &&
         ((int32_t)layerIndex <= mClientCompositionInfo.mLastIndex)) {
         type = HWC2_COMPOSITION_DEVICE;
-    } else if (mLayers[layerIndex]->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) {
+    } else if (mLayers[layerIndex]->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) {
         type = HWC2_COMPOSITION_DEVICE;
     } else if ((mLayers[layerIndex]->mCompositionType == HWC2_COMPOSITION_CURSOR) &&
-               (mLayers[layerIndex]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE)) {
+               (mLayers[layerIndex]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)) {
         if (mDisplayControl.cursorSupport == true)
             type = HWC2_COMPOSITION_CURSOR;
         else
             type = HWC2_COMPOSITION_DEVICE;
     } else if ((mLayers[layerIndex]->mCompositionType == HWC2_COMPOSITION_SOLID_COLOR) &&
-               (mLayers[layerIndex]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE)) {
+               (mLayers[layerIndex]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)) {
         type = HWC2_COMPOSITION_SOLID_COLOR;
     } else if ((mLayers[layerIndex]->mCompositionType == HWC2_COMPOSITION_REFRESH_RATE_INDICATOR) &&
-               (mLayers[layerIndex]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE)) {
+               (mLayers[layerIndex]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)) {
         type = HWC2_COMPOSITION_REFRESH_RATE_INDICATOR;
     } else {
-        type = mLayers[layerIndex]->mValidateCompositionType;
+        type = mLayers[layerIndex]->getValidateCompositionType();
     }
 
     return type;
@@ -3121,9 +3122,11 @@ int32_t ExynosDisplay::getChangedCompositionTypes(
 
     int32_t ret = 0;
     for (size_t i = 0; i < mLayers.size(); i++) {
-        DISPLAY_LOGD(eDebugHWC, "[%zu] layer: mCompositionType(%d), mValidateCompositionType(%d), mExynosCompositionType(%d), skipFlag(%d)",
-                i, mLayers[i]->mCompositionType, mLayers[i]->mValidateCompositionType,
-                mLayers[i]->mExynosCompositionType, mClientCompositionInfo.mSkipFlag);
+        DISPLAY_LOGD(eDebugHWC,
+                     "[%zu] layer: mCompositionType(%d), mValidateCompositionType(%d), "
+                     "mExynosCompositionType(%d), skipFlag(%d)",
+                     i, mLayers[i]->mCompositionType, mLayers[i]->getValidateCompositionType(),
+                     mLayers[i]->mExynosCompositionType, mClientCompositionInfo.mSkipFlag);
         if ((ret = set_out_param(mLayers[i], getLayerCompositionTypeForValidationType(i), count,
                                  *outNumElements, outLayers, outTypes)) < 0) {
             break;
@@ -3134,9 +3137,10 @@ int32_t ExynosDisplay::getChangedCompositionTypes(
             DISPLAY_LOGD(eDebugHWC,
                          "[%zu] ignore layer: mCompositionType(%d), mValidateCompositionType(%d)",
                          i, mIgnoreLayers[i]->mCompositionType,
-                         mIgnoreLayers[i]->mValidateCompositionType);
-            if ((ret = set_out_param(mIgnoreLayers[i], mIgnoreLayers[i]->mValidateCompositionType,
-                                     count, *outNumElements, outLayers, outTypes)) < 0) {
+                         mIgnoreLayers[i]->getValidateCompositionType());
+            if ((ret = set_out_param(mIgnoreLayers[i],
+                                     mIgnoreLayers[i]->getValidateCompositionType(), count,
+                                     *outNumElements, outLayers, outTypes)) < 0) {
                 break;
             }
         }
@@ -3918,11 +3922,10 @@ int32_t ExynosDisplay::presentDisplay(int32_t* outRetireFence) {
     /* Check all of acquireFence are closed */
     for (size_t i=0; i < mLayers.size(); i++) {
         if (mLayers[i]->mAcquireFence != -1) {
-            DISPLAY_LOGE("layer[%zu] fence(%d) type(%d, %d, %d) is not closed",
-                    i, mLayers[i]->mAcquireFence,
-                    mLayers[i]->mCompositionType,
-                    mLayers[i]->mExynosCompositionType,
-                    mLayers[i]->mValidateCompositionType);
+            DISPLAY_LOGE("layer[%zu] fence(%d) type(%d, %d, %d) is not closed", i,
+                         mLayers[i]->mAcquireFence, mLayers[i]->mCompositionType,
+                         mLayers[i]->mExynosCompositionType,
+                         mLayers[i]->getValidateCompositionType());
             if (mLayers[i]->mM2mMPP != NULL)
                 DISPLAY_LOGE("\t%s is assigned", mLayers[i]->mM2mMPP->mName.c_str());
             if (mLayers[i]->mAcquireFence > 0)
@@ -4623,6 +4626,8 @@ inline int32_t ExynosDisplay::getDisplayFrameScanoutPeriodFromConfig(hwc2_config
                 frameScanoutPeriodNs =
                         (frameScanoutPeriodNs <= opPeriodNs) ? frameScanoutPeriodNs : opPeriodNs;
             }
+        } else if (mDisplayConfigs[config].isBoost2xBts) {
+            frameScanoutPeriodNs = frameScanoutPeriodNs / 2;
         }
     }
 
@@ -4955,7 +4960,7 @@ int32_t ExynosDisplay::validateDisplay(
             for (size_t i = (size_t)mClientCompositionInfo.mFirstIndex; i <= (size_t)mClientCompositionInfo.mLastIndex; i++) {
                 if (mLayers[i]->mOverlayPriority >= ePriorityHigh)
                     continue;
-                mLayers[i]->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+                mLayers[i]->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT);
             }
         }
     }
@@ -4987,8 +4992,7 @@ int32_t ExynosDisplay::validateDisplay(
         mExynosCompositionInfo.initializeInfos(this);
         for (uint32_t i = 0; i < mLayers.size(); i++) {
             ExynosLayer *layer = mLayers[i];
-            layer->mOverlayInfo |= eResourceAssignFail;
-            layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eResourceAssignFail);
             addClientCompositionLayer(i);
         }
         mResourceManager->assignCompositionTarget(this, COMPOSITION_CLIENT);
@@ -5041,8 +5045,8 @@ int32_t ExynosDisplay::startPostProcessing()
 
     // loop for all layer
     for (size_t i=0; i < mLayers.size(); i++) {
-        if((mLayers[i]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) &&
-           (mLayers[i]->mM2mMPP != NULL)) {
+        if ((mLayers[i]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) &&
+            (mLayers[i]->mM2mMPP != NULL)) {
             /* mAcquireFence is updated, Update image info */
             struct exynos_image srcImg, dstImg, midImg;
             mLayers[i]->setSrcExynosImage(&srcImg);
@@ -5103,7 +5107,23 @@ void ExynosDisplay::dumpConfig(const exynos_win_config_data &c)
     }
 }
 
-void ExynosDisplay::dump(String8& result) {
+void ExynosDisplay::miniDump(String8& result)
+{
+    Mutex::Autolock lock(mDRMutex);
+    result.appendFormat("=======================  Mini dump  ================================\n");
+    TableBuilder tb;
+    ExynosSortedLayer allLayers = mLayers;
+    for (auto layer : mIgnoreLayers)
+        allLayers.push_back(layer);
+    allLayers.vector_sort();
+
+    for (auto layer : allLayers)
+        layer->miniDump(tb);
+
+    result.appendFormat("%s", tb.buildForMiniDump().c_str());
+}
+
+void ExynosDisplay::dump(String8 &result, const std::vector<std::string>& args) {
     Mutex::Autolock lock(mDisplayMutex);
     dumpLocked(result);
 }
@@ -5276,7 +5296,7 @@ int32_t ExynosDisplay::initializeValidateInfos()
     mCursorIndex = -1;
     for (uint32_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        layer->mValidateCompositionType = HWC2_COMPOSITION_INVALID;
+        layer->updateValidateCompositionType(HWC2_COMPOSITION_INVALID);
         layer->mOverlayInfo = 0;
         if ((mDisplayControl.cursorSupport == true) &&
             (mLayers[i]->mCompositionType == HWC2_COMPOSITION_CURSOR))
@@ -5334,17 +5354,16 @@ int32_t ExynosDisplay::addClientCompositionLayer(uint32_t layerIndex)
                          layer->mOverlayPriority);
             continue;
         }
-        if (layer->mValidateCompositionType != HWC2_COMPOSITION_CLIENT)
-        {
+        if (layer->getValidateCompositionType() != HWC2_COMPOSITION_CLIENT) {
             DISPLAY_LOGD(eDebugResourceManager, "\t[%d] layer changed", i);
-            if (layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS)
+            if (layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS)
                 exynosCompositionChanged = true;
             else {
-                if (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) mWindowNumUsed--;
+                if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)
+                    mWindowNumUsed--;
             }
             layer->resetAssignedResource();
-            layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
-            layer->mOverlayInfo |= eSandwitchedBetweenGLES;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eSandwichedBetweenGLES);
         }
     }
 
@@ -5368,7 +5387,7 @@ int32_t ExynosDisplay::addClientCompositionLayer(uint32_t layerIndex)
         for (uint32_t i = 0; i < mLayers.size(); i++)
         {
             ExynosLayer *exynosLayer = mLayers[i];
-            if (exynosLayer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) {
+            if (exynosLayer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) {
                 newFirstIndex = min(newFirstIndex, i);
                 newLastIndex = max(newLastIndex, (int32_t)i);
             }
@@ -5511,8 +5530,7 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
             continue;
         }
 
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS)
-            continue;
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) continue;
 
         exynos_image src_img;
         exynos_image dst_img;
@@ -5523,24 +5541,22 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
         if ((layer->mSupportedMPPFlag & m2mMPP->mLogicalType) != 0)
             isAssignable = m2mMPP->isAssignable(this, src_img, dst_img, totalUsedCapa);
 
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT)
-        {
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT) {
             DISPLAY_LOGD(eDebugResourceManager, "\t[%d] layer is client composition", i);
             invalidFlag = true;
         } else if (((layer->mSupportedMPPFlag & m2mMPP->mLogicalType) == 0) ||
-                   (isAssignable == false))
-        {
+                   (isAssignable == false)) {
             DISPLAY_LOGD(eDebugResourceManager, "\t[%d] layer is not supported by G2D", i);
             invalidFlag = true;
             layer->resetAssignedResource();
-            layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT);
             if ((ret = addClientCompositionLayer(i)) < 0)
                 return ret;
             changeFlag |= ret;
-        } else if ((layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) ||
-                   (layer->mValidateCompositionType == HWC2_COMPOSITION_INVALID)) {
+        } else if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) ||
+                   (layer->getValidateCompositionType() == HWC2_COMPOSITION_INVALID)) {
             DISPLAY_LOGD(eDebugResourceManager, "\t[%d] layer changed", i);
-            layer->mOverlayInfo |= eSandwitchedBetweenEXYNOS;
+            layer->mOverlayInfo |= eSandwichedBetweenEXYNOS;
             layer->resetAssignedResource();
             if ((ret = m2mMPP->assignMPP(this, layer)) != NO_ERROR)
             {
@@ -5548,13 +5564,13 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
                         __func__, m2mMPP->mName.c_str(), ret);
                 return ret;
             }
-            if (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) mWindowNumUsed--;
-            layer->mValidateCompositionType = HWC2_COMPOSITION_EXYNOS;
+            if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) mWindowNumUsed--;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_EXYNOS);
             mExynosCompositionInfo.mFirstIndex = min(mExynosCompositionInfo.mFirstIndex, (int32_t)i);
             mExynosCompositionInfo.mLastIndex = max(mExynosCompositionInfo.mLastIndex, (int32_t)i);
         } else {
             DISPLAY_LOGD(eDebugResourceManager, "\t[%d] layer has known type (%d)", i,
-                         layer->mValidateCompositionType);
+                         layer->getValidateCompositionType());
         }
     }
 
@@ -5570,18 +5586,18 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
 
             for (int32_t i = startIndex; i <= endIndex; i++) {
                 if (mLayers[i]->mOverlayPriority == ePriorityMax ||
-                        mLayers[i]->mValidateCompositionType == HWC2_COMPOSITION_CLIENT)
+                    mLayers[i]->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT)
                     continue;
                 mLayers[i]->resetAssignedResource();
-                mLayers[i]->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+                mLayers[i]->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT);
                 if ((ret = addClientCompositionLayer(i)) < 0)
                     return ret;
                 changeFlag |= ret;
             }
 
-            if (mLayers[maxPriorityIndex]->mValidateCompositionType
-                    != HWC2_COMPOSITION_EXYNOS) {
-                mLayers[maxPriorityIndex]->mValidateCompositionType = HWC2_COMPOSITION_EXYNOS;
+            if (mLayers[maxPriorityIndex]->getValidateCompositionType() !=
+                HWC2_COMPOSITION_EXYNOS) {
+                mLayers[maxPriorityIndex]->updateValidateCompositionType(HWC2_COMPOSITION_EXYNOS);
                 mLayers[maxPriorityIndex]->resetAssignedResource();
                 if ((ret = m2mMPP->assignMPP(this, mLayers[maxPriorityIndex])) != NO_ERROR)
                 {
@@ -5605,14 +5621,16 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
             if ((mClientCompositionInfo.mFirstIndex - mExynosCompositionInfo.mFirstIndex) <
                 (mExynosCompositionInfo.mLastIndex - mClientCompositionInfo.mLastIndex)) {
                 mLayers[mExynosCompositionInfo.mFirstIndex]->resetAssignedResource();
-                mLayers[mExynosCompositionInfo.mFirstIndex]->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+                mLayers[mExynosCompositionInfo.mFirstIndex]->updateValidateCompositionType(
+                        HWC2_COMPOSITION_CLIENT);
                 if ((ret = addClientCompositionLayer(mExynosCompositionInfo.mFirstIndex)) < 0)
                     return ret;
                 mExynosCompositionInfo.mFirstIndex = mClientCompositionInfo.mLastIndex + 1;
                 changeFlag |= ret;
             } else {
                 mLayers[mExynosCompositionInfo.mLastIndex]->resetAssignedResource();
-                mLayers[mExynosCompositionInfo.mLastIndex]->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+                mLayers[mExynosCompositionInfo.mLastIndex]->updateValidateCompositionType(
+                        HWC2_COMPOSITION_CLIENT);
                 if ((ret = addClientCompositionLayer(mExynosCompositionInfo.mLastIndex)) < 0)
                     return ret;
                 mExynosCompositionInfo.mLastIndex = (mClientCompositionInfo.mFirstIndex - 1);
@@ -5654,8 +5672,10 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
     if (highPriorityCheck && (m2mMPP->mLogicalType != MPP_LOGICAL_G2D_COMBO)) {
         startIndex = mExynosCompositionInfo.mFirstIndex;
         endIndex = mExynosCompositionInfo.mLastIndex;
-        DISPLAY_LOGD(eDebugResourceManager, "\texynos composition is disabled because of sandwitched max priority layer (%d, %d)",
-                mExynosCompositionInfo.mFirstIndex, mExynosCompositionInfo.mLastIndex);
+        DISPLAY_LOGD(eDebugResourceManager,
+                     "\texynos composition is disabled because of sandwiched max priority layer "
+                     "(%d, %d)",
+                     mExynosCompositionInfo.mFirstIndex, mExynosCompositionInfo.mLastIndex);
         for (int32_t i = startIndex; i <= endIndex; i++) {
             int32_t checkPri = 0;
             for (uint32_t j = 0; j < highPriorityNum; j++) {
@@ -5669,7 +5689,7 @@ int32_t ExynosDisplay::addExynosCompositionLayer(uint32_t layerIndex, float tota
                 continue;
 
             mLayers[i]->resetAssignedResource();
-            mLayers[i]->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+            mLayers[i]->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT);
             if ((ret = addClientCompositionLayer(i)) < 0)
                 HWC_LOGE(this, "%d layer: addClientCompositionLayer() fail", i);
         }
@@ -5963,9 +5983,8 @@ void ExynosDisplay::closeFencesForSkipFrame(rendering_state renderingState)
             for (size_t i = 0; i < mLayers.size(); i++) {
                 exynos_image outImage;
                 ExynosMPP* m2mMPP = mLayers[i]->mM2mMPP;
-                if ((mLayers[i]->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) &&
-                    (m2mMPP != NULL) &&
-                    (m2mMPP->mAssignedDisplay == this) &&
+                if ((mLayers[i]->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) &&
+                    (m2mMPP != NULL) && (m2mMPP->mAssignedDisplay == this) &&
                     (m2mMPP->getDstImageInfo(&outImage) == NO_ERROR)) {
                     if (m2mMPP->mPhysicalType == MPP_MSC) {
                         fence_close(outImage.releaseFenceFd, this, FENCE_TYPE_DST_RELEASE, FENCE_IP_MSC);
@@ -6447,34 +6466,6 @@ nsecs_t ExynosDisplay::getPredictedPresentTime(nsecs_t startTime) {
     return expectedPresentTime;
 }
 
-nsecs_t ExynosDisplay::getSignalTime(int32_t fd) const {
-    if (fd == -1) {
-        return SIGNAL_TIME_INVALID;
-    }
-
-    struct sync_file_info *finfo = sync_file_info(fd);
-    if (finfo == nullptr) {
-        return SIGNAL_TIME_INVALID;
-    }
-
-    if (finfo->status != 1) {
-        const auto status = finfo->status;
-        sync_file_info_free(finfo);
-        return status < 0 ? SIGNAL_TIME_INVALID : SIGNAL_TIME_PENDING;
-    }
-
-    uint64_t timestamp = 0;
-    struct sync_fence_info *pinfo = sync_get_fence_info(finfo);
-    for (size_t i = 0; i < finfo->num_fences; i++) {
-        if (pinfo[i].timestamp_ns > timestamp) {
-            timestamp = pinfo[i].timestamp_ns;
-        }
-    }
-
-    sync_file_info_free(finfo);
-    return nsecs_t(timestamp);
-}
-
 std::optional<nsecs_t> ExynosDisplay::getPredictedDuration(bool duringValidation) {
     AveragesKey beforeFenceKey(mLayers.size(), duringValidation, true);
     AveragesKey afterFenceKey(mLayers.size(), duringValidation, false);
@@ -6940,7 +6931,7 @@ void ExynosDisplay::resetColorMappingInfoForClientComp() {
     for (uint32_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
         if (layer->mPrevValidateCompositionType != HWC2_COMPOSITION_CLIENT &&
-            layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT) {
+            layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT) {
             if ((ret = resetColorMappingInfo(layer)) != NO_ERROR) {
                 DISPLAY_LOGE("%s:: resetColorMappingInfo() idx=%d error(%d)", __func__, i, ret);
             }
@@ -6959,12 +6950,12 @@ void ExynosDisplay::resetColorMappingInfoForClientComp() {
 void ExynosDisplay::storePrevValidateCompositionType() {
     for (uint32_t i = 0; i < mIgnoreLayers.size(); i++) {
         ExynosLayer *layer = mIgnoreLayers[i];
-        layer->mPrevValidateCompositionType = layer->mValidateCompositionType;
+        layer->mPrevValidateCompositionType = layer->getValidateCompositionType();
     }
 
     for (uint32_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        layer->mPrevValidateCompositionType = layer->mValidateCompositionType;
+        layer->mPrevValidateCompositionType = layer->getValidateCompositionType();
     }
     mClientCompositionInfo.mPrevHasCompositionLayer = mClientCompositionInfo.mHasCompositionLayer;
 }
diff --git a/libhwc2.1/libdevice/ExynosDisplay.h b/libhwc2.1/libdevice/ExynosDisplay.h
index 1972de6..735956d 100644
--- a/libhwc2.1/libdevice/ExynosDisplay.h
+++ b/libhwc2.1/libdevice/ExynosDisplay.h
@@ -94,6 +94,22 @@ class WorkDuration;
 } // namespace android
 } // namespace aidl
 
+namespace aidl {
+namespace com {
+namespace google {
+namespace hardware {
+namespace pixel {
+namespace display {
+
+class IDisplayProximitySensorCallback;
+
+} // namespace display
+} // namespace pixel
+} // namespace hardware
+} // namespace google
+} // namespace com
+} // namespace aidl
+
 using WorkDuration = aidl::android::hardware::power::WorkDuration;
 
 enum dynamic_recomp_mode {
@@ -412,6 +428,7 @@ typedef struct displayConfigs {
     /* internal use */
     bool isNsMode = false;
     bool isOperationRateToBts;
+    bool isBoost2xBts;
     int32_t refreshRate;
 } displayConfigs_t;
 
@@ -595,6 +612,10 @@ class ExynosDisplay {
 
         std::unique_ptr<DisplayTe2Manager> mDisplayTe2Manager;
 
+        std::shared_ptr<
+                aidl::com::google::hardware::pixel::display::IDisplayProximitySensorCallback>
+                mProximitySensorStateChangeCallback;
+
         /* For debugging */
         hwc_display_contents_1_t *mHWC1LayerList;
         int mBufferDumpCount = 0;
@@ -1248,7 +1269,9 @@ class ExynosDisplay {
         int32_t uncacheLayerBuffers(ExynosLayer* layer, const std::vector<buffer_handle_t>& buffers,
                                     std::vector<buffer_handle_t>& outClearableBuffers);
 
-        virtual void dump(String8& result);
+        virtual void miniDump(String8& result);
+        virtual void dump(String8& result, const std::vector<std::string>& args = {});
+
         void dumpLocked(String8& result) REQUIRES(mDisplayMutex);
         void dumpAllBuffers() REQUIRES(mDisplayMutex);
 
@@ -1376,6 +1399,8 @@ class ExynosDisplay {
         }
 
         virtual int32_t setFixedTe2Rate(const int __unused rateHz) { return NO_ERROR; }
+        virtual void onProximitySensorStateChanged(bool __unused active) { return; }
+        bool isProximitySensorStateCallbackSupported() { return mDisplayTe2Manager != nullptr; }
 
         virtual int32_t setDisplayTemperature(const int __unused temperature) { return NO_ERROR; }
 
@@ -1623,8 +1648,6 @@ class ExynosDisplay {
         };
 
         static const constexpr int kAveragesBufferSize = 3;
-        static const constexpr nsecs_t SIGNAL_TIME_PENDING = INT64_MAX;
-        static const constexpr nsecs_t SIGNAL_TIME_INVALID = -1;
         std::unordered_map<uint32_t, RollingAverage<kAveragesBufferSize>> mRollingAverages;
         // mPowerHalHint should be declared only after mDisplayId and mDisplayTraceName have been
         // declared since mDisplayId and mDisplayTraceName are needed as the parameter of
@@ -1650,7 +1673,6 @@ class ExynosDisplay {
         bool mUsePowerHints = false;
         nsecs_t getExpectedPresentTime(nsecs_t startTime);
         nsecs_t getPredictedPresentTime(nsecs_t startTime);
-        nsecs_t getSignalTime(int32_t fd) const;
         void updateAverages(nsecs_t endTime);
         std::optional<nsecs_t> getPredictedDuration(bool duringValidation);
         atomic_bool mDebugRCDLayerEnabled = true;
diff --git a/libhwc2.1/libdevice/ExynosLayer.cpp b/libhwc2.1/libdevice/ExynosLayer.cpp
index f5bdf26..3f833a3 100644
--- a/libhwc2.1/libdevice/ExynosLayer.cpp
+++ b/libhwc2.1/libdevice/ExynosLayer.cpp
@@ -15,11 +15,12 @@
  */
 
 #include <aidl/android/hardware/graphics/common/BufferUsage.h>
-#include <utils/Errors.h>
+#include <aidl/android/hardware/graphics/common/Transform.h>
+#include <hardware/exynos/ion.h>
+#include <hardware/hwcomposer_defs.h>
 #include <linux/videodev2.h>
 #include <sys/mman.h>
-#include <hardware/hwcomposer_defs.h>
-#include <hardware/exynos/ion.h>
+#include <utils/Errors.h>
 
 #include "BrightnessController.h"
 #include "ExynosLayer.h"
@@ -795,7 +796,7 @@ int32_t ExynosLayer::setLayerBlockingRegion(const std::vector<hwc_rect_t>& block
 
 void ExynosLayer::resetValidateData()
 {
-    mValidateCompositionType = HWC2_COMPOSITION_INVALID;
+    updateValidateCompositionType(HWC2_COMPOSITION_INVALID);
     mOtfMPP = NULL;
     mM2mMPP = NULL;
     mOverlayInfo = 0x0;
@@ -1122,6 +1123,62 @@ void ExynosLayer::dump(String8& result)
 
 }
 
+void ExynosLayer::miniDump(TableBuilder& tb) {
+    int format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
+    int32_t fd, fd1, fd2;
+    if (mLayerBuffer != NULL) {
+        VendorGraphicBufferMeta gmeta(mLayerBuffer);
+        format = gmeta.format;
+        fd = gmeta.fd;
+        fd1 = gmeta.fd1;
+        fd2 = gmeta.fd2;
+    } else {
+        format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
+        fd = -1;
+        fd1 = -1;
+        fd2 = -1;
+    }
+
+    tb.addKeyValue("z", mZOrder)
+            .addKeyValue("priority", mOverlayPriority)
+            .addKeyValue("format",
+                         std::string(mCompressionInfo.type != COMP_TYPE_NONE ? "C-" : "") +
+                                 getFormatStr(format, mCompressionInfo.type).c_str())
+            .addKeyValue("dataspace", transDataSpaceToString(mDataSpace))
+            .addKeyValue("colorTr", mLayerColorTransform.enable)
+            .addKeyValue("blend", transBlendModeToString(mBlending))
+            .addKeyValue("alpha", mPlaneAlpha)
+            .addKeyValue("tr", transTransformToString(mTransform))
+            .addKeyValue("sourceCrop",
+                         std::vector<double>({mPreprocessedInfo.sourceCrop.left,
+                                              mPreprocessedInfo.sourceCrop.top,
+                                              mPreprocessedInfo.sourceCrop.right,
+                                              mPreprocessedInfo.sourceCrop.bottom}))
+            .addKeyValue("dispFrame",
+                         std::vector<int>({mPreprocessedInfo.displayFrame.left,
+                                           mPreprocessedInfo.displayFrame.top,
+                                           mPreprocessedInfo.displayFrame.right,
+                                           mPreprocessedInfo.displayFrame.bottom}))
+            .addKeyValue("CompType",
+                         std::vector<std::string>({transCompTypeToString(mRequestedCompositionType),
+                                                   transCompTypeToString(mValidateCompositionType),
+                                                   transCompTypeToString(mCompositionType)}))
+            .addKeyValue("OvlInfo", transOvlInfoToString(mOverlayInfo).c_str());
+    if (mValidateCompositionType == HWC2_COMPOSITION_DISPLAY_DECORATION)
+        tb.addKeyValue("MPP", "RCD");
+    else if (mOverlayInfo & eIgnoreLayer)
+        tb.addKeyValue("MPP", "IGN");
+    else if ((mOtfMPP == NULL) && (mM2mMPP == NULL))
+        tb.addKeyValue("MPP", "NA");
+    else if (mM2mMPP != NULL && mOtfMPP != NULL) {
+        String8 MPP = mM2mMPP->mName + "," + mOtfMPP->mName;
+        tb.addKeyValue("MPP", MPP.c_str());
+    } else if (mOtfMPP != NULL)
+        tb.addKeyValue("MPP", mOtfMPP->mName.c_str());
+    else
+        tb.addKeyValue("MPP", "NA");
+}
+
 void ExynosLayer::printLayer()
 {
     int format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
diff --git a/libhwc2.1/libdevice/ExynosLayer.h b/libhwc2.1/libdevice/ExynosLayer.h
index e3750f4..21e23cf 100644
--- a/libhwc2.1/libdevice/ExynosLayer.h
+++ b/libhwc2.1/libdevice/ExynosLayer.h
@@ -75,13 +75,6 @@ typedef struct pre_processed_layer_info
     uint32_t mPrivateFormat = 0;
 } pre_processed_layer_info_t;
 
-enum {
-    HWC2_COMPOSITION_DISPLAY_DECORATION = toUnderlying(Composition::DISPLAY_DECORATION),
-    HWC2_COMPOSITION_REFRESH_RATE_INDICATOR = toUnderlying(Composition::REFRESH_RATE_INDICATOR),
-    /*add after hwc2_composition_t, margin number here*/
-    HWC2_COMPOSITION_EXYNOS = 32,
-};
-
 class ExynosLayer : public ExynosMPPSource {
     public:
 
@@ -111,11 +104,19 @@ class ExynosLayer : public ExynosMPPSource {
          */
         int32_t mExynosCompositionType;
 
+    private:
         /**
          * Validated compositionType
          */
         int32_t mValidateCompositionType;
 
+    public:
+        void updateValidateCompositionType(const int32_t& type, const int32_t& ovlInfo = 0) {
+            mValidateCompositionType = type;
+            mOverlayInfo |= ovlInfo;
+        }
+        int32_t getValidateCompositionType() const { return mValidateCompositionType; }
+
         /**
          * The last validated composition type
          */
@@ -476,6 +477,7 @@ class ExynosLayer : public ExynosMPPSource {
 
         void resetValidateData();
         virtual void dump(String8& result);
+        virtual void miniDump(TableBuilder& tb);
         void printLayer();
         int32_t setSrcExynosImage(exynos_image *src_img);
         int32_t setDstExynosImage(exynos_image *dst_img);
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
index b8d6464..cf76d73 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.cpp
@@ -829,6 +829,7 @@ int32_t ExynosDisplayDrmInterface::initDrmDevice(DrmDevice *drmDevice)
         mExynosDisplay->mHistogramController->initDrm(*mDrmDevice, *mDrmCrtc);
     }
 
+    mVsyncCallback.setTransientDuration(getConfigChangeDuration());
     return NO_ERROR;
 }
 
@@ -914,17 +915,40 @@ bool ExynosDisplayDrmInterface::ExynosVsyncCallback::Callback(
     mVsyncTimeStamp = timestamp;
 
     /* There was no config chage request */
-    if (!mDesiredVsyncPeriod)
+    if (!mDesiredVsyncPeriod) {
+        ATRACE_NAME("No pending desired VSync period");
         return true;
-
+    }
     /*
      * mDesiredVsyncPeriod is nanoseconds
      * Compare with 20% margin
      */
-    if (abs(static_cast<int32_t>(mDesiredVsyncPeriod - mVsyncPeriod)) < (mDesiredVsyncPeriod / 5))
+    const int error = mDesiredVsyncPeriod / 5;
+    if (abs(static_cast<int32_t>(mDesiredVsyncPeriod - mVsyncPeriod)) < error) {
+        ATRACE_NAME("Received the desired VSync period");
         return true;
+    }
+    bool isModeSwitchTimeReached = false;
+    nsecs_t signalTime = 0;
+    {
+        std::lock_guard<std::mutex> lock(mFenceMutex);
+        signalTime = getSignalTime(mModeSetFence);
+        if (signalTime != SIGNAL_TIME_INVALID && signalTime != SIGNAL_TIME_PENDING &&
+            timestamp > (signalTime + mVsyncPeriod * mTransientDuration - error)) {
+            close(mModeSetFence);
+            mModeSetFence = -1;
+            isModeSwitchTimeReached = true;
+        }
+    }
+    if (isModeSwitchTimeReached && ATRACE_ENABLED()) {
+        std::stringstream str;
+        str << "Over the RR duration: timestamp:" << timestamp << ",signalTime:" << signalTime
+            << ",VSyncPeriod:" << mVsyncPeriod << ",desiredVsyncPeriod:" << mDesiredVsyncPeriod
+            << ",transientDuration:" << mTransientDuration;
+        ATRACE_NAME(str.str().c_str());
+    }
 
-    return false;
+    return isModeSwitchTimeReached;
 }
 
 int32_t ExynosDisplayDrmInterface::getLowPowerDrmModeModeInfo() {
@@ -1153,6 +1177,7 @@ int32_t ExynosDisplayDrmInterface::getDisplayConfigs(
                 return HWC2_ERROR_BAD_DISPLAY;
             }
             configs.isOperationRateToBts = mode.is_operation_rate_to_bts();
+            configs.isBoost2xBts = mode.is_boost_2x_bts();
             configs.width = mode.h_display();
             configs.height = mode.v_display();
             // Dots per 1000 inches
@@ -1486,6 +1511,7 @@ int32_t ExynosDisplayDrmInterface::setActiveDrmMode(DrmMode const &mode) {
     mDrmConnector->set_active_mode(mode);
     mActiveModeState.setMode(mode, modeBlob, drmReq);
     mActiveModeState.clearPendingModeState();
+    mVsyncCallback.setVsyncPeriod(mode.te_period());
 
     if (reconfig) {
         mDrmConnector->ResetLpMode();
@@ -2214,6 +2240,18 @@ int32_t ExynosDisplayDrmInterface::deliverWinConfigData()
                          __func__, ret);
             }
         }
+
+        if (mXrrSettings.versionInfo.needVrrParameters()) {
+            auto frameInterval = mExynosDisplay->getPendingFrameInterval();
+            if ((ret = drmReq.atomicAddProperty(mDrmConnector->id(),
+                                                mDrmConnector->frame_interval(),
+                                                frameInterval)) < 0) {
+                HWC_LOGE(mExynosDisplay, "%s: Fail to set frameInterval property (%d)",
+                         __func__,
+                         ret);
+            }
+        }
+
         mExynosDisplay->applyExpectedPresentTime();
     }
 
@@ -2244,6 +2282,7 @@ int32_t ExynosDisplayDrmInterface::deliverWinConfigData()
             getLowPowerDrmModeModeInfo();
         }
         mVsyncCallback.setDesiredVsyncPeriod(mActiveModeState.mode.te_period());
+        mVsyncCallback.setModeSetFence(dup(mExynosDisplay->mDpuData.retire_fence));
         /* Enable vsync to check vsync period */
         mDrmVSyncWorker.VSyncControl(true);
     }
diff --git a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.h b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.h
index 064621e..ff03dc2 100644
--- a/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.h
+++ b/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterface.h
@@ -302,11 +302,30 @@ class ExynosDisplayDrmInterface :
                 bool Callback(int display, int64_t timestamp);
                 void resetVsyncTimeStamp() { mVsyncTimeStamp = 0; };
                 void resetDesiredVsyncPeriod() { mDesiredVsyncPeriod = 0;};
+
+                // Sets the vsync period to sync with ExynosDisplay::setActiveConfig.
+                // Note: Vsync period updates should typically be done through Callback.
+                void setVsyncPeriod(const uint64_t& period) { mVsyncPeriod = period; }
+                void setTransientDuration(const int& transientDuration) {
+                    mTransientDuration = transientDuration;
+                }
+                void setModeSetFence(const int fence) {
+                    std::lock_guard<std::mutex> lock(mFenceMutex);
+                    if (mModeSetFence != -1) {
+                        close(mModeSetFence);
+                        mModeSetFence = -1;
+                    }
+                    mModeSetFence = fence;
+                }
+
             private:
                 bool mVsyncEnabled = false;
                 uint64_t mVsyncTimeStamp = 0;
                 uint64_t mVsyncPeriod = 0;
                 uint64_t mDesiredVsyncPeriod = 0;
+                int mModeSetFence = -1;
+                int mTransientDuration = 0;
+                std::mutex mFenceMutex;
         };
         void Callback(int display, int64_t timestamp) override;
 
diff --git a/libhwc2.1/libdrmresource/drm/drmconnector.cpp b/libhwc2.1/libdrmresource/drm/drmconnector.cpp
index eef49b1..d35aeb7 100644
--- a/libhwc2.1/libdrmresource/drm/drmconnector.cpp
+++ b/libhwc2.1/libdrmresource/drm/drmconnector.cpp
@@ -109,6 +109,11 @@ int DrmConnector::Init() {
     ALOGE("Could not get hdr_formats property\n");
   }
 
+  ret = drm_->GetConnectorProperty(*this, "frame_interval", &frame_interval_);
+  if (ret) {
+    ALOGE("Could not get frame_interval property\n");
+  }
+
   ret = drm_->GetConnectorProperty(*this, "panel orientation", &orientation_);
   if (ret) {
     ALOGE("Could not get orientation property\n");
@@ -188,6 +193,7 @@ int DrmConnector::Init() {
   properties_.push_back(&max_avg_luminance_);
   properties_.push_back(&min_luminance_);
   properties_.push_back(&hdr_formats_);
+  properties_.push_back(&frame_interval_);
   properties_.push_back(&orientation_);
   properties_.push_back(&lp_mode_property_);
   properties_.push_back(&brightness_cap_);
@@ -258,7 +264,7 @@ std::string DrmConnector::name() const {
   }
 }
 
-int DrmConnector::UpdateModes(bool is_vrr_mode) {
+int DrmConnector::UpdateModes(bool use_vrr_mode) {
   std::lock_guard<std::recursive_mutex> lock(modes_lock_);
 
   int fd = drm_->fd();
@@ -299,8 +305,12 @@ int DrmConnector::UpdateModes(bool is_vrr_mode) {
       }
     }
     if (!exists) {
+      bool is_vrr_mode = ((c->modes[i].type & DRM_MODE_TYPE_VRR) != 0);
       // Remove modes that mismatch with the VRR setting..
-      if (is_vrr_mode != ((c->modes[i].type & DRM_MODE_TYPE_VRR) != 0)) {
+      if ((use_vrr_mode != is_vrr_mode) ||
+          (!external() && is_vrr_mode &&
+           ((c->modes[i].flags & DRM_MODE_FLAG_TE_FREQ_X2) ||
+            (c->modes[i].flags & DRM_MODE_FLAG_TE_FREQ_X4)))) {
         continue;
       }
       DrmMode m(&c->modes[i]);
@@ -476,6 +486,10 @@ const DrmProperty &DrmConnector::content_protection() const {
     return content_protection_;
 }
 
+const DrmProperty &DrmConnector::frame_interval() const {
+  return frame_interval_;
+}
+
 DrmEncoder *DrmConnector::encoder() const {
   return encoder_;
 }
diff --git a/libhwc2.1/libdrmresource/drm/drmmode.cpp b/libhwc2.1/libdrmresource/drm/drmmode.cpp
index a883a20..44bf0f3 100644
--- a/libhwc2.1/libdrmresource/drm/drmmode.cpp
+++ b/libhwc2.1/libdrmresource/drm/drmmode.cpp
@@ -175,6 +175,15 @@ bool DrmMode::is_operation_rate_to_bts() const {
   return false;
 }
 
+bool DrmMode::is_boost_2x_bts() const {
+  if (!is_vrr_mode()) {
+    auto vfp = v_sync_start() - v_display();
+    if (vfp > v_display())
+      return true;
+  }
+  return false;
+}
+
 uint32_t DrmMode::flags() const {
   return flags_;
 }
diff --git a/libhwc2.1/libdrmresource/drm/drmproperty.cpp b/libhwc2.1/libdrmresource/drm/drmproperty.cpp
index 6c1fff4..4405e4b 100644
--- a/libhwc2.1/libdrmresource/drm/drmproperty.cpp
+++ b/libhwc2.1/libdrmresource/drm/drmproperty.cpp
@@ -165,7 +165,7 @@ std::tuple<uint64_t, int> DrmProperty::getEnumValueWithName(std::string name) co
 
 bool DrmProperty::validateChange(uint64_t value) const {
   if (isImmutable()) {
-    ALOGE("%s: %s is immutable drm property (%zu)", __func__, name().c_str());
+    ALOGE("%s: %s is immutable drm property (%u)", __func__, name().c_str(), id());
     return false;
   } else if (isRange()) {
     if (value < values_[0] || value > values_[1]) {
diff --git a/libhwc2.1/libdrmresource/include/drmconnector.h b/libhwc2.1/libdrmresource/include/drmconnector.h
index 5239b36..dfc541d 100644
--- a/libhwc2.1/libdrmresource/include/drmconnector.h
+++ b/libhwc2.1/libdrmresource/include/drmconnector.h
@@ -91,6 +91,7 @@ class DrmConnector {
   const DrmProperty &operation_rate() const;
   const DrmProperty &refresh_on_lp() const;
   const DrmProperty &content_protection() const;
+  const DrmProperty &frame_interval() const;
 
   const std::vector<DrmProperty *> &properties() const {
       return properties_;
@@ -153,6 +154,7 @@ class DrmConnector {
   DrmProperty operation_rate_;
   DrmProperty refresh_on_lp_;
   DrmProperty content_protection_;
+  DrmProperty frame_interval_;
   std::vector<DrmProperty *> properties_;
 
   std::vector<DrmEncoder *> possible_encoders_;
diff --git a/libhwc2.1/libdrmresource/include/drmmode.h b/libhwc2.1/libdrmresource/include/drmmode.h
index 2dbcc60..86ac5ca 100644
--- a/libhwc2.1/libdrmresource/include/drmmode.h
+++ b/libhwc2.1/libdrmresource/include/drmmode.h
@@ -73,6 +73,7 @@ class DrmMode {
   float te_period(int64_t unit = std::nano::den) const;
 
   bool is_operation_rate_to_bts() const;
+  bool is_boost_2x_bts() const;
   uint32_t flags() const;
   uint32_t type() const;
 
diff --git a/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp b/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
index 134e26f..791f4b6 100644
--- a/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
+++ b/libhwc2.1/libexternaldisplay/ExynosExternalDisplay.cpp
@@ -218,7 +218,7 @@ bool ExynosExternalDisplay::handleRotate()
             layer->mOverlayInfo = eSkipRotateAnim;
             for (size_t j = 0; j < mLayers.size(); j++) {
                 ExynosLayer *skipLayer = mLayers[j];
-                skipLayer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+                skipLayer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE);
             }
             mIsSkipFrame = true;
             return true;
@@ -293,9 +293,10 @@ int32_t ExynosExternalDisplay::validateDisplay(
         uint32_t changed_count = 0;
         for (size_t i = 0; i < mLayers.size(); i++) {
             ExynosLayer *layer = mLayers[i];
-            if (layer && (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE ||
-                layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS)) {
-                layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+            if (layer &&
+                (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE ||
+                 layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS)) {
+                layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eSkipStartFrame);
                 layer->mReleaseFence = layer->mAcquireFence;
                 changed_count++;
             }
diff --git a/libhwc2.1/libhwchelper/ExynosHWCHelper.cpp b/libhwc2.1/libhwchelper/ExynosHWCHelper.cpp
index feab46e..325a242 100644
--- a/libhwc2.1/libhwchelper/ExynosHWCHelper.cpp
+++ b/libhwc2.1/libhwchelper/ExynosHWCHelper.cpp
@@ -1214,6 +1214,68 @@ std::string TableBuilder::build() {
     return output;
 }
 
+std::string TableBuilder::buildForMiniDump() {
+    std::stringstream splitter, header;
+    std::vector<std::stringstream> contents;
+    splitter << "|";
+    header << "|";
+    if (kToVs.size()) {
+        contents.resize(kToVs.begin()->second.size());
+        for (auto& content : contents) content << "|";
+    }
+
+    for (const auto& key : keys) {
+        auto& values = kToVs[key];
+        auto max_value_iter = std::max_element(values.begin(), values.end(),
+                                               [](const std::string& a, const std::string& b) {
+                                                   return a.size() < b.size();
+                                               });
+        const int size = max_value_iter != values.end()
+                ? std::max(key.size(), max_value_iter->size())
+                : key.size();
+        splitter << std::string(size, '-') << "+";
+        header << buildPaddedString(key, size) << "|";
+        for (size_t i = 0; i < values.size(); ++i) {
+            contents[i] << buildPaddedString(values[i], size) << "|";
+        }
+    }
+
+    std::string output = splitter.str() + "\n" + header.str() + "\n";
+    for (auto& content : contents) {
+        output += splitter.str() + "\n" + content.str() + "\n";
+    }
+    output += splitter.str() + "\n";
+    return output;
+}
+
+TableBuilder& TableBuilder::addKeyValue(const std::string& key, const uint64_t& value, bool toHex) {
+    recordKeySequence(key);
+    std::stringstream v;
+    if (toHex)
+        v << "0x" << std::hex << value;
+    else
+        v << value;
+    kToVs[key].emplace_back(v.str());
+    return *this;
+}
+
+TableBuilder& TableBuilder::addKeyValue(const std::string& key, const std::vector<uint64_t>& values,
+                                        bool toHex) {
+    recordKeySequence(key);
+    std::stringstream value;
+    for (int i = 0; i < values.size(); i++) {
+        if (i) value << ", ";
+
+        if (toHex)
+            value << "0x" << std::hex << values[i];
+        else
+            value << values[i];
+    }
+
+    kToVs[key].emplace_back(value.str());
+    return *this;
+}
+
 std::string TableBuilder::buildPaddedString(const std::string& str, int size) {
     int totalPadding = size - str.size();
     int leftPadding = totalPadding / 2.0;
@@ -1403,3 +1465,31 @@ uint32_t nanoSec2Hz(uint64_t ns) {
     constexpr auto nsecsPerSec = std::chrono::nanoseconds(1s).count();
     return round(static_cast<float>(nsecsPerSec) / ns);
 };
+
+nsecs_t getSignalTime(const int32_t fd) {
+    if (fd == -1) {
+        return SIGNAL_TIME_INVALID;
+    }
+
+    struct sync_file_info* finfo = sync_file_info(fd);
+    if (finfo == nullptr) {
+        return SIGNAL_TIME_INVALID;
+    }
+
+    if (finfo->status != 1) {
+        const auto status = finfo->status;
+        sync_file_info_free(finfo);
+        return status < 0 ? SIGNAL_TIME_INVALID : SIGNAL_TIME_PENDING;
+    }
+
+    uint64_t timestamp = 0;
+    struct sync_fence_info* pinfo = sync_get_fence_info(finfo);
+    for (size_t i = 0; i < finfo->num_fences; i++) {
+        if (pinfo[i].timestamp_ns > timestamp) {
+            timestamp = pinfo[i].timestamp_ns;
+        }
+    }
+
+    sync_file_info_free(finfo);
+    return nsecs_t(timestamp);
+}
\ No newline at end of file
diff --git a/libhwc2.1/libhwchelper/ExynosHWCHelper.h b/libhwc2.1/libhwchelper/ExynosHWCHelper.h
index 8c05781..1f6dff8 100644
--- a/libhwc2.1/libhwchelper/ExynosHWCHelper.h
+++ b/libhwc2.1/libhwchelper/ExynosHWCHelper.h
@@ -16,6 +16,8 @@
 #ifndef _EXYNOSHWCHELPER_H
 #define _EXYNOSHWCHELPER_H
 
+#include <aidl/android/hardware/graphics/common/Transform.h>
+#include <aidl/android/hardware/graphics/composer3/Composition.h>
 #include <drm/drm_fourcc.h>
 #include <drm/samsung_drm.h>
 #include <hardware/hwcomposer2.h>
@@ -60,6 +62,8 @@
 #define DRM_FORMAT_YUV420_10BIT fourcc_code('Y', 'U', '1', '0')
 #endif
 
+using AidlTransform = ::aidl::android::hardware::graphics::common::Transform;
+
 static constexpr uint32_t DISPLAYID_MASK_LEN = 8;
 
 template<typename T> inline T max(T a, T b) { return (a > b) ? a : b; }
@@ -333,30 +337,32 @@ enum {
 };
 
 enum {
-    eSkipLayer                    =     0x00000001,
-    eInvalidHandle                =     0x00000002,
-    eHasFloatSrcCrop              =     0x00000004,
-    eUpdateExynosComposition      =     0x00000008,
-    eDynamicRecomposition         =     0x00000010,
-    eForceFbEnabled               =     0x00000020,
-    eSandwitchedBetweenGLES       =     0x00000040,
-    eSandwitchedBetweenEXYNOS     =     0x00000080,
-    eInsufficientWindow           =     0x00000100,
-    eInsufficientMPP              =     0x00000200,
-    eSkipStaticLayer              =     0x00000400,
-    eUnSupportedUseCase           =     0x00000800,
-    eDimLayer                     =     0x00001000,
-    eResourcePendingWork          =     0x00002000,
-    eSkipRotateAnim               =     0x00004000,
-    eUnSupportedColorTransform    =     0x00008000,
-    eLowFpsLayer                  =     0x00010000,
-    eReallocOnGoingForDDI         =     0x00020000,
-    eInvalidDispFrame             =     0x00040000,
-    eExceedMaxLayerNum            =     0x00080000,
-    eExceedSdrDimRatio            =     0x00100000,
-    eResourceAssignFail           =     0x20000000,
-    eMPPUnsupported               =     0x40000000,
-    eUnknown                      =     0x80000000,
+    eForceBySF = 0x00000001,
+    eInvalidHandle = 0x00000002,
+    eHasFloatSrcCrop = 0x00000004,
+    eUpdateExynosComposition = 0x00000008,
+    eDynamicRecomposition = 0x00000010,
+    eForceFbEnabled = 0x00000020,
+    eSandwichedBetweenGLES = 0x00000040,
+    eSandwichedBetweenEXYNOS = 0x00000080,
+    eInsufficientWindow = 0x00000100,
+    eInsufficientMPP = 0x00000200,
+    eSkipStaticLayer = 0x00000400,
+    eUnSupportedUseCase = 0x00000800,
+    eDimLayer = 0x00001000,
+    eResourcePendingWork = 0x00002000,
+    eSkipRotateAnim = 0x00004000,
+    eUnSupportedColorTransform = 0x00008000,
+    eLowFpsLayer = 0x00010000,
+    eReallocOnGoingForDDI = 0x00020000,
+    eInvalidDispFrame = 0x00040000,
+    eExceedMaxLayerNum = 0x00080000,
+    eExceedSdrDimRatio = 0x00100000,
+    eIgnoreLayer = 0x00200000,
+    eSkipStartFrame = 0x008000000,
+    eResourceAssignFail = 0x20000000,
+    eMPPUnsupported = 0x40000000,
+    eUnknown = 0x80000000,
 };
 
 enum regionType {
@@ -582,6 +588,36 @@ bool hasPPC(uint32_t physicalType, uint32_t formatIndex, uint32_t rotIndex);
 
 class TableBuilder {
 public:
+    void recordKeySequence(const std::string& key) {
+        if (kToVs.find(key) == kToVs.end()) keys.push_back(key);
+    }
+    template <typename T>
+    TableBuilder& addKeyValue(const std::string& key, const T& value) {
+        recordKeySequence(key);
+        std::stringstream v;
+        v << value;
+        kToVs[key].emplace_back(v.str());
+        return *this;
+    }
+
+    template <typename T>
+    TableBuilder& addKeyValue(const std::string& key, const std::vector<T>& values) {
+        recordKeySequence(key);
+        std::stringstream value;
+        for (int i = 0; i < values.size(); i++) {
+            if (i) value << ", ";
+            value << values[i];
+        }
+
+        kToVs[key].emplace_back(value.str());
+        return *this;
+    }
+
+    // Template overrides for hex integers
+    TableBuilder& addKeyValue(const std::string& key, const uint64_t& value, bool toHex);
+    TableBuilder& addKeyValue(const std::string& key, const std::vector<uint64_t>& values,
+                              bool toHex);
+
     template <typename T>
     TableBuilder& add(const std::string& key, const T& value) {
         std::stringstream v;
@@ -607,12 +643,16 @@ public:
     TableBuilder& add(const std::string& key, const std::vector<uint64_t>& values, bool toHex);
 
     std::string build();
+    std::string buildForMiniDump();
 
 private:
     std::string buildPaddedString(const std::string& str, int size);
 
     using StringPairVec = std::vector<std::pair<std::string, std::string>>;
     StringPairVec data;
+
+    std::vector<std::string> keys;
+    std::map<std::string, std::vector<std::string>> kToVs;
 };
 
 void writeFileNode(FILE *fd, int value);
@@ -680,4 +720,167 @@ uint32_t rectSize(const hwc_rect_t &rect);
 void assign(decon_win_rect &win_rect, uint32_t left, uint32_t right, uint32_t width,
             uint32_t height);
 uint32_t nanoSec2Hz(uint64_t ns);
+
+inline std::string transOvlInfoToString(const int32_t ovlInfo) {
+    std::string ret;
+    if (ovlInfo & eForceBySF) ret += "ForceBySF ";
+    if (ovlInfo & eInvalidHandle) ret += "InvalidHandle ";
+    if (ovlInfo & eHasFloatSrcCrop) ret += "FloatSrcCrop ";
+    if (ovlInfo & eUpdateExynosComposition) ret += "ExyComp ";
+    if (ovlInfo & eDynamicRecomposition) ret += "DR ";
+    if (ovlInfo & eForceFbEnabled) ret += "ForceFb ";
+    if (ovlInfo & eSandwichedBetweenGLES) ret += "SandwichGLES ";
+    if (ovlInfo & eSandwichedBetweenEXYNOS) ret += "SandwichExy ";
+    if (ovlInfo & eInsufficientWindow) ret += "NoWin ";
+    if (ovlInfo & eInsufficientMPP) ret += "NoMPP ";
+    if (ovlInfo & eSkipStaticLayer) ret += "SkipStaticLayer ";
+    if (ovlInfo & eUnSupportedUseCase) ret += "OutOfCase ";
+    if (ovlInfo & eDimLayer) ret += "Dim ";
+    if (ovlInfo & eResourcePendingWork) ret += "ResourcePending ";
+    if (ovlInfo & eSkipRotateAnim) ret += "SkipRotAnim ";
+    if (ovlInfo & eUnSupportedColorTransform) ret += "UnsupportedColorTrans ";
+    if (ovlInfo & eLowFpsLayer) ret += "LowFps ";
+    if (ovlInfo & eReallocOnGoingForDDI) ret += "ReallocForDDI ";
+    if (ovlInfo & eInvalidDispFrame) ret += "InvalidDispFrame ";
+    if (ovlInfo & eExceedMaxLayerNum) ret += "OverMaxLayer ";
+    if (ovlInfo & eExceedSdrDimRatio) ret += "OverSdrDimRatio ";
+    if (ovlInfo & eIgnoreLayer) ret += "Ignore ";
+    if (ovlInfo & eSkipStartFrame) ret += "SkipFirstFrame ";
+    if (ovlInfo & eResourceAssignFail) ret += "ResourceAssignFail ";
+    if (ovlInfo & eMPPUnsupported) ret += "MPPUnspported ";
+    if (ovlInfo & eUnknown) ret += "Unknown ";
+
+    if (std::size_t found = ret.find_last_of(" ");
+        found != std::string::npos && found < ret.size()) {
+        ret.erase(found);
+    }
+    return ret;
+}
+
+inline std::string transDataSpaceToString(const uint32_t& dataspace) {
+    std::string ret;
+    const uint32_t standard = dataspace & HAL_DATASPACE_STANDARD_MASK;
+    if (standard == HAL_DATASPACE_STANDARD_UNSPECIFIED)
+        ret += std::string("NA");
+    else if (standard == HAL_DATASPACE_STANDARD_BT709)
+        ret += std::string("BT709");
+    else if (standard == HAL_DATASPACE_STANDARD_BT601_625)
+        ret += std::string("BT601_625");
+    else if (standard == HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED)
+        ret += std::string("BT601_625_UNADJUSTED");
+    else if (standard == HAL_DATASPACE_STANDARD_BT601_525)
+        ret += std::string("BT601_525");
+    else if (standard == HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED)
+        ret += std::string("BT601_525_UNADJUSTED");
+    else if (standard == HAL_DATASPACE_STANDARD_BT2020)
+        ret += std::string("BT2020");
+    else if (standard == HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE)
+        ret += std::string("BT2020_CONSTANT_LUMINANCE");
+    else if (standard == HAL_DATASPACE_STANDARD_BT470M)
+        ret += std::string("BT470M");
+    else if (standard == HAL_DATASPACE_STANDARD_FILM)
+        ret += std::string("FILM");
+    else if (standard == HAL_DATASPACE_STANDARD_DCI_P3)
+        ret += std::string("DCI-P3");
+    else if (standard == HAL_DATASPACE_STANDARD_ADOBE_RGB)
+        ret += std::string("Adobe RGB");
+    else
+        ret += std::string("Unknown");
+
+    const uint32_t transfer = dataspace & HAL_DATASPACE_TRANSFER_MASK;
+    if (transfer == HAL_DATASPACE_TRANSFER_LINEAR)
+        ret += std::string(",Linear");
+    else if (transfer == HAL_DATASPACE_TRANSFER_SRGB)
+        ret += std::string(",SRGB");
+    else if (transfer == HAL_DATASPACE_TRANSFER_SMPTE_170M)
+        ret += std::string(",SMPTE");
+    else if (transfer == HAL_DATASPACE_TRANSFER_GAMMA2_2)
+        ret += std::string(",G2.2");
+    else if (transfer == HAL_DATASPACE_TRANSFER_GAMMA2_6)
+        ret += std::string(",G2.6");
+    else if (transfer == HAL_DATASPACE_TRANSFER_GAMMA2_8)
+        ret += std::string(",G2.8");
+    else if (transfer == HAL_DATASPACE_TRANSFER_ST2084)
+        ret += std::string(",ST2084");
+    else if (transfer == HAL_DATASPACE_TRANSFER_HLG)
+        ret += std::string(",HLG");
+    else
+        ret += std::string(",Unknown");
+
+    const uint32_t range = dataspace & HAL_DATASPACE_RANGE_MASK;
+    if (range == HAL_DATASPACE_RANGE_FULL)
+        ret += std::string(",Full");
+    else if (range == HAL_DATASPACE_RANGE_LIMITED)
+        ret += std::string(",Limited");
+    else if (range == HAL_DATASPACE_RANGE_EXTENDED)
+        ret += std::string(",Extend");
+    else
+        ret += std::string(",Unknown");
+    return ret;
+}
+
+inline std::string transBlendModeToString(const uint32_t& blend) {
+    if (blend == HWC2_BLEND_MODE_NONE)
+        return std::string("None");
+    else if (blend == HWC2_BLEND_MODE_PREMULTIPLIED)
+        return std::string("Premult");
+    else if (blend == HWC2_BLEND_MODE_COVERAGE)
+        return std::string("Coverage");
+    else
+        return std::string("Unknown");
+}
+
+inline std::string transTransformToString(const uint32_t& tr) {
+    if (tr == toUnderlying(AidlTransform::NONE))
+        return std::string("None");
+    else if (tr == toUnderlying(AidlTransform::FLIP_H))
+        return std::string("FLIP_H");
+    else if (tr == toUnderlying(AidlTransform::FLIP_V))
+        return std::string("FLIP_V");
+    else if (tr == toUnderlying(AidlTransform::ROT_90))
+        return std::string("ROT_90");
+    else if (tr == toUnderlying(AidlTransform::ROT_180))
+        return std::string("ROT_180");
+    else if (tr == toUnderlying(AidlTransform::ROT_270))
+        return std::string("ROT_270");
+    return std::string("Unknown");
+}
+
+using ::aidl::android::hardware::graphics::composer3::Composition;
+
+enum {
+    HWC2_COMPOSITION_DISPLAY_DECORATION = toUnderlying(Composition::DISPLAY_DECORATION),
+    HWC2_COMPOSITION_REFRESH_RATE_INDICATOR = toUnderlying(Composition::REFRESH_RATE_INDICATOR),
+    /*add after hwc2_composition_t, margin number here*/
+    HWC2_COMPOSITION_EXYNOS = 32,
+};
+
+inline std::string transCompTypeToString(const uint32_t& type) {
+    if (type == HWC2_COMPOSITION_INVALID)
+        return std::string("Invalid");
+    else if (type == HWC2_COMPOSITION_CLIENT)
+        return std::string("CLI");
+    else if (type == HWC2_COMPOSITION_DEVICE)
+        return std::string("DEV");
+    else if (type == HWC2_COMPOSITION_SOLID_COLOR)
+        return std::string("SOLID");
+    else if (type == HWC2_COMPOSITION_CURSOR)
+        return std::string("CURSOR");
+    else if (type == HWC2_COMPOSITION_SIDEBAND)
+        return std::string("SIDEBAND");
+    else if (type == HWC2_COMPOSITION_DISPLAY_DECORATION)
+        return std::string("RCD");
+    else if (type == HWC2_COMPOSITION_REFRESH_RATE_INDICATOR)
+        return std::string("REFRESH_RATE");
+    else if (type == HWC2_COMPOSITION_EXYNOS)
+        return std::string("EXYNOS");
+    else
+        return std::string("Unknown");
+}
+
+static constexpr int64_t SIGNAL_TIME_PENDING = INT64_MAX;
+static constexpr int64_t SIGNAL_TIME_INVALID = -1;
+
+nsecs_t getSignalTime(int32_t fd);
+
 #endif
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
index 34d89f3..7498cea 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
@@ -235,7 +235,7 @@ ExynosPrimaryDisplay::ExynosPrimaryDisplay(uint32_t index, ExynosDevice* device,
             if (content.has_value() &&
                 !(content.value().compare(0, kRefreshControlNodeEnabled.length(),
                                           kRefreshControlNodeEnabled))) {
-                bool ret = fileNode->WriteUint32(kRefreshControlNodeName, refreshControlCommand);
+                bool ret = fileNode->writeValue(kRefreshControlNodeName, refreshControlCommand);
                 if (!ret) {
                     ALOGE("%s(): write command to file node %s%s failed.", __func__,
                           displayFileNodePath.c_str(), kRefreshControlNodeName.c_str());
@@ -853,9 +853,9 @@ int32_t ExynosPrimaryDisplay::getDisplayConfigs(uint32_t* outNumConfigs,
 int32_t ExynosPrimaryDisplay::presentDisplay(int32_t* outRetireFence) {
     auto res = ExynosDisplay::presentDisplay(outRetireFence);
     // Forward presentDisplay if there is a listener.
-    const auto presentListener = getPresentListener();
-    if (res == HWC2_ERROR_NONE && presentListener) {
-        presentListener->onPresent(*outRetireFence);
+    const auto refreshListener = getRefreshListener();
+    if (res == HWC2_ERROR_NONE && refreshListener) {
+        refreshListener->onPresent(*outRetireFence);
     }
     return res;
 }
@@ -868,6 +868,8 @@ void ExynosPrimaryDisplay::onVsync(int64_t timestamp) {
 }
 
 int32_t ExynosPrimaryDisplay::notifyExpectedPresent(int64_t timestamp, int32_t frameIntervalNs) {
+    DISPLAY_ATRACE_INT64("expectedPresentTimeDelta", timestamp - systemTime());
+    DISPLAY_ATRACE_INT("frameInterval", frameIntervalNs);
     if (mVariableRefreshRateController) {
         mVariableRefreshRateController->notifyExpectedPresent(timestamp, frameIntervalNs);
     }
@@ -925,6 +927,13 @@ int32_t ExynosPrimaryDisplay::setLhbmDisplayConfigLocked(uint32_t peakRate) {
 
 void ExynosPrimaryDisplay::restoreLhbmDisplayConfigLocked() {
     enableConfigSetting(true);
+
+    if (*mPowerModeState == HWC2_POWER_MODE_DOZE ||
+        *mPowerModeState == HWC2_POWER_MODE_DOZE_SUSPEND) {
+        DISPLAY_LOGI("%s: in aod mode(%d), skip restore", __func__, *mPowerModeState);
+        return;
+    }
+
     hwc2_config_t pendingConfig = mPendingConfig;
     auto hwConfig = mDisplayInterface->getActiveModeId();
     if (pendingConfig != UINT_MAX && pendingConfig != hwConfig) {
@@ -1142,11 +1151,14 @@ void ExynosPrimaryDisplay::setEarlyWakeupDisplay() {
 }
 
 void ExynosPrimaryDisplay::setExpectedPresentTime(uint64_t timestamp, int frameIntervalNs) {
+    DISPLAY_ATRACE_INT64("expectedPresentTimeDelta", timestamp - systemTime());
+    DISPLAY_ATRACE_INT("frameInterval", frameIntervalNs);
+
     mExpectedPresentTimeAndInterval.store(std::make_tuple(timestamp, frameIntervalNs));
     // Forward presentDisplay if there is a listener.
-    const auto presentListener = getPresentListener();
-    if (presentListener) {
-        presentListener->setExpectedPresentTime(timestamp, frameIntervalNs);
+    const auto refreshListener = getRefreshListener();
+    if (refreshListener) {
+        refreshListener->setExpectedPresentTime(timestamp, frameIntervalNs);
     }
 }
 
@@ -1342,6 +1354,13 @@ int32_t ExynosPrimaryDisplay::setDisplayTemperature(const int temperature) {
     return HWC2_ERROR_UNSUPPORTED;
 }
 
+void ExynosPrimaryDisplay::onProximitySensorStateChanged(bool active) {
+    if (mProximitySensorStateChangeCallback) {
+        ALOGI("ExynosPrimaryDisplay: %s: %d", __func__, active);
+        mProximitySensorStateChangeCallback->onProximitySensorStateChanged(active);
+    }
+}
+
 int32_t ExynosPrimaryDisplay::setMinIdleRefreshRate(const int targetFps,
                                                     const RrThrottleRequester requester) {
     if (targetFps < 0) {
@@ -1402,6 +1421,9 @@ int32_t ExynosPrimaryDisplay::setMinIdleRefreshRate(const int targetFps,
             ALOGD("%s: proximity state %s, min %dhz, doze mode %d", __func__,
                   proximityActive ? "active" : "inactive", targetFps, dozeMode);
             mDisplayTe2Manager->updateTe2OptionForProximity(proximityActive, targetFps, dozeMode);
+            if (!dozeMode) {
+                mDisplayTe2Manager->handleProximitySensorStateChange(proximityActive);
+            }
         }
 
         if (maxMinIdleFps == mMinIdleRefreshRate) return NO_ERROR;
@@ -1494,7 +1516,7 @@ int32_t ExynosPrimaryDisplay::setRefreshRateThrottleNanos(const int64_t delayNan
     return ret;
 }
 
-void ExynosPrimaryDisplay::dump(String8 &result) {
+void ExynosPrimaryDisplay::dump(String8& result, const std::vector<std::string>& args) {
     ExynosDisplay::dump(result);
     result.appendFormat("Display idle timer: %s\n",
                         (mDisplayIdleTimerEnabled) ? "enabled" : "disabled");
@@ -1533,6 +1555,22 @@ void ExynosPrimaryDisplay::dump(String8 &result) {
         result.appendFormat("Temperature : %d°C\n", mDisplayTemperature);
     }
     result.appendFormat("\n");
+
+    DisplayType displayType = getDcDisplayType();
+    std::string displayTypeIdentifier;
+    if (displayType == DisplayType::DISPLAY_PRIMARY) {
+        displayTypeIdentifier = "primarydisplay";
+    } else if (displayType == DisplayType::DISPLAY_EXTERNAL) {
+        displayTypeIdentifier = "externaldisplay";
+    }
+    if (!displayTypeIdentifier.empty()) {
+        auto xrrVersion =
+                android::hardware::graphics::composer::getDisplayXrrVersion(displayTypeIdentifier);
+        result.appendFormat("XRR version: %d.%d\n", xrrVersion.first, xrrVersion.second);
+    }
+    if (mVariableRefreshRateController) {
+        mVariableRefreshRateController->dump(result, args);
+    }
 }
 
 void ExynosPrimaryDisplay::calculateTimelineLocked(
@@ -1556,7 +1594,7 @@ void ExynosPrimaryDisplay::calculateTimelineLocked(
         std::lock_guard<std::mutex> lock(mIdleRefreshRateThrottleMutex);
         threshold = mRefreshRateDelayNanos;
         mRrUseDelayNanos = 0;
-        mIsRrNeedCheckDelay =
+        mIsRrNeedCheckDelay = !mXrrSettings.versionInfo.needVrrParameters() &&
                 mDisplayConfigs[mActiveConfig].vsyncPeriod < mDisplayConfigs[config].vsyncPeriod;
         if (threshold != 0 && mLastRefreshRateAppliedNanos != 0 && mIsRrNeedCheckDelay) {
             lastUpdateDelta = desiredUpdateTimeNanos - mLastRefreshRateAppliedNanos;
@@ -1689,7 +1727,7 @@ int32_t ExynosPrimaryDisplay::setDbmState(bool enabled) {
     return NO_ERROR;
 }
 
-PresentListener* ExynosPrimaryDisplay::getPresentListener() {
+RefreshListener* ExynosPrimaryDisplay::getRefreshListener() {
     if (mVariableRefreshRateController) {
         return mVariableRefreshRateController.get();
     }
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
index 95fd5bb..dd80ef1 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
@@ -22,7 +22,7 @@
 #include "../libvrr/VariableRefreshRateController.h"
 #include <cutils/properties.h>
 
-using android::hardware::graphics::composer::PresentListener;
+using android::hardware::graphics::composer::RefreshListener;
 using android::hardware::graphics::composer::VariableRefreshRateController;
 using android::hardware::graphics::composer::VsyncListener;
 using namespace displaycolor;
@@ -62,7 +62,7 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
         virtual bool isDbmSupported() override;
         virtual int32_t setDbmState(bool enabled) override;
 
-        virtual void dump(String8& result) override;
+        virtual void dump(String8& result, const std::vector<std::string>& args = {}) override;
         virtual void updateAppliedActiveConfig(const hwc2_config_t newConfig,
                                                const int64_t ts) override;
         virtual void checkBtsReassignResource(const int32_t vsyncPeriod,
@@ -82,6 +82,8 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
 
         virtual int32_t setFixedTe2Rate(const int rateHz) override;
 
+        virtual void onProximitySensorStateChanged(bool active) override;
+
         virtual int32_t setDisplayTemperature(const int temperatue) override;
 
         const std::string& getPanelName() final;
@@ -228,7 +230,7 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
         bool mDisplayNeedHandleIdleExit;
 
         // Function and variables related to Vrr.
-        PresentListener* getPresentListener();
+        RefreshListener* getRefreshListener();
         VsyncListener* getVsyncListener();
 
         XrrSettings_t mXrrSettings;
diff --git a/libhwc2.1/libresource/ExynosResourceManager.cpp b/libhwc2.1/libresource/ExynosResourceManager.cpp
index 808eaa2..92730bd 100644
--- a/libhwc2.1/libresource/ExynosResourceManager.cpp
+++ b/libhwc2.1/libresource/ExynosResourceManager.cpp
@@ -490,17 +490,15 @@ int32_t ExynosResourceManager::setResourcePriority(ExynosDisplay *display)
 
     for (uint32_t i = 0; i < display->mLayers.size(); i++) {
         ExynosLayer *layer = display->mLayers[i];
-        if ((layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) &&
-            (layer->mM2mMPP != NULL) &&
-            (layer->mM2mMPP->mPhysicalType == MPP_G2D) &&
+        if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) &&
+            (layer->mM2mMPP != NULL) && (layer->mM2mMPP->mPhysicalType == MPP_G2D) &&
             ((check_ret = layer->mM2mMPP->prioritize(2)) != NO_ERROR)) {
             if (check_ret < 0) {
                 HWC_LOGE(display, "Fail to set exynoscomposition priority(%d)", ret);
             } else {
                 m2mMPP = layer->mM2mMPP;
                 layer->resetAssignedResource();
-                layer->mOverlayInfo |= eResourcePendingWork;
-                layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+                layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE, eResourcePendingWork);
                 ret = EXYNOS_ERROR_CHANGED;
                 HDEBUGLOGD(eDebugResourceManager, "\t%s is reserved without display because of panding work",
                         m2mMPP->mName.c_str());
@@ -528,8 +526,8 @@ int32_t ExynosResourceManager::setResourcePriority(ExynosDisplay *display)
                     for (uint32_t i = firstIndex; i <= lastIndex; i++) {
                         ExynosLayer *layer = display->mLayers[i];
                         layer->resetAssignedResource();
-                        layer->mOverlayInfo |= eResourcePendingWork;
-                        layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+                        layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE,
+                                                             eResourcePendingWork);
                         layer->mCheckMPPFlag[m2mMPP->mLogicalType] = eMPPHWBusy;
                     }
                 }
@@ -562,8 +560,7 @@ int32_t ExynosResourceManager::assignResourceInternal(ExynosDisplay *display)
     for (uint32_t i = 0; i < display->mLayers.size(); i++) {
         ExynosLayer *layer = display->mLayers[i];
         if (layer->mCompositionType == HWC2_COMPOSITION_CLIENT) {
-            layer->mOverlayInfo |= eSkipLayer;
-            layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eForceBySF);
             if (((ret = display->addClientCompositionLayer(i)) != NO_ERROR) &&
                  (ret != EXYNOS_ERROR_CHANGED)) {
                 HWC_LOGE(display, "Handle HWC2_COMPOSITION_CLIENT type layers, but addClientCompositionLayer failed (%d)", ret);
@@ -614,8 +611,7 @@ int32_t ExynosResourceManager::assignResourceInternal(ExynosDisplay *display)
                 for (uint32_t i = firstIndex; i <= lastIndex; i++) {
                     ExynosLayer *layer = display->mLayers[i];
                     layer->resetAssignedResource();
-                    layer->mOverlayInfo |= eInsufficientMPP;
-                    layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
+                    layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eInsufficientMPP);
                     if (((ret = display->addClientCompositionLayer(i)) != NO_ERROR) &&
                         (ret != EXYNOS_ERROR_CHANGED)) {
                         HWC_LOGE(display, "Change compositionTypes to HWC2_COMPOSITION_CLIENT, but addClientCompositionLayer failed (%d)", ret);
@@ -699,7 +695,8 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                     if ((layer->mSupportedMPPFlag & m2mMPP->mLogicalType) != 0)
                         isAssignableState = isAssignable(m2mMPP, display, src_img, dst_img, layer);
 
-                    bool canChange = (layer->mValidateCompositionType != HWC2_COMPOSITION_CLIENT) &&
+                    bool canChange =
+                            (layer->getValidateCompositionType() != HWC2_COMPOSITION_CLIENT) &&
                             ((display->mDisplayControl.cursorSupport == false) ||
                              (layer->mCompositionType != HWC2_COMPOSITION_CURSOR)) &&
                             (layer->mSupportedMPPFlag & m2mMPP->mLogicalType) && isAssignableState;
@@ -707,11 +704,10 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                     HDEBUGLOGD(eDebugResourceAssigning,
                                "\tlayer[%d] type: %d, 0x%8x, isAssignable: %d, canChange: %d, "
                                "remainNum(%d)",
-                               i, layer->mValidateCompositionType, layer->mSupportedMPPFlag,
+                               i, layer->getValidateCompositionType(), layer->mSupportedMPPFlag,
                                isAssignableState, canChange, remainNum);
                     if (canChange) {
                         layer->resetAssignedResource();
-                        layer->mOverlayInfo |= eUpdateExynosComposition;
                         if ((ret = m2mMPP->assignMPP(display, layer)) != NO_ERROR)
                         {
                             ALOGE("%s:: %s MPP assignMPP() error (%d)",
@@ -721,7 +717,8 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                         layer->setExynosMidImage(dst_img);
                         float totalUsedCapacity = getResourceUsedCapa(*m2mMPP);
                         display->addExynosCompositionLayer(i, totalUsedCapacity);
-                        layer->mValidateCompositionType = HWC2_COMPOSITION_EXYNOS;
+                        layer->updateValidateCompositionType(HWC2_COMPOSITION_EXYNOS,
+                                                             eUpdateExynosComposition);
                         remainNum--;
                     }
                     if ((canChange == false) || (remainNum == 0))
@@ -739,7 +736,8 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                     if ((layer->mSupportedMPPFlag & m2mMPP->mLogicalType) != 0)
                         isAssignableState = isAssignable(m2mMPP, display, src_img, dst_img, layer);
 
-                    bool canChange = (layer->mValidateCompositionType != HWC2_COMPOSITION_CLIENT) &&
+                    bool canChange =
+                            (layer->getValidateCompositionType() != HWC2_COMPOSITION_CLIENT) &&
                             ((display->mDisplayControl.cursorSupport == false) ||
                              (layer->mCompositionType != HWC2_COMPOSITION_CURSOR)) &&
                             (layer->mSupportedMPPFlag & m2mMPP->mLogicalType) && isAssignableState;
@@ -747,7 +745,7 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                     HDEBUGLOGD(eDebugResourceAssigning,
                                "\tlayer[%d] type: %d, 0x%8x, isAssignable: %d, canChange: %d, "
                                "remainNum(%d)",
-                               i, layer->mValidateCompositionType, layer->mSupportedMPPFlag,
+                               i, layer->getValidateCompositionType(), layer->mSupportedMPPFlag,
                                isAssignableState, canChange, remainNum);
                     if (canChange) {
                         layer->resetAssignedResource();
@@ -761,7 +759,7 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
                         layer->setExynosMidImage(dst_img);
                         float totalUsedCapacity = getResourceUsedCapa(*m2mMPP);
                         display->addExynosCompositionLayer(i, totalUsedCapacity);
-                        layer->mValidateCompositionType = HWC2_COMPOSITION_EXYNOS;
+                        layer->updateValidateCompositionType(HWC2_COMPOSITION_EXYNOS);
                         remainNum--;
                     }
                     if ((canChange == false) || (remainNum == 0))
@@ -788,7 +786,7 @@ int32_t ExynosResourceManager::updateExynosComposition(ExynosDisplay *display)
             ExynosLayer* layer = display->mLayers[display->mExynosCompositionInfo.mFirstIndex];
             if (layer->mSupportedMPPFlag & otfMPP->mLogicalType) {
                 layer->resetAssignedResource();
-                layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+                layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE);
                 display->mExynosCompositionInfo.initializeInfos(display);
                 // reset otfMPP
                 if ((ret = otfMPP->resetAssignedState()) != NO_ERROR)
@@ -839,7 +837,7 @@ int32_t ExynosResourceManager::changeLayerFromClientToDevice(ExynosDisplay* disp
         HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: %s MPP is assigned", layer_index,
                    m2mMPP->mName.c_str());
     }
-    layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+    layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE);
     display->mWindowNumUsed++;
     HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: mWindowNumUsed(%d)", layer_index,
                display->mWindowNumUsed);
@@ -875,7 +873,7 @@ int32_t ExynosResourceManager::updateClientComposition(ExynosDisplay *display)
         int32_t compositionType = 0;
         ExynosLayer *layer = display->mLayers[i];
         if ((layer->mOverlayPriority >= ePriorityHigh) &&
-            (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE)) {
+            (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)) {
             display->mClientCompositionInfo.mFirstIndex++;
             continue;
         }
@@ -906,7 +904,7 @@ int32_t ExynosResourceManager::updateClientComposition(ExynosDisplay *display)
         int32_t compositionType = 0;
         ExynosLayer *layer = display->mLayers[i];
         if ((layer->mOverlayPriority >= ePriorityHigh) &&
-            (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE)) {
+            (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE)) {
             display->mClientCompositionInfo.mLastIndex--;
             continue;
         }
@@ -1079,8 +1077,7 @@ int32_t ExynosResourceManager::validateLayer(uint32_t index, ExynosDisplay *disp
         return eReallocOnGoingForDDI;
     }
 
-    if (layer->mCompositionType == HWC2_COMPOSITION_CLIENT)
-        return eSkipLayer;
+    if (layer->mCompositionType == HWC2_COMPOSITION_CLIENT) return eForceBySF;
 
 #ifndef HWC_SUPPORT_COLOR_TRANSFORM
     if (display->mColorTransformHint != HAL_COLOR_TRANSFORM_IDENTITY) {
@@ -1649,8 +1646,8 @@ int32_t ExynosResourceManager::assignLayers(ExynosDisplay * display, uint32_t pr
         uint32_t validateFlag = 0;
         int32_t compositionType = 0;
 
-        if ((layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT) ||
-            (layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS))
+        if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT) ||
+            (layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS))
             continue;
         if (layer->mOverlayPriority != priority)
             continue;
@@ -1665,7 +1662,7 @@ int32_t ExynosResourceManager::assignLayers(ExynosDisplay * display, uint32_t pr
         // TODO: call validate function for RCD layer
         if (layer->mCompositionType == HWC2_COMPOSITION_DISPLAY_DECORATION &&
             validateRCDLayer(*display, *layer, i, src_img, dst_img) == NO_ERROR) {
-            layer->mValidateCompositionType = HWC2_COMPOSITION_DISPLAY_DECORATION;
+            layer->updateValidateCompositionType(HWC2_COMPOSITION_DISPLAY_DECORATION);
             continue;
         }
 
@@ -1692,7 +1689,7 @@ int32_t ExynosResourceManager::assignLayers(ExynosDisplay * display, uint32_t pr
                 HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: %s MPP is assigned", i,
                            m2mMPP->mName.c_str());
             }
-            layer->mValidateCompositionType = compositionType;
+            layer->updateValidateCompositionType(compositionType, validateFlag);
             display->mWindowNumUsed++;
             HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: mWindowNumUsed(%d)", i,
                        display->mWindowNumUsed);
@@ -1709,7 +1706,7 @@ int32_t ExynosResourceManager::assignLayers(ExynosDisplay * display, uint32_t pr
                 HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: %s MPP is assigned", i,
                            m2mMPP->mName.c_str());
             }
-            layer->mValidateCompositionType = compositionType;
+            layer->updateValidateCompositionType(compositionType, validateFlag);
 
             HDEBUGLOGD(eDebugResourceAssigning, "\t\t[%d] layer: exynosComposition", i);
             /* G2D composition */
@@ -1743,12 +1740,12 @@ int32_t ExynosResourceManager::assignLayers(ExynosDisplay * display, uint32_t pr
             }
 
             /* Fail to assign resource, set HWC2_COMPOSITION_CLIENT */
-            if (validateFlag != NO_ERROR)
-                layer->mOverlayInfo |= validateFlag;
-            else
-                layer->mOverlayInfo |= eMPPUnsupported;
+            if (validateFlag != NO_ERROR) {
+                layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, validateFlag);
+            } else {
+                layer->updateValidateCompositionType(HWC2_COMPOSITION_CLIENT, eMPPUnsupported);
+            }
 
-            layer->mValidateCompositionType = HWC2_COMPOSITION_CLIENT;
             if (((ret = display->addClientCompositionLayer(i)) == EXYNOS_ERROR_CHANGED) ||
                 (ret < 0))
                 return ret;
@@ -1787,15 +1784,15 @@ int32_t ExynosResourceManager::assignWindow(ExynosDisplay *display)
     for (uint32_t i = 0; i < display->mLayers.size(); i++) {
         ExynosLayer *layer = display->mLayers[i];
         HDEBUGLOGD(eDebugResourceAssigning, "\t[%d] layer type: %d", i,
-                   layer->mValidateCompositionType);
+                   layer->getValidateCompositionType());
 
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE) {
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE) {
             layer->mWindowIndex = windowIndex;
             HDEBUGLOGD(eDebugResourceManager, "\t\t[%d] layer windowIndex: %d", i, windowIndex);
-        } else if ((layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT) ||
-                   (layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS)) {
+        } else if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT) ||
+                   (layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS)) {
             ExynosCompositionInfo *compositionInfo;
-            if (layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT)
+            if (layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT)
                 compositionInfo = &display->mClientCompositionInfo;
             else
                 compositionInfo = &display->mExynosCompositionInfo;
@@ -1816,12 +1813,12 @@ int32_t ExynosResourceManager::assignWindow(ExynosDisplay *display)
             compositionInfo->mWindowIndex = windowIndex;
             HDEBUGLOGD(eDebugResourceManager, "\t\t[%d] %s Composition windowIndex: %d",
                     i, compositionInfo->getTypeStr().c_str(), windowIndex);
-        } else if (layer->mValidateCompositionType == HWC2_COMPOSITION_DISPLAY_DECORATION) {
+        } else if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DISPLAY_DECORATION) {
             layer->mWindowIndex = -1;
             continue;
         } else {
             HWC_LOGE(display, "%s:: Invalid layer compositionType layer(%d), compositionType(%d)",
-                    __func__, i, layer->mValidateCompositionType);
+                     __func__, i, layer->getValidateCompositionType());
             continue;
         }
         windowIndex++;
diff --git a/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplay.cpp b/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplay.cpp
index 0e97559..f3889dd 100644
--- a/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplay.cpp
+++ b/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplay.cpp
@@ -395,12 +395,12 @@ void ExynosVirtualDisplay::setCompositionType()
     size_t CompositionDeviceLayerCount = 0;;
     for (size_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_CLIENT ||
-            layer->mValidateCompositionType == HWC2_COMPOSITION_INVALID) {
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_CLIENT ||
+            layer->getValidateCompositionType() == HWC2_COMPOSITION_INVALID) {
             compositionClientLayerCount++;
         }
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE ||
-            layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) {
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE ||
+            layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) {
             CompositionDeviceLayerCount++;
         }
     }
@@ -465,14 +465,14 @@ void ExynosVirtualDisplay::setDrmMode()
     mIsSecureDRM = false;
     for (size_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        if ((layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE ||
-            layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) &&
+        if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE ||
+             layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) &&
             layer->mLayerBuffer && getDrmMode(layer->mLayerBuffer) == SECURE_DRM) {
             mIsSecureDRM = true;
             DISPLAY_LOGD(eDebugVirtualDisplay, "include secure drm layer");
         }
-        if ((layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE ||
-            layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) &&
+        if ((layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE ||
+             layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) &&
             layer->mLayerBuffer && getDrmMode(layer->mLayerBuffer) == NORMAL_DRM) {
             mIsNormalDRM = true;
             DISPLAY_LOGD(eDebugVirtualDisplay, "include normal drm layer");
@@ -486,7 +486,7 @@ void ExynosVirtualDisplay::handleSkipFrame()
     mIsSkipFrame = true;
     for (size_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        layer->mValidateCompositionType = HWC2_COMPOSITION_DEVICE;
+        layer->updateValidateCompositionType(HWC2_COMPOSITION_DEVICE);
     }
     mIsSecureDRM = false;
     mIsNormalDRM = false;
@@ -500,8 +500,8 @@ void ExynosVirtualDisplay::handleAcquireFence()
     /* handle fence of DEVICE or EXYNOS composition layers */
     for (size_t i = 0; i < mLayers.size(); i++) {
         ExynosLayer *layer = mLayers[i];
-        if (layer->mValidateCompositionType == HWC2_COMPOSITION_DEVICE ||
-            layer->mValidateCompositionType == HWC2_COMPOSITION_EXYNOS) {
+        if (layer->getValidateCompositionType() == HWC2_COMPOSITION_DEVICE ||
+            layer->getValidateCompositionType() == HWC2_COMPOSITION_EXYNOS) {
             layer->mReleaseFence = layer->mAcquireFence;
             setFenceInfo(layer->mAcquireFence, this, FENCE_TYPE_SRC_ACQUIRE, FENCE_IP_LAYER,
                          HwcFenceDirection::TO);
diff --git a/libhwc2.1/libvrr/FileNode.cpp b/libhwc2.1/libvrr/FileNode.cpp
index 9da7e09..4ab5b9f 100644
--- a/libhwc2.1/libvrr/FileNode.cpp
+++ b/libhwc2.1/libvrr/FileNode.cpp
@@ -14,9 +14,10 @@
  * limitations under the License.
  */
 
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
 #include "FileNode.h"
-
 #include <log/log.h>
+#include <utils/Trace.h>
 #include <sstream>
 
 namespace android {
@@ -37,17 +38,18 @@ std::string FileNode::dump() {
     std::ostringstream os;
     os << "FileNode: root path: " << mNodePath << std::endl;
     for (const auto& item : mFds) {
-        auto lastWrittenValue = getLastWrittenValue(item.first);
-        os << "FileNode: sysfs node = " << item.first << ", last written value = 0x" << std::setw(8)
-           << std::setfill('0') << std::hex << lastWrittenValue << std::endl;
+        auto lastWrittenString = getLastWrittenString(item.first);
+        if (lastWrittenString)
+            os << "FileNode: sysfs node = " << item.first
+               << ", last written value = " << *lastWrittenString << std::endl;
     }
     return os.str();
 }
 
-uint32_t FileNode::getLastWrittenValue(const std::string& nodeName) {
+std::optional<std::string> FileNode::getLastWrittenString(const std::string& nodeName) {
     int fd = getFileHandler(nodeName);
-    if ((fd < 0) || (mLastWrittenValue.count(fd) <= 0)) return 0;
-    return mLastWrittenValue[fd];
+    if ((fd < 0) || (mLastWrittenString.count(fd) <= 0)) return std::nullopt;
+    return mLastWrittenString[fd];
 }
 
 std::optional<std::string> FileNode::readString(const std::string& nodeName) {
@@ -61,24 +63,6 @@ std::optional<std::string> FileNode::readString(const std::string& nodeName) {
     return std::nullopt;
 }
 
-bool FileNode::WriteUint32(const std::string& nodeName, uint32_t value) {
-    int fd = getFileHandler(nodeName);
-    if (fd >= 0) {
-        std::string cmdString = std::to_string(value);
-        int ret = write(fd, cmdString.c_str(), std::strlen(cmdString.c_str()));
-        if (ret < 0) {
-            ALOGE("Write 0x%x to file node %s%s failed, ret = %d errno = %d", value,
-                  mNodePath.c_str(), nodeName.c_str(), ret, errno);
-            return false;
-        }
-    } else {
-        ALOGE("Write to invalid file node %s%s", mNodePath.c_str(), nodeName.c_str());
-        return false;
-    }
-    mLastWrittenValue[fd] = value;
-    return true;
-}
-
 int FileNode::getFileHandler(const std::string& nodeName) {
     if (mFds.count(nodeName) > 0) {
         return mFds[nodeName];
@@ -93,5 +77,23 @@ int FileNode::getFileHandler(const std::string& nodeName) {
     return fd;
 }
 
+bool FileNode::writeString(const std::string& nodeName, const std::string& str) {
+    int fd = getFileHandler(nodeName);
+    if (fd < 0) {
+        ALOGE("Write to invalid file node %s%s", mNodePath.c_str(), nodeName.c_str());
+        return false;
+    }
+    int ret = write(fd, str.c_str(), str.size());
+    if (ret < 0) {
+        ALOGE("Write %s to file node %s%s failed, ret = %d errno = %d", str.c_str(),
+              mNodePath.c_str(), nodeName.c_str(), ret, errno);
+        return false;
+    }
+    std::ostringstream oss;
+    oss << "Write " << str << " to file node " << mNodePath.c_str() << nodeName.c_str();
+    ATRACE_NAME(oss.str().c_str());
+    mLastWrittenString[fd] = str;
+    return true;
+}
 }; // namespace hardware::graphics::composer
 }; // namespace android
diff --git a/libhwc2.1/libvrr/FileNode.h b/libhwc2.1/libvrr/FileNode.h
index 888de28..c33c6f6 100644
--- a/libhwc2.1/libvrr/FileNode.h
+++ b/libhwc2.1/libvrr/FileNode.h
@@ -34,18 +34,35 @@ public:
 
     std::string dump();
 
-    uint32_t getLastWrittenValue(const std::string& nodeName);
+    std::optional<std::string> getLastWrittenString(const std::string& nodeName);
+
+    template <typename T>
+    status_t getLastWrittenValue(const std::string& nodeName, T& value) {
+        int fd = getFileHandler(nodeName);
+        if (fd < 0) return BAD_VALUE;
+
+        auto iter = mLastWrittenString.find(fd);
+        if (iter == mLastWrittenString.end()) return BAD_VALUE;
+
+        std::istringstream iss(iter->second);
+        iss >> value;
+        return NO_ERROR;
+    }
 
     std::optional<std::string> readString(const std::string& nodeName);
 
-    bool WriteUint32(const std::string& nodeName, uint32_t value);
+    template <typename T>
+    bool writeValue(const std::string& nodeName, const T value) {
+        return writeString(nodeName, std::to_string(value));
+    }
 
-private:
     int getFileHandler(const std::string& nodeName);
 
+private:
     std::string mNodePath;
     std::unordered_map<std::string, int> mFds;
-    std::unordered_map<int, uint32_t> mLastWrittenValue;
+    std::unordered_map<int, std::string> mLastWrittenString;
+    bool writeString(const std::string& nodeName, const std::string& str);
 };
 
 class FileNodeManager : public Singleton<FileNodeManager> {
diff --git a/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.cpp b/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.cpp
index b59acbf..9fbd023 100644
--- a/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.cpp
+++ b/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.cpp
@@ -20,18 +20,6 @@
 
 namespace android::hardware::graphics::composer {
 
-// Currently, the FPS ranges from [1, |kMaxFrameRate| = 120], and the maximum TE
-// frequency(|kMaxTefrequency|) = 240. We express fps by dividing the maximum TE by the number of
-// vsync. Here, the numerator is set to |kMaxTefrequency|, fraction reduction is not needed here.
-const std::set<Fraction<int>> DisplayStateResidencyProvider::kFpsMappingTable =
-        {{240, 240}, {240, 120}, {240, 24}, {240, 10}, {240, 8}, {240, 7},
-         {240, 6},   {240, 5},   {240, 4},  {240, 3},  {240, 2}};
-
-const std::unordered_set<int> DisplayStateResidencyProvider::kFpsLowPowerModeMappingTable = {1, 30};
-
-const std::unordered_set<int> DisplayStateResidencyProvider::kActivePowerModes =
-        {HWC2_POWER_MODE_DOZE, HWC2_POWER_MODE_ON};
-
 namespace {
 
 static constexpr uint64_t MilliToNano = 1000000;
@@ -42,15 +30,11 @@ DisplayStateResidencyProvider::DisplayStateResidencyProvider(
         std::shared_ptr<CommonDisplayContextProvider> displayContextProvider,
         std::shared_ptr<StatisticsProvider> statisticsProvider)
       : mDisplayContextProvider(displayContextProvider), mStatisticsProvider(statisticsProvider) {
-    if (parseDisplayStateResidencyPattern()) {
-        generatePowerStatsStates();
-    }
+    generatePowerStatsStates();
     mStartStatisticTimeNs = mStatisticsProvider->getStartStatisticTimeNs();
 }
 
 void DisplayStateResidencyProvider::getStateResidency(std::vector<StateResidency>* stats) {
-    mapStatistics();
-
     int64_t powerStatsTotalTimeNs = aggregateStatistics();
 #ifdef DEBUG_VRR_POWERSTATS
     uint64_t statisticDurationNs = getBootClockTimeNs() - mStartStatisticTimeNs;
@@ -77,169 +61,116 @@ const std::vector<State>& DisplayStateResidencyProvider::getStates() {
     return mStates;
 }
 
-void DisplayStateResidencyProvider::mapStatistics() {
-    auto mUpdatedStatistics = mStatisticsProvider->getUpdatedStatistics();
-#ifdef DEBUG_VRR_POWERSTATS
-    for (const auto& item : mUpdatedStatistics) {
-        ALOGI("DisplayStateResidencyProvider : update key %s value %s",
-              item.first.toString().c_str(), item.second.toString().c_str());
-    }
-#endif
-    mRemappedStatistics.clear();
-    for (const auto& item : mUpdatedStatistics) {
-        mStatistics[item.first] = item.second;
-    }
-
-    for (const auto& item : mStatistics) {
-        const auto& displayPresentProfile = item.first;
-        PowerStatsPresentProfile powerStatsPresentProfile;
-        if (displayPresentProfile.mNumVsync <
-            0) { // To address the specific scenario of powering off.
-            powerStatsPresentProfile.mFps = -1;
-            mRemappedStatistics[powerStatsPresentProfile] += item.second;
-            mRemappedStatistics[powerStatsPresentProfile].mUpdated = true;
-            continue;
-        }
-        const auto& configId = displayPresentProfile.mCurrentDisplayConfig.mActiveConfigId;
-        powerStatsPresentProfile.mWidth = mDisplayContextProvider->getWidth(configId);
-        powerStatsPresentProfile.mHeight = mDisplayContextProvider->getHeight(configId);
-        powerStatsPresentProfile.mPowerMode =
-                displayPresentProfile.mCurrentDisplayConfig.mPowerMode;
-        powerStatsPresentProfile.mBrightnessMode =
-                displayPresentProfile.mCurrentDisplayConfig.mBrightnessMode;
-        auto teFrequency = mDisplayContextProvider->getTeFrequency(configId);
-        Fraction fps(teFrequency, displayPresentProfile.mNumVsync);
-        if ((kFpsMappingTable.count(fps) > 0)) {
-            powerStatsPresentProfile.mFps = fps.round();
-            mRemappedStatistics[powerStatsPresentProfile] += item.second;
-            mRemappedStatistics[powerStatsPresentProfile].mUpdated = true;
-        } else {
-            // Others.
-            auto key = powerStatsPresentProfile;
-            const auto& value = item.second;
-            key.mFps = 0;
-            mRemappedStatistics[key].mUpdated = true;
-            mRemappedStatistics[key].mCount += value.mCount;
-            mRemappedStatistics[key].mAccumulatedTimeNs += value.mAccumulatedTimeNs;
-            mRemappedStatistics[key].mLastTimeStampInBootClockNs =
-                    std::max(mRemappedStatistics[key].mLastTimeStampInBootClockNs,
-                             value.mLastTimeStampInBootClockNs);
-        }
-    }
-}
-
 uint64_t DisplayStateResidencyProvider::aggregateStatistics() {
     uint64_t totalTimeNs = 0;
-    for (auto& statistic : mRemappedStatistics) {
-        if (!statistic.second.mUpdated) {
-            continue;
-        }
-        auto it = mPowerStatsPresentProfileToIdMap.find(statistic.first);
-        if (it == mPowerStatsPresentProfileToIdMap.end()) {
+    std::set<int> firstIteration;
+    auto updatedStatistics = mStatisticsProvider->getUpdatedStatistics();
+    for (auto& statistic : updatedStatistics) {
+        auto it = mPowerStatsProfileToIdMap.find(statistic.first.toPowerStatsProfile());
+        if (it == mPowerStatsProfileToIdMap.end()) {
             ALOGE("DisplayStateResidencyProvider %s(): unregistered powerstats state [%s]",
-                  __func__, statistic.first.toString().c_str());
+                  __func__, statistic.first.toPowerStatsProfile().toString().c_str());
             continue;
         }
         int id = it->second;
         const auto& displayPresentRecord = statistic.second;
 
         auto& stateResidency = mStateResidency[id];
-        stateResidency.totalStateEntryCount = displayPresentRecord.mCount;
-        stateResidency.lastEntryTimestampMs =
-                displayPresentRecord.mLastTimeStampInBootClockNs / MilliToNano;
-        stateResidency.totalTimeInStateMs = displayPresentRecord.mAccumulatedTimeNs / MilliToNano;
+        if (firstIteration.count(id) > 0) {
+            stateResidency.totalStateEntryCount += displayPresentRecord.mCount;
+            stateResidency.lastEntryTimestampMs =
+                    std::max<uint64_t>(stateResidency.lastEntryTimestampMs,
+                                       displayPresentRecord.mLastTimeStampInBootClockNs /
+                                               MilliToNano);
+            stateResidency.totalTimeInStateMs +=
+                    displayPresentRecord.mAccumulatedTimeNs / MilliToNano;
+        } else {
+            stateResidency.totalStateEntryCount = displayPresentRecord.mCount;
+            stateResidency.lastEntryTimestampMs =
+                    displayPresentRecord.mLastTimeStampInBootClockNs / MilliToNano;
+            stateResidency.totalTimeInStateMs =
+                    displayPresentRecord.mAccumulatedTimeNs / MilliToNano;
+            firstIteration.insert(id);
+        }
+
         statistic.second.mUpdated = false;
         totalTimeNs += displayPresentRecord.mAccumulatedTimeNs;
     }
     return totalTimeNs;
 }
 
-void DisplayStateResidencyProvider::generatePowerStatsStates() {
+void DisplayStateResidencyProvider::generateUniqueStates() {
     auto configs = mDisplayContextProvider->getDisplayConfigs();
-    if (!configs) return;
-    std::set<PowerStatsPresentProfile> powerStatsPresentProfileCandidates;
-    PowerStatsPresentProfile powerStatsPresentProfile;
+    if (!configs) return; // Early return if no configs
 
-    // Generate a list of potential DisplayConfigProfiles.
-    // Include the special case 'OFF'.
-    powerStatsPresentProfile.mPowerMode = HWC2_POWER_MODE_OFF;
-    powerStatsPresentProfileCandidates.insert(powerStatsPresentProfile);
-    for (auto powerMode : kActivePowerModes) {
-        powerStatsPresentProfile.mPowerMode = powerMode;
-        for (int brightnesrMode = static_cast<int>(BrightnessMode::kNormalBrightnessMode);
-             brightnesrMode < BrightnessMode::kInvalidBrightnessMode; ++brightnesrMode) {
-            powerStatsPresentProfile.mBrightnessMode = static_cast<BrightnessMode>(brightnesrMode);
+    // Special case: Power mode OFF
+    mUniqueStates.emplace(PowerStatsProfile{.mPowerMode = HWC2_POWER_MODE_OFF}, "OFF");
+
+    // Iterate through all combinations
+    for (auto refreshSource : android::hardware::graphics::composer::kRefreshSource) {
+        for (auto powerMode : android::hardware::graphics::composer::kActivePowerModes) {
+            // LPM and NP is not possible. skipping
+            if (!isPresentRefresh(refreshSource) && powerMode == HWC2_POWER_MODE_DOZE) {
+                continue;
+            }
             for (const auto& config : *configs) {
-                powerStatsPresentProfile.mWidth = mDisplayContextProvider->getWidth(config.first);
-                powerStatsPresentProfile.mHeight = mDisplayContextProvider->getHeight(config.first);
-                // Handle the special case LPM(Low Power Mode).
-                if (powerMode == HWC_POWER_MODE_DOZE) {
-                    for (auto fps : kFpsLowPowerModeMappingTable) {
-                        powerStatsPresentProfile.mFps = fps;
-                        powerStatsPresentProfileCandidates.insert(powerStatsPresentProfile);
+                for (int brightnessMode = static_cast<int>(BrightnessMode::kNormalBrightnessMode);
+                     brightnessMode < static_cast<int>(BrightnessMode::kInvalidBrightnessMode);
+                     ++brightnessMode) {
+                    PowerStatsProfile
+                            profile{.mWidth = mDisplayContextProvider->getWidth(config.first),
+                                    .mHeight = mDisplayContextProvider->getHeight(config.first),
+                                    .mFps = 0, // Initially set to 0
+                                    .mPowerMode = powerMode,
+                                    .mBrightnessMode = static_cast<BrightnessMode>(brightnessMode),
+                                    .mRefreshSource = refreshSource};
+
+                    if (powerMode == HWC_POWER_MODE_DOZE) {
+                        for (auto fps :
+                             android::hardware::graphics::composer::kFpsLowPowerModeMappingTable) {
+                            profile.mFps = fps;
+                            mUniqueStates.emplace(profile,
+                                                  mPowerStatsProfileTokenGenerator
+                                                          .generateStateName(&profile));
+                        }
+                    } else {
+                        mUniqueStates.emplace(profile,
+                                              mPowerStatsProfileTokenGenerator.generateStateName(
+                                                      &profile));
+                        for (auto fps : android::hardware::graphics::composer::kFpsMappingTable) {
+                            profile.mFps = fps.round();
+                            mUniqueStates.emplace(profile,
+                                                  mPowerStatsProfileTokenGenerator
+                                                          .generateStateName(&profile));
+                        }
                     }
-                    continue;
-                }
-                // Include the special case: other fps.
-                powerStatsPresentProfile.mFps = 0;
-                powerStatsPresentProfileCandidates.insert(powerStatsPresentProfile);
-                for (auto fps : kFpsMappingTable) {
-                    powerStatsPresentProfile.mFps = fps.round();
-                    powerStatsPresentProfileCandidates.insert(powerStatsPresentProfile);
-                }
-            }
-        }
-    }
-
-    auto uniqueComp = [](const std::pair<std::string, PowerStatsPresentProfile>& v1,
-                         const std::pair<std::string, PowerStatsPresentProfile>& v2) {
-        return v1.first < v2.first;
-    };
-
-    // Transform candidate DisplayConfigProfiles into a string and eliminate duplicates.
-    std::set<std::pair<std::string, PowerStatsPresentProfile>, decltype(uniqueComp)> uniqueStates;
-    for (const auto& powerStatsPresentProfile : powerStatsPresentProfileCandidates) {
-        std::string stateName;
-        mPowerStatsPresentProfileTokenGenerator.setPowerStatsPresentProfile(
-                &powerStatsPresentProfile);
-        for (const auto& pattern : mDisplayStateResidencyPattern) {
-            const auto token = mPowerStatsPresentProfileTokenGenerator.generateToken(pattern.first);
-            if (token.has_value()) {
-                stateName += token.value();
-                // Handle special case when mode is 'OFF'.
-                if (pattern.first == "mode" && token.value() == "OFF") {
-                    break;
                 }
-            } else {
-                ALOGE("DisplayStateResidencyProvider %s(): cannot find token with label %s",
-                      __func__, pattern.first.c_str());
-                continue;
             }
-            stateName += pattern.second;
         }
-        uniqueStates.insert(std::make_pair(stateName, powerStatsPresentProfile));
     }
+}
 
-    auto sortComp = [](const std::pair<std::string, PowerStatsPresentProfile>& v1,
-                       const std::pair<std::string, PowerStatsPresentProfile>& v2) {
-        return v1.second < v2.second;
-    };
-    std::set<std::pair<std::string, PowerStatsPresentProfile>, decltype(sortComp)> sortedStates;
-    // Sort power stats according to a predefined order.
-    std::for_each(uniqueStates.begin(), uniqueStates.end(),
-                  [&](const std::pair<std::string, PowerStatsPresentProfile>& item) {
-                      sortedStates.insert(item);
-                  });
+void DisplayStateResidencyProvider::generatePowerStatsStates() {
+    generateUniqueStates();
 
     // Sort and assign a unique identifier to each state string.
-    mStateResidency.resize(sortedStates.size());
-    int id = 0;
+    std::map<std::string, int> stateNameIDMap;
     int index = 0;
-    for (const auto& state : sortedStates) {
-        mStates.push_back({id, state.first});
-        mPowerStatsPresentProfileToIdMap[state.second] = id;
-        mStateResidency[index++].id = id;
-        ++id;
+    for (const auto& state : mUniqueStates) {
+        auto it = stateNameIDMap.find(state.second);
+        int id = index;
+        // If the stateName already exists, update mPowerStatsProfileToIdMap, and skip
+        // updating mStates/Residency
+        if (it != stateNameIDMap.end()) {
+            id = it->second;
+        } else {
+            stateNameIDMap.insert({state.second, id});
+            index++;
+            mStates.push_back({id, state.second});
+            mStateResidency.emplace_back();
+            mStateResidency.back().id = id;
+        }
+        mPowerStatsProfileToIdMap[state.first] = id;
     }
 
 #ifdef DEBUG_VRR_POWERSTATS
@@ -250,35 +181,4 @@ void DisplayStateResidencyProvider::generatePowerStatsStates() {
 #endif
 }
 
-bool DisplayStateResidencyProvider::parseDisplayStateResidencyPattern() {
-    size_t start, end;
-    start = 0;
-    end = -1;
-    while (true) {
-        start = kDisplayStateResidencyPattern.find_first_of(kTokenLabelStart, end + 1);
-        if (start == std::string::npos) {
-            break;
-        }
-        ++start;
-        end = kDisplayStateResidencyPattern.find_first_of(kTokenLabelEnd, start);
-        if (end == std::string::npos) {
-            break;
-        }
-        std::string tokenLabel(kDisplayStateResidencyPattern.substr(start, end - start));
-
-        start = kDisplayStateResidencyPattern.find_first_of(kDelimiterStart, end + 1);
-        if (start == std::string::npos) {
-            break;
-        }
-        ++start;
-        end = kDisplayStateResidencyPattern.find_first_of(kDelimiterEnd, start);
-        if (end == std::string::npos) {
-            break;
-        }
-        std::string delimiter(kDisplayStateResidencyPattern.substr(start, end - start));
-        mDisplayStateResidencyPattern.emplace_back(std::make_pair(tokenLabel, delimiter));
-    }
-    return (end == kDisplayStateResidencyPattern.length() - 1);
-}
-
 } // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.h b/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.h
index 117f8f7..6804841 100644
--- a/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.h
+++ b/libhwc2.1/libvrr/Power/DisplayStateResidencyProvider.h
@@ -16,13 +16,14 @@
 
 #pragma once
 
-#include <unordered_set>
+#include <vector>
 
 #include <aidl/android/hardware/power/stats/State.h>
 #include <aidl/android/hardware/power/stats/StateResidency.h>
 
 #include "../Statistics/VariableRefreshRateStatistic.h"
-#include "PowerStatsPresentProfileTokenGenerator.h"
+#include "../display/common/Constants.h"
+#include "PowerStatsProfileTokenGenerator.h"
 
 // #define DEBUG_VRR_POWERSTATS 1
 
@@ -47,41 +48,25 @@ public:
     DisplayStateResidencyProvider& operator=(const DisplayStateResidencyProvider& other) = delete;
 
 private:
-    static const std::set<Fraction<int>> kFpsMappingTable;
-    static const std::unordered_set<int> kFpsLowPowerModeMappingTable;
-    static const std::unordered_set<int> kActivePowerModes;
-
-    // The format of pattern is: ([token label]'delimiter'?)*
-    static constexpr std::string_view kDisplayStateResidencyPattern =
-            "[mode](:)[width](x)[height](@)[fps]()";
-
-    static constexpr char kTokenLabelStart = '[';
-    static constexpr char kTokenLabelEnd = ']';
-    static constexpr char kDelimiterStart = '(';
-    static constexpr char kDelimiterEnd = ')';
+    static const std::vector<int> kActivePowerModes;
+    static const std::vector<RefreshSource> kRefreshSource;
 
     void mapStatistics();
     uint64_t aggregateStatistics();
 
     void generatePowerStatsStates();
 
-    bool parseDisplayStateResidencyPattern();
+    void generateUniqueStates();
 
     std::shared_ptr<CommonDisplayContextProvider> mDisplayContextProvider;
 
     std::shared_ptr<StatisticsProvider> mStatisticsProvider;
 
-    DisplayPresentStatistics mStatistics;
-
-    typedef std::map<PowerStatsPresentProfile, DisplayPresentRecord> PowerStatsPresentStatistics;
-
-    PowerStatsPresentStatistics mRemappedStatistics;
-
-    PowerStatsPresentProfileTokenGenerator mPowerStatsPresentProfileTokenGenerator;
-    std::vector<std::pair<std::string, std::string>> mDisplayStateResidencyPattern;
+    PowerStatsProfileTokenGenerator mPowerStatsProfileTokenGenerator;
 
+    std::set<std::pair<PowerStatsProfile, std::string>> mUniqueStates;
     std::vector<State> mStates;
-    std::map<PowerStatsPresentProfile, int> mPowerStatsPresentProfileToIdMap;
+    std::map<PowerStatsProfile, int> mPowerStatsProfileToIdMap;
 
 #ifdef DEBUG_VRR_POWERSTATS
     int64_t mLastGetStateResidencyTimeNs = -1;
diff --git a/libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.cpp b/libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.cpp
deleted file mode 100644
index eb2b327..0000000
--- a/libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.cpp
+++ /dev/null
@@ -1,83 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include "PowerStatsPresentProfileTokenGenerator.h"
-
-#include <string>
-#include <unordered_map>
-
-namespace android::hardware::graphics::composer {
-
-std::string PowerStatsPresentProfileTokenGenerator::generateModeToken() {
-    if (mPowerStatsProfile->isOff()) {
-        return "OFF";
-    } else {
-        if (mPowerStatsProfile->mPowerMode == HWC_POWER_MODE_DOZE) {
-            return "LPM";
-        }
-        return (mPowerStatsProfile->mBrightnessMode == BrightnessMode::kHighBrightnessMode) ? "HBM"
-                                                                                            : "NBM";
-    }
-}
-
-std::string PowerStatsPresentProfileTokenGenerator::generateWidthToken() {
-    if (mPowerStatsProfile->isOff()) {
-        return "";
-    }
-    return std::to_string(mPowerStatsProfile->mWidth);
-}
-
-std::string PowerStatsPresentProfileTokenGenerator::generateHeightToken() {
-    if (mPowerStatsProfile->isOff()) {
-        return "";
-    }
-    return std::to_string(mPowerStatsProfile->mHeight);
-}
-
-std::string PowerStatsPresentProfileTokenGenerator::generateFpsToken() {
-    if (mPowerStatsProfile->isOff()) {
-        return "";
-    }
-    if (mPowerStatsProfile->mFps == 0) {
-        return "oth";
-    }
-    return std::to_string(mPowerStatsProfile->mFps);
-}
-
-std::optional<std::string> PowerStatsPresentProfileTokenGenerator::generateToken(
-        const std::string& tokenLabel) {
-    static std::unordered_map<std::string, std::function<std::string()>> functors =
-            {{"mode", std::bind(&PowerStatsPresentProfileTokenGenerator::generateModeToken, this)},
-             {"width",
-              std::bind(&PowerStatsPresentProfileTokenGenerator::generateWidthToken, this)},
-             {"height",
-              std::bind(&PowerStatsPresentProfileTokenGenerator::generateHeightToken, this)},
-             {"fps", std::bind(&PowerStatsPresentProfileTokenGenerator::generateFpsToken, this)}};
-
-    if (!mPowerStatsProfile) {
-        ALOGE("%s: haven't set target mPowerStatsProfile", __func__);
-        return std::nullopt;
-    }
-
-    if (functors.find(tokenLabel) != functors.end()) {
-        return (functors[tokenLabel])();
-    } else {
-        ALOGE("%s syntax error: unable to find token label = %s", __func__, tokenLabel.c_str());
-        return std::nullopt;
-    }
-}
-
-} // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.h b/libhwc2.1/libvrr/Power/PowerStatsProfile.h
similarity index 73%
rename from libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.h
rename to libhwc2.1/libvrr/Power/PowerStatsProfile.h
index 7fb1034..c604859 100644
--- a/libhwc2.1/libvrr/Power/PowerStatsPresentProfileTokenGenerator.h
+++ b/libhwc2.1/libvrr/Power/PowerStatsProfile.h
@@ -16,15 +16,16 @@
 
 #pragma once
 
+#include <hardware/hwcomposer2.h>
 #include <optional>
+#include <sstream>
 #include <string>
 
-#include "../Statistics/VariableRefreshRateStatistic.h"
 #include "../display/common/CommonDisplayContextProvider.h"
 
 namespace android::hardware::graphics::composer {
 
-typedef struct PowerStatsPresentProfile {
+typedef struct PowerStatsProfile {
     inline bool isOff() const {
         if ((mPowerMode == HWC_POWER_MODE_OFF) || (mPowerMode == HWC_POWER_MODE_DOZE_SUSPEND)) {
             return true;
@@ -33,15 +34,16 @@ typedef struct PowerStatsPresentProfile {
         }
     }
 
-    bool operator==(const PowerStatsPresentProfile& rhs) const {
+    bool operator==(const PowerStatsProfile& rhs) const {
         if (isOff() || rhs.isOff()) {
             return isOff() == rhs.isOff();
         }
         return (mWidth == rhs.mWidth) && (mHeight == rhs.mHeight) && (mFps == rhs.mFps) &&
-                (mPowerMode == rhs.mPowerMode) && (mBrightnessMode == rhs.mBrightnessMode);
+                (mPowerMode == rhs.mPowerMode) && (mBrightnessMode == rhs.mBrightnessMode) &&
+                (mRefreshSource == rhs.mRefreshSource);
     }
 
-    bool operator<(const PowerStatsPresentProfile& rhs) const {
+    bool operator<(const PowerStatsProfile& rhs) const {
         if (isOff() && rhs.isOff()) {
             return false;
         }
@@ -50,6 +52,8 @@ typedef struct PowerStatsPresentProfile {
             return (isOff() || (mPowerMode < rhs.mPowerMode));
         } else if (mBrightnessMode != rhs.mBrightnessMode) {
             return mBrightnessMode < rhs.mBrightnessMode;
+        } else if (mRefreshSource != rhs.mRefreshSource) {
+            return mRefreshSource < rhs.mRefreshSource;
         } else if (mWidth != rhs.mWidth) {
             return mWidth < rhs.mWidth;
         } else if (mHeight != rhs.mHeight) {
@@ -64,6 +68,7 @@ typedef struct PowerStatsPresentProfile {
         os << "mWidth = " << mWidth;
         os << " mHeight = " << mHeight;
         os << " mFps = " << mFps;
+        os << ", mRefreshSource = " << mRefreshSource;
         os << ", power mode = " << mPowerMode;
         os << ", brightness = " << static_cast<int>(mBrightnessMode);
         return os.str();
@@ -74,29 +79,7 @@ typedef struct PowerStatsPresentProfile {
     int mFps = -1;
     int mPowerMode = HWC_POWER_MODE_OFF;
     BrightnessMode mBrightnessMode = BrightnessMode::kInvalidBrightnessMode;
-
-} PowerStatsPresentProfile;
-
-class PowerStatsPresentProfileTokenGenerator {
-public:
-    PowerStatsPresentProfileTokenGenerator() = default;
-
-    void setPowerStatsPresentProfile(const PowerStatsPresentProfile* powerStatsPresentProfile) {
-        mPowerStatsProfile = powerStatsPresentProfile;
-    }
-
-    std::optional<std::string> generateToken(const std::string& tokenLabel);
-
-private:
-    std::string generateModeToken();
-
-    std::string generateWidthToken();
-
-    std::string generateHeightToken();
-
-    std::string generateFpsToken();
-
-    const PowerStatsPresentProfile* mPowerStatsProfile;
-};
+    RefreshSource mRefreshSource = kRefreshSourceActivePresent;
+} PowerStatsProfile;
 
 } // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.cpp b/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.cpp
new file mode 100644
index 0000000..42834a8
--- /dev/null
+++ b/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.cpp
@@ -0,0 +1,170 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "PowerStatsProfileTokenGenerator.h"
+
+#include <string>
+#include <unordered_map>
+
+namespace android::hardware::graphics::composer {
+
+PowerStatsProfileTokenGenerator::PowerStatsProfileTokenGenerator() {
+    parseDisplayStateResidencyPattern();
+}
+
+std::string PowerStatsProfileTokenGenerator::generateRefreshSourceToken(
+        PowerStatsProfile* profile) const {
+    if (profile->isOff()) {
+        return "";
+    }
+
+    if (isPresentRefresh(profile->mRefreshSource)) {
+        return "p";
+    } else {
+        return "np";
+    }
+}
+
+std::string PowerStatsProfileTokenGenerator::generateModeToken(PowerStatsProfile* profile) const {
+    if (profile->isOff()) {
+        return "OFF";
+    } else {
+        if (profile->mPowerMode == HWC_POWER_MODE_DOZE) {
+            return "LPM";
+        }
+        return (profile->mBrightnessMode == BrightnessMode::kHighBrightnessMode) ? "HBM" : "NBM";
+    }
+}
+
+std::string PowerStatsProfileTokenGenerator::generateWidthToken(PowerStatsProfile* profile) const {
+    if (profile->isOff()) {
+        return "";
+    }
+    return std::to_string(profile->mWidth);
+}
+
+std::string PowerStatsProfileTokenGenerator::generateHeightToken(PowerStatsProfile* profile) const {
+    if (profile->isOff()) {
+        return "";
+    }
+    return std::to_string(profile->mHeight);
+}
+
+std::string PowerStatsProfileTokenGenerator::generateFpsToken(PowerStatsProfile* profile) const {
+    if (profile->isOff()) {
+        return "";
+    }
+    if (profile->mFps == 0) {
+        return "oth";
+    }
+    return std::to_string(profile->mFps);
+}
+
+std::optional<std::string> PowerStatsProfileTokenGenerator::generateToken(
+        const std::string& tokenLabel, PowerStatsProfile* profile) {
+    static std::unordered_map<std::string, std::function<std::string(PowerStatsProfile*)>>
+            functors = {{"refreshSource",
+                         std::bind(&PowerStatsProfileTokenGenerator::generateRefreshSourceToken,
+                                   this, std::placeholders::_1)},
+                        {"mode",
+                         std::bind(&PowerStatsProfileTokenGenerator::generateModeToken, this,
+                                   std::placeholders::_1)},
+                        {"width",
+                         std::bind(&PowerStatsProfileTokenGenerator::generateWidthToken, this,
+                                   std::placeholders::_1)},
+                        {"height",
+                         std::bind(&PowerStatsProfileTokenGenerator::generateHeightToken, this,
+                                   std::placeholders::_1)},
+                        {"fps",
+                         std::bind(&PowerStatsProfileTokenGenerator::generateFpsToken, this,
+                                   std::placeholders::_1)}};
+
+    if (functors.find(tokenLabel) != functors.end()) {
+        return (functors[tokenLabel])(profile);
+    } else {
+        ALOGE("%s syntax error: unable to find token label = %s", __func__, tokenLabel.c_str());
+        return std::nullopt;
+    }
+}
+
+std::string PowerStatsProfileTokenGenerator::generateStateName(PowerStatsProfile* profile,
+                                                               bool enableMapping) {
+    std::string stateName;
+    const std::vector<std::pair<std::string, std::string>>& residencyPattern =
+            !isPresentRefresh(profile->mRefreshSource) ? mNonPresentDisplayStateResidencyPatternList
+                                                       : mPresentDisplayStateResidencyPatternList;
+
+    for (const auto& pattern : residencyPattern) {
+        const auto token = generateToken(pattern.first, profile);
+        if (token.has_value()) {
+            stateName += token.value();
+            if (pattern.first == "mode" && token.value() == "OFF") {
+                break;
+            }
+        } else {
+            ALOGE("DisplayStateResidencyProvider %s(): cannot find token with label %s", __func__,
+                  pattern.first.c_str());
+            continue;
+        }
+        stateName += pattern.second;
+    }
+    if (!enableMapping && !isPresentRefresh(profile->mRefreshSource)) {
+        stateName += generateFpsToken(profile);
+    }
+    return stateName;
+}
+
+bool PowerStatsProfileTokenGenerator::parseResidencyPattern(
+        std::vector<std::pair<std::string, std::string>>& residencyPatternMap,
+        const std::string_view residencyPattern) {
+    size_t start, end;
+    start = 0;
+    end = -1;
+    while (true) {
+        start = residencyPattern.find_first_of(kTokenLabelStart, end + 1);
+        if (start == std::string::npos) {
+            break;
+        }
+        ++start;
+        end = residencyPattern.find_first_of(kTokenLabelEnd, start);
+        if (end == std::string::npos) {
+            break;
+        }
+        std::string tokenLabel(residencyPattern.substr(start, end - start));
+
+        start = residencyPattern.find_first_of(kDelimiterStart, end + 1);
+        if (start == std::string::npos) {
+            break;
+        }
+        ++start;
+        end = residencyPattern.find_first_of(kDelimiterEnd, start);
+        if (end == std::string::npos) {
+            break;
+        }
+        std::string delimiter(residencyPattern.substr(start, end - start));
+        residencyPatternMap.emplace_back(std::make_pair(tokenLabel, delimiter));
+    }
+    return (end == residencyPattern.length() - 1);
+}
+
+bool PowerStatsProfileTokenGenerator::parseDisplayStateResidencyPattern() {
+    return parseResidencyPattern(mPresentDisplayStateResidencyPatternList,
+                                 kPresentDisplayStateResidencyPattern) &&
+            parseResidencyPattern(mNonPresentDisplayStateResidencyPatternList,
+                                  kNonPresentDisplayStateResidencyPattern);
+}
+
+} // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.h b/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.h
new file mode 100644
index 0000000..a6f424e
--- /dev/null
+++ b/libhwc2.1/libvrr/Power/PowerStatsProfileTokenGenerator.h
@@ -0,0 +1,124 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <optional>
+#include <string>
+
+#include "../display/common/CommonDisplayContextProvider.h"
+#include "PowerStatsProfile.h"
+
+namespace android::hardware::graphics::composer {
+
+struct StateNameComparator {
+    bool operator()(const std::string& a, const std::string& b) const {
+        // 1. Find the last '@' in both strings
+        size_t posA = a.rfind('@');
+        size_t posB = b.rfind('@');
+
+        // 2. Extract the parts before and after the '@'
+        std::string prefixA = (posA != std::string::npos) ? a.substr(0, posA) : a;
+        std::string suffixA = (posA != std::string::npos) ? a.substr(posA + 1) : "";
+        std::string prefixB = (posB != std::string::npos) ? b.substr(0, posB) : b;
+        std::string suffixB = (posB != std::string::npos) ? b.substr(posB + 1) : "";
+
+        // 3. Compare prefixes first
+        if (prefixA != prefixB) {
+            return prefixA < prefixB;
+        }
+
+        // 4. If prefixes are the same, check for "np" and extract numeric parts
+        bool hasNpA = suffixA.find("np") == 0;
+        bool hasNpB = suffixB.find("np") == 0;
+        std::string numPartA = hasNpA ? suffixA.substr(2) : suffixA;
+        std::string numPartB = hasNpB ? suffixB.substr(2) : suffixB;
+
+        // 5. Compare based on "np" presence
+        if (hasNpA != hasNpB) {
+            return !hasNpA; // "np" prefixes come after non-"np" prefixes
+        }
+
+        // 6. If both have "np" or neither has it, compare numeric parts
+        bool isNumA = std::all_of(numPartA.begin(), numPartA.end(), ::isdigit);
+        bool isNumB = std::all_of(numPartB.begin(), numPartB.end(), ::isdigit);
+
+        if (isNumA && isNumB) {
+            char* endPtrA;
+            char* endPtrB;
+
+            long numA = strtol(numPartA.c_str(), &endPtrA, 10);
+            long numB = strtol(numPartB.c_str(), &endPtrB, 10);
+
+            if (*endPtrA != '\0' || *endPtrB != '\0' || numA < std::numeric_limits<int>::min() ||
+                numA > std::numeric_limits<int>::max() || numB < std::numeric_limits<int>::min() ||
+                numB > std::numeric_limits<int>::max()) {
+                ALOGE("Error parsing numeric parts in KeyComparator");
+
+                return false;
+            }
+
+            return numA < numB;
+        } else {
+            return suffixA < suffixB;
+        }
+    }
+};
+
+class PowerStatsProfileTokenGenerator {
+public:
+    PowerStatsProfileTokenGenerator();
+
+    std::optional<std::string> generateToken(const std::string& tokenLabel,
+                                             PowerStatsProfile* profile);
+
+    std::string generateStateName(PowerStatsProfile* profile, bool enableMapping = true);
+
+private:
+    // The format of pattern is: ([token label]'delimiter'?)*
+    static constexpr std::string_view kPresentDisplayStateResidencyPattern =
+            "[mode](:)[width](x)[height](@)[fps]()";
+
+    // The format of pattern is: ([token label]'delimiter'?)*
+    static constexpr std::string_view kNonPresentDisplayStateResidencyPattern =
+            "[mode](:)[width](x)[height](@)[refreshSource]()";
+
+    static constexpr char kTokenLabelStart = '[';
+    static constexpr char kTokenLabelEnd = ']';
+    static constexpr char kDelimiterStart = '(';
+    static constexpr char kDelimiterEnd = ')';
+
+    bool parseDisplayStateResidencyPattern();
+
+    bool parseResidencyPattern(
+            std::vector<std::pair<std::string, std::string>>& residencyPatternMap,
+            const std::string_view residencyPattern);
+
+    std::string generateRefreshSourceToken(PowerStatsProfile* profile) const;
+
+    std::string generateModeToken(PowerStatsProfile* profile) const;
+
+    std::string generateWidthToken(PowerStatsProfile* profile) const;
+
+    std::string generateHeightToken(PowerStatsProfile* profile) const;
+
+    std::string generateFpsToken(PowerStatsProfile* profile) const;
+
+    std::vector<std::pair<std::string, std::string>> mNonPresentDisplayStateResidencyPatternList;
+    std::vector<std::pair<std::string, std::string>> mPresentDisplayStateResidencyPatternList;
+};
+
+} // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
index b1a58ca..8af158a 100644
--- a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
+++ b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.cpp
@@ -44,12 +44,12 @@ VariableRefreshRateStatistic::VariableRefreshRateStatistic(
     mUpdateEvent.mWhenNs = getSteadyClockTimeNs() + mUpdatePeriodNs;
     mEventQueue->mPriorityQueue.emplace(mUpdateEvent);
 #endif
-    mStatistics[mDisplayPresentProfile] = DisplayPresentRecord();
+    mStatistics[mDisplayRefreshProfile] = DisplayRefreshRecord();
 }
 
 uint64_t VariableRefreshRateStatistic::getPowerOffDurationNs() const {
     if (isPowerModeOffNowLocked()) {
-        const auto& item = mStatistics.find(mDisplayPresentProfile);
+        const auto& item = mStatistics.find(mDisplayRefreshProfile);
         if (item == mStatistics.end()) {
             ALOGE("%s We should have inserted power-off item in constructor.", __func__);
             return 0;
@@ -65,38 +65,155 @@ uint64_t VariableRefreshRateStatistic::getStartStatisticTimeNs() const {
     return mStartStatisticTimeNs;
 }
 
-DisplayPresentStatistics VariableRefreshRateStatistic::getStatistics() {
+DisplayRefreshStatistics VariableRefreshRateStatistic::getStatistics() {
     updateIdleStats();
     std::scoped_lock lock(mMutex);
     return mStatistics;
 }
 
-DisplayPresentStatistics VariableRefreshRateStatistic::getUpdatedStatistics() {
+DisplayRefreshStatistics VariableRefreshRateStatistic::getUpdatedStatistics() {
     updateIdleStats();
     std::scoped_lock lock(mMutex);
-    DisplayPresentStatistics updatedStatistics;
+    DisplayRefreshStatistics updatedStatistics;
     for (auto& it : mStatistics) {
         if (it.second.mUpdated) {
             if (it.first.mNumVsync < 0) {
                 it.second.mAccumulatedTimeNs = getPowerOffDurationNs();
             }
-            updatedStatistics[it.first] = it.second;
-            it.second.mUpdated = false;
         }
+        // need all mStatistics to be able to do aggregation and bucketing accurately
+        updatedStatistics[it.first] = it.second;
     }
     if (isPowerModeOffNowLocked()) {
-        mStatistics[mDisplayPresentProfile].mUpdated = true;
+        mStatistics[mDisplayRefreshProfile].mUpdated = true;
     }
+
     return std::move(updatedStatistics);
 }
 
+std::string VariableRefreshRateStatistic::dumpStatistics(bool getUpdatedOnly,
+                                                         RefreshSource refreshSource,
+                                                         const std::string& delimiter) {
+    std::string res;
+    updateIdleStats();
+    std::scoped_lock lock(mMutex);
+    for (auto& it : mStatistics) {
+        if ((!getUpdatedOnly) || (it.second.mUpdated)) {
+            if (it.first.mRefreshSource & refreshSource) {
+                if (it.first.mNumVsync < 0) {
+                    it.second.mAccumulatedTimeNs = getPowerOffDurationNs();
+                }
+                res += "[";
+                res += it.first.toString();
+                res += " , ";
+                res += it.second.toString();
+                res += "]";
+                res += delimiter;
+            }
+        }
+    }
+    return res;
+}
+
+std::string VariableRefreshRateStatistic::normalizeString(const std::string& input) {
+    static constexpr int kDesiredLength = 30;
+    static constexpr int kSpaceWidth = 1;
+    int extraSpacesNeeded = std::max(0, (kDesiredLength - static_cast<int>(input.length())));
+    return input + std::string(extraSpacesNeeded, ' ');
+}
+
+void VariableRefreshRateStatistic::dump(String8& result, const std::vector<std::string>& args) {
+    bool hasDelta = false;
+
+    if (!args.empty()) {
+        for (const auto& arg : args) {
+            std::string lowercaseArg = arg;
+            std::transform(lowercaseArg.begin(), lowercaseArg.end(), lowercaseArg.begin(),
+                           [](unsigned char c) { return std::tolower(c); });
+
+            if (lowercaseArg.find("delta") != std::string::npos) {
+                hasDelta = true;
+            }
+        }
+    }
+
+    auto updatedStatistics = getUpdatedStatistics();
+    auto curTime = getSteadyClockTimeNs();
+    std::map<std::string, DisplayRefreshRecord, StateNameComparator> aggregatedStats;
+    std::map<std::string, DisplayRefreshRecord> aggregatedStatsSnapshot;
+    // Aggregating lastSnapshot dumpsys to calculate delta
+    for (const auto& it : mStatisticsSnapshot) {
+        PowerStatsProfile profile = it.first.toPowerStatsProfile(false);
+        std::string stateName = mPowerStatsProfileTokenGenerator.generateStateName(&profile, false);
+        aggregatedStatsSnapshot[stateName] += it.second;
+    }
+
+    for (const auto& it : updatedStatistics) {
+        PowerStatsProfile profile = it.first.toPowerStatsProfile(false);
+        std::string stateName = mPowerStatsProfileTokenGenerator.generateStateName(&profile, false);
+        aggregatedStats[stateName] += it.second;
+    }
+
+    if (hasDelta) {
+        result.appendFormat("Elapsed Time: %lu \n", (curTime - mLastDumpsysTime) / 1000000);
+    }
+
+    std::string headerString = hasDelta ? normalizeString("StateName") + "\t" +
+                    normalizeString("Total Time (ms)") + "\t" + normalizeString("Delta") + "\t" +
+                    normalizeString("Total Entries") + "\t" + normalizeString("Delta") + "\t" +
+                    normalizeString("Last Entry TStamp (ms)") + "\t" + normalizeString("Delta")
+                                        : normalizeString("StateName") + "\t" +
+                    normalizeString("Total Time (ms)") + "\t" + normalizeString("Total Entries") +
+                    "\t" + normalizeString("Last Entry TStamp (ms)");
+
+    result.appendFormat("%s \n", headerString.c_str());
+
+    for (const auto& it : aggregatedStats) {
+        uint64_t countDelta = 0;
+        uint64_t accumulatedTimeNsDelta = 0;
+        uint64_t lastTimeStampInBootClockNsDelta = 0;
+
+        auto agIt = aggregatedStatsSnapshot.find(it.first);
+        if (agIt != aggregatedStatsSnapshot.end()) {
+            countDelta = it.second.mCount - agIt->second.mCount;
+            accumulatedTimeNsDelta = it.second.mAccumulatedTimeNs - agIt->second.mAccumulatedTimeNs;
+            lastTimeStampInBootClockNsDelta = it.second.mLastTimeStampInBootClockNs -
+                    agIt->second.mLastTimeStampInBootClockNs;
+        }
+
+        std::string statsString = hasDelta
+                ? normalizeString(it.first) + "\t" +
+                        normalizeString(std::to_string(it.second.mAccumulatedTimeNs / 1000000)) +
+                        "\t" + normalizeString(std::to_string(accumulatedTimeNsDelta / 1000000)) +
+                        "\t" + normalizeString(std::to_string(it.second.mCount)) + "\t" +
+                        normalizeString(std::to_string(countDelta)) + "\t" +
+                        normalizeString(
+                                std::to_string(it.second.mLastTimeStampInBootClockNs / 1000000)) +
+                        "\t" +
+                        normalizeString(std::to_string(lastTimeStampInBootClockNsDelta / 1000000))
+                :
+
+                normalizeString(it.first) + "\t" +
+                        normalizeString(std::to_string(it.second.mAccumulatedTimeNs / 1000000)) +
+                        "\t" + normalizeString(std::to_string(it.second.mCount)) + "\t" +
+                        normalizeString(
+                                std::to_string(it.second.mLastTimeStampInBootClockNs / 1000000));
+
+        result.appendFormat("%s \n", statsString.c_str());
+    }
+
+    // Take a snapshot of updatedStatistics and time
+    mLastDumpsysTime = curTime;
+    mStatisticsSnapshot = DisplayRefreshStatistics(updatedStatistics);
+}
+
 void VariableRefreshRateStatistic::onPowerStateChange(int from, int to) {
     if (from == to) {
         return;
     }
-    if (mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode != from) {
+    if (mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode != from) {
         ALOGE("%s Power mode mismatch between storing state(%d) and actual mode(%d)", __func__,
-              mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode, from);
+              mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode, from);
     }
     updateIdleStats();
     std::scoped_lock lock(mMutex);
@@ -104,24 +221,24 @@ void VariableRefreshRateStatistic::onPowerStateChange(int from, int to) {
         // Currently the for power stats both |HWC_POWER_MODE_OFF| and |HWC_POWER_MODE_DOZE_SUSPEND|
         // are classified as "off" states in power statistics. Consequently,we assign the value of
         // |HWC_POWER_MODE_OFF| to |mPowerMode| when it is |HWC_POWER_MODE_DOZE_SUSPEND|.
-        mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode = HWC_POWER_MODE_OFF;
+        mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode = HWC_POWER_MODE_OFF;
 
-        auto& record = mStatistics[mDisplayPresentProfile];
+        auto& record = mStatistics[mDisplayRefreshProfile];
         ++record.mCount;
         record.mLastTimeStampInBootClockNs = getBootClockTimeNs();
         record.mUpdated = true;
 
-        mLastPresentTimeInBootClockNs = kDefaultInvalidPresentTimeNs;
+        mLastRefreshTimeInBootClockNs = kDefaultInvalidPresentTimeNs;
     } else {
         if (isPowerModeOff(from)) {
             mPowerOffDurationNs +=
                     (getBootClockTimeNs() -
-                     mStatistics[mDisplayPresentProfile].mLastTimeStampInBootClockNs);
+                     mStatistics[mDisplayRefreshProfile].mLastTimeStampInBootClockNs);
         }
-        mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode = to;
+        mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode = to;
         if (to == HWC_POWER_MODE_DOZE) {
-            mDisplayPresentProfile.mNumVsync = mTeFrequency;
-            auto& record = mStatistics[mDisplayPresentProfile];
+            mDisplayRefreshProfile.mNumVsync = mTeFrequency;
+            auto& record = mStatistics[mDisplayRefreshProfile];
             ++record.mCount;
             record.mLastTimeStampInBootClockNs = getBootClockTimeNs();
             record.mUpdated = true;
@@ -130,41 +247,58 @@ void VariableRefreshRateStatistic::onPowerStateChange(int from, int to) {
 }
 
 void VariableRefreshRateStatistic::onPresent(int64_t presentTimeNs, int flag) {
-    int64_t presentTimeInBootClockNs = steadyClockTimeToBootClockTimeNs(presentTimeNs);
-    if (mLastPresentTimeInBootClockNs == kDefaultInvalidPresentTimeNs) {
-        mLastPresentTimeInBootClockNs = presentTimeInBootClockNs;
+    onRefreshInternal(presentTimeNs, flag, RefreshSource::kRefreshSourceActivePresent);
+}
+
+void VariableRefreshRateStatistic::onNonPresentRefresh(int64_t refreshTimeNs,
+                                                       RefreshSource refreshSource) {
+    onRefreshInternal(refreshTimeNs, 0, refreshSource);
+}
+
+void VariableRefreshRateStatistic::onRefreshInternal(int64_t refreshTimeNs, int flag,
+                                                     RefreshSource refreshSource) {
+    int64_t presentTimeInBootClockNs = steadyClockTimeToBootClockTimeNs(refreshTimeNs);
+    if (mLastRefreshTimeInBootClockNs == kDefaultInvalidPresentTimeNs) {
+        mLastRefreshTimeInBootClockNs = presentTimeInBootClockNs;
         updateCurrentDisplayStatus();
-        // Ignore first present after resume
+        // Ignore first refresh after resume
         return;
     }
     updateIdleStats(presentTimeInBootClockNs);
     updateCurrentDisplayStatus();
     if (hasPresentFrameFlag(flag, PresentFrameFlag::kPresentingWhenDoze)) {
         // In low power mode, panel boost to 30 Hz while presenting new frame.
-        mDisplayPresentProfile.mNumVsync = mTeFrequency / kFrameRateWhenPresentAtLpMode;
-        mLastPresentTimeInBootClockNs =
+        mDisplayRefreshProfile.mNumVsync = mTeFrequency / kFrameRateWhenPresentAtLpMode;
+        mLastRefreshTimeInBootClockNs =
                 presentTimeInBootClockNs + (std::nano::den / kFrameRateWhenPresentAtLpMode);
     } else {
-        int numVsync = roundDivide((presentTimeInBootClockNs - mLastPresentTimeInBootClockNs),
+        int numVsync = roundDivide((presentTimeInBootClockNs - mLastRefreshTimeInBootClockNs),
                                    mTeIntervalNs);
+        // TODO(b/353976456): Implement a scheduler to avoid conflicts between present and
+        // non-present refresh. Currently, If a conflict occurs, both present and non-present
+        // refresh may request to take effect simultaneously, resulting in a zero duration between
+        // them. To address this, we avoid including statistics with zero duration. This issue
+        // should be resolved once the scheduler is implemented.
+        if (numVsync == 0) return;
         numVsync = std::max(1, std::min(mTeFrequency, numVsync));
-        mDisplayPresentProfile.mNumVsync = numVsync;
-        mLastPresentTimeInBootClockNs = presentTimeInBootClockNs;
+        mDisplayRefreshProfile.mNumVsync = numVsync;
+        mLastRefreshTimeInBootClockNs = presentTimeInBootClockNs;
+        mDisplayRefreshProfile.mRefreshSource = refreshSource;
     }
     {
         std::scoped_lock lock(mMutex);
 
-        auto& record = mStatistics[mDisplayPresentProfile];
+        auto& record = mStatistics[mDisplayRefreshProfile];
         ++record.mCount;
-        record.mAccumulatedTimeNs += (mTeIntervalNs * mDisplayPresentProfile.mNumVsync);
+        record.mAccumulatedTimeNs += (mTeIntervalNs * mDisplayRefreshProfile.mNumVsync);
         record.mLastTimeStampInBootClockNs = presentTimeInBootClockNs;
         record.mUpdated = true;
         if (hasPresentFrameFlag(flag, PresentFrameFlag::kPresentingWhenDoze)) {
             // After presenting a frame in AOD, we revert back to 1 Hz operation.
-            mDisplayPresentProfile.mNumVsync = mTeFrequency;
-            auto& record = mStatistics[mDisplayPresentProfile];
+            mDisplayRefreshProfile.mNumVsync = mTeFrequency;
+            auto& record = mStatistics[mDisplayRefreshProfile];
             ++record.mCount;
-            record.mLastTimeStampInBootClockNs = mLastPresentTimeInBootClockNs;
+            record.mLastTimeStampInBootClockNs = mLastRefreshTimeInBootClockNs;
             record.mUpdated = true;
         }
     }
@@ -172,7 +306,10 @@ void VariableRefreshRateStatistic::onPresent(int64_t presentTimeNs, int flag) {
 
 void VariableRefreshRateStatistic::setActiveVrrConfiguration(int activeConfigId, int teFrequency) {
     updateIdleStats();
-    mDisplayPresentProfile.mCurrentDisplayConfig.mActiveConfigId = activeConfigId;
+    mDisplayRefreshProfile.mCurrentDisplayConfig.mActiveConfigId = activeConfigId;
+    mDisplayRefreshProfile.mWidth = mDisplayContextProvider->getWidth(activeConfigId);
+    mDisplayRefreshProfile.mHeight = mDisplayContextProvider->getHeight(activeConfigId);
+    mDisplayRefreshProfile.mTeFrequency = mDisplayContextProvider->getTeFrequency(activeConfigId);
     mTeFrequency = teFrequency;
     if (mTeFrequency % mMaxFrameRate != 0) {
         ALOGW("%s TE frequency does not align with the maximum frame rate as a multiplier.",
@@ -200,61 +337,70 @@ void VariableRefreshRateStatistic::setFixedRefreshRate(uint32_t rate) {
                       __func__);
             }
         } else {
-            mMaximumFrameIntervalNs = kMaxPresentIntervalNs;
+            mMaximumFrameIntervalNs = kMaxRefreshIntervalNs;
         }
     }
 }
 
 bool VariableRefreshRateStatistic::isPowerModeOffNowLocked() const {
-    return isPowerModeOff(mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode);
+    return isPowerModeOff(mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode);
 }
 
 void VariableRefreshRateStatistic::updateCurrentDisplayStatus() {
-    mDisplayPresentProfile.mCurrentDisplayConfig.mBrightnessMode =
+    mDisplayRefreshProfile.mCurrentDisplayConfig.mBrightnessMode =
             mDisplayContextProvider->getBrightnessMode();
-    if (mDisplayPresentProfile.mCurrentDisplayConfig.mBrightnessMode ==
+    if (mDisplayRefreshProfile.mCurrentDisplayConfig.mBrightnessMode ==
         BrightnessMode::kInvalidBrightnessMode) {
-        mDisplayPresentProfile.mCurrentDisplayConfig.mBrightnessMode =
+        mDisplayRefreshProfile.mCurrentDisplayConfig.mBrightnessMode =
                 BrightnessMode::kNormalBrightnessMode;
     }
 }
 
 void VariableRefreshRateStatistic::updateIdleStats(int64_t endTimeStampInBootClockNs) {
-    if (mDisplayPresentProfile.isOff()) return;
-    if (mLastPresentTimeInBootClockNs == kDefaultInvalidPresentTimeNs) return;
+    if (mDisplayRefreshProfile.isOff()) return;
+    if (mLastRefreshTimeInBootClockNs == kDefaultInvalidPresentTimeNs) return;
 
     endTimeStampInBootClockNs =
             endTimeStampInBootClockNs < 0 ? getBootClockTimeNs() : endTimeStampInBootClockNs;
-    auto durationFromLastPresentNs = endTimeStampInBootClockNs - mLastPresentTimeInBootClockNs;
+    auto durationFromLastPresentNs = endTimeStampInBootClockNs - mLastRefreshTimeInBootClockNs;
     durationFromLastPresentNs = durationFromLastPresentNs < 0 ? 0 : durationFromLastPresentNs;
-    if (mDisplayPresentProfile.mCurrentDisplayConfig.mPowerMode == HWC_POWER_MODE_DOZE) {
-        mDisplayPresentProfile.mNumVsync = mTeFrequency;
+    if (mDisplayRefreshProfile.mCurrentDisplayConfig.mPowerMode == HWC_POWER_MODE_DOZE) {
+        mDisplayRefreshProfile.mNumVsync = mTeFrequency;
 
         std::scoped_lock lock(mMutex);
 
-        auto& record = mStatistics[mDisplayPresentProfile];
+        auto& record = mStatistics[mDisplayRefreshProfile];
         record.mAccumulatedTimeNs += durationFromLastPresentNs;
-        record.mLastTimeStampInBootClockNs = mLastPresentTimeInBootClockNs;
-        mLastPresentTimeInBootClockNs = endTimeStampInBootClockNs;
+        record.mLastTimeStampInBootClockNs = mLastRefreshTimeInBootClockNs;
+        mLastRefreshTimeInBootClockNs = endTimeStampInBootClockNs;
         record.mUpdated = true;
     } else {
+        if ((mMinimumRefreshRate > 1) &&
+            (!isPresentRefresh(mDisplayRefreshProfile.mRefreshSource))) {
+            ALOGE("%s We should not have non-present refresh when the minimum refresh rate is set, "
+                  "as it should use auto mode.",
+                  __func__);
+            return;
+        }
+        mDisplayRefreshProfile.mRefreshSource = RefreshSource::kRefreshSourceIdlePresent;
+
         int numVsync = roundDivide(durationFromLastPresentNs, mTeIntervalNs);
-        mDisplayPresentProfile.mNumVsync =
+        mDisplayRefreshProfile.mNumVsync =
                 (mMinimumRefreshRate > 1 ? (mTeFrequency / mMinimumRefreshRate) : mTeFrequency);
-        if (numVsync <= mDisplayPresentProfile.mNumVsync) return;
+        if (numVsync <= mDisplayRefreshProfile.mNumVsync) return;
 
         // Ensure that the last vsync should not be included now, since it would be processed for
         // next update or |onPresent|
-        auto count = (numVsync - 1) / mDisplayPresentProfile.mNumVsync;
+        auto count = (numVsync - 1) / mDisplayRefreshProfile.mNumVsync;
         auto alignedDurationNs = mMaximumFrameIntervalNs * count;
         {
             std::scoped_lock lock(mMutex);
 
-            auto& record = mStatistics[mDisplayPresentProfile];
+            auto& record = mStatistics[mDisplayRefreshProfile];
             record.mCount += count;
             record.mAccumulatedTimeNs += alignedDurationNs;
-            mLastPresentTimeInBootClockNs += alignedDurationNs;
-            record.mLastTimeStampInBootClockNs = mLastPresentTimeInBootClockNs;
+            mLastRefreshTimeInBootClockNs += alignedDurationNs;
+            record.mLastTimeStampInBootClockNs = mLastRefreshTimeInBootClockNs;
             record.mUpdated = true;
         }
     }
diff --git a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.h b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.h
index 926f004..ec67194 100644
--- a/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.h
+++ b/libhwc2.1/libvrr/Statistics/VariableRefreshRateStatistic.h
@@ -22,9 +22,12 @@
 #include <string>
 #include <utility>
 
+#include "../Power/PowerStatsProfile.h"
+#include "../Power/PowerStatsProfileTokenGenerator.h"
 #include "EventQueue.h"
 #include "Utils.h"
 #include "display/common/CommonDisplayContextProvider.h"
+#include "display/common/Constants.h"
 #include "interface/DisplayContextProvider.h"
 #include "interface/VariableRefreshRateInterface.h"
 
@@ -78,11 +81,36 @@ typedef struct DisplayStatus {
     BrightnessMode mBrightnessMode = BrightnessMode::kInvalidBrightnessMode;
 } DisplayStatus;
 
-// |DisplayPresentProfile| is the key to the statistics.
-typedef struct DisplayPresentProfile {
+// |DisplayRefreshProfile| is the key to the statistics.
+typedef struct DisplayRefreshProfile {
+    PowerStatsProfile toPowerStatsProfile(bool enableMapping = true) const {
+        PowerStatsProfile powerStatsProfile;
+        if (mNumVsync < 0) { // To address the specific scenario of powering off
+            powerStatsProfile.mFps = -1;
+            return powerStatsProfile;
+        }
+        powerStatsProfile.mWidth = mWidth;
+        powerStatsProfile.mHeight = mHeight;
+        powerStatsProfile.mPowerMode = mCurrentDisplayConfig.mPowerMode;
+        powerStatsProfile.mBrightnessMode = mCurrentDisplayConfig.mBrightnessMode;
+        powerStatsProfile.mRefreshSource = mRefreshSource;
+        Fraction fps(mTeFrequency, mNumVsync);
+        if (enableMapping) {
+            if ((android::hardware::graphics::composer::kFpsMappingTable.count(fps) > 0)) {
+                powerStatsProfile.mFps = fps.round();
+            } else {
+                powerStatsProfile.mFps = 0;
+            }
+        } else {
+            powerStatsProfile.mFps = fps.round();
+        }
+
+        return powerStatsProfile;
+    }
+
     inline bool isOff() const { return mCurrentDisplayConfig.isOff(); }
 
-    bool operator<(const DisplayPresentProfile& rhs) const {
+    bool operator<(const DisplayRefreshProfile& rhs) const {
         if (isOff() || rhs.isOff()) {
             if (isOff() == rhs.isOff()) {
                 return false;
@@ -91,28 +119,35 @@ typedef struct DisplayPresentProfile {
 
         if (mCurrentDisplayConfig != rhs.mCurrentDisplayConfig) {
             return (mCurrentDisplayConfig < rhs.mCurrentDisplayConfig);
-        } else {
+        } else if (mNumVsync != rhs.mNumVsync) {
             return (mNumVsync < rhs.mNumVsync);
+        } else {
+            return (mRefreshSource < rhs.mRefreshSource);
         }
     }
 
     std::string toString() const {
         std::string res = mCurrentDisplayConfig.toString();
-        res += ", mNumVsync = " + std::to_string(mNumVsync);
+        res += ", mNumVsync = " + std::to_string(mNumVsync) + ", refresh source = " +
+                (isPresentRefresh(mRefreshSource) ? "present" : "nonpresent");
         return res;
     }
 
     DisplayStatus mCurrentDisplayConfig;
+    int mTeFrequency;
+    int mWidth = 0;
+    int mHeight = 0;
     // |mNumVsync| is the timing property of the key for statistics, representing the distribution
-    // of presentations. It represents the interval between a present and the previous present in
+    // of refreshs. It represents the interval between a refresh and the previous refresh in
     // terms of the number of vsyncs.
     int mNumVsync = -1;
-} DisplayPresentProfile;
+    RefreshSource mRefreshSource = kRefreshSourceActivePresent;
+} DisplayRefreshProfile;
 
-// |DisplayPresentRecord| is the value to the statistics.
-typedef struct DisplayPresentRecord {
-    DisplayPresentRecord() = default;
-    DisplayPresentRecord& operator+=(const DisplayPresentRecord& other) {
+// |DisplayRefreshRecord| is the value to the statistics.
+typedef struct DisplayRefreshRecord {
+    DisplayRefreshRecord() = default;
+    DisplayRefreshRecord& operator+=(const DisplayRefreshRecord& other) {
         this->mCount += other.mCount;
         this->mAccumulatedTimeNs += other.mAccumulatedTimeNs;
         this->mLastTimeStampInBootClockNs =
@@ -123,7 +158,7 @@ typedef struct DisplayPresentRecord {
     std::string toString() const {
         std::ostringstream os;
         os << "Count = " << mCount;
-        os << ", AccumulatedTimeNs = " << mAccumulatedTimeNs / 1000000;
+        os << ", AccumulatedTime Ms = " << mAccumulatedTimeNs / 1000000;
         os << ", LastTimeStampInBootClockNs = " << mLastTimeStampInBootClockNs;
         return os.str();
     }
@@ -131,11 +166,11 @@ typedef struct DisplayPresentRecord {
     uint64_t mAccumulatedTimeNs = 0;
     uint64_t mLastTimeStampInBootClockNs = 0;
     bool mUpdated = false;
-} DisplayPresentRecord;
+} DisplayRefreshRecord;
 
-// |DisplayPresentStatistics| is a map consisting of key-value pairs for statistics.
+// |DisplayRefreshStatistics| is a map consisting of key-value pairs for statistics.
 // The key consists of two parts: display configuration and refresh frequency (in terms of vsync).
-typedef std::map<DisplayPresentProfile, DisplayPresentRecord> DisplayPresentStatistics;
+typedef std::map<DisplayRefreshProfile, DisplayRefreshRecord> DisplayRefreshStatistics;
 
 class StatisticsProvider {
 public:
@@ -143,13 +178,13 @@ public:
 
     virtual uint64_t getStartStatisticTimeNs() const = 0;
 
-    virtual DisplayPresentStatistics getStatistics() = 0;
+    virtual DisplayRefreshStatistics getStatistics() = 0;
 
-    virtual DisplayPresentStatistics getUpdatedStatistics() = 0;
+    virtual DisplayRefreshStatistics getUpdatedStatistics() = 0;
 };
 
 class VariableRefreshRateStatistic : public PowerModeListener,
-                                     public PresentListener,
+                                     public RefreshListener,
                                      public StatisticsProvider {
 public:
     VariableRefreshRateStatistic(CommonDisplayContextProvider* displayContextProvider,
@@ -160,14 +195,16 @@ public:
 
     uint64_t getStartStatisticTimeNs() const override;
 
-    DisplayPresentStatistics getStatistics() override;
+    DisplayRefreshStatistics getStatistics() override;
 
-    DisplayPresentStatistics getUpdatedStatistics() override;
+    DisplayRefreshStatistics getUpdatedStatistics() override;
 
     void onPowerStateChange(int from, int to) final;
 
     void onPresent(int64_t presentTimeNs, int flag) override;
 
+    void onNonPresentRefresh(int64_t refreshTimeNs, RefreshSource refreshSource) override;
+
     void setActiveVrrConfiguration(int activeConfigId, int teFrequency);
 
     // If |minimumRefreshRate| is not equal to zero, enforce the minimum (fixed) refresh rate;
@@ -177,12 +214,20 @@ public:
     VariableRefreshRateStatistic(const VariableRefreshRateStatistic& other) = delete;
     VariableRefreshRateStatistic& operator=(const VariableRefreshRateStatistic& other) = delete;
 
+    std::string dumpStatistics(bool getUpdatedOnly, RefreshSource refreshSource,
+                               const std::string& delimiter = ";");
+    void dump(String8& result, const std::vector<std::string>& args = {});
+
 private:
-    static constexpr int64_t kMaxPresentIntervalNs = std::nano::den;
+    static constexpr int64_t kMaxRefreshIntervalNs = std::nano::den;
     static constexpr uint32_t kFrameRateWhenPresentAtLpMode = 30;
 
     bool isPowerModeOffNowLocked() const;
 
+    std::string normalizeString(const std::string& input);
+
+    void onRefreshInternal(int64_t refreshTimeNs, int flag, RefreshSource refreshSource);
+
     void updateCurrentDisplayStatus();
 
     void updateIdleStats(int64_t endTimeStampInBootClockNs = -1);
@@ -191,6 +236,8 @@ private:
     int updateStatistic();
 #endif
 
+    PowerStatsProfileTokenGenerator mPowerStatsProfileTokenGenerator;
+
     CommonDisplayContextProvider* mDisplayContextProvider;
     EventQueue* mEventQueue;
 
@@ -203,15 +250,17 @@ private:
 
     const int64_t mUpdatePeriodNs;
 
-    int64_t mLastPresentTimeInBootClockNs = kDefaultInvalidPresentTimeNs;
+    int64_t mLastDumpsysTime = 0;
+    int64_t mLastRefreshTimeInBootClockNs = kDefaultInvalidPresentTimeNs;
 
-    DisplayPresentStatistics mStatistics;
-    DisplayPresentProfile mDisplayPresentProfile;
+    DisplayRefreshStatistics mStatistics;
+    DisplayRefreshStatistics mStatisticsSnapshot;
+    DisplayRefreshProfile mDisplayRefreshProfile;
 
     uint64_t mPowerOffDurationNs = 0;
 
     uint32_t mMinimumRefreshRate = 1;
-    uint64_t mMaximumFrameIntervalNs = kMaxPresentIntervalNs; // 1 second.
+    uint64_t mMaximumFrameIntervalNs = kMaxRefreshIntervalNs; // 1 second.
 
     uint64_t mStartStatisticTimeNs;
 
diff --git a/libhwc2.1/libvrr/Utils.cpp b/libhwc2.1/libvrr/Utils.cpp
index f77d5d6..1b63086 100644
--- a/libhwc2.1/libvrr/Utils.cpp
+++ b/libhwc2.1/libvrr/Utils.cpp
@@ -48,10 +48,6 @@ int64_t getBootClockTimeNs() {
             .count();
 }
 
-int64_t steadyClockTimeToBootClockTimeNs(int64_t steadyClockTimeNs) {
-    return steadyClockTimeNs + (getBootClockTimeNs() - getSteadyClockTimeNs());
-}
-
 bool hasPresentFrameFlag(int flag, PresentFrameFlag target) {
     return flag & static_cast<int>(target);
 }
@@ -60,6 +56,10 @@ bool isPowerModeOff(int powerMode) {
     return ((powerMode == HWC_POWER_MODE_OFF) || (powerMode == HWC_POWER_MODE_DOZE_SUSPEND));
 }
 
+bool isPresentRefresh(RefreshSource refreshSource) {
+    return (refreshSource & kRefreshSourcePresentMask);
+}
+
 void setTimedEventWithAbsoluteTime(TimedEvent& event) {
     if (event.mIsRelativeTime) {
         event.mWhenNs += getSteadyClockTimeNs();
@@ -67,4 +67,8 @@ void setTimedEventWithAbsoluteTime(TimedEvent& event) {
     }
 }
 
+int64_t steadyClockTimeToBootClockTimeNs(int64_t steadyClockTimeNs) {
+    return steadyClockTimeNs + (getBootClockTimeNs() - getSteadyClockTimeNs());
+}
+
 } // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/Utils.h b/libhwc2.1/libvrr/Utils.h
index 9586bcc..ffbe27c 100644
--- a/libhwc2.1/libvrr/Utils.h
+++ b/libhwc2.1/libvrr/Utils.h
@@ -20,6 +20,7 @@
 #include <cmath>
 #include <cstdint>
 #include "interface/Event.h"
+#include "interface/VariableRefreshRateInterface.h"
 
 inline void clearBit(uint32_t& data, uint32_t bit) {
     data &= ~(1L << (bit));
@@ -98,12 +99,14 @@ int64_t getSteadyClockTimeNs();
 int64_t getBootClockTimeMs();
 int64_t getBootClockTimeNs();
 
-int64_t steadyClockTimeToBootClockTimeNs(int64_t steadyClockTimeNs);
-
 bool hasPresentFrameFlag(int flag, PresentFrameFlag target);
 
 bool isPowerModeOff(int powerMode);
 
+bool isPresentRefresh(RefreshSource refreshSource);
+
 void setTimedEventWithAbsoluteTime(TimedEvent& event);
 
+int64_t steadyClockTimeToBootClockTimeNs(int64_t steadyClockTimeNs);
+
 } // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/VariableRefreshRateController.cpp b/libhwc2.1/libvrr/VariableRefreshRateController.cpp
index ceee484..c233657 100644
--- a/libhwc2.1/libvrr/VariableRefreshRateController.cpp
+++ b/libhwc2.1/libvrr/VariableRefreshRateController.cpp
@@ -107,7 +107,7 @@ auto VariableRefreshRateController::CreateInstance(ExynosDisplay* display,
 
 VariableRefreshRateController::VariableRefreshRateController(ExynosDisplay* display,
                                                              const std::string& panelName)
-      : mDisplay(display), mPanelName(panelName) {
+      : mDisplay(display), mPanelName(panelName), mPendingVendorRenderingTimeoutTasks(this) {
     mState = VrrControllerState::kDisable;
     std::string displayFileNodePath = mDisplay->getPanelSysfsPath();
     if (displayFileNodePath.empty()) {
@@ -168,9 +168,7 @@ VariableRefreshRateController::VariableRefreshRateController(ExynosDisplay* disp
 
     mPowerModeListeners.push_back(mRefreshRateCalculator.get());
 
-    std::string fullPath = displayFileNodePath + kFrameRateNodeName;
-    int fd = open(fullPath.c_str(), O_WRONLY, 0);
-    if (fd >= 0) {
+    if (mFileNode->getFileHandler(kFrameRateNodeName) >= 0) {
         mFrameRateReporter =
                 refreshRateCalculatorFactory
                         .BuildRefreshRateCalculator(&mEventQueue,
@@ -225,6 +223,24 @@ int VariableRefreshRateController::notifyExpectedPresent(int64_t timestamp,
         // Post kNotifyExpectedPresentConfig event.
         postEvent(VrrControllerEventType::kNotifyExpectedPresentConfig, getSteadyClockTimeNs());
     }
+
+    if (mFileNode == nullptr) {
+        LOG(WARNING) << "VrrController: Cannot find file node of display: "
+                     << mDisplay->mDisplayName;
+    } else {
+        if (!mFileNode->writeValue("expected_present_time_ns", timestamp)) {
+            std::string displayFileNodePath = mDisplay->getPanelSysfsPath();
+            ALOGE("%s(): write command to file node %s%s failed.", __func__,
+                  displayFileNodePath.c_str(), "expect_present_time");
+        }
+
+        if (!mFileNode->writeValue("frame_interval_ns", frameIntervalNs)) {
+            std::string displayFileNodePath = mDisplay->getPanelSysfsPath();
+            ALOGE("%s(): write command to file node %s%s failed.", __func__,
+                  displayFileNodePath.c_str(), "frame_interval");
+        }
+    }
+
     mCondition.notify_all();
     return 0;
 }
@@ -254,12 +270,12 @@ void VariableRefreshRateController::setActiveVrrConfiguration(hwc2_config_t conf
             LOG(ERROR) << "VrrController: Set an undefined active configuration";
             return;
         }
-        const auto oldMaxFrameRate =
-                durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
-        mVrrActiveConfig = config;
         if (mFrameRateReporter) {
             mFrameRateReporter->onPresent(getSteadyClockTimeNs(), 0);
         }
+        const auto oldMaxFrameRate =
+                durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
+        mVrrActiveConfig = config;
         // If the minimum refresh rate is active and the maximum refresh rate timeout is set,
         // also we are stay at the maximum refresh rate, any change in the active configuration
         // needs to reconfigure the maximum refresh rate according to the newly activated
@@ -270,7 +286,7 @@ void VariableRefreshRateController::setActiveVrrConfiguration(hwc2_config_t conf
                 auto newMaxFrameRate = durationNsToFreq(mVrrConfigs[config].minFrameIntervalNs);
                 setBitField(command, newMaxFrameRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
                             kPanelRefreshCtrlMinimumRefreshRateMask);
-                if (!mFileNode->WriteUint32(composer::kRefreshControlNodeName, command)) {
+                if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
                     LOG(WARNING) << "VrrController: write file node error, command = " << command;
                 }
                 onRefreshRateChangedInternal(newMaxFrameRate);
@@ -343,14 +359,18 @@ void VariableRefreshRateController::preSetPowerMode(int32_t powerMode) {
             case HWC_POWER_MODE_DOZE_SUSPEND: {
                 uint32_t command = getCurrentRefreshControlStateLocked();
                 setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
-                if (!mFileNode->WriteUint32(kRefreshControlNodeName, command)) {
+                mPresentTimeoutController = PresentTimeoutControllerType::kHardware;
+                if (!mFileNode->writeValue(kRefreshControlNodeName, command)) {
                     LOG(ERROR) << "VrrController: write file node error, command = " << command;
                 }
-                dropEventLocked(VrrControllerEventType::kVendorRenderingTimeout);
+                cancelPresentTimeoutHandlingLocked();
+                return;
+            }
+            case HWC_POWER_MODE_OFF: {
                 return;
             }
-            case HWC_POWER_MODE_OFF:
             case HWC_POWER_MODE_NORMAL: {
+                mPresentTimeoutController = mDefaultPresentTimeoutController;
                 return;
             }
             default: {
@@ -484,20 +504,37 @@ void VariableRefreshRateController::setPresentTimeoutParameters(
 void VariableRefreshRateController::setPresentTimeoutController(uint32_t controllerType) {
     const std::lock_guard<std::mutex> lock(mMutex);
 
-    PresentTimeoutControllerType newControllerType =
+    if (mPowerMode != HWC_POWER_MODE_NORMAL) {
+        LOG(WARNING) << "VrrController: Please change the present timeout controller only when the "
+                        "power mode is on.";
+        return;
+    }
+
+    PresentTimeoutControllerType newDefaultControllerType =
             static_cast<PresentTimeoutControllerType>(controllerType);
-    if (newControllerType != mPresentTimeoutController) {
-        if (mPresentTimeoutController == PresentTimeoutControllerType::kSoftware) {
-            dropEventLocked(VrrControllerEventType::kVendorRenderingTimeout);
+    if (newDefaultControllerType != mDefaultPresentTimeoutController) {
+        mDefaultPresentTimeoutController = newDefaultControllerType;
+        PresentTimeoutControllerType oldControllerType = mPresentTimeoutController;
+        if (mDefaultPresentTimeoutController == PresentTimeoutControllerType::kHardware) {
+            mPresentTimeoutController = PresentTimeoutControllerType::kHardware;
+        } else {
+            // When change |mDefaultPresentTimeoutController| from |kHardware| to |kSoftware|,
+            // only change |mPresentTimeoutController| if the minimum refresh rate has not been set.
+            // Otherwise, retain the current |mPresentTimeoutController| until the conditions are
+            // met.
+            if (!(isMinimumRefreshRateActive())) {
+                mPresentTimeoutController = PresentTimeoutControllerType::kSoftware;
+            }
         }
-        mPresentTimeoutController = newControllerType;
+        if (oldControllerType == mPresentTimeoutController) return;
         uint32_t command = getCurrentRefreshControlStateLocked();
-        if (newControllerType == PresentTimeoutControllerType::kHardware) {
+        if (mPresentTimeoutController == PresentTimeoutControllerType::kHardware) {
+            cancelPresentTimeoutHandlingLocked();
             setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
         } else {
             clearBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
         }
-        if (!mFileNode->WriteUint32(composer::kRefreshControlNodeName, command)) {
+        if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
             LOG(ERROR) << "VrrController: write file node error, command = " << command;
         }
     }
@@ -523,7 +560,7 @@ int VariableRefreshRateController::setFixedRefreshRateRange(
     mMaximumRefreshRateTimeoutNs = minLockTimeForPeakRefreshRate;
     dropEventLocked(VrrControllerEventType::kMinLockTimeForPeakRefreshRate);
     if (isMinimumRefreshRateActive()) {
-        dropEventLocked(VrrControllerEventType::kVendorRenderingTimeout);
+        cancelPresentTimeoutHandlingLocked();
         // Delegate timeout management to hardware.
         setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
         // Configure panel to maintain the minimum refresh rate.
@@ -563,29 +600,39 @@ int VariableRefreshRateController::setFixedRefreshRateRange(
                     if (mVariableRefreshRateStatistic) {
                         mVariableRefreshRateStatistic->setFixedRefreshRate(mMinimumRefreshRate);
                     }
+                    if (mPresentTimeoutController != PresentTimeoutControllerType::kHardware) {
+                        LOG(WARNING)
+                                << "VrrController: incorrect type of present timeout controller.";
+                    }
                     uint32_t command = getCurrentRefreshControlStateLocked();
                     setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
                     setBitField(command, mMinimumRefreshRate,
                                 kPanelRefreshCtrlMinimumRefreshRateOffset,
                                 kPanelRefreshCtrlMinimumRefreshRateMask);
                     onRefreshRateChangedInternal(mMinimumRefreshRate);
-                    return mFileNode->WriteUint32(composer::kRefreshControlNodeName, command);
+                    return mFileNode->writeValue(composer::kRefreshControlNodeName, command);
                 }
             };
         }
-        if (!mFileNode->WriteUint32(composer::kRefreshControlNodeName, command)) {
+        if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
             return -1;
         }
+        mPresentTimeoutController = PresentTimeoutControllerType::kHardware;
         // Report refresh rate change.
         onRefreshRateChangedInternal(mMinimumRefreshRate);
     } else {
-        clearBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
-        // Configure panel with the minimum refresh rate = 1.
-        setBitField(command, 1, kPanelRefreshCtrlMinimumRefreshRateOffset,
-                    kPanelRefreshCtrlMinimumRefreshRateMask);
-        // Inform Statistics about the minimum refresh rate change.
-        if (!mFileNode->WriteUint32(composer::kRefreshControlNodeName, command)) {
-            return -1;
+        // If the minimum refresh rate is 1, check |mDefaultPresentTimeoutController|.
+        // Only disable auto mode if |mDefaultPresentTimeoutController| is |kSoftware|.
+        mPresentTimeoutController = mDefaultPresentTimeoutController;
+        if (mPresentTimeoutController == PresentTimeoutControllerType::kSoftware) {
+            clearBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
+            // Configure panel with the minimum refresh rate = 1.
+            setBitField(command, 1, kPanelRefreshCtrlMinimumRefreshRateOffset,
+                        kPanelRefreshCtrlMinimumRefreshRateMask);
+            // Inform Statistics about the minimum refresh rate change.
+            if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
+                return -1;
+            }
         }
         // TODO(b/333204544): ensure the correct refresh rate is set when calling
         // setFixedRefreshRate().
@@ -654,13 +701,17 @@ void VariableRefreshRateController::onPresent(int fence) {
             // 120, no refresh rate promotion is needed.
             if (maxFrameRate != mMinimumRefreshRate) {
                 if (mMinimumRefreshRatePresentStates == kAtMinimumRefreshRate) {
+                    if (mPresentTimeoutController != PresentTimeoutControllerType::kHardware) {
+                        LOG(WARNING)
+                                << "VrrController: incorrect type of present timeout controller.";
+                    }
                     uint32_t command = getCurrentRefreshControlStateLocked();
                     // Delegate timeout management to hardware.
                     setBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
                     // Configure panel to maintain the minimum refresh rate.
                     setBitField(command, maxFrameRate, kPanelRefreshCtrlMinimumRefreshRateOffset,
                                 kPanelRefreshCtrlMinimumRefreshRateMask);
-                    if (!mFileNode->WriteUint32(composer::kRefreshControlNodeName, command)) {
+                    if (!mFileNode->writeValue(composer::kRefreshControlNodeName, command)) {
                         LOG(WARNING)
                                 << "VrrController: write file node error, command = " << command;
                         return;
@@ -709,9 +760,6 @@ void VariableRefreshRateController::onPresent(int fence) {
             LOG(WARNING) << "VrrController: last present fence remains open.";
         }
         mLastPresentFence = dupFence;
-        // Drop the out of date timeout.
-        dropEventLocked(VrrControllerEventType::kSystemRenderingTimeout);
-        cancelPresentTimeoutHandlingLocked();
         // Post next rendering timeout.
         int64_t timeoutNs;
         if (mVrrConfigs[mVrrActiveConfig].isFullySupported) {
@@ -723,15 +771,22 @@ void VariableRefreshRateController::onPresent(int fence) {
         postEvent(VrrControllerEventType::kSystemRenderingTimeout,
                   getSteadyClockTimeNs() + timeoutNs);
         if (shouldHandleVendorRenderingTimeout()) {
-            auto presentTimeoutNs = mVendorPresentTimeoutOverride
-                    ? mVendorPresentTimeoutOverride.value().mTimeoutNs
-                    : mPresentTimeoutEventHandler->getPresentTimeoutNs();
-            // If |presentTimeoutNs| == 0, we don't need to handle the present timeout. Otherwise,
-            // post the next frame insertion event
-            if (presentTimeoutNs) {
-                // Convert the relative time clock from now to the absolute steady time clock.
-                presentTimeoutNs = getSteadyClockTimeNs() + presentTimeoutNs;
-                postEvent(VrrControllerEventType::kVendorRenderingTimeout, presentTimeoutNs);
+            // Post next frame insertion event.
+            int64_t firstTimeOutNs;
+            if (mVendorPresentTimeoutOverride) {
+                firstTimeOutNs = mVendorPresentTimeoutOverride.value().mTimeoutNs;
+            } else {
+                firstTimeOutNs = mPresentTimeoutEventHandler->getPresentTimeoutNs();
+            }
+            mPendingVendorRenderingTimeoutTasks.baseTimeNs += firstTimeOutNs;
+            firstTimeOutNs -= kDefaultAheadOfTimeNs;
+            if (firstTimeOutNs >= 0) {
+                auto vendorPresentTimeoutNs =
+                        mRecord.mPendingCurrentPresentTime.value().mTime + firstTimeOutNs;
+                postEvent(VrrControllerEventType::kVendorRenderingTimeoutInit,
+                          vendorPresentTimeoutNs);
+            } else {
+                LOG(ERROR) << "VrrController: the first vendor present timeout is negative";
             }
         }
         mRecord.mPendingCurrentPresentTime = std::nullopt;
@@ -744,6 +799,10 @@ void VariableRefreshRateController::setExpectedPresentTime(int64_t timestampNano
     ATRACE_CALL();
 
     const std::lock_guard<std::mutex> lock(mMutex);
+    // Drop the out of date timeout.
+    dropEventLocked(VrrControllerEventType::kSystemRenderingTimeout);
+    cancelPresentTimeoutHandlingLocked();
+    mPendingVendorRenderingTimeoutTasks.baseTimeNs = timestampNanos;
     mRecord.mPendingCurrentPresentTime = {mVrrActiveConfig, timestampNanos, frameIntervalNs};
 }
 
@@ -756,8 +815,9 @@ void VariableRefreshRateController::onVsync(int64_t timestampNanos,
 }
 
 void VariableRefreshRateController::cancelPresentTimeoutHandlingLocked() {
-    dropEventLocked(VrrControllerEventType::kVendorRenderingTimeout);
-    dropEventLocked(VrrControllerEventType::kHandleVendorRenderingTimeout);
+    dropEventLocked(VrrControllerEventType::kVendorRenderingTimeoutInit);
+    dropEventLocked(VrrControllerEventType::kVendorRenderingTimeoutPost);
+    mPendingVendorRenderingTimeoutTasks.reset();
 }
 
 void VariableRefreshRateController::dropEventLocked() {
@@ -796,9 +856,16 @@ std::string VariableRefreshRateController::dumpEventQueueLocked() {
     return content;
 }
 
+void VariableRefreshRateController::dump(String8& result, const std::vector<std::string>& args) {
+    result.appendFormat("\nVariableRefreshRateStatistic: \n");
+    mVariableRefreshRateStatistic->dump(result, args);
+}
+
 uint32_t VariableRefreshRateController::getCurrentRefreshControlStateLocked() const {
-    return (mFileNode->getLastWrittenValue(kRefreshControlNodeName) &
-            kPanelRefreshCtrlStateBitsMask);
+    uint32_t state = 0;
+    return (mFileNode->getLastWrittenValue(kRefreshControlNodeName, state) == NO_ERROR)
+            ? (state & kPanelRefreshCtrlStateBitsMask)
+            : 0;
 }
 
 int64_t VariableRefreshRateController::getLastFenceSignalTimeUnlocked(int fd) {
@@ -894,21 +961,41 @@ void VariableRefreshRateController::handleStayHibernate() {
               getSteadyClockTimeNs() + kDefaultWakeUpTimeInPowerSaving);
 }
 
-void VariableRefreshRateController::handlePresentTimeout(const VrrControllerEvent& event) {
+void VariableRefreshRateController::handlePresentTimeout() {
     ATRACE_CALL();
 
     if (mState == VrrControllerState::kDisable) {
         cancelPresentTimeoutHandlingLocked();
         return;
     }
-    uint32_t command = mFileNode->getLastWrittenValue(composer::kRefreshControlNodeName);
-    clearBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
-    setBitField(command, 1, kPanelRefreshCtrlFrameInsertionFrameCountOffset,
-                kPanelRefreshCtrlFrameInsertionFrameCountMask);
-    mFileNode->WriteUint32(composer::kRefreshControlNodeName, command);
+
+    // During doze, the present timeout controller switches to |kHardware|.
+    // This remains until |handlePresentTimeout| is first called here where the controller type is
+    // reset back to |mDefaultPresentTimeoutController|(|kSoftware|).
+    if (mDefaultPresentTimeoutController != PresentTimeoutControllerType::kSoftware) {
+        LOG(WARNING) << "VrrController: incorrect type of default present timeout controller.";
+    }
+    uint32_t command = 0;
+    if (mFileNode->getLastWrittenValue(composer::kRefreshControlNodeName, command) == NO_ERROR) {
+        clearBit(command, kPanelRefreshCtrlFrameInsertionAutoModeOffset);
+        setBitField(command, 1, kPanelRefreshCtrlFrameInsertionFrameCountOffset,
+                    kPanelRefreshCtrlFrameInsertionFrameCountMask);
+        mFileNode->writeValue(composer::kRefreshControlNodeName, command);
+        if (mPresentTimeoutController != PresentTimeoutControllerType::kSoftware) {
+            mPresentTimeoutController = PresentTimeoutControllerType::kSoftware;
+        }
+    } else {
+        LOG(ERROR) << "VrrController: no last wrttien value for kRefreshControlNodeName";
+    }
     if (mFrameRateReporter) {
         mFrameRateReporter->onPresent(getSteadyClockTimeNs(), 0);
     }
+    if (mVariableRefreshRateStatistic) {
+        mVariableRefreshRateStatistic
+                ->onNonPresentRefresh(getSteadyClockTimeNs(),
+                                      RefreshSource::kRefreshSourceFrameInsertion);
+    }
+    mPendingVendorRenderingTimeoutTasks.scheduleNextTask();
 }
 
 void VariableRefreshRateController::onFrameRateChangedForDBI(int refreshRate) {
@@ -917,8 +1004,8 @@ void VariableRefreshRateController::onFrameRateChangedForDBI(int refreshRate) {
     // this case.
     auto maxFrameRate = durationNsToFreq(mVrrConfigs[mVrrActiveConfig].minFrameIntervalNs);
     refreshRate = std::max(1, refreshRate);
-    refreshRate = std::min(maxFrameRate, refreshRate);
-    mFileNode->WriteUint32(kFrameRateNodeName, refreshRate);
+    mFrameRate = std::min(maxFrameRate, refreshRate);
+    postEvent(VrrControllerEventType::kUpdateDbiFrameRate, getSteadyClockTimeNs());
 }
 
 void VariableRefreshRateController::onRefreshRateChanged(int refreshRate) {
@@ -988,6 +1075,10 @@ int VariableRefreshRateController::convertToValidRefreshRate(int refreshRate) {
 }
 
 bool VariableRefreshRateController::shouldHandleVendorRenderingTimeout() const {
+    // We skip the check |mPresentTimeoutController| == |kSoftware| here because, even if it's set
+    // to |kHardware| when resuming from doze, we still allow vendor rendering timeouts. Once this
+    // timeout occurs, |mPresentTimeoutController| will be reset to
+    // |mDefaultPresentTimeoutController| (which should be |kSoftware|).
     return (mPresentTimeoutController == PresentTimeoutControllerType::kSoftware) &&
             ((!mVendorPresentTimeoutOverride) ||
              (mVendorPresentTimeoutOverride.value().mSchedule.size() > 0)) &&
@@ -995,13 +1086,14 @@ bool VariableRefreshRateController::shouldHandleVendorRenderingTimeout() const {
 }
 
 void VariableRefreshRateController::threadBody() {
-    struct sched_param param = {.sched_priority = sched_get_priority_max(SCHED_FIFO)};
+    struct sched_param param = {.sched_priority = sched_get_priority_min(SCHED_FIFO)};
     if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
         LOG(ERROR) << "VrrController: fail to set scheduler to SCHED_FIFO.";
         return;
     }
     for (;;) {
         bool stateChanged = false;
+        uint32_t frameRate = 0;
         {
             std::unique_lock<std::mutex> lock(mMutex);
             if (mThreadExit) break;
@@ -1035,6 +1127,9 @@ void VariableRefreshRateController::threadBody() {
                 handleCallbackEventLocked(event);
                 continue;
             }
+            if (event.mEventType == VrrControllerEventType::kUpdateDbiFrameRate) {
+                frameRate = mFrameRate;
+            }
             if (mState == VrrControllerState::kRendering) {
                 if (event.mEventType == VrrControllerEventType::kHibernateTimeout) {
                     LOG(ERROR) << "VrrController: receiving a hibernate timeout event while in the "
@@ -1051,41 +1146,52 @@ void VariableRefreshRateController::threadBody() {
                         handleCadenceChange();
                         break;
                     }
-                    case VrrControllerEventType::kVendorRenderingTimeout: {
+                    case VrrControllerEventType::kVendorRenderingTimeoutInit: {
                         if (mPresentTimeoutEventHandler) {
+                            size_t numberOfIntervals = 0;
                             // Verify whether a present timeout override exists, and if so, execute
                             // it first.
                             if (mVendorPresentTimeoutOverride) {
                                 const auto& params = mVendorPresentTimeoutOverride.value();
-                                TimedEvent timedEvent("VendorPresentTimeoutOverride");
-                                timedEvent.mIsRelativeTime = true;
-                                timedEvent.mFunctor = params.mFunctor;
                                 int64_t whenFromNowNs = 0;
                                 for (int i = 0; i < params.mSchedule.size(); ++i) {
-                                    uint32_t intervalNs = params.mSchedule[i].second;
-                                    for (int j = 0; j < params.mSchedule[i].first; ++j) {
-                                        timedEvent.mWhenNs = whenFromNowNs;
-                                        postEvent(VrrControllerEventType::
-                                                          kHandleVendorRenderingTimeout,
-                                                  timedEvent);
-                                        whenFromNowNs += intervalNs;
+                                    numberOfIntervals += params.mSchedule[i].first;
+                                }
+                                if (numberOfIntervals > 0) {
+                                    mPendingVendorRenderingTimeoutTasks.reserveSpace(
+                                            numberOfIntervals);
+                                    for (int i = 0; i < params.mSchedule.size(); ++i) {
+                                        uint32_t intervalNs = params.mSchedule[i].second;
+                                        for (int j = 0; j < params.mSchedule[i].first; ++j) {
+                                            mPendingVendorRenderingTimeoutTasks.addTask(
+                                                    whenFromNowNs);
+                                            whenFromNowNs += intervalNs;
+                                        }
                                     }
                                 }
                             } else {
                                 auto handleEvents = mPresentTimeoutEventHandler->getHandleEvents();
                                 if (!handleEvents.empty()) {
-                                    for (auto& event : handleEvents) {
-                                        postEvent(VrrControllerEventType::
-                                                          kHandleVendorRenderingTimeout,
-                                                  event);
+                                    numberOfIntervals = handleEvents.size();
+                                    mPendingVendorRenderingTimeoutTasks.reserveSpace(
+                                            numberOfIntervals);
+                                    for (int i = 0; i < handleEvents.size(); ++i) {
+                                        mPendingVendorRenderingTimeoutTasks.addTask(
+                                                handleEvents[i].mWhenNs);
                                     }
                                 }
                             }
+                            if (numberOfIntervals > 0) {
+                                // Start from 1 since we will execute the first task immediately
+                                // below.
+                                mPendingVendorRenderingTimeoutTasks.nextTaskIndex = 1;
+                                handlePresentTimeout();
+                            }
                         }
                         break;
                     }
-                    case VrrControllerEventType::kHandleVendorRenderingTimeout: {
-                        handlePresentTimeout(event);
+                    case VrrControllerEventType::kVendorRenderingTimeoutPost: {
+                        handlePresentTimeout();
                         if (event.mFunctor) {
                             event.mFunctor();
                         }
@@ -1127,6 +1233,14 @@ void VariableRefreshRateController::threadBody() {
         if (stateChanged) {
             updateVsyncHistory();
         }
+        // Write pending values without holding mutex shared with HWC main thread.
+        if (frameRate) {
+            if (!mFileNode->writeValue(kFrameRateNodeName, frameRate)) {
+                LOG(ERROR) << "VrrController: write to node = " << kFrameRateNodeName
+                           << " failed, value = " << frameRate;
+            }
+            ATRACE_INT("frameRate", frameRate);
+        }
     }
 }
 
diff --git a/libhwc2.1/libvrr/VariableRefreshRateController.h b/libhwc2.1/libvrr/VariableRefreshRateController.h
index e46485f..6563da4 100644
--- a/libhwc2.1/libvrr/VariableRefreshRateController.h
+++ b/libhwc2.1/libvrr/VariableRefreshRateController.h
@@ -41,7 +41,7 @@
 namespace android::hardware::graphics::composer {
 
 class VariableRefreshRateController : public VsyncListener,
-                                      public PresentListener,
+                                      public RefreshListener,
                                       public DisplayContextProvider,
                                       public DisplayConfigurationsOwner {
 public:
@@ -130,6 +130,8 @@ public:
     int setFixedRefreshRateRange(uint32_t minimumRefreshRate,
                                  uint64_t minLockTimeForPeakRefreshRate);
 
+    void dump(String8& result, const std::vector<std::string>& args = {});
+
 private:
     static constexpr int kMaxFrameRate = 120;
     static constexpr int kMaxTefrequency = 240;
@@ -148,12 +150,50 @@ private:
 
     static constexpr std::string_view kVendorDisplayPanelLibrary = "libdisplaypanel.so";
 
+    static constexpr int64_t kDefaultAheadOfTimeNs = 1000000; // 1 ms;
+
     enum class VrrControllerState {
         kDisable = 0,
         kRendering,
         kHibernate,
     };
 
+    typedef struct PendingVendorRenderingTimeoutTasks {
+        PendingVendorRenderingTimeoutTasks(VariableRefreshRateController* controller)
+              : host(controller), taskExecutionTimeNs(kDefaultMaximumNumberOfTasks, 0) {}
+
+        void addTask(int64_t executionIntervalNs) {
+            taskExecutionTimeNs[numberOfTasks++] = baseTimeNs + executionIntervalNs;
+        }
+
+        void scheduleNextTask() {
+            if (!isDone()) {
+                host->postEvent(VrrControllerEventType::kVendorRenderingTimeoutPost,
+                                std::max(getSteadyClockTimeNs(),
+                                         taskExecutionTimeNs[nextTaskIndex++] -
+                                                 kDefaultAheadOfTimeNs));
+            }
+        }
+
+        bool isDone() const { return (numberOfTasks == nextTaskIndex); }
+
+        void reserveSpace(size_t size) {
+            if (size > taskExecutionTimeNs.size()) {
+                taskExecutionTimeNs.resize(size);
+            }
+        }
+
+        void reset() { numberOfTasks = nextTaskIndex = 0; }
+
+        static constexpr size_t kDefaultMaximumNumberOfTasks = 10;
+
+        VariableRefreshRateController* host;
+        int64_t baseTimeNs = 0;
+        int numberOfTasks = 0;
+        int nextTaskIndex = 0;
+        std::vector<int64_t> taskExecutionTimeNs;
+    } PendingVendorRenderingTimeoutTasks;
+
     typedef struct PresentEvent {
         hwc2_config_t config;
         int64_t mTime;
@@ -226,7 +266,7 @@ private:
 
     VariableRefreshRateController(ExynosDisplay* display, const std::string& panelName);
 
-    // Implement interface PresentListener.
+    // Implement interface RefreshListener.
     virtual void onPresent(int32_t fence) override;
     virtual void setExpectedPresentTime(int64_t timestampNanos, int frameIntervalNs) override;
 
@@ -279,7 +319,7 @@ private:
         }
     }
 
-    void handlePresentTimeout(const VrrControllerEvent& event);
+    void handlePresentTimeout();
 
     inline bool isMinimumRefreshRateActive() const { return (mMinimumRefreshRate > 1); }
 
@@ -317,6 +357,7 @@ private:
     hwc2_config_t mVrrActiveConfig = -1;
     std::unordered_map<hwc2_config_t, VrrConfig_t> mVrrConfigs;
     std::optional<int> mLastPresentFence;
+    uint32_t mFrameRate = 0;
 
     std::shared_ptr<FileNode> mFileNode;
 
@@ -345,6 +386,8 @@ private:
     bool mEnabled = false;
     bool mThreadExit = false;
 
+    PresentTimeoutControllerType mDefaultPresentTimeoutController =
+            PresentTimeoutControllerType::kSoftware;
     PresentTimeoutControllerType mPresentTimeoutController =
             PresentTimeoutControllerType::kSoftware;
 
@@ -361,6 +404,8 @@ private:
 
     std::vector<std::shared_ptr<RefreshRateChangeListener>> mRefreshRateChangeListeners;
 
+    PendingVendorRenderingTimeoutTasks mPendingVendorRenderingTimeoutTasks;
+
     std::mutex mMutex;
     std::condition_variable mCondition;
 };
diff --git a/libhwc2.1/libvrr/display/common/Constants.h b/libhwc2.1/libvrr/display/common/Constants.h
new file mode 100644
index 0000000..0a71df7
--- /dev/null
+++ b/libhwc2.1/libvrr/display/common/Constants.h
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <set>
+
+namespace android::hardware::graphics::composer {
+
+inline const std::set<Fraction<int>> kFpsMappingTable = {{240, 240}, {240, 120}, {240, 24},
+                                                         {240, 10},  {240, 8},   {240, 7},
+                                                         {240, 6},   {240, 5},   {240, 4},
+                                                         {240, 3},   {240, 2}};
+
+inline const std::vector<int> kFpsLowPowerModeMappingTable = {1, 30};
+
+const std::vector<int> kActivePowerModes = {HWC2_POWER_MODE_DOZE, HWC2_POWER_MODE_ON};
+
+const std::vector<RefreshSource> kRefreshSource = {kRefreshSourceActivePresent,
+                                                   kRefreshSourceIdlePresent,
+                                                   kRefreshSourceFrameInsertion,
+                                                   kRefreshSourceBrightness};
+} // namespace android::hardware::graphics::composer
diff --git a/libhwc2.1/libvrr/interface/Event.h b/libhwc2.1/libvrr/interface/Event.h
index 461c589..2211dee 100644
--- a/libhwc2.1/libvrr/interface/Event.h
+++ b/libhwc2.1/libvrr/interface/Event.h
@@ -26,31 +26,33 @@
 namespace android::hardware::graphics::composer {
 
 enum class VrrControllerEventType {
-    kGeneralEventMask = 0x100,
+    kGeneralEventMask = 0x10000000,
     // kSystemRenderingTimeout is responsible for managing present timeout according to the
     // configuration specified in the system HAL API.
-    kSystemRenderingTimeout,
-    // kVendorRenderingTimeout is responsible for managing present timeout based on the vendor's
-    // proprietary definition.
-    kVendorRenderingTimeout,
-    // kHandleVendorRenderingTimeout is responsible for addressing present timeout by invoking
-    // the handling function provided by the vendor.
-    kHandleVendorRenderingTimeout,
-    kHibernateTimeout,
-    kNotifyExpectedPresentConfig,
-    kGeneralEventMax = 0x1FF,
+    kSystemRenderingTimeout = kGeneralEventMask + (1 << 0),
+    // kVendorRenderingTimeoutInit is responsible for initializing vendor's timeout
+    // configurations and kicking off subsequent handling
+    kVendorRenderingTimeoutInit = kGeneralEventMask + (1 << 1),
+    // kVendorRenderingTimeoutPost is responsible for handling the timeout event
+    // per config after initialization
+    kVendorRenderingTimeoutPost = kGeneralEventMask + (1 << 2),
+    kHibernateTimeout = kGeneralEventMask + (1 << 3),
+    kNotifyExpectedPresentConfig = kGeneralEventMask + (1 << 4),
+    kTestEvent = kGeneralEventMask + (1 << 5),
+    kUpdateDbiFrameRate = kGeneralEventMask + (1 << 6),
+    kGeneralEventMax = kGeneralEventMask + (1 << 27),
     // General callback events.
-    kCallbackEventMask = 0x200,
-    kRefreshRateCalculatorUpdateMask = 0x200,
-    kInstantRefreshRateCalculatorUpdate,
-    kPeriodRefreshRateCalculatorUpdate,
-    kVideoFrameRateCalculatorUpdate,
-    kCombinedRefreshRateCalculatorUpdate,
-    kAodRefreshRateCalculatorUpdate,
-    kExitIdleRefreshRateCalculatorUpdate,
-    kStaticticUpdate,
-    kMinLockTimeForPeakRefreshRate,
-    kCallbackEventMax = 0x2FF,
+    kCallbackEventMask = 0x20000000,
+    kRefreshRateCalculatorUpdateMask = kCallbackEventMask,
+    kInstantRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 0),
+    kPeriodRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 1),
+    kVideoFrameRateCalculatorUpdate = kCallbackEventMask + (1 << 2),
+    kCombinedRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 3),
+    kAodRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 4),
+    kExitIdleRefreshRateCalculatorUpdate = kCallbackEventMask + (1 << 5),
+    kStaticticUpdate = kCallbackEventMask + (1 << 6),
+    kMinLockTimeForPeakRefreshRate = kCallbackEventMask + (1 << 7),
+    kCallbackEventMax = kCallbackEventMask + (1 << 27),
     // Sensors, outer events...
 };
 
@@ -75,10 +77,12 @@ struct VrrControllerEvent {
         switch (mEventType) {
             case VrrControllerEventType::kSystemRenderingTimeout:
                 return "kSystemRenderingTimeout";
-            case VrrControllerEventType::kVendorRenderingTimeout:
-                return "kVendorRenderingTimeout";
-            case VrrControllerEventType::kHandleVendorRenderingTimeout:
-                return "kHandleVendorRenderingTimeout";
+            case VrrControllerEventType::kExitIdleRefreshRateCalculatorUpdate:
+                return "kExitIdleRefreshRateCalculatorUpdate";
+            case VrrControllerEventType::kVendorRenderingTimeoutInit:
+                return "kVendorRenderingTimeoutInit";
+            case VrrControllerEventType::kVendorRenderingTimeoutPost:
+                return "kVendorRenderingTimeoutPost";
             case VrrControllerEventType::kHibernateTimeout:
                 return "kHibernateTimeout";
             case VrrControllerEventType::kNotifyExpectedPresentConfig:
diff --git a/libhwc2.1/libvrr/interface/VariableRefreshRateInterface.h b/libhwc2.1/libvrr/interface/VariableRefreshRateInterface.h
index d7721ac..d4d8499 100644
--- a/libhwc2.1/libvrr/interface/VariableRefreshRateInterface.h
+++ b/libhwc2.1/libvrr/interface/VariableRefreshRateInterface.h
@@ -18,16 +18,34 @@
 
 namespace android::hardware::graphics::composer {
 
-class PresentListener {
+enum RefreshSource {
+    // Refresh triggered by presentation.
+    kRefreshSourceActivePresent = (1 << 0),
+    kRefreshSourceIdlePresent = (1 << 1),
+    // Refresh NOT triggered by presentation.
+    kRefreshSourceFrameInsertion = (1 << 2),
+    kRefreshSourceBrightness = (1 << 3),
+};
+
+static constexpr int kRefreshSourcePresentMask =
+        kRefreshSourceActivePresent | kRefreshSourceIdlePresent;
+
+static constexpr int kRefreshSourceNonPresentMask =
+        kRefreshSourceFrameInsertion | kRefreshSourceBrightness;
+
+class RefreshListener {
 public:
-    virtual ~PresentListener() = default;
+    virtual ~RefreshListener() = default;
 
     virtual void setExpectedPresentTime(int64_t __unused timestampNanos,
                                         int __unused frameIntervalNs) {}
 
     virtual void onPresent(int32_t __unused fence) {}
 
-    virtual void onPresent(int64_t __unused presentTimeNs, __unused int flag) {}
+    virtual void onPresent(int64_t __unused presentTimeNs, int __unused flag) {}
+
+    virtual void onNonPresentRefresh(int64_t __unused refreshTimeNs,
+                                     RefreshSource __unused source) {}
 };
 
 class VsyncListener {
diff --git a/libhwc2.1/pixel-display-default.xml b/libhwc2.1/pixel-display-default.xml
index 5d3de9d..c96c8d9 100644
--- a/libhwc2.1/pixel-display-default.xml
+++ b/libhwc2.1/pixel-display-default.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>com.google.hardware.pixel.display</name>
-        <version>12</version>
+        <version>13</version>
         <fqname>IDisplay/default</fqname>
     </hal>
 </manifest>
diff --git a/libhwc2.1/pixel-display-secondary.xml b/libhwc2.1/pixel-display-secondary.xml
index 1979248..5c9aae7 100644
--- a/libhwc2.1/pixel-display-secondary.xml
+++ b/libhwc2.1/pixel-display-secondary.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>com.google.hardware.pixel.display</name>
-        <version>12</version>
+        <version>13</version>
         <fqname>IDisplay/secondary</fqname>
     </hal>
 </manifest>
diff --git a/libhwc2.1/pixel-display.cpp b/libhwc2.1/pixel-display.cpp
index d70291e..d1b0123 100644
--- a/libhwc2.1/pixel-display.cpp
+++ b/libhwc2.1/pixel-display.cpp
@@ -437,6 +437,23 @@ ndk::ScopedAStatus Display::queryStats(DisplayStats::Tag tag,
     return ndk::ScopedAStatus::ok();
 }
 
+ndk::ScopedAStatus Display::isProximitySensorStateCallbackSupported(bool* _aidl_return) {
+    if (mDisplay) {
+        *_aidl_return = mDisplay->isProximitySensorStateCallbackSupported();
+        return ndk::ScopedAStatus::ok();
+    }
+    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
+}
+
+ndk::ScopedAStatus Display::registerProximitySensorStateChangeCallback(
+        const std::shared_ptr<IDisplayProximitySensorCallback>& callback) {
+    if (mDisplay && callback) {
+        mDisplay->mProximitySensorStateChangeCallback = callback;
+        return ndk::ScopedAStatus::ok();
+    }
+    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
+}
+
 } // namespace display
 } // namespace pixel
 } // namespace hardware
diff --git a/libhwc2.1/pixel-display.h b/libhwc2.1/pixel-display.h
index 0d9a7cc..fb00b44 100644
--- a/libhwc2.1/pixel-display.h
+++ b/libhwc2.1/pixel-display.h
@@ -79,6 +79,9 @@ public:
     ndk::ScopedAStatus setFixedTe2Rate(int rateHz, int* _aidl_return) override;
     ndk::ScopedAStatus queryStats(DisplayStats::Tag tag,
                                   std::optional<DisplayStats>* _aidl_return) override;
+    ndk::ScopedAStatus isProximitySensorStateCallbackSupported(bool* _aidl_return) override;
+    ndk::ScopedAStatus registerProximitySensorStateChangeCallback(
+            const std::shared_ptr<IDisplayProximitySensorCallback>& callback) override;
 
 private:
     bool runMediator(const RoiRect &roi, const Weight &weight, const HistogramPos &pos,
```

