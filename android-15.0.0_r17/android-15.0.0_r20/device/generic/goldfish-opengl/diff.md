```diff
diff --git a/OWNERS b/OWNERS
index 392be476..633f3314 100644
--- a/OWNERS
+++ b/OWNERS
@@ -8,7 +8,6 @@ msandy@google.com
 natsu@google.com
 rkir@google.com
 tutankhamen@google.com
-yahan@google.com
 kocdemir@google.com
 joshuaduong@google.com
 sergiuferentz@google.com
diff --git a/system/hwc3/Android.bp b/system/hwc3/Android.bp
index 9e0a1ab7..4f603e04 100644
--- a/system/hwc3/Android.bp
+++ b/system/hwc3/Android.bp
@@ -26,6 +26,7 @@ cc_binary {
 
     defaults: [
         "android.hardware.graphics.composer3-ndk_shared",
+        "mesa_platform_virtgpu_defaults",
     ],
 
     relative_install_path: "hw",
diff --git a/system/hwc3/ComposerClient.cpp b/system/hwc3/ComposerClient.cpp
index 2ae24998..5dd0dddb 100644
--- a/system/hwc3/ComposerClient.cpp
+++ b/system/hwc3/ComposerClient.cpp
@@ -674,6 +674,33 @@ ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
     return ToBinderStatus(HWC3::Error::Unsupported);
 }
 
+ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t displayId, int32_t*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::startHdcpNegotiation(int64_t displayId,
+    const aidl::android::hardware::drm::HdcpLevels& /*levels*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getLuts(int64_t displayId,
+        const std::vector<Buffer>&,
+        std::vector<Luts>*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
 ndk::SpAIBinder ComposerClient::createBinder() {
     auto binder = BnComposerClient::createBinder();
     AIBinder_setInheritRt(binder.get(), true);
@@ -1196,11 +1223,16 @@ void ComposerClient::executeLayerCommandSetLayerPerFrameMetadataBlobs(
     }
 }
 
-void ComposerClient::executeLayerCommandSetLayerLuts(CommandResultWriter& /*commandResults*/,
-                                                     Display& /*display*/, Layer* /*layer*/,
-                                                     const std::vector<std::optional<Lut>>& /*luts*/) {
+void ComposerClient::executeLayerCommandSetLayerLuts(CommandResultWriter& commandResults,
+                                                     Display& display, Layer* layer,
+                                                     const Luts& luts) {
     DEBUG_LOG("%s", __FUNCTION__);
-    //TODO(b/358188835)
+
+    auto error = layer->setLuts(luts);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
 }
 
 std::shared_ptr<Display> ComposerClient::getDisplay(int64_t displayId) {
diff --git a/system/hwc3/ComposerClient.h b/system/hwc3/ComposerClient.h
index 3cf10685..87a4eb01 100644
--- a/system/hwc3/ComposerClient.h
+++ b/system/hwc3/ComposerClient.h
@@ -18,7 +18,7 @@
 #define ANDROID_HWC_COMPOSERCLIENT_H
 
 #include <aidl/android/hardware/graphics/composer3/BnComposerClient.h>
-#include <aidl/android/hardware/graphics/composer3/Lut.h>
+#include <aidl/android/hardware/graphics/composer3/Luts.h>
 #include <android-base/thread_annotations.h>
 
 #include <memory>
@@ -124,6 +124,13 @@ class ComposerClient : public BnComposerClient {
     ndk::ScopedAStatus notifyExpectedPresent(int64_t displayId,
                                              const ClockMonotonicTimestamp& expectedPresentTime,
                                              int32_t maxFrameIntervalNs) override;
+    ndk::ScopedAStatus getMaxLayerPictureProfiles(int64_t displayId, int32_t* outMaxProfiles)
+                                                  override;
+    ndk::ScopedAStatus startHdcpNegotiation(
+        int64_t displayId, const aidl::android::hardware::drm::HdcpLevels& levels) override;
+    ndk::ScopedAStatus getLuts(int64_t displayId,
+            const std::vector<Buffer>&,
+            std::vector<Luts>*) override;
 
    protected:
     ndk::SpAIBinder createBinder() override;
@@ -205,7 +212,7 @@ class ComposerClient : public BnComposerClient {
         const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadataBlob);
     void executeLayerCommandSetLayerLuts(
         CommandResultWriter& commandResults, Display& display, Layer* layer,
-        const std::vector<std::optional<Lut>>& luts);
+        const Luts& luts);
 
     // Returns the display with the given id or nullptr if not found.
     std::shared_ptr<Display> getDisplay(int64_t displayId);
@@ -249,4 +256,4 @@ class ComposerClient : public BnComposerClient {
 
 }  // namespace aidl::android::hardware::graphics::composer3::impl
 
-#endif
\ No newline at end of file
+#endif
diff --git a/system/hwc3/DrmConnector.cpp b/system/hwc3/DrmConnector.cpp
index d8906445..a7b67299 100644
--- a/system/hwc3/DrmConnector.cpp
+++ b/system/hwc3/DrmConnector.cpp
@@ -67,7 +67,6 @@ bool DrmConnector::update(::android::base::borrowed_fd drmFd) {
         mModes.push_back(std::move(mode));
     }
 
-    drmModeFreeConnector(drmConnector);
 
     if (mStatus == DRM_MODE_CONNECTED) {
         std::optional<EdidInfo> maybeEdidInfo = loadEdid(drmFd);
@@ -87,6 +86,7 @@ bool DrmConnector::update(::android::base::borrowed_fd drmFd) {
               __FUNCTION__, mId, (mWidthMillimeters ? *mWidthMillimeters : 0),
               (mHeightMillimeters ? *mHeightMillimeters : 0));
 
+    drmModeFreeConnector(drmConnector);
     return true;
 }
 
diff --git a/system/hwc3/GuestFrameComposer.cpp b/system/hwc3/GuestFrameComposer.cpp
index 24002b89..c5d5d99e 100644
--- a/system/hwc3/GuestFrameComposer.cpp
+++ b/system/hwc3/GuestFrameComposer.cpp
@@ -35,6 +35,39 @@
 namespace aidl::android::hardware::graphics::composer3::impl {
 namespace {
 
+// Returns a color matrix that can be used with libyuv by converting values
+// in -1 to 1 into -64 to 64 and converting row-major to column-major by transposing.
+std::array<std::int8_t, 16> ToLibyuvColorMatrix(const std::array<float, 16>& in) {
+    std::array<std::int8_t, 16> out;
+
+    for (int r = 0; r < 4; r++) {
+        for (int c = 0; c < 4; c++) {
+            int indexIn = (4 * r) + c;
+            int indexOut = (4 * c) + r;
+
+            float clampedValue = std::max(
+                -128.0f, std::min(127.0f, in[static_cast<size_t>(indexIn)] * 64.0f + 0.5f));
+            out[(size_t)indexOut] = static_cast<std::int8_t>(clampedValue);
+        }
+    }
+
+    return out;
+}
+
+std::uint8_t ToLibyuvColorChannel(float v) {
+    return static_cast<std::uint8_t>(std::min(255, static_cast<int>(v * 255.0f + 0.5f)));
+}
+
+std::uint32_t ToLibyuvColor(float r, float g, float b, float a) {
+    std::uint32_t out;
+    std::uint8_t* outChannels = reinterpret_cast<std::uint8_t*>(&out);
+    outChannels[0] = ToLibyuvColorChannel(r);
+    outChannels[1] = ToLibyuvColorChannel(g);
+    outChannels[2] = ToLibyuvColorChannel(b);
+    outChannels[3] = ToLibyuvColorChannel(a);
+    return out;
+}
+
 using ::android::hardware::graphics::common::V1_0::ColorTransform;
 
 uint32_t AlignToPower2(uint32_t val, uint8_t align_log) {
@@ -343,6 +376,22 @@ int DoAttenuation(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
                                  width, height);
 }
 
+int DoBrightnessShading(const BufferSpec& src, const BufferSpec& dst, float layerBrightness) {
+    ATRACE_CALL();
+
+    const float layerBrightnessGammaCorrected = std::pow(layerBrightness, 1.0f / 2.2f);
+
+    const std::uint32_t shade =
+        ToLibyuvColor(layerBrightnessGammaCorrected, layerBrightnessGammaCorrected,
+                      layerBrightnessGammaCorrected, 1.0f);
+
+    auto ret = libyuv::ARGBShade(src.buffer, static_cast<int>(src.strideBytes), dst.buffer,
+                                 static_cast<int>(dst.strideBytes), static_cast<int>(dst.width),
+                                 static_cast<int>(dst.height), shade);
+
+    return ret;
+}
+
 int DoBlending(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
     ATRACE_CALL();
 
@@ -483,14 +532,14 @@ HWC3::Error GuestFrameComposer::onDisplayCreate(Display* display) {
     displayInfo.swapchain = DrmSwapchain::create(static_cast<uint32_t>(displayWidth),
                                                  static_cast<uint32_t>(displayHeight),
                                                  ::android::GraphicBuffer::USAGE_HW_COMPOSER |
-                                                   ::android::GraphicBuffer::USAGE_SW_READ_OFTEN |
-                                                   ::android::GraphicBuffer::USAGE_SW_WRITE_OFTEN,
+                                                     ::android::GraphicBuffer::USAGE_SW_READ_OFTEN |
+                                                     ::android::GraphicBuffer::USAGE_SW_WRITE_OFTEN,
                                                  &mDrmClient);
 
     if (displayId == 0) {
         auto compositionResult = displayInfo.swapchain->getNextImage();
         auto [flushError, flushSyncFd] =
-                mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
+            mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
         if (flushError != HWC3::Error::None) {
             ALOGW(
                 "%s: Initial display flush failed. HWComposer assuming that we are "
@@ -515,8 +564,7 @@ HWC3::Error GuestFrameComposer::onDisplayDestroy(Display* display) {
 
     auto it = mDisplayInfos.find(displayId);
     if (it == mDisplayInfos.end()) {
-        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__,
-            displayId);
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
         return HWC3::Error::BadDisplay;
     }
     mDisplayInfos.erase(it);
@@ -667,14 +715,13 @@ HWC3::Error GuestFrameComposer::presentDisplay(
     compositionResult->wait();
 
     if (compositionResult->getBuffer() == nullptr) {
-        ALOGE("%s: display:%" PRIu32 " missing composition result buffer",
-            __FUNCTION__, displayId);
+        ALOGE("%s: display:%" PRIu32 " missing composition result buffer", __FUNCTION__, displayId);
         return HWC3::Error::NoResources;
     }
 
     if (compositionResult->getDrmBuffer() == nullptr) {
-        ALOGE("%s: display:%" PRIu32 " missing composition result drm buffer",
-            __FUNCTION__, displayId);
+        ALOGE("%s: display:%" PRIu32 " missing composition result drm buffer", __FUNCTION__,
+              displayId);
         return HWC3::Error::NoResources;
     }
 
@@ -778,6 +825,7 @@ HWC3::Error GuestFrameComposer::presentDisplay(
         for (Layer* layer : layers) {
             const auto layerId = layer->getId();
             const auto layerCompositionType = layer->getCompositionType();
+
             if (layerCompositionType != Composition::DEVICE &&
                 layerCompositionType != Composition::SOLID_COLOR) {
                 continue;
@@ -811,19 +859,18 @@ HWC3::Error GuestFrameComposer::presentDisplay(
         }
     }
 
-    DEBUG_LOG("%s display:%" PRIu32 " flushing drm buffer", __FUNCTION__,
-                displayId);
+    DEBUG_LOG("%s display:%" PRIu32 " flushing drm buffer", __FUNCTION__, displayId);
 
-    auto [error, fence] = mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
+    auto [error, fence] =
+        mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
     if (error != HWC3::Error::None) {
-        ALOGE("%s: display:%" PRIu32 " failed to flush drm buffer" PRIu64,
-            __FUNCTION__, displayId);
+        ALOGE("%s: display:%" PRIu32 " failed to flush drm buffer" PRIu64, __FUNCTION__, displayId);
     }
 
     *outDisplayFence = std::move(fence);
     compositionResult->markAsInUse(outDisplayFence->ok()
-                                        ? ::android::base::unique_fd(dup(*outDisplayFence))
-                                        : ::android::base::unique_fd());
+                                       ? ::android::base::unique_fd(dup(*outDisplayFence))
+                                       : ::android::base::unique_fd());
     return error;
 }
 
@@ -861,6 +908,10 @@ bool GuestFrameComposer::canComposeLayer(Layer* layer) {
         return false;
     }
 
+    if (layer->hasLuts()) {
+        return false;
+    }
+
     return true;
 }
 
@@ -921,6 +972,7 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     bool needsVFlip = GetVFlipFromTransform(srcLayer->getTransform());
     bool needsAttenuation = LayerNeedsAttenuation(*srcLayer);
     bool needsBlending = LayerNeedsBlending(*srcLayer);
+    bool needsBrightness = srcLayer->getBrightness() != 1.0f;
     bool needsCopy = !(needsConversion || needsScaling || needsRotation || needsVFlip ||
                        needsAttenuation || needsBlending);
 
@@ -946,7 +998,7 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     int neededIntermediateImages = (needsFill ? 1 : 0) + (needsConversion ? 1 : 0) +
                                    (needsScaling ? 1 : 0) + (needsRotation ? 1 : 0) +
                                    (needsAttenuation ? 1 : 0) + (needsBlending ? 1 : 0) +
-                                   (needsCopy ? 1 : 0) - 1;
+                                   (needsCopy ? 1 : 0) + (needsBrightness ? 1 : 0) - 1;
 
     uint32_t mScratchBufferWidth =
         static_cast<uint32_t>(srcLayerDisplayFrame.right - srcLayerDisplayFrame.left);
@@ -1060,6 +1112,16 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
         dstBufferStack.pop_back();
     }
 
+    if (needsBrightness) {
+        int retval =
+            DoBrightnessShading(srcLayerSpec, dstBufferStack.back(), srcLayer->getBrightness());
+        if (retval) {
+            ALOGE("Got error code %d from DoBrightnessShading function", retval);
+        }
+        srcLayerSpec = dstBufferStack.back();
+        dstBufferStack.pop_back();
+    }
+
     if (needsCopy) {
         int retval = DoCopy(srcLayerSpec, dstBufferStack.back(), needsVFlip);
         needsVFlip = false;
@@ -1085,28 +1147,6 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     return HWC3::Error::None;
 }
 
-namespace {
-
-// Returns a color matrix that can be used with libyuv by converting values
-// in -1 to 1 into -64 to 64 and transposing.
-std::array<std::int8_t, 16> ToLibyuvColorMatrix(const std::array<float, 16>& in) {
-    std::array<std::int8_t, 16> out;
-
-    for (size_t r = 0; r < 4; r++) {
-        for (size_t c = 0; c < 4; c++) {
-            size_t indexIn = (4 * r) + c;
-            size_t indexOut = (4 * c) + r;
-
-            out[indexOut] = static_cast<std::int8_t>(
-                std::max(-128, std::min(127, static_cast<int>(in[indexIn] * 64.0f + 0.5f))));
-        }
-    }
-
-    return out;
-}
-
-}  // namespace
-
 HWC3::Error GuestFrameComposer::applyColorTransformToRGBA(
     const std::array<float, 16>& transfromMatrix,  //
     std::uint8_t* buffer,                          //
diff --git a/system/hwc3/HostFrameComposer.cpp b/system/hwc3/HostFrameComposer.cpp
index d14d812c..15ce8be6 100644
--- a/system/hwc3/HostFrameComposer.cpp
+++ b/system/hwc3/HostFrameComposer.cpp
@@ -30,9 +30,10 @@
 #include <optional>
 #include <tuple>
 
-#include "gfxstream/guest/goldfish_sync.h"
 #include "Display.h"
 #include "HostUtils.h"
+#include "Sync.h"
+#include "gfxstream/guest/goldfish_sync.h"
 #include "virtgpu_drm.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
@@ -172,6 +173,8 @@ HWC3::Error HostFrameComposer::init() {
             ALOGE("%s: failed to initialize DrmClient", __FUNCTION__);
             return error;
         }
+
+        mSyncHelper.reset(gfxstream::createPlatformSyncHelper());
     } else {
         mSyncDeviceFd = goldfish_sync_open();
     }
@@ -403,8 +406,7 @@ HWC3::Error HostFrameComposer::validateDisplay(Display* display, DisplayChanges*
 
     // If one layer requires a fall back to the client composition type, all
     // layers will fall back to the client composition type.
-    bool fallBackToClient =
-        (!hostCompositionV1 && !hostCompositionV2);
+    bool fallBackToClient = (!hostCompositionV1 && !hostCompositionV2);
     std::unordered_map<Layer*, Composition> changes;
 
     if (!fallBackToClient) {
@@ -434,7 +436,11 @@ HWC3::Error HostFrameComposer::validateDisplay(Display* display, DisplayChanges*
                     break;
                 default:
                     ALOGE("%s: layer %" PRIu32 " has an unknown composition type: %s", __FUNCTION__,
-                          static_cast<uint32_t>(layer->getId()), layerCompositionTypeString.c_str());
+                          static_cast<uint32_t>(layer->getId()),
+                          layerCompositionTypeString.c_str());
+            }
+            if (layer->hasLuts()) {
+                layerFallBackTo = Composition::CLIENT;
             }
             if (layerFallBackTo == Composition::CLIENT) {
                 fallBackToClient = true;
@@ -524,7 +530,8 @@ HWC3::Error HostFrameComposer::presentDisplay(
 
                     *outDisplayFence = std::move(flushCompleteFence);
                 } else {
-                    post(hostCon, rcEnc, displayInfo.hostDisplayId, displayClientTarget.getBuffer());
+                    post(hostCon, rcEnc, displayInfo.hostDisplayId,
+                         displayClientTarget.getBuffer());
                     *outDisplayFence = std::move(fence);
                 }
             }
@@ -575,6 +582,10 @@ HWC3::Error HostFrameComposer::presentDisplay(
                     if (err < 0 && errno == ETIME) {
                         ALOGE("%s waited on fence %d for 3000 ms", __FUNCTION__, fence.get());
                     }
+
+#if GOLDFISH_OPENGL_SYNC_DEBUG
+                    mSyncHelper->debugPrint(fence.get());
+#endif
                 } else {
                     ALOGV("%s: acquire fence not set for layer %u", __FUNCTION__,
                           (uint32_t)layer->getId());
@@ -593,7 +604,20 @@ HWC3::Error HostFrameComposer::presentDisplay(
             l->displayFrame = AsHwcRect(layer->getDisplayFrame());
             l->crop = AsHwcFrect(layer->getSourceCrop());
             l->blendMode = static_cast<int32_t>(layer->getBlendMode());
-            l->alpha = layer->getPlaneAlpha();
+            float alpha = layer->getPlaneAlpha();
+            float brightness = layer->getBrightness();
+            // Apply brightness by modulating the layer's alpha.
+            //
+            // Due to limitations in the current implementation, per-layer brightness control
+            // is not supported. To simulate the desired visual effect, brightness is approximated
+            // by adjusting the alpha value of the layer.
+            //
+            // This approach, while not ideal, is sufficient enough for a virtual device (TV
+            // Cuttlefish) because virtual displays based on Virtio GPU do not have per-layer
+            // brightness control.
+
+            float mixFactor = 0.5f;
+            l->alpha = (alpha * (1.0f - mixFactor)) + (brightness * mixFactor);
             l->color = AsHwcColor(layer->getColor());
             l->transform = AsHwcTransform(layer->getTransform());
             ALOGV(
@@ -713,9 +737,8 @@ void HostFrameComposer::post(HostConnection* hostCon, ExtendedRCEncoderContext*
     assert(cb && "native_handle_t::from(h) failed");
 
     hostCon->lock();
-    rcEnc->rcSetDisplayColorBuffer(
-        rcEnc, hostDisplayId,
-        hostCon->grallocHelper()->getHostHandle(h));
+    rcEnc->rcSetDisplayColorBuffer(rcEnc, hostDisplayId,
+                                   hostCon->grallocHelper()->getHostHandle(h));
     rcEnc->rcFBPost(rcEnc, hostCon->grallocHelper()->getHostHandle(h));
     hostCon->flush();
     hostCon->unlock();
diff --git a/system/hwc3/HostFrameComposer.h b/system/hwc3/HostFrameComposer.h
index 2cd9854a..79d98783 100644
--- a/system/hwc3/HostFrameComposer.h
+++ b/system/hwc3/HostFrameComposer.h
@@ -88,6 +88,7 @@ class HostFrameComposer : public FrameComposer {
         std::shared_ptr<DrmBuffer> clientTargetDrmBuffer;
     };
 
+    std::unique_ptr<gfxstream::SyncHelper> mSyncHelper = nullptr;
     std::unordered_map<int64_t, HostComposerDisplayInfo> mDisplayInfos;
 
     std::optional<DrmClient> mDrmClient;
diff --git a/system/hwc3/Layer.cpp b/system/hwc3/Layer.cpp
index 7cc1abab..d391f2b5 100644
--- a/system/hwc3/Layer.cpp
+++ b/system/hwc3/Layer.cpp
@@ -316,6 +316,19 @@ HWC3::Error Layer::setPerFrameMetadataBlobs(
     return HWC3::Error::None;
 }
 
+HWC3::Error Layer::setLuts(const Luts& luts) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    mHasLuts = luts.pfd.get() >= 0;
+    return HWC3::Error::None;
+}
+
+bool Layer::hasLuts() const {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mHasLuts;
+}
+
 void Layer::logCompositionFallbackIfChanged(Composition to) {
     Composition from = getCompositionType();
     if (mLastCompositionFallback && mLastCompositionFallback->from == from &&
diff --git a/system/hwc3/Layer.h b/system/hwc3/Layer.h
index 05dc5ee2..22ac4e96 100644
--- a/system/hwc3/Layer.h
+++ b/system/hwc3/Layer.h
@@ -91,6 +91,9 @@ class Layer {
     HWC3::Error setPerFrameMetadataBlobs(
         const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadata);
 
+    HWC3::Error setLuts(const Luts& luts);
+    bool hasLuts() const;
+
     // For log use only.
     void logCompositionFallbackIfChanged(Composition to);
 
@@ -116,6 +119,7 @@ class Layer {
     int32_t mZOrder = 0;
     std::optional<std::array<float, 16>> mColorTransform;
     float mBrightness = 1.0f;
+    bool mHasLuts = false;
 };
 
 }  // namespace aidl::android::hardware::graphics::composer3::impl
```

