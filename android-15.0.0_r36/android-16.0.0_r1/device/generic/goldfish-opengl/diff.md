```diff
diff --git a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
index d77cba07..6b97caff 100644
--- a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
+++ b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
@@ -429,8 +429,8 @@ C2GoldfishAvcDec::C2GoldfishAvcDec(const char *name, c2_node_id_t id,
                                    const std::shared_ptr<IntfImpl> &intfImpl)
     : SimpleC2Component(
           std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
-      mIntf(intfImpl), mOutBufferFlush(nullptr), mWidth(1920), mHeight(1080),
-      mHeaderDecoded(false), mOutIndex(0u) {
+      mIntf(intfImpl), mOutBufferFlush(nullptr), mOutIndex(0u),
+      mWidth(1920), mHeight(1080), mHeaderDecoded(false) {
     mWidth = mIntf->width();
     mHeight = mIntf->height();
     DDD("creating avc decoder now w %d h %d", mWidth, mHeight);
diff --git a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h
index 4204eb37..33aa2d97 100644
--- a/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h
+++ b/system/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h
@@ -59,9 +59,6 @@ class C2GoldfishAvcDec : public SimpleC2Component {
                       const std::shared_ptr<C2BlockPool> &pool) override;
 
   private:
-    std::unique_ptr<MediaH264Decoder> mContext;
-    bool mEnableAndroidNativeBuffers{true};
-
     void checkMode(const std::shared_ptr<C2BlockPool> &pool);
     //    status_t createDecoder();
     status_t createDecoder();
@@ -79,19 +76,11 @@ class C2GoldfishAvcDec : public SimpleC2Component {
     void resetPlugin();
     void deleteContext();
 
-    std::shared_ptr<IntfImpl> mIntf;
 
     void removePts(uint64_t pts);
     void insertPts(uint32_t work_index, uint64_t pts);
     uint64_t getWorkIndex(uint64_t pts);
 
-    // there are same pts matching to different work indices
-    // this happen during csd0/csd1 switching
-    std::map<uint64_t, uint64_t> mOldPts2Index;
-    std::map<uint64_t, uint64_t> mPts2Index;
-    std::map<uint64_t, uint64_t> mIndex2Pts;
-    uint64_t  mPts {0};
-
     // TODO:This is not the right place for this enum. These should
     // be part of c2-vndk so that they can be accessed by all video plugins
     // until then, make them feel at home
@@ -101,29 +90,6 @@ class C2GoldfishAvcDec : public SimpleC2Component {
         kPreferContainer,
     };
 
-    std::shared_ptr<C2GraphicBlock> mOutBlock;
-    uint8_t *mOutBufferFlush;
-
-    int mHostColorBufferId{-1};
-
-    void getVuiParams(h264_image_t &img);
-    void copyImageData(h264_image_t &img);
-
-    h264_image_t mImg{};
-    uint32_t mConsumedBytes{0};
-    uint8_t *mInPBuffer{nullptr};
-    uint32_t mInPBufferSize;
-    uint32_t mInTsMarker;
-
-    // size_t mNumCores;
-    // uint32_t mOutputDelay;
-    uint32_t mWidth;
-    uint32_t mHeight;
-    uint32_t mStride;
-    bool mSignalledOutputEos;
-    bool mSignalledError;
-    bool mHeaderDecoded;
-    std::atomic_uint64_t mOutIndex;
     // Color aspects. These are ISO values and are meant to detect changes in
     // aspects to avoid converting them to C2 values for each frame
     struct VuiColorAspects {
@@ -136,16 +102,62 @@ class C2GoldfishAvcDec : public SimpleC2Component {
         VuiColorAspects()
             : primaries(2), transfer(2), coeffs(2), fullRange(0) {}
 
-        bool operator==(const VuiColorAspects &o) {
+        bool operator==(const VuiColorAspects &o) const {
             return primaries == o.primaries && transfer == o.transfer &&
                    coeffs == o.coeffs && fullRange == o.fullRange;
         }
-    } mBitstreamColorAspects;
+    };
 
-    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+    void getVuiParams(h264_image_t &img);
+    void copyImageData(h264_image_t &img);
 
     void sendMetadata();
 
+    void decodeHeaderAfterFlush();
+
+    std::unique_ptr<MediaH264Decoder> mContext;
+    std::shared_ptr<C2GraphicBlock> mOutBlock;
+    std::unique_ptr<GoldfishH264Helper> mH264Helper;
+
+    std::shared_ptr<IntfImpl> mIntf;
+    uint8_t *mOutBufferFlush{nullptr};
+    uint8_t *mInPBuffer{nullptr};
+
+    // there are same pts matching to different work indices
+    // this happen during csd0/csd1 switching
+    std::map<uint64_t, uint64_t> mOldPts2Index;
+    std::map<uint64_t, uint64_t> mPts2Index;
+    std::map<uint64_t, uint64_t> mIndex2Pts;
+
+    std::vector<uint8_t> mCsd0;
+    std::vector<uint8_t> mCsd1;
+
+    std::atomic_uint64_t mOutIndex;
+    uint64_t  mPts {0};
+
+    h264_image_t mImg{};
+    VuiColorAspects mBitstreamColorAspects;
+    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+
+
+    uint32_t mConsumedBytes{0};
+    uint32_t mInPBufferSize{0};
+    uint32_t mInTsMarker{0};
+
+    // size_t mNumCores;
+    // uint32_t mOutputDelay;
+    uint32_t mWidth{0};
+    uint32_t mHeight{0};
+    uint32_t mStride{0};
+
+    int mHostColorBufferId{-1};
+    int mId = -1;
+
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mHeaderDecoded{false};
+
     // profile
     struct timeval mTimeStart;
     struct timeval mTimeEnd;
@@ -153,13 +165,6 @@ class C2GoldfishAvcDec : public SimpleC2Component {
     char mInFile[200];
 #endif /* FILE_DUMP_ENABLE */
 
-    std::vector<uint8_t> mCsd0;
-    std::vector<uint8_t> mCsd1;
-    void decodeHeaderAfterFlush();
-
-    std::unique_ptr<GoldfishH264Helper> mH264Helper;
-
-    int mId = -1;
     C2_DO_NOT_COPY(C2GoldfishAvcDec);
 };
 
diff --git a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
index 81c07a85..3197be05 100644
--- a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
+++ b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
@@ -380,8 +380,8 @@ C2GoldfishHevcDec::C2GoldfishHevcDec(const char *name, c2_node_id_t id,
                                    const std::shared_ptr<IntfImpl> &intfImpl)
     : SimpleC2Component(
           std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
-      mIntf(intfImpl), mOutBufferFlush(nullptr), mWidth(1920), mHeight(1080),
-      mHeaderDecoded(false), mOutIndex(0u) {
+      mIntf(intfImpl), mOutBufferFlush(nullptr), mOutIndex(0u),
+      mWidth(1920), mHeight(1080), mHeaderDecoded(false) {
     mWidth = mIntf->width();
     mHeight = mIntf->height();
     DDD("creating hevc decoder now w %d h %d", mWidth, mHeight);
diff --git a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h
index 04a4d722..f1486df3 100644
--- a/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h
+++ b/system/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h
@@ -59,9 +59,6 @@ class C2GoldfishHevcDec : public SimpleC2Component {
                       const std::shared_ptr<C2BlockPool> &pool) override;
 
   private:
-    std::unique_ptr<MediaHevcDecoder> mContext;
-    bool mEnableAndroidNativeBuffers{true};
-
     void checkMode(const std::shared_ptr<C2BlockPool> &pool);
     //    status_t createDecoder();
     status_t createDecoder();
@@ -79,19 +76,10 @@ class C2GoldfishHevcDec : public SimpleC2Component {
     void resetPlugin();
     void deleteContext();
 
-    std::shared_ptr<IntfImpl> mIntf;
-
     void removePts(uint64_t pts);
     void insertPts(uint32_t work_index, uint64_t pts);
     uint64_t getWorkIndex(uint64_t pts);
 
-    // there are same pts matching to different work indices
-    // this happen during csd0/csd1 switching
-    std::map<uint64_t, uint64_t> mOldPts2Index;
-    std::map<uint64_t, uint64_t> mPts2Index;
-    std::map<uint64_t, uint64_t> mIndex2Pts;
-    uint64_t  mPts {0};
-
     // TODO:This is not the right place for this enum. These should
     // be part of c2-vndk so that they can be accessed by all video plugins
     // until then, make them feel at home
@@ -101,29 +89,12 @@ class C2GoldfishHevcDec : public SimpleC2Component {
         kPreferContainer,
     };
 
-    std::shared_ptr<C2GraphicBlock> mOutBlock;
-    uint8_t *mOutBufferFlush;
-
-    int mHostColorBufferId{-1};
-
     void getVuiParams(hevc_image_t &img);
     void copyImageData(hevc_image_t &img);
 
-    hevc_image_t mImg{};
-    uint32_t mConsumedBytes{0};
-    uint8_t *mInPBuffer{nullptr};
-    uint32_t mInPBufferSize;
-    uint32_t mInTsMarker;
 
-    // size_t mNumCores;
-    // uint32_t mOutputDelay;
-    uint32_t mWidth;
-    uint32_t mHeight;
-    uint32_t mStride;
-    bool mSignalledOutputEos;
-    bool mSignalledError;
-    bool mHeaderDecoded;
-    std::atomic_uint64_t mOutIndex;
+
+
     // Color aspects. These are ISO values and are meant to detect changes in
     // aspects to avoid converting them to C2 values for each frame
     struct VuiColorAspects {
@@ -136,15 +107,56 @@ class C2GoldfishHevcDec : public SimpleC2Component {
         VuiColorAspects()
             : primaries(2), transfer(2), coeffs(2), fullRange(0) {}
 
-        bool operator==(const VuiColorAspects &o) {
+        bool operator==(const VuiColorAspects &o) const {
             return primaries == o.primaries && transfer == o.transfer &&
                    coeffs == o.coeffs && fullRange == o.fullRange;
         }
-    } mBitstreamColorAspects;
+    };
+
+    void sendMetadata();
+
+    void decodeHeaderAfterFlush();
+
+    std::unique_ptr<MediaHevcDecoder> mContext;
+    std::unique_ptr<GoldfishHevcHelper> mHevcHelper;
+    std::shared_ptr<IntfImpl> mIntf;
+    std::shared_ptr<C2GraphicBlock> mOutBlock;
+
+    std::vector<uint8_t> mCsd0;
+    std::vector<uint8_t> mCsd1;
+
+    std::map<uint64_t, uint64_t> mOldPts2Index;
+    std::map<uint64_t, uint64_t> mPts2Index;
+    std::map<uint64_t, uint64_t> mIndex2Pts;
+
+    uint8_t *mInPBuffer{nullptr};
+    uint8_t *mOutBufferFlush{nullptr};
 
+    hevc_image_t mImg{};
+    VuiColorAspects mBitstreamColorAspects;
     MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
 
-    void sendMetadata();
+    std::atomic_uint64_t mOutIndex;
+    // there are same pts matching to different work indices
+    // this happen during csd0/csd1 switching
+    uint64_t  mPts {0};
+
+    uint32_t mConsumedBytes{0};
+    uint32_t mInPBufferSize = 0;
+    uint32_t mInTsMarker = 0;
+
+    // size_t mNumCores;
+    // uint32_t mOutputDelay;
+    uint32_t mWidth = 0;
+    uint32_t mHeight = 0;
+    uint32_t mStride = 0;
+
+    int mHostColorBufferId{-1};
+
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mHeaderDecoded{false};
 
     // profile
     struct timeval mTimeStart;
@@ -153,12 +165,6 @@ class C2GoldfishHevcDec : public SimpleC2Component {
     char mInFile[200];
 #endif /* FILE_DUMP_ENABLE */
 
-    std::vector<uint8_t> mCsd0;
-    std::vector<uint8_t> mCsd1;
-    void decodeHeaderAfterFlush();
-
-    std::unique_ptr<GoldfishHevcHelper> mHevcHelper;
-
     C2_DO_NOT_COPY(C2GoldfishHevcDec);
 };
 
diff --git a/system/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h b/system/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h
index 878950e7..b071aa15 100644
--- a/system/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h
+++ b/system/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h
@@ -43,20 +43,12 @@ struct hevc_image_t {
     int ret;
 };
 
-enum class RenderMode {
+enum class RenderMode : uint8_t {
     RENDER_BY_HOST_GPU = 1,
     RENDER_BY_GUEST_CPU = 2,
 };
 
 class MediaHevcDecoder {
-    uint64_t mHostHandle = 0;
-    uint32_t mVersion = 100;
-    RenderMode mRenderMode = RenderMode::RENDER_BY_GUEST_CPU;
-
-    bool mHasAddressSpaceMemory = false;
-    uint64_t mAddressOffSet = 0;
-    int mSlot = -1;
-
   public:
     MediaHevcDecoder(RenderMode renderMode);
     virtual ~MediaHevcDecoder() = default;
@@ -94,5 +86,12 @@ class MediaHevcDecoder {
 
     void sendMetadata(MetaDataColorAspects *ptr);
 
+  private:
+    uint64_t mHostHandle = 0;
+    uint64_t mAddressOffSet = 0;
+    uint32_t mVersion = 100;
+    int mSlot = -1;
+    RenderMode mRenderMode = RenderMode::RENDER_BY_GUEST_CPU;
+    bool mHasAddressSpaceMemory = false;
 };
 #endif
diff --git a/system/codecs/c2/decoders/vpxdec/Android.bp b/system/codecs/c2/decoders/vpxdec/Android.bp
index 7be2d50f..2e08a6d5 100644
--- a/system/codecs/c2/decoders/vpxdec/Android.bp
+++ b/system/codecs/c2/decoders/vpxdec/Android.bp
@@ -7,51 +7,55 @@ package {
     default_applicable_licenses: ["device_generic_goldfish-opengl_license"],
 }
 
-cc_library_shared {
-    name: "libcodec2_goldfish_vp9dec",
+cc_library_static {
+    name: "goldfish_vpx_impl",
     vendor: true,
+    srcs: [
+        "goldfish_vpx_impl.cpp",
+    ],
+    shared_libs: [
+        "libcodec2_goldfish_common",
+        "libgoldfish_codec2_store",
+        "liblog",
+    ],
+}
+
+cc_defaults {
+    name: "libcodec2_goldfish_vpXdec_defaults",
     defaults: [
         "libcodec2_goldfish-defaults",
     ],
 
-    srcs: ["C2GoldfishVpxDec.cpp",
-        "goldfish_vpx_impl.cpp",
+    vendor: true,
+    srcs: [
+        "C2GoldfishVpxDec.cpp",
     ],
-
-    shared_libs: ["libvpx",
-	    "android.hardware.graphics.allocator@3.0",
-		"android.hardware.graphics.mapper@3.0",
-         "libgoldfish_codec2_store",
+    header_libs: [
+        "libgralloc_cb.ranchu",
     ],
-
-   header_libs: [
-    "libgralloc_cb.ranchu",
+    static_libs: [
+        "android.hardware.graphics.common-V6-ndk",
+        "goldfish_vpx_impl",
     ],
-
-    cflags: [
-        "-DVP9",
+    shared_libs: [
+        "libgoldfish_codec2_store",
+        "libvpx",
     ],
 }
 
 cc_library_shared {
     name: "libcodec2_goldfish_vp8dec",
-    vendor: true,
     defaults: [
-        "libcodec2_goldfish-defaults",
+        "libcodec2_goldfish_vpXdec_defaults",
     ],
+}
 
-    srcs: ["C2GoldfishVpxDec.cpp",
-        "goldfish_vpx_impl.cpp",
-    ],
-
-
-   header_libs: [
-    "libgralloc_cb.ranchu",
+cc_library_shared {
+    name: "libcodec2_goldfish_vp9dec",
+    defaults: [
+        "libcodec2_goldfish_vpXdec_defaults",
     ],
-
-    shared_libs: ["libvpx",
-	    "android.hardware.graphics.allocator@3.0",
-		"android.hardware.graphics.mapper@3.0",
-         "libgoldfish_codec2_store",
+    cflags: [
+        "-DVP9",
     ],
 }
diff --git a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
index 1d2a70ec..f1407af1 100644
--- a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
+++ b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
@@ -20,16 +20,13 @@
 
 #include <algorithm>
 
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+
 #include <media/stagefright/foundation/AUtils.h>
 #include <media/stagefright/foundation/MediaDefs.h>
 
 #include <C2AllocatorGralloc.h>
 #include <C2PlatformSupport.h>
-//#include <android/hardware/graphics/common/1.0/types.h>
-
-#include <android/hardware/graphics/allocator/3.0/IAllocator.h>
-#include <android/hardware/graphics/mapper/3.0/IMapper.h>
-#include <hidl/LegacySupport.h>
 
 #include <C2Debug.h>
 #include <C2PlatformSupport.h>
@@ -48,8 +45,8 @@
 #else
 #define DDD(...) ((void)0)
 #endif
-using ::android::hardware::graphics::common::V1_0::BufferUsage;
-using ::android::hardware::graphics::common::V1_2::PixelFormat;
+
+using aidl::android::hardware::graphics::common::BufferUsage;
 
 namespace android {
 constexpr size_t kMinInputBufferSize = 6 * 1024 * 1024;
@@ -506,7 +503,7 @@ C2GoldfishVpxDec::C2GoldfishVpxDec(const char *name, c2_node_id_t id,
                                    const std::shared_ptr<IntfImpl> &intfImpl)
     : SimpleC2Component(
           std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
-      mIntf(intfImpl), mCtx(nullptr), mQueue(new Mutexed<ConversionQueue>) {}
+      mIntf(intfImpl), mQueue(new Mutexed<ConversionQueue>) {}
 
 C2GoldfishVpxDec::~C2GoldfishVpxDec() { onRelease(); }
 
@@ -582,12 +579,6 @@ c2_status_t C2GoldfishVpxDec::onFlush_sm() {
 
 status_t C2GoldfishVpxDec::initDecoder() {
     ALOGI("calling init GoldfishVPX");
-#ifdef VP9
-    mMode = MODE_VP9;
-#else
-    mMode = MODE_VP8;
-#endif
-
     mWidth = 320;
     mHeight = 240;
     mFrameParallelMode = false;
@@ -605,7 +596,11 @@ void C2GoldfishVpxDec::checkContext(const std::shared_ptr<C2BlockPool> &pool) {
     mHeight = mIntf->height();
     ALOGI("created decoder context w %d h %d", mWidth, mHeight);
     mCtx = new vpx_codec_ctx_t;
-    mCtx->vpversion = mMode == MODE_VP8 ? 8 : 9;
+#ifdef VP9
+    mCtx->vpversion = 9;
+#else
+    mCtx->vpversion = 8;
+#endif
 
     //const bool isGraphic = (pool->getLocalId() == C2PlatformAllocatorStore::GRALLOC);
     const bool isGraphic = (pool->getAllocatorId() & C2Allocator::GRAPHIC);
@@ -613,7 +608,7 @@ void C2GoldfishVpxDec::checkContext(const std::shared_ptr<C2BlockPool> &pool) {
     if (isGraphic) {
         uint64_t client_usage = getClientUsage(pool);
         DDD("client has usage as 0x%llx", client_usage);
-        if (client_usage & BufferUsage::CPU_READ_MASK) {
+        if (client_usage & static_cast<uint32_t>(BufferUsage::CPU_READ_MASK)) {
             DDD("decoding to guest byte buffer as client has read usage");
             mEnableAndroidNativeBuffers = false;
         } else {
@@ -763,7 +758,8 @@ void C2GoldfishVpxDec::process(const std::unique_ptr<C2Work> &work,
         (int)work->input.ordinal.timestamp.peeku(),
         (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
 
-    if (mMode == MODE_VP8) {
+#ifndef VP9
+    {
         constexpr uint64_t ONE_SECOND_IN_MICRO_SECOND = 1000 * 1000;
         // bug: 349159609
         // note, vp8 does not have the FLAG_CODEC_CONFIG and the test
@@ -793,6 +789,7 @@ void C2GoldfishVpxDec::process(const std::unique_ptr<C2Work> &work,
             m_matrix = defaultColorAspects->matrix;
         }
     }
+#endif  // #ifndef VP9
 
     if (codecConfig) {
         {
@@ -808,10 +805,10 @@ void C2GoldfishVpxDec::process(const std::unique_ptr<C2Work> &work,
         }
 
         DDD("%s %d updated coloraspect due to codec config", __func__, __LINE__);
-        if (mMode == MODE_VP9) {
-            fillEmptyWork(work);
-            return;
-        }
+#ifdef VP9
+        fillEmptyWork(work);
+        return;
+#endif
     }
 
     sendMetadata();
@@ -886,8 +883,7 @@ void C2GoldfishVpxDec::setup_ctx_parameters(vpx_codec_ctx_t *ctx,
     ctx->hostColorBufferId = hostColorBufferId;
     ctx->outputBufferWidth = mWidth;
     ctx->outputBufferHeight = mHeight;
-    int32_t bpp = 1;
-    ctx->bpp = bpp;
+    ctx->bpp = 1;
 }
 
 status_t
diff --git a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h
index ceb46bdb..25141455 100644
--- a/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h
+++ b/system/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h
@@ -41,11 +41,6 @@ struct C2GoldfishVpxDec : public SimpleC2Component {
                       const std::shared_ptr<C2BlockPool> &pool) override;
 
   private:
-    enum {
-        MODE_VP8,
-        MODE_VP9,
-    } mMode;
-
     struct ConversionQueue;
 
     class ConverterThread : public Thread {
@@ -59,44 +54,20 @@ struct C2GoldfishVpxDec : public SimpleC2Component {
         std::shared_ptr<Mutexed<ConversionQueue>> mQueue;
     };
 
+    struct ConversionQueue {
+        std::list<std::function<void()>> entries;
+        Condition cond;
+        size_t numPending{0u};
+    };
+
     // create context that talks to host decoder: it needs to use
     // pool to decide whether decoding to host color buffer ot
     // decode to guest bytebuffer when pool cannot fetch valid host
     // color buffer id
     void checkContext(const std::shared_ptr<C2BlockPool> &pool);
-    bool mEnableAndroidNativeBuffers{true};
 
     void setup_ctx_parameters(vpx_codec_ctx_t *ctx, int hostColorBufferId = -1);
 
-    std::shared_ptr<C2StreamColorAspectsTuning::output> mColorAspects;
-
-
-    std::shared_ptr<IntfImpl> mIntf;
-    vpx_codec_ctx_t *mCtx;
-    bool mFrameParallelMode; // Frame parallel is only supported by VP9 decoder.
-    vpx_image_t *mImg;
-
-    uint32_t mWidth;
-    uint32_t mHeight;
-    bool mSignalledOutputEos;
-    bool mSignalledError;
-
-    // this is VP8 only
-    uint64_t mLastPts { 0 };
-
-    C2Color::range_t m_range;
-    C2Color::primaries_t m_primaries;
-    C2Color::transfer_t m_transfer;
-    C2Color::matrix_t m_matrix;
-
-    struct ConversionQueue {
-        std::list<std::function<void()>> entries;
-        Condition cond;
-        size_t numPending{0u};
-    };
-    std::shared_ptr<Mutexed<ConversionQueue>> mQueue;
-    std::vector<sp<ConverterThread>> mConverterThreads;
-
     status_t initDecoder();
     status_t destroyDecoder();
     void finishWork(uint64_t index, const std::unique_ptr<C2Work> &work,
@@ -107,9 +78,32 @@ struct C2GoldfishVpxDec : public SimpleC2Component {
                               const std::shared_ptr<C2BlockPool> &pool,
                               const std::unique_ptr<C2Work> &work);
 
-    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
     void sendMetadata();
 
+    std::shared_ptr<C2StreamColorAspectsTuning::output> mColorAspects;
+    std::shared_ptr<IntfImpl> mIntf;
+    std::shared_ptr<Mutexed<ConversionQueue>> mQueue;
+    std::vector<sp<ConverterThread>> mConverterThreads;
+    vpx_codec_ctx_t *mCtx{nullptr};
+    vpx_image_t *mImg{nullptr};
+
+#ifndef VP9
+    uint64_t mLastPts { 0 };
+    C2Color::range_t m_range;
+    C2Color::primaries_t m_primaries;
+    C2Color::transfer_t m_transfer;
+    C2Color::matrix_t m_matrix;
+#endif
+
+    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+
+    uint32_t mWidth{0};
+    uint32_t mHeight{0};
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mFrameParallelMode{false}; // Frame parallel is only supported by VP9 decoder.
+
     C2_DO_NOT_COPY(C2GoldfishVpxDec);
 };
 
diff --git a/system/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h b/system/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h
index 1be05c9f..cccd1c72 100644
--- a/system/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h
+++ b/system/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h
@@ -1,12 +1,13 @@
 #ifndef MY_VPX_DEFS_H_
 #define MY_VPX_DEFS_H_
 
+#include <cstdint>
+
 #define VPX_IMG_FMT_PLANAR 0x100       /**< Image is a planar format. */
 #define VPX_IMG_FMT_UV_FLIP 0x200      /**< V plane precedes U in memory. */
 #define VPX_IMG_FMT_HAS_ALPHA 0x400    /**< Image has an alpha channel. */
 #define VPX_IMG_FMT_HIGHBITDEPTH 0x800 /**< Image uses 16bit framebuffer. */
 
-typedef unsigned char uint8_t;
 typedef int vpx_codec_err_t;
 
 enum class RenderMode {
@@ -29,29 +30,31 @@ enum vpx_img_fmt_t {
 };
 
 struct vpx_image_t {
-    vpx_img_fmt_t fmt; /**< Image Format */
-    unsigned int d_w;  /**< Displayed image width */
-    unsigned int d_h;  /**< Displayed image height */
     void *user_priv;
+    uint32_t d_w;       /**< Displayed image width */
+    uint32_t d_h;       /**< Displayed image height */
+    vpx_img_fmt_t fmt;  /**< Image Format */
 };
 
 #define VPX_CODEC_OK 0
 
 struct vpx_codec_ctx_t {
-    int vpversion; // 8: vp8 or 9: vp9
-    int version;   // 100: return decoded frame to guest; 200: render on host
-    int hostColorBufferId;
-    uint64_t id; // >= 1, unique
-    int memory_slot;
-    uint64_t address_offset = 0;
-    size_t outputBufferWidth;
-    size_t outputBufferHeight;
-    size_t width;
-    size_t height;
-    size_t bpp;
+    vpx_image_t myImg;
     uint8_t *data;
     uint8_t *dst;
-    vpx_image_t myImg;
+    uint64_t address_offset = 0;
+    uint64_t id; // >= 1, unique
+
+    uint32_t outputBufferWidth;
+    uint32_t outputBufferHeight;
+    uint32_t width;
+    uint32_t height;
+
+    int hostColorBufferId;
+    int memory_slot;
+    int version;        // 100: return decoded frame to guest; 200: render on host
+    uint8_t vpversion;  // 8: vp8 or 9: vp9
+    uint8_t bpp;
 };
 
 int vpx_codec_destroy(vpx_codec_ctx_t *);
diff --git a/system/hwc3/Display.cpp b/system/hwc3/Display.cpp
index 17963ddb..08b7a46a 100644
--- a/system/hwc3/Display.cpp
+++ b/system/hwc3/Display.cpp
@@ -298,6 +298,7 @@ HWC3::Error Display::getDisplayConfigurations(std::vector<DisplayConfiguration>*
                                     static_cast<float>(displayConfig.getDpiY())};
         displayConfiguration.vsyncPeriod = displayConfig.getVsyncPeriod();
         displayConfiguration.configGroup = displayConfig.getConfigGroup();
+        displayConfiguration.hdrOutputType = OutputType::SYSTEM;
 
         outConfigs->emplace_back(displayConfiguration);
     }
diff --git a/system/hwc3/Display.h b/system/hwc3/Display.h
index 78cd3dc3..9f89b221 100644
--- a/system/hwc3/Display.h
+++ b/system/hwc3/Display.h
@@ -26,6 +26,7 @@
 #include <aidl/android/hardware/graphics/composer3/DisplayContentSample.h>
 #include <aidl/android/hardware/graphics/composer3/DisplayIdentification.h>
 #include <aidl/android/hardware/graphics/composer3/HdrCapabilities.h>
+#include <aidl/android/hardware/graphics/composer3/OutputType.h>
 #include <aidl/android/hardware/graphics/composer3/PerFrameMetadataKey.h>
 #include <aidl/android/hardware/graphics/composer3/PowerMode.h>
 #include <aidl/android/hardware/graphics/composer3/ReadbackBufferAttributes.h>
diff --git a/system/hwc3/GuestFrameComposer.cpp b/system/hwc3/GuestFrameComposer.cpp
index c5d5d99e..9fc0b3c8 100644
--- a/system/hwc3/GuestFrameComposer.cpp
+++ b/system/hwc3/GuestFrameComposer.cpp
@@ -76,6 +76,10 @@ uint32_t AlignToPower2(uint32_t val, uint8_t align_log) {
 }
 
 bool LayerNeedsScaling(const Layer& layer) {
+    if (layer.getCompositionType() == Composition::SOLID_COLOR) {
+        return false;
+    }
+
     common::Rect crop = layer.getSourceCropInt();
     common::Rect frame = layer.getDisplayFrame();
 
@@ -196,6 +200,12 @@ struct BufferSpec {
 
 int DoFill(const BufferSpec& dst, const Color& color) {
     ATRACE_CALL();
+    DEBUG_LOG(
+        "%s with r:%f g:%f b:%f a:%f in dst.buffer:%p dst.width:%" PRIu32 " dst.height:%" PRIu32
+        " dst.cropX:%" PRIu32 " dst.cropY:%" PRIu32 " dst.cropWidth:%" PRIu32
+        " dst.cropHeight:%" PRIu32 " dst.strideBytes:%" PRIu32 " dst.sampleBytes:%" PRIu32,
+        __FUNCTION__, color.r, color.g, color.b, color.a, dst.buffer, dst.width, dst.height,
+        dst.cropX, dst.cropY, dst.cropWidth, dst.cropHeight, dst.strideBytes, dst.sampleBytes);
 
     const uint8_t r = static_cast<uint8_t>(color.r * 255.0f);
     const uint8_t g = static_cast<uint8_t>(color.g * 255.0f);
@@ -205,12 +215,18 @@ int DoFill(const BufferSpec& dst, const Color& color) {
     const uint32_t rgba = static_cast<uint32_t>(r) | static_cast<uint32_t>(g) << 8 |
                           static_cast<uint32_t>(b) << 16 | static_cast<uint32_t>(a) << 24;
 
-    // Point to the upper left corner of the crop rectangle.
-    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    if (dst.drmFormat != DRM_FORMAT_ABGR8888 && dst.drmFormat != DRM_FORMAT_XBGR8888) {
+        ALOGE("Failed to DoFill: unhandled drm format:%" PRIu32, dst.drmFormat);
+        return -1;
+    }
 
-    libyuv::SetPlane(dstBuffer, static_cast<int>(dst.strideBytes), static_cast<int>(dst.cropWidth),
-                     static_cast<int>(dst.cropHeight), rgba);
-    return 0;
+    return libyuv::ARGBRect(dst.buffer,                         //
+                            static_cast<int>(dst.strideBytes),  //
+                            static_cast<int>(dst.cropX),        //
+                            static_cast<int>(dst.cropY),        //
+                            static_cast<int>(dst.cropWidth),    //
+                            static_cast<int>(dst.cropHeight),   //
+                            rgba);
 }
 
 int ConvertFromRGB565(const BufferSpec& src, const BufferSpec& dst, bool vFlip) {
@@ -782,7 +798,7 @@ HWC3::Error GuestFrameComposer::presentDisplay(
         [](const Layer* layer) { return layer->getCompositionType() == Composition::CLIENT; });
 
     if (noOpComposition) {
-        ALOGW("%s: display:%" PRIu32 " empty composition", __FUNCTION__, displayId);
+        DEBUG_LOG("%s: display:%" PRIu32 " empty composition", __FUNCTION__, displayId);
     } else if (allLayersClientComposed) {
         auto clientTargetBufferOpt = mGralloc.Import(display->waitAndGetClientTargetBuffer());
         if (!clientTargetBufferOpt) {
@@ -925,6 +941,11 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     std::uint32_t dstBufferBytesPerPixel) {
     ATRACE_CALL();
 
+    DEBUG_LOG("%s dstBuffer:%p dstBufferWidth:%" PRIu32 " dstBufferHeight:%" PRIu32
+              " dstBufferStrideBytes:%" PRIu32 " dstBufferBytesPerPixel:%" PRIu32,
+              __FUNCTION__, dstBuffer, dstBufferWidth, dstBufferHeight, dstBufferStrideBytes,
+              dstBufferBytesPerPixel);
+
     libyuv::RotationMode rotation = GetRotationFromTransform(srcLayer->getTransform());
 
     common::Rect srcLayerCrop = srcLayer->getSourceCropInt();
@@ -973,8 +994,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     bool needsAttenuation = LayerNeedsAttenuation(*srcLayer);
     bool needsBlending = LayerNeedsBlending(*srcLayer);
     bool needsBrightness = srcLayer->getBrightness() != 1.0f;
-    bool needsCopy = !(needsConversion || needsScaling || needsRotation || needsVFlip ||
-                       needsAttenuation || needsBlending);
+    bool needsCopy = !(needsFill || needsConversion || needsScaling || needsRotation ||
+                       needsVFlip || needsAttenuation || needsBlending);
 
     BufferSpec dstLayerSpec(
         dstBuffer,
@@ -1008,6 +1029,7 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
         AlignToPower2(mScratchBufferWidth * dstBufferBytesPerPixel, 4);
     uint32_t mScratchBufferSizeBytes = mScratchBufferHeight * mScratchBufferStrideBytes;
 
+    DEBUG_LOG("%s neededIntermediateImages:%d", __FUNCTION__, neededIntermediateImages);
     for (uint32_t i = 0; i < neededIntermediateImages; i++) {
         BufferSpec mScratchBufferspec(
             compositionIntermediateStorage.getRotatingScratchBuffer(mScratchBufferSizeBytes, i),
@@ -1020,6 +1042,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     // in the scratch buffers) in a common format.
 
     if (needsFill) {
+        DEBUG_LOG("%s needs fill", __FUNCTION__);
+
         BufferSpec& dstBufferSpec = dstBufferStack.back();
 
         int retval = DoFill(dstBufferSpec, srcLayer->getColor());
@@ -1035,6 +1059,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     // assumption that scaling ARGB is faster than scaling I420 (the most common).
     // This should be confirmed with testing.
     if (needsConversion) {
+        DEBUG_LOG("%s needs conversion", __FUNCTION__);
+
         BufferSpec& dstBufferSpec = dstBufferStack.back();
         if (needsScaling || needsTranspose) {
             // If a rotation or a scaling operation are needed the dimensions at the
@@ -1070,6 +1096,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     }
 
     if (needsScaling) {
+        DEBUG_LOG("%s needs scaling", __FUNCTION__);
+
         BufferSpec& dstBufferSpec = dstBufferStack.back();
         if (needsTranspose) {
             // If a rotation is needed, the temporary buffer has the correct size but
@@ -1093,6 +1121,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     }
 
     if (needsRotation) {
+        DEBUG_LOG("%s needs rotation", __FUNCTION__);
+
         int retval = DoRotation(srcLayerSpec, dstBufferStack.back(), rotation, needsVFlip);
         needsVFlip = false;
         if (retval) {
@@ -1103,6 +1133,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     }
 
     if (needsAttenuation) {
+        DEBUG_LOG("%s needs attenuation", __FUNCTION__);
+
         int retval = DoAttenuation(srcLayerSpec, dstBufferStack.back(), needsVFlip);
         needsVFlip = false;
         if (retval) {
@@ -1113,6 +1145,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     }
 
     if (needsBrightness) {
+        DEBUG_LOG("%s needs brightness", __FUNCTION__);
+
         int retval =
             DoBrightnessShading(srcLayerSpec, dstBufferStack.back(), srcLayer->getBrightness());
         if (retval) {
@@ -1123,6 +1157,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     }
 
     if (needsCopy) {
+        DEBUG_LOG("%s needs copy", __FUNCTION__);
+
         int retval = DoCopy(srcLayerSpec, dstBufferStack.back(), needsVFlip);
         needsVFlip = false;
         if (retval) {
@@ -1135,6 +1171,8 @@ HWC3::Error GuestFrameComposer::composeLayerInto(
     // Blending (if needed) should always be the last operation, so that it reads
     // and writes in the destination layer and not some temporary buffer.
     if (needsBlending) {
+        DEBUG_LOG("%s needs blending", __FUNCTION__);
+
         int retval = DoBlending(srcLayerSpec, dstBufferStack.back(), needsVFlip);
         needsVFlip = false;
         if (retval) {
@@ -1154,6 +1192,7 @@ HWC3::Error GuestFrameComposer::applyColorTransformToRGBA(
     std::uint32_t bufferHeight,                    //
     std::uint32_t bufferStrideBytes) {
     ATRACE_CALL();
+    DEBUG_LOG("%s", __FUNCTION__);
 
     const auto transformMatrixLibyuv = ToLibyuvColorMatrix(transfromMatrix);
     libyuv::ARGBColorMatrix(buffer, static_cast<int>(bufferStrideBytes),  //
```

