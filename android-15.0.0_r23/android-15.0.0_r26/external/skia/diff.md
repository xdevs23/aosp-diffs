```diff
diff --git a/resources/images/bmp-size-32x32-8bpp.bmp b/resources/images/bmp-size-32x32-8bpp.bmp
new file mode 100644
index 0000000000..d2f800d673
Binary files /dev/null and b/resources/images/bmp-size-32x32-8bpp.bmp differ
diff --git a/src/codec/SkBmpStandardCodec.cpp b/src/codec/SkBmpStandardCodec.cpp
index 1a9b844117..cf16ca780b 100644
--- a/src/codec/SkBmpStandardCodec.cpp
+++ b/src/codec/SkBmpStandardCodec.cpp
@@ -191,7 +191,7 @@ void SkBmpStandardCodec::initializeSwizzler(const SkImageInfo& dstInfo, const Op
 
     SkImageInfo swizzlerInfo = dstInfo;
     SkCodec::Options swizzlerOptions = opts;
-    if (this->colorXform()) {
+    if (this->xformOnDecode()) {
         swizzlerInfo = swizzlerInfo.makeColorType(kXformSrcColorType);
         if (kPremul_SkAlphaType == dstInfo.alphaType()) {
             swizzlerInfo = swizzlerInfo.makeAlphaType(kUnpremul_SkAlphaType);
diff --git a/tests/CodecTest.cpp b/tests/CodecTest.cpp
index 7c4121a354..7dbb1b4059 100644
--- a/tests/CodecTest.cpp
+++ b/tests/CodecTest.cpp
@@ -40,6 +40,7 @@
 #include "src/base/SkAutoMalloc.h"
 #include "src/base/SkRandom.h"
 #include "src/codec/SkCodecImageGenerator.h"
+#include "src/core/SkAutoPixmapStorage.h"
 #include "src/core/SkColorSpacePriv.h"
 #include "src/core/SkMD5.h"
 #include "src/core/SkStreamPriv.h"
@@ -2081,3 +2082,26 @@ DEF_TEST(Codec_jpeg_can_return_data_from_original_stream, r) {
     REPORTER_ASSERT(r, encodedData->size() == expectedBytes);
     REPORTER_ASSERT(r, SkJpegDecoder::IsJpeg(encodedData->data(), encodedData->size()));
 }
+
+DEF_TEST(Codec_bmp_indexed_colorxform, r) {
+    constexpr char path[] = "images/bmp-size-32x32-8bpp.bmp";
+    std::unique_ptr<SkStream> stream(GetResourceAsStream(path));
+    if (!stream) {
+        SkDebugf("Missing resource '%s'\n", path);
+        return;
+    }
+
+    std::unique_ptr<SkCodec> codec = SkCodec::MakeFromStream(std::move(stream));
+    REPORTER_ASSERT(r, codec);
+
+    // decode to a < 32bpp buffer with a color transform
+    const SkImageInfo decodeInfo = codec->getInfo().makeColorType(kRGB_565_SkColorType)
+                                                   .makeColorSpace(SkColorSpace::MakeSRGBLinear());
+    SkAutoPixmapStorage aps;
+    aps.alloc(decodeInfo);
+
+    // should not crash
+    auto res = codec->getPixels(aps);
+
+    REPORTER_ASSERT(r, res == SkCodec::kSuccess);
+}
```

